// SPDX-License-Identifier: GPL-2.0
/*
 * Userspace sframe access functions
 */

#define pr_fmt(fmt)	"sframe: " fmt

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/string_helpers.h>
#include <linux/sframe.h>
#include <linux/unwind_user_types.h>

#include "sframe.h"
#include "sframe_debug.h"

struct sframe_fde_internal {
	unsigned long	func_addr;
	u32		func_size;
	u32		fda_off;
	u32		fres_off;
	u32		fres_num;
	u8		info;
	u8		info2;
	u8		rep_size;
};

struct sframe_fre_internal {
	unsigned int	size;
	u32		ip_off;
	s32		cfa_off;
	s32		ra_off;
	s32		fp_off;
	u8		info;
};

DEFINE_STATIC_SRCU(sframe_srcu);

static __always_inline unsigned char fre_type_to_size(unsigned char fre_type)
{
	if (fre_type > 2)
		return 0;
	return 1 << fre_type;
}

static __always_inline unsigned char dataword_size_enum_to_size(unsigned char dataword_size)
{
	if (dataword_size > 2)
		return 0;
	return 1 << dataword_size;
}

static __always_inline int __read_fde(struct sframe_section *sec,
				      unsigned int fde_num,
				      struct sframe_fde_internal *fde)
{
	unsigned long fde_addr, fda_addr, func_addr;
	struct sframe_fde_v3 _fde;
	struct sframe_fda_v3 _fda;

	fde_addr = sec->fdes_start + (fde_num * sizeof(struct sframe_fde_v3));
	unsafe_copy_from_user(&_fde, (void __user *)fde_addr,
			      sizeof(struct sframe_fde_v3), Efault);

	func_addr = fde_addr + _fde.func_start_off;
	if (func_addr < sec->text_start || func_addr > sec->text_end)
		return -EINVAL;

	fda_addr = sec->fres_start + _fde.fres_off;
	if (fda_addr + sizeof(struct sframe_fda_v3) > sec->fres_end)
		return -EINVAL;
	unsafe_copy_from_user(&_fda, (void __user *)fda_addr,
			      sizeof(struct sframe_fda_v3), Efault);

	fde->func_addr	= func_addr;
	fde->func_size	= _fde.func_size;
	fde->fda_off	= _fde.fres_off;
	fde->fres_off	= _fde.fres_off + sizeof(struct sframe_fda_v3);
	fde->fres_num	= _fda.fres_num;
	fde->info	= _fda.info;
	fde->info2	= _fda.info2;
	fde->rep_size	= _fda.rep_size;

	return 0;

Efault:
	return -EFAULT;
}

static __always_inline int __find_fde(struct sframe_section *sec,
				      unsigned long ip,
				      struct sframe_fde_internal *fde)
{
	unsigned long func_addr_low = 0, func_addr_high = ULONG_MAX;
	struct sframe_fde_v3 __user *first, *low, *high, *found = NULL;
	int ret;

	first = (void __user *)sec->fdes_start;
	low = first;
	high = first + sec->num_fdes - 1;

	while (low <= high) {
		struct sframe_fde_v3 __user *mid;
		s64 func_off;
		unsigned long func_addr;

		mid = low + ((high - low) / 2);

		unsafe_get_user(func_off, (s64 __user *)mid, Efault);
		func_addr = (unsigned long)mid + func_off;

		if (ip >= func_addr) {
			if (func_addr < func_addr_low)
				return -EFAULT;

			func_addr_low = func_addr;

			found = mid;
			low = mid + 1;
		} else {
			if (func_addr > func_addr_high)
				return -EFAULT;

			func_addr_high = func_addr;

			high = mid - 1;
		}
	}

	if (!found)
		return -EINVAL;

	ret = __read_fde(sec, found - first, fde);
	if (ret)
		return ret;

	/* make sure it's not in a gap */
	if (ip < fde->func_addr || ip >= fde->func_addr + fde->func_size)
		return -EINVAL;

	return 0;

Efault:
	return -EFAULT;
}

#define ____UNSAFE_GET_USER_INC(to, from, type, label)			\
({									\
	type __to;							\
	unsafe_get_user(__to, (type __user *)from, label);		\
	from += sizeof(__to);						\
	to = __to;							\
})

#define __UNSAFE_GET_USER_INC(to, from, size, label, u_or_s)		\
({									\
	switch (size) {							\
	case 1:								\
		____UNSAFE_GET_USER_INC(to, from, u_or_s##8, label);	\
		break;							\
	case 2:								\
		____UNSAFE_GET_USER_INC(to, from, u_or_s##16, label);	\
		break;							\
	case 4:								\
		____UNSAFE_GET_USER_INC(to, from, u_or_s##32, label);	\
		break;							\
	default:							\
		return -EFAULT;						\
	}								\
})

#define UNSAFE_GET_USER_UNSIGNED_INC(to, from, size, label)		\
	__UNSAFE_GET_USER_INC(to, from, size, label, u)

#define UNSAFE_GET_USER_SIGNED_INC(to, from, size, label)		\
	__UNSAFE_GET_USER_INC(to, from, size, label, s)

#define UNSAFE_GET_USER_INC(to, from, size, label)				\
	_Generic(to,								\
		 u8 :	UNSAFE_GET_USER_UNSIGNED_INC(to, from, size, label),	\
		 u16 :	UNSAFE_GET_USER_UNSIGNED_INC(to, from, size, label),	\
		 u32 :	UNSAFE_GET_USER_UNSIGNED_INC(to, from, size, label),	\
		 u64 :	UNSAFE_GET_USER_UNSIGNED_INC(to, from, size, label),	\
		 s8 :	UNSAFE_GET_USER_SIGNED_INC(to, from, size, label),	\
		 s16 :	UNSAFE_GET_USER_SIGNED_INC(to, from, size, label),	\
		 s32 :	UNSAFE_GET_USER_SIGNED_INC(to, from, size, label),	\
		 s64 :	UNSAFE_GET_USER_SIGNED_INC(to, from, size, label))

static __always_inline int __read_fre(struct sframe_section *sec,
				      struct sframe_fde_internal *fde,
				      unsigned long fre_addr,
				      struct sframe_fre_internal *fre)
{
	unsigned char fde_type = SFRAME_V3_FDE_TYPE(fde->info2);
	unsigned char fde_pctype = SFRAME_V3_FDE_PCTYPE(fde->info);
	unsigned char fre_type = SFRAME_V3_FDE_FRE_TYPE(fde->info);
	unsigned char dataword_count, dataword_size;
	s32 cfa_off, ra_off, fp_off;
	unsigned long cur = fre_addr;
	unsigned char addr_size;
	u32 ip_off;
	u8 info;

	addr_size = fre_type_to_size(fre_type);
	if (!addr_size)
		return -EFAULT;

	if (fre_addr + addr_size + 1 > sec->fres_end)
		return -EFAULT;

	UNSAFE_GET_USER_INC(ip_off, cur, addr_size, Efault);
	if (fde_pctype == SFRAME_FDE_PCTYPE_INC && ip_off > fde->func_size)
		return -EFAULT;

	UNSAFE_GET_USER_INC(info, cur, 1, Efault);
	dataword_count = SFRAME_V3_FRE_DATAWORD_COUNT(info);
	dataword_size  = dataword_size_enum_to_size(SFRAME_V3_FRE_DATAWORD_SIZE(info));
	if (!dataword_size)
		return -EFAULT;

	if (cur + (dataword_count * dataword_size) > sec->fres_end)
		return -EFAULT;

	/* TODO: Support for flexible FDEs not implemented yet. */
	if (fde_type != SFRAME_FDE_TYPE_REGULAR)
		return -EFAULT;

	if (!dataword_count) {
		/*
		 * A FRE without data words indicates RA undefined /
		 * outermost frame.
		 */
		cfa_off	= 0;
		ra_off	= 0;
		fp_off	= 0;
		goto done;
	}

	UNSAFE_GET_USER_INC(cfa_off, cur, dataword_size, Efault);
	dataword_count--;

	ra_off = sec->ra_off;
	if (!ra_off) {
		if (!dataword_count--)
			return -EFAULT;

		UNSAFE_GET_USER_INC(ra_off, cur, dataword_size, Efault);
	}

	fp_off = sec->fp_off;
	if (!fp_off && dataword_count) {
		dataword_count--;
		UNSAFE_GET_USER_INC(fp_off, cur, dataword_size, Efault);
	}

	if (dataword_count)
		return -EFAULT;

done:
	fre->size	= addr_size + 1 + (dataword_count * dataword_size);
	fre->ip_off	= ip_off;
	fre->cfa_off	= cfa_off;
	fre->ra_off	= ra_off;
	fre->fp_off	= fp_off;
	fre->info	= info;

	return 0;

Efault:
	return -EFAULT;
}

static __always_inline int __find_fre(struct sframe_section *sec,
				      struct sframe_fde_internal *fde,
				      unsigned long ip,
				      struct unwind_user_frame *frame)
{
	unsigned char fde_pctype = SFRAME_V3_FDE_PCTYPE(fde->info);
	struct sframe_fre_internal *fre, *prev_fre = NULL;
	struct sframe_fre_internal fres[2];
	unsigned long fre_addr;
	bool which = false;
	unsigned int i;
	u32 ip_off;

	ip_off = ip - fde->func_addr;

	if (fde_pctype == SFRAME_FDE_PCTYPE_MASK)
		ip_off %= fde->rep_size;

	fre_addr = sec->fres_start + fde->fres_off;

	for (i = 0; i < fde->fres_num; i++) {
		int ret;

		/*
		 * Alternate between the two fre_addr[] entries for 'fre' and
		 * 'prev_fre'.
		 */
		fre = which ? fres : fres + 1;
		which = !which;

		ret = __read_fre(sec, fde, fre_addr, fre);
		if (ret)
			return ret;

		fre_addr += fre->size;

		if (prev_fre && fre->ip_off <= prev_fre->ip_off)
			return -EFAULT;

		if (fre->ip_off > ip_off)
			break;

		prev_fre = fre;
	}

	if (!prev_fre)
		return -EINVAL;
	fre = prev_fre;

	frame->cfa_off = fre->cfa_off;
	frame->ra_off  = fre->ra_off;
	frame->fp_off  = fre->fp_off;
	frame->use_fp  = SFRAME_V3_FRE_CFA_BASE_REG_ID(fre->info) == SFRAME_BASE_REG_FP;
	frame->outermost = SFRAME_V3_FRE_RA_UNDEFINED_P(fre->info);

	return 0;
}

int sframe_find(unsigned long ip, struct unwind_user_frame *frame)
{
	struct mm_struct *mm = current->mm;
	struct sframe_section *sec;
	struct sframe_fde_internal fde;
	int ret;

	if (!mm)
		return -EINVAL;

	guard(srcu)(&sframe_srcu);

	sec = mtree_load(&mm->sframe_mt, ip);
	if (!sec)
		return -EINVAL;

	if (!user_read_access_begin((void __user *)sec->sframe_start,
				    sec->sframe_end - sec->sframe_start))
		return -EFAULT;

	ret = __find_fde(sec, ip, &fde);
	if (ret)
		goto end;

	ret = __find_fre(sec, &fde, ip, frame);
end:
	user_read_access_end();
	return ret;
}

static void free_section(struct sframe_section *sec)
{
	kfree(sec);
}

static int sframe_read_header(struct sframe_section *sec)
{
	unsigned long header_end, fdes_start, fdes_end, fres_start, fres_end;
	struct sframe_header shdr;
	unsigned int num_fdes;

	if (copy_from_user(&shdr, (void __user *)sec->sframe_start, sizeof(shdr))) {
		dbg("header usercopy failed\n");
		return -EFAULT;
	}

	if (shdr.preamble.magic != SFRAME_MAGIC ||
	    shdr.preamble.version != SFRAME_VERSION_3 ||
	    !(shdr.preamble.flags & SFRAME_F_FDE_SORTED) ||
	    !(shdr.preamble.flags & SFRAME_F_FDE_FUNC_START_PCREL) ||
	    shdr.auxhdr_len) {
		dbg("bad/unsupported sframe header\n");
		return -EINVAL;
	}

	if (!shdr.num_fdes || !shdr.num_fres) {
		dbg("no fde/fre entries\n");
		return -EINVAL;
	}

	header_end = sec->sframe_start + SFRAME_HEADER_SIZE(shdr);
	if (header_end >= sec->sframe_end) {
		dbg("header doesn't fit in section\n");
		return -EINVAL;
	}

	num_fdes   = shdr.num_fdes;
	fdes_start = header_end + shdr.fdes_off;
	fdes_end   = fdes_start + (num_fdes * sizeof(struct sframe_fde_v3));

	fres_start = header_end + shdr.fres_off;
	fres_end   = fres_start + shdr.fre_len;

	if (fres_start < fdes_end || fres_end > sec->sframe_end) {
		dbg("inconsistent fde/fre offsets\n");
		return -EINVAL;
	}

	sec->num_fdes		= num_fdes;
	sec->fdes_start		= fdes_start;
	sec->fres_start		= fres_start;
	sec->fres_end		= fres_end;

	sec->ra_off		= shdr.cfa_fixed_ra_offset;
	sec->fp_off		= shdr.cfa_fixed_fp_offset;

	return 0;
}

int sframe_add_section(unsigned long sframe_start, unsigned long sframe_end,
		       unsigned long text_start, unsigned long text_end)
{
	struct maple_tree *sframe_mt = &current->mm->sframe_mt;
	struct vm_area_struct *sframe_vma, *text_vma;
	struct mm_struct *mm = current->mm;
	struct sframe_section *sec;
	int ret;

	if (!sframe_start || !sframe_end || !text_start || !text_end) {
		dbg("zero-length sframe/text address\n");
		return -EINVAL;
	}

	scoped_guard(mmap_read_lock, mm) {
		sframe_vma = vma_lookup(mm, sframe_start);
		if (!sframe_vma || sframe_end > sframe_vma->vm_end) {
			dbg("bad sframe address (0x%lx - 0x%lx)\n",
			    sframe_start, sframe_end);
			return -EINVAL;
		}

		text_vma = vma_lookup(mm, text_start);
		if (!text_vma ||
		    !(text_vma->vm_flags & VM_EXEC) ||
		    text_end > text_vma->vm_end) {
			dbg("bad text address (0x%lx - 0x%lx)\n",
			    text_start, text_end);
			return -EINVAL;
		}
	}

	sec = kzalloc(sizeof(*sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;

	sec->sframe_start	= sframe_start;
	sec->sframe_end		= sframe_end;
	sec->text_start		= text_start;
	sec->text_end		= text_end;

	ret = sframe_read_header(sec);
	if (ret) {
		dbg_print_header(sec);
		goto err_free;
	}

	ret = mtree_insert_range(sframe_mt, sec->text_start, sec->text_end, sec, GFP_KERNEL);
	if (ret) {
		dbg("mtree_insert_range failed: text=%lx-%lx\n",
		    sec->text_start, sec->text_end);
		goto err_free;
	}

	return 0;

err_free:
	free_section(sec);
	return ret;
}

static void sframe_free_srcu(struct rcu_head *rcu)
{
	struct sframe_section *sec = container_of(rcu, struct sframe_section, rcu);

	free_section(sec);
}

static int __sframe_remove_section(struct mm_struct *mm,
				   struct sframe_section *sec)
{
	if (!mtree_erase(&mm->sframe_mt, sec->text_start)) {
		dbg("mtree_erase failed: text=%lx\n", sec->text_start);
		return -EINVAL;
	}

	call_srcu(&sframe_srcu, &sec->rcu, sframe_free_srcu);

	return 0;
}

int sframe_remove_section(unsigned long sframe_start)
{
	struct mm_struct *mm = current->mm;
	struct sframe_section *sec;
	unsigned long index = 0;
	bool found = false;
	int ret = 0;

	mt_for_each(&mm->sframe_mt, sec, index, ULONG_MAX) {
		if (sec->sframe_start == sframe_start) {
			found = true;
			ret |= __sframe_remove_section(mm, sec);
		}
	}

	if (!found || ret)
		return -EINVAL;

	return 0;
}

void sframe_free_mm(struct mm_struct *mm)
{
	struct sframe_section *sec;
	unsigned long index = 0;

	if (!mm)
		return;

	mt_for_each(&mm->sframe_mt, sec, index, ULONG_MAX)
		free_section(sec);

	mtree_destroy(&mm->sframe_mt);
}

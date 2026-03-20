/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SFRAME_H
#define _LINUX_SFRAME_H

#include <linux/mm_types.h>
#include <linux/srcu.h>

#define UNWIND_RULE_DEREF			BIT(31)

enum unwind_cfa_rule {
	UNWIND_CFA_RULE_SP_OFFSET,		/* CFA = SP + offset */
	UNWIND_CFA_RULE_FP_OFFSET,		/* CFA = FP + offset */
	UNWIND_CFA_RULE_REG_OFFSET,	/* CFA = reg + offset */
	/* DEREF variants */
	UNWIND_CFA_RULE_REG_OFFSET_DEREF =	/* CFA = *(reg + offset) */
		UNWIND_CFA_RULE_REG_OFFSET | UNWIND_RULE_DEREF,
};

struct unwind_cfa_rule_data {
	enum unwind_cfa_rule rule;
	s32 offset;
	unsigned int regnum;
};

enum unwind_rule {
	UNWIND_RULE_RETAIN,		/* entity = entity */
	UNWIND_RULE_CFA_OFFSET,		/* entity = CFA + offset */
	UNWIND_RULE_REG_OFFSET,		/* entity = register + offset */
	/* DEREF variants */
	UNWIND_RULE_CFA_OFFSET_DEREF =	/* entity = *(CFA + offset) */
		UNWIND_RULE_CFA_OFFSET | UNWIND_RULE_DEREF,
	UNWIND_RULE_REG_OFFSET_DEREF =	/* entity = *(register + offset) */
		UNWIND_RULE_REG_OFFSET | UNWIND_RULE_DEREF,
};

struct unwind_rule_data {
	enum unwind_rule rule;
	s32 offset;
	unsigned int regnum;
};

struct unwind_frame {
	struct unwind_cfa_rule_data cfa;
	struct unwind_rule_data ra;
	struct unwind_rule_data fp;
	bool outermost;
};

#ifdef CONFIG_SFRAME_LOOKUP

enum sframe_sec_type {
	SFRAME_KERNEL,
	SFRAME_USER,
};

struct sframe_section {
	struct rcu_head  rcu;
#ifdef CONFIG_DYNAMIC_DEBUG
	const char		*filename;
#endif
	enum sframe_sec_type	sec_type;
	unsigned long		sframe_start;
	unsigned long		sframe_end;
	unsigned long		text_start;
	unsigned long		text_end;

	unsigned long		fdes_start;
	unsigned long		fres_start;
	unsigned long		fres_end;
	unsigned int		num_fdes;

	signed char		ra_off;
	signed char		fp_off;
};

#endif /* CONFIG_SFRAME_LOOKUP */

#ifdef CONFIG_HAVE_UNWIND_USER_SFRAME

#define INIT_MM_SFRAME .sframe_mt = MTREE_INIT(sframe_mt, 0),
extern void sframe_free_mm(struct mm_struct *mm);

extern int sframe_add_section(unsigned long sframe_start, unsigned long sframe_end,
			      unsigned long text_start, unsigned long text_end);
extern int sframe_remove_section(unsigned long sframe_addr);

static inline bool current_has_sframe(void)
{
	struct mm_struct *mm = current->mm;

	return mm && !mtree_empty(&mm->sframe_mt);
}

extern int sframe_find_user(unsigned long ip, struct unwind_frame *frame);

#else /* !CONFIG_HAVE_UNWIND_USER_SFRAME */

#define INIT_MM_SFRAME
static inline void sframe_free_mm(struct mm_struct *mm) {}
static inline int sframe_add_section(unsigned long sframe_start, unsigned long sframe_end,
				     unsigned long text_start, unsigned long text_end)
{
	return -ENOSYS;
}
static inline int sframe_remove_section(unsigned long sframe_addr) { return -ENOSYS; }
static inline bool current_has_sframe(void) { return false; }

static inline int sframe_find_user(unsigned long ip, struct unwind_frame *frame) { return -ENOSYS; }

#endif /* CONFIG_HAVE_UNWIND_USER_SFRAME */

#endif /* _LINUX_SFRAME_H */

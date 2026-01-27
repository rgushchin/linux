/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * From https://www.sourceware.org/binutils/docs/sframe-spec.html
 */
#ifndef _SFRAME_H
#define _SFRAME_H

#include <linux/types.h>

#define SFRAME_VERSION_1			1
#define SFRAME_VERSION_2			2
#define SFRAME_VERSION_3			3
#define SFRAME_MAGIC				0xdee2

#define SFRAME_F_FDE_SORTED			0x1
#define SFRAME_F_FRAME_POINTER			0x2
#define SFRAME_F_FDE_FUNC_START_PCREL		0x4

#define SFRAME_ABI_AARCH64_ENDIAN_BIG		1
#define SFRAME_ABI_AARCH64_ENDIAN_LITTLE	2
#define SFRAME_ABI_AMD64_ENDIAN_LITTLE		3

struct sframe_preamble {
	u16	magic;
	u8	version;
	u8	flags;
} __packed;

struct sframe_header {
	struct sframe_preamble preamble;
	u8	abi_arch;
	s8	cfa_fixed_fp_offset;
	s8	cfa_fixed_ra_offset;
	u8	auxhdr_len;
	u32	num_fdes;
	u32	num_fres;
	u32	fre_len;
	u32	fdes_off;
	u32	fres_off;
} __packed;

#define SFRAME_HEADER_SIZE(header) \
	((sizeof(struct sframe_header) + (header).auxhdr_len))

struct sframe_fde_v3 {
	s64	func_start_off;
	u32	func_size;
	u32	fres_off;
} __packed;

struct sframe_fda_v3 {
	u16	fres_num;
	u8	info;
	u8	info2;
	u8	rep_size;
} __packed;

#define SFRAME_FDE_PCTYPE_INC			0
#define SFRAME_FDE_PCTYPE_MASK			1

#define SFRAME_AARCH64_PAUTH_KEY_A		0
#define SFRAME_AARCH64_PAUTH_KEY_B		1

#define SFRAME_V3_FDE_FRE_TYPE(info)		((info) & 0xf)
#define SFRAME_V3_FDE_PCTYPE(info)		(((info) >> 4) & 0x1)
#define SFRAME_V3_AARCH64_FDE_PAUTH_KEY(info)	(((info) >> 5) & 0x1)

#define SFRAME_FDE_TYPE_REGULAR			0

#define SFRAME_V3_FDE_TYPE_MASK			0x0f
#define SFRAME_V3_FDE_TYPE(info2)		((info2) & SFRAME_V3_FDE_TYPE_MASK)

#define SFRAME_BASE_REG_FP			0
#define SFRAME_BASE_REG_SP			1

#define SFRAME_V3_FRE_CFA_BASE_REG_ID(info)		((info) & 0x1)
#define SFRAME_V3_FRE_DATAWORD_COUNT(info)		(((info) >> 1) & 0xf)
#define SFRAME_V3_FRE_DATAWORD_SIZE(info)		(((info) >> 5) & 0x3)
#define SFRAME_V3_AARCH64_FRE_MANGLED_RA_P(info)	(((info) >> 7) & 0x1)

#endif /* _SFRAME_H */

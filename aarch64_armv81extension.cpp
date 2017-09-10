/*
 * aarch64_armv81extension - an IDA processor extender to support ARM v8.1 opcodes
 * Copyright (C) 2017 Stefan Esser / Antid0te UG <stefan@antid0te.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>

#ifndef __EA64__
#error This extension only makes sense in a 64bit context
#endif

#define MAGIC_ACTIVATED   333
#define MAGIC_DEACTIVATED 777

static ea_t ea;

inline bool is_arm64_ea(ea_t ea)
{
	segment_t *seg = getseg(ea);
	return seg != NULL && seg->use64();
}

#define cond segpref

#define simd_sz specflag1

#define cAL 14

#define Q0 45
#define S0 93
#define V0 163
#define X0 129
#define XSP (X0+32)

enum {
	arm_ldadd = CUSTOM_CMD_ITYPE+0x2000,
	arm_ldadda,
	arm_ldaddal,
	arm_ldaddl,
	arm_ldaddb,
	arm_ldaddab,
	arm_ldaddalb,
	arm_ldaddlb,
	arm_ldaddh,
	arm_ldaddah,
	arm_ldaddalh,
	arm_ldaddlh,
	arm_stadd,
	arm_staddl,
	arm_staddb,
	arm_staddlb,
	arm_staddh,
	arm_staddlh,
	
	arm_cas,
	arm_casa,
	arm_casal,
	arm_casl,
	arm_casb,
	arm_casab,
	arm_casalb,
	arm_caslb,
	arm_cash,
	arm_casah,
	arm_casalh,
	arm_caslh,

	arm_casp,
	arm_caspa,
	arm_caspal,
	arm_caspl,
	
	arm_ldclr,
	arm_ldclra,
	arm_ldclral,
	arm_ldclrl,
	arm_ldclrb,
	arm_ldclrab,
	arm_ldclralb,
	arm_ldclrlb,
	arm_ldclrh,
	arm_ldclrah,
	arm_ldclralh,
	arm_ldclrlh,
	arm_stclr,
	arm_stclrl,
	arm_stclrb,
	arm_stclrlb,
	arm_stclrh,
	arm_stclrlh,
	
	arm_ldeor,
	arm_ldeora,
	arm_ldeoral,
	arm_ldeorl,
	arm_ldeorb,
	arm_ldeorab,
	arm_ldeoralb,
	arm_ldeorlb,
	arm_ldeorh,
	arm_ldeorah,
	arm_ldeoralh,
	arm_ldeorlh,
	arm_steor,
	arm_steorl,
	arm_steorb,
	arm_steorlb,
	arm_steorh,
	arm_steorlh,
	
	arm_ldset,
	arm_ldseta,
	arm_ldsetal,
	arm_ldsetl,
	arm_ldsetb,
	arm_ldsetab,
	arm_ldsetalb,
	arm_ldsetlb,
	arm_ldseth,
	arm_ldsetah,
	arm_ldsetalh,
	arm_ldsetlh,
	arm_stset,
	arm_stsetl,
	arm_stsetb,
	arm_stsetlb,
	arm_stseth,
	arm_stsetlh,
	
	arm_ldsmax,
	arm_ldsmaxa,
	arm_ldsmaxal,
	arm_ldsmaxl,
	arm_ldsmaxb,
	arm_ldsmaxab,
	arm_ldsmaxalb,
	arm_ldsmaxlb,
	arm_ldsmaxh,
	arm_ldsmaxah,
	arm_ldsmaxalh,
	arm_ldsmaxlh,
	arm_stsmax,
	arm_stsmaxl,
	arm_stsmaxb,
	arm_stsmaxlb,
	arm_stsmaxh,
	arm_stsmaxlh,
	
	arm_ldsmin,
	arm_ldsmina,
	arm_ldsminal,
	arm_ldsminl,
	arm_ldsminb,
	arm_ldsminab,
	arm_ldsminalb,
	arm_ldsminlb,
	arm_ldsminh,
	arm_ldsminah,
	arm_ldsminalh,
	arm_ldsminlh,
	arm_stsmin,
	arm_stsminl,
	arm_stsminb,
	arm_stsminlb,
	arm_stsminh,
	arm_stsminlh,
	
	arm_ldumax,
	arm_ldumaxa,
	arm_ldumaxal,
	arm_ldumaxl,
	arm_ldumaxb,
	arm_ldumaxab,
	arm_ldumaxalb,
	arm_ldumaxlb,
	arm_ldumaxh,
	arm_ldumaxah,
	arm_ldumaxalh,
	arm_ldumaxlh,
	arm_stumax,
	arm_stumaxl,
	arm_stumaxb,
	arm_stumaxlb,
	arm_stumaxh,
	arm_stumaxlh,

	arm_ldumin,
	arm_ldumina,
	arm_lduminal,
	arm_lduminl,
	arm_lduminb,
	arm_lduminab,
	arm_lduminalb,
	arm_lduminlb,
	arm_lduminh,
	arm_lduminah,
	arm_lduminalh,
	arm_lduminlh,
	arm_stumin,
	arm_stuminl,
	arm_stuminb,
	arm_stuminlb,
	arm_stuminh,
	arm_stuminlh,
	
	
	arm_swp,
	arm_swpa,
	arm_swpal,
	arm_swpl,
	arm_swpb,
	arm_swpab,
	arm_swpalb,
	arm_swplb,
	arm_swph,
	arm_swpah,
	arm_swpalh,
	arm_swplh,
};

char *get_insn_mnem()
{
  switch (cmd.itype) {
	case arm_cas: return "CAS";
	case arm_casa: return "CASA";
	case arm_casal: return "CASAL";
	case arm_casl: return "CASL";
	case arm_casb: return "CASB";
	case arm_casab: return "CASAB";
	case arm_casalb: return "CASALB";
	case arm_caslb: return "CASLB";
	case arm_cash: return "CASH";
	case arm_casah: return "CASAH";
	case arm_casalh: return "CASALH";
	case arm_caslh: return "CASLH";

	case arm_casp: return "CASP";
	case arm_caspa: return "CASPA";
	case arm_caspal: return "CASPAL";
	case arm_caspl: return "CASPL";
	
	case arm_ldadd: return "LDADD";
	case arm_ldadda: return "LDADDA";
	case arm_ldaddal: return "LDADDAL";
	case arm_ldaddl: return "LDADDL";
	case arm_ldaddb: return "LDADDB";
	case arm_ldaddab: return "LDADDAB";
	case arm_ldaddalb: return "LDADDALB";
	case arm_ldaddlb: return "LDADDLB";
	case arm_ldaddh: return "LDADDH";
	case arm_ldaddah: return "LDADDAH";
	case arm_ldaddalh: return "LDADDALH";
	case arm_ldaddlh: return "LDADDLH";
	case arm_stadd: return "STADD";
	case arm_staddl: return "STADDL";
	case arm_staddb: return "STADDB";
	case arm_staddlb: return "STADDLB";
	case arm_staddh: return "STADDH";
	case arm_staddlh: return "STADDLH";
	
	case arm_ldclr: return "LDCLR";
	case arm_ldclra: return "LDCLRA";
	case arm_ldclral: return "LDCLRAL";
	case arm_ldclrl: return "LDCLRL";
	case arm_ldclrb: return "LDCLRB";
	case arm_ldclrab: return "LDCLRAB";
	case arm_ldclralb: return "LDCLRALB";
	case arm_ldclrlb: return "LDCLRLB";
	case arm_ldclrh: return "LDCLRH";
	case arm_ldclrah: return "LDCLRAH";
	case arm_ldclralh: return "LDCLRALH";
	case arm_ldclrlh: return "LDCLRLH";
	case arm_stclr: return "STCLR";
	case arm_stclrl: return "STCLRL";
	case arm_stclrb: return "STCLRB";
	case arm_stclrlb: return "STCLRLB";
	case arm_stclrh: return "STCLRH";
	case arm_stclrlh: return "STCLRLH";

	case arm_ldeor: return "LDEOR";
	case arm_ldeora: return "LDEORA";
	case arm_ldeoral: return "LDEORAL";
	case arm_ldeorl: return "LDEORL";
	case arm_ldeorb: return "LDEORB";
	case arm_ldeorab: return "LDEORAB";
	case arm_ldeoralb: return "LDEORALB";
	case arm_ldeorlb: return "LDEORLB";
	case arm_ldeorh: return "LDEORH";
	case arm_ldeorah: return "LDEORAH";
	case arm_ldeoralh: return "LDEORALH";
	case arm_ldeorlh: return "LDEORLH";
	case arm_steor: return "STEOR";
	case arm_steorl: return "STEORL";
	case arm_steorb: return "STEORB";
	case arm_steorlb: return "STEORLB";
	case arm_steorh: return "STEORH";
	case arm_steorlh: return "STEORLH";
	
	case arm_ldset: return "LDSET";
	case arm_ldseta: return "LDSETA";
	case arm_ldsetal: return "LDSETAL";
	case arm_ldsetl: return "LDSETL";
	case arm_ldsetb: return "LDSETB";
	case arm_ldsetab: return "LDSETAB";
	case arm_ldsetalb: return "LDSETALB";
	case arm_ldsetlb: return "LDSETLB";
	case arm_ldseth: return "LDSETH";
	case arm_ldsetah: return "LDSETAH";
	case arm_ldsetalh: return "LDSETALH";
	case arm_ldsetlh: return "LDSETLH";
	case arm_stset: return "STSET";
	case arm_stsetl: return "STSETL";
	case arm_stsetb: return "STSETB";
	case arm_stsetlb: return "STSETLB";
	case arm_stseth: return "STSETH";
	case arm_stsetlh: return "STSETLH";
	
	case arm_ldsmax: return "LDSMAX";
	case arm_ldsmaxa: return "LDSMAXA";
	case arm_ldsmaxal: return "LDSMAXAL";
	case arm_ldsmaxl: return "LDSMAXL";
	case arm_ldsmaxb: return "LDSMAXB";
	case arm_ldsmaxab: return "LDSMAXAB";
	case arm_ldsmaxalb: return "LDSMAXALB";
	case arm_ldsmaxlb: return "LDSMAXLB";
	case arm_ldsmaxh: return "LDSMAXH";
	case arm_ldsmaxah: return "LDSMAXAH";
	case arm_ldsmaxalh: return "LDSMAXALH";
	case arm_ldsmaxlh: return "LDSMAXLH";
	case arm_stsmax: return "STSMAX";
	case arm_stsmaxl: return "STSMAXL";
	case arm_stsmaxb: return "STSMAXB";
	case arm_stsmaxlb: return "STSMAXLB";
	case arm_stsmaxh: return "STSMAXH";
	case arm_stsmaxlh: return "STSMAXLH";
	
	case arm_ldsmin: return "LDSMIN";
	case arm_ldsmina: return "LDSMINA";
	case arm_ldsminal: return "LDSMINAL";
	case arm_ldsminl: return "LDSMINL";
	case arm_ldsminb: return "LDSMINB";
	case arm_ldsminab: return "LDSMINAB";
	case arm_ldsminalb: return "LDSMINALB";
	case arm_ldsminlb: return "LDSMINLB";
	case arm_ldsminh: return "LDSMINH";
	case arm_ldsminah: return "LDSMINAH";
	case arm_ldsminalh: return "LDSMINALH";
	case arm_ldsminlh: return "LDSMINLH";
	case arm_stsmin: return "STSMIN";
	case arm_stsminl: return "STSMINL";
	case arm_stsminb: return "STSMINB";
	case arm_stsminlb: return "STSMINLB";
	case arm_stsminh: return "STSMINH";
	case arm_stsminlh: return "STSMINLH";
	
	case arm_ldumax: return "LDUMAX";
	case arm_ldumaxa: return "LDUMAXA";
	case arm_ldumaxal: return "LDUMAXAL";
	case arm_ldumaxl: return "LDUMAXL";
	case arm_ldumaxb: return "LDUMAXB";
	case arm_ldumaxab: return "LDUMAXAB";
	case arm_ldumaxalb: return "LDUMAXALB";
	case arm_ldumaxlb: return "LDUMAXLB";
	case arm_ldumaxh: return "LDUMAXH";
	case arm_ldumaxah: return "LDUMAXAH";
	case arm_ldumaxalh: return "LDUMAXALH";
	case arm_ldumaxlh: return "LDUMAXLH";
	case arm_stumax: return "STUMAX";
	case arm_stumaxl: return "STUMAXL";
	case arm_stumaxb: return "STUMAXB";
	case arm_stumaxlb: return "STUMAXLB";
	case arm_stumaxh: return "STUMAXH";
	case arm_stumaxlh: return "STUMAXLH";
	
	case arm_ldumin: return "LDUMIN";
	case arm_ldumina: return "LDUMINA";
	case arm_lduminal: return "LDUMINAL";
	case arm_lduminl: return "LDUMINL";
	case arm_lduminb: return "LDUMINB";
	case arm_lduminab: return "LDUMINAB";
	case arm_lduminalb: return "LDUMINALB";
	case arm_lduminlb: return "LDUMINLB";
	case arm_lduminh: return "LDUMINH";
	case arm_lduminah: return "LDUMINAH";
	case arm_lduminalh: return "LDUMINALH";
	case arm_lduminlh: return "LDUMINLH";
	case arm_stumin: return "STUMIN";
	case arm_stuminl: return "STUMINL";
	case arm_stuminb: return "STUMINB";
	case arm_stuminlb: return "STUMINLB";
	case arm_stuminh: return "STUMINH";
	case arm_stuminlh: return "STUMINLH";
	
	case arm_swp: return "SWP";
	case arm_swpa: return "SWPA";
	case arm_swpal: return "SWPAL";
	case arm_swpl: return "SWPL";
	case arm_swpb: return "SWPB";
	case arm_swpab: return "SWPAB";
	case arm_swpalb: return "SWPALB";
	case arm_swplb: return "SWPLB";
	case arm_swph: return "SWPH";
	case arm_swpah: return "SWPAH";
	case arm_swpalh: return "SWPALH";
	case arm_swplh: return "SWPLH";
  }
  return NULL;
}

static size_t handle_ldst(uint32_t base, uint32_t code)
{	
	uint32_t size = (code >> 30) & 3;
	uint32_t A = (code >> 23) & 1;
	uint32_t R = (code >> 22) & 1;
	uint32_t Rs = (code >> 16) & 0x1f;
	uint32_t Rn = (code >> 5) & 0x1f;
	uint32_t Rt = (code) & 0x1f;
	
	uint32_t opcodes[4][4] = 
		{	{arm_ldclrb, arm_ldclrlb, arm_ldclrab, arm_ldclralb }, 
			{arm_ldclrh, arm_ldclrlh, arm_ldclrah, arm_ldclralh },
			{arm_ldclr, arm_ldclrl, arm_ldclra, arm_ldclral },
			{arm_ldclr, arm_ldclrl, arm_ldclra, arm_ldclral } };
	uint32_t opcodes2[4][2] = 
		{	{arm_stclrb, arm_stclrlb},
	 		{arm_stclrh, arm_stclrlh},
			{arm_stclr, arm_stclrl},
			{arm_stclr, arm_stclrl} };
		
	/* STCLR... */	
	if (A == 0 && Rt == 0x1f) {
		cmd.itype = opcodes2[size][R] - arm_ldclr + base;
		cmd.cond = cAL;
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rs + X0;
		cmd.Op2.type = o_displ;
		if (Rn == 31) cmd.Op2.phrase = XSP; else cmd.Op2.phrase = Rn + X0;
		cmd.Op2.addr = 0;
		cmd.Op2.flags = OF_NO_BASE_DISP|OF_SHOW;
		cmd.Op2.dtyp = dt_qword;
		switch (size) {
			case 0:
			case 1:
			case 2:
			cmd.Op1.dtyp = dt_dword;
			break;
			case 3:
			cmd.Op1.dtyp = dt_qword;
		}
		return 4;
	}
	
	cmd.itype = opcodes[size][(A<<1)+R] - arm_ldclr + base;
	cmd.cond = cAL;
	cmd.Op1.type = o_reg;
	cmd.Op1.reg = Rs + X0;
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = Rt + X0;
	cmd.Op3.type = o_displ;
	if (Rn == 31) cmd.Op3.phrase = XSP; else cmd.Op3.phrase = Rn + X0;
	cmd.Op3.addr = 0;
	cmd.Op3.flags = OF_NO_BASE_DISP|OF_SHOW;
	cmd.Op3.dtyp = dt_qword;
	
	switch (size) {
		case 0:
		case 1:
		case 2:
		cmd.Op1.dtyp = dt_dword;
		cmd.Op2.dtyp = dt_dword;
		break;
		case 3:
		cmd.Op1.dtyp = dt_qword;
		cmd.Op2.dtyp = dt_qword;
	}
	
	return 4;
}

static size_t handle_swp(uint32_t base, uint32_t code)
{	
	uint32_t size = (code >> 30) & 3;
	uint32_t A = (code >> 23) & 1;
	uint32_t R = (code >> 22) & 1;
	uint32_t Rs = (code >> 16) & 0x1f;
	uint32_t Rn = (code >> 5) & 0x1f;
	uint32_t Rt = (code) & 0x1f;
	
	uint32_t opcodes[4][4] = 
		{	{arm_ldclrb, arm_ldclrlb, arm_ldclrab, arm_ldclralb }, 
			{arm_ldclrh, arm_ldclrlh, arm_ldclrah, arm_ldclralh },
			{arm_ldclr, arm_ldclrl, arm_ldclra, arm_ldclral },
			{arm_ldclr, arm_ldclrl, arm_ldclra, arm_ldclral } };
	
	cmd.itype = opcodes[size][(A<<1)+R] - arm_ldclr + base;
	cmd.cond = cAL;
	cmd.Op1.type = o_reg;
	cmd.Op1.reg = Rs + X0;
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = Rt + X0;
	cmd.Op3.type = o_displ;
	if (Rn == 31) cmd.Op3.phrase = XSP; else cmd.Op3.phrase = Rn + X0;
	cmd.Op3.addr = 0;
	cmd.Op3.flags = OF_NO_BASE_DISP|OF_SHOW;
	cmd.Op3.dtyp = dt_qword;
	
	switch (size) {
		case 0:
		case 1:
		case 2:
		cmd.Op1.dtyp = dt_dword;
		cmd.Op2.dtyp = dt_dword;
		break;
		case 3:
		cmd.Op1.dtyp = dt_qword;
		cmd.Op2.dtyp = dt_qword;
	}
	
	return 4;
}

static size_t handle_casp(uint32_t code)
{
	uint32_t size = (code >> 30) & 3;
	uint32_t L = (code >> 22) & 1;
	uint32_t o0 = (code >> 15) & 1;
	uint32_t Rs = (code >> 16) & 0x1f;
	uint32_t Rn = (code >> 5) & 0x1f;
	uint32_t Rt = (code) & 0x1f;
	
	uint32_t opcodes[4] = { arm_casp, arm_caspl, arm_caspa, arm_caspal };
	
	cmd.itype = opcodes[(L<<1)+o0];
	cmd.cond = cAL;
	cmd.Op1.type = o_reg;
	cmd.Op1.reg = Rs + X0;
	cmd.Op2.type = o_reg;
	cmd.Op2.reg = Rs + X0 + 1;
	cmd.Op3.type = o_reg;
	cmd.Op3.reg = Rt + X0;
	cmd.Op4.type = o_reg;
	cmd.Op4.reg = Rt + X0 + 1;
	cmd.Op5.type = o_displ;
	if (Rn == 31) cmd.Op5.phrase = XSP; else cmd.Op5.phrase = Rn + X0;
	cmd.Op5.addr = 0;
	cmd.Op5.flags = OF_NO_BASE_DISP|OF_SHOW;
	cmd.Op5.dtyp = dt_qword;
	
	switch (size) {
		case 0:
		cmd.Op1.dtyp = dt_dword;
		cmd.Op2.dtyp = dt_dword;
		cmd.Op3.dtyp = dt_dword;
		cmd.Op4.dtyp = dt_dword;
		break;
		case 1:
		cmd.Op1.dtyp = dt_qword;
		cmd.Op2.dtyp = dt_qword;
		cmd.Op3.dtyp = dt_qword;
		cmd.Op4.dtyp = dt_qword;
	}
	
	return 4;
}

static size_t ana(void)
{
	uint32_t code = get_long(ea++);
	
	/* LDADD.../STADD... */
	if ((code & 0x3F20FC00) == 0x38200000) {
		return handle_ldst(arm_ldclr, code);
	}
	
	/* LDCLR.../STCLR... */
	if ((code & 0x3F20FC00) == 0x38201000) {
		return handle_ldst(arm_ldclr, code);
	}
	
	/* LDEOR.../STEOR... */
	if ((code & 0x3F20FC00) == 0x38202000) {
		return handle_ldst(arm_ldeor, code);
	}
		
	/* LDSET.../STSET... */
	if ((code & 0x3F20FC00) == 0x38203000) {
		return handle_ldst(arm_ldset, code);
	}
	
	/* LDSMAX.../STSMAX... */
	if ((code & 0x3F20FC00) == 0x38204000) {
		return handle_ldst(arm_ldsmax, code);
	}
	
	/* LDSMIN.../STSMIN... */
	if ((code & 0x3F20FC00) == 0x38205000) {
		return handle_ldst(arm_ldsmin, code);
	}
	
	/* LDUMAX.../STUMAX... */
	if ((code & 0x3F20FC00) == 0x38206000) {
		return handle_ldst(arm_ldumax, code);
	}
	
	/* LDUMIN.../STUMIN... */
	if ((code & 0x3F20FC00) == 0x38207000) {
		return handle_ldst(arm_ldumin, code);
	}

	/* LDUMIN.../STUMIN... */
	if ((code & 0x3F20FC00) == 0x38208000) {
		return handle_swp(arm_swp, code);
	}
	
	/* CASP... */
	if ((code & 0xBFA07C00) == 0x08207C00) {
		return handle_casp(code);
	}
	
	/* CAS... */
	if ((code & 0x3FA07C00) == 0x08A07C00) {
		uint32_t size = (code >> 30) & 3;
		uint32_t L = (code >> 22) & 1;
		uint32_t o0 = (code >> 15) & 1;
		uint32_t Rs = (code >> 16) & 0x1f;
		uint32_t Rn = (code >> 5) & 0x1f;
		uint32_t Rt = (code) & 0x1f;
		
		uint32_t opcodes[4][4] = 
			{	{arm_casb, arm_caslb, arm_casab, arm_casalb }, 
				{arm_cash, arm_caslh, arm_casah, arm_casalh },
				{arm_cas, arm_casl, arm_casa, arm_casal },
				{arm_cas, arm_casl, arm_casa, arm_casal } };
		
		cmd.itype = opcodes[size][(L<<1)+o0];
		cmd.cond = cAL;
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rs + X0;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rt + X0;
		cmd.Op3.type = o_displ;
		if (Rn == 31) cmd.Op3.phrase = XSP; else cmd.Op3.phrase = Rn + X0;
		cmd.Op3.addr = 0;
		cmd.Op3.flags = OF_NO_BASE_DISP|OF_SHOW;
		cmd.Op3.dtyp = dt_qword;
		
		switch (size) {
			case 0:
			case 1:
			case 2:
			cmd.Op1.dtyp = dt_dword;
			cmd.Op2.dtyp = dt_dword;
			break;
			case 3:
			cmd.Op1.dtyp = dt_qword;
			cmd.Op2.dtyp = dt_qword;
		}
		
		return 4;
	}

	return 0;
}

static int idaapi aarch64_extension_callback(void * user_data, int event_id, va_list va)
{
	switch (event_id)
	{
		case processor_t::custom_ana:
		{
			ea = cmd.ea;
			if (is_arm64_ea(ea)) {
				size_t length = ana();
				if (length)
				{
					cmd.size = (uint16)length;
					return 2;
				}
			}
		}
	 	break;
		case processor_t::custom_mnem:
			if ( cmd.itype >= CUSTOM_CMD_ITYPE )
			{
				char *buf   = va_arg(va, char *);
				size_t size = va_arg(va, size_t);
				char *mnem = get_insn_mnem();
				if (mnem == NULL) return 0;
				qstrncpy(buf, get_insn_mnem(), size);
				return 2;
			}
	 	break;
	}
	return 0;
}

static bool enabled = false;
static netnode aarch64_node;
static const char node_name[] = "$ AArch64 v8.1 processor extender parameters";

int idaapi init(void)
{
	if (ph.id != PLFM_ARM) return PLUGIN_SKIP;
	aarch64_node.create(node_name);
	enabled = aarch64_node.altval(0) != MAGIC_DEACTIVATED;
	if (enabled)
	{
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
		msg("AArch64 crypto extension processor extender is enabled\n");
		return PLUGIN_KEEP;
	}
	return PLUGIN_OK;
}


void idaapi term(void)
{
	unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
}

void idaapi run(int /*arg*/)
{
	if (enabled) {
		unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
	} else {
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
	}
	enabled = !enabled;
	aarch64_node.create(node_name);
	aarch64_node.altset(0, enabled ? MAGIC_ACTIVATED : MAGIC_DEACTIVATED);
	info("AUTOHIDE NONE\n" "AArch64 v8.1 processor extender now is %s", enabled ? "enabled" : "disabled");
}

//--------------------------------------------------------------------------
static const char comment[] = "AArch64 v8.1 processor extender";
static const char help[] = "This module adds support for AArch64 v8.1 instructions to IDA.\n";

static const char wanted_name[] = "AArch64 v8.1 processor extender";

static const char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,
	term,
	run,
	comment,
	help,
	wanted_name,
	wanted_hotkey
};

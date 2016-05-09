/*
 * PLASMA : Generate an indented asm code (pseudo-C) with colored syntax.
 * Copyright (C) 2016    Joel
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.    If not, see <http://www.gnu.org/licenses/>.
 */


typedef char bool;
#define true 1
#define false 0

#include <Python.h>
#include <stdlib.h>
#include <capstone/x86.h>

// Same as lib.consts
#define FUNC_OFF_VARS 2
#define FUNC_INST_ADDR 4


// It supports only the most common registers (see capstone.x86)
#define LAST_REG X86_REG_SS
#define NB_REGS (LAST_REG + 1)

#define INVALID_VALUE -1


struct regs_context {
    PyObject_HEAD
    long **regs; // each reg point inside the reg_values array
    bool **is_def; // same thing for is_def_values
    bool *is_stack;
    long *reg_values;
    bool *is_def_values;
};


static PyTypeObject regs_context_T = {
    PyVarObject_HEAD_INIT(0, 0)
    "RegsContext",
    sizeof(struct regs_context),
};


static int REG8[] = {
    X86_REG_AH, X86_REG_AL, X86_REG_BH, X86_REG_BL, X86_REG_BPL,
    X86_REG_CL, X86_REG_CH, X86_REG_DIL, X86_REG_DL, X86_REG_DH,
    X86_REG_SIL, X86_REG_SPL};
static int REG16[] = {
    X86_REG_BP, X86_REG_AX, X86_REG_BX, X86_REG_CX, X86_REG_CS,
    X86_REG_DI, X86_REG_DS, X86_REG_DX, X86_REG_ES, X86_REG_FS,
    X86_REG_GS, X86_REG_IP, X86_REG_SI, X86_REG_SP, X86_REG_SS};
static int REG32[] = {
    X86_REG_EAX, X86_REG_EBP, X86_REG_EBX, X86_REG_ECX, X86_REG_EDI,
    X86_REG_EDX, X86_REG_EIP, X86_REG_ESI, X86_REG_ESP};
static int REG64[] = {
    X86_REG_RAX, X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI,
    X86_REG_RDX, X86_REG_RIP, X86_REG_RSI, X86_REG_RSP};


static inline long py_aslong2(PyObject *obj, const char *name)
{
    PyObject *tmp = PyObject_GetAttrString(obj, name);
    long n = PyLong_AsUnsignedLongMask(tmp);
    Py_DECREF(tmp);
    return n;
}

static inline long py_aslong3(PyObject *obj, const char *name1, const char *name2)
{
    PyObject *tmp = PyObject_GetAttrString(obj, name1);
    PyObject *tmp2 = PyObject_GetAttrString(tmp, name2);
    long n = PyLong_AsUnsignedLongMask(tmp2);
    Py_DECREF(tmp);
    Py_DECREF(tmp2);
    return n;
}

static int is_reg8(int r)
{
    unsigned int i;
    for (i = 0 ; i < sizeof(REG8) / sizeof(REG8[0]) ; i++)
        if (REG8[i] == r)
            return 1;
    return 0;
}

static int is_reg16(int r)
{
    unsigned int i;
    for (i = 0 ; i < sizeof(REG16) / sizeof(REG16[0]) ; i++)
        if (REG16[i] == r)
            return 1;
    return 0;
}

static int is_reg32(int r)
{
    unsigned int i;
    for (i = 0 ; i < sizeof(REG32) / sizeof(REG32[0]) ; i++)
        if (REG32[i] == r)
            return 1;
    return 0;
}

static int is_reg64(int r)
{
    unsigned int i;
    for (i = 0 ; i < sizeof(REG64) / sizeof(REG64[0]); i++)
        if (REG64[i] == r)
            return 1;
    return 0;
}

static PyObject *new_regs_context(PyObject *self, PyObject *args)
{
    int i;
    struct regs_context *r;
    r = PyObject_NEW(struct regs_context, &regs_context_T);

    r->regs = (long**) malloc(NB_REGS * sizeof(long*));
    r->reg_values = (long*) malloc(NB_REGS * sizeof(long));
    r->is_stack = (bool*) malloc(NB_REGS * sizeof(bool));
    r->is_def = (bool**) malloc(NB_REGS * sizeof(bool*));
    r->is_def_values = (bool*) malloc(NB_REGS * sizeof(bool));

    if (r == NULL || r->regs == NULL || r->reg_values == NULL ||
        r->is_stack == NULL || r->is_def == NULL || r->is_def_values == NULL) {
        // fatal error, but don't quit to let the user save the database
        fprintf(stderr, "error: no more memory !!\n");
        Py_RETURN_NONE;
    }

    for (i = 0 ; i <= LAST_REG ; i++) {
        r->is_stack[i] = false;
        r->is_def_values[i] = false;
        r->is_def[i] = &r->is_def_values[i];
        r->regs[i] = &r->reg_values[i];
    }

    r->regs[X86_REG_AL] = &r->reg_values[X86_REG_RAX];
    r->regs[X86_REG_AH] = &r->reg_values[X86_REG_RAX] + 1;
    r->regs[X86_REG_BL] = &r->reg_values[X86_REG_RBX];
    r->regs[X86_REG_BH] = &r->reg_values[X86_REG_RBX] + 1;
    r->regs[X86_REG_CL] = &r->reg_values[X86_REG_RCX];
    r->regs[X86_REG_CH] = &r->reg_values[X86_REG_RCX] + 1;
    r->regs[X86_REG_DL] = &r->reg_values[X86_REG_RDX];
    r->regs[X86_REG_DH] = &r->reg_values[X86_REG_RDX] + 1;

    r->regs[X86_REG_DIL] = &r->reg_values[X86_REG_RDI];
    r->regs[X86_REG_SIL] = &r->reg_values[X86_REG_RSI];
    r->regs[X86_REG_SPL] = &r->reg_values[X86_REG_RSP];
    r->regs[X86_REG_BPL] = &r->reg_values[X86_REG_RBP];

    r->regs[X86_REG_AX] = &r->reg_values[X86_REG_RAX];
    r->regs[X86_REG_BX] = &r->reg_values[X86_REG_RBX];
    r->regs[X86_REG_CX] = &r->reg_values[X86_REG_RCX];
    r->regs[X86_REG_DX] = &r->reg_values[X86_REG_RDX];
    r->regs[X86_REG_DI] = &r->reg_values[X86_REG_RDI];
    r->regs[X86_REG_SI] = &r->reg_values[X86_REG_RSI];
    r->regs[X86_REG_IP] = &r->reg_values[X86_REG_RIP];
    r->regs[X86_REG_BP] = &r->reg_values[X86_REG_RBP];
    r->regs[X86_REG_SP] = &r->reg_values[X86_REG_RSP];

    r->regs[X86_REG_EAX] = &r->reg_values[X86_REG_RAX];
    r->regs[X86_REG_EBX] = &r->reg_values[X86_REG_RBX];
    r->regs[X86_REG_ECX] = &r->reg_values[X86_REG_RCX];
    r->regs[X86_REG_EDX] = &r->reg_values[X86_REG_RDX];
    r->regs[X86_REG_EDI] = &r->reg_values[X86_REG_RDI];
    r->regs[X86_REG_ESI] = &r->reg_values[X86_REG_RSI];
    r->regs[X86_REG_EIP] = &r->reg_values[X86_REG_RIP];
    r->regs[X86_REG_EBP] = &r->reg_values[X86_REG_RBP];
    r->regs[X86_REG_ESP] = &r->reg_values[X86_REG_RSP];

    r->is_def[X86_REG_AL] = &r->is_def_values[X86_REG_RAX];
    r->is_def[X86_REG_AH] = &r->is_def_values[X86_REG_RAX];
    r->is_def[X86_REG_BL] = &r->is_def_values[X86_REG_RBX];
    r->is_def[X86_REG_BH] = &r->is_def_values[X86_REG_RBX];
    r->is_def[X86_REG_CL] = &r->is_def_values[X86_REG_RCX];
    r->is_def[X86_REG_CH] = &r->is_def_values[X86_REG_RCX];
    r->is_def[X86_REG_DL] = &r->is_def_values[X86_REG_RDX];
    r->is_def[X86_REG_DH] = &r->is_def_values[X86_REG_RDX];

    r->is_def[X86_REG_DIL] = &r->is_def_values[X86_REG_RDI];
    r->is_def[X86_REG_SIL] = &r->is_def_values[X86_REG_RSI];
    r->is_def[X86_REG_SPL] = &r->is_def_values[X86_REG_RSP];
    r->is_def[X86_REG_BPL] = &r->is_def_values[X86_REG_RBP];

    r->is_def[X86_REG_AX] = &r->is_def_values[X86_REG_RAX];
    r->is_def[X86_REG_BX] = &r->is_def_values[X86_REG_RBX];
    r->is_def[X86_REG_CX] = &r->is_def_values[X86_REG_RCX];
    r->is_def[X86_REG_DX] = &r->is_def_values[X86_REG_RDX];
    r->is_def[X86_REG_DI] = &r->is_def_values[X86_REG_RDI];
    r->is_def[X86_REG_SI] = &r->is_def_values[X86_REG_RSI];
    r->is_def[X86_REG_IP] = &r->is_def_values[X86_REG_RIP];
    r->is_def[X86_REG_BP] = &r->is_def_values[X86_REG_RBP];
    r->is_def[X86_REG_SP] = &r->is_def_values[X86_REG_RSP];

    r->is_def[X86_REG_EAX] = &r->is_def_values[X86_REG_RAX];
    r->is_def[X86_REG_EBX] = &r->is_def_values[X86_REG_RBX];
    r->is_def[X86_REG_ECX] = &r->is_def_values[X86_REG_RCX];
    r->is_def[X86_REG_EDX] = &r->is_def_values[X86_REG_RDX];
    r->is_def[X86_REG_EDI] = &r->is_def_values[X86_REG_RDI];
    r->is_def[X86_REG_ESI] = &r->is_def_values[X86_REG_RSI];
    r->is_def[X86_REG_EIP] = &r->is_def_values[X86_REG_RIP];
    r->is_def[X86_REG_EBP] = &r->is_def_values[X86_REG_RBP];
    r->is_def[X86_REG_ESP] = &r->is_def_values[X86_REG_RSP];

    *(r->regs[X86_REG_RSP]) = 0;
    *(r->is_def[X86_REG_RSP]) = true;
    r->is_stack[X86_REG_RSP] = true;
    r->is_stack[X86_REG_ESP] = true;
    r->is_stack[X86_REG_SP] = true;

    return (PyObject*) r;
}

static PyObject *clone_regs_context(PyObject *self, PyObject *args)
{
    int i;
    struct regs_context *regs, *new;

    if (!PyArg_ParseTuple(args, "O", &regs))
        Py_RETURN_NONE;

    new = (struct regs_context*) new_regs_context(self, args);

    for (i = 0 ; i <= LAST_REG ; i++) {
        *(new->regs[i]) = *(regs->regs[i]);
        *(new->is_def[i]) = *(regs->is_def[i]);
        new->is_stack[i] = regs->is_stack[i];
    }

    return (PyObject*) new;
}

static void regs_context_dealloc(PyObject *self)
{
    struct regs_context *r = (struct regs_context*) self;
    free(r->regs);
    free(r->is_def);
    free(r->is_def_values);
    free(r->is_stack);
    free(r->reg_values);
}

static inline int is_reg_supported(int r)
{
    return r > 0 && r <= LAST_REG;
}

static inline int is_reg_defined(struct regs_context *self, int r)
{
    return is_reg_supported(r) && *(self->is_def[r]);
}

static PyObject* reg_value(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    int r;

    if (!PyArg_ParseTuple(args, "OB", &regs, &r))
        Py_RETURN_NONE;

    if (!is_reg_defined(regs, r))
        Py_RETURN_NONE;

    return PyLong_FromLong(*(regs->regs[r]));
}

static void reg_mov(struct regs_context *self, int r, long v)
{
    if (is_reg64(r)) {
        *(self->regs[r]) = (long) v;
        *(self->is_def[r]) = true;
    }
    else if (is_reg32(r)) {
        *((int*) self->regs[r]) = (int) v;
        *(self->is_def[r]) = true;
    }
    else if (is_reg8(r)) {
        *((char*) self->regs[r]) = (char) v;
        *(self->is_def[r]) = true;
    }
    else if (is_reg16(r)) {
        *((short*) self->regs[r]) = (short) v;
        *(self->is_def[r]) = true;
    }
}

static void reg_add(struct regs_context *self, int r, long v)
{
    if (is_reg64(r))
        *(self->regs[r]) += (long) v;
    else if (is_reg32(r))
        *((int*) self->regs[r]) += (int) v;
    else if (is_reg8(r))
        *((char*) self->regs[r]) += (char) v;
    else if (is_reg16(r))
        *((short*) self->regs[r]) += (short) v;
}

static void reg_sub(struct regs_context *self, int r, long v)
{
    if (is_reg64(r))
        *(self->regs[r]) -= (long) v;
    else if (is_reg32(r))
        *((int*) self->regs[r]) -= (int) v;
    else if (is_reg8(r))
        *((char*) self->regs[r]) -= (char) v;
    else if (is_reg16(r))
        *((short*) self->regs[r]) -= (short) v;
}

static void reg_or(struct regs_context *self, int r, long v)
{
    if (is_reg64(r))
        *(self->regs[r]) |= (long) v;
    else if (is_reg32(r))
        *((int*) self->regs[r]) |= (int) v;
    else if (is_reg8(r))
        *((char*) self->regs[r]) |= (char) v;
    else if (is_reg16(r))
        *((short*) self->regs[r]) |= (short) v;
}

static void reg_and(struct regs_context *self, int r, long v)
{
    if (is_reg64(r))
        *(self->regs[r]) &= (long) v;
    else if (is_reg32(r))
        *((int*) self->regs[r]) &= (int) v;
    else if (is_reg8(r))
        *((char*) self->regs[r]) &= (char) v;
    else if (is_reg16(r))
        *((short*) self->regs[r]) &= (short) v;
}

static void reg_xor(struct regs_context *self, int r, long v)
{
    if (is_reg64(r))
        *(self->regs[r]) ^= (long) v;
    else if (is_reg32(r))
        *((int*) self->regs[r]) ^= (int) v;
    else if (is_reg8(r))
        *((char*) self->regs[r]) ^= (char) v;
    else if (is_reg16(r))
        *((short*) self->regs[r]) ^= (short) v;
}

static void reg_inc(struct regs_context *self, int r)
{
    if (is_reg64(r))
        *(self->regs[r]) += 1;
    else if (is_reg32(r))
        *((int*) self->regs[r]) += 1;
    else if (is_reg8(r))
        *((char*) self->regs[r]) += 1;
    else if (is_reg16(r))
        *((short*) self->regs[r]) += 1;
}

static void reg_dec(struct regs_context *self, int r)
{
    if (is_reg64(r))
        *(self->regs[r]) -= 1;
    else if (is_reg32(r))
        *((int*) self->regs[r]) -= 1;
    else if (is_reg8(r))
        *((char*) self->regs[r]) -= 1;
    else if (is_reg16(r))
        *((short*) self->regs[r]) -= 1;
}

static inline int get_insn_address(PyObject *op)
{
    return py_aslong2(op, "address");
}

static inline int get_insn_size(PyObject *op)
{
    return py_aslong2(op, "size");
}

static inline int get_op_type(PyObject *op)
{
    return py_aslong2(op, "type");
}

static inline int get_op_reg(PyObject *op)
{
    return py_aslong3(op, "value", "reg");
}

static inline int get_op_size(PyObject *op)
{
    return py_aslong2(op, "size");
}

static inline int get_op_mem_base(PyObject *op)
{
    return py_aslong3(op, "mem", "base");
}

static inline int get_op_mem_index(PyObject *op)
{
    return py_aslong3(op, "mem", "index");
}

static inline int get_op_mem_segment(PyObject *op)
{
    return py_aslong3(op, "mem", "segment");
}

static inline int get_op_mem_scale(PyObject *op)
{
    return py_aslong3(op, "mem", "scale");
}

static inline int get_op_mem_disp(PyObject *op)
{
    return py_aslong3(op, "mem", "disp");
}

static inline long get_op_imm(PyObject *op)
{
    long imm = py_aslong3(op, "value", "imm");
    switch (get_op_size(op)) {
        case 1:
            return (long) ((char) imm);
        case 2:
            return (long) ((short) imm);
        case 4:
            return (long) ((int) imm);
        case 8:
            return imm;
    }
    // should not happen
    return 0;
}

static long get_reg_value(struct regs_context *regs, int r)
{
    if (is_reg64(r))
        return (long) *((long*) regs->regs[r]);
    if (is_reg32(r))
        return (long) *((int*) regs->regs[r]);
    if (is_reg8(r))
        return (long) *((char*) regs->regs[r]);
    if (is_reg16(r))
        return (long) *((short*) regs->regs[r]);
    // should not happen
    return 0;
}

// out : value, is_stack
// return true if there is an error (example: a register is invalid or
// not defined)
static bool get_op_value(struct regs_context *regs, PyObject *insn, 
                         PyObject *op, long *value, bool *is_stack)
{
    int r, base, index, scale;
    long imm;
    switch (get_op_type(op)) {
        case X86_OP_IMM:
            *value = get_op_imm(op);
            *is_stack = false;
            break;

        case X86_OP_REG:
            r = get_op_reg(op);
            if (!is_reg_defined(regs, r))
                return true;
            *value = get_reg_value(regs, r);
            *is_stack = regs->is_stack[r];
            break;

        case X86_OP_MEM:
            if (get_op_mem_segment(op) != 0) // FIXME
                return true;

            *is_stack = false;
            scale = get_op_mem_scale(op);
            imm = get_op_mem_disp(op);

            base = get_op_mem_base(op);
            if (base) {
                if (base == X86_REG_RIP || base == X86_REG_EIP) {
                    imm += get_insn_address(insn) + get_insn_size(insn);
                }
                else {
                    if (!is_reg_defined(regs, base))
                        return true;
                    imm += get_reg_value(regs, base);
                    *is_stack = regs->is_stack[base];
                }
            }

            index = get_op_mem_index(op);
            if (index) {
                if (index == X86_REG_RIP || index == X86_REG_EIP) {
                    imm += (get_insn_address(insn) + get_insn_size(insn)) * scale;
                }
                else {
                    if (!is_reg_defined(regs, index))
                        return true;
                    imm += get_reg_value(regs, index) * scale;
                    *is_stack |= regs->is_stack[index];
                    if (*is_stack && scale > 1) // FIXME
                        return true;
                }
            }

            *value = imm;
            break;

        default:
            return true;
    }

    return false;
}


static PyObject* analyze_operands(PyObject *self, PyObject *args)
{
    int i;
    PyObject *analyzer;
    struct regs_context *regs;
    PyObject *insn;
    PyObject *func_obj;

    // See the FIXME in lib.analyzer.__sub_analyze_flow
    // this is a hack for the cdecl calling convention.
    bool one_call_called;
 
    if (!PyArg_ParseTuple(args, "OOOOB",
            &analyzer, &regs, &insn, &func_obj, &one_call_called))
        Py_RETURN_NONE;

    int id = py_aslong2(insn, "id");

    PyObject *list_ops = PyObject_GetAttrString(insn, "operands");
    int len_ops = PyList_Size(list_ops);

    if (len_ops == 0)
        goto end;

    PyObject *ops[2];

    ops[0] = len_ops >= 1 ? PyList_GET_ITEM(list_ops, 0) : NULL;
    ops[1] = len_ops == 2 ? PyList_GET_ITEM(list_ops, 1) : NULL;

    // TODO : not supported
    if (len_ops > 2) {
        if (get_op_type(ops[0]) != X86_OP_REG)
            goto end;

        int r1 = get_op_reg(ops[0]);

        if (!is_reg_supported(r1))
            goto end;

        *(regs->is_def[r1]) = false;
        goto end;
    }

    if (id == X86_INS_XOR) {
        if (get_op_type(ops[0]) != X86_OP_REG)
            goto end;

        int r1 = get_op_reg(ops[0]);

        if (!is_reg_supported(r1))
            goto end;

        if (r1 == get_op_reg(ops[1])) {
            reg_mov(regs, r1, 0);
            goto end;
        }
    }

    long values[2] = {0, 0};
    bool is_stack[2] = {false, false};
    bool err[2];

    if (len_ops == 1) {
        // Stack simualation not supported, just update the stack register
        if (id == X86_INS_POP) {
            reg_add(regs, X86_REG_RSP, get_op_size(ops[0]));

            if (get_op_type(ops[0]) != X86_OP_REG)
                goto end;

            int r1 = get_op_reg(ops[0]);

            if (!is_reg_supported(r1))
                goto end;

            *(regs->is_def[r1]) = false;
        }
        else if (id == X86_INS_PUSH) {
            reg_sub(regs, X86_REG_RSP, get_op_size(ops[0]));
            goto analyze_push_value;
        }
        else {
            int r = get_op_reg(ops[0]);
            if (!is_reg_defined(regs, r))
                goto end;
            if (id == X86_INS_INC)
                reg_inc(regs, r);
            else if (id == X86_INS_DEC)
                reg_dec(regs, r);
        }
        goto end;
    }

analyze_push_value:

    // Save operands values and search stack variables

    for (i = 0 ; i < len_ops ; i++) {
        err[i] = get_op_value(regs, insn, ops[i], &values[i], &is_stack[i]);

        if (err[i])
            continue;

        if (get_op_type(ops[i]) == X86_OP_MEM) {
            // Pointers are not dereferenced actually.
            // So it means that we will not simulate this instruction.
            err[i] = true;

            // Check if there is a stack reference
            if (is_stack[i] && func_obj != Py_None) {
                PyObject *tmp;
                PyObject *db = PyObject_GetAttrString(analyzer, "db");
                PyObject *mem = PyObject_GetAttrString(db, "mem");

                PyObject *ty = PyObject_CallMethod(mem, "find_type", "i",
                                                   get_op_size(ops[i]));

                // The second item is the name of the variable
                // func_obj[FUNC_OFF_VARS][v] = [ty, None]
                tmp = PyList_GET_ITEM(func_obj, FUNC_OFF_VARS);
                Py_INCREF(tmp);
                PyObject *l = PyList_New(2);
                PyList_SET_ITEM(l, 0, ty);
                PyList_SET_ITEM(l, 1, Py_None);
                PyDict_SetItem(tmp, PyLong_FromLong(values[i]), l);
                Py_DECREF(tmp);

                // func_obj[FUNC_INST_ADDR][i.address] = v
                tmp = PyList_GET_ITEM(func_obj, FUNC_INST_ADDR);
                Py_INCREF(tmp);
                PyDict_SetItem(tmp, PyObject_GetAttrString(insn, "address"),
                               PyLong_FromLong(values[i]));
                Py_DECREF(tmp);

                Py_DECREF(db);
                Py_DECREF(mem);
                continue;
            }
        }

        PyObject_CallMethod(analyzer, "analyze_imm", "OOi",
                            insn, ops[i], values[i]);
    }
    
    if (id == X86_INS_PUSH)
        goto end;

    if (get_op_type(ops[0]) != X86_OP_REG)
        goto end;

    int r1 = get_op_reg(ops[0]);

    if (!is_reg_supported(r1))
        goto end;

    if (id == X86_INS_MOV) {
        if (err[1]) {
            // Unset the first register which is the destination in x86
            *(regs->is_def[r1]) = false;
            goto end;
        }
        reg_mov(regs, r1, values[1]);
        regs->is_stack[r1] = is_stack[1];
        goto end;
    }

    if (err[0] || err[1]) {
        // Unset the first register which is the destination in x86
        *(regs->is_def[r1]) = false;
        goto end;
    }

    regs->is_stack[r1] = is_stack[0] | is_stack[1];

    switch (id) {
        case X86_INS_ADD:
            // Update the register only if this is not a cdecl call (supposed)
            if (!one_call_called || (r1 != X86_REG_RSP &&
                    r1 != X86_REG_ESP && r1 != X86_REG_SP))
                reg_add(regs, r1, values[1]);
            break;

        case X86_INS_SUB:
            reg_sub(regs, r1, values[1]);
            break;

        case X86_INS_XOR:
            reg_xor(regs, r1, values[1]);
            break;

        case X86_INS_AND:
            reg_and(regs, r1, values[1]);
            break;

        case X86_INS_OR:
            reg_or(regs, r1, values[1]);
            break;

        default:
            // Can't simulate this instruction, so unset the value of the register
            *(regs->is_def[r1]) = false;
    }

end:
    Py_DECREF(list_ops);
    Py_RETURN_NONE;
}


static PyMethodDef mod_methods[] = {
    { "new_regs_context", new_regs_context, METH_VARARGS },
    { "clone_regs_context", clone_regs_context, METH_VARARGS },
    { "analyze_operands", analyze_operands, METH_VARARGS },
    { "reg_value", reg_value, METH_VARARGS },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef mod_def = {
    PyModuleDef_HEAD_INIT, "analyzer", NULL, -1, mod_methods
};

PyMODINIT_FUNC PyInit_analyzer(void)
{
    regs_context_T.tp_dealloc = regs_context_dealloc;
    return PyModule_Create(&mod_def);
}

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
#define MEM_ACCESS_NOT_COMPLETED 2

#include <Python.h>
#include <stdlib.h>
#include <capstone/x86.h>

// Same as lib.consts
#define FUNC_VARS 2
#define FUNC_INST_VARS_OFF 4
#define FUNC_FRAME_SIZE 5


// It supports only the most common registers (see capstone.x86)
#define LAST_REG X86_REG_SS
#define NB_REGS (LAST_REG + 1)

#define INVALID_VALUE -1


struct regs_context {
    PyObject_HEAD
    long **regs; // each reg point inside the reg_values array
    bool **is_def; // same thing for is_def_values
    bool **is_set;
    bool *is_stack;
    long *reg_values;
    bool *is_def_values;
    bool *is_set_values;
};


// Set by lib.analyzer
static int WORDSIZE = 0;


static PyTypeObject regs_context_T = {
    PyVarObject_HEAD_INIT(0, 0)
    "RegsContext",
    sizeof(struct regs_context),
};

static int reg_size(int r)
{
    switch (r) {
    case X86_REG_AH:
    case X86_REG_AL:
    case X86_REG_BH:
    case X86_REG_BL:
    case X86_REG_BPL:
    case X86_REG_CL:
    case X86_REG_CH:
    case X86_REG_DIL:
    case X86_REG_DL:
    case X86_REG_DH:
    case X86_REG_SIL:
    case X86_REG_SPL:
        return 1;

    case X86_REG_BP:
    case X86_REG_AX:
    case X86_REG_BX:
    case X86_REG_CX:
    case X86_REG_CS:
    case X86_REG_DI:
    case X86_REG_DS:
    case X86_REG_DX:
    case X86_REG_ES:
    case X86_REG_FS:
    case X86_REG_GS:
    case X86_REG_IP:
    case X86_REG_SI:
    case X86_REG_SP:
    case X86_REG_SS:
        return 2;

    case X86_REG_EAX:
    case X86_REG_EBP:
    case X86_REG_EBX:
    case X86_REG_ECX:
    case X86_REG_EDI:
    case X86_REG_EDX:
    case X86_REG_EIP:
    case X86_REG_ESI:
    case X86_REG_ESP:
        return 4;

    case X86_REG_RAX:
    case X86_REG_RBP:
    case X86_REG_RBX:
    case X86_REG_RCX:
    case X86_REG_RDI:
    case X86_REG_RDX:
    case X86_REG_RIP:
    case X86_REG_RSI:
    case X86_REG_RSP:
        return 8;
    }

    return 0;
}

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
    r->is_set = (bool**) malloc(NB_REGS * sizeof(bool*));
    r->is_set_values = (bool*) malloc(NB_REGS * sizeof(bool));

    if (r == NULL || r->regs == NULL || r->reg_values == NULL ||
        r->is_stack == NULL || r->is_def == NULL || r->is_def_values == NULL ||
        r->is_set == NULL || r->is_set_values == NULL) {
        // fatal error, but don't quit to let the user save the database
        fprintf(stderr, "error: no more memory !!\n");
        Py_RETURN_NONE;
    }

    for (i = 0 ; i <= LAST_REG ; i++) {
        r->is_stack[i] = false;
        r->is_def_values[i] = false;
        r->is_set_values[i] = false;
        r->is_def[i] = &r->is_def_values[i];
        r->is_set[i] = &r->is_set_values[i];
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

    r->is_set[X86_REG_AL] = &r->is_set_values[X86_REG_RAX];
    r->is_set[X86_REG_AH] = &r->is_set_values[X86_REG_RAX];
    r->is_set[X86_REG_BL] = &r->is_set_values[X86_REG_RBX];
    r->is_set[X86_REG_BH] = &r->is_set_values[X86_REG_RBX];
    r->is_set[X86_REG_CL] = &r->is_set_values[X86_REG_RCX];
    r->is_set[X86_REG_CH] = &r->is_set_values[X86_REG_RCX];
    r->is_set[X86_REG_DL] = &r->is_set_values[X86_REG_RDX];
    r->is_set[X86_REG_DH] = &r->is_set_values[X86_REG_RDX];

    r->is_set[X86_REG_DIL] = &r->is_set_values[X86_REG_RDI];
    r->is_set[X86_REG_SIL] = &r->is_set_values[X86_REG_RSI];
    r->is_set[X86_REG_SPL] = &r->is_set_values[X86_REG_RSP];
    r->is_set[X86_REG_BPL] = &r->is_set_values[X86_REG_RBP];

    r->is_set[X86_REG_AX] = &r->is_set_values[X86_REG_RAX];
    r->is_set[X86_REG_BX] = &r->is_set_values[X86_REG_RBX];
    r->is_set[X86_REG_CX] = &r->is_set_values[X86_REG_RCX];
    r->is_set[X86_REG_DX] = &r->is_set_values[X86_REG_RDX];
    r->is_set[X86_REG_DI] = &r->is_set_values[X86_REG_RDI];
    r->is_set[X86_REG_SI] = &r->is_set_values[X86_REG_RSI];
    r->is_set[X86_REG_IP] = &r->is_set_values[X86_REG_RIP];
    r->is_set[X86_REG_BP] = &r->is_set_values[X86_REG_RBP];
    r->is_set[X86_REG_SP] = &r->is_set_values[X86_REG_RSP];

    r->is_set[X86_REG_EAX] = &r->is_set_values[X86_REG_RAX];
    r->is_set[X86_REG_EBX] = &r->is_set_values[X86_REG_RBX];
    r->is_set[X86_REG_ECX] = &r->is_set_values[X86_REG_RCX];
    r->is_set[X86_REG_EDX] = &r->is_set_values[X86_REG_RDX];
    r->is_set[X86_REG_EDI] = &r->is_set_values[X86_REG_RDI];
    r->is_set[X86_REG_ESI] = &r->is_set_values[X86_REG_RSI];
    r->is_set[X86_REG_EIP] = &r->is_set_values[X86_REG_RIP];
    r->is_set[X86_REG_EBP] = &r->is_set_values[X86_REG_RBP];
    r->is_set[X86_REG_ESP] = &r->is_set_values[X86_REG_RSP];

    *(r->regs[X86_REG_RSP]) = 0;
    *(r->is_def[X86_REG_RSP]) = true;
    *(r->is_set[X86_REG_RSP]) = true;
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
        new->reg_values[i] = regs->reg_values[i];
        new->is_def_values[i] = regs->is_def_values[i];
        new->is_set_values[i] = regs->is_set_values[i];
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
    free(r->is_set);
    free(r->is_set_values);
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

static inline int is_reg_setted(struct regs_context *self, int r)
{
    return is_reg_supported(r) && *(self->is_set[r]);
}

static PyObject* reg_value(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    int r;

    if (!PyArg_ParseTuple(args, "Oi", &regs, &r))
        Py_RETURN_NONE;

    if (!is_reg_defined(regs, r))
        Py_RETURN_NONE;

    return PyLong_FromLong(*(regs->regs[r]));
}

static PyObject* reg_is_setted(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    int r;

    if (!PyArg_ParseTuple(args, "Oi", &regs, &r))
        Py_RETURN_NONE;

    if (is_reg_setted(regs, r))
        Py_RETURN_TRUE;

    Py_RETURN_FALSE;
}

static void reg_mov(struct regs_context *self, int r, long v)
{
    switch (reg_size(r)) {
    case 8:
        *(self->regs[r]) = (long) v;
        *(self->is_def[r]) = true;
        break;
    case 4:
        *((int*) self->regs[r]) = (int) v;
        *(self->is_def[r]) = true;
        break;
    case 1:
        *((char*) self->regs[r]) = (char) v;
        *(self->is_def[r]) = true;
        break;
    case 2:
        *((short*) self->regs[r]) = (short) v;
        *(self->is_def[r]) = true;
        break;
    }
}

static void reg_add(struct regs_context *self, int r, long v)
{
    switch (reg_size(r)) {
    case 8:
        *(self->regs[r]) += (long) v;
        break;
    case 4:
        *((int*) self->regs[r]) += (int) v;
        break;
    case 1:
        *((char*) self->regs[r]) += (char) v;
        break;
    case 2:
        *((short*) self->regs[r]) += (short) v;
        break;
    }
}

static void reg_sub(struct regs_context *self, int r, long v)
{
    switch (reg_size(r)) {
    case 8:
        *(self->regs[r]) -= (long) v;
        break;
    case 4:
        *((int*) self->regs[r]) -= (int) v;
        break;
    case 1:
        *((char*) self->regs[r]) -= (char) v;
        break;
    case 2:
        *((short*) self->regs[r]) -= (short) v;
        break;
    }
}

static void reg_or(struct regs_context *self, int r, long v)
{
    switch (reg_size(r)) {
    case 8:
        *(self->regs[r]) |= (long) v;
        break;
    case 4:
        *((int*) self->regs[r]) |= (int) v;
        break;
    case 1:
        *((char*) self->regs[r]) |= (char) v;
        break;
    case 2:
        *((short*) self->regs[r]) |= (short) v;
        break;
    }
}

static void reg_and(struct regs_context *self, int r, long v)
{
    switch (reg_size(r)) {
    case 8:
        *(self->regs[r]) &= (long) v;
        break;
    case 4:
        *((int*) self->regs[r]) &= (int) v;
        break;
    case 1:
        *((char*) self->regs[r]) &= (char) v;
        break;
    case 2:
        *((short*) self->regs[r]) &= (short) v;
        break;
    }
}

static void reg_xor(struct regs_context *self, int r, long v)
{
    switch (reg_size(r)) {
    case 8:
        *(self->regs[r]) ^= (long) v;
        break;
    case 4:
        *((int*) self->regs[r]) ^= (int) v;
        break;
    case 1:
        *((char*) self->regs[r]) ^= (char) v;
        break;
    case 2:
        *((short*) self->regs[r]) ^= (short) v;
        break;
    }
}

static PyObject* get_sp(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    if (!PyArg_ParseTuple(args, "O", &regs))
        Py_RETURN_NONE;
    if (WORDSIZE == 8)
        return PyLong_FromLong(*(regs->regs[X86_REG_RSP]));
    if (WORDSIZE == 4)
        return PyLong_FromLong(*((int*) regs->regs[X86_REG_ESP]));
    if (WORDSIZE == 2)
        return PyLong_FromLong(*((short*) regs->regs[X86_REG_SP]));
    Py_RETURN_NONE;
}

static PyObject* set_sp(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    long imm;
    if (!PyArg_ParseTuple(args, "Ol", &regs, &imm))
        Py_RETURN_NONE;
    if (WORDSIZE == 8)
        reg_mov(regs, X86_REG_RSP, imm);
    else if (WORDSIZE == 4)
        reg_mov(regs, X86_REG_ESP, (int) imm);
    else if (WORDSIZE == 2)
        reg_mov(regs, X86_REG_SP, (short) imm);
    Py_RETURN_NONE;
}

static PyObject* set_wordsize(PyObject *self, PyObject *args)
{
    PyArg_ParseTuple(args, "i", &WORDSIZE);
    Py_RETURN_NONE;
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
    switch (reg_size(r)) {
    case 8:
        return (long) *((long*) regs->regs[r]);
    case 4:
        return (long) *((int*) regs->regs[r]);
    case 1:
        return (long) *((char*) regs->regs[r]);
    case 2:
        return (long) *((short*) regs->regs[r]);
    }
    // should not happen
    return 0;
}

// out : value, is_stack
// return true if there is an error (example: a register is invalid or
// not defined)
static bool get_op_value(struct regs_context *regs, PyObject *insn, 
                         PyObject *op, long *value, bool *is_stack)
{
    int r, base, index, scale, disp;
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
            imm = disp = get_op_mem_disp(op);

            base = get_op_mem_base(op);
            if (base) {
                if (base == X86_REG_RIP || base == X86_REG_EIP) {
                    imm += get_insn_address(insn) + get_insn_size(insn);
                }
                else {
                    if (!is_reg_defined(regs, base)) {
                        // just analyze the disp value
                        *value = disp;
                        return MEM_ACCESS_NOT_COMPLETED;
                    }
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
                    if (!is_reg_defined(regs, index)) {
                        // just analyze the disp value
                        *value = disp;
                        return MEM_ACCESS_NOT_COMPLETED;
                    }
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
    int i, r1;
    PyObject *analyzer;
    struct regs_context *regs;
    PyObject *insn;
    PyObject *func_obj;
    PyObject *tmp, *db;

    /* if True: stack variables will not be saved and analysis on immediates
     * will not be run. It will only simulate registers.
     */
    bool only_simulate;

    if (!PyArg_ParseTuple(args, "OOOOb",
                &analyzer, &regs, &insn, &func_obj, &only_simulate))
        Py_RETURN_NONE;

    int id = py_aslong2(insn, "id");

    PyObject *list_ops = PyObject_GetAttrString(insn, "operands");
    int len_ops = PyList_Size(list_ops);

    if (len_ops == 0) {
        switch (id) {
        case X86_INS_LEAVE:
            if (WORDSIZE == 4) {
                if (is_reg_defined(regs, X86_REG_EBP)) // should be true
                    reg_mov(regs, X86_REG_ESP, get_reg_value(regs, X86_REG_EBP));
                reg_add(regs, X86_REG_ESP, WORDSIZE);
            }
            else if (WORDSIZE == 8) {
                if (is_reg_defined(regs, X86_REG_RBP)) // should be true
                    reg_mov(regs, X86_REG_RSP, get_reg_value(regs, X86_REG_RBP));
                reg_add(regs, X86_REG_RSP, WORDSIZE);
            }
            break;

        case X86_INS_POPAW:
        case X86_INS_POPAL:
            if (id == X86_INS_POPAW)
                reg_add(regs, X86_REG_RSP, 8 * 2);
            else
                reg_add(regs, X86_REG_RSP, 8 * 4);
            *(regs->is_def[X86_REG_RAX]) = false;
            *(regs->is_def[X86_REG_RBX]) = false;
            *(regs->is_def[X86_REG_RCX]) = false;
            *(regs->is_def[X86_REG_RDX]) = false;
            *(regs->is_def[X86_REG_RBP]) = false;
            *(regs->is_def[X86_REG_RSI]) = false;
            *(regs->is_def[X86_REG_RDI]) = false;
            break;

        case X86_INS_POPF:
            reg_add(regs, X86_REG_RSP, 2);
            break;

        case X86_INS_POPFD:
            reg_add(regs, X86_REG_RSP, 4);
            break;

        case X86_INS_POPFQ:
            reg_add(regs, X86_REG_RSP, 8);
            break;

        case X86_INS_PUSHAW:
            reg_sub(regs, X86_REG_RSP, 8 * 2);
            break;

        case X86_INS_PUSHAL:
            reg_sub(regs, X86_REG_RSP, 8 * 4);
            break;

        case X86_INS_PUSHF:
            reg_sub(regs, X86_REG_RSP, 2);
            break;

        case X86_INS_PUSHFD:
            reg_sub(regs, X86_REG_RSP, 4);
            break;

        case X86_INS_PUSHFQ:
            reg_sub(regs, X86_REG_RSP, 8);
            break;
        }

        goto end;
    }

    PyObject *ops[2];

    ops[0] = len_ops >= 1 ? PyList_GET_ITEM(list_ops, 0) : NULL;
    ops[1] = len_ops == 2 ? PyList_GET_ITEM(list_ops, 1) : NULL;

    // FIXME : not supported
    if (len_ops > 2) {
        if (get_op_type(ops[0]) != X86_OP_REG)
            goto end;

        r1 = get_op_reg(ops[0]);

        if (!is_reg_supported(r1))
            goto end;

        *(regs->is_def[r1]) = false;
        goto end;
    }

    if (id == X86_INS_XOR) {
        if (get_op_type(ops[0]) != X86_OP_REG)
            goto end;

        r1 = get_op_reg(ops[0]);

        if (!is_reg_supported(r1))
            goto end;

        *(regs->is_set[r1]) = true;

        if (r1 == get_op_reg(ops[1])) {
            reg_mov(regs, r1, 0);
            goto save_imm;
        }
    }

    long values[2] = {0, 0};
    bool is_stack[2] = {false, false};
    bool err[2];

    if (len_ops == 1) {
        // Stack simualation not supported, just update the stack register
        switch (id) {
        case X86_INS_POP:
            reg_add(regs, X86_REG_RSP, get_op_size(ops[0]));
            if (get_op_type(ops[0]) == X86_OP_REG) {
                r1 = get_op_reg(ops[0]);
                if (is_reg_supported(r1)) {
                    *(regs->is_def[r1]) = false;
                    *(regs->is_set[r1]) = true;
                }
            }
            goto end;

        case X86_INS_PUSH:
            reg_sub(regs, X86_REG_RSP, get_op_size(ops[0]));
            break;

        case X86_INS_INC:
        case X86_INS_DEC:
            if (get_op_type(ops[0]) == X86_OP_REG) {
                r1 = get_op_reg(ops[0]);
                if (is_reg_defined(regs, r1)) {
                    if (id == X86_INS_INC)
                        reg_add(regs, r1, 1);
                    else if (id == X86_INS_DEC)
                        reg_sub(regs, r1, 1);
                }
                goto save_imm;
            }
            break;
        }
    }

    // Save operand values and search stack variables

    for (i = 0 ; i < len_ops ; i++) {
        err[i] = get_op_value(regs, insn, ops[i], &values[i], &is_stack[i]);

        if (only_simulate) {
            if (get_op_type(ops[i]) == X86_OP_MEM) {
                if (err[i] == MEM_ACCESS_NOT_COMPLETED)
                    err[i] = true;
                else
                    err[i] = id != X86_INS_LEA;
            }
            continue;
        }

        if (err[i] == true)
            continue;

        if (get_op_type(ops[i]) == X86_OP_MEM) {
            // Pointers are not dereferenced actually.
            // So it means that we will not simulate this instruction.
            if (err[i] == MEM_ACCESS_NOT_COMPLETED)
                err[i] = true;
            else
                err[i] = id != X86_INS_LEA;

            // Check if there is a stack reference
            if (is_stack[i] && func_obj != Py_None &&
                -values[i] <= PyLong_AsLong(PyList_GET_ITEM(func_obj, FUNC_FRAME_SIZE))) {
                PyObject_CallMethod(analyzer, "add_stack_variable", "OOii",
                                    func_obj, insn, values[i],
                                    get_op_size(ops[i]));
                continue;
            }
        }

        PyObject_CallMethod(analyzer, "analyze_imm", "OOiB",
                            insn, ops[i], values[i], false);
    }

    if (id == X86_INS_XADD && get_op_type(ops[1]) == X86_OP_REG) {
        // TODO : unsupported
        int r2 = get_op_reg(ops[1]);
        *(regs->is_def[r2]) = false;
    }

    if (len_ops != 2 || get_op_type(ops[0]) != X86_OP_REG)
        goto end;

    r1 = get_op_reg(ops[0]);

    if (id == X86_INS_MOV || id == X86_INS_LEA) {
        if (!is_reg_supported(r1))
            goto end;

        *(regs->is_set[r1]) = true;

        if (err[1] == true) {
            // Unset the first register which is the destination in x86
            *(regs->is_def[r1]) = false;
            goto end;
        }
        reg_mov(regs, r1, values[1]);
        regs->is_stack[r1] = is_stack[1];
        goto save_imm;
    }

    if (err[0] == true || err[1] == true) {
        if (is_reg_supported(r1))
            // Unset the first register which is the destination in x86
            *(regs->is_def[r1]) = false;
        goto end;
    }

    regs->is_stack[r1] = is_stack[0] | is_stack[1];

    *(regs->is_set[r1]) = true;

    switch (id) {
        case X86_INS_ADD:
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
            goto end;
    }

save_imm:
    if (!regs->is_stack[r1]) {
        long v = get_reg_value(regs, r1);
        bool save;

        if (id != X86_INS_MOV && id != X86_INS_LEA) {
            PyObject *ret = PyObject_CallMethod(
                    analyzer, "analyze_imm", "OOiB", insn, ops[0], v, true);
            save = ret == Py_True;
        } else {
            save = false;
        }

        if (save) {
            db = PyObject_GetAttrString(analyzer, "db");
            tmp = PyObject_GetAttrString(db, "immediates");
            PyDict_SetItem(tmp, PyObject_GetAttrString(insn, "address"),
                           PyLong_FromLong(v));
            Py_DECREF(tmp);
            Py_DECREF(db);
        }
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
    { "reg_is_setted", reg_is_setted, METH_VARARGS },
    { "get_sp", get_sp, METH_VARARGS },
    { "set_sp", set_sp, METH_VARARGS },
    { "set_wordsize", set_wordsize, METH_VARARGS },
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

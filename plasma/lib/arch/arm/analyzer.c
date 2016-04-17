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


// TODO : registers simulation

typedef char bool;
#define true 1
#define false 0

#include <Python.h>
#include <stdlib.h>
#include <capstone/arm.h>

// Same as lib.consts
#define FUNC_OFF_VARS 2
#define FUNC_INST_ADDR 4


// It supports only the most common registers (see capstone.arm)
#define LAST_REG 0
#define NB_REGS (LAST_REG + 1)

#define INVALID_VALUE -1


struct regs_context {
    PyObject_HEAD
    long *regs;
    bool *is_stack;
    bool *is_def;
};

static PyTypeObject regs_context_T = {
    PyVarObject_HEAD_INIT(0, 0)
    "RegsContext",
    sizeof(struct regs_context),
};

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

    r->regs = (long*) malloc(NB_REGS * sizeof(long));
    r->is_stack = (bool*) malloc(NB_REGS * sizeof(bool));
    r->is_def = (bool*) malloc(NB_REGS * sizeof(bool));

    if (r == NULL || r->regs == NULL || r->is_stack == NULL || r->is_def == NULL) {
        // fatal error, but don't quit to let the user save the database
        fprintf(stderr, "error: no more memory !!\n");
        Py_RETURN_NONE;
    }

    for (i = 0 ; i <= LAST_REG ; i++) {
        r->is_stack[i] = false;
        r->is_def[i] = false;
    }

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
        new->regs[i] = regs->regs[i];
        new->is_def[i] = regs->is_def[i];
        new->is_stack[i] = regs->is_stack[i];
    }

    return (PyObject*) new;
}

static void regs_context_dealloc(PyObject *self)
{
    struct regs_context *r = (struct regs_context*) self;
    free(r->regs);
    free(r->is_def);
    free(r->is_stack);
}

static inline int is_reg_supported(int r)
{
    return r > 0 && r <= LAST_REG;
}

static inline int is_reg_defined(struct regs_context *self, int r)
{
    return is_reg_supported(r) && self->is_def[r];
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

static inline int get_op_mem_size(int insn_id)
{
    return 0;
}

static inline int get_op_mem_index(PyObject *op)
{
    return py_aslong3(op, "mem", "index");
}

static inline int get_op_mem_base(PyObject *op)
{
    return py_aslong3(op, "mem", "base");
}

static inline int get_op_mem_disp(PyObject *op)
{
    return py_aslong3(op, "mem", "disp");
}

static inline long get_op_imm(PyObject *op)
{
    return py_aslong3(op, "value", "imm");
}

// out : value, is_stack
// return true if there is an error (example: a register is invalid or
// not defined)
static bool get_op_value(struct regs_context *regs, PyObject *insn, 
                         PyObject *op, long *value, bool *is_stack)
{
    int disp;
    switch (get_op_type(op)) {
        case ARM_OP_IMM:
            *value = get_op_imm(op);
            *is_stack = false;
            break;

        case ARM_OP_MEM:
            if (get_op_mem_index(op) == 0 && get_op_mem_base(op) == ARM_REG_PC) {
                disp = get_op_mem_disp(op);
                *value = get_insn_address(insn) + get_insn_size(insn) * 2 + disp;
                *is_stack = false;
                return false;
            }
            return true;

        default:
            return true;
    }

    return false;
}

static PyObject* reg_value(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    int r;

    if (!PyArg_ParseTuple(args, "OB", &regs, &r))
        Py_RETURN_NONE;

    if (!is_reg_defined(regs, r))
        Py_RETURN_NONE;

    return PyLong_FromLong(regs->regs[r]);
}

static PyObject* analyze_operands(PyObject *self, PyObject *args)
{
    int i;
    PyObject *analyzer;
    struct regs_context *regs;
    PyObject *insn;
    PyObject *func_obj;
    bool one_call_called;

    if (!PyArg_ParseTuple(args, "OOOOB",
            &analyzer, &regs, &insn, &func_obj, &one_call_called))
        Py_RETURN_NONE;

    PyObject *list_ops = PyObject_GetAttrString(insn, "operands");
    int len_ops = PyList_Size(list_ops);

    // FIXME
    if (len_ops <= 1 || len_ops > 3)
        goto end;

    PyObject *ops[3];

    ops[0] = len_ops >= 1 ? PyList_GET_ITEM(list_ops, 0) : NULL;
    ops[1] = len_ops >= 2 ? PyList_GET_ITEM(list_ops, 1) : NULL;
    ops[2] = len_ops == 3 ? PyList_GET_ITEM(list_ops, 2) : NULL;

    // Save operands values and search stack variables

    long values[3] = {0, 0, 0};
    bool is_stack[3] = {false, false, false};
    bool err[3];

    // The first operand is always a register and always the destination
    int r1 = get_op_reg(ops[0]);
    err[0] = !is_reg_supported(r1);

    for (i = 1 ; i < len_ops ; i++) {
        err[i] = get_op_value(regs, insn, ops[i], &values[i], &is_stack[i]);

        if (err[i])
            continue;

        PyObject_CallMethod(analyzer, "analyze_imm", "OOi",
                            insn, ops[i], values[i]);
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

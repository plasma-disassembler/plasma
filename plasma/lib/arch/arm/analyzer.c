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
#define FUNC_FRAME_SIZE 5


// It supports only the most common registers (see capstone.arm)
#define LAST_REG ARM_REG_S31
#define NB_REGS (LAST_REG + 1)

#define INVALID_VALUE -1

// Set by lib.analyzer
static int WORDSIZE = 0;


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

static inline bool is_load(int insn_id)
{
    switch (insn_id) {
    case ARM_INS_LDA:
    case ARM_INS_LDAB:
    case ARM_INS_LDAEX:
    case ARM_INS_LDAEXB:
    case ARM_INS_LDAEXD:
    case ARM_INS_LDAEXH:
    case ARM_INS_LDAH:
    case ARM_INS_LDC2L:
    case ARM_INS_LDC2:
    case ARM_INS_LDCL:
    case ARM_INS_LDC:
    case ARM_INS_LDMDA:
    case ARM_INS_LDMDB:
    case ARM_INS_LDM:
    case ARM_INS_LDMIB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDRB:
    case ARM_INS_LDRD:
    case ARM_INS_LDREX:
    case ARM_INS_LDREXB:
    case ARM_INS_LDREXD:
    case ARM_INS_LDREXH:
    case ARM_INS_LDRH:
    case ARM_INS_LDRHT:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSBT:
    case ARM_INS_LDRSH:
    case ARM_INS_LDRSHT:
    case ARM_INS_LDRT:
    case ARM_INS_LDR:
        return true;
    }
    return false;
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

    r->regs[ARM_REG_SP] = 0;
    r->is_def[ARM_REG_SP] = true;
    r->is_stack[ARM_REG_SP] = true;

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

static PyObject* set_wordsize(PyObject *self, PyObject *args)
{
    PyArg_ParseTuple(args, "i", &WORDSIZE);
    Py_RETURN_NONE;
}

static inline int is_reg_supported(int r)
{
    return r > 0 && r <= LAST_REG;
}

static inline int is_reg_defined(struct regs_context *self, int r)
{
    return is_reg_supported(r) && self->is_def[r];
}

static inline void reg_mov(struct regs_context *self, int r, long v)
{
    self->regs[r] = (long) v;
    self->is_def[r] = true;
}

static inline void reg_add(struct regs_context *self, int r, int v1, int v2)
{
    *((int*) &self->regs[r]) = v1 + v2;
}

static inline void reg_sub(struct regs_context *self, int r, int v1, int v2)
{
    *((int*) &self->regs[r]) = v1 - v2;
}

static inline void reg_and(struct regs_context *self, int r, int v1, int v2)
{
    *((int*) &self->regs[r]) = v1 & v2;
}

static PyObject* get_sp(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    if (!PyArg_ParseTuple(args, "O", &regs))
        Py_RETURN_NONE;
    return PyLong_FromLong((int) regs->regs[ARM_REG_SP]);
}

static PyObject* set_sp(PyObject *self, PyObject *args)
{
    struct regs_context *regs;
    long imm;
    if (!PyArg_ParseTuple(args, "Ol", &regs, &imm))
        Py_RETURN_NONE;
    reg_mov(regs, ARM_REG_SP, (int) imm);
    Py_RETURN_NONE;
}

static inline int get_insn_address(PyObject *op)
{
    return py_aslong2(op, "address");
}

static long get_reg_value(struct regs_context *regs, int r)
{
    return (long) regs->regs[r];
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

static inline int get_op_mem_shift_type(PyObject *op)
{
    return py_aslong3(op, "shift", "type");
}

static inline int get_op_mem_scale(PyObject *op)
{
    return py_aslong3(op, "mem", "scale");
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
        case ARM_OP_IMM:
            *value = get_op_imm(op);
            *is_stack = false;
            break;

        case ARM_OP_REG:
            r = get_op_reg(op);
            if (!is_reg_defined(regs, r))
                return true;
            *value = get_reg_value(regs, r);
            *is_stack = regs->is_stack[r];
            break;

        case ARM_OP_MEM:
            *is_stack = false;
            scale = get_op_mem_scale(op);
            imm = disp = get_op_mem_disp(op);

            base = get_op_mem_base(op);
            if (base) {
                if (base == ARM_REG_PC) {
                    imm += get_insn_address(insn) + get_insn_size(insn) * 2;
                }
                else {
                    if (!is_reg_defined(regs, base)) {
                        // just analyze the disp value
                        *value = disp;
                        return false;
                    }
                    imm += get_reg_value(regs, base);
                    *is_stack = regs->is_stack[base];
                }
            }

            index = get_op_mem_index(op);
            if (index) {
                if (get_op_mem_shift_type(op) != 0) // FIXME
                    return true;

                if (index == ARM_REG_PC) {
                    imm += (get_insn_address(insn) + get_insn_size(insn) * 2) * scale;
                }
                else {
                    if (!is_reg_defined(regs, index)) {
                        // just analyze the disp value
                        *value = disp;
                        return false;
                    }
                    imm += get_reg_value(regs, index) * scale;
                    *is_stack |= regs->is_stack[index];
                    if (*is_stack && scale > 1) // FIXME
                        return true;
                }
            }

            *value = imm;
            return false;

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
    PyObject *db, *tmp, *mem, *ty;

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

    if (id == ARM_INS_PUSH) {
        reg_sub(regs, ARM_REG_SP, get_reg_value(regs, ARM_REG_SP),
                WORDSIZE * len_ops);
        goto end;
    }

    if (id == ARM_INS_POP) {
        reg_add(regs, ARM_REG_SP, get_reg_value(regs, ARM_REG_SP),
                WORDSIZE * len_ops);
        goto end;
    }

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

    // The first operand is always a register and always the destination (except st* ?)
    int r1 = get_op_reg(ops[0]);
    err[0] = !is_reg_supported(r1);

    // Start to the second op !
    for (i = 1 ; i < len_ops ; i++) {
        err[i] = get_op_value(regs, insn, ops[i], &values[i], &is_stack[i]);

        if (err[i] || only_simulate)
            continue;

        if (get_op_type(ops[i]) == ARM_OP_MEM) {
            // Pointers are not dereferenced actually.
            // So it means that we will not simulate this instruction.
            err[i] = true;

            // Check if there is a stack reference
            if (is_stack[i] && func_obj != Py_None &&
                PyLong_AsLong(PyList_GET_ITEM(func_obj, FUNC_FRAME_SIZE)) != -1) {

                // ty = analyzer.db.mem.get_type_from_size(op_size)
                db = PyObject_GetAttrString(analyzer, "db");
                mem = PyObject_GetAttrString(db, "mem");
                ty = PyObject_CallMethod(mem, "get_type_from_size", "i",
                                         get_op_mem_size(id));

                // The second item is the name of the variable
                // func_obj[FUNC_OFF_VARS][v] = [ty, None]
                tmp = PyList_GET_ITEM(func_obj, FUNC_OFF_VARS);
                Py_INCREF(tmp);
                PyObject *l = PyList_New(2);
                PyList_SET_ITEM(l, 0, ty);
                PyList_SET_ITEM(l, 1, Py_None);
                PyDict_SetItem(tmp, PyLong_FromLong((int) values[i]), l);
                Py_DECREF(tmp);

                // func_obj[FUNC_INST_ADDR][i.address] = v
                tmp = PyList_GET_ITEM(func_obj, FUNC_INST_ADDR);
                Py_INCREF(tmp);
                PyDict_SetItem(tmp, PyObject_GetAttrString(insn, "address"),
                               PyLong_FromLong((int) values[i]));
                Py_DECREF(tmp);

                Py_DECREF(mem);
                Py_DECREF(db);
                continue;
            }
        }

        PyObject_CallMethod(analyzer, "analyze_imm", "OOiB",
                            insn, ops[i], values[i], false);
    }

    // err[0] = !is_reg_supported(r1)

    if (err[0])
        goto end;

    if (len_ops == 2) {
        if (id == ARM_INS_MOV || id == ARM_INS_MVN) {
            if (!err[1]) {
                if (id == ARM_INS_MVN)
                    values[1] = ~values[1];
                reg_mov(regs, r1, values[1]);
                regs->is_stack[r1] = is_stack[1];
                goto save_imm;
            }
        }

        // Undefine the register if it's a load
        if (is_load(id)) {
            regs->is_def[r1] = false;
        }

        // Do nothing for all others 2 operands instructions
        goto end;
    }

    if (err[1] || err[2]) {
        // Unset the first register which is the destination in ARM
        regs->is_def[r1] = false;
        goto end;
    }

    regs->is_stack[r1] = is_stack[1] | is_stack[2];

    switch (id) {
        case ARM_INS_ADD:
            reg_add(regs, r1, values[1], values[2]);
            break;

        case ARM_INS_SUB:
            reg_sub(regs, r1, values[1], values[2]);
            break;

        case ARM_INS_AND:
            reg_and(regs, r1, values[1], values[2]);
            break;

        default:
            // Can't simulate this instruction, so unset the value of the register
            regs->is_def[r1] = false;
            goto end;
    }

save_imm:
    if (!regs->is_stack[r1]) {
        long v = get_reg_value(regs, r1);

        PyObject *ret = PyObject_CallMethod(
                analyzer, "analyze_imm", "OOiB", insn, ops[0], v, true);

        if (ret == Py_True) {
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

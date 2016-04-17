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
#include <capstone/mips.h>

// Same as lib.consts
#define FUNC_OFF_VARS 2
#define FUNC_INST_ADDR 4


// It supports only the most common registers (see capstone.mips)
#define LAST_REG MIPS_REG_31
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

static unsigned long GP = 0;

static inline bool is_load(int insn_id)
{
    switch (insn_id) {
    case MIPS_INS_LB:
    case MIPS_INS_LBUX:
    case MIPS_INS_LBU:
    case MIPS_INS_LH:
    case MIPS_INS_LHX:
    case MIPS_INS_LHU:
    case MIPS_INS_LW:
    case MIPS_INS_LWL:
    case MIPS_INS_LWR:
    case MIPS_INS_LWU:
    case MIPS_INS_LWX:
    case MIPS_INS_LWC1:
    case MIPS_INS_LWC2:
    case MIPS_INS_LWC3:
    case MIPS_INS_LWXC1:
    case MIPS_INS_LWPC:
    case MIPS_INS_LWUPC:
    case MIPS_INS_LL:
    case MIPS_INS_LD:
    case MIPS_INS_LDL:
    case MIPS_INS_LDR:
    case MIPS_INS_LDC1:
    case MIPS_INS_LDC2:
    case MIPS_INS_LDC3:
    case MIPS_INS_LDXC1:
    case MIPS_INS_LUXC1:
    case MIPS_INS_LDPC:
    case MIPS_INS_LLD:
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

    r->regs[MIPS_REG_ZERO] = 0;
    r->is_def[MIPS_REG_ZERO] = true;

    r->regs[MIPS_REG_SP] = 0;
    r->is_def[MIPS_REG_SP] = true;
    r->is_stack[MIPS_REG_SP] = true;

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

static inline void reg_mov(struct regs_context *self, int r, long v)
{
    if (r == MIPS_REG_ZERO)
        return;
    self->regs[r] = (long) v;
    self->is_def[r] = true;
}

static inline void reg_add(struct regs_context *self, int r, int v1, int v2)
{
    if (r == MIPS_REG_ZERO)
        return;
    *((int*) &self->regs[r]) = v1 + v2;
}

static inline void reg_sub(struct regs_context *self, int r, int v1, int v2)
{
    if (r == MIPS_REG_ZERO)
        return;
    *((int*) &self->regs[r]) = v1 - v2;
}

static inline void reg_or(struct regs_context *self, int r, int v1, int v2)
{
    if (r == MIPS_REG_ZERO)
        return;
    *((int*) &self->regs[r]) = v1 | v2;
}

static inline void reg_and(struct regs_context *self, int r, int v1, int v2)
{
    if (r == MIPS_REG_ZERO)
        return;
    *((int*) &self->regs[r]) = v1 & v2;
}

static inline void reg_xor(struct regs_context *self, int r, int v1, int v2)
{
    if (r == MIPS_REG_ZERO)
        return;
    *((int*) &self->regs[r]) = v1 ^ v2;
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
    switch (insn_id) {
    case MIPS_INS_LB:
    case MIPS_INS_LBUX:
    case MIPS_INS_LBU:
    case MIPS_INS_SB:
        return 1;

    case MIPS_INS_LH:
    case MIPS_INS_LHX:
    case MIPS_INS_LHU:
    case MIPS_INS_SH:
        return 2;

    case MIPS_INS_LW:
    case MIPS_INS_LWL:
    case MIPS_INS_LWR:
    case MIPS_INS_LWU:
    case MIPS_INS_LWX:
    case MIPS_INS_LWC1:
    case MIPS_INS_LWC2:
    case MIPS_INS_LWC3:
    case MIPS_INS_LWXC1:
    case MIPS_INS_LWPC:
    case MIPS_INS_LWUPC:
    case MIPS_INS_SW:
    case MIPS_INS_SWC1:
    case MIPS_INS_SWC2:
    case MIPS_INS_SWC3:
    case MIPS_INS_SWL:
    case MIPS_INS_SWR:
    case MIPS_INS_SWXC1:
    case MIPS_INS_LL:
    case MIPS_INS_SC:
        return 4;

    case MIPS_INS_LD:
    case MIPS_INS_LDL:
    case MIPS_INS_LDR:
    case MIPS_INS_LDC1:
    case MIPS_INS_LDC2:
    case MIPS_INS_LDC3:
    case MIPS_INS_LDXC1:
    case MIPS_INS_LUXC1:
    case MIPS_INS_LDPC:
    case MIPS_INS_SD:
    case MIPS_INS_SDC1:
    case MIPS_INS_SDC2:
    case MIPS_INS_SDC3:
    case MIPS_INS_SDL:
    case MIPS_INS_SDR:
    case MIPS_INS_SDXC1:
    case MIPS_INS_SUXC1:
    case MIPS_INS_LLD:
    case MIPS_INS_SCD:
        return 8;

    default:
        return 0;
    }
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

static long get_reg_value(struct regs_context *regs, int r)
{
    if (r == MIPS_REG_GP)
        return GP;
    return (long) regs->regs[r];
}

// out : value, is_stack
// return true if there is an error (example: a register is invalid or
// not defined)
static bool get_op_value(struct regs_context *regs, PyObject *insn, 
                         PyObject *op, long *value, bool *is_stack)
{
    int r, base;
    long imm;
    switch (get_op_type(op)) {
        case MIPS_OP_IMM:
            *value = get_op_imm(op);
            *is_stack = false;
            break;

        case MIPS_OP_REG:
            r = get_op_reg(op);
            if (!is_reg_defined(regs, r))
                return true;
            *value = get_reg_value(regs, r);
            *is_stack = regs->is_stack[r];
            break;

        case MIPS_OP_MEM:
            *is_stack = false;
            imm = get_op_mem_disp(op);

            base = get_op_mem_base(op);
            if (base) {
                if (base == MIPS_REG_GP) {
                    imm += GP;
                }
                else {
                    if (!is_reg_defined(regs, base))
                        return true;
                    imm += get_reg_value(regs, base);
                    *is_stack = regs->is_stack[base];
                }
            }

            *value = imm;
            break;

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

    if (!GP)
        GP = py_aslong3(analyzer, "dis", "mips_gp");

    int id = py_aslong2(insn, "id");

    PyObject *list_ops = PyObject_GetAttrString(insn, "operands");
    int len_ops = PyList_Size(list_ops);

    // FIXME
    if (len_ops <= 1)
        goto end;

    PyObject *ops[3];

    ops[0] = len_ops >= 1 ? PyList_GET_ITEM(list_ops, 0) : NULL;
    ops[1] = len_ops >= 2 ? PyList_GET_ITEM(list_ops, 1) : NULL;
    ops[2] = len_ops == 3 ? PyList_GET_ITEM(list_ops, 2) : NULL;

    if (id == MIPS_INS_XOR) {
        int r1 = get_op_reg(ops[0]);
        int r2 = get_op_reg(ops[1]);
        int r3 = get_op_reg(ops[2]);

        if (!is_reg_supported(r1))
            goto end;

        if (r2 == r3) {
            reg_mov(regs, r1, 0);
            goto end;
        }
    }

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

        if (get_op_type(ops[i]) == MIPS_OP_MEM) {
            // Pointers are not dereferenced actually.
            // So it means that we will not simulate this instruction.
            err[i] = true;

            // Check if there is a stack reference
            if (is_stack[i] && func_obj != Py_None) {
                // ty = analyzer.db.mem.find_type(op_size)
                PyObject *tmp;
                PyObject *db = PyObject_GetAttrString(analyzer, "db");
                PyObject *mem = PyObject_GetAttrString(db, "mem");
                PyObject *ty = PyObject_CallMethod(mem, "find_type", "i",
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

                Py_DECREF(db);
                Py_DECREF(mem);
                continue;
            }
        }

        PyObject_CallMethod(analyzer, "analyze_imm", "OOi",
                            insn, ops[i], values[i]);
    }

    if (!is_reg_supported(r1))
        goto end;

    if (len_ops == 2) {
        if (id == MIPS_INS_MOVE) {
            int r2 = get_op_reg(ops[1]);

            if (!is_reg_defined(regs, r2))
                goto end;

            reg_mov(regs, r1, get_reg_value(regs, r2));
            regs->is_stack[r1] = regs->is_stack[r2];
            goto end;
        }

        // Undefine the register if it's a load
        if (is_load(id)) {
            int r1 = get_op_reg(ops[0]);

            if (!is_reg_supported(r1) || r1 == MIPS_REG_GP)
                goto end;

            regs->is_def[r1] = false;
            goto end;
        }

        // Do nothing for all others 2 operands instructions
        goto end;
    }

    if (err[0] || err[1] || err[2]) {
        // Unset the first register which is the destination in MIPS
        regs->is_def[r1] = false;
        goto end;
    }

    regs->is_stack[r1] = is_stack[1] | is_stack[2];

    switch (id) {
        case MIPS_INS_ADDIU:
        case MIPS_INS_ADD:
            reg_add(regs, r1, values[1], values[2]);
            break;

        case MIPS_INS_SUB:
        case MIPS_INS_SUBU:
            reg_sub(regs, r1, values[1], values[2]);
            break;

        case MIPS_INS_XOR:
        case MIPS_INS_XORI:
            reg_xor(regs, r1, values[1], values[2]);
            break;

        case MIPS_INS_AND:
        case MIPS_INS_ANDI:
            reg_and(regs, r1, values[1], values[2]);
            break;

        case MIPS_INS_OR:
        case MIPS_INS_ORI:
            reg_or(regs, r1, values[1], values[2]);
            break;

        default:
            // Can't simulate this instruction, so unset the value of the register
            regs->is_def[r1] = false;
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

import lib.arch.arm.output
import lib.arch.arm.utils
import lib.arch.arm.process_ast

registered = [
    process_ast.convert_cond_to_if,
    process_ast.fuse_inst_with_if,
]

import plasma.lib.arch.arm.output
import plasma.lib.arch.arm.utils
import plasma.lib.arch.arm.process_ast

registered = [
    process_ast.convert_cond_to_if,
    process_ast.fuse_inst_with_if,
]

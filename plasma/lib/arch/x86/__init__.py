import plasma.lib.arch.x86.output
import plasma.lib.arch.x86.utils
import plasma.lib.arch.x86.process_ast
import plasma.lib.arch.x86.int80

registered = [
    process_ast.fuse_inst_with_if,
    int80.int80,
]

import reverse.lib.arch.x86.output
import reverse.lib.arch.x86.utils
import reverse.lib.arch.x86.process_ast
import reverse.lib.arch.x86.int80

registered = [
    process_ast.fuse_inst_with_if,
    process_ast.search_local_vars,
    process_ast.search_canary_plt,
    int80.int80,
]

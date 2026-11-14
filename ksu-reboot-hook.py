# 让管理器的 reboot(magic) 通信绕过 app 的 seccomp。
#
# KernelSU 3.x 通过 reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd)
# 取内核通信 fd，内核侧由 __x64_sys_reboot 上的 kprobe 拦截。
# 但 Android app 的 seccomp 策略把 reboot 返回 EPERM，系统调用根本到不了 kprobe，
# ksud 因此报 "KernelSU driver install syscall was blocked by seccomp"。
#
# sys_enter tracepoint 在 secure_computing() 之前触发（5.10 的
# syscall_trace_enter 先 trace_sys_enter，再 secure_computing），
# 所以把 reboot 注册进 dispatcher 后：
#   tracepoint 改写 orig_ax 为 dispatcher 槽(134) -> seccomp 只看到 134 并放行
#   -> do_syscall_64 调 sys_call_table[134] -> dispatcher 恢复 orig_ax=169
#   -> passthrough 调原始 __x64_sys_reboot -> kprobe 拿到 magic 并安装 fd。
import sys
import os

root = sys.argv[1]
path = os.path.join(root, "kernel/hook/syscall_hook_manager.c")
src = open(path, encoding="utf-8").read()

# 1) 在 faccessat 注册之后追加 reboot 路由
anchor = "    ksu_register_syscall_hook(__NR_faccessat, ksu_hook_faccessat);\n"
if anchor not in src:
    raise SystemExit("anchor for syscall hook registration not found")

addition = (
    "#if defined(__x86_64__)\n"
    "    /*\n"
    "     * 管理器的 reboot(magic) 通信会被 app seccomp 拦截，而 sys_enter\n"
    "     * tracepoint 在 seccomp 之前触发。把 reboot 也挂到 dispatcher，\n"
    "     * 使 magic 调用能到达 __x64_sys_reboot 上的 reboot kprobe。\n"
    "     */\n"
    "    ksu_register_syscall_hook(__NR_reboot, ksu_hook_reboot_passthrough);\n"
    "#endif\n"
)
src = src.replace(anchor, anchor + addition, 1)

# 2) 加入 passthrough 处理函数：直接调用 syscall 表中的原始项
init_sig = "void __init ksu_syscall_hook_manager_init(void)"
if init_sig not in src:
    raise SystemExit("ksu_syscall_hook_manager_init not found")

func = (
    "#if defined(__x86_64__)\n"
    "/* 把 reboot 原样交回 sys_call_table，让 reboot kprobe 处理 KSU magic。 */\n"
    "static long ksu_hook_reboot_passthrough(int nr, const struct pt_regs *regs)\n"
    "{\n"
    "    return ((long (*)(const struct pt_regs *))ksu_syscall_table[nr])(regs);\n"
    "}\n"
    "#endif\n"
    "\n"
)
src = src.replace(init_sig, func + init_sig, 1)

open(path, "w", encoding="utf-8").write(src)
print("patched:", path)

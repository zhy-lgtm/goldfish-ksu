# 放行 KernelSU 管理器的 reboot(magic) 安装调用。
#
# KernelSU 3.x 的管理器/ksud 通过
#     reboot(0xdeadbeef, 0xcafebabe, 0, &fd)
# 取内核通信 fd，内核侧由 __x64_sys_reboot 上的 reboot kprobe 拦截。
#
# 但 Android 给 app 的 seccomp 策略把 reboot 返回 EPERM。seccomp 在
# syscall_trace_enter 里先于 sys_call_table 分发执行，于是：
#   - reboot 永远到不了 __x64_sys_reboot
#   - reboot kprobe 一次都不命中
#   - ksud 报 "KernelSU driver install syscall was blocked by seccomp"
#   - 管理器界面一直显示"未安装"
#
# 前面的做法（kprobe __secure_computing 改 ptrace / orig_ax、kprobe
# __seccomp_filter 改 sd->nr）都被证实不生效或会内核 panic。
# 这里直接改 kernel/seccomp.c：在 __secure_computing 最前面识别 KSU 的两个
# magic，命中就直接 return 0 跳过全部过滤。判定依据是当前 syscall regs，
# 与 seccomp 建 sd 的方式一致，不依赖任何 kprobe。
import os
import sys

root = sys.argv[1]
path = os.path.join(root, "kernel/seccomp.c")
src = open(path, encoding="utf-8").read()

anchor = """	if (IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) &&
	    unlikely(current->ptrace & PT_SUSPEND_SECCOMP))
		return 0;
"""
if anchor not in src:
    raise SystemExit("seccomp.c anchor not found")

gate = anchor + """
#ifdef CONFIG_KSU
	/*
	 * KernelSU 管理器的 reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, ...)
	 * 用来取内核通信 fd。app 的 seccomp 策略会把它判成 EPERM，
	 * 导致 reboot kprobe 永远收不到请求。这里只放行这一种调用。
	 */
	{
		struct pt_regs *ksu_regs = current_pt_regs();

		if (ksu_regs && ksu_regs->orig_ax == __NR_reboot &&
		    (int)ksu_regs->di == 0xdeadbeef && (int)ksu_regs->si == 0xcafebabe) {
			pr_info_ratelimited("KernelSU: allow install syscall past seccomp\\n");
			return 0;
		}
	}
#endif
"""
src = src.replace(anchor, gate, 1)

# 需要 current_pt_regs() 与 __NR_reboot
if "asm/ptrace.h" not in src:
    src = src.replace("#include <asm/syscall.h>", "#include <asm/ptrace.h>\n#include <asm/syscall.h>", 1)
if "asm/unistd.h" not in src:
    src = src.replace("#include <asm/ptrace.h>", "#include <asm/unistd.h>\n#include <asm/ptrace.h>", 1)
if "linux/sched/task_stack.h" not in src:
    src = src.replace("#include <asm/ptrace.h>", "#include <linux/sched/task_stack.h>\n#include <asm/ptrace.h>", 1)

open(path, "w", encoding="utf-8").write(src)
print("patched:", path)

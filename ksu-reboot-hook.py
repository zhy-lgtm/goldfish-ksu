# 放行管理器的 reboot(magic)，让 KSU 能拿到内核通信 fd。
#
# KernelSU 3.x 的管理器/ksud 通过
#     reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd)
# 取内核通信 fd，内核侧由 __x64_sys_reboot 上的 reboot kprobe 拦截。
#
# 但 Android 给 app 的 seccomp 策略把 reboot 返回 EPERM：
#   - syscall 在 secure_computing() 就被拦下，到不了 sys_call_table[__NR_reboot]
#   - reboot kprobe 因此一次都不会命中，ksud 报
#     "KernelSU driver install syscall was blocked by seccomp"
#
# 内核在 __secure_computing 开头有官方逃生门：
#     if (IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) &&
#         unlikely(current->ptrace & PT_SUSPEND_SECCOMP))
#             return 0;
# 这里在 __secure_computing 入口只对 KSU 的两个 magic 临时置上
# PT_SUSPEND_SECCOMP，函数会直接 return 0 跳过 seccomp；post_handler 立刻
# 还原 ptrace，其他系统调用和 reboot 调用完全不受影响。
# 需要内核打开 CONFIG_CHECKPOINT_RESTORE（workflow 已加）。
import os
import sys

root = sys.argv[1]
path = os.path.join(root, "kernel/supercall/supercall.c")
src = open(path, encoding="utf-8").read()

# 1) 需要 current_pt_regs()
inc_anchor = '#include "klog.h" // IWYU pragma: keep\n'
if inc_anchor not in src:
    raise SystemExit("include anchor not found")
if "linux/sched/task_stack.h" not in src:
    src = src.replace(inc_anchor, inc_anchor + "#include <linux/sched/task_stack.h>\n", 1)
if "linux/ptrace.h" not in src:
    src = src.replace(inc_anchor, inc_anchor + "#include <linux/ptrace.h>\n", 1)

# 2) 在 reboot kprobe 之后加入 seccomp 逃生门 kprobe
kp_anchor = (
    "static struct kprobe reboot_kp = {\n"
    "    .symbol_name = REBOOT_SYMBOL,\n"
    "    .pre_handler = reboot_handler_pre,\n"
    "};\n"
)
if kp_anchor not in src:
    raise SystemExit("reboot_kp anchor not found")

add = """
/*
 * app 的 seccomp 策略把 reboot 返回 EPERM，管理器的 reboot(KSU magic)
 * 到不了 sys_call_table[__NR_reboot]，reboot kprobe 也就装不上 fd。
 * __secure_computing 对 PT_SUSPEND_SECCOMP 会直接 return 0，这里只对
 * KSU 的两个 magic 临时置位，post_handler 立即还原。
 */
static DEFINE_PER_CPU(unsigned int, ksu_saved_ptrace);
static DEFINE_PER_CPU(bool, ksu_seccomp_suspended);

static int secure_computing_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *sys_regs = current_pt_regs();

    this_cpu_write(ksu_seccomp_suspended, false);
    if (!sys_regs)
        return 0;

    if (sys_regs->orig_ax == __NR_reboot && (int)sys_regs->di == KSU_INSTALL_MAGIC1 &&
        (int)sys_regs->si == KSU_INSTALL_MAGIC2 && !(current->ptrace & PT_SUSPEND_SECCOMP)) {
        this_cpu_write(ksu_saved_ptrace, current->ptrace);
        current->ptrace |= PT_SUSPEND_SECCOMP;
        this_cpu_write(ksu_seccomp_suspended, true);
    }
    return 0;
}

static void secure_computing_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    if (!this_cpu_read(ksu_seccomp_suspended))
        return;
    this_cpu_write(ksu_seccomp_suspended, false);
    current->ptrace = this_cpu_read(ksu_saved_ptrace);
}

static struct kprobe secure_computing_kp = {
    .symbol_name = "__secure_computing",
    .pre_handler = secure_computing_handler_pre,
    .post_handler = secure_computing_handler_post,
};
"""
src = src.replace(kp_anchor, kp_anchor + add, 1)

# 3) 注册
reg_anchor = """    } else {
        pr_info("reboot kprobe registered successfully\\n");
    }
"""
if reg_anchor not in src:
    raise SystemExit("register anchor not found")

reg_add = """
    rc = register_kprobe(&secure_computing_kp);
    if (rc) {
        pr_err("secure_computing kprobe failed: %d\\n", rc);
    } else {
        pr_info("secure_computing kprobe registered successfully\\n");
    }
"""
src = src.replace(reg_anchor, reg_anchor + reg_add, 1)

# 4) 注销
exit_anchor = "    unregister_kprobe(&reboot_kp);\n"
if exit_anchor not in src:
    raise SystemExit("exit anchor not found")
src = src.replace(exit_anchor, exit_anchor + "    unregister_kprobe(&secure_computing_kp);\n", 1)

# 5) 额外按 sys_call_table 实际地址注册 reboot kprobe：
#    CFI 下符号地址和 sys_call_table 项可能不一致，双保险。
if "hook/syscall_hook.h" not in src:
    src = src.replace(inc_anchor, inc_anchor + '#include "hook/syscall_hook.h"\n', 1)

table_kp = """
/* sys_call_table[__NR_reboot] 才是实际被调用的入口，符号地址未必一致。 */
static struct kprobe reboot_table_kp = {
    .pre_handler = reboot_handler_pre,
};
"""
src = src.replace(kp_anchor + add, kp_anchor + add + table_kp, 1)

src = src.replace(reg_add, reg_add + """
    reboot_table_kp.addr = (kprobe_opcode_t *)ksu_syscall_table[__NR_reboot];
    rc = register_kprobe(&reboot_table_kp);
    if (rc) {
        pr_err("reboot table kprobe failed: %d\\n", rc);
    } else {
        pr_info("reboot table kprobe registered successfully\\n");
    }
""", 1)

src = src.replace(exit_anchor, exit_anchor + "    unregister_kprobe(&reboot_table_kp);\n", 1)

open(path, "w", encoding="utf-8").write(src)
print("patched:", path)

# 放行管理器的 reboot(magic)，让 KSU 能拿到内核通信 fd。
#
# KernelSU 3.x 的管理器/ksud 通过
#     reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd)
# 取内核通信 fd，内核侧由 __x64_sys_reboot 上的 reboot kprobe 拦截。
#
# 但 Android 给 app 的 seccomp 策略把 reboot 返回 EPERM，系统调用在
# secure_computing() 就被拦下，到不了 sys_call_table[__NR_reboot]，
# ksud 报 "KernelSU driver install syscall was blocked by seccomp"，
# 管理器一直显示"未安装"。
#
# seccomp 的 nr 来自 syscall_get_nr()，即当前 pt_regs 的 orig_ax。
# 在 __secure_computing 入口把命中 KSU magic 的 orig_ax 临时换成一定被
# 允许的 getpid，filter 放行后再在 post_handler 还原。do_syscall_64 的
# 局部 nr 不受影响，仍会调用 sys_call_table[__NR_reboot]，reboot kprobe
# 就能正常安装 fd。其他 reboot 调用不受影响。
import os
import sys

root = sys.argv[1]
path = os.path.join(root, "kernel/supercall/supercall.c")
src = open(path, encoding="utf-8").read()

# 1) 需要 task_pt_regs()
inc_anchor = '#include "klog.h" // IWYU pragma: keep\n'
if inc_anchor not in src:
    raise SystemExit("include anchor not found")
extra = ""
if "linux/sched/task_stack.h" not in src:
    extra += "#include <linux/sched/task_stack.h>\n"
if "linux/percpu.h" not in src:
    extra += "#include <linux/percpu.h>\n"
if extra:
    src = src.replace(inc_anchor, inc_anchor + extra, 1)

# 2) 在 reboot kprobe 之后加入 seccomp 预处理 kprobe
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
 * seccomp 判定用的 nr 就是 syscall pt_regs 的 orig_ax。命中 KSU 安装 magic
 * 的 reboot 在 app 策略里会拿到 EPERM，这里临时换成 getpid 让 filter 放行，
 * post_handler 再还原；实际被调用的仍是 sys_call_table[__NR_reboot]，
 * reboot kprobe 照常安装 fd。
 */
static DEFINE_PER_CPU(bool, ksu_seccomp_bypassed);

static int secure_computing_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *sys_regs = task_pt_regs(current);

    this_cpu_write(ksu_seccomp_bypassed, false);
    if (!sys_regs)
        return 0;

    if (sys_regs->orig_ax == __NR_reboot && (int)sys_regs->di == KSU_INSTALL_MAGIC1 &&
        (int)sys_regs->si == KSU_INSTALL_MAGIC2) {
        sys_regs->orig_ax = __NR_getpid;
        this_cpu_write(ksu_seccomp_bypassed, true);
    }
    return 0;
}

static void secure_computing_handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct pt_regs *sys_regs;

    if (!this_cpu_read(ksu_seccomp_bypassed))
        return;
    this_cpu_write(ksu_seccomp_bypassed, false);

    sys_regs = task_pt_regs(current);
    if (sys_regs && sys_regs->orig_ax == __NR_getpid)
        sys_regs->orig_ax = __NR_reboot;
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

open(path, "w", encoding="utf-8").write(src)
print("patched:", path)

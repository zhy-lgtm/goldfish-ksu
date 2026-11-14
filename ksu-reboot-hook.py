# 放行管理器的 reboot(magic)，让 KSU 能拿到内核通信 fd。
#
# KernelSU 3.x 的管理器/ksud 通过
#     reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd)
# 取内核通信 fd，内核侧由 __x64_sys_reboot 上的 reboot kprobe 拦截。
#
# 但 Android 给 app 的 seccomp 策略把 reboot 返回 EPERM，系统调用在
# secure_computing() 就被拦下，根本走不到 sys_call_table[__NR_reboot]，
# ksud 因此打印 "KernelSU driver install syscall was blocked by seccomp"，
# 管理器一直显示"未安装"。
#
# seccomp 只检查 seccomp_data::nr。这里在 __secure_computing 入口把
# 命中 KSU magic 的 reboot 临时改成一定被允许的 getpid：filter 放行后
# do_syscall_64 仍按原 nr 调 sys_call_table[__NR_reboot]，reboot kprobe
# 就能正常安装 fd。其他 reboot 调用不受影响。
import os
import sys

root = sys.argv[1]
path = os.path.join(root, "kernel/supercall/supercall.c")
src = open(path, encoding="utf-8").read()

# 1) 需要 struct seccomp_data
inc_anchor = '#include "klog.h" // IWYU pragma: keep\n'
if inc_anchor not in src:
    raise SystemExit("include anchor not found")
if "uapi/linux/seccomp.h" not in src:
    src = src.replace(inc_anchor, inc_anchor + "#include <uapi/linux/seccomp.h>\n", 1)

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
 * seccomp 在 __secure_computing 入口拿到 seccomp_data。命中 KSU 安装 magic
 * 的 reboot 会被 app 策略返回 EPERM，这里把 nr 换成 getpid 让 filter 放行；
 * 真正被调用的仍是 sys_call_table[__NR_reboot]，reboot kprobe 照常安装 fd。
 */
static int secure_computing_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    const struct seccomp_data *sd = (const struct seccomp_data *)PT_REGS_PARM1(real_regs);

    if (!sd)
        return 0;
    if (sd->nr == __NR_reboot && (int)sd->args[0] == KSU_INSTALL_MAGIC1 &&
        (int)sd->args[1] == KSU_INSTALL_MAGIC2) {
        ((struct seccomp_data *)sd)->nr = __NR_getpid;
    }
    return 0;
}

static struct kprobe secure_computing_kp = {
    .symbol_name = "__secure_computing",
    .pre_handler = secure_computing_handler_pre,
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

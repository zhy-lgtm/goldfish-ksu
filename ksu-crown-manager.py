# 管理器 uid 加冕：调用 reboot(KSU magic) 时直接设为 manager appid。
#
# KernelSU 的标准加冕流程依赖 track_throne()，它由 ksud 的 boot-completed
# 事件触发。但是模拟器上没有 /data/adb/ksud，boot_completed 事件不会发生，
# track_throne 永不运行，manager appid 一直是 KSU_INVALID_APPID，于是
# 管理器的 GET_FEATURE / GET_APP_PROFILE 等 ioctl 全部 EPERM，界面显示"未安装"。
#
# 只有真实的管理器/ksud 才知道 KSU 的 reboot magic，所以 reboot_handler_pre
# 识别到 magic 时，直接把当前调用者的 uid 加冕为 manager。这是本环境里
# 最可靠的加冕路径。调用者随后即可通过只允许 manager 的 ioctl。
import os
import sys

root = sys.argv[1]
path = os.path.join(root, "kernel/supercall/supercall.c")
src = open(path, encoding="utf-8").read()

# 1) 确保 include manager/manager_identity.h（提供 ksu_set_manager_appid / KSU_INVALID_APPID / KSU_PER_USER_RANGE）
inc_anchor = '#include "klog.h" // IWYU pragma: keep\n'
if inc_anchor not in src:
    raise SystemExit("include anchor not found")
if "manager/manager_identity.h" not in src:
    src = src.replace(inc_anchor, inc_anchor + '#include "manager/manager_identity.h"\n', 1)

# 2) 在 reboot_handler_pre 的 magic 匹配块中加冕
handler_anchor = """    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
"""
if handler_anchor not in src:
    raise SystemExit("reboot handler anchor not found")

crown = """    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);

        // Emulator image has no /data/adb/ksud, so track_throne never runs.
        // Crown the caller (the only party that knows the magic) as manager.
        // Lock once only: root (uid 0) also reaches here via built-in su and
        // would otherwise override the real manager's uid on every install.
        {
            uid_t caller = current_uid().val % KSU_PER_USER_RANGE;
            if (ksu_get_manager_appid() == KSU_INVALID_APPID) {
                pr_info("ksu crown manager uid=%u\\n", caller);
                ksu_set_manager_appid(caller);
            }
        }
"""
src = src.replace(handler_anchor, crown, 1)

open(path, "w", encoding="utf-8").write(src)
print("patched:", path)
Response:
My thinking process to answer the request about the `context_lookup_benchmark_data.handroid` file goes like this:

1. **Understand the Goal:** The core request is to explain the functionality of this file, its relation to Android, and provide details about libc functions, dynamic linking, and potential usage errors. Crucially, the prompt asks for a *summary* of its function in this first part.

2. **Initial Analysis of the File Content:** I scanned the content of the provided code. The key observation is the presence of two large string literals: `oreo_property_contexts` and `aosp_s_property_contexts`. These strings contain what appears to be a list of property names and their associated security contexts. The format looks like `property_name  security_context`.

3. **Identify the Core Functionality:** Based on the content, the primary function of this file is to store data that maps system properties to their SELinux security contexts. This is critical for Android's security model.

4. **Relate to Android Functionality:**  I know that Android uses system properties extensively for configuration and inter-process communication. SELinux is the mandatory access control system that enhances Android's security. Therefore, this file directly relates to how Android manages access control for system properties. A concrete example is how the system determines if a process can read or write a specific system property.

5. **Consider the File Name and Path:** The file name `context_lookup_benchmark_data.handroid` and its location within `bionic/libc/system_properties` give further clues. "context_lookup" clearly suggests the mapping functionality. "benchmark_data" indicates this data might be used for performance testing or comparisons related to property context lookups. The `.handroid` extension is less common but likely signifies an Android-specific data file. The `bionic/libc/system_properties` path strongly points to a low-level system component responsible for property management.

6. **Address Specific Questions (even if details come later):** The prompt asks about libc functions, dynamic linking, and errors. Although the *current* file doesn't *contain* libc function calls or dynamic linking, I know these are relevant to the broader context of system properties. I need to acknowledge this and indicate that these aspects will likely be covered in the subsequent parts of the analysis. Similarly, while the file itself doesn't show direct user errors, I can anticipate that incorrect property settings or security context mismatches could be issues.

7. **Formulate the Summary:**  Based on the above points, I can now create a concise summary of the file's function for Part 1. The summary should highlight:
    * Its role in storing property-to-security context mappings.
    * Its importance for Android's security (SELinux).
    * The fact that it appears to be benchmark data.
    * The two sets of contexts (Oreo and aosp_s).

8. **Plan for Part 2 (Implicitly):** While not explicitly requested for Part 1, I mentally noted the need to elaborate on libc functions, dynamic linking, and the interaction with the Android framework in the next part. This prepares me for the subsequent request.

9. **Refine and Structure:** Finally, I organized the summary in a clear and logical way, using bullet points for key features and providing an overall description. I made sure to address the "归纳一下它的功能" (summarize its function) part of the prompt directly.

By following this process, I can accurately assess the provided file's purpose and deliver a relevant and informative summary for Part 1 of the request. The focus on identifying the core data and its purpose within the Android ecosystem is key.
好的，让我们来分析一下 `bionic/libc/system_properties/context_lookup_benchmark_data.handroid` 这个源代码文件，并归纳一下它的功能。

**文件功能归纳：**

这个文件主要功能是**存储预定义的系统属性 (System Properties) 与 SELinux 安全上下文 (Security Contexts) 的映射关系数据**。  它包含了两个不同的映射数据集，分别对应 Android Oreo 和 AOSP S 版本（或类似的版本）。

更具体地说，这个文件的作用是：

1. **提供系统属性查找的安全上下文数据：**  Android 系统中的许多组件和服务需要读取或设置系统属性。为了确保安全性，SELinux 会限制哪些进程可以访问哪些属性。这个文件就提供了在特定 Android 版本中，哪些属性应该被分配给哪个安全上下文的信息。

2. **用于性能基准测试：**  文件名中的 "benchmark_data" 暗示这个文件的数据主要用于测试系统属性查找的性能。  通过使用预定义的映射关系，可以测试在大量属性中快速找到对应安全上下文的效率。

3. **包含不同 Android 版本的映射：** 文件中定义了 `oreo_property_contexts` 和 `aosp_s_property_contexts` 两个不同的字符数组。这表明不同版本的 Android 系统可能具有不同的属性安全上下文配置。

**与 Android 功能的关系举例：**

* **SELinux 安全策略执行：** 当一个进程尝试读取或设置一个系统属性时，SELinux 策略会检查该进程是否具有访问该属性安全上下文的权限。这个文件提供的数据就是策略判断的基础。
    * **例子：**  假设一个应用程序尝试读取 `net.dns` 属性。系统会查找这个文件，找到 `net.dns    u:object_r:net_dns_prop:s0` 的映射关系。然后，SELinux 会检查尝试访问的应用程序的上下文是否允许访问 `u:object_r:net_dns_prop:s0` 这个对象角色。

* **`init` 进程启动和服务：**  `init` 进程是 Android 系统的根进程，负责启动各种系统服务。在启动过程中，`init` 进程会读取系统属性来配置服务的行为。这个文件的数据可以帮助 `init` 进程确定哪些属性可以被哪些服务访问。
    * **例子：**  `init` 进程在启动网络服务时，可能会读取 `net.*` 开头的属性来获取网络配置信息。这个文件确保了只有具有 `u:object_r:net_radio_prop:s0` 或 `u:object_r:net_dns_prop:s0` 上下文的进程才能有效地设置这些属性。

**详细解释 libc 函数的功能实现：**

这个文件本身**不包含任何 libc 函数的调用**。它只是一个存储数据的静态字符数组。  然而，这个文件的数据会被其他使用 libc 提供的系统属性相关函数的代码所使用。常见的 libc 函数包括：

* **`property_get(const char *name, char *value)`:**  用于获取指定名称的系统属性的值。
* **`property_set(const char *name, const char *value)`:** 用于设置指定名称的系统属性的值。
* **内部实现可能涉及的函数：**  为了实现 `property_get` 和 `property_set`，libc 内部可能使用如 `strcmp` (字符串比较), `strcpy` (字符串复制), 内存管理函数等。

**对于涉及 dynamic linker 的功能：**

这个文件本身**不直接涉及 dynamic linker 的功能**。  Dynamic linker (如 `linker64` 或 `linker`) 负责在程序运行时加载和链接共享库 (`.so` 文件)。

**SO 布局样本和链接处理过程：**

由于这个文件不涉及 dynamic linker，这里无法提供直接相关的 SO 布局样本和链接处理过程。

**逻辑推理、假设输入与输出：**

这个文件主要是一个静态数据文件，没有直接的逻辑推理过程。  它的“输入”是属性名称，“输出”是对应的 SELinux 安全上下文。

* **假设输入：**  属性名称 "net.dns"
* **假设输出（根据文件内容）：** 安全上下文 "u:object_r:net_dns_prop:s0"

* **假设输入：** 属性名称 "persist.sys.safemode"
* **假设输出（根据文件内容）：** 安全上下文 "u:object_r:safemode_prop:s0"

**用户或编程常见的使用错误：**

由于这个文件是系统内部数据，普通用户或开发者通常不会直接修改它。  与系统属性相关的常见错误包括：

* **尝试设置没有权限的属性：**  应用程序尝试使用 `property_set` 设置一个它不具有安全上下文权限的属性。这会导致操作失败，并可能在日志中看到 SELinux 相关的错误信息。
    * **例子：**  一个普通的应用程序尝试设置 `net.dns` 属性，由于其安全上下文与 `u:object_r:net_dns_prop:s0` 不匹配，SELinux 会阻止这次操作。

* **错误地假设属性存在或不存在：**  代码中假设某个属性一定存在或不存在，但实际情况可能并非如此，导致程序行为异常。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例：**

1. **Android Framework/NDK 调用系统属性相关 API：**
   * 在 Java 层，可以使用 `System.getProperty(String key)` 和 `System.setProperty(String key, String value)`。
   * 在 Native 层（NDK），可以使用 `__system_property_get(const char* name, char* value)` 和 `__system_property_set(const char* name, const char* value)`.

2. **系统调用到 `libc`:**  这些 API 的底层实现会通过系统调用与 `libc` 中的系统属性处理函数交互。

3. **`libc` 查找属性的安全上下文：**  `libc` 中的代码（与这个文件相关）会加载并查找 `context_lookup_benchmark_data.handroid` 文件中的数据，以确定给定属性的 SELinux 安全上下文。

**Frida Hook 示例：**

要 hook 系统属性的获取过程，可以使用 Frida 拦截 `__system_property_get` 函数：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const SystemProperties = Module.findExportByName(null, "__system_property_get");
    if (SystemProperties) {
        Interceptor.attach(SystemProperties, {
            onEnter: function (args) {
                const name = Memory.readUtf8String(args[0]);
                console.log("[*] __system_property_get called, name: " + name);
            },
            onLeave: function (retval) {
                if (retval > 0) {
                    const valuePtr = this.context.sp.add(8); // Adjust offset based on architecture and calling convention
                    const value = Memory.readUtf8String(ptr(valuePtr.readPointer()));
                    console.log("[*] __system_property_get returned, value: " + value);
                }
            }
        });
    } else {
        console.log("[-] __system_property_get not found.");
    }
} else if (Process.arch === 'arm') {
    const SystemProperties = Module.findExportByName("libc.so", "__system_property_get");
    if (SystemProperties) {
        Interceptor.attach(SystemProperties, {
            onEnter: function (args) {
                const name = Memory.readUtf8String(args[0]);
                console.log("[*] __system_property_get called, name: " + name);
            },
            onLeave: function (retval) {
                if (retval > 0) {
                    const valuePtr = this.context.sp.add(4); // Adjust offset based on architecture and calling convention
                    const value = Memory.readUtf8String(ptr(valuePtr.readPointer()));
                    console.log("[*] __system_property_get returned, value: " + value);
                }
            }
        });
    } else {
        console.log("[-] __system_property_get not found.");
    }
}
```

这个 Frida 脚本会 hook `__system_property_get` 函数，并在每次调用时打印出要获取的属性名称和获取到的值。虽然这个 hook 没有直接触及 `context_lookup_benchmark_data.handroid`，但它展示了如何跟踪系统属性的访问，从而间接地观察到这个文件的作用。

**总结 (Part 1 的归纳):**

总而言之，`bionic/libc/system_properties/context_lookup_benchmark_data.handroid` 文件是一个存储系统属性到 SELinux 安全上下文映射关系的静态数据文件。它主要用于在 Android 系统中进行系统属性查找时的安全上下文确定，并可能被用于性能基准测试。文件中包含了针对不同 Android 版本（如 Oreo 和 AOSP S）的映射数据。虽然这个文件本身不包含 libc 函数调用或 dynamic linker 的操作，但其数据对于系统属性相关功能的正常运行至关重要。

### 提示词
```
这是目录为bionic/libc/system_properties/context_lookup_benchmark_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2020 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

static char oreo_property_contexts[] = R"(
net.rmnet               u:object_r:net_radio_prop:s0
net.gprs                u:object_r:net_radio_prop:s0
net.ppp                 u:object_r:net_radio_prop:s0
net.qmi                 u:object_r:net_radio_prop:s0
net.lte                 u:object_r:net_radio_prop:s0
net.cdma                u:object_r:net_radio_prop:s0
net.dns                 u:object_r:net_dns_prop:s0
sys.usb.config          u:object_r:system_radio_prop:s0
ril.                    u:object_r:radio_prop:s0
ro.ril.                 u:object_r:radio_prop:s0
gsm.                    u:object_r:radio_prop:s0
persist.radio           u:object_r:radio_prop:s0
net.                    u:object_r:system_prop:s0
dev.                    u:object_r:system_prop:s0
ro.runtime.             u:object_r:system_prop:s0
ro.runtime.firstboot    u:object_r:firstboot_prop:s0
hw.                     u:object_r:system_prop:s0
ro.hw.                  u:object_r:system_prop:s0
sys.                    u:object_r:system_prop:s0
sys.cppreopt            u:object_r:cppreopt_prop:s0
sys.powerctl            u:object_r:powerctl_prop:s0
sys.usb.ffs.            u:object_r:ffs_prop:s0
service.                u:object_r:system_prop:s0
dhcp.                   u:object_r:dhcp_prop:s0
dhcp.bt-pan.result      u:object_r:pan_result_prop:s0
bluetooth.              u:object_r:bluetooth_prop:s0
debug.                  u:object_r:debug_prop:s0
debug.db.               u:object_r:debuggerd_prop:s0
dumpstate.              u:object_r:dumpstate_prop:s0
dumpstate.options       u:object_r:dumpstate_options_prop:s0
log.                    u:object_r:log_prop:s0
log.tag                 u:object_r:log_tag_prop:s0
log.tag.WifiHAL         u:object_r:wifi_log_prop:s0
security.perf_harden    u:object_r:shell_prop:s0
service.adb.root        u:object_r:shell_prop:s0
service.adb.tcp.port    u:object_r:shell_prop:s0
persist.audio.          u:object_r:audio_prop:s0
persist.bluetooth.      u:object_r:bluetooth_prop:s0
persist.debug.          u:object_r:persist_debug_prop:s0
persist.logd.           u:object_r:logd_prop:s0
persist.logd.security   u:object_r:device_logging_prop:s0
persist.logd.logpersistd        u:object_r:logpersistd_logging_prop:s0
logd.logpersistd        u:object_r:logpersistd_logging_prop:s0
persist.log.tag         u:object_r:log_tag_prop:s0
persist.mmc.            u:object_r:mmc_prop:s0
persist.sys.            u:object_r:system_prop:s0
persist.sys.safemode    u:object_r:safemode_prop:s0
ro.sys.safemode         u:object_r:safemode_prop:s0
persist.sys.audit_safemode      u:object_r:safemode_prop:s0
persist.service.        u:object_r:system_prop:s0
persist.service.bdroid. u:object_r:bluetooth_prop:s0
persist.security.       u:object_r:system_prop:s0
persist.vendor.overlay.  u:object_r:overlay_prop:s0
ro.boot.vendor.overlay.  u:object_r:overlay_prop:s0
ro.boottime.             u:object_r:boottime_prop:s0
ro.serialno             u:object_r:serialno_prop:s0
ro.boot.btmacaddr       u:object_r:bluetooth_prop:s0
ro.boot.serialno        u:object_r:serialno_prop:s0
ro.bt.                  u:object_r:bluetooth_prop:s0
# Boolean property set by system server upon boot indicating
# if device owner is provisioned.
ro.device_owner         u:object_r:device_logging_prop:s0
# selinux non-persistent properties
selinux.restorecon_recursive   u:object_r:restorecon_prop:s0
# default property context
*                       u:object_r:default_prop:s0
# data partition encryption properties
vold.                   u:object_r:vold_prop:s0
ro.crypto.              u:object_r:vold_prop:s0
# ro.build.fingerprint is either set in /system/build.prop, or is
# set at runtime by system_server.
ro.build.fingerprint    u:object_r:fingerprint_prop:s0
ro.persistent_properties.ready  u:object_r:persistent_properties_ready_prop:s0
# ctl properties
ctl.bootanim            u:object_r:ctl_bootanim_prop:s0
ctl.dumpstate           u:object_r:ctl_dumpstate_prop:s0
ctl.fuse_               u:object_r:ctl_fuse_prop:s0
ctl.mdnsd               u:object_r:ctl_mdnsd_prop:s0
ctl.ril-daemon          u:object_r:ctl_rildaemon_prop:s0
ctl.bugreport           u:object_r:ctl_bugreport_prop:s0
ctl.console             u:object_r:ctl_console_prop:s0
ctl.                    u:object_r:ctl_default_prop:s0
# NFC properties
nfc.                    u:object_r:nfc_prop:s0
# These properties are not normally set by processes other than init.
# They are only distinguished here for setting by qemu-props on the
# emulator/goldfish.
config.                 u:object_r:config_prop:s0
ro.config.              u:object_r:config_prop:s0
dalvik.                 u:object_r:dalvik_prop:s0
ro.dalvik.              u:object_r:dalvik_prop:s0
# Shared between system server and wificond
wlan.                   u:object_r:wifi_prop:s0
# hwservicemanager properties
hwservicemanager.       u:object_r:hwservicemanager_prop:s0
# ASAN install trigger
asan.restore_reboot  u:object_r:asan_reboot_prop:s0)";

static char aosp_s_property_contexts[] = R"(
net.rmnet               u:object_r:net_radio_prop:s0
net.gprs                u:object_r:net_radio_prop:s0
net.ppp                 u:object_r:net_radio_prop:s0
net.qmi                 u:object_r:net_radio_prop:s0
net.lte                 u:object_r:net_radio_prop:s0
net.cdma                u:object_r:net_radio_prop:s0
net.dns                 u:object_r:net_dns_prop:s0
ril.                    u:object_r:radio_prop:s0
ro.ril.                 u:object_r:radio_prop:s0
gsm.                    u:object_r:radio_prop:s0
persist.radio           u:object_r:radio_prop:s0

net.                    u:object_r:system_prop:s0
dev.                    u:object_r:system_prop:s0
ro.runtime.             u:object_r:system_prop:s0
ro.runtime.firstboot    u:object_r:firstboot_prop:s0
hw.                     u:object_r:system_prop:s0
ro.hw.                  u:object_r:system_prop:s0
sys.                    u:object_r:system_prop:s0
sys.audio.              u:object_r:audio_prop:s0
sys.init.perf_lsm_hooks u:object_r:init_perf_lsm_hooks_prop:s0
sys.cppreopt            u:object_r:cppreopt_prop:s0
sys.lpdumpd             u:object_r:lpdumpd_prop:s0
sys.powerctl            u:object_r:powerctl_prop:s0
service.                u:object_r:system_prop:s0
dhcp.                   u:object_r:dhcp_prop:s0
dhcp.bt-pan.result      u:object_r:pan_result_prop:s0
bluetooth.              u:object_r:bluetooth_prop:s0

debug.                  u:object_r:debug_prop:s0
debug.db.               u:object_r:debuggerd_prop:s0
dumpstate.              u:object_r:dumpstate_prop:s0
dumpstate.options       u:object_r:dumpstate_options_prop:s0
init.svc_debug_pid.     u:object_r:init_svc_debug_prop:s0
llk.                    u:object_r:llkd_prop:s0
khungtask.              u:object_r:llkd_prop:s0
ro.llk.                 u:object_r:llkd_prop:s0
ro.khungtask.           u:object_r:llkd_prop:s0
log.                    u:object_r:log_prop:s0
log.tag                 u:object_r:log_tag_prop:s0
log.tag.WifiHAL         u:object_r:wifi_log_prop:s0
security.perf_harden    u:object_r:shell_prop:s0
service.adb.root        u:object_r:shell_prop:s0
service.adb.tls.port    u:object_r:adbd_prop:s0
persist.adb.wifi.       u:object_r:adbd_prop:s0
persist.adb.tls_server.enable  u:object_r:system_adbd_prop:s0

persist.audio.          u:object_r:audio_prop:s0
persist.bluetooth.      u:object_r:bluetooth_prop:s0
persist.nfc_cfg.        u:object_r:nfc_prop:s0
persist.debug.          u:object_r:persist_debug_prop:s0
logd.                   u:object_r:logd_prop:s0
persist.logd.           u:object_r:logd_prop:s0
ro.logd.                u:object_r:logd_prop:s0
persist.logd.security   u:object_r:device_logging_prop:s0
persist.logd.logpersistd        u:object_r:logpersistd_logging_prop:s0
logd.logpersistd        u:object_r:logpersistd_logging_prop:s0
persist.log.tag         u:object_r:log_tag_prop:s0
persist.mmc.            u:object_r:mmc_prop:s0
persist.netd.stable_secret      u:object_r:netd_stable_secret_prop:s0
persist.pm.mock-upgrade u:object_r:mock_ota_prop:s0
persist.sys.            u:object_r:system_prop:s0
persist.sys.safemode    u:object_r:safemode_prop:s0
persist.sys.theme       u:object_r:theme_prop:s0
persist.sys.fflag.override.settings_dynamic_system    u:object_r:dynamic_system_prop:s0
ro.sys.safemode         u:object_r:safemode_prop:s0
persist.sys.audit_safemode      u:object_r:safemode_prop:s0
persist.sys.dalvik.jvmtiagent   u:object_r:system_jvmti_agent_prop:s0
persist.service.        u:object_r:system_prop:s0
persist.service.bdroid. u:object_r:bluetooth_prop:s0
persist.security.       u:object_r:system_prop:s0
persist.traced.enable   u:object_r:traced_enabled_prop:s0
traced.lazy.            u:object_r:traced_lazy_prop:s0
persist.heapprofd.enable u:object_r:heapprofd_enabled_prop:s0
persist.traced_perf.enable u:object_r:traced_perf_enabled_prop:s0
persist.vendor.overlay.  u:object_r:overlay_prop:s0
ro.boot.vendor.overlay.  u:object_r:overlay_prop:s0
ro.boottime.             u:object_r:boottime_prop:s0
ro.serialno             u:object_r:serialno_prop:s0
ro.boot.btmacaddr       u:object_r:bluetooth_prop:s0
ro.boot.serialno        u:object_r:serialno_prop:s0
ro.bt.                  u:object_r:bluetooth_prop:s0
ro.boot.bootreason      u:object_r:bootloader_boot_reason_prop:s0
persist.sys.boot.reason u:object_r:last_boot_reason_prop:s0
sys.boot.reason         u:object_r:system_boot_reason_prop:s0
sys.boot.reason.last    u:object_r:last_boot_reason_prop:s0
pm.                     u:object_r:pm_prop:s0
test.sys.boot.reason    u:object_r:test_boot_reason_prop:s0
test.userspace_reboot.requested u:object_r:userspace_reboot_test_prop:s0
sys.lmk.                u:object_r:system_lmk_prop:s0
sys.trace.              u:object_r:system_trace_prop:s0

# Fastbootd protocol control property
fastbootd.protocol    u:object_r:fastbootd_protocol_prop:s0 exact enum usb tcp

# adbd protoctl configuration property
service.adb.tcp.port    u:object_r:adbd_config_prop:s0 exact int

# Boolean property set by system server upon boot indicating
# if device is fully owned by organization instead of being
# a personal device.
ro.organization_owned   u:object_r:device_logging_prop:s0

# selinux non-persistent properties
selinux.restorecon_recursive   u:object_r:restorecon_prop:s0

# default property context
*                       u:object_r:default_prop:s0

# data partition encryption properties
vold.                   u:object_r:vold_prop:s0
ro.crypto.              u:object_r:vold_prop:s0

# ro.build.fingerprint is either set in /system/build.prop, or is
# set at runtime by system_server.
ro.build.fingerprint    u:object_r:fingerprint_prop:s0 exact string

ro.persistent_properties.ready  u:object_r:persistent_properties_ready_prop:s0

# ctl properties
ctl.bootanim            u:object_r:ctl_bootanim_prop:s0
ctl.dumpstate           u:object_r:ctl_dumpstate_prop:s0
ctl.fuse_               u:object_r:ctl_fuse_prop:s0
ctl.mdnsd               u:object_r:ctl_mdnsd_prop:s0
ctl.ril-daemon          u:object_r:ctl_rildaemon_prop:s0
ctl.bugreport           u:object_r:ctl_bugreport_prop:s0
ctl.console             u:object_r:ctl_console_prop:s0
ctl.                    u:object_r:ctl_default_prop:s0

# Don't allow uncontrolled access to all services
ctl.sigstop_on$         u:object_r:ctl_sigstop_prop:s0
ctl.sigstop_off$        u:object_r:ctl_sigstop_prop:s0
ctl.start$              u:object_r:ctl_start_prop:s0
ctl.stop$               u:object_r:ctl_stop_prop:s0
ctl.restart$            u:object_r:ctl_restart_prop:s0
ctl.interface_start$    u:object_r:ctl_interface_start_prop:s0
ctl.interface_stop$     u:object_r:ctl_interface_stop_prop:s0
ctl.interface_restart$  u:object_r:ctl_interface_restart_prop:s0

 # Restrict access to starting/stopping adbd
ctl.start$adbd             u:object_r:ctl_adbd_prop:s0
ctl.stop$adbd              u:object_r:ctl_adbd_prop:s0
ctl.restart$adbd           u:object_r:ctl_adbd_prop:s0

# Restrict access to starting/stopping gsid.
ctl.start$gsid          u:object_r:ctl_gsid_prop:s0
ctl.stop$gsid           u:object_r:ctl_gsid_prop:s0
ctl.restart$gsid        u:object_r:ctl_gsid_prop:s0

# Restrict access to stopping apexd.
ctl.stop$apexd          u:object_r:ctl_apexd_prop:s0

# Restrict access to restart dumpstate
ctl.interface_restart$android.hardware.dumpstate u:object_r:ctl_dumpstate_prop:s0

# NFC properties
nfc.                    u:object_r:nfc_prop:s0

# These properties are not normally set by processes other than init.
# They are only distinguished here for setting by qemu-props on the
# emulator/goldfish.
config.                 u:object_r:config_prop:s0
ro.config.              u:object_r:config_prop:s0
dalvik.                 u:object_r:dalvik_prop:s0
ro.dalvik.              u:object_r:dalvik_prop:s0

# Shared between system server and wificond
wifi.                   u:object_r:wifi_prop:s0
wlan.                   u:object_r:wifi_prop:s0

# Lowpan properties
lowpan.                 u:object_r:lowpan_prop:s0
ro.lowpan.              u:object_r:lowpan_prop:s0

# heapprofd properties
heapprofd.              u:object_r:heapprofd_prop:s0

# hwservicemanager properties
hwservicemanager.       u:object_r:hwservicemanager_prop:s0

# Common default properties for vendor, odm, vendor_dlkm, and odm_dlkm.
init.svc.odm.           u:object_r:vendor_default_prop:s0
init.svc.vendor.        u:object_r:vendor_default_prop:s0
ro.hardware.            u:object_r:vendor_default_prop:s0
ro.odm.                 u:object_r:vendor_default_prop:s0
ro.vendor.              u:object_r:vendor_default_prop:s0
ro.vendor_dlkm.         u:object_r:vendor_default_prop:s0
ro.odm_dlkm.            u:object_r:vendor_default_prop:s0
odm.                    u:object_r:vendor_default_prop:s0
persist.odm.            u:object_r:vendor_default_prop:s0
persist.vendor.         u:object_r:vendor_default_prop:s0
vendor.                 u:object_r:vendor_default_prop:s0

# Properties that relate to time / timezone detection behavior.
persist.time.           u:object_r:time_prop:s0

# Properties that relate to server configurable flags
device_config.reset_performed           u:object_r:device_config_reset_performed_prop:s0
persist.device_config.activity_manager_native_boot. u:object_r:device_config_activity_manager_native_boot_prop:s0
persist.device_config.attempted_boot_count        u:object_r:device_config_boot_count_prop:s0
persist.device_config.input_native_boot. u:object_r:device_config_input_native_boot_prop:s0
persist.device_config.netd_native.           u:object_r:device_config_netd_native_prop:s0
persist.device_config.runtime_native.        u:object_r:device_config_runtime_native_prop:s0
persist.device_config.runtime_native_boot.   u:object_r:device_config_runtime_native_boot_prop:s0
persist.device_config.media_native.          u:object_r:device_config_media_native_prop:s0
persist.device_config.storage_native_boot.   u:object_r:device_config_storage_native_boot_prop:s0
persist.device_config.window_manager_native_boot. u:object_r:device_config_window_manager_native_boot_prop:s0
persist.device_config.configuration. u:object_r:device_config_configuration_prop:s0

# Properties that relate to legacy server configurable flags
persist.device_config.global_settings.sys_traced u:object_r:device_config_sys_traced_prop:s0

apexd.                  u:object_r:apexd_prop:s0
persist.apexd.          u:object_r:apexd_prop:s0

bpf.progs_loaded        u:object_r:bpf_progs_loaded_prop:s0

gsid.                   u:object_r:gsid_prop:s0
ro.gsid.                u:object_r:gsid_prop:s0

# Property for disabling NNAPI vendor extensions on product image (used on GSI /product image,
# which can't use NNAPI vendor extensions).
ro.nnapi.extensions.deny_on_product                u:object_r:nnapi_ext_deny_product_prop:s0

# Property that is set once ueventd finishes cold boot.
ro.cold_boot_done       u:object_r:cold_boot_done_prop:s0

# Charger properties
ro.charger.                 u:object_r:charger_prop:s0
sys.boot_from_charger_mode  u:object_r:charger_status_prop:s0 exact int
ro.enable_boot_charger_mode u:object_r:charger_config_prop:s0 exact bool

# Virtual A/B properties
ro.virtual_ab.enabled   u:object_r:virtual_ab_prop:s0
ro.virtual_ab.retrofit  u:object_r:virtual_ab_prop:s0

ro.product.ab_ota_partitions u:object_r:ota_prop:s0 exact string
# Property to set/clear the warm reset flag after an OTA update.
ota.warm_reset  u:object_r:ota_prop:s0

# Module properties
com.android.sdkext.                  u:object_r:module_sdkextensions_prop:s0
persist.com.android.sdkext.          u:object_r:module_sdkextensions_prop:s0

# Userspace reboot properties
sys.userspace_reboot.log.         u:object_r:userspace_reboot_log_prop:s0
persist.sys.userspace_reboot.log. u:object_r:userspace_reboot_log_prop:s0

# Integer property which is used in libgui to configure the number of frames
# tracked by buffer queue's frame event timing history. The property is set
# by devices with video decoding pipelines long enough to overflow the default
# history size.
ro.lib_gui.frame_event_history_size u:object_r:bq_config_prop:s0

af.fast_track_multiplier     u:object_r:audio_config_prop:s0 exact int
ro.af.client_heap_size_kbyte u:object_r:audio_config_prop:s0 exact int

audio.camerasound.force         u:object_r:audio_config_prop:s0 exact bool
audio.deep_buffer.media         u:object_r:audio_config_prop:s0 exact bool
audio.offload.video             u:object_r:audio_config_prop:s0 exact bool
audio.offload.min.duration.secs u:object_r:audio_config_prop:s0 exact int

ro.audio.ignore_effects  u:object_r:audio_config_prop:s0 exact bool
ro.audio.monitorRotation u:object_r:audio_config_prop:s0 exact bool

persist.config.calibration_fac u:object_r:camera_calibration_prop:s0 exact string

config.disable_cameraservice u:object_r:camera_config_prop:s0 exact bool

camera.disable_zsl_mode u:object_r:camera_config_prop:s0 exact bool
camera.fifo.disable     u:object_r:camera_config_prop:s0 exact bool
ro.camera.notify_nfc    u:object_r:camera_config_prop:s0 exact bool
ro.camera.enableLazyHal u:object_r:camera_config_prop:s0 exact bool

# Should always_debuggable be bool? It's checked against the string "1".
dalvik.vm.always_debuggable                   u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.appimageformat                      u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.backgroundgctype                    u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.boot-dex2oat-cpu-set                u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.boot-dex2oat-threads                u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.boot-image                          u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.checkjni                            u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.dex2oat-Xms                         u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.dex2oat-Xmx                         u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.dex2oat-cpu-set                     u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.dex2oat-filter                      u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.dex2oat-flags                       u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.dex2oat-max-image-block-size        u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.dex2oat-minidebuginfo               u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.dex2oat-resolve-startup-strings     u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.dex2oat-threads                     u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.dex2oat-updatable-bcp-packages-file u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.dex2oat-very-large                  u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.dex2oat-swap                        u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.dex2oat64.enabled                   u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.dexopt.secondary                    u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.execution-mode                      u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.extra-opts                          u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.foreground-heap-growth-multiplier   u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.gctype                              u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.heapgrowthlimit                     u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.heapmaxfree                         u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.heapminfree                         u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.heapsize                            u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.heapstartsize                       u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.heaptargetutilization               u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.hot-startup-method-samples          u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.image-dex2oat-Xms                   u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.image-dex2oat-Xmx                   u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.image-dex2oat-cpu-set               u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.image-dex2oat-filter                u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.image-dex2oat-flags                 u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.image-dex2oat-threads               u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.isa.arm.features                    u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.arm.variant                     u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.arm64.features                  u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.arm64.variant                   u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.mips.features                   u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.mips.variant                    u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.mips64.features                 u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.mips64.variant                  u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.unknown.features                u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.unknown.variant                 u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.x86.features                    u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.x86.variant                     u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.x86_64.features                 u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.isa.x86_64.variant                  u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.jitinitialsize                      u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.jitmaxsize                          u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.jitprithreadweight                  u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.jitthreshold                        u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.jittransitionweight                 u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.jniopts                             u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.lockprof.threshold                  u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.method-trace                        u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.method-trace-file                   u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.method-trace-file-siz               u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.method-trace-stream                 u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.profilesystemserver                 u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.profilebootclasspath                u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.restore-dex2oat-cpu-set             u:object_r:dalvik_config_prop:s0 exact string
dalvik.vm.restore-dex2oat-threads             u:object_r:dalvik_config_prop:s0 exact int
dalvik.vm.usejit                              u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.usejitprofiles                      u:object_r:dalvik_config_prop:s0 exact bool
dalvik.vm.zygote.max-boot-retry               u:object_r:dalvik_config_prop:s0 exact int
ro.zygote                                     u:object_r:dalvik_config_prop:s0 exact string

persist.sys.dalvik.vm.lib.2 u:object_r:dalvik_runtime_prop:s0 exact string

keyguard.no_require_sim u:object_r:keyguard_config_prop:s0 exact bool

media.recorder.show_manufacturer_and_model   u:object_r:media_config_prop:s0 exact bool
media.stagefright.cache-params               u:object_r:media_config_prop:s0 exact string
media.stagefright.thumbnail.prefer_hw_codecs u:object_r:media_config_prop:s0 exact bool
persist.sys.media.avsync                     u:object_r:media_config_prop:s0 exact bool

persist.bluetooth.a2dp_offload.cap             u:object_r:bluetooth_a2dp_offload_prop:s0 exact string
persist.bluetooth.a2dp_offload.disabled        u:object_r:bluetooth_a2dp_offload_prop:s0 exact bool
persist.bluetooth.bluetooth_audio_hal.disabled u:object_r:bluetooth_audio_hal_prop:s0 exact bool
persist.bluetooth.btsnoopenable                u:object_r:exported_bluetooth_prop:s0 exact bool

persist.radio.multisim.config u:object_r:radio_control_prop:s0 exact string

persist.sys.hdmi.keep_awake              u:object_r:hdmi_config_prop:s0 exact bool
ro.hdmi.cec_device_types                 u:object_r:hdmi_config_prop:s0 exact string
ro.hdmi.device_type                      u:object_r:hdmi_config_prop:s0 exact string
ro.hdmi.wake_on_hotplug                  u:object_r:hdmi_config_prop:s0 exact bool
ro.hdmi.cec.source.send_standby_on_sleep u:object_r:hdmi_config_prop:s0 exact enum to_tv broadcast none

pm.dexopt.ab-ota                        u:object_r:exported_pm_prop:s0 exact string
pm.dexopt.bg-dexopt                     u:object_r:exported_pm_prop:s0 exact string
pm.dexopt.boot                          u:object_r:exported_pm_prop:s0 exact string
pm.dexopt.disable_bg_dexopt             u:object_r:exported_pm_prop:s0 exact bool
pm.dexopt.downgrade_after_inactive_days u:object_r:exported_pm_prop:s0 exact int
pm.dexopt.first-boot                    u:object_r:exported_pm_prop:s0 exact string
pm.dexopt.inactive                      u:object_r:exported_pm_prop:s0 exact string
pm.dexopt.install                       u:object_r:exported_pm_prop:s0 exact string
pm.dexopt.shared                        u:object_r:exported_pm_prop:s0 exact string

ro.apk_verity.mode u:object_r:apk_verity_prop:s0 exact int

ro.bluetooth.a2dp_offload.supported u:object_r:bluetooth_a2dp_offload_prop:s0 exact bool

ro.boot.vendor.overlay.theme u:object_r:exported_overlay_prop:s0 exact string

ro.bt.bdaddr_path u:object_r:exported_bluetooth_prop:s0 exact string

ro.config.alarm_alert         u:object_r:systemsound_config_prop:s0 exact string
ro.config.alarm_vol_default   u:object_r:systemsound_config_prop:s0 exact int
ro.config.alarm_vol_steps     u:object_r:systemsound_config_prop:s0 exact int
ro.config.media_vol_default   u:object_r:systemsound_config_prop:s0 exact int
ro.config.media_vol_steps     u:object_r:systemsound_config_prop:s0 exact int
ro.config.notification_sound  u:object_r:systemsound_config_prop:s0 exact string
ro.config.ringtone            u:object_r:systemsound_config_prop:s0 exact string
ro.config.system_vol_default  u:object_r:systemsound_config_prop:s0 exact int
ro.config.system_vol_steps    u:object_r:systemsound_config_prop:s0 exact int
ro.config.vc_call_vol_default u:object_r:systemsound_config_prop:s0 exact int

ro.control_privapp_permissions u:object_r:packagemanager_config_prop:s0 exact enum disable enforce log
ro.cp_system_other_odex        u:object_r:packagemanager_config_prop:s0 exact bool

ro.crypto.allow_encrypt_override                u:object_r:vold_config_prop:s0 exact bool
ro.crypto.dm_default_key.options_format.version u:object_r:vold_config_prop:s0 exact int
ro.crypto.fde_algorithm                         u:object_r:vold_config_prop:s0 exact string
ro.crypto.fde_sector_size                       u:object_r:vold_config_prop:s0 exact int
ro.crypto.scrypt_params                         u:object_r:vold_config_prop:s0 exact string
ro.crypto.set_dun                               u:object_r:vold_config_prop:s0 exact bool
ro.crypto.volume.contents_mode                  u:object_r:vold_config_prop:s0 exact string
ro.crypto.volume.filenames_mode                 u:object_r:vold_config_prop:s0 exact string
ro.crypto.volume.metadata.encryption            u:object_r:vold_config_prop:s0 exact string
ro.crypto.volume.metadata.method                u:object_r:vold_config_prop:s0 exact string
ro.crypto.volume.options                        u:object_r:vold_config_prop:s0 exact string

ro.dalvik.vm.native.bridge u:object_r:dalvik_config_prop:s0 exact string

external_storage.projid.enabled   u:object_r:storage_config_prop:s0 exact bool
external_storage.casefold.enabled u:object_r:storage_config_prop:s0 exact bool
external_storage.sdcardfs.enabled u:object_r:storage_config_prop:s0 exact bool

ro.config.per_app_memcg         u:object_r:lmkd_config_prop:s0 exact bool
ro.lmk.critical                 u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.critical_upgrade         u:object_r:lmkd_config_prop:s0 exact bool
ro.lmk.debug                    u:object_r:lmkd_config_prop:s0 exact bool
ro.lmk.downgrade_pressure       u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.kill_heaviest_task       u:object_r:lmkd_config_prop:s0 exact bool
ro.lmk.kill_timeout_ms          u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.low                      u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.medium                   u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.psi_partial_stall_ms     u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.psi_complete_stall_ms    u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.swap_free_low_percentage u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.swap_util_max            u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.thrashing_limit          u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.thrashing_limit_decay    u:object_r:lmkd_config_prop:s0 exact int
ro.lmk.use_minfree_levels       u:object_r:lmkd_config_prop:s0 exact bool
ro.lmk.upgrade_pressure         u:object_r:lmkd_config_prop:s0 exact int
lmkd.reinit                     u:object_r:lmkd_prop:s0 exact int

ro.media.xml_variant.codecs             u:object_r:media_variant_prop:s0 exact string
ro.media.xml_variant.codecs_performance u:object_r:media_variant_prop:s0 exact string
ro.media.xml_variant.profiles           u:object_r:media_variant_prop:s0 exact string

ro.minui.default_rotation u:object_r:recovery_config_prop:s0 exact string
ro.minui.overscan_percent u:object_r:recovery_config_prop:s0 exact int
ro.minui.pixel_format     u:object_r:recovery_config_prop:s0 exact string

ro.oem_unlock_supported u:object_r:oem_unlock_prop:s0 exact int

ro.rebootescrow.device u:object_r:rebootescrow_hal_prop:s0 exact string

ro.storage_manager.enabled u:object_r:sto
```
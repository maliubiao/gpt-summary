Response:
Let's break down the thought process to answer the request about the `psci.h` header file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided `psci.h` header file. This involves identifying its purpose, its relationship to Android, explaining the function implementations (though it's *just* a header, so we need to address that nuance), explaining dynamic linking (even though this file doesn't directly *do* any linking), identifying potential errors, and showing how it's used within Android.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_LINUX_PSCI_H` etc.:**  Standard header file inclusion guard.
* **`/* This file is auto-generated... */`:**  Important!  This tells us we're not looking at hand-written code that performs complex logic. It's generated from some other source (likely a definition file or a kernel source).
* **`#define PSCI_0_2_FN_BASE 0x84000000` and subsequent `#define`s:**  This is the key part. The file defines a series of constants related to PSCI (Power State Coordination Interface). These constants represent function identifiers and bitmasks for various PSCI features and states.

**3. Identifying the Functionality:**

Based on the defined constants (like `PSCI_0_2_FN_CPU_SUSPEND`, `PSCI_0_2_FN_CPU_ON`, `PSCI_0_2_FN_SYSTEM_OFF`), it's clear that this header deals with **power management** at a low level. Specifically, it provides the function identifiers used to communicate with the firmware or hypervisor to control CPU and system power states.

**4. Connecting to Android:**

Given that Bionic is Android's C library and this header is under `bionic/libc/kernel/uapi/linux/`, it's evident that these PSCI functions are used by the Android kernel (Linux) running on ARM architectures. Android relies heavily on power management to optimize battery life.

**5. Addressing the "libc Function Implementation" Question:**

This is a crucial point where we need to be precise. The header file *doesn't implement* any libc functions. It *defines constants*. The actual implementation of these PSCI operations happens within the **kernel** or the **firmware/bootloader**. Bionic (and thus userspace Android code) uses these constants to make system calls (or potentially use other mechanisms) to request these power state changes.

**6. Addressing the "Dynamic Linker" Question:**

Similarly, this header file itself is not directly involved in dynamic linking. However, the *code that uses these constants* (likely in some HAL or low-level system service) might be part of a shared library (`.so`) and therefore subject to dynamic linking. We need to explain the general principles of dynamic linking and provide a plausible scenario, even if this specific header doesn't trigger it directly.

**7. Logic and Assumptions:**

Since the file is just definitions, there's minimal "logic" to trace. However, we can make assumptions about how these constants are used. For example, if `PSCI_0_2_FN_CPU_OFF` is used, we can assume the intent is to turn off a CPU core.

**8. Common Usage Errors:**

Even though this is a header file, incorrect usage of the *constants defined in it* can lead to errors. For instance, using an incorrect function ID or providing invalid parameters when making a PSCI call.

**9. Tracing the Usage from Android Framework/NDK:**

This requires reasoning about the Android architecture. The path from the framework to this low-level header likely involves several layers:

* **Framework (Java):**  High-level power management APIs.
* **System Services (Native):** Implement the framework APIs using lower-level interfaces.
* **HAL (Hardware Abstraction Layer):**  Provides an interface to specific hardware, including power management. This is a likely place where PSCI calls would be made.
* **Kernel Drivers:**  The ultimate handler of the PSCI calls.

We can illustrate this with a concrete example like the "PowerManager" in the framework.

**10. Frida Hook Example:**

To debug this, we need to hook a function that *uses* these constants. Since the constants are primarily for internal kernel/firmware communication, hooking at the HAL level is a good starting point. We'd look for a function in a power management HAL that seems to be invoking PSCI related operations.

**11. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the request with clear headings and explanations. Use examples to illustrate concepts and make the explanation more concrete. Pay attention to the language (Chinese, as requested).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This is a header file, so it doesn't *do* anything."
* **Correction:**  "While it doesn't contain executable code, it defines crucial constants that *are used* by other code to perform power management. The focus should be on the *meaning* and *usage* of these constants."
* **Initial thought:** "Explain libc function implementations."
* **Correction:** "Clarify that this header *defines* constants, not implements libc functions. Explain where the *actual implementation* resides (kernel/firmware) and how userspace interacts with it."
* **Initial thought:** "Directly explain dynamic linking in relation to this header."
* **Correction:**  "Explain the general principles of dynamic linking and how code *using* these constants might be part of a dynamically linked library. Provide a general example rather than forcing a connection where it's not direct."

By following these steps and refining the understanding along the way, we arrive at the comprehensive and accurate answer provided previously.
这个文件 `bionic/libc/kernel/uapi/linux/psci.h` 定义了 **电源状态协调接口 (Power State Coordination Interface, PSCI)** 的用户空间 API。PSCI 是一个在 ARM 架构上用于管理系统电源状态的标准接口，它允许操作系统和 hypervisor (如果存在) 控制 CPU 和系统的电源状态转换。

**功能列举:**

该文件定义了一系列宏，这些宏代表了 PSCI 规范中定义的各种功能调用 ID 和相关的常量。这些功能主要围绕以下几个方面：

1. **获取 PSCI 版本信息:**
   - `PSCI_0_2_FN_PSCI_VERSION`: 获取 PSCI 的版本号。

2. **CPU 电源管理:**
   - `PSCI_0_2_FN_CPU_SUSPEND` / `PSCI_0_2_FN64_CPU_SUSPEND`: 将指定的 CPU 核置于低功耗挂起状态。
   - `PSCI_0_2_FN_CPU_OFF`: 关闭指定的 CPU 核。
   - `PSCI_0_2_FN_CPU_ON` / `PSCI_0_2_FN64_CPU_ON`: 启动指定的 CPU 核。
   - `PSCI_1_0_FN_CPU_FREEZE`: 冻结指定的 CPU 核。
   - `PSCI_1_0_FN_CPU_DEFAULT_SUSPEND` / `PSCI_1_0_FN64_CPU_DEFAULT_SUSPEND`: 将指定的 CPU 核置于默认的低功耗挂起状态。

3. **CPU 亲和性信息:**
   - `PSCI_0_2_FN_AFFINITY_INFO` / `PSCI_0_2_FN64_AFFINITY_INFO`: 查询指定亲和性级别上 CPU 的状态 (例如，是否在线)。

4. **CPU 迁移:**
   - `PSCI_0_2_FN_MIGRATE` / `PSCI_0_2_FN64_MIGRATE`: 将当前执行线程迁移到指定的 CPU 核。
   - `PSCI_0_2_FN_MIGRATE_INFO_TYPE`: 查询迁移信息的类型。
   - `PSCI_0_2_FN_MIGRATE_INFO_UP_CPU` / `PSCI_0_2_FN64_MIGRATE_INFO_UP_CPU`: 获取可以迁移到的 CPU 核。

5. **系统电源管理:**
   - `PSCI_0_2_FN_SYSTEM_OFF`: 关闭整个系统。
   - `PSCI_0_2_FN_SYSTEM_RESET`: 重启整个系统。
   - `PSCI_1_0_FN_SYSTEM_SUSPEND` / `PSCI_1_0_FN64_SYSTEM_SUSPEND`: 将整个系统置于低功耗挂起状态。
   - `PSCI_1_1_FN_SYSTEM_RESET2` / `PSCI_1_1_FN64_SYSTEM_RESET2`:  带有附加参数的系统重启。

6. **节点硬件状态:**
   - `PSCI_1_0_FN_NODE_HW_STATE` / `PSCI_1_0_FN64_NODE_HW_STATE`: 查询系统中节点的硬件状态。

7. **挂起模式设置:**
   - `PSCI_1_0_FN_SET_SUSPEND_MODE`: 设置系统的挂起模式。

8. **统计信息:**
   - `PSCI_1_0_FN_STAT_RESIDENCY` / `PSCI_1_0_FN64_STAT_RESIDENCY`: 获取电源状态的驻留时间统计信息。
   - `PSCI_1_0_FN_STAT_COUNT` / `PSCI_1_0_FN64_STAT_COUNT`: 获取电源状态的进入次数统计信息。

9. **内存保护:**
    - `PSCI_1_1_FN_MEM_PROTECT`:  设置内存保护。
    - `PSCI_1_1_FN_MEM_PROTECT_CHECK_RANGE` / `PSCI_1_1_FN64_MEM_PROTECT_CHECK_RANGE`: 检查内存保护范围。

10. **PSCI 功能查询:**
    - `PSCI_1_0_FN_PSCI_FEATURES`: 查询 PSCI 实现支持的功能。

**与 Android 功能的关系及举例说明:**

PSCI 对于 Android 设备的电源管理至关重要。Android 系统需要有效地管理 CPU 和系统的电源状态，以延长电池寿命并优化性能。以下是一些例子：

* **CPU 热插拔 (CPU Hotplug):** Android 系统可以在运行时动态地开启或关闭 CPU 核以响应负载变化。`PSCI_0_2_FN_CPU_ON` 和 `PSCI_0_2_FN_CPU_OFF` (或其 64 位版本) 就用于实现这个功能。例如，当设备负载较低时，Android 可以关闭一些 CPU 核以节省电量。
* **休眠 (Sleep/Suspend):** 当用户按下电源键或设备一段时间不活动时，Android 可以将系统置于低功耗的休眠状态。`PSCI_1_0_FN_SYSTEM_SUSPEND` (或其 64 位版本) 用于触发这种状态。
* **重启 (Reboot):** 当系统需要重启时，Android 会调用 `PSCI_0_2_FN_SYSTEM_RESET`。
* **CPU 频率调整 (CPU Frequency Scaling):** 虽然 PSCI 本身不直接控制 CPU 频率，但它可以与其他电源管理机制协同工作。例如，当某些 CPU 核被挂起时，剩余的 CPU 核可能会以更高的频率运行。
* **电源管理统计:** Android 可以使用 `PSCI_1_0_FN_STAT_RESIDENCY` 和 `PSCI_1_0_FN_STAT_COUNT` 来收集电源状态统计信息，用于性能分析和电源优化。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要明确的是，这个 `psci.h` 文件本身并没有实现任何 libc 函数。** 它只是一个 **头文件**，定义了一些宏常量。这些宏常量代表了 PSCI 调用的函数 ID。

真正的 PSCI 功能实现位于以下层次：

1. **固件 (Firmware) 或监控程序 (Monitor):**  在 ARM 架构的系统中，PSCI 通常由固件 (例如，ARM Trusted Firmware) 或运行在 EL3 (Exception Level 3) 的监控程序实现。这是最底层的实现，直接与硬件交互来控制电源状态。

2. **内核驱动程序 (Kernel Driver):** Linux 内核包含一个 PSCI 驱动程序，它负责与底层的固件或监控程序通信。当用户空间程序 (例如，通过 system call) 请求执行一个 PSCI 操作时，内核驱动程序会根据请求的函数 ID，按照 PSCI 规范定义的调用约定，调用固件或监控程序提供的接口 (通常是通过 SMC - Secure Monitor Call 指令)。

3. **用户空间 (Userspace):** 用户空间的程序通常 **不会直接调用 PSCI 函数**。相反，它们会调用 Bionic 库或其他库提供的更高级别的 API，这些 API 最终可能会调用内核提供的接口，进而触发 PSCI 调用。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个 `psci.h` 文件本身并不直接涉及 dynamic linker。** 它定义的是内核接口的常量。然而，如果用户空间的某个共享库 (`.so`) 需要使用 PSCI 相关的功能，那么这个库可能会包含调用内核的代码。

**假设一个名为 `libpower_manager.so` 的共享库需要使用 PSCI 功能:**

**`libpower_manager.so` 布局样本:**

```
libpower_manager.so:
    .text          // 代码段
        power_on_cpu:
            // ... 一些逻辑 ...
            mov     r0, #cpu_id
            ldr     r1, =PSCI_0_2_FN_CPU_ON  // 从 .rodata 加载 PSCI 函数 ID
            svc     #0                      // 发起系统调用 (假设使用某种系统调用接口)
            // ... 后续处理 ...
        ... 其他电源管理相关函数 ...
    .rodata        // 只读数据段
        PSCI_0_2_FN_CPU_ON: .word 0x84000003  // 存储 PSCI 函数 ID
    .data          // 可读写数据段
    .bss           // 未初始化数据段
    ... 其他段 ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译 `libpower_manager.so` 的源代码时，编译器会将对 `PSCI_0_2_FN_CPU_ON` 等宏的引用替换为它们对应的值。这些值在 `psci.h` 中定义。
2. **动态链接:** 当 Android 系统加载 `libpower_manager.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 主要负责以下任务：
   - **加载共享库:** 将 `libpower_manager.so` 的代码和数据段加载到内存中的合适位置。
   - **重定位:**  如果 `libpower_manager.so` 中有需要重定位的符号 (例如，引用了其他共享库的函数或全局变量)，dynamic linker 会更新这些符号的地址，使其指向正确的内存位置。
   - **符号解析:**  如果 `libpower_manager.so` 依赖于其他共享库提供的符号，dynamic linker 会查找并绑定这些符号。

**在这个场景中，`psci.h` 定义的常量在编译时就被嵌入到 `libpower_manager.so` 中了，因此 dynamic linker 不需要专门处理 `psci.h` 中的符号。**  dynamic linker 主要处理的是共享库之间的依赖关系和符号解析。

**逻辑推理、假设输入与输出 (虽然 `psci.h` 本身不执行逻辑):**

尽管 `psci.h` 只是定义常量，我们可以假设一个使用这些常量的场景进行逻辑推理：

**假设场景:** 用户空间的进程想要关闭 CPU 核 1。

**假设输入:** CPU 核 ID = 1

**处理步骤 (可能在内核驱动程序中):**

1. 用户空间进程通过某种机制 (例如，ioctl 系统调用) 向内核发送请求，请求关闭 CPU 核 1。该请求可能包含 CPU 核 ID 和操作类型 (关闭)。
2. 内核驱动程序接收到请求。
3. 内核驱动程序根据操作类型，确定需要调用 PSCI 的 `CPU_OFF` 函数。
4. 内核驱动程序从 `psci.h` (或内核中对应的定义) 获取 `PSCI_0_2_FN_CPU_OFF` 的值 (假设为 `0x84000002`)。
5. 内核驱动程序按照 PSCI 规范的调用约定，设置寄存器参数，通常包括函数 ID 和目标 CPU 核 ID。
6. 内核驱动程序执行 SMC 指令，调用固件或监控程序提供的 PSCI 实现。
7. 底层固件或监控程序接收到 SMC 调用，解析函数 ID 和参数，并执行关闭 CPU 核 1 的操作。
8. 底层固件或监控程序返回执行结果 (例如，成功或失败)。
9. 内核驱动程序接收到返回结果，并将其传递回用户空间进程。

**假设输出:** 如果操作成功，则返回 0 (`PSCI_RET_SUCCESS`)；如果 CPU 核不存在或操作失败，则返回相应的错误码 (例如，`PSCI_RET_INVALID_PARAMS` 或 `PSCI_RET_DENIED`)。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用了错误的函数 ID:**  如果程序使用了与 PSCI 规范不符的函数 ID，固件或监控程序可能会返回 `PSCI_RET_NOT_SUPPORTED` 或 `PSCI_RET_INVALID_PARAMS`。
   ```c
   // 错误示例：使用了一个不存在的 PSCI 函数 ID
   long psci_call(unsigned long function_id, unsigned long arg1, unsigned long arg2, unsigned long arg3) {
       // ... 系统调用实现 ...
   }

   int main() {
       // 假设 0xFFFFFFFF 不是一个有效的 PSCI 函数 ID
       long result = psci_call(0xFFFFFFFF, 0, 0, 0);
       if (result == PSCI_RET_NOT_SUPPORTED) {
           printf("PSCI function not supported.\n");
       }
       return 0;
   }
   ```

2. **传递了无效的参数:**  例如，尝试关闭一个不存在的 CPU 核，或者在系统状态不允许的情况下尝试执行某些 PSCI 操作。固件或监控程序可能会返回 `PSCI_RET_INVALID_PARAMS` 或 `PSCI_RET_DENIED`。
   ```c
   // 错误示例：尝试关闭一个不存在的 CPU 核 (假设系统只有 4 个核，ID 为 0-3)
   long psci_call(unsigned long function_id, unsigned long arg1, unsigned long arg2, unsigned long arg3);

   int main() {
       long result = psci_call(PSCI_0_2_FN_CPU_OFF, 4, 0, 0); // 尝试关闭 CPU 核 4
       if (result == PSCI_RET_INVALID_PARAMS) {
           printf("Invalid CPU ID.\n");
       }
       return 0;
   }
   ```

3. **在不合适的上下文中调用 PSCI 函数:**  某些 PSCI 函数可能只能在特定的异常级别或系统状态下调用。例如，某些电源管理操作可能只能由特权代码执行。

4. **忽略返回值:**  PSCI 函数会返回状态码，指示操作是否成功。忽略返回值可能导致程序无法正确处理错误情况。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

从 Android Framework 或 NDK 到达 PSCI 接口通常会经过多个层次：

1. **Android Framework (Java/Kotlin):**  高层电源管理相关的 API，例如 `android.os.PowerManager`。
2. **System Server (Native):**  系统服务 (例如，`power_manager_service`) 实现了 Framework 提供的 API，并与更底层的 HAL 进行交互。
3. **HAL (Hardware Abstraction Layer):**  电源管理相关的 HAL 模块 (例如，`android.hardware.power@X.Y-service`) 定义了硬件抽象接口。
4. **Kernel Driver:**  PSCI 驱动程序 (例如，`drivers/firmware/arm_scmi.c` 或类似的驱动)。

**Frida Hook 示例:**

假设我们想查看当 Android Framework 请求关闭 CPU 核时，PSCI 是如何被调用的。我们可以 Hook 电源管理 HAL 中的相关函数。

**假设 HAL 接口中有一个函数 `set_power_state`，它可以触发 CPU 关闭操作。**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['msg']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn(["com.android.systemui"]) # 假设与电源管理相关的代码在 SystemUI 进程中
    device.resume(pid)
    session = device.attach(pid)

    script_code = """
    Java.perform(function() {
        var PowerManagerService = Java.use('com.android.server.power.PowerManagerService');
        PowerManagerService.shutdown.implementation = function(reboot, reason, confirm, wait) {
            console.log("[*] PowerManagerService.shutdown called");
            this.shutdown(reboot, reason, confirm, wait);
        };
    });

    // Hook 电源管理 HAL 的服务进程 (需要找到对应的进程名)
    var PowerHal = Process.getModuleByName("android.hardware.power@4.0-service"); // 假设 HAL 服务进程名
    if (PowerHal) {
        var symbols = PowerHal.enumerateSymbols();
        for (var i = 0; i < symbols.length; i++) {
            var symbol = symbols[i];
            if (symbol.name.indexOf("set_power_state") !== -1) { // 查找可能的 HAL 函数名
                console.log("[*] Found HAL function: " + symbol.name);
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        console.log("[*] set_power_state called");
                        console.log("[*] Arguments: " + args);
                        // 在这里可以进一步分析参数，判断是否是 CPU 关闭相关的操作
                    },
                    onLeave: function(retval) {
                        console.log("[*] set_power_state returned: " + retval);
                    }
                });
            }
        }
    } else {
        console.log("[!] Power HAL service not found.");
    }

    // 尝试 Hook 内核中的 PSCI 调用 (这通常比较复杂，需要内核符号信息)
    // 可以尝试 Hook 系统调用入口，然后过滤与 PSCI 相关的调用
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

except Exception as e:
    print(e)
```

**解释:**

1. **Hook Android Framework:**  首先，我们 Hook 了 `PowerManagerService.shutdown` 方法，这是一个高层的电源管理入口点。
2. **Hook HAL Service:**  我们尝试找到电源管理 HAL 服务进程的模块，并枚举其符号。然后，我们查找可能与设置电源状态相关的函数 (例如，`set_power_state`) 并进行 Hook。
3. **Hook Kernel (复杂):**  直接 Hook 内核中的 PSCI 调用比较困难，因为需要内核符号信息。一种方法是 Hook 系统调用入口点，然后根据系统调用号和参数来判断是否是与 PSCI 相关的调用。这需要更深入的内核知识。

**调试步骤:**

1. **运行 Frida 脚本:**  将脚本保存为 `.py` 文件，然后在连接到 Android 设备的计算机上运行。
2. **触发电源操作:**  在 Android 设备上触发需要调试的电源操作，例如，按下电源键尝试关机。
3. **查看 Frida 输出:**  Frida 会在终端输出 Hook 到的函数调用和参数，帮助你跟踪电源管理流程，并观察是否最终到达了与 PSCI 相关的代码。

**请注意:**

* 上述 Frida 脚本只是一个示例，实际情况可能更复杂，需要根据具体的 Android 版本和硬件平台进行调整。
* 查找 HAL 服务进程名和相关的 HAL 函数名可能需要一些逆向分析工作。
* Hook 内核函数需要 root 权限和对内核结构的了解。

总而言之，`bionic/libc/kernel/uapi/linux/psci.h` 定义了与电源管理相关的底层接口常量，Android 系统通过多个层次最终使用这些常量与固件或监控程序进行通信，实现对 CPU 和系统电源状态的控制。理解这些常量和其背后的机制对于深入理解 Android 的电源管理至关重要。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/psci.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_PSCI_H
#define _UAPI_LINUX_PSCI_H
#define PSCI_0_2_FN_BASE 0x84000000
#define PSCI_0_2_FN(n) (PSCI_0_2_FN_BASE + (n))
#define PSCI_0_2_64BIT 0x40000000
#define PSCI_0_2_FN64_BASE (PSCI_0_2_FN_BASE + PSCI_0_2_64BIT)
#define PSCI_0_2_FN64(n) (PSCI_0_2_FN64_BASE + (n))
#define PSCI_0_2_FN_PSCI_VERSION PSCI_0_2_FN(0)
#define PSCI_0_2_FN_CPU_SUSPEND PSCI_0_2_FN(1)
#define PSCI_0_2_FN_CPU_OFF PSCI_0_2_FN(2)
#define PSCI_0_2_FN_CPU_ON PSCI_0_2_FN(3)
#define PSCI_0_2_FN_AFFINITY_INFO PSCI_0_2_FN(4)
#define PSCI_0_2_FN_MIGRATE PSCI_0_2_FN(5)
#define PSCI_0_2_FN_MIGRATE_INFO_TYPE PSCI_0_2_FN(6)
#define PSCI_0_2_FN_MIGRATE_INFO_UP_CPU PSCI_0_2_FN(7)
#define PSCI_0_2_FN_SYSTEM_OFF PSCI_0_2_FN(8)
#define PSCI_0_2_FN_SYSTEM_RESET PSCI_0_2_FN(9)
#define PSCI_0_2_FN64_CPU_SUSPEND PSCI_0_2_FN64(1)
#define PSCI_0_2_FN64_CPU_ON PSCI_0_2_FN64(3)
#define PSCI_0_2_FN64_AFFINITY_INFO PSCI_0_2_FN64(4)
#define PSCI_0_2_FN64_MIGRATE PSCI_0_2_FN64(5)
#define PSCI_0_2_FN64_MIGRATE_INFO_UP_CPU PSCI_0_2_FN64(7)
#define PSCI_1_0_FN_PSCI_FEATURES PSCI_0_2_FN(10)
#define PSCI_1_0_FN_CPU_FREEZE PSCI_0_2_FN(11)
#define PSCI_1_0_FN_CPU_DEFAULT_SUSPEND PSCI_0_2_FN(12)
#define PSCI_1_0_FN_NODE_HW_STATE PSCI_0_2_FN(13)
#define PSCI_1_0_FN_SYSTEM_SUSPEND PSCI_0_2_FN(14)
#define PSCI_1_0_FN_SET_SUSPEND_MODE PSCI_0_2_FN(15)
#define PSCI_1_0_FN_STAT_RESIDENCY PSCI_0_2_FN(16)
#define PSCI_1_0_FN_STAT_COUNT PSCI_0_2_FN(17)
#define PSCI_1_1_FN_SYSTEM_RESET2 PSCI_0_2_FN(18)
#define PSCI_1_1_FN_MEM_PROTECT PSCI_0_2_FN(19)
#define PSCI_1_1_FN_MEM_PROTECT_CHECK_RANGE PSCI_0_2_FN(20)
#define PSCI_1_0_FN64_CPU_DEFAULT_SUSPEND PSCI_0_2_FN64(12)
#define PSCI_1_0_FN64_NODE_HW_STATE PSCI_0_2_FN64(13)
#define PSCI_1_0_FN64_SYSTEM_SUSPEND PSCI_0_2_FN64(14)
#define PSCI_1_0_FN64_STAT_RESIDENCY PSCI_0_2_FN64(16)
#define PSCI_1_0_FN64_STAT_COUNT PSCI_0_2_FN64(17)
#define PSCI_1_1_FN64_SYSTEM_RESET2 PSCI_0_2_FN64(18)
#define PSCI_1_1_FN64_MEM_PROTECT_CHECK_RANGE PSCI_0_2_FN64(20)
#define PSCI_0_2_POWER_STATE_ID_MASK 0xffff
#define PSCI_0_2_POWER_STATE_ID_SHIFT 0
#define PSCI_0_2_POWER_STATE_TYPE_SHIFT 16
#define PSCI_0_2_POWER_STATE_TYPE_MASK (0x1 << PSCI_0_2_POWER_STATE_TYPE_SHIFT)
#define PSCI_0_2_POWER_STATE_AFFL_SHIFT 24
#define PSCI_0_2_POWER_STATE_AFFL_MASK (0x3 << PSCI_0_2_POWER_STATE_AFFL_SHIFT)
#define PSCI_1_0_EXT_POWER_STATE_ID_MASK 0xfffffff
#define PSCI_1_0_EXT_POWER_STATE_ID_SHIFT 0
#define PSCI_1_0_EXT_POWER_STATE_TYPE_SHIFT 30
#define PSCI_1_0_EXT_POWER_STATE_TYPE_MASK (0x1 << PSCI_1_0_EXT_POWER_STATE_TYPE_SHIFT)
#define PSCI_0_2_AFFINITY_LEVEL_ON 0
#define PSCI_0_2_AFFINITY_LEVEL_OFF 1
#define PSCI_0_2_AFFINITY_LEVEL_ON_PENDING 2
#define PSCI_0_2_TOS_UP_MIGRATE 0
#define PSCI_0_2_TOS_UP_NO_MIGRATE 1
#define PSCI_0_2_TOS_MP 2
#define PSCI_1_1_RESET_TYPE_SYSTEM_WARM_RESET 0
#define PSCI_1_1_RESET_TYPE_VENDOR_START 0x80000000U
#define PSCI_VERSION_MAJOR_SHIFT 16
#define PSCI_VERSION_MINOR_MASK ((1U << PSCI_VERSION_MAJOR_SHIFT) - 1)
#define PSCI_VERSION_MAJOR_MASK ~PSCI_VERSION_MINOR_MASK
#define PSCI_VERSION_MAJOR(ver) (((ver) & PSCI_VERSION_MAJOR_MASK) >> PSCI_VERSION_MAJOR_SHIFT)
#define PSCI_VERSION_MINOR(ver) ((ver) & PSCI_VERSION_MINOR_MASK)
#define PSCI_VERSION(maj,min) ((((maj) << PSCI_VERSION_MAJOR_SHIFT) & PSCI_VERSION_MAJOR_MASK) | ((min) & PSCI_VERSION_MINOR_MASK))
#define PSCI_1_0_FEATURES_CPU_SUSPEND_PF_SHIFT 1
#define PSCI_1_0_FEATURES_CPU_SUSPEND_PF_MASK (0x1 << PSCI_1_0_FEATURES_CPU_SUSPEND_PF_SHIFT)
#define PSCI_1_0_OS_INITIATED BIT(0)
#define PSCI_1_0_SUSPEND_MODE_PC 0
#define PSCI_1_0_SUSPEND_MODE_OSI 1
#define PSCI_RET_SUCCESS 0
#define PSCI_RET_NOT_SUPPORTED - 1
#define PSCI_RET_INVALID_PARAMS - 2
#define PSCI_RET_DENIED - 3
#define PSCI_RET_ALREADY_ON - 4
#define PSCI_RET_ON_PENDING - 5
#define PSCI_RET_INTERNAL_FAILURE - 6
#define PSCI_RET_NOT_PRESENT - 7
#define PSCI_RET_DISABLED - 8
#define PSCI_RET_INVALID_ADDRESS - 9
#endif
```
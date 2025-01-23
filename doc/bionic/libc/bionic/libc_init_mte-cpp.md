Response:
Let's break down the thought process for answering the user's request about `libc_init_mte.cpp`.

**1. Understanding the Core Task:**

The primary goal of `libc_init_mte.cpp` is to initialize Memory Tagging Extension (MTE) within the Android libc. This involves determining the appropriate MTE level (sync, async, or off), configuring the kernel, and setting up signal handling.

**2. Identifying Key Functionalities:**

I need to analyze the code and pinpoint the major actions it performs. Scanning the code, I see several distinct functions and code blocks that handle different aspects of MTE initialization:

* **Determining MTE level:**  `__get_tagging_level`, `__get_memtag_level_from_note`, `get_environment_memtag_setting`. These functions read MTE configuration from ELF notes, environment variables, and system properties.
* **Enabling MTE:**  The code uses `prctl` to set the tagged address control register.
* **Signal handling:** `__enable_mte_signal_handler` handles a specific signal (`BIONIC_ENABLE_MTE`) to potentially re-enable MTE.
* **Timed upgrade:** `__get_memtag_upgrade_secs` and related logic manage a potential upgrade from asynchronous to synchronous MTE.
* **Stack MTE:** `__libc_init_mte_stack` handles setting the `PROT_MTE` flag for the stack.
* **Checking if MTE is enabled:** `__libc_mte_enabled`.

**3. Connecting to Android Features:**

MTE is a memory safety feature. I need to explain *why* Android would use it and how it relates to overall system security and stability. The connection is direct: MTE helps detect and prevent memory corruption bugs.

**4. Explaining Libc Function Implementations:**

For each identified function, I need to describe what it does and *how* it achieves it. This involves looking at the code and explaining the steps. For example, `__get_memtag_level_from_note` reads the ELF note, parses its contents, and extracts the MTE level.

**5. Addressing Dynamic Linker Involvement:**

The comment within `__libc_init_mte` stating it's called "from the linker before the main executable is relocated" is crucial. This indicates a direct interaction with the dynamic linker. I need to explain:

* **Why the linker is involved:** The linker needs to know the MTE settings of the executable to configure the process correctly.
* **How it's involved:** The linker likely passes information (like the `phdr_start`, `phdr_ct`, and `load_bias`) to `__libc_init_mte`.
* **Provide a sample SO layout:**  Illustrate how the ELF note containing MTE information is embedded within a shared object file.
* **Describe the linking process:** Explain the sequence of events where the linker reads the ELF header, program headers, and notes.

**6. Logical Reasoning and Input/Output:**

For parts of the code that involve decision-making (like choosing the MTE level), I should consider different inputs and their expected outputs. For instance, if the ELF note specifies asynchronous MTE, but the environment variable requests synchronous MTE, the environment variable should override.

**7. Common Usage Errors:**

I need to think about how developers might misuse or misunderstand MTE and what errors could arise. Examples include:

* Relying on MTE for security without proper testing.
* Ignoring MTE-related crashes without investigating the root cause.
* Incorrectly setting environment variables.

**8. Tracing the Path from Framework/NDK:**

This requires understanding the Android startup process. The sequence is roughly:

1. App starts.
2. `zygote` forks a new process.
3. The dynamic linker (`linker64` or `linker`) is invoked.
4. The linker loads the executable and its dependencies.
5. The linker calls `__libc_init_mte` in `libc.so`.

A Frida hook example should target `__libc_init_mte` to observe its execution.

**9. Structure and Language:**

The request specifies Chinese, so the entire response needs to be in Chinese. The response should also be well-structured, with clear headings and bullet points to make it easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the code itself.
* **Correction:** Realize the need to explain the *context* and *purpose* of the code within the Android ecosystem.
* **Initial thought:** Briefly mention the dynamic linker.
* **Refinement:** Understand the critical role of the linker and provide more detail, including the SO layout and linking process.
* **Initial thought:** List the functions and their immediate actions.
* **Refinement:** Explain the *why* behind these actions and their impact on the system.
* **Initial thought:**  A simple Frida hook is enough.
* **Refinement:**  Provide a hook that demonstrates observing the function's arguments.

By following these steps, iterating on the explanation, and focusing on the user's request for comprehensive information, I can construct a detailed and helpful answer. The key is to move beyond simply describing the code to explaining its role and implications within the larger Android system.
这个文件 `bionic/libc/bionic/libc_init_mte.cpp` 是 Android Bionic C 库中负责初始化 **内存标记扩展 (Memory Tagging Extension, MTE)** 功能的源代码文件。MTE 是一种硬件辅助的内存安全功能，旨在帮助检测和防止内存安全漏洞，例如堆溢出和释放后使用。

下面详细列举它的功能，并结合 Android 的特性进行说明：

**核心功能：初始化 MTE**

* **检测和配置 MTE 支持:**  该文件首先会检测当前硬件和内核是否支持 MTE。它通过 `getauxval(AT_HWCAP)` 获取硬件能力，并检查 `HWCAP_MTE` 位。
* **读取 MTE 配置:**  从多个来源读取 MTE 的配置信息：
    * **ELF Note:**  检查可执行文件和共享库的 ELF 头部中是否存在 `NT_ANDROID_TYPE_MEMTAG` 类型的 Note，其中包含了编译时指定的 MTE 级别 (同步或异步) 和是否启用栈 MTE。
    * **Dynamic Entries:** 对于动态链接的可执行文件和共享库，会检查动态链接段 (`.dynamic`) 中是否存在 `DT_AARCH64_MEMTAG_MODE` 和 `DT_AARCH64_MEMTAG_STACK` 类型的 Dynamic Entry，它们提供了与 ELF Note 相同的功能。
    * **环境变量和系统属性:**  检查环境变量 `MEMTAG_OPTIONS` 和系统属性（例如 `arm64.memtag.process.*`, `persist.arm64.memtag.default`, `persist.device_config.memory_safety_native.mode_override.process.*`），允许在运行时覆盖编译时的 MTE 配置。这对于调试和针对特定应用启用/禁用 MTE 非常有用。
* **设置 MTE 模式:**  根据读取到的配置信息，使用 `prctl(PR_SET_TAGGED_ADDR_CTRL)` 系统调用来启用 MTE，并设置其操作模式（同步或异步）。
    * **同步模式 (SYNC):**  当检测到内存标签不匹配时，会立即触发硬件异常 (SIGSEGV)。这种模式可以精确地定位错误发生的位置，但可能会带来一些性能开销。
    * **异步模式 (ASYNC):**  当检测到内存标签不匹配时，不会立即触发异常，而是将错误记录下来，并在稍后的某个时间点报告。这种模式对性能的影响较小，但错误定位可能不如同步模式精确。
* **处理栈 MTE:** 如果配置启用了栈 MTE，它会在线程启动时使用 `mprotect` 系统调用将线程的栈内存区域标记为 `PROT_MTE`，启用栈的内存标记保护。
* **实现 MTE 的定时升级:**  支持从异步 MTE 模式定时升级到同步 MTE 模式。这可以通过设置环境变量 `BIONIC_MEMTAG_UPGRADE_SECS` 来实现。这种机制允许在应用启动初期使用性能影响较小的异步模式，然后在关键操作前切换到更严格的同步模式。
* **处理 `BIONIC_ENABLE_MTE` 信号:**  注册一个信号处理函数 `__enable_mte_signal_handler` 来处理 `BIONIC_ENABLE_MTE` 信号。这个信号可以被发送来动态地重新启用 MTE，即使它在启动时被禁用了。

**与 Android 功能的关系及举例说明：**

* **增强应用安全性:** MTE 是 Android 平台提高应用安全性的重要组成部分。通过硬件级别的内存标记，可以有效检测和阻止各种内存安全漏洞，例如缓冲区溢出、释放后使用等，从而减少应用崩溃和安全风险。例如，一个 C++ 应用如果存在堆溢出漏洞，在启用了 MTE 的设备上运行时，很大概率会因为内存标签不匹配而崩溃，从而暴露漏洞。
* **系统稳定性:**  libc 是 Android 系统中所有应用的基础库，其安全性直接关系到整个系统的稳定性。`libc_init_mte.cpp` 的功能确保了在支持 MTE 的设备上，libc 及其依赖的组件能够正确地利用 MTE 进行内存保护，从而提高系统的整体稳定性。
* **开发者调试工具:**  通过环境变量和系统属性动态控制 MTE 的行为，为开发者提供了强大的调试工具。例如，开发者可以在开发阶段或测试阶段针对特定的应用或场景启用同步 MTE，以便更精确地定位内存错误。
* **兼容性处理:**  该文件需要处理不同 MTE 支持程度的设备。如果硬件或内核不支持 MTE，它会优雅地降级，不会导致应用崩溃。
* **与 Android 的进程模型集成:**  MTE 的初始化是在进程启动的早期阶段进行的，与 Android 的进程模型紧密集成。它在 `linker` 加载可执行文件和共享库之后，但在执行 `main` 函数之前被调用。

**详细解释 libc 函数的实现：**

由于代码中大部分是配置和初始化逻辑，以及对系统调用的封装，我们重点关注几个关键点：

* **`__get_memtag_level_from_note`:**  这个函数负责从 ELF Note 中读取 MTE 配置。它使用 `__find_elf_note` 函数在 Program Header 中查找指定类型的 Note (`NT_ANDROID_TYPE_MEMTAG`)。找到 Note 后，它会解析 Note 的描述部分，提取 MTE 级别和栈 MTE 标志。`__find_elf_note` 本身会遍历 Program Header，找到 `PT_NOTE` 类型的段，并在其中搜索匹配的 Note。
* **`get_environment_memtag_setting`:**  这个函数负责读取环境变量和系统属性来覆盖 MTE 配置。它使用 `getenv` 获取环境变量，使用 `__system_property_get` 获取系统属性。它会按照优先级顺序检查这些配置，并解析字符串值 ("sync", "async", "off") 来设置对应的 MTE 级别。`__gnu_basename` 用于提取进程名的基本名称，用于匹配进程特定的系统属性。
* **`__get_tagging_level`:**  这个函数是获取 MTE 级别的核心逻辑。它首先尝试从 Dynamic Entries 中读取配置，如果不存在，则回退到从 ELF Note 中读取。最后，它会检查是否存在环境变量或系统属性的覆盖。
* **`__enable_mte_signal_handler`:**  这是一个信号处理函数，当接收到 `BIONIC_ENABLE_MTE` 信号时被调用。它使用 `prctl(PR_GET_TAGGED_ADDR_CTRL)` 获取当前的 MTE 配置，然后根据信号传递的值，使用 `prctl(PR_SET_TAGGED_ADDR_CTRL)` 重新设置 MTE 模式。这个机制允许在运行时动态地调整 MTE 的启用状态。
* **`__libc_init_mte`:**  这是 MTE 初始化的入口函数。它调用 `__get_tagging_level` 获取最终的 MTE 级别，然后使用 `prctl` 系统调用启用 MTE 并设置相应的模式。如果配置了定时升级，还会设置一个定时器。最后，它注册 `BIONIC_ENABLE_MTE` 信号的处理函数。
* **`__libc_init_mte_stack`:**  这个函数负责初始化栈 MTE。它首先检查全局变量 `initial_memtag_stack_abi`，该变量指示是否需要启用栈 MTE。如果需要，并且设备支持 MTE，它会使用 `mprotect` 系统调用将栈内存区域标记为 `PROT_MTE`。`__allocate_stack_mte_ringbuffer` 负责分配用于栈 MTE 的环形缓冲区。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

`__libc_init_mte` 函数的调用发生在 dynamic linker 加载共享库之后，但在执行任何应用代码之前。linker 需要知道可执行文件及其依赖的共享库的 MTE 配置，以便正确地为进程配置 MTE。

**SO 布局样本：**

```
ELF Header:
  ...
Program Headers:
  ...
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags Align
  NOTE           0x00000120         0x00000120         0x00000120
                 0x00000020         0x00000020         R     4
  ...
Dynamic Section:
  ...
  Tag        Type                         Name/Value
  0x00000019 (DT_AARCH64_MEMTAG_MODE)   0x1  (ASYNC)
  0x0000001a (DT_AARCH64_MEMTAG_STACK)  0x1  (Enabled)
  ...
```

在这个例子中：

* **Program Headers 中的 NOTE 段:**  可能包含 `NT_ANDROID_TYPE_MEMTAG` 类型的 Note，用于静态链接的可执行文件或者旧版本的共享库。Note 的数据部分会包含 MTE 级别和栈 MTE 标志。
* **Dynamic Section 中的 `DT_AARCH64_MEMTAG_MODE` 和 `DT_AARCH64_MEMTAG_STACK`:**  用于动态链接的共享库，提供了更现代的 MTE 配置方式。`DT_AARCH64_MEMTAG_MODE` 的值为 0 表示同步 MTE，1 表示异步 MTE。`DT_AARCH64_MEMTAG_STACK` 的值为 1 表示启用栈 MTE。

**链接的处理过程：**

1. **linker 解析 ELF Header 和 Program Headers:**  linker 首先读取可执行文件和共享库的 ELF Header，然后解析 Program Headers，找到 `PT_NOTE` 类型的段。
2. **linker 查找 ELF Note:**  在 `PT_NOTE` 段中，linker 会查找 `NT_ANDROID_TYPE_MEMTAG` 类型的 Note。如果找到，它会读取 Note 的描述部分，获取 MTE 配置信息。
3. **linker 解析 Dynamic Section:**  linker 还会解析 Dynamic Section，查找 `DT_AARCH64_MEMTAG_MODE` 和 `DT_AARCH64_MEMTAG_STACK` 类型的 Dynamic Entry，获取 MTE 配置信息。
4. **linker 调用 `__libc_init_mte`:**  在完成必要的加载和重定位之后，linker 会调用 libc 中的 `__libc_init_mte` 函数，并将从 ELF Note 或 Dynamic Entry 中提取的 MTE 配置信息作为参数传递给该函数。
5. **`__libc_init_mte` 配置 MTE:**  `__libc_init_mte` 函数根据接收到的配置信息，使用 `prctl` 系统调用来启用和配置 MTE。

**逻辑推理，假设输入与输出：**

**假设输入：**

* **场景 1：** 可执行文件 ELF Note 中指定了同步 MTE，且启用了栈 MTE。环境变量和系统属性没有覆盖配置。
* **场景 2：** 共享库的 Dynamic Section 中指定了异步 MTE，但未启用栈 MTE。环境变量 `MEMTAG_OPTIONS` 设置为 "sync"。
* **场景 3：** 设备不支持 MTE。

**预期输出：**

* **场景 1：** `__libc_init_mte` 将会调用 `prctl` 设置 MTE 为同步模式，并且 `__libc_shared_globals()->initial_memtag_stack_abi` 将被设置为 `true`。
* **场景 2：** `get_environment_memtag_setting` 将会读取到环境变量的覆盖，`__get_tagging_level` 将会返回同步 MTE。`__libc_init_mte` 将会调用 `prctl` 设置 MTE 为同步模式，即使共享库本身指定的是异步。
* **场景 3：** `__libc_init_mte` 检测到不支持 MTE，将不会调用 `prctl` 设置 MTE 的同步或异步模式，但可能会尝试启用 TBI (Tag-Based Addressing)。`__libc_mte_enabled()` 将返回 `false`。

**涉及用户或者编程常见的使用错误，请举例说明：**

* **错误地假设所有设备都支持 MTE:**  开发者不应假设所有运行其应用的 Android 设备都支持 MTE。在不支持 MTE 的设备上，与 MTE 相关的代码（例如期望 MTE 捕获错误）将不会按预期工作。应该进行适当的特性检测。
* **过度依赖 MTE 进行内存安全，而忽略其他安全实践:**  MTE 是一种强大的工具，但它不能替代良好的编程实践，例如避免缓冲区溢出、正确管理内存等。开发者不应仅仅依赖 MTE 来保证内存安全。
* **错误地配置环境变量或系统属性:**  如果开发者或用户错误地设置了与 MTE 相关的环境变量或系统属性，可能会导致 MTE 的行为不符合预期，例如意外地禁用了 MTE，或者使用了错误的 MTE 模式。
* **混淆同步和异步 MTE 的行为:**  开发者需要理解同步和异步 MTE 的区别。在同步模式下，内存错误会立即导致崩溃，而在异步模式下，错误可能不会立即显现。如果开发者期望立即捕获所有内存错误，但应用运行在异步 MTE 模式下，可能会错过一些错误。
* **在没有充分理解的情况下修改 MTE 相关代码:**  直接修改 bionic 库中的 MTE 相关代码是非常危险的，可能会导致系统不稳定或其他不可预测的问题。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **应用启动:** 当一个 Android 应用启动时，操作系统会创建一个新的进程来运行该应用。
2. **Zygote 进程 fork:**  通常情况下，这个新进程是通过 Zygote 进程 fork 出来的。Zygote 是 Android 系统中一个特殊的进程，用于快速启动新的应用进程。
3. **Dynamic Linker 的调用:** 在新进程创建后，内核会加载 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
4. **Linker 加载依赖库:** dynamic linker 会读取可执行文件的 ELF Header，找到其依赖的共享库（例如 `libc.so`），并将这些库加载到进程的内存空间中。
5. **Linker 解析 ELF 和 Dynamic Section:** linker 会解析加载的共享库的 ELF Header 和 Dynamic Section，包括查找 MTE 相关的 Note 或 Dynamic Entry。
6. **Linker 调用 `__libc_init_mte`:** 在完成必要的库加载和重定位之后，dynamic linker 会调用 `libc.so` 中的 `__libc_init_mte` 函数。这是 MTE 初始化过程的关键步骤。
7. **`__libc_init_mte_stack` 的调用:** 随后，`__libc_init_mte_stack` 会被调用，以设置线程栈的 MTE 保护。
8. **应用代码执行:**  在 MTE 初始化完成后，dynamic linker 会将控制权交给应用的入口点 (`main` 函数或其他指定的入口点)。

**Frida Hook 示例：**

可以使用 Frida Hook 来观察 `__libc_init_mte` 函数的执行过程和参数：

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你要调试的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__libc_init_mte"), {
    onEnter: function(args) {
        console.log("[*] __libc_init_mte called");
        console.log("[*] memtag_dynamic_entries:", args[0]);
        console.log("[*] phdr_start:", args[1]);
        console.log("[*] phdr_ct:", args[2]);
        console.log("[*] load_bias:", args[3]);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__libc_init_mte_stack"), {
    onEnter: function(args) {
        console.log("[*] __libc_init_mte_stack called");
        console.log("[*] stack_top:", args[0]);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print(f"[*] Hooked on '__libc_init_mte' and '__libc_init_mte_stack' in '{package_name}'. Press Ctrl+C to detach.")
sys.stdin.read()
```

**使用方法：**

1. 确保你的 Android 设备已连接并通过 adb 可访问。
2. 确保你已经安装了 Frida 和 frida-tools。
3. 将 `your.package.name` 替换为你想要调试的 Android 应用的包名。
4. 运行这个 Python 脚本。
5. 启动目标 Android 应用。

**预期输出：**

当目标应用启动时，Frida 会 hook 到 `libc.so` 中的 `__libc_init_mte` 和 `__libc_init_mte_stack` 函数，并在控制台上打印出函数的调用信息以及参数值。通过这些信息，你可以观察 MTE 的初始化过程，例如传递给 `__libc_init_mte` 的 MTE 配置信息，以及 `__libc_init_mte_stack` 中设置的栈顶地址。

这个 Frida 示例可以帮助你理解 Android Framework 或 NDK 应用是如何一步步地触发 `libc_init_mte.cpp` 中的代码执行的，并可以用于调试 MTE 相关的行为。

### 提示词
```
这是目录为bionic/libc/bionic/libc_init_mte.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <android/api-level.h>
#include <elf.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/mman.h>

#include "async_safe/log.h"
#include "heap_tagging.h"
#include "libc_init_common.h"
#include "platform/bionic/macros.h"
#include "platform/bionic/mte.h"
#include "platform/bionic/page.h"
#include "platform/bionic/reserved_signals.h"
#include "private/KernelArgumentBlock.h"
#include "private/bionic_asm.h"
#include "private/bionic_asm_note.h"
#include "private/bionic_call_ifunc_resolver.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"
#include "private/elf_note.h"
#include "pthread_internal.h"
#include "sys/system_properties.h"
#include "sysprop_helpers.h"

#ifdef __aarch64__
extern "C" const char* __gnu_basename(const char* path);

static HeapTaggingLevel __get_memtag_level_from_note(const ElfW(Phdr) * phdr_start, size_t phdr_ct,
                                                     const ElfW(Addr) load_bias, bool* stack) {
  const ElfW(Nhdr) * note;
  const char* desc;
  if (!__find_elf_note(NT_ANDROID_TYPE_MEMTAG, "Android", phdr_start, phdr_ct, &note, &desc,
                       load_bias)) {
    return M_HEAP_TAGGING_LEVEL_TBI;
  }

  // Previously (in Android 12), if the note was != 4 bytes, we check-failed
  // here. Let's be more permissive to allow future expansion.
  if (note->n_descsz < 4) {
    async_safe_fatal("unrecognized android.memtag note: n_descsz = %d, expected >= 4",
                     note->n_descsz);
  }

  // `desc` is always aligned due to ELF requirements, enforced in __find_elf_note().
  ElfW(Word) note_val = *reinterpret_cast<const ElfW(Word)*>(desc);
  *stack = (note_val & NT_MEMTAG_STACK) != 0;

  // Warning: In Android 12, any value outside of bits [0..3] resulted in a check-fail.
  if (!(note_val & (NT_MEMTAG_HEAP | NT_MEMTAG_STACK))) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc",
                          "unrecognised memtag note_val did not specificy heap or stack: %u",
                          note_val);
    return M_HEAP_TAGGING_LEVEL_TBI;
  }

  unsigned mode = note_val & NT_MEMTAG_LEVEL_MASK;
  switch (mode) {
    case NT_MEMTAG_LEVEL_NONE:
      // Note, previously (in Android 12), NT_MEMTAG_LEVEL_NONE was
      // NT_MEMTAG_LEVEL_DEFAULT, which implied SYNC mode. This was never used
      // by anyone, but we note it (heh) here for posterity, in case the zero
      // level becomes meaningful, and binaries with this note can be executed
      // on Android 12 devices.
      return M_HEAP_TAGGING_LEVEL_TBI;
    case NT_MEMTAG_LEVEL_ASYNC:
      return M_HEAP_TAGGING_LEVEL_ASYNC;
    case NT_MEMTAG_LEVEL_SYNC:
    default:
      // We allow future extensions to specify mode 3 (currently unused), with
      // the idea that it might be used for ASYMM mode or something else. On
      // this version of Android, it falls back to SYNC mode.
      return M_HEAP_TAGGING_LEVEL_SYNC;
  }
}

// Returns true if there's an environment setting (either sysprop or env var)
// that should overwrite the ELF note, and places the equivalent heap tagging
// level into *level.
static bool get_environment_memtag_setting(HeapTaggingLevel* level) {
  static const char kMemtagPrognameSyspropPrefix[] = "arm64.memtag.process.";
  static const char kMemtagGlobalSysprop[] = "persist.arm64.memtag.default";
  static const char kMemtagOverrideSyspropPrefix[] =
      "persist.device_config.memory_safety_native.mode_override.process.";

  const char* progname = __libc_shared_globals()->init_progname;
  if (progname == nullptr) return false;

  const char* basename = __gnu_basename(progname);

  char options_str[PROP_VALUE_MAX];
  char sysprop_name[512];
  async_safe_format_buffer(sysprop_name, sizeof(sysprop_name), "%s%s", kMemtagPrognameSyspropPrefix,
                           basename);
  char remote_sysprop_name[512];
  async_safe_format_buffer(remote_sysprop_name, sizeof(remote_sysprop_name), "%s%s",
                           kMemtagOverrideSyspropPrefix, basename);
  const char* sys_prop_names[] = {sysprop_name, remote_sysprop_name, kMemtagGlobalSysprop};

  if (!get_config_from_env_or_sysprops("MEMTAG_OPTIONS", sys_prop_names, arraysize(sys_prop_names),
                                       options_str, sizeof(options_str))) {
    return false;
  }

  if (strcmp("sync", options_str) == 0) {
    *level = M_HEAP_TAGGING_LEVEL_SYNC;
  } else if (strcmp("async", options_str) == 0) {
    *level = M_HEAP_TAGGING_LEVEL_ASYNC;
  } else if (strcmp("off", options_str) == 0) {
    *level = M_HEAP_TAGGING_LEVEL_TBI;
  } else {
    async_safe_format_log(
        ANDROID_LOG_ERROR, "libc",
        "unrecognized memtag level: \"%s\" (options are \"sync\", \"async\", or \"off\").",
        options_str);
    return false;
  }

  return true;
}

// Returns the initial heap tagging level. Note: This function will never return
// M_HEAP_TAGGING_LEVEL_NONE, if MTE isn't enabled for this process we enable
// M_HEAP_TAGGING_LEVEL_TBI.
static HeapTaggingLevel __get_tagging_level(const memtag_dynamic_entries_t* memtag_dynamic_entries,
                                            const void* phdr_start, size_t phdr_ct,
                                            uintptr_t load_bias, bool* stack) {
  HeapTaggingLevel level = M_HEAP_TAGGING_LEVEL_TBI;

  // If the dynamic entries exist, use those. Otherwise, fall back to the old
  // Android note, which is still used for fully static executables. When
  // -fsanitize=memtag* is used in newer toolchains, currently both the dynamic
  // entries and the old note are created, but we'd expect to move to just the
  // dynamic entries for dynamically linked executables in the future. In
  // addition, there's still some cleanup of the build system (that uses a
  // manually-constructed note) needed. For more information about the dynamic
  // entries, see:
  // https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#dynamic-section
  if (memtag_dynamic_entries && memtag_dynamic_entries->has_memtag_mode) {
    switch (memtag_dynamic_entries->memtag_mode) {
      case 0:
        level = M_HEAP_TAGGING_LEVEL_SYNC;
        break;
      case 1:
        level = M_HEAP_TAGGING_LEVEL_ASYNC;
        break;
      default:
        async_safe_format_log(ANDROID_LOG_INFO, "libc",
                              "unrecognised DT_AARCH64_MEMTAG_MODE value: %u",
                              memtag_dynamic_entries->memtag_mode);
    }
    *stack = memtag_dynamic_entries->memtag_stack;
  } else {
    level = __get_memtag_level_from_note(reinterpret_cast<const ElfW(Phdr)*>(phdr_start), phdr_ct,
                                         load_bias, stack);
  }

  // We can't short-circuit the environment override, as `stack` is still inherited from the
  // binary's settings.
  get_environment_memtag_setting(&level);
  return level;
}

static void __enable_mte_signal_handler(int, siginfo_t* info, void*) {
  if (info->si_code != SI_TIMER) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "Got BIONIC_ENABLE_MTE not from SI_TIMER");
    return;
  }
  int tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  if (tagged_addr_ctrl < 0) {
    async_safe_fatal("failed to PR_GET_TAGGED_ADDR_CTRL: %m");
  }
  if ((tagged_addr_ctrl & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE) {
    return;
  }
  async_safe_format_log(ANDROID_LOG_INFO, "libc",
                        "Re-enabling MTE, value: %x (tagged_addr_ctrl %lu)",
                        info->si_value.sival_int, info->si_value.sival_int & PR_MTE_TCF_MASK);
  tagged_addr_ctrl =
      (tagged_addr_ctrl & ~PR_MTE_TCF_MASK) | (info->si_value.sival_int & PR_MTE_TCF_MASK);
  if (prctl(PR_SET_TAGGED_ADDR_CTRL, tagged_addr_ctrl, 0, 0, 0) < 0) {
    async_safe_fatal("failed to PR_SET_TAGGED_ADDR_CTRL %d: %m", tagged_addr_ctrl);
  }
}

static int64_t __get_memtag_upgrade_secs() {
  char* env = getenv("BIONIC_MEMTAG_UPGRADE_SECS");
  if (!env) return 0;
  int64_t timed_upgrade = 0;
  static const char kAppProcessName[] = "app_process64";
  const char* progname = __libc_shared_globals()->init_progname;
  progname = progname ? __gnu_basename(progname) : nullptr;
  // disable timed upgrade for zygote, as the thread spawned will violate the requirement
  // that it be single-threaded.
  if (!progname || strncmp(progname, kAppProcessName, sizeof(kAppProcessName)) != 0) {
    char* endptr;
    timed_upgrade = strtoll(env, &endptr, 10);
    if (*endptr != '\0' || timed_upgrade < 0) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                            "Invalid value for BIONIC_MEMTAG_UPGRADE_SECS: %s", env);
      timed_upgrade = 0;
    }
  }
  // Make sure that this does not get passed to potential processes inheriting
  // this environment.
  unsetenv("BIONIC_MEMTAG_UPGRADE_SECS");
  return timed_upgrade;
}

// Figure out the desired memory tagging mode (sync/async, heap/globals/stack) for this executable.
// This function is called from the linker before the main executable is relocated.
__attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte(
    const memtag_dynamic_entries_t* memtag_dynamic_entries, const void* phdr_start, size_t phdr_ct,
    uintptr_t load_bias) {
  bool memtag_stack = false;
  HeapTaggingLevel level =
      __get_tagging_level(memtag_dynamic_entries, phdr_start, phdr_ct, load_bias, &memtag_stack);
  if (memtag_stack) __libc_shared_globals()->initial_memtag_stack_abi = true;

  if (int64_t timed_upgrade = __get_memtag_upgrade_secs()) {
    if (level == M_HEAP_TAGGING_LEVEL_ASYNC) {
      async_safe_format_log(ANDROID_LOG_INFO, "libc",
                            "Attempting timed MTE upgrade from async to sync.");
      __libc_shared_globals()->heap_tagging_upgrade_timer_sec = timed_upgrade;
      level = M_HEAP_TAGGING_LEVEL_SYNC;
    } else if (level != M_HEAP_TAGGING_LEVEL_SYNC) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                            "Requested timed MTE upgrade from invalid %s to sync. Ignoring.",
                            DescribeTaggingLevel(level));
    }
  }
  if (level == M_HEAP_TAGGING_LEVEL_SYNC || level == M_HEAP_TAGGING_LEVEL_ASYNC) {
    unsigned long prctl_arg = PR_TAGGED_ADDR_ENABLE | PR_MTE_TAG_SET_NONZERO;
    prctl_arg |= (level == M_HEAP_TAGGING_LEVEL_SYNC) ? PR_MTE_TCF_SYNC : PR_MTE_TCF_ASYNC;

    // When entering ASYNC mode, specify that we want to allow upgrading to SYNC by OR'ing in the
    // SYNC flag. But if the kernel doesn't support specifying multiple TCF modes, fall back to
    // specifying a single mode.
    if (prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg | PR_MTE_TCF_SYNC, 0, 0, 0) == 0 ||
        prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg, 0, 0, 0) == 0) {
      __libc_shared_globals()->initial_heap_tagging_level = level;

      struct sigaction action = {};
      action.sa_flags = SA_SIGINFO | SA_RESTART;
      action.sa_sigaction = __enable_mte_signal_handler;
      sigaction(BIONIC_ENABLE_MTE, &action, nullptr);
      return;
    }
  }

  // MTE was either not enabled, or wasn't supported on this device. Try and use
  // TBI.
  if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
    __libc_shared_globals()->initial_heap_tagging_level = M_HEAP_TAGGING_LEVEL_TBI;
  }
  // We did not enable MTE, so we do not need to arm the upgrade timer.
  __libc_shared_globals()->heap_tagging_upgrade_timer_sec = 0;
}

// Figure out whether we need to map the stack as PROT_MTE.
// For dynamic executables, this has to be called after loading all
// DT_NEEDED libraries, in case one of them needs stack MTE.
__attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte_stack(void* stack_top) {
  if (!__libc_shared_globals()->initial_memtag_stack_abi) {
    return;
  }

  // Even if the device doesn't support MTE, we have to allocate stack
  // history buffers for code compiled for stack MTE. That is because the
  // codegen expects a buffer to be present in TLS_SLOT_STACK_MTE either
  // way.
  __get_bionic_tcb()->tls_slot(TLS_SLOT_STACK_MTE) = __allocate_stack_mte_ringbuffer(0, nullptr);

  if (__libc_mte_enabled()) {
    __libc_shared_globals()->initial_memtag_stack = true;
    void* pg_start = reinterpret_cast<void*>(page_start(reinterpret_cast<uintptr_t>(stack_top)));
    if (mprotect(pg_start, page_size(), PROT_READ | PROT_WRITE | PROT_MTE | PROT_GROWSDOWN)) {
      async_safe_fatal("error: failed to set PROT_MTE on main thread stack: %m");
    }
  }
}

#else   // __aarch64__
void __libc_init_mte(const memtag_dynamic_entries_t*, const void*, size_t, uintptr_t) {}
void __libc_init_mte_stack(void*) {}
#endif  // __aarch64__

bool __libc_mte_enabled() {
  HeapTaggingLevel lvl = __libc_shared_globals()->initial_heap_tagging_level;
  return lvl == M_HEAP_TAGGING_LEVEL_SYNC || lvl == M_HEAP_TAGGING_LEVEL_ASYNC;
}
```
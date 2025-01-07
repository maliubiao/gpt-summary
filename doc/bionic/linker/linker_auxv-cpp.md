Response:
Let's break down the thought process for answering the user's request about `linker_auxv.cpp`.

**1. Understanding the Core Request:**

The user wants to know about the functionality of `linker_auxv.cpp` within the Android Bionic library. They are interested in:

* **Core functions:** What does the code *do*?
* **Android Relevance:** How does it relate to Android's workings?  Specific examples are requested.
* **`libc` Function Details:**  Explanation of the `libc` functions used.
* **Dynamic Linker Details:** How it ties into the dynamic linking process, including SO layout and linking steps.
* **Logical Reasoning:** Any assumptions and their consequences.
* **Common Errors:** Pitfalls for developers.
* **Android Framework/NDK Path:** How execution reaches this code.
* **Debugging:** Frida hook examples.

**2. Initial Code Analysis - High Level:**

The code primarily deals with the `auxv` array. I can see:

* **`auxv_name(int at)`:**  This function maps `AT_` constants to human-readable string names. It's basically a lookup table.
* **`ld_show_auxv(ElfW(auxv_t)* auxv)`:** This function iterates through the `auxv` array (until `AT_NULL` is reached) and prints the name and value of each entry to standard output. The formatting of the output depends on the `a_type`.

**3. Connecting to Key Concepts - Auxv and Dynamic Linking:**

I recognize that `auxv` stands for "auxiliary vector."  This is a crucial mechanism in Linux-based systems (including Android) for passing information from the kernel to a newly executed process *before* the `main()` function starts. This information is especially important for the dynamic linker.

Key pieces of information in the `auxv`:

* **`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`:** Location, size, and number of program headers in the ELF executable. The dynamic linker needs this to find shared libraries.
* **`AT_BASE`:** The load address of the interpreter (the dynamic linker itself).
* **`AT_ENTRY`:** The entry point of the executable.
* **`AT_RANDOM`:** A pointer to a 16-byte random value.
* **`AT_PLATFORM`:**  A string identifying the hardware platform.
* **`AT_HWCAP`, `AT_HWCAP2`, etc.:**  Hardware capabilities of the CPU.

**4. Addressing Specific User Questions - Detail by Detail:**

* **Functionality:**  The main function is to display the contents of the `auxv` array in a human-readable format. It's primarily for debugging and introspection.
* **Android Relevance:**  Crucial for the dynamic linker's operation. Examples:  Finding shared libraries (`AT_PHDR`), determining the dynamic linker's base address (`AT_BASE`).
* **`libc` Functions:**  Identify the used functions:
    * `stdio.h`: `snprintf` (format and print to a string).
    * `sys/auxv.h`:  Defines the `auxv_t` structure and the `AT_` constants. *Crucial for the purpose of this file.*
    * `unistd.h`: `STDOUT_FILENO` (standard output file descriptor).
    * `async_safe/log.h`: `async_safe_format_fd` (thread-safe formatted output to a file descriptor). *Important Android detail – using async-safe logging.*  Explain why this is necessary in a multi-threaded context.
* **Dynamic Linker:**
    * **SO Layout Sample:** Create a simple example with a main executable and a shared library, showing load addresses and how the `auxv` helps the linker find the shared library's program headers.
    * **Linking Process:** Briefly outline the steps: kernel loads the executable, passes control to the dynamic linker, the dynamic linker reads the `auxv`, maps shared libraries, resolves symbols, and finally transfers control to the application's entry point.
* **Logical Reasoning:** The primary assumption is that the `auxv` array passed to the dynamic linker is correctly populated by the kernel. If it's corrupt, the linker will likely fail. Input: a valid `auxv` array. Output: formatted output of the array's contents.
* **Common Errors:**  Focus on developer interaction (or lack thereof). Developers don't directly *use* this file. The errors would likely be in the kernel or dynamic linker itself. However, *misinterpreting* the output could be a user error.
* **Android Framework/NDK Path:**  Trace the execution flow:
    1. App starts (e.g., through Zygote).
    2. Kernel loads the app's executable.
    3. Kernel sets up the stack and `auxv`.
    4. Kernel starts the dynamic linker.
    5. The dynamic linker (using code like `linker_auxv.cpp` for debugging) processes the `auxv`.
* **Frida Hook:** Show how to hook `ld_show_auxv` to inspect the `auxv` at runtime. This is a powerful debugging technique.

**5. Structuring the Answer:**

Organize the answer logically, following the user's request structure. Use clear headings and subheadings. Provide code examples and explanations where needed. Use bold text for emphasis.

**6. Refinement and Language:**

Ensure the language is clear, concise, and technically accurate. Avoid jargon where possible, or explain it clearly. Translate any code comments and variable names that are relevant to the explanation. Double-check for any inconsistencies or errors. Since the request is in Chinese, the final output should be in Chinese.

By following these steps, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request. The process involves understanding the code, connecting it to relevant concepts, addressing specific questions, and providing clear explanations and examples.
这个 `bionic/linker/linker_auxv.cpp` 文件是 Android Bionic 库中动态链接器 (dynamic linker) 的一部分，它的主要功能是**提供一种调试和查看辅助向量 (auxiliary vector, auxv) 内容的方法**。

**功能概述：**

1. **定义 `auxv_name(int at)` 函数:**  这个函数接收一个整数参数 `at`，该参数代表一个辅助向量条目的类型（例如 `AT_PHDR`, `AT_BASE` 等）。函数的作用是将这些整型的类型值转换为易于理解的字符串名称。这使得打印和查看 auxv 内容时更加清晰。
2. **定义 `ld_show_auxv(ElfW(auxv_t)* auxv)` 函数:**  这个函数接收一个指向辅助向量数组的指针 `auxv`。它的主要功能是遍历这个数组，并使用 `auxv_name` 函数获取每个条目的名称，然后将条目的类型和值打印到标准输出（使用 `async_safe_format_fd`，这是一个线程安全的格式化输出函数）。
3. **格式化输出:**  根据辅助向量条目的类型，`ld_show_auxv` 函数会以不同的格式打印值。例如：
    * 地址类型的条目 (如 `AT_PHDR`, `AT_BASE`) 会以十六进制格式 (`%#lx`) 打印。
    * 标志位类型的条目 (如 `AT_FLAGS`, `AT_HWCAP`) 会以二进制格式 (`%#lb`) 打印。
    * 字符串类型的条目 (如 `AT_EXECFN`, `AT_PLATFORM`) 会以字符串格式 (`"%s"`) 打印。
    * 其他类型的条目会以十进制格式 (`%ld`) 打印。

**与 Android 功能的关系及举例说明：**

这个文件直接服务于 Android 的动态链接器。辅助向量是内核在启动程序时传递给程序的信息，包含了程序运行所需的一些关键参数。动态链接器需要这些信息来完成诸如加载共享库、定位程序入口点等操作。

**举例说明：**

* **`AT_PHDR` (Program Headers Address):**  动态链接器需要知道程序头表的起始地址，才能解析 ELF 文件结构，找到需要加载的共享库信息。`ld_show_auxv` 可以打印出 `AT_PHDR` 的值，让你知道程序头表在哪里。
* **`AT_BASE` (Base Address of Interpreter):** 这指向动态链接器自身的加载地址。当一个动态链接的程序启动时，内核首先加载动态链接器，然后动态链接器负责加载程序本身以及其依赖的共享库。`ld_show_auxv` 可以显示动态链接器被加载到哪个内存地址。
* **`AT_PLATFORM` (Platform String):** 这是一个描述运行平台（例如 "linux"）的字符串。动态链接器可能会根据平台的不同采取不同的行为。`ld_show_auxv` 可以显示当前运行的平台信息。
* **`AT_HWCAP` (Hardware Capabilities):**  这是一个位掩码，指示了处理器支持的硬件特性（例如浮点运算、SIMD 指令集等）。动态链接器和程序可以使用这些信息来选择最优化的代码路径。`ld_show_auxv` 可以打印出这些硬件能力标志。

**详细解释每一个 libc 函数的功能是如何实现的：**

这里涉及的 libc 函数主要有：

1. **`snprintf` (stdio.h):**  用于格式化字符串并将其写入字符数组。它类似于 `sprintf`，但提供了缓冲区大小的限制，防止缓冲区溢出。
    * **实现原理：**  `snprintf` 内部会解析格式化字符串中的占位符（例如 `%d`, `%s`, `%x`），然后将相应的参数转换为字符串并填充到目标缓冲区中。它会确保写入的字符数不超过指定的缓冲区大小。
2. **`async_safe_format_fd` (async_safe/log.h):**  这是一个 Android 特有的函数，用于线程安全地格式化输出到文件描述符。
    * **实现原理：**  由于 Android 系统中多个线程可能会同时进行日志输出等操作，传统的 `printf` 等函数可能不是线程安全的。`async_safe_format_fd` 通过使用原子操作或者锁机制来保证在多线程环境下的安全性，避免数据竞争和错误。它通常用于在链接器或系统服务等关键组件中进行日志输出，因为这些组件可能在各种线程上下文中运行。
3. **`sys/auxv.h` 中定义的宏和结构体:**  这个头文件定义了 `auxv_t` 结构体和 `AT_` 开头的各种常量。
    * **`auxv_t` 结构体：**  通常包含两个成员：`a_type` (表示条目类型，即 `AT_` 常量) 和 `a_un` (一个联合体，用于存储条目的值，可能是整数、指针等)。
    * **`AT_` 常量：**  预定义的整数宏，用于表示不同的辅助向量条目类型。这些常量由内核设置，并被动态链接器读取。
4. **`unistd.h` 中的 `STDOUT_FILENO`:**  这是一个预定义的常量，表示标准输出的文件描述符，通常是 1。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**SO 布局样本：**

假设我们有一个简单的程序 `my_app`，它依赖于一个共享库 `libmylib.so`。

```
内存地址空间:

[栈区]
...
[堆区]
...
[共享库区域]
  0xb7000000 - 0xb7001fff  libmylib.so (加载地址，可能不同)
    .text (代码段)
    .rodata (只读数据段)
    .data (可写数据段)
    .bss (未初始化数据段)
  0xb7100000 - 0xb71fffff  /system/lib/libc.so (加载地址，可能不同)
    ...
  0xb7200000 - 0xb72xxxxx  动态链接器 (linker) 的代码和数据 (加载地址，由 AT_BASE 提供)
...
[程序代码段]
  0x00400000 - 0x00400fff  my_app 的 .text 段
  0x00401000 - 0x00401fff  my_app 的 .rodata 段
  ...
[程序数据段]
  0x00403000 - 0x00403fff  my_app 的 .data 段
  0x00404000 - 0x00404fff  my_app 的 .bss 段
```

**链接的处理过程：**

1. **程序启动:** 当操作系统启动 `my_app` 时，内核会读取 `my_app` 的 ELF 头，发现它是一个动态链接的程序。
2. **加载动态链接器:** 内核会首先将动态链接器加载到内存中的某个地址（这个地址信息会通过 `auxv` 中的 `AT_BASE` 传递给动态链接器）。
3. **传递控制权:** 内核将控制权转移到动态链接器的入口点。
4. **解析 auxv:** 动态链接器开始运行，它会读取内核传递给它的 `auxv` 数组。
5. **获取程序头表信息:** 动态链接器从 `auxv` 中获取 `AT_PHDR` (程序头表地址), `AT_PHENT` (程序头表条目大小), `AT_PHNUM` (程序头表条目数量)。
6. **解析程序头表:** 动态链接器遍历程序头表，查找 `LOAD` 段，确定 `my_app` 代码段、数据段等需要加载到内存的地址和大小。
7. **处理 `PT_DYNAMIC` 段:** 动态链接器查找程序头表中的 `PT_DYNAMIC` 段，该段包含了动态链接的信息，例如依赖的共享库列表 (`DT_NEEDED`)、符号表信息、重定位表信息等。
8. **加载共享库:** 对于 `DT_NEEDED` 中列出的每个共享库（例如 `libmylib.so`），动态链接器会：
    * 查找共享库文件。
    * 将共享库加载到内存中的某个地址（避免地址冲突）。
    * 解析共享库的程序头表，加载其代码段、数据段等。
9. **符号解析和重定位:** 动态链接器会遍历 `my_app` 和加载的共享库的重定位表。重定位表指示了哪些地址需要被修改，以便指向正确的符号地址。
    * 例如，如果 `my_app` 中调用了 `libmylib.so` 中的一个函数 `my_function`，那么在 `my_app` 的代码段中，调用 `my_function` 的指令会先指向一个占位符地址。
    * 动态链接器会在 `libmylib.so` 的符号表中查找 `my_function` 的实际地址。
    * 然后，动态链接器会修改 `my_app` 中调用 `my_function` 的指令，将其指向 `my_function` 的实际地址。
10. **执行初始化代码:**  动态链接器会执行共享库和主程序的初始化函数 (`.init` 和 `.ctors` 段中的代码)。
11. **将控制权转移到程序入口点:** 最后，动态链接器将控制权转移到 `my_app` 的入口点（由 `auxv` 中的 `AT_ENTRY` 提供）。

**假设输入与输出 (针对 `ld_show_auxv`)：**

**假设输入：**

假设在程序启动时，内核传递给动态链接器的 `auxv` 数组包含以下条目（简化示例）：

```
AT_PHDR: 0x7ffffffffe000  // 程序头表地址
AT_PHENT: 56              // 程序头表条目大小
AT_PHNUM: 13              // 程序头表条目数量
AT_BASE: 0xb7200000      // 动态链接器加载地址
AT_ENTRY: 0x400100        // 程序入口点地址
AT_PLATFORM: "linux"
AT_HWCAP: 0xbfebfbff
AT_NULL: 0               // 结束标记
```

**预期输出 (通过 `ld_show_auxv` 打印到标准输出)：**

```
AT_PHDR              0x7ffffffffe000
AT_PHENT             56
AT_PHNUM             13
AT_BASE              0xb7200000
AT_ENTRY             0x400100
AT_PLATFORM          "linux"
AT_HWCAP             0xbfebfbff
```

**用户或编程常见的使用错误：**

1. **直接操作 `auxv` 数组:**  普通用户或应用程序开发者不应该尝试直接修改或访问 `auxv` 数组。这个数组是由内核设置的，并且在程序启动后不应该被更改。尝试这样做可能会导致程序崩溃或行为异常。
2. **误解 `auxv` 的内容:**  理解 `auxv` 中各个条目的含义对于调试动态链接问题非常重要。误解某些条目的含义可能会导致错误的分析和结论。
3. **依赖特定的 `auxv` 值:**  虽然 `auxv` 提供了一些标准的信息，但某些条目的值可能会因操作系统版本、架构或配置而异。不应该编写代码来硬编码或假设特定的 `auxv` 值，除非你非常清楚其适用范围。

**Android framework or ndk 是如何一步步的到达这里：**

1. **应用程序启动:**  当一个 Android 应用程序启动时，无论是 Java 代码还是 Native 代码（通过 NDK），最终都会调用 `fork` 或相关的系统调用来创建一个新的进程。
2. **内核执行:**  内核负责加载应用程序的可执行文件（通常是 APK 包中的 `app_process` 或 `app_process64`，或者 NDK 应用中的可执行文件）。
3. **设置执行环境:**  在加载可执行文件之前，内核会设置新进程的执行环境，包括创建堆栈、加载器环境等。其中一个重要的步骤就是构建 `auxv` 数组，并将相关信息填充进去。这些信息包括程序头表的位置、动态链接器的加载地址、硬件能力等等。
4. **加载动态链接器:** 如果应用程序是动态链接的（通常情况下是），内核会首先加载动态链接器到进程的地址空间。
5. **传递控制权和 `auxv`:**  内核将控制权转移到动态链接器的入口点，并将指向 `auxv` 数组的指针作为参数传递给动态链接器（通常是通过堆栈传递）。
6. **动态链接器运行:**  动态链接器开始执行，它会读取 `auxv` 数组中的信息，执行加载共享库、符号解析、重定位等操作。
7. **`ld_show_auxv` 的使用:**  `ld_show_auxv` 函数通常不会在应用程序的正常执行流程中被调用。它主要是用于动态链接器的内部调试和测试。开发者可以通过修改动态链接器的源代码，在特定的位置调用 `ld_show_auxv` 来查看当前的 `auxv` 内容，以便理解动态链接器的行为。

**Frida hook 示例调试这些步骤：**

你可以使用 Frida hook `ld_show_auxv` 函数来观察在 Android 进程启动时传递给动态链接器的 `auxv` 内容。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用程序的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}. 请确保应用正在运行.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("linker", "_Z11ld_show_auxvP11ElfW_auxv_t"), {
    onEnter: function(args) {
        console.log("[*] 调用 ld_show_auxv");
        const auxv = ptr(args[0]);
        let i = 0;
        while (true) {
            const type = auxv.add(i * Process.pointerSize * 2).readU32();
            const value = auxv.add(i * Process.pointerSize * 2 + Process.pointerSize).readPointer();
            if (type === 0) { // AT_NULL
                break;
            }
            const name = getAuxvName(type);
            console.log(`[*] ${name}: ${value}`);
            i++;
        }
    }
});

function getAuxvName(type) {
    switch (type) {
        case 0: return "AT_NULL";
        case 3: return "AT_PHDR";
        case 4: return "AT_PHENT";
        case 5: return "AT_PHNUM";
        case 6: return "AT_PAGESZ";
        case 7: return "AT_BASE";
        case 9: return "AT_ENTRY";
        case 15: return "AT_PLATFORM";
        case 16: return "AT_HWCAP";
        // ... 添加其他你感兴趣的 AT_ 常量
        default: return "AT_UNKNOWN (" + type + ")";
    }
}
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

try:
    input("按 Enter 键退出...\n")
except KeyboardInterrupt:
    sys.exit()
finally:
    session.detach()
```

**使用步骤：**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 Frida-tools。
2. **连接设备/模拟器:** 确保你的 Android 设备或模拟器已连接到电脑，并且 adb 可用。
3. **运行应用程序:** 启动你要调试的 Android 应用程序。
4. **运行 Frida 脚本:** 将上面的 Python 代码保存为一个文件（例如 `hook_auxv.py`），并将 `package_name` 替换为你的应用程序的包名。然后在终端中运行 `python hook_auxv.py`。
5. **查看输出:** Frida 脚本会 hook 动态链接器中的 `ld_show_auxv` 函数，并在控制台上打印出 `auxv` 数组的内容。

这个 Frida 脚本示例提供了一个基本的方法来观察 `auxv` 的内容。你可以根据需要修改脚本来打印更详细的信息或者过滤特定的 `auxv` 条目。注意，你需要 root 权限或者在可调试的应用上运行 Frida。

Prompt: 
```
这是目录为bionic/linker/linker_auxv.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "linker_auxv.h"

#include <elf.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>

#include <async_safe/log.h>

static const char* auxv_name(int at) {
  switch (at) {
  case AT_NULL: return "AT_NULL";
  case AT_IGNORE: return "AT_IGNORE";
  case AT_EXECFD: return "AT_EXECFD";
  case AT_PHDR: return "AT_PHDR";
  case AT_PHENT: return "AT_PHENT";
  case AT_PHNUM: return "AT_PHNUM";
  case AT_PAGESZ: return "AT_PAGESZ";
  case AT_BASE: return "AT_BASE";
  case AT_FLAGS: return "AT_FLAGS";
  case AT_ENTRY: return "AT_ENTRY";
  case AT_NOTELF: return "AT_NOTELF";
  case AT_UID: return "AT_UID";
  case AT_EUID: return "AT_EUID";
  case AT_GID: return "AT_GID";
  case AT_EGID: return "AT_EGID";
  case AT_PLATFORM: return "AT_PLATFORM";
  case AT_HWCAP: return "AT_HWCAP";
  case AT_CLKTCK: return "AT_CLKTCK";
  case AT_SECURE: return "AT_SECURE";
  case AT_BASE_PLATFORM: return "AT_BASE_PLATFORM";
  case AT_RANDOM: return "AT_RANDOM";
  case AT_HWCAP2: return "AT_HWCAP2";
  case AT_RSEQ_FEATURE_SIZE: return "AT_RSEQ_FEATURE_SIZE";
  case AT_RSEQ_ALIGN: return "AT_RSEQ_ALIGN";
  case AT_HWCAP3: return "AT_HWCAP3";
  case AT_HWCAP4: return "AT_HWCAP4";
  case AT_EXECFN: return "AT_EXECFN";
  case AT_SYSINFO_EHDR: return "AT_SYSINFO_EHDR";
  case AT_MINSIGSTKSZ: return "AT_MINSIGSTKSZ";
#if defined(AT_VECTOR_SIZE_ARCH)
  // AT_VECTOR_SIZE_ARCH isn't a value: it's the number of architecture-specific
  // values that exist for the current architecture, so not relevant here.
#endif
#if defined(AT_SYSINFO)
  case AT_SYSINFO: return "AT_SYSINFO";
#endif
#if defined(AT_L1I_CACHESIZE)
  case AT_L1I_CACHESIZE: return "AT_L1I_CACHESIZE";
#endif
#if defined(AT_L1I_CACHEGEOMETRY)
  case AT_L1I_CACHEGEOMETRY: return "AT_L1I_CACHEGEOMETRY";
#endif
#if defined(AT_L1D_CACHESIZE)
  case AT_L1D_CACHESIZE: return "AT_L1D_CACHESIZE";
#endif
#if defined(AT_L1D_CACHEGEOMETRY)
  case AT_L1D_CACHEGEOMETRY: return "AT_L1D_CACHEGEOMETRY";
#endif
#if defined(AT_L2_CACHESIZE)
  case AT_L2_CACHESIZE: return "AT_L2_CACHESIZE";
#endif
#if defined(AT_L2_CACHEGEOMETRY)
  case AT_L2_CACHEGEOMETRY: return "AT_L2_CACHEGEOMETRY";
#endif
#if defined(AT_L3_CACHESIZE)
  case AT_L3_CACHESIZE: return "AT_L3_CACHESIZE";
#endif
#if defined(AT_L3_CACHEGEOMETRY)
  case AT_L3_CACHEGEOMETRY: return "AT_L3_CACHEGEOMETRY";
#endif
  }
  static char name[32];
  snprintf(name, sizeof(name), "AT_??? (%d)", at);
  return name;
}

void ld_show_auxv(ElfW(auxv_t)* auxv) {
  for (ElfW(auxv_t)* v = auxv; v->a_type != AT_NULL; ++v) {
    const char* name = auxv_name(v->a_type);
    long value = v->a_un.a_val;
    switch (v->a_type) {
    case AT_SYSINFO_EHDR:
    case AT_PHDR:
    case AT_BASE:
    case AT_ENTRY:
    case AT_RANDOM:
      async_safe_format_fd(STDOUT_FILENO, "%-20s %#lx\n", name, value);
      break;
    case AT_FLAGS:
    case AT_HWCAP:
    case AT_HWCAP2:
    case AT_HWCAP3:
    case AT_HWCAP4:
      async_safe_format_fd(STDOUT_FILENO, "%-20s %#lb\n", name, value);
      break;
    case AT_EXECFN:
    case AT_PLATFORM:
      async_safe_format_fd(STDOUT_FILENO, "%-20s \"%s\"\n", name, reinterpret_cast<char*>(value));
      break;
    default:
      async_safe_format_fd(STDOUT_FILENO, "%-20s %ld\n", name, value);
      break;
    }
  }
}

"""

```
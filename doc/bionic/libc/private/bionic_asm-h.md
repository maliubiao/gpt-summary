Response:
My thinking process to answer the request goes through these stages:

1. **Understanding the Core Request:** The user wants to understand the functionality of the `bionic_asm.handroid` header file within the Android Bionic library. They are interested in its purpose, relationship to Android, implementation details, dynamic linking aspects, error handling, and how it's used within the Android framework and NDK. They also want a Frida hooking example.

2. **Initial Analysis of the Code:** I first scan the provided C code. Key observations include:
    * **Copyright and License:** Standard Android Open Source Project license.
    * **Inclusion of `features.h`:** Suggests it's related to conditional compilation and platform-specific features.
    * **Inclusion of `asm/unistd.h`:**  Indicates interaction with system calls.
    * **Architecture-Specific Includes:**  The `#if defined(...)` block clearly points to architecture-specific assembly code (`bionic_asm_arm64.h`, `bionic_asm_arm.h`, etc.). This is a crucial clue about the file's primary function.
    * **Macros:** The code is full of macros like `ENTRY`, `END`, `ALIAS_SYMBOL`. These are the core building blocks and need careful examination.
    * **`.cfi_startproc` and `.cfi_endproc`:**  Relate to DWARF debugging information.
    * **`.globl`, `.hidden`, `.weak`:** These are assembler directives controlling symbol visibility.
    * **`.equ`:**  An assembler directive for defining aliases.
    * **`NOTE_GNU_PROPERTY()`:**  Related to ELF notes.

3. **Identifying Key Functionalities:** Based on the initial analysis, I can deduce the main functions of `bionic_asm.handroid`:
    * **Abstraction Layer for Assembly:** It provides macros to simplify writing assembly code, hiding architecture-specific details to some extent.
    * **System Call Interface:** The inclusion of `asm/unistd.h` and the context suggest it's used to invoke system calls.
    * **Symbol Management:** The `ENTRY`, `ENTRY_PRIVATE`, `ENTRY_WEAK_FOR_NATIVE_BRIDGE`, `ALIAS_SYMBOL` macros are clearly involved in defining and managing the visibility and properties of symbols (functions, data) in the assembly code.
    * **Debugging Information:** The `.cfi_startproc` and `.cfi_endproc` macros indicate the generation of DWARF debugging information.
    * **ELF Notes:** The `NOTE_GNU_PROPERTY()` macro deals with adding ELF notes, particularly relevant for security features like PAC/BTI.

4. **Connecting to Android Functionality:** The file being part of Bionic and dealing with assembly directly links it to core Android functionality. I can connect the identified functionalities to specific Android aspects:
    * **System Calls:** Any interaction with the operating system kernel in Android goes through system calls. This file helps define how those calls are made at the assembly level.
    * **Native Code Execution:** Android relies heavily on native code (C/C++). This header is fundamental for defining the entry points and structure of native functions.
    * **Dynamic Linking:** The `ENTRY_WEAK_FOR_NATIVE_BRIDGE` and `ALIAS_SYMBOL_WEAK_FOR_NATIVE_BRIDGE` macros explicitly mention native bridges, a key component of Android's dynamic linking mechanism for handling ABI compatibility.
    * **Security:** The `NOTE_GNU_PROPERTY()` macro's connection to PAC/BTI illustrates its role in implementing security features.

5. **Explaining Libc Function Implementations:**  Since this file *defines* the structure for assembly functions within Bionic, it doesn't directly *implement* standard libc functions in C. Instead, it provides the scaffolding for the assembly implementations of those functions. I need to explain that the *actual* implementations reside in other `.S` files (assembly source files) included based on the architecture. The macros in this file are the building blocks used within those `.S` files.

6. **Addressing Dynamic Linking:** The macros related to symbol visibility (global, hidden, weak) are directly related to dynamic linking. I need to explain:
    * **SO Layout:** A basic example of how symbols are organized within a shared object (`.so`) file.
    * **Linking Process:**  The role of the dynamic linker in resolving symbols and the implications of global, hidden, and weak symbols. `ENTRY_WEAK_FOR_NATIVE_BRIDGE` is crucial here, as it allows native bridges to override default implementations.

7. **Considering User Errors:**  While this file isn't directly used by end-user programmers, understanding its purpose can help diagnose issues related to:
    * **ABI Compatibility:** Incorrectly defined or managed symbols could lead to linking errors or runtime crashes when native bridges are involved.
    * **Security Vulnerabilities:** Misusing ELF notes or symbol visibility could potentially create security holes.

8. **Tracing the Path from Android Framework/NDK:**  I need to illustrate the call chain:
    * **Framework/NDK Request:** An app making a system call or using a native library function.
    * **NDK Stubs/Wrappers:** The NDK provides C/C++ wrappers around system calls and libc functions.
    * **Bionic Libc:** These wrappers call into the Bionic libc.
    * **Assembly Entry Points:**  The Bionic libc functions often have assembly implementations (or parts of them), and this header file defines the entry points for those assembly implementations.

9. **Frida Hooking Example:**  A Frida example should target a function whose entry point is defined using these macros. A simple libc function like `open` or `read` would be suitable. The hook should demonstrate how to intercept the function call and log information.

10. **Structuring the Answer:** I need to organize the information logically, addressing each part of the user's request. Clear headings, bullet points, and code examples will make the answer easier to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** I might initially focus too much on the specific macros without clearly explaining the overall purpose of the file. I need to step back and first establish that it's an abstraction layer for assembly within Bionic.
* **Clarifying Libc Function Implementation:** I must emphasize that this file doesn't contain the *implementation* of libc functions but defines the *structure* for their assembly implementations.
* **Dynamic Linking Details:** The explanation of dynamic linking needs to be clear and focus on the role of symbol visibility and how `ENTRY_WEAK_FOR_NATIVE_BRIDGE` facilitates overriding.
* **Frida Example Relevance:** The Frida example needs to directly relate to the content of the file, targeting a function whose entry point is likely defined using these macros.

By following these steps and continually refining my understanding, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request.
这个 `bionic/libc/private/bionic_asm.handroid` 头文件是 Android Bionic C 库中非常核心的一个文件，它定义了一些用于编写汇编代码的宏和约定。由于它位于 `private` 目录下，意味着这些接口通常不应该被外部直接使用，而是 Bionic 内部使用的。

**功能列举:**

1. **定义汇编代码的入口和出口:**  它提供了 `ENTRY` 和 `END` 宏，用于标记汇编函数的开始和结束。这包括了处理 DWARF 调试信息。
2. **定义不同可见性的汇编入口:** 提供了 `ENTRY_PRIVATE` (隐藏)，`ENTRY_WEAK_FOR_NATIVE_BRIDGE` (弱链接，用于本地桥接覆盖) 等宏，允许更精细地控制汇编符号的可见性。
3. **定义没有 DWARF 信息的私有汇编入口/出口:** 提供了 `ENTRY_NO_DWARF_PRIVATE` 和 `END_NO_DWARF`，用于一些非常底层的、不需要调试信息的内部函数，例如 `sa_restorer` 中使用的函数。
4. **创建符号别名:** 提供了 `ALIAS_SYMBOL` 和 `ALIAS_SYMBOL_WEAK_FOR_NATIVE_BRIDGE` 宏，用于为现有符号创建别名，可以用于兼容性或本地桥接。
5. **添加 GNU 属性 ELF 注释:**  提供了 `NOTE_GNU_PROPERTY()` 宏，用于在生成的 ELF 文件中添加 GNU 属性注释，例如用于声明对 PAC/BTI (指针认证和分支目标指示) 的支持，这在 ARM64 架构上非常重要。
6. **提供局部标签的便捷语法:**  定义了 `L(__label)` 宏，使得局部标签的命名更简洁。
7. **根据架构包含不同的汇编头文件:**  通过预处理器宏 (`__aarch64__`, `__arm__`, `__i386__`, `__riscv`, `__x86_64__`) 包含架构特定的汇编头文件 (`bionic_asm_arm64.h`, `bionic_asm_arm.h` 等)，实现了跨架构的抽象。
8. **定义系统调用相关的常量:** 定义了 `MAX_ERRNO`，用于识别系统调用返回的错误。
9. **提供自定义的入口和出口钩子:** 提供了 `__bionic_asm_custom_entry` 和 `__bionic_asm_custom_end` 宏，虽然默认是空的，但允许在编译时注入自定义的汇编代码。

**与 Android 功能的关系及举例说明:**

这个文件对于 Android 的底层运行至关重要，因为它直接关系到 Bionic libc 中许多核心函数的实现，尤其是那些需要直接操作硬件或进行底层优化的函数。

* **系统调用:** `asm/unistd.h` 包含了系统调用的编号。Bionic libc 中很多与操作系统交互的函数 (例如 `open`, `read`, `write`, `mmap`) 的实现最终会通过汇编代码调用这些系统调用。`bionic_asm.handroid` 提供的宏用于定义这些汇编函数的入口。
    * **例子:**  `open` 函数的实现可能包含一个汇编部分，使用 `ENTRY(open)` 定义入口，调用对应的 `__NR_open` 系统调用，然后使用 `END(open)` 结束。
* **性能优化:**  一些对性能要求极高的 libc 函数，例如内存操作函数 (`memcpy`, `memset`)、字符串操作函数 (`strlen`, `strcmp`) 等，通常会有汇编优化版本。`bionic_asm.handroid` 提供的宏用于组织这些汇编代码。
    * **例子:** `memcpy` 函数可能有一个针对特定架构优化的汇编实现，使用 `ENTRY(memcpy)` 定义入口，利用特定的 CPU 指令进行快速内存复制。
* **动态链接器:** `ENTRY_WEAK_FOR_NATIVE_BRIDGE` 宏的存在直接关系到 Android 的动态链接器 (linker)。本地桥接 (native bridge) 机制允许在不同的架构上运行为特定架构编译的代码。通过将某些符号声明为弱链接，本地桥接可以在运行时提供自己的实现来覆盖 Bionic 的默认实现。
    * **例子:** 假设有一个为 `arm` 架构编译的 SO 库，在 `arm64` 设备上运行时，动态链接器可能会加载一个 `arm64` 的本地桥接库，该桥接库提供了 `ENTRY_WEAK_FOR_NATIVE_BRIDGE` 声明的函数的 `arm64` 版本实现，从而保证兼容性。
* **安全特性:** `NOTE_GNU_PROPERTY()` 宏用于添加 ELF 注释，这在实现安全特性（如 PAC/BTI）时至关重要。这些注释告诉操作系统或硬件如何处理函数指针，防止某些类型的安全攻击。
    * **例子:** 在 ARM64 架构上，Bionic libc 中使用 `NOTE_GNU_PROPERTY()` 标记支持 PAC/BTI 的函数，使得操作系统在加载这些库时可以启用相应的硬件安全特性。

**libc 函数的实现 (以系统调用为例):**

以 `open` 系统调用为例，简化的实现流程如下：

1. **C 接口:** Bionic libc 提供了一个 C 语言的 `open` 函数接口，它接受路径、标志和模式作为参数。
2. **系统调用号:**  `asm/unistd.h` 中定义了 `open` 系统调用对应的编号，例如 `__NR_open`。
3. **汇编入口:**  在某个 `.S` (汇编源文件) 中，可能会有类似下面的代码：
   ```assembly
   #include <private/bionic_asm.h>
   #include <asm/unistd.h>

   ENTRY(open)
       // ... 将参数移动到正确的寄存器中 (架构相关) ...
       mov     r7, __NR_open  // 将系统调用号加载到 r7 寄存器 (ARM 架构)
       swi     #0             // 触发软中断，发起系统调用
       // ... 处理系统调用的返回值，例如检查错误 ...
       bx      lr             // 返回
   END(open)
   ```
4. **内核处理:** 当执行到 `swi #0` 指令时，CPU 进入内核态，内核根据 `r7` 寄存器中的系统调用号调用相应的内核函数。
5. **返回:** 内核函数执行完毕后，将结果写入寄存器，然后返回到用户空间。汇编代码会检查返回值，并可能设置 `errno`。

**dynamic linker 的功能及 so 布局样本和链接处理过程:**

`bionic_asm.handroid` 中与 dynamic linker 相关的主要体现在 `ENTRY_WEAK_FOR_NATIVE_BRIDGE` 和 `ALIAS_SYMBOL_WEAK_FOR_NATIVE_BRIDGE` 宏的使用上。

**SO 布局样本:**

假设有一个名为 `libexample.so` 的共享库，它包含以下符号：

```c
// libexample.c
int normal_function() { return 1; }
__attribute__((weak)) int weak_function() { return 2; }
```

编译成 SO 后，其符号表 (可以使用 `readelf -s libexample.so` 查看) 可能包含：

```
Num:    Value          Size Type    Bind   Vis      Ndx Name
...
  10: 00001000     24 FUNC    GLOBAL DEFAULT   11 normal_function
  11: 00001020     24 FUNC    WEAK   DEFAULT   11 weak_function
...
```

**链接处理过程:**

1. **加载 SO:** 当 Android 系统加载 `libexample.so` 时，dynamic linker (linker64 或 linker) 会解析其 ELF 头和段信息，将其加载到内存中。
2. **符号解析:** 当其他模块 (例如 APK 的 native library) 依赖 `libexample.so` 中的符号时，dynamic linker 会查找这些符号的定义。
3. **处理弱符号:** 对于使用 `ENTRY_WEAK_FOR_NATIVE_BRIDGE` (在汇编层面) 或 `__attribute__((weak))` (在 C/C++ 层面) 声明的弱符号，dynamic linker 的处理方式有所不同：
   * **首选强符号:** 如果在其他已加载的共享库中找到了同名的 *强符号* (非弱符号)，dynamic linker 会优先链接到强符号。
   * **使用自身符号:** 如果没有找到同名的强符号，dynamic linker 会链接到 `libexample.so` 自身定义的弱符号。
   * **不报错:**  即使没有找到弱符号的定义，链接器通常也不会报错 (除非在链接时指定了某些选项)。

**本地桥接的例子:**

假设 `libexample.so` 中有一个弱符号 `target_function`，并且存在一个本地桥接库 `libnativebridge.so`，它提供了 `target_function` 的另一种实现 (可能是为了兼容不同的架构)。

1. 当 Android 系统在 `arm64` 设备上加载为 `arm` 架构编译的 `libexample.so` 时，dynamic linker 会首先加载本地桥接库 `libnativebridge.so`。
2. `libnativebridge.so` 中可能包含一个使用 `ENTRY(target_function)` 定义的 `arm64` 版本的 `target_function`。
3. 当链接器解析对 `target_function` 的引用时，由于 `libnativebridge.so` 中提供的是强符号，它会优先链接到 `libnativebridge.so` 中的实现，而不是 `libexample.so` 中定义的弱符号。

**假设输入与输出 (逻辑推理):**

假设有一个简单的汇编函数 `add`，它接收两个整数参数并通过寄存器返回它们的和。

**假设输入:** 寄存器 `r0` 和 `r1` 分别包含整数 5 和 10 (ARM 架构为例)。

**汇编代码片段:**

```assembly
#include <private/bionic_asm.h>

ENTRY(add)
    add r0, r0, r1  // 将 r0 和 r1 的值相加，结果存回 r0
    bx lr           // 返回
END(add)
```

**输出:**  执行完 `add` 函数后，寄存器 `r0` 的值将变为 15。

**用户或编程常见的使用错误:**

1. **宏的错误使用:**  例如，忘记使用 `END()` 宏来结束汇编函数定义，可能导致汇编器报错或生成错误的调试信息。
2. **符号可见性错误:**  将本应是内部使用的函数声明为全局可见 (`ENTRY`)，可能导致符号冲突或被意外调用。反之，将需要被外部调用的函数声明为私有 (`ENTRY_PRIVATE`) 会导致链接错误。
3. **本地桥接的误用:**  错误地将不需要被桥接的函数声明为 `ENTRY_WEAK_FOR_NATIVE_BRIDGE`，可能会导致不必要的性能损耗或逻辑错误。
4. **忽略架构差异:**  在编写汇编代码时没有充分考虑不同架构的指令集和调用约定，可能导致代码在某些架构上无法正常工作。
5. **忘记保存和恢复寄存器:**  在汇编函数中修改了调用者期望保持不变的寄存器，但没有进行保存和恢复，可能导致程序状态损坏。

**Android Framework or NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

1. **Android Framework/NDK 发起调用:**
   * **Framework:**  Java 代码通过 JNI (Java Native Interface) 调用 Native 代码。例如，`java.io.File` 类的某些操作最终会调用 Bionic libc 中的文件操作函数。
   * **NDK:**  开发者使用 NDK 编写 C/C++ 代码，这些代码编译后会链接到 Bionic libc。

2. **进入 NDK 编译的 Native 代码或 JNI 调用的 Native 代码:**  这些代码会调用 Bionic libc 提供的函数接口。例如，调用 `open()` 函数打开一个文件。

3. **Bionic libc 函数调用:**  `open()` 函数的 C 语言实现 (在 Bionic libc 源代码中) 可能会进行一些参数校验和处理。

4. **进入汇编实现 (对于某些函数):**  对于性能敏感或需要直接进行系统调用的函数，Bionic libc 可能会有汇编实现。`bionic_asm.handroid` 中定义的 `ENTRY()` 宏就是这些汇编函数的入口。

5. **系统调用:**  汇编代码会设置系统调用号和参数，然后触发系统调用。

**Frida Hook 示例:**

假设我们要 hook `open` 系统调用，观察其调用。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

# 连接到设备上的应用
session = frida.get_usb_device().attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var pathname = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        var mode = args[2] ? args[2].toInt() : -1;
        console.log("open(" + pathname + ", " + flags.toString(8) + ", " + mode.toString(8) + ")");
    },
    onLeave: function(retval) {
        console.log("open returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**调试步骤解释:**

1. **`Interceptor.attach(Module.findExportByName("libc.so", "open"), ...)`:**  这段代码使用 Frida 的 `Interceptor` API 来拦截对 `libc.so` 中 `open` 函数的调用。`Module.findExportByName` 用于查找指定模块中导出函数的地址。
2. **`onEnter: function(args)`:**  当 `open` 函数被调用时，`onEnter` 函数会被执行。`args` 数组包含了传递给 `open` 函数的参数。
3. **`Memory.readUtf8String(args[0])`:**  `open` 函数的第一个参数是文件路径，通常是一个字符串指针。`Memory.readUtf8String` 用于读取该指针指向的字符串。
4. **`args[1].toInt()` 和 `args[2].toInt()`:**  `open` 函数的第二个和第三个参数分别是标志和模式，通常是整数。`.toInt()` 将参数转换为整数。
5. **`console.log(...)`:**  在 Frida 的控制台中打印 `open` 函数的参数值。
6. **`onLeave: function(retval)`:**  当 `open` 函数执行完毕并返回时，`onLeave` 函数会被执行。`retval` 包含了函数的返回值。
7. **`console.log("open returned: " + retval)`:**  打印 `open` 函数的返回值。

通过运行这个 Frida 脚本，当目标应用调用 `open` 函数时，你可以在 Frida 的控制台中看到 `open` 函数的参数和返回值，从而观察 Android Framework 或 NDK 如何一步步地调用到 Bionic libc 的 `open` 函数。虽然这个 hook 的是 C 语言的 `open` 函数，但其内部实现很可能涉及到通过 `bionic_asm.handroid` 定义入口的汇编代码来最终执行系统调用。

Prompt: 
```
这是目录为bionic/libc/private/bionic_asm.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

/* https://github.com/android/ndk/issues/1422 */
#include <features.h>

#include <asm/unistd.h> /* For system call numbers. */
#define MAX_ERRNO 4095  /* For recognizing system call error returns. */

#define __bionic_asm_custom_entry(f)
#define __bionic_asm_custom_end(f)
#define __bionic_asm_function_type @function
#define __bionic_asm_custom_note_gnu_section()

#if defined(__aarch64__)
#include <private/bionic_asm_arm64.h>
#elif defined(__arm__)
#include <private/bionic_asm_arm.h>
#elif defined(__i386__)
#include <private/bionic_asm_x86.h>
#elif defined(__riscv)
#include <private/bionic_asm_riscv64.h>
#elif defined(__x86_64__)
#include <private/bionic_asm_x86_64.h>
#endif

// Starts a normal assembler routine.
#define ENTRY(__f) __ENTRY_WITH_BINDING(__f, .globl)

// Starts an assembler routine with hidden visibility.
#define ENTRY_PRIVATE(__f)           \
  __ENTRY_WITH_BINDING(__f, .globl); \
  .hidden __f;

// Starts an assembler routine that's weak so native bridges can override it.
#define ENTRY_WEAK_FOR_NATIVE_BRIDGE(__f) __ENTRY_WITH_BINDING(__f, .weak)

// Starts an assembler routine with hidden visibility and no DWARF information.
// Only used for internal functions passed via sa_restorer.
// TODO: can't we just delete all those and let the kernel do its thing?
#define ENTRY_NO_DWARF_PRIVATE(__f) \
  __ENTRY_NO_DWARF(__f, .globl);    \
  .hidden __f;

// (Implementation detail.)
#define __ENTRY_NO_DWARF(__f, __binding) \
  .text;                                 \
  __binding __f;                         \
  .balign __bionic_asm_align;            \
  .type __f, __bionic_asm_function_type; \
  __f:                                   \
  __bionic_asm_custom_entry(__f);

// (Implementation detail.)
#define __ENTRY_WITH_BINDING(__f, __binding) \
  __ENTRY_NO_DWARF(__f, __binding);          \
  .cfi_startproc;

// Ends a normal assembler routine.
#define END(__f) \
  .cfi_endproc;  \
  END_NO_DWARF(__f)

// Ends an assembler routine with no DWARF information.
// Only used for internal functions passed via sa_restorer.
// TODO: can't we just delete all those and let the kernel do its thing?
#define END_NO_DWARF(__f) \
  .size __f, .- __f;      \
  __bionic_asm_custom_end(__f)

// Creates an alias `alias` for the symbol `original`.
#define ALIAS_SYMBOL(alias, original) \
  .globl alias;                       \
  .equ alias, original

// Creates an alias `alias` for the symbol `original` that's weak so it can be
// separately overridden by native bridges.
#define ALIAS_SYMBOL_WEAK_FOR_NATIVE_BRIDGE(alias, original) \
  .weak alias;                                               \
  .equ alias, original

// Adds a GNU property ELF note. Important on arm64 to declare PAC/BTI support.
#define NOTE_GNU_PROPERTY() __bionic_asm_custom_note_gnu_section()

// Gives local labels a more convenient and readable syntax.
#define L(__label) .L##__label

"""

```
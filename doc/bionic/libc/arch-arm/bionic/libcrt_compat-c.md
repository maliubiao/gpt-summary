Response:
Let's break down the thought process for generating the response to the user's request.

**1. Understanding the Core Request:**

The user provided a C source file (`libcrt_compat.c`) and wants to understand its function within Android's Bionic library. The key points are:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it connect to the broader Android ecosystem?  Provide concrete examples.
* **Detailed Explanations:** Explain the individual functions listed in the file.
* **Dynamic Linking:**  Explain how this relates to the dynamic linker, including a sample SO layout and the linking process.
* **Logical Reasoning:** If there's any logic or decision-making in the code, explain it with examples.
* **Common Errors:** Point out potential mistakes users might make related to this.
* **Android Framework/NDK Integration:**  Trace the path from higher-level Android components down to this file and provide a Frida hook example.

**2. Initial Analysis of the Source Code:**

The first thing that jumps out is the long list of `extern char` declarations followed by an array initialization. All the `extern char` declarations have names that look like compiler intrinsics or helper functions related to floating-point operations, integer division/modulo, and potentially exception handling (`unwind`).

The `__bionic_libcrt_compat_symbols` array is an array of pointers to these external symbols. This immediately suggests that this file is *not* implementing these functions. Instead, it's providing a *list* of their addresses.

**3. Forming a Hypothesis about the File's Purpose:**

Based on the above analysis, the most likely purpose of this file is to provide a set of compatibility symbols. This is common in dynamic linking scenarios where an older library or binary might expect certain symbols to be present. The `libcrt_compat` part of the filename reinforces this idea. It's likely there to ensure backward compatibility.

**4. Detailing the Functionality (Point 1 of the Request):**

The file's primary function is to create a symbol table containing the addresses of a specific set of low-level runtime functions. These functions are typically provided by the C runtime library (libc) and the compiler's support library (libgcc or equivalent).

**5. Connecting to Android (Point 2 of the Request):**

This is crucial for Bionic's role in Android. Bionic needs to ensure that applications compiled against different versions of the Android NDK or using different compiler versions can still run correctly. This compatibility layer bridges potential gaps in symbol availability. Examples include:

* **Floating-point operations:** Different ARM architectures or compiler versions might have slightly different implementations of floating-point math.
* **Integer division:**  The way integer division by zero is handled can vary.
* **Exception handling:** The ABI for stack unwinding might evolve.

**6. Explaining Individual Functions (Point 3 of the Request):**

Since the file *doesn't* implement the functions, the explanation focuses on their *general purpose*. It's crucial to acknowledge that the implementation resides elsewhere (within libc or libgcc). For each category of functions (arithmetic, comparison, conversion, etc.), provide a brief explanation of what they do. It's also important to mention the naming conventions (e.g., `__aeabi_` for ARM EABI).

**7. Addressing Dynamic Linking (Point 4 of the Request):**

This is a core part of understanding this file. Explain how the dynamic linker uses symbol tables to resolve external references. Provide a simplified SO layout example showing the `.symtab` and `.dynsym` sections. The linking process involves the dynamic linker searching through the symbol tables of loaded libraries to find the definitions of the symbols referenced by an executable or shared library.

**8. Logical Reasoning (Point 5 of the Request):**

This file doesn't contain much explicit *logic*. The "logic" here is the static definition of the symbol table. The *dynamic linker* performs the actual logical steps of resolving symbols. Therefore, the explanation focuses on the dynamic linker's behavior based on the presence of these symbols. A hypothetical scenario could involve an older application expecting `__adddf3` and the dynamic linker finding its address in this compatibility table.

**9. Common Errors (Point 6 of the Request):**

Focus on errors related to *linking* and *ABI compatibility*. Examples include linking against the wrong version of a library or attempting to use functions that are not available in the target environment.

**10. Android Framework/NDK Integration and Frida Hook (Point 7 of the Request):**

Trace the execution flow from a high-level Android component (like an Activity using the NDK) down to the dynamic linker and how it might encounter these compatibility symbols. The Frida hook example should demonstrate how to intercept the access or resolution of one of these symbols. This helps visualize how the compatibility layer is actually used at runtime.

**11. Structuring the Response:**

Organize the information logically using headings and bullet points. Use clear and concise language, avoiding overly technical jargon where possible. Provide examples to illustrate abstract concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file *implements* these functions. **Correction:** The `extern char` declaration and the array of pointers clearly indicate it's just providing a list of addresses, not the implementations.
* **Need to be clearer about the "why":**  Simply stating the functions isn't enough. Explain *why* these specific functions are included – they represent common low-level operations.
* **Dynamic linking needs a concrete example:**  Just explaining the concept isn't as helpful as showing a simplified SO layout.
* **Frida hook needs to be practical:** Focus on hooking the symbol resolution or the function itself.

By following this thought process, breaking down the request into smaller, manageable parts, and continuously refining the understanding of the code's purpose, a comprehensive and accurate response can be generated.
好的，让我们详细分析一下 `bionic/libc/arch-arm/bionic/libcrt_compat.c` 这个文件。

**文件功能总览:**

`libcrt_compat.c` 文件的主要功能是**提供一组符号定义，用于在 Android Bionic 库中提供与旧版本或某些特定编译器生成的代码的兼容性。**  简单来说，它创建了一个符号表，列出了一些常见的底层运行时函数的地址。这些函数通常是编译器生成的代码所依赖的，例如浮点运算、整数运算、异常处理等。

**与 Android 功能的关系及举例说明:**

Android Bionic 作为 Android 系统的 C 标准库、数学库和动态链接器，需要保证应用程序的兼容性。不同的编译器版本或者不同的构建配置可能会生成依赖于不同名称或版本的底层运行时函数的代码。`libcrt_compat.c` 就是为了解决这个问题而存在的。

**举例说明:**

假设有一个较旧的 Android NDK 版本编译的 native 库，它在进行双精度浮点数加法时，期望链接到名为 `__adddf3` 的函数。而在当前 Bionic 版本中，实际使用的可能是另一个名称或者实现方式。

通过在 `libcrt_compat.c` 中定义 `extern char __adddf3;` 并在 `__bionic_libcrt_compat_symbols` 数组中放入 `&__adddf3` 的地址，即使实际的加法函数名称或实现有所不同，动态链接器也能找到一个名为 `__adddf3` 的符号，从而使得旧的 native 库能够正常加载和运行。

**详细解释每一个 libc 函数的功能是如何实现的:**

**关键点：`libcrt_compat.c` *本身并不实现这些函数*。**  它只是声明了这些函数的存在，并提供了它们的地址。这些函数的实际实现位于 Bionic 库的其他部分（例如 `libc.so` 或 `libm.so`，以及编译器提供的库，如 `libgcc.so` 或 `libunwind.so`）。

`libcrt_compat.c` 中列出的函数大致可以分为以下几类：

* **双精度浮点数运算 (`__adddf3`, `__subdf3`, `__muldf3`, `__divdf3`)**:  执行双精度浮点数的加、减、乘、除运算。
* **单精度浮点数运算 (`__addsf3`, `__subsf3`, `__mulsf3`, `__divsf3`)**: 执行单精度浮点数的加、减、乘、除运算。
* **浮点数比较 (`__cmpdf2`, `__cmpsf2`, `__eqdf2`, `__eqsf2`, `__gedf2`, `__gesf2`, `__gtdf2`, `__gtsf2`, `__ledf2`, `__lesf2`, `__ltdf2`, `__ltsf2`, `__nedf2`, `__nesf2`, `__unorddf2`, `__unordsf2`)**:  比较两个浮点数的大小关系（等于、大于、小于等）。`unord` 表示操作数是 NaN (Not a Number)。
* **浮点数类型转换 (`__extendsfdf2`, `__truncdfsf2`, `__floatsidf`, `__floatsisf`, `__floatdidf`, `__floatdisf`, `__floatundidf`, `__floatundisf`, `__floatunsidf`, `__floatunsisf`)**: 在不同精度的浮点数和整数之间进行转换。例如，`__extendsfdf2` 将单精度浮点数转换为双精度浮点数，`__floatsidf` 将有符号整数转换为双精度浮点数。
* **定点数到整数的转换 (`__fixdfsi`, `__fixsfsi`, `__fixunsdfsi`)**: 将浮点数转换为有符号或无符号整数。
* **整数除法和取模 (`__aeabi_idiv`, `__aeabi_idivmod`, `__aeabi_uidiv`, `__aeabi_uidivmod`, `__gnu_ldivmod_helper`, `__gnu_uldivmod_helper`)**: 执行有符号和无符号整数的除法和取模运算。`__aeabi_` 前缀通常表示 ARM EABI (Embedded Application Binary Interface) 定义的函数。`__gnu_` 前缀表示 GNU 提供的函数。
* **长整型运算 (`__muldi3`, `__udivdi3`)**:  执行 64 位整数的乘法和无符号除法运算。
* **位运算 (`__aeabi_lasr`, `__aeabi_llsl`, `__aeabi_llsr`)**: 执行算术右移、逻辑左移和逻辑右移操作。
* **浮点数和整数之间的转换 (ARM EABI 风格) (`__aeabi_f2d`, `__aeabi_d2f`, `__aeabi_i2d`, `__aeabi_i2f`, `__aeabi_l2d`, `__aeabi_l2f`, `__aeabi_ui2d`, `__aeabi_ui2f`, `__aeabi_ul2d`, `__aeabi_ul2f`, `__aeabi_f2iz`, `__aeabi_f2uiz`, `__aeabi_d2iz`, `__aeabi_d2uiz`)**:  在不同类型的浮点数和整数之间进行转换，`iz` 和 `uiz` 后缀表示转换为截断为零的有符号和无符号整数。
* **浮点数比较 (ARM EABI 风格) (`__aeabi_cfcmpeq`, `__aeabi_cfcmple`, `__aeabi_cfrcmple`, `__aeabi_cdcmpeq`, `__aeabi_cdcmple`, `__aeabi_cdrcmple`)**:  执行单精度和双精度浮点数的比较，`c` 表示比较结果为条件代码，`r` 表示反向比较。
* **浮点数算术运算 (ARM EABI 风格) (`__aeabi_fadd`, `__aeabi_fsub`, `__aeabi_fmul`, `__aeabi_fdiv`, `__aeabi_frsub`, `__aeabi_dadd`, `__aeabi_dsub`, `__aeabi_dmul`, `__aeabi_ddiv`, `__aeabi_drsub`)**: 执行单精度和双精度浮点数的加、减、乘、除运算，`rsub` 表示反向减法（第二个操作数减去第一个操作数）。
* **异常处理 (`__aeabi_unwind_cpp_pr0`, `__aeabi_unwind_cpp_pr1`)**:  C++ 异常处理相关的展开操作。`pr0` 和 `pr1` 可能代表不同的展开阶段或协议。
* **人口计数 (`__popcountsi2`)**: 计算一个 32 位整数中二进制位为 1 的个数。`__popcount_tab` 可能是一个用于加速人口计数的查找表。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`libcrt_compat.c` 通过 `__bionic_libcrt_compat_symbols` 数组，向动态链接器提供了一组符号。当一个可执行文件或共享库依赖于这些符号时，动态链接器会查找这些符号的定义。

**SO 布局样本:**

一个典型的共享库 (`.so`) 文件布局可能包含以下部分（简化）：

```
.dynamic        # 动态链接信息，包含依赖库、符号表地址等
.hash           # 符号哈希表，用于加速符号查找
.dynsym         # 动态符号表，包含导出和导入的符号信息
.dynstr         # 动态符号字符串表，存储符号名称字符串
.rel.dyn        # 动态重定位表，用于在加载时修正地址
.rel.plt        # PLT (Procedure Linkage Table) 重定位表，用于延迟绑定
.text           # 代码段
.rodata         # 只读数据段
.data           # 可读写数据段
.bss            # 未初始化数据段
```

**链接处理过程:**

1. **加载时：** 当 Android 系统加载一个可执行文件或共享库时，动态链接器（`linker` 或 `ld-android.so`）会被启动。
2. **解析依赖：** 动态链接器会解析可执行文件或共享库的 `.dynamic` 段，找到其依赖的其他共享库。
3. **查找符号：** 对于可执行文件或共享库中未定义的符号（即外部符号），动态链接器会在其依赖的共享库的符号表（`.dynsym`）中查找。
4. **使用 `libcrt_compat_symbols`：**  `libcrt_compat.so` （或者 `libc.so` 中包含了这部分符号）导出了 `__bionic_libcrt_compat_symbols` 数组。动态链接器在查找符号时，会遍历已加载的共享库的符号表，包括 `libcrt_compat.so` 提供的这组兼容性符号。
5. **重定位：** 一旦找到符号的地址，动态链接器会使用重定位表（`.rel.dyn` 或 `.rel.plt`）来更新可执行文件或共享库中引用该符号的位置，将其指向实际的函数地址。

**假设输入与输出 (逻辑推理，虽然此文件本身不包含复杂逻辑):**

假设有一个旧的 native 库 `old_lib.so`，它在代码中调用了 `__adddf3` 函数。

* **输入：** 加载 `old_lib.so` 的请求。动态链接器开始解析 `old_lib.so` 的依赖和符号引用。
* **查找 `__adddf3`：** 动态链接器在 `libc.so` 的符号表中没有找到名为 `__adddf3` 的符号（假设当前的 `libc.so` 使用了不同的内部名称）。
* **查找兼容性符号：** 动态链接器继续查找，并在 `libcrt_compat.so` 提供的 `__bionic_libcrt_compat_symbols` 数组中找到了 `__adddf3` 的地址。这个地址实际上指向了当前 `libc.so` 中用于双精度浮点数加法的函数的地址。
* **输出：** `old_lib.so` 成功加载，并且对 `__adddf3` 的调用最终会执行当前 `libc.so` 中的双精度浮点数加法实现。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **ABI 不兼容：**  如果在编译 native 代码时使用了与目标 Android 系统不兼容的 toolchain 或 NDK 版本，可能会导致链接器无法找到某些必要的符号，即使 `libcrt_compat.c` 提供了一些兼容性符号，也无法覆盖所有情况。例如，如果依赖于一个完全被移除的函数，则无法通过这种方式兼容。
2. **错误的函数签名：**  `libcrt_compat.c` 只能提供符号的地址，而不能改变函数的调用约定或参数类型。如果 native 代码期望的函数签名与实际提供的函数签名不匹配，仍然会导致运行时错误，例如栈损坏。
3. **过度依赖兼容性符号：**  虽然 `libcrt_compat.c` 提供了一定的便利性，但开发者应该尽量避免依赖于这些兼容性符号，而是应该使用与目标 Android 系统版本相匹配的 NDK 进行编译，以确保代码的稳定性和性能。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 调用 NDK 代码：**
   - Android Framework (Java 层) 通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。
   - 例如，一个 Activity 中的某个 Java 方法可能会调用一个声明为 `native` 的方法。
   - JVM 会查找并加载包含该 Native 方法实现的共享库 (`.so` 文件)。

2. **动态链接器介入：**
   - 当 JVM 加载 `.so` 文件时，Android 的动态链接器会负责解析该库的依赖关系并链接所需的符号。
   - 动态链接器会读取 `.so` 文件的头部信息，找到其依赖的其他库，例如 `libc.so`。

3. **查找符号并使用 `libcrt_compat_symbols`：**
   - 如果 `.so` 文件中引用了 `libcrt_compat.c` 中定义的某个符号（例如 `__adddf3`），动态链接器会在 `libc.so` 中查找。
   - `libc.so` 会将 `__bionic_libcrt_compat_symbols` 数组导出，供动态链接器使用。
   - 动态链接器找到 `__adddf3` 在 `__bionic_libcrt_compat_symbols` 中的地址，并将其链接到 `.so` 文件中对应的调用位置。

**Frida Hook 示例:**

我们可以使用 Frida hook `__adddf3` 函数，来观察何时以及如何调用到这个兼容性符号。

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名
function_name = "__adddf3"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Hooked {function_name}: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = f"""
Interceptor.attach(Module.findExportByName(null, "{function_name}"), {
    onEnter: function(args) {
        console.log("[*] Entering {function_name}");
        console.log("arg0: " + args[0]); // 第一个参数
        console.log("arg1: " + args[1]); // 第二个参数
        // 可以修改参数值
        // args[0] = ...;
    },
    onLeave: function(retval) {
        console.log("[*] Leaving {function_name}");
        console.log("retval: " + retval); // 返回值
        // 可以修改返回值
        // retval.replace(...);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida-tools。
2. **运行目标应用:** 启动你想要调试的 Android 应用。
3. **运行 Frida 脚本:** 将上面的 Python 脚本保存为 `hook_adddf3.py`，并将 `your.app.package.name` 替换为你的应用包名。在终端中运行 `python hook_adddf3.py`。
4. **触发调用:** 在你的应用中执行会间接调用到 `__adddf3` 的操作（例如，涉及到双精度浮点数运算的 native 代码）。
5. **查看输出:** Frida 会拦截对 `__adddf3` 的调用，并打印出进入函数时的参数和离开函数时的返回值。

通过这个 Frida hook 示例，你可以观察到当 Android Framework 调用到使用了浮点运算的 NDK 代码时，可能会触发对 `__adddf3` 兼容性符号的调用，从而验证 `libcrt_compat.c` 在其中的作用。

总结来说，`libcrt_compat.c` 虽然代码量不大，但在 Android Bionic 中扮演着重要的角色，它通过提供一组兼容性符号，提高了 Android 系统的稳定性和对旧版本 native 代码的兼容性。

### 提示词
```
这是目录为bionic/libc/arch-arm/bionic/libcrt_compat.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

extern char __adddf3;
extern char __addsf3;
extern char __aeabi_cdcmpeq;
extern char __aeabi_cdcmple;
extern char __aeabi_cdrcmple;
extern char __aeabi_cfcmpeq;
extern char __aeabi_cfcmple;
extern char __aeabi_cfrcmple;
extern char __aeabi_d2f;
extern char __aeabi_d2iz;
extern char __aeabi_d2uiz;
extern char __aeabi_dadd;
extern char __aeabi_dcmpeq;
extern char __aeabi_dcmpge;
extern char __aeabi_dcmpgt;
extern char __aeabi_dcmple;
extern char __aeabi_dcmplt;
extern char __aeabi_dcmpun;
extern char __aeabi_ddiv;
extern char __aeabi_dmul;
extern char __aeabi_drsub;
extern char __aeabi_dsub;
extern char __aeabi_f2d;
extern char __aeabi_f2iz;
extern char __aeabi_f2uiz;
extern char __aeabi_fadd;
extern char __aeabi_fcmpeq;
extern char __aeabi_fcmpge;
extern char __aeabi_fcmpgt;
extern char __aeabi_fcmple;
extern char __aeabi_fcmplt;
extern char __aeabi_fcmpun;
extern char __aeabi_fdiv;
extern char __aeabi_fmul;
extern char __aeabi_frsub;
extern char __aeabi_fsub;
extern char __aeabi_i2d;
extern char __aeabi_i2f;
extern char __aeabi_idiv;
extern char __aeabi_idivmod;
extern char __aeabi_l2d;
extern char __aeabi_l2f;
extern char __aeabi_lasr;
extern char __aeabi_ldivmod;
extern char __aeabi_llsl;
extern char __aeabi_llsr;
extern char __aeabi_lmul;
extern char __aeabi_ui2d;
extern char __aeabi_ui2f;
extern char __aeabi_uidiv;
extern char __aeabi_uidivmod;
extern char __aeabi_ul2d;
extern char __aeabi_ul2f;
extern char __aeabi_uldivmod;
extern char __aeabi_unwind_cpp_pr0;
extern char __aeabi_unwind_cpp_pr1;
extern char __cmpdf2;
extern char __cmpsf2;
extern char __divdf3;
extern char __divsf3;
extern char __eqdf2;
extern char __eqsf2;
extern char __extendsfdf2;
extern char __fixdfsi;
extern char __fixsfsi;
extern char __fixunsdfsi;
extern char __floatdidf;
extern char __floatdisf;
extern char __floatsidf;
extern char __floatsisf;
extern char __floatundidf;
extern char __floatundisf;
extern char __floatunsidf;
extern char __floatunsisf;
extern char __gedf2;
extern char __gesf2;
extern char __gtdf2;
extern char __gtsf2;
extern char __gnu_ldivmod_helper;
extern char __gnu_uldivmod_helper;
extern char __ledf2;
extern char __lesf2;
extern char __ltdf2;
extern char __ltsf2;
extern char __muldf3;
extern char __muldi3;
extern char __mulsf3;
extern char __nedf2;
extern char __nesf2;
extern char __popcount_tab;
extern char __popcountsi2;
extern char __subdf3;
extern char __subsf3;
extern char __truncdfsf2;
extern char __udivdi3;
extern char __unorddf2;
extern char __unordsf2;

void* __bionic_libcrt_compat_symbols[] = {
    &__adddf3,
    &__addsf3,
    &__aeabi_cdcmpeq,
    &__aeabi_cdcmple,
    &__aeabi_cdrcmple,
    &__aeabi_cfcmpeq,
    &__aeabi_cfcmple,
    &__aeabi_cfrcmple,
    &__aeabi_d2f,
    &__aeabi_d2iz,
    &__aeabi_d2uiz,
    &__aeabi_dadd,
    &__aeabi_dcmpeq,
    &__aeabi_dcmpge,
    &__aeabi_dcmpgt,
    &__aeabi_dcmple,
    &__aeabi_dcmplt,
    &__aeabi_dcmpun,
    &__aeabi_ddiv,
    &__aeabi_dmul,
    &__aeabi_drsub,
    &__aeabi_dsub,
    &__aeabi_f2d,
    &__aeabi_f2iz,
    &__aeabi_f2uiz,
    &__aeabi_fadd,
    &__aeabi_fcmpeq,
    &__aeabi_fcmpge,
    &__aeabi_fcmpgt,
    &__aeabi_fcmple,
    &__aeabi_fcmplt,
    &__aeabi_fcmpun,
    &__aeabi_fdiv,
    &__aeabi_fmul,
    &__aeabi_frsub,
    &__aeabi_fsub,
    &__aeabi_i2d,
    &__aeabi_i2f,
    &__aeabi_idiv,
    &__aeabi_idivmod,
    &__aeabi_l2d,
    &__aeabi_l2f,
    &__aeabi_lasr,
    &__aeabi_ldivmod,
    &__aeabi_llsl,
    &__aeabi_llsr,
    &__aeabi_lmul,
    &__aeabi_ui2d,
    &__aeabi_ui2f,
    &__aeabi_uidiv,
    &__aeabi_uidivmod,
    &__aeabi_ul2d,
    &__aeabi_ul2f,
    &__aeabi_uldivmod,
    &__aeabi_unwind_cpp_pr0,
    &__aeabi_unwind_cpp_pr1,
    &__cmpdf2,
    &__cmpsf2,
    &__divdf3,
    &__divsf3,
    &__eqdf2,
    &__eqsf2,
    &__extendsfdf2,
    &__fixdfsi,
    &__fixsfsi,
    &__fixunsdfsi,
    &__floatdidf,
    &__floatdisf,
    &__floatsidf,
    &__floatsisf,
    &__floatundidf,
    &__floatundisf,
    &__floatunsidf,
    &__floatunsisf,
    &__gedf2,
    &__gesf2,
    &__gtdf2,
    &__gtsf2,
    &__gnu_ldivmod_helper,
    &__gnu_uldivmod_helper,
    &__ledf2,
    &__lesf2,
    &__ltdf2,
    &__ltsf2,
    &__muldf3,
    &__muldi3,
    &__mulsf3,
    &__nedf2,
    &__nesf2,
    &__popcount_tab,
    &__popcountsi2,
    &__subdf3,
    &__subsf3,
    &__truncdfsf2,
    &__udivdi3,
    &__unorddf2,
    &__unordsf2,
};
```
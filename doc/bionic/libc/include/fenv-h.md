Response:
Let's break down the thought process for answering this request. The goal is to provide a comprehensive explanation of `fenv.h` in the context of Android.

**1. Understanding the Core Request:**

The request asks for a breakdown of the `fenv.h` header file's functionality within Android's Bionic libc. It specifically requests examples related to Android functionality, explanations of the libc functions, details on dynamic linking (if applicable), common usage errors, and how Android components reach this code, along with a Frida hook example.

**2. Initial Analysis of `fenv.h`:**

The first step is to read through the provided `fenv.h` source code. Key observations:

* **Purpose:** The header deals with the floating-point environment (FPE). This involves controlling aspects of floating-point arithmetic like rounding modes and handling exceptions.
* **Includes:** It conditionally includes architecture-specific headers (`bits/fenv_arm.h`, `bits/fenv_x86.h`, etc.). This indicates platform dependency in the underlying implementation.
* **Function Declarations:**  It declares standard C99 FPE functions like `feclearexcept`, `fegetround`, `fesetenv`, etc. The comments next to each function refer to their man pages, suggesting standard behavior.
* **`FE_DFL_ENV`:**  Defines a constant representing the default floating-point environment.
* **Comments on Android:**  The comments for `feenableexcept`, `fedisableexcept`, and `fegetexcept` explicitly state that these are "not generally useful on Android" because only x86/x86-64 can trap. This is a crucial Android-specific detail.

**3. Addressing the Specific Questions:**

Now, let's tackle each part of the request systematically:

* **功能列表 (List of Functions):** This is straightforward. Simply list all the declared functions and briefly describe their purpose based on their names and the comments. Group them logically (exception handling, rounding modes, environment management).

* **与 Android 功能的关系 (Relationship with Android Functionality):** This requires thinking about where floating-point operations are used in Android. Consider:
    * **Graphics:**  OpenGL ES and Vulkan heavily use floating-point numbers for transformations, colors, etc.
    * **Media:** Audio and video processing often involve floating-point calculations.
    * **Scientific/Mathematical Libraries:** Libraries within the NDK might expose functions that benefit from controlled floating-point behavior.
    * **General Computation:** Any Android app performing mathematical calculations using `float` or `double` can be affected by the FPE settings.
    * *Initially, I might have focused too heavily on system-level components. It's important to remember that even app-level code uses floating-point numbers.*

* **libc 函数的实现 (Implementation of libc Functions):** This is where the architecture-specific includes become important. The `fenv.h` header is just a declaration. The *implementation* resides in the architecture-specific files (like `bits/fenv_arm.h`). Therefore, the explanation should focus on:
    * `fenv.h` as the interface.
    * The architecture-specific headers containing the actual implementation (often implemented using inline assembly or compiler intrinsics to directly manipulate CPU registers).
    * The standard nature of these functions (defined by C99).
    * Briefly mention the CPU registers involved (FPSCR on ARM, FPU control word on x86).

* **dynamic linker 的功能 (Dynamic Linker Functionality):**  Initially, I might have thought this header file directly interacts heavily with the dynamic linker. However, after closer inspection, it's clear that `fenv.h` itself doesn't involve dynamic linking in a significant way. The functions it declares *are* part of `libc.so`, which is linked dynamically. The connection is that the *implementation* of these functions will reside within `libc.so`. The dynamic linker resolves the symbols when a program uses these functions. Therefore, the explanation should:
    * Emphasize that `fenv.h` declares functions *within* `libc.so`.
    * Provide a sample `libc.so` layout showing sections like `.text` (code).
    * Explain the linking process: symbol resolution, relocation.

* **逻辑推理 (Logical Deduction):**  This involves providing examples of how the functions can be used and their effects. For instance, demonstrating how `fesetround` changes the result of a division. The "假设输入与输出" (assumed input and output) helps illustrate the function's behavior.

* **常见的使用错误 (Common Usage Errors):**  Think about typical mistakes programmers make when dealing with FPE:
    * Incorrectly assuming default rounding behavior.
    * Not checking for or handling floating-point exceptions.
    * Unintended side effects when modifying the global FPE.
    * Forgetting to save and restore the FPE.

* **Android Framework/NDK 如何到达这里 (How Android Framework/NDK Reaches Here):** This requires tracing the execution flow:
    * **NDK:** Direct C/C++ calls to these functions.
    * **Android Framework (Java):**  Indirectly through JNI calls. The Java code might call native methods that internally use floating-point operations, leading to the execution of these `libc` functions.
    * **Example:** `android.graphics.Matrix` operations involve floating-point calculations.

* **Frida Hook 示例 (Frida Hook Example):**  Provide a practical example of how to use Frida to intercept and monitor calls to these FPE functions. This helps in debugging and understanding their behavior. A basic hook for `fesetround` is a good starting point.

**4. Structuring the Answer:**

Organize the answer logically, following the structure of the request. Use clear headings and subheadings to make it easy to read and understand. Use code blocks for code examples and format them properly.

**5. Language and Tone:**

Use clear, concise, and technically accurate language. Explain concepts in a way that is accessible to someone with a basic understanding of C programming and operating systems. Maintain a helpful and informative tone.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis on System-Level:** I initially focused too much on kernel-level interactions. Realized that user-space applications are the primary users of these functions.
* **Dynamic Linking Depth:**  Initially might have tried to explain the dynamic linker's internal mechanisms too deeply. Refined it to focus on the connection between `fenv.h`'s declarations and the implementation within `libc.so`, and the role of the linker in resolving symbols.
* **Frida Hook Clarity:**  Ensured the Frida hook example was clear and provided the necessary context (attaching to a process, hooking the function, logging arguments and return value).

By following this structured thought process, breaking down the request into smaller parts, and refining the answers along the way, it's possible to generate a comprehensive and accurate response like the example provided in the prompt.
好的，让我们详细分析一下 `bionic/libc/include/fenv.handroid` 这个头文件。

**功能列表:**

这个 `fenv.h` 头文件定义了与浮点环境相关的函数和宏，主要用于控制和查询浮点运算的行为，例如：

* **异常处理:**
    * `feclearexcept(int __exceptions)`: 清除指定的浮点异常标志。
    * `fegetexceptflag(fexcept_t* _Nonnull __flag_ptr, int __exceptions)`: 获取指定浮点异常的状态并存储到 `flag_ptr` 指向的变量中。
    * `feraiseexcept(int __exceptions)`: 触发指定的浮点异常。
    * `fesetexceptflag(const fexcept_t* _Nonnull __flag_ptr, int __exceptions)`: 设置指定的浮点异常状态。
    * `fetestexcept(int __exceptions)`: 测试指定的浮点异常是否被设置。
* **舍入模式控制:**
    * `fegetround(void)`: 获取当前的浮点舍入模式。
    * `fesetround(int __rounding_mode)`: 设置浮点舍入模式。
* **浮点环境管理:**
    * `fegetenv(fenv_t* _Nonnull __env)`: 获取当前的完整浮点环境并存储到 `env` 指向的变量中。
    * `feholdexcept(fenv_t* _Nonnull __env)`: 获取当前的浮点环境，清除所有异常标志，并将异常模式设置为非停止模式（忽略异常）。
    * `fesetenv(const fenv_t* _Nonnull __env)`: 设置当前的浮点环境为 `env` 指向的值。
    * `feupdateenv(const fenv_t* _Nonnull __env)`: 设置当前的浮点环境为 `env` 指向的值，但保留当前已触发的异常标志。
* **陷阱使能 (通常在 Android 上不常用):**
    * `feenableexcept(int __exceptions)`: 启用指定的浮点异常陷阱（当发生这些异常时，会产生信号）。
    * `fedisableexcept(int __exceptions)`: 禁用指定的浮点异常陷阱。
    * `fegetexcept(void)`: 获取当前启用的浮点异常陷阱。
* **默认浮点环境:**
    * `FE_DFL_ENV`:  一个指向默认浮点环境的常量指针，这个环境在程序启动时被设置。

**与 Android 功能的关系及举例:**

浮点环境控制在 Android 系统和应用中都有其作用，尤其是在涉及到数值计算的场景中。

* **图形渲染 (OpenGL ES, Vulkan):** 图形渲染大量依赖浮点运算，例如矩阵变换、颜色计算等。`fenv.h` 中的函数可以用来控制这些浮点运算的精度和舍入方式。
    * **例子:** 假设一个游戏开发者希望在特定场景下使用“向零舍入”的模式，以保证数值的某种特定行为，他可以使用 `fesetround(FE_TOWARDZERO)` 来设置舍入模式。
* **音频/视频处理:** 音频和视频编解码、特效处理等也常常涉及复杂的浮点运算。
    * **例子:** 在音频处理中，对音频采样进行滤波操作时，可能需要控制浮点数的精度和溢出行为，`feclearexcept` 可以用来清除之前的溢出标志，确保后续计算的准确性。
* **科学计算和机器学习库 (NDK):**  使用 NDK 开发的应用，如果涉及到科学计算或者机器学习，往往会直接使用这些浮点环境控制函数。
    * **例子:** 一个使用 TensorFlow Lite 进行模型推理的 Native 代码，可能需要设置特定的浮点异常处理方式，以应对某些特殊的数值情况。
* **基础库和系统服务:**  Android 的一些底层库和系统服务也可能在内部使用这些函数来管理浮点运算行为。

**libc 函数的实现:**

`fenv.h` 本身只是头文件，声明了这些函数。具体的实现位于 bionic libc 的源代码中，并且会根据不同的 CPU 架构有所不同。

* **通用逻辑:** 大部分函数会直接操作 CPU 的浮点控制寄存器或状态寄存器。这些寄存器控制着浮点单元 (FPU) 的行为，包括舍入模式、异常掩码和状态标志。
* **架构差异:**
    * **ARM (aarch64, arm):**  这些函数会操作 FPSCR (Floating-point Status and Control Register) 寄存器。例如，`fesetround` 会修改 FPSCR 中的舍入模式位。
    * **x86/x86-64:**  会操作 FPU 的控制字 (Control Word) 和状态字 (Status Word)。例如，`feclearexcept` 会清除状态字中的异常标志位。
    * **RISC-V:** 会操作相应的浮点控制和状态寄存器。

**例如 `fesetround` 的实现逻辑 (简化描述):**

1. `fesetround` 函数接收一个表示舍入模式的整数参数（例如 `FE_TONEAREST`, `FE_UPWARD` 等）。
2. 根据当前的 CPU 架构，函数会执行相应的操作来修改 FPU 的控制寄存器。
3. **ARM:** 会将传入的舍入模式值映射到 FPSCR 寄存器中对应的位域。
4. **x86/x86-64:** 会将传入的舍入模式值映射到 FPU 控制字中对应的位域。
5. 函数返回 0 表示成功，非 0 表示失败 (例如，传入了无效的舍入模式)。

**动态链接器功能和 so 布局样本及链接处理:**

`fenv.h` 中声明的函数是 bionic libc (`libc.so`) 的一部分。当一个 Android 应用或 Native 库调用这些函数时，动态链接器负责将这些函数调用链接到 `libc.so` 中对应的实现代码。

**so 布局样本 (简化的 `libc.so` 示例):**

```
libc.so:
    .dynsym:
        fesetround  (地址: 0xXXXXXXXX)
        feclearexcept (地址: 0xYYYYYYYY)
        ...
    .text:
        0xXXXXXXXX:  <fesetround 的机器码实现>
        0xYYYYYYYY:  <feclearexcept 的机器码实现>
        ...
```

**链接处理过程:**

1. **应用或 Native 库加载:** 当 Android 系统加载应用或 Native 库时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 也被激活。
2. **依赖项解析:** 动态链接器会检查应用或 Native 库的依赖项，其中包括 `libc.so`。
3. **符号查找:** 当应用代码调用 `fesetround` 时，链接器会在 `libc.so` 的 `.dynsym` 段中查找 `fesetround` 符号。
4. **地址重定位:** 找到符号后，链接器会将应用代码中对 `fesetround` 的调用地址重定向到 `libc.so` 中 `fesetround` 函数的实际地址 (0xXXXXXXXX)。
5. **执行:** 当程序执行到 `fesetround` 调用时，会跳转到 `libc.so` 中相应的代码执行。

**逻辑推理、假设输入与输出:**

**假设输入:**

```c
#include <fenv.h>
#include <stdio.h>

int main() {
    double a = 1.0;
    double b = 3.0;
    double result;

    // 默认舍入模式 (通常是 FE_TONEAREST)
    result = a / b;
    printf("默认舍入: %.17g\n", result);

    // 设置为向上舍入
    fesetround(FE_UPWARD);
    result = a / b;
    printf("向上舍入: %.17g\n", result);

    // 设置为向下舍入
    fesetround(FE_DOWNWARD);
    result = a / b;
    printf("向下舍入: %.17g\n", result);

    return 0;
}
```

**假设输出:**

```
默认舍入: 0.33333333333333331
向上舍入: 0.33333333333333337
向下舍入: 0.33333333333333331
```

**解释:**

* 默认舍入模式通常是“舍入到最接近， ties 到偶数”。
* 向上舍入会朝正无穷方向舍入。
* 向下舍入会朝负无穷方向舍入。

**用户或编程常见的使用错误:**

1. **未包含头文件:** 忘记包含 `<fenv.h>` 导致编译错误。
2. **错误地假设默认行为:**  假设浮点运算总是按照某种特定的方式进行，而没有显式地设置。不同的平台或编译器可能存在细微的差异。
3. **忽略浮点异常:**  进行可能产生浮点异常的运算时，没有检查异常标志，导致程序行为不可预测。例如，除零操作会产生 `FE_DIVBYZERO` 异常。
4. **过度或不必要的修改浮点环境:** 在多线程环境中，全局修改浮点环境可能会导致其他线程出现问题。应该谨慎地使用这些函数，并在必要时保存和恢复浮点环境。
5. **错误地使用陷阱:**  在 Android 上，启用浮点异常陷阱通常不会产生预期的效果（除非在 x86/x86-64 架构上），容易导致误解。
6. **不理解舍入模式的影响:**  在金融计算等对精度要求极高的场景中，错误的舍入模式可能导致严重的计算误差。

**Android Framework 或 NDK 如何一步步到达这里:**

**NDK (Native 开发):**

1. **C/C++ 代码调用:**  开发者在 Native 代码中直接调用 `feclearexcept()`, `fesetround()` 等函数。
2. **编译链接:**  NDK 工具链在编译和链接 Native 代码时，会将这些函数调用链接到 `libc.so`。
3. **运行时执行:**  当应用运行到这些函数调用时，系统会执行 `libc.so` 中相应的代码。

**Android Framework (Java 开发):**

1. **Java 代码调用:**  Android Framework 的 Java 代码本身很少直接调用这些底层的浮点环境控制函数。
2. **JNI 调用:**  某些 Framework 组件可能会通过 JNI (Java Native Interface) 调用 Native 代码，而这些 Native 代码可能会使用 `fenv.h` 中的函数。
    * **例子:** `android.graphics.Matrix` 类在进行矩阵运算时，其 Native 实现可能会涉及到浮点数的处理，并可能间接地影响到浮点环境。
3. **底层库调用:** Framework 可能会调用一些底层的 Native 库（例如 Skia 图形库），这些库可能会使用 `fenv.h` 中的函数。

**Frida Hook 示例调试步骤:**

假设我们要 Hook `fesetround` 函数，观察其调用情况。

```python
import frida
import sys

# 要附加的进程名称或 PID
process_name = "com.example.myapp"  # 替换为你的应用进程名

try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"找不到进程: {process_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fesetround"), {
    onEnter: function(args) {
        console.log("fesetround called!");
        console.log("  Rounding mode:", args[0].toInt());
        // 可以根据需要打印更多信息
    },
    onLeave: function(retval) {
        console.log("fesetround returned:", retval.toInt());
    }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **安装 Frida 和 Python 环境:** 确保你的开发环境安装了 Frida 和 Python 的 Frida 绑定。
2. **找到目标进程:**  确定你要调试的 Android 应用的进程名称或 PID。
3. **编写 Frida Hook 脚本:**  如上面的示例代码，使用 `Interceptor.attach` 监听 `libc.so` 中 `fesetround` 函数的调用。
4. **运行 Frida 脚本:**  在你的 PC 上运行 Frida 脚本，并将其附加到目标 Android 进程。
5. **触发目标代码:**  在 Android 设备上操作目标应用，触发可能调用 `fesetround` 的代码路径。
6. **查看 Frida 输出:**  Frida 会在控制台上打印出 `fesetround` 函数被调用时的信息，包括传入的舍入模式参数和返回值。

通过这种方式，你可以监控哪些代码路径调用了浮点环境控制函数，以及传递了哪些参数，从而帮助你理解和调试相关的行为。

希望这个详细的解释能够帮助你理解 `bionic/libc/include/fenv.handroid` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/fenv.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*  $OpenBSD: fenv.h,v 1.2 2011/05/25 21:46:49 martynas Exp $ */
/*  $NetBSD: fenv.h,v 1.2.4.1 2011/02/08 16:18:55 bouyer Exp $  */

/*
 * Copyright (c) 2010 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

/**
 * @file fenv.h
 * @brief Floating-point environment.
 */

#include <sys/cdefs.h>

#if defined(__aarch64__) || defined(__arm__)
#include <bits/fenv_arm.h>
#elif defined(__i386__)
#include <bits/fenv_x86.h>
#elif defined(__riscv)
#include <bits/fenv_riscv64.h>
#elif defined(__x86_64__)
#include <bits/fenv_x86_64.h>
#endif

__BEGIN_DECLS

/**
 * [feclearexcept(3)](https://man7.org/linux/man-pages/man3/feclearexcept.3.html)
 * clears the given `exceptions` in hardware.
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int feclearexcept(int __exceptions);

/**
 * [fegetexceptflag(3)](https://man7.org/linux/man-pages/man3/fegetexceptflag.3.html)
 * copies the state of the given `exceptions` from hardware into `*flag_ptr`.
 * See fesetexceptflag().
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int fegetexceptflag(fexcept_t* _Nonnull __flag_ptr, int __exceptions);

/**
 * [feraiseexcept(3)](https://man7.org/linux/man-pages/man3/feraiseexcept.3.html)
 * raises the given `exceptions` in hardware.
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int feraiseexcept(int __exceptions);

/**
 * [fesetexceptflag(3)](https://man7.org/linux/man-pages/man3/fesetexceptflag.3.html)
 * copies the state of the given `exceptions` from `*flag_ptr` into hardware.
 * See fesetexceptflag().
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int fesetexceptflag(const fexcept_t* _Nonnull __flag_ptr, int __exceptions);

/**
 * [fetestexcept(3)](https://man7.org/linux/man-pages/man3/fetestexcept.3.html)
 * tests whether the given `exceptions` are set in hardware.
 *
 * Returns the currently-set subset of `exceptions`.
 */
int fetestexcept(int __exceptions);

/**
 * [fegetround(3)](https://man7.org/linux/man-pages/man3/fegetround.3.html)
 * returns the current rounding mode.
 *
 * Returns the rounding mode on success, and returns a negative value on failure.
 */
int fegetround(void);

/**
 * [fesetround(3)](https://man7.org/linux/man-pages/man3/fesetround.3.html)
 * sets the current rounding mode.
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int fesetround(int __rounding_mode);

/**
 * [fegetenv(3)](https://man7.org/linux/man-pages/man3/fegetenv.3.html)
 * gets the current floating-point environment. See fesetenv().
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int fegetenv(fenv_t* _Nonnull __env);

/**
 * [feholdexcept(3)](https://man7.org/linux/man-pages/man3/feholdexcept.3.html)
 * gets the current floating-point environment, clears the status flags, and
 * ignores floating point exceptions. See fesetenv()/feupdateenv().
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int feholdexcept(fenv_t* _Nonnull __env);

/**
 * [fesetenv(3)](https://man7.org/linux/man-pages/man3/fesetenv.3.html)
 * sets the current floating-point environment. See fegetenv().
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int fesetenv(const fenv_t* _Nonnull __env);

/**
 * [feupdateenv(3)](https://man7.org/linux/man-pages/man3/feupdateenv.3.html)
 * sets the current floating-point environment to `*env` but with currently-raised
 * exceptions still raised. See fesetenv().
 *
 * Returns 0 on success, and returns non-zero on failure.
 */
int feupdateenv(const fenv_t* _Nonnull __env);

/**
 * [feenableexcept(3)](https://man7.org/linux/man-pages/man3/feenableexcept.3.html)
 * sets the given `exceptions` to trap, if the hardware supports it. This is not
 * generally useful on Android, because only x86/x86-64 can trap.
 *
 * Returns the previous set of enabled exceptions on success, and returns -1 on failure.
 */
int feenableexcept(int __exceptions);

/**
 * [fedisableexcept(3)](https://man7.org/linux/man-pages/man3/fedisableexcept.3.html)
 * sets the given `exceptions` to not trap, if the hardware supports it. This is not
 * generally useful on Android, because only x86/x86-64 can trap.
 *
 * Returns the previous set of enabled exceptions on success, and returns -1 on failure.
 */
int fedisableexcept(int __exceptions);

/**
 * [fegetexcept(3)](https://man7.org/linux/man-pages/man3/fegetexcept.3.html)
 * returns the exceptions that currently trap. This is not generally useful on
 * Android, because only x86/x86-64 can trap.
 *
 * Returns the exceptions that currently trap.
 */
int fegetexcept(void);

/** See FE_DFL_ENV. */
extern const fenv_t __fe_dfl_env;

/**
 * Constant representing the default floating-point environment
 * (that is, the one installed at program startup).
 *
 * It can be used as an argument to the functions that manage the floating-point
 * environment, namely fesetenv() and feupdateenv().
 */
#define FE_DFL_ENV (&__fe_dfl_env)

__END_DECLS

"""

```
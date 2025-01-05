Response:
Let's break down the thought process for analyzing the `s_ccosh.c` file.

1. **Understanding the Goal:** The primary goal is to analyze the given C code for `ccosh` (complex hyperbolic cosine) and related functions within the Android Bionic library. This involves understanding its functionality, relationship to Android, implementation details, linking aspects, potential errors, and how it fits into the larger Android ecosystem.

2. **Initial Code Scan and Function Identification:**  The first step is to quickly scan the code to identify the main function and any supporting helper functions or constants. We see `ccosh` as the primary function and a helper constant `huge`. A secondary function `ccos` is also present, which is related to `ccosh`.

3. **Core Functionality Identification (ccosh):**
    * Read the comment block at the beginning. It clearly states the purpose: calculating the hyperbolic cosine of a complex number. The mathematical formula is provided: `cosh(x+iy) = cosh(x) cos(y) + i sinh(x) sin(y)`. This is crucial for understanding the expected behavior.
    * Examine the function signature: `double complex ccosh(double complex z)`. This confirms it takes a complex number as input and returns a complex number.
    * Analyze the internal logic:
        * **Extract Real and Imaginary Parts:** `creal(z)` and `cimag(z)` are used to get the real (x) and imaginary (y) parts.
        * **Bit Manipulation (EXTRACT_WORDS):** The `EXTRACT_WORDS` macro is used to get the high and low words of the double-precision floating-point numbers. This suggests the code handles special cases and performs comparisons based on the bit representation.
        * **Branching Logic:** The code uses `if` and `else if` statements to handle different ranges of `x` and `y`. This is a common technique in numerical libraries to optimize for different scenarios and handle potential overflow/underflow.
        * **Standard Math Functions:**  Calls to `cosh`, `cos`, `sinh`, `sin`, `fabs`, `exp`, `copysign` are evident. These are standard C math library functions.
        * **Special Value Handling:**  The comments and `if` conditions point to handling special values like infinity, NaN (Not a Number), and zero. This is critical for robustness in floating-point calculations.
        * **Scaling and Overflow Prevention:** The code includes logic (e.g., when `ix >= 0x40360000`) to handle large values of `x` where direct computation might lead to overflow. The use of `__ldexp_cexp` (likely a Bionic-specific function for scaling complex exponentials) suggests optimization for these cases.

4. **Secondary Functionality Identification (ccos):**
    * Read the concise comment: `/* ccos(z) = ccosh(I * z) */`. This reveals that the complex cosine is implemented by transforming the input and calling `ccosh`. This is a standard mathematical identity.

5. **Relationship to Android:**
    * **Bionic Context:** The file path clearly indicates this is part of Bionic, Android's C library. This immediately establishes its core relevance to Android.
    * **Math Library:**  `libm` signifies the math library. Complex number functions are essential for various applications on Android, including games, graphics, scientific computing, and signal processing.

6. **Implementation Details (libc functions):**
    * **`creal(z)` and `cimag(z)`:** These are standard C99 complex number functions. They likely involve accessing the appropriate parts of the `double complex` structure.
    * **`cosh(x)` and `sinh(x)`:** Standard hyperbolic cosine and sine functions. These often have platform-specific optimized implementations.
    * **`cos(y)` and `sin(y)`:** Standard trigonometric cosine and sine functions. Again, often optimized.
    * **`fabs(x)`:** Standard absolute value function.
    * **`exp(x)`:** Standard exponential function.
    * **`copysign(magnitude, sign)`:** Standard function to copy the sign of one number to another's magnitude.
    * **`CMPLX(real, imaginary)`:** Standard C99 macro to construct a complex number.
    * **`INFINITY`:** Standard macro representing positive infinity.
    * **`NaN` (implicitly):** The code uses expressions like `y - y` to generate NaN.
    * **`EXTRACT_WORDS` and `__ldexp_cexp`:** These are likely Bionic-specific or platform-specific internal functions for low-level floating-point manipulation and complex exponential calculation with scaling, respectively. Their exact implementation would be in other Bionic source files.

7. **Dynamic Linker Aspects:**
    * **Shared Library (`.so`):**  The functions in `libm` are part of a shared library (likely `libm.so`).
    * **Linking:** When an Android application or framework component uses `ccosh`, the dynamic linker resolves the symbol `ccosh` to the implementation within `libm.so`.
    * **SO Layout:**  A typical `libm.so` would contain various mathematical functions, including `ccosh`, `ccos`, `sin`, `cos`, etc. The layout is determined during the library's compilation and linking process.

8. **Logical Reasoning and Examples:**
    * **Normal Case:**  Demonstrate the basic formula application for small values.
    * **Large `x` Case:** Show how the code approximates `cosh(x)` with `exp(|x|)/2` and handles potential overflows.
    * **Special Value Cases:**  Illustrate the behavior for inputs like infinity, NaN, and zero according to the IEEE 754 standard and the documented behavior.

9. **User Errors:**
    * **Incorrect Input Types:** Passing non-complex numbers (though the C compiler would catch this).
    * **Extremely Large Inputs:** Leading to potential overflow or loss of precision (though the library attempts to handle this).
    * **Assuming Exact Results:**  Floating-point arithmetic has inherent limitations.

10. **Android Framework/NDK Path:**
    * **NDK:**  A native C/C++ application using the NDK can directly call `ccosh` by including `<complex.h>` and `<math.h>`. The linker will resolve the symbol to `libm.so`.
    * **Framework:** Java framework components interacting with native code via JNI might indirectly call functions that rely on `ccosh`. For example, a graphics library performing complex transformations or a signal processing module. The call path would involve Java code -> JNI call -> native code within a framework library -> eventually calling `ccosh` in `libm.so`.

11. **Debugging Hints:**
    * **Logging:** Use `ALOG` (Android logging) within the NDK or framework to trace execution and variable values.
    * **Debugger:** Use a debugger like GDB (possibly through Android Studio) to step through the code, set breakpoints, and inspect variables within `ccosh`.
    * **Understanding Special Values:** Pay close attention to how infinity and NaN are handled during debugging.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus heavily on the mathematical formula.
* **Correction:** Realize the importance of the special value handling and the logic for preventing overflow, as these are significant parts of the implementation.
* **Initial thought:** Assume all standard math functions have a single, simple implementation.
* **Correction:** Recognize that these functions are often highly optimized and might have platform-specific implementations within Bionic.
* **Initial thought:**  Focus solely on NDK usage.
* **Correction:**  Consider how framework components might indirectly use these functions.
* **Initial thought:**  Provide only basic usage examples.
* **Correction:** Include examples of potential errors and debugging strategies.

By following these steps and iteratively refining the analysis, we arrive at a comprehensive understanding of the `s_ccosh.c` file and its role within the Android ecosystem.
好的，让我们详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/s_ccosh.c` 这个文件。

**功能概述:**

`s_ccosh.c` 文件实现了复数双曲余弦函数 `ccosh(double complex z)` 以及复数余弦函数 `ccos(double complex z)`。

* **`ccosh(double complex z)`:** 计算一个复数 `z` 的双曲余弦值。如果 `z = x + iy`，那么 `cosh(z) = cosh(x)cos(y) + i sinh(x)sin(y)`。
* **`ccos(double complex z)`:** 计算一个复数 `z` 的余弦值。它通过调用 `ccosh` 函数来实现，利用了恒等式 `cos(z) = cosh(iz)`。

**与 Android 功能的关系举例:**

这些复数数学函数是 Android 系统底层的数学运算基础，被上层各种模块间接或直接使用：

1. **图形渲染 (Graphics Rendering):** 在 OpenGL ES 或 Vulkan 等图形 API 的底层实现中，可能会涉及到复数运算，例如在处理傅里叶变换、信号处理或某些特殊的几何变换时。虽然不常见直接使用 `ccosh`，但相关的复数运算函数会被用到。

2. **音频处理 (Audio Processing):**  音频信号处理中，傅里叶变换 (FFT) 是一个核心算法，它涉及到复数运算。虽然 `ccosh` 本身不直接用于 FFT，但 `libm` 提供的其他复数运算函数会被广泛使用。

3. **科学计算和工程应用 (Scientific Computing and Engineering Applications):** 如果你在 Android 上运行科学计算或工程相关的 App (通过 NDK 开发)，这些复数函数可能会被直接调用。例如，求解某些类型的微分方程、电路分析或物理模拟。

4. **密码学 (Cryptography):** 某些加密算法可能会涉及到复数或更广义的代数结构，虽然 `ccosh` 不是密码学中的核心函数，但 `libm` 提供的基础数学函数是构建更复杂密码算法的基石。

**libc 函数的功能实现详细解释:**

让我们逐行分析 `ccosh` 函数的实现逻辑：

1. **包含头文件:**
   ```c
   #include <complex.h>
   #include <math.h>
   #include "math_private.h"
   ```
   * `<complex.h>`: 定义了复数类型 `double complex` 和相关的宏，例如 `CMPLX`，`creal`，`cimag`。
   * `<math.h>`: 包含了标准数学函数的声明，例如 `cosh`，`sinh`，`cos`，`sin`，`fabs`，`exp`，`copysign`。
   * `"math_private.h"`:  包含了 `libm` 内部使用的私有宏或函数声明，例如 `EXTRACT_WORDS` 和 `__ldexp_cexp`。

2. **定义常量:**
   ```c
   static const double huge = 0x1p1023;
   ```
   * `huge`: 定义了一个很大的双精度浮点数，接近于双精度浮点数的最大值，用于处理溢出情况。`0x1p1023` 是十六进制浮点数表示，表示 1 * 2<sup>1023</sup>。

3. **`ccosh(double complex z)` 函数:**
   ```c
   double complex
   ccosh(double complex z)
   {
       double x, y, h;
       int32_t hx, hy, ix, iy, lx, ly;
   ```
   * 声明局部变量：`x` 和 `y` 用于存储复数 `z` 的实部和虚部，`h` 是一个辅助变量。`hx`, `lx`, `hy`, `ly` 分别存储实部和虚部的高 32 位和低 32 位，`ix` 和 `iy` 存储实部和虚部的绝对值部分（去掉符号位）。

   ```c
       x = creal(z);
       y = cimag(z);
   ```
   * `creal(z)`:  从复数 `z` 中提取实部。
   * `cimag(z)`:  从复数 `z` 中提取虚部。

   ```c
       EXTRACT_WORDS(hx, lx, x);
       EXTRACT_WORDS(hy, ly, y);
   ```
   * `EXTRACT_WORDS(hx, lx, x)`: 这是一个宏，用于将双精度浮点数 `x` 的 64 位表示分解为两个 32 位整数 `hx` (高位字) 和 `lx` (低位字)。这个宏通常在 `math_private.h` 中定义，用于进行底层的位操作，以便快速检查浮点数的特殊属性，例如是否为 NaN 或无穷大。

   ```c
       ix = 0x7fffffff & hx;
       iy = 0x7fffffff & hy;
   ```
   * 这两行代码通过与 `0x7fffffff` 进行按位与操作，去除了 `hx` 和 `hy` 的符号位，得到实部和虚部绝对值的整数表示。

   ```c
       /* Handle the nearly-non-exceptional cases where x and y are finite. */
       if (ix < 0x7ff00000 && iy < 0x7ff00000) {
           // ... 处理 x 和 y 都是有限值的情况
       }
   ```
   * `0x7ff00000` 是 IEEE 754 标准中表示无穷大的指数部分的起始值。如果 `ix` 和 `iy` 都小于这个值，说明 `x` 和 `y` 都是有限值。

   **处理 x 和 y 都是有限值的情况:**

   ```c
           if ((iy | ly) == 0)
               return (CMPLX(cosh(x), x * y));
   ```
   * 如果 `y` 为 0 (包括 +0 和 -0)，则 `cos(y)` 为 1，`sin(y)` 为 0。`ccosh(x + 0i) = cosh(x) + i * sinh(x) * 0 = cosh(x) + 0i`。这里返回 `CMPLX(cosh(x), x * y)` 是为了保持结果虚部的符号（如果 `y` 是 -0）。

   ```c
           if (ix < 0x40360000)	/* |x| < 22: normal case */
               return (CMPLX(cosh(x) * cos(y), sinh(x) * sin(y)));
   ```
   * `0x40360000` 大约对应于十进制的 22。当 `|x| < 22` 时，使用标准的公式直接计算 `cosh(x) * cos(y)` 和 `sinh(x) * sin(y)`。

   ```c
           /* |x| >= 22, so cosh(x) ~= exp(|x|) */
           if (ix < 0x40862e42) {
               /* x < 710: exp(|x|) won't overflow */
               h = exp(fabs(x)) * 0.5;
               return (CMPLX(h * cos(y), copysign(h, x) * sin(y)));
           } else if (ix < 0x4096bbaa) {
               /* x < 1455: scale to avoid overflow */
               z = __ldexp_cexp(CMPLX(fabs(x), y), -1);
               return (CMPLX(creal(z), cimag(z) * copysign(1, x)));
           } else {
               /* x >= 1455: the result always overflows */
               h = huge * x;
               return (CMPLX(h * h * cos(y), h * sin(y)));
           }
   ```
   * 当 `|x| >= 22` 时，`cosh(x)` 的值会很大，接近于 `exp(|x|) / 2`。
     * 如果 `|x| < 710`，`exp(|x|)` 不会溢出，可以直接计算。
     * 如果 `710 <= |x| < 1455`，为了避免溢出，使用 `__ldexp_cexp` 函数对指数进行缩放。`__ldexp_cexp` 可能是 `libm` 内部的一个函数，用于计算 `exp(a + ib)` 并进行缩放。
     * 如果 `|x| >= 1455`，结果肯定会溢出，使用 `huge` 乘以 `x` 进行近似计算。

   **处理特殊值 (无穷大和 NaN):**

   剩下的 `if` 语句块处理了各种特殊情况，包括 `x` 或 `y` 为无穷大或 NaN 的情况，并根据 IEEE 754 标准返回相应的结果。例如：

   ```c
       /*
        * cosh(+-0 +- I Inf) = dNaN + I (+-)(+-)0.
        * ...
        */
       if ((ix | lx) == 0)		/* && iy >= 0x7ff00000 */
           return (CMPLX(y - y, x * copysign(0, y)));
   ```
   * 当 `x` 为 0 且 `y` 为无穷大时，返回 `NaN + i * sign(x) * 0`。`y - y` 会产生 NaN。

   代码中其他的 `if` 语句块类似地处理了各种特殊情况，确保 `ccosh` 函数在各种输入下都能返回符合标准的結果。

4. **`ccos(double complex z)` 函数:**
   ```c
   double complex
   ccos(double complex z)
   {
       /* ccos(z) = ccosh(I * z) */
       return (ccosh(CMPLX(-cimag(z), creal(z))));
   }
   ```
   * `ccos` 函数的实现非常简洁，它利用了复数余弦和双曲余弦之间的关系：`cos(z) = cosh(iz)`。
   * `CMPLX(-cimag(z), creal(z))` 创建了一个新的复数，相当于将 `z` 乘以 `i`。如果 `z = x + iy`，那么 `iz = i(x + iy) = ix - y = -y + ix`。
   * 然后调用 `ccosh` 函数计算结果。

**涉及 dynamic linker 的功能:**

`s_ccosh.c` 中的代码本身并不直接涉及动态链接器的操作。然而，作为 `libm` 库的一部分，`ccosh` 和 `ccos` 函数是通过动态链接被应用程序使用的。

**so 布局样本:**

假设你的 Android 应用链接了 `libm.so`，那么 `libm.so` 的布局可能会是这样的一个简化模型：

```
libm.so:
    .text:  // 存放代码段
        ccosh:       // ccosh 函数的代码
        ccos:        // ccos 函数的代码
        sin:         // sin 函数的代码
        cos:         // cos 函数的代码
        ...          // 其他数学函数
    .data:  // 存放已初始化的全局变量
        一些数学常量
    .bss:   // 存放未初始化的全局变量
    .symtab: // 符号表
        ccosh: address_of_ccosh
        ccos:  address_of_ccos
        sin:   address_of_sin
        ...
    .strtab: // 字符串表
        "ccosh"
        "ccos"
        "sin"
        ...
```

**链接的处理过程:**

1. **编译时:** 当你的 Android NDK 代码中调用了 `ccosh` 函数时，编译器会生成对 `ccosh` 符号的未定义引用。

2. **链接时:** Android 构建系统中的链接器 (通常是 `lld`) 会将你的代码与所需的共享库 (`libm.so`) 链接在一起。链接器会查找 `libm.so` 的符号表 (`.symtab`)，找到 `ccosh` 符号对应的地址。

3. **运行时:** 当你的应用在 Android 设备上运行时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载所需的共享库到进程的内存空间，并解析未定义的符号。
   * 当你的代码第一次调用 `ccosh` 时，动态链接器会查找 `libm.so` 中 `ccosh` 函数的地址，并将该地址填入调用点的跳转指令中。这个过程称为**延迟绑定**或**PLT/GOT 机制**。
   * **PLT (Procedure Linkage Table):**  调用点的指令最初会跳转到 PLT 中的一个条目。
   * **GOT (Global Offset Table):** PLT 条目会间接地跳转到 GOT 中的一个地址。最初，GOT 中的地址指向 PLT 中的解析器代码。
   * 当第一次调用时，解析器会找到 `ccosh` 在内存中的实际地址，并更新 GOT 表中的条目。
   * 后续对 `ccosh` 的调用将直接通过 GOT 表跳转到 `ccosh` 的实际地址，避免了重复解析的开销。

**逻辑推理的假设输入与输出:**

* **假设输入:** `z = 1.0 + 1.0i`
* **推理过程:**
    * `x = 1.0`, `y = 1.0`
    * `cosh(1.0) ≈ 1.543`
    * `sinh(1.0) ≈ 1.175`
    * `cos(1.0) ≈ 0.540`
    * `sin(1.0) ≈ 0.841`
    * `ccosh(1.0 + 1.0i) ≈ 1.543 * 0.540 + i * 1.175 * 0.841 ≈ 0.833 + 0.988i`
* **预期输出:**  `0.833 + 0.988i` (实际计算可能会有精度差异)

* **假设输入 (特殊值):** `z = 0.0 + INFINITY * i`
* **推理过程 (根据代码逻辑):** 代码会进入处理 `iy >= 0x7ff00000` 和 `(ix | lx) == 0` 的分支。
* **预期输出:** `NaN + i * 0.0` (符号取决于实现细节)

**用户或编程常见的使用错误:**

1. **类型错误:** 传递非 `double complex` 类型的参数。C 编译器会进行类型检查，但这仍然是一个潜在的错误。
2. **忽略精度问题:** 浮点数运算存在精度限制，不应期望得到绝对精确的结果。
3. **未处理特殊值:** 如果应用程序依赖于 `ccosh` 的结果，应该考虑到输入为无穷大或 NaN 时的输出，并进行相应的处理，避免程序崩溃或产生错误的结果。
4. **性能问题 (在循环中频繁调用):** 虽然 `libm` 的实现通常很高效，但在性能敏感的应用中，频繁调用这些函数仍然可能成为瓶颈，需要考虑优化。

**Android Framework 或 NDK 如何一步步到达这里 (调试线索):**

**NDK 开发:**

1. **C/C++ 代码调用:** 你在 NDK 编写的 C/C++ 代码中直接包含了 `<complex.h>` 和 `<math.h>`，并调用了 `ccosh(z)`。
2. **编译链接:** NDK 构建系统使用 `clang` 或 `gcc` 编译你的代码，并将对 `ccosh` 的调用链接到 `libm.so`。
3. **运行时加载:** 当你的 App 启动时，Android 系统的动态链接器会加载 `libm.so`，并解析 `ccosh` 的符号。
4. **执行 `ccosh`:** 当你的代码执行到调用 `ccosh` 的地方，程序会跳转到 `libm.so` 中 `ccosh` 函数的地址执行。

**Android Framework:**

Framework 中使用 `ccosh` 的路径可能更复杂，通常是通过 JNI (Java Native Interface) 调用到 native 代码，然后 native 代码再调用 `libm` 中的函数。

1. **Java 代码:** Android Framework 的某个 Java 类可能需要进行复数运算。
2. **JNI 调用:** 该 Java 类调用一个 native 方法 (使用 `native` 关键字声明)。
3. **Native 代码:** 该 native 方法的实现 (通常是 C/C++ 代码) 会进行复数运算，并可能间接或直接调用 `ccosh`。
4. **`libm` 调用:** native 代码调用了 `libm.so` 中的 `ccosh` 函数。

**调试线索:**

1. **使用 Android Studio Debugger:**
   * 在你的 NDK 代码中设置断点在调用 `ccosh` 之前。
   * 运行 Debug 模式，当程序停在断点时，你可以查看变量 `z` 的值。
   * 单步执行，观察程序是否跳转到 `libm.so` 的 `ccosh` 函数中。

2. **使用 `adb logcat`:**
   * 在你的 native 代码中，可以使用 `__android_log_print` 打印调用 `ccosh` 前后的参数和返回值。
   * 过滤 `logcat` 输出，查找你的应用的日志信息。

3. **使用 `strace` (需要 root 权限):**
   * `strace -p <pid>` 可以跟踪进程的系统调用。你可以看到动态链接器加载 `libm.so` 的过程，以及程序调用 `ccosh` 的系统调用。

4. **查看 `linker` 日志 (需要 root 权限或开发者选项):**
   * Android 的动态链接器可以输出详细的链接和加载信息。你可以查看链接器的日志，了解 `libm.so` 是如何被加载和符号是如何被解析的。

5. **反汇编 `libm.so` (高级):**
   * 使用工具 (如 `objdump` 或 IDA Pro) 反汇编 `libm.so`，可以查看 `ccosh` 函数的汇编代码，了解其具体的实现细节。

通过以上分析，我们对 `bionic/libm/upstream-freebsd/lib/msun/src/s_ccosh.c` 文件的功能、实现、与 Android 的关系以及调试方法有了深入的了解。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_ccosh.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005 Bruce D. Evans and Steven G. Kargl
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Hyperbolic cosine of a complex argument z = x + i y.
 *
 * cosh(z) = cosh(x+iy)
 *         = cosh(x) cos(y) + i sinh(x) sin(y).
 *
 * Exceptional values are noted in the comments within the source code.
 * These values and the return value were taken from n1124.pdf.
 * The sign of the result for some exceptional values is unspecified but
 * must satisfy both cosh(conj(z)) == conj(cosh(z)) and cosh(-z) == cosh(z).
 */

#include <complex.h>
#include <math.h>

#include "math_private.h"

static const double huge = 0x1p1023;

double complex
ccosh(double complex z)
{
	double x, y, h;
	int32_t hx, hy, ix, iy, lx, ly;

	x = creal(z);
	y = cimag(z);

	EXTRACT_WORDS(hx, lx, x);
	EXTRACT_WORDS(hy, ly, y);

	ix = 0x7fffffff & hx;
	iy = 0x7fffffff & hy;

	/* Handle the nearly-non-exceptional cases where x and y are finite. */
	if (ix < 0x7ff00000 && iy < 0x7ff00000) {
		if ((iy | ly) == 0)
			return (CMPLX(cosh(x), x * y));
		if (ix < 0x40360000)	/* |x| < 22: normal case */
			return (CMPLX(cosh(x) * cos(y), sinh(x) * sin(y)));

		/* |x| >= 22, so cosh(x) ~= exp(|x|) */
		if (ix < 0x40862e42) {
			/* x < 710: exp(|x|) won't overflow */
			h = exp(fabs(x)) * 0.5;
			return (CMPLX(h * cos(y), copysign(h, x) * sin(y)));
		} else if (ix < 0x4096bbaa) {
			/* x < 1455: scale to avoid overflow */
			z = __ldexp_cexp(CMPLX(fabs(x), y), -1);
			return (CMPLX(creal(z), cimag(z) * copysign(1, x)));
		} else {
			/* x >= 1455: the result always overflows */
			h = huge * x;
			return (CMPLX(h * h * cos(y), h * sin(y)));
		}
	}

	/*
	 * cosh(+-0 +- I Inf) = dNaN + I (+-)(+-)0.
	 * The sign of 0 in the result is unspecified.  Choice = product
	 * of the signs of the argument.  Raise the invalid floating-point
	 * exception.
	 *
	 * cosh(+-0 +- I NaN) = d(NaN) + I (+-)(+-)0.
	 * The sign of 0 in the result is unspecified.  Choice = product
	 * of the signs of the argument.
	 */
	if ((ix | lx) == 0)		/* && iy >= 0x7ff00000 */
		return (CMPLX(y - y, x * copysign(0, y)));

	/*
	 * cosh(+-Inf +- I 0) = +Inf + I (+-)(+-)0.
	 *
	 * cosh(NaN +- I 0)   = d(NaN) + I (+-)(+-)0.
	 * The sign of 0 in the result is unspecified.  Choice = product
	 * of the signs of the argument.
	 */
	if ((iy | ly) == 0)		/* && ix >= 0x7ff00000 */
		return (CMPLX(x * x, copysign(0, x) * y));

	/*
	 * cosh(x +- I Inf) = dNaN + I dNaN.
	 * Raise the invalid floating-point exception for finite nonzero x.
	 *
	 * cosh(x + I NaN) = d(NaN) + I d(NaN).
	 * Optionally raises the invalid floating-point exception for finite
	 * nonzero x.  Choice = don't raise (except for signaling NaNs).
	 */
	if (ix < 0x7ff00000)		/* && iy >= 0x7ff00000 */
		return (CMPLX(y - y, x * (y - y)));

	/*
	 * cosh(+-Inf + I NaN)  = +Inf + I d(NaN).
	 *
	 * cosh(+-Inf +- I Inf) = +Inf + I dNaN.
	 * The sign of Inf in the result is unspecified.  Choice = always +.
	 * Raise the invalid floating-point exception.
	 *
	 * cosh(+-Inf + I y)   = +Inf cos(y) +- I Inf sin(y)
	 */
	if (ix == 0x7ff00000 && lx == 0) {
		if (iy >= 0x7ff00000)
			return (CMPLX(INFINITY, x * (y - y)));
		return (CMPLX(INFINITY * cos(y), x * sin(y)));
	}

	/*
	 * cosh(NaN + I NaN)  = d(NaN) + I d(NaN).
	 *
	 * cosh(NaN +- I Inf) = d(NaN) + I d(NaN).
	 * Optionally raises the invalid floating-point exception.
	 * Choice = raise.
	 *
	 * cosh(NaN + I y)    = d(NaN) + I d(NaN).
	 * Optionally raises the invalid floating-point exception for finite
	 * nonzero y.  Choice = don't raise (except for signaling NaNs).
	 */
	return (CMPLX(((long double)x * x) * (y - y),
	    ((long double)x + x) * (y - y)));
}

double complex
ccos(double complex z)
{

	/* ccos(z) = ccosh(I * z) */
	return (ccosh(CMPLX(-cimag(z), creal(z))));
}

"""

```
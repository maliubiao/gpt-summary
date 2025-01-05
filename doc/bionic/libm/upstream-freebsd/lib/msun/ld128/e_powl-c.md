Response:
Let's break down the thought process for analyzing this `e_powl.c` file. The goal is to understand its functionality and how it relates to Android.

**1. Initial Scan and High-Level Understanding:**

* **Copyright Notices:** The file includes copyright notices from Sun Microsystems and Stephen L. Moshier. This immediately tells us it's based on established, high-quality math library code. The dual licensing suggests a history and potential influences.
* **Function Signature:** `long double powl(long double x, long double y)` clearly indicates this function calculates `x` raised to the power of `y`, operating on `long double` precision floating-point numbers. The `l` suffix signifies "long double".
* **Method Comment:** The initial "Method" section provides a high-level algorithm overview. It mentions calculating the logarithm, performing multiplication, and then exponentiating. This is a standard approach for calculating powers. The breakdown into `w1`, `w2`, `n`, and `y'` hints at handling precision and integer/fractional parts.
* **Special Cases:**  A long list of "Special cases" follows. This is crucial for understanding how the function handles edge cases like NaN, infinity, zero, and specific values like 1 and -1. This list is a goldmine of information about the function's behavior in corner scenarios.
* **Includes:** `<float.h>` and `<math.h>` are standard C headers for floating-point constants and math function declarations. `"math_private.h"` suggests internal definitions and structures specific to the math library implementation.
* **Static Constants:**  The declaration of various `long double` constants like `bp`, `dp_h`, `dp_l`, `zero`, `one`, `two`, `two113`, `huge`, `tiny`, `LN`, `LD`, `PN`, `PD`, `lg2`, `lg2_h`, `lg2_l`, `ovt`, `cp`, `cp_h`, `cp_l`  immediately signals that this implementation relies on pre-computed values for efficiency and accuracy. The names give clues to their purpose (e.g., `lg2` for log base 2).
* **IEEE Quad Shape Type:** The use of `ieee_quad_shape_type` suggests direct manipulation of the bit representation of `long double` (which is often a quad-precision type). This is typical for high-performance, low-level math library implementations.

**2. Deeper Dive into Functionality (Following the Code):**

* **Input Handling:** The code starts by extracting the bit patterns of `x` and `y` using the `ieee_quad_shape_type` union. This allows for quick checks of special values based on their bit representations.
* **Special Case Implementation:** The code directly implements the logic described in the "Special cases" comment. It checks for zero, one, NaN, infinity, etc., using bitwise operations and comparisons.
* **Integer Check:** The `yisint` logic determines if `y` is an integer (odd or even) when `x` is negative. This is needed to handle the definition of negative numbers raised to fractional powers.
* **Magnitude Reduction and Logarithm Calculation:** The code normalizes `x` and calculates its logarithm using a combination of polynomial approximations and pre-computed constants. The `LN` and `LD` arrays are coefficients for a rational function approximation of the logarithm. The manipulation of `n` and the handling of subnormal numbers are part of this process.
* **Multiplication and Exponentiation:** The code then multiplies the logarithm by `y` and performs the exponentiation using polynomial approximations (`PN`, `PD`). It carefully handles potential overflow and underflow.
* **Reconstruction of Result:** Finally, it combines the results and applies the correct sign based on whether the base was negative and the exponent was an odd integer.

**3. Android Relevance and Examples:**

* **`libm` and NDK:**  Knowing this is part of `bionic/libm` directly connects it to Android's math library. NDK applications can use `powl` from `<math.h>`.
* **Framework Usage:**  The Android Framework, written in Java/Kotlin, relies on native code for performance-critical operations. The `java.lang.Math.pow()` function ultimately calls down to native implementations like this for `long double` calculations (though `double` is more common).
* **Examples:**  Simple code snippets demonstrating `powl` usage in NDK and the framework can illustrate the connection.

**4. libc Function Explanations:**

* **`fabsl()`:**  Standard C library function for calculating the absolute value of a `long double`. The implementation usually involves clearing the sign bit.
* **`floorl()`:** Standard C library function for finding the largest integer not greater than the input `long double`. The implementation involves manipulating the exponent and mantissa bits to truncate the fractional part.
* **`sqrtl()`:** Standard C library function for calculating the square root of a `long double`. Implementations often use iterative methods like the Babylonian method or lookup tables and polynomial approximations.
* **`nan_mix()`:**  Not a standard libc function. Its presence in `math_private.h` indicates an Android-specific helper function for generating NaN values, likely preserving some information from the inputs.
* **`scalbnl()`:** Standard C library function for multiplying a `long double` by 2 raised to an integer power. This is a very efficient way to scale floating-point numbers by adjusting the exponent.

**5. Dynamic Linker (Conceptual):**

* **SO Layout:**  Provide a simplified `.so` layout showing sections like `.text`, `.data`, `.bss`, `.symtab`, `.strtab`, `.plt`, `.got`.
* **Symbol Resolution:** Explain the roles of `.symtab` (symbol definitions) and `.dynsym` (dynamic symbol definitions), `.strtab` (string table), `.plt` (Procedure Linkage Table - for lazy binding), and `.got` (Global Offset Table - for storing addresses). Describe the linking process (lazy vs. direct).

**6. Logical Reasoning and Assumptions:**

* **Input/Output Examples:** Provide specific examples with expected outputs, covering normal cases and edge cases from the "Special cases" list. This helps demonstrate the function's behavior.

**7. Common User Errors:**

* Provide examples of incorrect usage, such as passing inappropriate arguments (e.g., negative base with a fractional exponent) or assuming specific behavior that violates the documented special cases.

**8. Debugging Clues (Android Framework/NDK to `e_powl.c`):**

* **NDK:**  Show a simple NDK example using `powl`. Explain how the compiler links against `libm.so`.
* **Framework:**  Trace a call from `java.lang.Math.pow()` down through JNI to the native implementation. This involves mentioning JNI calls and potentially looking at the Android source code for `java.lang.Math`.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the mathematical algorithm.
* **Correction:**  Realize the importance of the "Special cases" and the need to explain how those are implemented.
* **Initial thought:** Provide a generic explanation of the dynamic linker.
* **Correction:** Tailor the explanation to the context of Android and its `.so` files.
* **Initial thought:**  Assume the user has deep C knowledge.
* **Correction:**  Explain potentially less familiar concepts like `ieee_quad_shape_type` and the purpose of the pre-computed constants.
* **Initial thought:**  Omit the debugging part.
* **Correction:** Include debugging information to make the analysis more practical for developers.

By following these steps and iteratively refining the analysis, a comprehensive understanding of the `e_powl.c` file and its role within Android can be achieved.
这是 Android Bionic 中 `libm` 库中 `ld128/e_powl.c` 文件的源代码。这个文件实现了 `powl()` 函数，用于计算 `long double` 类型的数的幂。

下面我们来详细分析其功能和相关方面：

**1. 功能概述:**

`powl(x, y)` 函数计算 `x` 的 `y` 次方，即 x<sup>y</sup>，其中 `x` 和 `y` 都是 `long double` 类型。

**2. 与 Android 功能的关系及举例:**

* **核心数学库:** `libm` 是 Android 系统的核心数学库，提供了各种数学函数，供系统组件、Android Framework 以及 NDK 开发的应用使用。`powl()` 作为其中的一个函数，被广泛用于需要进行高精度幂运算的场景。
* **NDK 开发:** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的一部分。当 NDK 应用中需要进行 `long double` 类型的幂运算时，就会调用到 `libm.so` 中的 `powl()` 函数。
    * **举例:** 一个科学计算类的 NDK 应用可能需要计算非常大或非常小的数的幂，这时 `long double` 提供的更高精度就很有用。例如，计算复利、物理模拟等场景。
* **Android Framework:** 虽然 Android Framework 主要使用 Java/Kotlin 编写，但其底层很多性能敏感的部分仍然依赖 native 代码。某些 Framework 服务或组件在内部可能需要进行高精度的幂运算，从而间接调用到 `powl()`。
    * **举例:**  图形渲染引擎在进行光照计算时，可能会用到幂运算。虽然通常使用 `float` 或 `double`，但在某些高精度需求下，也可能涉及 `long double` 相关的计算。

**3. libc 函数的实现原理:**

`powl()` 函数的实现采用了一种常见的计算幂的方法，主要步骤如下：

* **处理特殊情况:** 首先，函数会检查各种特殊输入情况，例如：
    * `y` 为 0：任何数的 0 次方都为 1。
    * `y` 为 1：任何数的 1 次方都是自身。
    * `x` 或 `y` 为 NaN (Not a Number)：结果为 NaN。
    * 特定值的组合（例如，±∞，±0，±1）等，这些情况在注释中详细列出。
* **对数和指数方法:** 对于一般情况，`powl()` 使用对数和指数的特性进行计算：
    * **计算 log2(x):**  将底数 `x` 表示为 2<sup>n</sup> * (1+f) 的形式，然后计算 `log2(x) = n + log2(1+f)`。  `log2(1+f)` 通常通过多项式逼近来计算，为了提高精度，可能拆分成高位 `w1` 和低位 `w2` 两个部分。
    * **计算 y * log2(x):**  将指数 `y` 乘以 `log2(x)`，得到 `y * log2(x) = n + y'`，其中 `n` 是整数部分，`y'` 是小数部分，且 `|y'| <= 0.5`。这步也可能采用多精度算法来保证精度。
    * **计算 2<sup>n</sup> * exp(y' * log2):**  最终结果为 2 的 `n` 次方乘以 `exp(y' * log2)`。 `exp()` 函数通常也通过多项式逼近来计算。
* **精度处理:** 为了保证 `long double` 的精度，实现中使用了许多技巧，例如：
    * **将浮点数拆分为高低位:** 例如，`log2(x)` 被计算为 `w1 + w2`。
    * **使用预计算的常量:**  例如，`log2(1.5)` 的高低位 `dp_h` 和 `dp_l`，以及用于多项式逼近的系数 `LN`、`LD`、`PN`、`PD`。
    * **仔细的误差控制:**  在每一步计算中都尽量减小误差累积。
* **特殊值的处理:** 代码中大量篇幅用于处理各种特殊输入值，确保在边界情况下返回正确的结果，并符合 IEEE 754 浮点数标准。

**详细解释关键步骤:**

* **计算 log2(x):**
    1. **归一化:** 将 `x` 表示为 `2^n * (1+f)` 的形式，提取出指数 `n` 和尾数 `1+f`。
    2. **区间缩减:**  根据 `f` 的大小，选择合适的区间进行计算。代码中使用了两个区间，通过常量 `bp` 来区分 (1.0 和 1.5)。
    3. **变量代换:**  引入变量 `s = (x-1)/(x+1)` 或 `s = (x-1.5)/(x+1.5)`，将计算范围映射到更小的区间，提高多项式逼近的精度。
    4. **多项式逼近:** 使用有理函数逼近 `log(ax)`，其中 `ax` 是归一化后的 `x`。`LN` 和 `LD` 数组存储了多项式的系数。
    5. **精度补偿:**  计算过程中会产生舍入误差，通过计算高低位 `s_h`、`s_l` 等进行补偿。
    6. **转换为 log2:**  将自然对数转换为以 2 为底的对数。

* **计算 exp(z):**
    1. **区间缩减:** 将指数 `z` 缩小到合适的范围内进行计算。
    2. **多项式逼近:** 使用多项式逼近 `exp(z)`，`PN` 和 `PD` 数组存储了多项式的系数。

**4. Dynamic Linker 的功能:**

Dynamic Linker (在 Android 中主要是 `linker64` 或 `linker`) 负责在程序运行时将共享库 (Shared Objects, `.so` 文件) 加载到内存中，并解析和绑定程序中使用的符号。

**SO 布局样本:**

一个典型的 `.so` 文件布局可能如下：

```
.so 文件头 (ELF Header)
Program Headers (描述内存段的加载信息)
Section Headers (描述各个 section 的信息)

.text         (代码段，包含可执行指令)
.rodata       (只读数据段，包含常量字符串等)
.data         (已初始化的可读写数据段)
.bss          (未初始化的可读写数据段)

.symtab       (符号表，包含全局和静态符号的定义)
.strtab       (字符串表，存储符号名称等字符串)
.dynsym       (动态符号表，包含需要动态链接的符号)
.dynstr       (动态字符串表，存储动态符号名称等字符串)
.rel.plt      (PLT 重定位表)
.rel.dyn      (其他重定位表)
.plt          (Procedure Linkage Table，过程链接表)
.got          (Global Offset Table，全局偏移表)

... 其他 sections ...
```

**每种符号的处理过程:**

1. **程序启动:** 当 Android 系统启动一个使用共享库的应用时，Dynamic Linker 会被加载到进程空间。
2. **加载共享库:** Dynamic Linker 根据程序依赖的共享库信息，将相关的 `.so` 文件加载到内存中。
3. **解析符号表:** Dynamic Linker 会解析 `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表)，找到程序引用的外部符号。
4. **重定位:**  由于共享库的加载地址在运行时才能确定，Dynamic Linker 需要修改代码和数据段中对外部符号的引用，使其指向正确的内存地址。这个过程称为重定位。
    * **全局变量:** 对于全局变量，Dynamic Linker 会在 `.got` (Global Offset Table) 中分配一个条目，并将该全局变量的实际地址填入。程序通过 `.got` 表间接访问全局变量。
    * **函数:** 对于函数，通常使用 **延迟绑定 (Lazy Binding)** 或 **立即绑定 (Immediate Binding)**。
        * **延迟绑定 (默认):**  当程序第一次调用一个外部函数时，会跳转到 `.plt` (Procedure Linkage Table) 中的一段代码。`.plt` 代码会调用 Dynamic Linker 来解析该函数的实际地址，并更新 `.got` 表中对应的条目。后续对该函数的调用将直接通过 `.got` 表跳转到实际地址，避免重复解析。
        * **立即绑定:** 在加载时就解析所有外部函数的地址并更新 `.got` 表。
5. **符号查找顺序:** Dynamic Linker 在查找符号时会按照一定的顺序进行，通常包括：
    * **当前可执行文件:**  首先在程序自身查找。
    * **已加载的共享库:**  按照加载顺序查找。
    * **系统默认库路径:** 例如 `/system/lib64` 或 `/vendor/lib64`。

**`powl` 函数的符号处理:**

当一个程序 (例如，一个 NDK 应用) 调用 `powl()` 函数时，链接过程如下：

1. **编译时:** 编译器会将对 `powl()` 的调用生成一个对外部符号的引用。
2. **链接时:** 静态链接器会将这个引用标记为需要动态链接。
3. **运行时:** Dynamic Linker 加载 `libm.so`，并在其 `.dynsym` 中找到 `powl` 符号的定义。
4. **重定位:** Dynamic Linker 会更新调用 `powl()` 的代码中的地址，使其指向 `libm.so` 中 `powl` 函数的实际地址。  如果使用延迟绑定，则在第一次调用时完成。

**6. 逻辑推理的假设输入与输出:**

* **假设输入:** `x = 2.0`, `y = 3.0`
* **预期输出:** `8.0`

* **假设输入:** `x = 10.0`, `y = 0.5`
* **预期输出:** `3.1622776601683793319988935444327185337196` (近似值，`sqrt(10.0)`)

* **假设输入:** `x = -2.0`, `y = 3.0`
* **预期输出:** `-8.0`

* **假设输入:** `x = -2.0`, `y = 3.5`
* **预期输出:** `NaN` (负数的非整数次幂)

* **假设输入:** `x = 0.0`, `y = 2.0`
* **预期输出:** `0.0`

* **假设输入:** `x = 0.0`, `y = -2.0`
* **预期输出:** `+Infinity`

**7. 用户或编程常见的使用错误:**

* **对负数进行非整数次幂运算:**  例如 `powl(-2.0, 0.5)`，数学上没有实数结果，会返回 `NaN`。
* **溢出或下溢:** 当底数和指数的值很大或很小时，计算结果可能超出 `long double` 的表示范围，导致溢出 (返回 ±Infinity) 或下溢 (返回 ±0)。
* **精度问题:**  虽然 `long double` 提供了更高的精度，但在进行大量计算时，仍然可能存在累积的舍入误差。
* **不理解特殊情况:**  例如，认为 `0**0` 是 0 或 1，但实际上 `powl(0.0, 0.0)` 根据 IEEE 754 标准返回 `1.0`。

**举例说明常见错误:**

```c
#include <stdio.h>
#include <math.h>

int main() {
  long double result;

  // 错误示例 1: 对负数进行非整数次幂运算
  result = powl(-2.0L, 0.5L);
  printf("powl(-2.0, 0.5) = %Lf\n", result); // 输出 NaN

  // 错误示例 2: 可能导致溢出
  result = powl(1.0e100L, 10.0L);
  printf("powl(1.0e100, 10.0) = %Lf\n", result); // 输出 +Infinity

  return 0;
}
```

**8. Android Framework 或 NDK 如何一步步到达这里 (调试线索):**

**Android Framework 到 `e_powl.c`:**

1. **Java 代码调用 `java.lang.Math.pow(double a, double b)`:**  Framework 中某个 Java 类需要进行幂运算，例如图形渲染、动画计算等。
2. **`java.lang.Math.pow()` 调用 native 方法:** `java.lang.Math.pow()` 是一个 native 方法。
3. **JNI (Java Native Interface) 调用:**  Java 虚拟机 (Dalvik/ART) 通过 JNI 机制调用到对应的 native 实现。
4. **Native 实现 (通常在 `libjavacrypto.so` 或类似的库中):**  `java.lang.Math.pow(double, double)` 的 native 实现会调用 `libm.so` 中的 `pow()` 函数 (注意这里是 `double` 版本)。
5. **如果需要 `long double` 精度:**  在某些特殊的 Framework 组件或库中，可能直接使用 JNI 调用到 `libm.so` 中的 `powl()` 函数。但这相对较少，因为 Framework 中更多使用 `double` 类型。

**NDK 到 `e_powl.c`:**

1. **NDK 应用代码调用 `powl()`:** NDK 开发的 C/C++ 代码中包含了 `<math.h>` 并调用了 `powl(long double, long double)`。
2. **编译和链接:** NDK 编译工具链 (如 Clang) 会将对 `powl()` 的调用编译为对外部符号的引用。链接器会将这个引用链接到 Android 系统提供的共享库 `libm.so`。
3. **运行时加载:** 当 NDK 应用运行时，Android 的 Dynamic Linker (`linker64` 或 `linker`) 会加载 `libm.so` 到进程空间。
4. **符号解析和绑定:** Dynamic Linker 解析 `libm.so` 的符号表，找到 `powl` 函数的地址，并将 NDK 应用中对 `powl()` 的调用绑定到 `libm.so` 中 `e_powl.c` 实现的函数。

**调试线索:**

* **NDK 调试:** 可以使用 GDB 或 LLDB 连接到正在运行的 Android 设备或模拟器上的 NDK 进程，设置断点在 `powl()` 函数入口处，观察调用堆栈。
* **Framework 调试:**  需要查看 Android Framework 的源代码，找到调用 `java.lang.Math.pow()` 的地方，并跟踪其 native 实现的调用过程。可以使用 Android Studio 的调试功能，或者通过 logcat 输出调试信息。
* **查看 `libm.so` 的符号表:** 使用 `readelf -s /system/lib64/libm.so` (或对应的路径) 可以查看 `libm.so` 中定义的符号，确认 `powl` 的存在。
* **反汇编代码:** 使用 `objdump -d /system/lib64/libm.so` 可以反汇编 `libm.so` 的代码，查看 `powl` 函数的具体实现。

总而言之，`e_powl.c` 是 Android Bionic 中 `libm` 库提供高精度幂运算功能的核心实现，它通过精巧的算法和对特殊情况的细致处理，确保了在各种场景下都能返回准确的结果。 理解其实现原理有助于我们更好地理解 Android 系统的底层机制以及如何进行高性能的数学计算。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/e_powl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * Copyright (c) 2008 Stephen L. Moshier <steve@moshier.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* powl(x,y) return x**y
 *
 *		      n
 * Method:  Let x =  2   * (1+f)
 *	1. Compute and return log2(x) in two pieces:
 *		log2(x) = w1 + w2,
 *	   where w1 has 113-53 = 60 bit trailing zeros.
 *	2. Perform y*log2(x) = n+y' by simulating multi-precision
 *	   arithmetic, where |y'|<=0.5.
 *	3. Return x**y = 2**n*exp(y'*log2)
 *
 * Special cases:
 *	1.  (anything) ** 0  is 1
 *	2.  (anything) ** 1  is itself
 *	3.  (anything) ** NAN is NAN
 *	4.  NAN ** (anything except 0) is NAN
 *	5.  +-(|x| > 1) **  +INF is +INF
 *	6.  +-(|x| > 1) **  -INF is +0
 *	7.  +-(|x| < 1) **  +INF is +0
 *	8.  +-(|x| < 1) **  -INF is +INF
 *	9.  +-1         ** +-INF is NAN
 *	10. +0 ** (+anything except 0, NAN)               is +0
 *	11. -0 ** (+anything except 0, NAN, odd integer)  is +0
 *	12. +0 ** (-anything except 0, NAN)               is +INF
 *	13. -0 ** (-anything except 0, NAN, odd integer)  is +INF
 *	14. -0 ** (odd integer) = -( +0 ** (odd integer) )
 *	15. +INF ** (+anything except 0,NAN) is +INF
 *	16. +INF ** (-anything except 0,NAN) is +0
 *	17. -INF ** (anything)  = -0 ** (-anything)
 *	18. (-anything) ** (integer) is (-1)**(integer)*(+anything**integer)
 *	19. (-anything except 0 and inf) ** (non-integer) is NAN
 *
 */

#include <float.h>
#include <math.h>

#include "math_private.h"

static const long double bp[] = {
  1.0L,
  1.5L,
};

/* log_2(1.5) */
static const long double dp_h[] = {
  0.0,
  5.8496250072115607565592654282227158546448E-1L
};

/* Low part of log_2(1.5) */
static const long double dp_l[] = {
  0.0,
  1.0579781240112554492329533686862998106046E-16L
};

static const long double zero = 0.0L,
  one = 1.0L,
  two = 2.0L,
  two113 = 1.0384593717069655257060992658440192E34L,
  huge = 1.0e3000L,
  tiny = 1.0e-3000L;

/* 3/2 log x = 3 z + z^3 + z^3 (z^2 R(z^2))
   z = (x-1)/(x+1)
   1 <= x <= 1.25
   Peak relative error 2.3e-37 */
static const long double LN[] =
{
 -3.0779177200290054398792536829702930623200E1L,
  6.5135778082209159921251824580292116201640E1L,
 -4.6312921812152436921591152809994014413540E1L,
  1.2510208195629420304615674658258363295208E1L,
 -9.9266909031921425609179910128531667336670E-1L
};
static const long double LD[] =
{
 -5.129862866715009066465422805058933131960E1L,
  1.452015077564081884387441590064272782044E2L,
 -1.524043275549860505277434040464085593165E2L,
  7.236063513651544224319663428634139768808E1L,
 -1.494198912340228235853027849917095580053E1L
  /* 1.0E0 */
};

/* exp(x) = 1 + x - x / (1 - 2 / (x - x^2 R(x^2)))
   0 <= x <= 0.5
   Peak relative error 5.7e-38  */
static const long double PN[] =
{
  5.081801691915377692446852383385968225675E8L,
  9.360895299872484512023336636427675327355E6L,
  4.213701282274196030811629773097579432957E4L,
  5.201006511142748908655720086041570288182E1L,
  9.088368420359444263703202925095675982530E-3L,
};
static const long double PD[] =
{
  3.049081015149226615468111430031590411682E9L,
  1.069833887183886839966085436512368982758E8L,
  8.259257717868875207333991924545445705394E5L,
  1.872583833284143212651746812884298360922E3L,
  /* 1.0E0 */
};

static const long double
  /* ln 2 */
  lg2 = 6.9314718055994530941723212145817656807550E-1L,
  lg2_h = 6.9314718055994528622676398299518041312695E-1L,
  lg2_l = 2.3190468138462996154948554638754786504121E-17L,
  ovt = 8.0085662595372944372e-0017L,
  /* 2/(3*log(2)) */
  cp = 9.6179669392597560490661645400126142495110E-1L,
  cp_h = 9.6179669392597555432899980587535537779331E-1L,
  cp_l = 5.0577616648125906047157785230014751039424E-17L;

long double
powl(long double x, long double y)
{
  long double z, ax, z_h, z_l, p_h, p_l;
  long double yy1, t1, t2, r, s, t, u, v, w;
  long double s2, s_h, s_l, t_h, t_l;
  int32_t i, j, k, yisint, n;
  u_int32_t ix, iy;
  int32_t hx, hy;
  ieee_quad_shape_type o, p, q;

  p.value = x;
  hx = p.parts32.mswhi;
  ix = hx & 0x7fffffff;

  q.value = y;
  hy = q.parts32.mswhi;
  iy = hy & 0x7fffffff;


  /* y==zero: x**0 = 1 */
  if ((iy | q.parts32.mswlo | q.parts32.lswhi | q.parts32.lswlo) == 0)
    return one;

  /* 1.0**y = 1; -1.0**+-Inf = 1 */
  if (x == one)
    return one;
  if (x == -1.0L && iy == 0x7fff0000
      && (q.parts32.mswlo | q.parts32.lswhi | q.parts32.lswlo) == 0)
    return one;

  /* +-NaN return x+y */
  if ((ix > 0x7fff0000)
      || ((ix == 0x7fff0000)
	  && ((p.parts32.mswlo | p.parts32.lswhi | p.parts32.lswlo) != 0))
      || (iy > 0x7fff0000)
      || ((iy == 0x7fff0000)
	  && ((q.parts32.mswlo | q.parts32.lswhi | q.parts32.lswlo) != 0)))
    return nan_mix(x, y);

  /* determine if y is an odd int when x < 0
   * yisint = 0       ... y is not an integer
   * yisint = 1       ... y is an odd int
   * yisint = 2       ... y is an even int
   */
  yisint = 0;
  if (hx < 0)
    {
      if (iy >= 0x40700000)	/* 2^113 */
	yisint = 2;		/* even integer y */
      else if (iy >= 0x3fff0000)	/* 1.0 */
	{
	  if (floorl (y) == y)
	    {
	      z = 0.5 * y;
	      if (floorl (z) == z)
		yisint = 2;
	      else
		yisint = 1;
	    }
	}
    }

  /* special value of y */
  if ((q.parts32.mswlo | q.parts32.lswhi | q.parts32.lswlo) == 0)
    {
      if (iy == 0x7fff0000)	/* y is +-inf */
	{
	  if (((ix - 0x3fff0000) | p.parts32.mswlo | p.parts32.lswhi |
	    p.parts32.lswlo) == 0)
	    return y - y;	/* +-1**inf is NaN */
	  else if (ix >= 0x3fff0000)	/* (|x|>1)**+-inf = inf,0 */
	    return (hy >= 0) ? y : zero;
	  else			/* (|x|<1)**-,+inf = inf,0 */
	    return (hy < 0) ? -y : zero;
	}
      if (iy == 0x3fff0000)
	{			/* y is  +-1 */
	  if (hy < 0)
	    return one / x;
	  else
	    return x;
	}
      if (hy == 0x40000000)
	return x * x;		/* y is  2 */
      if (hy == 0x3ffe0000)
	{			/* y is  0.5 */
	  if (hx >= 0)		/* x >= +0 */
	    return sqrtl (x);
	}
    }

  ax = fabsl (x);
  /* special value of x */
  if ((p.parts32.mswlo | p.parts32.lswhi | p.parts32.lswlo) == 0)
    {
      if (ix == 0x7fff0000 || ix == 0 || ix == 0x3fff0000)
	{
	  z = ax;		/*x is +-0,+-inf,+-1 */
	  if (hy < 0)
	    z = one / z;	/* z = (1/|x|) */
	  if (hx < 0)
	    {
	      if (((ix - 0x3fff0000) | yisint) == 0)
		{
		  z = (z - z) / (z - z);	/* (-1)**non-int is NaN */
		}
	      else if (yisint == 1)
		z = -z;		/* (x<0)**odd = -(|x|**odd) */
	    }
	  return z;
	}
    }

  /* (x<0)**(non-int) is NaN */
  if (((((u_int32_t) hx >> 31) - 1) | yisint) == 0)
    return (x - x) / (x - x);

  /* |y| is huge.
     2^-16495 = 1/2 of smallest representable value.
     If (1 - 1/131072)^y underflows, y > 1.4986e9 */
  if (iy > 0x401d654b)
    {
      /* if (1 - 2^-113)^y underflows, y > 1.1873e38 */
      if (iy > 0x407d654b)
	{
	  if (ix <= 0x3ffeffff)
	    return (hy < 0) ? huge * huge : tiny * tiny;
	  if (ix >= 0x3fff0000)
	    return (hy > 0) ? huge * huge : tiny * tiny;
	}
      /* over/underflow if x is not close to one */
      if (ix < 0x3ffeffff)
	return (hy < 0) ? huge * huge : tiny * tiny;
      if (ix > 0x3fff0000)
	return (hy > 0) ? huge * huge : tiny * tiny;
    }

  n = 0;
  /* take care subnormal number */
  if (ix < 0x00010000)
    {
      ax *= two113;
      n -= 113;
      o.value = ax;
      ix = o.parts32.mswhi;
    }
  n += ((ix) >> 16) - 0x3fff;
  j = ix & 0x0000ffff;
  /* determine interval */
  ix = j | 0x3fff0000;		/* normalize ix */
  if (j <= 0x3988)
    k = 0;			/* |x|<sqrt(3/2) */
  else if (j < 0xbb67)
    k = 1;			/* |x|<sqrt(3)   */
  else
    {
      k = 0;
      n += 1;
      ix -= 0x00010000;
    }

  o.value = ax;
  o.parts32.mswhi = ix;
  ax = o.value;

  /* compute s = s_h+s_l = (x-1)/(x+1) or (x-1.5)/(x+1.5) */
  u = ax - bp[k];		/* bp[0]=1.0, bp[1]=1.5 */
  v = one / (ax + bp[k]);
  s = u * v;
  s_h = s;

  o.value = s_h;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  s_h = o.value;
  /* t_h=ax+bp[k] High */
  t_h = ax + bp[k];
  o.value = t_h;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  t_h = o.value;
  t_l = ax - (t_h - bp[k]);
  s_l = v * ((u - s_h * t_h) - s_h * t_l);
  /* compute log(ax) */
  s2 = s * s;
  u = LN[0] + s2 * (LN[1] + s2 * (LN[2] + s2 * (LN[3] + s2 * LN[4])));
  v = LD[0] + s2 * (LD[1] + s2 * (LD[2] + s2 * (LD[3] + s2 * (LD[4] + s2))));
  r = s2 * s2 * u / v;
  r += s_l * (s_h + s);
  s2 = s_h * s_h;
  t_h = 3.0 + s2 + r;
  o.value = t_h;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  t_h = o.value;
  t_l = r - ((t_h - 3.0) - s2);
  /* u+v = s*(1+...) */
  u = s_h * t_h;
  v = s_l * t_h + t_l * s;
  /* 2/(3log2)*(s+...) */
  p_h = u + v;
  o.value = p_h;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  p_h = o.value;
  p_l = v - (p_h - u);
  z_h = cp_h * p_h;		/* cp_h+cp_l = 2/(3*log2) */
  z_l = cp_l * p_h + p_l * cp + dp_l[k];
  /* log2(ax) = (s+..)*2/(3*log2) = n + dp_h + z_h + z_l */
  t = (long double) n;
  t1 = (((z_h + z_l) + dp_h[k]) + t);
  o.value = t1;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  t1 = o.value;
  t2 = z_l - (((t1 - t) - dp_h[k]) - z_h);

  /* s (sign of result -ve**odd) = -1 else = 1 */
  s = one;
  if (((((u_int32_t) hx >> 31) - 1) | (yisint - 1)) == 0)
    s = -one;			/* (-ve)**(odd int) */

  /* split up y into yy1+y2 and compute (yy1+y2)*(t1+t2) */
  yy1 = y;
  o.value = yy1;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  yy1 = o.value;
  p_l = (y - yy1) * t1 + y * t2;
  p_h = yy1 * t1;
  z = p_l + p_h;
  o.value = z;
  j = o.parts32.mswhi;
  if (j >= 0x400d0000) /* z >= 16384 */
    {
      /* if z > 16384 */
      if (((j - 0x400d0000) | o.parts32.mswlo | o.parts32.lswhi |
	o.parts32.lswlo) != 0)
	return s * huge * huge;	/* overflow */
      else
	{
	  if (p_l + ovt > z - p_h)
	    return s * huge * huge;	/* overflow */
	}
    }
  else if ((j & 0x7fffffff) >= 0x400d01b9)	/* z <= -16495 */
    {
      /* z < -16495 */
      if (((j - 0xc00d01bc) | o.parts32.mswlo | o.parts32.lswhi |
	o.parts32.lswlo)
	  != 0)
	return s * tiny * tiny;	/* underflow */
      else
	{
	  if (p_l <= z - p_h)
	    return s * tiny * tiny;	/* underflow */
	}
    }
  /* compute 2**(p_h+p_l) */
  i = j & 0x7fffffff;
  k = (i >> 16) - 0x3fff;
  n = 0;
  if (i > 0x3ffe0000)
    {				/* if |z| > 0.5, set n = [z+0.5] */
      n = floorl (z + 0.5L);
      t = n;
      p_h -= t;
    }
  t = p_l + p_h;
  o.value = t;
  o.parts32.lswlo = 0;
  o.parts32.lswhi &= 0xf8000000;
  t = o.value;
  u = t * lg2_h;
  v = (p_l - (t - p_h)) * lg2 + t * lg2_l;
  z = u + v;
  w = v - (z - u);
  /*  exp(z) */
  t = z * z;
  u = PN[0] + t * (PN[1] + t * (PN[2] + t * (PN[3] + t * PN[4])));
  v = PD[0] + t * (PD[1] + t * (PD[2] + t * (PD[3] + t)));
  t1 = z - t * u / v;
  r = (z * t1) / (t1 - two) - (w + z * w);
  z = one - (r - z);
  o.value = z;
  j = o.parts32.mswhi;
  j += (n << 16);
  if ((j >> 16) <= 0)
    z = scalbnl (z, n);	/* subnormal output */
  else
    {
      o.parts32.mswhi = j;
      z = o.value;
    }
  return s * z;
}

"""

```
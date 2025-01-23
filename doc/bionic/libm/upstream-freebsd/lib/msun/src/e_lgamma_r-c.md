Response:
Let's break down the thought process for analyzing the `e_lgamma_r.c` file.

1. **Understand the Goal:** The primary request is to analyze the functionality of this C source file, its relation to Android, the implementation details of libc functions, dynamic linker behavior (though this file isn't directly related to it), potential usage errors, and how Android reaches this code.

2. **Initial Reading and Keyword Identification:**  Skim through the code, paying attention to comments, function names, included headers, and constant definitions. Keywords like `lgamma_r`, `Gamma function`, `logarithm`, `polynomial approximation`, `rational approximation`, `argument reduction`, `signgamp`, `sin_pi`, `__kernel_sin`, `__kernel_cos`, `EXTRACT_WORDS`, `volatile`, `static const`, and conditional compilation (`#if`) stand out.

3. **Functionality Identification (High-Level):** The core purpose is clearly calculating the natural logarithm of the absolute value of the Gamma function, `lgamma(|x|)`. The `_r` suffix suggests a reentrant version, and the `signgamp` argument indicates it also provides the sign of the Gamma function.

4. **Algorithm Breakdown (Mid-Level):**  The comments provide a good roadmap of the implementation strategy:
    * **Argument Reduction (0 < x <= 8):** Reduce the input to the [1.5, 2.5] range using the property `lgamma(1+s) = log(s) + lgamma(s)`.
    * **Polynomial Approximation (around minimum):** For values near the minimum of lgamma, use a polynomial approximation.
    * **Rational Approximation (primary interval [2, 3]):** For the interval [2, 3], use a rational function approximation.
    * **Asymptotic Expansion (x >= 8):** For large x, use an asymptotic expansion based on Stirling's approximation.
    * **Negative x:**  Use the reflection formula involving the sine function.
    * **Special Cases:** Handle specific values like 0, 1, 2, negative integers, infinity, and NaN.

5. **Code Deep Dive (Low-Level - Selective):** Now, focus on specific code sections:
    * **Include Headers:** `float.h` for floating-point limits, `math.h` for standard math functions, `math_private.h` likely for internal math library functions.
    * **Constants:** Examine the defined constants (`zero`, `half`, `one`, `pi`, coefficients for polynomials and rational functions). The names often hint at their purpose (e.g., `a0`, `t0`, `u0`, `r1`, `w0`).
    * **`sin_pi` function:**  This function is interesting. It calculates `sin(pi*x)` without directly computing `pi*x` to maintain accuracy, especially for large x. It cleverly uses modulo arithmetic and calls `__kernel_sin` and `__kernel_cos`.
    * **`lgamma_r` function:**  Trace the main logic flow:
        * **NaN/Inf handling:** Check for and return early for these cases.
        * **Zero/tiny argument handling:** Return `-log(|x|)` or infinity.
        * **Negative number handling:** Calculate `sin_pi(x)` and use the reflection formula.
        * **Small positive x handling:** Use the argument reduction and polynomial/rational approximations.
        * **Large positive x handling:** Apply the asymptotic expansion.
    * **`EXTRACT_WORDS` macro:**  Recognize this as a common way to access the raw bit representation of a double, essential for precise floating-point manipulation.
    * **`__weak_reference`:** Note this is for compatibility and might link `lgamma_r` and `lgammal_r` (the `long double` version).

6. **Android Relevance:**
    * **libc Function:**  `lgamma_r` is a standard C math library function, directly part of Android's Bionic libc. Any Android app using the NDK can call this function.
    * **System Calls (Indirect):**  While `lgamma_r` itself doesn't make direct system calls, the underlying `__kernel_sin` and `__kernel_cos` might eventually rely on highly optimized, potentially architecture-specific implementations that could involve very low-level operations.

7. **Dynamic Linker (Separate but Related):**  While this specific file *implements* a libc function, it doesn't directly handle dynamic linking. Think about the *result* of compiling this: a shared library (`.so`).
    * **SO Layout:**  Consider the typical sections: `.text` (code), `.rodata` (read-only data like constants), `.data` (initialized data), `.bss` (uninitialized data), symbol tables.
    * **Symbol Resolution:**  When an app uses `lgamma_r`, the dynamic linker finds the symbol in `libc.so` (or a similar library), resolves its address, and patches the call site.

8. **Common Errors:** Think about typical mistakes programmers make when dealing with Gamma functions or logarithms:
    * **Domain Errors:** Passing non-positive integers to `lgamma`.
    * **Overflow/Underflow:**  Gamma function grows very rapidly.
    * **Precision Issues:**  While the implementation is careful, general floating-point precision limitations can arise.

9. **Debugging Path (Android Framework/NDK to `lgamma_r`):** Trace the execution flow from a high-level Android context down to this function:
    * **Java Code:**  Android framework code (in Java) might need gamma-related calculations.
    * **JNI:**  To use `lgamma_r`, Java code would call a native method via the Java Native Interface (JNI).
    * **NDK C/C++ Code:**  The native method implementation (written in C/C++ using the NDK) would then call the `lgamma_r` function.
    * **`libc.so`:** The linker would resolve `lgamma_r` to its implementation within `libc.so`.

10. **Review and Refine:** Go back through the generated information, ensuring clarity, accuracy, and completeness. Organize the points logically, using headings and bullet points. Add examples where appropriate. For instance, when discussing dynamic linking, a simplified SO layout example is beneficial. Double-check the explanations of the algorithms and the function of `sin_pi`.

This detailed, step-by-step approach helps ensure all aspects of the prompt are addressed comprehensively and accurately. The key is to move from a high-level understanding down to the implementation details and then back up to the broader context of Android and its development ecosystem.
这个文件 `e_lgamma_r.c` 实现了 `lgamma_r` 函数，这是标准 C 库 (`libc`) 中的一个数学函数。让我们详细分析它的功能和相关方面。

**功能列举:**

1. **计算 Gamma 函数的绝对值的自然对数 (Log Gamma):**  `lgamma_r(x, signgamp)` 的主要功能是计算输入参数 `x` 的 Gamma 函数 `Γ(x)` 的绝对值的自然对数，即 `ln(|Γ(x)|)`.

2. **返回 Gamma 函数的符号:**  除了计算对数伽玛值，`lgamma_r` 还通过指针参数 `signgamp` 返回 `Γ(x)` 的符号。如果 `Γ(x)` 为正，则 `*signgamp` 为正数；如果 `Γ(x)` 为负，则 `*signgamp` 为负数。

3. **处理各种输入情况:**  该函数需要能够处理各种类型的输入 `x`，包括：
    * 正数
    * 负数
    * 小数值
    * 大数值
    * 特殊值 (如 0, 1, 2, 正负无穷大, NaN)

**与 Android 功能的关系举例:**

`lgamma_r` 是 Bionic libc 的一部分，因此任何使用标准 C 库数学函数的 Android 应用或系统组件都可以间接地或直接地使用它。

* **NDK 开发:** 使用 Android NDK 进行原生开发的应用程序可以直接调用 `lgamma_r`。例如，一个需要进行统计计算或科学计算的应用可能会用到 Gamma 函数及其对数。

  ```c
  #include <math.h>
  #include <stdio.h>

  int main() {
      double x = 3.5;
      int sign;
      double result = lgamma_r(x, &sign);
      printf("lgamma_r(%f) = %f, sign = %d\n", x, result, sign);
      return 0;
  }
  ```

* **Android Framework:** 虽然 Android Framework 主要使用 Java，但在某些底层操作或性能敏感的模块中，可能会使用 JNI (Java Native Interface) 调用到底层的 C/C++ 代码，这些代码可能会使用 `lgamma_r`。例如，一些机器学习或信号处理相关的系统服务可能在内部使用。

**详细解释 libc 函数的功能是如何实现的:**

`e_lgamma_r.c` 中的代码提供了 `lgamma_r` 函数的具体实现方法。它使用了多种数学技巧和近似方法来提高计算效率和精度：

1. **参数约简 (Argument Reduction) for 0 < x <= 8:**
   - 利用 Gamma 函数的性质 `Γ(x+1) = x * Γ(x)`，推导出 `lgamma(x+1) = log(x) + lgamma(x)`。
   - 将 `x` 约减到 `[1.5, 2.5]` 区间，通过迭代应用上述公式。这减少了需要进行高精度计算的输入范围。

2. **在最小值附近的多项式逼近:**
   - 在 `lgamma(x)` 的最小值附近（大约在 `x = 1.46`），使用多项式来逼近函数值。
   - 这种方法在局部提供了高精度的近似。

3. **在主要区间 [2, 3] 的有理逼近:**
   - 对于 `x` 在 `[2, 3]` 区间，使用有理函数（两个多项式的比值）来逼近 `lgamma(x)`。
   - 注释中提到了基于 Euler 常数的展开式，这为选择有理逼近的形式提供了理论基础。

4. **对于 x >= 8 的渐近展开:**
   - 当 `x` 很大时，使用斯特林公式的对数形式进行近似：`lgamma(x) ≈ (x - 0.5)log(x) - x + 0.5*log(2π) + ...`
   - 代码中使用了更精确的形式，并利用变量替换 `z = 1/x` 来构建多项式逼近剩余项。

5. **对于负数 x 的处理:**
   - 利用 Gamma 函数的反射公式：`Γ(x)Γ(1-x) = π / sin(πx)`。
   - 对其取绝对值并取对数，得到 `lgamma(x) = log(π / |x sin(πx)|) - lgamma(-x)`。
   - `signgamp` 的值根据 `sin(πx)` 的符号确定。
   - 代码中调用了 `sin_pi(x)` 函数来计算 `sin(πx)`，这个函数避免了直接计算 `π*x` 以减少精度损失。

6. **特殊情况处理:**
   - `lgamma(1) = lgamma(2) = 0`
   - 对于很小的 `x`，`lgamma(x) ≈ -log(|x|)`
   - `lgamma(0)` 和负整数的 `lgamma` 值是无穷大，会引发除零错误。
   - `lgamma(inf) = inf`
   - `lgamma(-inf) = inf` (C99 标准中的行为)

**`sin_pi(double x)` 函数的实现:**

`sin_pi(double x)` 函数用于计算 `sin(πx)`，特别是在处理负数 `x` 时。它的实现方式避免了直接计算 `pi * x`，而是利用了正弦函数的周期性和对称性，以及 `__kernel_sin` 和 `__kernel_cos` 这两个更底层的函数。

- 它将 `x` 的整数部分分离出来，并将问题转化为计算 `sin(π * fractional_part)` 或 `cos(π * fractional_part)`。
- 通过对 `x` 进行适当的调整，将计算范围缩小到一个较小的区间 `[0, 2]`。
- 根据 `x mod 2` 的值，调用 `__kernel_sin` 或 `__kernel_cos` 来计算结果。

**Dynamic Linker 的功能:**

虽然 `e_lgamma_r.c` 本身是 C 代码，不直接涉及动态链接，但当这个文件被编译成共享库 (如 `libc.so`) 后，dynamic linker (在 Android 中是 `linker64` 或 `linker`) 就负责在程序运行时加载和链接这个库。

**SO 布局样本 (以 `libc.so` 为例):**

```
libc.so:
  .text         # 包含 lgamma_r 等函数的机器码
  .rodata       # 包含常量，如代码中定义的 zero, half, pi 等
  .data         # 包含已初始化的全局变量
  .bss          # 包含未初始化的全局变量
  .dynsym       # 动态符号表，列出导出的和导入的符号
  .dynstr       # 动态字符串表，包含符号名称
  .plt          # 程序链接表，用于延迟绑定
  .got.plt      # 全局偏移表，存储外部符号的地址
  ...          # 其他段
```

**每种符号的处理过程:**

1. **导出符号 (Exported Symbols):**
   - `lgamma_r` 就是一个导出符号。
   - 当 `libc.so` 被编译时，`lgamma_r` 的符号信息（名称、地址等）会被添加到 `.dynsym` 和 `.dynstr` 中。
   - Dynamic linker 在加载依赖于 `libc.so` 的可执行文件或共享库时，会查找这些导出符号来解析未定义的引用。

2. **导入符号 (Imported Symbols):**
   - 在 `e_lgamma_r.c` 中，`__kernel_sin` 和 `__kernel_cos` 是导入符号（假设它们在其他的共享库中定义，虽然通常它们也在 `libc.so` 或类似的库中）。
   - 编译时，这些符号会被标记为未定义，并在 `.dynsym` 中记录它们的需求。
   - Dynamic linker 在加载 `libc.so` 时，会查找提供这些符号定义的其他共享库，并更新 `libc.so` 的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table) 中的相应条目，使得 `lgamma_r` 可以正确调用 `__kernel_sin` 和 `__kernel_cos`。

**符号解析过程:**

- 当一个程序调用 `lgamma_r` 时，如果这是第一次调用，并且使用了延迟绑定，那么会先跳转到 PLT 中的一个桩代码。
- 这个桩代码会调用 dynamic linker 的解析函数。
- Dynamic linker 会在已加载的共享库中查找 `lgamma_r` 的定义。
- 找到定义后，dynamic linker 会更新 GOT 中 `lgamma_r` 对应的条目，使其指向 `lgamma_r` 的实际地址。
- 后续对 `lgamma_r` 的调用将直接通过 GOT 跳转到其地址，避免了重复的符号查找。

**假设输入与输出 (逻辑推理):**

假设我们调用 `lgamma_r` 函数：

- **假设输入:** `x = 3.0`, `signgamp` 是一个指向 `int` 的指针。
- **逻辑推理:**
    - `Γ(3) = 2! = 2`
    - `ln(|Γ(3)|) = ln(2) ≈ 0.693147`
    - `Γ(3)` 是正数，所以 `*signgamp` 应该被设置为 `1`。
- **预期输出:** `lgamma_r(3.0, &sign)` 返回值约为 `0.693147`，并且 `sign` 的值变为 `1`。

- **假设输入:** `x = -0.5`, `signgamp` 是一个指向 `int` 的指针。
- **逻辑推理:**
    - `Γ(-0.5) = -2√π`
    - `ln(|Γ(-0.5)|) = ln(2√π) = ln(2) + 0.5 * ln(π) ≈ 0.693147 + 0.5 * 1.14473 ≈ 1.2655`
    - `Γ(-0.5)` 是负数，所以 `*signgamp` 应该被设置为 `-1`。
- **预期输出:** `lgamma_r(-0.5, &sign)` 返回值约为 `1.2655`，并且 `sign` 的值变为 `-1`。

**用户或编程常见的使用错误:**

1. **传递非正整数给 `lgamma_r`:** Gamma 函数在非正整数处未定义（或趋于无穷大）。虽然 `lgamma_r` 会返回一个很大的值或处理特殊情况，但这通常是编程错误。

   ```c
   #include <math.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       int sign;
       double result = lgamma_r(-2, &sign);
       if (errno == EDOM) {
           perror("lgamma_r"); // 输出 "lgamma_r: Domain error"
       }
       printf("lgamma_r(-2) = %f, sign = %d\n", result, sign); // 结果可能是 inf
       return 0;
   }
   ```

2. **忽略 `signgamp` 的值:** 如果程序的逻辑依赖于 Gamma 函数的符号，但程序员没有检查 `signgamp` 的值，可能会导致错误的结果。

3. **精度问题:**  虽然 `lgamma_r` 的实现力求高精度，但在极端情况下，浮点数的精度限制可能会导致误差。

4. **不处理 NaN 输入:** 如果输入 `x` 是 NaN (Not a Number)，`lgamma_r` 会返回 NaN，程序应该适当地处理这种情况。

**Android Framework 或 NDK 如何一步步到达这里 (作为调试线索):**

1. **Android Framework (Java 代码):**
   - 假设某个 Android Framework 的 Java 组件需要进行涉及 Gamma 函数的计算。
   - Java 标准库的 `Math` 类没有直接提供 Gamma 函数。

2. **JNI 调用:**
   - Framework 组件会调用一个原生的 (C/C++) 方法，通过 JNI。
   - 这个原生方法会使用 NDK 开发。

3. **NDK C/C++ 代码:**
   - 原生方法中包含了对 `lgamma_r` 的调用。
   - 需要包含 `<math.h>` 头文件。

   ```c++
   #include <jni.h>
   #include <math.h>
   #include <android/log.h>

   #define LOG_TAG "MyGammaLib"
   #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

   extern "C" JNIEXPORT jdouble JNICALL
   Java_com_example_myapp_MyMathUtils_nativeLGamma(JNIEnv *env, jclass clazz, jdouble x) {
       int sign;
       double result = lgamma_r(x, &sign);
       LOGI("lgamma_r(%f) = %f, sign = %d", x, result, sign);
       return result;
   }
   ```

4. **动态链接:**
   - 当包含上述 JNI 代码的 APK 被加载到 Android 设备上时，`libnative-lib.so` (或类似的名称) 会被加载。
   - 这个共享库依赖于 `libc.so`，其中包含了 `lgamma_r` 的实现。
   - Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会解析 `libnative-lib.so` 中对 `lgamma_r` 的未定义引用，并将其链接到 `libc.so` 中 `lgamma_r` 的实际地址。

5. **执行 `lgamma_r`:**
   - 当 Java 代码调用 `nativeLGamma` 方法时，JNI 调用会进入原生代码。
   - 原生代码执行到 `lgamma_r(x, &sign)` 时，实际上会跳转到 `bionic/libm/upstream-freebsd/lib/msun/src/e_lgamma_r.c` 编译生成的机器码。

**调试线索:**

- **崩溃堆栈跟踪 (Crash Backtrace):** 如果在调用 `lgamma_r` 的过程中发生错误（例如，由于输入不当导致了除零错误），崩溃堆栈跟踪可能会显示程序执行到了 `lgamma_r` 函数内部。
- **日志输出:** 在 JNI 代码中添加日志输出可以帮助跟踪参数值和执行流程。
- **使用调试器 (如 GDB 或 LLDB):** 可以附加到正在运行的 Android 进程，并在 `lgamma_r` 函数入口处设置断点，单步执行代码，查看变量值。
- **查看 Bionic 源代码:**  如你提供的文件，阅读 `lgamma_r` 的源代码可以深入理解其行为和可能的边界情况。
- **静态分析工具:**  可以使用静态分析工具来检查潜在的代码缺陷和安全漏洞。

总而言之，`e_lgamma_r.c` 文件是 Android Bionic libc 中一个重要的数学函数实现，它通过精巧的数学方法提供了计算对数 Gamma 函数及其符号的功能，并被 Android 系统和应用广泛使用。理解其实现细节对于调试和优化相关程序至关重要。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_lgamma_r.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/* lgamma_r(x, signgamp)
 * Reentrant version of the logarithm of the Gamma function
 * with user provide pointer for the sign of Gamma(x).
 *
 * Method:
 *   1. Argument Reduction for 0 < x <= 8
 * 	Since gamma(1+s)=s*gamma(s), for x in [0,8], we may
 * 	reduce x to a number in [1.5,2.5] by
 * 		lgamma(1+s) = log(s) + lgamma(s)
 *	for example,
 *		lgamma(7.3) = log(6.3) + lgamma(6.3)
 *			    = log(6.3*5.3) + lgamma(5.3)
 *			    = log(6.3*5.3*4.3*3.3*2.3) + lgamma(2.3)
 *   2. Polynomial approximation of lgamma around its
 *	minimum ymin=1.461632144968362245 to maintain monotonicity.
 *	On [ymin-0.23, ymin+0.27] (i.e., [1.23164,1.73163]), use
 *		Let z = x-ymin;
 *		lgamma(x) = -1.214862905358496078218 + z^2*poly(z)
 *	where
 *		poly(z) is a 14 degree polynomial.
 *   2. Rational approximation in the primary interval [2,3]
 *	We use the following approximation:
 *		s = x-2.0;
 *		lgamma(x) = 0.5*s + s*P(s)/Q(s)
 *	with accuracy
 *		|P/Q - (lgamma(x)-0.5s)| < 2**-61.71
 *	Our algorithms are based on the following observation
 *
 *                             zeta(2)-1    2    zeta(3)-1    3
 * lgamma(2+s) = s*(1-Euler) + --------- * s  -  --------- * s  + ...
 *                                 2                 3
 *
 *	where Euler = 0.5771... is the Euler constant, which is very
 *	close to 0.5.
 *
 *   3. For x>=8, we have
 *	lgamma(x)~(x-0.5)log(x)-x+0.5*log(2pi)+1/(12x)-1/(360x**3)+....
 *	(better formula:
 *	   lgamma(x)~(x-0.5)*(log(x)-1)-.5*(log(2pi)-1) + ...)
 *	Let z = 1/x, then we approximation
 *		f(z) = lgamma(x) - (x-0.5)(log(x)-1)
 *	by
 *	  			    3       5             11
 *		w = w0 + w1*z + w2*z  + w3*z  + ... + w6*z
 *	where
 *		|w - f(z)| < 2**-58.74
 *
 *   4. For negative x, since (G is gamma function)
 *		-x*G(-x)*G(x) = pi/sin(pi*x),
 * 	we have
 * 		G(x) = pi/(sin(pi*x)*(-x)*G(-x))
 *	since G(-x) is positive, sign(G(x)) = sign(sin(pi*x)) for x<0
 *	Hence, for x<0, signgam = sign(sin(pi*x)) and
 *		lgamma(x) = log(|Gamma(x)|)
 *			  = log(pi/(|x*sin(pi*x)|)) - lgamma(-x);
 *	Note: one should avoid compute pi*(-x) directly in the
 *	      computation of sin(pi*(-x)).
 *
 *   5. Special Cases
 *		lgamma(2+s) ~ s*(1-Euler) for tiny s
 *		lgamma(1) = lgamma(2) = 0
 *		lgamma(x) ~ -log(|x|) for tiny x
 *		lgamma(0) = lgamma(neg.integer) = inf and raise divide-by-zero
 *		lgamma(inf) = inf
 *		lgamma(-inf) = inf (bug for bug compatible with C99!?)
 */

#include <float.h>

#include "math.h"
#include "math_private.h"

static const volatile double vzero = 0;

static const double
zero=  0.00000000000000000000e+00,
half=  5.00000000000000000000e-01, /* 0x3FE00000, 0x00000000 */
one =  1.00000000000000000000e+00, /* 0x3FF00000, 0x00000000 */
pi  =  3.14159265358979311600e+00, /* 0x400921FB, 0x54442D18 */
a0  =  7.72156649015328655494e-02, /* 0x3FB3C467, 0xE37DB0C8 */
a1  =  3.22467033424113591611e-01, /* 0x3FD4A34C, 0xC4A60FAD */
a2  =  6.73523010531292681824e-02, /* 0x3FB13E00, 0x1A5562A7 */
a3  =  2.05808084325167332806e-02, /* 0x3F951322, 0xAC92547B */
a4  =  7.38555086081402883957e-03, /* 0x3F7E404F, 0xB68FEFE8 */
a5  =  2.89051383673415629091e-03, /* 0x3F67ADD8, 0xCCB7926B */
a6  =  1.19270763183362067845e-03, /* 0x3F538A94, 0x116F3F5D */
a7  =  5.10069792153511336608e-04, /* 0x3F40B6C6, 0x89B99C00 */
a8  =  2.20862790713908385557e-04, /* 0x3F2CF2EC, 0xED10E54D */
a9  =  1.08011567247583939954e-04, /* 0x3F1C5088, 0x987DFB07 */
a10 =  2.52144565451257326939e-05, /* 0x3EFA7074, 0x428CFA52 */
a11 =  4.48640949618915160150e-05, /* 0x3F07858E, 0x90A45837 */
tc  =  1.46163214496836224576e+00, /* 0x3FF762D8, 0x6356BE3F */
tf  = -1.21486290535849611461e-01, /* 0xBFBF19B9, 0xBCC38A42 */
/* tt = -(tail of tf) */
tt  = -3.63867699703950536541e-18, /* 0xBC50C7CA, 0xA48A971F */
t0  =  4.83836122723810047042e-01, /* 0x3FDEF72B, 0xC8EE38A2 */
t1  = -1.47587722994593911752e-01, /* 0xBFC2E427, 0x8DC6C509 */
t2  =  6.46249402391333854778e-02, /* 0x3FB08B42, 0x94D5419B */
t3  = -3.27885410759859649565e-02, /* 0xBFA0C9A8, 0xDF35B713 */
t4  =  1.79706750811820387126e-02, /* 0x3F9266E7, 0x970AF9EC */
t5  = -1.03142241298341437450e-02, /* 0xBF851F9F, 0xBA91EC6A */
t6  =  6.10053870246291332635e-03, /* 0x3F78FCE0, 0xE370E344 */
t7  = -3.68452016781138256760e-03, /* 0xBF6E2EFF, 0xB3E914D7 */
t8  =  2.25964780900612472250e-03, /* 0x3F6282D3, 0x2E15C915 */
t9  = -1.40346469989232843813e-03, /* 0xBF56FE8E, 0xBF2D1AF1 */
t10 =  8.81081882437654011382e-04, /* 0x3F4CDF0C, 0xEF61A8E9 */
t11 = -5.38595305356740546715e-04, /* 0xBF41A610, 0x9C73E0EC */
t12 =  3.15632070903625950361e-04, /* 0x3F34AF6D, 0x6C0EBBF7 */
t13 = -3.12754168375120860518e-04, /* 0xBF347F24, 0xECC38C38 */
t14 =  3.35529192635519073543e-04, /* 0x3F35FD3E, 0xE8C2D3F4 */
u0  = -7.72156649015328655494e-02, /* 0xBFB3C467, 0xE37DB0C8 */
u1  =  6.32827064025093366517e-01, /* 0x3FE4401E, 0x8B005DFF */
u2  =  1.45492250137234768737e+00, /* 0x3FF7475C, 0xD119BD6F */
u3  =  9.77717527963372745603e-01, /* 0x3FEF4976, 0x44EA8450 */
u4  =  2.28963728064692451092e-01, /* 0x3FCD4EAE, 0xF6010924 */
u5  =  1.33810918536787660377e-02, /* 0x3F8B678B, 0xBF2BAB09 */
v1  =  2.45597793713041134822e+00, /* 0x4003A5D7, 0xC2BD619C */
v2  =  2.12848976379893395361e+00, /* 0x40010725, 0xA42B18F5 */
v3  =  7.69285150456672783825e-01, /* 0x3FE89DFB, 0xE45050AF */
v4  =  1.04222645593369134254e-01, /* 0x3FBAAE55, 0xD6537C88 */
v5  =  3.21709242282423911810e-03, /* 0x3F6A5ABB, 0x57D0CF61 */
s0  = -7.72156649015328655494e-02, /* 0xBFB3C467, 0xE37DB0C8 */
s1  =  2.14982415960608852501e-01, /* 0x3FCB848B, 0x36E20878 */
s2  =  3.25778796408930981787e-01, /* 0x3FD4D98F, 0x4F139F59 */
s3  =  1.46350472652464452805e-01, /* 0x3FC2BB9C, 0xBEE5F2F7 */
s4  =  2.66422703033638609560e-02, /* 0x3F9B481C, 0x7E939961 */
s5  =  1.84028451407337715652e-03, /* 0x3F5E26B6, 0x7368F239 */
s6  =  3.19475326584100867617e-05, /* 0x3F00BFEC, 0xDD17E945 */
r1  =  1.39200533467621045958e+00, /* 0x3FF645A7, 0x62C4AB74 */
r2  =  7.21935547567138069525e-01, /* 0x3FE71A18, 0x93D3DCDC */
r3  =  1.71933865632803078993e-01, /* 0x3FC601ED, 0xCCFBDF27 */
r4  =  1.86459191715652901344e-02, /* 0x3F9317EA, 0x742ED475 */
r5  =  7.77942496381893596434e-04, /* 0x3F497DDA, 0xCA41A95B */
r6  =  7.32668430744625636189e-06, /* 0x3EDEBAF7, 0xA5B38140 */
w0  =  4.18938533204672725052e-01, /* 0x3FDACFE3, 0x90C97D69 */
w1  =  8.33333333333329678849e-02, /* 0x3FB55555, 0x5555553B */
w2  = -2.77777777728775536470e-03, /* 0xBF66C16C, 0x16B02E5C */
w3  =  7.93650558643019558500e-04, /* 0x3F4A019F, 0x98CF38B6 */
w4  = -5.95187557450339963135e-04, /* 0xBF4380CB, 0x8C0FE741 */
w5  =  8.36339918996282139126e-04, /* 0x3F4B67BA, 0x4CDAD5D1 */
w6  = -1.63092934096575273989e-03; /* 0xBF5AB89D, 0x0B9E43E4 */

/*
 * Compute sin(pi*x) without actually doing the pi*x multiplication.
 * sin_pi(x) is only called for x < 0 and |x| < 2**(p-1) where p is
 * the precision of x.
 */
static double
sin_pi(double x)
{
	volatile double vz;
	double y,z;
	int n;

	y = -x;

	vz = y+0x1p52;			/* depend on 0 <= y < 0x1p52 */
	z = vz-0x1p52;			/* rint(y) for the above range */
	if (z == y)
	    return zero;

	vz = y+0x1p50;
	GET_LOW_WORD(n,vz);		/* bits for rounded y (units 0.25) */
	z = vz-0x1p50;			/* y rounded to a multiple of 0.25 */
	if (z > y) {
	    z -= 0.25;			/* adjust to round down */
	    n--;
	}
	n &= 7;				/* octant of y mod 2 */
	y = y - z + n * 0.25;		/* y mod 2 */

	switch (n) {
	    case 0:   y =  __kernel_sin(pi*y,zero,0); break;
	    case 1:
	    case 2:   y =  __kernel_cos(pi*(0.5-y),zero); break;
	    case 3:
	    case 4:   y =  __kernel_sin(pi*(one-y),zero,0); break;
	    case 5:
	    case 6:   y = -__kernel_cos(pi*(y-1.5),zero); break;
	    default:  y =  __kernel_sin(pi*(y-2.0),zero,0); break;
	    }
	return -y;
}


double
lgamma_r(double x, int *signgamp)
{
	double nadj,p,p1,p2,p3,q,r,t,w,y,z;
	int32_t hx;
	int i,ix,lx;

	EXTRACT_WORDS(hx,lx,x);

    /* purge +-Inf and NaNs */
	*signgamp = 1;
	ix = hx&0x7fffffff;
	if(ix>=0x7ff00000) return x*x;

    /* purge +-0 and tiny arguments */
	*signgamp = 1-2*((uint32_t)hx>>31);
	if(ix<0x3c700000) {	/* |x|<2**-56, return -log(|x|) */
	    if((ix|lx)==0)
	        return one/vzero;
	    return -log(fabs(x));
	}

    /* purge negative integers and start evaluation for other x < 0 */
	if(hx<0) {
	    *signgamp = 1;
	    if(ix>=0x43300000) 	/* |x|>=2**52, must be -integer */
		return one/vzero;
	    t = sin_pi(x);
	    if(t==zero) return one/vzero; /* -integer */
	    nadj = log(pi/fabs(t*x));
	    if(t<zero) *signgamp = -1;
	    x = -x;
	}

    /* purge 1 and 2 */
	if((((ix-0x3ff00000)|lx)==0)||(((ix-0x40000000)|lx)==0)) r = 0;
    /* for x < 2.0 */
	else if(ix<0x40000000) {
	    if(ix<=0x3feccccc) { 	/* lgamma(x) = lgamma(x+1)-log(x) */
		r = -log(x);
		if(ix>=0x3FE76944) {y = one-x; i= 0;}
		else if(ix>=0x3FCDA661) {y= x-(tc-one); i=1;}
	  	else {y = x; i=2;}
	    } else {
	  	r = zero;
	        if(ix>=0x3FFBB4C3) {y=2.0-x;i=0;} /* [1.7316,2] */
	        else if(ix>=0x3FF3B4C4) {y=x-tc;i=1;} /* [1.23,1.73] */
		else {y=x-one;i=2;}
	    }
	    switch(i) {
	      case 0:
		z = y*y;
		p1 = a0+z*(a2+z*(a4+z*(a6+z*(a8+z*a10))));
		p2 = z*(a1+z*(a3+z*(a5+z*(a7+z*(a9+z*a11)))));
		p  = y*p1+p2;
		r  += p-y/2; break;
	      case 1:
		z = y*y;
		w = z*y;
		p1 = t0+w*(t3+w*(t6+w*(t9 +w*t12)));	/* parallel comp */
		p2 = t1+w*(t4+w*(t7+w*(t10+w*t13)));
		p3 = t2+w*(t5+w*(t8+w*(t11+w*t14)));
		p  = z*p1-(tt-w*(p2+y*p3));
		r += tf + p; break;
	      case 2:
		p1 = y*(u0+y*(u1+y*(u2+y*(u3+y*(u4+y*u5)))));
		p2 = one+y*(v1+y*(v2+y*(v3+y*(v4+y*v5))));
		r += p1/p2-y/2;
	    }
	}
    /* x < 8.0 */
	else if(ix<0x40200000) {
	    i = x;
	    y = x-i;
	    p = y*(s0+y*(s1+y*(s2+y*(s3+y*(s4+y*(s5+y*s6))))));
	    q = one+y*(r1+y*(r2+y*(r3+y*(r4+y*(r5+y*r6)))));
	    r = y/2+p/q;
	    z = one;	/* lgamma(1+s) = log(s) + lgamma(s) */
	    switch(i) {
	    case 7: z *= (y+6);		/* FALLTHRU */
	    case 6: z *= (y+5);		/* FALLTHRU */
	    case 5: z *= (y+4);		/* FALLTHRU */
	    case 4: z *= (y+3);		/* FALLTHRU */
	    case 3: z *= (y+2);		/* FALLTHRU */
		    r += log(z); break;
	    }
    /* 8.0 <= x < 2**56 */
	} else if (ix < 0x43700000) {
	    t = log(x);
	    z = one/x;
	    y = z*z;
	    w = w0+z*(w1+y*(w2+y*(w3+y*(w4+y*(w5+y*w6)))));
	    r = (x-half)*(t-one)+w;
	} else
    /* 2**56 <= x <= inf */
	    r =  x*(log(x)-one);
	if(hx<0) r = nadj - r;
	return r;
}

#if (LDBL_MANT_DIG == 53)
__weak_reference(lgamma_r, lgammal_r);
#endif
```
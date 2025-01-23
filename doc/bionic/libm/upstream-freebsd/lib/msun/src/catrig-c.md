Response:
Let's break down the thought process for analyzing this `catrig.c` file. The goal is to understand its purpose, functionality, and connections within the Android ecosystem.

**1. Initial Understanding & Context:**

* **File Path:** `bionic/libm/upstream-freebsd/lib/msun/src/catrig.c` tells us several crucial things:
    * `bionic`: This immediately points to the Android C library.
    * `libm`:  This signifies that it's part of the math library.
    * `upstream-freebsd`:  This is a massive clue! It means the code is derived from the FreeBSD operating system's math library. This is important because it suggests a focus on correctness and standard compliance. Android often takes components from well-established open-source projects.
    * `lib/msun/src/`: Further pinpoints it as a source file within the math software unit (`msun`).
    * `catrig.c`: The `catrig` likely refers to complex arc trigonometric functions (the "c" for complex).

* **License:** The BSD-2-Clause license confirms it's open-source and gives us information about its redistribution terms.

* **Copyright:** The copyright notice further confirms the origin from FreeBSD.

* **Includes:**  `<complex.h>`, `<float.h>`, `"math.h"`, `"math_private.h"` are standard math-related headers. `complex.h` confirms the file deals with complex numbers. `math_private.h` suggests internal, non-public math functions and definitions.

**2. Identifying Core Functionality:**

* **Function Prototypes:**  Looking at the function names (`casinh`, `casin`, `cacos`, `cacosh`, `catanh`, `catan`) immediately reveals the primary purpose: implementing the complex inverse hyperbolic and trigonometric functions.

* **Comments:** The extensive comments are invaluable. They explain:
    * The accuracy goals (4 ULP).
    * Performance considerations.
    * The reliance on the Hull et al. paper for `casinh`, `casin`, `cacos`, and `cacosh`. This highlights a sophisticated algorithm.
    * The handling of edge cases (near zero, infinity, NaN).
    * Specific numerical stability techniques.

**3. Deeper Dive into Implementation Details:**

* **Constants:**  The static constants (`A_crossover`, `B_crossover`, `FOUR_SQRT_MIN`, etc.) are critical for the numerical stability algorithms. The comments often explain their purpose. For example, the crossover points are used to switch between different calculation methods based on input values to avoid precision issues.

* **`f(double a, double b, double hypot_a_b)`:** This helper function is a key optimization and numerical stability trick. The comments within `do_hard_work` explain how it helps avoid underflow and overflow.

* **`do_hard_work(...)`:**  This function appears to be the core numerical engine for calculating the real and imaginary parts of the complex inverse hyperbolic/trigonometric functions. The comments detail the formulas and the conditions under which different calculation paths are taken. The rescaling of `sqrt_A2my2` and `new_y` is a strong indication of underflow prevention.

* **`clog_for_large_values(double complex z)`:**  This function shows how logarithms of large complex numbers are handled, specifically addressing potential overflow issues in `hypot`.

* **`sum_squares(double x, double y)`:** A simple but important helper to avoid underflow when calculating the sum of squares.

* **`real_part_reciprocal(double x, double y)`:**  Another numerical stability function to calculate the real part of a complex reciprocal without unnecessary underflow. The reference to C99 n1124.pdf reinforces the focus on standards compliance.

**4. Connecting to Android:**

* **`bionic` Context:**  The file's location within `bionic` makes the connection to Android explicit. These functions are part of the standard C math library available to Android apps and the Android framework.

* **NDK Usage:** Android NDK developers can directly use these functions by including `<complex.h>` and `<math.h>`.

* **Framework Usage:**  The Android Framework, written in Java/Kotlin, relies on native code for performance-critical operations. These math functions are available to the Framework through JNI (Java Native Interface) calls into `libm.so`.

**5. Dynamic Linking Aspects:**

* **`__weak_reference`:**  The presence of `__weak_reference` signifies dynamic linking. It allows the system to provide optimized versions (e.g., `cacoshl` for `long double`) if they are available, but the program won't fail if they are not. This is a common optimization technique in shared libraries.

* **`libm.so`:** The functions in `catrig.c` will be compiled into the `libm.so` shared library.

* **Linking Process:** The dynamic linker resolves symbols (like `casinh`) when an application or library using these functions is loaded.

**6. Anticipating Common Errors and Providing Frida Hooks:**

* **Common Errors:** Thinking about how developers might misuse these functions leads to examples like passing NaN or infinity, or expecting perfect precision when dealing with floating-point numbers.

* **Frida Hooks:**  Frida is a powerful tool for runtime inspection. Creating hook examples for `casinh` allows developers to trace calls, inspect arguments, and examine return values, aiding in debugging and understanding the function's behavior.

**7. Structuring the Response:**

The final step is to organize the information logically and clearly:

* **Overview of Functionality:** Start with a high-level summary of what the file does.
* **Detailed Function Explanation:** Go through each function, explaining its purpose, algorithm (especially for the complex ones), and numerical stability techniques.
* **Android Integration:** Explain how these functions are used within the Android ecosystem.
* **Dynamic Linking:** Discuss the shared library, linking process, and the role of `__weak_reference`.
* **Logic Inference:** Provide examples with hypothetical inputs and outputs to illustrate the functions' behavior.
* **Common Errors:**  Point out potential pitfalls for developers.
* **Android Framework/NDK Path:** Describe how a call might reach these functions from the Android layers.
* **Frida Hooks:**  Provide practical examples for debugging.

**Self-Correction/Refinement during the Thought Process:**

* **Initially, I might focus too much on the mathematical formulas.**  It's important to also consider the *engineering* aspects: numerical stability, performance, and how it fits into the Android system.
* **The `upstream-freebsd` clue is key.**  It saves time from having to reverse-engineer the complex math algorithms entirely. Knowing the origin allows focusing on the Android-specific integration aspects.
* **Pay close attention to the comments.** They provide invaluable insights into the design decisions.
* **Think like a developer using these functions.** What problems might they encounter? How can they debug them? This helps in generating relevant examples and the Frida hook.

By following this structured approach and paying attention to the clues within the code and its context, a comprehensive and accurate analysis can be achieved.
好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/catrig.c` 这个文件。

**文件功能概述**

`catrig.c` 文件实现了复数的反三角函数和反双曲函数，包括：

* **复数反双曲正弦 (casinh):**  计算一个复数的反双曲正弦值。
* **复数反双曲余弦 (cacosh):** 计算一个复数的反双曲余弦值。
* **复数反双曲正切 (catanh):** 计算一个复数的反双曲正切值。
* **复数反正弦 (casin):**  计算一个复数的反正弦值。
* **复数反余弦 (cacos):**  计算一个复数的反余弦值。
* **复数反正切 (catan):**  计算一个复数的反正切值。

这些函数是标准 C 库中 `<complex.h>` 头文件提供的对应函数的实现。由于 Android 的 `bionic` 库直接或间接地使用了来自 FreeBSD 的 `libm` 库，因此这些实现源自 FreeBSD 的 `msun` (math software unit)。

**与 Android 功能的关系及举例**

这些复数反三角和反双曲函数是基础的数学运算，虽然在日常 Android 应用开发中可能不常用，但在某些特定的领域或底层库中扮演着重要角色。

**举例说明:**

1. **图形图像处理:** 某些复杂的图形变换或滤镜算法可能会涉及到复数运算，例如傅里叶变换的复数形式。虽然开发者通常使用更高级的图像处理库，但这些库底层可能就依赖于 `libm` 提供的复数运算功能。
2. **信号处理:** 在音频或无线通信等信号处理领域，复数被广泛用于表示信号的幅度和相位。计算信号的某些特性可能需要用到这些反函数。例如，计算阻抗匹配网络可能需要求解复数方程。
3. **科学计算和工程应用:**  如果 Android 设备被用于科学研究或工程应用，例如进行物理模拟、电路分析等，这些复数函数可能是必要的工具。通过 NDK 开发，开发者可以直接使用这些函数进行高性能的计算。
4. **游戏开发:**  某些高级游戏可能会使用复数来表示旋转、缩放等变换，或者在物理引擎中处理复杂的碰撞和运动。

**libc 函数的实现细节**

这个文件中的每个函数都采用了复杂的数值计算方法来保证精度和处理各种边界情况，例如输入为无穷大、NaN (非数字) 或接近零的情况。

**通用实现策略：**

* **公式转换和数值稳定性:**  直接使用反函数的定义公式进行计算可能会导致数值不稳定，特别是当输入值处于某些特殊范围时。因此，代码中会根据输入值的范围选择不同的计算公式或技巧，例如使用 `log1p(x)` 来精确计算 `log(1+x)` 当 `x` 接近零时。
* **处理特殊值:**  对于输入为 `NaN` 或无穷大的情况，代码会根据 C 标准的规定返回特定的结果。
* **避免溢出和下溢:**  中间计算结果可能超出浮点数的表示范围，代码中会采用一些技巧来避免这种情况，例如对中间结果进行缩放。
* **使用辅助函数:**  为了代码的清晰和可维护性，一些通用的计算逻辑会被封装成辅助函数，例如 `f(double a, double b, double hypot_a_b)` 用于计算 `(hypot(a, b) - b) / 2`，这在 `casinh`, `casin`, `cacos`, `cacosh` 的实现中被大量使用。
* **利用已知数学恒等式:**  例如，`casin(z)` 的实现就利用了 `casin(z) = reverse(casinh(reverse(z)))` 的关系，其中 `reverse(x + I*y) = y + I*x`。

**具体函数实现分析 (选取几个关键函数):**

* **`casinh(double complex z)`:**  这个函数的实现最为复杂，因为它需要处理多种不同的输入情况以保证数值稳定。它采用了 Hull et al. 在他们的论文 "Implementing the complex arcsine and arccosine functions using exception handling" 中提出的算法。核心思想是根据 `z` 的实部和虚部的绝对值大小，选择不同的公式来计算反双曲正弦的实部和虚部。例如，当 `A` 值小于某个阈值 `A_crossover` 时，使用 `log1p` 来计算对数，避免精度损失。当 `B` 值大于某个阈值 `B_crossover` 时，使用 `atan2` 来计算反正弦。

* **`f(double a, double b, double hypot_a_b)`:** 这个内联函数用于计算 `(hypot(a, b) - b) / 2`。它通过不同的分支处理 `b` 的符号来避免数值问题。当 `b < 0` 时，直接计算；当 `b == 0` 时，返回 `a / 2`；当 `b > 0` 时，使用 `a * a / (hypot_a_b + b) / 2`，这在数值上更稳定。

* **`clog_for_large_values(double complex z)`:**  这是一个优化版本的复数对数函数 `clog()`，专门用于处理模很大的复数。直接计算 `log(hypot(x, y))` 当 `x` 和 `y` 都很大时可能导致溢出。这个函数通过将 `x` 和 `y` 除以 `m_e` (自然常数 e) 来避免溢出，并在最后的结果中加上 1。

* **`catanh(double complex z)`:**  这个函数的实现相对简单一些，使用了 `catanh(z) = log((1+z)/(1-z)) / 2` 的定义。为了数值稳定，它也针对输入值的范围采用了不同的计算方法，例如当 `ax` 接近 1 且 `ay` 很小时，使用特定的公式来计算实部。

**涉及 dynamic linker 的功能**

在这个文件中，涉及 dynamic linker 的功能主要是通过 `__weak_reference` 宏来实现的。

* **`__weak_reference(cacosh, cacoshl);` 等宏:**  这些宏定义了弱引用。这意味着如果系统中存在 `cacoshl` (计算 `long double complex` 类型的反双曲余弦函数) 的实现，那么程序会优先链接到它。如果不存在，程序会链接到 `cacosh` (计算 `double complex` 类型)。

**so 布局样本:**

假设编译后的 `libm.so` 文件布局如下（简化）：

```
libm.so:
    ...
    .text:
        casinh:  <casinh 函数的机器码>
        cacosh:  <cacosh 函数的机器码>
        catanh:  <catanh 函数的机器码>
        casin:   <casin 函数的机器码>
        cacos:   <cacos 函数的机器码>
        catan:   <catan 函数的机器码>
        cacoshl: <cacoshl 函数的机器码>  (可能存在，也可能不存在)
        ...
    .data:
        A_crossover: <A_crossover 的值>
        B_crossover: <B_crossover 的值>
        ...
    ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译使用了复数反三角/反双曲函数的代码时，会生成对这些函数的符号引用（例如 `casinh`）。
2. **链接时 (静态链接，不常见于 Android 的动态库):** 链接器会将这些符号引用解析到 `libm.a` (静态库) 中对应的函数地址。
3. **运行时 (动态链接):**
   - 当一个应用程序或共享库加载时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析其依赖的共享库。
   - 如果程序中调用了 `cacosh`，动态链接器会在 `libm.so` 的符号表 (symbol table) 中查找 `cacosh` 的地址，并将其填入程序的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table)。
   - **对于弱引用:**  如果系统中存在 `cacoshl`，动态链接器会找到它的地址并使用它。如果 `cacoshl` 不存在，动态链接器会使用 `cacosh` 的地址。这允许在提供更高精度版本时进行优化，而不会导致程序在缺少 `cacoshl` 时无法运行。

**逻辑推理和假设输入与输出**

由于这些是标准的数学函数，它们的行为是有明确定义的。

**假设输入与输出示例 (以 `casinh` 为例):**

* **假设输入:** `z = 0.0 + 0.0i`
* **预期输出:** `casinh(z) = 0.0 + 0.0i` (反双曲正弦在 0 点的值为 0)

* **假设输入:** `z = 1.0 + 0.0i`
* **预期输出:** `casinh(z)` 的实部为 `asinh(1.0)`，虚部为 `0.0`。`asinh(1.0) = ln(1 + sqrt(2))`。

* **假设输入:** `z = 0.0 + 1.0i`
* **预期输出:** `casinh(z)` 的实部为 `0.0`，虚部为 `asin(1.0) = pi/2`。

* **假设输入:** `z = NaN + 0.0i`
* **预期输出:** `casinh(z) = NaN + 0.0i` (根据 C 标准，涉及 NaN 的运算通常返回 NaN)

* **假设输入:** `z = Infinity + 0.0i`
* **预期输出:** `casinh(z) = Infinity + 0.0i`

**用户或编程常见的使用错误**

1. **误解定义域:**  复数反三角和反双曲函数的定义域是整个复平面，但用户可能不清楚其取值范围（主值）。
2. **精度问题:**  浮点数运算存在精度限制，用户可能期望得到无限精确的结果。
3. **处理 NaN:**  不正确地处理输入为 NaN 的情况，可能导致程序逻辑错误。
4. **性能问题:**  在性能敏感的应用中，频繁调用这些复杂的数学函数可能会带来性能开销。
5. **忘记包含头文件:**  使用这些函数需要包含 `<complex.h>` 和 `<math.h>`。

**举例说明常见错误:**

```c
#include <stdio.h>
#include <complex.h>
#include <math.h>

int main() {
    double complex z = asin(2.0); // 错误: 反正弦的定义域是 [-1, 1]
    printf("asin(2.0) = %f + %fi\n", creal(z), cimag(z));

    double complex w = casinh(NAN + 0.0i);
    if (isnan(creal(w))) {
        printf("Input was NaN, result is NaN.\n");
    } else {
        printf("Result is not NaN, something is wrong.\n");
    }
    return 0;
}
```

**Android Framework 或 NDK 如何到达这里**

**Android Framework 路径:**

1. **Java/Kotlin 代码调用:**  Android Framework 中的某些组件 (例如，处理动画、图形效果的组件) 可能会在底层使用 native 代码进行复杂的数学计算。
2. **JNI 调用:**  Java/Kotlin 代码通过 JNI (Java Native Interface) 调用到对应的 C/C++ 代码。
3. **Native 代码调用 `libm` 函数:**  这些 native 代码会链接到 `libm.so`，并调用 `casinh` 等函数。

**Android NDK 路径:**

1. **NDK 开发:**  使用 Android NDK 进行开发的 C/C++ 代码可以直接包含 `<complex.h>` 和 `<math.h>`。
2. **直接调用 `libm` 函数:**  NDK 代码中可以直接调用 `casinh`, `cacos` 等函数，链接器会在编译和链接时处理对 `libm.so` 的依赖。

**Frida Hook 示例作为调试线索**

可以使用 Frida 来 hook 这些函数，以便在运行时观察它们的输入和输出，这对于调试和理解其行为非常有帮助。

**Frida Hook `casinh` 的示例:**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libm.so");
  const casinhPtr = libc.getExportByName("casinh");

  if (casinhPtr) {
    Interceptor.attach(casinhPtr, {
      onEnter: function (args) {
        const z = {
          real: args[0].readDouble(),
          imag: args[1].readDouble()
        };
        console.log("Called casinh with z =", z);
      },
      onLeave: function (retval) {
        const result = {
          real: retval.readDouble(),
          imag: retval.add(8).readDouble()
        };
        console.log("casinh returned =", result);
      }
    });
    console.log("Successfully hooked casinh");
  } else {
    console.log("Failed to find casinh in libm.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**解释 Frida Hook 代码:**

1. **检查平台:** 确保脚本在 Android 平台上运行。
2. **获取 `libm.so` 模块:** 使用 `Process.getModuleByName("libm.so")` 获取 `libm.so` 模块的句柄。
3. **获取 `casinh` 函数地址:** 使用 `libc.getExportByName("casinh")` 获取 `casinh` 函数的地址。
4. **附加 Interceptor:**
   - `onEnter`: 在 `casinh` 函数被调用之前执行。读取函数的参数 (复数的实部和虚部) 并打印到控制台。
   - `onLeave`: 在 `casinh` 函数执行完毕后执行。读取函数的返回值 (复数的实部和虚部) 并打印到控制台。注意复数返回值通常是两个连续的 double 值。
5. **错误处理:** 检查是否成功找到并 hook 了 `casinh` 函数。

通过这个 Frida hook，你可以在 Android 设备上运行目标应用，观察每次调用 `casinh` 时的输入复数和输出复数，从而更好地理解其行为。可以类似地 hook 其他复数反三角/反双曲函数。

希望这个详细的分析能够帮助你理解 `bionic/libm/upstream-freebsd/lib/msun/src/catrig.c` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/catrig.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例作为调试线索。
用中文回复。
```

### 源代码
```c
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2012 Stephen Montgomery-Smith <stephen@FreeBSD.ORG>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <complex.h>
#include <float.h>

#include "math.h"
#include "math_private.h"

#undef isinf
#define isinf(x)	(fabs(x) == INFINITY)
#undef isnan
#define isnan(x)	((x) != (x))
#define	raise_inexact()	do { volatile float junk __unused = 1 + tiny; } while(0)
#undef signbit
#define signbit(x)	(__builtin_signbit(x))

/* We need that DBL_EPSILON^2/128 is larger than FOUR_SQRT_MIN. */
static const double
A_crossover =		10, /* Hull et al suggest 1.5, but 10 works better */
B_crossover =		0.6417,			/* suggested by Hull et al */
FOUR_SQRT_MIN =		0x1p-509,		/* >= 4 * sqrt(DBL_MIN) */
QUARTER_SQRT_MAX =	0x1p509,		/* <= sqrt(DBL_MAX) / 4 */
m_e =			2.7182818284590452e0,	/*  0x15bf0a8b145769.0p-51 */
m_ln2 =			6.9314718055994531e-1,	/*  0x162e42fefa39ef.0p-53 */
pio2_hi =		1.5707963267948966e0,	/*  0x1921fb54442d18.0p-52 */
RECIP_EPSILON =		1 / DBL_EPSILON,
SQRT_3_EPSILON =	2.5809568279517849e-8,	/*  0x1bb67ae8584caa.0p-78 */
SQRT_6_EPSILON =	3.6500241499888571e-8,	/*  0x13988e1409212e.0p-77 */
SQRT_MIN =		0x1p-511;		/* >= sqrt(DBL_MIN) */

static const volatile double
pio2_lo =		6.1232339957367659e-17;	/*  0x11a62633145c07.0p-106 */
static const volatile float
tiny =			0x1p-100; 

static double complex clog_for_large_values(double complex z);

/*
 * Testing indicates that all these functions are accurate up to 4 ULP.
 * The functions casin(h) and cacos(h) are about 2.5 times slower than asinh.
 * The functions catan(h) are a little under 2 times slower than atanh.
 *
 * The code for casinh, casin, cacos, and cacosh comes first.  The code is
 * rather complicated, and the four functions are highly interdependent.
 *
 * The code for catanh and catan comes at the end.  It is much simpler than
 * the other functions, and the code for these can be disconnected from the
 * rest of the code.
 */

/*
 *			================================
 *			| casinh, casin, cacos, cacosh |
 *			================================
 */

/*
 * The algorithm is very close to that in "Implementing the complex arcsine
 * and arccosine functions using exception handling" by T. E. Hull, Thomas F.
 * Fairgrieve, and Ping Tak Peter Tang, published in ACM Transactions on
 * Mathematical Software, Volume 23 Issue 3, 1997, Pages 299-335,
 * http://dl.acm.org/citation.cfm?id=275324.
 *
 * Throughout we use the convention z = x + I*y.
 *
 * casinh(z) = sign(x)*log(A+sqrt(A*A-1)) + I*asin(B)
 * where
 * A = (|z+I| + |z-I|) / 2
 * B = (|z+I| - |z-I|) / 2 = y/A
 *
 * These formulas become numerically unstable:
 *   (a) for Re(casinh(z)) when z is close to the line segment [-I, I] (that
 *       is, Re(casinh(z)) is close to 0);
 *   (b) for Im(casinh(z)) when z is close to either of the intervals
 *       [I, I*infinity) or (-I*infinity, -I] (that is, |Im(casinh(z))| is
 *       close to PI/2).
 *
 * These numerical problems are overcome by defining
 * f(a, b) = (hypot(a, b) - b) / 2 = a*a / (hypot(a, b) + b) / 2
 * Then if A < A_crossover, we use
 *   log(A + sqrt(A*A-1)) = log1p((A-1) + sqrt((A-1)*(A+1)))
 *   A-1 = f(x, 1+y) + f(x, 1-y)
 * and if B > B_crossover, we use
 *   asin(B) = atan2(y, sqrt(A*A - y*y)) = atan2(y, sqrt((A+y)*(A-y)))
 *   A-y = f(x, y+1) + f(x, y-1)
 * where without loss of generality we have assumed that x and y are
 * non-negative.
 *
 * Much of the difficulty comes because the intermediate computations may
 * produce overflows or underflows.  This is dealt with in the paper by Hull
 * et al by using exception handling.  We do this by detecting when
 * computations risk underflow or overflow.  The hardest part is handling the
 * underflows when computing f(a, b).
 *
 * Note that the function f(a, b) does not appear explicitly in the paper by
 * Hull et al, but the idea may be found on pages 308 and 309.  Introducing the
 * function f(a, b) allows us to concentrate many of the clever tricks in this
 * paper into one function.
 */

/*
 * Function f(a, b, hypot_a_b) = (hypot(a, b) - b) / 2.
 * Pass hypot(a, b) as the third argument.
 */
static inline double
f(double a, double b, double hypot_a_b)
{
	if (b < 0)
		return ((hypot_a_b - b) / 2);
	if (b == 0)
		return (a / 2);
	return (a * a / (hypot_a_b + b) / 2);
}

/*
 * All the hard work is contained in this function.
 * x and y are assumed positive or zero, and less than RECIP_EPSILON.
 * Upon return:
 * rx = Re(casinh(z)) = -Im(cacos(y + I*x)).
 * B_is_usable is set to 1 if the value of B is usable.
 * If B_is_usable is set to 0, sqrt_A2my2 = sqrt(A*A - y*y), and new_y = y.
 * If returning sqrt_A2my2 has potential to result in an underflow, it is
 * rescaled, and new_y is similarly rescaled.
 */
static inline void
do_hard_work(double x, double y, double *rx, int *B_is_usable, double *B,
    double *sqrt_A2my2, double *new_y)
{
	double R, S, A; /* A, B, R, and S are as in Hull et al. */
	double Am1, Amy; /* A-1, A-y. */

	R = hypot(x, y + 1);		/* |z+I| */
	S = hypot(x, y - 1);		/* |z-I| */

	/* A = (|z+I| + |z-I|) / 2 */
	A = (R + S) / 2;
	/*
	 * Mathematically A >= 1.  There is a small chance that this will not
	 * be so because of rounding errors.  So we will make certain it is
	 * so.
	 */
	if (A < 1)
		A = 1;

	if (A < A_crossover) {
		/*
		 * Am1 = fp + fm, where fp = f(x, 1+y), and fm = f(x, 1-y).
		 * rx = log1p(Am1 + sqrt(Am1*(A+1)))
		 */
		if (y == 1 && x < DBL_EPSILON * DBL_EPSILON / 128) {
			/*
			 * fp is of order x^2, and fm = x/2.
			 * A = 1 (inexactly).
			 */
			*rx = sqrt(x);
		} else if (x >= DBL_EPSILON * fabs(y - 1)) {
			/*
			 * Underflow will not occur because
			 * x >= DBL_EPSILON^2/128 >= FOUR_SQRT_MIN
			 */
			Am1 = f(x, 1 + y, R) + f(x, 1 - y, S);
			*rx = log1p(Am1 + sqrt(Am1 * (A + 1)));
		} else if (y < 1) {
			/*
			 * fp = x*x/(1+y)/4, fm = x*x/(1-y)/4, and
			 * A = 1 (inexactly).
			 */
			*rx = x / sqrt((1 - y) * (1 + y));
		} else {		/* if (y > 1) */
			/*
			 * A-1 = y-1 (inexactly).
			 */
			*rx = log1p((y - 1) + sqrt((y - 1) * (y + 1)));
		}
	} else {
		*rx = log(A + sqrt(A * A - 1));
	}

	*new_y = y;

	if (y < FOUR_SQRT_MIN) {
		/*
		 * Avoid a possible underflow caused by y/A.  For casinh this
		 * would be legitimate, but will be picked up by invoking atan2
		 * later on.  For cacos this would not be legitimate.
		 */
		*B_is_usable = 0;
		*sqrt_A2my2 = A * (2 / DBL_EPSILON);
		*new_y = y * (2 / DBL_EPSILON);
		return;
	}

	/* B = (|z+I| - |z-I|) / 2 = y/A */
	*B = y / A;
	*B_is_usable = 1;

	if (*B > B_crossover) {
		*B_is_usable = 0;
		/*
		 * Amy = fp + fm, where fp = f(x, y+1), and fm = f(x, y-1).
		 * sqrt_A2my2 = sqrt(Amy*(A+y))
		 */
		if (y == 1 && x < DBL_EPSILON / 128) {
			/*
			 * fp is of order x^2, and fm = x/2.
			 * A = 1 (inexactly).
			 */
			*sqrt_A2my2 = sqrt(x) * sqrt((A + y) / 2);
		} else if (x >= DBL_EPSILON * fabs(y - 1)) {
			/*
			 * Underflow will not occur because
			 * x >= DBL_EPSILON/128 >= FOUR_SQRT_MIN
			 * and
			 * x >= DBL_EPSILON^2 >= FOUR_SQRT_MIN
			 */
			Amy = f(x, y + 1, R) + f(x, y - 1, S);
			*sqrt_A2my2 = sqrt(Amy * (A + y));
		} else if (y > 1) {
			/*
			 * fp = x*x/(y+1)/4, fm = x*x/(y-1)/4, and
			 * A = y (inexactly).
			 *
			 * y < RECIP_EPSILON.  So the following
			 * scaling should avoid any underflow problems.
			 */
			*sqrt_A2my2 = x * (4 / DBL_EPSILON / DBL_EPSILON) * y /
			    sqrt((y + 1) * (y - 1));
			*new_y = y * (4 / DBL_EPSILON / DBL_EPSILON);
		} else {		/* if (y < 1) */
			/*
			 * fm = 1-y >= DBL_EPSILON, fp is of order x^2, and
			 * A = 1 (inexactly).
			 */
			*sqrt_A2my2 = sqrt((1 - y) * (1 + y));
		}
	}
}

/*
 * casinh(z) = z + O(z^3)   as z -> 0
 *
 * casinh(z) = sign(x)*clog(sign(x)*z) + O(1/z^2)   as z -> infinity
 * The above formula works for the imaginary part as well, because
 * Im(casinh(z)) = sign(x)*atan2(sign(x)*y, fabs(x)) + O(y/z^3)
 *    as z -> infinity, uniformly in y
 */
double complex
casinh(double complex z)
{
	double x, y, ax, ay, rx, ry, B, sqrt_A2my2, new_y;
	int B_is_usable;
	double complex w;

	x = creal(z);
	y = cimag(z);
	ax = fabs(x);
	ay = fabs(y);

	if (isnan(x) || isnan(y)) {
		/* casinh(+-Inf + I*NaN) = +-Inf + I*NaN */
		if (isinf(x))
			return (CMPLX(x, y + y));
		/* casinh(NaN + I*+-Inf) = opt(+-)Inf + I*NaN */
		if (isinf(y))
			return (CMPLX(y, x + x));
		/* casinh(NaN + I*0) = NaN + I*0 */
		if (y == 0)
			return (CMPLX(x + x, y));
		/*
		 * All other cases involving NaN return NaN + I*NaN.
		 * C99 leaves it optional whether to raise invalid if one of
		 * the arguments is not NaN, so we opt not to raise it.
		 */
		return (CMPLX(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON) {
		/* clog...() will raise inexact unless x or y is infinite. */
		if (signbit(x) == 0)
			w = clog_for_large_values(z) + m_ln2;
		else
			w = clog_for_large_values(-z) + m_ln2;
		return (CMPLX(copysign(creal(w), x), copysign(cimag(w), y)));
	}

	/* Avoid spuriously raising inexact for z = 0. */
	if (x == 0 && y == 0)
		return (z);

	/* All remaining cases are inexact. */
	raise_inexact();

	if (ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4)
		return (z);

	do_hard_work(ax, ay, &rx, &B_is_usable, &B, &sqrt_A2my2, &new_y);
	if (B_is_usable)
		ry = asin(B);
	else
		ry = atan2(new_y, sqrt_A2my2);
	return (CMPLX(copysign(rx, x), copysign(ry, y)));
}

/*
 * casin(z) = reverse(casinh(reverse(z)))
 * where reverse(x + I*y) = y + I*x = I*conj(z).
 */
double complex
casin(double complex z)
{
	double complex w = casinh(CMPLX(cimag(z), creal(z)));

	return (CMPLX(cimag(w), creal(w)));
}

/*
 * cacos(z) = PI/2 - casin(z)
 * but do the computation carefully so cacos(z) is accurate when z is
 * close to 1.
 *
 * cacos(z) = PI/2 - z + O(z^3)   as z -> 0
 *
 * cacos(z) = -sign(y)*I*clog(z) + O(1/z^2)   as z -> infinity
 * The above formula works for the real part as well, because
 * Re(cacos(z)) = atan2(fabs(y), x) + O(y/z^3)
 *    as z -> infinity, uniformly in y
 */
double complex
cacos(double complex z)
{
	double x, y, ax, ay, rx, ry, B, sqrt_A2mx2, new_x;
	int sx, sy;
	int B_is_usable;
	double complex w;

	x = creal(z);
	y = cimag(z);
	sx = signbit(x);
	sy = signbit(y);
	ax = fabs(x);
	ay = fabs(y);

	if (isnan(x) || isnan(y)) {
		/* cacos(+-Inf + I*NaN) = NaN + I*opt(-)Inf */
		if (isinf(x))
			return (CMPLX(y + y, -INFINITY));
		/* cacos(NaN + I*+-Inf) = NaN + I*-+Inf */
		if (isinf(y))
			return (CMPLX(x + x, -y));
		/* cacos(0 + I*NaN) = PI/2 + I*NaN with inexact */
		if (x == 0)
			return (CMPLX(pio2_hi + pio2_lo, y + y));
		/*
		 * All other cases involving NaN return NaN + I*NaN.
		 * C99 leaves it optional whether to raise invalid if one of
		 * the arguments is not NaN, so we opt not to raise it.
		 */
		return (CMPLX(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON) {
		/* clog...() will raise inexact unless x or y is infinite. */
		w = clog_for_large_values(z);
		rx = fabs(cimag(w));
		ry = creal(w) + m_ln2;
		if (sy == 0)
			ry = -ry;
		return (CMPLX(rx, ry));
	}

	/* Avoid spuriously raising inexact for z = 1. */
	if (x == 1 && y == 0)
		return (CMPLX(0, -y));

	/* All remaining cases are inexact. */
	raise_inexact();

	if (ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4)
		return (CMPLX(pio2_hi - (x - pio2_lo), -y));

	do_hard_work(ay, ax, &ry, &B_is_usable, &B, &sqrt_A2mx2, &new_x);
	if (B_is_usable) {
		if (sx == 0)
			rx = acos(B);
		else
			rx = acos(-B);
	} else {
		if (sx == 0)
			rx = atan2(sqrt_A2mx2, new_x);
		else
			rx = atan2(sqrt_A2mx2, -new_x);
	}
	if (sy == 0)
		ry = -ry;
	return (CMPLX(rx, ry));
}

/*
 * cacosh(z) = I*cacos(z) or -I*cacos(z)
 * where the sign is chosen so Re(cacosh(z)) >= 0.
 */
double complex
cacosh(double complex z)
{
	double complex w;
	double rx, ry;

	w = cacos(z);
	rx = creal(w);
	ry = cimag(w);
	/* cacosh(NaN + I*NaN) = NaN + I*NaN */
	if (isnan(rx) && isnan(ry))
		return (CMPLX(ry, rx));
	/* cacosh(NaN + I*+-Inf) = +Inf + I*NaN */
	/* cacosh(+-Inf + I*NaN) = +Inf + I*NaN */
	if (isnan(rx))
		return (CMPLX(fabs(ry), rx));
	/* cacosh(0 + I*NaN) = NaN + I*NaN */
	if (isnan(ry))
		return (CMPLX(ry, ry));
	return (CMPLX(fabs(ry), copysign(rx, cimag(z))));
}

/*
 * Optimized version of clog() for |z| finite and larger than ~RECIP_EPSILON.
 */
static double complex
clog_for_large_values(double complex z)
{
	double x, y;
	double ax, ay, t;

	x = creal(z);
	y = cimag(z);
	ax = fabs(x);
	ay = fabs(y);
	if (ax < ay) {
		t = ax;
		ax = ay;
		ay = t;
	}

	/*
	 * Avoid overflow in hypot() when x and y are both very large.
	 * Divide x and y by E, and then add 1 to the logarithm.  This
	 * depends on E being larger than sqrt(2), since the return value of
	 * hypot cannot overflow if neither argument is greater in magnitude
	 * than 1/sqrt(2) of the maximum value of the return type.  Likewise
	 * this determines the necessary threshold for using this method
	 * (however, actually use 1/2 instead as it is simpler).
	 *
	 * Dividing by E causes an insignificant loss of accuracy; however
	 * this method is still poor since it is uneccessarily slow.
	 */
	if (ax > DBL_MAX / 2)
		return (CMPLX(log(hypot(x / m_e, y / m_e)) + 1, atan2(y, x)));

	/*
	 * Avoid overflow when x or y is large.  Avoid underflow when x or
	 * y is small.
	 */
	if (ax > QUARTER_SQRT_MAX || ay < SQRT_MIN)
		return (CMPLX(log(hypot(x, y)), atan2(y, x)));

	return (CMPLX(log(ax * ax + ay * ay) / 2, atan2(y, x)));
}

/*
 *				=================
 *				| catanh, catan |
 *				=================
 */

/*
 * sum_squares(x,y) = x*x + y*y (or just x*x if y*y would underflow).
 * Assumes x*x and y*y will not overflow.
 * Assumes x and y are finite.
 * Assumes y is non-negative.
 * Assumes fabs(x) >= DBL_EPSILON.
 */
static inline double
sum_squares(double x, double y)
{

	/* Avoid underflow when y is small. */
	if (y < SQRT_MIN)
		return (x * x);

	return (x * x + y * y);
}

/*
 * real_part_reciprocal(x, y) = Re(1/(x+I*y)) = x/(x*x + y*y).
 * Assumes x and y are not NaN, and one of x and y is larger than
 * RECIP_EPSILON.  We avoid unwarranted underflow.  It is important to not use
 * the code creal(1/z), because the imaginary part may produce an unwanted
 * underflow.
 * This is only called in a context where inexact is always raised before
 * the call, so no effort is made to avoid or force inexact.
 */
static inline double
real_part_reciprocal(double x, double y)
{
	double scale;
	uint32_t hx, hy;
	int32_t ix, iy;

	/*
	 * This code is inspired by the C99 document n1124.pdf, Section G.5.1,
	 * example 2.
	 */
	GET_HIGH_WORD(hx, x);
	ix = hx & 0x7ff00000;
	GET_HIGH_WORD(hy, y);
	iy = hy & 0x7ff00000;
#define	BIAS	(DBL_MAX_EXP - 1)
/* XXX more guard digits are useful iff there is extra precision. */
#define	CUTOFF	(DBL_MANT_DIG / 2 + 1)	/* just half or 1 guard digit */
	if (ix - iy >= CUTOFF << 20 || isinf(x))
		return (1 / x);		/* +-Inf -> +-0 is special */
	if (iy - ix >= CUTOFF << 20)
		return (x / y / y);	/* should avoid double div, but hard */
	if (ix <= (BIAS + DBL_MAX_EXP / 2 - CUTOFF) << 20)
		return (x / (x * x + y * y));
	scale = 1;
	SET_HIGH_WORD(scale, 0x7ff00000 - ix);	/* 2**(1-ilogb(x)) */
	x *= scale;
	y *= scale;
	return (x / (x * x + y * y) * scale);
}

/*
 * catanh(z) = log((1+z)/(1-z)) / 2
 *           = log1p(4*x / |z-1|^2) / 4
 *             + I * atan2(2*y, (1-x)*(1+x)-y*y) / 2
 *
 * catanh(z) = z + O(z^3)   as z -> 0
 *
 * catanh(z) = 1/z + sign(y)*I*PI/2 + O(1/z^3)   as z -> infinity
 * The above formula works for the real part as well, because
 * Re(catanh(z)) = x/|z|^2 + O(x/z^4)
 *    as z -> infinity, uniformly in x
 */
double complex
catanh(double complex z)
{
	double x, y, ax, ay, rx, ry;

	x = creal(z);
	y = cimag(z);
	ax = fabs(x);
	ay = fabs(y);

	/* This helps handle many cases. */
	if (y == 0 && ax <= 1)
		return (CMPLX(atanh(x), y));

	/* To ensure the same accuracy as atan(), and to filter out z = 0. */
	if (x == 0)
		return (CMPLX(x, atan(y)));

	if (isnan(x) || isnan(y)) {
		/* catanh(+-Inf + I*NaN) = +-0 + I*NaN */
		if (isinf(x))
			return (CMPLX(copysign(0, x), y + y));
		/* catanh(NaN + I*+-Inf) = sign(NaN)0 + I*+-PI/2 */
		if (isinf(y))
			return (CMPLX(copysign(0, x),
			    copysign(pio2_hi + pio2_lo, y)));
		/*
		 * All other cases involving NaN return NaN + I*NaN.
		 * C99 leaves it optional whether to raise invalid if one of
		 * the arguments is not NaN, so we opt not to raise it.
		 */
		return (CMPLX(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON)
		return (CMPLX(real_part_reciprocal(x, y),
		    copysign(pio2_hi + pio2_lo, y)));

	if (ax < SQRT_3_EPSILON / 2 && ay < SQRT_3_EPSILON / 2) {
		/*
		 * z = 0 was filtered out above.  All other cases must raise
		 * inexact, but this is the only case that needs to do it
		 * explicitly.
		 */
		raise_inexact();
		return (z);
	}

	if (ax == 1 && ay < DBL_EPSILON)
		rx = (m_ln2 - log(ay)) / 2;
	else
		rx = log1p(4 * ax / sum_squares(ax - 1, ay)) / 4;

	if (ax == 1)
		ry = atan2(2, -ay) / 2;
	else if (ay < DBL_EPSILON)
		ry = atan2(2 * ay, (1 - ax) * (1 + ax)) / 2;
	else
		ry = atan2(2 * ay, (1 - ax) * (1 + ax) - ay * ay) / 2;

	return (CMPLX(copysign(rx, x), copysign(ry, y)));
}

/*
 * catan(z) = reverse(catanh(reverse(z)))
 * where reverse(x + I*y) = y + I*x = I*conj(z).
 */
double complex
catan(double complex z)
{
	double complex w = catanh(CMPLX(cimag(z), creal(z)));

	return (CMPLX(cimag(w), creal(w)));
}

#if LDBL_MANT_DIG == 53
__weak_reference(cacosh, cacoshl);
__weak_reference(cacos, cacosl);
__weak_reference(casinh, casinhl);
__weak_reference(casin, casinl);
__weak_reference(catanh, catanhl);
__weak_reference(catan, catanl);
#endif
```
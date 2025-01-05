Response:
Let's break down the thought process for analyzing the `b_tgamma.c` file and generating the comprehensive response.

**1. Understanding the Request:**

The core request is to analyze the provided C code for `tgamma`, a function that calculates the Gamma function. The prompt asks for:

* **Functionality:** What does the code do?
* **Android Relevance:** How does it fit into the Android ecosystem?
* **Implementation Details:** A deep dive into the function's logic.
* **Dynamic Linking:**  Information about how it's linked and used.
* **Logic and Examples:** Illustrative inputs and outputs.
* **Common Errors:** How users might misuse it.
* **Android Integration:** How the code is reached from higher levels (framework/NDK).
* **Frida Hooking:**  How to observe its behavior with Frida.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to read through the code and identify key elements:

* **Header Comments:**  These provide a high-level overview, licensing information, and historical context. The mention of FreeBSD and the author P. McIlroy is important.
* **Includes:** `<float.h>`, `math.h`, `math_private.h`, `b_log.c`, `b_exp.c`. This tells us about dependencies and related functions (logarithm and exponential).
* **Global Variables and Constants:** `zero`, `tiny`, `ln2pi_hi`, `ln2pi_lo`, `Pa0` - `Pa7`, `a0_hi`, `a0_lo`, `P0` - `P4`, `Q0` - `Q8`, `left`, `x0`, `xmax`, `iota`. These are crucial for understanding the algorithm and its numerical constants.
* **Helper Functions:** `large_gam`, `small_gam`, `ratfun_gam`, `smaller_gam`, `neg_gam`. This indicates a range-based approach to calculating the Gamma function.
* **Main Function:** `tgamma(double x)`. This is the entry point of the functionality.
* **Special Value Handling:** The comments within `tgamma` explicitly list how different inputs (NaN, infinities, negative integers, zero) are handled.
* **Accuracy Notes:**  The comments mention the accuracy of the approximation.
* **Weak Reference:** `__weak_reference(tgamma, tgammal);`. This suggests compatibility or alternative naming.

**3. Deconstructing the `tgamma` Function:**

The core of the analysis lies in understanding how `tgamma` works. The code clearly divides the input range `x` into several cases:

* **`x >= 6`:** Uses `large_gam`, which implements Stirling's approximation for large values.
* **`6 > x >= 1 + left + x0`:** Uses `small_gam`, which employs argument reduction and a rational approximation.
* **`1 + left + x0 > x > iota`:** Uses `smaller_gam`, another rational approximation for values near 0.
* **`iota > x > -iota`:** Handles values very close to zero, returning infinity with a potential inexact flag.
* **`!isfinite(x)`:** Handles NaN and -Infinity.
* **`x < 0`:** Uses `neg_gam`, applying the reflection formula.

**4. Analyzing Helper Functions:**

For each helper function (`large_gam`, `small_gam`, etc.), the task is to understand the core algorithm:

* **`large_gam`:** Stirling's approximation involves logarithms and polynomial approximations. The constants are coefficients for this approximation.
* **`small_gam`:**  Argument reduction `G(x+1) = xG(x)` brings the input to a range where a rational function (`ratfun_gam`) is used.
* **`ratfun_gam`:** This implements a specific rational function approximation for the Gamma function within a certain range. The constants are the coefficients of the polynomials in the numerator and denominator.
* **`smaller_gam`:** Another rational function approximation for small positive values.
* **`neg_gam`:** Uses the reflection formula involving `sinpi`, `cospi`, and potentially recursion or calls to `large_gam`.

**5. Addressing Specific Prompt Points:**

* **Functionality:** Summarize the overall purpose of calculating the Gamma function and its mathematical definition.
* **Android Relevance:**  Emphasize its role in the C standard library (`libm`), its use in NDK applications, and potentially in the Android framework for mathematical operations. Give concrete examples of NDK usage (scientific computing, image processing).
* **Implementation Details:**  Explain the range partitioning and the algorithms used in each case, detailing the role of the constants.
* **Dynamic Linking:**  Describe how `libm.so` is loaded by the dynamic linker, the linker's role in resolving symbols, and provide a simplified `libm.so` layout.
* **Logic and Examples:**  Choose representative inputs for each range and special case, showing the expected output (or special return values like NaN or infinity).
* **Common Errors:** Focus on misuse related to input ranges (negative integers), large values causing overflow, and small values causing underflow.
* **Android Integration:**  Trace the path from Java/Kotlin code using JNI to the NDK, which then calls the `tgamma` function in `libm.so`.
* **Frida Hooking:** Provide a practical Frida script example to intercept calls to `tgamma` and inspect arguments and return values.

**6. Refinement and Language:**

* **Clarity:** Use clear and concise language, avoiding overly technical jargon where possible.
* **Structure:** Organize the response logically, addressing each part of the prompt systematically. Use headings and bullet points for readability.
* **Accuracy:** Ensure the technical details are correct and align with the code.
* **Completeness:**  Try to cover all aspects of the prompt.
* **Code Formatting:**  Present code snippets clearly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might oversimplify the rational function approximations. Realize the importance of mentioning the specific constants and their purpose.
* **Dynamic Linking:**  Need to make sure the explanation is clear and avoids getting bogged down in excessive detail about the linker's inner workings. A high-level overview is sufficient.
* **Frida Hooking:** Ensure the script is practical and includes both argument and return value inspection.
* **Android Integration:**  Clearly explain the JNI bridge and the path from Java/Kotlin to native code.

By following this structured approach, analyzing the code segment by segment, and focusing on the specific points raised in the prompt, it's possible to generate a comprehensive and accurate explanation of the `b_tgamma.c` file and its role in the Android ecosystem.
好的，让我们详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/bsdsrc/b_tgamma.c` 这个文件。

**功能列举:**

`b_tgamma.c` 文件实现了计算 Gamma 函数的功能。Gamma 函数是阶乘函数在实数和复数域上的扩展。更具体地说，此文件中的 `tgamma(double x)` 函数接收一个双精度浮点数 `x` 作为输入，并返回 `x` 的 Gamma 函数值 Γ(x)。

**与 Android 功能的关系及举例:**

这个文件是 Android Bionic 库的一部分，Bionic 是 Android 系统的 C 标准库、数学库和动态链接器。`tgamma` 函数作为标准数学函数，被 Android 系统和应用广泛使用。

* **NDK (Native Development Kit) 开发:** 使用 NDK 进行原生代码开发的应用程序可以直接调用 `tgamma` 函数。例如，一个进行科学计算或统计分析的 Android 应用，如果使用 C/C++ 编写核心算法，就可能调用 `tgamma` 来计算阶乘的推广值。
* **Android Framework:** 虽然 Android Framework 主要使用 Java/Kotlin，但在某些底层或性能敏感的模块，Framework 可能会通过 JNI (Java Native Interface) 调用到 `libm.so` 中的 `tgamma` 函数。例如，一些图形渲染、音频处理或机器学习相关的 Framework 组件可能间接使用到它。

**libc 函数功能实现详解:**

`tgamma(double x)` 函数的实现相当复杂，因为它需要处理各种输入范围和特殊情况，以保证精度和正确性。其核心思想是将输入 `x` 分成多个区间，并使用不同的近似方法或公式来计算 Gamma 函数值。

1. **大数值 (x >= 6): `large_gam(x)`**
   - 使用 Stirling 近似公式（斯特林公式）计算 Gamma 函数的对数，然后通过指数运算得到 Gamma 值。
   - Stirling 公式是一种用于近似大数值阶乘的公式，这里进行了调整以适应 Gamma 函数。
   - 代码中 `large_gam` 函数计算的是 `log(Gamma(x))`。
   - **实现细节:**  计算 `log(Gamma(x))` 近似为 `(x-0.5)*(log(x)-1) + 0.5(log(2*pi)-1) + 1/x*P(1/(x*x))`，其中 `P` 是一个多项式。使用高精度浮点运算来减少舍入误差。最后，主函数 `tgamma` 调用 `__exp__D` (可能是内部的指数函数实现) 来计算 `exp(log(Gamma(x)))`。

2. **中间数值 (1 + left + x0 <= x < 6): `small_gam(x)`**
   - 使用递推关系 `Γ(x+1) = xΓ(x)` 将参数规约到 `[1.066.., 2.066..]` 区间。
   - 在规约后的区间内，使用有理函数逼近 `ratfun_gam` 来计算 Gamma 函数值。
   - **实现细节:** `small_gam` 首先通过循环不断地使用 `Γ(x) = Γ(x+1)/x` 将 `x` 减小，直到它落入 `ratfun_gam` 适用的区间。然后，调用 `ratfun_gam` 计算该区间内的 Gamma 值，并将之前除掉的因子乘回去。

3. **小正数值 (iota < x < 1 + left + x0): `smaller_gam(x)`**
   - 直接使用有理函数逼近 `ratfun_gam` 计算 Gamma 函数值，但做了针对小数值的优化。
   - **实现细节:**  `smaller_gam` 也使用 `ratfun_gam`，但参数处理略有不同，可能为了提高小数值计算的精度。

4. **接近零的值 (-iota < x < iota):**
   - 当 `x` 非常接近 0 时，Gamma 函数的值会趋于无穷大。
   - 如果 `x` 非零，会设置一个标志位表示结果不精确，并返回 `1/x`。
   - 如果 `x` 为零，会返回 `+/-Inf` 并触发除零错误。

5. **负数值 (x < 0): `neg_gam(x)`**
   - 使用反射公式 `Γ(x) = π / (sin(πx) * Γ(1-x))` 计算 Gamma 函数值。
   - 对于负整数，Gamma 函数没有定义，返回 NaN 并触发无效操作异常。
   - **实现细节:** `neg_gam` 首先检查 `x` 是否为负整数。然后，根据反射公式，计算 `sin(pi*x)` 和 `Gamma(1-x)`。对于 `Gamma(1-x)` 的计算，如果 `1-x` 较大，可能会调用 `large_gam`。

6. **特殊值处理:**
   - **-Inf:** 返回 NaN 并触发无效操作异常。
   - **负整数:** 返回 NaN 并触发无效操作异常。
   - **非常小的正数 (接近机器精度下限):** 返回 `+/-0` 并触发下溢错误。
   - **+/-0:** 返回 `+/-Inf` 并触发除零错误。
   - **非常大的正数 (超过可表示范围):** 返回 `+Inf` 并触发上溢错误。
   - **+Inf:** 返回 `+Inf`。
   - **NaN:** 返回 NaN。

**`ratfun_gam(double z, double c)` 的功能:**

`ratfun_gam` 是一个辅助函数，用于在特定区间内使用有理函数逼近 Gamma 函数。它接收两个参数 `z` 和 `c`，并计算 `a0 + (z + c)^2 * P(z) / Q(z)`，其中 `P(z)` 和 `Q(z)` 是关于 `z` 的多项式，`a0` 是一个常数。这个函数被 `small_gam` 和 `smaller_gam` 调用。

**涉及 dynamic linker 的功能:**

这个 `.c` 文件本身不直接涉及动态链接器的操作。动态链接器负责在程序启动或运行时加载共享库 (`.so` 文件) 并解析符号引用。

* **so 布局样本 (libm.so):**

```
libm.so
├── .text          // 包含可执行代码
│   ├── tgamma     // tgamma 函数的机器码
│   ├── ...        // 其他数学函数
├── .data          // 包含已初始化的全局变量
│   ├── ...
├── .rodata        // 包含只读数据 (例如，这里的常数)
│   ├── zero
│   ├── tiny
│   ├── ln2pi_hi
│   ├── ...
├── .bss           // 包含未初始化的全局变量
└── .symtab        // 符号表，包含导出的函数和变量
    ├── tgamma
    ├── ...
```

* **链接的处理过程:**

1. **编译:** 当 Android 系统或 NDK 应用编译时，如果代码中使用了 `tgamma` 函数，编译器会在目标文件中生成一个对 `tgamma` 符号的未解析引用。
2. **链接:** 链接器（在 Android 中主要是 `lld`）在链接阶段会将这些未解析的引用与相应的共享库 (`libm.so`) 中的符号定义关联起来。
3. **加载:** 当应用启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会加载应用依赖的共享库，包括 `libm.so`。
4. **符号解析:** 动态链接器会解析应用中对 `tgamma` 的引用，将其指向 `libm.so` 中 `tgamma` 函数的实际地址。这样，当应用调用 `tgamma` 时，实际上执行的是 `libm.so` 中的代码。

**逻辑推理和假设输入与输出:**

* **假设输入:** `x = 7.0` (使用 `large_gam`)
   - **输出:** 预期输出接近 `Gamma(7) = 6! = 720.0`。由于是近似计算，可能会有微小的浮点误差。
* **假设输入:** `x = 1.5` (使用 `small_gam` 或 `ratfun_gam`)
   - **输出:** 预期输出接近 `Gamma(1.5) = sqrt(pi) / 2 ≈ 0.886226925`。
* **假设输入:** `x = 0.5` (使用 `smaller_gam`)
   - **输出:** 预期输出接近 `Gamma(0.5) = sqrt(pi) ≈ 1.77245385`。
* **假设输入:** `x = -2.0` (使用 `neg_gam`)
   - **输出:**  由于是负整数，预期输出为 `NaN`，并可能触发无效操作异常。
* **假设输入:** `x = 0.0`
   - **输出:** 预期输出为 `Inf` 或 `-Inf`，并触发除零错误。

**用户或编程常见的使用错误:**

1. **输入负整数:**  `tgamma` 函数对于负整数没有定义，会导致返回 NaN。开发者可能没有对输入进行适当的校验。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double result = tgamma(-2.0);
       if (isnan(result)) {
           printf("Error: tgamma is not defined for negative integers.\n");
       } else {
           printf("tgamma(-2.0) = %f\n", result); // 不会执行到这里
       }
       return 0;
   }
   ```

2. **输入非常大的正数:**  可能导致结果溢出，返回 `Inf`。开发者可能没有考虑到数值的范围。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double x = 175.0; // 一个可能导致溢出的较大值
       double result = tgamma(x);
       if (isinf(result)) {
           printf("Warning: tgamma result overflowed.\n");
       } else {
           printf("tgamma(%f) = %f\n", x, result);
       }
       return 0;
   }
   ```

3. **误用 `lgamma`:**  有时开发者可能需要的是 Gamma 函数绝对值的自然对数，这时应该使用 `lgamma` 函数，而不是 `tgamma`。`lgamma` 返回 `log(|Γ(x)|)`，并提供一个符号指示。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java/Kotlin):**
   - 假设 Android Framework 中的某个 Java 或 Kotlin 组件需要计算 Gamma 函数。
   - 该组件可能会调用 JNI 方法来调用 native 代码。
   - Native 代码中会调用 `tgamma` 函数，该函数链接到 `libm.so` 中。

2. **NDK 应用 (C/C++):**
   - NDK 应用的开发者可以直接在 C/C++ 代码中包含 `<math.h>` 并调用 `tgamma` 函数。
   - 在编译和链接阶段，`tgamma` 的符号引用会被解析到 Android 系统提供的 `libm.so` 库中。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook 调试 `tgamma` 函数的示例：

1. **准备 Frida 环境:** 确保你的设备已 root，并安装了 Frida 和 frida-tools。

2. **编写 Frida Hook 脚本 (tgamma_hook.js):**

```javascript
if (Process.platform === 'android') {
  const libmModule = Process.getModuleByName("libm.so");
  const tgammaAddress = libmModule.getExportByName("tgamma");

  if (tgammaAddress) {
    Interceptor.attach(tgammaAddress, {
      onEnter: function (args) {
        const x = args[0].toDouble();
        console.log(`[tgamma Hook] Called with x = ${x}`);
        this.startTime = Date.now();
      },
      onLeave: function (retval) {
        const result = retval.toDouble();
        const endTime = Date.now();
        const elapsedTime = endTime - this.startTime;
        console.log(`[tgamma Hook] Returned ${result}, execution time: ${elapsedTime} ms`);
      }
    });
    console.log("[tgamma Hook] tgamma function hooked successfully!");
  } else {
    console.error("[tgamma Hook] Failed to find tgamma function in libm.so");
  }
} else {
  console.log("[tgamma Hook] Not running on Android, script not applicable.");
}
```

3. **运行 Frida Hook:**

   - 找到目标 Android 进程的名称或 PID。例如，假设目标进程的名称是 `com.example.myapp`。
   - 使用 `frida` 命令运行 Hook 脚本：
     ```bash
     frida -U -f com.example.myapp -l tgamma_hook.js --no-pause
     ```
     或者，如果进程已经在运行：
     ```bash
     frida -U com.example.myapp -l tgamma_hook.js
     ```

4. **触发 `tgamma` 调用:**  在目标 Android 应用中执行某些操作，使其调用到 `tgamma` 函数。

5. **查看 Frida 输出:**  Frida 会在控制台输出 `tgamma` 函数的调用信息，包括输入参数和返回值以及执行时间。

**示例输出:**

```
[tgamma Hook] tgamma function hooked successfully!
[tgamma Hook] Called with x = 7
[tgamma Hook] Returned 720.000000, execution time: 0 ms
[tgamma Hook] Called with x = 1.5
[tgamma Hook] Returned 0.886227, execution time: 0 ms
[tgamma Hook] Called with x = -2
[tgamma Hook] Returned NaN, execution time: 0 ms
```

通过 Frida Hook，你可以动态地观察 `tgamma` 函数的调用情况，这对于理解其行为、调试问题或进行性能分析非常有帮助。

总而言之，`b_tgamma.c` 文件是 Android 系统中提供标准 Gamma 函数计算的关键组件，它通过精巧的算法和对不同输入范围的特殊处理，保证了计算的精度和效率。理解其实现细节有助于开发者更好地利用这个函数，并避免常见的错误。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/bsdsrc/b_tgamma.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The original code, FreeBSD's old svn r93211, contained the following
 * attribution:
 *
 *    This code by P. McIlroy, Oct 1992;
 *
 *    The financial support of UUNET Communications Services is greatfully
 *    acknowledged.
 *
 *  The algorithm remains, but the code has been re-arranged to facilitate
 *  porting to other precisions.
 */

#include <float.h>

#include "math.h"
#include "math_private.h"

/* Used in b_log.c and below. */
struct Double {
	double a;
	double b;
};

#include "b_log.c"
#include "b_exp.c"

/*
 * The range is broken into several subranges.  Each is handled by its
 * helper functions.
 *
 *         x >=   6.0: large_gam(x)
 *   6.0 > x >= xleft: small_gam(x) where xleft = 1 + left + x0.
 * xleft > x >   iota: smaller_gam(x) where iota = 1e-17.
 *  iota > x >  -itoa: Handle x near 0.
 * -iota > x         : neg_gam
 *
 * Special values:
 *	-Inf:			return NaN and raise invalid;
 *	negative integer:	return NaN and raise invalid;
 *	other x ~< 177.79:	return +-0 and raise underflow;
 *	+-0:			return +-Inf and raise divide-by-zero;
 *	finite x ~> 171.63:	return +Inf and raise overflow;
 *	+Inf:			return +Inf;
 *	NaN: 			return NaN.
 *
 * Accuracy: tgamma(x) is accurate to within
 *	x > 0:  error provably < 0.9ulp.
 *	Maximum observed in 1,000,000 trials was .87ulp.
 *	x < 0:
 *	Maximum observed error < 4ulp in 1,000,000 trials.
 */

/*
 * Constants for large x approximation (x in [6, Inf])
 * (Accurate to 2.8*10^-19 absolute)
 */

static const double zero = 0.;
static const volatile double tiny = 1e-300;
/*
 * x >= 6
 *
 * Use the asymptotic approximation (Stirling's formula) adjusted fof
 * equal-ripples:
 *
 * log(G(x)) ~= (x-0.5)*(log(x)-1) + 0.5(log(2*pi)-1) + 1/x*P(1/(x*x))
 *
 * Keep extra precision in multiplying (x-.5)(log(x)-1), to avoid
 * premature round-off.
 *
 * Accurate to max(ulp(1/128) absolute, 2^-66 relative) error.
 */
static const double
    ln2pi_hi =  0.41894531250000000,
    ln2pi_lo = -6.7792953272582197e-6,
    Pa0 =  8.3333333333333329e-02, /* 0x3fb55555, 0x55555555 */
    Pa1 = -2.7777777777735404e-03, /* 0xbf66c16c, 0x16c145ec */
    Pa2 =  7.9365079044114095e-04, /* 0x3f4a01a0, 0x183de82d */
    Pa3 = -5.9523715464225254e-04, /* 0xbf438136, 0x0e681f62 */
    Pa4 =  8.4161391899445698e-04, /* 0x3f4b93f8, 0x21042a13 */
    Pa5 = -1.9065246069191080e-03, /* 0xbf5f3c8b, 0x357cb64e */
    Pa6 =  5.9047708485785158e-03, /* 0x3f782f99, 0xdaf5d65f */
    Pa7 = -1.6484018705183290e-02; /* 0xbf90e12f, 0xc4fb4df0 */

static struct Double
large_gam(double x)
{
	double p, z, thi, tlo, xhi, xlo;
	struct Double u;

	z = 1 / (x * x);
	p = Pa0 + z * (Pa1 + z * (Pa2 + z * (Pa3 + z * (Pa4 + z * (Pa5 +
	    z * (Pa6 + z * Pa7))))));
	p = p / x;

	u = __log__D(x);
	u.a -= 1;

	/* Split (x - 0.5) in high and low parts. */
	x -= 0.5;
	xhi = (float)x;
	xlo = x - xhi;

	/* Compute  t = (x-.5)*(log(x)-1) in extra precision. */
	thi = xhi * u.a;
	tlo = xlo * u.a + x * u.b;

	/* Compute thi + tlo + ln2pi_hi + ln2pi_lo + p. */
	tlo += ln2pi_lo;
	tlo += p;
	u.a = ln2pi_hi + tlo;
	u.a += thi;
	u.b = thi - u.a;
	u.b += ln2pi_hi;
	u.b += tlo;
	return (u);
}
/*
 * Rational approximation, A0 + x * x * P(x) / Q(x), on the interval
 * [1.066.., 2.066..] accurate to 4.25e-19.
 *
 * Returns r.a + r.b = a0 + (z + c)^2 * p / q, with r.a truncated.
 */
static const double
#if 0
    a0_hi =  8.8560319441088875e-1,
    a0_lo = -4.9964270364690197e-17,
#else
    a0_hi =  8.8560319441088875e-01, /* 0x3fec56dc, 0x82a74aef */
    a0_lo = -4.9642368725563397e-17, /* 0xbc8c9deb, 0xaa64afc3 */
#endif
    P0 =  6.2138957182182086e-1,
    P1 =  2.6575719865153347e-1,
    P2 =  5.5385944642991746e-3,
    P3 =  1.3845669830409657e-3,
    P4 =  2.4065995003271137e-3,
    Q0 =  1.4501953125000000e+0,
    Q1 =  1.0625852194801617e+0,
    Q2 = -2.0747456194385994e-1,
    Q3 = -1.4673413178200542e-1,
    Q4 =  3.0787817615617552e-2,
    Q5 =  5.1244934798066622e-3,
    Q6 = -1.7601274143166700e-3,
    Q7 =  9.3502102357378894e-5,
    Q8 =  6.1327550747244396e-6;

static struct Double
ratfun_gam(double z, double c)
{
	double p, q, thi, tlo;
	struct Double r;

	q = Q0 + z * (Q1 + z * (Q2 + z * (Q3 + z * (Q4 + z * (Q5 + 
	    z * (Q6 + z * (Q7 + z * Q8)))))));
	p = P0 + z * (P1 + z * (P2 + z * (P3 + z * P4)));
	p = p / q;

	/* Split z into high and low parts. */
	thi = (float)z;
	tlo = (z - thi) + c;
	tlo *= (thi + z);

	/* Split (z+c)^2 into high and low parts. */
	thi *= thi;
	q = thi;
	thi = (float)thi;
	tlo += (q - thi);

	/* Split p/q into high and low parts. */
	r.a = (float)p;
	r.b = p - r.a;

	tlo = tlo * p + thi * r.b + a0_lo;
	thi *= r.a;				/* t = (z+c)^2*(P/Q) */
	r.a = (float)(thi + a0_hi);
	r.b = ((a0_hi - r.a) + thi) + tlo;
	return (r);				/* r = a0 + t */
}
/*
 * x < 6
 *
 * Use argument reduction G(x+1) = xG(x) to reach the range [1.066124,
 * 2.066124].  Use a rational approximation centered at the minimum
 * (x0+1) to ensure monotonicity.
 *
 * Good to < 1 ulp.  (provably .90 ulp; .87 ulp on 1,000,000 runs.)
 * It also has correct monotonicity.
 */
static const double
    left = -0.3955078125,	/* left boundary for rat. approx */
    x0 = 4.6163214496836236e-1;	/* xmin - 1 */

static double
small_gam(double x)
{
	double t, y, ym1;
	struct Double yy, r;

	y = x - 1;
	if (y <= 1 + (left + x0)) {
		yy = ratfun_gam(y - x0, 0);
		return (yy.a + yy.b);
	}

	r.a = (float)y;
	yy.a = r.a - 1;
	y = y - 1 ;
	r.b = yy.b = y - yy.a;

	/* Argument reduction: G(x+1) = x*G(x) */
	for (ym1 = y - 1; ym1 > left + x0; y = ym1--, yy.a--) {
		t = r.a * yy.a;
		r.b = r.a * yy.b + y * r.b;
		r.a = (float)t;
		r.b += (t - r.a);
	}

	/* Return r*tgamma(y). */
	yy = ratfun_gam(y - x0, 0);
	y = r.b * (yy.a + yy.b) + r.a * yy.b;
	y += yy.a * r.a;
	return (y);
}
/*
 * Good on (0, 1+x0+left].  Accurate to 1 ulp.
 */
static double
smaller_gam(double x)
{
	double d, rhi, rlo, t, xhi, xlo;
	struct Double r;

	if (x < x0 + left) {
		t = (float)x;
		d = (t + x) * (x - t);
		t *= t;
		xhi = (float)(t + x);
		xlo = x - xhi;
		xlo += t;
		xlo += d;
		t = 1 - x0;
		t += x;
		d = 1 - x0;
		d -= t;
		d += x;
		x = xhi + xlo;
	} else {
		xhi = (float)x;
		xlo = x - xhi;
		t = x - x0;
		d = - x0 - t;
		d += x;
	}

	r = ratfun_gam(t, d);
	d = (float)(r.a / x);
	r.a -= d * xhi;
	r.a -= d * xlo;
	r.a += r.b;

	return (d + r.a / x);
}
/*
 * x < 0
 *
 * Use reflection formula, G(x) = pi/(sin(pi*x)*x*G(x)).
 * At negative integers, return NaN and raise invalid.
 */
static double
neg_gam(double x)
{
	int sgn = 1;
	struct Double lg, lsine;
	double y, z;

	y = ceil(x);
	if (y == x)		/* Negative integer. */
		return ((x - x) / zero);

	z = y - x;
	if (z > 0.5)
		z = 1 - z;

	y = y / 2;
	if (y == ceil(y))
		sgn = -1;

	if (z < 0.25)
		z = sinpi(z);
	else
		z = cospi(0.5 - z);

	/* Special case: G(1-x) = Inf; G(x) may be nonzero. */
	if (x < -170) {

		if (x < -190)
			return (sgn * tiny * tiny);

		y = 1 - x;			/* exact: 128 < |x| < 255 */
		lg = large_gam(y);
		lsine = __log__D(M_PI / z);	/* = TRUNC(log(u)) + small */
		lg.a -= lsine.a;		/* exact (opposite signs) */
		lg.b -= lsine.b;
		y = -(lg.a + lg.b);
		z = (y + lg.a) + lg.b;
		y = __exp__D(y, z);
		if (sgn < 0) y = -y;
		return (y);
	}

	y = 1 - x;
	if (1 - y == x)
		y = tgamma(y);
	else		/* 1-x is inexact */
		y = - x * tgamma(-x);

	if (sgn < 0) y = -y;
	return (M_PI / (y * z));
}
/*
 * xmax comes from lgamma(xmax) - emax * log(2) = 0.
 * static const float  xmax = 35.040095f
 * static const double xmax = 171.624376956302725;
 * ld80: LD80C(0xdb718c066b352e20, 10, 1.75554834290446291689e+03L),
 * ld128: 1.75554834290446291700388921607020320e+03L,
 *
 * iota is a sloppy threshold to isolate x = 0.
 */
static const double xmax = 171.624376956302725;
static const double iota = 0x1p-56;

double
tgamma(double x)
{
	struct Double u;

	if (x >= 6) {
		if (x > xmax)
			return (x / zero);
		u = large_gam(x);
		return (__exp__D(u.a, u.b));
	}

	if (x >= 1 + left + x0)
		return (small_gam(x));

	if (x > iota)
		return (smaller_gam(x));

	if (x > -iota) {
		if (x != 0.)
			u.a = 1 - tiny;	/* raise inexact */
		return (1 / x);
	}

	if (!isfinite(x))
		return (x - x);		/* x is NaN or -Inf */

	return (neg_gam(x));
}

#if (LDBL_MANT_DIG == 53)
__weak_reference(tgamma, tgammal);
#endif

"""

```
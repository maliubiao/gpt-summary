Response:
Let's break down the thought process for analyzing the `s_fma.c` code.

1. **Understand the Goal:** The primary goal is to analyze the provided C source code for the `fma` function, part of Android's math library. The analysis needs to cover its functionality, relation to Android, implementation details, dynamic linking aspects (though the code itself doesn't directly handle this), potential errors, and debugging information.

2. **Initial Code Examination (Skimming):**  First, I'd quickly skim the code to get a general idea of its structure. Keywords like `#include`, `double`, `struct`, `static inline`, `if/else`, and function names like `dd_add`, `dd_mul`, `add_adjusted`, and `add_and_denormalize` stand out. The header comments mention BSD licensing and David Schultz, suggesting it's derived from FreeBSD. The presence of `#ifdef USE_BUILTIN_FMA` is a significant clue about different implementation paths.

3. **Identify the Core Functionality:** The function `fma(double x, double y, double z)` is the central focus. The comments indicate it's for "fused multiply-add," computing `x * y + z` with a single rounding error.

4. **Analyze the Conditional Compilation:** The `#ifdef USE_BUILTIN_FMA` is crucial. This immediately tells us there are two main implementation approaches:
    * **Built-in:** If `USE_BUILTIN_FMA` is defined (likely by the compiler or build system), the function simply calls `__builtin_fma`. This means the actual FMA operation is handled by the processor's instruction set.
    * **Software Implementation:** If the built-in isn't used, there's a more complex software implementation. This requires deeper investigation.

5. **Deconstruct the Software Implementation:**
    * **`struct dd`:** This structure is clearly designed to represent a double-double number (high and low parts for increased precision). The comments explain its purpose.
    * **Helper Functions (`dd_add`, `dd_mul`, `add_adjusted`, `add_and_denormalize`):** These are the building blocks of the software FMA. Each function needs to be examined individually:
        * `dd_add`:  Implements exact addition of two doubles, storing the result in the `dd` structure. The formulas used are standard techniques for high-precision addition.
        * `add_adjusted`:  Adds a twist to `dd_add` by setting a "sticky bit." The comments explain the reason for this (counteracting double rounding).
        * `add_and_denormalize`: Handles addition when the result will be subnormal, taking care to avoid double rounding in this specific scenario.
        * `dd_mul`: Implements exact multiplication of two doubles, again storing the result in the `dd` structure. The "split" constant and the subsequent calculations are related to Dekker's method for high-precision multiplication.
    * **The Main `fma` Function (Software Path):** This is the most involved part. I'd analyze it step-by-step:
        * **Special Cases:** The initial `if` statements handle edge cases like zero inputs, infinities, and NaNs. Understanding the order and return values in these cases is important for correctness.
        * **Scaling with `frexp` and `ldexp`:** The code uses `frexp` to extract the significand and exponent and `ldexp` to scale values. This is a common technique to prevent overflow or underflow during intermediate calculations.
        * **Rounding Mode Check:** The code considers the current floating-point rounding mode (`fegetround`).
        * **The Core Algorithm (Round-to-Nearest):** The comments clearly outline the steps for the round-to-nearest case using the double-double arithmetic.
        * **Directed Rounding Modes:** The code handles other rounding modes separately, noting that double rounding isn't a concern in these cases.
        * **Denormalization Handling:**  There's specific logic for handling denormalized results.

6. **Relate to Android:** The code is located within Android's Bionic library, specifically in the math library (`libm`). This signifies its direct use by Android applications. Examples of math-intensive tasks in Android (game physics, image processing, etc.) would be relevant.

7. **Dynamic Linking (Conceptual):** While the `s_fma.c` file itself doesn't perform dynamic linking, it's *part of* a shared library (`libm.so`) that *is* dynamically linked. Therefore, describing the general principles of dynamic linking in Android, including SO layout and symbol resolution, is necessary. A simplified SO layout example would be helpful.

8. **Identify Potential Errors:** Common mistakes when using floating-point functions, such as assuming exact results or not considering rounding errors, are important to highlight. Examples would illustrate these points.

9. **Debugging Path:**  Tracing how a function call from an Android app reaches `s_fma.c` involves understanding the layers: NDK (if used), Android Framework (less direct for `libm`), system calls, and finally the dynamic linker loading `libm.so`.

10. **Assumptions and Simplifications:**  Throughout the analysis, it's important to make reasonable assumptions (e.g., focusing on common scenarios) and simplify complex topics (like dynamic linking) for clarity.

11. **Structure and Presentation:**  Organize the information logically using headings and bullet points for readability. Provide clear explanations and concrete examples.

12. **Review and Refine:** After drafting the initial analysis, review it for accuracy, completeness, and clarity. Ensure the language is precise and easy to understand. For instance, initially, I might have just said "it handles rounding," but refining it to explain the double-rounding issue and the sticky bit makes it much clearer. Similarly, just stating "dynamic linking happens" isn't enough; providing a basic SO layout and symbol resolution process adds significant value.
好的，我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/s_fma.c` 这个文件。

**功能列举:**

`s_fma.c` 文件实现了 `fma()` 函数，即 **Fused Multiply-Add** 操作。`fma(x, y, z)` 计算 `(x * y) + z`，并只进行**一次最终的舍入**。

**具体功能：**

1. **高精度计算:** `fma` 函数相比先算乘法再算加法，可以提供更高的精度。因为中间的乘积不会被舍入，所有有效位都会参与到后续的加法运算中。
2. **避免双重舍入:**  传统的 `(x * y) + z` 会进行两次舍入：一次在乘法之后，一次在加法之后。`fma` 通过单次舍入，避免了双重舍入可能带来的精度损失。
3. **处理特殊情况:**  代码中包含了处理特殊浮点数（如零、无穷大、NaN）的逻辑，以确保在各种输入下都能得到符合 IEEE 754 标准的结果。
4. **可配置实现:** 代码通过预编译宏 `USE_BUILTIN_FMA` 提供了两种实现方式：
    * **内置实现 (`__builtin_fma`):**  如果编译器支持内置的 FMA 指令，则直接使用硬件指令，性能更高。
    * **软件实现:** 如果没有内置指令，则使用代码实现，通过双精度算法模拟高精度计算。

**与 Android 功能的关系及举例说明:**

`fma` 函数是 C 标准库 `<math.h>` 的一部分，因此在 Android 中被广泛使用。它对于任何需要高精度浮点数计算的场景都很有用。

**举例说明：**

* **图形渲染:** 在 3D 图形渲染中，矩阵运算和向量运算非常频繁，涉及到大量的浮点数乘法和加法。使用 `fma` 可以提高计算精度，从而提升渲染质量。例如，计算光照模型时，可能需要计算 `ambient + diffuse * intensity`，这里就可以使用 `fma`。
* **物理模拟:** 游戏引擎或科学计算应用中，物理模拟需要精确地计算物体的位置、速度和加速度。例如，在计算阻力时，可能会有类似 `force - drag * velocity` 的表达式，可以使用 `fma` 来提高精度。
* **音频处理:**  音频处理算法，如滤波器设计和信号合成，也经常涉及到浮点数运算。`fma` 可以提高音频处理的精度和质量。例如，在 IIR 滤波器的计算中，会涉及到前几个输出和输入的线性组合，可以使用 `fma` 来保证计算的准确性。
* **机器学习:** 某些机器学习算法，特别是涉及到数值计算密集型的部分，可能会受益于 `fma` 带来的精度提升。

**libc 函数的实现详解:**

我们主要关注软件实现的 `fma` 函数，因为内置实现依赖于硬件。

1. **`struct dd`:** 定义了一个双精度结构体，用于存储双倍精度的浮点数。`hi` 存储高 53 位，`lo` 存储低位，这样可以模拟更高精度的计算。

2. **`dd_add(double a, double b)`:**  实现两个 `double` 类型的数 `a` 和 `b` 的精确加法，结果存储在 `struct dd` 中。
   * `ret.hi = a + b;`：先计算标准的双精度加法，结果存储在高位 `hi` 中。
   * `s = ret.hi - a;`: 计算一个中间值 `s`，用于提取加法运算中的舍入误差。
   * `ret.lo = (a - (ret.hi - s)) + (b - s);`:  利用 Kahan 求和公式的思想，计算出低位 `lo`，它包含了在计算 `ret.hi` 时损失的精度。

3. **`add_adjusted(double a, double b)`:** 在 `dd_add` 的基础上，对结果的最低有效位进行调整，模拟“粘滞位”（sticky bit）。粘滞位用于记录所有因舍入而丢失的位信息。
   * 先调用 `dd_add` 计算精确和。
   * 如果 `sum.lo` 不为零，说明有精度损失。
   * 检查 `sum.hi` 的最低位是否为 0。如果是，则根据 `sum.hi` 和 `sum.lo` 的符号调整 `sum.hi` 的最低位为 1，相当于设置了粘滞位。

4. **`add_and_denormalize(double a, double b, int scale)`:**  用于计算可能产生非规格化数（subnormal number）的加法。它考虑了双重舍入的问题。
   * 先调用 `dd_add` 计算精确和。
   * 计算由于非规格化导致的精度损失位数 `bits_lost`。
   * 如果损失的位数大于 1，或者损失 1 位但 `sum.hi` 的最低位为 0，则调整 `sum.hi` 的最低位，设置粘滞位。
   * 最后，使用 `ldexp` 将结果缩放到正确的指数范围。

5. **`dd_mul(double a, double b)`:** 实现两个 `double` 类型数 `a` 和 `b` 的精确乘法，结果存储在 `struct dd` 中。使用了一种称为“拆分”的技术（类似 Dekker 算法）。
   * 通过 `split` 常量将 `a` 和 `b` 分解成高位部分 (`ha`, `hb`) 和低位部分 (`la`, `lb`)。
   * 计算部分乘积：`p = ha * hb;`，`q = ha * lb + la * hb;`。
   * 高位结果 `ret.hi = p + q;`。
   * 低位结果 `ret.lo = p - ret.hi + q + la * lb;`。

6. **`fma(double x, double y, double z)` (软件实现):**
   * **处理特殊情况:**  首先处理输入为 0、无穷大或 NaN 的情况。
   * **缩放 (Scaling):** 使用 `frexp` 将 `x`、`y`、`z` 分解为尾数和指数，进行缩放，防止中间计算溢出或下溢。
   * **处理大指数差:** 如果 `x * y` 和 `z` 的数量级相差很大，则直接根据舍入模式返回 `z` 或其邻近值。
   * **设置舍入模式:**  临时设置为最接近舍入 (`FE_TONEAREST`) 进行中间计算。
   * **精确乘法:** 调用 `dd_mul` 计算 `x * y` 的精确结果。
   * **精确加法:** 调用 `dd_add` 计算 `xy.hi + z` 的精确结果。
   * **处理加法结果为 0 的情况:**  确保结果的符号正确。
   * **处理非最接近舍入模式:**  直接计算 `r.hi + r.lo + xy.lo`，不需要考虑双重舍入。
   * **最接近舍入模式:** 调用 `add_adjusted` 将 `r.lo` 和 `xy.lo` 相加，并设置粘滞位。
   * **最终结果:** 使用 `ldexp` 将结果缩放到正确的指数范围。如果结果是次正规数，则调用 `add_and_denormalize` 进行处理。

**dynamic linker 的功能，so 布局样本，以及每种符号如何的处理过程:**

`s_fma.c` 本身是 C 源代码，并不直接涉及动态链接器的功能。动态链接器 (`linker` 或 `ld-linux.so`) 的作用是在程序运行时加载和链接共享库 (`.so` 文件)。 `s_fma.c` 编译后会成为 `libm.so` 的一部分。

**SO 布局样本 (简化):**

一个典型的 `.so` 文件（如 `libm.so`）的布局可能如下：

```
ELF Header:
  ... (包含文件类型、架构等信息)

Program Headers:
  LOAD: (可加载段，包含代码和数据)
  DYNAMIC: (包含动态链接信息)
  ...

Section Headers:
  .text: (代码段，包含 fma 等函数的机器码)
  .rodata: (只读数据段，包含常量)
  .data: (已初始化数据段)
  .bss: (未初始化数据段)
  .symtab: (符号表，包含导出的和导入的符号信息)
  .strtab: (字符串表，存储符号名称)
  .dynsym: (动态符号表，用于动态链接)
  .dynstr: (动态字符串表)
  .plt: (过程链接表，用于延迟绑定)
  .got: (全局偏移量表)
  ...
```

**符号处理过程:**

1. **定义符号:** 在 `s_fma.c` 中定义的函数 `fma` (如果不是 `USE_BUILTIN_FMA`) 和一些静态辅助函数 (`dd_add`, `dd_mul` 等) 会被编译器处理成符号。`fma` 是一个导出的符号，因为它是 `libm` 库的公共接口。静态函数通常是库内部使用的，不会被导出。

2. **符号表:** 编译器会将这些符号信息存储在 `.symtab` 和 `.dynsym` 段中。每个符号条目包含符号的名称、类型（函数、变量等）、绑定属性（GLOBAL, WEAK, LOCAL）、所在地址等信息。

3. **动态链接:** 当 Android 应用或其他共享库需要使用 `fma` 函数时，动态链接器会执行以下步骤：
   * **加载共享库:**  当程序启动或调用 `dlopen` 等函数时，动态链接器会加载 `libm.so` 到内存中。
   * **符号解析:** 动态链接器会查找程序中对 `fma` 函数的未定义引用。它会在 `libm.so` 的动态符号表 (`.dynsym`) 中查找名为 `fma` 且绑定属性为 `GLOBAL` 或 `WEAK` 的符号。
   * **重定位:**  一旦找到符号定义，动态链接器会将程序中对 `fma` 函数的引用地址更新为 `fma` 函数在 `libm.so` 中的实际内存地址。这个过程称为重定位。全局偏移量表 (`.got`) 和过程链接表 (`.plt`) 在延迟绑定中扮演重要角色。
   * **延迟绑定 (Lazy Binding):** 为了提高启动速度，动态链接器通常采用延迟绑定。最初，对外部函数的调用会跳转到 `.plt` 中的一段代码，该代码会调用链接器来解析符号并更新 `.got` 表项，然后才真正调用到 `fma` 函数的实现。后续的调用会直接通过 `.got` 表跳转到 `fma` 的地址。

**符号类型处理:**

* **GLOBAL 符号:**  例如 `fma`。可以被其他共享库或主程序引用。动态链接器负责解析这些符号。
* **WEAK 符号:**  例如 `__weak_reference(fma, fmal);` 定义的 `fmal`。如果其他库中也定义了同名的符号，链接器可以选择使用其他库的定义。
* **LOCAL 符号:** 例如 `dd_add` 等静态函数。仅在定义它们的编译单元内部可见，不会被动态链接器处理。

**假设输入与输出 (逻辑推理):**

假设 `fma(3.0, 4.0, 1.0)`：

* **精确计算:** `(3.0 * 4.0) + 1.0 = 12.0 + 1.0 = 13.0`
* **`fma` 输出:**  由于 `fma` 进行单次舍入，理想情况下，结果应该非常接近 13.0，取决于浮点数的精度。如果使用软件实现，会通过高精度计算保证结果的准确性。

假设 `fma(DBL_MAX, 2.0, -DBL_MAX)`，其中 `DBL_MAX` 是最大的 `double` 值：

* **普通计算:** `DBL_MAX * 2.0` 会导致溢出，结果可能是无穷大。无穷大减去 `DBL_MAX` 的结果是未定义的 (NaN)。
* **`fma` 输出:**  `fma` 的实现会处理溢出情况。由于中间乘积是隐式的高精度，`fma` 可能会得到一个接近 `DBL_MAX` 的值。具体的行为取决于 IEEE 754 标准和实现细节。

**用户或编程常见的使用错误举例说明:**

1. **误以为浮点数运算是精确的:**  开发者可能没有意识到 `fma` 与直接计算 `(x * y) + z` 在精度上的差异，导致在需要高精度计算的场景下使用了精度较低的方式。
   ```c
   double x = 0.1;
   double y = 0.2;
   double z = 0.3;
   double res1 = (x * y) + z;
   double res2 = fma(x, y, z);
   // res1 和 res2 在某些情况下可能略有不同，res2 更精确
   ```

2. **不理解 `fma` 的性能影响:**  软件实现的 `fma` 比直接的乘法和加法操作要慢。在性能敏感的代码中，不加选择地使用 `fma` 可能会降低性能。开发者需要在精度和性能之间进行权衡。

3. **错误地处理特殊值:**  虽然 `fma` 内部处理了特殊值，但开发者在使用 `fma` 的结果时，仍然需要注意 NaN 和无穷大的传播。

4. **没有启用编译器的 FMA 优化:**  即使硬件支持 FMA 指令，编译器也可能默认不使用。开发者需要检查编译选项，确保启用了 FMA 相关的优化，例如 `-mfma` (GCC/Clang)。

**Android Framework 或 NDK 如何到达这里，作为调试线索:**

1. **应用层 (Java/Kotlin):**  Android 应用通常使用 Java 或 Kotlin 编写。如果需要进行底层的数学运算，可以通过 JNI (Java Native Interface) 调用 C/C++ 代码。

2. **NDK (Native Development Kit):**  NDK 允许开发者在 Android 应用中使用 C 和 C++ 代码。在 NDK 代码中，可以像标准的 C 库一样包含 `<math.h>` 并调用 `fma` 函数。

3. **C/C++ 运行时库 (Bionic):**  当 NDK 代码调用 `fma` 时，它实际上调用的是 Android 系统提供的 C 运行时库 Bionic 中的实现。`s_fma.c` 就是 Bionic 中 `libm` 库的一部分。

4. **共享库加载 (Dynamic Linker):**  当应用启动或首次调用到 `libm.so` 中的函数时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 `libm.so` 到进程的内存空间，并解析和重定位符号。

**调试线索:**

* **断点调试:** 在 NDK 代码中，可以使用调试器（如 LLDB）设置断点，单步执行到 `fma` 函数的调用。然后，可以进一步步入 `libm.so` 的 `fma` 实现进行调试。
* **查看汇编代码:** 可以查看 `fma` 函数编译后的汇编代码，了解编译器是否使用了内置的 FMA 指令，以及软件实现的具体指令序列。
* **`strace`:** 使用 `strace` 命令可以跟踪应用的系统调用，包括共享库的加载过程，可以观察 `libm.so` 是否被加载。
* **`dladdr`:** 在运行时，可以使用 `dladdr` 函数查找给定地址所属的共享库和符号信息，可以用来确认 `fma` 函数的地址是否指向 `libm.so` 中的代码。
* **日志输出:** 在 NDK 代码中添加日志输出，可以追踪 `fma` 函数的输入和输出值，帮助理解计算过程。

总而言之，`s_fma.c` 文件在 Android 系统中扮演着提供高精度浮点数乘加运算的重要角色，它通过软件或硬件方式实现了 `fma` 函数，并被上层应用和框架通过 NDK 和 Bionic 库调用。理解其实现原理有助于开发者更好地利用浮点数运算，并进行相关的性能优化和调试。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_fma.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005-2011 David Schultz <das@FreeBSD.ORG>
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

#include <fenv.h>
#include <float.h>
#include <math.h>

#include "math_private.h"

#ifdef USE_BUILTIN_FMA
double
fma(double x, double y, double z)
{
	return (__builtin_fma(x, y, z));
}
#else
/*
 * A struct dd represents a floating-point number with twice the precision
 * of a double.  We maintain the invariant that "hi" stores the 53 high-order
 * bits of the result.
 */
struct dd {
	double hi;
	double lo;
};

/*
 * Compute a+b exactly, returning the exact result in a struct dd.  We assume
 * that both a and b are finite, but make no assumptions about their relative
 * magnitudes.
 */
static inline struct dd
dd_add(double a, double b)
{
	struct dd ret;
	double s;

	ret.hi = a + b;
	s = ret.hi - a;
	ret.lo = (a - (ret.hi - s)) + (b - s);
	return (ret);
}

/*
 * Compute a+b, with a small tweak:  The least significant bit of the
 * result is adjusted into a sticky bit summarizing all the bits that
 * were lost to rounding.  This adjustment negates the effects of double
 * rounding when the result is added to another number with a higher
 * exponent.  For an explanation of round and sticky bits, see any reference
 * on FPU design, e.g.,
 *
 *     J. Coonen.  An Implementation Guide to a Proposed Standard for
 *     Floating-Point Arithmetic.  Computer, vol. 13, no. 1, Jan 1980.
 */
static inline double
add_adjusted(double a, double b)
{
	struct dd sum;
	uint64_t hibits, lobits;

	sum = dd_add(a, b);
	if (sum.lo != 0) {
		EXTRACT_WORD64(hibits, sum.hi);
		if ((hibits & 1) == 0) {
			/* hibits += (int)copysign(1.0, sum.hi * sum.lo) */
			EXTRACT_WORD64(lobits, sum.lo);
			hibits += 1 - ((hibits ^ lobits) >> 62);
			INSERT_WORD64(sum.hi, hibits);
		}
	}
	return (sum.hi);
}

/*
 * Compute ldexp(a+b, scale) with a single rounding error. It is assumed
 * that the result will be subnormal, and care is taken to ensure that
 * double rounding does not occur.
 */
static inline double
add_and_denormalize(double a, double b, int scale)
{
	struct dd sum;
	uint64_t hibits, lobits;
	int bits_lost;

	sum = dd_add(a, b);

	/*
	 * If we are losing at least two bits of accuracy to denormalization,
	 * then the first lost bit becomes a round bit, and we adjust the
	 * lowest bit of sum.hi to make it a sticky bit summarizing all the
	 * bits in sum.lo. With the sticky bit adjusted, the hardware will
	 * break any ties in the correct direction.
	 *
	 * If we are losing only one bit to denormalization, however, we must
	 * break the ties manually.
	 */
	if (sum.lo != 0) {
		EXTRACT_WORD64(hibits, sum.hi);
		bits_lost = -((int)(hibits >> 52) & 0x7ff) - scale + 1;
		if ((bits_lost != 1) ^ (int)(hibits & 1)) {
			/* hibits += (int)copysign(1.0, sum.hi * sum.lo) */
			EXTRACT_WORD64(lobits, sum.lo);
			hibits += 1 - (((hibits ^ lobits) >> 62) & 2);
			INSERT_WORD64(sum.hi, hibits);
		}
	}
	return (ldexp(sum.hi, scale));
}

/*
 * Compute a*b exactly, returning the exact result in a struct dd.  We assume
 * that both a and b are normalized, so no underflow or overflow will occur.
 * The current rounding mode must be round-to-nearest.
 */
static inline struct dd
dd_mul(double a, double b)
{
	static const double split = 0x1p27 + 1.0;
	struct dd ret;
	double ha, hb, la, lb, p, q;

	p = a * split;
	ha = a - p;
	ha += p;
	la = a - ha;

	p = b * split;
	hb = b - p;
	hb += p;
	lb = b - hb;

	p = ha * hb;
	q = ha * lb + la * hb;

	ret.hi = p + q;
	ret.lo = p - ret.hi + q + la * lb;
	return (ret);
}

/*
 * Fused multiply-add: Compute x * y + z with a single rounding error.
 *
 * We use scaling to avoid overflow/underflow, along with the
 * canonical precision-doubling technique adapted from:
 *
 *	Dekker, T.  A Floating-Point Technique for Extending the
 *	Available Precision.  Numer. Math. 18, 224-242 (1971).
 *
 * This algorithm is sensitive to the rounding precision.  FPUs such
 * as the i387 must be set in double-precision mode if variables are
 * to be stored in FP registers in order to avoid incorrect results.
 * This is the default on FreeBSD, but not on many other systems.
 *
 * Hardware instructions should be used on architectures that support it,
 * since this implementation will likely be several times slower.
 */
double
fma(double x, double y, double z)
{
	double xs, ys, zs, adj;
	struct dd xy, r;
	int oround;
	int ex, ey, ez;
	int spread;

	/*
	 * Handle special cases. The order of operations and the particular
	 * return values here are crucial in handling special cases involving
	 * infinities, NaNs, overflows, and signed zeroes correctly.
	 */
	if (x == 0.0 || y == 0.0)
		return (x * y + z);
	if (z == 0.0)
		return (x * y);
	if (!isfinite(x) || !isfinite(y))
		return (x * y + z);
	if (!isfinite(z))
		return (z);

	xs = frexp(x, &ex);
	ys = frexp(y, &ey);
	zs = frexp(z, &ez);
	oround = fegetround();
	spread = ex + ey - ez;

	/*
	 * If x * y and z are many orders of magnitude apart, the scaling
	 * will overflow, so we handle these cases specially.  Rounding
	 * modes other than FE_TONEAREST are painful.
	 */
	if (spread < -DBL_MANT_DIG) {
		feraiseexcept(FE_INEXACT);
		if (!isnormal(z))
			feraiseexcept(FE_UNDERFLOW);
		switch (oround) {
		case FE_TONEAREST:
			return (z);
		case FE_TOWARDZERO:
			if ((x > 0.0) ^ (y < 0.0) ^ (z < 0.0))
				return (z);
			else
				return (nextafter(z, 0));
		case FE_DOWNWARD:
			if ((x > 0.0) ^ (y < 0.0))
				return (z);
			else
				return (nextafter(z, -INFINITY));
		default:	/* FE_UPWARD */
			if ((x > 0.0) ^ (y < 0.0))
				return (nextafter(z, INFINITY));
			else
				return (z);
		}
	}
	if (spread <= DBL_MANT_DIG * 2)
		zs = ldexp(zs, -spread);
	else
		zs = copysign(DBL_MIN, zs);

	fesetround(FE_TONEAREST);
	/* work around clang issue #8472 */
	volatile double vxs = xs;

	/*
	 * Basic approach for round-to-nearest:
	 *
	 *     (xy.hi, xy.lo) = x * y		(exact)
	 *     (r.hi, r.lo)   = xy.hi + z	(exact)
	 *     adj = xy.lo + r.lo		(inexact; low bit is sticky)
	 *     result = r.hi + adj		(correctly rounded)
	 */
	xy = dd_mul(vxs, ys);
	r = dd_add(xy.hi, zs);

	spread = ex + ey;

	if (r.hi == 0.0 && xy.lo == 0) {
		/*
		 * When the addends cancel to 0, ensure that the result has
		 * the correct sign.
		 */
		fesetround(oround);
		volatile double vzs = zs; /* XXX gcc CSE bug workaround */
		return (xy.hi + vzs);
	}

	if (oround != FE_TONEAREST) {
		/*
		 * There is no need to worry about double rounding in directed
		 * rounding modes.
		 */
		fesetround(oround);
		/* work around clang issue #8472 */
		volatile double vrlo = r.lo;
		adj = vrlo + xy.lo;
		return (ldexp(r.hi + adj, spread));
	}

	adj = add_adjusted(r.lo, xy.lo);
	if (spread + ilogb(r.hi) > -1023)
		return (ldexp(r.hi + adj, spread));
	else
		return (add_and_denormalize(r.hi, adj, spread));
}
#endif /* !USE_BUILTIN_FMA */

#if (LDBL_MANT_DIG == 53)
__weak_reference(fma, fmal);
#endif

"""

```
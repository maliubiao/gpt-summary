Response:
My thought process for analyzing the `s_fmal.c` file went through these stages:

1. **Identify the Core Function:** The filename `s_fmal.c` and the prominent function `fmal(long double x, long double y, long double z)` immediately pointed to the core functionality: the fused multiply-add operation.

2. **Understand the Header:**  The initial comment block provides important context:  BSD-2-Clause license, copyright information, and the origin within FreeBSD. The `#include` directives signal dependencies on standard math and floating-point libraries (`fenv.h`, `float.h`, `math.h`) and a local header `fpmath.h`. This hints at the file implementing a standard math function, potentially with custom floating-point handling.

3. **Dissect Data Structures:** The `struct dd` definition was the next critical piece. The comment "represents a floating-point number with twice the precision of a long double" and the names `hi` and `lo` strongly suggest a double-double representation used for intermediate calculations with higher precision.

4. **Analyze Helper Functions:**  I then examined the static inline functions:
    * `dd_add`:  Clearly performs exact addition of two `long double` values, storing the result in the `dd` structure. The comment explains the algorithm used to compute the low-order part.
    * `add_adjusted`:  Modifies the result of `dd_add` by setting a sticky bit. The comment referencing Coonen's work is a significant clue about its purpose: mitigating double rounding issues.
    * `add_and_denormalize`: Handles addition where the result might be subnormal. The detailed comment about adjusting the sticky bit and handling the single-bit loss case is crucial for understanding its role in preserving accuracy near zero.
    * `dd_mul`: Implements exact multiplication using a splitting technique (likely Dekker's method) to calculate the high and low parts of the product. The `#if LDBL_MANT_DIG == ...` block shows it adapts to different precisions of `long double`.

5. **Deep Dive into `fmal`:** This is the main function. I focused on understanding its structure:
    * **Special Case Handling:** The initial `if` conditions deal with zero inputs, NaNs, and infinities. The comments highlight the importance of the order of operations for correctness.
    * **Scaling:** The use of `frexpl` and `ldexpl` suggests a strategy to prevent overflow and underflow during intermediate calculations. The `spread` variable is key to this scaling.
    * **Handling Large Differences:** The `if (spread < -LDBL_MANT_DIG)` block addresses scenarios where the magnitudes of `x * y` and `z` differ significantly. The different rounding mode cases are handled explicitly.
    * **Double-Double Arithmetic:** The core calculation uses `dd_mul` and `dd_add` to perform the multiplication and addition with higher precision.
    * **Rounding Mode Handling:** The code carefully handles different rounding modes (`FE_TONEAREST`, `FE_TOWARDZERO`, `FE_DOWNWARD`, `FE_UPWARD`). The `add_adjusted` function is used specifically for round-to-nearest.
    * **Denormalization Handling:** The `add_and_denormalize` function is invoked when the final result is close to zero.
    * **Workarounds:** The comments about "clang issue #8472" and "gcc CSE bug workaround" indicate the presence of compiler-specific problems that needed to be addressed.

6. **Infer Functionality and Relationships:** Based on the code and comments, I deduced the primary function is implementing the fused multiply-add operation (`x * y + z`) with a single rounding error, crucial for numerical stability and accuracy. The helper functions are building blocks to achieve this with higher internal precision and careful handling of rounding and special cases. The connection to Android is through `libm`, the math library.

7. **Address Specific Requirements:** I then systematically went through the prompt's requests:
    * **Functionality:** Summarized the core purpose of `fmal` and its helper functions.
    * **Android Relevance:** Explained its role in `libm` and how applications use it.
    * **Libc Function Implementation:**  Detailed the logic within each function, focusing on the double-double arithmetic, scaling, and rounding.
    * **Dynamic Linker:** Since the code itself doesn't directly involve dynamic linking, I explained the general linking process for `libm.so`. I provided a sample SO layout and described the resolution of symbols.
    * **Logical Reasoning:**  I constructed simple examples to illustrate the behavior of `fmal`, particularly around precision and rounding.
    * **Common Errors:** I focused on potential pitfalls like assuming standard `a * b + c` will produce the same result and issues with floating-point comparisons.
    * **Android Framework/NDK:** I outlined the typical call path from an Android app using the NDK to the `fmal` implementation in `libm.so`.

8. **Refine and Organize:** Finally, I organized the information logically, using clear headings and bullet points to present the analysis effectively. I ensured the explanations were detailed yet accessible. I paid attention to the specific details requested in the prompt, such as providing a sample SO layout and discussing debugging.

This iterative process of reading the code, understanding its components, connecting them to the broader context of a math library, and then addressing the specific questions in the prompt allowed me to generate a comprehensive analysis of the `s_fmal.c` file.
好的，让我们详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/s_fmal.c` 这个文件。

**功能列举**

`s_fmal.c` 文件实现了 `fmal` 函数，即 **浮点数的融合乘加运算 (fused multiply-add)**。 这个函数计算 `x * y + z`，并只进行 **一次舍入**。

更具体地说，该文件还包含一些辅助函数，用于支持 `fmal` 的高精度计算：

* **`struct dd`:**  定义了一个结构体，用于表示双倍精度的浮点数。它由两个 `long double` 组成，`hi` 存储高位部分，`lo` 存储低位部分。这是一种常见的实现高精度计算的方法。
* **`dd_add(long double a, long double b)`:**  精确计算两个 `long double` 类型的 `a` 和 `b` 的和，并将结果以 `struct dd` 的形式返回。它利用一些巧妙的技巧来避免舍入误差，从而得到精确的和。
* **`add_adjusted(long double a, long double b)`:**  计算 `a + b`，并在结果的最低有效位设置一个“粘滞位”。这个粘滞位总结了所有因舍入而丢失的位。这种调整可以抵消双重舍入的影响，尤其是在将结果加到具有更高指数的另一个数时。
* **`add_and_denormalize(long double a, long double b, int scale)`:**  计算 `ldexp(a + b, scale)`，即先计算 `a + b`，然后乘以 2 的 `scale` 次幂。这个函数专门用于处理结果是次正规数的情况，并仔细避免双重舍入。
* **`dd_mul(long double a, long double b)`:**  精确计算两个 `long double` 类型的 `a` 和 `b` 的积，并将结果以 `struct dd` 的形式返回。它也采用了一些技巧来实现精确的乘法。

**与 Android 功能的关系及举例**

`fmal` 函数是标准 C 库 (`libc`) 中 `math.h` 头文件声明的函数之一。在 Android 中，`libc` 的实现是 Bionic。因此，这个文件直接提供了 Android 系统中 `fmal` 函数的实现。

**举例说明：**

任何需要在 Android 上进行精确浮点数乘加运算的程序都会间接使用到这个函数。这包括：

* **科学计算应用:**  例如进行物理模拟、数据分析等需要高精度计算的应用。
* **图形渲染引擎:**  在进行矩阵运算、向量运算时，`fmal` 可以提高精度和性能。
* **机器学习框架:**  在进行模型训练和推理时，涉及到大量的浮点数运算，`fmal` 可以提升计算精度。

**例如，在 Android NDK 中使用 `fmal`：**

```c
#include <math.h>
#include <stdio.h>

int main() {
  long double x = 1.23L;
  long double y = 4.56L;
  long double z = 7.89L;

  long double result = fmal(x, y, z);

  printf("fmal(%Lf, %Lf, %Lf) = %Lf\n", x, y, z, result);
  return 0;
}
```

这个简单的 NDK 程序直接调用了 `fmal` 函数。当这个程序在 Android 设备上运行时，它将链接到 `libm.so`，并执行 `s_fmal.c` 中实现的 `fmal` 函数。

**libc 函数的实现细节**

让我们逐个详细解释这些函数的功能是如何实现的：

**1. `struct dd`**

* **功能:**  定义双倍精度浮点数的结构。
* **实现:**  简单地包含两个 `long double` 类型的成员 `hi` 和 `lo`。`hi` 存储数值的高位部分，`lo` 存储低位部分，使得 `hi + lo` 能够更精确地表示原始数值。

**2. `dd_add(long double a, long double b)`**

* **功能:**  精确计算 `a + b`。
* **实现:**  采用了 **Knuth 的双倍精度加法算法** 或类似的技巧。
    * 首先计算 `ret.hi = a + b`，这会进行标准的浮点数加法，可能存在舍入误差。
    * 然后，通过一些巧妙的代数运算，计算出舍入误差并存储在 `ret.lo` 中。
    * 关键在于 `s = ret.hi - a`，这计算的是 `b` 的一个近似值。
    * 接着， `(a - (ret.hi - s))` 计算的是 `a - (a + b - a)`，即 `-b` 的误差。
    * `(b - s)` 计算的是 `b - b` 的误差。
    * 两者相加，`ret.lo = (a - (ret.hi - s)) + (b - s)`，最终得到的就是加法的误差部分。

**3. `add_adjusted(long double a, long double b)`**

* **功能:**  计算 `a + b`，并设置粘滞位。
* **实现:**
    * 首先调用 `dd_add(a, b)` 得到精确的和 `sum`。
    * 如果 `sum.lo` 不为零，说明存在精度损失。
    * 通过 `union IEEEl2bits u; u.e = sum.hi;`，将 `sum.hi` 的位模式解释为一个 IEEE 754 长双精度浮点数。
    * `(u.bits.manl & 1) == 0` 检查 `sum.hi` 的最低有效位是否为 0。
    * `nextafterl(sum.hi, INFINITY * sum.lo)`  根据 `sum.lo` 的符号，将 `sum.hi` 向正无穷或负无穷方向移动一个最小单位。如果 `sum.lo` 是正的，相当于向上舍入；如果 `sum.lo` 是负的，相当于向下舍入。这相当于设置了粘滞位。

**4. `add_and_denormalize(long double a, long double b, int scale)`**

* **功能:**  计算 `ldexp(a + b, scale)`，并处理次正规数。
* **实现:**
    * 首先使用 `dd_add(a, b)` 计算精确的和 `sum`。
    * 计算由于归一化可能损失的位数 `bits_lost = -u.bits.exp - scale + 1;`。
    * 如果损失的位数大于 1，则像 `add_adjusted` 那样设置粘滞位，以避免双重舍入。
    * 如果只损失一位，则需要手动处理舍入。 `(bits_lost != 1) ^ (int)(u.bits.manl & 1)` 这个条件判断是否需要向上舍入。
    * 最后使用 `ldexp(sum.hi, scale)` 进行缩放。

**5. `dd_mul(long double a, long double b)`**

* **功能:**  精确计算 `a * b`。
* **实现:**  采用了 **Dekker 算法** 或类似的 **拆分算法**。
    * 使用一个特定的 `split` 值（例如 `0x1p32L + 1.0` 或 `0x1p57L + 1.0`，取决于 `LDBL_MANT_DIG`，即长双精度的尾数位数），将 `a` 和 `b` 分解成高位部分 (`ha`, `hb`) 和低位部分 (`la`, `lb`)。
    * 计算部分积 `p = ha * hb` 和 `q = ha * lb + la * hb`。
    * 精确的积的高位部分 `ret.hi = p + q`。
    * 精确的积的低位部分 `ret.lo = p - ret.hi + q + la * lb`。  这里也利用了一些技巧来提取误差部分。

**6. `fmal(long double x, long double y, long double z)`**

* **功能:**  计算 `x * y + z`，只进行一次舍入。
* **实现:**
    * **处理特殊情况:**  首先检查输入是否为 0、无穷大或 NaN，并根据 IEEE 754 标准处理这些情况。
    * **缩放:**  为了避免中间计算的溢出或下溢，对 `x`、`y` 和 `z` 进行缩放，记录它们的指数 (`ex`, `ey`, `ez`)。
    * **处理数量级差异过大的情况:** 如果 `x * y` 和 `z` 的数量级相差太大，直接返回 `z` 并设置相应的异常标志。
    * **设置舍入模式为最近舍入:**  使用 `fesetround(FE_TONEAREST)` 确保中间计算使用最近舍入模式。
    * **精确计算乘积:**  使用 `dd_mul(vxs, ys)` 计算 `x * y` 的精确结果，存储在 `xy.hi` 和 `xy.lo` 中。
    * **精确计算加法:**  使用 `dd_add(xy.hi, zs)` 计算 `xy.hi + z` 的精确结果，存储在 `r.hi` 和 `r.lo` 中。
    * **处理加法结果为零的情况:**  如果加法结果为零，需要确保符号的正确性。
    * **处理非最近舍入模式:**  如果当前的舍入模式不是最近舍入，则不需要担心双重舍入，直接计算 `r.hi + r.lo + xy.lo` 并进行缩放。
    * **处理最近舍入模式:**  使用 `add_adjusted(r.lo, xy.lo)` 计算低位部分的和，并设置粘滞位。
    * **最终结果:**  将高位部分和调整后的低位部分相加，并进行反向缩放，得到最终的融合乘加结果。如果结果接近于零，则使用 `add_and_denormalize` 处理次正规数。

**涉及 dynamic linker 的功能**

`s_fmal.c` 本身的代码并不直接涉及 dynamic linker 的功能。它只是一个实现了 `fmal` 函数的源文件。dynamic linker 的作用在于将这个函数编译成的机器码链接到需要它的程序中。

**SO 布局样本 (libm.so)**

```
libm.so (共享库文件)
├── .text        (代码段，包含 fmal 等函数的机器码)
│   ├── fmal:    (fmal 函数的机器码)
│   ├── ...       (其他数学函数的机器码)
├── .rodata      (只读数据段，例如常量)
├── .data        (可读写数据段，例如全局变量)
├── .bss         (未初始化数据段)
├── .dynsym      (动态符号表，包含导出的符号，如 fmal)
├── .dynstr      (动态字符串表，包含符号名称)
├── .plt         (过程链接表，用于延迟绑定)
├── .got.plt     (全局偏移表，用于存储外部符号的地址)
└── ...
```

**链接的处理过程**

1. **编译:**  `s_fmal.c` 被编译器编译成包含 `fmal` 函数机器码的目标文件 (例如 `s_fmal.o`)。
2. **链接到 libm.so:**  这个目标文件与其他实现了 `libm` 中其他数学函数的目标文件一起被链接器链接成共享库 `libm.so`。在链接过程中，`fmal` 这样的导出函数会被添加到 `.dynsym` (动态符号表) 中。
3. **程序编译:** 当一个 Android 应用程序或 NDK 程序使用了 `math.h` 中的 `fmal` 函数时，编译器会生成对 `fmal` 函数的未定义引用。
4. **动态链接:**  当程序在 Android 设备上启动时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载程序依赖的共享库，包括 `libm.so`。
5. **符号解析:** dynamic linker 会查找 `libm.so` 的 `.dynsym` 表，找到 `fmal` 符号的定义。
6. **重定位:** dynamic linker 会更新程序代码中的 `fmal` 函数调用地址，使其指向 `libm.so` 中 `fmal` 函数的实际地址。这个过程通常通过 `.plt` 和 `.got.plt` 来实现，以支持延迟绑定（第一次调用时才解析符号）。

**假设输入与输出 (逻辑推理)**

假设我们调用 `fmal(1.0L, 2.0L, 3.0L)`：

* **输入:** `x = 1.0L`, `y = 2.0L`, `z = 3.0L`
* **计算过程:**
    * `x * y` 的精确结果是 `2.0L`。
    * `x * y + z` 的精确结果是 `2.0L + 3.0L = 5.0L`。
* **输出:** `5.0L`。由于结果可以直接用浮点数精确表示，因此 `fmal` 的结果与直接计算 `1.0L * 2.0L + 3.0L` 的结果相同。

再假设我们调用 `fmal(0.1L, 0.2L, 0.3L)`，这里可能会涉及到舍入误差：

* **输入:** `x = 0.1L`, `y = 0.2L`, `z = 0.3L`
* **计算过程:**
    * `0.1L` 和 `0.2L` 在二进制浮点数中可能无法精确表示，因此 `0.1L * 0.2L` 的计算会产生舍入误差。
    * `fmal` 会尽可能精确地计算 `0.1L * 0.2L`，然后将其与 `0.3L` 相加，并只进行一次最终的舍入。
* **输出:**  `fmal(0.1L, 0.2L, 0.3L)` 的结果会比 `0.1L * 0.2L + 0.3L` 的结果更精确，因为它只进行一次舍入。

**用户或编程常见的使用错误**

* **误以为 `fmal(x, y, z)` 等价于 `x * y + z`:**  虽然数学上等价，但在浮点数运算中，`fmal` 只进行一次舍入，而 `x * y + z` 会进行两次舍入（一次乘法，一次加法）。在某些情况下，这会导致精度差异。
* **不理解浮点数舍入误差的影响:**  即使使用 `fmal`，浮点数运算仍然存在固有的舍入误差。程序员需要理解这些误差的来源和影响，并采取适当的措施来减轻它们。
* **在不需要高精度的情况下使用 `fmal`:**  `fmal` 的计算成本可能比普通的乘加运算略高。如果对精度要求不高，使用普通的乘加运算可能更有效率。
* **不正确地处理特殊值 (NaN, Infinity):**  虽然 `fmal` 内部会处理这些特殊值，但程序员在使用时也需要注意输入和输出中可能出现的这些值。

**Android Framework 或 NDK 如何到达这里 (调试线索)**

1. **应用层 (Java/Kotlin):**  Android 应用如果需要进行高性能的数学计算，可能会使用 NDK 调用本地代码。
2. **NDK 代码 (C/C++):**  NDK 代码中，程序员会包含 `<math.h>` 头文件，并调用 `fmal` 函数。
3. **链接器:**  在编译 NDK 代码时，链接器会将 NDK 代码链接到 Android 系统提供的共享库，包括 `libm.so`。
4. **libm.so:**  当 NDK 代码调用 `fmal` 时，实际上会调用 `libm.so` 中实现的 `fmal` 函数。
5. **s_fmal.c:**  `libm.so` 中的 `fmal` 函数的实现就位于 `bionic/libm/upstream-freebsd/lib/msun/src/s_fmal.c` 文件中。

**调试线索:**

* **使用 NDK 调试器 (gdb, lldb):**  可以在 NDK 代码中设置断点，单步执行到 `fmal` 函数的调用。然后，可以 step into (`si`) 进入 `libm.so` 的 `fmal` 实现。
* **查看汇编代码:**  可以使用 `objdump` 或类似的工具查看 `libm.so` 中 `fmal` 函数的汇编代码，了解其具体的执行流程。
* **使用 `strace` 或 `ltrace`:**  可以跟踪应用程序的系统调用和库函数调用，查看是否调用了 `fmal` 函数。
* **查看 `maps` 文件:**  在程序运行时，可以查看 `/proc/<pid>/maps` 文件，了解 `libm.so` 加载的地址范围，从而确定 `fmal` 函数在内存中的位置。

总而言之，`s_fmal.c` 是 Android Bionic 中实现高精度浮点数融合乘加运算的关键文件。它通过一些精巧的算法和数据结构，确保了 `fmal` 函数的正确性和精度，并在 Android 系统的各种场景中发挥着重要作用。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_fmal.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
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

#include "fpmath.h"

/*
 * A struct dd represents a floating-point number with twice the precision
 * of a long double.  We maintain the invariant that "hi" stores the high-order
 * bits of the result.
 */
struct dd {
	long double hi;
	long double lo;
};

/*
 * Compute a+b exactly, returning the exact result in a struct dd.  We assume
 * that both a and b are finite, but make no assumptions about their relative
 * magnitudes.
 */
static inline struct dd
dd_add(long double a, long double b)
{
	struct dd ret;
	long double s;

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
static inline long double
add_adjusted(long double a, long double b)
{
	struct dd sum;
	union IEEEl2bits u;

	sum = dd_add(a, b);
	if (sum.lo != 0) {
		u.e = sum.hi;
		if ((u.bits.manl & 1) == 0)
			sum.hi = nextafterl(sum.hi, INFINITY * sum.lo);
	}
	return (sum.hi);
}

/*
 * Compute ldexp(a+b, scale) with a single rounding error. It is assumed
 * that the result will be subnormal, and care is taken to ensure that
 * double rounding does not occur.
 */
static inline long double
add_and_denormalize(long double a, long double b, int scale)
{
	struct dd sum;
	int bits_lost;
	union IEEEl2bits u;

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
		u.e = sum.hi;
		bits_lost = -u.bits.exp - scale + 1;
		if ((bits_lost != 1) ^ (int)(u.bits.manl & 1))
			sum.hi = nextafterl(sum.hi, INFINITY * sum.lo);
	}
	return (ldexp(sum.hi, scale));
}

/*
 * Compute a*b exactly, returning the exact result in a struct dd.  We assume
 * that both a and b are normalized, so no underflow or overflow will occur.
 * The current rounding mode must be round-to-nearest.
 */
static inline struct dd
dd_mul(long double a, long double b)
{
#if LDBL_MANT_DIG == 64
	static const long double split = 0x1p32L + 1.0;
#elif LDBL_MANT_DIG == 113
	static const long double split = 0x1p57L + 1.0;
#endif
	struct dd ret;
	long double ha, hb, la, lb, p, q;

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
 */
long double
fmal(long double x, long double y, long double z)
{
	long double xs, ys, zs, adj;
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

	xs = frexpl(x, &ex);
	ys = frexpl(y, &ey);
	zs = frexpl(z, &ez);
	oround = fegetround();
	spread = ex + ey - ez;

	/*
	 * If x * y and z are many orders of magnitude apart, the scaling
	 * will overflow, so we handle these cases specially.  Rounding
	 * modes other than FE_TONEAREST are painful.
	 */
	if (spread < -LDBL_MANT_DIG) {
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
				return (nextafterl(z, 0));
		case FE_DOWNWARD:
			if ((x > 0.0) ^ (y < 0.0))
				return (z);
			else
				return (nextafterl(z, -INFINITY));
		default:	/* FE_UPWARD */
			if ((x > 0.0) ^ (y < 0.0))
				return (nextafterl(z, INFINITY));
			else
				return (z);
		}
	}
	if (spread <= LDBL_MANT_DIG * 2)
		zs = ldexpl(zs, -spread);
	else
		zs = copysignl(LDBL_MIN, zs);

	fesetround(FE_TONEAREST);
	/* work around clang issue #8472 */
	volatile long double vxs = xs;

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
		volatile long double vzs = zs; /* XXX gcc CSE bug workaround */
		return (xy.hi + vzs);
	}

	if (oround != FE_TONEAREST) {
		/*
		 * There is no need to worry about double rounding in directed
		 * rounding modes.
		 */
		fesetround(oround);
		/* work around clang issue #8472 */
		volatile long double vrlo = r.lo;
		adj = vrlo + xy.lo;
		return (ldexpl(r.hi + adj, spread));
	}

	adj = add_adjusted(r.lo, xy.lo);
	if (spread + ilogbl(r.hi) > -16383)
		return (ldexpl(r.hi + adj, spread));
	else
		return (add_and_denormalize(r.hi, adj, spread));
}
```
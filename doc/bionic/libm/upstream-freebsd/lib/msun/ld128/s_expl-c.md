Response:
Let's break down the thought process for analyzing this C code and generating the comprehensive response.

**1. Initial Understanding & Goal Setting:**

The first step is to understand the context. This is the `s_expl.c` file within the `ld128` directory of Android's Bionic libc, specifically the math library. The filename suggests it's related to the `expl` function (exponential function). The request asks for a breakdown of its functionality, its relation to Android, explanations of libc functions, dynamic linker details, logic reasoning, error examples, and how to reach this code during debugging. This sets the scope and goals.

**2. High-Level Functionality Identification:**

Quickly scanning the code reveals two main functions: `expll(long double x)` and `expm1l(long double x)`. The comments and structure suggest these are implementations of the exponential function `e^x` and the exponential minus one function `e^x - 1`, specifically for `long double` precision.

**3. Deeper Dive into `expll`:**

* **Exceptional Cases:** The code starts by handling edge cases (infinity, NaN, very large/small numbers). This is standard practice in robust mathematical function implementations. These checks use bitwise manipulation on the `long double` representation.
* **Scaling and the `__k_expl` function:**  The code calls `__k_expl`. The prefix `__` often indicates an internal helper function. The variables `hi`, `lo`, and `k` suggest this helper likely performs some kind of argument reduction, separating the input into a fractional part (`hi`, `lo`) and an integer scaling factor (`k`).
* **Scaling by 2<sup>k</sup>:**  The logic after calling `__k_expl` clearly involves multiplying by powers of 2 (using `twopk` and `twom10000`). This confirms the argument reduction idea.
* **Performance Considerations:** The comment about "sparc64 multiplication" hints at optimization strategies that might be relevant in different architectures.

**4. Deeper Dive into `expm1l`:**

* **Similar Initial Filtering:**  Like `expll`, `expm1l` begins with handling exceptional cases.
* **Taylor Series Approximation (for small |x|):** The `if (T1 < x && x < T2)` block strongly suggests a Taylor series approximation for `e^x - 1` when `x` is close to zero. The constants `C3` through `C18` and `D3` through `D17` are clearly coefficients of these series. The splitting into two ranges (`x < T3` and `otherwise`) likely optimizes accuracy or performance.
* **Argument Reduction (for larger |x|):**  The code then uses a different approach, involving `rnint`, `irint`, `L1`, `L2`, and `tbl`. This strongly indicates a more sophisticated argument reduction technique using precomputed tables. The "Reduce x to (k*ln2 + endpoint[n2] + r1 + r2)" comment confirms this.
* **Table Lookups:** The `tbl` array is used. This table likely contains precomputed values related to `exp` at specific points to aid in the reduction.
* **Reconstruction:** After reduction, the result is reconstructed by multiplying with `twopk` (powers of 2).

**5. Identifying Android Relevance:**

The crucial point is that this code *is* part of Android's core math library. Any Android application using standard math functions like `expl` or `expm1l` (or functions that internally rely on them) will ultimately execute this code. Examples include:
    * Games using physics simulations.
    * Financial apps performing calculations.
    * Scientific applications.
    * Even seemingly simple apps that might use these functions indirectly through other libraries.

**6. Explaining libc Functions:**

The request asks for detailed explanations of libc functions. The core functions here are `expll` and `expm1l` themselves. The internal helper `__k_expl` is also important. The analysis so far provides clues about their roles.

**7. Dynamic Linker Aspects:**

This requires knowledge of how shared libraries (`.so` files) are loaded and linked in Android. The thought process here involves:

* **Understanding SO Structure:** Recalling the basic components of an ELF shared object (header, code sections, data sections, symbol tables, relocation tables, etc.).
* **Symbol Resolution:** How the dynamic linker finds the addresses of functions and variables needed by a library. Distinguishing between global symbols, local symbols, and how relocation entries guide the linker.
* **Lazy vs. Eager Binding:** Knowing that Android uses lazy binding by default for performance reasons.

**8. Logic Reasoning and Assumptions:**

This involves analyzing specific code paths and their expected behavior. For example:

* **Small `x` in `expll`:**  If `|x|` is very small, the function returns `1 + x`. The assumption is that for very small values, the higher-order terms of the Taylor series are negligible.
* **Large Positive `x` in `expll`:**  The function returns `huge * huge`, implying overflow.
* **Argument Reduction in `expm1l`:** The assumption is that the precomputed tables and the reduction formulas accurately approximate the exponential function.

**9. Common Errors:**

Thinking about typical mistakes programmers make when using exponential functions:

* **Overflow/Underflow:**  Not handling cases where the result is too large or too small to represent.
* **Precision Issues:**  Expecting infinite precision, which is not possible with floating-point numbers.
* **Incorrect Input Ranges:**  Not understanding the domain of the function.

**10. Debugging Path:**

This requires understanding the Android software stack:

* **NDK:**  Native code directly uses libc.
* **Android Framework (Java):**  Framework classes might call native methods through JNI, which eventually leads to libc.
* **System Calls:**  Ultimately, libc interacts with the kernel through system calls.

The debugging process involves using tools like `adb`, `gdb` (or lldb), and potentially analyzing stack traces or using logging.

**11. Structuring the Response:**

Finally, organizing the information logically is crucial. Using headings, bullet points, code snippets, and clear explanations makes the response easier to understand. The order of the sections should flow naturally, starting with basic functionality and moving to more advanced topics like dynamic linking and debugging.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus on the specific algorithms used for the Taylor series and argument reduction.
* **Correction:**  While interesting, the request asks for a broader overview. Focus on the *purpose* and *how* these techniques fit into the overall function.
* **Initial thought:** Go deep into the bitwise manipulation of floating-point numbers.
* **Correction:** Provide a basic explanation but avoid getting lost in excessive detail, as it might not be the primary focus of the request.
* **Continuously check:** Ensure each part of the original prompt is addressed.

By following this structured thought process, combined with knowledge of C, math libraries, operating systems, and the Android ecosystem, one can generate a comprehensive and accurate response to the given prompt.
好的，让我们深入分析一下 `bionic/libm/upstream-freebsd/lib/msun/ld128/s_expl.c` 这个文件。

**文件功能：**

这个文件 `s_expl.c` 实现了 `expl(long double x)` 和 `expm1l(long double x)` 这两个函数，它们分别是：

* **`expl(long double x)`:** 计算自然指数函数 e<sup>x</sup> 的值，输入参数 `x` 是 `long double` 类型（扩展精度浮点数）。
* **`expm1l(long double x)`:** 计算 e<sup>x</sup> - 1 的值，输入参数 `x` 是 `long double` 类型。这个函数在 `x` 接近 0 时能提供比直接计算 `expl(x) - 1` 更高的精度，因为它可以避免有效数字的损失。

**与 Android 功能的关系及举例：**

这个文件是 Android Bionic 库的一部分，而 Bionic 是 Android 操作系统的 C 标准库、数学库和动态链接器。因此，`s_expl.c` 中实现的 `expll` 和 `expm1l` 函数是 Android 系统中基础的数学运算功能。任何需要计算指数的 Android 应用或系统组件都会间接地或直接地使用到这些函数。

**举例说明：**

* **科学计算 App:** 一个进行科学计算的 Android 应用可能需要计算各种指数函数，例如物理模拟、金融模型等。这些应用会通过 NDK (Native Development Kit) 调用 C/C++ 代码，而这些 C/C++ 代码会链接到 Bionic 库，最终调用到 `expll` 或 `expm1l`。
* **图形渲染引擎:** 一些图形渲染算法可能涉及到指数运算，例如计算光照衰减、曲线插值等。如果这些渲染引擎使用 native 代码实现，它们同样会使用 Bionic 提供的数学函数。
* **Android Framework 内部:** Android Framework 的某些底层组件，例如虚拟机 (ART) 或一些系统服务，在内部实现时可能需要进行数学计算，包括指数运算。

**详细解释 libc 函数的实现：**

让我们分别看一下 `expll` 和 `expm1l` 的实现逻辑：

**`expl(long double x)` 的实现：**

1. **处理特殊情况:**
   - 检查 `x` 是否为 NaN (非数字)、正无穷或负无穷。对于这些情况，直接返回相应的结果。
   - 检查 `x` 是否超出 `long double` 能表示的范围（过大或过小），并返回 `huge * huge` 或 `tiny * tiny` 来表示溢出或下溢。
   - 对于非常接近 0 的 `x`，直接返回 `1 + x`，这是一种优化的近似处理。

2. **参数约减 (`__k_expl`)：**
   - 调用内部函数 `__k_expl(x, &hi, &lo, &k)`。这个函数是核心，它的作用是将输入的 `x` 约减到一个较小的范围内，并计算出一个整数 `k`，使得 e<sup>x</sup> ≈ e<sup>r</sup> * 2<sup>k</sup>，其中 `r` 由 `hi` 和 `lo` 两个 `long double` 数值表示，构成高低部分，共同表示约减后的值。
   - `__k_expl` 的具体实现（在 `k_expl.h` 中声明，通常在 `k_expl.c` 中定义）会使用各种数学技巧，例如将 `x` 分解为整数部分和小数部分，利用对数的性质，并可能使用查找表来加速计算。

3. **计算 e<sup>r</sup> 的近似值:**
   - 使用 `SUM2P(hi, lo)` 将 `hi` 和 `lo` 合并成一个更精确的 `long double` 值 `t`，它近似等于 e<sup>r</sup>。

4. **乘以 2<sup>k</sup> 进行缩放:**
   - 根据 `k` 的值，将 `t` 乘以 2<sup>k</sup>。这里需要注意处理 `k` 过大或过小的情况，以避免溢出或下溢。
   - 如果 `k` 在 `LDBL_MIN_EXP` 以上，直接构造一个表示 2<sup>k</sup> 的 `long double` 值 `twopk` 并相乘。
   - 如果 `k` 很小，为了避免直接计算很小的 2 的幂导致的精度损失，会乘以一个较小的 2 的幂和一个预定义的常数 `twom10000`。

**`expm1l(long double x)` 的实现：**

`expm1l` 的实现比 `expll` 更复杂，因为它需要处理 `x` 接近 0 的情况，以保证精度。

1. **处理特殊情况:**
   - 类似于 `expll`，处理 NaN、正负无穷以及超出范围的 `x`。
   - 对于较大的负 `x`，返回 `tiny - 1`，近似于 -1。

2. **针对小 `x` 的泰勒展开:**
   - 如果 `x` 落在 `T1` 和 `T2` 之间（一个接近 0 的小区间），则使用泰勒展开来计算 e<sup>x</sup> - 1。
   - 代码中定义了多个常数 `C3` 到 `C18` 和 `D3` 到 `D17`，这些是泰勒展开式的系数。
   - 根据 `x` 的大小选择不同的多项式进行计算，以提高效率和精度。
   - 将 `x` 分解为高低部分 `x_hi` 和 `x_lo`，并计算 `x`<sup>2</sup> 的高低部分 `hx2_hi` 和 `hx2_lo`，以进行高精度计算。

3. **参数约减 (针对较大 `x`)：**
   - 如果 `x` 不在小区间内，则使用参数约减的方法。
   - 将 `x` 约减为 `k * ln(2) + endpoint[n2] + r1 + r2` 的形式，其中 `endpoint` 来自预计算的表格 `tbl`，`r1` 和 `r2` 是余项。
   - `fn` 是 `x / ln(2)` 的最接近整数，用于确定约减的步数。
   - `n2` 用于索引查找表 `tbl`。
   - `k` 是缩放因子。

4. **使用查找表 (`tbl`) 和多项式计算:**
   - `tbl` 数组存储了 e<sup>endpoint</sup> 的值及其相关信息，用于加速计算。
   - 使用多项式近似计算 e<sup>r1 + r2</sup>。

5. **乘以 2<sup>k</sup> 进行缩放:**
   - 根据 `k` 的值，将结果乘以 2<sup>k</sup>。

**dynamic linker 的功能：**

动态链接器 (通常是 `linker` 或 `ld-linux.so`) 的主要功能是在程序运行时加载共享库 (`.so` 文件) 并解析和链接符号。

**SO 布局样本：**

一个典型的 Android `.so` 文件（ELF 格式）的布局大致如下：

```
ELF Header
Program Headers (描述内存段，如代码段、数据段)
Section Headers (描述各个节，如 .text, .data, .symtab, .rel.dyn, .rel.plt)

.text        代码段 (机器指令)
.rodata      只读数据段 (常量字符串、只读变量)
.data        已初始化的可读写数据段 (全局变量、静态变量)
.bss         未初始化的可读写数据段 (全局变量、静态变量，在加载时清零)

.dynsym      动态符号表 (共享库导出的和导入的符号)
.symtab      符号表 (包含所有符号，包括本地符号)
.strtab      字符串表 (存储符号名称)
.dynstr      动态字符串表 (存储动态符号名称)

.rel.dyn     动态重定位表 (用于重定位数据段中的符号引用)
.rel.plt     过程链接表重定位表 (用于重定位函数调用)

.plt         过程链接表 (Procedure Linkage Table，用于延迟绑定)
.got.plt     全局偏移表 (Global Offset Table，存储被调用函数的实际地址)
```

**每种符号的处理过程：**

1. **全局符号 (Global Symbols):**
   - **导出符号 (Exported Symbols):** 这些是 `.so` 文件提供给其他共享库或可执行文件使用的符号（通常是函数和全局变量）。动态链接器会将这些符号添加到全局符号表中，使得其他模块可以找到它们。
   - **导入符号 (Imported Symbols):** 这些是 `.so` 文件依赖的其他共享库提供的符号。动态链接器需要在加载时找到提供这些符号的共享库，并解析它们的地址。

2. **本地符号 (Local Symbols):**
   - 这些符号在 `.so` 文件内部使用，对外部不可见。动态链接器主要在链接 `.so` 文件内部的符号引用时使用它们。

3. **符号解析和重定位：**
   - **加载时:** 动态链接器首先加载 `.so` 文件到内存中。
   - **符号解析:** 动态链接器遍历 `.rel.dyn` 和 `.rel.plt` 重定位表，找到需要重定位的符号引用。对于每个符号引用，它会在已加载的共享库的动态符号表 (`.dynsym`) 中查找符号的地址。
   - **重定位:** 找到符号的地址后，动态链接器会根据重定位条目的指示，修改内存中相应的地址，将其指向符号的实际地址。
   - **延迟绑定 (Lazy Binding):** 对于函数调用，Android 默认使用延迟绑定。这意味着函数地址的解析和重定位发生在第一次调用该函数时。过程链接表 (`.plt`) 和全局偏移表 (`.got.plt`) 用于实现延迟绑定。第一次调用时，`.plt` 中的代码会将控制权转移到动态链接器，动态链接器解析函数地址并更新 `.got.plt`，后续调用将直接通过 `.got.plt` 跳转到函数地址。

**假设输入与输出 (逻辑推理)：**

**对于 `expll`：**

* **假设输入:** `x = 1.0`
* **预期输出:** 近似于 e<sup>1</sup> ≈ 2.71828...

* **假设输入:** `x = 0.0`
* **预期输出:** e<sup>0</sup> = 1.0

* **假设输入:** `x = -infinity`
* **预期输出:** 0.0

* **假设输入:** `x = infinity`
* **预期输出:** infinity

**对于 `expm1l`：**

* **假设输入:** `x = 1.0`
* **预期输出:** e<sup>1</sup> - 1 ≈ 1.71828...

* **假设输入:** `x = 0.000001` (接近 0)
* **预期输出:**  约等于 0.000001，但会使用泰勒展开保证精度，避免 `expl(0.000001) - 1` 的精度损失。

* **假设输入:** `x = -infinity`
* **预期输出:** -1.0

**用户或编程常见的使用错误：**

1. **溢出/下溢:**
   - **错误示例:**  计算 `expll(1000)`，这会导致结果超出 `long double` 的表示范围，可能返回无穷大。
   - **错误示例:** 计算 `expll(-1000)`，这会导致结果非常接近 0，可能因为下溢而变成 0。
   - **说明:** 用户需要注意输入值的范围，避免指数运算结果超出数值类型的表示能力。

2. **精度问题:**
   - **错误示例:** 当 `x` 非常接近 0 时，使用 `expll(x) - 1` 计算 e<sup>x</sup> - 1。这可能导致有效数字的损失，因为 `expll(x)` 会非常接近 1，相减后高位数字会被消去。
   - **正确做法:**  对于接近 0 的 `x`，应该使用 `expm1l(x)`。

3. **误解函数功能:**
   - **错误示例:** 期望 `expll` 返回以 10 为底的指数值。
   - **说明:** `expll` 计算的是自然指数（以 e 为底）。如果需要计算其他底的指数，需要使用公式，例如 a<sup>x</sup> = e<sup>x * ln(a)</sup>。

**说明 Android Framework 或 NDK 如何一步步到达这里（作为调试线索）：**

1. **NDK 调用:**
   - 如果 Android 应用使用了 NDK 进行 native 开发，C/C++ 代码中直接包含了 `<math.h>` 头文件，并调用了 `expll` 或 `expm1l` 函数。
   - 编译器和链接器会将这些调用链接到 Bionic 库中的相应函数实现。
   - **调试线索:** 在 native 代码中使用 GDB 或 LLDB 进行调试，设置断点在 `expll` 或 `expm1l` 函数入口。

2. **Android Framework (Java) 调用:**
   - Android Framework 的某些 Java 类可能需要进行指数运算。
   - 这些 Java 类可能会调用 JNI (Java Native Interface) 方法，这些 JNI 方法是用 C/C++ 实现的，并且会调用 Bionic 库中的 `expll` 或 `expm1l`。
   - **调试线索:**
     - 找到 Java Framework 中进行指数运算的调用点。
     - 如果涉及到 JNI 调用，可以使用 JDWP (Java Debug Wire Protocol) 调试 Java 代码，并在 JNI 方法中设置断点。
     - 在 native 代码的 JNI 实现中，可以进一步使用 GDB 或 LLDB 调试到 `expll` 或 `expm1l`。
     - 可以使用 `adb logcat` 查看系统日志，特别是与 native 代码相关的日志输出。

3. **系统调用和库加载:**
   - 当应用或 Framework 组件首次调用 `expll` 或 `expm1l` 时，如果对应的 Bionic 库尚未加载，动态链接器会负责加载 `libm.so` (或其他包含这些函数的共享库)。
   - 动态链接器会解析符号，并将函数调用重定向到 `s_expl.c` 中编译生成的机器码。
   - **调试线索:** 可以使用 `adb shell dumpsys meminfo <进程名>` 查看进程加载的共享库。可以使用 `ldd <可执行文件或.so文件>` 查看其依赖的共享库。

**总结:**

`bionic/libm/upstream-freebsd/lib/msun/ld128/s_expl.c` 文件是 Android 系统中用于高精度指数运算的关键组成部分。理解其功能和实现细节对于开发高性能、高精度的 Android 应用至关重要。在调试过程中，需要结合 NDK、Framework 和动态链接器的知识，才能有效地定位到这些底层的数学函数调用。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/s_expl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009-2013 Steven G. Kargl
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
 *
 * Optimized by Bruce D. Evans.
 */

/*
 * ld128 version of s_expl.c.  See ../ld80/s_expl.c for most comments.
 */

#include <float.h>

#include "fpmath.h"
#include "math.h"
#include "math_private.h"
#include "k_expl.h"

/* XXX Prevent compilers from erroneously constant folding these: */
static const volatile long double
huge = 0x1p10000L,
tiny = 0x1p-10000L;

static const long double
twom10000 = 0x1p-10000L;

static const long double
/* log(2**16384 - 0.5) rounded towards zero: */
/* log(2**16384 - 0.5 + 1) rounded towards zero for expm1l() is the same: */
o_threshold =  11356.523406294143949491931077970763428L,
/* log(2**(-16381-64-1)) rounded towards zero: */
u_threshold = -11433.462743336297878837243843452621503L;

long double
expl(long double x)
{
	union IEEEl2bits u;
	long double hi, lo, t, twopk;
	int k;
	uint16_t hx, ix;

	/* Filter out exceptional cases. */
	u.e = x;
	hx = u.xbits.expsign;
	ix = hx & 0x7fff;
	if (ix >= BIAS + 13) {		/* |x| >= 8192 or x is NaN */
		if (ix == BIAS + LDBL_MAX_EXP) {
			if (hx & 0x8000)  /* x is -Inf or -NaN */
				RETURNF(-1 / x);
			RETURNF(x + x);	/* x is +Inf or +NaN */
		}
		if (x > o_threshold)
			RETURNF(huge * huge);
		if (x < u_threshold)
			RETURNF(tiny * tiny);
	} else if (ix < BIAS - 114) {	/* |x| < 0x1p-114 */
		RETURNF(1 + x);		/* 1 with inexact iff x != 0 */
	}

	ENTERI();

	twopk = 1;
	__k_expl(x, &hi, &lo, &k);
	t = SUM2P(hi, lo);

	/* Scale by 2**k. */
	/*
	 * XXX sparc64 multiplication was so slow that scalbnl() is faster,
	 * but performance on aarch64 and riscv hasn't yet been quantified.
	 */
	if (k >= LDBL_MIN_EXP) {
		if (k == LDBL_MAX_EXP)
			RETURNI(t * 2 * 0x1p16383L);
		SET_LDBL_EXPSIGN(twopk, BIAS + k);
		RETURNI(t * twopk);
	} else {
		SET_LDBL_EXPSIGN(twopk, BIAS + k + 10000);
		RETURNI(t * twopk * twom10000);
	}
}

/*
 * Our T1 and T2 are chosen to be approximately the points where method
 * A and method B have the same accuracy.  Tang's T1 and T2 are the
 * points where method A's accuracy changes by a full bit.  For Tang,
 * this drop in accuracy makes method A immediately less accurate than
 * method B, but our larger INTERVALS makes method A 2 bits more
 * accurate so it remains the most accurate method significantly
 * closer to the origin despite losing the full bit in our extended
 * range for it.
 *
 * Split the interval [T1, T2] into two intervals [T1, T3] and [T3, T2].
 * Setting T3 to 0 would require the |x| < 0x1p-113 condition to appear
 * in both subintervals, so set T3 = 2**-5, which places the condition
 * into the [T1, T3] interval.
 *
 * XXX we now do this more to (partially) balance the number of terms
 * in the C and D polys than to avoid checking the condition in both
 * intervals.
 *
 * XXX these micro-optimizations are excessive.
 */
static const double
T1 = -0.1659,				/* ~-30.625/128 * log(2) */
T2 =  0.1659,				/* ~30.625/128 * log(2) */
T3 =  0.03125;

/*
 * Domain [-0.1659, 0.03125], range ~[2.9134e-44, 1.8404e-37]:
 * |(exp(x)-1-x-x**2/2)/x - p(x)| < 2**-122.03
 *
 * XXX none of the long double C or D coeffs except C10 is correctly printed.
 * If you re-print their values in %.35Le format, the result is always
 * different.  For example, the last 2 digits in C3 should be 59, not 67.
 * 67 is apparently from rounding an extra-precision value to 36 decimal
 * places.
 */
static const long double
C3  =  1.66666666666666666666666666666666667e-1L,
C4  =  4.16666666666666666666666666666666645e-2L,
C5  =  8.33333333333333333333333333333371638e-3L,
C6  =  1.38888888888888888888888888891188658e-3L,
C7  =  1.98412698412698412698412697235950394e-4L,
C8  =  2.48015873015873015873015112487849040e-5L,
C9  =  2.75573192239858906525606685484412005e-6L,
C10 =  2.75573192239858906612966093057020362e-7L,
C11 =  2.50521083854417203619031960151253944e-8L,
C12 =  2.08767569878679576457272282566520649e-9L,
C13 =  1.60590438367252471783548748824255707e-10L;

/*
 * XXX this has 1 more coeff than needed.
 * XXX can start the double coeffs but not the double mults at C10.
 * With my coeffs (C10-C17 double; s = best_s):
 * Domain [-0.1659, 0.03125], range ~[-1.1976e-37, 1.1976e-37]:
 * |(exp(x)-1-x-x**2/2)/x - p(x)| ~< 2**-122.65
 */
static const double
C14 =  1.1470745580491932e-11,		/*  0x1.93974a81dae30p-37 */
C15 =  7.6471620181090468e-13,		/*  0x1.ae7f3820adab1p-41 */
C16 =  4.7793721460260450e-14,		/*  0x1.ae7cd18a18eacp-45 */
C17 =  2.8074757356658877e-15,		/*  0x1.949992a1937d9p-49 */
C18 =  1.4760610323699476e-16;		/*  0x1.545b43aabfbcdp-53 */

/*
 * Domain [0.03125, 0.1659], range ~[-2.7676e-37, -1.0367e-38]:
 * |(exp(x)-1-x-x**2/2)/x - p(x)| < 2**-121.44
 */
static const long double
D3  =  1.66666666666666666666666666666682245e-1L,
D4  =  4.16666666666666666666666666634228324e-2L,
D5  =  8.33333333333333333333333364022244481e-3L,
D6  =  1.38888888888888888888887138722762072e-3L,
D7  =  1.98412698412698412699085805424661471e-4L,
D8  =  2.48015873015873015687993712101479612e-5L,
D9  =  2.75573192239858944101036288338208042e-6L,
D10 =  2.75573192239853161148064676533754048e-7L,
D11 =  2.50521083855084570046480450935267433e-8L,
D12 =  2.08767569819738524488686318024854942e-9L,
D13 =  1.60590442297008495301927448122499313e-10L;

/*
 * XXX this has 1 more coeff than needed.
 * XXX can start the double coeffs but not the double mults at D11.
 * With my coeffs (D11-D16 double):
 * Domain [0.03125, 0.1659], range ~[-1.1980e-37, 1.1980e-37]:
 * |(exp(x)-1-x-x**2/2)/x - p(x)| ~< 2**-122.65
 */
static const double
D14 =  1.1470726176204336e-11,		/*  0x1.93971dc395d9ep-37 */
D15 =  7.6478532249581686e-13,		/*  0x1.ae892e3D16fcep-41 */
D16 =  4.7628892832607741e-14,		/*  0x1.ad00Dfe41feccp-45 */
D17 =  3.0524857220358650e-15;		/*  0x1.D7e8d886Df921p-49 */

long double
expm1l(long double x)
{
	union IEEEl2bits u, v;
	long double hx2_hi, hx2_lo, q, r, r1, t, twomk, twopk, x_hi;
	long double x_lo, x2;
	double dr, dx, fn, r2;
	int k, n, n2;
	uint16_t hx, ix;

	/* Filter out exceptional cases. */
	u.e = x;
	hx = u.xbits.expsign;
	ix = hx & 0x7fff;
	if (ix >= BIAS + 7) {		/* |x| >= 128 or x is NaN */
		if (ix == BIAS + LDBL_MAX_EXP) {
			if (hx & 0x8000)  /* x is -Inf or -NaN */
				RETURNF(-1 / x - 1);
			RETURNF(x + x);	/* x is +Inf or +NaN */
		}
		if (x > o_threshold)
			RETURNF(huge * huge);
		/*
		 * expm1l() never underflows, but it must avoid
		 * unrepresentable large negative exponents.  We used a
		 * much smaller threshold for large |x| above than in
		 * expl() so as to handle not so large negative exponents
		 * in the same way as large ones here.
		 */
		if (hx & 0x8000)	/* x <= -128 */
			RETURNF(tiny - 1);	/* good for x < -114ln2 - eps */
	}

	ENTERI();

	if (T1 < x && x < T2) {
		x2 = x * x;
		dx = x;

		if (x < T3) {
			if (ix < BIAS - 113) {	/* |x| < 0x1p-113 */
				/* x (rounded) with inexact if x != 0: */
				RETURNI(x == 0 ? x :
				    (0x1p200 * x + fabsl(x)) * 0x1p-200);
			}
			q = x * x2 * C3 + x2 * x2 * (C4 + x * (C5 + x * (C6 +
			    x * (C7 + x * (C8 + x * (C9 + x * (C10 +
			    x * (C11 + x * (C12 + x * (C13 +
			    dx * (C14 + dx * (C15 + dx * (C16 +
			    dx * (C17 + dx * C18))))))))))))));
		} else {
			q = x * x2 * D3 + x2 * x2 * (D4 + x * (D5 + x * (D6 +
			    x * (D7 + x * (D8 + x * (D9 + x * (D10 +
			    x * (D11 + x * (D12 + x * (D13 +
			    dx * (D14 + dx * (D15 + dx * (D16 +
			    dx * D17)))))))))))));
		}

		x_hi = (float)x;
		x_lo = x - x_hi;
		hx2_hi = x_hi * x_hi / 2;
		hx2_lo = x_lo * (x + x_hi) / 2;
		if (ix >= BIAS - 7)
			RETURNI((hx2_hi + x_hi) + (hx2_lo + x_lo + q));
		else
			RETURNI(x + (hx2_lo + q + hx2_hi));
	}

	/* Reduce x to (k*ln2 + endpoint[n2] + r1 + r2). */
	fn = rnint((double)x * INV_L);
	n = irint(fn);
	n2 = (unsigned)n % INTERVALS;
	k = n >> LOG2_INTERVALS;
	r1 = x - fn * L1;
	r2 = fn * -L2;
	r = r1 + r2;

	/* Prepare scale factor. */
	v.e = 1;
	v.xbits.expsign = BIAS + k;
	twopk = v.e;

	/*
	 * Evaluate lower terms of
	 * expl(endpoint[n2] + r1 + r2) = tbl[n2] * expl(r1 + r2).
	 */
	dr = r;
	q = r2 + r * r * (A2 + r * (A3 + r * (A4 + r * (A5 + r * (A6 +
	    dr * (A7 + dr * (A8 + dr * (A9 + dr * A10))))))));

	t = tbl[n2].lo + tbl[n2].hi;

	if (k == 0) {
		t = SUM2P(tbl[n2].hi - 1, tbl[n2].lo * (r1 + 1) + t * q +
		    tbl[n2].hi * r1);
		RETURNI(t);
	}
	if (k == -1) {
		t = SUM2P(tbl[n2].hi - 2, tbl[n2].lo * (r1 + 1) + t * q +
		    tbl[n2].hi * r1);
		RETURNI(t / 2);
	}
	if (k < -7) {
		t = SUM2P(tbl[n2].hi, tbl[n2].lo + t * (q + r1));
		RETURNI(t * twopk - 1);
	}
	if (k > 2 * LDBL_MANT_DIG - 1) {
		t = SUM2P(tbl[n2].hi, tbl[n2].lo + t * (q + r1));
		if (k == LDBL_MAX_EXP)
			RETURNI(t * 2 * 0x1p16383L - 1);
		RETURNI(t * twopk - 1);
	}

	v.xbits.expsign = BIAS - k;
	twomk = v.e;

	if (k > LDBL_MANT_DIG - 1)
		t = SUM2P(tbl[n2].hi, tbl[n2].lo - twomk + t * (q + r1));
	else
		t = SUM2P(tbl[n2].hi - twomk, tbl[n2].lo + t * (q + r1));
	RETURNI(t * twopk);
}
```
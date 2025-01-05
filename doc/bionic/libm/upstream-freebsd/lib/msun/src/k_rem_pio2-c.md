Response:
Let's break down the thought process for analyzing this C code. The goal is to understand its functionality, its relationship to Android, and various implementation details.

**1. Initial Understanding and Overview:**

* **Identify the File:**  The filename `k_rem_pio2.c` and the directory `bionic/libm/upstream-freebsd/lib/msun/src/` immediately suggest a math library function related to modulo operations with pi/2. The `k_` prefix often indicates a "kernel" or low-level implementation.
* **Read the Header Comments:** The initial block of comments is crucial. It clearly states the purpose: computing `y = x - N*pi/2` such that `|y| < pi/2` and returning the last three digits of `N`. This identifies the core mathematical operation.
* **High-Level Algorithm:** The comments mention the method involves computing integer and fractional parts of `(2/pi)*x` without a full multiplication. This hints at an optimization strategy for handling large input values. The use of an array `ipio2[]` representing `2/pi` further reinforces this.
* **Input/Output Parameters:** The description of `x`, `y`, `e0`, `nx`, and `prec` is essential for understanding how the function is used. The breakdown of `x` into 24-bit chunks and the different precisions for `y` are key details.

**2. Dissecting the Functionality:**

* **Key Variables:** The comments explain the purpose of local variables like `jk`, `jz`, `jv`, `q`, `PIo2`, `f`, `iq`, `fq`, and `ih`. Understanding these is crucial for following the code's logic.
* **Constants:**  The definitions of `init_jk`, `ipio2`, `PIo2`, `zero`, `one`, `two24`, and `twon24` provide valuable context. `ipio2` (for 2/pi) and `PIo2` (for pi/2) are central to the calculation.
* **Step-by-Step Analysis of the Code:**  Go through the code block by block, relating it back to the comments and variable descriptions.
    * **Initialization:**  `jk` is initialized based on `prec`.
    * **Determining Indices:** `jx`, `jv`, and `q0` are calculated to select the appropriate portions of the `ipio2` table.
    * **Setting Up `f`:** The `f` array is populated with values from `ipio2`.
    * **Computing `q`:**  This is where the core multiplication of `x` and `2/pi` (represented by `f`) happens in chunks.
    * **`recompute` Label:**  This indicates a potential iterative process if initial calculations are insufficient.
    * **Distilling `q` into `iq`:**  This step extracts the integer parts of the product.
    * **Computing `n`:** The integer part of the result is calculated.
    * **Handling `ih`:** This variable tracks the sign and magnitude of the fractional part.
    * **Recomputation Check:** The code checks if more precision is needed.
    * **Chopping Zero Terms:** Optimization to remove unnecessary calculations.
    * **Converting `iq` to Floating-Point:** The integer chunks are converted back to floating-point values.
    * **Computing `PIo2 * q`:**  The product is calculated using the pre-computed `PIo2` table.
    * **Compressing `fq` into `y`:** The final result is assembled based on the desired precision.
* **Flow of Logic:**  Trace the execution path, especially the conditional statements and loops. Understanding how the code handles different precisions is important.

**3. Relating to Android and System Aspects:**

* **Bionic and `libm`:** Recognize that this code is part of Android's math library (`libm`). This means it's a fundamental building block for numerical computations on Android.
* **NDK Usage:** Consider how developers using the NDK might call functions that rely on `__kernel_rem_pio2` indirectly (e.g., `sin`, `cos`, `tan`).
* **Dynamic Linking:**  The request about the dynamic linker requires a separate line of thinking. This involves understanding how shared libraries (`.so` files) are loaded and how symbols are resolved.

**4. Examples, Errors, and Debugging:**

* **Hypothetical Inputs and Outputs:**  Think about simple cases to test understanding (e.g., `x` close to `pi/2`, `x` close to `pi`).
* **Common Errors:**  Consider what mistakes a programmer might make when using functions that depend on this low-level routine (e.g., passing incorrect precision, dealing with very large or small numbers).
* **Debugging Path:**  Outline how you would trace a function call from an Android app or NDK code down to this specific function.

**5. Structuring the Answer:**

* **Organize by Request:**  Address each part of the prompt systematically (functionality, Android relation, libc details, dynamic linker, logic, errors, debugging).
* **Clarity and Detail:** Explain concepts clearly and provide sufficient detail without being overly verbose.
* **Code Snippets:**  Include relevant code snippets to illustrate points.
* **Examples:** Use concrete examples to make abstract concepts easier to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like a straightforward modulo operation."  **Correction:**  The comments and code reveal it's more complex due to the need for high precision and efficiency, especially for large inputs. The chunking strategy is a key optimization.
* **Initial thought:** "The `ipio2` table is just a constant." **Correction:**  The comments explain that its size needs to be sufficient based on the input exponent, implying a potential limitation and the need for expansion if extremely large inputs are encountered.
* **Dynamic Linker:** Realizing that the prompt asks specifically about the *dynamic* linker, not just linking in general, focuses the explanation on runtime symbol resolution and the structure of shared libraries.

By following this detailed analysis and refinement process, we can produce a comprehensive and accurate explanation of the provided C code.
好的，让我们深入分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/k_rem_pio2.c` 这个文件。

**功能概述**

`__kernel_rem_pio2` 函数的主要功能是计算一个正数 `x` 除以 π/2 后的余数，并将结果表示为 `y = x - N * pi/2` 的形式，其中 `|y| < pi/2`，并返回整数 `N` 的最后三位（模 8 的结果）。

更具体地说，它不是直接进行高精度的乘法和减法，而是采用一种优化的方法来计算 `(2/pi) * x` 的整数部分（模 8）和分数部分。这种方法避免了对非常大的整数部分进行完整计算，使得运算量与输入 `x` 的指数大小无关。

**与 Android 功能的关系**

这个函数是 Android 系统 C 库 `bionic` 的一部分，位于数学库 `libm` 中。这意味着它被用于 Android 系统中各种需要进行浮点数运算的场景。

**举例说明:**

任何涉及到三角函数（如 `sin`, `cos`, `tan`）的计算，最终都可能依赖于这个函数。例如：

1. **Android Framework:** 当 Android Framework 中的某些图形渲染或动画效果需要计算角度时，可能会调用 `Math.sin()` 或 `Math.cos()`。这些 Java 函数会通过 JNI 调用到 `libm` 中对应的 C 函数 (`sin`, `cos`)，而这些 C 函数内部可能会调用 `__kernel_rem_pio2` 来将角度归约到 `[-pi/2, pi/2]` 的范围内，以便进行更精确的计算。

2. **NDK 开发:** 使用 Android NDK 进行原生代码开发的程序员，如果调用了 `<math.h>` 中的 `sin()`, `cos()`, `tan()` 等函数，那么最终也会执行到 `libm` 中的实现，进而可能调用 `__kernel_rem_pio2`。

**libc 函数的实现解释**

这个 C 文件本身并没有直接实现标准的 POSIX libc 函数，它是一个 `libm` 内部的辅助函数。但是，它使用了几个 C 标准库函数：

1. **`scalbn(double x, int n)`:**
   - **功能:** 计算 `x * 2^n`。
   - **实现:**  通常通过操作浮点数的指数部分来实现，避免了直接进行乘法运算，提高了效率。例如，如果 `x` 的二进制表示为 `m * 2^e`，那么 `scalbn(x, n)` 的结果的指数部分将是 `e + n`，尾数 `m` 不变。

2. **`floor(double x)`:**
   - **功能:** 返回不大于 `x` 的最大整数。
   - **实现:**  一种常见的实现方法是检查浮点数的符号位和指数部分。对于正数，将小数部分截断为零。对于负数，如果存在小数部分，则将整数部分减一。

**`__kernel_rem_pio2` 函数的详细实现**

下面对 `__kernel_rem_pio2` 函数的实现进行更详细的解释：

1. **常量初始化:**
   - `init_jk`:  根据不同的精度 (`prec`) 初始化 `jk` 的值，`jk` 控制了计算中 `ipio2` 数组所需的项数。精度越高，需要的项数越多。
   - `ipio2`:  这是一个包含 2/π 的高精度表示的整数数组。每个元素存储了 2/π 的 24 位。
   - `PIo2`:  这是一个包含 π/2 的高精度表示的浮点数数组，用于最终计算余数。
   - `zero`, `one`, `two24`, `twon24`: 一些常用的浮点数常量。

2. **计算初始参数:**
   - 根据输入参数 `e0` (x[0] 的缩放指数) 和 `nx` (x 数组的维度)，计算 `jx`, `jv`, `q0` 等索引和参数，这些参数用于选择 `ipio2` 数组中相关的部分。

3. **计算 `q` 数组:**
   - `q` 数组用于存储 `x` 和 `2/pi` 的部分乘积。它通过将 `x` 的不同 24 位片段与 `ipio2` 的相应片段相乘并累加得到。

4. **`recompute` 标签和重新计算:**
   - 这部分处理精度不足的情况。如果初始计算的精度不够，需要使用 `ipio2` 数组的更多项进行重新计算。

5. **将 `q` 数组提炼为 `iq` 数组:**
   - `iq` 数组存储了 `q` 数组中每个元素的 24 位整数部分。

6. **计算 `n` (整数部分):**
   - 根据 `iq` 数组的值计算 `x / (pi/2)` 的整数部分 `n`。这里使用了模 8 的技巧，只关心最后三位。

7. **处理 `ih` (符号指示):**
   - `ih` 用于指示余数的符号。如果 `q` 大于 0.5，则需要对结果进行调整。

8. **检查是否需要重新计算:**
   - 如果计算出的余数接近于零，并且 `iq` 数组中还有非零的高位，则说明需要更高的精度，会跳转到 `recompute` 重新计算。

9. **截断零项:**
   - 如果余数恰好为零，则可以减少后续计算的项数。

10. **将整数 "位" 块转换为浮点数:**
    - 将 `iq` 数组中的整数值转换为浮点数，存储回 `q` 数组。

11. **计算 `PIo2 * q`:**
    - 使用预先计算的 `PIo2` 数组和 `q` 数组计算最终的余数。

12. **将 `fq` 压缩到 `y` 数组:**
    - 根据所需的精度 (`prec`)，将计算出的余数 `fq` 存储到输出数组 `y` 中。对于更高的精度，余数可能需要拆分成多个双精度浮点数。

13. **返回 `n & 7`:**
    - 返回整数部分 `n` 的最后三位（模 8 的结果）。

**dynamic linker 的功能**

Android 的动态链接器 (linker) 负责在程序运行时加载共享库 (`.so` 文件) 并解析符号。

**so 布局样本:**

一个典型的 `.so` 文件布局可能如下：

```
.dynamic (动态链接信息)
.hash (符号哈希表)
.dynsym (动态符号表)
.dynstr (动态字符串表)
.rel.dyn (数据段重定位表)
.rel.plt (过程链接表重定位表)
.plt (过程链接表)
.text (代码段)
.rodata (只读数据段)
.data (已初始化数据段)
.bss (未初始化数据段)
```

**每种符号的处理过程:**

1. **未定义符号 (Undefined Symbols):**  这些是在当前 `.so` 文件中引用，但在该文件中没有定义的符号。动态链接器需要在加载时找到这些符号的定义，通常在其他已加载的 `.so` 文件或主程序中。
   - **处理过程:** 当加载一个 `.so` 文件时，linker 会遍历其 `.dynsym` 表中的未定义符号。然后，它会在已经加载的共享库列表中查找匹配的已定义符号。如果找到，就将未定义符号的引用地址更新为已定义符号的地址（这个过程称为重定位）。如果在所有已加载的库中都找不到定义，则会报告链接错误。

2. **已定义符号 (Defined Symbols):** 这些是在当前 `.so` 文件中定义的符号，可以被其他 `.so` 文件引用。
   - **处理过程:** linker 将已定义符号的信息添加到全局符号表中。当其他 `.so` 文件需要链接到这些符号时，linker 可以从全局符号表中找到它们的地址。

3. **全局符号 (Global Symbols):**  通常，`.so` 文件中的函数和全局变量都是全局符号，可以被其他模块访问。
   - **处理过程:** 如上所述，全局符号会被添加到全局符号表中，以便其他模块可以找到并链接到它们。

4. **本地符号 (Local Symbols):** 这些符号的作用域仅限于定义它们的 `.so` 文件内部，不会被其他模块看到。
   - **处理过程:** 本地符号通常不会出现在 `.dynsym` 表中，或者会被特殊标记。动态链接器主要处理全局符号的链接。

**过程链接表 (PLT) 和全局偏移表 (GOT):**

对于函数符号的动态链接，通常会使用 PLT 和 GOT 来实现延迟绑定。

- **PLT:**  包含外部函数的桩代码。第一次调用外部函数时，PLT 中的代码会将控制权交给 linker。
- **GOT:**  包含外部函数的实际地址。初始时，GOT 中的条目指向 PLT 中的一段代码，当 linker 解析符号后，会将实际地址写入 GOT。

**`__kernel_rem_pio2` 的符号处理:**

- 如果 `__kernel_rem_pio2` 是在 `libm.so` 内部使用的（例如被 `sin`, `cos` 等函数调用），那么它可能是一个本地符号或者是一个非公开的全局符号。
- 如果 `__kernel_rem_pio2` 需要被其他 `.so` 文件直接调用（这种情况不太常见，因为它通常是一个内部辅助函数），那么它会是一个全局符号，需要被动态链接器解析。

**假设输入与输出 (逻辑推理)**

假设 `prec = 1` (双精度)，`x` 的值接近 `pi`。

**假设输入:**

- `x[0]`, `x[1]`: 表示接近 `pi` 的双精度数（根据 `x` 的拆分方式）。
- `e0`:  `x[0]` 的指数。
- `nx`: 2 (因为是双精度，`x` 分成两部分)。
- `prec`: 1 (双精度)。

**预期输出:**

- `y[0]`, `y[1]`:  表示 `pi - 1 * pi/2 = pi/2` 的结果，或者 `pi - 2 * pi/2 = 0` 的结果，由于 `|y| < pi/2`，所以结果会接近 `pi/2` 或 `-pi/2`。
- 返回值: `n & 7`，这里 `N` 可能是 1 或 2，所以返回值可能是 1 或 2。

**更具体的例子:**

假设 `x = 3.1415926535`，`pi/2 ≈ 1.5707963267`。
那么 `x / (pi/2) ≈ 2.0000000000`。
`N` 可能是 2。
`y = x - 2 * pi/2 = x - pi ≈ 0`。
返回值可能是 `2 & 7 = 2`。

**用户或编程常见的使用错误**

1. **不正确的精度参数 (`prec`):**  如果传递的 `prec` 值与实际输入的 `x` 数组大小不匹配，会导致计算错误或崩溃。例如，如果 `x` 只包含一个双精度数，但 `prec` 传递为 3 (quad 精度)，可能会导致访问越界。

2. **输入 `x` 为负数:**  该函数的注释明确指出输入值必须为正数。如果传入负数，行为是未定义的，可能会导致错误的计算结果。

3. **`e0` 值超出范围:**  注释中提到 `e0` 的值不能超过 16360，否则需要扩展 `ipio2` 表。超出此范围的输入可能会导致数组访问越界。

4. **误解返回值:**  用户可能会误以为返回值是完整的 `N`，但实际上它只返回 `N` 的最后三位（模 8）。

**Android Framework 或 NDK 如何到达这里 (调试线索)**

假设我们想调试 `Math.sin(angle)` 的实现：

1. **Java 代码:** Android 应用或 Framework 调用 `Math.sin(angle)`.
2. **JNI 调用:** `Math.sin()` 是一个 native 方法，它会通过 Java Native Interface (JNI) 调用到 Android 运行时环境 (ART)。
3. **`libm` 中的 `sin` 函数:** ART 会找到并执行 `libm.so` 中对应的 `sin` 函数实现。
   - 在 bionic 的 `libm` 源码中，你可以找到 `bionic/libm/upstream-freebsd/lib/msun/src/s_sin.c` 文件，其中实现了 `sin` 函数。
4. **角度归约:**  `sin` 函数通常需要将输入的角度归约到 `[-pi/2, pi/2]` 的范围内，以提高计算精度和效率。这步可能会调用 `__kernel_rem_pio2` 或类似的函数。
   - 你可以在 `s_sin.c` 中查找对 `__kernel_rem_pio2` 的调用，或者查看其调用的其他辅助函数，这些函数可能会间接调用 `__kernel_rem_pio2`.
5. **执行 `__kernel_rem_pio2`:**  如果需要进行角度归约，并且采用了 `__kernel_rem_pio2` 的算法，那么会执行到这个函数。

**调试步骤:**

- **使用 NDK 调试器:**  如果你在 NDK 代码中调用了 `sin()`, 可以使用 Android Studio 的 NDK 调试器来单步执行 C/C++ 代码，查看函数调用堆栈，直到进入 `__kernel_rem_pio2`。
- **日志输出:** 在 `libm` 的源码中添加日志输出 (例如使用 `__android_log_print`)，以跟踪函数的调用和变量的值。这需要重新编译 Android 系统或 `libm` 库。
- **源码分析:**  仔细阅读 `libm` 的源码，特别是 `s_sin.c`, `k_rem_pio2.c` 等相关文件，理解函数之间的调用关系。
- **反汇编:** 使用反汇编工具 (如 `objdump`, `IDA Pro`) 查看 `libm.so` 的汇编代码，可以更底层地了解函数的执行过程。

希望以上详细的分析能够帮助你理解 `bionic/libm/upstream-freebsd/lib/msun/src/k_rem_pio2.c` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/k_rem_pio2.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""

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

/*
 * __kernel_rem_pio2(x,y,e0,nx,prec)
 * double x[],y[]; int e0,nx,prec;
 * 
 * __kernel_rem_pio2 return the last three digits of N with 
 *		y = x - N*pi/2
 * so that |y| < pi/2.
 *
 * The method is to compute the integer (mod 8) and fraction parts of 
 * (2/pi)*x without doing the full multiplication. In general we
 * skip the part of the product that are known to be a huge integer (
 * more accurately, = 0 mod 8 ). Thus the number of operations are
 * independent of the exponent of the input.
 *
 * (2/pi) is represented by an array of 24-bit integers in ipio2[].
 *
 * Input parameters:
 * 	x[]	The input value (must be positive) is broken into nx 
 *		pieces of 24-bit integers in double precision format.
 *		x[i] will be the i-th 24 bit of x. The scaled exponent 
 *		of x[0] is given in input parameter e0 (i.e., x[0]*2^e0 
 *		match x's up to 24 bits.
 *
 *		Example of breaking a double positive z into x[0]+x[1]+x[2]:
 *			e0 = ilogb(z)-23
 *			z  = scalbn(z,-e0)
 *		for i = 0,1,2
 *			x[i] = floor(z)
 *			z    = (z-x[i])*2**24
 *
 *
 *	y[]	output result in an array of double precision numbers.
 *		The dimension of y[] is:
 *			24-bit  precision	1
 *			53-bit  precision	2
 *			64-bit  precision	2
 *			113-bit precision	3
 *		The actual value is the sum of them. Thus for 113-bit
 *		precision, one may have to do something like:
 *
 *		long double t,w,r_head, r_tail;
 *		t = (long double)y[2] + (long double)y[1];
 *		w = (long double)y[0];
 *		r_head = t+w;
 *		r_tail = w - (r_head - t);
 *
 *	e0	The exponent of x[0]. Must be <= 16360 or you need to
 *              expand the ipio2 table.
 *
 *	nx	dimension of x[]
 *
 *  	prec	an integer indicating the precision:
 *			0	24  bits (single)
 *			1	53  bits (double)
 *			2	64  bits (extended)
 *			3	113 bits (quad)
 *
 * External function:
 *	double scalbn(), floor();
 *
 *
 * Here is the description of some local variables:
 *
 * 	jk	jk+1 is the initial number of terms of ipio2[] needed
 *		in the computation. The minimum and recommended value
 *		for jk is 3,4,4,6 for single, double, extended, and quad.
 *		jk+1 must be 2 larger than you might expect so that our
 *		recomputation test works. (Up to 24 bits in the integer
 *		part (the 24 bits of it that we compute) and 23 bits in
 *		the fraction part may be lost to cancellation before we
 *		recompute.)
 *
 * 	jz	local integer variable indicating the number of 
 *		terms of ipio2[] used. 
 *
 *	jx	nx - 1
 *
 *	jv	index for pointing to the suitable ipio2[] for the
 *		computation. In general, we want
 *			( 2^e0*x[0] * ipio2[jv-1]*2^(-24jv) )/8
 *		is an integer. Thus
 *			e0-3-24*jv >= 0 or (e0-3)/24 >= jv
 *		Hence jv = max(0,(e0-3)/24).
 *
 *	jp	jp+1 is the number of terms in PIo2[] needed, jp = jk.
 *
 * 	q[]	double array with integral value, representing the
 *		24-bits chunk of the product of x and 2/pi.
 *
 *	q0	the corresponding exponent of q[0]. Note that the
 *		exponent for q[i] would be q0-24*i.
 *
 *	PIo2[]	double precision array, obtained by cutting pi/2
 *		into 24 bits chunks. 
 *
 *	f[]	ipio2[] in floating point 
 *
 *	iq[]	integer array by breaking up q[] in 24-bits chunk.
 *
 *	fq[]	final product of x*(2/pi) in fq[0],..,fq[jk]
 *
 *	ih	integer. If >0 it indicates q[] is >= 0.5, hence
 *		it also indicates the *sign* of the result.
 *
 */


/*
 * Constants:
 * The hexadecimal values are the intended ones for the following 
 * constants. The decimal values may be used, provided that the 
 * compiler will convert from decimal to binary accurately enough 
 * to produce the hexadecimal values shown.
 */

#include <float.h>

#include "math.h"
#include "math_private.h"

static const int init_jk[] = {3,4,4,6}; /* initial value for jk */

/*
 * Table of constants for 2/pi, 396 Hex digits (476 decimal) of 2/pi
 *
 *		integer array, contains the (24*i)-th to (24*i+23)-th 
 *		bit of 2/pi after binary point. The corresponding 
 *		floating value is
 *
 *			ipio2[i] * 2^(-24(i+1)).
 *
 * NB: This table must have at least (e0-3)/24 + jk terms.
 *     For quad precision (e0 <= 16360, jk = 6), this is 686.
 */
static const int32_t ipio2[] = {
0xA2F983, 0x6E4E44, 0x1529FC, 0x2757D1, 0xF534DD, 0xC0DB62, 
0x95993C, 0x439041, 0xFE5163, 0xABDEBB, 0xC561B7, 0x246E3A, 
0x424DD2, 0xE00649, 0x2EEA09, 0xD1921C, 0xFE1DEB, 0x1CB129, 
0xA73EE8, 0x8235F5, 0x2EBB44, 0x84E99C, 0x7026B4, 0x5F7E41, 
0x3991D6, 0x398353, 0x39F49C, 0x845F8B, 0xBDF928, 0x3B1FF8, 
0x97FFDE, 0x05980F, 0xEF2F11, 0x8B5A0A, 0x6D1F6D, 0x367ECF, 
0x27CB09, 0xB74F46, 0x3F669E, 0x5FEA2D, 0x7527BA, 0xC7EBE5, 
0xF17B3D, 0x0739F7, 0x8A5292, 0xEA6BFB, 0x5FB11F, 0x8D5D08, 
0x560330, 0x46FC7B, 0x6BABF0, 0xCFBC20, 0x9AF436, 0x1DA9E3, 
0x91615E, 0xE61B08, 0x659985, 0x5F14A0, 0x68408D, 0xFFD880, 
0x4D7327, 0x310606, 0x1556CA, 0x73A8C9, 0x60E27B, 0xC08C6B, 

#if LDBL_MAX_EXP > 1024
#if LDBL_MAX_EXP > 16384
#error "ipio2 table needs to be expanded"
#endif
0x47C419, 0xC367CD, 0xDCE809, 0x2A8359, 0xC4768B, 0x961CA6,
0xDDAF44, 0xD15719, 0x053EA5, 0xFF0705, 0x3F7E33, 0xE832C2,
0xDE4F98, 0x327DBB, 0xC33D26, 0xEF6B1E, 0x5EF89F, 0x3A1F35,
0xCAF27F, 0x1D87F1, 0x21907C, 0x7C246A, 0xFA6ED5, 0x772D30,
0x433B15, 0xC614B5, 0x9D19C3, 0xC2C4AD, 0x414D2C, 0x5D000C,
0x467D86, 0x2D71E3, 0x9AC69B, 0x006233, 0x7CD2B4, 0x97A7B4,
0xD55537, 0xF63ED7, 0x1810A3, 0xFC764D, 0x2A9D64, 0xABD770,
0xF87C63, 0x57B07A, 0xE71517, 0x5649C0, 0xD9D63B, 0x3884A7,
0xCB2324, 0x778AD6, 0x23545A, 0xB91F00, 0x1B0AF1, 0xDFCE19,
0xFF319F, 0x6A1E66, 0x615799, 0x47FBAC, 0xD87F7E, 0xB76522,
0x89E832, 0x60BFE6, 0xCDC4EF, 0x09366C, 0xD43F5D, 0xD7DE16,
0xDE3B58, 0x929BDE, 0x2822D2, 0xE88628, 0x4D58E2, 0x32CAC6,
0x16E308, 0xCB7DE0, 0x50C017, 0xA71DF3, 0x5BE018, 0x34132E,
0x621283, 0x014883, 0x5B8EF5, 0x7FB0AD, 0xF2E91E, 0x434A48,
0xD36710, 0xD8DDAA, 0x425FAE, 0xCE616A, 0xA4280A, 0xB499D3,
0xF2A606, 0x7F775C, 0x83C2A3, 0x883C61, 0x78738A, 0x5A8CAF,
0xBDD76F, 0x63A62D, 0xCBBFF4, 0xEF818D, 0x67C126, 0x45CA55,
0x36D9CA, 0xD2A828, 0x8D61C2, 0x77C912, 0x142604, 0x9B4612,
0xC459C4, 0x44C5C8, 0x91B24D, 0xF31700, 0xAD43D4, 0xE54929,
0x10D5FD, 0xFCBE00, 0xCC941E, 0xEECE70, 0xF53E13, 0x80F1EC,
0xC3E7B3, 0x28F8C7, 0x940593, 0x3E71C1, 0xB3092E, 0xF3450B,
0x9C1288, 0x7B20AB, 0x9FB52E, 0xC29247, 0x2F327B, 0x6D550C,
0x90A772, 0x1FE76B, 0x96CB31, 0x4A1679, 0xE27941, 0x89DFF4,
0x9794E8, 0x84E6E2, 0x973199, 0x6BED88, 0x365F5F, 0x0EFDBB,
0xB49A48, 0x6CA467, 0x427271, 0x325D8D, 0xB8159F, 0x09E5BC,
0x25318D, 0x3974F7, 0x1C0530, 0x010C0D, 0x68084B, 0x58EE2C,
0x90AA47, 0x02E774, 0x24D6BD, 0xA67DF7, 0x72486E, 0xEF169F,
0xA6948E, 0xF691B4, 0x5153D1, 0xF20ACF, 0x339820, 0x7E4BF5,
0x6863B2, 0x5F3EDD, 0x035D40, 0x7F8985, 0x295255, 0xC06437,
0x10D86D, 0x324832, 0x754C5B, 0xD4714E, 0x6E5445, 0xC1090B,
0x69F52A, 0xD56614, 0x9D0727, 0x50045D, 0xDB3BB4, 0xC576EA,
0x17F987, 0x7D6B49, 0xBA271D, 0x296996, 0xACCCC6, 0x5414AD,
0x6AE290, 0x89D988, 0x50722C, 0xBEA404, 0x940777, 0x7030F3,
0x27FC00, 0xA871EA, 0x49C266, 0x3DE064, 0x83DD97, 0x973FA3,
0xFD9443, 0x8C860D, 0xDE4131, 0x9D3992, 0x8C70DD, 0xE7B717,
0x3BDF08, 0x2B3715, 0xA0805C, 0x93805A, 0x921110, 0xD8E80F,
0xAF806C, 0x4BFFDB, 0x0F9038, 0x761859, 0x15A562, 0xBBCB61,
0xB989C7, 0xBD4010, 0x04F2D2, 0x277549, 0xF6B6EB, 0xBB22DB,
0xAA140A, 0x2F2689, 0x768364, 0x333B09, 0x1A940E, 0xAA3A51,
0xC2A31D, 0xAEEDAF, 0x12265C, 0x4DC26D, 0x9C7A2D, 0x9756C0,
0x833F03, 0xF6F009, 0x8C402B, 0x99316D, 0x07B439, 0x15200C,
0x5BC3D8, 0xC492F5, 0x4BADC6, 0xA5CA4E, 0xCD37A7, 0x36A9E6,
0x9492AB, 0x6842DD, 0xDE6319, 0xEF8C76, 0x528B68, 0x37DBFC,
0xABA1AE, 0x3115DF, 0xA1AE00, 0xDAFB0C, 0x664D64, 0xB705ED,
0x306529, 0xBF5657, 0x3AFF47, 0xB9F96A, 0xF3BE75, 0xDF9328,
0x3080AB, 0xF68C66, 0x15CB04, 0x0622FA, 0x1DE4D9, 0xA4B33D,
0x8F1B57, 0x09CD36, 0xE9424E, 0xA4BE13, 0xB52333, 0x1AAAF0,
0xA8654F, 0xA5C1D2, 0x0F3F0B, 0xCD785B, 0x76F923, 0x048B7B,
0x721789, 0x53A6C6, 0xE26E6F, 0x00EBEF, 0x584A9B, 0xB7DAC4,
0xBA66AA, 0xCFCF76, 0x1D02D1, 0x2DF1B1, 0xC1998C, 0x77ADC3,
0xDA4886, 0xA05DF7, 0xF480C6, 0x2FF0AC, 0x9AECDD, 0xBC5C3F,
0x6DDED0, 0x1FC790, 0xB6DB2A, 0x3A25A3, 0x9AAF00, 0x9353AD,
0x0457B6, 0xB42D29, 0x7E804B, 0xA707DA, 0x0EAA76, 0xA1597B,
0x2A1216, 0x2DB7DC, 0xFDE5FA, 0xFEDB89, 0xFDBE89, 0x6C76E4,
0xFCA906, 0x70803E, 0x156E85, 0xFF87FD, 0x073E28, 0x336761,
0x86182A, 0xEABD4D, 0xAFE7B3, 0x6E6D8F, 0x396795, 0x5BBF31,
0x48D784, 0x16DF30, 0x432DC7, 0x356125, 0xCE70C9, 0xB8CB30,
0xFD6CBF, 0xA200A4, 0xE46C05, 0xA0DD5A, 0x476F21, 0xD21262,
0x845CB9, 0x496170, 0xE0566B, 0x015299, 0x375550, 0xB7D51E,
0xC4F133, 0x5F6E13, 0xE4305D, 0xA92E85, 0xC3B21D, 0x3632A1,
0xA4B708, 0xD4B1EA, 0x21F716, 0xE4698F, 0x77FF27, 0x80030C,
0x2D408D, 0xA0CD4F, 0x99A520, 0xD3A2B3, 0x0A5D2F, 0x42F9B4,
0xCBDA11, 0xD0BE7D, 0xC1DB9B, 0xBD17AB, 0x81A2CA, 0x5C6A08,
0x17552E, 0x550027, 0xF0147F, 0x8607E1, 0x640B14, 0x8D4196,
0xDEBE87, 0x2AFDDA, 0xB6256B, 0x34897B, 0xFEF305, 0x9EBFB9,
0x4F6A68, 0xA82A4A, 0x5AC44F, 0xBCF82D, 0x985AD7, 0x95C7F4,
0x8D4D0D, 0xA63A20, 0x5F57A4, 0xB13F14, 0x953880, 0x0120CC,
0x86DD71, 0xB6DEC9, 0xF560BF, 0x11654D, 0x6B0701, 0xACB08C,
0xD0C0B2, 0x485551, 0x0EFB1E, 0xC37295, 0x3B06A3, 0x3540C0,
0x7BDC06, 0xCC45E0, 0xFA294E, 0xC8CAD6, 0x41F3E8, 0xDE647C,
0xD8649B, 0x31BED9, 0xC397A4, 0xD45877, 0xC5E369, 0x13DAF0,
0x3C3ABA, 0x461846, 0x5F7555, 0xF5BDD2, 0xC6926E, 0x5D2EAC,
0xED440E, 0x423E1C, 0x87C461, 0xE9FD29, 0xF3D6E7, 0xCA7C22,
0x35916F, 0xC5E008, 0x8DD7FF, 0xE26A6E, 0xC6FDB0, 0xC10893,
0x745D7C, 0xB2AD6B, 0x9D6ECD, 0x7B723E, 0x6A11C6, 0xA9CFF7,
0xDF7329, 0xBAC9B5, 0x5100B7, 0x0DB2E2, 0x24BA74, 0x607DE5,
0x8AD874, 0x2C150D, 0x0C1881, 0x94667E, 0x162901, 0x767A9F,
0xBEFDFD, 0xEF4556, 0x367ED9, 0x13D9EC, 0xB9BA8B, 0xFC97C4,
0x27A831, 0xC36EF1, 0x36C594, 0x56A8D8, 0xB5A8B4, 0x0ECCCF,
0x2D8912, 0x34576F, 0x89562C, 0xE3CE99, 0xB920D6, 0xAA5E6B,
0x9C2A3E, 0xCC5F11, 0x4A0BFD, 0xFBF4E1, 0x6D3B8E, 0x2C86E2,
0x84D4E9, 0xA9B4FC, 0xD1EEEF, 0xC9352E, 0x61392F, 0x442138,
0xC8D91B, 0x0AFC81, 0x6A4AFB, 0xD81C2F, 0x84B453, 0x8C994E,
0xCC2254, 0xDC552A, 0xD6C6C0, 0x96190B, 0xB8701A, 0x649569,
0x605A26, 0xEE523F, 0x0F117F, 0x11B5F4, 0xF5CBFC, 0x2DBC34,
0xEEBC34, 0xCC5DE8, 0x605EDD, 0x9B8E67, 0xEF3392, 0xB817C9,
0x9B5861, 0xBC57E1, 0xC68351, 0x103ED8, 0x4871DD, 0xDD1C2D,
0xA118AF, 0x462C21, 0xD7F359, 0x987AD9, 0xC0549E, 0xFA864F,
0xFC0656, 0xAE79E5, 0x362289, 0x22AD38, 0xDC9367, 0xAAE855,
0x382682, 0x9BE7CA, 0xA40D51, 0xB13399, 0x0ED7A9, 0x480569,
0xF0B265, 0xA7887F, 0x974C88, 0x36D1F9, 0xB39221, 0x4A827B,
0x21CF98, 0xDC9F40, 0x5547DC, 0x3A74E1, 0x42EB67, 0xDF9DFE,
0x5FD45E, 0xA4677B, 0x7AACBA, 0xA2F655, 0x23882B, 0x55BA41,
0x086E59, 0x862A21, 0x834739, 0xE6E389, 0xD49EE5, 0x40FB49,
0xE956FF, 0xCA0F1C, 0x8A59C5, 0x2BFA94, 0xC5C1D3, 0xCFC50F,
0xAE5ADB, 0x86C547, 0x624385, 0x3B8621, 0x94792C, 0x876110,
0x7B4C2A, 0x1A2C80, 0x12BF43, 0x902688, 0x893C78, 0xE4C4A8,
0x7BDBE5, 0xC23AC4, 0xEAF426, 0x8A67F7, 0xBF920D, 0x2BA365,
0xB1933D, 0x0B7CBD, 0xDC51A4, 0x63DD27, 0xDDE169, 0x19949A,
0x9529A8, 0x28CE68, 0xB4ED09, 0x209F44, 0xCA984E, 0x638270,
0x237C7E, 0x32B90F, 0x8EF5A7, 0xE75614, 0x08F121, 0x2A9DB5,
0x4D7E6F, 0x5119A5, 0xABF9B5, 0xD6DF82, 0x61DD96, 0x023616,
0x9F3AC4, 0xA1A283, 0x6DED72, 0x7A8D39, 0xA9B882, 0x5C326B,
0x5B2746, 0xED3400, 0x7700D2, 0x55F4FC, 0x4D5901, 0x8071E0,
#endif

};

static const double PIo2[] = {
  1.57079625129699707031e+00, /* 0x3FF921FB, 0x40000000 */
  7.54978941586159635335e-08, /* 0x3E74442D, 0x00000000 */
  5.39030252995776476554e-15, /* 0x3CF84698, 0x80000000 */
  3.28200341580791294123e-22, /* 0x3B78CC51, 0x60000000 */
  1.27065575308067607349e-29, /* 0x39F01B83, 0x80000000 */
  1.22933308981111328932e-36, /* 0x387A2520, 0x40000000 */
  2.73370053816464559624e-44, /* 0x36E38222, 0x80000000 */
  2.16741683877804819444e-51, /* 0x3569F31D, 0x00000000 */
};

static const double			
zero   = 0.0,
one    = 1.0,
two24   =  1.67772160000000000000e+07, /* 0x41700000, 0x00000000 */
twon24  =  5.96046447753906250000e-08; /* 0x3E700000, 0x00000000 */

int
__kernel_rem_pio2(double *x, double *y, int e0, int nx, int prec)
{
	int32_t jz,jx,jv,jp,jk,carry,n,iq[20],i,j,k,m,q0,ih;
	double z,fw,f[20],fq[20],q[20];

    /* initialize jk*/
	jk = init_jk[prec];
	jp = jk;

    /* determine jx,jv,q0, note that 3>q0 */
	jx =  nx-1;
	jv = (e0-3)/24; if(jv<0) jv=0;
	q0 =  e0-24*(jv+1);

    /* set up f[0] to f[jx+jk] where f[jx+jk] = ipio2[jv+jk] */
	j = jv-jx; m = jx+jk;
	for(i=0;i<=m;i++,j++) f[i] = (j<0)? zero : (double) ipio2[j];

    /* compute q[0],q[1],...q[jk] */
	for (i=0;i<=jk;i++) {
	    for(j=0,fw=0.0;j<=jx;j++) fw += x[j]*f[jx+i-j]; q[i] = fw;
	}

	jz = jk;
recompute:
    /* distill q[] into iq[] reversingly */
	for(i=0,j=jz,z=q[jz];j>0;i++,j--) {
	    fw    =  (double)((int32_t)(twon24* z));
	    iq[i] =  (int32_t)(z-two24*fw);
	    z     =  q[j-1]+fw;
	}

    /* compute n */
	z  = scalbn(z,q0);		/* actual value of z */
	z -= 8.0*floor(z*0.125);		/* trim off integer >= 8 */
	n  = (int32_t) z;
	z -= (double)n;
	ih = 0;
	if(q0>0) {	/* need iq[jz-1] to determine n */
	    i  = (iq[jz-1]>>(24-q0)); n += i;
	    iq[jz-1] -= i<<(24-q0);
	    ih = iq[jz-1]>>(23-q0);
	} 
	else if(q0==0) ih = iq[jz-1]>>23;
	else if(z>=0.5) ih=2;

	if(ih>0) {	/* q > 0.5 */
	    n += 1; carry = 0;
	    for(i=0;i<jz ;i++) {	/* compute 1-q */
		j = iq[i];
		if(carry==0) {
		    if(j!=0) {
			carry = 1; iq[i] = 0x1000000- j;
		    }
		} else  iq[i] = 0xffffff - j;
	    }
	    if(q0>0) {		/* rare case: chance is 1 in 12 */
	        switch(q0) {
	        case 1:
	    	   iq[jz-1] &= 0x7fffff; break;
	    	case 2:
	    	   iq[jz-1] &= 0x3fffff; break;
	        }
	    }
	    if(ih==2) {
		z = one - z;
		if(carry!=0) z -= scalbn(one,q0);
	    }
	}

    /* check if recomputation is needed */
	if(z==zero) {
	    j = 0;
	    for (i=jz-1;i>=jk;i--) j |= iq[i];
	    if(j==0) { /* need recomputation */
		for(k=1;iq[jk-k]==0;k++);   /* k = no. of terms needed */

		for(i=jz+1;i<=jz+k;i++) {   /* add q[jz+1] to q[jz+k] */
		    f[jx+i] = (double) ipio2[jv+i];
		    for(j=0,fw=0.0;j<=jx;j++) fw += x[j]*f[jx+i-j];
		    q[i] = fw;
		}
		jz += k;
		goto recompute;
	    }
	}

    /* chop off zero terms */
	if(z==0.0) {
	    jz -= 1; q0 -= 24;
	    while(iq[jz]==0) { jz--; q0-=24;}
	} else { /* break z into 24-bit if necessary */
	    z = scalbn(z,-q0);
	    if(z>=two24) { 
		fw = (double)((int32_t)(twon24*z));
		iq[jz] = (int32_t)(z-two24*fw);
		jz += 1; q0 += 24;
		iq[jz] = (int32_t) fw;
	    } else iq[jz] = (int32_t) z ;
	}

    /* convert integer "bit" chunk to floating-point value */
	fw = scalbn(one,q0);
	for(i=jz;i>=0;i--) {
	    q[i] = fw*(double)iq[i]; fw*=twon24;
	}

    /* compute PIo2[0,...,jp]*q[jz,...,0] */
	for(i=jz;i>=0;i--) {
	    for(fw=0.0,k=0;k<=jp&&k<=jz-i;k++) fw += PIo2[k]*q[i+k];
	    fq[jz-i] = fw;
	}

    /* compress fq[] into y[] */
	switch(prec) {
	    case 0:
		fw = 0.0;
		for (i=jz;i>=0;i--) fw += fq[i];
		y[0] = (ih==0)? fw: -fw; 
		break;
	    case 1:
	    case 2:
		fw = 0.0;
		for (i=jz;i>=0;i--) fw += fq[i]; 
		STRICT_ASSIGN(double,fw,fw);
		y[0] = (ih==0)? fw: -fw; 
		fw = fq[0]-fw;
		for (i=1;i<=jz;i++) fw += fq[i];
		y[1] = (ih==0)? fw: -fw; 
		break;
	    case 3:	/* painful */
		for (i=jz;i>0;i--) {
		    fw      = fq[i-1]+fq[i]; 
		    fq[i]  += fq[i-1]-fw;
		    fq[i-1] = fw;
		}
		for (i=jz;i>1;i--) {
		    fw      = fq[i-1]+fq[i]; 
		    fq[i]  += fq[i-1]-fw;
		    fq[i-1] = fw;
		}
		for (fw=0.0,i=jz;i>=2;i--) fw += fq[i]; 
		if(ih==0) {
		    y[0] =  fq[0]; y[1] =  fq[1]; y[2] =  fw;
		} else {
		    y[0] = -fq[0]; y[1] = -fq[1]; y[2] = -fw;
		}
	}
	return n&7;
}

"""

```
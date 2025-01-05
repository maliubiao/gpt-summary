Response:
Let's break down the thought process for analyzing the provided C code for `e_j0.c`.

**1. Initial Understanding & Context:**

* **File Location:** The path `bionic/libm/upstream-freebsd/lib/msun/src/e_j0.c` immediately tells us this is a math library function (`libm`) within Android's Bionic libc. It's sourced from FreeBSD's `msun` (mathematical software in the public domain), indicating it's a standard, well-established implementation.
* **Function Names:**  The file name and the comments within clearly indicate the presence of `j0(x)` and `y0(x)`, which are Bessel functions of the first and second kind of order zero. This is the core functionality.
* **Copyright:** The copyright notice reinforces the FreeBSD origin and the permissive licensing.

**2. Deeper Dive into Functionality:**

* **`j0(double x)`:**
    * **Small `x`:** The comment describes a Taylor series approximation (`1 - x^2/4 + x^4/64 - ...`). This is a standard technique for approximating functions near zero.
    * **Intermediate `x` (0, 2):**  A rational function approximation is used (`1-z/4+ z^2*R0/S0`, where `z = x*x`). The comment even provides a precision estimate. This is efficient and accurate for a specific range.
    * **Large `x` (2, inf):** An asymptotic expansion involving trigonometric functions (`sqrt(2/(pi*x))*(p0(x)*cos(x0)-q0(x)*sin(x0))`) is employed. This is typical for Bessel functions at larger arguments. The comment explains the clever trigonometric identity to avoid cancellation errors.
    * **Special Cases:** Handles `NaN`, `0`, and `inf` explicitly.
* **`y0(double x)`:**
    * **Small `x` (< 2):**  A formula involving `j0(x)` and `ln(x)` is used. The comment explains that `y0(x) - (2/pi)*j0(x)*ln(x)` is even. A rational function approximation (`U(z)/V(z)`) is used to handle the remaining part. The "tiny x" case is highlighted for efficiency.
    * **Large `x` (>= 2):** Similar asymptotic expansion as `j0(x)`, but with a plus sign in the trigonometric term.
    * **Special Cases:** Handles `0`, negative `x`, and `inf`.
* **Helper Functions (`pzero(double x)`, `qzero(double x)`):** These are clearly used within the large `x` cases for both `j0` and `y0`. They provide polynomial approximations for the `P(0,x)` and `Q(0,x)` terms in the asymptotic expansions. The comments mention the form of the asymptotic expansions and the ranges over which different polynomial approximations are used (using constants like `pR8`, `pS8`, etc.).

**3. Relationship to Android:**

* **Core Math Library:**  As part of Bionic's `libm`, these functions are fundamental for any application performing mathematical calculations.
* **NDK Usage:**  Native code developed using the NDK can directly call `j0()` and `y0()`.
* **Framework Dependence:** While the Android Framework itself might not *directly* call these specific low-level functions, higher-level framework components (graphics, physics simulations, etc.) ultimately rely on the underlying math library.

**4. Detailed Explanation of `libc` Functions:**

* **`fabs(double x)`:**  Standard absolute value function.
* **`sincos(double x, double *s, double *c)`:**  Calculates sine and cosine simultaneously, potentially more efficient than separate calls.
* **`cos(double x)`:** Standard cosine function.
* **`sin(double x)`:** Standard sine function.
* **`sqrt(double x)`:** Standard square root function.
* **`log(double x)`:** Standard natural logarithm function.
* **`GET_HIGH_WORD(i, d)` and `EXTRACT_WORDS(hi, lo, d)`:**  These are *not* standard C library functions. They are likely Bionic-specific macros for directly accessing the bits of a double-precision floating-point number. This is a common optimization technique in low-level math libraries for handling special cases and performing bitwise operations on floating-point representations.

**5. Dynamic Linker Considerations:**

* **SO Layout:** A typical shared object (`.so`) layout was sketched, showing sections for code, read-only data, read-write data, symbol tables, etc.
* **Symbol Resolution:**  The process of resolving global symbols (like `j0`, `y0`) and local static symbols was explained, highlighting the role of the symbol tables and relocation entries.

**6. Logic and Assumptions:**

* **Input/Output Examples:**  Simple examples were provided to illustrate the behavior of `j0()` and `y0()` for various inputs, including edge cases like zero, negative numbers, and infinity.

**7. Common Usage Errors:**

* **`y0(x)` with `x <= 0`:**  This will result in `NaN` or `-inf`.
* **Overflow/Underflow:** While less likely with these specific functions, it's a general concern with floating-point calculations.
* **Precision Issues:** Understanding the limits of floating-point representation is crucial.

**8. Debugging Path:**

The process of tracing a call from the Android Framework or NDK down to `e_j0.c` was outlined, starting with application code, moving through framework services, potentially involving JNI calls for NDK interaction, and finally reaching the Bionic `libm`.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe the trigonometric functions are implemented directly within this file. **Correction:** The `#include "math.h"` and `#include "math_private.h"` indicate reliance on other parts of the math library for these core functions.
* **Initial thought:** Focus only on the mathematical formulas. **Correction:**  Realized the importance of explaining the bit manipulation macros (`GET_HIGH_WORD`, `EXTRACT_WORDS`) and their purpose in optimizing floating-point handling.
* **Initial thought:** Provide a very high-level overview of the dynamic linker. **Correction:** Decided to add a simple SO layout and explain the basic symbol resolution process to provide a more concrete picture.
* **Considered adding:** Benchmarking or performance comparisons. **Decision:**  While relevant, it would make the analysis too broad. Focused on functionality and linking aspects.

By following this structured approach, combining code analysis with knowledge of the Android system and standard mathematical practices, a comprehensive explanation of the `e_j0.c` file can be constructed.
好的，让我们深入分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_j0.c` 这个文件。

**文件功能概述**

这个 C 源代码文件实现了以下两个数学函数：

* **`j0(double x)`:**  计算第一类零阶贝塞尔函数 (Bessel function of the first kind of order zero)。
* **`y0(double x)`:** 计算第二类零阶贝塞尔函数 (Bessel function of the second kind of order zero)，也称为诺伊曼函数 (Neumann function)。

**与 Android 功能的关系及举例**

作为 Android Bionic 的一部分，这个文件提供的贝塞尔函数是底层数学运算的基础，被 Android 系统和应用程序广泛使用。

* **Android Framework:**
    * **图形渲染:**  在图形处理中，例如在 OpenGL ES 或 Vulkan 中，一些特殊的材质或效果可能涉及到贝塞尔函数的计算。虽然 framework 不会直接调用 `j0` 或 `y0`，但其底层的图形库 (如 libGLES) 可能依赖于 `libm` 提供的这些函数。
    * **音频处理:**  在音频合成、滤波或分析中，贝塞尔函数有时会被用于创建特定的波形或进行频谱分析。Android 的 Media Framework 可能会间接使用到这些函数。
    * **物理模拟:**  一些游戏引擎或物理模拟库在 Android 上运行时，如果需要精确的圆柱或球形波的描述，可能会用到贝塞尔函数。
* **Android NDK:**
    * **游戏开发:** 使用 NDK 开发的游戏，如果涉及到复杂的数学运算、物理模拟或特殊效果，开发者可以直接调用 `j0(x)` 和 `y0(x)`。
    * **科学计算应用:**  基于 Android 的科学计算应用，例如信号处理、图像分析、数值模拟等，会直接使用这些贝塞尔函数。

**libc 函数的实现细节**

让我们逐个分析代码中使用的 `libc` 函数以及一些非标准的宏。

1. **`fabs(double x)`:**
   * **功能:** 计算双精度浮点数 `x` 的绝对值。
   * **实现:** 通常通过检查浮点数的符号位来实现。如果符号位是负数，则将其置为零。

2. **`sincos(double x, double *s, double *c)`:**
   * **功能:** 同时计算双精度浮点数 `x` 的正弦值和余弦值，并将结果分别存储在 `s` 和 `c` 指向的内存位置。
   * **实现:**  这通常是一个优化过的函数，因为它可以在一次计算中同时得到 `sin` 和 `cos`，避免了分别计算的冗余。它的实现可能涉及：
      * **区间规约:** 将输入角度 `x` 规约到一个较小的区间 (例如 `[0, 2*PI]`)。
      * **泰勒展开或切比雪夫逼近:** 在规约后的区间内使用多项式逼近来计算 `sin` 和 `cos`。

3. **`cos(double x)`:**
   * **功能:** 计算双精度浮点数 `x` 的余弦值。
   * **实现:** 类似于 `sincos` 的实现，通常涉及区间规约和多项式逼近。

4. **`sin(double x)`:**
   * **功能:** 计算双精度浮点数 `x` 的正弦值。
   * **实现:** 同样类似于 `sincos` 的实现。

5. **`sqrt(double x)`:**
   * **功能:** 计算双精度浮点数 `x` 的平方根。
   * **实现:**  有多种实现方法，常见的包括：
      * **牛顿迭代法:**  通过迭代逼近平方根。
      * **硬件指令:** 现代处理器通常有专门的指令来计算平方根。
      * **查找表和插值:**  对于某些精度要求不高的场景，可以使用预先计算的平方根表进行插值。

6. **`log(double x)`:**
   * **功能:** 计算双精度浮点数 `x` 的自然对数。
   * **实现:**  常见的实现方法包括：
      * **区间规约:** 将 `x` 规约到一个接近 1 的区间。
      * **泰勒展开:**  使用 `ln(1+y)` 的泰勒展开 (`y - y^2/2 + y^3/3 - ...`)。
      * **切比雪夫逼近:** 使用更精确的多项式逼近。

7. **`GET_HIGH_WORD(i, d)` 和 `EXTRACT_WORDS(hi, lo, d)`:**
   * **功能:** 这不是标准的 `libc` 函数，而是 `math_private.h` 中定义的宏，用于直接访问双精度浮点数的内部表示（IEEE 754 标准）。
   * **实现:** 这些宏通常使用类型双关 (type punning) 的技巧，将 `double` 类型的变量重新解释为整数类型，以便访问其高位和低位字 (word)。这允许直接操作浮点数的符号位、指数部分和尾数部分，用于快速判断特殊情况 (如 NaN, Infinity, 零) 或进行某些优化。

**dynamic linker 的功能**

Android 的动态链接器 (linker, 通常是 `linker64` 或 `linker`) 负责在程序运行时加载共享库 (`.so` 文件) 并解析符号。

**SO 布局样本:**

一个典型的 `.so` 文件 (例如 `libm.so`) 的布局可能如下：

```
.dynamic  # 动态链接信息，包含依赖库、符号表位置等
.hash     # 符号哈希表，加速符号查找
.gnu.hash # GNU 风格的符号哈希表
.dynsym   # 动态符号表，包含导出的和导入的符号
.dynstr   # 动态符号字符串表，存储符号名称
.rel.dyn  # 数据段的重定位信息
.rel.plt  # PLT (Procedure Linkage Table) 的重定位信息
.plt      # PLT，用于延迟绑定
.text     # 代码段
.rodata   # 只读数据段 (例如这里的常量)
.data     # 可读写数据段 (全局变量、静态变量)
.bss      # 未初始化的数据段
...       # 其他段
```

**符号处理过程:**

1. **加载共享库:** 当应用程序或另一个共享库需要使用 `libm.so` 中的函数时，动态链接器会将 `libm.so` 加载到内存中。
2. **查找依赖:** 动态链接器读取 `.dynamic` 段，找到 `libm.so` 依赖的其他共享库，并递归加载它们。
3. **符号解析 (Symbol Resolution):**
   * **应用程序/共享库引用符号:**  当代码中调用 `j0(x)` 时，编译器会生成一个对 `j0` 的未定义引用。
   * **动态链接器查找符号:** 动态链接器在已加载的共享库的动态符号表 (`.dynsym`) 中查找名为 `j0` 的符号。它使用符号哈希表 (`.hash` 或 `.gnu.hash`) 来加速查找。
   * **找到符号:** 如果在 `libm.so` 的 `.dynsym` 中找到了 `j0` 符号，动态链接器会获取 `j0` 函数的地址。
   * **重定位 (Relocation):** 动态链接器使用重定位信息 (`.rel.dyn` 和 `.rel.plt`) 来更新调用点的指令，将未定义的引用替换为 `j0` 函数的实际内存地址。
4. **延迟绑定 (Lazy Binding, 通过 PLT):**  为了优化启动时间，动态链接器通常使用延迟绑定。
   * 首次调用 `j0` 时，会跳转到 PLT 中一个桩 (stub) 函数。
   * 这个桩函数会调用动态链接器来解析 `j0` 的地址。
   * 动态链接器解析地址后，会更新 PLT 表项，使得后续对 `j0` 的调用可以直接跳转到 `j0` 的实际地址，而无需再次经过动态链接器。

**每种符号的处理过程:**

* **全局符号 (例如 `j0`, `y0`):** 这些符号在 `.dynsym` 中导出，可以被其他共享库或应用程序引用。动态链接器负责找到这些符号的定义并进行重定位。
* **静态符号 (例如 `pzero`, `qzero`, 以及 `static const double` 声明的常量):**  这些符号的作用域限制在当前编译单元 (`.c` 文件) 内。它们通常不会出现在动态符号表中，也不会被其他共享库直接引用。链接器在链接 `libm.so` 时会处理这些符号的地址。
* **局部符号 (例如函数内的局部变量):** 这些符号只在函数内部可见，不会出现在符号表中。

**逻辑推理、假设输入与输出**

让我们以 `j0(x)` 函数为例进行逻辑推理。

**假设输入:**

* `x = 0.0`:  根据代码注释，`j0(0)` 应该返回 `1.0`。
* `x = NaN`:  根据代码注释，`j0(NaN)` 应该返回 `NaN`。
* `x = infinity`: 根据代码注释，`j0(infinity)` 应该返回 `0.0`。
* `x = 0.5`:  根据代码中的公式，会使用 `|x| < 1.00` 的情况，即 `one + z*((r/s)-qrtr)` 计算。
* `x = 3.0`:  根据代码中的公式，会使用 `|x| >= 2.0` 的情况，计算涉及 `sincos(x)` 和 `pzero(x)`, `qzero(x)`。

**预期输出:**

* `j0(0.0)`  -> `1.0`
* `j0(NaN)`  -> `NaN`
* `j0(infinity)` -> `0.0`
* `j0(0.5)`  ->  可以通过手动计算或运行代码得到一个接近真实贝塞尔函数值的浮点数。
* `j0(3.0)`  ->  同样，可以通过计算得到一个浮点数结果。

**涉及用户或编程常见的使用错误**

1. **传递无效参数给 `y0(x)`:**
   * **`x <= 0`:** `y0(x)` 在 `x` 小于或等于 0 时未定义。用户传递这样的参数会导致返回 `NaN` 或 `-infinity`，并可能触发浮点异常。
   * **示例:** `y0(-1.0)` 或 `y0(0.0)`。

2. **忽略 NaN 的传播:**
   * 如果传递给 `j0` 或 `y0` 的参数是 `NaN`，结果也会是 `NaN`。用户需要注意检查和处理 `NaN` 值，避免其在后续计算中引发错误。

3. **精度问题:**
   * 贝塞尔函数的计算涉及到浮点数运算，存在固有的精度限制。用户在比较计算结果时，应该考虑一定的误差容限，而不是期望完全精确的相等。

4. **性能考虑:**
   * 对于大规模的贝塞尔函数计算，用户可能需要考虑性能优化，例如使用向量化指令 (SIMD) 或者选择更适合特定场景的近似算法。

**Android Framework 或 NDK 如何到达这里 (调试线索)**

以下是一个可能的调用路径，从 Android 应用到 `e_j0.c` 中的函数：

1. **Java 代码调用:** Android 应用的 Java 代码可能需要进行某些数学运算，例如，在一个图形渲染相关的操作中。

2. **NDK 调用 (如果使用):** 如果应用使用了 NDK，Java 代码可能会通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。

3. **Native 代码调用 `libm` 函数:** Native 代码中会包含类似 `double result = j0(some_value);` 的调用。

4. **动态链接器解析符号:** 当 Native 代码被加载执行时，动态链接器会解析 `j0` 符号，找到 `libm.so` 中 `j0` 函数的地址。

5. **`libm.so` 中的 `j0` 函数执行:**  最终，会执行 `bionic/libm/upstream-freebsd/lib/msun/src/e_j0.c` 文件中实现的 `j0` 函数。

**调试线索:**

* **使用 Android Studio 的调试器:**  可以在 Java 代码和 Native 代码中设置断点，逐步跟踪代码执行流程，查看变量的值。
* **使用 `adb logcat`:** 可以查看系统日志，了解库的加载情况、错误信息等。
* **使用 `strace` (需要 root 权限):** 可以跟踪系统调用，查看动态链接器的行为。
* **检查链接库:** 确保 Native 代码正确链接了 `libm` 库。在 `Android.mk` 或 `CMakeLists.txt` 文件中应该有类似 `LOCAL_LDLIBS += -lm` 或 `target_link_libraries(your_target m)` 的配置。
* **使用符号化的 backtrace:**  如果程序崩溃，可以获取 backtrace 信息，符号化后可以看到调用栈中涉及的函数，从而定位问题。

希望以上分析能够帮助你理解 `e_j0.c` 文件的功能、在 Android 中的作用以及相关的技术细节。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_j0.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

/* j0(x), y0(x)
 * Bessel function of the first and second kinds of order zero.
 * Method -- j0(x):
 *	1. For tiny x, we use j0(x) = 1 - x^2/4 + x^4/64 - ...
 *	2. Reduce x to |x| since j0(x)=j0(-x),  and
 *	   for x in (0,2)
 *		j0(x) = 1-z/4+ z^2*R0/S0,  where z = x*x;
 *	   (precision:  |j0-1+z/4-z^2R0/S0 |<2**-63.67 )
 *	   for x in (2,inf)
 * 		j0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)-q0(x)*sin(x0))
 * 	   where x0 = x-pi/4. It is better to compute sin(x0),cos(x0)
 *	   as follow:
 *		cos(x0) = cos(x)cos(pi/4)+sin(x)sin(pi/4)
 *			= 1/sqrt(2) * (cos(x) + sin(x))
 *		sin(x0) = sin(x)cos(pi/4)-cos(x)sin(pi/4)
 *			= 1/sqrt(2) * (sin(x) - cos(x))
 * 	   (To avoid cancellation, use
 *		sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
 * 	    to compute the worse one.)
 *
 *	3 Special cases
 *		j0(nan)= nan
 *		j0(0) = 1
 *		j0(inf) = 0
 *
 * Method -- y0(x):
 *	1. For x<2.
 *	   Since
 *		y0(x) = 2/pi*(j0(x)*(ln(x/2)+Euler) + x^2/4 - ...)
 *	   therefore y0(x)-2/pi*j0(x)*ln(x) is an even function.
 *	   We use the following function to approximate y0,
 *		y0(x) = U(z)/V(z) + (2/pi)*(j0(x)*ln(x)), z= x^2
 *	   where
 *		U(z) = u00 + u01*z + ... + u06*z^6
 *		V(z) = 1  + v01*z + ... + v04*z^4
 *	   with absolute approximation error bounded by 2**-72.
 *	   Note: For tiny x, U/V = u0 and j0(x)~1, hence
 *		y0(tiny) = u0 + (2/pi)*ln(tiny), (choose tiny<2**-27)
 *	2. For x>=2.
 * 		y0(x) = sqrt(2/(pi*x))*(p0(x)*cos(x0)+q0(x)*sin(x0))
 * 	   where x0 = x-pi/4. It is better to compute sin(x0),cos(x0)
 *	   by the method mentioned above.
 *	3. Special cases: y0(0)=-inf, y0(x<0)=NaN, y0(inf)=0.
 */

#include "math.h"
#include "math_private.h"

static __inline double pzero(double), qzero(double);

static const volatile double vone = 1, vzero = 0;

static const double
huge 	= 1e300,
one	= 1.0,
invsqrtpi=  5.64189583547756279280e-01, /* 0x3FE20DD7, 0x50429B6D */
tpi      =  6.36619772367581382433e-01, /* 0x3FE45F30, 0x6DC9C883 */
/* R0/S0 on [0, 2.00] */
R02  =  1.56249999999999947958e-02, /* 0x3F8FFFFF, 0xFFFFFFFD */
R03  = -1.89979294238854721751e-04, /* 0xBF28E6A5, 0xB61AC6E9 */
R04  =  1.82954049532700665670e-06, /* 0x3EBEB1D1, 0x0C503919 */
R05  = -4.61832688532103189199e-09, /* 0xBE33D5E7, 0x73D63FCE */
S01  =  1.56191029464890010492e-02, /* 0x3F8FFCE8, 0x82C8C2A4 */
S02  =  1.16926784663337450260e-04, /* 0x3F1EA6D2, 0xDD57DBF4 */
S03  =  5.13546550207318111446e-07, /* 0x3EA13B54, 0xCE84D5A9 */
S04  =  1.16614003333790000205e-09; /* 0x3E1408BC, 0xF4745D8F */

static const double zero = 0, qrtr = 0.25;

double
j0(double x)
{
	double z, s,c,ss,cc,r,u,v;
	int32_t hx,ix;

	GET_HIGH_WORD(hx,x);
	ix = hx&0x7fffffff;
	if(ix>=0x7ff00000) return one/(x*x);
	x = fabs(x);
	if(ix >= 0x40000000) {	/* |x| >= 2.0 */
		sincos(x, &s, &c);
		ss = s-c;
		cc = s+c;
		if(ix<0x7fe00000) {  /* Make sure x+x does not overflow. */
		    z = -cos(x+x);
		    if ((s*c)<zero) cc = z/ss;
		    else 	    ss = z/cc;
		}
	/*
	 * j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
	 * y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)
	 */
		if(ix>0x48000000) z = (invsqrtpi*cc)/sqrt(x);
		else {
		    u = pzero(x); v = qzero(x);
		    z = invsqrtpi*(u*cc-v*ss)/sqrt(x);
		}
		return z;
	}
	if(ix<0x3f200000) {	/* |x| < 2**-13 */
	    if(huge+x>one) {	/* raise inexact if x != 0 */
	        if(ix<0x3e400000) return one;	/* |x|<2**-27 */
	        else 	      return one - x*x/4;
	    }
	}
	z = x*x;
	r =  z*(R02+z*(R03+z*(R04+z*R05)));
	s =  one+z*(S01+z*(S02+z*(S03+z*S04)));
	if(ix < 0x3FF00000) {	/* |x| < 1.00 */
	    return one + z*((r/s)-qrtr);
	} else {
	    u = x/2;
	    return((one+u)*(one-u)+z*(r/s));
	}
}

static const double
u00  = -7.38042951086872317523e-02, /* 0xBFB2E4D6, 0x99CBD01F */
u01  =  1.76666452509181115538e-01, /* 0x3FC69D01, 0x9DE9E3FC */
u02  = -1.38185671945596898896e-02, /* 0xBF8C4CE8, 0xB16CFA97 */
u03  =  3.47453432093683650238e-04, /* 0x3F36C54D, 0x20B29B6B */
u04  = -3.81407053724364161125e-06, /* 0xBECFFEA7, 0x73D25CAD */
u05  =  1.95590137035022920206e-08, /* 0x3E550057, 0x3B4EABD4 */
u06  = -3.98205194132103398453e-11, /* 0xBDC5E43D, 0x693FB3C8 */
v01  =  1.27304834834123699328e-02, /* 0x3F8A1270, 0x91C9C71A */
v02  =  7.60068627350353253702e-05, /* 0x3F13ECBB, 0xF578C6C1 */
v03  =  2.59150851840457805467e-07, /* 0x3E91642D, 0x7FF202FD */
v04  =  4.41110311332675467403e-10; /* 0x3DFE5018, 0x3BD6D9EF */

double
y0(double x)
{
	double z, s,c,ss,cc,u,v;
	int32_t hx,ix,lx;

	EXTRACT_WORDS(hx,lx,x);
        ix = 0x7fffffff&hx;
	/*
	 * y0(NaN) = NaN.
	 * y0(Inf) = 0.
	 * y0(-Inf) = NaN and raise invalid exception.
	 */
	if(ix>=0x7ff00000) return vone/(x+x*x);
	/* y0(+-0) = -inf and raise divide-by-zero exception. */
	if((ix|lx)==0) return -one/vzero;
	/* y0(x<0) = NaN and raise invalid exception. */
	if(hx<0) return vzero/vzero;
        if(ix >= 0x40000000) {  /* |x| >= 2.0 */
        /* y0(x) = sqrt(2/(pi*x))*(p0(x)*sin(x0)+q0(x)*cos(x0))
         * where x0 = x-pi/4
         *      Better formula:
         *              cos(x0) = cos(x)cos(pi/4)+sin(x)sin(pi/4)
         *                      =  1/sqrt(2) * (sin(x) + cos(x))
         *              sin(x0) = sin(x)cos(3pi/4)-cos(x)sin(3pi/4)
         *                      =  1/sqrt(2) * (sin(x) - cos(x))
         * To avoid cancellation, use
         *              sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
         * to compute the worse one.
         */
                sincos(x, &s, &c);
                ss = s-c;
                cc = s+c;
	/*
	 * j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
	 * y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)
	 */
                if(ix<0x7fe00000) {  /* make sure x+x not overflow */
                    z = -cos(x+x);
                    if ((s*c)<zero) cc = z/ss;
                    else            ss = z/cc;
                }
                if(ix>0x48000000) z = (invsqrtpi*ss)/sqrt(x);
                else {
                    u = pzero(x); v = qzero(x);
                    z = invsqrtpi*(u*ss+v*cc)/sqrt(x);
                }
                return z;
	}
	if(ix<=0x3e400000) {	/* x < 2**-27 */
	    return(u00 + tpi*log(x));
	}
	z = x*x;
	u = u00+z*(u01+z*(u02+z*(u03+z*(u04+z*(u05+z*u06)))));
	v = one+z*(v01+z*(v02+z*(v03+z*v04)));
	return(u/v + tpi*(j0(x)*log(x)));
}

/* The asymptotic expansions of pzero is
 *	1 - 9/128 s^2 + 11025/98304 s^4 - ...,	where s = 1/x.
 * For x >= 2, We approximate pzero by
 * 	pzero(x) = 1 + (R/S)
 * where  R = pR0 + pR1*s^2 + pR2*s^4 + ... + pR5*s^10
 * 	  S = 1 + pS0*s^2 + ... + pS4*s^10
 * and
 *	| pzero(x)-1-R/S | <= 2  ** ( -60.26)
 */
static const double pR8[6] = { /* for x in [inf, 8]=1/[0,0.125] */
  0.00000000000000000000e+00, /* 0x00000000, 0x00000000 */
 -7.03124999999900357484e-02, /* 0xBFB1FFFF, 0xFFFFFD32 */
 -8.08167041275349795626e+00, /* 0xC02029D0, 0xB44FA779 */
 -2.57063105679704847262e+02, /* 0xC0701102, 0x7B19E863 */
 -2.48521641009428822144e+03, /* 0xC0A36A6E, 0xCD4DCAFC */
 -5.25304380490729545272e+03, /* 0xC0B4850B, 0x36CC643D */
};
static const double pS8[5] = {
  1.16534364619668181717e+02, /* 0x405D2233, 0x07A96751 */
  3.83374475364121826715e+03, /* 0x40ADF37D, 0x50596938 */
  4.05978572648472545552e+04, /* 0x40E3D2BB, 0x6EB6B05F */
  1.16752972564375915681e+05, /* 0x40FC810F, 0x8F9FA9BD */
  4.76277284146730962675e+04, /* 0x40E74177, 0x4F2C49DC */
};

static const double pR5[6] = { /* for x in [8,4.5454]=1/[0.125,0.22001] */
 -1.14125464691894502584e-11, /* 0xBDA918B1, 0x47E495CC */
 -7.03124940873599280078e-02, /* 0xBFB1FFFF, 0xE69AFBC6 */
 -4.15961064470587782438e+00, /* 0xC010A370, 0xF90C6BBF */
 -6.76747652265167261021e+01, /* 0xC050EB2F, 0x5A7D1783 */
 -3.31231299649172967747e+02, /* 0xC074B3B3, 0x6742CC63 */
 -3.46433388365604912451e+02, /* 0xC075A6EF, 0x28A38BD7 */
};
static const double pS5[5] = {
  6.07539382692300335975e+01, /* 0x404E6081, 0x0C98C5DE */
  1.05125230595704579173e+03, /* 0x40906D02, 0x5C7E2864 */
  5.97897094333855784498e+03, /* 0x40B75AF8, 0x8FBE1D60 */
  9.62544514357774460223e+03, /* 0x40C2CCB8, 0xFA76FA38 */
  2.40605815922939109441e+03, /* 0x40A2CC1D, 0xC70BE864 */
};

static const double pR3[6] = {/* for x in [4.547,2.8571]=1/[0.2199,0.35001] */
 -2.54704601771951915620e-09, /* 0xBE25E103, 0x6FE1AA86 */
 -7.03119616381481654654e-02, /* 0xBFB1FFF6, 0xF7C0E24B */
 -2.40903221549529611423e+00, /* 0xC00345B2, 0xAEA48074 */
 -2.19659774734883086467e+01, /* 0xC035F74A, 0x4CB94E14 */
 -5.80791704701737572236e+01, /* 0xC04D0A22, 0x420A1A45 */
 -3.14479470594888503854e+01, /* 0xC03F72AC, 0xA892D80F */
};
static const double pS3[5] = {
  3.58560338055209726349e+01, /* 0x4041ED92, 0x84077DD3 */
  3.61513983050303863820e+02, /* 0x40769839, 0x464A7C0E */
  1.19360783792111533330e+03, /* 0x4092A66E, 0x6D1061D6 */
  1.12799679856907414432e+03, /* 0x40919FFC, 0xB8C39B7E */
  1.73580930813335754692e+02, /* 0x4065B296, 0xFC379081 */
};

static const double pR2[6] = {/* for x in [2.8570,2]=1/[0.3499,0.5] */
 -8.87534333032526411254e-08, /* 0xBE77D316, 0xE927026D */
 -7.03030995483624743247e-02, /* 0xBFB1FF62, 0x495E1E42 */
 -1.45073846780952986357e+00, /* 0xBFF73639, 0x8A24A843 */
 -7.63569613823527770791e+00, /* 0xC01E8AF3, 0xEDAFA7F3 */
 -1.11931668860356747786e+01, /* 0xC02662E6, 0xC5246303 */
 -3.23364579351335335033e+00, /* 0xC009DE81, 0xAF8FE70F */
};
static const double pS2[5] = {
  2.22202997532088808441e+01, /* 0x40363865, 0x908B5959 */
  1.36206794218215208048e+02, /* 0x4061069E, 0x0EE8878F */
  2.70470278658083486789e+02, /* 0x4070E786, 0x42EA079B */
  1.53875394208320329881e+02, /* 0x40633C03, 0x3AB6FAFF */
  1.46576176948256193810e+01, /* 0x402D50B3, 0x44391809 */
};

static __inline double
pzero(double x)
{
	const double *p,*q;
	double z,r,s;
	int32_t ix;
	GET_HIGH_WORD(ix,x);
	ix &= 0x7fffffff;
	if(ix>=0x40200000)     {p = pR8; q= pS8;}
	else if(ix>=0x40122E8B){p = pR5; q= pS5;}
	else if(ix>=0x4006DB6D){p = pR3; q= pS3;}
	else                   {p = pR2; q= pS2;}	/* ix>=0x40000000 */
	z = one/(x*x);
	r = p[0]+z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))));
	s = one+z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*q[4]))));
	return one+ r/s;
}


/* For x >= 8, the asymptotic expansions of qzero is
 *	-1/8 s + 75/1024 s^3 - ..., where s = 1/x.
 * We approximate pzero by
 * 	qzero(x) = s*(-1.25 + (R/S))
 * where  R = qR0 + qR1*s^2 + qR2*s^4 + ... + qR5*s^10
 * 	  S = 1 + qS0*s^2 + ... + qS5*s^12
 * and
 *	| qzero(x)/s +1.25-R/S | <= 2  ** ( -61.22)
 */
static const double qR8[6] = { /* for x in [inf, 8]=1/[0,0.125] */
  0.00000000000000000000e+00, /* 0x00000000, 0x00000000 */
  7.32421874999935051953e-02, /* 0x3FB2BFFF, 0xFFFFFE2C */
  1.17682064682252693899e+01, /* 0x40278952, 0x5BB334D6 */
  5.57673380256401856059e+02, /* 0x40816D63, 0x15301825 */
  8.85919720756468632317e+03, /* 0x40C14D99, 0x3E18F46D */
  3.70146267776887834771e+04, /* 0x40E212D4, 0x0E901566 */
};
static const double qS8[6] = {
  1.63776026895689824414e+02, /* 0x406478D5, 0x365B39BC */
  8.09834494656449805916e+03, /* 0x40BFA258, 0x4E6B0563 */
  1.42538291419120476348e+05, /* 0x41016652, 0x54D38C3F */
  8.03309257119514397345e+05, /* 0x412883DA, 0x83A52B43 */
  8.40501579819060512818e+05, /* 0x4129A66B, 0x28DE0B3D */
 -3.43899293537866615225e+05, /* 0xC114FD6D, 0x2C9530C5 */
};

static const double qR5[6] = { /* for x in [8,4.5454]=1/[0.125,0.22001] */
  1.84085963594515531381e-11, /* 0x3DB43D8F, 0x29CC8CD9 */
  7.32421766612684765896e-02, /* 0x3FB2BFFF, 0xD172B04C */
  5.83563508962056953777e+00, /* 0x401757B0, 0xB9953DD3 */
  1.35111577286449829671e+02, /* 0x4060E392, 0x0A8788E9 */
  1.02724376596164097464e+03, /* 0x40900CF9, 0x9DC8C481 */
  1.98997785864605384631e+03, /* 0x409F17E9, 0x53C6E3A6 */
};
static const double qS5[6] = {
  8.27766102236537761883e+01, /* 0x4054B1B3, 0xFB5E1543 */
  2.07781416421392987104e+03, /* 0x40A03BA0, 0xDA21C0CE */
  1.88472887785718085070e+04, /* 0x40D267D2, 0x7B591E6D */
  5.67511122894947329769e+04, /* 0x40EBB5E3, 0x97E02372 */
  3.59767538425114471465e+04, /* 0x40E19118, 0x1F7A54A0 */
 -5.35434275601944773371e+03, /* 0xC0B4EA57, 0xBEDBC609 */
};

static const double qR3[6] = {/* for x in [4.547,2.8571]=1/[0.2199,0.35001] */
  4.37741014089738620906e-09, /* 0x3E32CD03, 0x6ADECB82 */
  7.32411180042911447163e-02, /* 0x3FB2BFEE, 0x0E8D0842 */
  3.34423137516170720929e+00, /* 0x400AC0FC, 0x61149CF5 */
  4.26218440745412650017e+01, /* 0x40454F98, 0x962DAEDD */
  1.70808091340565596283e+02, /* 0x406559DB, 0xE25EFD1F */
  1.66733948696651168575e+02, /* 0x4064D77C, 0x81FA21E0 */
};
static const double qS3[6] = {
  4.87588729724587182091e+01, /* 0x40486122, 0xBFE343A6 */
  7.09689221056606015736e+02, /* 0x40862D83, 0x86544EB3 */
  3.70414822620111362994e+03, /* 0x40ACF04B, 0xE44DFC63 */
  6.46042516752568917582e+03, /* 0x40B93C6C, 0xD7C76A28 */
  2.51633368920368957333e+03, /* 0x40A3A8AA, 0xD94FB1C0 */
 -1.49247451836156386662e+02, /* 0xC062A7EB, 0x201CF40F */
};

static const double qR2[6] = {/* for x in [2.8570,2]=1/[0.3499,0.5] */
  1.50444444886983272379e-07, /* 0x3E84313B, 0x54F76BDB */
  7.32234265963079278272e-02, /* 0x3FB2BEC5, 0x3E883E34 */
  1.99819174093815998816e+00, /* 0x3FFFF897, 0xE727779C */
  1.44956029347885735348e+01, /* 0x402CFDBF, 0xAAF96FE5 */
  3.16662317504781540833e+01, /* 0x403FAA8E, 0x29FBDC4A */
  1.62527075710929267416e+01, /* 0x403040B1, 0x71814BB4 */
};
static const double qS2[6] = {
  3.03655848355219184498e+01, /* 0x403E5D96, 0xF7C07AED */
  2.69348118608049844624e+02, /* 0x4070D591, 0xE4D14B40 */
  8.44783757595320139444e+02, /* 0x408A6645, 0x22B3BF22 */
  8.82935845112488550512e+02, /* 0x408B977C, 0x9C5CC214 */
  2.12666388511798828631e+02, /* 0x406A9553, 0x0E001365 */
 -5.31095493882666946917e+00, /* 0xC0153E6A, 0xF8B32931 */
};

static __inline double
qzero(double x)
{
	static const double eighth = 0.125;
	const double *p,*q;
	double s,r,z;
	int32_t ix;
	GET_HIGH_WORD(ix,x);
	ix &= 0x7fffffff;
	if(ix>=0x40200000)     {p = qR8; q= qS8;}
	else if(ix>=0x40122E8B){p = qR5; q= qS5;}
	else if(ix>=0x4006DB6D){p = qR3; q= qS3;}
	else                   {p = qR2; q= qS2;}	/* ix>=0x40000000 */
	z = one/(x*x);
	r = p[0]+z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))));
	s = one+z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*(q[4]+z*q[5])))));
	return (r/s-eighth)/x;
}

"""

```
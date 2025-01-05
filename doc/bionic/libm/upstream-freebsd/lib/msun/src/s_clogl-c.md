Response:
Let's break down the thought process for analyzing the `s_clogl.c` code. The goal is to understand its function, its relationship to Android, how it's implemented, its place in the Android ecosystem, and potential pitfalls.

**1. Initial Understanding and Function Identification:**

* **File Name and Location:**  The path `bionic/libm/upstream-freebsd/lib/msun/src/s_clogl.c` immediately tells us this is part of the math library (`libm`) in Android's C library (`bionic`). The `s_` prefix often suggests a single-precision or standard implementation of a mathematical function. The `clogl` part strongly indicates a complex logarithm function.
* **Copyright Notice:**  The FreeBSD copyright suggests this code (or a significant portion of it) originated from the FreeBSD project. This is common for foundational libraries.
* **Includes:**  `<complex.h>`, `<float.h>`, `<ieeefp.h>` (potentially architecture-specific), `fpmath.h`, `math.h`, and `math_private.h` provide hints about the code's functionality and dependencies. `<complex.h>` confirms it deals with complex numbers. The others are standard math library headers.
* **Function Signature:** `long double complex clogl(long double complex z)` definitively confirms that this function computes the natural logarithm of a complex number with `long double` precision.

**2. Core Functionality -  Complex Logarithm:**

* **Mathematical Definition:** Recall the mathematical definition of the complex logarithm: `log(z) = log(|z|) + i * arg(z)`, where `|z|` is the magnitude (absolute value) of `z`, and `arg(z)` is the argument (angle) of `z`.
* **Code Mapping:** The code directly implements this:
    * `x = creall(z); y = cimagl(z);`: Extracts the real and imaginary parts.
    * `v = atan2l(y, x);`: Calculates the argument using `atan2l`.
    * The rest of the code focuses on calculating `log(|z|)`.
    * The final `RETURNI(CMPLXL(..., v))` combines the calculated magnitude logarithm with the argument.

**3. Detailed Implementation Analysis (Iterative and Keyword-Driven):**

* **Magnitude Calculation (`log(|z|)`):** This is the more complex part. The code handles various edge cases and optimizations:
    * **NaNs and Infs:**  The first check handles these special floating-point values using the general formula, preventing issues.
    * **Special Cases (ax == 1):** Optimization for when the real part's absolute value is 1.
    * **Large Differences in Magnitudes:**  If `ax` is much larger than `ay`, `log(|z|)` is approximately `log(ax)`.
    * **Overflow and Underflow Prevention:** The code carefully scales values using powers of 2 (`0x1p-16382L`, `0x1p16383L`) and adds/subtracts multiples of `ln(2)` to avoid overflow or underflow during intermediate calculations. This is a common technique in high-precision numerical computations.
    * **Denormal Numbers:** Special handling for very small numbers to maintain precision.
    * **Near 1 Optimization (log1p):** When `|z|` is close to 1, using `log1p(x)` (which computes `log(1+x)` accurately for small `x`) improves precision.
    * **Dekker's Algorithm:** The code uses Dekker's algorithm for high-precision multiplication to calculate `ax*ax` and `ay*ay`. This signals a concern for accuracy and potential cancellation errors.
    * **Briggs-Kahan Algorithm (Modified):**  A variant of the Briggs-Kahan algorithm is used for summing the squares.
* **Constants:**  The definitions of `ln2_hi`, `ln2l_lo`, and `MULT_REDUX` are important for the implementation's accuracy and efficiency. These constants are related to the binary representation of `ln(2)` and are used for range reduction.
* **Macros:** `ENTERIT` and `RETURNI` are likely macros for debugging or tracing. `GET_LDBL_EXPSIGN` is for extracting the exponent and sign of a `long double`.

**4. Relationship to Android and Examples:**

* **Foundation of Math:**  Emphasize that this function is a fundamental building block for many higher-level math operations.
* **NDK Use:**  Explain how NDK developers can directly use `clogl` through the `<complex.h>` header. Provide a simple C++ example.
* **Framework Use (Indirect):** Highlight that while framework developers don't directly call `clogl`, it's used by other system libraries and potentially by Java's `Math` class for complex number calculations (though Java's built-in support for complex numbers is limited).

**5. Dynamic Linker (Conceptual Explanation):**

* **Focus on the "Why":** Explain that understanding the dynamic linker helps understand how this code is loaded and used.
* **Simplified SO Layout:**  Provide a basic diagram of an SO file with sections like `.text`, `.data`, `.rodata`, `.dynsym`, `.rel.dyn`, and `.rel.plt`.
* **Symbol Resolution:** Describe the process of how the dynamic linker resolves symbols (functions, variables) needed by the SO, explaining the roles of `.dynsym`, `.rel.dyn`, and `.rel.plt`. Distinguish between direct linking and PLT for function calls.

**6. Assumptions, Inputs, and Outputs:**

* **Standard Complex Number Input:** Assume the input `z` is a valid `long double complex` number.
* **Output:** The output is the natural logarithm of `z`, also a `long double complex` number.
* **Edge Cases:** Consider inputs like 0, negative real numbers (where the imaginary part will be pi), and very large or very small complex numbers.

**7. Common User Errors:**

* **Incorrect Headers:** Emphasize the need to include `<complex.h>`.
* **Type Mismatches:** Point out potential issues when mixing `float`, `double`, and `long double` without explicit casting.
* **Lack of Complex Number Awareness:** Explain that beginners might try to use `logl()` directly on complex numbers, which is incorrect.

**8. Debugging and Tracing:**

* **NDK Debugging:** Explain how to use `adb`, `gdb`, and breakpoints to step into the `clogl` function.
* **Source Code Availability:**  Highlight that having the source code (`s_clogl.c`) is crucial for in-depth debugging.
* **Log Statements (Hypothetical):**  Suggest adding `LOG` statements within the code (if one had the ability to modify and rebuild the system library for debugging purposes) to track variable values.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:**  Focus solely on the mathematical formulas.
* **Correction:** Realize the importance of explaining the practical aspects of how this code fits into the Android ecosystem (NDK, dynamic linking).
* **Initial thought:** Provide a highly technical explanation of Dekker's algorithm.
* **Correction:**  Provide a high-level explanation, recognizing the audience might not be numerical analysis experts. Focus on the *purpose* of the algorithm (high precision).
* **Initial thought:**  Assume the reader has deep knowledge of dynamic linking.
* **Correction:**  Provide a simplified overview of the key concepts relevant to understanding how the `clogl` code is loaded and used.

By following these steps, breaking down the problem into smaller parts, and iteratively refining the analysis, we can arrive at a comprehensive and understandable explanation of the `s_clogl.c` code.好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/s_clogl.c` 这个文件。

**1. 功能列举**

`s_clogl.c` 文件实现了计算 **长双精度浮点数复数的自然对数** 的函数 `clogl(long double complex z)`。  更具体地说，它计算了复数 `z` 的主值对数。

**2. 与 Android 功能的关系及举例**

* **Android 的 C 标准库 (Bionic Libc) 的一部分:**  `libm` 是 Bionic 中提供数学运算支持的关键库。`clogl` 作为复数运算的一部分，为需要进行复数对数计算的 Android 组件提供基础功能。
* **NDK (Native Development Kit) 支持:** 通过 NDK，开发者可以使用 C/C++ 编写 Android 应用的 native 代码。`clogl` 函数可以通过 `<complex.h>` 头文件在 NDK 中被调用。例如，一个使用 NDK 的游戏引擎或科学计算应用可能会使用 `clogl` 来进行复数相关的数学运算。

   ```c++
   #include <complex.h>
   #include <stdio.h>

   int main() {
       long double complex z = 2.0 + 3.0 * I;
       long double complex result = clogl(z);
       printf("clogl(%Lf + %Lfi) = %Lf + %Lfi\n", creall(z), cimagl(z), creall(result), cimagl(result));
       return 0;
   }
   ```

* **Android Framework 的间接使用:** 虽然 Android Framework 通常使用 Java 进行开发，但在底层，许多系统库和组件仍然使用 C/C++。Framework 中一些涉及数学计算的模块可能会间接地依赖 `libm` 中的函数，包括 `clogl`。例如，图形渲染、音频处理等底层模块在某些情况下可能涉及复数运算。

**3. `libc` 函数 `clogl` 的实现详解**

`clogl(long double complex z)` 函数的实现基于复数对数的定义：

`log(z) = log(|z|) + i * arg(z)`

其中，`|z|` 是 `z` 的模（绝对值），`arg(z)` 是 `z` 的辐角（角度）。

以下是代码实现的关键步骤和技术：

* **提取实部和虚部:**
   ```c
   x = creall(z);
   y = cimagl(z);
   ```
   使用 `creall()` 和 `cimagl()` 宏（或函数）分别获取复数 `z` 的实部 `x` 和虚部 `y`。

* **计算辐角:**
   ```c
   v = atan2l(y, x);
   ```
   使用 `atan2l(y, x)` 函数计算复数的辐角 `v`。`atan2l` 能够根据 `x` 和 `y` 的符号确定正确的象限。

* **计算模的对数:**  这是实现的核心和难点，代码采取了多种优化策略以提高精度和处理各种特殊情况：
    * **处理 NaN 和 Inf:**
      ```c
      if (kx == MAX_EXP || ky == MAX_EXP)
          RETURNI(CMPLXL(logl(hypotl(x, y)), v));
      ```
      如果实部或虚部为 NaN 或无穷大，则使用通用的公式，计算模的对数使用 `logl(hypotl(x, y))`，其中 `hypotl(x, y)` 计算 `sqrt(x^2 + y^2)`。
    * **避免不必要的下溢和提高当 ax 接近 1 时的精度:**
      ```c
      if (ax == 1) {
          if (ky < (MIN_EXP - 1) / 2)
              RETURNI(CMPLXL((ay / 2) * ay, v));
          RETURNI(CMPLXL(log1pl(ay * ay) / 2, v));
      }
      ```
      当实部的绝对值 `ax` 为 1 时，进行特殊处理，使用 `log1pl(ay * ay) / 2`，其中 `log1pl(x)` 计算 `log(1 + x)`，对于接近 0 的 `x` 能提供更高的精度。
    * **避免当 ax 不小时的下溢和处理零参数:**
      ```c
      if (kx - ky > MANT_DIG || ay == 0)
          RETURNI(CMPLXL(logl(ax), v));
      ```
      如果 `ax` 比 `ay` 大很多，或者虚部为 0，模的对数近似等于 `logl(ax)`。
    * **避免溢出:**
      ```c
      if (kx >= MAX_EXP - 1)
          RETURNI(CMPLXL(logl(hypotl(x * 0x1p-16382L, y * 0x1p-16382L)) +
              (MAX_EXP - 2) * ln2l_lo + (MAX_EXP - 2) * ln2_hi, v));
      if (kx >= (MAX_EXP - 1) / 2)
          RETURNI(CMPLXL(logl(hypotl(x, y)), v));
      ```
      当 `ax` 非常大时，通过缩放输入来避免 `hypotl` 函数的溢出。这里用到了 `ln(2)` 的高精度近似值 `ln2_hi` 和 `ln2l_lo`。
    * **减少不精确性和避免当 ax 是次正规数时的下溢:**
      ```c
      if (kx <= MIN_EXP - 2)
          RETURNI(CMPLXL(logl(hypotl(x * 0x1p16383L, y * 0x1p16383L)) +
              (MIN_EXP - 2) * ln2l_lo + (MIN_EXP - 2) * ln2_hi, v));
      ```
      当 `ax` 是次正规数（非常接近 0）时，通过放大输入来提高计算精度。
    * **避免剩余的下溢:**
      ```c
      if (ky < (MIN_EXP - 1) / 2 + MANT_DIG)
          RETURNI(CMPLXL(logl(hypotl(x, y)), v));
      ```
      进一步处理小数值的情况。
    * **使用 Dekker 算法精确计算平方:**
      ```c
      t = (long double)(ax * (MULT_REDUX + 1));
      axh = (long double)(ax - t) + t;
      axl = ax - axh;
      ax2h = ax * ax;
      ax2l = axh * axh - ax2h + 2 * axh * axl + axl * axl;
      // ... 对 ay 进行类似的操作
      ```
      Dekker 算法用于将浮点数的平方计算分解成高位和低位两部分，以提高精度。
    * **根据模的大小选择不同的计算策略:**
      ```c
      sh = ax2h;
      sl = ay2h;
      _2sumF(sh, sl);
      if (sh < 0.5 || sh >= 3)
          RETURNI(CMPLXL(logl(ay2l + ax2l + sl + sh) / 2, v));
      sh -= 1;
      _2sum(sh, sl);
      _2sum(ax2l, ay2l);
      _2sum(sh, ax2l);
      _2sum(sl, ay2l);
      t = ax2l + sl;
      _2sumF(sh, t);
      RETURNI(CMPLXL(log1pl(ay2l + t + sh) / 2, v));
      ```
      这段代码根据 `ax^2 + ay^2` 的大小选择不同的计算方法。如果模的平方远离 1，直接使用 `logl`；如果模的平方接近 1，则使用 `log1pl` 以提高精度。这里还使用了类似 Briggs-Kahan 算法的思想来更精确地计算和。`_2sumF` 和 `_2sum` 可能是用于高精度加法的宏或内联函数。

* **组合结果:**
   ```c
   RETURNI(CMPLXL(..., v));
   ```
   使用 `CMPLXL` 宏将计算得到的模的对数和辐角组合成最终的复数结果。`RETURNI` 可能是一个包含返回语句和一些清理工作的宏。

**4. Dynamic Linker 的功能及符号处理**

Dynamic Linker（在 Android 上主要是 `linker64` 或 `linker`）负责在程序运行时加载共享库（.so 文件）并将它们链接到应用程序的进程空间。

**SO 布局样本:**

一个典型的 Android .so 文件的布局可能如下所示（简化）：

```
ELF Header
Program Headers
Section Headers

.text          (可执行代码段)
.rodata        (只读数据段，例如字符串常量)
.data          (可读写数据段，例如全局变量)
.bss           (未初始化的数据段)
.dynsym        (动态符号表)
.dynstr        (动态字符串表)
.hash          (符号哈希表)
.plt           (过程链接表，用于延迟绑定)
.got           (全局偏移表)
.rel.dyn       (用于 .data 段的重定位信息)
.rel.plt       (用于 .plt 段的重定位信息)
... (其他段)
```

**符号处理过程:**

1. **加载 SO 文件:** 当程序需要使用一个共享库时，Dynamic Linker 会找到并加载该 .so 文件到内存中。
2. **解析 ELF Header 和 Program Headers:**  Linker 读取这些头部信息，了解 SO 文件的结构和加载方式。
3. **符号查找:** 当程序调用共享库中的函数（例如 `clogl`）时，Linker 需要找到该函数的地址。
    * **动态符号表 (`.dynsym`):**  包含了 SO 文件导出的符号（例如 `clogl`）以及它需要的外部符号。每个符号都有一个名称（指向 `.dynstr` 的偏移）和其他属性（类型、绑定信息、地址等）。
    * **动态字符串表 (`.dynstr`):**  存储了符号名称的字符串。
    * **符号哈希表 (`.hash`):**  用于加速符号查找。
4. **重定位:** 由于共享库在编译时并不知道最终的加载地址，因此需要进行重定位。
    * **全局偏移表 (`.got`):**  存储了全局变量和外部函数的地址。在加载时，Linker 会用实际地址填充 GOT 表项。
    * **过程链接表 (`.plt`):**  用于延迟绑定。第一次调用外部函数时，会跳转到 PLT 中的一段代码，该代码负责调用 Linker 来解析符号并更新 GOT 表项。后续调用将直接跳转到 GOT 中已解析的地址。
    * **重定位表 (`.rel.dyn`, `.rel.plt`):**  包含了如何修改代码和数据段中某些位置的指令，以便它们指向正确的地址。例如，`.rel.plt` 指示如何修改 PLT 条目。
5. **符号绑定:**  Linker 将程序中对共享库符号的引用绑定到共享库中相应的符号地址。

**`clogl` 的符号处理:**

* **导出符号:**  `clogl` 函数会被标记为导出符号，这意味着其他共享库或可执行文件可以调用它。它的信息会存储在 `.dynsym` 中。
* **被调用:** 当应用程序或另一个共享库调用 `clogl` 时，如果 `clogl` 位于不同的共享库中，Dynamic Linker 将负责解析 `clogl` 的地址并建立正确的调用关系。如果使用延迟绑定，首次调用 `clogl` 时会触发符号解析。

**5. 逻辑推理，假设输入与输出**

假设输入 `z = 1.0 + 1.0i`：

* **输入:** `z = 1.0 + 1.0i`
* **计算模:** `|z| = sqrt(1^2 + 1^2) = sqrt(2)`
* **计算模的对数:** `log(|z|) = log(sqrt(2)) = 0.5 * log(2) ≈ 0.34657`
* **计算辐角:** `arg(z) = atan2(1, 1) = pi / 4 ≈ 0.78540`
* **输出:** `clogl(1.0 + 1.0i) ≈ 0.34657 + 0.78540i`

**6. 用户或编程常见的使用错误**

* **未包含头文件:**  忘记包含 `<complex.h>`，导致 `clogl` 未声明。
* **类型错误:**  将实数传递给 `clogl`，或者期望 `clogl` 返回实数。`clogl` 接受 `long double complex` 并返回 `long double complex`。
* **对数分支的理解不足:**  复数对数是多值函数，`clogl` 返回的是主值。用户可能没有意识到这一点，导致结果与预期不符。
* **精度问题:**  虽然 `long double` 提供了较高的精度，但在极端情况下仍然可能存在精度损失。用户应该了解浮点数运算的局限性。
* **在不支持复数的环境中使用:**  尝试在不包含复数支持的 C 或 C++ 环境中使用 `clogl`。

**7. Android Framework 或 NDK 如何到达这里作为调试线索**

调试涉及 `clogl` 的问题时，可以按照以下步骤追踪调用栈：

**Android Framework (Java 层):**

1. **Java 代码调用:**  Framework 可能会使用 `java.lang.Math` 或其他相关类进行数学运算。虽然 Java 的 `Math` 类不直接支持复数，但一些底层的图形或信号处理库（可能通过 JNI 调用 native 代码）可能会间接使用复数运算。
2. **JNI 调用:**  Java 代码通过 JNI (Java Native Interface) 调用 native 代码 (C/C++)。
3. **Native 代码:**  Native 代码中可能会调用 `libm.so` 中的函数，包括 `clogl`。可以使用调试器（例如 gdbserver 和 gdb）来跟踪 JNI 调用。

**NDK (Native 层):**

1. **NDK 代码调用:**  使用 NDK 开发的应用可以直接在 C/C++ 代码中包含 `<complex.h>` 并调用 `clogl`。
2. **链接 `libm.so`:**  NDK 构建系统会将应用链接到 `libm.so`。
3. **动态链接:**  在应用启动时，Dynamic Linker 会加载 `libm.so`，并将应用中对 `clogl` 的调用链接到 `libm.so` 中的实现。

**调试线索:**

* **断点:**  在 gdb 中设置断点到 `clogl` 函数的入口地址。
* **查看调用栈:**  使用 `bt` 命令查看调用栈，可以了解 `clogl` 是从哪里被调用的。
* **检查寄存器和内存:**  查看传递给 `clogl` 的参数值，以及函数内部的变量值。
* **使用 `adb logcat`:**  在 native 代码中使用 `__android_log_print` 输出调试信息。
* **查看 `maps` 文件:**  `/proc/<pid>/maps` 文件显示了进程的内存映射，可以确认 `libm.so` 是否被加载以及加载地址。
* **使用 `strace`:**  跟踪系统调用，可以看到动态链接器的加载过程和符号解析过程。

总而言之，`s_clogl.c` 是 Android 系统中用于计算复数自然对数的关键底层函数，它通过精心的数值算法处理各种边界条件和精度要求，为上层应用和框架提供可靠的数学支持。理解其实现原理和在 Android 系统中的位置对于进行底层开发和问题排查至关重要。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_clogl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * Copyright (c) 2013 Bruce D. Evans
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

#include <complex.h>
#include <float.h>
#ifdef __i386__
#include <ieeefp.h>
#endif

#include "fpmath.h"
#include "math.h"
#include "math_private.h"

#define	MANT_DIG	LDBL_MANT_DIG
#define	MAX_EXP		LDBL_MAX_EXP
#define	MIN_EXP		LDBL_MIN_EXP

static const double
ln2_hi = 6.9314718055829871e-1;		/*  0x162e42fefa0000.0p-53 */

#if LDBL_MANT_DIG == 64
#define	MULT_REDUX	0x1p32		/* exponent MANT_DIG / 2 rounded up */
static const double
ln2l_lo = 1.6465949582897082e-12;	/*  0x1cf79abc9e3b3a.0p-92 */
#elif LDBL_MANT_DIG == 113
#define	MULT_REDUX	0x1p57
static const long double
ln2l_lo = 1.64659495828970812809844307550013433e-12L;	/*  0x1cf79abc9e3b39803f2f6af40f343.0p-152L */
#else
#error "Unsupported long double format"
#endif

long double complex
clogl(long double complex z)
{
	long double ax, ax2h, ax2l, axh, axl, ay, ay2h, ay2l, ayh, ayl;
	long double sh, sl, t;
	long double x, y, v;
	uint16_t hax, hay;
	int kx, ky;

	ENTERIT(long double complex);

	x = creall(z);
	y = cimagl(z);
	v = atan2l(y, x);

	ax = fabsl(x);
	ay = fabsl(y);
	if (ax < ay) {
		t = ax;
		ax = ay;
		ay = t;
	}

	GET_LDBL_EXPSIGN(hax, ax);
	kx = hax - 16383;
	GET_LDBL_EXPSIGN(hay, ay);
	ky = hay - 16383;

	/* Handle NaNs and Infs using the general formula. */
	if (kx == MAX_EXP || ky == MAX_EXP)
		RETURNI(CMPLXL(logl(hypotl(x, y)), v));

	/* Avoid spurious underflow, and reduce inaccuracies when ax is 1. */
	if (ax == 1) {
		if (ky < (MIN_EXP - 1) / 2)
			RETURNI(CMPLXL((ay / 2) * ay, v));
		RETURNI(CMPLXL(log1pl(ay * ay) / 2, v));
	}

	/* Avoid underflow when ax is not small.  Also handle zero args. */
	if (kx - ky > MANT_DIG || ay == 0)
		RETURNI(CMPLXL(logl(ax), v));

	/* Avoid overflow. */
	if (kx >= MAX_EXP - 1)
		RETURNI(CMPLXL(logl(hypotl(x * 0x1p-16382L, y * 0x1p-16382L)) +
		    (MAX_EXP - 2) * ln2l_lo + (MAX_EXP - 2) * ln2_hi, v));
	if (kx >= (MAX_EXP - 1) / 2)
		RETURNI(CMPLXL(logl(hypotl(x, y)), v));

	/* Reduce inaccuracies and avoid underflow when ax is denormal. */
	if (kx <= MIN_EXP - 2)
		RETURNI(CMPLXL(logl(hypotl(x * 0x1p16383L, y * 0x1p16383L)) +
		    (MIN_EXP - 2) * ln2l_lo + (MIN_EXP - 2) * ln2_hi, v));

	/* Avoid remaining underflows (when ax is small but not denormal). */
	if (ky < (MIN_EXP - 1) / 2 + MANT_DIG)
		RETURNI(CMPLXL(logl(hypotl(x, y)), v));

	/* Calculate ax*ax and ay*ay exactly using Dekker's algorithm. */
	t = (long double)(ax * (MULT_REDUX + 1));
	axh = (long double)(ax - t) + t;
	axl = ax - axh;
	ax2h = ax * ax;
	ax2l = axh * axh - ax2h + 2 * axh * axl + axl * axl;
	t = (long double)(ay * (MULT_REDUX + 1));
	ayh = (long double)(ay - t) + t;
	ayl = ay - ayh;
	ay2h = ay * ay;
	ay2l = ayh * ayh - ay2h + 2 * ayh * ayl + ayl * ayl;

	/*
	 * When log(|z|) is far from 1, accuracy in calculating the sum
	 * of the squares is not very important since log() reduces
	 * inaccuracies.  We depended on this to use the general
	 * formula when log(|z|) is very far from 1.  When log(|z|) is
	 * moderately far from 1, we go through the extra-precision
	 * calculations to reduce branches and gain a little accuracy.
	 *
	 * When |z| is near 1, we subtract 1 and use log1p() and don't
	 * leave it to log() to subtract 1, since we gain at least 1 bit
	 * of accuracy in this way.
	 *
	 * When |z| is very near 1, subtracting 1 can cancel almost
	 * 3*MANT_DIG bits.  We arrange that subtracting 1 is exact in
	 * doubled precision, and then do the rest of the calculation
	 * in sloppy doubled precision.  Although large cancellations
	 * often lose lots of accuracy, here the final result is exact
	 * in doubled precision if the large calculation occurs (because
	 * then it is exact in tripled precision and the cancellation
	 * removes enough bits to fit in doubled precision).  Thus the
	 * result is accurate in sloppy doubled precision, and the only
	 * significant loss of accuracy is when it is summed and passed
	 * to log1p().
	 */
	sh = ax2h;
	sl = ay2h;
	_2sumF(sh, sl);
	if (sh < 0.5 || sh >= 3)
		RETURNI(CMPLXL(logl(ay2l + ax2l + sl + sh) / 2, v));
	sh -= 1;
	_2sum(sh, sl);
	_2sum(ax2l, ay2l);
	/* Briggs-Kahan algorithm (except we discard the final low term): */
	_2sum(sh, ax2l);
	_2sum(sl, ay2l);
	t = ax2l + sl;
	_2sumF(sh, t);
	RETURNI(CMPLXL(log1pl(ay2l + t + sh) / 2, v));
}

"""

```
Response:
Let's break down the thought process for answering the request about `e_sqrtl.c`.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the provided C code (`e_sqrtl.c`) within the context of Android's Bionic library. The request specifically asks for:

* Functionality explanation.
* Relationship to Android features.
* Detailed explanation of `libc` functions used.
* Handling of dynamic linking (if applicable).
* Logical inference with examples.
* Common usage errors.
* How Android frameworks/NDK reach this code.
* Frida hooking examples.

**2. Initial Code Analysis and Identification of Key Function:**

The first step is to examine the code itself. The filename `e_sqrtl.c` and the presence of a function named `sqrtl` immediately suggest that this file implements the square root function for `long double` (extended precision floating-point numbers). The BSD license header confirms its origin from FreeBSD.

**3. Deconstructing the `sqrtl` Function:**

Next, analyze the `sqrtl` function step-by-step:

* **Handling Special Cases:** Notice the initial checks for NaN, Infinity, and zero. These are crucial for conforming to IEEE 754 standards.
* **Handling Negative Input:** The code explicitly checks for negative input and returns NaN, raising an "invalid operation" exception (implicitly).
* **Normalization and Scaling:**  The code normalizes subnormal numbers and scales the input to be within a specific range (between 1 and 4) with an appropriate power of 2. This simplifies the initial guess for the Newton-Raphson iteration.
* **Newton-Raphson Iteration:** The core of the algorithm is the Newton-Raphson method for finding the square root. The code uses an initial estimate (`sqrt(u.e)`) and then refines it. There's even an optimization for higher precision (`LDBL_MANT_DIG > 100`).
* **Precision Refinement:**  The code meticulously handles the lower bits of the mantissa to improve accuracy.
* **Rounding:**  The code pays close attention to rounding modes (`FE_TOWARDZERO`, `FE_TONEAREST`, `FE_UPWARD`) to ensure correct results based on the current floating-point environment.
* **Error Handling:** The code uses `fenv.h` functions (`feholdexcept`, `feclearexcept`, `fegetround`, `fesetround`, `fetestexcept`, `feupdateenv`) to manage floating-point exceptions and rounding modes.

**4. Identifying Related `libc` Functions and Concepts:**

As the `sqrtl` function is analyzed, identify the standard C library (`libc`) functions used:

* **`sqrt()`:**  This is the `double` precision square root function, used for the initial estimate.
* **Floating-Point Environment Functions (`fenv.h`)**:  `feholdexcept`, `feclearexcept`, `fegetround`, `fesetround`, `fetestexcept`, `feupdateenv`. These are key for managing floating-point behavior.
* **Data Types:** `long double`, `union IEEEl2bits`, `fenv_t`. Understanding these data types is crucial.

**5. Connecting to Android's Bionic:**

Recognize that this code resides within Bionic, Android's standard C library. This means:

* **Direct Usage by NDK:**  Native code developed using the Android NDK can directly call `sqrtl`.
* **Usage by Android Framework (Indirectly):**  While the Android framework is primarily Java-based, its native components and some system services are written in C/C++ and utilize Bionic.
* **Dynamic Linking:** Bionic is a shared library (`.so`), and applications link against it at runtime.

**6. Addressing Dynamic Linking:**

Since Bionic is involved, explain how dynamic linking works in this context:

* **Shared Object (`.so`):** Bionic (`libc.so`) is a shared library.
* **SO Layout:** Provide a basic example of a `.so` structure, highlighting the GOT and PLT.
* **Linking Process:** Describe how the dynamic linker resolves symbols like `sqrtl` at runtime, using the GOT and PLT.

**7. Crafting Examples and Scenarios:**

Develop examples to illustrate:

* **Logical Inference:** Show how the function handles different inputs (positive, negative, zero, infinity, NaN).
* **Common Usage Errors:**  Explain potential issues like passing a negative number to `sqrtl` without proper error handling.

**8. Detailing the Android Framework/NDK Path:**

Outline the steps involved in calling `sqrtl` from an Android application:

* **NDK:** Java calls native method -> JNI -> Native C/C++ code calls `sqrtl`.
* **Framework:** Java code (less likely to directly call `sqrtl`) might invoke native services that eventually use it.

**9. Providing Frida Hooking Examples:**

Create Frida snippets to demonstrate how to intercept calls to `sqrtl` for debugging and analysis. Show examples for logging arguments and return values.

**10. Structuring the Response:**

Organize the information logically, using clear headings and explanations. Use formatting (like code blocks) to improve readability. Ensure the language is precise and avoids jargon where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus heavily on the bit manipulation in `inc` and `dec`. **Correction:** While important for understanding the ulp calculations, the higher-level functionality of `sqrtl` is more critical for the initial request.
* **Initial thought:**  Go deep into the mathematical proof of Newton-Raphson. **Correction:**  Keep the explanation of the algorithm concise and focus on its purpose within the code.
* **Initial thought:** Provide very complex Frida examples. **Correction:** Start with simple logging examples to make it easier to understand.

By following this detailed thinking process, the comprehensive and accurate answer to the request can be generated. It's a process of understanding the code, connecting it to the broader Android ecosystem, and then presenting the information in a clear and organized manner.
好的，我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_sqrtl.c` 这个文件。

**功能概述**

`e_sqrtl.c` 文件实现了 `sqrtl(long double x)` 函数，其功能是计算 `long double` 类型浮点数 `x` 的平方根。这是一个高精度版本的平方根函数，通常用于需要较高精度的数学计算。

**与 Android 功能的关系**

`sqrtl` 函数是 Android Bionic 库（C 库）的一部分，因此它是 Android 系统和应用程序中进行数学运算的基础功能之一。

* **NDK 开发:** 使用 Android NDK（Native Development Kit）进行原生开发的应用程序可以直接调用 `sqrtl` 函数进行高精度平方根计算。例如，一个需要进行复杂物理模拟或图形计算的游戏引擎可能会使用此函数。
* **Android Framework:** 虽然 Android Framework 主要使用 Java，但在其底层实现中，一些系统服务和组件会使用 C/C++ 代码，这些代码可能会间接调用 `sqrtl`。例如，一些图形渲染相关的 native 代码可能会使用到。
* **系统库和工具:** Android 系统本身的一些库和工具（例如与硬件抽象层 HAL 交互的代码）也可能使用到 `sqrtl`。

**`libc` 函数功能实现详解**

1. **`sqrtl(long double x)`:**
   - **特殊值处理:**
     - 如果 `x` 是 NaN (Not a Number)，则 `sqrtl(x)` 返回 NaN。
     - 如果 `x` 是正无穷大，则 `sqrtl(x)` 返回正无穷大。
     - 如果 `x` 是负无穷大，则 `sqrtl(x)` 返回 NaN。
     - 如果 `x` 是 `+0` 或 `-0`，则 `sqrtl(x)` 返回 `+0` 或 `-0`。
   - **负数处理:** 如果 `x` 是负数，则触发 "invalid operation" 浮点异常，并返回 NaN。
   - **子常数处理:** 如果 `x` 是一个很小的子常数（subnormal number），代码会将其调整到正常范围，并记录一个偏移量 `k`。
   - **归一化处理:** 将 `x` 归一化为 `e * 2^n` 的形式，并根据 `n` 的奇偶性调整 `e` 的范围，同时更新偏移量 `k`。这有助于提高牛顿迭代的效率。
   - **牛顿迭代法:** 使用牛顿迭代法逼近平方根。
     - 首先，使用 `sqrt(u.e)` (标准 `double` 类型的平方根函数) 获取一个初始的 53 位精度的估计值 `xn`。
     - 如果需要更高的精度 (`LDBL_MANT_DIG > 100`)，则进行一次额外的牛顿迭代来提高到 106 位精度。
     - 将 `u.e` 分解为高位和低位部分，以实现更高的精度。
     - 使用公式 `xn = xn + (u.e / xn)` 和低位信息进行迭代优化。
   - **指数调整:** 将结果的指数调整回正确的范围，考虑之前记录的偏移量 `k`。
   - **精确度校正和舍入:**
     - 设置舍入模式为向零舍入 (`FE_TOWARDZERO`)。
     - 计算 `x / u.e`，如果结果是精确的（没有触发 `FE_INEXACT` 异常），并且等于 `u.e`，则直接返回 `u.e`。
     - 如果结果不精确，或者需要进行舍入校正，则根据当前的舍入模式 (`FE_TONEAREST`, `FE_UPWARD` 等) 对结果进行微调 (`inc` 或 `dec` 函数用于增加或减少一个最小单位 ulp)。
   - **浮点异常处理:** 使用 `fenv.h` 中的函数来保存和恢复浮点环境，清除和检查浮点异常。

2. **`inc(long double x)` (静态内联函数):**
   - 功能：返回比 `x` 大的最小的 `long double` 值（即 `x` 加上一个最小单位 ulp - unit in the last place）。
   - 实现：直接操作 `long double` 的位表示。增加最低有效位，并处理可能的进位。

3. **`dec(long double x)` (静态内联函数):**
   - 功能：返回比 `x` 小的最大的 `long double` 值（即 `x` 减去一个最小单位 ulp）。
   - 实现：直接操作 `long double` 的位表示。减少最低有效位，并处理可能的借位。

**涉及 dynamic linker 的功能**

`e_sqrtl.c` 本身的代码不直接涉及 dynamic linker 的操作。但是，作为 `libc.so` 的一部分，`sqrtl` 函数是通过 dynamic linker 加载和链接的。

**SO 布局样本**

```
libc.so:
    ...
    .text:
        ...
        [sqrtl 函数的机器码]  <-- sqrtl 的代码位于 .text 段
        ...
    .rodata:
        ...
    .data:
        ...
    .bss:
        ...
    .dynsym:  <-- 动态符号表
        ...
        sqrtl  <-- 记录了 sqrtl 函数的符号信息和地址
        ...
    .dynstr:  <-- 动态字符串表
        ...
        sqrtl
        ...
    .got:      <-- 全局偏移表 (Global Offset Table)
        ...
        [sqrtl 函数的 GOT 条目] <---  初始可能为 0，加载时被 linker 填充
        ...
    .plt:      <-- 程序链接表 (Procedure Linkage Table)
        ...
        [sqrtl 函数的 PLT 条目] <---  用于跳转到实际的 sqrtl 函数
        ...
    ...
```

**链接的处理过程**

1. **编译时:** 当应用程序或共享库的代码调用 `sqrtl` 时，编译器会生成对 `sqrtl` 的外部引用。链接器在链接时会注意到这个外部引用，但由于 `sqrtl` 在 `libc.so` 中，链接器不会将其代码直接链接到当前的可执行文件或共享库中。链接器会在当前模块的 GOT 和 PLT 中创建相应的条目。
2. **加载时:** 当 Android 系统加载应用程序或共享库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责解析动态链接。
3. **符号查找:** Dynamic linker 会查找 `libc.so` 中的 `sqrtl` 符号。它会遍历 `libc.so` 的 `.dynsym` 段，找到 `sqrtl` 的地址。
4. **GOT 表填充:** Dynamic linker 将 `sqrtl` 函数在 `libc.so` 中的实际地址填充到调用模块的 GOT 表中对应 `sqrtl` 的条目。
5. **PLT 表跳转:** 当程序第一次调用 `sqrtl` 时，会跳转到 PLT 表中 `sqrtl` 对应的条目。PLT 条目会首先检查 GOT 表中的地址是否已填充。如果未填充（通常是第一次调用），PLT 条目会调用 dynamic linker 的一个辅助函数来解析符号。解析完成后，dynamic linker 会将实际地址写入 GOT 表，并且 PLT 条目会将控制权转移到 `sqrtl` 函数的实际地址。后续对 `sqrtl` 的调用将直接通过 GOT 表跳转，避免了重复的符号解析。

**逻辑推理示例**

**假设输入:** `x = 4.0L`

**执行流程:**

1. `u.e` 被赋值为 4.0。
2. 特殊值检查不满足。
3. 负数检查不满足。
4. 子常数检查不满足。
5. 归一化处理：`u.bits.exp` 会被调整，`k` 会被更新。由于 4.0 的指数是偶数，`u.bits.exp` 会被设置为 `0x4000`，`k` 会相应调整。
6. 牛顿迭代：
   - `xn = sqrt(4.0)`，结果为 `2.0`。
   - 后续的迭代会进一步提高精度。
7. 指数调整：结果的指数会根据 `k` 进行调整。
8. 精确度校正和舍入：由于 4.0 的平方根是精确的 2.0，可能不需要进行额外的舍入。
9. **输出:** 接近于 `2.0L` 的 `long double` 值。

**假设输入:** `x = -9.0L`

**执行流程:**

1. `u.e` 被赋值为 -9.0。
2. 符号位检查发现 `u.bits.sign` 为真。
3. **输出:** 返回 NaN (`(x - x) / (x - x)` 的结果为 NaN），并可能触发 "invalid operation" 浮点异常。

**用户或编程常见的使用错误**

1. **传递负数给 `sqrtl` 而不进行检查:**
   ```c
   long double num = -5.0L;
   long double result = sqrtl(num); // 结果是 NaN，可能导致后续计算错误
   ```
   **建议:** 在调用 `sqrtl` 之前，应该检查输入是否为非负数，并处理负数的情况（例如返回错误或使用绝对值）。

2. **忽略浮点异常:** `sqrtl` 在输入为负数时会触发 "invalid operation" 异常。如果程序没有正确处理这些异常，可能会导致不可预测的行为。
   ```c
   #include <fenv.h>
   #include <stdio.h>
   #include <math.h>

   int main() {
       fesetexceptflag(FE_INVALID, 0); // 清除 invalid 标志
       long double num = -5.0L;
       long double result = sqrtl(num);
       if (fetestexcept(FE_INVALID)) {
           printf("Error: Invalid operation (sqrt of a negative number)\n");
       }
       return 0;
   }
   ```

3. **精度问题:** 虽然 `long double` 提供更高的精度，但在某些极端情况下，仍然可能存在精度损失。程序员需要理解浮点数的局限性。

**Android Framework 或 NDK 如何到达这里**

**NDK 路径示例:**

1. **Java 代码调用 Native 方法:**
   ```java
   public class MyMathUtils {
       static {
           System.loadLibrary("native-lib");
       }
       public native double nativeSqrt(double x); // 注意这里为了演示方便使用了 double

       public static void main(String[] args) {
           MyMathUtils utils = new MyMathUtils();
           double result = utils.nativeSqrt(9.0);
           System.out.println("Result: " + result);
       }
   }
   ```

2. **Native (C/C++) 代码实现:**
   ```c++
   #include <jni.h>
   #include <cmath> // 或者直接包含 math.h

   extern "C" JNIEXPORT jdouble JNICALL
   Java_com_example_myapp_MyMathUtils_nativeSqrt(JNIEnv *env, jobject /* this */, jdouble number) {
       return std::sqrt(number); // 这里 std::sqrt 可能会间接调用 libm 中的实现
   }
   ```

   如果需要使用 `long double` 版本，可以将 Java 中的类型更改为不常用的 `long double` 的对应类型 (如果存在，或者通过 JNI 传递字节数组)，并在 Native 代码中使用 `sqrtl`:

   ```c++
   #include <jni.h>
   #include <cmath>
   #include <cfloat> // For LDBL_DIG

   extern "C" JNIEXPORT jdouble JNICALL // 假设 Java 端传递的是 double，但内部计算使用 long double
   Java_com_example_myapp_MyMathUtils_nativeSqrt(JNIEnv *env, jobject /* this */, jdouble number) {
       long double ld_number = (long double)number;
       long double result = sqrtl(ld_number);
       return (jdouble)result; // 转换回 double
   }
   ```

3. **链接:** 当 Native 库被加载时，dynamic linker 会解析 `sqrtl` 的符号，并将其链接到 `libc.so` 中的实现。

**Android Framework 路径示例 (较为间接):**

1. **Java Framework 代码:** Android Framework 中的一些 Java 代码可能会调用系统服务。
2. **系统服务 (C++):** 某些系统服务是用 C++ 实现的，这些服务在执行某些计算时可能会调用 `libc` 中的数学函数。
3. **`libc.so`:**  最终，这些调用会通过函数调用链到达 `libc.so` 中的 `sqrtl` 实现。

**Frida Hook 示例**

```javascript
// Hook sqrtl 函数
Interceptor.attach(Module.findExportByName("libc.so", "sqrtl"), {
  onEnter: function (args) {
    console.log("sqrtl called with argument:", args[0]);
  },
  onLeave: function (retval) {
    console.log("sqrtl returned:", retval);
  }
});

// Hook inc 函数 (静态函数，需要找到其地址)
var incAddress = Module.findExportByName("libc.so", "_Z3inclE"); // 可能需要 demangle 符号名
if (incAddress) {
  Interceptor.attach(incAddress, {
    onEnter: function (args) {
      console.log("inc called with argument:", args[0]);
    },
    onLeave: function (retval) {
      console.log("inc returned:", retval);
    }
  });
} else {
  console.log("Could not find inc function");
}

// Hook dec 函数 (静态函数，需要找到其地址)
var decAddress = Module.findExportByName("libc.so", "_Z3declE"); // 可能需要 demangle 符号名
if (decAddress) {
  Interceptor.attach(decAddress, {
    onEnter: function (args) {
      console.log("dec called with argument:", args[0]);
    },
    onLeave: function (retval) {
      console.log("dec returned:", retval);
    }
  });
} else {
  console.log("Could not find dec function");
}
```

**说明:**

* `Module.findExportByName("libc.so", "sqrtl")` 用于查找 `libc.so` 中导出的 `sqrtl` 函数的地址。
* `Interceptor.attach` 用于拦截函数的调用。
* `onEnter` 函数在目标函数执行之前调用，可以访问函数的参数 (`args`)。
* `onLeave` 函数在目标函数返回之后调用，可以访问函数的返回值 (`retval`).
* 对于静态函数 `inc` 和 `dec`，可能需要使用工具（如 `readelf` 或 `nm`）找到它们的符号名 (可能需要 demangle)，或者使用更高级的 Frida 技术来定位它们。

希望以上详细的解释能够帮助你理解 `e_sqrtl.c` 文件及其在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_sqrtl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例作为调试线索。
用中文回复。

"""
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2007 Steven G. Kargl
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

#include <fenv.h>
#include <float.h>

#include "fpmath.h"
#include "math.h"

/* Return (x + ulp) for normal positive x. Assumes no overflow. */
static inline long double
inc(long double x)
{
	union IEEEl2bits u;

	u.e = x;
	if (++u.bits.manl == 0) {
		if (++u.bits.manh == 0) {
			u.bits.exp++;
			u.bits.manh |= LDBL_NBIT;
		}
	}
	return (u.e);
}

/* Return (x - ulp) for normal positive x. Assumes no underflow. */
static inline long double
dec(long double x)
{
	union IEEEl2bits u;

	u.e = x;
	if (u.bits.manl-- == 0) {
		if (u.bits.manh-- == LDBL_NBIT) {
			u.bits.exp--;
			u.bits.manh |= LDBL_NBIT;
		}
	}
	return (u.e);
}

#pragma STDC FENV_ACCESS ON

/*
 * This is slow, but simple and portable. You should use hardware sqrt
 * if possible.
 */

long double
sqrtl(long double x)
{
	union IEEEl2bits u;
	int k, r;
	long double lo, xn;
	fenv_t env;

	u.e = x;

	/* If x = NaN, then sqrt(x) = NaN. */
	/* If x = Inf, then sqrt(x) = Inf. */
	/* If x = -Inf, then sqrt(x) = NaN. */
	if (u.bits.exp == LDBL_MAX_EXP * 2 - 1)
		return (x * x + x);

	/* If x = +-0, then sqrt(x) = +-0. */
	if ((u.bits.manh | u.bits.manl | u.bits.exp) == 0)
		return (x);

	/* If x < 0, then raise invalid and return NaN */
	if (u.bits.sign)
		return ((x - x) / (x - x));

	feholdexcept(&env);

	if (u.bits.exp == 0) {
		/* Adjust subnormal numbers. */
		u.e *= 0x1.0p514;
		k = -514;
	} else {
		k = 0;
	}
	/*
	 * u.e is a normal number, so break it into u.e = e*2^n where
	 * u.e = (2*e)*2^2k for odd n and u.e = (4*e)*2^2k for even n.
	 */
	if ((u.bits.exp - 0x3ffe) & 1) {	/* n is odd.     */
		k += u.bits.exp - 0x3fff;	/* 2k = n - 1.   */
		u.bits.exp = 0x3fff;		/* u.e in [1,2). */
	} else {
		k += u.bits.exp - 0x4000;	/* 2k = n - 2.   */
		u.bits.exp = 0x4000;		/* u.e in [2,4). */
	}

	/*
	 * Newton's iteration.
	 * Split u.e into a high and low part to achieve additional precision.
	 */
	xn = sqrt(u.e);			/* 53-bit estimate of sqrtl(x). */
#if LDBL_MANT_DIG > 100
	xn = (xn + (u.e / xn)) * 0.5;	/* 106-bit estimate. */
#endif
	lo = u.e;
	u.bits.manl = 0;		/* Zero out lower bits. */
	lo = (lo - u.e) / xn;		/* Low bits divided by xn. */
	xn = xn + (u.e / xn);		/* High portion of estimate. */
	u.e = xn + lo;			/* Combine everything. */
	u.bits.exp += (k >> 1) - 1;

	feclearexcept(FE_INEXACT);
	r = fegetround();
	fesetround(FE_TOWARDZERO);	/* Set to round-toward-zero. */
	xn = x / u.e;			/* Chopped quotient (inexact?). */

	if (!fetestexcept(FE_INEXACT)) { /* Quotient is exact. */
		if (xn == u.e) {
			fesetenv(&env);
			return (u.e);
		}
		/* Round correctly for inputs like x = y**2 - ulp. */
		xn = dec(xn);		/* xn = xn - ulp. */
	}

	if (r == FE_TONEAREST) {
		xn = inc(xn);		/* xn = xn + ulp. */
	} else if (r == FE_UPWARD) {
		u.e = inc(u.e);		/* u.e = u.e + ulp. */
		xn = inc(xn);		/* xn  = xn + ulp. */
	}
	u.e = u.e + xn;				/* Chopped sum. */
	feupdateenv(&env);	/* Restore env and raise inexact */
	u.bits.exp--;
	return (u.e);
}

"""

```
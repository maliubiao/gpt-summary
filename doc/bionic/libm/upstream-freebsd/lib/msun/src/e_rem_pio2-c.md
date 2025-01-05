Response:
Let's break down the thought process for analyzing this C code snippet. The goal is to understand its functionality, its relation to Android, and potential usage patterns and pitfalls.

**1. Initial Understanding & Context:**

* **Identify the Core Purpose:** The code's comment `return the remainder of x rem pi/2 in y[0]+y[1]` immediately tells us the main function: calculate `x mod (pi/2)`. The `y[0]` and `y[1]` hint at high-precision results.
* **Recognize the Location:** The path `bionic/libm/upstream-freebsd/lib/msun/src/e_rem_pio2.c` is crucial. "bionic" means Android's C library. `libm` is the math library. "upstream-freebsd" indicates the code originated from FreeBSD's math library, suggesting a level of established correctness. This context is vital for understanding its role within Android.
* **Identify Key Functions/Macros:**  `__ieee754_rem_pio2`, `__kernel_rem_pio2`, `GET_HIGH_WORD`, `GET_LOW_WORD`, `INSERT_WORDS`, `rnint`, `irint`, `scalbn`, `ilogb`. Recognizing these (even if you don't know exactly what they do yet) gives you entry points for investigation.
* **Examine Included Headers:** `<float.h>`, `"math.h"`, `"math_private.h"` provide clues about the data types and related math functions used. `math_private.h` often contains internal details not exposed in the standard `math.h`.
* **Note Constants:**  The definitions of `zero`, `two24`, `invpio2`, `pio2_1`, `pio2_1t`, etc., are important. They represent pre-calculated values related to pi/2 and powers of 2, used for efficient computation.

**2. Functionality Breakdown (Step-by-Step Analysis):**

* **High-Level Flow:** The code seems to handle different ranges of `x` differently. There are early exits for small `x`, specific calculations for intermediate ranges, and a more complex approach for very large `x`.
* **Handling Small `x`:** The commented-out section `if(ix<=0x3fe921fb)` suggests an optimization: if `|x|` is small enough (roughly `pi/4`), the remainder is just `x`.
* **Handling Intermediate `x`:** The code uses a series of `if` and `else if` blocks to handle ranges of `x` up to `9pi/4`. It subtracts multiples of `pi/2` (using pre-calculated constants) and stores the remainder in `y`. The `y[0]` and `y[1]` structure emerges here, likely representing the high and low parts of the remainder for improved accuracy.
* **The `medium` Case:**  This section handles larger `x` values but not astronomically large. It uses `rnint` (round to nearest integer) to estimate how many multiples of `pi/2` fit in `x`. It then performs subtractions and refinements to get the precise remainder. The iterative approach with `pio2_1`, `pio2_2`, `pio2_3` suggests increasing precision in the calculation.
* **Handling Very Large `x`:**  For very large `x`, the code uses `__kernel_rem_pio2`. This strongly suggests that `__ieee754_rem_pio2` acts as a wrapper, handling simpler cases and delegating the hard work to a more general-purpose function. The manipulation with `GET_HIGH_WORD`, `GET_LOW_WORD`, and `INSERT_WORDS`, along with `scalbn` and `ilogb` (though not directly called here, the comment hints at its use conceptually), implies breaking down `x` into smaller pieces for more manageable calculations.
* **Sign Handling:** The code explicitly checks the sign of `x` (`hx > 0` or `hx < 0`) and adjusts the sign of the remainder accordingly.

**3. Connecting to Android:**

* **`libm`'s Role:** The code's location within `bionic/libm` directly links it to Android's core math functionality. Any Android application using standard math functions like `fmod` (for floating-point modulo) might indirectly rely on this code for arguments involving large numbers or requiring high precision.
* **NDK Usage:** Developers using the NDK and performing advanced mathematical calculations in native code would directly interact with functions provided by `libm`, potentially including this one.

**4. Explaining `libc` Functions:**

* **Focus on the Obvious:** Start with functions directly used in the code like `GET_HIGH_WORD`, `GET_LOW_WORD`, `INSERT_WORDS`. These are likely macros or inline functions for manipulating the bit representation of doubles. Explain their purpose in accessing and modifying the sign, exponent, and mantissa.
* **Infer Functionality:**  `rnint` and `irint` strongly suggest rounding to the nearest integer (floating-point and integer result, respectively).
* **Defer Complex Functions:** Acknowledge `__kernel_rem_pio2` as a more complex internal function that handles the core logic for very large numbers. You don't need to fully explain its implementation without more context, but mention its purpose.

**5. Dynamic Linker Aspects:**

* **`libm.so`:** The code resides within `libm`, which will be compiled into a shared object (`.so`) file.
* **Dependency:** Other libraries or the Android framework itself will link against `libm.so` to use its math functions.
* **Linking Process (Conceptual):** Briefly explain how the dynamic linker resolves symbols at runtime. The example SO layout helps visualize this.

**6. Assumptions, Inputs, and Outputs:**

* **Simple Cases:**  Think of basic scenarios, like `x = pi/2 + 0.1` or `x = 3*pi/2 - 0.0001`. Trace the code's logic for these simple inputs to predict the output (`y[0]`, `y[1]`, and the return value).
* **Edge Cases:** Consider inputs like very large numbers, negative numbers, or numbers close to multiples of `pi/2`.

**7. Common Errors:**

* **Incorrect Usage (Though Less Likely Directly):**  Since this is an internal function, direct misuse is less probable. Focus on potential issues if a developer were to *misunderstand* the behavior of related functions like `fmod` and rely on incorrect assumptions about precision for very large arguments.

**8. Debugging Path (Android Framework/NDK):**

* **Start with the User:** How does a user-level action (e.g., an animation) or an NDK call lead to a math function being invoked?
* **Framework and System Services:**  Trace calls down through framework layers. Math operations might be used in graphics, animations, sensor processing, etc.
* **NDK to `libm`:** Explain how an NDK call to a math function directly links against `libm.so`.
* **System Calls (Less Direct):**  In some cases, math functions might be used within system calls, though this is less common for this specific function.
* **Debugging Tools:** Mention `adb logcat`, debuggers, and potentially tracing tools as methods for observing this call chain.

**Self-Correction/Refinement During the Process:**

* **Realizing the Complexity of `__kernel_rem_pio2`:** Initially, you might try to understand its inner workings. However, recognizing it as a separate, more intricate function allows you to focus on the role of `__ieee754_rem_pio2` as a dispatcher.
* **Focusing on the User Perspective (for Errors and Debugging):** While the code itself is low-level, frame potential errors and debugging paths from the perspective of someone using the Android framework or NDK.
* **Iterative Refinement:** Your understanding will deepen as you analyze the code. Go back and refine your explanations as you discover more details. For instance, the initial guess about `y[0]` and `y[1]` might solidify as you see how they are used to accumulate the remainder.
好的，我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_rem_pio2.c` 这个文件。

**文件功能：**

该文件定义了一个函数 `__ieee754_rem_pio2(double x, double *y)`，其主要功能是计算 `x` 除以 `pi/2` 的精确余数，并将余数存储在 `y[0]` 和 `y[1]` 中，其中 `y[0]` 是余数的高精度部分，`y[1]` 是低精度部分。  更具体地说，它返回一个整数 `n`，使得 `x - n * pi/2 = y[0] + y[1]`，且 `|y[0] + y[1]| <= pi/4`。

**与 Android 功能的关系及举例：**

这个函数是 Android 底层数学库 `libm` 的一部分，因此与所有依赖浮点数运算的 Android 功能都有潜在关系。以下是一些例子：

1. **图形渲染 (Graphics Rendering):** Android 的图形系统 (例如，Skia 库) 在进行旋转、缩放、平移等变换时，经常需要进行三角函数运算 (sin, cos, tan 等)。这些三角函数的实现通常会调用 `__ieee754_rem_pio2` 来将角度归约到 `[-pi/4, pi/4]` 区间，以提高计算精度和效率。
   * **例子:** 当一个 Android 应用进行 3D 动画，需要旋转一个物体时，图形库会计算旋转角度的正弦和余弦值。为了确保精度，即使旋转角度很大，也会先用 `__ieee754_rem_pio2` 将角度归约到合适的范围内。

2. **音频处理 (Audio Processing):** 音频信号处理中，例如生成波形、进行傅里叶变换等，也会涉及到三角函数运算。
   * **例子:** 一个音频应用在合成正弦波时，会计算 `sin(frequency * time)`。如果时间很长，`frequency * time` 的值可能很大，`__ieee754_rem_pio2` 会被用来归约角度。

3. **传感器数据处理 (Sensor Data Processing):** 一些传感器 (如陀螺仪、加速度计) 的数据处理可能需要进行坐标转换和角度计算。
   * **例子:** 一个游戏需要根据陀螺仪的读数来控制视角旋转。对陀螺仪的读数进行积分得到旋转角度，如果角度过大，可能需要用 `__ieee754_rem_pio2` 进行归约。

4. **科学计算应用 (Scientific Computing Applications):**  运行在 Android 平台上的科学计算应用会直接或间接地使用 `libm` 提供的数学函数，因此会用到 `__ieee754_rem_pio2`。

**libc 函数的实现细节：**

`__ieee754_rem_pio2` 的实现采用了分段处理和高精度计算的方法，以应对不同大小的输入 `x`。

1. **处理小 `|x|`:** 如果 `|x|` 足够小 (大约小于等于 `pi/4`)，则不需要进行归约，直接将 `x` 作为余数返回。这部分在代码中被注释掉了，说明这个优化可能放在了调用者的逻辑中。

2. **处理中等 `|x|`:** 对于中等大小的 `|x|` (例如，在几个 `pi/2` 的范围内)，代码通过直接减去 `pi/2` 的倍数来计算余数。为了保证精度，使用了 `pio2_1`、`pio2_1t` 等预先计算好的 `pi/2` 的不同精度部分。例如，`pio2_1` 是 `pi/2` 的高 33 位，`pio2_1t` 是剩余的低位部分。这种方法可以有效地计算出高精度的余数。

3. **处理较大的 `|x|` (medium 标签):** 对于更大的 `|x|`，直接减去 `pi/2` 的倍数可能会导致精度损失。这里使用了更复杂的方法：
   * **估计 `pi/2` 的倍数:** 使用 `rnint((double_t)x*invpio2)` 来估计 `x` 是 `pi/2` 的多少倍 (这里 `invpio2` 是 `2/pi` 的近似值)。
   * **初步计算余数:**  计算 `r = x - fn * pio2_1`，其中 `fn` 是估计的倍数。
   * **高精度修正:**  使用 `pio2_1t`、`pio2_2`、`pio2_2t`、`pio2_3`、`pio2_3t` 等更高精度的 `pi/2` 部分进行迭代修正，以得到更精确的余数。

4. **处理非常大的 `|x|`:**  对于非常大的 `|x|`，该函数会调用 `__kernel_rem_pio2`。这表明 `__kernel_rem_pio2` 是一个更通用的、处理大数值情况的函数。在调用之前，`__ieee754_rem_pio2` 会将 `x` 拆分成多个双精度数 `tx[i]`，以便 `__kernel_rem_pio2` 进行高精度计算。

**关于 `__kernel_rem_pio2` 的实现 (超出本文件范围，但很重要)：**

`__kernel_rem_pio2` 函数通常采用更高级的算法，例如使用多精度算术和三角恒等式，来精确计算大角度的三角函数余数。它接收一个由多个双精度数组成的数组 `tx` (代表高精度的 `x`)，以及其他参数，并返回余数 `ty`。

**涉及 dynamic linker 的功能：**

`__ieee754_rem_pio2` 本身的代码不直接涉及 dynamic linker 的功能。但是，作为 `libm.so` 的一部分，它的存在和被调用依赖于 dynamic linker 的工作。

**`libm.so` 布局样本：**

```
libm.so:
    ...
    .text:
        __ieee754_rem_pio2:  # 函数 __ieee754_rem_pio2 的机器码
            ...
        __kernel_rem_pio2:  # 函数 __kernel_rem_pio2 的机器码
            ...
        sin:                 # sin 函数的机器码，可能会调用 __ieee754_rem_pio2
            ...
        cos:                 # cos 函数的机器码，可能会调用 __ieee754_rem_pio2
            ...
        ...
    .data:
        invpio2:             # 常量 invpio2 的值
        pio2_1:              # 常量 pio2_1 的值
        ...
    .dynsym:                # 动态符号表
        __ieee754_rem_pio2  # 符号 __ieee754_rem_pio2
        __kernel_rem_pio2  # 符号 __kernel_rem_pio2
        ...
    .rel.dyn:               # 动态重定位表
        ...
```

**链接的处理过程：**

1. **编译时：** 当一个 Android 应用或 Native 代码模块 (通过 NDK) 调用 `sin()` 或 `cos()` 等数学函数时，编译器会生成对这些函数的未解析引用。

2. **链接时：**
   * **静态链接 (较少见):** 如果采用静态链接，`libm.a` 的代码会被直接复制到最终的可执行文件中。
   * **动态链接 (常见):** 更常见的情况是动态链接。链接器会在生成可执行文件或共享库时，记录下对 `libm.so` 中符号的依赖。

3. **运行时：**
   * 当应用启动或共享库被加载时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libm.so`。
   * Dynamic linker 会解析可执行文件或共享库中对 `libm.so` 中符号的引用。例如，当代码调用 `sin()` 时，如果 `sin()` 的实现内部调用了 `__ieee754_rem_pio2`，dynamic linker 会将 `sin()` 中的 `__ieee754_rem_pio2` 调用地址指向 `libm.so` 中 `__ieee754_rem_pio2` 函数的实际地址。
   * 这个过程依赖于 `.dynsym` (动态符号表) 和 `.rel.dyn` (动态重定位表) 等 sections，它们包含了符号信息和重定位信息。

**逻辑推理、假设输入与输出：**

假设输入 `x = 3.0 * M_PI` (其中 `M_PI` 是 `pi` 的定义)，我们来推断 `__ieee754_rem_pio2(x, y)` 的行为：

1. **`ix` 的计算:** `x` 大约是 9.42，对应的浮点数表示的 `ix` 值会落入处理中等或较大 `|x|` 的范围。

2. **进入 `medium` 情况或更大:** 由于 `x` 较大，会进入 `ix<0x413921fb` 的 `medium` 分支，或者更大的数值会直接调用 `__kernel_rem_pio2`。

3. **`medium` 分支处理 (假设):**
   * `fn = rnint((double_t)x*invpio2)`: `x * invpio2` 大约是 `9.42 * (2/3.14) = 6`，所以 `fn` 大概是 6。
   * `n = irint(fn)`: `n` 将是 6。
   * `r = x - fn * pio2_1`:  `r` 将是 `3*pi - 6 * (pi/2)`，理想情况下是 0。但由于浮点精度问题，`r` 会是一个很小的数。
   * 后续的 `w` 的计算和 `y[0]` 的更新会使用 `pio2_1t` 等进行高精度修正。

4. **`__kernel_rem_pio2` 处理 (如果 `x` 非常大):** 如果 `x` 非常大，`__ieee754_rem_pio2` 会将 `x` 分解成 `tx` 数组，然后调用 `__kernel_rem_pio2(tx, ty, e0, nx, 1)`。`__kernel_rem_pio2` 会计算出高精度的余数并存储在 `ty` 中。

**预期输出 (近似):**

* 返回值 `n`:  接近于 `x / (pi/2)` 的最接近整数。对于 `x = 3 * M_PI`，`n` 应该是 6。
* `y[0] + y[1]`: 应该非常接近于 `x - n * pi/2 = 3 * pi - 6 * (pi / 2) = 0`。由于浮点精度，`y[0]` 会是一个非常小的数，`y[1]` 会更小，表示低精度部分。

**用户或编程常见的使用错误：**

1. **直接调用 `__ieee754_rem_pio2`:**  这个函数是 `libm` 的内部实现，通常不应该被用户代码直接调用。用户应该使用标准的 `math.h` 中提供的函数，如 `fmod()` 或三角函数。直接调用内部函数可能会导致 ABI 兼容性问题，因为这些内部函数的实现可能会在不同的 Android 版本中发生变化。

2. **误解余数的含义:**  `__ieee754_rem_pio2` 计算的是相对于 `pi/2` 的余数，而不是相对于任意数的余数。如果不理解这一点，可能会在需要计算其他模的余数时错误地使用它。

3. **精度假设错误:**  虽然 `__ieee754_rem_pio2` 旨在提供高精度，但浮点运算仍然存在精度限制。在极端情况下，或者当输入 `x` 非常大时，即使是高精度计算也可能存在微小的误差。

**Android Framework 或 NDK 如何一步步到达这里 (调试线索)：**

1. **应用层 (Java/Kotlin):**
   * 开发者在 Android 应用中使用 `android.util.MathUtils` 类或直接进行浮点数运算。
   * 例如，使用 `Math.sin()` 或 `Math.cos()`。

2. **Framework 层 (Java/Kotlin):**
   * `java.lang.Math.sin()` 等方法是 `native` 方法，其实现位于 Android 运行时的本地代码中 (例如，`libjavacrypto.so`, `libandroid_runtime.so`)。
   * 这些本地方法会调用到 `libm.so` 中对应的 C 函数。

3. **NDK 层 (C/C++):**
   * 使用 NDK 开发的 Native 代码可以直接调用 `math.h` 中声明的数学函数，如 `sin()`、`cos()`。
   * 这些函数的实现位于 `bionic/libm/` 目录下。

4. **`libm.so` 内部:**
   * 当调用 `sin(x)` 或 `cos(x)` 时，`libm` 中的 `sin` 和 `cos` 函数的实现通常会首先使用 `__ieee754_rem_pio2(x, y)` 将输入角度 `x` 归约到 `[-pi/4, pi/4]` 区间。
   * 归约后的角度用于计算三角函数的近似值，可以提高计算效率和精度。

**调试线索：**

* **使用 `adb logcat`:** 可以查看系统日志，但不太可能直接看到 `__ieee754_rem_pio2` 的调用，因为它是内部函数。
* **使用 Android Studio Debugger:**
   * 对于 Java/Kotlin 代码，可以设置断点在 `Math.sin()` 等方法上，然后逐步跟踪到 native 方法的调用。
   * 对于 NDK 代码，可以使用 C/C++ 调试器 (如 LLDB) 设置断点在 `sin()` 等函数上，然后单步执行，查看是否调用了 `__ieee754_rem_pio2`。
* **使用 `strace` (需要 root 权限):** 可以跟踪系统调用，但 `__ieee754_rem_pio2` 是库函数调用，不会直接产生系统调用。
* **反汇编 `libm.so`:** 可以使用工具 (如 `objdump`, `readelf`) 反汇编 `libm.so`，查看 `sin` 和 `cos` 函数的实现，确认是否调用了 `__ieee754_rem_pio2`。
* **静态分析工具:** 可以使用静态分析工具分析代码调用关系。

总结来说，`e_rem_pio2.c` 中的 `__ieee754_rem_pio2` 函数是 Android 底层数学库中一个重要的组成部分，负责高精度地计算一个数除以 `pi/2` 的余数，这对于实现精确的三角函数等数学运算至关重要。理解它的功能和实现方式有助于深入了解 Android 平台的底层机制。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_rem_pio2.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
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
 *
 * Optimized by Bruce D. Evans.
 */

/* __ieee754_rem_pio2(x,y)
 * 
 * return the remainder of x rem pi/2 in y[0]+y[1] 
 * use __kernel_rem_pio2()
 */

#include <float.h>

#include "math.h"
#include "math_private.h"

/*
 * invpio2:  53 bits of 2/pi
 * pio2_1:   first  33 bit of pi/2
 * pio2_1t:  pi/2 - pio2_1
 * pio2_2:   second 33 bit of pi/2
 * pio2_2t:  pi/2 - (pio2_1+pio2_2)
 * pio2_3:   third  33 bit of pi/2
 * pio2_3t:  pi/2 - (pio2_1+pio2_2+pio2_3)
 */

static const double
zero =  0.00000000000000000000e+00, /* 0x00000000, 0x00000000 */
two24 =  1.67772160000000000000e+07, /* 0x41700000, 0x00000000 */
invpio2 =  6.36619772367581382433e-01, /* 0x3FE45F30, 0x6DC9C883 */
pio2_1  =  1.57079632673412561417e+00, /* 0x3FF921FB, 0x54400000 */
pio2_1t =  6.07710050650619224932e-11, /* 0x3DD0B461, 0x1A626331 */
pio2_2  =  6.07710050630396597660e-11, /* 0x3DD0B461, 0x1A600000 */
pio2_2t =  2.02226624879595063154e-21, /* 0x3BA3198A, 0x2E037073 */
pio2_3  =  2.02226624871116645580e-21, /* 0x3BA3198A, 0x2E000000 */
pio2_3t =  8.47842766036889956997e-32; /* 0x397B839A, 0x252049C1 */

#ifdef INLINE_REM_PIO2
static __always_inline
#endif
int
__ieee754_rem_pio2(double x, double *y)
{
	double z,w,t,r,fn;
	double tx[3],ty[2];
	int32_t e0,i,j,nx,n,ix,hx;
	u_int32_t low;

	GET_HIGH_WORD(hx,x);		/* high word of x */
	ix = hx&0x7fffffff;
#if 0 /* Must be handled in caller. */
	if(ix<=0x3fe921fb)   /* |x| ~<= pi/4 , no need for reduction */
	    {y[0] = x; y[1] = 0; return 0;}
#endif
	if (ix <= 0x400f6a7a) {		/* |x| ~<= 5pi/4 */
	    if ((ix & 0xfffff) == 0x921fb)  /* |x| ~= pi/2 or 2pi/2 */
		goto medium;		/* cancellation -- use medium case */
	    if (ix <= 0x4002d97c) {	/* |x| ~<= 3pi/4 */
		if (hx > 0) {
		    z = x - pio2_1;	/* one round good to 85 bits */
		    y[0] = z - pio2_1t;
		    y[1] = (z-y[0])-pio2_1t;
		    return 1;
		} else {
		    z = x + pio2_1;
		    y[0] = z + pio2_1t;
		    y[1] = (z-y[0])+pio2_1t;
		    return -1;
		}
	    } else {
		if (hx > 0) {
		    z = x - 2*pio2_1;
		    y[0] = z - 2*pio2_1t;
		    y[1] = (z-y[0])-2*pio2_1t;
		    return 2;
		} else {
		    z = x + 2*pio2_1;
		    y[0] = z + 2*pio2_1t;
		    y[1] = (z-y[0])+2*pio2_1t;
		    return -2;
		}
	    }
	}
	if (ix <= 0x401c463b) {		/* |x| ~<= 9pi/4 */
	    if (ix <= 0x4015fdbc) {	/* |x| ~<= 7pi/4 */
		if (ix == 0x4012d97c)	/* |x| ~= 3pi/2 */
		    goto medium;
		if (hx > 0) {
		    z = x - 3*pio2_1;
		    y[0] = z - 3*pio2_1t;
		    y[1] = (z-y[0])-3*pio2_1t;
		    return 3;
		} else {
		    z = x + 3*pio2_1;
		    y[0] = z + 3*pio2_1t;
		    y[1] = (z-y[0])+3*pio2_1t;
		    return -3;
		}
	    } else {
		if (ix == 0x401921fb)	/* |x| ~= 4pi/2 */
		    goto medium;
		if (hx > 0) {
		    z = x - 4*pio2_1;
		    y[0] = z - 4*pio2_1t;
		    y[1] = (z-y[0])-4*pio2_1t;
		    return 4;
		} else {
		    z = x + 4*pio2_1;
		    y[0] = z + 4*pio2_1t;
		    y[1] = (z-y[0])+4*pio2_1t;
		    return -4;
		}
	    }
	}
	if(ix<0x413921fb) {	/* |x| ~< 2^20*(pi/2), medium size */
medium:
	    fn = rnint((double_t)x*invpio2);
	    n  = irint(fn);
	    r  = x-fn*pio2_1;
	    w  = fn*pio2_1t;	/* 1st round good to 85 bit */
	    {
	        u_int32_t high;
	        j  = ix>>20;
	        y[0] = r-w; 
		GET_HIGH_WORD(high,y[0]);
	        i = j-((high>>20)&0x7ff);
	        if(i>16) {  /* 2nd iteration needed, good to 118 */
		    t  = r;
		    w  = fn*pio2_2;	
		    r  = t-w;
		    w  = fn*pio2_2t-((t-r)-w);	
		    y[0] = r-w;
		    GET_HIGH_WORD(high,y[0]);
		    i = j-((high>>20)&0x7ff);
		    if(i>49)  {	/* 3rd iteration need, 151 bits acc */
		    	t  = r;	/* will cover all possible cases */
		    	w  = fn*pio2_3;	
		    	r  = t-w;
		    	w  = fn*pio2_3t-((t-r)-w);	
		    	y[0] = r-w;
		    }
		}
	    }
	    y[1] = (r-y[0])-w;
	    return n;
	}
    /* 
     * all other (large) arguments
     */
	if(ix>=0x7ff00000) {		/* x is inf or NaN */
	    y[0]=y[1]=x-x; return 0;
	}
    /* set z = scalbn(|x|,ilogb(x)-23) */
	GET_LOW_WORD(low,x);
	e0 	= (ix>>20)-1046;	/* e0 = ilogb(z)-23; */
	INSERT_WORDS(z, ix - ((int32_t)((u_int32_t)e0<<20)), low);
	for(i=0;i<2;i++) {
		tx[i] = (double)((int32_t)(z));
		z     = (z-tx[i])*two24;
	}
	tx[2] = z;
	nx = 3;
	while(tx[nx-1]==zero) nx--;	/* skip zero term */
	n  =  __kernel_rem_pio2(tx,ty,e0,nx,1);
	if(hx<0) {y[0] = -ty[0]; y[1] = -ty[1]; return -n;}
	y[0] = ty[0]; y[1] = ty[1]; return n;
}

"""

```
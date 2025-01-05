Response:
Let's break down the thought process for analyzing the `k_tan.c` code. The goal is to understand its function, its relationship to Android, how it's implemented, and potential issues.

**1. Initial Understanding and Context:**

* **Identify the Core Function:** The filename `k_tan.c` and the function name `__kernel_tan` immediately suggest this is a core function for calculating the tangent. The "kernel" prefix often indicates a low-level, highly optimized function.
* **Locate the File:**  Knowing the file path `bionic/libm/upstream-freebsd/lib/msun/src/k_tan.c` is crucial. This tells us:
    * **`bionic`:** This is the Android C library, meaning this code is part of the fundamental system.
    * **`libm`:**  Specifically, it's part of the math library.
    * **`upstream-freebsd`:**  A key piece of information! Android's `libm` is derived from FreeBSD's math library. This means we can often find corresponding documentation and explanations in FreeBSD's documentation.
    * **`msun/src`:** This confirms it's source code for math functions.
* **Examine the Header Comments:** The initial copyright and permission notice is standard. The function-level comment is incredibly helpful:
    * It describes the function's purpose: kernel tangent on a small interval.
    * It defines the input parameters (`x`, `y`, `k`).
    * It outlines the algorithm's key steps. This is a roadmap for understanding the code.

**2. Deconstructing the Code - Top-Down Approach:**

* **Function Signature:** `double __kernel_tan(double x, double y, int iy)`
    * `double x`, `double y`:  Suggests high-precision input. The comment clarifies `y` is the "tail" of `x`, likely for handling floating-point precision.
    * `int iy`:  The comment mentions `k` and its values (1 for `tan`, -1 for `-1/tan`). The parameter name `iy` is a bit cryptic but the comment explains its role.
* **Constants:** The `xxx` array and the `#define` statements are crucial. The comments next to the numbers (e.g., `3FD55555, 55555563`) are hexadecimal representations of floating-point numbers. These are likely pre-calculated coefficients for the polynomial approximation. The names `one`, `pio4`, `pio4lo` are also suggestive.
* **Initial Checks:** The code starts with getting the high word of `x` and checking its magnitude. This is a common optimization to handle different input ranges efficiently. The check `ix >= 0x3FE59428` corresponds to the boundary mentioned in the comments (~0.6744).
* **Branching Logic:**  The `if (ix >= 0x3FE59428)` block implements the formula for `tan(pi/4 - y)`. This directly corresponds to step 4 of the algorithm described in the comments.
* **Polynomial Approximation:** The code within the `else` block (when `|x|` is smaller) implements the polynomial approximation described in step 3 of the algorithm. The nested structure of the `r` and `v` calculations is a way to efficiently evaluate the polynomial using Horner's method (although slightly modified).
* **Handling `iy`:** The final `if (iy == 1)` and `else` blocks handle the two cases for the `iy` parameter, calculating either `tan(x)` or `-1/tan(x)`. The more complex calculation for `-1/tan(x)` highlights the need for accuracy.

**3. Connecting to Android and `libc`:**

* **`libm` Role:**  Recognize that this function is a building block for the standard `tan()` function. The standard `tan()` likely performs argument reduction (bringing the input into the `[-pi/4, pi/4]` range) and then calls `__kernel_tan`.
* **NDK and Framework:**  Think about how a developer might use `tan()`. It's part of the standard C library, accessible via the NDK. The Android Framework itself uses math functions extensively for graphics, animations, physics simulations, etc.
* **Debugging:** Consider how a developer would debug issues related to `tan()`. They'd likely start with standard debugging tools, but if the issue is precision or edge cases, understanding the implementation of `__kernel_tan` becomes important.

**4. Dynamic Linker (Conceptual at First):**

* **Shared Libraries:** Realize that `libm.so` is a shared library.
* **Symbol Resolution:**  Think about how symbols like `__kernel_tan` are resolved at runtime. The dynamic linker is responsible for this.
* **SO Layout (General):**  Recall the basic structure of a shared library (code, data, symbol tables, etc.).

**5. Detailed Explanations and Examples:**

* **Function Implementation:**  Go through each section of the code, explaining the purpose of the calculations, referencing the algorithm described in the comments. Explain the tricks used for precision (like handling the "tail" of `x`).
* **`libc` Functions:** Focus on how `__kernel_tan` fits into the larger `tan()` function. Explain argument reduction and how it leads to calling the kernel function.
* **Dynamic Linker (More Specific):**
    * **SO Layout:** Sketch out a basic memory layout of `libm.so`.
    * **Symbol Resolution:** Explain the process of finding and binding symbols (global offset table, procedure linkage table). Differentiate between regular function calls and calls to symbols in other shared libraries.
* **Assumptions and Examples:** Create concrete examples to illustrate how the function works for different inputs (small values, values near pi/4). Show potential edge cases and how the code handles them (or might fail to handle them).
* **Common Errors:**  Think about typical mistakes developers make when using `tan()` or other math functions (e.g., assuming perfect precision, not handling edge cases).
* **Debugging Path:**  Outline the steps involved in tracing a call from an Android app or framework down to `__kernel_tan`.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe the polynomial coefficients are arbitrary. **Correction:** Realize they are carefully chosen to minimize approximation error within the specified range.
* **Initial thought:** The `y` parameter is just for error handling. **Correction:** Understand that it's a key part of high-precision floating-point arithmetic.
* **Initial thought:** Dynamic linking is just "it finds the function." **Correction:** Elaborate on the actual mechanisms (GOT, PLT).

By following this structured approach, combining code analysis with the contextual information (Android, `libm`, FreeBSD), and then refining the understanding with examples and potential issues, we can arrive at a comprehensive explanation of the `k_tan.c` file.
好的，让我们深入了解一下 `bionic/libm/upstream-freebsd/lib/msun/src/k_tan.c` 这个文件。

**功能列举:**

`k_tan.c` 文件实现了在一定限制条件下的正切函数 (`tan`) 或余切函数的倒数 (`-1/tan`) 的核心计算逻辑。它并不是完整的 `tan()` 函数实现，而是一个针对特定输入范围优化的“内核”函数。

具体来说，它的功能可以概括为：

1. **针对小角度的精确 `tan(x)` 计算:**  当输入的角度 `x` 绝对值小于等于 pi/4 时，它使用一个高阶奇次多项式来逼近 `tan(x)` 的值。
2. **针对接近 pi/4 的角度的 `tan(x)` 计算:** 当输入的角度 `x` 接近 pi/4 时，它通过公式 `tan(x) = tan(pi/4 - y) = (1 - tan(y))/(1 + tan(y))` 来计算，其中 `y = pi/4 - x`。这样可以将计算转换为对一个较小角度 `y` 的正切运算。
3. **计算 `-1/tan(x)`:**  根据输入的 `iy` 参数，可以选择计算 `-1/tan(x)`。这通常在某些需要余切函数或者处理极点附近的值时使用。

**与 Android 功能的关系及举例说明:**

`k_tan.c` 是 Android 系统底层数学库 `libm` 的一部分，因此与 Android 的各种功能都有着密切的关系。 任何在 Android 上进行数值计算、图形渲染、物理模拟、信号处理等操作，最终都有可能间接地依赖到这个函数。

* **Android Framework:**
    * **图形系统 (SurfaceFlinger, libgui):**  在进行 2D/3D 图形变换、动画效果计算时，经常需要用到三角函数，例如旋转、投影等。`tan()` 函数是基础三角函数之一，`k_tan.c` 为其提供了核心计算能力。
    * **传感器框架 (Sensor Framework):**  处理传感器数据，例如陀螺仪、加速度计的读数，可能涉及到角度计算，从而间接使用到 `tan()`。
    * **动画框架 (Animation Framework):**  各种动画效果的实现可能需要用到三角函数来控制运动轨迹或属性变化。

* **Android NDK:**
    * **游戏开发:** 使用 C/C++ 进行游戏开发时，进行物理引擎计算、角色动画、相机控制等，会频繁使用到 `tan()`。
    * **科学计算应用:**  通过 NDK 开发的科学计算应用，如数据分析、信号处理、图像处理等，也会直接调用 `tan()` 函数。
    * **音视频处理:**  在音频编解码、特效处理中，可能需要用到三角函数。

**举例说明:**

假设一个简单的 Android 应用程序，需要绘制一个可以旋转的矩形。

1. **Java 代码 (Android Framework):**
   ```java
   public class MyView extends View {
       private float rotationAngle = 0f;

       @Override
       protected void onDraw(Canvas canvas) {
           super.onDraw(canvas);
           canvas.rotate(rotationAngle, getWidth() / 2f, getHeight() / 2f);
           canvas.drawRect(100, 100, 300, 200, new Paint());
       }

       public void setRotationAngle(float angle) {
           this.rotationAngle = angle;
           invalidate();
       }
   }
   ```

2. **底层实现 (可能涉及):**
   * `canvas.rotate()` 方法最终会调用底层的图形库（例如 Skia）。
   * Skia 内部在进行旋转变换时，会涉及到矩阵运算，而矩阵运算中会使用到三角函数 `sin()` 和 `cos()`。
   * 虽然这个例子没有直接用到 `tan()`, 但 `tan(x)` 可以由 `sin(x) / cos(x)` 计算得到，并且在某些角度计算或变换中可能会被间接使用。  如果 Skia 内部有对特定角度的正切运算优化，那么 `k_tan.c` 就可能参与其中。

**libc 函数功能实现详解:**

`k_tan.c` 中实现的 `__kernel_tan` 函数并不是一个标准的 libc 函数。它是一个内部的、辅助的函数，用于优化 `tan()` 的计算。 真正的 `tan()` 函数（通常在 `tan.c` 或其他相关文件中）会负责以下步骤：

1. **参数处理和范围归约 (Argument Reduction):**
   * 处理特殊值，例如 NaN、无穷大。
   * 将输入的任意角度 `x` 归约到 `[-pi/4, pi/4]` 的范围内。这是通过利用三角函数的周期性（`tan(x + n*pi) = tan(x)`）和对称性 (`tan(-x) = -tan(x)`) 来实现的。
   * 归约过程中需要精确计算 `x` 除以 `pi` 的商和余数。

2. **调用内核函数:**
   * 将归约后的角度（以及可能的尾数部分 `y`，用于高精度计算）以及指示需要计算 `tan` 还是 `-1/tan` 的标志传递给 `__kernel_tan` 函数。

3. **结果处理:**
   * 根据 `__kernel_tan` 的返回值，可能需要进行符号调整或者其他后处理，以得到最终的 `tan(x)` 值。

**`__kernel_tan` 的实现细节:**

* **小角度逼近:** 对于 `|x| < 0.6744` 的情况，使用奇次多项式逼近：
   ```
   tan(x) ≈ x + T1*x^3 + T2*x^5 + ... + T13*x^27
   ```
   代码中通过 Horner 算法的变体来高效地计算这个多项式。 这样做是为了在小角度范围内获得较高的精度。
* **接近 pi/4 的处理:** 对于 `0.6744 <= |x| <= pi/4` 的情况，使用公式 `tan(x) = tan(pi/4 - y)`。 这里的 `pio4` 和 `pio4lo` 常量分别代表 `pi/4` 的高位和低位部分，用于进行高精度的减法运算。
* **计算 `-1/tan(x)`:** 当 `iy` 不为 1 时，代码会计算 `-1/(x+r)`。为了保证精度，它使用了额外的步骤来精确计算倒数。

**Dynamic Linker 功能 (针对 `libm.so`):**

当程序调用 `tan()` 函数时，如果 `tan()` 的实现位于一个共享库（如 `libm.so`）中，那么动态链接器会负责在运行时加载该共享库，并将程序的调用重定向到库中的正确函数地址。

**SO 布局样本 (简化的 `libm.so`):**

```
libm.so:
    .text:  // 机器指令代码段
        _start:         // 库的入口点 (通常为空或进行初始化)
        tan:            // tan 函数的入口地址
            ...          // tan 函数的指令
        __kernel_tan:   // __kernel_tan 函数的入口地址
            ...          // __kernel_tan 函数的指令
        sin:            // sin 函数的入口地址
            ...
        cos:            // cos 函数的入口地址
        ...

    .rodata: // 只读数据段 (常量、字符串等)
        _math_constants: // 数学常量 (pi, e 等)
        xxx:            // k_tan.c 中定义的 xxx 数组
        ...

    .data:  // 可读写数据段 (全局变量)
        ...

    .bss:   // 未初始化数据段 (未初始化的全局变量)
        ...

    .symtab: // 符号表
        tan (GLOBAL, FUNCTION, .text, 地址)
        __kernel_tan (LOCAL, FUNCTION, .text, 地址)
        sin (GLOBAL, FUNCTION, .text, 地址)
        cos (GLOBAL, FUNCTION, .text, 地址)
        _start (GLOBAL, FUNCTION, .text, 地址)
        ...

    .strtab: // 字符串表 (符号名称等)
        "tan"
        "__kernel_tan"
        "sin"
        "cos"
        "_start"
        ...

    .rel.dyn: // 动态重定位表 (指示需要动态链接器修改的地址)
        偏移地址:  需要重定位的符号 (例如外部引用的函数)

    .plt:   // Procedure Linkage Table (过程链接表，用于延迟绑定)
        tan@plt:
            jmp *GOT[条目n]
        ...

    .got:   // Global Offset Table (全局偏移表，存储全局变量和外部函数的地址)
        GOT[条目n]:  // 存放 tan 函数的最终地址 (由动态链接器填充)
        ...
```

**每种符号的处理过程:**

1. **全局函数符号 (例如 `tan`):**
   * **编译时:** 编译器生成对 `tan` 函数的调用，但由于 `tan` 在外部共享库中，此时无法确定其确切地址。编译器会在 `.plt` 和 `.got` 中生成相应的条目。
   * **链接时:** 静态链接器会标记 `tan` 为需要动态链接的符号，并在 `.rel.dyn` 中记录重定位信息。
   * **运行时 (动态链接器):**
     * 当程序第一次调用 `tan` 时，会跳转到 `.plt` 中 `tan@plt` 的入口。
     * `tan@plt` 中的指令会跳转到 `.got` 中对应的条目。 最初，`.got` 中的这个条目指向 `plt` 中的下一条指令。
     * 这个跳转会触发动态链接器介入。
     * 动态链接器在符号表中查找 `tan` 函数在 `libm.so` 中的地址。
     * 动态链接器将 `tan` 函数的实际地址写入 `.got` 中对应的条目。
     * 下次再调用 `tan` 时，会直接跳转到 `.got` 中存储的实际地址，从而避免了再次调用动态链接器，这称为 **延迟绑定**。

2. **局部函数符号 (例如 `__kernel_tan`):**
   * 局部符号只在库内部可见。
   * 编译器和链接器会处理这些符号，但它们不会出现在库的全局符号表中，也不会参与动态链接过程。
   * 库内部的函数调用可以直接通过相对地址或绝对地址进行。

3. **全局变量符号:**
   * 处理方式类似于全局函数，使用 `.got` 来存储全局变量的地址。

**逻辑推理 (假设输入与输出):**

* **假设输入:** `x = 0.1`, `y = 0.0` (尾数), `iy = 1` (计算 `tan`)
* **推理:**
    * `|x| < 0.6744`，进入小角度逼近分支。
    * 代码会计算多项式 `0.1 + T[0]*0.1^3 + T[1]*0.1^5 + ...`
    * 输出将是一个接近 `tan(0.1)` 的双精度浮点数。

* **假设输入:** `x = 0.78`, `y = 0.00539816339744827899` (尾数，使得 `x+y` 接近 `pi/4`), `iy = 1`
* **推理:**
    * `|x| >= 0.6744`，进入接近 pi/4 的处理分支。
    * 计算 `z = pio4 - x` 和 `w = pio4lo - y`。
    * 计算 `x = z + w`，实际上是计算 `pi/4 - (x + y)`.
    * 然后对这个较小的 `x` 值使用多项式逼近来计算 `tan(x)`.
    * 最终结果会通过公式 `(1 - tan(x)) / (1 + tan(x))` 得到。

**用户或编程常见的使用错误:**

1. **大角度输入:** 直接使用 `tan()` 函数而不进行角度归约，可能导致精度损失或计算错误。例如，计算 `tan(1000 * pi + 0.1)` 时，应该先将角度归约到 `0.1`。
2. **接近奇数倍 pi/2 的输入:**  `tan(x)` 在 `x = (n + 0.5) * pi` 附近会趋于无穷大。在这些点附近计算 `tan()` 可能会导致溢出或非常大的数值，需要特别处理。
3. **精度假设:** 假设浮点数运算具有无限精度。 浮点数运算存在舍入误差，尤其是在进行多次运算后，误差可能会累积。
4. **不处理 NaN 或无穷大:**  如果输入是 NaN 或无穷大，`tan()` 函数会返回 NaN。  程序需要能正确处理这些特殊情况。
5. **过度依赖默认精度:**  在某些需要极高精度的场景下，标准 `double` 类型的精度可能不够，需要考虑使用更高精度的库或算法。

**Android Framework 或 NDK 如何到达这里 (调试线索):**

1. **应用程序代码 (Java/Kotlin):**
   ```java
   double angle = Math.toRadians(45); // 例如，将角度转换为弧度
   double tangentValue = Math.tan(angle);
   ```

2. **Android Framework (java.lang.Math):**
   `java.lang.Math.tan()` 是一个 native 方法。

3. **NDK (libm.so):**
   `java.lang.Math.tan()` 的 native 实现会调用到 Android 系统库 `libm.so` 中的 `tan` 函数。 这通常通过 JNI (Java Native Interface) 完成。

4. **`libm.so` 中的 `tan` 函数 (`bionic/libm/src/tan.c` 或类似文件):**
   * `tan` 函数会进行参数处理和范围归约。
   * 对于归约后的角度，它会调用 `__kernel_tan` 函数来执行核心计算。

5. **`k_tan.c` 中的 `__kernel_tan` 函数:**
   * 根据输入的角度大小，选择使用多项式逼近或接近 pi/4 的计算方法。

**调试线索:**

* **崩溃或异常:** 如果在调用 `Math.tan()` 时发生崩溃，可以使用 Android Studio 的调试器连接到正在运行的应用程序，查看调用堆栈，可以追踪到 `libm.so` 中的函数。
* **日志输出:** 在 NDK 代码中，可以使用 `__android_log_print` 输出中间变量的值，例如传递给 `__kernel_tan` 的参数，以及 `__kernel_tan` 的返回值。
* **使用符号表:**  可以使用 `adb shell` 和 `dumpsys` 命令查看进程的内存映射和加载的共享库。可以使用 `readelf` 或 `objdump` 命令查看 `libm.so` 的符号表，了解函数的地址。
* **反汇编:** 可以使用反汇编工具（如 IDA Pro, Ghidra）反汇编 `libm.so`，查看 `tan` 和 `__kernel_tan` 函数的汇编代码，理解其执行流程。

总而言之，`k_tan.c` 虽然只是 `tan()` 函数的一个组成部分，但它对于理解 Android 底层数学运算的实现至关重要。理解其功能和实现细节，可以帮助开发者更好地理解数值计算的精度问题，并在需要时进行更精细的优化或调试。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/k_tan.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright 2004 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/* __kernel_tan( x, y, k )
 * kernel tan function on ~[-pi/4, pi/4] (except on -0), pi/4 ~ 0.7854
 * Input x is assumed to be bounded by ~pi/4 in magnitude.
 * Input y is the tail of x.
 * Input k indicates whether tan (if k = 1) or -1/tan (if k = -1) is returned.
 *
 * Algorithm
 *	1. Since tan(-x) = -tan(x), we need only to consider positive x.
 *	2. Callers must return tan(-0) = -0 without calling here since our
 *	   odd polynomial is not evaluated in a way that preserves -0.
 *	   Callers may do the optimization tan(x) ~ x for tiny x.
 *	3. tan(x) is approximated by a odd polynomial of degree 27 on
 *	   [0,0.67434]
 *		  	         3             27
 *	   	tan(x) ~ x + T1*x + ... + T13*x
 *	   where
 *
 * 	        |tan(x)         2     4            26   |     -59.2
 * 	        |----- - (1+T1*x +T2*x +.... +T13*x    )| <= 2
 * 	        |  x 					|
 *
 *	   Note: tan(x+y) = tan(x) + tan'(x)*y
 *		          ~ tan(x) + (1+x*x)*y
 *	   Therefore, for better accuracy in computing tan(x+y), let
 *		     3      2      2       2       2
 *		r = x *(T2+x *(T3+x *(...+x *(T12+x *T13))))
 *	   then
 *		 		    3    2
 *		tan(x+y) = x + (T1*x + (x *(r+y)+y))
 *
 *      4. For x in [0.67434,pi/4],  let y = pi/4 - x, then
 *		tan(x) = tan(pi/4-y) = (1-tan(y))/(1+tan(y))
 *		       = 1 - 2*(tan(y) - (tan(y)^2)/(1+tan(y)))
 */

#include "math.h"
#include "math_private.h"
static const double xxx[] = {
		 3.33333333333334091986e-01,	/* 3FD55555, 55555563 */
		 1.33333333333201242699e-01,	/* 3FC11111, 1110FE7A */
		 5.39682539762260521377e-02,	/* 3FABA1BA, 1BB341FE */
		 2.18694882948595424599e-02,	/* 3F9664F4, 8406D637 */
		 8.86323982359930005737e-03,	/* 3F8226E3, E96E8493 */
		 3.59207910759131235356e-03,	/* 3F6D6D22, C9560328 */
		 1.45620945432529025516e-03,	/* 3F57DBC8, FEE08315 */
		 5.88041240820264096874e-04,	/* 3F4344D8, F2F26501 */
		 2.46463134818469906812e-04,	/* 3F3026F7, 1A8D1068 */
		 7.81794442939557092300e-05,	/* 3F147E88, A03792A6 */
		 7.14072491382608190305e-05,	/* 3F12B80F, 32F0A7E9 */
		-1.85586374855275456654e-05,	/* BEF375CB, DB605373 */
		 2.59073051863633712884e-05,	/* 3EFB2A70, 74BF7AD4 */
/* one */	 1.00000000000000000000e+00,	/* 3FF00000, 00000000 */
/* pio4 */	 7.85398163397448278999e-01,	/* 3FE921FB, 54442D18 */
/* pio4lo */	 3.06161699786838301793e-17	/* 3C81A626, 33145C07 */
};
#define	one	xxx[13]
#define	pio4	xxx[14]
#define	pio4lo	xxx[15]
#define	T	xxx
/* INDENT ON */

double
__kernel_tan(double x, double y, int iy) {
	double z, r, v, w, s;
	int32_t ix, hx;

	GET_HIGH_WORD(hx,x);
	ix = hx & 0x7fffffff;			/* high word of |x| */
	if (ix >= 0x3FE59428) {	/* |x| >= 0.6744 */
		if (hx < 0) {
			x = -x;
			y = -y;
		}
		z = pio4 - x;
		w = pio4lo - y;
		x = z + w;
		y = 0.0;
	}
	z = x * x;
	w = z * z;
	/*
	 * Break x^5*(T[1]+x^2*T[2]+...) into
	 * x^5(T[1]+x^4*T[3]+...+x^20*T[11]) +
	 * x^5(x^2*(T[2]+x^4*T[4]+...+x^22*[T12]))
	 */
	r = T[1] + w * (T[3] + w * (T[5] + w * (T[7] + w * (T[9] +
		w * T[11]))));
	v = z * (T[2] + w * (T[4] + w * (T[6] + w * (T[8] + w * (T[10] +
		w * T[12])))));
	s = z * x;
	r = y + z * (s * (r + v) + y);
	r += T[0] * s;
	w = x + r;
	if (ix >= 0x3FE59428) {
		v = (double) iy;
		return (double) (1 - ((hx >> 30) & 2)) *
			(v - 2.0 * (x - (w * w / (w + v) - r)));
	}
	if (iy == 1)
		return w;
	else {
		/*
		 * if allow error up to 2 ulp, simply return
		 * -1.0 / (x+r) here
		 */
		/* compute -1.0 / (x+r) accurately */
		double a, t;
		z = w;
		SET_LOW_WORD(z,0);
		v = r - (z - x);	/* z+v = r+x */
		t = a = -1.0 / w;	/* a = -1.0/w */
		SET_LOW_WORD(t,0);
		s = 1.0 + t * z;
		return t + a * (s + t * v);
	}
}

"""

```
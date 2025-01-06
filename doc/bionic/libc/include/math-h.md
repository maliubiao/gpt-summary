Response:
Let's break down the thought process for analyzing this `math.handroid` header file.

1. **Understanding the Context:** The first sentence is crucial: "这是目录为bionic/libc/include/math.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker."  This tells us:
    * **Location:** The file lives within the Android Bionic library's `include` directory, specifically for math.
    * **Purpose:**  Bionic is the core C library for Android, encompassing math functions and the dynamic linker. This `math.handroid` file is *part of* the math library.

2. **Initial Scan for Functionality:**  A quick skim reveals a long list of function declarations. These are clearly mathematical functions. Keywords like `acos`, `sin`, `log`, `pow`, `sqrt`, etc., immediately stand out. The presence of `f`, `l` suffixes (e.g., `acosf`, `acosl`) indicates single-precision (float) and extended-precision (long double) versions of the functions, respectively.

3. **Categorizing Functionality:**  To organize the analysis, it's helpful to group the functions:
    * **Trigonometric:** `acos`, `asin`, `atan`, `cos`, `sin`, `tan`, `atan2` and their `f` and `l` variants.
    * **Hyperbolic:** `acosh`, `asinh`, `atanh`, `cosh`, `sinh`, `tanh` and their variants.
    * **Exponential and Logarithmic:** `exp`, `exp2`, `expm1`, `frexp`, `ilogb`, `ldexp`, `log`, `log10`, `log1p`, `log2`, `logb` and their variants.
    * **Manipulation:** `modf`, `scalbn`, `scalbln`, `cbrt`, `fabs`, `hypot`, `pow`, `sqrt`.
    * **Error Functions:** `erf`, `erfc`, `lgamma`, `tgamma`.
    * **Rounding and Integer Conversion:** `ceil`, `floor`, `nearbyint`, `rint`, `lrint`, `llrint`, `round`, `lround`, `llround`, `trunc`.
    * **Remainder and Division:** `fmod`, `remainder`, `remquo`.
    * **Floating-Point Properties:** `copysign`, `nan`, `nextafter`, `nexttoward`, `fdim`, `fmax`, `fmin`, `fma`, `fpclassify`, `isfinite`, `isinf`, `isnan`, `isnormal`, `signbit`.
    * **Comparison Macros:** `isgreater`, `isgreaterequal`, `isless`, `islessequal`, `islessgreater`, `isunordered`.
    * **POSIX Extensions:** `signgam`, `j0`, `j1`, `jn`, `y0`, `y1`, `yn`.
    * **Constants:**  `M_E`, `M_PI`, etc.

4. **Relating to Android:**  The key insight here is that *any* Android application performing mathematical calculations will likely use these functions, either directly or indirectly through higher-level libraries. Examples are easy to come up with:
    * **Game development:** Physics engines rely heavily on trigonometric and vector math (using `sin`, `cos`, `atan2`, `hypot`, etc.).
    * **Graphics and image processing:** Transformations, filters, and rendering involve math functions.
    * **Scientific and engineering apps:**  These are direct users of the full range of math functions.
    * **Location-based services:** Calculating distances and angles uses trigonometric functions.

5. **Explaining Libc Function Implementation (Conceptual):** The request asks *how* these functions are implemented. While the header file doesn't contain the implementation, I know that:
    * **Low-level assembly or highly optimized C:**  For performance reasons, many core math functions are implemented at a very low level.
    * **Platform-specific optimizations:** Implementations can leverage specific CPU instructions (like FPU instructions).
    * **Numerical algorithms:**  Techniques like Taylor series expansions, iterative methods (e.g., Newton-Raphson for square roots), and lookup tables are common.
    * **Handling special cases:**  Dealing with NaN, infinity, and denormalized numbers is crucial.

6. **Dynamic Linker and SO Layout (Conceptual):**  The file belongs to `libc.so`. Therefore:
    * **SO Layout:**  `libc.so` will contain:
        * `.text` section: The compiled code for these math functions.
        * `.data` and `.rodata` sections:  Possibly constants or lookup tables used by the functions.
        * Symbol table:  Mapping function names (like `acos`) to their addresses within the `.text` section.
    * **Linking Process:** When an app uses `acos`, the dynamic linker (`/system/bin/linker64` or similar) resolves the symbol `acos` to its address in `libc.so` at runtime. This involves looking up the symbol in `libc.so`'s symbol table. The PLT/GOT mechanism is involved for lazy binding.

7. **Logical Reasoning (Example):**  Consider `hypot(x, y)`.
    * **Input:** Two floating-point numbers, `x` and `y`.
    * **Output:** `sqrt(x*x + y*y)`.
    * **Potential Issue:**  Directly calculating `x*x` and `y*y` can lead to overflow if `x` or `y` are large, even if the final result is within representable bounds.
    * **Improved Implementation (Likely):** The actual implementation will likely scale the inputs to avoid overflow, compute the sum of squares, and then scale back. This demonstrates the kind of logical reasoning involved in numerical stability.

8. **Common Usage Errors:**  Think about how programmers might misuse these functions:
    * **Domain errors:**  Passing negative values to `sqrt` or values outside the [-1, 1] range to `acos`/`asin`.
    * **Overflow/Underflow:**  Calculations resulting in values too large or too small to represent.
    * **Precision issues:**  Comparing floating-point numbers for exact equality.
    * **Incorrect function choice:**  Using `log10` when `log` (natural logarithm) is intended.

9. **Android Framework/NDK Path:**  Trace how a call might reach these functions:
    * **Java Framework:**  `android.location.Location.distanceTo()` internally uses math functions for distance calculations. This Java code calls native methods.
    * **NDK:**  Native C/C++ code directly calls these functions.
    * **System Libraries:**  Other Android system components might use them.
    * **Example:** A Java app calls `Location.distanceTo()`. This calls a native method in a framework library (e.g., `framework.jar`). This native method then calls `libc.so` functions like `sqrt` and trigonometric functions.

10. **Frida Hooking:**  Demonstrate how to intercept calls:
    * Hook `acos` within `libc.so`.
    * Log the arguments and the return value.
    * Show a basic Frida script.

11. **Review and Refine:** Finally, reread the entire analysis to ensure clarity, accuracy, and completeness. Organize the information logically under the specified headings. Make sure to use clear and concise language. Address all parts of the original prompt.
好的，让我们详细分析一下 `bionic/libc/include/math.handroid` 这个头文件。

**功能列举**

这个头文件定义了 Android Bionic C 库中的数学函数接口。它声明了各种常用的数学函数，涵盖了以下几个主要方面：

1. **基本算术运算:**
   - 绝对值: `fabs`, `fabsf`, `fabsl`
   - 次方和平方根: `pow`, `powf`, `powl`, `sqrt`, `sqrtf`, `sqrtl`, `cbrt`, `cbrtf`, `cbrtl`
   - 浮点数操作: `fmod`, `fmodf`, `fmodl`, `remainder`, `remainderf`, `remainderl`, `remquo`, `remquof`, `remquol`, `copysign`, `copysignf`, `copysignl`, `nan`, `nanf`, `nanl`, `nextafter`, `nextafterf`, `nextafterl`, `nexttoward`, `nexttowardf`, `nexttowardl`, `fdim`, `fdimf`, `fdiml`, `fmax`, `fmaxf`, `fmaxl`, `fmin`, `fminf`, `fminl`, `fma`, `fmaf`, `fmal`

2. **指数和对数函数:**
   - 指数: `exp`, `expf`, `expl`, `exp2`, `exp2f`, `exp2l`, `expm1`, `expm1f`, `expm1l`
   - 对数: `log`, `logf`, `logl`, `log10`, `log10f`, `log10l`, `log1p`, `log1pf`, `log1pl`, `log2`, `log2f`, `log2l`, `logb`, `logbf`, `logbl`
   - `frexp`, `ldexp`: 用于将浮点数分解为尾数和指数，以及从尾数和指数重建浮点数。
   - `ilogb`: 返回浮点数的指数部分 (整数)。
   - `scalbn`, `scalbln`: 将浮点数乘以 2 的指定次方。

3. **三角函数和反三角函数:**
   - 正弦和余弦: `sin`, `sinf`, `sinl`, `cos`, `cosf`, `cosl`
   - 正切: `tan`, `tanf`, `tanl`
   - 反正弦和反余弦: `asin`, `asinf`, `asinl`, `acos`, `acosf`, `acosl`
   - 反正切: `atan`, `atanf`, `atanl`, `atan2`, `atan2f`, `atan2l`

4. **双曲函数和反双曲函数:**
   - 双曲正弦和余弦: `sinh`, `sinhf`, `sinhl`, `cosh`, `coshf`, `coshl`
   - 双曲正切: `tanh`, `tanhf`, `tanhl`
   - 反双曲正弦和余弦: `asinh`, `asinhf`, `asinhl`, `acosh`, `acoshf`, `acoshl`
   - 反双曲正切: `atanh`, `atanhf`, `atanhl`

5. **取整函数:**
   - `ceil`, `ceilf`, `ceill`: 向上取整
   - `floor`, `floorf`, `floorl`: 向下取整
   - `nearbyint`, `nearbyintf`, `nearbyintl`: 舍入到最接近的整数（根据当前的舍入模式）
   - `rint`, `rintf`, `rintl`: 舍入到最接近的整数
   - `lrint`, `lrintf`, `lrintl`, `llrint`, `llrintf`, `llrintl`: 舍入到最接近的整数并转换为 `long` 或 `long long`
   - `round`, `roundf`, `roundl`: 四舍五入到最接近的整数
   - `lround`, `lroundf`, `lroundl`, `llround`, `llroundf`, `llroundl`: 四舍五入到最接近的整数并转换为 `long` 或 `long long`
   - `trunc`, `truncf`, `truncl`: 截断到整数部分

6. **特殊函数:**
   - 误差函数: `erf`, `erff`, `erfl`, `erfc`, `erfcf`, `erfcl`
   - 伽玛函数: `lgamma`, `lgammaf`, `lgammal`, `tgamma`, `tgammaf`, `tgammal`
   - Bessel 函数 (POSIX 扩展): `j0`, `j1`, `jn`, `y0`, `y1`, `yn`

7. **浮点数分类和比较:**
   - `fpclassify`:  对浮点数进行分类 (NaN, 无穷大, 正常, 次正常, 零)
   - `isfinite`: 检查浮点数是否是有限的 (不是 NaN 或无穷大)
   - `isinf`: 检查浮点数是否是无穷大
   - `isnan`: 检查浮点数是否是 NaN (Not a Number)
   - `isnormal`: 检查浮点数是否是正常的 (不是零, 次正常, 无穷大或 NaN)
   - `signbit`: 检查浮点数的符号位
   - `isgreater`, `isgreaterequal`, `isless`, `islessequal`, `islessgreater`, `isunordered`: 用于浮点数的比较，可以处理 NaN 的情况。

8. **常量定义:**
   - `HUGE_VAL`, `HUGE_VALF`, `HUGE_VALL`: 表示双精度、单精度和长双精度浮点数的最大值。
   - `INFINITY`: 表示无穷大。
   - `NAN`: 表示 NaN。
   - `M_E`, `M_LOG2E`, `M_LOG10E`, `M_LN2`, `M_LN10`, `M_PI`, `M_PI_2`, `M_PI_4`, `M_1_PI`, `M_2_PI`, `M_2_SQRTPI`, `M_SQRT2`, `M_SQRT1_2`:  常用的数学常量，如 e 和 π。

**与 Android 功能的关系及举例**

Android 作为一个操作系统，其各种功能都可能涉及到数学运算。这个头文件中定义的函数是 Android 系统和应用程序进行数值计算的基础。

**举例说明:**

* **图形渲染:**  在 Android 的图形系统中（例如 SurfaceFlinger 或应用层的 Canvas），进行 2D 或 3D 图形的变换（旋转、缩放、平移）、投影、光照计算等，都需要大量的三角函数 (`sin`, `cos`, `tan`)、平方根 (`sqrt`)、幂运算 (`pow`) 等。
* **游戏开发:** 游戏中的物理引擎需要计算物体的位置、速度、碰撞等，会用到向量运算、三角函数、距离计算（`hypot`）。
* **音频处理:**  音频编解码、音频特效处理（例如均衡器、混响）可能涉及到对数运算 (`log`)、指数运算 (`exp`)、三角函数（生成波形）。
* **传感器数据处理:**  处理来自加速度计、陀螺仪、磁力计等传感器的数据时，可能需要进行向量计算、角度转换（`atan2`)。
* **定位服务:**  计算两个地理坐标之间的距离需要使用三角函数和反三角函数。
* **机器学习和人工智能:**  Android 设备上运行的机器学习模型（例如通过 TensorFlow Lite）在进行推理计算时，底层可能使用到这些数学函数。

**详细解释每一个 libc 函数的功能是如何实现的**

这个头文件只包含了函数的声明，实际的函数实现位于 Bionic 库的源代码中（通常是汇编语言或高度优化的 C 代码）。 解释每个函数的具体实现非常复杂，涉及到数值分析和计算机体系结构的知识。以下是一些通用原则和示例：

* **基本算术运算:**  通常直接映射到 CPU 的浮点运算单元 (FPU) 指令，例如加法、减法、乘法、除法等。
* **指数和对数函数:**  常见的实现方法包括：
    * **泰勒级数展开:**  将函数展开成无穷级数，计算有限项的和来逼近函数值。例如，`exp(x)` 可以用泰勒级数逼近。
    * **查找表与插值:**  预先计算一些关键点的函数值并存储在查找表中，对于其他值，通过插值算法估算。
    * **迭代方法:**  使用迭代公式逐步逼近函数值，例如牛顿迭代法可以用于计算平方根。
    * **位操作技巧:**  对于一些特殊情况，例如计算 2 的幂，可以使用位操作来提高效率。
* **三角函数:**
    * **范围缩减:**  利用三角函数的周期性，将输入角度缩减到一个较小的区间（例如 [0, π/4]）。
    * **泰勒级数或切比雪夫多项式逼近:**  在缩减后的范围内，使用多项式来逼近函数值。
    * **CORDIC 算法:**  一种迭代的移位和加法算法，常用于计算三角函数。
* **取整函数:**  通常基于浮点数的位表示进行操作，或者使用 FPU 提供的取整指令。
* **浮点数分类和比较:**  直接检查浮点数的位模式，例如 NaN 和无穷大有特定的位表示。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

这个 `math.handroid` 头文件本身不直接涉及 dynamic linker 的功能。它声明的数学函数最终会被编译到 `libc.so` (或其变体) 这个共享库中。Dynamic linker 的作用是在程序运行时加载和链接这些共享库。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:  // 代码段
        acos:  // acos 函数的代码
            ...
        sin:   // sin 函数的代码
            ...
        // 其他数学函数的代码
        ...
    .rodata: // 只读数据段
        // 数学常量，例如 PI 的近似值
        ...
    .data:   // 可读写数据段 (可能包含一些全局变量)
        ...
    .symtab: // 符号表
        acos: [地址]
        sin:  [地址]
        // 其他符号
        ...
    .dynsym: // 动态符号表 (用于动态链接)
        acos: [地址]
        sin:  [地址]
        // 其他动态符号
        ...
    .plt:    // 程序链接表 (Procedure Linkage Table)
        acos@plt:
            jmp *acos@GOT
        sin@plt:
            jmp *sin@GOT
        ...
    .got:    // 全局偏移表 (Global Offset Table)
        acos@GOT: 0x0  // 初始值为 0，运行时被 dynamic linker 填充
        sin@GOT:  0x0
        ...
```

**链接的处理过程:**

1. **编译时:** 当一个应用程序或库使用 `acos` 函数时，编译器会生成对 `acos` 的调用指令，并记录需要链接 `acos` 这个符号。
2. **链接时 (静态链接):** 如果是静态链接，`acos` 函数的代码会直接被复制到最终的可执行文件中。Bionic 通常使用动态链接。
3. **运行时 (动态链接):**
   - 当程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会被首先执行。
   - Dynamic linker 会加载程序依赖的共享库，包括 `libc.so`。
   - **符号解析:** 当程序执行到第一次调用 `acos` 函数时，由于使用了延迟绑定 (lazy binding)，程序会先跳转到 `.plt` 段中 `acos@plt` 的入口。
   - `acos@plt` 中的指令会跳转到 `acos@GOT` 指向的地址。最初，`acos@GOT` 的值为 0。
   - 这个跳转会触发 dynamic linker 的介入。
   - Dynamic linker 会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `acos` 符号，找到其在 `.text` 段中的实际地址。
   - Dynamic linker 将 `acos` 的实际地址写入 `acos@GOT`。
   - 接下来再次调用 `acos` 时，程序会直接跳转到 `acos@GOT` 中存储的实际地址，从而执行 `acos` 函数的代码。

**假设输入与输出 (逻辑推理示例)**

假设我们分析 `sqrt` 函数：

* **假设输入:** `x = 4.0`
* **预期输出:** `2.0`
* **逻辑推理:** `sqrt` 函数计算一个非负数的平方根。对于输入 4.0，其平方根为 2.0。

* **假设输入:** `x = -1.0`
* **预期输出:**  NaN (因为负数没有实数平方根)
* **逻辑推理:** `sqrt` 函数对于负数输入，根据 IEEE 754 标准，通常会返回 NaN。

* **假设输入:** `x = INFINITY`
* **预期输出:** `INFINITY`
* **逻辑推理:** 无穷大的平方根仍然是无穷大。

**用户或者编程常见的使用错误举例说明**

1. **对负数取平方根:**
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double x = -1.0;
       double result = sqrt(x);
       printf("sqrt(%f) = %f\n", x, result); // 输出 sqrt(-1.000000) = nan
       return 0;
   }
   ```
   **错误:**  `sqrt` 函数的定义域是非负数。应该在调用前检查输入是否为非负数。

2. **`asin` 或 `acos` 的参数超出 [-1, 1] 范围:**
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double x = 2.0;
       double result = asin(x);
       printf("asin(%f) = %f\n", x, result); // 输出 asin(2.000000) = nan
       return 0;
   }
   ```
   **错误:** `asin` 和 `acos` 函数的定义域是 [-1, 1]。

3. **使用浮点数进行精确比较:**
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double a = 0.1 + 0.1 + 0.1;
       double b = 0.3;
       if (a == b) {
           printf("a is equal to b\n");
       } else {
           printf("a is not equal to b\n"); // 通常会输出这个
       }
       return 0;
   }
   ```
   **错误:** 浮点数在计算机中以二进制近似表示，直接比较可能因为精度问题而失败。应该使用一个小的 epsilon 值进行比较。

4. **没有处理数学函数的错误 (`math_errhandling`):** 某些数学函数在出错时会设置 `errno` 或引发浮点异常。没有适当处理这些错误可能导致程序行为不可预测。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤**

**Android Framework 到 `libc.so` 的路径 (以 `Math.sqrt()` 为例):**

1. **Java 代码:** Android Framework 或应用程序的 Java 代码调用 `java.lang.Math.sqrt(double a)`.
2. **Native 方法:** `java.lang.Math.sqrt()` 是一个 native 方法，其实现位于 Android Runtime (ART) 的本地代码中。
3. **JNI 调用:** ART 通过 Java Native Interface (JNI) 调用到 `libjavacore.so` 或 ART 内部的本地方法实现。
4. **Bionic Math 函数:**  在 `libjavacore.so` 或 ART 内部，可能会直接调用 Bionic 库中的 `sqrt` 函数（在 `libc.so` 中）。

**NDK 到 `libc.so` 的路径:**

1. **C/C++ 代码:** 使用 NDK 开发的应用程序可以直接在 C/C++ 代码中包含 `<math.h>` 并调用 `sqrt()`, `sin()`, 等函数。
2. **编译链接:** NDK 的编译器和链接器会将这些函数调用链接到 Bionic 库 `libc.so`。
3. **运行时:**  当 NDK 应用运行时，dynamic linker 会加载 `libc.so`，并将 NDK 代码中对数学函数的调用链接到 `libc.so` 中对应的函数实现。

**Frida Hook 示例 (Hook `sqrt` 函数):**

```javascript
// Frida 脚本

// 获取 libc.so 的基地址
const libc = Process.getModuleByName("libc.so");
const sqrtAddress = libc.getExportByName("sqrt");

if (sqrtAddress) {
  Interceptor.attach(sqrtAddress, {
    onEnter: function(args) {
      const input = args[0].toDouble();
      console.log(`[+] Calling sqrt with input: ${input}`);
      this.input = input; // 保存输入值
    },
    onLeave: function(retval) {
      const output = retval.toDouble();
      console.log(`[+] sqrt(${this.input}) returned: ${output}`);
    }
  });
  console.log("[+] Hooked sqrt function in libc.so");
} else {
  console.log("[-] Could not find sqrt function in libc.so");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook_sqrt.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <your_app_package_name> -l hook_sqrt.js --no-pause
   ```
   或者如果目标应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_sqrt.js
   ```

**调试步骤:**

1. 运行带有 Frida hook 的应用程序。
2. 当应用程序中的任何代码（无论是 Framework 的还是 NDK 的）调用 `sqrt` 函数时，Frida 脚本会拦截该调用。
3. `onEnter` 函数会在调用 `sqrt` 之前执行，打印出输入参数。
4. `onLeave` 函数会在 `sqrt` 函数返回之后执行，打印出返回值。

通过 Frida hook，你可以观察到 `sqrt` 函数何时被调用，以及传入的参数和返回的结果，从而验证 Android Framework 或 NDK 是如何一步步到达 Bionic 的数学函数的。你可以针对其他数学函数编写类似的 Frida 脚本进行调试。

Prompt: 
```
这是目录为bionic/libc/include/math.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * Originally based on fdlibm.h 5.1 via FreeBSD.
 */

#pragma once

#include <sys/cdefs.h>
#include <limits.h>

__BEGIN_DECLS

/* C11. */

typedef double __double_t;
typedef __double_t double_t;
typedef float __float_t;
typedef __float_t float_t;

#define HUGE_VAL __builtin_huge_val()
#define HUGE_VALF __builtin_huge_valf()
#define HUGE_VALL __builtin_huge_vall()

#define INFINITY __builtin_inff()

#define NAN __builtin_nanf("")

#define FP_INFINITE 0x01
#define FP_NAN 0x02
#define FP_NORMAL 0x04
#define FP_SUBNORMAL 0x08
#define FP_ZERO 0x10

#if defined(__FP_FAST_FMA)
#define FP_FAST_FMA 1
#endif
#if defined(__FP_FAST_FMAF)
#define FP_FAST_FMAF 1
#endif
#if defined(__FP_FAST_FMAL)
#define FP_FAST_FMAL 1
#endif

#define FP_ILOGB0 (-INT_MAX)
#define FP_ILOGBNAN INT_MAX

#define MATH_ERRNO 1
#define MATH_ERREXCEPT 2
#define math_errhandling MATH_ERREXCEPT

#define fpclassify(x) __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x)

#define isfinite(x) __builtin_isfinite(x)

#define isinf(x) __builtin_isinf(x)

#define isnan(x) __builtin_isnan(x)

#define isnormal(x) __builtin_isnormal(x)

#define signbit(x) __builtin_signbit(x)

double acos(double __x);
float acosf(float __x);
long double acosl(long double __x);

double asin(double __x);
float asinf(float __x);
long double asinl(long double __x);

double atan(double __x);
float atanf(float __x);
long double atanl(long double __x);

double atan2(double __y, double __x);
float atan2f(float __y, float __x);
long double atan2l(long double __y, long double __x);

double cos(double __x);
float cosf(float __x);
long double cosl(long double __x);

double sin(double __x);
float sinf(float __x);
long double sinl(long double __x);

double tan(double __x);
float tanf(float __x);
long double tanl(long double __x);

double acosh(double __x);
float acoshf(float __x);
long double acoshl(long double __x);

double asinh(double __x);
float asinhf(float __x);
long double asinhl(long double __x);

double atanh(double __x);
float atanhf(float __x);
long double atanhl(long double __x);

double cosh(double __x);
float coshf(float __x);
long double coshl(long double __x);

double sinh(double __x);
float sinhf(float __x);
long double sinhl(long double __x);

double tanh(double __x);
float tanhf(float __x);
long double tanhl(long double __x);

double exp(double __x);
float expf(float __x);
long double expl(long double __x);

double exp2(double __x);
float exp2f(float __x);
long double exp2l(long double __x);

double expm1(double __x);
float expm1f(float __x);
long double expm1l(long double __x);

double frexp(double __x, int* _Nonnull __exponent);
float frexpf(float __x, int* _Nonnull __exponent);
long double frexpl(long double __x, int* _Nonnull __exponent);

int ilogb(double __x) __attribute_const__;
int ilogbf(float __x) __attribute_const__;
int ilogbl(long double __x) __attribute_const__;

double ldexp(double __x, int __exponent);
float ldexpf(float __x, int __exponent);
long double ldexpl(long double __x, int __exponent);

double log(double __x);
float logf(float __x);
long double logl(long double __x);

double log10(double __x);
float log10f(float __x);
long double log10l(long double __x);

double log1p(double __x);
float log1pf(float __x);
long double log1pl(long double __x);

double log2(double __x);
float log2f(float __x);
long double log2l(long double __x);

double logb(double __x);
float logbf(float __x);
long double logbl(long double __x);

double modf(double __x, double* _Nonnull __integral_part);
float modff(float __x, float* _Nonnull __integral_part);
long double modfl(long double __x, long double* _Nonnull __integral_part);

double scalbn(double __x, int __exponent);
float scalbnf(float __x, int __exponent);
long double scalbnl(long double __x, int __exponent);

double scalbln(double __x, long __exponent);
float scalblnf(float __x, long __exponent);
long double scalblnl(long double __x, long __exponent);

double cbrt(double __x);
float cbrtf(float __x);
long double cbrtl(long double __x);

double fabs(double __x) __attribute_const__;
float fabsf(float __x) __attribute_const__;
long double fabsl(long double __x) __attribute_const__;

double hypot(double __x, double __y);
float hypotf(float __x, float __y);
long double hypotl(long double __x, long double __y);

double pow(double __x, double __y);
float powf(float __x, float __y);
long double powl(long double __x, long double __y);

double sqrt(double __x);
float sqrtf(float __x);
long double sqrtl(long double __x);

double erf(double __x);
float erff(float __x);
long double erfl(long double __x);

double erfc(double __x);
float erfcf(float __x);
long double erfcl(long double __x);

double lgamma(double __x);
float lgammaf(float __x);
long double lgammal(long double __x);

double tgamma(double __x);
float tgammaf(float __x);
long double tgammal(long double __x);

double ceil(double __x);
float ceilf(float __x);
long double ceill(long double __x);

double floor(double __x);
float floorf(float __x);
long double floorl(long double __x);

double nearbyint(double __x);
float nearbyintf(float __x);
long double nearbyintl(long double __x);

double rint(double __x);
float rintf(float __x);
long double rintl(long double __x);

long lrint(double __x);
long lrintf(float __x);
long lrintl(long double __x);

long long llrint(double __x);
long long llrintf(float __x);
long long llrintl(long double __x);

double round(double __x);
float roundf(float __x);
long double roundl(long double __x);

long lround(double __x);
long lroundf(float __x);
long lroundl(long double __x);

long long llround(double __x);
long long llroundf(float __x);
long long llroundl(long double __x);

double trunc(double __x);
float truncf(float __x);
long double truncl(long double __x);

double fmod(double __x, double __y);
float fmodf(float __x, float __y);
long double fmodl(long double __x, long double __y);

double remainder(double __x, double __y);
float remainderf(float __x, float __y);
long double remainderl(long double __x, long double __y);

double remquo(double __x, double __y, int* _Nonnull __quotient_bits);
float remquof(float __x, float __y, int* _Nonnull __quotient_bits);
long double remquol(long double __x, long double __y, int* _Nonnull __quotient_bits);

double copysign(double __value, double __sign) __attribute_const__;
float copysignf(float __value, float __sign) __attribute_const__;
long double copysignl(long double __value, long double __sign) __attribute_const__;

double nan(const char* _Nonnull __kind) __attribute_const__;
float nanf(const char* _Nonnull __kind) __attribute_const__;
long double nanl(const char* _Nonnull __kind) __attribute_const__;

double nextafter(double __x, double __y);
float nextafterf(float __x, float __y);
long double nextafterl(long double __x, long double __y);

double nexttoward(double __x, long double __y);
float nexttowardf(float __x, long double __y);
long double nexttowardl(long double __x, long double __y);

double fdim(double __x, double __y);
float fdimf(float __x, float __y);
long double fdiml(long double __x, long double __y);

double fmax(double __x, double __y) __attribute_const__;
float fmaxf(float __x, float __y) __attribute_const__;
long double fmaxl(long double __x, long double __y) __attribute_const__;

double fmin(double __x, double __y) __attribute_const__;
float fminf(float __x, float __y) __attribute_const__;
long double fminl(long double __x, long double __y) __attribute_const__;

double fma(double __x, double __y, double __z);
float fmaf(float __x, float __y, float __z);
long double fmal(long double __x, long double __y, long double __z);

#define isgreater(x, y) __builtin_isgreater((x), (y))
#define isgreaterequal(x, y) __builtin_isgreaterequal((x), (y))
#define isless(x, y) __builtin_isless((x), (y))
#define islessequal(x, y) __builtin_islessequal((x), (y))
#define islessgreater(x, y) __builtin_islessgreater((x), (y))
#define isunordered(x, y) __builtin_isunordered((x), (y))

/* POSIX extensions. */

extern int signgam;

double j0(double __x);
double j1(double __x);
double jn(int __n, double __x);
double y0(double __x);
double y1(double __x);
double yn(int __n, double __x);

#define M_E		2.7182818284590452354	/* e */
#define M_LOG2E		1.4426950408889634074	/* log 2e */
#define M_LOG10E	0.43429448190325182765	/* log 10e */
#define M_LN2		0.69314718055994530942	/* log e2 */
#define M_LN10		2.30258509299404568402	/* log e10 */
#define M_PI		3.14159265358979323846	/* pi */
#define M_PI_2		1.57079632679489661923	/* pi/2 */
#define M_PI_4		0.78539816339744830962	/* pi/4 */
#define M_1_PI		0.31830988618379067154	/* 1/pi */
#define M_2_PI		0.63661977236758134308	/* 2/pi */
#define M_2_SQRTPI	1.12837916709551257390	/* 2/sqrt(pi) */
#define M_SQRT2		1.41421356237309504880	/* sqrt(2) */
#define M_SQRT1_2	0.70710678118654752440	/* 1/sqrt(2) */

#define MAXFLOAT	((float)3.40282346638528860e+38)

/* BSD extensions. */

#if defined(__USE_BSD)
#define HUGE MAXFLOAT
#endif

/* Extensions in both BSD and GNU. */

#if defined(__USE_BSD) || defined(__USE_GNU)
double gamma(double __x);
double scalb(double __x, double __exponent);
double drem(double __x, double __y);
int finite(double __x) __attribute_const__;
int isinff(float __x) __attribute_const__;
int isnanf(float __x) __attribute_const__;
double gamma_r(double __x, int* _Nonnull __sign);
double lgamma_r(double __x, int* _Nonnull __sign);
double significand(double __x);

#if __BIONIC_AVAILABILITY_GUARD(23)
long double lgammal_r(long double __x, int* _Nonnull __sign) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

long double significandl(long double __x);
float dremf(float __x, float __y);
int finitef(float __x) __attribute_const__;
float gammaf(float __x);
float j0f(float __x);
float j1f(float __x);
float jnf(int __n, float __x);
float scalbf(float __x, float __exponent);
float y0f(float __x);
float y1f(float __x);
float ynf(int __n, float __x);
float gammaf_r(float __x, int* _Nonnull __sign);
float lgammaf_r(float __x, int* _Nonnull __sign);
float significandf(float __x);
void sincos(double __x, double* _Nonnull __sin, double* _Nonnull __cos);
void sincosf(float __x, float* _Nonnull __sin, float* _Nonnull __cos);
void sincosl(long double __x, long double* _Nonnull __sin, long double* _Nonnull __cos);
#endif

/* GNU extensions. */

#if defined(__USE_GNU)
#define M_El            2.718281828459045235360287471352662498L /* e */
#define M_LOG2El        1.442695040888963407359924681001892137L /* log 2e */
#define M_LOG10El       0.434294481903251827651128918916605082L /* log 10e */
#define M_LN2l          0.693147180559945309417232121458176568L /* log e2 */
#define M_LN10l         2.302585092994045684017991454684364208L /* log e10 */
#define M_PIl           3.141592653589793238462643383279502884L /* pi */
#define M_PI_2l         1.570796326794896619231321691639751442L /* pi/2 */
#define M_PI_4l         0.785398163397448309615660845819875721L /* pi/4 */
#define M_1_PIl         0.318309886183790671537767526745028724L /* 1/pi */
#define M_2_PIl         0.636619772367581343075535053490057448L /* 2/pi */
#define M_2_SQRTPIl     1.128379167095512573896158903121545172L /* 2/sqrt(pi) */
#define M_SQRT2l        1.414213562373095048801688724209698079L /* sqrt(2) */
#define M_SQRT1_2l      0.707106781186547524400844362104849039L /* 1/sqrt(2) */
int isinfl(long double __x) __attribute_const__;
int isnanl(long double __x) __attribute_const__;
#endif

__END_DECLS

"""

```
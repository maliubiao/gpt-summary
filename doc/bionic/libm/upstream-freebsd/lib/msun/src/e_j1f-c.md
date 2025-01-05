Response:
Let's break down the thought process to analyze this C code for `e_j1f.c`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this specific C file within the context of Android's `bionic` library. This means identifying the mathematical functions it implements, explaining their purpose, and connecting them to how they might be used in Android. Additionally, the prompt asks about the dynamic linker, requiring knowledge of shared libraries and symbol resolution.

**2. Initial Code Scan (High-Level):**

* **Filename:** `e_j1f.c` suggests it's related to Bessel functions, specifically `j1`. The `f` suffix indicates it operates on `float` (single-precision) numbers. The `e_` prefix might indicate it's part of the core math library implementation.
* **Copyright:** The Sun Microsystems copyright and the comment about being a "float version of e_j1.c" confirm the Bessel function connection.
* **Includes:** `math.h` and `math_private.h` are standard for math library implementations.
* **Static Inline Functions:** `ponef` and `qonef` are helper functions declared as `static __inline`, hinting they are internal and optimized for speed.
* **Constants:** Several `static const float` variables are defined. These are likely coefficients for polynomial approximations or specific mathematical values (like `invsqrtpi`). The names (e.g., `r00`, `s01`, `U0`, `V0`) suggest coefficients for different approximation ranges.
* **Function Declarations:** `float j1f(float x)` and `float y1f(float x)` are the main exported functions. `j1f` is clearly the Bessel function of the first kind of order 1. `y1f` is likely the Bessel function of the second kind (or Neumann function) of order 1.
* **Conditional Logic:**  The `j1f` and `y1f` functions have `if` statements checking the magnitude of the input `x`. This strongly suggests different approximation methods are used for different ranges to maintain accuracy and efficiency.
* **`GET_FLOAT_WORD` Macro:**  This macro is used to access the raw bit representation of the float, which is common for handling special cases like NaN or infinity and for bitwise manipulations.
* **`sincosf`:** This standard library function calculates sine and cosine simultaneously, likely for performance.
* **Polynomial Structures:** The definitions of `U0`, `V0`, `pr8`, `ps8`, etc., clearly represent the coefficients of polynomials used in approximations.

**3. Deep Dive into `j1f(float x)`:**

* **Special Cases:** The function first handles NaN and infinity. Then it takes the absolute value of `x`.
* **Large `|x|`:** If `|x| >= 2.0`, it uses trigonometric functions (`sincosf`, `cosf`) and the helper functions `ponef` and `qonef`. The comments mention asymptotic expansions, indicating this is for large arguments.
* **Small `|x|`:** If `|x| < 2**-13`, a simple linear approximation is used.
* **Intermediate `|x|`:**  For the remaining range, a polynomial approximation is used. The coefficients `r00` through `s05` are used in the calculation.
* **Sign Handling:** The sign of the result is adjusted based on the original sign of `x`.

**4. Deep Dive into `y1f(float x)`:**

* **Special Cases:** Handles NaN, infinity, and zero. Also handles negative input by returning NaN (domain error).
* **Large `|x|`:** Similar to `j1f`, it uses trigonometric functions and `ponef`/`qonef` for asymptotic expansion. The comments explain the trigonometric identities used to avoid cancellation errors.
* **Small `|x|`:** For very small `x`, a simple approximation involving `tpi` (likely $\frac{3}{4}\pi$) is used.
* **Intermediate `|x|`:** A more complex polynomial approximation is employed using the `U0` and `V0` coefficients. It also uses `j1f(x)` and `logf(x)`, indicating a relationship between `y1f` and `j1f`.

**5. Analyzing `ponef(float x)` and `qonef(float x)`:**

* **Purpose:** These functions are used for approximating parts of the Bessel function calculations for larger values of `x`.
* **Range-Based Approximations:**  They use different sets of polynomial coefficients (`pr8`, `ps8`, `qr8`, `qs8`, etc.) depending on the magnitude of `x`. This piecewise approximation approach is a common technique in math libraries for balancing accuracy and performance.
* **Rational Function Form:**  The approximations are in the form of a rational function (ratio of two polynomials) plus a constant (for `ponef`). This is a standard way to approximate functions.

**6. Connecting to Android:**

* **NDK Usage:**  Android developers using the NDK can call `j1f` and `y1f` via `<cmath>` or `<math.h>`.
* **Framework Usage:** The Android framework itself, being written in C++ and Java, relies on the C library for low-level math operations. Components dealing with signal processing, physics simulations, or graphics might indirectly use these functions.
* **Example:** An audio processing app using the NDK might use Bessel functions in algorithms for synthesizing or analyzing sounds.

**7. Dynamic Linker (Conceptual):**

* **SO Layout:**  A typical `.so` (shared object) file contains:
    * **Header:** Metadata about the SO (entry point, symbol table offset, etc.).
    * **`.text` Section:**  Executable code (the compiled functions).
    * **`.rodata` Section:** Read-only data (like the constant coefficients).
    * **`.data` Section:** Initialized global and static variables.
    * **`.bss` Section:** Uninitialized global and static variables.
    * **Symbol Table:**  Lists exported (global) symbols and imported symbols (dependencies).
    * **Relocation Table:**  Instructions on how to adjust addresses when the SO is loaded into memory.
* **Symbol Resolution:**
    * **Exported Symbols (e.g., `j1f`, `y1f`):** When another SO or the main executable needs `j1f`, the dynamic linker looks up the address of `j1f` in the symbol table of `libm.so` (or wherever this code is compiled).
    * **Imported Symbols (e.g., `sincosf`, `sqrtf`, `logf`):**  The dynamic linker ensures these symbols are provided by other loaded libraries.
    * **Static Symbols (e.g., `ponef`, `qonef`, constants):** These are internal to the SO and not visible outside. Their addresses are resolved during the linking process.

**8. Assumptions and Hypothetical Inputs/Outputs:**

* **Assumption:** The code aims for accuracy within the precision of `float`.
* **Input `j1f(1.0f)`:**  Should produce a result close to the mathematical value of $J_1(1)$, which is approximately 0.4400505857.
* **Input `y1f(10.0f)`:** Should produce a result close to the mathematical value of $Y_1(10)$, which is approximately 0.05566945.
* **Input `j1f(0.0f)`:** Should return 0.0f.
* **Input `y1f(0.0f)`:** Should return negative infinity (handled as a special case).

**9. Common Usage Errors:**

* **Passing `NaN` or Infinity:** While the code handles these, users might not expect the specific return values.
* **Incorrect Input Range for Approximations (if manually implementing):** If someone were to try and reimplement parts of this, using the wrong approximation for a given input range would lead to inaccurate results.
* **Precision Issues:** Expecting double-precision accuracy from `float` functions.

**10. Debugging Lineage:**

1. **NDK Call:** An Android app using the NDK calls `j1f(x)`.
2. **System Call (Implicit):** The NDK call translates into a call to the system's C library.
3. **Dynamic Linker:** The dynamic linker ensures the correct `libm.so` (or equivalent) is loaded and the `j1f` symbol is resolved.
4. **`j1f` Execution:** The code within `e_j1f.c`'s `j1f` function is executed.
5. **Helper Function Calls:**  `j1f` might call `ponef`, `qonef`, `sincosf`, `sqrtf`, etc., within the same library.

This systematic approach, starting with a high-level overview and then drilling down into specifics, combined with contextual knowledge of Android and math libraries, allows for a comprehensive understanding of the provided C code.
这是一个关于Android Bionic库中 `libm` 库的源代码文件 `e_j1f.c` 的分析。这个文件实现了单精度浮点数版本的 Bessel 函数 `j1` 和 `y1`。

**功能列举:**

1. **`j1f(float x)`:** 计算第一类贝塞尔函数 $J_1(x)$ 的单精度浮点数值。
2. **`y1f(float x)`:** 计算第二类贝塞尔函数 $Y_1(x)$ (也称为诺依曼函数) 的单精度浮点数值。
3. **内部辅助函数 `ponef(float x)` 和 `qonef(float x)`:** 这两个静态内联函数用于在计算 `j1f` 和 `y1f` 时，对于较大的 `x` 值，提供渐近展开式的多项式逼近。

**与 Android 功能的关系及举例:**

`libm` 是 Android 系统中提供数学运算的核心库。许多 Android 的底层组件和应用框架都依赖于 `libm` 提供的数学函数。

* **Android Framework:**
    * **图形渲染:**  OpenGL ES 和 Skia 等图形库在进行矩阵变换、光照计算、曲线绘制等操作时，可能会间接使用到贝塞尔函数。例如，在某些特殊效果或路径动画的计算中，贝塞尔曲线会被用到，而贝塞尔函数的计算可能是其基础。
    * **音频处理:**  在音频信号处理中，例如音频合成、滤波器设计、频谱分析等，贝塞尔函数有时会被用于构建特定的滤波器或进行信号分解。
    * **传感器数据处理:**  某些传感器数据，例如陀螺仪或加速度计的数据，在进行滤波或特征提取时，可能涉及更高级的数学运算，间接用到 `libm` 的函数。
* **Android NDK:**
    * 使用 C/C++ 开发 Android 应用的开发者，可以通过 NDK 调用标准 C 库提供的数学函数，包括 `j1f` 和 `y1f`。
    * **游戏开发:** 物理引擎、动画系统、特效渲染等都可能需要复杂的数学计算，贝塞尔函数可能在其中某些特定的算法中被使用。
    * **科学计算应用:**  如果开发涉及科学计算、数据分析的应用，直接使用这些数学函数是常见的。
    * **音视频处理应用:**  如上所述，NDK 开发的音视频应用可能会直接使用贝塞尔函数。

**`libc` 函数的功能实现:**

1. **`j1f(float x)` 的实现:**
   * **特殊值处理:** 首先处理输入 `x` 为 NaN (Not a Number) 或无穷大的情况，返回相应的值。
   * **大 `|x|` 的情况 (`ix >= 0x40000000`，即 $|x| \ge 2.0$)**:
     * 使用三角函数 `sincosf` 计算 $\sin(y)$ 和 $\cos(y)$，其中 $y = |x|$。
     * 为了提高精度和避免直接计算 $\cos(x - 3\pi/4)$ 和 $\sin(x - 3\pi/4)$ 可能出现的精度损失，利用三角恒等式进行变换。
     * 调用内部辅助函数 `ponef(y)` 和 `qonef(y)` 来计算渐近展开式的多项式逼近。
     * 根据公式 $J_1(x) \approx \sqrt{\frac{2}{\pi x}} (P(1,x) \cos(x - 3\pi/4) - Q(1,x) \sin(x - 3\pi/4))$ 计算结果。
     * 对于非常大的 `|x|` (`ix > 0x58000000`)，使用更简化的近似。
   * **小 `|x|` 的情况 (`ix < 0x39000000`，即 $|x| < 2^{-13}$)**:
     * 使用近似公式 $J_1(x) \approx \frac{x}{2}$。
   * **中间 `|x|` 的情况:**
     * 使用多项式逼近：$J_1(x) \approx \frac{x}{2} + x \frac{r(x^2)}{s(x^2)}$，其中 `r` 和 `s` 是关于 $x^2$ 的多项式，系数分别为 `r00` 到 `r03` 和 `s01` 到 `s05`。
   * **符号处理:** 根据输入 `x` 的符号调整结果的符号。

2. **`y1f(float x)` 的实现:**
   * **特殊值处理:** 处理 NaN、无穷大、零以及负数输入（根据定义，第二类贝塞尔函数在负数上无定义，通常返回 NaN）。
   * **大 `|x|` 的情况 (`ix >= 0x40000000`，即 $|x| \ge 2.0`)**:
     * 类似于 `j1f`，使用三角函数和内部辅助函数 `ponef` 和 `qonef`。
     * 根据公式 $Y_1(x) \approx \sqrt{\frac{2}{\pi x}} (P(1,x) \sin(x - 3\pi/4) + Q(1,x) \cos(x - 3\pi/4))$ 计算结果。
   * **小 `|x|` 的情况 (`ix <= 0x33000000`，即 $|x| < 2^{-25}`):
     * 使用近似公式 $Y_1(x) \approx -\frac{2}{\pi x}$，代码中使用 `tpi/x`，其中 `tpi` 近似于 $\frac{2}{\pi}$。
   * **中间 `|x|` 的情况:**
     * 使用更复杂的多项式逼近，涉及到系数 `U0` 和 `V0`。
     * 还利用了 `j1f(x)` 和 `logf(x)` 的结果，表示 $Y_1(x)$ 的计算可能依赖于 $J_1(x)$。

3. **`ponef(float x)` 和 `qonef(float x)` 的实现:**
   * 这两个函数都使用有理函数逼近，即多项式除以多项式，来计算 $P(1,x)$ 和 $Q(1,x)$ 的值。
   * 它们根据 `x` 的不同范围选择不同的多项式系数，以提高在不同区间的逼近精度。
   * 例如，`ponef` 对于不同的 `x` 区间 (由 `ix` 的值决定)，使用不同的系数数组 `pr8`, `ps8`, `pr5`, `ps5`, `pr3`, `ps3`, `pr2`, `ps2`。

**Dynamic Linker 的功能:**

Dynamic Linker (在 Android 中通常是 `linker` 或 `ld-android.so`) 负责在程序启动或运行时加载共享库 (`.so` 文件)，并解析和链接库中的符号。

**SO 布局样本 (以 `libm.so` 为例):**

```
libm.so:
  .text         # 存放可执行的代码段 (包括 j1f, y1f, ponef, qonef 等函数的机器码)
  .rodata       # 存放只读数据 (包括常量 vone, vzero, huge, one, invsqrtpi, tpi, 以及多项式系数等)
  .data         # 存放已初始化的全局变量和静态变量
  .bss          # 存放未初始化的全局变量和静态变量
  .plt          # Procedure Linkage Table，用于延迟绑定外部函数
  .got.plt      # Global Offset Table，用于存储外部函数的地址
  .symtab       # 符号表，包含库中定义和引用的符号信息
  .strtab       # 字符串表，存储符号名称等字符串
  .rel.dyn      # 动态重定位表，记录需要在加载时调整的地址
  .rel.plt      # PLT 的重定位表
  ...          # 其他段 (如 .hash, .dynamic 等)
```

**每种符号的处理过程:**

1. **导出的全局符号 (例如 `j1f`, `y1f`):**
   * 在 `libm.so` 的 `.symtab` 中有对应的条目，标记为 `GLOBAL` 和 `FUNC`。
   * 当其他共享库或可执行文件需要使用 `j1f` 时，Dynamic Linker 会在 `libm.so` 的符号表中查找该符号。
   * 找到符号后，Dynamic Linker 会将该符号的地址 (在 `.text` 段中的位置) 记录在调用者的 GOT (Global Offset Table) 中，实现符号的链接。这个过程可能发生在加载时 (预绑定) 或首次调用时 (延迟绑定)。

2. **导入的外部符号 (例如 `sincosf`, `sqrtf`, `logf`):**
   * 在 `e_j1f.c` 中使用了 `sincosf`, `sqrtf` 等函数，这些函数可能定义在其他的 `libc` 库或其他共享库中。
   * `libm.so` 的符号表中会有对这些符号的引用，标记为 `UNDEF` (未定义)。
   * Dynamic Linker 在加载 `libm.so` 时，会查找提供这些符号的库，并在其符号表中找到对应的定义。
   * 然后，Dynamic Linker 会更新 `libm.so` 的 GOT 中这些符号的地址，指向提供这些符号的库中的实现。

3. **静态符号 (例如 `ponef`, `qonef`, 以及常量 `huge`, `one` 等):**
   * 这些符号在 `e_j1f.c` 中被声明为 `static`，意味着它们的作用域仅限于当前编译单元 (即 `e_j1f.o`，最终包含在 `libm.so` 中)。
   * 静态函数和常量不会在共享库的全局符号表中导出，因此外部库无法直接访问。
   * 它们的地址在库加载时由 Dynamic Linker 分配，并且在库内部直接使用，无需通过 GOT 进行间接访问。

**逻辑推理的假设输入与输出:**

假设输入 `x` 为一个单精度浮点数。

* **假设输入:** `j1f(1.0f)`
* **预期输出:**  接近于第一类贝塞尔函数 $J_1(1)$ 的值，约为 `0.4400505857`。

* **假设输入:** `y1f(5.0f)`
* **预期输出:** 接近于第二类贝塞尔函数 $Y_1(5)$ 的值，约为 `-0.0177596770`。

* **假设输入:** `j1f(0.0f)`
* **预期输出:** `0.0f`

* **假设输入:** `y1f(0.0f)`
* **预期输出:**  根据代码，如果 `ix == 0`，返回 `-one/vzero`，即负无穷大。

**用户或编程常见的使用错误:**

1. **输入超出函数定义域:** 例如，`y1f` 在负数上的定义可能不符合预期（通常返回 NaN 或引发错误）。用户可能会错误地传入负数。
   ```c
   float result = y1f(-2.0f); // 可能会得到 NaN
   ```

2. **误用单精度和双精度函数:**  开发者可能错误地将双精度浮点数传递给 `j1f` 或 `y1f`，或者期望得到双精度的结果。应该使用 `j1` 和 `y1` 来处理双精度浮点数。

3. **精度问题:**  对于某些应用，单精度浮点数的精度可能不够。用户需要理解单精度浮点数的精度限制。

4. **忽略特殊情况:**  开发者可能没有充分考虑输入为 NaN 或无穷大的情况，导致程序出现未预期的行为。

5. **性能考虑不周:**  频繁调用这些复杂的数学函数可能会影响性能，特别是在对性能敏感的应用中。开发者可能需要考虑使用近似算法或查表法等优化手段。

**Android Framework 或 NDK 到达这里的调试线索:**

1. **NDK 开发:**
   * 在 C/C++ 代码中调用 `<math.h>` 或 `<cmath>` 中的 `j1f(x)` 或 `y1f(x)` 函数。
   * 编译 NDK 代码时，链接器会将这些符号链接到 `libm.so`。
   * 运行时，当执行到调用 `j1f` 或 `y1f` 的代码时，Dynamic Linker 会加载 `libm.so` 并解析符号。
   * 可以使用 `adb logcat` 查看加载库的信息，或者使用 `lldb` 或 `gdb` 进行调试，在 `j1f` 或 `y1f` 函数入口设置断点。
   * 使用 `maps` 命令 (在调试器中) 可以查看 `libm.so` 在内存中的加载地址。

2. **Android Framework:**
   * 如果是 Framework 的 Java 代码间接调用，例如通过 JNI 调用到 Native 代码，最终会走到 `libm.so` 中的函数。
   * 可以通过查看 Framework 相关的 Native 代码 (如果开源) 来追踪调用链。
   * 使用 `systrace` 或 `perfetto` 等工具可以分析系统调用和函数调用关系，找到对 `libm` 中函数的调用。
   * 在 Android Framework 的 Native 组件中，可以使用 `ALOG` 等日志输出进行调试。
   * 同样可以使用调试器连接到 Framework 进程，并在 `libm.so` 的相关函数入口设置断点。

**逐步到达 `e_j1f.c` 的过程示例 (NDK):**

1. **Java 代码:**
   ```java
   public class MainActivity extends AppCompatActivity {
       static {
           System.loadLibrary("native-lib");
       }
       private native float calculateJ1(float x);
       // ...
           float input = 2.0f;
           float result = calculateJ1(input);
           Log.d("Bessel", "J1(" + input + ") = " + result);
       // ...
   }
   ```

2. **Native 代码 (`native-lib.cpp`):**
   ```cpp
   #include <jni.h>
   #include <cmath>
   #include <android/log.h>

   #define TAG "NativeLib"

   extern "C" JNIEXPORT jfloat JNICALL
   Java_com_example_myapp_MainActivity_calculateJ1(JNIEnv *env, jobject /* this */, jfloat x) {
       float result = j1f(x);
       __android_log_print(ANDROID_LOG_DEBUG, TAG, "Calculating j1f(%f) = %f", x, result);
       return result;
   }
   ```

3. **编译链接:**
   * NDK 编译系统会编译 `native-lib.cpp` 生成 `native-lib.so`。
   * 链接时，`j1f` 函数的符号会被解析为 `libm.so` 中 `e_j1f.o` 编译生成的代码。

4. **运行调试:**
   * 当 `MainActivity` 的 `calculateJ1` 方法被调用时，会执行到 `j1f(x)`。
   * 如果使用调试器 (如 lldb)，可以在 `e_j1f.c` 的 `j1f` 函数入口设置断点，观察执行过程和变量值。

通过以上分析，可以对 `bionic/libm/upstream-freebsd/lib/msun/src/e_j1f.c` 文件的功能、与 Android 的关系、实现细节以及在 Android 系统中的使用和调试方法有一个较为全面的了解。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_j1f.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/* e_j1f.c -- float version of e_j1.c.
 * Conversion to float by Ian Lance Taylor, Cygnus Support, ian@cygnus.com.
 */

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
 * See e_j1.c for complete comments.
 */

#include "math.h"
#include "math_private.h"

static __inline float ponef(float), qonef(float);

static const volatile float vone = 1, vzero = 0;

static const float
huge    = 1e30,
one	= 1.0,
invsqrtpi=  5.6418961287e-01, /* 0x3f106ebb */
tpi      =  6.3661974669e-01, /* 0x3f22f983 */
/* R0/S0 on [0,2] */
r00  = -6.2500000000e-02, /* 0xbd800000 */
r01  =  1.4070566976e-03, /* 0x3ab86cfd */
r02  = -1.5995563444e-05, /* 0xb7862e36 */
r03  =  4.9672799207e-08, /* 0x335557d2 */
s01  =  1.9153760746e-02, /* 0x3c9ce859 */
s02  =  1.8594678841e-04, /* 0x3942fab6 */
s03  =  1.1771846857e-06, /* 0x359dffc2 */
s04  =  5.0463624390e-09, /* 0x31ad6446 */
s05  =  1.2354227016e-11; /* 0x2d59567e */

static const float zero    = 0.0;

float
j1f(float x)
{
	float z, s,c,ss,cc,r,u,v,y;
	int32_t hx,ix;

	GET_FLOAT_WORD(hx,x);
	ix = hx&0x7fffffff;
	if(ix>=0x7f800000) return one/x;
	y = fabsf(x);
	if(ix >= 0x40000000) {	/* |x| >= 2.0 */
		sincosf(y, &s, &c);
		ss = -s-c;
		cc = s-c;
		if(ix<0x7f000000) {  /* make sure y+y not overflow */
		    z = cosf(y+y);
		    if ((s*c)>zero) cc = z/ss;
		    else 	    ss = z/cc;
		}
	/*
	 * j1(x) = 1/sqrt(pi) * (P(1,x)*cc - Q(1,x)*ss) / sqrt(x)
	 * y1(x) = 1/sqrt(pi) * (P(1,x)*ss + Q(1,x)*cc) / sqrt(x)
	 */
		if(ix>0x58000000) z = (invsqrtpi*cc)/sqrtf(y); /* |x|>2**49 */
		else {
		    u = ponef(y); v = qonef(y);
		    z = invsqrtpi*(u*cc-v*ss)/sqrtf(y);
		}
		if(hx<0) return -z;
		else  	 return  z;
	}
	if(ix<0x39000000) {	/* |x|<2**-13 */
	    if(huge+x>one) return (float)0.5*x;/* inexact if x!=0 necessary */
	}
	z = x*x;
	r =  z*(r00+z*(r01+z*(r02+z*r03)));
	s =  one+z*(s01+z*(s02+z*(s03+z*(s04+z*s05))));
	r *= x;
	return(x*(float)0.5+r/s);
}

static const float U0[5] = {
 -1.9605709612e-01, /* 0xbe48c331 */
  5.0443872809e-02, /* 0x3d4e9e3c */
 -1.9125689287e-03, /* 0xbafaaf2a */
  2.3525259166e-05, /* 0x37c5581c */
 -9.1909917899e-08, /* 0xb3c56003 */
};
static const float V0[5] = {
  1.9916731864e-02, /* 0x3ca3286a */
  2.0255257550e-04, /* 0x3954644b */
  1.3560879779e-06, /* 0x35b602d4 */
  6.2274145840e-09, /* 0x31d5f8eb */
  1.6655924903e-11, /* 0x2d9281cf */
};

float
y1f(float x)
{
	float z, s,c,ss,cc,u,v;
	int32_t hx,ix;

	GET_FLOAT_WORD(hx,x);
        ix = 0x7fffffff&hx;
	if(ix>=0x7f800000) return  vone/(x+x*x);
	if(ix==0) return -one/vzero;
	if(hx<0) return vzero/vzero;
        if(ix >= 0x40000000) {  /* |x| >= 2.0 */
                sincosf(x, &s, &c);
                ss = -s-c;
                cc = s-c;
                if(ix<0x7f000000) {  /* make sure x+x not overflow */
                    z = cosf(x+x);
                    if ((s*c)>zero) cc = z/ss;
                    else            ss = z/cc;
                }
        /* y1(x) = sqrt(2/(pi*x))*(p1(x)*sin(x0)+q1(x)*cos(x0))
         * where x0 = x-3pi/4
         *      Better formula:
         *              cos(x0) = cos(x)cos(3pi/4)+sin(x)sin(3pi/4)
         *                      =  1/sqrt(2) * (sin(x) - cos(x))
         *              sin(x0) = sin(x)cos(3pi/4)-cos(x)sin(3pi/4)
         *                      = -1/sqrt(2) * (cos(x) + sin(x))
         * To avoid cancellation, use
         *              sin(x) +- cos(x) = -cos(2x)/(sin(x) -+ cos(x))
         * to compute the worse one.
         */
                if(ix>0x58000000) z = (invsqrtpi*ss)/sqrtf(x); /* |x|>2**49 */
                else {
                    u = ponef(x); v = qonef(x);
                    z = invsqrtpi*(u*ss+v*cc)/sqrtf(x);
                }
                return z;
        }
        if(ix<=0x33000000) {    /* x < 2**-25 */
            return(-tpi/x);
        }
        z = x*x;
        u = U0[0]+z*(U0[1]+z*(U0[2]+z*(U0[3]+z*U0[4])));
        v = one+z*(V0[0]+z*(V0[1]+z*(V0[2]+z*(V0[3]+z*V0[4]))));
        return(x*(u/v) + tpi*(j1f(x)*logf(x)-one/x));
}

/* For x >= 8, the asymptotic expansions of pone is
 *	1 + 15/128 s^2 - 4725/2^15 s^4 - ...,	where s = 1/x.
 * We approximate pone by
 * 	pone(x) = 1 + (R/S)
 * where  R = pr0 + pr1*s^2 + pr2*s^4 + ... + pr5*s^10
 * 	  S = 1 + ps0*s^2 + ... + ps4*s^10
 * and
 *	| pone(x)-1-R/S | <= 2  ** ( -60.06)
 */

static const float pr8[6] = { /* for x in [inf, 8]=1/[0,0.125] */
  0.0000000000e+00, /* 0x00000000 */
  1.1718750000e-01, /* 0x3df00000 */
  1.3239480972e+01, /* 0x4153d4ea */
  4.1205184937e+02, /* 0x43ce06a3 */
  3.8747453613e+03, /* 0x45722bed */
  7.9144794922e+03, /* 0x45f753d6 */
};
static const float ps8[5] = {
  1.1420736694e+02, /* 0x42e46a2c */
  3.6509309082e+03, /* 0x45642ee5 */
  3.6956207031e+04, /* 0x47105c35 */
  9.7602796875e+04, /* 0x47bea166 */
  3.0804271484e+04, /* 0x46f0a88b */
};

static const float pr5[6] = { /* for x in [8,4.5454]=1/[0.125,0.22001] */
  1.3199052094e-11, /* 0x2d68333f */
  1.1718749255e-01, /* 0x3defffff */
  6.8027510643e+00, /* 0x40d9b023 */
  1.0830818176e+02, /* 0x42d89dca */
  5.1763616943e+02, /* 0x440168b7 */
  5.2871520996e+02, /* 0x44042dc6 */
};
static const float ps5[5] = {
  5.9280597687e+01, /* 0x426d1f55 */
  9.9140142822e+02, /* 0x4477d9b1 */
  5.3532670898e+03, /* 0x45a74a23 */
  7.8446904297e+03, /* 0x45f52586 */
  1.5040468750e+03, /* 0x44bc0180 */
};

static const float pr3[6] = {
  3.0250391081e-09, /* 0x314fe10d */
  1.1718686670e-01, /* 0x3defffab */
  3.9329774380e+00, /* 0x407bb5e7 */
  3.5119403839e+01, /* 0x420c7a45 */
  9.1055007935e+01, /* 0x42b61c2a */
  4.8559066772e+01, /* 0x42423c7c */
};
static const float ps3[5] = {
  3.4791309357e+01, /* 0x420b2a4d */
  3.3676245117e+02, /* 0x43a86198 */
  1.0468714600e+03, /* 0x4482dbe3 */
  8.9081134033e+02, /* 0x445eb3ed */
  1.0378793335e+02, /* 0x42cf936c */
};

static const float pr2[6] = {/* for x in [2.8570,2]=1/[0.3499,0.5] */
  1.0771083225e-07, /* 0x33e74ea8 */
  1.1717621982e-01, /* 0x3deffa16 */
  2.3685150146e+00, /* 0x401795c0 */
  1.2242610931e+01, /* 0x4143e1bc */
  1.7693971634e+01, /* 0x418d8d41 */
  5.0735230446e+00, /* 0x40a25a4d */
};
static const float ps2[5] = {
  2.1436485291e+01, /* 0x41ab7dec */
  1.2529022980e+02, /* 0x42fa9499 */
  2.3227647400e+02, /* 0x436846c7 */
  1.1767937469e+02, /* 0x42eb5bd7 */
  8.3646392822e+00, /* 0x4105d590 */
};

static __inline float
ponef(float x)
{
	const float *p,*q;
	float z,r,s;
        int32_t ix;
	GET_FLOAT_WORD(ix,x);
	ix &= 0x7fffffff;
        if(ix>=0x41000000)     {p = pr8; q= ps8;}
        else if(ix>=0x409173eb){p = pr5; q= ps5;}
        else if(ix>=0x4036d917){p = pr3; q= ps3;}
	else                   {p = pr2; q= ps2;}	/* ix>=0x40000000 */
        z = one/(x*x);
        r = p[0]+z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))));
        s = one+z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*q[4]))));
        return one+ r/s;
}


/* For x >= 8, the asymptotic expansions of qone is
 *	3/8 s - 105/1024 s^3 - ..., where s = 1/x.
 * We approximate pone by
 * 	qone(x) = s*(0.375 + (R/S))
 * where  R = qr1*s^2 + qr2*s^4 + ... + qr5*s^10
 * 	  S = 1 + qs1*s^2 + ... + qs6*s^12
 * and
 *	| qone(x)/s -0.375-R/S | <= 2  ** ( -61.13)
 */

static const float qr8[6] = { /* for x in [inf, 8]=1/[0,0.125] */
  0.0000000000e+00, /* 0x00000000 */
 -1.0253906250e-01, /* 0xbdd20000 */
 -1.6271753311e+01, /* 0xc1822c8d */
 -7.5960174561e+02, /* 0xc43de683 */
 -1.1849806641e+04, /* 0xc639273a */
 -4.8438511719e+04, /* 0xc73d3683 */
};
static const float qs8[6] = {
  1.6139537048e+02, /* 0x43216537 */
  7.8253862305e+03, /* 0x45f48b17 */
  1.3387534375e+05, /* 0x4802bcd6 */
  7.1965775000e+05, /* 0x492fb29c */
  6.6660125000e+05, /* 0x4922be94 */
 -2.9449025000e+05, /* 0xc88fcb48 */
};

static const float qr5[6] = { /* for x in [8,4.5454]=1/[0.125,0.22001] */
 -2.0897993405e-11, /* 0xadb7d219 */
 -1.0253904760e-01, /* 0xbdd1fffe */
 -8.0564479828e+00, /* 0xc100e736 */
 -1.8366960144e+02, /* 0xc337ab6b */
 -1.3731937256e+03, /* 0xc4aba633 */
 -2.6124443359e+03, /* 0xc523471c */
};
static const float qs5[6] = {
  8.1276550293e+01, /* 0x42a28d98 */
  1.9917987061e+03, /* 0x44f8f98f */
  1.7468484375e+04, /* 0x468878f8 */
  4.9851425781e+04, /* 0x4742bb6d */
  2.7948074219e+04, /* 0x46da5826 */
 -4.7191835938e+03, /* 0xc5937978 */
};

static const float qr3[6] = {
 -5.0783124372e-09, /* 0xb1ae7d4f */
 -1.0253783315e-01, /* 0xbdd1ff5b */
 -4.6101160049e+00, /* 0xc0938612 */
 -5.7847221375e+01, /* 0xc267638e */
 -2.2824453735e+02, /* 0xc3643e9a */
 -2.1921012878e+02, /* 0xc35b35cb */
};
static const float qs3[6] = {
  4.7665153503e+01, /* 0x423ea91e */
  6.7386511230e+02, /* 0x4428775e */
  3.3801528320e+03, /* 0x45534272 */
  5.5477290039e+03, /* 0x45ad5dd5 */
  1.9031191406e+03, /* 0x44ede3d0 */
 -1.3520118713e+02, /* 0xc3073381 */
};

static const float qr2[6] = {/* for x in [2.8570,2]=1/[0.3499,0.5] */
 -1.7838172539e-07, /* 0xb43f8932 */
 -1.0251704603e-01, /* 0xbdd1f475 */
 -2.7522056103e+00, /* 0xc0302423 */
 -1.9663616180e+01, /* 0xc19d4f16 */
 -4.2325313568e+01, /* 0xc2294d1f */
 -2.1371921539e+01, /* 0xc1aaf9b2 */
};
static const float qs2[6] = {
  2.9533363342e+01, /* 0x41ec4454 */
  2.5298155212e+02, /* 0x437cfb47 */
  7.5750280762e+02, /* 0x443d602e */
  7.3939318848e+02, /* 0x4438d92a */
  1.5594900513e+02, /* 0x431bf2f2 */
 -4.9594988823e+00, /* 0xc09eb437 */
};

static __inline float
qonef(float x)
{
	const float *p,*q;
	float  s,r,z;
	int32_t ix;
	GET_FLOAT_WORD(ix,x);
	ix &= 0x7fffffff;
	if(ix>=0x41000000)     {p = qr8; q= qs8;}
	else if(ix>=0x409173eb){p = qr5; q= qs5;}
	else if(ix>=0x4036d917){p = qr3; q= qs3;}
	else                   {p = qr2; q= qs2;}	/* ix>=0x40000000 */
	z = one/(x*x);
	r = p[0]+z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))));
	s = one+z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*(q[4]+z*q[5])))));
	return ((float).375 + r/s)/x;
}

"""

```
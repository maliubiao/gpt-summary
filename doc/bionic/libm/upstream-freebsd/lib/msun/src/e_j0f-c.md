Response:
Let's break down the thought process for answering the request about `e_j0f.c`.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the `e_j0f.c` file within the Android Bionic library and its relation to Android. This involves dissecting the code, explaining individual functions, considering the dynamic linker aspect, addressing potential errors, and tracing the execution path from Android.

**2. Initial Code Scan and Keyword Identification:**

I'd start by scanning the code for key mathematical terms and function names. I see `j0f`, `y0f`, `pzerof`, `qzerof`, `sincosf`, `cosf`, `sqrtf`, `logf`, `fabsf`. The `j0f` and `y0f` names strongly suggest Bessel functions of the first and second kind, order 0. The `f` suffix indicates these are single-precision float versions.

**3. Function-by-Function Analysis:**

* **`j0f(float x)`:** This is clearly the main function for calculating the Bessel function of the first kind, order 0, for a float input `x`. The code branches based on the magnitude of `x`.
    * **Large `x`:**  It uses trigonometric functions (`sincosf`, `cosf`) and asymptotic expansions. The comments mentioning "P(0,x)" and "Q(0,x)" hint at approximations using rational functions.
    * **Small `x`:**  It uses polynomial approximations. The special handling for very small `x` (near zero) suggests dealing with potential precision issues and the behavior of the Bessel function near zero (which is 1).
    * **Intermediate `x`:**  A combination of polynomial approximations is used.
* **`y0f(float x)`:**  Similar to `j0f`, this calculates the Bessel function of the second kind, order 0. It also handles different ranges of `x` and uses similar techniques (trigonometric functions, asymptotic expansions, polynomial approximations). The special handling for `x=0` (returning negative infinity) and negative `x` (returning NaN) is characteristic of the Y0 Bessel function.
* **`pzerof(float x)` and `qzerof(float x)`:** These are helper functions used in the asymptotic expansions for large `x`. The comments and the `pR*` and `qR*` arrays clearly point to rational function approximations. The different sets of constants (`pR8`, `pS8`, etc.) for different ranges of `x` suggest piecewise approximations for better accuracy.

**4. Connecting to Android Functionality:**

The core functionality is providing mathematical functions. Android's math library (part of Bionic) is used by many higher-level components.

* **Examples:** Graphics rendering (OpenGL ES), audio processing, physics simulations, sensor data processing, and even some aspects of the Android UI framework might indirectly use these functions. I would try to think of concrete examples where these mathematical functions are essential. For instance, calculating the intensity pattern of a circular aperture (diffraction) involves Bessel functions.

**5. Explaining `libc` Functions:**

I need to explain the *standard* C library functions used within `e_j0f.c`:

* **`fabsf(float x)`:**  Absolute value. Straightforward.
* **`sqrtf(float x)`:** Square root. Emphasize its importance in the asymptotic expansions.
* **`sincosf(float x, float *s, float *c)`:**  Simultaneous sine and cosine calculation. Highlight its efficiency compared to calling `sinf` and `cosf` separately.
* **`cosf(float x)`:** Cosine.
* **`logf(float x)`:** Natural logarithm. Important for `y0f` near zero.
* **`GET_FLOAT_WORD(hx, x)` and `SET_FLOAT_WORD(y, ix)` (implicitly used):**  These are Bionic-specific macros for manipulating the bit representation of floats. Explain why this is necessary for handling special cases (NaN, infinity) and potentially for performance optimizations.

**6. Dynamic Linker Aspects:**

This requires understanding how shared libraries work in Android.

* **SO Layout:** Describe the typical sections: `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), `.rodata` (read-only data), symbol tables (`.symtab`, `.dynsym`), relocation tables (`.rel.dyn`, `.rel.plt`).
* **Symbol Resolution:** Explain the difference between static and dynamic linking. Focus on how the dynamic linker resolves symbols at runtime, using the symbol tables to find the addresses of functions and variables. Explain the different types of symbols (global, local, function, object). For PLT/GOT, provide a simplified explanation of how lazy binding works.

**7. Logical Reasoning (Assumptions and Outputs):**

Come up with some simple test cases.

* **Input:** `x = 0.0f` for `j0f`. **Output:** Should be close to 1.0f.
* **Input:** `x` being a large positive number for `j0f`. **Output:** Should oscillate and decrease in magnitude.
* **Input:** `x = 0.0f` for `y0f`. **Output:** Should be negative infinity.
* **Input:** `x` being negative for `y0f`. **Output:** Should be NaN.

**8. Common Usage Errors:**

Focus on practical mistakes a programmer might make.

* Passing negative values to `sqrtf` or `logf`.
* Not handling potential NaN or infinity results.
* Using the double-precision versions (`j0`, `y0`) when single-precision is intended (or vice-versa) and the performance implications.
* Underflow or overflow when dealing with very large or very small inputs.

**9. Android Framework/NDK Call Stack:**

Think about how a call might originate in an Android app.

* **NDK:** A C/C++ app using the NDK can directly call math functions.
* **Framework (Java):**  Java code might call native methods (JNI) that eventually call Bionic functions. Think of classes like `android.opengl.Matrix` or `android.media.AudioTrack` that might involve mathematical operations.
* **System Services:**  Lower-level Android system services (written in C/C++) also heavily rely on Bionic.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on the complex polynomial approximations. **Correction:** While important, also emphasize the higher-level purpose (Bessel function calculation) and its relevance to Android.
* **Initial thought:**  Go into extreme detail about GOT/PLT. **Correction:** Keep the explanation concise and focused on the core idea of dynamic symbol resolution for this particular context.
* **Initial thought:**  Only consider direct NDK usage. **Correction:**  Broaden the scope to include indirect usage through the Android Framework and system services.

By following this structured approach, breaking down the problem into smaller, manageable parts, and considering different aspects of the request, a comprehensive and accurate answer can be constructed. The process involves a mix of code analysis, understanding mathematical concepts, knowledge of operating systems and linking, and practical software development experience.
好的，让我们深入了解一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_j0f.c` 这个文件。

**功能概述**

`e_j0f.c` 文件实现了单精度浮点数（`float`）的零阶第一类贝塞尔函数 `j0f(x)` 和零阶第二类贝塞尔函数 `y0f(x)`。

* **`j0f(float x)`:** 计算给定单精度浮点数 `x` 的零阶第一类贝塞尔函数的值。第一类贝塞尔函数通常用于描述波动现象，例如声波、电磁波在圆柱形或球形几何体中的传播。
* **`y0f(float x)`:** 计算给定单精度浮点数 `x` 的零阶第二类贝塞尔函数的值。第二类贝塞尔函数，也称为诺依曼函数或韦伯函数，与第一类贝塞尔函数线性无关，在某些物理问题的解中也会出现，特别是在涉及到奇点或原点附近的行为时。

**与 Android 功能的关系及举例**

Bionic 是 Android 的 C 库，`libm` 是其数学库。因此，`e_j0f.c` 中实现的贝塞尔函数直接为 Android 平台上的应用程序和系统服务提供了底层的数学支持。

**举例说明：**

1. **音频处理:** 在音频信号处理中，某些滤波器的设计可能涉及到贝塞尔函数，以实现特定的频率响应特性。Android 的音频框架底层的 Native 代码可能会使用这些函数。
2. **图形渲染 (OpenGL ES):**  在进行某些特殊效果的渲染时，例如模拟衍射或干涉，可能会用到贝塞尔函数来计算光线的强度分布。Android 的图形库可能间接使用这些函数。
3. **科学计算和工程应用:**  如果 Android 设备上运行科学计算或工程相关的 App（通过 NDK 开发），这些 App 可能会直接调用 `j0f` 和 `y0f` 来解决相关的数学问题。
4. **传感器数据处理:** 某些传感器数据的分析，例如陀螺仪或加速度计的信号处理，在特定的算法中可能需要用到贝塞尔函数。

**libc 函数的实现细节**

让我们详细看看 `j0f` 和 `y0f` 的实现：

**`j0f(float x)` 的实现**

`j0f(float x)` 的实现采用了分段逼近的方法，针对 `x` 的不同取值范围使用不同的计算策略，以保证精度和效率：

1. **处理特殊情况:**
   * 如果 `x` 是 NaN 或无穷大，返回 `1/(x*x)`，这是一个约定俗成的处理方式，虽然数学上不太严谨，但避免了程序崩溃。
   * 如果 `x` 的绝对值非常小（小于 `2**-12`），则 `j0f(x)` 近似为 1。
   * 如果 `x` 的绝对值较小（小于 1），使用一个基于多项式的逼近公式：`one + z*((r/s)-qrtr)`，其中 `z = x*x`，`r` 和 `s` 是关于 `z` 的多项式。
   * 如果 `x` 的绝对值在 1 到 2 之间，使用另一个基于多项式的逼近公式：`(one+u)*(one-u)+z*(r/s)`，其中 `u = x/2`。
   * 如果 `x` 的绝对值大于等于 2，使用基于三角函数的渐近展开式：`invsqrtpi*(u*cc-v*ss)/sqrtf(x)`，其中 `s` 和 `c` 是 `sin(x)` 和 `cos(x)`，`ss = s-c`, `cc = s+c`，`u` 和 `v` 是由 `pzerof(x)` 和 `qzerof(x)` 计算出的逼近值。对于非常大的 `x`，为了性能，直接使用简化的渐近公式。

2. **辅助函数 `pzerof(float x)` 和 `qzerof(float x)`:**  这两个函数用于计算在 `j0f` 和 `y0f` 的渐近展开式中需要的 `P(0,x)` 和 `Q(0,x)` 的近似值。它们的实现也是基于分段有理函数逼近，针对 `x` 的不同范围使用不同的多项式系数。这些系数是通过数值方法预先计算好的，以保证在各自的范围内具有较高的精度。

**`y0f(float x)` 的实现**

`y0f(float x)` 的实现逻辑与 `j0f(float x)` 类似，也采用了分段逼近的方法：

1. **处理特殊情况:**
   * 如果 `x` 是 NaN 或无穷大，返回 `vone/(x+x*x)`。
   * 如果 `x` 为 0，返回负无穷大 `-one/vzero`。
   * 如果 `x` 为负数，返回 NaN (`vzero/vzero`)，因为零阶第二类贝塞尔函数在负数域没有定义实数值。
   * 如果 `x` 的绝对值非常小（小于 `2**-13`），使用一个近似公式，包含对数项 `tpi*logf(x)`。
   * 如果 `x` 的绝对值较小，使用基于多项式的逼近公式，并加上一个包含 `j0f(x)*logf(x)` 的项。
   * 如果 `x` 的绝对值大于等于 2，使用基于三角函数的渐近展开式：`invsqrtpi*(u*ss+v*cc)/sqrtf(x)`，同样依赖于 `pzerof(x)` 和 `qzerof(x)`。

**关键的 libc 函数及其实现简述:**

* **`fabsf(float x)`:**  计算浮点数 `x` 的绝对值。通常通过屏蔽符号位来实现。
* **`sqrtf(float x)`:** 计算浮点数 `x` 的平方根。实现方法通常包括牛顿迭代法或查找表结合插值等。
* **`sincosf(float x, float *s, float *c)`:** 同时计算 `sin(x)` 和 `cos(x)`。这比分别调用 `sinf` 和 `cosf` 更高效，因为可以共享一些中间计算结果。内部实现通常基于泰勒级数展开或 CORDIC 算法，针对不同的 `x` 值范围可能采用不同的策略。
* **`cosf(float x)`:** 计算浮点数 `x` 的余弦值。实现方法与 `sincosf` 中的余弦部分类似。
* **`logf(float x)`:** 计算浮点数 `x` 的自然对数。实现方法通常基于查找表和多项式逼近，或者使用迭代方法。

**Dynamic Linker 的功能**

Dynamic Linker (在 Android 中主要是 `linker` 或 `lldb-server`) 的主要功能是在程序启动时将程序依赖的共享库加载到内存中，并将程序中对共享库中符号的引用解析到共享库中对应的地址。

**SO 布局样本:**

一个典型的共享库 (`.so`) 文件布局如下（简化版）：

```
ELF Header
Program Headers
Section Headers

.text         # 代码段 (可执行指令)
.rodata       # 只读数据段 (例如，字符串常量，`e_j0f.c` 中的 `static const float` 数据)
.data         # 已初始化的可读写数据段 (全局变量，静态变量)
.bss          # 未初始化的可读写数据段 (未初始化的全局变量，静态变量)

.symtab       # 符号表 (包含库中定义的符号信息，用于静态链接)
.strtab       # 字符串表 (存储符号名称等字符串)
.shstrtab     # 节区字符串表 (存储节区名称)

.dynsym       # 动态符号表 (包含需要在运行时解析的符号信息)
.dynstr       # 动态字符串表 (存储动态符号名称)
.rel.dyn      # 数据段重定位表 (记录数据段中需要重定位的地址)
.rel.plt      # PLT (Procedure Linkage Table) 重定位表 (记录函数调用需要重定位的地址)

... 其他节区 ...
```

**每种符号的处理过程:**

1. **全局符号 (Global Symbols):**
   * **定义在当前 SO 中:** 这些符号的信息会记录在 `.dynsym` 中。当其他 SO 依赖这些符号时，dynamic linker 会在加载时找到这些定义并更新引用者的地址。
   * **需要从其他 SO 导入:** 这些符号在当前 SO 的 `.dynsym` 中标记为未定义。Dynamic linker 会在加载时搜索其他已加载的 SO，找到提供这些符号的 SO，并更新当前 SO 中对这些符号的引用。

2. **局部符号 (Local Symbols):**
   * 这些符号通常只在定义它们的编译单元内部可见，不会出现在动态符号表中，主要用于静态链接和调试。

3. **函数符号 (Function Symbols):**
   * 函数符号的地址是代码在内存中的起始地址。Dynamic linker 会将调用这些函数的指令中的占位符地址替换为函数实际的内存地址。对于动态链接的函数调用，通常会使用 PLT 和 GOT (Global Offset Table) 机制实现延迟绑定。

4. **对象符号 (Object Symbols, 例如全局变量):**
   * 对象符号的地址是变量在内存中的起始地址。Dynamic linker 会更新引用这些变量的指令或数据结构中的地址。

**PLT 和 GOT 的处理过程 (延迟绑定):**

* **初始状态:** 当程序首次调用一个动态链接的函数时，PLT 中的对应条目会跳转到 dynamic linker 的一个例程。
* **Dynamic Linker 解析:** Dynamic linker 根据 GOT 中对应条目的信息，查找函数在内存中的实际地址。
* **更新 GOT:** Dynamic linker 将找到的函数地址写入 GOT 中对应的条目。
* **后续调用:** 后续对同一函数的调用会直接跳转到 GOT 中已更新的地址，避免了重复的解析过程。

**假设输入与输出 (逻辑推理)**

**假设输入 `j0f(2.0f)`:**

* **预期输出:**  根据贝塞尔函数的性质，`j0(2.0)` 的值应该在 0 附近。你可以使用科学计算器或软件验证，实际值约为 `0.223890779`.
* **推理过程:** `j0f` 函数会根据输入 `2.0f` 进入相应的计算分支 (可能是直接的多项式逼近或渐近展开)。函数会使用预先计算好的系数进行运算，最终得到一个浮点数结果。

**假设输入 `y0f(0.5f)`:**

* **预期输出:**  `y0(0.5)` 应该是一个负数，因为零阶第二类贝塞尔函数在接近零时趋于负无穷大。实际值约为 `-0.444519358`.
* **推理过程:** `y0f` 函数会根据输入 `0.5f` 进入相应的计算分支，可能使用包含对数项的逼近公式。

**用户或编程常见的使用错误**

1. **输入超出定义域:**  例如，`y0f` 的输入为负数，会导致 NaN (Not a Number) 的结果。程序员需要注意函数的定义域。
   ```c
   float result = y0f(-1.0f); // result 将是 NaN
   ```

2. **精度问题:** 使用单精度浮点数 `j0f` 和 `y0f` 时，精度有限。对于需要更高精度的计算，应该使用双精度版本 `j0` 和 `y0`。
   ```c
   float x = 1000.0f;
   float j0_single = j0f(x);
   double j0_double = j0(x); // 更高的精度
   ```

3. **未处理 NaN 或无穷大:**  贝塞尔函数在某些情况下可能返回 NaN 或无穷大。程序员需要检查返回值，避免在后续计算中引入错误。
   ```c
   float x = 0.0f;
   float y0_val = y0f(x);
   if (isnan(y0_val) || isinf(y0_val)) {
       // 处理错误情况
   }
   ```

4. **性能考虑:**  在循环中频繁调用这些函数可能会影响性能。如果可能，可以考虑优化算法或使用查表法等技巧。

**Android Framework 或 NDK 如何到达这里 (调试线索)**

假设一个 Android 应用的 Native 代码中调用了 `j0f`：

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码，其中包含了对 `j0f` 的调用。
   ```c++
   #include <cmath>
   #include <android/log.h>

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_myapp_MainActivity_calculateBessel(JNIEnv* env, jobject /* this */, float x) {
       float result = j0f(x);
       __android_log_print(ANDROID_LOG_DEBUG, "MyTag", "j0f(%f) = %f", x, result);
   }
   ```

2. **编译和链接:** NDK 构建系统会将 C/C++ 代码编译成机器码，并将对 `j0f` 的调用链接到 Bionic 的 `libm.so` 共享库。

3. **APK 打包:**  编译后的 Native 库 (`.so` 文件) 会被打包到 APK 文件中。

4. **应用启动:** 当 Android 应用启动时，ClassLoader 会加载应用的 Java 代码。如果应用使用了 Native 代码，Android 系统会加载相应的 Native 库 (`.so` 文件)。

5. **Dynamic Linker 介入:**  系统加载 Native 库时，Dynamic Linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责：
   * 将 `libm.so` 加载到内存中。
   * 解析 `MainActivity.calculateBessel` 函数中对 `j0f` 的符号引用，找到 `libm.so` 中 `j0f` 函数的地址。
   * 更新 `MainActivity.calculateBessel` 函数中的跳转指令，使其指向 `libm.so` 中 `j0f` 的实际地址。

6. **JNI 调用:** 当 Java 代码调用 `MainActivity.calculateBessel` 方法时，会通过 JNI 机制跳转到 Native 代码。

7. **执行 `j0f`:** 在 Native 代码中，执行到 `j0f(x)` 时，CPU 会跳转到 `libm.so` 中 `e_j0f.c` 编译生成的 `j0f` 函数的机器码执行。

**调试线索:**

* **Logcat:**  在 Native 代码中使用 `__android_log_print` 可以输出调试信息，查看 `j0f` 的输入和输出。
* **GDB 或 LLDB:**  可以使用 GDB 或 LLDB 等调试器attach 到正在运行的 Android 进程，设置断点在 `j0f` 函数入口，单步执行，查看寄存器和内存中的值。
* **`adb shell` 和 `maps`:**  可以使用 `adb shell` 连接到设备，通过 `cat /proc/<pid>/maps` 查看进程的内存映射，确认 `libm.so` 是否被加载，以及其加载地址。
* **`readelf` 或 `objdump`:**  可以使用 `readelf` 或 `objdump` 等工具分析 `libm.so` 文件的结构，查看符号表、动态符号表等信息。

总而言之，`e_j0f.c` 是 Android 数学库中实现重要数学函数的基础代码，通过 NDK 调用或 Android Framework 间接调用，为各种 Android 应用和系统服务提供数学计算能力。理解其功能和实现细节有助于开发者更好地利用这些函数，并进行问题排查和性能优化。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_j0f.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/* e_j0f.c -- float version of e_j0.c.
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
 * See e_j0.c for complete comments.
 */

#include "math.h"
#include "math_private.h"

static __inline float pzerof(float), qzerof(float);

static const volatile float vone = 1,  vzero = 0;

static const float
huge 	= 1e30,
one	= 1.0,
invsqrtpi=  5.6418961287e-01, /* 0x3f106ebb */
tpi      =  6.3661974669e-01, /* 0x3f22f983 */
 		/* R0/S0 on [0, 2.00] */
R02  =  1.5625000000e-02, /* 0x3c800000 */
R03  = -1.8997929874e-04, /* 0xb947352e */
R04  =  1.8295404516e-06, /* 0x35f58e88 */
R05  = -4.6183270541e-09, /* 0xb19eaf3c */
S01  =  1.5619102865e-02, /* 0x3c7fe744 */
S02  =  1.1692678527e-04, /* 0x38f53697 */
S03  =  5.1354652442e-07, /* 0x3509daa6 */
S04  =  1.1661400734e-09; /* 0x30a045e8 */

static const float zero = 0, qrtr = 0.25;

float
j0f(float x)
{
	float z, s,c,ss,cc,r,u,v;
	int32_t hx,ix;

	GET_FLOAT_WORD(hx,x);
	ix = hx&0x7fffffff;
	if(ix>=0x7f800000) return one/(x*x);
	x = fabsf(x);
	if(ix >= 0x40000000) {	/* |x| >= 2.0 */
		sincosf(x, &s, &c);
		ss = s-c;
		cc = s+c;
		if(ix<0x7f000000) {  /* Make sure x+x does not overflow. */
		    z = -cosf(x+x);
		    if ((s*c)<zero) cc = z/ss;
		    else 	    ss = z/cc;
		}
	/*
	 * j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
	 * y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)
	 */
		if(ix>0x58000000) z = (invsqrtpi*cc)/sqrtf(x); /* |x|>2**49 */
		else {
		    u = pzerof(x); v = qzerof(x);
		    z = invsqrtpi*(u*cc-v*ss)/sqrtf(x);
		}
		return z;
	}
	if(ix<0x3b000000) {	/* |x| < 2**-9 */
	    if(huge+x>one) {	/* raise inexact if x != 0 */
	        if(ix<0x39800000) return one;	/* |x|<2**-12 */
	        else 	      return one - x*x/4;
	    }
	}
	z = x*x;
	r =  z*(R02+z*(R03+z*(R04+z*R05)));
	s =  one+z*(S01+z*(S02+z*(S03+z*S04)));
	if(ix < 0x3F800000) {	/* |x| < 1.00 */
	    return one + z*((r/s)-qrtr);
	} else {
	    u = x/2;
	    return((one+u)*(one-u)+z*(r/s));
	}
}

static const float
u00  = -7.3804296553e-02, /* 0xbd9726b5 */
u01  =  1.7666645348e-01, /* 0x3e34e80d */
u02  = -1.3818567619e-02, /* 0xbc626746 */
u03  =  3.4745343146e-04, /* 0x39b62a69 */
u04  = -3.8140706238e-06, /* 0xb67ff53c */
u05  =  1.9559013964e-08, /* 0x32a802ba */
u06  = -3.9820518410e-11, /* 0xae2f21eb */
v01  =  1.2730483897e-02, /* 0x3c509385 */
v02  =  7.6006865129e-05, /* 0x389f65e0 */
v03  =  2.5915085189e-07, /* 0x348b216c */
v04  =  4.4111031494e-10; /* 0x2ff280c2 */

float
y0f(float x)
{
	float z, s,c,ss,cc,u,v;
	int32_t hx,ix;

	GET_FLOAT_WORD(hx,x);
        ix = 0x7fffffff&hx;
	if(ix>=0x7f800000) return  vone/(x+x*x);
	if(ix==0) return -one/vzero;
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
                sincosf(x, &s, &c);
                ss = s-c;
                cc = s+c;
	/*
	 * j0(x) = 1/sqrt(pi) * (P(0,x)*cc - Q(0,x)*ss) / sqrt(x)
	 * y0(x) = 1/sqrt(pi) * (P(0,x)*ss + Q(0,x)*cc) / sqrt(x)
	 */
                if(ix<0x7f000000) {  /* make sure x+x not overflow */
                    z = -cosf(x+x);
                    if ((s*c)<zero) cc = z/ss;
                    else            ss = z/cc;
                }
                if(ix>0x58000000) z = (invsqrtpi*ss)/sqrtf(x); /* |x|>2**49 */
                else {
                    u = pzerof(x); v = qzerof(x);
                    z = invsqrtpi*(u*ss+v*cc)/sqrtf(x);
                }
                return z;
	}
	if(ix<=0x39000000) {	/* x < 2**-13 */
	    return(u00 + tpi*logf(x));
	}
	z = x*x;
	u = u00+z*(u01+z*(u02+z*(u03+z*(u04+z*(u05+z*u06)))));
	v = one+z*(v01+z*(v02+z*(v03+z*v04)));
	return(u/v + tpi*(j0f(x)*logf(x)));
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
static const float pR8[6] = { /* for x in [inf, 8]=1/[0,0.125] */
  0.0000000000e+00, /* 0x00000000 */
 -7.0312500000e-02, /* 0xbd900000 */
 -8.0816707611e+00, /* 0xc1014e86 */
 -2.5706311035e+02, /* 0xc3808814 */
 -2.4852163086e+03, /* 0xc51b5376 */
 -5.2530439453e+03, /* 0xc5a4285a */
};
static const float pS8[5] = {
  1.1653436279e+02, /* 0x42e91198 */
  3.8337448730e+03, /* 0x456f9beb */
  4.0597855469e+04, /* 0x471e95db */
  1.1675296875e+05, /* 0x47e4087c */
  4.7627726562e+04, /* 0x473a0bba */
};
static const float pR5[6] = { /* for x in [8,4.5454]=1/[0.125,0.22001] */
 -1.1412546255e-11, /* 0xad48c58a */
 -7.0312492549e-02, /* 0xbd8fffff */
 -4.1596107483e+00, /* 0xc0851b88 */
 -6.7674766541e+01, /* 0xc287597b */
 -3.3123129272e+02, /* 0xc3a59d9b */
 -3.4643338013e+02, /* 0xc3ad3779 */
};
static const float pS5[5] = {
  6.0753936768e+01, /* 0x42730408 */
  1.0512523193e+03, /* 0x44836813 */
  5.9789707031e+03, /* 0x45bad7c4 */
  9.6254453125e+03, /* 0x461665c8 */
  2.4060581055e+03, /* 0x451660ee */
};

static const float pR3[6] = {/* for x in [4.547,2.8571]=1/[0.2199,0.35001] */
 -2.5470459075e-09, /* 0xb12f081b */
 -7.0311963558e-02, /* 0xbd8fffb8 */
 -2.4090321064e+00, /* 0xc01a2d95 */
 -2.1965976715e+01, /* 0xc1afba52 */
 -5.8079170227e+01, /* 0xc2685112 */
 -3.1447946548e+01, /* 0xc1fb9565 */
};
static const float pS3[5] = {
  3.5856033325e+01, /* 0x420f6c94 */
  3.6151397705e+02, /* 0x43b4c1ca */
  1.1936077881e+03, /* 0x44953373 */
  1.1279968262e+03, /* 0x448cffe6 */
  1.7358093262e+02, /* 0x432d94b8 */
};

static const float pR2[6] = {/* for x in [2.8570,2]=1/[0.3499,0.5] */
 -8.8753431271e-08, /* 0xb3be98b7 */
 -7.0303097367e-02, /* 0xbd8ffb12 */
 -1.4507384300e+00, /* 0xbfb9b1cc */
 -7.6356959343e+00, /* 0xc0f4579f */
 -1.1193166733e+01, /* 0xc1331736 */
 -3.2336456776e+00, /* 0xc04ef40d */
};
static const float pS2[5] = {
  2.2220300674e+01, /* 0x41b1c32d */
  1.3620678711e+02, /* 0x430834f0 */
  2.7047027588e+02, /* 0x43873c32 */
  1.5387539673e+02, /* 0x4319e01a */
  1.4657617569e+01, /* 0x416a859a */
};

static __inline float
pzerof(float x)
{
	const float *p,*q;
	float z,r,s;
	int32_t ix;
	GET_FLOAT_WORD(ix,x);
	ix &= 0x7fffffff;
	if(ix>=0x41000000)     {p = pR8; q= pS8;}
	else if(ix>=0x409173eb){p = pR5; q= pS5;}
	else if(ix>=0x4036d917){p = pR3; q= pS3;}
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
static const float qR8[6] = { /* for x in [inf, 8]=1/[0,0.125] */
  0.0000000000e+00, /* 0x00000000 */
  7.3242187500e-02, /* 0x3d960000 */
  1.1768206596e+01, /* 0x413c4a93 */
  5.5767340088e+02, /* 0x440b6b19 */
  8.8591972656e+03, /* 0x460a6cca */
  3.7014625000e+04, /* 0x471096a0 */
};
static const float qS8[6] = {
  1.6377603149e+02, /* 0x4323c6aa */
  8.0983447266e+03, /* 0x45fd12c2 */
  1.4253829688e+05, /* 0x480b3293 */
  8.0330925000e+05, /* 0x49441ed4 */
  8.4050156250e+05, /* 0x494d3359 */
 -3.4389928125e+05, /* 0xc8a7eb69 */
};

static const float qR5[6] = { /* for x in [8,4.5454]=1/[0.125,0.22001] */
  1.8408595828e-11, /* 0x2da1ec79 */
  7.3242180049e-02, /* 0x3d95ffff */
  5.8356351852e+00, /* 0x40babd86 */
  1.3511157227e+02, /* 0x43071c90 */
  1.0272437744e+03, /* 0x448067cd */
  1.9899779053e+03, /* 0x44f8bf4b */
};
static const float qS5[6] = {
  8.2776611328e+01, /* 0x42a58da0 */
  2.0778142090e+03, /* 0x4501dd07 */
  1.8847289062e+04, /* 0x46933e94 */
  5.6751113281e+04, /* 0x475daf1d */
  3.5976753906e+04, /* 0x470c88c1 */
 -5.3543427734e+03, /* 0xc5a752be */
};

static const float qR3[6] = {/* for x in [4.547,2.8571]=1/[0.2199,0.35001] */
  4.3774099900e-09, /* 0x3196681b */
  7.3241114616e-02, /* 0x3d95ff70 */
  3.3442313671e+00, /* 0x405607e3 */
  4.2621845245e+01, /* 0x422a7cc5 */
  1.7080809021e+02, /* 0x432acedf */
  1.6673394775e+02, /* 0x4326bbe4 */
};
static const float qS3[6] = {
  4.8758872986e+01, /* 0x42430916 */
  7.0968920898e+02, /* 0x44316c1c */
  3.7041481934e+03, /* 0x4567825f */
  6.4604252930e+03, /* 0x45c9e367 */
  2.5163337402e+03, /* 0x451d4557 */
 -1.4924745178e+02, /* 0xc3153f59 */
};

static const float qR2[6] = {/* for x in [2.8570,2]=1/[0.3499,0.5] */
  1.5044444979e-07, /* 0x342189db */
  7.3223426938e-02, /* 0x3d95f62a */
  1.9981917143e+00, /* 0x3fffc4bf */
  1.4495602608e+01, /* 0x4167edfd */
  3.1666231155e+01, /* 0x41fd5471 */
  1.6252708435e+01, /* 0x4182058c */
};
static const float qS2[6] = {
  3.0365585327e+01, /* 0x41f2ecb8 */
  2.6934811401e+02, /* 0x4386ac8f */
  8.4478375244e+02, /* 0x44533229 */
  8.8293585205e+02, /* 0x445cbbe5 */
  2.1266638184e+02, /* 0x4354aa98 */
 -5.3109550476e+00, /* 0xc0a9f358 */
};

static __inline float
qzerof(float x)
{
	static const float eighth = 0.125;
	const float *p,*q;
	float s,r,z;
	int32_t ix;
	GET_FLOAT_WORD(ix,x);
	ix &= 0x7fffffff;
	if(ix>=0x41000000)     {p = qR8; q= qS8;}
	else if(ix>=0x409173eb){p = qR5; q= qS5;}
	else if(ix>=0x4036d917){p = qR3; q= qS3;}
	else                   {p = qR2; q= qS2;}	/* ix>=0x40000000 */
	z = one/(x*x);
	r = p[0]+z*(p[1]+z*(p[2]+z*(p[3]+z*(p[4]+z*p[5]))));
	s = one+z*(q[0]+z*(q[1]+z*(q[2]+z*(q[3]+z*(q[4]+z*q[5])))));
	return (r/s-eighth)/x;
}
```
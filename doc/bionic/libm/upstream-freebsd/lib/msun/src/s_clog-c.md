Response:
Let's break down the thought process for analyzing the `s_clog.c` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of a specific C source file (`s_clog.c`) from Android's `libm`. The core task is to understand its functionality and its place within the Android ecosystem. Key aspects include:

* **Functionality:** What does the `clog` function do?
* **Android Relevance:** How does this function relate to Android?
* **Implementation Details:** How is the function implemented? (libc functions)
* **Dynamic Linking:** Does it involve the dynamic linker? If so, how?
* **Edge Cases/Errors:** Potential issues and how users might misuse it.
* **Tracing and Debugging:** How to find this code in the Android framework and how to debug it.

**2. Initial Examination of the Code:**

* **Copyright and License:** Note the copyright information and the BSD license. This is standard boilerplate, but good to be aware of.
* **Includes:** Identify the included headers: `<complex.h>`, `<float.h>`, `"fpmath.h"`, `"math.h"`, `"math_private.h"`. This tells us it's dealing with complex numbers and floating-point arithmetic. The `private.h` header suggests internal math library details.
* **Constants:** The `ln2_hi` and `ln2_lo` constants hint at a base-2 logarithm calculation or related operations.
* **Function Signature:** `double complex clog(double complex z)`. This clearly indicates the function calculates the complex logarithm of a double-precision complex number.

**3. Deconstructing the Function's Logic (Step-by-Step):**

* **Input and Output:** The function takes a `double complex` as input and returns a `double complex`.
* **Extracting Real and Imaginary Parts:** `x = creal(z);`, `y = cimag(z);`. Standard way to access the components of a complex number.
* **Calculating the Argument (Phase):** `v = atan2(y, x);`. This is the standard way to get the angle (argument) of the complex number in the complex plane.
* **Handling Magnitudes:** `ax = fabs(x);`, `ay = fabs(y);`. Working with absolute values. The subsequent `if (ax < ay)` suggests normalizing the magnitude or optimizing for a specific quadrant.
* **Bit Manipulation:** `GET_HIGH_WORD(hax, ax);`, `kx = (hax >> 20) - 1023;`. This directly manipulates the bits of the floating-point representation to extract the exponent. This is a common technique in high-performance math libraries for handling special cases quickly.
* **Special Cases:** The code has several `if` conditions that check for:
    * **NaNs and Infs:**  Handles these gracefully using the general formula involving `hypot` (magnitude) and `log`.
    * **`ax == 1`:**  Optimizes the calculation when the real part's magnitude is 1.
    * **Large differences in exponents (`kx - ky > MANT_DIG`):** Simplifies to `log(ax)`.
    * **Potential Overflow (`kx >= MAX_EXP - 1`):** Scales the input to avoid overflow.
    * **Denormal Numbers (`kx <= MIN_EXP - 2`):** Scales the input to handle denormals.
    * **Near-Zero Imaginary Part:** Handles cases where `ay` is close to zero.
* **Precise Square Calculation:** The Dekker's algorithm section calculates `ax*ax` and `ay*ay` with higher precision. This is crucial for accuracy in numerical computations.
* **Logarithm Calculation:** The core logic uses `log` and `log1p`. `log1p(x)` is `log(1 + x)` and is more accurate for small values of `x`. The conditions around `sh < 0.5 || sh >= 3` suggest different calculation paths depending on the magnitude. The Briggs-Kahan summation algorithm is used for improved accuracy.
* **Weak Reference:** `#if (LDBL_MANT_DIG == 53) __weak_reference(clog, clogl); #endif`. This creates a weak alias for `long double` if its precision is the same as `double`.

**4. Connecting to Android:**

* **`libm`:** Recognize that `s_clog.c` is part of Android's math library (`libm`). This is a fundamental system library.
* **Framework/NDK Usage:**  Think about where complex logarithms might be used. Scientific computations, signal processing, graphics, and certain types of game development are possibilities. NDK developers can directly use `clog`. Android Framework likely uses it indirectly through higher-level APIs or through other libraries that rely on `libm`.

**5. Dynamic Linking Aspects:**

* **Shared Object:** `libm.so` is the relevant shared object.
* **Linking Process:** When an app or library needs `clog`, the dynamic linker (`linker64` or `linker`) resolves the symbol and links against `libm.so`.
* **SO Layout:**  Imagine the sections within `libm.so` (.text, .data, .dynsym, etc.). `clog` resides in the `.text` section.

**6. User Errors and Edge Cases:**

* **Invalid Input:** Passing NaN or infinity as input (though the code handles these).
* **Range Issues:**  While the code handles potential overflow and underflow internally to some extent, extremely large or small input magnitudes could still lead to precision loss or unexpected results.

**7. Tracing and Debugging (Frida):**

* **Identify the Target:**  The `clog` function in `libm.so`.
* **Basic Hook:** A simple Frida script to intercept calls and log arguments and return values.
* **Advanced Hooking:**  Modifying arguments, return values, or observing internal variables.

**8. Structuring the Response:**

Organize the information logically, covering all the points raised in the original request. Use clear headings and bullet points. Provide code examples where appropriate (Frida script, SO layout). Explain technical terms.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just about complex logarithms."  **Correction:**  Realize the deeper implications of it being part of `libm` and its role in the Android ecosystem.
* **Vague understanding of Dekker's algorithm:**  **Refinement:** Briefly research and explain its purpose in high-precision arithmetic.
* **Missing Frida example:** **Correction:** Add a concrete Frida script to illustrate debugging.
* **Not enough detail on dynamic linking:** **Refinement:**  Explain the role of the dynamic linker and provide a basic SO layout.

By following these steps and continuously refining the understanding, you can generate a comprehensive and accurate analysis of the provided C source code.好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/s_clog.c` 这个文件。

**功能列举**

这个 `s_clog.c` 文件实现了计算双精度浮点数复数的自然对数的功能，即 `clog(z)`，其中 `z` 是一个复数。  更具体地说，它实现了以下数学公式：

`clog(x + iy) = ln|x + iy| + i * atan2(y, x)`

其中：

* `x` 是复数的实部。
* `y` 是复数的虚部。
* `ln` 是自然对数。
* `|x + iy|` 是复数的模，等于 `sqrt(x^2 + y^2)`。
* `atan2(y, x)` 是 `y/x` 的反正切，返回值的角度范围是 `(-π, π]`，用于确定复数的辐角。

**与 Android 功能的关系及举例**

`clog` 函数作为 `libm` 的一部分，是 Android 系统中进行数学计算的基础。许多上层的功能，包括 Android Framework 和 NDK 开发的应用，如果需要进行复数运算，很可能间接地或直接地使用到 `clog`。

**举例：**

1. **NDK 开发的游戏或科学计算应用：**  使用 C/C++ 进行开发的 Android 应用，如果需要进行例如信号处理、傅里叶变换、量子力学计算等涉及复数的运算，很可能会直接调用 `clog` 函数。例如，一个音频处理应用可能需要计算复数频谱的对数幅度。

   ```c++
   #include <complex.h>
   #include <stdio.h>

   int main() {
       double complex z = 3.0 + 4.0 * I;
       double complex log_z = clog(z);
       printf("clog(%f + %fi) = %f + %fi\n", creal(z), cimag(z), creal(log_z), cimag(log_z));
       return 0;
   }
   ```

2. **Android Framework 的某些底层算法：** 虽然 Framework 层面直接使用复数运算可能较少，但某些底层的图形处理、信号处理或机器学习库（这些库可能是以 native 代码形式存在并被 Framework 调用）可能会用到复数和复数对数。例如，某些图像滤波器在频域进行操作时可能会涉及到复数运算。

**libc 函数的功能实现**

让我们详细解释一下 `s_clog.c` 中使用的一些关键 libc 函数是如何实现的：

1. **`creal(z)` 和 `cimag(z)`:**  这两个函数分别用于提取复数 `z` 的实部和虚部。它们的实现通常非常简单，因为复数在 C 语言中以结构体形式表示，包含实部和虚部两个成员。这两个函数只是直接访问对应的结构体成员。

   ```c
   // 假设 double complex 的定义类似
   typedef struct {
       double real;
       double imag;
   } double complex;

   double creal(double complex z) {
       return z.real;
   }

   double cimag(double complex z) {
       return z.imag;
   }
   ```

2. **`atan2(y, x)`:**  这个函数计算 `y/x` 的反正切，但它使用两个参数 `y` 和 `x` 的符号来确定返回角的象限。这使得 `atan2` 比 `atan(y/x)` 更可靠，因为它能处理 `x` 为零的情况，并能给出正确的角度范围。

   `atan2` 的实现通常会涉及到以下步骤：
   * 处理特殊情况，如 `x` 和 `y` 均为零，或其中一个为无穷大。
   * 根据 `x` 和 `y` 的符号确定结果的象限。
   * 使用泰勒级数或其他数值逼近方法来计算反正切值。为了提高精度和效率，可能会使用查找表和多项式逼近的组合。

3. **`fabs(x)`:** 返回浮点数 `x` 的绝对值。其实现通常是通过清除浮点数表示中的符号位来实现的。

4. **`hypot(x, y)`:** 计算 `sqrt(x^2 + y^2)`，即直角三角形斜边的长度或复数的模。实现时需要考虑防止溢出和下溢。例如，当 `x` 或 `y` 非常大时，直接计算 `x*x + y*y` 可能会溢出。一种常见的技巧是先将 `x` 和 `y` 都除以较大的值，计算平方和后再乘以该值。

5. **`log(x)`:** 计算 `x` 的自然对数。其实现通常比较复杂，会涉及到以下步骤：
   * 特殊情况处理：如 `x` 为负数（返回 NaN），`x` 为 0（返回负无穷大），`x` 为正无穷大（返回正无穷大）。
   * 范围规约：将 `x` 规约到 `[1, 2)` 或其他易于计算的范围。这通常通过提取 `x` 的指数部分完成，例如 `x = m * 2^e`，那么 `log(x) = log(m) + e * log(2)`。
   * 使用多项式或有理函数逼近 `log(m)`。为了提高精度，可能会使用高阶逼近。

6. **`log1p(x)`:** 计算 `log(1 + x)`。当 `x` 的绝对值非常小时，直接计算 `log(1 + x)` 可能会因为舍入误差而损失精度。`log1p(x)` 的实现会利用针对小 `x` 值的特殊展开或逼近方法来提高精度。例如，可以使用泰勒展开 `x - x^2/2 + x^3/3 - ...`。

7. **`GET_HIGH_WORD(i,d)`:** 这是一个宏，用于获取双精度浮点数 `d` 的高 32 位，并存储到无符号整数 `i` 中。这通常通过类型双关 (type punning) 或位运算实现。

   ```c
   #define GET_HIGH_WORD(i,d) \
       do { \
           union { double d; uint32_t i[2]; } cw; \
           cw.d = (d); \
           (i) = cw.i[_IEEE_BIG_ENDIAN ? 0 : 1]; \
       } while(0)
   ```
   这个宏使用了联合体来访问 `double` 的底层表示。字节序 (endianness) 会影响高低位的存储顺序。

8. **`_2sumF(a, b)` 和 `_2sum(a, b)`:** 这两个函数用于执行带有误差校正的浮点数加法，也被称为 Knuth 的双精度求和算法。它们将两个浮点数 `a` 和 `b` 相加，并返回和的高位部分。低位部分（误差）会被累加到 `b` 中。这有助于提高数值计算的精度。

   ```c
   void _2sumF(double a, double b) {
       double x = a + b;
       double y = b - (x - a);
       b = y; // 将误差存回 b
   }

   void _2sum(double a, double b) {
       double x = a + b;
       double y = b - (x - a);
       b = y; // 将误差存回 b
   }
   ```

**涉及 dynamic linker 的功能**

在这个 `s_clog.c` 文件中，直接涉及 dynamic linker 的部分是使用了 `__weak_reference(clog, clogl)` 宏。

* **`__weak_reference(symbol1, symbol2)`:**  这是一个编译器指令，用于创建符号 `symbol2` 作为 `symbol1` 的弱引用。这意味着如果在链接时找到了 `symbol1` 的定义，`symbol2` 将解析为 `symbol1`。但是，如果找不到 `symbol1` 的定义，使用 `symbol2` 不会导致链接错误。

在这个例子中，如果系统中存在 `clogl` (通常是 `long double` 版本的复数自然对数函数)，那么 `clogl` 将会指向 `clog` 的实现（前提是 `LDBL_MANT_DIG == 53`，即 `long double` 和 `double` 有相同的尾数位数，意味着它们有相同的精度）。如果不存在 `clogl`，则调用 `clogl` 仍然有效，但其行为可能需要根据具体情况进行处理（例如，可能由另一个默认实现或链接器行为来处理）。

**so 布局样本和链接处理过程**

当一个 Android 应用或库需要使用 `clog` 函数时，链接过程如下：

1. **编译时：** 编译器遇到对 `clog` 函数的调用，会在其生成的目标文件中记录一个对 `clog` 符号的未解析引用。

2. **链接时：** 链接器（在 Android 上通常是 `lld`）会将应用或库的目标文件与所需的共享库链接在一起。对于 `clog` 来说，它属于 `libm.so` 这个共享库。链接器会在 `libm.so` 的符号表（`.dynsym` 或 `.symtab` 节）中查找 `clog` 的定义。

3. **运行时：** 当应用启动时，Android 的动态链接器 (`linker` 或 `linker64`) 会加载所需的共享库（`libm.so`）。动态链接器会解析应用中对 `clog` 的未解析引用，将其指向 `libm.so` 中 `clog` 函数的实际地址。

**`libm.so` 的 SO 布局样本（简化）：**

```
libm.so:
  .text:  // 包含可执行代码
    ...
    clog 的机器码
    ...
    其他数学函数的机器码 (sin, cos, exp, etc.)
    ...
  .data:  // 包含已初始化的全局变量
    ...
    一些数学常量
    ...
  .rodata: // 包含只读数据
    ...
    一些查找表或常量
    ...
  .dynsym: // 动态符号表
    ...
    clog (FUNCTION, GLOBAL, DEFAULT)  // 表明 clog 是一个全局可见的函数
    ...
    其他导出符号
    ...
  .symtab: // 符号表 (可能包含更多符号，包括本地符号)
    ...
  .rel.dyn: // 动态重定位表
    ...
  .rel.plt: // PLT (Procedure Linkage Table) 重定位表
    ...
```

**链接处理过程示例：**

假设你的应用 `my_app` 调用了 `clog`：

1. `my_app` 的可执行文件中会有一个 PLT 条目对应 `clog` 的调用。首次调用 `clog` 时，PLT 条目会跳转到一个 resolver 例程。

2. 动态链接器会查找 `clog` 符号，在 `libm.so` 的 `.dynsym` 中找到其定义。

3. 动态链接器会将 `clog` 在 `libm.so` 中的实际地址写入 `my_app` 的 PLT 条目中。

4. 后续对 `clog` 的调用将直接跳转到 `libm.so` 中 `clog` 的实现。

**逻辑推理的假设输入与输出**

假设输入 `z = 1 + i`：

* `x = 1`, `y = 1`
* `|z| = sqrt(1^2 + 1^2) = sqrt(2)`
* `atan2(1, 1) = π/4`
* `ln|z| = ln(sqrt(2)) = 0.5 * ln(2) ≈ 0.34657`

预期输出 `clog(1 + i) ≈ 0.34657 + 0.785398i`

假设输入 `z = e` (实数，虚部为 0)：

* `x = e`, `y = 0`
* `|z| = e`
* `atan2(0, e) = 0`
* `ln|z| = ln(e) = 1`

预期输出 `clog(e) = 1 + 0i`

**用户或编程常见的使用错误**

1. **传递无效的复数：** 虽然 `clog` 可以处理某些特殊情况（如 NaN 和 Inf），但传递未初始化的或包含无效值的复数可能导致未定义的行为或错误的结果。

2. **期望实数对数的结果：** 用户可能会忘记 `clog` 返回的是复数，当输入是实数时，虚部应该为 0。

3. **忽略虚部：** 在某些情况下，用户可能只关心复数对数的模，而忽略了辐角（虚部），这可能会导致信息的丢失。

4. **处理 `clog(0 + 0i)`：** `clog(0)` 的结果是负无穷大加上一个不确定的虚部（取决于趋近于零的方式）。用户需要小心处理这种情况。

5. **精度问题：** 浮点数运算存在精度限制。对于极大的或极小的复数，计算结果可能存在一定的误差。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 应用直接调用：** 最直接的方式是 NDK 开发的应用通过 `<complex.h>` 和 `<math.h>` 包含 `clog` 的声明，并在代码中直接调用。

   ```c++
   #include <complex.h>
   #include <stdio.h>

   int main() {
       double complex z = 2.0 + 3.0 * I;
       double complex result = clog(z);
       printf("clog result: %f + %fi\n", creal(result), cimag(result));
       return 0;
   }
   ```

   编译时，链接器会将这个应用与 `libm.so` 链接。

2. **Android Framework 中的 Native 代码：** Android Framework 的某些组件是用 C/C++ 编写的，例如 Skia 图形库、MediaCodec 等。这些组件内部如果需要进行复数运算，可能会调用 `libm.so` 中的 `clog`。例如，在实现傅里叶变换相关的操作时。

3. **通过 Java Native Interface (JNI)：**  Java 代码可以通过 JNI 调用 Native 代码。如果 Native 代码中使用了 `clog`，那么 Java 代码间接地会触发对 `clog` 的调用。

   **Java 代码：**
   ```java
   public class MyMath {
       static {
           System.loadLibrary("mymath"); // 加载包含 native 方法的库
       }
       public native doubleComplex clogNative(double real, double imag);

       public static class doubleComplex {
           public double real;
           public double imag;
       }
   }
   ```

   **Native 代码 (mymath.c):**
   ```c++
   #include <jni.h>
   #include <complex.h>
   #include <math.h>

   extern "C" JNIEXPORT jobject JNICALL
   Java_com_example_myapp_MyMath_clogNative(JNIEnv *env, jclass clazz, jdouble real, jdouble imag) {
       double complex z = real + imag * I;
       double complex result = clog(z);

       jclass complexClass = env->FindClass("com/example/myapp/MyMath$doubleComplex");
       jmethodID constructor = env->GetMethodID(complexClass, "<init>", "()V");
       jfieldID realField = env->GetFieldID(complexClass, "real", "D");
       jfieldID imagField = env->GetFieldID(complexClass, "imag", "D");

       jobject complexObj = env->NewObject(complexClass, constructor);
       env->SetDoubleField(complexObj, realField, creal(result));
       env->SetDoubleField(complexObj, imagField, cimag(result));
       return complexObj;
   }
   ```

**Frida Hook 示例**

可以使用 Frida 来 Hook `clog` 函数，以便在运行时观察其输入和输出。

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    var clogPtr = Module.findExportByName("libm.so", "clog");
    if (clogPtr) {
        Interceptor.attach(clogPtr, {
            onEnter: function (args) {
                var real = args[0];
                var imag_ptr = ptr(args[0]).add(8); // 假设 double complex 的布局是先实部后虚部
                var imag = imag_ptr.readDouble();
                console.log("[clog] Input: z = " + real + " + " + imag + "i");
            },
            onLeave: function (retval) {
                var real = retval;
                var imag_ptr = ptr(retval).add(8);
                var imag = imag_ptr.readDouble();
                console.log("[clog] Output: clog(z) = " + real + " + " + imag + "i");
            }
        });
        console.log("Hooked clog at " + clogPtr);
    } else {
        console.log("clog not found in libm.so");
    }
} else {
    console.log("Frida hook for clog is specific to ARM architectures in this example.");
}
```

这个 Frida 脚本会找到 `libm.so` 中的 `clog` 函数，并拦截对其的调用。在 `onEnter` 中，它会读取输入复数的实部和虚部，并在 `onLeave` 中读取返回的复数对数的实部和虚部，并打印到控制台。

请注意，复数的内存布局可能因编译器和架构而异，因此在实际使用中可能需要调整读取虚部的方式。

希望以上详细的解释能够帮助你理解 `s_clog.c` 文件的功能、它在 Android 中的作用以及相关的技术细节。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_clog.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例作为调试线索。
用中文回复。
```

### 源代码
```c
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

#include "fpmath.h"
#include "math.h"
#include "math_private.h"

#define	MANT_DIG	DBL_MANT_DIG
#define	MAX_EXP		DBL_MAX_EXP
#define	MIN_EXP		DBL_MIN_EXP

static const double
ln2_hi = 6.9314718055829871e-1,		/*  0x162e42fefa0000.0p-53 */
ln2_lo = 1.6465949582897082e-12;	/*  0x1cf79abc9e3b3a.0p-92 */

double complex
clog(double complex z)
{
	double_t ax, ax2h, ax2l, axh, axl, ay, ay2h, ay2l, ayh, ayl, sh, sl, t;
	double x, y, v;
	uint32_t hax, hay;
	int kx, ky;

	x = creal(z);
	y = cimag(z);
	v = atan2(y, x);

	ax = fabs(x);
	ay = fabs(y);
	if (ax < ay) {
		t = ax;
		ax = ay;
		ay = t;
	}

	GET_HIGH_WORD(hax, ax);
	kx = (hax >> 20) - 1023;
	GET_HIGH_WORD(hay, ay);
	ky = (hay >> 20) - 1023;

	/* Handle NaNs and Infs using the general formula. */
	if (kx == MAX_EXP || ky == MAX_EXP)
		return (CMPLX(log(hypot(x, y)), v));

	/* Avoid spurious underflow, and reduce inaccuracies when ax is 1. */
	if (ax == 1) {
		if (ky < (MIN_EXP - 1) / 2)
			return (CMPLX((ay / 2) * ay, v));
		return (CMPLX(log1p(ay * ay) / 2, v));
	}

	/* Avoid underflow when ax is not small.  Also handle zero args. */
	if (kx - ky > MANT_DIG || ay == 0)
		return (CMPLX(log(ax), v));

	/* Avoid overflow. */
	if (kx >= MAX_EXP - 1)
		return (CMPLX(log(hypot(x * 0x1p-1022, y * 0x1p-1022)) +
		    (MAX_EXP - 2) * ln2_lo + (MAX_EXP - 2) * ln2_hi, v));
	if (kx >= (MAX_EXP - 1) / 2)
		return (CMPLX(log(hypot(x, y)), v));

	/* Reduce inaccuracies and avoid underflow when ax is denormal. */
	if (kx <= MIN_EXP - 2)
		return (CMPLX(log(hypot(x * 0x1p1023, y * 0x1p1023)) +
		    (MIN_EXP - 2) * ln2_lo + (MIN_EXP - 2) * ln2_hi, v));

	/* Avoid remaining underflows (when ax is small but not denormal). */
	if (ky < (MIN_EXP - 1) / 2 + MANT_DIG)
		return (CMPLX(log(hypot(x, y)), v));

	/* Calculate ax*ax and ay*ay exactly using Dekker's algorithm. */
	t = (double)(ax * (0x1p27 + 1));
	axh = (double)(ax - t) + t;
	axl = ax - axh;
	ax2h = ax * ax;
	ax2l = axh * axh - ax2h + 2 * axh * axl + axl * axl;
	t = (double)(ay * (0x1p27 + 1));
	ayh = (double)(ay - t) + t;
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
		return (CMPLX(log(ay2l + ax2l + sl + sh) / 2, v));
	sh -= 1;
	_2sum(sh, sl);
	_2sum(ax2l, ay2l);
	/* Briggs-Kahan algorithm (except we discard the final low term): */
	_2sum(sh, ax2l);
	_2sum(sl, ay2l);
	t = ax2l + sl;
	_2sumF(sh, t);
	return (CMPLX(log1p(ay2l + t + sh) / 2, v));
}

#if (LDBL_MANT_DIG == 53)
__weak_reference(clog, clogl);
#endif
```
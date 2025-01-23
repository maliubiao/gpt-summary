Response:
Let's break down the thought process to answer the user's request about the `complex.handroid` header file.

**1. Understanding the Core Request:**

The user provided a C header file and asked for a comprehensive analysis, covering functionality, relationship to Android, implementation details, dynamic linking aspects, common errors, and how to reach this code from higher levels (Android Framework/NDK). They also requested a Frida hook example. The key context is "bionic," Android's C library.

**2. Initial Scan and Purpose Identification:**

The first step is to quickly scan the header file. The `#ifndef _COMPLEX_H` and `#define _COMPLEX_H` guards immediately identify this as a header file intended to prevent multiple inclusions. The `#include <sys/cdefs.h>` and the copyright notice point to a standard C library component. The presence of many function declarations with `complex` in their names strongly suggests this file defines functions for complex number arithmetic.

**3. Functional Breakdown:**

Next, categorize the functions. The comments like "7.3.5 Trigonometric functions," "7.3.6 Hyperbolic functions," "7.3.7 Exponential and logarithmic functions," and "7.3.8 Power and absolute-value functions" provide a clear structure. Group the functions accordingly (trigonometric, hyperbolic, exponential/logarithmic, power/absolute value, and manipulation).

**4. Connecting to Android:**

The presence of `__BIONIC_AVAILABILITY_GUARD(version)` is a critical indicator of Android-specific functionality. This mechanism controls when these functions become available based on the Android API level. This immediately establishes the connection between the file and the Android operating system. Explain the purpose of these guards and how they relate to API level compatibility.

**5. Implementation Details (Challenges and Simplification):**

The request to "详细解释每一个libc函数的功能是如何实现的" is quite broad and would involve analyzing the *source code* of the actual implementations (likely in assembly or optimized C). Since only the header file is provided, a direct explanation of *how* each function is implemented is impossible. The strategy here is to explain the *general concept* of complex number operations and how the functions manipulate the real and imaginary parts. Avoid speculating on low-level implementation details without the actual source.

**6. Dynamic Linking and SO Layout:**

The request about dynamic linking is pertinent because these functions reside within `libc.so`. Focus on the *general* principles of dynamic linking in Android. Describe how shared libraries (`.so` files) are loaded, the role of the dynamic linker, and the concept of symbol resolution. A simplified `.so` layout is sufficient, highlighting the important sections like `.text`, `.data`, and `.dynsym`. The linking process involves finding the function symbols within the `.dynsym` table.

**7. Common Usage Errors:**

Think about how developers typically interact with complex numbers. Common errors include forgetting to include the header, using the wrong data types, misunderstanding the behavior of certain complex functions (e.g., the branch cut of `clog`), and potential performance issues if complex numbers are used unnecessarily in performance-critical code. Provide illustrative code examples.

**8. Tracing the Path from Android Framework/NDK:**

Start from the top: Android Framework Java code might use JNI to call native code. NDK developers directly write C/C++ code. Illustrate a possible call chain starting from Java (e.g., `android.media.effect`) or NDK math libraries, eventually leading to the complex number functions in `libc.so`.

**9. Frida Hook Example:**

A practical Frida hook example is essential. Choose a simple, representative function (like `cabs`). The hook should demonstrate how to intercept calls, log arguments, and potentially modify the return value. Keep the example concise and easy to understand.

**10. Structure and Language:**

Organize the answer logically using headings and bullet points for clarity. Use clear and concise Chinese. Ensure all parts of the original request are addressed. Be precise with terminology (e.g., "header file," "shared library," "dynamic linker").

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Should I try to guess the implementation details of the functions?
* **Correction:** No, the header file doesn't provide that information. Focus on the *purpose* of the functions and the general concepts of complex number arithmetic.

* **Initial thought:** Should I provide a very detailed explanation of the dynamic linking process?
* **Correction:**  Keep it concise and focus on the key concepts relevant to the use of `libc.so`. Avoid going into excessive detail about linker internals unless specifically asked.

* **Initial thought:** Should I provide Frida hooks for *all* the functions?
* **Correction:** No, one or two representative examples are sufficient to demonstrate the concept. Focus on clarity and conciseness.

By following these steps and incorporating self-correction, we can generate a comprehensive and accurate answer to the user's request.这是一个C语言头文件 `complex.handroid`，它定义了用于处理复数的数学函数。这个文件是 Android Bionic C 库的一部分，这意味着它提供的功能可以在 Android 系统上运行的应用程序中使用。

**功能列表:**

这个头文件主要声明了以下几类处理复数的函数：

1. **三角函数:**
   - `cacos`, `cacosf`, `cacosl`: 复数反余弦
   - `casin`, `casinf`, `casinl`: 复数反正弦
   - `catan`, `catanf`, `catanl`: 复数反正切
   - `ccos`, `ccosf`, `ccosl`: 复数余弦
   - `csin`, `csinf`, `csinl`: 复数正弦
   - `ctan`, `ctanf`, `ctanl`: 复数正切

2. **双曲函数:**
   - `cacosh`, `cacoshf`, `cacoshl`: 复数反双曲余弦
   - `casinh`, `casinhf`, `casinhl`: 复数反双曲正弦
   - `catanh`, `catanhf`, `catanhl`: 复数反双曲正切
   - `ccosh`, `ccoshf`, `ccoshl`: 复数双曲余弦
   - `csinh`, `csinhf`, `csinhl`: 复数双曲正弦
   - `ctanh`, `ctanhf`, `ctanhl`: 复数双曲正切

3. **指数和对数函数:**
   - `cexp`, `cexpf`, `cexpl`: 复数指数函数 (e 的 z 次方)
   - `clog`, `clogf`, `clogl`: 复数自然对数

4. **幂和绝对值函数:**
   - `cabs`, `cabsf`, `cabsl`: 复数的绝对值（模）
   - `cpow`, `cpowf`, `cpowl`: 复数的幂运算 (x 的 z 次方)
   - `csqrt`, `csqrtf`, `csqrtl`: 复数平方根

5. **操作函数:**
   - `carg`, `cargf`, `cargl`: 复数的辐角 (argument)
   - `cimag`, `cimagf`, `cimagl`: 复数的虚部
   - `conj`, `conjf`, `conjl`: 复数的共轭
   - `cproj`, `cprojf`, `cprojl`: 复数在黎曼球面上的投影
   - `creal`, `crealf`, `creall`: 复数的实部

**与 Android 功能的关系及举例说明:**

这些复数运算函数在 Android 的底层数学计算、信号处理、图形处理等领域都有应用。

* **音频/视频处理:** 例如，在音频编解码、滤波算法中，可能会使用复数来表示频率和相位信息。`cabs` 可以用于计算信号的幅度，`carg` 可以用于计算相位。
* **科学计算应用:** 许多科学计算应用需要在 Android 设备上运行，这些应用可能涉及到复数运算，例如求解物理模型、进行傅里叶变换等。
* **游戏开发:** 某些游戏可能在数学计算中使用复数，例如处理旋转、振荡等效果。
* **NDK 开发:** 使用 Android NDK 进行原生 C/C++ 开发的开发者可以直接使用这些函数进行复数运算。

**示例:**

假设一个 Android 应用需要计算一个复数 `z = 3 + 4i` 的模和辐角：

```c
#include <complex.h>
#include <stdio.h>

int main() {
  double complex z = 3.0 + 4.0 * I;
  double modulus = cabs(z);
  double argument = carg(z);

  printf("复数 z = %.1f + %.1fi\n", creal(z), cimag(z));
  printf("模 |z| = %.3f\n", modulus);
  printf("辐角 arg(z) = %.3f 弧度\n", argument);
  return 0;
}
```

**libc 函数的实现细节:**

这个头文件本身只包含函数的声明，具体的实现位于 Bionic C 库的其他源文件中（通常是 `.c` 或汇编文件）。这些函数的实现通常会利用底层的浮点数运算指令，并遵循 IEEE 754 标准关于复数运算的定义。由于这是标准 C 库的一部分，其实现会力求高效和精确。

例如，`cabs(double complex z)` 的实现大致思路是计算 `sqrt(creal(z) * creal(z) + cimag(z) * cimag(z))`，但为了避免溢出或下溢，实际实现可能会采用更复杂的算法，尤其是在实部和虚部大小差异很大的情况下。

**涉及 dynamic linker 的功能:**

这个头文件本身不直接涉及 dynamic linker 的功能，它只是定义了接口。但是，当一个 Android 应用程序使用这些复数函数时，dynamic linker (在 Android 上是 `linker64` 或 `linker`) 会负责在运行时将应用程序的代码与包含这些函数实现的共享库 (`libc.so`) 链接起来。

**so 布局样本:**

`libc.so` 是 Android 系统中非常核心的共享库，它包含了 C 标准库的各种函数实现。其布局大致如下：

```
libc.so:
    .text          # 可执行代码段，包含 cacos 等函数的机器码
    .rodata        # 只读数据段，包含常量字符串等
    .data          # 已初始化的可读写数据段，包含全局变量等
    .bss           # 未初始化的可读写数据段
    .dynamic       # 动态链接信息
    .dynsym        # 动态符号表，包含导出的符号 (如 cacos)
    .dynstr        # 动态字符串表，包含符号名称等字符串
    .plt           # Procedure Linkage Table，用于延迟绑定
    .got           # Global Offset Table，用于存储全局变量的地址
    ...           # 其他段
```

**链接的处理过程:**

1. **编译时:** 当编译器遇到对 `cacos` 等函数的调用时，它会在目标文件中记录下对这些符号的未解析引用。
2. **链接时:** 静态链接器 (在构建 APK 时) 并不会将 `libc.so` 的代码直接嵌入到应用程序的 APK 中，而是记录下需要链接的共享库。
3. **运行时:**
   - 当 Android 系统加载应用程序时，dynamic linker 会被激活。
   - Dynamic linker 会解析应用程序依赖的共享库列表，其中包括 `libc.so`。
   - Dynamic linker 会将 `libc.so` 加载到内存中。
   - Dynamic linker 会遍历应用程序的未解析符号引用，并在 `libc.so` 的 `.dynsym` 表中查找对应的符号 (例如 `cacos`)。
   - 找到符号后，dynamic linker 会更新应用程序的 GOT (Global Offset Table) 表，将 `cacos` 函数在 `libc.so` 中的实际地址填入 GOT 表中。
   - 当应用程序首次调用 `cacos` 函数时，会通过 PLT (Procedure Linkage Table) 跳转到 GOT 表中对应的地址，从而执行 `libc.so` 中 `cacos` 的实现。这个过程称为延迟绑定。

**逻辑推理、假设输入与输出:**

假设调用 `cabs(3.0 + 4.0 * I)`：

* **输入:** 一个 `double complex` 类型的值，实部为 3.0，虚部为 4.0。
* **逻辑推理:** `cabs` 函数会计算 `sqrt(3.0 * 3.0 + 4.0 * 4.0)`，即 `sqrt(9.0 + 16.0)`，即 `sqrt(25.0)`。
* **输出:** 返回一个 `double` 类型的值 5.0。

假设调用 `carg(-1.0 + 0.0 * I)`：

* **输入:** 一个 `double complex` 类型的值，实部为 -1.0，虚部为 0.0。
* **逻辑推理:** `carg` 函数会计算该复数的辐角。由于该复数位于复平面的负实轴上，其辐角为 π 或 -π。具体实现可能返回 π。
* **输出:** 返回一个 `double` 类型的值，近似为 3.14159。

**用户或编程常见的使用错误:**

1. **忘记包含头文件:** 如果使用了复数类型或函数，但忘记 `#include <complex.h>`，会导致编译错误。
2. **类型不匹配:**  使用了 `float complex` 类型的变量，却调用了接受 `double complex` 参数的函数，可能导致隐式类型转换，精度损失，或者编译错误（取决于编译器）。应该使用对应的 `f` 或 `l` 后缀的函数，例如 `cabsf` 处理 `float complex`。
3. **对辐角理解不清:**  `carg` 函数返回的辐角通常在 (-π, π] 区间内。不理解这个范围可能导致逻辑错误。
4. **对数函数的分支切割:** `clog` 函数的实现涉及到复对数的分支切割。不了解分支切割可能导致对于某些复数值得到意外的结果。
5. **性能问题:** 过度使用复数运算可能比实数运算更耗时。在不需要复数的情况下使用复数可能会影响性能。

**Android framework or ndk 如何一步步的到达这里:**

1. **Android Framework (Java 代码):**
   - Android Framework 的某些 Java 类可能需要进行复杂的数学运算。
   - 如果 Java 本身没有提供直接的复数运算支持（早期的 Android 版本就是如此），开发者可能需要自己实现，或者使用第三方库。
   - 在某些情况下，Framework 可能会通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++) 来执行这些复杂的运算。

2. **Android NDK (C/C++ 代码):**
   - NDK 开发者可以直接使用 Bionic 提供的 `complex.h` 中的复数函数。
   - 例如，一个使用 OpenGL ES 进行图形渲染的 NDK 应用，如果需要进行复数相关的数学变换，可以直接包含 `<complex.h>` 并调用相应的函数。
   - 又或者，一个音频处理的 NDK 库，可能会使用复数来进行傅里叶变换等操作。

**调用链示例 (假设 NDK 应用):**

```c++
// NDK 代码 (例如，在 .cpp 文件中)
#include <complex.h>
#include <stdio.h>

void process_complex_signal(double real_part, double imaginary_part) {
  double complex signal = real_part + imaginary_part * I;
  double magnitude = cabs(signal);
  printf("信号幅度: %f\n", magnitude);
}

// Java 代码 (通过 JNI 调用)
public class MyNativeLib {
    static {
        System.loadLibrary("mynativelib"); // 加载 NDK 库
    }
    public native void processSignal(double real, double imaginary);
}

// JNI 桥接代码 (在 NDK 库中)
#include <jni.h>
#include "mynativelib.h" // 假设有对应的头文件

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MyNativeLib_processSignal(JNIEnv *env, jobject thiz, jdouble real, jdouble imaginary) {
    process_complex_signal(real, imaginary); // 调用 NDK 的复数处理函数
}
```

在这个例子中：

1. Java 代码 `MyNativeLib.processSignal()` 被调用。
2. 该 Java 方法通过 JNI 调用了 Native 代码中的 `Java_com_example_myapp_MyNativeLib_processSignal` 函数。
3. Native 函数 `Java_com_example_myapp_MyNativeLib_processSignal` 又调用了 `process_complex_signal` 函数。
4. `process_complex_signal` 函数使用了 `complex.h` 中声明的 `cabs` 函数。
5. 当程序运行时，dynamic linker 会将 NDK 库 (`mynativelib.so`) 与 `libc.so` 链接，使得 `cabs` 函数的实现能够被调用。

**Frida Hook 示例:**

假设我们要 hook `cabs` 函数，查看其输入和输出：

```javascript
// Frida 脚本
if (Process.arch === "arm64" || Process.arch === "arm") {
    const libc = Module.findExportByName("libc.so", "cabs");
    if (libc) {
        Interceptor.attach(libc, {
            onEnter: function (args) {
                const realPart = Memory.readDouble(args[0]);
                const imaginaryPart = Memory.readDouble(args[0].add(8)); // 假设 double complex 结构体是连续存储的
                console.log(`[cabs] Entering, z = ${realPart} + ${imaginaryPart}i`);
            },
            onLeave: function (retval) {
                console.log(`[cabs] Leaving, returns = ${retval}`);
            }
        });
        console.log("Hooked cabs in libc.so");
    } else {
        console.error("Could not find cabs in libc.so");
    }
} else {
    console.log("Frida script for complex numbers is designed for ARM architectures.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_cabs.js`).
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <your_app_package_name> -l hook_cabs.js --no-pause
   ```
   或者，如果你的应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_cabs.js
   ```

**解释:**

- 这个 Frida 脚本首先检查进程的架构是否为 ARM。
- 然后，它尝试在 `libc.so` 中查找导出的 `cabs` 函数。
- 如果找到 `cabs`，它会使用 `Interceptor.attach` 来 hook 这个函数。
- `onEnter` 函数在 `cabs` 函数被调用时执行，它读取参数（复数的实部和虚部）并打印到控制台。
- `onLeave` 函数在 `cabs` 函数返回时执行，它读取返回值（模）并打印到控制台。

通过这个 Frida hook，你可以在应用程序运行时，实时观察 `cabs` 函数的输入和输出，从而帮助你调试和理解复数运算在 Android 系统中的使用。

请注意，这只是一个简单的示例。对于更复杂的复数函数，可能需要更仔细地处理参数和返回值，并考虑不同的数据类型 (`float complex`, `long double complex`)。 另外，实际的内存布局可能需要根据具体的架构和编译器进行调整。

### 提示词
```
这是目录为bionic/libc/include/complex.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*-
 * Copyright (c) 2001-2011 The FreeBSD Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _COMPLEX_H
#define	_COMPLEX_H

#include <sys/cdefs.h>

#ifdef __GNUC__
#define	_Complex_I	((float _Complex)1.0i)
#endif

#ifdef __generic
_Static_assert(__generic(_Complex_I, float _Complex, 1, 0),
    "_Complex_I must be of type float _Complex");
#endif

#define	complex		_Complex
#define	I		_Complex_I

#if __STDC_VERSION__ >= 201112L
#define	CMPLX(x, y)	((double complex){ x, y })
#define	CMPLXF(x, y)	((float complex){ x, y })
#define	CMPLXL(x, y)	((long double complex){ x, y })
#endif

__BEGIN_DECLS

/* 7.3.5 Trigonometric functions */
/* 7.3.5.1 The cacos functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex cacos(double complex __z) __INTRODUCED_IN(23);
float complex cacosf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex cacosl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.5.2 The casin functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex casin(double complex __z) __INTRODUCED_IN(23);
float complex casinf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex casinl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.5.1 The catan functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex catan(double complex __z) __INTRODUCED_IN(23);
float complex catanf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex catanl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.5.1 The ccos functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex ccos(double complex __z) __INTRODUCED_IN(23);
float complex ccosf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex ccosl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.5.1 The csin functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex csin(double complex __z) __INTRODUCED_IN(23);
float complex csinf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex csinl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.5.1 The ctan functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex ctan(double complex __z) __INTRODUCED_IN(23);
float complex ctanf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex ctanl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


/* 7.3.6 Hyperbolic functions */
/* 7.3.6.1 The cacosh functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex cacosh(double complex __z) __INTRODUCED_IN(23);
float complex cacoshf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex cacoshl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.6.2 The casinh functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex casinh(double complex __z) __INTRODUCED_IN(23);
float complex casinhf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex casinhl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.6.3 The catanh functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex catanh(double complex __z) __INTRODUCED_IN(23);
float complex catanhf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex catanhl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.6.4 The ccosh functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex ccosh(double complex __z) __INTRODUCED_IN(23);
float complex ccoshf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex ccoshl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.6.5 The csinh functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex csinh(double complex __z) __INTRODUCED_IN(23);
float complex csinhf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex csinhl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.6.6 The ctanh functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex ctanh(double complex __z) __INTRODUCED_IN(23);
float complex ctanhf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex ctanhl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


/* 7.3.7 Exponential and logarithmic functions */
/* 7.3.7.1 The cexp functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex cexp(double complex __z) __INTRODUCED_IN(23);
float complex cexpf(float complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(26)
long double complex cexpl(long double complex __z) __INTRODUCED_IN(26);
/* 7.3.7.2 The clog functions */
double complex clog(double complex __z) __INTRODUCED_IN(26);
float complex clogf(float complex __z) __INTRODUCED_IN(26);
long double complex clogl(long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


/* 7.3.8 Power and absolute-value functions */
/* 7.3.8.1 The cabs functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double cabs(double complex __z) __INTRODUCED_IN(23);
float cabsf(float complex __z) __INTRODUCED_IN(23);
long double cabsl(long double complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

/* 7.3.8.2 The cpow functions */

#if __BIONIC_AVAILABILITY_GUARD(26)
double complex cpow(double complex __x, double complex __z) __INTRODUCED_IN(26);
float complex cpowf(float complex __x, float complex __z) __INTRODUCED_IN(26);
long double complex cpowl(long double complex __x, long double complex __z) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

/* 7.3.8.3 The csqrt functions */

#if __BIONIC_AVAILABILITY_GUARD(23)
double complex csqrt(double complex __z) __INTRODUCED_IN(23);
float complex csqrtf(float complex __z) __INTRODUCED_IN(23);
long double complex csqrtl(long double complex __z) __INTRODUCED_IN(23);

/* 7.3.9 Manipulation functions */
/* 7.3.9.1 The carg functions */
double carg(double complex __z) __INTRODUCED_IN(23);
float cargf(float complex __z) __INTRODUCED_IN(23);
long double cargl(long double complex __z) __INTRODUCED_IN(23);
/* 7.3.9.2 The cimag functions */
double cimag(double complex __z) __INTRODUCED_IN(23);
float cimagf(float complex __z) __INTRODUCED_IN(23);
long double cimagl(long double complex __z) __INTRODUCED_IN(23);
/* 7.3.9.3 The conj functions */
double complex conj(double complex __z) __INTRODUCED_IN(23);
float complex conjf(float complex __z) __INTRODUCED_IN(23);
long double complex conjl(long double complex __z) __INTRODUCED_IN(23);
/* 7.3.9.4 The cproj functions */
double complex cproj(double complex __z) __INTRODUCED_IN(23);
float complex cprojf(float complex __z) __INTRODUCED_IN(23);
long double complex cprojl(long double complex __z) __INTRODUCED_IN(23);
/* 7.3.9.5 The creal functions */
double creal(double complex __z) __INTRODUCED_IN(23);
float crealf(float complex __z) __INTRODUCED_IN(23);
long double creall(long double complex __z) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


__END_DECLS

#endif
```
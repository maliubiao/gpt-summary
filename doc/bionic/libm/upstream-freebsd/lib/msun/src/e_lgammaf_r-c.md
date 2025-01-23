Response:
Let's break down the thought process for analyzing the `e_lgammaf_r.c` source code.

**1. Understanding the Goal:**

The request is to analyze the provided C code, focusing on its functionality, relationship to Android, implementation details, dynamic linking aspects, potential errors, and debugging techniques. The target audience is someone familiar with programming but potentially not intimately with the C standard library internals or Android's specifics.

**2. Initial Code Scan and Identification:**

First, quickly read through the code to get a general idea of what's happening. Key observations:

* **Function Name:** `lgammaf_r`. The `f` likely indicates a float version, and the `_r` often (but not always) signifies a re-entrant or thread-safe version (although this particular implementation doesn't seem explicitly re-entrant in the typical sense, as it doesn't take a state argument). The core part is `lgamma`, which strongly suggests the Log-Gamma function.
* **Copyright Notice:**  Indicates it originates from FreeBSD's `libm`. This is a crucial point for understanding its likely purpose.
* **Includes:** `math.h` and `math_private.h`. These point towards standard math functions and potentially internal math library definitions.
* **Static Constants:**  A large number of `static const float` variables. These are likely coefficients for polynomial approximations or special values related to the Gamma function.
* **`sin_pif` Function:** A local helper function to calculate `sin(pi * x)`. This is often needed when dealing with the Gamma function for negative arguments.
* **Core `lgammaf_r` Function Logic:** A series of `if-else if` conditions based on the magnitude and sign of the input `x`. This suggests different approximation methods are used for different ranges of input.
* **`GET_FLOAT_WORD` Macro:** Hints at direct manipulation of the floating-point number's bit representation. This is common in low-level math libraries for performance and precise handling of special values.
* **`signgamp` Output Parameter:** An integer pointer used to return the sign of the Gamma function. This is important because `lgamma` returns the logarithm of the absolute value.
* **Use of Standard Math Functions:**  Calls to `logf`, `fabsf`, `__kernel_sindf`, `__kernel_cosdf`. These are standard C math library functions or internal kernel versions.

**3. Functionality Deduction:**

Based on the function name, the copyright, and the use of coefficients, it's clear the primary function is to calculate the **natural logarithm of the absolute value of the Gamma function (lgamma)** for a single-precision floating-point number (`float`). The `signgamp` parameter indicates it also returns the sign of the Gamma function itself.

**4. Relationship to Android:**

The crucial point here is the file path: `bionic/libm/upstream-freebsd/...`. This directly states that this code is part of Android's `libm` (the math library) and originates from FreeBSD. Therefore, it's a fundamental building block for math operations within Android. Examples would involve any Android component performing scientific calculations, statistical analysis, or anything that relies on the Gamma function.

**5. Implementation Details (Deep Dive):**

This is where the detailed analysis of the code logic comes in.

* **Special Value Handling:** The code explicitly checks for and handles `NaN`, `+/-Infinity`, `+/-0`, and very small numbers.
* **Negative Argument Handling:** The `sin_pif` function and the logic involving `nadj` are used to handle negative inputs. The Gamma function for negative non-integer values involves trigonometric functions.
* **Range Reduction and Approximations:** The series of `if-else if` conditions partition the input domain into different ranges. For each range, a specific polynomial approximation or series expansion is used to calculate `lgammaf`. The constants are coefficients for these approximations. This is a standard technique in numerical computation to achieve accuracy and efficiency.
* **Specific Ranges and Approximations:**  Carefully examining the conditions (e.g., `ix<0x40000000`) and the corresponding calculations reveals the different approximation strategies used for arguments close to 0, 1, 2, between 2 and 8, and larger values. The comments in the code itself provide valuable clues about the approximation formulas used in each range. For instance, the comments mention formulas like  `lgamma(x) = lgamma(x+1)-log(x)` or expansions around specific points like `tc`.

**6. Dynamic Linker Aspects:**

Since this is part of `libm`, it's a shared library (`.so` file) on Android.

* **SO Layout:**  Describe a typical `.so` structure, including sections like `.text`, `.data`, `.rodata`, `.bss`, `.plt`, `.got`.
* **Linking Process:** Explain how the dynamic linker (`linker64` or `linker`) resolves symbols when an app uses `lgammaf`. Mention the PLT/GOT mechanism and how the linker finds the address of `lgammaf_r` in `libm.so`.

**7. Logical Reasoning and Assumptions:**

* **Input/Output Examples:** Create simple examples to illustrate the function's behavior for different inputs, including positive, negative, and special values. Focus on showcasing the `signgamp` output.

**8. Common Usage Errors:**

Think about how developers might misuse this function or make mistakes related to the Gamma function in general. Examples include:

* Forgetting to check `signgamp`.
* Passing invalid input (NaN, infinity) without proper handling.
* Misunderstanding the domain of the Gamma function (e.g., applying it to negative integers).

**9. Android Framework/NDK and Frida Hooking:**

* **Path from Framework/NDK:**  Explain how a high-level Android API call (potentially indirectly through a Java math function) can eventually lead to this native `lgammaf_r` function in `libm.so`. Mention the NDK as the bridge for native code.
* **Frida Hooking:** Provide a practical Frida script to intercept calls to `lgammaf_r`, log the input and output, and potentially modify the behavior for debugging purposes.

**10. Language and Structure:**

Organize the information logically with clear headings and explanations in Chinese, as requested. Use precise technical terms where appropriate but also provide explanations for potentially less familiar concepts. Ensure the tone is informative and helpful.

**Self-Correction/Refinement during the Process:**

* **Re-entrancy:** Initially, I might have assumed `_r` always means re-entrant. However, upon closer inspection, this specific implementation doesn't seem to have explicit re-entrancy mechanisms. It's important to be precise and not make assumptions based on naming conventions alone.
* **Approximation Details:** The exact mathematical derivations of the polynomial approximations are complex. Focus on the *fact* that different approximations are used in different ranges rather than trying to reproduce the derivations within the scope of this analysis.
* **SO Layout Details:** While a detailed explanation of every section is good, prioritize the `.plt` and `.got` for illustrating the dynamic linking process.

By following these steps, breaking down the code into manageable parts, and focusing on the specific requirements of the prompt, a comprehensive and accurate analysis of `e_lgammaf_r.c` can be generated.
好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_lgammaf_r.c` 这个源代码文件。

**功能概述**

`e_lgammaf_r.c` 文件实现了单精度浮点数版本的 `lgamma_r` 函数。`lgamma_r` 函数的功能是计算输入参数的伽玛函数的自然对数的绝对值，并返回伽玛函数的符号。

更具体地说：

* **计算 `ln(|Γ(x)|)`:**  它计算输入 `x` 的伽玛函数 `Γ(x)` 的自然对数的绝对值。
* **返回符号:** 它通过指针参数 `signgamp` 返回 `Γ(x)` 的符号 (+1 或 -1)。

**与 Android 功能的关系**

`e_lgammaf_r.c` 是 Android Bionic C 库（`libc.so`）的组成部分，位于其数学库 (`libm.so`) 中。这意味着任何在 Android 上运行的程序，无论是 Java 代码通过 Android Framework 调用，还是通过 NDK 编写的 C/C++ 代码，都可以间接地或直接地使用这个函数。

**举例说明:**

* **Android Framework:** Android Framework 中的某些高级数学或统计 API，例如在 `android.util.MathUtils` 或一些科学计算相关的库中，底层实现可能会调用到 `lgammaf` 或其双精度版本 `lgamma`。这些函数最终会链接到 `libm.so` 中的实现。
* **NDK 开发:** 如果一个使用 NDK 开发的 Android 应用需要进行涉及伽玛函数的计算（例如在统计学、概率论、物理学等领域的应用），开发者可以直接调用 `<math.h>` 中声明的 `lgammaf` 函数。链接器会将这个调用指向 `libm.so` 中 `e_lgammaf_r.c` 编译生成的代码。

**libc 函数功能实现详解**

`e_lgammaf_r.c` 的实现采用了分段逼近的方法，针对不同的输入 `x` 的范围，使用了不同的多项式或近似公式来计算 `lgammaf(x)`。

以下是对代码逻辑的详细解释：

1. **特殊值处理:**
   - **NaN 和无穷大:** 对于 `NaN` (Not a Number) 和无穷大，直接返回输入值本身，并将 `signgamp` 设置为 1。
   - **零和非常小的数:** 对于 `+/-0` 和非常小的正数（绝对值小于 `2**-27`），返回正无穷大 (`one/vzero`)，并根据输入的符号设置 `signgamp`。对于非常小的负数，返回 `-log(|x|)`。

2. **负数处理:**
   - 如果 `x` 是负数，首先使用 `sin_pif(x)` 函数计算 `sin(πx)`。伽玛函数对于负非整数有定义，其值与正数的伽玛函数有关，并通过 `sin(πx)` 连接。
   - 如果 `sin(πx)` 为零（表示 `x` 是负整数），则伽玛函数在这些点无定义，返回正无穷大。
   - 计算修正项 `nadj = logf(pi/fabsf(t*x))`，其中 `t` 是 `sin_pif(x)` 的值。
   - 根据 `t` 的符号设置 `signgamp`。
   - 将 `x` 取反，后续的计算基于正数 `x`。

3. **特定整数处理:**
   - 如果 `x` 为 1 或 2，`lgamma(x)` 为 0。

4. **小正数 (x < 2.0) 的处理:**
   - 代码根据 `x` 的不同小范围，使用不同的多项式逼近：
     - `0 < x <= 1 - 2**-5`: 使用围绕 1 的多项式展开。
     - `tc - 1 <= x <= tc + 0.28` (其中 `tc` 约等于 1.46): 使用围绕 `tc` 的多项式展开。
     - 其他小正数: 使用围绕 0 的多项式展开。
   - 这些多项式的系数 `a0` 到 `a5`，`t0` 到 `t7`，`u0` 到 `v3` 都是预先计算好的，以保证在对应范围内的精度。

5. **中等大小正数 (2.0 < x <= 8.0) 的处理:**
   - 将 `x` 分解为整数部分 `i` 和小数部分 `y`。
   - 使用多项式逼近计算 `lgamma(y+2)`，并根据 `i` 的值利用伽玛函数的递推关系 `Γ(x+1) = xΓ(x)` 来计算 `lgamma(x)`。

6. **较大正数 (8.0 < x < 2**27**) 的处理:**
   - 使用 Stirling 公式的对数形式进行逼近：`lgamma(x) ≈ (x - 0.5) * (log(x) - 1) + w(1/x)`，其中 `w(1/x)` 是一个关于 `1/x` 的多项式，用于提高精度。

7. **非常大的正数 (x >= 2**27**) 的处理:**
   - 对于非常大的 `x`，使用简化的 Stirling 公式：`lgamma(x) ≈ x * (log(x) - 1)`。

8. **最终结果:**
   - 如果原始输入 `x` 是负数，则根据之前计算的 `nadj` 和正数 `x` 的 `lgamma` 值计算最终结果。
   - 返回计算得到的 `lgammaf(x)` 的值，并通过 `signgamp` 指针返回伽玛函数的符号。

**涉及 dynamic linker 的功能**

`e_lgammaf_r.c` 编译生成的代码最终会被链接到 `libm.so` 动态链接库中。当一个应用程序（或其他动态库）需要调用 `lgammaf` 函数时，dynamic linker 负责找到 `libm.so` 并解析 `lgammaf` 的地址。

**so 布局样本:**

一个简化的 `libm.so` 的布局可能如下所示：

```
libm.so:
    .interp         // 指向 dynamic linker 的路径
    .note.android.ident
    .gnu.hash
    .dynsym         // 动态符号表
    .dynstr         // 动态字符串表
    .gnu.version
    .gnu.version_r
    .rela.dyn
    .rela.plt
    .plt            // 程序链接表 (Procedure Linkage Table)
        lgammaf@plt:  // lgammaf 的 PLT 条目
            ...
    .text           // 代码段
        e_lgammaf_r:  // e_lgammaf_r 函数的代码
            ...
        其他数学函数的代码
    .rodata         // 只读数据段
        常量数据 (例如 a0, a1, pi 等)
    .data           // 可读写数据段
    .bss            // 未初始化数据段
    ...
```

**链接的处理过程:**

1. **编译时:** 当应用程序或共享库的代码中调用了 `lgammaf` 函数时，编译器会在生成的目标文件中留下一个对 `lgammaf` 的未解析引用。
2. **链接时:** 链接器（对于 Android 来说，是 `ld` 或 `lld`）在创建可执行文件或共享库时，会将这些未解析的引用放入 `.plt` 和 `.got` (Global Offset Table)。
3. **运行时:**
   - 当程序首次执行到调用 `lgammaf` 的代码时，会跳转到 `.plt` 中对应的条目。
   - `.plt` 条目最初会跳转到 dynamic linker 中的一段代码。
   - Dynamic linker 会查看 `.got` 中 `lgammaf` 对应的条目，如果该条目尚未被解析（通常初始化为指向 `.plt` 中的下一条指令），dynamic linker 会：
     - 在 `libm.so` 的动态符号表 (`.dynsym`) 中查找 `lgammaf` 的定义。
     - 获取 `lgammaf` 在 `libm.so` 中的实际地址。
     - 将该地址写入 `.got` 中 `lgammaf` 对应的条目。
   - 接下来，`.plt` 条目会被修改，使得后续的调用会直接跳转到 `.got` 中存储的 `lgammaf` 的实际地址，从而避免了重复解析。

**假设输入与输出 (逻辑推理)**

假设我们调用 `lgammaf_r` 函数：

* **输入:** `x = 3.0f`, `signgamp` 指向一个 int 变量。
* **推理:**
    - `x` 是一个正整数，`Γ(3) = 2! = 2`。
    - `log(|Γ(3)|) = log(2) ≈ 0.69314718`。
    - `Γ(3)` 是正数，所以符号为 +1。
* **输出:** 函数返回值应该接近 `0.69314718`，`signgamp` 指向的变量的值应该为 `1`。

* **输入:** `x = -0.5f`, `signgamp` 指向一个 int 变量。
* **推理:**
    - `Γ(-0.5) = -2√π ≈ -3.5449077`。
    - `log(|Γ(-0.5)|) = log(3.5449077) ≈ 1.2655121`。
    - `Γ(-0.5)` 是负数，所以符号为 -1。
* **输出:** 函数返回值应该接近 `1.2655121`，`signgamp` 指向的变量的值应该为 `-1`。

**用户或编程常见的使用错误**

1. **未初始化 `signgamp`:**  用户必须提供一个有效的 `int` 变量的地址给 `signgamp`，否则可能导致程序崩溃或未定义行为。
   ```c
   float result = lgammaf_r(2.5f, NULL); // 错误：signgamp 为 NULL
   int sign;
   float result = lgammaf_r(2.5f, &sign); // 正确
   ```

2. **忽略 `signgamp` 的值:**  `lgammaf_r` 返回的是伽玛函数绝对值的对数。如果需要伽玛函数本身的符号，必须检查 `signgamp` 的值。
   ```c
   int sign;
   float log_gamma = lgammaf_r(-1.5f, &sign);
   if (sign > 0) {
       // 伽玛函数为正
   } else {
       // 伽玛函数为负
   }
   ```

3. **对负整数调用:** 伽玛函数在负整数处是无定义的。`e_lgammaf_r.c` 会返回正无穷大，但用户可能没有正确处理这种情况。
   ```c
   int sign;
   float log_gamma = lgammaf_r(-2.0f, &sign); // log_gamma 为正无穷大
   if (isinf(log_gamma)) {
       // 处理伽玛函数在负整数无定义的情况
   }
   ```

4. **精度问题:**  由于使用了浮点数和近似算法，计算结果可能存在一定的精度误差。用户需要理解浮点运算的局限性。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
   - 假设 Android Framework 中的某个组件需要计算伽玛函数，可能会使用 `java.lang.Math` 或其他相关的工具类。
   - `java.lang.Math` 中的一些方法（如 `log`, `exp`, `sin` 等）在底层会调用到 Android 系统的 native library，即 `libm.so`。
   - 对于更复杂的数学函数，可能会有专门的 native 实现，或者组合使用 `libm.so` 中的基本函数。
   - 如果 Framework 需要直接使用伽玛函数，可能需要通过 JNI (Java Native Interface) 调用 NDK 编写的 C/C++ 代码。

2. **NDK (C/C++ 代码):**
   - NDK 开发者可以直接包含 `<math.h>` 头文件。
   - 调用 `lgammaf(x)` 函数。
   - 编译时，链接器会将这个调用链接到 `libm.so` 中的 `e_lgammaf_r` 函数。

**Frida Hook 示例**

以下是一个使用 Frida Hook 拦截 `lgammaf_r` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const lgammaf_r_ptr = Module.findExportByName("libm.so", "lgammaf_r");

    if (lgammaf_r_ptr) {
        Interceptor.attach(lgammaf_r_ptr, {
            onEnter: function (args) {
                const x = args[0].readFloat();
                const signgampPtr = ptr(args[1]);
                console.log("[lgammaf_r] Entering with x =", x, ", signgampPtr =", signgampPtr);
            },
            onLeave: function (retval) {
                const result = retval.readFloat();
                const signgampPtr = this.context.sp.add(Process.pointerSize * 1); // 假设 signgamp 是第二个参数
                const signgamp = signgampPtr.readS32();
                console.log("[lgammaf_r] Leaving with result =", result, ", *signgamp =", signgamp);
            }
        });
        console.log("[Frida] lgammaf_r hooked!");
    } else {
        console.log("[Frida] lgammaf_r not found in libm.so");
    }
} else {
    console.log("[Frida] Hooking lgammaf_r is only supported on ARM/ARM64");
}
```

**代码解释:**

1. **检查架构:**  Hook 代码通常需要考虑不同的处理器架构。
2. **查找导出函数:** 使用 `Module.findExportByName` 在 `libm.so` 中查找 `lgammaf_r` 函数的地址。
3. **拦截器:** 使用 `Interceptor.attach` 拦截对 `lgammaf_r` 的调用。
4. **`onEnter`:** 在函数调用之前执行，打印输入参数 `x` 和 `signgamp` 的指针。
5. **`onLeave`:** 在函数返回之后执行，打印返回值和 `signgamp` 指向的值。  **注意:**  这里获取 `signgamp` 的值的方式可能需要根据实际的调用约定和栈布局进行调整。在 ARM64 上，参数通常通过寄存器传递，但在栈上也会有备份。
6. **打印消息:**  指示 Hook 是否成功。

这个 Frida 脚本可以帮助开发者在运行时观察 `lgammaf_r` 的行为，例如查看传递的参数和返回的结果，从而进行调试或逆向分析。

希望以上详细的解释能够帮助你理解 `e_lgammaf_r.c` 的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_lgammaf_r.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/* e_lgammaf_r.c -- float version of e_lgamma_r.c.
 * Conversion to float by Ian Lance Taylor, Cygnus Support, ian@cygnus.com.
 * Conversion to float fixed By Steven G. Kargl.
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

#include "math.h"
#include "math_private.h"

static const volatile float vzero = 0;

static const float
zero=  0,
half=  0.5,
one =  1,
pi  =  3.1415927410e+00, /* 0x40490fdb */
/*
 * Domain y in [0x1p-27, 0.27], range ~[-3.4599e-10, 3.4590e-10]:
 * |(lgamma(2 - y) + 0.5 * y) / y - a(y)| < 2**-31.4
 */
a0  =  7.72156641e-02, /* 0x3d9e233f */
a1  =  3.22467119e-01, /* 0x3ea51a69 */
a2  =  6.73484802e-02, /* 0x3d89ee00 */
a3  =  2.06395667e-02, /* 0x3ca9144f */
a4  =  6.98275631e-03, /* 0x3be4cf9b */
a5  =  4.11768444e-03, /* 0x3b86eda4 */
/*
 * Domain x in [tc-0.24, tc+0.28], range ~[-5.6577e-10, 5.5677e-10]:
 * |(lgamma(x) - tf) - t(x - tc)| < 2**-30.8.
 */
tc  =  1.46163213e+00, /* 0x3fbb16c3 */
tf  = -1.21486291e-01, /* 0xbdf8cdce */
t0  = -2.94064460e-11, /* 0xae0154b7 */
t1  = -2.35939837e-08, /* 0xb2caabb8 */
t2  =  4.83836412e-01, /* 0x3ef7b968 */
t3  = -1.47586212e-01, /* 0xbe1720d7 */
t4  =  6.46013096e-02, /* 0x3d844db1 */
t5  = -3.28450352e-02, /* 0xbd068884 */
t6  =  1.86483748e-02, /* 0x3c98c47a */
t7  = -9.89206228e-03, /* 0xbc221251 */
/*
 * Domain y in [-0.1, 0.232], range ~[-8.4931e-10, 8.7794e-10]:
 * |(lgamma(1 + y) + 0.5 * y) / y - u(y) / v(y)| < 2**-31.2
 */
u0  = -7.72156641e-02, /* 0xbd9e233f */
u1  =  7.36789703e-01, /* 0x3f3c9e40 */
u2  =  4.95649040e-01, /* 0x3efdc5b6 */
v1  =  1.10958421e+00, /* 0x3f8e06db */
v2  =  2.10598111e-01, /* 0x3e57a708 */
v3  = -1.02995494e-02, /* 0xbc28bf71 */
/*
 * Domain x in (2, 3], range ~[-5.5189e-11, 5.2317e-11]:
 * |(lgamma(y+2) - 0.5 * y) / y - s(y)/r(y)| < 2**-35.0
 * with y = x - 2.
 */
s0 = -7.72156641e-02, /* 0xbd9e233f */
s1 =  2.69987404e-01, /* 0x3e8a3bca */
s2 =  1.42851010e-01, /* 0x3e124789 */
s3 =  1.19389519e-02, /* 0x3c439b98 */
r1 =  6.79650068e-01, /* 0x3f2dfd8c */
r2 =  1.16058730e-01, /* 0x3dedb033 */
r3 =  3.75673687e-03, /* 0x3b763396 */
/*
 * Domain z in [8, 0x1p24], range ~[-1.2640e-09, 1.2640e-09]:
 * |lgamma(x) - (x - 0.5) * (log(x) - 1) - w(1/x)| < 2**-29.6.
 */
w0 =  4.18938547e-01, /* 0x3ed67f1d */
w1 =  8.33332464e-02, /* 0x3daaaa9f */
w2 = -2.76129087e-03; /* 0xbb34f6c6 */

static float
sin_pif(float x)
{
	volatile float vz;
	float y,z;
	int n;

	y = -x;

	vz = y+0x1p23F;			/* depend on 0 <= y < 0x1p23 */
	z = vz-0x1p23F;			/* rintf(y) for the above range */
	if (z == y)
	    return zero;

	vz = y+0x1p21F;
	GET_FLOAT_WORD(n,vz);		/* bits for rounded y (units 0.25) */
	z = vz-0x1p21F;			/* y rounded to a multiple of 0.25 */
	if (z > y) {
	    z -= 0.25F;			/* adjust to round down */
	    n--;
	}
	n &= 7;				/* octant of y mod 2 */
	y = y - z + n * 0.25F;		/* y mod 2 */

	switch (n) {
	    case 0:   y =  __kernel_sindf(pi*y); break;
	    case 1:
	    case 2:   y =  __kernel_cosdf(pi*((float)0.5-y)); break;
	    case 3:
	    case 4:   y =  __kernel_sindf(pi*(one-y)); break;
	    case 5:
	    case 6:   y = -__kernel_cosdf(pi*(y-(float)1.5)); break;
	    default:  y =  __kernel_sindf(pi*(y-(float)2.0)); break;
	    }
	return -y;
}


float
lgammaf_r(float x, int *signgamp)
{
	float nadj,p,p1,p2,q,r,t,w,y,z;
	int32_t hx;
	int i,ix;

	GET_FLOAT_WORD(hx,x);

    /* purge +-Inf and NaNs */
	*signgamp = 1;
	ix = hx&0x7fffffff;
	if(ix>=0x7f800000) return x*x;

    /* purge +-0 and tiny arguments */
	*signgamp = 1-2*((uint32_t)hx>>31);
	if(ix<0x32000000) {		/* |x|<2**-27, return -log(|x|) */
	    if(ix==0)
	        return one/vzero;
	    return -logf(fabsf(x));
	}

    /* purge negative integers and start evaluation for other x < 0 */
	if(hx<0) {
	    *signgamp = 1;
	    if(ix>=0x4b000000) 		/* |x|>=2**23, must be -integer */
		return one/vzero;
	    t = sin_pif(x);
	    if(t==zero) return one/vzero; /* -integer */
	    nadj = logf(pi/fabsf(t*x));
	    if(t<zero) *signgamp = -1;
	    x = -x;
	}

    /* purge 1 and 2 */
	if (ix==0x3f800000||ix==0x40000000) r = 0;
    /* for x < 2.0 */
	else if(ix<0x40000000) {
	    if(ix<=0x3f666666) { 	/* lgamma(x) = lgamma(x+1)-log(x) */
		r = -logf(x);
		if(ix>=0x3f3b4a20) {y = one-x; i= 0;}
		else if(ix>=0x3e6d3308) {y= x-(tc-one); i=1;}
	  	else {y = x; i=2;}
	    } else {
	  	r = zero;
	        if(ix>=0x3fdda618) {y=2-x;i=0;} /* [1.7316,2] */
	        else if(ix>=0x3F9da620) {y=x-tc;i=1;} /* [1.23,1.73] */
		else {y=x-one;i=2;}
	    }
	    switch(i) {
	      case 0:
		z = y*y;
		p1 = a0+z*(a2+z*a4);
		p2 = z*(a1+z*(a3+z*a5));
		p  = y*p1+p2;
		r  += p-y/2; break;
	      case 1:
		p = t0+y*t1+y*y*(t2+y*(t3+y*(t4+y*(t5+y*(t6+y*t7)))));
		r += tf + p; break;
	      case 2:
		p1 = y*(u0+y*(u1+y*u2));
		p2 = one+y*(v1+y*(v2+y*v3));
		r += p1/p2-y/2;
	    }
	}
    /* x < 8.0 */
	else if(ix<0x41000000) {
	    i = x;
	    y = x-i;
	    p = y*(s0+y*(s1+y*(s2+y*s3)));
	    q = one+y*(r1+y*(r2+y*r3));
	    r = y/2+p/q;
	    z = one;	/* lgamma(1+s) = log(s) + lgamma(s) */
	    switch(i) {
	    case 7: z *= (y+6);		/* FALLTHRU */
	    case 6: z *= (y+5);		/* FALLTHRU */
	    case 5: z *= (y+4);		/* FALLTHRU */
	    case 4: z *= (y+3);		/* FALLTHRU */
	    case 3: z *= (y+2);		/* FALLTHRU */
		    r += logf(z); break;
	    }
    /* 8.0 <= x < 2**27 */
	} else if (ix < 0x4d000000) {
	    t = logf(x);
	    z = one/x;
	    y = z*z;
	    w = w0+z*(w1+y*w2);
	    r = (x-half)*(t-one)+w;
	} else
    /* 2**27 <= x <= inf */
	    r =  x*(logf(x)-one);
	if(hx<0) r = nadj - r;
	return r;
}
```
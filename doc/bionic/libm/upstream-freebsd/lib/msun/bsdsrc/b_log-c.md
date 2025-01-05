Response:
Let's break down the thought process for answering the request about `b_log.c`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C code for a logarithm function and relate it to Android's Bionic library. This involves identifying functionalities, explaining implementation details, considering dynamic linking, anticipating errors, and describing its role in the Android ecosystem.

**2. Initial Code Scan and Key Observations:**

* **Copyright and Origin:** The code originates from FreeBSD, suggesting a porting effort to Bionic. This is important context.
* **Function Name:** The filename `b_log.c` strongly indicates it implements the natural logarithm function (`log`). The internal function `__log__D` with `struct Double` return suggests a high-precision calculation.
* **Table-Driven Approach:** The comments explicitly mention a "Table-driven natural logarithm" and cite Peter Tang's paper. This immediately points to the core algorithm.
* **Argument Reduction:** Comments about `2^m*F*(1+f/F)` and `frexp` indicate a standard technique for simplifying logarithm calculations.
* **Polynomial Approximation:** The presence of constants `A1`, `A2`, `A3` suggests a Taylor series or similar approximation for `log(1+x)`.
* **Lookup Tables:** `logF_head` and `logF_tail` are clearly lookup tables for logarithms of specific values.
* **Special Cases:** The code notes handling of 0, negative numbers, and infinity, which are crucial for a robust math function.

**3. Deconstructing the Functionality:**

Based on the initial scan, I'd start listing the functions:

* **`__log__D(double x)`:**  This is the core function. Its "D" suffix likely indicates a higher precision implementation (perhaps returning a double-double). I'd analyze its steps in detail.
* **Implicit `log(double x)`:** Although not explicitly present in the provided snippet, a standard `log` function (likely calling `__log__D`) must exist in the larger library. It would handle initial error checks and call the core implementation.

**4. Explaining the Implementation (`__log__D`):**

I would go through the code line by line, focusing on:

* **Argument Reduction:** Explain how `frexp` extracts the exponent (`m`) and mantissa (`g`), and why this is done (to work with a smaller range). Explain the handling of subnormal numbers.
* **Table Lookup:** Detail how `j` is calculated to index into the `logF_head` and `logF_tail` tables. Explain the purpose of these tables (pre-computed logarithms of values close to 1).
* **Polynomial Approximation:** Explain the formula for `log(1 + f/F)` and the role of the `A` coefficients. Mention the Taylor series connection.
* **Combining Terms:** Explain how the logarithms of the parts (`2^m`, `F`, `1+f/F`) are combined to get the final result.
* **Precision Handling:**  Note the separate calculation of `u1` and `u2` for higher precision. Explain the special handling when `m` and `j` are zero (small input values).

**5. Connecting to Android/Bionic:**

* **Fundamental Math Library:** Emphasize that `log` is a basic mathematical function essential for many applications.
* **NDK Usage:** Explain how NDK developers directly use `log` from `<cmath>`.
* **Framework Usage:**  Consider examples of where logarithms might be used in the Android Framework (e.g., audio processing, signal analysis, certain UI animations, and potentially within the VM).
* **Bionic as the Implementation:**  Clarify that this code *is* the implementation within Bionic.

**6. Dynamic Linking:**

* **Shared Object:** Identify `libm.so` as the relevant shared object containing math functions.
* **SO Layout:**  Describe the typical layout (code, data, GOT, PLT).
* **Linking Process:** Explain how the dynamic linker resolves the `log` symbol at runtime using the GOT and PLT. A simplified explanation focusing on the lookup is sufficient.

**7. Common Errors:**

Focus on typical issues users might encounter:

* **Invalid Input:**  Explain what happens when `log` is called with negative numbers or zero.
* **Overflow/Underflow:** Discuss potential issues with very large or very small inputs.
* **Precision:**  Mention that floating-point arithmetic has inherent limitations.

**8. Frida Hooking:**

* **Basic Hook:** Show a simple example of hooking the `log` function to intercept calls and print arguments/return values.
* **Advanced Hooks:**  Suggest possibilities like modifying arguments or return values for testing.

**9. Structure and Language:**

* **Use Clear Headings:** Organize the information logically.
* **Explain Technical Terms:** Define terms like "argument reduction," "mantissa," "exponent," "dynamic linker," "GOT," "PLT."
* **Provide Examples:**  Use concrete examples to illustrate concepts.
* **Maintain Accuracy:** Ensure the technical details are correct.
* **Use Chinese:**  Answer in the requested language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe just explain the general idea of logarithms. **Correction:** The request asks for detailed implementation analysis, so focus on the code.
* **Initial thought:**  Provide the entire dynamic linking process in extreme detail. **Correction:** The request doesn't require a deep dive into every aspect of the dynamic linker. Focus on the essentials of symbol resolution.
* **Initial thought:**  Assume the reader is an expert in numerical methods. **Correction:** Explain concepts clearly and avoid overly complex jargon. Provide context and background.

By following these steps and constantly refining the approach, the comprehensive answer addressing all aspects of the request can be constructed.
好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/bsdsrc/b_log.c` 这个文件。

**文件功能总览**

`b_log.c` 文件是 Android Bionic C 库中数学库 (`libm`) 的一部分，它实现了自然对数函数 `log(double x)`。更具体地说，它提供了一个高精度的内部实现 `__log__D(double x)`，并被更高层次的 `log` 函数调用。

**主要功能分解**

1. **计算自然对数:** 该文件核心功能是计算给定双精度浮点数 `x` 的自然对数 (以 *e* 为底的对数)。

2. **高精度实现:** 提供了 `__log__D` 函数，它使用一种结合查表和多项式逼近的方法来计算高精度的对数结果。它返回一个 `struct Double`，包含两个 `double` 值 `a` 和 `b`，它们的和可以提供比标准 `double` 更高的精度。

3. **参数规约 (Argument Reduction):**  为了简化计算，代码首先将输入 `x` 规约到一个更小的范围内。它利用了对数的性质 `log(a * b) = log(a) + log(b)` 和浮点数的表示形式。具体来说，它将 `x` 表示为 `2^m * F * (1 + f/F)`，其中：
   - `m` 是整数，使得 `x / 2^m` 在 [1, 2) 范围内。
   - `F` 的形式是 `j/128 + 1`，其中 `j` 是 0 到 128 之间的整数。
   - `f` 是一个小的余项，使得 `|f/F| <= 1/256`。

4. **查表法 (Table Lookup):**  代码使用了两个静态表 `logF_head` 和 `logF_tail` 来存储预先计算好的 `log(F)` 的高精度值。`logF_head[j]` 存储主要部分，`logF_tail[j]` 存储尾部的小数部分，以提高精度。

5. **多项式逼近 (Polynomial Approximation):** 对于 `log(1 + f/F)` 部分，代码使用了一个三次多项式进行逼近。多项式的系数 `A1`, `A2`, `A3` 是预先计算好的。

6. **特殊情况处理:** 代码考虑了输入 `x` 的特殊情况：
   - 如果 `x` 为 0，返回负无穷大 (`-Inf`) 并触发信号。
   - 如果 `x` 为负数，返回 NaN (非数字) 并触发信号。
   - 如果 `x` 为正无穷大 (`+Inf`)，返回正无穷大。

**与 Android 功能的关系举例**

`log` 函数是基础数学运算，在 Android 的各种组件和应用中都有广泛应用：

* **NDK 开发:** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的一部分。NDK 应用可以直接调用 `libm.so` 中的 `log` 函数进行数学计算。例如，在游戏开发、图形渲染、音频处理等高性能计算场景中，经常需要使用对数运算。

   ```c++
   // NDK 代码示例
   #include <cmath>
   #include <android/log.h>

   void calculate_log(double value) {
       double result = std::log(value);
       __android_log_print(ANDROID_LOG_INFO, "MyApp", "log(%f) = %f", value, result);
   }
   ```

* **Framework 层:**  Android Framework 的某些部分也可能间接或直接使用 `log` 函数。例如，在处理音频信号的振幅、计算传感器数据的某些指标、或者在图形处理中进行对数变换时。虽然 Framework 通常使用 Java API，但底层的实现可能依赖于 Native 代码。

* **虚拟机 (Dalvik/ART):**  Java 中的 `java.lang.Math.log()` 方法最终会调用底层的 Native 实现，即 `libm.so` 中的 `log` 函数。

**libc 函数的功能实现详解**

这里主要涉及的是 `log` 函数的实现，更具体地说是 `__log__D` 的实现：

1. **参数规约 (frexp, ilogb):**
   - `frexp(x, &m)`: 将浮点数 `x` 分解为规格化的分数 (`0.5 <= significand < 1.0`) 和 2 的幂指数 `m`，使得 `x = significand * 2^m`。这步是为了将 `x` 的范围规约到 [1, 2)。
   - `ilogb(g)`: 提取浮点数 `g` 的指数部分（以 2 为底）。在处理非常小的数（subnormal numbers）时，需要调整指数 `m`。

2. **计算索引和 F 的值:**
   - `j = N * (g - 1) + 0.5;`: 根据规约后的值 `g` 计算一个整数索引 `j`，用于在 `logF_head` 和 `logF_tail` 表中查找对应的预计算对数值。`N` 被定义为 128。
   - `F = (1. / N) * j + 1;`: 计算 `F` 的值，它近似于 `g` 的一部分。

3. **计算余项 f:**
   - `f = g - F;`: 计算 `g` 和 `F` 之间的差值 `f`，这是一个很小的数。

4. **多项式逼近 log(1 + f/F):**
   - `g = 1 / (2 * F + f);`: 计算中间变量 `g`。
   - `u = 2 * f * g;`: 计算多项式逼近的主要项。
   - `v = u * u;`: 计算 `u` 的平方。
   - `q = u * v * (A1 + v * (A2 + v * A3));`: 使用预先计算的系数 `A1`, `A2`, `A3` 计算多项式逼近的结果 `q`，它近似于 `log(1 + f/F)`。

5. **组合各项计算高精度对数:**
   - `u1 = ...; u2 = ...;`:  分别计算对数结果的主要部分 (`u1`) 和尾部部分 (`u2`)。这里考虑了精度问题，对不同的情况使用了不同的计算方式。当 `m` 和 `j` 都为 0 时，使用相对精度更高的计算方式。
   - `u1 += m * logF_head[N] + logF_head[j];`: 将指数部分的对数 (`m * log(2)`) 和 `log(F)` 的主要部分加到 `u1` 中。注意 `logF_head[N]` 实际上存储的是 `log(2)` 的近似值。
   - `u2 += logF_tail[j]; u2 += q; u2 += logF_tail[N] * m;`: 将 `log(F)` 的尾部部分、多项式逼近的结果和指数部分对数的尾部部分加到 `u2` 中。

6. **返回高精度结果:**
   - `r.a = (float)(u1 + u2);`: 将 `u1 + u2` 强制转换为 `float`，这会导致舍入，得到一个精度较低的值。
   - `r.b = (u1 - r.a) + u2;`:  计算 `u1` 的舍入误差，并将其与 `u2` 相加，得到一个补偿值。这样，`r.a + r.b` 可以提供更高精度的对数结果。

**涉及 dynamic linker 的功能及处理**

`b_log.c` 本身的代码不直接涉及 dynamic linker 的操作。但是，作为 `libm.so` 的一部分，它的函数需要在运行时被动态链接器加载和链接。

**so 布局样本 (libm.so)**

```
libm.so:
    .text          # 存放代码段，包括 log 函数的机器码
        ...
        <log 函数的指令>
        <__log__D 函数的指令>
        ...
    .rodata        # 存放只读数据，例如 logF_head, logF_tail, A1, A2, A3 等常量
        logF_head: ...
        logF_tail: ...
        A1: ...
        A2: ...
        A3: ...
    .data          # 存放已初始化的全局变量和静态变量
        ...
    .bss           # 存放未初始化的全局变量和静态变量
        ...
    .dynsym        # 动态符号表，包含导出的符号信息，例如 log
        log (function, global)
        ...
    .dynstr        # 动态字符串表，存储符号名称的字符串
        "log"
        ...
    .rel.plt       # PLT 重定位表，用于延迟绑定
    .rel.dyn       # 数据段重定位表
    .got.plt       # 全局偏移量表 (PLT 部分)
    .got           # 全局偏移量表 (其他数据)
```

**链接的处理过程**

1. **编译时:** 当一个程序（例如 NDK 应用）调用 `std::log` 时，编译器会在其生成的目标文件中记录一个对 `log` 符号的未定义引用。

2. **链接时:** 链接器将不同的目标文件和库文件组合成最终的可执行文件或共享库。对于动态链接，链接器不会将 `log` 函数的代码直接链接到程序中，而是在可执行文件中创建一个 PLT (Procedure Linkage Table) 条目，并在 GOT (Global Offset Table) 中预留一个条目。

3. **运行时加载:** 当 Android 系统加载程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，例如 `libm.so`。

4. **符号解析 (Lazy Binding):** 默认情况下，动态链接是延迟绑定的。当程序第一次调用 `log` 函数时：
   - 程序跳转到 PLT 中 `log` 对应的条目。
   - PLT 条目中的指令会将控制权交给 dynamic linker。
   - dynamic linker 查找 `libm.so` 的 `.dynsym` 表，找到 `log` 符号的地址。
   - dynamic linker 将 `log` 函数的实际地址写入 GOT 中 `log` 对应的条目。
   - dynamic linker 将控制权返回给程序，程序再次执行 PLT 条目时，会直接跳转到 GOT 中存储的 `log` 函数的地址。

**逻辑推理的假设输入与输出**

假设输入 `x = 2.0`：

- **参数规约:** `frexp(2.0, &m)` 会得到 `significand = 0.5`，`m = 2`。由于代码中 `g = frexp(x, &m) * 2; m--;`，所以 `g = 1.0`, `m = 1`。
- **计算索引:** `j = 128 * (1.0 - 1) + 0.5 = 0.5`，取整后 `j = 0`。
- **计算 F:** `F = (1. / 128) * 0 + 1 = 1.0`。
- **计算 f:** `f = 1.0 - 1.0 = 0.0`。
- **多项式逼近:** 由于 `f` 为 0，多项式逼近的结果 `q` 也为 0。
- **组合计算:**
    - `u1` 会包含 `1 * logF_head[128]` (近似 `log(2)`) 和 `logF_head[0]` (为 0)。
    - `u2` 会包含 `logF_tail[0]` (为 0)，`q` (为 0) 和 `logF_tail[128] * 1` (很小的数，是 `log(2)` 的尾部精度补偿)。
- **输出:** `__log__D` 返回的 `r.a + r.b` 应该非常接近 `log(2.0)`，即约等于 0.6931471805599453。

**用户或编程常见的使用错误**

1. **对负数或零取对数:**
   ```c++
   #include <cmath>
   #include <iostream>

   int main() {
       double negative_val = -1.0;
       double zero_val = 0.0;
       double log_neg = std::log(negative_val); // 结果为 NaN
       double log_zero = std::log(zero_val);    // 结果为 -Infinity

       std::cout << "log(-1.0) = " << log_neg << std::endl;
       std::cout << "log(0.0) = " << log_zero << std::endl;
       return 0;
   }
   ```
   **说明:**  数学上，负数和零没有实数域的自然对数。`std::log` 会返回 NaN 或负无穷大，但初学者可能忘记处理这些特殊情况。

2. **期望过高的精度:** 虽然 `__log__D` 提供了高精度实现，但最终用户通常使用标准的 `double log(double x)` 函数，其精度受到 `double` 类型的限制。期望浮点数运算具有无限精度是不现实的。

3. **未包含头文件:** 使用 `std::log` 前需要包含 `<cmath>` 头文件。

**Android Framework 或 NDK 如何到达这里**

**Android Framework:**

1. **Java 代码调用:** Framework 层的一些 Java 代码可能需要计算对数，例如 `android.media.audiofx` 中的音频处理，或者 `android.graphics` 中的某些变换。

2. **调用 Native 方法:** Java 代码会通过 JNI (Java Native Interface) 调用 Framework 层的 Native 代码（通常是 C++）。

3. **Framework Native 代码调用 libm:** Framework 的 Native 代码可能会直接或间接地调用 `libm.so` 中的 `log` 函数。例如，某些算法的实现可能依赖于标准的数学函数。

**NDK:**

1. **NDK 应用代码:** NDK 开发者在 C/C++ 代码中使用 `<cmath>` 头文件中的 `std::log` 函数。

2. **编译链接:** NDK 构建系统会将代码编译成机器码，并在链接阶段链接到必要的系统库，包括 `libm.so`.

3. **运行时加载:** 当 Android 系统启动 NDK 应用时，dynamic linker 会加载 `libm.so`，并将 NDK 应用中对 `log` 的调用链接到 `libm.so` 中对应的实现。

**Frida Hook 示例调试步骤**

假设我们要 Hook `log` 函数来查看其输入和输出：

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在你的 PC 上安装了 Frida 客户端。

2. **编写 Frida 脚本 (log_hook.js):**

   ```javascript
   console.log("Script loaded successfully!");

   if (Process.arch === 'arm64') {
       var logPtr = Module.findExportByName("libm.so", "log");
   } else if (Process.arch === 'arm') {
       var logPtr = Module.findExportByName("libm.so", "logf"); // 可能是 logf 对于 float
   } else {
       console.error("Unsupported architecture:", Process.arch);
   }

   if (logPtr) {
       Interceptor.attach(logPtr, {
           onEnter: function (args) {
               console.log("\nCalled log with argument:", args[0].toDouble());
           },
           onLeave: function (retval) {
               console.log("log returned:", retval.toDouble());
           }
       });
   } else {
       console.error("Could not find log function in libm.so");
   }
   ```

3. **运行 Frida 脚本:**

   ```bash
   frida -U -f <your_app_package_name> -l log_hook.js
   ```
   或者，如果你的应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l log_hook.js
   ```

4. **触发 `log` 函数调用:** 在你的 Android 应用中执行某些操作，这些操作会间接地或直接地调用 `log` 函数。例如，如果你的应用有计算对数的功能，或者使用了某些依赖对数的算法。

5. **查看 Frida 输出:** 在你的终端上，Frida 会打印出 `log` 函数被调用时的参数和返回值。

**更精细的 Hook (Hook `__log__D`):**

由于 `__log__D` 是内部实现，Hook 它的方式类似，但需要注意其参数和返回值结构：

```javascript
console.log("Script loaded successfully!");

if (Process.arch === 'arm64') {
    var logDPtr = Module.findExportByName("libm.so", "__log__D");
} else if (Process.arch === 'arm') {
    // 查找对应 ARM 架构的符号，可能名称不同
    var logDPtr = null; // 需要根据具体情况确定
    console.warn("__log__D hooking on ARM might require different symbol name.");
} else {
    console.error("Unsupported architecture:", Process.arch);
}

if (logDPtr) {
    Interceptor.attach(logDPtr, {
        onEnter: function (args) {
            console.log("\nCalled __log__D with argument:", args[0].toDouble());
        },
        onLeave: function (retval) {
            // __log__D 返回一个结构体，需要读取其成员
            console.log("__log__D returned: a =", retval.a.toDouble(), ", b =", retval.b.toDouble());
        }
    });
} else {
    console.error("Could not find __log__D function in libm.so");
}
```

**总结**

`b_log.c` 文件是 Android Bionic 库中实现自然对数功能的核心部分，它采用了高效的查表法和多项式逼近相结合的方法，并考虑了高精度和特殊情况的处理。理解这个文件的功能和实现方式，有助于我们更深入地了解 Android 底层数学库的工作原理，以及如何在 NDK 开发中正确使用数学函数。 通过 Frida 这样的工具，我们可以动态地观察和调试这些底层的函数调用，从而更好地理解系统的运行机制。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/bsdsrc/b_log.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Table-driven natural logarithm.
 *
 * This code was derived, with minor modifications, from:
 *	Peter Tang, "Table-Driven Implementation of the
 *	Logarithm in IEEE Floating-Point arithmetic." ACM Trans.
 *	Math Software, vol 16. no 4, pp 378-400, Dec 1990).
 *
 * Calculates log(2^m*F*(1+f/F)), |f/F| <= 1/256,
 * where F = j/128 for j an integer in [0, 128].
 *
 * log(2^m) = log2_hi*m + log2_tail*m
 * The leading term is exact, because m is an integer,
 * m has at most 10 digits (for subnormal numbers),
 * and log2_hi has 11 trailing zero bits.
 *
 * log(F) = logF_hi[j] + logF_lo[j] is in table below.
 * logF_hi[] + 512 is exact.
 *
 * log(1+f/F) = 2*f/(2*F + f) + 1/12 * (2*f/(2*F + f))**3 + ...
 *
 * The leading term is calculated to extra precision in two
 * parts, the larger of which adds exactly to the dominant
 * m and F terms.
 *
 * There are two cases:
 *	1. When m and j are non-zero (m | j), use absolute
 *	   precision for the leading term.
 *	2. When m = j = 0, |1-x| < 1/256, and log(x) ~= (x-1).
 *	   In this case, use a relative precision of 24 bits.
 * (This is done differently in the original paper)
 *
 * Special cases:
 *	0	return signalling -Inf
 *	neg	return signalling NaN
 *	+Inf	return +Inf
 */

#define N 128

/*
 * Coefficients in the polynomial approximation of log(1+f/F).
 * Domain of x is [0,1./256] with 2**(-64.187) precision.
 */
static const double
    A1 =  8.3333333333333329e-02, /* 0x3fb55555, 0x55555555 */
    A2 =  1.2499999999943598e-02, /* 0x3f899999, 0x99991a98 */
    A3 =  2.2321527525957776e-03; /* 0x3f624929, 0xe24e70be */

/*
 * Table of log(Fj) = logF_head[j] + logF_tail[j], for Fj = 1+j/128.
 * Used for generation of extend precision logarithms.
 * The constant 35184372088832 is 2^45, so the divide is exact.
 * It ensures correct reading of logF_head, even for inaccurate
 * decimal-to-binary conversion routines.  (Everybody gets the
 * right answer for integers less than 2^53.)
 * Values for log(F) were generated using error < 10^-57 absolute
 * with the bc -l package.
 */
static double logF_head[N+1] = {
	0.,
	.007782140442060381246,
	.015504186535963526694,
	.023167059281547608406,
	.030771658666765233647,
	.038318864302141264488,
	.045809536031242714670,
	.053244514518837604555,
	.060624621816486978786,
	.067950661908525944454,
	.075223421237524235039,
	.082443669210988446138,
	.089612158689760690322,
	.096729626458454731618,
	.103796793681567578460,
	.110814366340264314203,
	.117783035656430001836,
	.124703478501032805070,
	.131576357788617315236,
	.138402322859292326029,
	.145182009844575077295,
	.151916042025732167530,
	.158605030176659056451,
	.165249572895390883786,
	.171850256926518341060,
	.178407657472689606947,
	.184922338493834104156,
	.191394852999565046047,
	.197825743329758552135,
	.204215541428766300668,
	.210564769107350002741,
	.216873938300523150246,
	.223143551314024080056,
	.229374101064877322642,
	.235566071312860003672,
	.241719936886966024758,
	.247836163904594286577,
	.253915209980732470285,
	.259957524436686071567,
	.265963548496984003577,
	.271933715484010463114,
	.277868451003087102435,
	.283768173130738432519,
	.289633292582948342896,
	.295464212893421063199,
	.301261330578199704177,
	.307025035294827830512,
	.312755710004239517729,
	.318453731118097493890,
	.324119468654316733591,
	.329753286372579168528,
	.335355541920762334484,
	.340926586970454081892,
	.346466767346100823488,
	.351976423156884266063,
	.357455888922231679316,
	.362905493689140712376,
	.368325561158599157352,
	.373716409793814818840,
	.379078352934811846353,
	.384411698910298582632,
	.389716751140440464951,
	.394993808240542421117,
	.400243164127459749579,
	.405465108107819105498,
	.410659924985338875558,
	.415827895143593195825,
	.420969294644237379543,
	.426084395310681429691,
	.431173464818130014464,
	.436236766774527495726,
	.441274560805140936281,
	.446287102628048160113,
	.451274644139630254358,
	.456237433481874177232,
	.461175715122408291790,
	.466089729924533457960,
	.470979715219073113985,
	.475845904869856894947,
	.480688529345570714212,
	.485507815781602403149,
	.490303988045525329653,
	.495077266798034543171,
	.499827869556611403822,
	.504556010751912253908,
	.509261901790523552335,
	.513945751101346104405,
	.518607764208354637958,
	.523248143765158602036,
	.527867089620485785417,
	.532464798869114019908,
	.537041465897345915436,
	.541597282432121573947,
	.546132437597407260909,
	.550647117952394182793,
	.555141507540611200965,
	.559615787935399566777,
	.564070138285387656651,
	.568504735352689749561,
	.572919753562018740922,
	.577315365035246941260,
	.581691739635061821900,
	.586049045003164792433,
	.590387446602107957005,
	.594707107746216934174,
	.599008189645246602594,
	.603290851438941899687,
	.607555250224322662688,
	.611801541106615331955,
	.616029877215623855590,
	.620240409751204424537,
	.624433288012369303032,
	.628608659422752680256,
	.632766669570628437213,
	.636907462236194987781,
	.641031179420679109171,
	.645137961373620782978,
	.649227946625615004450,
	.653301272011958644725,
	.657358072709030238911,
	.661398482245203922502,
	.665422632544505177065,
	.669430653942981734871,
	.673422675212350441142,
	.677398823590920073911,
	.681359224807238206267,
	.685304003098281100392,
	.689233281238557538017,
	.693147180560117703862
};

static double logF_tail[N+1] = {
	0.,
	-.00000000000000543229938420049,
	 .00000000000000172745674997061,
	-.00000000000001323017818229233,
	-.00000000000001154527628289872,
	-.00000000000000466529469958300,
	 .00000000000005148849572685810,
	-.00000000000002532168943117445,
	-.00000000000005213620639136504,
	-.00000000000001819506003016881,
	 .00000000000006329065958724544,
	 .00000000000008614512936087814,
	-.00000000000007355770219435028,
	 .00000000000009638067658552277,
	 .00000000000007598636597194141,
	 .00000000000002579999128306990,
	-.00000000000004654729747598444,
	-.00000000000007556920687451336,
	 .00000000000010195735223708472,
	-.00000000000017319034406422306,
	-.00000000000007718001336828098,
	 .00000000000010980754099855238,
	-.00000000000002047235780046195,
	-.00000000000008372091099235912,
	 .00000000000014088127937111135,
	 .00000000000012869017157588257,
	 .00000000000017788850778198106,
	 .00000000000006440856150696891,
	 .00000000000016132822667240822,
	-.00000000000007540916511956188,
	-.00000000000000036507188831790,
	 .00000000000009120937249914984,
	 .00000000000018567570959796010,
	-.00000000000003149265065191483,
	-.00000000000009309459495196889,
	 .00000000000017914338601329117,
	-.00000000000001302979717330866,
	 .00000000000023097385217586939,
	 .00000000000023999540484211737,
	 .00000000000015393776174455408,
	-.00000000000036870428315837678,
	 .00000000000036920375082080089,
	-.00000000000009383417223663699,
	 .00000000000009433398189512690,
	 .00000000000041481318704258568,
	-.00000000000003792316480209314,
	 .00000000000008403156304792424,
	-.00000000000034262934348285429,
	 .00000000000043712191957429145,
	-.00000000000010475750058776541,
	-.00000000000011118671389559323,
	 .00000000000037549577257259853,
	 .00000000000013912841212197565,
	 .00000000000010775743037572640,
	 .00000000000029391859187648000,
	-.00000000000042790509060060774,
	 .00000000000022774076114039555,
	 .00000000000010849569622967912,
	-.00000000000023073801945705758,
	 .00000000000015761203773969435,
	 .00000000000003345710269544082,
	-.00000000000041525158063436123,
	 .00000000000032655698896907146,
	-.00000000000044704265010452446,
	 .00000000000034527647952039772,
	-.00000000000007048962392109746,
	 .00000000000011776978751369214,
	-.00000000000010774341461609578,
	 .00000000000021863343293215910,
	 .00000000000024132639491333131,
	 .00000000000039057462209830700,
	-.00000000000026570679203560751,
	 .00000000000037135141919592021,
	-.00000000000017166921336082431,
	-.00000000000028658285157914353,
	-.00000000000023812542263446809,
	 .00000000000006576659768580062,
	-.00000000000028210143846181267,
	 .00000000000010701931762114254,
	 .00000000000018119346366441110,
	 .00000000000009840465278232627,
	-.00000000000033149150282752542,
	-.00000000000018302857356041668,
	-.00000000000016207400156744949,
	 .00000000000048303314949553201,
	-.00000000000071560553172382115,
	 .00000000000088821239518571855,
	-.00000000000030900580513238244,
	-.00000000000061076551972851496,
	 .00000000000035659969663347830,
	 .00000000000035782396591276383,
	-.00000000000046226087001544578,
	 .00000000000062279762917225156,
	 .00000000000072838947272065741,
	 .00000000000026809646615211673,
	-.00000000000010960825046059278,
	 .00000000000002311949383800537,
	-.00000000000058469058005299247,
	-.00000000000002103748251144494,
	-.00000000000023323182945587408,
	-.00000000000042333694288141916,
	-.00000000000043933937969737844,
	 .00000000000041341647073835565,
	 .00000000000006841763641591466,
	 .00000000000047585534004430641,
	 .00000000000083679678674757695,
	-.00000000000085763734646658640,
	 .00000000000021913281229340092,
	-.00000000000062242842536431148,
	-.00000000000010983594325438430,
	 .00000000000065310431377633651,
	-.00000000000047580199021710769,
	-.00000000000037854251265457040,
	 .00000000000040939233218678664,
	 .00000000000087424383914858291,
	 .00000000000025218188456842882,
	-.00000000000003608131360422557,
	-.00000000000050518555924280902,
	 .00000000000078699403323355317,
	-.00000000000067020876961949060,
	 .00000000000016108575753932458,
	 .00000000000058527188436251509,
	-.00000000000035246757297904791,
	-.00000000000018372084495629058,
	 .00000000000088606689813494916,
	 .00000000000066486268071468700,
	 .00000000000063831615170646519,
	 .00000000000025144230728376072,
	-.00000000000017239444525614834
};
/*
 * Extra precision variant, returning struct {double a, b;};
 * log(x) = a+b to 63 bits, with 'a' rounded to 24 bits.
 */
static struct Double
__log__D(double x)
{
	int m, j;
	double F, f, g, q, u, v, u1, u2;
	struct Double r;

	/*
	 * Argument reduction: 1 <= g < 2; x/2^m = g;
	 * y = F*(1 + f/F) for |f| <= 2^-8
	 */
	g = frexp(x, &m);
	g *= 2;
	m--;
	if (m == -1022) {
		j = ilogb(g);
		m += j;
		g = ldexp(g, -j);
	}
	j = N * (g - 1) + 0.5;
	F = (1. / N) * j + 1;
	f = g - F;

	g = 1 / (2 * F + f);
	u = 2 * f * g;
	v = u * u;
	q = u * v * (A1 + v * (A2 + v * A3));
	if (m | j) {
		u1 = u + 513;
		u1 -= 513;
	} else {
		u1 = (float)u;
	}
	u2 = (2 * (f - F * u1) - u1 * f) * g;

	u1 += m * logF_head[N] + logF_head[j];

	u2 += logF_tail[j];
	u2 += q;
	u2 += logF_tail[N] * m;
	r.a = (float)(u1 + u2);		/* Only difference is here. */
	r.b = (u1 - r.a) + u2;
	return (r);
}

"""

```
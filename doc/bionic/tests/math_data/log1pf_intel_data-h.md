Response:
Let's break down the thought process for answering this complex request about the `log1pf_intel_data.handroid` file.

**1. Understanding the Core Request:**

The central goal is to analyze the provided C code snippet and explain its function, context within Android, implementation details, dynamic linking aspects, potential errors, and debugging approaches.

**2. Initial Assessment of the Code:**

* **Data Structure:** The code defines a static array `g_log1pf_intel_data` of a type `data_1_1_t<float, float>`. This immediately suggests it's holding pairs of floating-point numbers.
* **Naming Convention:** The name "log1pf" strongly hints at the mathematical function `log1p(x)`, which calculates the natural logarithm of (1 + x). The "intel_data" suggests it might be test data specifically tailored for Intel architectures or generated using Intel's math libraries. "handroid" clearly ties it to Android.
* **Content:** The array is filled with hexadecimal floating-point literals. Each entry has two `float` values.

**3. Deconstructing the Request - Keyword Analysis:**

* **"功能 (Functionality)":** What does this file *do*?  It holds data. What kind of data? Input-output pairs for testing `log1p`.
* **"与android的功能有关系 (Relationship with Android functionality)":**  How is this used *within* Android?  It's part of bionic's math library tests. This means it's used to ensure the `log1pf` implementation in `libm.so` works correctly.
* **"对应的举例说明 (Corresponding Examples)":**  Provide concrete examples of how this is used. Testing the `log1pf` function in `libm.so`.
* **"详细解释每一个libc函数的功能是如何实现的 (Detailed explanation of how each libc function is implemented)":**  This is a tricky part. The provided code *isn't* a libc function implementation. It's *data*. So, the focus shifts to the function that *uses* this data, which is `log1pf`. This requires explaining general implementation strategies for `log1p`.
* **"对于涉及dynamic linker的功能 (For functionality involving the dynamic linker)":**  How does this relate to dynamic linking?  The data is used to test a function in `libm.so`, which is a dynamically linked library. This involves explaining the basic dynamic linking process, the role of the linker, and a sample `libm.so` layout.
* **"请给对应的so布局样本，以及链接的处理过程 (Provide a sample so layout and the linking process)":**  Provide a simplified example of `libm.so` structure and how the dynamic linker resolves the `log1pf` function.
* **"如果做了逻辑推理，请给出假设输入与输出 (If logical reasoning is done, provide assumed input and output)":** The data itself *is* the input and expected output for `log1pf`. Provide examples from the array.
* **"如果涉及用户或者编程常见的使用错误，请举例说明 (If it involves common user or programming errors, give examples)":** What mistakes could developers make related to `log1pf`?  Passing invalid inputs, not handling edge cases, precision issues.
* **"说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤 (Explain how Android Framework or NDK reaches here step by step, give a Frida hook example to debug these steps)":** How does code in an Android app end up using `log1pf` and how can we observe this with Frida?  Describe the path from application code to NDK, then to `libm.so`. Provide a Frida script to hook `log1pf`.

**4. Structuring the Answer:**

Organize the answer logically based on the keywords in the request. Start with a summary of the file's purpose, then delve into the details.

**5. Addressing the "libc function implementation" challenge:**

Recognize that the file itself doesn't *implement* a libc function. Instead, explain that it's test data for the *implementation* of `log1pf` within `libm.so`. Describe general strategies for implementing `log1p` (reduction, Taylor series, lookup tables).

**6. Dynamic Linking Explanation:**

Focus on the core concepts: `libm.so`, the dynamic linker, symbol resolution. Provide a simplified `libm.so` layout showing sections like `.text`, `.data`, `.dynsym`, `.dynstr`. Explain the steps of symbol lookup.

**7. Frida Hook Example:**

Craft a simple Frida script that attaches to an application, finds the `log1pf` function in `libm.so`, and intercepts its calls, logging input and output.

**8. Language and Tone:**

Use clear and concise Chinese. Maintain a helpful and informative tone.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the `data_1_1_t` structure. **Correction:** Realize the structure is secondary to the *purpose* of the data.
* **Initial thought:**  Try to explain the *exact* implementation of `log1pf`. **Correction:**  Recognize that the source code for `log1pf` isn't provided. Explain *general* implementation techniques instead.
* **Initial thought:**  Provide a highly detailed dynamic linking explanation. **Correction:** Simplify the explanation to focus on the essential concepts relevant to this file's context.

By following these steps, the detailed and comprehensive answer generated in the example becomes achievable. The key is to break down the request, understand the code's context, and address each part of the prompt systematically.
这是一个位于 Android Bionic 库中，名为 `log1pf_intel_data.handroid` 的源代码文件。从文件名和路径来看，它很明显是用于测试 `log1pf` 函数的数据集，并且特别针对 Intel 架构。Bionic 是 Android 的 C 库，因此这个文件是 Bionic 中数学库测试的一部分。

**功能列举:**

1. **提供 `log1pf` 函数的测试数据:**  这个文件的主要功能是提供一系列的输入值和对应的预期输出值，用于测试 `log1pf` 函数的正确性。
2. **针对 Intel 架构优化或验证:** 文件名中的 `intel_data` 表明这些测试数据可能是基于 Intel 处理器的特性或用于验证在 Intel 处理器上的 `log1pf` 实现。
3. **作为 Bionic 数学库测试套件的一部分:**  这个文件是 Bionic 数学库（`libm.so`）测试框架的一部分，用于确保数学函数的准确性和可靠性。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 系统底层的数学运算能力。`log1pf(x)` 函数计算的是 `ln(1 + x)`，这是一个常见的数学函数，在很多领域都有应用，包括但不限于：

* **网络编程:**  计算某些网络协议中的指数退避值。
* **音频处理:**  在某些音频算法中，对数运算是重要的组成部分。
* **机器学习/人工智能:**  许多机器学习模型，例如逻辑回归，会用到对数运算。
* **图形渲染:**  在某些光照模型或纹理计算中可能会使用到。

**举例说明:**

假设一个 Android 应用需要计算某个概率值的自然对数。该应用可能会调用 Bionic 提供的 `log1pf` 函数，例如：

```c
#include <math.h>
#include <stdio.h>

int main() {
  float x = 0.5;
  float result = log1pf(x);
  printf("log1pf(%f) = %f\n", x, result); // 期望输出接近 log(1 + 0.5) ≈ 0.405465
  return 0;
}
```

Bionic 的 `libm.so` 库中实现了 `log1pf` 函数。当这个应用运行时，系统会加载 `libm.so`，并执行其中的 `log1pf` 函数。为了确保 `log1pf` 的实现是正确的，Android 的开发者会使用像 `log1pf_intel_data.handroid` 这样的测试数据集来验证其输出是否符合预期。

**详细解释 `libc` 函数 (`log1pf`) 的功能是如何实现的:**

`log1pf(x)` 函数计算的是 `ln(1 + x)`。由于计算机只能进行加减乘除等基本运算，因此 `log1pf` 的实现通常会采用以下策略：

1. **处理特殊情况:**
   * 如果 `x` 是 NaN (Not a Number)，则返回 NaN。
   * 如果 `x` 是 -1，则 `1 + x` 为 0，`ln(0)` 为负无穷大，返回 `-INFINITY`。
   * 如果 `x` 是正无穷大，则 `1 + x` 也是正无穷大，`ln(正无穷大)` 也是正无穷大，返回 `INFINITY`。
   * 如果 `x` 是负数且大于 -1，则直接计算。
   * 如果 `x` 小于 -1，则 `1 + x` 为负数或零，对负数取对数在实数范围内无意义，可能会返回 NaN 或引发错误。

2. **范围缩减 (Range Reduction):**  为了提高精度和效率，通常会将 `x` 的范围缩小到一个较小的区间。例如，可以利用对数的性质：
   * `ln(1 + x) = ln(2 * (0.5 + x/2))`
   * `ln(1 + x) = ln((1 + y) / (1 - y))`，其中 `y = x / (2 + x)`。
   选择合适的变换可以将 `x` 映射到一个更小的范围，例如 `[-0.5, 0.5]` 或更小。

3. **多项式逼近或查找表:**
   * **多项式逼近:** 在缩减后的范围内，使用多项式来逼近 `ln(1 + x)` 的值。常用的方法是泰勒展开或切比雪夫逼近。泰勒展开式为 `ln(1 + x) = x - x^2/2 + x^3/3 - x^4/4 + ...`。在实际实现中，通常会选择有限项的多项式来保证计算效率和精度。
   * **查找表:**  对于某些精度要求不高的情况，可以使用查找表。预先计算一些点的 `ln(1 + x)` 值并存储在表中。对于给定的 `x`，可以通过查表或插值来获取近似值。这种方法速度快，但精度受限于表的大小。

4. **组合结果:** 将范围缩减的步骤中产生的常数项（例如 `ln(2)`）与多项式逼近的结果组合起来，得到最终的 `ln(1 + x)` 值。

**对于涉及 dynamic linker 的功能:**

`log1pf` 函数位于 `libm.so` 这个动态链接库中。当一个应用程序需要使用 `log1pf` 时，操作系统会使用动态链接器（在 Android 中是 `linker` 或 `linker64`）来加载 `libm.so` 并解析对 `log1pf` 函数的引用。

**`libm.so` 布局样本:**

一个简化的 `libm.so` 布局可能如下所示：

```
libm.so:
    .so起始地址
    ...
    .text:  # 代码段，包含 log1pf 的机器指令
        ...
        [log1pf 函数的机器码]
        ...
    .data:  # 初始化数据段，可能包含一些常量
        ...
    .rodata: # 只读数据段，可能包含一些常量
        ...
    .dynsym: # 动态符号表，包含导出的符号信息，例如 log1pf
        [log1pf 的符号信息，包括名称和地址]
        ...
    .dynstr: # 动态字符串表，包含符号表中使用的字符串
        "log1pf"
        ...
    .rel.dyn: # 动态重定位表
        ...
    .plt:   # Procedure Linkage Table，用于延迟绑定
        ...
    .got.plt: # Global Offset Table，用于存储外部符号的地址
        ...
    ...
    .so结束地址
```

**链接的处理过程:**

1. **加载库:** 当应用程序启动或首次调用 `log1pf` 时，动态链接器会找到并加载 `libm.so` 到内存中的某个地址。
2. **符号查找:** 应用程序在编译时，对 `log1pf` 的调用只是一个占位符。当动态链接器加载 `libm.so` 后，它会查看 `libm.so` 的 `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表)，找到名为 "log1pf" 的符号，并获取其在 `libm.so` 中的实际地址。
3. **重定位:**  动态链接器会更新应用程序的 `.got.plt` (全局偏移量表) 中 `log1pf` 对应的条目，将其指向 `libm.so` 中 `log1pf` 函数的实际地址。
4. **调用:**  当应用程序再次调用 `log1pf` 时，会通过 `.plt` (过程链接表) 跳转到 `.got.plt` 中存储的实际地址，从而执行 `libm.so` 中的 `log1pf` 函数。

**假设输入与输出 (逻辑推理基于数据):**

查看 `log1pf_intel_data.handroid` 文件中的数据，每一行都是一个测试用例，格式为 `{-输入值, 预期输出值}`。

* **假设输入:** `-0x1.630430efae4a1e08a52dd228f774747ap-1` (这是一个十六进制浮点数表示，大约等于 -0.886)
* **预期输出:** `-0x1.0010p-1` (大约等于 -0.500244)

根据 `log1pf(x) = ln(1 + x)`，计算 `ln(1 - 0.886) = ln(0.114)`，其值接近 `-2.171`。 然而，这里的数据是用于测试浮点数的实现，因此需要考虑精度问题。

让我们看一个更简单的例子：

* **假设输入:** `0x1.000000fffffd55555755555888887dddp-23` (非常小的正数，接近 1.175e-07)
* **预期输出:** `0x1.000002p-23` (非常小的正数，接近 1.175e-07)

当 `x` 非常小时，`log1pf(x) ≈ x`，因此输入和输出非常接近。

**用户或编程常见的使用错误:**

1. **传入无效的输入值:**
   * 传入小于 -1 的值，例如 `log1pf(-2.0f)`，会导致 `1 + x` 为负数，对负数取对数在实数范围内没有定义，可能返回 NaN。
   * 传入 NaN 值，`log1pf(NAN)`，通常会返回 NaN。

2. **精度问题:**  浮点数运算存在精度限制。对于非常大或非常小的 `x` 值，`1 + x` 可能因为精度损失而无法准确表示，导致 `log1pf` 的结果不精确。

3. **误解函数的功能:**  错误地使用 `logf(1 + x)` 代替 `log1pf(x)`。虽然结果在数学上是相同的，但在数值计算上，当 `x` 接近 0 时，`log1pf(x)` 通常能提供更高的精度。

**Android Framework 或 NDK 如何到达这里，给出 Frida Hook 示例调试这些步骤:**

1. **Android Framework/NDK 调用:** 应用程序（无论是 Java/Kotlin 还是 Native 代码）最终会调用到 Bionic 的 `libm.so` 中的 `log1pf` 函数。
   * **Framework:**  Java 代码可能会调用 Android SDK 提供的 Math 类中的方法，这些方法在底层可能会调用到 Native 代码。
   * **NDK:**  Native 代码可以直接调用 Bionic 提供的数学函数，只需包含 `<math.h>` 头文件并链接 `libm.so`。

2. **动态链接:** 当程序执行到调用 `log1pf` 的代码时，动态链接器会解析符号并跳转到 `libm.so` 中 `log1pf` 的实现。

**Frida Hook 示例:**

可以使用 Frida 来 Hook `log1pf` 函数，观察其输入和输出。以下是一个 Frida 脚本示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const log1pfPtr = Module.findExportByName("libm.so", "log1pf");
    if (log1pfPtr) {
        Interceptor.attach(log1pfPtr, {
            onEnter: function (args) {
                const x = args[0].toFloat();
                console.log(`Called log1pf with x = ${x}`);
            },
            onLeave: function (retval) {
                const result = retval.toFloat();
                console.log(`log1pf returned ${result}`);
            }
        });
        console.log("Successfully hooked log1pf");
    } else {
        console.log("Failed to find log1pf in libm.so");
    }
} else {
    console.log("Frida hook for log1pf is only supported on arm64 and x64 architectures.");
}
```

**使用步骤:**

1. **启动目标 Android 应用。**
2. **运行 Frida 脚本:** 使用 Frida 命令行工具或 API 将上述脚本注入到目标应用进程中。例如：
   ```bash
   frida -U -f <package_name> -l hook_log1pf.js --no-pause
   ```
   将 `<package_name>` 替换为目标应用的包名，`hook_log1pf.js` 保存上述 Frida 脚本。

**调试过程:**

当目标应用调用 `log1pf` 函数时，Frida 脚本会拦截调用，并在控制台上打印出传入的参数 `x` 和函数的返回值 `result`。这样就可以观察 `log1pf` 的实际行为，验证其输入输出是否符合预期。

总而言之，`bionic/tests/math_data/log1pf_intel_data.handroid` 文件是 Android Bionic 数学库测试的关键组成部分，用于确保 `log1pf` 函数在 Intel 架构上的正确实现。它通过提供一系列预定义的输入和输出值，帮助开发者验证和调试底层的数学运算功能。

### 提示词
```
这是目录为bionic/tests/math_data/log1pf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

static data_1_1_t<float, float> g_log1pf_intel_data[] = {
  { // Entry 0
    -0x1.630430efae4a1e08a52dd228f774747ap-1,
    -0x1.0010p-1
  },
  { // Entry 1
    -0x1.0a6a950320b815309cee76c6c346aa8ap-6,
    -0x1.084310p-6
  },
  { // Entry 2
    -0x1.4592f4df3c22380a8a7a6bd256a231c9p-2,
    -0x1.16e480p-2
  },
  { // Entry 3
    -0x1.5362b6deece53e28930e0d75f3b0e969p-2,
    -0x1.20e0p-2
  },
  { // Entry 4
    -0x1.66ea0edec29ccaccbbc9459e55583852p-2,
    -0x1.2ec3p-2
  },
  { // Entry 5
    -0x1.e5ee02ef643742b40691cfbbe5c34235p-1,
    -0x1.39ce80p-1
  },
  { // Entry 6
    -0x1.ee2a156b413e4fe8b48e04a1a81d7d1fp-2,
    -0x1.88p-2
  },
  { // Entry 7
    -0x1.af8967d890ceb5ae2c25ac22be3d5d14p-4,
    -0x1.999502p-4
  },
  { // Entry 8
    -0x1.c50e9e00c0346f0253e08a684bbb9a7ep-7,
    -0x1.c1f080p-7
  },
  { // Entry 9
    -0x1.d240ed01404debfca8485f4159238678p-7,
    -0x1.cef3c0p-7
  },
  { // Entry 10
    -0x1.e3d6ff014fb650f40fcce84889424dadp-7,
    -0x1.e04906p-7
  },
  { // Entry 11
    -0x1.e3dbcb012249a6d99fa2c2ccddddacc7p-7,
    -0x1.e04dc0p-7
  },
  { // Entry 12
    -0x1.e9924b01a753cecfd33f2d536b84f02fp-7,
    -0x1.e5eeb0p-7
  },
  { // Entry 13
    -0x1.f82ba0e78ab204f65a17734933732987p-6,
    -0x1.f07ep-6
  },
  { // Entry 14
    -0x1.f9c13b02072dd9618b9803ed7ddfbabep-7,
    -0x1.f5df2ep-7
  },
  { // Entry 15
    -0x1.fa2f5d01c871d22cde70cc085ced02ebp-7,
    -0x1.f64ba0p-7
  },
  { // Entry 16
    -0x1.fb1175021cc3e1272f3c6b103248fc29p-7,
    -0x1.f72a40p-7
  },
  { // Entry 17
    -0x1.fd69f70227b4fea60671e68dcb4dee6cp-7,
    -0x1.f97984p-7
  },
  { // Entry 18
    -0x1.62c42eefb8f3c8a68360fc37186210edp-1,
    -0x1.ffdffep-2
  },
  { // Entry 19
    -0x1.fffffdfffffaaaaaa6aaaab111112666p-24,
    -0x1.fffffcp-24
  },
  { // Entry 20
    0x1.ff802a9ab10e678a78e854f8ec6ac72bp-10,
    0x1.p-9
  },
  { // Entry 21
    0x1.ffc00aa8ab10fbc04d051924c9347471p-11,
    0x1.p-10
  },
  { // Entry 22
    0x1.fffff00000aaaaa2aaab11110bbbbc04p-21,
    0x1.p-20
  },
  { // Entry 23
    0x1.fffff800002aaaa9aaaab11110e66667p-22,
    0x1.p-21
  },
  { // Entry 24
    0x1.ffffffffffffffffffffffffffffffp-121,
    0x1.p-120
  },
  { // Entry 25
    0.0f,
    0x1.p-149
  },
  { // Entry 26
    0x1.fc0a8effff421db6014956cf936c5246p-7,
    0x1.000002p-6
  },
  { // Entry 27
    0x1.ffffc40009aaa8e9ab0190ff8c14b319p-19,
    0x1.000002p-18
  },
  { // Entry 28
    0x1.000000fffffd55555755555888887dddp-23,
    0x1.000002p-23
  },
  { // Entry 29
    0x1.000001ffffbfffff0000145555d5554ep-41,
    0x1.000002p-41
  },
  { // Entry 30
    0x1.e270851b92b64555fb421203aa0bcb5cp-4,
    0x1.000008p-3
  },
  { // Entry 31
    0x1.193ead002577c5e89dc7604b89fc7cebp0,
    0x1.000008p1
  },
  { // Entry 32
    0x1.193f3cfff9f7d6d8965e4e6b818cb622p0,
    0x1.0000e0p1
  },
  { // Entry 33
    0x1.ffd006a99ad908d29312234ef301f8a7p-11,
    0x1.0008p-10
  },
  { // Entry 34
    0x1.f2a7c700004b00f1cb775536c5857252p-5,
    0x1.01128cp-4
  },
  { // Entry 35
    0x1.cabc19000311437879afccdb6fc91aafp-3,
    0x1.0116p-2
  },
  { // Entry 36
    0x1.20794701579253647a43cecd04c093e2p4,
    0x1.01fffep26
  },
  { // Entry 37
    0x1.02d59bfffebbee3ec0c159b239188c69p-7,
    0x1.03dcp-7
  },
  { // Entry 38
    0x1.ea5f11000fca3ff94bceefddbe67b553p-4,
    0x1.047752p-3
  },
  { // Entry 39
    0x1.be69c4ffffedd2cb5e5f046e949251cap-2,
    0x1.17c5f0p-1
  },
  { // Entry 40
    0x1.f40ade790277455219208e6cbce12c81p-3,
    0x1.1b30p-2
  },
  { // Entry 41
    0x1.b17d614548b69a74509e9d003c096acdp0,
    0x1.1cp2
  },
  { // Entry 42
    0x1.c4017efffec839b96cd1a043d59e5735p-2,
    0x1.1c1cp-1
  },
  { // Entry 43
    0x1.6fb67efffb26578a0527f61362ac8fa8p-8,
    0x1.70bf14p-8
  },
  { // Entry 44
    0x1.7b9b982b27d8fd65f78363d3dedc97b2p-14,
    0x1.7b9ffep-14
  },
  { // Entry 45
    0x1.4402c0fffffff1ee8f659da5ea3af296p-2,
    0x1.7d2286p-2
  },
  { // Entry 46
    0x1.453252ffffff9b941dfd07fbfe366e98p3,
    0x1.94d4eap14
  },
  { // Entry 47
    0x1.981eb6000011b05ecb59c7545ff929fap-4,
    0x1.ad250ap-4
  },
  { // Entry 48
    0x1.ff1e1e73e713dc5a44e45f9c3f28b7c8p-1,
    0x1.b6ae94p0
  },
  { // Entry 49
    0x1.990193ffffdd6f9fee37f808cd2663abp-3,
    0x1.c4b528p-3
  },
  { // Entry 50
    0x1.cd15fefff69640aea34534134c884cf5p-14,
    0x1.cd1c7cp-14
  },
  { // Entry 51
    0x1.d29b864c3678db9fafb9295703bb2bc1p-7,
    0x1.d5f20ep-7
  },
  { // Entry 52
    0x1.db8be7c511d00e008415288ce9a25163p-8,
    0x1.dd46aap-8
  },
  { // Entry 53
    0x1.9a37cb000006cf9ac9e3b0eedec553ffp-2,
    0x1.f88cf6p-2
  },
  { // Entry 54
    0x1.0b2148000d52175d80c54887b0d4a470p2,
    0x1.ffbffep5
  },
  { // Entry 55
    0x1.fc090efffd0dee6eb02f2fa5b5d354afp-7,
    0x1.fffe7ep-7
  },
  { // Entry 56
    0x1.193e2700053065bd8378fbbd3b637eb6p0,
    0x1.fffe7ep0
  },
  { // Entry 57
    0x1.f82970e7831004cf7a6be71673528989p-6,
    0x1.ffffbep-6
  },
  { // Entry 58
    0x1.193ea500258270930f8e7d7af244dcffp0,
    0x1.fffff8p0
  },
  { // Entry 59
    0x1.fffff400004aaaa88aaabb11108d1115p-22,
    0x1.fffffcp-22
  },
  { // Entry 60
    0x1.11d14de2e6a77280841e892fac90ccfap-1,
    0x1.6a09e6p-1
  },
  { // Entry 61
    0x1.2ccac6d04834d03c513a0f03d4c89b83p-1,
    0x1.995256p-1
  },
  { // Entry 62
    0x1.466a92ae5453d95b0ba6631497388e92p-1,
    0x1.c89ac6p-1
  },
  { // Entry 63
    0x1.5ed1a85999ba7b8b5440ce7e5a6b56f2p-1,
    0x1.f7e336p-1
  },
  { // Entry 64
    0x1.761c7d56e25f3f7369eb2e8d33b8209cp-1,
    0x1.1395d2p0
  },
  { // Entry 65
    0x1.8c63d26f597f171e4d44ff4b30356555p-1,
    0x1.2b3a0ap0
  },
  { // Entry 66
    0x1.a1bd4c9e41df1dbc9bdcf52548fe75b2p-1,
    0x1.42de42p0
  },
  { // Entry 67
    0x1.b63bf811a5f2ac93a5d17ec91bb5daabp-1,
    0x1.5a827ap0
  },
  { // Entry 68
    0x1.c9f0adb76b4112afacd4ebe2a82850c6p-1,
    0x1.7226b2p0
  },
  { // Entry 69
    0x1.dcea66c807b8ed92f41a4c7968b5559fp-1,
    0x1.89caeap0
  },
  { // Entry 70
    0x1.ef368161759d5a9bb2da51833d2b502bp-1,
    0x1.a16f22p0
  },
  { // Entry 71
    0x1.00707ca544fcb52315ebafd578b872b3p0,
    0x1.b9135ap0
  },
  { // Entry 72
    0x1.08fa4b9ede8a0b58b4cad9c182b5bc7ap0,
    0x1.d0b792p0
  },
  { // Entry 73
    0x1.113d8c489a020b1485aeadcbd8328e39p0,
    0x1.e85bcap0
  },
  { // Entry 74
    0x1.193ea7aad030a976a4198d55053b7cb5p0,
    0x1.p1
  },
  { // Entry 75
    0x1.11d14de2e6a77280841e892fac90ccfap-1,
    0x1.6a09e6p-1
  },
  { // Entry 76
    0x1.26990d712acaf377db999b7a4d6f0d77p-1,
    0x1.8e3e16p-1
  },
  { // Entry 77
    0x1.3a9149340db314ea32356ecefac481p-1,
    0x1.b27246p-1
  },
  { // Entry 78
    0x1.4dc99695710c65b9bcf0bb6b8edd5d21p-1,
    0x1.d6a676p-1
  },
  { // Entry 79
    0x1.604fd9d3719dfe935e33ddc7d697914bp-1,
    0x1.fadaa6p-1
  },
  { // Entry 80
    0x1.7230837fde6a8438b4a457e20a8e06fep-1,
    0x1.0f876cp0
  },
  { // Entry 81
    0x1.8376bee5d088c50a9458bc6f7ae9a783p-1,
    0x1.21a184p0
  },
  { // Entry 82
    0x1.942ca20e8cddd1db45fd28a8128ba122p-1,
    0x1.33bb9cp0
  },
  { // Entry 83
    0x1.a45b4d36cf3486c62245ff3fa2915f6fp-1,
    0x1.45d5b4p0
  },
  { // Entry 84
    0x1.b40b09d2982dde5fa679cf307e5857c2p-1,
    0x1.57efccp0
  },
  { // Entry 85
    0x1.c343641957c53687deafd15a44326c6cp-1,
    0x1.6a09e4p0
  },
  { // Entry 86
    0x1.1e85f5e7040d03dec59a5f3e3c6be5cfp-1,
    0x1.80p-1
  },
  { // Entry 87
    0x1.34024a8c5f61c82ac61e318087908df6p-1,
    0x1.a66666p-1
  },
  { // Entry 88
    0x1.48a112280d6abde96ac67b1fb5ecb146p-1,
    0x1.ccccccp-1
  },
  { // Entry 89
    0x1.5c73756fb0dea2087cd90d8b7bc997a9p-1,
    0x1.f33332p-1
  },
  { // Entry 90
    0x1.6f88b1bee42272ff0a57db75096d585ep-1,
    0x1.0cccccp0
  },
  { // Entry 91
    0x1.81ee60afb50199b91090d89ef318de90p-1,
    0x1.20p0
  },
  { // Entry 92
    0x1.93b0af9c4ab8019e279f9c3bc8a37955p-1,
    0x1.333334p0
  },
  { // Entry 93
    0x1.a4da932e285ccc3fc07f118701145a41p-1,
    0x1.466668p0
  },
  { // Entry 94
    0x1.b575ef12280c4d1b4f06a46e25e8a4a6p-1,
    0x1.59999cp0
  },
  { // Entry 95
    0x1.c58bb849aa7457a9abbdac063833d724p-1,
    0x1.6cccd0p0
  },
  { // Entry 96
    0x1.d5240f0e0e077a082b27e2fc06cc768ap-1,
    0x1.80p0
  },
  { // Entry 97
    0x1.62e42fefa39ef35793c7673007e5ed5ep-1,
    0x1.p0
  },
  { // Entry 98
    0x1.7bdf36901c7f350041da6ef1304395cep-1,
    0x1.19999ap0
  },
  { // Entry 99
    0x1.93b0af9c4ab8019e279f9c3bc8a37955p-1,
    0x1.333334p0
  },
  { // Entry 100
    0x1.aa731192391a8863f4bfe8452991c141p-1,
    0x1.4ccccep0
  },
  { // Entry 101
    0x1.c03d718c8b4dafcae9e8be78cf83cbf4p-1,
    0x1.666668p0
  },
  { // Entry 102
    0x1.d52410a7a7a06fcabadb6d90a4a19793p-1,
    0x1.800002p0
  },
  { // Entry 103
    0x1.e938cda74ef6d0be179304b52619eb82p-1,
    0x1.99999cp0
  },
  { // Entry 104
    0x1.fc8b8126826242614b481d83aaec3cbdp-1,
    0x1.b33336p0
  },
  { // Entry 105
    0x1.07952480b0ea35a6256b2037158f39fdp0,
    0x1.ccccd0p0
  },
  { // Entry 106
    0x1.1090e340e02935eda17728b57dbb2974p0,
    0x1.e6666ap0
  },
  { // Entry 107
    0x1.193ea7aad030a976a4198d55053b7cb5p0,
    0x1.p1
  },
  { // Entry 108
    -0x1.62e42fefa39ef35793c7673007e5ed5ep-1,
    -0x1.p-1
  },
  { // Entry 109
    -0x1.3217b042fc85e510ffef322447286167p-1,
    -0x1.ccccccp-2
  },
  { // Entry 110
    -0x1.058aee52bbf036e43da60fe740480ec8p-1,
    -0x1.999998p-2
  },
  { // Entry 111
    -0x1.b91f246ff08e2be21ff79355d363de75p-2,
    -0x1.666664p-2
  },
  { // Entry 112
    -0x1.6d3c2dbbcad2f6c5b9711be3c95acd83p-2,
    -0x1.333330p-2
  },
  { // Entry 113
    -0x1.26961d134dbb2783bd621217b5546c80p-2,
    -0x1.fffffap-3
  },
  { // Entry 114
    -0x1.c8ff7579a9a52ac25bb899dbd264ce86p-3,
    -0x1.999994p-3
  },
  { // Entry 115
    -0x1.4cd6b35b45fbb9ed92ccfd7f10d29dfcp-3,
    -0x1.33332ep-3
  },
  { // Entry 116
    -0x1.af8e7765f96eba7449d2e369edb815d8p-4,
    -0x1.999990p-4
  },
  { // Entry 117
    -0x1.a431c11b1271b3c8501cfaf9d3319015p-5,
    -0x1.999986p-5
  },
  { // Entry 118
    0.0,
    0.0
  },
  { // Entry 119
    0.0,
    0.0
  },
  { // Entry 120
    0x1.8fb06450b296f7b66ab1a549ae4826a2p-5,
    0x1.99999ap-5
  },
  { // Entry 121
    0x1.8663f7f0dbb23a23b18a99f13b06839ap-4,
    0x1.99999ap-4
  },
  { // Entry 122
    0x1.1e3b830fe6a17974c7bd84c4e3eab82cp-3,
    0x1.333334p-3
  },
  { // Entry 123
    0x1.756501739ebcb722ad1079954ab64abbp-3,
    0x1.99999ap-3
  },
  { // Entry 124
    0x1.c8ff7c79a9a21ac25d81ef2ffb9a24aep-3,
    0x1.p-2
  },
  { // Entry 125
    0x1.0ca9385ba5764f40265b8842277dec27p-2,
    0x1.333334p-2
  },
  { // Entry 126
    0x1.334e9f7738caf691d9028f70d0039fefp-2,
    0x1.666668p-2
  },
  { // Entry 127
    0x1.588c2f480eb6532d57552d24a22c18b8p-2,
    0x1.99999cp-2
  },
  { // Entry 128
    0x1.7c7b2a6204723e0ab52a960a21dbe461p-2,
    0x1.ccccd0p-2
  },
  { // Entry 129
    0x1.9f323ecbf984bf2b68d766f405221819p-2,
    0x1.p-1
  },
  { // Entry 130
    -0x1.7f7425b73e3d1503aef4db985cf47e98p1,
    -0x1.e66666p-1
  },
  { // Entry 131
    -0x1.26bb19bb5555582dca0301cc5afb0340p1,
    -0x1.ccccccp-1
  },
  { // Entry 132
    -0x1.e5a9a3c3ac498090b9d029dbb4ad807ap0,
    -0x1.b33332p-1
  },
  { // Entry 133
    -0x1.9c041b7ed8db36afca225000b2030fd2p0,
    -0x1.999998p-1
  },
  { // Entry 134
    -0x1.62e42befa3a6f3577e72121ab28fcb3cp0,
    -0x1.7ffffep-1
  },
  { // Entry 135
    -0x1.34378bcbda7a06e4efec7643b0ba89cbp0,
    -0x1.666664p-1
  },
  { // Entry 136
    -0x1.0cc1208b56d4b4c06755206193cd1ceap0,
    -0x1.4ccccap-1
  },
  { // Entry 137
    -0x1.d524070e0e177a08007d38d15c203245p-1,
    -0x1.333330p-1
  },
  { // Entry 138
    -0x1.98d5f831b831ae342b6d390d5ee4078ap-1,
    -0x1.199996p-1
  },
  { // Entry 139
    -0x1.62e42fefa39ef35793c7673007e5ed5ep-1,
    -0x1.p-1
  },
  { // Entry 140
    0x1.1542457337d42e1c6b73c89d866ba171p6,
    0x1.p100
  },
  { // Entry 141
    0x1.15a3de7291226038f89b79079de74b15p6,
    0x1.19999ap100
  },
  { // Entry 142
    0x1.15fcf7f671a38b9552200b4c17f03284p6,
    0x1.333334p100
  },
  { // Entry 143
    0x1.164eeeaea72addd7387b5fd890994481p6,
    0x1.4ccccep100
  },
  { // Entry 144
    0x1.169ad1a55b50990c54e1e650029fc95ap6,
    0x1.666668p100
  },
  { // Entry 145
    0x1.16e177b7592304a2b3519037089451c5p6,
    0x1.800002p100
  },
  { // Entry 146
    0x1.17238e1ada469675b97116744955a040p6,
    0x1.99999cp100
  },
  { // Entry 147
    0x1.1761a27cf0fff16c1e86b183310631dfp6,
    0x1.b33336p100
  },
  { // Entry 148
    0x1.179c2a39af642757a6a61b00bba160aep6,
    0x1.ccccd0p100
  },
  { // Entry 149
    0x1.17d3879ff3b917735e3bb947a1e5476fp6,
    0x1.e6666ap100
  },
  { // Entry 150
    0x1.18080dd3171b6c031a9b576be65b6d4cp6,
    0x1.p101
  },
  { // Entry 151
    0x1.62e42feba39ef15793c611dab1909808p6,
    0x1.fffffep127
  },
  { // Entry 152
    0.0f,
    0x1.p-149
  },
  { // Entry 153
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 154
    0x1.11d14cb6fa73c6e3e2b32fdc2e39187cp-1,
    0x1.6a09e4p-1
  },
  { // Entry 155
    0x1.11d14de2e6a77280841e892fac90ccfap-1,
    0x1.6a09e6p-1
  },
  { // Entry 156
    0x1.11d14f0ed2da6e6c589fb5f4332d476fp-1,
    0x1.6a09e8p-1
  },
  { // Entry 157
    -0x1.3a5ac1c04c5f3b4913b799da9d738173p0,
    -0x1.6a09e8p-1
  },
  { // Entry 158
    -0x1.3a5abe5642755d2215d06656abb38c5dp0,
    -0x1.6a09e6p-1
  },
  { // Entry 159
    -0x1.3a5abaec38972722a15fd1d5c0a89c36p0,
    -0x1.6a09e4p-1
  },
  { // Entry 160
    0x1.c343641957c53687deafd15a44326c6cp-1,
    0x1.6a09e4p0
  },
  { // Entry 161
    0x1.c34365c17f5fcd5f0800083c5f3f2de3p-1,
    0x1.6a09e6p0
  },
  { // Entry 162
    0x1.c3436769a6f904d49759471bcfce4490p-1,
    0x1.6a09e8p0
  },
  { // Entry 163
    0x1.9f323d76a42f30f2853c89b7f554a97bp-2,
    0x1.fffffep-2
  },
  { // Entry 164
    0x1.9f323ecbf984bf2b68d766f405221819p-2,
    0x1.p-1
  },
  { // Entry 165
    0x1.9f324176a42e8647db03a6298d08cf83p-2,
    0x1.000002p-1
  },
  { // Entry 166
    0x1.1e85f4c271c38bb4f9b938ae62856a75p-1,
    0x1.7ffffep-1
  },
  { // Entry 167
    0x1.1e85f5e7040d03dec59a5f3e3c6be5cfp-1,
    0x1.80p-1
  },
  { // Entry 168
    0x1.1e85f70b9655d4d98c420da42f457a6ep-1,
    0x1.800002p-1
  },
  { // Entry 169
    -0x1.62e433efa3a6f357a91cbcc55d3c0f80p0,
    -0x1.800002p-1
  },
  { // Entry 170
    -0x1.62e42fefa39ef35793c7673007e5ed5ep0,
    -0x1.80p-1
  },
  { // Entry 171
    -0x1.62e42befa3a6f3577e72121ab28fcb3cp0,
    -0x1.7ffffep-1
  },
  { // Entry 172
    0x1.d5240d74746d3c9786f9771f52074ef3p-1,
    0x1.7ffffep0
  },
  { // Entry 173
    0x1.d5240f0e0e077a082b27e2fc06cc768ap-1,
    0x1.80p0
  },
  { // Entry 174
    0x1.d52410a7a7a06fcabadb6d90a4a19793p-1,
    0x1.800002p0
  },
  { // Entry 175
    -0x1.0a2b23f3bab73681aed58d6405ec7206p4,
    -0x1.fffffep-1
  },
  { // Entry 176
    0x1.9c041eb20c0617f78d606f27acf69e28p0,
    0x1.fffffep1
  },
  { // Entry 177
    0x1.9c041f7ed8d336afdf77a516075931f4p0,
    0x1.p2
  },
  { // Entry 178
    0x1.9c042118726b889b65f3e3e28e3e4e66p0,
    0x1.000002p2
  },
  { // Entry 179
    0x1.193ea7002585c5e86b1cb66b1832016cp0,
    0x1.fffffep0
  },
  { // Entry 180
    0x1.193ea7aad030a976a4198d55053b7cb5p0,
    0x1.p1
  },
  { // Entry 181
    0x1.193ea90025851b3dc15599f89374611bp0,
    0x1.000002p1
  },
  { // Entry 182
    0x1.62e42eefa39eb35793b211daaa909805p-1,
    0x1.fffffep-1
  },
  { // Entry 183
    0x1.62e42fefa39ef35793c7673007e5ed5ep-1,
    0x1.p0
  },
  { // Entry 184
    0x1.62e431efa39df357947211da3290986fp-1,
    0x1.000002p0
  },
  { // Entry 185
    0x1.9f323d76a42f30f2853c89b7f554a97bp-2,
    0x1.fffffep-2
  },
  { // Entry 186
    0x1.9f323ecbf984bf2b68d766f405221819p-2,
    0x1.p-1
  },
  { // Entry 187
    0x1.9f324176a42e8647db03a6298d08cf83p-2,
    0x1.000002p-1
  },
  { // Entry 188
    0x1.c8ff7ae010085833015383537a710bf7p-3,
    0x1.fffffep-3
  },
  { // Entry 189
    0x1.c8ff7c79a9a21ac25d81ef2ffb9a24aep-3,
    0x1.p-2
  },
  { // Entry 190
    0x1.c8ff7facdcd4aa1e86a3628ed2816e49p-3,
    0x1.000002p-2
  },
  { // Entry 191
    0x1.e270751b92bc7e3985ba2b4eda27e177p-4,
    0x1.fffffep-4
  },
  { // Entry 192
    0x1.e27076e2af2e5e9ea87ffe1fe9e155dbp-4,
    0x1.p-3
  },
  { // Entry 193
    0x1.e2707a70e81187b4c829d7073485c254p-4,
    0x1.000002p-3
  },
  { // Entry 194
    0x1.f0a30a1f34487609a04c201edd1f6224p-5,
    0x1.fffffep-5
  },
  { // Entry 195
    0x1.f0a30c01162a6617cc9716eeb32f131ap-5,
    0x1.p-4
  },
  { // Entry 196
    0x1.f0a30fc4d9edf12a66bd3268f53eb247p-5,
    0x1.000002p-4
  },
  { // Entry 197
    0x1.f829aef70710f587dcdc1e46f5c8fc28p-6,
    0x1.fffffep-6
  },
  { // Entry 198
    0x1.f829b0e7833004cf8fc13c7bc8a7ebabp-6,
    0x1.p-5
  },
  { // Entry 199
    0x1.f829b4c87b6df63c671750b0d49bd0d0p-6,
    0x1.000002p-5
  },
  { // Entry 200
    0x1.fc0a8917a0bc40f9af9b81ceffb6876ap-7,
    0x1.fffffep-7
  },
  { // Entry 201
    0x1.fc0a8b0fc03e3cf9eda74d37abd56df5p-7,
    0x1.p-6
  },
  { // Entry 202
    0x1.fc0a8effff421db6014956cf936c5246p-7,
    0x1.000002p-6
  },
  { // Entry 203
    0x1.fe02a4b4fe886e0adfcd9bf770796795p-8,
    0x1.fffffep-8
  },
  { // Entry 204
    0x1.fe02a6b106788fc37690391dc282d2b3p-8,
    0x1.p-7
  },
  { // Entry 205
    0x1.fe02aaa91658c7641591cbf711392789p-8,
    0x1.000002p-7
  },
  { // Entry 206
    0x1.ff00a82d0ebe01a481bb62141d1d53b5p-9,
    0x1.fffffep-9
  },
  { // Entry 207
    0x1.ff00aa2b10bc04a086b569b4d4b76919p-9,
    0x1.p-8
  },
  { // Entry 208
    0x1.ff00ae2714b804a47ec15f0e31f390edp-9,
    0x1.000002p-8
  },
  { // Entry 209
    0x1.ff80289bb08ea6eb088098a49a71d9d9p-10,
    0x1.fffffep-10
  },
  { // Entry 210
    0x1.ff802a9ab10e678a78e854f8ec6ac72bp-10,
    0x1.p-9
  },
  { // Entry 211
    0x1.ff802e98b20de5cc57794db0a1879185p-10,
    0x1.000002p-9
  },
  { // Entry 212
    0x1.ffc008a92af1037e6d78fd20e4e62f56p-11,
    0x1.fffffep-11
  },
  { // Entry 213
    0x1.ffc00aa8ab10fbc04d051924c9347471p-11,
    0x1.p-10
  },
  { // Entry 214
    0x1.ffc00ea7ab50eac4cbd56964e4284cb6p-11,
    0x1.000002p-10
  },
  { // Entry 215
    0x1.fff7fe2ab9aa310ce6c785f0bd1aefcfp-14,
    0x1.fffffep-14
  },
  { // Entry 216
    0x1.fff8002aa9aab110e6678af0afc3daa4p-14,
    0x1.p-13
  },
  { // Entry 217
    0x1.fff8042a89abb0e8e8a770f314eeb25dp-14,
    0x1.000002p-13
  },
  { // Entry 218
    -0x1.62e433efa3a2f357991cbc8d5d3b4f80p-1,
    -0x1.000002p-1
  },
  { // Entry 219
    -0x1.62e42fefa39ef35793c7673007e5ed5ep-1,
    -0x1.p-1
  },
  { // Entry 220
    -0x1.62e42defa39ff357931cbc85dd3b424dp-1,
    -0x1.fffffep-2
  },
  { // Entry 221
    -0x1.269623bdf864b5bca2aac313becfafc7p-2,
    -0x1.000002p-2
  },
  { // Entry 222
    -0x1.269621134db92783beb7676c0aa9c2a3p-2,
    -0x1.p-2
  },
  { // Entry 223
    -0x1.26961fbdf8640b11f78e514c72f59cb5p-2,
    -0x1.fffffep-3
  },
  { // Entry 224
    -0x1.1178ea6ba2da5a9f4da9ec87413daa29p-3,
    -0x1.000002p-3
  },
  { // Entry 225
    -0x1.1178e8227e47bde338b41fc72de81e3bp-3,
    -0x1.p-3
  },
  { // Entry 226
    -0x1.1178e6fdebfeae36d034bf0026e7ba26p-3,
    -0x1.fffffep-4
  },
  { // Entry 227
    -0x1.08598d7c05c2af150ef0536d3a6bec43p-4,
    -0x1.000002p-4
  },
  { // Entry 228
    -0x1.08598b59e3a0688a3fd9bf503372c12fp-4,
    -0x1.p-4
  },
  { // Entry 229
    -0x1.08598a48d28f60935a04940d6d173246p-4,
    -0x1.fffffep-5
  },
  { // Entry 230
    -0x1.0415daaef8656050097e0aa39f7eb53ep-5,
    -0x1.000002p-5
  },
  { // Entry 231
    -0x1.0415d89e7444470173c75d4d8889de0ep-5,
    -0x1.p-5
  },
  { // Entry 232
    -0x1.0415d7963233c7238cd1a9779dfbd10fp-5,
    -0x1.fffffep-6
  },
  { // Entry 233
    -0x1.02056791560685012dd216873106670ep-6,
    -0x1.000002p-6
  },
  { // Entry 234
    -0x1.020565893584749f23a105b9c7bb9a6fp-6,
    -0x1.p-6
  },
  { // Entry 235
    -0x1.020564852543729f44a720c573005c5fp-6,
    -0x1.fffffep-7
  },
  { // Entry 236
    -0x1.0101595c95f736dd7dddd4f4a84fc30ep-7,
    -0x1.000002p-7
  },
  { // Entry 237
    -0x1.010157588de7128ccc5a82f9da00f48bp-7,
    -0x1.p-7
  },
  { // Entry 238
    -0x1.0101565689df037097f9d05a2038a6fep-7,
    -0x1.fffffep-8
  },
  { // Entry 239
    -0x1.008057978ab55beba0ed4c4e688b0fddp-8,
    -0x1.000002p-8
  },
  { // Entry 240
    -0x1.0080559588b357e598e33d8d9db37a29p-8,
    -0x1.p-8
  },
  { // Entry 241
    -0x1.0080549487b2576599643eb948ddce3cp-8,
    -0x1.fffffep-9
  },
  { // Entry 242
    -0x1.0040175e590a1f9177e773be9c970fbep-9,
    -0x1.000002p-9
  },
  { // Entry 243
    -0x1.0040155d5889de70671eeec0bfcefe53p-9,
    -0x1.p-9
  },
  { // Entry 244
    -0x1.0040145cd849bea09f4b0cbe55e0522ap-9,
    -0x1.fffffep-10
  },
  { // Entry 245
    -0x1.00200756d5a89bb7bd700a29d438709dp-10,
    -0x1.000002p-10
  },
  { // Entry 246
    -0x1.00200556558893357cd7e1f486bd0705p-10,
    -0x1.p-10
  },
  { // Entry 247
    -0x1.0020045615788f548c9dd3ebcc957ecfp-10,
    -0x1.fffffep-11
  },
  { // Entry 248
    -0x1.0004021565d5d89c9efe7d2c354c8573p-13,
    -0x1.000002p-13
  },
  { // Entry 249
    -0x1.0004001555d558889dde702b028c9996p-13,
    -0x1.p-13
  },
  { // Entry 250
    -0x1.0003ff154dd5188a9e0e72ab0936642cp-13,
    -0x1.fffffep-14
  },
  { // Entry 251
    0x1.732426090cb8287b20767f822cff213fp-1,
    0x1.1082aep0
  },
  { // Entry 252
    0x1.732427f90e136dae43644376436d483ap-1,
    0x1.1082b0p0
  },
  { // Entry 253
    0x1.732429e90f6cd25ec74c889c28bbeb0dp-1,
    0x1.1082b2p0
  },
  { // Entry 254
    0x1.73242bd910c4568cafd24e8cbead4f8cp-1,
    0x1.1082b4p0
  },
  { // Entry 255
    0x1.73242dc91219fa38009894d655459f92p-1,
    0x1.1082b6p0
  },
  { // Entry 256
    0x1.73242fb9136dbd60bd425afcaacb11f0p-1,
    0x1.1082b8p0
  },
  { // Entry 257
    0x1.732431a914bfa006e972a078ebc6136bp-1,
    0x1.1082bap0
  },
  { // Entry 258
    -0x1.0000031332fb3170f147bbabd5a5dbe2p-4,
    -0x1.f0540ap-5
  },
  { // Entry 259
    -0x1.00000202b0458e4ed1041496e7335a4dp-4,
    -0x1.f05408p-5
  },
  { // Entry 260
    -0x1.000000f22d8ffd4e110ab2e7abbf098bp-4,
    -0x1.f05406p-5
  },
  { // Entry 261
    -0x1.ffffffc355b4fcdd62b25a0e3f78a172p-5,
    -0x1.f05404p-5
  },
  { // Entry 262
    -0x1.fffffda2504a236163da32bc8033b657p-5,
    -0x1.f05402p-5
  },
  { // Entry 263
    -0x1.fffffb814adf6e2825881cac148330d7p-5,
    -0x1.f054p-5
  },
  { // Entry 264
    -0x1.fffff9604574dd31a7b744aef831786ep-5,
    -0x1.f053fep-5
  },
  { // Entry 265
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 266
    0x1.62e42feba39ef15793c611dab1909808p6,
    0x1.fffffep127
  },
  { // Entry 267
    0x1.62e42fe7a39eeb5793bcbc854d3b429ap6,
    0x1.fffffcp127
  },
  { // Entry 268
    0x1.6bcbed6499137a6d8cb88a3b46fe313bp0,
    0x1.921fb6p1
  },
  { // Entry 269
    0x1.e3703e42b92e44cc4a16c64759347ba9p-1,
    0x1.921fb6p0
  },
  { // Entry 270
    0x1.62e431efa39df357947211da3290986fp-1,
    0x1.000002p0
  },
  { // Entry 271
    0x1.62e42fefa39ef35793c7673007e5ed5ep-1,
    0x1.p0
  },
  { // Entry 272
    -HUGE_VALF,
    -0x1.p0
  },
  { // Entry 273
    0x1.62e42eefa39eb35793b211daaa909805p-1,
    0x1.fffffep-1
  },
  { // Entry 274
    -0x1.0a2b23f3bab73681aed58d6405ec7206p4,
    -0x1.fffffep-1
  },
  { // Entry 275
    0x1.28c6c410c6e97e86ac65cbbaf9be56e1p-1,
    0x1.921fb6p-1
  },
  { // Entry 276
    -0x1.89fa00c1dfad872a5efe4c31eb7dddb5p0,
    -0x1.921fb6p-1
  },
  { // Entry 277
    0x1.000001fffffffffffffffffffffffffdp-126,
    0x1.000002p-126
  },
  { // Entry 278
    -0x1.00000200000000000000000000000002p-126,
    -0x1.000002p-126
  },
  { // Entry 279
    0x1.fffffffffffffffffffffffffffffffcp-127,
    0x1.p-126
  },
  { // Entry 280
    -0x1.00000000000000000000000000000002p-126,
    -0x1.p-126
  },
  { // Entry 281
    0x1.fffffbfffffffffffffffffffffffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 282
    -0x1.fffffc00000000000000000000000003p-127,
    -0x1.fffffcp-127
  },
  { // Entry 283
    0x1.fffff7fffffffffffffffffffffffffcp-127,
    0x1.fffff8p-127
  },
  { // Entry 284
    -0x1.fffff800000000000000000000000003p-127,
    -0x1.fffff8p-127
  },
  { // Entry 285
    0x1.ffffffffffffffffffffffffffffffffp-149,
    0x1.p-148
  },
  { // Entry 286
    -0x1.p-148,
    -0x1.p-148
  },
  { // Entry 287
    0.0f,
    0x1.p-149
  },
  { // Entry 288
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 289
    0.0,
    0.0f
  },
  { // Entry 290
    -0.0,
    -0.0f
  }
};
```
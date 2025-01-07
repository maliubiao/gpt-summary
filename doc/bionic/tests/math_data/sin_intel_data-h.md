Response:
Let's break down the thought process for answering the request about the `sin_intel_data.handroid` file.

**1. Understanding the Core Request:**

The user wants to know the *functionality* of this specific data file within the context of Android's Bionic library. They are particularly interested in its relationship to Android, the implementation of relevant libc functions, dynamic linking aspects, potential errors, how Android reaches this file, and finally, a summary of its function for this first part.

**2. Initial Analysis of the File Content:**

The file contains a C++ array named `g_sin_intel_data`. The array's type is `data_1_1_t<double, double>`. This immediately suggests that the file holds pairs of double-precision floating-point numbers. The naming convention "sin_intel_data" strongly hints at a connection to the sine function and potentially data from Intel. The ".handroid" suffix suggests it's tailored for Android.

**3. Formulating the Core Functionality:**

Based on the name and content, the most logical conclusion is that this file provides *test data* for the sine function implementation in Bionic. This data likely consists of input values and their corresponding expected sine values.

**4. Connecting to Android Functionality:**

Knowing that it's test data for `sin`, the next step is to explain *why* this is relevant to Android. The `sin` function is a fundamental mathematical function used in countless Android applications and system components. Bionic provides this implementation. Therefore, robust testing is crucial for correctness and performance.

* **Example:** Imagine a game that uses trigonometric functions for character movement or physics calculations. Incorrect `sin` results would lead to visual glitches or unexpected behavior.

**5. Addressing Libc Function Implementation:**

The request asks for a detailed explanation of how `libc` functions are implemented. This is where a crucial distinction needs to be made. This *data file* doesn't *implement* the `sin` function. It provides *data for testing* the implementation, which resides in other source files (likely written in C or assembly). It's important to clarify this. We can mention that the actual `sin` implementation involves algorithms like Taylor series expansions or CORDIC, but this file itself is just data.

**6. Dynamic Linker Relevance:**

The request also asks about the dynamic linker. While this specific *data file* isn't directly involved in dynamic linking, it's part of the Bionic library, which *is* dynamically linked. Therefore, it's relevant to briefly explain how shared libraries are loaded and linked.

* **SO Layout:**  Provide a basic example of a `.so` file structure.
* **Linking Process:** Describe the steps involved in resolving symbols at runtime.

**Crucially, acknowledge that this *data file* itself isn't a shared object and doesn't undergo linking.**

**7. Logical Inference (Hypothetical Input/Output):**

Even though this is a data file, we can infer the logic of its usage. The *testing code* will take the input values from the file and compare the calculated `sin` values against the expected output values in the same file.

* **Hypothetical Input:** An input value from the file (e.g., `0x1.9259e3708bd39ffffffffffffff1bdbep-5`).
* **Hypothetical Output:** The corresponding expected sine value (e.g., `0x1.9283586503fe0p-5`).

**8. Common Usage Errors:**

Since this is a *data file*, common errors won't be about *using* this file directly in application code. Instead, they would be related to:

* **Incorrect data:**  Errors in the values within the file itself.
* **Mismatched data:** Input and output values not correctly paired.
* **Incorrect interpretation:** The testing code misinterpreting the data format.

**9. Android Framework/NDK Path and Frida Hook:**

This requires understanding how Android developers might use the `sin` function and how to intercept the usage of this data during testing.

* **Framework/NDK Path:** Explain that applications using the NDK's math library will eventually call the Bionic `sin` implementation.
* **Frida Hook:** Provide a basic Frida script example to intercept calls to a hypothetical `sin` test function and log the input/output data being used. It's important to emphasize that you can't directly hook the *data*, but you can hook the code that *uses* the data.

**10. Summarizing the Functionality (Part 1):**

Finally, provide a concise summary based on the previous points. Emphasize that the file's primary role is to serve as test data for the `sin` function in Bionic.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Could this file be involved in the actual calculation of `sin`?  **Correction:** No, the format and naming suggest it's for *testing*, not implementation.
* **Initial thought:**  Focus heavily on dynamic linking mechanisms. **Correction:**  While relevant to Bionic, this specific file isn't a linked object. Keep the dynamic linking explanation concise and focused on the overall context.
* **Initial thought:**  Provide very detailed explanations of `sin` algorithm implementations. **Correction:**  The request is about this *data file*. Mentioning the existence of algorithms is enough.
* **Frida example complexity:**  Start with a simple hook that demonstrates the concept. Avoid overly complex scripts.

By following this structured thought process and refining assumptions along the way, we can arrive at a comprehensive and accurate answer to the user's request. The key is to focus on the specific role of the *data file* while providing relevant context about the Bionic library and the Android ecosystem.
好的，让我们来分析一下 `bionic/tests/math_data/sin_intel_data.handroid` 这个源代码文件（第一部分）。

**功能归纳 (针对第一部分):**

这个文件的主要功能是**为 Android Bionic 库中的 `sin` 函数提供测试数据**。

具体来说，它包含一个名为 `g_sin_intel_data` 的静态数组，该数组的元素类型是 `data_1_1_t<double, double>`。每个元素都是一个结构体，包含两个 `double` 类型的数值。  这些数值对很可能代表了：

* **第一个 `double` 值:**  `sin` 函数的**输入值** (以十六进制浮点数表示)。
* **第二个 `double` 值:**  对于给定输入值的 `sin` 函数的**预期输出值** (以十六进制浮点数表示)。

文件名中的 "intel_data" 可能意味着这些测试数据是基于 Intel 处理器上的 `sin` 函数实现或测试结果生成的，或者旨在测试 Bionic 的 `sin` 函数在处理类似 Intel 实现的数据时的兼容性。 ".handroid" 后缀则明确表示这是 Android 平台的测试数据。

**与 Android 功能的关系及举例说明:**

这个文件是 Android 系统底层库 Bionic 的一部分，直接关系到 Android 平台上所有需要计算正弦值的操作。

* **Android Framework:** Android Framework 中许多组件可能会间接或直接使用到 `sin` 函数。例如，动画框架在计算动画轨迹时可能使用三角函数；图形渲染引擎 (如 Skia) 在处理图形变换时也会用到。虽然 Framework 通常不会直接调用 Bionic 的 `sin` 函数，而是通过上层库（如 Java 的 `Math.sin()`，最终会调用到 Native 代码），但 Bionic 的正确性是至关重要的。
* **Android NDK:**  使用 NDK 开发的应用可以直接调用 Bionic 提供的数学函数，包括 `sin`。例如，一个游戏引擎使用 C++ 开发，需要进行复杂的物理模拟，其中就可能频繁调用 `sin` 函数。如果这个测试数据覆盖了各种边界情况和精度要求，就能确保 NDK 应用的数学计算的准确性。

**libc 函数的功能实现 (在这个文件中不适用):**

这个文件本身 **并不实现任何 libc 函数**。它是一个静态数据文件，用于测试 `sin` 函数的实现。 `sin` 函数的实际实现代码位于 Bionic 库的其他源文件中（通常是 C 或汇编语言）。

如果需要解释 `sin` 函数的实现，通常会涉及到以下概念：

* **区间归约 (Range Reduction):**  将任意大小的输入值归约到一个较小的、易于计算的区间（例如，[-π/4, π/4]）。这通常利用三角函数的周期性和对称性。
* **多项式逼近 (Polynomial Approximation):**  在归约后的区间内，使用多项式（例如，泰勒级数或 minimax 多项式）来逼近 `sin` 函数的值。
* **查找表 (Lookup Tables):** 对于某些平台或特定的精度要求，可能会使用预先计算好的查找表来加速计算。
* **硬件加速:** 某些架构提供了硬件级别的浮点运算单元，可以直接执行 `sin` 指令。

**Dynamic Linker 的功能 (在这个文件中不适用，但 Bionic 整体涉及):**

这个文件本身也不是一个动态链接库 (`.so` 文件)，因此不涉及动态链接器的直接处理。然而，作为 Bionic 库的一部分，它会被编译到 Bionic 的数学库中，该数学库会以动态链接库的形式加载到进程空间。

* **SO 布局样本:**
   ```
   libm.so (Bionic 的数学库)
   |-- .text      (代码段，包含 sin 等函数的机器码)
   |-- .data      (已初始化的全局变量，可能包含一些常量)
   |-- .rodata    (只读数据，很可能包含 g_sin_intel_data)
   |-- .bss       (未初始化的全局变量)
   |-- .dynsym    (动态符号表)
   |-- .dynstr    (动态字符串表)
   |-- .rel.dyn   (动态重定位表)
   |-- ...
   ```
   `g_sin_intel_data` 很可能被放置在 `.rodata` 段中，因为它是一个只读的测试数据数组。

* **链接的处理过程:**
    1. **编译时:**  包含 `g_sin_intel_data` 的源文件被编译成目标文件 (`.o`)。
    2. **链接时:**  链接器将多个目标文件以及所需的库文件组合成一个共享对象 (`.so`)，例如 `libm.so`。链接器会解析符号引用，例如 `sin` 函数的定义和 `g_sin_intel_data` 的地址。
    3. **运行时:** 当一个 Android 应用启动并需要使用 `sin` 函数时，动态链接器 (如 `linker64` 或 `linker`) 会负责加载 `libm.so` 到进程的内存空间。动态链接器会根据 `.dynsym` 和 `.rel.dyn` 中的信息，将 `sin` 函数的调用地址和 `g_sin_intel_data` 的地址绑定到正确的内存位置。

**逻辑推理 (假设输入与输出):**

假设测试代码会遍历 `g_sin_intel_data` 数组：

* **假设输入:**  测试代码从数组中读取一个输入值，例如 `0x1.a1490c8c06ba6fffffffffffffa98611p-4`。
* **预期输出:** 测试代码会期望 `sin` 函数对于该输入值的计算结果与数组中对应的输出值 `0x1.a202b3fb84788p-4` 相匹配（或在一定的误差范围内）。

**用户或编程常见的使用错误 (与此文件间接相关):**

虽然用户不会直接使用这个数据文件，但与 `sin` 函数相关的常见错误包括：

* **精度问题:**  浮点数运算本身存在精度限制。用户可能期望得到无限精确的结果，但实际计算结果可能存在舍入误差。
* **输入范围错误:**  `sin` 函数的输入是弧度值。用户可能错误地使用了角度值，导致计算结果不正确。
* **未处理特殊值:**  例如，对于非常大或非常小的输入值，`sin` 函数的实现可能需要特殊处理，否则可能导致溢出或精度丢失。测试数据会覆盖这些边界情况。
* **误用库函数:** 用户可能在没有正确链接数学库的情况下调用 `sin` 函数，导致链接错误。

**Android Framework 或 NDK 如何到达这里 (Frida Hook 示例):**

1. **应用层 (Java/Kotlin):** 一个 Android 应用可能调用 `java.lang.Math.sin(double a)`。
2. **Framework 层:** `Math.sin()` 方法最终会调用到 Native 代码。
3. **NDK/Bionic 层:** NDK 中提供的 `math.h` 头文件声明了 `sin()` 函数，该函数在 Bionic 的 `libm.so` 中实现。当应用调用 NDK 的 `sin()` 时，实际上会调用 `libm.so` 中的实现。
4. **测试阶段:** 在 Bionic 的测试阶段，测试代码会读取 `bionic/tests/math_data/sin_intel_data.handroid` 文件中的数据，并用这些输入值调用 Bionic 的 `sin` 函数实现，然后将计算结果与文件中预期的输出值进行比较。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 来观察测试代码如何使用 `g_sin_intel_data` 的示例（需要假设存在一个测试函数 `test_sin_with_data`）：

```javascript
// 假设测试代码的 so 库名称为：libbionic_tests.so

// 找到加载了测试数据的库
const libbionicTests = Process.getModuleByName("libbionic_tests.so");

// 假设测试函数名为 test_sin_with_data，它可能接受输入值和预期输出值
// 需要根据实际的测试代码来确定函数签名和参数
const testSinWithData = libbionicTests.findExportByName("test_sin_with_data");

if (testSinWithData) {
  Interceptor.attach(testSinWithData, {
    onEnter: function(args) {
      // 假设第一个参数是输入值，第二个参数是预期输出值
      const input = args[0].toDouble();
      const expectedOutput = args[1].toDouble();
      console.log(`[+] Calling test_sin_with_data with input: ${input}, expected output: ${expectedOutput}`);
    },
    onLeave: function(retval) {
      console.log(`[+] test_sin_with_data returned: ${retval}`);
    }
  });
  console.log("[+] Hooked test_sin_with_data");
} else {
  console.log("[-] test_sin_with_data function not found");
}

// 如果需要更细粒度的观察，例如直接观察数组数据的访问，
// 则需要分析测试代码的实现细节，找到访问 g_sin_intel_data 的地址
// 并 hook 该地址的读取操作 (可能需要更底层的 hook 技术)
```

**总结 (针对第一部分):**

`bionic/tests/math_data/sin_intel_data.handroid` (第一部分) 的核心功能是作为 Android Bionic 库中 `sin` 函数的测试数据来源。它包含了一系列预定义的输入值和对应的预期输出值，用于验证 `sin` 函数实现的正确性和精度。这个文件是 Bionic 库质量保证的关键组成部分，间接地影响着所有 Android 平台上需要计算正弦值的应用和系统组件。

请继续提供后续部分，我会尽力分析。

Prompt: 
```
这是目录为bionic/tests/math_data/sin_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共5部分，请归纳一下它的功能

"""
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

static data_1_1_t<double, double> g_sin_intel_data[] = {
  { // Entry 0
    0x1.9259e3708bd39ffffffffffffff1bdbep-5,
    0x1.9283586503fe0p-5
  },
  { // Entry 1
    -0x1.9259e3708bd39ffffffffffffff1bdbep-5,
    -0x1.9283586503fe0p-5
  },
  { // Entry 2
    0x1.d77b117f230d5ffffffffffffff2adc7p-5,
    0x1.d7bdcd778049fp-5
  },
  { // Entry 3
    -0x1.d77b117f230d5ffffffffffffff2adc7p-5,
    -0x1.d7bdcd778049fp-5
  },
  { // Entry 4
    0x1.a1490c8c06ba6fffffffffffffa98611p-4,
    0x1.a202b3fb84788p-4
  },
  { // Entry 5
    -0x1.a1490c8c06ba6fffffffffffffa98611p-4,
    -0x1.a202b3fb84788p-4
  },
  { // Entry 6
    0x1.cc40c3805229a7ffffffffffff83e76bp-3,
    0x1.d037cb27ee6dfp-3
  },
  { // Entry 7
    -0x1.cc40c3805229a7ffffffffffff83e76bp-3,
    -0x1.d037cb27ee6dfp-3
  },
  { // Entry 8
    0x1.d0ef799001ba900000000000005ea4e9p-3,
    0x1.d5064e6fe82c5p-3
  },
  { // Entry 9
    -0x1.d0ef799001ba900000000000005ea4e9p-3,
    -0x1.d5064e6fe82c5p-3
  },
  { // Entry 10
    0x1.e9950730c4695ffffffffffffffffc2ep-2,
    0x1.fe767739d0f6dp-2
  },
  { // Entry 11
    -0x1.e9950730c4695ffffffffffffffffc2ep-2,
    -0x1.fe767739d0f6dp-2
  },
  { // Entry 12
    0x1.98dcd093377928000000000000167dc7p-1,
    0x1.d98c4c612718dp-1
  },
  { // Entry 13
    -0x1.98dcd093377928000000000000167dc7p-1,
    -0x1.d98c4c612718dp-1
  },
  { // Entry 14
    0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.921fb54442d18p0
  },
  { // Entry 15
    -0x1.ffffffffffffffffffffffffffec8831p-1,
    -0x1.921fb54442d18p0
  },
  { // Entry 16
    0x1.70a9d825b506400422155aecd519d54cp-1,
    -0x1.0000001f8p500
  },
  { // Entry 17
    -0x1.70a9d825b506400422155aecd519d54cp-1,
    0x1.0000001f8p500
  },
  { // Entry 18
    0x1.bf3980c6c1e9f4496795f4ce535016b6p-1,
    -0x1.00c0bf8p700
  },
  { // Entry 19
    -0x1.bf3980c6c1e9f4496795f4ce535016b6p-1,
    0x1.00c0bf8p700
  },
  { // Entry 20
    0x1.d62899d48b4397fb275ba44095971364p-4,
    -0x1.13fffffffff80p6
  },
  { // Entry 21
    -0x1.d62899d48b4397fb275ba44095971364p-4,
    0x1.13fffffffff80p6
  },
  { // Entry 22
    -0x1.17b7a60ce1f1485824711523ab0fd6d1p-5,
    -0x1.17c5920767dfcp-5
  },
  { // Entry 23
    0x1.17b7a60ce1f1485824711523ab0fd6d1p-5,
    0x1.17c5920767dfcp-5
  },
  { // Entry 24
    0x1.f0192b794fbbe030fe25edf65a5db9bfp-1,
    -0x1.1d99be08713ccp2
  },
  { // Entry 25
    -0x1.f0192b794fbbe030fe25edf65a5db9bfp-1,
    0x1.1d99be08713ccp2
  },
  { // Entry 26
    -0x1.5e61328c0034ec3a05d053b72e2d5945p-3,
    -0x1.1ddbfd64fc0d3p81
  },
  { // Entry 27
    0x1.5e61328c0034ec3a05d053b72e2d5945p-3,
    0x1.1ddbfd64fc0d3p81
  },
  { // Entry 28
    0x1.fb028c5df1db3eb32b0062c6cd4dea0bp-1,
    -0x1.1e2a1563e068ep7
  },
  { // Entry 29
    -0x1.fb028c5df1db3eb32b0062c6cd4dea0bp-1,
    0x1.1e2a1563e068ep7
  },
  { // Entry 30
    -0x1.2cefb196ba2077fffffd4bd650722bfbp-3,
    -0x1.2e07a91314dp-3
  },
  { // Entry 31
    0x1.2cefb196ba2077fffffd4bd650722bfbp-3,
    0x1.2e07a91314dp-3
  },
  { // Entry 32
    0x1.b80f489d3edf4835de7deeeb5bb38ad9p-2,
    -0x1.3bcec270444e2p3
  },
  { // Entry 33
    -0x1.b80f489d3edf4835de7deeeb5bb38ad9p-2,
    0x1.3bcec270444e2p3
  },
  { // Entry 34
    -0x1.4fffffffffa38800000004dd22ccccccp-20,
    -0x1.5000000000040p-20
  },
  { // Entry 35
    0x1.4fffffffffa38800000004dd22ccccccp-20,
    0x1.5000000000040p-20
  },
  { // Entry 36
    -0x1.d29da5b44f51b7fc019f183e1d3bd511p-2,
    -0x1.559001a42d90cp1
  },
  { // Entry 37
    0x1.d29da5b44f51b7fc019f183e1d3bd511p-2,
    0x1.559001a42d90cp1
  },
  { // Entry 38
    -0x1.f85f526147f787fffff15241e719734bp-1,
    -0x1.597bf3e9776b7p99
  },
  { // Entry 39
    0x1.f85f526147f787fffff15241e719734bp-1,
    0x1.597bf3e9776b7p99
  },
  { // Entry 40
    -0x1.6d61b58c99c42f1396af4a42148f73c6p-59,
    -0x1.6c6cbc45dc8dep7
  },
  { // Entry 41
    0x1.6d61b58c99c42f1396af4a42148f73c6p-59,
    0x1.6c6cbc45dc8dep7
  },
  { // Entry 42
    0x1.e5c3c08a258a77f1d12efa8c30166709p-1,
    -0x1.73d8d173f90d0p4
  },
  { // Entry 43
    -0x1.e5c3c08a258a77f1d12efa8c30166709p-1,
    0x1.73d8d173f90d0p4
  },
  { // Entry 44
    0x1.feb36806ca5fb7ea442119af41be0f4fp-1,
    -0x1.8c202d3a31802p6
  },
  { // Entry 45
    -0x1.feb36806ca5fb7ea442119af41be0f4fp-1,
    0x1.8c202d3a31802p6
  },
  { // Entry 46
    -0x1.7c6c7b01b98d947cd8add5e5d1ae11cap-1,
    -0x1.acd538b1a6d5dp-1
  },
  { // Entry 47
    0x1.7c6c7b01b98d947cd8add5e5d1ae11cap-1,
    0x1.acd538b1a6d5dp-1
  },
  { // Entry 48
    -0x1.191be2059dcb57fed86dd2cc62eb1a9fp-1,
    -0x1.b7525ac97e0d2p2
  },
  { // Entry 49
    0x1.191be2059dcb57fed86dd2cc62eb1a9fp-1,
    0x1.b7525ac97e0d2p2
  },
  { // Entry 50
    -0x1.f8305993a212c7fffffc15c2afa5e57ep-1,
    -0x1.bee5fa8a84b02p0
  },
  { // Entry 51
    0x1.f8305993a212c7fffffc15c2afa5e57ep-1,
    0x1.bee5fa8a84b02p0
  },
  { // Entry 52
    0x1.ff3b13530fd70e72b77f7c6721da1131p-1,
    -0x1.c393979fe5921p9
  },
  { // Entry 53
    -0x1.ff3b13530fd70e72b77f7c6721da1131p-1,
    0x1.c393979fe5921p9
  },
  { // Entry 54
    -0x1.f119da81a4da57ffd8bcc5a1247f5590p-1,
    -0x1.c48ffc72563c8p18
  },
  { // Entry 55
    0x1.f119da81a4da57ffd8bcc5a1247f5590p-1,
    0x1.c48ffc72563c8p18
  },
  { // Entry 56
    -0x1.fd73b81e04ccc7e9d764eca8bb085109p-1,
    -0x1.c79548bc31856p3
  },
  { // Entry 57
    0x1.fd73b81e04ccc7e9d764eca8bb085109p-1,
    0x1.c79548bc31856p3
  },
  { // Entry 58
    -0x1.c7885aef33a94ffc5ae06be9444efad5p-3,
    -0x1.cb6p-3
  },
  { // Entry 59
    0x1.c7885aef33a94ffc5ae06be9444efad5p-3,
    0x1.cb6p-3
  },
  { // Entry 60
    -0x1.e6494911eedd08d1650a4b5136c3e6d6p-7,
    -0x1.e64ddaf7bd72fp-7
  },
  { // Entry 61
    0x1.e6494911eedd08d1650a4b5136c3e6d6p-7,
    0x1.e64ddaf7bd72fp-7
  },
  { // Entry 62
    0x1.e180eef5b1c887fff585594949b46e6cp-1,
    -0x1.ecdd0fbf07942p5
  },
  { // Entry 63
    -0x1.e180eef5b1c887fff585594949b46e6cp-1,
    0x1.ecdd0fbf07942p5
  },
  { // Entry 64
    -0x1.fd98d20c1be4380000001ee51562d7a8p-1,
    -0x1.f073a23292337p2
  },
  { // Entry 65
    0x1.fd98d20c1be4380000001ee51562d7a8p-1,
    0x1.f073a23292337p2
  },
  { // Entry 66
    -0x1.7268c112297c87d17633bab722f31a3fp-5,
    -0x1.f5e4c410f4ef8p15
  },
  { // Entry 67
    0x1.7268c112297c87d17633bab722f31a3fp-5,
    0x1.f5e4c410f4ef8p15
  },
  { // Entry 68
    0x1.420796146070e628c19d38d1e90df228p-18,
    -0x1.f8000000002p95
  },
  { // Entry 69
    -0x1.420796146070e628c19d38d1e90df228p-18,
    0x1.f8000000002p95
  },
  { // Entry 70
    -0x1.e4f6dc499d9cc8035607fa3d76f9f4c5p-2,
    -0x1.f9365d79546e1p-2
  },
  { // Entry 71
    0x1.e4f6dc499d9cc8035607fa3d76f9f4c5p-2,
    0x1.f9365d79546e1p-2
  },
  { // Entry 72
    0x1.b2ef99b140d650468aed82fe0d442adap-14,
    -0x1.ffffffffffe7ep1023
  },
  { // Entry 73
    -0x1.b2ef99b140d650468aed82fe0d442adap-14,
    0x1.ffffffffffe7ep1023
  },
  { // Entry 74
    0x1.db0ffc3ecc6e3b8e37357ca002d5625bp-1,
    0x1.0p15
  },
  { // Entry 75
    -0x1.db0ffc3ecc6e3b8e37357ca002d5625bp-1,
    -0x1.0p15
  },
  { // Entry 76
    -0x1.e98f87098b62699ad16e0259b0e85b24p-1,
    0x1.0000000000001p13
  },
  { // Entry 77
    0x1.e98f87098b62699ad16e0259b0e85b24p-1,
    -0x1.0000000000001p13
  },
  { // Entry 78
    0x1.053c35068e10d45ee50f2d1ddcabcf3dp-4,
    0x1.0000000000001p52
  },
  { // Entry 79
    -0x1.053c35068e10d45ee50f2d1ddcabcf3dp-4,
    -0x1.0000000000001p52
  },
  { // Entry 80
    0x1.72d421b6884e500bbd3a9efc0f0ced92p-1,
    0x1.0000000000001p228
  },
  { // Entry 81
    -0x1.72d421b6884e500bbd3a9efc0f0ced92p-1,
    -0x1.0000000000001p228
  },
  { // Entry 82
    0x1.77fba987c56533a665e88e5a592ca10cp-1,
    0x1.0000000000001p491
  },
  { // Entry 83
    -0x1.77fba987c56533a665e88e5a592ca10cp-1,
    -0x1.0000000000001p491
  },
  { // Entry 84
    -0x1.723b2625331af2e79a9f07145a1e5731p-1,
    0x1.0000000000003p215
  },
  { // Entry 85
    0x1.723b2625331af2e79a9f07145a1e5731p-1,
    -0x1.0000000000003p215
  },
  { // Entry 86
    0x1.aed548f090cf47fe7e32103ab140caf8p-1,
    0x1.0000000000006p0
  },
  { // Entry 87
    -0x1.aed548f090cf47fe7e32103ab140caf8p-1,
    -0x1.0000000000006p0
  },
  { // Entry 88
    -0x1.ff983208c7dc978079174b461b3809f0p-1,
    0x1.0000000000007p8
  },
  { // Entry 89
    0x1.ff983208c7dc978079174b461b3809f0p-1,
    -0x1.0000000000007p8
  },
  { // Entry 90
    0x1.ffef29dc38452ffef4a779a1f86707dap-1,
    0x1.0000000000007p275
  },
  { // Entry 91
    -0x1.ffef29dc38452ffef4a779a1f86707dap-1,
    -0x1.0000000000007p275
  },
  { // Entry 92
    -0x1.fa88c375723c0d7ea1f2d08ebb2f9407p-8,
    0x1.0000000000007p449
  },
  { // Entry 93
    0x1.fa88c375723c0d7ea1f2d08ebb2f9407p-8,
    -0x1.0000000000007p449
  },
  { // Entry 94
    0x1.fff5322c94eae1b0b51086c08faa585cp-1,
    0x1.0000000000011p644
  },
  { // Entry 95
    -0x1.fff5322c94eae1b0b51086c08faa585cp-1,
    -0x1.0000000000011p644
  },
  { // Entry 96
    -0x1.a73630af8f15b8000054ddd950bba107p-1,
    0x1.000000000001fp164
  },
  { // Entry 97
    0x1.a73630af8f15b8000054ddd950bba107p-1,
    -0x1.000000000001fp164
  },
  { // Entry 98
    0x1.1c548f9249e4474988646b86894e9581p-2,
    0x1.0000000000038p380
  },
  { // Entry 99
    -0x1.1c548f9249e4474988646b86894e9581p-2,
    -0x1.0000000000038p380
  },
  { // Entry 100
    0x1.ca965bd2c4dfee4779ca8c797806292dp-3,
    0x1.0000000000118p380
  },
  { // Entry 101
    -0x1.ca965bd2c4dfee4779ca8c797806292dp-3,
    -0x1.0000000000118p380
  },
  { // Entry 102
    -0x1.837b9dddc24cf2f729a38147795b18d2p-1,
    0x1.000000000012cp2
  },
  { // Entry 103
    0x1.837b9dddc24cf2f729a38147795b18d2p-1,
    -0x1.000000000012cp2
  },
  { // Entry 104
    0x1.d82c1784c3ecbfefb02d7d6b585f73c4p-2,
    0x1.00000000001f8p700
  },
  { // Entry 105
    -0x1.d82c1784c3ecbfefb02d7d6b585f73c4p-2,
    -0x1.00000000001f8p700
  },
  { // Entry 106
    0x1.fffeaaaaef2ee7ee876f90b70b512475p-8,
    0x1.00000000002p-7
  },
  { // Entry 107
    -0x1.fffeaaaaef2ee7ee876f90b70b512475p-8,
    -0x1.00000000002p-7
  },
  { // Entry 108
    -0x1.0871bddd90fc5834034ee3f6f86b43a3p-1,
    0x1.00000000002p40
  },
  { // Entry 109
    0x1.0871bddd90fc5834034ee3f6f86b43a3p-1,
    -0x1.00000000002p40
  },
  { // Entry 110
    0x1.fffeaaaaef2f07ee476fa60c5dbe4886p-8,
    0x1.0000000000201p-7
  },
  { // Entry 111
    -0x1.fffeaaaaef2f07ee476fa60c5dbe4886p-8,
    -0x1.0000000000201p-7
  },
  { // Entry 112
    0x1.fffeaaaaef3307e6477250b6ab524ab7p-8,
    0x1.0000000000221p-7
  },
  { // Entry 113
    -0x1.fffeaaaaef3307e6477250b6ab524ab7p-8,
    -0x1.0000000000221p-7
  },
  { // Entry 114
    0x1.fffeaaaaef3627e00774660bb7d7a87cp-8,
    0x1.000000000023ap-7
  },
  { // Entry 115
    -0x1.fffeaaaaef3627e00774660bb7d7a87cp-8,
    -0x1.000000000023ap-7
  },
  { // Entry 116
    0x1.e0c6edfa9360159534def713925f126fp-9,
    0x1.00000000040p45
  },
  { // Entry 117
    -0x1.e0c6edfa9360159534def713925f126fp-9,
    -0x1.00000000040p45
  },
  { // Entry 118
    0x1.ea1f618356db0d3ab66d0ef6493bc93dp-5,
    0x1.0000000c0p40
  },
  { // Entry 119
    -0x1.ea1f618356db0d3ab66d0ef6493bc93dp-5,
    -0x1.0000000c0p40
  },
  { // Entry 120
    0x1.faaeed7587541fffff9922ba6690b8bap-3,
    0x1.00000013c86f4p-2
  },
  { // Entry 121
    -0x1.faaeed7587541fffff9922ba6690b8bap-3,
    -0x1.00000013c86f4p-2
  },
  { // Entry 122
    0x1.540bc7785680ac2ca169ff9e3cc4b152p-1,
    0x1.001p13
  },
  { // Entry 123
    -0x1.540bc7785680ac2ca169ff9e3cc4b152p-1,
    -0x1.001p13
  },
  { // Entry 124
    -0x1.37a7cb907a2e500106b04d9e3f0b1b8cp-1,
    0x1.003p699
  },
  { // Entry 125
    0x1.37a7cb907a2e500106b04d9e3f0b1b8cp-1,
    -0x1.003p699
  },
  { // Entry 126
    -0x1.29e5845fc54b580145273f2cafe73ab5p-1,
    0x1.00380p40
  },
  { // Entry 127
    0x1.29e5845fc54b580145273f2cafe73ab5p-1,
    -0x1.00380p40
  },
  { // Entry 128
    0x1.ffe5ca46564917a1e812aedd48fe107cp-1,
    0x1.007p10
  },
  { // Entry 129
    -0x1.ffe5ca46564917a1e812aedd48fe107cp-1,
    -0x1.007p10
  },
  { // Entry 130
    0x1.ea4df82db014ac0c913465da57b6a643p-1,
    0x1.007p25
  },
  { // Entry 131
    -0x1.ea4df82db014ac0c913465da57b6a643p-1,
    -0x1.007p25
  },
  { // Entry 132
    0x1.fe757aef1c80c7ec16003d3ae5f0ce15p-1,
    0x1.007p41
  },
  { // Entry 133
    -0x1.fe757aef1c80c7ec16003d3ae5f0ce15p-1,
    -0x1.007p41
  },
  { // Entry 134
    0x1.e9b71805ec0685d484f6270f6411dc36p-7,
    0x1.00cp41
  },
  { // Entry 135
    -0x1.e9b71805ec0685d484f6270f6411dc36p-7,
    -0x1.00cp41
  },
  { // Entry 136
    0x1.b0b6d0a54058280008e80488f8ab1bb7p-1,
    0x1.01c00000001p0
  },
  { // Entry 137
    -0x1.b0b6d0a54058280008e80488f8ab1bb7p-1,
    -0x1.01c00000001p0
  },
  { // Entry 138
    0x1.fef009262701280b92aaf925dda63bbap-3,
    0x1.02322e46da919p-2
  },
  { // Entry 139
    -0x1.fef009262701280b92aaf925dda63bbap-3,
    -0x1.02322e46da919p-2
  },
  { // Entry 140
    0x1.ffc90059804a082d9b3f46b77ee81932p-3,
    0x1.02a236478p-2
  },
  { // Entry 141
    -0x1.ffc90059804a082d9b3f46b77ee81932p-3,
    -0x1.02a236478p-2
  },
  { // Entry 142
    0x1.ffd10a6b5429e828bef4d9413eb9f6c0p-3,
    0x1.02a65d08ca5e5p-2
  },
  { // Entry 143
    -0x1.ffd10a6b5429e828bef4d9413eb9f6c0p-3,
    -0x1.02a65d08ca5e5p-2
  },
  { // Entry 144
    0x1.ffd10ab302a3f7e0a048db5861e7b20bp-3,
    0x1.02a65d2dce49ap-2
  },
  { // Entry 145
    -0x1.ffd10ab302a3f7e0a048db5861e7b20bp-3,
    -0x1.02a65d2dce49ap-2
  },
  { // Entry 146
    0x1.ffe0b1764ca4c7d2329433828cdc901cp-3,
    0x1.02ae7238ap-2
  },
  { // Entry 147
    -0x1.ffe0b1764ca4c7d2329433828cdc901cp-3,
    -0x1.02ae7238ap-2
  },
  { // Entry 148
    -0x1.f68f0e26c0f6ad44f7184d56be95e1aep-3,
    0x1.0501d22221dacp621
  },
  { // Entry 149
    0x1.f68f0e26c0f6ad44f7184d56be95e1aep-3,
    -0x1.0501d22221dacp621
  },
  { // Entry 150
    0x1.b63c41f09eb747f30c1af5f254340a4cp-1,
    0x1.06ffffffffff8p0
  },
  { // Entry 151
    -0x1.b63c41f09eb747f30c1af5f254340a4cp-1,
    -0x1.06ffffffffff8p0
  },
  { // Entry 152
    -0x1.ffdc173adabb1afd58fcb5643cd86562p-1,
    0x1.07023d3d44215p12
  },
  { // Entry 153
    0x1.ffdc173adabb1afd58fcb5643cd86562p-1,
    -0x1.07023d3d44215p12
  },
  { // Entry 154
    0x1.0889e11bef1357a88742ab3a7f180786p-5,
    0x1.0895a7a3e8ae6p-5
  },
  { // Entry 155
    -0x1.0889e11bef1357a88742ab3a7f180786p-5,
    -0x1.0895a7a3e8ae6p-5
  },
  { // Entry 156
    0x1.08ca077c764457aa6d968afc1d1b17b3p-5,
    0x1.08d5d69840601p-5
  },
  { // Entry 157
    -0x1.08ca077c764457aa6d968afc1d1b17b3p-5,
    -0x1.08d5d69840601p-5
  },
  { // Entry 158
    -0x1.ff7fbe518023e90b3f28f81ab93e872fp-1,
    0x1.0e0p6
  },
  { // Entry 159
    0x1.ff7fbe518023e90b3f28f81ab93e872fp-1,
    -0x1.0e0p6
  },
  { // Entry 160
    -0x1.fd6c68b877afe803aaab2bd30124ecdfp-1,
    0x1.107ba49c346e4p9
  },
  { // Entry 161
    0x1.fd6c68b877afe803aaab2bd30124ecdfp-1,
    -0x1.107ba49c346e4p9
  },
  { // Entry 162
    -0x1.a2ba6bc70bce4801ea4d1c85f116193dp-1,
    0x1.1491544774440p745
  },
  { // Entry 163
    0x1.a2ba6bc70bce4801ea4d1c85f116193dp-1,
    -0x1.1491544774440p745
  },
  { // Entry 164
    0x1.165609790f23484a4701b4439d4fe51fp-5,
    0x1.1663c0e518180p-5
  },
  { // Entry 165
    -0x1.165609790f23484a4701b4439d4fe51fp-5,
    -0x1.1663c0e518180p-5
  },
  { // Entry 166
    -0x1.fc0523ff94e44c01731e45963034cba8p-1,
    0x1.1745d1745d176p238
  },
  { // Entry 167
    0x1.fc0523ff94e44c01731e45963034cba8p-1,
    -0x1.1745d1745d176p238
  },
  { // Entry 168
    0x1.f34a729c584bcc9666402cfdb48839ffp-1,
    0x1.17472a408a3e0p97
  },
  { // Entry 169
    -0x1.f34a729c584bcc9666402cfdb48839ffp-1,
    -0x1.17472a408a3e0p97
  },
  { // Entry 170
    0x1.177fae169fdf0858b1d4e7bad69981dcp-5,
    0x1.178d91b6b992dp-5
  },
  { // Entry 171
    -0x1.177fae169fdf0858b1d4e7bad69981dcp-5,
    -0x1.178d91b6b992dp-5
  },
  { // Entry 172
    0x1.177fae16a120e85843d1dfef36726cecp-5,
    0x1.178d91b6bad4ep-5
  },
  { // Entry 173
    -0x1.177fae16a120e85843d1dfef36726cecp-5,
    -0x1.178d91b6bad4ep-5
  },
  { // Entry 174
    0x1.177fae16a1f78856637cc9da8aaf6439p-5,
    0x1.178d91b6bbabap-5
  },
  { // Entry 175
    -0x1.177fae16a1f78856637cc9da8aaf6439p-5,
    -0x1.178d91b6bbabap-5
  },
  { // Entry 176
    0x1.177fae16a40fe858da1ddcb583bb9f3bp-5,
    0x1.178d91b6bdc45p-5
  },
  { // Entry 177
    -0x1.177fae16a40fe858da1ddcb583bb9f3bp-5,
    -0x1.178d91b6bdc45p-5
  },
  { // Entry 178
    0x1.297c768f2413080002edcb9a905946afp-1,
    0x1.19752dbee5f6ap933
  },
  { // Entry 179
    -0x1.297c768f2413080002edcb9a905946afp-1,
    -0x1.19752dbee5f6ap933
  },
  { // Entry 180
    0x1.b826df5cafafa824779bb808d64de6fbp-2,
    0x1.1b3009cfe4dbcp8
  },
  { // Entry 181
    -0x1.b826df5cafafa824779bb808d64de6fbp-2,
    -0x1.1b3009cfe4dbcp8
  },
  { // Entry 182
    0x1.b7a5956250b6a83882133bbe14c847ccp-2,
    0x1.1f6475d95bf18p3
  },
  { // Entry 183
    -0x1.b7a5956250b6a83882133bbe14c847ccp-2,
    -0x1.1f6475d95bf18p3
  },
  { // Entry 184
    0x1.4db6566b645477ffea9faaf8bf463a1ep-1,
    0x1.229148a452291p118
  },
  { // Entry 185
    -0x1.4db6566b645477ffea9faaf8bf463a1ep-1,
    -0x1.229148a452291p118
  },
  { // Entry 186
    0x1.1686fee2c49a7fffb68df681b2da7e49p-1,
    0x1.268p-1
  },
  { // Entry 187
    -0x1.1686fee2c49a7fffb68df681b2da7e49p-1,
    -0x1.268p-1
  },
  { // Entry 188
    0x1.22eb21a44d62780000031ae43c448511p-2,
    0x1.26fb3844dd190p-2
  },
  { // Entry 189
    -0x1.22eb21a44d62780000031ae43c448511p-2,
    -0x1.26fb3844dd190p-2
  },
  { // Entry 190
    0x1.d4a216d89b2b37f40ff08753ed600e74p-1,
    0x1.27fffffffe6b0p0
  },
  { // Entry 191
    -0x1.d4a216d89b2b37f40ff08753ed600e74p-1,
    -0x1.27fffffffe6b0p0
  },
  { // Entry 192
    -0x1.76c9b0f3a22f73cfd4453fcf7b21e358p-1,
    0x1.284b84048d481p204
  },
  { // Entry 193
    0x1.76c9b0f3a22f73cfd4453fcf7b21e358p-1,
    -0x1.284b84048d481p204
  },
  { // Entry 194
    -0x1.ff01226f97d32d6b5c0d5e4a3a2f53c3p-1,
    0x1.2999e3109cad4p2
  },
  { // Entry 195
    0x1.ff01226f97d32d6b5c0d5e4a3a2f53c3p-1,
    -0x1.2999e3109cad4p2
  },
  { // Entry 196
    0x1.2a8f11e7ae82c0a374855b53b3605d3bp-5,
    0x1.2aap-5
  },
  { // Entry 197
    -0x1.2a8f11e7ae82c0a374855b53b3605d3bp-5,
    -0x1.2aap-5
  },
  { // Entry 198
    0x1.2b03d1bf773df7b697d8a97eccefec50p-5,
    0x1.2b14d3be0c230p-5
  },
  { // Entry 199
    -0x1.2b03d1bf773df7b697d8a97eccefec50p-5,
    -0x1.2b14d3be0c230p-5
  },
  { // Entry 200
    -0x1.ffb90ee641791e699aa7fc7139bf58b4p-1,
    0x1.2b7cb44849981p2
  },
  { // Entry 201
    0x1.ffb90ee641791e699aa7fc7139bf58b4p-1,
    -0x1.2b7cb44849981p2
  },
  { // Entry 202
    -0x1.ffffff79e71a3db22109c6bb87f9c237p-1,
    0x1.2becc86852580p200
  },
  { // Entry 203
    0x1.ffffff79e71a3db22109c6bb87f9c237p-1,
    -0x1.2becc86852580p200
  },
  { // Entry 204
    -0x1.fff9edaf85b76f6cbb2f5b7e384cbbc9p-1,
    0x1.2cfa14ce27cd5p2
  },
  { // Entry 205
    0x1.fff9edaf85b76f6cbb2f5b7e384cbbc9p-1,
    -0x1.2cfa14ce27cd5p2
  },
  { // Entry 206
    0x1.2cbaaa4cebb517fe7bd14f062afec390p-4,
    0x1.2d0p-4
  },
  { // Entry 207
    -0x1.2cbaaa4cebb517fe7bd14f062afec390p-4,
    -0x1.2d0p-4
  },
  { // Entry 208
    -0x1.ffffbc177e00ff89cbb4f49a0643da78p-1,
    0x1.2d76d18721be8p2
  },
  { // Entry 209
    0x1.ffffbc177e00ff89cbb4f49a0643da78p-1,
    -0x1.2d76d18721be8p2
  },
  { // Entry 210
    0x1.745843dfafefd1bf9656896a8fb5b0e3p-18,
    0x1.302a494e09090p97
  },
  { // Entry 211
    -0x1.745843dfafefd1bf9656896a8fb5b0e3p-18,
    -0x1.302a494e09090p97
  },
  { // Entry 212
    0x1.ffcc568d423766c92e9c175f9210f1f4p-1,
    0x1.31cc731cc731cp1000
  },
  { // Entry 213
    -0x1.ffcc568d423766c92e9c175f9210f1f4p-1,
    -0x1.31cc731cc731cp1000
  },
  { // Entry 214
    0x1.b676077d4faf7927da1f858539fad1ffp-1,
    0x1.328463d4f8ca6p441
  },
  { // Entry 215
    -0x1.b676077d4faf7927da1f858539fad1ffp-1,
    -0x1.328463d4f8ca6p441
  },
  { // Entry 216
    -0x1.fffffffffffffffff3471d8dc070d5e6p-1,
    0x1.32ce90b32171ep18
  },
  { // Entry 217
    0x1.fffffffffffffffff3471d8dc070d5e6p-1,
    -0x1.32ce90b32171ep18
  },
  { // Entry 218
    0x1.35cbd3240d148845d39ebd54b1556779p-5,
    0x1.35debd7f020ecp-5
  },
  { // Entry 219
    -0x1.35cbd3240d148845d39ebd54b1556779p-5,
    -0x1.35debd7f020ecp-5
  },
  { // Entry 220
    0x1.3bb2086559fa982e5c6da10d8d9ac931p-7,
    0x1.3bb3487893405p-7
  },
  { // Entry 221
    -0x1.3bb2086559fa982e5c6da10d8d9ac931p-7,
    -0x1.3bb3487893405p-7
  },
  { // Entry 222
    0x1.3bb2086559fab82dfb1925eac2ab8bc1p-7,
    0x1.3bb3487893407p-7
  },
  { // Entry 223
    -0x1.3bb2086559fab82dfb1925eac2ab8bc1p-7,
    -0x1.3bb3487893407p-7
  },
  { // Entry 224
    0x1.dff197edc51d235e4a4cc6e34bd1fd10p-16,
    0x1.3bb681d65aa60p100
  },
  { // Entry 225
    -0x1.dff197edc51d235e4a4cc6e34bd1fd10p-16,
    -0x1.3bb681d65aa60p100
  },
  { // Entry 226
    -0x1.5d08d3dbb41af80000053ba30e95e709p-3,
    0x1.3f9aa8626042fp83
  },
  { // Entry 227
    0x1.5d08d3dbb41af80000053ba30e95e709p-3,
    -0x1.3f9aa8626042fp83
  },
  { // Entry 228
    0x1.fb503983f94bb749fce9ccca56a35ec6p-3,
    0x1.3fep19
  },
  { // Entry 229
    -0x1.fb503983f94bb749fce9ccca56a35ec6p-3,
    -0x1.3fep19
  },
  { // Entry 230
    -0x1.d3876eacc9ee6ec5a93ea14e032f9b02p-1,
    0x1.4285478f1e3c8p58
  },
  { // Entry 231
    0x1.d3876eacc9ee6ec5a93ea14e032f9b02p-1,
    -0x1.4285478f1e3c8p58
  },
  { // Entry 232
    0x1.42b66d54f69c0fabe371d703a1d7d7c9p-5,
    0x1.42cbcf45a169ep-5
  },
  { // Entry 233
    -0x1.42b66d54f69c0fabe371d703a1d7d7c9p-5,
    -0x1.42cbcf45a169ep-5
  },
  { // Entry 234
    0x1.b45e9e942755380000015e1db0ce188dp-1,
    0x1.43fffffffff6ap557
  },
  { // Entry 235
    -0x1.b45e9e942755380000015e1db0ce188dp-1,
    -0x1.43fffffffff6ap557
  },
  { // Entry 236
    0x1.43ffffffea602800006ed7862b3224a6p-17,
    0x1.440p-17
  },
  { // Entry 237
    -0x1.43ffffffea602800006ed7862b3224a6p-17,
    -0x1.440p-17
  },
  { // Entry 238
    -0x1.6a4e98d2d8b1b7fb43fef1bc4e3245bbp-1,
    0x1.4748c08dc0976p200
  },
  { // Entry 239
    0x1.6a4e98d2d8b1b7fb43fef1bc4e3245bbp-1,
    -0x1.4748c08dc0976p200
  },
  { // Entry 240
    -0x1.b57ca8aacf2a937a269ccdfa8b38c8c1p-1,
    0x1.478fc08p43
  },
  { // Entry 241
    0x1.b57ca8aacf2a937a269ccdfa8b38c8c1p-1,
    -0x1.478fc08p43
  },
  { // Entry 242
    0x1.ffe38008ef6b4956b290202d414d59c3p-1,
    0x1.4cf36d17c596ep200
  },
  { // Entry 243
    -0x1.ffe38008ef6b4956b290202d414d59c3p-1,
    -0x1.4cf36d17c596ep200
  },
  { // Entry 244
    0x1.d6457a3f12e6c527a853470401d35d2dp-1,
    0x1.4f0f308p488
  },
  { // Entry 245
    -0x1.d6457a3f12e6c527a853470401d35d2dp-1,
    -0x1.4f0f308p488
  },
  { // Entry 246
    0x1.4fffffffff9f88000000084f22ccccccp-20,
    0x1.5p-20
  },
  { // Entry 247
    -0x1.4fffffffff9f88000000084f22ccccccp-20,
    -0x1.5p-20
  },
  { // Entry 248
    -0x1.cbad095f503a18019a7b27170f6a4acfp-1,
    0x1.5143e25a488f1p3
  },
  { // Entry 249
    0x1.cbad095f503a18019a7b27170f6a4acfp-1,
    -0x1.5143e25a488f1p3
  },
  { // Entry 250
    -0x1.f942d6262e82dd6834ded8c90d0f8212p-5,
    0x1.51f0f44da4df4p200
  },
  { // Entry 251
    0x1.f942d6262e82dd6834ded8c90d0f8212p-5,
    -0x1.51f0f44da4df4p200
  },
  { // Entry 252
    -0x1.fc466ccaece804aac14e79aaba4b5c1ep-3,
    0x1.52ad6c5a3602fp16
  },
  { // Entry 253
    0x1.fc466ccaece804aac14e79aaba4b5c1ep-3,
    -0x1.52ad6c5a3602fp16
  },
  { // Entry 254
    0x1.d69c3cf4eecdd9b43726a2a7fa405c31p-1,
    0x1.52f00e0p793
  },
  { // Entry 255
    -0x1.d69c3cf4eecdd9b43726a2a7fa405c31p-1,
    -0x1.52f00e0p793
  },
  { // Entry 256
    0x1.e120292f3d4956579f9c3164cd94bad6p-1,
    0x1.5555555555556p239
  },
  { // Entry 257
    -0x1.e120292f3d4956579f9c3164cd94bad6p-1,
    -0x1.5555555555556p239
  },
  { // Entry 258
    -0x1.fd1d85b7ef0037fc4b1d1763882085f1p-1,
    0x1.5a0000008p6
  },
  { // Entry 259
    0x1.fd1d85b7ef0037fc4b1d1763882085f1p-1,
    -0x1.5a0000008p6
  },
  { // Entry 260
    0x1.5aff9664b07e1a2e0f24b2572ddbff64p-6,
    0x1.5b063ad2dd08fp-6
  },
  { // Entry 261
    -0x1.5aff9664b07e1a2e0f24b2572ddbff64p-6,
    -0x1.5b063ad2dd08fp-6
  },
  { // Entry 262
    -0x1.83f8bbb59f2f8cd8ebbd44c459e4c493p-1,
    0x1.5b179d75fa285p2
  },
  { // Entry 263
    0x1.83f8bbb59f2f8cd8ebbd44c459e4c493p-1,
    -0x1.5b179d75fa285p2
  },
  { // Entry 264
    0x1.fa865b0d994968390f9480c9caf49cb1p-1,
    0x1.5bb5967402f9cp79
  },
  { // Entry 265
    -0x1.fa865b0d994968390f9480c9caf49cb1p-1,
    -0x1.5bb5967402f9cp79
  },
  { // Entry 266
    0x1.e8a523fce884d189bdb87c20ed615944p-2,
    0x1.5bea010p468
  },
  { // Entry 267
    -0x1.e8a523fce884d189bdb87c20ed615944p-2,
    -0x1.5bea010p468
  },
  { // Entry 268
    -0x1.ff2ad941f0a40ea3bc29e6dd9c339b63p-1,
    0x1.5f19fbc507af6p9
  },
  { // Entry 269
    0x1.ff2ad941f0a40ea3bc29e6dd9c339b63p-1,
    -0x1.5f19fbc507af6p9
  },
  { // Entry 270
    -0x1.75ce4a0d0bd037fd53042cab82404953p-1,
    0x1.60a610a658da9p889
  },
  { // Entry 271
    0x1.75ce4a0d0bd037fd53042cab82404953p-1,
    -0x1.60a610a658da9p889
  },
  { // Entry 272
    -0x1.721586594ab4818acd4cb41fafc99484p-1,
    0x1.62ad7ce17143dp62
  },
  { // Entry 273
    0x1.721586594ab4818acd4cb41fafc99484p-1,
    -0x1.62ad7ce17143dp62
  },
  { // Entry 274
    0x1.b8d27019d1b9e836b953613c87acf3a9p-2,
    0x1.645926cc1132cp9
  },
  { // Entry 275
    -0x1.b8d27019d1b9e836b953613c87acf3a9p-2,
    -0x1.645926cc1132cp9
  },
  { // Entry 276
    0x1.647e09059c1e98000013714cd0c6a43dp-9,
    0x1.647e25d391f17p-9
  },
  { // Entry 277
    -0x1.647e09059c1e98000013714cd0c6a43dp-9,
    -0x1.647e25d391f17p-9
  },
  { // Entry 278
    -0x1.8d3b53ff85a823d06537413901229e45p-1,
    0x1.64ef438p142
  },
  { // Entry 279
    0x1.8d3b53ff85a823d06537413901229e45p-1,
    -0x1.64ef438p142
  },
  { // Entry 280
    -0x1.f7c8630e62a01ffd4e02577956e5523ep-1,
    0x1.6599665996658p3
  },
  { // Entry 281
    0x1.f7c8630e62a01ffd4e02577956e5523ep-1,
    -0x1.6599665996658p3
  },
  { // Entry 282
    0x1.67028e3602034800f45a9158d20a340cp-5,
    0x1.672p-5
  },
  { // Entry 283
    -0x1.67028e3602034800f45a9158d20a340cp-5,
    -0x1.672p-5
  },
  { // Entry 284
    0x1.bc60c8c33cb5ebf693d71650cbf166f9p-2,
    0x1.688ae6c138ea8p299
  },
  { // Entry 285
    -0x1.bc60c8c33cb5ebf693d71650cbf166f9p-2,
    -0x1.688ae6c138ea8p299
  },
  { // Entry 286
    -0x1.fc3b4bb8b012e8042d3ebced12def0c9p-1,
    0x1.6aa78p17
  },
  { // Entry 287
    0x1.fc3b4bb8b012e8042d3ebced12def0c9p-1,
    -0x1.6aa78p17
  },
  { // Entry 288
    0x1.ffffffffffffffffffffffffffffffb5p-1,
    0x1.6ac5b262ca1ffp849
  },
  { // Entry 289
    -0x1.ffffffffffffffffffffffffffffffb5p-1,
    -0x1.6ac5b262ca1ffp849
  },
  { // Entry 290
    -0x1.82317836a97c8cea1cd2e3a4d0d48f29p-1,
    0x1.6d88083749412p4
  },
  { // Entry 291
    0x1.82317836a97c8cea1cd2e3a4d0d48f29p-1,
    -0x1.6d88083749412p4
  },
  { // Entry 292
    0x1.6f781c78cc82a7ffcd20ba801e6691b1p-6,
    0x1.6f8p-6
  },
  { // Entry 293
    -0x1.6f781c78cc82a7ffcd20ba801e6691b1p-6,
    -0x1.6f8p-6
  },
  { // Entry 294
    -0x1.fdbe5085494ae7fe47fa067aaea7fdf9p-1,
    0x1.729aa6859d1f4p396
  },
  { // Entry 295
    0x1.fdbe5085494ae7fe47fa067aaea7fdf9p-1,
    -0x1.729aa6859d1f4p396
  },
  { // Entry 296
    -0x1.fffffae862b4fec1c2f1712aa165807cp-1,
    0x1.73e2dbe9a2f80p10
  },
  { // Entry 297
    0x1.fffffae862b4fec1c2f1712aa165807cp-1,
    -0x1.73e2dbe9a2f80p10
  },
  { // Entry 298
    0x1.769ac74459b058456b333238833f1d1ap-7,
    0x1.769cde0b90b80p-7
  },
  { // Entry 299
    -0x1.769ac74459b058456b333238833f1d1ap-7,
    -0x1.769cde0b90b80p-7
  },
  { // Entry 300
    0x1.769e8afb6a4ebf99ade465d19be86ac0p-5,
    0x1.76cp-5
  },
  { // Entry 301
    -0x1.769e8afb6a4ebf99ade465d19be86ac0p-5,
    -0x1.76cp-5
  },
  { // Entry 302
    0x1.fd562611f5bd4800de503e4210cc7df4p-1,
    0x1.78001p0
  },
  { // Entry 303
    -0x1.fd562611f5bd4800de503e4210cc7df4p-1,
    -0x1.78001p0
  },
  { // Entry 304
    0x1.fdba784ca00f17ebcc2b5b1098e83bffp-1,
    0x1.7a0p0
  },
  { // Entry 305
    -0x1.fdba784ca00f17ebcc2b5b1098e83bffp-1,
    -0x1.7a0p0
  },
  { // Entry 306
    0x1.f930c222a8682d7d1920a12b68870c36p-5,
    0x1.7abd870381c2dp38
  },
  { // Entry 307
    -0x1.f930c222a8682d7d1920a12b68870c36p-5,
    -0x1.7abd870381c2dp38
  },
  { // Entry 308
    0x1.ffeb2ff2b692367bc5660dab6960b57dp-1,
    0x1.7dc945c212480p95
  },
  { // Entry 309
    -0x1.ffeb2ff2b692367bc5660dab6960b57dp-1,
    -0x1.7dc945c212480p95
  },
  { // Entry 310
    0x1.b279153c23fb180000ce3a0d47d8c476p-2,
    0x1.7f73e1594b70cp98
  },
  { // Entry 311
    -0x1.b279153c23fb180000ce3a0d47d8c476p-2,
    -0x1.7f73e1594b70cp98
  },
  { // Entry 312
    -0x1.599fad35cf60ad43760cf3a9da3d9c30p-41,
    0x1.7f7ef77e83f1ap21
  },
  { // Entry 313
    0x1.599fad35cf60ad43760cf3a9da3d9c30p-41,
    -0x1.7f7ef77e83f1ap21
  },
  { // Entry 314
    0x1.feb7a9b2c6d8ade6e17fdacaef4fd96cp-1,
    0x1.8p0
  },
  { // Entry 315
    -0x1.feb7a9b2c6d8ade6e17fdacaef4fd96cp-1,
    -0x1.8p0
  },
  { // Entry 316
    0x1.f798d01ec615b8ededa474e3c6cd0c92p-1,
    0x1.8p6
  },
  { // Entry 317
    -0x1.f798d01ec615b8ededa474e3c6cd0c92p-1,
    -0x1.8p6
  },
  { // Entry 318
    0x1.fee1a2a977bced179f8ab8455ada525fp-1,
    0x1.8132ceb1c4f39p0
  },
  { // Entry 319
    -0x1.fee1a2a977bced179f8ab8455ada525fp-1,
    -0x1.8132ceb1c4f39p0
  },
  { // Entry 320
    -0x1.24245af4cd994e9b3bba992d0f57fc3fp-52,
    0x1.81ae0dffa3b33p959
  },
  { // Entry 321
    0x1.24245af4cd994e9b3bba992d0f57fc3fp-52,
    -0x1.81ae0dffa3b33p959
  },
  { // Entry 322
    0x1.85d41b0bf30907fffff1913a5ced7645p-4,
    0x1.85ec5a399a2e6p1
  },
  { // Entry 323
    -0x1.85d41b0bf30907fffff1913a5ced7645p-4,
    -0x1.85ec5a399a2e6p1
  },
  { // Entry 324
    0x1.1e42ae3cfbdc60976884087f97a0fda9p-24,
    0x1.86a0092754022p16
  },
  { // Entry 325
    -0x1.1e42ae3cfbdc60976884087f97a0fda9p-24,
    -0x1.86a0092754022p16
  },
  { // Entry 326
    -0x1.dbf4e594cefe1548efc24098d631e950p-1,
    0x1.8720588p392
  },
  { // Entry 327
    0x1.dbf4e594cefe1548efc24098d631e950p-1,
    -0x1.8720588p392
  },
  { // Entry 328
    0x1.44302d6a82d403badf1f9b71420ccdcap-9,
    0x1.8929354ebc6aap43
  },
  { // Entry 329
    -0x1.44302d6a82d403badf1f9b71420ccdcap-9,
    -0x1.8929354ebc6aap43
  },
  { // Entry 330
    0x1.8a52189ec34877bb5944413e00ad52edp-5,
    0x1.8a791e4791e75p-5
  },
  { // Entry 331
    -0x1.8a52189ec34877bb5944413e00ad52edp-5,
    -0x1.8a791e4791e75p-5
  },
  { // Entry 332
    -0x1.fe8566e538122db33c17f13b83474a04p-1,
    0x1.8ba761438f5edp11
  },
  { // Entry 333
    0x1.fe8566e538122db33c17f13b83474a04p-1,
    -0x1.8ba761438f5edp11
  },
  { // Entry 334
    0x1.fff42aca4cb5a80000057f1a48af65dep-1,
    0x1.8eaf16de63920p0
  },
  { // Entry 335
    -0x1.fff42aca4cb5a80000057f1a48af65dep-1,
    -0x1.8eaf16de63920p0
  },
  { // Entry 336
    0x1.fffb7d3f3a252da56d96327c18627f57p-1,
    0x1.9p0
  },
  { // Entry 337
    -0x1.fffb7d3f3a252da56d96327c18627f57p-1,
    -0x1.9p0
  },
  { // Entry 338
    -0x1.e815770667fd87f9525154edc867605fp-4,
    0x1.91a5657fb6a9ap6
  },
  { // Entry 339
    0x1.e815770667fd87f9525154edc867605fp-4,
    -0x1.91a5657fb6a9ap6
  },
  { // Entry 340
    -0x1.fffffffd311dc7ec5d0ae5728a7960fdp-1,
    0x1.921fb54468847p37
  },
  { // Entry 341
    0x1.fffffffd311dc7ec5d0ae5728a7960fdp-1,
    -0x1.921fb54468847p37
  },
  { // Entry 342
    0x1.ffffffff875e5e4497dd0760336e63f3p-17,
    0x1.921ff54442d18p2
  },
  { // Entry 343
    -0x1.ffffffff875e5e4497dd0760336e63f3p-17,
    -0x1.921ff54442d18p2
  },
  { // Entry 344
    0x1.812a5da3777cd7f6e17288638b40aa09p-8,
    0x1.928p2
  },
  { // Entry 345
    -0x1.812a5da3777cd7f6e17288638b40aa09p-8,
    -0x1.928p2
  },
  { // Entry 346
    0x1.fff9be8d82572c746f944934bbf1b697p-1,
    0x1.94ap0
  },
  { // Entry 347
    -0x1.fff9be8d82572c746f944934bbf1b697p-1,
    -0x1.94ap0
  },
  { // Entry 348
    0x1.947b0ace235f2850b27b164c49102a49p-5,
    0x1.94a5294a51bdep-5
  },
  { // Entry 349
    -0x1.947b0ace235f2850b27b164c49102a49p-5,
    -0x1.94a5294a51bdep-5
  },
  { // Entry 350
    0x1.c34f70e55a707bbd053a70e749105174p-2,
    0x1.94a5294a52948p100
  },
  { // Entry 351
    -0x1.c34f70e55a707bbd053a70e749105174p-2,
    -0x1.94a5294a52948p100
  },
  { // Entry 352
    0x1.950bcfc0f3d50850941a41d66cfa3721p-5,
    0x1.95361b8f7697dp-5
  },
  { // Entry 353
    -0x1.950bcfc0f3d50850941a41d6
"""


```
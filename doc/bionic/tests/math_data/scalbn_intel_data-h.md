Response:
Let's break down the thought process for analyzing this code snippet and answering the prompt.

**1. Understanding the Core Request:**

The fundamental request is to analyze a C data file within the Android bionic library, specifically related to the `scalbn` function. The prompt asks for its function, its relationship to Android, explanations of involved libc functions, dynamic linking aspects, example inputs/outputs, common errors, and how to reach this code via the Android framework/NDK with Frida. The immediate follow-up is to summarize its function.

**2. Initial Code Scan and Keyword Identification:**

A quick scan reveals the following:

* **`/* ... */` comments:** These provide context about the file's origin (Android Open Source Project, Apache 2.0 license) and a brief description.
* **`static data_1_2_t<double, double, int> g_scalbn_intel_data[] = { ... };`:** This is the core data structure. It's a static array named `g_scalbn_intel_data`. The type `data_1_2_t<double, double, int>` suggests it holds tuples (or structs) containing two doubles and an integer.
* **Floating-point literals:**  Numbers like `-0.0`, `-0x1.0p-1074`, `HUGE_VAL`. The `0x1.0p-1074` notation is hexadecimal floating-point format, crucial for understanding the data.
* **Integer literals:** Numbers like `-10`, `-1022`, `2147483647`.
* **`scalbn`:**  The filename itself (`scalbn_intel_data.handroid`) and the array name strongly suggest this data is related to the `scalbn` function.

**3. Inferring the Function's Purpose:**

Given the filename and the data structure, the primary function of this file is almost certainly to provide **test data** for the `scalbn` function. The array likely contains sets of inputs and expected outputs for testing various scenarios and edge cases.

**4. Connecting to Android:**

The file resides within the `bionic/tests` directory, which clearly links it to the testing infrastructure of Android's C library. `bionic` is Android's foundational C library, so anything within it is directly related to Android's core functionality.

**5. Analyzing the Data Structure and Entries:**

Each entry in the `g_scalbn_intel_data` array represents a test case. Let's analyze the structure of a single entry:

```c++
{ // Entry 0
    -0.0,               // Input double
    -0x1.0p-1074,      // Expected output double
    (int)-10            // Input integer (exponent)
}
```

This pattern repeats throughout the file. This strongly suggests the structure is: `{input_value, expected_output, exponent}`.

**6. Understanding `scalbn` (even without the implementation):**

Based on the data structure, we can infer the functionality of `scalbn`. It likely takes a `double` and an `int` as input and returns a `double`. The `int` seems to represent an exponent that modifies the input `double`. The name `scalbn` (scale binary) reinforces this idea.

**7. Considering Dynamic Linking (and realizing it's not the focus here):**

The prompt mentions the dynamic linker. While this file *is part of* `bionic`, it's a *data* file, not executable code. It doesn't directly involve the dynamic linker's loading or linking processes. The dynamic linker is responsible for loading shared libraries (`.so` files) at runtime and resolving symbols. This data file is likely linked into the test executable statically. Therefore, detailed dynamic linking analysis isn't directly relevant *to this specific file*. However, it's important to acknowledge its place within the broader `bionic` context.

**8. Hypothesizing Input and Output:**

Based on the `scalbn` function's likely purpose, we can formulate example inputs and outputs. For example, `scalbn(1.0, 2)` should return `4.0` (1.0 * 2^2). The data file provides more complex examples, including negative numbers, zero, and special values like `HUGE_VAL`.

**9. Considering Common Errors (with `scalbn` in general):**

Thinking about how `scalbn` is used, common errors could involve:

* **Incorrect exponent values:**  Very large or very small exponents could lead to overflow or underflow.
* **Passing NaN or infinity as the base:**  The behavior of `scalbn` with these special values needs to be tested.

**10. Tracing the Execution Path (and acknowledging limitations):**

The prompt asks how the code is reached. This data file is used in tests. The execution path would involve:

* Android framework/NDK triggering a mathematical operation.
* The C library's `scalbn` implementation being called.
* *Separately*, a test suite for `scalbn` being run, which *uses this data file* to verify the correctness of the `scalbn` implementation.

It's important to distinguish between the *use* of `scalbn` in general Android code and the *testing* of `scalbn` where this data file comes into play. Providing a full Frida hook example requires knowing the specific test executable and the structure of the test framework, which isn't provided in the snippet.

**11. Structuring the Answer:**

Organize the findings logically, addressing each part of the prompt. Use clear headings and bullet points.

**12. Drafting the Summary (for Part 1):**

Focus on the core purpose of the file: providing test data for the `scalbn` function. Mention the data structure and its components.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file contains optimized `scalbn` implementations for Intel.
* **Correction:** The filename `..._data.handroid` and the presence in `bionic/tests` strongly suggest it's test data, not implementation code. The `intel` part likely indicates it's testing Intel-specific behavior or edge cases.
* **Initial thought:**  Dive deep into the dynamic linker's mechanics.
* **Correction:** This file is data. The dynamic linker isn't directly involved in its processing. Focus on its role within the broader `bionic` context.

By following these steps,  breaking down the problem, inferring functionality, and connecting the code to the broader Android ecosystem, we arrive at a comprehensive and accurate answer to the prompt.
## 对 bionic/tests/math_data/scalbn_intel_data.handroid 的功能归纳 (第 1 部分)

根据提供的源代码文件 `bionic/tests/math_data/scalbn_intel_data.handroid`，我们可以归纳出它的主要功能是：

**核心功能：提供 `scalbn` 函数在特定输入下的测试数据。**

具体来说，这个文件定义了一个静态的 C++ 数组 `g_scalbn_intel_data`，该数组的每个元素都包含三个部分，用于测试 `scalbn` 函数：

1. **输入值 (double):**  `scalbn` 函数的第一个参数，即需要进行缩放的浮点数。
2. **预期输出值 (double):**  在给定输入值和指数的情况下，`scalbn` 函数应该返回的正确结果。
3. **指数 (int):** `scalbn` 函数的第二个参数，表示要乘以的 2 的幂次方。

**更详细的解释：**

这个文件很明显不是 `scalbn` 函数的实现代码，而是一组精心设计的测试用例。 这些测试用例的目标是验证 `scalbn` 函数在各种不同输入情况下的正确性，包括：

* **正数、负数和零：**  测试不同符号的输入值。
* **Subnormal Numbers (次正规数):** 例如 `0x1.0p-1074`，测试接近于零的小数值。
* **Normal Numbers (正规数):**  测试常规范围内的浮点数。
* **边界情况：**  例如 `HUGE_VAL` (表示正无穷大)，测试特殊值。
* **不同的指数值：**  包括正数、负数和零，测试乘以不同大小的 2 的幂次方。
* **各种精度和尾数的值：**  通过不同的十六进制浮点数表示，覆盖不同的内部表示。

**与 Android 功能的关系举例：**

`scalbn` 函数是 C 标准库 `<math.h>` 中的一个函数，用于计算 `x * 2^n` 的值，其中 `x` 是浮点数，`n` 是整数。它在 Android 的底层 C 库 `bionic` 中被实现和提供。

**举例说明：**

* **图形渲染:** 在图形处理中，可能需要对顶点坐标或颜色值进行缩放操作，`scalbn` 可以用于快速乘以 2 的幂次方。
* **音频处理:**  音频信号的幅度调整可能涉及到乘以或除以 2 的幂次方，`scalbn` 可以提供高效的实现。
* **科学计算:**  在需要进行数值计算的 Android 应用中，例如物理模拟或数据分析，`scalbn` 可以用于处理指数缩放。

**为何需要这样的测试数据？**

在开发像 `bionic` 这样底层的库时，确保每个函数的正确性至关重要。 像 `scalbn` 这样的数学函数，其实现可能涉及到对浮点数内部表示的复杂操作，很容易出现边界错误或精度问题。  预先定义好各种输入和预期输出的测试数据，可以帮助开发者：

* **验证实现的正确性：**  运行测试用例，比较实际输出和预期输出，确保 `scalbn` 函数在各种情况下都能返回正确的结果。
* **回归测试：**  在修改或优化 `scalbn` 函数的实现后，可以重新运行这些测试用例，确保新的改动没有引入新的错误。
* **跨平台兼容性测试：**  虽然这个文件命名为 `scalbn_intel_data.handroid`，可能暗示了它最初是针对 Intel 架构的，但类似的测试数据通常也会用于验证在其他架构上的实现。

**总结：**

`bionic/tests/math_data/scalbn_intel_data.handroid` 文件是 Android `bionic` 库中用于测试 `scalbn` 函数正确性的关键组成部分。它通过预定义一系列具有代表性的输入值、指数和对应的预期输出值，为开发者提供了一种系统化的方法来验证和保证 `scalbn` 函数的质量。

**后续部分预告：**

在后续的第 2 和第 3 部分，我们可以深入探讨：

* **libc 函数的实现细节：**  `scalbn` 函数在 `bionic` 中是如何实现的？
* **dynamic linker 的作用：**  虽然这个文件本身不是可执行代码，但 `scalbn` 函数所在的库是如何被加载和链接的？
* **更深入的测试用例分析：**  每个测试用例的具体目的和覆盖范围是什么？
* **Frida Hook 调试示例：** 如何使用 Frida 来观察 `scalbn` 函数的执行过程，并验证测试数据的有效性？

Prompt: 
```
这是目录为bionic/tests/math_data/scalbn_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

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

static data_1_2_t<double, double, int> g_scalbn_intel_data[] = {
  { // Entry 0
    -0.0,
    -0x1.0p-1074,
    (int)-10
  },
  { // Entry 1
    -0x1.55555555555560p-1024,
    -0x1.5555555555556p-2,
    (int)-1022
  },
  { // Entry 2
    -0x1.6db6db6db6db70p-1023,
    -0x1.6db6db6db6db7p-1,
    (int)-1022
  },
  { // Entry 3
    -0x1.8e38e38e38e390p-1023,
    -0x1.8e38e38e38e39p-1,
    (int)-1022
  },
  { // Entry 4
    0.0,
    0x1.0p-1074,
    (int)-1
  },
  { // Entry 5
    0.0,
    0x1.0p-1074,
    (int)-10
  },
  { // Entry 6
    0.0,
    0x1.0p-1074,
    (int)-47
  },
  { // Entry 7
    0x1.p-51,
    0x1.0p-1074,
    (int)1023
  },
  { // Entry 8
    0x1.29e4129e4129e0p-1024,
    0x1.29e4129e4129ep-7,
    (int)-1017
  },
  { // Entry 9
    HUGE_VAL,
    0x1.8e147ae147ae1p0,
    (int)2147483647
  },
  { // Entry 10
    0.0,
    0x1.dddddddddddddp-2,
    (int)-1073
  },
  { // Entry 11
    0.0,
    0x1.f7df7df7df7dfp-2,
    (int)-1073
  },
  { // Entry 12
    0x1.ffffffffffffc0p-1033,
    0x1.ffffffffffffcp-1023,
    (int)-10
  },
  { // Entry 13
    0x1.ffffffffffffc0p-1022,
    0x1.ffffffffffffcp-1023,
    (int)1
  },
  { // Entry 14
    0x1.ffffffffffffe0p-1070,
    0x1.ffffffffffffep-1023,
    (int)-47
  },
  { // Entry 15
    0x1.ffffffffffffe0p-1022,
    0x1.ffffffffffffep-1023,
    (int)1
  },
  { // Entry 16
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    (int)2147483647
  },
  { // Entry 17
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    (int)2147483647
  },
  { // Entry 18
    -0x1.p-10,
    -0x1.0p0,
    (int)-10
  },
  { // Entry 19
    -0x1.p-9,
    -0x1.0p0,
    (int)-9
  },
  { // Entry 20
    -0x1.p-8,
    -0x1.0p0,
    (int)-8
  },
  { // Entry 21
    -0x1.p-7,
    -0x1.0p0,
    (int)-7
  },
  { // Entry 22
    -0x1.p-6,
    -0x1.0p0,
    (int)-6
  },
  { // Entry 23
    -0x1.p-5,
    -0x1.0p0,
    (int)-5
  },
  { // Entry 24
    -0x1.p-4,
    -0x1.0p0,
    (int)-4
  },
  { // Entry 25
    -0x1.p-3,
    -0x1.0p0,
    (int)-3
  },
  { // Entry 26
    -0x1.p-2,
    -0x1.0p0,
    (int)-2
  },
  { // Entry 27
    -0x1.p-1,
    -0x1.0p0,
    (int)-1
  },
  { // Entry 28
    -0x1.p0,
    -0x1.0p0,
    (int)0
  },
  { // Entry 29
    -0x1.p1,
    -0x1.0p0,
    (int)1
  },
  { // Entry 30
    -0x1.p2,
    -0x1.0p0,
    (int)2
  },
  { // Entry 31
    -0x1.p3,
    -0x1.0p0,
    (int)3
  },
  { // Entry 32
    -0x1.p4,
    -0x1.0p0,
    (int)4
  },
  { // Entry 33
    -0x1.p5,
    -0x1.0p0,
    (int)5
  },
  { // Entry 34
    -0x1.p6,
    -0x1.0p0,
    (int)6
  },
  { // Entry 35
    -0x1.p7,
    -0x1.0p0,
    (int)7
  },
  { // Entry 36
    -0x1.p8,
    -0x1.0p0,
    (int)8
  },
  { // Entry 37
    -0x1.p9,
    -0x1.0p0,
    (int)9
  },
  { // Entry 38
    -0x1.p10,
    -0x1.0p0,
    (int)10
  },
  { // Entry 39
    -0x1.d1745d1745d170p-11,
    -0x1.d1745d1745d17p-1,
    (int)-10
  },
  { // Entry 40
    -0x1.d1745d1745d170p-10,
    -0x1.d1745d1745d17p-1,
    (int)-9
  },
  { // Entry 41
    -0x1.d1745d1745d170p-9,
    -0x1.d1745d1745d17p-1,
    (int)-8
  },
  { // Entry 42
    -0x1.d1745d1745d170p-8,
    -0x1.d1745d1745d17p-1,
    (int)-7
  },
  { // Entry 43
    -0x1.d1745d1745d170p-7,
    -0x1.d1745d1745d17p-1,
    (int)-6
  },
  { // Entry 44
    -0x1.d1745d1745d170p-6,
    -0x1.d1745d1745d17p-1,
    (int)-5
  },
  { // Entry 45
    -0x1.d1745d1745d170p-5,
    -0x1.d1745d1745d17p-1,
    (int)-4
  },
  { // Entry 46
    -0x1.d1745d1745d170p-4,
    -0x1.d1745d1745d17p-1,
    (int)-3
  },
  { // Entry 47
    -0x1.d1745d1745d170p-3,
    -0x1.d1745d1745d17p-1,
    (int)-2
  },
  { // Entry 48
    -0x1.d1745d1745d170p-2,
    -0x1.d1745d1745d17p-1,
    (int)-1
  },
  { // Entry 49
    -0x1.d1745d1745d170p-1,
    -0x1.d1745d1745d17p-1,
    (int)0
  },
  { // Entry 50
    -0x1.d1745d1745d170p0,
    -0x1.d1745d1745d17p-1,
    (int)1
  },
  { // Entry 51
    -0x1.d1745d1745d170p1,
    -0x1.d1745d1745d17p-1,
    (int)2
  },
  { // Entry 52
    -0x1.d1745d1745d170p2,
    -0x1.d1745d1745d17p-1,
    (int)3
  },
  { // Entry 53
    -0x1.d1745d1745d170p3,
    -0x1.d1745d1745d17p-1,
    (int)4
  },
  { // Entry 54
    -0x1.d1745d1745d170p4,
    -0x1.d1745d1745d17p-1,
    (int)5
  },
  { // Entry 55
    -0x1.d1745d1745d170p5,
    -0x1.d1745d1745d17p-1,
    (int)6
  },
  { // Entry 56
    -0x1.d1745d1745d170p6,
    -0x1.d1745d1745d17p-1,
    (int)7
  },
  { // Entry 57
    -0x1.d1745d1745d170p7,
    -0x1.d1745d1745d17p-1,
    (int)8
  },
  { // Entry 58
    -0x1.d1745d1745d170p8,
    -0x1.d1745d1745d17p-1,
    (int)9
  },
  { // Entry 59
    -0x1.d1745d1745d170p9,
    -0x1.d1745d1745d17p-1,
    (int)10
  },
  { // Entry 60
    -0x1.a2e8ba2e8ba2e0p-11,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-10
  },
  { // Entry 61
    -0x1.a2e8ba2e8ba2e0p-10,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-9
  },
  { // Entry 62
    -0x1.a2e8ba2e8ba2e0p-9,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-8
  },
  { // Entry 63
    -0x1.a2e8ba2e8ba2e0p-8,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-7
  },
  { // Entry 64
    -0x1.a2e8ba2e8ba2e0p-7,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-6
  },
  { // Entry 65
    -0x1.a2e8ba2e8ba2e0p-6,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-5
  },
  { // Entry 66
    -0x1.a2e8ba2e8ba2e0p-5,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-4
  },
  { // Entry 67
    -0x1.a2e8ba2e8ba2e0p-4,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-3
  },
  { // Entry 68
    -0x1.a2e8ba2e8ba2e0p-3,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-2
  },
  { // Entry 69
    -0x1.a2e8ba2e8ba2e0p-2,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-1
  },
  { // Entry 70
    -0x1.a2e8ba2e8ba2e0p-1,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)0
  },
  { // Entry 71
    -0x1.a2e8ba2e8ba2e0p0,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)1
  },
  { // Entry 72
    -0x1.a2e8ba2e8ba2e0p1,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)2
  },
  { // Entry 73
    -0x1.a2e8ba2e8ba2e0p2,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)3
  },
  { // Entry 74
    -0x1.a2e8ba2e8ba2e0p3,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)4
  },
  { // Entry 75
    -0x1.a2e8ba2e8ba2e0p4,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)5
  },
  { // Entry 76
    -0x1.a2e8ba2e8ba2e0p5,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)6
  },
  { // Entry 77
    -0x1.a2e8ba2e8ba2e0p6,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)7
  },
  { // Entry 78
    -0x1.a2e8ba2e8ba2e0p7,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)8
  },
  { // Entry 79
    -0x1.a2e8ba2e8ba2e0p8,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)9
  },
  { // Entry 80
    -0x1.a2e8ba2e8ba2e0p9,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)10
  },
  { // Entry 81
    -0x1.745d1745d17450p-11,
    -0x1.745d1745d1745p-1,
    (int)-10
  },
  { // Entry 82
    -0x1.745d1745d17450p-10,
    -0x1.745d1745d1745p-1,
    (int)-9
  },
  { // Entry 83
    -0x1.745d1745d17450p-9,
    -0x1.745d1745d1745p-1,
    (int)-8
  },
  { // Entry 84
    -0x1.745d1745d17450p-8,
    -0x1.745d1745d1745p-1,
    (int)-7
  },
  { // Entry 85
    -0x1.745d1745d17450p-7,
    -0x1.745d1745d1745p-1,
    (int)-6
  },
  { // Entry 86
    -0x1.745d1745d17450p-6,
    -0x1.745d1745d1745p-1,
    (int)-5
  },
  { // Entry 87
    -0x1.745d1745d17450p-5,
    -0x1.745d1745d1745p-1,
    (int)-4
  },
  { // Entry 88
    -0x1.745d1745d17450p-4,
    -0x1.745d1745d1745p-1,
    (int)-3
  },
  { // Entry 89
    -0x1.745d1745d17450p-3,
    -0x1.745d1745d1745p-1,
    (int)-2
  },
  { // Entry 90
    -0x1.745d1745d17450p-2,
    -0x1.745d1745d1745p-1,
    (int)-1
  },
  { // Entry 91
    -0x1.745d1745d17450p-1,
    -0x1.745d1745d1745p-1,
    (int)0
  },
  { // Entry 92
    -0x1.745d1745d17450p0,
    -0x1.745d1745d1745p-1,
    (int)1
  },
  { // Entry 93
    -0x1.745d1745d17450p1,
    -0x1.745d1745d1745p-1,
    (int)2
  },
  { // Entry 94
    -0x1.745d1745d17450p2,
    -0x1.745d1745d1745p-1,
    (int)3
  },
  { // Entry 95
    -0x1.745d1745d17450p3,
    -0x1.745d1745d1745p-1,
    (int)4
  },
  { // Entry 96
    -0x1.745d1745d17450p4,
    -0x1.745d1745d1745p-1,
    (int)5
  },
  { // Entry 97
    -0x1.745d1745d17450p5,
    -0x1.745d1745d1745p-1,
    (int)6
  },
  { // Entry 98
    -0x1.745d1745d17450p6,
    -0x1.745d1745d1745p-1,
    (int)7
  },
  { // Entry 99
    -0x1.745d1745d17450p7,
    -0x1.745d1745d1745p-1,
    (int)8
  },
  { // Entry 100
    -0x1.745d1745d17450p8,
    -0x1.745d1745d1745p-1,
    (int)9
  },
  { // Entry 101
    -0x1.745d1745d17450p9,
    -0x1.745d1745d1745p-1,
    (int)10
  },
  { // Entry 102
    -0x1.45d1745d1745c0p-11,
    -0x1.45d1745d1745cp-1,
    (int)-10
  },
  { // Entry 103
    -0x1.45d1745d1745c0p-10,
    -0x1.45d1745d1745cp-1,
    (int)-9
  },
  { // Entry 104
    -0x1.45d1745d1745c0p-9,
    -0x1.45d1745d1745cp-1,
    (int)-8
  },
  { // Entry 105
    -0x1.45d1745d1745c0p-8,
    -0x1.45d1745d1745cp-1,
    (int)-7
  },
  { // Entry 106
    -0x1.45d1745d1745c0p-7,
    -0x1.45d1745d1745cp-1,
    (int)-6
  },
  { // Entry 107
    -0x1.45d1745d1745c0p-6,
    -0x1.45d1745d1745cp-1,
    (int)-5
  },
  { // Entry 108
    -0x1.45d1745d1745c0p-5,
    -0x1.45d1745d1745cp-1,
    (int)-4
  },
  { // Entry 109
    -0x1.45d1745d1745c0p-4,
    -0x1.45d1745d1745cp-1,
    (int)-3
  },
  { // Entry 110
    -0x1.45d1745d1745c0p-3,
    -0x1.45d1745d1745cp-1,
    (int)-2
  },
  { // Entry 111
    -0x1.45d1745d1745c0p-2,
    -0x1.45d1745d1745cp-1,
    (int)-1
  },
  { // Entry 112
    -0x1.45d1745d1745c0p-1,
    -0x1.45d1745d1745cp-1,
    (int)0
  },
  { // Entry 113
    -0x1.45d1745d1745c0p0,
    -0x1.45d1745d1745cp-1,
    (int)1
  },
  { // Entry 114
    -0x1.45d1745d1745c0p1,
    -0x1.45d1745d1745cp-1,
    (int)2
  },
  { // Entry 115
    -0x1.45d1745d1745c0p2,
    -0x1.45d1745d1745cp-1,
    (int)3
  },
  { // Entry 116
    -0x1.45d1745d1745c0p3,
    -0x1.45d1745d1745cp-1,
    (int)4
  },
  { // Entry 117
    -0x1.45d1745d1745c0p4,
    -0x1.45d1745d1745cp-1,
    (int)5
  },
  { // Entry 118
    -0x1.45d1745d1745c0p5,
    -0x1.45d1745d1745cp-1,
    (int)6
  },
  { // Entry 119
    -0x1.45d1745d1745c0p6,
    -0x1.45d1745d1745cp-1,
    (int)7
  },
  { // Entry 120
    -0x1.45d1745d1745c0p7,
    -0x1.45d1745d1745cp-1,
    (int)8
  },
  { // Entry 121
    -0x1.45d1745d1745c0p8,
    -0x1.45d1745d1745cp-1,
    (int)9
  },
  { // Entry 122
    -0x1.45d1745d1745c0p9,
    -0x1.45d1745d1745cp-1,
    (int)10
  },
  { // Entry 123
    -0x1.1745d1745d1730p-11,
    -0x1.1745d1745d173p-1,
    (int)-10
  },
  { // Entry 124
    -0x1.1745d1745d1730p-10,
    -0x1.1745d1745d173p-1,
    (int)-9
  },
  { // Entry 125
    -0x1.1745d1745d1730p-9,
    -0x1.1745d1745d173p-1,
    (int)-8
  },
  { // Entry 126
    -0x1.1745d1745d1730p-8,
    -0x1.1745d1745d173p-1,
    (int)-7
  },
  { // Entry 127
    -0x1.1745d1745d1730p-7,
    -0x1.1745d1745d173p-1,
    (int)-6
  },
  { // Entry 128
    -0x1.1745d1745d1730p-6,
    -0x1.1745d1745d173p-1,
    (int)-5
  },
  { // Entry 129
    -0x1.1745d1745d1730p-5,
    -0x1.1745d1745d173p-1,
    (int)-4
  },
  { // Entry 130
    -0x1.1745d1745d1730p-4,
    -0x1.1745d1745d173p-1,
    (int)-3
  },
  { // Entry 131
    -0x1.1745d1745d1730p-3,
    -0x1.1745d1745d173p-1,
    (int)-2
  },
  { // Entry 132
    -0x1.1745d1745d1730p-2,
    -0x1.1745d1745d173p-1,
    (int)-1
  },
  { // Entry 133
    -0x1.1745d1745d1730p-1,
    -0x1.1745d1745d173p-1,
    (int)0
  },
  { // Entry 134
    -0x1.1745d1745d1730p0,
    -0x1.1745d1745d173p-1,
    (int)1
  },
  { // Entry 135
    -0x1.1745d1745d1730p1,
    -0x1.1745d1745d173p-1,
    (int)2
  },
  { // Entry 136
    -0x1.1745d1745d1730p2,
    -0x1.1745d1745d173p-1,
    (int)3
  },
  { // Entry 137
    -0x1.1745d1745d1730p3,
    -0x1.1745d1745d173p-1,
    (int)4
  },
  { // Entry 138
    -0x1.1745d1745d1730p4,
    -0x1.1745d1745d173p-1,
    (int)5
  },
  { // Entry 139
    -0x1.1745d1745d1730p5,
    -0x1.1745d1745d173p-1,
    (int)6
  },
  { // Entry 140
    -0x1.1745d1745d1730p6,
    -0x1.1745d1745d173p-1,
    (int)7
  },
  { // Entry 141
    -0x1.1745d1745d1730p7,
    -0x1.1745d1745d173p-1,
    (int)8
  },
  { // Entry 142
    -0x1.1745d1745d1730p8,
    -0x1.1745d1745d173p-1,
    (int)9
  },
  { // Entry 143
    -0x1.1745d1745d1730p9,
    -0x1.1745d1745d173p-1,
    (int)10
  },
  { // Entry 144
    -0x1.d1745d1745d140p-12,
    -0x1.d1745d1745d14p-2,
    (int)-10
  },
  { // Entry 145
    -0x1.d1745d1745d140p-11,
    -0x1.d1745d1745d14p-2,
    (int)-9
  },
  { // Entry 146
    -0x1.d1745d1745d140p-10,
    -0x1.d1745d1745d14p-2,
    (int)-8
  },
  { // Entry 147
    -0x1.d1745d1745d140p-9,
    -0x1.d1745d1745d14p-2,
    (int)-7
  },
  { // Entry 148
    -0x1.d1745d1745d140p-8,
    -0x1.d1745d1745d14p-2,
    (int)-6
  },
  { // Entry 149
    -0x1.d1745d1745d140p-7,
    -0x1.d1745d1745d14p-2,
    (int)-5
  },
  { // Entry 150
    -0x1.d1745d1745d140p-6,
    -0x1.d1745d1745d14p-2,
    (int)-4
  },
  { // Entry 151
    -0x1.d1745d1745d140p-5,
    -0x1.d1745d1745d14p-2,
    (int)-3
  },
  { // Entry 152
    -0x1.d1745d1745d140p-4,
    -0x1.d1745d1745d14p-2,
    (int)-2
  },
  { // Entry 153
    -0x1.d1745d1745d140p-3,
    -0x1.d1745d1745d14p-2,
    (int)-1
  },
  { // Entry 154
    -0x1.d1745d1745d140p-2,
    -0x1.d1745d1745d14p-2,
    (int)0
  },
  { // Entry 155
    -0x1.d1745d1745d140p-1,
    -0x1.d1745d1745d14p-2,
    (int)1
  },
  { // Entry 156
    -0x1.d1745d1745d140p0,
    -0x1.d1745d1745d14p-2,
    (int)2
  },
  { // Entry 157
    -0x1.d1745d1745d140p1,
    -0x1.d1745d1745d14p-2,
    (int)3
  },
  { // Entry 158
    -0x1.d1745d1745d140p2,
    -0x1.d1745d1745d14p-2,
    (int)4
  },
  { // Entry 159
    -0x1.d1745d1745d140p3,
    -0x1.d1745d1745d14p-2,
    (int)5
  },
  { // Entry 160
    -0x1.d1745d1745d140p4,
    -0x1.d1745d1745d14p-2,
    (int)6
  },
  { // Entry 161
    -0x1.d1745d1745d140p5,
    -0x1.d1745d1745d14p-2,
    (int)7
  },
  { // Entry 162
    -0x1.d1745d1745d140p6,
    -0x1.d1745d1745d14p-2,
    (int)8
  },
  { // Entry 163
    -0x1.d1745d1745d140p7,
    -0x1.d1745d1745d14p-2,
    (int)9
  },
  { // Entry 164
    -0x1.d1745d1745d140p8,
    -0x1.d1745d1745d14p-2,
    (int)10
  },
  { // Entry 165
    -0x1.745d1745d17420p-12,
    -0x1.745d1745d1742p-2,
    (int)-10
  },
  { // Entry 166
    -0x1.745d1745d17420p-11,
    -0x1.745d1745d1742p-2,
    (int)-9
  },
  { // Entry 167
    -0x1.745d1745d17420p-10,
    -0x1.745d1745d1742p-2,
    (int)-8
  },
  { // Entry 168
    -0x1.745d1745d17420p-9,
    -0x1.745d1745d1742p-2,
    (int)-7
  },
  { // Entry 169
    -0x1.745d1745d17420p-8,
    -0x1.745d1745d1742p-2,
    (int)-6
  },
  { // Entry 170
    -0x1.745d1745d17420p-7,
    -0x1.745d1745d1742p-2,
    (int)-5
  },
  { // Entry 171
    -0x1.745d1745d17420p-6,
    -0x1.745d1745d1742p-2,
    (int)-4
  },
  { // Entry 172
    -0x1.745d1745d17420p-5,
    -0x1.745d1745d1742p-2,
    (int)-3
  },
  { // Entry 173
    -0x1.745d1745d17420p-4,
    -0x1.745d1745d1742p-2,
    (int)-2
  },
  { // Entry 174
    -0x1.745d1745d17420p-3,
    -0x1.745d1745d1742p-2,
    (int)-1
  },
  { // Entry 175
    -0x1.745d1745d17420p-2,
    -0x1.745d1745d1742p-2,
    (int)0
  },
  { // Entry 176
    -0x1.745d1745d17420p-1,
    -0x1.745d1745d1742p-2,
    (int)1
  },
  { // Entry 177
    -0x1.745d1745d17420p0,
    -0x1.745d1745d1742p-2,
    (int)2
  },
  { // Entry 178
    -0x1.745d1745d17420p1,
    -0x1.745d1745d1742p-2,
    (int)3
  },
  { // Entry 179
    -0x1.745d1745d17420p2,
    -0x1.745d1745d1742p-2,
    (int)4
  },
  { // Entry 180
    -0x1.745d1745d17420p3,
    -0x1.745d1745d1742p-2,
    (int)5
  },
  { // Entry 181
    -0x1.745d1745d17420p4,
    -0x1.745d1745d1742p-2,
    (int)6
  },
  { // Entry 182
    -0x1.745d1745d17420p5,
    -0x1.745d1745d1742p-2,
    (int)7
  },
  { // Entry 183
    -0x1.745d1745d17420p6,
    -0x1.745d1745d1742p-2,
    (int)8
  },
  { // Entry 184
    -0x1.745d1745d17420p7,
    -0x1.745d1745d1742p-2,
    (int)9
  },
  { // Entry 185
    -0x1.745d1745d17420p8,
    -0x1.745d1745d1742p-2,
    (int)10
  },
  { // Entry 186
    -0x1.1745d1745d17p-12,
    -0x1.1745d1745d170p-2,
    (int)-10
  },
  { // Entry 187
    -0x1.1745d1745d17p-11,
    -0x1.1745d1745d170p-2,
    (int)-9
  },
  { // Entry 188
    -0x1.1745d1745d17p-10,
    -0x1.1745d1745d170p-2,
    (int)-8
  },
  { // Entry 189
    -0x1.1745d1745d17p-9,
    -0x1.1745d1745d170p-2,
    (int)-7
  },
  { // Entry 190
    -0x1.1745d1745d17p-8,
    -0x1.1745d1745d170p-2,
    (int)-6
  },
  { // Entry 191
    -0x1.1745d1745d17p-7,
    -0x1.1745d1745d170p-2,
    (int)-5
  },
  { // Entry 192
    -0x1.1745d1745d17p-6,
    -0x1.1745d1745d170p-2,
    (int)-4
  },
  { // Entry 193
    -0x1.1745d1745d17p-5,
    -0x1.1745d1745d170p-2,
    (int)-3
  },
  { // Entry 194
    -0x1.1745d1745d17p-4,
    -0x1.1745d1745d170p-2,
    (int)-2
  },
  { // Entry 195
    -0x1.1745d1745d17p-3,
    -0x1.1745d1745d170p-2,
    (int)-1
  },
  { // Entry 196
    -0x1.1745d1745d17p-2,
    -0x1.1745d1745d170p-2,
    (int)0
  },
  { // Entry 197
    -0x1.1745d1745d17p-1,
    -0x1.1745d1745d170p-2,
    (int)1
  },
  { // Entry 198
    -0x1.1745d1745d17p0,
    -0x1.1745d1745d170p-2,
    (int)2
  },
  { // Entry 199
    -0x1.1745d1745d17p1,
    -0x1.1745d1745d170p-2,
    (int)3
  },
  { // Entry 200
    -0x1.1745d1745d17p2,
    -0x1.1745d1745d170p-2,
    (int)4
  },
  { // Entry 201
    -0x1.1745d1745d17p3,
    -0x1.1745d1745d170p-2,
    (int)5
  },
  { // Entry 202
    -0x1.1745d1745d17p4,
    -0x1.1745d1745d170p-2,
    (int)6
  },
  { // Entry 203
    -0x1.1745d1745d17p5,
    -0x1.1745d1745d170p-2,
    (int)7
  },
  { // Entry 204
    -0x1.1745d1745d17p6,
    -0x1.1745d1745d170p-2,
    (int)8
  },
  { // Entry 205
    -0x1.1745d1745d17p7,
    -0x1.1745d1745d170p-2,
    (int)9
  },
  { // Entry 206
    -0x1.1745d1745d17p8,
    -0x1.1745d1745d170p-2,
    (int)10
  },
  { // Entry 207
    -0x1.745d1745d173d0p-13,
    -0x1.745d1745d173dp-3,
    (int)-10
  },
  { // Entry 208
    -0x1.745d1745d173d0p-12,
    -0x1.745d1745d173dp-3,
    (int)-9
  },
  { // Entry 209
    -0x1.745d1745d173d0p-11,
    -0x1.745d1745d173dp-3,
    (int)-8
  },
  { // Entry 210
    -0x1.745d1745d173d0p-10,
    -0x1.745d1745d173dp-3,
    (int)-7
  },
  { // Entry 211
    -0x1.745d1745d173d0p-9,
    -0x1.745d1745d173dp-3,
    (int)-6
  },
  { // Entry 212
    -0x1.745d1745d173d0p-8,
    -0x1.745d1745d173dp-3,
    (int)-5
  },
  { // Entry 213
    -0x1.745d1745d173d0p-7,
    -0x1.745d1745d173dp-3,
    (int)-4
  },
  { // Entry 214
    -0x1.745d1745d173d0p-6,
    -0x1.745d1745d173dp-3,
    (int)-3
  },
  { // Entry 215
    -0x1.745d1745d173d0p-5,
    -0x1.745d1745d173dp-3,
    (int)-2
  },
  { // Entry 216
    -0x1.745d1745d173d0p-4,
    -0x1.745d1745d173dp-3,
    (int)-1
  },
  { // Entry 217
    -0x1.745d1745d173d0p-3,
    -0x1.745d1745d173dp-3,
    (int)0
  },
  { // Entry 218
    -0x1.745d1745d173d0p-2,
    -0x1.745d1745d173dp-3,
    (int)1
  },
  { // Entry 219
    -0x1.745d1745d173d0p-1,
    -0x1.745d1745d173dp-3,
    (int)2
  },
  { // Entry 220
    -0x1.745d1745d173d0p0,
    -0x1.745d1745d173dp-3,
    (int)3
  },
  { // Entry 221
    -0x1.745d1745d173d0p1,
    -0x1.745d1745d173dp-3,
    (int)4
  },
  { // Entry 222
    -0x1.745d1745d173d0p2,
    -0x1.745d1745d173dp-3,
    (int)5
  },
  { // Entry 223
    -0x1.745d1745d173d0p3,
    -0x1.745d1745d173dp-3,
    (int)6
  },
  { // Entry 224
    -0x1.745d1745d173d0p4,
    -0x1.745d1745d173dp-3,
    (int)7
  },
  { // Entry 225
    -0x1.745d1745d173d0p5,
    -0x1.745d1745d173dp-3,
    (int)8
  },
  { // Entry 226
    -0x1.745d1745d173d0p6,
    -0x1.745d1745d173dp-3,
    (int)9
  },
  { // Entry 227
    -0x1.745d1745d173d0p7,
    -0x1.745d1745d173dp-3,
    (int)10
  },
  { // Entry 228
    -0x1.745d1745d17340p-14,
    -0x1.745d1745d1734p-4,
    (int)-10
  },
  { // Entry 229
    -0x1.745d1745d17340p-13,
    -0x1.745d1745d1734p-4,
    (int)-9
  },
  { // Entry 230
    -0x1.745d1745d17340p-12,
    -0x1.745d1745d1734p-4,
    (int)-8
  },
  { // Entry 231
    -0x1.745d1745d17340p-11,
    -0x1.745d1745d1734p-4,
    (int)-7
  },
  { // Entry 232
    -0x1.745d1745d17340p-10,
    -0x1.745d1745d1734p-4,
    (int)-6
  },
  { // Entry 233
    -0x1.745d1745d17340p-9,
    -0x1.745d1745d1734p-4,
    (int)-5
  },
  { // Entry 234
    -0x1.745d1745d17340p-8,
    -0x1.745d1745d1734p-4,
    (int)-4
  },
  { // Entry 235
    -0x1.745d1745d17340p-7,
    -0x1.745d1745d1734p-4,
    (int)-3
  },
  { // Entry 236
    -0x1.745d1745d17340p-6,
    -0x1.745d1745d1734p-4,
    (int)-2
  },
  { // Entry 237
    -0x1.745d1745d17340p-5,
    -0x1.745d1745d1734p-4,
    (int)-1
  },
  { // Entry 238
    -0x1.745d1745d17340p-4,
    -0x1.745d1745d1734p-4,
    (int)0
  },
  { // Entry 239
    -0x1.745d1745d17340p-3,
    -0x1.745d1745d1734p-4,
    (int)1
  },
  { // Entry 240
    -0x1.745d1745d17340p-2,
    -0x1.745d1745d1734p-4,
    (int)2
  },
  { // Entry 241
    -0x1.745d1745d17340p-1,
    -0x1.745d1745d1734p-4,
    (int)3
  },
  { // Entry 242
    -0x1.745d1745d17340p0,
    -0x1.745d1745d1734p-4,
    (int)4
  },
  { // Entry 243
    -0x1.745d1745d17340p1,
    -0x1.745d1745d1734p-4,
    (int)5
  },
  { // Entry 244
    -0x1.745d1745d17340p2,
    -0x1.745d1745d1734p-4,
    (int)6
  },
  { // Entry 245
    -0x1.745d1745d17340p3,
    -0x1.745d1745d1734p-4,
    (int)7
  },
  { // Entry 246
    -0x1.745d1745d17340p4,
    -0x1.745d1745d1734p-4,
    (int)8
  },
  { // Entry 247
    -0x1.745d1745d17340p5,
    -0x1.745d1745d1734p-4,
    (int)9
  },
  { // Entry 248
    -0x1.745d1745d17340p6,
    -0x1.745d1745d1734p-4,
    (int)10
  },
  { // Entry 249
    0x1.20p-62,
    0x1.2p-52,
    (int)-10
  },
  { // Entry 250
    0x1.20p-61,
    0x1.2p-52,
    (int)-9
  },
  { // Entry 251
    0x1.20p-60,
    0x1.2p-52,
    (int)-8
  },
  { // Entry 252
    0x1.20p-59,
    0x1.2p-52,
    (int)-7
  },
  { // Entry 253
    0x1.20p-58,
    0x1.2p-52,
    (int)-6
  },
  { // Entry 254
    0x1.20p-57,
    0x1.2p-52,
    (int)-5
  },
  { // Entry 255
    0x1.20p-56,
    0x1.2p-52,
    (int)-4
  },
  { // Entry 256
    0x1.20p-55,
    0x1.2p-52,
    (int)-3
  },
  { // Entry 257
    0x1.20p-54,
    0x1.2p-52,
    (int)-2
  },
  { // Entry 258
    0x1.20p-53,
    0x1.2p-52,
    (int)-1
  },
  { // Entry 259
    0x1.20p-52,
    0x1.2p-52,
    (int)0
  },
  { // Entry 260
    0x1.20p-51,
    0x1.2p-52,
    (int)1
  },
  { // Entry 261
    0x1.20p-50,
    0x1.2p-52,
    (int)2
  },
  { // Entry 262
    0x1.20p-49,
    0x1.2p-52,
    (int)3
  },
  { // Entry 263
    0x1.20p-48,
    0x1.2p-52,
    (int)4
  },
  { // Entry 264
    0x1.20p-47,
    0x1.2p-52,
    (int)5
  },
  { // Entry 265
    0x1.20p-46,
    0x1.2p-52,
    (int)6
  },
  { // Entry 266
    0x1.20p-45,
    0x1.2p-52,
    (int)7
  },
  { // Entry 267
    0x1.20p-44,
    0x1.2p-52,
    (int)8
  },
  { // Entry 268
    0x1.20p-43,
    0x1.2p-52,
    (int)9
  },
  { // Entry 269
    0x1.20p-42,
    0x1.2p-52,
    (int)10
  },
  { // Entry 270
    0x1.745d1745d17580p-14,
    0x1.745d1745d1758p-4,
    (int)-10
  },
  { // Entry 271
    0x1.745d1745d17580p-13,
    0x1.745d1745d1758p-4,
    (int)-9
  },
  { // Entry 272
    0x1.745d1745d17580p-12,
    0x1.745d1745d1758p-4,
    (int)-8
  },
  { // Entry 273
    0x1.745d1745d17580p-11,
    0x1.745d1745d1758p-4,
    (int)-7
  },
  { // Entry 274
    0x1.745d1745d17580p-10,
    0x1.745d1745d1758p-4,
    (int)-6
  },
  { // Entry 275
    0x1.745d1745d17580p-9,
    0x1.745d1745d1758p-4,
    (int)-5
  },
  { // Entry 276
    0x1.745d1745d17580p-8,
    0x1.745d1745d1758p-4,
    (int)-4
  },
  { // Entry 277
    0x1.745d1745d17580p-7,
    0x1.745d1745d1758p-4,
    (int)-3
  },
  { // Entry 278
    0x1.745d1745d17580p-6,
    0x1.745d1745d1758p-4,
    (int)-2
  },
  { // Entry 279
    0x1.745d1745d17580p-5,
    0x1.745d1745d1758p-4,
    (int)-1
  },
  { // Entry 280
    0x1.745d1745d17580p-4,
    0x1.745d1745d1758p-4,
    (int)0
  },
  { // Entry 281
    0x1.745d1745d17580p-3,
    0x1.745d1745d1758p-4,
    (int)1
  },
  { // Entry 282
    0x1.745d1745d17580p-2,
    0x1.745d1745d1758p-4,
    (int)2
  },
  { // Entry 283
    0x1.745d1745d17580p-1,
    0x1.745d1745d1758p-4,
    (int)3
  },
  { // Entry 284
    0x1.745d1745d17580p0,
    0x1.745d1745d1758p-4,
    (int)4
  },
  { // Entry 285
    0x1.745d1745d17580p1,
    0x1.745d1745d1758p-4,
    (int)5
  },
  { // Entry 286
    0x1.745d1745d17580p2,
    0x1.745d1745d1758p-4,
    (int)6
  },
  { // Entry 287
    0x1.745d1745d17580p3,
    0x1.745d1745d1758p-4,
    (int)7
  },
  { // Entry 288
    0x1.745d1745d17580p4,
    0x1.745d1745d1758p-4,
    (int)8
  },
  { // Entry 289
    0x1.745d1745d17580p5,
    0x1.745d1745d1758p-4,
    (int)9
  },
  { // Entry 290
    0x1.745d1745d17580p6,
    0x1.745d1745d1758p-4,
    (int)10
  },
  { // Entry 291
    0x1.745d1745d174f0p-13,
    0x1.745d1745d174fp-3,
    (int)-10
  },
  { // Entry 292
    0x1.745d1745d174f0p-12,
    0x1.745d1745d174fp-3,
    (int)-9
  },
  { // Entry 293
    0x1.745d1745d174f0p-11,
    0x1.745d1745d174fp-3,
    (int)-8
  },
  { // Entry 294
    0x1.745d1745d174f0p-10,
    0x1.745d1745d174fp-3,
    (int)-7
  },
  { // Entry 295
    0x1.745d1745d174f0p-9,
    0x1.745d1745d174fp-3,
    (int)-6
  },
  { // Entry 296
    0x1.745d1745d174f0p-8,
    0x1.745d1745d174fp-3,
    (int)-5
  },
  { // Entry 297
    0x1.745d1745d174f0p-7,
    0x1.745d1745d174fp-3,
    (int)-4
  },
  { // Entry 298
    0x1.745d1745d174f0p-6,
    0x1.745d1745d174fp-3,
    (int)-3
  },
  { // Entry 299
    0x1.745d1745d174f0p-5,
    0x1.745d1745d174fp-3,
    (int)-2
  },
  { // Entry 300
    0x1.745d1745d174f0p-4,
    0x1.745d1745d174fp-3,
    (int)-1
  },
  { // Entry 301
    0x1.745d1745d174f0p-3,
    0x1.745d1745d174fp-3,
    (int)0
  },
  { // Entry 302
    0x1.745d1745d174f0p-2,
    0x1.745d1745d174fp-3,
    (int)1
  },
  { // Entry 303
    0x1.745d1745d174f0p-1,
    0x1.745d1745d174fp-3,
    (int)2
  },
  { // Entry 304
    0x1.745d1745d174f0p0,
    0x1.745d1745d174fp-3,
    (int)3
  },
  { // Entry 305
    0x1.745d1745d174f0p1,
    0x1.745d1745d174fp-3,
    (int)4
  },
  { // Entry 306
    0x1.745d1745d174f0p2,
    0x1.745d1745d174fp-3,
    (int)5
  },
  { // Entry 307
    0x1.745d1745d174f0p3,
    0x1.745d1745d174fp-3,
    (int)6
  },
  { // Entry 308
    0x1.745d1745d174f0p4,
    0x1.745d1745d174fp-3,
    (int)7
  },
  { // Entry 309
    0x1.745d1745d174f0p5,
    0x1.745d1745d174fp-3,
    (int)8
  },
  { // Entry 310
    0x1.745d1745d174f0p6,
    0x1.745d1745d174fp-3,
    (int)9
  },
  { // Entry 311
    0x1.745d1745d174f0p7,
    0x1.745d1745d174fp-3,
    (int)10
  },
  { // Entry 312
    0x1.1745d1745d1790p-12,
    0x1.1745d1745d179p-2,
    (int)-10
  },
  { // Entry 313
    0x1.1745d1745d1790p-11,
    0x1.1745d1745d179p-2,
    (int)-9
  },
  { // Entry 314
    0x1.1745d1745d1790p-10,
    0x1.1745d1745d179p-2,
    (int)-8
  },
  { // Entry 315
    0x1.1745d1745d1790p-9,
    0x1.1745d1745d179p-2,
    (int)-7
  },
  { // Entry 316
    0x1.1745d1745d1790p-8,
    0x1.1745d1745d179p-2,
    (int)-6
  },
  { // Entry 317
    0x1.1745d1745d1790p-7,
    0x1.1745d1745d179p-2,
    (int)-5
  },
  { // Entry 318
    0x1.1745d1745d1790p-6,
    0x1.1745d1745d179p-2,
    (int)-4
  },
  { // Entry 319
    0x1.1745d1745d1790p-5,
    0x1.1745d1745d179p-2,
    (int)-3
  },
  { // Entry 320
    0x1.1745d1745d1790p-4,
    0x1.1745d1745d179p-2,
    (int)-2
  },
  { // Entry 321
    0x1.1745d1745d1790p-3,
    0x1.1745d1745d179p-2,
    (int)-1
  },
  { // Entry 322
    0x1.1745d1745d1790p-2,
    0x1.1745d1745d179p-2,
    (int)0
  },
  { // Entry 323
    0x1.1745d1745d1790p-1,
    0x1.1745d1745d179p-2,
    (int)1
  },
  { // Entry 324
    0x1.1745d1745d1790p0,
    0x1.1745d1745d179p-2,
    (int)2
  },
  { // Entry 325
    0x1.1745d1745d1790p1,
    0x1.1745d1745d179p-2,
    (int)3
  },
  { // Entry 326
    0x1.1745d1745d1790p2,
    0x1.1745d1745d179p-2,
    (int)4
  },
  { // Entry 327
    0x1.1745d1745d1790p3,
    0x1.1745d1745d179p-2,
    (int)5
  },
  { // Entry 328
    0x1.1745d1745d1790p4,
    0x1.1745d1745d179p-2,
    (int)6
  },
  { // Entry 329
    0x1.1745d1745d1790p5,
    0x1.1745d1745d179p-2,
    (int)7
  },
  { // Entry 330
    0x1.1745d1745d1790p6,
    0x1.1745d1745d179p-2,
    (int)8
  },
  { // Entry 331
    0x1.1745d1745d1790p7,
    0x1.1745d1745d179p-2,
    (int)9
  },
  { // Entry 332
    0x1.1745d1745d1790p8,
    0x1.1745d1745d179p-2,
    (int)10
  },
  { // Entry 333
    0x1.745d1745d174a0p-12,
    0x1.745d1745d174ap-2,
    (int)-10
  },
  { // Entry 334
    0x1.745d1745d174a0p-11,
    0x1.745d1745d174ap-2,
    (int)-9
  },
  { // Entry 335
    0x1.745d1745d174a0p-10,
    0x1.745d1745d174ap-2,
    (int)-8
  },
  { // Entry 336
    0x1.745d1745d174a0p-9,
    0x1.745d1745d174ap-2,
    (int)-7
  },
  { // Entry 337
    0x1.745d1745d174a0p-8,
    0x1.745d1745d174ap-2,
    (int)-6
  },
  { // Entry 338
    0x1.745d1745d174a0p-7,
    0x1.745d1745d174ap-2,
    (int)-5
  },
  { // Entry 339
    0x1.745d1745d174a0p-6,
    0x1.745d1745d174ap-2,
    (int)-4
  },
  { // Entry 340
    0x1.745d1745d174a0p-5,
    0x1.745d1745d174ap-2,
    (int)-3
  },
  { // Entry 341
    0x1.745d1745d174a0p-4,
    0x1.745d1745d174ap-2,
    (int)-2
  },
  { // Entry 342
    0x1.745d1745d174a0p-3,
    0x1.745d1745d174ap-2,
    (int)-1
  },
  { // Entry 343
    0x1.745d1745d174a0p-2,
    0x1.745d1745d174ap-2,
    (int)0
  },
  { // Entry 344
    0x1.745d1745d174a0p-1,
    0x1.745d1745d174ap-2,
    (int)1
  },
  { // Entry 345
    0x1.745d1745d174a0p0,
    0x1.745d1745d174ap-2,
    (int)2
  },
  { // Entry 346
    0x1.745d1745d174a0p1,
    0x1.745d1745d174ap-2,
    (int)3
  },
  { // Entry 347
    0x1.745d1745d174a0p2,
    0x1.745d1745d174ap-2,
    (int)4
  },
  { // Entry 348
    0x1.745d1745d174a0p3,
    0x1.745d1745d174ap-2,
    (int)5
  },
  { // Entry 349
    0x1.745d1745d174a0p4,
    0x1.745d1745d174ap-2,
    (int)6
  },
  { // Entry 350
    0x1.745d1745d174a0p5,
    0x1.745d1745d174ap-2,
    (int)7
  },
  { // Entry 351
    0x1.745d1745d174a0p6,
    0x1.745d1745d174ap-2,
    (int)8
  },
  { // Entry 352
    0x1.745d1745d174a0p7,
    0x1.745d1745d174ap-2,
    (int)9
  },
  { // Entry 353
    0x1.745d1745d174a0p8,
    0x1.745d1745d174ap-2,
    (int)10
  },
  { // Entry 354
    0x1.d1745d1745d1c0p-12,
    0x1.d1745d1745d1cp-2,
    (int)-10
  },
  { // Entry 355
    0x1.d1745d1745d1c0p-11,
    0x1.d1745d1745d1cp-2,
    (int)-9
  },
  { // Entry 356
    0x1.d1745d1745d1c0p-10,
    0x1.d1745d1745d1cp-2,
    (int)-8
  },
  { // Entry 357
    0x1.d1745d1745d1c0p-9,
    0x1.d1745d1745d1cp-2,
    (int)-7
  },
  { // Entry 358
    0x1.d1745d1745d1c0p-8,
    0x1.d1745d1745d1cp-2,
    (int)-6
  },
  { // Entry 359
    0x1.d1745d1745d1c0p-7,
    0x1.d1745d1745d1cp-2,
    (int)-5
  },
  { // Entry 360
    0x1.d1745d1745d1c0p-6,
    0x1.d1745d1745d1cp-2,
    (int)-4
  },
  { // Entry 361
    0x1.d1745d1745d1c0p-5,
    0x1.d1745d1745d1cp-2,
    (int)-3
  },
  { // Entry 362
    0x1.d1745d1745d1c0p-4,
    0x1.d1745d1745d1cp-2,
    (int)-2
  },
  { // Entry 363
    0x1.d1745d1745d1c0p-3,
    0x1.d1745d1745d1cp-2,
    (int)-1
  },
  { // Entry 364
    0x1.d1745d1745d1c0p-2,
    0x1.d1745d1745d1cp-2,
    (int)0
  },
  { // Entry 365
    0x1.d1745d1745d1c0p-1,
    0x1.d1745d1745d1cp-2,
    (int)1
  },
  { // Entry 366
    0x1.d1745d1745d1c0p0,
    0x1.d1745d1745d1cp-2,
    (int)2
  },
  { // Entry 367
    0x1.d1745d1745d1c0p1,
    0x1.d1745d1745d1cp-2,
    (int)3
  },
  { // Entry 368
    0x1.d1745d1745d1c0p2,
    0x1.d1745d1745d1cp-2,
    (int)4
  },
  { // Entry 369
    0x1.d1745d1745d1c0p3,
    0x1.d1745d1745d1cp-2,
    (int)5
  },
  { // Entry 370
    0x1.d1745d1745d1c0p4,
    0x1.d1745d1745d1cp-2,
    (int)6
  },
  { // Entry 371
    0x1.d1745d1745d1c0p5,
    0x1.d1745d1745d1cp-2,
    (int)7
  },
  { // Entry 372
    0x1.d1745d1745d1c0p6,
    0x1.d1745d1745d1cp-2,
    (int)8
  },
  { // Entry 373
    0x1.d1745d1745d1c0p7,
    0x1.d1745d1745d1cp-2,
    (int)9
  },
  { // Entry 374
    0x1.d1745d1745d1c0p8,
    0x1.d1745d1745d1cp-2,
    (int)10
  },
  { // Entry 375
    0x1.1745d1745d1770p-11,
    0x1.1745d1745d177p-1,
    (int)-10
  },
  { // Entry 376
    0x1.1745d1745d1770p-10,
    0x1.1745d1745d177p-1,
    (int)-9
  },
  { // Entry 377
    0x1.1745d1745d1770p-9,
    0x1.1745d1745d177p-1,
    (int)-8
  },
  { // Entry 378
    0x1.1745d1745d1770p-8,
    0x1.1745d1745d177p-1,
    (int)-7
  },
  { // Entry 379
    0x1.1745d1745d1770p-7,
    0x1.1745d1745d177p-1,
    (int)-6
  },
  { // Entry 380
    0x1.1745d1745d1770p-6,
    0x1.1745d1745d177p-1,
    (int)-5
  },
  { // Entry
"""


```
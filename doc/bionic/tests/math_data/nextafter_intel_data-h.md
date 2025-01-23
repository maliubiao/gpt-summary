Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Task:** The primary goal is to analyze the provided C code snippet, which appears to be a data file for testing the `nextafter` function in Android's bionic library. I need to understand what the data represents and its purpose within the context of testing.

2. **Identify Key Information:** I first skim the code to pick out important details:
    * The file path: `bionic/tests/math_data/nextafter_intel_data.handroid`
    * The `bionic` context (Android's C library).
    * The filename suggests data related to the `nextafter` function and "intel".
    * The data structure `data_1_2_t<double, double, double>` implies a structure holding three double-precision floating-point numbers.
    * The naming convention `g_nextafter_intel_data` strongly suggests this is a global array of test data for `nextafter`.
    * Each element in the array is initialized with three double values, labeled "Entry X".

3. **Infer the Purpose of the Data:**  Given the filename and the data structure, I can deduce that this array likely contains test cases for the `nextafter` function. Each entry probably represents:
    * The first input to `nextafter`.
    * The second input to `nextafter`.
    * The expected output of `nextafter` given those inputs.

4. **Connect to `nextafter` Function:** I recall what the `nextafter` function does. It takes two floating-point numbers as input and returns the next representable floating-point value after the first argument in the direction of the second argument.

5. **Relate to Android:**  Since the file is within Android's bionic library, this data is used to ensure the correctness of the `nextafter` implementation within the Android C library. This is crucial for the stability and accuracy of applications running on Android.

6. **Address Specific Questions (Mental Check-list):**

    * **功能 (Functionality):**  The primary function is to provide test data for the `nextafter` function.
    * **与 Android 的关系 (Relationship to Android):**  Directly related to the correctness of the math library in Android's C library (bionic).
    * **libc 函数功能实现 (libc function implementation):**  While the *data* file doesn't *implement* `nextafter`, it *tests* its implementation. I'll need to explain how `nextafter` generally works. Since the prompt asks about *this* file, I should emphasize its role in *testing* that implementation.
    * **dynamic linker 功能 (dynamic linker functionality):** This file is just data, it doesn't involve dynamic linking. I need to state this clearly.
    * **逻辑推理 (Logical reasoning):** The input and output pairs are the core logic. I need to give examples of how the `nextafter` function is being tested with specific values.
    * **用户或编程常见错误 (Common user/programming errors):**  It's less about *using* this data file directly and more about potential errors when *using* the `nextafter` function itself.
    * **Android framework/NDK 到达路径 (Android framework/NDK path):**  This data is used internally by the Android build system for testing. I need to outline the general testing process.
    * **Frida hook 示例 (Frida hook example):**  I can provide a Frida example to hook the `nextafter` function and observe its behavior with these test data inputs.
    * **归纳功能 (Summarize functionality):**  Reiterate the main purpose of the file.

7. **Structure the Answer:** I organize the answer according to the prompt's points, providing clear and concise explanations for each.

8. **Elaborate on Key Aspects:**

    * **`nextafter` explanation:**  Provide a clear description of what the `nextafter` function does, using the provided data as examples.
    * **Data format:** Explain the structure of the `g_nextafter_intel_data` array and the meaning of each element.
    * **Android context:** Emphasize its role in ensuring the quality of the Android platform.
    * **Frida example:** Craft a practical Frida script to demonstrate how to interact with the `nextafter` function.

9. **Refine and Review:** I reread my answer to ensure accuracy, completeness, and clarity. I check for any misunderstandings of the prompt or technical errors. I make sure the language is natural and easy to understand.

By following this process, I can systematically break down the request and generate a comprehensive and informative answer that addresses all the specified points. The key is to understand the context of the code snippet within the larger Android ecosystem.
## 对 `bionic/tests/math_data/nextafter_intel_data.handroid` 源代码文件的功能归纳 (第 1 部分)

**这个 C 源代码文件 `bionic/tests/math_data/nextafter_intel_data.handroid` 的主要功能是：**

**提供一组预定义的测试用例数据，用于验证 Android Bionic 库中 `nextafter` 函数在特定平台（Intel）上的正确性。**

更具体地说，这个文件定义了一个全局数组 `g_nextafter_intel_data`，其中包含了多个结构体，每个结构体代表一个独立的测试用例。每个测试用例包含三个 `double` 类型的数值：

1. **第一个数值：**  作为 `nextafter` 函数的第一个输入参数。
2. **第二个数值：**  作为 `nextafter` 函数的第二个输入参数，用于指定查找下一个浮点数的方向。
3. **第三个数值：**  是根据前两个输入参数，`nextafter` 函数应该返回的预期结果。

**总而言之，这个文件的核心功能是作为 `nextafter` 函数在 Intel 架构上的一个测试数据源，用于自动化测试和验证其实现是否符合预期。**

**以下是更详细的解释，将在后续部分展开：**

* **功能详细说明：**  文件内部定义了一个静态全局数组，包含了各种边界情况、正常情况和特殊情况下的 `nextafter` 函数的输入和预期输出值。
* **与 Android 的关系：** 这个文件是 Android Bionic 库测试套件的一部分，用于确保 Android 平台提供的 C 标准库函数的正确性和可靠性。
* **libc 函数的功能实现：**  这个文件本身不实现 `nextafter` 函数，而是用于测试它的实现。Bionic 库中 `nextafter` 的实现会使用到一些底层的浮点数操作和表示。
* **dynamic linker 的功能：** 这个文件不直接涉及 dynamic linker 的功能。Dynamic linker 负责在程序运行时加载和链接动态库，而这个文件是静态编译进测试程序的。
* **逻辑推理：** 文件中的每个数据条目都基于对 `nextafter` 函数行为的逻辑推理。例如，给定一个数和一个更大的数，`nextafter` 应该返回比原数稍微大一点的数。
* **用户或编程常见的使用错误：** 虽然这个文件是测试数据，但它反映了 `nextafter` 函数可能涉及的一些边界情况，例如处理零、无穷大、NaN 等。
* **Android framework or ndk 如何到达这里：**  开发者在 NDK 中使用 math.h 头文件声明的 `nextafter` 函数时，最终会调用到 Bionic 库中的实现。Android Framework 内部也可能使用到这些底层的数学函数。
* **Frida hook 示例：** 可以使用 Frida Hook 技术来拦截 `nextafter` 函数的调用，并观察其输入输出，从而验证测试数据的有效性。

**请等待第 2 部分，其中将详细解释以上各个方面。**

### 提示词
```
这是目录为bionic/tests/math_data/nextafter_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
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

static data_1_2_t<double, double, double> g_nextafter_intel_data[] = {
  { // Entry 0
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 1
    -0.0,
    -0x1.0p-1074,
    -0.0
  },
  { // Entry 2
    -0.0,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 3
    -0x1.p-1074,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 4
    -0.0,
    -0.0,
    -0.0
  },
  { // Entry 5
    0x1.p-1074,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 6
    0.0,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 7
    0.0,
    0x1.0p-1074,
    -0.0
  },
  { // Entry 8
    0x1.p-1074,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 9
    0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 10
    0x1.p0,
    0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 11
    0x1.p0,
    0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 12
    0x1.fffffffffffff0p-1,
    0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 13
    0x1.p0,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 14
    0x1.00000000000010p0,
    0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 15
    0x1.p0,
    0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 16
    0x1.p0,
    0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 17
    0x1.00000000000010p0,
    0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 18
    0x1.ffffffffffffe0p-1,
    0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 19
    0x1.ffffffffffffe0p-1,
    0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 20
    0x1.ffffffffffffe0p-1,
    0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 21
    0x1.fffffffffffff0p-1,
    0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 22
    0x1.fffffffffffff0p-1,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 23
    0x1.fffffffffffff0p-1,
    0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 24
    0x1.p0,
    0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 25
    0x1.p0,
    0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 26
    0x1.p0,
    0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 27
    -0x1.p0,
    -0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 28
    -0x1.p0,
    -0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 29
    -0x1.p0,
    -0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 30
    -0x1.fffffffffffff0p-1,
    -0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 31
    -0x1.fffffffffffff0p-1,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 32
    -0x1.fffffffffffff0p-1,
    -0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 33
    -0x1.ffffffffffffe0p-1,
    -0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 34
    -0x1.ffffffffffffe0p-1,
    -0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 35
    -0x1.ffffffffffffe0p-1,
    -0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 36
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 37
    -0x1.p0,
    -0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 38
    -0x1.p0,
    -0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 39
    -0x1.00000000000010p0,
    -0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 40
    -0x1.p0,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 41
    -0x1.fffffffffffff0p-1,
    -0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 42
    -0x1.p0,
    -0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 43
    -0x1.p0,
    -0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 44
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 45
    0x1.fffffffffffff0p0,
    0x1.fffffffffffffp0,
    0x1.fffffffffffffp0
  },
  { // Entry 46
    0x1.p1,
    0x1.fffffffffffffp0,
    0x1.0p1
  },
  { // Entry 47
    0x1.p1,
    0x1.fffffffffffffp0,
    0x1.0000000000001p1
  },
  { // Entry 48
    0x1.fffffffffffff0p0,
    0x1.0p1,
    0x1.fffffffffffffp0
  },
  { // Entry 49
    0x1.p1,
    0x1.0p1,
    0x1.0p1
  },
  { // Entry 50
    0x1.00000000000010p1,
    0x1.0p1,
    0x1.0000000000001p1
  },
  { // Entry 51
    0x1.p1,
    0x1.0000000000001p1,
    0x1.fffffffffffffp0
  },
  { // Entry 52
    0x1.p1,
    0x1.0000000000001p1,
    0x1.0p1
  },
  { // Entry 53
    0x1.00000000000010p1,
    0x1.0000000000001p1,
    0x1.0000000000001p1
  },
  { // Entry 54
    0x1.ffffffffffffe0p0,
    0x1.fffffffffffffp0,
    -0x1.0000000000001p1
  },
  { // Entry 55
    0x1.ffffffffffffe0p0,
    0x1.fffffffffffffp0,
    -0x1.0p1
  },
  { // Entry 56
    0x1.ffffffffffffe0p0,
    0x1.fffffffffffffp0,
    -0x1.fffffffffffffp0
  },
  { // Entry 57
    0x1.fffffffffffff0p0,
    0x1.0p1,
    -0x1.0000000000001p1
  },
  { // Entry 58
    0x1.fffffffffffff0p0,
    0x1.0p1,
    -0x1.0p1
  },
  { // Entry 59
    0x1.fffffffffffff0p0,
    0x1.0p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 60
    0x1.p1,
    0x1.0000000000001p1,
    -0x1.0000000000001p1
  },
  { // Entry 61
    0x1.p1,
    0x1.0000000000001p1,
    -0x1.0p1
  },
  { // Entry 62
    0x1.p1,
    0x1.0000000000001p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 63
    -0x1.p1,
    -0x1.0000000000001p1,
    0x1.fffffffffffffp0
  },
  { // Entry 64
    -0x1.p1,
    -0x1.0000000000001p1,
    0x1.0p1
  },
  { // Entry 65
    -0x1.p1,
    -0x1.0000000000001p1,
    0x1.0000000000001p1
  },
  { // Entry 66
    -0x1.fffffffffffff0p0,
    -0x1.0p1,
    0x1.fffffffffffffp0
  },
  { // Entry 67
    -0x1.fffffffffffff0p0,
    -0x1.0p1,
    0x1.0p1
  },
  { // Entry 68
    -0x1.fffffffffffff0p0,
    -0x1.0p1,
    0x1.0000000000001p1
  },
  { // Entry 69
    -0x1.ffffffffffffe0p0,
    -0x1.fffffffffffffp0,
    0x1.fffffffffffffp0
  },
  { // Entry 70
    -0x1.ffffffffffffe0p0,
    -0x1.fffffffffffffp0,
    0x1.0p1
  },
  { // Entry 71
    -0x1.ffffffffffffe0p0,
    -0x1.fffffffffffffp0,
    0x1.0000000000001p1
  },
  { // Entry 72
    -0x1.00000000000010p1,
    -0x1.0000000000001p1,
    -0x1.0000000000001p1
  },
  { // Entry 73
    -0x1.p1,
    -0x1.0000000000001p1,
    -0x1.0p1
  },
  { // Entry 74
    -0x1.p1,
    -0x1.0000000000001p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 75
    -0x1.00000000000010p1,
    -0x1.0p1,
    -0x1.0000000000001p1
  },
  { // Entry 76
    -0x1.p1,
    -0x1.0p1,
    -0x1.0p1
  },
  { // Entry 77
    -0x1.fffffffffffff0p0,
    -0x1.0p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 78
    -0x1.p1,
    -0x1.fffffffffffffp0,
    -0x1.0000000000001p1
  },
  { // Entry 79
    -0x1.p1,
    -0x1.fffffffffffffp0,
    -0x1.0p1
  },
  { // Entry 80
    -0x1.fffffffffffff0p0,
    -0x1.fffffffffffffp0,
    -0x1.fffffffffffffp0
  },
  { // Entry 81
    0x1.fffffffffffff0p9,
    0x1.fffffffffffffp9,
    0x1.fffffffffffffp9
  },
  { // Entry 82
    0x1.p10,
    0x1.fffffffffffffp9,
    0x1.0p10
  },
  { // Entry 83
    0x1.p10,
    0x1.fffffffffffffp9,
    0x1.0000000000001p10
  },
  { // Entry 84
    0x1.fffffffffffff0p9,
    0x1.0p10,
    0x1.fffffffffffffp9
  },
  { // Entry 85
    0x1.p10,
    0x1.0p10,
    0x1.0p10
  },
  { // Entry 86
    0x1.00000000000010p10,
    0x1.0p10,
    0x1.0000000000001p10
  },
  { // Entry 87
    0x1.p10,
    0x1.0000000000001p10,
    0x1.fffffffffffffp9
  },
  { // Entry 88
    0x1.p10,
    0x1.0000000000001p10,
    0x1.0p10
  },
  { // Entry 89
    0x1.00000000000010p10,
    0x1.0000000000001p10,
    0x1.0000000000001p10
  },
  { // Entry 90
    0x1.ffffffffffffe0p9,
    0x1.fffffffffffffp9,
    -0x1.0000000000001p10
  },
  { // Entry 91
    0x1.ffffffffffffe0p9,
    0x1.fffffffffffffp9,
    -0x1.0p10
  },
  { // Entry 92
    0x1.ffffffffffffe0p9,
    0x1.fffffffffffffp9,
    -0x1.fffffffffffffp9
  },
  { // Entry 93
    0x1.fffffffffffff0p9,
    0x1.0p10,
    -0x1.0000000000001p10
  },
  { // Entry 94
    0x1.fffffffffffff0p9,
    0x1.0p10,
    -0x1.0p10
  },
  { // Entry 95
    0x1.fffffffffffff0p9,
    0x1.0p10,
    -0x1.fffffffffffffp9
  },
  { // Entry 96
    0x1.p10,
    0x1.0000000000001p10,
    -0x1.0000000000001p10
  },
  { // Entry 97
    0x1.p10,
    0x1.0000000000001p10,
    -0x1.0p10
  },
  { // Entry 98
    0x1.p10,
    0x1.0000000000001p10,
    -0x1.fffffffffffffp9
  },
  { // Entry 99
    -0x1.p10,
    -0x1.0000000000001p10,
    0x1.fffffffffffffp9
  },
  { // Entry 100
    -0x1.p10,
    -0x1.0000000000001p10,
    0x1.0p10
  },
  { // Entry 101
    -0x1.p10,
    -0x1.0000000000001p10,
    0x1.0000000000001p10
  },
  { // Entry 102
    -0x1.fffffffffffff0p9,
    -0x1.0p10,
    0x1.fffffffffffffp9
  },
  { // Entry 103
    -0x1.fffffffffffff0p9,
    -0x1.0p10,
    0x1.0p10
  },
  { // Entry 104
    -0x1.fffffffffffff0p9,
    -0x1.0p10,
    0x1.0000000000001p10
  },
  { // Entry 105
    -0x1.ffffffffffffe0p9,
    -0x1.fffffffffffffp9,
    0x1.fffffffffffffp9
  },
  { // Entry 106
    -0x1.ffffffffffffe0p9,
    -0x1.fffffffffffffp9,
    0x1.0p10
  },
  { // Entry 107
    -0x1.ffffffffffffe0p9,
    -0x1.fffffffffffffp9,
    0x1.0000000000001p10
  },
  { // Entry 108
    -0x1.00000000000010p10,
    -0x1.0000000000001p10,
    -0x1.0000000000001p10
  },
  { // Entry 109
    -0x1.p10,
    -0x1.0000000000001p10,
    -0x1.0p10
  },
  { // Entry 110
    -0x1.p10,
    -0x1.0000000000001p10,
    -0x1.fffffffffffffp9
  },
  { // Entry 111
    -0x1.00000000000010p10,
    -0x1.0p10,
    -0x1.0000000000001p10
  },
  { // Entry 112
    -0x1.p10,
    -0x1.0p10,
    -0x1.0p10
  },
  { // Entry 113
    -0x1.fffffffffffff0p9,
    -0x1.0p10,
    -0x1.fffffffffffffp9
  },
  { // Entry 114
    -0x1.p10,
    -0x1.fffffffffffffp9,
    -0x1.0000000000001p10
  },
  { // Entry 115
    -0x1.p10,
    -0x1.fffffffffffffp9,
    -0x1.0p10
  },
  { // Entry 116
    -0x1.fffffffffffff0p9,
    -0x1.fffffffffffffp9,
    -0x1.fffffffffffffp9
  },
  { // Entry 117
    0x1.fffffffffffff0p99,
    0x1.fffffffffffffp99,
    0x1.fffffffffffffp99
  },
  { // Entry 118
    0x1.p100,
    0x1.fffffffffffffp99,
    0x1.0p100
  },
  { // Entry 119
    0x1.p100,
    0x1.fffffffffffffp99,
    0x1.0000000000001p100
  },
  { // Entry 120
    0x1.fffffffffffff0p99,
    0x1.0p100,
    0x1.fffffffffffffp99
  },
  { // Entry 121
    0x1.p100,
    0x1.0p100,
    0x1.0p100
  },
  { // Entry 122
    0x1.00000000000010p100,
    0x1.0p100,
    0x1.0000000000001p100
  },
  { // Entry 123
    0x1.p100,
    0x1.0000000000001p100,
    0x1.fffffffffffffp99
  },
  { // Entry 124
    0x1.p100,
    0x1.0000000000001p100,
    0x1.0p100
  },
  { // Entry 125
    0x1.00000000000010p100,
    0x1.0000000000001p100,
    0x1.0000000000001p100
  },
  { // Entry 126
    0x1.ffffffffffffe0p99,
    0x1.fffffffffffffp99,
    -0x1.0000000000001p100
  },
  { // Entry 127
    0x1.ffffffffffffe0p99,
    0x1.fffffffffffffp99,
    -0x1.0p100
  },
  { // Entry 128
    0x1.ffffffffffffe0p99,
    0x1.fffffffffffffp99,
    -0x1.fffffffffffffp99
  },
  { // Entry 129
    0x1.fffffffffffff0p99,
    0x1.0p100,
    -0x1.0000000000001p100
  },
  { // Entry 130
    0x1.fffffffffffff0p99,
    0x1.0p100,
    -0x1.0p100
  },
  { // Entry 131
    0x1.fffffffffffff0p99,
    0x1.0p100,
    -0x1.fffffffffffffp99
  },
  { // Entry 132
    0x1.p100,
    0x1.0000000000001p100,
    -0x1.0000000000001p100
  },
  { // Entry 133
    0x1.p100,
    0x1.0000000000001p100,
    -0x1.0p100
  },
  { // Entry 134
    0x1.p100,
    0x1.0000000000001p100,
    -0x1.fffffffffffffp99
  },
  { // Entry 135
    -0x1.p100,
    -0x1.0000000000001p100,
    0x1.fffffffffffffp99
  },
  { // Entry 136
    -0x1.p100,
    -0x1.0000000000001p100,
    0x1.0p100
  },
  { // Entry 137
    -0x1.p100,
    -0x1.0000000000001p100,
    0x1.0000000000001p100
  },
  { // Entry 138
    -0x1.fffffffffffff0p99,
    -0x1.0p100,
    0x1.fffffffffffffp99
  },
  { // Entry 139
    -0x1.fffffffffffff0p99,
    -0x1.0p100,
    0x1.0p100
  },
  { // Entry 140
    -0x1.fffffffffffff0p99,
    -0x1.0p100,
    0x1.0000000000001p100
  },
  { // Entry 141
    -0x1.ffffffffffffe0p99,
    -0x1.fffffffffffffp99,
    0x1.fffffffffffffp99
  },
  { // Entry 142
    -0x1.ffffffffffffe0p99,
    -0x1.fffffffffffffp99,
    0x1.0p100
  },
  { // Entry 143
    -0x1.ffffffffffffe0p99,
    -0x1.fffffffffffffp99,
    0x1.0000000000001p100
  },
  { // Entry 144
    -0x1.00000000000010p100,
    -0x1.0000000000001p100,
    -0x1.0000000000001p100
  },
  { // Entry 145
    -0x1.p100,
    -0x1.0000000000001p100,
    -0x1.0p100
  },
  { // Entry 146
    -0x1.p100,
    -0x1.0000000000001p100,
    -0x1.fffffffffffffp99
  },
  { // Entry 147
    -0x1.00000000000010p100,
    -0x1.0p100,
    -0x1.0000000000001p100
  },
  { // Entry 148
    -0x1.p100,
    -0x1.0p100,
    -0x1.0p100
  },
  { // Entry 149
    -0x1.fffffffffffff0p99,
    -0x1.0p100,
    -0x1.fffffffffffffp99
  },
  { // Entry 150
    -0x1.p100,
    -0x1.fffffffffffffp99,
    -0x1.0000000000001p100
  },
  { // Entry 151
    -0x1.p100,
    -0x1.fffffffffffffp99,
    -0x1.0p100
  },
  { // Entry 152
    -0x1.fffffffffffff0p99,
    -0x1.fffffffffffffp99,
    -0x1.fffffffffffffp99
  },
  { // Entry 153
    0x1.fffffffffffff0p999,
    0x1.fffffffffffffp999,
    0x1.fffffffffffffp999
  },
  { // Entry 154
    0x1.p1000,
    0x1.fffffffffffffp999,
    0x1.0p1000
  },
  { // Entry 155
    0x1.p1000,
    0x1.fffffffffffffp999,
    0x1.0000000000001p1000
  },
  { // Entry 156
    0x1.fffffffffffff0p999,
    0x1.0p1000,
    0x1.fffffffffffffp999
  },
  { // Entry 157
    0x1.p1000,
    0x1.0p1000,
    0x1.0p1000
  },
  { // Entry 158
    0x1.00000000000010p1000,
    0x1.0p1000,
    0x1.0000000000001p1000
  },
  { // Entry 159
    0x1.p1000,
    0x1.0000000000001p1000,
    0x1.fffffffffffffp999
  },
  { // Entry 160
    0x1.p1000,
    0x1.0000000000001p1000,
    0x1.0p1000
  },
  { // Entry 161
    0x1.00000000000010p1000,
    0x1.0000000000001p1000,
    0x1.0000000000001p1000
  },
  { // Entry 162
    0x1.ffffffffffffe0p999,
    0x1.fffffffffffffp999,
    -0x1.0000000000001p1000
  },
  { // Entry 163
    0x1.ffffffffffffe0p999,
    0x1.fffffffffffffp999,
    -0x1.0p1000
  },
  { // Entry 164
    0x1.ffffffffffffe0p999,
    0x1.fffffffffffffp999,
    -0x1.fffffffffffffp999
  },
  { // Entry 165
    0x1.fffffffffffff0p999,
    0x1.0p1000,
    -0x1.0000000000001p1000
  },
  { // Entry 166
    0x1.fffffffffffff0p999,
    0x1.0p1000,
    -0x1.0p1000
  },
  { // Entry 167
    0x1.fffffffffffff0p999,
    0x1.0p1000,
    -0x1.fffffffffffffp999
  },
  { // Entry 168
    0x1.p1000,
    0x1.0000000000001p1000,
    -0x1.0000000000001p1000
  },
  { // Entry 169
    0x1.p1000,
    0x1.0000000000001p1000,
    -0x1.0p1000
  },
  { // Entry 170
    0x1.p1000,
    0x1.0000000000001p1000,
    -0x1.fffffffffffffp999
  },
  { // Entry 171
    -0x1.p1000,
    -0x1.0000000000001p1000,
    0x1.fffffffffffffp999
  },
  { // Entry 172
    -0x1.p1000,
    -0x1.0000000000001p1000,
    0x1.0p1000
  },
  { // Entry 173
    -0x1.p1000,
    -0x1.0000000000001p1000,
    0x1.0000000000001p1000
  },
  { // Entry 174
    -0x1.fffffffffffff0p999,
    -0x1.0p1000,
    0x1.fffffffffffffp999
  },
  { // Entry 175
    -0x1.fffffffffffff0p999,
    -0x1.0p1000,
    0x1.0p1000
  },
  { // Entry 176
    -0x1.fffffffffffff0p999,
    -0x1.0p1000,
    0x1.0000000000001p1000
  },
  { // Entry 177
    -0x1.ffffffffffffe0p999,
    -0x1.fffffffffffffp999,
    0x1.fffffffffffffp999
  },
  { // Entry 178
    -0x1.ffffffffffffe0p999,
    -0x1.fffffffffffffp999,
    0x1.0p1000
  },
  { // Entry 179
    -0x1.ffffffffffffe0p999,
    -0x1.fffffffffffffp999,
    0x1.0000000000001p1000
  },
  { // Entry 180
    -0x1.00000000000010p1000,
    -0x1.0000000000001p1000,
    -0x1.0000000000001p1000
  },
  { // Entry 181
    -0x1.p1000,
    -0x1.0000000000001p1000,
    -0x1.0p1000
  },
  { // Entry 182
    -0x1.p1000,
    -0x1.0000000000001p1000,
    -0x1.fffffffffffffp999
  },
  { // Entry 183
    -0x1.00000000000010p1000,
    -0x1.0p1000,
    -0x1.0000000000001p1000
  },
  { // Entry 184
    -0x1.p1000,
    -0x1.0p1000,
    -0x1.0p1000
  },
  { // Entry 185
    -0x1.fffffffffffff0p999,
    -0x1.0p1000,
    -0x1.fffffffffffffp999
  },
  { // Entry 186
    -0x1.p1000,
    -0x1.fffffffffffffp999,
    -0x1.0000000000001p1000
  },
  { // Entry 187
    -0x1.p1000,
    -0x1.fffffffffffffp999,
    -0x1.0p1000
  },
  { // Entry 188
    -0x1.fffffffffffff0p999,
    -0x1.fffffffffffffp999,
    -0x1.fffffffffffffp999
  },
  { // Entry 189
    0x1.ffffffffffffe0p1023,
    0x1.ffffffffffffep1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 190
    0x1.fffffffffffff0p1023,
    0x1.ffffffffffffep1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 191
    0x1.fffffffffffff0p1023,
    0x1.ffffffffffffep1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 192
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 193
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 194
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 195
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 196
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 197
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 198
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 199
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 200
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 201
    -0x1.fffffffffffff0p1023,
    -0x1.ffffffffffffep1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 202
    -0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffep1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 203
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 204
    -0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffdp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 205
    -0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffdp1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 206
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffdp1023,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 207
    0x1.ffffffffffffd0p1023,
    0x1.ffffffffffffep1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 208
    0x1.ffffffffffffd0p1023,
    0x1.ffffffffffffep1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 209
    0x1.ffffffffffffd0p1023,
    0x1.ffffffffffffep1023,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 210
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 211
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 212
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 213
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 214
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 215
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 216
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 217
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 218
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 219
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 220
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 221
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 222
    -0x1.ffffffffffffc0p1023,
    -0x1.ffffffffffffdp1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 223
    -0x1.ffffffffffffc0p1023,
    -0x1.ffffffffffffdp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 224
    -0x1.ffffffffffffc0p1023,
    -0x1.ffffffffffffdp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 225
    0x1.ffffffffffffd0p1023,
    0x1.ffffffffffffep1023,
    -0x1.0p-1074
  },
  { // Entry 226
    0x1.ffffffffffffd0p1023,
    0x1.ffffffffffffep1023,
    -0.0
  },
  { // Entry 227
    0x1.ffffffffffffd0p1023,
    0x1.ffffffffffffep1023,
    0x1.0p-1074
  },
  { // Entry 228
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 229
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 230
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 231
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 232
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 233
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 234
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 235
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 236
    -0x1.ffffffffffffe0p1023,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 237
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    -0x1.0p-1074
  },
  { // Entry 238
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    -0.0
  },
  { // Entry 239
    -0x1.ffffffffffffd0p1023,
    -0x1.ffffffffffffep1023,
    0x1.0p-1074
  },
  { // Entry 240
    -0x1.ffffffffffffc0p1023,
    -0x1.ffffffffffffdp1023,
    -0x1.0p-1074
  },
  { // Entry 241
    -0x1.ffffffffffffc0p1023,
    -0x1.ffffffffffffdp1023,
    -0.0
  },
  { // Entry 242
    -0x1.ffffffffffffc0p1023,
    -0x1.ffffffffffffdp1023,
    0x1.0p-1074
  },
  { // Entry 243
    -0.0,
    -0x1.0p-1074,
    0x1.ffffffffffffep1023
  },
  { // Entry 244
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 245
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 246
    0x1.p-1074,
    -0.0,
    0x1.ffffffffffffep1023
  },
  { // Entry 247
    0x1.p-1074,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 248
    0x1.p-1074,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 249
    0x1.p-1073,
    0x1.0p-1074,
    0x1.ffffffffffffep1023
  },
  { // Entry 250
    0x1.p-1073,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 251
    0x1.p-1073,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 252
    -0x1.p-1073,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 253
    -0x1.p-1073,
    -0x1.0p-1074,
    -0x1.ffffffffffffep1023
  },
  { // Entry 254
    -0x1.p-1073,
    -0x1.0p-1074,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 255
    -0x1.p-1074,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 256
    -0x1.p-1074,
    -0.0,
    -0x1.ffffffffffffep1023
  },
  { // Entry 257
    -0x1.p-1074,
    -0.0,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 258
    0.0,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 259
    0.0,
    0x1.0p-1074,
    -0x1.ffffffffffffep1023
  },
  { // Entry 260
    0.0,
    0x1.0p-1074,
    -0x1.ffffffffffffdp1023
  },
  { // Entry 261
    0x1.00000fffffffe0p1,
    0x1.00000fffffffep1,
    0x1.00000fffffffep1
  },
  { // Entry 262
    0x1.00000ffffffff0p1,
    0x1.00000fffffffep1,
    0x1.00000ffffffffp1
  },
  { // Entry 263
    0x1.00000ffffffff0p1,
    0x1.00000fffffffep1,
    0x1.00001p1
  },
  { // Entry 264
    0x1.00000fffffffe0p1,
    0x1.00000ffffffffp1,
    0x1.00000fffffffep1
  },
  { // Entry 265
    0x1.00000ffffffff0p1,
    0x1.00000ffffffffp1,
    0x1.00000ffffffffp1
  },
  { // Entry 266
    0x1.000010p1,
    0x1.00000ffffffffp1,
    0x1.00001p1
  },
  { // Entry 267
    0x1.00000ffffffff0p1,
    0x1.00001p1,
    0x1.00000fffffffep1
  },
  { // Entry 268
    0x1.00000ffffffff0p1,
    0x1.00001p1,
    0x1.00000ffffffffp1
  },
  { // Entry 269
    0x1.000010p1,
    0x1.00001p1,
    0x1.00001p1
  },
  { // Entry 270
    HUGE_VAL,
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 271
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 272
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    0x1.0p-1022
  },
  { // Entry 273
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    0x1.ffffffffffffep-1023
  },
  { // Entry 274
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    0x1.0p-1074
  },
  { // Entry 275
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    0.0
  },
  { // Entry 276
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    -0.0
  },
  { // Entry 277
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    -0x1.0p-1074
  },
  { // Entry 278
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 279
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    -0x1.0p-1022
  },
  { // Entry 280
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    -0x1.fffffffffffffp1023
  },
  { // Entry 281
    0x1.fffffffffffff0p1023,
    HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 282
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    HUGE_VAL
  },
  { // Entry 283
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 284
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1022
  },
  { // Entry 285
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 286
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 287
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    0.0
  },
  { // Entry 288
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 289
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 290
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 291
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1022
  },
  { // Entry 292
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 293
    0x1.ffffffffffffe0p1023,
    0x1.fffffffffffffp1023,
    -HUGE_VAL
  },
  { // Entry 294
    0x1.00000000000010p-1022,
    0x1.0p-1022,
    HUGE_VAL
  },
  { // Entry 295
    0x1.00000000000010p-1022,
    0x1.0p-1022,
    0x1.fffffffffffffp1023
  },
  { // Entry 296
    0x1.p-1022,
    0x1.0p-1022,
    0x1.0p-1022
  },
  { // Entry 297
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    0x1.ffffffffffffep-1023
  },
  { // Entry 298
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    0x1.0p-1074
  },
  { // Entry 299
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    0.0
  },
  { // Entry 300
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    -0.0
  },
  { // Entry 301
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    -0x1.0p-1074
  },
  { // Entry 302
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 303
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    -0x1.0p-1022
  },
  { // Entry 304
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    -0x1.fffffffffffffp1023
  },
  { // Entry 305
    0x1.ffffffffffffe0p-1023,
    0x1.0p-1022,
    -HUGE_VAL
  },
  { // Entry 306
    0x1.p-1022,
    0x1.ffffffffffffep-1023,
    HUGE_VAL
  },
  { // Entry 307
    0x1.p-1022,
    0x1.ffffffffffffep-1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 308
    0x1.p-1022,
    0x1.ffffffffffffep-1023,
    0x1.0p-1022
  },
  { // Entry 309
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 310
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    0x1.0p-1074
  },
  { // Entry 311
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    0.0
  },
  { // Entry 312
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    -0.0
  },
  { // Entry 313
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.0p-1074
  },
  { // Entry 314
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 315
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.0p-1022
  },
  { // Entry 316
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 317
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffep-1023,
    -HUGE_VAL
  },
  { // Entry 318
    0x1.p-1073,
    0x1.0p-1074,
    HUGE_VAL
  },
  { // Entry 319
    0x1.p-1073,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 320
    0x1.p-1073,
    0x1.0p-1074,
    0x1.0p-1022
  },
  { // Entry 321
    0x1.p-1073,
    0x1.0p-1074,
    0x1.ffffffffffffep-1023
  },
  { // Entry 322
    0x1.p-1074,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 323
    0.0,
    0x1.0p-1074,
    0.0
  },
  { // Entry 324
    0.0,
    0x1.0p-1074,
    -0.0
  },
  { // Entry 325
    0.0,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 326
    0.0,
    0x1.0p-1074,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 327
    0.0,
    0x1.0p-1074,
    -0x1.0p-1022
  },
  { // Entry 328
    0.0,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 329
    0.0,
    0x1.0p-1074,
    -HUGE_VAL
  },
  { // Entry 330
    0x1.p-1074,
    0.0,
    HUGE_VAL
  },
  { // Entry 331
    0x1.p-1074,
    0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 332
    0x1.p-1074,
    0.0,
    0x1.0p-1022
  },
  { // Entry 333
    0x1.p-1074,
    0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 334
    0x1.p-1074,
    0.0,
    0x1.0p-1074
  },
  { // Entry 335
    0.0,
    0.0,
    0.0
  },
  { // Entry 336
    -0.0,
    0.0,
    -0.0
  },
  { // Entry 337
    -0x1.p-1074,
    0.0,
    -0x1.0p-1074
  },
  { // Entry 338
    -0x1.p-1074,
    0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 339
    -0x1.p-1074,
    0.0,
    -0x1.0p-1022
  },
  { // Entry 340
    -0x1.p-1074,
    0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 341
    -0x1.p-1074,
    0.0,
    -HUGE_VAL
  },
  { // Entry 342
    0x1.p-1074,
    -0.0,
    HUGE_VAL
  },
  { // Entry 343
    0x1.p-1074,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 344
    0x1.p-1074,
    -0.0,
    0x1.0p-1022
  },
  { // Entry 345
    0x1.p-1074,
    -0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 346
    0x1.p-1074,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 347
    0.0,
    -0.0,
    0.0
  },
  { // Entry 348
    -0.0,
    -0.0,
    -0.0
  },
  { // Entry 349
    -0x1.p-1074,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 350
    -0x1.p-1074,
    -0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 351
    -0x1.p-1074,
    -0.0,
    -0x1.0p-1022
  },
  { // Entry 352
    -0x1.p-1074,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 353
    -0x1.p-1074,
    -0.0,
    -HUGE_VAL
  },
  { // Entry 354
    -0.0,
    -0x1.0p-1074,
    HUGE_VAL
  },
  { // Entry 355
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 356
    -0.0,
    -0x1.0p-1074,
    0x1.0p-1022
  },
  { // Entry 357
    -0.0,
    -0x1.0p-1074,
    0x1.ffffffffffffep-1023
  },
  { // Entry 358
    -0.0,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 359
    -0.0,
    -0x1.0p-1074,
    0.0
  },
  { // Entry 360
    -0.0,
    -0x1.0p-1074,
    -0.0
  },
  { // Entry 361
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 362
    -0x1.p-1073,
    -0x1.0p-1074,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 363
    -0x1.p-1073,
    -0x1.0p-1074,
    -0x1.0p-1022
  },
  { // Entry 364
    -0x1.p-1073,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 365
    -0x1.p-1073,
    -0x1.0p-1074,
    -HUGE_VAL
  },
  { // Entry 366
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffep-1023,
    HUGE_VAL
  },
  { // Entry 367
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 368
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.0p-1022
  },
  { // Entry 369
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 370
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffep-1023,
    0x
```
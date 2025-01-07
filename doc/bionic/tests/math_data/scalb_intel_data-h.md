Response:
Let's break down the thought process for answering the prompt.

**1. Understanding the Core Request:**

The central request is to analyze the provided C code snippet, specifically `bionic/tests/math_data/scalb_intel_data.handroid`, and explain its purpose and relationship to Android. The prompt also asks for detailed explanations of libc functions, dynamic linker involvement, usage errors, and how Android components reach this code. It's explicitly labeled as part 1 of 3, and the immediate goal is to summarize the functionality.

**2. Initial Code Inspection:**

The first step is to quickly scan the code. Key observations:

* **Copyright Notice:** Indicates it's part of the Android Open Source Project.
* **`static data_1_2_t<double, double, double> g_scalb_intel_data[]`:**  This is the main data structure. It's a static array named `g_scalb_intel_data`. The type `data_1_2_t` suggests it's a template likely defined elsewhere, and it holds three `double` values.
* **Large Array of Initializers:**  The code is primarily a large list of brace-enclosed triplets of floating-point numbers.
* **Hexadecimal Floating-Point Literals:**  The numbers are in hexadecimal floating-point format (e.g., `-0x1.0p-1074`). This is a strong clue about the nature of the data.
* **Comments like `// Entry 0`:** These are just index markers and don't provide functional information.
* **`HUGE_VAL`:** This macro suggests the data might involve boundary conditions or special values related to floating-point arithmetic.

**3. Connecting to the File Path:**

The file path `bionic/tests/math_data/scalb_intel_data.handroid` is crucial:

* **`bionic`:** This immediately tells us it's related to Android's core C library.
* **`tests`:**  This confirms the data is used for testing.
* **`math_data`:**  This narrows down the purpose to testing mathematical functions.
* **`scalb_intel_data`:** The `scalb` part is a strong indicator. `scalb` is a standard math library function. The `intel_data` part suggests these test cases might be specific to Intel architectures or were derived from Intel's testing. The `.handroid` extension likely indicates it's specifically for Android.

**4. Deducing the Functionality (scalb):**

Based on the filename and the structure of the data, the most logical deduction is that this file contains test data for the `scalb` function. The `scalb` function multiplies a floating-point number by 2 raised to an integer power.

**5. Interpreting the Data Structure:**

The `data_1_2_t<double, double, double>` structure, combined with the knowledge of `scalb`, suggests the following interpretation for each entry:

* **First `double`:**  Likely the *input* value to the `scalb` function.
* **Second `double`:** Likely the *scale factor* (the power of 2) to be used in `scalb`. It's presented as a floating-point number, which might represent the intended scaling factor or an intermediate value.
* **Third `double`:** Likely the *expected output* of the `scalb` function for the given input and scale factor.

**6. Formulating the Summary:**

Now, it's time to synthesize the observations into a concise summary. The key points to include are:

* The file's location within Android's Bionic library.
* Its purpose as test data.
* The specific function it likely tests: `scalb`.
* The structure of the data (triplets of doubles).
* The potential meaning of each double in the triplet (input, scale factor/intermediate, expected output).

**7. Refining the Language:**

Finally, the summary needs to be clear and concise, using appropriate technical terminology. For example, mentioning "test vectors" or "test cases" is good. Emphasizing that the data is used for verifying the correctness of the `scalb` implementation is also important.

This step-by-step process allows us to analyze the code snippet, understand its context within the Android ecosystem, and arrive at a logical and informative summary of its functionality, even without seeing the definition of `data_1_2_t` or the implementation of `scalb`.
好的，根据你提供的代码片段，这是 `bionic/tests/math_data/scalb_intel_data.handroid` 文件的内容，它位于 Android 的 Bionic 库中。Bionic 库是 Android 的 C 库、数学库和动态链接器。

**功能归纳:**

这个文件 `scalb_intel_data.handroid` 的主要功能是为 `scalb` 函数提供测试数据。 具体来说，它包含了一个静态数组 `g_scalb_intel_data`，该数组由多个结构体 `data_1_2_t` 组成，每个结构体都包含了三个 `double` 类型的数值。 这些数值很可能代表了 `scalb` 函数的输入参数和期望的输出结果，用于测试 `scalb` 函数在不同输入下的行为是否正确。

**更详细的解释：**

* **测试数据:**  这个文件很明显是一个测试数据文件，从文件名中的 `tests` 和 `data` 可以看出。 它的目的是提供一系列预定义的输入和期望输出，用于自动化测试 `scalb` 函数的实现是否符合规范。
* **`scalb` 函数:**  文件名中明确指出了 `scalb`，这是一个标准的 C 语言数学库函数。 `scalb(x, n)` 函数的功能是将浮点数 `x` 乘以 2 的 `n` 次幂，即 `x * 2^n`。
* **`g_scalb_intel_data` 数组:**  这是一个静态数组，意味着它的内容在编译时就已经确定，并且在程序运行期间不会改变。 `static` 关键字也意味着这个数组的作用域仅限于当前文件。
* **`data_1_2_t<double, double, double>` 结构体:**  这是一个模板结构体，通常在测试代码中用于组织测试用例的数据。从类型参数 `<double, double, double>` 可以推断，每个结构体实例包含三个 `double` 类型的成员。
* **可能的结构体成员含义:** 结合 `scalb` 函数的功能，这三个 `double` 值很可能分别代表：
    1. **输入值 (x):**  `scalb` 函数的第一个参数，即要进行缩放的浮点数。
    2. **缩放指数 (n):** `scalb` 函数的第二个参数，即 2 的幂指数。 注意，这里也使用了 `double` 类型，这可能是为了表示各种类型的指数，或者在某些测试场景下，第二个值可能不是直接的整数指数，而是与指数计算相关的中间值。
    3. **期望输出值 (x * 2^n):**  对于给定的输入值和缩放指数，`scalb` 函数应该返回的正确结果。

**与 Android 功能的关系举例:**

在 Android 系统中，各种应用程序和系统服务都可能需要进行数学计算，包括浮点数运算。 Bionic 库作为 Android 的 C 标准库，提供了 `scalb` 这样的基础数学函数。

例如：

* **图形渲染:**  在进行 2D 或 3D 图形渲染时，可能需要对坐标或向量进行缩放操作，`scalb` 可以用于快速进行 2 的幂次方的缩放。
* **音频处理:** 音频信号的幅度调整可能涉及到乘以 2 的幂次方，`scalb` 可以用于实现这种操作。
* **科学计算类应用:**  这类应用经常需要进行各种复杂的数学运算，`scalb` 可以作为其中的一个基础构建块。

**总结（针对第1部分）:**

总而言之，`bionic/tests/math_data/scalb_intel_data.handroid` 文件是一个存储 `scalb` 函数测试数据的静态数组。 数组中的每个元素都包含一组输入值和期望的输出值，用于验证 `scalb` 函数在 Android Bionic 库中的实现是否正确。 这种测试驱动的方法有助于确保 Android 平台的数学运算的准确性和可靠性。

Prompt: 
```
这是目录为bionic/tests/math_data/scalb_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_2_t<double, double, double> g_scalb_intel_data[] = {
  { // Entry 0
    -0.0,
    -0x1.0p-1074,
    -0x1.4p3
  },
  { // Entry 1
    -0x1.55555555555560p-1024,
    -0x1.5555555555556p-2,
    -0x1.ff0p9
  },
  { // Entry 2
    -0x1.6db6db6db6db70p-1023,
    -0x1.6db6db6db6db7p-1,
    -0x1.ff0p9
  },
  { // Entry 3
    -0x1.8e38e38e38e390p-1023,
    -0x1.8e38e38e38e39p-1,
    -0x1.ff0p9
  },
  { // Entry 4
    0.0,
    0x1.0p-1074,
    -0x1.0p0
  },
  { // Entry 5
    0.0,
    0x1.0p-1074,
    -0x1.4p3
  },
  { // Entry 6
    0.0,
    0x1.0p-1074,
    -0x1.780p5
  },
  { // Entry 7
    0x1.p-51,
    0x1.0p-1074,
    0x1.ff8p9
  },
  { // Entry 8
    0x1.5464a606112880p-1026,
    0x1.5464a60611288p-2,
    -0x1.0p10
  },
  { // Entry 9
    HUGE_VAL,
    0x1.8e147ae147ae1p0,
    0x1.fffffffc0p30
  },
  { // Entry 10
    0.0,
    0x1.dddddddddddddp-2,
    -0x1.0c4p10
  },
  { // Entry 11
    0.0,
    0x1.f7df7df7df7dfp-2,
    -0x1.0c4p10
  },
  { // Entry 12
    HUGE_VAL,
    0x1.ffffffffffff6p30,
    0x1.0p31
  },
  { // Entry 13
    0x1.ffffffffffffc0p-1033,
    0x1.ffffffffffffcp-1023,
    -0x1.4p3
  },
  { // Entry 14
    0x1.ffffffffffffc0p-1022,
    0x1.ffffffffffffcp-1023,
    0x1.0p0
  },
  { // Entry 15
    0x1.ffffffffffffe0p-1070,
    0x1.ffffffffffffep-1023,
    -0x1.780p5
  },
  { // Entry 16
    0x1.ffffffffffffe0p-1022,
    0x1.ffffffffffffep-1023,
    0x1.0p0
  },
  { // Entry 17
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    0x1.fffffffc0p30
  },
  { // Entry 18
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    0x1.fffffffc0p30
  },
  { // Entry 19
    -0x1.p-10,
    -0x1.0p0,
    -0x1.4p3
  },
  { // Entry 20
    -0x1.p-9,
    -0x1.0p0,
    -0x1.2p3
  },
  { // Entry 21
    -0x1.p-8,
    -0x1.0p0,
    -0x1.0p3
  },
  { // Entry 22
    -0x1.p-7,
    -0x1.0p0,
    -0x1.cp2
  },
  { // Entry 23
    -0x1.p-6,
    -0x1.0p0,
    -0x1.8p2
  },
  { // Entry 24
    -0x1.p-5,
    -0x1.0p0,
    -0x1.4p2
  },
  { // Entry 25
    -0x1.p-4,
    -0x1.0p0,
    -0x1.0p2
  },
  { // Entry 26
    -0x1.p-3,
    -0x1.0p0,
    -0x1.8p1
  },
  { // Entry 27
    -0x1.p-2,
    -0x1.0p0,
    -0x1.0p1
  },
  { // Entry 28
    -0x1.p-1,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 29
    -0x1.p0,
    -0x1.0p0,
    0.0
  },
  { // Entry 30
    -0x1.p1,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 31
    -0x1.p2,
    -0x1.0p0,
    0x1.0p1
  },
  { // Entry 32
    -0x1.p3,
    -0x1.0p0,
    0x1.8p1
  },
  { // Entry 33
    -0x1.p4,
    -0x1.0p0,
    0x1.0p2
  },
  { // Entry 34
    -0x1.p5,
    -0x1.0p0,
    0x1.4p2
  },
  { // Entry 35
    -0x1.p6,
    -0x1.0p0,
    0x1.8p2
  },
  { // Entry 36
    -0x1.p7,
    -0x1.0p0,
    0x1.cp2
  },
  { // Entry 37
    -0x1.p8,
    -0x1.0p0,
    0x1.0p3
  },
  { // Entry 38
    -0x1.p9,
    -0x1.0p0,
    0x1.2p3
  },
  { // Entry 39
    -0x1.p10,
    -0x1.0p0,
    0x1.4p3
  },
  { // Entry 40
    -0x1.d1745d1745d170p-11,
    -0x1.d1745d1745d17p-1,
    -0x1.4p3
  },
  { // Entry 41
    -0x1.d1745d1745d170p-10,
    -0x1.d1745d1745d17p-1,
    -0x1.2p3
  },
  { // Entry 42
    -0x1.d1745d1745d170p-9,
    -0x1.d1745d1745d17p-1,
    -0x1.0p3
  },
  { // Entry 43
    -0x1.d1745d1745d170p-8,
    -0x1.d1745d1745d17p-1,
    -0x1.cp2
  },
  { // Entry 44
    -0x1.d1745d1745d170p-7,
    -0x1.d1745d1745d17p-1,
    -0x1.8p2
  },
  { // Entry 45
    -0x1.d1745d1745d170p-6,
    -0x1.d1745d1745d17p-1,
    -0x1.4p2
  },
  { // Entry 46
    -0x1.d1745d1745d170p-5,
    -0x1.d1745d1745d17p-1,
    -0x1.0p2
  },
  { // Entry 47
    -0x1.d1745d1745d170p-4,
    -0x1.d1745d1745d17p-1,
    -0x1.8p1
  },
  { // Entry 48
    -0x1.d1745d1745d170p-3,
    -0x1.d1745d1745d17p-1,
    -0x1.0p1
  },
  { // Entry 49
    -0x1.d1745d1745d170p-2,
    -0x1.d1745d1745d17p-1,
    -0x1.0p0
  },
  { // Entry 50
    -0x1.d1745d1745d170p-1,
    -0x1.d1745d1745d17p-1,
    0.0
  },
  { // Entry 51
    -0x1.d1745d1745d170p0,
    -0x1.d1745d1745d17p-1,
    0x1.0p0
  },
  { // Entry 52
    -0x1.d1745d1745d170p1,
    -0x1.d1745d1745d17p-1,
    0x1.0p1
  },
  { // Entry 53
    -0x1.d1745d1745d170p2,
    -0x1.d1745d1745d17p-1,
    0x1.8p1
  },
  { // Entry 54
    -0x1.d1745d1745d170p3,
    -0x1.d1745d1745d17p-1,
    0x1.0p2
  },
  { // Entry 55
    -0x1.d1745d1745d170p4,
    -0x1.d1745d1745d17p-1,
    0x1.4p2
  },
  { // Entry 56
    -0x1.d1745d1745d170p5,
    -0x1.d1745d1745d17p-1,
    0x1.8p2
  },
  { // Entry 57
    -0x1.d1745d1745d170p6,
    -0x1.d1745d1745d17p-1,
    0x1.cp2
  },
  { // Entry 58
    -0x1.d1745d1745d170p7,
    -0x1.d1745d1745d17p-1,
    0x1.0p3
  },
  { // Entry 59
    -0x1.d1745d1745d170p8,
    -0x1.d1745d1745d17p-1,
    0x1.2p3
  },
  { // Entry 60
    -0x1.d1745d1745d170p9,
    -0x1.d1745d1745d17p-1,
    0x1.4p3
  },
  { // Entry 61
    -0x1.a2e8ba2e8ba2e0p-11,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.4p3
  },
  { // Entry 62
    -0x1.a2e8ba2e8ba2e0p-10,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.2p3
  },
  { // Entry 63
    -0x1.a2e8ba2e8ba2e0p-9,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.0p3
  },
  { // Entry 64
    -0x1.a2e8ba2e8ba2e0p-8,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.cp2
  },
  { // Entry 65
    -0x1.a2e8ba2e8ba2e0p-7,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.8p2
  },
  { // Entry 66
    -0x1.a2e8ba2e8ba2e0p-6,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.4p2
  },
  { // Entry 67
    -0x1.a2e8ba2e8ba2e0p-5,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.0p2
  },
  { // Entry 68
    -0x1.a2e8ba2e8ba2e0p-4,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.8p1
  },
  { // Entry 69
    -0x1.a2e8ba2e8ba2e0p-3,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.0p1
  },
  { // Entry 70
    -0x1.a2e8ba2e8ba2e0p-2,
    -0x1.a2e8ba2e8ba2ep-1,
    -0x1.0p0
  },
  { // Entry 71
    -0x1.a2e8ba2e8ba2e0p-1,
    -0x1.a2e8ba2e8ba2ep-1,
    0.0
  },
  { // Entry 72
    -0x1.a2e8ba2e8ba2e0p0,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.0p0
  },
  { // Entry 73
    -0x1.a2e8ba2e8ba2e0p1,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.0p1
  },
  { // Entry 74
    -0x1.a2e8ba2e8ba2e0p2,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.8p1
  },
  { // Entry 75
    -0x1.a2e8ba2e8ba2e0p3,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.0p2
  },
  { // Entry 76
    -0x1.a2e8ba2e8ba2e0p4,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.4p2
  },
  { // Entry 77
    -0x1.a2e8ba2e8ba2e0p5,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.8p2
  },
  { // Entry 78
    -0x1.a2e8ba2e8ba2e0p6,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.cp2
  },
  { // Entry 79
    -0x1.a2e8ba2e8ba2e0p7,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.0p3
  },
  { // Entry 80
    -0x1.a2e8ba2e8ba2e0p8,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.2p3
  },
  { // Entry 81
    -0x1.a2e8ba2e8ba2e0p9,
    -0x1.a2e8ba2e8ba2ep-1,
    0x1.4p3
  },
  { // Entry 82
    -0x1.745d1745d17450p-11,
    -0x1.745d1745d1745p-1,
    -0x1.4p3
  },
  { // Entry 83
    -0x1.745d1745d17450p-10,
    -0x1.745d1745d1745p-1,
    -0x1.2p3
  },
  { // Entry 84
    -0x1.745d1745d17450p-9,
    -0x1.745d1745d1745p-1,
    -0x1.0p3
  },
  { // Entry 85
    -0x1.745d1745d17450p-8,
    -0x1.745d1745d1745p-1,
    -0x1.cp2
  },
  { // Entry 86
    -0x1.745d1745d17450p-7,
    -0x1.745d1745d1745p-1,
    -0x1.8p2
  },
  { // Entry 87
    -0x1.745d1745d17450p-6,
    -0x1.745d1745d1745p-1,
    -0x1.4p2
  },
  { // Entry 88
    -0x1.745d1745d17450p-5,
    -0x1.745d1745d1745p-1,
    -0x1.0p2
  },
  { // Entry 89
    -0x1.745d1745d17450p-4,
    -0x1.745d1745d1745p-1,
    -0x1.8p1
  },
  { // Entry 90
    -0x1.745d1745d17450p-3,
    -0x1.745d1745d1745p-1,
    -0x1.0p1
  },
  { // Entry 91
    -0x1.745d1745d17450p-2,
    -0x1.745d1745d1745p-1,
    -0x1.0p0
  },
  { // Entry 92
    -0x1.745d1745d17450p-1,
    -0x1.745d1745d1745p-1,
    0.0
  },
  { // Entry 93
    -0x1.745d1745d17450p0,
    -0x1.745d1745d1745p-1,
    0x1.0p0
  },
  { // Entry 94
    -0x1.745d1745d17450p1,
    -0x1.745d1745d1745p-1,
    0x1.0p1
  },
  { // Entry 95
    -0x1.745d1745d17450p2,
    -0x1.745d1745d1745p-1,
    0x1.8p1
  },
  { // Entry 96
    -0x1.745d1745d17450p3,
    -0x1.745d1745d1745p-1,
    0x1.0p2
  },
  { // Entry 97
    -0x1.745d1745d17450p4,
    -0x1.745d1745d1745p-1,
    0x1.4p2
  },
  { // Entry 98
    -0x1.745d1745d17450p5,
    -0x1.745d1745d1745p-1,
    0x1.8p2
  },
  { // Entry 99
    -0x1.745d1745d17450p6,
    -0x1.745d1745d1745p-1,
    0x1.cp2
  },
  { // Entry 100
    -0x1.745d1745d17450p7,
    -0x1.745d1745d1745p-1,
    0x1.0p3
  },
  { // Entry 101
    -0x1.745d1745d17450p8,
    -0x1.745d1745d1745p-1,
    0x1.2p3
  },
  { // Entry 102
    -0x1.745d1745d17450p9,
    -0x1.745d1745d1745p-1,
    0x1.4p3
  },
  { // Entry 103
    -0x1.45d1745d1745c0p-11,
    -0x1.45d1745d1745cp-1,
    -0x1.4p3
  },
  { // Entry 104
    -0x1.45d1745d1745c0p-10,
    -0x1.45d1745d1745cp-1,
    -0x1.2p3
  },
  { // Entry 105
    -0x1.45d1745d1745c0p-9,
    -0x1.45d1745d1745cp-1,
    -0x1.0p3
  },
  { // Entry 106
    -0x1.45d1745d1745c0p-8,
    -0x1.45d1745d1745cp-1,
    -0x1.cp2
  },
  { // Entry 107
    -0x1.45d1745d1745c0p-7,
    -0x1.45d1745d1745cp-1,
    -0x1.8p2
  },
  { // Entry 108
    -0x1.45d1745d1745c0p-6,
    -0x1.45d1745d1745cp-1,
    -0x1.4p2
  },
  { // Entry 109
    -0x1.45d1745d1745c0p-5,
    -0x1.45d1745d1745cp-1,
    -0x1.0p2
  },
  { // Entry 110
    -0x1.45d1745d1745c0p-4,
    -0x1.45d1745d1745cp-1,
    -0x1.8p1
  },
  { // Entry 111
    -0x1.45d1745d1745c0p-3,
    -0x1.45d1745d1745cp-1,
    -0x1.0p1
  },
  { // Entry 112
    -0x1.45d1745d1745c0p-2,
    -0x1.45d1745d1745cp-1,
    -0x1.0p0
  },
  { // Entry 113
    -0x1.45d1745d1745c0p-1,
    -0x1.45d1745d1745cp-1,
    0.0
  },
  { // Entry 114
    -0x1.45d1745d1745c0p0,
    -0x1.45d1745d1745cp-1,
    0x1.0p0
  },
  { // Entry 115
    -0x1.45d1745d1745c0p1,
    -0x1.45d1745d1745cp-1,
    0x1.0p1
  },
  { // Entry 116
    -0x1.45d1745d1745c0p2,
    -0x1.45d1745d1745cp-1,
    0x1.8p1
  },
  { // Entry 117
    -0x1.45d1745d1745c0p3,
    -0x1.45d1745d1745cp-1,
    0x1.0p2
  },
  { // Entry 118
    -0x1.45d1745d1745c0p4,
    -0x1.45d1745d1745cp-1,
    0x1.4p2
  },
  { // Entry 119
    -0x1.45d1745d1745c0p5,
    -0x1.45d1745d1745cp-1,
    0x1.8p2
  },
  { // Entry 120
    -0x1.45d1745d1745c0p6,
    -0x1.45d1745d1745cp-1,
    0x1.cp2
  },
  { // Entry 121
    -0x1.45d1745d1745c0p7,
    -0x1.45d1745d1745cp-1,
    0x1.0p3
  },
  { // Entry 122
    -0x1.45d1745d1745c0p8,
    -0x1.45d1745d1745cp-1,
    0x1.2p3
  },
  { // Entry 123
    -0x1.45d1745d1745c0p9,
    -0x1.45d1745d1745cp-1,
    0x1.4p3
  },
  { // Entry 124
    -0x1.1745d1745d1730p-11,
    -0x1.1745d1745d173p-1,
    -0x1.4p3
  },
  { // Entry 125
    -0x1.1745d1745d1730p-10,
    -0x1.1745d1745d173p-1,
    -0x1.2p3
  },
  { // Entry 126
    -0x1.1745d1745d1730p-9,
    -0x1.1745d1745d173p-1,
    -0x1.0p3
  },
  { // Entry 127
    -0x1.1745d1745d1730p-8,
    -0x1.1745d1745d173p-1,
    -0x1.cp2
  },
  { // Entry 128
    -0x1.1745d1745d1730p-7,
    -0x1.1745d1745d173p-1,
    -0x1.8p2
  },
  { // Entry 129
    -0x1.1745d1745d1730p-6,
    -0x1.1745d1745d173p-1,
    -0x1.4p2
  },
  { // Entry 130
    -0x1.1745d1745d1730p-5,
    -0x1.1745d1745d173p-1,
    -0x1.0p2
  },
  { // Entry 131
    -0x1.1745d1745d1730p-4,
    -0x1.1745d1745d173p-1,
    -0x1.8p1
  },
  { // Entry 132
    -0x1.1745d1745d1730p-3,
    -0x1.1745d1745d173p-1,
    -0x1.0p1
  },
  { // Entry 133
    -0x1.1745d1745d1730p-2,
    -0x1.1745d1745d173p-1,
    -0x1.0p0
  },
  { // Entry 134
    -0x1.1745d1745d1730p-1,
    -0x1.1745d1745d173p-1,
    0.0
  },
  { // Entry 135
    -0x1.1745d1745d1730p0,
    -0x1.1745d1745d173p-1,
    0x1.0p0
  },
  { // Entry 136
    -0x1.1745d1745d1730p1,
    -0x1.1745d1745d173p-1,
    0x1.0p1
  },
  { // Entry 137
    -0x1.1745d1745d1730p2,
    -0x1.1745d1745d173p-1,
    0x1.8p1
  },
  { // Entry 138
    -0x1.1745d1745d1730p3,
    -0x1.1745d1745d173p-1,
    0x1.0p2
  },
  { // Entry 139
    -0x1.1745d1745d1730p4,
    -0x1.1745d1745d173p-1,
    0x1.4p2
  },
  { // Entry 140
    -0x1.1745d1745d1730p5,
    -0x1.1745d1745d173p-1,
    0x1.8p2
  },
  { // Entry 141
    -0x1.1745d1745d1730p6,
    -0x1.1745d1745d173p-1,
    0x1.cp2
  },
  { // Entry 142
    -0x1.1745d1745d1730p7,
    -0x1.1745d1745d173p-1,
    0x1.0p3
  },
  { // Entry 143
    -0x1.1745d1745d1730p8,
    -0x1.1745d1745d173p-1,
    0x1.2p3
  },
  { // Entry 144
    -0x1.1745d1745d1730p9,
    -0x1.1745d1745d173p-1,
    0x1.4p3
  },
  { // Entry 145
    -0x1.d1745d1745d140p-12,
    -0x1.d1745d1745d14p-2,
    -0x1.4p3
  },
  { // Entry 146
    -0x1.d1745d1745d140p-11,
    -0x1.d1745d1745d14p-2,
    -0x1.2p3
  },
  { // Entry 147
    -0x1.d1745d1745d140p-10,
    -0x1.d1745d1745d14p-2,
    -0x1.0p3
  },
  { // Entry 148
    -0x1.d1745d1745d140p-9,
    -0x1.d1745d1745d14p-2,
    -0x1.cp2
  },
  { // Entry 149
    -0x1.d1745d1745d140p-8,
    -0x1.d1745d1745d14p-2,
    -0x1.8p2
  },
  { // Entry 150
    -0x1.d1745d1745d140p-7,
    -0x1.d1745d1745d14p-2,
    -0x1.4p2
  },
  { // Entry 151
    -0x1.d1745d1745d140p-6,
    -0x1.d1745d1745d14p-2,
    -0x1.0p2
  },
  { // Entry 152
    -0x1.d1745d1745d140p-5,
    -0x1.d1745d1745d14p-2,
    -0x1.8p1
  },
  { // Entry 153
    -0x1.d1745d1745d140p-4,
    -0x1.d1745d1745d14p-2,
    -0x1.0p1
  },
  { // Entry 154
    -0x1.d1745d1745d140p-3,
    -0x1.d1745d1745d14p-2,
    -0x1.0p0
  },
  { // Entry 155
    -0x1.d1745d1745d140p-2,
    -0x1.d1745d1745d14p-2,
    0.0
  },
  { // Entry 156
    -0x1.d1745d1745d140p-1,
    -0x1.d1745d1745d14p-2,
    0x1.0p0
  },
  { // Entry 157
    -0x1.d1745d1745d140p0,
    -0x1.d1745d1745d14p-2,
    0x1.0p1
  },
  { // Entry 158
    -0x1.d1745d1745d140p1,
    -0x1.d1745d1745d14p-2,
    0x1.8p1
  },
  { // Entry 159
    -0x1.d1745d1745d140p2,
    -0x1.d1745d1745d14p-2,
    0x1.0p2
  },
  { // Entry 160
    -0x1.d1745d1745d140p3,
    -0x1.d1745d1745d14p-2,
    0x1.4p2
  },
  { // Entry 161
    -0x1.d1745d1745d140p4,
    -0x1.d1745d1745d14p-2,
    0x1.8p2
  },
  { // Entry 162
    -0x1.d1745d1745d140p5,
    -0x1.d1745d1745d14p-2,
    0x1.cp2
  },
  { // Entry 163
    -0x1.d1745d1745d140p6,
    -0x1.d1745d1745d14p-2,
    0x1.0p3
  },
  { // Entry 164
    -0x1.d1745d1745d140p7,
    -0x1.d1745d1745d14p-2,
    0x1.2p3
  },
  { // Entry 165
    -0x1.d1745d1745d140p8,
    -0x1.d1745d1745d14p-2,
    0x1.4p3
  },
  { // Entry 166
    -0x1.745d1745d17420p-12,
    -0x1.745d1745d1742p-2,
    -0x1.4p3
  },
  { // Entry 167
    -0x1.745d1745d17420p-11,
    -0x1.745d1745d1742p-2,
    -0x1.2p3
  },
  { // Entry 168
    -0x1.745d1745d17420p-10,
    -0x1.745d1745d1742p-2,
    -0x1.0p3
  },
  { // Entry 169
    -0x1.745d1745d17420p-9,
    -0x1.745d1745d1742p-2,
    -0x1.cp2
  },
  { // Entry 170
    -0x1.745d1745d17420p-8,
    -0x1.745d1745d1742p-2,
    -0x1.8p2
  },
  { // Entry 171
    -0x1.745d1745d17420p-7,
    -0x1.745d1745d1742p-2,
    -0x1.4p2
  },
  { // Entry 172
    -0x1.745d1745d17420p-6,
    -0x1.745d1745d1742p-2,
    -0x1.0p2
  },
  { // Entry 173
    -0x1.745d1745d17420p-5,
    -0x1.745d1745d1742p-2,
    -0x1.8p1
  },
  { // Entry 174
    -0x1.745d1745d17420p-4,
    -0x1.745d1745d1742p-2,
    -0x1.0p1
  },
  { // Entry 175
    -0x1.745d1745d17420p-3,
    -0x1.745d1745d1742p-2,
    -0x1.0p0
  },
  { // Entry 176
    -0x1.745d1745d17420p-2,
    -0x1.745d1745d1742p-2,
    0.0
  },
  { // Entry 177
    -0x1.745d1745d17420p-1,
    -0x1.745d1745d1742p-2,
    0x1.0p0
  },
  { // Entry 178
    -0x1.745d1745d17420p0,
    -0x1.745d1745d1742p-2,
    0x1.0p1
  },
  { // Entry 179
    -0x1.745d1745d17420p1,
    -0x1.745d1745d1742p-2,
    0x1.8p1
  },
  { // Entry 180
    -0x1.745d1745d17420p2,
    -0x1.745d1745d1742p-2,
    0x1.0p2
  },
  { // Entry 181
    -0x1.745d1745d17420p3,
    -0x1.745d1745d1742p-2,
    0x1.4p2
  },
  { // Entry 182
    -0x1.745d1745d17420p4,
    -0x1.745d1745d1742p-2,
    0x1.8p2
  },
  { // Entry 183
    -0x1.745d1745d17420p5,
    -0x1.745d1745d1742p-2,
    0x1.cp2
  },
  { // Entry 184
    -0x1.745d1745d17420p6,
    -0x1.745d1745d1742p-2,
    0x1.0p3
  },
  { // Entry 185
    -0x1.745d1745d17420p7,
    -0x1.745d1745d1742p-2,
    0x1.2p3
  },
  { // Entry 186
    -0x1.745d1745d17420p8,
    -0x1.745d1745d1742p-2,
    0x1.4p3
  },
  { // Entry 187
    -0x1.1745d1745d17p-12,
    -0x1.1745d1745d170p-2,
    -0x1.4p3
  },
  { // Entry 188
    -0x1.1745d1745d17p-11,
    -0x1.1745d1745d170p-2,
    -0x1.2p3
  },
  { // Entry 189
    -0x1.1745d1745d17p-10,
    -0x1.1745d1745d170p-2,
    -0x1.0p3
  },
  { // Entry 190
    -0x1.1745d1745d17p-9,
    -0x1.1745d1745d170p-2,
    -0x1.cp2
  },
  { // Entry 191
    -0x1.1745d1745d17p-8,
    -0x1.1745d1745d170p-2,
    -0x1.8p2
  },
  { // Entry 192
    -0x1.1745d1745d17p-7,
    -0x1.1745d1745d170p-2,
    -0x1.4p2
  },
  { // Entry 193
    -0x1.1745d1745d17p-6,
    -0x1.1745d1745d170p-2,
    -0x1.0p2
  },
  { // Entry 194
    -0x1.1745d1745d17p-5,
    -0x1.1745d1745d170p-2,
    -0x1.8p1
  },
  { // Entry 195
    -0x1.1745d1745d17p-4,
    -0x1.1745d1745d170p-2,
    -0x1.0p1
  },
  { // Entry 196
    -0x1.1745d1745d17p-3,
    -0x1.1745d1745d170p-2,
    -0x1.0p0
  },
  { // Entry 197
    -0x1.1745d1745d17p-2,
    -0x1.1745d1745d170p-2,
    0.0
  },
  { // Entry 198
    -0x1.1745d1745d17p-1,
    -0x1.1745d1745d170p-2,
    0x1.0p0
  },
  { // Entry 199
    -0x1.1745d1745d17p0,
    -0x1.1745d1745d170p-2,
    0x1.0p1
  },
  { // Entry 200
    -0x1.1745d1745d17p1,
    -0x1.1745d1745d170p-2,
    0x1.8p1
  },
  { // Entry 201
    -0x1.1745d1745d17p2,
    -0x1.1745d1745d170p-2,
    0x1.0p2
  },
  { // Entry 202
    -0x1.1745d1745d17p3,
    -0x1.1745d1745d170p-2,
    0x1.4p2
  },
  { // Entry 203
    -0x1.1745d1745d17p4,
    -0x1.1745d1745d170p-2,
    0x1.8p2
  },
  { // Entry 204
    -0x1.1745d1745d17p5,
    -0x1.1745d1745d170p-2,
    0x1.cp2
  },
  { // Entry 205
    -0x1.1745d1745d17p6,
    -0x1.1745d1745d170p-2,
    0x1.0p3
  },
  { // Entry 206
    -0x1.1745d1745d17p7,
    -0x1.1745d1745d170p-2,
    0x1.2p3
  },
  { // Entry 207
    -0x1.1745d1745d17p8,
    -0x1.1745d1745d170p-2,
    0x1.4p3
  },
  { // Entry 208
    -0x1.745d1745d173d0p-13,
    -0x1.745d1745d173dp-3,
    -0x1.4p3
  },
  { // Entry 209
    -0x1.745d1745d173d0p-12,
    -0x1.745d1745d173dp-3,
    -0x1.2p3
  },
  { // Entry 210
    -0x1.745d1745d173d0p-11,
    -0x1.745d1745d173dp-3,
    -0x1.0p3
  },
  { // Entry 211
    -0x1.745d1745d173d0p-10,
    -0x1.745d1745d173dp-3,
    -0x1.cp2
  },
  { // Entry 212
    -0x1.745d1745d173d0p-9,
    -0x1.745d1745d173dp-3,
    -0x1.8p2
  },
  { // Entry 213
    -0x1.745d1745d173d0p-8,
    -0x1.745d1745d173dp-3,
    -0x1.4p2
  },
  { // Entry 214
    -0x1.745d1745d173d0p-7,
    -0x1.745d1745d173dp-3,
    -0x1.0p2
  },
  { // Entry 215
    -0x1.745d1745d173d0p-6,
    -0x1.745d1745d173dp-3,
    -0x1.8p1
  },
  { // Entry 216
    -0x1.745d1745d173d0p-5,
    -0x1.745d1745d173dp-3,
    -0x1.0p1
  },
  { // Entry 217
    -0x1.745d1745d173d0p-4,
    -0x1.745d1745d173dp-3,
    -0x1.0p0
  },
  { // Entry 218
    -0x1.745d1745d173d0p-3,
    -0x1.745d1745d173dp-3,
    0.0
  },
  { // Entry 219
    -0x1.745d1745d173d0p-2,
    -0x1.745d1745d173dp-3,
    0x1.0p0
  },
  { // Entry 220
    -0x1.745d1745d173d0p-1,
    -0x1.745d1745d173dp-3,
    0x1.0p1
  },
  { // Entry 221
    -0x1.745d1745d173d0p0,
    -0x1.745d1745d173dp-3,
    0x1.8p1
  },
  { // Entry 222
    -0x1.745d1745d173d0p1,
    -0x1.745d1745d173dp-3,
    0x1.0p2
  },
  { // Entry 223
    -0x1.745d1745d173d0p2,
    -0x1.745d1745d173dp-3,
    0x1.4p2
  },
  { // Entry 224
    -0x1.745d1745d173d0p3,
    -0x1.745d1745d173dp-3,
    0x1.8p2
  },
  { // Entry 225
    -0x1.745d1745d173d0p4,
    -0x1.745d1745d173dp-3,
    0x1.cp2
  },
  { // Entry 226
    -0x1.745d1745d173d0p5,
    -0x1.745d1745d173dp-3,
    0x1.0p3
  },
  { // Entry 227
    -0x1.745d1745d173d0p6,
    -0x1.745d1745d173dp-3,
    0x1.2p3
  },
  { // Entry 228
    -0x1.745d1745d173d0p7,
    -0x1.745d1745d173dp-3,
    0x1.4p3
  },
  { // Entry 229
    -0x1.745d1745d17340p-14,
    -0x1.745d1745d1734p-4,
    -0x1.4p3
  },
  { // Entry 230
    -0x1.745d1745d17340p-13,
    -0x1.745d1745d1734p-4,
    -0x1.2p3
  },
  { // Entry 231
    -0x1.745d1745d17340p-12,
    -0x1.745d1745d1734p-4,
    -0x1.0p3
  },
  { // Entry 232
    -0x1.745d1745d17340p-11,
    -0x1.745d1745d1734p-4,
    -0x1.cp2
  },
  { // Entry 233
    -0x1.745d1745d17340p-10,
    -0x1.745d1745d1734p-4,
    -0x1.8p2
  },
  { // Entry 234
    -0x1.745d1745d17340p-9,
    -0x1.745d1745d1734p-4,
    -0x1.4p2
  },
  { // Entry 235
    -0x1.745d1745d17340p-8,
    -0x1.745d1745d1734p-4,
    -0x1.0p2
  },
  { // Entry 236
    -0x1.745d1745d17340p-7,
    -0x1.745d1745d1734p-4,
    -0x1.8p1
  },
  { // Entry 237
    -0x1.745d1745d17340p-6,
    -0x1.745d1745d1734p-4,
    -0x1.0p1
  },
  { // Entry 238
    -0x1.745d1745d17340p-5,
    -0x1.745d1745d1734p-4,
    -0x1.0p0
  },
  { // Entry 239
    -0x1.745d1745d17340p-4,
    -0x1.745d1745d1734p-4,
    0.0
  },
  { // Entry 240
    -0x1.745d1745d17340p-3,
    -0x1.745d1745d1734p-4,
    0x1.0p0
  },
  { // Entry 241
    -0x1.745d1745d17340p-2,
    -0x1.745d1745d1734p-4,
    0x1.0p1
  },
  { // Entry 242
    -0x1.745d1745d17340p-1,
    -0x1.745d1745d1734p-4,
    0x1.8p1
  },
  { // Entry 243
    -0x1.745d1745d17340p0,
    -0x1.745d1745d1734p-4,
    0x1.0p2
  },
  { // Entry 244
    -0x1.745d1745d17340p1,
    -0x1.745d1745d1734p-4,
    0x1.4p2
  },
  { // Entry 245
    -0x1.745d1745d17340p2,
    -0x1.745d1745d1734p-4,
    0x1.8p2
  },
  { // Entry 246
    -0x1.745d1745d17340p3,
    -0x1.745d1745d1734p-4,
    0x1.cp2
  },
  { // Entry 247
    -0x1.745d1745d17340p4,
    -0x1.745d1745d1734p-4,
    0x1.0p3
  },
  { // Entry 248
    -0x1.745d1745d17340p5,
    -0x1.745d1745d1734p-4,
    0x1.2p3
  },
  { // Entry 249
    -0x1.745d1745d17340p6,
    -0x1.745d1745d1734p-4,
    0x1.4p3
  },
  { // Entry 250
    0x1.20p-62,
    0x1.2p-52,
    -0x1.4p3
  },
  { // Entry 251
    0x1.20p-61,
    0x1.2p-52,
    -0x1.2p3
  },
  { // Entry 252
    0x1.20p-60,
    0x1.2p-52,
    -0x1.0p3
  },
  { // Entry 253
    0x1.20p-59,
    0x1.2p-52,
    -0x1.cp2
  },
  { // Entry 254
    0x1.20p-58,
    0x1.2p-52,
    -0x1.8p2
  },
  { // Entry 255
    0x1.20p-57,
    0x1.2p-52,
    -0x1.4p2
  },
  { // Entry 256
    0x1.20p-56,
    0x1.2p-52,
    -0x1.0p2
  },
  { // Entry 257
    0x1.20p-55,
    0x1.2p-52,
    -0x1.8p1
  },
  { // Entry 258
    0x1.20p-54,
    0x1.2p-52,
    -0x1.0p1
  },
  { // Entry 259
    0x1.20p-53,
    0x1.2p-52,
    -0x1.0p0
  },
  { // Entry 260
    0x1.20p-52,
    0x1.2p-52,
    0.0
  },
  { // Entry 261
    0x1.20p-51,
    0x1.2p-52,
    0x1.0p0
  },
  { // Entry 262
    0x1.20p-50,
    0x1.2p-52,
    0x1.0p1
  },
  { // Entry 263
    0x1.20p-49,
    0x1.2p-52,
    0x1.8p1
  },
  { // Entry 264
    0x1.20p-48,
    0x1.2p-52,
    0x1.0p2
  },
  { // Entry 265
    0x1.20p-47,
    0x1.2p-52,
    0x1.4p2
  },
  { // Entry 266
    0x1.20p-46,
    0x1.2p-52,
    0x1.8p2
  },
  { // Entry 267
    0x1.20p-45,
    0x1.2p-52,
    0x1.cp2
  },
  { // Entry 268
    0x1.20p-44,
    0x1.2p-52,
    0x1.0p3
  },
  { // Entry 269
    0x1.20p-43,
    0x1.2p-52,
    0x1.2p3
  },
  { // Entry 270
    0x1.20p-42,
    0x1.2p-52,
    0x1.4p3
  },
  { // Entry 271
    0x1.745d1745d17580p-14,
    0x1.745d1745d1758p-4,
    -0x1.4p3
  },
  { // Entry 272
    0x1.745d1745d17580p-13,
    0x1.745d1745d1758p-4,
    -0x1.2p3
  },
  { // Entry 273
    0x1.745d1745d17580p-12,
    0x1.745d1745d1758p-4,
    -0x1.0p3
  },
  { // Entry 274
    0x1.745d1745d17580p-11,
    0x1.745d1745d1758p-4,
    -0x1.cp2
  },
  { // Entry 275
    0x1.745d1745d17580p-10,
    0x1.745d1745d1758p-4,
    -0x1.8p2
  },
  { // Entry 276
    0x1.745d1745d17580p-9,
    0x1.745d1745d1758p-4,
    -0x1.4p2
  },
  { // Entry 277
    0x1.745d1745d17580p-8,
    0x1.745d1745d1758p-4,
    -0x1.0p2
  },
  { // Entry 278
    0x1.745d1745d17580p-7,
    0x1.745d1745d1758p-4,
    -0x1.8p1
  },
  { // Entry 279
    0x1.745d1745d17580p-6,
    0x1.745d1745d1758p-4,
    -0x1.0p1
  },
  { // Entry 280
    0x1.745d1745d17580p-5,
    0x1.745d1745d1758p-4,
    -0x1.0p0
  },
  { // Entry 281
    0x1.745d1745d17580p-4,
    0x1.745d1745d1758p-4,
    0.0
  },
  { // Entry 282
    0x1.745d1745d17580p-3,
    0x1.745d1745d1758p-4,
    0x1.0p0
  },
  { // Entry 283
    0x1.745d1745d17580p-2,
    0x1.745d1745d1758p-4,
    0x1.0p1
  },
  { // Entry 284
    0x1.745d1745d17580p-1,
    0x1.745d1745d1758p-4,
    0x1.8p1
  },
  { // Entry 285
    0x1.745d1745d17580p0,
    0x1.745d1745d1758p-4,
    0x1.0p2
  },
  { // Entry 286
    0x1.745d1745d17580p1,
    0x1.745d1745d1758p-4,
    0x1.4p2
  },
  { // Entry 287
    0x1.745d1745d17580p2,
    0x1.745d1745d1758p-4,
    0x1.8p2
  },
  { // Entry 288
    0x1.745d1745d17580p3,
    0x1.745d1745d1758p-4,
    0x1.cp2
  },
  { // Entry 289
    0x1.745d1745d17580p4,
    0x1.745d1745d1758p-4,
    0x1.0p3
  },
  { // Entry 290
    0x1.745d1745d17580p5,
    0x1.745d1745d1758p-4,
    0x1.2p3
  },
  { // Entry 291
    0x1.745d1745d17580p6,
    0x1.745d1745d1758p-4,
    0x1.4p3
  },
  { // Entry 292
    0x1.745d1745d174f0p-13,
    0x1.745d1745d174fp-3,
    -0x1.4p3
  },
  { // Entry 293
    0x1.745d1745d174f0p-12,
    0x1.745d1745d174fp-3,
    -0x1.2p3
  },
  { // Entry 294
    0x1.745d1745d174f0p-11,
    0x1.745d1745d174fp-3,
    -0x1.0p3
  },
  { // Entry 295
    0x1.745d1745d174f0p-10,
    0x1.745d1745d174fp-3,
    -0x1.cp2
  },
  { // Entry 296
    0x1.745d1745d174f0p-9,
    0x1.745d1745d174fp-3,
    -0x1.8p2
  },
  { // Entry 297
    0x1.745d1745d174f0p-8,
    0x1.745d1745d174fp-3,
    -0x1.4p2
  },
  { // Entry 298
    0x1.745d1745d174f0p-7,
    0x1.745d1745d174fp-3,
    -0x1.0p2
  },
  { // Entry 299
    0x1.745d1745d174f0p-6,
    0x1.745d1745d174fp-3,
    -0x1.8p1
  },
  { // Entry 300
    0x1.745d1745d174f0p-5,
    0x1.745d1745d174fp-3,
    -0x1.0p1
  },
  { // Entry 301
    0x1.745d1745d174f0p-4,
    0x1.745d1745d174fp-3,
    -0x1.0p0
  },
  { // Entry 302
    0x1.745d1745d174f0p-3,
    0x1.745d1745d174fp-3,
    0.0
  },
  { // Entry 303
    0x1.745d1745d174f0p-2,
    0x1.745d1745d174fp-3,
    0x1.0p0
  },
  { // Entry 304
    0x1.745d1745d174f0p-1,
    0x1.745d1745d174fp-3,
    0x1.0p1
  },
  { // Entry 305
    0x1.745d1745d174f0p0,
    0x1.745d1745d174fp-3,
    0x1.8p1
  },
  { // Entry 306
    0x1.745d1745d174f0p1,
    0x1.745d1745d174fp-3,
    0x1.0p2
  },
  { // Entry 307
    0x1.745d1745d174f0p2,
    0x1.745d1745d174fp-3,
    0x1.4p2
  },
  { // Entry 308
    0x1.745d1745d174f0p3,
    0x1.745d1745d174fp-3,
    0x1.8p2
  },
  { // Entry 309
    0x1.745d1745d174f0p4,
    0x1.745d1745d174fp-3,
    0x1.cp2
  },
  { // Entry 310
    0x1.745d1745d174f0p5,
    0x1.745d1745d174fp-3,
    0x1.0p3
  },
  { // Entry 311
    0x1.745d1745d174f0p6,
    0x1.745d1745d174fp-3,
    0x1.2p3
  },
  { // Entry 312
    0x1.745d1745d174f0p7,
    0x1.745d1745d174fp-3,
    0x1.4p3
  },
  { // Entry 313
    0x1.1745d1745d1790p-12,
    0x1.1745d1745d179p-2,
    -0x1.4p3
  },
  { // Entry 314
    0x1.1745d1745d1790p-11,
    0x1.1745d1745d179p-2,
    -0x1.2p3
  },
  { // Entry 315
    0x1.1745d1745d1790p-10,
    0x1.1745d1745d179p-2,
    -0x1.0p3
  },
  { // Entry 316
    0x1.1745d1745d1790p-9,
    0x1.1745d1745d179p-2,
    -0x1.cp2
  },
  { // Entry 317
    0x1.1745d1745d1790p-8,
    0x1.1745d1745d179p-2,
    -0x1.8p2
  },
  { // Entry 318
    0x1.1745d1745d1790p-7,
    0x1.1745d1745d179p-2,
    -0x1.4p2
  },
  { // Entry 319
    0x1.1745d1745d1790p-6,
    0x1.1745d1745d179p-2,
    -0x1.0p2
  },
  { // Entry 320
    0x1.1745d1745d1790p-5,
    0x1.1745d1745d179p-2,
    -0x1.8p1
  },
  { // Entry 321
    0x1.1745d1745d1790p-4,
    0x1.1745d1745d179p-2,
    -0x1.0p1
  },
  { // Entry 322
    0x1.1745d1745d1790p-3,
    0x1.1745d1745d179p-2,
    -0x1.0p0
  },
  { // Entry 323
    0x1.1745d1745d1790p-2,
    0x1.1745d1745d179p-2,
    0.0
  },
  { // Entry 324
    0x1.1745d1745d1790p-1,
    0x1.1745d1745d179p-2,
    0x1.0p0
  },
  { // Entry 325
    0x1.1745d1745d1790p0,
    0x1.1745d1745d179p-2,
    0x1.0p1
  },
  { // Entry 326
    0x1.1745d1745d1790p1,
    0x1.1745d1745d179p-2,
    0x1.8p1
  },
  { // Entry 327
    0x1.1745d1745d1790p2,
    0x1.1745d1745d179p-2,
    0x1.0p2
  },
  { // Entry 328
    0x1.1745d1745d1790p3,
    0x1.1745d1745d179p-2,
    0x1.4p2
  },
  { // Entry 329
    0x1.1745d1745d1790p4,
    0x1.1745d1745d179p-2,
    0x1.8p2
  },
  { // Entry 330
    0x1.1745d1745d1790p5,
    0x1.1745d1745d179p-2,
    0x1.cp2
  },
  { // Entry 331
    0x1.1745d1745d1790p6,
    0x1.1745d1745d179p-2,
    0x1.0p3
  },
  { // Entry 332
    0x1.1745d1745d1790p7,
    0x1.1745d1745d179p-2,
    0x1.2p3
  },
  { // Entry 333
    0x1.1745d1745d1790p8,
    0x1.1745d1745d179p-2,
    0x1.4p3
  },
  { // Entry 334
    0x1.745d1745d174a0p-12,
    0x1.745d1745d174ap-2,
    -0x1.4p3
  },
  { // Entry 335
    0x1.745d1745d174a0p-11,
    0x1.745d1745d174ap-2,
    -0x1.2p3
  },
  { // Entry 336
    0x1.745d1745d174a0p-10,
    0x1.745d1745d174ap-2,
    -0x1.0p3
  },
  { // Entry 337
    0x1.745d1745d174a0p-9,
    0x1.745d1745d174ap-2,
    -0x1.cp2
  },
  { // Entry 338
    0x1.745d1745d174a0p-8,
    0x1.745d1745d174ap-2,
    -0x1.8p2
  },
  { // Entry 339
    0x1.745d1745d174a0p-7,
    0x1.745d1745d174ap-2,
    -0x1.4p2
  },
  { // Entry 340
    0x1.745d1745d174a0p-6,
    0x1.745d1745d174ap-2,
    -0x1.0p2
  },
  { // Entry 341
    0x1.745d1745d174a0p-5,
    0x1.745d1745d174ap-2,
    -0x1.8p1
  },
  { // Entry 342
    0x1.745d1745d174a0p-4,
    0x1.745d1745d174ap-2,
    -0x1.0p1
  },
  { // Entry 343
    0x1.745d1745d174a0p-3,
    0x1.745d1745d174ap-2,
    -0x1.0p0
  },
  { // Entry 344
    0x1.745d1745d174a0p-2,
    0x1.745d1745d174ap-2,
    0.0
  },
  { // Entry 345
    0x1.745d1745d174a0p-1,
    0x1.745d1745d174ap-2,
    0x1.0p0
  },
  { // Entry 346
    0x1.745d1745d174a0p0,
    0x1.745d1745d174ap-2,
    0x1.0p1
  },
  { // Entry 347
    0x1.745d1745d174a0p1,
    0x1.745d1745d174ap-2,
    0x1.8p1
  },
  { // Entry 348
    0x1.745d1745d174a0p2,
    0x1.745d1745d174ap-2,
    0x1.0p2
  },
  { // Entry 349
    0x1.745d1745d174a0p3,
    0x1.745d1745d174ap-2,
    0x1.4p2
  },
  { // Entry 350
    0x1.745d1745d174a0p4,
    0x1.745d1745d174ap-2,
    0x1.8p2
  },
  { // Entry 351
    0x1.745d1745d174a0p5,
    0x1.745d1745d174ap-2,
    0x1.cp2
  },
  { // Entry 352
    0x1.745d1745d174a0p6,
    0x1.745d1745d174ap-2,
    0x1.0p3
  },
  { // Entry 353
    0x1.745d1745d174a0p7,
    0x1.745d1745d174ap-2,
    0x1.2p3
  },
  { // Entry 354
    0x1.745d1745d174a0p8,
    0x1.745d1745d174ap-2,
    0x1.4p3
  },
  { // Entry 355
    0x1.d1745d1745d1c0p-12,
    0x1.d1745d1745d1cp-2,
    -0x1.4p3
  },
  { // Entry 356
    0x1.d1745d1745d1c0p-11,
    0x1.d1745d1745d1cp-2,
    -0x1.2p3
  },
  { // Entry 357
    0x1.d1745d1745d1c0p-10,
    0x1.d1745d1745d1cp-2,
    -0x1.0p3
  },
  { // Entry 358
    0x1.d1745d1745d1c0p-9,
    0x1.d1745d1745d1cp-2,
    -0x1.cp2
  },
  { // Entry 359
    0x1.d1745d1745d1c0p-8,
    0x1.d1745d1745d1cp-2,
    -0x1.8p2
  },
  { // Entry 360
    0x1.d1745d1745d1c0p-7,
    0x1.d1745d1745d1cp-2,
    -0x1.4p2
  },
  { // Entry 361
    0x1.d1745d1745d1c0p-6,
    0x1.d1745d1745d1cp-2,
    -0x1.0p2
  },
  { // Entry 362
    0x1.d1745d1745d1c0p-5,
    0x1.d1745d1745d1cp-2,
    -0x1.8p1
  },
  { // Entry 363
    0x1.d1745d1745d1c0p-4,
    0x1.d1745d1745d1cp-2,
    -0x1.0p1
  },
  { // Entry 364
    0x1.d1745d1745d1c0p-3,
    0x1.d1745d1745d1cp-2,
    -0x1.0p0
  },
  { // Entry 365
    0x1.d1745d1745d1c0p-2,
    0x1.d1745d1745d1cp-2,
    0.0
  },
  { // Entry 366
    0x1.d1745d1745d1c0p-1,
    0x1.d1745d1745d1cp-2,
    0x1.0p0
  },
  { // Entry 367
    0x1.d1745d1745d1c0p0,
    0x1.d1745d1745d1cp-2,
    0x1.0p1
  },
  { // Entry 368
    0x1.d1745d1745d1c0p1,
    0x1.d1745d1745d1cp-2,
    0x1.8p1
  },
  { // Entry 369
    0x1.d1745d1745d1c0p2,
    0x1.d1745d1745d1cp-2,
    0x1.0p2
  },
  { // Entry 370
    0x1.d1745d1745d1c0p3,
    0x1.d1745d1745d1cp-2,
    0x1.4p2
  },
  { // Entry 371
    0x1.d1745d1745d1c0p4,
    0x1.d1745d1745d1cp-2,
    0x1.8p2
  },
  { // Entry 372
    0x1.d1745d1745d1c0p5,
    0x1.d1745d1745d1cp-2,
    0x1.cp2
  },
  { // Entry 373
    0x1.d1745d1745d1c0p6,
    0x1.d1745d1745d1cp-2,
    0x1.0p3
  },
  { // Entry 374
    0x1.d1745d1745d1c0p7,
    0x1.d1745d1745d1cp-2,
    0x1.2p3
  },
  { // Entry 375
    0x1.d1745d1745d1c0p8,
    0x1.d1745d1745d1cp-2,
    0x1.4p3
  },
  { // Entry 376
    0x1.1745d1745d1770p-11,
    0x1.1745d1745d177p-1,
    -0x1.4p3
  },
  { // Entry 377
    0x1.1745d1745d1770p-10,
    0x1.1745d1745d177p-1,
    -0x1.2p3
  },
  { // Entry 378
"""


```
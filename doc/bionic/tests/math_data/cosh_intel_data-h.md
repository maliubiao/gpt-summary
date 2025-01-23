Response:
Let's break down the thought process for answering the request about the `cosh_intel_data.handroid` file.

**1. Understanding the Core Request:**

The user has provided a snippet of C++ code containing a large array named `g_cosh_intel_data`. The primary goal is to understand the *function* of this code. Since the file path indicates it's part of the Android bionic library (specifically for math and related to `cosh`), we can infer that it's data used in the implementation or testing of the `cosh` function.

**2. Initial Analysis of the Code:**

* **Data Structure:** The array `g_cosh_intel_data` is an array of `data_1_1_t<double, double>`. This immediately tells us it's holding pairs of `double` values.
* **Naming Convention:** The "cosh" in the filename strongly suggests a connection to the hyperbolic cosine function. "intel_data" likely indicates these data points are either specifically tailored for or derived from Intel's math library implementations (or for testing on Intel architectures). "handroid" probably signifies it's adapted or used in the Android environment.
* **Number Format:** The `0x1.somethingp` notation is the hexadecimal representation of floating-point numbers. This reinforces the idea that the data is for numerical computation.
* **Alternating Signs:**  Notice the consistent pattern of positive and negative values in the second element of each pair. This is a key observation that needs an explanation.

**3. Formulating Hypotheses and Inferences:**

Based on the initial analysis, we can start forming hypotheses:

* **Hypothesis 1:** The file contains test data for the `cosh` function. The first `double` in each pair is likely an input value for `cosh`, and the second `double` is the expected output.
* **Hypothesis 2:** The alternating signs suggest something about the symmetry of the `cosh` function. `cosh(x) = cosh(-x)`. The pairs might be testing this property.
* **Hypothesis 3:**  "intel_data" suggests these values might be edge cases or specific values used by Intel's implementation for accuracy or performance reasons.
* **Hypothesis 4:** Since it's in the `tests` directory, it's likely used by unit tests to verify the correctness of the `cosh` implementation in bionic.

**4. Addressing the Specific Questions in the Request:**

The request asks for a breakdown of the file's functionality and its relation to Android. We need to elaborate on the hypotheses:

* **Functionality:** Confirm that it's test data for `cosh`. Explain the structure of the data pairs.
* **Android Relation:** Explain that `cosh` is a standard math function provided by the C library (`libc`), which is a core component of Android. Bionic is Android's specific implementation of `libc`.
* **libc Implementation:** Briefly mention that `cosh` is usually implemented using mathematical formulas, potentially involving exponentials. Avoid going into extreme detail without the actual `cosh` function's source code. *Initially, I might have considered diving deeper into Taylor series or other approximations, but since the request is about the *data* file, it's better to keep the `libc` implementation explanation high-level.*
* **Dynamic Linker:** The file itself doesn't directly involve the dynamic linker. It's a data file. State this clearly and explain *why* it's not involved. *Initially, I might have considered if the `cosh` function itself relies on dynamically linked libraries, but the question pertains to *this specific data file*.*
* **Logic and Assumptions:**  The primary assumption is that the data represents input/output pairs for `cosh`. The alternating signs are a crucial logical point.
* **Common Errors:** This file itself doesn't lead to user errors. However, incorrect usage of the `cosh` function (e.g., with very large inputs) *could* be related, so that's a relevant example.
* **Android Framework/NDK:** Briefly outline how a `cosh` call from Java/Kotlin (via the Framework) or native code (via the NDK) would eventually reach the bionic `cosh` implementation. Frida hook examples can be provided generically for hooking into libc functions. *It's important to distinguish between the *data file* and the *function* it supports.*

**5. Structuring the Answer (For Part 1):**

The request asks for a summary of the file's function in Part 1. Therefore, the summary should focus on the core purpose:

* It's test data.
* Specifically for the `cosh` function.
* Contains pairs of input and expected output values.
* Likely used for verifying the correctness of the `cosh` implementation in Android's bionic library.

**Self-Correction/Refinement during the Thought Process:**

* **Over-speculation about Intel:** While the filename mentions "intel," it's important not to overstate the connection. The data might simply be *suitable* for testing on Intel architectures, or derived from Intel's reference values.
* **Focus on the data file:** The prompt asks about *this specific file*. Avoid getting too sidetracked into the general implementation details of `cosh` or the dynamic linker unless they directly relate to the data file's purpose.
* **Clarity and Conciseness:**  Use clear and concise language. Avoid overly technical jargon where a simpler explanation suffices. For instance, while the number format is hexadecimal floating-point, explaining *why* it's in that format is less important than understanding that it *represents* floating-point numbers.

By following this structured thought process, analyzing the code, forming hypotheses, and directly addressing the prompt's questions, we arrive at a comprehensive and accurate answer about the functionality of the `cosh_intel_data.handroid` file.
好的，这是对文件 `bionic/tests/math_data/cosh_intel_data.handroid` 功能的归纳总结：

**功能归纳:**

这个 C++ 源代码文件定义了一个名为 `g_cosh_intel_data` 的静态数组。这个数组的主要功能是作为**测试数据**，用于验证 Android Bionic 库中 `cosh` 函数（双精度浮点数的双曲余弦函数）的实现是否正确。

具体来说：

* **存储测试用例:** 数组中的每个元素都是一个 `data_1_1_t<double, double>` 类型的结构体。  很可能，这个结构体用于存储一对双精度浮点数，其中：
    * 第一个 `double` 值是 `cosh` 函数的**输入值**。
    * 第二个 `double` 值是对应输入值 `cosh` 函数的**预期输出值**。
* **针对特定平台（Intel）的测试数据:** 文件名中的 "intel_data" 表明这些测试数据可能是针对 Intel 架构的，或者来源于 Intel 的数学库实现，用于确保在 Intel 处理器上 `cosh` 函数的精度和正确性。 "handroid" 表明这是在 Android 环境下使用的。
* **覆盖各种输入场景:**  数组中包含了大量的测试用例，涵盖了 `cosh` 函数可能遇到的各种输入值，包括：
    * 非常接近零的值
    * 正数和负数（考虑到 `cosh(x) = cosh(-x)` 的特性，可能成对出现，输入值绝对值相同，预期输出相同）
    * 具有不同指数和尾数的浮点数
    * 一些特殊值 (例如，Entry 24 和 25 的输入为 1.0，可能是测试 `cosh(0)` 或其他边界情况)
* **用于单元测试:** 这个数据文件很可能是被 Bionic 库的单元测试代码所使用，通过将数组中的输入值传递给 `cosh` 函数，然后将函数的实际输出与数组中存储的预期输出进行比较，从而验证 `cosh` 函数的实现是否符合预期。

**与其他功能的关联性 (基于文件名和上下文推断):**

* **`cosh` 函数的实现:** 这个数据文件是 `cosh` 函数实现的直接支持，用于确保其正确性。 `cosh` 函数本身是 `libc` (C标准库) 中定义的数学函数，Bionic 提供了 Android 平台的实现。
* **Bionic 库的测试框架:** 这个数据文件是 Bionic 库测试体系的一部分，用于进行自动化测试，确保库的质量。
* **数学相关的其他函数:**  虽然这个文件只针对 `cosh` 函数，但 Bionic 库中其他数学函数的测试很可能也采用了类似的结构，拥有各自的测试数据文件。

**总结:**

`bionic/tests/math_data/cosh_intel_data.handroid` 这个文件是 Android Bionic 库中用于测试双精度浮点数双曲余弦函数 (`cosh`) 实现正确性的**静态测试数据集合**，可能特别关注在 Intel 架构上的表现。它通过预定义的输入和预期输出值对，为单元测试提供了基础，以确保 `cosh` 函数在各种场景下的精度和正确性。

### 提示词
```
这是目录为bionic/tests/math_data/cosh_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_cosh_intel_data[] = {
  { // Entry 0
    0x1.f9225f7e3193c80156e29378c34b23d3p831,
    -0x1.20b0659d8a7e1p9
  },
  { // Entry 1
    0x1.f9225f7e3193c80156e29378c34b23d3p831,
    0x1.20b0659d8a7e1p9
  },
  { // Entry 2
    0x1.e128d3a99c4b28216511a7ad98d106f0p911,
    -0x1.3c640p9
  },
  { // Entry 3
    0x1.e128d3a99c4b28216511a7ad98d106f0p911,
    0x1.3c640p9
  },
  { // Entry 4
    0x1.f5f62d444f24c3bee8aeb75a413b8101p941,
    -0x1.46cf1a4e8eff8p9
  },
  { // Entry 5
    0x1.f5f62d444f24c3bee8aeb75a413b8101p941,
    0x1.46cf1a4e8eff8p9
  },
  { // Entry 6
    0x1.fd0d27f4cfe98801d15fa2d48e5a54c0p952,
    -0x1.4aa0d96719fc6p9
  },
  { // Entry 7
    0x1.fd0d27f4cfe98801d15fa2d48e5a54c0p952,
    0x1.4aa0d96719fc6p9
  },
  { // Entry 8
    0x1.eb34f0a92ee7280128c114f07d355776p958,
    -0x1.4cb09e65eb930p9
  },
  { // Entry 9
    0x1.eb34f0a92ee7280128c114f07d355776p958,
    0x1.4cb09e65eb930p9
  },
  { // Entry 10
    0x1.d2108e9aa1b124168960a67f1cb28b07p960,
    -0x1.4d5b56d5b55acp9
  },
  { // Entry 11
    0x1.d2108e9aa1b124168960a67f1cb28b07p960,
    0x1.4d5b56d5b55acp9
  },
  { // Entry 12
    0x1.f68d7cf30e0123c2164c1368d213f9b5p970,
    -0x1.50dc3739dde8ep9
  },
  { // Entry 13
    0x1.f68d7cf30e0123c2164c1368d213f9b5p970,
    0x1.50dc3739dde8ep9
  },
  { // Entry 14
    0x1.fd799430443f0800ef2fcf2cd9da9697p975,
    -0x1.529994bb15795p9
  },
  { // Entry 15
    0x1.fd799430443f0800ef2fcf2cd9da9697p975,
    0x1.529994bb15795p9
  },
  { // Entry 16
    0x1.e7b36eb1f1e698017d905c91e25df616p1005,
    -0x1.5cf9ace27d120p9
  },
  { // Entry 17
    0x1.e7b36eb1f1e698017d905c91e25df616p1005,
    0x1.5cf9ace27d120p9
  },
  { // Entry 18
    0x1.f3ae6e6ad6cf33f952b8d7d26abcd946p1013,
    -0x1.5fc2907bbfb53p9
  },
  { // Entry 19
    0x1.f3ae6e6ad6cf33f952b8d7d26abcd946p1013,
    0x1.5fc2907bbfb53p9
  },
  { // Entry 20
    0x1.fffffffffeb2a1b0e263ac68076ed4e0p1022,
    -0x1.62e42fefa39eap9
  },
  { // Entry 21
    0x1.fffffffffeb2a1b0e263ac68076ed4e0p1022,
    0x1.62e42fefa39eap9
  },
  { // Entry 22
    0x1.000004a24e558c02a9470bd8d4f869a3p0,
    -0x1.85acfb6cf0992p-11
  },
  { // Entry 23
    0x1.000004a24e558c02a9470bd8d4f869a3p0,
    0x1.85acfb6cf0992p-11
  },
  { // Entry 24
    0x1.p0,
    -0x1.9p-1069
  },
  { // Entry 25
    0x1.p0,
    0x1.9p-1069
  },
  { // Entry 26
    0x1.14c128b1a7c2b69f584c42e1f5d24e43p0,
    -0x1.999999999999ap-2
  },
  { // Entry 27
    0x1.14c128b1a7c2b69f584c42e1f5d24e43p0,
    0x1.999999999999ap-2
  },
  { // Entry 28
    0x1.580485993cf5380007b6f3dfb3426795p1,
    -0x1.a52f2fff26658p0
  },
  { // Entry 29
    0x1.580485993cf5380007b6f3dfb3426795p1,
    0x1.a52f2fff26658p0
  },
  { // Entry 30
    0x1.786cf5655ff2cf9f3e2f91013f3f8c31p9,
    -0x1.d449f6b92fb70p2
  },
  { // Entry 31
    0x1.786cf5655ff2cf9f3e2f91013f3f8c31p9,
    0x1.d449f6b92fb70p2
  },
  { // Entry 32
    0x1.072f2f89ddc2f7a6dd2420f4fde2c244p0,
    -0x1.e411ac17c616dp-3
  },
  { // Entry 33
    0x1.072f2f89ddc2f7a6dd2420f4fde2c244p0,
    0x1.e411ac17c616dp-3
  },
  { // Entry 34
    0x1.0000000000200000000000aaaaaaaaaap0,
    0x1.0p-21
  },
  { // Entry 35
    0x1.0000000000200000000000aaaaaaaaaap0,
    -0x1.0p-21
  },
  { // Entry 36
    0x1.000000000000080000000000000aaaaap0,
    0x1.0p-26
  },
  { // Entry 37
    0x1.000000000000080000000000000aaaaap0,
    -0x1.0p-26
  },
  { // Entry 38
    0x1.95e54c5dd42177f53f4d5219df11ca3bp183,
    0x1.0p7
  },
  { // Entry 39
    0x1.95e54c5dd42177f53f4d5219df11ca3bp183,
    -0x1.0p7
  },
  { // Entry 40
    0x1.0000000000000000000020p0,
    0x1.0000000000001p-41
  },
  { // Entry 41
    0x1.0000000000000000000020p0,
    -0x1.0000000000001p-41
  },
  { // Entry 42
    0x1.p0,
    0x1.0000000000001p-352
  },
  { // Entry 43
    0x1.p0,
    -0x1.0000000000001p-352
  },
  { // Entry 44
    0x1.749eaa93f4e98ffecd44eae03d0a1d5bp10,
    0x1.0000000000003p3
  },
  { // Entry 45
    0x1.749eaa93f4e98ffecd44eae03d0a1d5bp10,
    -0x1.0000000000003p3
  },
  { // Entry 46
    0x1.41c7a8814c78683cdbc165597ca61d23p368,
    0x1.0000000000007p8
  },
  { // Entry 47
    0x1.41c7a8814c78683cdbc165597ca61d23p368,
    -0x1.0000000000007p8
  },
  { // Entry 48
    0x1.000000000000080000000000110aaaaap0,
    0x1.0000000000011p-26
  },
  { // Entry 49
    0x1.000000000000080000000000110aaaaap0,
    -0x1.0000000000011p-26
  },
  { // Entry 50
    0x1.8b07551d9f67f7fdc0ff67bf92a962fdp0,
    0x1.0000000000102p0
  },
  { // Entry 51
    0x1.8b07551d9f67f7fdc0ff67bf92a962fdp0,
    -0x1.0000000000102p0
  },
  { // Entry 52
    0x1.1f43fcc5952c37ff0506eaa1b0c216eep45,
    0x1.0000000006345p5
  },
  { // Entry 53
    0x1.1f43fcc5952c37ff0506eaa1b0c216eep45,
    -0x1.0000000006345p5
  },
  { // Entry 54
    0x1.94dbdfbb66bc651ee76572119d9c1c4cp737,
    0x1.0000202p9
  },
  { // Entry 55
    0x1.94dbdfbb66bc651ee76572119d9c1c4cp737,
    -0x1.0000202p9
  },
  { // Entry 56
    0x1.203fc65a034d07ffda891f0ce56a69b6p45,
    0x1.00070p5
  },
  { // Entry 57
    0x1.203fc65a034d07ffda891f0ce56a69b6p45,
    -0x1.00070p5
  },
  { // Entry 58
    0x1.000000000000080100080000000aad55p0,
    0x1.001p-26
  },
  { // Entry 59
    0x1.000000000000080100080000000aad55p0,
    -0x1.001p-26
  },
  { // Entry 60
    0x1.75e54432c8551fabeec3248201e6c2ccp10,
    0x1.001c0p3
  },
  { // Entry 61
    0x1.75e54432c8551fabeec3248201e6c2ccp10,
    -0x1.001c0p3
  },
  { // Entry 62
    0x1.e708d6f7a319258034ee3b204d26ca92p1,
    0x1.018p1
  },
  { // Entry 63
    0x1.e708d6f7a319258034ee3b204d26ca92p1,
    -0x1.018p1
  },
  { // Entry 64
    0x1.0000216287cecc0d0dc2c5304f513db1p0,
    0x1.057b17480eb6bp-9
  },
  { // Entry 65
    0x1.0000216287cecc0d0dc2c5304f513db1p0,
    -0x1.057b17480eb6bp-9
  },
  { // Entry 66
    0x1.000008637bdd480001e95efd80447405p0,
    0x1.0624dd41d1d06p-10
  },
  { // Entry 67
    0x1.000008637bdd480001e95efd80447405p0,
    -0x1.0624dd41d1d06p-10
  },
  { // Entry 68
    0x1.fe87c460adc0882fbe85314df418d2b4p1,
    0x1.07bd69f72017dp1
  },
  { // Entry 69
    0x1.fe87c460adc0882fbe85314df418d2b4p1,
    -0x1.07bd69f72017dp1
  },
  { // Entry 70
    0x1.0000000000220800000000c10560p0,
    0x1.080p-21
  },
  { // Entry 71
    0x1.0000000000220800000000c10560p0,
    -0x1.080p-21
  },
  { // Entry 72
    0x1.f39a59f250416803923a1c1e1528d74dp10,
    0x1.0962589625894p3
  },
  { // Entry 73
    0x1.f39a59f250416803923a1c1e1528d74dp10,
    -0x1.0962589625894p3
  },
  { // Entry 74
    0x1.09c4fe008ebbf7feff9c55742944c979p47,
    0x1.0a77d78f63c77p5
  },
  { // Entry 75
    0x1.09c4fe008ebbf7feff9c55742944c979p47,
    -0x1.0a77d78f63c77p5
  },
  { // Entry 76
    0x1.250e830d17c53ffff0f0a7b37c3274aep0,
    0x1.1044110441104p-1
  },
  { // Entry 77
    0x1.250e830d17c53ffff0f0a7b37c3274aep0,
    -0x1.1044110441104p-1
  },
  { // Entry 78
    0x1.0000024ff524ec0206bcebcbcb8fd2d8p0,
    0x1.1343b94c10b91p-11
  },
  { // Entry 79
    0x1.0000024ff524ec0206bcebcbcb8fd2d8p0,
    -0x1.1343b94c10b91p-11
  },
  { // Entry 80
    0x1.a4e4693413b9970755c15633af25f96bp399,
    0x1.15c18de877563p8
  },
  { // Entry 81
    0x1.a4e4693413b9970755c15633af25f96bp399,
    -0x1.15c18de877563p8
  },
  { // Entry 82
    0x1.a7b0a63b771487fe7ea3e4c4c6a5986cp0,
    0x1.170p0
  },
  { // Entry 83
    0x1.a7b0a63b771487fe7ea3e4c4c6a5986cp0,
    -0x1.170p0
  },
  { // Entry 84
    0x1.2040f2a1ab52f6519acd0a68e44e2672p2,
    0x1.17cp1
  },
  { // Entry 85
    0x1.2040f2a1ab52f6519acd0a68e44e2672p2,
    -0x1.17cp1
  },
  { // Entry 86
    0x1.ffffffffffff691afdbf851f5ebecf8fp24,
    0x1.205966f2b4f12p4
  },
  { // Entry 87
    0x1.ffffffffffff691afdbf851f5ebecf8fp24,
    -0x1.205966f2b4f12p4
  },
  { // Entry 88
    0x1.79842c1bcf0097ff7fb2dd182713e67ap207,
    0x1.2120481204831p7
  },
  { // Entry 89
    0x1.79842c1bcf0097ff7fb2dd182713e67ap207,
    -0x1.2120481204831p7
  },
  { // Entry 90
    0x1.29fbb84ba8876b368d8a9db5c1e1454dp0,
    0x1.215c31dfb06bep-1
  },
  { // Entry 91
    0x1.29fbb84ba8876b368d8a9db5c1e1454dp0,
    -0x1.215c31dfb06bep-1
  },
  { // Entry 92
    0x1.eaa521edf1bc28014602191ce618c05fp845,
    0x1.2586ca9cf411bp9
  },
  { // Entry 93
    0x1.eaa521edf1bc28014602191ce618c05fp845,
    -0x1.2586ca9cf411bp9
  },
  { // Entry 94
    0x1.6a09e667f3b873e3fe3a64632e382c20p25,
    0x1.25e4f7b2737f7p4
  },
  { // Entry 95
    0x1.6a09e667f3b873e3fe3a64632e382c20p25,
    -0x1.25e4f7b2737f7p4
  },
  { // Entry 96
    0x1.57261d902201780090571fb5bf70f618p12,
    0x1.29b98d2ca77bfp3
  },
  { // Entry 97
    0x1.57261d902201780090571fb5bf70f618p12,
    -0x1.29b98d2ca77bfp3
  },
  { // Entry 98
    0x1.bfa86b3a08ba080003331b84fa809b78p5,
    0x1.2dee0f9476ef0p2
  },
  { // Entry 99
    0x1.bfa86b3a08ba080003331b84fa809b78p5,
    -0x1.2dee0f9476ef0p2
  },
  { // Entry 100
    0x1.ca2d30aee8c837f93c016463c234beb0p0,
    0x1.2fap0
  },
  { // Entry 101
    0x1.ca2d30aee8c837f93c016463c234beb0p0,
    -0x1.2fap0
  },
  { // Entry 102
    0x1.dc851a55686d48012add3c02a54cc4d9p875,
    0x1.2fe8bcd183299p9
  },
  { // Entry 103
    0x1.dc851a55686d48012add3c02a54cc4d9p875,
    -0x1.2fe8bcd183299p9
  },
  { // Entry 104
    0x1.ff12f7296b0408017eaaf48fbf280399p877,
    0x1.30a324d6033b5p9
  },
  { // Entry 105
    0x1.ff12f7296b0408017eaaf48fbf280399p877,
    -0x1.30a324d6033b5p9
  },
  { // Entry 106
    0x1.0000b839f863b3e4bcae71b55072ca80p0,
    0x1.331f2adbaf98dp-8
  },
  { // Entry 107
    0x1.0000b839f863b3e4bcae71b55072ca80p0,
    -0x1.331f2adbaf98dp-8
  },
  { // Entry 108
    0x1.f3a98884eba4bc32647b7ac3c5404f85p26,
    0x1.3623c0c9e9d5ap4
  },
  { // Entry 109
    0x1.f3a98884eba4bc32647b7ac3c5404f85p26,
    -0x1.3623c0c9e9d5ap4
  },
  { // Entry 110
    0x1.75a07cfb107ca6ba9dba1e2c2cedd659p453,
    0x1.3b11206005429p8
  },
  { // Entry 111
    0x1.75a07cfb107ca6ba9dba1e2c2cedd659p453,
    -0x1.3b11206005429p8
  },
  { // Entry 112
    0x1.f1ef9c8a4fdae801b19f8e42eff2c4a8p929,
    0x1.42a565e456e04p9
  },
  { // Entry 113
    0x1.f1ef9c8a4fdae801b19f8e42eff2c4a8p929,
    -0x1.42a565e456e04p9
  },
  { // Entry 114
    0x1.f4ec44194b642801a4afd4c50633e8aap937,
    0x1.456bf23e02428p9
  },
  { // Entry 115
    0x1.f4ec44194b642801a4afd4c50633e8aap937,
    -0x1.456bf23e02428p9
  },
  { // Entry 116
    0x1.ea91d9533b394801bf3d3ec8f88de568p938,
    0x1.45c1feef8086cp9
  },
  { // Entry 117
    0x1.ea91d9533b394801bf3d3ec8f88de568p938,
    -0x1.45c1feef8086cp9
  },
  { // Entry 118
    0x1.4dbe273792bde7fc45ff4f687bf81f94p6,
    0x1.478p2
  },
  { // Entry 119
    0x1.4dbe273792bde7fc45ff4f687bf81f94p6,
    -0x1.478p2
  },
  { // Entry 120
    0x1.a1732beffb81e80f059be59df088e0dcp2,
    0x1.480p1
  },
  { // Entry 121
    0x1.a1732beffb81e80f059be59df088e0dcp2,
    -0x1.480p1
  },
  { // Entry 122
    0x1.f292b709c70c9039aec2c978d1d7e73ep0,
    0x1.494p0
  },
  { // Entry 123
    0x1.f292b709c70c9039aec2c978d1d7e73ep0,
    -0x1.494p0
  },
  { // Entry 124
    0x1.a6c83c0fd645320793a014725c3d6e2dp2,
    0x1.49a4d26934980p1
  },
  { // Entry 125
    0x1.a6c83c0fd645320793a014725c3d6e2dp2,
    -0x1.49a4d26934980p1
  },
  { // Entry 126
    0x1.14ff8ce7eedcf7ff00c85c22990fd0fep951,
    0x1.49fa3bc9fa3bcp9
  },
  { // Entry 127
    0x1.14ff8ce7eedcf7ff00c85c22990fd0fep951,
    -0x1.49fa3bc9fa3bcp9
  },
  { // Entry 128
    0x1.f6c6651de70d704c55837250811c86ddp0,
    0x1.4bcp0
  },
  { // Entry 129
    0x1.f6c6651de70d704c55837250811c86ddp0,
    -0x1.4bcp0
  },
  { // Entry 130
    0x1.c18c56303fe66fff9d9b8c47655f12c0p2,
    0x1.51965d2b59826p1
  },
  { // Entry 131
    0x1.c18c56303fe66fff9d9b8c47655f12c0p2,
    -0x1.51965d2b59826p1
  },
  { // Entry 132
    0x1.eeac3d912b1ce80100df042cfb33c06ep59,
    0x1.51fafb7826f27p5
  },
  { // Entry 133
    0x1.eeac3d912b1ce80100df042cfb33c06ep59,
    -0x1.51fafb7826f27p5
  },
  { // Entry 134
    0x1.9548e9688fb2e800c466e7d893328f68p991,
    0x1.5807dc787a5d5p9
  },
  { // Entry 135
    0x1.9548e9688fb2e800c466e7d893328f68p991,
    -0x1.5807dc787a5d5p9
  },
  { // Entry 136
    0x1.000003a93be72bffaeb829ad23f9901bp0,
    0x1.5a5c6af3cbf35p-11
  },
  { // Entry 137
    0x1.000003a93be72bffaeb829ad23f9901bp0,
    -0x1.5a5c6af3cbf35p-11
  },
  { // Entry 138
    0x1.8d35b12c48404800034bee73c998316fp14,
    0x1.5ac4908a754c1p3
  },
  { // Entry 139
    0x1.8d35b12c48404800034bee73c998316fp14,
    -0x1.5ac4908a754c1p3
  },
  { // Entry 140
    0x1.f2a3c29fc6d723a63e349bbcd7894a8ap1007,
    0x1.5dadf5d1e452cp9
  },
  { // Entry 141
    0x1.f2a3c29fc6d723a63e349bbcd7894a8ap1007,
    -0x1.5dadf5d1e452cp9
  },
  { // Entry 142
    0x1.edcb14879613e80176087c1a76dec97cp1008,
    0x1.5e056ed40e56ep9
  },
  { // Entry 143
    0x1.edcb14879613e80176087c1a76dec97cp1008,
    -0x1.5e056ed40e56ep9
  },
  { // Entry 144
    0x1.96faa872a06aa3003f5158de9c570302p1023,
    0x1.631f86ac0611bp9
  },
  { // Entry 145
    0x1.96faa872a06aa3003f5158de9c570302p1023,
    -0x1.631f86ac0611bp9
  },
  { // Entry 146
    0x1.bf668fc6f4f9d31f753c408261bb02b4p1023,
    0x1.632ba58eae071p9
  },
  { // Entry 147
    0x1.bf668fc6f4f9d31f753c408261bb02b4p1023,
    -0x1.632ba58eae071p9
  },
  { // Entry 148
    0x1.ffffffffbcd3ae595303e74abb3fd75dp1023,
    0x1.633ce8fb9f771p9
  },
  { // Entry 149
    0x1.ffffffffbcd3ae595303e74abb3fd75dp1023,
    -0x1.633ce8fb9f771p9
  },
  { // Entry 150
    0x1.fffffffff093ae594ed7508a02429436p1023,
    0x1.633ce8fb9f840p9
  },
  { // Entry 151
    0x1.fffffffff093ae594ed7508a02429436p1023,
    -0x1.633ce8fb9f840p9
  },
  { // Entry 152
    0x1.fffffffff713ae594eafc080a48289f9p1023,
    0x1.633ce8fb9f85ap9
  },
  { // Entry 153
    0x1.fffffffff713ae594eafc080a48289f9p1023,
    -0x1.633ce8fb9f85ap9
  },
  { // Entry 154
    0x1.1350a413023bfffffe14156b2ad2a0aap1,
    0x1.6666666678dc9p0
  },
  { // Entry 155
    0x1.1350a413023bfffffe14156b2ad2a0aap1,
    -0x1.6666666678dc9p0
  },
  { // Entry 156
    0x1.4152c1863ba8280001cbf788e6aa237cp0,
    0x1.66666666a6b7ep-1
  },
  { // Entry 157
    0x1.4152c1863ba8280001cbf788e6aa237cp0,
    -0x1.66666666a6b7ep-1
  },
  { // Entry 158
    0x1.ffffd47fb735b800740691174c7f5813p31,
    0x1.6dfb50131e66dp4
  },
  { // Entry 159
    0x1.ffffd47fb735b800740691174c7f5813p31,
    -0x1.6dfb50131e66dp4
  },
  { // Entry 160
    0x1.23aaacaf304fbfffff85f2e03f117872p3,
    0x1.733333335c84ap1
  },
  { // Entry 161
    0x1.23aaacaf304fbfffff85f2e03f117872p3,
    -0x1.733333335c84ap1
  },
  { // Entry 162
    0x1.000000000047f4008000035ee023fep0,
    0x1.7fep-21
  },
  { // Entry 163
    0x1.000000000047f4008000035ee023fep0,
    -0x1.7fep-21
  },
  { // Entry 164
    0x1.f0e3e5b6c17c02a799c306dbc1b1a8ecp555,
    0x1.820d92fc4b42ap8
  },
  { // Entry 165
    0x1.f0e3e5b6c17c02a799c306dbc1b1a8ecp555,
    -0x1.820d92fc4b42ap8
  },
  { // Entry 166
    0x1.9d55555ab98f4817a9f90acefca23523p140,
    0x1.88d9eff243ec8p6
  },
  { // Entry 167
    0x1.9d55555ab98f4817a9f90acefca23523p140,
    -0x1.88d9eff243ec8p6
  },
  { // Entry 168
    0x1.04c5f3d75091e8012559fb87285a99dep0,
    0x1.8aep-3
  },
  { // Entry 169
    0x1.04c5f3d75091e8012559fb87285a99dep0,
    -0x1.8aep-3
  },
  { // Entry 170
    0x1.50a125ad300e5802736ad2f68de9efdap0,
    0x1.8c6318c6318c4p-1
  },
  { // Entry 171
    0x1.50a125ad300e5802736ad2f68de9efdap0,
    -0x1.8c6318c6318c4p-1
  },
  { // Entry 172
    0x1.a2cc09e2e7dd780005c588bf2ebd2d28p35,
    0x1.9720cc66f1cbbp4
  },
  { // Entry 173
    0x1.a2cc09e2e7dd780005c588bf2ebd2d28p35,
    -0x1.9720cc66f1cbbp4
  },
  { // Entry 174
    0x1.49ea5b155646500001cb3c7a14d4f641p1,
    0x1.99999999b8db8p0
  },
  { // Entry 175
    0x1.49ea5b155646500001cb3c7a14d4f641p1,
    -0x1.99999999b8db8p0
  },
  { // Entry 176
    0x1.0147f40224ea77fffe35f63e0620c28ep0,
    0x1.99999999bbe1bp-4
  },
  { // Entry 177
    0x1.0147f40224ea77fffe35f63e0620c28ep0,
    -0x1.99999999bbe1bp-4
  },
  { // Entry 178
    0x1.0523184b26181ffffe5ad5f60af39607p0,
    0x1.9999999ab6eebp-3
  },
  { // Entry 179
    0x1.0523184b26181ffffe5ad5f60af39607p0,
    -0x1.9999999ab6eebp-3
  },
  { // Entry 180
    0x1.0147f4022697680001b3e13f009af80bp0,
    0x1.9999999ac7857p-4
  },
  { // Entry 181
    0x1.0147f4022697680001b3e13f009af80bp0,
    -0x1.9999999ac7857p-4
  },
  { // Entry 182
    0x1.0523184b290290000199de7723bc799dp0,
    0x1.9999999b2aca1p-3
  },
  { // Entry 183
    0x1.0523184b290290000199de7723bc799dp0,
    -0x1.9999999b2aca1p-3
  },
  { // Entry 184
    0x1.0147f402280ed80001d59eeac36ba73dp0,
    0x1.9999999bb1c77p-4
  },
  { // Entry 185
    0x1.0147f402280ed80001d59eeac36ba73dp0,
    -0x1.9999999bb1c77p-4
  },
  { // Entry 186
    0x1.ffffffffffed457a42e161456cf862b2p590,
    0x1.9a57d76d152fcp8
  },
  { // Entry 187
    0x1.ffffffffffed457a42e161456cf862b2p590,
    -0x1.9a57d76d152fcp8
  },
  { // Entry 188
    0x1.6375401c4fbbf8003386ea381d3fe669p0,
    0x1.b5daed76bb580p-1
  },
  { // Entry 189
    0x1.6375401c4fbbf8003386ea381d3fe669p0,
    -0x1.b5daed76bb580p-1
  },
  { // Entry 190
    0x1.f30605e8b5451805101b3ea033bab41cp8,
    0x1.b9f89e22629b5p2
  },
  { // Entry 191
    0x1.f30605e8b5451805101b3ea033bab41cp8,
    -0x1.b9f89e22629b5p2
  },
  { // Entry 192
    0x1.f309ebf823d108054159f278e16ad109p8,
    0x1.b9f91e22629b5p2
  },
  { // Entry 193
    0x1.f309ebf823d108054159f278e16ad109p8,
    -0x1.b9f91e22629b5p2
  },
  { // Entry 194
    0x1.185c2bf1d5276fffd73fd51a307743a4p0,
    0x1.bb4p-2
  },
  { // Entry 195
    0x1.185c2bf1d5276fffd73fd51a307743a4p0,
    -0x1.bb4p-2
  },
  { // Entry 196
    0x1.0005ffd0c797f7ff1970be180784a55cp0,
    0x1.bb6p-7
  },
  { // Entry 197
    0x1.0005ffd0c797f7ff1970be180784a55cp0,
    -0x1.bb6p-7
  },
  { // Entry 198
    0x1.968ef6ceade7f60edc2b4f0265da6ba4p640,
    0x1.bcc517b553c93p8
  },
  { // Entry 199
    0x1.968ef6ceade7f60edc2b4f0265da6ba4p640,
    -0x1.bcc517b553c93p8
  },
  { // Entry 200
    0x1.7b972e453783930f202a8aa455bb6c01p1,
    0x1.c02p0
  },
  { // Entry 201
    0x1.7b972e453783930f202a8aa455bb6c01p1,
    -0x1.c02p0
  },
  { // Entry 202
    0x1.7eec19d4dcbc738baa1a1114dee049b8p1,
    0x1.c28p0
  },
  { // Entry 203
    0x1.7eec19d4dcbc738baa1a1114dee049b8p1,
    -0x1.c28p0
  },
  { // Entry 204
    0x1.0656561cbe53c7fffdb60e1b054d8f16p0,
    0x1.c6c2e93467e80p-3
  },
  { // Entry 205
    0x1.0656561cbe53c7fffdb60e1b054d8f16p0,
    -0x1.c6c2e93467e80p-3
  },
  { // Entry 206
    0x1.06a2b3e7b603e800c2f4167761b30bf8p0,
    0x1.d14bf83b48ec3p-3
  },
  { // Entry 207
    0x1.06a2b3e7b603e800c2f4167761b30bf8p0,
    -0x1.d14bf83b48ec3p-3
  },
  { // Entry 208
    0x1.fb4d9de0ad845677ec6fc467c2ca9f9ap19,
    0x1.d18p3
  },
  { // Entry 209
    0x1.fb4d9de0ad845677ec6fc467c2ca9f9ap19,
    -0x1.d18p3
  },
  { // Entry 210
    0x1.73a6cd8f2f6d681e70f9695a25f39c35p0,
    0x1.d60p-1
  },
  { // Entry 211
    0x1.73a6cd8f2f6d681e70f9695a25f39c35p0,
    -0x1.d60p-1
  },
  { // Entry 212
    0x1.9fb7158a225e000047f44f47edad0545p1,
    0x1.d8b5f14439f87p0
  },
  { // Entry 213
    0x1.9fb7158a225e000047f44f47edad0545p1,
    -0x1.d8b5f14439f87p0
  },
  { // Entry 214
    0x1.ea40b4c3630d1000615de8737ec4857cp9,
    0x1.e532a134b958cp2
  },
  { // Entry 215
    0x1.ea40b4c3630d1000615de8737ec4857cp9,
    -0x1.e532a134b958cp2
  },
  { // Entry 216
    0x1.dbca9263f840fca48450e408fa36b56bp177,
    0x1.effffffffffffp6
  },
  { // Entry 217
    0x1.dbca9263f840fca48450e408fa36b56bp177,
    -0x1.effffffffffffp6
  },
  { // Entry 218
    0x1.01e4fad3b993aa1a52d036790b34e1cep0,
    0x1.f1fffffffffffp-4
  },
  { // Entry 219
    0x1.01e4fad3b993aa1a52d036790b34e1cep0,
    -0x1.f1fffffffffffp-4
  },
  { // Entry 220
    0x1.07a6bb7edb5de8000669b121a48f81e9p0,
    0x1.f37a7a76cbc72p-3
  },
  { // Entry 221
    0x1.07a6bb7edb5de8000669b121a48f81e9p0,
    -0x1.f37a7a76cbc72p-3
  },
  { // Entry 222
    0x1.d1ee8e62b2098fff7b22532973b4ccp1,
    0x1.f73a29b8fcc22p0
  },
  { // Entry 223
    0x1.d1ee8e62b2098fff7b22532973b4ccp1,
    -0x1.f73a29b8fcc22p0
  },
  { // Entry 224
    0x1.f617a27e250ce1b06488e5167c0849a8p90,
    0x1.fdfffffffffffp5
  },
  { // Entry 225
    0x1.f617a27e250ce1b06488e5167c0849a8p90,
    -0x1.fdfffffffffffp5
  },
  { // Entry 226
    0x1.000000000007f4018180a8332feed269p0,
    0x1.fe7f9fe7f9fc1p-23
  },
  { // Entry 227
    0x1.000000000007f4018180a8332feed269p0,
    -0x1.fe7f9fe7f9fc1p-23
  },
  { // Entry 228
    0x1.000007f7824c94120eb9c3be21444195p0,
    0x1.feeffffffffffp-11
  },
  { // Entry 229
    0x1.000007f7824c94120eb9c3be21444195p0,
    -0x1.feeffffffffffp-11
  },
  { // Entry 230
    0x1.dfa36f8e6bf72fa8a934ef27b5231b54p1,
    0x1.feeffffffffffp0
  },
  { // Entry 231
    0x1.dfa36f8e6bf72fa8a934ef27b5231b54p1,
    -0x1.feeffffffffffp0
  },
  { // Entry 232
    0x1.08086ec43bf6287590f3692c2b8d555dp0,
    0x1.ffb886fe444c0p-3
  },
  { // Entry 233
    0x1.08086ec43bf6287590f3692c2b8d555dp0,
    -0x1.ffb886fe444c0p-3
  },
  { // Entry 234
    0x1.080972995a2b573ac07666762f1a0b72p0,
    0x1.ffd8af33686dbp-3
  },
  { // Entry 235
    0x1.080972995a2b573ac07666762f1a0b72p0,
    -0x1.ffd8af33686dbp-3
  },
  { // Entry 236
    0x1.6d4fd9ab47c9200073aa8127a2419ac8p737,
    0x1.ffe5effffffffp8
  },
  { // Entry 237
    0x1.6d4fd9ab47c9200073aa8127a2419ac8p737,
    -0x1.ffe5effffffffp8
  },
  { // Entry 238
    0x1.74418e8eaca63c82e25a9f7d06548e5dp10,
    0x1.ffeffffffffffp2
  },
  { // Entry 239
    0x1.74418e8eaca63c82e25a9f7d06548e5dp10,
    -0x1.ffeffffffffffp2
  },
  { // Entry 240
    0x1.080a3deb46ec08a56cbd7f1bde2759b0p0,
    0x1.fff1d77ffffffp-3
  },
  { // Entry 241
    0x1.080a3deb46ec08a56cbd7f1bde2759b0p0,
    -0x1.fff1d77ffffffp-3
  },
  { // Entry 242
    0x1.941a855acbf7a7ffc58b32660a23ba32p737,
    0x1.ffffc5dffffffp8
  },
  { // Entry 243
    0x1.941a855acbf7a7ffc58b32660a23ba32p737,
    -0x1.ffffc5dffffffp8
  },
  { // Entry 244
    0x1.95e4816b60a8d769724b586e4deb3b1bp183,
    0x1.fffffdfffffffp6
  },
  { // Entry 245
    0x1.95e4816b60a8d769724b586e4deb3b1bp183,
    -0x1.fffffdfffffffp6
  },
  { // Entry 246
    0x1.080ab0589b61286b6d41402698d5bfeep0,
    0x1.ffffff7ffffffp-3
  },
  { // Entry 247
    0x1.080ab0589b61286b6d41402698d5bfeep0,
    -0x1.ffffff7ffffffp-3
  },
  { // Entry 248
    0x1.20ac18541756f8007b9a2f43dab0cc9cp0,
    0x1.ffffff8ffffffp-2
  },
  { // Entry 249
    0x1.20ac18541756f8007b9a2f43dab0cc9cp0,
    -0x1.ffffff8ffffffp-2
  },
  { // Entry 250
    0x1.e18fa0deb98c68008c19676612286a2dp1,
    0x1.ffffffffbffffp0
  },
  { // Entry 251
    0x1.e18fa0deb98c68008c19676612286a2dp1,
    -0x1.ffffffffbffffp0
  },
  { // Entry 252
    0x1.p0,
    0x1.fffffffff7fffp-352
  },
  { // Entry 253
    0x1.p0,
    -0x1.fffffffff7fffp-352
  },
  { // Entry 254
    0x1.0f2ebd0a7fc177f6fa2a0a4e6bb2f696p22,
    0x1.fffffffffff7fp3
  },
  { // Entry 255
    0x1.0f2ebd0a7fc177f6fa2a0a4e6bb2f696p22,
    -0x1.fffffffffff7fp3
  },
  { // Entry 256
    0x1.e18fa0df2d99b84e92f43b9b47f7341ep1,
    0x1.fffffffffffeep0
  },
  { // Entry 257
    0x1.e18fa0df2d99b84e92f43b9b47f7341ep1,
    -0x1.fffffffffffeep0
  },
  { // Entry 258
    0x1.b4ee858de3e5a800f659793765248fb4p4,
    0x1.ffffffffffff5p1
  },
  { // Entry 259
    0x1.b4ee858de3e5a800f659793765248fb4p4,
    -0x1.ffffffffffff5p1
  },
  { // Entry 260
    0x1.p0,
    0x1.ffffffffffffdp-200
  },
  { // Entry 261
    0x1.p0,
    -0x1.ffffffffffffdp-200
  },
  { // Entry 262
    0x1.0000000000001ffffffffffffcaaaaaap0,
    0x1.ffffffffffffep-26
  },
  { // Entry 263
    0x1.0000000000001ffffffffffffcaaaaaap0,
    -0x1.ffffffffffffep-26
  },
  { // Entry 264
    0x1.00000000000007ffffffffffff0aaaaap0,
    0x1.ffffffffffffep-27
  },
  { // Entry 265
    0x1.00000000000007ffffffffffff0aaaaap0,
    -0x1.ffffffffffffep-27
  },
  { // Entry 266
    0x1.9476504ba82057f69310608c30e76cebp737,
    0x1.ffffffffffffep8
  },
  { // Entry 267
    0x1.9476504ba82057f69310608c30e76cebp737,
    -0x1.ffffffffffffep8
  },
  { // Entry 268
    0x1.p0,
    0.0
  },
  { // Entry 269
    0x1.00a7413869e0bc675ef8f8059bcc3722p0,
    0x1.2492492492492p-4
  },
  { // Entry 270
    0x1.00a7413869e0bc675ef8f8059bcc3722p0,
    -0x1.2492492492492p-4
  },
  { // Entry 271
    0x1.029ddf6df7f29c6e5531c853aa7ef551p0,
    0x1.2492492492492p-3
  },
  { // Entry 272
    0x1.029ddf6df7f29c6e5531c853aa7ef551p0,
    -0x1.2492492492492p-3
  },
  { // Entry 273
    0x1.05e66b632df1253b01df69be9ece44e3p0,
    0x1.b6db6db6db6dbp-3
  },
  { // Entry 274
    0x1.05e66b632df1253b01df69be9ece44e3p0,
    -0x1.b6db6db6db6dbp-3
  },
  { // Entry 275
    0x1.0a852f6aef4fd03008a8aa0554865518p0,
    0x1.2492492492492p-2
  },
  { // Entry 276
    0x1.0a852f6aef4fd03008a8aa0554865518p0,
    -0x1.2492492492492p-2
  },
  { // Entry 277
    0x1.10803503a700f31eb1d4ed9defcba588p0,
    0x1.6db6db6db6db6p-2
  },
  { // Entry 278
    0x1.10803503a700f31eb1d4ed9defcba588p0,
    -0x1.6db6db6db6db6p-2
  },
  { // Entry 279
    0x1.17df4cbabde0a25651179bc95d273b63p0,
    0x1.b6db6db6db6dap-2
  },
  { // Entry 280
    0x1.17df4cbabde0a25651179bc95d273b63p0,
    -0x1.b6db6db6db6dap-2
  },
  { // Entry 281
    0x1.20ac1862ae8d021a4e365577227270b1p0,
    0x1.ffffffffffffep-2
  },
  { // Entry 282
    0x1.20ac1862ae8d021a4e365577227270b1p0,
    -0x1.ffffffffffffep-2
  },
  { // Entry 283
    0x1.20ac1862ae8d0645823a4f060800e88cp0,
    0x1.0p-1
  },
  { // Entry 284
    0x1.20ac1862ae8d0645823a4f060800e88cp0,
    -0x1.0p-1
  },
  { // Entry 285
    0x1.2af217a90e6dec39004f56495cd43505p0,
    0x1.2492492492492p-1
  },
  { // Entry 286
    0x1.2af217a90e6dec39004f56495cd43505p0,
    -0x1.2492492492492p-1
  },
  { // Entry 287
    0x1.36beb71cfe154fa26b865cb1a3cb8a5fp0,
    0x1.4924924924924p-1
  },
  { // Entry 288
    0x1.36beb71cfe154fa26b865cb1a3cb8a5fp0,
    -0x1.4924924924924p-1
  },
  { // Entry 289
    0x1.442161b9a30711902871e6d507913362p0,
    0x1.6db6db6db6db6p-1
  },
  { // Entry 290
    0x1.442161b9a30711902871e6d507913362p0,
    -0x1.6db6db6db6db6p-1
  },
  { // Entry 291
    0x1.532b950b9683060720f579e323e93474p0,
    0x1.9249249249248p-1
  },
  { // Entry 292
    0x1.532b950b9683060720f579e323e93474p0,
    -0x1.9249249249248p-1
  },
  { // Entry 293
    0x1.63f0f80b9c6bb0519d8eae2c3ccbbd98p0,
    0x1.b6db6db6db6dap-1
  },
  { // Entry 294
    0x1.63f0f80b9c6bb0519d8eae2c3ccbbd98p0,
    -0x1.b6db6db6db6dap-1
  },
  { // Entry 295
    0x1.768774cc7f49764e7589347e3613d36bp0,
    0x1.db6db6db6db6cp-1
  },
  { // Entry 296
    0x1.768774cc7f49764e7589347e3613d36bp0,
    -0x1.db6db6db6db6cp-1
  },
  { // Entry 297
    0x1.8b07551d9f54f1f51d63c148150ff9f0p0,
    0x1.ffffffffffffep-1
  },
  { // Entry 298
    0x1.8b07551d9f54f1f51d63c148150ff9f0p0,
    -0x1.ffffffffffffep-1
  },
  { // Entry 299
    0x1.p0,
    0.0
  },
  { // Entry 300
    0x1.0009a148b0e06dc3d0614c40dd1468d6p0,
    0x1.18de5ab277f45p-6
  },
  { // Entry 301
    0x1.0009a148b0e06dc3d0614c40dd1468d6p0,
    -0x1.18de5ab277f45p-6
  },
  { // Entry 302
    0x1.002685dc3cf39cdb36154a8c673f400bp0,
    0x1.18de5ab277f45p-5
  },
  { // Entry 303
    0x1.002685dc3cf39cdb36154a8c673f400bp0,
    -0x1.18de5ab277f45p-5
  },
  { // Entry 304
    0x1.0056afe71e837cc56169a00a96535d60p0,
    0x1.a54d880bb3ee8p-5
  },
  { // Entry 305
    0x1.0056afe71e837cc56169a00a96535d60p0,
    -0x1.a54d880bb3ee8p-5
  },
  { // Entry 306
    0x1.009a2308fa8fcdaddee63777dbb370e6p0,
    0x1.18de5ab277f45p-4
  },
  { // Entry 307
    0x1.009a2308fa8fcdaddee63777dbb370e6p0,
    -0x1.18de5ab277f45p-4
  },
  { // Entry 308
    0x1.00f0e454e69896dbe7bfa42c490502bbp0,
    0x1.5f15f15f15f16p-4
  },
  { // Entry 309
    0x1.00f0e454e69896dbe7bfa42c490502bbp0,
    -0x1.5f15f15f15f16p-4
  },
  { // Entry 310
    0x1.015afa51ca5a8c6a812cb74010fd2339p0,
    0x1.a54d880bb3ee7p-4
  },
  { // Entry 311
    0x1.015afa51ca5a8c6a812cb74010fd2339p0,
    -0x1.a54d880bb3ee7p-4
  },
  { // Entry 312
    0x1.01d86cfadd84bef42effbee90fd3b265p0,
    0x1.eb851eb851eb8p-4
  },
  { // Entry 313
    0x1.01d86cfadd84bef42effbee90fd3b265p0,
    -0x1.eb851eb851eb8p-4
  },
  { // Entry 314
    0x1.01d86cfadd84bef42effbee90fd3b265p0,
    0x1.eb851eb851eb8p-4
  },
  { // Entry 315
    0x1.01d86cfadd84bef42effbee90fd3b265p0,
    -0x1.eb851eb851eb8p-4
  },
  { // Entry 316
    0x1.02068cf05597373684859565fe36babfp0,
    0x1.01767dce434aap-3
  },
  { // Entry 317
    0x1.02068cf05597373684859565fe36babfp0,
    -0x1.01767dce434aap-3
  },
  { // Entry 318
    0x1.0236d50fb0daff9feea39dcae5219685p0,
    0x1.0d2a6c405d9f8p-3
  },
  { // Entry 319
    0x1.0236d50fb0daff9feea39dcae5219685p0,
    -0x1.0d2a6c405d9f8p-3
  },
  { // Entry 320
    0x1.026945c041710aacb6e5b3c7fb2aa37ap0,
    0x1.18de5ab277f46p-3
  },
  { // Entry 321
    0x1.026945c041710aacb6e5b3c7fb2aa37ap0,
    -0x1.18de5ab277f46p-3
  },
  { // Entry 322
    0x1.029ddf6df7f29d011dd86bfe01ec3683p0,
    0x1.2492492492494p-3
  },
  { // Entry 323
    0x1.029ddf6df7f29d011dd86bfe01ec3683p0,
    -0x1.2492492492494p-3
  },
  { // Entry 324
    0x1.02d4a289645849faf12a95a92d2534d5p0,
    0x1.30463796ac9e2p-3
  },
  { // Entry 325
    0x1.02d4a289645849faf12a95a92d2534d5p0,
    -0x1.30463796ac9e2p-3
  },
  { // Entry 326
    0x1.030d8f87b6ead4a0bc7464b33dbba3aap0,
    0x1.3bfa2608c6f30p-3
  },
  { // Entry 327
    0x1.030d8f87b6ead4a0bc7464b33dbba3aap0,
    -0x1.3bfa2608c6f30p-3
  },
  { // Entry 328
    0x1.0348a6e2c13df5fb3d99c361a1bb9dcbp0,
    0x1.47ae147ae147bp-3
  },
  { // Entry 329
    0x1.0348a6e2c13df5fb3d99c361a1bb9dcbp0,
    -0x1.47ae147ae147bp-3
  },
  { // Entry 330
    0x1.0348a6e2c13df5fb3d99c361a1bb9dcbp0,
    0x1.47ae147ae147bp-3
  },
  { // Entry 331
    0x1.0348a6e2c13df5fb3d99c361a1bb9dcbp0,
    -0x1.47ae147ae147bp-3
  },
  { // Entry 332
    0x1.0a19d6de605abf08129cddde1636dd2ap0,
    0x1.1eb851eb851ecp-2
  },
  { // Entry 333
    0x1.0a19d6de605abf08129cddde1636dd2ap0,
    -0x1.1eb851eb851ecp-2
  },
  { // Entry 334
    0x1.14c128b1a7c2b69f584c42e1f5d24e43p0,
    0x1.999999999999ap-2
  },
  { // Entry 335
    0x1.14c128b1a7c2b69f584c42e1f5d24e43p0,
    -0x1.999999999999ap-2
  },
  { // Entry 336
    0x1.2365ee6c60d331135d0b3ad315833363p0,
    0x1.0a3d70a3d70a4p-1
  },
  { // Entry 337
    0x1.2365ee6c60d331135d0b3ad315833363p0,
    -0x1.0a3d70a3d70a4p-1
  },
  { // Entry 338
    0x1.363e341f66160527d93c30b63d619a60p0,
    0x1.47ae147ae147bp-1
  },
  { // Entry 339
    0x1.363e341f66160527d93c30b63d619a60p0,
    -0x1.47ae147ae147bp-1
  },
  { // Entry 340
    0x1.4d8f87572582badd7439620bd7e9590bp0,
    0x1.851eb851eb852p-1
  },
  { // Entry 341
    0x1.4d8f87572582badd7439620bd7e9590bp0,
    -0x1.851eb851eb852p-1
  },
  { // Entry 342
    0x1.69aff7d0ce135dcd1a6ec2e65d0a89dfp0,
    0x1.c28f5c28f5c29p-1
  },
  { // Entry 343
    0x1.69aff7d0ce135dcd1a6ec2e65d0a89dfp0,
    -0x1.c28f5c28f5c29p-1
  },
  { // Entry 344
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    0x1.0p0
  },
  { // Entry 345
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    -0x1.0p0
  },
  { // Entry 346
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    0x1.0p0
  },
  { // Entry 347
    0x1.8b07551d9f5504c2bd28100196a4f66ap0,
    -0x1.0p0
  },
  { // Entry 348
    0x1.c035cc3cf78edf8213cbad9479090d14p7,
    0x1.86bc88cbf1b67p2
  },
  { // Entry 349
    0x1.c035cc3cf78edf8213cbad9479090d14p7,
    -0x1.86bc88cbf1b67p2
  },
  { // Entry 350
    0x1.20af6cbb4ba69598ec939d7de84f588dp15,
    0x1.66bc88cbf1b67p3
  },
  { // Entry 351
    0x1.20af6cbb4ba69598ec939d7de84f588dp15,
    -0x1.66bc88cbf1b67p3
  },
  { // Entry 352
    0x1.73e096cf57b5505242fb8e3b8be68034p22,
    0x1.050d6698f548dp4
  },
  { // Entry 353
    0x1.73e096cf57b5505242fb8e3b8be68034p22,
    -0x1.050d6698f548dp4
  },
  { // Entry 354
    0x1.df0b13a84513e2dfcb4b2dd0b765caf4p29,
    0x1.56bc88cbf1b67p4
  },
  { // Entry 355
    0x1.df0b13a84513e2dfcb4b2dd0b765caf4p29,
    -0x1.56bc88cbf1b67p4
  },
  { // Entry 356
    0x1.348bc1e018bc593ce3145e9f4c06b22cp37,
    0x1.a86baafeee241p4
  },
  { // Entry 357
    0x1.348bc1e018bc593ce3145e9f4c06b22cp37,
    -0x1.a86baafeee241p4
  },
  { // Entry 358
    0x1.8d761a3398942448ea796cb7e602a205p44,
    0x1.fa1acd31ea91bp4
  },
  { // Entry 359
    0x1.8d761a3398942448ea796cb7e602a205p44,
    -0x1.fa1acd31ea91bp4
  },
  { // Entry 360
    0x1.ffffffffffff9ede67b7a30e671c79e2p51,
    0x1.25e4f7b2737fap5
  },
  { // Entry 361
    0x1.ffffffffffff9ede67b7a30e671c79e2p51,
```
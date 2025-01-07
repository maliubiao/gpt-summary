Response:
Let's break down the thought process for answering the prompt.

1. **Understanding the Core Request:** The main goal is to analyze a C source code file (`tan_intel_data.handroid`) and explain its purpose and context within Android's Bionic library. The request specifically asks for a summary in this first part.

2. **Initial Scan of the Code:**  A quick glance reveals the following:
    * The file starts with a copyright notice indicating it's part of the Android Open Source Project.
    * It declares a static array named `g_tan_intel_data`.
    * The array's elements are of type `data_1_1_t<double, double>`.
    * The data within the array looks like pairs of hexadecimal floating-point numbers. Each pair is labeled with an "Entry" number.

3. **Inferring the Purpose:**  Based on the name `tan_intel_data` and the `double, double` type, the most likely purpose is to store data used in the calculation of the tangent function. The "intel" part might suggest architecture-specific optimizations or data derived from Intel hardware testing. The "handroid" suffix might be a historical artifact or internal codename.

4. **Connecting to Android's Functionality:**  Since this is in `bionic/tests/math_data`, it's clearly related to the math library (`libm`) within Bionic. The `tan` function is a standard mathematical function, so this data likely supports the implementation of `tan()` in Android. This data probably serves as test cases to verify the accuracy of the `tan()` implementation across different input values.

5. **Identifying Key Data Structure:** The `data_1_1_t<double, double>` template isn't defined in this snippet. However, based on the data, it's reasonable to assume it's a simple structure or pair holding an input value and the corresponding expected output value for the tangent function.

6. **Focusing on the "归纳一下它的功能" (Summarize its function) part for Part 1:** The request specifically asks for a summary in this first part. Therefore, I need to extract the core function without going into excessive detail.

7. **Drafting the Summary (Initial Thoughts):**
    * This file contains data for the tangent function.
    * It's used for testing the `tan()` implementation in Bionic.
    * The data is likely input-output pairs.

8. **Refining the Summary (Adding More Context and Specificity):**
    * Be more explicit about the data being for the `tan()` function in Android's math library.
    * Emphasize the role of testing and validation.
    * Mention the data format (pairs of doubles).
    * Include the potential for architecture-specific considerations (the "intel" part).
    * Add that it's part of the Bionic testing infrastructure.

9. **Finalizing the Summary (Addressing Key Aspects of the Prompt):**
    * **功能 (Functionality):** Explicitly state its function is to provide test data for the `tan()` function.
    * **与 Android 的关系 (Relationship with Android):** Connect it to Android's Bionic library, specifically the math library (`libm`), and the need for accurate math functions.
    * **其他 (Other):**  Include the "intel" aspect and its potential implications.

10. **Self-Correction/Refinement during the process:**
    * Initially, I might have simply said "test data." But the prompt implies a deeper understanding. So, I elaborated on *what* is being tested and *why*.
    * I considered mentioning the negative values in the data, which suggest testing of symmetry or edge cases. While relevant for a deeper dive, for a summary in Part 1, it might be too much detail.
    * I also initially focused heavily on the "intel" part but realized that without more context, it's just a speculation. So, I phrased it as a possibility.

By following these steps, focusing on the core request, gradually building the explanation, and refining it with relevant details while keeping the "summary" constraint of Part 1 in mind, I arrived at the provided answer. The key is to read the prompt carefully, identify the core information in the code, and connect it to the broader context of Android's Bionic library.
好的，我们来归纳一下 `bionic/tests/math_data/tan_intel_data.handroid` 文件的功能。

**功能归纳：**

这个 C 源代码文件 `tan_intel_data.handroid` 的主要功能是：

**存储用于测试 `tan()` 函数的测试数据。**

更具体地说：

* **提供了一系列预定义的输入和期望输出值对，用于验证 Android 系统中 `tan()` 函数的实现是否正确和精确。**  这些数据针对的是 `double` 类型的输入和输出。
* **这些测试数据可能是针对特定的硬件架构（Intel）进行优化的或基于 Intel 硬件测试得到的。** 文件名中的 "intel" 暗示了这一点。
* **这些数据是 Bionic 库的测试套件的一部分，用于确保其数学库的质量和可靠性。**

**与 Android 功能的关系：**

该文件直接关系到 Android 系统中数学运算的正确性。`tan()` 函数是标准 C 库 `<math.h>` 中的一个函数，用于计算给定角度（弧度）的正切值。

**举例说明：**

Android 应用程序或系统服务在进行涉及到三角函数计算时，会调用 Bionic 库中的 `tan()` 函数。`tan_intel_data.handroid` 中存储的数据被用于测试这个 `tan()` 函数的实现是否正确。例如，测试代码可能会取该文件中的一个输入值，传递给 `tan()` 函数，然后将函数的返回值与文件中对应的期望输出值进行比较，以判断 `tan()` 函数的实现是否符合预期。

**总结（针对第 1 部分）：**

总而言之，`bionic/tests/math_data/tan_intel_data.handroid` 是 Android Bionic 库中用于测试 `tan()` 函数实现的测试数据文件，它包含了一系列 Intel 架构相关的输入和预期输出值对，用于验证 `tan()` 函数的准确性。 它是 Android 平台保证数学运算功能正确性的重要组成部分。

**请注意：**  由于这只是文件的内容，我们只能推断其功能。要了解其更详细的使用方式，需要查看相关的测试代码。

Prompt: 
```
这是目录为bionic/tests/math_data/tan_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共4部分，请归纳一下它的功能

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

static data_1_1_t<double, double> g_tan_intel_data[] = {
  { // Entry 0
    0x1.5078cebff9c728000000000000024df8p-5,
    0x1.50486b2f87014p-5
  },
  { // Entry 1
    -0x1.5078cebff9c728000000000000024df8p-5,
    -0x1.50486b2f87014p-5
  },
  { // Entry 2
    0x1.5389e6df41978fffffffffffffc61f54p-4,
    0x1.52c39ef070cadp-4
  },
  { // Entry 3
    -0x1.5389e6df41978fffffffffffffc61f54p-4,
    -0x1.52c39ef070cadp-4
  },
  { // Entry 4
    0x1.a933fe176b37500000000000000a4065p-3,
    0x1.a33f32ac5ceb5p-3
  },
  { // Entry 5
    -0x1.a933fe176b37500000000000000a4065p-3,
    -0x1.a33f32ac5ceb5p-3
  },
  { // Entry 6
    0x1.fac71cd34eea680000000000009a0c10p-2,
    0x1.d696bfa988db9p-2
  },
  { // Entry 7
    -0x1.fac71cd34eea680000000000009a0c10p-2,
    -0x1.d696bfa988db9p-2
  },
  { // Entry 8
    0x1.7ba49f739829efffffffffffffe7e9bep-1,
    0x1.46ac372243536p-1
  },
  { // Entry 9
    -0x1.7ba49f739829efffffffffffffe7e9bep-1,
    -0x1.46ac372243536p-1
  },
  { // Entry 10
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 11
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 12
    -0x1.8f048832144b70021ccd7a5246cb0b20p0,
    -0x1.00180p0
  },
  { // Entry 13
    0x1.8f048832144b70021ccd7a5246cb0b20p0,
    0x1.00180p0
  },
  { // Entry 14
    -0x1.8e884b24313ae802db47899fad15a6c6p0,
    -0x1.090cca18a5565p2
  },
  { // Entry 15
    0x1.8e884b24313ae802db47899fad15a6c6p0,
    0x1.090cca18a5565p2
  },
  { // Entry 16
    -0x1.ca18654b356972967a4f1e8404b9f972p0,
    -0x1.0faa7650df144p0
  },
  { // Entry 17
    0x1.ca18654b356972967a4f1e8404b9f972p0,
    0x1.0faa7650df144p0
  },
  { // Entry 18
    -0x1.e52fafa22ef1481d437e7ed32cba03b1p-2,
    -0x1.1800000000040p5
  },
  { // Entry 19
    0x1.e52fafa22ef1481d437e7ed32cba03b1p-2,
    0x1.1800000000040p5
  },
  { // Entry 20
    -0x1.a3ca421dc30f1c5760a1ae07396fec33p-3,
    -0x1.4000527aca388p99
  },
  { // Entry 21
    0x1.a3ca421dc30f1c5760a1ae07396fec33p-3,
    0x1.4000527aca388p99
  },
  { // Entry 22
    0x1.1f3b7d1978609800a1628e1df9558df6p1,
    -0x1.486c3634751ecp2
  },
  { // Entry 23
    -0x1.1f3b7d1978609800a1628e1df9558df6p1,
    0x1.486c3634751ecp2
  },
  { // Entry 24
    -0x1.7eb873343fa7ab5d9ef9a78afd33d501p-1,
    -0x1.48a71800b5713p-1
  },
  { // Entry 25
    0x1.7eb873343fa7ab5d9ef9a78afd33d501p-1,
    0x1.48a71800b5713p-1
  },
  { // Entry 26
    0x1.be071572f64e88047c3939ba46626a25p-1,
    -0x1.49af0314eea3cp299
  },
  { // Entry 27
    -0x1.be071572f64e88047c3939ba46626a25p-1,
    0x1.49af0314eea3cp299
  },
  { // Entry 28
    0x1.ffbb2647f57a181bd1296faf33c04e3ep-1,
    -0x1.5fe00c814ffd6p2
  },
  { // Entry 29
    -0x1.ffbb2647f57a181bd1296faf33c04e3ep-1,
    0x1.5fe00c814ffd6p2
  },
  { // Entry 30
    -0x1.a8eb142b2f42756e6dedff09267a62c6p-1,
    -0x1.62ac241f79439p-1
  },
  { // Entry 31
    0x1.a8eb142b2f42756e6dedff09267a62c6p-1,
    0x1.62ac241f79439p-1
  },
  { // Entry 32
    -0x1.7d1d3559ddac885ee30632c760998c8ep-4,
    -0x1.7c051b476ca8dp-4
  },
  { // Entry 33
    0x1.7d1d3559ddac885ee30632c760998c8ep-4,
    0x1.7c051b476ca8dp-4
  },
  { // Entry 34
    -0x1.0e1d0305b7b727ff193d9d0b8eaff181p2,
    -0x1.7e43c880074c6p996
  },
  { // Entry 35
    0x1.0e1d0305b7b727ff193d9d0b8eaff181p2,
    0x1.7e43c880074c6p996
  },
  { // Entry 36
    -0x1.812bdfe0246bbf2a7ab6477a5cbb352bp-4,
    -0x1.800ac363398c4p-4
  },
  { // Entry 37
    0x1.812bdfe0246bbf2a7ab6477a5cbb352bp-4,
    0x1.800ac363398c4p-4
  },
  { // Entry 38
    -0x1.850e5544b0c797b36034c98e16f3fafbp-4,
    -0x1.83e46aedbff36p-4
  },
  { // Entry 39
    0x1.850e5544b0c797b36034c98e16f3fafbp-4,
    0x1.83e46aedbff36p-4
  },
  { // Entry 40
    0x1.e6b5d91bba9337fc0ceb686c60cd29bdp-2,
    -0x1.83ecf42e9265ap3
  },
  { // Entry 41
    -0x1.e6b5d91bba9337fc0ceb686c60cd29bdp-2,
    0x1.83ecf42e9265ap3
  },
  { // Entry 42
    -0x1.f3688bc2594e20102573cff48190ac28p-1,
    -0x1.8bcp-1
  },
  { // Entry 43
    0x1.f3688bc2594e20102573cff48190ac28p-1,
    0x1.8bcp-1
  },
  { // Entry 44
    0x1.ec0d0facdd08b773a1d93484e2d66c45p-2,
    -0x1.8d2ffffffffd1p9
  },
  { // Entry 45
    -0x1.ec0d0facdd08b773a1d93484e2d66c45p-2,
    0x1.8d2ffffffffd1p9
  },
  { // Entry 46
    0x1.ec0336d5392597689b640bf049227338p-2,
    -0x1.8d3000fffffd1p9
  },
  { // Entry 47
    -0x1.ec0336d5392597689b640bf049227338p-2,
    0x1.8d3000fffffd1p9
  },
  { // Entry 48
    -0x1.f8093a017021f81c01c131475e50e49bp-1,
    -0x1.baeee6f6fa538p6
  },
  { // Entry 49
    0x1.f8093a017021f81c01c131475e50e49bp-1,
    0x1.baeee6f6fa538p6
  },
  { // Entry 50
    0x1.deaf34994b7e77fd52a408f0c677eae1p3,
    -0x1.c6867e07455eap3
  },
  { // Entry 51
    -0x1.deaf34994b7e77fd52a408f0c677eae1p3,
    0x1.c6867e07455eap3
  },
  { // Entry 52
    -0x1.f29aa87d4e1dd81b7b69abe9790ee0abp-1,
    -0x1.d27ffffffe0p7
  },
  { // Entry 53
    0x1.f29aa87d4e1dd81b7b69abe9790ee0abp-1,
    0x1.d27ffffffe0p7
  },
  { // Entry 54
    0x1.762fb47a192597ffffffeeedb26fb978p-3,
    -0x1.f0df38029c9efp3
  },
  { // Entry 55
    -0x1.762fb47a192597ffffffeeedb26fb978p-3,
    0x1.f0df38029c9efp3
  },
  { // Entry 56
    -0x1.8eb23ef2126bb7fffd153c7ff90e9f6cp0,
    -0x1.fffffc0000fffp-1
  },
  { // Entry 57
    0x1.8eb23ef2126bb7fffd153c7ff90e9f6cp0,
    0x1.fffffc0000fffp-1
  },
  { // Entry 58
    -0x1.d299d285bf018423fbc14efc00ed5799p-2,
    -0x1.ffffffffffffcp1023
  },
  { // Entry 59
    0x1.d299d285bf018423fbc14efc00ed5799p-2,
    0x1.ffffffffffffcp1023
  },
  { // Entry 60
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 61
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 62
    -0x1.82bee572e2ac8c76d6909c66b282e962p-6,
    0x1.0p64
  },
  { // Entry 63
    0x1.82bee572e2ac8c76d6909c66b282e962p-6,
    -0x1.0p64
  },
  { // Entry 64
    0x1.f53a8d05afcf6c4bf2e1e5208b34d5c6p4,
    0x1.0000000000001p51
  },
  { // Entry 65
    -0x1.f53a8d05afcf6c4bf2e1e5208b34d5c6p4,
    -0x1.0000000000001p51
  },
  { // Entry 66
    -0x1.6b371df5980cd3db36768e36046a4a81p-1,
    0x1.0000000000001p1017
  },
  { // Entry 67
    0x1.6b371df5980cd3db36768e36046a4a81p-1,
    -0x1.0000000000001p1017
  },
  { // Entry 68
    -0x1.b32e78f49a0c83c7f60a3dc3ef8ecf1fp2,
    0x1.0000000000003p3
  },
  { // Entry 69
    0x1.b32e78f49a0c83c7f60a3dc3ef8ecf1fp2,
    -0x1.0000000000003p3
  },
  { // Entry 70
    0x1.98afbd24264bc3a9d1838074a3daa5e5p-1,
    0x1.0000000000003p21
  },
  { // Entry 71
    -0x1.98afbd24264bc3a9d1838074a3daa5e5p-1,
    -0x1.0000000000003p21
  },
  { // Entry 72
    0x1.b667a2abe36c280315c62a1f974e7611p0,
    0x1.0000000000003p511
  },
  { // Entry 73
    -0x1.b667a2abe36c280315c62a1f974e7611p0,
    -0x1.0000000000003p511
  },
  { // Entry 74
    0x1.204c26a427861ffefb73796bcf1fd724p-2,
    0x1.0000000000003p716
  },
  { // Entry 75
    -0x1.204c26a427861ffefb73796bcf1fd724p-2,
    -0x1.0000000000003p716
  },
  { // Entry 76
    0x1.91c8f2938262ce2e9ad99ab17e46abd6p4,
    0x1.0000000000007p8
  },
  { // Entry 77
    -0x1.91c8f2938262ce2e9ad99ab17e46abd6p4,
    -0x1.0000000000007p8
  },
  { // Entry 78
    -0x1.27f7f0880031fe42ed1d5fedc496d14ep-2,
    0x1.0000000000038p380
  },
  { // Entry 79
    0x1.27f7f0880031fe42ed1d5fedc496d14ep-2,
    -0x1.0000000000038p380
  },
  { // Entry 80
    -0x1.d6890cc32711d4b046903ad8851a41bbp-3,
    0x1.0000000000118p380
  },
  { // Entry 81
    0x1.d6890cc32711d4b046903ad8851a41bbp-3,
    -0x1.0000000000118p380
  },
  { // Entry 82
    0x1.9af0e6f72f9127ffffc0200ea7f406f4p-3,
    0x1.0000000000908p500
  },
  { // Entry 83
    -0x1.9af0e6f72f9127ffffc0200ea7f406f4p-3,
    -0x1.0000000000908p500
  },
  { // Entry 84
    0x1.17b4f5bf440978002d66f1bd37032532p-1,
    0x1.000000000c0p-1
  },
  { // Entry 85
    -0x1.17b4f5bf440978002d66f1bd37032532p-1,
    -0x1.000000000c0p-1
  },
  { // Entry 86
    -0x1.17eb22e4dba72800d2a000698263d582p0,
    0x1.00000001cp40
  },
  { // Entry 87
    0x1.17eb22e4dba72800d2a000698263d582p0,
    -0x1.00000001cp40
  },
  { // Entry 88
    0x1.f6f03ce5690a6e3880b95fd8b2c8363ep-1,
    0x1.0000001p250
  },
  { // Entry 89
    -0x1.f6f03ce5690a6e3880b95fd8b2c8363ep-1,
    -0x1.0000001p250
  },
  { // Entry 90
    0x1.e23b78282a75d0dd6da35692d142bc63p-1,
    0x1.000000988p27
  },
  { // Entry 91
    -0x1.e23b78282a75d0dd6da35692d142bc63p-1,
    -0x1.000000988p27
  },
  { // Entry 92
    -0x1.981b657e1ca27009d82d8e18314240b5p-3,
    0x1.00000c0p429
  },
  { // Entry 93
    0x1.981b657e1ca27009d82d8e18314240b5p-3,
    -0x1.00000c0p429
  },
  { // Entry 94
    -0x1.455a2184f4c3dffb0986919cece683a4p-1,
    0x1.00000fcp1000
  },
  { // Entry 95
    0x1.455a2184f4c3dffb0986919cece683a4p-1,
    -0x1.00000fcp1000
  },
  { // Entry 96
    0x1.8ee66962f210c800000568c7daad3a28p0,
    0x1.000f371b7a006p0
  },
  { // Entry 97
    -0x1.8ee66962f210c800000568c7daad3a28p0,
    -0x1.000f371b7a006p0
  },
  { // Entry 98
    -0x1.ecd75cf6d4663bee1c96f03184fae086p-3,
    0x1.001p15
  },
  { // Entry 99
    0x1.ecd75cf6d4663bee1c96f03184fae086p-3,
    -0x1.001p15
  },
  { // Entry 100
    0x1.17d42033277cc8244ccb6e5154482105p-1,
    0x1.0017ffffffffdp-1
  },
  { // Entry 101
    -0x1.17d42033277cc8244ccb6e5154482105p-1,
    -0x1.0017ffffffffdp-1
  },
  { // Entry 102
    0x1.8f048832144b70021ccd7a5246cb0b20p0,
    0x1.00180p0
  },
  { // Entry 103
    -0x1.8f048832144b70021ccd7a5246cb0b20p0,
    -0x1.00180p0
  },
  { // Entry 104
    -0x1.18273cc3e763900743704028cfb114a5p-2,
    0x1.001fffep500
  },
  { // Entry 105
    0x1.18273cc3e763900743704028cfb114a5p-2,
    -0x1.001fffep500
  },
  { // Entry 106
    -0x1.d8f90cad30546ce5b8268b330ce50a6fp-2,
    0x1.018p40
  },
  { // Entry 107
    0x1.d8f90cad30546ce5b8268b330ce50a6fp-2,
    -0x1.018p40
  },
  { // Entry 108
    0x1.b079ea0d14a4a7ffc04bd6fbf451bb34p-2,
    0x1.01b8a484ac0b6p4
  },
  { // Entry 109
    -0x1.b079ea0d14a4a7ffc04bd6fbf451bb34p-2,
    -0x1.01b8a484ac0b6p4
  },
  { // Entry 110
    -0x1.a40c262f6ab997fef43bf54af3c5a765p-1,
    0x1.026ac0ef32d40p28
  },
  { // Entry 111
    0x1.a40c262f6ab997fef43bf54af3c5a765p-1,
    -0x1.026ac0ef32d40p28
  },
  { // Entry 112
    0x1.03b8c1f3296657c651a13eb5b100fc78p-4,
    0x1.035fdcd08a596p-4
  },
  { // Entry 113
    -0x1.03b8c1f3296657c651a13eb5b100fc78p-4,
    -0x1.035fdcd08a596p-4
  },
  { // Entry 114
    0x1.044979d134ed97c78bfe58a9003bfac5p-4,
    0x1.03fp-4
  },
  { // Entry 115
    -0x1.044979d134ed97c78bfe58a9003bfac5p-4,
    -0x1.03fp-4
  },
  { // Entry 116
    -0x1.e717de7da2ce831066bad1df5e88a030p0,
    0x1.070p1
  },
  { // Entry 117
    0x1.e717de7da2ce831066bad1df5e88a030p0,
    -0x1.070p1
  },
  { // Entry 118
    -0x1.8c896f607ff52bbae86f63e19a988d2bp-1,
    0x1.070p30
  },
  { // Entry 119
    0x1.8c896f607ff52bbae86f63e19a988d2bp-1,
    -0x1.070p30
  },
  { // Entry 120
    0x1.fffffffff5d846af6f017262c9c81de4p-1,
    0x1.07e4cef4cbb0ep4
  },
  { // Entry 121
    -0x1.fffffffff5d846af6f017262c9c81de4p-1,
    -0x1.07e4cef4cbb0ep4
  },
  { // Entry 122
    0x1.b476d32c1b7457ffff66edb3f78a7003p0,
    0x1.0a53a78b13ab2p0
  },
  { // Entry 123
    -0x1.b476d32c1b7457ffff66edb3f78a7003p0,
    -0x1.0a53a78b13ab2p0
  },
  { // Entry 124
    0x1.f2df7c02d20cd81b33117c00545f7a6bp-1,
    0x1.0afbc268b9848p6
  },
  { // Entry 125
    -0x1.f2df7c02d20cd81b33117c00545f7a6bp-1,
    -0x1.0afbc268b9848p6
  },
  { // Entry 126
    -0x1.b571af562f08a5a03dd8493990b29db1p0,
    0x1.0cd5d435bea6dp1
  },
  { // Entry 127
    0x1.b571af562f08a5a03dd8493990b29db1p0,
    -0x1.0cd5d435bea6dp1
  },
  { // Entry 128
    -0x1.ac73d2920a7955336ab2a3436c77c276p0,
    0x1.0e0p1
  },
  { // Entry 129
    0x1.ac73d2920a7955336ab2a3436c77c276p0,
    -0x1.0e0p1
  },
  { // Entry 130
    -0x1.126dce8ac7c818000cfcf3df066a4a2dp-1,
    0x1.1086210842108p5
  },
  { // Entry 131
    0x1.126dce8ac7c818000cfcf3df066a4a2dp-1,
    -0x1.1086210842108p5
  },
  { // Entry 132
    -0x1.9680c02601046ca506c0e3f744db1d0ap0,
    0x1.110p1
  },
  { // Entry 133
    0x1.9680c02601046ca506c0e3f744db1d0ap0,
    -0x1.110p1
  },
  { // Entry 134
    0x1.d1e716934469b2bc02fa835ae0149f58p0,
    0x1.118p0
  },
  { // Entry 135
    -0x1.d1e716934469b2bc02fa835ae0149f58p0,
    -0x1.118p0
  },
  { // Entry 136
    -0x1.6aa73101430837fffffebaafd45f7efap-1,
    0x1.19df389f39e0ap3
  },
  { // Entry 137
    0x1.6aa73101430837fffffebaafd45f7efap-1,
    -0x1.19df389f39e0ap3
  },
  { // Entry 138
    0x1.cb9a99227bdc972cd4145969c3dc38c1p1,
    0x1.1c3598211013ap2
  },
  { // Entry 139
    -0x1.cb9a99227bdc972cd4145969c3dc38c1p1,
    -0x1.1c3598211013ap2
  },
  { // Entry 140
    -0x1.bc109c3e6172450a5308b4c6eb2898cap7,
    0x1.1d65aa4224c30p118
  },
  { // Entry 141
    0x1.bc109c3e6172450a5308b4c6eb2898cap7,
    -0x1.1d65aa4224c30p118
  },
  { // Entry 142
    -0x1.09b393f48b2c67ffff3bd559c6326e60p-1,
    0x1.1e4658272dc6fp3
  },
  { // Entry 143
    0x1.09b393f48b2c67ffff3bd559c6326e60p-1,
    -0x1.1e4658272dc6fp3
  },
  { // Entry 144
    0x1.20000000000798000000003d82666666p-22,
    0x1.2p-22
  },
  { // Entry 145
    -0x1.20000000000798000000003d82666666p-22,
    -0x1.2p-22
  },
  { // Entry 146
    -0x1.02a335b00707a7ffffbe455adab7e814p0,
    0x1.2127409620cacp95
  },
  { // Entry 147
    0x1.02a335b00707a7ffffbe455adab7e814p0,
    -0x1.2127409620cacp95
  },
  { // Entry 148
    0x1.2508b9c1273ac034c3c79c4088e2acfdp-4,
    0x1.2489224892248p-4
  },
  { // Entry 149
    -0x1.2508b9c1273ac034c3c79c4088e2acfdp-4,
    -0x1.2489224892248p-4
  },
  { // Entry 150
    0x1.fded5f53d132d26a8244a63f9bcdf153p2,
    0x1.2a52d119da061p237
  },
  { // Entry 151
    -0x1.fded5f53d132d26a8244a63f9bcdf153p2,
    -0x1.2a52d119da061p237
  },
  { // Entry 152
    0x1.2de56a6ef9c5d7e9c71030407530f1d7p-4,
    0x1.2d59ebab8dae4p-4
  },
  { // Entry 153
    -0x1.2de56a6ef9c5d7e9c71030407530f1d7p-4,
    -0x1.2d59ebab8dae4p-4
  },
  { // Entry 154
    0x1.31665eb191fba800b7e715fd11716c8cp-4,
    0x1.30d5f8e54b6d8p-4
  },
  { // Entry 155
    -0x1.31665eb191fba800b7e715fd11716c8cp-4,
    -0x1.30d5f8e54b6d8p-4
  },
  { // Entry 156
    0x1.3cc1d4d28bfd17fded9ae50407590f3fp-2,
    0x1.333275d63ec50p-2
  },
  { // Entry 157
    -0x1.3cc1d4d28bfd17fded9ae50407590f3fp-2,
    -0x1.333275d63ec50p-2
  },
  { // Entry 158
    0x1.3cc237c0c7dcbfff1046ad9a068af510p-2,
    0x1.3332d020b6da9p-2
  },
  { // Entry 159
    -0x1.3cc237c0c7dcbfff1046ad9a068af510p-2,
    -0x1.3332d020b6da9p-2
  },
  { // Entry 160
    0x1.5e472e16999df00000fc06ee474fbfc9p-1,
    0x1.333333401e66bp-1
  },
  { // Entry 161
    -0x1.5e472e16999df00000fc06ee474fbfc9p-1,
    -0x1.333333401e66bp-1
  },
  { // Entry 162
    0x1.b5ed1c2080a987fc84f26ec958b2ac47p-1,
    0x1.38f137cb9dbfcp9
  },
  { // Entry 163
    -0x1.b5ed1c2080a987fc84f26ec958b2ac47p-1,
    -0x1.38f137cb9dbfcp9
  },
  { // Entry 164
    0x1.01aa22e2133d37fffff2a0c08093358ep1,
    0x1.39a383f3fa003p85
  },
  { // Entry 165
    -0x1.01aa22e2133d37fffff2a0c08093358ep1,
    -0x1.39a383f3fa003p85
  },
  { // Entry 166
    0x1.ffffffffff58236322819d060eb67c3cp-1,
    0x1.3a28c59d54311p4
  },
  { // Entry 167
    -0x1.ffffffffff58236322819d060eb67c3cp-1,
    -0x1.3a28c59d54311p4
  },
  { // Entry 168
    0x1.7166689d4803e83d2b6b1d15f5aca26ep-1,
    0x1.4000000003fffp-1
  },
  { // Entry 169
    -0x1.7166689d4803e83d2b6b1d15f5aca26ep-1,
    -0x1.4000000003fffp-1
  },
  { // Entry 170
    -0x1.ff7d27b37eba0819199e533cc5016f0dp-1,
    0x1.40724a44714cfp5
  },
  { // Entry 171
    0x1.ff7d27b37eba0819199e533cc5016f0dp-1,
    -0x1.40724a44714cfp5
  },
  { // Entry 172
    0x1.453a7d29dadad7c0dda78a7398be0873p-4,
    0x1.448c2d6e1e1afp-4
  },
  { // Entry 173
    -0x1.453a7d29dadad7c0dda78a7398be0873p-4,
    -0x1.448c2d6e1e1afp-4
  },
  { // Entry 174
    -0x1.a50f7601413e53ab1c5a2f0d676c397cp0,
    0x1.478fc08p43
  },
  { // Entry 175
    0x1.a50f7601413e53ab1c5a2f0d676c397cp0,
    -0x1.478fc08p43
  },
  { // Entry 176
    -0x1.a9991acb7636beee5b1a5d35a8a89917p-4,
    0x1.4e93bee72b565p62
  },
  { // Entry 177
    0x1.a9991acb7636beee5b1a5d35a8a89917p-4,
    -0x1.4e93bee72b565p62
  },
  { // Entry 178
    0x1.2952396945947b726ebf025a8ba07093p1,
    0x1.4f0f308p488
  },
  { // Entry 179
    -0x1.2952396945947b726ebf025a8ba07093p1,
    -0x1.4f0f308p488
  },
  { // Entry 180
    0x1.5078cebff9c728000000000000024df8p-5,
    0x1.50486b2f87014p-5
  },
  { // Entry 181
    -0x1.5078cebff9c728000000000000024df8p-5,
    -0x1.50486b2f87014p-5
  },
  { // Entry 182
    -0x1.1c929b6ede9ee8000040a3d1ca90a9f4p-1,
    0x1.5130d552f1036p1
  },
  { // Entry 183
    0x1.1c929b6ede9ee8000040a3d1ca90a9f4p-1,
    -0x1.5130d552f1036p1
  },
  { // Entry 184
    0x1.2ab3189e2d4ae41c1aff3cc30cfedd30p1,
    0x1.52f00e0p793
  },
  { // Entry 185
    -0x1.2ab3189e2d4ae41c1aff3cc30cfedd30p1,
    -0x1.52f00e0p793
  },
  { // Entry 186
    -0x1.7d2e63fb988907a109091d130f9f20d1p0,
    0x1.5371684e5fb34p2
  },
  { // Entry 187
    0x1.7d2e63fb988907a109091d130f9f20d1p0,
    -0x1.5371684e5fb34p2
  },
  { // Entry 188
    -0x1.f9f4f0da4de54499283a8ac2f55f7258p-1,
    0x1.54ef2208956p239
  },
  { // Entry 189
    0x1.f9f4f0da4de54499283a8ac2f55f7258p-1,
    -0x1.54ef2208956p239
  },
  { // Entry 190
    0x1.1483073142e608008f8849daf5f8c58dp2,
    0x1.57e590af09014p0
  },
  { // Entry 191
    -0x1.1483073142e608008f8849daf5f8c58dp2,
    -0x1.57e590af09014p0
  },
  { // Entry 192
    0x1.9972d4021c971563936055d8c1eaae0ap-1,
    0x1.596p-1
  },
  { // Entry 193
    -0x1.9972d4021c971563936055d8c1eaae0ap-1,
    -0x1.596p-1
  },
  { // Entry 194
    -0x1.e501ffd3a68c38336d977f634326a342p-2,
    0x1.5981293783e1fp1
  },
  { // Entry 195
    0x1.e501ffd3a68c38336d977f634326a342p-2,
    -0x1.5981293783e1fp1
  },
  { // Entry 196
    0x1.1604cc3dfc4181c3e9481558467a85fep-1,
    0x1.5bea010p468
  },
  { // Entry 197
    -0x1.1604cc3dfc4181c3e9481558467a85fep-1,
    -0x1.5bea010p468
  },
  { // Entry 198
    -0x1.f76ca50bbbaeb012beade2a328e5fc03p-1,
    0x1.60661c1969666p2
  },
  { // Entry 199
    0x1.f76ca50bbbaeb012beade2a328e5fc03p-1,
    -0x1.60661c1969666p2
  },
  { // Entry 200
    0x1.cd8b73c9430fef75dc710ffdfe091b42p0,
    0x1.62c5a850a142ap59
  },
  { // Entry 201
    -0x1.cd8b73c9430fef75dc710ffdfe091b42p0,
    -0x1.62c5a850a142ap59
  },
  { // Entry 202
    0x1.3accfd453ee67296088378f582eacb02p0,
    0x1.64ef438p142
  },
  { // Entry 203
    -0x1.3accfd453ee67296088378f582eacb02p0,
    -0x1.64ef438p142
  },
  { // Entry 204
    -0x1.acd9302d72de4bd8dda8f5650b77e732p-1,
    0x1.658p2
  },
  { // Entry 205
    0x1.acd9302d72de4bd8dda8f5650b77e732p-1,
    -0x1.658p2
  },
  { // Entry 206
    0x1.f004f875c2e738159c7d75a3980cafd7p-1,
    0x1.6603c65d348d2p5
  },
  { // Entry 207
    -0x1.f004f875c2e738159c7d75a3980cafd7p-1,
    -0x1.6603c65d348d2p5
  },
  { // Entry 208
    0x1.f53496e6d7f7181a62fec4c8a710900ep-1,
    0x1.660e6bf2e092ap5
  },
  { // Entry 209
    -0x1.f53496e6d7f7181a62fec4c8a710900ep-1,
    -0x1.660e6bf2e092ap5
  },
  { // Entry 210
    0x1.b64ee24f0119c800d5d0bb10a39aca4ep-1,
    0x1.6a8p-1
  },
  { // Entry 211
    -0x1.b64ee24f0119c800d5d0bb10a39aca4ep-1,
    -0x1.6a8p-1
  },
  { // Entry 212
    -0x1.d9ba9a7975635a3acc324e6aeda45133p60,
    0x1.6ac5b262ca1ffp849
  },
  { // Entry 213
    0x1.d9ba9a7975635a3acc324e6aeda45133p60,
    -0x1.6ac5b262ca1ffp849
  },
  { // Entry 214
    0x1.b6f557b999e22e0db10a92b908e877f6p-1,
    0x1.6aep-1
  },
  { // Entry 215
    -0x1.b6f557b999e22e0db10a92b908e877f6p-1,
    -0x1.6aep-1
  },
  { // Entry 216
    0x1.c1e1d5c4c0f077fc871d4bd0a03c6431p-1,
    0x1.6cdb36cdb36c9p239
  },
  { // Entry 217
    -0x1.c1e1d5c4c0f077fc871d4bd0a03c6431p-1,
    -0x1.6cdb36cdb36c9p239
  },
  { // Entry 218
    0x1.95bce4f5786978078c310210dced6f3fp-1,
    0x1.6f1af1612270ap6
  },
  { // Entry 219
    -0x1.95bce4f5786978078c310210dced6f3fp-1,
    -0x1.6f1af1612270ap6
  },
  { // Entry 220
    0x1.711e8f5fffba1f599595fbaac5b70e0bp-4,
    0x1.702p-4
  },
  { // Entry 221
    -0x1.711e8f5fffba1f599595fbaac5b70e0bp-4,
    -0x1.702p-4
  },
  { // Entry 222
    0x1.fb5898f29bb257fda6f2bedfc491abaep2,
    0x1.720p0
  },
  { // Entry 223
    -0x1.fb5898f29bb257fda6f2bedfc491abaep2,
    -0x1.720p0
  },
  { // Entry 224
    -0x1.ff9b771284d23290cdd83717cc905773p1,
    0x1.7348c347ddc20p239
  },
  { // Entry 225
    0x1.ff9b771284d23290cdd83717cc905773p1,
    -0x1.7348c347ddc20p239
  },
  { // Entry 226
    0x1.f72d47a0080e2d3d040863d56dbb567ep-2,
    0x1.739ce739ce738p100
  },
  { // Entry 227
    -0x1.f72d47a0080e2d3d040863d56dbb567ep-2,
    -0x1.739ce739ce738p100
  },
  { // Entry 228
    0x1.76441e7f8ea5f8000001d1c5c84f104ep-4,
    0x1.753acc3d3ff35p-4
  },
  { // Entry 229
    -0x1.76441e7f8ea5f8000001d1c5c84f104ep-4,
    -0x1.753acc3d3ff35p-4
  },
  { // Entry 230
    0x1.ce3f642e15af3c921dd7129db5e39342p-1,
    0x1.77fffffffffffp-1
  },
  { // Entry 231
    -0x1.ce3f642e15af3c921dd7129db5e39342p-1,
    -0x1.77fffffffffffp-1
  },
  { // Entry 232
    0x1.f425002a548eb405450970a353d307f7p42,
    0x1.78fdb9effea26p4
  },
  { // Entry 233
    -0x1.f425002a548eb405450970a353d307f7p42,
    -0x1.78fdb9effea26p4
  },
  { // Entry 234
    -0x1.dbc80de7dd042a9371e1b45718e51babp-1,
    0x1.7a5f74607e851p19
  },
  { // Entry 235
    0x1.dbc80de7dd042a9371e1b45718e51babp-1,
    -0x1.7a5f74607e851p19
  },
  { // Entry 236
    0x1.7b3bb3d0b3ca42f13207842899e0ba71p42,
    0x1.7f7ef77e83f1ap19
  },
  { // Entry 237
    -0x1.7b3bb3d0b3ca42f13207842899e0ba71p42,
    -0x1.7f7ef77e83f1ap19
  },
  { // Entry 238
    0x1.e7f05b71cd2d0fb4df6a43375cd8f670p33,
    0x1.7f7f10a07f45ep20
  },
  { // Entry 239
    -0x1.e7f05b71cd2d0fb4df6a43375cd8f670p33,
    -0x1.7f7f10a07f45ep20
  },
  { // Entry 240
    0x1.80000000000038000000000007333333p-25,
    0x1.7ffffffffffffp-25
  },
  { // Entry 241
    -0x1.80000000000038000000000007333333p-25,
    -0x1.7ffffffffffffp-25
  },
  { // Entry 242
    0x1.80000000000068000000000022333333p-25,
    0x1.8000000000002p-25
  },
  { // Entry 243
    -0x1.80000000000068000000000022333333p-25,
    -0x1.8000000000002p-25
  },
  { // Entry 244
    0x1.24245af4cd994e9b3bba992d1016365bp-52,
    0x1.81ae0dffa3b33p959
  },
  { // Entry 245
    -0x1.24245af4cd994e9b3bba992d1016365bp-52,
    -0x1.81ae0dffa3b33p959
  },
  { // Entry 246
    0x1.d72261d98e26b7ffa300d89fd46fb775p-1,
    0x1.846bd7a4dce55p698
  },
  { // Entry 247
    -0x1.d72261d98e26b7ffa300d89fd46fb775p-1,
    -0x1.846bd7a4dce55p698
  },
  { // Entry 248
    0x1.42d8a1ba441ad4028ac7f1a6a5ee0c54p1,
    0x1.8720588p392
  },
  { // Entry 249
    -0x1.42d8a1ba441ad4028ac7f1a6a5ee0c54p1,
    -0x1.8720588p392
  },
  { // Entry 250
    0x1.ea7b444cd798d7faeeff093f1d9971adp-1,
    0x1.8722a67ea14acp-1
  },
  { // Entry 251
    -0x1.ea7b444cd798d7faeeff093f1d9971adp-1,
    -0x1.8722a67ea14acp-1
  },
  { // Entry 252
    -0x1.c7dc7f08dbba089f2d7e890021bedcb7p-1,
    0x1.89936c8828d38p299
  },
  { // Entry 253
    0x1.c7dc7f08dbba089f2d7e890021bedcb7p-1,
    -0x1.89936c8828d38p299
  },
  { // Entry 254
    0x1.569653e319bba800000c83632e43abdep1,
    0x1.8a69106fb9798p6
  },
  { // Entry 255
    -0x1.569653e319bba800000c83632e43abdep1,
    -0x1.8a69106fb9798p6
  },
  { // Entry 256
    0x1.f2db21469f3d5819fa9ba8dccbff914ap-1,
    0x1.8b777e1d2308cp-1
  },
  { // Entry 257
    -0x1.f2db21469f3d5819fa9ba8dccbff914ap-1,
    -0x1.8b777e1d2308cp-1
  },
  { // Entry 258
    0x1.f3688bc2594e20102573cff48190ac28p-1,
    0x1.8bcp-1
  },
  { // Entry 259
    -0x1.f3688bc2594e20102573cff48190ac28p-1,
    -0x1.8bcp-1
  },
  { // Entry 260
    0x1.8d3a2544566df7b559b4ac48e12eac71p-4,
    0x1.8bfd2274d851ap-4
  },
  { // Entry 261
    -0x1.8d3a2544566df7b559b4ac48e12eac71p-4,
    -0x1.8bfd2274d851ap-4
  },
  { // Entry 262
    0x1.f4575cc4e477f019dab5d0103aaf91cfp-1,
    0x1.8c3a450071dd9p-1
  },
  { // Entry 263
    -0x1.f4575cc4e477f019dab5d0103aaf91cfp-1,
    -0x1.8c3a450071dd9p-1
  },
  { // Entry 264
    -0x1.1e09f66c4250b94e9030cadd00851158p11,
    0x1.8cc0dd2b0f4b8p200
  },
  { // Entry 265
    0x1.1e09f66c4250b94e9030cadd00851158p11,
    -0x1.8cc0dd2b0f4b8p200
  },
  { // Entry 266
    0x1.f71496cb921e5a4d2f39046a628b6509p-1,
    0x1.8dap-1
  },
  { // Entry 267
    -0x1.f71496cb921e5a4d2f39046a628b6509p-1,
    -0x1.8dap-1
  },
  { // Entry 268
    0x1.f71b4a6591169819476e6b759c7aae52p-1,
    0x1.8da368da368d8p-1
  },
  { // Entry 269
    -0x1.f71b4a6591169819476e6b759c7aae52p-1,
    -0x1.8da368da368d8p-1
  },
  { // Entry 270
    0x1.ff9b68ccadb2ff62c26864288ed6a4dfp-1,
    0x1.91ed64b977a9ap-1
  },
  { // Entry 271
    -0x1.ff9b68ccadb2ff62c26864288ed6a4dfp-1,
    -0x1.91ed64b977a9ap-1
  },
  { // Entry 272
    0x1.00000000290484779fa491c728aef945p18,
    0x1.921f754442d19p0
  },
  { // Entry 273
    -0x1.00000000290484779fa491c728aef945p18,
    -0x1.921f754442d19p0
  },
  { // Entry 274
    0x1.eef067afd328f311ce2c7a1f420a5983p48,
    0x1.921fb54442d10p0
  },
  { // Entry 275
    -0x1.eef067afd328f311ce2c7a1f420a5983p48,
    -0x1.921fb54442d10p0
  },
  { // Entry 276
    0x1.0000000003af2f223eb1e709cba00ec3p-17,
    0x1.921ff54442d18p1
  },
  { // Entry 277
    -0x1.0000000003af2f223eb1e709cba00ec3p-17,
    -0x1.921ff54442d18p1
  },
  { // Entry 278
    -0x1.b6772cb667dc187b7d019d1d7232c9e7p17,
    0x1.922p0
  },
  { // Entry 279
    0x1.b6772cb667dc187b7d019d1d7232c9e7p17,
    -0x1.922p0
  },
  { // Entry 280
    -0x1.fffffffceeefe791be2074779fd1dd9ep-1,
    0x1.922071c31fc99p20
  },
  { // Entry 281
    0x1.fffffffceeefe791be2074779fd1dd9ep-1,
    -0x1.922071c31fc99p20
  },
  { // Entry 282
    0x1.9d7c1354ba6f781c8b04408094f45284p-3,
    0x1.97fffffffffffp-3
  },
  { // Entry 283
    -0x1.9d7c1354ba6f781c8b04408094f45284p-3,
    -0x1.97fffffffffffp-3
  },
  { // Entry 284
    0x1.9af8877bb45e47ffffe961084b2c0beap-4,
    0x1.999999a10a13cp-4
  },
  { // Entry 285
    -0x1.9af8877bb45e47ffffe961084b2c0beap-4,
    -0x1.999999a10a13cp-4
  },
  { // Entry 286
    -0x1.b6ce128587cd07ffff757abda294c151p4,
    0x1.9b74446ed05dcp0
  },
  { // Entry 287
    0x1.b6ce128587cd07ffff757abda294c151p4,
    -0x1.9b74446ed05dcp0
  },
  { // Entry 288
    0x1.ff65aef54c8fc8042841071b45b6d7d9p-1,
    0x1.9eae494d2b275p4
  },
  { // Entry 289
    -0x1.ff65aef54c8fc8042841071b45b6d7d9p-1,
    -0x1.9eae494d2b275p4
  },
  { // Entry 290
    0x1.61776aa407a437f617fcadb15c7f61c2p-3,
    0x1.a80p1
  },
  { // Entry 291
    -0x1.61776aa407a437f617fcadb15c7f61c2p-3,
    -0x1.a80p1
  },
  { // Entry 292
    0x1.b6001de13ad9580073acba4aa423e2d9p-3,
    0x1.af8p-3
  },
  { // Entry 293
    -0x1.b6001de13ad9580073acba4aa423e2d9p-3,
    -0x1.af8p-3
  },
  { // Entry 294
    0x1.b5a0503ae354b7a16f7c50f8b3bef2cap-4,
    0x1.b3f8ea7b1f91bp-4
  },
  { // Entry 295
    -0x1.b5a0503ae354b7a16f7c50f8b3bef2cap-4,
    -0x1.b3f8ea7b1f91bp-4
  },
  { // Entry 296
    0x1.b5a0503ae4c7b792537327f4245ac6fbp-4,
    0x1.b3f8ea7b21008p-4
  },
  { // Entry 297
    -0x1.b5a0503ae4c7b792537327f4245ac6fbp-4,
    -0x1.b3f8ea7b21008p-4
  },
  { // Entry 298
    0x1.057584c429b3a6ea0a65caff98634490p59,
    0x1.b951f1572eba5p23
  },
  { // Entry 299
    -0x1.057584c429b3a6ea0a65caff98634490p59,
    -0x1.b951f1572eba5p23
  },
  { // Entry 300
    -0x1.9a282fa1ff7d98039be3bf5b39cc6d89p2,
    0x1.b9cp0
  },
  { // Entry 301
    0x1.9a282fa1ff7d98039be3bf5b39cc6d89p2,
    -0x1.b9cp0
  },
  { // Entry 302
    -0x1.027d184afb1984ca1d21b1ac93111887p-52,
    0x1.bab62ed655019p970
  },
  { // Entry 303
    0x1.027d184afb1984ca1d21b1ac93111887p-52,
    -0x1.bab62ed655019p970
  },
  { // Entry 304
    0x1.ca6efdf845d6c7fffebaea1afbf7e961p2,
    0x1.bea1b35f3cb6dp84
  },
  { // Entry 305
    -0x1.ca6efdf845d6c7fffebaea1afbf7e961p2,
    -0x1.bea1b35f3cb6dp84
  },
  { // Entry 306
    0x1.fd87b34747b746b8b657cac797c0870dp42,
    0x1.c463abeccb27bp3
  },
  { // Entry 307
    -0x1.fd87b34747b746b8b657cac797c0870dp42,
    -0x1.c463abeccb27bp3
  },
  { // Entry 308
    0x1.ffffffffffffb094541a2461e734daeep-1,
    0x1.c463abeccb2bbp2
  },
  { // Entry 309
    -0x1.ffffffffffffb094541a2461e734daeep-1,
    -0x1.c463abeccb2bbp2
  },
  { // Entry 310
    0x1.fb057029acfd17fffffa5ac8204f0803p-1,
    0x1.c6cbe26b7b45fp86
  },
  { // Entry 311
    -0x1.fb057029acfd17fffffa5ac8204f0803p-1,
    -0x1.c6cbe26b7b45fp86
  },
  { // Entry 312
    0x1.c8d5a08be40c20p-117,
    0x1.c8d5a08be40c2p-117
  },
  { // Entry 313
    -0x1.c8d5a08be40c20p-117,
    -0x1.c8d5a08be40c2p-117
  },
  { // Entry 314
    0x1.e5dffd7f06cb3754933cea578deaad36p-2,
    0x1.cad4e9827a2bep1
  },
  { // Entry 315
    -0x1.e5dffd7f06cb3754933cea578deaad36p-2,
    -0x1.cad4e9827a2bep1
  },
  { // Entry 316
    0x1.e6be378b1b4eb7658e85ad0af33836a9p-2,
    0x1.caeb940e4b997p1
  },
  { // Entry 317
    -0x1.e6be378b1b4eb7658e85ad0af33836a9p-2,
    -0x1.caeb940e4b997p1
  },
  { // Entry 318
    0x1.e72bd025a1fd5765f853469a85ae7b7dp-2,
    0x1.caf6c04ecd034p1
  },
  { // Entry 319
    -0x1.e72bd025a1fd5765f853469a85ae7b7dp-2,
    -0x1.caf6c04ecd034p1
  },
  { // Entry 320
    0x1.e844b3d7cbe4375c28e322da6ba5d7d8p-2,
    0x1.cb135ec1c956ep1
  },
  { // Entry 321
    -0x1.e844b3d7cbe4375c28e322da6ba5d7d8p-2,
    -0x1.cb135ec1c956ep1
  },
  { // Entry 322
    0x1.dd38a1f1d289b6173115721bc5c1fc72p-54,
    0x1.cb44e86bc192bp648
  },
  { // Entry 323
    -0x1.dd38a1f1d289b6173115721bc5c1fc72p-54,
    -0x1.cb44e86bc192bp648
  },
  { // Entry 324
    0x1.dd38a1f1d289b6173115721bc629a23dp-53,
    0x1.cb44e86bc192bp649
  },
  { // Entry 325
    -0x1.dd38a1f1d289b6173115721bc629a23dp-53,
    -0x1.cb44e86bc192bp649
  },
  { // Entry 326
    -0x1.fff6e755320ed78db4d6eff4bf6a6b10p1,
    0x1.cb61afedb2b3cp119
  },
  { // Entry 327
    0x1.fff6e755320ed78db4d6eff4bf6a6b10p1,
    -0x1.cb61afedb2b3cp119
  },
  { // Entry 328
    0x1.ccdf4aa6c228f8041be91a142e0e271bp-7,
    0x1.ccd7834ba3804p-7
  },
  { // Entry 329
    -0x1.ccdf4aa6c228f8041be91a142e0e271bp-7,
    -0x1.ccd7834ba3804p-7
  },
  { // Entry 330
    0x1.cee50016fc2d8837286bf6fd431a7b3bp-4,
    0x1.ccf0599da478ep-4
  },
  { // Entry 331
    -0x1.cee50016fc2d8837286bf6fd431a7b3bp-4,
    -0x1.ccf0599da478ep-4
  },
  { // Entry 332
    0x1.44cf3ee8a75a87cc6657e62f94a93e6fp0,
    0x1.ce8p-1
  },
  { // Entry 333
    -0x1.44cf3ee8a75a87cc6657e62f94a93e6fp0,
    -0x1.ce8p-1
  },
  { // Entry 334
    0x1.45aa12ff98152800001fbd8799a96a2cp0,
    0x1.cf276c9cb9af0p-1
  },
  { // Entry 335
    -0x1.45aa12ff98152800001fbd8799a96a2cp0,
    -0x1.cf276c9cb9af0p-1
  },
  { // Entry 336
    0x1.f9bc744f61e0ed853829e2f765b8a12cp-4,
    0x1.d2e979148a458p61
  },
  { // Entry 337
    -0x1.f9bc744f61e0ed853829e2f765b8a12cp-4,
    -0x1.d2e979148a458p61
  },
  { // Entry 338
    0x1.6e70f9edbd1a082ae6f90c62ef4f31ddp-2,
    0x1.d6b5ad6b5ab68p100
  },
  { // Entry 339
    -0x1.6e70f9edbd1a082ae6f90c62ef4f31ddp-2,
    -0x1.d6b5ad6b5ab68p100
  },
  { // Entry 340
    0x1.13e9c6a348e4a7bede82724505269f68p2,
    0x1.d96e058p488
  },
  { // Entry 341
    -0x1.13e9c6a348e4a7bede82724505269f68p2,
    -0x1.d96e058p488
  },
  { // Entry 342
    -0x1.d355463c2303582fa31a3238dcbe560ep-5,
    0x1.dd10f25171bc9p5
  },
  { // Entry 343
    0x1.d355463c2303582fa31a3238dcbe560ep-5,
    -0x1.dd10f25171bc9p5
  },
  { // Entry 344
    0x1.ddf21ebf6fc927fffffbb3ecc0cff66ep-6,
    0x1.ddcf6e56696a4p-6
  },
  { // Entry 345
    -0x1.ddf21ebf6fc927fffffbb3ecc0cff66ep-6,
    -0x1.ddcf6e56696a4p-6
  },
  { // Entry 346
    0x1.5cb0bfc1558007e0c5d095f729e3427bp0,
    0x1.ep-1
  },
  { // Entry 347
    -0x1.5cb0bfc1558007e0c5d095f729e3427bp0,
    -0x1.ep-1
  },
  { // Entry 348
    -0x1.97b5e8ae9a21c7f4821922bc5b3782ccp1,
    0x1.ep0
  },
  { // Entry 349
    0x1.97b5e8ae9a21c7f4821922bc5b3782ccp1,
    -0x1.ep0
  },
  { // Entry 350
    -0x1.f8bf68d0c23f3741efb8bd99853bae8ap0,
    0x1.e779de779de71p118
  },
  { // Entry 351
    0x1.f8bf68d0c23f3741efb8bd99853bae8ap0,
    -0x1.e779de779de71p118
  },
  { // Entry 352
    -0x1.fffffffffd71cf934ef3e5df4008665fp-1,
    0x1.eb0567bed1f71p12
  },
  { // Entry 353
    0x1.fffffffffd71cf934ef3e5df4008665fp-1,
    -0x1.eb0567bed1f71p12
  },
  { // Entry 354
    0x1.ee788d1cc7954841878473aa5d2615a5p-4,
    0x1.ec16f30a34fbcp-4
  },
  { // Entry 355
    -0x1.ee788d1cc7954841878473aa5d2615a5p-4,
    -0x1.ec16f30a34fbcp-4
  },
  { // Entry 356
    0x1.efdad938b4b0e834014bf56a7084675dp-4,
    0x1.ed7424ba2aa4ep-4
  },
  { // Entry 357
    -
"""


```
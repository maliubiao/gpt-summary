Response:
The user wants to understand the purpose of the provided C code snippet, which is a data file for the `asin` function in Android's bionic library.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name `asin_intel_data.handroid` and the variable name `g_asin_intel_data` strongly suggest this is data used for testing or implementation of the `asin` (arcsine) function. The "intel_data" part might indicate it's specific to Intel architectures, or perhaps a set of standard data. The `.handroid` extension is less common but likely denotes a specific format used within Android's build system or testing framework.

2. **Analyze the data structure:** The code defines a static array `g_asin_intel_data` of type `data_1_1_t<double, double>`. This means each element in the array is a structure (or a template instantiation) containing two `double` values. Looking at the data, the first `double` in each pair seems to be an input value, and the second `double` appears to be the corresponding output of the `asin` function. The hexadecimal representation with `p` indicates floating-point numbers in base-2 exponential notation.

3. **Relate to `asin` function:** The `asin` function calculates the arcsine of a given number. Knowing this, the data represents test cases: specific input values for `asin` and their expected results. This is crucial for verifying the correctness of the `asin` implementation.

4. **Connect to Android:**  Since the file is located within the bionic library (Android's C library), it directly relates to the core functionality of Android. The `asin` function is a standard math function available to Android applications and system components.

5. **Explain the "why":**  Why have this data file?  The most important reason is for testing the `asin` implementation. It provides a set of known good inputs and outputs to ensure the function works accurately across different input ranges. The "intel_data" part might suggest it was specifically designed or chosen to test edge cases or performance on Intel processors.

6. **Address the request for "归纳一下它的功能" (summarize its function):**  The primary function is to provide test data for the `asin` function in Android's bionic library.

7. **Structure the answer:**  Organize the information logically with clear headings. Start with the most basic identification and then elaborate on the purpose and relationship to Android. Use bullet points or numbered lists for clarity. Explain the data format to provide a deeper understanding.

8. **Refine the language:** Use clear and concise Chinese. Explain technical terms like "arcsine" and "test data" in a way that is easy to understand.

Essentially, the process is: **Identify -> Analyze -> Relate -> Explain -> Summarize -> Structure -> Refine**. The key insight is recognizing the data as input/output pairs for the `asin` function, which then allows connecting it to the broader context of bionic and Android's math library.
这是目录为 `bionic/tests/math_data/asin_intel_data.handroid` 的源代码文件的第一部分。这个文件是 Android Bionic 库的一部分，Bionic 是 Android 的 C 库、数学库和动态链接器。

**归纳一下它的功能:**

这个文件的主要功能是**为 `asin` (反正弦) 数学函数提供测试数据**。

具体来说：

* **存储了大量的输入-输出对:**  文件中定义了一个名为 `g_asin_intel_data` 的静态数组，数组的元素类型是 `data_1_1_t<double, double>`。这意味着数组中的每个元素都包含两个 `double` 类型的浮点数。
* **用于验证 `asin` 函数的正确性:**  这些数据对被用来测试 Android Bionic 库中 `asin` 函数的实现是否正确。第一个 `double` 值是 `asin` 函数的输入，第二个 `double` 值是该输入对应的预期输出结果。
* **可能针对特定架构优化或测试:** 文件名中的 "intel_data" 可能暗示这些数据是特别为 Intel 架构的处理器或者为了测试在 Intel 架构上的特定行为而设计的。

**简单来说，这个文件就是一个包含许多预先计算好的反正弦函数输入和预期输出的数据集，用于自动化测试和验证 Android 系统中 `asin` 函数的实现是否准确无误。**

在接下来的部分，我们将详细展开讨论你提出的其他问题。

### 提示词
```
这是目录为bionic/tests/math_data/asin_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_asin_intel_data[] = {
  { // Entry 0
    0x1.9283586503fe000000000000000e46aap-5,
    0x1.9259e3708bd3ap-5
  },
  { // Entry 1
    -0x1.9283586503fe000000000000000e46aap-5,
    -0x1.9259e3708bd3ap-5
  },
  { // Entry 2
    0x1.d7bdcd778049f00000000000000d57e1p-5,
    0x1.d77b117f230d6p-5
  },
  { // Entry 3
    -0x1.d7bdcd778049f00000000000000d57e1p-5,
    -0x1.d77b117f230d6p-5
  },
  { // Entry 4
    0x1.a202b3fb84788000000000000056edb7p-4,
    0x1.a1490c8c06ba7p-4
  },
  { // Entry 5
    -0x1.a202b3fb84788000000000000056edb7p-4,
    -0x1.a1490c8c06ba7p-4
  },
  { // Entry 6
    0x1.994ffb5daf0f97ffffffffffffa81adap-3,
    0x1.9697cb602c582p-3
  },
  { // Entry 7
    -0x1.994ffb5daf0f97ffffffffffffa81adap-3,
    -0x1.9697cb602c582p-3
  },
  { // Entry 8
    0x1.d5064e6fe82c4fffffffffffff9ed184p-3,
    0x1.d0ef799001ba9p-3
  },
  { // Entry 9
    -0x1.d5064e6fe82c4fffffffffffff9ed184p-3,
    -0x1.d0ef799001ba9p-3
  },
  { // Entry 10
    0x1.fe767739d0f6d0000000000000000458p-2,
    0x1.e9950730c4696p-2
  },
  { // Entry 11
    -0x1.fe767739d0f6d0000000000000000458p-2,
    -0x1.e9950730c4696p-2
  },
  { // Entry 12
    0x1.30706f699466d7ffffffffffff5f2011p-1,
    0x1.1ed06d50f7e88p-1
  },
  { // Entry 13
    -0x1.30706f699466d7ffffffffffff5f2011p-1,
    -0x1.1ed06d50f7e88p-1
  },
  { // Entry 14
    0x1.29517ab4c132a800000000000089db56p0,
    0x1.d5b05a89d3e77p-1
  },
  { // Entry 15
    -0x1.29517ab4c132a800000000000089db56p0,
    -0x1.d5b05a89d3e77p-1
  },
  { // Entry 16
    0x1.3aa301f6ebb1dfffffffffffff16c28cp0,
    0x1.e264357ea0e29p-1
  },
  { // Entry 17
    -0x1.3aa301f6ebb1dfffffffffffff16c28cp0,
    -0x1.e264357ea0e29p-1
  },
  { // Entry 18
    -0x1.0c152382d73658465bb32e0f567ad116p-1,
    -0x1.0p-1
  },
  { // Entry 19
    0x1.0c152382d73658465bb32e0f567ad116p-1,
    0x1.0p-1
  },
  { // Entry 20
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 21
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 22
    -0x1.0000000000001002aaaaaaaaaaab2abdp-30,
    -0x1.0000000000001p-30
  },
  { // Entry 23
    0x1.0000000000001002aaaaaaaaaaab2abdp-30,
    0x1.0000000000001p-30
  },
  { // Entry 24
    -0x1.1fc5e19315892ffd69defb731e5b723ap-2,
    -0x1.1c0p-2
  },
  { // Entry 25
    0x1.1fc5e19315892ffd69defb731e5b723ap-2,
    0x1.1c0p-2
  },
  { // Entry 26
    -0x1.322f6d8e910113592ff4014f403aad06p-1,
    -0x1.20424621202acp-1
  },
  { // Entry 27
    0x1.322f6d8e910113592ff4014f403aad06p-1,
    0x1.20424621202acp-1
  },
  { // Entry 28
    -0x1.57c8d32d4c7a763ab677a006ae66467fp-1,
    -0x1.3e872c7cba096p-1
  },
  { // Entry 29
    0x1.57c8d32d4c7a763ab677a006ae66467fp-1,
    0x1.3e872c7cba096p-1
  },
  { // Entry 30
    -0x1.759edd04f68e48001bb07775889fc8a5p-1,
    -0x1.555555555555ap-1
  },
  { // Entry 31
    0x1.759edd04f68e48001bb07775889fc8a5p-1,
    0x1.555555555555ap-1
  },
  { // Entry 32
    -0x1.782333f928813ffec11dba3a89d05c6cp-1,
    -0x1.573489b9ae5adp-1
  },
  { // Entry 33
    0x1.782333f928813ffec11dba3a89d05c6cp-1,
    0x1.573489b9ae5adp-1
  },
  { // Entry 34
    -0x1.94d8b4c7808fb7a87e757b5f42035aacp-1,
    -0x1.6bf5707aa0f6bp-1
  },
  { // Entry 35
    0x1.94d8b4c7808fb7a87e757b5f42035aacp-1,
    0x1.6bf5707aa0f6bp-1
  },
  { // Entry 36
    -0x1.b235315cc8d0081c027b42e63e305a66p-1,
    -0x1.800000004p-1
  },
  { // Entry 37
    0x1.b235315cc8d0081c027b42e63e305a66p-1,
    0x1.800000004p-1
  },
  { // Entry 38
    -0x1.96b6e8a201871000f870b24841c05f73p-4,
    -0x1.960be5db7a892p-4
  },
  { // Entry 39
    0x1.96b6e8a201871000f870b24841c05f73p-4,
    0x1.960be5db7a892p-4
  },
  { // Entry 40
    -0x1.98ad7f9954c2c000dda10069f24bfb9fp-4,
    -0x1.980p-4
  },
  { // Entry 41
    0x1.98ad7f9954c2c000dda10069f24bfb9fp-4,
    0x1.980p-4
  },
  { // Entry 42
    -0x1.aa371ee73bd1c8079ffffa36ba5e5d8cp-2,
    -0x1.9e03d2f534734p-2
  },
  { // Entry 43
    0x1.aa371ee73bd1c8079ffffa36ba5e5d8cp-2,
    0x1.9e03d2f534734p-2
  },
  { // Entry 44
    -0x1.ed27cb01adedd7ae3d6cfc08b5b1ca73p-1,
    -0x1.a45ca57a33fcdp-1
  },
  { // Entry 45
    0x1.ed27cb01adedd7ae3d6cfc08b5b1ca73p-1,
    0x1.a45ca57a33fcdp-1
  },
  { // Entry 46
    -0x1.b34d1c29d5ccbffecdc2bdebc095bf13p-6,
    -0x1.b34p-6
  },
  { // Entry 47
    0x1.b34d1c29d5ccbffecdc2bdebc095bf13p-6,
    0x1.b34p-6
  },
  { // Entry 48
    -0x1.bf79714a2c1567fffff9585f49069adbp-15,
    -0x1.bf7971469ca1fp-15
  },
  { // Entry 49
    0x1.bf79714a2c1567fffff9585f49069adbp-15,
    0x1.bf7971469ca1fp-15
  },
  { // Entry 50
    -0x1.bf79714a2c19b8000013b283b77d9f82p-15,
    -0x1.bf7971469ca64p-15
  },
  { // Entry 51
    0x1.bf79714a2c19b8000013b283b77d9f82p-15,
    0x1.bf7971469ca64p-15
  },
  { // Entry 52
    -0x1.cfaf2746103107617c4b6b2c15223d0dp-2,
    -0x1.c0000000003ffp-2
  },
  { // Entry 53
    0x1.cfaf2746103107617c4b6b2c15223d0dp-2,
    0x1.c0000000003ffp-2
  },
  { // Entry 54
    -0x1.0129be4949aae7feec564fbe5489c78ep-1,
    -0x1.ecf8cad745f54p-2
  },
  { // Entry 55
    0x1.0129be4949aae7feec564fbe5489c78ep-1,
    0x1.ecf8cad745f54p-2
  },
  { // Entry 56
    -0x1.5047d77b0f8938000011f5af41f72c88p0,
    -0x1.ef28841197292p-1
  },
  { // Entry 57
    0x1.5047d77b0f8938000011f5af41f72c88p0,
    0x1.ef28841197292p-1
  },
  { // Entry 58
    -0x1.fb9f1177a8157880070f3ad2a1f9422ep-6,
    -0x1.fb8a474fa66d0p-6
  },
  { // Entry 59
    0x1.fb9f1177a8157880070f3ad2a1f9422ep-6,
    0x1.fb8a474fa66d0p-6
  },
  { // Entry 60
    -0x1.7b9033edad533793d172bb5d680b97b4p0,
    -0x1.fe0359a2193f8p-1
  },
  { // Entry 61
    0x1.7b9033edad533793d172bb5d680b97b4p0,
    0x1.fe0359a2193f8p-1
  },
  { // Entry 62
    -0x1.7b9033f17fe8b7728028f04d5b42dfa4p0,
    -0x1.fe0359a2c5813p-1
  },
  { // Entry 63
    0x1.7b9033f17fe8b7728028f04d5b42dfa4p0,
    0x1.fe0359a2c5813p-1
  },
  { // Entry 64
    -0x1.7da665f5fe592780850c1bef60fac479p0,
    -0x1.fe5d0b4f2f569p-1
  },
  { // Entry 65
    0x1.7da665f5fe592780850c1bef60fac479p0,
    0x1.fe5d0b4f2f569p-1
  },
  { // Entry 66
    -0x1.ff348201393248a795686f3f0d307c5ap-6,
    -0x1.ff1f4655459b6p-6
  },
  { // Entry 67
    0x1.ff348201393248a795686f3f0d307c5ap-6,
    0x1.ff1f4655459b6p-6
  },
  { // Entry 68
    0x1.0000000000001002aaaaaaaaaaab2abdp-30,
    0x1.0000000000001p-30
  },
  { // Entry 69
    -0x1.0000000000001002aaaaaaaaaaab2abdp-30,
    -0x1.0000000000001p-30
  },
  { // Entry 70
    0x1.0c152382d736d999ee9a1f752604d40ep-1,
    0x1.0000000000007p-1
  },
  { // Entry 71
    -0x1.0c152382d736d999ee9a1f752604d40ep-1,
    -0x1.0000000000007p-1
  },
  { // Entry 72
    0x1.0c152382d7495341342a52c5694cd736p-1,
    0x1.0000000000107p-1
  },
  { // Entry 73
    -0x1.0c152382d7495341342a52c5694cd736p-1,
    -0x1.0000000000107p-1
  },
  { // Entry 74
    0x1.0c152382d74c92a39b64abd4b3dd08c3p-1,
    0x1.0000000000134p-1
  },
  { // Entry 75
    -0x1.0c152382d74c92a39b64abd4b3dd08c3p-1,
    -0x1.0000000000134p-1
  },
  { // Entry 76
    0x1.000aabde0bba85978d6ad9f48828ec86p-5,
    0x1.00000000001e0p-5
  },
  { // Entry 77
    -0x1.000aabde0bba85978d6ad9f48828ec86p-5,
    -0x1.00000000001e0p-5
  },
  { // Entry 78
    0x1.000aabde0bbc75d5990d467c55b9ae34p-5,
    0x1.00000000001ffp-5
  },
  { // Entry 79
    -0x1.000aabde0bbc75d5990d467c55b9ae34p-5,
    -0x1.00000000001ffp-5
  },
  { // Entry 80
    0x1.000aabde0c8daffe80d2e7d3e14097d7p-5,
    0x1.0000000000f11p-5
  },
  { // Entry 81
    -0x1.000aabde0c8daffe80d2e7d3e14097d7p-5,
    -0x1.0000000000f11p-5
  },
  { // Entry 82
    0x1.02be9ce0ba0b280001c151672b571466p-2,
    0x1.000000000181bp-2
  },
  { // Entry 83
    -0x1.02be9ce0ba0b280001c151672b571466p-2,
    -0x1.000000000181bp-2
  },
  { // Entry 84
    0x1.0c152382de23f70071cd464afd26d0adp-1,
    0x1.00000000060p-1
  },
  { // Entry 85
    -0x1.0c152382de23f70071cd464afd26d0adp-1,
    -0x1.00000000060p-1
  },
  { // Entry 86
    0x1.0c152382f2ecd32eb46eb26eaa3a3436p-1,
    0x1.00000000180p-1
  },
  { // Entry 87
    -0x1.0c152382f2ecd32eb46eb26eaa3a3436p-1,
    -0x1.00000000180p-1
  },
  { // Entry 88
    0x1.0c1523836b039272e99d2aa6c733fbd4p-1,
    0x1.000000008p-1
  },
  { // Entry 89
    -0x1.0c1523836b039272e99d2aa6c733fbd4p-1,
    -0x1.000000008p-1
  },
  { // Entry 90
    0x1.0c15258825828aed7433be734fa034e0p-1,
    0x1.000001cp-1
  },
  { // Entry 91
    -0x1.0c15258825828aed7433be734fa034e0p-1,
    -0x1.000001cp-1
  },
  { // Entry 92
    0x1.0c15258d2e27e114dc33e19be219a967p-1,
    0x1.000001c45c0p-1
  },
  { // Entry 93
    -0x1.0c15258d2e27e114dc33e19be219a967p-1,
    -0x1.000001c45c0p-1
  },
  { // Entry 94
    0x1.02c23a43a81227fff55e30293b8669cfp-2,
    0x1.00038p-2
  },
  { // Entry 95
    -0x1.02c23a43a81227fff55e30293b8669cfp-2,
    -0x1.00038p-2
  },
  { // Entry 96
    0x1.0032c1ec76116800257dc6de53c0616ep-4,
    0x1.0007fffffffd1p-4
  },
  { // Entry 97
    -0x1.0032c1ec76116800257dc6de53c0616ep-4,
    -0x1.0007fffffffd1p-4
  },
  { // Entry 98
    0x1.0c279d5b633cdc69f2775e85622dc4a2p-1,
    0x1.001p-1
  },
  { // Entry 99
    -0x1.0c279d5b633cdc69f2775e85622dc4a2p-1,
    -0x1.001p-1
  },
  { // Entry 100
    0x1.0c4c923447087dae5cae7c825ed2a0ccp-1,
    0x1.003p-1
  },
  { // Entry 101
    -0x1.0c4c923447087dae5cae7c825ed2a0ccp-1,
    -0x1.003p-1
  },
  { // Entry 102
    0x1.0c55cfa828c0b38becd1409b658d6950p-1,
    0x1.00380p-1
  },
  { // Entry 103
    -0x1.0c55cfa828c0b38becd1409b658d6950p-1,
    -0x1.00380p-1
  },
  { // Entry 104
    0x1.0062da048ea0d7efd536d5c643e9f215p-4,
    0x1.00380p-4
  },
  { // Entry 105
    -0x1.0062da048ea0d7efd536d5c643e9f215p-4,
    -0x1.00380p-4
  },
  { // Entry 106
    0x1.00402aaac5e698004c94e39262202714p-8,
    0x1.003fffep-8
  },
  { // Entry 107
    -0x1.00402aaac5e698004c94e39262202714p-8,
    -0x1.003fffep-8
  },
  { // Entry 108
    0x1.0c9720590ac37fd593221825ec3a084bp-1,
    0x1.00708a54b2c67p-1
  },
  { // Entry 109
    -0x1.0c9720590ac37fd593221825ec3a084bp-1,
    -0x1.00708a54b2c67p-1
  },
  { // Entry 110
    0x1.00c00000000000000000000ac2bcaf2ap-45,
    0x1.00cp-45
  },
  { // Entry 111
    -0x1.00c00000000000000000000ac2bcaf2ap-45,
    -0x1.00cp-45
  },
  { // Entry 112
    0x1.0d96e57290c3f1c3681bab8c1f00b39cp-1,
    0x1.014dcaa237970p-1
  },
  { // Entry 113
    -0x1.0d96e57290c3f1c3681bab8c1f00b39cp-1,
    -0x1.014dcaa237970p-1
  },
  { // Entry 114
    0x1.0dabf55dce937f7558a8b531d459f15ep-1,
    0x1.016p-1
  },
  { // Entry 115
    -0x1.0dabf55dce937f7558a8b531d459f15ep-1,
    -0x1.016p-1
  },
  { // Entry 116
    0x1.0dc2ef671d6c33eaa546ddae05d5e453p-1,
    0x1.0173dc94b6306p-1
  },
  { // Entry 117
    -0x1.0dc2ef671d6c33eaa546ddae05d5e453p-1,
    -0x1.0173dc94b6306p-1
  },
  { // Entry 118
    0x1.0f1e6ec54eea2c73401f62badd2976acp-1,
    0x1.02ap-1
  },
  { // Entry 119
    -0x1.0f1e6ec54eea2c73401f62badd2976acp-1,
    -0x1.02ap-1
  },
  { // Entry 120
    0x1.0f4da9229cffec0c3743997491f11d56p-1,
    0x1.02c8c16dc1934p-1
  },
  { // Entry 121
    -0x1.0f4da9229cffec0c3743997491f11d56p-1,
    -0x1.02c8c16dc1934p-1
  },
  { // Entry 122
    0x1.0f6899dc73e34a54ad3cce806ce29011p-1,
    0x1.02ep-1
  },
  { // Entry 123
    -0x1.0f6899dc73e34a54ad3cce806ce29011p-1,
    -0x1.02ep-1
  },
  { // Entry 124
    0x1.0f838e30479aba67ec652b632028fefap-1,
    0x1.02f740f61e37ap-1
  },
  { // Entry 125
    -0x1.0f838e30479aba67ec652b632028fefap-1,
    -0x1.02f740f61e37ap-1
  },
  { // Entry 126
    0x1.0fe301c2f5be2a63ef5b2626fe19c78ap-1,
    0x1.034993ee3b8dap-1
  },
  { // Entry 127
    -0x1.0fe301c2f5be2a63ef5b2626fe19c78ap-1,
    -0x1.034993ee3b8dap-1
  },
  { // Entry 128
    0x1.1022212ba23069c4a937494d32fea558p-1,
    0x1.038p-1
  },
  { // Entry 129
    -0x1.1022212ba23069c4a937494d32fea558p-1,
    -0x1.038p-1
  },
  { // Entry 130
    0x1.10282996f9883a58886ba1799ed5dd8ep-1,
    0x1.038533564d2f6p-1
  },
  { // Entry 131
    -0x1.10282996f9883a58886ba1799ed5dd8ep-1,
    -0x1.038533564d2f6p-1
  },
  { // Entry 132
    0x1.1066e87eac0fa20763c3465fae49f6f3p-1,
    0x1.03bb47eba27acp-1
  },
  { // Entry 133
    -0x1.1066e87eac0fa20763c3465fae49f6f3p-1,
    -0x1.03bb47eba27acp-1
  },
  { // Entry 134
    0x1.10cbb4c8656620d5e25de954cc196a15p-1,
    0x1.04122069afab2p-1
  },
  { // Entry 135
    -0x1.10cbb4c8656620d5e25de954cc196a15p-1,
    -0x1.04122069afab2p-1
  },
  { // Entry 136
    0x1.116717f96556ee4420b909b7fa6b63dfp-1,
    0x1.0497edab6ede1p-1
  },
  { // Entry 137
    -0x1.116717f96556ee4420b909b7fa6b63dfp-1,
    -0x1.0497edab6ede1p-1
  },
  { // Entry 138
    0x1.1179dbb27e582d73878c014b8e3e1cc0p-1,
    0x1.04a814758e0f8p-1
  },
  { // Entry 139
    -0x1.1179dbb27e582d73878c014b8e3e1cc0p-1,
    -0x1.04a814758e0f8p-1
  },
  { // Entry 140
    0x1.1198c0d79289b2f9f277c2f3a7a05d25p-1,
    0x1.04c2ab77cf474p-1
  },
  { // Entry 141
    -0x1.1198c0d79289b2f9f277c2f3a7a05d25p-1,
    -0x1.04c2ab77cf474p-1
  },
  { // Entry 142
    0x1.196875557f2137d39d74d174f529db4bp-1,
    0x1.0b73c2dcdc2b8p-1
  },
  { // Entry 143
    -0x1.196875557f2137d39d74d174f529db4bp-1,
    -0x1.0b73c2dcdc2b8p-1
  },
  { // Entry 144
    0x1.1b553e4436fee055d4d2c67c601a0212p-1,
    0x1.0d177bea3f610p-1
  },
  { // Entry 145
    -0x1.1b553e4436fee055d4d2c67c601a0212p-1,
    -0x1.0d177bea3f610p-1
  },
  { // Entry 146
    0x1.1c38449a61c9580d6859380e343d833cp-1,
    0x1.0dd885a3ef4fcp-1
  },
  { // Entry 147
    -0x1.1c38449a61c9580d6859380e343d833cp-1,
    -0x1.0dd885a3ef4fcp-1
  },
  { // Entry 148
    0x1.1cc4b3c079836265872b7d492044d616p-1,
    0x1.0e4fd42b1d0e6p-1
  },
  { // Entry 149
    -0x1.1cc4b3c079836265872b7d492044d616p-1,
    -0x1.0e4fd42b1d0e6p-1
  },
  { // Entry 150
    0x1.1cfd6e266de95f1bf48764f46577e309p-1,
    0x1.0e8p-1
  },
  { // Entry 151
    -0x1.1cfd6e266de95f1bf48764f46577e309p-1,
    -0x1.0e8p-1
  },
  { // Entry 152
    0x1.21cdcf52000c220a966befeb62e640f6p-1,
    0x1.129345051b29dp-1
  },
  { // Entry 153
    -0x1.21cdcf52000c220a966befeb62e640f6p-1,
    -0x1.129345051b29dp-1
  },
  { // Entry 154
    0x1.130d3aa02dac280175032d7dcd901029p-5,
    0x1.130p-5
  },
  { // Entry 155
    -0x1.130d3aa02dac280175032d7dcd901029p-5,
    -0x1.130p-5
  },
  { // Entry 156
    0x1.140000000d5df80001bf7913cb80995cp-17,
    0x1.140p-17
  },
  { // Entry 157
    -0x1.140000000d5df80001bf7913cb80995cp-17,
    -0x1.140p-17
  },
  { // Entry 158
    0x1.2775c4b617d654588958a178dea861bap-1,
    0x1.1755174d62823p-1
  },
  { // Entry 159
    -0x1.2775c4b617d654588958a178dea861bap-1,
    -0x1.1755174d62823p-1
  },
  { // Entry 160
    0x1.199af8e5ca4257fcd763543b8f3fce81p-5,
    0x1.198cc66331980p-5
  },
  { // Entry 161
    -0x1.199af8e5ca4257fcd763543b8f3fce81p-5,
    -0x1.198cc66331980p-5
  },
  { // Entry 162
    0x1.2c5ab8264bdbb3e1bc65214317759a09p-1,
    0x1.1b6bdc91e8ed8p-1
  },
  { // Entry 163
    -0x1.2c5ab8264bdbb3e1bc65214317759a09p-1,
    -0x1.1b6bdc91e8ed8p-1
  },
  { // Entry 164
    0x1.2cee00a870ba528fbe6b9f3cda1408b3p-1,
    0x1.1be67991de2d4p-1
  },
  { // Entry 165
    -0x1.2cee00a870ba528fbe6b9f3cda1408b3p-1,
    -0x1.1be67991de2d4p-1
  },
  { // Entry 166
    0x1.1fc5e19315892ffd69defb731e5b723ap-2,
    0x1.1c0p-2
  },
  { // Entry 167
    -0x1.1fc5e19315892ffd69defb731e5b723ap-2,
    -0x1.1c0p-2
  },
  { // Entry 168
    0x1.2febc655185c99c444ff04c55bfb6d66p-1,
    0x1.1e627f69af588p-1
  },
  { // Entry 169
    -0x1.2febc655185c99c444ff04c55bfb6d66p-1,
    -0x1.1e627f69af588p-1
  },
  { // Entry 170
    0x1.30d8a981b9948a394e1467470cfad235p-1,
    0x1.1f26bdf8a0343p-1
  },
  { // Entry 171
    -0x1.30d8a981b9948a394e1467470cfad235p-1,
    -0x1.1f26bdf8a0343p-1
  },
  { // Entry 172
    0x1.30f8d6bccdf217fff8c0dda31391974fp-1,
    0x1.1f41613172746p-1
  },
  { // Entry 173
    -0x1.30f8d6bccdf217fff8c0dda31391974fp-1,
    -0x1.1f41613172746p-1
  },
  { // Entry 174
    0x1.3110249047eaf30fc3ba6988a43b8ccbp-1,
    0x1.1f54ab50e347ep-1
  },
  { // Entry 175
    -0x1.3110249047eaf30fc3ba6988a43b8ccbp-1,
    -0x1.1f54ab50e347ep-1
  },
  { // Entry 176
    0x1.31462f20d3145a25898cd5561126dbefp-1,
    0x1.1f816460b6e0dp-1
  },
  { // Entry 177
    -0x1.31462f20d3145a25898cd5561126dbefp-1,
    -0x1.1f816460b6e0dp-1
  },
  { // Entry 178
    0x1.31ef197bde35531a915e264fef2305e8p-1,
    0x1.200d19c3f0b0bp-1
  },
  { // Entry 179
    -0x1.31ef197bde35531a915e264fef2305e8p-1,
    -0x1.200d19c3f0b0bp-1
  },
  { // Entry 180
    0x1.321d12e54f83b31627f80c3fa62b7ca1p-1,
    0x1.20331ab8a7458p-1
  },
  { // Entry 181
    -0x1.321d12e54f83b31627f80c3fa62b7ca1p-1,
    -0x1.20331ab8a7458p-1
  },
  { // Entry 182
    0x1.2177521a338b07fff0d9c9957c5a6cebp-16,
    0x1.21775219f5dc5p-16
  },
  { // Entry 183
    -0x1.2177521a338b07fff0d9c9957c5a6cebp-16,
    -0x1.21775219f5dc5p-16
  },
  { // Entry 184
    0x1.3e67925d0e6f8bcbb21a79d27ecca7d2p-1,
    0x1.2a46471805efdp-1
  },
  { // Entry 185
    -0x1.3e67925d0e6f8bcbb21a79d27ecca7d2p-1,
    -0x1.2a46471805efdp-1
  },
  { // Entry 186
    0x1.2bb1862a568148015c0bf4a2a7154dc1p-3,
    0x1.2aap-3
  },
  { // Entry 187
    -0x1.2bb1862a568148015c0bf4a2a7154dc1p-3,
    -0x1.2aap-3
  },
  { // Entry 188
    0x1.3f6fd0f27823d7fefc74a71eccd96298p-1,
    0x1.2b1ce548833aep-1
  },
  { // Entry 189
    -0x1.3f6fd0f27823d7fefc74a71eccd96298p-1,
    -0x1.2b1ce548833aep-1
  },
  { // Entry 190
    0x1.411bb49364c5ea4184bb3805a893e054p-1,
    0x1.2c77c3b7fadbcp-1
  },
  { // Entry 191
    -0x1.411bb49364c5ea4184bb3805a893e054p-1,
    -0x1.2c77c3b7fadbcp-1
  },
  { // Entry 192
    0x1.442ff6c0f5d4d7fe7775e70c3e4e8219p-1,
    0x1.2ef49e5511ddfp-1
  },
  { // Entry 193
    -0x1.442ff6c0f5d4d7fe7775e70c3e4e8219p-1,
    -0x1.2ef49e5511ddfp-1
  },
  { // Entry 194
    0x1.443fecfebc1df7de68052624a8b1d61dp-1,
    0x1.2f017c4fe3544p-1
  },
  { // Entry 195
    -0x1.443fecfebc1df7de68052624a8b1d61dp-1,
    -0x1.2f017c4fe3544p-1
  },
  { // Entry 196
    0x1.457bf318fe516a79da6f4a61af7a7fa5p-1,
    0x1.3p-1
  },
  { // Entry 197
    -0x1.457bf318fe516a79da6f4a61af7a7fa5p-1,
    -0x1.3p-1
  },
  { // Entry 198
    0x1.5ccd5c05e68fb800000849ddd0fe2ca5p-1,
    0x1.4270ed4aad70ep-1
  },
  { // Entry 199
    -0x1.5ccd5c05e68fb800000849ddd0fe2ca5p-1,
    -0x1.4270ed4aad70ep-1
  },
  { // Entry 200
    0x1.44000000159fd80003e593b785ba9626p-17,
    0x1.440p-17
  },
  { // Entry 201
    -0x1.44000000159fd80003e593b785ba9626p-17,
    -0x1.440p-17
  },
  { // Entry 202
    0x1.63b1cbb66b8a17ae1fd76035d949e2b7p-1,
    0x1.47c3fdc9bf433p-1
  },
  { // Entry 203
    -0x1.63b1cbb66b8a17ae1fd76035d949e2b7p-1,
    -0x1.47c3fdc9bf433p-1
  },
  { // Entry 204
    0x1.65fc8f66ba692e01a5afda7ace8deae2p-1,
    0x1.4985ec22e7bf6p-1
  },
  { // Entry 205
    -0x1.65fc8f66ba692e01a5afda7ace8deae2p-1,
    -0x1.4985ec22e7bf6p-1
  },
  { // Entry 206
    0x1.4d78bac08656681847462467555e549bp-3,
    0x1.4c0p-3
  },
  { // Entry 207
    -0x1.4d78bac08656681847462467555e549bp-3,
    -0x1.4c0p-3
  },
  { // Entry 208
    0x1.6d59bfe3f2224f6000acc00b769ed440p-1,
    0x1.4f2p-1
  },
  { // Entry 209
    -0x1.6d59bfe3f2224f6000acc00b769ed440p-1,
    -0x1.4f2p-1
  },
  { // Entry 210
    0x1.5000000000207800000013a839333343p-20,
    0x1.4fffffffffcp-20
  },
  { // Entry 211
    -0x1.5000000000207800000013a839333343p-20,
    -0x1.4fffffffffcp-20
  },
  { // Entry 212
    0x1.500000000060780000004ac83933337fp-20,
    0x1.5p-20
  },
  { // Entry 213
    -0x1.500000000060780000004ac83933337fp-20,
    -0x1.5p-20
  },
  { // Entry 214
    0x1.55277b9f38d027ffff30112bed0c9f0fp-4,
    0x1.54c28a8e4f3e2p-4
  },
  { // Entry 215
    -0x1.55277b9f38d027ffff30112bed0c9f0fp-4,
    -0x1.54c28a8e4f3e2p-4
  },
  { // Entry 216
    0x1.5ed2a392bb50f7fad69db4d959b3510ap-2,
    0x1.580p-2
  },
  { // Entry 217
    -0x1.5ed2a392bb50f7fad69db4d959b3510ap-2,
    -0x1.580p-2
  },
  { // Entry 218
    0x1.7f1f4917c72b6003b55c8200e8dcecc0p-1,
    0x1.5c5b3407f55e1p-1
  },
  { // Entry 219
    -0x1.7f1f4917c72b6003b55c8200e8dcecc0p-1,
    -0x1.5c5b3407f55e1p-1
  },
  { // Entry 220
    0x1.8b6201c0f179080000d81b7964ae4654p-1,
    0x1.653da5baf7440p-1
  },
  { // Entry 221
    -0x1.8b6201c0f179080000d81b7964ae4654p-1,
    -0x1.653da5baf7440p-1
  },
  { // Entry 222
    0x1.7250952ca29c0813f4e50a0ad18f3648p-2,
    0x1.6a4bb63c82129p-2
  },
  { // Entry 223
    -0x1.7250952ca29c0813f4e50a0ad18f3648p-2,
    -0x1.6a4bb63c82129p-2
  },
  { // Entry 224
    0x1.77b27e3a4418480d8c0062be11693e16p-2,
    0x1.6f533603e2320p-2
  },
  { // Entry 225
    -0x1.77b27e3a4418480d8c0062be11693e16p-2,
    -0x1.6f533603e2320p-2
  },
  { // Entry 226
    0x1.9e149bad9649280000eb9dad7440c574p-1,
    0x1.7264d0bec49b2p-1
  },
  { // Entry 227
    -0x1.9e149bad9649280000eb9dad7440c574p-1,
    -0x1.7264d0bec49b2p-1
  },
  { // Entry 228
    0x1.7cc0ee7ed8ad48137e185fb9156bae4cp-2,
    0x1.740a59647d7a5p-2
  },
  { // Entry 229
    -0x1.7cc0ee7ed8ad48137e185fb9156bae4cp-2,
    -0x1.740a59647d7a5p-2
  },
  { // Entry 230
    0x1.a207566488fc97fcadc30933e3392d3dp-1,
    0x1.751bcca851309p-1
  },
  { // Entry 231
    -0x1.a207566488fc97fcadc30933e3392d3dp-1,
    -0x1.751bcca851309p-1
  },
  { // Entry 232
    0x1.7e693c113d4a4814c150d8ac5b0c8d53p-2,
    0x1.7595883b67f16p-2
  },
  { // Entry 233
    -0x1.7e693c113d4a4814c150d8ac5b0c8d53p-2,
    -0x1.7595883b67f16p-2
  },
  { // Entry 234
    0x1.7ee6be5058d0201a24d137f52ff6909ep-2,
    0x1.760a6116c7198p-2
  },
  { // Entry 235
    -0x1.7ee6be5058d0201a24d137f52ff6909ep-2,
    -0x1.760a6116c7198p-2
  },
  { // Entry 236
    0x1.a6a1bef361a7d7f9c2816e02dbac1bf5p-1,
    0x1.783ee81831665p-1
  },
  { // Entry 237
    -0x1.a6a1bef361a7d7f9c2816e02dbac1bf5p-1,
    -0x1.783ee81831665p-1
  },
  { // Entry 238
    0x1.86618612c359e81481d9a7341d6a2a51p-2,
    0x1.7cfe473430fc6p-2
  },
  { // Entry 239
    -0x1.86618612c359e81481d9a7341d6a2a51p-2,
    -0x1.7cfe473430fc6p-2
  },
  { // Entry 240
    0x1.88d8a3b14d9e1ff14bbde3d33d157530p-2,
    0x1.7f47cd10de0e8p-2
  },
  { // Entry 241
    -0x1.88d8a3b14d9e1ff14bbde3d33d157530p-2,
    -0x1.7f47cd10de0e8p-2
  },
  { // Entry 242
    0x1.8988868fc564c81982b2db8ce8bc0625p-2,
    0x1.7feae137d5ddep-2
  },
  { // Entry 243
    -0x1.8988868fc564c81982b2db8ce8bc0625p-2,
    -0x1.7feae137d5ddep-2
  },
  { // Entry 244
    0x1.899fd8f017515812de14f44be98d055cp-2,
    0x1.80007ffffffffp-2
  },
  { // Entry 245
    -0x1.899fd8f017515812de14f44be98d055cp-2,
    -0x1.80007ffffffffp-2
  },
  { // Entry 246
    0x1.b27ae0f5ee6e67fffb44fb3a0cb3c215p-1,
    0x1.802e143a91c4ep-1
  },
  { // Entry 247
    -0x1.b27ae0f5ee6e67fffb44fb3a0cb3c215p-1,
    -0x1.802e143a91c4ep-1
  },
  { // Entry 248
    0x1.8b7809bb86ae17ec6c24da984138f419p-2,
    0x1.81b612840dbaep-2
  },
  { // Entry 249
    -0x1.8b7809bb86ae17ec6c24da984138f419p-2,
    -0x1.81b612840dbaep-2
  },
  { // Entry 250
    0x1.8f91c0fb8e2e97ef847eab1159f00cc6p-2,
    0x1.8581ade28355fp-2
  },
  { // Entry 251
    -0x1.8f91c0fb8e2e97ef847eab1159f00cc6p-2,
    -0x1.8581ade28355fp-2
  },
  { // Entry 252
    0x1.8c16f3fc4a5840013187c62d948aa003p-3,
    0x1.89ap-3
  },
  { // Entry 253
    -0x1.8c16f3fc4a5840013187c62d948aa003p-3,
    -0x1.89ap-3
  },
  { // Entry 254
    0x1.c1e120b980b3cf3fbf17268200fc8ffbp-1,
    0x1.8a2f2f54d849ep-1
  },
  { // Entry 255
    -0x1.c1e120b980b3cf3fbf17268200fc8ffbp-1,
    -0x1.8a2f2f54d849ep-1
  },
  { // Entry 256
    0x1.95b5a93656211806335e5300e251533cp-2,
    0x1.8b2da077338c2p-2
  },
  { // Entry 257
    -0x1.95b5a93656211806335e5300e251533cp-2,
    -0x1.8b2da077338c2p-2
  },
  { // Entry 258
    0x1.90cc7766b33bd000fff143442b4e2043p-4,
    0x1.9028ceb4afd2cp-4
  },
  { // Entry 259
    -0x1.90cc7766b33bd000fff143442b4e2043p-4,
    -0x1.9028ceb4afd2cp-4
  },
  { // Entry 260
    0x1.cbe2739ce56927fbb7d0777fc5057965p-1,
    0x1.907e632b1000ep-1
  },
  { // Entry 261
    -0x1.cbe2739ce56927fbb7d0777fc5057965p-1,
    -0x1.907e632b1000ep-1
  },
  { // Entry 262
    0x1.9eff7d224a10cffd0ccc2eea39c4ecacp-2,
    0x1.93bb0fc0700b7p-2
  },
  { // Entry 263
    -0x1.9eff7d224a10cffd0ccc2eea39c4ecacp-2,
    -0x1.93bb0fc0700b7p-2
  },
  { // Entry 264
    0x1.a0552aa49b7117fa53b105630024fe49p-2,
    0x1.94f4f95477d9ep-2
  },
  { // Entry 265
    -0x1.a0552aa49b7117fa53b105630024fe49p-2,
    -0x1.94f4f95477d9ep-2
  },
  { // Entry 266
    0x1.994ffb5daf0f97ffffffffffffa81adap-3,
    0x1.9697cb602c582p-3
  },
  { // Entry 267
    -0x1.994ffb5daf0f97ffffffffffffa81adap-3,
    -0x1.9697cb602c582p-3
  },
  { // Entry 268
    0x1.98ad7f9954c2c000dda10069f24bfb9fp-4,
    0x1.980p-4
  },
  { // Entry 269
    -0x1.98ad7f9954c2c000dda10069f24bfb9fp-4,
    -0x1.980p-4
  },
  { // Entry 270
    0x1.9c618aafabed50000080bb9d9c6d602ep-3,
    0x1.999999a45e898p-3
  },
  { // Entry 271
    -0x1.9c618aafabed50000080bb9d9c6d602ep-3,
    -0x1.999999a45e898p-3
  },
  { // Entry 272
    0x1.9c618aafac061003732b347dbb6bf610p-3,
    0x1.999999a45ea1cp-3
  },
  { // Entry 273
    -0x1.9c618aafac061003732b347dbb6bf610p-3,
    -0x1.999999a45ea1cp-3
  },
  { // Entry 274
    0x1.9c618ab54a7b2ffe4628191f82391647p-3,
    0x1.999999a9e006dp-3
  },
  { // Entry 275
    -0x1.9c618ab54a7b2ffe4628191f82391647p-3,
    -0x1.999999a9e006dp-3
  },
  { // Entry 276
    0x1.9c618ab55b092ffd804a3f4bc32f43c6p-3,
    0x1.999999a9f03f3p-3
  },
  { // Entry 277
    -0x1.9c618ab55b092ffd804a3f4bc32f43c6p-3,
    -0x1.999999a9f03f3p-3
  },
  { // Entry 278
    0x1.ddedf400713097ce31df0888bcde8d69p-1,
    0x1.9b7c1d9445413p-1
  },
  { // Entry 279
    -0x1.ddedf400713097ce31df0888bcde8d69p-1,
    -0x1.9b7c1d9445413p-1
  },
  { // Entry 280
    0x1.eca34562d4a0d79516186d1c200eae46p-1,
    0x1.a410ef3ffe9b1p-1
  },
  { // Entry 281
    -0x1.eca34562d4a0d79516186d1c200eae46p-1,
    -0x1.a410ef3ffe9b1p-1
  },
  { // Entry 282
    0x1.f90469438f616801edb23ef0fcf7a322p-1,
    0x1.ab053825fa3c7p-1
  },
  { // Entry 283
    -0x1.f90469438f616801edb23ef0fcf7a322p-1,
    -0x1.ab053825fa3c7p-1
  },
  { // Entry 284
    0x1.b000000000cd0800000106bc80666823p-20,
    0x1.bp-20
  },
  { // Entry 285
    -0x1.b000000000cd0800000106bc80666823p-20,
    -0x1.bp-20
  },
  { // Entry 286
    0x1.b3b0da67543b3807834a8feb1c1eba94p-3,
    0x1.b0696dec2c0a1p-3
  },
  { // Entry 287
    -0x1.b3b0da67543b3807834a8feb1c1eba94p-3,
    -0x1.b0696dec2c0a1p-3
  },
  { // Entry 288
    0x1.04179cbe1e5c1fffff818794e482d547p0,
    0x1.b333333761245p-1
  },
  { // Entry 289
    -0x1.04179cbe1e5c1fffff818794e482d547p0,
    -0x1.b333333761245p-1
  },
  { // Entry 290
    0x1.b34d1c29d5ccbffecdc2bdebc095bf13p-6,
    0x1.b34p-6
  },
  { // Entry 291
    -0x1.b34d1c29d5ccbffecdc2bdebc095bf13p-6,
    -0x1.b34p-6
  },
  { // Entry 292
    0x1.0554bb3242a2a800df4cee49ca092177p0,
    0x1.b48p-1
  },
  { // Entry 293
    -0x1.0554bb3242a2a800df4cee49ca092177p0,
    -0x1.b48p-1
  },
  { // Entry 294
    0x1.b8a88f38bc5ac8137e8c7eb54443675ep-3,
    0x1.b54423c1483e2p-3
  },
  { // Entry 295
    -0x1.b8a88f38bc5ac8137e8c7eb54443675ep-3,
    -0x1.b54423c1483e2p-3
  },
  { // Entry 296
    0x1.07d8cdf7eeee880fbc5277faa149e24ap0,
    0x1.b71bdc2c4ecf6p-1
  },
  { // Entry 297
    -0x1.07d8cdf7eeee880fbc5277faa149e24ap0,
    -0x1.b71bdc2c4ecf6p-1
  },
  { // Entry 298
    0x1.bf06ca3159a247fffd949acbf7190141p-6,
    0x1.bef89775b5e88p-6
  },
  { // Entry 299
    -0x1.bf06ca3159a247fffd949acbf7190141p-6,
    -0x1.bef89775b5e88p-6
  },
  { // Entry 300
    0x1.ce8c7a50bddbaffeae205209c4b290fcp-2,
    0x1.befa8c764e35dp-2
  },
  { // Entry 301
    -0x1.ce8c7a50bddbaffeae205209c4b290fcp-2,
    -0x1.befa8c764e35dp-2
  },
  { // Entry 302
    0x1.cf79cf3c63f057d0885a264fa7e14a24p-2,
    0x1.bfd007a1b1a48p-2
  },
  { // Entry 303
    -0x1.cf79cf3c63f057d0885a264fa7e14a24p-2,
    -0x1.bfd007a1b1a48p-2
  },
  { // Entry 304
    0x1.c0e0d42a150f980e71b5f03eded5070fp-23,
    0x1.c0e0d42a150c0p-23
  },
  { // Entry 305
    -0x1.c0e0d42a150f980e71b5f03eded5070fp-23,
    -0x1.c0e0d42a150c0p-23
  },
  { // Entry 306
    0x1.c14a6c452bfa080160389f80233eca63p-6,
    0x1.c13c020751a78p-6
  },
  { // Entry 307
    -0x1.c14a6c452bfa080160389f80233eca63p-6,
    -0x1.c13c020751a78p-6
  },
  { // Entry 308
    0x1.d11a7b81b1c1e79cf616ad2e273afb43p-2,
    0x1.c1469a15e68f5p-2
  },
  { // Entry 309
    -0x1.d11a7b81b1c1e79cf616ad2e273afb43p-2,
    -0x1.c1469a15e68f5p-2
  },
  { // Entry 310
    0x1.16f4bb864adfc800008fd38fd1e04261p0,
    0x1.c5e01019009efp-1
  },
  { // Entry 311
    -0x1.16f4bb864adfc800008fd38fd1e04261p0,
    -0x1.c5e01019009efp-1
  },
  { // Entry 312
    0x1.c678548c22ba90p-115,
    0x1.c678548c22ba9p-115
  },
  { // Entry 313
    -0x1.c678548c22ba90p-115,
    -0x1.c678548c22ba9p-115
  },
  { // Entry 314
    0x1.d7efd0e20d07d8013801e962e317e549p-2,
    0x1.c767fffffffffp-2
  },
  { // Entry 315
    -0x1.d7efd0e20d07d8013801e962e317e549p-2,
    -0x1.c767fffffffffp-2
  },
  { // Entry 316
    0x1.c9e63f1fe0f0e821b29667bc4eb4d50bp-4,
    0x1.c8f23c8f23c8cp-4
  },
  { // Entry 317
    -0x1.c9e63f1fe0f0e821b29667bc4eb4d50bp-4,
    -0x1.c8f23c8f23c8cp-4
  },
  { // Entry 318
    0x1.1ea9370e567be7ffffffe01e15866a33p0,
    0x1.ccccccd416c08p-1
  },
  { // Entry 319
    -0x1.1ea9370e567be7ffffffe01e15866a33p0,
    -0x1.ccccccd416c08p-1
  },
  { // Entry 320
    0x1.22927e6073b4c80000d27967f2a7a4f7p0,
    0x1.d027e48f2c2bap-1
  },
  { // Entry 321
    -0x1.22927e6073b4c80000d27967f2a7a4f7p0,
    -0x1.d027e48f2c2bap-1
  },
  { // Entry 322
    0x1.d2e000000102cdc6eb418359d0682dedp-20,
    0x1.d2ep-20
  },
  { // Entry 323
    -0x1.d2e000000102cdc6eb418359d0682dedp-20,
    -0x1.d2ep-20
  },
  { // Entry 324
    0x1.281b4c2fcafe57fe16b4679be76d29f5p0,
    0x1.d4b81182fe13bp-1
  },
  { // Entry 325
    -0x1.281b4c2fcafe57fe16b4679be76d29f5p0,
    -0x1.d4b81182fe13bp-1
  },
  { // Entry 326
    0x1.e70a08011eeb97fb46e212681fd509f0p-2,
    0x1.d4e205cadb381p-2
  },
  { // Entry 327
    -0x1.e70a08011eeb97fb46e212681fd509f0p-2,
    -0x1.d4e205cadb381p-2
  },
  { // Entry 328
    0x1.d90d0803393b9819fec9e92bfd414223p-4,
    0x1.d80p-4
  },
  { // Entry 329
    -0x1.d90d0803393b9819fec9e92bfd414223p-4,
    -0x1.d80p-4
  },
  { // Entry 330
    0x1.3172527a00f7e8002439c6d9f1d3590dp0,
    0x1.dbec0e2ae5bdbp-1
  },
  { // Entry 331
    -0x1.3172527a00f7e8002439c6d9f1d3590dp0,
    -0x1.dbec0e2ae5bdbp-1
  },
  { // Entry 332
    0x1.dd2bf488d4241c11bf324d508cfacbeap-11,
    0x1.dd2bf03799278p-11
  },
  { // Entry 333
    -0x1.dd2bf488d4241c11bf324d508cfacbeap-11,
    -0x1.dd2bf03799278p-11
  },
  { // Entry 334
    0x1.f192112f19e6f7fc311ba78ec60abb13p-2,
    0x1.de386d60903a5p-2
  },
  { // Entry 335
    -0x1.f192112f19e6f7fc311ba78ec60abb13p-2,
    -0x1.de386d60903a5p-2
  },
  { // Entry 336
    0x1.f408515902f777fad5cb629690c96e8cp-2,
    0x1.e0655f628fcc4p-2
  },
  { // Entry 337
    -0x1.f408515902f777fad5cb629690c96e8cp-2,
    -0x1.e0655f628fcc4p-2
  },
  { // Entry 338
    0x1.f425d0cdf031d78d14e47ef92c30410dp-2,
    0x1.e07f6c11f3ad7p-2
  },
  { // Entry 339
    -0x1.f425d0cdf031d78d14e47ef92c30410dp-2,
    -0x1.e07f6c11f3ad7p-2
  },
  { // Entry 340
    0x1.e4c86c3587e888034c71e60a370d6263p-5,
    0x1.e48p-5
  },
  { // Entry 341
    -0x1.e4c86c3587e888034c71e60a370d6263p-5,
    -0x1.e48p-5
  },
  { // Entry 342
    0x1.e6c2ee85159eeffd05dd82882578d1d4p-5,
    0x1.e6799e6799e64p-5
  },
  { // Entry 343
    -0x1.e6c2ee85159eeffd05dd82882578d1d4p-5,
    -0x1.e6799e6799e64p-5
  },
  { // Entry 344
    0x1.e92973bd05fb21d34afdf692cee7c5d5p-4,
    0x1.e80p-4
  },
  { // Entry 345
    -0x1.e92973bd05fb21d34afdf692cee7c5d5p-4,
    -0x1.e80p-4
  },
  { // Entry 346
    0x1.eb3228982dcb8aaa55776e8b9ba3cd25p-4,
    0x1.ea04fb75153f7p-4
  },
  { // Entry 347
    -0x1.eb3228982dcb8aaa55776e8b9ba3cd25p-4,
    -0x1.ea04fb75153f7p-4
  },
  { // Entry 348
    0x1.f026f488662fc51b1e6d97371bb4f957p-3,
    0x1.eb50295fad425p-3
  },
  { // Entry 349
    -0x1.f026f488662fc51b1e6d97371bb4f957p-3,
    -0x1.eb50295fad425p-3
  },
  { // Entry 350
    0x1.eb63051149d3b7822ba54208fc03580ep-6,
    0x1.eb50295fad425p-6
  },
  { // Entry 351
    -0x1.eb63051149d3b7822ba54208fc03580ep-6,
    -0x1.eb50295fad425p-6
  },
  { // Entry 352
    0x1.4a55ae332c7a4c09ea98e7d59d9872dfp0,
    0x1.ec0p-1
  },
  { // Entry 353
    -0x1.4a55ae332c7a4c09ea98e7d59d9872dfp0,
    -0x1.ec0p-1
  },
  { // Entry 354
    0x1.4c655babcbe0b41389bc82e9f12e67c7p0,
    0x1.ed2p-1
  },
  { // Entry 355
    -0x1.4c655bab
```
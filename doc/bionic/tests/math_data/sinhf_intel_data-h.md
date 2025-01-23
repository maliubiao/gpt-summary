Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The central task is to analyze a C source code file, `sinhf_intel_data.handroid`, located within the Android Bionic library, and describe its functionality. The request also asks for context within Android, explanations of relevant libc functions (though this file doesn't *contain* libc functions, it *tests* them), dynamic linker information (not directly applicable here, but needs to be considered), examples, usage errors, and how Android components reach this code.

**2. Initial Analysis of the Source Code:**

The first thing that jumps out is the naming: `sinhf_intel_data`. `sinhf` strongly suggests a relationship with the hyperbolic sine function for floating-point numbers. The `_intel_data` part indicates this data is likely specific to Intel architectures or a set of test data. The file contents confirm this: it's an array `g_sinhf_intel_data` of a custom structure `data_1_1_t`. Each element contains two floats. The format of the float values suggests hexadecimal representation, often used in low-level programming and testing for precision.

**3. Identifying the Purpose:**

Given the name and content, the most logical conclusion is that this file provides test data for the `sinhf` function in the Bionic math library. Each entry in the array likely represents:

* **Input:** The first float value.
* **Expected Output:** The second float value, which should be the result of `sinhf` applied to the input.

The licensing information at the top confirms this is part of the Android Open Source Project, further supporting its role in the Android system.

**4. Connecting to Android Functionality:**

The `sinhf` function is part of the standard C math library (libc), and Bionic provides its implementation for Android. This test data is crucial for ensuring the correctness and accuracy of Bionic's `sinhf` implementation on Android devices, particularly those with Intel processors. This connects directly to Android's core functionality, as many applications rely on math functions.

**5. Addressing Specific Request Points (and Identifying Limitations):**

* **Functionality:**  The core function is to provide test data for `sinhf`.
* **Relationship to Android:**  Crucial for the correctness of the Bionic libc's `sinhf` implementation, which underpins many Android applications.
* **Explanation of libc functions:**  This file *doesn't implement* `sinhf` or other libc functions. It *tests* one. Therefore, a detailed explanation of `sinhf`'s implementation would come from the actual `sinhf` source code (likely in `bionic/libc/math`). I need to acknowledge this distinction.
* **Dynamic Linker:** This file doesn't directly involve the dynamic linker. It's static data. I need to explain why it's not relevant here, but also understand the dynamic linker's broader role in Bionic.
* **Logical Reasoning:** The assumption is that the first float is the input to `sinhf`, and the second is the expected output. Example inputs and outputs are explicitly given in the file.
* **Common Usage Errors:**  Not directly applicable to a *data* file. Usage errors would be related to *using* the `sinhf` function incorrectly (e.g., passing invalid input, not handling potential errors like overflow).
* **Android Framework/NDK Path:**  This is a more complex part. I need to trace how an app using `sinhf` would eventually involve this test data. This would involve:
    * NDK app using `<math.h>`.
    * Linking against Bionic's libc.so.
    * Bionic's `sinhf` implementation being called.
    * The Bionic test suite (where this data file resides) being run during development/testing to verify the correctness of the `sinhf` implementation.
* **Frida Hook:**  Since this is test data, hooking directly into *this file* isn't the primary goal. The goal would be to hook the *`sinhf` function* itself to see the inputs and outputs and potentially compare them to this test data.

**6. Structuring the Response:**

The request asks for a summary of functionality for "Part 1". Therefore, I need to focus on the core purpose of the file without going into excessive detail about the other requested points (those will likely be covered in "Part 2").

**7. Refinement and Clarity:**

Review the generated summary to ensure it's accurate, concise, and addresses the key aspects of the request for "Part 1". Make sure to explicitly state that the file provides *test data* and doesn't implement the `sinhf` function itself.

By following this thought process, I can systematically analyze the provided source code, connect it to the broader Android ecosystem, and generate a comprehensive and accurate response, while also identifying the limitations of the given file in relation to some of the more advanced requests (like dynamic linking and direct Frida hooking of the data file).
好的，让我们分析一下这个名为 `sinhf_intel_data.handroid` 的源代码文件。

**功能归纳（第 1 部分）：**

这个文件的主要功能是 **为 `sinhf` 函数提供测试数据**。

具体来说：

* **测试 `sinhf` 函数的正确性:**  该文件定义了一个名为 `g_sinhf_intel_data` 的静态数组，数组中的每个元素都是一个包含两个 `float` 类型数据的结构体 `data_1_1_t`。
* **提供输入和预期输出:**  每个结构体的第一个 `float` 成员是 `sinhf` 函数的 **输入值**，第二个 `float` 成员是该输入值对应的 `sinhf` 函数的 **预期输出值**。
* **针对 Intel 架构:** 文件名中包含 `intel_data`，这暗示这些测试数据可能是特别针对 Intel 架构的处理器进行优化或验证的。
* **Bionic 测试套件的一部分:** 文件路径 `bionic/tests/math_data/` 表明它是 Android Bionic 库中数学库测试套件的一部分。这意味着它的目的是在 Bionic 库的开发和测试过程中，用于自动化地验证 `sinhf` 函数的实现是否正确。

**总结来说，`sinhf_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `sinhf` 函数（单精度浮点数的双曲正弦函数）正确性的一组预定义的输入和预期输出数据。它可能特别关注在 Intel 架构上的 `sinhf` 实现。**

接下来，在第 2 部分，我们可以深入探讨你提出的其他问题。

### 提示词
```
这是目录为bionic/tests/math_data/sinhf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_sinhf_intel_data[] = {
  { // Entry 0
    -0x1.00000000000aaaaaaaaaaaccccccccccp-21,
    -0x1.p-21
  },
  { // Entry 1
    0x1.00000000000aaaaaaaaaaaccccccccccp-21,
    0x1.p-21
  },
  { // Entry 2
    -0x1.1770c0fffee31db7a31664de401a57cdp-1,
    -0x1.0b26eep-1
  },
  { // Entry 3
    0x1.1770c0fffee31db7a31664de401a57cdp-1,
    0x1.0b26eep-1
  },
  { // Entry 4
    -0x1.204fd00000000000000f3ca3e81c03afp-37,
    -0x1.204fd0p-37
  },
  { // Entry 5
    0x1.204fd00000000000000f3ca3e81c03afp-37,
    0x1.204fd0p-37
  },
  { // Entry 6
    -0x1.43510055f383351ba9ec4cdf5b1b1fa5p-12,
    -0x1.4351p-12
  },
  { // Entry 7
    0x1.43510055f383351ba9ec4cdf5b1b1fa5p-12,
    0x1.4351p-12
  },
  { // Entry 8
    -0x1.4f1fe6fffd055403a0afa5f61f7ad456p122,
    -0x1.561b10p6
  },
  { // Entry 9
    0x1.4f1fe6fffd055403a0afa5f61f7ad456p122,
    0x1.561b10p6
  },
  { // Entry 10
    -0x1.76339d048c41010db95311bf38824f7fp-2,
    -0x1.6e564ep-2
  },
  { // Entry 11
    0x1.76339d048c41010db95311bf38824f7fp-2,
    0x1.6e564ep-2
  },
  { // Entry 12
    -0x1.a6399b00031ae7e2d10c4d5ca8b85bb6p-2,
    -0x1.9b17d8p-2
  },
  { // Entry 13
    0x1.a6399b00031ae7e2d10c4d5ca8b85bb6p-2,
    0x1.9b17d8p-2
  },
  { // Entry 14
    -0x1.ed9c6b045cf886a719553b239eced39ap-1,
    -0x1.b62492p-1
  },
  { // Entry 15
    0x1.ed9c6b045cf886a719553b239eced39ap-1,
    0x1.b62492p-1
  },
  { // Entry 16
    -0x1.ffb1b2f8d872ac8cb2c8ae78073874cep-1,
    -0x1.c30c06p-1
  },
  { // Entry 17
    0x1.ffb1b2f8d872ac8cb2c8ae78073874cep-1,
    0x1.c30c06p-1
  },
  { // Entry 18
    -0x1.490e3effd17cc5e5cebb7150a45530b0p9,
    -0x1.cbae70p2
  },
  { // Entry 19
    0x1.490e3effd17cc5e5cebb7150a45530b0p9,
    0x1.cbae70p2
  },
  { // Entry 20
    -0x1.d3735503c31601d8a231e42764dca76bp-12,
    -0x1.d37354p-12
  },
  { // Entry 21
    0x1.d3735503c31601d8a231e42764dca76bp-12,
    0x1.d37354p-12
  },
  { // Entry 22
    -0x1.d3750103c5df89146104862bc8eb9511p-12,
    -0x1.d375p-12
  },
  { // Entry 23
    0x1.d3750103c5df89146104862bc8eb9511p-12,
    0x1.d375p-12
  },
  { // Entry 24
    -0x1.d4bc08fe54522492a18ed763f5905a3cp-6,
    -0x1.d4abacp-6
  },
  { // Entry 25
    0x1.d4bc08fe54522492a18ed763f5905a3cp-6,
    0x1.d4abacp-6
  },
  { // Entry 26
    -0x1.b495d8f96ad2507c36e288f42ed69c65p4,
    -0x1.fffcp1
  },
  { // Entry 27
    0x1.b495d8f96ad2507c36e288f42ed69c65p4,
    0x1.fffcp1
  },
  { // Entry 28
    0x1.0acd00fe63b96ca357895761ae66224ap-1,
    0x1.p-1
  },
  { // Entry 29
    -0x1.0acd00fe63b96ca357895761ae66224ap-1,
    -0x1.p-1
  },
  { // Entry 30
    0x1.00000000000aaaaaaaaaaaccccccccccp-21,
    0x1.p-21
  },
  { // Entry 31
    -0x1.00000000000aaaaaaaaaaaccccccccccp-21,
    -0x1.p-21
  },
  { // Entry 32
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 33
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 34
    0x1.000002000000000000000aaaaaeaaaabp-41,
    0x1.000002p-41
  },
  { // Entry 35
    -0x1.000002000000000000000aaaaaeaaaabp-41,
    -0x1.000002p-41
  },
  { // Entry 36
    0x1.00aae5001d35b2cc9f1bf5024aad3fc7p-3,
    0x1.000018p-3
  },
  { // Entry 37
    -0x1.00aae5001d35b2cc9f1bf5024aad3fc7p-3,
    -0x1.000018p-3
  },
  { // Entry 38
    0x1.2cdc4cd13dbaaea971cf4c6df8d02db1p0,
    0x1.000180p0
  },
  { // Entry 39
    -0x1.2cdc4cd13dbaaea971cf4c6df8d02db1p0,
    -0x1.000180p0
  },
  { // Entry 40
    0x1.000220000000000000002aabbaacecacp-40,
    0x1.000220p-40
  },
  { // Entry 41
    -0x1.000220000000000000002aabbaacecacp-40,
    -0x1.000220p-40
  },
  { // Entry 42
    0x1.75b684fbb21e3fadfd76948a74ff619cp10,
    0x1.0018p3
  },
  { // Entry 43
    -0x1.75b684fbb21e3fadfd76948a74ff619cp10,
    -0x1.0018p3
  },
  { // Entry 44
    0x1.0af11706dc935e6b8d9889ffd9d7f9eep-1,
    0x1.0020p-1
  },
  { // Entry 45
    -0x1.0af11706dc935e6b8d9889ffd9d7f9eep-1,
    -0x1.0020p-1
  },
  { // Entry 46
    0x1.2de53500112b48b54416fd3ac0fd5d35p0,
    0x1.00adp0
  },
  { // Entry 47
    -0x1.2de53500112b48b54416fd3ac0fd5d35p0,
    -0x1.00adp0
  },
  { // Entry 48
    0x1.d311590094b7169257222f29159c5274p1,
    0x1.00c0p1
  },
  { // Entry 49
    -0x1.d311590094b7169257222f29159c5274p1,
    -0x1.00c0p1
  },
  { // Entry 50
    0x1.bb8be0f928fa482d264aec809030cb98p4,
    0x1.0101p2
  },
  { // Entry 51
    -0x1.bb8be0f928fa482d264aec809030cb98p4,
    -0x1.0101p2
  },
  { // Entry 52
    0x1.d6509cfff1b887cd50d3c7b33a490af5p1,
    0x1.019bp1
  },
  { // Entry 53
    -0x1.d6509cfff1b887cd50d3c7b33a490af5p1,
    -0x1.019bp1
  },
  { // Entry 54
    0x1.d99ef101df23c13de5368e55ebb4c952p45,
    0x1.04p5
  },
  { // Entry 55
    -0x1.d99ef101df23c13de5368e55ebb4c952p45,
    -0x1.04p5
  },
  { // Entry 56
    0x1.b61e5ca3a5e30b2f0a03f292f9ce0084p92,
    0x1.04p6
  },
  { // Entry 57
    -0x1.b61e5ca3a5e30b2f0a03f292f9ce0084p92,
    -0x1.04p6
  },
  { // Entry 58
    0x1.0f53c500dab3115ec83d0a87f389efa5p-1,
    0x1.0401c0p-1
  },
  { // Entry 59
    -0x1.0f53c500dab3115ec83d0a87f389efa5p-1,
    -0x1.0401c0p-1
  },
  { // Entry 60
    0x1.07a43d780cd02aa326997430cb72ec6ep-2,
    0x1.04d0p-2
  },
  { // Entry 61
    -0x1.07a43d780cd02aa326997430cb72ec6ep-2,
    -0x1.04d0p-2
  },
  { // Entry 62
    0x1.070b91000585e92eceba7f1d10686783p-5,
    0x1.07p-5
  },
  { // Entry 63
    -0x1.070b91000585e92eceba7f1d10686783p-5,
    -0x1.07p-5
  },
  { // Entry 64
    0x1.0aef2dfa6f09af758cfac3ec7bbe6580p-2,
    0x1.08p-2
  },
  { // Entry 65
    -0x1.0aef2dfa6f09af758cfac3ec7bbe6580p-2,
    -0x1.08p-2
  },
  { // Entry 66
    0x1.0ab8c103d210ecc999dea2fb1e601dffp-7,
    0x1.0ab8p-7
  },
  { // Entry 67
    -0x1.0ab8c103d210ecc999dea2fb1e601dffp-7,
    -0x1.0ab8p-7
  },
  { // Entry 68
    HUGE_VALF,
    0x1.0bd822p85
  },
  { // Entry 69
    -HUGE_VALF,
    -0x1.0bd822p85
  },
  { // Entry 70
    0x1.1b0bd9fff434fa99eb934f12cfcde40dp-1,
    0x1.0e50p-1
  },
  { // Entry 71
    -0x1.1b0bd9fff434fa99eb934f12cfcde40dp-1,
    -0x1.0e50p-1
  },
  { // Entry 72
    0x1.13a0d500d2f8e84e29cf7e0b47593d6bp-7,
    0x1.13a0p-7
  },
  { // Entry 73
    -0x1.13a0d500d2f8e84e29cf7e0b47593d6bp-7,
    -0x1.13a0p-7
  },
  { // Entry 74
    0x1.14635aff07928f6b82b6efd046d85611p-6,
    0x1.1460p-6
  },
  { // Entry 75
    -0x1.14635aff07928f6b82b6efd046d85611p-6,
    -0x1.1460p-6
  },
  { // Entry 76
    0x1.1837d7019c29ac4261d83dbdd9540770p-4,
    0x1.18p-4
  },
  { // Entry 77
    -0x1.1837d7019c29ac4261d83dbdd9540770p-4,
    -0x1.18p-4
  },
  { // Entry 78
    0x1.1e9a66ffff67888e2226adc979242050p-2,
    0x1.1afcc0p-2
  },
  { // Entry 79
    -0x1.1e9a66ffff67888e2226adc979242050p-2,
    -0x1.1afcc0p-2
  },
  { // Entry 80
    0x1.5851b581ab5774b6bc22fe804a609974p0,
    0x1.1b08p0
  },
  { // Entry 81
    -0x1.5851b581ab5774b6bc22fe804a609974p0,
    -0x1.1b08p0
  },
  { // Entry 82
    0x1.1fc09496b655ab5f571a14fc538740f3p-2,
    0x1.1c18p-2
  },
  { // Entry 83
    -0x1.1fc09496b655ab5f571a14fc538740f3p-2,
    -0x1.1c18p-2
  },
  { // Entry 84
    0x1.1c4fa6fffe2308d6059816c28ca68b93p-6,
    0x1.1c4cp-6
  },
  { // Entry 85
    -0x1.1c4fa6fffe2308d6059816c28ca68b93p-6,
    -0x1.1c4cp-6
  },
  { // Entry 86
    0x1.1ef0f05245d564eb621bc3580e810ecbp-7,
    0x1.1ef0p-7
  },
  { // Entry 87
    -0x1.1ef0f05245d564eb621bc3580e810ecbp-7,
    -0x1.1ef0p-7
  },
  { // Entry 88
    0x1.5ef59f4fb8454858c70cce0b76f0d1c1p0,
    0x1.1ef8p0
  },
  { // Entry 89
    -0x1.5ef59f4fb8454858c70cce0b76f0d1c1p0,
    -0x1.1ef8p0
  },
  { // Entry 90
    0x1.7922d2f6a620cc176196ee619e38cedep0,
    0x1.2e073ap0
  },
  { // Entry 91
    -0x1.7922d2f6a620cc176196ee619e38cedep0,
    -0x1.2e073ap0
  },
  { // Entry 92
    0x1.43b381fff77c0efbac7ee89fffb83db3p-1,
    0x1.31497ep-1
  },
  { // Entry 93
    -0x1.43b381fff77c0efbac7ee89fffb83db3p-1,
    -0x1.31497ep-1
  },
  { // Entry 94
    0x1.32b4320000022be269a7e0844e8fb427p-3,
    0x1.3191a2p-3
  },
  { // Entry 95
    -0x1.32b4320000022be269a7e0844e8fb427p-3,
    -0x1.3191a2p-3
  },
  { // Entry 96
    0x1.81e2b0f865f7d68960908dea8dbff652p0,
    0x1.32e74cp0
  },
  { // Entry 97
    -0x1.81e2b0f865f7d68960908dea8dbff652p0,
    -0x1.32e74cp0
  },
  { // Entry 98
    0x1.684f9300049996963e27553b525d785cp2,
    0x1.36ea5cp1
  },
  { // Entry 99
    -0x1.684f9300049996963e27553b525d785cp2,
    -0x1.36ea5cp1
  },
  { // Entry 100
    0x1.3e8c5a52344c5fc05de7cf393fd80bacp-12,
    0x1.3e8c5ap-12
  },
  { // Entry 101
    -0x1.3e8c5a52344c5fc05de7cf393fd80bacp-12,
    -0x1.3e8c5ap-12
  },
  { // Entry 102
    0x1.3ebc005259354f37ecfabafab164439dp-12,
    0x1.3ebcp-12
  },
  { // Entry 103
    -0x1.3ebc005259354f37ecfabafab164439dp-12,
    -0x1.3ebcp-12
  },
  { // Entry 104
    0x1.3ec66e52614b0b45d34f5458bd2b6d4ap-12,
    0x1.3ec66ep-12
  },
  { // Entry 105
    -0x1.3ec66e52614b0b45d34f5458bd2b6d4ap-12,
    -0x1.3ec66ep-12
  },
  { // Entry 106
    0x1.9a856d00436428754784f838aa53dcdep0,
    0x1.403a42p0
  },
  { // Entry 107
    -0x1.9a856d00436428754784f838aa53dcdep0,
    -0x1.403a42p0
  },
  { // Entry 108
    0x1.4674690003b5c33e7fd09a6bffacac02p-2,
    0x1.4129d6p-2
  },
  { // Entry 109
    -0x1.4674690003b5c33e7fd09a6bffacac02p-2,
    -0x1.4129d6p-2
  },
  { // Entry 110
    0x1.442556569d4a81e2d99f316cd704988bp-12,
    0x1.442556p-12
  },
  { // Entry 111
    -0x1.442556569d4a81e2d99f316cd704988bp-12,
    -0x1.442556p-12
  },
  { // Entry 112
    0x1.f897f07e50760e5213f6121940ce7277p115,
    0x1.4455a8p6
  },
  { // Entry 113
    -0x1.f897f07e50760e5213f6121940ce7277p115,
    -0x1.4455a8p6
  },
  { // Entry 114
    0x1.f7c601c26a0aab07acb3aed129529860p116,
    0x1.4719c6p6
  },
  { // Entry 115
    -0x1.f7c601c26a0aab07acb3aed129529860p116,
    -0x1.4719c6p6
  },
  { // Entry 116
    0x1.8fd142fffbf07bcd9c6607b02fc55b74p117,
    0x1.48f2e4p6
  },
  { // Entry 117
    -0x1.8fd142fffbf07bcd9c6607b02fc55b74p117,
    -0x1.48f2e4p6
  },
  { // Entry 118
    0x1.54e2c50008b73d8e4d7ed6ca4c155dbcp-3,
    0x1.5354c2p-3
  },
  { // Entry 119
    -0x1.54e2c50008b73d8e4d7ed6ca4c155dbcp-3,
    -0x1.5354c2p-3
  },
  { // Entry 120
    0x1.7ff7f6932445d2e31f1b7c20d7c7d875p125,
    0x1.5ef7bcp6
  },
  { // Entry 121
    -0x1.7ff7f6932445d2e31f1b7c20d7c7d875p125,
    -0x1.5ef7bcp6
  },
  { // Entry 122
    0x1.f13408794171d98e14f95245a340ab06p125,
    0x1.600060p6
  },
  { // Entry 123
    -0x1.f13408794171d98e14f95245a340ab06p125,
    -0x1.600060p6
  },
  { // Entry 124
    0x1.f916467349b058b9c38906911b856056p125,
    0x1.60107cp6
  },
  { // Entry 125
    -0x1.f916467349b058b9c38906911b856056p125,
    -0x1.60107cp6
  },
  { // Entry 126
    0x1.6918410000c5ae5656882e7cea64f25bp-2,
    0x1.620054p-2
  },
  { // Entry 127
    -0x1.6918410000c5ae5656882e7cea64f25bp-2,
    -0x1.620054p-2
  },
  { // Entry 128
    0x1.0021063836b49dcc89e4c5aab5e911d1p127,
    0x1.62e4b4p6
  },
  { // Entry 129
    -0x1.0021063836b49dcc89e4c5aab5e911d1p127,
    -0x1.62e4b4p6
  },
  { // Entry 130
    0x1.f40a2c6c7e4eec4c0ed1fae32d255e23p127,
    0x1.6591c4p6
  },
  { // Entry 131
    -0x1.f40a2c6c7e4eec4c0ed1fae32d255e23p127,
    -0x1.6591c4p6
  },
  { // Entry 132
    0x1.ff0714d44fc871ff0c086096f1bf0ae0p127,
    0x1.65a806p6
  },
  { // Entry 133
    -0x1.ff0714d44fc871ff0c086096f1bf0ae0p127,
    -0x1.65a806p6
  },
  { // Entry 134
    0x1.ff70ec400b9c2d8dee878e30b56339bep127,
    0x1.65a8dap6
  },
  { // Entry 135
    -0x1.ff70ec400b9c2d8dee878e30b56339bep127,
    -0x1.65a8dap6
  },
  { // Entry 136
    0x1.fff2d869d07d11d6c64d896f117f0094p127,
    0x1.65a9dep6
  },
  { // Entry 137
    -0x1.fff2d869d07d11d6c64d896f117f0094p127,
    -0x1.65a9dep6
  },
  { // Entry 138
    0x1.6e444103bc8945311358dde7a66bdb38p-2,
    0x1.66dffap-2
  },
  { // Entry 139
    -0x1.6e444103bc8945311358dde7a66bdb38p-2,
    -0x1.66dffap-2
  },
  { // Entry 140
    0x1.67cf01000052cb8c07fcbe6cb68dcc3dp-6,
    0x1.67c79ap-6
  },
  { // Entry 141
    -0x1.67cf01000052cb8c07fcbe6cb68dcc3dp-6,
    -0x1.67c79ap-6
  },
  { // Entry 142
    0x1.7800852fb7173f3c300caca6708f0d6fp-8,
    0x1.77fffep-8
  },
  { // Entry 143
    -0x1.7800852fb7173f3c300caca6708f0d6fp-8,
    -0x1.77fffep-8
  },
  { // Entry 144
    0x1.80000900001033334115f1660750774cp-10,
    0x1.80p-10
  },
  { // Entry 145
    -0x1.80000900001033334115f1660750774cp-10,
    -0x1.80p-10
  },
  { // Entry 146
    0x1.5df91cff9ace26df572d528a8d7e4d99p16,
    0x1.8313eap3
  },
  { // Entry 147
    -0x1.5df91cff9ace26df572d528a8d7e4d99p16,
    -0x1.8313eap3
  },
  { // Entry 148
    0x1.16c370fc40a0ef3180f8a61c8b25157cp1,
    0x1.853c56p0
  },
  { // Entry 149
    -0x1.16c370fc40a0ef3180f8a61c8b25157cp1,
    -0x1.853c56p0
  },
  { // Entry 150
    0x1.880000993055674ae98a9a44aa624509p-12,
    0x1.88p-12
  },
  { // Entry 151
    -0x1.880000993055674ae98a9a44aa624509p-12,
    -0x1.88p-12
  },
  { // Entry 152
    0x1.dab77d03d9ceea48387c7a3e5ebde612p16,
    0x1.8cd558p3
  },
  { // Entry 153
    -0x1.dab77d03d9ceea48387c7a3e5ebde612p16,
    -0x1.8cd558p3
  },
  { // Entry 154
    0x1.b36be4f606d0cd43778f0b56d6c78c69p3,
    0x1.a70ca4p1
  },
  { // Entry 155
    -0x1.b36be4f606d0cd43778f0b56d6c78c69p3,
    -0x1.a70ca4p1
  },
  { // Entry 156
    0x1.9fc768f63e2199d4161ad52c42c43993p8,
    0x1.ae4a96p2
  },
  { // Entry 157
    -0x1.9fc768f63e2199d4161ad52c42c43993p8,
    -0x1.ae4a96p2
  },
  { // Entry 158
    0x1.fddcb5028f3c5f2f9057b275fda963b5p-1,
    0x1.c1c0p-1
  },
  { // Entry 159
    -0x1.fddcb5028f3c5f2f9057b275fda963b5p-1,
    -0x1.c1c0p-1
  },
  { // Entry 160
    0x1.c9d78317aae58861bfa01747e05aaa21p-3,
    0x1.c61c8ep-3
  },
  { // Entry 161
    -0x1.c9d78317aae58861bfa01747e05aaa21p-3,
    -0x1.c61c8ep-3
  },
  { // Entry 162
    0x1.17d46d00e7aa2bd311c9d06faf31cd0fp4,
    0x1.c71c78p1
  },
  { // Entry 163
    -0x1.17d46d00e7aa2bd311c9d06faf31cd0fp4,
    -0x1.c71c78p1
  },
  { // Entry 164
    0x1.d00fdefedbdc86d82e34a1726ce6fd5ep-6,
    0x1.cffffep-6
  },
  { // Entry 165
    -0x1.d00fdefedbdc86d82e34a1726ce6fd5ep-6,
    -0x1.cffffep-6
  },
  { // Entry 166
    0x1.d12f11000068b29f1390f76019d191e9p-12,
    0x1.d12f10p-12
  },
  { // Entry 167
    -0x1.d12f11000068b29f1390f76019d191e9p-12,
    -0x1.d12f10p-12
  },
  { // Entry 168
    0x1.e161430003f635efa46c1b93b40d124ap-2,
    0x1.d13608p-2
  },
  { // Entry 169
    -0x1.e161430003f635efa46c1b93b40d124ap-2,
    -0x1.d13608p-2
  },
  { // Entry 170
    0x1.e518f10016d4233539a6a86b46de305dp9,
    0x1.e48570p2
  },
  { // Entry 171
    -0x1.e518f10016d4233539a6a86b46de305dp9,
    -0x1.e48570p2
  },
  { // Entry 172
    0x1.f882f8ffff8c2c97052fff77b0fe05cap-2,
    0x1.e60da6p-2
  },
  { // Entry 173
    -0x1.f882f8ffff8c2c97052fff77b0fe05cap-2,
    -0x1.e60da6p-2
  },
  { // Entry 174
    0x1.a6565af66cc00367cd4b44acef8fe3b4p1,
    0x1.e8bce0p0
  },
  { // Entry 175
    -0x1.a6565af66cc00367cd4b44acef8fe3b4p1,
    -0x1.e8bce0p0
  },
  { // Entry 176
    0x1.ee2fa5ffffffd478a109217059ddb3a9p-4,
    0x1.ecfeb6p-4
  },
  { // Entry 177
    -0x1.ee2fa5ffffffd478a109217059ddb3a9p-4,
    -0x1.ecfeb6p-4
  },
  { // Entry 178
    0x1.b54f74f65bab12830f959a3e2d7e1c61p1,
    0x1.f14910p0
  },
  { // Entry 179
    -0x1.b54f74f65bab12830f959a3e2d7e1c61p1,
    -0x1.f14910p0
  },
  { // Entry 180
    0x1.b56a96f6fbbb8045af62b07d5d56b656p1,
    0x1.f1584ep0
  },
  { // Entry 181
    -0x1.b56a96f6fbbb8045af62b07d5d56b656p1,
    -0x1.f1584ep0
  },
  { // Entry 182
    0x1.f6e42e000047623ec2a83a461e98dec7p-3,
    0x1.f1f852p-3
  },
  { // Entry 183
    -0x1.f6e42e000047623ec2a83a461e98dec7p-3,
    -0x1.f1f852p-3
  },
  { // Entry 184
    0x1.f6ec1458fb3487aac4bfeec4b6812670p-3,
    0x1.f1fffep-3
  },
  { // Entry 185
    -0x1.f6ec1458fb3487aac4bfeec4b6812670p-3,
    -0x1.f1fffep-3
  },
  { // Entry 186
    0x1.f2fda6fdfa98a35b66e5104fdacd2bd5p-9,
    0x1.f2fd58p-9
  },
  { // Entry 187
    -0x1.f2fda6fdfa98a35b66e5104fdacd2bd5p-9,
    -0x1.f2fd58p-9
  },
  { // Entry 188
    0x1.f8521dffffcd41462b0d73569b1d3819p-3,
    0x1.f35bacp-3
  },
  { // Entry 189
    -0x1.f8521dffffcd41462b0d73569b1d3819p-3,
    -0x1.f35bacp-3
  },
  { // Entry 190
    0x1.f4dda8fe2ec303fc7f7568475545139cp-11,
    0x1.f4dda4p-11
  },
  { // Entry 191
    -0x1.f4dda8fe2ec303fc7f7568475545139cp-11,
    -0x1.f4dda4p-11
  },
  { // Entry 192
    0x1.f51a7d0000ac50ad5402c949ba82e8a3p-11,
    0x1.f51a78p-11
  },
  { // Entry 193
    -0x1.f51a7d0000ac50ad5402c949ba82e8a3p-11,
    -0x1.f51a78p-11
  },
  { // Entry 194
    0x1.a664dced7cb98c68f2b973d65c676a35p21,
    0x1.f7fffep3
  },
  { // Entry 195
    -0x1.a664dced7cb98c68f2b973d65c676a35p21,
    -0x1.f7fffep3
  },
  { // Entry 196
    0x1.f9b658ffff3ce39965e1b291abc9efb8p-4,
    0x1.f86facp-4
  },
  { // Entry 197
    -0x1.f9b658ffff3ce39965e1b291abc9efb8p-4,
    -0x1.f86facp-4
  },
  { // Entry 198
    0x1.28c3fb0016be4fd802e83c9be0d9cad1p0,
    0x1.faaee8p-1
  },
  { // Entry 199
    -0x1.28c3fb0016be4fd802e83c9be0d9cad1p0,
    -0x1.faaee8p-1
  },
  { // Entry 200
    0x1.29b1530000004a3722ae1117c2787152p0,
    0x1.fbe4b0p-1
  },
  { // Entry 201
    -0x1.29b1530000004a3722ae1117c2787152p0,
    -0x1.fbe4b0p-1
  },
  { // Entry 202
    0x1.fc14d4961039dc857c796f56b34af3b3p-6,
    0x1.fbfffep-6
  },
  { // Entry 203
    -0x1.fc14d4961039dc857c796f56b34af3b3p-6,
    -0x1.fbfffep-6
  },
  { // Entry 204
    0x1.fc4d7fd2d8e70ecb66e028137da8ba9dp-7,
    0x1.fc4848p-7
  },
  { // Entry 205
    -0x1.fc4d7fd2d8e70ecb66e028137da8ba9dp-7,
    -0x1.fc4848p-7
  },
  { // Entry 206
    0x1.fce613caa0469e68c720c7696cf35c3dp-9,
    0x1.fce5c0p-9
  },
  { // Entry 207
    -0x1.fce613caa0469e68c720c7696cf35c3dp-9,
    -0x1.fce5c0p-9
  },
  { // Entry 208
    0x1.fdf50fe0194330cfcecb2935b09d09a3p-6,
    0x1.fddffep-6
  },
  { // Entry 209
    -0x1.fdf50fe0194330cfcecb2935b09d09a3p-6,
    -0x1.fddffep-6
  },
  { // Entry 210
    0x1.ff92198272299e9dd5a4315372947bb7p-4,
    0x1.fe3ffep-4
  },
  { // Entry 211
    -0x1.ff92198272299e9dd5a4315372947bb7p-4,
    -0x1.fe3ffep-4
  },
  { // Entry 212
    0x1.fed49818a86c9e5d357348cc86552ecfp-5,
    0x1.fe7ffep-5
  },
  { // Entry 213
    -0x1.fed49818a86c9e5d357348cc86552ecfp-5,
    -0x1.fe7ffep-5
  },
  { // Entry 214
    0x1.3d59d2d8b22b41c2bb6334c9be7be902p91,
    0x1.ffdffep5
  },
  { // Entry 215
    -0x1.3d59d2d8b22b41c2bb6334c9be7be902p91,
    -0x1.ffdffep5
  },
  { // Entry 216
    0x1.fff77f554451e1f58b2d5e1ecc407a66p-12,
    0x1.fff77ep-12
  },
  { // Entry 217
    -0x1.fff77f554451e1f58b2d5e1ecc407a66p-12,
    -0x1.fff77ep-12
  },
  { // Entry 218
    0x1.7474c2f9144f003acd66e60d58643f07p10,
    0x1.fff8cep2
  },
  { // Entry 219
    -0x1.7474c2f9144f003acd66e60d58643f07p10,
    -0x1.fff8cep2
  },
  { // Entry 220
    0x1.b495d8f96ad2507c36e288f42ed69c65p4,
    0x1.fffcp1
  },
  { // Entry 221
    -0x1.b495d8f96ad2507c36e288f42ed69c65p4,
    -0x1.fffcp1
  },
  { // Entry 222
    0x1.2cd7476ede0aac2c3be4d81efc1fae2bp0,
    0x1.fffc7ep-1
  },
  { // Entry 223
    -0x1.2cd7476ede0aac2c3be4d81efc1fae2bp0,
    -0x1.fffc7ep-1
  },
  { // Entry 224
    0x1.d03a90ffffa72affa30aae2126410fd3p1,
    0x1.fffebap0
  },
  { // Entry 225
    -0x1.d03a90ffffa72affa30aae2126410fd3p1,
    -0x1.fffebap0
  },
  { // Entry 226
    0x1.b4a0e9ff76786bf6ec2ea4f53a42a118p4,
    0x1.ffff3ep1
  },
  { // Entry 227
    -0x1.b4a0e9ff76786bf6ec2ea4f53a42a118p4,
    -0x1.ffff3ep1
  },
  { // Entry 228
    0.0,
    0.0
  },
  { // Entry 229
    0x1.24d1fe8cfad7f98fcdbea5882af8e32dp-4,
    0x1.24924ap-4
  },
  { // Entry 230
    -0x1.24d1fe8cfad7f98fcdbea5882af8e32dp-4,
    -0x1.24924ap-4
  },
  { // Entry 231
    0x1.25914e250092e5c3cddf2040afd79c65p-3,
    0x1.24924ap-3
  },
  { // Entry 232
    -0x1.25914e250092e5c3cddf2040afd79c65p-3,
    -0x1.24924ap-3
  },
  { // Entry 233
    0x1.ba393734ca25f6f4197cc41844ff6e7dp-3,
    0x1.b6db70p-3
  },
  { // Entry 234
    -0x1.ba393734ca25f6f4197cc41844ff6e7dp-3,
    -0x1.b6db70p-3
  },
  { // Entry 235
    0x1.28917b1a67c439ef2a28337ebef6dc3cp-2,
    0x1.24924ap-2
  },
  { // Entry 236
    -0x1.28917b1a67c439ef2a28337ebef6dc3cp-2,
    -0x1.24924ap-2
  },
  { // Entry 237
    0x1.7589df829503fa20ed8774c31e6a332cp-2,
    0x1.6db6dcp-2
  },
  { // Entry 238
    -0x1.7589df829503fa20ed8774c31e6a332cp-2,
    -0x1.6db6dcp-2
  },
  { // Entry 239
    0x1.c46a5c1d32d4860b81155aef808f7d0fp-2,
    0x1.b6db6ep-2
  },
  { // Entry 240
    -0x1.c46a5c1d32d4860b81155aef808f7d0fp-2,
    -0x1.b6db6ep-2
  },
  { // Entry 241
    0x1.0acd00fe63b96ca357895761ae66224ap-1,
    0x1.p-1
  },
  { // Entry 242
    -0x1.0acd00fe63b96ca357895761ae66224ap-1,
    -0x1.p-1
  },
  { // Entry 243
    0x1.0acd00fe63b96ca357895761ae66224ap-1,
    0x1.p-1
  },
  { // Entry 244
    -0x1.0acd00fe63b96ca357895761ae66224ap-1,
    -0x1.p-1
  },
  { // Entry 245
    0x1.34c1747f635dfc16c1d88e5910239fe8p-1,
    0x1.24924ap-1
  },
  { // Entry 246
    -0x1.34c1747f635dfc16c1d88e5910239fe8p-1,
    -0x1.24924ap-1
  },
  { // Entry 247
    0x1.604959cb9dca66a6c6b1d52214b88901p-1,
    0x1.492494p-1
  },
  { // Entry 248
    -0x1.604959cb9dca66a6c6b1d52214b88901p-1,
    -0x1.492494p-1
  },
  { // Entry 249
    0x1.8d9d92611935ee8bcc9e9c1bbcb4ec0dp-1,
    0x1.6db6dep-1
  },
  { // Entry 250
    -0x1.8d9d92611935ee8bcc9e9c1bbcb4ec0dp-1,
    -0x1.6db6dep-1
  },
  { // Entry 251
    0x1.bcf9593d2ecc12e3836d15a1067a7896p-1,
    0x1.924928p-1
  },
  { // Entry 252
    -0x1.bcf9593d2ecc12e3836d15a1067a7896p-1,
    -0x1.924928p-1
  },
  { // Entry 253
    0x1.ee9a9041b2e77dc8645b07cd35bf1333p-1,
    0x1.b6db72p-1
  },
  { // Entry 254
    -0x1.ee9a9041b2e77dc8645b07cd35bf1333p-1,
    -0x1.b6db72p-1
  },
  { // Entry 255
    0x1.116108889abd3fd6df9a909af5b4b3abp0,
    0x1.db6dbcp-1
  },
  { // Entry 256
    -0x1.116108889abd3fd6df9a909af5b4b3abp0,
    -0x1.db6dbcp-1
  },
  { // Entry 257
    0x1.2cd9fc44eb9825a80249487f064ffd5cp0,
    0x1.p0
  },
  { // Entry 258
    -0x1.2cd9fc44eb9825a80249487f064ffd5cp0,
    -0x1.p0
  },
  { // Entry 259
    0.0,
    0.0
  },
  { // Entry 260
    0x1.18e1df94a3c9eec616f3c33e116ff136p-6,
    0x1.18de5ap-6
  },
  { // Entry 261
    -0x1.18e1df94a3c9eec616f3c33e116ff136p-6,
    -0x1.18de5ap-6
  },
  { // Entry 262
    0x1.18ec707b41cb05757f702b2e7bc8168fp-5,
    0x1.18de5ap-5
  },
  { // Entry 263
    -0x1.18ec707b41cb05757f702b2e7bc8168fp-5,
    -0x1.18de5ap-5
  },
  { // Entry 264
    0x1.a57d14c544db6f79ccb29cf647ec3bd6p-5,
    0x1.a54d88p-5
  },
  { // Entry 265
    -0x1.a57d14c544db6f79ccb29cf647ec3bd6p-5,
    -0x1.a54d88p-5
  },
  { // Entry 266
    0x1.1916b67842dff1025e79e06864bad805p-4,
    0x1.18de5ap-4
  },
  { // Entry 267
    -0x1.1916b67842dff1025e79e06864bad805p-4,
    -0x1.18de5ap-4
  },
  { // Entry 268
    0x1.5f840854828275e07b52147a0b34cec2p-4,
    0x1.5f15f0p-4
  },
  { // Entry 269
    -0x1.5f840854828275e07b52147a0b34cec2p-4,
    -0x1.5f15f0p-4
  },
  { // Entry 270
    0x1.a60bcc64888b5d1a7338b1a0f9243f1ep-4,
    0x1.a54d86p-4
  },
  { // Entry 271
    -0x1.a60bcc64888b5d1a7338b1a0f9243f1ep-4,
    -0x1.a54d86p-4
  },
  { // Entry 272
    0x1.ecb35112d674d05785ec00066c2b3ec8p-4,
    0x1.eb851cp-4
  },
  { // Entry 273
    -0x1.ecb35112d674d05785ec00066c2b3ec8p-4,
    -0x1.eb851cp-4
  },
  { // Entry 274
    0x1.ecb35316874ebf73aba92491a44e079fp-4,
    0x1.eb851ep-4
  },
  { // Entry 275
    -0x1.ecb35316874ebf73aba92491a44e079fp-4,
    -0x1.eb851ep-4
  },
  { // Entry 276
    0x1.02243d1276143106404fa4cb3fcadf33p-3,
    0x1.01767ep-3
  },
  { // Entry 277
    -0x1.02243d1276143106404fa4cb3fcadf33p-3,
    -0x1.01767ep-3
  },
  { // Entry 278
    0x1.0df0f8011126593efedda045c8fa0e09p-3,
    0x1.0d2a6cp-3
  },
  { // Entry 279
    -0x1.0df0f8011126593efedda045c8fa0e09p-3,
    -0x1.0d2a6cp-3
  },
  { // Entry 280
    0x1.19bff49926d4870c4cae1f4076b8e37ap-3,
    0x1.18de5ap-3
  },
  { // Entry 281
    -0x1.19bff49926d4870c4cae1f4076b8e37ap-3,
    -0x1.18de5ap-3
  },
  { // Entry 282
    0x1.25914c1fc4d40b236a218f858c70fb53p-3,
    0x1.249248p-3
  },
  { // Entry 283
    -0x1.25914c1fc4d40b236a218f858c70fb53p-3,
    -0x1.249248p-3
  },
  { // Entry 284
    0x1.316517df03194e62cdc39c303b8105ffp-3,
    0x1.304636p-3
  },
  { // Entry 285
    -0x1.316517df03194e62cdc39c303b8105ffp-3,
    -0x1.304636p-3
  },
  { // Entry 286
    0x1.3d3b712639f615986771a910d344617ep-3,
    0x1.3bfa24p-3
  },
  { // Entry 287
    -0x1.3d3b712639f615986771a910d344617ep-3,
    -0x1.3bfa24p-3
  },
  { // Entry 288
    0x1.4914714a38430228edb55e7949c30a96p-3,
    0x1.47ae12p-3
  },
  { // Entry 289
    -0x1.4914714a38430228edb55e7949c30a96p-3,
    -0x1.47ae12p-3
  },
  { // Entry 290
    0x1.49147350c990b8731b5aa06b375e9ad0p-3,
    0x1.47ae14p-3
  },
  { // Entry 291
    -0x1.49147350c990b8731b5aa06b375e9ad0p-3,
    -0x1.47ae14p-3
  },
  { // Entry 292
    0x1.227b2f3d30af1d4e22444c8e7f338460p-2,
    0x1.1eb852p-2
  },
  { // Entry 293
    -0x1.227b2f3d30af1d4e22444c8e7f338460p-2,
    -0x1.1eb852p-2
  },
  { // Entry 294
    0x1.a49c42670497025996a8b3ff42a49c6fp-2,
    0x1.99999ap-2
  },
  { // Entry 295
    -0x1.a49c42670497025996a8b3ff42a49c6fp-2,
    -0x1.99999ap-2
  },
  { // Entry 296
    0x1.1666dcd198ff92b46da6bfab8aba56a0p-1,
    0x1.0a3d70p-1
  },
  { // Entry 297
    -0x1.1666dcd198ff92b46da6bfab8aba56a0p-1,
    -0x1.0a3d70p-1
  },
  { // Entry 298
    0x1.5e8321e07e76d08e1e985ab3cd7da5b6p-1,
    0x1.47ae14p-1
  },
  { // Entry 299
    -0x1.5e8321e07e76d08e1e985ab3cd7da5b6p-1,
    -0x1.47ae14p-1
  },
  { // Entry 300
    0x1.abad14f0aa07a2fd5cc86f6098a8cf80p-1,
    0x1.851eb8p-1
  },
  { // Entry 301
    -0x1.abad14f0aa07a2fd5cc86f6098a8cf80p-1,
    -0x1.851eb8p-1
  },
  { // Entry 302
    0x1.ff0182668411539d3db9b8fd9af11fd0p-1,
    0x1.c28f5cp-1
  },
  { // Entry 303
    -0x1.ff0182668411539d3db9b8fd9af11fd0p-1,
    -0x1.c28f5cp-1
  },
  { // Entry 304
    0x1.2cd9fc44eb9825a80249487f064ffd5cp0,
    0x1.p0
  },
  { // Entry 305
    -0x1.2cd9fc44eb9825a80249487f064ffd5cp0,
    -0x1.p0
  },
  { // Entry 306
    0x1.2cd9fc44eb9825a80249487f064ffd5cp0,
    0x1.p0
  },
  { // Entry 307
    -0x1.2cd9fc44eb9825a80249487f064ffd5cp0,
    -0x1.p0
  },
  { // Entry 308
    0x1.95525e4a2ef718eb0754642866b5a7d4p3,
    0x1.9de826p1
  },
  { // Entry 309
    -0x1.95525e4a2ef718eb0754642866b5a7d4p3,
    -0x1.9de826p1
  },
  { // Entry 310
    0x1.d9a0eee58bbd37706f9307edad7da7ecp6,
    0x1.5de826p2
  },
  { // Entry 311
    -0x1.d9a0eee58bbd37706f9307edad7da7ecp6,
    -0x1.5de826p2
  },
  { // Entry 312
    0x1.144da80a2e3513241fedacab70954631p10,
    0x1.ecdc38p2
  },
  { // Entry 313
    -0x1.144da80a2e3513241fedacab70954631p10,
    -0x1.ecdc38p2
  },
  { // Entry 314
    0x1.425f2a3eb0771d774c3e790cd0f40c63p13,
    0x1.3de826p3
  },
  { // Entry 315
    -0x1.425f2a3eb0771d774c3e790cd0f40c63p13,
    -0x1.3de826p3
  },
  { // Entry 316
    0x1.781f001b7cc45e8c057d098d300a73d1p16,
    0x1.856230p3
  },
  { // Entry 317
    -0x1.781f001b7cc45e8c057d098d300a73d1p16,
    -0x1.856230p3
  },
  { // Entry 318
    0x1.b6d506c59d8cbe5c54f7f8927c597f84p19,
    0x1.ccdc3ap3
  },
  { // Entry 319
    -0x1.b6d506c59d8cbe5c54f7f8927c597f84p19,
    -0x1.ccdc3ap3
  },
  { // Entry 320
    0x1.ffffc188ace6b110a80fe49615910ff2p22,
    0x1.0a2b22p4
  },
  { // Entry 321
    -0x1.ffffc188ace6b110a80fe49615910ff2p22,
    -0x1.0a2b22p4
  },
  { // Entry 322
    0x1.ffffc103c9f0158d22d963e5b764c750p14,
    0x1.62e42cp3
  },
  { // Entry 323
    -0x1.ffffc103c9f0158d22d963e5b764c750p14,
    -0x1.62e42cp3
  },
  { // Entry 324
    0x1.ffffe103c7009212034b389759a93fddp14,
    0x1.62e42ep3
  },
  { // Entry 325
    -0x1.ffffe103c7009212034b389759a93fddp14,
    -0x1.62e42ep3
  },
  { // Entry 326
    0x1.00000081e308873bf3c21c42db0354c7p15,
    0x1.62e430p3
  },
  { // Entry 327
    -0x1.00000081e308873bf3c21c42db0354c7p15,
    -0x1.62e430p3
  },
  { // Entry 328
    0x1.fffde082c48329d920ae3d83c4008840p6,
    0x1.62e42cp2
  },
  { // Entry 329
    -0x1.fffde082c48329d920ae3d83c4008840p6,
    -0x1.62e42cp2
  },
  { // Entry 330
    0x1.fffdf082d3c741b1c6dfdaeedbc1cf8ep6,
    0x1.62e42ep2
  },
  { // Entry 331
    -0x1.fffdf082d3c741b1c6dfdaeedbc1cf8ep6,
    -0x1.62e42ep2
  },
  { // Entry 332
    0x1.fffe0082e38b59068dc66cd507e027edp6,
    0x1.62e430p2
  },
  { // Entry 333
    -0x1.fffe0082e38b59068dc66cd507e027edp6,
    -0x1.62e430p2
  },
  { // Entry 334
    0x1.fdfff031b333717da1077c4a50b5cc66p2,
    0x1.62e42cp1
  },
  { // Entry 335
    -0x1.fdfff031b333717da1077c4a50b5cc66p2,
    -0x1.62e42cp1
  },
  { // Entry 336
    0x1.fdfff839b304a63e7b93e68eccb8b8e4p2,
    0x1.62e42ep1
  },
  { // Entry 337
    -0x1.fdfff839b304a63e7b93e68eccb8b8e4p2,
    -0x1.62e42ep1
  },
  { // Entry 338
    0x1.fe000041b2f5bafed9bb81482ca2b8c4p2,
    0x1.62e430p1
  },
  { // Entry 339
    -0x1.fe000041b2f5bafed9bb81482ca2b8c4p2,
    -0x1.62e430p1
  },
  { // Entry 340
    0x1.dffff7a2c45cc12beb2065181f0d2495p0,
    0x1.62e42cp0
  },
  { // Entry 341
    -0x1.dffff7a2c45cc12beb2065181f0d2495p0,
    -0x1.62e42cp0
  },
  { // Entry 342
    0x1.dffffbe2c451be866a16d0ecdd9b167ep0,
    0x1.62e42ep0
  },
  { // Entry 343
    -0x1.dffffbe2c451be866a16d0ecdd9b167ep0,
    -0x1.62e42ep0
  },
  { // Entry 344
    0x1.e0000022c44e3be0d8984e0b1642ab45p0,
    0x1.62e430p0
  },
  { // Entry 345
    -0x1.e0000022c44e3be0d8984e0b1642ab45p0,
    -0x1.62e430p0
  },
  { // Entry 346
    0x1.7ffffb14737c377a230d14a4c1d143bdp-1,
    0x1.62e42cp-1
  },
  { // Entry 347
    -0x1.7ffffb14737c377a230d14a4c1d143bdp-1,
    -0x1.62e42cp-1
  },
  { // Entry 348
    0x1.7ffffd94737a03bf6ea2e40ff28f406bp-1,
    0x1.62e42ep-1
  },
  { // Entry 349
    -0x1.7ffffd94737a03bf6ea2e40ff28f406bp-1,
    -0x1.62e42ep-1
  },
  { // Entry 350
    0x1.8000001473795004b7cd26f5470cab89p-1,
    0x1.62e430p-1
  },
  { // Entry 351
    -0x1.8000001473795004b7cd26f5470cab89p-1,
    -0x1.62e430p-1
  },
  { // Entry 352
    0x1.6a09e23b307ca82c1b1f6dd4a0d1ed94p-2,
    0x1.62e42cp-2
  },
  { // Entry 353
    -0x1.6a09e23b307ca82c1b1f6dd4a0d1ed94p-2,
    -0x1.62e42cp-2
  },
  { // Entry 354
    0x1.6a09e45a3f55bf3a68e492142f0e7acfp-2,
    0x1.62e42ep-2
  },
  { // Entry 355
    -0x1.6a09e45a3f55bf3a68e492142f0e7acfp-2,
    -0x1.62e42ep-2
  },
  { // Entry 356
    0x1.6a09e6794e2f30cb2fc046292efc5a1dp-2,
    0x1.62e430p-2
  },
  { // Entry 357
    -0x1.6a09e6794e2f30cb2fc046292efc5a1dp-2,
    -0x1.62e430p-2
  },
  { // Entry 358
    0x1.64ab8b624500dcc74dc5de97a0720aabp-3,
    0x1.62e42cp-3
  },
  { // Entry 359
    -0x1.64ab8b624500dcc74dc5de97a0720aabp-3,
    -0x1.62e42cp-3
  },
  { // Entry 360
    0x1.64ab8d69f9de29ffa2a5944cf26374fap-3,
    0x1.62e42ep-3
  },
  { // Entry 361
    -0x1.64ab8d69f9de29ffa2a5944cf26374fap-3,
    -0x1.62e42ep-3
  },
  { // Entry 362
    0x1.64ab8f71aebb8d82b05be9a027129269p-3,
    0x1.62e430p-3
  },
  { // Entry 363
    -0x1.64ab8f71aebb8d82b05be9a027129269p-3,
    -0x1.62e430p-3
  },
  { // Entry 364
    0x1.6355e30c5322853739b87125ec22bdecp-4,
    0x1.62e42cp-4
  },
  { // Entry 365
    -0x1.6355e30c5322853739b87125ec22bdecp-4,
    -0x1.62e42cp-4
  },
  { // Entry 366
    0x1.6355e50e3f6d2cc2dd6e747f61bb8c65p-4,
    0x1.62e42ep-4
  },
  { // Entry 367
    -0x1.6355e50e3f6d2cc2dd6e747f61bb8c65p-4,
    -0x1.62e42ep-4
  },
  { // Entry 368
    0x1.6355e7102bb7d9dbd8b8b0d68c09401bp-4,
    0x1.62e430p-4
  },
  { // Entry 369
    -0x1.6355e7102bb7d9dbd8b8b0d68c09401bp-4,
    -0x1.62e430p-4
  },
  { // Entry 370
    0x1.630097b6aaea36d905a1e74a332b0102p-5,
    0x1.62e42cp-5
  },
  { // Entry 371
    -0x1.630097b6aaea36d905a1e74a332b0102p-5,
    -0x1.62e42cp-5
  },
  { // Entry 372
    0x1.630099b725ee198cf48f439e2807bf07p-5,
    0x1.62e42ep-5
  },
  { // Entry 373
    -0x1.630099b725ee198cf48f439e2807bf07p-5,
    -0x1.62e42ep-5
  },
  { // Entry 374
    0x1.63009bb7a0f1fda3e41657180afe2797p-5,
    0x1.62e430p-5
  },
  { // Entry 375
    -0x1.63009bb7a0f1fda3e41657180afe2797p-5,
    -0x1.62e430p-5
  },
  { // Entry 376
    0x1.62eb46cce5848efc0a888499742bfd4cp-6,
    0x1.62e42cp-6
  },
  { // Entry 377
    -0x1.62eb46cce5848efc0a888499742bfd4cp-6,
    -0x1.62e42cp-6
  },
  { // Entry 378
    0x1.62eb48cd04449b44496ceeff57490075p-6,
    0x1.62e42ep-6
  },
  { // Entry 379
    -0x1.62eb48cd04449b44496ceeff57490075p-6,
    -0x1.62e42ep-6
  },
  { // Entry 380
    0x1.62eb4acd2304a7e543238ca64b8cd689p-6,
    0x1.62e430p-6
  },
  { // Entry 381
```
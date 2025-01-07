Response:
The user is asking for a summary of the functionality of the provided C source code file.
The file is located in `bionic/tests/math_data/cos_intel_data.handroid` and is part of Android's bionic library.
The code defines a static array `g_cos_intel_data` of a template type `data_1_1_t<double, double>`.
Each element in the array is an initializer list containing two double-precision floating-point numbers represented in hexadecimal format.
The name of the file and the array suggest that this data is related to the cosine function.
Specifically, it seems to be a set of input-output pairs for testing the implementation of the cosine function, potentially optimized for Intel architectures (due to "intel" in the filename).
The "handroid" likely signifies that this data is specific to the Android environment.

Therefore, the primary function of this code is to provide test data for the cosine function in the Android bionic library.

**Summary:** The provided code defines a static array of double-precision floating-point number pairs intended as test data for the cosine function within Android's bionic library. This data is likely used for verifying the correctness and accuracy of the cosine implementation, possibly with optimizations specific to Intel architectures.
这是定义了一个用于测试 `cos` 函数的静态数据数组。

**具体来说，它的功能是:**

1. **提供测试用例:**  `g_cos_intel_data` 数组包含了大量的预设输入和对应的预期输出值，用于测试 `cos` 函数的实现。
2. **验证 `cos` 函数的准确性:** 通过将数组中的第一个 `double` 值作为 `cos` 函数的输入，并与数组中的第二个 `double` 值进行比较，可以验证 `cos` 函数在不同输入下的计算结果是否正确。
3. **针对特定架构的测试数据:** 文件名中的 "intel" 表明这些测试数据可能是为了验证在 Intel 架构上的 `cos` 函数实现的准确性，可能涵盖了该架构下的特定优化或边缘情况。
4. **作为 bionic 库测试套件的一部分:**  该文件位于 `bionic/tests` 目录下，表明它是 bionic 库的自动化测试套件的一部分，用于确保 bionic 库中 `cos` 函数的质量和可靠性。

**与 Android 功能的关系举例说明:**

在 Android 系统中，许多上层应用和 Framework 层的功能都依赖于底层的数学运算，例如：

* **图形渲染:**  计算旋转、缩放、平移等变换时会用到三角函数，`cos` 函数就是其中之一。例如，在 SurfaceFlinger 中进行图层合成时，可能需要计算旋转角度对应的余弦值。
* **动画效果:**  动画的缓动函数、路径计算等也可能涉及到三角函数。例如，一个视图的平滑旋转动画就需要不断计算角度对应的余弦值。
* **传感器数据处理:**  某些传感器（如加速度计、陀螺仪）的数据处理可能需要用到三角函数进行坐标转换或者角度计算。
* **音频处理:**  音频信号的生成、分析和处理也会用到三角函数。

这个 `cos_intel_data.handroid` 文件提供的测试数据，就是为了确保 Android 系统在进行这些操作时，底层的 `cos` 函数能够提供精确的结果。如果 `cos` 函数的实现有错误，可能会导致图形渲染错误、动画不流畅、传感器数据不准确等问题。

**总结:**

该文件的核心功能是提供了一系列预定义的输入输出对，用于测试 Android bionic 库中 `cos` 函数在 Intel 架构上的实现是否正确和精确。它是 Android 底层数学库质量保证的关键组成部分。

Prompt: 
```
这是目录为bionic/tests/math_data/cos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_cos_intel_data[] = {
  { // Entry 0
    0x1.c1a27ae836f128000000000000504e9bp-1,
    0x1.feb1f7920e248p-2
  },
  { // Entry 1
    0x1.c1a27ae836f128000000000000504e9bp-1,
    -0x1.feb1f7920e248p-2
  },
  { // Entry 2
    0x1.78daf01036d0cfffffffffffff9890d6p-1,
    0x1.7cb7648526f99p-1
  },
  { // Entry 3
    0x1.78daf01036d0cfffffffffffff9890d6p-1,
    -0x1.7cb7648526f99p-1
  },
  { // Entry 4
    0x1.ff8eb6a91ecb000000000000001f8f56p-1,
    0x1.549ec0c0c5afap-5
  },
  { // Entry 5
    0x1.ff8eb6a91ecb000000000000001f8f56p-1,
    -0x1.549ec0c0c5afap-5
  },
  { // Entry 6
    0x1.fed0476fc75c9800000000000020b13ep-1,
    0x1.16e534ee36580p-4
  },
  { // Entry 7
    0x1.fed0476fc75c9800000000000020b13ep-1,
    -0x1.16e534ee36580p-4
  },
  { // Entry 8
    0x1.f10fc61e2c78efffffffffffff87666ap-1,
    0x1.efeef61d39ac2p-3
  },
  { // Entry 9
    0x1.f10fc61e2c78efffffffffffff87666ap-1,
    -0x1.efeef61d39ac2p-3
  },
  { // Entry 10
    0x1.434a3645be2087ffffffffffff72d0aep-1,
    0x1.c65a170474549p-1
  },
  { // Entry 11
    0x1.434a3645be2087ffffffffffff72d0aep-1,
    -0x1.c65a170474549p-1
  },
  { // Entry 12
    0x1.337fc5b072c52800000000000017fe77p-3,
    0x1.6b8a6273d7c21p0
  },
  { // Entry 13
    0x1.337fc5b072c52800000000000017fe77p-3,
    -0x1.6b8a6273d7c21p0
  },
  { // Entry 14
    0x1.efa7cddb128fb8004356877b74ee8abdp-1,
    -0x1.036f4ba7e90aap-2
  },
  { // Entry 15
    0x1.efa7cddb128fb8004356877b74ee8abdp-1,
    0x1.036f4ba7e90aap-2
  },
  { // Entry 16
    0x1.fffffffffffffffb5117fee2eda7f13ep-1,
    -0x1.1500766c9df20p-31
  },
  { // Entry 17
    0x1.fffffffffffffffb5117fee2eda7f13ep-1,
    0x1.1500766c9df20p-31
  },
  { // Entry 18
    0x1.ec231802917bdffa627ab6a59abe3f7dp-1,
    -0x1.1e2a1563e068ep-2
  },
  { // Entry 19
    0x1.ec231802917bdffa627ab6a59abe3f7dp-1,
    0x1.1e2a1563e068ep-2
  },
  { // Entry 20
    0x1.dc044ac92b7fb9007913c87db76fa49fp-8,
    -0x1.2115aa73f8d05p5
  },
  { // Entry 21
    0x1.dc044ac92b7fb9007913c87db76fa49fp-8,
    0x1.2115aa73f8d05p5
  },
  { // Entry 22
    0x1.d1fa67c50dd527f6e9abbb0bd0664ab9p-4,
    -0x1.34e3bcdf8f69ap2
  },
  { // Entry 23
    0x1.d1fa67c50dd527f6e9abbb0bd0664ab9p-4,
    0x1.34e3bcdf8f69ap2
  },
  { // Entry 24
    0x1.e2f8d19fb8db88056dcddd76f5a05c20p-2,
    -0x1.380000000000bp7
  },
  { // Entry 25
    0x1.e2f8d19fb8db88056dcddd76f5a05c20p-2,
    0x1.380000000000bp7
  },
  { // Entry 26
    0x1.8da9c90c3eda17f5bd708cfc414ff1b8p-1,
    -0x1.440000004p6
  },
  { // Entry 27
    0x1.8da9c90c3eda17f5bd708cfc414ff1b8p-1,
    0x1.440000004p6
  },
  { // Entry 28
    0x1.b59b320603f837ff015e2a961e75946ep-1,
    -0x1.550c8ee67a4c4p29
  },
  { // Entry 29
    0x1.b59b320603f837ff015e2a961e75946ep-1,
    0x1.550c8ee67a4c4p29
  },
  { // Entry 30
    0x1.ffffff7af6c887e5f3186371a17dd81fp-1,
    -0x1.711789fdb2e8ap-13
  },
  { // Entry 31
    0x1.ffffff7af6c887e5f3186371a17dd81fp-1,
    0x1.711789fdb2e8ap-13
  },
  { // Entry 32
    0x1.c1b68ebb0b4fe82e8e99f9d425ee901ap-2,
    -0x1.77e000002p8
  },
  { // Entry 33
    0x1.c1b68ebb0b4fe82e8e99f9d425ee901ap-2,
    0x1.77e000002p8
  },
  { // Entry 34
    0x1.1161e1dad76dbfd55f08c4a4a90bd547p-4,
    -0x1.8106561931b43p0
  },
  { // Entry 35
    0x1.1161e1dad76dbfd55f08c4a4a90bd547p-4,
    0x1.8106561931b43p0
  },
  { // Entry 36
    0x1.f828c3226b3d77c374e789d7216a85b3p-5,
    -0x1.825be2461cad4p0
  },
  { // Entry 37
    0x1.f828c3226b3d77c374e789d7216a85b3p-5,
    0x1.825be2461cad4p0
  },
  { // Entry 38
    0x1.f2990d742e9fa80dd19483a2c0de428bp-5,
    -0x1.8288755803b08p0
  },
  { // Entry 39
    0x1.f2990d742e9fa80dd19483a2c0de428bp-5,
    0x1.8288755803b08p0
  },
  { // Entry 40
    -0x1.ff150dda7524ce678ab97ee460e8e961p-1,
    -0x1.8a75701f4ccd3p1
  },
  { // Entry 41
    -0x1.ff150dda7524ce678ab97ee460e8e961p-1,
    0x1.8a75701f4ccd3p1
  },
  { // Entry 42
    0x1.015c47c32b574802eb81deb0db46c207p-1,
    -0x1.b389316f37f37p3
  },
  { // Entry 43
    0x1.015c47c32b574802eb81deb0db46c207p-1,
    0x1.b389316f37f37p3
  },
  { // Entry 44
    0x1.d681a366a05347fa56b75d845b33c7bbp-1,
    -0x1.c602c465d7d27p6
  },
  { // Entry 45
    0x1.d681a366a05347fa56b75d845b33c7bbp-1,
    0x1.c602c465d7d27p6
  },
  { // Entry 46
    -0x1.84e896c7543d54c16d7be346e0f40017p-1,
    -0x1.cfb81fe69664cp4
  },
  { // Entry 47
    -0x1.84e896c7543d54c16d7be346e0f40017p-1,
    0x1.cfb81fe69664cp4
  },
  { // Entry 48
    0x1.fc5dcfddd54c07f1574ce114c1e5effep-1,
    -0x1.d08f2d86b12c6p13
  },
  { // Entry 49
    0x1.fc5dcfddd54c07f1574ce114c1e5effep-1,
    0x1.d08f2d86b12c6p13
  },
  { // Entry 50
    0x1.fe83235fbe015d6c361556ee5a0e2294p-3,
    -0x1.de13f0943c494p99
  },
  { // Entry 51
    0x1.fe83235fbe015d6c361556ee5a0e2294p-3,
    0x1.de13f0943c494p99
  },
  { // Entry 52
    -0x1.720321239ec4f38d55b40d8445099c2ap-1,
    -0x1.de3c1f1285e8bp3
  },
  { // Entry 53
    -0x1.720321239ec4f38d55b40d8445099c2ap-1,
    0x1.de3c1f1285e8bp3
  },
  { // Entry 54
    0x1.f7143c8bba406d6f834a3bca5e9c6a58p-4,
    -0x1.fffffffffff7fp1023
  },
  { // Entry 55
    0x1.f7143c8bba406d6f834a3bca5e9c6a58p-4,
    0x1.fffffffffff7fp1023
  },
  { // Entry 56
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 57
    -0x1.fffe62ecfab753c071b2680e1e26bbcep-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 58
    0x1.055e457ac122766a7a343ea4ac739b2ep-5,
    0x1.0000000000001p51
  },
  { // Entry 59
    0x1.055e457ac122766a7a343ea4ac739b2ep-5,
    -0x1.0000000000001p51
  },
  { // Entry 60
    0x1.c1528065b7d4e2d84d640301800ddd81p-1,
    0x1.0000000000003p-1
  },
  { // Entry 61
    0x1.c1528065b7d4e2d84d640301800ddd81p-1,
    -0x1.0000000000003p-1
  },
  { // Entry 62
    0x1.fffffffffffffffeffffffffffffa0p-1,
    0x1.0000000000003p-32
  },
  { // Entry 63
    0x1.fffffffffffffffeffffffffffffa0p-1,
    -0x1.0000000000003p-32
  },
  { // Entry 64
    0x1.fffea444bc05e0b2ec693f7226d056b8p-1,
    0x1.0000000000020p150
  },
  { // Entry 65
    0x1.fffea444bc05e0b2ec693f7226d056b8p-1,
    -0x1.0000000000020p150
  },
  { // Entry 66
    -0x1.ebddee876f4338cc885394d1039acfe1p-1,
    0x1.0000000000038p380
  },
  { // Entry 67
    -0x1.ebddee876f4338cc885394d1039acfe1p-1,
    -0x1.0000000000038p380
  },
  { // Entry 68
    -0x1.f2ffc51dc69681ded33362645b4e8513p-1,
    0x1.0000000000118p380
  },
  { // Entry 69
    -0x1.f2ffc51dc69681ded33362645b4e8513p-1,
    -0x1.0000000000118p380
  },
  { // Entry 70
    -0x1.f8fbb4d358b207f4f81c36cf21c4af97p-1,
    0x1.00000000003ffp641
  },
  { // Entry 71
    -0x1.f8fbb4d358b207f4f81c36cf21c4af97p-1,
    -0x1.00000000003ffp641
  },
  { // Entry 72
    -0x1.aa2265753e6687fde76269ee92a784b0p-2,
    0x1.00000000010p1
  },
  { // Entry 73
    -0x1.aa2265753e6687fde76269ee92a784b0p-2,
    -0x1.00000000010p1
  },
  { // Entry 74
    0x1.fd1242c25994d0cc5daf405fa510e539p-1,
    0x1.000000008p452
  },
  { // Entry 75
    0x1.fd1242c25994d0cc5daf405fa510e539p-1,
    -0x1.000000008p452
  },
  { // Entry 76
    0x1.fffc0001554da8000048828de97acccbp-1,
    0x1.00000000effafp-7
  },
  { // Entry 77
    0x1.fffc0001554da8000048828de97acccbp-1,
    -0x1.00000000effafp-7
  },
  { // Entry 78
    0x1.14a27f292552280000dd30fbf6b38481p-1,
    0x1.00000114fefe2p0
  },
  { // Entry 79
    0x1.14a27f292552280000dd30fbf6b38481p-1,
    -0x1.00000114fefe2p0
  },
  { // Entry 80
    0x1.bf81e0269c59c7ff753ca32147666c56p-3,
    0x1.0000070p40
  },
  { // Entry 81
    0x1.bf81e0269c59c7ff753ca32147666c56p-3,
    -0x1.0000070p40
  },
  { // Entry 82
    0x1.14a26ed1960d67ffffdf8d13b43fa2b4p-1,
    0x1.00000acadb3d3p0
  },
  { // Entry 83
    0x1.14a26ed1960d67ffffdf8d13b43fa2b4p-1,
    -0x1.00000acadb3d3p0
  },
  { // Entry 84
    0x1.ffffffffbfffe7ffff155655559a7d2dp-1,
    0x1.00003p-17
  },
  { // Entry 85
    0x1.ffffffffbfffe7ffff155655559a7d2dp-1,
    -0x1.00003p-17
  },
  { // Entry 86
    0x1.ffffffffeffff7ffff15f96ad3b29d94p-1,
    0x1.00003ffffffaep-18
  },
  { // Entry 87
    0x1.ffffffffeffff7ffff15f96ad3b29d94p-1,
    -0x1.00003ffffffaep-18
  },
  { // Entry 88
    0x1.ffffffffeffff7ffff15576aab329f45p-1,
    0x1.00003ffffffffp-18
  },
  { // Entry 89
    0x1.ffffffffeffff7ffff15576aab329f45p-1,
    -0x1.00003ffffffffp-18
  },
  { // Entry 90
    -0x1.dab7efeb35bad7fbdcb0efedb662097cp-2,
    0x1.00007ffffdea0p41
  },
  { // Entry 91
    -0x1.dab7efeb35bad7fbdcb0efedb662097cp-2,
    -0x1.00007ffffdea0p41
  },
  { // Entry 92
    0x1.fffffffffbfff8000001595aa9afffcfp-1,
    0x1.0000ffff8p-19
  },
  { // Entry 93
    0x1.fffffffffbfff8000001595aa9afffcfp-1,
    -0x1.0000ffff8p-19
  },
  { // Entry 94
    0x1.fffffffffefff80000004b36423050f6p-1,
    0x1.0003fff800051p-20
  },
  { // Entry 95
    0x1.fffffffffefff80000004b36423050f6p-1,
    -0x1.0003fff800051p-20
  },
  { // Entry 96
    0x1.fffffffffefff800000042961fb095f7p-1,
    0x1.0003fff800096p-20
  },
  { // Entry 97
    0x1.fffffffffefff800000042961fb095f7p-1,
    -0x1.0003fff800096p-20
  },
  { // Entry 98
    -0x1.fbf2b71a23a577fddd081d30bc24917fp-2,
    0x1.000fd20p334
  },
  { // Entry 99
    -0x1.fbf2b71a23a577fddd081d30bc24917fp-2,
    -0x1.000fd20p334
  },
  { // Entry 100
    0x1.fccc87eae7736d8d8a4776314f6b0ba7p-5,
    0x1.003p514
  },
  { // Entry 101
    0x1.fccc87eae7736d8d8a4776314f6b0ba7p-5,
    -0x1.003p514
  },
  { // Entry 102
    -0x1.a43f40d92b7ed7eef0fe6d1799442cfap-7,
    0x1.00600000015f4p41
  },
  { // Entry 103
    -0x1.a43f40d92b7ed7eef0fe6d1799442cfap-7,
    -0x1.00600000015f4p41
  },
  { // Entry 104
    0x1.c11cc38f40ab2827dd0ff8c6f3dd1dafp-1,
    0x1.007p-1
  },
  { // Entry 105
    0x1.c11cc38f40ab2827dd0ff8c6f3dd1dafp-1,
    -0x1.007p-1
  },
  { // Entry 106
    0x1.ffffffffffbfc7f3c0000157ac331d0cp-1,
    0x1.007p-21
  },
  { // Entry 107
    0x1.ffffffffffbfc7f3c0000157ac331d0cp-1,
    -0x1.007p-21
  },
  { // Entry 108
    0x1.e9ba98231f7346e0566694e1484a5b98p-8,
    0x1.00cp40
  },
  { // Entry 109
    0x1.e9ba98231f7346e0566694e1484a5b98p-8,
    -0x1.00cp40
  },
  { // Entry 110
    0x1.fefdf48ed649cd087e3e801219edf804p-1,
    0x1.011p-4
  },
  { // Entry 111
    0x1.fefdf48ed649cd087e3e801219edf804p-1,
    -0x1.011p-4
  },
  { // Entry 112
    -0x1.ffc16a0f12ff271ced72fc659ddcd382p-1,
    0x1.011p996
  },
  { // Entry 113
    -0x1.ffc16a0f12ff271ced72fc659ddcd382p-1,
    -0x1.011p996
  },
  { // Entry 114
    0x1.efd5b61a30a387fff1400519845fcb1ep-1,
    0x1.020p-2
  },
  { // Entry 115
    0x1.efd5b61a30a387fff1400519845fcb1ep-1,
    -0x1.020p-2
  },
  { // Entry 116
    0x1.c97b8161dc50a06cd4801deeb8e0715bp-2,
    0x1.0204260c18307p59
  },
  { // Entry 117
    0x1.c97b8161dc50a06cd4801deeb8e0715bp-2,
    -0x1.0204260c18307p59
  },
  { // Entry 118
    -0x1.bf26a3c9b9fbe83488449343f08b08d7p-2,
    0x1.02e78a321155ep1
  },
  { // Entry 119
    -0x1.bf26a3c9b9fbe83488449343f08b08d7p-2,
    -0x1.02e78a321155ep1
  },
  { // Entry 120
    0x1.fef806b1f84e4dfd5f71307a3c3eb602p-1,
    0x1.040p-4
  },
  { // Entry 121
    0x1.fef806b1f84e4dfd5f71307a3c3eb602p-1,
    -0x1.040p-4
  },
  { // Entry 122
    0x1.fe851fbf87d176fb4c69295c7f928402p-1,
    0x1.04bde8bb80258p98
  },
  { // Entry 123
    0x1.fe851fbf87d176fb4c69295c7f928402p-1,
    -0x1.04bde8bb80258p98
  },
  { // Entry 124
    0x1.70f6a51da8efec398e74169e771386eap-1,
    0x1.077e749e37ceep236
  },
  { // Entry 125
    0x1.70f6a51da8efec398e74169e771386eap-1,
    -0x1.077e749e37ceep236
  },
  { // Entry 126
    0x1.6b408c856bda57fe5829a58361fea112p-3,
    0x1.07f80p300
  },
  { // Entry 127
    0x1.6b408c856bda57fe5829a58361fea112p-3,
    -0x1.07f80p300
  },
  { // Entry 128
    0x1.2b2f965ae40fc7ffffbca0b7eaec5919p-1,
    0x1.07f9bea1b3546p27
  },
  { // Entry 129
    0x1.2b2f965ae40fc7ffffbca0b7eaec5919p-1,
    -0x1.07f9bea1b3546p27
  },
  { // Entry 130
    -0x1.4eed2f3fc76a77f803d8911eeddcc5e8p-1,
    0x1.090d18372f2d5p4
  },
  { // Entry 131
    -0x1.4eed2f3fc76a77f803d8911eeddcc5e8p-1,
    -0x1.090d18372f2d5p4
  },
  { // Entry 132
    0x1.fba59aecee5000315cee323079ed1427p-1,
    0x1.0b4p-3
  },
  { // Entry 133
    0x1.fba59aecee5000315cee323079ed1427p-1,
    -0x1.0b4p-3
  },
  { // Entry 134
    0x1.fffd1bcda7a7d5510aa3d0ed8addc785p-1,
    0x1.0c0d5c2af3c2ep346
  },
  { // Entry 135
    0x1.fffd1bcda7a7d5510aa3d0ed8addc785p-1,
    -0x1.0c0d5c2af3c2ep346
  },
  { // Entry 136
    -0x1.e4dfe831292867fdc1333c0a4c3f3f70p-1,
    0x1.0d30596ee91fdp216
  },
  { // Entry 137
    -0x1.e4dfe831292867fdc1333c0a4c3f3f70p-1,
    -0x1.0d30596ee91fdp216
  },
  { // Entry 138
    0x1.fb8432886a283b17acaa524e312ab1e3p-2,
    0x1.0d6p0
  },
  { // Entry 139
    0x1.fb8432886a283b17acaa524e312ab1e3p-2,
    -0x1.0d6p0
  },
  { // Entry 140
    0x1.ffffee202853ffbbc1684847019727a0p-1,
    0x1.0e9474c68831cp-10
  },
  { // Entry 141
    0x1.ffffee202853ffbbc1684847019727a0p-1,
    -0x1.0e9474c68831cp-10
  },
  { // Entry 142
    -0x1.b70d3d5584b1a83c68e254e523d37dfdp-2,
    0x1.113bae4049849p2
  },
  { // Entry 143
    -0x1.b70d3d5584b1a83c68e254e523d37dfdp-2,
    -0x1.113bae4049849p2
  },
  { // Entry 144
    0x1.fed8df58f625fdcbb1e40cf83caa2ca2p-1,
    0x1.12eb870976540p-4
  },
  { // Entry 145
    0x1.fed8df58f625fdcbb1e40cf83caa2ca2p-1,
    -0x1.12eb870976540p-4
  },
  { // Entry 146
    0x1.e536ae395dfce001457970c8aaac3b1fp-2,
    0x1.13cp0
  },
  { // Entry 147
    0x1.e536ae395dfce001457970c8aaac3b1fp-2,
    -0x1.13cp0
  },
  { // Entry 148
    0x1.fed0476fc75c9800000000000020b13ep-1,
    0x1.16e534ee36580p-4
  },
  { // Entry 149
    0x1.fed0476fc75c9800000000000020b13ep-1,
    -0x1.16e534ee36580p-4
  },
  { // Entry 150
    0x1.fb38e82e3193a7f19a17d231a2e8194ep-1,
    0x1.17fffffffea98p-3
  },
  { // Entry 151
    0x1.fb38e82e3193a7f19a17d231a2e8194ep-1,
    -0x1.17fffffffea98p-3
  },
  { // Entry 152
    0x1.fb38e82e3187fc65747ae443461eb434p-1,
    0x1.180p-3
  },
  { // Entry 153
    0x1.fb38e82e3187fc65747ae443461eb434p-1,
    -0x1.180p-3
  },
  { // Entry 154
    -0x1.e59647f1fe9c750059b9eafb88c2aceap-1,
    0x1.1a191ebbb4d7fp7
  },
  { // Entry 155
    -0x1.e59647f1fe9c750059b9eafb88c2aceap-1,
    -0x1.1a191ebbb4d7fp7
  },
  { // Entry 156
    -0x1.d0dca1f8715bd7f9ff373c763522db0ep-4,
    0x1.1da84f2b7b1d8p7
  },
  { // Entry 157
    -0x1.d0dca1f8715bd7f9ff373c763522db0ep-4,
    -0x1.1da84f2b7b1d8p7
  },
  { // Entry 158
    0x1.b917ebbc30e1d8364bc3c2c10ea13539p-2,
    0x1.201e973251302p0
  },
  { // Entry 159
    0x1.b917ebbc30e1d8364bc3c2c10ea13539p-2,
    -0x1.201e973251302p0
  },
  { // Entry 160
    0x1.fffadf12ff4147f6f6f35b44b0f6cb46p-1,
    0x1.21e02p-7
  },
  { // Entry 161
    0x1.fffadf12ff4147f6f6f35b44b0f6cb46p-1,
    -0x1.21e02p-7
  },
  { // Entry 162
    -0x1.598a4dab3de597d52faa736762a3f651p-1,
    0x1.27e29a4b985bfp1
  },
  { // Entry 163
    -0x1.598a4dab3de597d52faa736762a3f651p-1,
    -0x1.27e29a4b985bfp1
  },
  { // Entry 164
    0x1.fa95c1154abf56c4dbb77bfe5e4e8f42p-1,
    0x1.2a1f28dbfb6c0p-3
  },
  { // Entry 165
    0x1.fa95c1154abf56c4dbb77bfe5e4e8f42p-1,
    -0x1.2a1f28dbfb6c0p-3
  },
  { // Entry 166
    -0x1.6412293adb7bca97731e50a86312da2dp-1,
    0x1.2b8p1
  },
  { // Entry 167
    -0x1.6412293adb7bca97731e50a86312da2dp-1,
    -0x1.2b8p1
  },
  { // Entry 168
    0x1.fffa518a7d0e77f3b431fcd0ba353095p-1,
    0x1.31199def72f4dp-7
  },
  { // Entry 169
    0x1.fffa518a7d0e77f3b431fcd0ba353095p-1,
    -0x1.31199def72f4dp-7
  },
  { // Entry 170
    0x1.f36895fe177f77fe84798264ad4f33b1p-1,
    0x1.31260e1485014p4
  },
  { // Entry 171
    0x1.f36895fe177f77fe84798264ad4f33b1p-1,
    -0x1.31260e1485014p4
  },
  { // Entry 172
    0x1.d36207b4fee167f6b3185fdd9294a233p-4,
    0x1.34e964cd103bdp2
  },
  { // Entry 173
    0x1.d36207b4fee167f6b3185fdd9294a233p-4,
    -0x1.34e964cd103bdp2
  },
  { // Entry 174
    -0x1.84a37f4fa7616caad66b4d701ab53e94p-1,
    0x1.37618a0ba7850p1
  },
  { // Entry 175
    -0x1.84a37f4fa7616caad66b4d701ab53e94p-1,
    -0x1.37618a0ba7850p1
  },
  { // Entry 176
    -0x1.c830bbc99e2290f9d93aa62b2ddfec97p-39,
    0x1.379704f5f1eb3p24
  },
  { // Entry 177
    -0x1.c830bbc99e2290f9d93aa62b2ddfec97p-39,
    -0x1.379704f5f1eb3p24
  },
  { // Entry 178
    0x1.b5daaa233bd4f7fcf34b6d5d0280172fp-3,
    0x1.3b61dd166d470p2
  },
  { // Entry 179
    0x1.b5daaa233bd4f7fcf34b6d5d0280172fp-3,
    -0x1.3b61dd166d470p2
  },
  { // Entry 180
    -0x1.ffd00dc4db400d962e2d255a661e3ccbp-4,
    0x1.3c011022acbd0p37
  },
  { // Entry 181
    -0x1.ffd00dc4db400d962e2d255a661e3ccbp-4,
    -0x1.3c011022acbd0p37
  },
  { // Entry 182
    -0x1.14052b4016ff57fe5750ed3426bfd758p-1,
    0x1.3e7788e900b70p727
  },
  { // Entry 183
    -0x1.14052b4016ff57fe5750ed3426bfd758p-1,
    -0x1.3e7788e900b70p727
  },
  { // Entry 184
    0x1.ffffe6a5e4197f5fc50acb189eb85c94p-1,
    0x1.423eafdcc2779p-10
  },
  { // Entry 185
    0x1.ffffe6a5e4197f5fc50acb189eb85c94p-1,
    -0x1.423eafdcc2779p-10
  },
  { // Entry 186
    -0x1.fe09fc3d16fedd7508301df68857b756p-6,
    0x1.4321828c1b538p119
  },
  { // Entry 187
    -0x1.fe09fc3d16fedd7508301df68857b756p-6,
    -0x1.4321828c1b538p119
  },
  { // Entry 188
    0x1.b685d949a27a0143c4ac9b553541ebecp-14,
    0x1.43506cb22975dp22
  },
  { // Entry 189
    0x1.b685d949a27a0143c4ac9b553541ebecp-14,
    -0x1.43506cb22975dp22
  },
  { // Entry 190
    0x1.fe398090e203bc2f6fe6830d380facc4p-1,
    0x1.439f63495786ap67
  },
  { // Entry 191
    0x1.fe398090e203bc2f6fe6830d380facc4p-1,
    -0x1.439f63495786ap67
  },
  { // Entry 192
    0x1.fe6274e000973a26c1a0053e3fdeffc7p-1,
    0x1.457538a6bd073p-4
  },
  { // Entry 193
    0x1.fe6274e000973a26c1a0053e3fdeffc7p-1,
    -0x1.457538a6bd073p-4
  },
  { // Entry 194
    0x1.09fcb69359c09d5739f1f0255d4fce83p-1,
    0x1.478fc08p43
  },
  { // Entry 195
    0x1.09fcb69359c09d5739f1f0255d4fce83p-1,
    -0x1.478fc08p43
  },
  { // Entry 196
    -0x1.20c2158511e7899f1ec379e90c296780p-9,
    0x1.48a45797cbe63p61
  },
  { // Entry 197
    -0x1.20c2158511e7899f1ec379e90c296780p-9,
    -0x1.48a45797cbe63p61
  },
  { // Entry 198
    0x1.990d17aae25307fec4ae6d4e98f30093p-1,
    0x1.4a62e0e12c173p-1
  },
  { // Entry 199
    0x1.990d17aae25307fec4ae6d4e98f30093p-1,
    -0x1.4a62e0e12c173p-1
  },
  { // Entry 200
    0x1.fdd4f1e00b38700419f96d341905d045p-3,
    0x1.4c596642a9488p9
  },
  { // Entry 201
    0x1.fdd4f1e00b38700419f96d341905d045p-3,
    -0x1.4c596642a9488p9
  },
  { // Entry 202
    0x1.fe4f141032f377fe135b13e04436c5ffp-1,
    0x1.4d0p-4
  },
  { // Entry 203
    0x1.fe4f141032f377fe135b13e04436c5ffp-1,
    -0x1.4d0p-4
  },
  { // Entry 204
    0x1.94e9f45d43c137a3f345644240a2cef0p-2,
    0x1.4f0f308p488
  },
  { // Entry 205
    0x1.94e9f45d43c137a3f345644240a2cef0p-2,
    -0x1.4f0f308p488
  },
  { // Entry 206
    0x1.9355f69ad4326404827cd5ccff8a0c69p-2,
    0x1.52f00e0p793
  },
  { // Entry 207
    0x1.9355f69ad4326404827cd5ccff8a0c69p-2,
    -0x1.52f00e0p793
  },
  { // Entry 208
    0x1.1a19be8bea10a801d0b2d09d9509c2c4p-1,
    0x1.52f06c730ec02p2
  },
  { // Entry 209
    0x1.1a19be8bea10a801d0b2d09d9509c2c4p-1,
    -0x1.52f06c730ec02p2
  },
  { // Entry 210
    0x1.385d92ec0c7337fea39493f6f2674328p-1,
    0x1.53e7d5845fe3dp220
  },
  { // Entry 211
    0x1.385d92ec0c7337fea39493f6f2674328p-1,
    -0x1.53e7d5845fe3dp220
  },
  { // Entry 212
    0x1.fffffffffe2f0f000000465e3592bffbp-1,
    0x1.590p-20
  },
  { // Entry 213
    0x1.fffffffffe2f0f000000465e3592bffbp-1,
    -0x1.590p-20
  },
  { // Entry 214
    -0x1.ffd7bc28ded91ffa200d677109251801p-1,
    0x1.592f1176f0980p86
  },
  { // Entry 215
    -0x1.ffd7bc28ded91ffa200d677109251801p-1,
    -0x1.592f1176f0980p86
  },
  { // Entry 216
    -0x1.cee28b3d79799000009ea8081244116cp-1,
    0x1.5999999dc09dcp1
  },
  { // Entry 217
    -0x1.cee28b3d79799000009ea8081244116cp-1,
    -0x1.5999999dc09dcp1
  },
  { // Entry 218
    0x1.c1f1eb08c26040a32800f087952a383cp-1,
    0x1.5bea010p468
  },
  { // Entry 219
    0x1.c1f1eb08c26040a32800f087952a383cp-1,
    -0x1.5bea010p468
  },
  { // Entry 220
    0x1.fffe35ab09a653e266eada6f44055214p-1,
    0x1.5cb80a6135e5ap1000
  },
  { // Entry 221
    0x1.fffe35ab09a653e266eada6f44055214p-1,
    -0x1.5cb80a6135e5ap1000
  },
  { // Entry 222
    -0x1.07b85f606e75d765b1aa3bbccba6eaf8p-3,
    0x1.5d5be48730d2dp13
  },
  { // Entry 223
    -0x1.07b85f606e75d765b1aa3bbccba6eaf8p-3,
    -0x1.5d5be48730d2dp13
  },
  { // Entry 224
    0x1.ffffffffff86239c000004d581b055ebp-1,
    0x1.614p-21
  },
  { // Entry 225
    0x1.ffffffffff86239c000004d581b055ebp-1,
    -0x1.614p-21
  },
  { // Entry 226
    -0x1.dd3a806e89cf17fffff16ecd5397b486p-1,
    0x1.62adc8a660364p1
  },
  { // Entry 227
    -0x1.dd3a806e89cf17fffff16ecd5397b486p-1,
    -0x1.62adc8a660364p1
  },
  { // Entry 228
    -0x1.4308b14f4b6edc4c07ee6895f3188af3p-1,
    0x1.64ef438p142
  },
  { // Entry 229
    -0x1.4308b14f4b6edc4c07ee6895f3188af3p-1,
    -0x1.64ef438p142
  },
  { // Entry 230
    0x1.6623d2eb6add1ffc398a3c20447f9d06p-3,
    0x1.652p0
  },
  { // Entry 231
    0x1.6623d2eb6add1ffc398a3c20447f9d06p-3,
    -0x1.652p0
  },
  { // Entry 232
    0x1.fff832c50f471ff5599c23dc968eb8e4p-1,
    0x1.65865b2cb08a2p-7
  },
  { // Entry 233
    0x1.fff832c50f471ff5599c23dc968eb8e4p-1,
    -0x1.65865b2cb08a2p-7
  },
  { // Entry 234
    0x1.acc251be330228021bc31307bc81dc16p-1,
    0x1.6a937daabc20ep375
  },
  { // Entry 235
    0x1.acc251be330228021bc31307bc81dc16p-1,
    -0x1.6a937daabc20ep375
  },
  { // Entry 236
    -0x1.14ae72e6ba22ef4608875c41378eb052p-61,
    0x1.6ac5b262ca1ffp849
  },
  { // Entry 237
    -0x1.14ae72e6ba22ef4608875c41378eb052p-61,
    -0x1.6ac5b262ca1ffp849
  },
  { // Entry 238
    0x1.e0619960a11c6801e80ab0c9e25f89d0p-2,
    0x1.6f7bdef7bdef4p3
  },
  { // Entry 239
    0x1.e0619960a11c6801e80ab0c9e25f89d0p-2,
    -0x1.6f7bdef7bdef4p3
  },
  { // Entry 240
    0x1.8d23f97901a307fffd6c52adf83f0993p-1,
    0x1.739ce759ce738p200
  },
  { // Entry 241
    0x1.8d23f97901a307fffd6c52adf83f0993p-1,
    -0x1.739ce759ce738p200
  },
  { // Entry 242
    0x1.fffff78a14ba0f38a84b48dcdb63d44fp-1,
    0x1.7450c3f49d0b2p-11
  },
  { // Entry 243
    0x1.fffff78a14ba0f38a84b48dcdb63d44fp-1,
    -0x1.7450c3f49d0b2p-11
  },
  { // Entry 244
    0x1.d6f1c727fb2cb7f7e9cbee2e14246c08p-4,
    0x1.749fe53f963fdp0
  },
  { // Entry 245
    0x1.d6f1c727fb2cb7f7e9cbee2e14246c08p-4,
    -0x1.749fe53f963fdp0
  },
  { // Entry 246
    -0x1.f284b5028c1847fffffc9532fe892aadp-1,
    0x1.74af6725c6206p1
  },
  { // Entry 247
    -0x1.f284b5028c1847fffffc9532fe892aadp-1,
    -0x1.74af6725c6206p1
  },
  { // Entry 248
    -0x1.f3165a0b306b1ffcf8d11909fffba167p-1,
    0x1.7550d28ffccc4p1
  },
  { // Entry 249
    -0x1.f3165a0b306b1ffcf8d11909fffba167p-1,
    -0x1.7550d28ffccc4p1
  },
  { // Entry 250
    0x1.d66d2078ebdeb7ffedf8a48e25084c19p-1,
    0x1.775e397cd6aa0p6
  },
  { // Entry 251
    0x1.d66d2078ebdeb7ffedf8a48e25084c19p-1,
    -0x1.775e397cd6aa0p6
  },
  { // Entry 252
    0x1.7af9a13085f5382a87a541ae0b2e5965p-1,
    0x1.799302bf7f290p-1
  },
  { // Entry 253
    0x1.7af9a13085f5382a87a541ae0b2e5965p-1,
    -0x1.799302bf7f290p-1
  },
  { // Entry 254
    0x1.ffdd2fdac0c2483e7b116d6d488e7a4bp-1,
    0x1.799fffffffffdp-6
  },
  { // Entry 255
    0x1.ffdd2fdac0c2483e7b116d6d488e7a4bp-1,
    -0x1.799fffffffffdp-6
  },
  { // Entry 256
    0x1.fff744f185a737f256732ce87dbaf7a7p-1,
    0x1.7a3692ca94490p-7
  },
  { // Entry 257
    0x1.fff744f185a737f256732ce87dbaf7a7p-1,
    -0x1.7a3692ca94490p-7
  },
  { // Entry 258
    0x1.7a6b326b690fa831ee4d0dd72787fbc3p-1,
    0x1.7a66a638ac5b5p-1
  },
  { // Entry 259
    0x1.7a6b326b690fa831ee4d0dd72787fbc3p-1,
    -0x1.7a66a638ac5b5p-1
  },
  { // Entry 260
    0x1.671fdb64ffbed7e4952a9d967941e7dap-4,
    0x1.7ba65462b49a0p0
  },
  { // Entry 261
    0x1.671fdb64ffbed7e4952a9d967941e7dap-4,
    -0x1.7ba65462b49a0p0
  },
  { // Entry 262
    0x1.ffa55490f206e3b4323a02477b4149e8p-1,
    0x1.7cdf37cdf37c9p239
  },
  { // Entry 263
    0x1.ffa55490f206e3b4323a02477b4149e8p-1,
    -0x1.7cdf37cdf37c9p239
  },
  { // Entry 264
    0x1.4c5b5970a3a488233005742af5e6a95ep-4,
    0x1.7d542565f472ep0
  },
  { // Entry 265
    0x1.4c5b5970a3a488233005742af5e6a95ep-4,
    -0x1.7d542565f472ep0
  },
  { // Entry 266
    0x1.479a5667c63f57da26adf180a7eb2ffbp-4,
    0x1.7da0751649058p0
  },
  { // Entry 267
    0x1.479a5667c63f57da26adf180a7eb2ffbp-4,
    -0x1.7da0751649058p0
  },
  { // Entry 268
    0x1.fff717511dcb57f32d38f29c01379b98p-1,
    0x1.7e0ddcda6cc0dp-7
  },
  { // Entry 269
    0x1.fff717511dcb57f32d38f29c01379b98p-1,
    -0x1.7e0ddcda6cc0dp-7
  },
  { // Entry 270
    0x1.ffffffffff7077e7000006b4c7060c33p-1,
    0x1.7f6p-21
  },
  { // Entry 271
    0x1.ffffffffff7077e7000006b4c7060c33p-1,
    -0x1.7f6p-21
  },
  { // Entry 272
    -0x1.fff9e1554698017220917c3fb31188ddp-1,
    0x1.7f90117d44c74p100
  },
  { // Entry 273
    -0x1.fff9e1554698017220917c3fb31188ddp-1,
    -0x1.7f90117d44c74p100
  },
  { // Entry 274
    0x1.ffdc006bff7e984a8d5031a7152d36e5p-1,
    0x1.7ffffffffef7ap-6
  },
  { // Entry 275
    0x1.ffdc006bff7e984a8d5031a7152d36e5p-1,
    -0x1.7ffffffffef7ap-6
  },
  { // Entry 276
    0x1.ffdc006bff7e78474d66d7f25c3ac277p-1,
    0x1.7fffffffffa26p-6
  },
  { // Entry 277
    0x1.ffdc006bff7e78474d66d7f25c3ac277p-1,
    -0x1.7fffffffffa26p-6
  },
  { // Entry 278
    0x1.ffdc006bff7e6839adba2a91108d56afp-1,
    0x1.7ffffffffff80p-6
  },
  { // Entry 279
    0x1.ffdc006bff7e6839adba2a91108d56afp-1,
    -0x1.7ffffffffff80p-6
  },
  { // Entry 280
    0x1.760718ab443977fdd8f8f2221ca4db3cp-1,
    0x1.80ep-1
  },
  { // Entry 281
    0x1.760718ab443977fdd8f8f2221ca4db3cp-1,
    -0x1.80ep-1
  },
  { // Entry 282
    -0x1.fffffffffffffffffffffffffeb29d0bp-1,
    0x1.81ae0dffa3b33p959
  },
  { // Entry 283
    -0x1.fffffffffffffffffffffffffeb29d0bp-1,
    -0x1.81ae0dffa3b33p959
  },
  { // Entry 284
    -0x1.fbdc48125b34574cf1f91419e7edb75bp-1,
    0x1.81d612289c5cfp1
  },
  { // Entry 285
    -0x1.fbdc48125b34574cf1f91419e7edb75bp-1,
    -0x1.81d612289c5cfp1
  },
  { // Entry 286
    0x1.ff9e396651cc97e935b2e0ee73607d12p-5,
    0x1.8220192270a0ep0
  },
  { // Entry 287
    0x1.ff9e396651cc97e935b2e0ee73607d12p-5,
    -0x1.8220192270a0ep0
  },
  { // Entry 288
    0x1.fe2b26dddb5c882f30a885c1b291f945p-5,
    0x1.822bb780e9104p0
  },
  { // Entry 289
    0x1.fe2b26dddb5c882f30a885c1b291f945p-5,
    -0x1.822bb780e9104p0
  },
  { // Entry 290
    0x1.eb87cff7c91157a755818c01284b0e51p-5,
    0x1.82c119c4b8e49p0
  },
  { // Entry 291
    0x1.eb87cff7c91157a755818c01284b0e51p-5,
    -0x1.82c119c4b8e49p0
  },
  { // Entry 292
    0x1.eb87cff7a62b77b57a66ac275a3104c8p-5,
    0x1.82c119c4b9fc4p0
  },
  { // Entry 293
    0x1.eb87cff7a62b77b57a66ac275a3104c8p-5,
    -0x1.82c119c4b9fc4p0
  },
  { // Entry 294
    0x1.eb87cff795ab17a807864d8fb0ca43cap-5,
    0x1.82c119c4ba808p0
  },
  { // Entry 295
    0x1.eb87cff795ab17a807864d8fb0ca43cap-5,
    -0x1.82c119c4ba808p0
  },
  { // Entry 296
    0x1.de1d17ab0d6a48367523193d68568c1bp-5,
    0x1.832c9fc765270p0
  },
  { // Entry 297
    0x1.de1d17ab0d6a48367523193d68568c1bp-5,
    -0x1.832c9fc765270p0
  },
  { // Entry 298
    0x1.dc86e7bec0c44848cfc39b7f1b8204acp-5,
    0x1.833956ce7d1f9p0
  },
  { // Entry 299
    0x1.dc86e7bec0c44848cfc39b7f1b8204acp-5,
    -0x1.833956ce7d1f9p0
  },
  { // Entry 300
    0x1.db03cbb942a7a84974e904ecc896a5eep-5,
    0x1.834574eb1c099p0
  },
  { // Entry 301
    0x1.db03cbb942a7a84974e904ecc896a5eep-5,
    -0x1.834574eb1c099p0
  },
  { // Entry 302
    0x1.ce431710d15077b1e8170a532b68abdep-5,
    0x1.83aba5688e13ep0
  },
  { // Entry 303
    0x1.ce431710d15077b1e8170a532b68abdep-5,
    -0x1.83aba5688e13ep0
  },
  { // Entry 304
    0x1.cd46b3a77f6dd7ab0d312546aba7c0afp-5,
    0x1.83b38bbafd75bp0
  },
  { // Entry 305
    0x1.cd46b3a77f6dd7ab0d312546aba7c0afp-5,
    -0x1.83b38bbafd75bp0
  },
  { // Entry 306
    -0x1.ff29bc666bee6ea44d4db000e5f173bfp-1,
    0x1.86a017cb1c31cp16
  },
  { // Entry 307
    -0x1.ff29bc666bee6ea44d4db000e5f173bfp-1,
    -0x1.86a017cb1c31cp16
  },
  { // Entry 308
    -0x1.7968916e4c64630e8e3ae60276ba2d27p-2,
    0x1.8720588p392
  },
  { // Entry 309
    -0x1.7968916e4c64630e8e3ae60276ba2d27p-2,
    -0x1.8720588p392
  },
  { // Entry 310
    0x1.fb97c7e452917f59890dfb47e7c9b5e3p-1,
    0x1.88a2288a22888p9
  },
  { // Entry 311
    0x1.fb97c7e452917f59890dfb47e7c9b5e3p-1,
    -0x1.88a2288a22888p9
  },
  { // Entry 312
    -0x1.ae44a5f01bf633015e5aacccab4a7f3dp-1,
    0x1.8cf013991c308p1000
  },
  { // Entry 313
    -0x1.ae44a5f01bf633015e5aacccab4a7f3dp-1,
    -0x1.8cf013991c308p1000
  },
  { // Entry 314
    0x1.d96e82f71a9dc7fd86f57480e75491e3p-1,
    0x1.9p-2
  },
  { // Entry 315
    0x1.d96e82f71a9dc7fd86f57480e75491e3p-1,
    -0x1.9p-2
  },
  { // Entry 316
    0x1.0fd9d5c093df4f57fc49463e2f3f33e6p-7,
    0x1.9p0
  },
  { // Entry 317
    0x1.0fd9d5c093df4f57fc49463e2f3f33e6p-7,
    -0x1.9p0
  },
  { // Entry 318
    0x1.0fd9d5c05e5fc801a0f5cbfa33777ae4p-7,
    0x1.90000000006b0p0
  },
  { // Entry 319
    0x1.0fd9d5c05e5fc801a0f5cbfa33777ae4p-7,
    -0x1.90000000006b0p0
  },
  { // Entry 320
    0x1.bc8be725417d8800000cada42eeea04ep-1,
    0x1.900c206d44162p6
  },
  { // Entry 321
    0x1.bc8be725417d8800000cada42eeea04ep-1,
    -0x1.900c206d44162p6
  },
  { // Entry 322
    0x1.fffffffff63b67e4972d86a2f9d8209bp-1,
    0x1.900c2af7baef3p-19
  },
  { // Entry 323
    0x1.fffffffff63b67e4972d86a2f9d8209bp-1,
    -0x1.900c2af7baef3p-19
  },
  { // Entry 324
    0x1.bd464c9352d107ffffff8db9e0da71c0p-1,
    0x1.900f11bd8955dp6
  },
  { // Entry 325
    0x1.bd464c9352d107ffffff8db9e0da71c0p-1,
    -0x1.900f11bd8955dp6
  },
  { // Entry 326
    0x1.fffffda85cdd0d431e06f9aa74bc8ce0p-1,
    0x1.910b35c3253d4p100
  },
  { // Entry 327
    0x1.fffffda85cdd0d431e06f9aa74bc8ce0p-1,
    -0x1.910b35c3253d4p100
  },
  { // Entry 328
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    0x1.921fb54442d18p0
  },
  { // Entry 329
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    -0x1.921fb54442d18p0
  },
  { // Entry 330
    -0x1.2aeef4b9ea1ae4e64c71fccf1fd06f40p-18,
    0x1.922p0
  },
  { // Entry 331
    -0x1.2aeef4b9ea1ae4e64c71fccf1fd06f40p-18,
    -0x1.922p0
  },
  { // Entry 332
    -0x1.ffffffffd904847798c7acd46ad183cap-18,
    0x1.9220354442d18p0
  },
  { // Entry 333
    -0x1.ffffffffd904847798c7acd46ad183cap-18,
    -0x1.9220354442d18p0
  },
  { // Entry 334
    -0x1.ffffffffffffffffffff2ac8c3da72cbp-1,
    0x1.9251f93aeb59dp12
  },
  { // Entry 335
    -0x1.ffffffffffffffffffff2ac8c3da72cbp-1,
    -0x1.9251f93aeb59dp12
  },
  { // Entry 336
    0x1.ffb8c4d1f78a87fffffb23d171bd54d0p-1,
    0x1.943be221d909ap2
  },
  { // Entry 337
    0x1.ffb8c4d1f78a87fffffb23d171bd54d0p-1,
    -0x1.943be221d909ap2
  },
  { // Entry 338
    0x1.fff6011fdddab7f25c82e5384d46cc69p-1,
    0x1.94af699302875p-7
  },
  { // Entry 339
    0x1.fff6011fdddab7f25c82e5384d46cc69p-1,
    -0x1.94af699302875p-7
  },
  { // Entry 340
    0x1.d7954e7a3ee998000099470604329b68p-1,
    0x1.999999ab7b0edp-2
  },
  { // Entry 341
    0x1.d7954e7a3ee998000099470604329b68p-1,
    -0x1.999999ab7b0edp-2
  },
  { // Entry 342
    0x1.d7954e76c8e30fffff5a9bf455a06410p-1,
    0x1.999999bd4190bp-2
  },
  { // Entry 343
    0x1.d7954e76c8e30fffff5a9bf455a06410p-1,
    -0x1.999999bd4190bp-2
  },
  { // Entry 344
    0x1.fa23cfb82022440eb972c7e083933d20p-1,
    0x1.9bd0f19479a24p2
  },
  { // Entry 345
    0x1.fa23cfb82022440eb972c7e083933d20p-1,
    -0x1.9bd0f19479a24p2
  },
  { // Entry 346
    -0x1.6a09e667f3af07f2f4676b5f6f268c81p-1,
    0x1.9c55835e7e83ep8
  },
  { // Entry 347
    -0x1.6a09e667f3af07f2f4676b5f6f268c81p-1,
    -0x1.9c55835e7e83ep8
  },
  { // Entry 348
    0x1.fff59c12558097f2858f4a1326f2ddf4p-1,
    0x1.9c9942b14448dp-7
  },
  { // Entry 349
    0x1.fff59c12558097f2858f4a1326f2ddf4p-1,
    -0x1.9c9942b14448dp-7
  },
  { // Entry 350
    0x1.ffece5cab4ca5652ea2fc7ccce883304p-1,
    0x1.9d3d92485e2b5p523
  },
  { // Entry 351
    0x1.ffece5cab4ca5652ea2fc7ccce883304p-1,
    -0x1.9d3d92485e2b5p523
  },
  { // Entry 352
    -0x1.ff55301d3a780d19c28c22c82c1f5383p-5,
    0x1.a0d068341a080p1000
  },
  { // Entry 353
    -0x1.ff55301d3a780d19c28c22c82c1f5383p-5,
    -0x1.a0d068341a080p1000
  },
  { // 
"""


```
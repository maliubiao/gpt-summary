Response:
The user wants a summary of the provided C source code file. This file is located in `bionic/tests/math_data/cbrt_intel_data.handroid`, which suggests it contains test data for the `cbrt` function in Android's bionic library.

Here's a breakdown of the content:

1. **Copyright and License:** Standard Apache 2.0 license.
2. **Data Structure:**  The code defines a static array named `g_cbrt_intel_data`.
3. **Data Type:** The array's elements are of type `data_1_1_t<double, double>`. This implies a structure or template that holds two `double` values.
4. **Data Content:** The array is populated with pairs of `double` values, represented in hexadecimal floating-point format. Each pair seems to correspond to an input value and its expected cube root.

Therefore, the primary function of this file is to provide a set of test cases for the cube root function (`cbrt`). Each entry likely represents a specific input and the corresponding expected output, used for verifying the correctness of the `cbrt` implementation.
这是位于 Android Bionic 库中的一个测试数据文件，专门用于测试 `cbrt` (立方根) 函数的实现，尤其针对 Intel 架构。

**功能归纳:**

该文件的主要功能是提供一系列预定义的双精度浮点数输入值及其对应的精确立方根值。 这些数据用于测试 Bionic 库中 `cbrt` 函数在 Intel 架构上的实现是否正确。

**更具体地说，该文件包含以下信息:**

* **测试用例集合:**  `g_cbrt_intel_data` 数组包含了多个 `data_1_1_t<double, double>` 类型的元素。 每个元素代表一个独立的测试用例。
* **输入-输出对:** 每个测试用例（即数组中的一个元素）都包含一对双精度浮点数：
    * 第一个 `double` 值是作为 `cbrt` 函数的输入。
    * 第二个 `double` 值是该输入的预期立方根结果。
* **覆盖各种场景:**  从数据来看，这些测试用例覆盖了不同量级的正数和负数，包括非常小的值、接近于 0 的值、以及比较大的值。这有助于确保 `cbrt` 函数在各种输入情况下都能正确工作。
* **针对 Intel 架构:** 文件名 `cbrt_intel_data.handroid`  暗示这些数据可能特别针对 Intel 架构上的 `cbrt` 实现进行了优化或验证。可能存在其他架构的类似测试数据文件。

**与 Android 功能的关系举例:**

Android 系统中的各种应用程序和服务在执行数学运算时可能会调用 Bionic 库提供的 `cbrt` 函数。 例如：

* **图形渲染:**  计算三维空间中的距离、角度等可能需要用到立方根。
* **科学计算类应用:**  物理模拟、工程计算等领域经常需要计算立方根。
* **游戏开发:**  游戏中的一些物理引擎或特效计算可能涉及到立方根。

如果 Bionic 库的 `cbrt` 函数实现不正确，使用了错误的算法或者存在精度问题，那么依赖该函数的 Android 应用可能会出现计算错误，导致功能异常或者结果不准确。

**总结:**

该文件是一个测试数据集合，用于确保 Android 系统核心库 Bionic 中的 `cbrt` 函数在 Intel 架构上能够准确地计算立方根。它是 Android 质量保证体系的一部分，通过提供精确的预期结果来验证底层数学函数的正确性。

### 提示词
```
这是目录为bionic/tests/math_data/cbrt_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_cbrt_intel_data[] = {
  { // Entry 0
    -0x1.p-10,
    -0x1.0p-30
  },
  { // Entry 1
    0x1.p-10,
    0x1.0p-30
  },
  { // Entry 2
    -0x1.00000000007fffffffffc00000000035p-3,
    -0x1.00000000018p-9
  },
  { // Entry 3
    0x1.00000000007fffffffffc00000000035p-3,
    0x1.00000000018p-9
  },
  { // Entry 4
    -0x1.0000000007ffffffffc0000000035555p-340,
    -0x1.00000000180p-1020
  },
  { // Entry 5
    0x1.0000000007ffffffffc0000000035555p-340,
    0x1.00000000180p-1020
  },
  { // Entry 6
    -0x1.9986657fedfe4fd36e533ebb59e96ee6p-14,
    -0x1.060p-40
  },
  { // Entry 7
    0x1.9986657fedfe4fd36e533ebb59e96ee6p-14,
    0x1.060p-40
  },
  { // Entry 8
    -0x1.45abfb7ef7189911ba894c45eca1ddcap-1,
    -0x1.0787c1fa77ce0p-2
  },
  { // Entry 9
    0x1.45abfb7ef7189911ba894c45eca1ddcap-1,
    0x1.0787c1fa77ce0p-2
  },
  { // Entry 10
    -0x1.9e9ee2bee69fe80c4f73cb59ccb7f3d1p5,
    -0x1.0fe6fc05ac8c0p17
  },
  { // Entry 11
    0x1.9e9ee2bee69fe80c4f73cb59ccb7f3d1p5,
    0x1.0fe6fc05ac8c0p17
  },
  { // Entry 12
    -0x1.493b33358f83ff197c29192baacf2763p-9,
    -0x1.10441104412p-26
  },
  { // Entry 13
    0x1.493b33358f83ff197c29192baacf2763p-9,
    0x1.10441104412p-26
  },
  { // Entry 14
    -0x1.9f187bb994b4e822d4c29f84eda66145p-1,
    -0x1.10d67c062d7e0p-1
  },
  { // Entry 15
    0x1.9f187bb994b4e822d4c29f84eda66145p-1,
    0x1.10d67c062d7e0p-1
  },
  { // Entry 16
    -0x1.0af6562f82937800f6aaeb59ca8be923p-2,
    -0x1.2250ab3726b08p-6
  },
  { // Entry 17
    0x1.0af6562f82937800f6aaeb59ca8be923p-2,
    0x1.2250ab3726b08p-6
  },
  { // Entry 18
    -0x1.a9cd919402f48820501d0a16e616a1efp30,
    -0x1.268029abf1585p92
  },
  { // Entry 19
    0x1.a9cd919402f48820501d0a16e616a1efp30,
    0x1.268029abf1585p92
  },
  { // Entry 20
    -0x1.aa74fb53ace248137ec2a68f4e2c0e6ap-11,
    -0x1.27dc102fbaaecp-31
  },
  { // Entry 21
    0x1.aa74fb53ace248137ec2a68f4e2c0e6ap-11,
    0x1.27dc102fbaaecp-31
  },
  { // Entry 22
    -0x1.bfb5c1cdaa6ddfd032c8a87db7a19ca2p-5,
    -0x1.5655956559580p-13
  },
  { // Entry 23
    0x1.bfb5c1cdaa6ddfd032c8a87db7a19ca2p-5,
    0x1.5655956559580p-13
  },
  { // Entry 24
    -0x1.cb8a75541abed81fa799464451a558d3p30,
    -0x1.7232560b9ccc6p92
  },
  { // Entry 25
    0x1.cb8a75541abed81fa799464451a558d3p30,
    0x1.7232560b9ccc6p92
  },
  { // Entry 26
    -0x1.7d038d6155dc480a9f29e86566a5f43dp-356,
    -0x1.a60p-1067
  },
  { // Entry 27
    0x1.7d038d6155dc480a9f29e86566a5f43dp-356,
    0x1.a60p-1067
  },
  { // Entry 28
    -0x1.e3b9dfbcafcda8395331b22320212c4cp7,
    -0x1.afc6abf5d0ce0p23
  },
  { // Entry 29
    0x1.e3b9dfbcafcda8395331b22320212c4cp7,
    0x1.afc6abf5d0ce0p23
  },
  { // Entry 30
    -0x1.84ad603727a0508cbedd2bca0ec48725p0,
    -0x1.bffa90d87aa98p1
  },
  { // Entry 31
    0x1.84ad603727a0508cbedd2bca0ec48725p0,
    0x1.bffa90d87aa98p1
  },
  { // Entry 32
    -0x1.947c09fa258151cfeee85175bc41fb81p-3,
    -0x1.f8e38e38e38e4p-8
  },
  { // Entry 33
    0x1.947c09fa258151cfeee85175bc41fb81p-3,
    0x1.f8e38e38e38e4p-8
  },
  { // Entry 34
    -0x1.ffffffffffff9fffffffffffedffffffp-341,
    -0x1.fffffffffffeep-1021
  },
  { // Entry 35
    0x1.ffffffffffff9fffffffffffedffffffp-341,
    0x1.fffffffffffeep-1021
  },
  { // Entry 36
    0x1.428a2f98d728c24ae0d4448847c4a6bap-341,
    0x1.0000000000003p-1022
  },
  { // Entry 37
    -0x1.428a2f98d728c24ae0d4448847c4a6bap-341,
    -0x1.0000000000003p-1022
  },
  { // Entry 38
    0x1.965fea53d6e3faf702e41590b070bffbp-14,
    0x1.0000000000006p-40
  },
  { // Entry 39
    -0x1.965fea53d6e3faf702e41590b070bffbp-14,
    -0x1.0000000000006p-40
  },
  { // Entry 40
    0x1.965fea53d6e3faf702e41590b070bffbp0,
    0x1.0000000000006p2
  },
  { // Entry 41
    -0x1.965fea53d6e3faf702e41590b070bffbp0,
    -0x1.0000000000006p2
  },
  { // Entry 42
    0x1.965fea53d6e607dd91906073bf1a35edp0,
    0x1.0000000000044p2
  },
  { // Entry 43
    -0x1.965fea53d6e607dd91906073bf1a35edp0,
    -0x1.0000000000044p2
  },
  { // Entry 44
    0x1.965fea53d6e697ca348e11e2a091d5b6p0,
    0x1.0000000000055p2
  },
  { // Entry 45
    -0x1.965fea53d6e697ca348e11e2a091d5b6p0,
    -0x1.0000000000055p2
  },
  { // Entry 46
    0x1.00000000000cbfffffffff5d70p1,
    0x1.0000000000264p3
  },
  { // Entry 47
    -0x1.00000000000cbfffffffff5d70p1,
    -0x1.0000000000264p3
  },
  { // Entry 48
    0x1.965fea53d702f7bcb128b0aa890997e0p0,
    0x1.00000000003afp2
  },
  { // Entry 49
    -0x1.965fea53d702f7bcb128b0aa890997e0p0,
    -0x1.00000000003afp2
  },
  { // Entry 50
    0x1.428a2f98d75e6fd4d753df927b6b1d4fp-14,
    0x1.00000000008p-41
  },
  { // Entry 51
    -0x1.428a2f98d75e6fd4d753df927b6b1d4fp-14,
    -0x1.00000000008p-41
  },
  { // Entry 52
    0x1.00000000007fffffffffc00000000035p-3,
    0x1.00000000018p-9
  },
  { // Entry 53
    -0x1.00000000007fffffffffc00000000035p-3,
    -0x1.00000000018p-9
  },
  { // Entry 54
    0x1.965fea53da1087ffad4108c4ea80cbc2p-14,
    0x1.00000000060p-40
  },
  { // Entry 55
    -0x1.965fea53da1087ffad4108c4ea80cbc2p-14,
    -0x1.00000000060p-40
  },
  { // Entry 56
    0x1.965fea53da4af7aa8f6e6d4048e52f2bp1,
    0x1.00000000066e7p5
  },
  { // Entry 57
    -0x1.965fea53da4af7aa8f6e6d4048e52f2bp1,
    -0x1.00000000066e7p5
  },
  { // Entry 58
    0x1.0000000007ffffffffc0000000035555p-340,
    0x1.00000000180p-1020
  },
  { // Entry 59
    -0x1.0000000007ffffffffc0000000035555p-340,
    -0x1.00000000180p-1020
  },
  { // Entry 60
    0x1.965fea55f54097c36a6737d85dd006dcp-40,
    0x1.0000000401004p-118
  },
  { // Entry 61
    -0x1.965fea55f54097c36a6737d85dd006dcp-40,
    -0x1.0000000401004p-118
  },
  { // Entry 62
    0x1.428a2fa15995e7ffff68534daa2646edp0,
    0x1.00000014430e2p1
  },
  { // Entry 63
    -0x1.428a2fa15995e7ffff68534daa2646edp0,
    -0x1.00000014430e2p1
  },
  { // Entry 64
    0x1.428a2fbea35a3d9d86d0a73d050d1379p-348,
    0x1.0000005a0p-1043
  },
  { // Entry 65
    -0x1.428a2fbea35a3d9d86d0a73d050d1379p-348,
    -0x1.0000005a0p-1043
  },
  { // Entry 66
    0x1.965ff2caa42317c00ffd791c040fb91dp-34,
    0x1.00000fff0p-100
  },
  { // Entry 67
    -0x1.965ff2caa42317c00ffd791c040fb91dp-34,
    -0x1.00000fff0p-100
  },
  { // Entry 68
    0x1.965ff2cb2b9860374c7a92e3bf79265dp-14,
    0x1.00001p-40
  },
  { // Entry 69
    -0x1.965ff2cb2b9860374c7a92e3bf79265dp-14,
    -0x1.00001p-40
  },
  { // Entry 70
    0x1.9660b58366b9c81443c564c8519c1649p-341,
    0x1.00018000008p-1021
  },
  { // Entry 71
    -0x1.9660b58366b9c81443c564c8519c1649p-341,
    -0x1.00018000008p-1021
  },
  { // Entry 72
    0x1.96639e80554d07f44482ed4edeb69024p-14,
    0x1.00070p-40
  },
  { // Entry 73
    -0x1.96639e80554d07f44482ed4edeb69024p-14,
    -0x1.00070p-40
  },
  { // Entry 74
    0x1.9665b2342f8d97ab827cc907bea6a6a0p-2,
    0x1.000aecf24b8bbp-4
  },
  { // Entry 75
    -0x1.9665b2342f8d97ab827cc907bea6a6a0p-2,
    -0x1.000aecf24b8bbp-4
  },
  { // Entry 76
    0x1.96664e51470857ba927fd8c83e4a668fp-2,
    0x1.000c14046c27cp-4
  },
  { // Entry 77
    -0x1.96664e51470857ba927fd8c83e4a668fp-2,
    -0x1.000c14046c27cp-4
  },
  { // Entry 78
    0x1.9681cd4d59cf3c49d09a44a6e5a71a0bp-4,
    0x1.00401004000dep-10
  },
  { // Entry 79
    -0x1.9681cd4d59cf3c49d09a44a6e5a71a0bp-4,
    -0x1.00401004000dep-10
  },
  { // Entry 80
    0x1.00254fe4e09a28161b19a150ed679c38p-340,
    0x1.007p-1020
  },
  { // Entry 81
    -0x1.00254fe4e09a28161b19a150ed679c38p-340,
    -0x1.007p-1020
  },
  { // Entry 82
    0x1.42b9323abafd78d0666f2ca1fbd9f8b9p-341,
    0x1.007p-1022
  },
  { // Entry 83
    -0x1.42b9323abafd78d0666f2ca1fbd9f8b9p-341,
    -0x1.007p-1022
  },
  { // Entry 84
    0x1.005a8aa11fd96610f475d13eb6f8247fp-340,
    0x1.011p-1020
  },
  { // Entry 85
    -0x1.005a8aa11fd96610f475d13eb6f8247fp-340,
    -0x1.011p-1020
  },
  { // Entry 86
    0x1.976e211b4a5fda2f3d9110f59316298ap-14,
    0x1.020p-40
  },
  { // Entry 87
    -0x1.976e211b4a5fda2f3d9110f59316298ap-14,
    -0x1.020p-40
  },
  { // Entry 88
    0x1.97f4c72a4cc937c8ec5808f7e0f23f1dp334,
    0x1.03001fc0eb6f0p1004
  },
  { // Entry 89
    -0x1.97f4c72a4cc937c8ec5808f7e0f23f1dp334,
    -0x1.03001fc0eb6f0p1004
  },
  { // Entry 90
    0x1.97f5f8160b8917c80d38a6af1f6f152bp0,
    0x1.03026484c3994p2
  },
  { // Entry 91
    -0x1.97f5f8160b8917c80d38a6af1f6f152bp0,
    -0x1.03026484c3994p2
  },
  { // Entry 92
    0x1.446c1fbe1a821a88b3a25b8549559d1cp-81,
    0x1.0482412090482p-242
  },
  { // Entry 93
    -0x1.446c1fbe1a821a88b3a25b8549559d1cp-81,
    -0x1.0482412090482p-242
  },
  { // Entry 94
    0x1.9986657fedfe4fd36e533ebb59e96ee6p-14,
    0x1.060p-40
  },
  { // Entry 95
    -0x1.9986657fedfe4fd36e533ebb59e96ee6p-14,
    -0x1.060p-40
  },
  { // Entry 96
    0x1.454088d15010f7f343422c761e601e61p-1,
    0x1.068341a0d0680p-2
  },
  { // Entry 97
    -0x1.454088d15010f7f343422c761e601e61p-1,
    -0x1.068341a0d0680p-2
  },
  { // Entry 98
    0x1.9a92c607cfd737e7521bc7f98770b170p2,
    0x1.08046a3c709e3p8
  },
  { // Entry 99
    -0x1.9a92c607cfd737e7521bc7f98770b170p2,
    -0x1.08046a3c709e3p8
  },
  { // Entry 100
    0x1.9a93cde71ba557e6218528c1cb0d6e32p-1,
    0x1.08066749584ddp-1
  },
  { // Entry 101
    -0x1.9a93cde71ba557e6218528c1cb0d6e32p-1,
    -0x1.08066749584ddp-1
  },
  { // Entry 102
    0x1.9a952773d350c7e97b4223564fd73be7p-347,
    0x1.080901ebap-1039
  },
  { // Entry 103
    -0x1.9a952773d350c7e97b4223564fd73be7p-347,
    -0x1.080901ebap-1039
  },
  { // Entry 104
    0x1.032ee63c56e3b55628c6400c742d93edp1,
    0x1.09ab38ed184bap3
  },
  { // Entry 105
    -0x1.032ee63c56e3b55628c6400c742d93edp1,
    -0x1.09ab38ed184bap3
  },
  { // Entry 106
    0x1.9b9968457c86a7d7dbb54f5a02fc037bp4,
    0x1.0a0056960e368p14
  },
  { // Entry 107
    -0x1.9b9968457c86a7d7dbb54f5a02fc037bp4,
    -0x1.0a0056960e368p14
  },
  { // Entry 108
    0x1.9e9f1f2d0855881624b60f77c042b78dp0,
    0x1.0fe772e9039f5p2
  },
  { // Entry 109
    -0x1.9e9f1f2d0855881624b60f77c042b78dp0,
    -0x1.0fe772e9039f5p2
  },
  { // Entry 110
    0x1.9ea753cde1bd0855df2edf015f707a04p1,
    0x1.0ff797ef1a3c3p5
  },
  { // Entry 111
    -0x1.9ea753cde1bd0855df2edf015f707a04p1,
    -0x1.0ff797ef1a3c3p5
  },
  { // Entry 112
    0x1.491fc152578ca7cdd8078fdafcb33036p-357,
    0x1.1p-1070
  },
  { // Entry 113
    -0x1.491fc152578ca7cdd8078fdafcb33036p-357,
    -0x1.1p-1070
  },
  { // Entry 114
    0x1.9eac9efc6e88d7c312cafbfcbd94b5b4p0,
    0x1.1002029e1aaddp2
  },
  { // Entry 115
    -0x1.9eac9efc6e88d7c312cafbfcbd94b5b4p0,
    -0x1.1002029e1aaddp2
  },
  { // Entry 116
    0x1.9f1445f47beb881feb8cc6da6423f1fap0,
    0x1.10ce2ee39f71bp2
  },
  { // Entry 117
    -0x1.9f1445f47beb881feb8cc6da6423f1fap0,
    -0x1.10ce2ee39f71bp2
  },
  { // Entry 118
    0x1.9f16f1b3849098203460c5bf7946e9ddp-1,
    0x1.10d37312af8fap-1
  },
  { // Entry 119
    -0x1.9f16f1b3849098203460c5bf7946e9ddp-1,
    -0x1.10d37312af8fap-1
  },
  { // Entry 120
    0x1.9f22b8991664081f68f99db9a1cc0b73p0,
    0x1.10eaac892a245p2
  },
  { // Entry 121
    -0x1.9f22b8991664081f68f99db9a1cc0b73p0,
    -0x1.10eaac892a245p2
  },
  { // Entry 122
    0x1.9f458921d52a281fafef2e225aaab6c6p0,
    0x1.112f5c03ecec0p2
  },
  { // Entry 123
    -0x1.9f458921d52a281fafef2e225aaab6c6p0,
    -0x1.112f5c03ecec0p2
  },
  { // Entry 124
    0x1.4c4c991ac651a84e0ff0656285977047p1,
    0x1.17f2cafabb46ap4
  },
  { // Entry 125
    -0x1.4c4c991ac651a84e0ff0656285977047p1,
    -0x1.17f2cafabb46ap4
  },
  { // Entry 126
    0x1.a430ecfcf44ee7dc4e735762947d3dc3p0,
    0x1.1b02602c908bfp2
  },
  { // Entry 127
    -0x1.a430ecfcf44ee7dc4e735762947d3dc3p0,
    -0x1.1b02602c908bfp2
  },
  { // Entry 128
    0x1.a6a556b95dffa828a9a81a921f87fa85p-4,
    0x1.1fff905c3adbcp-10
  },
  { // Entry 129
    -0x1.a6a556b95dffa828a9a81a921f87fa85p-4,
    -0x1.1fff905c3adbcp-10
  },
  { // Entry 130
    0x1.a6a58d55e307bdded6f0c26447e14afap-14,
    0x1.2p-40
  },
  { // Entry 131
    -0x1.a6a58d55e307bdded6f0c26447e14afap-14,
    -0x1.2p-40
  },
  { // Entry 132
    0x1.a741dcaa85c507f8f476871a86c8f2fbp-14,
    0x1.214p-40
  },
  { // Entry 133
    -0x1.a741dcaa85c507f8f476871a86c8f2fbp-14,
    -0x1.214p-40
  },
  { // Entry 134
    0x1.a9b9a98cfc11381defe6253a98938775p-4,
    0x1.2656ddd0ef9a9p-10
  },
  { // Entry 135
    -0x1.a9b9a98cfc11381defe6253a98938775p-4,
    -0x1.2656ddd0ef9a9p-10
  },
  { // Entry 136
    0x1.a9ce86294341981ffbd04f46339b7ca3p0,
    0x1.26822529cb997p2
  },
  { // Entry 137
    -0x1.a9ce86294341981ffbd04f46339b7ca3p0,
    -0x1.26822529cb997p2
  },
  { // Entry 138
    0x1.aa3393610111800c773e492ba03c0bc0p-4,
    0x1.2754041e0bd58p-10
  },
  { // Entry 139
    -0x1.aa3393610111800c773e492ba03c0bc0p-4,
    -0x1.2754041e0bd58p-10
  },
  { // Entry 140
    0x1.aa6eaf149711081267d4d3bcfb21576ap-1,
    0x1.27cef4d58fa06p-1
  },
  { // Entry 141
    -0x1.aa6eaf149711081267d4d3bcfb21576ap-1,
    -0x1.27cef4d58fa06p-1
  },
  { // Entry 142
    0x1.ab0111c4f67687eab45b47dba3899345p-14,
    0x1.290p-40
  },
  { // Entry 143
    -0x1.ab0111c4f67687eab45b47dba3899345p-14,
    -0x1.290p-40
  },
  { // Entry 144
    0x1.ab7d23f59ed937e12fad7075ab2a34f5p66,
    0x1.2a032f360b141p200
  },
  { // Entry 145
    -0x1.ab7d23f59ed937e12fad7075ab2a34f5p66,
    -0x1.2a032f360b141p200
  },
  { // Entry 146
    0x1.0e7fe920f31d3746275027b3282172eep-340,
    0x1.2e025c04b85fcp-1020
  },
  { // Entry 147
    -0x1.0e7fe920f31d3746275027b3282172eep-340,
    -0x1.2e025c04b85fcp-1020
  },
  { // Entry 148
    0x1.55aaaaae387217d53fbba423cebb1a2ep-2,
    0x1.304c1304c1304p-5
  },
  { // Entry 149
    -0x1.55aaaaae387217d53fbba423cebb1a2ep-2,
    -0x1.304c1304c1304p-5
  },
  { // Entry 150
    0x1.b3dd56a2b132e7fdf10074b0924288f1p32,
    0x1.3bdfee33b02f8p98
  },
  { // Entry 151
    -0x1.b3dd56a2b132e7fdf10074b0924288f1p32,
    -0x1.3bdfee33b02f8p98
  },
  { // Entry 152
    0x1.b439df3c2659081df6a3085c877c7cffp0,
    0x1.3ca946e736845p2
  },
  { // Entry 153
    -0x1.b439df3c2659081df6a3085c877c7cffp0,
    -0x1.3ca946e736845p2
  },
  { // Entry 154
    0x1.138291eabb92efba9fe0d9849a897aa5p-340,
    0x1.3f1aa4d984256p-1020
  },
  { // Entry 155
    -0x1.138291eabb92efba9fe0d9849a897aa5p-340,
    -0x1.3f1aa4d984256p-1020
  },
  { // Entry 156
    0x1.b5695d4850bf002f93a8951840fdbdc1p-14,
    0x1.3f4p-40
  },
  { // Entry 157
    -0x1.b5695d4850bf002f93a8951840fdbdc1p-14,
    -0x1.3f4p-40
  },
  { // Entry 158
    0x1.13c484138704e8100660522ff714d063p-2,
    0x1.3ffffffffffffp-6
  },
  { // Entry 159
    -0x1.13c484138704e8100660522ff714d063p-2,
    -0x1.3ffffffffffffp-6
  },
  { // Entry 160
    0x1.b67bc3075e4107fa3e70de5d4fa75b20p0,
    0x1.419a4a4598f5ap2
  },
  { // Entry 161
    -0x1.b67bc3075e4107fa3e70de5d4fa75b20p0,
    -0x1.419a4a4598f5ap2
  },
  { // Entry 162
    0x1.b94a867d7d37304bf35180360c8f26bap-11,
    0x1.47d1f47d1f471p-31
  },
  { // Entry 163
    -0x1.b94a867d7d37304bf35180360c8f26bap-11,
    -0x1.47d1f47d1f471p-31
  },
  { // Entry 164
    0x1.ba6940f949a5f802cb51c7c838c7308dp-2,
    0x1.4a5294a5294a5p-4
  },
  { // Entry 165
    -0x1.ba6940f949a5f802cb51c7c838c7308dp-2,
    -0x1.4a5294a5294a5p-4
  },
  { // Entry 166
    0x1.1765862491b577ffff674fac52ee428ep0,
    0x1.4ccccccf6cc89p0
  },
  { // Entry 167
    -0x1.1765862491b577ffff674fac52ee428ep0,
    -0x1.4ccccccf6cc89p0
  },
  { // Entry 168
    0x1.17658624b3b6a7ffff67369ed724b90ap0,
    0x1.4ccccccfe64bdp0
  },
  { // Entry 169
    -0x1.17658624b3b6a7ffff67369ed724b90ap0,
    -0x1.4ccccccfe64bdp0
  },
  { // Entry 170
    0x1.1765862ca9ee78000097306b13e0ad9bp0,
    0x1.4cccccec59b21p0
  },
  { // Entry 171
    -0x1.1765862ca9ee78000097306b13e0ad9bp0,
    -0x1.4cccccec59b21p0
  },
  { // Entry 172
    0x1.c04d1376c37e4817e18315bd6a9e85e3p-8,
    0x1.57b1272bb8441p-22
  },
  { // Entry 173
    -0x1.c04d1376c37e4817e18315bd6a9e85e3p-8,
    -0x1.57b1272bb8441p-22
  },
  { // Entry 174
    0x1.c06ebba26ccd500a0de09b79cc640f3dp-1,
    0x1.57fe95dbd7d28p-1
  },
  { // Entry 175
    -0x1.c06ebba26ccd500a0de09b79cc640f3dp-1,
    -0x1.57fe95dbd7d28p-1
  },
  { // Entry 176
    0x1.c0e29e3b4a9e87f43c4eb9d13de23aefp0,
    0x1.59098ae904084p2
  },
  { // Entry 177
    -0x1.c0e29e3b4a9e87f43c4eb9d13de23aefp0,
    -0x1.59098ae904084p2
  },
  { // Entry 178
    0x1.c3db07e1a14ac838412532030d4d4d78p0,
    0x1.5feea74303d38p2
  },
  { // Entry 179
    -0x1.c3db07e1a14ac838412532030d4d4d78p0,
    -0x1.5feea74303d38p2
  },
  { // Entry 180
    0x1.6d73ab7df4e47b07582a3ea009214428p-14,
    0x1.746p-41
  },
  { // Entry 181
    -0x1.6d73ab7df4e47b07582a3ea009214428p-14,
    -0x1.746p-41
  },
  { // Entry 182
    0x1.22622dd15ed89a9f922c42a1b1289769p-2,
    0x1.75ap-6
  },
  { // Entry 183
    -0x1.22622dd15ed89a9f922c42a1b1289769p-2,
    -0x1.75ap-6
  },
  { // Entry 184
    0x1.cd8515b56ceb3f41561edc76c9bf01b0p-14,
    0x1.770p-40
  },
  { // Entry 185
    -0x1.cd8515b56ceb3f41561edc76c9bf01b0p-14,
    -0x1.770p-40
  },
  { // Entry 186
    0x1.d449b6dbbc459812bdd21f77ccdfd045p-4,
    0x1.87bdb17ed3d1fp-10
  },
  { // Entry 187
    -0x1.d449b6dbbc459812bdd21f77ccdfd045p-4,
    -0x1.87bdb17ed3d1fp-10
  },
  { // Entry 188
    0x1.280a36cf6379ea8fdfafc89cc9d77091p-7,
    0x1.8be2f8be2f8b1p-21
  },
  { // Entry 189
    -0x1.280a36cf6379ea8fdfafc89cc9d77091p-7,
    -0x1.8be2f8be2f8b1p-21
  },
  { // Entry 190
    0x1.75460639f871b7ffff679bb948d1e585p0,
    0x1.8cccccd41928ap1
  },
  { // Entry 191
    -0x1.75460639f871b7ffff679bb948d1e585p0,
    -0x1.8cccccd41928ap1
  },
  { // Entry 192
    0x1.d7bd00808f8337d9a59ba78f7f1d6790p-1,
    0x1.9076c775b5273p-1
  },
  { // Entry 193
    -0x1.d7bd00808f8337d9a59ba78f7f1d6790p-1,
    -0x1.9076c775b5273p-1
  },
  { // Entry 194
    0x1.d7e64dc80f7097f1129998d4da209031p-14,
    0x1.90ep-40
  },
  { // Entry 195
    -0x1.d7e64dc80f7097f1129998d4da209031p-14,
    -0x1.90ep-40
  },
  { // Entry 196
    0x1.da7c2ab04f88d7e99ecbfecf1a524bcbp-14,
    0x1.978p-40
  },
  { // Entry 197
    -0x1.da7c2ab04f88d7e99ecbfecf1a524bcbp-14,
    -0x1.978p-40
  },
  { // Entry 198
    0x1.dad49d2409c36ff2d4c9b994a1547f79p-4,
    0x1.98640c41ec378p-10
  },
  { // Entry 199
    -0x1.dad49d2409c36ff2d4c9b994a1547f79p-4,
    -0x1.98640c41ec378p-10
  },
  { // Entry 200
    0x1.79eafa03cd0c9b7054cf5184f3432188p-1,
    0x1.9bcbd6d204234p-2
  },
  { // Entry 201
    -0x1.79eafa03cd0c9b7054cf5184f3432188p-1,
    -0x1.9bcbd6d204234p-2
  },
  { // Entry 202
    0x1.7a41970365eebffe84779d36e5b55ff9p-4,
    0x1.9ce739ce739c1p-11
  },
  { // Entry 203
    -0x1.7a41970365eebffe84779d36e5b55ff9p-4,
    -0x1.9ce739ce739c1p-11
  },
  { // Entry 204
    0x1.dd182f9eccd338154df52c8068d21c58p-4,
    0x1.9e429e92b01aap-10
  },
  { // Entry 205
    -0x1.dd182f9eccd338154df52c8068d21c58p-4,
    -0x1.9e429e92b01aap-10
  },
  { // Entry 206
    0x1.7b184c99eafd98080039f19cdaba9566p-2,
    0x1.9fa7e9fa7e9f8p-5
  },
  { // Entry 207
    -0x1.7b184c99eafd98080039f19cdaba9566p-2,
    -0x1.9fa7e9fa7e9f8p-5
  },
  { // Entry 208
    0x1.2cf888f8db02e80cf78a32d60db9310ep-1,
    0x1.ap-3
  },
  { // Entry 209
    -0x1.2cf888f8db02e80cf78a32d60db9310ep-1,
    -0x1.ap-3
  },
  { // Entry 210
    0x1.7d9d668054af70ab308f4cce4f06da18p-12,
    0x1.a80p-35
  },
  { // Entry 211
    -0x1.7d9d668054af70ab308f4cce4f06da18p-12,
    -0x1.a80p-35
  },
  { // Entry 212
    0x1.7f867ca5bf7fd8000095d700659c419bp1,
    0x1.ae666667ef215p4
  },
  { // Entry 213
    -0x1.7f867ca5bf7fd8000095d700659c419bp1,
    -0x1.ae666667ef215p4
  },
  { // Entry 214
    0x1.e3ce44a1a91cb00d803d37f957814cd0p-1,
    0x1.affd4ad81d672p-1
  },
  { // Entry 215
    -0x1.e3ce44a1a91cb00d803d37f957814cd0p-1,
    -0x1.affd4ad81d672p-1
  },
  { // Entry 216
    0x1.807936a48a0f47ffff8f15d7f7433972p1,
    0x1.b199999b7b95cp4
  },
  { // Entry 217
    -0x1.807936a48a0f47ffff8f15d7f7433972p1,
    -0x1.b199999b7b95cp4
  },
  { // Entry 218
    0x1.e59391f23400e00084dca80338a86267p-14,
    0x1.b4cp-40
  },
  { // Entry 219
    -0x1.e59391f23400e00084dca80338a86267p-14,
    -0x1.b4cp-40
  },
  { // Entry 220
    0x1.32e4d254e0dc255221323a5c06838a1ap0,
    0x1.b90bf360408b6p0
  },
  { // Entry 221
    -0x1.32e4d254e0dc255221323a5c06838a1ap0,
    -0x1.b90bf360408b6p0
  },
  { // Entry 222
    0x1.e86c9f7f43066f552417904aa615b9a0p3,
    0x1.bc7acad8dd5acp11
  },
  { // Entry 223
    -0x1.e86c9f7f43066f552417904aa615b9a0p3,
    -0x1.bc7acad8dd5acp11
  },
  { // Entry 224
    0x1.e9b5dba58189dbbca0a6d76e870ebb59p-348,
    0x1.cp-1042
  },
  { // Entry 225
    -0x1.e9b5dba58189dbbca0a6d76e870ebb59p-348,
    -0x1.cp-1042
  },
  { // Entry 226
    0x1.eac78857bf50afff5f93dd134572416dp-11,
    0x1.c2f0bc2f0bc21p-31
  },
  { // Entry 227
    -0x1.eac78857bf50afff5f93dd134572416dp-11,
    -0x1.c2f0bc2f0bc21p-31
  },
  { // Entry 228
    0x1.ec05b532dfa5c62bee423818abe2bee1p-14,
    0x1.c66p-40
  },
  { // Entry 229
    -0x1.ec05b532dfa5c62bee423818abe2bee1p-14,
    -0x1.c66p-40
  },
  { // Entry 230
    0x1.ee6a99864dfff7f9fa4d2ad7424eaa16p0,
    0x1.cd0a43a2eeb58p2
  },
  { // Entry 231
    -0x1.ee6a99864dfff7f9fa4d2ad7424eaa16p0,
    -0x1.cd0a43a2eeb58p2
  },
  { // Entry 232
    0x1.3943209755b3d556bbdf7b713db939cbp0,
    0x1.d513b4b6d224dp0
  },
  { // Entry 233
    -0x1.3943209755b3d556bbdf7b713db939cbp0,
    -0x1.d513b4b6d224dp0
  },
  { // Entry 234
    0x1.396bdc60bdb41f01722a27e291122a02p0,
    0x1.d5cac80757178p0
  },
  { // Entry 235
    -0x1.396bdc60bdb41f01722a27e291122a02p0,
    -0x1.d5cac80757178p0
  },
  { // Entry 236
    0x1.8ae2d99c67b21d4a107cd7180cb6047cp0,
    0x1.d5cac80757234p1
  },
  { // Entry 237
    -0x1.8ae2d99c67b21d4a107cd7180cb6047cp0,
    -0x1.d5cac80757234p1
  },
  { // Entry 238
    0x1.8ae2d99c67b3b0c177f3b4d020019db3p0,
    0x1.d5cac8075728ep1
  },
  { // Entry 239
    -0x1.8ae2d99c67b3b0c177f3b4d020019db3p0,
    -0x1.d5cac8075728ep1
  },
  { // Entry 240
    0x1.f51a62037e9555df224a09e8431605ecp-348,
    0x1.ep-1042
  },
  { // Entry 241
    -0x1.f51a62037e9555df224a09e8431605ecp-348,
    -0x1.ep-1042
  },
  { // Entry 242
    0x1.8f1aa664697648005040ca059dec2aa7p1,
    0x1.e501f9914b497p4
  },
  { // Entry 243
    -0x1.8f1aa664697648005040ca059dec2aa7p1,
    -0x1.e501f9914b497p4
  },
  { // Entry 244
    0x1.91d389680d252578c71bd969e9e5df7cp-12,
    0x1.ef0p-35
  },
  { // Entry 245
    -0x1.91d389680d252578c71bd969e9e5df7cp-12,
    -0x1.ef0p-35
  },
  { // Entry 246
    0x1.fa9c3138585675b633ac519bbe7eb6cap-1,
    0x1.fp-1
  },
  { // Entry 247
    -0x1.fa9c3138585675b633ac519bbe7eb6cap-1,
    -0x1.fp-1
  },
  { // Entry 248
    0x1.92a20771ff112584a4790389196565d1p0,
    0x1.f1fca6c583c30p1
  },
  { // Entry 249
    -0x1.92a20771ff112584a4790389196565d1p0,
    -0x1.f1fca6c583c30p1
  },
  { // Entry 250
    0x1.fd7cd96ce16437fdae1d4bfb787b426fp-14,
    0x1.f88p-40
  },
  { // Entry 251
    -0x1.fd7cd96ce16437fdae1d4bfb787b426fp-14,
    -0x1.f88p-40
  },
  { // Entry 252
    0x1.fe9c895bb318681d0b5408d96d1beae5p-1,
    0x1.fbd87fc327a2dp-1
  },
  { // Entry 253
    -0x1.fe9c895bb318681d0b5408d96d1beae5p-1,
    -0x1.fbd87fc327a2dp-1
  },
  { // Entry 254
    0x1.feb271deb951f820004e9934bbbf7e43p-1,
    0x1.fc19e0f734ee1p-1
  },
  { // Entry 255
    -0x1.feb271deb951f820004e9934bbbf7e43p-1,
    -0x1.fc19e0f734ee1p-1
  },
  { // Entry 256
    0x1.9583540d8fdae068f8c9ddb6ceab0c37p-14,
    0x1.fccp-41
  },
  { // Entry 257
    -0x1.9583540d8fdae068f8c9ddb6ceab0c37p-14,
    -0x1.fccp-41
  },
  { // Entry 258
    0x1.feee5cca3c43bff6182abd6ea83a6125p-1,
    0x1.fcccccccccccdp-1
  },
  { // Entry 259
    -0x1.feee5cca3c43bff6182abd6ea83a6125p-1,
    -0x1.fcccccccccccdp-1
  },
  { // Entry 260
    0x1.96143e1178b6a02e01899e1296e91759p-2,
    0x1.fee22eb294d1cp-5
  },
  { // Entry 261
    -0x1.96143e1178b6a02e01899e1296e91759p-2,
    -0x1.fee22eb294d1cp-5
  },
  { // Entry 262
    0x1.ffa545425dad5803a4c5925748cce2a0p-341,
    0x1.feeffffffffffp-1021
  },
  { // Entry 263
    -0x1.ffa545425dad5803a4c5925748cce2a0p-341,
    -0x1.feeffffffffffp-1021
  },
  { // Entry 264
    0x1.ffb49f9263cfa814d8ba77ebbb974678p-4,
    0x1.ff1e000000070p-10
  },
  { // Entry 265
    -0x1.ffb49f9263cfa814d8ba77ebbb974678p-4,
    -0x1.ff1e000000070p-10
  },
  { // Entry 266
    0x1.ffc5b3203ea9282e4a10ace3963e1fbbp1,
    0x1.ff512d4a5d2dcp5
  },
  { // Entry 267
    -0x1.ffc5b3203ea9282e4a10ace3963e1fbbp1,
    -0x1.ff512d4a5d2dcp5
  },
  { // Entry 268
    0x1.965207315dc4902bd076fcf408a70902p-1,
    0x1.ffcb843a0a6cbp-2
  },
  { // Entry 269
    -0x1.965207315dc4902bd076fcf408a70902p-1,
    -0x1.ffcb843a0a6cbp-2
  },
  { // Entry 270
    0x1.965316982580502bb83c58cdaeb3a369p0,
    0x1.ffcf85cbf1176p1
  },
  { // Entry 271
    -0x1.965316982580502bb83c58cdaeb3a369p0,
    -0x1.ffcf85cbf1176p1
  },
  { // Entry 272
    0x1.42801af6b3a2a61ff5fa71d0a6845a9bp-340,
    0x1.ffcffffffffffp-1020
  },
  { // Entry 273
    -0x1.42801af6b3a2a61ff5fa71d0a6845a9bp-340,
    -0x1.ffcffffffffffp-1020
  },
  { // Entry 274
    0x1.965fea101c3caaac6eab292aa5769bcap-14,
    0x1.fffffefffffffp-41
  },
  { // Entry 275
    -0x1.965fea101c3caaac6eab292aa5769bcap-14,
    -0x1.fffffefffffffp-41
  },
  { // Entry 276
    0x1.fffffff555554fc71c718c3f35a9339fp-14,
    0x1.ffffffdffffffp-40
  },
  { // Entry 277
    -0x1.fffffff555554fc71c718c3f35a9339fp-14,
    -0x1.ffffffdffffffp-40
  },
  { // Entry 278
    0x1.965fea4d7d641a86999ad2b1b38192d3p-14,
    0x1.ffffffe7fffffp-41
  },
  { // Entry 279
    -0x1.965fea4d7d641a86999ad2b1b38192d3p-14,
    -0x1.ffffffe7fffffp-41
  },
  { // Entry 280
    0x1.965fea4d7d641a86999ad2b1b38192d3p0,
    0x1.ffffffe7fffffp1
  },
  { // Entry 281
    -0x1.965fea4d7d641a86999ad2b1b38192d3p0,
    -0x1.ffffffe7fffffp1
  },
  { // Entry 282
    0x1.965fea4d7d641a86999ad2b1b38192d3p13,
    0x1.ffffffe7fffffp40
  },
  { // Entry 283
    -0x1.965fea4d7d641a86999ad2b1b38192d3p13,
    -0x1.ffffffe7fffffp40
  },
  { // Entry 284
    0x1.fffffffd55554ffc71c70e30fcc8817fp-14,
    0x1.fffffff7fffffp-40
  },
  { // Entry 285
    -0x1.fffffffd55554ffc71c70e30fcc8817fp-14,
    -0x1.fffffff7fffffp-40
  },
  { // Entry 286
    0x1.fffffffffff34fffffffffaf837fffffp-1,
    0x1.ffffffffffd9fp-1
  },
  { // Entry 287
    -0x1.fffffffffff34fffffffffaf837fffffp-1,
    -0x1.ffffffffffd9fp-1
  },
  { // Entry 288
    0x1.fffffffffff9ffffffffffedffffffffp-341,
    0x1.ffffffffffee0p-1021
  },
  { // Entry 289
    -0x1.fffffffffff9ffffffffffedffffffffp-341,
    -0x1.ffffffffffee0p-1021
  },
  { // Entry 290
    0x1.ffffffffffff9fffffffffffedffffffp-341,
    0x1.fffffffffffeep-1021
  },
  { // Entry 291
    -0x1.ffffffffffff9fffffffffffedffffffp-341,
    -0x1.fffffffffffeep-1021
  },
  { // Entry 292
    0x1.965fea53d6e38034b41ac1fbdae9a22fp-14,
    0x1.fffffffffffefp-41
  },
  { // Entry 293
    -0x1.965fea53d6e38034b41ac1fbdae9a22fp-14,
    -0x1.fffffffffffefp-41
  },
  { // Entry 294
    0x1.965fea53d6e38034b41ac1fbdae9a22fp0,
    0x1.fffffffffffefp1
  },
  { // Entry 295
    -0x1.965fea53d6e38034b41ac1fbdae9a22fp0,
    -0x1.fffffffffffefp1
  },
  { // Entry 296
    0x1.965fea53d6e38034b41ac1fbdae9a22fp13,
    0x1.fffffffffffefp40
  },
  { // Entry 297
    -0x1.965fea53d6e38034b41ac1fbdae9a22fp13,
    -0x1.fffffffffffefp40
  },
  { // Entry 298
    0x1.ffffffffffffeaaaaaaaaaaaa9c71c71p-14,
    0x1.ffffffffffffcp-40
  },
  { // Entry 299
    -0x1.ffffffffffffeaaaaaaaaaaaa9c71c71p-14,
    -0x1.ffffffffffffcp-40
  },
  { // Entry 300
    0x1.ffffffffffffeaaaaaaaaaaaa9c71c71p-341,
    0x1.ffffffffffffcp-1021
  },
  { // Entry 301
    -0x1.ffffffffffffeaaaaaaaaaaaa9c71c71p-341,
    -0x1.ffffffffffffcp-1021
  },
  { // Entry 302
    0x1.428a2f98d728a76a078787ef8fb5d54bp-340,
    0x1.ffffffffffffep-1020
  },
  { // Entry 303
    -0x1.428a2f98d728a76a078787ef8fb5d54bp-340,
    -0x1.ffffffffffffep-1020
  },
  { // Entry 304
    0x1.965fea53d6e3bfb3b0b7db8f7ec17d0fp-341,
    0x1.ffffffffffffep-1022
  },
  { // Entry 305
    -0x1.965fea53d6e3bfb3b0b7db8f7ec17d0fp-341,
    -0x1.ffffffffffffep-1022
  },
  { // Entry 306
    0x1.p0,
    0x1.0p0
  },
  { // Entry 307
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 308
    0x1.0ce9d573f43b4429b89ec57945e5d434p0,
    0x1.28ba2e8ba2e8cp0
  },
  { // Entry 309
    -0x1.0ce9d573f43b4429b89ec57945e5d434p0,
    -0x1.28ba2e8ba2e8cp0
  },
  { // Entry 310
    0x1.18b16f086288d6f00ce5c5780fcb86f0p0,
    0x1.51745d1745d18p0
  },
  { // Entry 311
    -0x1.18b16f086288d6f00ce5c5780fcb86f0p0,
    -0x1.51745d1745d18p0
  },
  { // Entry 312
    0x1.238f2c8477adc049b515c7f78f3ae422p0,
    0x1.7a2e8ba2e8ba4p0
  },
  { // Entry 313
    -0x1.238f2c8477adc049b515c7f78f3ae422p0,
    -0x1.7a2e8ba2e8ba4p0
  },
  { // Entry 314
    0x1.2dabb7e49e39ff2a10deddc33bc81fccp0,
    0x1.a2e8ba2e8ba30p0
  },
  { // Entry 315
    -0x1.2dabb7e49e39ff2a10deddc33bc81fccp0,
    -0x1.a2e8ba2e8ba30p0
  },
  { // Entry 316
    0x1.372579fd08bf3f740d425e125a1352ffp0,
    0x1.cba2e8ba2e8bcp0
  },
  { // Entry 317
    -0x1.372579fd08bf3f740d425e125a1352ffp0,
    -0x1.cba2e8ba2e8bcp0
  },
  { // Entry 318
    0x1.4013dac5da2a703e1c77ca4721acee1cp0,
    0x1.f45d1745d1748p0
  },
  { // Entry 319
    -0x1.4013dac5da2a703e1c77ca4721acee1cp0,
    -0x1.f45d1745d1748p0
  },
  { // Entry 320
    0x1.48894c52b3445f6f84012f405de32fa2p0,
    0x1.0e8ba2e8ba2eap1
  },
  { // Entry 321
    -0x1.48894c52b3445f6f84012f405de32fa2p0,
    -0x1.0e8ba2e8ba2eap1
  },
  { // Entry 322
    0x1.5094a1d6e6b639229cdb3810b410cd5cp0,
    0x1.22e8ba2e8ba30p1
  },
  { // Entry 323
    -0x1.5094a1d6e6b639229cdb3810b410cd5cp0,
    -0x1.22e8ba2e8ba30p1
  },
  { // Entry 324
    0x1.5841f8c61fd58c8dad04fdec3cf0af73p0,
    0x1.3745d1745d176p1
  },
  { // Entry 325
    -0x1.5841f8c61fd58c8dad04fdec3cf0af73p0,
    -0x1.3745d1745d176p1
  },
  { // Entry 326
    0x1.5f9b5c16910ae69ed06d3e621a09f184p0,
    0x1.4ba2e8ba2e8bcp1
  },
  { // Entry 327
    -0x1.5f9b5c16910ae69ed06d3e621a09f184p0,
    -0x1.4ba2e8ba2e8bcp1
  },
  { // Entry 328
    0x1.66a9398ba2a3a698c051df109f770e88p0,
    0x1.6000000000002p1
  },
  { // Entry 329
    -0x1.66a9398ba2a3a698c051df109f770e88p0,
    -0x1.6000000000002p1
  },
  { // Entry 330
    0x1.6d72b7dcc7672cfcef1093936e2afe79p0,
    0x1.745d1745d1748p1
  },
  { // Entry 331
    -0x1.6d72b7dcc7672cfcef1093936e2afe79p0,
    -0x1.745d1745d1748p1
  },
  { // Entry 332
    0x1.73fdf738e55e14736c80bd51b7812f30p0,
    0x1.88ba2e8ba2e8ep1
  },
  { // Entry 333
    -0x1.73fdf738e55e14736c80bd51b7812f30p0,
    -0x1.88ba2e8ba2e8ep1
  },
  { // Entry 334
    0x1.7a504269f3f8eaacfe698899d72d5624p0,
    0x1.9d1745d1745d4p1
  },
  { // Entry 335
    -0x1.7a504269f3f8eaacfe698899d72d5624p0,
    -0x1.9d1745d1745d4p1
  },
  { // Entry 336
    0x1.806e34d4af571a8ec04858e9296e6f3bp0,
    0x1.b1745d1745d1ap1
  },
  { // Entry 337
    -0x1.806e34d4af571a8ec04858e9296e6f3bp0,
    -0x1.b1745d1745d1ap1
  },
  { // Entry 338
    0x1.865bd841493085e78103debe7c1f93c8p0,
    0x1.c5d1745d17460p1
  },
  { // Entry 339
    -0x1.865bd841493085e78103debe7c1f93c8p0,
    -0x1.c5d1745d17460p1
  },
  { // Entry 340
    0x1.8c1cbc7cd4e55e886cb4a94f63941b44p0,
    0x1.da2e8ba2e8ba6p1
  },
  { // Entry 341
    -0x1.8c1cbc7cd4e55e886cb4a94f63941b44p0,
    -0x1.da2e8ba2e8ba6p1
  },
  { // Entry 342
    0x1.91b40a4df21132c467d86553807600cdp0,
    0x1.ee8ba2e8ba2ecp1
  },
  { // Entry 343
    -0x1.91b40a4df21132c467d86553807600cdp0,
    -0x1.ee8ba2e8ba2ecp1
  },
  { // Entry 344
    0x1.972492d08e2c99d904b83bd8d8b5b7b7p0,
    0x1.01745d1745d19p2
  },
  { // Entry 345
    -0x1.972492d08e2c99d904b83bd8d8b5b7b7p0,
    -0x1.01745d1745d19p2
  },
  { // Entry 346
    0x1.9c70dc04b206ec6b858fbed95865bda0p0,
    0x1.0ba2e8ba2e8bcp2
  },
  { // Entry 347
    -0x1.9c70dc04b206ec6b858fbed95865bda0p0,
    -0x1.0ba2e8ba2e8bcp2
  },
  { // Entry 348
    0x1.a19b2b2929306e418bc85ca14b471159p0,
    0x1.15d1745d1745fp2
  },
  { // Entry 349
    -0x1.a19b2b2929306e418bc85ca14b471159p0,
    -0x1.15d1745d1745fp2
  },
  { // Entry 350
    0x1.a6a58d55e307cd862806e73ea3aa75dcp0,
    0x1.2000000000002p2
  },
  { // Entry 351
    -0x1.a6a58d55e307cd862806e73ea3aa75dcp0,
    -0x1.2000000000002p2
  },
  { // Entry 352
    0x1.ab91deaee6e7398a4db8d908e1d20b42p0,
    0x1.2a2e8ba2e8ba5p2
  },
  { // Entry 353
    -0x1.ab91deaee6e7398a4db8d908e1d20b42p0,
    -0x1.
```
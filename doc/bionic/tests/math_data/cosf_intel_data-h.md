Response:
The user wants a summary of the provided C code file. The file is located in the `bionic/tests/math_data` directory, specifically for `cosf` and "intel data" on Android.

Therefore, the file likely contains test data for the `cosf` function, tailored for Intel architectures within the Android bionic library.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core function:** The file name `cosf_intel_data.handroid` strongly suggests the data is related to the `cosf` function (cosine for floats).

2. **Determine the purpose:** The file resides in a `tests` directory and is named "*_data*", indicating it holds data used for testing. The "intel" part further specifies the target architecture.

3. **Understand the data structure:** The code defines `g_cosf_intel_data` as an array of `data_1_1_t<float, float>`. Each element in the array appears to be a pair of floating-point numbers.

4. **Infer the meaning of the data:**  Given it's `cosf` test data, the two floats in each pair likely represent an input value and the expected output of the `cosf` function for that input.

5. **Relate to Android:** The file is within the bionic library, which is a core part of Android. This means this test data is used to ensure the `cosf` function in Android's C library works correctly on Intel-based Android devices.

6. **Formulate the summary:** Combine these points into a concise summary.
这是 `bionic/tests/math_data/cosf_intel_data.handroid` 源代码文件的第一部分。根据文件名和路径，可以归纳出它的主要功能是：

**存储用于测试 `cosf` 函数（单精度浮点数余弦函数）在 Intel 架构 Android 设备上的测试数据。**

更具体地说：

* **测试数据:**  文件中的 `g_cosf_intel_data` 数组包含了大量的测试用例。
* **针对 `cosf` 函数:**  文件名明确指出这些数据用于测试 `cosf` 函数的正确性。
* **Intel 架构:**  文件名中的 "intel" 表明这些测试数据可能是针对 Intel 处理器的特定特性或已知问题而设计的。
* **Android 平台:**  文件路径位于 Android 的 bionic 库测试目录中，说明这些测试是 Android 系统自身的一部分，用于保证其 C 库的正确性。

**总结来说，这个文件的功能是为 Android 系统中 `cosf` 函数在 Intel 架构上的实现提供一组预定义的输入和预期输出，用于进行单元测试和验证。**

Prompt: 
```
这是目录为bionic/tests/math_data/cosf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_cosf_intel_data[] = {
  { // Entry 0
    0x1.bc7b66ffb7689d646dd1af83e9661d2dp-1,
    -0x1.09ebacp-1
  },
  { // Entry 1
    0x1.bc7b66ffb7689d646dd1af83e9661d2dp-1,
    0x1.09ebacp-1
  },
  { // Entry 2
    0x1.dee8d0fffcd997ce5cfbab0a5a336c14p-5,
    -0x1.156564p4
  },
  { // Entry 3
    0x1.dee8d0fffcd997ce5cfbab0a5a336c14p-5,
    0x1.156564p4
  },
  { // Entry 4
    -0x1.c11bb2f056552ca4cdb6c5a0cf71509dp-8,
    -0x1.406a40p6
  },
  { // Entry 5
    -0x1.c11bb2f056552ca4cdb6c5a0cf71509dp-8,
    0x1.406a40p6
  },
  { // Entry 6
    0x1.ff836cff97077bf489aadc5f349a9fb9p-1,
    -0x1.653078p-5
  },
  { // Entry 7
    0x1.ff836cff97077bf489aadc5f349a9fb9p-1,
    0x1.653078p-5
  },
  { // Entry 8
    0x1.b29cd4f9da2964e8c6bb5693387d3f3bp-5,
    -0x1.6c0008p5
  },
  { // Entry 9
    0x1.b29cd4f9da2964e8c6bb5693387d3f3bp-5,
    0x1.6c0008p5
  },
  { // Entry 10
    0x1.df40d3f650f6c94390a3ca5d8d9b48c1p-1,
    -0x1.703824p-2
  },
  { // Entry 11
    0x1.df40d3f650f6c94390a3ca5d8d9b48c1p-1,
    0x1.703824p-2
  },
  { // Entry 12
    0x1.f76316f541e10ef15d57c5a23775329cp-1,
    -0x1.782e2ep-3
  },
  { // Entry 13
    0x1.f76316f541e10ef15d57c5a23775329cp-1,
    0x1.782e2ep-3
  },
  { // Entry 14
    0x1.cfab0ec2fc95382986fa511648bd4e6fp-24,
    -0x1.8e3266p9
  },
  { // Entry 15
    0x1.cfab0ec2fc95382986fa511648bd4e6fp-24,
    0x1.8e3266p9
  },
  { // Entry 16
    0x1.92e66b5920a85d6083e9cc85568ceaa3p-21,
    -0x1.c6ac02p14
  },
  { // Entry 17
    0x1.92e66b5920a85d6083e9cc85568ceaa3p-21,
    0x1.c6ac02p14
  },
  { // Entry 18
    0x1.d1ceb4ffff6ed05b5ef5fc618231214ap-2,
    -0x1.e513fcp4
  },
  { // Entry 19
    0x1.d1ceb4ffff6ed05b5ef5fc618231214ap-2,
    0x1.e513fcp4
  },
  { // Entry 20
    0x1.c27e049dfeab38e1b8ea6a09631829fep-1,
    -0x1.fb1904p-2
  },
  { // Entry 21
    0x1.c27e049dfeab38e1b8ea6a09631829fep-1,
    0x1.fb1904p-2
  },
  { // Entry 22
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    -0x1.fffffep127
  },
  { // Entry 23
    0x1.b4bf2c79bdfcdaa53ed6c013f65e0963p-1,
    0x1.fffffep127
  },
  { // Entry 24
    0x1.ffffff000000155555549f49f4a28a28p-1,
    0x1.p-12
  },
  { // Entry 25
    0x1.ffffff000000155555549f49f4a28a28p-1,
    -0x1.p-12
  },
  { // Entry 26
    0x1.ffffffffffc000000000015555555555p-1,
    0x1.p-21
  },
  { // Entry 27
    0x1.ffffffffffc000000000015555555555p-1,
    -0x1.p-21
  },
  { // Entry 28
    0x1.fffffffffff000000000001555555555p-1,
    0x1.p-22
  },
  { // Entry 29
    0x1.fffffffffff000000000001555555555p-1,
    -0x1.p-22
  },
  { // Entry 30
    0x1.fffffefffffc155551ff49f696c4aecap-1,
    0x1.000002p-12
  },
  { // Entry 31
    0x1.fffffefffffc155551ff49f696c4aecap-1,
    -0x1.000002p-12
  },
  { // Entry 32
    0x1.882d606ba07505a7a09ae74d713f9788p-1,
    0x1.000002p51
  },
  { // Entry 33
    0x1.882d606ba07505a7a09ae74d713f9788p-1,
    -0x1.000002p51
  },
  { // Entry 34
    0x1.fc0154f7f5b6422f7794bf156ee98b7ep-1,
    0x1.000006p-3
  },
  { // Entry 35
    0x1.fc0154f7f5b6422f7794bf156ee98b7ep-1,
    -0x1.000006p-3
  },
  { // Entry 36
    0x1.34e976ef67d60a3de814ad3d0203ba21p-10,
    0x1.000006p121
  },
  { // Entry 37
    0x1.34e976ef67d60a3de814ad3d0203ba21p-10,
    -0x1.000006p121
  },
  { // Entry 38
    -0x1.ffffa2cf59398dc6180801e9ea3120c8p-1,
    0x1.000006p122
  },
  { // Entry 39
    -0x1.ffffa2cf59398dc6180801e9ea3120c8p-1,
    -0x1.000006p122
  },
  { // Entry 40
    0x1.ffc0014453315d47e2a318bf63e4caa7p-1,
    0x1.000022p-5
  },
  { // Entry 41
    0x1.ffc0014453315d47e2a318bf63e4caa7p-1,
    -0x1.000022p-5
  },
  { // Entry 42
    0x1.c15215015f3d916a0019a39e3acc7364p-1,
    0x1.0000e0p-1
  },
  { // Entry 43
    0x1.c15215015f3d916a0019a39e3acc7364p-1,
    -0x1.0000e0p-1
  },
  { // Entry 44
    0x1.ff001394e93085c7cce53915893af765p-1,
    0x1.0000e0p-4
  },
  { // Entry 45
    0x1.ff001394e93085c7cce53915893af765p-1,
    -0x1.0000e0p-4
  },
  { // Entry 46
    0x1.90b0c97de2370587a68aeae2b6943953p-15,
    0x1.000322p23
  },
  { // Entry 47
    0x1.90b0c97de2370587a68aeae2b6943953p-15,
    -0x1.000322p23
  },
  { // Entry 48
    -0x1.8b90c67677565874f44d9314ca2ba634p-6,
    0x1.000402p8
  },
  { // Entry 49
    -0x1.8b90c67677565874f44d9314ca2ba634p-6,
    -0x1.000402p8
  },
  { // Entry 50
    0x1.14735fffd55120a4480b7c91a1d78d6ep-1,
    0x1.001cp0
  },
  { // Entry 51
    0x1.14735fffd55120a4480b7c91a1d78d6ep-1,
    -0x1.001cp0
  },
  { // Entry 52
    0x1.c0b6d10005468a3a3eb056eb59b58ce2p-1,
    0x1.0144p-1
  },
  { // Entry 53
    0x1.c0b6d10005468a3a3eb056eb59b58ce2p-1,
    -0x1.0144p-1
  },
  { // Entry 54
    -0x1.c403d90006509b0762642d0bea40e4b1p-2,
    0x1.0394c8p1
  },
  { // Entry 55
    -0x1.c403d90006509b0762642d0bea40e4b1p-2,
    -0x1.0394c8p1
  },
  { // Entry 56
    -0x1.270da18b198e6ebfc8782082902bf2d4p-25,
    0x1.04ccbcp18
  },
  { // Entry 57
    -0x1.270da18b198e6ebfc8782082902bf2d4p-25,
    -0x1.04ccbcp18
  },
  { // Entry 58
    0x1.ee0f67015b9fb39ba6eb91d47829c913p-1,
    0x1.07b518p99
  },
  { // Entry 59
    0x1.ee0f67015b9fb39ba6eb91d47829c913p-1,
    -0x1.07b518p99
  },
  { // Entry 60
    0x1.fef05d000666cb47f1632c478a6282a8p-1,
    0x1.07bf80p-4
  },
  { // Entry 61
    0x1.fef05d000666cb47f1632c478a6282a8p-1,
    -0x1.07bf80p-4
  },
  { // Entry 62
    0x1.16f4330000b44c8288679f8c79d36c4fp-6,
    0x1.07c1f0p5
  },
  { // Entry 63
    0x1.16f4330000b44c8288679f8c79d36c4fp-6,
    -0x1.07c1f0p5
  },
  { // Entry 64
    0x1.cfb404557277d85bf149496d46c2fa9fp-18,
    0x1.0bd21ep9
  },
  { // Entry 65
    0x1.cfb404557277d85bf149496d46c2fa9fp-18,
    -0x1.0bd21ep9
  },
  { // Entry 66
    0x1.bb543efffd6cacac12698b8a94ed2c3ep-1,
    0x1.0c3cp-1
  },
  { // Entry 67
    0x1.bb543efffd6cacac12698b8a94ed2c3ep-1,
    -0x1.0c3cp-1
  },
  { // Entry 68
    0x1.bb0a22c13b616cdcad32c7fca58e6643p-1,
    0x1.0cd0p-1
  },
  { // Entry 69
    0x1.bb0a22c13b616cdcad32c7fca58e6643p-1,
    -0x1.0cd0p-1
  },
  { // Entry 70
    0x1.f98f9b1d05e7c922ac5e5c6b6ac86876p-2,
    0x1.0df0p0
  },
  { // Entry 71
    0x1.f98f9b1d05e7c922ac5e5c6b6ac86876p-2,
    -0x1.0df0p0
  },
  { // Entry 72
    0x1.ee15181830c25b0b10ce671e8f7a3289p-1,
    0x1.0fb4p-2
  },
  { // Entry 73
    0x1.ee15181830c25b0b10ce671e8f7a3289p-1,
    -0x1.0fb4p-2
  },
  { // Entry 74
    0x1.edf6cc16defe6361f38ffa60ece3944cp-1,
    0x1.109ab2p-2
  },
  { // Entry 75
    0x1.edf6cc16defe6361f38ffa60ece3944cp-1,
    -0x1.109ab2p-2
  },
  { // Entry 76
    0x1.dee8d0fffcd997ce5cfbab0a5a336c14p-5,
    0x1.156564p4
  },
  { // Entry 77
    0x1.dee8d0fffcd997ce5cfbab0a5a336c14p-5,
    -0x1.156564p4
  },
  { // Entry 78
    0x1.b656d60000155bacb4aa874b28de2ff9p-1,
    0x1.160cp-1
  },
  { // Entry 79
    0x1.b656d60000155bacb4aa874b28de2ff9p-1,
    -0x1.160cp-1
  },
  { // Entry 80
    0x1.ffb275967c191ee95f862efb4f790cecp-1,
    0x1.19ccp-5
  },
  { // Entry 81
    0x1.ffb275967c191ee95f862efb4f790cecp-1,
    -0x1.19ccp-5
  },
  { // Entry 82
    0x1.c59c50ffe542233b7ea21100df87bb60p-2,
    0x1.1ca4p0
  },
  { // Entry 83
    0x1.c59c50ffe542233b7ea21100df87bb60p-2,
    -0x1.1ca4p0
  },
  { // Entry 84
    0x1.af630f86b77571b9de2f17fee2b6c5cep-5,
    0x1.1ffffep79
  },
  { // Entry 85
    0x1.af630f86b77571b9de2f17fee2b6c5cep-5,
    -0x1.1ffffep79
  },
  { // Entry 86
    0x1.b1493ef1fbc62673ec140c12adc5a134p-6,
    0x1.2620p10
  },
  { // Entry 87
    0x1.b1493ef1fbc62673ec140c12adc5a134p-6,
    -0x1.2620p10
  },
  { // Entry 88
    -0x1.ad00b6f15c6ac5c3e79ef55d2fec70bdp-5,
    0x1.2a3d62p2
  },
  { // Entry 89
    -0x1.ad00b6f15c6ac5c3e79ef55d2fec70bdp-5,
    -0x1.2a3d62p2
  },
  { // Entry 90
    -0x1.ab9984f283f114cf13cc6df38c67955fp-6,
    0x1.2bec22p2
  },
  { // Entry 91
    -0x1.ab9984f283f114cf13cc6df38c67955fp-6,
    -0x1.2bec22p2
  },
  { // Entry 92
    0x1.99bc5b961b1acaca18d971f68ae99da9p-27,
    0x1.2d97c8p2
  },
  { // Entry 93
    0x1.99bc5b961b1acaca18d971f68ae99da9p-27,
    -0x1.2d97c8p2
  },
  { // Entry 94
    -0x1.ffffffffffffd703498c3b8288563915p-1,
    0x1.2d97c8p3
  },
  { // Entry 95
    -0x1.ffffffffffffd703498c3b8288563915p-1,
    -0x1.2d97c8p3
  },
  { // Entry 96
    0x1.ffffffffffff5c0d2630ee0a27e8d6d1p-1,
    0x1.2d97c8p4
  },
  { // Entry 97
    0x1.ffffffffffff5c0d2630ee0a27e8d6d1p-1,
    -0x1.2d97c8p4
  },
  { // Entry 98
    -0x1.99b69cf0c4a2c8ddad3f4cf29453e509p-6,
    0x1.2fefc4p9
  },
  { // Entry 99
    -0x1.99b69cf0c4a2c8ddad3f4cf29453e509p-6,
    -0x1.2fefc4p9
  },
  { // Entry 100
    0x1.e92148328d620fc186df9d6ce1088fd9p-1,
    0x1.333724p-2
  },
  { // Entry 101
    0x1.e92148328d620fc186df9d6ce1088fd9p-1,
    -0x1.333724p-2
  },
  { // Entry 102
    0x1.a1caab00002d3189e0699f2aaf20d9fcp-1,
    0x1.3b90f8p-1
  },
  { // Entry 103
    0x1.a1caab00002d3189e0699f2aaf20d9fcp-1,
    -0x1.3b90f8p-1
  },
  { // Entry 104
    0x1.fc33baffffffbb055ce03690bd392531p-1,
    0x1.41c470p16
  },
  { // Entry 105
    0x1.fc33baffffffbb055ce03690bd392531p-1,
    -0x1.41c470p16
  },
  { // Entry 106
    0x1.4798b30672f21602a21aaf471e8259a0p-19,
    0x1.442f74p15
  },
  { // Entry 107
    0x1.4798b30672f21602a21aaf471e8259a0p-19,
    -0x1.442f74p15
  },
  { // Entry 108
    0x1.e2b5ecffffa49c8c68d743c47f624633p-1,
    0x1.5c09dap-2
  },
  { // Entry 109
    0x1.e2b5ecffffa49c8c68d743c47f624633p-1,
    -0x1.5c09dap-2
  },
  { // Entry 110
    0x1.10591094ac58a270d9ad91802df49fd0p-11,
    0x1.5fe0p3
  },
  { // Entry 111
    0x1.10591094ac58a270d9ad91802df49fd0p-11,
    -0x1.5fe0p3
  },
  { // Entry 112
    -0x1.fffe580ee141c0225b44281c1c6f7ff1p-1,
    0x1.665982p119
  },
  { // Entry 113
    -0x1.fffe580ee141c0225b44281c1c6f7ff1p-1,
    -0x1.665982p119
  },
  { // Entry 114
    -0x1.e2b8ecffed91ce3a4b9dc5a592fb0b14p-1,
    0x1.66a0bap1
  },
  { // Entry 115
    -0x1.e2b8ecffed91ce3a4b9dc5a592fb0b14p-1,
    -0x1.66a0bap1
  },
  { // Entry 116
    -0x1.a08c6cfdbe04b859c0e16d478ff81f7bp-5,
    0x1.6bee42p12
  },
  { // Entry 117
    -0x1.a08c6cfdbe04b859c0e16d478ff81f7bp-5,
    -0x1.6bee42p12
  },
  { // Entry 118
    0x1.ff7c719a18439c4267075e2df688343ap-1,
    0x1.6f1070p-5
  },
  { // Entry 119
    0x1.ff7c719a18439c4267075e2df688343ap-1,
    -0x1.6f1070p-5
  },
  { // Entry 120
    0x1.ff7c3b997d6bea661ef0d1e69e222bfep-1,
    0x1.6f5bc2p-5
  },
  { // Entry 121
    0x1.ff7c3b997d6bea661ef0d1e69e222bfep-1,
    -0x1.6f5bc2p-5
  },
  { // Entry 122
    -0x1.6a0a0ee68da131091e29e055226a1bd9p-1,
    0x1.72b53cp5
  },
  { // Entry 123
    -0x1.6a0a0ee68da131091e29e055226a1bd9p-1,
    -0x1.72b53cp5
  },
  { // Entry 124
    0x1.ff777b9a218985c1a191c92b2d11ffbap-1,
    0x1.75ec1ap-5
  },
  { // Entry 125
    0x1.ff777b9a218985c1a191c92b2d11ffbap-1,
    -0x1.75ec1ap-5
  },
  { // Entry 126
    0x1.6d487f92427920e81dc5ae34e0e8d7bap-2,
    0x1.78b3fap100
  },
  { // Entry 127
    0x1.6d487f92427920e81dc5ae34e0e8d7bap-2,
    -0x1.78b3fap100
  },
  { // Entry 128
    0x1.4949c2fffa0cd336dfda998216dae393p-4,
    0x1.7d8568p0
  },
  { // Entry 129
    0x1.4949c2fffa0cd336dfda998216dae393p-4,
    -0x1.7d8568p0
  },
  { // Entry 130
    -0x1.b9ed9eb33eacbfac8151cda113734c29p-1,
    0x1.830688p57
  },
  { // Entry 131
    -0x1.b9ed9eb33eacbfac8151cda113734c29p-1,
    -0x1.830688p57
  },
  { // Entry 132
    0x1.c7349af06d61394cae1912233f64a04ep-5,
    0x1.83e430p0
  },
  { // Entry 133
    0x1.c7349af06d61394cae1912233f64a04ep-5,
    -0x1.83e430p0
  },
  { // Entry 134
    0x1.ab73f0f0fe04403e6a7fdde141a38a8ep-5,
    0x1.84c288p0
  },
  { // Entry 135
    0x1.ab73f0f0fe04403e6a7fdde141a38a8ep-5,
    -0x1.84c288p0
  },
  { // Entry 136
    0x1.ff6c2799dcf0d6c8f7acaf5b0a46e6e2p-1,
    0x1.852140p-5
  },
  { // Entry 137
    0x1.ff6c2799dcf0d6c8f7acaf5b0a46e6e2p-1,
    -0x1.852140p-5
  },
  { // Entry 138
    0x1.ff69ed99de70e51f519f30bad247a4d9p-1,
    0x1.880cb6p-5
  },
  { // Entry 139
    0x1.ff69ed99de70e51f519f30bad247a4d9p-1,
    -0x1.880cb6p-5
  },
  { // Entry 140
    -0x1.fd76c57f872f85bc4b0e1bf591b3b5b0p-1,
    0x1.9364eap119
  },
  { // Entry 141
    -0x1.fd76c57f872f85bc4b0e1bf591b3b5b0p-1,
    -0x1.9364eap119
  },
  { // Entry 142
    -0x1.f87c1ceec5fd5811c9c089cdaeeff13cp-8,
    0x1.979e28p9
  },
  { // Entry 143
    -0x1.f87c1ceec5fd5811c9c089cdaeeff13cp-8,
    -0x1.979e28p9
  },
  { // Entry 144
    -0x1.16ae29144d3b1ea8d907b8776f704157p-26,
    0x1.9a48dep15
  },
  { // Entry 145
    -0x1.16ae29144d3b1ea8d907b8776f704157p-26,
    -0x1.9a48dep15
  },
  { // Entry 146
    -0x1.977552f8e6ab3c01cb29ec77803007cfp-13,
    0x1.9cbc1ap50
  },
  { // Entry 147
    -0x1.977552f8e6ab3c01cb29ec77803007cfp-13,
    -0x1.9cbc1ap50
  },
  { // Entry 148
    0x1.ff58c5ffffffc7266a9df4e921726771p-1,
    0x1.9ddb06p-5
  },
  { // Entry 149
    0x1.ff58c5ffffffc7266a9df4e921726771p-1,
    -0x1.9ddb06p-5
  },
  { // Entry 150
    0x1.fffffffffffff5700019fffff0094c15p-1,
    0x1.9ffffep-27
  },
  { // Entry 151
    0x1.fffffffffffff5700019fffff0094c15p-1,
    -0x1.9ffffep-27
  },
  { // Entry 152
    0x1.31bd63004b1ff4d722c745044706d517p-1,
    0x1.ac129cp24
  },
  { // Entry 153
    0x1.31bd63004b1ff4d722c745044706d517p-1,
    -0x1.ac129cp24
  },
  { // Entry 154
    -0x1.f1ad0f000009e06ce449f5bde03d5d1ap-1,
    0x1.b078f8p1
  },
  { // Entry 155
    -0x1.f1ad0f000009e06ce449f5bde03d5d1ap-1,
    -0x1.b078f8p1
  },
  { // Entry 156
    0x1.ff4776ffe324ba2958aca8d73cf8b839p-1,
    0x1.b2c03cp-5
  },
  { // Entry 157
    0x1.ff4776ffe324ba2958aca8d73cf8b839p-1,
    -0x1.b2c03cp-5
  },
  { // Entry 158
    0x1.ff437f00005e500d29bd8103a8e769e9p-1,
    0x1.b766f6p-5
  },
  { // Entry 159
    0x1.ff437f00005e500d29bd8103a8e769e9p-1,
    -0x1.b766f6p-5
  },
  { // Entry 160
    -0x1.99663da94db7348bcbb257ed16b7227cp-24,
    0x1.beeeeep79
  },
  { // Entry 161
    -0x1.99663da94db7348bcbb257ed16b7227cp-24,
    -0x1.beeeeep79
  },
  { // Entry 162
    0x1.f3d620ffffff860e49bbab8963dcc42ep-1,
    0x1.bf4e1cp-3
  },
  { // Entry 163
    0x1.f3d620ffffff860e49bbab8963dcc42ep-1,
    -0x1.bf4e1cp-3
  },
  { // Entry 164
    0x1.81ff79ed9201755f7ad18b533aa99d18p-1,
    0x1.c0p2
  },
  { // Entry 165
    0x1.81ff79ed9201755f7ad18b533aa99d18p-1,
    -0x1.c0p2
  },
  { // Entry 166
    -0x1.af3c6108887730fcecedf61d2d81ceabp-15,
    0x1.c20ec8p23
  },
  { // Entry 167
    -0x1.af3c6108887730fcecedf61d2d81ceabp-15,
    -0x1.c20ec8p23
  },
  { // Entry 168
    -0x1.b1656ef91447fa6a546cbd81034cafabp-14,
    0x1.c79d20p17
  },
  { // Entry 169
    -0x1.b1656ef91447fa6a546cbd81034cafabp-14,
    -0x1.c79d20p17
  },
  { // Entry 170
    0x1.2da1d3007a57461f6f67f2d3e983f798p-1,
    0x1.ca7ce0p24
  },
  { // Entry 171
    0x1.2da1d3007a57461f6f67f2d3e983f798p-1,
    -0x1.ca7ce0p24
  },
  { // Entry 172
    0x1.ffdd37888387ce3c9828144676f2ab0dp-1,
    0x1.cc31b8p18
  },
  { // Entry 173
    0x1.ffdd37888387ce3c9828144676f2ab0dp-1,
    -0x1.cc31b8p18
  },
  { // Entry 174
    0x1.395ba4ffffa061223f7304299be0aad8p-1,
    0x1.d30892p-1
  },
  { // Entry 175
    0x1.395ba4ffffa061223f7304299be0aad8p-1,
    -0x1.d30892p-1
  },
  { // Entry 176
    0x1.cb27c6ffd8e9d51a0605b57fd02ee483p-1,
    0x1.d5574cp-2
  },
  { // Entry 177
    0x1.cb27c6ffd8e9d51a0605b57fd02ee483p-1,
    -0x1.d5574cp-2
  },
  { // Entry 178
    0x1.a0a09cfd2b2b23476f09aa3eb631351cp-5,
    0x1.d7557ap12
  },
  { // Entry 179
    0x1.a0a09cfd2b2b23476f09aa3eb631351cp-5,
    -0x1.d7557ap12
  },
  { // Entry 180
    0x1.38ae6d000c49df5001baf701b1a2a564p-1,
    0x1.dbe75cp24
  },
  { // Entry 181
    0x1.38ae6d000c49df5001baf701b1a2a564p-1,
    -0x1.dbe75cp24
  },
  { // Entry 182
    0x1.ffff1f00125abf3d1765781b64e6fe07p-1,
    0x1.dffffep-9
  },
  { // Entry 183
    0x1.ffff1f00125abf3d1765781b64e6fe07p-1,
    -0x1.dffffep-9
  },
  { // Entry 184
    -0x1.9abc76f7eb1d15a727e0be7ab16400a7p-1,
    0x1.e02a42p108
  },
  { // Entry 185
    -0x1.9abc76f7eb1d15a727e0be7ab16400a7p-1,
    -0x1.e02a42p108
  },
  { // Entry 186
    0x1.5a1429044eb087032dbee719cdd30226p-1,
    0x1.e701eap100
  },
  { // Entry 187
    0x1.5a1429044eb087032dbee719cdd30226p-1,
    -0x1.e701eap100
  },
  { // Entry 188
    -0x1.94ffc0f8d888f6f46c6d55a2efa1083fp-1,
    0x1.edf188p24
  },
  { // Entry 189
    -0x1.94ffc0f8d888f6f46c6d55a2efa1083fp-1,
    -0x1.edf188p24
  },
  { // Entry 190
    -0x1.27c6d300d8756e78846b84a1fa3b12a2p-1,
    0x1.f4c63ap24
  },
  { // Entry 191
    -0x1.27c6d300d8756e78846b84a1fa3b12a2p-1,
    -0x1.f4c63ap24
  },
  { // Entry 192
    0x1.da54ecefb1cd39510555126a76cb20d4p-7,
    0x1.f5ba76p2
  },
  { // Entry 193
    0x1.da54ecefb1cd39510555126a76cb20d4p-7,
    -0x1.f5ba76p2
  },
  { // Entry 194
    0x1.fc28da000006bc4f0b0cd3c8ab10fc57p-1,
    0x1.f5ff4ep-4
  },
  { // Entry 195
    0x1.fc28da000006bc4f0b0cd3c8ab10fc57p-1,
    -0x1.f5ff4ep-4
  },
  { // Entry 196
    -0x1.ffffffffffea396ab8aee509392c755dp-1,
    0x1.f6a7a2p3
  },
  { // Entry 197
    -0x1.ffffffffffea396ab8aee509392c755dp-1,
    -0x1.f6a7a2p3
  },
  { // Entry 198
    0x1.a4f1d4fd0ea286f32f3cb3092b4ced14p-5,
    0x1.f6bff2p12
  },
  { // Entry 199
    0x1.a4f1d4fd0ea286f32f3cb3092b4ced14p-5,
    -0x1.f6bff2p12
  },
  { // Entry 200
    -0x1.fffffffffffffaf33de290ca99e2faf3p-1,
    0x1.f9cbe2p8
  },
  { // Entry 201
    -0x1.fffffffffffffaf33de290ca99e2faf3p-1,
    -0x1.f9cbe2p8
  },
  { // Entry 202
    0x1.fdd40d6d912ce2594f200104570ac1b3p-3,
    0x1.fc767ep12
  },
  { // Entry 203
    0x1.fdd40d6d912ce2594f200104570ac1b3p-3,
    -0x1.fc767ep12
  },
  { // Entry 204
    -0x1.752de2ffffb1a5e227bf2c12f4083203p-1,
    0x1.ff5352p8
  },
  { // Entry 205
    -0x1.752de2ffffb1a5e227bf2c12f4083203p-1,
    -0x1.ff5352p8
  },
  { // Entry 206
    -0x1.4ed4c5ffc8018741870949767ff8dafap-1,
    0x1.fff1fep1
  },
  { // Entry 207
    -0x1.4ed4c5ffc8018741870949767ff8dafap-1,
    -0x1.fff1fep1
  },
  { // Entry 208
    -0x1.28406a0025545c9a568dacd45518dd65p-3,
    0x1.fff1fep2
  },
  { // Entry 209
    -0x1.28406a0025545c9a568dacd45518dd65p-3,
    -0x1.fff1fep2
  },
  { // Entry 210
    0x1.f015c8c24ca5e99c7c65599c8d60976ep-1,
    0x1.fff7fep-3
  },
  { // Entry 211
    0x1.f015c8c24ca5e99c7c65599c8d60976ep-1,
    -0x1.fff7fep-3
  },
  { // Entry 212
    0x1.aff9b45e94d32d8e5bde25dec6f357d6p-9,
    0x1.fffe3ep41
  },
  { // Entry 213
    0x1.aff9b45e94d32d8e5bde25dec6f357d6p-9,
    -0x1.fffe3ep41
  },
  { // Entry 214
    -0x1.ea5464fff571f6ff335004eade301b56p-1,
    0x1.ffff8ep3
  },
  { // Entry 215
    -0x1.ea5464fff571f6ff335004eade301b56p-1,
    -0x1.ffff8ep3
  },
  { // Entry 216
    0x1.fffd4e735df6db6a7ca7cb0436e6ef48p-1,
    0x1.ffff8ep40
  },
  { // Entry 217
    0x1.fffd4e735df6db6a7ca7cb0436e6ef48p-1,
    -0x1.ffff8ep40
  },
  { // Entry 218
    -0x1.88e527ffedd85d2e2429166f795d9788p-7,
    0x1.ffff9ep45
  },
  { // Entry 219
    -0x1.88e527ffedd85d2e2429166f795d9788p-7,
    -0x1.ffff9ep45
  },
  { // Entry 220
    -0x1.db8fa0e071f98061f27ef67161511437p-3,
    0x1.ffffbap23
  },
  { // Entry 221
    -0x1.db8fa0e071f98061f27ef67161511437p-3,
    -0x1.ffffbap23
  },
  { // Entry 222
    -0x1.fe5b337f4cfe25d468defe65d5c524adp-1,
    0x1.ffffdcp8
  },
  { // Entry 223
    -0x1.fe5b337f4cfe25d468defe65d5c524adp-1,
    -0x1.ffffdcp8
  },
  { // Entry 224
    -0x1.f59038f4c2dd33d159171ee80bb64886p-5,
    0x1.fffff8p118
  },
  { // Entry 225
    -0x1.f59038f4c2dd33d159171ee80bb64886p-5,
    -0x1.fffff8p118
  },
  { // Entry 226
    0x1.fffffc00001155553a7d27f4a289f319p-1,
    0x1.fffffcp-12
  },
  { // Entry 227
    0x1.fffffc00001155553a7d27f4a289f319p-1,
    -0x1.fffffcp-12
  },
  { // Entry 228
    -0x1.f9d6bdd62473cd2b729fe3a67a4e9157p-4,
    0x1.fffffcp22
  },
  { // Entry 229
    -0x1.f9d6bdd62473cd2b729fe3a67a4e9157p-4,
    -0x1.fffffcp22
  },
  { // Entry 230
    0x1.eb408300005d91b9814cada88f5fc596p-1,
    0x1.24836cp-2
  },
  { // Entry 231
    0x1.eb408300005d91b9814cada88f5fc596p-1,
    -0x1.24836cp-2
  },
  { // Entry 232
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 233
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 234
    0x1.p0,
    0.0
  },
  { // Entry 235
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 236
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 237
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.000002p-126
  },
  { // Entry 238
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.000002p-126
  },
  { // Entry 239
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-126
  },
  { // Entry 240
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-126
  },
  { // Entry 241
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffcp-127
  },
  { // Entry 242
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffcp-127
  },
  { // Entry 243
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffcp-127
  },
  { // Entry 244
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffcp-127
  },
  { // Entry 245
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-126
  },
  { // Entry 246
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-126
  },
  { // Entry 247
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.000002p-126
  },
  { // Entry 248
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.000002p-126
  },
  { // Entry 249
    0x1.ffffff5c28f57960cd56ebfe9482a61fp-1,
    0x1.99999ap-13
  },
  { // Entry 250
    0x1.ffffff5c28f57960cd56ebfe9482a61fp-1,
    -0x1.99999ap-13
  },
  { // Entry 251
    0x1.fffffd70a3d64e5ec165cd4307ad1326p-1,
    0x1.99999ap-12
  },
  { // Entry 252
    0x1.fffffd70a3d64e5ec165cd4307ad1326p-1,
    -0x1.99999ap-12
  },
  { // Entry 253
    0x1.fffffa3d709eecbfb5a385b0f3e0cb8fp-1,
    0x1.333334p-11
  },
  { // Entry 254
    0x1.fffffa3d709eecbfb5a385b0f3e0cb8fp-1,
    -0x1.333334p-11
  },
  { // Entry 255
    0x1.fffff5c28f5fc733c4202aa0bda92f97p-1,
    0x1.99999ap-11
  },
  { // Entry 256
    0x1.fffff5c28f5fc733c4202aa0bda92f97p-1,
    -0x1.99999ap-11
  },
  { // Entry 257
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    0x1.p-10
  },
  { // Entry 258
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    -0x1.p-10
  },
  { // Entry 259
    0x1.ffffe8f5c29ce07640bd5f6d8bb1ea6bp-1,
    0x1.333334p-10
  },
  { // Entry 260
    0x1.ffffe8f5c29ce07640bd5f6d8bb1ea6bp-1,
    -0x1.333334p-10
  },
  { // Entry 261
    0x1.ffffe0a3d714839f3601147ada73f8d9p-1,
    0x1.666668p-10
  },
  { // Entry 262
    0x1.ffffe0a3d714839f3601147ada73f8d9p-1,
    -0x1.666668p-10
  },
  { // Entry 263
    0x1.ffffd70a3d8191f66de5408fb2b995a0p-1,
    0x1.99999cp-10
  },
  { // Entry 264
    0x1.ffffd70a3d8191f66de5408fb2b995a0p-1,
    -0x1.99999cp-10
  },
  { // Entry 265
    0x1.ffffcc28f6d096b87d6d19a06e96999bp-1,
    0x1.ccccccp-10
  },
  { // Entry 266
    0x1.ffffcc28f6d096b87d6d19a06e96999bp-1,
    -0x1.ccccccp-10
  },
  { // Entry 267
    0x1.fffbcc2a71ceaabf5582b6da1fc30531p-1,
    0x1.066666p-7
  },
  { // Entry 268
    0x1.fffbcc2a71ceaabf5582b6da1fc30531p-1,
    -0x1.066666p-7
  },
  { // Entry 269
    0x1.fff30a4b7b5119d8e299f717ec0ece16p-1,
    0x1.ccccccp-7
  },
  { // Entry 270
    0x1.fff30a4b7b5119d8e299f717ec0ece16p-1,
    -0x1.ccccccp-7
  },
  { // Entry 271
    0x1.ffe57a785123226c1e2efb411353edc9p-1,
    0x1.499998p-6
  },
  { // Entry 272
    0x1.ffe57a785123226c1e2efb411353edc9p-1,
    -0x1.499998p-6
  },
  { // Entry 273
    0x1.ffd31cd10cb632d9733ac5f5f327a5f9p-1,
    0x1.acccccp-6
  },
  { // Entry 274
    0x1.ffd31cd10cb632d9733ac5f5f327a5f9p-1,
    -0x1.acccccp-6
  },
  { // Entry 275
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    0x1.08p-5
  },
  { // Entry 276
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    -0x1.08p-5
  },
  { // Entry 277
    0x1.ff9ff8c2eaeaee30fb211765af835171p-1,
    0x1.39999ap-5
  },
  { // Entry 278
    0x1.ff9ff8c2eaeaee30fb211765af835171p-1,
    -0x1.39999ap-5
  },
  { // Entry 279
    0x1.ff7f32d6eb1f9cf90226ec291c9e0922p-1,
    0x1.6b3334p-5
  },
  { // Entry 280
    0x1.ff7f32d6eb1f9cf90226ec291c9e0922p-1,
    -0x1.6b3334p-5
  },
  { // Entry 281
    0x1.ff59a00cc4ad492ca2597495412998edp-1,
    0x1.9ccccep-5
  },
  { // Entry 282
    0x1.ff59a00cc4ad492ca2597495412998edp-1,
    -0x1.9ccccep-5
  },
  { // Entry 283
    0x1.ff2f40c08acf4580a8d13380d9073398p-1,
    0x1.ce6666p-5
  },
  { // Entry 284
    0x1.ff2f40c08acf4580a8d13380d9073398p-1,
    -0x1.ce6666p-5
  },
  { // Entry 285
    0x1.8ca46ca011771bfae0d9edbf1dacb402p-1,
    0x1.5e7fc4p-1
  },
  { // Entry 286
    0x1.8ca46ca011771bfae0d9edbf1dacb402p-1,
    -0x1.5e7fc4p-1
  },
  { // Entry 287
    0x1.0b5d38d5d82e4a7624dac4e10ce159c2p-2,
    0x1.4e7fc4p0
  },
  { // Entry 288
    0x1.0b5d38d5d82e4a7624dac4e10ce159c2p-2,
    -0x1.4e7fc4p0
  },
  { // Entry 289
    -0x1.66b96e204e69cda8e9cf50996432539ep-2,
    0x1.edbfa6p0
  },
  { // Entry 290
    -0x1.66b96e204e69cda8e9cf50996432539ep-2,
    -0x1.edbfa6p0
  },
  { // Entry 291
    -0x1.a935540edeca4c220ed91dc5481e4d9bp-1,
    0x1.467fc4p1
  },
  { // Entry 292
    -0x1.a935540edeca4c220ed91dc5481e4d9bp-1,
    -0x1.467fc4p1
  },
  { // Entry 293
    -0x1.ffc0017dd9209dd8891f17fe4c9eee46p-1,
    0x1.961fb4p1
  },
  { // Entry 294
    -0x1.ffc0017dd9209dd8891f17fe4c9eee46p-1,
    -0x1.961fb4p1
  },
  { // Entry 295
    -0x1.969082007733d787f4c36ba0f9425694p-1,
    0x1.e5bfa4p1
  },
  { // Entry 296
    -0x1.969082007733d787f4c36ba0f9425694p-1,
    -0x1.e5bfa4p1
  },
  { // Entry 297
    -0x1.2a1e74223d9bddb7db59f781f96b65ecp-2,
    0x1.1aafcap2
  },
  { // Entry 298
    -0x1.2a1e74223d9bddb7db59f781f96b65ecp-2,
    -0x1.1aafcap2
  },
  { // Entry 299
    0x1.4894d50b84dbc981134a591ac4165d9ep-2,
    0x1.427fc2p2
  },
  { // Entry 300
    0x1.4894d50b84dbc981134a591ac4165d9ep-2,
    -0x1.427fc2p2
  },
  { // Entry 301
    0x1.a016dd7480a1eea4d49efb585fa49c86p-1,
    0x1.6a4fbap2
  },
  { // Entry 302
    0x1.a016dd7480a1eea4d49efb585fa49c86p-1,
    -0x1.6a4fbap2
  },
  { // Entry 303
    0x1.a30a6a3bf4a3e2b7e27666d3a9c3b74bp-1,
    0x1.6af2f0p2
  },
  { // Entry 304
    0x1.a30a6a3bf4a3e2b7e27666d3a9c3b74bp-1,
    -0x1.6af2f0p2
  },
  { // Entry 305
    0x1.5bd625504015ccc101e4f4340d4b762bp-2,
    0x1.43c62ap2
  },
  { // Entry 306
    0x1.5bd625504015ccc101e4f4340d4b762bp-2,
    -0x1.43c62ap2
  },
  { // Entry 307
    -0x1.0cb733448c30ee3ddffb4da69f0b3842p-2,
    0x1.1c9964p2
  },
  { // Entry 308
    -0x1.0cb733448c30ee3ddffb4da69f0b3842p-2,
    -0x1.1c9964p2
  },
  { // Entry 309
    -0x1.89d874ad30e3fb46244daa24451690d7p-1,
    0x1.ead93cp1
  },
  { // Entry 310
    -0x1.89d874ad30e3fb46244daa24451690d7p-1,
    -0x1.ead93cp1
  },
  { // Entry 311
    -0x1.fe51ae09f0d39ed554e68bef3e2f8a03p-1,
    0x1.9c7fb0p1
  },
  { // Entry 312
    -0x1.fe51ae09f0d39ed554e68bef3e2f8a03p-1,
    -0x1.9c7fb0p1
  },
  { // Entry 313
    -0x1.b97bf76ae765eb69cf55e80aae977303p-1,
    0x1.4e2624p1
  },
  { // Entry 314
    -0x1.b97bf76ae765eb69cf55e80aae977303p-1,
    -0x1.4e2624p1
  },
  { // Entry 315
    -0x1.a8ac5793e32629b131984ecffd2d0f31p-2,
    0x1.ff9932p0
  },
  { // Entry 316
    -0x1.a8ac5793e32629b131984ecffd2d0f31p-2,
    -0x1.ff9932p0
  },
  { // Entry 317
    0x1.77a92ca01bc79c195dda33736807f986p-3,
    0x1.62e61cp0
  },
  { // Entry 318
    0x1.77a92ca01bc79c195dda33736807f986p-3,
    -0x1.62e61cp0
  },
  { // Entry 319
    0x1.6e1060282c1488d9abd83da1d68cd0f7p-1,
    0x1.8c662cp-1
  },
  { // Entry 320
    0x1.6e1060282c1488d9abd83da1d68cd0f7p-1,
    -0x1.8c662cp-1
  },
  { // Entry 321
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    -0x1.a8aa1cp0
  },
  { // Entry 322
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    0x1.a8aa1cp0
  },
  { // Entry 323
    -0x1.e665cb2af842be5ba5f65960599a97ecp-7,
    -0x1.95ec8ap0
  },
  { // Entry 324
    -0x1.e665cb2af842be5ba5f65960599a97ecp-7,
    0x1.95ec8ap0
  },
  { // Entry 325
    0x1.ddd231501b12fcf2bc20633be4d51e51p-5,
    -0x1.832ef8p0
  },
  { // Entry 326
    0x1.ddd231501b12fcf2bc20633be4d51e51p-5,
    0x1.832ef8p0
  },
  { // Entry 327
    0x1.0caba6997691ab1970d43c7419ed51e1p-3,
    -0x1.707166p0
  },
  { // Entry 328
    0x1.0caba6997691ab1970d43c7419ed51e1p-3,
    0x1.707166p0
  },
  { // Entry 329
    0x1.a072541fd6eaf8b65a874c58d6cc5739p-3,
    -0x1.5db3d4p0
  },
  { // Entry 330
    0x1.a072541fd6eaf8b65a874c58d6cc5739p-3,
    0x1.5db3d4p0
  },
  { // Entry 331
    0x1.18fef8106bea63b9e96a7adf538c6194p-2,
    -0x1.4af642p0
  },
  { // Entry 332
    0x1.18fef8106bea63b9e96a7adf538c6194p-2,
    0x1.4af642p0
  },
  { // Entry 333
    0x1.60437277d48067e85230bce1883eaabap-2,
    -0x1.3838b0p0
  },
  { // Entry 334
    0x1.60437277d48067e85230bce1883eaabap-2,
    0x1.3838b0p0
  },
  { // Entry 335
    0x1.a5a4ded492bedfe8cf5c34cadd78df75p-2,
    -0x1.257b1ep0
  },
  { // Entry 336
    0x1.a5a4ded492bedfe8cf5c34cadd78df75p-2,
    0x1.257b1ep0
  },
  { // Entry 337
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    -0x1.12bd92p0
  },
  { // Entry 338
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    0x1.12bd92p0
  },
  { // Entry 339
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    -0x1.ea5c3ep-1
  },
  { // Entry 340
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    0x1.ea5c3ep-1
  },
  { // Entry 341
    0x1.3805a2dafda7f8554aec65dab348a714p-1,
    -0x1.d4b87cp-1
  },
  { // Entry 342
    0x1.3805a2dafda7f8554aec65dab348a714p-1,
    0x1.d4b87cp-1
  },
  { // Entry 343
    0x1.48e52ff5bbe794618b85190b86411824p-1,
    -0x1.bf14bap-1
  },
  { // Entry 344
    0x1.48e52ff5bbe794618b85190b86411824p-1,
    0x1.bf14bap-1
  },
  { // Entry 345
    0x1.592e5b615ef5ae463976d31141dbacf0p-1,
    -0x1.a970f8p-1
  },
  { // Entry 346
    0x1.592e5b615ef5ae463976d31141dbacf0p-1,
    0x1.a970f8p-1
  },
  { // Entry 347
    0x1.68d9b2d657e4307d331eb7bd35ee1879p-1,
    -0x1.93cd36p-1
  },
  { // Entry 348
    0x1.68d9b2d657e4307d331eb7bd35ee1879p-1,
    0x1.93cd36p-1
  },
  { // Entry 349
    0x1.77e00c3718528c36f722e63096c2646bp-1,
    -0x1.7e2974p-1
  },
  { // Entry 350
    0x1.77e00c3718528c36f722e63096c2646bp-1,
    0x1.7e2974p-1
  },
  { // Entry 351
    0x1.863a88d6b064f36f34370722d361ce9fp-1,
    -0x1.6885b2p-1
  },
  { // Entry 352
    0x1.863a88d6b064f36f34370722d361ce9fp-1,
    0x1.6885b2p-1
  },
  { // Entry 353
    0x1.93e2989cee6084e34b533b1eb92746dap-1,
    -0x1.52e1f0p-1
  },
  { // Entry 354
    0x1.93e2989cee6084e34b533b1eb92746dap-1,
    0x1.52e1f0p-1
  },
  { // Entry 355
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    -0x1.3d3e36p-1
  },
  { // Entry 356
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    0x1.3d3e36p-1
  },
  { // Entry 357
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    -0x1.0a0b02p-1
  },
  { // Entry 358
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    0x1.0a0b02p-1
  },
  { // Entry 359
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    -0x1.d8f720p-2
  },
  { // Entry 360
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    0x1.d8f720p-2
  },
  { // Entry 361
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    -0x1.9dd83cp-2
  },
  { // Entry 362
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    0x1.9dd83cp-2
  },
  { // Entry 363
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    -0x1.62b958p-2
  },
  { // Entry 364
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    0x1.62b958p-2
  },
  { // Entry 365
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    -0x1.279a74p-2
  },
  { // Entry 366
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    0x1.279a74p-2
  },
  { // Entry 367
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    -0x1.d8f720p-3
  },
  { // Entry 368
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    0x1.d8f720p-3
  },
  { // Entry 369
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    -0x1.62b958p-3
  },
  { // Entry 370
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    0x1.62b958p-3
  },
  { // Entry 371
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    -0x1.d8f720p-4
  },
  { // Entry 372
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    0x1.d8f720p-4
  },
  { // Entry 373
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    -0x1.d8f720p-5
  },
  { // Entry 374
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    0x1.d8f720p-5
  },
  { // Entry 375
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    0x1.d8f720p-5
  },
  { // Entry 376
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    -0x1.d8f720p-5
  },
  { // Entry 377
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    0x1.d8f720p-4
  },

"""


```
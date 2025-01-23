Response:
The user wants to understand the functionality of the provided C source code file. This file seems to contain test data for the `tanh` function, specifically for Intel architecture within the Android bionic library.

Here's a breakdown of the thinking process to answer the user's request for a summary of the file's functionality:

1. **Identify the core purpose of the file:** The filename `tanh_intel_data.handroid` and the comment mentioning "test data" strongly suggest this file holds data used for testing the `tanh` function. The "intel" part indicates this data might be specific to how `tanh` is implemented or behaves on Intel processors within Android.

2. **Understand the data structure:** The code defines a `static data_1_1_t<double, double> g_tanh_intel_data[]`. This signifies an array named `g_tanh_intel_data`. Each element in this array is of type `data_1_1_t`, which appears to be a template taking two `double` arguments. Looking at the entries, each element is a pair of double-precision floating-point numbers.

3. **Infer the meaning of the data pairs:** Given the context of `tanh`, the most likely interpretation is that the first `double` in each pair represents an input value to the `tanh` function, and the second `double` represents the expected output for that input.

4. **Recognize the testing aspect:**  The presence of input-output pairs points to a testing methodology. This data is likely used to verify the correctness and accuracy of the `tanh` implementation on Android/Intel.

5. **Connect to Android:** Since the file is located within the `bionic/tests` directory, it's directly related to testing the core C library of Android. The `tanh` function is a standard mathematical function provided by `libc` (the C library).

6. **Synthesize a concise summary:** Based on the above points, a concise summary should highlight the following:
    * The file contains test data.
    * The data is for the `tanh` function.
    * The data is specific to Intel architecture on Android.
    * The data consists of input-output pairs for testing.

7. **Formulate the summary in Chinese:**  Translate the key findings into natural-sounding Chinese.

Therefore, the thought process leads to the following summary: 该文件是 Android Bionic 库中 `tanh` 函数的测试数据文件，专门用于 Intel 架构的 Android 设备。它包含了一系列的双精度浮点数对，每一对数据代表了 `tanh` 函数的一个测试用例，其中第一个数值是 `tanh` 函数的输入，第二个数值是对应的预期输出。这些数据用于验证 `tanh` 函数在 Android Intel 平台上的实现是否正确。
好的，这是第1部分的分析和归纳：

**功能归纳:**

该文件 `tanh_intel_data.handroid` 是 Android Bionic 库中用于测试 `tanh` (双曲正切) 数学函数的测试数据文件。它专门针对 Intel 架构的 Android 设备。

**具体来说，该文件的主要功能是:**

* **存储测试用例:**  文件中定义了一个名为 `g_tanh_intel_data` 的静态数组，该数组的元素是 `data_1_1_t<double, double>` 类型。这表明它存储了一系列用于测试 `tanh` 函数的输入和预期输出的配对数据。
* **提供 `tanh` 函数的基准数据:**  每一对数据 `{输入值, 预期输出值}`  构成了 `tanh` 函数的一个测试用例。这些数据用于验证 `tanh` 函数在特定输入下的计算结果是否与预期一致。
* **针对 Intel 架构:** 文件名中的 "intel" 表明这些测试数据可能是在 Intel 架构的处理器上生成或验证的，可能考虑到了该架构上的特定浮点数运算特性或精度要求。

**与 Android 功能的关系举例说明:**

该文件直接关联到 Android 底层库的正确性和可靠性。

* **libc 数学库测试:** `tanh` 函数是 C 标准库 `<math.h>` 中定义的函数，Android 的 Bionic 库提供了该函数的实现。这个数据文件用于确保 Bionic 库提供的 `tanh` 函数在 Intel 架构上能够正确计算。
* **NDK 开发支持:**  使用 Android NDK (Native Development Kit) 进行原生开发的开发者可能会调用 `tanh` 函数。这个测试数据文件间接地保证了 NDK 提供的数学函数在 Intel 设备上的正确性，从而避免开发者遇到因底层库错误导致的计算问题。
* **Framework 依赖:** Android Framework 的某些部分在底层也可能依赖于 `libc` 提供的数学函数。确保这些基础函数的正确性对于 Framework 的稳定运行至关重要。例如，一些图形渲染或传感器数据处理的模块可能会用到 `tanh` 或其他数学函数。

**总结:**

总而言之，`tanh_intel_data.handroid` 文件是 Android Bionic 库中一个关键的测试数据文件，它通过提供一系列预先计算好的输入输出对，用于验证和确保在 Intel 架构的 Android 设备上 `tanh` 函数的实现是准确可靠的。 这对于保证 Android 系统的稳定性和为开发者提供正确的数学运算能力至关重要。

### 提示词
```
这是目录为bionic/tests/math_data/tanh_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
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

static data_1_1_t<double, double> g_tanh_intel_data[] = {
  { // Entry 0
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p40
  },
  { // Entry 1
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p40
  },
  { // Entry 2
    -0x1.fff5559997e1091212284e477e6b601bp-7,
    -0x1.000000000000cp-6
  },
  { // Entry 3
    0x1.fff5559997e1091212284e477e6b601bp-7,
    0x1.000000000000cp-6
  },
  { // Entry 4
    -0x1.fffffffffff4e7ff9444b603d6dd765cp-1,
    -0x1.02020p4
  },
  { // Entry 5
    0x1.fffffffffff4e7ff9444b603d6dd765cp-1,
    0x1.02020p4
  },
  { // Entry 6
    -0x1.fbae8ebca20d4c5880046e52256af91ep-3,
    -0x1.033db279cac50p-2
  },
  { // Entry 7
    0x1.fbae8ebca20d4c5880046e52256af91ep-3,
    0x1.033db279cac50p-2
  },
  { // Entry 8
    -0x1.ef865be1ef42880100008a5e4e4190c5p-1,
    -0x1.0741ea37759d0p1
  },
  { // Entry 9
    0x1.ef865be1ef42880100008a5e4e4190c5p-1,
    0x1.0741ea37759d0p1
  },
  { // Entry 10
    -0x1.fffffe4130884001624e28693fd77976p-1,
    -0x1.17701b3bf0502p3
  },
  { // Entry 11
    0x1.fffffe4130884001624e28693fd77976p-1,
    0x1.17701b3bf0502p3
  },
  { // Entry 12
    -0x1.bfe15277a8709fff7196fc7ed299cacfp-1,
    -0x1.5a6p0
  },
  { // Entry 13
    0x1.bfe15277a8709fff7196fc7ed299cacfp-1,
    0x1.5a6p0
  },
  { // Entry 14
    -0x1.4597c2c7089a5296d1b38cc8fc3b35b2p-1,
    -0x1.80aa4dee35c52p-1
  },
  { // Entry 15
    0x1.4597c2c7089a5296d1b38cc8fc3b35b2p-1,
    0x1.80aa4dee35c52p-1
  },
  { // Entry 16
    -0x1.8535183c81bec818a4482b6aa562704ap-4,
    -0x1.86629b25ad139p-4
  },
  { // Entry 17
    0x1.8535183c81bec818a4482b6aa562704ap-4,
    0x1.86629b25ad139p-4
  },
  { // Entry 18
    -0x1.49914b1c7a6a3040d7a1246b5c9a7223p-1,
    -0x1.8765183af0bf8p-1
  },
  { // Entry 19
    0x1.49914b1c7a6a3040d7a1246b5c9a7223p-1,
    0x1.8765183af0bf8p-1
  },
  { // Entry 20
    -0x1.9070fe4e6f41f7e2e1d3a8d017f0997ep-4,
    -0x1.91b97a94248cep-4
  },
  { // Entry 21
    0x1.9070fe4e6f41f7e2e1d3a8d017f0997ep-4,
    0x1.91b97a94248cep-4
  },
  { // Entry 22
    -0x1.53fca0a748a40b956f64ea48ae26ceb7p-1,
    -0x1.999999999999ap-1
  },
  { // Entry 23
    0x1.53fca0a748a40b956f64ea48ae26ceb7p-1,
    0x1.999999999999ap-1
  },
  { // Entry 24
    -0x1.afbec6429aad794d7f2a775b8759d621p-8,
    -0x1.afc05f9bb3e19p-8
  },
  { // Entry 25
    0x1.afbec6429aad794d7f2a775b8759d621p-8,
    0x1.afc05f9bb3e19p-8
  },
  { // Entry 26
    -0x1.ff142eecd1b15800cdeb0f526da78623p-1,
    -0x1.c0cffc79a8e7ap1
  },
  { // Entry 27
    0x1.ff142eecd1b15800cdeb0f526da78623p-1,
    0x1.c0cffc79a8e7ap1
  },
  { // Entry 28
    -0x1.69ee34427443cf9fe259a9bb2567fcc0p-1,
    -0x1.c30c0608de324p-1
  },
  { // Entry 29
    0x1.69ee34427443cf9fe259a9bb2567fcc0p-1,
    0x1.c30c0608de324p-1
  },
  { // Entry 30
    -0x1.78d4ef748dd52801170d542b2b0cb210p-1,
    -0x1.e225b5b8fe514p-1
  },
  { // Entry 31
    0x1.78d4ef748dd52801170d542b2b0cb210p-1,
    0x1.e225b5b8fe514p-1
  },
  { // Entry 32
    -0x1.ce716dc85f4f601568694f24eb23ca3cp-2,
    -0x1.f2652ecbdc0f1p-2
  },
  { // Entry 33
    0x1.ce716dc85f4f601568694f24eb23ca3cp-2,
    0x1.f2652ecbdc0f1p-2
  },
  { // Entry 34
    -0x1.d9353d750404d7fd4bd76174b9eb0c4ap-2,
    -0x1.ffffffff7ffffp-2
  },
  { // Entry 35
    0x1.d9353d750404d7fd4bd76174b9eb0c4ap-2,
    0x1.ffffffff7ffffp-2
  },
  { // Entry 36
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep6
  },
  { // Entry 37
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep6
  },
  { // Entry 38
    0x1.85efab514f3952c8d133af19e5e8cdd6p-1,
    0x1.0000000000001p0
  },
  { // Entry 39
    -0x1.85efab514f3952c8d133af19e5e8cdd6p-1,
    -0x1.0000000000001p0
  },
  { // Entry 40
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p40
  },
  { // Entry 41
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p40
  },
  { // Entry 42
    0x1.d9353d7568afe67b37fb989f559be834p-2,
    0x1.0000000000007p-1
  },
  { // Entry 43
    -0x1.d9353d7568afe67b37fb989f559be834p-2,
    -0x1.0000000000007p-1
  },
  { // Entry 44
    0x1.ffff5555999b9df5cab1d843ba27b16bp-9,
    0x1.0000000000011p-8
  },
  { // Entry 45
    -0x1.ffff5555999b9df5cab1d843ba27b16bp-9,
    -0x1.0000000000011p-8
  },
  { // Entry 46
    0x1.fff5559997e1e90412bd9e530b1bb1c8p-7,
    0x1.0000000000013p-6
  },
  { // Entry 47
    -0x1.fff5559997e1e90412bd9e530b1bb1c8p-7,
    -0x1.0000000000013p-6
  },
  { // Entry 48
    0x1.fd5992bc4b8938001f85b833d16495fap-4,
    0x1.0000000000030p-3
  },
  { // Entry 49
    -0x1.fd5992bc4b8938001f85b833d16495fap-4,
    -0x1.0000000000030p-3
  },
  { // Entry 50
    0x1.fff5559997f228001d929172a4eb85d4p-7,
    0x1.0000000000095p-6
  },
  { // Entry 51
    -0x1.fff5559997f228001d929172a4eb85d4p-7,
    -0x1.0000000000095p-6
  },
  { // Entry 52
    0x1.ed9505e1bc464849d749fc9de18202c2p-1,
    0x1.00000000002p1
  },
  { // Entry 53
    -0x1.ed9505e1bc464849d749fc9de18202c2p-1,
    -0x1.00000000002p1
  },
  { // Entry 54
    0x1.ff55997e035588295a0fea71abc3cb2ep-5,
    0x1.0000000000243p-4
  },
  { // Entry 55
    -0x1.ff55997e035588295a0fea71abc3cb2ep-5,
    -0x1.0000000000243p-4
  },
  { // Entry 56
    0x1.f597ea69a231a72e6af16bc1c1566108p-3,
    0x1.0000000000380p-2
  },
  { // Entry 57
    -0x1.f597ea69a231a72e6af16bc1c1566108p-3,
    -0x1.0000000000380p-2
  },
  { // Entry 58
    0x1.f597ea69a58af253fe597fddbebb43e2p-3,
    0x1.00000000020p-2
  },
  { // Entry 59
    -0x1.f597ea69a58af253fe597fddbebb43e2p-3,
    -0x1.00000000020p-2
  },
  { // Entry 60
    0x1.fffd55599de69fe673438a43e4e4e8f0p-8,
    0x1.00000000022a0p-7
  },
  { // Entry 61
    -0x1.fffd55599de69fe673438a43e4e4e8f0p-8,
    -0x1.00000000022a0p-7
  },
  { // Entry 62
    0x1.fffff872a91f87faf5806a50e5c4b91bp-1,
    0x1.0000000002ff0p3
  },
  { // Entry 63
    -0x1.fffff872a91f87faf5806a50e5c4b91bp-1,
    -0x1.0000000002ff0p3
  },
  { // Entry 64
    0x1.fffff872a91f87fb6e55d77442ed3d29p-1,
    0x1.00000000030p3
  },
  { // Entry 65
    -0x1.fffff872a91f87fb6e55d77442ed3d29p-1,
    -0x1.00000000030p3
  },
  { // Entry 66
    0x1.85efab5178d6d000016b608b6d73768fp-1,
    0x1.00000000318b9p0
  },
  { // Entry 67
    -0x1.85efab5178d6d000016b608b6d73768fp-1,
    -0x1.00000000318b9p0
  },
  { // Entry 68
    0x1.d9353d75bd3167fffe0ca38b641c896fp-2,
    0x1.0000000035ba6p-1
  },
  { // Entry 69
    -0x1.d9353d75bd3167fffe0ca38b641c896fp-2,
    -0x1.0000000035ba6p-1
  },
  { // Entry 70
    0x1.d9353d771617800000a9a580e469340ep-2,
    0x1.0000000111012p-1
  },
  { // Entry 71
    -0x1.d9353d771617800000a9a580e469340ep-2,
    -0x1.0000000111012p-1
  },
  { // Entry 72
    0x1.fd5992bf3fa307ce156b9614980779ecp-4,
    0x1.000000018p-3
  },
  { // Entry 73
    -0x1.fd5992bf3fa307ce156b9614980779ecp-4,
    -0x1.000000018p-3
  },
  { // Entry 74
    0x1.fff57197d7f21aad8cde741e0c0ad7fap-7,
    0x1.00000e0p-6
  },
  { // Entry 75
    -0x1.fff57197d7f21aad8cde741e0c0ad7fap-7,
    -0x1.00000e0p-6
  },
  { // Entry 76
    0x1.ff55b95e1854b7dec3a51ba27b39be8bp-5,
    0x1.00001p-4
  },
  { // Entry 77
    -0x1.ff55b95e1854b7dec3a51ba27b39be8bp-5,
    -0x1.00001p-4
  },
  { // Entry 78
    0x1.ff55ed7fe5192835b5778c9d03720c56p-5,
    0x1.00002a2b0p-4
  },
  { // Entry 79
    -0x1.ff55ed7fe5192835b5778c9d03720c56p-5,
    -0x1.00002a2b0p-4
  },
  { // Entry 80
    0x1.ffd9589953c32bc8da7c0ed0baa544b3p-6,
    0x1.00020p-5
  },
  { // Entry 81
    -0x1.ffd9589953c32bc8da7c0ed0baa544b3p-6,
    -0x1.00020p-5
  },
  { // Entry 82
    0x1.85fd1b1b96f55c651875290b2d7f494cp-1,
    0x1.001p0
  },
  { // Entry 83
    -0x1.85fd1b1b96f55c651875290b2d7f494cp-1,
    -0x1.001p0
  },
  { // Entry 84
    0x1.fdb8166cc3ed2817c1f59dbd8b23b2abp-4,
    0x1.003p-3
  },
  { // Entry 85
    -0x1.fdb8166cc3ed2817c1f59dbd8b23b2abp-4,
    -0x1.003p-3
  },
  { // Entry 86
    0x1.ffe8933bc5a6d7be8a7316e43ce9c6cdp-5,
    0x1.0049c689802d0p-4
  },
  { // Entry 87
    -0x1.ffe8933bc5a6d7be8a7316e43ce9c6cdp-5,
    -0x1.0049c689802d0p-4
  },
  { // Entry 88
    0x1.fa73af7a658375ff4348367f3830a567p-3,
    0x1.0295fad40a580p-2
  },
  { // Entry 89
    -0x1.fa73af7a658375ff4348367f3830a567p-3,
    -0x1.0295fad40a580p-2
  },
  { // Entry 90
    0x1.0624d77c51e6880001f9be17000b9cf1p-10,
    0x1.0624dd3655b8ap-10
  },
  { // Entry 91
    -0x1.0624d77c51e6880001f9be17000b9cf1p-10,
    -0x1.0624dd3655b8ap-10
  },
  { // Entry 92
    0x1.0624d79f9b19f7fffe0a9d21eca99d7cp-10,
    0x1.0624dd599eee6p-10
  },
  { // Entry 93
    -0x1.0624d79f9b19f7fffe0a9d21eca99d7cp-10,
    -0x1.0624dd599eee6p-10
  },
  { // Entry 94
    0x1.e429309abfffd2ddfd82de658136eba5p-2,
    0x1.07020e041c084p-1
  },
  { // Entry 95
    -0x1.e429309abfffd2ddfd82de658136eba5p-2,
    -0x1.07020e041c084p-1
  },
  { // Entry 96
    0x1.8c7f5c6b80f69a39323c4db93a0f72b0p-1,
    0x1.080p0
  },
  { // Entry 97
    -0x1.8c7f5c6b80f69a39323c4db93a0f72b0p-1,
    -0x1.080p0
  },
  { // Entry 98
    0x1.8d012ee7bd86f7ff002853771d7f8bf3p-1,
    0x1.08a278c042d05p0
  },
  { // Entry 99
    -0x1.8d012ee7bd86f7ff002853771d7f8bf3p-1,
    -0x1.08a278c042d05p0
  },
  { // Entry 100
    0x1.fffffe4130884001a9dd6277c63796bap-1,
    0x1.17701b3bf052bp3
  },
  { // Entry 101
    -0x1.fffffe4130884001a9dd6277c63796bap-1,
    -0x1.17701b3bf052bp3
  },
  { // Entry 102
    0x1.fdbcb70e1a79f7fae20bb105bc7b5a09p-2,
    0x1.17bd082f7494ap-1
  },
  { // Entry 103
    -0x1.fdbcb70e1a79f7fae20bb105bc7b5a09p-2,
    -0x1.17bd082f7494ap-1
  },
  { // Entry 104
    0x1.ff97efd9e06bae1b16cedbdb4a92304ep-2,
    0x1.18f94c43e4254p-1
  },
  { // Entry 105
    -0x1.ff97efd9e06bae1b16cedbdb4a92304ep-2,
    -0x1.18f94c43e4254p-1
  },
  { // Entry 106
    0x1.1abe341c3a920fff94d356d6f5ffbc8dp-7,
    0x1.1acp-7
  },
  { // Entry 107
    -0x1.1abe341c3a920fff94d356d6f5ffbc8dp-7,
    -0x1.1acp-7
  },
  { // Entry 108
    0x1.02e1e2b14b97c6a35cbdc397873184d2p-1,
    0x1.1d1a3a347468fp-1
  },
  { // Entry 109
    -0x1.02e1e2b14b97c6a35cbdc397873184d2p-1,
    -0x1.1d1a3a347468fp-1
  },
  { // Entry 110
    0x1.9d8d4198958f6f11c41090ab7e3accb0p-1,
    0x1.1ed47ae8419b9p0
  },
  { // Entry 111
    -0x1.9d8d4198958f6f11c41090ab7e3accb0p-1,
    -0x1.1ed47ae8419b9p0
  },
  { // Entry 112
    0x1.182d330b3abd2a2e07d69cfdde7a8e36p-2,
    0x1.1f8p-2
  },
  { // Entry 113
    -0x1.182d330b3abd2a2e07d69cfdde7a8e36p-2,
    -0x1.1f8p-2
  },
  { // Entry 114
    0x1.ffe0482ef94fe800fb76431a7260ec18p-1,
    0x1.20a0ea0ea0f75p2
  },
  { // Entry 115
    -0x1.ffe0482ef94fe800fb76431a7260ec18p-1,
    -0x1.20a0ea0ea0f75p2
  },
  { // Entry 116
    0x1.268f1d822590680082a05be831e4854ap-6,
    0x1.26973dc7c5be6p-6
  },
  { // Entry 117
    -0x1.268f1d822590680082a05be831e4854ap-6,
    -0x1.26973dc7c5be6p-6
  },
  { // Entry 118
    0x1.218ab0574162d800d421fdb840145675p-2,
    0x1.29a69bd13ee87p-2
  },
  { // Entry 119
    -0x1.218ab0574162d800d421fdb840145675p-2,
    -0x1.29a69bd13ee87p-2
  },
  { // Entry 120
    0x1.2a4dda7de0017fffffbc7994f1ba04a0p-2,
    0x1.3333333389314p-2
  },
  { // Entry 121
    -0x1.2a4dda7de0017fffffbc7994f1ba04a0p-2,
    -0x1.3333333389314p-2
  },
  { // Entry 122
    0x1.3588dea53e3e48000186808c28c507e0p-3,
    0x1.37eca6a41e727p-3
  },
  { // Entry 123
    -0x1.3588dea53e3e48000186808c28c507e0p-3,
    -0x1.37eca6a41e727p-3
  },
  { // Entry 124
    0x1.adc58b27626030403b9dea1c7eee05c0p-1,
    0x1.3818fe847da14p0
  },
  { // Entry 125
    -0x1.adc58b27626030403b9dea1c7eee05c0p-1,
    -0x1.3818fe847da14p0
  },
  { // Entry 126
    0x1.39e670f864e06800916b322435b7bc9ap-6,
    0x1.39f046957a2f6p-6
  },
  { // Entry 127
    -0x1.39e670f864e06800916b322435b7bc9ap-6,
    -0x1.39f046957a2f6p-6
  },
  { // Entry 128
    0x1.afb03526b454afc4fd8fbb37ba979691p-1,
    0x1.3b6071d1f7484p0
  },
  { // Entry 129
    -0x1.afb03526b454afc4fd8fbb37ba979691p-1,
    -0x1.3b6071d1f7484p0
  },
  { // Entry 130
    0x1.fff71a538fb237ffaecdafac07098ecdp-1,
    0x1.494ee9ac8da60p2
  },
  { // Entry 131
    -0x1.fff71a538fb237ffaecdafac07098ecdp-1,
    -0x1.494ee9ac8da60p2
  },
  { // Entry 132
    0x1.b8af4dc2536ea800f3619a37dabd112ep-1,
    0x1.4bcc5e389c6a2p0
  },
  { // Entry 133
    -0x1.b8af4dc2536ea800f3619a37dabd112ep-1,
    -0x1.4bcc5e389c6a2p0
  },
  { // Entry 134
    0x1.bfe15277a8709fff7196fc7ed299cacfp-1,
    0x1.5a6p0
  },
  { // Entry 135
    -0x1.bfe15277a8709fff7196fc7ed299cacfp-1,
    -0x1.5a6p0
  },
  { // Entry 136
    0x1.31e258b9d59417ff0172bc482ad0836bp-1,
    0x1.60d71db63fc38p-1
  },
  { // Entry 137
    -0x1.31e258b9d59417ff0172bc482ad0836bp-1,
    -0x1.60d71db63fc38p-1
  },
  { // Entry 138
    0x1.62fd595702658ff6ef9857182535c62fp-6,
    0x1.630b92e7f0f77p-6
  },
  { // Entry 139
    -0x1.62fd595702658ff6ef9857182535c62fp-6,
    -0x1.630b92e7f0f77p-6
  },
  { // Entry 140
    0x1.33ea141cebb6430c668ffce962626636p-1,
    0x1.64024f4a3b070p-1
  },
  { // Entry 141
    -0x1.33ea141cebb6430c668ffce962626636p-1,
    -0x1.64024f4a3b070p-1
  },
  { // Entry 142
    0x1.64c8407c232917fafcc3fa7256f65979p-13,
    0x1.64c840b5e30aap-13
  },
  { // Entry 143
    -0x1.64c8407c232917fafcc3fa7256f65979p-13,
    -0x1.64c840b5e30aap-13
  },
  { // Entry 144
    0x1.35061c5e8c503500e45460954fc60ba0p-1,
    0x1.65c0300548991p-1
  },
  { // Entry 145
    -0x1.35061c5e8c503500e45460954fc60ba0p-1,
    -0x1.65c0300548991p-1
  },
  { // Entry 146
    0x1.fc659d3ccb3ad0f406e5741895bf529bp-1,
    0x1.695ab3124e6f3p1
  },
  { // Entry 147
    -0x1.fc659d3ccb3ad0f406e5741895bf529bp-1,
    -0x1.695ab3124e6f3p1
  },
  { // Entry 148
    0x1.698e7945aa772812eb8246c066fe12cep-4,
    0x1.6a8p-4
  },
  { // Entry 149
    -0x1.698e7945aa772812eb8246c066fe12cep-4,
    -0x1.6a8p-4
  },
  { // Entry 150
    0x1.c9a96d9b25e257fef42254a09c5a8e89p-1,
    0x1.70dc370dc370cp0
  },
  { // Entry 151
    -0x1.c9a96d9b25e257fef42254a09c5a8e89p-1,
    -0x1.70dc370dc370cp0
  },
  { // Entry 152
    0x1.729b0b53891cd8029a198f346aded3c6p-5,
    0x1.72dbd9697a31ap-5
  },
  { // Entry 153
    -0x1.729b0b53891cd8029a198f346aded3c6p-5,
    -0x1.72dbd9697a31ap-5
  },
  { // Entry 154
    0x1.42dfc90ce7990801849a792e4b568e22p-1,
    0x1.7c2055eedea83p-1
  },
  { // Entry 155
    -0x1.42dfc90ce7990801849a792e4b568e22p-1,
    -0x1.7c2055eedea83p-1
  },
  { // Entry 156
    0x1.445fe311097e8b509753e0bbd4d8de8ap-1,
    0x1.7eap-1
  },
  { // Entry 157
    -0x1.445fe311097e8b509753e0bbd4d8de8ap-1,
    -0x1.7eap-1
  },
  { // Entry 158
    0x1.7e9dcb8e6272f7ff7aebf989fc716171p-6,
    0x1.7eaf9b6ae4ee3p-6
  },
  { // Entry 159
    -0x1.7e9dcb8e6272f7ff7aebf989fc716171p-6,
    -0x1.7eaf9b6ae4ee3p-6
  },
  { // Entry 160
    0x1.459f0dcdb1b2522b5637d303656306dep-1,
    0x1.80b68cceb89c4p-1
  },
  { // Entry 161
    -0x1.459f0dcdb1b2522b5637d303656306dep-1,
    -0x1.80b68cceb89c4p-1
  },
  { // Entry 162
    0x1.45b3111d091a910621ec7f399ccdb8c2p-1,
    0x1.80d82924ec44dp-1
  },
  { // Entry 163
    -0x1.45b3111d091a910621ec7f399ccdb8c2p-1,
    -0x1.80d82924ec44dp-1
  },
  { // Entry 164
    0x1.49009c6556eed1e5e07615b5b4c368ecp-1,
    0x1.866e5ae84b0e8p-1
  },
  { // Entry 165
    -0x1.49009c6556eed1e5e07615b5b4c368ecp-1,
    -0x1.866e5ae84b0e8p-1
  },
  { // Entry 166
    0x1.49a2006d9598d0564979f87ef81c5b1cp-1,
    0x1.8781a092a0f52p-1
  },
  { // Entry 167
    -0x1.49a2006d9598d0564979f87ef81c5b1cp-1,
    -0x1.8781a092a0f52p-1
  },
  { // Entry 168
    0x1.862c8470e675a07e123ea879f8baebb3p-3,
    0x1.8b0p-3
  },
  { // Entry 169
    -0x1.862c8470e675a07e123ea879f8baebb3p-3,
    -0x1.8b0p-3
  },
  { // Entry 170
    0x1.8f77d5d8932c9ff9095e8f77fddd070dp-6,
    0x1.8f8c1b47ec114p-6
  },
  { // Entry 171
    -0x1.8f77d5d8932c9ff9095e8f77fddd070dp-6,
    -0x1.8f8c1b47ec114p-6
  },
  { // Entry 172
    0x1.830e23e04e0347fe78663f1c44eb84fbp-2,
    0x1.974p-2
  },
  { // Entry 173
    -0x1.830e23e04e0347fe78663f1c44eb84fbp-2,
    -0x1.974p-2
  },
  { // Entry 174
    0x1.536c6d4bc8352db7986656026697f1a9p-1,
    0x1.98980p-1
  },
  { // Entry 175
    -0x1.536c6d4bc8352db7986656026697f1a9p-1,
    -0x1.98980p-1
  },
  { // Entry 176
    0x1.53ca8372b3cf0800c109372ef0258556p-1,
    0x1.994p-1
  },
  { // Entry 177
    -0x1.53ca8372b3cf0800c109372ef0258556p-1,
    -0x1.994p-1
  },
  { // Entry 178
    0x1.94022794ca0f90111cd01b7fcb8cf9b6p-3,
    0x1.996p-3
  },
  { // Entry 179
    -0x1.94022794ca0f90111cd01b7fcb8cf9b6p-3,
    -0x1.996p-3
  },
  { // Entry 180
    0x1.9439830b85ad100001b86875e3435678p-3,
    0x1.99999999e7fb6p-3
  },
  { // Entry 181
    -0x1.9439830b85ad100001b86875e3435678p-3,
    -0x1.99999999e7fb6p-3
  },
  { // Entry 182
    0x1.8511573d83e2980001dfb476af7fd902p-2,
    0x1.9999999b34a5bp-2
  },
  { // Entry 183
    -0x1.8511573d83e2980001dfb476af7fd902p-2,
    -0x1.9999999b34a5bp-2
  },
  { // Entry 184
    0x1.9439830d887d0800010c022856ad8045p-3,
    0x1.9999999bffa9bp-3
  },
  { // Entry 185
    -0x1.9439830d887d0800010c022856ad8045p-3,
    -0x1.9999999bffa9bp-3
  },
  { // Entry 186
    0x1.983d7799ce1f6ffffe2004e393d95329p-4,
    0x1.9999999d7d8a2p-4
  },
  { // Entry 187
    -0x1.983d7799ce1f6ffffe2004e393d95329p-4,
    -0x1.9999999d7d8a2p-4
  },
  { // Entry 188
    0x1.983d779b6c85f7fffe2905fb22397b60p-4,
    0x1.9999999f20191p-4
  },
  { // Entry 189
    -0x1.983d779b6c85f7fffe2905fb22397b60p-4,
    -0x1.9999999f20191p-4
  },
  { // Entry 190
    0x1.dcba660c6fece80d4553119effdd5c2ep-1,
    0x1.aaaaaaaaaaaacp0
  },
  { // Entry 191
    -0x1.dcba660c6fece80d4553119effdd5c2ep-1,
    -0x1.aaaaaaaaaaaacp0
  },
  { // Entry 192
    0x1.ad59b59465b065170605cbf13988832ap-7,
    0x1.ad6p-7
  },
  { // Entry 193
    -0x1.ad59b59465b065170605cbf13988832ap-7,
    -0x1.ad6p-7
  },
  { // Entry 194
    0x1.6010ea0ed51797ff8b6ca7fede1b8d31p-1,
    0x1.afd7ebf5faf80p-1
  },
  { // Entry 195
    -0x1.6010ea0ed51797ff8b6ca7fede1b8d31p-1,
    -0x1.afd7ebf5faf80p-1
  },
  { // Entry 196
    0x1.9b46310eb4e6d7fcfcd6e280870e9b65p-2,
    0x1.b3cfa6c7643acp-2
  },
  { // Entry 197
    -0x1.9b46310eb4e6d7fcfcd6e280870e9b65p-2,
    -0x1.b3cfa6c7643acp-2
  },
  { // Entry 198
    0x1.630edae8786c8eac4ae4fc2ca2fa0dbep-1,
    0x1.b590150dcf8bfp-1
  },
  { // Entry 199
    -0x1.630edae8786c8eac4ae4fc2ca2fa0dbep-1,
    -0x1.b590150dcf8bfp-1
  },
  { // Entry 200
    0x1.657a4f7f260d4f26d7f76db01c856ac3p-1,
    0x1.ba4108b264c6ap-1
  },
  { // Entry 201
    -0x1.657a4f7f260d4f26d7f76db01c856ac3p-1,
    -0x1.ba4108b264c6ap-1
  },
  { // Entry 202
    0x1.ba73ec4f0359a005d109ed3d8245363fp-6,
    0x1.ba8f78449f0b8p-6
  },
  { // Entry 203
    -0x1.ba73ec4f0359a005d109ed3d8245363fp-6,
    -0x1.ba8f78449f0b8p-6
  },
  { // Entry 204
    0x1.b42aa86fc0c0afc4c48569cd92293a6fp-3,
    0x1.baf2501e20528p-3
  },
  { // Entry 205
    -0x1.b42aa86fc0c0afc4c48569cd92293a6fp-3,
    -0x1.baf2501e20528p-3
  },
  { // Entry 206
    0x1.e0eb93e911bfd7ffc1cbb555f083546ap-1,
    0x1.bb6766c1a2624p0
  },
  { // Entry 207
    -0x1.e0eb93e911bfd7ffc1cbb555f083546ap-1,
    -0x1.bb6766c1a2624p0
  },
  { // Entry 208
    0x1.bc9c90043f5afff80b989f92cea4b087p-6,
    0x1.bcb883bb4a1d2p-6
  },
  { // Entry 209
    -0x1.bc9c90043f5afff80b989f92cea4b087p-6,
    -0x1.bcb883bb4a1d2p-6
  },
  { // Entry 210
    0x1.66de0bef230e8802075b728fcffdea9ep-1,
    0x1.bcf9b5e552e46p-1
  },
  { // Entry 211
    -0x1.66de0bef230e8802075b728fcffdea9ep-1,
    -0x1.bcf9b5e552e46p-1
  },
  { // Entry 212
    0x1.c761f75b6966c8015bc19070f6ab5006p-6,
    0x1.c78p-6
  },
  { // Entry 213
    -0x1.c761f75b6966c8015bc19070f6ab5006p-6,
    -0x1.c78p-6
  },
  { // Entry 214
    0x1.71421350a064b0b3b168c6e13a942da1p-1,
    0x1.d20p-1
  },
  { // Entry 215
    -0x1.71421350a064b0b3b168c6e13a942da1p-1,
    -0x1.d20p-1
  },
  { // Entry 216
    0x1.ca9adc00daadf21de2f8e2a3b667acc3p-3,
    0x1.d2827155cd7f2p-3
  },
  { // Entry 217
    -0x1.ca9adc00daadf21de2f8e2a3b667acc3p-3,
    -0x1.d2827155cd7f2p-3
  },
  { // Entry 218
    0x1.d3af0b409493d80f16690d417a020954p-5,
    0x1.d4315fde0fd60p-5
  },
  { // Entry 219
    -0x1.d3af0b409493d80f16690d417a020954p-5,
    -0x1.d4315fde0fd60p-5
  },
  { // Entry 220
    0x1.ff53ef909a53c7ff46ae6492b249f914p-1,
    0x1.d50p1
  },
  { // Entry 221
    -0x1.ff53ef909a53c7ff46ae6492b249f914p-1,
    -0x1.d50p1
  },
  { // Entry 222
    0x1.d4c6dbdd6204b7fdaefa65c2de6c3bc1p-5,
    0x1.d54a1b43f2119p-5
  },
  { // Entry 223
    -0x1.d4c6dbdd6204b7fdaefa65c2de6c3bc1p-5,
    -0x1.d54a1b43f2119p-5
  },
  { // Entry 224
    0x1.d60c056eebcb57ea94de726e86f49ee6p-4,
    0x1.d82076d07e0cap-4
  },
  { // Entry 225
    -0x1.d60c056eebcb57ea94de726e86f49ee6p-4,
    -0x1.d82076d07e0cap-4
  },
  { // Entry 226
    0x1.745a81f5485b0dad83d3ad761f034d17p-1,
    0x1.d8829d48d5ccap-1
  },
  { // Entry 227
    -0x1.745a81f5485b0dad83d3ad761f034d17p-1,
    -0x1.d8829d48d5ccap-1
  },
  { // Entry 228
    0x1.dab77f34d301c900e13d05b912fca596p-7,
    0x1.dacp-7
  },
  { // Entry 229
    -0x1.dab77f34d301c900e13d05b912fca596p-7,
    -0x1.dacp-7
  },
  { // Entry 230
    0x1.d59fb2c4927767ffaf038b5b533e17b8p-3,
    0x1.de2p-3
  },
  { // Entry 231
    -0x1.d59fb2c4927767ffaf038b5b533e17b8p-3,
    -0x1.de2p-3
  },
  { // Entry 232
    0x1.bebc593435695f3e5d9dfdce8ac65911p-2,
    0x1.ded4e157ebb5ap-2
  },
  { // Entry 233
    -0x1.bebc593435695f3e5d9dfdce8ac65911p-2,
    -0x1.ded4e157ebb5ap-2
  },
  { // Entry 234
    0x1.d7665cf9bb8287f53cfd2d51f28dbc87p-3,
    0x1.ep-3
  },
  { // Entry 235
    -0x1.d7665cf9bb8287f53cfd2d51f28dbc87p-3,
    -0x1.ep-3
  },
  { // Entry 236
    0x1.e1839a63361cd36a2077ec3be46fb31cp-6,
    0x1.e1a71c88d42abp-6
  },
  { // Entry 237
    -0x1.e1839a63361cd36a2077ec3be46fb31cp-6,
    -0x1.e1a71c88d42abp-6
  },
  { // Entry 238
    0x1.e94414bfb8b1c926487a611c3e9c82fep-1,
    0x1.e48p0
  },
  { // Entry 239
    -0x1.e94414bfb8b1c926487a611c3e9c82fep-1,
    -0x1.e48p0
  },
  { // Entry 240
    0x1.e47ecb0b519ed4c405e6925c6189b4d5p-6,
    0x1.e4a2f72376d83p-6
  },
  { // Entry 241
    -0x1.e47ecb0b519ed4c405e6925c6189b4d5p-6,
    -0x1.e4a2f72376d83p-6
  },
  { // Entry 242
    0x1.e94fc93631c7e9191f4973a0d807d78ap-1,
    0x1.e4c377153ca9ap0
  },
  { // Entry 243
    -0x1.e94fc93631c7e9191f4973a0d807d78ap-1,
    -0x1.e4c377153ca9ap0
  },
  { // Entry 244
    0x1.c4cc03a3d0c237fdcf5623b5615bbe1dp-2,
    0x1.e6577536d43e7p-2
  },
  { // Entry 245
    -0x1.c4cc03a3d0c237fdcf5623b5615bbe1dp-2,
    -0x1.e6577536d43e7p-2
  },
  { // Entry 246
    0x1.c6214d5944547e0b684eaf0557117675p-2,
    0x1.e80p-2
  },
  { // Entry 247
    -0x1.c6214d5944547e0b684eaf0557117675p-2,
    -0x1.e80p-2
  },
  { // Entry 248
    0x1.7cd8fa892ecf17fe5da6a217f1e8d441p-1,
    0x1.eb05b226cd194p-1
  },
  { // Entry 249
    -0x1.7cd8fa892ecf17fe5da6a217f1e8d441p-1,
    -0x1.eb05b226cd194p-1
  },
  { // Entry 250
    0x1.fb638c376c8fa8010dbbb805d349366ep-6,
    0x1.fb8d188a84c37p-6
  },
  { // Entry 251
    -0x1.fb638c376c8fa8010dbbb805d349366ep-6,
    -0x1.fb8d188a84c37p-6
  },
  { // Entry 252
    0x1.ed02211fde846895e3a231ab4b15fc07p-1,
    0x1.fbfffffffffffp0
  },
  { // Entry 253
    -0x1.ed02211fde846895e3a231ab4b15fc07p-1,
    -0x1.fbfffffffffffp0
  },
  { // Entry 254
    0x1.85558570498f17fd9281ca9c45bffb5ep-1,
    0x1.fe91bd20c2fa7p-1
  },
  { // Entry 255
    -0x1.85558570498f17fd9281ca9c45bffb5ep-1,
    -0x1.fe91bd20c2fa7p-1
  },
  { // Entry 256
    0x1.ff8f55c580d0ad705f464b9e36c04624p-9,
    0x1.ff8ffffffffffp-9
  },
  { // Entry 257
    -0x1.ff8f55c580d0ad705f464b9e36c04624p-9,
    -0x1.ff8ffffffffffp-9
  },
  { // Entry 258
    0x1.ffcf558594f9980987b40863efca6716p-9,
    0x1.ffcffffffffffp-9
  },
  { // Entry 259
    -0x1.ffcf558594f9980987b40863efca6716p-9,
    -0x1.ffcffffffffffp-9
  },
  { // Entry 260
    0x1.ffb5619756262b83f716223082574b9bp-6,
    0x1.ffep-6
  },
  { // Entry 261
    -0x1.ffb5619756262b83f716223082574b9bp-6,
    -0x1.ffep-6
  },
  { // Entry 262
    0x1.ffe14573a7c18e0b1e2b616408b023d0p-9,
    0x1.ffe1effffffffp-9
  },
  { // Entry 263
    -0x1.ffe14573a7c18e0b1e2b616408b023d0p-9,
    -0x1.ffe1effffffffp-9
  },
  { // Entry 264
    0x1.ffed559996e8080e35db4ddd5c5067b7p-8,
    0x1.ffeffffffffffp-8
  },
  { // Entry 265
    -0x1.ffed559996e8080e35db4ddd5c5067b7p-8,
    -0x1.ffeffffffffffp-8
  },
  { // Entry 266
    0x1.fd595b1bf5ffd7fd760222476204a3c8p-4,
    0x1.ffffc77ffff47p-4
  },
  { // Entry 267
    -0x1.fd595b1bf5ffd7fd760222476204a3c8p-4,
    -0x1.ffffc77ffff47p-4
  },
  { // Entry 268
    0x1.85efa37cbe334800fffc63002c8c03eep-1,
    0x1.ffffed5aeedc7p-1
  },
  { // Entry 269
    -0x1.85efa37cbe334800fffc63002c8c03eep-1,
    -0x1.ffffed5aeedc7p-1
  },
  { // Entry 270
    0x1.85efa9d9032e6ebb257c9dc7befcea9cp-1,
    0x1.fffffc7ffffffp-1
  },
  { // Entry 271
    -0x1.85efa9d9032e6ebb257c9dc7befcea9cp-1,
    -0x1.fffffc7ffffffp-1
  },
  { // Entry 272
    0x1.f597ea2d3c6b112fb996697ab9d730f8p-3,
    0x1.ffffffbfbffffp-3
  },
  { // Entry 273
    -0x1.f597ea2d3c6b112fb996697ab9d730f8p-3,
    -0x1.ffffffbfbffffp-3
  },
  { // Entry 274
    0x1.f597ea3c82e148049b81276747b22a43p-3,
    0x1.ffffffcffffffp-3
  },
  { // Entry 275
    -0x1.f597ea3c82e148049b81276747b22a43p-3,
    -0x1.ffffffcffffffp-3
  },
  { // Entry 276
    0x1.d9353d750404d7fd4bd76174b9eb0c4ap-2,
    0x1.ffffffff7ffffp-2
  },
  { // Entry 277
    -0x1.d9353d750404d7fd4bd76174b9eb0c4ap-2,
    -0x1.ffffffff7ffffp-2
  },
  { // Entry 278
    0x1.85efab514f10ed5614c26425b952b2a6p-1,
    0x1.ffffffffff9ffp-1
  },
  { // Entry 279
    -0x1.85efab514f10ed5614c26425b952b2a6p-1,
    -0x1.ffffffffff9ffp-1
  },
  { // Entry 280
    0x1.ffd559992af86be17634ba8180eb56e3p-6,
    0x1.ffffffffffda8p-6
  },
  { // Entry 281
    -0x1.ffd559992af86be17634ba8180eb56e3p-6,
    -0x1.ffffffffffda8p-6
  },
  { // Entry 282
    0x1.ff55997e02f5d7f9739cb079aec68ef1p-5,
    0x1.ffffffffffe85p-5
  },
  { // Entry 283
    -0x1.ff55997e02f5d7f9739cb079aec68ef1p-5,
    -0x1.ffffffffffe85p-5
  },
  { // Entry 284
    0x1.85efab514f38edfd97f9312bc98e2889p-1,
    0x1.ffffffffffff3p-1
  },
  { // Entry 285
    -0x1.85efab514f38edfd97f9312bc98e2889p-1,
    -0x1.ffffffffffff3p-1
  },
  { // Entry 286
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep6
  },
  { // Entry 287
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep6
  },
  { // Entry 288
    0.0,
    0.0
  },
  { // Entry 289
    0x1.1a5eeff27cc84e29675f038f1aba6042p-5,
    0x1.1a7b9611a7b96p-5
  },
  { // Entry 290
    -0x1.1a5eeff27cc84e29675f038f1aba6042p-5,
    -0x1.1a7b9611a7b96p-5
  },
  { // Entry 291
    0x1.1a09275c594348d69d3aa6bc5a6d3eacp-4,
    0x1.1a7b9611a7b96p-4
  },
  { // Entry 292
    -0x1.1a09275c594348d69d3aa6bc5a6d3eacp-4,
    -0x1.1a7b9611a7b96p-4
  },
  { // Entry 293
    0x1.a63815915c3db32a3543202f310ededbp-4,
    0x1.a7b9611a7b961p-4
  },
  { // Entry 294
    -0x1.a63815915c3db32a3543202f310ededbp-4,
    -0x1.a7b9611a7b961p-4
  },
  { // Entry 295
    0x1.18b472e84eb8a189e113a261ae412556p-3,
    0x1.1a7b9611a7b96p-3
  },
  { // Entry 296
    -0x1.18b472e84eb8a189e113a261ae412556p-3,
    -0x1.1a7b9611a7b96p-3
  },
  { // Entry 297
    0x1.5da54d60a7195c8adb545802f1bfc594p-3,
    0x1.611a7b9611a7cp-3
  },
  { // Entry 298
    -0x1.5da54d60a7195c8adb545802f1bfc594p-3,
    -0x1.611a7b9611a7cp-3
  },
  { // Entry 299
    0x1.a1c7a7122df5863ada1156ab3e6900a0p-3,
    0x1.a7b9611a7b962p-3
  },
  { // Entry 300
    -0x1.a1c7a7122df5863ada1156ab3e6900a0p-3,
    -0x1.a7b9611a7b962p-3
  },
  { // Entry 301
    0x1.e4f66c98ea9387f84c4b3ac494f670b7p-3,
    0x1.ee58469ee5848p-3
  },
  { // Entry 302
    -0x1.e4f66c98ea9387f84c4b3ac494f670b7p-3,
    -0x1.ee58469ee5848p-3
  },
  { // Entry 303
    0x1.13875ab3cead807903e1f1f3e8e5643ep-2,
    0x1.1a7b9611a7b97p-2
  },
  { // Entry 304
    -0x1.13875ab3cead807903e1f1f3e8e5643ep-2,
    -0x1.1a7b9611a7b97p-2
  },
  { // Entry 305
    0x1.33f8025638e0d966877007ff4292fc49p-2,
    0x1.3dcb08d3dcb0ap-2
  },
  { // Entry 306
    -0x1.33f8025638e0d966877007ff4292fc49p-2,
    -0x1.3dcb08d3dcb0ap-2
  },
  { // Entry 307
    0x1.53be3f9638299cc1042cd3014eb611a5p-2,
    0x1.611a7b9611a7dp-2
  },
  { // Entry 308
    -0x1.53be3f9638299cc1042cd3014eb611a5p-2,
    -0x1.611a7b9611a7dp-2
  },
  { // Entry 309
    0x1.72cc8acad74a0554ceab8f673d8fd9c1p-2,
    0x1.8469ee58469f0p-2
  },
  { // Entry 310
    -0x1.72cc8acad74a0554ceab8f673d8fd9c1p-2,
    -0x1.8469ee58469f0p-2
  },
  { // Entry 311
    0x1.9116d18d0f897a8cd0329175c1761056p-2,
    0x1.a7b9611a7b963p-2
  },
  { // Entry 312
    -0x1.9116d18d0f897a8cd0329175c1761056p-2,
    -0x1.a7b9611a7b963p-2
  },
  { // Entry 313
    0x1.ae92803956bf8fe7960fe047c58fe2cep-2,
    0x1.cb08d3dcb08d6p-2
  },
  { // Entry 314
    -0x1.ae92803956bf8fe7960fe047c58fe2cep-2,
    -0x1.cb08d3dcb08d6p-2
  },
  { // Entry 315
    0x1.cb3685d89f9d9f9f4ed38442b61bb2a8p-2,
    0x1.ee58469ee5849p-2
  },
  { // Entry 316
    -0x1.cb3685d89f9d9f9f4ed38442b61bb2a8p-2,
    -0x1.ee58469ee5849p-2
  },
  { // Entry 317
    0x1.e6fb52c30980e5f495d12b6477845637p-2,
    0x1.08d3dcb08d3dep-1
  },
  { // Entry 318
    -0x1.e6fb52c30980e5f495d12b6477845637p-2,
    -0x1.08d3dcb08d3dep-1
  },
  { // Entry 319
    0x1.00ed69341225491fa94ea8dd2d1c04adp-1,
    0x1.1a7b9611a7b97p-1
  },
  { // Entry 320
    -0x1.00ed69341225491fa94ea8dd2d1c04adp-1,
    -0x1.1a7b9611a7b97p-1
  },
  { // Entry 321
    0x1.0de8305e4cc3d5001e5239e63b8dbed5p-1,
    0x1.2c234f72c2350p-1
  },
  { // Entry 322
    -0x1.0de8305e4cc3d5001e5239e63b8dbed5p-1,
    -0x1.2c234f72c2350p-1
  },
  { // Entry 323
    0x1.1a6c5ded8f162aadbb0149b498cb1b24p-1,
    0x1.3dcb08d3dcb09p-1
  },
  { // Entry 324
    -0x1.1a6c5ded8f162aadbb0149b498cb1b24p-1,
    -0x1.3dcb08d3dcb09p-1
  },
  { // Entry 325
    0x1.2678f93777439d5d9ad904ba063ecb5ep-1,
    0x1.4f72c234f72c2p-1
  },
  { // Entry 326
    -0x1.2678f93777439d5d9ad904ba063ecb5ep-1,
    -0x1.4f72c234f72c2p-1
  },
  { // Entry 327
    0x1.320da7c091ef4552ae755c643a3b4933p-1,
    0x1.611a7b9611a7bp-1
  },
  { // Entry 328
    -0x1.320da7c091ef4552ae755c643a3b4933p-1,
    -0x1.611a7b9611a7bp-1
  },
  { // Entry 329
    0x1.3d2aa22040bdd68238402204b98c4e93p-1,
    0x1.72c234f72c234p-1
  },
  { // Entry 330
    -0x1.3d2aa22040bdd68238402204b98c4e93p-1,
    -0x1.72c234f72c234p-1
  },
  { // Entry 331
    0x1.47d0a82acb4267d301a5dffb3c9a40b2p-1,
    0x1.8469ee58469edp-1
  },
  { // Entry 332
    -0x1.47d0a82acb4267d301a5dffb3c9a40b2p-1,
    -0x1.8469ee58469edp-1
  },
  { // Entry 333
    0x1.5200f4a602b2eebb2c2d9b4d031da2b3p-1,
    0x1.9611a7b9611a6p-1
  },
  { // Entry 334
    -0x1.5200f4a602b2eebb2c2d9b4d031da2b3p-1,
    -0x1.9611a7b9611a6p-1
  },
  { // Entry 335
    0x1.5bbd30c7183021dd4ae1af94efeb7351p-1,
    0x1.a7b9611a7b95fp-1
  },
  { // Entry 336
    -0x1.5bbd30c7183021dd4ae1af94efeb7351p-1,
    -0x1.a7b9611a7b95fp-1
  },
  { // Entry 337
    0x1.650767b19bab5c9a85115d59c1bbbbecp-1,
    0x1.b9611a7b96118p-1
  },
  { // Entry 338
    -0x1.650767b19bab5c9a85115d59c1bbbbecp-1,
    -0x1.b9611a7b96118p-1
  },
  { // Entry 339
    0x1.6de1fa2868b7da01452d1e472d0223d9p-1,
    0x1.cb08d3dcb08d1p-1
  },
  { // Entry 340
    -0x1.6de1fa2868b7da01452d1e472d0223d9p-1,
    -0x1.cb08d3dcb08d1p-1
  },
  { // Entry 341
    0x1.764f9299df20114d026ebd244b4e904ap-1,
    0x1.dcb08d3dcb08ap-1
  },
  { // Entry 342
    -0x1.764f9299df20114d026ebd244b4e904ap-1,
    -0x1.dcb08d3dcb08ap-1
  },
  { // Entry 343
    0x1.7e5319a96b6639eb0ade7fa028ee0d3bp-1,
    0x1.ee58469ee5843p-1
  },
  { // Entry 344
    -0x1.7e5319a96b6639eb0ade7fa028ee0d3bp-1,
    -0x1.ee58469ee5843p-1
  },
  { // Entry 345
    0x1.85efab514f392a77871c49877ccdbfbep-1,
    0x1.ffffffffffffcp-1
  },
  { // Entry 346
    -0x1.85efab514f392a77871c49877ccdbfbep-1,
    -0x1.ffffffffffffcp-1
  },
  { // Entry 347
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p100
  },
  { // Entry 348
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p100
  },
  { // Entry 349
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0d79435e50d79p100
  },
  { // Entry 350
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0d79435e50d79p100
  },
  { // Entry 351
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.1af286bca1af2p100
  },
  { // Entry 352
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.1af286bca1af2p100
  },
  { // Entry 353
    0x1.ffffffffffffffffffffffffffffffffp-1
```
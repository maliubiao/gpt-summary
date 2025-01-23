Response:
My thinking process for summarizing the functionality of the `atan2f_intel_data.handroid` file goes like this:

1. **Identify the Core Purpose:** The filename `atan2f_intel_data.handroid` immediately suggests that this file contains data related to the `atan2f` function, specifically for Intel architectures on Android (`handroid`). The "data" suffix indicates it's not executable code but rather a collection of values.

2. **Examine the Data Structure:** The code defines `g_atan2f_intel_data` as an array of `data_1_2_t<float, float, float>`. This template suggests each entry in the array contains three floating-point values.

3. **Infer the Relationship to `atan2f`:** The function `atan2f(y, x)` calculates the arctangent of `y/x`, taking into account the signs of both `y` and `x` to determine the correct quadrant. Since there are three floats per entry, it's highly likely they represent input values for `atan2f` and the expected output.

4. **Analyze the Data Entries:**  Looking at the numerical values, they are mostly represented in hexadecimal floating-point format (e.g., `-0x1.ffffe4000187ffea90012c1fef963e3bp-60`). The presence of both positive and negative values for the first two floats suggests they correspond to the `y` and `x` inputs of `atan2f`. The third float likely represents the expected result.

5. **Identify the Testing Context:** The file resides in `bionic/tests/math_data`. This strongly indicates that the data is used for testing the `atan2f` function implementation in Android's Bionic library. The "intel" in the name suggests architecture-specific testing.

6. **Formulate a Concise Summary:** Based on the above analysis, I can summarize the file's functionality as:  It provides a set of test cases for the `atan2f` function, specifically for Intel architectures in the Android Bionic library. Each entry defines a pair of floating-point inputs (representing the `y` and `x` arguments of `atan2f`) and the corresponding expected floating-point output.

7. **Refine the Summary:**  To make the summary more precise, I can add details like the data structure used (array of structs/objects) and the purpose of these tests (verifying the correctness and accuracy of the `atan2f` implementation).

8. **Address the "Part 1" prompt:** Since the prompt explicitly asks for a summary for "Part 1", I should ensure the answer focuses on the high-level functionality and avoids delving into implementation details or the broader Android ecosystem aspects, which are likely reserved for subsequent parts.

Therefore, my thinking process led me to the summarized answer:  这个文件 `atan2f_intel_data.handroid` 的主要功能是 **为 Android Bionic 库中的 `atan2f` 函数提供一组测试数据**。

具体来说：

*   **测试用例集:**  这个文件定义了一个名为 `g_atan2f_intel_data` 的数组。
*   **`atan2f` 函数的输入和预期输出:**  数组中的每个元素（`data_1_2_t<float, float, float>`）都代表一个独立的测试用例，包含 `atan2f` 函数的两个 `float` 类型的输入值（对应 `atan2f(y, x)` 中的 `y` 和 `x`）以及期望的 `float` 类型的输出结果。
*   **针对 Intel 架构:** 文件名中的 "intel" 表明这些测试数据是专门为在 Intel 架构上运行的 Android 系统设计的。
*   **用于验证 `atan2f` 的正确性:** 这些数据被用于测试 Bionic 库中 `atan2f` 函数的实现是否正确，即对于给定的输入，函数是否能返回预期的精确结果。

简单来说，这个文件是用来**测试 Android 系统中 `atan2f` 函数在 Intel 平台上的正确性的数据集合**。
这是目录为 `bionic/tests/math_data/atan2f_intel_data.handroid` 的源代码文件。根据文件路径和内容，我们可以归纳出它的主要功能：

**核心功能：提供 `atan2f` 函数在 Intel 架构上的测试数据。**

具体来说：

*   **测试用例集:**  这个文件定义了一个名为 `g_atan2f_intel_data` 的数组。
*   **`atan2f` 函数的输入和预期输出:**  数组中的每个元素（`data_1_2_t<float, float, float>`）都代表一个独立的测试用例，包含 `atan2f` 函数的两个 `float` 类型的输入值（对应 `atan2f(y, x)` 中的 `y` 和 `x`）以及期望的 `float` 类型的输出结果。
*   **针对 Intel 架构:** 文件名中的 "intel" 表明这些测试数据是专门为在 Intel 架构上运行的 Android 系统设计的。
*   **用于验证 `atan2f` 的正确性:** 这些数据被用于测试 Bionic 库中 `atan2f` 函数的实现是否正确，即对于给定的输入，函数是否能返回预期的精确结果。

**简单来说，这个文件是用来测试 Android 系统中 `atan2f` 函数在 Intel 平台上的正确性的数据集合。**

### 提示词
```
这是目录为bionic/tests/math_data/atan2f_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_2_t<float, float, float> g_atan2f_intel_data[] = {
  { // Entry 0
    -0x1.ffffe4000187ffea90012c1fef963e3bp-60,
    -0x1.p-100,
    0x1.00000ep-41
  },
  { // Entry 1
    0x1.ffffe4000187ffea90012c1fef963e3bp-60,
    0x1.p-100,
    0x1.00000ep-41
  },
  { // Entry 2
    -0.0f,
    -0x1.p-100,
    0x1.00000ep50
  },
  { // Entry 3
    0.0f,
    0x1.p-100,
    0x1.00000ep50
  },
  { // Entry 4
    -0x1.7ffffffffff44cccff95f13b15ee40f3p-11,
    -0x1.000002p-10,
    0x1.555554p0
  },
  { // Entry 5
    0x1.7ffffffffff44cccff95f13b15ee40f3p-11,
    0x1.000002p-10,
    0x1.555554p0
  },
  { // Entry 6
    -0x1.fffffc00000d55550555571bbbb2d111p-23,
    -0x1.000004p0,
    0x1.000006p22
  },
  { // Entry 7
    0x1.fffffc00000d55550555571bbbb2d111p-23,
    0x1.000004p0,
    0x1.000006p22
  },
  { // Entry 8
    -0x1.dad20effbd30f4310a58502b0ff3965dp-2,
    -0x1.000006p3,
    0x1.fff186p3
  },
  { // Entry 9
    0x1.dad20effbd30f4310a58502b0ff3965dp-2,
    0x1.000006p3,
    0x1.fff186p3
  },
  { // Entry 10
    -0x1.ff654bdefc197c75159e23b86a1127c1p-5,
    -0x1.0008p16,
    0x1.000030p20
  },
  { // Entry 11
    0x1.ff654bdefc197c75159e23b86a1127c1p-5,
    0x1.0008p16,
    0x1.000030p20
  },
  { // Entry 12
    -0x1.ff9b39e1a4728254bcb91f895e52abc2p-5,
    -0x1.002304p3,
    0x1.000022p7
  },
  { // Entry 13
    0x1.ff9b39e1a4728254bcb91f895e52abc2p-5,
    0x1.002304p3,
    0x1.000022p7
  },
  { // Entry 14
    -0x1.43e6bb010a022abaa97bc92c2bf92b2dp-2,
    -0x1.04fd14p-4,
    0x1.8eb358p-3
  },
  { // Entry 15
    0x1.43e6bb010a022abaa97bc92c2bf92b2dp-2,
    0x1.04fd14p-4,
    0x1.8eb358p-3
  },
  { // Entry 16
    -0x1.905827610aa194066b73a36bcafa2041p-1,
    -0x1.0596bcp-3,
    0x1.0769dcp-3
  },
  { // Entry 17
    0x1.905827610aa194066b73a36bcafa2041p-1,
    0x1.0596bcp-3,
    0x1.0769dcp-3
  },
  { // Entry 18
    -0x1.f5b7710347b9a8b79afdefc31a2185a0p-2,
    -0x1.111118p-2,
    0x1.fffff8p-2
  },
  { // Entry 19
    0x1.f5b7710347b9a8b79afdefc31a2185a0p-2,
    0x1.111118p-2,
    0x1.fffff8p-2
  },
  { // Entry 20
    -0x1.151c477cb91ad4bb4a65e8d3fd3321f4p0,
    -0x1.111118p-14,
    0x1.222218p-15
  },
  { // Entry 21
    0x1.151c477cb91ad4bb4a65e8d3fd3321f4p0,
    0x1.111118p-14,
    0x1.222218p-15
  },
  { // Entry 22
    -0x1.520acb002e18e97cf7bea2ae9290357bp0,
    -0x1.199994p-1,
    0x1.20p-3
  },
  { // Entry 23
    0x1.520acb002e18e97cf7bea2ae9290357bp0,
    0x1.199994p-1,
    0x1.20p-3
  },
  { // Entry 24
    -0x1.d1a1ebad28ca743ee543132b45980d5cp-2,
    -0x1.199998p-1,
    0x1.20p0
  },
  { // Entry 25
    0x1.d1a1ebad28ca743ee543132b45980d5cp-2,
    0x1.199998p-1,
    0x1.20p0
  },
  { // Entry 26
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.19999ap0,
    0x1.p-149
  },
  { // Entry 27
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.19999ap0,
    0x1.p-149
  },
  { // Entry 28
    -0x1.922170fe86dc56969c78b959508174d3p-1,
    -0x1.2c0202p9,
    0x1.2bfffap9
  },
  { // Entry 29
    0x1.922170fe86dc56969c78b959508174d3p-1,
    0x1.2c0202p9,
    0x1.2bfffap9
  },
  { // Entry 30
    -0x1.8ec170fc51bb0a23bd010cc82696f548p0,
    -0x1.2ffff0p6,
    0x1.p0
  },
  { // Entry 31
    0x1.8ec170fc51bb0a23bd010cc82696f548p0,
    0x1.2ffff0p6,
    0x1.p0
  },
  { // Entry 32
    -0x1.2fffffffffffffffffffffffffffffffp-146,
    -0x1.30p-145,
    0x1.p1
  },
  { // Entry 33
    0x1.2fffffffffffffffffffffffffffffffp-146,
    0x1.30p-145,
    0x1.p1
  },
  { // Entry 34
    -0x1.2a73acfced538de0e37fe6b9b0a41ebap-2,
    -0x1.333338p-2,
    0x1.fffffcp-1
  },
  { // Entry 35
    0x1.2a73acfced538de0e37fe6b9b0a41ebap-2,
    0x1.333338p-2,
    0x1.fffffcp-1
  },
  { // Entry 36
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.40p-147,
    -0x1.fffffep127
  },
  { // Entry 37
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.40p-147,
    -0x1.fffffep127
  },
  { // Entry 38
    -0x1.3fffffffffffffffffffffffffffffffp-148,
    -0x1.40p-147,
    0x1.p1
  },
  { // Entry 39
    0x1.3fffffffffffffffffffffffffffffffp-148,
    0x1.40p-147,
    0x1.p1
  },
  { // Entry 40
    -0x1.ffa33dcc72ce5a24fbffc472e6d8aa54p-5,
    -0x1.77fffep-15,
    0x1.77c6e2p-11
  },
  { // Entry 41
    0x1.ffa33dcc72ce5a24fbffc472e6d8aa54p-5,
    0x1.77fffep-15,
    0x1.77c6e2p-11
  },
  { // Entry 42
    -0x1.72eab640dab3ff16e57acdbe73e804d6p-2,
    -0x1.7b4a16p-4,
    0x1.f474d8p-3
  },
  { // Entry 43
    0x1.72eab640dab3ff16e57acdbe73e804d6p-2,
    0x1.7b4a16p-4,
    0x1.f474d8p-3
  },
  { // Entry 44
    -0x1.7fffad001ebebf3a599c03854b51e597p-9,
    -0x1.7ffffep0,
    0x1.000006p9
  },
  { // Entry 45
    0x1.7fffad001ebebf3a599c03854b51e597p-9,
    0x1.7ffffep0,
    0x1.000006p9
  },
  { // Entry 46
    -0x1.e3539c0f15f7f48eab208803a29a2c7dp0,
    -0x1.85e85ep-1,
    -0x1.fffffcp-3
  },
  { // Entry 47
    0x1.e3539c0f15f7f48eab208803a29a2c7dp0,
    0x1.85e85ep-1,
    -0x1.fffffcp-3
  },
  { // Entry 48
    -0x1.fff7a95adac43e9c9763981911f0af91p-6,
    -0x1.881a4ap5,
    0x1.88p10
  },
  { // Entry 49
    0x1.fff7a95adac43e9c9763981911f0af91p-6,
    0x1.881a4ap5,
    0x1.88p10
  },
  { // Entry 50
    -0x1.afffffffffffffffffffffffffffffffp-146,
    -0x1.b0p-145,
    0x1.p1
  },
  { // Entry 51
    0x1.afffffffffffffffffffffffffffffffp-146,
    0x1.b0p-145,
    0x1.p1
  },
  { // Entry 52
    -0x1.a5ce8d1a28d5bcb270bc016790eb423ap0,
    -0x1.bbbbbcp-1,
    -0x1.1179f8p-4
  },
  { // Entry 53
    0x1.a5ce8d1a28d5bcb270bc016790eb423ap0,
    0x1.bbbbbcp-1,
    -0x1.1179f8p-4
  },
  { // Entry 54
    -0x1.eafe7000a5dc264f70fe1dd7f684b160p-3,
    -0x1.d55554p-1,
    0x1.dffffep1
  },
  { // Entry 55
    0x1.eafe7000a5dc264f70fe1dd7f684b160p-3,
    0x1.d55554p-1,
    0x1.dffffep1
  },
  { // Entry 56
    -0x1.eb4a75001deee59a8f1d03f2e725b3aep-2,
    -0x1.d5e926p-3,
    0x1.c38dc4p-2
  },
  { // Entry 57
    0x1.eb4a75001deee59a8f1d03f2e725b3aep-2,
    0x1.d5e926p-3,
    0x1.c38dc4p-2
  },
  { // Entry 58
    -0x1.dfffffffffffffffffffffffffffffffp-147,
    -0x1.e0p-146,
    0x1.p1
  },
  { // Entry 59
    0x1.dfffffffffffffffffffffffffffffffp-147,
    0x1.e0p-146,
    0x1.p1
  },
  { // Entry 60
    -0x1.f12ab8f4f73d14abefa8e36cac1681p-19,
    -0x1.f12a96p2,
    0x1.ffffdcp20
  },
  { // Entry 61
    0x1.f12ab8f4f73d14abefa8e36cac1681p-19,
    0x1.f12a96p2,
    0x1.ffffdcp20
  },
  { // Entry 62
    -0x1.e42b250039e7dca1fe04ee304684c0edp-2,
    -0x1.f8732ap-2,
    0x1.ed16e2p-1
  },
  { // Entry 63
    0x1.e42b250039e7dca1fe04ee304684c0edp-2,
    0x1.f8732ap-2,
    0x1.ed16e2p-1
  },
  { // Entry 64
    -0x1.ff571a1535e84a3ed0617f7c8bd43c9dp-5,
    -0x1.ffffdep-3,
    0x1.fffe7ep1
  },
  { // Entry 65
    0x1.ff571a1535e84a3ed0617f7c8bd43c9dp-5,
    0x1.ffffdep-3,
    0x1.fffe7ep1
  },
  { // Entry 66
    0.0,
    0.0,
    0.0
  },
  { // Entry 67
    0.0f,
    0x1.p-149,
    0x1.p1
  },
  { // Entry 68
    -0.0f,
    -0x1.p-149,
    0x1.p1
  },
  { // Entry 69
    0x1.5ffff7c000317ffed70006f5ffd63cp-147,
    0x1.p-149,
    0x1.745d20p-3
  },
  { // Entry 70
    -0x1.5ffff7c000317ffed70006f5ffd63cp-147,
    -0x1.p-149,
    0x1.745d20p-3
  },
  { // Entry 71
    0x1.40000dc0009740067fc0477d431261e1p-146,
    0x1.p-149,
    0x1.999988p-4
  },
  { // Entry 72
    -0x1.40000dc0009740067fc0477d431261e1p-146,
    -0x1.p-149,
    0x1.999988p-4
  },
  { // Entry 73
    0.0f,
    0x1.p-149,
    0x1.fffffep0
  },
  { // Entry 74
    -0.0f,
    -0x1.p-149,
    0x1.fffffep0
  },
  { // Entry 75
    0x1.000001000000fffaabaa9aabaa8aabddp-30,
    0x1.p2,
    0x1.fffffep31
  },
  { // Entry 76
    -0x1.000001000000fffaabaa9aabaa8aabddp-30,
    -0x1.p2,
    0x1.fffffep31
  },
  { // Entry 77
    0x1.03a264fffa8f8262b1fabf7149142cb1p-1,
    0x1.p9,
    0x1.ccccd8p9
  },
  { // Entry 78
    -0x1.03a264fffa8f8262b1fabf7149142cb1p-1,
    -0x1.p9,
    0x1.ccccd8p9
  },
  { // Entry 79
    0x1.096d02910676c2be11dcfe9fe3175278p1,
    0x1.000002p-1,
    -0x1.19998ep-2
  },
  { // Entry 80
    -0x1.096d02910676c2be11dcfe9fe3175278p1,
    -0x1.000002p-1,
    -0x1.19998ep-2
  },
  { // Entry 81
    0x1.ff54b8d04e797f1463152a327d0b86c4p-2,
    0x1.000002p-1,
    0x1.d55560p-1
  },
  { // Entry 82
    -0x1.ff54b8d04e797f1463152a327d0b86c4p-2,
    -0x1.000002p-1,
    0x1.d55560p-1
  },
  { // Entry 83
    0x1.dac67522e883aedcc9c473438e936964p-2,
    0x1.000002p-1,
    0x1.fffffep-1
  },
  { // Entry 84
    -0x1.dac67522e883aedcc9c473438e936964p-2,
    -0x1.000002p-1,
    0x1.fffffep-1
  },
  { // Entry 85
    0x1.f430999672c04e0df46fd1307191a380p-4,
    0x1.000002p-3,
    0x1.04bd9cp0
  },
  { // Entry 86
    -0x1.f430999672c04e0df46fd1307191a380p-4,
    -0x1.000002p-3,
    0x1.04bd9cp0
  },
  { // Entry 87
    0x1.7fb81eff43d4f24387e27e042d6562dbp-5,
    0x1.000002p-5,
    0x1.555552p-1
  },
  { // Entry 88
    -0x1.7fb81eff43d4f24387e27e042d6562dbp-5,
    -0x1.000002p-5,
    0x1.555552p-1
  },
  { // Entry 89
    0x1.000003000001aaaaa1aaaa80dddd98ddp-23,
    0x1.000002p-23,
    0x1.fffffep-1
  },
  { // Entry 90
    -0x1.000003000001aaaaa1aaaa80dddd98ddp-23,
    -0x1.000002p-23,
    0x1.fffffep-1
  },
  { // Entry 91
    0x1.921fb4fddc6a66f8e54f012a148cac4ep1,
    0x1.000002p-25,
    -0x1.d1745cp-1
  },
  { // Entry 92
    -0x1.921fb4fddc6a66f8e54f012a148cac4ep1,
    -0x1.000002p-25,
    -0x1.d1745cp-1
  },
  { // Entry 93
    0x1.0468a979b1a9f0624f4c1516d96c6422p1,
    0x1.000002p0,
    -0x1.000006p-1
  },
  { // Entry 94
    -0x1.0468a979b1a9f0624f4c1516d96c6422p1,
    -0x1.000002p0,
    -0x1.000006p-1
  },
  { // Entry 95
    0x1.b96e57abf90140f894091838c2b8a690p-1,
    0x1.000002p0,
    0x1.b6db76p-1
  },
  { // Entry 96
    -0x1.b96e57abf90140f894091838c2b8a690p-1,
    -0x1.000002p0,
    0x1.b6db76p-1
  },
  { // Entry 97
    0x1.f01ecfda25de70c3e0bfdea229510fd3p0,
    0x1.000002p1,
    -0x1.89d8a0p-1
  },
  { // Entry 98
    -0x1.f01ecfda25de70c3e0bfdea229510fd3p0,
    -0x1.000002p1,
    -0x1.89d8a0p-1
  },
  { // Entry 99
    0x1.ff5625094d950db0c74144886d91c14cp-5,
    0x1.000004p-3,
    0x1.ffff9ep0
  },
  { // Entry 100
    -0x1.ff5625094d950db0c74144886d91c14cp-5,
    -0x1.000004p-3,
    0x1.ffff9ep0
  },
  { // Entry 101
    0x1.fd5bd4fd7ac8b0cf6006c4414f743ea0p-4,
    0x1.000006p3,
    0x1.ffffe0p5
  },
  { // Entry 102
    -0x1.fd5bd4fd7ac8b0cf6006c4414f743ea0p-4,
    -0x1.000006p3,
    0x1.ffffe0p5
  },
  { // Entry 103
    0x1.8c4f470003e118b76491b0c859d6c053p1,
    0x1.000008p-2,
    -0x1.60p2
  },
  { // Entry 104
    -0x1.8c4f470003e118b76491b0c859d6c053p1,
    -0x1.000008p-2,
    -0x1.60p2
  },
  { // Entry 105
    0x1.2834603b51b0b1b7ada51badb8c5e787p-1,
    0x1.00000ep-20,
    0x1.88p-20
  },
  { // Entry 106
    -0x1.2834603b51b0b1b7ada51badb8c5e787p-1,
    -0x1.00000ep-20,
    0x1.88p-20
  },
  { // Entry 107
    0x1.f77e7bb64eb5f42395a6d8adcffa6337p-2,
    0x1.00000ep-20,
    0x1.ddfffep-20
  },
  { // Entry 108
    -0x1.f77e7bb64eb5f42395a6d8adcffa6337p-2,
    -0x1.00000ep-20,
    0x1.ddfffep-20
  },
  { // Entry 109
    0x1.ffd87cf6fd38249fc231c5402edbc122p-6,
    0x1.000010p-3,
    0x1.fffcfep1
  },
  { // Entry 110
    -0x1.ffd87cf6fd38249fc231c5402edbc122p-6,
    -0x1.000010p-3,
    0x1.fffcfep1
  },
  { // Entry 111
    0x1.fd5bd4fd76b8efb59210712d88b6e912p-4,
    0x1.00001ep3,
    0x1.000008p6
  },
  { // Entry 112
    -0x1.fd5bd4fd76b8efb59210712d88b6e912p-4,
    -0x1.00001ep3,
    0x1.000008p6
  },
  { // Entry 113
    0x1.fd5c357b879b2fe30dedcd3135cb691bp-4,
    0x1.000038p3,
    0x1.ffffe2p5
  },
  { // Entry 114
    -0x1.fd5c357b879b2fe30dedcd3135cb691bp-4,
    -0x1.000038p3,
    0x1.ffffe2p5
  },
  { // Entry 115
    0x1.99392cffffb1e34431dc0b78592ad27cp0,
    0x1.000262p0,
    -0x1.c67ffep-6
  },
  { // Entry 116
    -0x1.99392cffffb1e34431dc0b78592ad27cp0,
    -0x1.000262p0,
    -0x1.c67ffep-6
  },
  { // Entry 117
    0x1.ff654bdefc197c75159e23b86a1127c1p-5,
    0x1.0008p16,
    0x1.000030p20
  },
  { // Entry 118
    -0x1.ff654bdefc197c75159e23b86a1127c1p-5,
    -0x1.0008p16,
    0x1.000030p20
  },
  { // Entry 119
    0x1.321a6aeab209211260a57ffa3329874ep-1,
    0x1.000ep-20,
    0x1.77fffep-20
  },
  { // Entry 120
    -0x1.321a6aeab209211260a57ffa3329874ep-1,
    -0x1.000ep-20,
    0x1.77fffep-20
  },
  { // Entry 121
    0x1.ff753bea780e4b6715b12898d26fada0p-5,
    0x1.0010p-3,
    0x1.000030p1
  },
  { // Entry 122
    -0x1.ff753bea780e4b6715b12898d26fada0p-5,
    -0x1.0010p-3,
    0x1.000030p1
  },
  { // Entry 123
    0x1.400ea9fffd0dcf2989a4e76f8aa5db51p-1,
    0x1.001be4p-1,
    0x1.62e42ep-1
  },
  { // Entry 124
    -0x1.400ea9fffd0dcf2989a4e76f8aa5db51p-1,
    -0x1.001be4p-1,
    0x1.62e42ep-1
  },
  { // Entry 125
    0x1.ff9b39e1a4728254bcb91f895e52abc2p-5,
    0x1.002304p3,
    0x1.000022p7
  },
  { // Entry 126
    -0x1.ff9b39e1a4728254bcb91f895e52abc2p-5,
    -0x1.002304p3,
    0x1.000022p7
  },
  { // Entry 127
    0x1.943f9a4b36eb2b8033de5110689ec228p-1,
    0x1.022228p0,
    0x1.fffffcp-1
  },
  { // Entry 128
    -0x1.943f9a4b36eb2b8033de5110689ec228p-1,
    -0x1.022228p0,
    0x1.fffffcp-1
  },
  { // Entry 129
    0x1.c66450ffe905abdcfe0531d5f14c2238p0,
    0x1.0b7778p-21,
    -0x1.bb0cp-24
  },
  { // Entry 130
    -0x1.c66450ffe905abdcfe0531d5f14c2238p0,
    -0x1.0b7778p-21,
    -0x1.bb0cp-24
  },
  { // Entry 131
    0x1.f759ec36e59bd61b017b6ebaaf148489p-2,
    0x1.0df6b0p9,
    0x1.f83dc0p9
  },
  { // Entry 132
    -0x1.f759ec36e59bd61b017b6ebaaf148489p-2,
    -0x1.0df6b0p9,
    0x1.f83dc0p9
  },
  { // Entry 133
    0x1.0039e2465cf8081fc9c3f6acc6017e31p-1,
    0x1.0f83dap9,
    0x1.f07bd4p9
  },
  { // Entry 134
    -0x1.0039e2465cf8081fc9c3f6acc6017e31p-1,
    -0x1.0f83dap9,
    0x1.f07bd4p9
  },
  { // Entry 135
    0x1.32c00cffff80612ac29d96e5387e4acdp-1,
    0x1.10cee0p1,
    0x1.8f83e4p1
  },
  { // Entry 136
    -0x1.32c00cffff80612ac29d96e5387e4acdp-1,
    -0x1.10cee0p1,
    0x1.8f83e4p1
  },
  { // Entry 137
    0x1.fc9d3effcf63ce3c73d32f688b7e0d3ep-2,
    0x1.133332p9,
    0x1.fbbbacp9
  },
  { // Entry 138
    -0x1.fc9d3effcf63ce3c73d32f688b7e0d3ep-2,
    -0x1.133332p9,
    0x1.fbbbacp9
  },
  { // Entry 139
    0x1.13b7ba9cbd2bde0ae99dd5b90b6a6caep-4,
    0x1.142288p-5,
    0x1.p-1
  },
  { // Entry 140
    -0x1.13b7ba9cbd2bde0ae99dd5b90b6a6caep-4,
    -0x1.142288p-5,
    0x1.p-1
  },
  { // Entry 141
    0x1.9baeb903173549a4605c13cb0ec5c997p-1,
    0x1.1a8a08p-1,
    0x1.102e88p-1
  },
  { // Entry 142
    -0x1.9baeb903173549a4605c13cb0ec5c997p-1,
    -0x1.1a8a08p-1,
    0x1.102e88p-1
  },
  { // Entry 143
    0x1.585ed10003e25039288d2a597baabb4ep-1,
    0x1.1aab0ep-1,
    0x1.62e42ep-1
  },
  { // Entry 144
    -0x1.585ed10003e25039288d2a597baabb4ep-1,
    -0x1.1aab0ep-1,
    0x1.62e42ep-1
  },
  { // Entry 145
    0x1.fd7b30fe75452129dd4d92575b1b6643p-3,
    0x1.20p0,
    0x1.1b6db6p2
  },
  { // Entry 146
    -0x1.fd7b30fe75452129dd4d92575b1b6643p-3,
    -0x1.20p0,
    0x1.1b6db6p2
  },
  { // Entry 147
    0x1.5ee2abfffc833087a8462d843d375f40p-1,
    0x1.221ffcp-1,
    0x1.62e42ep-1
  },
  { // Entry 148
    -0x1.5ee2abfffc833087a8462d843d375f40p-1,
    -0x1.221ffcp-1,
    0x1.62e42ep-1
  },
  { // Entry 149
    0x1.922dd2fea41a07a00852062680449192p-1,
    0x1.223224p9,
    0x1.222224p9
  },
  { // Entry 150
    -0x1.922dd2fea41a07a00852062680449192p-1,
    -0x1.223224p9,
    0x1.222224p9
  },
  { // Entry 151
    0x1.fd98765b7a311ad974b5861737a89126p-4,
    0x1.3024a6p-1,
    0x1.2ffffcp2
  },
  { // Entry 152
    -0x1.fd98765b7a311ad974b5861737a89126p-4,
    -0x1.3024a6p-1,
    0x1.2ffffcp2
  },
  { // Entry 153
    0x1.ff173f59cb25f4362c94ce6ab39ece70p-4,
    0x1.310b7ep-1,
    0x1.2ffffcp2
  },
  { // Entry 154
    -0x1.ff173f59cb25f4362c94ce6ab39ece70p-4,
    -0x1.310b7ep-1,
    0x1.2ffffcp2
  },
  { // Entry 155
    0x1.893661d985cfb6e78d6ed0749b2fd803p-1,
    0x1.31f564p-4,
    0x1.3ccc80p-4
  },
  { // Entry 156
    -0x1.893661d985cfb6e78d6ed0749b2fd803p-1,
    -0x1.31f564p-4,
    0x1.3ccc80p-4
  },
  { // Entry 157
    0x1.3800a6f8595ae7372b172ef6aec40af3p-28,
    0x1.38p-20,
    0x1.fffeeep7
  },
  { // Entry 158
    -0x1.3800a6f8595ae7372b172ef6aec40af3p-28,
    -0x1.38p-20,
    0x1.fffeeep7
  },
  { // Entry 159
    0x1.f51dec230b3dcdee4d4b104276bd091bp0,
    0x1.3a58f8p0,
    -0x1.p-1
  },
  { // Entry 160
    -0x1.f51dec230b3dcdee4d4b104276bd091bp0,
    -0x1.3a58f8p0,
    -0x1.p-1
  },
  { // Entry 161
    0x1.add4fcfffc818f75eda49eae0d8f98e2p-2,
    0x1.3cc366p-2,
    0x1.62e42ep-1
  },
  { // Entry 162
    -0x1.add4fcfffc818f75eda49eae0d8f98e2p-2,
    -0x1.3cc366p-2,
    0x1.62e42ep-1
  },
  { // Entry 163
    0x1.9d6394fffffe8990edfcf5c33f9e7bc1p0,
    0x1.3fc2e4p3,
    -0x1.c28f5ep-2
  },
  { // Entry 164
    -0x1.9d6394fffffe8990edfcf5c33f9e7bc1p0,
    -0x1.3fc2e4p3,
    -0x1.c28f5ep-2
  },
  { // Entry 165
    0x1.16d00513a5c2b116688fed7c9e6d7bf9p-3,
    0x1.40a050p-6,
    0x1.24924ap-3
  },
  { // Entry 166
    -0x1.16d00513a5c2b116688fed7c9e6d7bf9p-3,
    -0x1.40a050p-6,
    0x1.24924ap-3
  },
  { // Entry 167
    0x1.6d71ea27ddde729204699db97fdd037ep-1,
    0x1.41f070p2,
    0x1.73b782p2
  },
  { // Entry 168
    -0x1.6d71ea27ddde729204699db97fdd037ep-1,
    -0x1.41f070p2,
    0x1.73b782p2
  },
  { // Entry 169
    0x1.6e2ce2182a658d8450720e677f21ce61p-1,
    0x1.429ap9,
    0x1.7368e2p9
  },
  { // Entry 170
    -0x1.6e2ce2182a658d8450720e677f21ce61p-1,
    -0x1.429ap9,
    0x1.7368e2p9
  },
  { // Entry 171
    0x1.740a75f5e00f3c2a265818a8e05ccc99p-1,
    0x1.435e54p0,
    0x1.6bca20p0
  },
  { // Entry 172
    -0x1.740a75f5e00f3c2a265818a8e05ccc99p-1,
    -0x1.435e54p0,
    0x1.6bca20p0
  },
  { // Entry 173
    0x1.4eb92766fa1641bdcd6b72f3bd619251p-1,
    0x1.5baa3ap-2,
    0x1.c5c85cp-2
  },
  { // Entry 174
    -0x1.4eb92766fa1641bdcd6b72f3bd619251p-1,
    -0x1.5baa3ap-2,
    0x1.c5c85cp-2
  },
  { // Entry 175
    0x1.feb17ca8152a6f1c96ebab23e1ca4438p-4,
    0x1.5d6c50p-8,
    0x1.5c80p-5
  },
  { // Entry 176
    -0x1.feb17ca8152a6f1c96ebab23e1ca4438p-4,
    -0x1.5d6c50p-8,
    0x1.5c80p-5
  },
  { // Entry 177
    0x1.61e054ffff517564fbb75fa927e9317dp1,
    0x1.62b140p1,
    -0x1.c0p2
  },
  { // Entry 178
    -0x1.61e054ffff517564fbb75fa927e9317dp1,
    -0x1.62b140p1,
    -0x1.c0p2
  },
  { // Entry 179
    0x1.926064fffd342f8f129a70df92a458b3p-1,
    0x1.633de6p-1,
    0x1.62e42ep-1
  },
  { // Entry 180
    -0x1.926064fffd342f8f129a70df92a458b3p-1,
    -0x1.633de6p-1,
    0x1.62e42ep-1
  },
  { // Entry 181
    0x1.ddf15cfffeff907133df83405cf1c383p-2,
    0x1.65a3e2p-2,
    0x1.62e42ep-1
  },
  { // Entry 182
    -0x1.ddf15cfffeff907133df83405cf1c383p-2,
    -0x1.65a3e2p-2,
    0x1.62e42ep-1
  },
  { // Entry 183
    0x1.a8c692fc3efe50c92076f2cdd3f6bd92p0,
    0x1.68b44ep0,
    -0x1.p-3
  },
  { // Entry 184
    -0x1.a8c692fc3efe50c92076f2cdd3f6bd92p0,
    -0x1.68b44ep0,
    -0x1.p-3
  },
  { // Entry 185
    0x1.1d730dfffc0d10826bfff4268c4db210p0,
    0x1.6a0092p0,
    0x1.62e42ep-1
  },
  { // Entry 186
    -0x1.1d730dfffc0d10826bfff4268c4db210p0,
    -0x1.6a0092p0,
    0x1.62e42ep-1
  },
  { // Entry 187
    0x1.9a06c6fffcb000f0eb371998c338bdaep-1,
    0x1.6e04f2p-1,
    0x1.62e42ep-1
  },
  { // Entry 188
    -0x1.9a06c6fffcb000f0eb371998c338bdaep-1,
    -0x1.6e04f2p-1,
    0x1.62e42ep-1
  },
  { // Entry 189
    0x1.921f9f0000092b6cc81e3cd97531299cp0,
    0x1.70p-1,
    0x1.0011p-20
  },
  { // Entry 190
    -0x1.921f9f0000092b6cc81e3cd97531299cp0,
    -0x1.70p-1,
    0x1.0011p-20
  },
  { // Entry 191
    0x1.55a1f300040b007b9fcf88e0bbaa4bf9p0,
    0x1.707652p1,
    0x1.62e42ep-1
  },
  { // Entry 192
    -0x1.55a1f300040b007b9fcf88e0bbaa4bf9p0,
    -0x1.707652p1,
    0x1.62e42ep-1
  },
  { // Entry 193
    0x1.ffa33dcc72ce5a24fbffc472e6d8aa54p-5,
    0x1.77fffep-15,
    0x1.77c6e2p-11
  },
  { // Entry 194
    -0x1.ffa33dcc72ce5a24fbffc472e6d8aa54p-5,
    -0x1.77fffep-15,
    0x1.77c6e2p-11
  },
  { // Entry 195
    0x1.7702d9c0f7f4e1f5f65e806e4e9e2eb4p-3,
    0x1.7b4274p-2,
    0x1.000006p1
  },
  { // Entry 196
    -0x1.7702d9c0f7f4e1f5f65e806e4e9e2eb4p-3,
    -0x1.7b4274p-2,
    0x1.000006p1
  },
  { // Entry 197
    0x1.fac9255e2e84501d7f69135fa78a7842p-2,
    0x1.7c1570p-2,
    0x1.601e80p-1
  },
  { // Entry 198
    -0x1.fac9255e2e84501d7f69135fa78a7842p-2,
    -0x1.7c1570p-2,
    0x1.601e80p-1
  },
  { // Entry 199
    0x1.a4c2220003e9ff7184d11c11dbed790ap-1,
    0x1.7db652p-1,
    0x1.62e42ep-1
  },
  { // Entry 200
    -0x1.a4c2220003e9ff7184d11c11dbed790ap-1,
    -0x1.7db652p-1,
    0x1.62e42ep-1
  },
  { // Entry 201
    0x1.487f682022d3a5562109a0306dcb05a2p-1,
    0x1.7e7a9ap-2,
    0x1.p-1
  },
  { // Entry 202
    -0x1.487f682022d3a5562109a0306dcb05a2p-1,
    -0x1.7e7a9ap-2,
    0x1.p-1
  },
  { // Entry 203
    0x1.e48b2fddff19e1b2ad305bf85f553acfp0,
    0x1.7fbddep0,
    -0x1.p-1
  },
  { // Entry 204
    -0x1.e48b2fddff19e1b2ad305bf85f553acfp0,
    -0x1.7fbddep0,
    -0x1.p-1
  },
  { // Entry 205
    0x1.8000030000017ffff0ffffc44ccc87ccp-23,
    0x1.80p-23,
    0x1.fffffcp-1
  },
  { // Entry 206
    -0x1.8000030000017ffff0ffffc44ccc87ccp-23,
    -0x1.80p-23,
    0x1.fffffcp-1
  },
  { // Entry 207
    0x1.236ede000419f0232206a19dc1c9ba72p0,
    0x1.807cdcp0,
    0x1.62e42ep-1
  },
  { // Entry 208
    -0x1.236ede000419f0232206a19dc1c9ba72p0,
    -0x1.807cdcp0,
    0x1.62e42ep-1
  },
  { // Entry 209
    0x1.23af91000432ff7ca91b5869446d2677p0,
    0x1.817ccep0,
    0x1.62e42ep-1
  },
  { // Entry 210
    -0x1.23af91000432ff7ca91b5869446d2677p0,
    -0x1.817ccep0,
    0x1.62e42ep-1
  },
  { // Entry 211
    0x1.1d0d78ffde75e005ce13a48bb96c20d2p1,
    0x1.86bcf6p-9,
    -0x1.2cde14p-9
  },
  { // Entry 212
    -0x1.1d0d78ffde75e005ce13a48bb96c20d2p1,
    -0x1.86bcf6p-9,
    -0x1.2cde14p-9
  },
  { // Entry 213
    0x1.c40b44f7d49ec3bebbe6c143bb874988p-17,
    0x1.88p-7,
    0x1.bbfdfep9
  },
  { // Entry 214
    -0x1.c40b44f7d49ec3bebbe6c143bb874988p-17,
    -0x1.88p-7,
    0x1.bbfdfep9
  },
  { // Entry 215
    0x1.ac7dfffd2b94ebd2b4155d81fcb743c8p-1,
    0x1.8ba2bcp9,
    0x1.64d916p9
  },
  { // Entry 216
    -0x1.ac7dfffd2b94ebd2b4155d81fcb743c8p-1,
    -0x1.8ba2bcp9,
    0x1.64d916p9
  },
  { // Entry 217
    0x1.f4436c2918d5691620bddea5f0bdb99fp0,
    0x1.904a6ap9,
    -0x1.42e220p8
  },
  { // Entry 218
    -0x1.f4436c2918d5691620bddea5f0bdb99fp0,
    -0x1.904a6ap9,
    -0x1.42e220p8
  },
  { // Entry 219
    0x1.f280a4a85a9834808487443a22c27f9cp-4,
    0x1.90c864p-5,
    0x1.99999ap-2
  },
  { // Entry 220
    -0x1.f280a4a85a9834808487443a22c27f9cp-4,
    -0x1.90c864p-5,
    0x1.99999ap-2
  },
  { // Entry 221
    0x1.0a58d9000005f0ba9a470ce5241f1b9cp-1,
    0x1.969770p-2,
    0x1.62e42ep-1
  },
  { // Entry 222
    -0x1.0a58d9000005f0ba9a470ce5241f1b9cp-1,
    -0x1.969770p-2,
    0x1.62e42ep-1
  },
  { // Entry 223
    0x1.f730a597948e5c35433d522c24bdefa5p-1,
    0x1.9b2698p9,
    0x1.1219d6p9
  },
  { // Entry 224
    -0x1.f730a597948e5c35433d522c24bdefa5p-1,
    -0x1.9b2698p9,
    0x1.1219d6p9
  },
  { // Entry 225
    0x1.25c78f0002b5030803b34e0d3d565ec5p1,
    0x1.a99552p-9,
    -0x1.788ee0p-9
  },
  { // Entry 226
    -0x1.25c78f0002b5030803b34e0d3d565ec5p1,
    -0x1.a99552p-9,
    -0x1.788ee0p-9
  },
  { // Entry 227
    0x1.fec12756125a1c17f496ca7eff6b5d07p-4,
    0x1.aac766p-1,
    0x1.a99994p2
  },
  { // Entry 228
    -0x1.fec12756125a1c17f496ca7eff6b5d07p-4,
    -0x1.aac766p-1,
    0x1.a99994p2
  },
  { // Entry 229
    0x1.ff2726fffadc57a59c068daf94011a06p-2,
    0x1.acd9c8p-2,
    0x1.89469ep-1
  },
  { // Entry 230
    -0x1.ff2726fffadc57a59c068daf94011a06p-2,
    -0x1.acd9c8p-2,
    0x1.89469ep-1
  },
  { // Entry 231
    0x1.6cefa52cd49df53a19a9664ef79b5d21p-1,
    0x1.ba8cp-2,
    0x1.p-1
  },
  { // Entry 232
    -0x1.6cefa52cd49df53a19a9664ef79b5d21p-1,
    -0x1.ba8cp-2,
    0x1.p-1
  },
  { // Entry 233
    0x1.ffecd1bdfc10703be4cadb1ac64a6eacp-6,
    0x1.bf31e2p-5,
    0x1.bf1d60p0
  },
  { // Entry 234
    -0x1.ffecd1bdfc10703be4cadb1ac64a6eacp-6,
    -0x1.bf31e2p-5,
    0x1.bf1d60p0
  },
  { // Entry 235
    0x1.d93732f77c9157c16887ce5aa762f389p-6,
    0x1.c1aep-5,
    0x1.e66658p0
  },
  { // Entry 236
    -0x1.d93732f77c9157c16887ce5aa762f389p-6,
    -0x1.c1aep-5,
    0x1.e66658p0
  },
  { // Entry 237
    0x1.cea8bcf57199048990f21a209a2d2d3ep-45,
    0x1.c25c26p-44,
    0x1.f263a0p0
  },
  { // Entry 238
    -0x1.cea8bcf57199048990f21a209a2d2d3ep-45,
    -0x1.c25c26p-44,
    0x1.f263a0p0
  },
  { // Entry 239
    0x1.90004702e62bf58fd25e1cb1c208fb8bp-1,
    0x1.c8dcb8p2,
    0x1.ccaa94p2
  },
  { // Entry 240
    -0x1.90004702e62bf58fd25e1cb1c208fb8bp-1,
    -0x1.c8dcb8p2,
    0x1.ccaa94p2
  },
  { // Entry 241
    0x1.fd7c865a3e71ad0d8a724c912f6fb8b9p-4,
    0x1.d64866p-3,
    0x1.d629c0p0
  },
  { // Entry 242
    -0x1.fd7c865a3e71ad0d8a724c912f6fb8b9p-4,
    -0x1.d64866p-3,
    0x1.d629c0p0
  },
  { // Entry 243
    0x1.4aa669000170483715efe0528369e73ep-1,
    0x1.d7011cp0,
    0x1.3880c8p1
  },
  { // Entry 244
    -0x1.4aa669000170483715efe0528369e73ep-1,
    -0x1.d7011cp0,
    0x1.3880c8p1
  },
  { // Entry 245
    0x1.f420e6032da03c581c213d0cc2eacf5bp-2,
    0x1.db6e30p-2,
    0x1.bf62a4p-1
  },
  { // Entry 246
    -0x1.f420e6032da03c581c213d0cc2eacf5bp-2,
    -0x1.db6e30p-2,
    0x1.bf62a4p-1
  },
  { // Entry 247
    0x1.922dc15dd25e294f02361f0292bc0df8p-1,
    0x1.dddddcp-2,
    0x1.ddc3a4p-2
  },
  { // Entry 248
    -0x1.922dc15dd25e294f02361f0292bc0df8p-1,
    -0x1.dddddcp-2,
    0x1.ddc3a4p-2
  },
  { // Entry 249
    0x1.9d6fd902defaede7830883b7a2788da8p-1,
    0x1.de61fcp9,
    0x1.c9b22cp9
  },
  { // Entry 250
    -0x1.9d6fd902defaede7830883b7a2788da8p-1,
    -0x1.de61fcp9,
    0x1.c9b22cp9
  },
  { // Entry 251
    0x1.7ee180ca27095c5506b0fa68e94004d0p-4,
    0x1.dffffep-2,
    0x1.40p2
  },
  { // Entry 252
    -0x1.7ee180ca27095c5506b0fa68e94004d0p-4,
    -0x1.dffffep-2,
    0x1.40p2
  },
  { // Entry 253
    0x1.7d848f000bfaf243f75b3a1218dad94ep0,
    0x1.dffffep2,
    0x1.35c292p-1
  },
  { // Entry 254
    -0x1.7d848f000bfaf243f75b3a1218dad94ep0,
    -0x1.dffffep2,
    0x1.35c292p-1
  },
  { // Entry 255
    0x1.dfffe63601c1383bc54eea3773a4624fp-11,
    0x1.dffffep10,
    0x1.000008p21
  },
  { // Entry 256
    -0x1.dfffe63601c1383bc54eea3773a4624fp-11,
    -0x1.dffffep10,
    0x1.000008p21
  },
  { // Entry 257
    0x1.8f82d1b1443d17b008f18f7822175902p-4,
    0x1.e0f078p-6,
    0x1.333334p-2
  },
  { // Entry 258
    -0x1.8f82d1b1443d17b008f18f7822175902p-4,
    -0x1.e0f078p-6,
    0x1.333334p-2
  },
  { // Entry 259
    0x1.07795d7bc568d7597605f1e44388198ep1,
    0x1.e2be36p-2,
    -0x1.fffffcp-3
  },
  { // Entry 260
    -0x1.07795d7bc568d7597605f1e44388198ep1,
    -0x1.e2be36p-2,
    -0x1.fffffcp-3
  },
  { // Entry 261
    0x1.fff95e57a0b39bb8afc31a89674dc197p-92,
    0x1.e62448p8,
    0x1.e62a94p99
  },
  { // Entry 262
    -0x1.fff95e57a0b39bb8afc31a89674dc197p-92,
    -0x1.e62448p8,
    0x1.e62a94p99
  },
  { // Entry 263
    0x1.0e06f7000a4e54e7181ed79d635dead3p0,
    0x1.e783d4p-1,
    0x1.148cf8p-1
  },
  { // Entry 264
    -0x1.0e06f7000a4e54e7181ed79d635dead3p0,
    -0x1.e783d4p-1,
    0x1.148cf8p-1
  },
  { // Entry 265
    0x1.fea63fbd167cf3f4fa0987d1e28cd75fp-4,
    0x1.e7a55ap-1,
    0x1.e66660p2
  },
  { // Entry 266
    -0x1.fea63fbd167cf3f4fa0987d1e28cd75fp-4,
    -0x1.e7a55ap-1,
    0x1.e66660p2
  },
  { // Entry 267
    0x1.d32abcfffffee42f5ad6cc888072e445p0,
    0x1.ece6d4p0,
    -0x1.p-1
  },
  { // Entry 268
    -0x1.d32abcfffffee42f5ad6cc888072e445p0,
    -0x1.ece6d4p0,
    -0x1.p-1
  },
  { // Entry 269
    0x1.ecac96fad1d02ec25eecde4b7f0b97eap-4,
    0x1.ef1060p-5,
    0x1.p-1
  },
  { // Entry 270
    -0x1.ecac96fad1d02ec25eecde4b7f0b97eap-4,
    -0x1.ef1060p-5,
    0x1.p-1
  },
  { // Entry 271
    0x1.1202c2e6b84549d2bdd30f506adfa9d4p0,
    0x1.f07bd2p9,
    0x1.0f83dcp9
  },
  { // Entry 272
    -0x1.1202c2e6b84549d2bdd30f506adfa9d4p0,
    -0x1.f07bd2p9,
    0x1.0f83dcp9
  },
  { // Entry 273
    0x1.ffe7d9701b27043f401f2771fcff61aap-6,
    0x1.fddffep15,
    0x1.fdcd90p20
  },
  { // Entry 274
    -0x1.ffe7d9701b27043f401f2771fcff61aap-6,
    -0x1.fddffep15,
    0x1.fdcd90p20
  },
  { // Entry 275
    0x1.919c94434fc91fb77041e0d4eaadf614p-1,
    0x1.fefffep-10,
    0x1.0003p-9
  },
  { // Entry 276
    -0x1.919c94434fc91fb77041e0d4eaadf614p-1,
    -0x1.fefffep-10,
    0x1.0003p-9
  },
  { // Entry 277
    0x1.1b57780820085bc0391cbd61b2fd2335p0,
    0x1.ff8ffep-20,
    0x1.000088p-20
  },
  { // Entry 278
    -0x1.1b57780820085bc0391cbd61b2fd2335p0,
    -0x1.ff8ffep-20,
    0x1.000088p-20
  },
  { // Entry 279
    0x1.ff976af6e817ac0b343cc79da075b8a8p-6,
    0x1.ffc0p-139,
    0x1.fffep-134
  },
  { // Entry 280
    -0x1.ff976af6e817ac0b343cc79da075b8a8p-6,
    -0x1.ffc0p-139,
    0x1.fffep-134
  },
  { // Entry 281
    0x1.ff7fc3e4933e894c72260e0533856313p-4,
    0x1.fff77ep-5,
    0x1.fdcd2ep-2
  },
  { // Entry 282
    -0x1.ff7fc3e4933e894c72260e0533856313p-4,
    -0x1.fff77ep-5,
    0x1.fdcd2ep-2
  },
  { // Entry 283
    0x1.ff571a1535e84a3ed0617f7c8bd43c9dp-5,
    0x1.ffffdep-3,
    0x1.fffe7ep1
  },
  { // Entry 284
    -0x1.ff571a1535e84a3ed0617f7c8bd43c9dp-5,
    -0x1.ffffdep-3,
    0x1.fffe7ep1
  },
  { // Entry 285
    0x1.fffffdfffff7ffffdfffff7ffffdffffp-127,
    0x1.fffff6p0,
    0x1.fffff8p126
  },
  { // Entry 286
    -0x1.fffffdfffff7ffffdfffff7ffffdffffp-127,
    -0x1.fffff6p0,
    0x1.fffff8p126
  },
  { // Entry 287
    0x1.ffffec000077fffd05556b3554a0155bp-34,
    0x1.fffff8p-2,
    0x1.000006p32
  },
  { // Entry 288
    -0x1.ffffec000077fffd05556b3554a0155bp-34,
    -0x1.fffff8p-2,
    0x1.000006p32
  },
  { // Entry 289
    0x1.55554fffffffffffffffffffffffffffp-104,
    0x1.fffff8p-127,
    0x1.80p-23
  },
  { // Entry 290
    -0x1.55554fffffffffffffffffffffffffffp-104,
    -0x1.fffff8p-127,
    0x1.80p-23
  },
  { // Entry 291
    0x1.ff54beeda807aa4ec5698ce8cc7dcba8p-2,
    0x1.fffffcp-1,
    0x1.d55552p0
  },
  { // Entry 292
    -0x1.ff54beeda807aa4ec5698ce8cc7dcba8p-2,
    -0x1.fffffcp-1,
    0x1.d55552p0
  },
  { // Entry 293
    0x1.fffff800000fffffe000003fffff80p-129,
    0x1.fffffcp-2,
    0x1.000002p127
  },
  { // Entry 294
    -0x1.fffff800000fffffe000003fffff80p-129,
    -0x1.fffffcp-2,
    0x1.000002p127
  },
  { // Entry 295
    0x1.d7625deb9d3d113e0be1ba5dac42e6c0p-2,
    0x1.fffffcp-2,
    0x1.022228p0
  },
  { // Entry 296
    -0x1.d7625deb9d3d113e0be1ba5dac42e6c0p-2,
    -0x1.fffffcp-2,
    0x1.022228p0
  },
  { // Entry 297
    0x1.0c30b75fc8b0637fcbaf3ed21f47bbd5p-118,
    0x1.fffffcp-122,
    0x1.e8ba40p-4
  },
  { // Entry 298
    -0x1.0c30b75fc8b0637fcbaf3ed21f47bbd5p-118,
    -0x1.fffffcp-122,
    0x1.e8ba40p-4
  },
  { // Entry 299
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-126,
    0x1.p1
  },
  { // Entry 300
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-126,
    0x1.p1
  },
  { // Entry 301
    0x1.f5b748fc32492f9b0e1a9e29c7b40a45p-3,
    0x1.fffffcp20,
    0x1.00000ap23
  },
  { // Entry 302
    -0x1.f5b748fc32492f9b0e1a9e29c7b40a45p-3,
    -0x1.fffffcp20,
    0x1.00000ap23
  },
  { // Entry 303
    0x1.e8009efffc72402f56046bbb3775db7ep-2,
    0x1.6e6d52p-2,
    0x1.62e42ep-1
  },
  { // Entry 304
    -0x1.e8009efffc72402f56046bbb3775db7ep-2,
    -0x1.6e6d52p-2,
    0x1.62e42ep-1
  },
  { // Entry 305
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 306
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 307
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 308
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p0,
    0x1.p0
  },
  { // Entry 309
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 310
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 311
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p0,
    0x1.p0
  },
  { // Entry 312
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 313
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p0,
    0x1.p0
  },
  { // Entry 314
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 315
    0x1.fd5ba9aac2f6dc65912f313e7d111defp-4,
```
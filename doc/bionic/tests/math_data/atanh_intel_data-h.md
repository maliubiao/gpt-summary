Response:
Let's break down the thought process for answering the request about the `atanh_intel_data.handroid` file.

**1. Understanding the Core Request:**

The request asks for a functional description of the provided code snippet, its relation to Android, explanations of relevant libc functions (implicitly `atanh`), dynamic linker aspects (though not directly present in the data file), common usage errors, and how Android frameworks reach this point, concluding with a summarization for part 1.

**2. Initial Analysis of the Code:**

The code defines a static array `g_atanh_intel_data` of type `data_1_1_t<double, double>`. Each element in the array is an initializer list containing two double-precision floating-point numbers. The comment block at the top indicates it's licensed under Apache 2.0 and belongs to the Android Open Source Project. The filename `atanh_intel_data.handroid` strongly suggests this data is used for testing or providing input/output pairs for the `atanh` (inverse hyperbolic tangent) function, specifically on Intel architectures ("intel"). The ".handroid" suffix is likely a convention within the bionic project.

**3. Identifying the Key Function:**

The filename and the context (math_data) immediately point to the `atanh` function as the central piece.

**4. Hypothesizing the Purpose:**

Given the structure of the array (pairs of doubles), the most likely scenario is that the first double in each pair represents an *input* value for the `atanh` function, and the second double represents the *expected output*. This is a standard practice for creating test data for mathematical functions.

**5. Connecting to Android:**

Since the file is part of bionic (Android's C library), it directly relates to how Android implements fundamental C library functions. Specifically, this data is used to test the correctness of the `atanh` implementation in bionic. This is crucial for the stability and reliability of Android as many higher-level functionalities rely on correct mathematical operations.

**6. Addressing the libc Function Explanation:**

The request explicitly asks for an explanation of the `libc` function. Here's the thinking process:

* **Identify the relevant function:** It's `atanh`.
* **Recall its definition:** The inverse hyperbolic tangent.
* **Explain the mathematical formula:**  `atanh(x) = 0.5 * ln((1 + x) / (1 - x))`.
* **Mention domain restrictions:**  -1 < x < 1.
* **Describe its purpose:** To find the value whose hyperbolic tangent is the input.
* **Consider potential uses in Android:** Examples include signal processing, machine learning, and graphics, though the data file itself is more about *testing* the implementation than demonstrating direct usage in a specific Android feature.

**7. Dynamic Linker Aspects:**

The provided file is just data. It doesn't contain executable code. Therefore, there are no direct dynamic linking aspects *within this file itself*. However, to address the request, it's important to explain *how* the `atanh` function (which this data supports) gets linked:

* **Identify the relevant SO:**  `libm.so` (the math library in Android).
* **Describe the typical SO layout:**  `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), symbol tables, etc.
* **Explain the linking process:**  When an app uses `atanh`, the dynamic linker finds `libm.so`, resolves the `atanh` symbol, and makes the function available to the app.

**8. Logic and Input/Output Examples:**

Since the file *is* the input/output data, concrete examples are easy to derive directly from the array:

* **Input:** `-0x1.p-1074` (a very small negative number)
* **Output:** `-0x1.0p-1074` (a very small negative number, approximately equal to the input for small values near 0).
* **Input:** `0.5`
* **Output:**  Calculate using the formula or look up a nearby value in the data. This demonstrates the testing nature of the data.

**9. Common Usage Errors:**

The most common error when using `atanh` is providing an input outside the valid domain (-1 < x < 1). This will result in `NaN` (Not a Number).

**10. Android Framework/NDK to this Point:**

This requires tracing the execution path:

* **Application uses `atanh`:**  An app calls a math function.
* **NDK (if used):**  The NDK provides headers and libraries for native development.
* **`libc` (bionic):** The call is routed to bionic's `atanh` implementation.
* **Testing:** The `atanh` implementation *might* use data like this for internal checks or during development. It's more likely this data is used in separate *test suites*.
* **Frida Hooking:**  Demonstrate how to hook the `atanh` function using Frida to intercept calls and examine arguments and results.

**11. Summarization for Part 1:**

Finally, condense the key findings: The file provides test data for the `atanh` function in Android's bionic library. It's a collection of input/output pairs used to verify the correctness of the implementation.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Could this data be used for optimization? While possible, the structure strongly suggests testing.
* **Clarification:** The dynamic linker isn't directly *in* this data file, but the function this data tests *is* linked dynamically. Need to clarify the relationship.
* **Example selection:** Choose input values that illustrate different scenarios (near zero, closer to the boundaries).
* **Frida Hooking specifics:** Ensure the example is clear and targets the correct function.

By following this structured approach, the comprehensive and accurate answer can be generated. The key is to connect the specific code snippet to the broader context of Android's architecture and development practices.
## 对 bionic/tests/math_data/atanh_intel_data.handroid 的功能归纳 (第 1 部分)

基于提供的代码片段，`bionic/tests/math_data/atanh_intel_data.handroid` 文件主要的功能是：

**1. 提供 `atanh` 函数的测试数据:**

   - 该文件定义了一个名为 `g_atanh_intel_data` 的静态数组，其元素类型为 `data_1_1_t<double, double>`。
   - 每个数组元素都包含一对 `double` 类型的数值。
   - **推测:** 结合文件名 `atanh` 和路径 `tests/math_data`，可以推断出这对数值很可能是一组 `atanh` 函数的 **输入值 (input)** 和对应的 **期望输出值 (expected output)**。

**2. 用于验证 `atanh` 函数在特定平台 (Intel) 上的实现是否正确:**

   - 文件名中包含 `intel_data`，表明这些测试数据可能是针对 Intel 架构的 `atanh` 函数实现的。
   - 这种针对特定平台的测试数据可以确保在不同的硬件架构上，`atanh` 函数的精度和正确性都能得到保证。
   - **假设输入与输出:** 例如，数组中的第一个元素 `{ -0x1.p-1074, -0x1.0p-1074 }`，假设 `-0x1.p-1074` 作为 `atanh` 函数的输入，那么期望的输出结果是 `-0x1.0p-1074`。

**3. 构成 bionic Math 库测试套件的一部分:**

   - 文件路径 `bionic/tests/math_data` 清晰地表明该文件是 Android Bionic 库中数学库测试的一部分。
   - 这些测试数据被用于自动化测试，以确保 bionic 库提供的 `atanh` 函数符合标准和预期。

**总结:**

总而言之，`bionic/tests/math_data/atanh_intel_data.handroid` 文件的核心功能是 **作为测试数据，用于验证 Android Bionic 库中 `atanh` 函数在 Intel 架构上的实现是否正确**。它提供了一系列预定义的输入和期望输出，是 bionic 数学库质量保证的关键组成部分。

---

接下来，我们继续分析后续部分的代码，才能更完整地了解其功能。

Prompt: 
```
这是目录为bionic/tests/math_data/atanh_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

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

static data_1_1_t<double, double> g_atanh_intel_data[] = {
  { // Entry 0
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 1
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 2
    -0x1.33c537256ac26ea1b8865a026e72c752p-1,
    -0x1.136p-1
  },
  { // Entry 3
    0x1.33c537256ac26ea1b8865a026e72c752p-1,
    0x1.136p-1
  },
  { // Entry 4
    -0x1.44767fdc853773ecd65b43b0efd1f8d6p-1,
    -0x1.1f07c1f07c1f4p-1
  },
  { // Entry 5
    0x1.44767fdc853773ecd65b43b0efd1f8d6p-1,
    0x1.1f07c1f07c1f4p-1
  },
  { // Entry 6
    -0x1.7761ddbd0573b7ff1d51e300bdb439bep-1,
    -0x1.400000010p-1
  },
  { // Entry 7
    0x1.7761ddbd0573b7ff1d51e300bdb439bep-1,
    0x1.400000010p-1
  },
  { // Entry 8
    -0x1.6259494a4bb397ff89dd84b74e230f31p-2,
    -0x1.54d9d811468c2p-2
  },
  { // Entry 9
    0x1.6259494a4bb397ff89dd84b74e230f31p-2,
    0x1.54d9d811468c2p-2
  },
  { // Entry 10
    -0x1.6719a6fbfef1d7fc326d067903183cddp-2,
    -0x1.5911c3a70cebdp-2
  },
  { // Entry 11
    0x1.6719a6fbfef1d7fc326d067903183cddp-2,
    0x1.5911c3a70cebdp-2
  },
  { // Entry 12
    -0x1.ad75b9841b24e264875483def1610c01p-1,
    -0x1.5ece354ff80a2p-1
  },
  { // Entry 13
    0x1.ad75b9841b24e264875483def1610c01p-1,
    0x1.5ece354ff80a2p-1
  },
  { // Entry 14
    -0x1.c08e6aa55e4172db4c413132b24283edp-1,
    -0x1.68ae1ca8f6ad6p-1
  },
  { // Entry 15
    0x1.c08e6aa55e4172db4c413132b24283edp-1,
    0x1.68ae1ca8f6ad6p-1
  },
  { // Entry 16
    -0x1.d6f10a7081e7ecc4a2d3d9e2371d1cb0p-1,
    -0x1.739ce739ce73cp-1
  },
  { // Entry 17
    0x1.d6f10a7081e7ecc4a2d3d9e2371d1cb0p-1,
    0x1.739ce739ce73cp-1
  },
  { // Entry 18
    -0x1.862796317ed3d7fcb8bec742b2ea5c0bp-2,
    -0x1.744f8613c514bp-2
  },
  { // Entry 19
    0x1.862796317ed3d7fcb8bec742b2ea5c0bp-2,
    0x1.744f8613c514bp-2
  },
  { // Entry 20
    -0x1.8027fe496eaad0006a3df4a7cfc399bap-5,
    -0x1.7fdff7fffffffp-5
  },
  { // Entry 21
    0x1.8027fe496eaad0006a3df4a7cfc399bap-5,
    0x1.7fdff7fffffffp-5
  },
  { // Entry 22
    -0x1.80602a138a48e581b7bf0a1d1f84769fp-10,
    -0x1.8060180601ff6p-10
  },
  { // Entry 23
    0x1.80602a138a48e581b7bf0a1d1f84769fp-10,
    0x1.8060180601ff6p-10
  },
  { // Entry 24
    -0x1.9f323ecbf984c5d61382119eafcddf36p-3,
    -0x1.999999999999ap-3
  },
  { // Entry 25
    0x1.9f323ecbf984c5d61382119eafcddf36p-3,
    0x1.999999999999ap-3
  },
  { // Entry 26
    -0x1.b7c54f4582a8f52cb0434b624cb3140bp-2,
    -0x1.9e9703735f652p-2
  },
  { // Entry 27
    0x1.b7c54f4582a8f52cb0434b624cb3140bp-2,
    0x1.9e9703735f652p-2
  },
  { // Entry 28
    -0x1.ac44a1f923250f86e06d88e6919a1a4fp-24,
    -0x1.ac44a1f923238p-24
  },
  { // Entry 29
    0x1.ac44a1f923250f86e06d88e6919a1a4fp-24,
    0x1.ac44a1f923238p-24
  },
  { // Entry 30
    -0x1.cee62c51688218abca36efcf5f6add63p-2,
    -0x1.b1bfa1c2ff5c8p-2
  },
  { // Entry 31
    0x1.cee62c51688218abca36efcf5f6add63p-2,
    0x1.b1bfa1c2ff5c8p-2
  },
  { // Entry 32
    -0x1.b4c1183827d4a805d64de6f870cd6888p-5,
    -0x1.b45746fb45980p-5
  },
  { // Entry 33
    0x1.b4c1183827d4a805d64de6f870cd6888p-5,
    0x1.b45746fb45980p-5
  },
  { // Entry 34
    -0x1.cd1ce8658f1e27f929bb26f71cf39ep-3,
    -0x1.c579d4043e054p-3
  },
  { // Entry 35
    0x1.cd1ce8658f1e27f929bb26f71cf39ep-3,
    0x1.c579d4043e054p-3
  },
  { // Entry 36
    -0x1.f4b9755f2c26e7fc906b87927f3076ecp-2,
    -0x1.d04b9bb0bda28p-2
  },
  { // Entry 37
    0x1.f4b9755f2c26e7fc906b87927f3076ecp-2,
    0x1.d04b9bb0bda28p-2
  },
  { // Entry 38
    -0x1.d49dd5cd8086d7fe196df1da63aadaf9p-4,
    -0x1.d29523bb69328p-4
  },
  { // Entry 39
    0x1.d49dd5cd8086d7fe196df1da63aadaf9p-4,
    0x1.d29523bb69328p-4
  },
  { // Entry 40
    -0x1.f7f60ac95611e75a2a085f35a7c508dcp-2,
    -0x1.d2dce780a7304p-2
  },
  { // Entry 41
    0x1.f7f60ac95611e75a2a085f35a7c508dcp-2,
    0x1.d2dce780a7304p-2
  },
  { // Entry 42
    -0x1.df875eb326b209b9c9a00f82e3dbc3bap-3,
    -0x1.d6f41e3ea643ap-3
  },
  { // Entry 43
    0x1.df875eb326b209b9c9a00f82e3dbc3bap-3,
    0x1.d6f41e3ea643ap-3
  },
  { // Entry 44
    -0x1.fe0dc4fabe81f72d042d459cdb17f7c5p-2,
    -0x1.d7ad1055ed587p-2
  },
  { // Entry 45
    0x1.fe0dc4fabe81f72d042d459cdb17f7c5p-2,
    0x1.d7ad1055ed587p-2
  },
  { // Entry 46
    -0x1.ede7fef85615d5762723a4bc9071bcfcp-4,
    -0x1.eb86b85bf65d8p-4
  },
  { // Entry 47
    0x1.ede7fef85615d5762723a4bc9071bcfcp-4,
    0x1.eb86b85bf65d8p-4
  },
  { // Entry 48
    -0x1.ffff0f05db419e0562a8a13e0c88ec0cp-3,
    -0x1.f59707e3f49d0p-3
  },
  { // Entry 49
    0x1.ffff0f05db419e0562a8a13e0c88ec0cp-3,
    0x1.f59707e3f49d0p-3
  },
  { // Entry 50
    -0x1.340af764783edfffac199b0ebf01c362p1,
    -0x1.f7cp-1
  },
  { // Entry 51
    0x1.340af764783edfffac199b0ebf01c362p1,
    0x1.f7cp-1
  },
  { // Entry 52
    -0x1.fc0000000000000000000000029aca95p-52,
    -0x1.fc0p-52
  },
  { // Entry 53
    0x1.fc0000000000000000000000029aca95p-52,
    0x1.fc0p-52
  },
  { // Entry 54
    -0x1.fdc93ea04e6030021bf3b7f1b7274addp-5,
    -0x1.fd210af77856cp-5
  },
  { // Entry 55
    0x1.fdc93ea04e6030021bf3b7f1b7274addp-5,
    0x1.fd210af77856cp-5
  },
  { // Entry 56
    -0x1.ffeaa91115a4e8716dc9f09be20a9364p-7,
    -0x1.ffep-7
  },
  { // Entry 57
    0x1.ffeaa91115a4e8716dc9f09be20a9364p-7,
    0x1.ffep-7
  },
  { // Entry 58
    -0x1.9a775e687850d877587114f931f61369p3,
    -0x1.ffffffffe03edp-1
  },
  { // Entry 59
    0x1.9a775e687850d877587114f931f61369p3,
    0x1.ffffffffe03edp-1
  },
  { // Entry 60
    -0x1.9ba863fb6bf8e791c8099e55cff570c3p3,
    -0x1.ffffffffe2863p-1
  },
  { // Entry 61
    0x1.9ba863fb6bf8e791c8099e55cff570c3p3,
    0x1.ffffffffe2863p-1
  },
  { // Entry 62
    -0x1.f369d8eedfbb384b0ee31be424423ec2p3,
    -0x1.ffffffffffe0bp-1
  },
  { // Entry 63
    0x1.f369d8eedfbb384b0ee31be424423ec2p3,
    0x1.ffffffffffe0bp-1
  },
  { // Entry 64
    -0x1.02bd22bd19797815b1ddefc90c41f8fbp4,
    -0x1.fffffffffff5ep-1
  },
  { // Entry 65
    0x1.02bd22bd19797815b1ddefc90c41f8fbp4,
    0x1.fffffffffff5ep-1
  },
  { // Entry 66
    -0x1.1841a4bab2d6d03a28537f43de9e90a4p4,
    -0x1.ffffffffffff5p-1
  },
  { // Entry 67
    0x1.1841a4bab2d6d03a28537f43de9e90a4p4,
    0x1.ffffffffffff5p-1
  },
  { // Entry 68
    0x1.p-99,
    0x1.0p-99
  },
  { // Entry 69
    -0x1.p-99,
    -0x1.0p-99
  },
  { // Entry 70
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 71
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 72
    0x1.00000000000010000000155555555555p-41,
    0x1.0000000000001p-41
  },
  { // Entry 73
    -0x1.00000000000010000000155555555555p-41,
    -0x1.0000000000001p-41
  },
  { // Entry 74
    0x1.015891c9eaefd81f5edb9583f3871889p-3,
    0x1.0000000000006p-3
  },
  { // Entry 75
    -0x1.015891c9eaefd81f5edb9583f3871889p-3,
    -0x1.0000000000006p-3
  },
  { // Entry 76
    0x1.193ea7aad0313ecbf96ee2aa7057ee7cp-1,
    0x1.0000000000007p-1
  },
  { // Entry 77
    -0x1.193ea7aad0313ecbf96ee2aa7057ee7cp-1,
    -0x1.0000000000007p-1
  },
  { // Entry 78
    0x1.000555888ad4c9be103a862dcf933db6p-6,
    0x1.0000000000030p-6
  },
  { // Entry 79
    -0x1.000555888ad4c9be103a862dcf933db6p-6,
    -0x1.0000000000030p-6
  },
  { // Entry 80
    0x1.0000055555a8988cd2ad575377ece0d7p-10,
    0x1.0000000000201p-10
  },
  { // Entry 81
    -0x1.0000055555a8988cd2ad575377ece0d7p-10,
    -0x1.0000000000201p-10
  },
  { // Entry 82
    0x1.015891c9f107d81f5edc2a1f85d03e57p-3,
    0x1.00000000060p-3
  },
  { // Entry 83
    -0x1.015891c9f107d81f5edc2a1f85d03e57p-3,
    -0x1.00000000060p-3
  },
  { // Entry 84
    0x1.005588ad597cefed3539549b86ce2b1bp-4,
    0x1.00000000220p-4
  },
  { // Entry 85
    -0x1.005588ad597cefed3539549b86ce2b1bp-4,
    -0x1.00000000220p-4
  },
  { // Entry 86
    0x1.0000055577888aaad1cf378dd5b4caa3p-10,
    0x1.00000000220p-10
  },
  { // Entry 87
    -0x1.0000055577888aaad1cf378dd5b4caa3p-10,
    -0x1.00000000220p-10
  },
  { // Entry 88
    0x1.193ea7fca06d7000000fd6e3e45036c3p-1,
    0x1.0000003d5c2d9p-1
  },
  { // Entry 89
    -0x1.193ea7fca06d7000000fd6e3e45036c3p-1,
    -0x1.0000003d5c2d9p-1
  },
  { // Entry 90
    0x1.0158920aeeffb7df62fc5f72d05afc8ap-3,
    0x1.0000004p-3
  },
  { // Entry 91
    -0x1.0158920aeeffb7df62fc5f72d05afc8ap-3,
    -0x1.0000004p-3
  },
  { // Entry 92
    0x1.015894d61bb2a7f0ee6532fa66c13887p-3,
    0x1.0000030p-3
  },
  { // Entry 93
    -0x1.015894d61bb2a7f0ee6532fa66c13887p-3,
    -0x1.0000030p-3
  },
  { // Entry 94
    0x1.00255c8a5b4f98134613c6ae100b17d2p-5,
    0x1.001p-5
  },
  { // Entry 95
    -0x1.00255c8a5b4f98134613c6ae100b17d2p-5,
    -0x1.001p-5
  },
  { // Entry 96
    0x1.199403c895f3b2fbd6e04ef63e5e0b99p-1,
    0x1.003fffcp-1
  },
  { // Entry 97
    -0x1.199403c895f3b2fbd6e04ef63e5e0b99p-1,
    -0x1.003fffcp-1
  },
  { // Entry 98
    0x1.00401004000480000000000005595756p-50,
    0x1.0040100400048p-50
  },
  { // Entry 99
    -0x1.00401004000480000000000005595756p-50,
    -0x1.0040100400048p-50
  },
  { // Entry 100
    0x1.00b5e931e4c3080916948fa283902fa8p-4,
    0x1.006p-4
  },
  { // Entry 101
    -0x1.00b5e931e4c3080916948fa283902fa8p-4,
    -0x1.006p-4
  },
  { // Entry 102
    0x1.021c8577650fa41d24281561edcb1273p-10,
    0x1.021c8p-10
  },
  { // Entry 103
    -0x1.021c8577650fa41d24281561edcb1273p-10,
    -0x1.021c8p-10
  },
  { // Entry 104
    0x1.03858e51088d27f9df83774139563f2cp-6,
    0x1.038p-6
  },
  { // Entry 105
    -0x1.03858e51088d27f9df83774139563f2cp-6,
    -0x1.038p-6
  },
  { // Entry 106
    0x1.1e9b2fd18d91b42e390d13e9beb6978cp-1,
    0x1.040p-1
  },
  { // Entry 107
    -0x1.1e9b2fd18d91b42e390d13e9beb6978cp-1,
    -0x1.040p-1
  },
  { // Entry 108
    0x1.0841776c420d4707689f45329a9bf2cep-7,
    0x1.084p-7
  },
  { // Entry 109
    -0x1.0841776c420d4707689f45329a9bf2cep-7,
    -0x1.084p-7
  },
  { // Entry 110
    0x1.37ed416dfaf6747b307bee589157fe93p-1,
    0x1.1650efedb9eb2p-1
  },
  { // Entry 111
    -0x1.37ed416dfaf6747b307bee589157fe93p-1,
    -0x1.1650efedb9eb2p-1
  },
  { // Entry 112
    0x1.45e1141a8c00e0b0eb767eb3382f20b8p-1,
    0x1.1ffffffffffffp-1
  },
  { // Entry 113
    -0x1.45e1141a8c00e0b0eb767eb3382f20b8p-1,
    -0x1.1ffffffffffffp-1
  },
  { // Entry 114
    0x1.45e1141a8c00f818c85ab35ce89683a2p-1,
    0x1.2p-1
  },
  { // Entry 115
    -0x1.45e1141a8c00f818c85ab35ce89683a2p-1,
    -0x1.2p-1
  },
  { // Entry 116
    0x1.2e223119d32f870a129b78a196ee4c8dp-7,
    0x1.2e2p-7
  },
  { // Entry 117
    -0x1.2e223119d32f870a129b78a196ee4c8dp-7,
    -0x1.2e2p-7
  },
  { // Entry 118
    0x1.600c9c6f70efcd85cd16189ee688ead0p-1,
    0x1.316p-1
  },
  { // Entry 119
    -0x1.600c9c6f70efcd85cd16189ee688ead0p-1,
    -0x1.316p-1
  },
  { // Entry 120
    0x1.3b5afc2b8cfd87f655c91414c5969d60p-2,
    0x1.31cp-2
  },
  { // Entry 121
    -0x1.3b5afc2b8cfd87f655c91414c5969d60p-2,
    -0x1.31cp-2
  },
  { // Entry 122
    0x1.62e4307128100800001f7881babc44f3p-1,
    0x1.3333338617529p-1
  },
  { // Entry 123
    -0x1.62e4307128100800001f7881babc44f3p-1,
    -0x1.3333338617529p-1
  },
  { // Entry 124
    0x1.33aef545bb20968537b09375e6d5c60ap-7,
    0x1.33aca4ae2b081p-7
  },
  { // Entry 125
    -0x1.33aef545bb20968537b09375e6d5c60ap-7,
    -0x1.33aca4ae2b081p-7
  },
  { // Entry 126
    0x1.9c5cfbb889a7419fe7705e893b99fbb5p-1,
    0x1.5586ad8669418p-1
  },
  { // Entry 127
    -0x1.9c5cfbb889a7419fe7705e893b99fbb5p-1,
    -0x1.5586ad8669418p-1
  },
  { // Entry 128
    0x1.9d5e0765d3182e417e4d91808f30b95fp-1,
    0x1.56152a51dda72p-1
  },
  { // Entry 129
    -0x1.9d5e0765d3182e417e4d91808f30b95fp-1,
    -0x1.56152a51dda72p-1
  },
  { // Entry 130
    0x1.9d783af9f97bce33bd221a9954befb0cp-1,
    0x1.5623ab271fa52p-1
  },
  { // Entry 131
    -0x1.9d783af9f97bce33bd221a9954befb0cp-1,
    -0x1.5623ab271fa52p-1
  },
  { // Entry 132
    0x1.56a0f0b4476de80270a6332ff4450533p-5,
    0x1.566dd4892fab9p-5
  },
  { // Entry 133
    -0x1.56a0f0b4476de80270a6332ff4450533p-5,
    -0x1.566dd4892fab9p-5
  },
  { // Entry 134
    0x1.5db43aa0e3e55fffa5ad9886e8f22cb8p-3,
    0x1.5a582cdc4e9d4p-3
  },
  { // Entry 135
    -0x1.5db43aa0e3e55fffa5ad9886e8f22cb8p-3,
    -0x1.5a582cdc4e9d4p-3
  },
  { // Entry 136
    0x1.ab9dfa0ec89b8247c03f70d6fccdfd66p-1,
    0x1.5dd34e7af8d61p-1
  },
  { // Entry 137
    -0x1.ab9dfa0ec89b8247c03f70d6fccdfd66p-1,
    -0x1.5dd34e7af8d61p-1
  },
  { // Entry 138
    0x1.67a648e5b16c6a6999d9665a8c288d27p-8,
    0x1.67a55c49aa5d6p-8
  },
  { // Entry 139
    -0x1.67a648e5b16c6a6999d9665a8c288d27p-8,
    -0x1.67a55c49aa5d6p-8
  },
  { // Entry 140
    0x1.7b57ee7bea57a7fcebaaea6f557706c2p-2,
    0x1.6ae491f70c7cbp-2
  },
  { // Entry 141
    -0x1.7b57ee7bea57a7fcebaaea6f557706c2p-2,
    -0x1.6ae491f70c7cbp-2
  },
  { // Entry 142
    0x1.7222b50fd4f8ce0954e89313933bded3p-3,
    0x1.6e2856e2856f5p-3
  },
  { // Entry 143
    -0x1.7222b50fd4f8ce0954e89313933bded3p-3,
    -0x1.6e2856e2856f5p-3
  },
  { // Entry 144
    0x1.cf6347191f5b5aba22dc8400fa882ceep-1,
    0x1.7p-1
  },
  { // Entry 145
    -0x1.cf6347191f5b5aba22dc8400fa882ceep-1,
    -0x1.7p-1
  },
  { // Entry 146
    0x1.83916f868284f882ad9463d174a59d97p-2,
    0x1.721060c1a73cep-2
  },
  { // Entry 147
    -0x1.83916f868284f882ad9463d174a59d97p-2,
    -0x1.721060c1a73cep-2
  },
  { // Entry 148
    0x1.85e0806e8e13b7fcc08479529c8104e6p-2,
    0x1.7411d463bfe90p-2
  },
  { // Entry 149
    -0x1.85e0806e8e13b7fcc08479529c8104e6p-2,
    -0x1.7411d463bfe90p-2
  },
  { // Entry 150
    0x1.f2272af46bbe08000012b87d08e7932fp-1,
    0x1.800000078eaacp-1
  },
  { // Entry 151
    -0x1.f2272af46bbe08000012b87d08e7932fp-1,
    -0x1.800000078eaacp-1
  },
  { // Entry 152
    0x1.f2272af46bbf0800001fad0fd766e8cfp-1,
    0x1.800000078eab3p-1
  },
  { // Entry 153
    -0x1.f2272af46bbf0800001fad0fd766e8cfp-1,
    -0x1.800000078eab3p-1
  },
  { // Entry 154
    0x1.83e4a353f34f3562d9d23f45dc8b2e29p-7,
    0x1.83ep-7
  },
  { // Entry 155
    -0x1.83e4a353f34f3562d9d23f45dc8b2e29p-7,
    -0x1.83ep-7
  },
  { // Entry 156
    0x1.89b541d1b39fa30a054d69c38ffbdb5ep-4,
    0x1.888p-4
  },
  { // Entry 157
    -0x1.89b541d1b39fa30a054d69c38ffbdb5ep-4,
    -0x1.888p-4
  },
  { // Entry 158
    0x1.8a08c32ee13cd9422b9ad12f398f50bbp-8,
    0x1.8a078c03f8dcep-8
  },
  { // Entry 159
    -0x1.8a08c32ee13cd9422b9ad12f398f50bbp-8,
    -0x1.8a078c03f8dcep-8
  },
  { // Entry 160
    0x1.946669a6bba909c4bc5da852e75a3d66p-8,
    0x1.9465194651941p-8
  },
  { // Entry 161
    -0x1.946669a6bba909c4bc5da852e75a3d66p-8,
    -0x1.9465194651941p-8
  },
  { // Entry 162
    0x1.9c7d184ac6505eee21ace6732a52730cp-3,
    0x1.970p-3
  },
  { // Entry 163
    -0x1.9c7d184ac6505eee21ace6732a52730cp-3,
    -0x1.970p-3
  },
  { // Entry 164
    0x1.98da3c40000e9801ec829a13899425ecp-4,
    0x1.978p-4
  },
  { // Entry 165
    -0x1.98da3c40000e9801ec829a13899425ecp-4,
    -0x1.978p-4
  },
  { // Entry 166
    0x1.9af93cdc56240000000fff41a04220ffp-4,
    0x1.999999a3a18c2p-4
  },
  { // Entry 167
    -0x1.9af93cdc56240000000fff41a04220ffp-4,
    -0x1.999999a3a18c2p-4
  },
  { // Entry 168
    0x1.9af93cdc566f000000197f297a13895cp-4,
    0x1.999999a3a1d66p-4
  },
  { // Entry 169
    -0x1.9af93cdc566f000000197f297a13895cp-4,
    -0x1.999999a3a1d66p-4
  },
  { // Entry 170
    0x1.193ea7fa8d771fffffe6de660aab4045p0,
    0x1.999999d303287p-1
  },
  { // Entry 171
    -0x1.193ea7fa8d771fffffe6de660aab4045p0,
    -0x1.999999d303287p-1
  },
  { // Entry 172
    0x1.9af93d0c9ef7d80000017b97c0c0930cp-4,
    0x1.999999d36ec44p-4
  },
  { // Entry 173
    -0x1.9af93d0c9ef7d80000017b97c0c0930cp-4,
    -0x1.999999d36ec44p-4
  },
  { // Entry 174
    0x1.9f323f7638726800001eda3701a5c338p-3,
    0x1.99999a3d09361p-3
  },
  { // Entry 175
    -0x1.9f323f7638726800001eda3701a5c338p-3,
    -0x1.99999a3d09361p-3
  },
  { // Entry 176
    0x1.9f323fd47175b7ffffe05fbf960efc6ap-3,
    0x1.99999a977d623p-3
  },
  { // Entry 177
    -0x1.9f323fd47175b7ffffe05fbf960efc6ap-3,
    -0x1.99999a977d623p-3
  },
  { // Entry 178
    0x1.9f323fe10c9a1800001efbbe0bb48ebbp-3,
    0x1.99999aa39770ap-3
  },
  { // Entry 179
    -0x1.9f323fe10c9a1800001efbbe0bb48ebbp-3,
    -0x1.99999aa39770ap-3
  },
  { // Entry 180
    0x1.9a179be1e7a6e801a0cbc1770ccc0691p-5,
    0x1.99cp-5
  },
  { // Entry 181
    -0x1.9a179be1e7a6e801a0cbc1770ccc0691p-5,
    -0x1.99cp-5
  },
  { // Entry 182
    0x1.a5256971dc6e440698f25410f9a508ffp-10,
    0x1.a52551b31353cp-10
  },
  { // Entry 183
    -0x1.a5256971dc6e440698f25410f9a508ffp-10,
    -0x1.a52551b31353cp-10
  },
  { // Entry 184
    0x1.ad6df00c82cd92c93177514dd245567bp-24,
    0x1.ad6df00c82cc0p-24
  },
  { // Entry 185
    -0x1.ad6df00c82cd92c93177514dd245567bp-24,
    -0x1.ad6df00c82cc0p-24
  },
  { // Entry 186
    0x1.aec648950aa9b6160bf45bf45b2ce0bep-8,
    0x1.aec4b201aa53bp-8
  },
  { // Entry 187
    -0x1.aec648950aa9b6160bf45bf45b2ce0bep-8,
    -0x1.aec4b201aa53bp-8
  },
  { // Entry 188
    0x1.b6cabb35f338f7fb83223470c9fbfb09p-3,
    0x1.b032e138a539dp-3
  },
  { // Entry 189
    -0x1.b6cabb35f338f7fb83223470c9fbfb09p-3,
    -0x1.b032e138a539dp-3
  },
  { // Entry 190
    0x1.d6f4c64bee95d884b07a53fe12d571f4p-2,
    0x1.b85680001c332p-2
  },
  { // Entry 191
    -0x1.d6f4c64bee95d884b07a53fe12d571f4p-2,
    -0x1.b85680001c332p-2
  },
  { // Entry 192
    0x1.c184b5fbed8192fa453d4d9c1577a9e3p-10,
    0x1.c184991bf2fp-10
  },
  { // Entry 193
    -0x1.c184b5fbed8192fa453d4d9c1577a9e3p-10,
    -0x1.c184991bf2fp-10
  },
  { // Entry 194
    0x1.e71d3517d3e01b42d5dae4c3aaf70503p-2,
    0x1.c56b0b96cdf91p-2
  },
  { // Entry 195
    -0x1.e71d3517d3e01b42d5dae4c3aaf70503p-2,
    -0x1.c56b0b96cdf91p-2
  },
  { // Entry 196
    0x1.c5e0000001db8fffed2e2b94fd54870dp-20,
    0x1.c5ep-20
  },
  { // Entry 197
    -0x1.c5e0000001db8fffed2e2b94fd54870dp-20,
    -0x1.c5ep-20
  },
  { // Entry 198
    0x1.f055451fb359e7fffffbe5195d4377e8p-2,
    0x1.ccccccd660083p-2
  },
  { // Entry 199
    -0x1.f055451fb359e7fffffbe5195d4377e8p-2,
    -0x1.ccccccd660083p-2
  },
  { // Entry 200
    0x1.f1c704e1f3c8a800b71131c90e193596p-2,
    0x1.cdf37cdf37cd9p-2
  },
  { // Entry 201
    -0x1.f1c704e1f3c8a800b71131c90e193596p-2,
    -0x1.cdf37cdf37cd9p-2
  },
  { // Entry 202
    0x1.d00a0587151948029cb1fb36b2a24903p-5,
    0x1.cf8b2052bbb11p-5
  },
  { // Entry 203
    -0x1.d00a0587151948029cb1fb36b2a24903p-5,
    -0x1.cf8b2052bbb11p-5
  },
  { // Entry 204
    0x1.f4656a69bea6d733e8f3dfaec12111c3p-2,
    0x1.d008d55f75360p-2
  },
  { // Entry 205
    -0x1.f4656a69bea6d733e8f3dfaec12111c3p-2,
    -0x1.d008d55f75360p-2
  },
  { // Entry 206
    0x1.d0cad6adc9a0c837bbecea984e9019d7p-5,
    0x1.d04b532bd5b41p-5
  },
  { // Entry 207
    -0x1.d0cad6adc9a0c837bbecea984e9019d7p-5,
    -0x1.d04b532bd5b41p-5
  },
  { // Entry 208
    0x1.f62f40794a7b089973231ae614553eb0p-2,
    0x1.d1745d1745d11p-2
  },
  { // Entry 209
    -0x1.f62f40794a7b089973231ae614553eb0p-2,
    -0x1.d1745d1745d11p-2
  },
  { // Entry 210
    0x1.d1c00000008077fe5d003fc8ce63e4a4p-21,
    0x1.d1cp-21
  },
  { // Entry 211
    -0x1.d1c00000008077fe5d003fc8ce63e4a4p-21,
    -0x1.d1cp-21
  },
  { // Entry 212
    0x1.f6beddb6ec29b749a9e4a3f67a36b414p-2,
    0x1.d1e646f156570p-2
  },
  { // Entry 213
    -0x1.f6beddb6ec29b749a9e4a3f67a36b414p-2,
    -0x1.d1e646f156570p-2
  },
  { // Entry 214
    0x1.fabc7c84166033eb57a453fd83585dc8p-2,
    0x1.d50efa205a174p-2
  },
  { // Entry 215
    -0x1.fabc7c84166033eb57a453fd83585dc8p-2,
    -0x1.d50efa205a174p-2
  },
  { // Entry 216
    0x1.d62f43b4c2c737fdd232cf2e299076f7p-11,
    0x1.d62f3b71fca8cp-11
  },
  { // Entry 217
    -0x1.d62f43b4c2c737fdd232cf2e299076f7p-11,
    -0x1.d62f3b71fca8cp-11
  },
  { // Entry 218
    0x1.e3a4b468f251480a6049e3fe17b89646p-5,
    0x1.e3150daedb476p-5
  },
  { // Entry 219
    -0x1.e3a4b468f251480a6049e3fe17b89646p-5,
    -0x1.e3150daedb476p-5
  },
  { // Entry 220
    0x1.e68e0c2de6d2280c8a117c4d61d8f42fp-5,
    0x1.e5fbc9eecbdaep-5
  },
  { // Entry 221
    -0x1.e68e0c2de6d2280c8a117c4d61d8f42fp-5,
    -0x1.e5fbc9eecbdaep-5
  },
  { // Entry 222
    0x1.e9de86e8fd3be801a9f830844ba5e501p-5,
    0x1.e9494303cd80fp-5
  },
  { // Entry 223
    -0x1.e9de86e8fd3be801a9f830844ba5e501p-5,
    -0x1.e9494303cd80fp-5
  },
  { // Entry 224
    0x1.edbcc82a00a4c001e7ac01891849800ep-5,
    0x1.ed23f4c89da70p-5
  },
  { // Entry 225
    -0x1.edbcc82a00a4c001e7ac01891849800ep-5,
    -0x1.ed23f4c89da70p-5
  },
  { // Entry 226
    0x1.fa0dc9d7131fee2b38ba993a65f82a06p-3,
    0x1.effffffffffffp-3
  },
  { // Entry 227
    -0x1.fa0dc9d7131fee2b38ba993a65f82a06p-3,
    -0x1.effffffffffffp-3
  },
  { // Entry 228
    0x1.f37429af961a9824754b77a1b593d39ap-4,
    0x1.f0fe3530f7239p-4
  },
  { // Entry 229
    -0x1.f37429af961a9824754b77a1b593d39ap-4,
    -0x1.f0fe3530f7239p-4
  },
  { // Entry 230
    0x1.f37429af961ab89edde6f4ae74375a06p-4,
    0x1.f0fe3530f723bp-4
  },
  { // Entry 231
    -0x1.f37429af961ab89edde6f4ae74375a06p-4,
    -0x1.f0fe3530f723bp-4
  },
  { // Entry 232
    0x1.f37429af961ac8dc1234b334d38f1d1bp-4,
    0x1.f0fe3530f723cp-4
  },
  { // Entry 233
    -0x1.f37429af961ac8dc1234b334d38f1d1bp-4,
    -0x1.f0fe3530f723cp-4
  },
  { // Entry 234
    0x1.f37429af962b268ac88eb6a2f4026151p-4,
    0x1.f0fe3530f733ep-4
  },
  { // Entry 235
    -0x1.f37429af962b268ac88eb6a2f4026151p-4,
    -0x1.f0fe3530f733ep-4
  },
  { // Entry 236
    0x1.f1e9c43b21348857c7e465e46799dce1p-5,
    0x1.f14d08c7109aap-5
  },
  { // Entry 237
    -0x1.f1e9c43b21348857c7e465e46799dce1p-5,
    -0x1.f14d08c7109aap-5
  },
  { // Entry 238
    0x1.f90b42375a486a39cdf9b2ccf2824fecp-4,
    0x1.f68p-4
  },
  { // Entry 239
    -0x1.f90b42375a486a39cdf9b2ccf2824fecp-4,
    -0x1.f68p-4
  },
  { // Entry 240
    0x1.f72a153ff7688808c896dd6ffe6516d4p-5,
    0x1.f688582bdf450p-5
  },
  { // Entry 241
    -0x1.f72a153ff7688808c896dd6ffe6516d4p-5,
    -0x1.f688582bdf450p-5
  },
  { // Entry 242
    0x1.f7e703f1db06e802f9321fd5e2394e07p-5,
    0x1.f744909706414p-5
  },
  { // Entry 243
    -0x1.f7e703f1db06e802f9321fd5e2394e07p-5,
    -0x1.f744909706414p-5
  },
  { // Entry 244
    0x1.340af764783edfffac199b0ebf01c362p1,
    0x1.f7cp-1
  },
  { // Entry 245
    -0x1.340af764783edfffac199b0ebf01c362p1,
    -0x1.f7cp-1
  },
  { // Entry 246
    0x1.fa24a006fb7277fe99107e535f1488d7p-5,
    0x1.f98p-5
  },
  { // Entry 247
    -0x1.fa24a006fb7277fe99107e535f1488d7p-5,
    -0x1.f98p-5
  },
  { // Entry 248
    0x1.fabe9384d8eb28030d5306c1d38ffe3cp-5,
    0x1.fa195d3f2824ap-5
  },
  { // Entry 249
    -0x1.fabe9384d8eb28030d5306c1d38ffe3cp-5,
    -0x1.fa195d3f2824ap-5
  },
  { // Entry 250
    0x1.fac53cc7f51a2825f03615ff2011a3f4p-5,
    0x1.fa2p-5
  },
  { // Entry 251
    -0x1.fac53cc7f51a2825f03615ff2011a3f4p-5,
    -0x1.fa2p-5
  },
  { // Entry 252
    0x1.fca715610d4c584a721b2c19e6223c63p-5,
    0x1.fbfffffffffffp-5
  },
  { // Entry 253
    -0x1.fca715610d4c584a721b2c19e6223c63p-5,
    -0x1.fbfffffffffffp-5
  },
  { // Entry 254
    0x1.ff2303e94a6fa776b99fdcdac342443dp-4,
    0x1.fc7ffffffffffp-4
  },
  { // Entry 255
    -0x1.ff2303e94a6fa776b99fdcdac342443dp-4,
    -0x1.fc7ffffffffffp-4
  },
  { // Entry 256
    0x1.fcca7762322a195ec28591033e93e55bp-7,
    0x1.fccp-7
  },
  { // Entry 257
    -0x1.fcca7762322a195ec28591033e93e55bp-7,
    -0x1.fccp-7
  },
  { // Entry 258
    0x1.fde34e5e71112802cd5dc4e1fb2d0640p-5,
    0x1.fd3b00ef28dc9p-5
  },
  { // Entry 259
    -0x1.fde34e5e71112802cd5dc4e1fb2d0640p-5,
    -0x1.fd3b00ef28dc9p-5
  },
  { // Entry 260
    0x1.fd5da51e6bee9b019e62cd796699df5cp-8,
    0x1.fd5b04f37a8adp-8
  },
  { // Entry 261
    -0x1.fd5da51e6bee9b019e62cd796699df5cp-8,
    -0x1.fd5b04f37a8adp-8
  },
  { // Entry 262
    0x1.ff08b9b3981768022e66dd42cd419f4cp-9,
    0x1.ff080ffffffffp-9
  },
  { // Entry 263
    -0x1.ff08b9b3981768022e66dd42cd419f4cp-9,
    -0x1.ff080ffffffffp-9
  },
  { // Entry 264
    0x1.ff782a88ba0fba00f908e16f051a1810p-10,
    0x1.ff77fffffffffp-10
  },
  { // Entry 265
    -0x1.ff782a88ba0fba00f908e16f051a1810p-10,
    -0x1.ff77fffffffffp-10
  },
  { // Entry 266
    0x1.0154818928eb11132905352501826af5p-3,
    0x1.fff7fffffffffp-4
  },
  { // Entry 267
    -0x1.0154818928eb11132905352501826af5p-3,
    -0x1.fff7fffffffffp-4
  },
  { // Entry 268
    0x1.fffca6a70d15564482dc93a139764e2dp-9,
    0x1.fffbfbfffffffp-9
  },
  { // Entry 269
    -0x1.fffca6a70d15564482dc93a139764e2dp-9,
    -0x1.fffbfbfffffffp-9
  },
  { // Entry 270
    0x1.0157cebdbc7ecff56d936def2dc90848p-3,
    0x1.fffe7ffffffffp-4
  },
  { // Entry 271
    -0x1.0157cebdbc7ecff56d936def2dc90848p-3,
    -0x1.fffe7ffffffffp-4
  },
  { // Entry 272
    0x1.ffff2aaa70e11229a646c3ea214d5c6bp-10,
    0x1.fffeffffffcffp-10
  },
  { // Entry 273
    -0x1.ffff2aaa70e11229a646c3ea214d5c6bp-10,
    -0x1.fffeffffffcffp-10
  },
  { // Entry 274
    0x1.fe849ae4ae0948fc35cd560fe0f7a64fp2,
    0x1.fffff8170432cp-1
  },
  { // Entry 275
    -0x1.fe849ae4ae0948fc35cd560fe0f7a64fp2,
    -0x1.fffff8170432cp-1
  },
  { // Entry 276
    0x1.fe8636119def0727f0b21ad8da17b705p2,
    0x1.fffff81769d3bp-1
  },
  { // Entry 277
    -0x1.fe8636119def0727f0b21ad8da17b705p2,
    -0x1.fffff81769d3bp-1
  },
  { // Entry 278
    0x1.feab0f8d089237326f5246ce7822ddcap2,
    0x1.fffff8207ffffp-1
  },
  { // Entry 279
    -0x1.feab0f8d089237326f5246ce7822ddcap2,
    -0x1.fffff8207ffffp-1
  },
  { // Entry 280
    0x1.fffffbc002aa9a99aab134f0ccf89dcfp-20,
    0x1.fffffbbffffffp-20
  },
  { // Entry 281
    -0x1.fffffbc002aa9a99aab134f0ccf89dcfp-20,
    -0x1.fffffbbffffffp-20
  },
  { // Entry 282
    0x1.38aa9bbc81de80372da066273e181f3dp3,
    0x1.ffffffc7fffffp-1
  },
  { // Entry 283
    -0x1.38aa9bbc81de80372da066273e181f3dp3,
    -0x1.ffffffc7fffffp-1
  },
  { // Entry 284
    0x1.a791d873bcf1ef6cc589b55be94c11ccp3,
    0x1.fffffffff1fffp-1
  },
  { // Entry 285
    -0x1.a791d873bcf1ef6cc589b55be94c11ccp3,
    -0x1.fffffffff1fffp-1
  },
  { // Entry 286
    0x1.048fa31ec6a076cfd26abb456c9e863ap4,
    0x1.fffffffffff7fp-1
  },
  { // Entry 287
    -0x1.048fa31ec6a076cfd26abb456c9e863ap4,
    -0x1.fffffffffff7fp-1
  },
  { // Entry 288
    0x1.ffffffffffff8aaaaaaaaaa9f1111111p-25,
    0x1.fffffffffffeep-25
  },
  { // Entry 289
    -0x1.ffffffffffff8aaaaaaaaaa9f1111111p-25,
    -0x1.fffffffffffeep-25
  },
  { // Entry 290
    -0x1.31dd28c89d64f3513ea98f014ae7630cp1,
    -0x1.f777777777777p-1
  },
  { // Entry 291
    0x1.31dd28c89d64f3513ea98f014ae7630cp1,
    0x1.f777777777777p-1
  },
  { // Entry 292
    -0x1.04f65f9c7297527749382883b8e88e33p1,
    -0x1.eeeeeeeeeeeeep-1
  },
  { // Entry 293
    0x1.04f65f9c7297527749382883b8e88e33p1,
    0x1.eeeeeeeeeeeeep-1
  },
  { // Entry 294
    -0x1.d4ef968880dcf1c48bf6d707008e71a0p0,
    -0x1.e666666666665p-1
  },
  { // Entry 295
    0x1.d4ef968880dcf1c48bf6d707008e71a0p0,
    0x1.e666666666665p-1
  },
  { // Entry 296
    -0x1.af038cbcdfe177f9b97cb13acb6a1d56p0,
    -0x1.ddddddddddddcp-1
  },
  { // Entry 297
    0x1.af038cbcdfe177f9b97cb13acb6a1d56p0,
    0x1.ddddddddddddcp-1
  },
  { // Entry 298
    -0x1.9157dfdd1b3e8bb2bc8c94b692c36c8bp0,
    -0x1.d555555555553p-1
  },
  { // Entry 299
    0x1.9157dfdd1b3e8bb2bc8c94b692c36c8bp0,
    0x1.d555555555553p-1
  },
  { // Entry 300
    -0x1.78e360604b32513afa302dd9090f54afp0,
    -0x1.ccccccccccccap-1
  },
  { // Entry 301
    0x1.78e360604b32513afa302dd9090f54afp0,
    0x1.ccccccccccccap-1
  },
  { // Entry 302
    -0x1.640775d4dd98457b36fb7ce98ec43308p0,
    -0x1.c444444444441p-1
  },
  { // Entry 303
    0x1.640775d4dd98457b36fb7ce98ec43308p0,
    0x1.c444444444441p-1
  },
  { // Entry 304
    -0x1.51cca16d7bb9ff79603c2533c5c76b7ap0,
    -0x1.bbbbbbbbbbbb8p-1
  },
  { // Entry 305
    0x1.51cca16d7bb9ff79603c2533c5c76b7ap0,
    0x1.bbbbbbbbbbbb8p-1
  },
  { // Entry 306
    -0x1.41933b0e446305a96ace1bc262cdee99p0,
    -0x1.b33333333332fp-1
  },
  { // Entry 307
    0x1.41933b0e446305a96ace1bc262cdee99p0,
    0x1.b33333333332fp-1
  },
  { // Entry 308
    -0x1.32ee3b77f374414d3a29141080dfabeap0,
    -0x1.aaaaaaaaaaaa6p-1
  },
  { // Entry 309
    0x1.32ee3b77f374414d3a29141080dfabeap0,
    0x1.aaaaaaaaaaaa6p-1
  },
  { // Entry 310
    -0x1.258fdae8372b9231a664ea76c9d6586fp0,
    -0x1.a22222222221dp-1
  },
  { // Entry 311
    0x1.258fdae8372b9231a664ea76c9d6586fp0,
    0x1.a22222222221dp-1
  },
  { // Entry 312
    -0x1.193ea7aad0302d04dcfd1b8e192ed85dp0,
    -0x1.9999999999994p-1
  },
  { // Entry 313
    0x1.193ea7aad0302d04dcfd1b8e192ed85dp0,
    0x1.9999999999994p-1
  },
  { // Entry 314
    -0x1.0dcefea4d025e0b8d09052e46fdf4f2ep0,
    -0x1.911111111110bp-1
  },
  { // Entry 315
    0x1.0dcefea4d025e0b8d09052e46fdf4f2ep0,
    0x1.911111111110bp-1
  },
  { // Entry 316
    -0x1.031ef11090f771d990e41e47d30913d6p0,
    -0x1.8888888888882p-1
  },
  { // Entry 317
    0x1.031ef11090f771d990e41e47d30913d6p0,
    0x1.8888888888882p-1
  },
  { // Entry 318
    -0x1.f2272ae325a47546f69496cf861be046p-1,
    -0x1.7fffffffffff9p-1
  },
  { // Entry 319
    0x1.f2272ae325a47546f69496cf861be046p-1,
    0x1.7fffffffffff9p-1
  },
  { // Entry 320
    -0x1.df2e6d6e5fb9a3aede73b55578f55672p-1,
    -0x1.7777777777770p-1
  },
  { // Entry 321
    0x1.df2e6d6e5fb9a3aede73b55578f55672p-1,
    0x1.7777777777770p-1
  },
  { // Entry 322
    -0x1.cd302116f50ababc40c132419e1dab2ap-1,
    -0x1.6eeeeeeeeeee7p-1
  },
  { // Entry 323
    0x1.cd302116f50ababc40c132419e1dab2ap-1,
    0x1.6eeeeeeeeeee7p-1
  },
  { // Entry 324
    -0x1.bc0ed0947fbd88e1ba52723b57950592p-1,
    -0x1.666666666665ep-1
  },
  { // Entry 325
    0x1.bc0ed0947fbd88e1ba52723b57950592p-1,
    0x1.666666666665ep-1
  },
  { // Entry 326
    -0x1.abb1c9065825972aaaf3d164ca1f5323p-1,
    -0x1.5ddddddddddd5p-1
  },
  { // Entry 327
    0x1.abb1c9065825972aaaf3d164ca1f5323p-1,
    0x1.5ddddddddddd5p-1
  },
  { // Entry 328
    -0x1.9c041f7ed8d229e312aad84998a0e008p-1,
    -0x1.555555555554cp-1
  },
  { // Entry 329
    0x1.9c041f7ed8d229e312aad84998a0e008p-1,
    0x1.555555555554cp-1
  },
  { // Entry 330
    -0x1.8cf3f3b791739ba35824b20bb67bc051p-1,
    -0x1.4ccccccccccc3p-1
  },
  { // Entry 331
    0x1.8cf3f3b791739ba35824b20bb67bc051p-1,
    0x1.4ccccccccccc3p-1
  },
  { // Entry 332
    -0x1.7e71ded66460614d3cfeeae5195853fdp-1,
    -0x1.444444444443ap-1
  },
  { // Entry 333
    0x1.7e71ded66460614d3cfeeae5195853fdp-1,
    0x1.444444444443ap-1
  },
  { // Entry 334
    -0x1.7070827f1c7ee9fc23eb09099495f760p-1,
    -0x1.3bbbbbbbbbbb1p-1
  },
  { // Entry 335
    0x1.7070827f1c7ee9fc23eb09099495f760p-1,
    0x1.3bbbbbbbbbbb1p-1
  },
  { // Entry 336
    -0x1.62e42fefa39ddb5793c7673063c5ed5ep-1,
    -0x1.3333333333328p-1
  },
  { // Entry 337
    0x1.62e42fefa39ddb5793c7673063c5ed5ep-1,
    0x1.3333333333328p-1
  },
  { // Entry 338
    -0x1.55c2a141bd913c9da91e9ba97d84ef42p-1,
    -0x1.2aaaaaaaaaa9fp-1
  },
  { // Entry 339
    0x1.55c2a141bd913c9da91e9ba97d84ef42p-1,
    0x1.2aaaaaaaaaa9fp-1
  },
  { // Entry 340
    -0x1.4902c08bec8b8d6ba2debcee67107aa5p-1,
    -0x1.2222222222216p-1
  },
  { // Entry 341
    0x1.4902c08bec8b8d6ba2debcee67107aa5p-1,
    0x1.2222222222216p-1
  },
  { // Entry 342
    -0x1.3c9c79bc8508ca2d5b90a842ee7edfa3p-1,
    -0x1.199999999998dp-1
  },
  { // Entry 343
    0x1.3c9c79bc8508ca2d5b90a842ee7edfa3p-1,
    0x1.199999999998dp-1
  },
  { // Entry 344
    -0x1.308894d710d767af349ad5664f91afbcp-1,
    -0x1.1111111111104p-1
  },
  { // Entry 345
    0x1.308894d710d767af349ad5664f91afbcp-1,
    0x1.1111111111104p-1
  },
  { // Entry 346
    -0x1.24c096cf976a96087c1335628fdc0098p-1,
    -0x1.088888888887bp-1
  },
  { // Entry 347
    0x1.24c096cf976a96087c1335628fdc0098p-1,
    0x1.088888888887bp-1
  },
  { // Entry 348
    -0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    -0x1.0p-1
  },
  { // Entry 349
    0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    0x1.0p-1
  },
  { // Entry 350
    0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    0x1.0p-1
  },
  { // Entry 351
    -0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    -0x1.0p-1
  },
  { // Entry 352
    0x1.24c096cf976bc79a7ab78995d36b066bp-1,
    0x1.0888888888889p-1
  },
  { // Entry 353
    -0x1.24c096cf976bc79a7ab78995d36b066bp-1,
    -0x1.0888888888889p-1
  },
  { // Entry 354
    0x1.308894d710d8a0ba55ff01eb87cbc220p-1,
    0x1.1111111111112p-1
  },
  { // Entry 355
    -0x1.308894d710d8a0ba55ff01eb87cbc220p-
"""


```
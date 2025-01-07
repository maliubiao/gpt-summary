Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The user wants to understand the purpose and function of the provided C code snippet. Keywords are "bionic", "sinf", "intel_data", "handroid", "的功能", "android的功能", "libc函数", "dynamic linker", "frida hook". This tells me the code is related to the `sinf` (single-precision sine function) implementation within Android's Bionic library, specifically using data potentially collected from Intel hardware.

2. **Initial Scan for Clues:**  I quickly scanned the code. The most obvious feature is the large array named `g_sinf_intel_data`. It's an array of structures (or a template instantiation resembling a structure) called `data_1_1_t`, containing two `float` values. The comments `// Entry N` further reinforce the idea of this being a table of data points.

3. **Formulate a High-Level Interpretation:**  Based on the filename, the array name, and the data structure, I hypothesize that this file contains test data for the `sinf` function. The two floats in each entry likely represent an input value and the corresponding expected output of the `sinf` function. The "intel_data" part suggests these test cases might be specifically designed to cover edge cases or behaviors observed on Intel processors. The "handroid" in the path is just an internal Android build configuration and isn't crucial to the core functionality of the *data itself*.

4. **Address the Specific Questions (Point by Point):**

   * **列举一下它的功能 (List its functions):**  The primary function is to provide test data for the `sinf` function. I need to be careful not to overstate its role. It's *data*, not code that performs calculations.

   * **如果它与android的功能有关系，请做出对应的举例说明 (If it's related to Android's functions, provide examples):**  The connection to Android is direct. `sinf` is a standard math function, and Bionic is Android's standard C library implementation. This data helps ensure the accuracy of `sinf` on Android devices. A good example is that an Android app using `sinf` will rely on the correctness of this implementation, which is validated by this kind of data.

   * **详细解释每一个libc函数的功能是如何实现的 (Explain how each libc function is implemented in detail):** This is a tricky point. The provided code *isn't* the implementation of `sinf`. It's *test data*. I need to explicitly state this. However, I *can* briefly explain *how* `sinf` is generally implemented (using approximations, Taylor series, etc.) without going into the Bionic-specific details, since those aren't in the provided snippet.

   * **对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程 (For dynamic linker functions, provide an SO layout and linking process):** This code doesn't directly involve the dynamic linker. It's static data. I need to clarify this. While `sinf` *itself* is in a shared library, this data file is separate. To answer the spirit of the question, I can provide a *general* explanation of how shared libraries are laid out and linked in Android, even though this specific file isn't a shared object. A simple `libm.so` example is appropriate.

   * **如果做了逻辑推理，请给出假设输入与输出 (If logical inference is used, provide example inputs and outputs):**  The data itself *is* the input and expected output. I can pick a few entries and show the input and expected output values directly as an example of how the test data is structured.

   * **如果涉及用户或者编程常见的使用错误，请举例说明 (If it involves common user or programming errors, provide examples):**  Since this is test data, direct user errors aren't really applicable. However, I *can* discuss potential errors in the *implementation* of `sinf` that this data is designed to catch (e.g., precision issues, handling of edge cases like very small or large numbers).

   * **说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤 (Explain how the Android framework or NDK reaches this code, and provide a Frida hook example):**  The Android framework or NDK doesn't directly *execute* this data file. Instead, developers use the `sinf` function via the NDK. The *test suite* within the Android build system uses this data to verify the `sinf` implementation. My explanation needs to cover this testing process. For the Frida hook, I can demonstrate hooking the `sinf` function itself, which is the function this data is designed to test. Hooking the *data file* directly isn't something you'd typically do.

5. **Focus on the "归纳一下它的功能 (Summarize its function)" for Part 1:** The core function is providing test data for `sinf`. Keep the summary concise.

6. **Structure and Language:**  Use clear, concise Chinese. Organize the answer logically, addressing each part of the request. Use code formatting where appropriate (though the provided snippet is mostly data). Explain technical terms simply. Be precise about what the code *is* and *is not*.

7. **Review and Refine:** Before submitting, I would reread my answer to ensure it accurately addresses all parts of the request, avoids overgeneralizations, and is easy for the user to understand. I'd double-check that I've correctly identified the purpose of the file as test data and haven't confused it with the actual `sinf` implementation.
好的，让我们来归纳一下 `bionic/tests/math_data/sinf_intel_data.handroid` 这个源代码文件的功能。

**功能归纳：**

这个 C 源代码文件定义了一个静态数组 `g_sinf_intel_data`，该数组包含了用于测试 `sinf` 函数（单精度浮点数正弦函数）的大量测试数据。

**更详细的解释：**

* **测试数据提供:**  这个文件的主要功能是提供一组预定义的输入值和对应的预期输出值，专门用于测试 `sinf` 函数在特定平台（这里暗示是 Intel 架构的 Android 设备，通过 "intel_data" 和可能的 "handroid" 配置推断）上的正确性。

* **数据结构:** 数组 `g_sinf_intel_data` 的元素类型是 `data_1_1_t<float, float>`。这表明每个测试用例包含两个单精度浮点数：
    * 第一个 `float` 值很可能是 `sinf` 函数的输入参数。
    * 第二个 `float` 值是对于该输入参数，`sinf` 函数在理想情况下应该返回的精确或近似值。

* **覆盖各种情况:**  从数组中包含的各种不同数量级和正负号的浮点数来看，这个测试数据集旨在覆盖 `sinf` 函数在各种输入场景下的行为，包括：
    * 接近零的小值
    * 接近 +/- 1 的值
    * 非常大或非常小的值（通过指数部分 `p-n` 表示）
    * 正数和负数
    * 特殊值，例如 0.0f 和 -0.0f

**与 Android 功能的关系举例：**

在 Android 系统中，应用程序和系统服务经常需要进行数学运算，包括三角函数。`sinf` 函数是 C 标准库 `<math.h>` 的一部分，由 Bionic 库提供。

* **应用程序开发:** Android 应用程序开发者可以使用 NDK (Native Development Kit) 在 C/C++ 代码中调用 `sinf` 函数来计算角度的正弦值，例如在图形渲染、物理模拟、信号处理等场景中。

* **系统库和框架:** Android Framework 的某些底层组件或系统库也可能依赖于 `sinf` 函数进行计算。

这个 `sinf_intel_data.handroid` 文件对于保证在特定 Android 设备上（例如基于 Intel 处理器的设备）`sinf` 函数的正确性和精度至关重要。在 Android 的构建和测试过程中，这个文件中的数据会被用来验证 Bionic 库中 `sinf` 函数的实现是否符合预期。

**后续部分的预告：**

在接下来的部分，我们可以深入探讨：

* **libc 函数 `sinf` 的实现原理:**  例如，通常使用泰勒级数展开或其他数值逼近方法。
* **Dynamic Linker 的角色:** 虽然这个文件本身是静态数据，但 `sinf` 函数的实现位于共享库中，Dynamic Linker 负责在程序运行时加载和链接这些库。
* **Frida Hook 调试示例:** 如何使用 Frida 来监控 `sinf` 函数的调用和返回值，以及如何利用这些测试数据进行更精细的调试。

总结来说，`bionic/tests/math_data/sinf_intel_data.handroid` 是 Bionic 库中用于测试 `sinf` 函数的测试数据集合，它对于确保 Android 系统中数学运算的正确性具有重要意义。

Prompt: 
```
这是目录为bionic/tests/math_data/sinf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_sinf_intel_data[] = {
  { // Entry 0
    -0x1.0003fffffff554d5535552cccf778ccdp-21,
    -0x1.0004p-21
  },
  { // Entry 1
    0x1.0003fffffff554d5535552cccf778ccdp-21,
    0x1.0004p-21
  },
  { // Entry 2
    -0x1.d30ca7008af24ef048a7a05eecde2120p-4,
    -0x1.00cbf0p10
  },
  { // Entry 3
    0x1.d30ca7008af24ef048a7a05eecde2120p-4,
    0x1.00cbf0p10
  },
  { // Entry 4
    0x1.8d665d0000200efc4478008658c617c7p-1,
    -0x1.01ee34p2
  },
  { // Entry 5
    -0x1.8d665d0000200efc4478008658c617c7p-1,
    0x1.01ee34p2
  },
  { // Entry 6
    0x1.ec042ff972e42c23f28f2da4fb75f851p-1,
    -0x1.18f1f4p4
  },
  { // Entry 7
    -0x1.ec042ff972e42c23f28f2da4fb75f851p-1,
    0x1.18f1f4p4
  },
  { // Entry 8
    0x1.f0d384240ad9f2dba47b96b08271b41fp-1,
    -0x1.1df906p2
  },
  { // Entry 9
    -0x1.f0d384240ad9f2dba47b96b08271b41fp-1,
    0x1.1df906p2
  },
  { // Entry 10
    -0x1.4616daf9cd3ce4e92186e7d8ec3d3ef0p-5,
    -0x1.3ap6
  },
  { // Entry 11
    0x1.4616daf9cd3ce4e92186e7d8ec3d3ef0p-5,
    0x1.3ap6
  },
  { // Entry 12
    0x1.df04c5f9de343235f4f8b1797286872bp-1,
    -0x1.44b096p2
  },
  { // Entry 13
    -0x1.df04c5f9de343235f4f8b1797286872bp-1,
    0x1.44b096p2
  },
  { // Entry 14
    -0x1.feffbd7334c7043b90a6bc2d76dda7c8p-1,
    -0x1.821cf6p0
  },
  { // Entry 15
    0x1.feffbd7334c7043b90a6bc2d76dda7c8p-1,
    0x1.821cf6p0
  },
  { // Entry 16
    0x1.ebac56ffe6f27893c69f68d1d7b4a448p-3,
    -0x1.829b86p2
  },
  { // Entry 17
    -0x1.ebac56ffe6f27893c69f68d1d7b4a448p-3,
    0x1.829b86p2
  },
  { // Entry 18
    0x1.b725ccef65b1390912a0f5eaab0e7202p-6,
    -0x1.8580fep7
  },
  { // Entry 19
    -0x1.b725ccef65b1390912a0f5eaab0e7202p-6,
    0x1.8580fep7
  },
  { // Entry 20
    0x1.0b3366508957520d9dc88d7c09337e24p-1,
    -0x1.fffffep127
  },
  { // Entry 21
    -0x1.0b3366508957520d9dc88d7c09337e24p-1,
    0x1.fffffep127
  },
  { // Entry 22
    0.0f,
    0x1.p-149
  },
  { // Entry 23
    -0.0f,
    -0x1.p-149
  },
  { // Entry 24
    -0x1.f83de7c0683d3bd90a769f62a41ac1c3p-1,
    0x1.000002p52
  },
  { // Entry 25
    0x1.f83de7c0683d3bd90a769f62a41ac1c3p-1,
    -0x1.000002p52
  },
  { // Entry 26
    -0x1.7dbd11ffde4c20dbb376019f1c654bb0p-2,
    0x1.000022p62
  },
  { // Entry 27
    0x1.7dbd11ffde4c20dbb376019f1c654bb0p-2,
    -0x1.000022p62
  },
  { // Entry 28
    0x1.eaf0d5008f2db899e2487da9d3b9cde7p-2,
    0x1.000150p-1
  },
  { // Entry 29
    -0x1.eaf0d5008f2db899e2487da9d3b9cde7p-2,
    -0x1.000150p-1
  },
  { // Entry 30
    0x1.ffae8cfefa813da87498df988c3d8f5ep-5,
    0x1.0001f0p-4
  },
  { // Entry 31
    -0x1.ffae8cfefa813da87498df988c3d8f5ep-5,
    -0x1.0001f0p-4
  },
  { // Entry 32
    0x1.89c7d6087a861bb6fe794148c3425348p-1,
    0x1.0003p40
  },
  { // Entry 33
    -0x1.89c7d6087a861bb6fe794148c3425348p-1,
    -0x1.0003p40
  },
  { // Entry 34
    -0x1.59e1f519ef8b722eae12a404cad937ebp-1,
    0x1.000380p126
  },
  { // Entry 35
    0x1.59e1f519ef8b722eae12a404cad937ebp-1,
    -0x1.000380p126
  },
  { // Entry 36
    0x1.0003fffffff554d5535552cccf778ccdp-21,
    0x1.0004p-21
  },
  { // Entry 37
    -0x1.0003fffffff554d5535552cccf778ccdp-21,
    -0x1.0004p-21
  },
  { // Entry 38
    0x1.383065027ec4f20ab1c0027d991b805ap-6,
    0x1.0007c0p9
  },
  { // Entry 39
    -0x1.383065027ec4f20ab1c0027d991b805ap-6,
    -0x1.0007c0p9
  },
  { // Entry 40
    0x1.eb0397002fdfbae226f069d6cd53c40fp-2,
    0x1.000cp-1
  },
  { // Entry 41
    -0x1.eb0397002fdfbae226f069d6cd53c40fp-2,
    -0x1.000cp-1
  },
  { // Entry 42
    0x1.fedc8b0001f7dacee090c5edc3bfa547p-4,
    0x1.0019p-3
  },
  { // Entry 43
    -0x1.fedc8b0001f7dacee090c5edc3bfa547p-4,
    -0x1.0019p-3
  },
  { // Entry 44
    0x1.ab471af26ffea23d7643cf614c860b18p-10,
    0x1.003820p68
  },
  { // Entry 45
    -0x1.ab471af26ffea23d7643cf614c860b18p-10,
    -0x1.003820p68
  },
  { // Entry 46
    0x1.ff29eefdde3041fc5c75a1f822a5421dp-4,
    0x1.0040p-3
  },
  { // Entry 47
    -0x1.ff29eefdde3041fc5c75a1f822a5421dp-4,
    -0x1.0040p-3
  },
  { // Entry 48
    0x1.29070175206b3f198c893e19b4bd6cb8p-13,
    0x1.01f0p103
  },
  { // Entry 49
    -0x1.29070175206b3f198c893e19b4bd6cb8p-13,
    -0x1.01f0p103
  },
  { // Entry 50
    -0x1.ffffffffffffaafbe53de74231954709p-1,
    0x1.04ccbcp18
  },
  { // Entry 51
    0x1.ffffffffffffaafbe53de74231954709p-1,
    -0x1.04ccbcp18
  },
  { // Entry 52
    0x1.f4f72cad5f5fb17ec608ec7ac1cbca8bp-2,
    0x1.05bcp-1
  },
  { // Entry 53
    -0x1.f4f72cad5f5fb17ec608ec7ac1cbca8bp-2,
    -0x1.05bcp-1
  },
  { // Entry 54
    0x1.f896c6689d7e75e351ecc85731254cd3p-1,
    0x1.07c1f8p119
  },
  { // Entry 55
    -0x1.f896c6689d7e75e351ecc85731254cd3p-1,
    -0x1.07c1f8p119
  },
  { // Entry 56
    -0x1.267593f4d59c7de6170090a6a084cdcap-14,
    0x1.080180p23
  },
  { // Entry 57
    0x1.267593f4d59c7de6170090a6a084cdcap-14,
    -0x1.080180p23
  },
  { // Entry 58
    0x1.fc86372a841549410c12dbec6fe80dc5p-2,
    0x1.0a14p-1
  },
  { // Entry 59
    -0x1.fc86372a841549410c12dbec6fe80dc5p-2,
    -0x1.0a14p-1
  },
  { // Entry 60
    0x1.bca28f0004316bae8df6a2352cca1382p-1,
    0x1.0b770ap1
  },
  { // Entry 61
    -0x1.bca28f0004316bae8df6a2352cca1382p-1,
    -0x1.0b770ap1
  },
  { // Entry 62
    -0x1.fade9abd67526d37189df004b51d9d5ap-1,
    0x1.0ddcp96
  },
  { // Entry 63
    0x1.fade9abd67526d37189df004b51d9d5ap-1,
    -0x1.0ddcp96
  },
  { // Entry 64
    0x1.bf683cffffec6e8672a49f08aae49c46p-1,
    0x1.1024p0
  },
  { // Entry 65
    -0x1.bf683cffffec6e8672a49f08aae49c46p-1,
    -0x1.1024p0
  },
  { // Entry 66
    -0x1.f14407f6441e92f480d2e22859d67a39p-1,
    0x1.109cc4p4
  },
  { // Entry 67
    0x1.f14407f6441e92f480d2e22859d67a39p-1,
    -0x1.109cc4p4
  },
  { // Entry 68
    -0x1.ff7e7b9983a7c2ebecfab1a0b0af3c4dp-1,
    0x1.13bfb2p4
  },
  { // Entry 69
    0x1.ff7e7b9983a7c2ebecfab1a0b0af3c4dp-1,
    -0x1.13bfb2p4
  },
  { // Entry 70
    0x1.c4942b1e9ec175aa7d3fd75f2e37e566p-1,
    0x1.1590p0
  },
  { // Entry 71
    -0x1.c4942b1e9ec175aa7d3fd75f2e37e566p-1,
    -0x1.1590p0
  },
  { // Entry 72
    0x1.fff8d36866faaac8c17e1267498bd132p-1,
    0x1.18p85
  },
  { // Entry 73
    -0x1.fff8d36866faaac8c17e1267498bd132p-1,
    -0x1.18p85
  },
  { // Entry 74
    0x1.c78d962546ce51b882c9054eccd829b1p-1,
    0x1.18c8p0
  },
  { // Entry 75
    -0x1.c78d962546ce51b882c9054eccd829b1p-1,
    -0x1.18c8p0
  },
  { // Entry 76
    0x1.c7cb99a111f26527b805734962fb12a0p-1,
    0x1.190cp0
  },
  { // Entry 77
    -0x1.c7cb99a111f26527b805734962fb12a0p-1,
    -0x1.190cp0
  },
  { // Entry 78
    -0x1.70898100055943898aa7053017ecba69p-1,
    0x1.1e8f14p62
  },
  { // Entry 79
    0x1.70898100055943898aa7053017ecba69p-1,
    -0x1.1e8f14p62
  },
  { // Entry 80
    0x1.cdef1e4eb37e9f2249656c27d62b1895p-1,
    0x1.1ff8p0
  },
  { // Entry 81
    -0x1.cdef1e4eb37e9f2249656c27d62b1895p-1,
    -0x1.1ff8p0
  },
  { // Entry 82
    -0x1.5df0dd60f122bf79d1ddcf295c34cb0ep-1,
    0x1.2244a6p59
  },
  { // Entry 83
    0x1.5df0dd60f122bf79d1ddcf295c34cb0ep-1,
    -0x1.2244a6p59
  },
  { // Entry 84
    -0x1.fb8dd74f1b091a7b0f9f9d44db84661cp-3,
    0x1.287ae0p13
  },
  { // Entry 85
    0x1.fb8dd74f1b091a7b0f9f9d44db84661cp-3,
    -0x1.287ae0p13
  },
  { // Entry 86
    -0x1.fffffffffffff5c0d2630ee0a1fb4e7bp-1,
    0x1.2d97c8p2
  },
  { // Entry 87
    0x1.fffffffffffff5c0d2630ee0a1fb4e7bp-1,
    -0x1.2d97c8p2
  },
  { // Entry 88
    -0x1.99bc5b961b1ac296dbe1980fd2c890a0p-26,
    0x1.2d97c8p3
  },
  { // Entry 89
    0x1.99bc5b961b1ac296dbe1980fd2c890a0p-26,
    -0x1.2d97c8p3
  },
  { // Entry 90
    0x1.ffd5158b81944ff6b4833fdf1faa9281p-1,
    0x1.32cdc6p18
  },
  { // Entry 91
    -0x1.ffd5158b81944ff6b4833fdf1faa9281p-1,
    -0x1.32cdc6p18
  },
  { // Entry 92
    0x1.e191e77f58f479b564ec538b671f98afp-14,
    0x1.37efd8p100
  },
  { // Entry 93
    -0x1.e191e77f58f479b564ec538b671f98afp-14,
    -0x1.37efd8p100
  },
  { // Entry 94
    0x1.fffe974dceb10d4877a75bc77870ffebp-1,
    0x1.38p11
  },
  { // Entry 95
    -0x1.fffe974dceb10d4877a75bc77870ffebp-1,
    -0x1.38p11
  },
  { // Entry 96
    -0x1.b63f2c3f537b10eec2fbf340e4898644p-18,
    0x1.3d72b8p15
  },
  { // Entry 97
    0x1.b63f2c3f537b10eec2fbf340e4898644p-18,
    -0x1.3d72b8p15
  },
  { // Entry 98
    -0x1.e0208cff17f9186218945af9256d736cp-1,
    0x1.444b20p7
  },
  { // Entry 99
    0x1.e0208cff17f9186218945af9256d736cp-1,
    -0x1.444b20p7
  },
  { // Entry 100
    0x1.fffff9002cf87dade6f62eb709dc2aa7p-1,
    0x1.46b71ep4
  },
  { // Entry 101
    -0x1.fffff9002cf87dade6f62eb709dc2aa7p-1,
    -0x1.46b71ep4
  },
  { // Entry 102
    0x1.c875581a762211dd5caaf9abde5cf656p-21,
    0x1.4d0242p7
  },
  { // Entry 103
    -0x1.c875581a762211dd5caaf9abde5cf656p-21,
    -0x1.4d0242p7
  },
  { // Entry 104
    -0x1.6a6f79000053a3842566f1e018d6359fp-1,
    0x1.511e8ep28
  },
  { // Entry 105
    0x1.6a6f79000053a3842566f1e018d6359fp-1,
    -0x1.511e8ep28
  },
  { // Entry 106
    0x1.fffe9ffa6b569dd8c720d68e80bd9a63p-1,
    0x1.5354d0p100
  },
  { // Entry 107
    -0x1.fffe9ffa6b569dd8c720d68e80bd9a63p-1,
    -0x1.5354d0p100
  },
  { // Entry 108
    0x1.3b4d58fffff29126460f258ec4423e9ap-1,
    0x1.53ad5cp-1
  },
  { // Entry 109
    -0x1.3b4d58fffff29126460f258ec4423e9ap-1,
    -0x1.53ad5cp-1
  },
  { // Entry 110
    -0x1.fffeb762e93ead5ac70f85064fc79cffp-1,
    0x1.60p3
  },
  { // Entry 111
    0x1.fffeb762e93ead5ac70f85064fc79cffp-1,
    -0x1.60p3
  },
  { // Entry 112
    0x1.1772377ffe5b1f436c0149e328446f74p-20,
    0x1.6c6cbcp6
  },
  { // Entry 113
    -0x1.1772377ffe5b1f436c0149e328446f74p-20,
    -0x1.6c6cbcp6
  },
  { // Entry 114
    0x1.77fffdfffffff78d0577d9552663ea3ep-26,
    0x1.77fffep-26
  },
  { // Entry 115
    -0x1.77fffdfffffff78d0577d9552663ea3ep-26,
    -0x1.77fffep-26
  },
  { // Entry 116
    -0x1.ff04979385946d0568c153bf9e125fccp-1,
    0x1.77fffep4
  },
  { // Entry 117
    0x1.ff04979385946d0568c153bf9e125fccp-1,
    -0x1.77fffep4
  },
  { // Entry 118
    0x1.feb7a96a577f715fa7ad8788294c045bp-1,
    0x1.7ffffep0
  },
  { // Entry 119
    -0x1.feb7a96a577f715fa7ad8788294c045bp-1,
    -0x1.7ffffep0
  },
  { // Entry 120
    0x1.feb7eb54653509617faf3268344437fcp-1,
    0x1.8001d0p0
  },
  { // Entry 121
    -0x1.feb7eb54653509617faf3268344437fcp-1,
    -0x1.8001d0p0
  },
  { // Entry 122
    0x1.ff6535998ea004d48763597b6df9cd65p-1,
    0x1.807ffep13
  },
  { // Entry 123
    -0x1.ff6535998ea004d48763597b6df9cd65p-1,
    -0x1.807ffep13
  },
  { // Entry 124
    0x1.ff76ed9a192e9a2126bcfc0f306240d4p-1,
    0x1.866a42p0
  },
  { // Entry 125
    -0x1.ff76ed9a192e9a2126bcfc0f306240d4p-1,
    -0x1.866a42p0
  },
  { // Entry 126
    0x1.ace844f1eb6c3077277929ff4ade3f41p-5,
    0x1.8864p35
  },
  { // Entry 127
    -0x1.ace844f1eb6c3077277929ff4ade3f41p-5,
    -0x1.8864p35
  },
  { // Entry 128
    0x1.e0d108f196fd3cbcb7c2c76aee738205p-5,
    0x1.8a9b56p1
  },
  { // Entry 129
    -0x1.e0d108f196fd3cbcb7c2c76aee738205p-5,
    -0x1.8a9b56p1
  },
  { // Entry 130
    -0x1.6a09af0006fe0b47c81d8695c017a8dfp-1,
    0x1.8e96eep9
  },
  { // Entry 131
    0x1.6a09af0006fe0b47c81d8695c017a8dfp-1,
    -0x1.8e96eep9
  },
  { // Entry 132
    -0x1.dd59dceecf3fbd015e9e29b37aaf511ap-9,
    0x1.91e40ap2
  },
  { // Entry 133
    0x1.dd59dceecf3fbd015e9e29b37aaf511ap-9,
    -0x1.91e40ap2
  },
  { // Entry 134
    -0x1.fb73f1187e5053bacb752b89c6a3de57p-9,
    0x1.91fffep3
  },
  { // Entry 135
    0x1.fb73f1187e5053bacb752b89c6a3de57p-9,
    -0x1.91fffep3
  },
  { // Entry 136
    -0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    0x1.921fb6p1
  },
  { // Entry 137
    0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    -0x1.921fb6p1
  },
  { // Entry 138
    -0x1.ffffff79db917265e675574b8d83fa6ep-1,
    0x1.94fd7cp100
  },
  { // Entry 139
    0x1.ffffff79db917265e675574b8d83fa6ep-1,
    -0x1.94fd7cp100
  },
  { // Entry 140
    0x1.ffffffffffd7e83678a38329c1e093b5p-1,
    0x1.986834p6
  },
  { // Entry 141
    -0x1.ffffffffffd7e83678a38329c1e093b5p-1,
    -0x1.986834p6
  },
  { // Entry 142
    0x1.16ae29144d3aeb0ef741c3e2aba34078p-24,
    0x1.9a48dep17
  },
  { // Entry 143
    -0x1.16ae29144d3aeb0ef741c3e2aba34078p-24,
    -0x1.9a48dep17
  },
  { // Entry 144
    0x1.ff7ad398fd589528bb07db1e0bdd40f5p-1,
    0x1.9daa38p0
  },
  { // Entry 145
    -0x1.ff7ad398fd589528bb07db1e0bdd40f5p-1,
    -0x1.9daa38p0
  },
  { // Entry 146
    0x1.9df5f10000002f4b7421dfe9e955b60dp-4,
    0x1.9eab2ep-4
  },
  { // Entry 147
    -0x1.9df5f10000002f4b7421dfe9e955b60dp-4,
    -0x1.9eab2ep-4
  },
  { // Entry 148
    0x1.76dcf7000053c428e30ef99d9cf91accp-1,
    0x1.a499p-1
  },
  { // Entry 149
    -0x1.76dcf7000053c428e30ef99d9cf91accp-1,
    -0x1.a499p-1
  },
  { // Entry 150
    0x1.a9d4510000a2a82c391a9b36186ead65p-5,
    0x1.aa0578p-5
  },
  { // Entry 151
    -0x1.a9d4510000a2a82c391a9b36186ead65p-5,
    -0x1.aa0578p-5
  },
  { // Entry 152
    0x1.6a097dcc8b1356712fc20f82c4f87e4dp-1,
    0x1.b4ae70p6
  },
  { // Entry 153
    -0x1.6a097dcc8b1356712fc20f82c4f87e4dp-1,
    -0x1.b4ae70p6
  },
  { // Entry 154
    0x1.849926ffffeb95860262a99770a8c9c3p-1,
    0x1.b936dap-1
  },
  { // Entry 155
    -0x1.849926ffffeb95860262a99770a8c9c3p-1,
    -0x1.b936dap-1
  },
  { // Entry 156
    -0x1.dac40ef1e040315f07519a99c2034fffp-5,
    0x1.ba2784p82
  },
  { // Entry 157
    0x1.dac40ef1e040315f07519a99c2034fffp-5,
    -0x1.ba2784p82
  },
  { // Entry 158
    0x1.81074b0346f07390395b4ee2b50b3f94p-14,
    0x1.bdb44ap107
  },
  { // Entry 159
    -0x1.81074b0346f07390395b4ee2b50b3f94p-14,
    -0x1.bdb44ap107
  },
  { // Entry 160
    0x1.235debb727b95daaec183bfa4e728be1p-9,
    0x1.bdbefep119
  },
  { // Entry 161
    -0x1.235debb727b95daaec183bfa4e728be1p-9,
    -0x1.bdbefep119
  },
  { // Entry 162
    -0x1.99663da94db5290730b029513370e863p-23,
    0x1.beeeeep80
  },
  { // Entry 163
    0x1.99663da94db5290730b029513370e863p-23,
    -0x1.beeeeep80
  },
  { // Entry 164
    -0x1.62faa0ffdc55a4c54f1229fc0302bd5fp-2,
    0x1.bf6fd0p1
  },
  { // Entry 165
    0x1.62faa0ffdc55a4c54f1229fc0302bd5fp-2,
    -0x1.bf6fd0p1
  },
  { // Entry 166
    -0x1.c6d444de6b90c7b8b43402ef749a4c3dp-5,
    0x1.bffffep45
  },
  { // Entry 167
    0x1.c6d444de6b90c7b8b43402ef749a4c3dp-5,
    -0x1.bffffep45
  },
  { // Entry 168
    0x1.ffffffffffffa3c7657b85e5b44bbd44p-1,
    0x1.c463acp3
  },
  { // Entry 169
    -0x1.ffffffffffffa3c7657b85e5b44bbd44p-1,
    -0x1.c463acp3
  },
  { // Entry 170
    0x1.913648ffff9e23787f5ddb75dc55eec8p-1,
    0x1.cd0a0cp-1
  },
  { // Entry 171
    -0x1.913648ffff9e23787f5ddb75dc55eec8p-1,
    -0x1.cd0a0cp-1
  },
  { // Entry 172
    -0x1.a1d47cfd2825f1c3e2835e943b9669efp-5,
    0x1.d41818p12
  },
  { // Entry 173
    0x1.a1d47cfd2825f1c3e2835e943b9669efp-5,
    -0x1.d41818p12
  },
  { // Entry 174
    0x1.6a22db000036a9592db722e2d9be4869p-1,
    0x1.e62944p8
  },
  { // Entry 175
    -0x1.6a22db000036a9592db722e2d9be4869p-1,
    -0x1.e62944p8
  },
  { // Entry 176
    0x1.d4de8affffffd96f83ba442fdf2f7101p-2,
    0x1.e7061ep-2
  },
  { // Entry 177
    -0x1.d4de8affffffd96f83ba442fdf2f7101p-2,
    -0x1.e7061ep-2
  },
  { // Entry 178
    -0x1.e3ce04f1b94e1d82f0001cb99fed9275p-5,
    0x1.e7fffep95
  },
  { // Entry 179
    0x1.e3ce04f1b94e1d82f0001cb99fed9275p-5,
    -0x1.e7fffep95
  },
  { // Entry 180
    0x1.e97362ffff5d46e1e98c8a8c94478a44p-5,
    0x1.e9be0ep-5
  },
  { // Entry 181
    -0x1.e97362ffff5d46e1e98c8a8c94478a44p-5,
    -0x1.e9be0ep-5
  },
  { // Entry 182
    -0x1.57975cfefd7e705f3eb03a9e8e48a18cp-1,
    0x1.eb1dbep12
  },
  { // Entry 183
    0x1.57975cfefd7e705f3eb03a9e8e48a18cp-1,
    -0x1.eb1dbep12
  },
  { // Entry 184
    -0x1.6a1012e4b69b086c3dc0427aba80bc96p-1,
    0x1.eb1e8ap12
  },
  { // Entry 185
    0x1.6a1012e4b69b086c3dc0427aba80bc96p-1,
    -0x1.eb1e8ap12
  },
  { // Entry 186
    -0x1.9f42e4f467696ad36a70ac8b70e0cd32p-1,
    0x1.effc8ap24
  },
  { // Entry 187
    0x1.9f42e4f467696ad36a70ac8b70e0cd32p-1,
    -0x1.effc8ap24
  },
  { // Entry 188
    0x1.cbadb8ef8f3e358d2b8be493c11b57b1p-6,
    0x1.f5c1c4p3
  },
  { // Entry 189
    -0x1.cbadb8ef8f3e358d2b8be493c11b57b1p-6,
    -0x1.f5c1c4p3
  },
  { // Entry 190
    0x1.5aee2cfff087e59dfcd856cbfe4544dcp-2,
    0x1.f7fffep111
  },
  { // Entry 191
    -0x1.5aee2cfff087e59dfcd856cbfe4544dcp-2,
    -0x1.f7fffep111
  },
  { // Entry 192
    0x1.26db7d00bb06743fee581a888e2378f8p-1,
    0x1.f92518p24
  },
  { // Entry 193
    -0x1.26db7d00bb06743fee581a888e2378f8p-1,
    -0x1.f92518p24
  },
  { // Entry 194
    0x1.fffffffffffffebccf78a432a67858bbp-1,
    0x1.f9cbe2p7
  },
  { // Entry 195
    -0x1.fffffffffffffebccf78a432a67858bbp-1,
    -0x1.f9cbe2p7
  },
  { // Entry 196
    -0x1.1fa3bb9a07e77fd667f493622c9029ffp-27,
    0x1.f9cbe2p8
  },
  { // Entry 197
    0x1.1fa3bb9a07e77fd667f493622c9029ffp-27,
    -0x1.f9cbe2p8
  },
  { // Entry 198
    0x1.9ec29af1e15dd67f17e32047d9ff8db7p-1,
    0x1.fad160p24
  },
  { // Entry 199
    -0x1.9ec29af1e15dd67f17e32047d9ff8db7p-1,
    -0x1.fad160p24
  },
  { // Entry 200
    0x1.fbc2780f4bf8bc24d3fccc17f9e77f32p-1,
    0x1.fee5bap2
  },
  { // Entry 201
    -0x1.fbc2780f4bf8bc24d3fccc17f9e77f32p-1,
    -0x1.fee5bap2
  },
  { // Entry 202
    0x1.a8d7c10005ada8f7d4912bf603a315fep-1,
    0x1.ff0caep10
  },
  { // Entry 203
    -0x1.a8d7c10005ada8f7d4912bf603a315fep-1,
    -0x1.ff0caep10
  },
  { // Entry 204
    -0x1.56b02d00045da146e855d3770c9646fap-1,
    0x1.ff8406p80
  },
  { // Entry 205
    0x1.56b02d00045da146e855d3770c9646fap-1,
    -0x1.ff8406p80
  },
  { // Entry 206
    0x1.c02749ff4c4c8fcbb471610884d8e0bdp-3,
    0x1.ff9ffep40
  },
  { // Entry 207
    -0x1.c02749ff4c4c8fcbb471610884d8e0bdp-3,
    -0x1.ff9ffep40
  },
  { // Entry 208
    -0x1.388e710058342aa5b69afe3e2090a457p-1,
    0x1.ffbd58p24
  },
  { // Entry 209
    0x1.388e710058342aa5b69afe3e2090a457p-1,
    -0x1.ffbd58p24
  },
  { // Entry 210
    0x1.9e805aef3282d4ced40272702f174f53p-6,
    0x1.ffdd7ep72
  },
  { // Entry 211
    -0x1.9e805aef3282d4ced40272702f174f53p-6,
    -0x1.ffdd7ep72
  },
  { // Entry 212
    -0x1.fb3aef016b8ce66370ab61974e8ee0b2p-6,
    0x1.ffdffep91
  },
  { // Entry 213
    0x1.fb3aef016b8ce66370ab61974e8ee0b2p-6,
    -0x1.ffdffep91
  },
  { // Entry 214
    -0x1.e43148da53f422356edd3bdbaef3b2fap-3,
    0x1.fff77ep23
  },
  { // Entry 215
    0x1.e43148da53f422356edd3bdbaef3b2fap-3,
    -0x1.fff77ep23
  },
  { // Entry 216
    0x1.d6e1864764d24b4de18cb4c1903a7957p-1,
    0x1.fffe3ep5
  },
  { // Entry 217
    -0x1.d6e1864764d24b4de18cb4c1903a7957p-1,
    -0x1.fffe3ep5
  },
  { // Entry 218
    -0x1.ffff49c52f585e672d7185448d46e977p-1,
    0x1.fffe3ep41
  },
  { // Entry 219
    0x1.ffff49c52f585e672d7185448d46e977p-1,
    -0x1.fffe3ep41
  },
  { // Entry 220
    0x1.afc6a99cbade83b6be92b2ca45167988p-5,
    0x1.fffe3ep45
  },
  { // Entry 221
    -0x1.afc6a99cbade83b6be92b2ca45167988p-5,
    -0x1.fffe3ep45
  },
  { // Entry 222
    -0x1.53a29e54b4b142830dc796c9ed5fc59bp-9,
    0x1.fffe7ep103
  },
  { // Entry 223
    0x1.53a29e54b4b142830dc796c9ed5fc59bp-9,
    -0x1.fffe7ep103
  },
  { // Entry 224
    -0x1.47e89fd5047c4c94b5c0f61e375f2849p-11,
    0x1.fffe7ep126
  },
  { // Entry 225
    0x1.47e89fd5047c4c94b5c0f61e375f2849p-11,
    -0x1.fffe7ep126
  },
  { // Entry 226
    0x1.a4256c90c37410ce957c0b2501937618p-8,
    0x1.ffff8ep40
  },
  { // Entry 227
    -0x1.a4256c90c37410ce957c0b2501937618p-8,
    -0x1.ffff8ep40
  },
  { // Entry 228
    -0x1.d2bd84f5018f40c94c7f6e4552ef8e91p-3,
    0x1.ffffa4p23
  },
  { // Entry 229
    0x1.d2bd84f5018f40c94c7f6e4552ef8e91p-3,
    -0x1.ffffa4p23
  },
  { // Entry 230
    0x1.ffaa8cffd381ebe7b2d6a3e69bda3887p-5,
    0x1.ffffdep-5
  },
  { // Entry 231
    -0x1.ffaa8cffd381ebe7b2d6a3e69bda3887p-5,
    -0x1.ffffdep-5
  },
  { // Entry 232
    0x1.fa8d3ca23be2a84d37f0c04e97bab5e5p-1,
    0x1.fffff0p2
  },
  { // Entry 233
    -0x1.fa8d3ca23be2a84d37f0c04e97bab5e5p-1,
    -0x1.fffff0p2
  },
  { // Entry 234
    -0x1.ff978ecd320ad2d70c200824e4010843p-1,
    0x1.fffff0p7
  },
  { // Entry 235
    0x1.ff978ecd320ad2d70c200824e4010843p-1,
    -0x1.fffff0p7
  },
  { // Entry 236
    0x1.d18f76ffc6e4ba0a3134e5be21b5bc8fp-1,
    0x1.fffff6p0
  },
  { // Entry 237
    -0x1.d18f76ffc6e4ba0a3134e5be21b5bc8fp-1,
    -0x1.fffff6p0
  },
  { // Entry 238
    0x1.eaee8200b8dba5138f9ada42a22ab319p-2,
    0x1.fffffap-2
  },
  { // Entry 239
    -0x1.eaee8200b8dba5138f9ada42a22ab319p-2,
    -0x1.fffffap-2
  },
  { // Entry 240
    -0x1.0b3366508957520d9dc88d7c09337e24p-1,
    0x1.fffffep127
  },
  { // Entry 241
    0x1.0b3366508957520d9dc88d7c09337e24p-1,
    -0x1.fffffep127
  },
  { // Entry 242
    -0.0f,
    -0x1.p-149
  },
  { // Entry 243
    0.0f,
    0x1.p-149
  },
  { // Entry 244
    0.0,
    0.0
  },
  { // Entry 245
    0.0f,
    0x1.p-149
  },
  { // Entry 246
    -0.0f,
    -0x1.p-149
  },
  { // Entry 247
    -0x1.000001ffffffffffffffffffffffffffp-126,
    -0x1.000002p-126
  },
  { // Entry 248
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.000002p-126
  },
  { // Entry 249
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126
  },
  { // Entry 250
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126
  },
  { // Entry 251
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127
  },
  { // Entry 252
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127
  },
  { // Entry 253
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127
  },
  { // Entry 254
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127
  },
  { // Entry 255
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126
  },
  { // Entry 256
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126
  },
  { // Entry 257
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.000002p-126
  },
  { // Entry 258
    -0x1.000001ffffffffffffffffffffffffffp-126,
    -0x1.000002p-126
  },
  { // Entry 259
    0x1.999999d44f3058c789014b7d0e22fec3p-13,
    0x1.99999ap-13
  },
  { // Entry 260
    -0x1.999999d44f3058c789014b7d0e22fec3p-13,
    -0x1.99999ap-13
  },
  { // Entry 261
    0x1.999999513cc173e51bb9955b066f1db8p-12,
    0x1.99999ap-12
  },
  { // Entry 262
    -0x1.999999513cc173e51bb9955b066f1db8p-12,
    -0x1.99999ap-12
  },
  { // Entry 263
    0x1.333332d91685321e5fc397d20a5af1e6p-11,
    0x1.333334p-11
  },
  { // Entry 264
    -0x1.333332d91685321e5fc397d20a5af1e6p-11,
    -0x1.333334p-11
  },
  { // Entry 265
    0x1.99999744f306dc03e9ef70897f78299ep-11,
    0x1.99999ap-11
  },
  { // Entry 266
    -0x1.99999744f306dc03e9ef70897f78299ep-11,
    -0x1.99999ap-11
  },
  { // Entry 267
    0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    0x1.p-10
  },
  { // Entry 268
    -0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    -0x1.p-10
  },
  { // Entry 269
    0x1.33332f645a18c3b0ccfc0a3cf7b2e91bp-10,
    0x1.333334p-10
  },
  { // Entry 270
    -0x1.33332f645a18c3b0ccfc0a3cf7b2e91bp-10,
    -0x1.333334p-10
  },
  { // Entry 271
    0x1.666660aec330821c7a100cf488c380ebp-10,
    0x1.666668p-10
  },
  { // Entry 272
    -0x1.666660aec330821c7a100cf488c380ebp-10,
    -0x1.666668p-10
  },
  { // Entry 273
    0x1.99999113cc034144fdbdc8a1dc713253p-10,
    0x1.99999cp-10
  },
  { // Entry 274
    -0x1.99999113cc034144fdbdc8a1dc713253p-10,
    -0x1.99999cp-10
  },
  { // Entry 275
    0x1.ccccbc72b05dd0951a9c5e65560c56e3p-10,
    0x1.ccccccp-10
  },
  { // Entry 276
    -0x1.ccccbc72b05dd0951a9c5e65560c56e3p-10,
    -0x1.ccccccp-10
  },
  { // Entry 277
    0x1.0665ae3615b5b7de52798064dfc59b29p-7,
    0x1.066666p-7
  },
  { // Entry 278
    -0x1.0665ae3615b5b7de52798064dfc59b29p-7,
    -0x1.066666p-7
  },
  { // Entry 279
    0x1.ccc8e8ae92586d8d66b6ad0aedcb0d94p-7,
    0x1.ccccccp-7
  },
  { // Entry 280
    -0x1.ccc8e8ae92586d8d66b6ad0aedcb0d94p-7,
    -0x1.ccccccp-7
  },
  { // Entry 281
    0x1.4993e70f7b17c10af9f97fc7b33b822bp-6,
    0x1.499998p-6
  },
  { // Entry 282
    -0x1.4993e70f7b17c10af9f97fc7b33b822bp-6,
    -0x1.499998p-6
  },
  { // Entry 283
    0x1.acc043f8b2d89ad5143c030e9766fc11p-6,
    0x1.acccccp-6
  },
  { // Entry 284
    -0x1.acc043f8b2d89ad5143c030e9766fc11p-6,
    -0x1.acccccp-6
  },
  { // Entry 285
    0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    0x1.08p-5
  },
  { // Entry 286
    -0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    -0x1.08p-5
  },
  { // Entry 287
    0x1.3985fead44fa2b851e651acba369d769p-5,
    0x1.39999ap-5
  },
  { // Entry 288
    -0x1.3985fead44fa2b851e651acba369d769p-5,
    -0x1.39999ap-5
  },
  { // Entry 289
    0x1.6b14beb5d40d745096247e59b622828bp-5,
    0x1.6b3334p-5
  },
  { // Entry 290
    -0x1.6b14beb5d40d745096247e59b622828bp-5,
    -0x1.6b3334p-5
  },
  { // Entry 291
    0x1.9ca01671a7995fc97cebd69729cc4309p-5,
    0x1.9ccccep-5
  },
  { // Entry 292
    -0x1.9ca01671a7995fc97cebd69729cc4309p-5,
    -0x1.9ccccep-5
  },
  { // Entry 293
    0x1.ce278cd9eb2cbd0c6a4e1279f690e856p-5,
    0x1.ce6666p-5
  },
  { // Entry 294
    -0x1.ce278cd9eb2cbd0c6a4e1279f690e856p-5,
    -0x1.ce6666p-5
  },
  { // Entry 295
    0x1.43c1e9972391aa8ecd8a9ccba907920ap-1,
    0x1.5e7fc4p-1
  },
  { // Entry 296
    -0x1.43c1e9972391aa8ecd8a9ccba907920ap-1,
    -0x1.5e7fc4p-1
  },
  { // Entry 297
    0x1.ee3d6bb21c64b2382efcff0cdf30ce0bp-1,
    0x1.4e7fc4p0
  },
  { // Entry 298
    -0x1.ee3d6bb21c64b2382efcff0cdf30ce0bp-1,
    -0x1.4e7fc4p0
  },
  { // Entry 299
    0x1.df8e2323e4bf1a538a100ec1bf3494a9p-1,
    0x1.edbfa6p0
  },
  { // Entry 300
    -0x1.df8e2323e4bf1a538a100ec1bf3494a9p-1,
    -0x1.edbfa6p0
  },
  { // Entry 301
    0x1.1d347aa02feb3bb1750d25509435da88p-1,
    0x1.467fc4p1
  },
  { // Entry 302
    -0x1.1d347aa02feb3bb1750d25509435da88p-1,
    -0x1.467fc4p1
  },
  { // Entry 303
    -0x1.ffea08e1c97f4c4de01961cc3e7b04dcp-6,
    0x1.961fb4p1
  },
  { // Entry 304
    0x1.ffea08e1c97f4c4de01961cc3e7b04dcp-6,
    -0x1.961fb4p1
  },
  { // Entry 305
    -0x1.3734cbced9c0f484e5f762e00216e620p-1,
    0x1.e5bfa4p1
  },
  { // Entry 306
    0x1.3734cbced9c0f484e5f762e00216e620p-1,
    -0x1.e5bfa4p1
  },
  { // Entry 307
    -0x1.e9d2592bec10c3acb15c5852239a2aa8p-1,
    0x1.1aafcap2
  },
  { // Entry 308
    0x1.e9d2592bec10c3acb15c5852239a2aa8p-1,
    -0x1.1aafcap2
  },
  { // Entry 309
    -0x1.e4ece208d0c4913ab019cab0ce9c785ep-1,
    0x1.427fc2p2
  },
  { // Entry 310
    0x1.e4ece208d0c4913ab019cab0ce9c785ep-1,
    -0x1.427fc2p2
  },
  { // Entry 311
    -0x1.2a5a02d392b54f641a0d88bd4ac6c2e1p-1,
    0x1.6a4fbap2
  },
  { // Entry 312
    0x1.2a5a02d392b54f641a0d88bd4ac6c2e1p-1,
    -0x1.6a4fbap2
  },
  { // Entry 313
    -0x1.263123df22d13ed329c665c83c0e71e8p-1,
    0x1.6af2f0p2
  },
  { // Entry 314
    0x1.263123df22d13ed329c665c83c0e71e8p-1,
    -0x1.6af2f0p2
  },
  { // Entry 315
    -0x1.e18e67b508ffc9e42f6c9e72f8e545f3p-1,
    0x1.43c62ap2
  },
  { // Entry 316
    0x1.e18e67b508ffc9e42f6c9e72f8e545f3p-1,
    -0x1.43c62ap2
  },
  { // Entry 317
    -0x1.ee0e80ec9d1562c17a6cf608af9b0ed4p-1,
    0x1.1c9964p2
  },
  { // Entry 318
    0x1.ee0e80ec9d1562c17a6cf608af9b0ed4p-1,
    -0x1.1c9964p2
  },
  { // Entry 319
    -0x1.472768637ea8866a652098a43aa688a6p-1,
    0x1.ead93cp1
  },
  { // Entry 320
    0x1.472768637ea8866a652098a43aa688a6p-1,
    -0x1.ead93cp1
  },
  { // Entry 321
    -0x1.4ba24f6325f21420e7c48d4f91e28064p-4,
    0x1.9c7fb0p1
  },
  { // Entry 322
    0x1.4ba24f6325f21420e7c48d4f91e28064p-4,
    -0x1.9c7fb0p1
  },
  { // Entry 323
    0x1.034c643295153aaffe5d9a0f29e92844p-1,
    0x1.4e2624p1
  },
  { // Entry 324
    -0x1.034c643295153aaffe5d9a0f29e92844p-1,
    -0x1.4e2624p1
  },
  { // Entry 325
    0x1.d1e4d96eac917574b948e4ea9e37b36dp-1,
    0x1.ff9932p0
  },
  { // Entry 326
    -0x1.d1e4d96eac917574b948e4ea9e37b36dp-1,
    -0x1.ff9932p0
  },
  { // Entry 327
    0x1.f7501e002bcafb897f931931d3a57afdp-1,
    0x1.62e61cp0
  },
  { // Entry 328
    -0x1.f7501e002bcafb897f931931d3a57afdp-1,
    -0x1.62e61cp0
  },
  { // Entry 329
    0x1.65f7d66ef6591cfc51ab29dc2086d3e7p-1,
    0x1.8c662cp-1
  },
  { // Entry 330
    -0x1.65f7d66ef6591cfc51ab29dc2086d3e7p-1,
    -0x1.8c662cp-1
  },
  { // Entry 331
    -0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    -0x1.a8aa1cp0
  },
  { // Entry 332
    0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    0x1.a8aa1cp0
  },
  { // Entry 333
    -0x1.fff18f313e66f1ae25f89a5f7a1f84c4p-1,
    -0x1.95ec8ap0
  },
  { // Entry 334
    0x1.fff18f313e66f1ae25f89a5f7a1f84c4p-1,
    0x1.95ec8ap0
  },
  { // Entry 335
    -0x1.ff20d920b9e9c23154f97e2f342a2884p-1,
    -0x1.832ef8p0
  },
  { // Entry 336
    0x1.ff20d920b9e9c23154f97e2f342a2884p-1,
    0x1.832ef8p0
  },
  { // Entry 337
    -0x1.fb933b89d7db3286eed0cfeabee98875p-1,
    -0x1.707166p0
  },
  { // Entry 338
    0x1.fb933b89d7db3286eed0cfeabee98875p-1,
    0x1.707166p0
  },
  { // Entry 339
    -0x1.f54d95c5058b7dc9972ab6f9928ca043p-1,
    -0x1.5db3d4p0
  },
  { // Entry 340
    0x1.f54d95c5058b7dc9972ab6f9928ca043p-1,
    0x1.5db3d4p0
  },
  { // Entry 341
    -0x1.ec5881a09c46aae020cd9036098a196ep-1,
    -0x1.4af642p0
  },
  { // Entry 342
    0x1.ec5881a09c46aae020cd9036098a196ep-1,
    0x1.4af642p0
  },
  { // Entry 343
    -0x1.e0c04795919d961a5e83e505df31c624p-1,
    -0x1.3838b0p0
  },
  { // Entry 344
    0x1.e0c04795919d961a5e83e505df31c624p-1,
    0x1.3838b0p0
  },
  { // Entry 345
    -0x1.d294cdef7cc161633a02d3e62058be0ep-1,
    -0x1.257b1ep0
  },
  { // Entry 346
    0x1.d294cdef7cc161633a02d3e62058be0ep-1,
    0x1.257b1ep0
  },
  { // Entry 347
    -0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    -0x1.12bd92p0
  },
  { // Entry 348
    0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    0x1.12bd92p0
  },
  { // Entry 349
    -0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    -0x1.ea5c3ep-1
  },
  { // Entry 350
    0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    0x1.ea5c3ep-1
  },
  { // Entry 351
    -0x1.95f05153644d60b94d2f2e700dfd3a37p-1,
    -0x1.d4b87cp-1
  },
  { // Entry 352
    0x1.95f05153644d60b94d2f2e700dfd3a37p-1,
    0x1.d4b87cp-1
  },
  { // Entry 353
    -0x1.88647d8ad2e41fb7c0af0f64614c9993p-1,
    -0x1.bf14bap-1
  },
  { // Entry 354
    0x1.88647d8ad2e41fb7c0af0f64614c9993p-1,
    0x1.bf14bap-1
  },
  { // Entry 355
    -0x1.7a253f9f89a7d3e4f9c54638418e97f6p-1,
    -0x1.a970f8p-1
  },
  { // Entry 356
    0x1.7a253f9f89a7d3e4f9c54638418e97f6p-1,
    0x1.a970f8p-1
  },
  { // Entry 357
    -0x1.6b391b34aab828fbe7cd7dcaf9ef3bd6p-1,
    -0x1.93cd36p-1
  },
  { // Entry 358
    0x1.6b391b34aab828fbe7cd7dcaf9ef3bd6p-1,
    0x1.93cd36p-1
  },
  { // Entry 359
    -0x1.5ba6e2fb980d482cf00ede80f5597fb2p-1,
    -0x1.7e2974p-1
  },
  { // Entry 360
    0x1.5ba6e2fb980d482cf00ede80f5597fb2p-1,
    0x1.7e2974p-1
  },
  { // Entry 361
    -0x1.4b75b5954e718020900719e25a7ea93bp-1,
    -0x1.6885b2p-1
  },
  { // Entry 362
    0x1.4b75b5954e718020900719e25a7ea93bp-1,
    0x1.6885b2p-1
  },
  { // Entry 363
    -0x1.3aacfa510810054c52ae0b67d116eb40p-1,
    -0x1.52e1f0p-1
  },
  { // Entry 364
    0x1.3aacfa510810054c52ae0b67d116eb40p-1,
    0x1.52e1f0p-1
  },
  { // Entry 365
    -0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    -0x1.3d3e36p-1
  },
  { // Entry 366
    0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    0x1.3d3e36p-1
  },
  { // Entry 367
    -0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    -0x1.0a0b02p-1
  },
  { // Entry 368
    0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    0x1.0a0b02p-1
  },
  { // Entry 369
    -0x1.c853c704e3b94322031d6b47aef853c9p-2,
    -0x1.d8f720p-2
  },
  { // Entry 370
    0x1.c853c704e3b94322031d6b47aef853c9p-2,
    0x1.d8f720p-2
  },
  { // Entry 371
    -0x1.92aba8981b25deda4cc1817251723a1bp-2,
    -0x1.9dd83cp-2
  },
  { // Entry 372
    0x1.92aba8981b25deda4cc1817251723a1bp-2,
    0x1.9dd83cp-2
  },
  { // Entry 373
    -0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    -0x1.62b958p-2
  },
  { // Entry 374
    0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    0x1.62b958p-2
  },
  { // Entry 375
    -0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    -0x1.279a74p-2
  },
  { // Entry 376
    0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    0x1.279a74p-2
  },
  { // Entry 377
    -0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    -0x1.d8f720p-3
  },
  { // Entry 378
    0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    0x1.d8f720p-3
  },
  { // Entry 379
    -0x1.
"""


```
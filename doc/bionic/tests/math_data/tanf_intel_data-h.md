Response:
Let's break down the thought process for analyzing the provided C code snippet.

**1. Initial Understanding and Context:**

* **Identify the core information:** The prompt explicitly states this is a source code file named `tanf_intel_data.handroid` located in the `bionic/tests/math_data/` directory. It also clarifies that "bionic is Android's C library, math library, and dynamic linker."
* **Recognize the file type:** The `.handroid` extension is unusual for typical C/C++ source. The presence of `data_1_1_t` and the structure of the array suggest it's likely *data* rather than executable code. The "intel_data" part hints at architecture-specific data.
* **Infer the purpose:** Given it's in `math_data` and the name includes `tanf`, the most probable purpose is to store test data for the `tanf` function (tangent for floats). The "intel" part likely means these are test cases tailored for Intel architectures, or perhaps generated/validated using Intel's math libraries.

**2. Analyzing the Data Structure:**

* **`static data_1_1_t<float, float> g_tanf_intel_data[]`:**  This declares a static array named `g_tanf_intel_data`.
    * `static`:  Means the array has internal linkage (visible only within this compilation unit).
    * `data_1_1_t<float, float>`: This is a template likely defined elsewhere. It probably represents a pair of floats. The first `float` is likely the input to `tanf`, and the second `float` is the expected output.
    * `[]`:  Indicates it's an array.
* **The data within the array:**  The data is a series of brace-enclosed pairs of hexadecimal floating-point numbers.
    * `0x1.somethingp-N`: This is the standard hexadecimal floating-point literal format. `1.something` is the significand, and `p-N` is the exponent.
    * **Observation:**  Each entry has two floating-point values. The comments `// Entry N` are just index markers.

**3. Connecting to Android and `tanf`:**

* **`tanf` function:**  This is a standard C library function for calculating the tangent of a floating-point number. It's part of `libm` (the math library). Bionic provides its own implementation of `libm`.
* **Testing:**  Android's Bionic library needs rigorous testing to ensure accuracy and correctness across different architectures. This data file is likely used for *unit testing* the `tanf` implementation in Bionic's `libm`.

**4. Considering Dynamic Linking (as requested in the prompt, even though this specific file doesn't directly involve it):**

* The prompt asks about the dynamic linker. Even though this data file isn't directly linked, the context of Bionic is crucial.
* **`libm.so`:** The `tanf` function resides within the dynamically linked shared object library `libm.so`.
* **Dynamic Linker's Role:**  The dynamic linker (`linker` or `ld-android.so`) is responsible for loading `libm.so` into a process's address space at runtime and resolving the symbol `tanf`.

**5. Addressing Other Points in the Prompt (even if not directly apparent in this file):**

* **`libc` function implementation:** While this file *tests* `tanf`, it doesn't *implement* it. The implementation would be in other `.c` files within Bionic's math library.
* **Assumptions and Input/Output:**  The structure of the data strongly suggests:
    * **Input:** The first float in each pair.
    * **Output:** The second float in each pair (the expected result of `tanf` for the input).
* **User/Programming Errors:**  This data file helps *prevent* errors in the `tanf` implementation. Common errors when using `tanf` might involve:
    * Passing `NaN` (Not a Number) as input.
    * Passing infinity as input.
    * Expecting exact results due to floating-point precision limitations.
* **Android Framework/NDK Path:**  The prompt asks how Android reaches this data.
    * **NDK:** Developers using the NDK call `tanf` from their native code. This links against Bionic's `libm.so`.
    * **Framework:**  Higher-level Android framework code (written in Java/Kotlin) might indirectly call `tanf` through JNI (Java Native Interface) if native math operations are required.
    * **Testing Framework:** The most direct path to this data file is through Bionic's own testing infrastructure. A test program would load this data and compare the results of Bionic's `tanf` implementation against the expected values.

**6. Formulating the Summary (Part 1):**

Based on the above analysis, the summary focuses on the core purpose of the file: providing test data for the `tanf` function within Android's Bionic library. It highlights the data structure and its likely usage in unit testing.

**Self-Correction/Refinement During the Thought Process:**

* Initially, I might have been tempted to overthink the "dynamic linker" aspect for this specific file. However, recognizing the file's role as *data* clarifies that its interaction with the dynamic linker is indirect (it's used by code that *is* linked).
*  The `.handroid` extension might have initially caused confusion. Realizing it's a data file format and not standard C++ resolves this. It suggests a custom format used within the Android build system or testing framework.
* The hexadecimal floating-point format requires careful interpretation. Double-checking the meaning of the `p` notation is important for accurate understanding.

By following this systematic analysis, combining explicit information with reasonable inferences based on the context and file naming, we can arrive at a comprehensive understanding of the file's function.
这是对位于 `bionic/tests/math_data/tanf_intel_data.handroid` 的源代码文件的前半部分（共三部分）的功能归纳。

**功能归纳:**

这个文件 `tanf_intel_data.handroid` 的主要功能是**为 Android Bionic 库中的 `tanf` 函数（单精度浮点数正切函数）提供测试数据。**

具体来说，它包含一个静态数组 `g_tanf_intel_data`，该数组存储了一系列预定义的输入和期望输出的配对，用于测试 `tanf` 函数在特定输入下的计算结果是否正确。

**更详细的解释:**

* **测试数据：**  该文件本质上是一个测试用例的数据集。每个“Entry”都代表一个测试用例。
* **`data_1_1_t<float, float>` 类型：**  这是一种自定义的数据结构（可能在其他头文件中定义），用于存储一对单精度浮点数。根据数据内容推断，第一个 `float` 是 `tanf` 函数的输入值，第二个 `float` 是对于该输入值，`tanf` 函数应该返回的期望输出值。
* **`static` 关键字：**  `static` 关键字表明 `g_tanf_intel_data` 这个数组的作用域仅限于当前编译单元（即这个 `.handroid` 文件被转换成的 `.o` 文件）。这通常意味着这个数据是内部使用的，不会被其他编译单元直接访问。
* **`g_tanf_intel_data` 数组命名：**
    * `g_`:  通常表示全局变量。
    * `tanf`:  明确指明了这是用于 `tanf` 函数的数据。
    * `intel`:  暗示这些测试数据可能是针对 Intel 架构的优化或特定的数值边界情况。
    * `data`:  清晰地表明这是数据文件。

**与 Android 功能的关系举例说明：**

Android 的 Bionic 库提供了 `tanf` 函数的实现。这个数据文件用于验证 Bionic 库中 `tanf` 函数的正确性。

**举例：**

例如，第一条数据 `{ -0x1.00000000001555555555577777777777p-21, -0x1.p-21 }` 表示：

* 当 `tanf` 函数的输入为 `-0x1.00000000001555555555577777777777p-21` 时，
* 期望的输出结果是 `-0x1.p-21`。

Android 的测试系统会读取这个数据文件，将第一个浮点数作为输入传递给 Bionic 库的 `tanf` 函数，然后将 `tanf` 函数的实际输出与文件中存储的第二个浮点数进行比较，以判断 `tanf` 函数的实现是否正确。

**总结:**

这个 `tanf_intel_data.handroid` 文件是 Android Bionic 库测试体系的一部分，专注于为 `tanf` 函数提供精确的测试用例数据，以确保其在不同输入下的数值计算的准确性。 它的存在是为了提高 Android 底层数学库的可靠性。

### 提示词
```
这是目录为bionic/tests/math_data/tanf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_tanf_intel_data[] = {
  { // Entry 0
    -0x1.00000000001555555555577777777777p-21,
    -0x1.p-21
  },
  { // Entry 1
    0x1.00000000001555555555577777777777p-21,
    0x1.p-21
  },
  { // Entry 2
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 3
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 4
    -0x1.00000200000000000000155555d55556p-41,
    -0x1.000002p-41
  },
  { // Entry 5
    0x1.00000200000000000000155555d55556p-41,
    0x1.000002p-41
  },
  { // Entry 6
    -0x1.ffb7eb004b7e12b369388faaa0342f6cp-3,
    -0x1.27cca6p7
  },
  { // Entry 7
    0x1.ffb7eb004b7e12b369388faaa0342f6cp-3,
    0x1.27cca6p7
  },
  { // Entry 8
    -0x1.3b7ddaffdc9a2fad39f329743fbf49e5p4,
    -0x1.2a5996p2
  },
  { // Entry 9
    0x1.3b7ddaffdc9a2fad39f329743fbf49e5p4,
    0x1.2a5996p2
  },
  { // Entry 10
    0x1.819f32ffd97b1ed667bc143387037ddep-1,
    -0x1.3f7f22p1
  },
  { // Entry 11
    -0x1.819f32ffd97b1ed667bc143387037ddep-1,
    0x1.3f7f22p1
  },
  { // Entry 12
    -0x1.405f900000000000000a7402846583d0p-38,
    -0x1.405f90p-38
  },
  { // Entry 13
    0x1.405f900000000000000a7402846583d0p-38,
    0x1.405f90p-38
  },
  { // Entry 14
    -0x1.8cd79995344c7943c7b3e021607da3cbp-2,
    -0x1.496e80p96
  },
  { // Entry 15
    0x1.8cd79995344c7943c7b3e021607da3cbp-2,
    0x1.496e80p96
  },
  { // Entry 16
    0x1.e144471ea2b49b6c1fdceff8ccceea7bp10,
    -0x1.5fe0p3
  },
  { // Entry 17
    -0x1.e144471ea2b49b6c1fdceff8ccceea7bp10,
    0x1.5fe0p3
  },
  { // Entry 18
    -0x1.ca0f4c2315ab5a9729e6afa857677b3fp-1,
    -0x1.75aef0p-1
  },
  { // Entry 19
    0x1.ca0f4c2315ab5a9729e6afa857677b3fp-1,
    0x1.75aef0p-1
  },
  { // Entry 20
    -0x1.c33ed50b887775a5d613c08c488fbb9cp3,
    -0x1.80p0
  },
  { // Entry 21
    0x1.c33ed50b887775a5d613c08c488fbb9cp3,
    0x1.80p0
  },
  { // Entry 22
    -0x1.c34513ee7140fdb8217e83dc2d6d6f53p3,
    -0x1.800040p0
  },
  { // Entry 23
    0x1.c34513ee7140fdb8217e83dc2d6d6f53p3,
    0x1.800040p0
  },
  { // Entry 24
    0x1.4e6b8a48164b9e1d8175e4512ab22ff1p0,
    -0x1.8e3560p98
  },
  { // Entry 25
    -0x1.4e6b8a48164b9e1d8175e4512ab22ff1p0,
    0x1.8e3560p98
  },
  { // Entry 26
    -0x1.d017e0214a953265d8dd5c0a11ea61d1p-1,
    -0x1.9de7d4p4
  },
  { // Entry 27
    0x1.d017e0214a953265d8dd5c0a11ea61d1p-1,
    0x1.9de7d4p4
  },
  { // Entry 28
    -0x1.d0473f02270c0eec883e753e50800670p-1,
    -0x1.9de8a4p4
  },
  { // Entry 29
    0x1.d0473f02270c0eec883e753e50800670p-1,
    0x1.9de8a4p4
  },
  { // Entry 30
    0x1.d0aada22aa5e3dc35b5063c639047df5p-1,
    -0x1.be7e5ap5
  },
  { // Entry 31
    -0x1.d0aada22aa5e3dc35b5063c639047df5p-1,
    0x1.be7e5ap5
  },
  { // Entry 32
    -0x1.ee9495000a190cdb6db3e83d2c05ef38p-2,
    -0x1.ccbeb0p-2
  },
  { // Entry 33
    0x1.ee9495000a190cdb6db3e83d2c05ef38p-2,
    0x1.ccbeb0p-2
  },
  { // Entry 34
    0x1.dc32eba638d13458c7b29d96abffe1cap-7,
    -0x1.fffep127
  },
  { // Entry 35
    -0x1.dc32eba638d13458c7b29d96abffe1cap-7,
    0x1.fffep127
  },
  { // Entry 36
    0x1.00000000001555555555577777777777p-21,
    0x1.p-21
  },
  { // Entry 37
    -0x1.00000000001555555555577777777777p-21,
    -0x1.p-21
  },
  { // Entry 38
    0x1.p-131,
    0x1.p-131
  },
  { // Entry 39
    -0x1.p-131,
    -0x1.p-131
  },
  { // Entry 40
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 41
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 42
    0x1.52f50e757941cbff5b7c2e06a1ab7e9dp6,
    0x1.p63
  },
  { // Entry 43
    -0x1.52f50e757941cbff5b7c2e06a1ab7e9dp6,
    -0x1.p63
  },
  { // Entry 44
    0x1.00000200000000000000155555d55556p-41,
    0x1.000002p-41
  },
  { // Entry 45
    -0x1.00000200000000000000155555d55556p-41,
    -0x1.000002p-41
  },
  { // Entry 46
    -0x1.adb7eb6d8cebbe362f197dbeda5c113cp-1,
    0x1.000002p51
  },
  { // Entry 47
    0x1.adb7eb6d8cebbe362f197dbeda5c113cp-1,
    -0x1.000002p51
  },
  { // Entry 48
    0x1.f7762b752b006715d90c389a11826d6bp1,
    0x1.000004p127
  },
  { // Entry 49
    -0x1.f7762b752b006715d90c389a11826d6bp1,
    -0x1.000004p127
  },
  { // Entry 50
    -0x1.09cff10000671912c84762f18c285470p0,
    0x1.000090p7
  },
  { // Entry 51
    0x1.09cff10000671912c84762f18c285470p0,
    -0x1.000090p7
  },
  { // Entry 52
    0x1.015901017edb67aa7e52ae694e990a19p-3,
    0x1.000180p-3
  },
  { // Entry 53
    -0x1.015901017edb67aa7e52ae694e990a19p-3,
    -0x1.000180p-3
  },
  { // Entry 54
    0x1.0002200000000000000055577559d958p-40,
    0x1.000220p-40
  },
  { // Entry 55
    -0x1.0002200000000000000055577559d958p-40,
    -0x1.000220p-40
  },
  { // Entry 56
    0x1.6d53796cdd401e3ddc09e835b8ea660ap3,
    0x1.000380p127
  },
  { // Entry 57
    -0x1.6d53796cdd401e3ddc09e835b8ea660ap3,
    -0x1.000380p127
  },
  { // Entry 58
    -0x1.b070e3a6968463af6e9db922e7845524p-7,
    0x1.000880p9
  },
  { // Entry 59
    0x1.b070e3a6968463af6e9db922e7845524p-7,
    -0x1.000880p9
  },
  { // Entry 60
    -0x1.fa61dcffa3efe325b32704fc412462cfp1,
    0x1.0020p62
  },
  { // Entry 61
    0x1.fa61dcffa3efe325b32704fc412462cfp1,
    -0x1.0020p62
  },
  { // Entry 62
    0x1.fffd825a3f377f012209982a00c346f0p-2,
    0x1.0060p90
  },
  { // Entry 63
    -0x1.fffd825a3f377f012209982a00c346f0p-2,
    -0x1.0060p90
  },
  { // Entry 64
    0x1.013c68fff04b698165dfdf9d48444a95p-6,
    0x1.0137p-6
  },
  { // Entry 65
    -0x1.013c68fff04b698165dfdf9d48444a95p-6,
    -0x1.0137p-6
  },
  { // Entry 66
    0x1.932c994f61d804a084f20d975a617c50p0,
    0x1.014cp0
  },
  { // Entry 67
    -0x1.932c994f61d804a084f20d975a617c50p0,
    -0x1.014cp0
  },
  { // Entry 68
    -0x1.c34ec20533e760565cb762b15c18d6fcp1,
    0x1.020446p58
  },
  { // Entry 69
    0x1.c34ec20533e760565cb762b15c18d6fcp1,
    -0x1.020446p58
  },
  { // Entry 70
    0x1.9ff71767ea051e4e9cc0008922b11129p0,
    0x1.04e4p0
  },
  { // Entry 71
    -0x1.9ff71767ea051e4e9cc0008922b11129p0,
    -0x1.04e4p0
  },
  { // Entry 72
    0x1.07c9c5001659079722f8e9190ffe6ec6p-3,
    0x1.0658p-3
  },
  { // Entry 73
    -0x1.07c9c5001659079722f8e9190ffe6ec6p-3,
    -0x1.0658p-3
  },
  { // Entry 74
    0x1.fd611072a50357e6266768b2cdf0194cp-3,
    0x1.0ac710p100
  },
  { // Entry 75
    -0x1.fd611072a50357e6266768b2cdf0194cp-3,
    -0x1.0ac710p100
  },
  { // Entry 76
    0x1.0ddbb5000244c4fb972eb72de00896c0p-3,
    0x1.0c50p-3
  },
  { // Entry 77
    -0x1.0ddbb5000244c4fb972eb72de00896c0p-3,
    -0x1.0c50p-3
  },
  { // Entry 78
    -0x1.c0aeb5f84be95da5ab0716dfba205e28p2,
    0x1.0ddcp96
  },
  { // Entry 79
    0x1.c0aeb5f84be95da5ab0716dfba205e28p2,
    -0x1.0ddcp96
  },
  { // Entry 80
    0x1.340754fffffeb780761e86337f0c55efp1,
    0x1.0e28a6p4
  },
  { // Entry 81
    -0x1.340754fffffeb780761e86337f0c55efp1,
    -0x1.0e28a6p4
  },
  { // Entry 82
    0x1.349d95ffee472ec7c10934570d3ba486p-1,
    0x1.15bcp-1
  },
  { // Entry 83
    -0x1.349d95ffee472ec7c10934570d3ba486p-1,
    -0x1.15bcp-1
  },
  { // Entry 84
    0x1.eec72403a4fd24d0c9e2af088a05fb85p0,
    0x1.17e4p0
  },
  { // Entry 85
    -0x1.eec72403a4fd24d0c9e2af088a05fb85p0,
    -0x1.17e4p0
  },
  { // Entry 86
    0x1.ef4bd7a215237b3065d569fd4c5f5a47p0,
    0x1.18p0
  },
  { // Entry 87
    -0x1.ef4bd7a215237b3065d569fd4c5f5a47p0,
    -0x1.18p0
  },
  { // Entry 88
    -0x1.fe793900138c9941836b4fcbc9b2260dp-4,
    0x1.18p64
  },
  { // Entry 89
    0x1.fe793900138c9941836b4fcbc9b2260dp-4,
    -0x1.18p64
  },
  { // Entry 90
    0x1.f08f0873c5819a9f7cc6bbf3c5291cc0p0,
    0x1.1844p0
  },
  { // Entry 91
    -0x1.f08f0873c5819a9f7cc6bbf3c5291cc0p0,
    -0x1.1844p0
  },
  { // Entry 92
    0x1.5c51cc18f091bc4b54ee83623438c9a7p11,
    0x1.18fffep19
  },
  { // Entry 93
    -0x1.5c51cc18f091bc4b54ee83623438c9a7p11,
    -0x1.18fffep19
  },
  { // Entry 94
    0x1.2633567898e691eeb87ad026bd16a7e4p-2,
    0x1.1e7cp-2
  },
  { // Entry 95
    -0x1.2633567898e691eeb87ad026bd16a7e4p-2,
    -0x1.1e7cp-2
  },
  { // Entry 96
    0x1.ffffedf558bfb3100f61125f296b8badp1,
    0x1.1ebep18
  },
  { // Entry 97
    -0x1.ffffedf558bfb3100f61125f296b8badp1,
    -0x1.1ebep18
  },
  { // Entry 98
    0x1.0e551b00007fae17236421a76e861c75p1,
    0x1.20ea9cp0
  },
  { // Entry 99
    -0x1.0e551b00007fae17236421a76e861c75p1,
    -0x1.20ea9cp0
  },
  { // Entry 100
    0x1.c07dfb0552ba60b71c7df6bd7ca409d6p20,
    0x1.2106cap5
  },
  { // Entry 101
    -0x1.c07dfb0552ba60b71c7df6bd7ca409d6p20,
    -0x1.2106cap5
  },
  { // Entry 102
    -0x1.fd23fd64a4bfcfb597c46933649f5ae2p-2,
    0x1.219dc6p119
  },
  { // Entry 103
    0x1.fd23fd64a4bfcfb597c46933649f5ae2p-2,
    -0x1.219dc6p119
  },
  { // Entry 104
    -0x1.b93c13000d016d14e756c25e42302d9fp-3,
    0x1.26cd6ap3
  },
  { // Entry 105
    0x1.b93c13000d016d14e756c25e42302d9fp-3,
    -0x1.26cd6ap3
  },
  { // Entry 106
    -0x1.ebcbcb138b274cbcbe61af5113da83ecp-4,
    0x1.29c4e0p3
  },
  { // Entry 107
    0x1.ebcbcb138b274cbcbe61af5113da83ecp-4,
    -0x1.29c4e0p3
  },
  { // Entry 108
    0x1.99bc5b961b1b24fdb77fcee08ba2f720p-25,
    0x1.2d97c8p4
  },
  { // Entry 109
    -0x1.99bc5b961b1b24fdb77fcee08ba2f720p-25,
    -0x1.2d97c8p4
  },
  { // Entry 110
    -0x1.ed18af0b0ba80dfa6e8ee1b3b31dfc60p-1,
    0x1.30p1
  },
  { // Entry 111
    0x1.ed18af0b0ba80dfa6e8ee1b3b31dfc60p-1,
    -0x1.30p1
  },
  { // Entry 112
    0x1.9ab24111cfc62df4dbca320216b94651p-4,
    0x1.30ca70p3
  },
  { // Entry 113
    -0x1.9ab24111cfc62df4dbca320216b94651p-4,
    -0x1.30ca70p3
  },
  { // Entry 114
    0x1.337d8ffffffede62f050e98b3b9596e1p-3,
    0x1.3135f0p-3
  },
  { // Entry 115
    -0x1.337d8ffffffede62f050e98b3b9596e1p-3,
    -0x1.3135f0p-3
  },
  { // Entry 116
    0x1.348e650000002ef3a765b9416d12cf7ep-3,
    0x1.3240bcp-3
  },
  { // Entry 117
    -0x1.348e650000002ef3a765b9416d12cf7ep-3,
    -0x1.3240bcp-3
  },
  { // Entry 118
    -0x1.b9e58aec61a44ab533c2b83726367e17p-8,
    0x1.32d53cp16
  },
  { // Entry 119
    0x1.b9e58aec61a44ab533c2b83726367e17p-8,
    -0x1.32d53cp16
  },
  { // Entry 120
    -0x1.e1fd68edea44fb78780ed62e73c6e017p-6,
    0x1.3a0aa8p6
  },
  { // Entry 121
    0x1.e1fd68edea44fb78780ed62e73c6e017p-6,
    -0x1.3a0aa8p6
  },
  { // Entry 122
    -0x1.62a28100001393080f6733dfaf9c76fcp-1,
    0x1.4495bap1
  },
  { // Entry 123
    0x1.62a28100001393080f6733dfaf9c76fcp-1,
    -0x1.4495bap1
  },
  { // Entry 124
    0x1.b923c3ba0bc0c500ba4c245301bad207p1,
    0x1.49d42ap0
  },
  { // Entry 125
    -0x1.b923c3ba0bc0c500ba4c245301bad207p1,
    -0x1.49d42ap0
  },
  { // Entry 126
    0x1.541f3f00022ac25cc8a90855ab6bb808p-3,
    0x1.510bbcp-3
  },
  { // Entry 127
    -0x1.541f3f00022ac25cc8a90855ab6bb808p-3,
    -0x1.510bbcp-3
  },
  { // Entry 128
    0x1.76f3efffff3057122e6e7ce50d12cbcep-3,
    0x1.549520p100
  },
  { // Entry 129
    -0x1.76f3efffff3057122e6e7ce50d12cbcep-3,
    -0x1.549520p100
  },
  { // Entry 130
    0x1.4cac0300643e12c46203b47d3eeed4ffp-9,
    0x1.54c4bap24
  },
  { // Entry 131
    -0x1.4cac0300643e12c46203b47d3eeed4ffp-9,
    -0x1.54c4bap24
  },
  { // Entry 132
    -0x1.70d5450000058974c20b97ba96fdae03p-3,
    0x1.5a757ep24
  },
  { // Entry 133
    0x1.70d5450000058974c20b97ba96fdae03p-3,
    -0x1.5a757ep24
  },
  { // Entry 134
    -0x1.ffffe9bba7f1321fae192943a3e848c0p-1,
    0x1.5fdbc0p2
  },
  { // Entry 135
    0x1.ffffe9bba7f1321fae192943a3e848c0p-1,
    -0x1.5fdbc0p2
  },
  { // Entry 136
    -0x1.ffb68f0050dabe5ce719202610fcac2ep-1,
    0x1.5fe056p2
  },
  { // Entry 137
    0x1.ffb68f0050dabe5ce719202610fcac2ep-1,
    -0x1.5fe056p2
  },
  { // Entry 138
    -0x1.dabb46e3937e6c505ab2062232339a16p-7,
    0x1.6493d4p95
  },
  { // Entry 139
    0x1.dabb46e3937e6c505ab2062232339a16p-7,
    -0x1.6493d4p95
  },
  { // Entry 140
    0x1.c832162481e1ce4f01736bb97a3019b9p-1,
    0x1.74a566p-1
  },
  { // Entry 141
    -0x1.c832162481e1ce4f01736bb97a3019b9p-1,
    -0x1.74a566p-1
  },
  { // Entry 142
    0x1.7b2fa40000038d569226512c77976ff5p-3,
    0x1.76f0b2p-3
  },
  { // Entry 143
    -0x1.7b2fa40000038d569226512c77976ff5p-3,
    -0x1.76f0b2p-3
  },
  { // Entry 144
    -0x1.4f375ad9dee5fd604fb29435f32efe57p1,
    0x1.78b3fap100
  },
  { // Entry 145
    0x1.4f375ad9dee5fd604fb29435f32efe57p1,
    -0x1.78b3fap100
  },
  { // Entry 146
    -0x1.00005efffbe73e7bafeab7f76c8a93efp0,
    0x1.78fdb4p3
  },
  { // Entry 147
    0x1.00005efffbe73e7bafeab7f76c8a93efp0,
    -0x1.78fdb4p3
  },
  { // Entry 148
    -0x1.fc3ace000029c331692aa9fe4e42f004p-1,
    0x1.791cp3
  },
  { // Entry 149
    0x1.fc3ace000029c331692aa9fe4e42f004p-1,
    -0x1.791cp3
  },
  { // Entry 150
    0x1.dcfa3254b53b6a70cec4473abe850102p-1,
    0x1.7ffffep-1
  },
  { // Entry 151
    -0x1.dcfa3254b53b6a70cec4473abe850102p-1,
    -0x1.7ffffep-1
  },
  { // Entry 152
    0x1.c33ed50b887775a5d613c08c488fbb9cp3,
    0x1.80p0
  },
  { // Entry 153
    -0x1.c33ed50b887775a5d613c08c488fbb9cp3,
    -0x1.80p0
  },
  { // Entry 154
    0x1.8008p-130,
    0x1.8008p-130
  },
  { // Entry 155
    -0x1.8008p-130,
    -0x1.8008p-130
  },
  { // Entry 156
    -0x1.f96370ec482d2bb0eb8ea7a530139fcfp-5,
    0x1.8180p83
  },
  { // Entry 157
    0x1.f96370ec482d2bb0eb8ea7a530139fcfp-5,
    -0x1.8180p83
  },
  { // Entry 158
    -0x1.fff664faa6f86fa8b4e5e2719d2195cfp-1,
    0x1.89e090p9
  },
  { // Entry 159
    0x1.fff664faa6f86fa8b4e5e2719d2195cfp-1,
    -0x1.89e090p9
  },
  { // Entry 160
    0x1.1c051101643be740782fe0dfc9dcd1ccp0,
    0x1.8c631ep15
  },
  { // Entry 161
    -0x1.1c051101643be740782fe0dfc9dcd1ccp0,
    -0x1.8c631ep15
  },
  { // Entry 162
    0x1.bb2e88f26b9363f9a852665f3413d994p13,
    0x1.8c67fep127
  },
  { // Entry 163
    -0x1.bb2e88f26b9363f9a852665f3413d994p13,
    -0x1.8c67fep127
  },
  { // Entry 164
    -0x1.f0e4ec133585cb30e67cfcbb36faad8ep1,
    0x1.91d858p12
  },
  { // Entry 165
    0x1.f0e4ec133585cb30e67cfcbb36faad8ep1,
    -0x1.91d858p12
  },
  { // Entry 166
    -0x1.5d14946dc98975d6421a55284fe020a1p24,
    0x1.921fb6p0
  },
  { // Entry 167
    0x1.5d14946dc98975d6421a55284fe020a1p24,
    -0x1.921fb6p0
  },
  { // Entry 168
    0x1.980ee0cfbf0f1ebc9d4fd24cce3cdfe7p15,
    0x1.922922p15
  },
  { // Entry 169
    -0x1.980ee0cfbf0f1ebc9d4fd24cce3cdfe7p15,
    -0x1.922922p15
  },
  { // Entry 170
    -0x1.fd43f8e891e227ddad2fb2e5520d4ff2p-1,
    0x1.9230fep15
  },
  { // Entry 171
    0x1.fd43f8e891e227ddad2fb2e5520d4ff2p-1,
    -0x1.9230fep15
  },
  { // Entry 172
    0x1.cf38f6212e7e6276f4add54878f1a7dbp-1,
    0x1.9510c8p6
  },
  { // Entry 173
    -0x1.cf38f6212e7e6276f4add54878f1a7dbp-1,
    -0x1.9510c8p6
  },
  { // Entry 174
    0x1.d03d45024c3ca4a2c4e1a91856135046p-1,
    0x1.9511e6p6
  },
  { // Entry 175
    -0x1.d03d45024c3ca4a2c4e1a91856135046p-1,
    -0x1.9511e6p6
  },
  { // Entry 176
    0x1.0554eb5cbd393e4f0770c86528f39ee1p17,
    0x1.979f24p9
  },
  { // Entry 177
    -0x1.0554eb5cbd393e4f0770c86528f39ee1p17,
    -0x1.979f24p9
  },
  { // Entry 178
    0x1.fad5df93de3051cf018ab32c0b323571p-1,
    0x1.a1e862p119
  },
  { // Entry 179
    -0x1.fad5df93de3051cf018ab32c0b323571p-1,
    -0x1.a1e862p119
  },
  { // Entry 180
    0x1.ff981b1534f78016bea4d9588254e996p3,
    0x1.ad1fp63
  },
  { // Entry 181
    -0x1.ff981b1534f78016bea4d9588254e996p3,
    -0x1.ad1fp63
  },
  { // Entry 182
    -0x1.fff4a1db1e1e38c438ddd38bb94f6d31p1,
    0x1.ada3dap39
  },
  { // Entry 183
    0x1.fff4a1db1e1e38c438ddd38bb94f6d31p1,
    -0x1.ada3dap39
  },
  { // Entry 184
    0x1.d01529023d951390200a4252f038b4afp-1,
    0x1.b125bap5
  },
  { // Entry 185
    -0x1.d01529023d951390200a4252f038b4afp-1,
    -0x1.b125bap5
  },
  { // Entry 186
    0x1.d67fa105f76868612c84f74a1f38f0acp-2,
    0x1.b90a02p-2
  },
  { // Entry 187
    -0x1.d67fa105f76868612c84f74a1f38f0acp-2,
    -0x1.b90a02p-2
  },
  { // Entry 188
    0x1.99663da94dbd57199cb8e3dae7018358p-23,
    0x1.beeeeep80
  },
  { // Entry 189
    -0x1.99663da94dbd57199cb8e3dae7018358p-23,
    -0x1.beeeeep80
  },
  { // Entry 190
    0x1.eb96571eb9da1337e703cc20e41e9719p-13,
    0x1.c3abf0p24
  },
  { // Entry 191
    -0x1.eb96571eb9da1337e703cc20e41e9719p-13,
    -0x1.c3abf0p24
  },
  { // Entry 192
    0x1.e198c48bef954151ee075815d85c5363p0,
    0x1.c71c74p116
  },
  { // Entry 193
    -0x1.e198c48bef954151ee075815d85c5363p0,
    -0x1.c71c74p116
  },
  { // Entry 194
    -0x1.e50e524610728cfb239cc6305b212fd6p-1,
    0x1.cc3252p18
  },
  { // Entry 195
    0x1.e50e524610728cfb239cc6305b212fd6p-1,
    -0x1.cc3252p18
  },
  { // Entry 196
    -0x1.6a69e7bb21b52030964bc21ced077c71p19,
    0x1.d38a2ap19
  },
  { // Entry 197
    0x1.6a69e7bb21b52030964bc21ced077c71p19,
    -0x1.d38a2ap19
  },
  { // Entry 198
    0x1.6529bf81b958ca781cdaac7cec6e636ep0,
    0x1.df0648p24
  },
  { // Entry 199
    -0x1.6529bf81b958ca781cdaac7cec6e636ep0,
    -0x1.df0648p24
  },
  { // Entry 200
    0x1.659e43b4315f21ba5e7048b1d8d7815cp0,
    0x1.df2204p24
  },
  { // Entry 201
    -0x1.659e43b4315f21ba5e7048b1d8d7815cp0,
    -0x1.df2204p24
  },
  { // Entry 202
    -0x1.71a580ffc4e167ae0ef8b02d5d27c99dp-1,
    0x1.df34p24
  },
  { // Entry 203
    0x1.71a580ffc4e167ae0ef8b02d5d27c99dp-1,
    -0x1.df34p24
  },
  { // Entry 204
    0x1.ecf119000017a2caef4290b4d6c63785p-4,
    0x1.ea951ap-4
  },
  { // Entry 205
    -0x1.ecf119000017a2caef4290b4d6c63785p-4,
    -0x1.ea951ap-4
  },
  { // Entry 206
    0x1.ccd55821fad69755c2d824be2bfd4c64p-1,
    0x1.efedc6p1
  },
  { // Entry 207
    -0x1.ccd55821fad69755c2d824be2bfd4c64p-1,
    -0x1.efedc6p1
  },
  { // Entry 208
    0x1.d6981efffff2549634686a24dfda77cep-1,
    0x1.f143a2p1
  },
  { // Entry 209
    -0x1.d6981efffff2549634686a24dfda77cep-1,
    -0x1.f143a2p1
  },
  { // Entry 210
    0x1.dba4d1124a78a6803a0965af0ab79f88p3,
    0x1.f25b06p2
  },
  { // Entry 211
    -0x1.dba4d1124a78a6803a0965af0ab79f88p3,
    -0x1.f25b06p2
  },
  { // Entry 212
    -0x1.6dfcbaffd78023ecfabbf7ccf0a0e4b4p-1,
    0x1.f32218p24
  },
  { // Entry 213
    0x1.6dfcbaffd78023ecfabbf7ccf0a0e4b4p-1,
    -0x1.f32218p24
  },
  { // Entry 214
    -0x1.ec35cf000061079295ead714892db1cap1,
    0x1.f44dbcp58
  },
  { // Entry 215
    0x1.ec35cf000061079295ead714892db1cap1,
    -0x1.f44dbcp58
  },
  { // Entry 216
    0x1.db06c10d2a959715bc0a2e75e6da093bp4,
    0x1.f47ffep2
  },
  { // Entry 217
    -0x1.db06c10d2a959715bc0a2e75e6da093bp4,
    -0x1.f47ffep2
  },
  { // Entry 218
    0x1.ffffeb55643b9a648c2720bde1d22764p-1,
    0x1.f6a7a0p1
  },
  { // Entry 219
    -0x1.ffffeb55643b9a648c2720bde1d22764p-1,
    -0x1.f6a7a0p1
  },
  { // Entry 220
    0x1.c0a570ffffd379d0972ea78cd040c304p-3,
    0x1.f6ded8p8
  },
  { // Entry 221
    -0x1.c0a570ffffd379d0972ea78cd040c304p-3,
    -0x1.f6ded8p8
  },
  { // Entry 222
    -0x1.cdf18d01234809a6895315e9de59d864p-1,
    0x1.f7ffbep15
  },
  { // Entry 223
    0x1.cdf18d01234809a6895315e9de59d864p-1,
    -0x1.f7ffbep15
  },
  { // Entry 224
    -0x1.82f196fb60a81dc3b4dcbbc831ab8f85p-1,
    0x1.f7fffep47
  },
  { // Entry 225
    0x1.82f196fb60a81dc3b4dcbbc831ab8f85p-1,
    -0x1.f7fffep47
  },
  { // Entry 226
    0x1.6c03590f3fe3b7d29e89ee0e65fc9b1ep0,
    0x1.f87d58p24
  },
  { // Entry 227
    -0x1.6c03590f3fe3b7d29e89ee0e65fc9b1ep0,
    -0x1.f87d58p24
  },
  { // Entry 228
    -0x1.c7ae6e9c145b8d54f7719893fa03849fp27,
    0x1.f9cbe2p7
  },
  { // Entry 229
    0x1.c7ae6e9c145b8d54f7719893fa03849fp27,
    -0x1.f9cbe2p7
  },
  { // Entry 230
    0x1.6d2910005161b2bfa61134d0fbc9e9c0p0,
    0x1.fd86bcp24
  },
  { // Entry 231
    -0x1.6d2910005161b2bfa61134d0fbc9e9c0p0,
    -0x1.fd86bcp24
  },
  { // Entry 232
    0x1.6c8f8d0c3ad4bbb639a3f3a94237f69fp0,
    0x1.fefa4ap24
  },
  { // Entry 233
    -0x1.6c8f8d0c3ad4bbb639a3f3a94237f69fp0,
    -0x1.fefa4ap24
  },
  { // Entry 234
    0x1.00e5b5fffa13f7d9c4b0b52fe11a339bp-3,
    0x1.ff1ffep-4
  },
  { // Entry 235
    -0x1.00e5b5fffa13f7d9c4b0b52fe11a339bp-3,
    -0x1.ff1ffep-4
  },
  { // Entry 236
    0x1.ff3f41f01c5b360cce75b67877ffd677p0,
    0x1.ff7ffep41
  },
  { // Entry 237
    -0x1.ff3f41f01c5b360cce75b67877ffd677p0,
    -0x1.ff7ffep41
  },
  { // Entry 238
    -0x1.86dd5e00d7edc7266969bf5198438babp0,
    0x1.ff9ffep12
  },
  { // Entry 239
    0x1.86dd5e00d7edc7266969bf5198438babp0,
    -0x1.ff9ffep12
  },
  { // Entry 240
    -0x1.f8fe4579fdee2491c7d8572ea512fe93p5,
    0x1.fffbfep45
  },
  { // Entry 241
    0x1.f8fe4579fdee2491c7d8572ea512fe93p5,
    -0x1.fffbfep45
  },
  { // Entry 242
    -0x1.85ff462f0f86ff44641305da18ea8fc8p-13,
    0x1.fffdf2p23
  },
  { // Entry 243
    0x1.85ff462f0f86ff44641305da18ea8fc8p-13,
    -0x1.fffdf2p23
  },
  { // Entry 244
    0x1.3392e2ffbcb25fc1b016b9136e69c00bp-2,
    0x1.fffdfep3
  },
  { // Entry 245
    -0x1.3392e2ffbcb25fc1b016b9136e69c00bp-2,
    -0x1.fffdfep3
  },
  { // Entry 246
    -0x1.2f6c4bd2605f037f8609819f865a8dcbp8,
    0x1.fffe3ep41
  },
  { // Entry 247
    0x1.2f6c4bd2605f037f8609819f865a8dcbp8,
    -0x1.fffe3ep41
  },
  { // Entry 248
    -0x1.53a2e90e817727255e6ddf64e28c019cp-9,
    0x1.fffe7ep103
  },
  { // Entry 249
    0x1.53a2e90e817727255e6ddf64e28c019cp-9,
    -0x1.fffe7ep103
  },
  { // Entry 250
    -0x1.b34676f095b5b1a325426cdf42c04799p2,
    0x1.ffff7ep2
  },
  { // Entry 251
    0x1.b34676f095b5b1a325426cdf42c04799p2,
    -0x1.ffff7ep2
  },
  { // Entry 252
    0x1.f640d94e6241db4349e33bed67cbd3dbp-1,
    0x1.ffff7ep119
  },
  { // Entry 253
    -0x1.f640d94e6241db4349e33bed67cbd3dbp-1,
    -0x1.ffff7ep119
  },
  { // Entry 254
    0x1.526c269bdda8a89d90706870f3801eafp-1,
    0x1.ffffeep4
  },
  { // Entry 255
    -0x1.526c269bdda8a89d90706870f3801eafp-1,
    -0x1.ffffeep4
  },
  { // Entry 256
    -0x1.a37593c105e1462c2a37260603483da6p1,
    0x1.fffffcp12
  },
  { // Entry 257
    0x1.a37593c105e1462c2a37260603483da6p1,
    -0x1.fffffcp12
  },
  { // Entry 258
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 259
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 260
    0.0,
    0.0
  },
  { // Entry 261
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 262
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 263
    -0x1.000002p-126,
    -0x1.000002p-126
  },
  { // Entry 264
    0x1.000002p-126,
    0x1.000002p-126
  },
  { // Entry 265
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 266
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 267
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 268
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 269
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 270
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 271
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 272
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 273
    0x1.000002p-126,
    0x1.000002p-126
  },
  { // Entry 274
    -0x1.000002p-126,
    -0x1.000002p-126
  },
  { // Entry 275
    0x1.99999a57619f679b6193af8a0a7a8778p-13,
    0x1.99999ap-13
  },
  { // Entry 276
    -0x1.99999a57619f679b6193af8a0a7a8778p-13,
    -0x1.99999ap-13
  },
  { // Entry 277
    0x1.99999b5d867eaadd0305587399905311p-12,
    0x1.99999ap-12
  },
  { // Entry 278
    -0x1.99999b5d867eaadd0305587399905311p-12,
    -0x1.99999ap-12
  },
  { // Entry 279
    0x1.3333364dd2fb949645bea998cbc1ee72p-11,
    0x1.333334p-11
  },
  { // Entry 280
    -0x1.3333364dd2fb949645bea998cbc1ee72p-11,
    -0x1.333334p-11
  },
  { // Entry 281
    0x1.99999f761a0b726c18b00c6496cbe10dp-11,
    0x1.99999ap-11
  },
  { // Entry 282
    -0x1.99999f761a0b726c18b00c6496cbe10dp-11,
    -0x1.99999ap-11
  },
  { // Entry 283
    0x1.000005555577777854854dedc28ead51p-10,
    0x1.p-10
  },
  { // Entry 284
    -0x1.000005555577777854854dedc28ead51p-10,
    -0x1.p-10
  },
  { // Entry 285
    0x1.33333d374c2e05d108161378389fc84fp-10,
    0x1.333334p-10
  },
  { // Entry 286
    -0x1.33333d374c2e05d108161378389fc84fp-10,
    -0x1.333334p-10
  },
  { // Entry 287
    0x1.666676a27a6d8214d198b2321ef9a9dcp-10,
    0x1.666668p-10
  },
  { // Entry 288
    -0x1.666676a27a6d8214d198b2321ef9a9dcp-10,
    -0x1.666668p-10
  },
  { // Entry 289
    0x1.9999b1d8698c24cfe3b90ffd006ffdcap-10,
    0x1.99999cp-10
  },
  { // Entry 290
    -0x1.9999b1d8698c24cfe3b90ffd006ffdcap-10,
    -0x1.99999cp-10
  },
  { // Entry 291
    0x1.cccceb1aa219f71bb19208d74a739bb1p-10,
    0x1.ccccccp-10
  },
  { // Entry 292
    -0x1.cccceb1aa219f71bb19208d74a739bb1p-10,
    -0x1.ccccccp-10
  },
  { // Entry 293
    0x1.0667d5968bbbbe4037024b9c93f7b049p-7,
    0x1.066666p-7
  },
  { // Entry 294
    -0x1.0667d5968bbbbe4037024b9c93f7b049p-7,
    -0x1.066666p-7
  },
  { // Entry 295
    0x1.ccd492d035a227758b8c30d79b168826p-7,
    0x1.ccccccp-7
  },
  { // Entry 296
    -0x1.ccd492d035a227758b8c30d79b168826p-7,
    -0x1.ccccccp-7
  },
  { // Entry 297
    0x1.49a4fa68e90d228f445026eb29adcefdp-6,
    0x1.499998p-6
  },
  { // Entry 298
    -0x1.49a4fa68e90d228f445026eb29adcefdp-6,
    -0x1.499998p-6
  },
  { // Entry 299
    0x1.ace5de090603fda8f519afece05c17eap-6,
    0x1.acccccp-6
  },
  { // Entry 300
    -0x1.ace5de090603fda8f519afece05c17eap-6,
    -0x1.acccccp-6
  },
  { // Entry 301
    0x1.081767fd3cb685f7b069146ce3333851p-5,
    0x1.08p-5
  },
  { // Entry 302
    -0x1.081767fd3cb685f7b069146ce3333851p-5,
    -0x1.08p-5
  },
  { // Entry 303
    0x1.39c0d745334a3387d672e4a05624bca5p-5,
    0x1.39999ap-5
  },
  { // Entry 304
    -0x1.39c0d745334a3387d672e4a05624bca5p-5,
    -0x1.39999ap-5
  },
  { // Entry 305
    0x1.6b702c627fc00b777ea8661cce36061cp-5,
    0x1.6b3334p-5
  },
  { // Entry 306
    -0x1.6b702c627fc00b777ea8661cce36061cp-5,
    -0x1.6b3334p-5
  },
  { // Entry 307
    0x1.9d26574cd84759bfff51d8bb18538a0dp-5,
    0x1.9ccccep-5
  },
  { // Entry 308
    -0x1.9d26574cd84759bfff51d8bb18538a0dp-5,
    -0x1.9ccccep-5
  },
  { // Entry 309
    0x1.cee4467e15bb7ef59658a8eddc195167p-5,
    0x1.ce6666p-5
  },
  { // Entry 310
    -0x1.cee4467e15bb7ef59658a8eddc195167p-5,
    -0x1.ce6666p-5
  },
  { // Entry 311
    0x1.a1eaed7aa62a740c0b2e09bcd0f735b5p-1,
    0x1.5e7fc4p-1
  },
  { // Entry 312
    -0x1.a1eaed7aa62a740c0b2e09bcd0f735b5p-1,
    -0x1.5e7fc4p-1
  },
  { // Entry 313
    0x1.d93b891cbcb15aac8b5796a0a16bf29ep1,
    0x1.4e7fc4p0
  },
  { // Entry 314
    -0x1.d93b891cbcb15aac8b5796a0a16bf29ep1,
    -0x1.4e7fc4p0
  },
  { // Entry 315
    -0x1.563ad063486c797653a68955c0bb1c0bp1,
    0x1.edbfa6p0
  },
  { // Entry 316
    0x1.563ad063486c797653a68955c0bb1c0bp1,
    -0x1.edbfa6p0
  },
  { // Entry 317
    -0x1.576b789d544b6d037c3b7119fd6dd6p-1,
    0x1.467fc4p1
  },
  { // Entry 318
    0x1.576b789d544b6d037c3b7119fd6dd6p-1,
    -0x1.467fc4p1
  },
  { // Entry 319
    0x1.00150652b2d7931e0c878875b9f4ba82p-5,
    0x1.961fb4p1
  },
  { // Entry 320
    -0x1.00150652b2d7931e0c878875b9f4ba82p-5,
    -0x1.961fb4p1
  },
  { // Entry 321
    0x1.87e987b6e5071dbd3f755a76a27d8fc8p-1,
    0x1.e5bfa4p1
  },
  { // Entry 322
    -0x1.87e987b6e5071dbd3f755a76a27d8fc8p-1,
    -0x1.e5bfa4p1
  },
  { // Entry 323
    0x1.a49e55bce1c8991232387ecd1124698ap1,
    0x1.1aafcap2
  },
  { // Entry 324
    -0x1.a49e55bce1c8991232387ecd1124698ap1,
    -0x1.1aafcap2
  },
  { // Entry 325
    -0x1.79cf03135a93679d5aa2e1dcc5adedafp1,
    0x1.427fc2p2
  },
  { // Entry 326
    0x1.79cf03135a93679d5aa2e1dcc5adedafp1,
    -0x1.427fc2p2
  },
  { // Entry 327
    -0x1.6f1f86fdb20bc9923627b94d771f5388p-1,
    0x1.6a4fbap2
  },
  { // Entry 328
    0x1.6f1f86fdb20bc9923627b94d771f5388p-1,
    -0x1.6a4fbap2
  },
  { // Entry 329
    -0x1.67747ca802821c66c87a086638f28d36p-1,
    0x1.6af2f0p2
  },
  { // Entry 330
    0x1.67747ca802821c66c87a086638f28d36p-1,
    -0x1.6af2f0p2
  },
  { // Entry 331
    -0x1.626a30298df0c42c2cf7a8f9c166d55dp1,
    0x1.43c62ap2
  },
  { // Entry 332
    0x1.626a30298df0c42c2cf7a8f9c166d55dp1,
    -0x1.43c62ap2
  },
  { // Entry 333
    0x1.d6ad8a22a4407cc68df20cda1ea1c6aap1,
    0x1.1c9964p2
  },
  { // Entry 334
    -0x1.d6ad8a22a4407cc68df20cda1ea1c6aap1,
    -0x1.1c9964p2
  },
  { // Entry 335
    0x1.a94d00a1710d9bcc7b80481f42857d05p-1,
    0x1.ead93cp1
  },
  { // Entry 336
    -0x1.a94d00a1710d9bcc7b80481f42857d05p-1,
    -0x1.ead93cp1
  },
  { // Entry 337
    0x1.4cb9f4d315a995b28bfbd6e6a0905738p-4,
    0x1.9c7fb0p1
  },
  { // Entry 338
    -0x1.4cb9f4d315a995b28bfbd6e6a0905738p-4,
    -0x1.9c7fb0p1
  },
  { // Entry 339
    -0x1.2cb6f3ba51cd4ca385d7f4a7567c3a0bp-1,
    0x1.4e2624p1
  },
  { // Entry 340
    0x1.2cb6f3ba51cd4ca385d7f4a7567c3a0bp-1,
    -0x1.4e2624p1
  },
  { // Entry 341
    -0x1.18d9399a8290b3f8b42a4afc1f4b21dep1,
    0x1.ff9932p0
  },
  { // Entry 342
    0x1.18d9399a8290b3f8b42a4afc1f4b21dep1,
    -0x1.ff9932p0
  },
  { // Entry 343
    0x1.56fd94b0c0681613d3831608457f5bf6p2,
    0x1.62e61cp0
  },
  { // Entry 344
    -0x1.56fd94b0c0681613d3831608457f5bf6p2,
    -0x1.62e61cp0
  },
  { // Entry 345
    0x1.f4ad37f13e818641fc1555bf78e0e942p-1,
    0x1.8c662cp-1
  },
  { // Entry 346
    -0x1.f4ad37f13e818641fc1555bf78e0e942p-1,
    -0x1.8c662cp-1
  },
  { // Entry 347
    0x1.6a7e30ad8460f1a710479e2db9495c9cp3,
    -0x1.a8aa1cp0
  },
  { // Entry 348
    -0x1.6a7e30ad8460f1a710479e2db9495c9cp3,
    0x1.a8aa1cp0
  },
  { // Entry 349
    0x1.0d71ffac1d5e6aa753cf804a2a8c1f5bp6,
    -0x1.95ec8ap0
  },
  { // Entry 350
    -0x1.0d71ffac1d5e6aa753cf804a2a8c1f5bp6,
    0x1.95ec8ap0
  },
  { // Entry 351
    -0x1.11d8498073e1f4b776fe5672abb1f54ap4,
    -0x1.832ef8p0
  },
  { // Entry 352
    0x1.11d8498073e1f4b776fe5672abb1f54ap4,
    0x1.832ef8p0
  },
  { // Entry 353
    -0x1.e3a34b32708883a8578805f84ea03c6ap2,
    -0x1.707166p0
  },
  { // Entry 354
    0x1.e3a34b32708883a8578805f84ea03c6ap2,
    0x1.707166p0
  },
  { // Entry 355
    -0x1.3429d2634054eaae3bdbee94a6cec17fp2,
    -0x1.5db3d4p0
  },
  { // Entry 356
    0x1.3429d2634054eaae3bdbee94a6cec17fp2,
    0x1.5db3d4p0
  },
  { // Entry 357
    -0x1.c08c957bbb45acafa856bfd792cbf663p1,
    -0x1.4af642p0
  },
  { // Entry 358
    0x1.c08c957bbb45acafa856bfd792cbf663p1,
    0x1.4af642p0
  },
  { // Entry 359
    -0x1.5d602b0d0bdda825221a53369c5338d7p1,
    -0x1.3838b0p0
  },
  { // Entry 360
    0x1.5d602b0d0bdda825221a53369c5338d7p1,
    0x1.3838b0p0
  },
  { // Entry 361
    -0x1.1b4894e498720ec01735a02e55eefad8p1,
    -0x1.257b1ep0
  },
  { // Entry 362
    0x1.1b4894e498720ec01735a02e55eefad8p1,
    0x1.257b1ep0
  },
  { // Entry 363
    -0x1.d74cb200ab59040290627a9b2ffe29cfp0,
    -0x1.12bd92p0
  },
  { // Entry 364
    0x1.d74cb200ab59040290627a9b2ffe29cfp0,
    0x1.12bd92p0
  },
  { // Entry 365
    -0x1.6be7019f34d34f25cb0c14d0c7bc7b32p0,
    -0x1.ea5c3ep-1
  },
  { // Entry 366
    0x1.6be7019f34d34f25cb0c14d0c7bc7b32p0,
    0x1.ea5c3ep-1
  },
  { // Entry 367
    -0x1.4d0defbcb48aa75ce13e1b82f1fcb049p0,
    -0x1.d4b87cp-1
  },
  { // Entry 368
    0x1.4d0defbcb48aa75ce13e1b82f1fcb049p0,
    0x1.d4b87cp-1
  },
  { // Entry 369
    -0x1.316c87fdb7599cb57354e4b99f38d7ffp0,
    -0x1.bf14bap-1
  },
  { // Entry 370
    0x1.316c87fdb7599cb57354e4b99f38d7ffp0,
    0x1.bf14bap-1
  },
  { // Entry 371
    -0x1.18729dfe51dfcf767f79f39b689ae95ep0,
    -0x1.a970f8p-1
  },
  { // Entry 372
    0x1.18729dfe51dfcf767f79f39b689ae95ep0,
    0x1.a970f8p-1
  },
  { // Entry 373
    -0x1.01aeea9cbe9a8fb4ccef99ad961b6ad8p0,
    -0x1.93cd36p-1
  },
  { // Entry 374
    0x1.01aeea9cbe9a8fb4ccef99ad961b6ad8p0,
    0x1.93cd36p-1
  },
  { // Entry 375
    -0x1.d98e373faad7da3d6c8865a7ff9ba7f3p-1,
    -0x1.7e2974p-1
  },
  { // Entry 376
    0x1.d98e373faad7da3d6c8865a7ff9ba7f3p-1,
    0x1.7e2974p-1
  },
  { // Entry 377
    -0x1.b2e46af704eb75d1fab0766afc74703fp-1,
    -0x1.6885b2p-1
  },
  { // Entry 378
    0x1.b2e46af704eb75d1fab0766afc74703fp-1,
    0x1.6885b2p-1
  },
  { // Entry 379
    -0x1.8ee90b7dc89b1f999ae6dbb41baceb0dp-1,
    -0x1.52e1f0p-1
  },
  { // Entry 380
    0x1.8ee90b7dc89b1f999ae6dbb41baceb0dp-1,
    0x1.52e1f0p-1
  },
  { // Entry 381
    -0x1.6d395f05820b42f51223dab884367e71p-1,
    -0x1.3d3e36p-1
  },
  { // Entry 382
    0x1.6d395f05820b42f51223dab884367e71p-1,
    0x1.3d3e36p-1
  },
  { // Entry 383
    -0x1.24e3dfad4ce1493caa123864cb4f45d3p-1,
    -0x1.0a0b02p-1
  },
  { // Entry 384
    0x1.24e3dfad4ce1493caa123864cb4f45d3p-1,
    0x1.0a0b02p-1
  },
  { // Entry 385
    -0x1.fdbd5e53e0a6fc9c8b803289f1c3dbb7p-2,
    -0x1.d8f720p-2
  },
  { // Entry 386
    0x1.fdbd5e53e0a6fc9c8b803289f1c3dbb7p-2,
    0x1.d8f720p-2
  },
  { // Entry 387
    -0x1.b5
```
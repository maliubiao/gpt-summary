Response:
My thinking process to answer the prompt, focusing on the first part's summarization, went something like this:

1. **Understand the Core Task:** The prompt asks for a summary of the provided C code snippet. It's crucial to identify what this code *is*.

2. **Identify Key Information in the Prompt:**  The prompt itself provides context:
    * File path: `bionic/tests/math_data/atanf_intel_data.handroid`
    * `bionic` is Android's C library, math library, and dynamic linker.
    * The file name contains `atanf`, `intel_data`, and `.handroid`.

3. **Analyze the Code Structure:**  I scanned the code and immediately noticed:
    * A `static` global array: `g_atanf_intel_data`.
    * The array's type: `data_1_1_t<float, float>`. This strongly suggests pairs of floating-point numbers.
    * The content of the array:  Numerous entries enclosed in `{}`.
    * The format of the entries: Each entry contains two hexadecimal floating-point numbers, often with one being negative and the corresponding one being positive. The comments like "// Entry 0", "// Entry 1", etc., are simply index markers.

4. **Infer the Purpose Based on Keywords:**
    * `atanf`: This is a standard C library function for calculating the arctangent (inverse tangent) of a float.
    * `intel_data`: This suggests the data might be specific to Intel architectures or generated/used in a context related to Intel.
    * `.handroid`: The `.handroid` extension, within the `bionic/tests` context, strongly indicates this is test data specifically for the Android C library.

5. **Formulate an Initial Hypothesis:** Based on the above, my initial hypothesis would be:  This file contains test data for the `atanf` function in Android's C library. The data likely consists of input/output pairs for testing the accuracy of the `atanf` implementation.

6. **Refine the Hypothesis by Examining the Data:**  Looking closer at the number pairs, I noticed:
    * The first number in each pair looks like an input value for `atanf`.
    * The second number looks like the expected output (the arctangent).
    * The positive/negative pairs suggest testing the behavior of `atanf` for both positive and negative inputs.
    * The sheer number of entries implies thorough testing across a range of input values.
    * The `p-` notation in the hexadecimal floats indicates they are represented in base-2 scientific notation.

7. **Connect to Android's Purpose:**  Knowing that `bionic` is Android's C library, this data is clearly used to ensure the correctness and robustness of the `atanf` function within the Android operating system. This is crucial for applications relying on accurate mathematical calculations.

8. **Construct the Summary:**  Based on the refined hypothesis, I would construct the summary, explicitly mentioning:
    * The file's location and context (`bionic/tests/math_data`).
    * The data type and structure (`static array of float pairs`).
    * The presumed purpose (test data for `atanf`).
    * The likely interpretation of the data (input/expected output).
    * The relevance to Android's C library (`bionic`) and ensuring the correctness of mathematical functions.

9. **Address Potential Ambiguities (Self-Correction):** I initially considered if the data could be for something other than direct input/output testing. However, the clear pairing and the `atanf` keyword made this the most likely scenario. I also noted the "intel_data" and considered if it implied architecture-specific optimizations, but without more code, I kept the interpretation focused on testing.

This iterative process of examining the code, using the provided context, and refining hypotheses allowed me to arrive at the concise and accurate summary provided in the example answer.
好的，这是对提供的代码片段的功能归纳：

**功能归纳：**

这个C源代码文件 `atanf_intel_data.handroid`  是 Android 系统 Bionic 库中用于测试 `atanf` 函数的数据文件。具体来说，它包含一个静态定义的全局数组 `g_atanf_intel_data`，这个数组存储了一系列 `float` 类型的输入/输出数据对。

每个数据对都旨在测试 `atanf` 函数在特定输入值下的计算结果是否与预期的输出值一致。这些数据很可能是为了确保 `atanf` 函数在 Android 系统中的实现（特别是针对 Intel 架构的优化或兼容性）的准确性和可靠性。

**更详细的解释：**

* **测试数据:**  这个文件明显是一个测试数据文件，其命名和所在的目录结构（`bionic/tests/math_data`）都暗示了这一点。
* **`atanf` 函数:** 文件名中的 `atanf` 表明这些数据是用来测试标准 C 库中的 `atanf` 函数的。`atanf` 函数计算单精度浮点数的反正切值。
* **`intel_data`:**  这部分暗示这些测试数据可能针对 Intel 架构进行了特定的设计或优化。这可能是因为不同的处理器架构在浮点数运算上可能存在细微的差异，需要针对性地进行测试。
* **`.handroid`:** 这个文件扩展名 `.handroid` 是 Bionic 库测试框架中用来标记特定于 Android 平台的测试数据或配置文件的约定。
* **数据格式:**  数组 `g_atanf_intel_data` 的元素类型 `data_1_1_t<float, float>`  表明存储的是由两个 `float` 值组成的结构体或模板类的实例。观察数组内容可以发现，每一对数据都包含一个输入值和一个期望的输出值。
* **输入/输出对:**  数组中的每个 `// Entry N` 注释后面的花括号 `{}` 包含两个用逗号分隔的十六进制浮点数。第一个浮点数是 `atanf` 函数的输入值，第二个浮点数是对于该输入的预期返回值。通常，正负对称的输入值会成对出现，以测试 `atanf` 函数对不同符号输入的处理。

**与 Android 功能的关系举例：**

Android 系统中许多应用程序和框架层的功能都依赖于精确的数学计算，例如：

* **图形渲染 (Graphics Rendering):**  在 OpenGL ES 或 Vulkan 等图形 API 中，计算角度、旋转、变换等操作时会用到三角函数及其反函数，包括 `atanf`。确保 `atanf` 的准确性对于渲染正确的图像至关重要。
* **传感器数据处理 (Sensor Data Processing):**  Android 设备上的传感器（如陀螺仪、加速度计）会产生大量数据，这些数据的处理和融合经常涉及到角度计算，因此需要准确的 `atanf` 函数。
* **定位服务 (Location Services):**  计算方位角、角度等地理位置信息时，也可能会使用到 `atanf` 函数。
* **科学计算类应用 (Scientific Applications):**  任何在 Android 上运行的需要进行复杂数学计算的应用程序都会直接或间接地使用到 `atanf`。

**总结：**

总而言之，`atanf_intel_data.handroid` 是 Android Bionic 库中用于测试 `atanf` 函数在 Intel 架构上的准确性的测试数据集。它通过提供一系列预期的输入和输出值，帮助开发者验证 `atanf` 函数的实现是否正确可靠，从而保证 Android 系统和运行在其上的应用程序的稳定性和准确性。

### 提示词
```
这是目录为bionic/tests/math_data/atanf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_atanf_intel_data[] = {
  { // Entry 0
    -0x1.dc2c98008d535c517dd9d371c44a6151p-2,
    -0x1.00e0p-1
  },
  { // Entry 1
    0x1.dc2c98008d535c517dd9d371c44a6151p-2,
    0x1.00e0p-1
  },
  { // Entry 2
    -0x1.93d63bfce467ef12745bcaf164c988cdp-1,
    -0x1.01b8p0
  },
  { // Entry 3
    0x1.93d63bfce467ef12745bcaf164c988cdp-1,
    0x1.01b8p0
  },
  { // Entry 4
    -0x1.93e6bcfcbf2868bf3d227ad52cc06775p-1,
    -0x1.01c89ep0
  },
  { // Entry 5
    0x1.93e6bcfcbf2868bf3d227ad52cc06775p-1,
    0x1.01c89ep0
  },
  { // Entry 6
    -0x1.e4353f004481a69e0d97136cd8302508p-2,
    -0x1.05ec48p-1
  },
  { // Entry 7
    0x1.e4353f004481a69e0d97136cd8302508p-2,
    0x1.05ec48p-1
  },
  { // Entry 8
    -0x1.980dd942c58931ccfa88aa5714d9589bp-1,
    -0x1.06p0
  },
  { // Entry 9
    0x1.980dd942c58931ccfa88aa5714d9589bp-1,
    0x1.06p0
  },
  { // Entry 10
    -0x1.e4e7050041fea5e474bc42bb3e9598edp-2,
    -0x1.065c78p-1
  },
  { // Entry 11
    0x1.e4e7050041fea5e474bc42bb3e9598edp-2,
    0x1.065c78p-1
  },
  { // Entry 12
    -0x1.fd08daffe290e806775f8df4ed63331fp-2,
    -0x1.15c8e2p-1
  },
  { // Entry 13
    0x1.fd08daffe290e806775f8df4ed63331fp-2,
    0x1.15c8e2p-1
  },
  { // Entry 14
    -0x1.12d0910000acd3796043ce397dc0aaf0p-1,
    -0x1.30a612p-1
  },
  { // Entry 15
    0x1.12d0910000acd3796043ce397dc0aaf0p-1,
    0x1.30a612p-1
  },
  { // Entry 16
    -0x1.8501defc40a94bd69a326f6f4efc3cabp0,
    -0x1.3801p4
  },
  { // Entry 17
    0x1.8501defc40a94bd69a326f6f4efc3cabp0,
    0x1.3801p4
  },
  { // Entry 18
    -0x1.1dbfdb002aafa34d56d4efdeb875d7ccp-1,
    -0x1.3fa5d0p-1
  },
  { // Entry 19
    0x1.1dbfdb002aafa34d56d4efdeb875d7ccp-1,
    0x1.3fa5d0p-1
  },
  { // Entry 20
    -0x1.91c7f6fffff6a5eef58d32a20cb76586p0,
    -0x1.7573fep9
  },
  { // Entry 21
    0x1.91c7f6fffff6a5eef58d32a20cb76586p0,
    0x1.7573fep9
  },
  { // Entry 22
    -0x1.f31d35b81259f5f45badc8b774241b15p-1,
    -0x1.79743ep0
  },
  { // Entry 23
    0x1.f31d35b81259f5f45badc8b774241b15p-1,
    0x1.79743ep0
  },
  { // Entry 24
    -0x1.f54b76ff8c8f4020ccc4dfba5f1dcfc4p-1,
    -0x1.7cefc8p0
  },
  { // Entry 25
    0x1.f54b76ff8c8f4020ccc4dfba5f1dcfc4p-1,
    0x1.7cefc8p0
  },
  { // Entry 26
    -0x1.921fa2ffefea1a475fc6364331e98c0fp0,
    -0x1.c07630p19
  },
  { // Entry 27
    0x1.921fa2ffefea1a475fc6364331e98c0fp0,
    0x1.c07630p19
  },
  { // Entry 28
    -0x1.c8d37cfff9732aae565e96c9ab1ae3p-4,
    -0x1.cabad0p-4
  },
  { // Entry 29
    0x1.c8d37cfff9732aae565e96c9ab1ae3p-4,
    0x1.cabad0p-4
  },
  { // Entry 30
    -0x1.8455816cd8b17910d5fb42c54a7a3f6ap-1,
    -0x1.e52326p-1
  },
  { // Entry 31
    0x1.8455816cd8b17910d5fb42c54a7a3f6ap-1,
    0x1.e52326p-1
  },
  { // Entry 32
    -0x1.87ce6ca38f66951f7d176d27e4cc7114p-1,
    -0x1.ebc518p-1
  },
  { // Entry 33
    0x1.87ce6ca38f66951f7d176d27e4cc7114p-1,
    0x1.ebc518p-1
  },
  { // Entry 34
    0x1.ffd55bba97624a84ef3aeedbb518c427p-6,
    0x1.p-5
  },
  { // Entry 35
    -0x1.ffd55bba97624a84ef3aeedbb518c427p-6,
    -0x1.p-5
  },
  { // Entry 36
    0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    0x1.000002p-4
  },
  { // Entry 37
    -0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    -0x1.000002p-4
  },
  { // Entry 38
    0x1.ff5632fb474b2bdff859ee6421a12d48p-5,
    0x1.00003cp-4
  },
  { // Entry 39
    -0x1.ff5632fb474b2bdff859ee6421a12d48p-5,
    -0x1.00003cp-4
  },
  { // Entry 40
    0x1.9220654406519246dee218750f6118e0p-1,
    0x1.0000b0p0
  },
  { // Entry 41
    -0x1.9220654406519246dee218750f6118e0p-1,
    -0x1.0000b0p0
  },
  { // Entry 42
    0x1.f5b8c8fc218568d2548c390de7a3dfcep-3,
    0x1.0000c0p-2
  },
  { // Entry 43
    -0x1.f5b8c8fc218568d2548c390de7a3dfcep-3,
    -0x1.0000c0p-2
  },
  { // Entry 44
    0x1.fd64d4fccffaeeedba9c9564a6730d18p-4,
    0x1.0004a8p-3
  },
  { // Entry 45
    -0x1.fd64d4fccffaeeedba9c9564a6730d18p-4,
    -0x1.0004a8p-3
  },
  { // Entry 46
    0x1.9227b5244326d9bed87bdeb00908aeb7p-1,
    0x1.0008p0
  },
  { // Entry 47
    -0x1.9227b5244326d9bed87bdeb00908aeb7p-1,
    -0x1.0008p0
  },
  { // Entry 48
    0x1.922b76ff245e6de6345559ddb2fcf536p-1,
    0x1.000bc2p0
  },
  { // Entry 49
    -0x1.922b76ff245e6de6345559ddb2fcf536p-1,
    -0x1.000bc2p0
  },
  { // Entry 50
    0x1.922b82fe9701aeaffb73a1443c0c83d0p-1,
    0x1.000bcep0
  },
  { // Entry 51
    -0x1.922b82fe9701aeaffb73a1443c0c83d0p-1,
    -0x1.000bcep0
  },
  { // Entry 52
    0x1.923faf44d816daa54d425d8045e2887dp-1,
    0x1.001ffcp0
  },
  { // Entry 53
    -0x1.923faf44d816daa54d425d8045e2887dp-1,
    -0x1.001ffcp0
  },
  { // Entry 54
    0x1.fe2484fd31d3cf098219a2af1d986eedp-4,
    0x1.0066p-3
  },
  { // Entry 55
    -0x1.fe2484fd31d3cf098219a2af1d986eedp-4,
    -0x1.0066p-3
  },
  { // Entry 56
    0x1.92939b003b069b3e275950af80cd63fcp-1,
    0x1.0074p0
  },
  { // Entry 57
    -0x1.92939b003b069b3e275950af80cd63fcp-1,
    -0x1.0074p0
  },
  { // Entry 58
    0x1.1b9d3b002159e2945b595dab6488de5bp0,
    0x1.0076p1
  },
  { // Entry 59
    -0x1.1b9d3b002159e2945b595dab6488de5bp0,
    -0x1.0076p1
  },
  { // Entry 60
    0x1.dc2c98008d535c517dd9d371c44a6151p-2,
    0x1.00e0p-1
  },
  { // Entry 61
    -0x1.dc2c98008d535c517dd9d371c44a6151p-2,
    -0x1.00e0p-1
  },
  { // Entry 62
    0x1.93d63bfce467ef12745bcaf164c988cdp-1,
    0x1.01b8p0
  },
  { // Entry 63
    -0x1.93d63bfce467ef12745bcaf164c988cdp-1,
    -0x1.01b8p0
  },
  { // Entry 64
    0x1.94167efccbc0fa6d4577f69f61e031d2p-1,
    0x1.01f8bap0
  },
  { // Entry 65
    -0x1.94167efccbc0fa6d4577f69f61e031d2p-1,
    -0x1.01f8bap0
  },
  { // Entry 66
    0x1.9672428abad4ced3d0a6e349e9bf2b3ep-1,
    0x1.045cp0
  },
  { // Entry 67
    -0x1.9672428abad4ced3d0a6e349e9bf2b3ep-1,
    -0x1.045cp0
  },
  { // Entry 68
    0x1.fe8abeff0d857adea735e07cdc25f45cp-3,
    0x1.04b198p-2
  },
  { // Entry 69
    -0x1.fe8abeff0d857adea735e07cdc25f45cp-3,
    -0x1.04b198p-2
  },
  { // Entry 70
    0x1.e3ee99003632acbd63018dcd998b0a66p-2,
    0x1.05bfb8p-1
  },
  { // Entry 71
    -0x1.e3ee99003632acbd63018dcd998b0a66p-2,
    -0x1.05bfb8p-1
  },
  { // Entry 72
    0x1.980dd942c58931ccfa88aa5714d9589bp-1,
    0x1.06p0
  },
  { // Entry 73
    -0x1.980dd942c58931ccfa88aa5714d9589bp-1,
    -0x1.06p0
  },
  { // Entry 74
    0x1.e4c00f0040fd5558135d221fc95d855ep-2,
    0x1.0643e0p-1
  },
  { // Entry 75
    -0x1.e4c00f0040fd5558135d221fc95d855ep-2,
    -0x1.0643e0p-1
  },
  { // Entry 76
    0x1.e4e7050041fea5e474bc42bb3e9598edp-2,
    0x1.065c78p-1
  },
  { // Entry 77
    -0x1.e4e7050041fea5e474bc42bb3e9598edp-2,
    -0x1.065c78p-1
  },
  { // Entry 78
    0x1.067fe90007689d48fb39791c0a809723p-9,
    0x1.0680p-9
  },
  { // Entry 79
    -0x1.067fe90007689d48fb39791c0a809723p-9,
    -0x1.0680p-9
  },
  { // Entry 80
    0x1.e5f6450041f31d7a1b1ffc6626e3a3a9p-2,
    0x1.0707ccp-1
  },
  { // Entry 81
    -0x1.e5f6450041f31d7a1b1ffc6626e3a3a9p-2,
    -0x1.0707ccp-1
  },
  { // Entry 82
    0x1.9a000a935bd8e2b2823be1b99de9aa6dp-1,
    0x1.08p0
  },
  { // Entry 83
    -0x1.9a000a935bd8e2b2823be1b99de9aa6dp-1,
    -0x1.08p0
  },
  { // Entry 84
    0x1.e7e095003c972c47c7b484d1174ef8f1p-2,
    0x1.083df4p-1
  },
  { // Entry 85
    -0x1.e7e095003c972c47c7b484d1174ef8f1p-2,
    -0x1.083df4p-1
  },
  { // Entry 86
    0x1.9b95d2027f3b51c408badd232447fca7p-1,
    0x1.09a4p0
  },
  { // Entry 87
    -0x1.9b95d2027f3b51c408badd232447fca7p-1,
    -0x1.09a4p0
  },
  { // Entry 88
    0x1.9bf2349c2fe1915b2ba951f4d90c2346p-1,
    0x1.0a04p0
  },
  { // Entry 89
    -0x1.9bf2349c2fe1915b2ba951f4d90c2346p-1,
    -0x1.0a04p0
  },
  { // Entry 90
    0x1.9c0d202ee6cadb3368d0bc3bc61620f7p-1,
    0x1.0a20p0
  },
  { // Entry 91
    -0x1.9c0d202ee6cadb3368d0bc3bc61620f7p-1,
    -0x1.0a20p0
  },
  { // Entry 92
    0x1.9c0e9ebf9ee6f339b8d4eb3e3659c70ep-1,
    0x1.0a218ep0
  },
  { // Entry 93
    -0x1.9c0e9ebf9ee6f339b8d4eb3e3659c70ep-1,
    -0x1.0a218ep0
  },
  { // Entry 94
    0x1.9d252e659267619beef68e8773dc6ec3p-1,
    0x1.0b44p0
  },
  { // Entry 95
    -0x1.9d252e659267619beef68e8773dc6ec3p-1,
    -0x1.0b44p0
  },
  { // Entry 96
    0x1.ee39fb000821b1a9c00089e135f069d2p-2,
    0x1.0c4670p-1
  },
  { // Entry 97
    -0x1.ee39fb000821b1a9c00089e135f069d2p-2,
    -0x1.0c4670p-1
  },
  { // Entry 98
    0x1.eff285034b3ca346fbed2f996a1534f1p-2,
    0x1.0d5f6ep-1
  },
  { // Entry 99
    -0x1.eff285034b3ca346fbed2f996a1534f1p-2,
    -0x1.0d5f6ep-1
  },
  { // Entry 100
    0x1.f33837034c37141c6ee6c4c215ebe879p-2,
    0x1.0f771ep-1
  },
  { // Entry 101
    -0x1.f33837034c37141c6ee6c4c215ebe879p-2,
    -0x1.0f771ep-1
  },
  { // Entry 102
    0x1.a169ad8725b3aa57831d5cea9cf84a45p-1,
    0x1.0fc3aep0
  },
  { // Entry 103
    -0x1.a169ad8725b3aa57831d5cea9cf84a45p-1,
    -0x1.0fc3aep0
  },
  { // Entry 104
    0x1.a199a5013b67a3668024b5fdba537ffbp-1,
    0x1.0ff6b6p0
  },
  { // Entry 105
    -0x1.a199a5013b67a3668024b5fdba537ffbp-1,
    -0x1.0ff6b6p0
  },
  { // Entry 106
    0x1.f9ef110001fb3099dbc032baff8a7c9cp-2,
    0x1.13c8p-1
  },
  { // Entry 107
    -0x1.f9ef110001fb3099dbc032baff8a7c9cp-2,
    -0x1.13c8p-1
  },
  { // Entry 108
    0x1.fb05f2d09a4dc6b31f91eaed3651aa0fp-2,
    0x1.147cp-1
  },
  { // Entry 109
    -0x1.fb05f2d09a4dc6b31f91eaed3651aa0fp-2,
    -0x1.147cp-1
  },
  { // Entry 110
    0x1.166210ff1f27419bd56d7ad58a532203p-4,
    0x1.16d0p-4
  },
  { // Entry 111
    -0x1.166210ff1f27419bd56d7ad58a532203p-4,
    -0x1.16d0p-4
  },
  { // Entry 112
    0x1.ff14479ea0d08b305667ea1e6b71efa9p-2,
    0x1.171cp-1
  },
  { // Entry 113
    -0x1.ff14479ea0d08b305667ea1e6b71efa9p-2,
    -0x1.171cp-1
  },
  { // Entry 114
    0x1.aa655941c2ed237529659b26a6d40360p-1,
    0x1.1980p0
  },
  { // Entry 115
    -0x1.aa655941c2ed237529659b26a6d40360p-1,
    -0x1.1980p0
  },
  { // Entry 116
    0x1.1ac3c9559802914487a1a7e1b563dc42p-4,
    0x1.1b37p-4
  },
  { // Entry 117
    -0x1.1ac3c9559802914487a1a7e1b563dc42p-4,
    -0x1.1b37p-4
  },
  { // Entry 118
    0x1.ace31afd63c618792d7f004a5f20bf53p-1,
    0x1.1c443ep0
  },
  { // Entry 119
    -0x1.ace31afd63c618792d7f004a5f20bf53p-1,
    -0x1.1c443ep0
  },
  { // Entry 120
    0x1.aefd63ceeeba596e1d377ed9501f9f2dp-1,
    0x1.1ea0p0
  },
  { // Entry 121
    -0x1.aefd63ceeeba596e1d377ed9501f9f2dp-1,
    -0x1.1ea0p0
  },
  { // Entry 122
    0x1.31e3ddfffbe9c81c178270bc759875e9p-3,
    0x1.342f6cp-3
  },
  { // Entry 123
    -0x1.31e3ddfffbe9c81c178270bc759875e9p-3,
    -0x1.342f6cp-3
  },
  { // Entry 124
    0x1.30f588fffee141782f61de3b913cc344p-2,
    0x1.3a4e82p-2
  },
  { // Entry 125
    -0x1.30f588fffee141782f61de3b913cc344p-2,
    -0x1.3a4e82p-2
  },
  { // Entry 126
    0x1.26c384fe95d5e24c9c60adf93f531182p-1,
    0x1.4c50e8p-1
  },
  { // Entry 127
    -0x1.26c384fe95d5e24c9c60adf93f531182p-1,
    -0x1.4c50e8p-1
  },
  { // Entry 128
    0x1.e42856fffdaf1e270f502c72bfe272b0p-1,
    0x1.62b140p0
  },
  { // Entry 129
    -0x1.e42856fffdaf1e270f502c72bfe272b0p-1,
    -0x1.62b140p0
  },
  { // Entry 130
    0x1.6703fefed06b914b99e3124ca0c2cb58p-2,
    0x1.767caap-2
  },
  { // Entry 131
    -0x1.6703fefed06b914b99e3124ca0c2cb58p-2,
    -0x1.767caap-2
  },
  { // Entry 132
    0x1.75cb06fffffebc09be37493223d1436ap-4,
    0x1.76d58ep-4
  },
  { // Entry 133
    -0x1.75cb06fffffebc09be37493223d1436ap-4,
    -0x1.76d58ep-4
  },
  { // Entry 134
    0x1.43fdd1a6959aa989f50575cf45455d64p-1,
    0x1.7780f2p-1
  },
  { // Entry 135
    -0x1.43fdd1a6959aa989f50575cf45455d64p-1,
    -0x1.7780f2p-1
  },
  { // Entry 136
    0x1.481bba0215fb04f66252d5b8f4a0299ap-1,
    0x1.7ddf62p-1
  },
  { // Entry 137
    -0x1.481bba0215fb04f66252d5b8f4a0299ap-1,
    -0x1.7ddf62p-1
  },
  { // Entry 138
    0x1.6f946595578bf7edcadbbe6e816838dap-2,
    0x1.8039f8p-2
  },
  { // Entry 139
    -0x1.6f946595578bf7edcadbbe6e816838dap-2,
    -0x1.8039f8p-2
  },
  { // Entry 140
    0x1.6f9d299cc53084feaeb4a89dd538984cp-2,
    0x1.8043f8p-2
  },
  { // Entry 141
    -0x1.6f9d299cc53084feaeb4a89dd538984cp-2,
    -0x1.8043f8p-2
  },
  { // Entry 142
    0x1.6fa461634385621a7b4a1f3f39e69e88p-2,
    0x1.804c34p-2
  },
  { // Entry 143
    -0x1.6fa461634385621a7b4a1f3f39e69e88p-2,
    -0x1.804c34p-2
  },
  { // Entry 144
    0x1.6fedbe03cf0b00cdb648f3f58822f3c8p-2,
    0x1.809fe8p-2
  },
  { // Entry 145
    -0x1.6fedbe03cf0b00cdb648f3f58822f3c8p-2,
    -0x1.809fe8p-2
  },
  { // Entry 146
    0x1.738c297a78e8c603048015fdc8bcf4c9p-2,
    0x1.84c270p-2
  },
  { // Entry 147
    -0x1.738c297a78e8c603048015fdc8bcf4c9p-2,
    -0x1.84c270p-2
  },
  { // Entry 148
    0x1.98f0340002c61b1d33f8d1e2c1af5581p-4,
    0x1.9a4d6ep-4
  },
  { // Entry 149
    -0x1.98f0340002c61b1d33f8d1e2c1af5581p-4,
    -0x1.9a4d6ep-4
  },
  { // Entry 150
    0x1.9f8b4300038b239eb63e7be822591b5fp-4,
    0x1.a0f9bcp-4
  },
  { // Entry 151
    -0x1.9f8b4300038b239eb63e7be822591b5fp-4,
    -0x1.a0f9bcp-4
  },
  { // Entry 152
    0x1.a0fd9d00039a60bddbfddc10b05c56a3p-4,
    0x1.a26ff0p-4
  },
  { // Entry 153
    -0x1.a0fd9d00039a60bddbfddc10b05c56a3p-4,
    -0x1.a26ff0p-4
  },
  { // Entry 154
    0x1.a4728900556fc2b8a5a530e3d999b1d7p-4,
    0x1.a5ee2cp-4
  },
  { // Entry 155
    -0x1.a4728900556fc2b8a5a530e3d999b1d7p-4,
    -0x1.a5ee2cp-4
  },
  { // Entry 156
    0x1.a4728afaf537b57369dd1613673f2757p-4,
    0x1.a5ee2ep-4
  },
  { // Entry 157
    -0x1.a4728afaf537b57369dd1613673f2757p-4,
    -0x1.a5ee2ep-4
  },
  { // Entry 158
    0x1.915e19aa098cba6ef178411ea4174f67p-2,
    0x1.a744d8p-2
  },
  { // Entry 159
    -0x1.915e19aa098cba6ef178411ea4174f67p-2,
    -0x1.a744d8p-2
  },
  { // Entry 160
    0x1.a95d5effffee8dfa2a44af912ff5c6bdp-4,
    0x1.aae686p-4
  },
  { // Entry 161
    -0x1.a95d5effffee8dfa2a44af912ff5c6bdp-4,
    -0x1.aae686p-4
  },
  { // Entry 162
    0x1.b0f897fdea5769efb43b734c6f5d38fdp-4,
    0x1.b29748p-4
  },
  { // Entry 163
    -0x1.b0f897fdea5769efb43b734c6f5d38fdp-4,
    -0x1.b29748p-4
  },
  { // Entry 164
    0x1.b6fd68fffbf33784a8e129606c5a3fd4p-4,
    0x1.b8adb0p-4
  },
  { // Entry 165
    -0x1.b6fd68fffbf33784a8e129606c5a3fd4p-4,
    -0x1.b8adb0p-4
  },
  { // Entry 166
    0x1.a205342c457ac3a056abcfe7527a4453p-2,
    0x1.bae68ep-2
  },
  { // Entry 167
    -0x1.a205342c457ac3a056abcfe7527a4453p-2,
    -0x1.bae68ep-2
  },
  { // Entry 168
    0x1.a64efd063370b5e3a708b2a37ddab223p-2,
    0x1.c00014p-2
  },
  { // Entry 169
    -0x1.a64efd063370b5e3a708b2a37ddab223p-2,
    -0x1.c00014p-2
  },
  { // Entry 170
    0x1.ad00f396db03faa7f9d7e3221d4552adp-2,
    0x1.c7fffep-2
  },
  { // Entry 171
    -0x1.ad00f396db03faa7f9d7e3221d4552adp-2,
    -0x1.c7fffep-2
  },
  { // Entry 172
    0x1.6e6d5d27bd08154a6349dd2d9a311e10p0,
    0x1.c7fffep2
  },
  { // Entry 173
    -0x1.6e6d5d27bd08154a6349dd2d9a311e10p0,
    -0x1.c7fffep2
  },
  { // Entry 174
    0x1.769885e484d0999ef07a0c7cc0ce73f5p-1,
    0x1.cbb484p-1
  },
  { // Entry 175
    -0x1.769885e484d0999ef07a0c7cc0ce73f5p-1,
    -0x1.cbb484p-1
  },
  { // Entry 176
    0x1.7805f5ed5a7d34cf922043471c74eecfp-1,
    0x1.ce4a36p-1
  },
  { // Entry 177
    -0x1.7805f5ed5a7d34cf922043471c74eecfp-1,
    -0x1.ce4a36p-1
  },
  { // Entry 178
    0x1.c85b2ebda13e4f781ea65e5aa1b8b9e1p-3,
    0x1.d00ffep-3
  },
  { // Entry 179
    -0x1.c85b2ebda13e4f781ea65e5aa1b8b9e1p-3,
    -0x1.d00ffep-3
  },
  { // Entry 180
    0x1.c8df373eebdbd7d2983d9c074687b3b1p-3,
    0x1.d09ad0p-3
  },
  { // Entry 181
    -0x1.c8df373eebdbd7d2983d9c074687b3b1p-3,
    -0x1.d09ad0p-3
  },
  { // Entry 182
    0x1.8108f7001b7ce9d26ea2a770acd41044p0,
    0x1.deaa38p3
  },
  { // Entry 183
    -0x1.8108f7001b7ce9d26ea2a770acd41044p0,
    -0x1.deaa38p3
  },
  { // Entry 184
    0x1.82d6b687d8692e9aefc611be6b1d44a8p-1,
    0x1.e24eaep-1
  },
  { // Entry 185
    -0x1.82d6b687d8692e9aefc611be6b1d44a8p-1,
    -0x1.e24eaep-1
  },
  { // Entry 186
    0x1.921fb5011d0bff02f51322a08f435689p0,
    0x1.e7fffep25
  },
  { // Entry 187
    -0x1.921fb5011d0bff02f51322a08f435689p0,
    -0x1.e7fffep25
  },
  { // Entry 188
    0x1.8755f7204b35fedd69304c014ba9193ap-1,
    0x1.eaddb6p-1
  },
  { // Entry 189
    -0x1.8755f7204b35fedd69304c014ba9193ap-1,
    -0x1.eaddb6p-1
  },
  { // Entry 190
    0x1.921facfffe4d525869adf36453ac0045p0,
    0x1.ef7bd0p20
  },
  { // Entry 191
    -0x1.921facfffe4d525869adf36453ac0045p0,
    -0x1.ef7bd0p20
  },
  { // Entry 192
    0x1.f14041fffc6f93742ff15942783907eep-4,
    0x1.f3b552p-4
  },
  { // Entry 193
    -0x1.f14041fffc6f93742ff15942783907eep-4,
    -0x1.f3b552p-4
  },
  { // Entry 194
    0x1.f4bb0afed7559483e5805dd4879465bcp-6,
    0x1.f4e2f8p-6
  },
  { // Entry 195
    -0x1.f4bb0afed7559483e5805dd4879465bcp-6,
    -0x1.f4e2f8p-6
  },
  { // Entry 196
    0x1.d45aeb02a07ca4b711c2193329425c78p-2,
    0x1.f7fffep-2
  },
  { // Entry 197
    -0x1.d45aeb02a07ca4b711c2193329425c78p-2,
    -0x1.f7fffep-2
  },
  { // Entry 198
    0x1.d539bcffd5888dca7deceba8a3f2d041p-2,
    0x1.f914e8p-2
  },
  { // Entry 199
    -0x1.d539bcffd5888dca7deceba8a3f2d041p-2,
    -0x1.f914e8p-2
  },
  { // Entry 200
    0x1.8ee84f1478a25b9bfacdabb49fcea6d5p-1,
    0x1.f99b76p-1
  },
  { // Entry 201
    -0x1.8ee84f1478a25b9bfacdabb49fcea6d5p-1,
    -0x1.f99b76p-1
  },
  { // Entry 202
    0x1.fadbf0ff486b15e264c02ca39b8e6e46p-6,
    0x1.fb055ap-6
  },
  { // Entry 203
    -0x1.fadbf0ff486b15e264c02ca39b8e6e46p-6,
    -0x1.fb055ap-6
  },
  { // Entry 204
    0x1.9044df034b8d943327bee5c633b3f31cp-1,
    0x1.fc4dc0p-1
  },
  { // Entry 205
    -0x1.9044df034b8d943327bee5c633b3f31cp-1,
    -0x1.fc4dc0p-1
  },
  { // Entry 206
    0x1.921f74fffa03e701accc9d1ee3bd2f43p0,
    0x1.fddffep17
  },
  { // Entry 207
    -0x1.921f74fffa03e701accc9d1ee3bd2f43p0,
    -0x1.fddffep17
  },
  { // Entry 208
    0x1.91af9bc0400e0e21fb44692a41829c5dp-1,
    0x1.ff1ffep-1
  },
  { // Entry 209
    -0x1.91af9bc0400e0e21fb44692a41829c5dp-1,
    -0x1.ff1ffep-1
  },
  { // Entry 210
    0x1.91bfa241a2bf1c8f33e7aee3a38362fap-1,
    0x1.ff3ffep-1
  },
  { // Entry 211
    -0x1.91bfa241a2bf1c8f33e7aee3a38362fap-1,
    -0x1.ff3ffep-1
  },
  { // Entry 212
    0x1.f502a50008dcfa3d1252e8256297aa16p-3,
    0x1.ff3ffep-3
  },
  { // Entry 213
    -0x1.f502a50008dcfa3d1252e8256297aa16p-3,
    -0x1.ff3ffep-3
  },
  { // Entry 214
    0x1.1b6c658f57d1e4435c946530e7d0415cp0,
    0x1.fff77ep0
  },
  { // Entry 215
    -0x1.1b6c658f57d1e4435c946530e7d0415cp0,
    -0x1.fff77ep0
  },
  { // Entry 216
    0x1.f5b0a8fac8ee3b2a0997552183bbaf86p-3,
    0x1.fff8dep-3
  },
  { // Entry 217
    -0x1.f5b0a8fac8ee3b2a0997552183bbaf86p-3,
    -0x1.fff8dep-3
  },
  { // Entry 218
    0x1.f5b0c8fad63b565edaa4205b5787d234p-3,
    0x1.fff9p-3
  },
  { // Entry 219
    -0x1.f5b0c8fad63b565edaa4205b5787d234p-3,
    -0x1.fff9p-3
  },
  { // Entry 220
    0x1.ffd048ff42ff02270154618cac768f98p-6,
    0x1.fffaecp-6
  },
  { // Entry 221
    -0x1.ffd048ff42ff02270154618cac768f98p-6,
    -0x1.fffaecp-6
  },
  { // Entry 222
    0x1.921de5429e50865c34386a247dc4ee4ep-1,
    0x1.fffc60p-1
  },
  { // Entry 223
    -0x1.921de5429e50865c34386a247dc4ee4ep-1,
    -0x1.fffc60p-1
  },
  { // Entry 224
    0x1.921f84443e21041cf1621a6d2e90a3cap-1,
    0x1.ffff9ep-1
  },
  { // Entry 225
    -0x1.921f84443e21041cf1621a6d2e90a3cap-1,
    -0x1.ffff9ep-1
  },
  { // Entry 226
    0x1.1b6e0d95213d8e5e8acacf6ee3b5dda1p0,
    0x1.ffffc6p0
  },
  { // Entry 227
    -0x1.1b6e0d95213d8e5e8acacf6ee3b5dda1p0,
    -0x1.ffffc6p0
  },
  { // Entry 228
    0x1.5368c551e98fc9a0436ff6aed5a43bfep0,
    0x1.ffffdep1
  },
  { // Entry 229
    -0x1.5368c551e98fc9a0436ff6aed5a43bfep0,
    -0x1.ffffdep1
  },
  { // Entry 230
    0x1.1b6e15952230c1a76e364414327ae250p0,
    0x1.ffffeep0
  },
  { // Entry 231
    -0x1.1b6e15952230c1a76e364414327ae250p0,
    -0x1.ffffeep0
  },
  { // Entry 232
    0x1.921fb14442c984697ee21a6c570dc22ap-1,
    0x1.fffff8p-1
  },
  { // Entry 233
    -0x1.921fb14442c984697ee21a6c570dc22ap-1,
    -0x1.fffff8p-1
  },
  { // Entry 234
    -0.0f,
    -0x1.p-149
  },
  { // Entry 235
    0.0f,
    0x1.p-149
  },
  { // Entry 236
    0.0,
    0.0
  },
  { // Entry 237
    0.0f,
    0x1.p-149
  },
  { // Entry 238
    -0.0f,
    -0x1.p-149
  },
  { // Entry 239
    -0x1.000001ffffffffffffffffffffffffffp-126,
    -0x1.000002p-126
  },
  { // Entry 240
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.000002p-126
  },
  { // Entry 241
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126
  },
  { // Entry 242
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126
  },
  { // Entry 243
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127
  },
  { // Entry 244
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127
  },
  { // Entry 245
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127
  },
  { // Entry 246
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127
  },
  { // Entry 247
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126
  },
  { // Entry 248
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126
  },
  { // Entry 249
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.000002p-126
  },
  { // Entry 250
    -0x1.000001ffffffffffffffffffffffffffp-126,
    -0x1.000002p-126
  },
  { // Entry 251
    0x1.999999a89e60d0512d6b0b39bd2a565ap-13,
    0x1.99999ap-13
  },
  { // Entry 252
    -0x1.999999a89e60d0512d6b0b39bd2a565ap-13,
    -0x1.99999ap-13
  },
  { // Entry 253
    0x1.999998a27984d3ebeb1c3290cc2c5caap-12,
    0x1.99999ap-12
  },
  { // Entry 254
    -0x1.999998a27984d3ebeb1c3290cc2c5caap-12,
    -0x1.99999ap-12
  },
  { // Entry 255
    0x1.333331b22d11b0ccb2bb7ba6f63b4d3cp-11,
    0x1.333334p-11
  },
  { // Entry 256
    -0x1.333331b22d11b0ccb2bb7ba6f63b4d3cp-11,
    -0x1.333334p-11
  },
  { // Entry 257
    0x1.99999489e62c7a2256e05c49880d23d9p-11,
    0x1.99999ap-11
  },
  { // Entry 258
    -0x1.99999489e62c7a2256e05c49880d23d9p-11,
    -0x1.99999ap-11
  },
  { // Entry 259
    0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    0x1.p-10
  },
  { // Entry 260
    -0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    -0x1.p-10
  },
  { // Entry 261
    0x1.33332ac8b4a6505aad1a5539202df4f4p-10,
    0x1.333334p-10
  },
  { // Entry 262
    -0x1.33332ac8b4a6505aad1a5539202df4f4p-10,
    -0x1.333334p-10
  },
  { // Entry 263
    0x1.6666595d875d6f587e4d878a7b492f47p-10,
    0x1.666668p-10
  },
  { // Entry 264
    -0x1.6666595d875d6f587e4d878a7b492f47p-10,
    -0x1.666668p-10
  },
  { // Entry 265
    0x1.9999862799f2a4104ba8c411863e71f7p-10,
    0x1.99999cp-10
  },
  { // Entry 266
    -0x1.9999862799f2a4104ba8c411863e71f7p-10,
    -0x1.99999cp-10
  },
  { // Entry 267
    0x1.ccccace5643276ecd8ffae54b28b87ffp-10,
    0x1.ccccccp-10
  },
  { // Entry 268
    -0x1.ccccace5643276ecd8ffae54b28b87ffp-10,
    -0x1.ccccccp-10
  },
  { // Entry 269
    0x1.0664f66f7cfd482cf0ff4582bbeef478p-7,
    0x1.066666p-7
  },
  { // Entry 270
    -0x1.0664f66f7cfd482cf0ff4582bbeef478p-7,
    -0x1.066666p-7
  },
  { // Entry 271
    0x1.ccc505948fe7a3b8e0837445c2136897p-7,
    0x1.ccccccp-7
  },
  { // Entry 272
    -0x1.ccc505948fe7a3b8e0837445c2136897p-7,
    -0x1.ccccccp-7
  },
  { // Entry 273
    0x1.498e36c4f385d5af3b6b6480a8ebfe14p-6,
    0x1.499998p-6
  },
  { // Entry 274
    -0x1.498e36c4f385d5af3b6b6480a8ebfe14p-6,
    -0x1.499998p-6
  },
  { // Entry 275
    0x1.acb3be5be013930205335e91f230ec8bp-6,
    0x1.acccccp-6
  },
  { // Entry 276
    -0x1.acb3be5be013930205335e91f230ec8bp-6,
    -0x1.acccccp-6
  },
  { // Entry 277
    0x1.07e89e3abee7df5bc22b883856e5d802p-5,
    0x1.08p-5
  },
  { // Entry 278
    -0x1.07e89e3abee7df5bc22b883856e5d802p-5,
    -0x1.08p-5
  },
  { // Entry 279
    0x1.39726b6fab059b66dd740ae83fb565b7p-5,
    0x1.39999ap-5
  },
  { // Entry 280
    -0x1.39726b6fab059b66dd740ae83fb565b7p-5,
    -0x1.39999ap-5
  },
  { // Entry 281
    0x1.6af65a41908039c267674f356f997d4dp-5,
    0x1.6b3334p-5
  },
  { // Entry 282
    -0x1.6af65a41908039c267674f356f997d4dp-5,
    -0x1.6b3334p-5
  },
  { // Entry 283
    0x1.9c737ecdb90a7c4f9d8682bc2815635bp-5,
    0x1.9ccccep-5
  },
  { // Entry 284
    -0x1.9c737ecdb90a7c4f9d8682bc2815635bp-5,
    -0x1.9ccccep-5
  },
  { // Entry 285
    0x1.cde8ebf5a33a269c5529c53e853ce492p-5,
    0x1.ce6666p-5
  },
  { // Entry 286
    -0x1.cde8ebf5a33a269c5529c53e853ce492p-5,
    -0x1.ce6666p-5
  },
  { // Entry 287
    0x1.3359bcc32e58c6de203f8b6c19fa5ff9p-1,
    0x1.5e7fc4p-1
  },
  { // Entry 288
    -0x1.3359bcc32e58c6de203f8b6c19fa5ff9p-1,
    -0x1.5e7fc4p-1
  },
  { // Entry 289
    0x1.d5ca705d09beeec558a5b8db2d657192p-1,
    0x1.4e7fc4p0
  },
  { // Entry 290
    -0x1.d5ca705d09beeec558a5b8db2d657192p-1,
    -0x1.4e7fc4p0
  },
  { // Entry 291
    0x1.17ac440d8febeb7a1d19a5ae8faa7d7ep0,
    0x1.edbfa6p0
  },
  { // Entry 292
    -0x1.17ac440d8febeb7a1d19a5ae8faa7d7ep0,
    -0x1.edbfa6p0
  },
  { // Entry 293
    0x1.3279e84703fc9c8f702a678693102c47p0,
    0x1.467fc4p1
  },
  { // Entry 294
    -0x1.3279e84703fc9c8f702a678693102c47p0,
    -0x1.467fc4p1
  },
  { // Entry 295
    0x1.43f64467a5781271582ce61ccc6b0199p0,
    0x1.961fb4p1
  },
  { // Entry 296
    -0x1.43f64467a5781271582ce61ccc6b0199p0,
    -0x1.961fb4p1
  },
  { // Entry 297
    0x1.502a1cf082c199f85892b1763efa6c61p0,
    0x1.e5bfa4p1
  },
  { // Entry 298
    -0x1.502a1cf082c199f85892b1763efa6c61p0,
    -0x1.e5bfa4p1
  },
  { // Entry 299
    0x1.592066563d61378c65a8ef7d091bdc95p0,
    0x1.1aafcap2
  },
  { // Entry 300
    -0x1.592066563d61378c65a8ef7d091bdc95p0,
    -0x1.1aafcap2
  },
  { // Entry 301
    0x1.5ff8e21f712f9ee4424bbc711e1ef6f3p0,
    0x1.427fc2p2
  },
  { // Entry 302
    -0x1.5ff8e21f712f9ee4424bbc711e1ef6f3p0,
    -0x1.427fc2p2
  },
  { // Entry 303
    0x1.655d64f377c9e58e727f460133ed97a3p0,
    0x1.6a4fbap2
  },
  { // Entry 304
    -0x1.655d64f377c9e58e727f460133ed97a3p0,
    -0x1.6a4fbap2
  },
  { // Entry 305
    0x1.65711d6dd7ca878481fcb2ec4f9f9341p0,
    0x1.6af2f0p2
  },
  { // Entry 306
    -0x1.65711d6dd7ca878481fcb2ec4f9f9341p0,
    -0x1.6af2f0p2
  },
  { // Entry 307
    0x1.602a2a92bb3778489bbc165a7d25fb68p0,
    0x1.43c62ap2
  },
  { // Entry 308
    -0x1.602a2a92bb3778489bbc165a7d25fb68p0,
    -0x1.43c62ap2
  },
  { // Entry 309
    0x1.597f46a19f06d53bf1df42bfaedc5c4dp0,
    0x1.1c9964p2
  },
  { // Entry 310
    -0x1.597f46a19f06d53bf1df42bfaedc5c4dp0,
    -0x1.1c9964p2
  },
  { // Entry 311
    0x1.50d201d4d8188bc950ce239cd4991bb9p0,
    0x1.ead93cp1
  },
  { // Entry 312
    -0x1.50d201d4d8188bc950ce239cd4991bb9p0,
    -0x1.ead93cp1
  },
  { // Entry 313
    0x1.45190b163719c828307d6a3d0cf0b54cp0,
    0x1.9c7fb0p1
  },
  { // Entry 314
    -0x1.45190b163719c828307d6a3d0cf0b54cp0,
    -0x1.9c7fb0p1
  },
  { // Entry 315
    0x1.34794bb84d2baa02953a0a72b717f0ebp0,
    0x1.4e2624p1
  },
  { // Entry 316
    -0x1.34794bb84d2baa02953a0a72b717f0ebp0,
    -0x1.4e2624p1
  },
  { // Entry 317
    0x1.1b59864724a10efac8597e77461bc3f1p0,
    0x1.ff9932p0
  },
  { // Entry 318
    -0x1.1b59864724a10efac8597e77461bc3f1p0,
    -0x1.ff9932p0
  },
  { // Entry 319
    0x1.e44c89086d1aecac1cbe2b3941c67a0fp-1,
    0x1.62e61cp0
  },
  { // Entry 320
    -0x1.e44c89086d1aecac1cbe2b3941c67a0fp-1,
    -0x1.62e61cp0
  },
  { // Entry 321
    0x1.5150f28aee7aa819cb475b4a85ae7569p-1,
    0x1.8c662cp-1
  },
  { // Entry 322
    -0x1.5150f28aee7aa819cb475b4a85ae7569p-1,
    -0x1.8c662cp-1
  },
  { // Entry 323
    -0x1.073ea11368f7a47972c7a90fc77e3c33p0,
    -0x1.a8aa1cp0
  },
  { // Entry 324
    0x1.073ea11368f7a47972c7a90fc77e3c33p0,
    0x1.a8aa1cp0
  },
  { // Entry 325
    -0x1.021548e71bb3457d648c1924de4f5d65p0,
    -0x1.95ec8ap0
  },
  { // Entry 326
    0x1.021548e71bb3457d648c1924de4f5d65p0,
    0x1.95ec8ap0
  },
  { // Entry 327
    -0x1.f92364ca1fa2dabc63ba7f6e8a68d3f6p-1,
    -0x1.832ef8p0
  },
  { // Entry 328
    0x1.f92364ca1fa2dabc63ba7f6e8a68d3f6p-1,
    0x1.832ef8p0
  },
  { // Entry 329
    -0x1.ed577ea7517c28cbc891c018438dac11p-1,
    -0x1.707166p0
  },
  { // Entry 330
    0x1.ed577ea7517c28cbc891c018438dac11p-1,
    0x1.707166p0
  },
  { // Entry 331
    -0x1.e0b5226ef36d67e005a0eb9cfdb9b51ap-1,
    -0x1.5db3d4p0
  },
  { // Entry 332
    0x1.e0b5226ef36d67e005a0eb9cfdb9b51ap-1,
    0x1.5db3d4p0
  },
  { // Entry 333
    -0x1.d3290427f1d17e30a6993fbe96cc1fdfp-1,
    -0x1.4af642p0
  },
  { // Entry 334
    0x1.d3290427f1d17e30a6993fbe96cc1fdfp-1,
    0x1.4af642p0
  },
  { // Entry 335
    -0x1.c49e4505cff7e9f58be9c60ef08b794dp-1,
    -0x1.3838b0p0
  },
  { // Entry 336
    0x1.c49e4505cff7e9f58be9c60ef08b794dp-1,
    0x1.3838b0p0
  },
  { // Entry 337
    -0x1.b4fe80019a190ceb39c7cce2f0847082p-1,
    -0x1.257b1ep0
  },
  { // Entry 338
    0x1.b4fe80019a190ceb39c7cce2f0847082p-1,
    0x1.257b1ep0
  },
  { // Entry 339
    -0x1.a431f41e221ee2993e28481f34f7c822p-1,
    -0x1.12bd92p0
  },
  { // Entry 340
    0x1.a431f41e221ee2993e28481f34f7c822p-1,
    0x1.12bd92p0
  },
  { // Entry 341
    -0x1.8712787339dc1bb28aacdbb75d0eda49p-1,
    -0x1.ea5c3ep-1
  },
  { // Entry 342
    0x1.8712787339dc1bb28aacdbb75d0eda49p-1,
    0x1.ea5c3ep-1
  },
  { // Entry 343
    -0x1.7b8b3af8b9278dd5c80bf4f386dc5503p-1,
    -0x1.d4b87cp-1
  },
  { // Entry 344
    0x1.7b8b3af8b9278dd5c80bf4f386dc5503p-1,
    0x1.d4b87cp-1
  },
  { // Entry 345
    -0x1.6f851d6a4f403a71ef874dcc9ed9d59ap-1,
    -0x1.bf14bap-1
  },
  { // Entry 346
    0x1.6f851d6a4f403a71ef874dcc9ed9d59ap-1,
    0x1.bf14bap-1
  },
  { // Entry 347
    -0x1.62fb625437af22ec34ce96b17c5ac9ecp-1,
    -0x1.a970f8p-1
  },
  { // Entry 348
    0x1.62fb625437af22ec34ce96b17c5ac9ecp-1,
    0x1.a970f8p-1
  },
  { // Entry 349
    -0x1.55e98421ee9465b922d19e78004b9e96p-1,
    -0x1.93cd36p-1
  },
  { // Entry 350
    0x1.55e98421ee9465b922d19e78004b9e96p-1,
    0x1.93cd36p-1
  },
  { // Entry 351
    -0x1.484b4edaf8871846261a76bd33d9f049p-1,
    -0x1.7e2974p-1
  },
  { // Entry 352
    0x1.484b4edaf8871846261a76bd33d9f049p-1,
    0x1.7e2974p-1
  },
  { // Entry 353
    -0x1.3a1cfde1e590471ac2ff5eefe745a249p-1,
    -0x1.6885b2p-1
  },
  { // Entry 354
    0x1.3a1cfde1e590471ac2ff5eefe745a249p-1,
    0x1.6885b2p-1
  },
  { // Entry 355
    -0x1.2b5b5dbe8467930df24be6b9046ddfaep-1,
    -0x1.52e1f0p-1
  },
  { // Entry 356
    0x1.2b5b5dbe8467930df24be6b9046ddfaep-1,
    0x1.52e1f0p-1
  },
  { // Entry 357
    -0x1.1c03f7900131c7cb3fbfbb5e6c5115eap-1,
    -0x1.3d3e36p-1
  },
  { // Entry 358
    0x1.1c03f7900131c7cb3fbfbb5e6c5115eap-1,
    0x1.3d3e36p-1
  },
  { // Entry 359
    -0x1.eab7b26f955752e78c062cb6087064d9p-2,
    -0x1.0a0b02p-1
  },
  { // Entry 360
    0x1.eab7b26f955752e78c062cb6087064d9p-2,
    0x1.0a0b02p-1
  },
  { // Entry 361
    -0x1.bb12f2d65df13ff36b74e12066022236p-2,
    -0x1.d8f720p-2
  },
  { // Entry 362
    0x1.bb12f2d65df13ff36b74e12066022236p-2,
    0x1.d8f720p-2
  },
  { // Entry 363
    -0x1.894ae05fefe6ee1164c3e769b2b1a84ep-2,
    -0x1.9dd83cp-2
  },
  { // Entry 364
    0x1.894ae05fefe6ee1164c3e769b2b1a84ep-2,
    0x1.9dd83cp-2
  },
  { // Entry 365
    -0x1.5579fd644a1a2d96faf5bb8844656d0cp-2,
    -0x1.62b958p-2
  },
  { // Entry 366
    0x1.5579fd644a1a2d96faf5bb8844656d0cp-2,
    0x1.62b958p-2
  },
  { // Entry 367
    -0x1.1fc79ca9ca92823d01375328ac472eedp-2,
    -0x1.279a74p-2
  },
  { // Entry 368
    0x1.1fc79ca9ca92823d01375328ac472eedp-2,
    0x1.279a74p-2
  },
  { // Entry 369
    -0x1.d0d0f7d861c753c31fa29e74145dc127p-3,
    -0x1.d8f720p-3
  },
  { // Entry 370
    0x1.d0d0f7d861c753c31fa29e74145dc127p-3,
    0x1.d8f720p-3
  },
  { // Entry 371
    -0x1.5f3d40f500501f80bba7a781b1619b85p-3,
    -0x1.62b958p-3
  },
  { // Entry 372
    0x1.5f3d40f500501f80bba7a781b1619b85p-3,
    0x1.62b958p-3
  },
  { // Entry 373
    -0x1.d6e1429159f6f0290cf9f2fb24bc26bdp-4,
    -0x1.d8f720p-4
  },
  { // Entry 374
    0x1.d6e1429159f6f0290cf9f2fb24bc26bdp-4,
    0x1.d8f720p-4
  },
  { // Entry 375
    -0x1.d870dc6f0c1b3da66fb282eb78c47134p-5,
    -0x1.d8f720p-5
  },
  { // Entry 376
    0x1.d870dc6f0c1b3da66fb282eb78c47134p-5,
    0x1.d8f720p-5
  },
  { // Entry 377
    0x1.d870dc6f0c1b3da66fb282eb78c47134p-5,
    0x1.d8f720p-5
  },
  { // Entry 378
    -0x1.d870dc6f0c1b3da66fb282eb78c47134p-5,
    -0x1.d8f720p-5
  },
  { // Entry 379
    0x1.d6e1429159f6f0290cf9f2fb24bc26bdp-4,
    0x1.d8f720p-4
```
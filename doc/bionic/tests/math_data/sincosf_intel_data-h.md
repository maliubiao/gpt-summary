Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The user provided a data file (`sincosf_intel_data.handroid`) and wants to know its purpose, relationship to Android, how it works internally, and how to debug it. Crucially, this is part 1 of a 4-part request, and I need to summarize the *immediate* functionality of this specific file.

2. **Initial Analysis of the File:**
    * **File Name and Path:** `bionic/tests/math_data/sincosf_intel_data.handroid`. Keywords here are "tests," "math_data," "sincosf," and "intel."  This strongly suggests it's test data for the `sincosf` function, likely optimized for Intel architectures within Android's math library.
    * **Copyright Notice:** Confirms it's part of the Android Open Source Project (AOSP).
    * **Data Structure:** The file contains an array named `g_sincosf_intel_data`. Each element of the array is a struct-like structure (though defined using a template `data_2_1_t`) holding three floating-point numbers.
    * **Floating-Point Representation:** The numbers are in hexadecimal floating-point format (e.g., `-0x1.b6a7abffaf59a5ac181e3e1abf961698p-1`). This reinforces the idea that it's numerical test data.
    * **Paired Entries:** The data appears in pairs (e.g., Entry 0 and Entry 1 have the same magnitude for the first two values but opposite signs for the first and third). This hints at testing symmetry or different quadrants for trigonometric functions.

3. **Formulate a Hypothesis:** Based on the analysis, the most likely function of this file is to provide input/output pairs for testing the `sincosf` function (calculating sine and cosine simultaneously) within Android's Bionic library, specifically for Intel-based Android devices. The three floats in each entry likely represent: input angle, expected sine, and expected cosine.

4. **Address the Specific Questions (for Part 1):**

    * **功能 (Functionality):** Directly states the hypothesis: test data for `sincosf`. Emphasizes the Intel-specific nature.
    * **与 Android 功能的关系 (Relationship to Android):** Connects it to Bionic's math library and its role in ensuring accurate math operations on Android devices. Explains that `sincosf` is a standard C library function, demonstrating its relevance within the broader Android ecosystem.
    * **libc 函数的功能是如何实现的 (How libc functions are implemented):**  Acknowledges that this file *doesn't* contain the implementation. It's *data* for testing the implementation. Briefly mentions that `sincosf` likely uses approximations and look-up tables for efficiency. Avoids getting bogged down in implementation details since it's not in the provided code.
    * **涉及 dynamic linker 的功能 (Dynamic linker functionality):** States that this file is *data*, not code, so it doesn't directly involve the dynamic linker. The dynamic linker is involved in loading the *library* containing the `sincosf` implementation, but this data file is used *by* that library.
    * **逻辑推理 (Logical deduction):** Explains the assumed input (angle) and outputs (sine and cosine) based on the observed data structure. Highlights the paired entries and the sign changes, connecting them to the properties of sine and cosine.
    * **用户或者编程常见的使用错误 (Common user/programming errors):** Focuses on misinterpreting or incorrectly using the *test data* itself (e.g., assuming it's the implementation or using the wrong data types).
    * **android framework or ndk 是如何一步步的到达这里 (How Android Framework/NDK reaches here):** Explains the general path: NDK calls a math function, which is implemented in Bionic, and this test data is used during Bionic's development/testing. Avoids overly specific details since the request is about *reaching* the data file, not the execution path within the `sincosf` function itself.
    * **frida hook 示例调试这些步骤 (Frida hook example):** Provides a basic example of hooking the `sincosf` function to observe the input and output, showing how Frida could interact with the *function* being tested, even though it doesn't directly interact with the *data file* at runtime.
    * **归纳一下它的功能 (Summarize its functionality):**  Reiterates the core purpose: test data for `sincosf`, emphasizing its role in verifying the correctness of the implementation.

5. **Review and Refine:** Ensures the language is clear, concise, and accurate. Checks that all parts of the "Part 1" request are addressed. Anticipates the user's next questions based on the structure of the full request (even though I'm only answering Part 1 now). This helps in setting the context and avoiding contradictions in later parts.

By following this systematic approach, I can generate a comprehensive and accurate answer to the user's request, specifically addressing the constraints of Part 1. The key is to carefully analyze the provided code snippet, make informed inferences, and connect it to the broader context of Android's Bionic library and the purpose of testing.
好的，根据您提供的代码文件 `bionic/tests/math_data/sincosf_intel_data.handroid` 的内容，我们可以归纳出以下功能：

**这个文件的主要功能是作为针对 `sincosf` 函数的测试数据。**

具体来说：

* **提供测试用例:** 文件中定义了一个名为 `g_sincosf_intel_data` 的数组。这个数组的元素是 `data_2_1_t<float, float, float>` 类型的结构体。每个结构体包含三个 `float` 类型的值。
* **用于验证 `sincosf` 的正确性:**  从结构体中数据的命名和数值格式来看，这三个 `float` 值很可能分别代表：
    * **输入角度 (弧度制):** 第一个 `float` 值。
    * **期望的 sin 值:** 第二个 `float` 值。
    * **期望的 cos 值:** 第三个 `float` 值。
* **针对 Intel 架构优化:** 文件名中包含 "intel"，暗示这些测试数据可能是为了验证或校准 `sincosf` 函数在 Intel 架构处理器上的实现和优化。
* **Bionic 库的一部分:**  文件位于 `bionic/tests/math_data/` 目录下，明确表明它是 Android Bionic 库数学测试套件的一部分。

**总结:**

`sincosf_intel_data.handroid` 文件是一个包含预定义输入角度及其对应的预期 `sin` 和 `cos` 值的测试数据集。它被用于测试 Android Bionic 库中 `sincosf` 函数在 Intel 架构上的实现是否正确和精准。

在后续的部分，我们可以进一步探讨：

* **这个文件与 Android 功能的关系。**
* **`sincosf` 函数的实现原理。**
* **动态链接器在加载和使用 `sincosf` 函数中的作用。**
* **如何使用这些数据进行测试和调试。**
* **Frida Hook 的应用场景。**

Prompt: 
```
这是目录为bionic/tests/math_data/sincosf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_2_1_t<float, float, float> g_sincosf_intel_data[] = {
  { // Entry 0
    -0x1.b6a7abffaf59a5ac181e3e1abf961698p-1,
    0x1.080e74c116863cfab82a0fd59c71b363p-1,
    -0x1.0768p0,
  },
  { // Entry 1
    0x1.b6a7abffaf59a5ac181e3e1abf961698p-1,
    0x1.080e74c116863cfab82a0fd59c71b363p-1,
    0x1.0768p0,
  },
  { // Entry 2
    0x1.762da6648fde00e398462e7163094d52p-2,
    0x1.dc9802ffffffe0cbfc57ef287d3c83afp-1,
    -0x1.8f219cp5,
  },
  { // Entry 3
    -0x1.762da6648fde00e398462e7163094d52p-2,
    0x1.dc9802ffffffe0cbfc57ef287d3c83afp-1,
    0x1.8f219cp5,
  },
  { // Entry 4
    -0x1.493b6a7d3f5b7bf66fa32a01515d6c43p-1,
    -0x1.881c26fd25d0bf6d6ea38708a0976b35p-1,
    -0x1.d3a51ap80,
  },
  { // Entry 5
    0x1.493b6a7d3f5b7bf66fa32a01515d6c43p-1,
    -0x1.881c26fd25d0bf6d6ea38708a0976b35p-1,
    0x1.d3a51ap80,
  },
  { // Entry 6
    -0x1.e0d1dc006e85835b0394abe97de77fbcp-4,
    0x1.fc75ca6313ef766012db3ca99a1a52d1p-1,
    -0x1.e1ee52p-4,
  },
  { // Entry 7
    0x1.e0d1dc006e85835b0394abe97de77fbcp-4,
    0x1.fc75ca6313ef766012db3ca99a1a52d1p-1,
    0x1.e1ee52p-4,
  },
  { // Entry 8
    -0x1.2b6a9ca3df622efe2aa3154a6352bc70p-1,
    -0x1.9f52def55d89e92e7df20ec21161deb8p-1,
    -0x1.f3ffe2p24,
  },
  { // Entry 9
    0x1.2b6a9ca3df622efe2aa3154a6352bc70p-1,
    -0x1.9f52def55d89e92e7df20ec21161deb8p-1,
    0x1.f3ffe2p24,
  },
  { // Entry 10
    0x1.a3422af13b2cfb78d0cc458d9ac6bde9p-1,
    -0x1.25e1aa1d9383c1f27027cf69b69477fdp-1,
    -0x1.ff211ep24,
  },
  { // Entry 11
    -0x1.a3422af13b2cfb78d0cc458d9ac6bde9p-1,
    -0x1.25e1aa1d9383c1f27027cf69b69477fdp-1,
    0x1.ff211ep24,
  },
  { // Entry 12
    0x1.ffffffaaaaaaaeeeeeeed4ed4ed549c6p-13,
    0x1.ffffff000000155555549f49f4a28a28p-1,
    0x1.p-12,
  },
  { // Entry 13
    -0x1.ffffffaaaaaaaeeeeeeed4ed4ed549c6p-13,
    0x1.ffffff000000155555549f49f4a28a28p-1,
    -0x1.p-12,
  },
  { // Entry 14
    0x1.000001d555545777758cbfcafc09ef7ep-12,
    0x1.fffffefffffc155551ff49f696c4aecap-1,
    0x1.000002p-12,
  },
  { // Entry 15
    -0x1.000001d555545777758cbfcafc09ef7ep-12,
    0x1.fffffefffffc155551ff49f696c4aecap-1,
    -0x1.000002p-12,
  },
  { // Entry 16
    0x1.000001ffffffffffd555545555535555p-32,
    0x1.fffffffffffffffefffffbfffffcp-1,
    0x1.000002p-32,
  },
  { // Entry 17
    -0x1.000001ffffffffffd555545555535555p-32,
    0x1.fffffffffffffffefffffbfffffcp-1,
    -0x1.000002p-32,
  },
  { // Entry 18
    0x1.eaf0d5008f2db899e2487da9d3b9cde7p-2,
    0x1.c151df4f12b197a665a2907e4933a1efp-1,
    0x1.000150p-1,
  },
  { // Entry 19
    -0x1.eaf0d5008f2db899e2487da9d3b9cde7p-2,
    0x1.c151df4f12b197a665a2907e4933a1efp-1,
    -0x1.000150p-1,
  },
  { // Entry 20
    0x1.eaf77efff659021bc827bbd5696ad19ep-2,
    0x1.c1500d494ed2cc5002c27cc5ca3d96f8p-1,
    0x1.00051cp-1,
  },
  { // Entry 21
    -0x1.eaf77efff659021bc827bbd5696ad19ep-2,
    0x1.c1500d494ed2cc5002c27cc5ca3d96f8p-1,
    -0x1.00051cp-1,
  },
  { // Entry 22
    -0x1.5aa53c1c1317f30b4c108722e2b64612p-1,
    0x1.78cdb6ffa6bff899e1723ed0139c48cbp-1,
    0x1.000fdep80,
  },
  { // Entry 23
    0x1.5aa53c1c1317f30b4c108722e2b64612p-1,
    0x1.78cdb6ffa6bff899e1723ed0139c48cbp-1,
    -0x1.000fdep80,
  },
  { // Entry 24
    0x1.aef38822e64311445545980fbc5b56fap-1,
    0x1.14735fffd55120a4480b7c91a1d78d6ep-1,
    0x1.001cp0,
  },
  { // Entry 25
    -0x1.aef38822e64311445545980fbc5b56fap-1,
    0x1.14735fffd55120a4480b7c91a1d78d6ep-1,
    -0x1.001cp0,
  },
  { // Entry 26
    -0x1.7e12aee0c862b1709bd50205bba32167p-1,
    -0x1.54d4290010a68826a882e7c87d6694d2p-1,
    0x1.0027b8p40,
  },
  { // Entry 27
    0x1.7e12aee0c862b1709bd50205bba32167p-1,
    -0x1.54d4290010a68826a882e7c87d6694d2p-1,
    -0x1.0027b8p40,
  },
  { // Entry 28
    -0x1.bd6944ef4dd1b43962e2d3480410fd87p-1,
    0x1.f8fc8efff67d834f6878ab4e44fa89b5p-2,
    0x1.004840p68,
  },
  { // Entry 29
    0x1.bd6944ef4dd1b43962e2d3480410fd87p-1,
    0x1.f8fc8efff67d834f6878ab4e44fa89b5p-2,
    -0x1.004840p68,
  },
  { // Entry 30
    0x1.f4e23e00165a4907a656a7cf532bbde4p-2,
    0x1.be91601e47bed6d45e8372687b373c0cp-1,
    0x1.05b0p-1,
  },
  { // Entry 31
    -0x1.f4e23e00165a4907a656a7cf532bbde4p-2,
    0x1.be91601e47bed6d45e8372687b373c0cp-1,
    -0x1.05b0p-1,
  },
  { // Entry 32
    0x1.b6a7abffaf59a5ac181e3e1abf961698p-1,
    0x1.080e74c116863cfab82a0fd59c71b363p-1,
    0x1.0768p0,
  },
  { // Entry 33
    -0x1.b6a7abffaf59a5ac181e3e1abf961698p-1,
    0x1.080e74c116863cfab82a0fd59c71b363p-1,
    -0x1.0768p0,
  },
  { // Entry 34
    0x1.bcb8aafffffd69d2865aaf3f4c5074e8p-1,
    0x1.fb69a6dc513bcba59d5dc68d3d59a05cp-2,
    0x1.0d67a4p0,
  },
  { // Entry 35
    -0x1.bcb8aafffffd69d2865aaf3f4c5074e8p-1,
    0x1.fb69a6dc513bcba59d5dc68d3d59a05cp-2,
    -0x1.0d67a4p0,
  },
  { // Entry 36
    0x1.bf683cffffec6e8672a49f08aae49c46p-1,
    0x1.f1e0f653d695977ccd240ff6b9297393p-2,
    0x1.1024p0,
  },
  { // Entry 37
    -0x1.bf683cffffec6e8672a49f08aae49c46p-1,
    0x1.f1e0f653d695977ccd240ff6b9297393p-2,
    -0x1.1024p0,
  },
  { // Entry 38
    0x1.8b1e8e1c16a8d970a78a2391eea6575cp-1,
    -0x1.459d4500000092b4b8307c652ee639a7p-1,
    0x1.21497ep1,
  },
  { // Entry 39
    -0x1.8b1e8e1c16a8d970a78a2391eea6575cp-1,
    -0x1.459d4500000092b4b8307c652ee639a7p-1,
    -0x1.21497ep1,
  },
  { // Entry 40
    0x1.6991e0ffe7f9c9b3ef7b3017d23639fap-1,
    -0x1.6a81c4133db73e276c89e724c6fe975bp-1,
    0x1.2dc230p1,
  },
  { // Entry 41
    -0x1.6991e0ffe7f9c9b3ef7b3017d23639fap-1,
    -0x1.6a81c4133db73e276c89e724c6fe975bp-1,
    -0x1.2dc230p1,
  },
  { // Entry 42
    0x1.41f6bd0000d13ba2bd7a63bf6d950865p-1,
    -0x1.8e197fe4fac9901dc07a2878baf15c7ap-1,
    0x1.344248p18,
  },
  { // Entry 43
    -0x1.41f6bd0000d13ba2bd7a63bf6d950865p-1,
    -0x1.8e197fe4fac9901dc07a2878baf15c7ap-1,
    -0x1.344248p18,
  },
  { // Entry 44
    0x1.37f8deffffff61ca15c366b3add8f373p-1,
    -0x1.95fa20d230fdf9e8cccc5921e61f03adp-1,
    0x1.3e42p1,
  },
  { // Entry 45
    -0x1.37f8deffffff61ca15c366b3add8f373p-1,
    -0x1.95fa20d230fdf9e8cccc5921e61f03adp-1,
    -0x1.3e42p1,
  },
  { // Entry 46
    0x1.2ed7ce518f4660cce49556856784970cp-1,
    0x1.9cd4f3000002264af2b32ebe5d8243c0p-1,
    0x1.440c3ap-1,
  },
  { // Entry 47
    -0x1.2ed7ce518f4660cce49556856784970cp-1,
    0x1.9cd4f3000002264af2b32ebe5d8243c0p-1,
    -0x1.440c3ap-1,
  },
  { // Entry 48
    0x1.475fc937750bdf2f704177612d31dc1fp-1,
    0x1.89a999000012c047e4b24181d6158640p-1,
    0x1.632f6ap-1,
  },
  { // Entry 49
    -0x1.475fc937750bdf2f704177612d31dc1fp-1,
    0x1.89a999000012c047e4b24181d6158640p-1,
    -0x1.632f6ap-1,
  },
  { // Entry 50
    -0x1.8ace1cfcc0a766b35d0e8f48f3169e8ap-1,
    -0x1.45fec95a40619819e3307aebe0cb5e89p-1,
    0x1.6e8f18p24,
  },
  { // Entry 51
    0x1.8ace1cfcc0a766b35d0e8f48f3169e8ap-1,
    -0x1.45fec95a40619819e3307aebe0cb5e89p-1,
    -0x1.6e8f18p24,
  },
  { // Entry 52
    0x1.7c6b92ff24ff028ea35c459e5ebeb2cdp-1,
    0x1.56ac2ae54cc9a5210ae673ea1ce31d47p-1,
    0x1.795840p23,
  },
  { // Entry 53
    -0x1.7c6b92ff24ff028ea35c459e5ebeb2cdp-1,
    0x1.56ac2ae54cc9a5210ae673ea1ce31d47p-1,
    -0x1.795840p23,
  },
  { // Entry 54
    0x1.697cf4ffea9244e85cea640d13c6fbb5p-1,
    -0x1.6a96a106ace21610ab529c9047c7e6e2p-1,
    0x1.7fe7fep35,
  },
  { // Entry 55
    -0x1.697cf4ffea9244e85cea640d13c6fbb5p-1,
    -0x1.6a96a106ace21610ab529c9047c7e6e2p-1,
    -0x1.7fe7fep35,
  },
  { // Entry 56
    0x1.9c6cf2fffffe8588512ea3c808b0fa9fp-1,
    0x1.2f6560e0f14cd5d68920bec0e0c25354p-1,
    0x1.ce1026p2,
  },
  { // Entry 57
    -0x1.9c6cf2fffffe8588512ea3c808b0fa9fp-1,
    0x1.2f6560e0f14cd5d68920bec0e0c25354p-1,
    -0x1.ce1026p2,
  },
  { // Entry 58
    -0x1.07fac04c6e73f485096bdaa3e65044d9p-1,
    -0x1.b6b387ffceb67a18c15e868550b96462p-1,
    0x1.d775d0p1,
  },
  { // Entry 59
    0x1.07fac04c6e73f485096bdaa3e65044d9p-1,
    -0x1.b6b387ffceb67a18c15e868550b96462p-1,
    -0x1.d775d0p1,
  },
  { // Entry 60
    0x1.9a8c62f4b2a949b06924662d9436bf17p-1,
    0x1.31ee7074e3ebc5a30f0092ec6c5d8b80p-1,
    0x1.dfeaaap108,
  },
  { // Entry 61
    -0x1.9a8c62f4b2a949b06924662d9436bf17p-1,
    0x1.31ee7074e3ebc5a30f0092ec6c5d8b80p-1,
    -0x1.dfeaaap108,
  },
  { // Entry 62
    0x1.d4de8affffffd96f83ba442fdf2f7101p-2,
    0x1.c72cd4e1d6c78547d31707be80b4b0aep-1,
    0x1.e7061ep-2,
  },
  { // Entry 63
    -0x1.d4de8affffffd96f83ba442fdf2f7101p-2,
    0x1.c72cd4e1d6c78547d31707be80b4b0aep-1,
    -0x1.e7061ep-2,
  },
  { // Entry 64
    -0x1.483445d4194813168a1ac63eee1943f9p-1,
    0x1.88f882fcbc81ffdf720a4bb1b2fca71dp-1,
    0x1.e89b2ap80,
  },
  { // Entry 65
    0x1.483445d4194813168a1ac63eee1943f9p-1,
    0x1.88f882fcbc81ffdf720a4bb1b2fca71dp-1,
    -0x1.e89b2ap80,
  },
  { // Entry 66
    0x1.565e410014916fa6550e606ed588c6b8p-1,
    0x1.7cb1b34af85589bdaf7c0793af30b682p-1,
    0x1.fe8270p18,
  },
  { // Entry 67
    -0x1.565e410014916fa6550e606ed588c6b8p-1,
    0x1.7cb1b34af85589bdaf7c0793af30b682p-1,
    -0x1.fe8270p18,
  },
  { // Entry 68
    -0x1.8356fbaea0454bce3983d9a0e0250c55p-1,
    -0x1.4ed4c5ffc8018741870949767ff8dafap-1,
    0x1.fff1fep1,
  },
  { // Entry 69
    0x1.8356fbaea0454bce3983d9a0e0250c55p-1,
    -0x1.4ed4c5ffc8018741870949767ff8dafap-1,
    -0x1.fff1fep1,
  },
  { // Entry 70
    0x1.fa9d6bfb33a77b2e3b3289168ced6dcap-1,
    -0x1.28406a0025545c9a568dacd45518dd65p-3,
    0x1.fff1fep2,
  },
  { // Entry 71
    -0x1.fa9d6bfb33a77b2e3b3289168ced6dcap-1,
    -0x1.28406a0025545c9a568dacd45518dd65p-3,
    -0x1.fff1fep2,
  },
  { // Entry 72
    0x1.d18f76ffc6e4ba0a3134e5be21b5bc8fp-1,
    -0x1.aa2241160227896c68ef17839f17dce5p-2,
    0x1.fffff6p0,
  },
  { // Entry 73
    -0x1.d18f76ffc6e4ba0a3134e5be21b5bc8fp-1,
    -0x1.aa2241160227896c68ef17839f17dce5p-2,
    -0x1.fffff6p0,
  },
  { // Entry 74
    0x1.fffffaaaaab2eeeedc3dc3f1ee7b41fep-12,
    0x1.fffffc00001155553a7d27f4a289f319p-1,
    0x1.fffffcp-12,
  },
  { // Entry 75
    -0x1.fffffaaaaab2eeeedc3dc3f1ee7b41fep-12,
    0x1.fffffc00001155553a7d27f4a289f319p-1,
    -0x1.fffffcp-12,
  },
  { // Entry 76
    -0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
  },
  { // Entry 77
    0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149,
  },
  { // Entry 78
    0.0,
    0x1.p0,
    0.0,
  },
  { // Entry 79
    0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149,
  },
  { // Entry 80
    -0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
  },
  { // Entry 81
    -0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.000002p-126,
  },
  { // Entry 82
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.000002p-126,
  },
  { // Entry 83
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-126,
  },
  { // Entry 84
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-126,
  },
  { // Entry 85
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffcp-127,
  },
  { // Entry 86
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffcp-127,
  },
  { // Entry 87
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffcp-127,
  },
  { // Entry 88
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffcp-127,
  },
  { // Entry 89
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-126,
  },
  { // Entry 90
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-126,
  },
  { // Entry 91
    0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.000002p-126,
  },
  { // Entry 92
    -0x1.000001ffffffffffffffffffffffffffp-126,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.000002p-126,
  },
  { // Entry 93
    0x1.999999d44f3058c789014b7d0e22fec3p-13,
    0x1.ffffff5c28f57960cd56ebfe9482a61fp-1,
    0x1.99999ap-13,
  },
  { // Entry 94
    -0x1.999999d44f3058c789014b7d0e22fec3p-13,
    0x1.ffffff5c28f57960cd56ebfe9482a61fp-1,
    -0x1.99999ap-13,
  },
  { // Entry 95
    0x1.999999513cc173e51bb9955b066f1db8p-12,
    0x1.fffffd70a3d64e5ec165cd4307ad1326p-1,
    0x1.99999ap-12,
  },
  { // Entry 96
    -0x1.999999513cc173e51bb9955b066f1db8p-12,
    0x1.fffffd70a3d64e5ec165cd4307ad1326p-1,
    -0x1.99999ap-12,
  },
  { // Entry 97
    0x1.333332d91685321e5fc397d20a5af1e6p-11,
    0x1.fffffa3d709eecbfb5a385b0f3e0cb8fp-1,
    0x1.333334p-11,
  },
  { // Entry 98
    -0x1.333332d91685321e5fc397d20a5af1e6p-11,
    0x1.fffffa3d709eecbfb5a385b0f3e0cb8fp-1,
    -0x1.333334p-11,
  },
  { // Entry 99
    0x1.99999744f306dc03e9ef70897f78299ep-11,
    0x1.fffff5c28f5fc733c4202aa0bda92f97p-1,
    0x1.99999ap-11,
  },
  { // Entry 100
    -0x1.99999744f306dc03e9ef70897f78299ep-11,
    0x1.fffff5c28f5fc733c4202aa0bda92f97p-1,
    -0x1.99999ap-11,
  },
  { // Entry 101
    0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    0x1.p-10,
  },
  { // Entry 102
    -0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    -0x1.p-10,
  },
  { // Entry 103
    0x1.33332f645a18c3b0ccfc0a3cf7b2e91bp-10,
    0x1.ffffe8f5c29ce07640bd5f6d8bb1ea6bp-1,
    0x1.333334p-10,
  },
  { // Entry 104
    -0x1.33332f645a18c3b0ccfc0a3cf7b2e91bp-10,
    0x1.ffffe8f5c29ce07640bd5f6d8bb1ea6bp-1,
    -0x1.333334p-10,
  },
  { // Entry 105
    0x1.666660aec330821c7a100cf488c380ebp-10,
    0x1.ffffe0a3d714839f3601147ada73f8d9p-1,
    0x1.666668p-10,
  },
  { // Entry 106
    -0x1.666660aec330821c7a100cf488c380ebp-10,
    0x1.ffffe0a3d714839f3601147ada73f8d9p-1,
    -0x1.666668p-10,
  },
  { // Entry 107
    0x1.99999113cc034144fdbdc8a1dc713253p-10,
    0x1.ffffd70a3d8191f66de5408fb2b995a0p-1,
    0x1.99999cp-10,
  },
  { // Entry 108
    -0x1.99999113cc034144fdbdc8a1dc713253p-10,
    0x1.ffffd70a3d8191f66de5408fb2b995a0p-1,
    -0x1.99999cp-10,
  },
  { // Entry 109
    0x1.ccccbc72b05dd0951a9c5e65560c56e3p-10,
    0x1.ffffcc28f6d096b87d6d19a06e96999bp-1,
    0x1.ccccccp-10,
  },
  { // Entry 110
    -0x1.ccccbc72b05dd0951a9c5e65560c56e3p-10,
    0x1.ffffcc28f6d096b87d6d19a06e96999bp-1,
    -0x1.ccccccp-10,
  },
  { // Entry 111
    0x1.0665ae3615b5b7de52798064dfc59b29p-7,
    0x1.fffbcc2a71ceaabf5582b6da1fc30531p-1,
    0x1.066666p-7,
  },
  { // Entry 112
    -0x1.0665ae3615b5b7de52798064dfc59b29p-7,
    0x1.fffbcc2a71ceaabf5582b6da1fc30531p-1,
    -0x1.066666p-7,
  },
  { // Entry 113
    0x1.ccc8e8ae92586d8d66b6ad0aedcb0d94p-7,
    0x1.fff30a4b7b5119d8e299f717ec0ece16p-1,
    0x1.ccccccp-7,
  },
  { // Entry 114
    -0x1.ccc8e8ae92586d8d66b6ad0aedcb0d94p-7,
    0x1.fff30a4b7b5119d8e299f717ec0ece16p-1,
    -0x1.ccccccp-7,
  },
  { // Entry 115
    0x1.4993e70f7b17c10af9f97fc7b33b822bp-6,
    0x1.ffe57a785123226c1e2efb411353edc9p-1,
    0x1.499998p-6,
  },
  { // Entry 116
    -0x1.4993e70f7b17c10af9f97fc7b33b822bp-6,
    0x1.ffe57a785123226c1e2efb411353edc9p-1,
    -0x1.499998p-6,
  },
  { // Entry 117
    0x1.acc043f8b2d89ad5143c030e9766fc11p-6,
    0x1.ffd31cd10cb632d9733ac5f5f327a5f9p-1,
    0x1.acccccp-6,
  },
  { // Entry 118
    -0x1.acc043f8b2d89ad5143c030e9766fc11p-6,
    0x1.ffd31cd10cb632d9733ac5f5f327a5f9p-1,
    -0x1.acccccp-6,
  },
  { // Entry 119
    0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    0x1.08p-5,
  },
  { // Entry 120
    -0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    -0x1.08p-5,
  },
  { // Entry 121
    0x1.3985fead44fa2b851e651acba369d769p-5,
    0x1.ff9ff8c2eaeaee30fb211765af835171p-1,
    0x1.39999ap-5,
  },
  { // Entry 122
    -0x1.3985fead44fa2b851e651acba369d769p-5,
    0x1.ff9ff8c2eaeaee30fb211765af835171p-1,
    -0x1.39999ap-5,
  },
  { // Entry 123
    0x1.6b14beb5d40d745096247e59b622828bp-5,
    0x1.ff7f32d6eb1f9cf90226ec291c9e0922p-1,
    0x1.6b3334p-5,
  },
  { // Entry 124
    -0x1.6b14beb5d40d745096247e59b622828bp-5,
    0x1.ff7f32d6eb1f9cf90226ec291c9e0922p-1,
    -0x1.6b3334p-5,
  },
  { // Entry 125
    0x1.9ca01671a7995fc97cebd69729cc4309p-5,
    0x1.ff59a00cc4ad492ca2597495412998edp-1,
    0x1.9ccccep-5,
  },
  { // Entry 126
    -0x1.9ca01671a7995fc97cebd69729cc4309p-5,
    0x1.ff59a00cc4ad492ca2597495412998edp-1,
    -0x1.9ccccep-5,
  },
  { // Entry 127
    0x1.ce278cd9eb2cbd0c6a4e1279f690e856p-5,
    0x1.ff2f40c08acf4580a8d13380d9073398p-1,
    0x1.ce6666p-5,
  },
  { // Entry 128
    -0x1.ce278cd9eb2cbd0c6a4e1279f690e856p-5,
    0x1.ff2f40c08acf4580a8d13380d9073398p-1,
    -0x1.ce6666p-5,
  },
  { // Entry 129
    0x1.43c1e9972391aa8ecd8a9ccba907920ap-1,
    0x1.8ca46ca011771bfae0d9edbf1dacb402p-1,
    0x1.5e7fc4p-1,
  },
  { // Entry 130
    -0x1.43c1e9972391aa8ecd8a9ccba907920ap-1,
    0x1.8ca46ca011771bfae0d9edbf1dacb402p-1,
    -0x1.5e7fc4p-1,
  },
  { // Entry 131
    0x1.ee3d6bb21c64b2382efcff0cdf30ce0bp-1,
    0x1.0b5d38d5d82e4a7624dac4e10ce159c2p-2,
    0x1.4e7fc4p0,
  },
  { // Entry 132
    -0x1.ee3d6bb21c64b2382efcff0cdf30ce0bp-1,
    0x1.0b5d38d5d82e4a7624dac4e10ce159c2p-2,
    -0x1.4e7fc4p0,
  },
  { // Entry 133
    0x1.df8e2323e4bf1a538a100ec1bf3494a9p-1,
    -0x1.66b96e204e69cda8e9cf50996432539ep-2,
    0x1.edbfa6p0,
  },
  { // Entry 134
    -0x1.df8e2323e4bf1a538a100ec1bf3494a9p-1,
    -0x1.66b96e204e69cda8e9cf50996432539ep-2,
    -0x1.edbfa6p0,
  },
  { // Entry 135
    0x1.1d347aa02feb3bb1750d25509435da88p-1,
    -0x1.a935540edeca4c220ed91dc5481e4d9bp-1,
    0x1.467fc4p1,
  },
  { // Entry 136
    -0x1.1d347aa02feb3bb1750d25509435da88p-1,
    -0x1.a935540edeca4c220ed91dc5481e4d9bp-1,
    -0x1.467fc4p1,
  },
  { // Entry 137
    -0x1.ffea08e1c97f4c4de01961cc3e7b04dcp-6,
    -0x1.ffc0017dd9209dd8891f17fe4c9eee46p-1,
    0x1.961fb4p1,
  },
  { // Entry 138
    0x1.ffea08e1c97f4c4de01961cc3e7b04dcp-6,
    -0x1.ffc0017dd9209dd8891f17fe4c9eee46p-1,
    -0x1.961fb4p1,
  },
  { // Entry 139
    -0x1.3734cbced9c0f484e5f762e00216e620p-1,
    -0x1.969082007733d787f4c36ba0f9425694p-1,
    0x1.e5bfa4p1,
  },
  { // Entry 140
    0x1.3734cbced9c0f484e5f762e00216e620p-1,
    -0x1.969082007733d787f4c36ba0f9425694p-1,
    -0x1.e5bfa4p1,
  },
  { // Entry 141
    -0x1.e9d2592bec10c3acb15c5852239a2aa8p-1,
    -0x1.2a1e74223d9bddb7db59f781f96b65ecp-2,
    0x1.1aafcap2,
  },
  { // Entry 142
    0x1.e9d2592bec10c3acb15c5852239a2aa8p-1,
    -0x1.2a1e74223d9bddb7db59f781f96b65ecp-2,
    -0x1.1aafcap2,
  },
  { // Entry 143
    -0x1.e4ece208d0c4913ab019cab0ce9c785ep-1,
    0x1.4894d50b84dbc981134a591ac4165d9ep-2,
    0x1.427fc2p2,
  },
  { // Entry 144
    0x1.e4ece208d0c4913ab019cab0ce9c785ep-1,
    0x1.4894d50b84dbc981134a591ac4165d9ep-2,
    -0x1.427fc2p2,
  },
  { // Entry 145
    -0x1.2a5a02d392b54f641a0d88bd4ac6c2e1p-1,
    0x1.a016dd7480a1eea4d49efb585fa49c86p-1,
    0x1.6a4fbap2,
  },
  { // Entry 146
    0x1.2a5a02d392b54f641a0d88bd4ac6c2e1p-1,
    0x1.a016dd7480a1eea4d49efb585fa49c86p-1,
    -0x1.6a4fbap2,
  },
  { // Entry 147
    -0x1.263123df22d13ed329c665c83c0e71e8p-1,
    0x1.a30a6a3bf4a3e2b7e27666d3a9c3b74bp-1,
    0x1.6af2f0p2,
  },
  { // Entry 148
    0x1.263123df22d13ed329c665c83c0e71e8p-1,
    0x1.a30a6a3bf4a3e2b7e27666d3a9c3b74bp-1,
    -0x1.6af2f0p2,
  },
  { // Entry 149
    -0x1.e18e67b508ffc9e42f6c9e72f8e545f3p-1,
    0x1.5bd625504015ccc101e4f4340d4b762bp-2,
    0x1.43c62ap2,
  },
  { // Entry 150
    0x1.e18e67b508ffc9e42f6c9e72f8e545f3p-1,
    0x1.5bd625504015ccc101e4f4340d4b762bp-2,
    -0x1.43c62ap2,
  },
  { // Entry 151
    -0x1.ee0e80ec9d1562c17a6cf608af9b0ed4p-1,
    -0x1.0cb733448c30ee3ddffb4da69f0b3842p-2,
    0x1.1c9964p2,
  },
  { // Entry 152
    0x1.ee0e80ec9d1562c17a6cf608af9b0ed4p-1,
    -0x1.0cb733448c30ee3ddffb4da69f0b3842p-2,
    -0x1.1c9964p2,
  },
  { // Entry 153
    -0x1.472768637ea8866a652098a43aa688a6p-1,
    -0x1.89d874ad30e3fb46244daa24451690d7p-1,
    0x1.ead93cp1,
  },
  { // Entry 154
    0x1.472768637ea8866a652098a43aa688a6p-1,
    -0x1.89d874ad30e3fb46244daa24451690d7p-1,
    -0x1.ead93cp1,
  },
  { // Entry 155
    -0x1.4ba24f6325f21420e7c48d4f91e28064p-4,
    -0x1.fe51ae09f0d39ed554e68bef3e2f8a03p-1,
    0x1.9c7fb0p1,
  },
  { // Entry 156
    0x1.4ba24f6325f21420e7c48d4f91e28064p-4,
    -0x1.fe51ae09f0d39ed554e68bef3e2f8a03p-1,
    -0x1.9c7fb0p1,
  },
  { // Entry 157
    0x1.034c643295153aaffe5d9a0f29e92844p-1,
    -0x1.b97bf76ae765eb69cf55e80aae977303p-1,
    0x1.4e2624p1,
  },
  { // Entry 158
    -0x1.034c643295153aaffe5d9a0f29e92844p-1,
    -0x1.b97bf76ae765eb69cf55e80aae977303p-1,
    -0x1.4e2624p1,
  },
  { // Entry 159
    0x1.d1e4d96eac917574b948e4ea9e37b36dp-1,
    -0x1.a8ac5793e32629b131984ecffd2d0f31p-2,
    0x1.ff9932p0,
  },
  { // Entry 160
    -0x1.d1e4d96eac917574b948e4ea9e37b36dp-1,
    -0x1.a8ac5793e32629b131984ecffd2d0f31p-2,
    -0x1.ff9932p0,
  },
  { // Entry 161
    0x1.f7501e002bcafb897f931931d3a57afdp-1,
    0x1.77a92ca01bc79c195dda33736807f986p-3,
    0x1.62e61cp0,
  },
  { // Entry 162
    -0x1.f7501e002bcafb897f931931d3a57afdp-1,
    0x1.77a92ca01bc79c195dda33736807f986p-3,
    -0x1.62e61cp0,
  },
  { // Entry 163
    0x1.65f7d66ef6591cfc51ab29dc2086d3e7p-1,
    0x1.6e1060282c1488d9abd83da1d68cd0f7p-1,
    0x1.8c662cp-1,
  },
  { // Entry 164
    -0x1.65f7d66ef6591cfc51ab29dc2086d3e7p-1,
    0x1.6e1060282c1488d9abd83da1d68cd0f7p-1,
    -0x1.8c662cp-1,
  },
  { // Entry 165
    -0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    -0x1.a8aa1cp0,
  },
  { // Entry 166
    0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    0x1.a8aa1cp0,
  },
  { // Entry 167
    -0x1.fff18f313e66f1ae25f89a5f7a1f84c4p-1,
    -0x1.e665cb2af842be5ba5f65960599a97ecp-7,
    -0x1.95ec8ap0,
  },
  { // Entry 168
    0x1.fff18f313e66f1ae25f89a5f7a1f84c4p-1,
    -0x1.e665cb2af842be5ba5f65960599a97ecp-7,
    0x1.95ec8ap0,
  },
  { // Entry 169
    -0x1.ff20d920b9e9c23154f97e2f342a2884p-1,
    0x1.ddd231501b12fcf2bc20633be4d51e51p-5,
    -0x1.832ef8p0,
  },
  { // Entry 170
    0x1.ff20d920b9e9c23154f97e2f342a2884p-1,
    0x1.ddd231501b12fcf2bc20633be4d51e51p-5,
    0x1.832ef8p0,
  },
  { // Entry 171
    -0x1.fb933b89d7db3286eed0cfeabee98875p-1,
    0x1.0caba6997691ab1970d43c7419ed51e1p-3,
    -0x1.707166p0,
  },
  { // Entry 172
    0x1.fb933b89d7db3286eed0cfeabee98875p-1,
    0x1.0caba6997691ab1970d43c7419ed51e1p-3,
    0x1.707166p0,
  },
  { // Entry 173
    -0x1.f54d95c5058b7dc9972ab6f9928ca043p-1,
    0x1.a072541fd6eaf8b65a874c58d6cc5739p-3,
    -0x1.5db3d4p0,
  },
  { // Entry 174
    0x1.f54d95c5058b7dc9972ab6f9928ca043p-1,
    0x1.a072541fd6eaf8b65a874c58d6cc5739p-3,
    0x1.5db3d4p0,
  },
  { // Entry 175
    -0x1.ec5881a09c46aae020cd9036098a196ep-1,
    0x1.18fef8106bea63b9e96a7adf538c6194p-2,
    -0x1.4af642p0,
  },
  { // Entry 176
    0x1.ec5881a09c46aae020cd9036098a196ep-1,
    0x1.18fef8106bea63b9e96a7adf538c6194p-2,
    0x1.4af642p0,
  },
  { // Entry 177
    -0x1.e0c04795919d961a5e83e505df31c624p-1,
    0x1.60437277d48067e85230bce1883eaabap-2,
    -0x1.3838b0p0,
  },
  { // Entry 178
    0x1.e0c04795919d961a5e83e505df31c624p-1,
    0x1.60437277d48067e85230bce1883eaabap-2,
    0x1.3838b0p0,
  },
  { // Entry 179
    -0x1.d294cdef7cc161633a02d3e62058be0ep-1,
    0x1.a5a4ded492bedfe8cf5c34cadd78df75p-2,
    -0x1.257b1ep0,
  },
  { // Entry 180
    0x1.d294cdef7cc161633a02d3e62058be0ep-1,
    0x1.a5a4ded492bedfe8cf5c34cadd78df75p-2,
    0x1.257b1ep0,
  },
  { // Entry 181
    -0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    -0x1.12bd92p0,
  },
  { // Entry 182
    0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    0x1.12bd92p0,
  },
  { // Entry 183
    -0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    -0x1.ea5c3ep-1,
  },
  { // Entry 184
    0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    0x1.ea5c3ep-1,
  },
  { // Entry 185
    -0x1.95f05153644d60b94d2f2e700dfd3a37p-1,
    0x1.3805a2dafda7f8554aec65dab348a714p-1,
    -0x1.d4b87cp-1,
  },
  { // Entry 186
    0x1.95f05153644d60b94d2f2e700dfd3a37p-1,
    0x1.3805a2dafda7f8554aec65dab348a714p-1,
    0x1.d4b87cp-1,
  },
  { // Entry 187
    -0x1.88647d8ad2e41fb7c0af0f64614c9993p-1,
    0x1.48e52ff5bbe794618b85190b86411824p-1,
    -0x1.bf14bap-1,
  },
  { // Entry 188
    0x1.88647d8ad2e41fb7c0af0f64614c9993p-1,
    0x1.48e52ff5bbe794618b85190b86411824p-1,
    0x1.bf14bap-1,
  },
  { // Entry 189
    -0x1.7a253f9f89a7d3e4f9c54638418e97f6p-1,
    0x1.592e5b615ef5ae463976d31141dbacf0p-1,
    -0x1.a970f8p-1,
  },
  { // Entry 190
    0x1.7a253f9f89a7d3e4f9c54638418e97f6p-1,
    0x1.592e5b615ef5ae463976d31141dbacf0p-1,
    0x1.a970f8p-1,
  },
  { // Entry 191
    -0x1.6b391b34aab828fbe7cd7dcaf9ef3bd6p-1,
    0x1.68d9b2d657e4307d331eb7bd35ee1879p-1,
    -0x1.93cd36p-1,
  },
  { // Entry 192
    0x1.6b391b34aab828fbe7cd7dcaf9ef3bd6p-1,
    0x1.68d9b2d657e4307d331eb7bd35ee1879p-1,
    0x1.93cd36p-1,
  },
  { // Entry 193
    -0x1.5ba6e2fb980d482cf00ede80f5597fb2p-1,
    0x1.77e00c3718528c36f722e63096c2646bp-1,
    -0x1.7e2974p-1,
  },
  { // Entry 194
    0x1.5ba6e2fb980d482cf00ede80f5597fb2p-1,
    0x1.77e00c3718528c36f722e63096c2646bp-1,
    0x1.7e2974p-1,
  },
  { // Entry 195
    -0x1.4b75b5954e718020900719e25a7ea93bp-1,
    0x1.863a88d6b064f36f34370722d361ce9fp-1,
    -0x1.6885b2p-1,
  },
  { // Entry 196
    0x1.4b75b5954e718020900719e25a7ea93bp-1,
    0x1.863a88d6b064f36f34370722d361ce9fp-1,
    0x1.6885b2p-1,
  },
  { // Entry 197
    -0x1.3aacfa510810054c52ae0b67d116eb40p-1,
    0x1.93e2989cee6084e34b533b1eb92746dap-1,
    -0x1.52e1f0p-1,
  },
  { // Entry 198
    0x1.3aacfa510810054c52ae0b67d116eb40p-1,
    0x1.93e2989cee6084e34b533b1eb92746dap-1,
    0x1.52e1f0p-1,
  },
  { // Entry 199
    -0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    -0x1.3d3e36p-1,
  },
  { // Entry 200
    0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    0x1.3d3e36p-1,
  },
  { // Entry 201
    -0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    -0x1.0a0b02p-1,
  },
  { // Entry 202
    0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    0x1.0a0b02p-1,
  },
  { // Entry 203
    -0x1.c853c704e3b94322031d6b47aef853c9p-2,
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    -0x1.d8f720p-2,
  },
  { // Entry 204
    0x1.c853c704e3b94322031d6b47aef853c9p-2,
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    0x1.d8f720p-2,
  },
  { // Entry 205
    -0x1.92aba8981b25deda4cc1817251723a1bp-2,
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    -0x1.9dd83cp-2,
  },
  { // Entry 206
    0x1.92aba8981b25deda4cc1817251723a1bp-2,
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    0x1.9dd83cp-2,
  },
  { // Entry 207
    -0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    -0x1.62b958p-2,
  },
  { // Entry 208
    0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    0x1.62b958p-2,
  },
  { // Entry 209
    -0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    -0x1.279a74p-2,
  },
  { // Entry 210
    0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    0x1.279a74p-2,
  },
  { // Entry 211
    -0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    -0x1.d8f720p-3,
  },
  { // Entry 212
    0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    0x1.d8f720p-3,
  },
  { // Entry 213
    -0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    -0x1.62b958p-3,
  },
  { // Entry 214
    0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    0x1.62b958p-3,
  },
  { // Entry 215
    -0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    -0x1.d8f720p-4,
  },
  { // Entry 216
    0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    0x1.d8f720p-4,
  },
  { // Entry 217
    -0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    -0x1.d8f720p-5,
  },
  { // Entry 218
    0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    0x1.d8f720p-5,
  },
  { // Entry 219
    0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    0x1.d8f720p-5,
  },
  { // Entry 220
    -0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    0x1.ff259b7b3d721edf063a5bf6e7a1f93cp-1,
    -0x1.d8f720p-5,
  },
  { // Entry 221
    0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    0x1.d8f720p-4,
  },
  { // Entry 222
    -0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    -0x1.d8f720p-4,
  },
  { // Entry 223
    0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    0x1.62b958p-3,
  },
  { // Entry 224
    -0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    -0x1.62b958p-3,
  },
  { // Entry 225
    0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    0x1.d8f720p-3,
  },
  { // Entry 226
    -0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    -0x1.d8f720p-3,
  },
  { // Entry 227
    0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    0x1.279a74p-2,
  },
  { // Entry 228
    -0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    -0x1.279a74p-2,
  },
  { // Entry 229
    0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    0x1.62b958p-2,
  },
  { // Entry 230
    -0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    -0x1.62b958p-2,
  },
  { // Entry 231
    0x1.92aba8981b25deda4cc1817251723a1bp-2,
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    0x1.9dd83cp-2,
  },
  { // Entry 232
    -0x1.92aba8981b25deda4cc1817251723a1bp-2,
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    -0x1.9dd83cp-2,
  },
  { // Entry 233
    0x1.c853c704e3b94322031d6b47aef853c9p-2,
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    0x1.d8f720p-2,
  },
  { // Entry 234
    -0x1.c853c704e3b94322031d6b47aef853c9p-2,
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    -0x1.d8f720p-2,
  },
  { // Entry 235
    0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    0x1.0a0b02p-1,
  },
  { // Entry 236
    -0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    -0x1.0a0b02p-1,
  },
  { // Entry 237
    0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    0x1.3d3e36p-1,
  },
  { // Entry 238
    -0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    -0x1.3d3e36p-1,
  },
  { // Entry 239
    0x1.3aad00a09268a39df1653c70db91f157p-1,
    0x1.93e293b23a6aa1ae5373214eb8fb9e96p-1,
    0x1.52e1f8p-1,
  },
  { // Entry 240
    -0x1.3aad00a09268a39df1653c70db91f157p-1,
    0x1.93e293b23a6aa1ae5373214eb8fb9e96p-1,
    -0x1.52e1f8p-1,
  },
  { // Entry 241
    0x1.4b75bbae388a7f3466e7f2d6bdcf72bbp-1,
    0x1.863a83a8d9826c6135509406ebe05c0fp-1,
    0x1.6885bap-1,
  },
  { // Entry 242
    -0x1.4b75bbae388a7f3466e7f2d6bdcf72bbp-1,
    0x1.863a83a8d9826c6135509406ebe05c0fp-1,
    -0x1.6885bap-1,
  },
  { // Entry 243
    0x1.5ba6e8db1833475712b9a42a1ad0d2c2p-1,
    0x1.77e006c87cbaded66ec5b960c93c568ap-1,
    0x1.7e297cp-1,
  },
  { // Entry 244
    -0x1.5ba6e8db1833475712b9a42a1ad0d2c2p-1,
    0x1.77e006c87cbaded66ec5b960c93c568ap-1,
    -0x1.7e297cp-1,
  },
  { // Entry 245
    0x1.6b3920d8117828928fe10ac70ba69e76p-1,
    0x1.68d9ad29736c1704caea6a2db6e71
"""


```
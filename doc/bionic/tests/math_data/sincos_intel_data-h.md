Response:
The user wants to understand the functionality of the provided C code snippet. This file seems to contain test data for the `sincos` function in Android's bionic library.

Here's a breakdown of the thought process to answer the user's request for a summary of the code's functionality:

1. **Identify the Core Purpose:** The code starts with a copyright notice and mentions "sincos_intel_data". The variable name `g_sincos_intel_data` and the type `data_2_1_t<double, double, double>` strongly suggest this data is related to the sine and cosine functions for Intel architectures. The `<double, double, double>` likely represents (input, sin(input), cos(input)) or a similar triplet.

2. **Recognize the Context:** The path `bionic/tests/math_data/` clearly indicates that this is *test data*, not the actual implementation of `sincos`. This is crucial for answering the user's questions about implementation details later.

3. **Analyze the Data Structure:** The data is an array of structs (or a template instantiation behaving like a struct). Each element in the array seems to represent a test case.

4. **Interpret the Data Format:** The values inside the curly braces are in hexadecimal floating-point format (e.g., `-0x1.ce9a94ea9c2ad95597b1193b2300d19ap-1`). This format is commonly used in low-level math libraries for precise representation of floating-point numbers.

5. **Infer the Testing Strategy:** The presence of numerous test cases suggests a thorough testing approach. The data likely covers a range of input values, potentially including edge cases, positive and negative values, and values near zero or one. The "intel_data" part suggests architecture-specific testing or optimization.

6. **Formulate the Summary:** Combine the above observations into a concise summary. Emphasize that it's test data, its relation to `sincos`, and the data structure.

7. **Address Potential Misconceptions (and Preemptively Address Future Questions):**  Although the user only asked for a summary *for this part*, anticipate that they'll later ask about the *implementation* of `sincos`. It's good to preemptively clarify that this file *doesn't contain the implementation*. This saves time and clarifies the scope of the current code.
这段代码定义了一个名为 `g_sincos_intel_data` 的静态全局数组。这个数组存储了 `double` 类型的测试数据，用于测试 `sincos` 函数在特定输入下的输出结果。

更具体地说，这个数组的每个元素都是一个结构体（或者通过模板 `data_2_1_t` 定义的类似结构体的类型），包含三个 `double` 类型的值。根据命名和常见的测试模式，这三个值很可能分别代表：

1. **输入值 (Input):**  `sincos` 函数的输入角度（以弧度为单位的可能性较大）。
2. **预期正弦值 (Expected Sin):** 对于给定的输入值，预期的 `sin` 函数的返回值。
3. **预期余弦值 (Expected Cos):** 对于给定的输入值，预期的 `cos` 函数的返回值。

**因此，这段代码的功能可以归纳为：**

**存储了一系列用于测试 `sincos` 函数（可能针对 Intel 架构优化）的输入、预期正弦值和预期余弦值的双精度浮点数数据。**

**它不是 `sincos` 函数的实现代码，而是用于验证 `sincos` 函数实现是否正确的测试数据。**

在后续的部分中，很可能会有代码使用这个数组，遍历其中的每个条目，将第一个值作为 `sincos` 函数的输入，然后将函数的实际输出与数组中存储的第二和第三个值进行比较，以判断 `sincos` 函数的实现是否正确。

### 提示词
```
这是目录为bionic/tests/math_data/sincos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共4部分，请归纳一下它的功能
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

static data_2_1_t<double, double, double> g_sincos_intel_data[] = {
  { // Entry 0
    -0x1.ce9a94ea9c2ad95597b1193b2300d19ap-1,
    -0x1.b6d3057776dc38335b16745f2d756ab6p-2,
    -0x1.01c000003p1,
  },
  { // Entry 1
    0x1.ce9a94ea9c2ad95597b1193b2300d19ap-1,
    -0x1.b6d3057776dc38335b16745f2d756ab6p-2,
    0x1.01c000003p1,
  },
  { // Entry 2
    -0x1.ce2cad2f92157153b4a9e012e3461d0ap-1,
    -0x1.b8a14c745bd4c832bae9785655c91b60p-2,
    -0x1.01fffc080p1,
  },
  { // Entry 3
    0x1.ce2cad2f92157153b4a9e012e3461d0ap-1,
    -0x1.b8a14c745bd4c832bae9785655c91b60p-2,
    0x1.01fffc080p1,
  },
  { // Entry 4
    -0x1.1a7444726f5e9dc2ee069dc3e500ab4fp-2,
    0x1.ec231802917bdffa627ab6a59abe3f7dp-1,
    -0x1.1e2a1563e068ep-2,
  },
  { // Entry 5
    0x1.1a7444726f5e9dc2ee069dc3e500ab4fp-2,
    0x1.ec231802917bdffa627ab6a59abe3f7dp-1,
    0x1.1e2a1563e068ep-2,
  },
  { // Entry 6
    -0x1.efdab5e65c8fd550d4688b62791fe694p-1,
    0x1.fe4123d266ca37faeee822138eb331d3p-3,
    -0x1.83ef2196f92f0p87,
  },
  { // Entry 7
    0x1.efdab5e65c8fd550d4688b62791fe694p-1,
    0x1.fe4123d266ca37faeee822138eb331d3p-3,
    0x1.83ef2196f92f0p87,
  },
  { // Entry 8
    -0x1.eff5edb1ad416cb6ca3109f1c0dfc34ap-1,
    0x1.fc9935a7481717fa8aeca7a9c5833084p-3,
    -0x1.a486d79764fb8p86,
  },
  { // Entry 9
    0x1.eff5edb1ad416cb6ca3109f1c0dfc34ap-1,
    0x1.fc9935a7481717fa8aeca7a9c5833084p-3,
    0x1.a486d79764fb8p86,
  },
  { // Entry 10
    -0x1.b78f2c97c88028396ec94ba9ea58dd68p-2,
    0x1.ce6dea6788fde425f68fe33b0ffcc244p-1,
    -0x1.c65173556ccfbp-2,
  },
  { // Entry 11
    0x1.b78f2c97c88028396ec94ba9ea58dd68p-2,
    0x1.ce6dea6788fde425f68fe33b0ffcc244p-1,
    0x1.c65173556ccfbp-2,
  },
  { // Entry 12
    -0x1.c7885aef33a94ffc5ae06be9444efad5p-3,
    0x1.f32c8792006349b33b09fe57f80d9ed1p-1,
    -0x1.cb6p-3,
  },
  { // Entry 13
    0x1.c7885aef33a94ffc5ae06be9444efad5p-3,
    0x1.f32c8792006349b33b09fe57f80d9ed1p-1,
    0x1.cb6p-3,
  },
  { // Entry 14
    -0x1.f74a97abb47bc823e92eb9d66f1d8b54p-3,
    0x1.f04c859e062b9202aa2b9bf0486b5afdp-1,
    -0x1.fc7fffffffffep-3,
  },
  { // Entry 15
    0x1.f74a97abb47bc823e92eb9d66f1d8b54p-3,
    0x1.f04c859e062b9202aa2b9bf0486b5afdp-1,
    0x1.fc7fffffffffep-3,
  },
  { // Entry 16
    0x1.0000000000002fffd555555555553d55p-32,
    0x1.fffffffffffffffeffffffffffffa0p-1,
    0x1.0000000000003p-32,
  },
  { // Entry 17
    -0x1.0000000000002fffd555555555553d55p-32,
    0x1.fffffffffffffffeffffffffffffa0p-1,
    -0x1.0000000000003p-32,
  },
  { // Entry 18
    0x1.d18f6ead199a3b95430d5516e93c8d7bp-1,
    -0x1.aa2265753e6687fde76269ee92a784b0p-2,
    0x1.00000000010p1,
  },
  { // Entry 19
    -0x1.d18f6ead199a3b95430d5516e93c8d7bp-1,
    -0x1.aa2265753e6687fde76269ee92a784b0p-2,
    -0x1.00000000010p1,
  },
  { // Entry 20
    0x1.b64d59dd8a5249e01113f4cb37d13c40p-1,
    -0x1.08a445ad4737e80060cf3a5ff94d3067p-1,
    0x1.001p557,
  },
  { // Entry 21
    -0x1.b64d59dd8a5249e01113f4cb37d13c40p-1,
    -0x1.08a445ad4737e80060cf3a5ff94d3067p-1,
    -0x1.001p557,
  },
  { // Entry 22
    0x1.ce77f24fd4d9a790125ff5290a62b7f1p-1,
    -0x1.b764f40c9716b834bb72589348cfa4b8p-2,
    0x1.01d4313757482p1,
  },
  { // Entry 23
    -0x1.ce77f24fd4d9a790125ff5290a62b7f1p-1,
    -0x1.b764f40c9716b834bb72589348cfa4b8p-2,
    -0x1.01d4313757482p1,
  },
  { // Entry 24
    0x1.ce39b7df7f4acb81e37c532638f9bf49p-1,
    -0x1.b86a908f05c0a839e19d4aa63156d32bp-2,
    0x1.01f867d44bc82p1,
  },
  { // Entry 25
    -0x1.ce39b7df7f4acb81e37c532638f9bf49p-1,
    -0x1.b86a908f05c0a839e19d4aa63156d32bp-2,
    -0x1.01f867d44bc82p1,
  },
  { // Entry 26
    0x1.ce70046acb80de75e903468cea8ab427p-1,
    -0x1.b78654766c76483ce90a0bc2ac957b59p-2,
    0x1.09860e8ed1e90p3,
  },
  { // Entry 27
    -0x1.ce70046acb80de75e903468cea8ab427p-1,
    -0x1.b78654766c76483ce90a0bc2ac957b59p-2,
    -0x1.09860e8ed1e90p3,
  },
  { // Entry 28
    0x1.ce68564e251f16285d604e04657f30e6p-1,
    -0x1.b7a6a56f5796683c58e01b5b7061c16cp-2,
    0x1.09872cce51fbdp3,
  },
  { // Entry 29
    -0x1.ce68564e251f16285d604e04657f30e6p-1,
    -0x1.b7a6a56f5796683c58e01b5b7061c16cp-2,
    -0x1.09872cce51fbdp3,
  },
  { // Entry 30
    -0x1.ce8ab32f3b002065f2d99e57a1072705p-1,
    -0x1.b715f769cf1e582e23a15e8b80a70486p-2,
    0x1.113b13b13b224p2,
  },
  { // Entry 31
    0x1.ce8ab32f3b002065f2d99e57a1072705p-1,
    -0x1.b715f769cf1e582e23a15e8b80a70486p-2,
    -0x1.113b13b13b224p2,
  },
  { // Entry 32
    0x1.c2df57188d3099e1baf7f721d7318bd9p-1,
    0x1.e536ae395dfce001457970c8aaac3b1fp-2,
    0x1.13cp0,
  },
  { // Entry 33
    -0x1.c2df57188d3099e1baf7f721d7318bd9p-1,
    0x1.e536ae395dfce001457970c8aaac3b1fp-2,
    -0x1.13cp0,
  },
  { // Entry 34
    0x1.b7dcd7c85c820838eecfa53e52078b2bp-2,
    -0x1.ce5b7372046eaa467f49e1debe3662dfp-1,
    0x1.1f628c5610717p3,
  },
  { // Entry 35
    -0x1.b7dcd7c85c820838eecfa53e52078b2bp-2,
    -0x1.ce5b7372046eaa467f49e1debe3662dfp-1,
    -0x1.1f628c5610717p3,
  },
  { // Entry 36
    0x1.ff3466b1ec8bed978f7c27018bc09678p-1,
    0x1.c86caa04929857c2816d30693fceab36p-5,
    0x1.1f699d708d497p16,
  },
  { // Entry 37
    -0x1.ff3466b1ec8bed978f7c27018bc09678p-1,
    0x1.c86caa04929857c2816d30693fceab36p-5,
    -0x1.1f699d708d497p16,
  },
  { // Entry 38
    0x1.b61d6aff754c2835697b5aa5339b635cp-2,
    -0x1.cec59b2d230a83a86804730afdf1becfp-1,
    0x1.1f72064620ef4p3,
  },
  { // Entry 39
    -0x1.b61d6aff754c2835697b5aa5339b635cp-2,
    -0x1.cec59b2d230a83a86804730afdf1becfp-1,
    -0x1.1f72064620ef4p3,
  },
  { // Entry 40
    0x1.cdf604838e499bd5d9d2712397b23c07p-1,
    0x1.b98656b85bc2683216a947335ea689fbp-2,
    0x1.1fffffdcefe40p0,
  },
  { // Entry 41
    -0x1.cdf604838e499bd5d9d2712397b23c07p-1,
    0x1.b98656b85bc2683216a947335ea689fbp-2,
    -0x1.1fffffdcefe40p0,
  },
  { // Entry 42
    0x1.ce913329696cd3fa471c7b00891075d4p-1,
    0x1.b6fa92e5f576c834fc15d8998fccc728p-2,
    0x1.20b478c4aa9edp0,
  },
  { // Entry 43
    -0x1.ce913329696cd3fa471c7b00891075d4p-1,
    0x1.b6fa92e5f576c834fc15d8998fccc728p-2,
    -0x1.20b478c4aa9edp0,
  },
  { // Entry 44
    0x1.ceabc025ed3d57323fca51626d2bf28cp-1,
    0x1.b68a988604a7e83cd382fdf329d0d76ep-2,
    0x1.20d37456e7453p0,
  },
  { // Entry 45
    -0x1.ceabc025ed3d57323fca51626d2bf28cp-1,
    0x1.b68a988604a7e83cd382fdf329d0d76ep-2,
    -0x1.20d37456e7453p0,
  },
  { // Entry 46
    0x1.ceb022b6b5ae07a267f0e7dc6a14a214p-1,
    0x1.b67816b80ed0a82d11aee7aaa8008fedp-2,
    0x1.20d8930cdf602p0,
  },
  { // Entry 47
    -0x1.ceb022b6b5ae07a267f0e7dc6a14a214p-1,
    0x1.b67816b80ed0a82d11aee7aaa8008fedp-2,
    -0x1.20d8930cdf602p0,
  },
  { // Entry 48
    -0x1.9e62aca53c660801b62604018a9d19ddp-4,
    -0x1.fd5f830f860f333de490a42c2f045012p-1,
    0x1.30d5f8e54b6d8p3,
  },
  { // Entry 49
    0x1.9e62aca53c660801b62604018a9d19ddp-4,
    -0x1.fd5f830f860f333de490a42c2f045012p-1,
    -0x1.30d5f8e54b6d8p3,
  },
  { // Entry 50
    0x1.3ed2aeefeafc97f0ee0fb3fa4fb46052p-3,
    0x1.f9c201e4eb65fd5e5dbd97662505ff6fp-1,
    0x1.402p-3,
  },
  { // Entry 51
    -0x1.3ed2aeefeafc97f0ee0fb3fa4fb46052p-3,
    0x1.f9c201e4eb65fd5e5dbd97662505ff6fp-1,
    -0x1.402p-3,
  },
  { // Entry 52
    -0x1.ff65d2ff4a8cc41cb8bb6df306e07be7p-1,
    -0x1.8d3822ef260a57b385611f08577b75d9p-5,
    0x1.4a40ec149a66fp16,
  },
  { // Entry 53
    0x1.ff65d2ff4a8cc41cb8bb6df306e07be7p-1,
    -0x1.8d3822ef260a57b385611f08577b75d9p-5,
    -0x1.4a40ec149a66fp16,
  },
  { // Entry 54
    0x1.4fffffffff9f88000000084f22ccccccp-20,
    0x1.fffffffffe47000000003f4ebffffffcp-1,
    0x1.5p-20,
  },
  { // Entry 55
    -0x1.4fffffffff9f88000000084f22ccccccp-20,
    0x1.fffffffffe47000000003f4ebffffffcp-1,
    -0x1.5p-20,
  },
  { // Entry 56
    0x1.79c599e1e91af809f9e69771796cd507p-1,
    -0x1.5997065cb9653702d4c9d9b6bc58f768p-1,
    0x1.5294a5294a528p4,
  },
  { // Entry 57
    -0x1.79c599e1e91af809f9e69771796cd507p-1,
    -0x1.5997065cb9653702d4c9d9b6bc58f768p-1,
    -0x1.5294a5294a528p4,
  },
  { // Entry 58
    -0x1.ff7996073bba6c6ede46f52d445623c9p-1,
    0x1.72e7437910cc083fac4f6f62a2eb38afp-5,
    0x1.57431aacf5c58p16,
  },
  { // Entry 59
    0x1.ff7996073bba6c6ede46f52d445623c9p-1,
    0x1.72e7437910cc083fac4f6f62a2eb38afp-5,
    -0x1.57431aacf5c58p16,
  },
  { // Entry 60
    0x1.f81c4f9a5181462ae735e21222d498c4p-1,
    0x1.6623d2eb6add1ffc398a3c20447f9d06p-3,
    0x1.652p0,
  },
  { // Entry 61
    -0x1.f81c4f9a5181462ae735e21222d498c4p-1,
    0x1.6623d2eb6add1ffc398a3c20447f9d06p-3,
    -0x1.652p0,
  },
  { // Entry 62
    -0x1.c42a091026f45286d061085c5c9fddb7p-1,
    0x1.e0619960a11c6801e80ab0c9e25f89d0p-2,
    0x1.6f7bdef7bdef4p3,
  },
  { // Entry 63
    0x1.c42a091026f45286d061085c5c9fddb7p-1,
    0x1.e0619960a11c6801e80ab0c9e25f89d0p-2,
    -0x1.6f7bdef7bdef4p3,
  },
  { // Entry 64
    -0x1.f9c4364ba198f7e32b672366c34b8b7dp-2,
    0x1.bd309f3dfcd489128e5ecbc31680c4a5p-1,
    0x1.711p2,
  },
  { // Entry 65
    0x1.f9c4364ba198f7e32b672366c34b8b7dp-2,
    0x1.bd309f3dfcd489128e5ecbc31680c4a5p-1,
    -0x1.711p2,
  },
  { // Entry 66
    -0x1.be6e5bea1a4d88331fd8e460cd677245p-2,
    0x1.ccc7d99b57ab54f04ed918ec14a2507dp-1,
    0x1.7540aa5882dc2p2,
  },
  { // Entry 67
    0x1.be6e5bea1a4d88331fd8e460cd677245p-2,
    0x1.ccc7d99b57ab54f04ed918ec14a2507dp-1,
    -0x1.7540aa5882dc2p2,
  },
  { // Entry 68
    0x1.c90c841d1494c0757e8ebb16725d8718p-3,
    -0x1.f3165a0b306b1ffcf8d11909fffba167p-1,
    0x1.7550d28ffccc4p1,
  },
  { // Entry 69
    -0x1.c90c841d1494c0757e8ebb16725d8718p-3,
    -0x1.f3165a0b306b1ffcf8d11909fffba167p-1,
    -0x1.7550d28ffccc4p1,
  },
  { // Entry 70
    -0x1.b649d577e1b2a839d25d19807eb2c564p-2,
    0x1.cebb175d36b934bc0995a0be35cde1eep-1,
    0x1.75d11fa0d6242p2,
  },
  { // Entry 71
    0x1.b649d577e1b2a839d25d19807eb2c564p-2,
    0x1.cebb175d36b934bc0995a0be35cde1eep-1,
    -0x1.75d11fa0d6242p2,
  },
  { // Entry 72
    0x1.b78730d11d8408320d21ca6ad2be3368p-2,
    -0x1.ce6fd00ed16501cb13b908477e102811p-1,
    0x1.bc50444ee6286p9,
  },
  { // Entry 73
    -0x1.b78730d11d8408320d21ca6ad2be3368p-2,
    -0x1.ce6fd00ed16501cb13b908477e102811p-1,
    -0x1.bc50444ee6286p9,
  },
  { // Entry 74
    0x1.b6b0b0996e7e6835acdb36e55a08bf15p-2,
    0x1.cea2b8cc552181d0b0aead27e94a9168p-1,
    0x1.c55b2bf19ce54p-2,
  },
  { // Entry 75
    -0x1.b6b0b0996e7e6835acdb36e55a08bf15p-2,
    0x1.cea2b8cc552181d0b0aead27e94a9168p-1,
    -0x1.c55b2bf19ce54p-2,
  },
  { // Entry 76
    0x1.b6facf665891482ea8c61f5ca32f280dp-2,
    0x1.ce9124cec4150559d947a526ad98f2f4p-1,
    0x1.c5ad34f5f472ap-2,
  },
  { // Entry 77
    -0x1.b6facf665891482ea8c61f5ca32f280dp-2,
    0x1.ce9124cec4150559d947a526ad98f2f4p-1,
    -0x1.c5ad34f5f472ap-2,
  },
  { // Entry 78
    -0x1.f83a0983dd15d00301e2df21e3bee635p-2,
    -0x1.bda0596df060004d579563ad8c67d151p-1,
    0x1.d4067c60f471ep1,
  },
  { // Entry 79
    0x1.f83a0983dd15d00301e2df21e3bee635p-2,
    -0x1.bda0596df060004d579563ad8c67d151p-1,
    -0x1.d4067c60f471ep1,
  },
  { // Entry 80
    0x1.9cb6a9bbce64a3e97a7267fdec25c83bp-1,
    0x1.2f011326420e5002172db245fd9063e2p-1,
    0x1.dffffffffffffp-1,
  },
  { // Entry 81
    -0x1.9cb6a9bbce64a3e97a7267fdec25c83bp-1,
    0x1.2f011326420e5002172db245fd9063e2p-1,
    -0x1.dffffffffffffp-1,
  },
  { // Entry 82
    0x1.f5f0be28565c5ad763c103d981fc5c4ep-5,
    0x1.ff09babb076e4803e57e68204570fd5bp-1,
    0x1.f64147d8add84p-5,
  },
  { // Entry 83
    -0x1.f5f0be28565c5ad763c103d981fc5c4ep-5,
    0x1.ff09babb076e4803e57e68204570fd5bp-1,
    -0x1.f64147d8add84p-5,
  },
  { // Entry 84
    -0x1.d4da5f56888e200fda4ebac7db1cdbefp-1,
    0x1.9b70cd3284e157fb84491d581cb86bd3p-2,
    0x1.fe6183efa397cp83,
  },
  { // Entry 85
    0x1.d4da5f56888e200fda4ebac7db1cdbefp-1,
    0x1.9b70cd3284e157fb84491d581cb86bd3p-2,
    -0x1.fe6183efa397cp83,
  },
  { // Entry 86
    0x1.fa9f6ca0ec44e0010026f385c0ab8690p-3,
    0x1.f016474b75667424a050d79014fd2385p-1,
    0x1.ffeffffffffffp-3,
  },
  { // Entry 87
    -0x1.fa9f6ca0ec44e0010026f385c0ab8690p-3,
    0x1.f016474b75667424a050d79014fd2385p-1,
    -0x1.ffeffffffffffp-3,
  },
  { // Entry 88
    -0x1.ff4868ddaba6ba32c6b714aef99ff2f7p-1,
    -0x1.b16f0eb25ae467c2a185e516f1188b20p-5,
    0x1.fff7ff800001fp15,
  },
  { // Entry 89
    0x1.ff4868ddaba6ba32c6b714aef99ff2f7p-1,
    -0x1.b16f0eb25ae467c2a185e516f1188b20p-5,
    -0x1.fff7ff800001fp15,
  },
  { // Entry 90
    -0x1.ff4f1e9c248912648701818d075b3953p-1,
    -0x1.a971e3b64d08d7c3f37d299b43616eb4p-5,
    0x1.fff7ffffffcp15,
  },
  { // Entry 91
    0x1.ff4f1e9c248912648701818d075b3953p-1,
    -0x1.a971e3b64d08d7c3f37d299b43616eb4p-5,
    -0x1.fff7ffffffcp15,
  },
  { // Entry 92
    0x1.d19616fc7ee4605345c25606cfc93235p-1,
    -0x1.aa054c4909384811a063273112604c31p-2,
    0x1.fff80p0,
  },
  { // Entry 93
    -0x1.d19616fc7ee4605345c25606cfc93235p-1,
    -0x1.aa054c4909384811a063273112604c31p-2,
    -0x1.fff80p0,
  },
  { // Entry 94
    0x1.ce3509751c4614837fa4b34963c6f5d8p-1,
    0x1.b87e37101654482144d71d04972267d8p-2,
    0x1.ffffbffe3ffffp14,
  },
  { // Entry 95
    -0x1.ce3509751c4614837fa4b34963c6f5d8p-1,
    0x1.b87e37101654482144d71d04972267d8p-2,
    -0x1.ffffbffe3ffffp14,
  },
  { // Entry 96
    0x1.d18f76ffc6e4ba0a3134e5be21b5bc8fp-1,
    -0x1.aa2241160227896c68ef17839f17dce5p-2,
    0x1.fffff60p0,
  },
  { // Entry 97
    -0x1.d18f76ffc6e4ba0a3134e5be21b5bc8fp-1,
    -0x1.aa2241160227896c68ef17839f17dce5p-2,
    -0x1.fffff60p0,
  },
  { // Entry 98
    -0x1.837b994a6d8ff7f2750755df5843e84dp-1,
    -0x1.4eaa65b9e2ecc308fd82f65e09d06be4p-1,
    0x1.fffffe3ffffffp1,
  },
  { // Entry 99
    0x1.837b994a6d8ff7f2750755df5843e84dp-1,
    -0x1.4eaa65b9e2ecc308fd82f65e09d06be4p-1,
    -0x1.fffffe3ffffffp1,
  },
  { // Entry 100
    0x1.aed548f090c1dffe6e04322dc8e8cbfap-1,
    0x1.14a280fb507cf8999a1b291995646152p-1,
    0x1.ffffffffffe7fp-1,
  },
  { // Entry 101
    -0x1.aed548f090c1dffe6e04322dc8e8cbfap-1,
    0x1.14a280fb507cf8999a1b291995646152p-1,
    -0x1.ffffffffffe7fp-1,
  },
  { // Entry 102
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 103
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 104
    -0.0,
    0x1.p0,
    -0.0,
  },
  { // Entry 105
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 106
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 107
    -0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022,
  },
  { // Entry 108
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p-1022,
  },
  { // Entry 109
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022,
  },
  { // Entry 110
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1022,
  },
  { // Entry 111
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023,
  },
  { // Entry 112
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep-1023,
  },
  { // Entry 113
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep-1023,
  },
  { // Entry 114
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023,
  },
  { // Entry 115
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1022,
  },
  { // Entry 116
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022,
  },
  { // Entry 117
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p-1022,
  },
  { // Entry 118
    -0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022,
  },
  { // Entry 119
    0x1.9999996de8ca198c24ab9449beee16d5p-13,
    0x1.ffffff5c28f5cb4c5272061281211120p-1,
    0x1.999999999999ap-13,
  },
  { // Entry 120
    -0x1.9999996de8ca198c24ab9449beee16d5p-13,
    0x1.ffffff5c28f5cb4c5272061281211120p-1,
    -0x1.999999999999ap-13,
  },
  { // Entry 121
    0x1.999998ead65b96f78a4dbfd839c7ef2ep-12,
    0x1.fffffd70a3d7960cd5695a06fdb80e74p-1,
    0x1.999999999999ap-12,
  },
  { // Entry 122
    -0x1.999998ead65b96f78a4dbfd839c7ef2ep-12,
    0x1.fffffd70a3d7960cd5695a06fdb80e74p-1,
    -0x1.999999999999ap-12,
  },
  { // Entry 123
    0x1.3333320c49babff151b6d04290e2c3a2p-11,
    0x1.fffffa3d70a69ad42b39d8696632f856p-1,
    0x1.3333333333334p-11,
  },
  { // Entry 124
    -0x1.3333320c49babff151b6d04290e2c3a2p-11,
    0x1.fffffa3d70a69ad42b39d8696632f856p-1,
    -0x1.3333333333334p-11,
  },
  { // Entry 125
    0x1.999996de8ca2884da2f08f25bb024d08p-11,
    0x1.fffff5c28f64e5ec0da0a4f7f4388052p-1,
    0x1.999999999999ap-11,
  },
  { // Entry 126
    -0x1.999996de8ca2884da2f08f25bb024d08p-11,
    0x1.fffff5c28f64e5ec0da0a4f7f4388052p-1,
    -0x1.999999999999ap-11,
  },
  { // Entry 127
    0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    0x1.0p-10,
  },
  { // Entry 128
    -0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    -0x1.0p-10,
  },
  { // Entry 129
    0x1.33332e978d552afc883bdb04751e3835p-10,
    0x1.ffffe8f5c2bb98c7c103d2ff79f15d6ap-1,
    0x1.3333333333333p-10,
  },
  { // Entry 130
    -0x1.33332e978d552afc883bdb04751e3835p-10,
    0x1.ffffe8f5c2bb98c7c103d2ff79f15d6ap-1,
    -0x1.3333333333333p-10,
  },
  { // Entry 131
    0x1.66665f1529aff8a3809246670a436c3cp-10,
    0x1.ffffe0a3d75c31b26451166d6f398abdp-1,
    0x1.6666666666666p-10,
  },
  { // Entry 132
    -0x1.66665f1529aff8a3809246670a436c3cp-10,
    0x1.ffffe0a3d75c31b26451166d6f398abdp-1,
    -0x1.6666666666666p-10,
  },
  { // Entry 133
    0x1.99998ead65cdf82e194c133997f2fb68p-10,
    0x1.ffffd70a3dfc733b3331d8382b1e9df5p-1,
    0x1.9999999999999p-10,
  },
  { // Entry 134
    -0x1.99998ead65cdf82e194c133997f2fb68p-10,
    0x1.ffffd70a3dfc733b3331d8382b1e9df5p-1,
    -0x1.9999999999999p-10,
  },
  { // Entry 135
    0x1.ccccbd3f7d15d42affb9f02bf1dc257bp-10,
    0x1.ffffcc28f6a2823f3765b50659ecb0e2p-1,
    0x1.cccccccccccccp-10,
  },
  { // Entry 136
    -0x1.ccccbd3f7d15d42affb9f02bf1dc257bp-10,
    0x1.ffffcc28f6a2823f3765b50659ecb0e2p-1,
    -0x1.cccccccccccccp-10,
  },
  { // Entry 137
    0x1.0665ae9c7b44ed280216be2104f28f02p-7,
    0x1.fffbcc2a6e86fef7d2af1580bd8e6699p-1,
    0x1.0666666666666p-7,
  },
  { // Entry 138
    -0x1.0665ae9c7b44ed280216be2104f28f02p-7,
    0x1.fffbcc2a6e86fef7d2af1580bd8e6699p-1,
    -0x1.0666666666666p-7,
  },
  { // Entry 139
    0x1.ccc8e97b59f618898c4ac3a0aeddf709p-7,
    0x1.fff30a4b6fcc1405e18fbf7335d2f789p-1,
    0x1.cccccccccccccp-7,
  },
  { // Entry 140
    -0x1.ccc8e97b59f618898c4ac3a0aeddf709p-7,
    0x1.fff30a4b6fcc1405e18fbf7335d2f789p-1,
    -0x1.cccccccccccccp-7,
  },
  { // Entry 141
    0x1.4993e8a8ff79b132046efa7856a97538p-6,
    0x1.ffe57a780f38c0db37051fa8c8d60fbcp-1,
    0x1.4999999999999p-6,
  },
  { // Entry 142
    -0x1.4993e8a8ff79b132046efa7856a97538p-6,
    0x1.ffe57a780f38c0db37051fa8c8d60fbcp-1,
    -0x1.4999999999999p-6,
  },
  { // Entry 143
    0x1.acc044c56db0e19f82c9c3cff246e201p-6,
    0x1.ffd31cd0e1d62c05d2cded21add8bd33p-1,
    0x1.accccccccccccp-6,
  },
  { // Entry 144
    -0x1.acc044c56db0e19f82c9c3cff246e201p-6,
    0x1.ffd31cd0e1d62c05d2cded21add8bd33p-1,
    -0x1.accccccccccccp-6,
  },
  { // Entry 145
    0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    0x1.080p-5,
  },
  { // Entry 146
    -0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    -0x1.080p-5,
  },
  { // Entry 147
    0x1.3985fe46f1c8714eaa1418561963e89bp-5,
    0x1.ff9ff8c3299f54457bbaf8c12173b46bp-1,
    0x1.399999999999ap-5,
  },
  { // Entry 148
    -0x1.3985fe46f1c8714eaa1418561963e89bp-5,
    0x1.ff9ff8c3299f54457bbaf8c12173b46bp-1,
    -0x1.399999999999ap-5,
  },
  { // Entry 149
    0x1.6b14bde93ac5f7d24544d0ecf8be7aeep-5,
    0x1.ff7f32d77c5b1c42f1660c9b6f2ef64fp-1,
    0x1.6b33333333334p-5,
  },
  { // Entry 150
    -0x1.6b14bde93ac5f7d24544d0ecf8be7aeep-5,
    0x1.ff7f32d77c5b1c42f1660c9b6f2ef64fp-1,
    -0x1.6b33333333334p-5,
  },
  { // Entry 151
    0x1.9ca0153ed8396b02f8605219a5fe5917p-5,
    0x1.ff59a00dbc40896bb5e4ac8ad293afb4p-1,
    0x1.9cccccccccccep-5,
  },
  { // Entry 152
    -0x1.9ca0153ed8396b02f8605219a5fe5917p-5,
    0x1.ff59a00dbc40896bb5e4ac8ad293afb4p-1,
    -0x1.9cccccccccccep-5,
  },
  { // Entry 153
    0x1.ce278d4027d34387f184d4ab2aaf545fp-5,
    0x1.ff2f40c02e60f61d6dcfc39b6c2be087p-1,
    0x1.ce66666666666p-5,
  },
  { // Entry 154
    -0x1.ce278d4027d34387f184d4ab2aaf545fp-5,
    0x1.ff2f40c02e60f61d6dcfc39b6c2be087p-1,
    -0x1.ce66666666666p-5,
  },
  { // Entry 155
    0x1.43c1e9c171a667a0b92519a04fa5a91cp-1,
    0x1.8ca46c7d8975e57a1484f05c3738d83bp-1,
    0x1.5e7fc4369bdadp-1,
  },
  { // Entry 156
    -0x1.43c1e9c171a667a0b92519a04fa5a91cp-1,
    0x1.8ca46c7d8975e57a1484f05c3738d83bp-1,
    -0x1.5e7fc4369bdadp-1,
  },
  { // Entry 157
    0x1.ee3d6bcea09ca18b1d1ce7ee04fd886fp-1,
    0x1.0b5d3802fc7991140168f294eedd7904p-2,
    0x1.4e7fc4369bdadp0,
  },
  { // Entry 158
    -0x1.ee3d6bcea09ca18b1d1ce7ee04fd886fp-1,
    0x1.0b5d3802fc7991140168f294eedd7904p-2,
    -0x1.4e7fc4369bdadp0,
  },
  { // Entry 159
    0x1.df8e22ea809d65c6a69b96aca60be432p-1,
    -0x1.66b96f53323af1d7e31a7162ab18a75bp-2,
    0x1.edbfa651e9c84p0,
  },
  { // Entry 160
    -0x1.df8e22ea809d65c6a69b96aca60be432p-1,
    -0x1.66b96f53323af1d7e31a7162ab18a75bp-2,
    -0x1.edbfa651e9c84p0,
  },
  { // Entry 161
    0x1.1d3479eac7ae35e2fbea0ae696434692p-1,
    -0x1.a93554888c32fa57f22a9529a320c1cbp-1,
    0x1.467fc4369bdadp1,
  },
  { // Entry 162
    -0x1.1d3479eac7ae35e2fbea0ae696434692p-1,
    -0x1.a93554888c32fa57f22a9529a320c1cbp-1,
    -0x1.467fc4369bdadp1,
  },
  { // Entry 163
    -0x1.ffeaaaeeee84b44ccefef832254d28c0p-6,
    -0x1.ffc00155527d2b9fda2ae89396e09727p-1,
    0x1.961fb54442d18p1,
  },
  { // Entry 164
    0x1.ffeaaaeeee84b44ccefef832254d28c0p-6,
    -0x1.ffc00155527d2b9fda2ae89396e09727p-1,
    -0x1.961fb54442d18p1,
  },
  { // Entry 165
    -0x1.3734d32d49bd0b942772a7567d514140p-1,
    -0x1.96907c5c7c25b88e34addff1fbef66e4p-1,
    0x1.e5bfa651e9c83p1,
  },
  { // Entry 166
    0x1.3734d32d49bd0b942772a7567d514140p-1,
    -0x1.96907c5c7c25b88e34addff1fbef66e4p-1,
    -0x1.e5bfa651e9c83p1,
  },
  { // Entry 167
    -0x1.e9d25d19911e205b653521f42b9b864fp-1,
    -0x1.2a1e5a50f948cd487c5309682b110a53p-2,
    0x1.1aafcbafc85f7p2,
  },
  { // Entry 168
    0x1.e9d25d19911e205b653521f42b9b864fp-1,
    -0x1.2a1e5a50f948cd487c5309682b110a53p-2,
    -0x1.1aafcbafc85f7p2,
  },
  { // Entry 169
    -0x1.e4ecdc5a4e465899928eb9fc95829d48p-1,
    0x1.4894f695dc56bce8b273e5524f181264p-2,
    0x1.427fc4369bdadp2,
  },
  { // Entry 170
    0x1.e4ecdc5a4e465899928eb9fc95829d48p-1,
    0x1.4894f695dc56bce8b273e5524f181264p-2,
    -0x1.427fc4369bdadp2,
  },
  { // Entry 171
    -0x1.2a59f1034426197fa6eee22762967f25p-1,
    0x1.a016ea3a692ce0c321b77f168de39122p-1,
    0x1.6a4fbcbd6f562p2,
  },
  { // Entry 172
    0x1.2a59f1034426197fa6eee22762967f25p-1,
    0x1.a016ea3a692ce0c321b77f168de39122p-1,
    -0x1.6a4fbcbd6f562p2,
  },
  { // Entry 173
    -0x1.26312443bd35f19312eac0a1a6b5659ep-1,
    0x1.a30a69f5537ebc22f0870c2bd26ef284p-1,
    0x1.6af2eff0a2896p2,
  },
  { // Entry 174
    0x1.26312443bd35f19312eac0a1a6b5659ep-1,
    0x1.a30a69f5537ebc22f0870c2bd26ef284p-1,
    -0x1.6af2eff0a2896p2,
  },
  { // Entry 175
    -0x1.e18e660a5e2fb316ecbb9ed70122eff5p-1,
    0x1.5bd62e8b04ad5915e66242349b756e11p-2,
    0x1.43c62a9d02414p2,
  },
  { // Entry 176
    0x1.e18e660a5e2fb316ecbb9ed70122eff5p-1,
    0x1.5bd62e8b04ad5915e66242349b756e11p-2,
    -0x1.43c62a9d02414p2,
  },
  { // Entry 177
    -0x1.ee0e83a0198b6e2ef7c48e6625291a0ap-1,
    -0x1.0cb71f671e63410966e78d2009c0616fp-2,
    0x1.1c99654961f92p2,
  },
  { // Entry 178
    0x1.ee0e83a0198b6e2ef7c48e6625291a0ap-1,
    -0x1.0cb71f671e63410966e78d2009c0616fp-2,
    -0x1.1c99654961f92p2,
  },
  { // Entry 179
    -0x1.4727747338e4653616eadbd7ec3d02d3p-1,
    -0x1.89d86aa8521c11b74f8b1954c08f9b36p-1,
    0x1.ead93feb8361fp1,
  },
  { // Entry 180
    0x1.4727747338e4653616eadbd7ec3d02d3p-1,
    -0x1.89d86aa8521c11b74f8b1954c08f9b36p-1,
    -0x1.ead93feb8361fp1,
  },
  { // Entry 181
    -0x1.4ba2f75dda5fe434320905a7184ff1afp-4,
    -0x1.fe51ac554a16ad8194f181085f8a17f2p-1,
    0x1.9c7fb54442d1ap1,
  },
  { // Entry 182
    0x1.4ba2f75dda5fe434320905a7184ff1afp-4,
    -0x1.fe51ac554a16ad8194f181085f8a17f2p-1,
    -0x1.9c7fb54442d1ap1,
  },
  { // Entry 183
    0x1.034c4d633b4ef0a9089b43892a462a26p-1,
    -0x1.b97c04d08bc5d765b341a22b2c720b6fp-1,
    0x1.4e262a9d02415p1,
  },
  { // Entry 184
    -0x1.034c4d633b4ef0a9089b43892a462a26p-1,
    -0x1.b97c04d08bc5d765b341a22b2c720b6fp-1,
    -0x1.4e262a9d02415p1,
  },
  { // Entry 185
    0x1.d1e4cde2f3944f4c134c05cc4e5339a3p-1,
    -0x1.a8ac8a3e58f6ca952390299d2e8b187fp-2,
    0x1.ff993feb83620p0,
  },
  { // Entry 186
    -0x1.d1e4cde2f3944f4c134c05cc4e5339a3p-1,
    -0x1.a8ac8a3e58f6ca952390299d2e8b187fp-2,
    -0x1.ff993feb83620p0,
  },
  { // Entry 187
    0x1.f750235c949926c48c90e41a91474c06p-1,
    0x1.77a8b9b3d254a9e39d02b3eb3e2390e7p-3,
    0x1.62e62a9d02416p0,
  },
  { // Entry 188
    -0x1.f750235c949926c48c90e41a91474c06p-1,
    0x1.77a8b9b3d254a9e39d02b3eb3e2390e7p-3,
    -0x1.62e62a9d02416p0,
  },
  { // Entry 189
    0x1.65f7d571279b0b8005552fd47a2e77aep-1,
    0x1.6e1061205dd79051c112d30a05097c61p-1,
    0x1.8c662a9d02419p-1,
  },
  { // Entry 190
    -0x1.65f7d571279b0b8005552fd47a2e77aep-1,
    0x1.6e1061205dd79051c112d30a05097c61p-1,
    -0x1.8c662a9d02419p-1,
  },
  { // Entry 191
    -0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    -0x1.a8aa1d11c44ffp0,
  },
  { // Entry 192
    0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    0x1.a8aa1d11c44ffp0,
  },
  { // Entry 193
    -0x1.fff18f24f3e4b87bf8c3762cb44f46d6p-1,
    -0x1.e6669a270c36d4879b428ddba96cd87bp-7,
    -0x1.95ec8b9e03d54p0,
  },
  { // Entry 194
    0x1.fff18f24f3e4b87bf8c3762cb44f46d6p-1,
    -0x1.e6669a270c36d4879b428ddba96cd87bp-7,
    0x1.95ec8b9e03d54p0,
  },
  { // Entry 195
    -0x1.ff20d961624e7063a78203b811f579cap-1,
    0x1.ddd1ec25e209f1bbf7e17ef6c8450cd7p-5,
    -0x1.832efa2a435a9p0,
  },
  { // Entry 196
    0x1.ff20d961624e7063a78203b811f579cap-1,
    0x1.ddd1ec25e209f1bbf7e17ef6c8450cd7p-5,
    0x1.832efa2a435a9p0,
  },
  { // Entry 197
    -0x1.fb933c40107fd775185ac14918c8fbafp-1,
    0x1.0cab9115640d993082a7343bb5affea2p-3,
    -0x1.707168b682dfep0,
  },
  { // Entry 198
    0x1.fb933c40107fd775185ac14918c8fbafp-1,
    0x1.0cab9115640d993082a7343bb5affea2p-3,
    0x1.707168b682dfep0,
  },
  { // Entry 199
    -0x1.f54d971881ad685b782ef88e6350f7cdp-1,
    0x1.a0723a95492edee5dc98394e45f96d88p-3,
    -0x1.5db3d742c2653p0,
  },
  { // Entry 200
    0x1.f54d971881ad685b782ef88e6350f7cdp-1,
    0x1.a0723a95492edee5dc98394e45f96d88p-3,
    0x1.5db3d742c2653p0,
  },
  { // Entry 201
    -0x1.ec5883b7b6cf4d859ab04e15d53698c9p-1,
    0x1.18fee96a1a585928a94cda7e3d916fe1p-2,
    -0x1.4af645cf01ea8p0,
  },
  { // Entry 202
    0x1.ec5883b7b6cf4d859ab04e15d53698c9p-1,
    0x1.18fee96a1a585928a94cda7e3d916fe1p-2,
    0x1.4af645cf01ea8p0,
  },
  { // Entry 203
    -0x1.e0c04a94e17309c806c1c78bddc1d607p-1,
    0x1.6043621b13be2ff07085f8278598e566p-2,
    -0x1.3838b45b416fdp0,
  },
  { // Entry 204
    0x1.e0c04a94e17309c806c1c78bddc1d607p-1,
    0x1.6043621b13be2ff07085f8278598e566p-2,
    0x1.3838b45b416fdp0,
  },
  { // Entry 205
    -0x1.d294d1f96c7ebdb9869dd97cf574ddb9p-1,
    0x1.a5a4ccf40d9d9ba97faa4e23ecce9e3ap-2,
    -0x1.257b22e780f52p0,
  },
  { // Entry 206
    0x1.d294d1f96c7ebdb9869dd97cf574ddb9p-1,
    0x1.a5a4ccf40d9d9ba97faa4e23ecce9e3ap-2,
    0x1.257b22e780f52p0,
  },
  { // Entry 207
    -0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    -0x1.12bd9173c07abp0,
  },
  { // Entry 208
    0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    0x1.12bd9173c07abp0,
  },
  { // Entry 209
    -0x1.a2c289d9d055ac377f67d7a54a0b3005p-1,
    0x1.26976a6c4e0f86633327f1ceecb508aep-1,
    -0x1.ea5c3ed5b3850p-1,
  },
  { // Entry 210
    0x1.a2c289d9d055ac377f67d7a54a0b3005p-1,
    0x1.26976a6c4e0f86633327f1ceecb508aep-1,
    0x1.ea5c3ed5b3850p-1,
  },
  { // Entry 211
    -0x1.95f05257dbcb5f4b12636c5878ea405ap-1,
    0x1.3805a1882009f2843da808e959f17861p-1,
    -0x1.d4b87dab670a0p-1,
  },
  { // Entry 212
    0x1.95f05257dbcb5f4b12636c5878ea405ap-1,
    0x1.3805a1882009f2843da808e959f17861p-1,
    0x1.d4b87dab670a0p-1,
  },
  { // Entry 213
    -0x1.88647f26a6e0f6b2715a6c3797ec11f5p-1,
    0x1.48e52e0a65bcb3cd46455c4d2338bdf2p-1,
    -0x1.bf14bc811a8f0p-1,
  },
  { // Entry 214
    0x1.88647f26a6e0f6b2715a6c3797ec11f5p-1,
    0x1.48e52e0a65bcb3cd46455c4d2338bdf2p-1,
    0x1.bf14bc811a8f0p-1,
  },
  { // Entry 215
    -0x1.7a2541dfd4e752de38f04aba21fc9d9fp-1,
    0x1.592e58ea0a9eec0b357eb4e9a83b0ea5p-1,
    -0x1.a970fb56ce140p-1,
  },
  { // Entry 216
    0x1.7a2541dfd4e752de38f04aba21fc9d9fp-1,
    0x1.592e58ea0a9eec0b357eb4e9a83b0ea5p-1,
    0x1.a970fb56ce140p-1,
  },
  { // Entry 217
    -0x1.6b391e25bc26cbbcf7a0184070af9c39p-1,
    0x1.68d9afe052d1f0e9324ae876961bcdb1p-1,
    -0x1.93cd3a2c81990p-1,
  },
  { // Entry 218
    0x1.6b391e25bc26cbbcf7a0184070af9c39p-1,
    0x1.68d9afe052d1f0e9324ae876961bcdb1p-1,
    0x1.93cd3a2c81990p-1,
  },
  { // Entry 219
    -0x1.5ba6e6a8e706535b98fc99dfaef824f1p-1,
    0x1.77e008d0775e744eb16a2c4ec7184c43p-1,
    -0x1.7e297902351e0p-1,
  },
  { // Entry 220
    0x1.5ba6e6a8e706535b98fc99dfaef824f1p-1,
    0x1.77e008d0775e744eb16a2c4ec7184c43p-1,
    0x1.7e297902351e0p-1,
  },
  { // Entry 221
    -0x1.4b75ba096fa549eb93595d8194ab917fp-1,
    0x1.863a850e438fe029302aba0f5f127616p-1,
    -0x1.6885b7d7e8a30p-1,
  },
  { // Entry 222
    0x1.4b75ba096fa549eb93595d8194ab917fp-1,
    0x1.863a850e438fe029302aba0f5f127616p-1,
    0x1.6885b7d7e8a30p-1,
  },
  { // Entry 223
    -0x1.3aacff95a3122b15f372bfd2fdf9a75fp-1,
    0x1.93e2948233fce814439ed51fd2548920p-1,
    -0x1.52e1f6ad9c280p-1,
  },
  { // Entry 224
    0x1.3aacff95a3122b15f372bfd2fdf9a75fp-1,
    0x1.93e2948233fce814439ed51fd2548920p-1,
    0x1.52e1f6ad9c280p-1,
  },
  { // Entry 225
    -0x1.295463e769284a5aed17a443392f38f3p-1,
    0x1.a0d1f8a9a791d4b5694ca68a42fe6c9bp-1,
    -0x1.3d3e35834fad0p-1,
  },
  { // Entry 226
    0x1.295463e769284a5aed17a443392f38f3p-1,
    0x1.a0d1f8a9a791d4b5694ca68a42fe6c9bp-1,
    0x1.3d3e35834fad0p-1,
  },
  { // Entry 227
    -0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    -0x1.0a0b02501c799p-1,
  },
  { // Entry 228
    0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    0x1.0a0b02501c799p-1,
  },
  { // Entry 229
    -0x1.c853c78462de46b5743315612f8b5a7cp-2,
    0x1.ca59c6fa3d9ce238a227393b6b075bc5p-1,
    -0x1.d8f7208e6b82cp-2,
  },
  { // Entry 230
    0x1.c853c78462de46b5743315612f8b5a7cp-2,
    0x1.ca59c6fa3d9ce238a227393b6b075bc5p-1,
    0x1.d8f7208e6b82cp-2,
  },
  { // Entry 231
    -0x1.92aba90aaf27249de49c78fc643c8b72p-2,
    0x1.d6c0b125791cffce83e32564712b78c6p-1,
    -0x1.9dd83c7c9e126p-2,
  },
  { // Entry 232
    0x1.92aba90aaf27249de49c78fc643c8b72p-2,
    0x1.d6c0b125791cffce83e32564712b78c6p-1,
    0x1.9dd83c7c9e126p-2,
  },
  { // Entry 233
    -0x1.5bac064658f39460c83113c0a0097a0cp-2,
    0x1.e1960261829858391645bbe12019e58ap-1,
    -0x1.62b9586ad0a20p-2,
  },
  { // Entry 234
    0x1.5bac064658f39460c83113c0a0097a0cp-2,
    0x1.e1960261829858391645bbe12019e58ap-1,
    0x1.62b9586ad0a20p-2,
  },
```
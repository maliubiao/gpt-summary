Response:
Let's break down the thought process to answer the user's request about the `asin_intel_data.handroid` file.

**1. Understanding the Core Request:**

The user wants to understand the *purpose* of this file within the context of Android's bionic library. The key clues are the filename, the directory structure, and the data format.

* **Filename:** `asin_intel_data.handroid`. "asin" strongly suggests the inverse sine function. "intel_data" implies data specific to Intel architectures. ".handroid" hints at data used for testing on Android.
* **Directory:** `bionic/tests/math_data/`. This confirms it's part of the bionic library's testing framework, specifically for math functions.
* **Data Format:** The file contains a C++ array of structs. Each struct has two double-precision floating-point numbers. The comments like `// Entry 356` are also important for identifying the purpose of each data point.

**2. Initial Hypotheses and Deductions:**

Based on the filename and context, the most likely function of this file is to provide **test data** for the `asin()` function. Specifically, it likely contains pairs of input values and their expected output values.

* **Hypothesis 1:** The first value in each struct is the input to `asin()`, and the second value is the expected result.
* **Hypothesis 2:**  The "intel_data" part suggests this data might be specifically designed to test the `asin()` implementation when optimized for Intel processors or to uncover platform-specific edge cases.
* **Hypothesis 3:** The presence of both positive and negative inputs suggests testing the function's behavior across different quadrants of the input domain. The different magnitudes of the numbers likely test precision and edge cases (near 0, near +/-1).

**3. Addressing the Specific Questions:**

Now, I'll go through each of the user's requests and formulate answers based on the deductions:

* **功能 (Functionality):** This is directly answered by Hypothesis 1. It provides test cases for `asin()`.

* **与 Android 功能的关系 (Relationship with Android functionality):**  The key here is that `asin()` is a standard math function provided by the C library (`libc`), which is a core component of Android. This file helps ensure the correctness of this fundamental function on Android. The "intel_data" aspect reinforces the platform-specific nature within the Android ecosystem.

* **libc 函数的实现 (Implementation of libc functions):**  While this file *tests* `asin()`, it doesn't *implement* it. The actual implementation of `asin()` in `libc` involves complex numerical algorithms (like Taylor series or minimax approximations). This file just provides the "ground truth" for verifying that implementation. It's important to distinguish between test data and implementation.

* **dynamic linker 的功能 (Functionality of the dynamic linker):** This file is a static data file. It's not directly involved in the dynamic linking process. Dynamic linking is about loading and resolving shared libraries (`.so` files). This file would be *linked* into a test executable, but it doesn't demonstrate dynamic linking itself. Therefore, the answer here is that it's *not* related to the dynamic linker's direct functionality. Providing an SO layout and linking process isn't relevant here.

* **逻辑推理 (Logical reasoning):** The assumption is that the first number is input, and the second is the expected output. Examples can be created based on specific entries in the file. For instance, if the input is -0x1.ed2p-1, the expected output is -0x1.ef00708a54b2cp-1.

* **用户或编程常见的使用错误 (Common user/programming errors):** Since this is test data, the common errors would be related to *using* the `asin()` function itself (e.g., providing input outside the [-1, 1] range).

* **Android framework or NDK 如何到达这里 (How Android framework/NDK reaches here):** This requires understanding the testing process within Android. The NDK provides tools to compile native code, including tests. The Android framework uses `libc` functions. The path involves compiling test code that includes this data, linking it, and then running the tests on an Android device or emulator. Frida can be used to hook the `asin()` function and observe its inputs and outputs during test execution.

**4.归纳功能 (Summarizing Functionality) for Part 2:**

Since this is part 2, the request asks for a summary. The summary should reinforce the core purpose: providing comprehensive test data for the `asin()` function within Android's bionic library, emphasizing its role in ensuring the accuracy of this mathematical function.

**Self-Correction/Refinement During the Process:**

* Initially, I might have been tempted to speculate about the specific numerical methods used in the `asin()` implementation. However, the file itself doesn't reveal that. It's important to stick to what the data *shows*.
* I needed to be clear about the distinction between *testing* a function and *implementing* it when discussing `libc` functions.
* I also needed to be precise about the relationship (or lack thereof) with the dynamic linker. This file is static data, not a shared library.

By following this structured thought process, breaking down the request into smaller parts, and focusing on the information provided in the file and its context, I can generate a comprehensive and accurate answer to the user's query.
## 对 `bionic/tests/math_data/asin_intel_data.handroid` 源代码文件的功能归纳 (第 2 部分)

根据您提供的代码片段，以及第一部分的内容，我们可以归纳出 `bionic/tests/math_data/asin_intel_data.handroid` 文件的主要功能是：

**提供针对 `asin` (反正弦) 函数的特定测试数据，用于在 Android Bionic 库中进行单元测试。**

具体来说，该文件以 C++ 数组的形式存储了一系列预定义的输入和预期输出值对，用于验证 `asin` 函数在特定平台（很可能是 Intel 架构）上的正确性和精度。

**更详细的解释:**

* **测试 `asin` 函数的正确性:** 文件中的每一对数据 `{input, expected_output}` 都代表了一个针对 `asin` 函数的测试用例。测试框架会使用 `input` 值调用 `asin` 函数，并将函数的实际返回值与 `expected_output` 进行比较，以判断 `asin` 函数的实现是否正确。
* **覆盖不同的输入范围和边界条件:**  从数据中可以看出，测试用例覆盖了 `asin` 函数的有效输入范围 [-1, 1] 内的各种值，包括正数、负数、接近 0 的值、接近 1 和 -1 的值。这有助于确保 `asin` 函数在各种情况下都能返回正确的结果。
* **针对特定平台 (Intel) 的优化和特性进行测试:** 文件名中的 "intel_data" 暗示这些测试用例可能特别关注 Intel 架构上 `asin` 函数的实现细节、优化策略或者可能出现的特定问题。这有助于确保 Bionic 库在不同硬件平台上都能提供可靠的数学函数。
* **作为单元测试的一部分:** 该文件位于 `bionic/tests` 目录下，这明确表明它是 Bionic 库单元测试框架的一部分。单元测试是软件开发中验证代码功能的最基本和重要的步骤之一。
* **使用十六进制浮点数表示:** 数据使用十六进制浮点数表示（例如 `0x1.ed2p-1`），这种表示方法可以精确地表达浮点数，避免了十进制到二进制转换可能带来的精度损失，更利于精确的测试。
* **包含正负输入和输出:**  测试用例同时包含了正负的输入和输出，这有助于全面测试 `asin` 函数在不同象限的行为。
* **高精度测试:** 许多测试用例使用了非常高精度的浮点数，这表明测试的目标是验证 `asin` 函数在极高精度下的正确性。

**总结来说，`asin_intel_data.handroid` 文件是 Android Bionic 库中用于确保 `asin` 函数在特定硬件平台上正确运行的关键组成部分，它通过提供大量的、精心设计的测试用例来保证数学函数的质量。**

**与第一部分内容的呼应:**

结合第一部分的分析，我们了解到该文件不仅提供了测试数据，而且这些数据是与 Android 的 `libc` 库中的 `asin` 函数紧密相关的。这些数据帮助验证了 `libc` 中 `asin` 函数的实现，确保了 Android 应用程序在调用该函数时能得到正确的结果。 虽然该文件本身不涉及 dynamic linker 的功能，但它是 Android 运行时环境（由 Bionic 提供支持）不可或缺的一部分。

**总而言之，这个文件就像一个详尽的测试计划，针对 `asin` 函数在特定条件下的行为进行了细致的验证，是保证 Android 系统底层数学库稳定性和可靠性的重要基石。**

### 提示词
```
这是目录为bionic/tests/math_data/asin_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
cbe0b41389bc82e9f12e67c7p0,
    -0x1.ed2p-1
  },
  { // Entry 356
    0x1.4ff93f191d3694ab593de5dd6371b96fp0,
    0x1.ef00708a54b2cp-1
  },
  { // Entry 357
    -0x1.4ff93f191d3694ab593de5dd6371b96fp0,
    -0x1.ef00708a54b2cp-1
  },
  { // Entry 358
    0x1.ef77ab8e8feff4c39e94fa09320902abp-21,
    0x1.ef77ab8e8fa2ap-21
  },
  { // Entry 359
    -0x1.ef77ab8e8feff4c39e94fa09320902abp-21,
    -0x1.ef77ab8e8fa2ap-21
  },
  { // Entry 360
    0x1.efe5d9610962p-114,
    0x1.efe5d96109620p-114
  },
  { // Entry 361
    -0x1.efe5d9610962p-114,
    -0x1.efe5d96109620p-114
  },
  { // Entry 362
    0x1.51f4bd13f858ebf929a2088e2df34c72p0,
    0x1.effffffffffffp-1
  },
  { // Entry 363
    -0x1.51f4bd13f858ebf929a2088e2df34c72p0,
    -0x1.effffffffffffp-1
  },
  { // Entry 364
    0x1.52f8c72726a5343c6b1f75919edb5695p0,
    0x1.f08p-1
  },
  { // Entry 365
    -0x1.52f8c72726a5343c6b1f75919edb5695p0,
    -0x1.f08p-1
  },
  { // Entry 366
    0x1.54a5553221e80bf87bdb823192526176p0,
    0x1.f14e94d8d2e1ep-1
  },
  { // Entry 367
    -0x1.54a5553221e80bf87bdb823192526176p0,
    -0x1.f14e94d8d2e1ep-1
  },
  { // Entry 368
    0x1.5587523c7468b4173cf688f3219a184bp0,
    0x1.f1b9535b4f194p-1
  },
  { // Entry 369
    -0x1.5587523c7468b4173cf688f3219a184bp0,
    -0x1.f1b9535b4f194p-1
  },
  { // Entry 370
    0x1.56f4285735ecd7fe51444aebf353c0fbp0,
    0x1.f26274adac979p-1
  },
  { // Entry 371
    -0x1.56f4285735ecd7fe51444aebf353c0fbp0,
    -0x1.f26274adac979p-1
  },
  { // Entry 372
    0x1.6a45631fc69f340139208a9ea48fe11ap0,
    0x1.f9cef541d5e40p-1
  },
  { // Entry 373
    -0x1.6a45631fc69f340139208a9ea48fe11ap0,
    -0x1.f9cef541d5e40p-1
  },
  { // Entry 374
    0x1.fa639fc0adc0454cb19c822984da84edp-10,
    0x1.fa638b1ceed60p-10
  },
  { // Entry 375
    -0x1.fa639fc0adc0454cb19c822984da84edp-10,
    -0x1.fa638b1ceed60p-10
  },
  { // Entry 376
    0x1.fbf655a75453f895b93ae4abf4622da1p-5,
    0x1.fba3053043e65p-5
  },
  { // Entry 377
    -0x1.fbf655a75453f895b93ae4abf4622da1p-5,
    -0x1.fba3053043e65p-5
  },
  { // Entry 378
    0x1.7b802087557af76d96f304c0322df996p0,
    0x1.fe0084356e6d3p-1
  },
  { // Entry 379
    -0x1.7b802087557af76d96f304c0322df996p0,
    -0x1.fe0084356e6d3p-1
  },
  { // Entry 380
    0x1.7b8020890cf9e76f8fbc0fabd64eff53p0,
    0x1.fe008435bc011p-1
  },
  { // Entry 381
    -0x1.7b8020890cf9e76f8fbc0fabd64eff53p0,
    -0x1.fe008435bc011p-1
  },
  { // Entry 382
    0x1.7e1781bb355ec7803ff31d5be8def463p0,
    0x1.fe6eec178dfcbp-1
  },
  { // Entry 383
    -0x1.7e1781bb355ec7803ff31d5be8def463p0,
    -0x1.fe6eec178dfcbp-1
  },
  { // Entry 384
    0x1.7e2f2046c07b287fa8dea80ba23ad32dp0,
    0x1.fe729b3d76af8p-1
  },
  { // Entry 385
    -0x1.7e2f2046c07b287fa8dea80ba23ad32dp0,
    -0x1.fe729b3d76af8p-1
  },
  { // Entry 386
    0x1.7e2f2de8b8a817806d1670be6f754d6dp0,
    0x1.fe729d5c93ad0p-1
  },
  { // Entry 387
    -0x1.7e2f2de8b8a817806d1670be6f754d6dp0,
    -0x1.fe729d5c93ad0p-1
  },
  { // Entry 388
    0x1.ff49880d5a20aac3e3526e6cf9e09cb8p-10,
    0x1.ff4972cecbed8p-10
  },
  { // Entry 389
    -0x1.ff49880d5a20aac3e3526e6cf9e09cb8p-10,
    -0x1.ff4972cecbed8p-10
  },
  { // Entry 390
    0x1.ff87e144b3d5285c831c0483be2e06a7p-6,
    0x1.ff729b33a450ap-6
  },
  { // Entry 391
    -0x1.ff87e144b3d5285c831c0483be2e06a7p-6,
    -0x1.ff729b33a450ap-6
  },
  { // Entry 392
    0x1.027c7bd81acdf7fffe09c8613b3ac04ap-2,
    0x1.ff7feffffffffp-3
  },
  { // Entry 393
    -0x1.027c7bd81acdf7fffe09c8613b3ac04ap-2,
    -0x1.ff7feffffffffp-3
  },
  { // Entry 394
    0x1.ff8ffffffffff0000000551d619470aap-41,
    0x1.ff8ffffffffffp-41
  },
  { // Entry 395
    -0x1.ff8ffffffffff0000000551d619470aap-41,
    -0x1.ff8ffffffffffp-41
  },
  { // Entry 396
    0x1.0bf4cf34f3faeff2e4c6b885b77bb549p-1,
    0x1.ffc7fffffffffp-2
  },
  { // Entry 397
    -0x1.0bf4cf34f3faeff2e4c6b885b77bb549p-1,
    -0x1.ffc7fffffffffp-2
  },
  { // Entry 398
    0x1.8ab0d642e4c54804398ead7dd2453377p0,
    0x1.ffc8c0c7e6e1ap-1
  },
  { // Entry 399
    -0x1.8ab0d642e4c54804398ead7dd2453377p0,
    -0x1.ffc8c0c7e6e1ap-1
  },
  { // Entry 400
    0x1.8bbc3fa798db6800007c1f9be356a554p0,
    0x1.ffd730634939cp-1
  },
  { // Entry 401
    -0x1.8bbc3fa798db6800007c1f9be356a554p0,
    -0x1.ffd730634939cp-1
  },
  { // Entry 402
    0x1.8bc09a510098b804dee9939611959c0ep0,
    0x1.ffd767f0eb014p-1
  },
  { // Entry 403
    -0x1.8bc09a510098b804dee9939611959c0ep0,
    -0x1.ffd767f0eb014p-1
  },
  { // Entry 404
    0x1.0022b9e6710f97fcdf56a91cace59e6dp-4,
    0x1.fff000000000ap-5
  },
  { // Entry 405
    -0x1.0022b9e6710f97fcdf56a91cace59e6dp-4,
    -0x1.fff000000000ap-5
  },
  { // Entry 406
    0x1.fff1065375e97dcce338cf6e9331a5d9p-10,
    0x1.fff0f0fffffffp-10
  },
  { // Entry 407
    -0x1.fff1065375e97dcce338cf6e9331a5d9p-10,
    -0x1.fff0f0fffffffp-10
  },
  { // Entry 408
    0x1.0c10851c1a1097dc3df97865c5caec5bp-1,
    0x1.fff7fffffffffp-2
  },
  { // Entry 409
    -0x1.0c10851c1a1097dc3df97865c5caec5bp-1,
    -0x1.fff7fffffffffp-2
  },
  { // Entry 410
    0x1.02be94db85e837fffd06abd4bb6eb065p-2,
    0x1.fffff077fffaep-3
  },
  { // Entry 411
    -0x1.02be94db85e837fffd06abd4bb6eb065p-2,
    -0x1.fffff077fffaep-3
  },
  { // Entry 412
    0x1.ffffff4555553f7bbbbd352972db79p-15,
    0x1.ffffff3ffffffp-15
  },
  { // Entry 413
    -0x1.ffffff4555553f7bbbbd352972db79p-15,
    -0x1.ffffff3ffffffp-15
  },
  { // Entry 414
    0x1.00abe0c026d6980000ee7b5b3c750ee4p-3,
    0x1.fffffffdfdf9bp-4
  },
  { // Entry 415
    -0x1.00abe0c026d6980000ee7b5b3c750ee4p-3,
    -0x1.fffffffdfdf9bp-4
  },
  { // Entry 416
    0x1.921e7bbb5b08af737a8c86a1f3470fb7p0,
    0x1.fffffffe7ffffp-1
  },
  { // Entry 417
    -0x1.921e7bbb5b08af737a8c86a1f3470fb7p0,
    -0x1.fffffffe7ffffp-1
  },
  { // Entry 418
    0x1.921e91836230570dcee4fe03756f458cp0,
    0x1.fffffffeb37ffp-1
  },
  { // Entry 419
    -0x1.921e91836230570dcee4fe03756f458cp0,
    -0x1.fffffffeb37ffp-1
  },
  { // Entry 420
    0x1.0002aabdac7327ffffd50d8db1e7238cp-6,
    0x1.ffffffff9bbffp-7
  },
  { // Entry 421
    -0x1.0002aabdac7327ffffd50d8db1e7238cp-6,
    -0x1.ffffffff9bbffp-7
  },
  { // Entry 422
    0x1.00abe0c121d1a80c0ce870896b905389p-3,
    0x1.ffffffffeffffp-4
  },
  { // Entry 423
    -0x1.00abe0c121d1a80c0ce870896b905389p-3,
    -0x1.ffffffffeffffp-4
  },
  { // Entry 424
    0x1.0002aabdde7237febfdec02e5706bab1p-6,
    0x1.ffffffffffbafp-7
  },
  { // Entry 425
    -0x1.0002aabdde7237febfdec02e5706bab1p-6,
    -0x1.ffffffffffbafp-7
  },
  { // Entry 426
    0x1.002abde95358d80170fb3700a02d872dp-4,
    0x1.ffffffffffee9p-5
  },
  { // Entry 427
    -0x1.002abde95358d80170fb3700a02d872dp-4,
    -0x1.ffffffffffee9p-5
  },
  { // Entry 428
    0x1.921fb2cdef21d7febc9f3f1b1d1683b0p0,
    0x1.fffffffffff9fp-1
  },
  { // Entry 429
    -0x1.921fb2cdef21d7febc9f3f1b1d1683b0p0,
    -0x1.fffffffffff9fp-1
  },
  { // Entry 430
    0x1.921fb48f3dde506fab247b4dc86ea6e0p0,
    0x1.ffffffffffff8p-1
  },
  { // Entry 431
    -0x1.921fb48f3dde506fab247b4dc86ea6e0p0,
    -0x1.ffffffffffff8p-1
  },
  { // Entry 432
    0x1.02be9ce0b87c980fa863b980f3eb6ed8p-2,
    0x1.ffffffffffff9p-3
  },
  { // Entry 433
    -0x1.02be9ce0b87c980fa863b980f3eb6ed8p-2,
    -0x1.ffffffffffff9p-3
  },
  { // Entry 434
    0x1.0c152382d73658465bb32e0f567ad116p-1,
    0x1.0p-1
  },
  { // Entry 435
    -0x1.0c152382d73658465bb32e0f567ad116p-1,
    -0x1.0p-1
  },
  { // Entry 436
    0x1.0c152382d73658465bb32e0f567ad116p-1,
    0x1.0p-1
  },
  { // Entry 437
    -0x1.0c152382d73658465bb32e0f567ad116p-1,
    -0x1.0p-1
  },
  { // Entry 438
    0x1.4a1ce4ed5846e1103ebca2dd90e3eb3fp-1,
    0x1.33b645a1cac08p-1
  },
  { // Entry 439
    -0x1.4a1ce4ed5846e1103ebca2dd90e3eb3fp-1,
    -0x1.33b645a1cac08p-1
  },
  { // Entry 440
    0x1.921fb54442d177a2e305f4ec49b839a2p-1,
    0x1.6a09e667f3bccp-1
  },
  { // Entry 441
    -0x1.921fb54442d177a2e305f4ec49b839a2p-1,
    -0x1.6a09e667f3bccp-1
  },
  { // Entry 442
    0x1.921fb54442d177a2e305f4ec49b839a2p-1,
    0x1.6a09e667f3bccp-1
  },
  { // Entry 443
    -0x1.921fb54442d177a2e305f4ec49b839a2p-1,
    -0x1.6a09e667f3bccp-1
  },
  { // Entry 444
    -0x1.b235315c680dc081583db360d5e1fa18p-1,
    -0x1.8p-1
  },
  { // Entry 445
    0x1.b235315c680dc081583db360d5e1fa18p-1,
    0x1.8p-1
  },
  { // Entry 446
    0x1.0c152382d736510b363f009eddefddebp0,
    0x1.bb67ae8584caap-1
  },
  { // Entry 447
    -0x1.0c152382d736510b363f009eddefddebp0,
    -0x1.bb67ae8584caap-1
  },
  { // Entry 448
    0x1.0c152382d736510b363f009eddefddebp0,
    0x1.bb67ae8584caap-1
  },
  { // Entry 449
    -0x1.0c152382d736510b363f009eddefddebp0,
    -0x1.bb67ae8584caap-1
  },
  { // Entry 450
    0x1.908138a8b9ab762dbe47f3cc71dd77a4p0,
    0x1.fffd60e94ee39p-1
  },
  { // Entry 451
    -0x1.908138a8b9ab762dbe47f3cc71dd77a4p0,
    -0x1.fffd60e94ee39p-1
  },
  { // Entry 452
    0x1.p-82,
    0x1.0p-82
  },
  { // Entry 453
    -0x1.p-82,
    -0x1.0p-82
  },
  { // Entry 454
    0x1.0000000000000000000000000000000ap-61,
    0x1.0p-61
  },
  { // Entry 455
    -0x1.0000000000000000000000000000000ap-61,
    -0x1.0p-61
  },
  { // Entry 456
    0x1.0000000000000000000002aaaaaaaaaap-42,
    0x1.0p-42
  },
  { // Entry 457
    -0x1.0000000000000000000002aaaaaaaaaap-42,
    -0x1.0p-42
  },
  { // Entry 458
    0x1.000000000002aaaaaaaaaabdddddddddp-22,
    0x1.0p-22
  },
  { // Entry 459
    -0x1.000000000002aaaaaaaaaabdddddddddp-22,
    -0x1.0p-22
  },
  { // Entry 460
    0x1.6a0a049378647a1e52ffdf31536df951p-9,
    0x1.6a09e667f3bcbp-9
  },
  { // Entry 461
    -0x1.6a0a049378647a1e52ffdf31536df951p-9,
    -0x1.6a09e667f3bcbp-9
  },
  { // Entry 462
    0x1.6a0a049378648a1e56ffe0b1540df936p-9,
    0x1.6a09e667f3bccp-9
  },
  { // Entry 463
    -0x1.6a0a049378648a1e56ffe0b1540df936p-9,
    -0x1.6a09e667f3bccp-9
  },
  { // Entry 464
    0x1.6a0a049378649a1e5affe23154adf976p-9,
    0x1.6a09e667f3bcdp-9
  },
  { // Entry 465
    -0x1.6a0a049378649a1e5affe23154adf976p-9,
    -0x1.6a09e667f3bcdp-9
  },
  { // Entry 466
    0x1.6a0a5f1657d1bf22d957bf86231eed1ap-8,
    0x1.6a09e667f3bcbp-8
  },
  { // Entry 467
    -0x1.6a0a5f1657d1bf22d957bf86231eed1ap-8,
    -0x1.6a09e667f3bcbp-8
  },
  { // Entry 468
    0x1.6a0a5f1657d1cf22e957d7864b1f3199p-8,
    0x1.6a09e667f3bccp-8
  },
  { // Entry 469
    -0x1.6a0a5f1657d1cf22e957d7864b1f3199p-8,
    -0x1.6a09e667f3bccp-8
  },
  { // Entry 470
    0x1.6a0a5f1657d1df22f957ef86731f7782p-8,
    0x1.6a09e667f3bcdp-8
  },
  { // Entry 471
    -0x1.6a0a5f1657d1df22f957ef86731f7782p-8,
    -0x1.6a09e667f3bcdp-8
  },
  { // Entry 472
    0x1.6a0bc9269b86124131fa4b997808aec8p-7,
    0x1.6a09e667f3bcbp-7
  },
  { // Entry 473
    -0x1.6a0bc9269b86124131fa4b997808aec8p-7,
    -0x1.6a09e667f3bcbp-7
  },
  { // Entry 474
    0x1.6a0bc9269b86224171fbcba3784eaabap-7,
    0x1.6a09e667f3bccp-7
  },
  { // Entry 475
    -0x1.6a0bc9269b86224171fbcba3784eaabap-7,
    -0x1.6a09e667f3bccp-7
  },
  { // Entry 476
    0x1.6a0bc9269b863241b1fd4bad7894ac55p-7,
    0x1.6a09e667f3bcdp-7
  },
  { // Entry 477
    -0x1.6a0bc9269b863241b1fd4bad7894ac55p-7,
    -0x1.6a09e667f3bcdp-7
  },
  { // Entry 478
    0x1.6a1171b40fe3d57da5c2e2ec8650d873p-6,
    0x1.6a09e667f3bcbp-6
  },
  { // Entry 479
    -0x1.6a1171b40fe3d57da5c2e2ec8650d873p-6,
    -0x1.6a09e667f3bcbp-6
  },
  { // Entry 480
    0x1.6a1171b40fe3e57ea5dae56ccc58a13ep-6,
    0x1.6a09e667f3bccp-6
  },
  { // Entry 481
    -0x1.6a1171b40fe3e57ea5dae56ccc58a13ep-6,
    -0x1.6a09e667f3bccp-6
  },
  { // Entry 482
    0x1.6a1171b40fe3f57fa5f2e7ed126080afp-6,
    0x1.6a09e667f3bcdp-6
  },
  { // Entry 483
    -0x1.6a1171b40fe3f57fa5f2e7ed126080afp-6,
    -0x1.6a09e667f3bcdp-6
  },
  { // Entry 484
    0x1.6a2818b1a0bd5f9b490a8ffd372921ffp-5,
    0x1.6a09e667f3bcbp-5
  },
  { // Entry 485
    -0x1.6a2818b1a0bd5f9b490a8ffd372921ffp-5,
    -0x1.6a09e667f3bcbp-5
  },
  { // Entry 486
    0x1.6a2818b1a0bd6f9f4a8b304356b73812p-5,
    0x1.6a09e667f3bccp-5
  },
  { // Entry 487
    -0x1.6a2818b1a0bd6f9f4a8b304356b73812p-5,
    -0x1.6a09e667f3bccp-5
  },
  { // Entry 488
    0x1.6a2818b1a0bd7fa34c0bd0897645a8ebp-5,
    0x1.6a09e667f3bcdp-5
  },
  { // Entry 489
    -0x1.6a2818b1a0bd7fa34c0bd0897645a8ebp-5,
    -0x1.6a09e667f3bcdp-5
  },
  { // Entry 490
    0x1.6a83017dfb54c538079f0571169f7c03p-4,
    0x1.6a09e667f3bcbp-4
  },
  { // Entry 491
    -0x1.6a83017dfb54c538079f0571169f7c03p-4,
    -0x1.6a09e667f3bcbp-4
  },
  { // Entry 492
    0x1.6a83017dfb54d5481fc74befff4e205fp-4,
    0x1.6a09e667f3bccp-4
  },
  { // Entry 493
    -0x1.6a83017dfb54d5481fc74befff4e205fp-4,
    -0x1.6a09e667f3bccp-4
  },
  { // Entry 494
    0x1.6a83017dfb54e55837ef926ee7fe330dp-4,
    0x1.6a09e667f3bcdp-4
  },
  { // Entry 495
    -0x1.6a83017dfb54e55837ef926ee7fe330dp-4,
    -0x1.6a09e667f3bcdp-4
  },
  { // Entry 496
    0x1.6bf38916421401c3b5732e0d6b50ebd0p-3,
    0x1.6a09e667f3bcbp-3
  },
  { // Entry 497
    -0x1.6bf38916421401c3b5732e0d6b50ebd0p-3,
    -0x1.6a09e667f3bcbp-3
  },
  { // Entry 498
    0x1.6bf38916421412053fbb34ebe8221436p-3,
    0x1.6a09e667f3bccp-3
  },
  { // Entry 499
    -0x1.6bf38916421412053fbb34ebe8221436p-3,
    -0x1.6a09e667f3bccp-3
  },
  { // Entry 500
    0x1.6bf3891642142246ca033bca64f92b66p-3,
    0x1.6a09e667f3bcdp-3
  },
  { // Entry 501
    -0x1.6bf3891642142246ca033bca64f92b66p-3,
    -0x1.6a09e667f3bcdp-3
  },
  { // Entry 502
    0x1.720a392c1d952d8e8ad756e1430b13d1p-2,
    0x1.6a09e667f3bcbp-2
  },
  { // Entry 503
    -0x1.720a392c1d952d8e8ad756e1430b13d1p-2,
    -0x1.6a09e667f3bcbp-2
  },
  { // Entry 504
    0x1.720a392c1d953ea959bcb7056cb6fa96p-2,
    0x1.6a09e667f3bccp-2
  },
  { // Entry 505
    -0x1.720a392c1d953ea959bcb7056cb6fa96p-2,
    -0x1.6a09e667f3bccp-2
  },
  { // Entry 506
    0x1.720a392c1d954fc428a21729967e8694p-2,
    0x1.6a09e667f3bcdp-2
  },
  { // Entry 507
    -0x1.720a392c1d954fc428a21729967e8694p-2,
    -0x1.6a09e667f3bcdp-2
  },
  { // Entry 508
    0x1.bb67e5f28d500f1ccaec1a38d240d53fp-9,
    0x1.bb67ae8584ca9p-9
  },
  { // Entry 509
    -0x1.bb67e5f28d500f1ccaec1a38d240d53fp-9,
    -0x1.bb67ae8584ca9p-9
  },
  { // Entry 510
    0x1.bb67e5f28d501f1cd0ec1d98d45cd638p-9,
    0x1.bb67ae8584caap-9
  },
  { // Entry 511
    -0x1.bb67e5f28d501f1cd0ec1d98d45cd638p-9,
    -0x1.bb67ae8584caap-9
  },
  { // Entry 512
    0x1.bb67e5f28d502f1cd6ec20f8d678d7a0p-9,
    0x1.bb67ae8584cabp-9
  },
  { // Entry 513
    -0x1.bb67e5f28d502f1cd6ec20f8d678d7a0p-9,
    -0x1.bb67ae8584cabp-9
  },
  { // Entry 514
    0x1.bb688c3a875bcb79b1d1fd5de10c96d1p-8,
    0x1.bb67ae8584ca9p-8
  },
  { // Entry 515
    -0x1.bb688c3a875bcb79b1d1fd5de10c96d1p-8,
    -0x1.bb67ae8584ca9p-8
  },
  { // Entry 516
    0x1.bb688c3a875bdb79c9d2335e680df78fp-8,
    0x1.bb67ae8584caap-8
  },
  { // Entry 517
    -0x1.bb688c3a875bdb79c9d2335e680df78fp-8,
    -0x1.bb67ae8584caap-8
  },
  { // Entry 518
    0x1.bb688c3a875beb79e1d2695eef0f5a08p-8,
    0x1.bb67ae8584cabp-8
  },
  { // Entry 519
    -0x1.bb688c3a875beb79e1d2695eef0f5a08p-8,
    -0x1.bb67ae8584cabp-8
  },
  { // Entry 520
    0x1.bb6b2567972165018cf35a469b36c5e6p-7,
    0x1.bb67ae8584ca9p-7
  },
  { // Entry 521
    -0x1.bb6b2567972165018cf35a469b36c5e6p-7,
    -0x1.bb67ae8584ca9p-7
  },
  { // Entry 522
    0x1.bb6b256797217501ecf6ba685c992e41p-7,
    0x1.bb67ae8584caap-7
  },
  { // Entry 523
    -0x1.bb6b256797217501ecf6ba685c992e41p-7,
    -0x1.bb67ae8584caap-7
  },
  { // Entry 524
    0x1.bb6b2567972185024cfa1a8a1dfb9d8ap-7,
    0x1.bb67ae8584cabp-7
  },
  { // Entry 525
    -0x1.bb6b2567972185024cfa1a8a1dfb9d8ap-7,
    -0x1.bb67ae8584cabp-7
  },
  { // Entry 526
    0x1.bb758aee66c4f6179c2a4c9e47ed2c98p-6,
    0x1.bb67ae8584ca9p-6
  },
  { // Entry 527
    -0x1.bb758aee66c4f6179c2a4c9e47ed2c98p-6,
    -0x1.bb67ae8584ca9p-6
  },
  { // Entry 528
    0x1.bb758aee66c506191c60550faa88e978p-6,
    0x1.bb67ae8584caap-6
  },
  { // Entry 529
    -0x1.bb758aee66c506191c60550faa88e978p-6,
    -0x1.bb67ae8584caap-6
  },
  { // Entry 530
    0x1.bb758aee66c5161a9c965d810d24c216p-6,
    0x1.bb67ae8584cabp-6
  },
  { // Entry 531
    -0x1.bb758aee66c5161a9c965d810d24c216p-6,
    -0x1.bb67ae8584cabp-6
  },
  { // Entry 532
    0x1.bb9f2e3879c2cf9ea454ab283af7825ap-5,
    0x1.bb67ae8584ca9p-5
  },
  { // Entry 533
    -0x1.bb9f2e3879c2cf9ea454ab283af7825ap-5,
    -0x1.bb67ae8584ca9p-5
  },
  { // Entry 534
    0x1.bb9f2e3879c2dfa4a7b6c88b8acffef5p-5,
    0x1.bb67ae8584caap-5
  },
  { // Entry 535
    -0x1.bb9f2e3879c2dfa4a7b6c88b8acffef5p-5,
    -0x1.bb67ae8584caap-5
  },
  { // Entry 536
    0x1.bb9f2e3879c2efaaab18e5eedaa8eae8p-5,
    0x1.bb67ae8584cabp-5
  },
  { // Entry 537
    -0x1.bb9f2e3879c2efaaab18e5eedaa8eae8p-5,
    -0x1.bb67ae8584cabp-5
  },
  { // Entry 538
    0x1.bc468fc3ecf6b031e5cd5bd050766cd7p-4,
    0x1.bb67ae8584ca9p-4
  },
  { // Entry 539
    -0x1.bc468fc3ecf6b031e5cd5bd050766cd7p-4,
    -0x1.bb67ae8584ca9p-4
  },
  { // Entry 540
    0x1.bc468fc3ecf6c04a1c55c1f784a40b33p-4,
    0x1.bb67ae8584caap-4
  },
  { // Entry 541
    -0x1.bc468fc3ecf6c04a1c55c1f784a40b33p-4,
    -0x1.bb67ae8584caap-4
  },
  { // Entry 542
    0x1.bc468fc3ecf6d06252de281eb8d36cdfp-4,
    0x1.bb67ae8584cabp-4
  },
  { // Entry 543
    -0x1.bc468fc3ecf6d06252de281eb8d36cdfp-4,
    -0x1.bb67ae8584cabp-4
  },
  { // Entry 544
    0x1.bef1bcb08890131f87f550d6c3652dd7p-3,
    0x1.bb67ae8584ca9p-3
  },
  { // Entry 545
    -0x1.bef1bcb08890131f87f550d6c3652dd7p-3,
    -0x1.bb67ae8584ca9p-3
  },
  { // Entry 546
    0x1.bef1bcb0889023830b2750073d51ac87p-3,
    0x1.bb67ae8584caap-3
  },
  { // Entry 547
    -0x1.bef1bcb0889023830b2750073d51ac87p-3,
    -0x1.bb67ae8584caap-3
  },
  { // Entry 548
    0x1.bef1bcb0889033e68e594f37b7459d46p-3,
    0x1.bb67ae8584cabp-3
  },
  { // Entry 549
    -0x1.bef1bcb0889033e68e594f37b7459d46p-3,
    -0x1.bb67ae8584cabp-3
  },
  { // Entry 550
    0x1.ca94936b98a1ffe8286e976abd1b0451p-2,
    0x1.bb67ae8584ca9p-2
  },
  { // Entry 551
    -0x1.ca94936b98a1ffe8286e976abd1b0451p-2,
    -0x1.bb67ae8584ca9p-2
  },
  { // Entry 552
    0x1.ca94936b98a211a8430ed35352bc881bp-2,
    0x1.bb67ae8584caap-2
  },
  { // Entry 553
    -0x1.ca94936b98a211a8430ed35352bc881bp-2,
    -0x1.bb67ae8584caap-2
  },
  { // Entry 554
    0x1.ca94936b98a223685daf0f3be883e2d0p-2,
    0x1.bb67ae8584cabp-2
  },
  { // Entry 555
    -0x1.ca94936b98a223685daf0f3be883e2d0p-2,
    -0x1.bb67ae8584cabp-2
  },
  { // Entry 556
    0x1.fffffffffffff0p-128,
    0x1.fffffffffffffp-128
  },
  { // Entry 557
    -0x1.fffffffffffff0p-128,
    -0x1.fffffffffffffp-128
  },
  { // Entry 558
    0x1.p-127,
    0x1.0p-127
  },
  { // Entry 559
    -0x1.p-127,
    -0x1.0p-127
  },
  { // Entry 560
    0x1.00000000000010p-127,
    0x1.0000000000001p-127
  },
  { // Entry 561
    -0x1.00000000000010p-127,
    -0x1.0000000000001p-127
  },
  { // Entry 562
    0x1.fffffffffffff0p-127,
    0x1.fffffffffffffp-127
  },
  { // Entry 563
    -0x1.fffffffffffff0p-127,
    -0x1.fffffffffffffp-127
  },
  { // Entry 564
    0x1.p-126,
    0x1.0p-126
  },
  { // Entry 565
    -0x1.p-126,
    -0x1.0p-126
  },
  { // Entry 566
    0x1.00000000000010p-126,
    0x1.0000000000001p-126
  },
  { // Entry 567
    -0x1.00000000000010p-126,
    -0x1.0000000000001p-126
  },
  { // Entry 568
    -0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 569
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 570
    -0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 571
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 572
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 573
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 574
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 575
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 576
    -0.0,
    -0.0
  },
  { // Entry 577
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 578
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 579
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 580
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 581
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 582
    -0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 583
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 584
    -0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 585
    0x1.fffffffffffff005555555555554d57bp-31,
    0x1.fffffffffffffp-31
  },
  { // Entry 586
    -0x1.fffffffffffff005555555555554d57bp-31,
    -0x1.fffffffffffffp-31
  },
  { // Entry 587
    0x1.0000000000000002aaaaaaaaaaaaaabdp-30,
    0x1.0p-30
  },
  { // Entry 588
    -0x1.0000000000000002aaaaaaaaaaaaaabdp-30,
    -0x1.0p-30
  },
  { // Entry 589
    0x1.0000000000001002aaaaaaaaaaab2abdp-30,
    0x1.0000000000001p-30
  },
  { // Entry 590
    -0x1.0000000000001002aaaaaaaaaaab2abdp-30,
    -0x1.0000000000001p-30
  },
  { // Entry 591
    0x1.fffffffffffff155555555555537bbbbp-28,
    0x1.fffffffffffffp-28
  },
  { // Entry 592
    -0x1.fffffffffffff155555555555537bbbbp-28,
    -0x1.fffffffffffffp-28
  },
  { // Entry 593
    0x1.00000000000000aaaaaaaaaaaaabddddp-27,
    0x1.0p-27
  },
  { // Entry 594
    -0x1.00000000000000aaaaaaaaaaaaabddddp-27,
    -0x1.0p-27
  },
  { // Entry 595
    0x1.00000000000010aaaaaaaaaaaacbddddp-27,
    0x1.0000000000001p-27
  },
  { // Entry 596
    -0x1.00000000000010aaaaaaaaaaaacbddddp-27,
    -0x1.0000000000001p-27
  },
  { // Entry 597
    0x1.00000000000002aaaaaaaaaaaaddddddp-25,
    0x1.fffffffffffffp-26
  },
  { // Entry 598
    -0x1.00000000000002aaaaaaaaaaaaddddddp-25,
    -0x1.fffffffffffffp-26
  },
  { // Entry 599
    0x1.0000000000000aaaaaaaaaaaabddddddp-25,
    0x1.0p-25
  },
  { // Entry 600
    -0x1.0000000000000aaaaaaaaaaaabddddddp-25,
    -0x1.0p-25
  },
  { // Entry 601
    0x1.0000000000001aaaaaaaaaaaadddddddp-25,
    0x1.0000000000001p-25
  },
  { // Entry 602
    -0x1.0000000000001aaaaaaaaaaaadddddddp-25,
    -0x1.0000000000001p-25
  },
  { // Entry 603
    0x1.00000002aaaaa2bddddd9e94b9489c80p-14,
    0x1.fffffffffffffp-15
  },
  { // Entry 604
    -0x1.00000002aaaaa2bddddd9e94b9489c80p-14,
    -0x1.fffffffffffffp-15
  },
  { // Entry 605
    0x1.00000002aaaaaabdddddde94b94b9c80p-14,
    0x1.0p-14
  },
  { // Entry 606
    -0x1.00000002aaaaaabdddddde94b94b9c80p-14,
    -0x1.0p-14
  },
  { // Entry 607
    0x1.00000002aaaababdddde5e94b9519c80p-14,
    0x1.0000000000001p-14
  },
  { // Entry 608
    -0x1.00000002aaaababdddde5e94b9519c80p-14,
    -0x1.0000000000001p-14
  },
  { // Entry 609
    0x1.0002aabdde94b912cccf6cb7a147dbe6p-6,
    0x1.fffffffffffffp-7
  },
  { // Entry 610
    -0x1.0002aabdde94b912cccf6cb7a147dbe6p-6,
    -0x1.fffffffffffffp-7
  },
  { // Entry 611
    0x1.0002aabdde94c1130cd26cdfa377f967p-6,
    0x1.0p-6
  },
  { // Entry 612
    -0x1.0002aabdde94c1130cd26cdfa377f967p-6,
    -0x1.0p-6
  },
  { // Entry 613
    0x1.0002aabdde94d1138cd86d2fa7d8406cp-6,
    0x1.0000000000001p-6
  },
  { // Entry 614
    -0x1.0002aabdde94d1138cd86d2fa7d8406cp-6,
    -0x1.0000000000001p-6
  },
  { // Entry 615
    0x1.000aabde0b9c79d5d91547bc0e143946p-5,
    0x1.fffffffffffffp-6
  },
  { // Entry 616
    -0x1.000aabde0b9c79d5d91547bc0e143946p-5,
    -0x1.fffffffffffffp-6
  },
  { // Entry 617
    0x1.000aabde0b9c81d6d94551be3e924e2ap-5,
    0x1.0p-5
  },
  { // Entry 618
    -0x1.000aabde0b9c81d6d94551be3e924e2ap-5,
    -0x1.0p-5
  },
  { // Entry 619
    0x1.000aabde0b9c91d8d9a565c29f8ea804p-5,
    0x1.0000000000001p-5
  },
  { // Entry 620
    -0x1.000aabde0b9c91d8d9a565c29f8ea804p-5,
    -0x1.0000000000001p-5
  },
  { // Entry 621
    0x1.002abde953618c5cb5b49945c179d0f3p-4,
    0x1.fffffffffffffp-5
  },
  { // Entry 622
    -0x1.002abde953618c5cb5b49945c179d0f3p-4,
    -0x1.fffffffffffffp-5
  },
  { // Entry 623
    0x1.002abde953619460b8b71b77bb495f57p-4,
    0x1.0p-4
  },
  { // Entry 624
    -0x1.002abde953619460b8b71b77bb495f57p-4,
    -0x1.0p-4
  },
  { // Entry 625
    0x1.002abde95361a468bebc1fdbaee93d3fp-4,
    0x1.0000000000001p-4
  },
  { // Entry 626
    -0x1.002abde95361a468bebc1fdbaee93d3fp-4,
    -0x1.0000000000001p-4
  },
  { // Entry 627
    0x1.00abe0c129e1d8ae44e53a515476507cp-3,
    0x1.fffffffffffffp-4
  },
  { // Entry 628
    -0x1.00abe0c129e1d8ae44e53a515476507cp-3,
    -0x1.fffffffffffffp-4
  },
  { // Entry 629
    0x1.00abe0c129e1e0be7587724ea14e03b1p-3,
    0x1.0p-3
  },
  { // Entry 630
    -0x1.00abe0c129e1e0be7587724ea14e03b1p-3,
    -0x1.0p-3
  },
  { // Entry 631
    0x1.00abe0c129e1f0ded6cbe2493b007c79p-3,
    0x1.0000000000001p-3
  },
  { // Entry 632
    -0x1.00abe0c129e1f0ded6cbe2493b007c79p-3,
    -0x1.0000000000001p-3
  },
  { // Entry 633
    0x1.02be9ce0b87cc9a2a64c386583040afap-2,
    0x1.fffffffffffffp-3
  },
  { // Entry 634
    -0x1.02be9ce0b87cc9a2a64c386583040afap-2,
    -0x1.fffffffffffffp-3
  },
  { // Entry 635
    0x1.02be9ce0b87cd1e5d09da2e0f0423bfap-2,
    0x1.0p-2
  },
  { // Entry 636
    -0x1.02be9ce0b87cd1e5d09da2e0f0423bfap-2,
    -0x1.0p-2
  },
  { // Entry 637
    0x1.02be9ce0b87ce26c254077d7cacbd63cp-2,
    0x1.0000000000001p-2
  },
  { // Entry 638
    -0x1.02be9ce0b87ce26c254077d7cacbd63cp-2,
    -0x1.0000000000001p-2
  },
  { // Entry 639
    0x1.0c152382d7364f09881065f5c8609169p-1,
    0x1.fffffffffffffp-2
  },
  { // Entry 640
    -0x1.0c152382d7364f09881065f5c8609169p-1,
    -0x1.fffffffffffffp-2
  },
  { // Entry 641
    0x1.0c152382d73658465bb32e0f567ad116p-1,
    0x1.0p-1
  },
  { // Entry 642
    -0x1.0c152382d73658465bb32e0f567ad116p-1,
    -0x1.0p-1
  },
  { // Entry 643
    0x1.0c152382d7366ac002f8be4272f9370fp-1,
    0x1.0000000000001p-1
  },
  { // Entry 644
    -0x1.0c152382d7366ac002f8be4272f9370fp-1,
    -0x1.0000000000001p-1
  },
  { // Entry 645
    0x1.921fb50442d18469898c9a6c570d8ef7p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 646
    -0x1.921fb50442d18469898c9a6c570d8ef7p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 647
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p0
  },
  { // Entry 648
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p0
  },
  { // Entry 649
    0x1.921fb54442d14a61a638f674b3b839a2p-1,
    0x1.6a09e667f3bcap-1
  },
  { // Entry 650
    -0x1.921fb54442d14a61a638f674b3b839a2p-1,
    -0x1.6a09e667f3bcap-1
  },
  { // Entry 651
    0x1.921fb54442d16102449f75b07e3839a2p-1,
    0x1.6a09e667f3bcbp-1
  },
  { // Entry 652
    -0x1.921fb54442d16102449f75b07e3839a2p-1,
    -0x1.6a09e667f3bcbp-1
  },
  { // Entry 653
    0x1.921fb54442d177a2e305f4ec49b839a2p-1,
    0x1.6a09e667f3bccp-1
  },
  { // Entry 654
    -0x1.921fb54442d177a2e305f4ec49b839a2p-1,
    -0x1.6a09e667f3bccp-1
  },
  { // Entry 655
    0x1.921fb54442d18e43816c7428163839a2p-1,
    0x1.6a09e667f3bcdp-1
  },
  { // Entry 656
    -0x1.921fb54442d18e43816c7428163839a2p-1,
    -0x1.6a09e667f3bcdp-1
  },
  { // Entry 657
    0x1.921fb54442d1a4e41fd2f363e3b839a2p-1,
    0x1.6a09e667f3bcep-1
  },
  { // Entry 658
    -0x1.921fb54442d1a4e41fd2f363e3b839a2p-1,
    -0x1.6a09e667f3bcep-1
  },
  { // Entry 659
    0x1.0c152382d736310b363f009ee2f7763ap0,
    0x1.bb67ae8584ca8p-1
  },
  { // Entry 660
    -0x1.0c152382d736310b363f009ee2f7763ap0,
    -0x1.bb67ae8584ca8p-1
  },
  { // Entry 661
    0x1.0c152382d736410b363f009edf95f63bp0,
    0x1.bb67ae8584ca9p-1
  },
  { // Entry 662
    -0x1.0c152382d736410b363f009edf95f63bp0,
    -0x1.bb67ae8584ca9p-1
  },
  { // Entry 663
    0x1.0c152382d736510b363f009eddefddebp0,
    0x1.bb67ae8584caap-1
  },
  { // Entry 664
    -0x1.0c152382d736510b363f009eddefddebp0,
    -0x1.bb67ae8584caap-1
  },
  { // Entry 665
    0x1.0c152382d736610b363f009ede052d4ap0,
    0x1.bb67ae8584cabp-1
  },
  { // Entry 666
    -0x1.0c152382d736610b363f009ede052d4ap0,
    -0x1.bb67ae8584cabp-1
  },
  { // Entry 667
    0x1.0c152382d736710b363f009edfd5e457p0,
    0x1.bb67ae8584cacp-1
  },
  { // Entry 668
    -0x1.0c152382d736710b363f009edfd5e457p0,
    -0x1.bb67ae8584cacp-1
  },
  { // Entry 669
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p0
  },
  { // Entry 670
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p0
  },
  { // Entry 671
    0x1.921fb50442d18469898c9a6c570d8ef7p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 672
    -0x1.921fb50442d18469898c9a6c570d8ef7p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 673
    0x1.ce8276c3e139c7eeab836fc4dd4a61bcp-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 674
    -0x1.ce8276c3e139c7eeab836fc4dd4a61bcp-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 675
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 676
    -0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 677
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 678
    -0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 679
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 680
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 681
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 682
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 683
    0x1.p-1073,
    0x1.0p-1073
  },
  { // Entry 684
    -0x1.p-1073,
    -0x1.0p-1073
  },
  { // Entry 685
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 686
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 687
    0.0,
    0.0
  },
  { // Entry 688
    -0.0,
    -0.0
  }
};
```
Response:
My thought process for answering the prompt goes like this:

1. **Understand the Goal:** The main goal is to summarize the functionality of the provided C code snippet, which is a part of Android's `bionic` library. Since it's labelled as part 2 of 4, the expectation is a focused summary of *this specific part*, not the entire file or cos function.

2. **Identify the Core Data:**  The code consists of a large array of `Entry` structs. Each `Entry` contains two `double` values represented in hexadecimal floating-point format. The comments like "// Entry 354" suggest this is a lookup table.

3. **Infer the Purpose:** Given the file path (`bionic/tests/math_data/cos_intel_data.handroid`), the likely purpose of this data is to test the `cos` function in the `bionic` math library. The two `double` values in each entry are highly suggestive of input and expected output for the cosine function. The "intel_data" part might indicate data specific to Intel architectures or generated using Intel's math libraries for comparison.

4. **Formulate a High-Level Summary:** Based on the above, the core functionality is providing test data for the cosine function. The data consists of pairs of input and expected output values.

5. **Address the "Part 2 of 4" Constraint:** Since this is part of a larger data set, it's crucial to highlight that this specific snippet contributes a portion of the total test cases.

6. **Consider Android Context:**  The data directly relates to Android's math library, which is a fundamental part of the system. This data helps ensure the accuracy of the `cos` function on Android devices.

7. **Structure the Summary:** A concise and organized summary is important. I'll use bullet points to clearly present the key functionalities:

    * **Core Function:** Clearly state that it's test data for the `cos` function.
    * **Data Structure:** Describe the data as an array of pairs (input, expected output).
    * **Purpose:** Explain its role in validating the `cos` implementation.
    * **Scope:** Mention that it's a *part* of a larger dataset.
    * **Android Relevance:** Emphasize its connection to Android's math library and ensuring accuracy on devices.

8. **Refine the Language:** Use precise language, such as "lookup table" or "pairs of double-precision floating-point numbers."  Avoid overly technical jargon unless necessary for clarity.

9. **Review and Verify:**  Read through the summary to ensure it accurately reflects the content of the code snippet and addresses the prompt's requirements. Make sure the tone is informative and concise.

By following these steps, I arrived at the summarized functionality provided in the initial good answer. The key was to move from the specific code to its likely purpose within the larger context of Android's math library testing.
好的，这是第2部分，让我们来归纳一下这段代码的功能。

这段代码是 `bionic/tests/math_data/cos_intel_data.handroid` 文件的一部分，主要功能是 **提供了一系列用于测试 `cos` 函数的输入和预期输出数据**。

具体来说，这段代码定义了一个包含多个元素的数组，每个元素都是一个包含两个 `double` 类型数值的结构体。

* **第一个 `double` 值** 代表 `cos` 函数的输入参数。
* **第二个 `double` 值** 代表对于给定输入参数，`cos` 函数的预期输出结果。

这些数据是以十六进制浮点数的形式表示的，例如 `0x1.5a5615acd0dc09bf32e903149634f999p-1`。

**因此，这段代码的核心功能可以归纳为：**

* **提供 `cos` 函数的测试用例数据。** 这些数据用于验证 `bionic` 库中 `cos` 函数的实现是否正确，并且能够处理各种不同的输入值，包括正数、负数、非常大和非常小的数字等。
* **作为自动化测试的一部分。**  这些数据可以被测试框架读取并用于自动化地执行 `cos` 函数的测试，比较实际输出和预期输出，从而确保 `cos` 函数的质量和准确性。
* **可能包含针对特定平台或编译器的测试数据。** 文件名中的 `intel_data` 可能暗示这些数据是针对 Intel 架构或者由 Intel 的数学库生成，用于对比不同实现之间的差异。 `handroid` 则明确表示这是用于 Android 平台的。

**与 Android 功能的关系举例：**

Android 系统和应用中经常需要进行数学运算，例如：

* **图形渲染:** 计算三角函数用于旋转、缩放等图形变换。
* **物理模拟:**  在游戏或科学计算应用中，可能需要计算角度和运动轨迹。
* **信号处理:**  在音频和视频处理中，三角函数是傅里叶变换等算法的基础。

因此，`bionic` 库中 `cos` 函数的正确性和性能直接影响到 Android 系统的稳定性和应用的运行效果。 这段测试数据就是为了确保 `cos` 函数在 Android 上的各种场景下都能正常工作。

**总结:**

这段代码是 `bionic` 库中 `cos` 函数测试数据的一部分，它提供了一系列的输入输出对，用于自动化地验证 `cos` 函数的实现是否正确，这对于保证 Android 系统和依赖该函数的应用的稳定性和准确性至关重要。 它是 Android 平台数学库质量保证的关键组成部分。

Prompt: 
```
这是目录为bionic/tests/math_data/cos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共4部分，请归纳一下它的功能

"""
Entry 354
    0x1.5a5615acd0dc09bf32e903149634f999p-1,
    0x1.a7ep-1
  },
  { // Entry 355
    0x1.5a5615acd0dc09bf32e903149634f999p-1,
    -0x1.a7ep-1
  },
  { // Entry 356
    0x1.766ad27a1de4fb1a5b667216bbe6bf68p-14,
    0x1.a858343863965p119
  },
  { // Entry 357
    0x1.766ad27a1de4fb1a5b667216bbe6bf68p-14,
    -0x1.a858343863965p119
  },
  { // Entry 358
    0x1.6bd4d5be7249325d8680606e6b9ea625p-1,
    0x1.ab190633d88eap3
  },
  { // Entry 359
    0x1.6bd4d5be7249325d8680606e6b9ea625p-1,
    -0x1.ab190633d88eap3
  },
  { // Entry 360
    0x1.ffffffffff4a57e64da87a5af47cfa18p-1,
    0x1.af4bd2f4bd2f0p-21
  },
  { // Entry 361
    0x1.ffffffffff4a57e64da87a5af47cfa18p-1,
    -0x1.af4bd2f4bd2f0p-21
  },
  { // Entry 362
    0x1.7ff2934ad29a74288b886124fead5842p-1,
    0x1.afa70300aee60p72
  },
  { // Entry 363
    0x1.7ff2934ad29a74288b886124fead5842p-1,
    -0x1.afa70300aee60p72
  },
  { // Entry 364
    0x1.ff866aebdce0a7fffffb6074d5199896p-1,
    0x1.b5ab427cffb4cp94
  },
  { // Entry 365
    0x1.ff866aebdce0a7fffffb6074d5199896p-1,
    -0x1.b5ab427cffb4cp94
  },
  { // Entry 366
    -0x1.f54f5227a4e83fbf939b2e96178f121dp-60,
    0x1.b951f1572eba5p23
  },
  { // Entry 367
    -0x1.f54f5227a4e83fbf939b2e96178f121dp-60,
    -0x1.b951f1572eba5p23
  },
  { // Entry 368
    0x1.fffd06d35579c7fe295dad17efbbbe97p-1,
    0x1.b96e5b96e5b91p-8
  },
  { // Entry 369
    0x1.fffd06d35579c7fe295dad17efbbbe97p-1,
    -0x1.b96e5b96e5b91p-8
  },
  { // Entry 370
    -0x1.7c4128e2aff4b2b78e147601fa658af5p-1,
    0x1.ba3b18395d17bp8
  },
  { // Entry 371
    -0x1.7c4128e2aff4b2b78e147601fa658af5p-1,
    -0x1.ba3b18395d17bp8
  },
  { // Entry 372
    -0x1.fffffffffffffffffffffffffefaff9dp-1,
    0x1.bab62ed655019p970
  },
  { // Entry 373
    -0x1.fffffffffffffffffffffffffefaff9dp-1,
    -0x1.bab62ed655019p970
  },
  { // Entry 374
    0x1.ffffff3e534467fffff37e509b7b792ep-1,
    0x1.bd55aa411ab46p-13
  },
  { // Entry 375
    0x1.ffffff3e534467fffff37e509b7b792ep-1,
    -0x1.bd55aa411ab46p-13
  },
  { // Entry 376
    -0x1.7fdb07b9f77e07ffff7207c4628d3f68p-1,
    0x1.bd616d4fe95cdp36
  },
  { // Entry 377
    -0x1.7fdb07b9f77e07ffff7207c4628d3f68p-1,
    -0x1.bd616d4fe95cdp36
  },
  { // Entry 378
    0x1.ffcf4da76222c889718239523341f4b5p-1,
    0x1.beap-6
  },
  { // Entry 379
    0x1.ffcf4da76222c889718239523341f4b5p-1,
    -0x1.beap-6
  },
  { // Entry 380
    -0x1.ddee13357ec6f7fcc9502399fccdc2f0p-1,
    0x1.c11516af585a4p1
  },
  { // Entry 381
    -0x1.ddee13357ec6f7fcc9502399fccdc2f0p-1,
    -0x1.c11516af585a4p1
  },
  { // Entry 382
    0x1.58cccec059da17d3f448a8b2b6e7c0e8p-1,
    0x1.c75e54de4c06ep2
  },
  { // Entry 383
    0x1.58cccec059da17d3f448a8b2b6e7c0e8p-1,
    -0x1.c75e54de4c06ep2
  },
  { // Entry 384
    -0x1.ffffffffffffffffffffffffffc8663ep-1,
    0x1.cb44e86bc192bp648
  },
  { // Entry 385
    -0x1.ffffffffffffffffffffffffffc8663ep-1,
    -0x1.cb44e86bc192bp648
  },
  { // Entry 386
    0x1.ffffffffffffffffffffffffff2198f9p-1,
    0x1.cb44e86bc192bp649
  },
  { // Entry 387
    0x1.ffffffffffffffffffffffffff2198f9p-1,
    -0x1.cb44e86bc192bp649
  },
  { // Entry 388
    -0x1.ca281d7fe44b07ffffd2b7d46ab5d361p-1,
    0x1.cd5a6f8762affp1
  },
  { // Entry 389
    -0x1.ca281d7fe44b07ffffd2b7d46ab5d361p-1,
    -0x1.cd5a6f8762affp1
  },
  { // Entry 390
    0x1.e80ad4fe54c71d4e604ede474cca0b19p-5,
    0x1.d0cb95f02ad77p464
  },
  { // Entry 391
    0x1.e80ad4fe54c71d4e604ede474cca0b19p-5,
    -0x1.d0cb95f02ad77p464
  },
  { // Entry 392
    0x1.0df8eb409efe37fffff925b5de2c80b6p-1,
    0x1.d31bd604903a0p2
  },
  { // Entry 393
    0x1.0df8eb409efe37fffff925b5de2c80b6p-1,
    -0x1.d31bd604903a0p2
  },
  { // Entry 394
    0x1.ff2ae968efe70ea4126849c3832c9cbdp-1,
    0x1.d32f4610180f6p-5
  },
  { // Entry 395
    0x1.ff2ae968efe70ea4126849c3832c9cbdp-1,
    -0x1.d32f4610180f6p-5
  },
  { // Entry 396
    -0x1.cec307a674d3ed2f8df47cf394aa88eap-3,
    0x1.d96e058p488
  },
  { // Entry 397
    -0x1.cec307a674d3ed2f8df47cf394aa88eap-3,
    -0x1.d96e058p488
  },
  { // Entry 398
    -0x1.ac8dbf9cdc95483577560b1814ea8895p-5,
    0x1.db0803c392b4cp15
  },
  { // Entry 399
    -0x1.ac8dbf9cdc95483577560b1814ea8895p-5,
    -0x1.db0803c392b4cp15
  },
  { // Entry 400
    -0x1.ac94870ca631684bd10b658b80cfcd42p-5,
    0x1.db0803c3ff51dp15
  },
  { // Entry 401
    -0x1.ac94870ca631684bd10b658b80cfcd42p-5,
    -0x1.db0803c3ff51dp15
  },
  { // Entry 402
    0x1.ff229073fd8b5e91d60dd095cfde5967p-1,
    0x1.dc4p-5
  },
  { // Entry 403
    0x1.ff229073fd8b5e91d60dd095cfde5967p-1,
    -0x1.dc4p-5
  },
  { // Entry 404
    0x1.ff21e5f975fffe83c2ae1c55a885f12fp-1,
    0x1.dcf73dcf73dccp-5
  },
  { // Entry 405
    0x1.ff21e5f975fffe83c2ae1c55a885f12fp-1,
    -0x1.dcf73dcf73dccp-5
  },
  { // Entry 406
    0x1.2f011326420e5002172db245fd9063e2p-1,
    0x1.dffffffffffffp-1
  },
  { // Entry 407
    0x1.2f011326420e5002172db245fd9063e2p-1,
    -0x1.dffffffffffffp-1
  },
  { // Entry 408
    0x1.f72c8e16dbc78b26afbf346185dccb48p-1,
    0x1.e123691a7c4bep26
  },
  { // Entry 409
    0x1.f72c8e16dbc78b26afbf346185dccb48p-1,
    -0x1.e123691a7c4bep26
  },
  { // Entry 410
    -0x1.4b0c6bb623f57fffff5e458203deef33p-2,
    0x1.e666666f9cf49p0
  },
  { // Entry 411
    -0x1.4b0c6bb623f57fffff5e458203deef33p-2,
    -0x1.e666666f9cf49p0
  },
  { // Entry 412
    0x1.fd74b5587588481884a92e83747f5c4ep-1,
    0x1.e83accfc50b70p995
  },
  { // Entry 413
    0x1.fd74b5587588481884a92e83747f5c4ep-1,
    -0x1.e83accfc50b70p995
  },
  { // Entry 414
    0x1.fff169b6ab7d17f43d59f6cf085accb0p-1,
    0x1.e8ep-7
  },
  { // Entry 415
    0x1.fff169b6ab7d17f43d59f6cf085accb0p-1,
    -0x1.e8ep-7
  },
  { // Entry 416
    0x1.7d39c9f1b0b3c0027a5fc9a76faee83dp-1,
    0x1.eaf5ea5317442p4
  },
  { // Entry 417
    0x1.7d39c9f1b0b3c0027a5fc9a76faee83dp-1,
    -0x1.eaf5ea5317442p4
  },
  { // Entry 418
    0x1.7f13af7081a6741660469fd60255fe49p-1,
    0x1.eb0c2b00b1b83p4
  },
  { // Entry 419
    0x1.7f13af7081a6741660469fd60255fe49p-1,
    -0x1.eb0c2b00b1b83p4
  },
  { // Entry 420
    -0x1.7ad7b88a1fe0f82b6f249c7c56dd8b5ap-1,
    0x1.ebc6b555311c4p15
  },
  { // Entry 421
    -0x1.7ad7b88a1fe0f82b6f249c7c56dd8b5ap-1,
    -0x1.ebc6b555311c4p15
  },
  { // Entry 422
    0x1.b06b2b58a2a23c98b12853415b5c83a1p-5,
    0x1.ef7bdef7bdef2p239
  },
  { // Entry 423
    0x1.b06b2b58a2a23c98b12853415b5c83a1p-5,
    -0x1.ef7bdef7bdef2p239
  },
  { // Entry 424
    0x1.fe6ded53172a6876790d3aab83a656f4p-1,
    0x1.efbbeefbbeef8p15
  },
  { // Entry 425
    0x1.fe6ded53172a6876790d3aab83a656f4p-1,
    -0x1.efbbeefbbeef8p15
  },
  { // Entry 426
    -0x1.fe2bcb87a7e158cffa2fe8d306cc7555p-1,
    0x1.f07c1f07c1ef7p239
  },
  { // Entry 427
    -0x1.fe2bcb87a7e158cffa2fe8d306cc7555p-1,
    -0x1.f07c1f07c1ef7p239
  },
  { // Entry 428
    -0x1.79d08d6b3a88282e0a0da2350464d0abp-1,
    0x1.f0f2b5e060b29p1
  },
  { // Entry 429
    -0x1.79d08d6b3a88282e0a0da2350464d0abp-1,
    -0x1.f0f2b5e060b29p1
  },
  { // Entry 430
    0x1.f0d11d321178d7ff15da48990d5983c2p-1,
    0x1.f40p-3
  },
  { // Entry 431
    0x1.f0d11d321178d7ff15da48990d5983c2p-1,
    -0x1.f40p-3
  },
  { // Entry 432
    0x1.e3ff5b15f723d7f7f7f5bb0dbce54d01p-4,
    0x1.f43d49f947e87p9
  },
  { // Entry 433
    0x1.e3ff5b15f723d7f7f7f5bb0dbce54d01p-4,
    -0x1.f43d49f947e87p9
  },
  { // Entry 434
    -0x1.6636c9f6a87a97f1cbdf708a2f1ad9bap-1,
    0x1.f7fffffffffffp1
  },
  { // Entry 435
    -0x1.6636c9f6a87a97f1cbdf708a2f1ad9bap-1,
    -0x1.f7fffffffffffp1
  },
  { // Entry 436
    0x1.ffc1be33092857ff26220f9981635bc7p-1,
    0x1.f8fffffffffffp-6
  },
  { // Entry 437
    0x1.ffc1be33092857ff26220f9981635bc7p-1,
    -0x1.f8fffffffffffp-6
  },
  { // Entry 438
    0x1.ffc1be33092857fb344affdd93d043a7p-1,
    0x1.f90p-6
  },
  { // Entry 439
    0x1.ffc1be33092857fb344affdd93d043a7p-1,
    -0x1.f90p-6
  },
  { // Entry 440
    -0x1.fffffffcab0d58220669dcfa421ccfa6p-1,
    0x1.fa0236523ce54p344
  },
  { // Entry 441
    -0x1.fffffffcab0d58220669dcfa421ccfa6p-1,
    -0x1.fa0236523ce54p344
  },
  { // Entry 442
    0x1.fc0d98ace2308800000212788a794eacp-1,
    0x1.fceab54d37da0p-4
  },
  { // Entry 443
    0x1.fc0d98ace2308800000212788a794eacp-1,
    -0x1.fceab54d37da0p-4
  },
  { // Entry 444
    -0x1.9589bca128b917fe59692a738c3791c9p-4,
    0x1.fd0072fffffffp2
  },
  { // Entry 445
    -0x1.9589bca128b917fe59692a738c3791c9p-4,
    -0x1.fd0072fffffffp2
  },
  { // Entry 446
    -0x1.4d304b07fc897cf1ade54fe97db7c8bdp-2,
    0x1.fe0f827673422p62
  },
  { // Entry 447
    -0x1.4d304b07fc897cf1ade54fe97db7c8bdp-2,
    -0x1.fe0f827673422p62
  },
  { // Entry 448
    0x1.c1a27ae836f128000000000000504e9bp-1,
    0x1.feb1f7920e248p-2
  },
  { // Entry 449
    0x1.c1a27ae836f128000000000000504e9bp-1,
    -0x1.feb1f7920e248p-2
  },
  { // Entry 450
    -0x1.936b64e955978d15aacfddf5821c6281p-1,
    0x1.feeffffffffc6p995
  },
  { // Entry 451
    -0x1.936b64e955978d15aacfddf5821c6281p-1,
    -0x1.feeffffffffc6p995
  },
  { // Entry 452
    0x1.fff007147ea577fb02130c68b335ef45p-1,
    0x1.ff8ffffffffffp-7
  },
  { // Entry 453
    0x1.fff007147ea577fb02130c68b335ef45p-1,
    -0x1.ff8ffffffffffp-7
  },
  { // Entry 454
    0x1.ffffc01bfe442b09cbec19f68af8fbf8p-1,
    0x1.ff8ffffffffffp-10
  },
  { // Entry 455
    0x1.ffffc01bfe442b09cbec19f68af8fbf8p-1,
    -0x1.ff8ffffffffffp-10
  },
  { // Entry 456
    0x1.7cc9fb75317ae93bf5ddee0e8b9c83cep-1,
    0x1.ff8ffffffffffp870
  },
  { // Entry 457
    0x1.7cc9fb75317ae93bf5ddee0e8b9c83cep-1,
    -0x1.ff8ffffffffffp870
  },
  { // Entry 458
    0x1.d6aea48015588e71983142804227fd84p-1,
    0x1.ffcfff8p19
  },
  { // Entry 459
    0x1.d6aea48015588e71983142804227fd84p-1,
    -0x1.ffcfff8p19
  },
  { // Entry 460
    -0x1.6a9972eee19badf9e34d36b0d1202091p-2,
    0x1.ffcfff8p365
  },
  { // Entry 461
    -0x1.6a9972eee19badf9e34d36b0d1202091p-2,
    -0x1.ffcfff8p365
  },
  { // Entry 462
    -0x1.3aaa15f7544b691a43e1fa1a639bdfc2p-1,
    0x1.ffcffffffff6cp720
  },
  { // Entry 463
    -0x1.3aaa15f7544b691a43e1fa1a639bdfc2p-1,
    -0x1.ffcffffffff6cp720
  },
  { // Entry 464
    0x1.3f164bce055c4c61b74a61f73ca73d3fp-1,
    0x1.ffcfffffffff9p320
  },
  { // Entry 465
    0x1.3f164bce055c4c61b74a61f73ca73d3fp-1,
    -0x1.ffcfffffffff9p320
  },
  { // Entry 466
    0x1.fffff002fff14d566ae8ec9d1edc3e3fp-1,
    0x1.ffcffffffffffp-11
  },
  { // Entry 467
    0x1.fffff002fff14d566ae8ec9d1edc3e3fp-1,
    -0x1.ffcffffffffffp-11
  },
  { // Entry 468
    -0x1.ffffff987f985d67944b867bff4ab857p-1,
    0x1.ffcffffffffffp405
  },
  { // Entry 469
    -0x1.ffffff987f985d67944b867bff4ab857p-1,
    -0x1.ffcffffffffffp405
  },
  { // Entry 470
    -0x1.ffff6235a25edb8c975b485c5c6f41f7p-1,
    0x1.ffcffffffffffp567
  },
  { // Entry 471
    -0x1.ffff6235a25edb8c975b485c5c6f41f7p-1,
    -0x1.ffcffffffffffp567
  },
  { // Entry 472
    0x1.fdf11ae4608b0894bab8786949aa6333p-3,
    0x1.ffefff8ffffffp16
  },
  { // Entry 473
    0x1.fdf11ae4608b0894bab8786949aa6333p-3,
    -0x1.ffefff8ffffffp16
  },
  { // Entry 474
    0x1.8f5525ab4583c064353aaad12c6cce6cp-1,
    0x1.ffeffffffffccp995
  },
  { // Entry 475
    0x1.8f5525ab4583c064353aaad12c6cce6cp-1,
    -0x1.ffeffffffffccp995
  },
  { // Entry 476
    0x1.a0af44a45c0569b72058cc34efd0e32ep-8,
    0x1.ffeffffffffffp77
  },
  { // Entry 477
    0x1.a0af44a45c0569b72058cc34efd0e32ep-8,
    -0x1.ffeffffffffffp77
  },
  { // Entry 478
    -0x1.df7546c31bf8cffef69c4859da055f33p-1,
    0x1.ffeffffffffffp122
  },
  { // Entry 479
    -0x1.df7546c31bf8cffef69c4859da055f33p-1,
    -0x1.ffeffffffffffp122
  },
  { // Entry 480
    -0x1.825a7bea27d5b1a598af6b684eb18478p-1,
    0x1.ffeffffffffffp179
  },
  { // Entry 481
    -0x1.825a7bea27d5b1a598af6b684eb18478p-1,
    -0x1.ffeffffffffffp179
  },
  { // Entry 482
    -0x1.1be2ab2078d547fff09932011fe16456p-1,
    0x1.ffeffffffffffp238
  },
  { // Entry 483
    -0x1.1be2ab2078d547fff09932011fe16456p-1,
    -0x1.ffeffffffffffp238
  },
  { // Entry 484
    -0x1.a4cc5f838f5297e0a7e749cb087c2f14p-7,
    0x1.fff0000002511p492
  },
  { // Entry 485
    -0x1.a4cc5f838f5297e0a7e749cb087c2f14p-7,
    -0x1.fff0000002511p492
  },
  { // Entry 486
    0x1.f16437d6119f89bfa73a2f14f377fd3ep-10,
    0x1.fff1fffffffffp41
  },
  { // Entry 487
    0x1.f16437d6119f89bfa73a2f14f377fd3ep-10,
    -0x1.fff1fffffffffp41
  },
  { // Entry 488
    0x1.898324c2f1cfc596e590b4a80d2508fbp-11,
    0x1.ffffc7fffffffp45
  },
  { // Entry 489
    0x1.898324c2f1cfc596e590b4a80d2508fbp-11,
    -0x1.ffffc7fffffffp45
  },
  { // Entry 490
    0x1.f0154c00688f87fcc96f14c8efb5914fp-1,
    0x1.ffffdf1ffffffp-3
  },
  { // Entry 491
    0x1.f0154c00688f87fcc96f14c8efb5914fp-1,
    -0x1.ffffdf1ffffffp-3
  },
  { // Entry 492
    0x1.ffc00157126a7d98216491df73d97cd3p-1,
    0x1.fffff8fffffffp-6
  },
  { // Entry 493
    0x1.ffc00157126a7d98216491df73d97cd3p-1,
    -0x1.fffff8fffffffp-6
  },
  { // Entry 494
    -0x1.e0d9f0f38c73f0069739e9de65191416p-2,
    0x1.fffffbfffffffp968
  },
  { // Entry 495
    -0x1.e0d9f0f38c73f0069739e9de65191416p-2,
    -0x1.fffffbfffffffp968
  },
  { // Entry 496
    0x1.fff4699dd560b5dbb88a029337b9ab86p-1,
    0x1.fffffcfffffffp40
  },
  { // Entry 497
    0x1.fff4699dd560b5dbb88a029337b9ab86p-1,
    -0x1.fffffcfffffffp40
  },
  { // Entry 498
    0x1.ff0015559f228802433732ae11942945p-1,
    0x1.ffffff0000040p-5
  },
  { // Entry 499
    0x1.ff0015559f228802433732ae11942945p-1,
    -0x1.ffffff0000040p-5
  },
  { // Entry 500
    -0x1.9c6951cccd39bf60d47db80be6fce34fp-2,
    0x1.ffffff8p119
  },
  { // Entry 501
    -0x1.9c6951cccd39bf60d47db80be6fce34fp-2,
    -0x1.ffffff8p119
  },
  { // Entry 502
    -0x1.f2c2263590034ec62522d45d2eeca285p-1,
    0x1.ffffff8p192
  },
  { // Entry 503
    -0x1.f2c2263590034ec62522d45d2eeca285p-1,
    -0x1.ffffff8p192
  },
  { // Entry 504
    0x1.c7884d6cfb5511a6b5111077fd0b1b72p-1,
    0x1.ffffff8p543
  },
  { // Entry 505
    0x1.c7884d6cfb5511a6b5111077fd0b1b72p-1,
    -0x1.ffffff8p543
  },
  { // Entry 506
    0x1.e66c79e776a1eff6b68f2d01289e08e8p-2,
    0x1.ffffffc3fffffp500
  },
  { // Entry 507
    0x1.e66c79e776a1eff6b68f2d01289e08e8p-2,
    -0x1.ffffffc3fffffp500
  },
  { // Entry 508
    0x1.c7c9a9c57c0b2009f18a6c2c07b52ea2p-3,
    0x1.ffffffe1fffffp700
  },
  { // Entry 509
    0x1.c7c9a9c57c0b2009f18a6c2c07b52ea2p-3,
    -0x1.ffffffe1fffffp700
  },
  { // Entry 510
    0x1.7bb28daf5f9ad3608dda8a16ea235cb4p-1,
    0x1.ffffffff0f0ffp400
  },
  { // Entry 511
    0x1.7bb28daf5f9ad3608dda8a16ea235cb4p-1,
    -0x1.ffffffff0f0ffp400
  },
  { // Entry 512
    0x1.fc015527d8bb37806e4976dcf7a7c98cp-1,
    0x1.ffffffff3ffffp-4
  },
  { // Entry 513
    0x1.fc015527d8bb37806e4976dcf7a7c98cp-1,
    -0x1.ffffffff3ffffp-4
  },
  { // Entry 514
    -0x1.ea5257eb66e3bffee900cd4447404c16p-1,
    0x1.ffffffff8ffffp3
  },
  { // Entry 515
    -0x1.ea5257eb66e3bffee900cd4447404c16p-1,
    -0x1.ffffffff8ffffp3
  },
  { // Entry 516
    -0x1.4eaa606dbef968000267b0375ded6872p-1,
    0x1.fffffffffbcffp1
  },
  { // Entry 517
    -0x1.4eaa606dbef968000267b0375ded6872p-1,
    -0x1.fffffffffbcffp1
  },
  { // Entry 518
    -0x1.fc9cd6b5f009482b0d5582e1c6cdf738p-1,
    0x1.fffffffffe0b5p720
  },
  { // Entry 519
    -0x1.fc9cd6b5f009482b0d5582e1c6cdf738p-1,
    -0x1.fffffffffe0b5p720
  },
  { // Entry 520
    0x1.e96ac045dd138d25741cb879b92afa48p-3,
    0x1.fffffffffe7ffp41
  },
  { // Entry 521
    0x1.e96ac045dd138d25741cb879b92afa48p-3,
    -0x1.fffffffffe7ffp41
  },
  { // Entry 522
    -0x1.fcaf39cfb94d48195d2b26060b30f822p-1,
    0x1.fffffffffee09p720
  },
  { // Entry 523
    -0x1.fcaf39cfb94d48195d2b26060b30f822p-1,
    -0x1.fffffffffee09p720
  },
  { // Entry 524
    0x1.8432232a6d1daa6ac8a94c0021e60d50p-1,
    0x1.ffffffffffdffp40
  },
  { // Entry 525
    0x1.8432232a6d1daa6ac8a94c0021e60d50p-1,
    -0x1.ffffffffffdffp40
  },
  { // Entry 526
    0x1.9e375143139d9a37b354ea33dd625cd6p-6,
    0x1.ffffffffffeffp41
  },
  { // Entry 527
    0x1.9e375143139d9a37b354ea33dd625cd6p-6,
    -0x1.ffffffffffeffp41
  },
  { // Entry 528
    0x1.fffc0001555528000049b10c26a1f539p-1,
    0x1.fffffffffff4ap-8
  },
  { // Entry 529
    0x1.fffc0001555528000049b10c26a1f539p-1,
    -0x1.fffffffffff4ap-8
  },
  { // Entry 530
    0x1.463a895c4ea5ce4e56e8f578388eed3ap-1,
    0x1.fffffffffff78p920
  },
  { // Entry 531
    0x1.463a895c4ea5ce4e56e8f578388eed3ap-1,
    -0x1.fffffffffff78p920
  },
  { // Entry 532
    0x1.3c1a48635cf380c8158d934c4d0dd87cp-1,
    0x1.fffffffffffd5p995
  },
  { // Entry 533
    0x1.3c1a48635cf380c8158d934c4d0dd87cp-1,
    -0x1.fffffffffffd5p995
  },
  { // Entry 534
    0x1.91c4e0708bd486217f5fc230f0416220p-1,
    0x1.fffffffffffe8p720
  },
  { // Entry 535
    0x1.91c4e0708bd486217f5fc230f0416220p-1,
    -0x1.fffffffffffe8p720
  },
  { // Entry 536
    -0x1.3e15cb849b5ea87bcc583f6344cbcc40p-1,
    0x1.fffffffffffebp920
  },
  { // Entry 537
    -0x1.3e15cb849b5ea87bcc583f6344cbcc40p-1,
    -0x1.fffffffffffebp920
  },
  { // Entry 538
    -0x1.816808349b80dd3c22cbe80b4c171d1fp-1,
    0x1.ffffffffffff1p245
  },
  { // Entry 539
    -0x1.816808349b80dd3c22cbe80b4c171d1fp-1,
    -0x1.ffffffffffff1p245
  },
  { // Entry 540
    0x1.4699c814c5f075bb0ed9472dfecc50a9p-1,
    0x1.ffffffffffff4p845
  },
  { // Entry 541
    0x1.4699c814c5f075bb0ed9472dfecc50a9p-1,
    -0x1.ffffffffffff4p845
  },
  { // Entry 542
    -0x1.815e92b7a2a019e74650a859968e0f29p-1,
    0x1.ffffffffffff4p1020
  },
  { // Entry 543
    -0x1.815e92b7a2a019e74650a859968e0f29p-1,
    -0x1.ffffffffffff4p1020
  },
  { // Entry 544
    -0x1.3e8d028153201ed272fc9549725fcb3fp-10,
    0x1.ffffffffffffcp45
  },
  { // Entry 545
    -0x1.3e8d028153201ed272fc9549725fcb3fp-10,
    -0x1.ffffffffffffcp45
  },
  { // Entry 546
    0x1.7d6765714c78532d3eb0f2a73c5d6126p-1,
    0x1.ffffffffffffep105
  },
  { // Entry 547
    0x1.7d6765714c78532d3eb0f2a73c5d6126p-1,
    -0x1.ffffffffffffep105
  },
  { // Entry 548
    -0x1.f869fb14d2568d67c37c90b0a038b240p-3,
    0x1.ffffffffffffep480
  },
  { // Entry 549
    -0x1.f869fb14d2568d67c37c90b0a038b240p-3,
    -0x1.ffffffffffffep480
  },
  { // Entry 550
    -0x1.80a75b369d3c3fd15b6060c6fb98f2d6p-1,
    0x1.ffffffffffffep970
  },
  { // Entry 551
    -0x1.80a75b369d3c3fd15b6060c6fb98f2d6p-1,
    -0x1.ffffffffffffep970
  },
  { // Entry 552
    -0x1.9dba69e853bd77fd883be3bb1171df55p-4,
    0x1.0000000000001p42
  },
  { // Entry 553
    -0x1.9dba69e853bd77fd883be3bb1171df55p-4,
    -0x1.0000000000001p42
  },
  { // Entry 554
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 555
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 556
    0x1.p0,
    -0.0
  },
  { // Entry 557
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 558
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 559
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022
  },
  { // Entry 560
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p-1022
  },
  { // Entry 561
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022
  },
  { // Entry 562
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1022
  },
  { // Entry 563
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 564
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep-1023
  },
  { // Entry 565
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep-1023
  },
  { // Entry 566
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 567
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1022
  },
  { // Entry 568
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022
  },
  { // Entry 569
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p-1022
  },
  { // Entry 570
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022
  },
  { // Entry 571
    0x1.ffffff5c28f5cb4c5272061281211120p-1,
    0x1.999999999999ap-13
  },
  { // Entry 572
    0x1.ffffff5c28f5cb4c5272061281211120p-1,
    -0x1.999999999999ap-13
  },
  { // Entry 573
    0x1.fffffd70a3d7960cd5695a06fdb80e74p-1,
    0x1.999999999999ap-12
  },
  { // Entry 574
    0x1.fffffd70a3d7960cd5695a06fdb80e74p-1,
    -0x1.999999999999ap-12
  },
  { // Entry 575
    0x1.fffffa3d70a69ad42b39d8696632f856p-1,
    0x1.3333333333334p-11
  },
  { // Entry 576
    0x1.fffffa3d70a69ad42b39d8696632f856p-1,
    -0x1.3333333333334p-11
  },
  { // Entry 577
    0x1.fffff5c28f64e5ec0da0a4f7f4388052p-1,
    0x1.999999999999ap-11
  },
  { // Entry 578
    0x1.fffff5c28f64e5ec0da0a4f7f4388052p-1,
    -0x1.999999999999ap-11
  },
  { // Entry 579
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    0x1.0p-10
  },
  { // Entry 580
    0x1.fffff0000015555549f49f4d34d34ca0p-1,
    -0x1.0p-10
  },
  { // Entry 581
    0x1.ffffe8f5c2bb98c7c103d2ff79f15d6ap-1,
    0x1.3333333333333p-10
  },
  { // Entry 582
    0x1.ffffe8f5c2bb98c7c103d2ff79f15d6ap-1,
    -0x1.3333333333333p-10
  },
  { // Entry 583
    0x1.ffffe0a3d75c31b26451166d6f398abdp-1,
    0x1.6666666666666p-10
  },
  { // Entry 584
    0x1.ffffe0a3d75c31b26451166d6f398abdp-1,
    -0x1.6666666666666p-10
  },
  { // Entry 585
    0x1.ffffd70a3dfc733b3331d8382b1e9df5p-1,
    0x1.9999999999999p-10
  },
  { // Entry 586
    0x1.ffffd70a3dfc733b3331d8382b1e9df5p-1,
    -0x1.9999999999999p-10
  },
  { // Entry 587
    0x1.ffffcc28f6a2823f3765b50659ecb0e2p-1,
    0x1.cccccccccccccp-10
  },
  { // Entry 588
    0x1.ffffcc28f6a2823f3765b50659ecb0e2p-1,
    -0x1.cccccccccccccp-10
  },
  { // Entry 589
    0x1.fffbcc2a6e86fef7d2af1580bd8e6699p-1,
    0x1.0666666666666p-7
  },
  { // Entry 590
    0x1.fffbcc2a6e86fef7d2af1580bd8e6699p-1,
    -0x1.0666666666666p-7
  },
  { // Entry 591
    0x1.fff30a4b6fcc1405e18fbf7335d2f789p-1,
    0x1.cccccccccccccp-7
  },
  { // Entry 592
    0x1.fff30a4b6fcc1405e18fbf7335d2f789p-1,
    -0x1.cccccccccccccp-7
  },
  { // Entry 593
    0x1.ffe57a780f38c0db37051fa8c8d60fbcp-1,
    0x1.4999999999999p-6
  },
  { // Entry 594
    0x1.ffe57a780f38c0db37051fa8c8d60fbcp-1,
    -0x1.4999999999999p-6
  },
  { // Entry 595
    0x1.ffd31cd0e1d62c05d2cded21add8bd33p-1,
    0x1.accccccccccccp-6
  },
  { // Entry 596
    0x1.ffd31cd0e1d62c05d2cded21add8bd33p-1,
    -0x1.accccccccccccp-6
  },
  { // Entry 597
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    0x1.080p-5
  },
  { // Entry 598
    0x1.ffbbf18207542ef81390d73c3ba89c1ap-1,
    -0x1.080p-5
  },
  { // Entry 599
    0x1.ff9ff8c3299f54457bbaf8c12173b46bp-1,
    0x1.399999999999ap-5
  },
  { // Entry 600
    0x1.ff9ff8c3299f54457bbaf8c12173b46bp-1,
    -0x1.399999999999ap-5
  },
  { // Entry 601
    0x1.ff7f32d77c5b1c42f1660c9b6f2ef64fp-1,
    0x1.6b33333333334p-5
  },
  { // Entry 602
    0x1.ff7f32d77c5b1c42f1660c9b6f2ef64fp-1,
    -0x1.6b33333333334p-5
  },
  { // Entry 603
    0x1.ff59a00dbc40896bb5e4ac8ad293afb4p-1,
    0x1.9cccccccccccep-5
  },
  { // Entry 604
    0x1.ff59a00dbc40896bb5e4ac8ad293afb4p-1,
    -0x1.9cccccccccccep-5
  },
  { // Entry 605
    0x1.ff2f40c02e60f61d6dcfc39b6c2be087p-1,
    0x1.ce66666666666p-5
  },
  { // Entry 606
    0x1.ff2f40c02e60f61d6dcfc39b6c2be087p-1,
    -0x1.ce66666666666p-5
  },
  { // Entry 607
    0x1.8ca46c7d8975e57a1484f05c3738d83bp-1,
    0x1.5e7fc4369bdadp-1
  },
  { // Entry 608
    0x1.8ca46c7d8975e57a1484f05c3738d83bp-1,
    -0x1.5e7fc4369bdadp-1
  },
  { // Entry 609
    0x1.0b5d3802fc7991140168f294eedd7904p-2,
    0x1.4e7fc4369bdadp0
  },
  { // Entry 610
    0x1.0b5d3802fc7991140168f294eedd7904p-2,
    -0x1.4e7fc4369bdadp0
  },
  { // Entry 611
    -0x1.66b96f53323af1d7e31a7162ab18a75bp-2,
    0x1.edbfa651e9c84p0
  },
  { // Entry 612
    -0x1.66b96f53323af1d7e31a7162ab18a75bp-2,
    -0x1.edbfa651e9c84p0
  },
  { // Entry 613
    -0x1.a93554888c32fa57f22a9529a320c1cbp-1,
    0x1.467fc4369bdadp1
  },
  { // Entry 614
    -0x1.a93554888c32fa57f22a9529a320c1cbp-1,
    -0x1.467fc4369bdadp1
  },
  { // Entry 615
    -0x1.ffc00155527d2b9fda2ae89396e09727p-1,
    0x1.961fb54442d18p1
  },
  { // Entry 616
    -0x1.ffc00155527d2b9fda2ae89396e09727p-1,
    -0x1.961fb54442d18p1
  },
  { // Entry 617
    -0x1.96907c5c7c25b88e34addff1fbef66e4p-1,
    0x1.e5bfa651e9c83p1
  },
  { // Entry 618
    -0x1.96907c5c7c25b88e34addff1fbef66e4p-1,
    -0x1.e5bfa651e9c83p1
  },
  { // Entry 619
    -0x1.2a1e5a50f948cd487c5309682b110a53p-2,
    0x1.1aafcbafc85f7p2
  },
  { // Entry 620
    -0x1.2a1e5a50f948cd487c5309682b110a53p-2,
    -0x1.1aafcbafc85f7p2
  },
  { // Entry 621
    0x1.4894f695dc56bce8b273e5524f181264p-2,
    0x1.427fc4369bdadp2
  },
  { // Entry 622
    0x1.4894f695dc56bce8b273e5524f181264p-2,
    -0x1.427fc4369bdadp2
  },
  { // Entry 623
    0x1.a016ea3a692ce0c321b77f168de39122p-1,
    0x1.6a4fbcbd6f562p2
  },
  { // Entry 624
    0x1.a016ea3a692ce0c321b77f168de39122p-1,
    -0x1.6a4fbcbd6f562p2
  },
  { // Entry 625
    0x1.a30a69f5537ebc22f0870c2bd26ef284p-1,
    0x1.6af2eff0a2896p2
  },
  { // Entry 626
    0x1.a30a69f5537ebc22f0870c2bd26ef284p-1,
    -0x1.6af2eff0a2896p2
  },
  { // Entry 627
    0x1.5bd62e8b04ad5915e66242349b756e11p-2,
    0x1.43c62a9d02414p2
  },
  { // Entry 628
    0x1.5bd62e8b04ad5915e66242349b756e11p-2,
    -0x1.43c62a9d02414p2
  },
  { // Entry 629
    -0x1.0cb71f671e63410966e78d2009c0616fp-2,
    0x1.1c99654961f92p2
  },
  { // Entry 630
    -0x1.0cb71f671e63410966e78d2009c0616fp-2,
    -0x1.1c99654961f92p2
  },
  { // Entry 631
    -0x1.89d86aa8521c11b74f8b1954c08f9b36p-1,
    0x1.ead93feb8361fp1
  },
  { // Entry 632
    -0x1.89d86aa8521c11b74f8b1954c08f9b36p-1,
    -0x1.ead93feb8361fp1
  },
  { // Entry 633
    -0x1.fe51ac554a16ad8194f181085f8a17f2p-1,
    0x1.9c7fb54442d1ap1
  },
  { // Entry 634
    -0x1.fe51ac554a16ad8194f181085f8a17f2p-1,
    -0x1.9c7fb54442d1ap1
  },
  { // Entry 635
    -0x1.b97c04d08bc5d765b341a22b2c720b6fp-1,
    0x1.4e262a9d02415p1
  },
  { // Entry 636
    -0x1.b97c04d08bc5d765b341a22b2c720b6fp-1,
    -0x1.4e262a9d02415p1
  },
  { // Entry 637
    -0x1.a8ac8a3e58f6ca952390299d2e8b187fp-2,
    0x1.ff993feb83620p0
  },
  { // Entry 638
    -0x1.a8ac8a3e58f6ca952390299d2e8b187fp-2,
    -0x1.ff993feb83620p0
  },
  { // Entry 639
    0x1.77a8b9b3d254a9e39d02b3eb3e2390e7p-3,
    0x1.62e62a9d02416p0
  },
  { // Entry 640
    0x1.77a8b9b3d254a9e39d02b3eb3e2390e7p-3,
    -0x1.62e62a9d02416p0
  },
  { // Entry 641
    0x1.6e1061205dd79051c112d30a05097c61p-1,
    0x1.8c662a9d02419p-1
  },
  { // Entry 642
    0x1.6e1061205dd79051c112d30a05097c61p-1,
    -0x1.8c662a9d02419p-1
  },
  { // Entry 643
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 644
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 645
    -0x1.e6669a270c36d4879b428ddba96cd87bp-7,
    -0x1.95ec8b9e03d54p0
  },
  { // Entry 646
    -0x1.e6669a270c36d4879b428ddba96cd87bp-7,
    0x1.95ec8b9e03d54p0
  },
  { // Entry 647
    0x1.ddd1ec25e209f1bbf7e17ef6c8450cd7p-5,
    -0x1.832efa2a435a9p0
  },
  { // Entry 648
    0x1.ddd1ec25e209f1bbf7e17ef6c8450cd7p-5,
    0x1.832efa2a435a9p0
  },
  { // Entry 649
    0x1.0cab9115640d993082a7343bb5affea2p-3,
    -0x1.707168b682dfep0
  },
  { // Entry 650
    0x1.0cab9115640d993082a7343bb5affea2p-3,
    0x1.707168b682dfep0
  },
  { // Entry 651
    0x1.a0723a95492edee5dc98394e45f96d88p-3,
    -0x1.5db3d742c2653p0
  },
  { // Entry 652
    0x1.a0723a95492edee5dc98394e45f96d88p-3,
    0x1.5db3d742c2653p0
  },
  { // Entry 653
    0x1.18fee96a1a585928a94cda7e3d916fe1p-2,
    -0x1.4af645cf01ea8p0
  },
  { // Entry 654
    0x1.18fee96a1a585928a94cda7e3d916fe1p-2,
    0x1.4af645cf01ea8p0
  },
  { // Entry 655
    0x1.6043621b13be2ff07085f8278598e566p-2,
    -0x1.3838b45b416fdp0
  },
  { // Entry 656
    0x1.6043621b13be2ff07085f8278598e566p-2,
    0x1.3838b45b416fdp0
  },
  { // Entry 657
    0x1.a5a4ccf40d9d9ba97faa4e23ecce9e3ap-2,
    -0x1.257b22e780f52p0
  },
  { // Entry 658
    0x1.a5a4ccf40d9d9ba97faa4e23ecce9e3ap-2,
    0x1.257b22e780f52p0
  },
  { // Entry 659
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    -0x1.12bd9173c07abp0
  },
  { // Entry 660
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    0x1.12bd9173c07abp0
  },
  { // Entry 661
    0x1.26976a6c4e0f86633327f1ceecb508aep-1,
    -0x1.ea5c3ed5b3850p-1
  },
  { // Entry 662
    0x1.26976a6c4e0f86633327f1ceecb508aep-1,
    0x1.ea5c3ed5b3850p-1
  },
  { // Entry 663
    0x1.3805a1882009f2843da808e959f17861p-1,
    -0x1.d4b87dab670a0p-1
  },
  { // Entry 664
    0x1.3805a1882009f2843da808e959f17861p-1,
    0x1.d4b87dab670a0p-1
  },
  { // Entry 665
    0x1.48e52e0a65bcb3cd46455c4d2338bdf2p-1,
    -0x1.bf14bc811a8f0p-1
  },
  { // Entry 666
    0x1.48e52e0a65bcb3cd46455c4d2338bdf2p-1,
    0x1.bf14bc811a8f0p-1
  },
  { // Entry 667
    0x1.592e58ea0a9eec0b357eb4e9a83b0ea5p-1,
    -0x1.a970fb56ce140p-1
  },
  { // Entry 668
    0x1.592e58ea0a9eec0b357eb4e9a83b0ea5p-1,
    0x1.a970fb56ce140p-1
  },
  { // Entry 669
    0x1.68d9afe052d1f0e9324ae876961bcdb1p-1,
    -0x1.93cd3a2c81990p-1
  },
  { // Entry 670
    0x1.68d9afe052d1f0e9324ae876961bcdb1p-1,
    0x1.93cd3a2c81990p-1
  },
  { // Entry 671
    0x1.77e008d0775e744eb16a2c4ec7184c43p-1,
    -0x1.7e297902351e0p-1
  },
  { // Entry 672
    0x1.77e008d0775e744eb16a2c4ec7184c43p-1,
    0x1.7e297902351e0p-1
  },
  { // Entry 673
    0x1.863a850e438fe029302aba0f5f127616p-1,
    -0x1.6885b7d7e8a30p-1
  },
  { // Entry 674
    0x1.863a850e438fe029302aba0f5f127616p-1,
    0x1.6885b7d7e8a30p-1
  },
  { // Entry 675
    0x1.93e2948233fce814439ed51fd2548920p-1,
    -0x1.52e1f6ad9c280p-1
  },
  { // Entry 676
    0x1.93e2948233fce814439ed51fd2548920p-1,
    0x1.52e1f6ad9c280p-1
  },
  { // Entry 677
    0x1.a0d1f8a9a791d4b5694ca68a42fe6c9bp-1,
    -0x1.3d3e35834fad0p-1
  },
  { // Entry 678
    0x1.a0d1f8a9a791d4b5694ca68a42fe6c9bp-1,
    0x1.3d3e35834fad0p-1
  },
  { // Entry 679
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 680
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    0x1.0a0b02501c799p-1
  },
  { // Entry 681
    0x1.ca59c6fa3d9ce238a227393b6b075bc5p-1,
    -0x1.d8f7208e6b82cp-2
  },
  { // Entry 682
    0x1.ca59c6fa3d9ce238a227393b6b075bc5p-1,
    0x1.d8f7208e6b82cp-2
  },
  { // Entry 683
    0x1.d6c0b125791cffce83e32564712b78c6p-1,
    -0x1.9dd83c7c9e126p-2
  },
  { // Entry 684
    0x1.d6c0b125791cffce83e32564712b78c6p-1,
    0x1.9dd83c7c9e126p-2
  },
  { // Entry 685
    0x1.e1960261829858391645bbe12019e58ap-1,
    -0x1.62b9586ad0a20p-2
  },
  { // Entry 686
    0x1.e1960261829858391645bbe12019e58ap-1,
    0x1.62b9586ad0a20p-2
  },
  { // Entry 687
    0x1.ead07cc6356964e27a1036d2f8b158f7p-1,
    -0x1.279a74590331ap-2
  },
  { // Entry 688
    0x1.ead07cc6356964e27a1036d2f8b158f7p-1,
    0x1.279a74590331ap-2
  },
  { // Entry 689
    0x1.f26840e7b2188f7a0cc661a0ede3728bp-1,
    -0x1.d8f7208e6b829p-3
  },
  { // Entry 690
    0x1.f26840e7b2188f7a0cc661a0ede3728bp-1,
    0x1.d8f7208e6b829p-3
  },
  { // Entry 691
    0x1.f856d48db797dec0b79e1353409dc3f2p-1,
    -0x1.62b9586ad0a1ep-3
  },
  { // Entry 692
    0x1.f856d48db797dec0b79e1353409dc3f2p-1,
    0x1.62b9586ad0a1ep-3
  },
  { // Entry 693
    0x1.fc97283a424797215f8a8d1967736c9bp-1,
    -0x1.d8f7208e6b826p-4
  },
  { // Entry 694
    0x1.fc97283a424797215f8a8d1967736c9bp-1,
    0x1.d8f7208e6b826p-4
  },
  { // Entry 695
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 696
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 697
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 698
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 699
    0x1.fc97283a424795847294654a1d8a08edp-1,
    0x1.d8f7208e6b82dp-4
  },
  { // Entry 700
    0x1.fc97283a424795847294654a1d8a08edp-1,
    -0x1.d8f7208e6b82dp-4
  },
  { // Entry 701
    0x1.f856d48db797dbfecfa8b4cd3be44027p-1,
    0x1.62b9586ad0a22p-3
  },
  { // Entry 702
    0x1.f856d48db797dbfecfa8b4cd3be44027p-1,
    -0x1.62b9586ad0a22p-3
  },
  { // Entry 703
    0x1.f26840e7b2188bd0814e3dfc7f6f3f87p-1,
    0x1.d8f7208e6b82dp-3
  },
  { // Entry 704
    0x1.f26840e7b2188bd0814e3dfc7f6f3f87p-1,
    -0x1.d8f7208e6b82dp-3
  },
  { // Entry 705
    0x1.ead07cc6356960546ae634ef62621fb2p-1,
    0x1.279a74590331cp-2
  },
  { // Entry 706
    0x1.ead07cc6356960546ae634ef62621fb2p-1,
    -0x1.279a74590331cp-2
  },
  { // Entry 707
    0x1.e1960261829852ca662ca27d518c2fa9p-1,
    0x1.62b9586ad0a22p-2
  },
  { // Entry 708
    0x1.e1960261829852ca662ca27d518c2fa9p-1,
    -0x1.62b9586ad0a22p-2
  },
  { // Entry 709
    0x1.d6c0b125791cf983d53efaa7d45e291ep-1,
    0x1.9dd83c7c9e128p-2
  },
  { // Entry 710
    0x1.d6c0b125
"""


```
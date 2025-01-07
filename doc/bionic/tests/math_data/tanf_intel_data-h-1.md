Response:
The user has provided a snippet of a C source code file named `tanf_intel_data.handroid` located in the `bionic/tests/math_data/` directory. This file seems to contain test data for the `tanf` function, likely optimized for Intel architectures. The request asks for a summary of its functionality based on the provided snippet, considering its relation to Android's functionalities.

**Breakdown of the request:**

1. **List functionality:**  Identify the purpose of the code snippet.
2. **Relationship to Android:** Explain how this code relates to the broader Android system.
3. **libc function explanation:** Detail how libc functions (if any are directly present in the snippet) are implemented.
4. **Dynamic linker details:** If dynamic linking is involved, explain the process, provide a sample `so` layout, and describe the linking steps.
5. **Logical reasoning with examples:** If the code performs calculations or logical operations, provide input/output examples.
6. **Common usage errors:** Discuss potential mistakes developers might make when using related functions.
7. **Android framework/NDK path:** Explain how the execution reaches this code from the Android framework or NDK.
8. **Frida hook example:** Provide a Frida script to debug related steps.
9. **Summarize functionality (for Part 2):** Provide a concise summary based on the provided code snippet.

**Analysis of the provided snippet:**

The snippet consists of a large array of structures (or similar data structures). Each element in the array appears to have two floating-point numbers. The hexadecimal representation (e.g., `0x1.b5f3d61c54ee4f6585e9bff489c00182p-2`) strongly suggests these are floating-point values in IEEE 754 format. The names like `tanf_intel_data` and the location within `bionic/tests/math_data` strongly suggest these are test input/output pairs for the `tanf` function (tangent of a float). The first value in each pair is likely the input to `tanf`, and the second is the expected output. The `// Entry NNN` comments indicate the index of each test case.

**High-level plan:**

For this specific Part 2, the focus should be on summarizing the observed functionality. Since the provided code is purely data, the summary will primarily revolve around its role in testing the `tanf` function. The more detailed explanations of libc functions, dynamic linking, etc., will likely be covered in other parts.

**Drafting the summary:**

The code snippet defines a set of test cases for the `tanf` function. Each test case provides an input value and its corresponding expected output value. This data is used to verify the correctness and accuracy of the `tanf` implementation in the Android Bionic library, particularly when optimized for Intel architectures.
好的，根据您提供的代码片段，这是 `bionic/tests/math_data/tanf_intel_data.handroid` 文件的一部分，它主要的功能是：

**核心功能：`tanf` 函数的测试数据**

这个代码片段定义了一个包含大量条目的数组，每个条目包含两个 `double` 类型的浮点数。 这些数据是用来测试 `tanf` 函数（单精度浮点数的正切函数）在 Intel 架构上的实现是否正确。

**更详细的解释:**

* **测试用例集合:**  该文件本质上是一个针对 `tanf` 函数的测试用例集合。每个花括号 `{}` 内部的两个浮点数构成一个独立的测试用例。
* **输入与期望输出:**  通常情况下，每个测试用例的第一个浮点数是 `tanf` 函数的输入值，而第二个浮点数是该输入值对应的预期输出值。
* **十六进制浮点数表示:** 代码中使用十六进制浮点数表示（例如 `0x1.b5f3d61c54ee4f6585e9bff489c00182p-2`），这是一种精确表示浮点数的方式，可以避免十进制表示带来的精度损失。 `p-2` 表示乘以 2 的 -2 次方。
* **覆盖各种输入:**  从数据可以看出，测试用例覆盖了各种不同的输入值，包括正数、负数、非常接近零的数、以及较大或较小的数。这有助于确保 `tanf` 函数在各种输入条件下都能正常工作并返回正确的结果。
* **针对 Intel 架构:** 文件名中的 `intel` 表明这些测试数据可能是针对 Intel 处理器架构优化的 `tanf` 实现进行测试的。不同的处理器架构可能在浮点数运算的精度和性能上有所差异，因此需要针对特定架构进行测试。

**与 Android 功能的关系 (举例说明):**

* **libm 的一部分:**  `tanf` 函数是 Android Bionic Libc 中的数学库 (libm) 的一部分。应用程序通过调用 libm 提供的函数来进行各种数学运算。
* **图形渲染:**  `tanf` 函数常用于图形渲染和游戏开发中，例如计算角度和进行坐标变换。Android 应用程序如果使用了 OpenGL ES 或 Vulkan 等图形 API，底层就会依赖 libm 中的 `tanf` 函数。
* **科学计算和工程应用:**  一些 Android 应用程序可能用于科学计算、工程模拟等领域，这些应用也会频繁使用 `tanf` 等三角函数。

**总结该代码片段的功能:**

总而言之，这个代码片段是 `bionic/tests/math_data/tanf_intel_data.handroid` 文件的一部分，其核心功能是 **提供了一系列用于测试 Android Bionic Libc 中 `tanf` 函数在 Intel 架构上实现的输入和期望输出值**。这些测试数据对于验证 `tanf` 函数的正确性和精度至关重要，确保 Android 系统上运行的应用程序能够获得准确的三角函数计算结果。

Prompt: 
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
这是第2部分，共3部分，请归纳一下它的功能

"""
f3d61c54ee4f6585e9bff489c00182p-2,
    -0x1.9dd83cp-2
  },
  { // Entry 388
    0x1.b5f3d61c54ee4f6585e9bff489c00182p-2,
    0x1.9dd83cp-2
  },
  { // Entry 389
    -0x1.71a0f907c661daf4903b7bbc015c5c14p-2,
    -0x1.62b958p-2
  },
  { // Entry 390
    0x1.71a0f907c661daf4903b7bbc015c5c14p-2,
    0x1.62b958p-2
  },
  { // Entry 391
    -0x1.30190941e699fdb2115a9ef6bf82d455p-2,
    -0x1.279a74p-2
  },
  { // Entry 392
    0x1.30190941e699fdb2115a9ef6bf82d455p-2,
    0x1.279a74p-2
  },
  { // Entry 393
    -0x1.e18e93867caf67efcaa19821898d50cap-3,
    -0x1.d8f720p-3
  },
  { // Entry 394
    0x1.e18e93867caf67efcaa19821898d50cap-3,
    0x1.d8f720p-3
  },
  { // Entry 395
    -0x1.665077dda822b189a56a02e15c04d5d4p-3,
    -0x1.62b958p-3
  },
  { // Entry 396
    0x1.665077dda822b189a56a02e15c04d5d4p-3,
    0x1.62b958p-3
  },
  { // Entry 397
    -0x1.db1423d877b250af6ea5546960743d72p-4,
    -0x1.d8f720p-4
  },
  { // Entry 398
    0x1.db1423d877b250af6ea5546960743d72p-4,
    0x1.d8f720p-4
  },
  { // Entry 399
    -0x1.d97dd643ffeef57d0a225051978ec8adp-5,
    -0x1.d8f720p-5
  },
  { // Entry 400
    0x1.d97dd643ffeef57d0a225051978ec8adp-5,
    0x1.d8f720p-5
  },
  { // Entry 401
    0x1.d97dd643ffeef57d0a225051978ec8adp-5,
    0x1.d8f720p-5
  },
  { // Entry 402
    -0x1.d97dd643ffeef57d0a225051978ec8adp-5,
    -0x1.d8f720p-5
  },
  { // Entry 403
    0x1.db1423d877b250af6ea5546960743d72p-4,
    0x1.d8f720p-4
  },
  { // Entry 404
    -0x1.db1423d877b250af6ea5546960743d72p-4,
    -0x1.d8f720p-4
  },
  { // Entry 405
    0x1.665077dda822b189a56a02e15c04d5d4p-3,
    0x1.62b958p-3
  },
  { // Entry 406
    -0x1.665077dda822b189a56a02e15c04d5d4p-3,
    -0x1.62b958p-3
  },
  { // Entry 407
    0x1.e18e93867caf67efcaa19821898d50cap-3,
    0x1.d8f720p-3
  },
  { // Entry 408
    -0x1.e18e93867caf67efcaa19821898d50cap-3,
    -0x1.d8f720p-3
  },
  { // Entry 409
    0x1.30190941e699fdb2115a9ef6bf82d455p-2,
    0x1.279a74p-2
  },
  { // Entry 410
    -0x1.30190941e699fdb2115a9ef6bf82d455p-2,
    -0x1.279a74p-2
  },
  { // Entry 411
    0x1.71a0f907c661daf4903b7bbc015c5c14p-2,
    0x1.62b958p-2
  },
  { // Entry 412
    -0x1.71a0f907c661daf4903b7bbc015c5c14p-2,
    -0x1.62b958p-2
  },
  { // Entry 413
    0x1.b5f3d61c54ee4f6585e9bff489c00182p-2,
    0x1.9dd83cp-2
  },
  { // Entry 414
    -0x1.b5f3d61c54ee4f6585e9bff489c00182p-2,
    -0x1.9dd83cp-2
  },
  { // Entry 415
    0x1.fdbd5e53e0a6fc9c8b803289f1c3dbb7p-2,
    0x1.d8f720p-2
  },
  { // Entry 416
    -0x1.fdbd5e53e0a6fc9c8b803289f1c3dbb7p-2,
    -0x1.d8f720p-2
  },
  { // Entry 417
    0x1.24e3dfad4ce1493caa123864cb4f45d3p-1,
    0x1.0a0b02p-1
  },
  { // Entry 418
    -0x1.24e3dfad4ce1493caa123864cb4f45d3p-1,
    -0x1.0a0b02p-1
  },
  { // Entry 419
    0x1.6d395f05820b42f51223dab884367e71p-1,
    0x1.3d3e36p-1
  },
  { // Entry 420
    -0x1.6d395f05820b42f51223dab884367e71p-1,
    -0x1.3d3e36p-1
  },
  { // Entry 421
    0x1.8ee91858fbaaf2a34a32dd947fd7e076p-1,
    0x1.52e1f8p-1
  },
  { // Entry 422
    -0x1.8ee91858fbaaf2a34a32dd947fd7e076p-1,
    -0x1.52e1f8p-1
  },
  { // Entry 423
    0x1.b2e478bc9ba738db90b2a4bc294ecf4fp-1,
    0x1.6885bap-1
  },
  { // Entry 424
    -0x1.b2e478bc9ba738db90b2a4bc294ecf4fp-1,
    -0x1.6885bap-1
  },
  { // Entry 425
    0x1.d98e4617a8bd1a1bb9e2e989d8ad35ccp-1,
    0x1.7e297cp-1
  },
  { // Entry 426
    -0x1.d98e4617a8bd1a1bb9e2e989d8ad35ccp-1,
    -0x1.7e297cp-1
  },
  { // Entry 427
    0x1.01aef2aa416545e3900864f2b35d86a6p0,
    0x1.93cd3ep-1
  },
  { // Entry 428
    -0x1.01aef2aa416545e3900864f2b35d86a6p0,
    -0x1.93cd3ep-1
  },
  { // Entry 429
    0x1.1872a6cb3dba156db8dc784e95d96a46p0,
    0x1.a971p-1
  },
  { // Entry 430
    -0x1.1872a6cb3dba156db8dc784e95d96a46p0,
    -0x1.a971p-1
  },
  { // Entry 431
    0x1.316c91af46b015a9c931a816fed89092p0,
    0x1.bf14c2p-1
  },
  { // Entry 432
    -0x1.316c91af46b015a9c931a816fed89092p0,
    -0x1.bf14c2p-1
  },
  { // Entry 433
    0x1.4d0dfa81e9cc806c10194fba6b767761p0,
    0x1.d4b884p-1
  },
  { // Entry 434
    -0x1.4d0dfa81e9cc806c10194fba6b767761p0,
    -0x1.d4b884p-1
  },
  { // Entry 435
    0x1.6be7019f34d34f25cb0c14d0c7bc7b32p0,
    0x1.ea5c3ep-1
  },
  { // Entry 436
    -0x1.6be7019f34d34f25cb0c14d0c7bc7b32p0,
    -0x1.ea5c3ep-1
  },
  { // Entry 437
    0x1.d74cb200ab59040290627a9b2ffe29cfp0,
    0x1.12bd92p0
  },
  { // Entry 438
    -0x1.d74cb200ab59040290627a9b2ffe29cfp0,
    -0x1.12bd92p0
  },
  { // Entry 439
    0x1.1b48a6964c024648f186bb6b1ebdeec2p1,
    0x1.257b24p0
  },
  { // Entry 440
    -0x1.1b48a6964c024648f186bb6b1ebdeec2p1,
    -0x1.257b24p0
  },
  { // Entry 441
    0x1.5d604466c5aee8f1a1d8470f7ff579cfp1,
    0x1.3838b6p0
  },
  { // Entry 442
    -0x1.5d604466c5aee8f1a1d8470f7ff579cfp1,
    -0x1.3838b6p0
  },
  { // Entry 443
    0x1.c08cbd52d2b012f0cb47bcb3ff513c6dp1,
    0x1.4af648p0
  },
  { // Entry 444
    -0x1.c08cbd52d2b012f0cb47bcb3ff513c6dp1,
    -0x1.4af648p0
  },
  { // Entry 445
    0x1.3429f6aa3446d703e6ef96e0b564fc0cp2,
    0x1.5db3dap0
  },
  { // Entry 446
    -0x1.3429f6aa3446d703e6ef96e0b564fc0cp2,
    -0x1.5db3dap0
  },
  { // Entry 447
    0x1.e3a3a25b2606418a13970971beef41d6p2,
    0x1.70716cp0
  },
  { // Entry 448
    -0x1.e3a3a25b2606418a13970971beef41d6p2,
    -0x1.70716cp0
  },
  { // Entry 449
    0x1.11d8b7ba41694658111af48925bbad68p4,
    0x1.832efep0
  },
  { // Entry 450
    -0x1.11d8b7ba41694658111af48925bbad68p4,
    -0x1.832efep0
  },
  { // Entry 451
    -0x1.0d70563193fe219f3fd31a285f4d6638p6,
    0x1.95ec90p0
  },
  { // Entry 452
    0x1.0d70563193fe219f3fd31a285f4d6638p6,
    -0x1.95ec90p0
  },
  { // Entry 453
    -0x1.6a7e30ad8460f1a710479e2db9495c9cp3,
    0x1.a8aa1cp0
  },
  { // Entry 454
    0x1.6a7e30ad8460f1a710479e2db9495c9cp3,
    -0x1.a8aa1cp0
  },
  { // Entry 455
    0x1.9f39ee9fedb2375ec05d6da7a288c6bdp0,
    0x1.04aff8p0
  },
  { // Entry 456
    -0x1.9f39ee9fedb2375ec05d6da7a288c6bdp0,
    -0x1.04aff8p0
  },
  { // Entry 457
    0x1.9f3c509c6a7d75e451088359c88def88p0,
    0x1.04b0a0p0
  },
  { // Entry 458
    -0x1.9f3c509c6a7d75e451088359c88def88p0,
    -0x1.04b0a0p0
  },
  { // Entry 459
    0x1.9f3eb29df9e6a20467474e24d8bf35bap0,
    0x1.04b148p0
  },
  { // Entry 460
    -0x1.9f3eb29df9e6a20467474e24d8bf35bap0,
    -0x1.04b148p0
  },
  { // Entry 461
    0x1.9f4114a49bfffc3f5a183d36000aa785p0,
    0x1.04b1f0p0
  },
  { // Entry 462
    -0x1.9f4114a49bfffc3f5a183d36000aa785p0,
    -0x1.04b1f0p0
  },
  { // Entry 463
    0x1.9f4376b050dbc56bf5596083192077b5p0,
    0x1.04b298p0
  },
  { // Entry 464
    -0x1.9f4376b050dbc56bf5596083192077b5p0,
    -0x1.04b298p0
  },
  { // Entry 465
    0x1.9f45d8c1188c3eb77bca2c4a84c7eaddp0,
    0x1.04b340p0
  },
  { // Entry 466
    -0x1.9f45d8c1188c3eb77bca2c4a84c7eaddp0,
    -0x1.04b340p0
  },
  { // Entry 467
    0x1.9f483ad6f323a9a5a90d4ae07a23d266p0,
    0x1.04b3e8p0
  },
  { // Entry 468
    -0x1.9f483ad6f323a9a5a90d4ae07a23d266p0,
    -0x1.04b3e8p0
  },
  { // Entry 469
    0x1.9f4a9cf1e0b44810b3aa7cca45d71cc9p0,
    0x1.04b490p0
  },
  { // Entry 470
    -0x1.9f4a9cf1e0b44810b3aa7cca45d71cc9p0,
    -0x1.04b490p0
  },
  { // Entry 471
    0x1.9f4cf08af6c60ed6e2badd5a7b5c1e87p0,
    0x1.04b534p0
  },
  { // Entry 472
    -0x1.9f4cf08af6c60ed6e2badd5a7b5c1e87p0,
    -0x1.04b534p0
  },
  { // Entry 473
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 474
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 475
    0.0,
    0.0
  },
  { // Entry 476
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 477
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 478
    0x1.4d82b334a582a56a802f96b3b96feb81p-1,
    0x1.279a72p-1
  },
  { // Entry 479
    -0x1.4d82b334a582a56a802f96b3b96feb81p-1,
    -0x1.279a72p-1
  },
  { // Entry 480
    0x1.4d82b60de428f92aa8c96a4a7fe88945p-1,
    0x1.279a74p-1
  },
  { // Entry 481
    -0x1.4d82b60de428f92aa8c96a4a7fe88945p-1,
    -0x1.279a74p-1
  },
  { // Entry 482
    0x1.4d82b8e722d302f5aa939a563b12b1a1p-1,
    0x1.279a76p-1
  },
  { // Entry 483
    -0x1.4d82b8e722d302f5aa939a563b12b1a1p-1,
    -0x1.279a76p-1
  },
  { // Entry 484
    -0x1.89714760e8fed9af03a91cf1527ceaadp2,
    0x1.bb67acp0
  },
  { // Entry 485
    0x1.89714760e8fed9af03a91cf1527ceaadp2,
    -0x1.bb67acp0
  },
  { // Entry 486
    -0x1.897133fb81f3169b3161d50b50ccc1a7p2,
    0x1.bb67aep0
  },
  { // Entry 487
    0x1.897133fb81f3169b3161d50b50ccc1a7p2,
    -0x1.bb67aep0
  },
  { // Entry 488
    -0x1.897120961cc4475eb3b8061df0409430p2,
    0x1.bb67b0p0
  },
  { // Entry 489
    0x1.897120961cc4475eb3b8061df0409430p2,
    -0x1.bb67b0p0
  },
  { // Entry 490
    0x1.def49c3ab0ad5dde93ba34c54db714c7p-2,
    0x1.bffffep-2
  },
  { // Entry 491
    -0x1.def49c3ab0ad5dde93ba34c54db714c7p-2,
    -0x1.bffffep-2
  },
  { // Entry 492
    0x1.def49eaab37a1479231e899509ecf26cp-2,
    0x1.c0p-2
  },
  { // Entry 493
    -0x1.def49eaab37a1479231e899509ecf26cp-2,
    -0x1.c0p-2
  },
  { // Entry 494
    0x1.def4a11ab647eef212b1997d3b51405ap-2,
    0x1.c00002p-2
  },
  { // Entry 495
    -0x1.def4a11ab647eef212b1997d3b51405ap-2,
    -0x1.c00002p-2
  },
  { // Entry 496
    0x1.a46caf652fa18987e4d0a79f8145dd5bp-1,
    0x1.5ffffep-1
  },
  { // Entry 497
    -0x1.a46caf652fa18987e4d0a79f8145dd5bp-1,
    -0x1.5ffffep-1
  },
  { // Entry 498
    0x1.a46cb2be6a0b1dacb36269c41a4a9147p-1,
    0x1.60p-1
  },
  { // Entry 499
    -0x1.a46cb2be6a0b1dacb36269c41a4a9147p-1,
    -0x1.60p-1
  },
  { // Entry 500
    0x1.a46cb617a47a31a156dc0005b4e6ebp-1,
    0x1.600002p-1
  },
  { // Entry 501
    -0x1.a46cb617a47a31a156dc0005b4e6ebp-1,
    -0x1.600002p-1
  },
  { // Entry 502
    0x1.3d6dc230869c70d5937fedc92d424df2p1,
    0x1.2ffffep0
  },
  { // Entry 503
    -0x1.3d6dc230869c70d5937fedc92d424df2p1,
    -0x1.2ffffep0
  },
  { // Entry 504
    0x1.3d6dc956eac7d3b8d6eb2174110d1ddcp1,
    0x1.30p0
  },
  { // Entry 505
    -0x1.3d6dc956eac7d3b8d6eb2174110d1ddcp1,
    -0x1.30p0
  },
  { // Entry 506
    0x1.3d6dd07d4f3a237589ad5c41c3801cb4p1,
    0x1.300002p0
  },
  { // Entry 507
    -0x1.3d6dd07d4f3a237589ad5c41c3801cb4p1,
    -0x1.300002p0
  },
  { // Entry 508
    -0x1.b2d8a858c90a538d1daad78040e69b98p-1,
    0x1.37fffep1
  },
  { // Entry 509
    0x1.b2d8a858c90a538d1daad78040e69b98p-1,
    -0x1.37fffep1
  },
  { // Entry 510
    -0x1.b2d89a938294c8a2604db9f7aa56a0f8p-1,
    0x1.38p1
  },
  { // Entry 511
    0x1.b2d89a938294c8a2604db9f7aa56a0f8p-1,
    -0x1.38p1
  },
  { // Entry 512
    -0x1.b2d88cce3c7cce174266439da309cf60p-1,
    0x1.380002p1
  },
  { // Entry 513
    0x1.b2d88cce3c7cce174266439da309cf60p-1,
    -0x1.380002p1
  },
  { // Entry 514
    0x1.06f8d0cecf169b06467e4aa036cf8279p-4,
    0x1.069c8cp-4
  },
  { // Entry 515
    -0x1.06f8d0cecf169b06467e4aa036cf8279p-4,
    -0x1.069c8cp-4
  },
  { // Entry 516
    0x1.080f746cd17397b60f908e2be01f7ba7p-3,
    0x1.069c8cp-3
  },
  { // Entry 517
    -0x1.080f746cd17397b60f908e2be01f7ba7p-3,
    -0x1.069c8cp-3
  },
  { // Entry 518
    0x1.8ed91550469d0eb08aae20658958043bp-3,
    0x1.89ead2p-3
  },
  { // Entry 519
    -0x1.8ed91550469d0eb08aae20658958043bp-3,
    -0x1.89ead2p-3
  },
  { // Entry 520
    0x1.0c864149dc68276df299282d04f69af6p-2,
    0x1.069c8cp-2
  },
  { // Entry 521
    -0x1.0c864149dc68276df299282d04f69af6p-2,
    -0x1.069c8cp-2
  },
  { // Entry 522
    0x1.53fdd01a98f07f208555cc644276ef2cp-2,
    0x1.4843b0p-2
  },
  { // Entry 523
    -0x1.53fdd01a98f07f208555cc644276ef2cp-2,
    -0x1.4843b0p-2
  },
  { // Entry 524
    0x1.9e925b7e237b88ac6098b513c371757cp-2,
    0x1.89ead4p-2
  },
  { // Entry 525
    -0x1.9e925b7e237b88ac6098b513c371757cp-2,
    -0x1.89ead4p-2
  },
  { // Entry 526
    0x1.ed21eadb08e47db8b2f11880fbb52879p-2,
    0x1.cb91f8p-2
  },
  { // Entry 527
    -0x1.ed21eadb08e47db8b2f11880fbb52879p-2,
    -0x1.cb91f8p-2
  },
  { // Entry 528
    0x1.205a63a04e31e1852af3da22e9f69a19p-1,
    0x1.069c8ep-1
  },
  { // Entry 529
    -0x1.205a63a04e31e1852af3da22e9f69a19p-1,
    -0x1.069c8ep-1
  },
  { // Entry 530
    0x1.4d466f84a3288515ab699dd1cec345d3p-1,
    0x1.277020p-1
  },
  { // Entry 531
    -0x1.4d466f84a3288515ab699dd1cec345d3p-1,
    -0x1.277020p-1
  },
  { // Entry 532
    0x1.7e1d9983b58754a29012e17a26f277d7p-1,
    0x1.4843b2p-1
  },
  { // Entry 533
    -0x1.7e1d9983b58754a29012e17a26f277d7p-1,
    -0x1.4843b2p-1
  },
  { // Entry 534
    0x1.b3df402fe49842a4164cf380ffa5dcp-1,
    0x1.691744p-1
  },
  { // Entry 535
    -0x1.b3df402fe49842a4164cf380ffa5dcp-1,
    -0x1.691744p-1
  },
  { // Entry 536
    0x1.efd8311ddf2cc393f20ea767c7b2264ap-1,
    0x1.89ead6p-1
  },
  { // Entry 537
    -0x1.efd8311ddf2cc393f20ea767c7b2264ap-1,
    -0x1.89ead6p-1
  },
  { // Entry 538
    0x1.19e271a6444ff34aa2f73c85014971c9p0,
    0x1.aabe68p-1
  },
  { // Entry 539
    -0x1.19e271a6444ff34aa2f73c85014971c9p0,
    -0x1.aabe68p-1
  },
  { // Entry 540
    0x1.410393802c1a22382914abf096afbee9p0,
    0x1.cb91fap-1
  },
  { // Entry 541
    -0x1.410393802c1a22382914abf096afbee9p0,
    -0x1.cb91fap-1
  },
  { // Entry 542
    0x1.6efed33b714045fe99cfa59471e1e9fdp0,
    0x1.ec658cp-1
  },
  { // Entry 543
    -0x1.6efed33b714045fe99cfa59471e1e9fdp0,
    -0x1.ec658cp-1
  },
  { // Entry 544
    0x1.a64c86c02e7a7d96e91f96a5584129f4p0,
    0x1.069c8ep0
  },
  { // Entry 545
    -0x1.a64c86c02e7a7d96e91f96a5584129f4p0,
    -0x1.069c8ep0
  },
  { // Entry 546
    0x1.eab4477e5b226dc5270bae9720ea13e3p0,
    0x1.170656p0
  },
  { // Entry 547
    -0x1.eab4477e5b226dc5270bae9720ea13e3p0,
    -0x1.170656p0
  },
  { // Entry 548
    0x1.21277f9a7d2f66bb131cff32f26629cdp1,
    0x1.27701ep0
  },
  { // Entry 549
    -0x1.21277f9a7d2f66bb131cff32f26629cdp1,
    -0x1.27701ep0
  },
  { // Entry 550
    0x1.5bd1406825b3ffeba48221ad6a8f5414p1,
    0x1.37d9e6p0
  },
  { // Entry 551
    -0x1.5bd1406825b3ffeba48221ad6a8f5414p1,
    -0x1.37d9e6p0
  },
  { // Entry 552
    0x1.af464352a989f802824152cad0afe8b7p1,
    0x1.4843aep0
  },
  { // Entry 553
    -0x1.af464352a989f802824152cad0afe8b7p1,
    -0x1.4843aep0
  },
  { // Entry 554
    0x1.1866fa7a601b87bb6f378b3438e3fc26p2,
    0x1.58ad76p0
  },
  { // Entry 555
    -0x1.1866fa7a601b87bb6f378b3438e3fc26p2,
    -0x1.58ad76p0
  },
  { // Entry 556
    0x1.8bdcc68718a70118860a1b945437fd90p2,
    0x1.69173ep0
  },
  { // Entry 557
    -0x1.8bdcc68718a70118860a1b945437fd90p2,
    -0x1.69173ep0
  },
  { // Entry 558
    0x1.4bb68859d3eafb2a130b73ba07e48e8ap3,
    0x1.798106p0
  },
  { // Entry 559
    -0x1.4bb68859d3eafb2a130b73ba07e48e8ap3,
    -0x1.798106p0
  },
  { // Entry 560
    0x1.f2efabaeb322ec5ca9d33869295c6063p4,
    0x1.89eacep0
  },
  { // Entry 561
    -0x1.f2efabaeb322ec5ca9d33869295c6063p4,
    -0x1.89eacep0
  },
  { // Entry 562
    -0x1.f2f13929323ef8f58db152143e65bcb7p4,
    0x1.9a5496p0
  },
  { // Entry 563
    0x1.f2f13929323ef8f58db152143e65bcb7p4,
    -0x1.9a5496p0
  },
  { // Entry 564
    -0x1.4bb6e0ec02cad5c110a4d70039db4d1cp3,
    0x1.aabe5ep0
  },
  { // Entry 565
    0x1.4bb6e0ec02cad5c110a4d70039db4d1cp3,
    -0x1.aabe5ep0
  },
  { // Entry 566
    -0x1.8bdd06a655dfa2f3195aca48798e5c86p2,
    0x1.bb2826p0
  },
  { // Entry 567
    0x1.8bdd06a655dfa2f3195aca48798e5c86p2,
    -0x1.bb2826p0
  },
  { // Entry 568
    -0x1.18671b76cfccf98a6edbc1fd5b8647b7p2,
    0x1.cb91eep0
  },
  { // Entry 569
    0x1.18671b76cfccf98a6edbc1fd5b8647b7p2,
    -0x1.cb91eep0
  },
  { // Entry 570
    -0x1.af466bac80dc9df668d1e0e9b442bf0ep1,
    0x1.dbfbb6p0
  },
  { // Entry 571
    0x1.af466bac80dc9df668d1e0e9b442bf0ep1,
    -0x1.dbfbb6p0
  },
  { // Entry 572
    -0x1.5bd15bcb3d06906cef5f3b2ec3ab4ab9p1,
    0x1.ec657ep0
  },
  { // Entry 573
    0x1.5bd15bcb3d06906cef5f3b2ec3ab4ab9p1,
    -0x1.ec657ep0
  },
  { // Entry 574
    -0x1.2127938a546d3c428292ba53ee6f67ccp1,
    0x1.fccf46p0
  },
  { // Entry 575
    0x1.2127938a546d3c428292ba53ee6f67ccp1,
    -0x1.fccf46p0
  },
  { // Entry 576
    -0x1.eab45caed706c4db622c90fe3e8d16c2p0,
    0x1.069c88p1
  },
  { // Entry 577
    0x1.eab45caed706c4db622c90fe3e8d16c2p0,
    -0x1.069c88p1
  },
  { // Entry 578
    -0x1.a64c979eb703d82cb4808044e8abf93fp0,
    0x1.0ed16cp1
  },
  { // Entry 579
    0x1.a64c979eb703d82cb4808044e8abf93fp0,
    -0x1.0ed16cp1
  },
  { // Entry 580
    -0x1.6efee11500263c10c1d1bb5904244de6p0,
    0x1.170650p1
  },
  { // Entry 581
    0x1.6efee11500263c10c1d1bb5904244de6p0,
    -0x1.170650p1
  },
  { // Entry 582
    -0x1.4103a1bc0f6576a760d49da3bfe55874p0,
    0x1.1f3b34p1
  },
  { // Entry 583
    0x1.4103a1bc0f6576a760d49da3bfe55874p0,
    -0x1.1f3b34p1
  },
  { // Entry 584
    -0x1.19e2801aa24ee0adcd9491e4d7af256fp0,
    0x1.277018p1
  },
  { // Entry 585
    0x1.19e2801aa24ee0adcd9491e4d7af256fp0,
    -0x1.277018p1
  },
  { // Entry 586
    -0x1.efd84e50652c1b7c71972ad8ee7c018ap-1,
    0x1.2fa4fcp1
  },
  { // Entry 587
    0x1.efd84e50652c1b7c71972ad8ee7c018ap-1,
    -0x1.2fa4fcp1
  },
  { // Entry 588
    -0x1.b3df5d9f54e2c748cf0227ee0974ea2ep-1,
    0x1.37d9e0p1
  },
  { // Entry 589
    0x1.b3df5d9f54e2c748cf0227ee0974ea2ep-1,
    -0x1.37d9e0p1
  },
  { // Entry 590
    -0x1.7e1db733769a1126a2b0ac7fa14a402cp-1,
    0x1.400ec4p1
  },
  { // Entry 591
    0x1.7e1db733769a1126a2b0ac7fa14a402cp-1,
    -0x1.400ec4p1
  },
  { // Entry 592
    -0x1.4d468d82c1a84fef7279fc5fb24419b2p-1,
    0x1.4843a8p1
  },
  { // Entry 593
    0x1.4d468d82c1a84fef7279fc5fb24419b2p-1,
    -0x1.4843a8p1
  },
  { // Entry 594
    -0x1.205a8202545202d891ce89bfa6cd1476p-1,
    0x1.50788cp1
  },
  { // Entry 595
    0x1.205a8202545202d891ce89bfa6cd1476p-1,
    -0x1.50788cp1
  },
  { // Entry 596
    -0x1.ed22289d891ed78cdc818a4cde6de918p-2,
    0x1.58ad70p1
  },
  { // Entry 597
    0x1.ed22289d891ed78cdc818a4cde6de918p-2,
    -0x1.58ad70p1
  },
  { // Entry 598
    -0x1.9e929a7fadf83b6f9e8fb851f512b44bp-2,
    0x1.60e254p1
  },
  { // Entry 599
    0x1.9e929a7fadf83b6f9e8fb851f512b44bp-2,
    -0x1.60e254p1
  },
  { // Entry 600
    -0x1.53fe10a547a6ecce5caddc2005db822bp-2,
    0x1.691738p1
  },
  { // Entry 601
    0x1.53fe10a547a6ecce5caddc2005db822bp-2,
    -0x1.691738p1
  },
  { // Entry 602
    -0x1.0c8683b1bc682759e28441ef97c8854bp-2,
    0x1.714c1cp1
  },
  { // Entry 603
    0x1.0c8683b1bc682759e28441ef97c8854bp-2,
    -0x1.714c1cp1
  },
  { // Entry 604
    -0x1.8ed99c8546008be46614ea66c7ddd7e6p-3,
    0x1.7981p1
  },
  { // Entry 605
    0x1.8ed99c8546008be46614ea66c7ddd7e6p-3,
    -0x1.7981p1
  },
  { // Entry 606
    -0x1.080ffef4eda0271d81658d58ae280792p-3,
    0x1.81b5e4p1
  },
  { // Entry 607
    0x1.080ffef4eda0271d81658d58ae280792p-3,
    -0x1.81b5e4p1
  },
  { // Entry 608
    -0x1.06f9ee83686aa6194c03de71a6b52f75p-4,
    0x1.89eac8p1
  },
  { // Entry 609
    0x1.06f9ee83686aa6194c03de71a6b52f75p-4,
    -0x1.89eac8p1
  },
  { // Entry 610
    0x1.0c8627ec3bc2e8f0e6df44f809f370fdp-2,
    -0x1.81b5eep2
  },
  { // Entry 611
    -0x1.0c8627ec3bc2e8f0e6df44f809f370fdp-2,
    0x1.81b5eep2
  },
  { // Entry 612
    0x1.205a49753bb89e8c971c6cd2842edaf0p-1,
    -0x1.714c26p2
  },
  { // Entry 613
    -0x1.205a49753bb89e8c971c6cd2842edaf0p-1,
    0x1.714c26p2
  },
  { // Entry 614
    0x1.efd7fb1d28b8a0602b25fadfe9e0277ap-1,
    -0x1.60e25ep2
  },
  { // Entry 615
    -0x1.efd7fb1d28b8a0602b25fadfe9e0277ap-1,
    0x1.60e25ep2
  },
  { // Entry 616
    0x1.a64c47bcfb5f9cbdb49360a65548fd6dp0,
    -0x1.507896p2
  },
  { // Entry 617
    -0x1.a64c47bcfb5f9cbdb49360a65548fd6dp0,
    0x1.507896p2
  },
  { // Entry 618
    0x1.af45dabd34b75597ff70079b3de986fdp1,
    -0x1.400ecep2
  },
  { // Entry 619
    -0x1.af45dabd34b75597ff70079b3de986fdp1,
    0x1.400ecep2
  },
  { // Entry 620
    0x1.f2eba583fff9f8df3693ffd969395de7p4,
    -0x1.2fa506p2
  },
  { // Entry 621
    -0x1.f2eba583fff9f8df3693ffd969395de7p4,
    0x1.2fa506p2
  },
  { // Entry 622
    -0x1.186770f5cef152a4ec75fe9a7031a56ap2,
    -0x1.1f3b3ep2
  },
  { // Entry 623
    0x1.186770f5cef152a4ec75fe9a7031a56ap2,
    0x1.1f3b3ep2
  },
  { // Entry 624
    -0x1.eab4b52e6cce160a5b9a23a4b929d01dp0,
    -0x1.0ed176p2
  },
  { // Entry 625
    0x1.eab4b52e6cce160a5b9a23a4b929d01dp0,
    0x1.0ed176p2
  },
  { // Entry 626
    -0x1.19e2a124bc3deef648338274627cc371p0,
    -0x1.fccf5ap1
  },
  { // Entry 627
    0x1.19e2a124bc3deef648338274627cc371p0,
    0x1.fccf5ap1
  },
  { // Entry 628
    -0x1.4d46aca48de47f5fd90c9000c15425d8p-1,
    -0x1.dbfbc8p1
  },
  { // Entry 629
    0x1.4d46aca48de47f5fd90c9000c15425d8p-1,
    0x1.dbfbc8p1
  },
  { // Entry 630
    -0x1.53fe2f6fc9d023774a2105c8213e4d5ep-2,
    -0x1.bb2836p1
  },
  { // Entry 631
    0x1.53fe2f6fc9d023774a2105c8213e4d5ep-2,
    0x1.bb2836p1
  },
  { // Entry 632
    -0x1.06fa1da43b26cd580ce5a5b89cf2eff3p-4,
    -0x1.9a54a4p1
  },
  { // Entry 633
    0x1.06fa1da43b26cd580ce5a5b89cf2eff3p-4,
    0x1.9a54a4p1
  },
  { // Entry 634
    0x1.8ed87198f413d3a122658287aa7fc33ep-3,
    -0x1.798112p1
  },
  { // Entry 635
    -0x1.8ed87198f413d3a122658287aa7fc33ep-3,
    0x1.798112p1
  },
  { // Entry 636
    0x1.ed218aee2df4e80e39340b0c4ec3b1d5p-2,
    -0x1.58ad80p1
  },
  { // Entry 637
    -0x1.ed218aee2df4e80e39340b0c4ec3b1d5p-2,
    0x1.58ad80p1
  },
  { // Entry 638
    0x1.b3defd0991e6315369dbd5e2de2d14fep-1,
    -0x1.37d9eep1
  },
  { // Entry 639
    -0x1.b3defd0991e6315369dbd5e2de2d14fep-1,
    0x1.37d9eep1
  },
  { // Entry 640
    0x1.6efe97c23f206826b4f0019f275d3a44p0,
    -0x1.17065cp1
  },
  { // Entry 641
    -0x1.6efe97c23f206826b4f0019f275d3a44p0,
    0x1.17065cp1
  },
  { // Entry 642
    0x1.5bd0ff925c94f7d608b88484f9081f2cp1,
    -0x1.ec6594p0
  },
  { // Entry 643
    -0x1.5bd0ff925c94f7d608b88484f9081f2cp1,
    0x1.ec6594p0
  },
  { // Entry 644
    0x1.4bb5ece657bee292a82a3fda6b812aadp3,
    -0x1.aabe70p0
  },
  { // Entry 645
    -0x1.4bb5ece657bee292a82a3fda6b812aadp3,
    0x1.aabe70p0
  },
  { // Entry 646
    -0x1.8bdd4feef18bfa8a6c23de6a721f2436p2,
    -0x1.69174cp0
  },
  { // Entry 647
    0x1.8bdd4feef18bfa8a6c23de6a721f2436p2,
    0x1.69174cp0
  },
  { // Entry 648
    -0x1.21279e1e8bf4bd3983a3677267e55809p1,
    -0x1.277028p0
  },
  { // Entry 649
    0x1.21279e1e8bf4bd3983a3677267e55809p1,
    0x1.277028p0
  },
  { // Entry 650
    -0x1.4103a8147ca836136cc98db9bc6ddf30p0,
    -0x1.cb920ap-1
  },
  { // Entry 651
    0x1.4103a8147ca836136cc98db9bc6ddf30p0,
    0x1.cb920ap-1
  },
  { // Entry 652
    -0x1.7e1db58a55d6a12a6457e3c5929ac2c7p-1,
    -0x1.4843c4p-1
  },
  { // Entry 653
    0x1.7e1db58a55d6a12a6457e3c5929ac2c7p-1,
    0x1.4843c4p-1
  },
  { // Entry 654
    -0x1.9e928a0c8e79023200164ed240caad05p-2,
    -0x1.89eafcp-2
  },
  { // Entry 655
    0x1.9e928a0c8e79023200164ed240caad05p-2,
    0x1.89eafcp-2
  },
  { // Entry 656
    -0x1.080fc9d24fbe9876b31b0aa29dd238eap-3,
    -0x1.069ce0p-3
  },
  { // Entry 657
    0x1.080fc9d24fbe9876b31b0aa29dd238eap-3,
    0x1.069ce0p-3
  },
  { // Entry 658
    0x1.080f1f07540fd03b82d4b370d237fa3dp-3,
    0x1.069c38p-3
  },
  { // Entry 659
    -0x1.080f1f07540fd03b82d4b370d237fa3dp-3,
    -0x1.069c38p-3
  },
  { // Entry 660
    0x1.9e922847e2b1b6a72d486700e18c05f2p-2,
    0x1.89eaa8p-2
  },
  { // Entry 661
    -0x1.9e922847e2b1b6a72d486700e18c05f2p-2,
    -0x1.89eaa8p-2
  },
  { // Entry 662
    0x1.7e1d74258cbc964b561d99c9a66f8c7ep-1,
    0x1.48439ap-1
  },
  { // Entry 663
    -0x1.7e1d74258cbc964b561d99c9a66f8c7ep-1,
    -0x1.48439ap-1
  },
  { // Entry 664
    0x1.4103720f2ca3e0580fba15849398a4e9p0,
    0x1.cb91e0p-1
  },
  { // Entry 665
    -0x1.4103720f2ca3e0580fba15849398a4e9p0,
    -0x1.cb91e0p-1
  },
  { // Entry 666
    0x1.2127611673ccc7531f5af5aeda3412c5p1,
    0x1.277014p0
  },
  { // Entry 667
    -0x1.2127611673ccc7531f5af5aeda3412c5p1,
    -0x1.277014p0
  },
  { // Entry 668
    0x1.8bdc8ba3d8277213c5b74ef806ef466bp2,
    0x1.691738p0
  },
  { // Entry 669
    -0x1.8bdc8ba3d8277213c5b74ef806ef466bp2,
    -0x1.691738p0
  },
  { // Entry 670
    -0x1.4bb6fc092bc16530216209a912aada37p3,
    0x1.aabe5cp0
  },
  { // Entry 671
    0x1.4bb6fc092bc16530216209a912aada37p3,
    -0x1.aabe5cp0
  },
  { // Entry 672
    -0x1.5bd15368f84be0bda8f135a5f79aeacbp1,
    0x1.ec6580p0
  },
  { // Entry 673
    0x1.5bd15368f84be0bda8f135a5f79aeacbp1,
    -0x1.ec6580p0
  },
  { // Entry 674
    -0x1.6efed4dc8946e1c3620d79bb0d654338p0,
    0x1.170652p1
  },
  { // Entry 675
    0x1.6efed4dc8946e1c3620d79bb0d654338p0,
    -0x1.170652p1
  },
  { // Entry 676
    -0x1.b3df4206d232794d5761992d88c5a394p-1,
    0x1.37d9e4p1
  },
  { // Entry 677
    0x1.b3df4206d232794d5761992d88c5a394p-1,
    -0x1.37d9e4p1
  },
  { // Entry 678
    -0x1.ed21ed7bc4b5968bdb0cd6da269cd55fp-2,
    0x1.58ad76p1
  },
  { // Entry 679
    0x1.ed21ed7bc4b5968bdb0cd6da269cd55fp-2,
    -0x1.58ad76p1
  },
  { // Entry 680
    -0x1.8ed917aa74e733b9194d537c8df33c64p-3,
    0x1.798108p1
  },
  { // Entry 681
    0x1.8ed917aa74e733b9194d537c8df33c64p-3,
    -0x1.798108p1
  },
  { // Entry 682
    0x1.06f8dc528ea01882064ee242f58a2b88p-4,
    0x1.9a549ap1
  },
  { // Entry 683
    -0x1.06f8dc528ea01882064ee242f58a2b88p-4,
    -0x1.9a549ap1
  },
  { // Entry 684
    0x1.53fdd69e1437db957c62e8cc55742beep-2,
    0x1.bb282cp1
  },
  { // Entry 685
    -0x1.53fdd69e1437db957c62e8cc55742beep-2,
    -0x1.bb282cp1
  },
  { // Entry 686
    0x1.4d4673b1c7635cc893e1c8d2ca57b3e9p-1,
    0x1.dbfbbep1
  },
  { // Entry 687
    -0x1.4d4673b1c7635cc893e1c8d2ca57b3e9p-1,
    -0x1.dbfbbep1
  },
  { // Entry 688
    0x1.19e274e4fdec9e78ef6872081b5572cfp0,
    0x1.fccf50p1
  },
  { // Entry 689
    -0x1.19e274e4fdec9e78ef6872081b5572cfp0,
    -0x1.fccf50p1
  },
  { // Entry 690
    0x1.eab445003a7b542a2d4d87a88793bb67p0,
    0x1.0ed170p2
  },
  { // Entry 691
    -0x1.eab445003a7b542a2d4d87a88793bb67p0,
    -0x1.0ed170p2
  },
  { // Entry 692
    0x1.1866f7c91660d9c9f4b2d14e91375732p2,
    0x1.1f3b38p2
  },
  { // Entry 693
    -0x1.1866f7c91660d9c9f4b2d14e91375732p2,
    -0x1.1f3b38p2
  },
  { // Entry 694
    -0x1.f2f1599b29a7de952b8ba1877d9f5e61p4,
    0x1.2fa5p2
  },
  { // Entry 695
    0x1.f2f1599b29a7de952b8ba1877d9f5e61p4,
    -0x1.2fa5p2
  },
  { // Entry 696
    -0x1.af466ef7b15645455e15fbbae6bb4bc6p1,
    0x1.400ec8p2
  },
  { // Entry 697
    0x1.af466ef7b15645455e15fbbae6bb4bc6p1,
    -0x1.400ec8p2
  },
  { // Entry 698
    -0x1.a64ca10bfefd2b04bb6a1bb708c28967p0,
    0x1.507890p2
  },
  { // Entry 699
    0x1.a64ca10bfefd2b04bb6a1bb708c28967p0,
    -0x1.507890p2
  },
  { // Entry 700
    -0x1.efd85821ec927f2a89ec41acee587230p-1,
    0x1.60e258p2
  },
  { // Entry 701
    0x1.efd85821ec927f2a89ec41acee587230p-1,
    -0x1.60e258p2
  },
  { // Entry 702
    -0x1.205a88aec64cad35d7752c73620c2139p-1,
    0x1.714c20p2
  },
  { // Entry 703
    0x1.205a88aec64cad35d7752c73620c2139p-1,
    -0x1.714c20p2
  },
  { // Entry 704
    -0x1.0c868e863543fd989476c8cdeffa93eap-2,
    0x1.81b5e8p2
  },
  { // Entry 705
    0x1.0c868e863543fd989476c8cdeffa93eap-2,
    -0x1.81b5e8p2
  },
  { // Entry 706
    0x1.f09b61a8a04f0898851f1d7604fa13c8p-5,
    0x1.effffep-5
  },
  { // Entry 707
    -0x1.f09b61a8a04f0898851f1d7604fa13c8p-5,
    -0x1.effffep-5
  },
  { // Entry 708
    0x1.f09b63aa81fc46e95e06405b41e8b4ccp-5,
    0x1.f0p-5
  },
  { // Entry 709
    -0x1.f09b63aa81fc46e95e06405b41e8b4ccp-5,
    -0x1.f0p-5
  },
  { // Entry 710
    0x1.f09b65ac63a9891f1418c4338c1e419ep-5,
    0x1.f00002p-5
  },
  { // Entry 711
    -0x1.f09b65ac63a9891f1418c4338c1e419ep-5,
    -0x1.f00002p-5
  },
  { // Entry 712
    0x1.fa8f1fc0ce86c214bf765fd59e8798a5p-4,
    0x1.f7fffep-4
  },
  { // Entry 713
    -0x1.fa8f1fc0ce86c214bf765fd59e8798a5p-4,
    -0x1.f7fffep-4
  },
  { // Entry 714
    0x1.fa8f21c8a33afd3355198e8d7716a811p-4,
    0x1.f8p-4
  },
  { // Entry 715
    -0x1.fa8f21c8a33afd3355198e8d7716a811p-4,
    -0x1.f8p-4
  },
  { // Entry 716
    0x1.fa8f23d077ef48645eff9a519628b3a9p-4,
    0x1.f80002p-4
  },
  { // Entry 717
    -0x1.fa8f23d077ef48645eff9a519628b3a9p-4,
    -0x1.f80002p-4
  },
  { // Entry 718
    0x1.4ef06aa73ee6a439c0c9f45046b25978p-3,
    0x1.4bfffep-3
  },
  { // Entry 719
    -0x1.4ef06aa73ee6a439c0c9f45046b25978p-3,
    -0x1.4bfffep-3
  },
  { // Entry 720
    0x1.4ef06cb4f0a87a5c8eeeebceb12a22b4p-3,
    0x1.4cp-3
  },
  { // Entry 721
    -0x1.4ef06cb4f0a87a5c8eeeebceb12a22b4p-3,
    -0x1.4cp-3
  },
  { // Entry 722
    0x1.4ef06ec2a26a7b7c1721ffafb93c0281p-3,
    0x1.4c0002p-3
  },
  { // Entry 723
    -0x1.4ef06ec2a26a7b7c1721ffafb93c0281p-3,
    -0x1.4c0002p-3
  },
  { // Entry 724
    0x1.3cc2a2fd911e1557d57b44abf28c4ccap-2,
    0x1.333332p-2
  },
  { // Entry 725
    -0x1.3cc2a2fd911e1557d57b44abf28c4ccap-2,
    -0x1.333332p-2
  },
  { // Entry 726
    0x1.3cc2a52e8f4137ca27d1dc0567195443p-2,
    0x1.333334p-2
  },
  { // Entry 727
    -0x1.3cc2a52e8f4137ca27d1dc0567195443p-2,
    -0x1.333334p-2
  },
  { // Entry 728
    0x1.3cc2a75f8d6507c589bf08e0371394bcp-2,
    0x1.333336p-2
  },
  { // Entry 729
    -0x1.3cc2a75f8d6507c589bf08e0371394bcp-2,
    -0x1.333336p-2
  },
  { // Entry 730
    0x1.99436e5f07b73dda1ef61a800aadfdd3p-1,
    0x1.594316p-1
  },
  { // Entry 731
    -0x1.99436e5f07b73dda1ef61a800aadfdd3p-1,
    -0x1.594316p-1
  },
  { // Entry 732
    0x1.994371a62bfe13eb1c755cb5be46f853p-1,
    0x1.594318p-1
  },
  { // Entry 733
    -0x1.994371a62bfe13eb1c755cb5be46f853p-1,
    -0x1.594318p-1
  },
  { // Entry 734
    0x1.994374ed504a278226573562b60eca9ap-1,
    0x1.59431ap-1
  },
  { // Entry 735
    -0x1.994374ed504a278226573562b60eca9ap-1,
    -0x1.59431ap-1
  },
  { // Entry 736
    0x1.fbc50de7c605a4d1d0f1119b1294b6f0p-1,
    0x1.8ffffep-1
  },
  { // Entry 737
    -0x1.fbc50de7c605a4d1d0f1119b1294b6f0p-1,
    -0x1.8ffffep-1
  },
  { // Entry 738
    0x1.fbc511df5917f539bbcf778bc1a22249p-1,
    0x1.90p-1
  },
  { // Entry 739
    -0x1.fbc511df5917f539bbcf778bc1a22249p-1,
    -0x1.90p-1
  },
  { // Entry 740
    0x1.fbc515d6ec3223ffbed4bb75154fda0fp-1,
    0x1.900002p-1
  },
  { // Entry 741
    -0x1.fbc515d6ec3223ffbed4bb75154fda0fp-1,
    -0x1.900002p-1
  },
  { // Entry 742
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 743
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 744
    0.0,
    0.0
  },
  { // Entry 745
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 746
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 747
    0x1.9272775ea5ecff4e43ecdef3d85ec226p-5,
    0x1.921fb4p-5
  },
  { // Entry 748
    -0x1.9272775ea5ecff4e43ecdef3d85ec226p-5,
    -0x1.921fb4p-5
  },
  { // Entry 749
    0x1.9272795fe242d9eb9393a7446620c394p-5,
    0x1.921fb6p-5
  },
  { // Entry 750
    -0x1.9272795fe242d9eb9393a7446620c394p-5,
    -0x1.921fb6p-5
  },
  { // Entry 751
    0x1.92727b611e98b7afb97977551d1c5f38p-5,
    0x1.921fb8p-5
  },
  { // Entry 752
    -0x1.92727b611e98b7afb97977551d1c5f38p-5,
    -0x1.921fb8p-5
  },
  { // Entry 753
    0x1.936bb77e4ac859bc69bc4abc9e91f025p-4,
    0x1.921fb4p-4
  },
  { // Entry 754
    -0x1.936bb77e4ac859bc69bc4abc9e91f025p-4,
    -0x1.921fb4p-4
  },
  { // Entry 755
    0x1.936bb9834241022ecd070b9064632721p-4,
    0x1.921fb6p-4
  },
  { // Entry 756
    -0x1.936bb9834241022ecd070b9064632721p-4,
    -0x1.921fb6p-4
  },
  { // Entry 757
    0x1.936bbb8839b9b75bdcc5f6870267a609p-4,
    0x1.921fb8p-4
  },
  { // Entry 758
    -0x1.936bbb8839b9b75bdcc5f6870267a609p-4,
    -0x1.921fb8p-4
  },
  { // Entry 759
    0x1.975f5cb43bd951aa2e89a05cbf5e70ffp-3,
    0x1.921fb4p-3
  },
  { // Entry 760
    -0x1.975f5cb43bd951aa2e89a05cbf5e70ffp-3,
    -0x1.921fb4p-3
  },
  { // Entry 761
    0x1.975f5ec87ddc4e7a357059f71a9f05b2p-3,
    0x1.921fb6p-3
  },
  { // Entry 762
    -0x1.975f5ec87ddc4e7a357059f71a9f05b2p-3,
    -0x1.921fb6p-3
  },
  { // Entry 763
    0x1.975f60dcbfdf8039f01eb7864bc09e13p-3,
    0x1.921fb8p-3
  },
  { // Entry 764
    -0x1.975f60dcbfdf8039f01eb7864bc09e13p-3,
    -0x1.921fb8p-3
  },
  { // Entry 765
    0x1.a8279823e9ba30ee623a5402a48590fcp-2,
    0x1.921fb4p-2
  },
  { // Entry 766
    -0x1.a8279823e9ba30ee623a5402a48590fcp-2,
    -0x1.921fb4p-2
  },
  { // Entry 767
    0x1.a8279a7bc2206fff3afa52f168c5f8f2p-2,
    0x1.921fb6p-2
  },
  { // Entry 768
    -0x1.a8279a7bc2206fff3afa52f168c5f8f2p-2,
    -0x1.921fb6p-2
  },
  { // Entry 769
    0x1.a8279cd39a87a786e140537db72ff334p-2,
    0x1.921fb8p-2
  },
  { // Entry 770
    -0x1.a8279cd39a87a786e140537db72ff334p-2,
    -0x1.921fb8p-2
  },
  { // Entry 771
    0x1.fffffd777a5e91e61f5380fb808d3272p-1,
    0x1.921fb4p-1
  },
  { // Entry 772
    -0x1.fffffd777a5e91e61f5380fb808d3272p-1,
    -0x1.921fb4p-1
  },
  { // Entry 773
    0x1.000000bbbd2ec06d6d6fff3655a346acp0,
    0x1.921fb6p-1
  },
  { // Entry 774
    -0x1.000000bbbd2ec06d6d6fff3655a346acp0,
    -0x1.921fb6p-1
  },
  { // Entry 775
    0x1.000002bbbd3237e7d114276ed329af5bp0,
    0x1.921fb8p-1
  },
  { // Entry 776
    -0x1.000002bbbd3237e7d114276ed329af5bp0,
    -0x1.921fb8p-1
  },
  { // Entry 777
    0x1.9437b336b6b0c479b2280999b19575c7p23,
  
"""


```
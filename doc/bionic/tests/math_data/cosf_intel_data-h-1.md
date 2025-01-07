Response:
The user wants to know the functionality of the provided C code snippet, which appears to be a data file containing pairs of floating-point numbers. The context "bionic/tests/math_data/cosf_intel_data.handroid" strongly suggests these are test data for the `cosf` function in Android's `bionic` math library. The ".handroid" suffix might indicate architecture-specific data for Android.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core functionality:** The code is a collection of pairs of floating-point numbers. Given the file path, the most likely interpretation is that these are input/output pairs for testing the `cosf` function. The first number in each pair is likely the input angle, and the second number is the expected cosine value.

2. **Relate to Android functionality:**  `cosf` is a standard C library function for calculating the cosine of a floating-point number. In Android, this function is part of the `bionic` library, which is the C standard library for Android. This data file is specifically used for testing the correctness of the `cosf` implementation on Android.

3. **Explain `libc` function implementation:** The `cosf` function is typically implemented using various techniques, including:
    * **Argument reduction:** Reducing the input angle to a smaller range (e.g., [0, pi/2]) using trigonometric identities.
    * **Taylor series or Chebyshev polynomials:** Approximating the cosine function using these mathematical series or polynomials.
    * **Lookup tables:** For certain ranges, precomputed values might be used for faster calculation.
    * **Hardware acceleration:**  On some architectures, dedicated hardware instructions might be available.

4. **Address dynamic linker aspects:** This specific data file *doesn't directly involve* the dynamic linker. It's a static data file. However, the `cosf` function itself *is* part of a shared library (`libc.so`), so it's linked dynamically. To explain this, I need to:
    * Provide a sample `libc.so` layout (simplified).
    * Explain the dynamic linking process for `cosf`: when a program calls `cosf`, the dynamic linker resolves the symbol and loads the necessary code from `libc.so`.

5. **Consider logical reasoning (input/output):**  The structure of the data provides the input and expected output. For example:
   * Input: `0x1.fc97283c4f5bd1f793201972b8db551fp-1` (approximately 1.98 in decimal)
   * Output: `-0x1.d8f720p-4` (approximately -0.115 in decimal).
   These pairs can be interpreted as `cos(input) = output`.

6. **Identify common usage errors:**  Users might make mistakes when using `cosf`, such as:
    * **Passing angles in degrees instead of radians:** The `cosf` function expects angles in radians.
    * **Incorrectly handling edge cases:**  Dealing with very large or very small input values.
    * **Floating-point precision issues:** Understanding that floating-point calculations are approximations.

7. **Explain how to reach this code from Android Framework/NDK:**
    * **Framework:** A Java application using `java.lang.Math.cos()` will eventually call native code. This native code, potentially within the Android Runtime (ART), will invoke the `cosf` function from `libc.so`.
    * **NDK:** A C/C++ application built with the NDK can directly call `cosf` by including `<math.h>`.

8. **Provide Frida hook examples:** Demonstrate how to intercept calls to `cosf` to observe the input and output values. This helps in debugging and understanding how the function is used.

9. **Summarize the functionality (Part 2):** Concisely state that the file contains test data for the `cosf` function in `bionic`, providing input values and their corresponding expected cosine values. This data is used for verifying the correctness of the `cosf` implementation.

10. **Structure the response:** Organize the information logically with clear headings and examples. Use the provided context (file path, "bionic") to guide the explanation. Ensure the language is Chinese as requested. Specifically for Part 2, focus on a high-level summary.
这是目录为bionic/tests/math_data/cosf_intel_data.handroid bionic的源代码文件的第2部分，主要包含了一系列用于测试 `cosf` 函数的数据。

**功能归纳 (第2部分):**

这部分代码的主要功能是**提供了一批用于测试 `cosf` 函数在特定输入下的预期输出值**。 具体来说，它定义了一个数组，其中每个元素都是一个包含两个 `double` 类型浮点数的结构体。

* **第一个浮点数:** 代表 `cosf` 函数的输入值 (以弧度表示的角度)。
* **第二个浮点数:** 代表在给定输入下，`cosf` 函数的预期输出值 (余弦值)。

这些数据是为了验证 `bionic` 库中 `cosf` 函数的实现是否正确，特别是在不同的输入范围内和精度下。  每一对数据都可以看作是一个独立的测试用例。

**结合上下文来看，整个 `cosf_intel_data.handroid` 文件的功能是：**

为 Android 系统 `bionic` 库中的单精度浮点余弦函数 `cosf` 提供全面的测试数据集。 这些数据可能针对 Intel 架构进行了优化或收集，并且涵盖了各种输入场景，包括：

* **正常值:**  常见的角度值。
* **边界值:**  接近于 0, π/2, π 等特殊角度的值。
* **大数值和小数值:**  用于测试数值稳定性和精度。
* **正负值:**  测试对不同符号的处理。

通过对比 `cosf` 函数的实际输出与这些预期的输出值，开发者可以确保该函数在 Android 系统上的正确性和可靠性。

**简而言之，这部分数据是 `cosf` 函数的测试用例库的一个片段，用于验证其在特定平台上的实现质量。**

Prompt: 
```
这是目录为bionic/tests/math_data/cosf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
  { // Entry 378
    0x1.fc97283c4f5bd1f793201972b8db551fp-1,
    -0x1.d8f720p-4
  },
  { // Entry 379
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    0x1.62b958p-3
  },
  { // Entry 380
    0x1.f856d49251bd37c54f0094270eecbd18p-1,
    -0x1.62b958p-3
  },
  { // Entry 381
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    0x1.d8f720p-3
  },
  { // Entry 382
    0x1.f26840efd86ceea23f388b6a1102ea4dp-1,
    -0x1.d8f720p-3
  },
  { // Entry 383
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    0x1.279a74p-2
  },
  { // Entry 384
    0x1.ead07cd2e0f7f19679646362bbc0eb80p-1,
    -0x1.279a74p-2
  },
  { // Entry 385
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    0x1.62b958p-2
  },
  { // Entry 386
    0x1.e1960273a4aaa1bd19ef0ccaa8874183p-1,
    -0x1.62b958p-2
  },
  { // Entry 387
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    0x1.9dd83cp-2
  },
  { // Entry 388
    0x1.d6c0b13df99613a49306b4dc6c57aa03p-1,
    -0x1.9dd83cp-2
  },
  { // Entry 389
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    0x1.d8f720p-2
  },
  { // Entry 390
    0x1.ca59c719f96075dd6b7a0ff443ad59dcp-1,
    -0x1.d8f720p-2
  },
  { // Entry 391
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    0x1.0a0b02p-1
  },
  { // Entry 392
    0x1.bc6bd889a8a59dbb56e546a37ae798f5p-1,
    -0x1.0a0b02p-1
  },
  { // Entry 393
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    0x1.3d3e36p-1
  },
  { // Entry 394
    0x1.a0d1f8613ebc60c7ee6502ee183c89e7p-1,
    -0x1.3d3e36p-1
  },
  { // Entry 395
    0x1.93e293b23a6aa1ae5373214eb8fb9e96p-1,
    0x1.52e1f8p-1
  },
  { // Entry 396
    0x1.93e293b23a6aa1ae5373214eb8fb9e96p-1,
    -0x1.52e1f8p-1
  },
  { // Entry 397
    0x1.863a83a8d9826c6135509406ebe05c0fp-1,
    0x1.6885bap-1
  },
  { // Entry 398
    0x1.863a83a8d9826c6135509406ebe05c0fp-1,
    -0x1.6885bap-1
  },
  { // Entry 399
    0x1.77e006c87cbaded66ec5b960c93c568ap-1,
    0x1.7e297cp-1
  },
  { // Entry 400
    0x1.77e006c87cbaded66ec5b960c93c568ap-1,
    -0x1.7e297cp-1
  },
  { // Entry 401
    0x1.68d9ad29736c1704caea6a2db6e71223p-1,
    0x1.93cd3ep-1
  },
  { // Entry 402
    0x1.68d9ad29736c1704caea6a2db6e71223p-1,
    -0x1.93cd3ep-1
  },
  { // Entry 403
    0x1.592e5578c9ec66acceddd4dc6ce66b26p-1,
    0x1.a971p-1
  },
  { // Entry 404
    0x1.592e5578c9ec66acceddd4dc6ce66b26p-1,
    -0x1.a971p-1
  },
  { // Entry 405
    0x1.48e529d429e721ec8bb1e014f94d48f1p-1,
    0x1.bf14c2p-1
  },
  { // Entry 406
    0x1.48e529d429e721ec8bb1e014f94d48f1p-1,
    -0x1.bf14c2p-1
  },
  { // Entry 407
    0x1.38059c833c58ea970f7b96d6ada3d9c4p-1,
    0x1.d4b884p-1
  },
  { // Entry 408
    0x1.38059c833c58ea970f7b96d6ada3d9c4p-1,
    -0x1.d4b884p-1
  },
  { // Entry 409
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    0x1.ea5c3ep-1
  },
  { // Entry 410
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    -0x1.ea5c3ep-1
  },
  { // Entry 411
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    0x1.12bd92p0
  },
  { // Entry 412
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    -0x1.12bd92p0
  },
  { // Entry 413
    0x1.a5a4c8f598fa0078971316eb4907f97bp-2,
    0x1.257b24p0
  },
  { // Entry 414
    0x1.a5a4c8f598fa0078971316eb4907f97bp-2,
    -0x1.257b24p0
  },
  { // Entry 415
    0x1.60435beed10ca05769f0a3d86a5a20f3p-2,
    0x1.3838b6p0
  },
  { // Entry 416
    0x1.60435beed10ca05769f0a3d86a5a20f3p-2,
    -0x1.3838b6p0
  },
  { // Entry 417
    0x1.18fee0fc45c31a79b2b9478b1f72a9ebp-2,
    0x1.4af648p0
  },
  { // Entry 418
    0x1.18fee0fc45c31a79b2b9478b1f72a9ebp-2,
    -0x1.4af648p0
  },
  { // Entry 419
    0x1.a072252090c33828767aee3e040ccddfp-3,
    0x1.5db3dap0
  },
  { // Entry 420
    0x1.a072252090c33828767aee3e040ccddfp-3,
    -0x1.5db3dap0
  },
  { // Entry 421
    0x1.0cab7703a8e9dacc4ad01188b443cfeep-3,
    0x1.70716cp0
  },
  { // Entry 422
    0x1.0cab7703a8e9dacc4ad01188b443cfeep-3,
    -0x1.70716cp0
  },
  { // Entry 423
    0x1.ddd171a3c9851e7819b5e4f6f90e763dp-5,
    0x1.832efep0
  },
  { // Entry 424
    0x1.ddd171a3c9851e7819b5e4f6f90e763dp-5,
    -0x1.832efep0
  },
  { // Entry 425
    -0x1.e668cb154eea68bbc7f8154f46b2e536p-7,
    0x1.95ec90p0
  },
  { // Entry 426
    -0x1.e668cb154eea68bbc7f8154f46b2e536p-7,
    -0x1.95ec90p0
  },
  { // Entry 427
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    0x1.a8aa1cp0
  },
  { // Entry 428
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    -0x1.a8aa1cp0
  },
  { // Entry 429
    0x1.0cb3449a0d0a9e0643d41f4a5b0f7db7p-1,
    0x1.04aff8p0
  },
  { // Entry 430
    0x1.0cb3449a0d0a9e0643d41f4a5b0f7db7p-1,
    -0x1.04aff8p0
  },
  { // Entry 431
    0x1.0cb22697153bcf1f8a63acddd96c54cbp-1,
    0x1.04b0a0p0
  },
  { // Entry 432
    0x1.0cb22697153bcf1f8a63acddd96c54cbp-1,
    -0x1.04b0a0p0
  },
  { // Entry 433
    0x1.0cb10893a9b5471a44356072cb33b395p-1,
    0x1.04b148p0
  },
  { // Entry 434
    0x1.0cb10893a9b5471a44356072cb33b395p-1,
    -0x1.04b148p0
  },
  { // Entry 435
    0x1.0cafea8fca7781236a57e5b1c8aed39cp-1,
    0x1.04b1f0p0
  },
  { // Entry 436
    0x1.0cafea8fca7781236a57e5b1c8aed39cp-1,
    -0x1.04b1f0p0
  },
  { // Entry 437
    0x1.0caecc8b7782f86827af92b0b2374510p-1,
    0x1.04b298p0
  },
  { // Entry 438
    0x1.0caecc8b7782f86827af92b0b2374510p-1,
    -0x1.04b298p0
  },
  { // Entry 439
    0x1.0cadae86b0d82815d8f632e67c7e1a99p-1,
    0x1.04b340p0
  },
  { // Entry 440
    0x1.0cadae86b0d82815d8f632e67c7e1a99p-1,
    -0x1.04b340p0
  },
  { // Entry 441
    0x1.0cac908176778b5a0cbad21ee75ce765p-1,
    0x1.04b3e8p0
  },
  { // Entry 442
    0x1.0cac908176778b5a0cbad21ee75ce765p-1,
    -0x1.04b3e8p0
  },
  { // Entry 443
    0x1.0cab727bc8619d628361876e1f30a633p-1,
    0x1.04b490p0
  },
  { // Entry 444
    0x1.0cab727bc8619d628361876e1f30a633p-1,
    -0x1.04b490p0
  },
  { // Entry 445
    0x1.0caa5b450a4324f204a556b072da124ap-1,
    0x1.04b534p0
  },
  { // Entry 446
    0x1.0caa5b450a4324f204a556b072da124ap-1,
    -0x1.04b534p0
  },
  { // Entry 447
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 448
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 449
    0x1.p0,
    0.0
  },
  { // Entry 450
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 451
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 452
    0x1.ad02c8b9cc93f448ef4eb068a88922a3p-1,
    0x1.279a72p-1
  },
  { // Entry 453
    0x1.ad02c8b9cc93f448ef4eb068a88922a3p-1,
    -0x1.279a72p-1
  },
  { // Entry 454
    0x1.ad02c7a258bfb362abbe86fb48f4e98bp-1,
    0x1.279a74p-1
  },
  { // Entry 455
    0x1.ad02c7a258bfb362abbe86fb48f4e98bp-1,
    -0x1.279a74p-1
  },
  { // Entry 456
    0x1.ad02c68ae4e9c579a08c04ce59be4002p-1,
    0x1.279a76p-1
  },
  { // Entry 457
    0x1.ad02c68ae4e9c579a08c04ce59be4002p-1,
    -0x1.279a76p-1
  },
  { // Entry 458
    -0x1.48d1c9e98b6c08784f10040f47a12191p-3,
    0x1.bb67acp0
  },
  { // Entry 459
    -0x1.48d1c9e98b6c08784f10040f47a12191p-3,
    -0x1.bb67acp0
  },
  { // Entry 460
    -0x1.48d1d9b467e37955337311decd09fc74p-3,
    0x1.bb67aep0
  },
  { // Entry 461
    -0x1.48d1d9b467e37955337311decd09fc74p-3,
    -0x1.bb67aep0
  },
  { // Entry 462
    -0x1.48d1e97f4455c6eab1048022238b2bd0p-3,
    0x1.bb67b0p0
  },
  { // Entry 463
    -0x1.48d1e97f4455c6eab1048022238b2bd0p-3,
    -0x1.bb67b0p0
  },
  { // Entry 464
    0x1.cfc6d011a0e5d0fcebb54b5fed672940p-1,
    0x1.bffffep-2
  },
  { // Entry 465
    0x1.cfc6d011a0e5d0fcebb54b5fed672940p-1,
    -0x1.bffffep-2
  },
  { // Entry 466
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    0x1.c0p-2
  },
  { // Entry 467
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    -0x1.c0p-2
  },
  { // Entry 468
    0x1.cfc6cf38b4cda76c3b09b17e9deb19eap-1,
    0x1.c00002p-2
  },
  { // Entry 469
    0x1.cfc6cf38b4cda76c3b09b17e9deb19eap-1,
    -0x1.c00002p-2
  },
  { // Entry 470
    0x1.8bb106eac7c75d33fbb19446313ecc2fp-1,
    0x1.5ffffep-1
  },
  { // Entry 471
    0x1.8bb106eac7c75d33fbb19446313ecc2fp-1,
    -0x1.5ffffep-1
  },
  { // Entry 472
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    0x1.60p-1
  },
  { // Entry 473
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    -0x1.60p-1
  },
  { // Entry 474
    0x1.8bb10460f157234ceec7d9644a1a78e5p-1,
    0x1.600002p-1
  },
  { // Entry 475
    0x1.8bb10460f157234ceec7d9644a1a78e5p-1,
    -0x1.600002p-1
  },
  { // Entry 476
    0x1.7ef48b9a6fd5c24f5ec39839e1729b78p-2,
    0x1.2ffffep0
  },
  { // Entry 477
    0x1.7ef48b9a6fd5c24f5ec39839e1729b78p-2,
    -0x1.2ffffep0
  },
  { // Entry 478
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    0x1.30p0
  },
  { // Entry 479
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    -0x1.30p0
  },
  { // Entry 480
    0x1.7ef47cc3a7bdedf9252074263d8a4596p-2,
    0x1.300002p0
  },
  { // Entry 481
    0x1.7ef47cc3a7bdedf9252074263d8a4596p-2,
    -0x1.300002p0
  },
  { // Entry 482
    -0x1.863ef5085bcc358d2ae8525bf39f0c40p-1,
    0x1.37fffep1
  },
  { // Entry 483
    -0x1.863ef5085bcc358d2ae8525bf39f0c40p-1,
    -0x1.37fffep1
  },
  { // Entry 484
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    0x1.38p1
  },
  { // Entry 485
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    -0x1.38p1
  },
  { // Entry 486
    -0x1.863eff63dfa00bfc758baf469469d741p-1,
    0x1.380002p1
  },
  { // Entry 487
    -0x1.863eff63dfa00bfc758baf469469d741p-1,
    -0x1.380002p1
  },
  { // Entry 488
    0x1.fef2b2d0a10e2739c566936480a1479bp-1,
    0x1.069c8cp-4
  },
  { // Entry 489
    0x1.fef2b2d0a10e2739c566936480a1479bp-1,
    -0x1.069c8cp-4
  },
  { // Entry 490
    0x1.fbcbe68dd10bad0a229ccbb580cc5436p-1,
    0x1.069c8cp-3
  },
  { // Entry 491
    0x1.fbcbe68dd10bad0a229ccbb580cc5436p-1,
    -0x1.069c8cp-3
  },
  { // Entry 492
    0x1.f68eebef72e7f6126b3f3dde646a755cp-1,
    0x1.89ead2p-3
  },
  { // Entry 493
    0x1.f68eebef72e7f6126b3f3dde646a755cp-1,
    -0x1.89ead2p-3
  },
  { // Entry 494
    0x1.ef41459d2e90ea1b7faad7fabd1fd444p-1,
    0x1.069c8cp-2
  },
  { // Entry 495
    0x1.ef41459d2e90ea1b7faad7fabd1fd444p-1,
    -0x1.069c8cp-2
  },
  { // Entry 496
    0x1.e5eaa23a27fe8d6890a3edace1c61998p-1,
    0x1.4843b0p-2
  },
  { // Entry 497
    0x1.e5eaa23a27fe8d6890a3edace1c61998p-1,
    -0x1.4843b0p-2
  },
  { // Entry 498
    0x1.da94d4b99c3a9a5e0d1fc86d53369a84p-1,
    0x1.89ead4p-2
  },
  { // Entry 499
    0x1.da94d4b99c3a9a5e0d1fc86d53369a84p-1,
    -0x1.89ead4p-2
  },
  { // Entry 500
    0x1.cd4bc9afc01230b2f982f6968dab7f05p-1,
    0x1.cb91f8p-2
  },
  { // Entry 501
    0x1.cd4bc9afc01230b2f982f6968dab7f05p-1,
    -0x1.cb91f8p-2
  },
  { // Entry 502
    0x1.be1d7adf077def2a360fec23dbbcef09p-1,
    0x1.069c8ep-1
  },
  { // Entry 503
    0x1.be1d7adf077def2a360fec23dbbcef09p-1,
    -0x1.069c8ep-1
  },
  { // Entry 504
    0x1.ad19e0847d25f3aa142289dab557bf96p-1,
    0x1.277020p-1
  },
  { // Entry 505
    0x1.ad19e0847d25f3aa142289dab557bf96p-1,
    -0x1.277020p-1
  },
  { // Entry 506
    0x1.9a52e08b191bd55512c8365074f1987fp-1,
    0x1.4843b2p-1
  },
  { // Entry 507
    0x1.9a52e08b191bd55512c8365074f1987fp-1,
    -0x1.4843b2p-1
  },
  { // Entry 508
    0x1.85dc3bb7c2e9abb5cccb6d96d12d39c4p-1,
    0x1.691744p-1
  },
  { // Entry 509
    0x1.85dc3bb7c2e9abb5cccb6d96d12d39c4p-1,
    -0x1.691744p-1
  },
  { // Entry 510
    0x1.6fcb78e1cd65d2e4fde7118caac79d6dp-1,
    0x1.89ead6p-1
  },
  { // Entry 511
    0x1.6fcb78e1cd65d2e4fde7118caac79d6dp-1,
    -0x1.89ead6p-1
  },
  { // Entry 512
    0x1.5837ce4dc835d4a5454ec0a1bb394081p-1,
    0x1.aabe68p-1
  },
  { // Entry 513
    0x1.5837ce4dc835d4a5454ec0a1bb394081p-1,
    -0x1.aabe68p-1
  },
  { // Entry 514
    0x1.3f3a09427966e9518802dee3bf443a95p-1,
    0x1.cb91fap-1
  },
  { // Entry 515
    0x1.3f3a09427966e9518802dee3bf443a95p-1,
    -0x1.cb91fap-1
  },
  { // Entry 516
    0x1.24ec73f1aeef4940bb8da19a82bbc49fp-1,
    0x1.ec658cp-1
  },
  { // Entry 517
    0x1.24ec73f1aeef4940bb8da19a82bbc49fp-1,
    -0x1.ec658cp-1
  },
  { // Entry 518
    0x1.096abb862f9bd5515982c2818c332ff9p-1,
    0x1.069c8ep0
  },
  { // Entry 519
    0x1.096abb862f9bd5515982c2818c332ff9p-1,
    -0x1.069c8ep0
  },
  { // Entry 520
    0x1.d9a39c0dddc654c717e3036da5dd685cp-2,
    0x1.170656p0
  },
  { // Entry 521
    0x1.d9a39c0dddc654c717e3036da5dd685cp-2,
    -0x1.170656p0
  },
  { // Entry 522
    0x1.9e7f81840c0bbd0f1b13733061062d34p-2,
    0x1.27701ep0
  },
  { // Entry 523
    0x1.9e7f81840c0bbd0f1b13733061062d34p-2,
    -0x1.27701ep0
  },
  { // Entry 524
    0x1.61a75e2deb596731c8cd45e3d9794526p-2,
    0x1.37d9e6p0
  },
  { // Entry 525
    0x1.61a75e2deb596731c8cd45e3d9794526p-2,
    -0x1.37d9e6p0
  },
  { // Entry 526
    0x1.235b337b091cdd8ac06390abc6816b82p-2,
    0x1.4843aep0
  },
  { // Entry 527
    0x1.235b337b091cdd8ac06390abc6816b82p-2,
    -0x1.4843aep0
  },
  { // Entry 528
    0x1.c7b9146d6d10824ff652dc390ba2d7f9p-3,
    0x1.58ad76p0
  },
  { // Entry 529
    0x1.c7b9146d6d10824ff652dc390ba2d7f9p-3,
    -0x1.58ad76p0
  },
  { // Entry 530
    0x1.46dc5b2f1de977efff7c278b5adb2a75p-3,
    0x1.69173ep0
  },
  { // Entry 531
    0x1.46dc5b2f1de977efff7c278b5adb2a75p-3,
    -0x1.69173ep0
  },
  { // Entry 532
    0x1.894f93ef49c4575800bbd646a3a31d2ap-4,
    0x1.798106p0
  },
  { // Entry 533
    0x1.894f93ef49c4575800bbd646a3a31d2ap-4,
    -0x1.798106p0
  },
  { // Entry 534
    0x1.069164e3f5cee94d865fb52e316dff6bp-5,
    0x1.89eacep0
  },
  { // Entry 535
    0x1.069164e3f5cee94d865fb52e316dff6bp-5,
    -0x1.89eacep0
  },
  { // Entry 536
    -0x1.069093eec0ed066ec83dd034498ef8bfp-5,
    0x1.9a5496p0
  },
  { // Entry 537
    -0x1.069093eec0ed066ec83dd034498ef8bfp-5,
    -0x1.9a5496p0
  },
  { // Entry 538
    -0x1.894f2be2979dd9ced83ccc60cf49cd44p-4,
    0x1.aabe5ep0
  },
  { // Entry 539
    -0x1.894f2be2979dd9ced83ccc60cf49cd44p-4,
    -0x1.aabe5ep0
  },
  { // Entry 540
    -0x1.46dc2796735195a15c80e5b719e2fc42p-3,
    0x1.bb2826p0
  },
  { // Entry 541
    -0x1.46dc2796735195a15c80e5b719e2fc42p-3,
    -0x1.bb2826p0
  },
  { // Entry 542
    -0x1.c7b8e178b7e8c01d9f320466cc7a68d4p-3,
    0x1.cb91eep0
  },
  { // Entry 543
    -0x1.c7b8e178b7e8c01d9f320466cc7a68d4p-3,
    -0x1.cb91eep0
  },
  { // Entry 544
    -0x1.235b1a6d767e4b362c64571ac97b4a1cp-2,
    0x1.dbfbb6p0
  },
  { // Entry 545
    -0x1.235b1a6d767e4b362c64571ac97b4a1cp-2,
    -0x1.dbfbb6p0
  },
  { // Entry 546
    -0x1.61a745a77b7e83c2f8a2f9b091e89aaap-2,
    0x1.ec657ep0
  },
  { // Entry 547
    -0x1.61a745a77b7e83c2f8a2f9b091e89aaap-2,
    -0x1.ec657ep0
  },
  { // Entry 548
    -0x1.9e7f699e8b9aaf8ed51c71c8f73b0b74p-2,
    0x1.fccf46p0
  },
  { // Entry 549
    -0x1.9e7f699e8b9aaf8ed51c71c8f73b0b74p-2,
    -0x1.fccf46p0
  },
  { // Entry 550
    -0x1.d9a38bfa3195ba1caa7fb69bc1d04e42p-2,
    0x1.069c88p1
  },
  { // Entry 551
    -0x1.d9a38bfa3195ba1caa7fb69bc1d04e42p-2,
    -0x1.069c88p1
  },
  { // Entry 552
    -0x1.096ab3c55c91f36e2359ed1c5a8342dfp-1,
    0x1.0ed16cp1
  },
  { // Entry 553
    -0x1.096ab3c55c91f36e2359ed1c5a8342dfp-1,
    -0x1.0ed16cp1
  },
  { // Entry 554
    -0x1.24ec6c8206e744322d99f47e9e41becep-1,
    0x1.170650p1
  },
  { // Entry 555
    -0x1.24ec6c8206e744322d99f47e9e41becep-1,
    -0x1.170650p1
  },
  { // Entry 556
    -0x1.3f3a009b82b5b8234e1296dd73cff49dp-1,
    0x1.1f3b34p1
  },
  { // Entry 557
    -0x1.3f3a009b82b5b8234e1296dd73cff49dp-1,
    -0x1.1f3b34p1
  },
  { // Entry 558
    -0x1.5837c4a184ccf7ed57c189f2addf32c5p-1,
    0x1.277018p1
  },
  { // Entry 559
    -0x1.5837c4a184ccf7ed57c189f2addf32c5p-1,
    -0x1.277018p1
  },
  { // Entry 560
    -0x1.6fcb6e6685e72fb4074e70cd3162d3bap-1,
    0x1.2fa4fcp1
  },
  { // Entry 561
    -0x1.6fcb6e6685e72fb4074e70cd3162d3bap-1,
    -0x1.2fa4fcp1
  },
  { // Entry 562
    -0x1.85dc30a79f26754ab1370338ee7bfd11p-1,
    0x1.37d9e0p1
  },
  { // Entry 563
    -0x1.85dc30a79f26754ab1370338ee7bfd11p-1,
    -0x1.37d9e0p1
  },
  { // Entry 564
    -0x1.9a52d523b1532e4ed477e27dc6051c12p-1,
    0x1.400ec4p1
  },
  { // Entry 565
    -0x1.9a52d523b1532e4ed477e27dc6051c12p-1,
    -0x1.400ec4p1
  },
  { // Entry 566
    -0x1.ad19d50664abf0c0141137d2ca509f21p-1,
    0x1.4843a8p1
  },
  { // Entry 567
    -0x1.ad19d50664abf0c0141137d2ca509f21p-1,
    -0x1.4843a8p1
  },
  { // Entry 568
    -0x1.be1d6f8d517db5c2cf7de0faf0808d30p-1,
    0x1.50788cp1
  },
  { // Entry 569
    -0x1.be1d6f8d517db5c2cf7de0faf0808d30p-1,
    -0x1.50788cp1
  },
  { // Entry 570
    -0x1.cd4bbecf7f2705d4fd00dd463780f45ep-1,
    0x1.58ad70p1
  },
  { // Entry 571
    -0x1.cd4bbecf7f2705d4fd00dd463780f45ep-1,
    -0x1.58ad70p1
  },
  { // Entry 572
    -0x1.da94ca915da3cdd1fff839d85eec39e2p-1,
    0x1.60e254p1
  },
  { // Entry 573
    -0x1.da94ca915da3cdd1fff839d85eec39e2p-1,
    -0x1.60e254p1
  },
  { // Entry 574
    -0x1.e5ea99116b39361ac926dd9fdc2089d1p-1,
    0x1.691738p1
  },
  { // Entry 575
    -0x1.e5ea99116b39361ac926dd9fdc2089d1p-1,
    -0x1.691738p1
  },
  { // Entry 576
    -0x1.ef413dbbda2859ffb0d1ab84342fd235p-1,
    0x1.714c1cp1
  },
  { // Entry 577
    -0x1.ef413dbbda2859ffb0d1ab84342fd235p-1,
    -0x1.714c1cp1
  },
  { // Entry 578
    -0x1.f68ee5b5bf356b10230944a18e70925cp-1,
    0x1.7981p1
  },
  { // Entry 579
    -0x1.f68ee5b5bf356b10230944a18e70925cp-1,
    -0x1.7981p1
  },
  { // Entry 580
    -0x1.fbcbe23296fc61b96f382f35ea15c768p-1,
    0x1.81b5e4p1
  },
  { // Entry 581
    -0x1.fbcbe23296fc61b96f382f35ea15c768p-1,
    -0x1.81b5e4p1
  },
  { // Entry 582
    -0x1.fef2b08943197cd3a8ba861095227c48p-1,
    0x1.89eac8p1
  },
  { // Entry 583
    -0x1.fef2b08943197cd3a8ba861095227c48p-1,
    -0x1.89eac8p1
  },
  { // Entry 584
    0x1.ef41489fc2fe801a6fc8ae791438eb78p-1,
    -0x1.81b5eep2
  },
  { // Entry 585
    0x1.ef41489fc2fe801a6fc8ae791438eb78p-1,
    0x1.81b5eep2
  },
  { // Entry 586
    0x1.be1d849ec649b797320e985d0b82ae85p-1,
    -0x1.714c26p2
  },
  { // Entry 587
    0x1.be1d849ec649b797320e985d0b82ae85p-1,
    0x1.714c26p2
  },
  { // Entry 588
    0x1.6fcb8c44bd30dd668148605969b1c161p-1,
    -0x1.60e25ep2
  },
  { // Entry 589
    0x1.6fcb8c44bd30dd668148605969b1c161p-1,
    0x1.60e25ep2
  },
  { // Entry 590
    0x1.096ad87c326622c42de34f92814cfa84p-1,
    -0x1.507896p2
  },
  { // Entry 591
    0x1.096ad87c326622c42de34f92814cfa84p-1,
    0x1.507896p2
  },
  { // Entry 592
    0x1.235b746a2a2eff2bf640dd8c04d35a5bp-2,
    -0x1.400ecep2
  },
  { // Entry 593
    0x1.235b746a2a2eff2bf640dd8c04d35a5bp-2,
    0x1.400ecep2
  },
  { // Entry 594
    0x1.0693827b46cee3b661ac17114b5fe0fbp-5,
    -0x1.2fa506p2
  },
  { // Entry 595
    0x1.0693827b46cee3b661ac17114b5fe0fbp-5,
    0x1.2fa506p2
  },
  { // Entry 596
    -0x1.c7b85d668e2abcc46542ca8527f0b801p-3,
    -0x1.1f3b3ep2
  },
  { // Entry 597
    -0x1.c7b85d668e2abcc46542ca8527f0b801p-3,
    0x1.1f3b3ep2
  },
  { // Entry 598
    -0x1.d9a348d4f4363ba4562110db01ee84e8p-2,
    -0x1.0ed176p2
  },
  { // Entry 599
    -0x1.d9a348d4f4363ba4562110db01ee84e8p-2,
    0x1.0ed176p2
  },
  { // Entry 600
    -0x1.5837ae8569c95846e6164d9636546120p-1,
    -0x1.fccf5ap1
  },
  { // Entry 601
    -0x1.5837ae8569c95846e6164d9636546120p-1,
    0x1.fccf5ap1
  },
  { // Entry 602
    -0x1.ad19c918883000b0b702ec080cf0122ep-1,
    -0x1.dbfbc8p1
  },
  { // Entry 603
    -0x1.ad19c918883000b0b702ec080cf0122ep-1,
    0x1.dbfbc8p1
  },
  { // Entry 604
    -0x1.e5ea94b2cf07add3d0d95ab3a30ad4abp-1,
    -0x1.bb2836p1
  },
  { // Entry 605
    -0x1.e5ea94b2cf07add3d0d95ab3a30ad4abp-1,
    0x1.bb2836p1
  },
  { // Entry 606
    -0x1.fef2b02908559f92de892d240a2b0b49p-1,
    -0x1.9a54a4p1
  },
  { // Entry 607
    -0x1.fef2b02908559f92de892d240a2b0b49p-1,
    0x1.9a54a4p1
  },
  { // Entry 608
    -0x1.f68ef3792e592c3cefbce1d5ded64a92p-1,
    -0x1.798112p1
  },
  { // Entry 609
    -0x1.f68ef3792e592c3cefbce1d5ded64a92p-1,
    0x1.798112p1
  },
  { // Entry 610
    -0x1.cd4bda943eea13630f8e508f8744f2f2p-1,
    -0x1.58ad80p1
  },
  { // Entry 611
    -0x1.cd4bda943eea13630f8e508f8744f2f2p-1,
    0x1.58ad80p1
  },
  { // Entry 612
    -0x1.85dc54f49f324bdfc71d5749483b3318p-1,
    -0x1.37d9eep1
  },
  { // Entry 613
    -0x1.85dc54f49f324bdfc71d5749483b3318p-1,
    0x1.37d9eep1
  },
  { // Entry 614
    -0x1.24ec93e04d4bdb54e20beaf383519af8p-1,
    -0x1.17065cp1
  },
  { // Entry 615
    -0x1.24ec93e04d4bdb54e20beaf383519af8p-1,
    0x1.17065cp1
  },
  { // Entry 616
    -0x1.61a7983d4c16c451b68bf2f5b70f3b6ap-2,
    -0x1.ec6594p0
  },
  { // Entry 617
    -0x1.61a7983d4c16c451b68bf2f5b70f3b6ap-2,
    0x1.ec6594p0
  },
  { // Entry 618
    -0x1.89504a8de6c9ecac663e67583cab47e8p-4,
    -0x1.aabe70p0
  },
  { // Entry 619
    -0x1.89504a8de6c9ecac663e67583cab47e8p-4,
    0x1.aabe70p0
  },
  { // Entry 620
    0x1.46dbec9ea3a5f08ba73aa69e7e22de1cp-3,
    -0x1.69174cp0
  },
  { // Entry 621
    0x1.46dbec9ea3a5f08ba73aa69e7e22de1cp-3,
    0x1.69174cp0
  },
  { // Entry 622
    0x1.9e7f5cf075d1ec4ef69c9c67b62c27cbp-2,
    -0x1.277028p0
  },
  { // Entry 623
    0x1.9e7f5cf075d1ec4ef69c9c67b62c27cbp-2,
    0x1.277028p0
  },
  { // Entry 624
    0x1.3f39fcc017653d2636837a55fdf6d2d4p-1,
    -0x1.cb920ap-1
  },
  { // Entry 625
    0x1.3f39fcc017653d2636837a55fdf6d2d4p-1,
    0x1.cb920ap-1
  },
  { // Entry 626
    0x1.9a52d5c700daa3dc8cf8f5a71f2df289p-1,
    -0x1.4843c4p-1
  },
  { // Entry 627
    0x1.9a52d5c700daa3dc8cf8f5a71f2df289p-1,
    0x1.4843c4p-1
  },
  { // Entry 628
    0x1.da94cd383dd7a3b91a2fc88ff905a6a0p-1,
    -0x1.89eafcp-2
  },
  { // Entry 629
    0x1.da94cd383dd7a3b91a2fc88ff905a6a0p-1,
    0x1.89eafcp-2
  },
  { // Entry 630
    0x1.fbcbe3de58e66c3283bc810d16c45833p-1,
    -0x1.069ce0p-3
  },
  { // Entry 631
    0x1.fbcbe3de58e66c3283bc810d16c45833p-1,
    0x1.069ce0p-3
  },
  { // Entry 632
    0x1.fbcbe93d48563d51b6e9d6efdb62495cp-1,
    0x1.069c38p-3
  },
  { // Entry 633
    0x1.fbcbe93d48563d51b6e9d6efdb62495cp-1,
    -0x1.069c38p-3
  },
  { // Entry 634
    0x1.da94dcfb1cd15853ce848ffb0264ad08p-1,
    0x1.89eaa8p-2
  },
  { // Entry 635
    0x1.da94dcfb1cd15853ce848ffb0264ad08p-1,
    -0x1.89eaa8p-2
  },
  { // Entry 636
    0x1.9a52eee5e35377d554ace881bdc4725bp-1,
    0x1.48439ap-1
  },
  { // Entry 637
    0x1.9a52eee5e35377d554ace881bdc4725bp-1,
    -0x1.48439ap-1
  },
  { // Entry 638
    0x1.3f3a1d9657ff6aa498c46f6faaf03b90p-1,
    0x1.cb91e0p-1
  },
  { // Entry 639
    0x1.3f3a1d9657ff6aa498c46f6faaf03b90p-1,
    -0x1.cb91e0p-1
  },
  { // Entry 640
    0x1.9e7fa617a1a3a400a7f59aa879088e31p-2,
    0x1.277014p0
  },
  { // Entry 641
    0x1.9e7fa617a1a3a400a7f59aa879088e31p-2,
    -0x1.277014p0
  },
  { // Entry 642
    0x1.46dc8a919b27840cda6e18a079da459cp-3,
    0x1.691738p0
  },
  { // Entry 643
    0x1.46dc8a919b27840cda6e18a079da459cp-3,
    -0x1.691738p0
  },
  { // Entry 644
    -0x1.894f0c0872415663b7f9e4e4801deaf0p-4,
    0x1.aabe5cp0
  },
  { // Entry 645
    -0x1.894f0c0872415663b7f9e4e4801deaf0p-4,
    -0x1.aabe5cp0
  },
  { // Entry 646
    -0x1.61a74d29774ae4e3bc5533a2ea08a14ap-2,
    0x1.ec6580p0
  },
  { // Entry 647
    -0x1.61a74d29774ae4e3bc5533a2ea08a14ap-2,
    -0x1.ec6580p0
  },
  { // Entry 648
    -0x1.24ec7311bd7b2255f9b890b3ff5899f4p-1,
    0x1.170652p1
  },
  { // Entry 649
    -0x1.24ec7311bd7b2255f9b890b3ff5899f4p-1,
    -0x1.170652p1
  },
  { // Entry 650
    -0x1.85dc3b06c435f524c873d9b5eba3def8p-1,
    0x1.37d9e4p1
  },
  { // Entry 651
    -0x1.85dc3b06c435f524c873d9b5eba3def8p-1,
    -0x1.37d9e4p1
  },
  { // Entry 652
    -0x1.cd4bc93947e86671ac7f0eacd9521377p-1,
    0x1.58ad76p1
  },
  { // Entry 653
    -0x1.cd4bc93947e86671ac7f0eacd9521377p-1,
    -0x1.58ad76p1
  },
  { // Entry 654
    -0x1.f68eebd3b8f12f9433e6d7224989c10ep-1,
    0x1.798108p1
  },
  { // Entry 655
    -0x1.f68eebd3b8f12f9433e6d7224989c10ep-1,
    -0x1.798108p1
  },
  { // Entry 656
    -0x1.fef2b2b91e40021a2fee74fc61812157p-1,
    0x1.9a549ap1
  },
  { // Entry 657
    -0x1.fef2b2b91e40021a2fee74fc61812157p-1,
    -0x1.9a549ap1
  },
  { // Entry 658
    -0x1.e5eaa14d86168b69918c22f3716a67eap-1,
    0x1.bb282cp1
  },
  { // Entry 659
    -0x1.e5eaa14d86168b69918c22f3716a67eap-1,
    -0x1.bb282cp1
  },
  { // Entry 660
    -0x1.ad19deead0eae2f72d04165e09e4a43dp-1,
    0x1.dbfbbep1
  },
  { // Entry 661
    -0x1.ad19deead0eae2f72d04165e09e4a43dp-1,
    -0x1.dbfbbep1
  },
  { // Entry 662
    -0x1.5837cc21dda44f3ab7fd96f57c014e19p-1,
    0x1.fccf50p1
  },
  { // Entry 663
    -0x1.5837cc21dda44f3ab7fd96f57c014e19p-1,
    -0x1.fccf50p1
  },
  { // Entry 664
    -0x1.d9a39df207139f99ebe9b56dafb234b7p-2,
    0x1.0ed170p2
  },
  { // Entry 665
    -0x1.d9a39df207139f99ebe9b56dafb234b7p-2,
    -0x1.0ed170p2
  },
  { // Entry 666
    -0x1.c7b9189638128bc0ae33fdf2729cc987p-3,
    0x1.1f3b38p2
  },
  { // Entry 667
    -0x1.c7b9189638128bc0ae33fdf2729cc987p-3,
    -0x1.1f3b38p2
  },
  { // Entry 668
    0x1.069082e04b25e9d2ea9e263b50d08b34p-5,
    0x1.2fa5p2
  },
  { // Entry 669
    0x1.069082e04b25e9d2ea9e263b50d08b34p-5,
    -0x1.2fa5p2
  },
  { // Entry 670
    0x1.235b1861f21aa86dce259e4e5b4ef395p-2,
    0x1.400ec8p2
  },
  { // Entry 671
    0x1.235b1861f21aa86dce259e4e5b4ef395p-2,
    -0x1.400ec8p2
  },
  { // Entry 672
    0x1.096aaf70341485062f443c80a90a3be3p-1,
    0x1.507890p2
  },
  { // Entry 673
    0x1.096aaf70341485062f443c80a90a3be3p-1,
    -0x1.507890p2
  },
  { // Entry 674
    0x1.6fcb6ae03107be458d07361371efabb4p-1,
    0x1.60e258p2
  },
  { // Entry 675
    0x1.6fcb6ae03107be458d07361371efabb4p-1,
    -0x1.60e258p2
  },
  { // Entry 676
    0x1.be1d6d10d5c8ceeb8bf9aeb7a9f690b9p-1,
    0x1.714c20p2
  },
  { // Entry 677
    0x1.be1d6d10d5c8ceeb8bf9aeb7a9f690b9p-1,
    -0x1.714c20p2
  },
  { // Entry 678
    0x1.ef413c72d988bb53937975e4fd4fcc7ap-1,
    0x1.81b5e8p2
  },
  { // Entry 679
    0x1.ef413c72d988bb53937975e4fd4fcc7ap-1,
    -0x1.81b5e8p2
  },
  { // Entry 680
    0x1.ff0fd2cb5a9228cfa1e01605d0626c84p-1,
    0x1.effffep-5
  },
  { // Entry 681
    0x1.ff0fd2cb5a9228cfa1e01605d0626c84p-1,
    -0x1.effffep-5
  },
  { // Entry 682
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    0x1.f0p-5
  },
  { // Entry 683
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    -0x1.f0p-5
  },
  { // Entry 684
    0x1.ff0fd2c77b2d4add40566ec5aa24fc6ep-1,
    0x1.f00002p-5
  },
  { // Entry 685
    0x1.ff0fd2c77b2d4add40566ec5aa24fc6ep-1,
    -0x1.f00002p-5
  },
  { // Entry 686
    0x1.fc21005d216a89de55b192096fc6b7bap-1,
    0x1.f7fffep-4
  },
  { // Entry 687
    0x1.fc21005d216a89de55b192096fc6b7bap-1,
    -0x1.f7fffep-4
  },
  { // Entry 688
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    0x1.f8p-4
  },
  { // Entry 689
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    -0x1.f8p-4
  },
  { // Entry 690
    0x1.fc21004d6b953945667f800ff81de0ebp-1,
    0x1.f80002p-4
  },
  { // Entry 691
    0x1.fc21004d6b953945667f800ff81de0ebp-1,
    -0x1.f80002p-4
  },
  { // Entry 692
    0x1.f94984c6fdf1be6168509ff1e35f62dep-1,
    0x1.4bfffep-3
  },
  { // Entry 693
    0x1.f94984c6fdf1be6168509ff1e35f62dep-1,
    -0x1.4bfffep-3
  },
  { // Entry 694
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    0x1.4cp-3
  },
  { // Entry 695
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    -0x1.4cp-3
  },
  { // Entry 696
    0x1.f949849dac6a548dd851139041106316p-1,
    0x1.4c0002p-3
  },
  { // Entry 697
    0x1.f949849dac6a548dd851139041106316p-1,
    -0x1.4c0002p-3
  },
  { // Entry 698
    0x1.e921dd7054ef5d4f727d938ce10a053cp-1,
    0x1.333332p-2
  },
  { // Entry 699
    0x1.e921dd7054ef5d4f727d938ce10a053cp-1,
    -0x1.333332p-2
  },
  { // Entry 700
    0x1.e921dd24adb9129efc053f9acd4d2444p-1,
    0x1.333334p-2
  },
  { // Entry 701
    0x1.e921dd24adb9129efc053f9acd4d2444p-1,
    -0x1.333334p-2
  },
  { // Entry 702
    0x1.e921dcd906824da60e43c03a7774b171p-1,
    0x1.333336p-2
  },
  { // Entry 703
    0x1.e921dcd906824da60e43c03a7774b171p-1,
    -0x1.333336p-2
  },
  { // Entry 704
    0x1.8feedc92764bfbdcb41389e82063ed6ep-1,
    0x1.594316p-1
  },
  { // Entry 705
    0x1.8feedc92764bfbdcb41389e82063ed6ep-1,
    -0x1.594316p-1
  },
  { // Entry 706
    0x1.8feedb52c750087c5f8727e0279e5f66p-1,
    0x1.594318p-1
  },
  { // Entry 707
    0x1.8feedb52c750087c5f8727e0279e5f66p-1,
    -0x1.594318p-1
  },
  { // Entry 708
    0x1.8feeda131852852d2fa7fe8847b05973p-1,
    0x1.59431ap-1
  },
  { // Entry 709
    0x1.8feeda131852852d2fa7fe8847b05973p-1,
    -0x1.59431ap-1
  },
  { // Entry 710
    0x1.6b8991127859fd9b43ca1d08b92aa401p-1,
    0x1.8ffffep-1
  },
  { // Entry 711
    0x1.6b8991127859fd9b43ca1d08b92aa401p-1,
    -0x1.8ffffep-1
  },
  { // Entry 712
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    0x1.90p-1
  },
  { // Entry 713
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    -0x1.90p-1
  },
  { // Entry 714
    0x1.6b898e4167103b31de6da67ebf5e9fe6p-1,
    0x1.900002p-1
  },
  { // Entry 715
    0x1.6b898e4167103b31de6da67ebf5e9fe6p-1,
    -0x1.900002p-1
  },
  { // Entry 716
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 717
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 718
    0x1.p0,
    0.0
  },
  { // Entry 719
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149
  },
  { // Entry 720
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149
  },
  { // Entry 721
    0x1.ff621e38956a3b3be920256ddb6034cdp-1,
    0x1.921fb4p-5
  },
  { // Entry 722
    0x1.ff621e38956a3b3be920256ddb6034cdp-1,
    -0x1.921fb4p-5
  },
  { // Entry 723
    0x1.ff621e370373dc6f3963d42896ede078p-1,
    0x1.921fb6p-5
  },
  { // Entry 724
    0x1.ff621e370373dc6f3963d42896ede078p-1,
    -0x1.921fb6p-5
  },
  { // Entry 725
    0x1.ff621e35717d7ba327894bdfde9f4787p-1,
    0x1.921fb8p-5
  },
  { // Entry 726
    0x1.ff621e35717d7ba327894bdfde9f4787p-1,
    -0x1.921fb8p-5
  },
  { // Entry 727
    0x1.fd88da410b61cd55221d9beb996d4d99p-1,
    0x1.921fb4p-4
  },
  { // Entry 728
    0x1.fd88da410b61cd55221d9beb996d4d99p-1,
    -0x1.921fb4p-4
  },
  { // Entry 729
    0x1.fd88da3ac5781f5a6fc32e40ed5122b0p-1,
    0x1.921fb6p-4
  },
  { // Entry 730
    0x1.fd88da3ac5781f5a6fc32e40ed5122b0p-1,
    -0x1.921fb6p-4
  },
  { // Entry 731
    0x1.fd88da347f8e696999ffd58060ba3569p-1,
    0x1.921fb8p-4
  },
  { // Entry 732
    0x1.fd88da347f8e696999ffd58060ba3569p-1,
    -0x1.921fb8p-4
  },
  { // Entry 733
    0x1.f6297d0f4671da580dfecdd4db29f473p-1,
    0x1.921fb4p-3
  },
  { // Entry 734
    0x1.f6297d0f4671da580dfecdd4db29f473p-1,
    -0x1.921fb4p-3
  },
  { // Entry 735
    0x1.f6297cf64db9a21d98ab3940fc8a86f0p-1,
    0x1.921fb6p-3
  },
  { // Entry 736
    0x1.f6297cf64db9a21d98ab3940fc8a86f0p-1,
    -0x1.921fb6p-3
  },
  { // Entry 737
    0x1.f6297cdd55014a808b883fd183f318acp-1,
    0x1.921fb8p-3
  },
  { // Entry 738
    0x1.f6297cdd55014a808b883fd183f318acp-1,
    -0x1.921fb8p-3
  },
  { // Entry 739
    0x1.d906bd313443007dcb0bd4e3d63284c0p-1,
    0x1.921fb4p-2
  },
  { // Entry 740
    0x1.d906bd313443007dcb0bd4e3d63284c0p-1,
    -0x1.921fb4p-2
  },
  { // Entry 741
    0x1.d906bccf3cb875874da3da4c01104bafp-1,
    0x1.921fb6p-2
  },
  { // Entry 742
    0x1.d906bccf3cb875874da3da4c01104bafp-1,
    -0x1.921fb6p-2
  },
  { // Entry 743
    0x1.d906bc6d452d744f210810861102f2dap-1,
    0x1.921fb8p-2
  },
  { // Entry 744
    0x1.d906bc6d452d744f210810861102f2dap-1,
    -0x1.921fb8p-2
  },
  { // Entry 745
    0x1.6a09e74d3d3fbb94d94274f37769f6eap-1,
    0x1.921fb4p-1
  },
  { // Entry 746
    0x1.6a09e74d3d3fbb94d94274f37769f6eap-1,
    -0x1.921fb4p-1
  },
  { // Entry 747
    0x1.6a09e5e3335983e5ac92e733e3f24b42p-1,
    0x1.921fb6p-1
  },
  { // Entry 748
    0x1.6a09e5e3335983e5ac92e733e3f24b42p-1,
    -0x1.921fb6p-1
  },
  { // Entry 749
    0x1.6a09e4792971e22c9a00261aeac070dap-1,
    0x1.921fb8p-1
  },
  { // Entry 750
    0x1.6a09e4792971e22c9a00261aeac070dap-1,
    -0x1.921fb8p-1
  },
  { // Entry 751
    0x1.4442d18469893610281a0f9b0e8d0eefp-24,
    0x1.921fb4p0
  },
  { // Entry 752
    0x1.4442d18469893610281a0f9b0e8d0eefp-24,
    -0x1.921fb4p0
  },
  { // Entry 753
    -0x1.777a5cf72cecc4cde3a31e7d5a026142p-25,
    0x1.921fb6p0
  },
  { // Entry 754
    -0x1.777a5cf72cecc4cde3a31e7d5a026142p-25,
    -0x1.921fb6p0
  },
  { // Entry 755
    -0x1.5dde973dcb3985f4a8e76a1feca29e1dp-23,
    0x1.921fb8p0
  },
  { // Entry 756
    -0x1.5dde973dcb3985f4a8e76a1feca29e1dp-23,
    -0x1.921fb8p0
  },
  { // Entry 757
    -0x1.fffffffffff9951b30e084732e60bb85p-1,
    0x1.921fb4p1
  },
  { // Entry 758
    -0x1.fffffffffff9951b30e084732e60bb85p-1,
    -0x1.921fb4p1
  },
  { // Entry 759
    -0x1.fffffffffffdd94849271d08eecf54a1p-1,
    0x1.921fb6p1
  },
  { // Entry 760
    -0x1.fffffffffffdd94849271d08eecf54a1p-1,
    -0x1.921fb6p1
  },
  { // Entry 761
    -0x1.ffffffffffe21d75616db5ebc56405f5p-1,
    0x1.921fb8p1
  },
  { // Entry 762
    -0x1.ffffffffffe21d75616db5ebc56405f5p-1,
    -0x1.921fb8p1
  },
  { // Entry 763
    0x1.ffffffffffe6546cc38211f5e8deeb97p-1,
    0x1.921fb4p2
  },
  { // Entry 764
    0x1.ffffffffffe6546cc38211f5
"""


```
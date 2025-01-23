Response:
The user has provided a snippet of C code representing data for `sincosf`. The task is to summarize the functionality of this code snippet within the larger context of Android's bionic library, specifically focusing on the math library.

Here's a breakdown of the thought process:

1. **Identify the core component:** The filename `sincosf_intel_data.handroid` strongly suggests that this data is used for the `sincosf` function, likely optimized for Intel architectures on Android. The `_data` suffix implies this is lookup table data rather than the implementation itself.

2. **Understand the data format:** The data is an array of structs. Each struct contains three floating-point numbers. Given the context of `sincosf`, these likely correspond to:
    * Input angle (or a related value).
    * Sine of the input angle.
    * Cosine of the input angle.

3. **Relate to Android's functionality:** The `sincosf` function is part of the standard C math library (`libm`). Android's bionic provides its own optimized implementation of these functions. This data likely contributes to the accuracy and performance of `sincosf` on Android devices.

4. **Consider the `handroid` suffix:**  This likely indicates a specialized or optimized version of the data for Android. It could be tuned for specific hardware or to meet Android's CTS (Compatibility Test Suite) requirements.

5. **Address the "功能" (functionality) question:** The primary function of this specific file is to provide pre-computed data for the `sincosf` function. This data is used to improve the performance and accuracy of calculating sine and cosine for single-precision floating-point numbers.

6. **Address the "与android的功能有关系" (relationship with Android functionality) question:**  The data directly supports the `sincosf` function, which is a crucial part of the standard C library available to Android applications through the NDK. Examples of its use include graphics rendering, physics simulations, and signal processing.

7. **Skip detailed libc function implementation explanation:**  The prompt specifically asks about *this* data file. Explaining the full implementation of `sincosf` or other libc functions is beyond the scope of this specific code snippet. It's important to focus on what *this data* contributes.

8. **Skip dynamic linker details:** This file contains static data, not executable code, so the dynamic linker is not directly involved in its usage. While `libm.so` itself is linked, this data within the `libm.so` binary doesn't involve dynamic linking at runtime.

9. **Skip logical reasoning and assumptions:**  The data is provided directly. There's no need for complex logical deduction about inputs and outputs; the data *is* the input and output relationship for specific pre-calculated values.

10. **Skip common usage errors:** This is a data file, not a function that developers directly call. Usage errors are more relevant to the `sincosf` function itself, not this data table.

11. **Address "android framework or ndk是如何一步步的到达这里" (how Android reaches this point):**  This involves a chain of events:
    * An Android application (either through the Framework or NDK) calls `sincosf`.
    * This call is routed to the `libm.so` library provided by bionic.
    * The `libm.so` implementation of `sincosf` (likely a more complex algorithm) uses this lookup table data as part of its calculation, possibly for initial approximations or range reduction.

12. **Provide a Frida hook example:**  To observe this data being used, a Frida hook could target the `sincosf` function within `libm.so`. The hook could log the input to `sincosf` and potentially examine how the implementation accesses or interpolates within this data table. A simple hook logging input and output would be sufficient to demonstrate the function's use. More advanced hooks could attempt to read memory around the data table's address during `sincosf` execution.

13. **Focus on the "归纳一下它的功能" (summarize its functionality) for Part 3:** Since this is part 3 of 4, the summary should focus on the specific contribution of the *data file*. It's a pre-computed lookup table used by `sincosf` for performance and accuracy.

14. **Structure the answer:** Organize the points logically, starting with the basic functionality and progressing to more complex aspects like Android integration and debugging. Use clear and concise language. Use the provided Chinese terms where appropriate.
好的，让我们来归纳一下文件 `bionic/tests/math_data/sincosf_intel_data.handroid` 的功能，这是第3部分，共4部分。

**功能归纳**

这个文件 `sincosf_intel_data.handroid` 的主要功能是**为 `sincosf` 函数提供预先计算好的测试数据**。

具体来说：

* **测试数据存储：**  它以结构体数组的形式存储了一系列的测试用例。每个结构体包含三个 `float` 类型的数值。
* **`sincosf` 函数测试：**  这些数值很可能对应于 `sincosf` 函数的输入角度以及期望的输出结果，即正弦值和余弦值。
* **Intel 平台优化：** 文件名中的 `intel` 表明这些数据可能专门针对 Intel 架构的处理器进行了优化或测试。
* **`handroid` 后缀：** `handroid` 表明这是 Android 系统中使用的测试数据。
* **精度验证：** 这些预计算的数据可以用来验证 `sincosf` 函数在特定输入下的计算精度是否符合预期。

**与 Android 功能的关系举例**

在 Android 系统中，许多图形渲染、物理模拟、信号处理等操作都会频繁地使用到三角函数。`sincosf` 函数作为标准 C 库的一部分，被广泛地调用。这个数据文件就直接服务于对 `sincosf` 函数的测试和验证，确保其在 Android 平台上，特别是在 Intel 架构设备上的正确性和性能。

例如，一个使用 OpenGL ES 进行 3D 渲染的 Android 应用，其底层的图形库会调用 `sincosf` 来计算旋转变换中的正弦和余弦值。为了保证渲染的正确性，就需要确保 `sincosf` 函数的输出是准确的。这个数据文件就可以用来测试 `libm.so` 中 `sincosf` 的实现是否正确。

**为什么需要这样的测试数据？**

* **回归测试：** 当 `sincosf` 函数的实现被修改或优化后，可以使用这些测试数据快速验证修改是否引入了错误。
* **平台特定优化验证：** 针对不同处理器架构（如 Intel）的优化实现，需要有相应的测试数据来确保优化的有效性和正确性。
* **精度保证：** 浮点运算本身存在精度问题，预先计算好的数据可以作为精度对比的基准。

**总结**

作为 `bionic` 中 `math_data` 的一部分，`sincosf_intel_data.handroid` 文件扮演着 **质量保证** 的角色。它提供了一组针对 Intel 平台优化的 `sincosf` 函数的测试用例，用于验证该函数在 Android 系统中的正确性和精度。这对于确保 Android 平台上各种依赖三角函数的应用能够正常运行至关重要。

请注意，由于这只是数据文件，它本身并不包含函数的实现逻辑或动态链接信息。它只是测试过程中的一个重要组成部分。

### 提示词
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
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
0eacd9521377p-1,
    0x1.58ad76p1,
  },
  { // Entry 497
    -0x1.bc4c0a9b3782e220ae55786369ccf190p-2,
    -0x1.cd4bc93947e86671ac7f0eacd9521377p-1,
    -0x1.58ad76p1,
  },
  { // Entry 498
    0x1.877e301f43cafffe6644a8958f108729p-3,
    -0x1.f68eebd3b8f12f9433e6d7224989c10ep-1,
    0x1.798108p1,
  },
  { // Entry 499
    -0x1.877e301f43cafffe6644a8958f108729p-3,
    -0x1.f68eebd3b8f12f9433e6d7224989c10ep-1,
    -0x1.798108p1,
  },
  { // Entry 500
    -0x1.066e8ae1f824a69817e6a806e6317e28p-4,
    -0x1.fef2b2b91e40021a2fee74fc61812157p-1,
    0x1.9a549ap1,
  },
  { // Entry 501
    0x1.066e8ae1f824a69817e6a806e6317e28p-4,
    -0x1.fef2b2b91e40021a2fee74fc61812157p-1,
    -0x1.9a549ap1,
  },
  { // Entry 502
    -0x1.42abc1eca11a0ad12ca6eeff197318aap-2,
    -0x1.e5eaa14d86168b69918c22f3716a67eap-1,
    0x1.bb282cp1,
  },
  { // Entry 503
    0x1.42abc1eca11a0ad12ca6eeff197318aap-2,
    -0x1.e5eaa14d86168b69918c22f3716a67eap-1,
    -0x1.bb282cp1,
  },
  { // Entry 504
    -0x1.17505efb8119773c647468be1dfee45ep-1,
    -0x1.ad19deead0eae2f72d04165e09e4a43dp-1,
    0x1.dbfbbep1,
  },
  { // Entry 505
    0x1.17505efb8119773c647468be1dfee45ep-1,
    -0x1.ad19deead0eae2f72d04165e09e4a43dp-1,
    -0x1.dbfbbep1,
  },
  { // Entry 506
    -0x1.7b05bd8091cd79dff359c8412b0de1a9p-1,
    -0x1.5837cc21dda44f3ab7fd96f57c014e19p-1,
    0x1.fccf50p1,
  },
  { // Entry 507
    0x1.7b05bd8091cd79dff359c8412b0de1a9p-1,
    -0x1.5837cc21dda44f3ab7fd96f57c014e19p-1,
    -0x1.fccf50p1,
  },
  { // Entry 508
    -0x1.c5f05982eabf022748960961666d540dp-1,
    -0x1.d9a39df207139f99ebe9b56dafb234b7p-2,
    0x1.0ed170p2,
  },
  { // Entry 509
    0x1.c5f05982eabf022748960961666d540dp-1,
    -0x1.d9a39df207139f99ebe9b56dafb234b7p-2,
    -0x1.0ed170p2,
  },
  { // Entry 510
    -0x1.f329bfbda8122f83e3a1ea0242eb76aap-1,
    -0x1.c7b9189638128bc0ae33fdf2729cc987p-3,
    0x1.1f3b38p2,
  },
  { // Entry 511
    0x1.f329bfbda8122f83e3a1ea0242eb76aap-1,
    -0x1.c7b9189638128bc0ae33fdf2729cc987p-3,
    -0x1.1f3b38p2,
  },
  { // Entry 512
    -0x1.ffbca88ae90f0900b6d3ad89eddd2c80p-1,
    0x1.069082e04b25e9d2ea9e263b50d08b34p-5,
    0x1.2fa5p2,
  },
  { // Entry 513
    0x1.ffbca88ae90f0900b6d3ad89eddd2c80p-1,
    0x1.069082e04b25e9d2ea9e263b50d08b34p-5,
    -0x1.2fa5p2,
  },
  { // Entry 514
    -0x1.ead687409c95dcaf61af98513517f507p-1,
    0x1.235b1861f21aa86dce259e4e5b4ef395p-2,
    0x1.400ec8p2,
  },
  { // Entry 515
    0x1.ead687409c95dcaf61af98513517f507p-1,
    0x1.235b1861f21aa86dce259e4e5b4ef395p-2,
    -0x1.400ec8p2,
  },
  { // Entry 516
    -0x1.b5d54fd79372b90d5d4c7acf7adaed42p-1,
    0x1.096aaf70341485062f443c80a90a3be3p-1,
    0x1.507890p2,
  },
  { // Entry 517
    0x1.b5d54fd79372b90d5d4c7acf7adaed42p-1,
    0x1.096aaf70341485062f443c80a90a3be3p-1,
    -0x1.507890p2,
  },
  { // Entry 518
    -0x1.643092f42ae797375531420c005ca2cfp-1,
    0x1.6fcb6ae03107be458d07361371efabb4p-1,
    0x1.60e258p2,
  },
  { // Entry 519
    0x1.643092f42ae797375531420c005ca2cfp-1,
    0x1.6fcb6ae03107be458d07361371efabb4p-1,
    -0x1.60e258p2,
  },
  { // Entry 520
    -0x1.f67edf3b7bee8554d54d84ea83f6cb21p-2,
    0x1.be1d6d10d5c8ceeb8bf9aeb7a9f690b9p-1,
    0x1.714c20p2,
  },
  { // Entry 521
    0x1.f67edf3b7bee8554d54d84ea83f6cb21p-2,
    0x1.be1d6d10d5c8ceeb8bf9aeb7a9f690b9p-1,
    -0x1.714c20p2,
  },
  { // Entry 522
    -0x1.03be4d93d949325340b2f464201545a7p-2,
    0x1.ef413c72d988bb53937975e4fd4fcc7ap-1,
    0x1.81b5e8p2,
  },
  { // Entry 523
    0x1.03be4d93d949325340b2f464201545a7p-2,
    0x1.ef413c72d988bb53937975e4fd4fcc7ap-1,
    -0x1.81b5e8p2,
  },
  { // Entry 524
    0x1.efb26cfa20f2098ff7e9e42f0260eb01p-5,
    0x1.ff0fd2cb5a9228cfa1e01605d0626c84p-1,
    0x1.effffep-5,
  },
  { // Entry 525
    -0x1.efb26cfa20f2098ff7e9e42f0260eb01p-5,
    0x1.ff0fd2cb5a9228cfa1e01605d0626c84p-1,
    -0x1.effffep-5,
  },
  { // Entry 526
    0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    0x1.f0p-5,
  },
  { // Entry 527
    -0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    -0x1.f0p-5,
  },
  { // Entry 528
    0x1.efb270f840979c65b75ee5c67016a866p-5,
    0x1.ff0fd2c77b2d4add40566ec5aa24fc6ep-1,
    0x1.f00002p-5,
  },
  { // Entry 529
    -0x1.efb270f840979c65b75ee5c67016a866p-5,
    0x1.ff0fd2c77b2d4add40566ec5aa24fc6ep-1,
    -0x1.f00002p-5,
  },
  { // Entry 530
    0x1.f6baa816fce5ea5a60d8c9fd2a289380p-4,
    0x1.fc21005d216a89de55b192096fc6b7bap-1,
    0x1.f7fffep-4,
  },
  { // Entry 531
    -0x1.f6baa816fce5ea5a60d8c9fd2a289380p-4,
    0x1.fc21005d216a89de55b192096fc6b7bap-1,
    -0x1.f7fffep-4,
  },
  { // Entry 532
    0x1.f6baaa131de6438e5611279864fe7663p-4,
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    0x1.f8p-4,
  },
  { // Entry 533
    -0x1.f6baaa131de6438e5611279864fe7663p-4,
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    -0x1.f8p-4,
  },
  { // Entry 534
    0x1.f6baac0f3ee694e760a138bc06c8be3dp-4,
    0x1.fc21004d6b953945667f800ff81de0ebp-1,
    0x1.f80002p-4,
  },
  { // Entry 535
    -0x1.f6baac0f3ee694e760a138bc06c8be3dp-4,
    0x1.fc21004d6b953945667f800ff81de0ebp-1,
    -0x1.f80002p-4,
  },
  { // Entry 536
    0x1.4a8c395552fb432af31780e883c98f71p-3,
    0x1.f94984c6fdf1be6168509ff1e35f62dep-1,
    0x1.4bfffep-3,
  },
  { // Entry 537
    -0x1.4a8c395552fb432af31780e883c98f71p-3,
    0x1.f94984c6fdf1be6168509ff1e35f62dep-1,
    -0x1.4bfffep-3,
  },
  { // Entry 538
    0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    0x1.4cp-3,
  },
  { // Entry 539
    -0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    -0x1.4cp-3,
  },
  { // Entry 540
    0x1.4a8c3d47e604a7d54f3f7de402409e2cp-3,
    0x1.f949849dac6a548dd851139041106316p-1,
    0x1.4c0002p-3,
  },
  { // Entry 541
    -0x1.4a8c3d47e604a7d54f3f7de402409e2cp-3,
    0x1.f949849dac6a548dd851139041106316p-1,
    -0x1.4c0002p-3,
  },
  { // Entry 542
    0x1.2e9cd83630eb35c12efcfb8413583998p-2,
    0x1.e921dd7054ef5d4f727d938ce10a053cp-1,
    0x1.333332p-2,
  },
  { // Entry 543
    -0x1.2e9cd83630eb35c12efcfb8413583998p-2,
    0x1.e921dd7054ef5d4f727d938ce10a053cp-1,
    -0x1.333332p-2,
  },
  { // Entry 544
    0x1.2e9cda1f52c88042833f236ff0f9d486p-2,
    0x1.e921dd24adb9129efc053f9acd4d2444p-1,
    0x1.333334p-2,
  },
  { // Entry 545
    -0x1.2e9cda1f52c88042833f236ff0f9d486p-2,
    0x1.e921dd24adb9129efc053f9acd4d2444p-1,
    -0x1.333334p-2,
  },
  { // Entry 546
    0x1.2e9cdc0874a57f1ca0f976a9b01e4a71p-2,
    0x1.e921dcd906824da60e43c03a7774b171p-1,
    0x1.333336p-2,
  },
  { // Entry 547
    -0x1.2e9cdc0874a57f1ca0f976a9b01e4a71p-2,
    0x1.e921dcd906824da60e43c03a7774b171p-1,
    -0x1.333336p-2,
  },
  { // Entry 548
    0x1.3faefb2b68e6786eb692bd4e4045213ep-1,
    0x1.8feedc92764bfbdcb41389e82063ed6ep-1,
    0x1.594316p-1,
  },
  { // Entry 549
    -0x1.3faefb2b68e6786eb692bd4e4045213ep-1,
    0x1.8feedc92764bfbdcb41389e82063ed6ep-1,
    -0x1.594316p-1,
  },
  { // Entry 550
    0x1.3faefcbb57c26b0d84b63dbfb72b413bp-1,
    0x1.8feedb52c750087c5f8727e0279e5f66p-1,
    0x1.594318p-1,
  },
  { // Entry 551
    -0x1.3faefcbb57c26b0d84b63dbfb72b413bp-1,
    0x1.8feedb52c750087c5f8727e0279e5f66p-1,
    -0x1.594318p-1,
  },
  { // Entry 552
    0x1.3faefe4b469d1dfd561e666edda7c6e6p-1,
    0x1.8feeda131852852d2fa7fe8847b05973p-1,
    0x1.59431ap-1,
  },
  { // Entry 553
    -0x1.3faefe4b469d1dfd561e666edda7c6e6p-1,
    0x1.8feeda131852852d2fa7fe8847b05973p-1,
    -0x1.59431ap-1,
  },
  { // Entry 554
    0x1.6888a375ab228c1e031c4005769509f9p-1,
    0x1.6b8991127859fd9b43ca1d08b92aa401p-1,
    0x1.8ffffep-1,
  },
  { // Entry 555
    -0x1.6888a375ab228c1e031c4005769509f9p-1,
    0x1.6b8991127859fd9b43ca1d08b92aa401p-1,
    -0x1.8ffffep-1,
  },
  { // Entry 556
    0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    0x1.90p-1,
  },
  { // Entry 557
    -0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    -0x1.90p-1,
  },
  { // Entry 558
    0x1.6888a64cbe41dffd6e4768dcca4db53bp-1,
    0x1.6b898e4167103b31de6da67ebf5e9fe6p-1,
    0x1.900002p-1,
  },
  { // Entry 559
    -0x1.6888a64cbe41dffd6e4768dcca4db53bp-1,
    0x1.6b898e4167103b31de6da67ebf5e9fe6p-1,
    -0x1.900002p-1,
  },
  { // Entry 560
    -0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
  },
  { // Entry 561
    0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149,
  },
  { // Entry 562
    0.0,
    0x1.p0,
    0.0,
  },
  { // Entry 563
    0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149,
  },
  { // Entry 564
    -0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
  },
  { // Entry 565
    0x1.91f65dccfead353d8db9c32f12262730p-5,
    0x1.ff621e38956a3b3be920256ddb6034cdp-1,
    0x1.921fb4p-5,
  },
  { // Entry 566
    -0x1.91f65dccfead353d8db9c32f12262730p-5,
    0x1.ff621e38956a3b3be920256ddb6034cdp-1,
    -0x1.921fb4p-5,
  },
  { // Entry 567
    0x1.91f65fcc60cb6d09fcc5c35dd6a798c8p-5,
    0x1.ff621e370373dc6f3963d42896ede078p-1,
    0x1.921fb6p-5,
  },
  { // Entry 568
    -0x1.91f65fcc60cb6d09fcc5c35dd6a798c8p-5,
    0x1.ff621e370373dc6f3963d42896ede078p-1,
    -0x1.921fb6p-5,
  },
  { // Entry 569
    0x1.91f661cbc2e9a3447571f72bcfbc21e2p-5,
    0x1.ff621e35717d7ba327894bdfde9f4787p-1,
    0x1.921fb8p-5,
  },
  { // Entry 570
    -0x1.91f661cbc2e9a3447571f72bcfbc21e2p-5,
    0x1.ff621e35717d7ba327894bdfde9f4787p-1,
    -0x1.921fb8p-5,
  },
  { // Entry 571
    0x1.917a6a7fe8297bf0a1125fb02b2038aep-4,
    0x1.fd88da410b61cd55221d9beb996d4d99p-1,
    0x1.921fb4p-4,
  },
  { // Entry 572
    -0x1.917a6a7fe8297bf0a1125fb02b2038aep-4,
    0x1.fd88da410b61cd55221d9beb996d4d99p-1,
    -0x1.921fb4p-4,
  },
  { // Entry 573
    0x1.917a6c7d7103b9d90e09615164449c6bp-4,
    0x1.fd88da3ac5781f5a6fc32e40ed5122b0p-1,
    0x1.921fb6p-4,
  },
  { // Entry 574
    -0x1.917a6c7d7103b9d90e09615164449c6bp-4,
    0x1.fd88da3ac5781f5a6fc32e40ed5122b0p-1,
    -0x1.921fb6p-4,
  },
  { // Entry 575
    0x1.917a6e7af9ddf17b914e6d2e8e83b33ep-4,
    0x1.fd88da347f8e696999ffd58060ba3569p-1,
    0x1.921fb8p-4,
  },
  { // Entry 576
    -0x1.917a6e7af9ddf17b914e6d2e8e83b33ep-4,
    0x1.fd88da347f8e696999ffd58060ba3569p-1,
    -0x1.921fb8p-4,
  },
  { // Entry 577
    0x1.8f8b82889296b5cf7904db1e74b3466bp-3,
    0x1.f6297d0f4671da580dfecdd4db29f473p-1,
    0x1.921fb4p-3,
  },
  { // Entry 578
    -0x1.8f8b82889296b5cf7904db1e74b3466bp-3,
    0x1.f6297d0f4671da580dfecdd4db29f473p-1,
    -0x1.921fb4p-3,
  },
  { // Entry 579
    0x1.8f8b847ebc13b8998ec5b37e7065341ep-3,
    0x1.f6297cf64db9a21d98ab3940fc8a86f0p-1,
    0x1.921fb6p-3,
  },
  { // Entry 580
    -0x1.8f8b847ebc13b8998ec5b37e7065341ep-3,
    0x1.f6297cf64db9a21d98ab3940fc8a86f0p-1,
    -0x1.921fb6p-3,
  },
  { // Entry 581
    0x1.8f8b8674e590a26aec3ea01d30aed486p-3,
    0x1.f6297cdd55014a808b883fd183f318acp-1,
    0x1.921fb8p-3,
  },
  { // Entry 582
    -0x1.8f8b8674e590a26aec3ea01d30aed486p-3,
    0x1.f6297cdd55014a808b883fd183f318acp-1,
    -0x1.921fb8p-3,
  },
  { // Entry 583
    0x1.87de293f569717a42a3bdb01aeae2063p-2,
    0x1.d906bd313443007dcb0bd4e3d63284c0p-1,
    0x1.921fb4p-2,
  },
  { // Entry 584
    -0x1.87de293f569717a42a3bdb01aeae2063p-2,
    0x1.d906bd313443007dcb0bd4e3d63284c0p-1,
    -0x1.921fb4p-2,
  },
  { // Entry 585
    0x1.87de2b185d5417dca800b85ca1319043p-2,
    0x1.d906bccf3cb875874da3da4c01104bafp-1,
    0x1.921fb6p-2,
  },
  { // Entry 586
    -0x1.87de2b185d5417dca800b85ca1319043p-2,
    0x1.d906bccf3cb875874da3da4c01104bafp-1,
    -0x1.921fb6p-2,
  },
  { // Entry 587
    0x1.87de2cf16410b61d9aff7e628fc853b2p-2,
    0x1.d906bc6d452d744f210810861102f2dap-1,
    0x1.921fb8p-2,
  },
  { // Entry 588
    -0x1.87de2cf16410b61d9aff7e628fc853b2p-2,
    0x1.d906bc6d452d744f210810861102f2dap-1,
    -0x1.921fb8p-2,
  },
  { // Entry 589
    0x1.6a09e582aa3945461b5a8a0787d5ab5bp-1,
    0x1.6a09e74d3d3fbb94d94274f37769f6eap-1,
    0x1.921fb4p-1,
  },
  { // Entry 590
    -0x1.6a09e582aa3945461b5a8a0787d5ab5bp-1,
    0x1.6a09e74d3d3fbb94d94274f37769f6eap-1,
    -0x1.921fb4p-1,
  },
  { // Entry 591
    0x1.6a09e6ecb41fdd7e681872c854887019p-1,
    0x1.6a09e5e3335983e5ac92e733e3f24b42p-1,
    0x1.921fb6p-1,
  },
  { // Entry 592
    -0x1.6a09e6ecb41fdd7e681872c854887019p-1,
    0x1.6a09e5e3335983e5ac92e733e3f24b42p-1,
    -0x1.921fb6p-1,
  },
  { // Entry 593
    0x1.6a09e856be050baccde9a76961e84aa7p-1,
    0x1.6a09e4792971e22c9a00261aeac070dap-1,
    0x1.921fb8p-1,
  },
  { // Entry 594
    -0x1.6a09e856be050baccde9a76961e84aa7p-1,
    0x1.6a09e4792971e22c9a00261aeac070dap-1,
    -0x1.921fb8p-1,
  },
  { // Entry 595
    0x1.fffffffffffe6546cc38211c26dabeebp-1,
    0x1.4442d18469893610281a0f9b0e8d0eefp-24,
    0x1.921fb4p0,
  },
  { // Entry 596
    -0x1.fffffffffffe6546cc38211c26dabeebp-1,
    0x1.4442d18469893610281a0f9b0e8d0eefp-24,
    -0x1.921fb4p0,
  },
  { // Entry 597
    0x1.ffffffffffff76521249c7422930ed82p-1,
    -0x1.777a5cf72cecc4cde3a31e7d5a026142p-25,
    0x1.921fb6p0,
  },
  { // Entry 598
    -0x1.ffffffffffff76521249c7422930ed82p-1,
    -0x1.777a5cf72cecc4cde3a31e7d5a026142p-25,
    -0x1.921fb6p0,
  },
  { // Entry 599
    0x1.fffffffffff8875d585b6d6cfce97d9cp-1,
    -0x1.5dde973dcb3985f4a8e76a1feca29e1dp-23,
    0x1.921fb8p0,
  },
  { // Entry 600
    -0x1.fffffffffff8875d585b6d6cfce97d9cp-1,
    -0x1.5dde973dcb3985f4a8e76a1feca29e1dp-23,
    -0x1.921fb8p0,
  },
  { // Entry 601
    0x1.4442d184698831f15b6315bfa6b5ae75p-23,
    -0x1.fffffffffff9951b30e084732e60bb85p-1,
    0x1.921fb4p1,
  },
  { // Entry 602
    -0x1.4442d184698831f15b6315bfa6b5ae75p-23,
    -0x1.fffffffffff9951b30e084732e60bb85p-1,
    -0x1.921fb4p1,
  },
  { // Entry 603
    -0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    -0x1.fffffffffffdd94849271d08eecf54a1p-1,
    0x1.921fb6p1,
  },
  { // Entry 604
    0x1.777a5cf72cec5fd61896cb4f40d1de79p-24,
    -0x1.fffffffffffdd94849271d08eecf54a1p-1,
    -0x1.921fb6p1,
  },
  { // Entry 605
    -0x1.5dde973dcb346afa46203cddc6f7fe97p-22,
    -0x1.ffffffffffe21d75616db5ebc56405f5p-1,
    0x1.921fb8p1,
  },
  { // Entry 606
    0x1.5dde973dcb346afa46203cddc6f7fe97p-22,
    -0x1.ffffffffffe21d75616db5ebc56405f5p-1,
    -0x1.921fb8p1,
  },
  { // Entry 607
    -0x1.4442d1846984217628872e56eb58b4c1p-22,
    0x1.ffffffffffe6546cc38211f5e8deeb97p-1,
    0x1.921fb4p2,
  },
  { // Entry 608
    0x1.4442d1846984217628872e56eb58b4c1p-22,
    0x1.ffffffffffe6546cc38211f5e8deeb97p-1,
    -0x1.921fb4p2,
  },
  { // Entry 609
    0x1.777a5cf72ceacbf6ec657e977ef771f1p-23,
    0x1.fffffffffff76521249c74285bf73c07p-1,
    0x1.921fb6p2,
  },
  { // Entry 610
    -0x1.777a5cf72ceacbf6ec657e977ef771f1p-23,
    0x1.fffffffffff76521249c74285bf73c07p-1,
    -0x1.921fb6p2,
  },
  { // Entry 611
    0x1.5dde973dcb1fff10bb0388479e82f4bbp-21,
    0x1.ffffffffff8875d585b6db2c31711004p-1,
    0x1.921fb8p2,
  },
  { // Entry 612
    -0x1.5dde973dcb1fff10bb0388479e82f4bbp-21,
    0x1.ffffffffff8875d585b6db2c31711004p-1,
    -0x1.921fb8p2,
  },
  { // Entry 613
    -0x1.4442d1846973df895d1791023ded513cp-21,
    0x1.ffffffffff9951b30e084a6a993b8675p-1,
    0x1.921fb4p3,
  },
  { // Entry 614
    0x1.4442d1846973df895d1791023ded513cp-21,
    0x1.ffffffffff9951b30e084a6a993b8675p-1,
    -0x1.921fb4p3,
  },
  { // Entry 615
    0x1.777a5cf72ce47c7a3ba04bc2a607a9a7p-22,
    0x1.ffffffffffdd94849271d0eb7b7b884bp-1,
    0x1.921fb6p3,
  },
  { // Entry 616
    -0x1.777a5cf72ce47c7a3ba04bc2a607a9a7p-22,
    0x1.ffffffffffdd94849271d0eb7b7b884bp-1,
    -0x1.921fb6p3,
  },
  { // Entry 617
    0x1.5dde973dcace4f6a8e90bd15e00610f8p-20,
    0x1.fffffffffe21d75616dba48283d3c2f7p-1,
    0x1.921fb8p3,
  },
  { // Entry 618
    -0x1.5dde973dcace4f6a8e90bd15e00610f8p-20,
    0x1.fffffffffe21d75616dba48283d3c2f7p-1,
    -0x1.921fb8p3,
  },
  { // Entry 619
    -0x1.4442d1846932d7d62f59209388c7f7cap-20,
    0x1.fffffffffe6546cc382152d9c0eb9b47p-1,
    0x1.921fb4p4,
  },
  { // Entry 620
    0x1.4442d1846932d7d62f59209388c7f7cap-20,
    0x1.fffffffffe6546cc382152d9c0eb9b47p-1,
    -0x1.921fb4p4,
  },
  { // Entry 621
    0x1.777a5cf72ccb3e87788b811229e725bcp-21,
    0x1.ffffffffff76521249c7484ea7d7a409p-1,
    0x1.921fb6p4,
  },
  { // Entry 622
    -0x1.777a5cf72ccb3e87788b811229e725bcp-21,
    0x1.ffffffffff76521249c7484ea7d7a409p-1,
    -0x1.921fb6p4,
  },
  { // Entry 623
    0x1.5dde973dc98790d1dcc602bd1b86bccap-19,
    0x1.fffffffff8875d585b720f25f0473943p-1,
    0x1.921fb8p4,
  },
  { // Entry 624
    -0x1.5dde973dc98790d1dcc602bd1b86bccap-19,
    0x1.fffffffff8875d585b720f25f0473943p-1,
    -0x1.921fb8p4,
  },
  { // Entry 625
    -0x1.4442d184682eb909785fad18bcb5dbfcp-19,
    0x1.fffffffff9951b30e087de5cc38683b8p-1,
    0x1.921fb4p5,
  },
  { // Entry 626
    0x1.4442d184682eb909785fad18bcb5dbfcp-19,
    0x1.fffffffff9951b30e087de5cc38683b8p-1,
    -0x1.921fb4p5,
  },
  { // Entry 627
    0x1.777a5cf72c6646bc6c38607eb34eea13p-20,
    0x1.fffffffffdd94849271d6b463df6bddfp-1,
    0x1.921fb6p5,
  },
  { // Entry 628
    -0x1.777a5cf72c6646bc6c38607eb34eea13p-20,
    0x1.fffffffffdd94849271d6b463df6bddfp-1,
    -0x1.921fb6p5,
  },
  { // Entry 629
    0x1.5dde973dc46c966f15a2403d60cd14d0p-18,
    0x1.ffffffffe21d75616e000e55d09f8757p-1,
    0x1.921fb8p5,
  },
  { // Entry 630
    -0x1.5dde973dc46c966f15a2403d60cd14d0p-18,
    0x1.ffffffffe21d75616e000e55d09f8757p-1,
    -0x1.921fb8p5,
  },
  { // Entry 631
    -0x1.4442d184641e3dd69c7ec32e14a209a5p-18,
    0x1.ffffffffe6546cc38248a8cf0b9b5795p-1,
    0x1.921fb4p6,
  },
  { // Entry 632
    0x1.4442d184641e3dd69c7ec32e14a209a5p-18,
    0x1.ffffffffe6546cc38248a8cf0b9b5795p-1,
    -0x1.921fb4p6,
  },
  { // Entry 633
    0x1.777a5cf72ad267903aec8118778b3b5ap-19,
    0x1.fffffffff76521249c7a4dd2e15dd1c4p-1,
    0x1.921fb6p6,
  },
  { // Entry 634
    -0x1.777a5cf72ad267903aec8118778b3b5ap-19,
    0x1.fffffffff76521249c7a4dd2e15dd1c4p-1,
    -0x1.921fb6p6,
  },
  { // Entry 635
    0x1.5dde973db000ace3f985a473ea1fc039p-17,
    0x1.ffffffff8875d585bb7d55383a9b39a4p-1,
    0x1.921fb8p6,
  },
  { // Entry 636
    -0x1.5dde973db000ace3f985a473ea1fc039p-17,
    0x1.ffffffff8875d585bb7d55383a9b39a4p-1,
    -0x1.921fb8p6,
  },
  { // Entry 637
    -0x1.4442d18453dc510b2d495b8bf79bd1cep-17,
    0x1.ffffffff9951b30e0bb598fc0679a6f7p-1,
    0x1.921fb4p7,
  },
  { // Entry 638
    0x1.4442d18453dc510b2d495b8bf79bd1cep-17,
    0x1.ffffffff9951b30e0bb598fc0679a6f7p-1,
    -0x1.921fb4p7,
  },
  { // Entry 639
    0x1.777a5cf72482eadf75c731f972507718p-18,
    0x1.ffffffffdd948492723342ea1da49bacp-1,
    0x1.921fb6p7,
  },
  { // Entry 640
    -0x1.777a5cf72482eadf75c731f972507718p-18,
    0x1.ffffffffdd948492723342ea1da49bacp-1,
    -0x1.921fb6p7,
  },
  { // Entry 641
    0x1.5dde973d5e5106b7903a18a552aefc6ep-16,
    0x1.fffffffe21d7561725c712f068fc9718p-1,
    0x1.921fb8p7,
  },
  { // Entry 642
    -0x1.5dde973d5e5106b7903a18a552aefc6ep-16,
    0x1.fffffffe21d7561725c712f068fc9718p-1,
    -0x1.921fb8p7,
  },
  { // Entry 643
    0x1.6a09f1940b80c8e25cfc8c10d42576c6p-1,
    -0x1.6a09db3bdba0868a31e766359a8406cap-1,
    0x1.2d97c4p1,
  },
  { // Entry 644
    -0x1.6a09f1940b80c8e25cfc8c10d42576c6p-1,
    -0x1.6a09db3bdba0868a31e766359a8406cap-1,
    -0x1.2d97c4p1,
  },
  { // Entry 645
    0x1.6a09ebebe40889245d57c5c9d90a6d82p-1,
    -0x1.6a09e0e4035b86694c16534e42fbe111p-1,
    0x1.2d97c6p1,
  },
  { // Entry 646
    -0x1.6a09ebebe40889245d57c5c9d90a6d82p-1,
    -0x1.6a09e0e4035b86694c16534e42fbe111p-1,
    -0x1.2d97c6p1,
  },
  { // Entry 647
    0x1.6a09e643bc79a8c79ef4bf187727e269p-1,
    -0x1.6a09e68c2affe5aa58050accb05c6248p-1,
    0x1.2d97c8p1,
  },
  { // Entry 648
    -0x1.6a09e643bc79a8c79ef4bf187727e269p-1,
    -0x1.6a09e68c2affe5aa58050accb05c6248p-1,
    -0x1.2d97c8p1,
  },
  { // Entry 649
    -0x1.6a09df19704cf14108e09000ff6374bfp-1,
    -0x1.6a09edb67706e0997121d12a0c87bae8p-1,
    0x1.f6a7a0p1,
  },
  { // Entry 650
    0x1.6a09df19704cf14108e09000ff6374bfp-1,
    -0x1.6a09edb67706e0997121d12a0c87bae8p-1,
    -0x1.f6a7a0p1,
  },
  { // Entry 651
    -0x1.6a09e4c197f87ace1c81b43022be39b1p-1,
    -0x1.6a09e80e4f7f2a88debed37faa93e8c8p-1,
    0x1.f6a7a2p1,
  },
  { // Entry 652
    0x1.6a09e4c197f87ace1c81b43022be39b1p-1,
    -0x1.6a09e80e4f7f2a88debed37faa93e8c8p-1,
    -0x1.f6a7a2p1,
  },
  { // Entry 653
    -0x1.6a09ea69bf8d63bce40958f5c4b4f155p-1,
    -0x1.6a09e26627e0d3d9cb76de00cb902becp-1,
    0x1.f6a7a4p1,
  },
  { // Entry 654
    0x1.6a09ea69bf8d63bce40958f5c4b4f155p-1,
    -0x1.6a09e26627e0d3d9cb76de00cb902becp-1,
    -0x1.f6a7a4p1,
  },
  { // Entry 655
    -0x1.ffffffffff065cb240bb8f9519d2c6f1p-1,
    -0x1.f9990e91a74168b90bd68dfab775c9cap-21,
    0x1.2d97c4p2,
  },
  { // Entry 656
    0x1.ffffffffff065cb240bb8f9519d2c6f1p-1,
    -0x1.f9990e91a74168b90bd68dfab775c9cap-21,
    -0x1.2d97c4p2,
  },
  { // Entry 657
    -0x1.ffffffffffc32939898f464aafc2e74ap-1,
    -0x1.f3321d234f1363d187dd09528b67b215p-22,
    0x1.2d97c6p2,
  },
  { // Entry 658
    0x1.ffffffffffc32939898f464aafc2e74ap-1,
    -0x1.f3321d234f1363d187dd09528b67b215p-22,
    -0x1.2d97c6p2,
  },
  { // Entry 659
    -0x1.fffffffffffff5c0d2630ee0a1fb4e7bp-1,
    0x1.99bc5b961b1acaca18d971f68ae99da9p-27,
    0x1.2d97c8p2,
  },
  { // Entry 660
    0x1.fffffffffffff5c0d2630ee0a1fb4e7bp-1,
    0x1.99bc5b961b1acaca18d971f68ae99da9p-27,
    -0x1.2d97c8p2,
  },
  { // Entry 661
    -0x1.6a09f529316cde5a190d235cc4ccb825p-1,
    0x1.6a09d7a6b572c2c824d137d0405d8188p-1,
    0x1.5fdbbcp2,
  },
  { // Entry 662
    0x1.6a09f529316cde5a190d235cc4ccb825p-1,
    0x1.6a09d7a6b572c2c824d137d0405d8188p-1,
    -0x1.5fdbbcp2,
  },
  { // Entry 663
    -0x1.6a09e9d8e2826770567ea818b2e89960p-1,
    0x1.6a09e2f704eecb181e3f5ece9be0ca0fp-1,
    0x1.5fdbbep2,
  },
  { // Entry 664
    0x1.6a09e9d8e2826770567ea818b2e89960p-1,
    0x1.6a09e2f704eecb181e3f5ece9be0ca0fp-1,
    -0x1.5fdbbep2,
  },
  { // Entry 665
    -0x1.6a09de88933d6e0c1db78e1d7cd15173p-1,
    0x1.6a09ee47541050ef59ec4bfce935cc1ap-1,
    0x1.5fdbc0p2,
  },
  { // Entry 666
    0x1.6a09de88933d6e0c1db78e1d7cd15173p-1,
    0x1.6a09ee47541050ef59ec4bfce935cc1ap-1,
    -0x1.5fdbc0p2,
  },
  { // Entry 667
    0x1.6a09d033fa715a407a6f03d01b91113fp-1,
    0x1.6a09fc9bebaba208c81ec0b1cd307589p-1,
    0x1.c463a8p2,
  },
  { // Entry 668
    -0x1.6a09d033fa715a407a6f03d01b91113fp-1,
    0x1.6a09fc9bebaba208c81ec0b1cd307589p-1,
    -0x1.c463a8p2,
  },
  { // Entry 669
    0x1.6a09db844a28f8635851fdf8818515efp-1,
    0x1.6a09f14b9cfcc0f6227d386cc3704a05p-1,
    0x1.c463aap2,
  },
  { // Entry 670
    -0x1.6a09db844a28f8635851fdf8818515efp-1,
    0x1.6a09f14b9cfcc0f6227d386cc3704a05p-1,
    -0x1.c463aap2,
  },
  { // Entry 671
    0x1.6a09e6d49986140f55226fc58672612cp-1,
    0x1.6a09e5fb4df35d6729f472da3413e404p-1,
    0x1.c463acp2,
  },
  { // Entry 672
    -0x1.6a09e6d49986140f55226fc58672612cp-1,
    0x1.6a09e5fb4df35d6729f472da3413e404p-1,
    -0x1.c463acp2,
  },
  { // Entry 673
    0x1.ffffffffff95397934cac1f28532d3d3p-1,
    0x1.4aa9c2f2c1defb8728f0d2da1217aae1p-21,
    0x1.f6a7a0p2,
  },
  { // Entry 674
    -0x1.ffffffffff95397934cac1f28532d3d3p-1,
    0x1.4aa9c2f2c1defb8728f0d2da1217aae1p-21,
    -0x1.f6a7a0p2,
  },
  { // Entry 675
    0x1.fffffffffffa8e5aae2bb93ae590f984p-1,
    0x1.2aa70bcb07d6d0f36b777cb380a845d9p-23,
    0x1.f6a7a2p2,
  },
  { // Entry 676
    -0x1.fffffffffffa8e5aae2bb93ae590f984p-1,
    0x1.2aa70bcb07d6d0f36b777cb380a845d9p-23,
    -0x1.f6a7a2p2,
  },
  { // Entry 677
    0x1.ffffffffffdfe33c278cb48a59ee3ef2p-1,
    -0x1.6aac7a1a7c0c7afc5fcb2313a7eca229p-22,
    0x1.f6a7a4p2,
  },
  { // Entry 678
    -0x1.ffffffffffdfe33c278cb48a59ee3ef2p-1,
    -0x1.6aac7a1a7c0c7afc5fcb2313a7eca229p-22,
    -0x1.f6a7a4p2,
  },
  { // Entry 679
    0x1.6a0a040ea5c32ba4afbeb86a614c5d16p-1,
    -0x1.6a09c8c13f48b7aad851f9d6474bcb31p-1,
    0x1.1475cap3,
  },
  { // Entry 680
    -0x1.6a0a040ea5c32ba4afbeb86a614c5d16p-1,
    -0x1.6a09c8c13f48b7aad851f9d6474bcb31p-1,
    -0x1.1475cap3,
  },
  { // Entry 681
    0x1.6a09ed6e088212b1e260a5132d6959b7p-1,
    -0x1.6a09df61ded49d1ee4fca4ba6140d179p-1,
    0x1.1475ccp3,
  },
  { // Entry 682
    -0x1.6a09ed6e088212b1e260a5132d6959b7p-1,
    -0x1.6a09df61ded49d1ee4fca4ba6140d179p-1,
    -0x1.1475ccp3,
  },
  { // Entry 683
    0x1.6a09d6cd69d6efd1a6fa2dd4c617cbbep-1,
    -0x1.6a09f6027cf678b38fc8992cd9990302p-1,
    0x1.1475cep3,
  },
  { // Entry 684
    -0x1.6a09d6cd69d6efd1a6fa2dd4c617cbbep-1,
    -0x1.6a09f6027cf678b38fc8992cd9990302p-1,
    -0x1.1475cep3,
  },
  { // Entry 685
    0x1.f9990e91a64ae486757878bdfee0f703p-20,
    -0x1.fffffffffc1972c902ef31c37cb54817p-1,
    0x1.2d97c4p3,
  },
  { // Entry 686
    -0x1.f9990e91a64ae486757878bdfee0f703p-20,
    -0x1.fffffffffc1972c902ef31c37cb54817p-1,
    -0x1.2d97c4p3,
  },
  { // Entry 687
    0x1.f3321d234ed8128aabb0499a43b4def2p-21,
    -0x1.ffffffffff0ca4e6263d27a0204389dfp-1,
    0x1.2d97c6p3,
  },
  { // Entry 688
    -0x1.f3321d234ed8128aabb0499a43b4def2p-21,
    -0x1.ffffffffff0ca4e6263d27a0204389dfp-1,
    -0x1.2d97c6p3,
  },
  { // Entry 689
    -0x1.99bc5b961b1ac296dbe1980fd2c890a0p-26,
    -0x1.ffffffffffffd703498c3b8288563915p-1,
    0x1.2d97c8p3,
  },
  { // Entry 690
    0x1.99bc5b961b1ac296dbe1980fd2c890a0p-26,
    -0x1.ffffffffffffd703498c3b8288563915p-1,
    -0x1.2d97c8p3,
  },
  { // Entry 691
    -0x1.6a09c14e83f8db080d1223f887cc12ecp-1,
    -0x1.6a0a0b815fb37b2d01551e07cb3009d1p-1,
    0x1.46b9c0p3,
  },
  { // Entry 692
    0x1.6a09c14e83f8db080d1223f887cc12ecp-1,
    -0x1.6a0a0b815fb37b2d01551e07cb3009d1p-1,
    -0x1.46b9c0p3,
  },
  { // Entry 693
    -0x1.6a09d7ef23fbec1ed812e807beb0492fp-1,
    -0x1.6a09f4e0c2e98deb78642b6032a73d46p-1,
    0x1.46b9c2p3,
  },
  { // Entry 694
    0x1.6a09d7ef23fbec1ed812e807beb0492fp-1,
    -0x1.6a09f4e0c2e98deb78642b6032a73d46p-1,
    -0x1.46b9c2p3,
  },
  { // Entry 695
    -0x1.6a09ee8fc294f35db3efce565365af89p-1,
    -0x1.6a09de4024b596b50eb06d562db8c777p-1,
    0x1.46b9c4p3,
  },
  { // Entry 696
    0x1.6a09ee8fc294f35db3efce565365af89p-1,
    -0x1.6a09de4024b596b50eb06d562db8c777p-1,
    -0x1.46b9c4p3,
  },
  { // Entry 697
    -0x1.fffffffffe4c96b397d951cb21861c95p-1,
    -0x1.4ddd3ba9edcd898b9946fdd20af22a68p-20,
    0x1.5fdbbcp3,
  },
  { // Entry 698
    0x1.fffffffffe4c96b397d951cb21861c95p-1,
    -0x1.4ddd3ba9edcd898b9946fdd20af22a68p-20,
    -0x1.5fdbbcp3,
  },
  { // Entry 699
    -0x1.ffffffffffe8512aebb56c9e75b41941p-1,
    -0x1.3774eea7b8abe8fa8c380142b97af4b6p-22,
    0x1.5fdbbep3,
  },
  { // Entry 700
    0x1.ffffffffffe8512aebb56c9e75b41941p-1,
    -0x1.3774eea7b8abe8fa8c380142b97af4b6p-22,
    -0x1.5fdbbep3,
  },
  { // Entry 701
    -0x1.ffffffffff840ba23f91c9cb49a10b27p-1,
    0x1.644588ac238ae493fa32435ba51329bfp-21,
    0x1.5fdbc0p3,
  },
  { // Entry 702
    0x1.ffffffffff840ba23f91c9cb49a10b27p-1,
    0x1.644588ac238ae493fa32435ba51329bfp-21,
    -0x1.5fdbc0p3,
  },
  { // Entry 703
    -0x1.6a0a12f4197c90a0ee4a094b6377aa23p-1,
    0x1.6a09b9dbc881c458e747908caf2aa5e1p-1,
    0x1.78fdb6p3,
  },
  { // Entry 704
    0x1.6a0a12f4197c90a0ee4a094b6377aa23p-1,
    0x1.6a09b9dbc881c458e747908caf2aa5e1p-1,
    -0x1.78fdb6p3,
  },
  { // Entry 705
    -0x1.6a09fc537d29cf131d6710991bebabedp-1,
    0x1.6a09d07c68fc010ffcfd3b19f1ee4f44p-1,
    0x1.78fdb8p3,
  },
  { // Entry 706
    0x1.6a09fc537d29cf131d6710991bebabedp-1,
    0x1.6a09d07c68fc010ffcfd3b19f1ee4f44p-1,
    -0x1.78fdb8p3,
  },
  { // Entry 707
    -0x1.6a09e5b2df6d0388f9070c4340f3e669p-1,
    0x1.6a09e71d080c33f6964a07d1a0bf5980p-1,
    0x1.78fdbap3,
  },
  { // Entry 708
    0x1.6a09e5b2df6d0388f9070c4340f3e669p-1,
    0x1.6a09e71d080c33f6964a07d1a0bf5980p-1,
    -0x1.78fdbap3,
  },
  { // Entry 709
    0x1.6a09c909add4dbf32253a39d5c306308p-1,
    0x1.6a0a03c63742d62802d163d5cfb3b7d5p-1,
    0x1.ab41aep3,
  },
  { // Entry 710
    -0x1.6a09c909add4dbf32253a39d5c306308p-1,
    0x1.6a0a03c63742d62802d163d5cfb3b7d5p-1,
    -0x1.ab41aep3,
  },
  { // Entry 711
    0x1.6a09dfaa4d5c3a7f056f3e61a365b29ep-1,
    0x1.6a09ed2599fd364c97660cca6652c0a3p-1,
    0x1.ab41b0p3,
  },
  { // Entry 712
    -0x1.6a09dfaa4d5c3a7f056f3e61a365b29ep-1,
    0x1.6a09ed2599fd364c97660cca6652c0a3p-1,
    -0x1.ab41b0p3,
  },
  { // Entry 713
    0x1.6a09f64aeb798f2b3e3d9b16e8e3c412p-1,
    0x1.6a09d684fb4d8c840660d6b42ec83039p-1,
    0x1.ab41b2p3,
  },
  { // Entry 714
    -0x1.6a09f64aeb798f2b3e3d9b16e8e3c412p-1,
    0x1.6a09d684fb4d8c840660d6b42ec83039p-1,
    -0x1.ab41b2p3,
  },
  { // Entry 715
    0x1.fffffffffc260d6ffb8f4cd8ab3fd020p-1,
    0x1.f66595da7a1ae308d26a18de4c2ed3a3p-20,
    0x1.c463a8p3,
  },
  { // Entry 716
    -0x1.fffffffffc260d6ffb8f4cd8ab3fd020p-1,
    0x1.f66595da7a1ae308d26a18de4c2ed3a3p-20,
    -0x1.c463a8p3,
  },
  { // Entry 717
    0x1.ffffffffff12d89bb084dd762848b3d6p-1,
    0x1.eccb2bb4f66ea861241fa09ca9d8a034p-21,
    0x1.c463aap3,
  },
  { // Entry 718
    -0x1.ffffffffff12d89bb084dd762848b3d6p-1,
    0x1.eccb2bb4f66ea861241fa09ca9d8a034p-21,
    -0x1.c463aap3,
  },
  { // Entry 719
    0x1.ffffffffffffa3c7657b85e5b44bbd44p-1,
    -0x1.334d44b0945407b118b361ab78171f67p-25,
    0x1.c463acp3,
  },
  { // Entry 720
    -0x1.ffffffffffffa3c7657b85e5b44bbd44p-1,
    -0x1.334d44b0945407b118b361ab78171f67p-25,
    -0x1.c463acp3,
  },
  { // Entry 721
    0x1.6a0a0b38f134a3295a0b386e42f1ca7ap-1,
    -0x1.6a09c196f2867cc916ae2b7e6c9d99c1p-1,
    0x1.dd85a4p3,
  },
  { // Entry 722
    -0x1.6a0a0b38f134a3295a0b386e42f1ca7ap-1,
    -0x1.6a09c196f2867cc916ae2b7e6c9d99c1p-1,
    -0x1.dd85a4p3,
  },
  { // Entry 723
    0x1.6a09f49854662eff1b35755a129044a7p-1,
    -0x1.6a09d837928506f7cff76f094b4e0377p-1,
    0x1.dd85a6p3,
  },
  { // Entry 724
    -0x1.6a09f49854662eff1b35755a129044a7p-1,
    -0x1.6a09d837928506f7cff76f094b4e0377p-1,
    -0x1.dd85a6p3,
  },
  { // Entry 725
    0x1.6a09ddf7b62db0e0440b6a4262203b11p-1,
    -0x1.6a09eed83119874e51ae4bb8aeddc1f2p-1,
    0x1.dd85a8p3,
  },
  { // Entry 726
    -0x1.6a09ddf7b62db0e0440b6a4262203b11p-1,
    -0x1.6a09eed83119874e51ae4bb8aeddc1f2p-1,
    -0x1.dd85a8p3,
  },
  { // Entry 727
    0x1.4aa9c2f2c19a062b18a017bcd5424feap-20,
    -0x1.fffffffffe54e5e4d32b3453166060b3p-1,
    0x1.f6a7a0p3,
  },
  { // Entry 728
    -0x1.4aa9c2f2c19a062b18a017bcd5424feap-20,
    -0x1.fffffffffe54e5e4d32b3453166060b3p-1,
    -0x1.f6a7a0p3,
  },
  { // Entry 729
    0x1.2aa70bcb07d3a40781510d213652e43ap-22,
    -0x1.ffffffffffea396ab8aee509392c755dp-1,
    0x1.f6a7a2p3,
  },
  { // Entry 730
    -0x1.2aa70bcb07d3a40781510d213652e43ap-22,
    -0x1.ffffffffffea396ab8aee509392c755dp-1,
    -0x1.f6a7a2p3,
  },
  { // Entry 731
    -0x1.6aac7a1a7bf5bbd49572ffb8d7749922p-21,
    -0x1.ffffffffff7f8cf09e32d6309bea85cap-1,
    0x1.f6a7a4p3,
  },
  { // Entry 732
    0x1.6aac7a1a7bf5bbd49572ffb8d7749922p-21,
    -0x1.ffffffffff7f8cf09e32d6309bea85cap-1,
    -0x1.f6a7a4p3,
  },
  { // Entry 733
    -0x1.6a09a383953124096898340f9168b9d5p-1,
    -0x1.6a0a294c45ec747a47711a4994d2c5e4p-1,
    0x1.07e4ccp4,
  },
  { // Entry 734
    0x1.6a09a383953124096898340f9168b9d5p-1,
    -0x1.6a0a294c45ec747a47711a4994d2c5e4p-1,
    -0x1.07e4ccp4,
  },
  { // Entry 735
    -0x1.6a09d0c4d7869961c47a9b0b968cc910p-1,
    -0x1.6a09fc0b0ea7ed9fb5dd50a0c8af19cbp-1,
    0x1.07e4cep4,
  },
  { // Entry 736
    0x1.6a09d0c4d7869961c47a9b0b968cc910p-1,
    -0x1.6a09fc0b0ea7ed9fb5dd50a0c8af19cbp-1,
    -0x1.07e4cep4,
  },
  { // Entry 737
    -0x1.6a09fe061433e7770d00ca59d5a56251p-1,
    -0x1.6a09cec9d1bb3ed4f810c9f9786d610ep-1,
    0x1.07e4d0p4,
  },
  { // Entry 738
    0x1.6a09fe061433e7770d00ca59d5a56251p-1,
    -0x1.6a09cec9d1bb3ed4f810c9f9786d610ep-1,
    -0x1.07e4d0p4,
  },
  { // Entry 739
    -0x1.fffffffff9219dae5feda1b539335803p-1,
    -0x1.4f76f80582c73fc0cc0903ed8ca7d6b3p-19,
    0x1.1475cap4,
  },
  { // Entry 740
    0x1.fffffffff9219dae5feda1b539335803p-1,
    -0x1.4f76f80582c73fc0cc0903ed8ca7d6b3p-19,
    -0x1.1475cap4,
  },
  { // Entry 741
    -0x1.ffffffffff9d556e8c0bf0a80d610808p-1,
    -0x1.3ddbe0161108b690eed70a7f59de751cp-21,
    0x1.1475ccp4,
  },
  { // Entry 742
    0x1.ffffffffff9d556e8c0bf0a80d610808p-1,
    -0x1.3ddbe0161108b690eed70a7f59de751cp-21,
    -0x1.1475ccp4,
  },
  { // Entry 743
    -0x1.fffffffffe190d2eb82e74efd2093215p-1,
    0x1.61120ff4f70180b0d55c3ae0f69585cap-20,
    0x1.1475cep4,
  },
  { // Entry 744
    0x1.fffffffffe190d2eb82e74efd2093215p-1,
    0x1.61120ff4f70180b0d55c3ae0f69585cap-20,
    -0x1.1475cep4,
  },
  { // Entry 745
    -0x1.6a0a1a1e64a28eee238dc852846aacd5p-1,
    0x1.6a09b2b17b741050a6cfd64b81c76485p-1,
    0x1.2106c8p4,
  },
  { // Entry 746
    0x1.6a0a1a1e64a28eee238dc852846aacd5p-1,
    0x1.6a09b2b17b741050a6cfd64b81c76485p-1,
    -0x1.2106c8p4,
  },
```
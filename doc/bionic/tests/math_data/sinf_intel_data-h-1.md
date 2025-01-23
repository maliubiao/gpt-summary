Response:
The user wants a summary of the functionality of the provided C source code snippet. This snippet appears to be a data table. It consists of an array of structs, each containing two floating-point numbers. The file path suggests this data is used for testing the `sinf` function in Android's math library. The naming convention `sinf_intel_data` hints that it might contain test cases specific to Intel's architecture or generated using Intel's tools.

Therefore, the core function of this code snippet is to provide test data for the single-precision floating-point sine function. Each entry in the table likely represents an input value and the expected output of the `sinf` function for that input.

To provide a good summary, I should focus on:

1. **Identifying the data type:** It's a table of floating-point pairs.
2. **Interpreting the purpose:**  It's used for testing the `sinf` function.
3. **Connecting to Android:** It's part of Android's Bionic library, specifically for math functions.
4. **Inferring the structure:** Each pair is likely an input and its expected sine value.
这段代码片段是 `bionic/tests/math_data/sinf_intel_data.handroid` 文件的一部分，它定义了一个用于测试单精度浮点数正弦函数 `sinf` 的数据表。

**功能归纳:**

这个代码片段的核心功能是 **提供了一系列预定义的输入值和对应的预期输出值，用于测试 `sinf` 函数的正确性**。

具体来说：

* **测试数据:**  代码中包含一个包含多个结构体的数组，每个结构体有两个 `float` 类型的成员。
* **输入与输出对:**  每一个结构体都代表一个测试用例，第一个 `float` 成员通常是 `sinf` 函数的输入值，第二个 `float` 成员是对于该输入值的预期的 `sinf` 函数的输出值。
* **测试目的:**  这个数据表被用来验证 Android 系统中 `sinf` 函数的实现是否符合预期，特别是对于不同的输入值，包括正数、负数、非常小和非常大的数等，是否能产生正确的输出。
* **`_intel_data` 的含义:**  文件名中的 `_intel_data` 可能暗示这些测试数据是针对特定 Intel 架构的优化或特性而设计的，或者使用了 Intel 的工具生成。`handroid` 可能表示这是为 Android 手持设备平台准备的数据。

**与 Android 功能的关系:**

这个数据表是 Android 系统底层数学库 `bionic` 的一部分，直接关系到 Android 平台上各种应用程序和框架对数学计算的正确性。

**举例说明:**

当一个 Android 应用（例如一个科学计算器应用或一个需要进行图形渲染的游戏）调用 `sinf(x)` 函数计算一个角度 `x` 的正弦值时，`bionic` 库中实现的 `sinf` 函数会被执行。为了确保这个函数在各种情况下都能返回正确的结果，Android 的测试框架会使用像 `sinf_intel_data.handroid` 这样的数据表来对 `sinf` 函数进行单元测试。

测试过程大致如下：

1. 遍历数据表中的每一个条目。
2. 对于每个条目，将第一个 `float` 值作为输入传递给 `sinf` 函数。
3. 将 `sinf` 函数的返回值与数据表中该条目的第二个 `float` 值进行比较。
4. 如果返回值与预期值在一定的误差范围内一致，则该测试用例通过。否则，测试失败，可能意味着 `sinf` 函数的实现存在 bug。

**为什么需要这样的数据表？**

* **覆盖各种情况:** 数据表中包含了各种各样的输入值，可以覆盖 `sinf` 函数在不同输入范围内的行为，包括边界情况和特殊值。
* **回归测试:**  在对 `sinf` 函数进行修改或优化后，可以使用这个数据表进行回归测试，确保修改没有引入新的错误。
* **平台一致性:**  确保在不同的 Android 设备和架构上，`sinf` 函数的行为保持一致。

总而言之，这段代码片段是 Android 系统中保障数学计算正确性的重要组成部分，它通过提供详细的测试用例来验证 `sinf` 函数的实现质量。

### 提示词
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
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
60f3fa460b85811d2ae710cd69ec3690p-3,
    -0x1.62b958p-3
  },
  { // Entry 380
    0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    0x1.62b958p-3
  },
  { // Entry 381
    -0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    -0x1.d8f720p-4
  },
  { // Entry 382
    0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    0x1.d8f720p-4
  },
  { // Entry 383
    -0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    -0x1.d8f720p-5
  },
  { // Entry 384
    0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    0x1.d8f720p-5
  },
  { // Entry 385
    0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    0x1.d8f720p-5
  },
  { // Entry 386
    -0x1.d8b3deba6ac493b04b2103a0dbaef02fp-5,
    -0x1.d8f720p-5
  },
  { // Entry 387
    0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    0x1.d8f720p-4
  },
  { // Entry 388
    -0x1.d7ea3d56e1e6244c8786d74f189d98acp-4,
    -0x1.d8f720p-4
  },
  { // Entry 389
    0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    0x1.62b958p-3
  },
  { // Entry 390
    -0x1.60f3fa460b85811d2ae710cd69ec3690p-3,
    -0x1.62b958p-3
  },
  { // Entry 391
    0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    0x1.d8f720p-3
  },
  { // Entry 392
    -0x1.d4c5bb872ea5375834ca0bca088d1d75p-3,
    -0x1.d8f720p-3
  },
  { // Entry 393
    0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    0x1.279a74p-2
  },
  { // Entry 394
    -0x1.2383ca2b249807d95005d96cfdaecd6cp-2,
    -0x1.279a74p-2
  },
  { // Entry 395
    0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    0x1.62b958p-2
  },
  { // Entry 396
    -0x1.5bac05e1e0a7c2de280fcb93be67a4dap-2,
    -0x1.62b958p-2
  },
  { // Entry 397
    0x1.92aba8981b25deda4cc1817251723a1bp-2,
    0x1.9dd83cp-2
  },
  { // Entry 398
    -0x1.92aba8981b25deda4cc1817251723a1bp-2,
    -0x1.9dd83cp-2
  },
  { // Entry 399
    0x1.c853c704e3b94322031d6b47aef853c9p-2,
    0x1.d8f720p-2
  },
  { // Entry 400
    -0x1.c853c704e3b94322031d6b47aef853c9p-2,
    -0x1.d8f720p-2
  },
  { // Entry 401
    0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    0x1.0a0b02p-1
  },
  { // Entry 402
    -0x1.fc769aecd265cfea08e0ff30c2fbcacdp-2,
    -0x1.0a0b02p-1
  },
  { // Entry 403
    0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    0x1.3d3e36p-1
  },
  { // Entry 404
    -0x1.2954644ceb8e3a2479c83ae84af57d3ep-1,
    -0x1.3d3e36p-1
  },
  { // Entry 405
    0x1.3aad00a09268a39df1653c70db91f157p-1,
    0x1.52e1f8p-1
  },
  { // Entry 406
    -0x1.3aad00a09268a39df1653c70db91f157p-1,
    -0x1.52e1f8p-1
  },
  { // Entry 407
    0x1.4b75bbae388a7f3466e7f2d6bdcf72bbp-1,
    0x1.6885bap-1
  },
  { // Entry 408
    -0x1.4b75bbae388a7f3466e7f2d6bdcf72bbp-1,
    -0x1.6885bap-1
  },
  { // Entry 409
    0x1.5ba6e8db1833475712b9a42a1ad0d2c2p-1,
    0x1.7e297cp-1
  },
  { // Entry 410
    -0x1.5ba6e8db1833475712b9a42a1ad0d2c2p-1,
    -0x1.7e297cp-1
  },
  { // Entry 411
    0x1.6b3920d8117828928fe10ac70ba69e76p-1,
    0x1.93cd3ep-1
  },
  { // Entry 412
    -0x1.6b3920d8117828928fe10ac70ba69e76p-1,
    -0x1.93cd3ep-1
  },
  { // Entry 413
    0x1.7a25450443098836c5202375db4b8462p-1,
    0x1.a971p-1
  },
  { // Entry 414
    -0x1.7a25450443098836c5202375db4b8462p-1,
    -0x1.a971p-1
  },
  { // Entry 415
    0x1.886482ae6797b38364f5c72ce9a3b76fp-1,
    0x1.bf14c2p-1
  },
  { // Entry 416
    -0x1.886482ae6797b38364f5c72ce9a3b76fp-1,
    -0x1.bf14c2p-1
  },
  { // Entry 417
    0x1.95f056337acc1d2d557525232e915467p-1,
    0x1.d4b884p-1
  },
  { // Entry 418
    -0x1.95f056337acc1d2d557525232e915467p-1,
    -0x1.d4b884p-1
  },
  { // Entry 419
    0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    0x1.ea5c3ep-1
  },
  { // Entry 420
    -0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    -0x1.ea5c3ep-1
  },
  { // Entry 421
    0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    0x1.12bd92p0
  },
  { // Entry 422
    -0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    -0x1.12bd92p0
  },
  { // Entry 423
    0x1.d294d2e06b3d10a4de263172d50f4497p-1,
    0x1.257b24p0
  },
  { // Entry 424
    -0x1.d294d2e06b3d10a4de263172d50f4497p-1,
    -0x1.257b24p0
  },
  { // Entry 425
    0x1.e0c04bb65bd33012be72a340df2c044bp-1,
    0x1.3838b6p0
  },
  { // Entry 426
    -0x1.e0c04bb65bd33012be72a340df2c044bp-1,
    -0x1.3838b6p0
  },
  { // Entry 427
    0x1.ec5884eb990c3deaaeebd3f0f84d6962p-1,
    0x1.4af648p0
  },
  { // Entry 428
    -0x1.ec5884eb990c3deaaeebd3f0f84d6962p-1,
    -0x1.4af648p0
  },
  { // Entry 429
    0x1.f54d9835b0e66e17612160272521f3b0p-1,
    0x1.5db3dap0
  },
  { // Entry 430
    -0x1.f54d9835b0e66e17612160272521f3b0p-1,
    -0x1.5db3dap0
  },
  { // Entry 431
    0x1.fb933d1cd931685e902e403a1baaecfdp-1,
    0x1.70716cp0
  },
  { // Entry 432
    -0x1.fb933d1cd931685e902e403a1baaecfdp-1,
    -0x1.70716cp0
  },
  { // Entry 433
    0x1.ff20d9d3e8984fec33982e42f5884f2cp-1,
    0x1.832efep0
  },
  { // Entry 434
    -0x1.ff20d9d3e8984fec33982e42f5884f2cp-1,
    -0x1.832efep0
  },
  { // Entry 435
    0x1.fff18f03a4b7e6aacf51f83931e85042p-1,
    0x1.95ec90p0
  },
  { // Entry 436
    -0x1.fff18f03a4b7e6aacf51f83931e85042p-1,
    -0x1.95ec90p0
  },
  { // Entry 437
    0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    0x1.a8aa1cp0
  },
  { // Entry 438
    -0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    -0x1.a8aa1cp0
  },
  { // Entry 439
    0x1.b3d36a96880cf69d9884a49f5381e917p-1,
    0x1.04aff8p0
  },
  { // Entry 440
    -0x1.b3d36a96880cf69d9884a49f5381e917p-1,
    -0x1.04aff8p0
  },
  { // Entry 441
    0x1.b3d41aebcf391c30c3d2f1ee7b79710cp-1,
    0x1.04b0a0p0
  },
  { // Entry 442
    -0x1.b3d41aebcf391c30c3d2f1ee7b79710cp-1,
    -0x1.04b0a0p0
  },
  { // Entry 443
    0x1.b3d4cb405ab3292be7df5b1b98032fbep-1,
    0x1.04b148p0
  },
  { // Entry 444
    -0x1.b3d4cb405ab3292be7df5b1b98032fbep-1,
    -0x1.04b148p0
  },
  { // Entry 445
    0x1.b3d57b942a7ad19e9b9892c9319e1be6p-1,
    0x1.04b1f0p0
  },
  { // Entry 446
    -0x1.b3d57b942a7ad19e9b9892c9319e1be6p-1,
    -0x1.04b1f0p0
  },
  { // Entry 447
    0x1.b3d62be73e8fc998c6c2df6590425613p-1,
    0x1.04b298p0
  },
  { // Entry 448
    -0x1.b3d62be73e8fc998c6c2df6590425613p-1,
    -0x1.04b298p0
  },
  { // Entry 449
    0x1.b3d6dc3996f1c52aa1f83bdee1d0e023p-1,
    0x1.04b340p0
  },
  { // Entry 450
    -0x1.b3d6dc3996f1c52aa1f83bdee1d0e023p-1,
    -0x1.04b340p0
  },
  { // Entry 451
    0x1.b3d78c8b33a07864b6a878573db34bcap-1,
    0x1.04b3e8p0
  },
  { // Entry 452
    -0x1.b3d78c8b33a07864b6a878573db34bcap-1,
    -0x1.04b3e8p0
  },
  { // Entry 453
    0x1.b3d83cdc149b9757df195ad885ab5201p-1,
    0x1.04b490p0
  },
  { // Entry 454
    -0x1.b3d83cdc149b9757df195ad885ab5201p-1,
    -0x1.04b490p0
  },
  { // Entry 455
    0x1.b3d8e8f9908360b38cd13fcbf6224d93p-1,
    0x1.04b534p0
  },
  { // Entry 456
    -0x1.b3d8e8f9908360b38cd13fcbf6224d93p-1,
    -0x1.04b534p0
  },
  { // Entry 457
    -0.0f,
    -0x1.p-149
  },
  { // Entry 458
    0.0f,
    0x1.p-149
  },
  { // Entry 459
    0.0,
    0.0
  },
  { // Entry 460
    0.0f,
    0x1.p-149
  },
  { // Entry 461
    -0.0f,
    -0x1.p-149
  },
  { // Entry 462
    0x1.1773d36a64df61d6715e60af063559f4p-1,
    0x1.279a72p-1
  },
  { // Entry 463
    -0x1.1773d36a64df61d6715e60af063559f4p-1,
    -0x1.279a72p-1
  },
  { // Entry 464
    0x1.1773d51767a78fe91b55f6b7e5fd44c2p-1,
    0x1.279a74p-1
  },
  { // Entry 465
    -0x1.1773d51767a78fe91b55f6b7e5fd44c2p-1,
    -0x1.279a74p-1
  },
  { // Entry 466
    0x1.1773d6c46a6ea687f03625194d25bb52p-1,
    0x1.279a76p-1
  },
  { // Entry 467
    -0x1.1773d6c46a6ea687f03625194d25bb52p-1,
    -0x1.279a76p-1
  },
  { // Entry 468
    0x1.f95b8f40501057ac49acef13993b0c55p-1,
    0x1.bb67acp0
  },
  { // Entry 469
    -0x1.f95b8f40501057ac49acef13993b0c55p-1,
    -0x1.bb67acp0
  },
  { // Entry 470
    0x1.f95b8e9be727702f7595ae1000a14a1ap-1,
    0x1.bb67aep0
  },
  { // Entry 471
    -0x1.f95b8e9be727702f7595ae1000a14a1ap-1,
    -0x1.bb67aep0
  },
  { // Entry 472
    0x1.f95b8df77e36a344670ed07149191a58p-1,
    0x1.bb67b0p0
  },
  { // Entry 473
    -0x1.f95b8df77e36a344670ed07149191a58p-1,
    -0x1.bb67b0p0
  },
  { // Entry 474
    0x1.b1d82e835a918de18f5fdadc8b1240cfp-2,
    0x1.bffffep-2
  },
  { // Entry 475
    -0x1.b1d82e835a918de18f5fdadc8b1240cfp-2,
    -0x1.bffffep-2
  },
  { // Entry 476
    0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    0x1.c0p-2
  },
  { // Entry 477
    -0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    -0x1.c0p-2
  },
  { // Entry 478
    0x1.b1d83222e830d83743258fd09040ee56p-2,
    0x1.c00002p-2
  },
  { // Entry 479
    -0x1.b1d83222e830d83743258fd09040ee56p-2,
    -0x1.c00002p-2
  },
  { // Entry 480
    0x1.44eb3691428062b27925c585ad59d62ap-1,
    0x1.5ffffep-1
  },
  { // Entry 481
    -0x1.44eb3691428062b27925c585ad59d62ap-1,
    -0x1.5ffffep-1
  },
  { // Entry 482
    0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    0x1.60p-1
  },
  { // Entry 483
    -0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    -0x1.60p-1
  },
  { // Entry 484
    0x1.44eb39a8a48bae6b98ae11c9400535e5p-1,
    0x1.600002p-1
  },
  { // Entry 485
    -0x1.44eb39a8a48bae6b98ae11c9400535e5p-1,
    -0x1.600002p-1
  },
  { // Entry 486
    0x1.dad9017b96408c375d4faf0e4776d1fcp-1,
    0x1.2ffffep0
  },
  { // Entry 487
    -0x1.dad9017b96408c375d4faf0e4776d1fcp-1,
    -0x1.2ffffep0
  },
  { // Entry 488
    0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    0x1.30p0
  },
  { // Entry 489
    -0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    -0x1.30p0
  },
  { // Entry 490
    0x1.dad904797f48ea4ef4fd2e47fe4d52bdp-1,
    0x1.300002p0
  },
  { // Entry 491
    -0x1.dad904797f48ea4ef4fd2e47fe4d52bdp-1,
    -0x1.300002p0
  },
  { // Entry 492
    0x1.4b708093c9cb45355e7821e5aad98ce8p-1,
    0x1.37fffep1
  },
  { // Entry 493
    -0x1.4b708093c9cb45355e7821e5aad98ce8p-1,
    -0x1.37fffep1
  },
  { // Entry 494
    0x1.4b707a7acdecc84239463e78b312fa10p-1,
    0x1.38p1
  },
  { // Entry 495
    -0x1.4b707a7acdecc84239463e78b312fa10p-1,
    -0x1.38p1
  },
  { // Entry 496
    0x1.4b707461d1f994476c677c5ad5ddb264p-1,
    0x1.380002p1
  },
  { // Entry 497
    -0x1.4b707461d1f994476c677c5ad5ddb264p-1,
    -0x1.380002p1
  },
  { // Entry 498
    0x1.066e7f705a6ca2b9e107f7dc9f3b26e6p-4,
    0x1.069c8cp-4
  },
  { // Entry 499
    -0x1.066e7f705a6ca2b9e107f7dc9f3b26e6p-4,
    -0x1.069c8cp-4
  },
  { // Entry 500
    0x1.05e476d27febc8b7e9690009b367c327p-3,
    0x1.069c8cp-3
  },
  { // Entry 501
    -0x1.05e476d27febc8b7e9690009b367c327p-3,
    -0x1.069c8cp-3
  },
  { // Entry 502
    0x1.877e2de5c9a066b8db595adc149af0c0p-3,
    0x1.89ead2p-3
  },
  { // Entry 503
    -0x1.877e2de5c9a066b8db595adc149af0c0p-3,
    -0x1.89ead2p-3
  },
  { // Entry 504
    0x1.03be07acb9dab719b4343a33b9fa6afep-2,
    0x1.069c8cp-2
  },
  { // Entry 505
    -0x1.03be07acb9dab719b4343a33b9fa6afep-2,
    -0x1.069c8cp-2
  },
  { // Entry 506
    0x1.42abbc5b3b2f91e8ece46e5effd28369p-2,
    0x1.4843b0p-2
  },
  { // Entry 507
    -0x1.42abbc5b3b2f91e8ece46e5effd28369p-2,
    -0x1.4843b0p-2
  },
  { // Entry 508
    0x1.804601411d93f4750919670061de07d9p-2,
    0x1.89ead4p-2
  },
  { // Entry 509
    -0x1.804601411d93f4750919670061de07d9p-2,
    -0x1.89ead4p-2
  },
  { // Entry 510
    0x1.bc4c08af356088b1694995bfaf8a297bp-2,
    0x1.cb91f8p-2
  },
  { // Entry 511
    -0x1.bc4c08af356088b1694995bfaf8a297bp-2,
    -0x1.cb91f8p-2
  },
  { // Entry 512
    0x1.f67eae34dc0b42b465fd2a3fb07564a4p-2,
    0x1.069c8ep-1
  },
  { // Entry 513
    -0x1.f67eae34dc0b42b465fd2a3fb07564a4p-2,
    -0x1.069c8ep-1
  },
  { // Entry 514
    0x1.17505c86231898fd86b18d2282d93eedp-1,
    0x1.277020p-1
  },
  { // Entry 515
    -0x1.17505c86231898fd86b18d2282d93eedp-1,
    -0x1.277020p-1
  },
  { // Entry 516
    0x1.323b8e40d16575e50dc7b6e567bb5084p-1,
    0x1.4843b2p-1
  },
  { // Entry 517
    -0x1.323b8e40d16575e50dc7b6e567bb5084p-1,
    -0x1.4843b2p-1
  },
  { // Entry 518
    0x1.4be49b08a1e1629cbdaa507e18255cd8p-1,
    0x1.691744p-1
  },
  { // Entry 519
    -0x1.4be49b08a1e1629cbdaa507e18255cd8p-1,
    -0x1.691744p-1
  },
  { // Entry 520
    0x1.6430847dbbbfd46cbebbc6d5f51c7c49p-1,
    0x1.89ead6p-1
  },
  { // Entry 521
    -0x1.6430847dbbbfd46cbebbc6d5f51c7c49p-1,
    -0x1.89ead6p-1
  },
  { // Entry 522
    0x1.7b05bb87b38844e56003c41ef804b273p-1,
    0x1.aabe68p-1
  },
  { // Entry 523
    -0x1.7b05bb87b38844e56003c41ef804b273p-1,
    -0x1.aabe68p-1
  },
  { // Entry 524
    0x1.904c3b389d55d3deddb39d05eb366571p-1,
    0x1.cb91fap-1
  },
  { // Entry 525
    -0x1.904c3b389d55d3deddb39d05eb366571p-1,
    -0x1.cb91fap-1
  },
  { // Entry 526
    0x1.a3eda211798a82697d62431f9ae46cc4p-1,
    0x1.ec658cp-1
  },
  { // Entry 527
    -0x1.a3eda211798a82697d62431f9ae46cc4p-1,
    -0x1.ec658cp-1
  },
  { // Entry 528
    0x1.b5d54883fcb6123bc28aac91f085e4eep-1,
    0x1.069c8ep0
  },
  { // Entry 529
    -0x1.b5d54883fcb6123bc28aac91f085e4eep-1,
    -0x1.069c8ep0
  },
  { // Entry 530
    0x1.c5f05a0135d4882c768cdf18e2e1112cp-1,
    0x1.170656p0
  },
  { // Entry 531
    -0x1.c5f05a0135d4882c768cdf18e2e1112cp-1,
    -0x1.170656p0
  },
  { // Entry 532
    0x1.d42de53e315c839ce188e201205e99dep-1,
    0x1.27701ep0
  },
  { // Entry 533
    -0x1.d42de53e315c839ce188e201205e99dep-1,
    -0x1.27701ep0
  },
  { // Entry 534
    0x1.e07eef45d91eea8a6cc7369aa0e55388p-1,
    0x1.37d9e6p0
  },
  { // Entry 535
    -0x1.e07eef45d91eea8a6cc7369aa0e55388p-1,
    -0x1.37d9e6p0
  },
  { // Entry 536
    0x1.ead6833b2aa002baa1c2b19a38dc9b79p-1,
    0x1.4843aep0
  },
  { // Entry 537
    -0x1.ead6833b2aa002baa1c2b19a38dc9b79p-1,
    -0x1.4843aep0
  },
  { // Entry 538
    0x1.f329bffa6a208591eecb6905d7594e3bp-1,
    0x1.58ad76p0
  },
  { // Entry 539
    -0x1.f329bffa6a208591eecb6905d7594e3bp-1,
    -0x1.58ad76p0
  },
  { // Entry 540
    0x1.f96fe38afbd95b5fcd08608110e9381fp-1,
    0x1.69173ep0
  },
  { // Entry 541
    -0x1.f96fe38afbd95b5fcd08608110e9381fp-1,
    -0x1.69173ep0
  },
  { // Entry 542
    0x1.fda25455d9567772f20f25d15efc6775p-1,
    0x1.798106p0
  },
  { // Entry 543
    -0x1.fda25455d9567772f20f25d15efc6775p-1,
    -0x1.798106p0
  },
  { // Entry 544
    0x1.ffbca816f1f1516ec5d757b0db54ae34p-1,
    0x1.89eacep0
  },
  { // Entry 545
    -0x1.ffbca816f1f1516ec5d757b0db54ae34p-1,
    -0x1.89eacep0
  },
  { // Entry 546
    0x1.ffbca88228b163189ab8d637db99bd2dp-1,
    0x1.9a5496p0
  },
  { // Entry 547
    -0x1.ffbca88228b163189ab8d637db99bd2dp-1,
    -0x1.9a5496p0
  },
  { // Entry 548
    0x1.fda255970ccddb9d127ecf63403c2bf7p-1,
    0x1.aabe5ep0
  },
  { // Entry 549
    -0x1.fda255970ccddb9d127ecf63403c2bf7p-1,
    -0x1.aabe5ep0
  },
  { // Entry 550
    0x1.f96fe5a0da244489fb2f4b97b3e48757p-1,
    0x1.bb2826p0
  },
  { // Entry 551
    -0x1.f96fe5a0da244489fb2f4b97b3e48757p-1,
    -0x1.bb2826p0
  },
  { // Entry 552
    0x1.f329c2e2c1a39bad8ecdcb87961ba44ap-1,
    0x1.cb91eep0
  },
  { // Entry 553
    -0x1.f329c2e2c1a39bad8ecdcb87961ba44ap-1,
    -0x1.cb91eep0
  },
  { // Entry 554
    0x1.ead686f2ec572c83ed34a01f764d193ep-1,
    0x1.dbfbb6p0
  },
  { // Entry 555
    -0x1.ead686f2ec572c83ed34a01f764d193ep-1,
    -0x1.dbfbb6p0
  },
  { // Entry 556
    0x1.e07ef3c91bd500a0de230ad573163163p-1,
    0x1.ec657ep0
  },
  { // Entry 557
    -0x1.e07ef3c91bd500a0de230ad573163163p-1,
    -0x1.ec657ep0
  },
  { // Entry 558
    0x1.d42dea8835c88adb9cde17347f934e25p-1,
    0x1.fccf46p0
  },
  { // Entry 559
    -0x1.d42dea8835c88adb9cde17347f934e25p-1,
    -0x1.fccf46p0
  },
  { // Entry 560
    0x1.c5f05e32c80fb0fe603033ec028a4c32p-1,
    0x1.069c88p1
  },
  { // Entry 561
    -0x1.c5f05e32c80fb0fe603033ec028a4c32p-1,
    -0x1.069c88p1
  },
  { // Entry 562
    0x1.b5d54d3732d3b2e79d4907e115401ddap-1,
    0x1.0ed16cp1
  },
  { // Entry 563
    -0x1.b5d54d3732d3b2e79d4907e115401ddap-1,
    -0x1.0ed16cp1
  },
  { // Entry 564
    0x1.a3eda74161d06b83ec2c8dc396d813b9p-1,
    0x1.170650p1
  },
  { // Entry 565
    -0x1.a3eda74161d06b83ec2c8dc396d813b9p-1,
    -0x1.170650p1
  },
  { // Entry 566
    0x1.904c421efce58f4e8170d36dcda8e02cp-1,
    0x1.1f3b34p1
  },
  { // Entry 567
    -0x1.904c421efce58f4e8170d36dcda8e02cp-1,
    -0x1.1f3b34p1
  },
  { // Entry 568
    0x1.7b05c45093944d6afb0c90d2f9cb217fp-1,
    0x1.277018p1
  },
  { // Entry 569
    -0x1.7b05c45093944d6afb0c90d2f9cb217fp-1,
    -0x1.277018p1
  },
  { // Entry 570
    0x1.64308f506ffdaf1326d10b3380278e98p-1,
    0x1.2fa4fcp1
  },
  { // Entry 571
    -0x1.64308f506ffdaf1326d10b3380278e98p-1,
    -0x1.2fa4fcp1
  },
  { // Entry 572
    0x1.4be4a8076c135a48f3f1a1aaa362475fp-1,
    0x1.37d9e0p1
  },
  { // Entry 573
    -0x1.4be4a8076c135a48f3f1a1aaa362475fp-1,
    -0x1.37d9e0p1
  },
  { // Entry 574
    0x1.323b9d888d4da77a610893735eeed1cbp-1,
    0x1.400ec4p1
  },
  { // Entry 575
    -0x1.323b9d888d4da77a610893735eeed1cbp-1,
    -0x1.400ec4p1
  },
  { // Entry 576
    0x1.17506e2dfb603d34b9af39b12c1db735p-1,
    0x1.4843a8p1
  },
  { // Entry 577
    -0x1.17506e2dfb603d34b9af39b12c1db735p-1,
    -0x1.4843a8p1
  },
  { // Entry 578
    0x1.f67ed667352d4827450013f15e321bfbp-2,
    0x1.50788cp1
  },
  { // Entry 579
    -0x1.f67ed667352d4827450013f15e321bfbp-2,
    -0x1.50788cp1
  },
  { // Entry 580
    0x1.bc4c35da51e34b776e5e04da58f23441p-2,
    0x1.58ad70p1
  },
  { // Entry 581
    -0x1.bc4c35da51e34b776e5e04da58f23441p-2,
    -0x1.58ad70p1
  },
  { // Entry 582
    0x1.8046336e68427cf756056d3f4edbb662p-2,
    0x1.60e254p1
  },
  { // Entry 583
    -0x1.8046336e68427cf756056d3f4edbb662p-2,
    -0x1.60e254p1
  },
  { // Entry 584
    0x1.42abf3872905e632f204c41b24af90b6p-2,
    0x1.691738p1
  },
  { // Entry 585
    -0x1.42abf3872905e632f204c41b24af90b6p-2,
    -0x1.691738p1
  },
  { // Entry 586
    0x1.03be43c699f3536990dcf5a6665ac239p-2,
    0x1.714c1cp1
  },
  { // Entry 587
    -0x1.03be43c699f3536990dcf5a6665ac239p-2,
    -0x1.714c1cp1
  },
  { // Entry 588
    0x1.877eadc2fdfc2f0db1e8b78cd3fbfbd2p-3,
    0x1.7981p1
  },
  { // Entry 589
    -0x1.877eadc2fdfc2f0db1e8b78cd3fbfbd2p-3,
    -0x1.7981p1
  },
  { // Entry 590
    0x1.05e4fdf846632a8208d90de72d3a6da8p-3,
    0x1.81b5e4p1
  },
  { // Entry 591
    -0x1.05e4fdf846632a8208d90de72d3a6da8p-3,
    -0x1.81b5e4p1
  },
  { // Entry 592
    0x1.066f9b630b72dff16450e89afdf7e048p-4,
    0x1.89eac8p1
  },
  { // Entry 593
    -0x1.066f9b630b72dff16450e89afdf7e048p-4,
    -0x1.89eac8p1
  },
  { // Entry 594
    0x1.03bdf0b79ccf739529d54d422861046cp-2,
    -0x1.81b5eep2
  },
  { // Entry 595
    -0x1.03bdf0b79ccf739529d54d422861046cp-2,
    0x1.81b5eep2
  },
  { // Entry 596
    0x1.f67e8b95f5460ea369a803837b721abdp-2,
    -0x1.714c26p2
  },
  { // Entry 597
    -0x1.f67e8b95f5460ea369a803837b721abdp-2,
    0x1.714c26p2
  },
  { // Entry 598
    0x1.643070791751dc0636d1854d2bdbc5d4p-1,
    -0x1.60e25ep2
  },
  { // Entry 599
    -0x1.643070791751dc0636d1854d2bdbc5d4p-1,
    0x1.60e25ep2
  },
  { // Entry 600
    0x1.b5d536f59113a43af30e8c9db8a951a5p-1,
    -0x1.507896p2
  },
  { // Entry 601
    -0x1.b5d536f59113a43af30e8c9db8a951a5p-1,
    0x1.507896p2
  },
  { // Entry 602
    0x1.ead679985549140318349f512dca7a6bp-1,
    -0x1.400ecep2
  },
  { // Entry 603
    -0x1.ead679985549140318349f512dca7a6bp-1,
    0x1.400ecep2
  },
  { // Entry 604
    0x1.ffbca7010e0b0452f56075cfd5982880p-1,
    -0x1.2fa506p2
  },
  { // Entry 605
    -0x1.ffbca7010e0b0452f56075cfd5982880p-1,
    0x1.2fa506p2
  },
  { // Entry 606
    0x1.f329ca6bfc7425d89c2b4b9ad73ab108p-1,
    -0x1.1f3b3ep2
  },
  { // Entry 607
    -0x1.f329ca6bfc7425d89c2b4b9ad73ab108p-1,
    0x1.1f3b3ep2
  },
  { // Entry 608
    0x1.c5f06fb69427ac0f2d69428d82b5e669p-1,
    -0x1.0ed176p2
  },
  { // Entry 609
    -0x1.c5f06fb69427ac0f2d69428d82b5e669p-1,
    0x1.0ed176p2
  },
  { // Entry 610
    0x1.7b05d864ec9802adbc4b5577c233836ap-1,
    -0x1.fccf5ap1
  },
  { // Entry 611
    -0x1.7b05d864ec9802adbc4b5577c233836ap-1,
    0x1.fccf5ap1
  },
  { // Entry 612
    0x1.1750808185a998bbcecc3a6ac0cb2907p-1,
    -0x1.dbfbc8p1
  },
  { // Entry 613
    -0x1.1750808185a998bbcecc3a6ac0cb2907p-1,
    0x1.dbfbc8p1
  },
  { // Entry 614
    0x1.42ac0dd9495211816bf04ca53bce4beap-2,
    -0x1.bb2836p1
  },
  { // Entry 615
    -0x1.42ac0dd9495211816bf04ca53bce4beap-2,
    0x1.bb2836p1
  },
  { // Entry 616
    0x1.066fca39a70b52d06f2cd7eab69c31f2p-4,
    -0x1.9a54a4p1
  },
  { // Entry 617
    -0x1.066fca39a70b52d06f2cd7eab69c31f2p-4,
    0x1.9a54a4p1
  },
  { // Entry 618
    -0x1.877d931298e6fbc654f065536cff2b54p-3,
    -0x1.798112p1
  },
  { // Entry 619
    0x1.877d931298e6fbc654f065536cff2b54p-3,
    0x1.798112p1
  },
  { // Entry 620
    -0x1.bc4bc2875eb6d38eda3b49cb2320b561p-2,
    -0x1.58ad80p1
  },
  { // Entry 621
    0x1.bc4bc2875eb6d38eda3b49cb2320b561p-2,
    0x1.58ad80p1
  },
  { // Entry 622
    -0x1.4be47d6354c4ced53780b1b519acdec2p-1,
    -0x1.37d9eep1
  },
  { // Entry 623
    0x1.4be47d6354c4ced53780b1b519acdec2p-1,
    0x1.37d9eep1
  },
  { // Entry 624
    -0x1.a3ed8bcb35cbcf8c6089f82a91c31d5bp-1,
    -0x1.17065cp1
  },
  { // Entry 625
    0x1.a3ed8bcb35cbcf8c6089f82a91c31d5bp-1,
    0x1.17065cp1
  },
  { // Entry 626
    -0x1.e07ee496ea109654c42e171fdc4537c4p-1,
    -0x1.ec6594p0
  },
  { // Entry 627
    0x1.e07ee496ea109654c42e171fdc4537c4p-1,
    0x1.ec6594p0
  },
  { // Entry 628
    -0x1.fda2522219689d0e8069d90f5c969b92p-1,
    -0x1.aabe70p0
  },
  { // Entry 629
    0x1.fda2522219689d0e8069d90f5c969b92p-1,
    0x1.aabe70p0
  },
  { // Entry 630
    -0x1.f96fe802fe570372d0fcb6e934b43061p-1,
    -0x1.69174cp0
  },
  { // Entry 631
    0x1.f96fe802fe570372d0fcb6e934b43061p-1,
    0x1.69174cp0
  },
  { // Entry 632
    -0x1.d42ded56ae88a6e1cf270af27e6f1804p-1,
    -0x1.277028p0
  },
  { // Entry 633
    0x1.d42ded56ae88a6e1cf270af27e6f1804p-1,
    0x1.277028p0
  },
  { // Entry 634
    -0x1.904c45326d6dde224381d1d590ada41cp-1,
    -0x1.cb920ap-1
  },
  { // Entry 635
    0x1.904c45326d6dde224381d1d590ada41cp-1,
    0x1.cb920ap-1
  },
  { // Entry 636
    -0x1.323b9cadbb19e75a44483fb64ad8ddf6p-1,
    -0x1.4843c4p-1
  },
  { // Entry 637
    0x1.323b9cadbb19e75a44483fb64ad8ddf6p-1,
    0x1.4843c4p-1
  },
  { // Entry 638
    -0x1.80462654bde766faf47f3140e290996dp-2,
    -0x1.89eafcp-2
  },
  { // Entry 639
    0x1.80462654bde766faf47f3140e290996dp-2,
    0x1.89eafcp-2
  },
  { // Entry 640
    -0x1.05e4ca21f386a82bc2e4efcdebb1962bp-3,
    -0x1.069ce0p-3
  },
  { // Entry 641
    0x1.05e4ca21f386a82bc2e4efcdebb1962bp-3,
    0x1.069ce0p-3
  },
  { // Entry 642
    0x1.05e423830be01f9fe3c57d06867e0056p-3,
    0x1.069c38p-3
  },
  { // Entry 643
    -0x1.05e423830be01f9fe3c57d06867e0056p-3,
    -0x1.069c38p-3
  },
  { // Entry 644
    0x1.8045d87852f1307fea6dc751c4d15992p-2,
    0x1.89eaa8p-2
  },
  { // Entry 645
    -0x1.8045d87852f1307fea6dc751c4d15992p-2,
    -0x1.89eaa8p-2
  },
  { // Entry 646
    0x1.323b7b04ee88cff98b2a1620e1f61a01p-1,
    0x1.48439ap-1
  },
  { // Entry 647
    -0x1.323b7b04ee88cff98b2a1620e1f61a01p-1,
    -0x1.48439ap-1
  },
  { // Entry 648
    0x1.904c2b02aa59528ce044bf2213c96859p-1,
    0x1.cb91e0p-1
  },
  { // Entry 649
    -0x1.904c2b02aa59528ce044bf2213c96859p-1,
    -0x1.cb91e0p-1
  },
  { // Entry 650
    0x1.d42ddd25b3797e6a679f76e05e6c3e08p-1,
    0x1.277014p0
  },
  { // Entry 651
    -0x1.d42ddd25b3797e6a679f76e05e6c3e08p-1,
    -0x1.277014p0
  },
  { // Entry 652
    0x1.f96fe1a0b12d0ad4fa8c82d8af989c5ap-1,
    0x1.691738p0
  },
  { // Entry 653
    -0x1.f96fe1a0b12d0ad4fa8c82d8af989c5ap-1,
    -0x1.691738p0
  },
  { // Entry 654
    0x1.fda255f96094d8fe4e859c4cf0dd68a5p-1,
    0x1.aabe5cp0
  },
  { // Entry 655
    -0x1.fda255f96094d8fe4e859c4cf0dd68a5p-1,
    -0x1.aabe5cp0
  },
  { // Entry 656
    0x1.e07ef267748b982778f8d50d2981bb3ap-1,
    0x1.ec6580p0
  },
  { // Entry 657
    -0x1.e07ef267748b982778f8d50d2981bb3ap-1,
    -0x1.ec6580p0
  },
  { // Entry 658
    0x1.a3eda2adb01143fb21453b20bd1748fep-1,
    0x1.170652p1
  },
  { // Entry 659
    -0x1.a3eda2adb01143fb21453b20bd1748fep-1,
    -0x1.170652p1
  },
  { // Entry 660
    0x1.4be49bd88a64a0bb414ddacac4fa8de9p-1,
    0x1.37d9e4p1
  },
  { // Entry 661
    -0x1.4be49bd88a64a0bb414ddacac4fa8de9p-1,
    -0x1.37d9e4p1
  },
  { // Entry 662
    0x1.bc4c0a9b3782e220ae55786369ccf190p-2,
    0x1.58ad76p1
  },
  { // Entry 663
    -0x1.bc4c0a9b3782e220ae55786369ccf190p-2,
    -0x1.58ad76p1
  },
  { // Entry 664
    0x1.877e301f43cafffe6644a8958f108729p-3,
    0x1.798108p1
  },
  { // Entry 665
    -0x1.877e301f43cafffe6644a8958f108729p-3,
    -0x1.798108p1
  },
  { // Entry 666
    -0x1.066e8ae1f824a69817e6a806e6317e28p-4,
    0x1.9a549ap1
  },
  { // Entry 667
    0x1.066e8ae1f824a69817e6a806e6317e28p-4,
    -0x1.9a549ap1
  },
  { // Entry 668
    -0x1.42abc1eca11a0ad12ca6eeff197318aap-2,
    0x1.bb282cp1
  },
  { // Entry 669
    0x1.42abc1eca11a0ad12ca6eeff197318aap-2,
    -0x1.bb282cp1
  },
  { // Entry 670
    -0x1.17505efb8119773c647468be1dfee45ep-1,
    0x1.dbfbbep1
  },
  { // Entry 671
    0x1.17505efb8119773c647468be1dfee45ep-1,
    -0x1.dbfbbep1
  },
  { // Entry 672
    -0x1.7b05bd8091cd79dff359c8412b0de1a9p-1,
    0x1.fccf50p1
  },
  { // Entry 673
    0x1.7b05bd8091cd79dff359c8412b0de1a9p-1,
    -0x1.fccf50p1
  },
  { // Entry 674
    -0x1.c5f05982eabf022748960961666d540dp-1,
    0x1.0ed170p2
  },
  { // Entry 675
    0x1.c5f05982eabf022748960961666d540dp-1,
    -0x1.0ed170p2
  },
  { // Entry 676
    -0x1.f329bfbda8122f83e3a1ea0242eb76aap-1,
    0x1.1f3b38p2
  },
  { // Entry 677
    0x1.f329bfbda8122f83e3a1ea0242eb76aap-1,
    -0x1.1f3b38p2
  },
  { // Entry 678
    -0x1.ffbca88ae90f0900b6d3ad89eddd2c80p-1,
    0x1.2fa5p2
  },
  { // Entry 679
    0x1.ffbca88ae90f0900b6d3ad89eddd2c80p-1,
    -0x1.2fa5p2
  },
  { // Entry 680
    -0x1.ead687409c95dcaf61af98513517f507p-1,
    0x1.400ec8p2
  },
  { // Entry 681
    0x1.ead687409c95dcaf61af98513517f507p-1,
    -0x1.400ec8p2
  },
  { // Entry 682
    -0x1.b5d54fd79372b90d5d4c7acf7adaed42p-1,
    0x1.507890p2
  },
  { // Entry 683
    0x1.b5d54fd79372b90d5d4c7acf7adaed42p-1,
    -0x1.507890p2
  },
  { // Entry 684
    -0x1.643092f42ae797375531420c005ca2cfp-1,
    0x1.60e258p2
  },
  { // Entry 685
    0x1.643092f42ae797375531420c005ca2cfp-1,
    -0x1.60e258p2
  },
  { // Entry 686
    -0x1.f67edf3b7bee8554d54d84ea83f6cb21p-2,
    0x1.714c20p2
  },
  { // Entry 687
    0x1.f67edf3b7bee8554d54d84ea83f6cb21p-2,
    -0x1.714c20p2
  },
  { // Entry 688
    -0x1.03be4d93d949325340b2f464201545a7p-2,
    0x1.81b5e8p2
  },
  { // Entry 689
    0x1.03be4d93d949325340b2f464201545a7p-2,
    -0x1.81b5e8p2
  },
  { // Entry 690
    0x1.efb26cfa20f2098ff7e9e42f0260eb01p-5,
    0x1.effffep-5
  },
  { // Entry 691
    -0x1.efb26cfa20f2098ff7e9e42f0260eb01p-5,
    -0x1.effffep-5
  },
  { // Entry 692
    0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    0x1.f0p-5
  },
  { // Entry 693
    -0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    -0x1.f0p-5
  },
  { // Entry 694
    0x1.efb270f840979c65b75ee5c67016a866p-5,
    0x1.f00002p-5
  },
  { // Entry 695
    -0x1.efb270f840979c65b75ee5c67016a866p-5,
    -0x1.f00002p-5
  },
  { // Entry 696
    0x1.f6baa816fce5ea5a60d8c9fd2a289380p-4,
    0x1.f7fffep-4
  },
  { // Entry 697
    -0x1.f6baa816fce5ea5a60d8c9fd2a289380p-4,
    -0x1.f7fffep-4
  },
  { // Entry 698
    0x1.f6baaa131de6438e5611279864fe7663p-4,
    0x1.f8p-4
  },
  { // Entry 699
    -0x1.f6baaa131de6438e5611279864fe7663p-4,
    -0x1.f8p-4
  },
  { // Entry 700
    0x1.f6baac0f3ee694e760a138bc06c8be3dp-4,
    0x1.f80002p-4
  },
  { // Entry 701
    -0x1.f6baac0f3ee694e760a138bc06c8be3dp-4,
    -0x1.f80002p-4
  },
  { // Entry 702
    0x1.4a8c395552fb432af31780e883c98f71p-3,
    0x1.4bfffep-3
  },
  { // Entry 703
    -0x1.4a8c395552fb432af31780e883c98f71p-3,
    -0x1.4bfffep-3
  },
  { // Entry 704
    0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    0x1.4cp-3
  },
  { // Entry 705
    -0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    -0x1.4cp-3
  },
  { // Entry 706
    0x1.4a8c3d47e604a7d54f3f7de402409e2cp-3,
    0x1.4c0002p-3
  },
  { // Entry 707
    -0x1.4a8c3d47e604a7d54f3f7de402409e2cp-3,
    -0x1.4c0002p-3
  },
  { // Entry 708
    0x1.2e9cd83630eb35c12efcfb8413583998p-2,
    0x1.333332p-2
  },
  { // Entry 709
    -0x1.2e9cd83630eb35c12efcfb8413583998p-2,
    -0x1.333332p-2
  },
  { // Entry 710
    0x1.2e9cda1f52c88042833f236ff0f9d486p-2,
    0x1.333334p-2
  },
  { // Entry 711
    -0x1.2e9cda1f52c88042833f236ff0f9d486p-2,
    -0x1.333334p-2
  },
  { // Entry 712
    0x1.2e9cdc0874a57f1ca0f976a9b01e4a71p-2,
    0x1.333336p-2
  },
  { // Entry 713
    -0x1.2e9cdc0874a57f1ca0f976a9b01e4a71p-2,
    -0x1.333336p-2
  },
  { // Entry 714
    0x1.3faefb2b68e6786eb692bd4e4045213ep-1,
    0x1.594316p-1
  },
  { // Entry 715
    -0x1.3faefb2b68e6786eb692bd4e4045213ep-1,
    -0x1.594316p-1
  },
  { // Entry 716
    0x1.3faefcbb57c26b0d84b63dbfb72b413bp-1,
    0x1.594318p-1
  },
  { // Entry 717
    -0x1.3faefcbb57c26b0d84b63dbfb72b413bp-1,
    -0x1.594318p-1
  },
  { // Entry 718
    0x1.3faefe4b469d1dfd561e666edda7c6e6p-1,
    0x1.59431ap-1
  },
  { // Entry 719
    -0x1.3faefe4b469d1dfd561e666edda7c6e6p-1,
    -0x1.59431ap-1
  },
  { // Entry 720
    0x1.6888a375ab228c1e031c4005769509f9p-1,
    0x1.8ffffep-1
  },
  { // Entry 721
    -0x1.6888a375ab228c1e031c4005769509f9p-1,
    -0x1.8ffffep-1
  },
  { // Entry 722
    0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    0x1.90p-1
  },
  { // Entry 723
    -0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    -0x1.90p-1
  },
  { // Entry 724
    0x1.6888a64cbe41dffd6e4768dcca4db53bp-1,
    0x1.900002p-1
  },
  { // Entry 725
    -0x1.6888a64cbe41dffd6e4768dcca4db53bp-1,
    -0x1.900002p-1
  },
  { // Entry 726
    -0.0f,
    -0x1.p-149
  },
  { // Entry 727
    0.0f,
    0x1.p-149
  },
  { // Entry 728
    0.0,
    0.0
  },
  { // Entry 729
    0.0f,
    0x1.p-149
  },
  { // Entry 730
    -0.0f,
    -0x1.p-149
  },
  { // Entry 731
    0x1.91f65dccfead353d8db9c32f12262730p-5,
    0x1.921fb4p-5
  },
  { // Entry 732
    -0x1.91f65dccfead353d8db9c32f12262730p-5,
    -0x1.921fb4p-5
  },
  { // Entry 733
    0x1.91f65fcc60cb6d09fcc5c35dd6a798c8p-5,
    0x1.921fb6p-5
  },
  { // Entry 734
    -0x1.91f65fcc60cb6d09fcc5c35dd6a798c8p-5,
    -0x1.921fb6p-5
  },
  { // Entry 735
    0x1.91f661cbc2e9a3447571f72bcfbc21e2p-5,
    0x1.921fb8p-5
  },
  { // Entry 736
    -0x1.91f661cbc2e9a3447571f72bcfbc21e2p-5,
    -0x1.921fb8p-5
  },
  { // Entry 737
    0x1.917a6a7fe8297bf0a1125fb02b2038aep-4,
    0x1.921fb4p-4
  },
  { // Entry 738
    -0x1.917a6a7fe8297bf0a1125fb02b2038aep-4,
    -0x1.921fb4p-4
  },
  { // Entry 739
    0x1.917a6c7d7103b9d90e09615164449c6bp-4,
    0x1.921fb6p-4
  },
  { // Entry 740
    -0x1.917a6c7d7103b9d90e09615164449c6bp-4,
    -0x1.921fb6p-4
  },
  { // Entry 741
    0x1.917a6e7af9ddf17b914e6d2e8e83b33ep-4,
    0x1.921fb8p-4
  },
  { // Entry 742
    -0x1.917a6e7af9ddf17b914e6d2e8e83b33ep-4,
    -0x1.921fb8p-4
  },
  { // Entry 743
    0x1.8f8b82889296b5cf7904db1e74b3466bp-3,
    0x1.921fb4p-3
  },
  { // Entry 744
    -0x1.8f8b82889296b5cf7904db1e74b3466bp-3,
    -0x1.921fb4p-3
  },
  { // Entry 745
    0x1.8f8b847ebc13b8998ec5b37e7065341ep-3,
    0x1.921fb6p-3
  },
  { // Entry 746
    -0x1.8f8b847ebc13b8998ec5b37e7065341ep-3,
    -0x1.921fb6p-3
  },
  { // Entry 747
    0x1.8f8b8674e590a26aec3ea01d30aed486p-3,
    0x1.921fb8p-3
  },
  { // Entry 748
    -0x1.8f8b8674e590a26aec3ea01d30aed486p-3,
    -0x1.921fb8p-3
  },
  { // Entry 749
    0x1.87de293f569717a42a3bdb01aeae2063p-2,
    0x1.921fb4p-2
  },
  { // Entry 750
    -0x1.87de293f569717a42a3bdb01aeae2063p-2,
    -0x1.921fb4p-2
  },
  { // Entry 751
    0x1.87de2b185d5417dca800b85ca1319043p-2,
    0x1.921fb6p-2
  },
  { // Entry 752
    -0x1.87de2b185d5417dca800b85ca1319043p-2,
    -0x1.921fb6p-2
  },
  { // Entry 753
    0x1.87de2cf16410b61d9aff7e628fc853b2p-2,
    0x1.921fb8p-2
  },
  { // Entry 754
    -0x1.87de2cf16410b61d9aff7e628fc853b2p-2,
    -0x1.921fb8p-2
  },
  { // Entry 755
    0x1.6a09e582aa3945461b5a8a0787d5ab5bp-1,
    0x1.921fb4p-1
  },
  { // Entry 756
    -0x1.6a09e582aa3945461b5a8a0787d5ab5bp-1,
    -0x1.921fb4p-1
  },
  { // Entry 757
    0x1.6a09e6ecb41fdd7e681872c854887019p-1,
    0x1.921fb6p-1
  },
  { // Entry 758
    -0x1.6a09e6ecb41fdd7e681872c854887019p-1,
    -0x1.921fb6p-1
  },
  { // Entry 759
    0x1.6a09e856be050baccde9a76961e84aa7p-1,
    0x1.921fb8p-1
  },
  { // Entry 760
    -0x1.6a09e856be050baccde9a76961e84aa7p-1,
    -0x1.921fb8p-1
  },
  { // Entry 761
    0x1.fffffffffffe6546cc38211c26dabeebp-1,
    0x1.921fb4p0
  },
  { // Entry 762
    -0x1.fffffffffffe6546cc38211c26dabeebp-1,
    -0x1.921fb4p0
  },
  { // Entry 763
    0x1.ffffffffffff76521249c7422930ed82p-1,
    0x1.921fb6p0
  },
  { // Entry 764
    -0x1.ffffffffffff76521249c7422930ed82p-1,
    -0x1.921fb6p0
  },
  { // Entry 765
    0x1.fffffffffff8875d585b6d6cfce97d9cp-1,
    0x1.921fb8p0
  },
  { // Entry 766
    -0x1.fffffffffff8875d585b6d6cfce97d9cp-1,
    -0x1.921fb8p0
  },
  { // Entry 767
    0x1.4442d184698831f15b6315bfa6b5ae75p-23,
    0x1.921fb4p1
  },
  { // Entry 768
    -0x1.444
```
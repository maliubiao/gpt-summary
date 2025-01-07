Response:
The user has provided a C source code file containing a large array of data. The file path suggests it's related to power function tests in Android's math library. The request asks for a summary of the file's functionality.

**Plan:**

1. **Identify the data structure:** The code defines a structure with three `double` members. The array is initialized with a large number of these structures.
2. **Infer the purpose:** Given the file path (`pow_intel_data.handroid`) and the data structure, it's highly likely this file contains test vectors for the `pow` function. The three doubles probably represent input values and the expected output.
3. **Summarize the function:** State that the file provides test data for the `pow` function.
这个C源代码文件 `bionic/tests/math_data/pow_intel_data.handroid` 的主要功能是**提供用于测试 `pow` 函数的测试数据**。

具体来说，它定义了一个包含多个条目的数组，每个条目都是一个结构体，该结构体包含三个 `double` 类型的浮点数。这些数据很可能被用作 `pow` 函数的输入（底数和指数）以及预期的输出结果，以便对 `pow` 函数的实现进行验证和测试。

**总结一下它的功能：**

这个文件是 Android Bionic 库中 `pow` 函数的测试数据集合，用于确保 `pow` 函数在各种输入情况下的正确性。 每个条目都包含了 `pow` 函数的一组测试用例，可能包括：

* **不同的底数：**  正数、负数、零、无穷大、NaN（非数字）等特殊值。
* **不同的指数：** 正数、负数、整数、小数、零、无穷大、NaN 等特殊值。
* **预期的结果：**  对于给定的底数和指数，`pow` 函数应该返回的正确结果。

这个文件可以被看作是 `pow` 函数的**黄金标准数据**，测试程序会用这些数据来比对实际计算结果，从而发现 `pow` 函数实现中的潜在错误或精度问题。

在后续的部分，如果需要更深入的分析，我们可以根据具体的需求进行展开。

Prompt: 
```
这是目录为bionic/tests/math_data/pow_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
,
    0x1.004p0, 0x1.0p2
  },
  { // Entry 320
    0x1.p5,
    0x1.0p-10, -0x1.0p-1
  },
  { // Entry 321
    0x1.p-5,
    0x1.0p-10, 0x1.0p-1
  },
  { // Entry 322
    0x1.ffc00bfd808be0873653647448220fdfp-1,
    0x1.004p0, -0x1.0p-1
  },
  { // Entry 323
    0x1.001ffe003ff601bfac107ca6b29a0c31p0,
    0x1.004p0, 0x1.0p-1
  },
  { // Entry 324
    0x1.01bd1e77170b415e7626621eb5aaff61p0,
    0x1.0p-10, -0x1.0p-10
  },
  { // Entry 325
    0x1.fc8bc4866e8ad2b963e1828b0761cbc6p-1,
    0x1.0p-10, 0x1.0p-10
  },
  { // Entry 326
    0x1.ffffe0040055355844443df8680a8e05p-1,
    0x1.004p0, -0x1.0p-10
  },
  { // Entry 327
    0x1.00000ffe00d5256285340e4f3ad36287p0,
    0x1.004p0, 0x1.0p-10
  },
  { // Entry 328
    0x1.0000000000000800000000000040p-1024,
    0x1.fffffffffffffp1023, -0x1.0p0
  },
  { // Entry 329
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023, 0x1.0p0
  },
  { // Entry 330
    0x1.3b2c47bff827194425605a92311acceep1020,
    0x1.0p-1074, -0x1.e666666666666p-1
  },
  { // Entry 331
    0x1.9fdf8bcce542f50814057837677baf82p-1021,
    0x1.0p-1074, 0x1.e666666666666p-1
  },
  { // Entry 332
    0x1.00000000000651591f9dd5cdb110f6e3p-384,
    0x1.fffffffffffffp-7, 0x1.fffffffffffffp5
  },
  { // Entry 333
    0x1.fffffffffffc000000000003efffffffp-385,
    0x1.fffffffffffffp-7, 0x1.0p6
  },
  { // Entry 334
    0x1.ffffffffffdaba9b8188aa7428411dd5p-385,
    0x1.fffffffffffffp-7, 0x1.0000000000001p6
  },
  { // Entry 335
    0x1.00000000000851591f9dd5dc4bc3361fp-384,
    0x1.0p-6, 0x1.fffffffffffffp5
  },
  { // Entry 336
    0x1.p-384,
    0x1.0p-6, 0x1.0p6
  },
  { // Entry 337
    0x1.ffffffffffdeba9b8188aa2ded7820e7p-385,
    0x1.0p-6, 0x1.0000000000001p6
  },
  { // Entry 338
    0x1.00000000000c51591f9dd6055127b496p-384,
    0x1.0000000000001p-6, 0x1.fffffffffffffp5
  },
  { // Entry 339
    0x1.000000000004000000000007e0p-384,
    0x1.0000000000001p-6, 0x1.0p6
  },
  { // Entry 340
    0x1.ffffffffffe6ba9b8188a9b917e62709p-385,
    0x1.0000000000001p-6, 0x1.0000000000001p6
  },
  { // Entry 341
    0x1.000000000002773a77d719106e939582p-160,
    0x1.fffffffffffffp-6, 0x1.fffffffffffffp4
  },
  { // Entry 342
    0x1.fffffffffffe000000000000f7ffffffp-161,
    0x1.fffffffffffffp-6, 0x1.0p5
  },
  { // Entry 343
    0x1.fffffffffff0231620a39c093f16f8cep-161,
    0x1.fffffffffffffp-6, 0x1.0000000000001p5
  },
  { // Entry 344
    0x1.000000000003773a77d7191361ce0d5ap-160,
    0x1.0p-5, 0x1.fffffffffffffp4
  },
  { // Entry 345
    0x1.p-160,
    0x1.0p-5, 0x1.0p5
  },
  { // Entry 346
    0x1.fffffffffff2231620a39bfa8a2d1972p-161,
    0x1.0p-5, 0x1.0000000000001p5
  },
  { // Entry 347
    0x1.000000000005773a77d7191c3042fd08p-160,
    0x1.0000000000001p-5, 0x1.fffffffffffffp4
  },
  { // Entry 348
    0x1.000000000002000000000001f0p-160,
    0x1.0000000000001p-5, 0x1.0p5
  },
  { // Entry 349
    0x1.fffffffffff6231620a39be2f0595ab9p-161,
    0x1.0000000000001p-5, 0x1.0000000000001p5
  },
  { // Entry 350
    0x1.000000000000e2e42fefa39f59e36bcbp-64,
    0x1.fffffffffffffp-5, 0x1.fffffffffffffp3
  },
  { // Entry 351
    0x1.ffffffffffff0000000000003bffffffp-65,
    0x1.fffffffffffffp-5, 0x1.0p4
  },
  { // Entry 352
    0x1.fffffffffff9746f4041718ed45990a2p-65,
    0x1.fffffffffffffp-5, 0x1.0000000000001p4
  },
  { // Entry 353
    0x1.00000000000162e42fefa39fe95583c3p-64,
    0x1.0p-4, 0x1.fffffffffffffp3
  },
  { // Entry 354
    0x1.p-64,
    0x1.0p-4, 0x1.0p4
  },
  { // Entry 355
    0x1.fffffffffffa746f4041718be29130c3p-65,
    0x1.0p-4, 0x1.0000000000001p4
  },
  { // Entry 356
    0x1.00000000000262e42fefa3a1bc39b3b3p-64,
    0x1.0000000000001p-4, 0x1.fffffffffffffp3
  },
  { // Entry 357
    0x1.00000000000100000000000078p-64,
    0x1.0000000000001p-4, 0x1.0p4
  },
  { // Entry 358
    0x1.fffffffffffc746f4041718767007104p-65,
    0x1.0000000000001p-4, 0x1.0000000000001p4
  },
  { // Entry 359
    0x1.000000000000451591f9dd5ba59328abp-24,
    0x1.fffffffffffffp-4, 0x1.fffffffffffffp2
  },
  { // Entry 360
    0x1.ffffffffffff8000000000000dffffffp-25,
    0x1.fffffffffffffp-4, 0x1.0p3
  },
  { // Entry 361
    0x1.fffffffffffd6ba9b8188a9332cfe24ap-25,
    0x1.fffffffffffffp-4, 0x1.0000000000001p3
  },
  { // Entry 362
    0x1.000000000000851591f9dd5bbdd88d2ap-24,
    0x1.0p-3, 0x1.fffffffffffffp2
  },
  { // Entry 363
    0x1.p-24,
    0x1.0p-3, 0x1.0p3
  },
  { // Entry 364
    0x1.fffffffffffdeba9b8188a92a7ba5050p-25,
    0x1.0p-3, 0x1.0000000000001p3
  },
  { // Entry 365
    0x1.000000000001051591f9dd5c18635627p-24,
    0x1.0000000000001p-3, 0x1.fffffffffffffp2
  },
  { // Entry 366
    0x1.0000000000008000000000001cp-24,
    0x1.0000000000001p-3, 0x1.0p3
  },
  { // Entry 367
    0x1.fffffffffffeeba9b8188a91e58f2c5cp-25,
    0x1.0000000000001p-3, 0x1.0000000000001p3
  },
  { // Entry 368
    0x1.0000000000000c5c85fdf473df375979p-8,
    0x1.fffffffffffffp-3, 0x1.fffffffffffffp1
  },
  { // Entry 369
    0x1.ffffffffffffc0000000000002ffffffp-9,
    0x1.fffffffffffffp-3, 0x1.0p2
  },
  { // Entry 370
    0x1.ffffffffffff0e8de8082e30ba42371ap-9,
    0x1.fffffffffffffp-3, 0x1.0000000000001p2
  },
  { // Entry 371
    0x1.0000000000002c5c85fdf473e242ea38p-8,
    0x1.0p-2, 0x1.fffffffffffffp1
  },
  { // Entry 372
    0x1.p-8,
    0x1.0p-2, 0x1.0p2
  },
  { // Entry 373
    0x1.ffffffffffff4e8de8082e30a513f41bp-9,
    0x1.0p-2, 0x1.0000000000001p2
  },
  { // Entry 374
    0x1.0000000000006c5c85fdf473f15a0bb8p-8,
    0x1.0000000000001p-2, 0x1.fffffffffffffp1
  },
  { // Entry 375
    0x1.00000000000040000000000006p-8,
    0x1.0000000000001p-2, 0x1.0p2
  },
  { // Entry 376
    0x1.ffffffffffffce8de8082e308cb76e1dp-9,
    0x1.0000000000001p-2, 0x1.0000000000001p2
  },
  { // Entry 377
    0x1.fffffffffffff62e42fefa39efcd9404p-3,
    0x1.fffffffffffffp-2, 0x1.fffffffffffffp0
  },
  { // Entry 378
    0x1.ffffffffffffe000000000000080p-3,
    0x1.fffffffffffffp-2, 0x1.0p1
  },
  { // Entry 379
    0x1.ffffffffffffb3a37a020b8c24c6d1c6p-3,
    0x1.fffffffffffffp-2, 0x1.0000000000001p1
  },
  { // Entry 380
    0x1.0000000000000b17217f7d1cf7d83c1ap-2,
    0x1.0p-1, 0x1.fffffffffffffp0
  },
  { // Entry 381
    0x1.p-2,
    0x1.0p-1, 0x1.0p1
  },
  { // Entry 382
    0x1.ffffffffffffd3a37a020b8c23810967p-3,
    0x1.0p-1, 0x1.0000000000001p1
  },
  { // Entry 383
    0x1.0000000000002b17217f7d1cf93b204ap-2,
    0x1.0000000000001p-1, 0x1.fffffffffffffp0
  },
  { // Entry 384
    0x1.00000000000020000000000001p-2,
    0x1.0000000000001p-1, 0x1.0p1
  },
  { // Entry 385
    0x1.00000000000009d1bd0105c611fabc53p-2,
    0x1.0000000000001p-1, 0x1.0000000000001p1
  },
  { // Entry 386
    0x1.fffffffffffff00000000000007fffffp-1,
    0x1.fffffffffffffp-1, 0x1.fffffffffffffp-1
  },
  { // Entry 387
    0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1, 0x1.0p0
  },
  { // Entry 388
    0x1.ffffffffffffefffffffffffffp-1,
    0x1.fffffffffffffp-1, 0x1.0000000000001p0
  },
  { // Entry 389
    0x1.p0,
    0x1.0p0, 0x1.fffffffffffffp-1
  },
  { // Entry 390
    0x1.p0,
    0x1.0p0, 0x1.0p0
  },
  { // Entry 391
    0x1.p0,
    0x1.0p0, 0x1.0000000000001p0
  },
  { // Entry 392
    0x1.0000000000000fffffffffffff7fffffp0,
    0x1.0000000000001p0, 0x1.fffffffffffffp-1
  },
  { // Entry 393
    0x1.00000000000010p0,
    0x1.0000000000001p0, 0x1.0p0
  },
  { // Entry 394
    0x1.00000000000010000000000001p0,
    0x1.0000000000001p0, 0x1.0000000000001p0
  },
  { // Entry 395
    0x1.6a09e667f3bcbf74c2970440d6d2a831p0,
    0x1.fffffffffffffp0, 0x1.fffffffffffffp-2
  },
  { // Entry 396
    0x1.6a09e667f3bcc3608b617397f7660a23p0,
    0x1.fffffffffffffp0, 0x1.0p-1
  },
  { // Entry 397
    0x1.6a09e667f3bccb381cf6524638ad6b43p0,
    0x1.fffffffffffffp0, 0x1.0000000000001p-1
  },
  { // Entry 398
    0x1.6a09e667f3bcc51cea30a40fc9c52aecp0,
    0x1.0p1, 0x1.fffffffffffffp-2
  },
  { // Entry 399
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p1, 0x1.0p-1
  },
  { // Entry 400
    0x1.6a09e667f3bcd0e0448ff2152c56bf1fp0,
    0x1.0p1, 0x1.0000000000001p-1
  },
  { // Entry 401
    0x1.6a09e667f3bcd06d3963e3adaf664e88p0,
    0x1.0000000000001p1, 0x1.fffffffffffffp-2
  },
  { // Entry 402
    0x1.6a09e667f3bcd459022e5304d0b08199p0,
    0x1.0000000000001p1, 0x1.0p-1
  },
  { // Entry 403
    0x1.6a09e667f3bcdc3093c331b3136584f9p0,
    0x1.0000000000001p1, 0x1.0000000000001p-1
  },
  { // Entry 404
    0x1.6a09e667f3bcc248d663d4285049157bp0,
    0x1.fffffffffffffp1, 0x1.fffffffffffffp-3
  },
  { // Entry 405
    0x1.6a09e667f3bcc6349f2e437f70faef9cp0,
    0x1.fffffffffffffp1, 0x1.0p-2
  },
  { // Entry 406
    0x1.6a09e667f3bcce0c30c3222db27f411dp0,
    0x1.fffffffffffffp1, 0x1.0000000000001p-2
  },
  { // Entry 407
    0x1.6a09e667f3bcc51cea30a40fc9c52aecp0,
    0x1.0p2, 0x1.fffffffffffffp-3
  },
  { // Entry 408
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p2, 0x1.0p-2
  },
  { // Entry 409
    0x1.6a09e667f3bcd0e0448ff2152c56bf1fp0,
    0x1.0p2, 0x1.0000000000001p-2
  },
  { // Entry 410
    0x1.6a09e667f3bccac511ca43debc8a6c6bp0,
    0x1.0000000000001p2, 0x1.fffffffffffffp-3
  },
  { // Entry 411
    0x1.6a09e667f3bcceb0da94b335dd97af1cp0,
    0x1.0000000000001p2, 0x1.0p-2
  },
  { // Entry 412
    0x1.6a09e667f3bcd6886c2991e41fd2d1bdp0,
    0x1.0000000000001p2, 0x1.0000000000001p-2
  },
  { // Entry 413
    0x1.4bfdad5362a26dd5e0bd02594b5812cbp0,
    0x1.fffffffffffffp2, 0x1.fffffffffffffp-4
  },
  { // Entry 414
    0x1.4bfdad5362a270883bcdab618baa8204p0,
    0x1.fffffffffffffp2, 0x1.0p-3
  },
  { // Entry 415
    0x1.4bfdad5362a275ecf1eefd720c603321p0,
    0x1.fffffffffffffp2, 0x1.0000000000001p-3
  },
  { // Entry 416
    0x1.4bfdad5362a26f21de6a55bbedc15eb4p0,
    0x1.0p3, 0x1.fffffffffffffp-4
  },
  { // Entry 417
    0x1.4bfdad5362a271d4397afec42e20e036p0,
    0x1.0p3, 0x1.0p-3
  },
  { // Entry 418
    0x1.4bfdad5362a27738ef9c50d4aef0b5e4p0,
    0x1.0p3, 0x1.0000000000001p-3
  },
  { // Entry 419
    0x1.4bfdad5362a271b9d9c4fc813278bab6p0,
    0x1.0000000000001p3, 0x1.fffffffffffffp-4
  },
  { // Entry 420
    0x1.4bfdad5362a2746c34d5a58972f260c9p0,
    0x1.0000000000001p3, 0x1.0p-3
  },
  { // Entry 421
    0x1.4bfdad5362a279d0eaf6f799f3f67f99p0,
    0x1.0000000000001p3, 0x1.0000000000001p-3
  },
  { // Entry 422
    0x1.306fe0a31b7150a04b58ad8027ceb050p0,
    0x1.fffffffffffffp3, 0x1.fffffffffffffp-5
  },
  { // Entry 423
    0x1.306fe0a31b7152465569f4a2a3da43d4p0,
    0x1.fffffffffffffp3, 0x1.0p-4
  },
  { // Entry 424
    0x1.306fe0a31b715592698c82e79bf84613p0,
    0x1.fffffffffffffp3, 0x1.0000000000001p-4
  },
  { // Entry 425
    0x1.306fe0a31b7151388348ff0de074c5a3p0,
    0x1.0p4, 0x1.fffffffffffffp-5
  },
  { // Entry 426
    0x1.306fe0a31b7152de8d5a46305c85edecp0,
    0x1.0p4, 0x1.0p-4
  },
  { // Entry 427
    0x1.306fe0a31b71562aa17cd47554af19b4p0,
    0x1.0p4, 0x1.0000000000001p-4
  },
  { // Entry 428
    0x1.306fe0a31b715268f329a22951b38f61p0,
    0x1.0000000000001p4, 0x1.fffffffffffffp-5
  },
  { // Entry 429
    0x1.306fe0a31b71540efd3ae94bcdcfe133p0,
    0x1.0000000000001p4, 0x1.0p-4
  },
  { // Entry 430
    0x1.306fe0a31b71575b115d7790c60f600dp0,
    0x1.0000000000001p4, 0x1.0000000000001p-4
  },
  { // Entry 431
    0x1.1d4873168b9aa641db97b491a37936aep0,
    0x1.fffffffffffffp4, 0x1.fffffffffffffp-6
  },
  { // Entry 432
    0x1.1d4873168b9aa739096362f6285cb516p0,
    0x1.fffffffffffffp4, 0x1.0p-5
  },
  { // Entry 433
    0x1.1d4873168b9aa92764fabfbf32263462p0,
    0x1.fffffffffffffp4, 0x1.0000000000001p-5
  },
  { // Entry 434
    0x1.1d4873168b9aa6892db47a348a21b2c7p0,
    0x1.0p5, 0x1.fffffffffffffp-6
  },
  { // Entry 435
    0x1.1d4873168b9aa7805b8028990f07a98bp0,
    0x1.0p5, 0x1.0p-5
  },
  { // Entry 436
    0x1.1d4873168b9aa96eb717856218d61990p0,
    0x1.0p5, 0x1.0000000000001p-5
  },
  { // Entry 437
    0x1.1d4873168b9aa717d1ee057a576c30c4p0,
    0x1.0000000000001p5, 0x1.fffffffffffffp-6
  },
  { // Entry 438
    0x1.1d4873168b9aa80effb9b3dedc571840p0,
    0x1.0000000000001p5, 0x1.0p-5
  },
  { // Entry 439
    0x1.1d4873168b9aa9fd5b5110a7e62f69b6p0,
    0x1.0000000000001p5, 0x1.0000000000001p-5
  },
  { // Entry 440
    0x1.11301d0125b5099e90ea43d6599ee2bbp0,
    0x1.fffffffffffffp5, 0x1.fffffffffffffp-7
  },
  { // Entry 441
    0x1.11301d0125b50a2c95ee0eb47aeb1a78p0,
    0x1.fffffffffffffp5, 0x1.0p-6
  },
  { // Entry 442
    0x1.11301d0125b50b489ff5a470bd846771p0,
    0x1.fffffffffffffp5, 0x1.0000000000001p-6
  },
  { // Entry 443
    0x1.11301d0125b509c0b6ede3fb103f9017p0,
    0x1.0p6, 0x1.fffffffffffffp-7
  },
  { // Entry 444
    0x1.11301d0125b50a4ebbf1aed9318ceac5p0,
    0x1.0p6, 0x1.0p-6
  },
  { // Entry 445
    0x1.11301d0125b50b6ac5f9449574287d9fp0,
    0x1.0p6, 0x1.0000000000001p-6
  },
  { // Entry 446
    0x1.11301d0125b50a0502f524447d7dc40ep0,
    0x1.0000000000001p6, 0x1.fffffffffffffp-7
  },
  { // Entry 447
    0x1.11301d0125b50a9307f8ef229ecd649ep0,
    0x1.0000000000001p6, 0x1.0p-6
  },
  { // Entry 448
    0x1.11301d0125b50baf120084dee16d833bp0,
    0x1.0000000000001p6, 0x1.0000000000001p-6
  },
  { // Entry 449
    0x1.ffffffffff2746f4041746255c99e90bp1023,
    0x1.ffffffffffffep0, 0x1.ffffffffffffep9
  },
  { // Entry 450
    0x1.ffffffffff53a37a020ba924b26cfc59p1023,
    0x1.ffffffffffffep0, 0x1.fffffffffffffp9
  },
  { // Entry 451
    0x1.ffffffffff80000000000ffbfffffffep1023,
    0x1.ffffffffffffep0, 0x1.0p10
  },
  { // Entry 452
    0x1.ffffffffffd8b90bfbe8e9328265d851p1023,
    0x1.ffffffffffffep0, 0x1.0000000000001p10
  },
  { // Entry 453
    HUGE_VAL,
    0x1.ffffffffffffep0, 0x1.0000000000002p10
  },
  { // Entry 454
    0x1.ffffffffff6746f404172f0d3b1a6bf2p1023,
    0x1.fffffffffffffp0, 0x1.ffffffffffffep9
  },
  { // Entry 455
    0x1.ffffffffff93a37a020b979a21ad3dcdp1023,
    0x1.fffffffffffffp0, 0x1.fffffffffffffp9
  },
  { // Entry 456
    0x1.ffffffffffc00000000003feffffffffp1023,
    0x1.fffffffffffffp0, 0x1.0p10
  },
  { // Entry 457
    HUGE_VAL,
    0x1.fffffffffffffp0, 0x1.0000000000001p10
  },
  { // Entry 458
    HUGE_VAL,
    0x1.fffffffffffffp0, 0x1.0000000000002p10
  },
  { // Entry 459
    0x1.ffffffffffa746f404171ff3199aeed7p1023,
    0x1.0p1, 0x1.ffffffffffffep9
  },
  { // Entry 460
    0x1.ffffffffffd3a37a020b8e0d90ed7f3fp1023,
    0x1.0p1, 0x1.fffffffffffffp9
  },
  { // Entry 461
    HUGE_VAL,
    0x1.0p1, 0x1.0p10
  },
  { // Entry 462
    HUGE_VAL,
    0x1.0p1, 0x1.0000000000001p10
  },
  { // Entry 463
    HUGE_VAL,
    0x1.0p1, 0x1.0000000000002p10
  },
  { // Entry 464
    HUGE_VAL,
    0x1.0000000000001p1, 0x1.ffffffffffffep9
  },
  { // Entry 465
    HUGE_VAL,
    0x1.0000000000001p1, 0x1.fffffffffffffp9
  },
  { // Entry 466
    HUGE_VAL,
    0x1.0000000000001p1, 0x1.0p10
  },
  { // Entry 467
    HUGE_VAL,
    0x1.0000000000001p1, 0x1.0000000000001p10
  },
  { // Entry 468
    HUGE_VAL,
    0x1.0000000000001p1, 0x1.0000000000002p10
  },
  { // Entry 469
    HUGE_VAL,
    0x1.0000000000002p1, 0x1.ffffffffffffep9
  },
  { // Entry 470
    HUGE_VAL,
    0x1.0000000000002p1, 0x1.fffffffffffffp9
  },
  { // Entry 471
    HUGE_VAL,
    0x1.0000000000002p1, 0x1.0p10
  },
  { // Entry 472
    HUGE_VAL,
    0x1.0000000000002p1, 0x1.0000000000001p10
  },
  { // Entry 473
    HUGE_VAL,
    0x1.0000000000002p1, 0x1.0000000000002p10
  },
  { // Entry 474
    0.0,
    0x1.ffffffffffffep0, -0x1.0cc0000000002p10
  },
  { // Entry 475
    0.0,
    0x1.ffffffffffffep0, -0x1.0cc0000000001p10
  },
  { // Entry 476
    0.0,
    0x1.ffffffffffffep0, -0x1.0ccp10
  },
  { // Entry 477
    0.0,
    0x1.ffffffffffffep0, -0x1.0cbffffffffffp10
  },
  { // Entry 478
    0.0,
    0x1.ffffffffffffep0, -0x1.0cbfffffffffep10
  },
  { // Entry 479
    0.0,
    0x1.fffffffffffffp0, -0x1.0cc0000000002p10
  },
  { // Entry 480
    0.0,
    0x1.fffffffffffffp0, -0x1.0cc0000000001p10
  },
  { // Entry 481
    0.0,
    0x1.fffffffffffffp0, -0x1.0ccp10
  },
  { // Entry 482
    0.0,
    0x1.fffffffffffffp0, -0x1.0cbffffffffffp10
  },
  { // Entry 483
    0.0,
    0x1.fffffffffffffp0, -0x1.0cbfffffffffep10
  },
  { // Entry 484
    0.0,
    0x1.0p1, -0x1.0cc0000000002p10
  },
  { // Entry 485
    0.0,
    0x1.0p1, -0x1.0cc0000000001p10
  },
  { // Entry 486
    0.0,
    0x1.0p1, -0x1.0ccp10
  },
  { // Entry 487
    0.0,
    0x1.0p1, -0x1.0cbffffffffffp10
  },
  { // Entry 488
    0.0,
    0x1.0p1, -0x1.0cbfffffffffep10
  },
  { // Entry 489
    0.0,
    0x1.0000000000001p1, -0x1.0cc0000000002p10
  },
  { // Entry 490
    0.0,
    0x1.0000000000001p1, -0x1.0cc0000000001p10
  },
  { // Entry 491
    0.0,
    0x1.0000000000001p1, -0x1.0ccp10
  },
  { // Entry 492
    0.0,
    0x1.0000000000001p1, -0x1.0cbffffffffffp10
  },
  { // Entry 493
    0.0,
    0x1.0000000000001p1, -0x1.0cbfffffffffep10
  },
  { // Entry 494
    0.0,
    0x1.0000000000002p1, -0x1.0cc0000000002p10
  },
  { // Entry 495
    0.0,
    0x1.0000000000002p1, -0x1.0cc0000000001p10
  },
  { // Entry 496
    0.0,
    0x1.0000000000002p1, -0x1.0ccp10
  },
  { // Entry 497
    0.0,
    0x1.0000000000002p1, -0x1.0cbffffffffffp10
  },
  { // Entry 498
    0.0,
    0x1.0000000000002p1, -0x1.0cbfffffffffep10
  },
  { // Entry 499
    0x1.a82e14690252e5ea2cfa30b25e947cedp-500,
    0x1.db6db6db6db70p-2, 0x1.c30c30c30c2fep8
  },
  { // Entry 500
    0x1.a82e1469023e8ea567883fcd2742e4b7p-500,
    0x1.db6db6db6db70p-2, 0x1.c30c30c30c2ffp8
  },
  { // Entry 501
    0x1.a82e1469022a3760a2164fe1a4cd3aa2p-500,
    0x1.db6db6db6db70p-2, 0x1.c30c30c30c3p8
  },
  { // Entry 502
    0x1.a82e14690215e01bdca460efd7337eaep-500,
    0x1.db6db6db6db70p-2, 0x1.c30c30c30c301p8
  },
  { // Entry 503
    0x1.a82e1469020188d7173272f7be75b0dcp-500,
    0x1.db6db6db6db70p-2, 0x1.c30c30c30c302p8
  },
  { // Entry 504
    0x1.a82e1469026c0cbfe6135b38e76d3a47p-500,
    0x1.db6db6db6db71p-2, 0x1.c30c30c30c2fep8
  },
  { // Entry 505
    0x1.a82e14690257b57b20a1691fd0d853d6p-500,
    0x1.db6db6db6db71p-2, 0x1.c30c30c30c2ffp8
  },
  { // Entry 506
    0x1.a82e146902435e365b2f78006f1f5b87p-500,
    0x1.db6db6db6db71p-2, 0x1.c30c30c30c3p8
  },
  { // Entry 507
    0x1.a82e1469022f06f195bd87dac2425159p-500,
    0x1.db6db6db6db71p-2, 0x1.c30c30c30c301p8
  },
  { // Entry 508
    0x1.a82e1469021aafacd04b98aeca41354dp-500,
    0x1.db6db6db6db71p-2, 0x1.c30c30c30c302p8
  },
  { // Entry 509
    0x1.a82e1469028533959f2c873c61cafb18p-500,
    0x1.db6db6db6db72p-2, 0x1.c30c30c30c2fep8
  },
  { // Entry 510
    0x1.a82e14690270dc50d9ba93ef6bf2c66dp-500,
    0x1.db6db6db6db72p-2, 0x1.c30c30c30c2ffp8
  },
  { // Entry 511
    0x1.a82e1469025c850c1448a19c2af67fe4p-500,
    0x1.db6db6db6db72p-2, 0x1.c30c30c30c3p8
  },
  { // Entry 512
    0x1.a82e146902482dc74ed6b0429ed6277cp-500,
    0x1.db6db6db6db72p-2, 0x1.c30c30c30c301p8
  },
  { // Entry 513
    0x1.a82e14690233d6828964bfe2c791bd35p-500,
    0x1.db6db6db6db72p-2, 0x1.c30c30c30c302p8
  },
  { // Entry 514
    0x1.a82e1469029e5a6b5845b4bccdadbf62p-500,
    0x1.db6db6db6db73p-2, 0x1.c30c30c30c2fep8
  },
  { // Entry 515
    0x1.a82e1469028a032692d3c03bf8923c7cp-500,
    0x1.db6db6db6db73p-2, 0x1.c30c30c30c2ffp8
  },
  { // Entry 516
    0x1.a82e14690275abe1cd61ccb4d852a7b9p-500,
    0x1.db6db6db6db73p-2, 0x1.c30c30c30c3p8
  },
  { // Entry 517
    0x1.a82e14690261549d07efda276cef0116p-500,
    0x1.db6db6db6db73p-2, 0x1.c30c30c30c301p8
  },
  { // Entry 518
    0x1.a82e1469024cfd58427de893b6674895p-500,
    0x1.db6db6db6db73p-2, 0x1.c30c30c30c302p8
  },
  { // Entry 519
    0x1.a82e146902b78141115ee3ba2b158723p-500,
    0x1.db6db6db6db74p-2, 0x1.c30c30c30c2fep8
  },
  { // Entry 520
    0x1.a82e146902a329fc4becee0576b6b603p-500,
    0x1.db6db6db6db74p-2, 0x1.c30c30c30c2ffp8
  },
  { // Entry 521
    0x1.a82e1469028ed2b7867af94a7733d305p-500,
    0x1.db6db6db6db74p-2, 0x1.c30c30c30c3p8
  },
  { // Entry 522
    0x1.a82e1469027a7b72c10905892c8cde29p-500,
    0x1.db6db6db6db74p-2, 0x1.c30c30c30c301p8
  },
  { // Entry 523
    0x1.a82e14690266242dfb9712c196c1d76dp-500,
    0x1.db6db6db6db74p-2, 0x1.c30c30c30c302p8
  },
  { // Entry 524
    -0x1.ffffffffffffe0000000000001ffffffp-1,
    -0x1.0000000000001p0, -0x1.0p0
  },
  { // Entry 525
    -0x1.p0,
    -0x1.0p0, -0x1.0p0
  },
  { // Entry 526
    -0x1.0000000000000800000000000040p0,
    -0x1.fffffffffffffp-1, -0x1.0p0
  },
  { // Entry 527
    HUGE_VAL,
    0x1.0p1, 0x1.0p10
  },
  { // Entry 528
    HUGE_VAL,
    0x1.0p2, 0x1.0p9
  },
  { // Entry 529
    0x1.ffffffffffec5c85fdf4743fd612b28ap-1025,
    0x1.fffffffffffffp-2, 0x1.fffffffffffffp9
  },
  { // Entry 530
    0x1.ffffffffffc00000000003feffffffffp-1025,
    0x1.fffffffffffffp-2, 0x1.0p10
  },
  { // Entry 531
    0x1.ffffffffff6746f404172f053b1a6bf2p-1025,
    0x1.fffffffffffffp-2, 0x1.0000000000001p10
  },
  { // Entry 532
    0x1.0000000000162e42fefa3ae53369388cp-1024,
    0x1.0p-1, 0x1.fffffffffffffp9
  },
  { // Entry 533
    0x1.p-1024,
    0x1.0p-1, 0x1.0p10
  },
  { // Entry 534
    0x1.ffffffffffa746f404171ff3199aeed7p-1025,
    0x1.0p-1, 0x1.0000000000001p10
  },
  { // Entry 535
    0x1.0000000000562e42fefa486cc428f71cp-1024,
    0x1.0000000000001p-1, 0x1.fffffffffffffp9
  },
  { // Entry 536
    0x1.0000000000400000000007fep-1024,
    0x1.0000000000001p-1, 0x1.0p10
  },
  { // Entry 537
    0x1.000000000013a37a020b8ce46b4dfa4ep-1024,
    0x1.0000000000001p-1, 0x1.0000000000001p10
  },
  { // Entry 538
    0x1.000000000074519a5623533df8dcd353p-1074,
    0x1.0p-1074, 0x1.ffffffffffffbp-1
  },
  { // Entry 539
    0x1.00000000005d0e1511b5d7f72c61368ap-1074,
    0x1.0p-1074, 0x1.ffffffffffffcp-1
  },
  { // Entry 540
    0x1.000000000045ca8fcd485ecd93a6ec9dp-1074,
    0x1.0p-1074, 0x1.ffffffffffffdp-1
  },
  { // Entry 541
    0x1.00000000002e870a88dae7c12eadf58cp-1074,
    0x1.0p-1074, 0x1.ffffffffffffep-1
  },
  { // Entry 542
    0x1.0000000000174385446d72d1fd765158p-1074,
    0x1.0p-1074, 0x1.fffffffffffffp-1
  },
  { // Entry 543
    0x1.p-1074,
    0x1.0p-1074, 0x1.0p0
  },
  { // Entry 544
    0.0,
    0x1.0p-1074, 0x1.0000000000001p0
  },
  { // Entry 545
    0.0,
    0x1.0p-1074, 0x1.0000000000002p0
  },
  { // Entry 546
    0.0,
    0x1.0p-1074, 0x1.0000000000003p0
  },
  { // Entry 547
    0.0,
    0x1.0p-1074, 0x1.0000000000004p0
  },
  { // Entry 548
    0.0,
    0x1.0p-1074, 0x1.0000000000005p0
  },
  { // Entry 549
    0x1.00000000007435e082649a68f64fe306p-1073,
    0x1.0p-1073, 0x1.ffffffffffffbp-1
  },
  { // Entry 550
    0x1.00000000005cf7e6ceb6ddb52e1b099ep-1073,
    0x1.0p-1073, 0x1.ffffffffffffcp-1
  },
  { // Entry 551
    0x1.000000000045b9ed1b09231d97c56c9dp-1073,
    0x1.0p-1073, 0x1.ffffffffffffdp-1
  },
  { // Entry 552
    0x1.00000000002e7bf3675b6aa2334f0c02p-1073,
    0x1.0p-1073, 0x1.ffffffffffffep-1
  },
  { // Entry 553
    0x1.0000000000173df9b3adb44300b7e7cep-1073,
    0x1.0p-1073, 0x1.fffffffffffffp-1
  },
  { // Entry 554
    0x1.p-1073,
    0x1.0p-1073, 0x1.0p0
  },
  { // Entry 555
    0x1.ffffffffffa3081931493b9d285bcb2bp-1074,
    0x1.0p-1073, 0x1.0000000000001p0
  },
  { // Entry 556
    0x1.ffffffffff4610326292881bdfb17983p-1074,
    0x1.0p-1073, 0x1.0000000000002p0
  },
  { // Entry 557
    0x1.fffffffffee9184b93dbe57c26010b04p-1074,
    0x1.0p-1073, 0x1.0000000000003p0
  },
  { // Entry 558
    0x1.fffffffffe8c2064c52553bdfb4a7fadp-1074,
    0x1.0p-1073, 0x1.0000000000004p0
  },
  { // Entry 559
    0x1.fffffffffe2f287df66ed2e15f8dd77ap-1074,
    0x1.0p-1073, 0x1.0000000000005p0
  },
  { // Entry 560
    0x1.8000000000ae387cd1e8f3f39fe157f9p-1073,
    0x1.8p-1073, 0x1.ffffffffffffbp-1
  },
  { // Entry 561
    0x1.80000000008b6063db20bcd67b4f5ba5p-1073,
    0x1.8p-1073, 0x1.ffffffffffffcp-1
  },
  { // Entry 562
    0x1.800000000068884ae45888e2bf6fd4afp-1073,
    0x1.8p-1073, 0x1.ffffffffffffdp-1
  },
  { // Entry 563
    0x1.800000000045b031ed9058186c42c317p-1073,
    0x1.8p-1073, 0x1.ffffffffffffep-1
  },
  { // Entry 564
    0x1.800000000022d818f6c82a7781c826dcp-1073,
    0x1.8p-1073, 0x1.fffffffffffffp-1
  },
  { // Entry 565
    0x1.80p-1073,
    0x1.8p-1073, 0x1.0p0
  },
  { // Entry 566
    0x1.7fffffffffba4fce126fb48d3687125dp-1073,
    0x1.8p-1073, 0x1.0000000000001p0
  },
  { // Entry 567
    0x1.7fffffffff749f9c24df75c00fd7fa2ep-1073,
    0x1.8p-1073, 0x1.0000000000002p0
  },
  { // Entry 568
    0x1.7fffffffff2eef6a374f43988bf2b76ep-1073,
    0x1.8p-1073, 0x1.0000000000003p0
  },
  { // Entry 569
    0x1.7ffffffffee93f3849bf1e16aad74a1dp-1073,
    0x1.8p-1073, 0x1.0000000000004p0
  },
  { // Entry 570
    0x1.7ffffffffea38f065c2f053a6c85b237p-1073,
    0x1.8p-1073, 0x1.0000000000005p0
  },
  { // Entry 571
    0x1.000000a0cf65eb1817a7095d9a0443a7p0,
    0x1.0p-29, -0x1.0p-29
  },
  { // Entry 572
    0x1.ffffff5f309a60aad5c2309f81f90defp-1,
    0x1.0p-29, 0x1.0p-30
  },
  { // Entry 573
    0x1.fffffd9e07cf07767a55afbe9acae93ep-1,
    0x1.0p55, -0x1.0p-29
  },
  { // Entry 574
    0x1.000000987e0cc66344d89b494e1f43b3p0,
    0x1.0p55, 0x1.0p-30
  },
  { // Entry 575
    0x1.fffffd669427cf159515873887c17cf2p-1,
    0x1.0p60, -0x1.0p-29
  },
  { // Entry 576
    0x1.000000a65af6ae61be88ea2558790cd7p0,
    0x1.0p60, 0x1.0p-30
  },
  { // Entry 577
    0x1.fffffffffe0000000000fff7ffffffaap-1,
    0x1.fffffffffffffp-1, 0x1.0p13
  },
  { // Entry 578
    0x1.fffffffff0000000003fffbfffff5557p-1,
    0x1.fffffffffffffp-1, 0x1.0p16
  },
  { // Entry 579
    0x1.p0,
    0x1.0p0, 0x1.0p13
  },
  { // Entry 580
    0x1.p0,
    0x1.0p0, 0x1.0p16
  },
  { // Entry 581
    0x1.00000000020000000001fff000000155p0,
    0x1.0000000000001p0, 0x1.0p13
  },
  { // Entry 582
    0x1.0000000010000000007fff800002aaa2p0,
    0x1.0000000000001p0, 0x1.0p16
  },
  { // Entry 583
    0x1.ffffffc0000004000001d5555516aaaap-1,
    -0x1.0000000000001p0, -0x1.0p25
  },
  { // Entry 584
    0x1.fffffe000000ffffffbaaaaab0000003p-1,
    -0x1.0000000000001p0, -0x1.0p28
  },
  { // Entry 585
    0x1.p0,
    -0x1.0p0, -0x1.0p25
  },
  { // Entry 586
    0x1.p0,
    -0x1.0p0, -0x1.0p28
  },
  { // Entry 587
    0x1.0000001000000080000042aaaaaeb555p0,
    -0x1.fffffffffffffp-1, -0x1.0p25
  },
  { // Entry 588
    0x1.00000080000020000007555557p0,
    -0x1.fffffffffffffp-1, -0x1.0p28
  },
  { // Entry 589
    0x1.368b2fc6f960a4c1d9aa628fe3f13fffp-1,
    -0x1.0000000000001p0, -0x1.0p51
  },
  { // Entry 590
    0x1.5fc21041027b23b05156b8aea8b5e925p-12,
    -0x1.0000000000001p0, -0x1.0p55
  },
  { // Entry 591
    0x1.p0,
    -0x1.0p0, -0x1.0p51
  },
  { // Entry 592
    0x1.p0,
    -0x1.0p0, -0x1.0p55
  },
  { // Entry 593
    0x1.48b5e3c3e81867bf31a77a83c32c4744p0,
    -0x1.fffffffffffffp-1, -0x1.0p51
  },
  { // Entry 594
    0x1.b4c902e273a5a1c56701e715edaf2115p5,
    -0x1.fffffffffffffp-1, -0x1.0p55
  },
  { // Entry 595
    0x1.5fc21041027b23b05156b8aea8b5e925p-12,
    -0x1.0000000000001p0, -0x1.0p55
  },
  { // Entry 596
    0x1.969d47321e4fe7f9bb8c43a5e486b9aep-93,
    -0x1.0000000000001p0, -0x1.0p58
  },
  { // Entry 597
    0x1.p0,
    -0x1.0p0, -0x1.0p55
  },
  { // Entry 598
    0x1.p0,
    -0x1.0p0, -0x1.0p58
  },
  { // Entry 599
    0x1.b4c902e273a5a1c56701e715edaf2115p5,
    -0x1.fffffffffffffp-1, -0x1.0p55
  },
  { // Entry 600
    0x1.1f43fcc4b663577a45ea9b49cce9ee73p46,
    -0x1.fffffffffffffp-1, -0x1.0p58
  },
  { // Entry 601
    0x1.44109edb20a756ad767d2515c94a003ap-739,
    -0x1.0000000000001p0, -0x1.0p61
  },
  { // Entry 602
    0.0,
    -0x1.0000000000001p0, -0x1.0p64
  },
  { // Entry 603
    0x1.p0,
    -0x1.0p0, -0x1.0p61
  },
  { // Entry 604
    0x1.p0,
    -0x1.0p0, -0x1.0p64
  },
  { // Entry 605
    0x1.41c7a8814bf0a801c5353f302a40cc7fp369,
    -0x1.fffffffffffffp-1, -0x1.0p61
  },
  { // Entry 606
    HUGE_VAL,
    -0x1.fffffffffffffp-1, -0x1.0p64
  },
  { // Entry 607
    0x1.0000001000000080000042aaaaaeb555p0,
    0x1.fffffffffffffp-1, -0x1.0p25
  },
  { // Entry 608
    0x1.00000080000020000007555557p0,
    0x1.fffffffffffffp-1, -0x1.0p28
  },
  { // Entry 609
    0x1.p0,
    0x1.0p0, -0x1.0p25
  },
  { // Entry 610
    0x1.p0,
    0x1.0p0, -0x1.0p28
  },
  { // Entry 611
    0x1.ffffffc0000004000001d5555516aaaap-1,
    0x1.0000000000001p0, -0x1.0p25
  },
  { // Entry 612
    0x1.fffffe000000ffffffbaaaaab0000003p-1,
    0x1.0000000000001p0, -0x1.0p28
  },
  { // Entry 613
    0x1.48b5e3c3e81867bf31a77a83c32c4744p0,
    0x1.fffffffffffffp-1, -0x1.0p51
  },
  { // Entry 614
    0x1.b4c902e273a5a1c56701e715edaf2115p5,
    0x1.fffffffffffffp-1, -0x1.0p55
  },
  { // Entry 615
    0x1.p0,
    0x1.0p0, -0x1.0p51
  },
  { // Entry 616
    0x1.p0,
    0x1.0p0, -0x1.0p55
  },
  { // Entry 617
    0x1.368b2fc6f960a4c1d9aa628fe3f13fffp-1,
    0x1.0000000000001p0, -0x1.0p51
  },
  { // Entry 618
    0x1.5fc21041027b23b05156b8aea8b5e925p-12,
    0x1.0000000000001p0, -0x1.0p55
  },
  { // Entry 619
    0x1.b4c902e273a5a1c56701e715edaf2115p5,
    0x1.fffffffffffffp-1, -0x1.0p55
  },
  { // Entry 620
    0x1.1f43fcc4b663577a45ea9b49cce9ee73p46,
    0x1.fffffffffffffp-1, -0x1.0p58
  },
  { // Entry 621
    0x1.p0,
    0x1.0p0, -0x1.0p55
  },
  { // Entry 622
    0x1.p0,
    0x1.0p0, -0x1.0p58
  },
  { // Entry 623
    0x1.5fc21041027b23b05156b8aea8b5e925p-12,
    0x1.0000000000001p0, -0x1.0p55
  },
  { // Entry 624
    0x1.969d47321e4fe7f9bb8c43a5e486b9aep-93,
    0x1.0000000000001p0, -0x1.0p58
  },
  { // Entry 625
    0x1.41c7a8814bf0a801c5353f302a40cc7fp369,
    0x1.fffffffffffffp-1, -0x1.0p61
  },
  { // Entry 626
    HUGE_VAL,
    0x1.fffffffffffffp-1, -0x1.0p64
  },
  { // Entry 627
    0x1.p0,
    0x1.0p0, -0x1.0p61
  },
  { // Entry 628
    0x1.p0,
    0x1.0p0, -0x1.0p64
  },
  { // Entry 629
    0x1.44109edb20a756ad767d2515c94a003ap-739,
    0x1.0000000000001p0, -0x1.0p61
  },
  { // Entry 630
    0.0,
    0x1.0000000000001p0, -0x1.0p64
  },
  { // Entry 631
    HUGE_VAL,
    -0x1.0p15, 0x1.0p63
  },
  { // Entry 632
    HUGE_VAL,
    0.0, -0x1.8p1
  },
  { // Entry 633
    -HUGE_VAL,
    -0.0, -0x1.8p1
  },
  { // Entry 634
    HUGE_VAL,
    0.0, -0x1.0p0
  },
  { // Entry 635
    -HUGE_VAL,
    -0.0, -0x1.0p0
  },
  { // Entry 636
    HUGE_VAL,
    0.0, -0x1.fffffffffffffp1023
  },
  { // Entry 637
    HUGE_VAL,
    0.0, -0x1.8p2
  },
  { // Entry 638
    HUGE_VAL,
    0.0, -0x1.0p1
  },
  { // Entry 639
    HUGE_VAL,
    0.0, -0x1.0000000000001p0
  },
  { // Entry 640
    HUGE_VAL,
    0.0, -0x1.fffffffffffffp-1
  },
  { // Entry 641
    HUGE_VAL,
    0.0, -0x1.0p-1022
  },
  { // Entry 642
    HUGE_VAL,
    0.0, -0x1.0p-1074
  },
  { // Entry 643
    HUGE_VAL,
    -0.0, -0x1.fffffffffffffp1023
  },
  { // Entry 644
    HUGE_VAL,
    -0.0, -0x1.8p2
  },
  { // Entry 645
    HUGE_VAL,
    -0.0, -0x1.0p1
  },
  { // Entry 646
    HUGE_VAL,
    -0.0, -0x1.0000000000001p0
  },
  { // Entry 647
    HUGE_VAL,
    -0.0, -0x1.fffffffffffffp-1
  },
  { // Entry 648
    HUGE_VAL,
    -0.0, -0x1.0p-1022
  },
  { // Entry 649
    HUGE_VAL,
    -0.0, -0x1.0p-1074
  },
  { // Entry 650
    HUGE_VAL,
    0.0, -HUGE_VAL
  },
  { // Entry 651
    HUGE_VAL,
    -0.0, -HUGE_VAL
  },
  { // Entry 652
    0.0,
    0.0, 0x1.8p1
  },
  { // Entry 653
    -0.0,
    -0.0, 0x1.8p1
  },
  { // Entry 654
    0.0,
    0.0, 0x1.0p0
  },
  { // Entry 655
    -0.0,
    -0.0, 0x1.0p0
  },
  { // Entry 656
    0.0,
    0.0, HUGE_VAL
  },
  { // Entry 657
    0.0,
    0.0, 0x1.fffffffffffffp1023
  },
  { // Entry 658
    0.0,
    0.0, 0x1.8p2
  },
  { // Entry 659
    0.0,
    0.0, 0x1.0p1
  },
  { // Entry 660
    0.0,
    0.0, 0x1.0000000000001p0
  },
  { // Entry 661
    0.0,
    0.0, 0x1.fffffffffffffp-1
  },
  { // Entry 662
    0.0,
    0.0, 0x1.0p-1022
  },
  { // Entry 663
    0.0,
    0.0, 0x1.0p-1074
  },
  { // Entry 664
    0.0,
    -0.0, HUGE_VAL
  },
  { // Entry 665
    0.0,
    -0.0, 0x1.fffffffffffffp1023
  },
  { // Entry 666
    0.0,
    -0.0, 0x1.8p2
  },
  { // Entry 667
    0.0,
    -0.0, 0x1.0p1
  },
  { // Entry 668
    0.0,
    -0.0, 0x1.0000000000001p0
  },
  { // Entry 669
    0.0,
    -0.0, 0x1.fffffffffffffp-1
  },
  { // Entry 670
    0.0,
    -0.0, 0x1.0p-1022
  },
  { // Entry 671
    0.0,
    -0.0, 0x1.0p-1074
  },
  { // Entry 672
    0x1.p0,
    -0x1.0p0, HUGE_VAL
  },
  { // Entry 673
    0x1.p0,
    -0x1.0p0, -HUGE_VAL
  },
  { // Entry 674
    0x1.p0,
    0x1.0p0, HUGE_VAL
  },
  { // Entry 675
    0x1.p0,
    0x1.0p0, -HUGE_VAL
  },
  { // Entry 676
    0x1.p0,
    0x1.0p0, 0x1.fffffffffffffp1023
  },
  { // Entry 677
    0x1.p0,
    0x1.0p0, -0x1.fffffffffffffp1023
  },
  { // Entry 678
    0x1.p0,
    -0x1.0p0, 0x1.fffffffffffffp1023
  },
  { // Entry 679
    0x1.p0,
    -0x1.0p0, -0x1.fffffffffffffp1023
  },
  { // Entry 680
    0x1.p0,
    0x1.0p0, 0x1.0p-1
  },
  { // Entry 681
    0x1.p0,
    0x1.0p0, -0x1.0p-1
  },
  { // Entry 682
    0x1.p0,
    0x1.0p0, 0x1.0p-1022
  },
  { // Entry 683
    0x1.p0,
    0x1.0p0, -0x1.0p-1022
  },
  { // Entry 684
    0x1.p0,
    0x1.0p0, 0x1.ffffffffffffep-1023
  },
  { // Entry 685
    0x1.p0,
    0x1.
"""


```
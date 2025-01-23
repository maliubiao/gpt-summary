Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the `tanh_intel_data.handroid` file located in the `bionic/tests/math_data` directory of Android's Bionic library.

This code snippet contains a large array of structures. Each structure seems to have two double-precision floating-point numbers. Given the filename `tanh_intel_data.handroid`, it's highly likely this data is used for testing the `tanh` function in the Bionic math library.

Therefore, the primary function of this code is to provide test vectors for the `tanh` function. Each entry likely represents an input value and its corresponding expected output value.

Let's summarize this understanding.
这是 `bionic/tests/math_data/tanh_intel_data.handroid` 文件的一部分内容。从文件名和路径来看，这个文件很可能包含了用于测试 `tanh` 函数（双曲正切函数）的数据。`bionic` 是 Android 的 C 库，因此这些数据被用于测试 Android 系统中 `tanh` 函数的实现是否正确。

**功能归纳：**

这个代码片段的主要功能是**提供了一系列预定义的输入和预期输出值，用于测试 `tanh` 函数的正确性**。具体来说，它定义了一个包含多个条目的数组，每个条目都是一个结构体，结构体中包含两个 `double` 类型的浮点数。第一个浮点数是 `tanh` 函数的输入值，第二个浮点数是对应输入的预期输出值。

可以推断，Android 的开发者使用这些数据来验证 `bionic` 库中 `tanh` 函数的实现是否符合预期，确保其在各种输入情况下的精度和正确性。 这些数据覆盖了不同的输入范围，包括正数、负数、零、非常大和非常小的数，以及一些特殊的值。

在后续的部分中，可能会看到如何使用这些数据进行单元测试，例如遍历这个数组，将第一个值作为 `tanh` 函数的输入，然后比较函数的实际输出和数组中的第二个预期输出值。

因此，总的来说，这段代码的功能是**提供 `tanh` 函数的测试用例数据**。

### 提示词
```
这是目录为bionic/tests/math_data/tanh_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
,
    0x1.286bca1af286bp100
  },
  { // Entry 354
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.286bca1af286bp100
  },
  { // Entry 355
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.35e50d79435e4p100
  },
  { // Entry 356
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.35e50d79435e4p100
  },
  { // Entry 357
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.435e50d79435dp100
  },
  { // Entry 358
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.435e50d79435dp100
  },
  { // Entry 359
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.50d79435e50d6p100
  },
  { // Entry 360
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.50d79435e50d6p100
  },
  { // Entry 361
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.5e50d79435e4fp100
  },
  { // Entry 362
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.5e50d79435e4fp100
  },
  { // Entry 363
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.6bca1af286bc8p100
  },
  { // Entry 364
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.6bca1af286bc8p100
  },
  { // Entry 365
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.79435e50d7941p100
  },
  { // Entry 366
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.79435e50d7941p100
  },
  { // Entry 367
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.86bca1af286bap100
  },
  { // Entry 368
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.86bca1af286bap100
  },
  { // Entry 369
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.9435e50d79433p100
  },
  { // Entry 370
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.9435e50d79433p100
  },
  { // Entry 371
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.a1af286bca1acp100
  },
  { // Entry 372
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.a1af286bca1acp100
  },
  { // Entry 373
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.af286bca1af25p100
  },
  { // Entry 374
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.af286bca1af25p100
  },
  { // Entry 375
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.bca1af286bc9ep100
  },
  { // Entry 376
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.bca1af286bc9ep100
  },
  { // Entry 377
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ca1af286bca17p100
  },
  { // Entry 378
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ca1af286bca17p100
  },
  { // Entry 379
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.d79435e50d790p100
  },
  { // Entry 380
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.d79435e50d790p100
  },
  { // Entry 381
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.e50d79435e509p100
  },
  { // Entry 382
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.e50d79435e509p100
  },
  { // Entry 383
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.f286bca1af282p100
  },
  { // Entry 384
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.f286bca1af282p100
  },
  { // Entry 385
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffbp100
  },
  { // Entry 386
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffbp100
  },
  { // Entry 387
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p200
  },
  { // Entry 388
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p200
  },
  { // Entry 389
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0d79435e50d79p200
  },
  { // Entry 390
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0d79435e50d79p200
  },
  { // Entry 391
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.1af286bca1af2p200
  },
  { // Entry 392
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.1af286bca1af2p200
  },
  { // Entry 393
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.286bca1af286bp200
  },
  { // Entry 394
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.286bca1af286bp200
  },
  { // Entry 395
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.35e50d79435e4p200
  },
  { // Entry 396
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.35e50d79435e4p200
  },
  { // Entry 397
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.435e50d79435dp200
  },
  { // Entry 398
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.435e50d79435dp200
  },
  { // Entry 399
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.50d79435e50d6p200
  },
  { // Entry 400
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.50d79435e50d6p200
  },
  { // Entry 401
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.5e50d79435e4fp200
  },
  { // Entry 402
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.5e50d79435e4fp200
  },
  { // Entry 403
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.6bca1af286bc8p200
  },
  { // Entry 404
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.6bca1af286bc8p200
  },
  { // Entry 405
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.79435e50d7941p200
  },
  { // Entry 406
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.79435e50d7941p200
  },
  { // Entry 407
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.86bca1af286bap200
  },
  { // Entry 408
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.86bca1af286bap200
  },
  { // Entry 409
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.9435e50d79433p200
  },
  { // Entry 410
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.9435e50d79433p200
  },
  { // Entry 411
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.a1af286bca1acp200
  },
  { // Entry 412
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.a1af286bca1acp200
  },
  { // Entry 413
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.af286bca1af25p200
  },
  { // Entry 414
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.af286bca1af25p200
  },
  { // Entry 415
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.bca1af286bc9ep200
  },
  { // Entry 416
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.bca1af286bc9ep200
  },
  { // Entry 417
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ca1af286bca17p200
  },
  { // Entry 418
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ca1af286bca17p200
  },
  { // Entry 419
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.d79435e50d790p200
  },
  { // Entry 420
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.d79435e50d790p200
  },
  { // Entry 421
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.e50d79435e509p200
  },
  { // Entry 422
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.e50d79435e509p200
  },
  { // Entry 423
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.f286bca1af282p200
  },
  { // Entry 424
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.f286bca1af282p200
  },
  { // Entry 425
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffbp200
  },
  { // Entry 426
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffbp200
  },
  { // Entry 427
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p1000
  },
  { // Entry 428
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p1000
  },
  { // Entry 429
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0d79435e50d79p1000
  },
  { // Entry 430
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0d79435e50d79p1000
  },
  { // Entry 431
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.1af286bca1af2p1000
  },
  { // Entry 432
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.1af286bca1af2p1000
  },
  { // Entry 433
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.286bca1af286bp1000
  },
  { // Entry 434
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.286bca1af286bp1000
  },
  { // Entry 435
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.35e50d79435e4p1000
  },
  { // Entry 436
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.35e50d79435e4p1000
  },
  { // Entry 437
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.435e50d79435dp1000
  },
  { // Entry 438
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.435e50d79435dp1000
  },
  { // Entry 439
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.50d79435e50d6p1000
  },
  { // Entry 440
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.50d79435e50d6p1000
  },
  { // Entry 441
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.5e50d79435e4fp1000
  },
  { // Entry 442
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.5e50d79435e4fp1000
  },
  { // Entry 443
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.6bca1af286bc8p1000
  },
  { // Entry 444
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.6bca1af286bc8p1000
  },
  { // Entry 445
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.79435e50d7941p1000
  },
  { // Entry 446
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.79435e50d7941p1000
  },
  { // Entry 447
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.86bca1af286bap1000
  },
  { // Entry 448
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.86bca1af286bap1000
  },
  { // Entry 449
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.9435e50d79433p1000
  },
  { // Entry 450
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.9435e50d79433p1000
  },
  { // Entry 451
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.a1af286bca1acp1000
  },
  { // Entry 452
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.a1af286bca1acp1000
  },
  { // Entry 453
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.af286bca1af25p1000
  },
  { // Entry 454
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.af286bca1af25p1000
  },
  { // Entry 455
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.bca1af286bc9ep1000
  },
  { // Entry 456
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.bca1af286bc9ep1000
  },
  { // Entry 457
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ca1af286bca17p1000
  },
  { // Entry 458
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ca1af286bca17p1000
  },
  { // Entry 459
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.d79435e50d790p1000
  },
  { // Entry 460
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.d79435e50d790p1000
  },
  { // Entry 461
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.e50d79435e509p1000
  },
  { // Entry 462
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.e50d79435e509p1000
  },
  { // Entry 463
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.f286bca1af282p1000
  },
  { // Entry 464
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.f286bca1af282p1000
  },
  { // Entry 465
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffbp1000
  },
  { // Entry 466
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffbp1000
  },
  { // Entry 467
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 468
    0.0,
    0x1.0p-1074
  },
  { // Entry 469
    -0.0,
    -0.0
  },
  { // Entry 470
    0.0,
    0x1.0p-1074
  },
  { // Entry 471
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 472
    0x1.d9353d7568af29bbdeb6502490ea91f5p-2,
    0x1.fffffffffffffp-2
  },
  { // Entry 473
    -0x1.d9353d7568af29bbdeb6502490ea91f5p-2,
    -0x1.fffffffffffffp-2
  },
  { // Entry 474
    0x1.d9353d7568af365128ee21c65b08d3a7p-2,
    0x1.0p-1
  },
  { // Entry 475
    -0x1.d9353d7568af365128ee21c65b08d3a7p-2,
    -0x1.0p-1
  },
  { // Entry 476
    0x1.d9353d7568af4f7bbd5dc509eeb9c854p-2,
    0x1.0000000000001p-1
  },
  { // Entry 477
    -0x1.d9353d7568af4f7bbd5dc509eeb9c854p-2,
    -0x1.0000000000001p-1
  },
  { // Entry 478
    0x1.ffffffffffffd9ce09d9ac0077339fccp-2,
    0x1.193ea7aad0309p-1
  },
  { // Entry 479
    -0x1.ffffffffffffd9ce09d9ac0077339fccp-2,
    -0x1.193ea7aad0309p-1
  },
  { // Entry 480
    0x1.fffffffffffff1ce09d9ac0078052f7dp-2,
    0x1.193ea7aad030ap-1
  },
  { // Entry 481
    -0x1.fffffffffffff1ce09d9ac0078052f7dp-2,
    -0x1.193ea7aad030ap-1
  },
  { // Entry 482
    0x1.00000000000004e704ecd6003c0b5f97p-1,
    0x1.193ea7aad030bp-1
  },
  { // Entry 483
    -0x1.00000000000004e704ecd6003c0b5f97p-1,
    -0x1.193ea7aad030bp-1
  },
  { // Entry 484
    0x1.fffffffffffffffa422f887a2db9896bp-1,
    0x1.5ffffffffffffp4
  },
  { // Entry 485
    -0x1.fffffffffffffffa422f887a2db9896bp-1,
    -0x1.5ffffffffffffp4
  },
  { // Entry 486
    0x1.fffffffffffffffa422f887a2dc5050cp-1,
    0x1.6p4
  },
  { // Entry 487
    -0x1.fffffffffffffffa422f887a2dc5050cp-1,
    -0x1.6p4
  },
  { // Entry 488
    0x1.fffffffffffffffa422f887a2dd080adp-1,
    0x1.6000000000001p4
  },
  { // Entry 489
    -0x1.fffffffffffffffa422f887a2dd080adp-1,
    -0x1.6000000000001p4
  },
  { // Entry 490
    -0x1.3333333333333b4d120fbdf5bd629059p-1,
    -0x1.62e42fefa39f0p-1
  },
  { // Entry 491
    0x1.3333333333333b4d120fbdf5bd629059p-1,
    0x1.62e42fefa39f0p-1
  },
  { // Entry 492
    -0x1.333333333333310fa16be6eb800e8ac1p-1,
    -0x1.62e42fefa39efp-1
  },
  { // Entry 493
    0x1.333333333333310fa16be6eb800e8ac1p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 494
    -0x1.33333333333326d230c80fe142583755p-1,
    -0x1.62e42fefa39eep-1
  },
  { // Entry 495
    0x1.33333333333326d230c80fe142583755p-1,
    0x1.62e42fefa39eep-1
  },
  { // Entry 496
    -0x1.5555555555556095b587a4471560a40bp-2,
    -0x1.62e42fefa39f0p-2
  },
  { // Entry 497
    0x1.5555555555556095b587a4471560a40bp-2,
    0x1.62e42fefa39f0p-2
  },
  { // Entry 498
    -0x1.555555555555525cd1f96b638732caf9p-2,
    -0x1.62e42fefa39efp-2
  },
  { // Entry 499
    0x1.555555555555525cd1f96b638732caf9p-2,
    0x1.62e42fefa39efp-2
  },
  { // Entry 500
    -0x1.5555555555554423ee6b327ff8df04ddp-2,
    -0x1.62e42fefa39eep-2
  },
  { // Entry 501
    0x1.5555555555554423ee6b327ff8df04ddp-2,
    0x1.62e42fefa39eep-2
  },
  { // Entry 502
    -0x1.5f619980c4337bbdd8e8c2066bb51eb7p-3,
    -0x1.62e42fefa39f0p-3
  },
  { // Entry 503
    0x1.5f619980c4337bbdd8e8c2066bb51eb7p-3,
    0x1.62e42fefa39f0p-3
  },
  { // Entry 504
    -0x1.5f619980c4336c366c1acb38d4f1b2bdp-3,
    -0x1.62e42fefa39efp-3
  },
  { // Entry 505
    0x1.5f619980c4336c366c1acb38d4f1b2bdp-3,
    0x1.62e42fefa39efp-3
  },
  { // Entry 506
    -0x1.5f619980c4335caeff4cd46b3e239e77p-3,
    -0x1.62e42fefa39eep-3
  },
  { // Entry 507
    0x1.5f619980c4335caeff4cd46b3e239e77p-3,
    0x1.62e42fefa39eep-3
  },
  { // Entry 508
    -0x1.620185e5621414c6823c701f4e8d83f5p-4,
    -0x1.62e42fefa39f0p-4
  },
  { // Entry 509
    0x1.620185e5621414c6823c701f4e8d83f5p-4,
    0x1.62e42fefa39f0p-4
  },
  { // Entry 510
    -0x1.620185e5621404e51abfd52a9fb35582p-4,
    -0x1.62e42fefa39efp-4
  },
  { // Entry 511
    0x1.620185e5621404e51abfd52a9fb35582p-4,
    0x1.62e42fefa39efp-4
  },
  { // Entry 512
    -0x1.620185e56213f503b3433a35f0d66857p-4,
    -0x1.62e42fefa39eep-4
  },
  { // Entry 513
    0x1.620185e56213f503b3433a35f0d66857p-4,
    0x1.62e42fefa39eep-4
  },
  { // Entry 514
    -0x1.62ab64c8162a91fbc4d3da77194b3135p-5,
    -0x1.62e42fefa39f0p-5
  },
  { // Entry 515
    0x1.62ab64c8162a91fbc4d3da77194b3135p-5,
    0x1.62e42fefa39f0p-5
  },
  { // Entry 516
    -0x1.62ab64c8162a8203724db05bba6bf1f1p-5,
    -0x1.62e42fefa39efp-5
  },
  { // Entry 517
    0x1.62ab64c8162a8203724db05bba6bf1f1p-5,
    0x1.62e42fefa39efp-5
  },
  { // Entry 518
    -0x1.62ab64c8162a720b1fc786405b8c01adp-5,
    -0x1.62e42fefa39eep-5
  },
  { // Entry 519
    0x1.62ab64c8162a720b1fc786405b8c01adp-5,
    0x1.62e42fefa39eep-5
  },
  { // Entry 520
    -0x1.62d5fb19f39d32db543feb53c0c8af33p-6,
    -0x1.62e42fefa39f0p-6
  },
  { // Entry 521
    0x1.62d5fb19f39d32db543feb53c0c8af33p-6,
    0x1.62e42fefa39f0p-6
  },
  { // Entry 522
    -0x1.62d5fb19f39d22dd401468a35602a39dp-6,
    -0x1.62e42fefa39efp-6
  },
  { // Entry 523
    0x1.62d5fb19f39d22dd401468a35602a39dp-6,
    0x1.62e42fefa39efp-6
  },
  { // Entry 524
    -0x1.62d5fb19f39d12df2be8e5f2eb3c6bb2p-6,
    -0x1.62e42fefa39eep-6
  },
  { // Entry 525
    0x1.62d5fb19f39d12df2be8e5f2eb3c6bb2p-6,
    0x1.62e42fefa39eep-6
  },
  { // Entry 526
    0x1.62d5fb19f39d12df2be8e5f2eb3c6bb2p-6,
    0x1.62e42fefa39eep-6
  },
  { // Entry 527
    -0x1.62d5fb19f39d12df2be8e5f2eb3c6bb2p-6,
    -0x1.62e42fefa39eep-6
  },
  { // Entry 528
    0x1.62d5fb19f39d22dd401468a35602a39dp-6,
    0x1.62e42fefa39efp-6
  },
  { // Entry 529
    -0x1.62d5fb19f39d22dd401468a35602a39dp-6,
    -0x1.62e42fefa39efp-6
  },
  { // Entry 530
    0x1.62d5fb19f39d32db543feb53c0c8af33p-6,
    0x1.62e42fefa39f0p-6
  },
  { // Entry 531
    -0x1.62d5fb19f39d32db543feb53c0c8af33p-6,
    -0x1.62e42fefa39f0p-6
  },
  { // Entry 532
    0x1.62ab64c8162a720b1fc786405b8c01adp-5,
    0x1.62e42fefa39eep-5
  },
  { // Entry 533
    -0x1.62ab64c8162a720b1fc786405b8c01adp-5,
    -0x1.62e42fefa39eep-5
  },
  { // Entry 534
    0x1.62ab64c8162a8203724db05bba6bf1f1p-5,
    0x1.62e42fefa39efp-5
  },
  { // Entry 535
    -0x1.62ab64c8162a8203724db05bba6bf1f1p-5,
    -0x1.62e42fefa39efp-5
  },
  { // Entry 536
    0x1.62ab64c8162a91fbc4d3da77194b3135p-5,
    0x1.62e42fefa39f0p-5
  },
  { // Entry 537
    -0x1.62ab64c8162a91fbc4d3da77194b3135p-5,
    -0x1.62e42fefa39f0p-5
  },
  { // Entry 538
    0x1.620185e56213f503b3433a35f0d66857p-4,
    0x1.62e42fefa39eep-4
  },
  { // Entry 539
    -0x1.620185e56213f503b3433a35f0d66857p-4,
    -0x1.62e42fefa39eep-4
  },
  { // Entry 540
    0x1.620185e5621404e51abfd52a9fb35582p-4,
    0x1.62e42fefa39efp-4
  },
  { // Entry 541
    -0x1.620185e5621404e51abfd52a9fb35582p-4,
    -0x1.62e42fefa39efp-4
  },
  { // Entry 542
    0x1.620185e5621414c6823c701f4e8d83f5p-4,
    0x1.62e42fefa39f0p-4
  },
  { // Entry 543
    -0x1.620185e5621414c6823c701f4e8d83f5p-4,
    -0x1.62e42fefa39f0p-4
  },
  { // Entry 544
    0x1.5f619980c4335caeff4cd46b3e239e77p-3,
    0x1.62e42fefa39eep-3
  },
  { // Entry 545
    -0x1.5f619980c4335caeff4cd46b3e239e77p-3,
    -0x1.62e42fefa39eep-3
  },
  { // Entry 546
    0x1.5f619980c4336c366c1acb38d4f1b2bdp-3,
    0x1.62e42fefa39efp-3
  },
  { // Entry 547
    -0x1.5f619980c4336c366c1acb38d4f1b2bdp-3,
    -0x1.62e42fefa39efp-3
  },
  { // Entry 548
    0x1.5f619980c4337bbdd8e8c2066bb51eb7p-3,
    0x1.62e42fefa39f0p-3
  },
  { // Entry 549
    -0x1.5f619980c4337bbdd8e8c2066bb51eb7p-3,
    -0x1.62e42fefa39f0p-3
  },
  { // Entry 550
    0x1.5555555555554423ee6b327ff8df04ddp-2,
    0x1.62e42fefa39eep-2
  },
  { // Entry 551
    -0x1.5555555555554423ee6b327ff8df04ddp-2,
    -0x1.62e42fefa39eep-2
  },
  { // Entry 552
    0x1.555555555555525cd1f96b638732caf9p-2,
    0x1.62e42fefa39efp-2
  },
  { // Entry 553
    -0x1.555555555555525cd1f96b638732caf9p-2,
    -0x1.62e42fefa39efp-2
  },
  { // Entry 554
    0x1.5555555555556095b587a4471560a40bp-2,
    0x1.62e42fefa39f0p-2
  },
  { // Entry 555
    -0x1.5555555555556095b587a4471560a40bp-2,
    -0x1.62e42fefa39f0p-2
  },
  { // Entry 556
    0x1.33333333333326d230c80fe142583755p-1,
    0x1.62e42fefa39eep-1
  },
  { // Entry 557
    -0x1.33333333333326d230c80fe142583755p-1,
    -0x1.62e42fefa39eep-1
  },
  { // Entry 558
    0x1.333333333333310fa16be6eb800e8ac1p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 559
    -0x1.333333333333310fa16be6eb800e8ac1p-1,
    -0x1.62e42fefa39efp-1
  },
  { // Entry 560
    0x1.3333333333333b4d120fbdf5bd629059p-1,
    0x1.62e42fefa39f0p-1
  },
  { // Entry 561
    -0x1.3333333333333b4d120fbdf5bd629059p-1,
    -0x1.62e42fefa39f0p-1
  },
  { // Entry 562
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.62e42fefa39eep9
  },
  { // Entry 563
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.62e42fefa39eep9
  },
  { // Entry 564
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.62e42fefa39efp9
  },
  { // Entry 565
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.62e42fefa39efp9
  },
  { // Entry 566
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.62e42fefa39f0p9
  },
  { // Entry 567
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.62e42fefa39f0p9
  },
  { // Entry 568
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.72e42fefa39f0p9
  },
  { // Entry 569
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.72e42fefa39f0p9
  },
  { // Entry 570
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.72e42fefa39efp9
  },
  { // Entry 571
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.72e42fefa39efp9
  },
  { // Entry 572
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.72e42fefa39eep9
  },
  { // Entry 573
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.72e42fefa39eep9
  },
  { // Entry 574
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.633ce8fb9f87cp9
  },
  { // Entry 575
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.633ce8fb9f87cp9
  },
  { // Entry 576
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.633ce8fb9f87dp9
  },
  { // Entry 577
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.633ce8fb9f87dp9
  },
  { // Entry 578
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.633ce8fb9f87ep9
  },
  { // Entry 579
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.633ce8fb9f87ep9
  },
  { // Entry 580
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.62e42fefa39f0p9
  },
  { // Entry 581
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.62e42fefa39f0p9
  },
  { // Entry 582
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.62e42fefa39efp9
  },
  { // Entry 583
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.62e42fefa39efp9
  },
  { // Entry 584
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.62e42fefa39eep9
  },
  { // Entry 585
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.62e42fefa39eep9
  },
  { // Entry 586
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffffffffffp62
  },
  { // Entry 587
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffffffffffp62
  },
  { // Entry 588
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p63
  },
  { // Entry 589
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p63
  },
  { // Entry 590
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p63
  },
  { // Entry 591
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p63
  },
  { // Entry 592
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffffffffffp26
  },
  { // Entry 593
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffffffffffp26
  },
  { // Entry 594
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p27
  },
  { // Entry 595
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p27
  },
  { // Entry 596
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p27
  },
  { // Entry 597
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p27
  },
  { // Entry 598
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffffffffffp23
  },
  { // Entry 599
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffffffffffp23
  },
  { // Entry 600
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p24
  },
  { // Entry 601
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p24
  },
  { // Entry 602
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0000000000001p24
  },
  { // Entry 603
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p24
  },
  { // Entry 604
    0x1.ffffffffffffffffffffffcd2c5719bcp-1,
    0x1.fffffffffffffp4
  },
  { // Entry 605
    -0x1.ffffffffffffffffffffffcd2c5719bcp-1,
    -0x1.fffffffffffffp4
  },
  { // Entry 606
    0x1.ffffffffffffffffffffffcd2c5719bcp-1,
    0x1.0p5
  },
  { // Entry 607
    -0x1.ffffffffffffffffffffffcd2c5719bcp-1,
    -0x1.0p5
  },
  { // Entry 608
    0x1.ffffffffffffffffffffffcd2c5719bcp-1,
    0x1.0000000000001p5
  },
  { // Entry 609
    -0x1.ffffffffffffffffffffffcd2c5719bcp-1,
    -0x1.0000000000001p5
  },
  { // Entry 610
    0x1.fffffffffff1bdcd844f4df082619d92p-1,
    0x1.fffffffffffffp3
  },
  { // Entry 611
    -0x1.fffffffffff1bdcd844f4df082619d92p-1,
    -0x1.fffffffffffffp3
  },
  { // Entry 612
    0x1.fffffffffff1bdcd844f4dfec4941943p-1,
    0x1.0p4
  },
  { // Entry 613
    -0x1.fffffffffff1bdcd844f4dfec4941943p-1,
    -0x1.0p4
  },
  { // Entry 614
    0x1.fffffffffff1bdcd844f4e1b48f910a4p-1,
    0x1.0000000000001p4
  },
  { // Entry 615
    -0x1.fffffffffff1bdcd844f4e1b48f910a4p-1,
    -0x1.0000000000001p4
  },
  { // Entry 616
    0x1.fffff872a91f8690ea47c1d1bd107d6ep-1,
    0x1.fffffffffffffp2
  },
  { // Entry 617
    -0x1.fffff872a91f8690ea47c1d1bd107d6ep-1,
    -0x1.fffffffffffffp2
  },
  { // Entry 618
    0x1.fffff872a91f8690ee0e6d3ad8aee46bp-1,
    0x1.0p3
  },
  { // Entry 619
    -0x1.fffff872a91f8690ee0e6d3ad8aee46bp-1,
    -0x1.0p3
  },
  { // Entry 620
    0x1.fffff872a91f8690f59bc40d0febacbdp-1,
    0x1.0000000000001p3
  },
  { // Entry 621
    -0x1.fffff872a91f8690f59bc40d0febacbdp-1,
    -0x1.0000000000001p3
  },
  { // Entry 622
    0x1.ffa81708a0b421525ec9970925cd4155p-1,
    0x1.fffffffffffffp1
  },
  { // Entry 623
    -0x1.ffa81708a0b421525ec9970925cd4155p-1,
    -0x1.fffffffffffffp1
  },
  { // Entry 624
    0x1.ffa81708a0b4216857246c19dc60acb8p-1,
    0x1.0p2
  },
  { // Entry 625
    -0x1.ffa81708a0b4216857246c19dc60acb8p-1,
    -0x1.0p2
  },
  { // Entry 626
    0x1.ffa81708a0b4219447da163b49770c0ep-1,
    0x1.0000000000001p2
  },
  { // Entry 627
    -0x1.ffa81708a0b4219447da163b49770c0ep-1,
    -0x1.0000000000001p2
  },
  { // Entry 628
    0x1.ed9505e1bc3d3af0feae367ddede350ep-1,
    0x1.fffffffffffffp0
  },
  { // Entry 629
    -0x1.ed9505e1bc3d3af0feae367ddede350ep-1,
    -0x1.fffffffffffffp0
  },
  { // Entry 630
    0x1.ed9505e1bc3d3d33c432fc3e8255c8b5p-1,
    0x1.0p1
  },
  { // Entry 631
    -0x1.ed9505e1bc3d3d33c432fc3e8255c8b5p-1,
    -0x1.0p1
  },
  { // Entry 632
    0x1.ed9505e1bc3d41b94f3c87bfc873b4a6p-1,
    0x1.0000000000001p1
  },
  { // Entry 633
    -0x1.ed9505e1bc3d41b94f3c87bfc873b4a6p-1,
    -0x1.0000000000001p1
  },
  { // Entry 634
    0x1.85efab514f393ea02c27fc50b2cbbe65p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 635
    -0x1.85efab514f393ea02c27fc50b2cbbe65p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 636
    0x1.85efab514f394558632be293c4274fe6p-1,
    0x1.0p0
  },
  { // Entry 637
    -0x1.85efab514f394558632be293c4274fe6p-1,
    -0x1.0p0
  },
  { // Entry 638
    0x1.85efab514f3952c8d133af19e5e8cdd6p-1,
    0x1.0000000000001p0
  },
  { // Entry 639
    -0x1.85efab514f3952c8d133af19e5e8cdd6p-1,
    -0x1.0000000000001p0
  },
  { // Entry 640
    0x1.d9353d7568af29bbdeb6502490ea91f5p-2,
    0x1.fffffffffffffp-2
  },
  { // Entry 641
    -0x1.d9353d7568af29bbdeb6502490ea91f5p-2,
    -0x1.fffffffffffffp-2
  },
  { // Entry 642
    0x1.d9353d7568af365128ee21c65b08d3a7p-2,
    0x1.0p-1
  },
  { // Entry 643
    -0x1.d9353d7568af365128ee21c65b08d3a7p-2,
    -0x1.0p-1
  },
  { // Entry 644
    0x1.d9353d7568af4f7bbd5dc509eeb9c854p-2,
    0x1.0000000000001p-1
  },
  { // Entry 645
    -0x1.d9353d7568af4f7bbd5dc509eeb9c854p-2,
    -0x1.0000000000001p-1
  },
  { // Entry 646
    0x1.f597ea69a1c850090bd4877911ae9956p-3,
    0x1.fffffffffffffp-3
  },
  { // Entry 647
    -0x1.f597ea69a1c850090bd4877911ae9956p-3,
    -0x1.fffffffffffffp-3
  },
  { // Entry 648
    0x1.f597ea69a1c85f1358d71d84729c80c8p-3,
    0x1.0p-2
  },
  { // Entry 649
    -0x1.f597ea69a1c85f1358d71d84729c80c8p-3,
    -0x1.0p-2
  },
  { // Entry 650
    0x1.f597ea69a1c87d27f2dc499b344c1b8cp-3,
    0x1.0000000000001p-2
  },
  { // Entry 651
    -0x1.f597ea69a1c87d27f2dc499b344c1b8cp-3,
    -0x1.0000000000001p-2
  },
  { // Entry 652
    0x1.fd5992bc4b834000063fd671ecd5ebeep-4,
    0x1.fffffffffffffp-4
  },
  { // Entry 653
    -0x1.fd5992bc4b834000063fd671ecd5ebeep-4,
    -0x1.fffffffffffffp-4
  },
  { // Entry 654
    0x1.fd5992bc4b834fc0af6ac8eff7d81040p-4,
    0x1.0p-3
  },
  { // Entry 655
    -0x1.fd5992bc4b834fc0af6ac8eff7d81040p-4,
    -0x1.0p-3
  },
  { // Entry 656
    0x1.fd5992bc4b836f4201c0adec0dd0980dp-4,
    0x1.0000000000001p-3
  },
  { // Entry 657
    -0x1.fd5992bc4b836f4201c0adec0dd0980dp-4,
    -0x1.0000000000001p-3
  },
  { // Entry 658
    0x1.ff55997e030d60692ab487c7d22013f6p-5,
    0x1.fffffffffffffp-5
  },
  { // Entry 659
    -0x1.ff55997e030d60692ab487c7d22013f6p-5,
    -0x1.fffffffffffffp-5
  },
  { // Entry 660
    0x1.ff55997e030d705935592a366a8a66d4p-5,
    0x1.0p-4
  },
  { // Entry 661
    -0x1.ff55997e030d705935592a366a8a66d4p-5,
    -0x1.0p-4
  },
  { // Entry 662
    0x1.ff55997e030d90394aa26f139b5c108ep-5,
    0x1.0000000000001p-4
  },
  { // Entry 663
    -0x1.ff55997e030d90394aa26f139b5c108ep-5,
    -0x1.0000000000001p-4
  },
  { // Entry 664
    0x1.ffd559992b1dd287055184b7d46402dap-6,
    0x1.fffffffffffffp-6
  },
  { // Entry 665
    -0x1.ffd559992b1dd287055184b7d46402dap-6,
    -0x1.fffffffffffffp-6
  },
  { // Entry 666
    0x1.ffd559992b1de28305fc17382205392ep-6,
    0x1.0p-5
  },
  { // Entry 667
    -0x1.ffd559992b1de28305fc17382205392ep-6,
    -0x1.0p-5
  },
  { // Entry 668
    0x1.ffd559992b1e027b07513c38bd46e616p-6,
    0x1.0000000000001p-5
  },
  { // Entry 669
    -0x1.ffd559992b1e027b07513c38bd46e616p-6,
    -0x1.0000000000001p-5
  },
  { // Entry 670
    0x1.fff5559997df792b111dad0e4c36a1efp-7,
    0x1.fffffffffffffp-7
  },
  { // Entry 671
    -0x1.fff5559997df792b111dad0e4c36a1efp-7,
    -0x1.fffffffffffffp-7
  },
  { // Entry 672
    0x1.fff5559997df892a1128575843fc0d52p-7,
    0x1.0p-6
  },
  { // Entry 673
    -0x1.fff5559997df892a1128575843fc0d52p-7,
    -0x1.0p-6
  },
  { // Entry 674
    0x1.fff5559997dfa928113dabec3386b41bp-7,
    0x1.0000000000001p-6
  },
  { // Entry 675
    -0x1.fff5559997dfa928113dabec3386b41bp-7,
    -0x1.0000000000001p-6
  },
  { // Entry 676
    0x1.fffffff555554599999a97df7ded4005p-15,
    0x1.fffffffffffffp-15
  },
  { // Entry 677
    -0x1.fffffff555554599999a97df7ded4005p-15,
    -0x1.fffffffffffffp-15
  },
  { // Entry 678
    0x1.fffffff555555599999997df7df7eab0p-15,
    0x1.0p-14
  },
  { // Entry 679
    -0x1.fffffff555555599999997df7df7eab0p-15,
    -0x1.0p-14
  },
  { // Entry 680
    0x1.fffffff555557599999797df7e0d4005p-15,
    0x1.0000000000001p-14
  },
  { // Entry 681
    -0x1.fffffff555557599999797df7e0d4005p-15,
    -0x1.0000000000001p-14
  },
  { // Entry 682
    0x1.ffffffffffffeff55555555555565599p-31,
    0x1.fffffffffffffp-31
  },
  { // Entry 683
    -0x1.ffffffffffffeff55555555555565599p-31,
    -0x1.fffffffffffffp-31
  },
  { // Entry 684
    0x1.fffffffffffffff55555555555555599p-31,
    0x1.0p-30
  },
  { // Entry 685
    -0x1.fffffffffffffff55555555555555599p-31,
    -0x1.0p-30
  },
  { // Entry 686
    0x1.0000000000000ffaaaaaaaaaaaa9aaccp-30,
    0x1.0000000000001p-30
  },
  { // Entry 687
    -0x1.0000000000000ffaaaaaaaaaaaa9aaccp-30,
    -0x1.0000000000001p-30
  },
  { // Entry 688
    0x1.ffffffffffffeffffffffffffffd5555p-56,
    0x1.fffffffffffffp-56
  },
  { // Entry 689
    -0x1.ffffffffffffeffffffffffffffd5555p-56,
    -0x1.fffffffffffffp-56
  },
  { // Entry 690
    0x1.fffffffffffffffffffffffffffd5555p-56,
    0x1.0p-55
  },
  { // Entry 691
    -0x1.fffffffffffffffffffffffffffd5555p-56,
    -0x1.0p-55
  },
  { // Entry 692
    0x1.0000000000000ffffffffffffffeaaaap-55,
    0x1.0000000000001p-55
  },
  { // Entry 693
    -0x1.0000000000000ffffffffffffffeaaaap-55,
    -0x1.0000000000001p-55
  },
  { // Entry 694
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 695
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 696
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 697
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 698
    0x1.p0,
    HUGE_VAL
  },
  { // Entry 699
    -0x1.p0,
    -HUGE_VAL
  },
  { // Entry 700
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 701
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 702
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.ffffffffffffep1023
  },
  { // Entry 703
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep1023
  },
  { // Entry 704
    0x1.fe175fa29280faada6e2c93ea708789ep-1,
    0x1.921fb54442d18p1
  },
  { // Entry 705
    -0x1.fe175fa29280faada6e2c93ea708789ep-1,
    -0x1.921fb54442d18p1
  },
  { // Entry 706
    0x1.d594fdae482b98a703d473d9a8cd44cdp-1,
    0x1.921fb54442d18p0
  },
  { // Entry 707
    -0x1.d594fdae482b98a703d473d9a8cd44cdp-1,
    -0x1.921fb54442d18p0
  },
  { // Entry 708
    0x1.85efab514f3952c8d133af19e5e8cdd6p-1,
    0x1.0000000000001p0
  },
  { // Entry 709
    -0x1.85efab514f3952c8d133af19e5e8cdd6p-1,
    -0x1.0000000000001p0
  },
  { // Entry 710
    0x1.85efab514f394558632be293c4274fe6p-1,
    0x1.0p0
  },
  { // Entry 711
    -0x1.85efab514f394558632be293c4274fe6p-1,
    -0x1.0p0
  },
  { // Entry 712
    0x1.85efab514f393ea02c27fc50b2cbbe65p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 713
    -0x1.85efab514f393ea02c27fc50b2cbbe65p-1,
    -0x1.fffffffffffffp-1
```
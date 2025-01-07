Response:
The user is asking for a summary of the functionality of the provided C code snippet. This is part 2 of a 3-part question.

The code defines a series of test data entries. Each entry appears to be a struct containing three fields: an input floating-point number, an expected output floating-point number, and an integer.

Based on the filename "scalbn_intel_data.handroid", it's highly likely that this data is used to test the `scalbn` function in the Android bionic library's math component. The `scalbn` function multiplies a floating-point number by 2 raised to the power of an integer.

Therefore, the functionality of this data file is to provide a comprehensive set of test cases for the `scalbn` function, specifically tailored for Intel architectures within the Android environment.
这段代码是 `bionic/tests/math_data/scalbn_intel_data.handroid` 文件的一部分，它定义了一个用于测试 `scalbn` 函数的数据集。

**功能归纳:**

这个代码片段定义了一系列结构体，每个结构体包含三个字段：

1. **一个用十六进制浮点数表示的输入值 (double)。** 例如：`0x1.1745d1745d1770p-5`。
2. **一个用十六进制浮点数表示的预期输出值 (double)。** 例如：`0x1.1745d1745d177p-1`。
3. **一个整数，表示 `scalbn` 函数的第二个参数 `n`。** 例如：`(int)-4`。

**总结来说，这段代码的主要功能是提供了一组预定义的输入、预期输出和指数值，用于测试 `scalbn` 函数在各种情况下的正确性。**  这些数据特别针对 Intel 架构进行了优化或调整，并在 Android 环境中使用。

**结合第一部分和第三部分，这个文件完整的功能是为 `scalbn` 函数提供一套全面的测试用例，涵盖了不同的输入值和指数，以确保该函数在 Android 系统的 bionic 库中能够正确地运行。**

Prompt: 
```
这是目录为bionic/tests/math_data/scalbn_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 381
    0x1.1745d1745d1770p-5,
    0x1.1745d1745d177p-1,
    (int)-4
  },
  { // Entry 382
    0x1.1745d1745d1770p-4,
    0x1.1745d1745d177p-1,
    (int)-3
  },
  { // Entry 383
    0x1.1745d1745d1770p-3,
    0x1.1745d1745d177p-1,
    (int)-2
  },
  { // Entry 384
    0x1.1745d1745d1770p-2,
    0x1.1745d1745d177p-1,
    (int)-1
  },
  { // Entry 385
    0x1.1745d1745d1770p-1,
    0x1.1745d1745d177p-1,
    (int)0
  },
  { // Entry 386
    0x1.1745d1745d1770p0,
    0x1.1745d1745d177p-1,
    (int)1
  },
  { // Entry 387
    0x1.1745d1745d1770p1,
    0x1.1745d1745d177p-1,
    (int)2
  },
  { // Entry 388
    0x1.1745d1745d1770p2,
    0x1.1745d1745d177p-1,
    (int)3
  },
  { // Entry 389
    0x1.1745d1745d1770p3,
    0x1.1745d1745d177p-1,
    (int)4
  },
  { // Entry 390
    0x1.1745d1745d1770p4,
    0x1.1745d1745d177p-1,
    (int)5
  },
  { // Entry 391
    0x1.1745d1745d1770p5,
    0x1.1745d1745d177p-1,
    (int)6
  },
  { // Entry 392
    0x1.1745d1745d1770p6,
    0x1.1745d1745d177p-1,
    (int)7
  },
  { // Entry 393
    0x1.1745d1745d1770p7,
    0x1.1745d1745d177p-1,
    (int)8
  },
  { // Entry 394
    0x1.1745d1745d1770p8,
    0x1.1745d1745d177p-1,
    (int)9
  },
  { // Entry 395
    0x1.1745d1745d1770p9,
    0x1.1745d1745d177p-1,
    (int)10
  },
  { // Entry 396
    0x1.45d1745d1746p-11,
    0x1.45d1745d17460p-1,
    (int)-10
  },
  { // Entry 397
    0x1.45d1745d1746p-10,
    0x1.45d1745d17460p-1,
    (int)-9
  },
  { // Entry 398
    0x1.45d1745d1746p-9,
    0x1.45d1745d17460p-1,
    (int)-8
  },
  { // Entry 399
    0x1.45d1745d1746p-8,
    0x1.45d1745d17460p-1,
    (int)-7
  },
  { // Entry 400
    0x1.45d1745d1746p-7,
    0x1.45d1745d17460p-1,
    (int)-6
  },
  { // Entry 401
    0x1.45d1745d1746p-6,
    0x1.45d1745d17460p-1,
    (int)-5
  },
  { // Entry 402
    0x1.45d1745d1746p-5,
    0x1.45d1745d17460p-1,
    (int)-4
  },
  { // Entry 403
    0x1.45d1745d1746p-4,
    0x1.45d1745d17460p-1,
    (int)-3
  },
  { // Entry 404
    0x1.45d1745d1746p-3,
    0x1.45d1745d17460p-1,
    (int)-2
  },
  { // Entry 405
    0x1.45d1745d1746p-2,
    0x1.45d1745d17460p-1,
    (int)-1
  },
  { // Entry 406
    0x1.45d1745d1746p-1,
    0x1.45d1745d17460p-1,
    (int)0
  },
  { // Entry 407
    0x1.45d1745d1746p0,
    0x1.45d1745d17460p-1,
    (int)1
  },
  { // Entry 408
    0x1.45d1745d1746p1,
    0x1.45d1745d17460p-1,
    (int)2
  },
  { // Entry 409
    0x1.45d1745d1746p2,
    0x1.45d1745d17460p-1,
    (int)3
  },
  { // Entry 410
    0x1.45d1745d1746p3,
    0x1.45d1745d17460p-1,
    (int)4
  },
  { // Entry 411
    0x1.45d1745d1746p4,
    0x1.45d1745d17460p-1,
    (int)5
  },
  { // Entry 412
    0x1.45d1745d1746p5,
    0x1.45d1745d17460p-1,
    (int)6
  },
  { // Entry 413
    0x1.45d1745d1746p6,
    0x1.45d1745d17460p-1,
    (int)7
  },
  { // Entry 414
    0x1.45d1745d1746p7,
    0x1.45d1745d17460p-1,
    (int)8
  },
  { // Entry 415
    0x1.45d1745d1746p8,
    0x1.45d1745d17460p-1,
    (int)9
  },
  { // Entry 416
    0x1.45d1745d1746p9,
    0x1.45d1745d17460p-1,
    (int)10
  },
  { // Entry 417
    0x1.745d1745d17490p-11,
    0x1.745d1745d1749p-1,
    (int)-10
  },
  { // Entry 418
    0x1.745d1745d17490p-10,
    0x1.745d1745d1749p-1,
    (int)-9
  },
  { // Entry 419
    0x1.745d1745d17490p-9,
    0x1.745d1745d1749p-1,
    (int)-8
  },
  { // Entry 420
    0x1.745d1745d17490p-8,
    0x1.745d1745d1749p-1,
    (int)-7
  },
  { // Entry 421
    0x1.745d1745d17490p-7,
    0x1.745d1745d1749p-1,
    (int)-6
  },
  { // Entry 422
    0x1.745d1745d17490p-6,
    0x1.745d1745d1749p-1,
    (int)-5
  },
  { // Entry 423
    0x1.745d1745d17490p-5,
    0x1.745d1745d1749p-1,
    (int)-4
  },
  { // Entry 424
    0x1.745d1745d17490p-4,
    0x1.745d1745d1749p-1,
    (int)-3
  },
  { // Entry 425
    0x1.745d1745d17490p-3,
    0x1.745d1745d1749p-1,
    (int)-2
  },
  { // Entry 426
    0x1.745d1745d17490p-2,
    0x1.745d1745d1749p-1,
    (int)-1
  },
  { // Entry 427
    0x1.745d1745d17490p-1,
    0x1.745d1745d1749p-1,
    (int)0
  },
  { // Entry 428
    0x1.745d1745d17490p0,
    0x1.745d1745d1749p-1,
    (int)1
  },
  { // Entry 429
    0x1.745d1745d17490p1,
    0x1.745d1745d1749p-1,
    (int)2
  },
  { // Entry 430
    0x1.745d1745d17490p2,
    0x1.745d1745d1749p-1,
    (int)3
  },
  { // Entry 431
    0x1.745d1745d17490p3,
    0x1.745d1745d1749p-1,
    (int)4
  },
  { // Entry 432
    0x1.745d1745d17490p4,
    0x1.745d1745d1749p-1,
    (int)5
  },
  { // Entry 433
    0x1.745d1745d17490p5,
    0x1.745d1745d1749p-1,
    (int)6
  },
  { // Entry 434
    0x1.745d1745d17490p6,
    0x1.745d1745d1749p-1,
    (int)7
  },
  { // Entry 435
    0x1.745d1745d17490p7,
    0x1.745d1745d1749p-1,
    (int)8
  },
  { // Entry 436
    0x1.745d1745d17490p8,
    0x1.745d1745d1749p-1,
    (int)9
  },
  { // Entry 437
    0x1.745d1745d17490p9,
    0x1.745d1745d1749p-1,
    (int)10
  },
  { // Entry 438
    0x1.a2e8ba2e8ba320p-11,
    0x1.a2e8ba2e8ba32p-1,
    (int)-10
  },
  { // Entry 439
    0x1.a2e8ba2e8ba320p-10,
    0x1.a2e8ba2e8ba32p-1,
    (int)-9
  },
  { // Entry 440
    0x1.a2e8ba2e8ba320p-9,
    0x1.a2e8ba2e8ba32p-1,
    (int)-8
  },
  { // Entry 441
    0x1.a2e8ba2e8ba320p-8,
    0x1.a2e8ba2e8ba32p-1,
    (int)-7
  },
  { // Entry 442
    0x1.a2e8ba2e8ba320p-7,
    0x1.a2e8ba2e8ba32p-1,
    (int)-6
  },
  { // Entry 443
    0x1.a2e8ba2e8ba320p-6,
    0x1.a2e8ba2e8ba32p-1,
    (int)-5
  },
  { // Entry 444
    0x1.a2e8ba2e8ba320p-5,
    0x1.a2e8ba2e8ba32p-1,
    (int)-4
  },
  { // Entry 445
    0x1.a2e8ba2e8ba320p-4,
    0x1.a2e8ba2e8ba32p-1,
    (int)-3
  },
  { // Entry 446
    0x1.a2e8ba2e8ba320p-3,
    0x1.a2e8ba2e8ba32p-1,
    (int)-2
  },
  { // Entry 447
    0x1.a2e8ba2e8ba320p-2,
    0x1.a2e8ba2e8ba32p-1,
    (int)-1
  },
  { // Entry 448
    0x1.a2e8ba2e8ba320p-1,
    0x1.a2e8ba2e8ba32p-1,
    (int)0
  },
  { // Entry 449
    0x1.a2e8ba2e8ba320p0,
    0x1.a2e8ba2e8ba32p-1,
    (int)1
  },
  { // Entry 450
    0x1.a2e8ba2e8ba320p1,
    0x1.a2e8ba2e8ba32p-1,
    (int)2
  },
  { // Entry 451
    0x1.a2e8ba2e8ba320p2,
    0x1.a2e8ba2e8ba32p-1,
    (int)3
  },
  { // Entry 452
    0x1.a2e8ba2e8ba320p3,
    0x1.a2e8ba2e8ba32p-1,
    (int)4
  },
  { // Entry 453
    0x1.a2e8ba2e8ba320p4,
    0x1.a2e8ba2e8ba32p-1,
    (int)5
  },
  { // Entry 454
    0x1.a2e8ba2e8ba320p5,
    0x1.a2e8ba2e8ba32p-1,
    (int)6
  },
  { // Entry 455
    0x1.a2e8ba2e8ba320p6,
    0x1.a2e8ba2e8ba32p-1,
    (int)7
  },
  { // Entry 456
    0x1.a2e8ba2e8ba320p7,
    0x1.a2e8ba2e8ba32p-1,
    (int)8
  },
  { // Entry 457
    0x1.a2e8ba2e8ba320p8,
    0x1.a2e8ba2e8ba32p-1,
    (int)9
  },
  { // Entry 458
    0x1.a2e8ba2e8ba320p9,
    0x1.a2e8ba2e8ba32p-1,
    (int)10
  },
  { // Entry 459
    0x1.d1745d1745d1b0p-11,
    0x1.d1745d1745d1bp-1,
    (int)-10
  },
  { // Entry 460
    0x1.d1745d1745d1b0p-10,
    0x1.d1745d1745d1bp-1,
    (int)-9
  },
  { // Entry 461
    0x1.d1745d1745d1b0p-9,
    0x1.d1745d1745d1bp-1,
    (int)-8
  },
  { // Entry 462
    0x1.d1745d1745d1b0p-8,
    0x1.d1745d1745d1bp-1,
    (int)-7
  },
  { // Entry 463
    0x1.d1745d1745d1b0p-7,
    0x1.d1745d1745d1bp-1,
    (int)-6
  },
  { // Entry 464
    0x1.d1745d1745d1b0p-6,
    0x1.d1745d1745d1bp-1,
    (int)-5
  },
  { // Entry 465
    0x1.d1745d1745d1b0p-5,
    0x1.d1745d1745d1bp-1,
    (int)-4
  },
  { // Entry 466
    0x1.d1745d1745d1b0p-4,
    0x1.d1745d1745d1bp-1,
    (int)-3
  },
  { // Entry 467
    0x1.d1745d1745d1b0p-3,
    0x1.d1745d1745d1bp-1,
    (int)-2
  },
  { // Entry 468
    0x1.d1745d1745d1b0p-2,
    0x1.d1745d1745d1bp-1,
    (int)-1
  },
  { // Entry 469
    0x1.d1745d1745d1b0p-1,
    0x1.d1745d1745d1bp-1,
    (int)0
  },
  { // Entry 470
    0x1.d1745d1745d1b0p0,
    0x1.d1745d1745d1bp-1,
    (int)1
  },
  { // Entry 471
    0x1.d1745d1745d1b0p1,
    0x1.d1745d1745d1bp-1,
    (int)2
  },
  { // Entry 472
    0x1.d1745d1745d1b0p2,
    0x1.d1745d1745d1bp-1,
    (int)3
  },
  { // Entry 473
    0x1.d1745d1745d1b0p3,
    0x1.d1745d1745d1bp-1,
    (int)4
  },
  { // Entry 474
    0x1.d1745d1745d1b0p4,
    0x1.d1745d1745d1bp-1,
    (int)5
  },
  { // Entry 475
    0x1.d1745d1745d1b0p5,
    0x1.d1745d1745d1bp-1,
    (int)6
  },
  { // Entry 476
    0x1.d1745d1745d1b0p6,
    0x1.d1745d1745d1bp-1,
    (int)7
  },
  { // Entry 477
    0x1.d1745d1745d1b0p7,
    0x1.d1745d1745d1bp-1,
    (int)8
  },
  { // Entry 478
    0x1.d1745d1745d1b0p8,
    0x1.d1745d1745d1bp-1,
    (int)9
  },
  { // Entry 479
    0x1.d1745d1745d1b0p9,
    0x1.d1745d1745d1bp-1,
    (int)10
  },
  { // Entry 480
    0x1.p-10,
    0x1.0p0,
    (int)-10
  },
  { // Entry 481
    0x1.p-9,
    0x1.0p0,
    (int)-9
  },
  { // Entry 482
    0x1.p-8,
    0x1.0p0,
    (int)-8
  },
  { // Entry 483
    0x1.p-7,
    0x1.0p0,
    (int)-7
  },
  { // Entry 484
    0x1.p-6,
    0x1.0p0,
    (int)-6
  },
  { // Entry 485
    0x1.p-5,
    0x1.0p0,
    (int)-5
  },
  { // Entry 486
    0x1.p-4,
    0x1.0p0,
    (int)-4
  },
  { // Entry 487
    0x1.p-3,
    0x1.0p0,
    (int)-3
  },
  { // Entry 488
    0x1.p-2,
    0x1.0p0,
    (int)-2
  },
  { // Entry 489
    0x1.p-1,
    0x1.0p0,
    (int)-1
  },
  { // Entry 490
    0x1.p0,
    0x1.0p0,
    (int)0
  },
  { // Entry 491
    0x1.p1,
    0x1.0p0,
    (int)1
  },
  { // Entry 492
    0x1.p2,
    0x1.0p0,
    (int)2
  },
  { // Entry 493
    0x1.p3,
    0x1.0p0,
    (int)3
  },
  { // Entry 494
    0x1.p4,
    0x1.0p0,
    (int)4
  },
  { // Entry 495
    0x1.p5,
    0x1.0p0,
    (int)5
  },
  { // Entry 496
    0x1.p6,
    0x1.0p0,
    (int)6
  },
  { // Entry 497
    0x1.p7,
    0x1.0p0,
    (int)7
  },
  { // Entry 498
    0x1.p8,
    0x1.0p0,
    (int)8
  },
  { // Entry 499
    0x1.p9,
    0x1.0p0,
    (int)9
  },
  { // Entry 500
    0x1.p10,
    0x1.0p0,
    (int)10
  },
  { // Entry 501
    0x1.fffffffffffff0p0,
    0x1.fffffffffffffp1023,
    (int)-1023
  },
  { // Entry 502
    0x1.fffffffffffff0p1,
    0x1.fffffffffffffp1023,
    (int)-1022
  },
  { // Entry 503
    0x1.fffffffffffff0p23,
    0x1.fffffffffffffp1023,
    (int)-1000
  },
  { // Entry 504
    0x1.fffffffffffff0p24,
    0x1.fffffffffffffp1023,
    (int)-999
  },
  { // Entry 505
    0x1.fffffffffffff0p1013,
    0x1.fffffffffffffp1023,
    (int)-10
  },
  { // Entry 506
    0x1.fffffffffffff0p1014,
    0x1.fffffffffffffp1023,
    (int)-9
  },
  { // Entry 507
    0x1.fffffffffffff0p1015,
    0x1.fffffffffffffp1023,
    (int)-8
  },
  { // Entry 508
    0x1.fffffffffffff0p1016,
    0x1.fffffffffffffp1023,
    (int)-7
  },
  { // Entry 509
    0x1.fffffffffffff0p1017,
    0x1.fffffffffffffp1023,
    (int)-6
  },
  { // Entry 510
    0x1.fffffffffffff0p1018,
    0x1.fffffffffffffp1023,
    (int)-5
  },
  { // Entry 511
    0x1.fffffffffffff0p1019,
    0x1.fffffffffffffp1023,
    (int)-4
  },
  { // Entry 512
    0x1.fffffffffffff0p1020,
    0x1.fffffffffffffp1023,
    (int)-3
  },
  { // Entry 513
    0x1.fffffffffffff0p1021,
    0x1.fffffffffffffp1023,
    (int)-2
  },
  { // Entry 514
    0x1.fffffffffffff0p1022,
    0x1.fffffffffffffp1023,
    (int)-1
  },
  { // Entry 515
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    (int)0
  },
  { // Entry 516
    0x1.p-51,
    0x1.0p-1074,
    (int)1023
  },
  { // Entry 517
    0x1.p-52,
    0x1.0p-1074,
    (int)1022
  },
  { // Entry 518
    0x1.p-74,
    0x1.0p-1074,
    (int)1000
  },
  { // Entry 519
    0x1.p-75,
    0x1.0p-1074,
    (int)999
  },
  { // Entry 520
    0x1.p-1074,
    0x1.0p-1074,
    (int)0
  },
  { // Entry 521
    0x1.p-1073,
    0x1.0p-1074,
    (int)1
  },
  { // Entry 522
    0x1.p-1072,
    0x1.0p-1074,
    (int)2
  },
  { // Entry 523
    0x1.p-1071,
    0x1.0p-1074,
    (int)3
  },
  { // Entry 524
    0x1.p-1070,
    0x1.0p-1074,
    (int)4
  },
  { // Entry 525
    0x1.p-1069,
    0x1.0p-1074,
    (int)5
  },
  { // Entry 526
    0x1.p-1068,
    0x1.0p-1074,
    (int)6
  },
  { // Entry 527
    0x1.p-1067,
    0x1.0p-1074,
    (int)7
  },
  { // Entry 528
    0x1.p-1066,
    0x1.0p-1074,
    (int)8
  },
  { // Entry 529
    0x1.p-1065,
    0x1.0p-1074,
    (int)9
  },
  { // Entry 530
    0x1.p-1064,
    0x1.0p-1074,
    (int)10
  },
  { // Entry 531
    0x1.p-1025,
    0x1.0p-2,
    (int)-1023
  },
  { // Entry 532
    0x1.p-1024,
    0x1.0p-2,
    (int)-1022
  },
  { // Entry 533
    0x1.p-1024,
    0x1.0p-1,
    (int)-1023
  },
  { // Entry 534
    0x1.p-1023,
    0x1.0p-1,
    (int)-1022
  },
  { // Entry 535
    0x1.80p-1024,
    0x1.8p-1,
    (int)-1023
  },
  { // Entry 536
    0x1.80p-1023,
    0x1.8p-1,
    (int)-1022
  },
  { // Entry 537
    0.0,
    0x1.0p-2,
    (int)-1074
  },
  { // Entry 538
    0.0,
    0x1.0p-2,
    (int)-1073
  },
  { // Entry 539
    0.0,
    0x1.0p-1,
    (int)-1074
  },
  { // Entry 540
    0x1.p-1074,
    0x1.0p-1,
    (int)-1073
  },
  { // Entry 541
    0.0,
    0x1.8p-1,
    (int)-1074
  },
  { // Entry 542
    0x1.80p-1074,
    0x1.8p-1,
    (int)-1073
  },
  { // Entry 543
    0x1.p1023,
    0x1.0p0,
    (int)1023
  },
  { // Entry 544
    0x1.p1022,
    0x1.0p0,
    (int)1022
  },
  { // Entry 545
    0x1.p-1074,
    0x1.0p-1074,
    (int)0
  },
  { // Entry 546
    0x1.p-1073,
    0x1.0p-1074,
    (int)1
  },
  { // Entry 547
    0x1.p-1072,
    0x1.0p-1074,
    (int)2
  },
  { // Entry 548
    0x1.p-1071,
    0x1.0p-1074,
    (int)3
  },
  { // Entry 549
    0x1.p-1070,
    0x1.0p-1074,
    (int)4
  },
  { // Entry 550
    0x1.p-1069,
    0x1.0p-1074,
    (int)5
  },
  { // Entry 551
    0x1.p-1068,
    0x1.0p-1074,
    (int)6
  },
  { // Entry 552
    0x1.p-1067,
    0x1.0p-1074,
    (int)7
  },
  { // Entry 553
    0x1.p-1066,
    0x1.0p-1074,
    (int)8
  },
  { // Entry 554
    0x1.p-1065,
    0x1.0p-1074,
    (int)9
  },
  { // Entry 555
    0x1.p-1064,
    0x1.0p-1074,
    (int)10
  },
  { // Entry 556
    0x1.p-1063,
    0x1.0p-1074,
    (int)11
  },
  { // Entry 557
    0x1.p-1062,
    0x1.0p-1074,
    (int)12
  },
  { // Entry 558
    0x1.p-1061,
    0x1.0p-1074,
    (int)13
  },
  { // Entry 559
    0x1.p-1060,
    0x1.0p-1074,
    (int)14
  },
  { // Entry 560
    0x1.p-1059,
    0x1.0p-1074,
    (int)15
  },
  { // Entry 561
    0x1.p-1058,
    0x1.0p-1074,
    (int)16
  },
  { // Entry 562
    0x1.p-1057,
    0x1.0p-1074,
    (int)17
  },
  { // Entry 563
    0x1.p-1056,
    0x1.0p-1074,
    (int)18
  },
  { // Entry 564
    0x1.p-1055,
    0x1.0p-1074,
    (int)19
  },
  { // Entry 565
    0x1.p-1054,
    0x1.0p-1074,
    (int)20
  },
  { // Entry 566
    0x1.p-1053,
    0x1.0p-1074,
    (int)21
  },
  { // Entry 567
    0x1.p-1052,
    0x1.0p-1074,
    (int)22
  },
  { // Entry 568
    0x1.p-1051,
    0x1.0p-1074,
    (int)23
  },
  { // Entry 569
    0x1.p-1050,
    0x1.0p-1074,
    (int)24
  },
  { // Entry 570
    0x1.p-1049,
    0x1.0p-1074,
    (int)25
  },
  { // Entry 571
    0x1.p-1048,
    0x1.0p-1074,
    (int)26
  },
  { // Entry 572
    0x1.p-1047,
    0x1.0p-1074,
    (int)27
  },
  { // Entry 573
    0x1.p-1046,
    0x1.0p-1074,
    (int)28
  },
  { // Entry 574
    0x1.p-1045,
    0x1.0p-1074,
    (int)29
  },
  { // Entry 575
    0x1.p-1044,
    0x1.0p-1074,
    (int)30
  },
  { // Entry 576
    0x1.p-1043,
    0x1.0p-1074,
    (int)31
  },
  { // Entry 577
    0x1.p-1042,
    0x1.0p-1074,
    (int)32
  },
  { // Entry 578
    0x1.p-1041,
    0x1.0p-1074,
    (int)33
  },
  { // Entry 579
    0x1.p-1040,
    0x1.0p-1074,
    (int)34
  },
  { // Entry 580
    0x1.p-1039,
    0x1.0p-1074,
    (int)35
  },
  { // Entry 581
    0x1.p-1038,
    0x1.0p-1074,
    (int)36
  },
  { // Entry 582
    0x1.p-1037,
    0x1.0p-1074,
    (int)37
  },
  { // Entry 583
    0x1.p-1036,
    0x1.0p-1074,
    (int)38
  },
  { // Entry 584
    0x1.p-1035,
    0x1.0p-1074,
    (int)39
  },
  { // Entry 585
    0x1.p-1034,
    0x1.0p-1074,
    (int)40
  },
  { // Entry 586
    0x1.p-1033,
    0x1.0p-1074,
    (int)41
  },
  { // Entry 587
    0x1.p-1032,
    0x1.0p-1074,
    (int)42
  },
  { // Entry 588
    0x1.p-1031,
    0x1.0p-1074,
    (int)43
  },
  { // Entry 589
    0x1.p-1030,
    0x1.0p-1074,
    (int)44
  },
  { // Entry 590
    0x1.p-1029,
    0x1.0p-1074,
    (int)45
  },
  { // Entry 591
    0x1.p-1028,
    0x1.0p-1074,
    (int)46
  },
  { // Entry 592
    0x1.p-1027,
    0x1.0p-1074,
    (int)47
  },
  { // Entry 593
    0x1.p-1026,
    0x1.0p-1074,
    (int)48
  },
  { // Entry 594
    0x1.p-1025,
    0x1.0p-1074,
    (int)49
  },
  { // Entry 595
    0x1.p-1024,
    0x1.0p-1074,
    (int)50
  },
  { // Entry 596
    0x1.p-1023,
    0x1.0p-1074,
    (int)51
  },
  { // Entry 597
    0x1.p-1022,
    0x1.0p-1074,
    (int)52
  },
  { // Entry 598
    0x1.p-1021,
    0x1.0p-1074,
    (int)53
  },
  { // Entry 599
    0x1.p-1020,
    0x1.0p-1074,
    (int)54
  },
  { // Entry 600
    0x1.p-1019,
    0x1.0p-1074,
    (int)55
  },
  { // Entry 601
    0x1.p-1018,
    0x1.0p-1074,
    (int)56
  },
  { // Entry 602
    0x1.p-1017,
    0x1.0p-1074,
    (int)57
  },
  { // Entry 603
    0x1.p-1016,
    0x1.0p-1074,
    (int)58
  },
  { // Entry 604
    0x1.p-1015,
    0x1.0p-1074,
    (int)59
  },
  { // Entry 605
    0x1.p-1014,
    0x1.0p-1074,
    (int)60
  },
  { // Entry 606
    0x1.p-1013,
    0x1.0p-1074,
    (int)61
  },
  { // Entry 607
    0x1.p-1012,
    0x1.0p-1074,
    (int)62
  },
  { // Entry 608
    0x1.p-1011,
    0x1.0p-1074,
    (int)63
  },
  { // Entry 609
    0x1.p-1010,
    0x1.0p-1074,
    (int)64
  },
  { // Entry 610
    0x1.p-1009,
    0x1.0p-1074,
    (int)65
  },
  { // Entry 611
    0x1.p-1008,
    0x1.0p-1074,
    (int)66
  },
  { // Entry 612
    0x1.p-1007,
    0x1.0p-1074,
    (int)67
  },
  { // Entry 613
    0x1.p-1006,
    0x1.0p-1074,
    (int)68
  },
  { // Entry 614
    0x1.p-1005,
    0x1.0p-1074,
    (int)69
  },
  { // Entry 615
    0x1.p-1004,
    0x1.0p-1074,
    (int)70
  },
  { // Entry 616
    0x1.p-1003,
    0x1.0p-1074,
    (int)71
  },
  { // Entry 617
    0x1.p-1002,
    0x1.0p-1074,
    (int)72
  },
  { // Entry 618
    0x1.p-1001,
    0x1.0p-1074,
    (int)73
  },
  { // Entry 619
    0x1.p-1000,
    0x1.0p-1074,
    (int)74
  },
  { // Entry 620
    0x1.p-999,
    0x1.0p-1074,
    (int)75
  },
  { // Entry 621
    0x1.p-998,
    0x1.0p-1074,
    (int)76
  },
  { // Entry 622
    0x1.p-997,
    0x1.0p-1074,
    (int)77
  },
  { // Entry 623
    0x1.p-996,
    0x1.0p-1074,
    (int)78
  },
  { // Entry 624
    0x1.p-995,
    0x1.0p-1074,
    (int)79
  },
  { // Entry 625
    0x1.p-994,
    0x1.0p-1074,
    (int)80
  },
  { // Entry 626
    0x1.p-993,
    0x1.0p-1074,
    (int)81
  },
  { // Entry 627
    0x1.p-992,
    0x1.0p-1074,
    (int)82
  },
  { // Entry 628
    0x1.p-991,
    0x1.0p-1074,
    (int)83
  },
  { // Entry 629
    0x1.p-990,
    0x1.0p-1074,
    (int)84
  },
  { // Entry 630
    0x1.p-989,
    0x1.0p-1074,
    (int)85
  },
  { // Entry 631
    0x1.p-988,
    0x1.0p-1074,
    (int)86
  },
  { // Entry 632
    0x1.p-987,
    0x1.0p-1074,
    (int)87
  },
  { // Entry 633
    0x1.p-986,
    0x1.0p-1074,
    (int)88
  },
  { // Entry 634
    0x1.p-985,
    0x1.0p-1074,
    (int)89
  },
  { // Entry 635
    0x1.p-984,
    0x1.0p-1074,
    (int)90
  },
  { // Entry 636
    0x1.p-983,
    0x1.0p-1074,
    (int)91
  },
  { // Entry 637
    0x1.p-982,
    0x1.0p-1074,
    (int)92
  },
  { // Entry 638
    0x1.p-981,
    0x1.0p-1074,
    (int)93
  },
  { // Entry 639
    0x1.p-980,
    0x1.0p-1074,
    (int)94
  },
  { // Entry 640
    0x1.p-979,
    0x1.0p-1074,
    (int)95
  },
  { // Entry 641
    0x1.p-978,
    0x1.0p-1074,
    (int)96
  },
  { // Entry 642
    0x1.p-977,
    0x1.0p-1074,
    (int)97
  },
  { // Entry 643
    0x1.p-976,
    0x1.0p-1074,
    (int)98
  },
  { // Entry 644
    0x1.p-975,
    0x1.0p-1074,
    (int)99
  },
  { // Entry 645
    0x1.p-974,
    0x1.0p-1074,
    (int)100
  },
  { // Entry 646
    0x1.p-973,
    0x1.0p-1074,
    (int)101
  },
  { // Entry 647
    0x1.p-972,
    0x1.0p-1074,
    (int)102
  },
  { // Entry 648
    0x1.p-971,
    0x1.0p-1074,
    (int)103
  },
  { // Entry 649
    0x1.p-970,
    0x1.0p-1074,
    (int)104
  },
  { // Entry 650
    0x1.p-969,
    0x1.0p-1074,
    (int)105
  },
  { // Entry 651
    0x1.p-968,
    0x1.0p-1074,
    (int)106
  },
  { // Entry 652
    0x1.p-967,
    0x1.0p-1074,
    (int)107
  },
  { // Entry 653
    0x1.p-966,
    0x1.0p-1074,
    (int)108
  },
  { // Entry 654
    0x1.p-965,
    0x1.0p-1074,
    (int)109
  },
  { // Entry 655
    0x1.p-964,
    0x1.0p-1074,
    (int)110
  },
  { // Entry 656
    0x1.p-963,
    0x1.0p-1074,
    (int)111
  },
  { // Entry 657
    0x1.p-962,
    0x1.0p-1074,
    (int)112
  },
  { // Entry 658
    0x1.p-961,
    0x1.0p-1074,
    (int)113
  },
  { // Entry 659
    0x1.p-960,
    0x1.0p-1074,
    (int)114
  },
  { // Entry 660
    0x1.p-959,
    0x1.0p-1074,
    (int)115
  },
  { // Entry 661
    0x1.p-958,
    0x1.0p-1074,
    (int)116
  },
  { // Entry 662
    0x1.p-957,
    0x1.0p-1074,
    (int)117
  },
  { // Entry 663
    0x1.p-956,
    0x1.0p-1074,
    (int)118
  },
  { // Entry 664
    0x1.p-955,
    0x1.0p-1074,
    (int)119
  },
  { // Entry 665
    0x1.p-954,
    0x1.0p-1074,
    (int)120
  },
  { // Entry 666
    0x1.p-953,
    0x1.0p-1074,
    (int)121
  },
  { // Entry 667
    0x1.p-952,
    0x1.0p-1074,
    (int)122
  },
  { // Entry 668
    0x1.p-951,
    0x1.0p-1074,
    (int)123
  },
  { // Entry 669
    0x1.p-950,
    0x1.0p-1074,
    (int)124
  },
  { // Entry 670
    0x1.p-949,
    0x1.0p-1074,
    (int)125
  },
  { // Entry 671
    0x1.p-948,
    0x1.0p-1074,
    (int)126
  },
  { // Entry 672
    0x1.p-947,
    0x1.0p-1074,
    (int)127
  },
  { // Entry 673
    0x1.p-946,
    0x1.0p-1074,
    (int)128
  },
  { // Entry 674
    0x1.p-945,
    0x1.0p-1074,
    (int)129
  },
  { // Entry 675
    0x1.p-944,
    0x1.0p-1074,
    (int)130
  },
  { // Entry 676
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    (int)0
  },
  { // Entry 677
    0x1.ffffffffffffe0p-1022,
    0x1.ffffffffffffep-1023,
    (int)1
  },
  { // Entry 678
    0x1.ffffffffffffe0p-1021,
    0x1.ffffffffffffep-1023,
    (int)2
  },
  { // Entry 679
    0x1.ffffffffffffe0p-1020,
    0x1.ffffffffffffep-1023,
    (int)3
  },
  { // Entry 680
    0x1.ffffffffffffe0p-1019,
    0x1.ffffffffffffep-1023,
    (int)4
  },
  { // Entry 681
    0x1.ffffffffffffe0p-1018,
    0x1.ffffffffffffep-1023,
    (int)5
  },
  { // Entry 682
    0x1.ffffffffffffe0p-1017,
    0x1.ffffffffffffep-1023,
    (int)6
  },
  { // Entry 683
    0x1.ffffffffffffe0p-1016,
    0x1.ffffffffffffep-1023,
    (int)7
  },
  { // Entry 684
    0x1.ffffffffffffe0p-1015,
    0x1.ffffffffffffep-1023,
    (int)8
  },
  { // Entry 685
    0x1.ffffffffffffe0p-1014,
    0x1.ffffffffffffep-1023,
    (int)9
  },
  { // Entry 686
    0x1.ffffffffffffe0p-1013,
    0x1.ffffffffffffep-1023,
    (int)10
  },
  { // Entry 687
    0x1.ffffffffffffe0p-1012,
    0x1.ffffffffffffep-1023,
    (int)11
  },
  { // Entry 688
    0x1.ffffffffffffe0p-1011,
    0x1.ffffffffffffep-1023,
    (int)12
  },
  { // Entry 689
    0x1.ffffffffffffe0p-1010,
    0x1.ffffffffffffep-1023,
    (int)13
  },
  { // Entry 690
    0x1.ffffffffffffe0p-1009,
    0x1.ffffffffffffep-1023,
    (int)14
  },
  { // Entry 691
    0x1.ffffffffffffe0p-1008,
    0x1.ffffffffffffep-1023,
    (int)15
  },
  { // Entry 692
    0x1.ffffffffffffe0p-1007,
    0x1.ffffffffffffep-1023,
    (int)16
  },
  { // Entry 693
    0x1.ffffffffffffe0p-1006,
    0x1.ffffffffffffep-1023,
    (int)17
  },
  { // Entry 694
    0x1.ffffffffffffe0p-1005,
    0x1.ffffffffffffep-1023,
    (int)18
  },
  { // Entry 695
    0x1.ffffffffffffe0p-1004,
    0x1.ffffffffffffep-1023,
    (int)19
  },
  { // Entry 696
    0x1.ffffffffffffe0p-1003,
    0x1.ffffffffffffep-1023,
    (int)20
  },
  { // Entry 697
    0x1.ffffffffffffe0p-1002,
    0x1.ffffffffffffep-1023,
    (int)21
  },
  { // Entry 698
    0x1.ffffffffffffe0p-1001,
    0x1.ffffffffffffep-1023,
    (int)22
  },
  { // Entry 699
    0x1.ffffffffffffe0p-1000,
    0x1.ffffffffffffep-1023,
    (int)23
  },
  { // Entry 700
    0x1.ffffffffffffe0p-999,
    0x1.ffffffffffffep-1023,
    (int)24
  },
  { // Entry 701
    0x1.ffffffffffffe0p-998,
    0x1.ffffffffffffep-1023,
    (int)25
  },
  { // Entry 702
    0x1.ffffffffffffe0p-997,
    0x1.ffffffffffffep-1023,
    (int)26
  },
  { // Entry 703
    0x1.ffffffffffffe0p-996,
    0x1.ffffffffffffep-1023,
    (int)27
  },
  { // Entry 704
    0x1.ffffffffffffe0p-995,
    0x1.ffffffffffffep-1023,
    (int)28
  },
  { // Entry 705
    0x1.ffffffffffffe0p-994,
    0x1.ffffffffffffep-1023,
    (int)29
  },
  { // Entry 706
    0x1.ffffffffffffe0p-993,
    0x1.ffffffffffffep-1023,
    (int)30
  },
  { // Entry 707
    0x1.ffffffffffffe0p-992,
    0x1.ffffffffffffep-1023,
    (int)31
  },
  { // Entry 708
    0x1.ffffffffffffe0p-991,
    0x1.ffffffffffffep-1023,
    (int)32
  },
  { // Entry 709
    0x1.ffffffffffffe0p-990,
    0x1.ffffffffffffep-1023,
    (int)33
  },
  { // Entry 710
    0x1.ffffffffffffe0p-989,
    0x1.ffffffffffffep-1023,
    (int)34
  },
  { // Entry 711
    0x1.ffffffffffffe0p-988,
    0x1.ffffffffffffep-1023,
    (int)35
  },
  { // Entry 712
    0x1.ffffffffffffe0p-987,
    0x1.ffffffffffffep-1023,
    (int)36
  },
  { // Entry 713
    0x1.ffffffffffffe0p-986,
    0x1.ffffffffffffep-1023,
    (int)37
  },
  { // Entry 714
    0x1.ffffffffffffe0p-985,
    0x1.ffffffffffffep-1023,
    (int)38
  },
  { // Entry 715
    0x1.ffffffffffffe0p-984,
    0x1.ffffffffffffep-1023,
    (int)39
  },
  { // Entry 716
    0x1.ffffffffffffe0p-983,
    0x1.ffffffffffffep-1023,
    (int)40
  },
  { // Entry 717
    0x1.ffffffffffffe0p-982,
    0x1.ffffffffffffep-1023,
    (int)41
  },
  { // Entry 718
    0x1.ffffffffffffe0p-981,
    0x1.ffffffffffffep-1023,
    (int)42
  },
  { // Entry 719
    0x1.ffffffffffffe0p-980,
    0x1.ffffffffffffep-1023,
    (int)43
  },
  { // Entry 720
    0x1.ffffffffffffe0p-979,
    0x1.ffffffffffffep-1023,
    (int)44
  },
  { // Entry 721
    0x1.ffffffffffffe0p-978,
    0x1.ffffffffffffep-1023,
    (int)45
  },
  { // Entry 722
    0x1.ffffffffffffe0p-977,
    0x1.ffffffffffffep-1023,
    (int)46
  },
  { // Entry 723
    0x1.ffffffffffffe0p-976,
    0x1.ffffffffffffep-1023,
    (int)47
  },
  { // Entry 724
    0x1.ffffffffffffe0p-975,
    0x1.ffffffffffffep-1023,
    (int)48
  },
  { // Entry 725
    0x1.ffffffffffffe0p-974,
    0x1.ffffffffffffep-1023,
    (int)49
  },
  { // Entry 726
    0x1.ffffffffffffe0p-973,
    0x1.ffffffffffffep-1023,
    (int)50
  },
  { // Entry 727
    0x1.ffffffffffffe0p-972,
    0x1.ffffffffffffep-1023,
    (int)51
  },
  { // Entry 728
    0x1.ffffffffffffe0p-971,
    0x1.ffffffffffffep-1023,
    (int)52
  },
  { // Entry 729
    0x1.ffffffffffffe0p-970,
    0x1.ffffffffffffep-1023,
    (int)53
  },
  { // Entry 730
    0x1.ffffffffffffe0p-969,
    0x1.ffffffffffffep-1023,
    (int)54
  },
  { // Entry 731
    0x1.ffffffffffffe0p-968,
    0x1.ffffffffffffep-1023,
    (int)55
  },
  { // Entry 732
    0x1.ffffffffffffe0p-967,
    0x1.ffffffffffffep-1023,
    (int)56
  },
  { // Entry 733
    0x1.ffffffffffffe0p-966,
    0x1.ffffffffffffep-1023,
    (int)57
  },
  { // Entry 734
    0x1.ffffffffffffe0p-965,
    0x1.ffffffffffffep-1023,
    (int)58
  },
  { // Entry 735
    0x1.ffffffffffffe0p-964,
    0x1.ffffffffffffep-1023,
    (int)59
  },
  { // Entry 736
    0x1.ffffffffffffe0p-963,
    0x1.ffffffffffffep-1023,
    (int)60
  },
  { // Entry 737
    0x1.ffffffffffffe0p-962,
    0x1.ffffffffffffep-1023,
    (int)61
  },
  { // Entry 738
    0x1.ffffffffffffe0p-961,
    0x1.ffffffffffffep-1023,
    (int)62
  },
  { // Entry 739
    0x1.ffffffffffffe0p-960,
    0x1.ffffffffffffep-1023,
    (int)63
  },
  { // Entry 740
    0x1.ffffffffffffe0p-959,
    0x1.ffffffffffffep-1023,
    (int)64
  },
  { // Entry 741
    0x1.ffffffffffffe0p-958,
    0x1.ffffffffffffep-1023,
    (int)65
  },
  { // Entry 742
    0x1.ffffffffffffe0p-957,
    0x1.ffffffffffffep-1023,
    (int)66
  },
  { // Entry 743
    0x1.ffffffffffffe0p-956,
    0x1.ffffffffffffep-1023,
    (int)67
  },
  { // Entry 744
    0x1.ffffffffffffe0p-955,
    0x1.ffffffffffffep-1023,
    (int)68
  },
  { // Entry 745
    0x1.ffffffffffffe0p-954,
    0x1.ffffffffffffep-1023,
    (int)69
  },
  { // Entry 746
    0x1.ffffffffffffe0p-953,
    0x1.ffffffffffffep-1023,
    (int)70
  },
  { // Entry 747
    0x1.ffffffffffffe0p-952,
    0x1.ffffffffffffep-1023,
    (int)71
  },
  { // Entry 748
    0x1.ffffffffffffe0p-951,
    0x1.ffffffffffffep-1023,
    (int)72
  },
  { // Entry 749
    0x1.ffffffffffffe0p-950,
    0x1.ffffffffffffep-1023,
    (int)73
  },
  { // Entry 750
    0x1.ffffffffffffe0p-949,
    0x1.ffffffffffffep-1023,
    (int)74
  },
  { // Entry 751
    0x1.ffffffffffffe0p-948,
    0x1.ffffffffffffep-1023,
    (int)75
  },
  { // Entry 752
    0x1.ffffffffffffe0p-947,
    0x1.ffffffffffffep-1023,
    (int)76
  },
  { // Entry 753
    0x1.ffffffffffffe0p-946,
    0x1.ffffffffffffep-1023,
    (int)77
  },
  { // Entry 754
    0x1.ffffffffffffe0p-945,
    0x1.ffffffffffffep-1023,
    (int)78
  },
  { // Entry 755
    0x1.ffffffffffffe0p-944,
    0x1.ffffffffffffep-1023,
    (int)79
  },
  { // Entry 756
    0x1.ffffffffffffe0p-943,
    0x1.ffffffffffffep-1023,
    (int)80
  },
  { // Entry 757
    0x1.ffffffffffffe0p-942,
    0x1.ffffffffffffep-1023,
    (int)81
  },
  { // Entry 758
    0x1.ffffffffffffe0p-941,
    0x1.ffffffffffffep-1023,
    (int)82
  },
  { // Entry 759
    0x1.ffffffffffffe0p-940,
    0x1.ffffffffffffep-1023,
    (int)83
  },
  { // Entry 760
    0x1.ffffffffffffe0p-939,
    0x1.ffffffffffffep-1023,
    (int)84
  },
  { // Entry 761
    0x1.ffffffffffffe0p-938,
    0x1.ffffffffffffep-1023,
    (int)85
  },
  { // Entry 762
    0x1.ffffffffffffe0p-937,
    0x1.ffffffffffffep-1023,
    (int)86
  },
  { // Entry 763
    0x1.ffffffffffffe0p-936,
    0x1.ffffffffffffep-1023,
    (int)87
  },
  { // Entry 764
    0x1.ffffffffffffe0p-935,
    0x1.ffffffffffffep-1023,
    (int)88
  },
  { // Entry 765
    0x1.ffffffffffffe0p-934,
    0x1.ffffffffffffep-1023,
    (int)89
  },
  { // Entry 766
    0x1.ffffffffffffe0p-933,
    0x1.ffffffffffffep-1023,
    (int)90
  },
  { // Entry 767
    0x1.ffffffffffffe0p-932,
    0x1.ffffffffffffep-1023,
    (int)91
  },
  { // Entry 768
    0x1.ffffffffffffe0p-931,
    0x1.ffffffffffffep-1023,
    (int)92
  },
  { // Entry 769
    0x1.ffffffffffffe0p-930,
    0x1.ffffffffffffep-1023,
    (int)93
  },
  { // Entry 770
    0x1.ffffffffffffe0p-929,
    0x1.ffffffffffffep-1023,
    (int)94
  },
  { // Entry 771
    0x1.ffffffffffffe0p-928,
    0x1.ffffffffffffep-1023,
    (int)95
  },
  { // Entry 772
    0x1.ffffffffffffe0p-927,
    0x1.ffffffffffffep-1023,
    (int)96
  },
  { // Entry 773
    0x1.ffffffffffffe0p-926,
    0x1.ffffffffffffep-1023,
    (int)97
  },
  { // Entry 774
    0x1.ffffffffffffe0p-925,
    0x1.ffffffffffffep-1023,
    (int)98
  },
  { // Entry 775
    0x1.ffffffffffffe0p-924,
    0x1.ffffffffffffep-1023,
    (int)99
  },
  { // Entry 776
    0x1.ffffffffffffe0p-923,
    0x1.ffffffffffffep-1023,
    (int)100
  },
  { // Entry 777
    0x1.ffffffffffffe0p-922,
    0x1.ffffffffffffep-1023,
    (int)101
  },
  { // Entry 778
    0x1.ffffffffffffe0p-921,
    0x1.ffffffffffffep-1023,
    (int)102
  },
  { // Entry 779
    0x1.ffffffffffffe0p-920,
    0x1.ffffffffffffep-1023,
    (int)103
  },
  { // Entry 780
    0x1.ffffffffffffe0p-919,
    0x1.ffffffffffffep-1023,
    (int)104
  },
  { // Entry 781
    0x1.ffffffffffffe0p-918,
    0x1.ffffffffffffep-1023,
    (int)105
  },
  { // Entry 782
    0x1.ffffffffffffe0p-917,
    0x1.ffffffffffffep-1023,
    (int)106
  },
  { // Entry 783
    0x1.ffffffffffffe0p-916,
    0x1.ffffffffffffep-1023,
    (int)107
  },
  { // Entry 784
    0x1.ffffffffffffe0p-915,
    0x1.ffffffffffffep-1023,
    (int)108
  },
  { // Entry 785
    0x1.ffffffffffffe0p-914,
    0x1.ffffffffffffep-1023,
    (int)109
  },
  { // Entry 786
    0x1.ffffffffffffe0p-913,
    0x1.ffffffffffffep-1023,
    (int)110
  },
  { // Entry 787
    0x1.ffffffffffffe0p-912,
    0x1.ffffffffffffep-1023,
    (int)111
  },
  { // Entry 788
    0x1.ffffffffffffe0p-911,
    0x1.ffffffffffffep-1023,
    (int)112
  },
  { // Entry 789
    0x1.ffffffffffffe0p-910,
    0x1.ffffffffffffep-1023,
    (int)113
  },
  { // Entry 790
    0x1.ffffffffffffe0p-909,
    0x1.ffffffffffffep-1023,
    (int)114
  },
  { // Entry 791
    0x1.ffffffffffffe0p-908,
    0x1.ffffffffffffep-1023,
    (int)115
  },
  { // Entry 792
    0x1.ffffffffffffe0p-907,
    0x1.ffffffffffffep-1023,
    (int)116
  },
  { // Entry 793
    0x1.ffffffffffffe0p-906,
    0x1.ffffffffffffep-1023,
    (int)117
  },
  { // Entry 794
    0x1.ffffffffffffe0p-905,
    0x1.ffffffffffffep-1023,
    (int)118
  },
  { // Entry 795
    0x1.ffffffffffffe0p-904,
    0x1.ffffffff
"""


```
Response:
The user wants a summary of the functionality of the provided C code snippet. This is the second part of a larger file.

Based on the provided data, the file `scalbf_intel_data.handroid` seems to be a data file containing test vectors for the `scalbf` function. `scalbf` is a standard C library function for scaling a floating-point number by a power of 2.

**Plan:**

1. **Identify the core functionality:** The file provides test data for `scalbf`.
2. **Explain the format of the data:** Each entry seems to represent a test case with input values and expected output.
3. **Relate it to the larger context:** The file is part of Android's bionic library, specifically for math functions on Intel architectures.
从提供的代码片段来看，这份数据文件（`scalbf_intel_data.handroid`）的主要功能是**为 `scalbf` 函数提供测试用例数据**。

`scalbf` 函数是 C 标准库 `<math.h>` 中定义的一个函数，用于将一个 `float` 类型的浮点数乘以 2 的整数次幂。

**归纳一下它的功能：**

这份数据文件包含了一系列预定义的输入和期望输出值，用于测试 `scalbf` 函数在各种情况下的正确性，特别是在 Intel 架构上的实现。

**更具体地说，每个“Entry”都代表一个独立的测试用例，包含以下信息：**

* **第一个值：**  `scalbf` 函数的第一个输入参数，即待缩放的浮点数。
* **第二个值：** `scalbf` 函数的第二个输入参数，即 2 的指数。
* **第三个值：** `scalbf` 函数的预期返回值，即缩放后的浮点数。

**例如，对于以下 Entry:**

```c
{ // Entry 446
    0x1.a2e8c4p-1,
    0x1.a2e8c4p-1,
    0x1.p-2
  },
```

这表示当 `scalbf` 函数的第一个参数是 `0x1.a2e8c4p-1`，第二个参数是 `0x1.a2e8c4p-1` 时，期望的返回值是 `0x1.p-2`。  这里使用的十六进制浮点数表示法，`0x1.a2e8c4p-1` 相当于 (1 + 10/16 + 2/256 + ... ) * 2<sup>-1</sup>。

**总结:**

作为第二部分，这份数据文件与第一部分一起，完整地定义了针对 `scalbf` 函数在 Intel 架构上的测试用例。这些测试用例覆盖了各种正常值、边界值（如 0、无穷大、NaN）以及不同的指数范围，旨在确保 `scalbf` 函数的实现符合预期，并且能处理各种可能的输入情况。  它不包含函数实现的代码，而是用于验证函数实现正确性的数据。

Prompt: 
```
这是目录为bionic/tests/math_data/scalbf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
c4p-1,
    0x1.p0
  },
  { // Entry 447
    0x1.a2e8c4p1,
    0x1.a2e8c4p-1,
    0x1.p1
  },
  { // Entry 448
    0x1.a2e8c4p2,
    0x1.a2e8c4p-1,
    0x1.80p1
  },
  { // Entry 449
    0x1.a2e8c4p3,
    0x1.a2e8c4p-1,
    0x1.p2
  },
  { // Entry 450
    0x1.a2e8c4p4,
    0x1.a2e8c4p-1,
    0x1.40p2
  },
  { // Entry 451
    0x1.a2e8c4p5,
    0x1.a2e8c4p-1,
    0x1.80p2
  },
  { // Entry 452
    0x1.a2e8c4p6,
    0x1.a2e8c4p-1,
    0x1.c0p2
  },
  { // Entry 453
    0x1.a2e8c4p7,
    0x1.a2e8c4p-1,
    0x1.p3
  },
  { // Entry 454
    0x1.a2e8c4p8,
    0x1.a2e8c4p-1,
    0x1.20p3
  },
  { // Entry 455
    0x1.a2e8c4p9,
    0x1.a2e8c4p-1,
    0x1.40p3
  },
  { // Entry 456
    0x1.d17468p-11,
    0x1.d17468p-1,
    -0x1.40p3
  },
  { // Entry 457
    0x1.d17468p-10,
    0x1.d17468p-1,
    -0x1.20p3
  },
  { // Entry 458
    0x1.d17468p-9,
    0x1.d17468p-1,
    -0x1.p3
  },
  { // Entry 459
    0x1.d17468p-8,
    0x1.d17468p-1,
    -0x1.c0p2
  },
  { // Entry 460
    0x1.d17468p-7,
    0x1.d17468p-1,
    -0x1.80p2
  },
  { // Entry 461
    0x1.d17468p-6,
    0x1.d17468p-1,
    -0x1.40p2
  },
  { // Entry 462
    0x1.d17468p-5,
    0x1.d17468p-1,
    -0x1.p2
  },
  { // Entry 463
    0x1.d17468p-4,
    0x1.d17468p-1,
    -0x1.80p1
  },
  { // Entry 464
    0x1.d17468p-3,
    0x1.d17468p-1,
    -0x1.p1
  },
  { // Entry 465
    0x1.d17468p-2,
    0x1.d17468p-1,
    -0x1.p0
  },
  { // Entry 466
    0x1.d17468p-1,
    0x1.d17468p-1,
    0.0
  },
  { // Entry 467
    0x1.d17468p0,
    0x1.d17468p-1,
    0x1.p0
  },
  { // Entry 468
    0x1.d17468p1,
    0x1.d17468p-1,
    0x1.p1
  },
  { // Entry 469
    0x1.d17468p2,
    0x1.d17468p-1,
    0x1.80p1
  },
  { // Entry 470
    0x1.d17468p3,
    0x1.d17468p-1,
    0x1.p2
  },
  { // Entry 471
    0x1.d17468p4,
    0x1.d17468p-1,
    0x1.40p2
  },
  { // Entry 472
    0x1.d17468p5,
    0x1.d17468p-1,
    0x1.80p2
  },
  { // Entry 473
    0x1.d17468p6,
    0x1.d17468p-1,
    0x1.c0p2
  },
  { // Entry 474
    0x1.d17468p7,
    0x1.d17468p-1,
    0x1.p3
  },
  { // Entry 475
    0x1.d17468p8,
    0x1.d17468p-1,
    0x1.20p3
  },
  { // Entry 476
    0x1.d17468p9,
    0x1.d17468p-1,
    0x1.40p3
  },
  { // Entry 477
    0x1.p-10,
    0x1.p0,
    -0x1.40p3
  },
  { // Entry 478
    0x1.p-9,
    0x1.p0,
    -0x1.20p3
  },
  { // Entry 479
    0x1.p-8,
    0x1.p0,
    -0x1.p3
  },
  { // Entry 480
    0x1.p-7,
    0x1.p0,
    -0x1.c0p2
  },
  { // Entry 481
    0x1.p-6,
    0x1.p0,
    -0x1.80p2
  },
  { // Entry 482
    0x1.p-5,
    0x1.p0,
    -0x1.40p2
  },
  { // Entry 483
    0x1.p-4,
    0x1.p0,
    -0x1.p2
  },
  { // Entry 484
    0x1.p-3,
    0x1.p0,
    -0x1.80p1
  },
  { // Entry 485
    0x1.p-2,
    0x1.p0,
    -0x1.p1
  },
  { // Entry 486
    0x1.p-1,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 487
    0x1.p0,
    0x1.p0,
    0.0
  },
  { // Entry 488
    0x1.p1,
    0x1.p0,
    0x1.p0
  },
  { // Entry 489
    0x1.p2,
    0x1.p0,
    0x1.p1
  },
  { // Entry 490
    0x1.p3,
    0x1.p0,
    0x1.80p1
  },
  { // Entry 491
    0x1.p4,
    0x1.p0,
    0x1.p2
  },
  { // Entry 492
    0x1.p5,
    0x1.p0,
    0x1.40p2
  },
  { // Entry 493
    0x1.p6,
    0x1.p0,
    0x1.80p2
  },
  { // Entry 494
    0x1.p7,
    0x1.p0,
    0x1.c0p2
  },
  { // Entry 495
    0x1.p8,
    0x1.p0,
    0x1.p3
  },
  { // Entry 496
    0x1.p9,
    0x1.p0,
    0x1.20p3
  },
  { // Entry 497
    0x1.p10,
    0x1.p0,
    0x1.40p3
  },
  { // Entry 498
    0x1.fffffep0,
    0x1.fffffep127,
    -0x1.fcp6
  },
  { // Entry 499
    0x1.fffffep1,
    0x1.fffffep127,
    -0x1.f8p6
  },
  { // Entry 500
    0x1.fffffep117,
    0x1.fffffep127,
    -0x1.40p3
  },
  { // Entry 501
    0x1.fffffep118,
    0x1.fffffep127,
    -0x1.20p3
  },
  { // Entry 502
    0x1.fffffep119,
    0x1.fffffep127,
    -0x1.p3
  },
  { // Entry 503
    0x1.fffffep120,
    0x1.fffffep127,
    -0x1.c0p2
  },
  { // Entry 504
    0x1.fffffep121,
    0x1.fffffep127,
    -0x1.80p2
  },
  { // Entry 505
    0x1.fffffep122,
    0x1.fffffep127,
    -0x1.40p2
  },
  { // Entry 506
    0x1.fffffep123,
    0x1.fffffep127,
    -0x1.p2
  },
  { // Entry 507
    0x1.fffffep124,
    0x1.fffffep127,
    -0x1.80p1
  },
  { // Entry 508
    0x1.fffffep125,
    0x1.fffffep127,
    -0x1.p1
  },
  { // Entry 509
    0x1.fffffep126,
    0x1.fffffep127,
    -0x1.p0
  },
  { // Entry 510
    0x1.fffffep127,
    0x1.fffffep127,
    0.0
  },
  { // Entry 511
    0x1.p-22,
    0x1.p-149,
    0x1.fcp6
  },
  { // Entry 512
    0x1.p-23,
    0x1.p-149,
    0x1.f8p6
  },
  { // Entry 513
    0x1.p-149,
    0x1.p-149,
    0.0
  },
  { // Entry 514
    0x1.p-148,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 515
    0x1.p-147,
    0x1.p-149,
    0x1.p1
  },
  { // Entry 516
    0x1.p-146,
    0x1.p-149,
    0x1.80p1
  },
  { // Entry 517
    0x1.p-145,
    0x1.p-149,
    0x1.p2
  },
  { // Entry 518
    0x1.p-144,
    0x1.p-149,
    0x1.40p2
  },
  { // Entry 519
    0x1.p-143,
    0x1.p-149,
    0x1.80p2
  },
  { // Entry 520
    0x1.p-142,
    0x1.p-149,
    0x1.c0p2
  },
  { // Entry 521
    0x1.p-141,
    0x1.p-149,
    0x1.p3
  },
  { // Entry 522
    0x1.p-140,
    0x1.p-149,
    0x1.20p3
  },
  { // Entry 523
    0x1.p-139,
    0x1.p-149,
    0x1.40p3
  },
  { // Entry 524
    0x1.p-129,
    0x1.p-2,
    -0x1.fcp6
  },
  { // Entry 525
    0x1.p-128,
    0x1.p-2,
    -0x1.f8p6
  },
  { // Entry 526
    0x1.p-128,
    0x1.p-1,
    -0x1.fcp6
  },
  { // Entry 527
    0x1.p-127,
    0x1.p-1,
    -0x1.f8p6
  },
  { // Entry 528
    0x1.80p-128,
    0x1.80p-1,
    -0x1.fcp6
  },
  { // Entry 529
    0x1.80p-127,
    0x1.80p-1,
    -0x1.f8p6
  },
  { // Entry 530
    0.0f,
    0x1.p-2,
    -0x1.2ap7
  },
  { // Entry 531
    0.0f,
    0x1.p-2,
    -0x1.28p7
  },
  { // Entry 532
    0.0f,
    0x1.p-1,
    -0x1.2ap7
  },
  { // Entry 533
    0x1.p-149,
    0x1.p-1,
    -0x1.28p7
  },
  { // Entry 534
    0.0f,
    0x1.80p-1,
    -0x1.2ap7
  },
  { // Entry 535
    0x1.80p-149,
    0x1.80p-1,
    -0x1.28p7
  },
  { // Entry 536
    0x1.p127,
    0x1.p0,
    0x1.fcp6
  },
  { // Entry 537
    0x1.p126,
    0x1.p0,
    0x1.f8p6
  },
  { // Entry 538
    0x1.p-149,
    0x1.p-149,
    0.0
  },
  { // Entry 539
    0x1.p-148,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 540
    0x1.p-147,
    0x1.p-149,
    0x1.p1
  },
  { // Entry 541
    0x1.p-146,
    0x1.p-149,
    0x1.80p1
  },
  { // Entry 542
    0x1.p-145,
    0x1.p-149,
    0x1.p2
  },
  { // Entry 543
    0x1.p-144,
    0x1.p-149,
    0x1.40p2
  },
  { // Entry 544
    0x1.p-143,
    0x1.p-149,
    0x1.80p2
  },
  { // Entry 545
    0x1.p-142,
    0x1.p-149,
    0x1.c0p2
  },
  { // Entry 546
    0x1.p-141,
    0x1.p-149,
    0x1.p3
  },
  { // Entry 547
    0x1.p-140,
    0x1.p-149,
    0x1.20p3
  },
  { // Entry 548
    0x1.p-139,
    0x1.p-149,
    0x1.40p3
  },
  { // Entry 549
    0x1.p-138,
    0x1.p-149,
    0x1.60p3
  },
  { // Entry 550
    0x1.p-137,
    0x1.p-149,
    0x1.80p3
  },
  { // Entry 551
    0x1.p-136,
    0x1.p-149,
    0x1.a0p3
  },
  { // Entry 552
    0x1.p-135,
    0x1.p-149,
    0x1.c0p3
  },
  { // Entry 553
    0x1.p-134,
    0x1.p-149,
    0x1.e0p3
  },
  { // Entry 554
    0x1.p-133,
    0x1.p-149,
    0x1.p4
  },
  { // Entry 555
    0x1.p-132,
    0x1.p-149,
    0x1.10p4
  },
  { // Entry 556
    0x1.p-131,
    0x1.p-149,
    0x1.20p4
  },
  { // Entry 557
    0x1.p-130,
    0x1.p-149,
    0x1.30p4
  },
  { // Entry 558
    0x1.p-129,
    0x1.p-149,
    0x1.40p4
  },
  { // Entry 559
    0x1.p-128,
    0x1.p-149,
    0x1.50p4
  },
  { // Entry 560
    0x1.p-127,
    0x1.p-149,
    0x1.60p4
  },
  { // Entry 561
    0x1.p-126,
    0x1.p-149,
    0x1.70p4
  },
  { // Entry 562
    0x1.p-125,
    0x1.p-149,
    0x1.80p4
  },
  { // Entry 563
    0x1.p-124,
    0x1.p-149,
    0x1.90p4
  },
  { // Entry 564
    0x1.p-123,
    0x1.p-149,
    0x1.a0p4
  },
  { // Entry 565
    0x1.p-122,
    0x1.p-149,
    0x1.b0p4
  },
  { // Entry 566
    0x1.p-121,
    0x1.p-149,
    0x1.c0p4
  },
  { // Entry 567
    0x1.p-120,
    0x1.p-149,
    0x1.d0p4
  },
  { // Entry 568
    0x1.p-119,
    0x1.p-149,
    0x1.e0p4
  },
  { // Entry 569
    0x1.p-118,
    0x1.p-149,
    0x1.f0p4
  },
  { // Entry 570
    0x1.p-117,
    0x1.p-149,
    0x1.p5
  },
  { // Entry 571
    0x1.p-116,
    0x1.p-149,
    0x1.08p5
  },
  { // Entry 572
    0x1.p-115,
    0x1.p-149,
    0x1.10p5
  },
  { // Entry 573
    0x1.p-114,
    0x1.p-149,
    0x1.18p5
  },
  { // Entry 574
    0x1.p-113,
    0x1.p-149,
    0x1.20p5
  },
  { // Entry 575
    0x1.p-112,
    0x1.p-149,
    0x1.28p5
  },
  { // Entry 576
    0x1.p-111,
    0x1.p-149,
    0x1.30p5
  },
  { // Entry 577
    0x1.p-110,
    0x1.p-149,
    0x1.38p5
  },
  { // Entry 578
    0x1.p-109,
    0x1.p-149,
    0x1.40p5
  },
  { // Entry 579
    0x1.p-108,
    0x1.p-149,
    0x1.48p5
  },
  { // Entry 580
    0x1.p-107,
    0x1.p-149,
    0x1.50p5
  },
  { // Entry 581
    0x1.p-106,
    0x1.p-149,
    0x1.58p5
  },
  { // Entry 582
    0x1.p-105,
    0x1.p-149,
    0x1.60p5
  },
  { // Entry 583
    0x1.p-104,
    0x1.p-149,
    0x1.68p5
  },
  { // Entry 584
    0x1.p-103,
    0x1.p-149,
    0x1.70p5
  },
  { // Entry 585
    0x1.p-102,
    0x1.p-149,
    0x1.78p5
  },
  { // Entry 586
    0x1.p-101,
    0x1.p-149,
    0x1.80p5
  },
  { // Entry 587
    0x1.p-100,
    0x1.p-149,
    0x1.88p5
  },
  { // Entry 588
    0x1.p-99,
    0x1.p-149,
    0x1.90p5
  },
  { // Entry 589
    0x1.p-98,
    0x1.p-149,
    0x1.98p5
  },
  { // Entry 590
    0x1.p-97,
    0x1.p-149,
    0x1.a0p5
  },
  { // Entry 591
    0x1.p-96,
    0x1.p-149,
    0x1.a8p5
  },
  { // Entry 592
    0x1.p-95,
    0x1.p-149,
    0x1.b0p5
  },
  { // Entry 593
    0x1.p-94,
    0x1.p-149,
    0x1.b8p5
  },
  { // Entry 594
    0x1.p-93,
    0x1.p-149,
    0x1.c0p5
  },
  { // Entry 595
    0x1.p-92,
    0x1.p-149,
    0x1.c8p5
  },
  { // Entry 596
    0x1.p-91,
    0x1.p-149,
    0x1.d0p5
  },
  { // Entry 597
    0x1.p-90,
    0x1.p-149,
    0x1.d8p5
  },
  { // Entry 598
    0x1.p-89,
    0x1.p-149,
    0x1.e0p5
  },
  { // Entry 599
    0x1.p-88,
    0x1.p-149,
    0x1.e8p5
  },
  { // Entry 600
    0x1.p-87,
    0x1.p-149,
    0x1.f0p5
  },
  { // Entry 601
    0x1.p-86,
    0x1.p-149,
    0x1.f8p5
  },
  { // Entry 602
    0x1.p-85,
    0x1.p-149,
    0x1.p6
  },
  { // Entry 603
    0x1.p-84,
    0x1.p-149,
    0x1.04p6
  },
  { // Entry 604
    0x1.p-83,
    0x1.p-149,
    0x1.08p6
  },
  { // Entry 605
    0x1.p-82,
    0x1.p-149,
    0x1.0cp6
  },
  { // Entry 606
    0x1.p-81,
    0x1.p-149,
    0x1.10p6
  },
  { // Entry 607
    0x1.p-80,
    0x1.p-149,
    0x1.14p6
  },
  { // Entry 608
    0x1.p-79,
    0x1.p-149,
    0x1.18p6
  },
  { // Entry 609
    0x1.p-78,
    0x1.p-149,
    0x1.1cp6
  },
  { // Entry 610
    0x1.p-77,
    0x1.p-149,
    0x1.20p6
  },
  { // Entry 611
    0x1.p-76,
    0x1.p-149,
    0x1.24p6
  },
  { // Entry 612
    0x1.p-75,
    0x1.p-149,
    0x1.28p6
  },
  { // Entry 613
    0x1.p-74,
    0x1.p-149,
    0x1.2cp6
  },
  { // Entry 614
    0x1.p-73,
    0x1.p-149,
    0x1.30p6
  },
  { // Entry 615
    0x1.p-72,
    0x1.p-149,
    0x1.34p6
  },
  { // Entry 616
    0x1.p-71,
    0x1.p-149,
    0x1.38p6
  },
  { // Entry 617
    0x1.p-70,
    0x1.p-149,
    0x1.3cp6
  },
  { // Entry 618
    0x1.p-69,
    0x1.p-149,
    0x1.40p6
  },
  { // Entry 619
    0x1.p-68,
    0x1.p-149,
    0x1.44p6
  },
  { // Entry 620
    0x1.p-67,
    0x1.p-149,
    0x1.48p6
  },
  { // Entry 621
    0x1.p-66,
    0x1.p-149,
    0x1.4cp6
  },
  { // Entry 622
    0x1.p-65,
    0x1.p-149,
    0x1.50p6
  },
  { // Entry 623
    0x1.p-64,
    0x1.p-149,
    0x1.54p6
  },
  { // Entry 624
    0x1.p-63,
    0x1.p-149,
    0x1.58p6
  },
  { // Entry 625
    0x1.p-62,
    0x1.p-149,
    0x1.5cp6
  },
  { // Entry 626
    0x1.p-61,
    0x1.p-149,
    0x1.60p6
  },
  { // Entry 627
    0x1.p-60,
    0x1.p-149,
    0x1.64p6
  },
  { // Entry 628
    0x1.p-59,
    0x1.p-149,
    0x1.68p6
  },
  { // Entry 629
    0x1.p-58,
    0x1.p-149,
    0x1.6cp6
  },
  { // Entry 630
    0x1.p-57,
    0x1.p-149,
    0x1.70p6
  },
  { // Entry 631
    0x1.p-56,
    0x1.p-149,
    0x1.74p6
  },
  { // Entry 632
    0x1.p-55,
    0x1.p-149,
    0x1.78p6
  },
  { // Entry 633
    0x1.p-54,
    0x1.p-149,
    0x1.7cp6
  },
  { // Entry 634
    0x1.p-53,
    0x1.p-149,
    0x1.80p6
  },
  { // Entry 635
    0x1.p-52,
    0x1.p-149,
    0x1.84p6
  },
  { // Entry 636
    0x1.p-51,
    0x1.p-149,
    0x1.88p6
  },
  { // Entry 637
    0x1.p-50,
    0x1.p-149,
    0x1.8cp6
  },
  { // Entry 638
    0x1.p-49,
    0x1.p-149,
    0x1.90p6
  },
  { // Entry 639
    0x1.p-48,
    0x1.p-149,
    0x1.94p6
  },
  { // Entry 640
    0x1.p-47,
    0x1.p-149,
    0x1.98p6
  },
  { // Entry 641
    0x1.p-46,
    0x1.p-149,
    0x1.9cp6
  },
  { // Entry 642
    0x1.p-45,
    0x1.p-149,
    0x1.a0p6
  },
  { // Entry 643
    0x1.p-44,
    0x1.p-149,
    0x1.a4p6
  },
  { // Entry 644
    0x1.p-43,
    0x1.p-149,
    0x1.a8p6
  },
  { // Entry 645
    0x1.p-42,
    0x1.p-149,
    0x1.acp6
  },
  { // Entry 646
    0x1.p-41,
    0x1.p-149,
    0x1.b0p6
  },
  { // Entry 647
    0x1.p-40,
    0x1.p-149,
    0x1.b4p6
  },
  { // Entry 648
    0x1.p-39,
    0x1.p-149,
    0x1.b8p6
  },
  { // Entry 649
    0x1.p-38,
    0x1.p-149,
    0x1.bcp6
  },
  { // Entry 650
    0x1.p-37,
    0x1.p-149,
    0x1.c0p6
  },
  { // Entry 651
    0x1.p-36,
    0x1.p-149,
    0x1.c4p6
  },
  { // Entry 652
    0x1.p-35,
    0x1.p-149,
    0x1.c8p6
  },
  { // Entry 653
    0x1.p-34,
    0x1.p-149,
    0x1.ccp6
  },
  { // Entry 654
    0x1.p-33,
    0x1.p-149,
    0x1.d0p6
  },
  { // Entry 655
    0x1.p-32,
    0x1.p-149,
    0x1.d4p6
  },
  { // Entry 656
    0x1.p-31,
    0x1.p-149,
    0x1.d8p6
  },
  { // Entry 657
    0x1.p-30,
    0x1.p-149,
    0x1.dcp6
  },
  { // Entry 658
    0x1.p-29,
    0x1.p-149,
    0x1.e0p6
  },
  { // Entry 659
    0x1.p-28,
    0x1.p-149,
    0x1.e4p6
  },
  { // Entry 660
    0x1.p-27,
    0x1.p-149,
    0x1.e8p6
  },
  { // Entry 661
    0x1.p-26,
    0x1.p-149,
    0x1.ecp6
  },
  { // Entry 662
    0x1.p-25,
    0x1.p-149,
    0x1.f0p6
  },
  { // Entry 663
    0x1.p-24,
    0x1.p-149,
    0x1.f4p6
  },
  { // Entry 664
    0x1.p-23,
    0x1.p-149,
    0x1.f8p6
  },
  { // Entry 665
    0x1.p-22,
    0x1.p-149,
    0x1.fcp6
  },
  { // Entry 666
    0x1.p-21,
    0x1.p-149,
    0x1.p7
  },
  { // Entry 667
    0x1.p-20,
    0x1.p-149,
    0x1.02p7
  },
  { // Entry 668
    0x1.p-19,
    0x1.p-149,
    0x1.04p7
  },
  { // Entry 669
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0
  },
  { // Entry 670
    0x1.fffffcp-126,
    0x1.fffffcp-127,
    0x1.p0
  },
  { // Entry 671
    0x1.fffffcp-125,
    0x1.fffffcp-127,
    0x1.p1
  },
  { // Entry 672
    0x1.fffffcp-124,
    0x1.fffffcp-127,
    0x1.80p1
  },
  { // Entry 673
    0x1.fffffcp-123,
    0x1.fffffcp-127,
    0x1.p2
  },
  { // Entry 674
    0x1.fffffcp-122,
    0x1.fffffcp-127,
    0x1.40p2
  },
  { // Entry 675
    0x1.fffffcp-121,
    0x1.fffffcp-127,
    0x1.80p2
  },
  { // Entry 676
    0x1.fffffcp-120,
    0x1.fffffcp-127,
    0x1.c0p2
  },
  { // Entry 677
    0x1.fffffcp-119,
    0x1.fffffcp-127,
    0x1.p3
  },
  { // Entry 678
    0x1.fffffcp-118,
    0x1.fffffcp-127,
    0x1.20p3
  },
  { // Entry 679
    0x1.fffffcp-117,
    0x1.fffffcp-127,
    0x1.40p3
  },
  { // Entry 680
    0x1.fffffcp-116,
    0x1.fffffcp-127,
    0x1.60p3
  },
  { // Entry 681
    0x1.fffffcp-115,
    0x1.fffffcp-127,
    0x1.80p3
  },
  { // Entry 682
    0x1.fffffcp-114,
    0x1.fffffcp-127,
    0x1.a0p3
  },
  { // Entry 683
    0x1.fffffcp-113,
    0x1.fffffcp-127,
    0x1.c0p3
  },
  { // Entry 684
    0x1.fffffcp-112,
    0x1.fffffcp-127,
    0x1.e0p3
  },
  { // Entry 685
    0x1.fffffcp-111,
    0x1.fffffcp-127,
    0x1.p4
  },
  { // Entry 686
    0x1.fffffcp-110,
    0x1.fffffcp-127,
    0x1.10p4
  },
  { // Entry 687
    0x1.fffffcp-109,
    0x1.fffffcp-127,
    0x1.20p4
  },
  { // Entry 688
    0x1.fffffcp-108,
    0x1.fffffcp-127,
    0x1.30p4
  },
  { // Entry 689
    0x1.fffffcp-107,
    0x1.fffffcp-127,
    0x1.40p4
  },
  { // Entry 690
    0x1.fffffcp-106,
    0x1.fffffcp-127,
    0x1.50p4
  },
  { // Entry 691
    0x1.fffffcp-105,
    0x1.fffffcp-127,
    0x1.60p4
  },
  { // Entry 692
    0x1.fffffcp-104,
    0x1.fffffcp-127,
    0x1.70p4
  },
  { // Entry 693
    0x1.fffffcp-103,
    0x1.fffffcp-127,
    0x1.80p4
  },
  { // Entry 694
    0x1.fffffcp-102,
    0x1.fffffcp-127,
    0x1.90p4
  },
  { // Entry 695
    0x1.fffffcp-101,
    0x1.fffffcp-127,
    0x1.a0p4
  },
  { // Entry 696
    0x1.fffffcp-100,
    0x1.fffffcp-127,
    0x1.b0p4
  },
  { // Entry 697
    0x1.fffffcp-99,
    0x1.fffffcp-127,
    0x1.c0p4
  },
  { // Entry 698
    0x1.fffffcp-98,
    0x1.fffffcp-127,
    0x1.d0p4
  },
  { // Entry 699
    0x1.fffffcp-97,
    0x1.fffffcp-127,
    0x1.e0p4
  },
  { // Entry 700
    0x1.fffffcp-96,
    0x1.fffffcp-127,
    0x1.f0p4
  },
  { // Entry 701
    0x1.fffffcp-95,
    0x1.fffffcp-127,
    0x1.p5
  },
  { // Entry 702
    0x1.fffffcp-94,
    0x1.fffffcp-127,
    0x1.08p5
  },
  { // Entry 703
    0x1.fffffcp-93,
    0x1.fffffcp-127,
    0x1.10p5
  },
  { // Entry 704
    0x1.fffffcp-92,
    0x1.fffffcp-127,
    0x1.18p5
  },
  { // Entry 705
    0x1.fffffcp-91,
    0x1.fffffcp-127,
    0x1.20p5
  },
  { // Entry 706
    0x1.fffffcp-90,
    0x1.fffffcp-127,
    0x1.28p5
  },
  { // Entry 707
    0x1.fffffcp-89,
    0x1.fffffcp-127,
    0x1.30p5
  },
  { // Entry 708
    0x1.fffffcp-88,
    0x1.fffffcp-127,
    0x1.38p5
  },
  { // Entry 709
    0x1.fffffcp-87,
    0x1.fffffcp-127,
    0x1.40p5
  },
  { // Entry 710
    0x1.fffffcp-86,
    0x1.fffffcp-127,
    0x1.48p5
  },
  { // Entry 711
    0x1.fffffcp-85,
    0x1.fffffcp-127,
    0x1.50p5
  },
  { // Entry 712
    0x1.fffffcp-84,
    0x1.fffffcp-127,
    0x1.58p5
  },
  { // Entry 713
    0x1.fffffcp-83,
    0x1.fffffcp-127,
    0x1.60p5
  },
  { // Entry 714
    0x1.fffffcp-82,
    0x1.fffffcp-127,
    0x1.68p5
  },
  { // Entry 715
    0x1.fffffcp-81,
    0x1.fffffcp-127,
    0x1.70p5
  },
  { // Entry 716
    0x1.fffffcp-80,
    0x1.fffffcp-127,
    0x1.78p5
  },
  { // Entry 717
    0x1.fffffcp-79,
    0x1.fffffcp-127,
    0x1.80p5
  },
  { // Entry 718
    0x1.fffffcp-78,
    0x1.fffffcp-127,
    0x1.88p5
  },
  { // Entry 719
    0x1.fffffcp-77,
    0x1.fffffcp-127,
    0x1.90p5
  },
  { // Entry 720
    0x1.fffffcp-76,
    0x1.fffffcp-127,
    0x1.98p5
  },
  { // Entry 721
    0x1.fffffcp-75,
    0x1.fffffcp-127,
    0x1.a0p5
  },
  { // Entry 722
    0x1.fffffcp-74,
    0x1.fffffcp-127,
    0x1.a8p5
  },
  { // Entry 723
    0x1.fffffcp-73,
    0x1.fffffcp-127,
    0x1.b0p5
  },
  { // Entry 724
    0x1.fffffcp-72,
    0x1.fffffcp-127,
    0x1.b8p5
  },
  { // Entry 725
    0x1.fffffcp-71,
    0x1.fffffcp-127,
    0x1.c0p5
  },
  { // Entry 726
    0x1.fffffcp-70,
    0x1.fffffcp-127,
    0x1.c8p5
  },
  { // Entry 727
    0x1.fffffcp-69,
    0x1.fffffcp-127,
    0x1.d0p5
  },
  { // Entry 728
    0x1.fffffcp-68,
    0x1.fffffcp-127,
    0x1.d8p5
  },
  { // Entry 729
    0x1.fffffcp-67,
    0x1.fffffcp-127,
    0x1.e0p5
  },
  { // Entry 730
    0x1.fffffcp-66,
    0x1.fffffcp-127,
    0x1.e8p5
  },
  { // Entry 731
    0x1.fffffcp-65,
    0x1.fffffcp-127,
    0x1.f0p5
  },
  { // Entry 732
    0x1.fffffcp-64,
    0x1.fffffcp-127,
    0x1.f8p5
  },
  { // Entry 733
    0x1.fffffcp-63,
    0x1.fffffcp-127,
    0x1.p6
  },
  { // Entry 734
    0x1.fffffcp-62,
    0x1.fffffcp-127,
    0x1.04p6
  },
  { // Entry 735
    0x1.fffffcp-61,
    0x1.fffffcp-127,
    0x1.08p6
  },
  { // Entry 736
    0x1.fffffcp-60,
    0x1.fffffcp-127,
    0x1.0cp6
  },
  { // Entry 737
    0x1.fffffcp-59,
    0x1.fffffcp-127,
    0x1.10p6
  },
  { // Entry 738
    0x1.fffffcp-58,
    0x1.fffffcp-127,
    0x1.14p6
  },
  { // Entry 739
    0x1.fffffcp-57,
    0x1.fffffcp-127,
    0x1.18p6
  },
  { // Entry 740
    0x1.fffffcp-56,
    0x1.fffffcp-127,
    0x1.1cp6
  },
  { // Entry 741
    0x1.fffffcp-55,
    0x1.fffffcp-127,
    0x1.20p6
  },
  { // Entry 742
    0x1.fffffcp-54,
    0x1.fffffcp-127,
    0x1.24p6
  },
  { // Entry 743
    0x1.fffffcp-53,
    0x1.fffffcp-127,
    0x1.28p6
  },
  { // Entry 744
    0x1.fffffcp-52,
    0x1.fffffcp-127,
    0x1.2cp6
  },
  { // Entry 745
    0x1.fffffcp-51,
    0x1.fffffcp-127,
    0x1.30p6
  },
  { // Entry 746
    0x1.fffffcp-50,
    0x1.fffffcp-127,
    0x1.34p6
  },
  { // Entry 747
    0x1.fffffcp-49,
    0x1.fffffcp-127,
    0x1.38p6
  },
  { // Entry 748
    0x1.fffffcp-48,
    0x1.fffffcp-127,
    0x1.3cp6
  },
  { // Entry 749
    0x1.fffffcp-47,
    0x1.fffffcp-127,
    0x1.40p6
  },
  { // Entry 750
    0x1.fffffcp-46,
    0x1.fffffcp-127,
    0x1.44p6
  },
  { // Entry 751
    0x1.fffffcp-45,
    0x1.fffffcp-127,
    0x1.48p6
  },
  { // Entry 752
    0x1.fffffcp-44,
    0x1.fffffcp-127,
    0x1.4cp6
  },
  { // Entry 753
    0x1.fffffcp-43,
    0x1.fffffcp-127,
    0x1.50p6
  },
  { // Entry 754
    0x1.fffffcp-42,
    0x1.fffffcp-127,
    0x1.54p6
  },
  { // Entry 755
    0x1.fffffcp-41,
    0x1.fffffcp-127,
    0x1.58p6
  },
  { // Entry 756
    0x1.fffffcp-40,
    0x1.fffffcp-127,
    0x1.5cp6
  },
  { // Entry 757
    0x1.fffffcp-39,
    0x1.fffffcp-127,
    0x1.60p6
  },
  { // Entry 758
    0x1.fffffcp-38,
    0x1.fffffcp-127,
    0x1.64p6
  },
  { // Entry 759
    0x1.fffffcp-37,
    0x1.fffffcp-127,
    0x1.68p6
  },
  { // Entry 760
    0x1.fffffcp-36,
    0x1.fffffcp-127,
    0x1.6cp6
  },
  { // Entry 761
    0x1.fffffcp-35,
    0x1.fffffcp-127,
    0x1.70p6
  },
  { // Entry 762
    0x1.fffffcp-34,
    0x1.fffffcp-127,
    0x1.74p6
  },
  { // Entry 763
    0x1.fffffcp-33,
    0x1.fffffcp-127,
    0x1.78p6
  },
  { // Entry 764
    0x1.fffffcp-32,
    0x1.fffffcp-127,
    0x1.7cp6
  },
  { // Entry 765
    0x1.fffffcp-31,
    0x1.fffffcp-127,
    0x1.80p6
  },
  { // Entry 766
    0x1.fffffcp-30,
    0x1.fffffcp-127,
    0x1.84p6
  },
  { // Entry 767
    0x1.fffffcp-29,
    0x1.fffffcp-127,
    0x1.88p6
  },
  { // Entry 768
    0x1.fffffcp-28,
    0x1.fffffcp-127,
    0x1.8cp6
  },
  { // Entry 769
    0x1.fffffcp-27,
    0x1.fffffcp-127,
    0x1.90p6
  },
  { // Entry 770
    0x1.fffffcp-26,
    0x1.fffffcp-127,
    0x1.94p6
  },
  { // Entry 771
    0x1.fffffcp-25,
    0x1.fffffcp-127,
    0x1.98p6
  },
  { // Entry 772
    0x1.fffffcp-24,
    0x1.fffffcp-127,
    0x1.9cp6
  },
  { // Entry 773
    0x1.fffffcp-23,
    0x1.fffffcp-127,
    0x1.a0p6
  },
  { // Entry 774
    0x1.fffffcp-22,
    0x1.fffffcp-127,
    0x1.a4p6
  },
  { // Entry 775
    0x1.fffffcp-21,
    0x1.fffffcp-127,
    0x1.a8p6
  },
  { // Entry 776
    0x1.fffffcp-20,
    0x1.fffffcp-127,
    0x1.acp6
  },
  { // Entry 777
    0x1.fffffcp-19,
    0x1.fffffcp-127,
    0x1.b0p6
  },
  { // Entry 778
    0x1.fffffcp-18,
    0x1.fffffcp-127,
    0x1.b4p6
  },
  { // Entry 779
    0x1.fffffcp-17,
    0x1.fffffcp-127,
    0x1.b8p6
  },
  { // Entry 780
    0x1.fffffcp-16,
    0x1.fffffcp-127,
    0x1.bcp6
  },
  { // Entry 781
    0x1.fffffcp-15,
    0x1.fffffcp-127,
    0x1.c0p6
  },
  { // Entry 782
    0x1.fffffcp-14,
    0x1.fffffcp-127,
    0x1.c4p6
  },
  { // Entry 783
    0x1.fffffcp-13,
    0x1.fffffcp-127,
    0x1.c8p6
  },
  { // Entry 784
    0x1.fffffcp-12,
    0x1.fffffcp-127,
    0x1.ccp6
  },
  { // Entry 785
    0x1.fffffcp-11,
    0x1.fffffcp-127,
    0x1.d0p6
  },
  { // Entry 786
    0x1.fffffcp-10,
    0x1.fffffcp-127,
    0x1.d4p6
  },
  { // Entry 787
    0x1.fffffcp-9,
    0x1.fffffcp-127,
    0x1.d8p6
  },
  { // Entry 788
    0x1.fffffcp-8,
    0x1.fffffcp-127,
    0x1.dcp6
  },
  { // Entry 789
    0x1.fffffcp-7,
    0x1.fffffcp-127,
    0x1.e0p6
  },
  { // Entry 790
    0x1.fffffcp-6,
    0x1.fffffcp-127,
    0x1.e4p6
  },
  { // Entry 791
    0x1.fffffcp-5,
    0x1.fffffcp-127,
    0x1.e8p6
  },
  { // Entry 792
    0x1.fffffcp-4,
    0x1.fffffcp-127,
    0x1.ecp6
  },
  { // Entry 793
    0x1.fffffcp-3,
    0x1.fffffcp-127,
    0x1.f0p6
  },
  { // Entry 794
    0x1.fffffcp-2,
    0x1.fffffcp-127,
    0x1.f4p6
  },
  { // Entry 795
    0x1.fffffcp-1,
    0x1.fffffcp-127,
    0x1.f8p6
  },
  { // Entry 796
    0x1.fffffcp0,
    0x1.fffffcp-127,
    0x1.fcp6
  },
  { // Entry 797
    0x1.fffffcp1,
    0x1.fffffcp-127,
    0x1.p7
  },
  { // Entry 798
    0x1.fffffcp2,
    0x1.fffffcp-127,
    0x1.02p7
  },
  { // Entry 799
    0x1.fffffcp3,
    0x1.fffffcp-127,
    0x1.04p7
  },
  { // Entry 800
    0x1.p0,
    0x1.p-149,
    0x1.2ap7
  },
  { // Entry 801
    0x1.p-1,
    0x1.p-149,
    0x1.28p7
  },
  { // Entry 802
    0x1.fffffcp22,
    0x1.fffffcp-127,
    0x1.2ap7
  },
  { // Entry 803
    0x1.fffffcp21,
    0x1.fffffcp-127,
    0x1.28p7
  },
  { // Entry 804
    0x1.p-126,
    0x1.p-149,
    0x1.70p4
  },
  { // Entry 805
    0x1.p-127,
    0x1.p-149,
    0x1.60p4
  },
  { // Entry 806
    0x1.fffffcp-104,
    0x1.fffffcp-127,
    0x1.70p4
  },
  { // Entry 807
    0x1.fffffcp-105,
    0x1.fffffcp-127,
    0x1.60p4
  },
  { // Entry 808
    0x1.p-149,
    0x1.p-149,
    0.0
  },
  { // Entry 809
    0x1.p-148,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 810
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0
  },
  { // Entry 811
    0x1.fffffcp-126,
    0x1.fffffcp-127,
    0x1.p0
  },
  { // Entry 812
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 813
    HUGE_VALF,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 814
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 815
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 816
    HUGE_VALF,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 817
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 818
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 819
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 820
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 821
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 822
    -HUGE_VALF,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 823
    -HUGE_VALF,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 824
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 825
    0.0f,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 826
    0.0,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 827
    HUGE_VALF,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 828
    HUGE_VALF,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 829
    HUGE_VALF,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 830
    -HUGE_VALF,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 831
    -HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 832
    -HUGE_VALF,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 833
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 834
    0.0f,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 835
    0.0,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 836
    0.0f,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 837
    0.0,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 838
    0.0f,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 839
    0.0,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 840
    0.0,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 841
    -0.0,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 842
    -0.0f,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 843
    -0.0,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 844
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 845
    -0.0,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 846
    -0.0f,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 847
    -0.0,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 848
    -0.0f,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 849
    -0.0,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 850
    0.0,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 851
    -0.0,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 852
    0.0,
    0.0f,
    0.0f
  },
  { // Entry 853
    -0.0,
    -0.0f,
    0.0f
  },
  { // Entry 854
    0.0,
    0.0f,
    -0.0f
  },
  { // Entry 855
    -0.0,
    -0.0f,
    -0.0f
  },
  { // Entry 856
    0.0,
    0.0f,
    0x1.p0
  },
  { // Entry 857
    -0.0,
    -0.0f,
    0x1.p0
  },
  { // Entry 858
    0.0,
    0.0f,
    -0x1.p0
  },
  { // Entry 859
    -0.0,
    -0.0f,
    -0x1.p0
  },
  { // Entry 860
    0.0,
    0.0f,
    0x1.fcp6
  },
  { // Entry 861
    -0.0,
    -0.0f,
    0x1.fcp6
  },
  { // Entry 862
    0.0,
    0.0f,
    -0x1.fcp6
  },
  { // Entry 863
    -0.0,
    -0.0f,
    -0x1.fcp6
  },
  { // Entry 864
    0.0,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 865
    -0.0,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 866
    HUGE_VALF,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 867
    -HUGE_VALF,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 868
    HUGE_VALF,
    HUGE_VALF,
    0.0f
  },
  { // Entry 869
    -HUGE_VALF,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 870
    HUGE_VALF,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 871
    -HUGE_VALF,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 872
    HUGE_VALF,
    HUGE_VALF,
    0x1.p0
  },
  { // Entry 873
    -HUGE_VALF,
    -HUGE_VALF,
    0x1.p0
  },
  { // Entry 874
    HUGE_VALF,
    HUGE_VALF,
    -0x1.p0
  },
  { // Entry 875
    -HUGE_VALF,
    -HUGE_VALF,
    -0x1.p0
  },
  { // Entry 876
    HUGE_VALF,
    HUGE_VALF,
    0x1.fcp6
  },
  { // Entry 877
    -HUGE_VALF,
    -HUGE_VALF,
    0x1.fcp6
  },
  { // Entry 878
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fcp6
  },
  { // Entry 879
    -HUGE_VALF,
    -HUGE_VALF,
    -0x1.fcp6
  },
  { // Entry 880
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 881
    -HUGE_VALF,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 882
    0x1.fffffep127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 883
    0x1.fffffep127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 884
    0x1.p-126,
    0x1.p-126,
    0.0f
  },
  { // Entry 885
    0x1.p-126,
    0x1.p-126,
    -0.0f
  },
  { // Entry 886
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 887
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 888
    0x1.p-149,
    0x1.p-149,
    0.0f
  },
  { // Entry 889
    0x1.p-149,
    0x1.p-149,
    -0.0f
  },
  { // Entry 890
    -0x1.p-149,
    -0x1.p-149,
    0.0f
  },
  { // Entry 891
    -0x1.p-149,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 892
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 893
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 894
    -0x1.p-126,
    -0x1.p-126,
    0.0f
  },
  { // Entry 895
    -0x1.p-126,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 896
    -0x1.fffffep127,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 897
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 898
    HUGE_VALF,
    0x1.fffffep127,
    0x1.p0
  },
  { // Entry 899
    HUGE_VALF,
    0x1.fffffep127,
    0x1.fcp6
  },
  { // Entry 900
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.p0
  },
  { // Entry 901
    -HUGE_VALF,
    -0x1.fffffep127,
    0x1.fcp6
  },
  { // Entry 902
    HUGE_VALF,
    0x1.p-126,
    0x1.3880p15
  },
  { // Entry 903
    HUGE_VALF,
    0x1.p-149,
    0x1.3880p15
  },
  { // Entry 904
    -HUGE_VALF,
    -0x1.p-126,
    0x1.3880p15
  },
  { // Entry 905
    -HUGE_VALF,
    -0x1.p-149,
    0x1.3880p15
  },
  { // Entry 906
    0x1.p-127,
    0x1.p-126,
    -0x1.p0
  },
  { // Entry 907
    0x1.fffffcp-128,
    0x1.fffffcp-127,
    -0x1.p0
  },
  { // Entry 908
    0.0f,
    0x1.p-149,
    -0x1.p0
  },
  { // Entry 909
    -0.0f,
    -0x1.p-149,
    -0x1.p0
  },
  { // Entry 910
    -0x1.fffffcp-128,
    -0x1.fffffcp-127,
    -0x1.p0
  },
  { // Entry 911
    -0x1.p-127,
    -0x1.p-126,
    -0x1.p0
  },
  { // Entry 912
    0.0f,
    0x1.fffffep127,
    -0x1.3880p15
  },
  { // Entry 913
    -0.0f,
    -0x1.fffffep127,
    -0x1.3880p15
  }
};

"""


```
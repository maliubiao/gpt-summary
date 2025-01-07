Response:
The user wants a summary of the functionality of the provided code snippet, which is the second part of a larger file named `atan2f_intel_data.handroid`. This file is located in the Android bionic library's test directory.

Based on the filename and the content, it seems like this file contains test data for the `atan2f` function. Each entry in the data appears to be a structure containing three floating-point numbers. Likely these represent input values for `atan2f` and the expected output.

**Therefore, the main function of this code snippet is to provide test data for validating the implementation of the `atan2f` function in the Android bionic library.**

Here's a breakdown of the thought process:

1. **Identify the context:** The user explicitly states the file's location within the Android bionic library, specifically the `tests/math_data` directory. This immediately suggests the file is related to testing the math library.

2. **Analyze the filename:** The filename `atan2f_intel_data.handroid` strongly indicates the purpose of the data. `atan2f` is a well-known math function. `intel_data` might suggest it's specifically targeted for Intel architectures or uses data generated or verified on Intel systems. `.handroid` could be a suffix indicating Android-specific handling or formatting.

3. **Examine the data structure:** The content consists of multiple blocks enclosed in `{}`, with each block containing three comma-separated values. The values are represented in hexadecimal floating-point format (e.g., `0x1.p0`, `-0x1.fd5ba9aac2f6dc65912f313e7d111defp-4`). This structure strongly implies a set of test cases.

4. **Infer the purpose of the three values:**  The `atan2f` function takes two arguments (y, x). The most logical assumption is that the first two values in each block represent the input `y` and `x` for the `atan2f` function, and the third value represents the expected output.

5. **Formulate the summary:** Based on the above analysis, the primary function is to provide test data for `atan2f`. This data is used to ensure the correct implementation of the function in the Android bionic library.
这段代码片段是 `bionic/tests/math_data/atan2f_intel_data.handroid` 文件的一部分，它主要的功能是 **提供一组用于测试 `atan2f` 函数的浮点数测试数据**。

具体来说，这个代码片段定义了一个包含多个条目的数据结构，每个条目看起来像是包含三个浮点数：

* **第一个浮点数:**  很可能代表 `atan2f` 函数的第一个输入参数 (通常是 y)。
* **第二个浮点数:** 很可能代表 `atan2f` 函数的第二个输入参数 (通常是 x)。
* **第三个浮点数:** 很可能代表对于给定的输入，`atan2f` 函数的预期输出结果。

这些数据通常被测试框架用来验证 `atan2f` 函数在不同输入情况下的正确性。测试框架会使用这些输入调用 `atan2f` 函数，并将实际的计算结果与这里提供的预期结果进行比较，从而判断 `atan2f` 的实现是否符合预期。

**总结来说，这个代码片段的主要功能是：**

* **定义 `atan2f` 函数的测试用例：**  提供了一系列精心挑选的输入值和对应的预期输出值。
* **用于验证 `atan2f` 函数的正确性：** 这些数据被测试程序读取并用于驱动 `atan2f` 函数的测试。

在整个 `atan2f_intel_data.handroid` 文件中，很可能包含了各种各样的测试用例，涵盖了正常情况、边界情况、特殊值（例如正负零、无穷大、NaN）等，以确保 `atan2f` 函数的鲁棒性和精确性。

Prompt: 
```
这是目录为bionic/tests/math_data/atan2f_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
  0x1.p0,
    0x1.p3
  },
  { // Entry 316
    -0x1.fd5ba9aac2f6dc65912f313e7d111defp-4,
    -0x1.p0,
    0x1.p3
  },
  { // Entry 317
    0x1.7249faa996a216a33079d20319e727c3p0,
    0x1.p3,
    0x1.p0
  },
  { // Entry 318
    -0x1.7249faa996a216a33079d20319e727c3p0,
    -0x1.p3,
    0x1.p0
  },
  { // Entry 319
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p3,
    0x1.p3
  },
  { // Entry 320
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p3,
    0x1.p3
  },
  { // Entry 321
    0x1.ffffd5555bbbba9729ab7aac089473a3p-10,
    0x1.p0,
    0x1.p9
  },
  { // Entry 322
    -0x1.ffffd5555bbbba9729ab7aac089473a3p-10,
    -0x1.p0,
    0x1.p9
  },
  { // Entry 323
    0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    0x1.p0,
    0x1.p10
  },
  { // Entry 324
    -0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    -0x1.p0,
    0x1.p10
  },
  { // Entry 325
    0x1.fff555bbb729ab77cf18ac802beec090p-7,
    0x1.p3,
    0x1.p9
  },
  { // Entry 326
    -0x1.fff555bbb729ab77cf18ac802beec090p-7,
    -0x1.p3,
    0x1.p9
  },
  { // Entry 327
    0x1.fffd555bbba972d00c46a3f77cc15e8ep-8,
    0x1.p3,
    0x1.p10
  },
  { // Entry 328
    -0x1.fffd555bbba972d00c46a3f77cc15e8ep-8,
    -0x1.p3,
    0x1.p10
  },
  { // Entry 329
    0x1.ffffffffffffffffffffffffffffffffp-101,
    0x1.p0,
    0x1.p100
  },
  { // Entry 330
    -0x1.ffffffffffffffffffffffffffffffffp-101,
    -0x1.p0,
    0x1.p100
  },
  { // Entry 331
    0x1.ffffffffffffffffffffffffffffffffp-102,
    0x1.p0,
    0x1.p101
  },
  { // Entry 332
    -0x1.ffffffffffffffffffffffffffffffffp-102,
    -0x1.p0,
    0x1.p101
  },
  { // Entry 333
    0x1.ffffffffffffffffffffffffffffffffp-98,
    0x1.p3,
    0x1.p100
  },
  { // Entry 334
    -0x1.ffffffffffffffffffffffffffffffffp-98,
    -0x1.p3,
    0x1.p100
  },
  { // Entry 335
    0x1.ffffffffffffffffffffffffffffffffp-99,
    0x1.p3,
    0x1.p101
  },
  { // Entry 336
    -0x1.ffffffffffffffffffffffffffffffffp-99,
    -0x1.p3,
    0x1.p101
  },
  { // Entry 337
    0x1.919fb54eed7a957ae3c25a3856b61485p0,
    0x1.p9,
    0x1.p0
  },
  { // Entry 338
    -0x1.919fb54eed7a957ae3c25a3856b61485p0,
    -0x1.p9,
    0x1.p0
  },
  { // Entry 339
    0x1.8e1fca98cb63311299ee93be01605c21p0,
    0x1.p9,
    0x1.p3
  },
  { // Entry 340
    -0x1.8e1fca98cb63311299ee93be01605c21p0,
    -0x1.p9,
    0x1.p3
  },
  { // Entry 341
    0x1.91dfb5459826ccf212a796bd00187cb7p0,
    0x1.p10,
    0x1.p0
  },
  { // Entry 342
    -0x1.91dfb5459826ccf212a796bd00187cb7p0,
    -0x1.p10,
    0x1.p0
  },
  { // Entry 343
    0x1.901fb7eee715daf6b9807e730a3b7843p0,
    0x1.p10,
    0x1.p3
  },
  { // Entry 344
    -0x1.901fb7eee715daf6b9807e730a3b7843p0,
    -0x1.p10,
    0x1.p3
  },
  { // Entry 345
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p9,
    0x1.p9
  },
  { // Entry 346
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p9,
    0x1.p9
  },
  { // Entry 347
    0x1.dac670561bb4f68adfc88bd978751a06p-2,
    0x1.p9,
    0x1.p10
  },
  { // Entry 348
    -0x1.dac670561bb4f68adfc88bd978751a06p-2,
    -0x1.p9,
    0x1.p10
  },
  { // Entry 349
    0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    0x1.p10,
    0x1.p9
  },
  { // Entry 350
    -0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    -0x1.p10,
    0x1.p9
  },
  { // Entry 351
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p10,
    0x1.p10
  },
  { // Entry 352
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p10,
    0x1.p10
  },
  { // Entry 353
    0x1.ffffffffffffffffffffffffffffffffp-92,
    0x1.p9,
    0x1.p100
  },
  { // Entry 354
    -0x1.ffffffffffffffffffffffffffffffffp-92,
    -0x1.p9,
    0x1.p100
  },
  { // Entry 355
    0x1.ffffffffffffffffffffffffffffffffp-93,
    0x1.p9,
    0x1.p101
  },
  { // Entry 356
    -0x1.ffffffffffffffffffffffffffffffffp-93,
    -0x1.p9,
    0x1.p101
  },
  { // Entry 357
    0x1.ffffffffffffffffffffffffffffffffp-91,
    0x1.p10,
    0x1.p100
  },
  { // Entry 358
    -0x1.ffffffffffffffffffffffffffffffffp-91,
    -0x1.p10,
    0x1.p100
  },
  { // Entry 359
    0x1.ffffffffffffffffffffffffffffffffp-92,
    0x1.p10,
    0x1.p101
  },
  { // Entry 360
    -0x1.ffffffffffffffffffffffffffffffffp-92,
    -0x1.p10,
    0x1.p101
  },
  { // Entry 361
    0x1.921fb54442d18469898cc516f1b839a2p0,
    0x1.p100,
    0x1.p0
  },
  { // Entry 362
    -0x1.921fb54442d18469898cc516f1b839a2p0,
    -0x1.p100,
    0x1.p0
  },
  { // Entry 363
    0x1.921fb54442d18469898cc51681b839a2p0,
    0x1.p100,
    0x1.p3
  },
  { // Entry 364
    -0x1.921fb54442d18469898cc51681b839a2p0,
    -0x1.p100,
    0x1.p3
  },
  { // Entry 365
    0x1.921fb54442d18469898cc516f9b839a2p0,
    0x1.p101,
    0x1.p0
  },
  { // Entry 366
    -0x1.921fb54442d18469898cc516f9b839a2p0,
    -0x1.p101,
    0x1.p0
  },
  { // Entry 367
    0x1.921fb54442d18469898cc516c1b839a2p0,
    0x1.p101,
    0x1.p3
  },
  { // Entry 368
    -0x1.921fb54442d18469898cc516c1b839a2p0,
    -0x1.p101,
    0x1.p3
  },
  { // Entry 369
    0x1.921fb54442d18469898cc4f701b839a2p0,
    0x1.p100,
    0x1.p9
  },
  { // Entry 370
    -0x1.921fb54442d18469898cc4f701b839a2p0,
    -0x1.p100,
    0x1.p9
  },
  { // Entry 371
    0x1.921fb54442d18469898cc4d701b839a2p0,
    0x1.p100,
    0x1.p10
  },
  { // Entry 372
    -0x1.921fb54442d18469898cc4d701b839a2p0,
    -0x1.p100,
    0x1.p10
  },
  { // Entry 373
    0x1.921fb54442d18469898cc50701b839a2p0,
    0x1.p101,
    0x1.p9
  },
  { // Entry 374
    -0x1.921fb54442d18469898cc50701b839a2p0,
    -0x1.p101,
    0x1.p9
  },
  { // Entry 375
    0x1.921fb54442d18469898cc4f701b839a2p0,
    0x1.p101,
    0x1.p10
  },
  { // Entry 376
    -0x1.921fb54442d18469898cc4f701b839a2p0,
    -0x1.p101,
    0x1.p10
  },
  { // Entry 377
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p100,
    0x1.p100
  },
  { // Entry 378
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p100,
    0x1.p100
  },
  { // Entry 379
    0x1.dac670561bb4f68adfc88bd978751a06p-2,
    0x1.p100,
    0x1.p101
  },
  { // Entry 380
    -0x1.dac670561bb4f68adfc88bd978751a06p-2,
    -0x1.p100,
    0x1.p101
  },
  { // Entry 381
    0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    0x1.p101,
    0x1.p100
  },
  { // Entry 382
    -0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    -0x1.p101,
    0x1.p100
  },
  { // Entry 383
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p101,
    0x1.p101
  },
  { // Entry 384
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p101,
    0x1.p101
  },
  { // Entry 385
    -0.0f,
    -0x1.p-149,
    0x1.fffffep0
  },
  { // Entry 386
    0.0f,
    0x1.p-149,
    0x1.fffffep0
  },
  { // Entry 387
    -0.0f,
    -0x1.p-149,
    0x1.p1
  },
  { // Entry 388
    0.0f,
    0x1.p-149,
    0x1.p1
  },
  { // Entry 389
    -0.0f,
    -0x1.p-149,
    0x1.000002p1
  },
  { // Entry 390
    0.0f,
    0x1.p-149,
    0x1.000002p1
  },
  { // Entry 391
    0.0,
    0.0,
    0x1.fffffep0
  },
  { // Entry 392
    0.0,
    0.0,
    0x1.p1
  },
  { // Entry 393
    0.0,
    0.0,
    0x1.000002p1
  },
  { // Entry 394
    0.0f,
    0x1.p-149,
    0x1.fffffep0
  },
  { // Entry 395
    -0.0f,
    -0x1.p-149,
    0x1.fffffep0
  },
  { // Entry 396
    0.0f,
    0x1.p-149,
    0x1.p1
  },
  { // Entry 397
    -0.0f,
    -0x1.p-149,
    0x1.p1
  },
  { // Entry 398
    0.0f,
    0x1.p-149,
    0x1.000002p1
  },
  { // Entry 399
    -0.0f,
    -0x1.p-149,
    0x1.000002p1
  },
  { // Entry 400
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.fffffep-4,
    0x1.fffffep0
  },
  { // Entry 401
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.fffffep-4,
    0x1.fffffep0
  },
  { // Entry 402
    0x1.ff55b974cde098738e59c07aa48dd110p-5,
    0x1.fffffep-4,
    0x1.p1
  },
  { // Entry 403
    -0x1.ff55b974cde098738e59c07aa48dd110p-5,
    -0x1.fffffep-4,
    0x1.p1
  },
  { // Entry 404
    0x1.ff55b578c9f078a33719a85ef29e8a20p-5,
    0x1.fffffep-4,
    0x1.000002p1
  },
  { // Entry 405
    -0x1.ff55b578c9f078a33719a85ef29e8a20p-5,
    -0x1.fffffep-4,
    0x1.000002p1
  },
  { // Entry 406
    0x1.ff55bd70d1de9a7192507f037e5414bbp-5,
    0x1.p-3,
    0x1.fffffep0
  },
  { // Entry 407
    -0x1.ff55bd70d1de9a7192507f037e5414bbp-5,
    -0x1.p-3,
    0x1.fffffep0
  },
  { // Entry 408
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.p-3,
    0x1.p1
  },
  { // Entry 409
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.p-3,
    0x1.p1
  },
  { // Entry 410
    0x1.ff55b776cbea888962afd8276c01a25ep-5,
    0x1.p-3,
    0x1.000002p1
  },
  { // Entry 411
    -0x1.ff55b776cbea888962afd8276c01a25ep-5,
    -0x1.p-3,
    0x1.000002p1
  },
  { // Entry 412
    0x1.ff55c16cd5de8a91665b84abb95e0cc7p-5,
    0x1.000002p-3,
    0x1.fffffep0
  },
  { // Entry 413
    -0x1.ff55c16cd5de8a91665b84abb95e0cc7p-5,
    -0x1.000002p-3,
    0x1.fffffep0
  },
  { // Entry 414
    0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    0x1.000002p-3,
    0x1.p1
  },
  { // Entry 415
    -0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    -0x1.000002p-3,
    0x1.p1
  },
  { // Entry 416
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.000002p-3,
    0x1.000002p1
  },
  { // Entry 417
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.000002p-3,
    0x1.000002p1
  },
  { // Entry 418
    -0x1.ff55c16cd5de8a91665b84abb95e0cc7p-5,
    -0x1.000002p-3,
    0x1.fffffep0
  },
  { // Entry 419
    0x1.ff55c16cd5de8a91665b84abb95e0cc7p-5,
    0x1.000002p-3,
    0x1.fffffep0
  },
  { // Entry 420
    -0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    -0x1.000002p-3,
    0x1.p1
  },
  { // Entry 421
    0x1.ff55bf6ed3da98798265cc3f27c896c7p-5,
    0x1.000002p-3,
    0x1.p1
  },
  { // Entry 422
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.000002p-3,
    0x1.000002p1
  },
  { // Entry 423
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.000002p-3,
    0x1.000002p1
  },
  { // Entry 424
    -0x1.ff55bd70d1de9a7192507f037e5414bbp-5,
    -0x1.p-3,
    0x1.fffffep0
  },
  { // Entry 425
    0x1.ff55bd70d1de9a7192507f037e5414bbp-5,
    0x1.p-3,
    0x1.fffffep0
  },
  { // Entry 426
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.p-3,
    0x1.p1
  },
  { // Entry 427
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.p-3,
    0x1.p1
  },
  { // Entry 428
    -0x1.ff55b776cbea888962afd8276c01a25ep-5,
    -0x1.p-3,
    0x1.000002p1
  },
  { // Entry 429
    0x1.ff55b776cbea888962afd8276c01a25ep-5,
    0x1.p-3,
    0x1.000002p1
  },
  { // Entry 430
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.fffffep-4,
    0x1.fffffep0
  },
  { // Entry 431
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.fffffep-4,
    0x1.fffffep0
  },
  { // Entry 432
    -0x1.ff55b974cde098738e59c07aa48dd110p-5,
    -0x1.fffffep-4,
    0x1.p1
  },
  { // Entry 433
    0x1.ff55b974cde098738e59c07aa48dd110p-5,
    0x1.fffffep-4,
    0x1.p1
  },
  { // Entry 434
    -0x1.ff55b578c9f078a33719a85ef29e8a20p-5,
    -0x1.fffffep-4,
    0x1.000002p1
  },
  { // Entry 435
    0x1.ff55b578c9f078a33719a85ef29e8a20p-5,
    0x1.fffffep-4,
    0x1.000002p1
  },
  { // Entry 436
    0x1.a271f5940186465d406645186f3ff94ap-2,
    0x1.bb67acp-1,
    0x1.fffffep0
  },
  { // Entry 437
    -0x1.a271f5940186465d406645186f3ff94ap-2,
    -0x1.bb67acp-1,
    0x1.fffffep0
  },
  { // Entry 438
    0x1.a271f41e9cbda3a2694ca4df76dc4a86p-2,
    0x1.bb67acp-1,
    0x1.p1
  },
  { // Entry 439
    -0x1.a271f41e9cbda3a2694ca4df76dc4a86p-2,
    -0x1.bb67acp-1,
    0x1.p1
  },
  { // Entry 440
    0x1.a271f133d333bccb9aba4067b1d551a2p-2,
    0x1.bb67acp-1,
    0x1.000002p1
  },
  { // Entry 441
    -0x1.a271f133d333bccb9aba4067b1d551a2p-2,
    -0x1.bb67acp-1,
    0x1.000002p1
  },
  { // Entry 442
    0x1.a271f74329f3af14ab02f72e14627e3ep-2,
    0x1.bb67aep-1,
    0x1.fffffep0
  },
  { // Entry 443
    -0x1.a271f74329f3af14ab02f72e14627e3ep-2,
    -0x1.bb67aep-1,
    0x1.fffffep0
  },
  { // Entry 444
    0x1.a271f5cdc529e5591cbe01f0dff5d436p-2,
    0x1.bb67aep-1,
    0x1.p1
  },
  { // Entry 445
    -0x1.a271f5cdc529e5591cbe01f0dff5d436p-2,
    -0x1.bb67aep-1,
    0x1.p1
  },
  { // Entry 446
    0x1.a271f2e2fb9db080e2f78cbaa7ae76dap-2,
    0x1.bb67aep-1,
    0x1.000002p1
  },
  { // Entry 447
    -0x1.a271f2e2fb9db080e2f78cbaa7ae76dap-2,
    -0x1.bb67aep-1,
    0x1.000002p1
  },
  { // Entry 448
    0x1.a271f8f252607a942b743a29251f41b3p-2,
    0x1.bb67b0p-1,
    0x1.fffffep0
  },
  { // Entry 449
    -0x1.a271f8f252607a942b743a29251f41b3p-2,
    -0x1.bb67b0p-1,
    0x1.fffffep0
  },
  { // Entry 450
    0x1.a271f77ced9589d7e7784be8c59b289ep-2,
    0x1.bb67b0p-1,
    0x1.p1
  },
  { // Entry 451
    -0x1.a271f77ced9589d7e7784be8c59b289ep-2,
    -0x1.bb67b0p-1,
    0x1.p1
  },
  { // Entry 452
    0x1.a271f492240706fe45667de97ee1051bp-2,
    0x1.bb67b0p-1,
    0x1.000002p1
  },
  { // Entry 453
    -0x1.a271f492240706fe45667de97ee1051bp-2,
    -0x1.bb67b0p-1,
    0x1.000002p1
  },
  { // Entry 454
    -0x1.a271f8f252607a942b743a29251f41b3p-2,
    -0x1.bb67b0p-1,
    0x1.fffffep0
  },
  { // Entry 455
    0x1.a271f8f252607a942b743a29251f41b3p-2,
    0x1.bb67b0p-1,
    0x1.fffffep0
  },
  { // Entry 456
    -0x1.a271f77ced9589d7e7784be8c59b289ep-2,
    -0x1.bb67b0p-1,
    0x1.p1
  },
  { // Entry 457
    0x1.a271f77ced9589d7e7784be8c59b289ep-2,
    0x1.bb67b0p-1,
    0x1.p1
  },
  { // Entry 458
    -0x1.a271f492240706fe45667de97ee1051bp-2,
    -0x1.bb67b0p-1,
    0x1.000002p1
  },
  { // Entry 459
    0x1.a271f492240706fe45667de97ee1051bp-2,
    0x1.bb67b0p-1,
    0x1.000002p1
  },
  { // Entry 460
    -0x1.a271f74329f3af14ab02f72e14627e3ep-2,
    -0x1.bb67aep-1,
    0x1.fffffep0
  },
  { // Entry 461
    0x1.a271f74329f3af14ab02f72e14627e3ep-2,
    0x1.bb67aep-1,
    0x1.fffffep0
  },
  { // Entry 462
    -0x1.a271f5cdc529e5591cbe01f0dff5d436p-2,
    -0x1.bb67aep-1,
    0x1.p1
  },
  { // Entry 463
    0x1.a271f5cdc529e5591cbe01f0dff5d436p-2,
    0x1.bb67aep-1,
    0x1.p1
  },
  { // Entry 464
    -0x1.a271f2e2fb9db080e2f78cbaa7ae76dap-2,
    -0x1.bb67aep-1,
    0x1.000002p1
  },
  { // Entry 465
    0x1.a271f2e2fb9db080e2f78cbaa7ae76dap-2,
    0x1.bb67aep-1,
    0x1.000002p1
  },
  { // Entry 466
    -0x1.a271f5940186465d406645186f3ff94ap-2,
    -0x1.bb67acp-1,
    0x1.fffffep0
  },
  { // Entry 467
    0x1.a271f5940186465d406645186f3ff94ap-2,
    0x1.bb67acp-1,
    0x1.fffffep0
  },
  { // Entry 468
    -0x1.a271f41e9cbda3a2694ca4df76dc4a86p-2,
    -0x1.bb67acp-1,
    0x1.p1
  },
  { // Entry 469
    0x1.a271f41e9cbda3a2694ca4df76dc4a86p-2,
    0x1.bb67acp-1,
    0x1.p1
  },
  { // Entry 470
    -0x1.a271f133d333bccb9aba4067b1d551a2p-2,
    -0x1.bb67acp-1,
    0x1.000002p1
  },
  { // Entry 471
    0x1.a271f133d333bccb9aba4067b1d551a2p-2,
    0x1.bb67acp-1,
    0x1.000002p1
  },
  { // Entry 472
    0x1.e1fc087d068cbfd25c64d0da9961de0dp-1,
    0x1.5f89e0p1,
    0x1.fffffep0
  },
  { // Entry 473
    -0x1.e1fc087d068cbfd25c64d0da9961de0dp-1,
    -0x1.5f89e0p1,
    0x1.fffffep0
  },
  { // Entry 474
    0x1.e1fc078961a1b8d58eff0ef3573e5ebbp-1,
    0x1.5f89e0p1,
    0x1.p1
  },
  { // Entry 475
    -0x1.e1fc078961a1b8d58eff0ef3573e5ebbp-1,
    -0x1.5f89e0p1,
    0x1.p1
  },
  { // Entry 476
    0x1.e1fc05a217cda574231fab7ef56a802ep-1,
    0x1.5f89e0p1,
    0x1.000002p1
  },
  { // Entry 477
    -0x1.e1fc05a217cda574231fab7ef56a802ep-1,
    -0x1.5f89e0p1,
    0x1.000002p1
  },
  { // Entry 478
    0x1.e1fc09dfe1de87be63d2efa76aedeef1p-1,
    0x1.5f89e2p1,
    0x1.fffffep0
  },
  { // Entry 479
    -0x1.e1fc09dfe1de87be63d2efa76aedeef1p-1,
    -0x1.5f89e2p1,
    0x1.fffffep0
  },
  { // Entry 480
    0x1.e1fc08ec3cf3edab43c88895dc8bd149p-1,
    0x1.5f89e2p1,
    0x1.p1
  },
  { // Entry 481
    -0x1.e1fc08ec3cf3edab43c88895dc8bd149p-1,
    -0x1.5f89e2p1,
    0x1.p1
  },
  { // Entry 482
    0x1.e1fc0704f320b41d2df91c8fc7a785a6p-1,
    0x1.5f89e2p1,
    0x1.000002p1
  },
  { // Entry 483
    -0x1.e1fc0704f320b41d2df91c8fc7a785a6p-1,
    -0x1.5f89e2p1,
    0x1.000002p1
  },
  { // Entry 484
    0x1.e1fc0b42bd2dac34dc336ebe1a5dd639p-1,
    0x1.5f89e4p1,
    0x1.fffffep0
  },
  { // Entry 485
    -0x1.e1fc0b42bd2dac34dc336ebe1a5dd639p-1,
    -0x1.5f89e4p1,
    0x1.fffffep0
  },
  { // Entry 486
    0x1.e1fc0a4f18437f0b6a89382bec836a03p-1,
    0x1.5f89e4p1,
    0x1.p1
  },
  { // Entry 487
    -0x1.e1fc0a4f18437f0b6a89382bec836a03p-1,
    -0x1.5f89e4p1,
    0x1.p1
  },
  { // Entry 488
    0x1.e1fc0867ce711f50acd36ef1986a9ed3p-1,
    0x1.5f89e4p1,
    0x1.000002p1
  },
  { // Entry 489
    -0x1.e1fc0867ce711f50acd36ef1986a9ed3p-1,
    -0x1.5f89e4p1,
    0x1.000002p1
  },
  { // Entry 490
    -0x1.e1fc0b42bd2dac34dc336ebe1a5dd639p-1,
    -0x1.5f89e4p1,
    0x1.fffffep0
  },
  { // Entry 491
    0x1.e1fc0b42bd2dac34dc336ebe1a5dd639p-1,
    0x1.5f89e4p1,
    0x1.fffffep0
  },
  { // Entry 492
    -0x1.e1fc0a4f18437f0b6a89382bec836a03p-1,
    -0x1.5f89e4p1,
    0x1.p1
  },
  { // Entry 493
    0x1.e1fc0a4f18437f0b6a89382bec836a03p-1,
    0x1.5f89e4p1,
    0x1.p1
  },
  { // Entry 494
    -0x1.e1fc0867ce711f50acd36ef1986a9ed3p-1,
    -0x1.5f89e4p1,
    0x1.000002p1
  },
  { // Entry 495
    0x1.e1fc0867ce711f50acd36ef1986a9ed3p-1,
    0x1.5f89e4p1,
    0x1.000002p1
  },
  { // Entry 496
    -0x1.e1fc09dfe1de87be63d2efa76aedeef1p-1,
    -0x1.5f89e2p1,
    0x1.fffffep0
  },
  { // Entry 497
    0x1.e1fc09dfe1de87be63d2efa76aedeef1p-1,
    0x1.5f89e2p1,
    0x1.fffffep0
  },
  { // Entry 498
    -0x1.e1fc08ec3cf3edab43c88895dc8bd149p-1,
    -0x1.5f89e2p1,
    0x1.p1
  },
  { // Entry 499
    0x1.e1fc08ec3cf3edab43c88895dc8bd149p-1,
    0x1.5f89e2p1,
    0x1.p1
  },
  { // Entry 500
    -0x1.e1fc0704f320b41d2df91c8fc7a785a6p-1,
    -0x1.5f89e2p1,
    0x1.000002p1
  },
  { // Entry 501
    0x1.e1fc0704f320b41d2df91c8fc7a785a6p-1,
    0x1.5f89e2p1,
    0x1.000002p1
  },
  { // Entry 502
    -0x1.e1fc087d068cbfd25c64d0da9961de0dp-1,
    -0x1.5f89e0p1,
    0x1.fffffep0
  },
  { // Entry 503
    0x1.e1fc087d068cbfd25c64d0da9961de0dp-1,
    0x1.5f89e0p1,
    0x1.fffffep0
  },
  { // Entry 504
    -0x1.e1fc078961a1b8d58eff0ef3573e5ebbp-1,
    -0x1.5f89e0p1,
    0x1.p1
  },
  { // Entry 505
    0x1.e1fc078961a1b8d58eff0ef3573e5ebbp-1,
    0x1.5f89e0p1,
    0x1.p1
  },
  { // Entry 506
    -0x1.e1fc05a217cda574231fab7ef56a802ep-1,
    -0x1.5f89e0p1,
    0x1.000002p1
  },
  { // Entry 507
    0x1.e1fc05a217cda574231fab7ef56a802ep-1,
    0x1.5f89e0p1,
    0x1.000002p1
  },
  { // Entry 508
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.fffffep0,
    0x1.fffffep0
  },
  { // Entry 509
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.fffffep0,
    0x1.fffffep0
  },
  { // Entry 510
    0x1.921fb44442d1046989621a6c570d8f04p-1,
    0x1.fffffep0,
    0x1.p1
  },
  { // Entry 511
    -0x1.921fb44442d1046989621a6c570d8f04p-1,
    -0x1.fffffep0,
    0x1.p1
  },
  { // Entry 512
    0x1.921fb24442d304698b0cc51401b839c8p-1,
    0x1.fffffep0,
    0x1.000002p1
  },
  { // Entry 513
    -0x1.921fb24442d304698b0cc51401b839c8p-1,
    -0x1.fffffep0,
    0x1.000002p1
  },
  { // Entry 514
    0x1.921fb64442d2046989b76fc1ac62e440p-1,
    0x1.p1,
    0x1.fffffep0
  },
  { // Entry 515
    -0x1.921fb64442d2046989b76fc1ac62e440p-1,
    -0x1.p1,
    0x1.fffffep0
  },
  { // Entry 516
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p1,
    0x1.p1
  },
  { // Entry 517
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p1,
    0x1.p1
  },
  { // Entry 518
    0x1.921fb34442d3846988376fc1ac62e5e6p-1,
    0x1.p1,
    0x1.000002p1
  },
  { // Entry 519
    -0x1.921fb34442d3846988376fc1ac62e5e6p-1,
    -0x1.p1,
    0x1.000002p1
  },
  { // Entry 520
    0x1.921fb84442d00469880cc51a01b8397bp-1,
    0x1.000002p1,
    0x1.fffffep0
  },
  { // Entry 521
    -0x1.921fb84442d00469880cc51a01b8397bp-1,
    -0x1.000002p1,
    0x1.fffffep0
  },
  { // Entry 522
    0x1.921fb74442cf84698ae21a6c570d8d5ep-1,
    0x1.000002p1,
    0x1.p1
  },
  { // Entry 523
    -0x1.921fb74442cf84698ae21a6c570d8d5ep-1,
    -0x1.000002p1,
    0x1.p1
  },
  { // Entry 524
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.000002p1,
    0x1.000002p1
  },
  { // Entry 525
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.000002p1,
    0x1.000002p1
  },
  { // Entry 526
    0x1.ffffffd555555bbbbbba972972d00dp-14,
    0x1.fffffep-13,
    0x1.fffffep0
  },
  { // Entry 527
    -0x1.ffffffd555555bbbbbba972972d00dp-14,
    -0x1.fffffep-13,
    0x1.fffffep0
  },
  { // Entry 528
    0x1.fffffdd55555dbbbbb1a9729e57ab751p-14,
    0x1.fffffep-13,
    0x1.p1
  },
  { // Entry 529
    -0x1.fffffdd55555dbbbbb1a9729e57ab751p-14,
    -0x1.fffffep-13,
    0x1.p1
  },
  { // Entry 530
    0x1.fffff9d55562dbbb9bda97790acf3db2p-14,
    0x1.fffffep-13,
    0x1.000002p1
  },
  { // Entry 531
    -0x1.fffff9d55562dbbb9bda97790acf3db2p-14,
    -0x1.fffffep-13,
    0x1.000002p1
  },
  { // Entry 532
    0x1.000000eaaaab6dddde6d4b951012b14cp-13,
    0x1.p-12,
    0x1.fffffep0
  },
  { // Entry 533
    -0x1.000000eaaaab6dddde6d4b951012b14cp-13,
    -0x1.p-12,
    0x1.fffffep0
  },
  { // Entry 534
    0x1.ffffffd555555bbbbbba972972d00dp-14,
    0x1.p-12,
    0x1.p1
  },
  { // Entry 535
    -0x1.ffffffd555555bbbbbba972972d00dp-14,
    -0x1.p-12,
    0x1.p1
  },
  { // Entry 536
    0x1.fffffbd5555e5bbba77a97585824f2d2p-14,
    0x1.p-12,
    0x1.000002p1
  },
  { // Entry 537
    -0x1.fffffbd5555e5bbba77a97585824f2d2p-14,
    -0x1.p-12,
    0x1.000002p1
  },
  { // Entry 538
    0x1.000002eaaaacedddde0d4b917d68009bp-13,
    0x1.000002p-12,
    0x1.fffffep0
  },
  { // Entry 539
    -0x1.000002eaaaacedddde0d4b917d68009bp-13,
    -0x1.000002p-12,
    0x1.fffffep0
  },
  { // Entry 540
    0x1.000001eaaaaa2ddddcfd4b9486bd5ca7p-13,
    0x1.000002p-12,
    0x1.p1
  },
  { // Entry 541
    -0x1.000001eaaaaa2ddddcfd4b9486bd5ca7p-13,
    -0x1.000002p-12,
    0x1.p1
  },
  { // Entry 542
    0x1.ffffffd555555bbbbbba972972d00dp-14,
    0x1.000002p-12,
    0x1.000002p1
  },
  { // Entry 543
    -0x1.ffffffd555555bbbbbba972972d00dp-14,
    -0x1.000002p-12,
    0x1.000002p1
  },
  { // Entry 544
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 545
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 546
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.p-149,
    0.0
  },
  { // Entry 547
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.p-149,
    0.0
  },
  { // Entry 548
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 549
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 550
    0x1.921fb54442d18469898cc51701b839a2p1,
    0.0,
    -0x1.p-149
  },
  { // Entry 551
    0.0,
    0.0,
    0.0
  },
  { // Entry 552
    0.0,
    0.0,
    0x1.p-149
  },
  { // Entry 553
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 554
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 555
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.p-149,
    0.0
  },
  { // Entry 556
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.p-149,
    0.0
  },
  { // Entry 557
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 558
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 559
    -0.0f,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 560
    0.0f,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 561
    0.0,
    0.0,
    0x1.fffffep127
  },
  { // Entry 562
    0.0f,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 563
    -0.0f,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 564
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 565
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 566
    0x1.921fb54442d18469898cc51701b839a2p1,
    0.0,
    -0x1.fffffep127
  },
  { // Entry 567
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 568
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 569
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 570
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 571
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffep127,
    0.0
  },
  { // Entry 572
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffep127,
    0.0
  },
  { // Entry 573
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 574
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 575
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 576
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 577
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffep127,
    0.0
  },
  { // Entry 578
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffep127,
    0.0
  },
  { // Entry 579
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 580
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 581
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 582
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 583
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 584
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 585
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.fffffep0,
    0x1.fffffep56
  },
  { // Entry 586
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.fffffep0,
    0x1.fffffep56
  },
  { // Entry 587
    0x1.fffffdffffffffffffffffffffff5555p-57,
    0x1.fffffep0,
    0x1.p57
  },
  { // Entry 588
    -0x1.fffffdffffffffffffffffffffff5555p-57,
    -0x1.fffffep0,
    0x1.p57
  },
  { // Entry 589
    0x1.fffffa00000bffffe800002ffffef555p-57,
    0x1.fffffep0,
    0x1.000002p57
  },
  { // Entry 590
    -0x1.fffffa00000bffffe800002ffffef555p-57,
    -0x1.fffffep0,
    0x1.000002p57
  },
  { // Entry 591
    0x1.000001000001000001000000ffffabaap-56,
    0x1.p1,
    0x1.fffffep56
  },
  { // Entry 592
    -0x1.000001000001000001000000ffffabaap-56,
    -0x1.p1,
    0x1.fffffep56
  },
  { // Entry 593
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.p1,
    0x1.p57
  },
  { // Entry 594
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.p1,
    0x1.p57
  },
  { // Entry 595
    0x1.fffffc000007fffff000001fffff1555p-57,
    0x1.p1,
    0x1.000002p57
  },
  { // Entry 596
    -0x1.fffffc000007fffff000001fffff1555p-57,
    -0x1.p1,
    0x1.000002p57
  },
  { // Entry 597
    0x1.000003000003000003000002ffffadaap-56,
    0x1.000002p1,
    0x1.fffffep56
  },
  { // Entry 598
    -0x1.000003000003000003000002ffffadaap-56,
    -0x1.000002p1,
    0x1.fffffep56
  },
  { // Entry 599
    0x1.000001ffffffffffffffffffffffaaaap-56,
    0x1.000002p1,
    0x1.p57
  },
  { // Entry 600
    -0x1.000001ffffffffffffffffffffffaaaap-56,
    -0x1.000002p1,
    0x1.p57
  },
  { // Entry 601
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.000002p1,
    0x1.000002p57
  },
  { // Entry 602
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.000002p1,
    0x1.000002p57
  },
  { // Entry 603
    -0x1.000003000003000003000002ffffadaap-56,
    -0x1.000002p1,
    0x1.fffffep56
  },
  { // Entry 604
    0x1.000003000003000003000002ffffadaap-56,
    0x1.000002p1,
    0x1.fffffep56
  },
  { // Entry 605
    -0x1.000001ffffffffffffffffffffffaaaap-56,
    -0x1.000002p1,
    0x1.p57
  },
  { // Entry 606
    0x1.000001ffffffffffffffffffffffaaaap-56,
    0x1.000002p1,
    0x1.p57
  },
  { // Entry 607
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.000002p1,
    0x1.000002p57
  },
  { // Entry 608
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.000002p1,
    0x1.000002p57
  },
  { // Entry 609
    -0x1.000001000001000001000000ffffabaap-56,
    -0x1.p1,
    0x1.fffffep56
  },
  { // Entry 610
    0x1.000001000001000001000000ffffabaap-56,
    0x1.p1,
    0x1.fffffep56
  },
  { // Entry 611
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.p1,
    0x1.p57
  },
  { // Entry 612
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.p1,
    0x1.p57
  },
  { // Entry 613
    -0x1.fffffc000007fffff000001fffff1555p-57,
    -0x1.p1,
    0x1.000002p57
  },
  { // Entry 614
    0x1.fffffc000007fffff000001fffff1555p-57,
    0x1.p1,
    0x1.000002p57
  },
  { // Entry 615
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.fffffep0,
    0x1.fffffep56
  },
  { // Entry 616
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.fffffep0,
    0x1.fffffep56
  },
  { // Entry 617
    -0x1.fffffdffffffffffffffffffffff5555p-57,
    -0x1.fffffep0,
    0x1.p57
  },
  { // Entry 618
    0x1.fffffdffffffffffffffffffffff5555p-57,
    0x1.fffffep0,
    0x1.p57
  },
  { // Entry 619
    -0x1.fffffa00000bffffe800002ffffef555p-57,
    -0x1.fffffep0,
    0x1.000002p57
  },
  { // Entry 620
    0x1.fffffa00000bffffe800002ffffef555p-57,
    0x1.fffffep0,
    0x1.000002p57
  },
  { // Entry 621
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.fffffep1,
    0x1.fffffep31
  },
  { // Entry 622
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.fffffep1,
    0x1.fffffep31
  },
  { // Entry 623
    0x1.fffffdfffffffff555557555553555bbp-31,
    0x1.fffffep1,
    0x1.p32
  },
  { // Entry 624
    -0x1.fffffdfffffffff555557555553555bbp-31,
    -0x1.fffffep1,
    0x1.p32
  },
  { // Entry 625
    0x1.fffffa00000bfff53d55b5855374f5c2p-31,
    0x1.fffffep1,
    0x1.000002p32
  },
  { // Entry 626
    -0x1.fffffa00000bfff53d55b5855374f5c2p-31,
    -0x1.fffffep1,
    0x1.000002p32
  },
  { // Entry 627
    0x1.000001000000fffaabaa9aabaa8aabddp-30,
    0x1.p2,
    0x1.fffffep31
  },
  { // Entry 628
    -0x1.000001000000fffaabaa9aabaa8aabddp-30,
    -0x1.p2,
    0x1.fffffep31
  },
  { // Entry 629
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.p2,
    0x1.p32
  },
  { // Entry 630
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.p2,
    0x1.p32
  },
  { // Entry 631
    0x1.fffffc000007fff545559575545515bfp-31,
    0x1.p2,
    0x1.000002p32
  },
  { // Entry 632
    -0x1.fffffc000007fff545559575545515bfp-31,
    -0x1.p2,
    0x1.000002p32
  },
  { // Entry 633
    0x1.000003000002fffaadaa7aada9eaaddbp-30,
    0x1.000002p2,
    0x1.fffffep31
  },
  { // Entry 634
    -0x1.000003000002fffaadaa7aada9eaaddbp-30,
    -0x1.000002p2,
    0x1.fffffep31
  },
  { // Entry 635
    0x1.000001fffffffffaaaaa8aaaaa6aaaddp-30,
    0x1.000002p2,
    0x1.p32
  },
  { // Entry 636
    -0x1.000001fffffffffaaaaa8aaaaa6aaaddp-30,
    -0x1.000002p2,
    0x1.p32
  },
  { // Entry 637
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.000002p2,
    0x1.000002p32
  },
  { // Entry 638
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.000002p2,
    0x1.000002p32
  },
  { // Entry 639
    -0x1.000003000002fffaadaa7aada9eaaddbp-30,
    -0x1.000002p-2,
    0x1.fffffep27
  },
  { // Entry 640
    0x1.000003000002fffaadaa7aada9eaaddbp-30,
    0x1.000002p-2,
    0x1.fffffep27
  },
  { // Entry 641
    -0x1.000001fffffffffaaaaa8aaaaa6aaaddp-30,
    -0x1.000002p-2,
    0x1.p28
  },
  { // Entry 642
    0x1.000001fffffffffaaaaa8aaaaa6aaaddp-30,
    0x1.000002p-2,
    0x1.p28
  },
  { // Entry 643
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.000002p-2,
    0x1.000002p28
  },
  { // Entry 644
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.000002p-2,
    0x1.000002p28
  },
  { // Entry 645
    -0x1.000001000000fffaabaa9aabaa8aabddp-30,
    -0x1.p-2,
    0x1.fffffep27
  },
  { // Entry 646
    0x1.000001000000fffaabaa9aabaa8aabddp-30,
    0x1.p-2,
    0x1.fffffep27
  },
  { // Entry 647
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.p-2,
    0x1.p28
  },
  { // Entry 648
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.p-2,
    0x1.p28
  },
  { // Entry 649
    -0x1.fffffc000007fff545559575545515bfp-31,
    -0x1.p-2,
    0x1.000002p28
  },
  { // Entry 650
    0x1.fffffc000007fff545559575545515bfp-31,
    0x1.p-2,
    0x1.000002p28
  },
  { // Entry 651
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.fffffep-3,
    0x1.fffffep27
  },
  { // Entry 652
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.fffffep-3,
    0x1.fffffep27
  },
  { // Entry 653
    -0x1.fffffdfffffffff555557555553555bbp-31,
    -0x1.fffffep-3,
    0x1.p28
  },
  { // Entry 654
    0x1.fffffdfffffffff555557555553555bbp-31,
    0x1.fffffep-3,
    0x1.p28
  },
  { // Entry 655
    -0x1.fffffa00000bfff53d55b5855374f5c
"""


```
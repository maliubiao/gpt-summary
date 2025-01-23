Response:
The user wants a summary of the functionality of the provided code snippet. This is the second part of a four-part analysis. The code snippet contains a large array of floating-point number pairs. These numbers are represented in hexadecimal floating-point format. Given the file path `bionic/tests/math_data/atan_intel_data.handroid`, and the fact that bionic is Android's C library including the math library, the data likely represents input and expected output values for testing the `atan` function (arctangent).

**Summary of Functionality:**

The provided code snippet defines a data structure (likely an array of structs) containing pairs of floating-point numbers. Each pair seems to represent an input value for the `atan` function and its corresponding expected output value. This data is used for testing the accuracy of the `atan` implementation within Android's bionic library.
这是一个C代码片段，定义了一个包含浮点数对的数组。根据文件路径 `bionic/tests/math_data/atan_intel_data.handroid`，可以推断出这个数组用于测试 `atan` 函数的实现。

**功能归纳:**

这个代码片段定义了一个用于测试 `atan` (反正切) 函数实现的数据集。它包含一系列的输入值和预期的输出值，用于验证 `atan` 函数在不同输入下的计算精度。

**与前一部分的关系 (假设):**

第一部分可能包含了数组的声明和一些初始的数据。这第二部分继续填充数组的具体测试数据。
### 提示词
```
这是目录为bionic/tests/math_data/atan_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
e79823616d18922d06p-5,
    -0x1.6b33333333334p-5
  },
  { // Entry 357
    0x1.9c737d9b4d07092c295584951a1f5a71p-5,
    0x1.9cccccccccccep-5
  },
  { // Entry 358
    -0x1.9c737d9b4d07092c295584951a1f5a71p-5,
    -0x1.9cccccccccccep-5
  },
  { // Entry 359
    0x1.cde8ec5bb65f0e742405e56b5ae426e2p-5,
    0x1.ce66666666666p-5
  },
  { // Entry 360
    -0x1.cde8ec5bb65f0e742405e56b5ae426e2p-5,
    -0x1.ce66666666666p-5
  },
  { // Entry 361
    0x1.3359bce85d4c0edf062a316ac9a3b035p-1,
    0x1.5e7fc4369bdadp-1
  },
  { // Entry 362
    -0x1.3359bce85d4c0edf062a316ac9a3b035p-1,
    -0x1.5e7fc4369bdadp-1
  },
  { // Entry 363
    0x1.d5ca708561450bec8cd54cd06ef71588p-1,
    0x1.4e7fc4369bdadp0
  },
  { // Entry 364
    -0x1.d5ca708561450bec8cd54cd06ef71588p-1,
    -0x1.4e7fc4369bdadp0
  },
  { // Entry 365
    0x1.17ac441eeac2e0e131633d5dbda1192dp0,
    0x1.edbfa651e9c84p0
  },
  { // Entry 366
    -0x1.17ac441eeac2e0e131633d5dbda1192dp0,
    -0x1.edbfa651e9c84p0
  },
  { // Entry 367
    0x1.3279e85590bed5c0a7d465c70e9312dbp0,
    0x1.467fc4369bdadp1
  },
  { // Entry 368
    -0x1.3279e85590bed5c0a7d465c70e9312dbp0,
    -0x1.467fc4369bdadp1
  },
  { // Entry 369
    0x1.43f644a23f11312b0baeda6469939df1p0,
    0x1.961fb54442d18p1
  },
  { // Entry 370
    -0x1.43f644a23f11312b0baeda6469939df1p0,
    -0x1.961fb54442d18p1
  },
  { // Entry 371
    0x1.502a1d3da2b62cdafdfc8df896fb781ep0,
    0x1.e5bfa651e9c83p1
  },
  { // Entry 372
    -0x1.502a1d3da2b62cdafdfc8df896fb781ep0,
    -0x1.e5bfa651e9c83p1
  },
  { // Entry 373
    0x1.592066aa733e56535ef23487f1ba45abp0,
    0x1.1aafcbafc85f7p2
  },
  { // Entry 374
    -0x1.592066aa733e56535ef23487f1ba45abp0,
    -0x1.1aafcbafc85f7p2
  },
  { // Entry 375
    0x1.5ff8e2755165d95ef4dfa238b69035c3p0,
    0x1.427fc4369bdadp2
  },
  { // Entry 376
    -0x1.5ff8e2755165d95ef4dfa238b69035c3p0,
    -0x1.427fc4369bdadp2
  },
  { // Entry 377
    0x1.655d65485dc172ad1da5d376106987dep0,
    0x1.6a4fbcbd6f562p2
  },
  { // Entry 378
    -0x1.655d65485dc172ad1da5d376106987dep0,
    -0x1.6a4fbcbd6f562p2
  },
  { // Entry 379
    0x1.65711d6bfd5303b266e1f766916353c0p0,
    0x1.6af2eff0a2896p2
  },
  { // Entry 380
    -0x1.65711d6bfd5303b266e1f766916353c0p0,
    -0x1.6af2eff0a2896p2
  },
  { // Entry 381
    0x1.602a2aaa59041e73fe9cbe5018d9258bp0,
    0x1.43c62a9d02414p2
  },
  { // Entry 382
    -0x1.602a2aaa59041e73fe9cbe5018d9258bp0,
    -0x1.43c62a9d02414p2
  },
  { // Entry 383
    0x1.597f46e10aa0ef6e7b79babd52218e41p0,
    0x1.1c99654961f92p2
  },
  { // Entry 384
    -0x1.597f46e10aa0ef6e7b79babd52218e41p0,
    -0x1.1c99654961f92p2
  },
  { // Entry 385
    0x1.50d20254a2ff42dab732523958fa024cp0,
    0x1.ead93feb8361fp1
  },
  { // Entry 386
    -0x1.50d20254a2ff42dab732523958fa024cp0,
    -0x1.ead93feb8361fp1
  },
  { // Entry 387
    0x1.45190c030df0f68611f816a36d10b59ap0,
    0x1.9c7fb54442d1ap1
  },
  { // Entry 388
    -0x1.45190c030df0f68611f816a36d10b59ap0,
    -0x1.9c7fb54442d1ap1
  },
  { // Entry 389
    0x1.34794d6993e603dc236dc9700bc984e9p0,
    0x1.4e262a9d02415p1
  },
  { // Entry 390
    -0x1.34794d6993e603dc236dc9700bc984e9p0,
    -0x1.4e262a9d02415p1
  },
  { // Entry 391
    0x1.1b598910bd9bdfeeb608b6b41a96f287p0,
    0x1.ff993feb83620p0
  },
  { // Entry 392
    -0x1.1b598910bd9bdfeeb608b6b41a96f287p0,
    -0x1.ff993feb83620p0
  },
  { // Entry 393
    0x1.e44c9309197c4f98392215a424630bb4p-1,
    0x1.62e62a9d02416p0
  },
  { // Entry 394
    -0x1.e44c9309197c4f98392215a424630bb4p-1,
    -0x1.62e62a9d02416p0
  },
  { // Entry 395
    0x1.5150f1acfb0190aa9794ba0211b4eb4bp-1,
    0x1.8c662a9d02419p-1
  },
  { // Entry 396
    -0x1.5150f1acfb0190aa9794ba0211b4eb4bp-1,
    -0x1.8c662a9d02419p-1
  },
  { // Entry 397
    -0x1.073ea15c614e11668ba9fe75888fee13p0,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 398
    0x1.073ea15c614e11668ba9fe75888fee13p0,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 399
    -0x1.0215495ceb1806c15504264e9f1be222p0,
    -0x1.95ec8b9e03d54p0
  },
  { // Entry 400
    0x1.0215495ceb1806c15504264e9f1be222p0,
    0x1.95ec8b9e03d54p0
  },
  { // Entry 401
    -0x1.f923661b52647e658c1f9707f87d1606p-1,
    -0x1.832efa2a435a9p0
  },
  { // Entry 402
    0x1.f923661b52647e658c1f9707f87d1606p-1,
    0x1.832efa2a435a9p0
  },
  { // Entry 403
    -0x1.ed57806b9090def7310604bffed0093dp-1,
    -0x1.707168b682dfep0
  },
  { // Entry 404
    0x1.ed57806b9090def7310604bffed0093dp-1,
    0x1.707168b682dfep0
  },
  { // Entry 405
    -0x1.e0b524b578b4212100f5f78ecd69a1ddp-1,
    -0x1.5db3d742c2653p0
  },
  { // Entry 406
    0x1.e0b524b578b4212100f5f78ecd69a1ddp-1,
    0x1.5db3d742c2653p0
  },
  { // Entry 407
    -0x1.d3290701e8ac987ea5732b16701a05fcp-1,
    -0x1.4af645cf01ea8p0
  },
  { // Entry 408
    0x1.d3290701e8ac987ea5732b16701a05fcp-1,
    0x1.4af645cf01ea8p0
  },
  { // Entry 409
    -0x1.c49e488683ace4d5fd4683f7caab7e9fp-1,
    -0x1.3838b45b416fdp0
  },
  { // Entry 410
    0x1.c49e488683ace4d5fd4683f7caab7e9fp-1,
    0x1.3838b45b416fdp0
  },
  { // Entry 411
    -0x1.b4fe843e9e803b2349ffd384aab807f3p-1,
    -0x1.257b22e780f52p0
  },
  { // Entry 412
    0x1.b4fe843e9e803b2349ffd384aab807f3p-1,
    0x1.257b22e780f52p0
  },
  { // Entry 413
    -0x1.a431f39bc6f4fc2f533fb8b685f7fa56p-1,
    -0x1.12bd9173c07abp0
  },
  { // Entry 414
    0x1.a431f39bc6f4fc2f533fb8b685f7fa56p-1,
    0x1.12bd9173c07abp0
  },
  { // Entry 415
    -0x1.871278e2b0226c7be314f39e634cb866p-1,
    -0x1.ea5c3ed5b3850p-1
  },
  { // Entry 416
    0x1.871278e2b0226c7be314f39e634cb866p-1,
    0x1.ea5c3ed5b3850p-1
  },
  { // Entry 417
    -0x1.7b8b3be13fca614c858af0d2c2879b7ap-1,
    -0x1.d4b87dab670a0p-1
  },
  { // Entry 418
    0x1.7b8b3be13fca614c858af0d2c2879b7ap-1,
    0x1.d4b87dab670a0p-1
  },
  { // Entry 419
    -0x1.6f851ed60f1e0ce1ff2d5577433c5ab2p-1,
    -0x1.bf14bc811a8f0p-1
  },
  { // Entry 420
    0x1.6f851ed60f1e0ce1ff2d5577433c5ab2p-1,
    0x1.bf14bc811a8f0p-1
  },
  { // Entry 421
    -0x1.62fb644de198ccbb0b7e0d32484d4ec0p-1,
    -0x1.a970fb56ce140p-1
  },
  { // Entry 422
    0x1.62fb644de198ccbb0b7e0d32484d4ec0p-1,
    0x1.a970fb56ce140p-1
  },
  { // Entry 423
    -0x1.55e986b4afe0cfdcf0138634c7c95b2bp-1,
    -0x1.93cd3a2c81990p-1
  },
  { // Entry 424
    0x1.55e986b4afe0cfdcf0138634c7c95b2bp-1,
    0x1.93cd3a2c81990p-1
  },
  { // Entry 425
    -0x1.484b52126a2735deb224632c4c2e4042p-1,
    -0x1.7e297902351e0p-1
  },
  { // Entry 426
    0x1.484b52126a2735deb224632c4c2e4042p-1,
    0x1.7e297902351e0p-1
  },
  { // Entry 427
    -0x1.3a1d01c9f4b1e99685e3fe739fdcffdap-1,
    -0x1.6885b7d7e8a30p-1
  },
  { // Entry 428
    0x1.3a1d01c9f4b1e99685e3fe739fdcffdap-1,
    0x1.6885b7d7e8a30p-1
  },
  { // Entry 429
    -0x1.2b5b626353bb47148742f9c053cd45c3p-1,
    -0x1.52e1f6ad9c280p-1
  },
  { // Entry 430
    0x1.2b5b626353bb47148742f9c053cd45c3p-1,
    0x1.52e1f6ad9c280p-1
  },
  { // Entry 431
    -0x1.1c03f735e818163698043ffa524dd5f7p-1,
    -0x1.3d3e35834fad0p-1
  },
  { // Entry 432
    0x1.1c03f735e818163698043ffa524dd5f7p-1,
    0x1.3d3e35834fad0p-1
  },
  { // Entry 433
    -0x1.eab7b2edbe26eb1b5fb149357f51d6c9p-2,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 434
    0x1.eab7b2edbe26eb1b5fb149357f51d6c9p-2,
    0x1.0a0b02501c799p-1
  },
  { // Entry 435
    -0x1.bb12f34bbefd630026b351ba15c3d256p-2,
    -0x1.d8f7208e6b82cp-2
  },
  { // Entry 436
    0x1.bb12f34bbefd630026b351ba15c3d256p-2,
    0x1.d8f7208e6b82cp-2
  },
  { // Entry 437
    -0x1.894ae0cb0ee2f00789eee093998b4a9bp-2,
    -0x1.9dd83c7c9e126p-2
  },
  { // Entry 438
    0x1.894ae0cb0ee2f00789eee093998b4a9bp-2,
    0x1.9dd83c7c9e126p-2
  },
  { // Entry 439
    -0x1.5579fdc3a8f3f9cf3f863dc6aa9b7198p-2,
    -0x1.62b9586ad0a20p-2
  },
  { // Entry 440
    0x1.5579fdc3a8f3f9cf3f863dc6aa9b7198p-2,
    0x1.62b9586ad0a20p-2
  },
  { // Entry 441
    -0x1.1fc79cfbf4e7b55f4dc25f1890fecd53p-2,
    -0x1.279a74590331ap-2
  },
  { // Entry 442
    0x1.1fc79cfbf4e7b55f4dc25f1890fecd53p-2,
    0x1.279a74590331ap-2
  },
  { // Entry 443
    -0x1.d0d0f85f973cce547bb0dc0a38708bffp-3,
    -0x1.d8f7208e6b829p-3
  },
  { // Entry 444
    0x1.d0d0f85f973cce547bb0dc0a38708bffp-3,
    0x1.d8f7208e6b829p-3
  },
  { // Entry 445
    -0x1.5f3d415cb47fed760072dbaeb268ceefp-3,
    -0x1.62b9586ad0a1ep-3
  },
  { // Entry 446
    0x1.5f3d415cb47fed760072dbaeb268ceefp-3,
    0x1.62b9586ad0a1ep-3
  },
  { // Entry 447
    -0x1.d6e1431de5be5630dec33d31fb926cbfp-4,
    -0x1.d8f7208e6b826p-4
  },
  { // Entry 448
    0x1.d6e1431de5be5630dec33d31fb926cbfp-4,
    0x1.d8f7208e6b826p-4
  },
  { // Entry 449
    -0x1.d870dcfcfe7d4ce3742c7268f8f5e0e8p-5,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 450
    0x1.d870dcfcfe7d4ce3742c7268f8f5e0e8p-5,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 451
    0x1.d870dcfcfe7d4ce3742c7268f8f5e0e8p-5,
    0x1.d8f7208e6b82dp-5
  },
  { // Entry 452
    -0x1.d870dcfcfe7d4ce3742c7268f8f5e0e8p-5,
    -0x1.d8f7208e6b82dp-5
  },
  { // Entry 453
    0x1.d6e1431de5bec4b79b64ec5a67bbcc08p-4,
    0x1.d8f7208e6b82dp-4
  },
  { // Entry 454
    -0x1.d6e1431de5bec4b79b64ec5a67bbcc08p-4,
    -0x1.d8f7208e6b82dp-4
  },
  { // Entry 455
    0x1.5f3d415cb4802b98cc41263eda7f242ap-3,
    0x1.62b9586ad0a22p-3
  },
  { // Entry 456
    -0x1.5f3d415cb4802b98cc41263eda7f242ap-3,
    -0x1.62b9586ad0a22p-3
  },
  { // Entry 457
    0x1.d0d0f85f973d0b16e9de3a03bdc6808bp-3,
    0x1.d8f7208e6b82dp-3
  },
  { // Entry 458
    -0x1.d0d0f85f973d0b16e9de3a03bdc6808bp-3,
    -0x1.d8f7208e6b82dp-3
  },
  { // Entry 459
    0x1.1fc79cfbf4e7d2e9265fe8f12eda96cap-2,
    0x1.279a74590331cp-2
  },
  { // Entry 460
    -0x1.1fc79cfbf4e7d2e9265fe8f12eda96cap-2,
    -0x1.279a74590331cp-2
  },
  { // Entry 461
    0x1.5579fdc3a8f4166188aad00fcf71b510p-2,
    0x1.62b9586ad0a22p-2
  },
  { // Entry 462
    -0x1.5579fdc3a8f4166188aad00fcf71b510p-2,
    -0x1.62b9586ad0a22p-2
  },
  { // Entry 463
    0x1.894ae0cb0ee30b895f6381f3b133dc04p-2,
    0x1.9dd83c7c9e128p-2
  },
  { // Entry 464
    -0x1.894ae0cb0ee30b895f6381f3b133dc04p-2,
    -0x1.9dd83c7c9e128p-2
  },
  { // Entry 465
    0x1.bb12f34bbefd7d5fccadb160103a2001p-2,
    0x1.d8f7208e6b82ep-2
  },
  { // Entry 466
    -0x1.bb12f34bbefd7d5fccadb160103a2001p-2,
    -0x1.d8f7208e6b82ep-2
  },
  { // Entry 467
    0x1.eab7b2edbe26eb1b5fb149357f51d6c9p-2,
    0x1.0a0b02501c799p-1
  },
  { // Entry 468
    -0x1.eab7b2edbe26eb1b5fb149357f51d6c9p-2,
    -0x1.0a0b02501c799p-1
  },
  { // Entry 469
    0x1.1c03f735e817e7f7c907ff3c4e54650dp-1,
    0x1.3d3e35834faccp-1
  },
  { // Entry 470
    -0x1.1c03f735e817e7f7c907ff3c4e54650dp-1,
    -0x1.3d3e35834faccp-1
  },
  { // Entry 471
    0x1.2b5b626353bb1a939a57893481fc6efep-1,
    0x1.52e1f6ad9c27cp-1
  },
  { // Entry 472
    -0x1.2b5b626353bb1a939a57893481fc6efep-1,
    -0x1.52e1f6ad9c27cp-1
  },
  { // Entry 473
    0x1.3a1d01c9f4b1becd56338b2ff004552cp-1,
    0x1.6885b7d7e8a2cp-1
  },
  { // Entry 474
    -0x1.3a1d01c9f4b1becd56338b2ff004552cp-1,
    -0x1.6885b7d7e8a2cp-1
  },
  { // Entry 475
    0x1.484b52126a270cc4c2f0b9b8d5749c23p-1,
    0x1.7e297902351dcp-1
  },
  { // Entry 476
    -0x1.484b52126a270cc4c2f0b9b8d5749c23p-1,
    -0x1.7e297902351dcp-1
  },
  { // Entry 477
    0x1.55e986b4afe0a867e17b875f8892133ep-1,
    0x1.93cd3a2c8198cp-1
  },
  { // Entry 478
    -0x1.55e986b4afe0a867e17b875f8892133ep-1,
    -0x1.93cd3a2c8198cp-1
  },
  { // Entry 479
    0x1.62fb644de198a6df044c5f206ab189e5p-1,
    0x1.a970fb56ce13cp-1
  },
  { // Entry 480
    -0x1.62fb644de198a6df044c5f206ab189e5p-1,
    -0x1.a970fb56ce13cp-1
  },
  { // Entry 481
    0x1.6f851ed60f1de8920ad396732d80e630p-1,
    0x1.bf14bc811a8ecp-1
  },
  { // Entry 482
    -0x1.6f851ed60f1de8920ad396732d80e630p-1,
    -0x1.bf14bc811a8ecp-1
  },
  { // Entry 483
    0x1.7b8b3be13fca3e7ae61ece393dc20351p-1,
    0x1.d4b87dab6709cp-1
  },
  { // Entry 484
    -0x1.7b8b3be13fca3e7ae61ece393dc20351p-1,
    -0x1.d4b87dab6709cp-1
  },
  { // Entry 485
    0x1.871278e2b0224b1a57a7517aa6080561p-1,
    0x1.ea5c3ed5b384cp-1
  },
  { // Entry 486
    -0x1.871278e2b0224b1a57a7517aa6080561p-1,
    -0x1.ea5c3ed5b384cp-1
  },
  { // Entry 487
    0x1.a431f39bc6f4fc2f533fb8b685f7fa56p-1,
    0x1.12bd9173c07abp0
  },
  { // Entry 488
    -0x1.a431f39bc6f4fc2f533fb8b685f7fa56p-1,
    -0x1.12bd9173c07abp0
  },
  { // Entry 489
    0x1.b4fe843e9e8072727b4b8be7730dc9f5p-1,
    0x1.257b22e780f56p0
  },
  { // Entry 490
    -0x1.b4fe843e9e8072727b4b8be7730dc9f5p-1,
    -0x1.257b22e780f56p0
  },
  { // Entry 491
    0x1.c49e488683ad184b42699159db8963c3p-1,
    0x1.3838b45b41701p0
  },
  { // Entry 492
    -0x1.c49e488683ad184b42699159db8963c3p-1,
    -0x1.3838b45b41701p0
  },
  { // Entry 493
    0x1.d3290701e8acc868f20733059c0c608ep-1,
    0x1.4af645cf01eacp0
  },
  { // Entry 494
    -0x1.d3290701e8acc868f20733059c0c608ep-1,
    -0x1.4af645cf01eacp0
  },
  { // Entry 495
    0x1.e0b524b578b44dca424e286b8612b332p-1,
    0x1.5db3d742c2657p0
  },
  { // Entry 496
    -0x1.e0b524b578b44dca424e286b8612b332p-1,
    -0x1.5db3d742c2657p0
  },
  { // Entry 497
    0x1.ed57806b909108a3ff02c70a568bf594p-1,
    0x1.707168b682e02p0
  },
  { // Entry 498
    -0x1.ed57806b909108a3ff02c70a568bf594p-1,
    -0x1.707168b682e02p0
  },
  { // Entry 499
    0x1.f923661b5264a5551df6c3d4c279e2c6p-1,
    0x1.832efa2a435adp0
  },
  { // Entry 500
    -0x1.f923661b5264a5551df6c3d4c279e2c6p-1,
    -0x1.832efa2a435adp0
  },
  { // Entry 501
    0x1.0215495ceb1818f77c287b62995eeddbp0,
    0x1.95ec8b9e03d58p0
  },
  { // Entry 502
    -0x1.0215495ceb1818f77c287b62995eeddbp0,
    -0x1.95ec8b9e03d58p0
  },
  { // Entry 503
    0x1.073ea15c614e11668ba9fe75888fee13p0,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 504
    -0x1.073ea15c614e11668ba9fe75888fee13p0,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 505
    0x1.96c4c0ec290ebef92ab936700e7d3f1bp-1,
    0x1.04aff6d330942p0
  },
  { // Entry 506
    -0x1.96c4c0ec290ebef92ab936700e7d3f1bp-1,
    -0x1.04aff6d330942p0
  },
  { // Entry 507
    0x1.96c565a66992e578d5536359e24d1cffp-1,
    0x1.04b09e98dcdb4p0
  },
  { // Entry 508
    -0x1.96c565a66992e578d5536359e24d1cffp-1,
    -0x1.04b09e98dcdb4p0
  },
  { // Entry 509
    0x1.96c60a603e270ac6f5547fd0c1f8f8ecp-1,
    0x1.04b1465e89226p0
  },
  { // Entry 510
    -0x1.96c60a603e270ac6f5547fd0c1f8f8ecp-1,
    -0x1.04b1465e89226p0
  },
  { // Entry 511
    0x1.96c6af19a6cb76e043213a66372fc856p-1,
    0x1.04b1ee2435698p0
  },
  { // Entry 512
    -0x1.96c6af19a6cb76e043213a66372fc856p-1,
    -0x1.04b1ee2435698p0
  },
  { // Entry 513
    0x1.96c753d2a38071c172287dd0e901a28ep-1,
    0x1.04b295e9e1b0ap0
  },
  { // Entry 514
    -0x1.96c753d2a38071c172287dd0e901a28ep-1,
    -0x1.04b295e9e1b0ap0
  },
  { // Entry 515
    0x1.96c7f88b3446436730e2c7c9e49c64fap-1,
    0x1.04b33daf8df7cp0
  },
  { // Entry 516
    -0x1.96c7f88b3446436730e2c7c9e49c64fap-1,
    -0x1.04b33daf8df7cp0
  },
  { // Entry 517
    0x1.96c89d43591d33ce28d17fec2513bfcbp-1,
    0x1.04b3e5753a3eep0
  },
  { // Entry 518
    -0x1.96c89d43591d33ce28d17fec2513bfcbp-1,
    -0x1.04b3e5753a3eep0
  },
  { // Entry 519
    0x1.96c941fb12058af2fe7e4e965a300441p-1,
    0x1.04b48d3ae6860p0
  },
  { // Entry 520
    -0x1.96c941fb12058af2fe7e4e965a300441p-1,
    -0x1.04b48d3ae6860p0
  },
  { // Entry 521
    0x1.96c9e6b25eff61b237930a7d05a731ebp-1,
    0x1.04b5350092ccfp0
  },
  { // Entry 522
    -0x1.96c9e6b25eff61b237930a7d05a731ebp-1,
    -0x1.04b5350092ccfp0
  },
  { // Entry 523
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 524
    0.0,
    0x1.0p-1074
  },
  { // Entry 525
    -0.0,
    -0.0
  },
  { // Entry 526
    0.0,
    0x1.0p-1074
  },
  { // Entry 527
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 528
    0x1.0c152382d73648a8c8f9175719d84f03p-1,
    0x1.279a74590331bp-1
  },
  { // Entry 529
    -0x1.0c152382d73648a8c8f9175719d84f03p-1,
    -0x1.279a74590331bp-1
  },
  { // Entry 530
    0x1.0c152382d73654a8c8f917571a1aed4ap-1,
    0x1.279a74590331cp-1
  },
  { // Entry 531
    -0x1.0c152382d73654a8c8f917571a1aed4ap-1,
    -0x1.279a74590331cp-1
  },
  { // Entry 532
    0x1.0c152382d73660a8c8f917571a0a6821p-1,
    0x1.279a74590331dp-1
  },
  { // Entry 533
    -0x1.0c152382d73660a8c8f917571a0a6821p-1,
    -0x1.279a74590331dp-1
  },
  { // Entry 534
    0x1.0c152382d7365277925622b33812561ep0,
    0x1.bb67ae8584ca9p0
  },
  { // Entry 535
    -0x1.0c152382d7365277925622b33812561ep0,
    -0x1.bb67ae8584ca9p0
  },
  { // Entry 536
    0x1.0c152382d7365677925622b338471928p0,
    0x1.bb67ae8584caap0
  },
  { // Entry 537
    -0x1.0c152382d7365677925622b338471928p0,
    -0x1.bb67ae8584caap0
  },
  { // Entry 538
    0x1.0c152382d7365a77925622b338446f3cp0,
    0x1.bb67ae8584cabp0
  },
  { // Entry 539
    -0x1.0c152382d7365a77925622b338446f3cp0,
    -0x1.bb67ae8584cabp0
  },
  { // Entry 540
    0x1.a64eec3cc23fbdfe90b96189d12851b4p-2,
    0x1.bffffffffffffp-2
  },
  { // Entry 541
    -0x1.a64eec3cc23fbdfe90b96189d12851b4p-2,
    -0x1.bffffffffffffp-2
  },
  { // Entry 542
    0x1.a64eec3cc23fcb6c84f92bd2003ce26cp-2,
    0x1.cp-2
  },
  { // Entry 543
    -0x1.a64eec3cc23fcb6c84f92bd2003ce26cp-2,
    -0x1.cp-2
  },
  { // Entry 544
    0x1.a64eec3cc23fd8da7938f61a2f29ff73p-2,
    0x1.c000000000001p-2
  },
  { // Entry 545
    -0x1.a64eec3cc23fd8da7938f61a2f29ff73p-2,
    -0x1.c000000000001p-2
  },
  { // Entry 546
    0x1.345f01cce37ba96325eacdc6f7ceec8cp-1,
    0x1.5ffffffffffffp-1
  },
  { // Entry 547
    -0x1.345f01cce37ba96325eacdc6f7ceec8cp-1,
    -0x1.5ffffffffffffp-1
  },
  { // Entry 548
    0x1.345f01cce37bb440844df1c4409fe779p-1,
    0x1.6p-1
  },
  { // Entry 549
    -0x1.345f01cce37bb440844df1c4409fe779p-1,
    -0x1.6p-1
  },
  { // Entry 550
    0x1.345f01cce37bbf1de2b115c1891fbafap-1,
    0x1.6000000000001p-1
  },
  { // Entry 551
    -0x1.345f01cce37bbf1de2b115c1891fbafap-1,
    -0x1.6000000000001p-1
  },
  { // Entry 552
    0x1.bde70ed439fe5f73a215d6096c04b42bp-1,
    0x1.2ffffffffffffp0
  },
  { // Entry 553
    -0x1.bde70ed439fe5f73a215d6096c04b42bp-1,
    -0x1.2ffffffffffffp0
  },
  { // Entry 554
    0x1.bde70ed439fe6cba95391a7f421b3821p-1,
    0x1.3p0
  },
  { // Entry 555
    -0x1.bde70ed439fe6cba95391a7f421b3821p-1,
    -0x1.3p0
  },
  { // Entry 556
    0x1.bde70ed439fe7a01885c5ef51760662ap-1,
    0x1.3000000000001p0
  },
  { // Entry 557
    -0x1.bde70ed439fe7a01885c5ef51760662ap-1,
    -0x1.3000000000001p0
  },
  { // Entry 558
    0x1.2e75728833a53c7ab9de734b9eb4f397p0,
    0x1.37fffffffffffp1
  },
  { // Entry 559
    -0x1.2e75728833a53c7ab9de734b9eb4f397p0,
    -0x1.37fffffffffffp1
  },
  { // Entry 560
    0x1.2e75728833a54116e3ef7326bd9839p0,
    0x1.380p1
  },
  { // Entry 561
    -0x1.2e75728833a54116e3ef7326bd9839p0,
    -0x1.380p1
  },
  { // Entry 562
    0x1.2e75728833a545b30e007301dc13e399p0,
    0x1.3800000000001p1
  },
  { // Entry 563
    -0x1.2e75728833a545b30e007301dc13e399p0,
    -0x1.3800000000001p1
  },
  { // Entry 564
    0x1.0640a74d6105ee338c5bcc6c7348c123p-4,
    0x1.069c8b46b3792p-4
  },
  { // Entry 565
    -0x1.0640a74d6105ee338c5bcc6c7348c123p-4,
    -0x1.069c8b46b3792p-4
  },
  { // Entry 566
    0x1.052fab368e062e72fbf2d39fe9d18888p-3,
    0x1.069c8b46b3792p-3
  },
  { // Entry 567
    -0x1.052fab368e062e72fbf2d39fe9d18888p-3,
    -0x1.069c8b46b3792p-3
  },
  { // Entry 568
    0x1.852a21876f242e8b182abd42c41ee89dp-3,
    0x1.89ead0ea0d35bp-3
  },
  { // Entry 569
    -0x1.852a21876f242e8b182abd42c41ee89dp-3,
    -0x1.89ead0ea0d35bp-3
  },
  { // Entry 570
    0x1.01123bc10a64bf0ab62d6ef7f32651aap-2,
    0x1.069c8b46b3792p-2
  },
  { // Entry 571
    -0x1.01123bc10a64bf0ab62d6ef7f32651aap-2,
    -0x1.069c8b46b3792p-2
  },
  { // Entry 572
    0x1.3daa733ee5357808e68aee008972c828p-2,
    0x1.4843ae1860576p-2
  },
  { // Entry 573
    -0x1.3daa733ee5357808e68aee008972c828p-2,
    -0x1.4843ae1860576p-2
  },
  { // Entry 574
    0x1.780c45b9736a9089f2fe1f8efa60bf44p-2,
    0x1.89ead0ea0d35ap-2
  },
  { // Entry 575
    -0x1.780c45b9736a9089f2fe1f8efa60bf44p-2,
    -0x1.89ead0ea0d35ap-2
  },
  { // Entry 576
    0x1.affaac96d797029e0b8ab4083d980b68p-2,
    0x1.cb91f3bbba13ep-2
  },
  { // Entry 577
    -0x1.affaac96d797029e0b8ab4083d980b68p-2,
    -0x1.cb91f3bbba13ep-2
  },
  { // Entry 578
    0x1.e54c7f9dac6708f315d38c8a8c2ce4d3p-2,
    0x1.069c8b46b3791p-1
  },
  { // Entry 579
    -0x1.e54c7f9dac6708f315d38c8a8c2ce4d3p-2,
    -0x1.069c8b46b3791p-1
  },
  { // Entry 580
    0x1.0bf560a09b924073e473cb0d5c32501ep-1,
    0x1.27701caf89e83p-1
  },
  { // Entry 581
    -0x1.0bf560a09b924073e473cb0d5c32501ep-1,
    -0x1.27701caf89e83p-1
  },
  { // Entry 582
    0x1.23e717d0fa7b0b8bf45d2cd120f6d29ep-1,
    0x1.4843ae1860575p-1
  },
  { // Entry 583
    -0x1.23e717d0fa7b0b8bf45d2cd120f6d29ep-1,
    -0x1.4843ae1860575p-1
  },
  { // Entry 584
    0x1.3a7e3f4793afa9a24b0112ea83035c7ep-1,
    0x1.69173f8136c67p-1
  },
  { // Entry 585
    -0x1.3a7e3f4793afa9a24b0112ea83035c7ep-1,
    -0x1.69173f8136c67p-1
  },
  { // Entry 586
    0x1.4fc2c55f7154871c8daa35843857b7ffp-1,
    0x1.89ead0ea0d359p-1
  },
  { // Entry 587
    -0x1.4fc2c55f7154871c8daa35843857b7ffp-1,
    -0x1.89ead0ea0d359p-1
  },
  { // Entry 588
    0x1.63c05ef8a353c6d1360ead977c2adb94p-1,
    0x1.aabe6252e3a4bp-1
  },
  { // Entry 589
    -0x1.63c05ef8a353c6d1360ead977c2adb94p-1,
    -0x1.aabe6252e3a4bp-1
  },
  { // Entry 590
    0x1.7685624cb374ad8950ee302aee748ad9p-1,
    0x1.cb91f3bbba13dp-1
  },
  { // Entry 591
    -0x1.7685624cb374ad8950ee302aee748ad9p-1,
    -0x1.cb91f3bbba13dp-1
  },
  { // Entry 592
    0x1.8821d1878dcb0371d2ed00f8bad7755ep-1,
    0x1.ec6585249082fp-1
  },
  { // Entry 593
    -0x1.8821d1878dcb0371d2ed00f8bad7755ep-1,
    -0x1.ec6585249082fp-1
  },
  { // Entry 594
    0x1.98a69592999488465c8b6185dd58b38ap-1,
    0x1.069c8b46b3791p0
  },
  { // Entry 595
    -0x1.98a69592999488465c8b6185dd58b38ap-1,
    -0x1.069c8b46b3791p0
  },
  { // Entry 596
    0x1.a824e56beafb17efb9ed12695185cc5bp-1,
    0x1.170653fb1eb0ap0
  },
  { // Entry 597
    -0x1.a824e56beafb17efb9ed12695185cc5bp-1,
    -0x1.170653fb1eb0ap0
  },
  { // Entry 598
    0x1.b6add448714e627e74ee9ce6911993e6p-1,
    0x1.27701caf89e83p0
  },
  { // Entry 599
    -0x1.b6add448714e627e74ee9ce6911993e6p-1,
    -0x1.27701caf89e83p0
  },
  { // Entry 600
    0x1.c4520007344f8b36a1c610e27f4bb57ep-1,
    0x1.37d9e563f51fcp0
  },
  { // Entry 601
    -0x1.c4520007344f8b36a1c610e27f4bb57ep-1,
    -0x1.37d9e563f51fcp0
  },
  { // Entry 602
    0x1.d12159a144ff3c88e549b6c7fe977a6bp-1,
    0x1.4843ae1860575p0
  },
  { // Entry 603
    -0x1.d12159a144ff3c88e549b6c7fe977a6bp-1,
    -0x1.4843ae1860575p0
  },
  { // Entry 604
    0x1.dd2b01e17c4270caa5ead83118478c99p-1,
    0x1.58ad76cccb8eep0
  },
  { // Entry 605
    -0x1.dd2b01e17c4270caa5ead83118478c99p-1,
    -0x1.58ad76cccb8eep0
  },
  { // Entry 606
    0x1.e87d358361bd4751c472fe76608804f7p-1,
    0x1.69173f8136c67p0
  },
  { // Entry 607
    -0x1.e87d358361bd4751c472fe76608804f7p-1,
    -0x1.69173f8136c67p0
  },
  { // Entry 608
    0x1.f32544b66aa5dfd1d5c551c7b435f099p-1,
    0x1.79810835a1fe0p0
  },
  { // Entry 609
    -0x1.f32544b66aa5dfd1d5c551c7b435f099p-1,
    -0x1.79810835a1fe0p0
  },
  { // Entry 610
    0x1.fd2f92d1f51f1d323eacb60983a6f40dp-1,
    0x1.89ead0ea0d359p0
  },
  { // Entry 611
    -0x1.fd2f92d1f51f1d323eacb60983a6f40dp-1,
    -0x1.89ead0ea0d359p0
  },
  { // Entry 612
    0x1.0353cdddc16607e33b1f4c9d55ff1784p0,
    0x1.9a54999e786d2p0
  },
  { // Entry 613
    -0x1.0353cdddc16607e33b1f4c9d55ff1784p0,
    -0x1.9a54999e786d2p0
  },
  { // Entry 614
    0x1.07cbfe8c14dd9ae6823776b5a4d81ba9p0,
    0x1.aabe6252e3a4bp0
  },
  { // Entry 615
    -0x1.07cbfe8c14dd9ae6823776b5a4d81ba9p0,
    -0x1.aabe6252e3a4bp0
  },
  { // Entry 616
    0x1.0c0540ee6eff5cb8c83f0e7e225652c0p0,
    0x1.bb282b074edc4p0
  },
  { // Entry 617
    -0x1.0c0540ee6eff5cb8c83f0e7e225652c0p0,
    -0x1.bb282b074edc4p0
  },
  { // Entry 618
    0x1.1004179915f3bd7827be1c9d557de4b1p0,
    0x1.cb91f3bbba13dp0
  },
  { // Entry 619
    -0x1.1004179915f3bd7827be1c9d557de4b1p0,
    -0x1.cb91f3bbba13dp0
  },
  { // Entry 620
    0x1.13cca8f590cdd610776bb232694ba1c1p0,
    0x1.dbfbbc70254b6p0
  },
  { // Entry 621
    -0x1.13cca8f590cdd610776bb232694ba1c1p0,
    -0x1.dbfbbc70254b6p0
  },
  { // Entry 622
    0x1.1762c60438ce2cf59a91a21864529016p0,
    0x1.ec6585249082fp0
  },
  { // Entry 623
    -0x1.1762c60438ce2cf59a91a21864529016p0,
    -0x1.ec6585249082fp0
  },
  { // Entry 624
    0x1.1ac9f0f5f0ac59ef468d0e8c13eecc94p0,
    0x1.fccf4dd8fbba8p0
  },
  { // Entry 625
    -0x1.1ac9f0f5f0ac59ef468d0e8c13eecc94p0,
    -0x1.fccf4dd8fbba8p0
  },
  { // Entry 626
    0x1.1e05637ffc0a8a6d0a7e22324ebefacfp0,
    0x1.069c8b46b3791p1
  },
  { // Entry 627
    -0x1.1e05637ffc0a8a6d0a7e22324ebefacfp0,
    -0x1.069c8b46b3791p1
  },
  { // Entry 628
    0x1.211814d79540eebd6dda8be7ed197d84p0,
    0x1.0ed16fa0e914ep1
  },
  { // Entry 629
    -0x1.211814d79540eebd6dda8be7ed197d84p0,
    -0x1.0ed16fa0e914ep1
  },
  { // Entry 630
    0x1.2404bf4b3ead000faf892c3f4eb4bfa9p0,
    0x1.170653fb1eb0bp1
  },
  { // Entry 631
    -0x1.2404bf4b3ead000faf892c3f4eb4bfa9p0,
    -0x1.170653fb1eb0bp1
  },
  { // Entry 632
    0x1.26cde575b64162e9e462d564797a5dd7p0,
    0x1.1f3b3855544c8p1
  },
  { // Entry 633
    -0x1.26cde575b64162e9e462d564797a5dd7p0,
    -0x1.1f3b3855544c8p1
  },
  { // Entry 634
    0x1.2975d70a874ee2c0fbc4d32b9997edb4p0,
    0x1.27701caf89e85p1
  },
  { // Entry 635
    -0x1.2975d70a874ee2c0fbc4d32b9997edb4p0,
    -0x1.27701caf89e85p1
  },
  { // Entry 636
    0x1.2bfeb53ef2d629fd2ec3bbe0988ec127p0,
    0x1.2fa50109bf842p1
  },
  { // Entry 637
    -0x1.2bfeb53ef2d629fd2ec3bbe0988ec127p0,
    -0x1.2fa50109bf842p1
  },
  { // Entry 638
    0x1.2e6a76d3a7c4daa88cd0858debcbfd55p0,
    0x1.37d9e563f51ffp1
  },
  { // Entry 639
    -0x1.2e6a76d3a7c4daa88cd0858debcbfd55p0,
    -0x1.37d9e563f51ffp1
  },
  { // Entry 640
    0x1.30baebc4d0b12279c4c6a70a83ec7404p0,
    0x1.400ec9be2abbcp1
  },
  { // Entry 641
    -0x1.30baebc4d0b12279c4c6a70a83ec7404p0,
    -0x1.400ec9be2abbcp1
  },
  { // Entry 642
    0x1.32f1c0a688709db9016d269725c02a4fp0,
    0x1.4843ae1860579p1
  },
  { // Entry 643
    -0x1.32f1c0a688709db9016d269725c02a4fp0,
    -0x1.4843ae1860579p1
  },
  { // Entry 644
    0x1.351081b3f9205c658eef3c57bcc8acb2p0,
    0x1.5078927295f36p1
  },
  { // Entry 645
    -0x1.351081b3f9205c658eef3c57bcc8acb2p0,
    -0x1.5078927295f36p1
  },
  { // Entry 646
    0x1.37189d975e5f9cb962f7bf8cf038ccc8p0,
    0x1.58ad76cccb8f3p1
  },
  { // Entry 647
    -0x1.37189d975e5f9cb962f7bf8cf038ccc8p0,
    -0x1.58ad76cccb8f3p1
  },
  { // Entry 648
    0x1.390b67f0f05fe3c31d028790ff0ff571p0,
    0x1.60e25b27012b0p1
  },
  { // Entry 649
    -0x1.390b67f0f05fe3c31d028790ff0ff571p0,
    -0x1.60e25b27012b0p1
  },
  { // Entry 650
    0x1.3aea1ba270fc7663f575c66a2dbf5ff8p0,
    0x1.69173f8136c6dp1
  },
  { // Entry 651
    -0x1.3aea1ba270fc7663f575c66a2dbf5ff8p0,
    -0x1.69173f8136c6dp1
  },
  { // Entry 652
    0x1.3cb5dce4b8f630b629d722f5ae3dc757p0,
    0x1.714c23db6c62ap1
  },
  { // Entry 653
    -0x1.3cb5dce4b8f630b629d722f5ae3dc757p0,
    -0x1.714c23db6c62ap1
  },
  { // Entry 654
    0x1.3e6fbb2c41396ce4aeff19d97552d217p0,
    0x1.79810835a1fe7p1
  },
  { // Entry 655
    -0x1.3e6fbb2c41396ce4aeff19d97552d217p0,
    -0x1.79810835a1fe7p1
  },
  { // Entry 656
    0x1.4018b2e13fe932bca7539dacbfa4d09ep0,
    0x1.81b5ec8fd79a4p1
  },
  { // Entry 657
    -0x1.4018b2e13fe932bca7539dacbfa4d09ep0,
    -0x1.81b5ec8fd79a4p1
  },
  { // Entry 658
    0x1.41b1aeef8e4ae6bd8723cc148d6caf10p0,
    0x1.89ead0ea0d35bp1
  },
  { // Entry 659
    -0x1.41b1aeef8e4ae6bd8723cc148d6caf10p0,
    -0x1.89ead0ea0d35bp1
  },
  { // Entry 660
    -0x1.6807a9c540dd353125463348a685edc8p0,
    -0x1.81b5ec8fd799fp2
  },
  { // Entry 661
    0x1.6807a9c540dd353125463348a685edc8p0,
    0x1.81b5ec8fd799fp2
  },
  { // Entry 662
    -0x1.6631e1a59590376d984470d99cc8df7bp0,
    -0x1.714c23db6c626p2
  },
  { // Entry 663
    0x1.6631e1a59590376d984470d99cc8df7bp0,
    0x1.714c23db6c626p2
  },
  { // Entry 664
    -0x1.6431bb7edf2bb723008b3c51ca448a76p0,
    -0x1.60e25b27012adp2
  },
  { // Entry 665
    0x1.6431bb7edf2bb723008b3c51ca448a76p0,
    0x1.60e25b27012adp2
  },
  { // Entry 666
    -0x1.6201493b022361bd3c406520761b65cfp0,
    -0x1.5078927295f34p2
  },
  { // Entry 667
    0x1.6201493b022361bd3c406520761b65cfp0,
    0x1.5078927295f34p2
  },
  { // Entry 668
    -0x1.5f9977a47aee17d0f12c193a7dd62259p0,
    -0x1.400ec9be2abbbp2
  },
  { // Entry 669
    0x1.5f9977a47aee17d0f12c193a7dd62259p0,
    0x1.400ec9be2abbbp2
  },
  { // Entry 670
    -0x1.5cf1c53dd9ca9fa29b3bb04ec56e073fp0,
    -0x1.2fa50109bf842p2
  },
  { // Entry 671
    0x1.5cf1c53dd9ca9fa29b3bb04ec56e073fp0,
    0x1.2fa50109bf842p2
  },
  { // Entry 672
    -0x1.59ffe278fb5d0fd66d3a875f34e955b9p0,
    -0x1.1f3b3855544c9p2
  },
  { // Entry 673
    0x1.59ffe278fb5d0fd66d3a875f34e955b9p0,
    0x1.1f3b3855544c9p2
  },
  { // Entry 674
    -0x1.56b732e5cd9e7665c855c33ec7ba86a3p0,
    -0x1.0ed16fa0e9150p2
  },
  { // Entry 675
    0x1.56b732e5cd9e7665c855c33ec7ba86a3p0,
    0x1.0ed16fa0e9150p2
  },
  { // Entry 676
    -0x1.530823483d3605b2bd96ffaf2c4679c9p0,
    -0x1.fccf4dd8fbbaep1
  },
  { // Entry 677
    0x1.530823483d3605b2bd96ffaf2c4679c9p0,
    0x1.fccf4dd8fbbaep1
  },
  { // Entry 678
    -0x1.4edf430c0024477cefffec364da85c1dp0,
    -0x1.dbfbbc70254bcp1
  },
  { // Entry 679
    0x1.4edf430c0024477cefffec364da85c1dp0,
    0x1.dbfbbc70254bcp1
  },
  { // Entry 680
    -0x1.4a2407447a81c7dc1121259e08565d3ep0,
    -0x1.bb282b074edcap1
  },
  { // Entry 681
    0x1.4a2407447a81c7dc1121259e08565d3ep0,
    0x1.bb282b074edcap1
  },
  { // Entry 682
    -0x1.44b710bde944f5b73d2380913fb96b93p0,
    -0x1.9a54999e786d8p1
  },
  { // Entry 683
    0x1.44b710bde944f5b73d2380913fb96b93p0,
    0x1.9a54999e786d8p1
  },
  { // Entry 684
    -0x1.3e6fbb2c41396997fae3ce7cb202ab3cp0,
    -0x1.79810835a1fe6p1
  },
  { // Entry 685
    0x1.3e6fbb2c41396997fae3ce7cb202ab3cp0,
    0x1.79810835a1fe6p1
  },
  { // Entry 686
    -0x1.37189d975e5fa09a38272d7f560e0da4p0,
    -0x1.58ad76cccb8f4p1
  },
  { // Entry 687
    0x1.37189d975e5fa09a38272d7f560e0da4p0,
    0x1.58ad76cccb8f4p1
  },
  { // Entry 688
    -0x1.2e6a76d3a7c4e87fefa518c326ab6156p0,
    -0x1.37d9e563f5202p1
  },
  { // Entry 689
    0x1.2e6a76d3a7c4e87fefa518c326ab6156p0,
    0x1.37d9e563f5202p1
  },
  { // Entry 690
    -0x1.2404bf4b3ead1be0d614e16bd1916f4dp0,
    -0x1.170653fb1eb10p1
  },
  { // Entry 691
    0x1.2404bf4b3ead1be0d614e16bd1916f4dp0,
    0x1.170653fb1eb10p1
  },
  { // Entry 692
    -0x1.1762c60438ce5938069b20cf6314944ap0,
    -0x1.ec6585249083cp0
  },
  { // Entry 693
    0x1.1762c60438ce5938069b20cf6314944ap0,
    0x1.ec6585249083cp0
  },
  { // Entry 694
    -0x1.07cbfe8c14ddd1f1d38ba981b0996a1ap0,
    -0x1.aabe6252e3a58p0
  },
  { // Entry 695
    0x1.07cbfe8c14ddd1f1d38ba981b0996a1ap0,
    0x1.aabe6252e3a58p0
  },
  { // Entry 696
    -0x1.e87d358361bdd2789fd13900549104c2p-1,
    -0x1.69173f8136c74p0
  },
  { // Entry 697
    0x1.e87d358361bdd2789fd13900549104c2p-1,
    0x1.69173f8136c74p0
  },
  { // Entry 698
    -0x1.b6add448714f14e4cbd045740116f534p-1,
    -0x1.27701caf89e90p0
  },
  { // Entry 699
    0x1.b6add448714f14e4cbd045740116f534p-1,
    0x1.27701caf89e90p0
  },
  { // Entry 700
    -0x1.7685624cb37593eb960af368aeea2616p-1,
    -0x1.cb91f3bbba157p-1
  },
  { // Entry 701
    0x1.7685624cb37593eb960af368aeea2616p-1,
    0x1.cb91f3bbba157p-1
  },
  { // Entry 702
    -0x1.23e717d0fa7c2705659e11ed85e6dac4p-1,
    -0x1.4843ae186058ep-1
  },
  { // Entry 703
    0x1.23e717d0fa7c2705659e11ed85e6dac4p-1,
    0x1.4843ae186058ep-1
  },
  { // Entry 704
    -0x1.780c45b9736d2d89e5dbc5fe7167a786p-2,
    -0x1.89ead0ea0d38ap-2
  },
  { // Entry 705
    0x1.780c45b9736d2d89e5dbc5fe7167a786p-2,
    0x1.89ead0ea0d38ap-2
  },
  { // Entry 706
    -0x1.052fab368e0bf61ea3f942bd2601e1bap-3,
    -0x1.069c8b46b37f0p-3
  },
  { // Entry 707
    0x1.052fab368e0bf61ea3f942bd2601e1bap-3,
    0x1.069c8b46b37f0p-3
  },
  { // Entry 708
    0x1.052fab368e0066c753ec64819b76a489p-3,
    0x1.069c8b46b3734p-3
  },
  { // Entry 709
    -0x1.052fab368e0066c753ec64819b76a489p-3,
    -0x1.069c8b46b3734p-3
  },
  { // Entry 710
    0x1.780c45b973680f69ff94600d976ecca3p-2,
    0x1.89ead0ea0d32cp-2
  },
  { // Entry 711
    -0x1.780c45b973680f69ff94600d976ecca3p-2,
    -0x1.89ead0ea0d32cp-2
  },
  { // Entry 712
    0x1.23e717d0fa7a1216d86181eab105dcf9p-1,
    0x1.4843ae186055fp-1
  },
  { // Entry 713
    -0x1.23e717d0fa7a1216d86181eab105dcf9p-1,
    -0x1.4843ae186055fp-1
  },
  { // Entry 714
    0x1.7685624cb373f375056aa629c14d7f7ep-1,
    0x1.cb91f3bbba128p-1
  },
  { // Entry 715
    -0x1.7685624cb373f375056aa629c14d7f7ep-1,
    -0x1.cb91f3bbba128p-1
```
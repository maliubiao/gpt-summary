Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of a larger file `sincosf_intel_data.handroid` in the Android Bionic library. This specific snippet contains a data array.

Here's a breakdown of the thought process:

1. **Identify the Core Element:** The code is a C array of structures. Each structure appears to have three floating-point numbers.

2. **Infer the Purpose from the Filename:** The filename `sincosf_intel_data.handroid` strongly suggests that this data is related to the `sinf` and `cosf` functions (single-precision sine and cosine) and is likely optimized for Intel architectures on Android. The `.handroid` suffix might indicate manual optimization or some specific Android-related data formatting.

3. **Analyze the Data Structure:** Each element in the array seems to correspond to a specific input value and its pre-calculated sine and cosine values. The three numbers in each structure likely represent:
    * The input angle (or a value related to the angle).
    * The cosine of that angle.
    * The sine of that angle.

4. **Consider the Context within Bionic:**  Bionic's `libm` (math library) needs to provide accurate and efficient implementations of trigonometric functions. Pre-calculated data tables are a common optimization technique for such functions, especially on embedded systems where computation might be more expensive than memory access.

5. **Formulate the Summary:** Based on the above, the core functionality is providing pre-computed data for the `sinf` and `cosf` functions.

6. **Address the "Part 2 of 4" aspect:** This suggests the data might be split into ranges or different levels of precision. This part likely covers a specific range of input values.

7. **Refine the Summary:** Combine the observations into a concise summary, emphasizing the purpose and context within the Android math library.
这段代码是 `bionic/tests/math_data/sincosf_intel_data.handroid` 文件的一部分，它位于 Android 的 Bionic 库中。  考虑到这是第 2 部分，我们需要结合文件名和数据内容来推断其功能。

**功能归纳：**

这部分代码定义了一个 C 语言数组，该数组包含了一系列预先计算好的单精度浮点数值。这些数值很可能用于优化 `sinf` 和 `cosf` 函数的计算，特别是针对 Intel 架构的 Android 设备。

**更详细的解释：**

* **数据结构:** 代码定义了一个匿名结构体的数组。每个结构体包含三个 `float` 类型的成员。
* **预计算数据:**  这些浮点数值很可能代表了 `sinf` 和 `cosf` 函数在特定输入值下的结果。
* **优化目的:**  通过预先计算并存储这些值，可以在实际调用 `sinf` 和 `cosf` 时，对于接近这些预计算输入的值，可以直接查表或者进行插值计算，从而提高计算效率。
* **Intel 架构 (`_intel`):** 文件名中的 `_intel` 表明这些数据可能是针对 Intel 处理器的特性进行过优化的。不同的处理器架构可能需要不同的优化策略。
* **`handroid` 后缀:**  这个后缀可能表示这些数据是手工调整或专门为 Android 环境准备的。

**结合整个文件的功能来理解 (虽然我们只有第 2 部分):**

整个 `sincosf_intel_data.handroid` 文件很可能是一个查找表或者一组查找表，用于快速近似计算单精度浮点数的正弦和余弦值。  不同的部分可能对应不同的输入范围或者精度级别。

**推测数据含义:**

虽然没有上下文，但我们可以合理推测每个结构体中的三个 `float` 值分别代表：

1. **输入值:** 用于计算正弦和余弦的输入角度值（或其某种变换形式）。由于数值都是接近 1 或 -1 的科学计数法表示，可能已经过某种归一化处理。
2. **余弦值:**  对应输入值的余弦值。
3. **正弦值:**  对应输入值的正弦值。

**与 Android 功能的关系举例说明:**

Android 框架或 NDK 中的图形渲染、动画、物理模拟等模块，以及各种需要进行数学计算的应用，都会频繁地调用 `sinf` 和 `cosf` 函数。使用这样的预计算数据可以显著提升这些计算的性能，从而提高应用的流畅度和响应速度。

例如，一个游戏引擎在计算游戏中物体的运动轨迹或者光照效果时，可能会多次调用 `sinf` 和 `cosf`。  Bionic 库提供的优化版本，通过查表等方式，可以避免复杂的浮点数运算，从而降低 CPU 负载，节省电量。

**关于其他部分的推测：**

* **第 1 部分:** 可能包含更小或更大的输入值范围的预计算数据，或者是一些控制参数和定义。
* **第 3 和第 4 部分:**  可能包含剩余输入值范围的预计算数据，或者针对特殊情况（例如接近零或 π/2 的角度）的额外数据。

**总结第 2 部分的功能:**

这部分代码定义了 `sincosf` 函数在特定输入范围内使用的一组预先计算好的单精度浮点数，用于优化在 Intel 架构 Android 设备上的正弦和余弦计算性能。它很可能是 `sincosf_intel_data.handroid` 文件中多个数据段的一部分，共同构成了一个用于快速近似计算的查找表。

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
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
223p-1,
    0x1.93cd3ep-1,
  },
  { // Entry 246
    -0x1.6b3920d8117828928fe10ac70ba69e76p-1,
    0x1.68d9ad29736c1704caea6a2db6e71223p-1,
    -0x1.93cd3ep-1,
  },
  { // Entry 247
    0x1.7a25450443098836c5202375db4b8462p-1,
    0x1.592e5578c9ec66acceddd4dc6ce66b26p-1,
    0x1.a971p-1,
  },
  { // Entry 248
    -0x1.7a25450443098836c5202375db4b8462p-1,
    0x1.592e5578c9ec66acceddd4dc6ce66b26p-1,
    -0x1.a971p-1,
  },
  { // Entry 249
    0x1.886482ae6797b38364f5c72ce9a3b76fp-1,
    0x1.48e529d429e721ec8bb1e014f94d48f1p-1,
    0x1.bf14c2p-1,
  },
  { // Entry 250
    -0x1.886482ae6797b38364f5c72ce9a3b76fp-1,
    0x1.48e529d429e721ec8bb1e014f94d48f1p-1,
    -0x1.bf14c2p-1,
  },
  { // Entry 251
    0x1.95f056337acc1d2d557525232e915467p-1,
    0x1.38059c833c58ea970f7b96d6ada3d9c4p-1,
    0x1.d4b884p-1,
  },
  { // Entry 252
    -0x1.95f056337acc1d2d557525232e915467p-1,
    0x1.38059c833c58ea970f7b96d6ada3d9c4p-1,
    -0x1.d4b884p-1,
  },
  { // Entry 253
    0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    0x1.ea5c3ep-1,
  },
  { // Entry 254
    -0x1.a2c2895edb0d4ba51cdbd5390cac468fp-1,
    0x1.26976b1b16d19091c09259765c4b3872p-1,
    -0x1.ea5c3ep-1,
  },
  { // Entry 255
    0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    0x1.12bd92p0,
  },
  { // Entry 256
    -0x1.c1e988b95614abd65d3d811f5c88039bp-1,
    0x1.e8c4040678d2ef736333a4537a1113a1p-2,
    -0x1.12bd92p0,
  },
  { // Entry 257
    0x1.d294d2e06b3d10a4de263172d50f4497p-1,
    0x1.a5a4c8f598fa0078971316eb4907f97bp-2,
    0x1.257b24p0,
  },
  { // Entry 258
    -0x1.d294d2e06b3d10a4de263172d50f4497p-1,
    0x1.a5a4c8f598fa0078971316eb4907f97bp-2,
    -0x1.257b24p0,
  },
  { // Entry 259
    0x1.e0c04bb65bd33012be72a340df2c044bp-1,
    0x1.60435beed10ca05769f0a3d86a5a20f3p-2,
    0x1.3838b6p0,
  },
  { // Entry 260
    -0x1.e0c04bb65bd33012be72a340df2c044bp-1,
    0x1.60435beed10ca05769f0a3d86a5a20f3p-2,
    -0x1.3838b6p0,
  },
  { // Entry 261
    0x1.ec5884eb990c3deaaeebd3f0f84d6962p-1,
    0x1.18fee0fc45c31a79b2b9478b1f72a9ebp-2,
    0x1.4af648p0,
  },
  { // Entry 262
    -0x1.ec5884eb990c3deaaeebd3f0f84d6962p-1,
    0x1.18fee0fc45c31a79b2b9478b1f72a9ebp-2,
    -0x1.4af648p0,
  },
  { // Entry 263
    0x1.f54d9835b0e66e17612160272521f3b0p-1,
    0x1.a072252090c33828767aee3e040ccddfp-3,
    0x1.5db3dap0,
  },
  { // Entry 264
    -0x1.f54d9835b0e66e17612160272521f3b0p-1,
    0x1.a072252090c33828767aee3e040ccddfp-3,
    -0x1.5db3dap0,
  },
  { // Entry 265
    0x1.fb933d1cd931685e902e403a1baaecfdp-1,
    0x1.0cab7703a8e9dacc4ad01188b443cfeep-3,
    0x1.70716cp0,
  },
  { // Entry 266
    -0x1.fb933d1cd931685e902e403a1baaecfdp-1,
    0x1.0cab7703a8e9dacc4ad01188b443cfeep-3,
    -0x1.70716cp0,
  },
  { // Entry 267
    0x1.ff20d9d3e8984fec33982e42f5884f2cp-1,
    0x1.ddd171a3c9851e7819b5e4f6f90e763dp-5,
    0x1.832efep0,
  },
  { // Entry 268
    -0x1.ff20d9d3e8984fec33982e42f5884f2cp-1,
    0x1.ddd171a3c9851e7819b5e4f6f90e763dp-5,
    -0x1.832efep0,
  },
  { // Entry 269
    0x1.fff18f03a4b7e6aacf51f83931e85042p-1,
    -0x1.e668cb154eea68bbc7f8154f46b2e536p-7,
    0x1.95ec90p0,
  },
  { // Entry 270
    -0x1.fff18f03a4b7e6aacf51f83931e85042p-1,
    -0x1.e668cb154eea68bbc7f8154f46b2e536p-7,
    -0x1.95ec90p0,
  },
  { // Entry 271
    0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    0x1.a8aa1cp0,
  },
  { // Entry 272
    -0x1.fe043f875c6ed4a2c1b8d69a09fcf578p-1,
    -0x1.682f2bb87a8f5011735094176c9b6dacp-4,
    -0x1.a8aa1cp0,
  },
  { // Entry 273
    0x1.b3d36a96880cf69d9884a49f5381e917p-1,
    0x1.0cb3449a0d0a9e0643d41f4a5b0f7db7p-1,
    0x1.04aff8p0,
  },
  { // Entry 274
    -0x1.b3d36a96880cf69d9884a49f5381e917p-1,
    0x1.0cb3449a0d0a9e0643d41f4a5b0f7db7p-1,
    -0x1.04aff8p0,
  },
  { // Entry 275
    0x1.b3d41aebcf391c30c3d2f1ee7b79710cp-1,
    0x1.0cb22697153bcf1f8a63acddd96c54cbp-1,
    0x1.04b0a0p0,
  },
  { // Entry 276
    -0x1.b3d41aebcf391c30c3d2f1ee7b79710cp-1,
    0x1.0cb22697153bcf1f8a63acddd96c54cbp-1,
    -0x1.04b0a0p0,
  },
  { // Entry 277
    0x1.b3d4cb405ab3292be7df5b1b98032fbep-1,
    0x1.0cb10893a9b5471a44356072cb33b395p-1,
    0x1.04b148p0,
  },
  { // Entry 278
    -0x1.b3d4cb405ab3292be7df5b1b98032fbep-1,
    0x1.0cb10893a9b5471a44356072cb33b395p-1,
    -0x1.04b148p0,
  },
  { // Entry 279
    0x1.b3d57b942a7ad19e9b9892c9319e1be6p-1,
    0x1.0cafea8fca7781236a57e5b1c8aed39cp-1,
    0x1.04b1f0p0,
  },
  { // Entry 280
    -0x1.b3d57b942a7ad19e9b9892c9319e1be6p-1,
    0x1.0cafea8fca7781236a57e5b1c8aed39cp-1,
    -0x1.04b1f0p0,
  },
  { // Entry 281
    0x1.b3d62be73e8fc998c6c2df6590425613p-1,
    0x1.0caecc8b7782f86827af92b0b2374510p-1,
    0x1.04b298p0,
  },
  { // Entry 282
    -0x1.b3d62be73e8fc998c6c2df6590425613p-1,
    0x1.0caecc8b7782f86827af92b0b2374510p-1,
    -0x1.04b298p0,
  },
  { // Entry 283
    0x1.b3d6dc3996f1c52aa1f83bdee1d0e023p-1,
    0x1.0cadae86b0d82815d8f632e67c7e1a99p-1,
    0x1.04b340p0,
  },
  { // Entry 284
    -0x1.b3d6dc3996f1c52aa1f83bdee1d0e023p-1,
    0x1.0cadae86b0d82815d8f632e67c7e1a99p-1,
    -0x1.04b340p0,
  },
  { // Entry 285
    0x1.b3d78c8b33a07864b6a878573db34bcap-1,
    0x1.0cac908176778b5a0cbad21ee75ce765p-1,
    0x1.04b3e8p0,
  },
  { // Entry 286
    -0x1.b3d78c8b33a07864b6a878573db34bcap-1,
    0x1.0cac908176778b5a0cbad21ee75ce765p-1,
    -0x1.04b3e8p0,
  },
  { // Entry 287
    0x1.b3d83cdc149b9757df195ad885ab5201p-1,
    0x1.0cab727bc8619d628361876e1f30a633p-1,
    0x1.04b490p0,
  },
  { // Entry 288
    -0x1.b3d83cdc149b9757df195ad885ab5201p-1,
    0x1.0cab727bc8619d628361876e1f30a633p-1,
    -0x1.04b490p0,
  },
  { // Entry 289
    0x1.b3d8e8f9908360b38cd13fcbf6224d93p-1,
    0x1.0caa5b450a4324f204a556b072da124ap-1,
    0x1.04b534p0,
  },
  { // Entry 290
    -0x1.b3d8e8f9908360b38cd13fcbf6224d93p-1,
    0x1.0caa5b450a4324f204a556b072da124ap-1,
    -0x1.04b534p0,
  },
  { // Entry 291
    -0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
  },
  { // Entry 292
    0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149,
  },
  { // Entry 293
    0.0,
    0x1.p0,
    0.0,
  },
  { // Entry 294
    0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-149,
  },
  { // Entry 295
    -0.0f,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
  },
  { // Entry 296
    0x1.1773d36a64df61d6715e60af063559f4p-1,
    0x1.ad02c8b9cc93f448ef4eb068a88922a3p-1,
    0x1.279a72p-1,
  },
  { // Entry 297
    -0x1.1773d36a64df61d6715e60af063559f4p-1,
    0x1.ad02c8b9cc93f448ef4eb068a88922a3p-1,
    -0x1.279a72p-1,
  },
  { // Entry 298
    0x1.1773d51767a78fe91b55f6b7e5fd44c2p-1,
    0x1.ad02c7a258bfb362abbe86fb48f4e98bp-1,
    0x1.279a74p-1,
  },
  { // Entry 299
    -0x1.1773d51767a78fe91b55f6b7e5fd44c2p-1,
    0x1.ad02c7a258bfb362abbe86fb48f4e98bp-1,
    -0x1.279a74p-1,
  },
  { // Entry 300
    0x1.1773d6c46a6ea687f03625194d25bb52p-1,
    0x1.ad02c68ae4e9c579a08c04ce59be4002p-1,
    0x1.279a76p-1,
  },
  { // Entry 301
    -0x1.1773d6c46a6ea687f03625194d25bb52p-1,
    0x1.ad02c68ae4e9c579a08c04ce59be4002p-1,
    -0x1.279a76p-1,
  },
  { // Entry 302
    0x1.f95b8f40501057ac49acef13993b0c55p-1,
    -0x1.48d1c9e98b6c08784f10040f47a12191p-3,
    0x1.bb67acp0,
  },
  { // Entry 303
    -0x1.f95b8f40501057ac49acef13993b0c55p-1,
    -0x1.48d1c9e98b6c08784f10040f47a12191p-3,
    -0x1.bb67acp0,
  },
  { // Entry 304
    0x1.f95b8e9be727702f7595ae1000a14a1ap-1,
    -0x1.48d1d9b467e37955337311decd09fc74p-3,
    0x1.bb67aep0,
  },
  { // Entry 305
    -0x1.f95b8e9be727702f7595ae1000a14a1ap-1,
    -0x1.48d1d9b467e37955337311decd09fc74p-3,
    -0x1.bb67aep0,
  },
  { // Entry 306
    0x1.f95b8df77e36a344670ed07149191a58p-1,
    -0x1.48d1e97f4455c6eab1048022238b2bd0p-3,
    0x1.bb67b0p0,
  },
  { // Entry 307
    -0x1.f95b8df77e36a344670ed07149191a58p-1,
    -0x1.48d1e97f4455c6eab1048022238b2bd0p-3,
    -0x1.bb67b0p0,
  },
  { // Entry 308
    0x1.b1d82e835a918de18f5fdadc8b1240cfp-2,
    0x1.cfc6d011a0e5d0fcebb54b5fed672940p-1,
    0x1.bffffep-2,
  },
  { // Entry 309
    -0x1.b1d82e835a918de18f5fdadc8b1240cfp-2,
    0x1.cfc6d011a0e5d0fcebb54b5fed672940p-1,
    -0x1.bffffep-2,
  },
  { // Entry 310
    0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    0x1.c0p-2,
  },
  { // Entry 311
    -0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    -0x1.c0p-2,
  },
  { // Entry 312
    0x1.b1d83222e830d83743258fd09040ee56p-2,
    0x1.cfc6cf38b4cda76c3b09b17e9deb19eap-1,
    0x1.c00002p-2,
  },
  { // Entry 313
    -0x1.b1d83222e830d83743258fd09040ee56p-2,
    0x1.cfc6cf38b4cda76c3b09b17e9deb19eap-1,
    -0x1.c00002p-2,
  },
  { // Entry 314
    0x1.44eb3691428062b27925c585ad59d62ap-1,
    0x1.8bb106eac7c75d33fbb19446313ecc2fp-1,
    0x1.5ffffep-1,
  },
  { // Entry 315
    -0x1.44eb3691428062b27925c585ad59d62ap-1,
    0x1.8bb106eac7c75d33fbb19446313ecc2fp-1,
    -0x1.5ffffep-1,
  },
  { // Entry 316
    0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    0x1.60p-1,
  },
  { // Entry 317
    -0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    -0x1.60p-1,
  },
  { // Entry 318
    0x1.44eb39a8a48bae6b98ae11c9400535e5p-1,
    0x1.8bb10460f157234ceec7d9644a1a78e5p-1,
    0x1.600002p-1,
  },
  { // Entry 319
    -0x1.44eb39a8a48bae6b98ae11c9400535e5p-1,
    0x1.8bb10460f157234ceec7d9644a1a78e5p-1,
    -0x1.600002p-1,
  },
  { // Entry 320
    0x1.dad9017b96408c375d4faf0e4776d1fcp-1,
    0x1.7ef48b9a6fd5c24f5ec39839e1729b78p-2,
    0x1.2ffffep0,
  },
  { // Entry 321
    -0x1.dad9017b96408c375d4faf0e4776d1fcp-1,
    0x1.7ef48b9a6fd5c24f5ec39839e1729b78p-2,
    -0x1.2ffffep0,
  },
  { // Entry 322
    0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    0x1.30p0,
  },
  { // Entry 323
    -0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    -0x1.30p0,
  },
  { // Entry 324
    0x1.dad904797f48ea4ef4fd2e47fe4d52bdp-1,
    0x1.7ef47cc3a7bdedf9252074263d8a4596p-2,
    0x1.300002p0,
  },
  { // Entry 325
    -0x1.dad904797f48ea4ef4fd2e47fe4d52bdp-1,
    0x1.7ef47cc3a7bdedf9252074263d8a4596p-2,
    -0x1.300002p0,
  },
  { // Entry 326
    0x1.4b708093c9cb45355e7821e5aad98ce8p-1,
    -0x1.863ef5085bcc358d2ae8525bf39f0c40p-1,
    0x1.37fffep1,
  },
  { // Entry 327
    -0x1.4b708093c9cb45355e7821e5aad98ce8p-1,
    -0x1.863ef5085bcc358d2ae8525bf39f0c40p-1,
    -0x1.37fffep1,
  },
  { // Entry 328
    0x1.4b707a7acdecc84239463e78b312fa10p-1,
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    0x1.38p1,
  },
  { // Entry 329
    -0x1.4b707a7acdecc84239463e78b312fa10p-1,
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    -0x1.38p1,
  },
  { // Entry 330
    0x1.4b707461d1f994476c677c5ad5ddb264p-1,
    -0x1.863eff63dfa00bfc758baf469469d741p-1,
    0x1.380002p1,
  },
  { // Entry 331
    -0x1.4b707461d1f994476c677c5ad5ddb264p-1,
    -0x1.863eff63dfa00bfc758baf469469d741p-1,
    -0x1.380002p1,
  },
  { // Entry 332
    0x1.066e7f705a6ca2b9e107f7dc9f3b26e6p-4,
    0x1.fef2b2d0a10e2739c566936480a1479bp-1,
    0x1.069c8cp-4,
  },
  { // Entry 333
    -0x1.066e7f705a6ca2b9e107f7dc9f3b26e6p-4,
    0x1.fef2b2d0a10e2739c566936480a1479bp-1,
    -0x1.069c8cp-4,
  },
  { // Entry 334
    0x1.05e476d27febc8b7e9690009b367c327p-3,
    0x1.fbcbe68dd10bad0a229ccbb580cc5436p-1,
    0x1.069c8cp-3,
  },
  { // Entry 335
    -0x1.05e476d27febc8b7e9690009b367c327p-3,
    0x1.fbcbe68dd10bad0a229ccbb580cc5436p-1,
    -0x1.069c8cp-3,
  },
  { // Entry 336
    0x1.877e2de5c9a066b8db595adc149af0c0p-3,
    0x1.f68eebef72e7f6126b3f3dde646a755cp-1,
    0x1.89ead2p-3,
  },
  { // Entry 337
    -0x1.877e2de5c9a066b8db595adc149af0c0p-3,
    0x1.f68eebef72e7f6126b3f3dde646a755cp-1,
    -0x1.89ead2p-3,
  },
  { // Entry 338
    0x1.03be07acb9dab719b4343a33b9fa6afep-2,
    0x1.ef41459d2e90ea1b7faad7fabd1fd444p-1,
    0x1.069c8cp-2,
  },
  { // Entry 339
    -0x1.03be07acb9dab719b4343a33b9fa6afep-2,
    0x1.ef41459d2e90ea1b7faad7fabd1fd444p-1,
    -0x1.069c8cp-2,
  },
  { // Entry 340
    0x1.42abbc5b3b2f91e8ece46e5effd28369p-2,
    0x1.e5eaa23a27fe8d6890a3edace1c61998p-1,
    0x1.4843b0p-2,
  },
  { // Entry 341
    -0x1.42abbc5b3b2f91e8ece46e5effd28369p-2,
    0x1.e5eaa23a27fe8d6890a3edace1c61998p-1,
    -0x1.4843b0p-2,
  },
  { // Entry 342
    0x1.804601411d93f4750919670061de07d9p-2,
    0x1.da94d4b99c3a9a5e0d1fc86d53369a84p-1,
    0x1.89ead4p-2,
  },
  { // Entry 343
    -0x1.804601411d93f4750919670061de07d9p-2,
    0x1.da94d4b99c3a9a5e0d1fc86d53369a84p-1,
    -0x1.89ead4p-2,
  },
  { // Entry 344
    0x1.bc4c08af356088b1694995bfaf8a297bp-2,
    0x1.cd4bc9afc01230b2f982f6968dab7f05p-1,
    0x1.cb91f8p-2,
  },
  { // Entry 345
    -0x1.bc4c08af356088b1694995bfaf8a297bp-2,
    0x1.cd4bc9afc01230b2f982f6968dab7f05p-1,
    -0x1.cb91f8p-2,
  },
  { // Entry 346
    0x1.f67eae34dc0b42b465fd2a3fb07564a4p-2,
    0x1.be1d7adf077def2a360fec23dbbcef09p-1,
    0x1.069c8ep-1,
  },
  { // Entry 347
    -0x1.f67eae34dc0b42b465fd2a3fb07564a4p-2,
    0x1.be1d7adf077def2a360fec23dbbcef09p-1,
    -0x1.069c8ep-1,
  },
  { // Entry 348
    0x1.17505c86231898fd86b18d2282d93eedp-1,
    0x1.ad19e0847d25f3aa142289dab557bf96p-1,
    0x1.277020p-1,
  },
  { // Entry 349
    -0x1.17505c86231898fd86b18d2282d93eedp-1,
    0x1.ad19e0847d25f3aa142289dab557bf96p-1,
    -0x1.277020p-1,
  },
  { // Entry 350
    0x1.323b8e40d16575e50dc7b6e567bb5084p-1,
    0x1.9a52e08b191bd55512c8365074f1987fp-1,
    0x1.4843b2p-1,
  },
  { // Entry 351
    -0x1.323b8e40d16575e50dc7b6e567bb5084p-1,
    0x1.9a52e08b191bd55512c8365074f1987fp-1,
    -0x1.4843b2p-1,
  },
  { // Entry 352
    0x1.4be49b08a1e1629cbdaa507e18255cd8p-1,
    0x1.85dc3bb7c2e9abb5cccb6d96d12d39c4p-1,
    0x1.691744p-1,
  },
  { // Entry 353
    -0x1.4be49b08a1e1629cbdaa507e18255cd8p-1,
    0x1.85dc3bb7c2e9abb5cccb6d96d12d39c4p-1,
    -0x1.691744p-1,
  },
  { // Entry 354
    0x1.6430847dbbbfd46cbebbc6d5f51c7c49p-1,
    0x1.6fcb78e1cd65d2e4fde7118caac79d6dp-1,
    0x1.89ead6p-1,
  },
  { // Entry 355
    -0x1.6430847dbbbfd46cbebbc6d5f51c7c49p-1,
    0x1.6fcb78e1cd65d2e4fde7118caac79d6dp-1,
    -0x1.89ead6p-1,
  },
  { // Entry 356
    0x1.7b05bb87b38844e56003c41ef804b273p-1,
    0x1.5837ce4dc835d4a5454ec0a1bb394081p-1,
    0x1.aabe68p-1,
  },
  { // Entry 357
    -0x1.7b05bb87b38844e56003c41ef804b273p-1,
    0x1.5837ce4dc835d4a5454ec0a1bb394081p-1,
    -0x1.aabe68p-1,
  },
  { // Entry 358
    0x1.904c3b389d55d3deddb39d05eb366571p-1,
    0x1.3f3a09427966e9518802dee3bf443a95p-1,
    0x1.cb91fap-1,
  },
  { // Entry 359
    -0x1.904c3b389d55d3deddb39d05eb366571p-1,
    0x1.3f3a09427966e9518802dee3bf443a95p-1,
    -0x1.cb91fap-1,
  },
  { // Entry 360
    0x1.a3eda211798a82697d62431f9ae46cc4p-1,
    0x1.24ec73f1aeef4940bb8da19a82bbc49fp-1,
    0x1.ec658cp-1,
  },
  { // Entry 361
    -0x1.a3eda211798a82697d62431f9ae46cc4p-1,
    0x1.24ec73f1aeef4940bb8da19a82bbc49fp-1,
    -0x1.ec658cp-1,
  },
  { // Entry 362
    0x1.b5d54883fcb6123bc28aac91f085e4eep-1,
    0x1.096abb862f9bd5515982c2818c332ff9p-1,
    0x1.069c8ep0,
  },
  { // Entry 363
    -0x1.b5d54883fcb6123bc28aac91f085e4eep-1,
    0x1.096abb862f9bd5515982c2818c332ff9p-1,
    -0x1.069c8ep0,
  },
  { // Entry 364
    0x1.c5f05a0135d4882c768cdf18e2e1112cp-1,
    0x1.d9a39c0dddc654c717e3036da5dd685cp-2,
    0x1.170656p0,
  },
  { // Entry 365
    -0x1.c5f05a0135d4882c768cdf18e2e1112cp-1,
    0x1.d9a39c0dddc654c717e3036da5dd685cp-2,
    -0x1.170656p0,
  },
  { // Entry 366
    0x1.d42de53e315c839ce188e201205e99dep-1,
    0x1.9e7f81840c0bbd0f1b13733061062d34p-2,
    0x1.27701ep0,
  },
  { // Entry 367
    -0x1.d42de53e315c839ce188e201205e99dep-1,
    0x1.9e7f81840c0bbd0f1b13733061062d34p-2,
    -0x1.27701ep0,
  },
  { // Entry 368
    0x1.e07eef45d91eea8a6cc7369aa0e55388p-1,
    0x1.61a75e2deb596731c8cd45e3d9794526p-2,
    0x1.37d9e6p0,
  },
  { // Entry 369
    -0x1.e07eef45d91eea8a6cc7369aa0e55388p-1,
    0x1.61a75e2deb596731c8cd45e3d9794526p-2,
    -0x1.37d9e6p0,
  },
  { // Entry 370
    0x1.ead6833b2aa002baa1c2b19a38dc9b79p-1,
    0x1.235b337b091cdd8ac06390abc6816b82p-2,
    0x1.4843aep0,
  },
  { // Entry 371
    -0x1.ead6833b2aa002baa1c2b19a38dc9b79p-1,
    0x1.235b337b091cdd8ac06390abc6816b82p-2,
    -0x1.4843aep0,
  },
  { // Entry 372
    0x1.f329bffa6a208591eecb6905d7594e3bp-1,
    0x1.c7b9146d6d10824ff652dc390ba2d7f9p-3,
    0x1.58ad76p0,
  },
  { // Entry 373
    -0x1.f329bffa6a208591eecb6905d7594e3bp-1,
    0x1.c7b9146d6d10824ff652dc390ba2d7f9p-3,
    -0x1.58ad76p0,
  },
  { // Entry 374
    0x1.f96fe38afbd95b5fcd08608110e9381fp-1,
    0x1.46dc5b2f1de977efff7c278b5adb2a75p-3,
    0x1.69173ep0,
  },
  { // Entry 375
    -0x1.f96fe38afbd95b5fcd08608110e9381fp-1,
    0x1.46dc5b2f1de977efff7c278b5adb2a75p-3,
    -0x1.69173ep0,
  },
  { // Entry 376
    0x1.fda25455d9567772f20f25d15efc6775p-1,
    0x1.894f93ef49c4575800bbd646a3a31d2ap-4,
    0x1.798106p0,
  },
  { // Entry 377
    -0x1.fda25455d9567772f20f25d15efc6775p-1,
    0x1.894f93ef49c4575800bbd646a3a31d2ap-4,
    -0x1.798106p0,
  },
  { // Entry 378
    0x1.ffbca816f1f1516ec5d757b0db54ae34p-1,
    0x1.069164e3f5cee94d865fb52e316dff6bp-5,
    0x1.89eacep0,
  },
  { // Entry 379
    -0x1.ffbca816f1f1516ec5d757b0db54ae34p-1,
    0x1.069164e3f5cee94d865fb52e316dff6bp-5,
    -0x1.89eacep0,
  },
  { // Entry 380
    0x1.ffbca88228b163189ab8d637db99bd2dp-1,
    -0x1.069093eec0ed066ec83dd034498ef8bfp-5,
    0x1.9a5496p0,
  },
  { // Entry 381
    -0x1.ffbca88228b163189ab8d637db99bd2dp-1,
    -0x1.069093eec0ed066ec83dd034498ef8bfp-5,
    -0x1.9a5496p0,
  },
  { // Entry 382
    0x1.fda255970ccddb9d127ecf63403c2bf7p-1,
    -0x1.894f2be2979dd9ced83ccc60cf49cd44p-4,
    0x1.aabe5ep0,
  },
  { // Entry 383
    -0x1.fda255970ccddb9d127ecf63403c2bf7p-1,
    -0x1.894f2be2979dd9ced83ccc60cf49cd44p-4,
    -0x1.aabe5ep0,
  },
  { // Entry 384
    0x1.f96fe5a0da244489fb2f4b97b3e48757p-1,
    -0x1.46dc2796735195a15c80e5b719e2fc42p-3,
    0x1.bb2826p0,
  },
  { // Entry 385
    -0x1.f96fe5a0da244489fb2f4b97b3e48757p-1,
    -0x1.46dc2796735195a15c80e5b719e2fc42p-3,
    -0x1.bb2826p0,
  },
  { // Entry 386
    0x1.f329c2e2c1a39bad8ecdcb87961ba44ap-1,
    -0x1.c7b8e178b7e8c01d9f320466cc7a68d4p-3,
    0x1.cb91eep0,
  },
  { // Entry 387
    -0x1.f329c2e2c1a39bad8ecdcb87961ba44ap-1,
    -0x1.c7b8e178b7e8c01d9f320466cc7a68d4p-3,
    -0x1.cb91eep0,
  },
  { // Entry 388
    0x1.ead686f2ec572c83ed34a01f764d193ep-1,
    -0x1.235b1a6d767e4b362c64571ac97b4a1cp-2,
    0x1.dbfbb6p0,
  },
  { // Entry 389
    -0x1.ead686f2ec572c83ed34a01f764d193ep-1,
    -0x1.235b1a6d767e4b362c64571ac97b4a1cp-2,
    -0x1.dbfbb6p0,
  },
  { // Entry 390
    0x1.e07ef3c91bd500a0de230ad573163163p-1,
    -0x1.61a745a77b7e83c2f8a2f9b091e89aaap-2,
    0x1.ec657ep0,
  },
  { // Entry 391
    -0x1.e07ef3c91bd500a0de230ad573163163p-1,
    -0x1.61a745a77b7e83c2f8a2f9b091e89aaap-2,
    -0x1.ec657ep0,
  },
  { // Entry 392
    0x1.d42dea8835c88adb9cde17347f934e25p-1,
    -0x1.9e7f699e8b9aaf8ed51c71c8f73b0b74p-2,
    0x1.fccf46p0,
  },
  { // Entry 393
    -0x1.d42dea8835c88adb9cde17347f934e25p-1,
    -0x1.9e7f699e8b9aaf8ed51c71c8f73b0b74p-2,
    -0x1.fccf46p0,
  },
  { // Entry 394
    0x1.c5f05e32c80fb0fe603033ec028a4c32p-1,
    -0x1.d9a38bfa3195ba1caa7fb69bc1d04e42p-2,
    0x1.069c88p1,
  },
  { // Entry 395
    -0x1.c5f05e32c80fb0fe603033ec028a4c32p-1,
    -0x1.d9a38bfa3195ba1caa7fb69bc1d04e42p-2,
    -0x1.069c88p1,
  },
  { // Entry 396
    0x1.b5d54d3732d3b2e79d4907e115401ddap-1,
    -0x1.096ab3c55c91f36e2359ed1c5a8342dfp-1,
    0x1.0ed16cp1,
  },
  { // Entry 397
    -0x1.b5d54d3732d3b2e79d4907e115401ddap-1,
    -0x1.096ab3c55c91f36e2359ed1c5a8342dfp-1,
    -0x1.0ed16cp1,
  },
  { // Entry 398
    0x1.a3eda74161d06b83ec2c8dc396d813b9p-1,
    -0x1.24ec6c8206e744322d99f47e9e41becep-1,
    0x1.170650p1,
  },
  { // Entry 399
    -0x1.a3eda74161d06b83ec2c8dc396d813b9p-1,
    -0x1.24ec6c8206e744322d99f47e9e41becep-1,
    -0x1.170650p1,
  },
  { // Entry 400
    0x1.904c421efce58f4e8170d36dcda8e02cp-1,
    -0x1.3f3a009b82b5b8234e1296dd73cff49dp-1,
    0x1.1f3b34p1,
  },
  { // Entry 401
    -0x1.904c421efce58f4e8170d36dcda8e02cp-1,
    -0x1.3f3a009b82b5b8234e1296dd73cff49dp-1,
    -0x1.1f3b34p1,
  },
  { // Entry 402
    0x1.7b05c45093944d6afb0c90d2f9cb217fp-1,
    -0x1.5837c4a184ccf7ed57c189f2addf32c5p-1,
    0x1.277018p1,
  },
  { // Entry 403
    -0x1.7b05c45093944d6afb0c90d2f9cb217fp-1,
    -0x1.5837c4a184ccf7ed57c189f2addf32c5p-1,
    -0x1.277018p1,
  },
  { // Entry 404
    0x1.64308f506ffdaf1326d10b3380278e98p-1,
    -0x1.6fcb6e6685e72fb4074e70cd3162d3bap-1,
    0x1.2fa4fcp1,
  },
  { // Entry 405
    -0x1.64308f506ffdaf1326d10b3380278e98p-1,
    -0x1.6fcb6e6685e72fb4074e70cd3162d3bap-1,
    -0x1.2fa4fcp1,
  },
  { // Entry 406
    0x1.4be4a8076c135a48f3f1a1aaa362475fp-1,
    -0x1.85dc30a79f26754ab1370338ee7bfd11p-1,
    0x1.37d9e0p1,
  },
  { // Entry 407
    -0x1.4be4a8076c135a48f3f1a1aaa362475fp-1,
    -0x1.85dc30a79f26754ab1370338ee7bfd11p-1,
    -0x1.37d9e0p1,
  },
  { // Entry 408
    0x1.323b9d888d4da77a610893735eeed1cbp-1,
    -0x1.9a52d523b1532e4ed477e27dc6051c12p-1,
    0x1.400ec4p1,
  },
  { // Entry 409
    -0x1.323b9d888d4da77a610893735eeed1cbp-1,
    -0x1.9a52d523b1532e4ed477e27dc6051c12p-1,
    -0x1.400ec4p1,
  },
  { // Entry 410
    0x1.17506e2dfb603d34b9af39b12c1db735p-1,
    -0x1.ad19d50664abf0c0141137d2ca509f21p-1,
    0x1.4843a8p1,
  },
  { // Entry 411
    -0x1.17506e2dfb603d34b9af39b12c1db735p-1,
    -0x1.ad19d50664abf0c0141137d2ca509f21p-1,
    -0x1.4843a8p1,
  },
  { // Entry 412
    0x1.f67ed667352d4827450013f15e321bfbp-2,
    -0x1.be1d6f8d517db5c2cf7de0faf0808d30p-1,
    0x1.50788cp1,
  },
  { // Entry 413
    -0x1.f67ed667352d4827450013f15e321bfbp-2,
    -0x1.be1d6f8d517db5c2cf7de0faf0808d30p-1,
    -0x1.50788cp1,
  },
  { // Entry 414
    0x1.bc4c35da51e34b776e5e04da58f23441p-2,
    -0x1.cd4bbecf7f2705d4fd00dd463780f45ep-1,
    0x1.58ad70p1,
  },
  { // Entry 415
    -0x1.bc4c35da51e34b776e5e04da58f23441p-2,
    -0x1.cd4bbecf7f2705d4fd00dd463780f45ep-1,
    -0x1.58ad70p1,
  },
  { // Entry 416
    0x1.8046336e68427cf756056d3f4edbb662p-2,
    -0x1.da94ca915da3cdd1fff839d85eec39e2p-1,
    0x1.60e254p1,
  },
  { // Entry 417
    -0x1.8046336e68427cf756056d3f4edbb662p-2,
    -0x1.da94ca915da3cdd1fff839d85eec39e2p-1,
    -0x1.60e254p1,
  },
  { // Entry 418
    0x1.42abf3872905e632f204c41b24af90b6p-2,
    -0x1.e5ea99116b39361ac926dd9fdc2089d1p-1,
    0x1.691738p1,
  },
  { // Entry 419
    -0x1.42abf3872905e632f204c41b24af90b6p-2,
    -0x1.e5ea99116b39361ac926dd9fdc2089d1p-1,
    -0x1.691738p1,
  },
  { // Entry 420
    0x1.03be43c699f3536990dcf5a6665ac239p-2,
    -0x1.ef413dbbda2859ffb0d1ab84342fd235p-1,
    0x1.714c1cp1,
  },
  { // Entry 421
    -0x1.03be43c699f3536990dcf5a6665ac239p-2,
    -0x1.ef413dbbda2859ffb0d1ab84342fd235p-1,
    -0x1.714c1cp1,
  },
  { // Entry 422
    0x1.877eadc2fdfc2f0db1e8b78cd3fbfbd2p-3,
    -0x1.f68ee5b5bf356b10230944a18e70925cp-1,
    0x1.7981p1,
  },
  { // Entry 423
    -0x1.877eadc2fdfc2f0db1e8b78cd3fbfbd2p-3,
    -0x1.f68ee5b5bf356b10230944a18e70925cp-1,
    -0x1.7981p1,
  },
  { // Entry 424
    0x1.05e4fdf846632a8208d90de72d3a6da8p-3,
    -0x1.fbcbe23296fc61b96f382f35ea15c768p-1,
    0x1.81b5e4p1,
  },
  { // Entry 425
    -0x1.05e4fdf846632a8208d90de72d3a6da8p-3,
    -0x1.fbcbe23296fc61b96f382f35ea15c768p-1,
    -0x1.81b5e4p1,
  },
  { // Entry 426
    0x1.066f9b630b72dff16450e89afdf7e048p-4,
    -0x1.fef2b08943197cd3a8ba861095227c48p-1,
    0x1.89eac8p1,
  },
  { // Entry 427
    -0x1.066f9b630b72dff16450e89afdf7e048p-4,
    -0x1.fef2b08943197cd3a8ba861095227c48p-1,
    -0x1.89eac8p1,
  },
  { // Entry 428
    0x1.03bdf0b79ccf739529d54d422861046cp-2,
    0x1.ef41489fc2fe801a6fc8ae791438eb78p-1,
    -0x1.81b5eep2,
  },
  { // Entry 429
    -0x1.03bdf0b79ccf739529d54d422861046cp-2,
    0x1.ef41489fc2fe801a6fc8ae791438eb78p-1,
    0x1.81b5eep2,
  },
  { // Entry 430
    0x1.f67e8b95f5460ea369a803837b721abdp-2,
    0x1.be1d849ec649b797320e985d0b82ae85p-1,
    -0x1.714c26p2,
  },
  { // Entry 431
    -0x1.f67e8b95f5460ea369a803837b721abdp-2,
    0x1.be1d849ec649b797320e985d0b82ae85p-1,
    0x1.714c26p2,
  },
  { // Entry 432
    0x1.643070791751dc0636d1854d2bdbc5d4p-1,
    0x1.6fcb8c44bd30dd668148605969b1c161p-1,
    -0x1.60e25ep2,
  },
  { // Entry 433
    -0x1.643070791751dc0636d1854d2bdbc5d4p-1,
    0x1.6fcb8c44bd30dd668148605969b1c161p-1,
    0x1.60e25ep2,
  },
  { // Entry 434
    0x1.b5d536f59113a43af30e8c9db8a951a5p-1,
    0x1.096ad87c326622c42de34f92814cfa84p-1,
    -0x1.507896p2,
  },
  { // Entry 435
    -0x1.b5d536f59113a43af30e8c9db8a951a5p-1,
    0x1.096ad87c326622c42de34f92814cfa84p-1,
    0x1.507896p2,
  },
  { // Entry 436
    0x1.ead679985549140318349f512dca7a6bp-1,
    0x1.235b746a2a2eff2bf640dd8c04d35a5bp-2,
    -0x1.400ecep2,
  },
  { // Entry 437
    -0x1.ead679985549140318349f512dca7a6bp-1,
    0x1.235b746a2a2eff2bf640dd8c04d35a5bp-2,
    0x1.400ecep2,
  },
  { // Entry 438
    0x1.ffbca7010e0b0452f56075cfd5982880p-1,
    0x1.0693827b46cee3b661ac17114b5fe0fbp-5,
    -0x1.2fa506p2,
  },
  { // Entry 439
    -0x1.ffbca7010e0b0452f56075cfd5982880p-1,
    0x1.0693827b46cee3b661ac17114b5fe0fbp-5,
    0x1.2fa506p2,
  },
  { // Entry 440
    0x1.f329ca6bfc7425d89c2b4b9ad73ab108p-1,
    -0x1.c7b85d668e2abcc46542ca8527f0b801p-3,
    -0x1.1f3b3ep2,
  },
  { // Entry 441
    -0x1.f329ca6bfc7425d89c2b4b9ad73ab108p-1,
    -0x1.c7b85d668e2abcc46542ca8527f0b801p-3,
    0x1.1f3b3ep2,
  },
  { // Entry 442
    0x1.c5f06fb69427ac0f2d69428d82b5e669p-1,
    -0x1.d9a348d4f4363ba4562110db01ee84e8p-2,
    -0x1.0ed176p2,
  },
  { // Entry 443
    -0x1.c5f06fb69427ac0f2d69428d82b5e669p-1,
    -0x1.d9a348d4f4363ba4562110db01ee84e8p-2,
    0x1.0ed176p2,
  },
  { // Entry 444
    0x1.7b05d864ec9802adbc4b5577c233836ap-1,
    -0x1.5837ae8569c95846e6164d9636546120p-1,
    -0x1.fccf5ap1,
  },
  { // Entry 445
    -0x1.7b05d864ec9802adbc4b5577c233836ap-1,
    -0x1.5837ae8569c95846e6164d9636546120p-1,
    0x1.fccf5ap1,
  },
  { // Entry 446
    0x1.1750808185a998bbcecc3a6ac0cb2907p-1,
    -0x1.ad19c918883000b0b702ec080cf0122ep-1,
    -0x1.dbfbc8p1,
  },
  { // Entry 447
    -0x1.1750808185a998bbcecc3a6ac0cb2907p-1,
    -0x1.ad19c918883000b0b702ec080cf0122ep-1,
    0x1.dbfbc8p1,
  },
  { // Entry 448
    0x1.42ac0dd9495211816bf04ca53bce4beap-2,
    -0x1.e5ea94b2cf07add3d0d95ab3a30ad4abp-1,
    -0x1.bb2836p1,
  },
  { // Entry 449
    -0x1.42ac0dd9495211816bf04ca53bce4beap-2,
    -0x1.e5ea94b2cf07add3d0d95ab3a30ad4abp-1,
    0x1.bb2836p1,
  },
  { // Entry 450
    0x1.066fca39a70b52d06f2cd7eab69c31f2p-4,
    -0x1.fef2b02908559f92de892d240a2b0b49p-1,
    -0x1.9a54a4p1,
  },
  { // Entry 451
    -0x1.066fca39a70b52d06f2cd7eab69c31f2p-4,
    -0x1.fef2b02908559f92de892d240a2b0b49p-1,
    0x1.9a54a4p1,
  },
  { // Entry 452
    -0x1.877d931298e6fbc654f065536cff2b54p-3,
    -0x1.f68ef3792e592c3cefbce1d5ded64a92p-1,
    -0x1.798112p1,
  },
  { // Entry 453
    0x1.877d931298e6fbc654f065536cff2b54p-3,
    -0x1.f68ef3792e592c3cefbce1d5ded64a92p-1,
    0x1.798112p1,
  },
  { // Entry 454
    -0x1.bc4bc2875eb6d38eda3b49cb2320b561p-2,
    -0x1.cd4bda943eea13630f8e508f8744f2f2p-1,
    -0x1.58ad80p1,
  },
  { // Entry 455
    0x1.bc4bc2875eb6d38eda3b49cb2320b561p-2,
    -0x1.cd4bda943eea13630f8e508f8744f2f2p-1,
    0x1.58ad80p1,
  },
  { // Entry 456
    -0x1.4be47d6354c4ced53780b1b519acdec2p-1,
    -0x1.85dc54f49f324bdfc71d5749483b3318p-1,
    -0x1.37d9eep1,
  },
  { // Entry 457
    0x1.4be47d6354c4ced53780b1b519acdec2p-1,
    -0x1.85dc54f49f324bdfc71d5749483b3318p-1,
    0x1.37d9eep1,
  },
  { // Entry 458
    -0x1.a3ed8bcb35cbcf8c6089f82a91c31d5bp-1,
    -0x1.24ec93e04d4bdb54e20beaf383519af8p-1,
    -0x1.17065cp1,
  },
  { // Entry 459
    0x1.a3ed8bcb35cbcf8c6089f82a91c31d5bp-1,
    -0x1.24ec93e04d4bdb54e20beaf383519af8p-1,
    0x1.17065cp1,
  },
  { // Entry 460
    -0x1.e07ee496ea109654c42e171fdc4537c4p-1,
    -0x1.61a7983d4c16c451b68bf2f5b70f3b6ap-2,
    -0x1.ec6594p0,
  },
  { // Entry 461
    0x1.e07ee496ea109654c42e171fdc4537c4p-1,
    -0x1.61a7983d4c16c451b68bf2f5b70f3b6ap-2,
    0x1.ec6594p0,
  },
  { // Entry 462
    -0x1.fda2522219689d0e8069d90f5c969b92p-1,
    -0x1.89504a8de6c9ecac663e67583cab47e8p-4,
    -0x1.aabe70p0,
  },
  { // Entry 463
    0x1.fda2522219689d0e8069d90f5c969b92p-1,
    -0x1.89504a8de6c9ecac663e67583cab47e8p-4,
    0x1.aabe70p0,
  },
  { // Entry 464
    -0x1.f96fe802fe570372d0fcb6e934b43061p-1,
    0x1.46dbec9ea3a5f08ba73aa69e7e22de1cp-3,
    -0x1.69174cp0,
  },
  { // Entry 465
    0x1.f96fe802fe570372d0fcb6e934b43061p-1,
    0x1.46dbec9ea3a5f08ba73aa69e7e22de1cp-3,
    0x1.69174cp0,
  },
  { // Entry 466
    -0x1.d42ded56ae88a6e1cf270af27e6f1804p-1,
    0x1.9e7f5cf075d1ec4ef69c9c67b62c27cbp-2,
    -0x1.277028p0,
  },
  { // Entry 467
    0x1.d42ded56ae88a6e1cf270af27e6f1804p-1,
    0x1.9e7f5cf075d1ec4ef69c9c67b62c27cbp-2,
    0x1.277028p0,
  },
  { // Entry 468
    -0x1.904c45326d6dde224381d1d590ada41cp-1,
    0x1.3f39fcc017653d2636837a55fdf6d2d4p-1,
    -0x1.cb920ap-1,
  },
  { // Entry 469
    0x1.904c45326d6dde224381d1d590ada41cp-1,
    0x1.3f39fcc017653d2636837a55fdf6d2d4p-1,
    0x1.cb920ap-1,
  },
  { // Entry 470
    -0x1.323b9cadbb19e75a44483fb64ad8ddf6p-1,
    0x1.9a52d5c700daa3dc8cf8f5a71f2df289p-1,
    -0x1.4843c4p-1,
  },
  { // Entry 471
    0x1.323b9cadbb19e75a44483fb64ad8ddf6p-1,
    0x1.9a52d5c700daa3dc8cf8f5a71f2df289p-1,
    0x1.4843c4p-1,
  },
  { // Entry 472
    -0x1.80462654bde766faf47f3140e290996dp-2,
    0x1.da94cd383dd7a3b91a2fc88ff905a6a0p-1,
    -0x1.89eafcp-2,
  },
  { // Entry 473
    0x1.80462654bde766faf47f3140e290996dp-2,
    0x1.da94cd383dd7a3b91a2fc88ff905a6a0p-1,
    0x1.89eafcp-2,
  },
  { // Entry 474
    -0x1.05e4ca21f386a82bc2e4efcdebb1962bp-3,
    0x1.fbcbe3de58e66c3283bc810d16c45833p-1,
    -0x1.069ce0p-3,
  },
  { // Entry 475
    0x1.05e4ca21f386a82bc2e4efcdebb1962bp-3,
    0x1.fbcbe3de58e66c3283bc810d16c45833p-1,
    0x1.069ce0p-3,
  },
  { // Entry 476
    0x1.05e423830be01f9fe3c57d06867e0056p-3,
    0x1.fbcbe93d48563d51b6e9d6efdb62495cp-1,
    0x1.069c38p-3,
  },
  { // Entry 477
    -0x1.05e423830be01f9fe3c57d06867e0056p-3,
    0x1.fbcbe93d48563d51b6e9d6efdb62495cp-1,
    -0x1.069c38p-3,
  },
  { // Entry 478
    0x1.8045d87852f1307fea6dc751c4d15992p-2,
    0x1.da94dcfb1cd15853ce848ffb0264ad08p-1,
    0x1.89eaa8p-2,
  },
  { // Entry 479
    -0x1.8045d87852f1307fea6dc751c4d15992p-2,
    0x1.da94dcfb1cd15853ce848ffb0264ad08p-1,
    -0x1.89eaa8p-2,
  },
  { // Entry 480
    0x1.323b7b04ee88cff98b2a1620e1f61a01p-1,
    0x1.9a52eee5e35377d554ace881bdc4725bp-1,
    0x1.48439ap-1,
  },
  { // Entry 481
    -0x1.323b7b04ee88cff98b2a1620e1f61a01p-1,
    0x1.9a52eee5e35377d554ace881bdc4725bp-1,
    -0x1.48439ap-1,
  },
  { // Entry 482
    0x1.904c2b02aa59528ce044bf2213c96859p-1,
    0x1.3f3a1d9657ff6aa498c46f6faaf03b90p-1,
    0x1.cb91e0p-1,
  },
  { // Entry 483
    -0x1.904c2b02aa59528ce044bf2213c96859p-1,
    0x1.3f3a1d9657ff6aa498c46f6faaf03b90p-1,
    -0x1.cb91e0p-1,
  },
  { // Entry 484
    0x1.d42ddd25b3797e6a679f76e05e6c3e08p-1,
    0x1.9e7fa617a1a3a400a7f59aa879088e31p-2,
    0x1.277014p0,
  },
  { // Entry 485
    -0x1.d42ddd25b3797e6a679f76e05e6c3e08p-1,
    0x1.9e7fa617a1a3a400a7f59aa879088e31p-2,
    -0x1.277014p0,
  },
  { // Entry 486
    0x1.f96fe1a0b12d0ad4fa8c82d8af989c5ap-1,
    0x1.46dc8a919b27840cda6e18a079da459cp-3,
    0x1.691738p0,
  },
  { // Entry 487
    -0x1.f96fe1a0b12d0ad4fa8c82d8af989c5ap-1,
    0x1.46dc8a919b27840cda6e18a079da459cp-3,
    -0x1.691738p0,
  },
  { // Entry 488
    0x1.fda255f96094d8fe4e859c4cf0dd68a5p-1,
    -0x1.894f0c0872415663b7f9e4e4801deaf0p-4,
    0x1.aabe5cp0,
  },
  { // Entry 489
    -0x1.fda255f96094d8fe4e859c4cf0dd68a5p-1,
    -0x1.894f0c0872415663b7f9e4e4801deaf0p-4,
    -0x1.aabe5cp0,
  },
  { // Entry 490
    0x1.e07ef267748b982778f8d50d2981bb3ap-1,
    -0x1.61a74d29774ae4e3bc5533a2ea08a14ap-2,
    0x1.ec6580p0,
  },
  { // Entry 491
    -0x1.e07ef267748b982778f8d50d2981bb3ap-1,
    -0x1.61a74d29774ae4e3bc5533a2ea08a14ap-2,
    -0x1.ec6580p0,
  },
  { // Entry 492
    0x1.a3eda2adb01143fb21453b20bd1748fep-1,
    -0x1.24ec7311bd7b2255f9b890b3ff5899f4p-1,
    0x1.170652p1,
  },
  { // Entry 493
    -0x1.a3eda2adb01143fb21453b20bd1748fep-1,
    -0x1.24ec7311bd7b2255f9b890b3ff5899f4p-1,
    -0x1.170652p1,
  },
  { // Entry 494
    0x1.4be49bd88a64a0bb414ddacac4fa8de9p-1,
    -0x1.85dc3b06c435f524c873d9b5eba3def8p-1,
    0x1.37d9e4p1,
  },
  { // Entry 495
    -0x1.4be49bd88a64a0bb414ddacac4fa8de9p-1,
    -0x1.85dc3b06c435f524c873d9b5eba3def8p-1,
    -0x1.37d9e4p1,
  },
  { // Entry 496
    0x1.bc4c0a9b3782e220ae55786369ccf190p-2,
    -0x1.cd4bc93947e86671ac7f
```
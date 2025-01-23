Response:
Let's break down the thought process for answering this complex prompt.

**1. Initial Understanding and Goal Setting:**

The core task is to analyze a code snippet (specifically a data file) within the Android bionic library and explain its purpose and context. The prompt explicitly asks for a summary of its functionality, connection to Android, details about libc functions (though none are present in this *data* file), dynamic linker information (also not directly present, but implied by the library's nature), error handling, how to reach this code, and a Frida hook example. The prompt also highlights it's part 2 of 5, suggesting a larger context likely involving the `sin` function.

**2. First Pass - Content Examination:**

The provided code is a large array of floating-point number pairs. The format strongly suggests a lookup table. The negative signs in alternating entries further suggest the data represents a function with odd symmetry (like sine). The file name "sin_intel_data.handroid" reinforces this idea, indicating it's likely data for the sine function optimized for Intel architectures on Android.

**3. Functionality Deduction (Core Idea):**

Based on the data format and file name, the primary function is to provide pre-calculated values for the sine function. This is a common optimization technique in math libraries for performance reasons. Instead of computing the sine of an angle directly every time, the library can look up a nearby pre-computed value and potentially interpolate for higher accuracy.

**4. Connecting to Android:**

Since this file is in bionic, the Android C library, it's directly used by Android. The sine function is fundamental and used throughout the Android framework, NDK, and even by apps. Examples include graphics rendering, animations, physics simulations, audio processing, etc.

**5. Addressing the "libc function" Requirement:**

The crucial realization is that this is a *data* file, not code. Therefore, it doesn't *implement* any libc functions directly. However, it's *used* by the `sin` function (likely in `libm.so`), which *is* a libc function. So, the explanation should focus on how this data *supports* the `sin` function's implementation.

**6. Dynamic Linker Aspect:**

While this file isn't executable code, `libm.so` (which uses this data) is a shared library. Therefore, the dynamic linker is involved in loading `libm.so` into a process's memory. A typical SO layout and the linking process need to be described generally, focusing on how symbols are resolved and the library is mapped.

**7. Logical Inference and Assumptions:**

* **Assumption:** The first value in each pair is an input to the sine function (an angle), and the second value is the corresponding pre-calculated sine value.
* **Assumption:** The data is sorted or organized in a way that allows for efficient lookup (e.g., by input value).
* **Inference:** The library likely uses some algorithm to find the closest entry in the table to the desired input and potentially interpolates for greater precision.

**8. User/Programming Errors:**

Focus on how developers would *use* the `sin` function. Common errors involve providing angles in the wrong units (degrees vs. radians), overflowing input values, or misunderstanding the function's domain and range.

**9. Android Framework/NDK Path:**

Trace a high-level path:
    * App makes a call to a framework function (e.g., animation).
    * Framework function calls a native method (JNI).
    * Native method uses NDK math functions (like `sin`).
    * NDK `sin` call resolves to the bionic `sin` implementation.
    * The bionic `sin` implementation uses this data file.

**10. Frida Hooking:**

Focus on hooking the `sin` function itself. Show how to intercept calls, log arguments, and potentially modify the return value. It's important to hook the function in `libm.so`.

**11. Part 2 Summary:**

Given that it's part 2 of 5, the summary should reiterate the core purpose of the data file within the broader context of the `sin` function's implementation. Emphasize that this specific part is the *data* component.

**12. Structuring the Answer:**

Organize the information logically according to the prompt's requirements: functionality, Android relation, libc function explanation (adapted for a data file), dynamic linker, logic/assumptions, user errors, Android framework path, Frida hook, and finally, the part 2 summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus on specific libc functions within the *file*. **Correction:** Realize it's a data file, so focus on how it supports the `sin` function.
* **Initial thought:** Explain the *implementation* of dynamic linking in detail. **Correction:** Provide a general overview relevant to how `libm.so` is loaded.
* **Initial thought:**  Assume the data is used directly without processing. **Correction:** Acknowledge the possibility of interpolation.
* **Frida example:**  Initially consider hooking lower-level memory access. **Correction:** Hooking the `sin` function itself is more direct and practical for demonstration.

By following this structured thought process, including analyzing the content, making logical deductions, addressing each part of the prompt, and refining the approach as needed, a comprehensive and accurate answer can be constructed.
好的，我们来归纳一下这个代码片段（`sin_intel_data.handroid` 文件的部分内容）的功能。

**功能归纳:**

这段代码片段是 Android Bionic 库中 `libm.so` 库用于计算 `sin` 函数的一个查找表（lookup table）的部分数据。

**具体来说，它的功能是：**

1. **存储预先计算的 `sin` 函数的输入和输出值：**  每一行 `{ 输入值, 输出值 }` 代表一个预先计算好的 `sin(输入值)` 的结果。
2. **用于提高 `sin` 函数的计算效率：**  在实际计算 `sin(x)` 时，`libm.so` 中的 `sin` 函数实现可能会先在这个查找表中寻找与 `x` 接近的输入值，然后使用对应的输出值或者通过插值计算得到最终结果，而不是每次都从头开始进行复杂的数学运算。
3. **针对特定硬件平台（Intel）的优化：** 文件名中的 `intel` 表明这些数据可能是针对 Intel 架构进行过特定优化的。
4. **提供一定范围内的 `sin` 函数值：**  观察数据，输入值有正有负，且分布在不同的数量级上，表明这个查找表覆盖了 `sin` 函数定义域的一部分。
5. **可能包含对称性优化：**  很多连续的条目是输入值和输出值的正负对称关系，这可能暗示了 `sin(-x) = -sin(x)` 的数学特性被利用来减少存储的数据量。

**与 Android 功能的关系：**

这个数据文件是 Android 系统底层数学库的一部分，它直接影响到所有依赖 `sin` 函数的 Android 功能的性能和精度。

**举例说明：**

* **图形渲染：**  Android 的图形系统（如 SurfaceFlinger、Skia）在进行 2D/3D 渲染、动画效果计算时，经常需要用到三角函数，例如旋转、缩放、路径计算等。`sin` 函数的快速计算直接影响到这些渲染操作的流畅性。
* **音频处理：**  Android 的音频框架在生成音频波形、进行音频分析和合成时，也可能使用 `sin` 函数生成正弦波等基础信号。
* **动画和过渡效果：**  Android 应用中的各种动画效果，例如淡入淡出、滑动、旋转等，其计算过程可能涉及到三角函数来控制动画的速度和轨迹。
* **传感器数据处理：**  某些传感器数据（例如陀螺仪）的处理可能需要用到三角函数进行角度和方向的计算。

**关于其他问题：**

由于这段代码片段本身是数据，而非可执行代码，因此：

* **详细解释 libc 函数的功能是如何实现的：**  这里没有直接涉及 libc 函数的实现，它只是 `sin` 函数的辅助数据。`sin` 函数的实现通常会包含多项式逼近、泰勒展开、CORDIC 算法等数学方法。
* **对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**  这个数据文件会被编译进 `libm.so` 库中。动态链接器在加载应用或系统服务时，会将 `libm.so` 加载到内存中的特定区域。在链接过程中，如果代码中调用了 `sin` 函数，链接器会找到 `libm.so` 中 `sin` 函数的符号，并将调用地址指向 `libm.so` 中 `sin` 函数的实现。`sin` 函数的实现就会使用这个预先计算的数据表。
* **如果做了逻辑推理，请给出假设输入与输出：**  例如，Entry 354 `{ 0x1.6c548bfcce6953f19a8d2dd480d9320cp-1, 0x1.956p-1 }`，假设输入是十六进制浮点数 `0x1.6c548bfcce6953f19a8d2dd480d9320cp-1`（大约是 0.80078125），那么预期的 `sin` 输出值是 `0x1.956p-1`（大约是 0.578125）。
* **如果涉及用户或者编程常见的使用错误，请举例说明：**  用户或开发者不会直接操作这个数据文件。常见的使用错误是在调用 `sin` 函数时传入了错误单位的角度（例如使用角度而不是弧度），或者超出函数定义域的值。
* **说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

   1. **Android Framework 调用:** 例如，一个 `View` 的 `rotation` 属性被设置了一个动画。
   2. **动画系统处理:**  Android 的动画框架会计算每一帧的旋转角度。
   3. **Native 代码调用 (JNI):**  动画框架的某些部分可能使用 Native 代码实现，并通过 JNI (Java Native Interface) 调用到 Native 层。
   4. **NDK 数学库使用:** Native 代码可能会调用 NDK 提供的数学函数，例如 `sin` 或相关的变换函数。
   5. **Bionic `libm.so` 调用:** NDK 的数学函数通常会链接到 Bionic 的 `libm.so` 库。
   6. **查找表使用:**  `libm.so` 中的 `sin` 函数实现会访问 `sin_intel_data.handroid` 中存储的数据来辅助计算。

   **Frida Hook 示例：**

   ```javascript
   if (Process.arch === 'arm64') {
     const libm = Module.load("libm.so");
     const sin_addr = libm.findExportByName("sin");

     if (sin_addr) {
       Interceptor.attach(sin_addr, {
         onEnter: function (args) {
           const input = args[0].toDouble();
           console.log("Calling sin with input:", input);
         },
         onLeave: function (retval) {
           const output = retval.toDouble();
           console.log("sin returned:", output);
         }
       });
       console.log("Successfully hooked sin function in libm.so");
     } else {
       console.log("Failed to find sin function in libm.so");
     }
   } else {
     console.log("This script is designed for arm64 architecture.");
   }
   ```

   这个 Frida 脚本会尝试 hook `libm.so` 中的 `sin` 函数，并在函数调用前后打印输入和输出值。通过观察这些日志，你可以跟踪 `sin` 函数的调用情况。要更深入地调试数据表的访问，可能需要更底层的 hook，例如 hook 访问数据表内存地址的代码。

**总结：**

这段代码片段是 `libm.so` 中 `sin` 函数实现的关键数据部分，通过存储预先计算的输入输出值来优化 `sin` 函数的计算效率，这直接影响到 Android 系统中各种依赖三角函数的功能的性能。它是 Android 底层数学库的重要组成部分。

### 提示词
```
这是目录为bionic/tests/math_data/sin_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```c
6cfa3721p-5,
    -0x1.95361b8f7697dp-5
  },
  { // Entry 354
    0x1.6c548bfcce6953f19a8d2dd480d9320cp-1,
    0x1.956p-1
  },
  { // Entry 355
    -0x1.6c548bfcce6953f19a8d2dd480d9320cp-1,
    -0x1.956p-1
  },
  { // Entry 356
    0x1.ffeffdbf67ca6711a57b7d82140093c6p-1,
    0x1.962p0
  },
  { // Entry 357
    -0x1.ffeffdbf67ca6711a57b7d82140093c6p-1,
    -0x1.962p0
  },
  { // Entry 358
    0x1.9708213bf67f4857135077d50826f588p-5,
    0x1.97330d2ea16d9p-5
  },
  { // Entry 359
    -0x1.9708213bf67f4857135077d50826f588p-5,
    -0x1.97330d2ea16d9p-5
  },
  { // Entry 360
    0x1.972bf92713d50858e64c1b9b26aeecd0p-5,
    0x1.9756f073b6b61p-5
  },
  { // Entry 361
    -0x1.972bf92713d50858e64c1b9b26aeecd0p-5,
    -0x1.9756f073b6b61p-5
  },
  { // Entry 362
    0x1.976845ebe71188580e468bad00ce23ecp-5,
    0x1.97935055cec1bp-5
  },
  { // Entry 363
    -0x1.976845ebe71188580e468bad00ce23ecp-5,
    -0x1.97935055cec1bp-5
  },
  { // Entry 364
    0x1.97535cee51a42806e15f6f878524e5b7p-4,
    0x1.980p-4
  },
  { // Entry 365
    -0x1.97535cee51a42806e15f6f878524e5b7p-4,
    -0x1.980p-4
  },
  { // Entry 366
    0x1.6f494c3356177000006502cdff975b08p-1,
    0x1.999999a42160cp-1
  },
  { // Entry 367
    -0x1.6f494c3356177000006502cdff975b08p-1,
    -0x1.999999a42160cp-1
  },
  { // Entry 368
    0x1.6f494c37edd6d800006dc76aee4cc8e4p-1,
    0x1.999999aab8f50p-1
  },
  { // Entry 369
    -0x1.6f494c37edd6d800006dc76aee4cc8e4p-1,
    -0x1.999999aab8f50p-1
  },
  { // Entry 370
    0x1.6fa912bdeaab280000164f16dd649356p-1,
    0x1.9a2324b9c6326p-1
  },
  { // Entry 371
    -0x1.6fa912bdeaab280000164f16dd649356p-1,
    -0x1.9a2324b9c6326p-1
  },
  { // Entry 372
    0x1.70c7ef4ef9b347ed234ca6131be1b786p-1,
    0x1.9bcp-1
  },
  { // Entry 373
    -0x1.70c7ef4ef9b347ed234ca6131be1b786p-1,
    -0x1.9bcp-1
  },
  { // Entry 374
    0x1.ff28176ad3163ea168c9991f155f875bp-1,
    0x1.a0d1d817d6c4ap0
  },
  { // Entry 375
    -0x1.ff28176ad3163ea168c9991f155f875bp-1,
    -0x1.a0d1d817d6c4ap0
  },
  { // Entry 376
    0x1.749468a7248dd26161e93d78928c66dep-1,
    0x1.a141c9de12fdfp-1
  },
  { // Entry 377
    -0x1.749468a7248dd26161e93d78928c66dep-1,
    -0x1.a141c9de12fdfp-1
  },
  { // Entry 378
    0x1.754ebb7e73f452ab49c615f0e8300d5cp-1,
    0x1.a251bc6766f20p-1
  },
  { // Entry 379
    -0x1.754ebb7e73f452ab49c615f0e8300d5cp-1,
    -0x1.a251bc6766f20p-1
  },
  { // Entry 380
    -0x1.7c3bfefa74bd07fe21336caac372a73ep-1,
    0x1.a2689ae1b86ddp62
  },
  { // Entry 381
    0x1.7c3bfefa74bd07fe21336caac372a73ep-1,
    -0x1.a2689ae1b86ddp62
  },
  { // Entry 382
    -0x1.ffff4f3648e02f9f494f42eb822f262bp-1,
    0x1.a3f66180c4550p100
  },
  { // Entry 383
    0x1.ffff4f3648e02f9f494f42eb822f262bp-1,
    -0x1.a3f66180c4550p100
  },
  { // Entry 384
    -0x1.1cf463983c0e28023161b7d0d2938e37p-3,
    0x1.a3fdd2a5286c3p1
  },
  { // Entry 385
    0x1.1cf463983c0e28023161b7d0d2938e37p-3,
    -0x1.a3fdd2a5286c3p1
  },
  { // Entry 386
    0x1.feb7948d224d7e759a7c9dd768ded727p-1,
    0x1.a44p0
  },
  { // Entry 387
    -0x1.feb7948d224d7e759a7c9dd768ded727p-1,
    -0x1.a44p0
  },
  { // Entry 388
    0x1.78801e3e1166482dce6208e98d3cc142p-1,
    0x1.a701ef3c7d54bp-1
  },
  { // Entry 389
    -0x1.78801e3e1166482dce6208e98d3cc142p-1,
    -0x1.a701ef3c7d54bp-1
  },
  { // Entry 390
    -0x1.fff11e871d59c3e1333db5475bb57e27p-1,
    0x1.a8c01fd43c0p537
  },
  { // Entry 391
    0x1.fff11e871d59c3e1333db5475bb57e27p-1,
    -0x1.a8c01fd43c0p537
  },
  { // Entry 392
    0x1.fdfa4366eb7337e6d973c4cb8f1a244ap-1,
    0x1.a8e29b7602f3bp0
  },
  { // Entry 393
    -0x1.fdfa4366eb7337e6d973c4cb8f1a244ap-1,
    -0x1.a8e29b7602f3bp0
  },
  { // Entry 394
    0x1.fde98b94e7947a04229d26eeb2bb4280p-1,
    0x1.a94p0
  },
  { // Entry 395
    -0x1.fde98b94e7947a04229d26eeb2bb4280p-1,
    -0x1.a94p0
  },
  { // Entry 396
    0x1.7931cba10000880000068f94098018a7p-2,
    0x1.aa445fce93b82p2
  },
  { // Entry 397
    -0x1.7931cba10000880000068f94098018a7p-2,
    -0x1.aa445fce93b82p2
  },
  { // Entry 398
    0x1.7af3f76c7a708834b4072f59ac71a0bap-1,
    0x1.aaa3fbc359fbep-1
  },
  { // Entry 399
    -0x1.7af3f76c7a708834b4072f59ac71a0bap-1,
    -0x1.aaa3fbc359fbep-1
  },
  { // Entry 400
    0x1.fd74e53ae32fcd8467bcf50da1d0f563p-6,
    0x1.abdd3dbd4d860p119
  },
  { // Entry 401
    -0x1.fd74e53ae32fcd8467bcf50da1d0f563p-6,
    -0x1.abdd3dbd4d860p119
  },
  { // Entry 402
    0x1.7d4a7bf183a3329ed434c0c4dd78b1d9p-1,
    0x1.ae2165a0c9f8ep-1
  },
  { // Entry 403
    -0x1.7d4a7bf183a3329ed434c0c4dd78b1d9p-1,
    -0x1.ae2165a0c9f8ep-1
  },
  { // Entry 404
    0x1.b81410edc79e0837507a3eef8d553bd6p-2,
    0x1.ae8dfefcfe13bp2
  },
  { // Entry 405
    -0x1.b81410edc79e0837507a3eef8d553bd6p-2,
    -0x1.ae8dfefcfe13bp2
  },
  { // Entry 406
    -0x1.ff751561dc5097fefe499301d034a0edp-2,
    0x1.b5597f950ee8cp29
  },
  { // Entry 407
    0x1.ff751561dc5097fefe499301d034a0edp-2,
    -0x1.b5597f950ee8cp29
  },
  { // Entry 408
    0x1.027d184afb1984ca1d21b1ac928d5391p-52,
    0x1.bab62ed655019p970
  },
  { // Entry 409
    -0x1.027d184afb1984ca1d21b1ac928d5391p-52,
    -0x1.bab62ed655019p970
  },
  { // Entry 410
    0x1.bc572e5e413e17fcb2246d40249a005fp-10,
    0x1.bc573c4ffffffp-10
  },
  { // Entry 411
    -0x1.bc572e5e413e17fcb2246d40249a005fp-10,
    -0x1.bc573c4ffffffp-10
  },
  { // Entry 412
    0x1.fb300f1e39afe80471f993abb8cfa428p-1,
    0x1.bef5cd25ab1adp9
  },
  { // Entry 413
    -0x1.fb300f1e39afe80471f993abb8cfa428p-1,
    -0x1.bef5cd25ab1adp9
  },
  { // Entry 414
    0x1.b1baaf622d3a27fd27d0716f7d08d992p-2,
    0x1.bfdf6df2a24c1p-2
  },
  { // Entry 415
    -0x1.b1baaf622d3a27fd27d0716f7d08d992p-2,
    -0x1.bfdf6df2a24c1p-2
  },
  { // Entry 416
    0x1.88fb762c35ce37fecbb4748d01feffcep-1,
    0x1.bfffffdffffffp-1
  },
  { // Entry 417
    -0x1.88fb762c35ce37fecbb4748d01feffcep-1,
    -0x1.bfffffdffffffp-1
  },
  { // Entry 418
    0x1.fe0ebff99ab8c80ce5939f1f072c2e91p-1,
    0x1.c2b489520e376p920
  },
  { // Entry 419
    -0x1.fe0ebff99ab8c80ce5939f1f072c2e91p-1,
    -0x1.c2b489520e376p920
  },
  { // Entry 420
    0x1.cf7f749f2a8357f7feab685ff6f8b624p-4,
    0x1.c54beb0085470p5
  },
  { // Entry 421
    -0x1.cf7f749f2a8357f7feab685ff6f8b624p-4,
    -0x1.c54beb0085470p5
  },
  { // Entry 422
    0x1.b6facf665891482ea8c61f5ca32f280dp-2,
    0x1.c5ad34f5f472ap-2
  },
  { // Entry 423
    -0x1.b6facf665891482ea8c61f5ca32f280dp-2,
    -0x1.c5ad34f5f472ap-2
  },
  { // Entry 424
    0x1.b851cd9b84ee683dc6bd3899ea81dbf9p-2,
    0x1.c728fc2f34bd6p-2
  },
  { // Entry 425
    -0x1.b851cd9b84ee683dc6bd3899ea81dbf9p-2,
    -0x1.c728fc2f34bd6p-2
  },
  { // Entry 426
    0x1.ba21b53cf2ff2832606f65eeeb4e3aafp-2,
    0x1.c92b0f6105089p-2
  },
  { // Entry 427
    -0x1.ba21b53cf2ff2832606f65eeeb4e3aafp-2,
    -0x1.c92b0f6105089p-2
  },
  { // Entry 428
    0x1.c9a2b68e30ec77c4e76c889704394a50p-5,
    0x1.c9dfbbe9ec704p-5
  },
  { // Entry 429
    -0x1.c9a2b68e30ec77c4e76c889704394a50p-5,
    -0x1.c9dfbbe9ec704p-5
  },
  { // Entry 430
    0x1.f370115c9ab35743e12217c6122e1a28p-1,
    0x1.caf31bd7ee217p0
  },
  { // Entry 431
    -0x1.f370115c9ab35743e12217c6122e1a28p-1,
    -0x1.caf31bd7ee217p0
  },
  { // Entry 432
    -0x1.dd38a1f1d289b6173115721bc58e298dp-54,
    0x1.cb44e86bc192bp648
  },
  { // Entry 433
    0x1.dd38a1f1d289b6173115721bc58e298dp-54,
    -0x1.cb44e86bc192bp648
  },
  { // Entry 434
    0x1.dd38a1f1d289b6173115721bc55a56a8p-53,
    0x1.cb44e86bc192bp649
  },
  { // Entry 435
    -0x1.dd38a1f1d289b6173115721bc55a56a8p-53,
    -0x1.cb44e86bc192bp649
  },
  { // Entry 436
    0x1.c7885aef33a94ffc5ae06be9444efad5p-3,
    0x1.cb6p-3
  },
  { // Entry 437
    -0x1.c7885aef33a94ffc5ae06be9444efad5p-3,
    -0x1.cb6p-3
  },
  { // Entry 438
    0x1.cd279aa6196b57f9be71cdffdd9f1919p-4,
    0x1.ce2271d2f662fp-4
  },
  { // Entry 439
    -0x1.cd279aa6196b57f9be71cdffdd9f1919p-4,
    -0x1.ce2271d2f662fp-4
  },
  { // Entry 440
    0x1.930b705f9fad17fb56813a45973a8d72p-1,
    0x1.d0000000004p-1
  },
  { // Entry 441
    -0x1.930b705f9fad17fb56813a45973a8d72p-1,
    -0x1.d0000000004p-1
  },
  { // Entry 442
    0x1.7ef24c8e67d9a8017a031f38e24cce06p-1,
    0x1.d01p199
  },
  { // Entry 443
    -0x1.7ef24c8e67d9a8017a031f38e24cce06p-1,
    -0x1.d01p199
  },
  { // Entry 444
    0x1.ffff124c001aafb1f175ccb531c053b0p-1,
    0x1.d024ba6f953cfp1000
  },
  { // Entry 445
    -0x1.ffff124c001aafb1f175ccb531c053b0p-1,
    -0x1.d024ba6f953cfp1000
  },
  { // Entry 446
    -0x1.f83a0983dd15d00301e2df21e3bee635p-2,
    0x1.d4067c60f471ep1
  },
  { // Entry 447
    0x1.f83a0983dd15d00301e2df21e3bee635p-2,
    -0x1.d4067c60f471ep1
  },
  { // Entry 448
    0x1.d79b9896ff55484d2591b677d54ea46fp-5,
    0x1.d7de6263bcaabp-5
  },
  { // Entry 449
    -0x1.d79b9896ff55484d2591b677d54ea46fp-5,
    -0x1.d7de6263bcaabp-5
  },
  { // Entry 450
    0x1.ed0b908a2982f7fd9c80bc1051dd4080p-1,
    0x1.d800000002274p0
  },
  { // Entry 451
    -0x1.ed0b908a2982f7fd9c80bc1051dd4080p-1,
    -0x1.d800000002274p0
  },
  { // Entry 452
    -0x1.f2c217cbc7dcc919243a7c434a209f9ap-1,
    0x1.d96e058p488
  },
  { // Entry 453
    0x1.f2c217cbc7dcc919243a7c434a209f9ap-1,
    -0x1.d96e058p488
  },
  { // Entry 454
    0x1.98dcd093377928000000000000167dc7p-1,
    0x1.d98c4c612718dp-1
  },
  { // Entry 455
    -0x1.98dcd093377928000000000000167dc7p-1,
    -0x1.d98c4c612718dp-1
  },
  { // Entry 456
    0x1.db3ba8775ca257da3bd5449d396a66e2p-5,
    0x1.db8p-5
  },
  { // Entry 457
    -0x1.db3ba8775ca257da3bd5449d396a66e2p-5,
    -0x1.db8p-5
  },
  { // Entry 458
    -0x1.9fee37697d5828031a6a2679c1433457p-2,
    0x1.de386d6090303p200
  },
  { // Entry 459
    0x1.9fee37697d5828031a6a2679c1433457p-2,
    -0x1.de386d6090303p200
  },
  { // Entry 460
    -0x1.5361ee6553188036e9dfcab428deb4e1p-53,
    0x1.de5e5054e921bp35
  },
  { // Entry 461
    0x1.5361ee6553188036e9dfcab428deb4e1p-53,
    -0x1.de5e5054e921bp35
  },
  { // Entry 462
    0x1.fec48d5e769ebe37448c10e0a7a0ecb1p-1,
    0x1.df77ddf77ddf4p10
  },
  { // Entry 463
    -0x1.fec48d5e769ebe37448c10e0a7a0ecb1p-1,
    -0x1.df77ddf77ddf4p10
  },
  { // Entry 464
    -0x1.2902a83d72632800003d1149b7e6c0fbp-1,
    0x1.e1562b0448a86p1
  },
  { // Entry 465
    0x1.2902a83d72632800003d1149b7e6c0fbp-1,
    -0x1.e1562b0448a86p1
  },
  { // Entry 466
    0x1.9e26c7bc96b68800000d4736ff132035p-1,
    0x1.e2700cdc86635p-1
  },
  { // Entry 467
    -0x1.9e26c7bc96b68800000d4736ff132035p-1,
    -0x1.e2700cdc86635p-1
  },
  { // Entry 468
    0x1.e6494911eedd18d0f1915fd4f6495469p-7,
    0x1.e64ddaf7bd730p-7
  },
  { // Entry 469
    -0x1.e6494911eedd18d0f1915fd4f6495469p-7,
    -0x1.e64ddaf7bd730p-7
  },
  { // Entry 470
    0x1.eb26c690bda2484a6c020a9c052ea846p-5,
    0x1.eb7239bca8afap-5
  },
  { // Entry 471
    -0x1.eb26c690bda2484a6c020a9c052ea846p-5,
    -0x1.eb7239bca8afap-5
  },
  { // Entry 472
    0x1.c73238790a4ce801e04107b2546b4ae3p-3,
    0x1.ef7b83f7bdef4p3
  },
  { // Entry 473
    -0x1.c73238790a4ce801e04107b2546b4ae3p-3,
    -0x1.ef7b83f7bdef4p3
  },
  { // Entry 474
    0x1.ed1b575acb8c881082ce315074a8a42ap-3,
    0x1.f20000000109bp-3
  },
  { // Entry 475
    -0x1.ed1b575acb8c881082ce315074a8a42ap-3,
    -0x1.f20000000109bp-3
  },
  { // Entry 476
    0x1.c1b50a56c8809800000282a516c13e25p-1,
    0x1.f40ca67a9e8d7p9
  },
  { // Entry 477
    -0x1.c1b50a56c8809800000282a516c13e25p-1,
    -0x1.f40ca67a9e8d7p9
  },
  { // Entry 478
    0x1.e321fea643a968083208768e9e2cd28ep-2,
    0x1.f7224d2c77540p-2
  },
  { // Entry 479
    -0x1.e321fea643a968083208768e9e2cd28ep-2,
    -0x1.f7224d2c77540p-2
  },
  { // Entry 480
    0x1.c1269b020a107ffc00612a563a919686p-3,
    0x1.f78a0d05e60e2p6
  },
  { // Entry 481
    -0x1.c1269b020a107ffc00612a563a919686p-3,
    -0x1.f78a0d05e60e2p6
  },
  { // Entry 482
    0x1.f76cae28a07747fffcd453a0142c2ec1p-5,
    0x1.f7bdef7bdf073p-5
  },
  { // Entry 483
    -0x1.f76cae28a07747fffcd453a0142c2ec1p-5,
    -0x1.f7bdef7bdf073p-5
  },
  { // Entry 484
    0x1.e42c139dc2053807b9440f1a28f7c9b9p-2,
    0x1.f8502d5955443p-2
  },
  { // Entry 485
    -0x1.e42c139dc2053807b9440f1a28f7c9b9p-2,
    -0x1.f8502d5955443p-2
  },
  { // Entry 486
    0x1.0fa749e07f63fc9d01c834de47654acbp-9,
    0x1.f8fc824d2693bp61
  },
  { // Entry 487
    -0x1.0fa749e07f63fc9d01c834de47654acbp-9,
    -0x1.f8fc824d2693bp61
  },
  { // Entry 488
    0x1.ffa80324e2d8ebc02f323ed49eb97a6cp-1,
    0x1.f8fffffffffffp2
  },
  { // Entry 489
    -0x1.ffa80324e2d8ebc02f323ed49eb97a6cp-1,
    -0x1.f8fffffffffffp2
  },
  { // Entry 490
    -0x1.7cdf79d5e37b8b212eff86d2ffe2044bp-1,
    0x1.fd8p1
  },
  { // Entry 491
    0x1.7cdf79d5e37b8b212eff86d2ffe2044bp-1,
    -0x1.fd8p1
  },
  { // Entry 492
    0x1.fd3f48847a1d10a8e5ff1d4db84ed26dp-5,
    0x1.fd9364d936596p-5
  },
  { // Entry 493
    -0x1.fd3f48847a1d10a8e5ff1d4db84ed26dp-5,
    -0x1.fd9364d936596p-5
  },
  { // Entry 494
    0x1.f93ad471d262f8032e92d596797f9d41p-3,
    0x1.fe8p-3
  },
  { // Entry 495
    -0x1.f93ad471d262f8032e92d596797f9d41p-3,
    -0x1.fe8p-3
  },
  { // Entry 496
    0x1.83b3062414973d92c4278507f0474d67p-1,
    0x1.febb646e2ee57p13
  },
  { // Entry 497
    -0x1.83b3062414973d92c4278507f0474d67p-1,
    -0x1.febb646e2ee57p13
  },
  { // Entry 498
    0x1.3b45bd744977547fa4673e42dfc99402p-1,
    0x1.feeffffffffc6p995
  },
  { // Entry 499
    -0x1.3b45bd744977547fa4673e42dfc99402p-1,
    -0x1.feeffffffffc6p995
  },
  { // Entry 500
    -0x1.eefb59d143645a40041bf726dc6f2fa0p-1,
    0x1.ff8ffffffffffp7
  },
  { // Entry 501
    0x1.eefb59d143645a40041bf726dc6f2fa0p-1,
    -0x1.ff8ffffffffffp7
  },
  { // Entry 502
    -0x1.56433f0c6bcee9848751611c6f5ade1fp-1,
    0x1.ff8ffffffffffp870
  },
  { // Entry 503
    0x1.56433f0c6bcee9848751611c6f5ade1fp-1,
    -0x1.ff8ffffffffffp870
  },
  { // Entry 504
    -0x1.930006246a6c05dab72ea697daaba69dp-2,
    0x1.ffcfff8p19
  },
  { // Entry 505
    0x1.930006246a6c05dab72ea697daaba69dp-2,
    -0x1.ffcfff8p19
  },
  { // Entry 506
    0x1.ded37a1f0aa6d05d782d6aab40cb8670p-1,
    0x1.ffcfff8p365
  },
  { // Entry 507
    -0x1.ded37a1f0aa6d05d782d6aab40cb8670p-1,
    -0x1.ffcfff8p365
  },
  { // Entry 508
    -0x1.93e4d96b621e07bca866c1a2e771881cp-1,
    0x1.ffcffffffff6cp720
  },
  { // Entry 509
    0x1.93e4d96b621e07bca866c1a2e771881cp-1,
    -0x1.ffcffffffff6cp720
  },
  { // Entry 510
    0x1.9068b90e42605e05010e147110688e52p-1,
    0x1.ffcfffffffff9p320
  },
  { // Entry 511
    -0x1.9068b90e42605e05010e147110688e52p-1,
    -0x1.ffcfffffffff9p320
  },
  { // Entry 512
    0x1.cf81642e7421c56507eb8187611c84dbp-1,
    0x1.ffcffffffffffp12
  },
  { // Entry 513
    -0x1.cf81642e7421c56507eb8187611c84dbp-1,
    -0x1.ffcffffffffffp12
  },
  { // Entry 514
    0x1.ffffffe61fe616b282c3a69ca225c2d2p-1,
    0x1.ffcffffffffffp404
  },
  { // Entry 515
    -0x1.ffffffe61fe616b282c3a69ca225c2d2p-1,
    -0x1.ffcffffffffffp404
  },
  { // Entry 516
    -0x1.406ee9ae91e16f1d58c96eb7165f595bp-1,
    0x1.ffeffffffffccp995
  },
  { // Entry 517
    0x1.406ee9ae91e16f1d58c96eb7165f595bp-1,
    -0x1.ffeffffffffccp995
  },
  { // Entry 518
    0x1.fa9f6ca0ec44e0010026f385c0ab8690p-3,
    0x1.ffeffffffffffp-3
  },
  { // Entry 519
    -0x1.fa9f6ca0ec44e0010026f385c0ab8690p-3,
    -0x1.ffeffffffffffp-3
  },
  { // Entry 520
    0x1.6b491db8b66d880121f830d8c755ae54p-4,
    0x1.ffeffffffffffp55
  },
  { // Entry 521
    -0x1.6b491db8b66d880121f830d8c755ae54p-4,
    -0x1.ffeffffffffffp55
  },
  { // Entry 522
    0x1.fb0ab102cb12fef9a4e4a869a299ed46p-1,
    0x1.ffeffffffffffp180
  },
  { // Entry 523
    -0x1.fb0ab102cb12fef9a4e4a869a299ed46p-1,
    -0x1.ffeffffffffffp180
  },
  { // Entry 524
    0x1.e4315ec04635cd34b3ef60370511281fp-3,
    0x1.ffeffffffffffp706
  },
  { // Entry 525
    -0x1.e4315ec04635cd34b3ef60370511281fp-3,
    -0x1.ffeffffffffffp706
  },
  { // Entry 526
    0x1.ffffc39997ef67d2b9c7e4efa8b77e50p-1,
    0x1.fff1fffffffffp41
  },
  { // Entry 527
    -0x1.ffffc39997ef67d2b9c7e4efa8b77e50p-1,
    -0x1.fff1fffffffffp41
  },
  { // Entry 528
    0x1.fff163992831e8c68b0234b42efa1d0ap-7,
    0x1.fff6b89ffffffp-7
  },
  { // Entry 529
    -0x1.fff163992831e8c68b0234b42efa1d0ap-7,
    -0x1.fff6b89ffffffp-7
  },
  { // Entry 530
    -0x1.d9757a05fcc42c664f3a66b5576a98e4p-1,
    0x1.fffdffff0001fp105
  },
  { // Entry 531
    0x1.d9757a05fcc42c664f3a66b5576a98e4p-1,
    -0x1.fffdffff0001fp105
  },
  { // Entry 532
    -0x1.83791fe63a17a80258f2c479c7e1d339p-1,
    0x1.ffff0c0000002p1
  },
  { // Entry 533
    0x1.83791fe63a17a80258f2c479c7e1d339p-1,
    -0x1.ffff0c0000002p1
  },
  { // Entry 534
    -0x1.d9d3a85acc50c8000005d13dd82f61b5p-1,
    0x1.ffffc00000055p150
  },
  { // Entry 535
    0x1.d9d3a85acc50c8000005d13dd82f61b5p-1,
    -0x1.ffffc00000055p150
  },
  { // Entry 536
    -0x1.f25d858dcdee7412cf0760e955cb8390p-3,
    0x1.ffffe3fffffffp40
  },
  { // Entry 537
    0x1.f25d858dcdee7412cf0760e955cb8390p-3,
    -0x1.ffffe3fffffffp40
  },
  { // Entry 538
    0x1.d18f7bfe557eb80001557142bda18baep-1,
    0x1.ffffefffcffaep0
  },
  { // Entry 539
    -0x1.d18f7bfe557eb80001557142bda18baep-1,
    -0x1.ffffefffcffaep0
  },
  { // Entry 540
    -0x1.bc14ebf6bfb51ffa5e6f5b0b0bf9e899p-4,
    0x1.fffffbfffffffp228
  },
  { // Entry 541
    0x1.bc14ebf6bfb51ffa5e6f5b0b0bf9e899p-4,
    -0x1.fffffbfffffffp228
  },
  { // Entry 542
    0x1.bb887a06f6c50fef0654d303c82f1a78p-3,
    0x1.fffffbfffffffp735
  },
  { // Entry 543
    -0x1.bb887a06f6c50fef0654d303c82f1a78p-3,
    -0x1.fffffbfffffffp735
  },
  { // Entry 544
    0x1.ffaaadef54e2f0c4081880b7b9e794dfp-5,
    0x1.fffffefffffffp-5
  },
  { // Entry 545
    -0x1.ffaaadef54e2f0c4081880b7b9e794dfp-5,
    -0x1.fffffefffffffp-5
  },
  { // Entry 546
    0x1.d4a3c62c5be08b123868e8a467eff0cep-1,
    0x1.ffffff8p119
  },
  { // Entry 547
    -0x1.d4a3c62c5be08b123868e8a467eff0cep-1,
    -0x1.ffffff8p119
  },
  { // Entry 548
    0x1.cec20f197703f4fd42048ddf889fe84ap-3,
    0x1.ffffff8p192
  },
  { // Entry 549
    -0x1.cec20f197703f4fd42048ddf889fe84ap-3,
    -0x1.ffffff8p192
  },
  { // Entry 550
    0x1.d37aadc7c8662501751dbf4e9e5701abp-2,
    0x1.ffffff8p543
  },
  { // Entry 551
    -0x1.d37aadc7c8662501751dbf4e9e5701abp-2,
    -0x1.ffffff8p543
  },
  { // Entry 552
    0x1.fa8d2a4d0a2027f0f74df3136cb78f72p-1,
    0x1.ffffffc0018ffp2
  },
  { // Entry 553
    -0x1.fa8d2a4d0a2027f0f74df3136cb78f72p-1,
    -0x1.ffffffc0018ffp2
  },
  { // Entry 554
    0x1.fa8d2a029f977ffe74cb14cb09df176dp-1,
    0x1.ffffffffeffffp2
  },
  { // Entry 555
    -0x1.fa8d2a029f977ffe74cb14cb09df176dp-1,
    -0x1.ffffffffeffffp2
  },
  { // Entry 556
    -0x1.2763f02a2d1e980000015dbf95d89ab2p-4,
    0x1.fffffffff8250p943
  },
  { // Entry 557
    0x1.2763f02a2d1e980000015dbf95d89ab2p-4,
    -0x1.fffffffff8250p943
  },
  { // Entry 558
    0x1.fcff128f77dda81c2a0ec03e4ed80422p-1,
    0x1.fffffffffe09dp320
  },
  { // Entry 559
    -0x1.fcff128f77dda81c2a0ec03e4ed80422p-1,
    -0x1.fffffffffe09dp320
  },
  { // Entry 560
    -0x1.fcc0bfedd84a5816d9596b8f9fbb9b41p-1,
    0x1.fffffffffe6e3p720
  },
  { // Entry 561
    0x1.fcc0bfedd84a5816d9596b8f9fbb9b41p-1,
    -0x1.fffffffffe6e3p720
  },
  { // Entry 562
    0x1.aed548f090c1dffe6e04322dc8e8cbfap-1,
    0x1.ffffffffffe7fp-1
  },
  { // Entry 563
    -0x1.aed548f090c1dffe6e04322dc8e8cbfap-1,
    -0x1.ffffffffffe7fp-1
  },
  { // Entry 564
    -0x1.f5e11def99d2b22098242ac9fb756adbp-1,
    0x1.ffffffffffeffp250
  },
  { // Entry 565
    0x1.f5e11def99d2b22098242ac9fb756adbp-1,
    -0x1.ffffffffffeffp250
  },
  { // Entry 566
    0x1.8a9cbf48fec9f2a0fde951f313b918ccp-1,
    0x1.fffffffffff78p920
  },
  { // Entry 567
    -0x1.8a9cbf48fec9f2a0fde951f313b918ccp-1,
    -0x1.fffffffffff78p920
  },
  { // Entry 568
    -0x1.7eba5894844cc00c88f39bd3d4197d14p-3,
    0x1.fffffffffff83p150
  },
  { // Entry 569
    0x1.7eba5894844cc00c88f39bd3d4197d14p-3,
    -0x1.fffffffffff83p150
  },
  { // Entry 570
    0x1.92c4f06d2cdd15d302609caa87882afap-1,
    0x1.fffffffffffd5p995
  },
  { // Entry 571
    -0x1.92c4f06d2cdd15d302609caa87882afap-1,
    -0x1.fffffffffffd5p995
  },
  { // Entry 572
    -0x1.3d5f7deb1d3bad63eb173b73e84110a0p-1,
    0x1.fffffffffffe8p720
  },
  { // Entry 573
    0x1.3d5f7deb1d3bad63eb173b73e84110a0p-1,
    -0x1.fffffffffffe8p720
  },
  { // Entry 574
    -0x1.91349b0ae90e5316539c07eea9b4e6b0p-1,
    0x1.fffffffffffebp920
  },
  { // Entry 575
    0x1.91349b0ae90e5316539c07eea9b4e6b0p-1,
    -0x1.fffffffffffebp920
  },
  { // Entry 576
    -0x1.837b9dddc1e8738d74b2a74fa42d802dp-1,
    0x1.ffffffffffff1p1
  },
  { // Entry 577
    0x1.837b9dddc1e8738d74b2a74fa42d802dp-1,
    -0x1.ffffffffffff1p1
  },
  { // Entry 578
    0x1.510e062e7fa2037d3842de993c9c5090p-1,
    0x1.ffffffffffff1p245
  },
  { // Entry 579
    -0x1.510e062e7fa2037d3842de993c9c5090p-1,
    -0x1.ffffffffffff1p245
  },
  { // Entry 580
    0x1.eaee8744b05e47fde092e3a14895d067p-2,
    0x1.ffffffffffff3p-2
  },
  { // Entry 581
    -0x1.eaee8744b05e47fde092e3a14895d067p-2,
    -0x1.ffffffffffff3p-2
  },
  { // Entry 582
    0x1.8a4dee8f4062791078766b0a01de360dp-1,
    0x1.ffffffffffff4p845
  },
  { // Entry 583
    -0x1.8a4dee8f4062791078766b0a01de360dp-1,
    -0x1.ffffffffffff4p845
  },
  { // Entry 584
    0x1.5118d6bbde07e4eebf2a11df4dc74d54p-1,
    0x1.ffffffffffff4p1020
  },
  { // Entry 585
    -0x1.5118d6bbde07e4eebf2a11df4dc74d54p-1,
    -0x1.ffffffffffff4p1020
  },
  { // Entry 586
    -0x1.5cd5c53cf30a97ff0e471d149c40955dp-1,
    0x1.ffffffffffff8p616
  },
  { // Entry 587
    0x1.5cd5c53cf30a97ff0e471d149c40955dp-1,
    -0x1.ffffffffffff8p616
  },
  { // Entry 588
    0x1.ffffa1f0d7daf693a80a2b817b16f277p-1,
    0x1.ffffffffffffcp475
  },
  { // Entry 589
    -0x1.ffffa1f0d7daf693a80a2b817b16f277p-1,
    -0x1.ffffffffffffcp475
  },
  { // Entry 590
    0x1.51e9d840106d73484d44a86f74c3d41dp-1,
    0x1.ffffffffffffep970
  },
  { // Entry 591
    -0x1.51e9d840106d73484d44a86f74c3d41dp-1,
    -0x1.ffffffffffffep970
  },
  { // Entry 592
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 593
    0.0,
    0x1.0p-1074
  },
  { // Entry 594
    -0.0,
    -0.0
  },
  { // Entry 595
    0.0,
    0x1.0p-1074
  },
  { // Entry 596
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 597
    -0x1.0000000000000fffffffffffffffffffp-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 598
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 599
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    -0x1.0p-1022
  },
  { // Entry 600
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.0p-1022
  },
  { // Entry 601
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 602
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 603
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 604
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 605
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.0p-1022
  },
  { // Entry 606
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    -0x1.0p-1022
  },
  { // Entry 607
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 608
    -0x1.0000000000000fffffffffffffffffffp-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 609
    0x1.9999996de8ca198c24ab9449beee16d5p-13,
    0x1.999999999999ap-13
  },
  { // Entry 610
    -0x1.9999996de8ca198c24ab9449beee16d5p-13,
    -0x1.999999999999ap-13
  },
  { // Entry 611
    0x1.999998ead65b96f78a4dbfd839c7ef2ep-12,
    0x1.999999999999ap-12
  },
  { // Entry 612
    -0x1.999998ead65b96f78a4dbfd839c7ef2ep-12,
    -0x1.999999999999ap-12
  },
  { // Entry 613
    0x1.3333320c49babff151b6d04290e2c3a2p-11,
    0x1.3333333333334p-11
  },
  { // Entry 614
    -0x1.3333320c49babff151b6d04290e2c3a2p-11,
    -0x1.3333333333334p-11
  },
  { // Entry 615
    0x1.999996de8ca2884da2f08f25bb024d08p-11,
    0x1.999999999999ap-11
  },
  { // Entry 616
    -0x1.999996de8ca2884da2f08f25bb024d08p-11,
    -0x1.999999999999ap-11
  },
  { // Entry 617
    0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    0x1.0p-10
  },
  { // Entry 618
    -0x1.fffffaaaaaaeeeeeed4ed4edab4c7bd6p-11,
    -0x1.0p-10
  },
  { // Entry 619
    0x1.33332e978d552afc883bdb04751e3835p-10,
    0x1.3333333333333p-10
  },
  { // Entry 620
    -0x1.33332e978d552afc883bdb04751e3835p-10,
    -0x1.3333333333333p-10
  },
  { // Entry 621
    0x1.66665f1529aff8a3809246670a436c3cp-10,
    0x1.6666666666666p-10
  },
  { // Entry 622
    -0x1.66665f1529aff8a3809246670a436c3cp-10,
    -0x1.6666666666666p-10
  },
  { // Entry 623
    0x1.99998ead65cdf82e194c133997f2fb68p-10,
    0x1.9999999999999p-10
  },
  { // Entry 624
    -0x1.99998ead65cdf82e194c133997f2fb68p-10,
    -0x1.9999999999999p-10
  },
  { // Entry 625
    0x1.ccccbd3f7d15d42affb9f02bf1dc257bp-10,
    0x1.cccccccccccccp-10
  },
  { // Entry 626
    -0x1.ccccbd3f7d15d42affb9f02bf1dc257bp-10,
    -0x1.cccccccccccccp-10
  },
  { // Entry 627
    0x1.0665ae9c7b44ed280216be2104f28f02p-7,
    0x1.0666666666666p-7
  },
  { // Entry 628
    -0x1.0665ae9c7b44ed280216be2104f28f02p-7,
    -0x1.0666666666666p-7
  },
  { // Entry 629
    0x1.ccc8e97b59f618898c4ac3a0aeddf709p-7,
    0x1.cccccccccccccp-7
  },
  { // Entry 630
    -0x1.ccc8e97b59f618898c4ac3a0aeddf709p-7,
    -0x1.cccccccccccccp-7
  },
  { // Entry 631
    0x1.4993e8a8ff79b132046efa7856a97538p-6,
    0x1.4999999999999p-6
  },
  { // Entry 632
    -0x1.4993e8a8ff79b132046efa7856a97538p-6,
    -0x1.4999999999999p-6
  },
  { // Entry 633
    0x1.acc044c56db0e19f82c9c3cff246e201p-6,
    0x1.accccccccccccp-6
  },
  { // Entry 634
    -0x1.acc044c56db0e19f82c9c3cff246e201p-6,
    -0x1.accccccccccccp-6
  },
  { // Entry 635
    0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    0x1.080p-5
  },
  { // Entry 636
    -0x1.07f44d67cf41afbc0c95108b99f91b01p-5,
    -0x1.080p-5
  },
  { // Entry 637
    0x1.3985fe46f1c8714eaa1418561963e89bp-5,
    0x1.399999999999ap-5
  },
  { // Entry 638
    -0x1.3985fe46f1c8714eaa1418561963e89bp-5,
    -0x1.399999999999ap-5
  },
  { // Entry 639
    0x1.6b14bde93ac5f7d24544d0ecf8be7aeep-5,
    0x1.6b33333333334p-5
  },
  { // Entry 640
    -0x1.6b14bde93ac5f7d24544d0ecf8be7aeep-5,
    -0x1.6b33333333334p-5
  },
  { // Entry 641
    0x1.9ca0153ed8396b02f8605219a5fe5917p-5,
    0x1.9cccccccccccep-5
  },
  { // Entry 642
    -0x1.9ca0153ed8396b02f8605219a5fe5917p-5,
    -0x1.9cccccccccccep-5
  },
  { // Entry 643
    0x1.ce278d4027d34387f184d4ab2aaf545fp-5,
    0x1.ce66666666666p-5
  },
  { // Entry 644
    -0x1.ce278d4027d34387f184d4ab2aaf545fp-5,
    -0x1.ce66666666666p-5
  },
  { // Entry 645
    0x1.43c1e9c171a667a0b92519a04fa5a91cp-1,
    0x1.5e7fc4369bdadp-1
  },
  { // Entry 646
    -0x1.43c1e9c171a667a0b92519a04fa5a91cp-1,
    -0x1.5e7fc4369bdadp-1
  },
  { // Entry 647
    0x1.ee3d6bcea09ca18b1d1ce7ee04fd886fp-1,
    0x1.4e7fc4369bdadp0
  },
  { // Entry 648
    -0x1.ee3d6bcea09ca18b1d1ce7ee04fd886fp-1,
    -0x1.4e7fc4369bdadp0
  },
  { // Entry 649
    0x1.df8e22ea809d65c6a69b96aca60be432p-1,
    0x1.edbfa651e9c84p0
  },
  { // Entry 650
    -0x1.df8e22ea809d65c6a69b96aca60be432p-1,
    -0x1.edbfa651e9c84p0
  },
  { // Entry 651
    0x1.1d3479eac7ae35e2fbea0ae696434692p-1,
    0x1.467fc4369bdadp1
  },
  { // Entry 652
    -0x1.1d3479eac7ae35e2fbea0ae696434692p-1,
    -0x1.467fc4369bdadp1
  },
  { // Entry 653
    -0x1.ffeaaaeeee84b44ccefef832254d28c0p-6,
    0x1.961fb54442d18p1
  },
  { // Entry 654
    0x1.ffeaaaeeee84b44ccefef832254d28c0p-6,
    -0x1.961fb54442d18p1
  },
  { // Entry 655
    -0x1.3734d32d49bd0b942772a7567d514140p-1,
    0x1.e5bfa651e9c83p1
  },
  { // Entry 656
    0x1.3734d32d49bd0b942772a7567d514140p-1,
    -0x1.e5bfa651e9c83p1
  },
  { // Entry 657
    -0x1.e9d25d19911e205b653521f42b9b864fp-1,
    0x1.1aafcbafc85f7p2
  },
  { // Entry 658
    0x1.e9d25d19911e205b653521f42b9b864fp-1,
    -0x1.1aafcbafc85f7p2
  },
  { // Entry 659
    -0x1.e4ecdc5a4e465899928eb9fc95829d48p-1,
    0x1.427fc4369bdadp2
  },
  { // Entry 660
    0x1.e4ecdc5a4e465899928eb9fc95829d48p-1,
    -0x1.427fc4369bdadp2
  },
  { // Entry 661
    -0x1.2a59f1034426197fa6eee22762967f25p-1,
    0x1.6a4fbcbd6f562p2
  },
  { // Entry 662
    0x1.2a59f1034426197fa6eee22762967f25p-1,
    -0x1.6a4fbcbd6f562p2
  },
  { // Entry 663
    -0x1.26312443bd35f19312eac0a1a6b5659ep-1,
    0x1.6af2eff0a2896p2
  },
  { // Entry 664
    0x1.26312443bd35f19312eac0a1a6b5659ep-1,
    -0x1.6af2eff0a2896p2
  },
  { // Entry 665
    -0x1.e18e660a5e2fb316ecbb9ed70122eff5p-1,
    0x1.43c62a9d02414p2
  },
  { // Entry 666
    0x1.e18e660a5e2fb316ecbb9ed70122eff5p-1,
    -0x1.43c62a9d02414p2
  },
  { // Entry 667
    -0x1.ee0e83a0198b6e2ef7c48e6625291a0ap-1,
    0x1.1c99654961f92p2
  },
  { // Entry 668
    0x1.ee0e83a0198b6e2ef7c48e6625291a0ap-1,
    -0x1.1c99654961f92p2
  },
  { // Entry 669
    -0x1.4727747338e4653616eadbd7ec3d02d3p-1,
    0x1.ead93feb8361fp1
  },
  { // Entry 670
    0x1.4727747338e4653616eadbd7ec3d02d3p-1,
    -0x1.ead93feb8361fp1
  },
  { // Entry 671
    -0x1.4ba2f75dda5fe434320905a7184ff1afp-4,
    0x1.9c7fb54442d1ap1
  },
  { // Entry 672
    0x1.4ba2f75dda5fe434320905a7184ff1afp-4,
    -0x1.9c7fb54442d1ap1
  },
  { // Entry 673
    0x1.034c4d633b4ef0a9089b43892a462a26p-1,
    0x1.4e262a9d02415p1
  },
  { // Entry 674
    -0x1.034c4d633b4ef0a9089b43892a462a26p-1,
    -0x1.4e262a9d02415p1
  },
  { // Entry 675
    0x1.d1e4cde2f3944f4c134c05cc4e5339a3p-1,
    0x1.ff993feb83620p0
  },
  { // Entry 676
    -0x1.d1e4cde2f3944f4c134c05cc4e5339a3p-1,
    -0x1.ff993feb83620p0
  },
  { // Entry 677
    0x1.f750235c949926c48c90e41a91474c06p-1,
    0x1.62e62a9d02416p0
  },
  { // Entry 678
    -0x1.f750235c949926c48c90e41a91474c06p-1,
    -0x1.62e62a9d02416p0
  },
  { // Entry 679
    0x1.65f7d571279b0b8005552fd47a2e77aep-1,
    0x1.8c662a9d02419p-1
  },
  { // Entry 680
    -0x1.65f7d571279b0b8005552fd47a2e77aep-1,
    -0x1.8c662a9d02419p-1
  },
  { // Entry 681
    -0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    -0x1.a8aa1d11c44ffp0
  },
  { // Entry 682
    0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    0x1.a8aa1d11c44ffp0
  },
  { // Entry 683
    -0x1.fff18f24f3e4b87bf8c3762cb44f46d6p-1,
    -0x1.95ec8b9e03d54p0
  },
  { // Entry 684
    0x1.fff18f24f3e4b87bf8c3762cb44f46d6p-1,
    0x1.95ec8b9e03d54p0
  },
  { // Entry 685
    -0x1.ff20d961624e7063a78203b811f579cap-1,
    -0x1.832efa2a435a9p0
  },
  { // Entry 686
    0x1.ff20d961624e7063a78203b811f579cap-1,
    0x1.832efa2a435a9p0
  },
  { // Entry 687
    -0x1.fb933c40107fd775185ac14918c8fbafp-1,
    -0x1.707168b682dfep0
  },
  { // Entry 688
    0x1.fb933c40107fd775185ac14918c8fbafp-1,
    0x1.707168b682dfep0
  },
  { // Entry 689
    -0x1.f54d971881ad685b782ef88e6350f7cdp-1,
    -0x1.5db3d742c2653p0
  },
  { // Entry 690
    0x1.f54d971881ad685b782ef88e6350f7cdp-1,
    0x1.5db3d742c2653p0
  },
  { // Entry 691
    -0x1.ec5883b7b6cf4d859ab04e15d53698c9p-1,
    -0x1.4af645cf01ea8p0
  },
  { // Entry 692
    0x1.ec5883b7b6cf4d859ab04e15d53698c9p-1,
    0x1.4af645cf01ea8p0
  },
  { // Entry 693
    -0x1.e0c04a94e17309c806c1c78bddc1d607p-1,
    -0x1.3838b45b416fdp0
  },
  { // Entry 694
    0x1.e0c04a94e17309c806c1c78bddc1d607p-1,
    0x1.3838b45b416fdp0
  },
  { // Entry 695
    -0x1.d294d1f96c7ebdb9869dd97cf574ddb9p-1,
    -0x1.257b22e780f52p0
  },
  { // Entry 696
    0x1.d294d1f96c7ebdb9869dd97cf574ddb9p-1,
    0x1.257b22e780f52p0
  },
  { // Entry 697
    -0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    -0x1.12bd9173c07abp0
  },
  { // Entry 698
    0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    0x1.12bd9173c07abp0
  },
  { // Entry 699
    -0x1.a2c289d9d055ac377f67d7a54a0b3005p-1,
    -0x1.ea5c3ed5b3850p-1
  },
  { // Entry 700
    0x1.a2c289d9d055ac377f67d7a54a0b3005p-1,
    0x1.ea5c3ed5b3850p-1
  },
  { // Entry 701
    -0x1.95f05257dbcb5f4b12636c5878ea405ap-1,
    -0x1.d4b87dab670a0p-1
  },
  { // Entry 702
    0x1.95f05257dbcb5f4b12636c5878ea405ap-1,
    0x1.d4b87dab670a0p-1
  },
  { // Entry 703
    -0x1.88647f26a6e0f6b2715a6c3797ec11f5p-1,
    -0x1.bf14bc811a8f0p-1
  },
  { // Entry 704
    0x1.88647f26a6e0f6b2715a6c3797ec11f5p-1,
    0x1.bf14bc811a8f0p-1
  },
  { // Entry 705
    -0x1.7a2541dfd4e752de38f04aba21fc9d9fp-1,
    -0x1.a970fb56ce140p-1
  },
  { // Entry 706
    0x1.7a2541dfd4e752de38f04aba21fc9d9fp-1,
    0x1.a970fb56ce140p-1
  },
  { // Entry 707
    -0x1.6b391e25bc26cbbcf7a0184070af9c39p-1,
    -0x1.93cd3a2c81990p-1
  },
  { // Entry 708
    0x1.6b391e25bc26cbbcf7a0184070af9c39p-1,
    0x1.93cd3a2c81990p-1
  },
  { // Entry 709
    -0x1.5ba6e6a8e706535b98fc99dfaef824f1p-1,
    -0x1.7e297902351e0p-1
  },
  { // Entry 710
    0x1.5ba6e6a8e706535b98fc99dfaef824f1p-1,
    0x1.7e297902351e0p-1
  },
  { // Entry 711
    -0x1.4b75ba096fa54
```
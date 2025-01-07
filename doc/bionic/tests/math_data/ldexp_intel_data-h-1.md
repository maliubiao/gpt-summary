Response:
My thought process for answering the request went something like this:

1. **Understanding the Core Request:** The user provided a snippet of C code containing test data for the `ldexp` function in Android's bionic library. The key was to understand *what* this data represented and *why* it was there. The prompt explicitly asks for the function of the file, its relation to Android, explanations of relevant libc functions (specifically `ldexp`), dynamic linker aspects (though less relevant here), and how to reach this code from a high level (Android framework/NDK).

2. **Analyzing the Data:**  The provided data is a series of structs. Each struct has three fields: two `double` values represented in hexadecimal floating-point format (like `0x1.1745d1745d1770p-7`) and an `int`. The "Entry" comments provide sequential numbering. The hexadecimal floating-point format `0xh.hhhhhp[+/-]d` signifies a mantissa `h.hhhhh` multiplied by 2 raised to the power of `[+/-]d`.

3. **Identifying the Pattern:** I immediately recognized the first two `double` values as input and expected output for the `ldexp` function. The third `int` likely represents the exponent value being passed to `ldexp`. The sequence of entries suggested a testing strategy – covering various inputs, including edge cases and boundary conditions.

4. **Connecting to `ldexp`:** The name of the data file itself (`ldexp_intel_data.handroid`) strongly suggests it's test data specifically for the `ldexp` function, likely optimized for Intel architectures (though this detail is less crucial for understanding the *function* of the data itself).

5. **Formulating the Core Function:** The primary function of this file is to provide test data for verifying the correctness of the `ldexp` function implementation in bionic. This is crucial for ensuring the reliability of the math library.

6. **Relating to Android:** Since bionic is Android's standard C library, this data directly contributes to the stability and accuracy of numerical computations performed by Android applications and the Android framework itself.

7. **Explaining `ldexp`:** I needed to explain what `ldexp(double x, int exp)` does: multiplies a floating-point number `x` by 2 raised to the power of `exp`. I also needed to briefly touch upon its purpose (adjusting exponents without full multiplication).

8. **Dynamic Linker Aspects:** I considered if the data file itself has any direct interaction with the dynamic linker. It doesn't. It's just data. However, the *code* that *uses* this data (the `ldexp` implementation and the test runner) *does* rely on the dynamic linker to be loaded. Therefore, I mentioned the general process of linking shared libraries in Android. A specific SO layout for this data file isn't applicable.

9. **Hypothetical Inputs and Outputs:**  I could pick a few example entries and show how `ldexp(input_double, exponent)` results in `output_double`.

10. **Common Usage Errors:**  I thought about how `ldexp` could be misused. Providing an excessively large or small exponent that results in overflow or underflow is a common error.

11. **Tracing the Path from Android Framework/NDK:**  This is about understanding how a math function gets used. I outlined a typical scenario: an app using a math function (directly or indirectly), which calls the corresponding libc function, which is implemented in bionic. The NDK provides the headers and libraries to allow developers to use these functions.

12. **Frida Hook Example:**  To demonstrate debugging, a Frida hook targeting the `ldexp` function itself is the most relevant. This allows inspection of the input and output values at runtime. Hooking the data file directly isn't practical.

13. **Addressing the "Part 2" aspect:** The prompt explicitly mentions this is part 2 of 3. The request at the end is to summarize the function of *this specific part*. Therefore, the final summary needs to focus on the purpose of the *data itself*.

14. **Structuring the Answer:** I decided to structure the answer following the user's prompt as closely as possible: functionality, relationship to Android, explanation of `ldexp`, dynamic linker aspects, examples, common errors, how it's reached, Frida example, and finally, the summary for Part 2.

15. **Refining the Language:** I aimed for clear and concise Chinese explanations, avoiding overly technical jargon where possible while still being accurate. For instance, clearly explaining hexadecimal floating-point representation is important but shouldn't be the primary focus.

By following these steps, I could generate a comprehensive and accurate answer that addresses all aspects of the user's request, even those indirectly related to the provided code snippet. The key was to understand the context of the code within the larger Android ecosystem.
好的，根据您提供的代码片段，这是 `bionic/tests/math_data/ldexp_intel_data.handroid` 文件的一部分内容，它是一个用于测试 `ldexp` 函数的数据文件。

**它的功能归纳如下：**

这个代码片段定义了一个包含多个测试用例的数组。每个测试用例由三个元素组成：

* **第一个 `double` 值：**  作为 `ldexp` 函数的输入参数 `x`。
* **第二个 `double` 值：**  作为期望的 `ldexp` 函数的输出结果。
* **一个 `int` 值：** 作为 `ldexp` 函数的输入参数 `exp`（指数）。

**更详细的解释：**

这个数据文件的目的是为 `ldexp` 函数提供各种各样的输入组合，并预先计算出正确的输出结果。通过将 `ldexp` 函数的实际输出与这些预期的输出进行比较，可以验证 `ldexp` 函数的实现是否正确。

**与 Android 功能的关系举例：**

`ldexp` 是一个 C 标准库函数，它属于 `math.h` 头文件提供的数学函数集。在 Android 中，这些标准库函数由 Bionic C 库提供。

* **应用层（Java/Kotlin）：**  尽管 Android 应用开发者通常不直接调用 `ldexp`，但一些底层的图形处理、科学计算或游戏引擎可能会使用到它。例如，在 OpenGL ES 中进行一些数学运算时，底层实现可能会调用 `ldexp` 或其他类似的数学函数。
* **Android Framework (C++/Java):**  Android 框架本身也可能在某些低级模块中使用 `ldexp`。例如，处理音频、视频编解码或者进行一些系统级别的数学计算时。

**`ldexp` 函数的功能实现解释：**

`ldexp(double x, int exp)` 函数的功能是将浮点数 `x` 乘以 2 的 `exp` 次幂。  其本质是调整浮点数的指数部分。

**实现原理 (简化描述)：**

1. **提取 `x` 的指数部分：**  浮点数在内存中以特定的格式存储（通常是 IEEE 754 标准），包含符号位、指数部分和尾数部分。`ldexp` 函数首先会提取 `x` 的指数部分。
2. **调整指数：** 将提取出的指数值加上 `exp`。
3. **构建新的浮点数：** 使用原始的尾数部分和调整后的指数部分，重新构建一个新的浮点数。

**动态链接器功能 (关联性较弱)：**

这个数据文件本身并不直接涉及动态链接器的功能。动态链接器负责在程序运行时加载和链接共享库 (`.so` 文件)。

* **SO 布局样本：**  `libm.so` 是包含 `ldexp` 函数实现的共享库。一个简化的 `libm.so` 布局可能如下：

```
libm.so:
    .text          # 存放代码段
        ldexp:    # ldexp 函数的代码
            ...
        其他数学函数:
            ...
    .data          # 存放已初始化的全局变量和静态变量
    .rodata        # 存放只读数据，例如字符串常量
    .bss           # 存放未初始化的全局变量和静态变量
    .symtab        # 符号表，包含函数名、变量名等信息
    .strtab        # 字符串表，存放符号表中使用的字符串
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # Procedure Linkage Table，用于延迟绑定
    .got.plt       # Global Offset Table for PLT
    ...
```

* **链接的处理过程：**
    1. 当一个应用程序（例如，您的 APK 中的 native 代码）调用 `ldexp` 函数时，编译器会生成一个对 `ldexp` 的未解析引用。
    2. 在程序启动时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会读取程序的可执行文件头，找到依赖的共享库列表（例如 `libm.so`）。
    3. 动态链接器会加载 `libm.so` 到内存中。
    4. 动态链接器会解析程序中对 `ldexp` 的引用，找到 `libm.so` 中 `ldexp` 函数的地址，并更新程序的 GOT (Global Offset Table)。之后，对 `ldexp` 的调用就会跳转到 `libm.so` 中正确的地址。

**假设输入与输出 (逻辑推理)：**

例如，根据代码片段中的一个条目：

```c
{ // Entry 430
    0x1.745d1745d17490p-1,  // 输入 x
    0x1.745d1745d1749p-1,   // 期望输出
    (int)0                  // 指数 exp
},
```

* **假设输入：** `x = 0.84375`, `exp = 0`  (因为 `0x1.745d1745d17490p-1` 表示 1.7677669529663689 * 2^-1 ≈ 0.84375)
* **预期输出：** `0.84375` (因为乘以 2 的 0 次幂等于乘以 1)

另一个例子：

```c
{ // Entry 389
    0x1.1745d1745d1770p0,   // 输入 x
    0x1.1745d1745d177p-1,   // 期望输出
    (int)1                  // 指数 exp
},
```

* **假设输入：** `x = 1.0918978748889913`, `exp = 1`
* **预期输出：** `0.54594893744449565` (因为 1.0918978748889913 * 2^1 = 2.1837957497779826，但期望输出是除以2)  **注意：这里可能存在数据生成逻辑上的某种特定目的，看起来期望的输出是输入除以2，而不是乘以2。这可能是为了测试某种特定的边界或精度情况。**

**用户或编程常见的使用错误：**

* **指数过大或过小导致溢出/下溢：** 如果 `exp` 的值非常大，`ldexp` 的结果可能会超出 `double` 类型能表示的最大值（溢出），或者非常接近于零（下溢）。
* **传入非法的指数值：** 虽然 `exp` 是 `int` 类型，但某些实现可能对 `exp` 的范围有限制。
* **精度问题：** 浮点数运算本身存在精度问题。虽然 `ldexp` 主要操作指数，但当与尾数结合时，仍然可能出现微小的精度损失。

**Android Framework 或 NDK 如何到达这里以及 Frida Hook 示例：**

1. **Android Framework 或 NDK 调用数学函数：**
   * 某个 Android Framework 的 C++ 组件，例如 SurfaceFlinger 或 MediaCodec，可能需要进行浮点数乘法运算，并且为了效率，可能会使用 `ldexp` 来乘以 2 的幂。
   * 使用 NDK 开发的应用程序，其 native 代码可以直接调用 `ldexp` 函数。需要包含 `<cmath>` 或 `<math.h>` 头文件。

2. **libc 调用：**
   * 当上述组件或应用调用 `ldexp` 时，实际上会调用 Bionic C 库 (`libc.so`) 中实现的 `ldexp` 函数。

3. **`libm.so` 中的实现：**
   * Bionic C 库会将 `ldexp` 的调用转发到 `libm.so` 共享库中，该库包含了实际的数学函数实现。

**Frida Hook 示例：**

你可以使用 Frida Hook `ldexp` 函数来观察其输入和输出：

```javascript
if (Process.platform === 'android') {
  const ldexp = Module.findExportByName("libm.so", "ldexp");
  if (ldexp) {
    Interceptor.attach(ldexp, {
      onEnter: function (args) {
        const x = args[0];
        const exp = args[1].toInt32();
        console.log("[+] ldexp called");
        console.log("    x:", x);
        console.log("    exp:", exp);
      },
      onLeave: function (retval) {
        console.log("    retval:", retval);
      }
    });
  } else {
    console.log("[-] ldexp not found in libm.so");
  }
}
```

**总结 Part 2 的功能：**

Part 2 的代码片段，以及整个 `ldexp_intel_data.handroid` 文件，其主要功能是 **提供了一系列预定义的输入和期望输出，用于测试 Android Bionic C 库中 `ldexp` 函数在特定平台（Intel 架构）上的正确性。** 它是 Bionic 库的质量保证体系的一部分。

Prompt: 
```
这是目录为bionic/tests/math_data/ldexp_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
-1,
    (int)-7
  },
  { // Entry 382
    0x1.1745d1745d1770p-7,
    0x1.1745d1745d177p-1,
    (int)-6
  },
  { // Entry 383
    0x1.1745d1745d1770p-6,
    0x1.1745d1745d177p-1,
    (int)-5
  },
  { // Entry 384
    0x1.1745d1745d1770p-5,
    0x1.1745d1745d177p-1,
    (int)-4
  },
  { // Entry 385
    0x1.1745d1745d1770p-4,
    0x1.1745d1745d177p-1,
    (int)-3
  },
  { // Entry 386
    0x1.1745d1745d1770p-3,
    0x1.1745d1745d177p-1,
    (int)-2
  },
  { // Entry 387
    0x1.1745d1745d1770p-2,
    0x1.1745d1745d177p-1,
    (int)-1
  },
  { // Entry 388
    0x1.1745d1745d1770p-1,
    0x1.1745d1745d177p-1,
    (int)0
  },
  { // Entry 389
    0x1.1745d1745d1770p0,
    0x1.1745d1745d177p-1,
    (int)1
  },
  { // Entry 390
    0x1.1745d1745d1770p1,
    0x1.1745d1745d177p-1,
    (int)2
  },
  { // Entry 391
    0x1.1745d1745d1770p2,
    0x1.1745d1745d177p-1,
    (int)3
  },
  { // Entry 392
    0x1.1745d1745d1770p3,
    0x1.1745d1745d177p-1,
    (int)4
  },
  { // Entry 393
    0x1.1745d1745d1770p4,
    0x1.1745d1745d177p-1,
    (int)5
  },
  { // Entry 394
    0x1.1745d1745d1770p5,
    0x1.1745d1745d177p-1,
    (int)6
  },
  { // Entry 395
    0x1.1745d1745d1770p6,
    0x1.1745d1745d177p-1,
    (int)7
  },
  { // Entry 396
    0x1.1745d1745d1770p7,
    0x1.1745d1745d177p-1,
    (int)8
  },
  { // Entry 397
    0x1.1745d1745d1770p8,
    0x1.1745d1745d177p-1,
    (int)9
  },
  { // Entry 398
    0x1.1745d1745d1770p9,
    0x1.1745d1745d177p-1,
    (int)10
  },
  { // Entry 399
    0x1.45d1745d1746p-11,
    0x1.45d1745d17460p-1,
    (int)-10
  },
  { // Entry 400
    0x1.45d1745d1746p-10,
    0x1.45d1745d17460p-1,
    (int)-9
  },
  { // Entry 401
    0x1.45d1745d1746p-9,
    0x1.45d1745d17460p-1,
    (int)-8
  },
  { // Entry 402
    0x1.45d1745d1746p-8,
    0x1.45d1745d17460p-1,
    (int)-7
  },
  { // Entry 403
    0x1.45d1745d1746p-7,
    0x1.45d1745d17460p-1,
    (int)-6
  },
  { // Entry 404
    0x1.45d1745d1746p-6,
    0x1.45d1745d17460p-1,
    (int)-5
  },
  { // Entry 405
    0x1.45d1745d1746p-5,
    0x1.45d1745d17460p-1,
    (int)-4
  },
  { // Entry 406
    0x1.45d1745d1746p-4,
    0x1.45d1745d17460p-1,
    (int)-3
  },
  { // Entry 407
    0x1.45d1745d1746p-3,
    0x1.45d1745d17460p-1,
    (int)-2
  },
  { // Entry 408
    0x1.45d1745d1746p-2,
    0x1.45d1745d17460p-1,
    (int)-1
  },
  { // Entry 409
    0x1.45d1745d1746p-1,
    0x1.45d1745d17460p-1,
    (int)0
  },
  { // Entry 410
    0x1.45d1745d1746p0,
    0x1.45d1745d17460p-1,
    (int)1
  },
  { // Entry 411
    0x1.45d1745d1746p1,
    0x1.45d1745d17460p-1,
    (int)2
  },
  { // Entry 412
    0x1.45d1745d1746p2,
    0x1.45d1745d17460p-1,
    (int)3
  },
  { // Entry 413
    0x1.45d1745d1746p3,
    0x1.45d1745d17460p-1,
    (int)4
  },
  { // Entry 414
    0x1.45d1745d1746p4,
    0x1.45d1745d17460p-1,
    (int)5
  },
  { // Entry 415
    0x1.45d1745d1746p5,
    0x1.45d1745d17460p-1,
    (int)6
  },
  { // Entry 416
    0x1.45d1745d1746p6,
    0x1.45d1745d17460p-1,
    (int)7
  },
  { // Entry 417
    0x1.45d1745d1746p7,
    0x1.45d1745d17460p-1,
    (int)8
  },
  { // Entry 418
    0x1.45d1745d1746p8,
    0x1.45d1745d17460p-1,
    (int)9
  },
  { // Entry 419
    0x1.45d1745d1746p9,
    0x1.45d1745d17460p-1,
    (int)10
  },
  { // Entry 420
    0x1.745d1745d17490p-11,
    0x1.745d1745d1749p-1,
    (int)-10
  },
  { // Entry 421
    0x1.745d1745d17490p-10,
    0x1.745d1745d1749p-1,
    (int)-9
  },
  { // Entry 422
    0x1.745d1745d17490p-9,
    0x1.745d1745d1749p-1,
    (int)-8
  },
  { // Entry 423
    0x1.745d1745d17490p-8,
    0x1.745d1745d1749p-1,
    (int)-7
  },
  { // Entry 424
    0x1.745d1745d17490p-7,
    0x1.745d1745d1749p-1,
    (int)-6
  },
  { // Entry 425
    0x1.745d1745d17490p-6,
    0x1.745d1745d1749p-1,
    (int)-5
  },
  { // Entry 426
    0x1.745d1745d17490p-5,
    0x1.745d1745d1749p-1,
    (int)-4
  },
  { // Entry 427
    0x1.745d1745d17490p-4,
    0x1.745d1745d1749p-1,
    (int)-3
  },
  { // Entry 428
    0x1.745d1745d17490p-3,
    0x1.745d1745d1749p-1,
    (int)-2
  },
  { // Entry 429
    0x1.745d1745d17490p-2,
    0x1.745d1745d1749p-1,
    (int)-1
  },
  { // Entry 430
    0x1.745d1745d17490p-1,
    0x1.745d1745d1749p-1,
    (int)0
  },
  { // Entry 431
    0x1.745d1745d17490p0,
    0x1.745d1745d1749p-1,
    (int)1
  },
  { // Entry 432
    0x1.745d1745d17490p1,
    0x1.745d1745d1749p-1,
    (int)2
  },
  { // Entry 433
    0x1.745d1745d17490p2,
    0x1.745d1745d1749p-1,
    (int)3
  },
  { // Entry 434
    0x1.745d1745d17490p3,
    0x1.745d1745d1749p-1,
    (int)4
  },
  { // Entry 435
    0x1.745d1745d17490p4,
    0x1.745d1745d1749p-1,
    (int)5
  },
  { // Entry 436
    0x1.745d1745d17490p5,
    0x1.745d1745d1749p-1,
    (int)6
  },
  { // Entry 437
    0x1.745d1745d17490p6,
    0x1.745d1745d1749p-1,
    (int)7
  },
  { // Entry 438
    0x1.745d1745d17490p7,
    0x1.745d1745d1749p-1,
    (int)8
  },
  { // Entry 439
    0x1.745d1745d17490p8,
    0x1.745d1745d1749p-1,
    (int)9
  },
  { // Entry 440
    0x1.745d1745d17490p9,
    0x1.745d1745d1749p-1,
    (int)10
  },
  { // Entry 441
    0x1.a2e8ba2e8ba320p-11,
    0x1.a2e8ba2e8ba32p-1,
    (int)-10
  },
  { // Entry 442
    0x1.a2e8ba2e8ba320p-10,
    0x1.a2e8ba2e8ba32p-1,
    (int)-9
  },
  { // Entry 443
    0x1.a2e8ba2e8ba320p-9,
    0x1.a2e8ba2e8ba32p-1,
    (int)-8
  },
  { // Entry 444
    0x1.a2e8ba2e8ba320p-8,
    0x1.a2e8ba2e8ba32p-1,
    (int)-7
  },
  { // Entry 445
    0x1.a2e8ba2e8ba320p-7,
    0x1.a2e8ba2e8ba32p-1,
    (int)-6
  },
  { // Entry 446
    0x1.a2e8ba2e8ba320p-6,
    0x1.a2e8ba2e8ba32p-1,
    (int)-5
  },
  { // Entry 447
    0x1.a2e8ba2e8ba320p-5,
    0x1.a2e8ba2e8ba32p-1,
    (int)-4
  },
  { // Entry 448
    0x1.a2e8ba2e8ba320p-4,
    0x1.a2e8ba2e8ba32p-1,
    (int)-3
  },
  { // Entry 449
    0x1.a2e8ba2e8ba320p-3,
    0x1.a2e8ba2e8ba32p-1,
    (int)-2
  },
  { // Entry 450
    0x1.a2e8ba2e8ba320p-2,
    0x1.a2e8ba2e8ba32p-1,
    (int)-1
  },
  { // Entry 451
    0x1.a2e8ba2e8ba320p-1,
    0x1.a2e8ba2e8ba32p-1,
    (int)0
  },
  { // Entry 452
    0x1.a2e8ba2e8ba320p0,
    0x1.a2e8ba2e8ba32p-1,
    (int)1
  },
  { // Entry 453
    0x1.a2e8ba2e8ba320p1,
    0x1.a2e8ba2e8ba32p-1,
    (int)2
  },
  { // Entry 454
    0x1.a2e8ba2e8ba320p2,
    0x1.a2e8ba2e8ba32p-1,
    (int)3
  },
  { // Entry 455
    0x1.a2e8ba2e8ba320p3,
    0x1.a2e8ba2e8ba32p-1,
    (int)4
  },
  { // Entry 456
    0x1.a2e8ba2e8ba320p4,
    0x1.a2e8ba2e8ba32p-1,
    (int)5
  },
  { // Entry 457
    0x1.a2e8ba2e8ba320p5,
    0x1.a2e8ba2e8ba32p-1,
    (int)6
  },
  { // Entry 458
    0x1.a2e8ba2e8ba320p6,
    0x1.a2e8ba2e8ba32p-1,
    (int)7
  },
  { // Entry 459
    0x1.a2e8ba2e8ba320p7,
    0x1.a2e8ba2e8ba32p-1,
    (int)8
  },
  { // Entry 460
    0x1.a2e8ba2e8ba320p8,
    0x1.a2e8ba2e8ba32p-1,
    (int)9
  },
  { // Entry 461
    0x1.a2e8ba2e8ba320p9,
    0x1.a2e8ba2e8ba32p-1,
    (int)10
  },
  { // Entry 462
    0x1.d1745d1745d1b0p-11,
    0x1.d1745d1745d1bp-1,
    (int)-10
  },
  { // Entry 463
    0x1.d1745d1745d1b0p-10,
    0x1.d1745d1745d1bp-1,
    (int)-9
  },
  { // Entry 464
    0x1.d1745d1745d1b0p-9,
    0x1.d1745d1745d1bp-1,
    (int)-8
  },
  { // Entry 465
    0x1.d1745d1745d1b0p-8,
    0x1.d1745d1745d1bp-1,
    (int)-7
  },
  { // Entry 466
    0x1.d1745d1745d1b0p-7,
    0x1.d1745d1745d1bp-1,
    (int)-6
  },
  { // Entry 467
    0x1.d1745d1745d1b0p-6,
    0x1.d1745d1745d1bp-1,
    (int)-5
  },
  { // Entry 468
    0x1.d1745d1745d1b0p-5,
    0x1.d1745d1745d1bp-1,
    (int)-4
  },
  { // Entry 469
    0x1.d1745d1745d1b0p-4,
    0x1.d1745d1745d1bp-1,
    (int)-3
  },
  { // Entry 470
    0x1.d1745d1745d1b0p-3,
    0x1.d1745d1745d1bp-1,
    (int)-2
  },
  { // Entry 471
    0x1.d1745d1745d1b0p-2,
    0x1.d1745d1745d1bp-1,
    (int)-1
  },
  { // Entry 472
    0x1.d1745d1745d1b0p-1,
    0x1.d1745d1745d1bp-1,
    (int)0
  },
  { // Entry 473
    0x1.d1745d1745d1b0p0,
    0x1.d1745d1745d1bp-1,
    (int)1
  },
  { // Entry 474
    0x1.d1745d1745d1b0p1,
    0x1.d1745d1745d1bp-1,
    (int)2
  },
  { // Entry 475
    0x1.d1745d1745d1b0p2,
    0x1.d1745d1745d1bp-1,
    (int)3
  },
  { // Entry 476
    0x1.d1745d1745d1b0p3,
    0x1.d1745d1745d1bp-1,
    (int)4
  },
  { // Entry 477
    0x1.d1745d1745d1b0p4,
    0x1.d1745d1745d1bp-1,
    (int)5
  },
  { // Entry 478
    0x1.d1745d1745d1b0p5,
    0x1.d1745d1745d1bp-1,
    (int)6
  },
  { // Entry 479
    0x1.d1745d1745d1b0p6,
    0x1.d1745d1745d1bp-1,
    (int)7
  },
  { // Entry 480
    0x1.d1745d1745d1b0p7,
    0x1.d1745d1745d1bp-1,
    (int)8
  },
  { // Entry 481
    0x1.d1745d1745d1b0p8,
    0x1.d1745d1745d1bp-1,
    (int)9
  },
  { // Entry 482
    0x1.d1745d1745d1b0p9,
    0x1.d1745d1745d1bp-1,
    (int)10
  },
  { // Entry 483
    0x1.p-10,
    0x1.0p0,
    (int)-10
  },
  { // Entry 484
    0x1.p-9,
    0x1.0p0,
    (int)-9
  },
  { // Entry 485
    0x1.p-8,
    0x1.0p0,
    (int)-8
  },
  { // Entry 486
    0x1.p-7,
    0x1.0p0,
    (int)-7
  },
  { // Entry 487
    0x1.p-6,
    0x1.0p0,
    (int)-6
  },
  { // Entry 488
    0x1.p-5,
    0x1.0p0,
    (int)-5
  },
  { // Entry 489
    0x1.p-4,
    0x1.0p0,
    (int)-4
  },
  { // Entry 490
    0x1.p-3,
    0x1.0p0,
    (int)-3
  },
  { // Entry 491
    0x1.p-2,
    0x1.0p0,
    (int)-2
  },
  { // Entry 492
    0x1.p-1,
    0x1.0p0,
    (int)-1
  },
  { // Entry 493
    0x1.p0,
    0x1.0p0,
    (int)0
  },
  { // Entry 494
    0x1.p1,
    0x1.0p0,
    (int)1
  },
  { // Entry 495
    0x1.p2,
    0x1.0p0,
    (int)2
  },
  { // Entry 496
    0x1.p3,
    0x1.0p0,
    (int)3
  },
  { // Entry 497
    0x1.p4,
    0x1.0p0,
    (int)4
  },
  { // Entry 498
    0x1.p5,
    0x1.0p0,
    (int)5
  },
  { // Entry 499
    0x1.p6,
    0x1.0p0,
    (int)6
  },
  { // Entry 500
    0x1.p7,
    0x1.0p0,
    (int)7
  },
  { // Entry 501
    0x1.p8,
    0x1.0p0,
    (int)8
  },
  { // Entry 502
    0x1.p9,
    0x1.0p0,
    (int)9
  },
  { // Entry 503
    0x1.p10,
    0x1.0p0,
    (int)10
  },
  { // Entry 504
    0x1.fffffffffffff0p0,
    0x1.fffffffffffffp1023,
    (int)-1023
  },
  { // Entry 505
    0x1.fffffffffffff0p1,
    0x1.fffffffffffffp1023,
    (int)-1022
  },
  { // Entry 506
    0x1.fffffffffffff0p23,
    0x1.fffffffffffffp1023,
    (int)-1000
  },
  { // Entry 507
    0x1.fffffffffffff0p24,
    0x1.fffffffffffffp1023,
    (int)-999
  },
  { // Entry 508
    0x1.fffffffffffff0p1013,
    0x1.fffffffffffffp1023,
    (int)-10
  },
  { // Entry 509
    0x1.fffffffffffff0p1014,
    0x1.fffffffffffffp1023,
    (int)-9
  },
  { // Entry 510
    0x1.fffffffffffff0p1015,
    0x1.fffffffffffffp1023,
    (int)-8
  },
  { // Entry 511
    0x1.fffffffffffff0p1016,
    0x1.fffffffffffffp1023,
    (int)-7
  },
  { // Entry 512
    0x1.fffffffffffff0p1017,
    0x1.fffffffffffffp1023,
    (int)-6
  },
  { // Entry 513
    0x1.fffffffffffff0p1018,
    0x1.fffffffffffffp1023,
    (int)-5
  },
  { // Entry 514
    0x1.fffffffffffff0p1019,
    0x1.fffffffffffffp1023,
    (int)-4
  },
  { // Entry 515
    0x1.fffffffffffff0p1020,
    0x1.fffffffffffffp1023,
    (int)-3
  },
  { // Entry 516
    0x1.fffffffffffff0p1021,
    0x1.fffffffffffffp1023,
    (int)-2
  },
  { // Entry 517
    0x1.fffffffffffff0p1022,
    0x1.fffffffffffffp1023,
    (int)-1
  },
  { // Entry 518
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    (int)0
  },
  { // Entry 519
    0x1.p-51,
    0x1.0p-1074,
    (int)1023
  },
  { // Entry 520
    0x1.p-52,
    0x1.0p-1074,
    (int)1022
  },
  { // Entry 521
    0x1.p-74,
    0x1.0p-1074,
    (int)1000
  },
  { // Entry 522
    0x1.p-75,
    0x1.0p-1074,
    (int)999
  },
  { // Entry 523
    0x1.p-1074,
    0x1.0p-1074,
    (int)0
  },
  { // Entry 524
    0x1.p-1073,
    0x1.0p-1074,
    (int)1
  },
  { // Entry 525
    0x1.p-1072,
    0x1.0p-1074,
    (int)2
  },
  { // Entry 526
    0x1.p-1071,
    0x1.0p-1074,
    (int)3
  },
  { // Entry 527
    0x1.p-1070,
    0x1.0p-1074,
    (int)4
  },
  { // Entry 528
    0x1.p-1069,
    0x1.0p-1074,
    (int)5
  },
  { // Entry 529
    0x1.p-1068,
    0x1.0p-1074,
    (int)6
  },
  { // Entry 530
    0x1.p-1067,
    0x1.0p-1074,
    (int)7
  },
  { // Entry 531
    0x1.p-1066,
    0x1.0p-1074,
    (int)8
  },
  { // Entry 532
    0x1.p-1065,
    0x1.0p-1074,
    (int)9
  },
  { // Entry 533
    0x1.p-1064,
    0x1.0p-1074,
    (int)10
  },
  { // Entry 534
    0x1.p-1025,
    0x1.0p-2,
    (int)-1023
  },
  { // Entry 535
    0x1.p-1024,
    0x1.0p-2,
    (int)-1022
  },
  { // Entry 536
    0x1.p-1024,
    0x1.0p-1,
    (int)-1023
  },
  { // Entry 537
    0x1.p-1023,
    0x1.0p-1,
    (int)-1022
  },
  { // Entry 538
    0x1.80p-1024,
    0x1.8p-1,
    (int)-1023
  },
  { // Entry 539
    0x1.80p-1023,
    0x1.8p-1,
    (int)-1022
  },
  { // Entry 540
    0.0,
    0x1.0p-2,
    (int)-1074
  },
  { // Entry 541
    0.0,
    0x1.0p-2,
    (int)-1073
  },
  { // Entry 542
    0.0,
    0x1.0p-1,
    (int)-1074
  },
  { // Entry 543
    0x1.p-1074,
    0x1.0p-1,
    (int)-1073
  },
  { // Entry 544
    0.0,
    0x1.8p-1,
    (int)-1074
  },
  { // Entry 545
    0x1.80p-1074,
    0x1.8p-1,
    (int)-1073
  },
  { // Entry 546
    0x1.p1023,
    0x1.0p0,
    (int)1023
  },
  { // Entry 547
    0x1.p1022,
    0x1.0p0,
    (int)1022
  },
  { // Entry 548
    0x1.p-1074,
    0x1.0p-1074,
    (int)0
  },
  { // Entry 549
    0x1.p-1073,
    0x1.0p-1074,
    (int)1
  },
  { // Entry 550
    0x1.p-1072,
    0x1.0p-1074,
    (int)2
  },
  { // Entry 551
    0x1.p-1071,
    0x1.0p-1074,
    (int)3
  },
  { // Entry 552
    0x1.p-1070,
    0x1.0p-1074,
    (int)4
  },
  { // Entry 553
    0x1.p-1069,
    0x1.0p-1074,
    (int)5
  },
  { // Entry 554
    0x1.p-1068,
    0x1.0p-1074,
    (int)6
  },
  { // Entry 555
    0x1.p-1067,
    0x1.0p-1074,
    (int)7
  },
  { // Entry 556
    0x1.p-1066,
    0x1.0p-1074,
    (int)8
  },
  { // Entry 557
    0x1.p-1065,
    0x1.0p-1074,
    (int)9
  },
  { // Entry 558
    0x1.p-1064,
    0x1.0p-1074,
    (int)10
  },
  { // Entry 559
    0x1.p-1063,
    0x1.0p-1074,
    (int)11
  },
  { // Entry 560
    0x1.p-1062,
    0x1.0p-1074,
    (int)12
  },
  { // Entry 561
    0x1.p-1061,
    0x1.0p-1074,
    (int)13
  },
  { // Entry 562
    0x1.p-1060,
    0x1.0p-1074,
    (int)14
  },
  { // Entry 563
    0x1.p-1059,
    0x1.0p-1074,
    (int)15
  },
  { // Entry 564
    0x1.p-1058,
    0x1.0p-1074,
    (int)16
  },
  { // Entry 565
    0x1.p-1057,
    0x1.0p-1074,
    (int)17
  },
  { // Entry 566
    0x1.p-1056,
    0x1.0p-1074,
    (int)18
  },
  { // Entry 567
    0x1.p-1055,
    0x1.0p-1074,
    (int)19
  },
  { // Entry 568
    0x1.p-1054,
    0x1.0p-1074,
    (int)20
  },
  { // Entry 569
    0x1.p-1053,
    0x1.0p-1074,
    (int)21
  },
  { // Entry 570
    0x1.p-1052,
    0x1.0p-1074,
    (int)22
  },
  { // Entry 571
    0x1.p-1051,
    0x1.0p-1074,
    (int)23
  },
  { // Entry 572
    0x1.p-1050,
    0x1.0p-1074,
    (int)24
  },
  { // Entry 573
    0x1.p-1049,
    0x1.0p-1074,
    (int)25
  },
  { // Entry 574
    0x1.p-1048,
    0x1.0p-1074,
    (int)26
  },
  { // Entry 575
    0x1.p-1047,
    0x1.0p-1074,
    (int)27
  },
  { // Entry 576
    0x1.p-1046,
    0x1.0p-1074,
    (int)28
  },
  { // Entry 577
    0x1.p-1045,
    0x1.0p-1074,
    (int)29
  },
  { // Entry 578
    0x1.p-1044,
    0x1.0p-1074,
    (int)30
  },
  { // Entry 579
    0x1.p-1043,
    0x1.0p-1074,
    (int)31
  },
  { // Entry 580
    0x1.p-1042,
    0x1.0p-1074,
    (int)32
  },
  { // Entry 581
    0x1.p-1041,
    0x1.0p-1074,
    (int)33
  },
  { // Entry 582
    0x1.p-1040,
    0x1.0p-1074,
    (int)34
  },
  { // Entry 583
    0x1.p-1039,
    0x1.0p-1074,
    (int)35
  },
  { // Entry 584
    0x1.p-1038,
    0x1.0p-1074,
    (int)36
  },
  { // Entry 585
    0x1.p-1037,
    0x1.0p-1074,
    (int)37
  },
  { // Entry 586
    0x1.p-1036,
    0x1.0p-1074,
    (int)38
  },
  { // Entry 587
    0x1.p-1035,
    0x1.0p-1074,
    (int)39
  },
  { // Entry 588
    0x1.p-1034,
    0x1.0p-1074,
    (int)40
  },
  { // Entry 589
    0x1.p-1033,
    0x1.0p-1074,
    (int)41
  },
  { // Entry 590
    0x1.p-1032,
    0x1.0p-1074,
    (int)42
  },
  { // Entry 591
    0x1.p-1031,
    0x1.0p-1074,
    (int)43
  },
  { // Entry 592
    0x1.p-1030,
    0x1.0p-1074,
    (int)44
  },
  { // Entry 593
    0x1.p-1029,
    0x1.0p-1074,
    (int)45
  },
  { // Entry 594
    0x1.p-1028,
    0x1.0p-1074,
    (int)46
  },
  { // Entry 595
    0x1.p-1027,
    0x1.0p-1074,
    (int)47
  },
  { // Entry 596
    0x1.p-1026,
    0x1.0p-1074,
    (int)48
  },
  { // Entry 597
    0x1.p-1025,
    0x1.0p-1074,
    (int)49
  },
  { // Entry 598
    0x1.p-1024,
    0x1.0p-1074,
    (int)50
  },
  { // Entry 599
    0x1.p-1023,
    0x1.0p-1074,
    (int)51
  },
  { // Entry 600
    0x1.p-1022,
    0x1.0p-1074,
    (int)52
  },
  { // Entry 601
    0x1.p-1021,
    0x1.0p-1074,
    (int)53
  },
  { // Entry 602
    0x1.p-1020,
    0x1.0p-1074,
    (int)54
  },
  { // Entry 603
    0x1.p-1019,
    0x1.0p-1074,
    (int)55
  },
  { // Entry 604
    0x1.p-1018,
    0x1.0p-1074,
    (int)56
  },
  { // Entry 605
    0x1.p-1017,
    0x1.0p-1074,
    (int)57
  },
  { // Entry 606
    0x1.p-1016,
    0x1.0p-1074,
    (int)58
  },
  { // Entry 607
    0x1.p-1015,
    0x1.0p-1074,
    (int)59
  },
  { // Entry 608
    0x1.p-1014,
    0x1.0p-1074,
    (int)60
  },
  { // Entry 609
    0x1.p-1013,
    0x1.0p-1074,
    (int)61
  },
  { // Entry 610
    0x1.p-1012,
    0x1.0p-1074,
    (int)62
  },
  { // Entry 611
    0x1.p-1011,
    0x1.0p-1074,
    (int)63
  },
  { // Entry 612
    0x1.p-1010,
    0x1.0p-1074,
    (int)64
  },
  { // Entry 613
    0x1.p-1009,
    0x1.0p-1074,
    (int)65
  },
  { // Entry 614
    0x1.p-1008,
    0x1.0p-1074,
    (int)66
  },
  { // Entry 615
    0x1.p-1007,
    0x1.0p-1074,
    (int)67
  },
  { // Entry 616
    0x1.p-1006,
    0x1.0p-1074,
    (int)68
  },
  { // Entry 617
    0x1.p-1005,
    0x1.0p-1074,
    (int)69
  },
  { // Entry 618
    0x1.p-1004,
    0x1.0p-1074,
    (int)70
  },
  { // Entry 619
    0x1.p-1003,
    0x1.0p-1074,
    (int)71
  },
  { // Entry 620
    0x1.p-1002,
    0x1.0p-1074,
    (int)72
  },
  { // Entry 621
    0x1.p-1001,
    0x1.0p-1074,
    (int)73
  },
  { // Entry 622
    0x1.p-1000,
    0x1.0p-1074,
    (int)74
  },
  { // Entry 623
    0x1.p-999,
    0x1.0p-1074,
    (int)75
  },
  { // Entry 624
    0x1.p-998,
    0x1.0p-1074,
    (int)76
  },
  { // Entry 625
    0x1.p-997,
    0x1.0p-1074,
    (int)77
  },
  { // Entry 626
    0x1.p-996,
    0x1.0p-1074,
    (int)78
  },
  { // Entry 627
    0x1.p-995,
    0x1.0p-1074,
    (int)79
  },
  { // Entry 628
    0x1.p-994,
    0x1.0p-1074,
    (int)80
  },
  { // Entry 629
    0x1.p-993,
    0x1.0p-1074,
    (int)81
  },
  { // Entry 630
    0x1.p-992,
    0x1.0p-1074,
    (int)82
  },
  { // Entry 631
    0x1.p-991,
    0x1.0p-1074,
    (int)83
  },
  { // Entry 632
    0x1.p-990,
    0x1.0p-1074,
    (int)84
  },
  { // Entry 633
    0x1.p-989,
    0x1.0p-1074,
    (int)85
  },
  { // Entry 634
    0x1.p-988,
    0x1.0p-1074,
    (int)86
  },
  { // Entry 635
    0x1.p-987,
    0x1.0p-1074,
    (int)87
  },
  { // Entry 636
    0x1.p-986,
    0x1.0p-1074,
    (int)88
  },
  { // Entry 637
    0x1.p-985,
    0x1.0p-1074,
    (int)89
  },
  { // Entry 638
    0x1.p-984,
    0x1.0p-1074,
    (int)90
  },
  { // Entry 639
    0x1.p-983,
    0x1.0p-1074,
    (int)91
  },
  { // Entry 640
    0x1.p-982,
    0x1.0p-1074,
    (int)92
  },
  { // Entry 641
    0x1.p-981,
    0x1.0p-1074,
    (int)93
  },
  { // Entry 642
    0x1.p-980,
    0x1.0p-1074,
    (int)94
  },
  { // Entry 643
    0x1.p-979,
    0x1.0p-1074,
    (int)95
  },
  { // Entry 644
    0x1.p-978,
    0x1.0p-1074,
    (int)96
  },
  { // Entry 645
    0x1.p-977,
    0x1.0p-1074,
    (int)97
  },
  { // Entry 646
    0x1.p-976,
    0x1.0p-1074,
    (int)98
  },
  { // Entry 647
    0x1.p-975,
    0x1.0p-1074,
    (int)99
  },
  { // Entry 648
    0x1.p-974,
    0x1.0p-1074,
    (int)100
  },
  { // Entry 649
    0x1.p-973,
    0x1.0p-1074,
    (int)101
  },
  { // Entry 650
    0x1.p-972,
    0x1.0p-1074,
    (int)102
  },
  { // Entry 651
    0x1.p-971,
    0x1.0p-1074,
    (int)103
  },
  { // Entry 652
    0x1.p-970,
    0x1.0p-1074,
    (int)104
  },
  { // Entry 653
    0x1.p-969,
    0x1.0p-1074,
    (int)105
  },
  { // Entry 654
    0x1.p-968,
    0x1.0p-1074,
    (int)106
  },
  { // Entry 655
    0x1.p-967,
    0x1.0p-1074,
    (int)107
  },
  { // Entry 656
    0x1.p-966,
    0x1.0p-1074,
    (int)108
  },
  { // Entry 657
    0x1.p-965,
    0x1.0p-1074,
    (int)109
  },
  { // Entry 658
    0x1.p-964,
    0x1.0p-1074,
    (int)110
  },
  { // Entry 659
    0x1.p-963,
    0x1.0p-1074,
    (int)111
  },
  { // Entry 660
    0x1.p-962,
    0x1.0p-1074,
    (int)112
  },
  { // Entry 661
    0x1.p-961,
    0x1.0p-1074,
    (int)113
  },
  { // Entry 662
    0x1.p-960,
    0x1.0p-1074,
    (int)114
  },
  { // Entry 663
    0x1.p-959,
    0x1.0p-1074,
    (int)115
  },
  { // Entry 664
    0x1.p-958,
    0x1.0p-1074,
    (int)116
  },
  { // Entry 665
    0x1.p-957,
    0x1.0p-1074,
    (int)117
  },
  { // Entry 666
    0x1.p-956,
    0x1.0p-1074,
    (int)118
  },
  { // Entry 667
    0x1.p-955,
    0x1.0p-1074,
    (int)119
  },
  { // Entry 668
    0x1.p-954,
    0x1.0p-1074,
    (int)120
  },
  { // Entry 669
    0x1.p-953,
    0x1.0p-1074,
    (int)121
  },
  { // Entry 670
    0x1.p-952,
    0x1.0p-1074,
    (int)122
  },
  { // Entry 671
    0x1.p-951,
    0x1.0p-1074,
    (int)123
  },
  { // Entry 672
    0x1.p-950,
    0x1.0p-1074,
    (int)124
  },
  { // Entry 673
    0x1.p-949,
    0x1.0p-1074,
    (int)125
  },
  { // Entry 674
    0x1.p-948,
    0x1.0p-1074,
    (int)126
  },
  { // Entry 675
    0x1.p-947,
    0x1.0p-1074,
    (int)127
  },
  { // Entry 676
    0x1.p-946,
    0x1.0p-1074,
    (int)128
  },
  { // Entry 677
    0x1.p-945,
    0x1.0p-1074,
    (int)129
  },
  { // Entry 678
    0x1.p-944,
    0x1.0p-1074,
    (int)130
  },
  { // Entry 679
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    (int)0
  },
  { // Entry 680
    0x1.ffffffffffffe0p-1022,
    0x1.ffffffffffffep-1023,
    (int)1
  },
  { // Entry 681
    0x1.ffffffffffffe0p-1021,
    0x1.ffffffffffffep-1023,
    (int)2
  },
  { // Entry 682
    0x1.ffffffffffffe0p-1020,
    0x1.ffffffffffffep-1023,
    (int)3
  },
  { // Entry 683
    0x1.ffffffffffffe0p-1019,
    0x1.ffffffffffffep-1023,
    (int)4
  },
  { // Entry 684
    0x1.ffffffffffffe0p-1018,
    0x1.ffffffffffffep-1023,
    (int)5
  },
  { // Entry 685
    0x1.ffffffffffffe0p-1017,
    0x1.ffffffffffffep-1023,
    (int)6
  },
  { // Entry 686
    0x1.ffffffffffffe0p-1016,
    0x1.ffffffffffffep-1023,
    (int)7
  },
  { // Entry 687
    0x1.ffffffffffffe0p-1015,
    0x1.ffffffffffffep-1023,
    (int)8
  },
  { // Entry 688
    0x1.ffffffffffffe0p-1014,
    0x1.ffffffffffffep-1023,
    (int)9
  },
  { // Entry 689
    0x1.ffffffffffffe0p-1013,
    0x1.ffffffffffffep-1023,
    (int)10
  },
  { // Entry 690
    0x1.ffffffffffffe0p-1012,
    0x1.ffffffffffffep-1023,
    (int)11
  },
  { // Entry 691
    0x1.ffffffffffffe0p-1011,
    0x1.ffffffffffffep-1023,
    (int)12
  },
  { // Entry 692
    0x1.ffffffffffffe0p-1010,
    0x1.ffffffffffffep-1023,
    (int)13
  },
  { // Entry 693
    0x1.ffffffffffffe0p-1009,
    0x1.ffffffffffffep-1023,
    (int)14
  },
  { // Entry 694
    0x1.ffffffffffffe0p-1008,
    0x1.ffffffffffffep-1023,
    (int)15
  },
  { // Entry 695
    0x1.ffffffffffffe0p-1007,
    0x1.ffffffffffffep-1023,
    (int)16
  },
  { // Entry 696
    0x1.ffffffffffffe0p-1006,
    0x1.ffffffffffffep-1023,
    (int)17
  },
  { // Entry 697
    0x1.ffffffffffffe0p-1005,
    0x1.ffffffffffffep-1023,
    (int)18
  },
  { // Entry 698
    0x1.ffffffffffffe0p-1004,
    0x1.ffffffffffffep-1023,
    (int)19
  },
  { // Entry 699
    0x1.ffffffffffffe0p-1003,
    0x1.ffffffffffffep-1023,
    (int)20
  },
  { // Entry 700
    0x1.ffffffffffffe0p-1002,
    0x1.ffffffffffffep-1023,
    (int)21
  },
  { // Entry 701
    0x1.ffffffffffffe0p-1001,
    0x1.ffffffffffffep-1023,
    (int)22
  },
  { // Entry 702
    0x1.ffffffffffffe0p-1000,
    0x1.ffffffffffffep-1023,
    (int)23
  },
  { // Entry 703
    0x1.ffffffffffffe0p-999,
    0x1.ffffffffffffep-1023,
    (int)24
  },
  { // Entry 704
    0x1.ffffffffffffe0p-998,
    0x1.ffffffffffffep-1023,
    (int)25
  },
  { // Entry 705
    0x1.ffffffffffffe0p-997,
    0x1.ffffffffffffep-1023,
    (int)26
  },
  { // Entry 706
    0x1.ffffffffffffe0p-996,
    0x1.ffffffffffffep-1023,
    (int)27
  },
  { // Entry 707
    0x1.ffffffffffffe0p-995,
    0x1.ffffffffffffep-1023,
    (int)28
  },
  { // Entry 708
    0x1.ffffffffffffe0p-994,
    0x1.ffffffffffffep-1023,
    (int)29
  },
  { // Entry 709
    0x1.ffffffffffffe0p-993,
    0x1.ffffffffffffep-1023,
    (int)30
  },
  { // Entry 710
    0x1.ffffffffffffe0p-992,
    0x1.ffffffffffffep-1023,
    (int)31
  },
  { // Entry 711
    0x1.ffffffffffffe0p-991,
    0x1.ffffffffffffep-1023,
    (int)32
  },
  { // Entry 712
    0x1.ffffffffffffe0p-990,
    0x1.ffffffffffffep-1023,
    (int)33
  },
  { // Entry 713
    0x1.ffffffffffffe0p-989,
    0x1.ffffffffffffep-1023,
    (int)34
  },
  { // Entry 714
    0x1.ffffffffffffe0p-988,
    0x1.ffffffffffffep-1023,
    (int)35
  },
  { // Entry 715
    0x1.ffffffffffffe0p-987,
    0x1.ffffffffffffep-1023,
    (int)36
  },
  { // Entry 716
    0x1.ffffffffffffe0p-986,
    0x1.ffffffffffffep-1023,
    (int)37
  },
  { // Entry 717
    0x1.ffffffffffffe0p-985,
    0x1.ffffffffffffep-1023,
    (int)38
  },
  { // Entry 718
    0x1.ffffffffffffe0p-984,
    0x1.ffffffffffffep-1023,
    (int)39
  },
  { // Entry 719
    0x1.ffffffffffffe0p-983,
    0x1.ffffffffffffep-1023,
    (int)40
  },
  { // Entry 720
    0x1.ffffffffffffe0p-982,
    0x1.ffffffffffffep-1023,
    (int)41
  },
  { // Entry 721
    0x1.ffffffffffffe0p-981,
    0x1.ffffffffffffep-1023,
    (int)42
  },
  { // Entry 722
    0x1.ffffffffffffe0p-980,
    0x1.ffffffffffffep-1023,
    (int)43
  },
  { // Entry 723
    0x1.ffffffffffffe0p-979,
    0x1.ffffffffffffep-1023,
    (int)44
  },
  { // Entry 724
    0x1.ffffffffffffe0p-978,
    0x1.ffffffffffffep-1023,
    (int)45
  },
  { // Entry 725
    0x1.ffffffffffffe0p-977,
    0x1.ffffffffffffep-1023,
    (int)46
  },
  { // Entry 726
    0x1.ffffffffffffe0p-976,
    0x1.ffffffffffffep-1023,
    (int)47
  },
  { // Entry 727
    0x1.ffffffffffffe0p-975,
    0x1.ffffffffffffep-1023,
    (int)48
  },
  { // Entry 728
    0x1.ffffffffffffe0p-974,
    0x1.ffffffffffffep-1023,
    (int)49
  },
  { // Entry 729
    0x1.ffffffffffffe0p-973,
    0x1.ffffffffffffep-1023,
    (int)50
  },
  { // Entry 730
    0x1.ffffffffffffe0p-972,
    0x1.ffffffffffffep-1023,
    (int)51
  },
  { // Entry 731
    0x1.ffffffffffffe0p-971,
    0x1.ffffffffffffep-1023,
    (int)52
  },
  { // Entry 732
    0x1.ffffffffffffe0p-970,
    0x1.ffffffffffffep-1023,
    (int)53
  },
  { // Entry 733
    0x1.ffffffffffffe0p-969,
    0x1.ffffffffffffep-1023,
    (int)54
  },
  { // Entry 734
    0x1.ffffffffffffe0p-968,
    0x1.ffffffffffffep-1023,
    (int)55
  },
  { // Entry 735
    0x1.ffffffffffffe0p-967,
    0x1.ffffffffffffep-1023,
    (int)56
  },
  { // Entry 736
    0x1.ffffffffffffe0p-966,
    0x1.ffffffffffffep-1023,
    (int)57
  },
  { // Entry 737
    0x1.ffffffffffffe0p-965,
    0x1.ffffffffffffep-1023,
    (int)58
  },
  { // Entry 738
    0x1.ffffffffffffe0p-964,
    0x1.ffffffffffffep-1023,
    (int)59
  },
  { // Entry 739
    0x1.ffffffffffffe0p-963,
    0x1.ffffffffffffep-1023,
    (int)60
  },
  { // Entry 740
    0x1.ffffffffffffe0p-962,
    0x1.ffffffffffffep-1023,
    (int)61
  },
  { // Entry 741
    0x1.ffffffffffffe0p-961,
    0x1.ffffffffffffep-1023,
    (int)62
  },
  { // Entry 742
    0x1.ffffffffffffe0p-960,
    0x1.ffffffffffffep-1023,
    (int)63
  },
  { // Entry 743
    0x1.ffffffffffffe0p-959,
    0x1.ffffffffffffep-1023,
    (int)64
  },
  { // Entry 744
    0x1.ffffffffffffe0p-958,
    0x1.ffffffffffffep-1023,
    (int)65
  },
  { // Entry 745
    0x1.ffffffffffffe0p-957,
    0x1.ffffffffffffep-1023,
    (int)66
  },
  { // Entry 746
    0x1.ffffffffffffe0p-956,
    0x1.ffffffffffffep-1023,
    (int)67
  },
  { // Entry 747
    0x1.ffffffffffffe0p-955,
    0x1.ffffffffffffep-1023,
    (int)68
  },
  { // Entry 748
    0x1.ffffffffffffe0p-954,
    0x1.ffffffffffffep-1023,
    (int)69
  },
  { // Entry 749
    0x1.ffffffffffffe0p-953,
    0x1.ffffffffffffep-1023,
    (int)70
  },
  { // Entry 750
    0x1.ffffffffffffe0p-952,
    0x1.ffffffffffffep-1023,
    (int)71
  },
  { // Entry 751
    0x1.ffffffffffffe0p-951,
    0x1.ffffffffffffep-1023,
    (int)72
  },
  { // Entry 752
    0x1.ffffffffffffe0p-950,
    0x1.ffffffffffffep-1023,
    (int)73
  },
  { // Entry 753
    0x1.ffffffffffffe0p-949,
    0x1.ffffffffffffep-1023,
    (int)74
  },
  { // Entry 754
    0x1.ffffffffffffe0p-948,
    0x1.ffffffffffffep-1023,
    (int)75
  },
  { // Entry 755
    0x1.ffffffffffffe0p-947,
    0x1.ffffffffffffep-1023,
    (int)76
  },
  { // Entry 756
    0x1.ffffffffffffe0p-946,
    0x1.ffffffffffffep-1023,
    (int)77
  },
  { // Entry 757
    0x1.ffffffffffffe0p-945,
    0x1.ffffffffffffep-1023,
    (int)78
  },
  { // Entry 758
    0x1.ffffffffffffe0p-944,
    0x1.ffffffffffffep-1023,
    (int)79
  },
  { // Entry 759
    0x1.ffffffffffffe0p-943,
    0x1.ffffffffffffep-1023,
    (int)80
  },
  { // Entry 760
    0x1.ffffffffffffe0p-942,
    0x1.ffffffffffffep-1023,
    (int)81
  },
  { // Entry 761
    0x1.ffffffffffffe0p-941,
    0x1.ffffffffffffep-1023,
    (int)82
  },
  { // Entry 762
    0x1.ffffffffffffe0p-940,
    0x1.ffffffffffffep-1023,
    (int)83
  },
  { // Entry 763
    0x1.ffffffffffffe0p-939,
    0x1.ffffffffffffep-1023,
    (int)84
  },
  { // Entry 764
    0x1.ffffffffffffe0p-938,
    0x1.ffffffffffffep-1023,
    (int)85
  },
  { // Entry 765
    0x1.ffffffffffffe0p-937,
    0x1.ffffffffffffep-1023,
    (int)86
  },
  { // Entry 766
    0x1.ffffffffffffe0p-936,
    0x1.ffffffffffffep-1023,
    (int)87
  },
  { // Entry 767
    0x1.ffffffffffffe0p-935,
    0x1.ffffffffffffep-1023,
    (int)88
  },
  { // Entry 768
    0x1.ffffffffffffe0p-934,
    0x1.ffffffffffffep-1023,
    (int)89
  },
  { // Entry 769
    0x1.ffffffffffffe0p-933,
    0x1.ffffffffffffep-1023,
    (int)90
  },
  { // Entry 770
    0x1.ffffffffffffe0p-932,
    0x1.ffffffffffffep-1023,
    (int)91
  },
  { // Entry 771
    0x1.ffffffffffffe0p-931,
    0x1.ffffffffffffep-1023,
    (int)92
  },
  { // Entry 772
    0x1.ffffffffffffe0p-930,
    0x1.ffffffffffffep-1023,
    (int)93
  },
  { // Entry 773
    0x1.ffffffffffffe0p-929,
    0x1.ffffffffffffep-1023,
    (int)94
  },
  { // Entry 774
    0x1.ffffffffffffe0p-928,
    0x1.ffffffffffffep-1023,
    (int)95
  },
  { // Entry 775
    0x1.ffffffffffffe0p-927,
    0x1.ffffffffffffep-1023,
    (int)96
  },
  { // Entry 776
    0x1.ffffffffffffe0p-926,
    0x1.ffffffffffffep-1023,
    (int)97
  },
  { // Entry 777
    0x1.ffffffffffffe0p-925,
    0x1.ffffffffffffep-1023,
    (int)98
  },
  { // Entry 778
    0x1.ffffffffffffe0p-924,
    0x1.ffffffffffffep-1023,
    (int)99
  },
  { // Entry 779
    0x1.ffffffffffffe0p-923,
    0x1.ffffffffffffep-1023,
    (int)100
  },
  { // Entry 780
    0x1.ffffffffffffe0p-922,
    0x1.ffffffffffffep-1023,
    (int)101
  },
  { // Entry 781
    0x1.ffffffffffffe0p-921,
    0x1.ffffffffffffep-1023,
    (int)102
  },
  { // Entry 782
    0x1.ffffffffffffe0p-920,
    0x1.ffffffffffffep-1023,
    (int)103
  },
  { // Entry 783
    0x1.ffffffffffffe0p-919,
    0x1.ffffffffffffep-1023,
    (int)104
  },
  { // Entry 784
    0x1.ffffffffffffe0p-918,
    0x1.ffffffffffffep-1023,
    (int)105
  },
  { // Entry 785
    0x1.ffffffffffffe0p-917,
    0x1.ffffffffffffep-1023,
    (int)106
  },
  { // Entry 786
    0x1.ffffffffffffe0p-916,
    0x1.ffffffffffffep-1023,
    (int)107
  },
  { // Entry 787
    0x1.ffffffffffffe0p-915,
    0x1.ffffffffffffep-1023,
    (int)108
  },
  { // Entry 788
    0x1.ffffffffffffe0p-914,
    0x1.ffffffffffffep-1023,
    (int)109
  },
  { // Entry 789
    0x1.ffffffffffffe0p-913,
    0x1.ffffffffffffep-1023,
    (int)110
  },
  { // Entry 790
    0x1.ffffffffffffe0p-912,
    0x1.ffffffffffffep-1023,
    (int)111
  },
  { // Entry 791
    0x1.ffffffffffffe0p-911,
    0x1.ffffffffffffep-1023,
    (int)112
  },
  { // Entry 792
    0x1.ffffffffffffe0p-910,
    0x1.ffffffffffffep-1023,
    (int)113
  },
  { // Entry 793
    0x1.ffffffffffffe0p-909,
    0x1.ffffffffffffep-1023,
    (int)114
  },
  { // Entry 794
    0x1.ffffffffffffe0p-908,
    0x1.ffffffffffffep-1023,
    (int)115
  },
  { // Entry 795
    0x1.ffffffffffffe0p-907,
    0x1.ffffffffffffep-1023,
    (int)116
  },
  { // Entry 796
    0x1.ffffffffffffe0p-
"""


```
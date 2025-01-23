Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user provided a code snippet and wants to know its functionality within the Android bionic library. The specific file path `bionic/tests/math_data/fmaf_intel_data.handroid` is crucial, as it immediately suggests this is *test data* for the `fmaf` function (fused multiply-add, single-precision floating-point). The suffix "intel_data" hints at architecture-specific test cases.

2. **Identify the Data Structure:** The code is a C++ array of structs. Each struct contains four `double` values (represented in hexadecimal floating-point notation). The comments `// Entry NNN` clearly label each test case.

3. **Infer the Purpose:** Knowing this is test data for `fmaf`, I can infer the purpose: to verify the correctness of the `fmaf` function across various input values, especially edge cases and boundary conditions. The four values likely represent:
    * Input `a`
    * Input `b`
    * Input `c`
    * Expected output of `fmaf(a, b, c)`

4. **Focus on the "归纳一下它的功能" (Summarize its functionality) part:** This is the immediate goal of this specific part of the multi-part request. The core function is to provide test cases for `fmaf`.

5. **Formulate the Summary:** Based on the above, I can write a concise summary: "这个C++源代码文件 `fmaf_intel_data.handroid` 的功能是为 `fmaf` 函数（单精度浮点数的融合乘加运算）提供测试数据。这些数据用于验证 `fmaf` 函数在各种输入情况下的正确性。"

6. **Address the Other Parts (Mentally, for now, as this is part 2):** Although the immediate request is just the summary, I need to keep the broader context of the multi-part question in mind for future parts. I would mentally note:
    * **Relationship to Android:**  The `fmaf` function is part of Android's math library (bionic). This test data ensures its reliability on Android devices.
    * **libc Function Details:** `fmaf` is a standard C library function (from `math.h`). Its implementation involves hardware-level floating-point instructions.
    * **Dynamic Linker:**  While this specific *data* file doesn't directly involve the dynamic linker, the `fmaf` function *itself* is part of a shared library that the dynamic linker loads.
    * **Logical Reasoning:** The test cases likely cover various input ranges, including normal numbers, zero, infinity, NaN, and edge cases near underflow/overflow.
    * **Common Errors:** Incorrect usage of `fmaf` might involve passing the wrong data types or misunderstanding its behavior.
    * **Android Framework/NDK:**  An Android app using the NDK could call `fmaf`. The framework itself might use it internally for graphics or other computations.
    * **Frida Hook:**  Frida can be used to intercept calls to `fmaf` and examine the inputs and outputs.

7. **Refine the Summary (Self-Correction):** I review my initial summary and make sure it's accurate and addresses the core request for Part 2. I consider if there's anything I've missed. In this case, noting the "intel_data" aspect adds a bit more specificity, suggesting architecture-dependent testing.

This structured approach, starting with the high-level understanding and progressively drilling down into the details (even if just mentally for subsequent parts), allows me to generate a relevant and informative answer. For this specific Part 2, the focus remains tightly on summarizing the file's purpose.

好的，根据您提供的代码片段，这是 `bionic/tests/math_data/fmaf_intel_data.handroid` 文件的第二部分。这个文件是 Android Bionic 库中用于测试 `fmaf` 函数（浮点数乘加运算）的数据文件。

**功能归纳：**

这个 C++ 源代码文件 `fmaf_intel_data.handroid` 的功能是为 `fmaf` 函数（单精度浮点数的融合乘加运算）提供测试数据。这些数据用于验证 `fmaf` 函数在各种输入情况下的正确性。

**更详细的解释（尽管是第2部分，但为了完整性，先进行初步分析）：**

* **测试 `fmaf` 函数：**  文件名中的 `fmaf` 表明这个文件专门用于测试 `fmaf` 函数。`fmaf` 是 fused multiply-add float 的缩写，表示浮点数的融合乘加运算，即计算 `a * b + c`，并且这个运算在硬件层面通常作为一个原子操作完成，以提高精度和效率。
* **提供测试用例：** 文件中的每一组 `{...}` 都代表一个测试用例。每个测试用例包含四个浮点数值。根据惯例和文件名，可以推测这四个值分别代表 `fmaf(a, b, c)` 的输入参数 `a`、`b`、`c` 和期望的输出结果。
* **覆盖多种输入情况：**  从数据中可以看出，测试用例覆盖了各种浮点数值，包括：
    * 常规数值 (例如 `0x1.000002p0`, `0x1.fffffep126`)
    * 特殊值（例如 `HUGE_VALF` 表示无穷大，`0.0` 表示零）
    * 正数和负数
    * 不同数量级和精度的数值
* **“intel_data”的含义：** 文件名中的 `intel_data` 可能意味着这些测试数据是基于 Intel 架构的特性或者为了在 Intel 处理器上进行更细致的测试而设计的。也可能是指最初的测试数据来源与 Intel 相关。
* **“.handroid” 的含义：** 这个后缀表明这些数据是为 Android 平台准备的。

**与 Android 功能的关系和举例：**

`fmaf` 函数是标准 C 库 `math.h` 中的函数，Android 的 Bionic 库提供了这个函数的实现。

* **图形渲染：** Android 的图形渲染引擎（例如 Skia）在进行矩阵运算、光照计算等过程中可能会使用到 `fmaf` 这样的数学函数来提高计算精度和性能。
* **音频处理：** 音频编解码、混音等操作也涉及到大量的浮点数运算，`fmaf` 可以用于优化这些计算。
* **科学计算和机器学习：** 如果 Android 应用涉及到科学计算、机器学习等领域，底层的库可能会使用 `fmaf` 来加速向量和矩阵运算。
* **NDK 开发：** 使用 Android NDK 进行原生开发的开发者可以直接调用 `fmaf` 函数，利用其性能优势。

**libc 函数的实现（`fmaf`）：**

`fmaf` 函数的实现通常依赖于底层硬件的支持。现代处理器（包括 ARM 和 x86）通常提供了专门的 FMA (Fused Multiply-Add) 指令。

1. **参数传递：**  当程序调用 `fmaf(a, b, c)` 时，参数 `a`、`b` 和 `c` 会被传递到对应的寄存器或者栈位置。
2. **硬件 FMA 指令：** Bionic 库中的 `fmaf` 函数实现会调用底层的 FMA 硬件指令。例如，在 x86 架构上可能是 `vfmaddss` 或 `vfmaddsd` 指令，在 ARM 架构上可能是 `fmla` 指令。
3. **原子操作：** 硬件 FMA 指令会将乘法和加法作为一个原子操作执行，这意味着中间结果不会被舍入，从而提高了最终结果的精度。
4. **返回结果：**  计算结果会存储在寄存器中，并作为函数的返回值返回。

**Dynamic Linker 的功能和链接处理过程（与此数据文件间接相关）：**

虽然这个数据文件本身不涉及 dynamic linker，但 `fmaf` 函数是 Bionic 库的一部分，而 Bionic 库是以共享对象 (Shared Object, `.so`) 的形式存在的，需要 dynamic linker 来加载和链接。

**SO 布局样本：**

假设一个使用了 `fmaf` 函数的 Native 库 `libmylib.so`：

```
libmylib.so:
    地址范围: 0xb4000000 - 0xb4010000
    .text (代码段): 0xb4000800 - 0xb400ffff  (包含调用 fmaf 的代码)
    .rodata (只读数据段): 0xb4010000 - 0xb4010800
    .data (可读写数据段): 0xb4010800 - 0xb4011000
    .bss (未初始化数据段): 0xb4011000 - 0xb4011800
    ...
    依赖的共享库:
        libc.so (包含 fmaf 的实现)

libc.so:
    地址范围: 0xb6000000 - 0xb6100000
    .text (代码段): 0xb6010000 - 0xb6080000 (包含 fmaf 的实现)
    ...
```

**链接的处理过程：**

1. **加载：** 当 Android 系统启动或者应用启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载必要的共享库，例如 `libc.so` 和 `libmylib.so`。
2. **符号查找：** 当 `libmylib.so` 中的代码调用 `fmaf` 时，dynamic linker 需要找到 `fmaf` 函数在 `libc.so` 中的地址。这通过查找符号表来实现。
3. **重定位：** 由于共享库加载到内存的地址可能是不固定的（ASLR），dynamic linker 需要对代码中的符号引用进行重定位，将对 `fmaf` 的调用地址修改为 `fmaf` 在 `libc.so` 中实际的加载地址。
4. **绑定：**  在首次调用 `fmaf` 时（或者在加载时进行完全绑定），`libmylib.so` 中对 `fmaf` 的调用会被绑定到 `libc.so` 中 `fmaf` 的实际地址。

**假设输入与输出（针对数据文件）：**

数据文件中的每一项都可以看作一个假设的输入和期望的输出。例如：

* **假设输入：** `a = fffcp126`, `b = 0x1.000002p0`, `c = 0x1.fffffep126`
* **期望输出：**  `fmaf(fffcp126, 0x1.000002p0, 0x1.fffffep126)` 的结果应该与数据文件中的第四个值一致。

测试代码会读取这些数据，然后实际调用 `fmaf` 函数，并将结果与期望的输出进行比较，以验证 `fmaf` 函数的正确性。

**用户或编程常见的使用错误：**

* **数据类型不匹配：**  将 `fmaf` 的参数传递为 `double` 或 `long double` 类型，而不是 `float`。虽然可能发生隐式转换，但这可能不是预期的行为，并且 `fma` 和 `fmal` 函数分别对应 `double` 和 `long double` 版本。
* **精度问题误解：**  不理解 FMA 的精度优势，仍然使用 `a * b + c` 的方式进行计算，可能导致在某些情况下精度损失。
* **性能考虑不周：**  在不需要高精度的情况下过度使用 FMA，可能引入不必要的开销。尽管 FMA 通常很快，但简单的乘加操作在某些架构上可能更轻量级。
* **忽略特殊值处理：**  没有充分测试和处理 NaN (Not a Number)、Infinity 等特殊浮点数值作为输入的情况。

**Frida Hook 示例调试步骤：**

假设你想 hook `fmaf` 函数来查看其输入和输出：

1. **准备 Frida 环境：** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在 PC 上安装了 Frida 客户端。
2. **编写 Frida 脚本：**

```javascript
Java.perform(function() {
    var libm = Process.getModuleByName("libm.so"); // 或者找到包含 fmaf 的具体库
    var fmaf_addr = libm.getExportByName("fmaf");

    Interceptor.attach(fmaf_addr, {
        onEnter: function(args) {
            console.log("调用 fmaf:");
            console.log("  参数 a: " + parseFloat(ptr(args[0]).readFloat()));
            console.log("  参数 b: " + parseFloat(ptr(args[4]).readFloat())); // 注意参数在不同架构和调用约定下可能位置不同
            console.log("  参数 c: " + parseFloat(ptr(args[8]).readFloat()));
        },
        onLeave: function(retval) {
            console.log("fmaf 返回值: " + parseFloat(ptr(retval).readFloat()));
        }
    });
});
```

3. **运行 Frida 脚本：** 使用 Frida 客户端连接到 Android 设备上的目标进程：

```bash
frida -U -f <目标应用的包名> -l your_frida_script.js --no-pause
```

或者，如果目标进程已经在运行：

```bash
frida -U <目标应用的包名> -l your_frida_script.js
```

4. **触发 `fmaf` 调用：**  运行目标应用，执行会调用 `fmaf` 函数的操作。
5. **查看 Frida 输出：** Frida 会在控制台上打印出每次调用 `fmaf` 时的参数值和返回值。

**Android Framework 或 NDK 如何到达这里：**

1. **NDK 开发：** 开发者使用 NDK 编写 C/C++ 代码，并在代码中直接调用 `fmaf` 函数。
2. **编译：** NDK 编译工具链会将 C/C++ 代码编译成包含 `fmaf` 调用的机器码。
3. **打包：** 编译后的 Native 库 (`.so` 文件) 会被打包到 APK 文件中。
4. **加载和链接：** 当应用运行时，Android 系统会加载 Native 库，dynamic linker 会负责链接 `fmaf` 函数到 Bionic 库中的实现。
5. **Framework 调用：**  Android Framework 内部的某些组件（例如图形、音频相关的服务）的 Native 代码可能会调用 `fmaf`。这些调用路径可能比较复杂，涉及多个 Framework 层的组件。

**总结第2部分的功能：**

总而言之，这个代码片段是 `fmaf_intel_data.handroid` 文件的一部分，其核心功能是作为 `fmaf` 函数的测试数据。它包含了一系列预定义的输入和期望输出，用于验证 `fmaf` 函数在 Android 平台上的 Bionic 库实现是否正确。

### 提示词
```
这是目录为bionic/tests/math_data/fmaf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
fffcp126,
    0x1.000002p0,
    0x1.fffffep126
  },
  { // Entry 339
    HUGE_VALF,
    0x1.fffffcp126,
    0x1.000002p0,
    0x1.p127
  },
  { // Entry 340
    0x1.fffffc000001p127,
    0x1.fffffep126,
    0x1.fffffep-1,
    0x1.fffffcp126
  },
  { // Entry 341
    0x1.fffffd000001p127,
    0x1.fffffep126,
    0x1.fffffep-1,
    0x1.fffffep126
  },
  { // Entry 342
    0x1.fffffe000001p127,
    0x1.fffffep126,
    0x1.fffffep-1,
    0x1.p127
  },
  { // Entry 343
    0x1.fffffdp127,
    0x1.fffffep126,
    0x1.p0,
    0x1.fffffcp126
  },
  { // Entry 344
    0x1.fffffep127,
    0x1.fffffep126,
    0x1.p0,
    0x1.fffffep126
  },
  { // Entry 345
    HUGE_VALF,
    0x1.fffffep126,
    0x1.p0,
    0x1.p127
  },
  { // Entry 346
    0x1.fffffefffffep127,
    0x1.fffffep126,
    0x1.000002p0,
    0x1.fffffcp126
  },
  { // Entry 347
    HUGE_VALF,
    0x1.fffffep126,
    0x1.000002p0,
    0x1.fffffep126
  },
  { // Entry 348
    HUGE_VALF,
    0x1.fffffep126,
    0x1.000002p0,
    0x1.p127
  },
  { // Entry 349
    0x1.fffffdp127,
    0x1.p127,
    0x1.fffffep-1,
    0x1.fffffcp126
  },
  { // Entry 350
    0x1.fffffep127,
    0x1.p127,
    0x1.fffffep-1,
    0x1.fffffep126
  },
  { // Entry 351
    HUGE_VALF,
    0x1.p127,
    0x1.fffffep-1,
    0x1.p127
  },
  { // Entry 352
    0x1.fffffep127,
    0x1.p127,
    0x1.p0,
    0x1.fffffcp126
  },
  { // Entry 353
    HUGE_VALF,
    0x1.p127,
    0x1.p0,
    0x1.fffffep126
  },
  { // Entry 354
    HUGE_VALF,
    0x1.p127,
    0x1.p0,
    0x1.p127
  },
  { // Entry 355
    HUGE_VALF,
    0x1.p127,
    0x1.000002p0,
    0x1.fffffcp126
  },
  { // Entry 356
    HUGE_VALF,
    0x1.p127,
    0x1.000002p0,
    0x1.fffffep126
  },
  { // Entry 357
    HUGE_VALF,
    0x1.p127,
    0x1.000002p0,
    0x1.p127
  },
  { // Entry 358
    0x1.fffffd000001p0,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 359
    0x1.fffffe000001p0,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 360
    0x1.00000000000080p1,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 361
    0x1.fffffep0,
    0x1.fffffep-1,
    0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 362
    0x1.ffffffp0,
    0x1.fffffep-1,
    0x1.p0,
    0x1.p0
  },
  { // Entry 363
    0x1.00000080p1,
    0x1.fffffep-1,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 364
    0x1.fffffffffffep0,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 365
    0x1.0000007fffffp1,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.p0
  },
  { // Entry 366
    0x1.0000017fffffp1,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 367
    0x1.fffffep0,
    0x1.p0,
    0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 368
    0x1.ffffffp0,
    0x1.p0,
    0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 369
    0x1.00000080p1,
    0x1.p0,
    0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 370
    0x1.ffffffp0,
    0x1.p0,
    0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 371
    0x1.p1,
    0x1.p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 372
    0x1.000001p1,
    0x1.p0,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 373
    0x1.00000080p1,
    0x1.p0,
    0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 374
    0x1.000001p1,
    0x1.p0,
    0x1.000002p0,
    0x1.p0
  },
  { // Entry 375
    0x1.000002p1,
    0x1.p0,
    0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 376
    0x1.fffffffffffep0,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 377
    0x1.0000007fffffp1,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 378
    0x1.0000017fffffp1,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 379
    0x1.00000080p1,
    0x1.000002p0,
    0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 380
    0x1.000001p1,
    0x1.000002p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 381
    0x1.000002p1,
    0x1.000002p0,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 382
    0x1.000001800002p1,
    0x1.000002p0,
    0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 383
    0x1.000002000002p1,
    0x1.000002p0,
    0x1.000002p0,
    0x1.p0
  },
  { // Entry 384
    0x1.000003000002p1,
    0x1.000002p0,
    0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 385
    -0x1.fffffep-24,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 386
    -0x1.fffffcp-25,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.p0
  },
  { // Entry 387
    0x1.000002p-24,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 388
    0.0,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 389
    0x1.p-24,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 390
    0x1.80p-23,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.000002p0
  },
  { // Entry 391
    0x1.fffffep-25,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 392
    0x1.ffffffp-24,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 393
    0x1.ffffff80p-23,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 394
    -0x1.80p-23,
    0x1.p0,
    -0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 395
    -0x1.p-23,
    0x1.p0,
    -0x1.000002p0,
    0x1.p0
  },
  { // Entry 396
    0.0,
    0x1.p0,
    -0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 397
    -0x1.p-24,
    0x1.p0,
    -0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 398
    0.0,
    0x1.p0,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 399
    0x1.p-23,
    0x1.p0,
    -0x1.p0,
    0x1.000002p0
  },
  { // Entry 400
    0.0,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 401
    0x1.p-24,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 402
    0x1.80p-23,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 403
    -0x1.400001p-22,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 404
    -0x1.000001p-22,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.p0
  },
  { // Entry 405
    -0x1.000002p-23,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 406
    -0x1.80p-23,
    0x1.000002p0,
    -0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 407
    -0x1.p-23,
    0x1.000002p0,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 408
    0.0,
    0x1.000002p0,
    -0x1.p0,
    0x1.000002p0
  },
  { // Entry 409
    -0x1.fffffep-24,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 410
    -0x1.fffffcp-25,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 411
    0x1.000002p-24,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 412
    0x1.fffffc000001ffffffffffffffffffffp-1,
    0x1.fffffep-1,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 413
    0x1.fffffc000002p-1,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 414
    0x1.fffffc000002p-1,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 415
    0x1.fffffdffffffffffffffffffffffffffp-1,
    0x1.fffffep-1,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 416
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.p0,
    0.0
  },
  { // Entry 417
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 418
    0x1.000000fffffdffffffffffffffffffffp0,
    0x1.fffffep-1,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 419
    0x1.000000fffffep0,
    0x1.fffffep-1,
    0x1.000002p0,
    0.0
  },
  { // Entry 420
    0x1.000000fffffep0,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 421
    0x1.fffffdffffffffffffffffffffffffffp-1,
    0x1.p0,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 422
    0x1.fffffep-1,
    0x1.p0,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 423
    0x1.fffffep-1,
    0x1.p0,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 424
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p0,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 425
    0x1.p0,
    0x1.p0,
    0x1.p0,
    0.0
  },
  { // Entry 426
    0x1.p0,
    0x1.p0,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 427
    0x1.000001ffffffffffffffffffffffffffp0,
    0x1.p0,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 428
    0x1.000002p0,
    0x1.p0,
    0x1.000002p0,
    0.0
  },
  { // Entry 429
    0x1.000002p0,
    0x1.p0,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 430
    0x1.000000fffffdffffffffffffffffffffp0,
    0x1.000002p0,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 431
    0x1.000000fffffep0,
    0x1.000002p0,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 432
    0x1.000000fffffep0,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 433
    0x1.000001ffffffffffffffffffffffffffp0,
    0x1.000002p0,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 434
    0x1.000002p0,
    0x1.000002p0,
    0x1.p0,
    0.0
  },
  { // Entry 435
    0x1.000002p0,
    0x1.000002p0,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 436
    0x1.000004000003ffffffffffffffffffffp0,
    0x1.000002p0,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 437
    0x1.000004000004p0,
    0x1.000002p0,
    0x1.000002p0,
    0.0
  },
  { // Entry 438
    0x1.000004000004p0,
    0x1.000002p0,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 439
    -0x1.000000fffffep0,
    0x1.fffffep-1,
    -0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 440
    -0x1.000000fffffep0,
    0x1.fffffep-1,
    -0x1.000002p0,
    0.0
  },
  { // Entry 441
    -0x1.000000fffffdffffffffffffffffffffp0,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.p-149
  },
  { // Entry 442
    -0x1.fffffep-1,
    0x1.fffffep-1,
    -0x1.p0,
    -0x1.p-149
  },
  { // Entry 443
    -0x1.fffffep-1,
    0x1.fffffep-1,
    -0x1.p0,
    0.0
  },
  { // Entry 444
    -0x1.fffffdffffffffffffffffffffffffffp-1,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.p-149
  },
  { // Entry 445
    -0x1.fffffc000002p-1,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 446
    -0x1.fffffc000002p-1,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0.0
  },
  { // Entry 447
    -0x1.fffffc000001ffffffffffffffffffffp-1,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 448
    -0x1.000002p0,
    0x1.p0,
    -0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 449
    -0x1.000002p0,
    0x1.p0,
    -0x1.000002p0,
    0.0
  },
  { // Entry 450
    -0x1.000001ffffffffffffffffffffffffffp0,
    0x1.p0,
    -0x1.000002p0,
    0x1.p-149
  },
  { // Entry 451
    -0x1.p0,
    0x1.p0,
    -0x1.p0,
    -0x1.p-149
  },
  { // Entry 452
    -0x1.p0,
    0x1.p0,
    -0x1.p0,
    0.0
  },
  { // Entry 453
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p0,
    -0x1.p0,
    0x1.p-149
  },
  { // Entry 454
    -0x1.fffffep-1,
    0x1.p0,
    -0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 455
    -0x1.fffffep-1,
    0x1.p0,
    -0x1.fffffep-1,
    0.0
  },
  { // Entry 456
    -0x1.fffffdffffffffffffffffffffffffffp-1,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 457
    -0x1.000004000004p0,
    0x1.000002p0,
    -0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 458
    -0x1.000004000004p0,
    0x1.000002p0,
    -0x1.000002p0,
    0.0
  },
  { // Entry 459
    -0x1.000004000003ffffffffffffffffffffp0,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.p-149
  },
  { // Entry 460
    -0x1.000002p0,
    0x1.000002p0,
    -0x1.p0,
    -0x1.p-149
  },
  { // Entry 461
    -0x1.000002p0,
    0x1.000002p0,
    -0x1.p0,
    0.0
  },
  { // Entry 462
    -0x1.000001ffffffffffffffffffffffffffp0,
    0x1.000002p0,
    -0x1.p0,
    0x1.p-149
  },
  { // Entry 463
    -0x1.000000fffffep0,
    0x1.000002p0,
    -0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 464
    -0x1.000000fffffep0,
    0x1.000002p0,
    -0x1.fffffep-1,
    0.0
  },
  { // Entry 465
    -0x1.000000fffffdffffffffffffffffffffp0,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 466
    0x1.000ffdfff001p0,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.fffffep-13
  },
  { // Entry 467
    0x1.000ffe000001p0,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.p-12
  },
  { // Entry 468
    0x1.000ffe002001p0,
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.000002p-12
  },
  { // Entry 469
    0x1.000ffefff0p0,
    0x1.fffffep-1,
    0x1.p0,
    0x1.fffffep-13
  },
  { // Entry 470
    0x1.000fffp0,
    0x1.fffffep-1,
    0x1.p0,
    0x1.p-12
  },
  { // Entry 471
    0x1.000fff0020p0,
    0x1.fffffep-1,
    0x1.p0,
    0x1.000002p-12
  },
  { // Entry 472
    0x1.001000ffeffep0,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.fffffep-13
  },
  { // Entry 473
    0x1.001000fffffep0,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.p-12
  },
  { // Entry 474
    0x1.001001001ffep0,
    0x1.fffffep-1,
    0x1.000002p0,
    0x1.000002p-12
  },
  { // Entry 475
    0x1.000ffefff0p0,
    0x1.p0,
    0x1.fffffep-1,
    0x1.fffffep-13
  },
  { // Entry 476
    0x1.000fffp0,
    0x1.p0,
    0x1.fffffep-1,
    0x1.p-12
  },
  { // Entry 477
    0x1.000fff0020p0,
    0x1.p0,
    0x1.fffffep-1,
    0x1.000002p-12
  },
  { // Entry 478
    0x1.000ffffff0p0,
    0x1.p0,
    0x1.p0,
    0x1.fffffep-13
  },
  { // Entry 479
    0x1.0010p0,
    0x1.p0,
    0x1.p0,
    0x1.p-12
  },
  { // Entry 480
    0x1.0010000020p0,
    0x1.p0,
    0x1.p0,
    0x1.000002p-12
  },
  { // Entry 481
    0x1.001001fff0p0,
    0x1.p0,
    0x1.000002p0,
    0x1.fffffep-13
  },
  { // Entry 482
    0x1.001002p0,
    0x1.p0,
    0x1.000002p0,
    0x1.p-12
  },
  { // Entry 483
    0x1.0010020020p0,
    0x1.p0,
    0x1.000002p0,
    0x1.000002p-12
  },
  { // Entry 484
    0x1.001000ffeffep0,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.fffffep-13
  },
  { // Entry 485
    0x1.001000fffffep0,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.p-12
  },
  { // Entry 486
    0x1.001001001ffep0,
    0x1.000002p0,
    0x1.fffffep-1,
    0x1.000002p-12
  },
  { // Entry 487
    0x1.001001fff0p0,
    0x1.000002p0,
    0x1.p0,
    0x1.fffffep-13
  },
  { // Entry 488
    0x1.001002p0,
    0x1.000002p0,
    0x1.p0,
    0x1.p-12
  },
  { // Entry 489
    0x1.0010020020p0,
    0x1.000002p0,
    0x1.p0,
    0x1.000002p-12
  },
  { // Entry 490
    0x1.001003fff004p0,
    0x1.000002p0,
    0x1.000002p0,
    0x1.fffffep-13
  },
  { // Entry 491
    0x1.001004000004p0,
    0x1.000002p0,
    0x1.000002p0,
    0x1.p-12
  },
  { // Entry 492
    0x1.001004002004p0,
    0x1.000002p0,
    0x1.000002p0,
    0x1.000002p-12
  },
  { // Entry 493
    -0x1.ffe002001ffcp-1,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.fffffep-13
  },
  { // Entry 494
    -0x1.ffe001fffffcp-1,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.p-12
  },
  { // Entry 495
    -0x1.ffe001ffbffcp-1,
    0x1.fffffep-1,
    -0x1.000002p0,
    0x1.000002p-12
  },
  { // Entry 496
    -0x1.ffdffe0020p-1,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.fffffep-13
  },
  { // Entry 497
    -0x1.ffdffep-1,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.p-12
  },
  { // Entry 498
    -0x1.ffdffdffc0p-1,
    0x1.fffffep-1,
    -0x1.p0,
    0x1.000002p-12
  },
  { // Entry 499
    -0x1.ffdffc002002p-1,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.fffffep-13
  },
  { // Entry 500
    -0x1.ffdffc000002p-1,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.p-12
  },
  { // Entry 501
    -0x1.ffdffbffc002p-1,
    0x1.fffffep-1,
    -0x1.fffffep-1,
    0x1.000002p-12
  },
  { // Entry 502
    -0x1.ffe0040020p-1,
    0x1.p0,
    -0x1.000002p0,
    0x1.fffffep-13
  },
  { // Entry 503
    -0x1.ffe004p-1,
    0x1.p0,
    -0x1.000002p0,
    0x1.p-12
  },
  { // Entry 504
    -0x1.ffe003ffc0p-1,
    0x1.p0,
    -0x1.000002p0,
    0x1.000002p-12
  },
  { // Entry 505
    -0x1.ffe0000020p-1,
    0x1.p0,
    -0x1.p0,
    0x1.fffffep-13
  },
  { // Entry 506
    -0x1.ffe0p-1,
    0x1.p0,
    -0x1.p0,
    0x1.p-12
  },
  { // Entry 507
    -0x1.ffdfffffc0p-1,
    0x1.p0,
    -0x1.p0,
    0x1.000002p-12
  },
  { // Entry 508
    -0x1.ffdffe0020p-1,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.fffffep-13
  },
  { // Entry 509
    -0x1.ffdffep-1,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.p-12
  },
  { // Entry 510
    -0x1.ffdffdffc0p-1,
    0x1.p0,
    -0x1.fffffep-1,
    0x1.000002p-12
  },
  { // Entry 511
    -0x1.ffe008002008p-1,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.fffffep-13
  },
  { // Entry 512
    -0x1.ffe008000008p-1,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.p-12
  },
  { // Entry 513
    -0x1.ffe007ffc008p-1,
    0x1.000002p0,
    -0x1.000002p0,
    0x1.000002p-12
  },
  { // Entry 514
    -0x1.ffe0040020p-1,
    0x1.000002p0,
    -0x1.p0,
    0x1.fffffep-13
  },
  { // Entry 515
    -0x1.ffe004p-1,
    0x1.000002p0,
    -0x1.p0,
    0x1.p-12
  },
  { // Entry 516
    -0x1.ffe003ffc0p-1,
    0x1.000002p0,
    -0x1.p0,
    0x1.000002p-12
  },
  { // Entry 517
    -0x1.ffe002001ffcp-1,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.fffffep-13
  },
  { // Entry 518
    -0x1.ffe001fffffcp-1,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.p-12
  },
  { // Entry 519
    -0x1.ffe001ffbffcp-1,
    0x1.000002p0,
    -0x1.fffffep-1,
    0x1.000002p-12
  },
  { // Entry 520
    -0x1.ffffff80p0,
    0x1.fffffep22,
    0x1.fffffep-1,
    -0x1.000002p23
  },
  { // Entry 521
    -0x1.ffffffp-1,
    0x1.fffffep22,
    0x1.fffffep-1,
    -0x1.p23
  },
  { // Entry 522
    -0x1.fffffep-2,
    0x1.fffffep22,
    0x1.fffffep-1,
    -0x1.fffffep22
  },
  { // Entry 523
    -0x1.80p0,
    0x1.fffffep22,
    0x1.p0,
    -0x1.000002p23
  },
  { // Entry 524
    -0x1.p-1,
    0x1.fffffep22,
    0x1.p0,
    -0x1.p23
  },
  { // Entry 525
    0.0,
    0x1.fffffep22,
    0x1.p0,
    -0x1.fffffep22
  },
  { // Entry 526
    -0x1.000002p-1,
    0x1.fffffep22,
    0x1.000002p0,
    -0x1.000002p23
  },
  { // Entry 527
    0x1.fffffcp-2,
    0x1.fffffep22,
    0x1.000002p0,
    -0x1.p23
  },
  { // Entry 528
    0x1.fffffep-1,
    0x1.fffffep22,
    0x1.000002p0,
    -0x1.fffffep22
  },
  { // Entry 529
    -0x1.80p0,
    0x1.p23,
    0x1.fffffep-1,
    -0x1.000002p23
  },
  { // Entry 530
    -0x1.p-1,
    0x1.p23,
    0x1.fffffep-1,
    -0x1.p23
  },
  { // Entry 531
    0.0,
    0x1.p23,
    0x1.fffffep-1,
    -0x1.fffffep22
  },
  { // Entry 532
    -0x1.p0,
    0x1.p23,
    0x1.p0,
    -0x1.000002p23
  },
  { // Entry 533
    0.0,
    0x1.p23,
    0x1.p0,
    -0x1.p23
  },
  { // Entry 534
    0x1.p-1,
    0x1.p23,
    0x1.p0,
    -0x1.fffffep22
  },
  { // Entry 535
    0.0,
    0x1.p23,
    0x1.000002p0,
    -0x1.000002p23
  },
  { // Entry 536
    0x1.p0,
    0x1.p23,
    0x1.000002p0,
    -0x1.p23
  },
  { // Entry 537
    0x1.80p0,
    0x1.p23,
    0x1.000002p0,
    -0x1.fffffep22
  },
  { // Entry 538
    -0x1.000002p-1,
    0x1.000002p23,
    0x1.fffffep-1,
    -0x1.000002p23
  },
  { // Entry 539
    0x1.fffffcp-2,
    0x1.000002p23,
    0x1.fffffep-1,
    -0x1.p23
  },
  { // Entry 540
    0x1.fffffep-1,
    0x1.000002p23,
    0x1.fffffep-1,
    -0x1.fffffep22
  },
  { // Entry 541
    0.0,
    0x1.000002p23,
    0x1.p0,
    -0x1.000002p23
  },
  { // Entry 542
    0x1.p0,
    0x1.000002p23,
    0x1.p0,
    -0x1.p23
  },
  { // Entry 543
    0x1.80p0,
    0x1.000002p23,
    0x1.p0,
    -0x1.fffffep22
  },
  { // Entry 544
    0x1.000002p0,
    0x1.000002p23,
    0x1.000002p0,
    -0x1.000002p23
  },
  { // Entry 545
    0x1.000001p1,
    0x1.000002p23,
    0x1.000002p0,
    -0x1.p23
  },
  { // Entry 546
    0x1.400001p1,
    0x1.000002p23,
    0x1.000002p0,
    -0x1.fffffep22
  },
  { // Entry 547
    0x1.08p-5,
    0x1.p-5,
    0x1.p-5,
    0x1.p-5
  },
  { // Entry 548
    0x1.0040p0,
    0x1.p-5,
    0x1.p-5,
    0x1.p0
  },
  { // Entry 549
    0x1.p-4,
    0x1.p-5,
    0x1.p0,
    0x1.p-5
  },
  { // Entry 550
    0x1.08p0,
    0x1.p-5,
    0x1.p0,
    0x1.p0
  },
  { // Entry 551
    0x1.p-4,
    0x1.p0,
    0x1.p-5,
    0x1.p-5
  },
  { // Entry 552
    0x1.08p0,
    0x1.p0,
    0x1.p-5,
    0x1.p0
  },
  { // Entry 553
    0x1.08p0,
    0x1.p0,
    0x1.p0,
    0x1.p-5
  },
  { // Entry 554
    0x1.p1,
    0x1.p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 555
    0x1.20p-2,
    0x1.p-5,
    0x1.p3,
    0x1.p-5
  },
  { // Entry 556
    0x1.40p0,
    0x1.p-5,
    0x1.p3,
    0x1.p0
  },
  { // Entry 557
    0x1.08p0,
    0x1.p-5,
    0x1.p5,
    0x1.p-5
  },
  { // Entry 558
    0x1.p1,
    0x1.p-5,
    0x1.p5,
    0x1.p0
  },
  { // Entry 559
    0x1.01p3,
    0x1.p0,
    0x1.p3,
    0x1.p-5
  },
  { // Entry 560
    0x1.20p3,
    0x1.p0,
    0x1.p3,
    0x1.p0
  },
  { // Entry 561
    0x1.0040p5,
    0x1.p0,
    0x1.p5,
    0x1.p-5
  },
  { // Entry 562
    0x1.08p5,
    0x1.p0,
    0x1.p5,
    0x1.p0
  },
  { // Entry 563
    0x1.0040p5,
    0x1.p-5,
    0x1.p10,
    0x1.p-5
  },
  { // Entry 564
    0x1.08p5,
    0x1.p-5,
    0x1.p10,
    0x1.p0
  },
  { // Entry 565
    0x1.0010p7,
    0x1.p-5,
    0x1.p12,
    0x1.p-5
  },
  { // Entry 566
    0x1.02p7,
    0x1.p-5,
    0x1.p12,
    0x1.p0
  },
  { // Entry 567
    0x1.0002p10,
    0x1.p0,
    0x1.p10,
    0x1.p-5
  },
  { // Entry 568
    0x1.0040p10,
    0x1.p0,
    0x1.p10,
    0x1.p0
  },
  { // Entry 569
    0x1.000080p12,
    0x1.p0,
    0x1.p12,
    0x1.p-5
  },
  { // Entry 570
    0x1.0010p12,
    0x1.p0,
    0x1.p12,
    0x1.p0
  },
  { // Entry 571
    0x1.0008p3,
    0x1.p-5,
    0x1.p-5,
    0x1.p3
  },
  { // Entry 572
    0x1.0002p5,
    0x1.p-5,
    0x1.p-5,
    0x1.p5
  },
  { // Entry 573
    0x1.01p3,
    0x1.p-5,
    0x1.p0,
    0x1.p3
  },
  { // Entry 574
    0x1.0040p5,
    0x1.p-5,
    0x1.p0,
    0x1.p5
  },
  { // Entry 575
    0x1.01p3,
    0x1.p0,
    0x1.p-5,
    0x1.p3
  },
  { // Entry 576
    0x1.0040p5,
    0x1.p0,
    0x1.p-5,
    0x1.p5
  },
  { // Entry 577
    0x1.20p3,
    0x1.p0,
    0x1.p0,
    0x1.p3
  },
  { // Entry 578
    0x1.08p5,
    0x1.p0,
    0x1.p0,
    0x1.p5
  },
  { // Entry 579
    0x1.08p3,
    0x1.p-5,
    0x1.p3,
    0x1.p3
  },
  { // Entry 580
    0x1.02p5,
    0x1.p-5,
    0x1.p3,
    0x1.p5
  },
  { // Entry 581
    0x1.20p3,
    0x1.p-5,
    0x1.p5,
    0x1.p3
  },
  { // Entry 582
    0x1.08p5,
    0x1.p-5,
    0x1.p5,
    0x1.p5
  },
  { // Entry 583
    0x1.p4,
    0x1.p0,
    0x1.p3,
    0x1.p3
  },
  { // Entry 584
    0x1.40p5,
    0x1.p0,
    0x1.p3,
    0x1.p5
  },
  { // Entry 585
    0x1.40p5,
    0x1.p0,
    0x1.p5,
    0x1.p3
  },
  { // Entry 586
    0x1.p6,
    0x1.p0,
    0x1.p5,
    0x1.p5
  },
  { // Entry 587
    0x1.40p5,
    0x1.p-5,
    0x1.p10,
    0x1.p3
  },
  { // Entry 588
    0x1.p6,
    0x1.p-5,
    0x1.p10,
    0x1.p5
  },
  { // Entry 589
    0x1.10p7,
    0x1.p-5,
    0x1.p12,
    0x1.p3
  },
  { // Entry 590
    0x1.40p7,
    0x1.p-5,
    0x1.p12,
    0x1.p5
  },
  { // Entry 591
    0x1.02p10,
    0x1.p0,
    0x1.p10,
    0x1.p3
  },
  { // Entry 592
    0x1.08p10,
    0x1.p0,
    0x1.p10,
    0x1.p5
  },
  { // Entry 593
    0x1.0080p12,
    0x1.p0,
    0x1.p12,
    0x1.p3
  },
  { // Entry 594
    0x1.02p12,
    0x1.p0,
    0x1.p12,
    0x1.p5
  },
  { // Entry 595
    0x1.000010p10,
    0x1.p-5,
    0x1.p-5,
    0x1.p10
  },
  { // Entry 596
    0x1.000004p12,
    0x1.p-5,
    0x1.p-5,
    0x1.p12
  },
  { // Entry 597
    0x1.0002p10,
    0x1.p-5,
    0x1.p0,
    0x1.p10
  },
  { // Entry 598
    0x1.000080p12,
    0x1.p-5,
    0x1.p0,
    0x1.p12
  },
  { // Entry 599
    0x1.0002p10,
    0x1.p0,
    0x1.p-5,
    0x1.p10
  },
  { // Entry 600
    0x1.000080p12,
    0x1.p0,
    0x1.p-5,
    0x1.p12
  },
  { // Entry 601
    0x1.0040p10,
    0x1.p0,
    0x1.p0,
    0x1.p10
  },
  { // Entry 602
    0x1.0010p12,
    0x1.p0,
    0x1.p0,
    0x1.p12
  },
  { // Entry 603
    0x1.0010p10,
    0x1.p-5,
    0x1.p3,
    0x1.p10
  },
  { // Entry 604
    0x1.0004p12,
    0x1.p-5,
    0x1.p3,
    0x1.p12
  },
  { // Entry 605
    0x1.0040p10,
    0x1.p-5,
    0x1.p5,
    0x1.p10
  },
  { // Entry 606
    0x1.0010p12,
    0x1.p-5,
    0x1.p5,
    0x1.p12
  },
  { // Entry 607
    0x1.02p10,
    0x1.p0,
    0x1.p3,
    0x1.p10
  },
  { // Entry 608
    0x1.0080p12,
    0x1.p0,
    0x1.p3,
    0x1.p12
  },
  { // Entry 609
    0x1.08p10,
    0x1.p0,
    0x1.p5,
    0x1.p10
  },
  { // Entry 610
    0x1.02p12,
    0x1.p0,
    0x1.p5,
    0x1.p12
  },
  { // Entry 611
    0x1.08p10,
    0x1.p-5,
    0x1.p10,
    0x1.p10
  },
  { // Entry 612
    0x1.02p12,
    0x1.p-5,
    0x1.p10,
    0x1.p12
  },
  { // Entry 613
    0x1.20p10,
    0x1.p-5,
    0x1.p12,
    0x1.p10
  },
  { // Entry 614
    0x1.08p12,
    0x1.p-5,
    0x1.p12,
    0x1.p12
  },
  { // Entry 615
    0x1.p11,
    0x1.p0,
    0x1.p10,
    0x1.p10
  },
  { // Entry 616
    0x1.40p12,
    0x1.p0,
    0x1.p10,
    0x1.p12
  },
  { // Entry 617
    0x1.40p12,
    0x1.p0,
    0x1.p12,
    0x1.p10
  },
  { // Entry 618
    0x1.p13,
    0x1.p0,
    0x1.p12,
    0x1.p12
  },
  { // Entry 619
    0x1.0020p6,
    0x1.p3,
    0x1.p3,
    0x1.p-5
  },
  { // Entry 620
    0x1.04p6,
    0x1.p3,
    0x1.p3,
    0x1.p0
  },
  { // Entry 621
    0x1.0008p8,
    0x1.p3,
    0x1.p5,
    0x1.p-5
  },
  { // Entry 622
    0x1.01p8,
    0x1.p3,
    0x1.p5,
    0x1.p0
  },
  { // Entry 623
    0x1.0008p8,
    0x1.p5,
    0x1.p3,
    0x1.p-5
  },
  { // Entry 624
    0x1.01p8,
    0x1.p5,
    0x1.p3,
    0x1.p0
  },
  { // Entry 625
    0x1.0002p10,
    0x1.p5,
    0x1.p5,
    0x1.p-5
  },
  { // Entry 626
    0x1.0040p10,
    0x1.p5,
    0x1.p5,
    0x1.p0
  },
  { // Entry 627
    0x1.20p6,
    0x1.p3,
    0x1.p3,
    0x1.p3
  },
  { // Entry 628
    0x1.80p6,
    0x1.p3,
    0x1.p3,
    0x1.p5
  },
  { // Entry 629
    0x1.08p8,
    0x1.p3,
    0x1.p5,
    0x1.p3
  },
  { // Entry 630
    0x1.20p8,
    0x1.p3,
    0x1.p5,
    0x1.p5
  },
  { // Entry 631
    0x1.08p8,
    0x1.p5,
    0x1.p3,
    0x1.p3
  },
  { // Entry 632
    0x1.20p8,
    0x1.p5,
    0x1.p3,
    0x1.p5
  },
  { // Entry 633
    0x1.02p10,
    0x1.p5,
    0x1.p5,
    0x1.p3
  },
  { // Entry 634
    0x1.08p10,
    0x1.p5,
    0x1.p5,
    0x1.p5
  },
  { // Entry 635
    0x1.10p10,
    0x1.p3,
    0x1.p3,
    0x1.p10
  },
  { // Entry 636
    0x1.04p12,
    0x1.p3,
    0x1.p3,
    0x1.p12
  },
  { // Entry 637
    0x1.40p10,
    0x1.p3,
    0x1.p5,
    0x1.p10
  },
  { // Entry 638
    0x1.10p12,
    0x1.p3,
    0x1.p5,
    0x1.p12
  },
  { // Entry 639
    0x1.40p10,
    0x1.p5,
    0x1.p3,
    0x1.p10
  },
  { // Entry 640
    0x1.10p12,
    0x1.p5,
    0x1.p3,
    0x1.p12
  },
  { // Entry 641
    0x1.p11,
    0x1.p5,
    0x1.p5,
    0x1.p10
  },
  { // Entry 642
    0x1.40p12,
    0x1.p5,
    0x1.p5,
    0x1.p12
  },
  { // Entry 643
    0x1.000040p13,
    0x1.p3,
    0x1.p10,
    0x1.p-5
  },
  { // Entry 644
    0x1.0008p13,
    0x1.p3,
    0x1.p10,
    0x1.p0
  },
  { // Entry 645
    0x1.000010p15,
    0x1.p3,
    0x1.p12,
    0x1.p-5
  },
  { // Entry 646
    0x1.0002p15,
    0x1.p3,
    0x1.p12,
    0x1.p0
  },
  { // Entry 647
    0x1.000010p15,
    0x1.p5,
    0x1.p10,
    0x1.p-5
  },
  { // Entry 648
    0x1.0002p15,
    0x1.p5,
    0x1.p10,
    0x1.p0
  },
  { // Entry 649
    0x1.000004p17,
    0x1.p5,
    0x1.p12,
    0x1.p-5
  },
  { // Entry 650
    0x1.000080p17,
    0x1.p5,
    0x1.p12,
    0x1.p0
  },
  { // Entry 651
    0x1.0040p13,
    0x1.p3,
    0x1.p10,
    0x1.p3
  },
  { // Entry 652
    0x1.01p13,
    0x1.p3,
    0x1.p10,
    0x1.p5
  },
  { // Entry 653
    0x1.0010p15,
    0x1.p3,
    0x1.p12,
    0x1.p3
  },
  { // Entry 654
    0x1.0040p15,
    0x1.p3,
    0x1.p12,
    0x1.p5
  },
  { // Entry 655
    0x1.0010p15,
    0x1.p5,
    0x1.p10,
    0x1.p3
  },
  { // Entry 656
    0x1.0040p15,
    0x1.p5,
    0x1.p10,
    0x1.p5
  },
  { // Entry 657
    0x1.0004p17,
    0x1.p5,
    0x1.p12,
    0x1.p3
  },
  { // Entry 658
    0x1.0010p17,
    0x1.p5,
    0x1.p12,
    0x1.p5
  },
  { // Entry 659
    0x1.20p13,
    0x1.p3,
    0x1.p10,
    0x1.p10
  },
  { // Entry 660
    0x1.80p13,
    0x1.p3,
    0x1.p10,
    0x1.p12
  },
  { // Entry 661
    0x1.08p15,
    0x1.p3,
    0x1.p12,
    0x1.p10
  },
  { // Entry 662
    0x1.20p15,
    0x1.p3,
    0x1.p12,
    0x1.p12
  },
  { // Entry 663
    0x1.08p15,
    0x1.p5,
    0x1.p10,
    0x1.p10
  },
  { // Entry 664
    0x1.20p15,
    0x1.p5,
    0x1.p10,
    0x1.p12
  },
  { // Entry 665
    0x1.02p17,
    0x1.p5,
    0x1.p12,
    0x1.p10
  },
  { // Entry 666
    0x1.08p17,
    0x1.p5,
    0x1.p12,
    0x1.p12
  },
  { // Entry 667
    -0x1.ffffe0p-21,
    -0x1.p-20,
    -0x1.p-20,
    -0x1.p-20
  },
  { // Entry 668
    0x1.000010p-20,
    -0x1.p-20,
    -0x1.p-20,
    0x1.p-20
  },
  { // Entry 669
    -0x1.000010p-20,
    -0x1.p-20,
    0x1.p-20,
    -0x1.p-20
  },
  { // Entry 670
    0x1.ffffe0p-21,
    -0x1.p-20,
    0x1.p-20,
    0x1.p-20
  },
  { // Entry 671
    -0x1.000010p-20,
    0x1.p-20,
    -0x1.p-20,
    -0x1.p-20
  },
  { // Entry 672
    0x1.ffffe0p-21,
    0x1.p-20,
    -0x1.p-20,
    0x1.p-20
  },
  { // Entry 673
    -0x1.ffffe0p-21,
    0x1.p-20,
    0x1.p-20,
    -0x1.p-20
  },
  { // Entry 674
    0x1.000010p-20,
    0x1.p-20,
    0x1.p-20,
    0x1.p-20
  },
  { // Entry 675
    0x1.fffffffffffffffffffep-21,
    -0x1.p-10,
    -0x1.p-10,
    -0x1.p-100
  },
  { // Entry 676
    0x1.00000000000000000001p-20,
    -0x1.p-10,
    -0x1.p-10,
    0x1.p-100
  },
  { // Entry 677
    -0x1.00000000000000000001p-20,
    -0x1.p-10,
    0x1.p-10,
    -0x1.p-100
  },
  { // Entry 678
    -0x1.fffffffffffffffffffep-21,
    -0x1.p-10,
    0x1.p-10,
    0x1.p-100
  },
  { // Entry 679
    -0x1.00000000000000000001p-20,
    0x1.p-10,
    -0x1.p-10,
    -0x1.p-100
  },
  { // Entry 680
    -0x1.fffffffffffffffffffep-21,
    0x1.p-10,
    -0x1.p-10,
    0x1.p-100
  },
  { // Entry 681
    0x1.fffffffffffffffffffep-21,
    0x1.p-10,
    0x1.p-10,
    -0x1.p-100
  },
  { // Entry 682
    0x1.00000000000000000001p-20,
    0x1.p-10,
    0x1.p-10,
    0x1.p-100
  },
  { // Entry 683
    0x1.f0p-11,
    -0x1.p-5,
    -0x1.p-5,
    -0x1.p-15
  },
  { // Entry 684
    0x1.08p-10,
    -0x1.p-5,
    -0x1.p-5,
    0x1.p-15
  },
  { // Entry 685
    -0x1.08p-10,
    -0x1.p-5,
    0x1.p-5,
    -0x1.p-15
  },
  { // Entry 686
    -0x1.f0p-11,
    -0x1.p-5,
    0x1.p-5,
    0x1.p-15
  },
  { // Entry 687
    -0x1.08p-10,
    0x1.p-5,
    -0x1.p-5,
    -0x1.p-15
  },
  { // Entry 688
    -0x1.f0p-11,
    0x1.p-5,
    -0x1.p-5,
    0x1.p-15
  },
  { // Entry 689
    0x1.f0p-11,
    0x1.p-5,
    0x1.p-5,
    -0x1.p-15
  },
  { // Entry 690
    0x1.08p-10,
    0x1.p-5,
    0x1.p-5,
    0x1.p-15
  },
  { // Entry 691
    0x1.68p6,
    -0x1.40p3,
    -0x1.40p3,
    -0x1.40p3
  },
  { // Entry 692
    0x1.b8p6,
    -0x1.40p3,
    -0x1.40p3,
    0x1.40p3
  },
  { // Entry 693
    -0x1.b8p6,
    -0x1.40p3,
    0x1.40p3,
    -0x1.40p3
  },
  { // Entry 694
    -0x1.68p6,
    -0x1.40p3,
    0x1.40p3,
    0x1.40p3
  },
  { // Entry 695
    -0x1.b8p6,
    0x1.40p3,
    -0x1.40p3,
    -0x1.40p3
  },
  { // Entry 696
    -0x1.68p6,
    0x1.40p3,
    -0x1.40p3,
    0x1.40p3
  },
  { // Entry 697
    0x1.68p6,
    0x1.40p3,
    0x1.40p3,
    -0x1.40p3
  },
  { // Entry 698
    0x1.b8p6,
    0x1.40p3,
    0x1.40p3,
    0x1.40p3
  },
  { // Entry 699
    0.0,
    -0x1.p0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 700
    0x1.p1,
    -0x1.p0,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 701
    -0x1.p1,
    -0x1.p0,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 702
    0.0,
    -0x1.p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 703
    -0x1.p1,
    0x1.p0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 704
    0.0,
    0x1.p0,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 705
    0.0,
    0x1.p0,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 706
    0x1.p1,
    0x1.p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 707
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 708
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 709
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 710
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 711
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 712
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 713
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 714
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 715
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 716
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    0.0f
  },
  { // Entry 717
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 718
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 719
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 720
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 721
    -HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF,
    0x1.p-126
```
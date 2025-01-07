Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of a larger file related to testing the `fmaf` function in Android's bionic library. The code defines a series of test cases for the fused multiply-add operation on single-precision floating-point numbers.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The data consists of a large array of structs. Each struct contains four `float` values. The file name `fmaf_intel_data.handroid` strongly suggests this data is used to test the `fmaf` function, likely against specific hardware implementations (Intel).

2. **Relate to Android:** Bionic is Android's standard C library. The `fmaf` function is a standard C math function. This data is part of the testing framework for ensuring the correct implementation of `fmaf` within Android.

3. **Infer Usage:**  The structure of the data suggests it's a set of input and expected output values for `fmaf`. The first three floats in each entry are likely inputs (a, b, c for a*b + c), and the fourth float is the expected result.

4. **Consider the "test" nature:** This isn't the *implementation* of `fmaf`, but *test data* for it. Therefore, the "functionality" is about providing comprehensive test coverage.

5. **Address the "Part 5 of 7" prompt:** This indicates the data is part of a larger testing suite, likely organized into different categories or sets of test cases.

6. **Formulate the Summary:** Combine the above points into a concise summary. Highlight that it's test data, for the `fmaf` function, within Android's bionic library, and part of a larger testing effort.
这是目录为 `bionic/tests/math_data/fmaf_intel_data.handroid` 的源代码文件的一部分，它位于 Android 的 Bionic 库中。这个文件主要包含用于测试 `fmaf` 函数（单精度浮点数的融合乘加运算）的数据。

**归纳一下它的功能：**

这个代码片段定义了一个包含大量测试用例的数据结构数组，用于测试 `fmaf` 函数在特定场景下的正确性。每个测试用例由四个单精度浮点数组成，代表了 `fmaf(a, b, c)` 的输入参数 `a`、`b`、`c` 以及期望的输出结果。这些数据很可能来源于 Intel 硬件的特定行为或者为了覆盖各种边界情况和特殊值而精心设计的。

**更详细的解释：**

* **测试 `fmaf` 函数：**  `fmaf` 函数是 fused multiply-add（融合乘加）的单精度浮点版本。它的作用是计算 `(x * y) + z`，但会将乘法和加法作为一个原子操作执行，这意味着只有一次舍入误差，从而提高精度。

* **与 Android 的功能关系：**  作为 Bionic 库的一部分，这个文件直接关系到 Android 系统的基础数学运算能力。`fmaf` 函数在很多高性能计算、图形处理以及其他需要精确浮点运算的场景中被使用。确保 `fmaf` 的正确实现对于 Android 系统的稳定性和性能至关重要。

    * **举例说明：** 假设一个 Android 应用程序使用 OpenGL ES 进行 3D 渲染。在计算顶点变换或者光照模型时，可能会涉及到大量的浮点数乘法和加法运算。如果底层的 `fmaf` 实现有错误，可能会导致渲染结果不正确，例如模型变形或光影错误。

* **libc 函数的功能实现：**  `fmaf` 函数的实现通常在底层的硬件或软件层完成，Bionic 库提供了这个函数的接口。具体的实现方式会依赖于 CPU 的架构和特性。在支持 FMA 指令的 CPU 上，`fmaf` 会直接映射到对应的硬件指令。在不支持的 CPU 上，可能会使用软件模拟的方式实现，但性能会相对较低。

* **dynamic linker 的功能：**  在这个特定的数据文件中，并没有直接涉及到 dynamic linker 的功能。Dynamic linker 主要负责在程序启动时加载和链接共享库 (`.so` 文件)。`fmaf` 函数通常包含在 `libm.so` (数学库) 中，dynamic linker 负责将应用程序链接到这个库。

    * **so 布局样本：**
      ```
      libm.so:
          地址空间: 0xb7000000 - 0xb7100000
          ...其他段信息...
          .text 段:  包含 fmaf 函数的机器码
          ...其他段信息...
      ```
    * **链接的处理过程：**
        1. 当应用程序调用 `fmaf` 时，编译器会生成一个对外部符号 `fmaf` 的引用。
        2. 在链接阶段，静态链接器会记录下这个未解析的符号。
        3. 当应用程序在 Android 上启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被操作系统调用。
        4. Dynamic linker 会解析应用程序的依赖关系，发现需要 `libm.so`。
        5. Dynamic linker 会在文件系统中查找 `libm.so`。
        6. Dynamic linker 将 `libm.so` 加载到内存中的某个地址空间。
        7. Dynamic linker 遍历应用程序和 `libm.so` 的重定位表，将应用程序中对 `fmaf` 的引用地址更新为 `libm.so` 中 `fmaf` 函数的实际地址。

* **逻辑推理、假设输入与输出：**  这个代码片段本身就是一系列的 "假设输入与输出"。例如，对于 Entry 1383：
    * **假设输入:** `a = 0x1.fffffdffffffffffffffffffffffffffp127`, `b = 0x1.fffffcp-127`, `c = -0x1.p-149`
    * **期望输出:** `0x1.fffffep127`
    这表示当 `fmaf` 函数使用这些输入时，测试框架期望得到 `0x1.fffffep127` 这个结果。测试框架会调用实际的 `fmaf` 函数，并将结果与期望输出进行比较，以判断 `fmaf` 的实现是否正确。

* **用户或编程常见的使用错误：**  直接使用这些测试数据进行编程的情况很少见。常见的 `fmaf` 使用错误可能包括：
    * **不了解 FMA 的精度优势：** 在不需要高精度的情况下，仍然使用 `fmaf` 可能不会带来明显的性能提升，反而可能因为函数调用开销而略微降低性能。
    * **误用或混淆 FMA 与普通乘加：**  在某些情况下，程序员可能错误地使用了 FMA 函数，或者期望普通乘加运算的结果，但实际调用了 FMA，导致结果略有不同。这通常发生在对浮点运算的精度特性理解不够深入时。
    * **处理特殊浮点值不当：**  像 `HUGE_VALF`、正负零、NaN 等特殊浮点值在 FMA 运算中可能会有特定的行为。如果代码没有正确处理这些情况，可能会导致意想不到的结果。

* **Android framework or ndk 如何到达这里：**
    1. **NDK 开发:**  开发者使用 NDK (Native Development Kit) 编写 C/C++ 代码。
    2. **调用 Math 函数:** NDK 代码中可能会直接调用 `<math.h>` 头文件中声明的 `fmaf` 函数。
    3. **Bionic 库链接:**  当 NDK 代码被编译链接成共享库 (`.so`) 时，链接器会将代码链接到 Android 系统的 Bionic 库，包括 `libm.so`。
    4. **系统调用:** 当应用程序运行到调用 `fmaf` 的代码时，实际上会调用 `libm.so` 中实现的 `fmaf` 函数。
    5. **测试执行:** 在 Android 系统开发或 CTS (Compatibility Test Suite) 测试中，会运行针对 Bionic 库的测试用例，这些测试用例会读取类似 `fmaf_intel_data.handroid` 这样的数据文件，并将数据作为输入传递给 `fmaf` 函数，验证其输出是否与预期一致。

* **Frida Hook 示例调试步骤：**

    ```python
    import frida
    import sys

    package_name = "你的应用包名" # 替换为你的应用包名

    def on_message(message, data):
        if message['type'] == 'send':
            print("[*] {}".format(message['payload']))
        else:
            print(message)

    session = frida.attach(package_name)

    script_code = """
    Interceptor.attach(Module.findExportByName("libm.so", "fmaf"), {
        onEnter: function(args) {
            send({
                a: parseFloat(args[0]),
                b: parseFloat(args[1]),
                c: parseFloat(args[2])
            }, "Calling fmaf with arguments");
        },
        onLeave: function(retval) {
            send({
                result: parseFloat(retval)
            }, "fmaf returned");
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    ```

    **调试步骤：**
    1. 将 `你的应用包名` 替换为你要调试的 Android 应用程序的包名。
    2. 确保你的设备已连接并运行了 Frida 服务。
    3. 运行这个 Python 脚本。
    4. 启动目标 Android 应用程序并执行会调用 `fmaf` 函数的操作。
    5. Frida 脚本会在 `fmaf` 函数被调用时拦截，并打印出输入参数和返回值。

**总结：**

这个代码片段是 Android Bionic 库中用于测试 `fmaf` 函数正确性的测试数据。它定义了大量的输入和期望输出，用于验证 `fmaf` 在各种场景下的行为是否符合预期，从而确保 Android 系统底层数学运算的可靠性。

Prompt: 
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
这是第5部分，共7部分，请归纳一下它的功能

"""
 -HUGE_VALF
  },
  { // Entry 1383
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffcp-127,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1384
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1385
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1386
    -0x1.p-126,
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1387
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1388
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1389
    0.0f,
    0x1.fffffcp-127,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1390
    -0x1.00000000000000000000000000000003p-149,
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1391
    -0.0f,
    0x1.fffffcp-127,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1392
    -0.0f,
    0x1.fffffcp-127,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1393
    HUGE_VALF,
    0x1.fffffcp-127,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1394
    -HUGE_VALF,
    0x1.fffffcp-127,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1395
    0x1.fffffep127,
    0x1.fffffcp-127,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1396
    -0x1.fffffep127,
    0x1.fffffcp-127,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1397
    0x1.p-126,
    0x1.fffffcp-127,
    0.0f,
    0x1.p-126
  },
  { // Entry 1398
    -0x1.p-126,
    0x1.fffffcp-127,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1399
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1400
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1401
    0x1.p-149,
    0x1.fffffcp-127,
    0.0f,
    0x1.p-149
  },
  { // Entry 1402
    -0x1.p-149,
    0x1.fffffcp-127,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1403
    0.0,
    0x1.fffffcp-127,
    0.0f,
    0.0f
  },
  { // Entry 1404
    0.0,
    0x1.fffffcp-127,
    0.0f,
    -0.0f
  },
  { // Entry 1405
    HUGE_VALF,
    0x1.fffffcp-127,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1406
    -HUGE_VALF,
    0x1.fffffcp-127,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1407
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1408
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1409
    0x1.p-126,
    0x1.fffffcp-127,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1410
    -0x1.p-126,
    0x1.fffffcp-127,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1411
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1412
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1413
    0x1.p-149,
    0x1.fffffcp-127,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1414
    -0x1.p-149,
    0x1.fffffcp-127,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1415
    0.0,
    0x1.fffffcp-127,
    -0.0f,
    0.0f
  },
  { // Entry 1416
    -0.0,
    0x1.fffffcp-127,
    -0.0f,
    -0.0f
  },
  { // Entry 1417
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 1418
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1419
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1420
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1421
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1422
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1423
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1424
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1425
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1426
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    0.0f
  },
  { // Entry 1427
    -HUGE_VALF,
    -0x1.fffffcp-127,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 1428
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 1429
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1430
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1431
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1432
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1433
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1434
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1435
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1436
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1437
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 1438
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 1439
    HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1440
    -HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1441
    0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1442
    -0x1.fffffe00000000000000000000000007p127,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1443
    -0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1444
    -0x1.fffffa00000400000000000000000002p1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1445
    -0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1446
    -0x1.fffffa00000400000000000000000001p1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1447
    -0x1.fffffa000003ffffffffffffffffffffp1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1448
    -0x1.fffffa000004p1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1449
    -0x1.fffffa000004p1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1450
    -0x1.fffffa000004p1,
    -0x1.fffffcp-127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1451
    HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1452
    -HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1453
    0x1.fffffe00000000000000000000000007p127,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1454
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1455
    0x1.fffffa00000400000000000000000002p1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1456
    0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1457
    0x1.fffffa00000400000000000000000001p1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1458
    0x1.fffffa000003fffffffffffffffffffep1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1459
    0x1.fffffa000004p1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1460
    0x1.fffffa000003ffffffffffffffffffffp1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1461
    0x1.fffffa000004p1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1462
    0x1.fffffa000004p1,
    -0x1.fffffcp-127,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1463
    HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1464
    -HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1465
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1466
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1467
    0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1468
    -0x1.00000000000000000000000000000003p-126,
    -0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1469
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1470
    -0x1.fffffc00000000000000000000000007p-127,
    -0x1.fffffcp-127,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1471
    0.0f,
    -0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1472
    -0x1.00000000000000000000000001fffffcp-149,
    -0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1473
    -0.0f,
    -0x1.fffffcp-127,
    0x1.p-126,
    0.0f
  },
  { // Entry 1474
    -0.0f,
    -0x1.fffffcp-127,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1475
    HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1476
    -HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1477
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1478
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1479
    0x1.00000000000000000000000000000003p-126,
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1480
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1481
    0x1.fffffc00000000000000000000000007p-127,
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1482
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1483
    0x1.00000000000000000000000001fffffcp-149,
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1484
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1485
    0.0f,
    -0x1.fffffcp-127,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1486
    0.0f,
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1487
    HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1488
    -HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1489
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1490
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1491
    0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1492
    -0x1.00000000000000000000000000000003p-126,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1493
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1494
    -0x1.fffffc00000000000000000000000007p-127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1495
    0.0f,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1496
    -0x1.00000000000000000000000001fffff8p-149,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1497
    -0.0f,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1498
    -0.0f,
    -0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1499
    HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1500
    -HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1501
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1502
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1503
    0x1.00000000000000000000000000000003p-126,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1504
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1505
    0x1.fffffc00000000000000000000000007p-127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1506
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1507
    0x1.00000000000000000000000001fffff8p-149,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1508
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1509
    0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1510
    0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1511
    HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1512
    -HUGE_VALF,
    -0x1.fffffcp-127,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1513
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1514
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1515
    0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1516
    -0x1.p-126,
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1517
    0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1518
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1519
    0.0f,
    -0x1.fffffcp-127,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1520
    -0x1.00000000000000000000000000000003p-149,
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1521
    -0.0f,
    -0x1.fffffcp-127,
    0x1.p-149,
    0.0f
  },
  { // Entry 1522
    -0.0f,
    -0x1.fffffcp-127,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1523
    HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1524
    -HUGE_VALF,
    -0x1.fffffcp-127,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1525
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1526
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1527
    0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1528
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1529
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1530
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1531
    0x1.00000000000000000000000000000003p-149,
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1532
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1533
    0.0f,
    -0x1.fffffcp-127,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1534
    0.0f,
    -0x1.fffffcp-127,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1535
    HUGE_VALF,
    -0x1.fffffcp-127,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1536
    -HUGE_VALF,
    -0x1.fffffcp-127,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1537
    0x1.fffffep127,
    -0x1.fffffcp-127,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1538
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1539
    0x1.p-126,
    -0x1.fffffcp-127,
    0.0f,
    0x1.p-126
  },
  { // Entry 1540
    -0x1.p-126,
    -0x1.fffffcp-127,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1541
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1542
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1543
    0x1.p-149,
    -0x1.fffffcp-127,
    0.0f,
    0x1.p-149
  },
  { // Entry 1544
    -0x1.p-149,
    -0x1.fffffcp-127,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1545
    0.0,
    -0x1.fffffcp-127,
    0.0f,
    0.0f
  },
  { // Entry 1546
    -0.0,
    -0x1.fffffcp-127,
    0.0f,
    -0.0f
  },
  { // Entry 1547
    HUGE_VALF,
    -0x1.fffffcp-127,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1548
    -HUGE_VALF,
    -0x1.fffffcp-127,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1549
    0x1.fffffep127,
    -0x1.fffffcp-127,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1550
    -0x1.fffffep127,
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1551
    0x1.p-126,
    -0x1.fffffcp-127,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1552
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1553
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1554
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1555
    0x1.p-149,
    -0x1.fffffcp-127,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1556
    -0x1.p-149,
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1557
    0.0,
    -0x1.fffffcp-127,
    -0.0f,
    0.0f
  },
  { // Entry 1558
    0.0,
    -0x1.fffffcp-127,
    -0.0f,
    -0.0f
  },
  { // Entry 1559
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 1560
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1561
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1562
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1563
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1564
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1565
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1566
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1567
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1568
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    0.0f
  },
  { // Entry 1569
    HUGE_VALF,
    0x1.p-149,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 1570
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 1571
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1572
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1573
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1574
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1575
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1576
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1577
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1578
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1579
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 1580
    -HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 1581
    HUGE_VALF,
    0x1.p-149,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1582
    -HUGE_VALF,
    0x1.p-149,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1583
    0x1.fffffep127,
    0x1.p-149,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1584
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1585
    0x1.fffffe00000000000000000001p-22,
    0x1.p-149,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1586
    0x1.fffffdffffffffffffffffffffp-22,
    0x1.p-149,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1587
    0x1.fffffe00000000000000000000fffffep-22,
    0x1.p-149,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1588
    0x1.fffffdffffffffffffffffffff000002p-22,
    0x1.p-149,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1589
    0x1.fffffe00000000000000000000000002p-22,
    0x1.p-149,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1590
    0x1.fffffdfffffffffffffffffffffffffep-22,
    0x1.p-149,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1591
    0x1.fffffep-22,
    0x1.p-149,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1592
    0x1.fffffep-22,
    0x1.p-149,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1593
    HUGE_VALF,
    0x1.p-149,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1594
    -HUGE_VALF,
    0x1.p-149,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1595
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1596
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1597
    -0x1.fffffdffffffffffffffffffffp-22,
    0x1.p-149,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1598
    -0x1.fffffe00000000000000000001p-22,
    0x1.p-149,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1599
    -0x1.fffffdffffffffffffffffffff000002p-22,
    0x1.p-149,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1600
    -0x1.fffffe00000000000000000000fffffep-22,
    0x1.p-149,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1601
    -0x1.fffffdfffffffffffffffffffffffffep-22,
    0x1.p-149,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1602
    -0x1.fffffe00000000000000000000000002p-22,
    0x1.p-149,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1603
    -0x1.fffffep-22,
    0x1.p-149,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1604
    -0x1.fffffep-22,
    0x1.p-149,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1605
    HUGE_VALF,
    0x1.p-149,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1606
    -HUGE_VALF,
    0x1.p-149,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1607
    0x1.fffffep127,
    0x1.p-149,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1608
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1609
    0x1.p-126,
    0x1.p-149,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1610
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-149,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1611
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1612
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-149,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1613
    0x1.00000000000000000000000000000004p-149,
    0x1.p-149,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1614
    -0.0f,
    0x1.p-149,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1615
    0.0f,
    0x1.p-149,
    0x1.p-126,
    0.0f
  },
  { // Entry 1616
    0.0f,
    0x1.p-149,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1617
    HUGE_VALF,
    0x1.p-149,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1618
    -HUGE_VALF,
    0x1.p-149,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1619
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1620
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1621
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-149,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1622
    -0x1.p-126,
    0x1.p-149,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1623
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-149,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1624
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1625
    0.0f,
    0x1.p-149,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1626
    -0x1.00000000000000000000000000000004p-149,
    0x1.p-149,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1627
    -0.0f,
    0x1.p-149,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1628
    -0.0f,
    0x1.p-149,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1629
    HUGE_VALF,
    0x1.p-149,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1630
    -HUGE_VALF,
    0x1.p-149,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1631
    0x1.fffffep127,
    0x1.p-149,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1632
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1633
    0x1.p-126,
    0x1.p-149,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1634
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-149,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1635
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1636
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-149,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1637
    0x1.00000000000000000000000000000003p-149,
    0x1.p-149,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1638
    -0.0f,
    0x1.p-149,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1639
    0.0f,
    0x1.p-149,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1640
    0.0f,
    0x1.p-149,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1641
    HUGE_VALF,
    0x1.p-149,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1642
    -HUGE_VALF,
    0x1.p-149,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1643
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1644
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1645
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-149,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1646
    -0x1.p-126,
    0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1647
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-149,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1648
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1649
    0.0f,
    0x1.p-149,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1650
    -0x1.00000000000000000000000000000003p-149,
    0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1651
    -0.0f,
    0x1.p-149,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1652
    -0.0f,
    0x1.p-149,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1653
    HUGE_VALF,
    0x1.p-149,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1654
    -HUGE_VALF,
    0x1.p-149,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1655
    0x1.fffffep127,
    0x1.p-149,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1656
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1657
    0x1.p-126,
    0x1.p-149,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1658
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-149,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1659
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1660
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-149,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1661
    0x1.p-149,
    0x1.p-149,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1662
    -0.0f,
    0x1.p-149,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1663
    0.0f,
    0x1.p-149,
    0x1.p-149,
    0.0f
  },
  { // Entry 1664
    0.0f,
    0x1.p-149,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1665
    HUGE_VALF,
    0x1.p-149,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1666
    -HUGE_VALF,
    0x1.p-149,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1667
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-149,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1668
    -0x1.fffffep127,
    0x1.p-149,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1669
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-149,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1670
    -0x1.p-126,
    0x1.p-149,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1671
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-149,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1672
    -0x1.fffffcp-127,
    0x1.p-149,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1673
    0.0f,
    0x1.p-149,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1674
    -0x1.p-149,
    0x1.p-149,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1675
    -0.0f,
    0x1.p-149,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1676
    -0.0f,
    0x1.p-149,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1677
    HUGE_VALF,
    0x1.p-149,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1678
    -HUGE_VALF,
    0x1.p-149,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1679
    0x1.fffffep127,
    0x1.p-149,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1680
    -0x1.fffffep127,
    0x1.p-149,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1681
    0x1.p-126,
    0x1.p-149,
    0.0f,
    0x1.p-126
  },
  { // Entry 1682
    -0x1.p-126,
    0x1.p-149,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1683
    0x1.fffffcp-127,
    0x1.p-149,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1684
    -0x1.fffffcp-127,
    0x1.p-149,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1685
    0x1.p-149,
    0x1.p-149,
    0.0f,
    0x1.p-149
  },
  { // Entry 1686
    -0x1.p-149,
    0x1.p-149,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1687
    0.0,
    0x1.p-149,
    0.0f,
    0.0f
  },
  { // Entry 1688
    0.0,
    0x1.p-149,
    0.0f,
    -0.0f
  },
  { // Entry 1689
    HUGE_VALF,
    0x1.p-149,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1690
    -HUGE_VALF,
    0x1.p-149,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1691
    0x1.fffffep127,
    0x1.p-149,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1692
    -0x1.fffffep127,
    0x1.p-149,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1693
    0x1.p-126,
    0x1.p-149,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1694
    -0x1.p-126,
    0x1.p-149,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1695
    0x1.fffffcp-127,
    0x1.p-149,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1696
    -0x1.fffffcp-127,
    0x1.p-149,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1697
    0x1.p-149,
    0x1.p-149,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1698
    -0x1.p-149,
    0x1.p-149,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1699
    0.0,
    0x1.p-149,
    -0.0f,
    0.0f
  },
  { // Entry 1700
    -0.0,
    0x1.p-149,
    -0.0f,
    -0.0f
  },
  { // Entry 1701
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 1702
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1703
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1704
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1705
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1706
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1707
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1708
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1709
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1710
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    0.0f
  },
  { // Entry 1711
    -HUGE_VALF,
    -0x1.p-149,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 1712
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 1713
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1714
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1715
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1716
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1717
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1718
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1719
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1720
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1721
    HUGE_VALF,
    -0x1.p-14
"""


```
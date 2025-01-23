Response:
My goal is to summarize the functionality of the provided code snippet, keeping in mind it's part 2 of a 3-part series analyzing a file named `scalb_intel_data.handroid`.

Here's my thinking process to arrive at the summary:

1. **Identify the Data Structure:** The code clearly defines an array of structures. Each structure contains three floating-point numbers. The comments like "// Entry N" indicate the index of each structure within the array.

2. **Recognize the Context:** The prompt states the file is located in `bionic/tests/math_data/` and `bionic` is Android's C library, math library, and dynamic linker. The filename `scalb_intel_data.handroid` strongly suggests this data is related to the `scalbn` or `scalbln` math functions, likely for testing purposes and potentially specific to Intel architectures. The ".handroid" suffix is a common convention in Android's bionic for hand-crafted test data.

3. **Infer the Functionality from the Data:**  The three floating-point numbers in each entry likely represent:
    * **Input Value:** The first number appears to be the input to a function.
    * **Scale Factor (Implicit):** The second number seems to be another input, likely used to determine the scaling factor. The exponents in these numbers show a pattern.
    * **Expected Output:** The third number is very likely the expected result of the `scalbn` or `scalbln` function applied to the first two numbers.

4. **Connect to `scalbn`/`scalbln`:** The `scalbn(x, n)` function multiplies a floating-point number `x` by 2 raised to the power of `n`. The data appears to be testing various input values (`x`) and integer exponents (`n`, derived from the second floating-point number). The third number confirms the expected outcome of this operation.

5. **Consider Edge Cases:** The data includes values like 0.0, very small numbers (denormals or subnormals), very large numbers, and specific bit patterns. This suggests the test data is designed to cover a wide range of inputs, including potential edge cases and boundary conditions that could expose implementation issues.

6. **Dynamic Linker Aspect (Limited):** While the prompt mentions the dynamic linker, this specific data file doesn't directly involve dynamic linking. It's pure data. However, it *supports* the math library, which is loaded by the dynamic linker. So, while not directly linked, it's a component within the broader bionic ecosystem managed by the dynamic linker.

7. **Formulate the Summary (Iterative Refinement):**  My initial thoughts would be something like "This file contains test data for the scalb function." I then refine it to be more precise:

    * Add the "likely" qualifier for `scalbn/scalbln`.
    * Clarify the purpose of the data (input, scaling factor representation, expected output).
    * Mention the testing focus (correctness and accuracy).
    * Highlight the inclusion of various input ranges and edge cases.
    * Acknowledge the indirect connection to the dynamic linker via the math library.
    * Emphasize its role in verifying the `scalbn/scalbln` implementation in bionic.
    * Note the ".handroid" convention for hand-crafted test data.

8. **Address the "Part 2" Context:** The prompt specifically asks for a summary in the context of being "part 2". This doesn't fundamentally change the analysis of the data itself, but it reinforces that this is an intermediate step in a larger investigation. The summary should stand alone but also fit within the broader analysis of the `scalb_intel_data.handroid` file.

By following these steps, I arrive at the summary provided in the initial good answer, which accurately captures the function of this data file within the bionic math library's testing framework.
好的，我们来归纳一下提供的代码片段的功能。

这段代码片段是文件 `bionic/tests/math_data/scalb_intel_data.handroid` 的一部分，具体来说是其中的数据部分。这个文件很可能用于测试 `scalbn` 或 `scalbln` 这两个 C 标准库函数在 Android Bionic 库中的实现。

**归纳其功能：**

这段代码定义了一个包含多个条目的数组，每个条目都是一个包含三个 `double` 类型浮点数的结构体。 这些数据很可能被用作 `scalbn` 或 `scalbln` 函数的测试用例，用于验证该函数在不同输入情况下的正确性和精度。

**具体来说，每个条目的三个浮点数可能代表：**

1. **输入值 (x)：** 第一个浮点数是 `scalbn` 或 `scalbln` 函数的第一个参数，即需要进行缩放的值。  从数据的格式来看，使用了十六进制浮点数表示法 (`0x1.xxxxxxxxxp+/-yy`)。
2. **缩放因子表示 (n 的某种形式)：**  第二个浮点数可能与 `scalbn` 或 `scalbln` 函数的第二个参数（整数 `n`，表示 2 的幂）有关。 然而，它本身也是一个浮点数，这可能是一种间接表示方式，或者用于测试某些特定情况。例如，它可能被用来计算或验证最终的指数变化。
3. **期望输出值 (scalbn(x, n) 的预期结果)：** 第三个浮点数是针对给定输入值和缩放因子的 `scalbn` 或 `scalbln` 函数的预期返回值。

**与 Android 功能的关系举例：**

在 Android 系统中，很多底层操作和高性能计算会涉及到浮点数运算。`scalbn` 这类函数在以下场景中可能会被用到：

* **音频和视频处理：** 调整音频信号的音量或视频帧的亮度，可能需要对浮点数表示的采样值进行快速的 2 的幂次方的缩放。
* **图形渲染：** 在 OpenGL ES 或 Vulkan 等图形 API 的底层，对顶点坐标、纹理坐标等进行变换时，可能需要用到高效的浮点数缩放操作。
* **科学计算和机器学习库：** 一些底层的数学运算或数值计算库可能会使用 `scalbn` 来进行数值的规范化或调整。
* **底层系统库：**  Bionic 作为 Android 的 C 库，其 `math` 库提供了这些基础的数学函数，供上层 Framework 和 NDK 使用。

**关于 libc 函数 `scalbn` 和 `scalbln` 的功能实现：**

`scalbn(double x, int n)` 和 `scalbln(long double x, int n)` 函数的功能是将浮点数 `x` 乘以 2 的 `n` 次方，即 `x * 2^n`。  它们的主要目的是提供一种比使用 `pow(2.0, n) * x` 更高效的方法来进行这种特定的缩放操作。

**实现原理：**

`scalbn` 和 `scalbln` 的实现通常直接操作浮点数的内部表示（符号位、指数位、尾数位）。  对于 IEEE 754 标准的浮点数，乘以 2 的幂次方可以通过直接修改其指数部分来实现，而无需进行完整的乘法运算。

1. **提取指数部分：** 从浮点数的二进制表示中提取出指数部分。
2. **调整指数：** 将提取出的指数值加上 `n`。
3. **处理溢出和下溢：**
    * 如果调整后的指数超出了浮点数类型的最大指数范围（溢出），则返回正无穷或负无穷。
    * 如果调整后的指数小于浮点数类型的最小指数范围（下溢），则返回 0.0 或一个非常小的次正规数。
4. **构建新的浮点数：** 将调整后的指数与原有的符号位和尾数位重新组合，形成新的浮点数。

**涉及 dynamic linker 的功能：**

这个数据文件本身并不直接涉及 dynamic linker 的功能。 动态链接器负责在程序运行时加载和链接共享库（.so 文件）。 `scalbn` 和 `scalbln` 函数的实现位于 Bionic 库的 `libm.so` 中。

**so 布局样本：**

```
/system/lib64/libm.so  (64位系统)
/system/lib/libm.so   (32位系统)

libm.so 的内部布局可能包含：

.text   # 包含 scalbn/scalbln 等函数的机器码
.rodata # 包含常量数据，例如数学常数
.data   # 包含可变数据
.bss    # 包含未初始化的全局变量
.dynsym # 动态符号表，列出导出的符号（例如 scalbn）
.dynstr # 动态字符串表，存储符号名称
.rel.dyn # 动态重定位表
.plt    # 程序链接表
.got    # 全局偏移表
...
```

**链接的处理过程：**

1. **编译时：** 当一个程序（例如一个使用了 `scalbn` 的 NDK 应用）被编译时，链接器会在其可执行文件中记录对 `libm.so` 中 `scalbn` 函数的依赖。
2. **加载时：** 当 Android 系统加载这个程序时，dynamic linker（在 Android 中通常是 `linker64` 或 `linker`）会检查程序的依赖项。
3. **查找共享库：** dynamic linker 会在预定义的路径（例如 `/system/lib64`, `/vendor/lib64` 等）中查找 `libm.so`。
4. **加载共享库：**  如果找到 `libm.so`，dynamic linker 会将其加载到内存中。
5. **符号解析和重定位：** dynamic linker 会解析程序中对 `scalbn` 的引用，并在 `libm.so` 中找到 `scalbn` 函数的地址。它会更新程序的全局偏移表 (GOT) 或程序链接表 (PLT)，以便程序在调用 `scalbn` 时能够跳转到正确的地址。

**假设输入与输出 (针对 `scalbn`)：**

假设 `scalbn` 的实现使用这段数据文件进行测试：

* **假设输入：** `x = 0x1.1745d1745d1770p-9`, `n` 的值可以通过某种方式从 `0x1.1745d1745d177p-1` 推导出来（例如，如果测试关注指数变化，则可能关注这两个数的指数部分差异）。 假设测试的逻辑是，如果第二个浮点数的指数部分减去某个基准值（比如 -1）得到 `k`，则认为 `n = k`。 在这个例子中，第二个浮点数的指数是 -1，假设基准值为 -1，则 `n = -1 - (-1) = 0`。 如果 `n` 的计算方式不同，结果也会不同。
* **预期输出：** `-0x1.0p3`

**用户或编程常见的使用错误：**

1. **传递错误的 `n` 值：**  如果传递的 `n` 值过大或过小，可能导致结果溢出为无穷大或下溢为零，而没有进行适当的错误处理。
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double x = 2.0;
       int n = 1024; // 对于 double 来说可能导致溢出
       double result = scalbn(x, n);
       printf("scalbn(%f, %d) = %f\n", x, n, result); // 可能输出 inf
       return 0;
   }
   ```

2. **忽视浮点数的精度问题：**  虽然 `scalbn` 主要是指数操作，但仍然是浮点数运算，需要注意精度问题。

3. **将 `scalbn` 与其他缩放方法混淆：**  `scalbn` 专门用于 2 的幂次方缩放，如果需要其他底数的缩放，应该使用 `pow` 函数。

**Android Framework 或 NDK 如何到达这里：**

1. **NDK 应用调用 `scalbn`：**  一个使用 NDK 开发的 Android 应用，其 C/C++ 代码中调用了 `scalbn` 函数。
   ```c++
   #include <cmath>

   double scale_value(double val, int power) {
       return std::scalbn(val, power);
   }
   ```

2. **编译和链接：**  使用 NDK 编译该应用时，链接器会将对 `std::scalbn` 的调用链接到 Bionic 库的 `libm.so` 中对应的符号。

3. **运行时加载：** 当应用在 Android 设备上运行时，dynamic linker 加载 `libm.so`。

4. **调用 `scalbn` 实现：** 当应用执行到 `scale_value` 函数并调用 `std::scalbn` 时，实际会执行 `libm.so` 中 `scalbn` 的实现代码。

5. **测试数据的使用：**  在 Bionic 库的开发和测试过程中，`bionic/tests/math_data/scalb_intel_data.handroid` 这样的文件会被用于单元测试，以确保 `scalbn` 的实现在各种输入情况下都能返回正确的结果。

**Frida Hook 示例调试步骤：**

可以使用 Frida hook `scalbn` 函数来观察其输入和输出。

```python
import frida
import sys

package_name = "你的应用包名" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "scalbn"), {
    onEnter: function(args) {
        console.log("[*] Called scalbn with arguments:");
        console.log("    x = " + args[0]);
        console.log("    n = " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[*] scalbn returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. **安装 Frida 和 Python 环境。**
2. **找到目标应用的包名。**
3. **将 Python 脚本中的 `package_name` 替换为实际的应用包名。**
4. **确保 Android 设备已连接并通过 USB 调试启用。**
5. **运行 Python 脚本。**
6. **在 Android 设备上运行目标应用，并触发调用 `scalbn` 的代码。**
7. **Frida 会拦截对 `scalbn` 的调用，并打印出其输入参数和返回值。**

这个 Frida 脚本会 hook `libm.so` 中的 `scalbn` 函数，并在函数被调用时打印出其参数 `x` 和 `n`，以及返回值。这可以帮助你调试应用中对 `scalbn` 的使用情况。

总结来说，这段代码片段是用于测试 `scalbn` 或 `scalbln` 函数在 Android Bionic 库中实现的测试数据，涵盖了各种不同的输入情况，以确保该函数的正确性和精度。 这与 Android 底层的数学运算能力密切相关，并最终服务于上层的 Framework 和 NDK 应用。

### 提示词
```
这是目录为bionic/tests/math_data/scalb_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
0x1.1745d1745d1770p-9,
    0x1.1745d1745d177p-1,
    -0x1.0p3
  },
  { // Entry 379
    0x1.1745d1745d1770p-8,
    0x1.1745d1745d177p-1,
    -0x1.cp2
  },
  { // Entry 380
    0x1.1745d1745d1770p-7,
    0x1.1745d1745d177p-1,
    -0x1.8p2
  },
  { // Entry 381
    0x1.1745d1745d1770p-6,
    0x1.1745d1745d177p-1,
    -0x1.4p2
  },
  { // Entry 382
    0x1.1745d1745d1770p-5,
    0x1.1745d1745d177p-1,
    -0x1.0p2
  },
  { // Entry 383
    0x1.1745d1745d1770p-4,
    0x1.1745d1745d177p-1,
    -0x1.8p1
  },
  { // Entry 384
    0x1.1745d1745d1770p-3,
    0x1.1745d1745d177p-1,
    -0x1.0p1
  },
  { // Entry 385
    0x1.1745d1745d1770p-2,
    0x1.1745d1745d177p-1,
    -0x1.0p0
  },
  { // Entry 386
    0x1.1745d1745d1770p-1,
    0x1.1745d1745d177p-1,
    0.0
  },
  { // Entry 387
    0x1.1745d1745d1770p0,
    0x1.1745d1745d177p-1,
    0x1.0p0
  },
  { // Entry 388
    0x1.1745d1745d1770p1,
    0x1.1745d1745d177p-1,
    0x1.0p1
  },
  { // Entry 389
    0x1.1745d1745d1770p2,
    0x1.1745d1745d177p-1,
    0x1.8p1
  },
  { // Entry 390
    0x1.1745d1745d1770p3,
    0x1.1745d1745d177p-1,
    0x1.0p2
  },
  { // Entry 391
    0x1.1745d1745d1770p4,
    0x1.1745d1745d177p-1,
    0x1.4p2
  },
  { // Entry 392
    0x1.1745d1745d1770p5,
    0x1.1745d1745d177p-1,
    0x1.8p2
  },
  { // Entry 393
    0x1.1745d1745d1770p6,
    0x1.1745d1745d177p-1,
    0x1.cp2
  },
  { // Entry 394
    0x1.1745d1745d1770p7,
    0x1.1745d1745d177p-1,
    0x1.0p3
  },
  { // Entry 395
    0x1.1745d1745d1770p8,
    0x1.1745d1745d177p-1,
    0x1.2p3
  },
  { // Entry 396
    0x1.1745d1745d1770p9,
    0x1.1745d1745d177p-1,
    0x1.4p3
  },
  { // Entry 397
    0x1.45d1745d1746p-11,
    0x1.45d1745d17460p-1,
    -0x1.4p3
  },
  { // Entry 398
    0x1.45d1745d1746p-10,
    0x1.45d1745d17460p-1,
    -0x1.2p3
  },
  { // Entry 399
    0x1.45d1745d1746p-9,
    0x1.45d1745d17460p-1,
    -0x1.0p3
  },
  { // Entry 400
    0x1.45d1745d1746p-8,
    0x1.45d1745d17460p-1,
    -0x1.cp2
  },
  { // Entry 401
    0x1.45d1745d1746p-7,
    0x1.45d1745d17460p-1,
    -0x1.8p2
  },
  { // Entry 402
    0x1.45d1745d1746p-6,
    0x1.45d1745d17460p-1,
    -0x1.4p2
  },
  { // Entry 403
    0x1.45d1745d1746p-5,
    0x1.45d1745d17460p-1,
    -0x1.0p2
  },
  { // Entry 404
    0x1.45d1745d1746p-4,
    0x1.45d1745d17460p-1,
    -0x1.8p1
  },
  { // Entry 405
    0x1.45d1745d1746p-3,
    0x1.45d1745d17460p-1,
    -0x1.0p1
  },
  { // Entry 406
    0x1.45d1745d1746p-2,
    0x1.45d1745d17460p-1,
    -0x1.0p0
  },
  { // Entry 407
    0x1.45d1745d1746p-1,
    0x1.45d1745d17460p-1,
    0.0
  },
  { // Entry 408
    0x1.45d1745d1746p0,
    0x1.45d1745d17460p-1,
    0x1.0p0
  },
  { // Entry 409
    0x1.45d1745d1746p1,
    0x1.45d1745d17460p-1,
    0x1.0p1
  },
  { // Entry 410
    0x1.45d1745d1746p2,
    0x1.45d1745d17460p-1,
    0x1.8p1
  },
  { // Entry 411
    0x1.45d1745d1746p3,
    0x1.45d1745d17460p-1,
    0x1.0p2
  },
  { // Entry 412
    0x1.45d1745d1746p4,
    0x1.45d1745d17460p-1,
    0x1.4p2
  },
  { // Entry 413
    0x1.45d1745d1746p5,
    0x1.45d1745d17460p-1,
    0x1.8p2
  },
  { // Entry 414
    0x1.45d1745d1746p6,
    0x1.45d1745d17460p-1,
    0x1.cp2
  },
  { // Entry 415
    0x1.45d1745d1746p7,
    0x1.45d1745d17460p-1,
    0x1.0p3
  },
  { // Entry 416
    0x1.45d1745d1746p8,
    0x1.45d1745d17460p-1,
    0x1.2p3
  },
  { // Entry 417
    0x1.45d1745d1746p9,
    0x1.45d1745d17460p-1,
    0x1.4p3
  },
  { // Entry 418
    0x1.745d1745d17490p-11,
    0x1.745d1745d1749p-1,
    -0x1.4p3
  },
  { // Entry 419
    0x1.745d1745d17490p-10,
    0x1.745d1745d1749p-1,
    -0x1.2p3
  },
  { // Entry 420
    0x1.745d1745d17490p-9,
    0x1.745d1745d1749p-1,
    -0x1.0p3
  },
  { // Entry 421
    0x1.745d1745d17490p-8,
    0x1.745d1745d1749p-1,
    -0x1.cp2
  },
  { // Entry 422
    0x1.745d1745d17490p-7,
    0x1.745d1745d1749p-1,
    -0x1.8p2
  },
  { // Entry 423
    0x1.745d1745d17490p-6,
    0x1.745d1745d1749p-1,
    -0x1.4p2
  },
  { // Entry 424
    0x1.745d1745d17490p-5,
    0x1.745d1745d1749p-1,
    -0x1.0p2
  },
  { // Entry 425
    0x1.745d1745d17490p-4,
    0x1.745d1745d1749p-1,
    -0x1.8p1
  },
  { // Entry 426
    0x1.745d1745d17490p-3,
    0x1.745d1745d1749p-1,
    -0x1.0p1
  },
  { // Entry 427
    0x1.745d1745d17490p-2,
    0x1.745d1745d1749p-1,
    -0x1.0p0
  },
  { // Entry 428
    0x1.745d1745d17490p-1,
    0x1.745d1745d1749p-1,
    0.0
  },
  { // Entry 429
    0x1.745d1745d17490p0,
    0x1.745d1745d1749p-1,
    0x1.0p0
  },
  { // Entry 430
    0x1.745d1745d17490p1,
    0x1.745d1745d1749p-1,
    0x1.0p1
  },
  { // Entry 431
    0x1.745d1745d17490p2,
    0x1.745d1745d1749p-1,
    0x1.8p1
  },
  { // Entry 432
    0x1.745d1745d17490p3,
    0x1.745d1745d1749p-1,
    0x1.0p2
  },
  { // Entry 433
    0x1.745d1745d17490p4,
    0x1.745d1745d1749p-1,
    0x1.4p2
  },
  { // Entry 434
    0x1.745d1745d17490p5,
    0x1.745d1745d1749p-1,
    0x1.8p2
  },
  { // Entry 435
    0x1.745d1745d17490p6,
    0x1.745d1745d1749p-1,
    0x1.cp2
  },
  { // Entry 436
    0x1.745d1745d17490p7,
    0x1.745d1745d1749p-1,
    0x1.0p3
  },
  { // Entry 437
    0x1.745d1745d17490p8,
    0x1.745d1745d1749p-1,
    0x1.2p3
  },
  { // Entry 438
    0x1.745d1745d17490p9,
    0x1.745d1745d1749p-1,
    0x1.4p3
  },
  { // Entry 439
    0x1.a2e8ba2e8ba320p-11,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.4p3
  },
  { // Entry 440
    0x1.a2e8ba2e8ba320p-10,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.2p3
  },
  { // Entry 441
    0x1.a2e8ba2e8ba320p-9,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.0p3
  },
  { // Entry 442
    0x1.a2e8ba2e8ba320p-8,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.cp2
  },
  { // Entry 443
    0x1.a2e8ba2e8ba320p-7,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.8p2
  },
  { // Entry 444
    0x1.a2e8ba2e8ba320p-6,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.4p2
  },
  { // Entry 445
    0x1.a2e8ba2e8ba320p-5,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.0p2
  },
  { // Entry 446
    0x1.a2e8ba2e8ba320p-4,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.8p1
  },
  { // Entry 447
    0x1.a2e8ba2e8ba320p-3,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.0p1
  },
  { // Entry 448
    0x1.a2e8ba2e8ba320p-2,
    0x1.a2e8ba2e8ba32p-1,
    -0x1.0p0
  },
  { // Entry 449
    0x1.a2e8ba2e8ba320p-1,
    0x1.a2e8ba2e8ba32p-1,
    0.0
  },
  { // Entry 450
    0x1.a2e8ba2e8ba320p0,
    0x1.a2e8ba2e8ba32p-1,
    0x1.0p0
  },
  { // Entry 451
    0x1.a2e8ba2e8ba320p1,
    0x1.a2e8ba2e8ba32p-1,
    0x1.0p1
  },
  { // Entry 452
    0x1.a2e8ba2e8ba320p2,
    0x1.a2e8ba2e8ba32p-1,
    0x1.8p1
  },
  { // Entry 453
    0x1.a2e8ba2e8ba320p3,
    0x1.a2e8ba2e8ba32p-1,
    0x1.0p2
  },
  { // Entry 454
    0x1.a2e8ba2e8ba320p4,
    0x1.a2e8ba2e8ba32p-1,
    0x1.4p2
  },
  { // Entry 455
    0x1.a2e8ba2e8ba320p5,
    0x1.a2e8ba2e8ba32p-1,
    0x1.8p2
  },
  { // Entry 456
    0x1.a2e8ba2e8ba320p6,
    0x1.a2e8ba2e8ba32p-1,
    0x1.cp2
  },
  { // Entry 457
    0x1.a2e8ba2e8ba320p7,
    0x1.a2e8ba2e8ba32p-1,
    0x1.0p3
  },
  { // Entry 458
    0x1.a2e8ba2e8ba320p8,
    0x1.a2e8ba2e8ba32p-1,
    0x1.2p3
  },
  { // Entry 459
    0x1.a2e8ba2e8ba320p9,
    0x1.a2e8ba2e8ba32p-1,
    0x1.4p3
  },
  { // Entry 460
    0x1.d1745d1745d1b0p-11,
    0x1.d1745d1745d1bp-1,
    -0x1.4p3
  },
  { // Entry 461
    0x1.d1745d1745d1b0p-10,
    0x1.d1745d1745d1bp-1,
    -0x1.2p3
  },
  { // Entry 462
    0x1.d1745d1745d1b0p-9,
    0x1.d1745d1745d1bp-1,
    -0x1.0p3
  },
  { // Entry 463
    0x1.d1745d1745d1b0p-8,
    0x1.d1745d1745d1bp-1,
    -0x1.cp2
  },
  { // Entry 464
    0x1.d1745d1745d1b0p-7,
    0x1.d1745d1745d1bp-1,
    -0x1.8p2
  },
  { // Entry 465
    0x1.d1745d1745d1b0p-6,
    0x1.d1745d1745d1bp-1,
    -0x1.4p2
  },
  { // Entry 466
    0x1.d1745d1745d1b0p-5,
    0x1.d1745d1745d1bp-1,
    -0x1.0p2
  },
  { // Entry 467
    0x1.d1745d1745d1b0p-4,
    0x1.d1745d1745d1bp-1,
    -0x1.8p1
  },
  { // Entry 468
    0x1.d1745d1745d1b0p-3,
    0x1.d1745d1745d1bp-1,
    -0x1.0p1
  },
  { // Entry 469
    0x1.d1745d1745d1b0p-2,
    0x1.d1745d1745d1bp-1,
    -0x1.0p0
  },
  { // Entry 470
    0x1.d1745d1745d1b0p-1,
    0x1.d1745d1745d1bp-1,
    0.0
  },
  { // Entry 471
    0x1.d1745d1745d1b0p0,
    0x1.d1745d1745d1bp-1,
    0x1.0p0
  },
  { // Entry 472
    0x1.d1745d1745d1b0p1,
    0x1.d1745d1745d1bp-1,
    0x1.0p1
  },
  { // Entry 473
    0x1.d1745d1745d1b0p2,
    0x1.d1745d1745d1bp-1,
    0x1.8p1
  },
  { // Entry 474
    0x1.d1745d1745d1b0p3,
    0x1.d1745d1745d1bp-1,
    0x1.0p2
  },
  { // Entry 475
    0x1.d1745d1745d1b0p4,
    0x1.d1745d1745d1bp-1,
    0x1.4p2
  },
  { // Entry 476
    0x1.d1745d1745d1b0p5,
    0x1.d1745d1745d1bp-1,
    0x1.8p2
  },
  { // Entry 477
    0x1.d1745d1745d1b0p6,
    0x1.d1745d1745d1bp-1,
    0x1.cp2
  },
  { // Entry 478
    0x1.d1745d1745d1b0p7,
    0x1.d1745d1745d1bp-1,
    0x1.0p3
  },
  { // Entry 479
    0x1.d1745d1745d1b0p8,
    0x1.d1745d1745d1bp-1,
    0x1.2p3
  },
  { // Entry 480
    0x1.d1745d1745d1b0p9,
    0x1.d1745d1745d1bp-1,
    0x1.4p3
  },
  { // Entry 481
    0x1.p-10,
    0x1.0p0,
    -0x1.4p3
  },
  { // Entry 482
    0x1.p-9,
    0x1.0p0,
    -0x1.2p3
  },
  { // Entry 483
    0x1.p-8,
    0x1.0p0,
    -0x1.0p3
  },
  { // Entry 484
    0x1.p-7,
    0x1.0p0,
    -0x1.cp2
  },
  { // Entry 485
    0x1.p-6,
    0x1.0p0,
    -0x1.8p2
  },
  { // Entry 486
    0x1.p-5,
    0x1.0p0,
    -0x1.4p2
  },
  { // Entry 487
    0x1.p-4,
    0x1.0p0,
    -0x1.0p2
  },
  { // Entry 488
    0x1.p-3,
    0x1.0p0,
    -0x1.8p1
  },
  { // Entry 489
    0x1.p-2,
    0x1.0p0,
    -0x1.0p1
  },
  { // Entry 490
    0x1.p-1,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 491
    0x1.p0,
    0x1.0p0,
    0.0
  },
  { // Entry 492
    0x1.p1,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 493
    0x1.p2,
    0x1.0p0,
    0x1.0p1
  },
  { // Entry 494
    0x1.p3,
    0x1.0p0,
    0x1.8p1
  },
  { // Entry 495
    0x1.p4,
    0x1.0p0,
    0x1.0p2
  },
  { // Entry 496
    0x1.p5,
    0x1.0p0,
    0x1.4p2
  },
  { // Entry 497
    0x1.p6,
    0x1.0p0,
    0x1.8p2
  },
  { // Entry 498
    0x1.p7,
    0x1.0p0,
    0x1.cp2
  },
  { // Entry 499
    0x1.p8,
    0x1.0p0,
    0x1.0p3
  },
  { // Entry 500
    0x1.p9,
    0x1.0p0,
    0x1.2p3
  },
  { // Entry 501
    0x1.p10,
    0x1.0p0,
    0x1.4p3
  },
  { // Entry 502
    0x1.fffffffffffff0p0,
    0x1.fffffffffffffp1023,
    -0x1.ff8p9
  },
  { // Entry 503
    0x1.fffffffffffff0p1,
    0x1.fffffffffffffp1023,
    -0x1.ff0p9
  },
  { // Entry 504
    0x1.fffffffffffff0p23,
    0x1.fffffffffffffp1023,
    -0x1.f40p9
  },
  { // Entry 505
    0x1.fffffffffffff0p24,
    0x1.fffffffffffffp1023,
    -0x1.f38p9
  },
  { // Entry 506
    0x1.fffffffffffff0p1013,
    0x1.fffffffffffffp1023,
    -0x1.4p3
  },
  { // Entry 507
    0x1.fffffffffffff0p1014,
    0x1.fffffffffffffp1023,
    -0x1.2p3
  },
  { // Entry 508
    0x1.fffffffffffff0p1015,
    0x1.fffffffffffffp1023,
    -0x1.0p3
  },
  { // Entry 509
    0x1.fffffffffffff0p1016,
    0x1.fffffffffffffp1023,
    -0x1.cp2
  },
  { // Entry 510
    0x1.fffffffffffff0p1017,
    0x1.fffffffffffffp1023,
    -0x1.8p2
  },
  { // Entry 511
    0x1.fffffffffffff0p1018,
    0x1.fffffffffffffp1023,
    -0x1.4p2
  },
  { // Entry 512
    0x1.fffffffffffff0p1019,
    0x1.fffffffffffffp1023,
    -0x1.0p2
  },
  { // Entry 513
    0x1.fffffffffffff0p1020,
    0x1.fffffffffffffp1023,
    -0x1.8p1
  },
  { // Entry 514
    0x1.fffffffffffff0p1021,
    0x1.fffffffffffffp1023,
    -0x1.0p1
  },
  { // Entry 515
    0x1.fffffffffffff0p1022,
    0x1.fffffffffffffp1023,
    -0x1.0p0
  },
  { // Entry 516
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0.0
  },
  { // Entry 517
    0x1.p-51,
    0x1.0p-1074,
    0x1.ff8p9
  },
  { // Entry 518
    0x1.p-52,
    0x1.0p-1074,
    0x1.ff0p9
  },
  { // Entry 519
    0x1.p-74,
    0x1.0p-1074,
    0x1.f40p9
  },
  { // Entry 520
    0x1.p-75,
    0x1.0p-1074,
    0x1.f38p9
  },
  { // Entry 521
    0x1.p-1074,
    0x1.0p-1074,
    0.0
  },
  { // Entry 522
    0x1.p-1073,
    0x1.0p-1074,
    0x1.0p0
  },
  { // Entry 523
    0x1.p-1072,
    0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 524
    0x1.p-1071,
    0x1.0p-1074,
    0x1.8p1
  },
  { // Entry 525
    0x1.p-1070,
    0x1.0p-1074,
    0x1.0p2
  },
  { // Entry 526
    0x1.p-1069,
    0x1.0p-1074,
    0x1.4p2
  },
  { // Entry 527
    0x1.p-1068,
    0x1.0p-1074,
    0x1.8p2
  },
  { // Entry 528
    0x1.p-1067,
    0x1.0p-1074,
    0x1.cp2
  },
  { // Entry 529
    0x1.p-1066,
    0x1.0p-1074,
    0x1.0p3
  },
  { // Entry 530
    0x1.p-1065,
    0x1.0p-1074,
    0x1.2p3
  },
  { // Entry 531
    0x1.p-1064,
    0x1.0p-1074,
    0x1.4p3
  },
  { // Entry 532
    0x1.p-1025,
    0x1.0p-2,
    -0x1.ff8p9
  },
  { // Entry 533
    0x1.p-1024,
    0x1.0p-2,
    -0x1.ff0p9
  },
  { // Entry 534
    0x1.p-1024,
    0x1.0p-1,
    -0x1.ff8p9
  },
  { // Entry 535
    0x1.p-1023,
    0x1.0p-1,
    -0x1.ff0p9
  },
  { // Entry 536
    0x1.80p-1024,
    0x1.8p-1,
    -0x1.ff8p9
  },
  { // Entry 537
    0x1.80p-1023,
    0x1.8p-1,
    -0x1.ff0p9
  },
  { // Entry 538
    0.0,
    0x1.0p-2,
    -0x1.0c8p10
  },
  { // Entry 539
    0.0,
    0x1.0p-2,
    -0x1.0c4p10
  },
  { // Entry 540
    0.0,
    0x1.0p-1,
    -0x1.0c8p10
  },
  { // Entry 541
    0x1.p-1074,
    0x1.0p-1,
    -0x1.0c4p10
  },
  { // Entry 542
    0.0,
    0x1.8p-1,
    -0x1.0c8p10
  },
  { // Entry 543
    0x1.80p-1074,
    0x1.8p-1,
    -0x1.0c4p10
  },
  { // Entry 544
    0x1.p1023,
    0x1.0p0,
    0x1.ff8p9
  },
  { // Entry 545
    0x1.p1022,
    0x1.0p0,
    0x1.ff0p9
  },
  { // Entry 546
    0x1.p-1074,
    0x1.0p-1074,
    0.0
  },
  { // Entry 547
    0x1.p-1073,
    0x1.0p-1074,
    0x1.0p0
  },
  { // Entry 548
    0x1.p-1072,
    0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 549
    0x1.p-1071,
    0x1.0p-1074,
    0x1.8p1
  },
  { // Entry 550
    0x1.p-1070,
    0x1.0p-1074,
    0x1.0p2
  },
  { // Entry 551
    0x1.p-1069,
    0x1.0p-1074,
    0x1.4p2
  },
  { // Entry 552
    0x1.p-1068,
    0x1.0p-1074,
    0x1.8p2
  },
  { // Entry 553
    0x1.p-1067,
    0x1.0p-1074,
    0x1.cp2
  },
  { // Entry 554
    0x1.p-1066,
    0x1.0p-1074,
    0x1.0p3
  },
  { // Entry 555
    0x1.p-1065,
    0x1.0p-1074,
    0x1.2p3
  },
  { // Entry 556
    0x1.p-1064,
    0x1.0p-1074,
    0x1.4p3
  },
  { // Entry 557
    0x1.p-1063,
    0x1.0p-1074,
    0x1.6p3
  },
  { // Entry 558
    0x1.p-1062,
    0x1.0p-1074,
    0x1.8p3
  },
  { // Entry 559
    0x1.p-1061,
    0x1.0p-1074,
    0x1.ap3
  },
  { // Entry 560
    0x1.p-1060,
    0x1.0p-1074,
    0x1.cp3
  },
  { // Entry 561
    0x1.p-1059,
    0x1.0p-1074,
    0x1.ep3
  },
  { // Entry 562
    0x1.p-1058,
    0x1.0p-1074,
    0x1.0p4
  },
  { // Entry 563
    0x1.p-1057,
    0x1.0p-1074,
    0x1.1p4
  },
  { // Entry 564
    0x1.p-1056,
    0x1.0p-1074,
    0x1.2p4
  },
  { // Entry 565
    0x1.p-1055,
    0x1.0p-1074,
    0x1.3p4
  },
  { // Entry 566
    0x1.p-1054,
    0x1.0p-1074,
    0x1.4p4
  },
  { // Entry 567
    0x1.p-1053,
    0x1.0p-1074,
    0x1.5p4
  },
  { // Entry 568
    0x1.p-1052,
    0x1.0p-1074,
    0x1.6p4
  },
  { // Entry 569
    0x1.p-1051,
    0x1.0p-1074,
    0x1.7p4
  },
  { // Entry 570
    0x1.p-1050,
    0x1.0p-1074,
    0x1.8p4
  },
  { // Entry 571
    0x1.p-1049,
    0x1.0p-1074,
    0x1.9p4
  },
  { // Entry 572
    0x1.p-1048,
    0x1.0p-1074,
    0x1.ap4
  },
  { // Entry 573
    0x1.p-1047,
    0x1.0p-1074,
    0x1.bp4
  },
  { // Entry 574
    0x1.p-1046,
    0x1.0p-1074,
    0x1.cp4
  },
  { // Entry 575
    0x1.p-1045,
    0x1.0p-1074,
    0x1.dp4
  },
  { // Entry 576
    0x1.p-1044,
    0x1.0p-1074,
    0x1.ep4
  },
  { // Entry 577
    0x1.p-1043,
    0x1.0p-1074,
    0x1.fp4
  },
  { // Entry 578
    0x1.p-1042,
    0x1.0p-1074,
    0x1.0p5
  },
  { // Entry 579
    0x1.p-1041,
    0x1.0p-1074,
    0x1.080p5
  },
  { // Entry 580
    0x1.p-1040,
    0x1.0p-1074,
    0x1.1p5
  },
  { // Entry 581
    0x1.p-1039,
    0x1.0p-1074,
    0x1.180p5
  },
  { // Entry 582
    0x1.p-1038,
    0x1.0p-1074,
    0x1.2p5
  },
  { // Entry 583
    0x1.p-1037,
    0x1.0p-1074,
    0x1.280p5
  },
  { // Entry 584
    0x1.p-1036,
    0x1.0p-1074,
    0x1.3p5
  },
  { // Entry 585
    0x1.p-1035,
    0x1.0p-1074,
    0x1.380p5
  },
  { // Entry 586
    0x1.p-1034,
    0x1.0p-1074,
    0x1.4p5
  },
  { // Entry 587
    0x1.p-1033,
    0x1.0p-1074,
    0x1.480p5
  },
  { // Entry 588
    0x1.p-1032,
    0x1.0p-1074,
    0x1.5p5
  },
  { // Entry 589
    0x1.p-1031,
    0x1.0p-1074,
    0x1.580p5
  },
  { // Entry 590
    0x1.p-1030,
    0x1.0p-1074,
    0x1.6p5
  },
  { // Entry 591
    0x1.p-1029,
    0x1.0p-1074,
    0x1.680p5
  },
  { // Entry 592
    0x1.p-1028,
    0x1.0p-1074,
    0x1.7p5
  },
  { // Entry 593
    0x1.p-1027,
    0x1.0p-1074,
    0x1.780p5
  },
  { // Entry 594
    0x1.p-1026,
    0x1.0p-1074,
    0x1.8p5
  },
  { // Entry 595
    0x1.p-1025,
    0x1.0p-1074,
    0x1.880p5
  },
  { // Entry 596
    0x1.p-1024,
    0x1.0p-1074,
    0x1.9p5
  },
  { // Entry 597
    0x1.p-1023,
    0x1.0p-1074,
    0x1.980p5
  },
  { // Entry 598
    0x1.p-1022,
    0x1.0p-1074,
    0x1.ap5
  },
  { // Entry 599
    0x1.p-1021,
    0x1.0p-1074,
    0x1.a80p5
  },
  { // Entry 600
    0x1.p-1020,
    0x1.0p-1074,
    0x1.bp5
  },
  { // Entry 601
    0x1.p-1019,
    0x1.0p-1074,
    0x1.b80p5
  },
  { // Entry 602
    0x1.p-1018,
    0x1.0p-1074,
    0x1.cp5
  },
  { // Entry 603
    0x1.p-1017,
    0x1.0p-1074,
    0x1.c80p5
  },
  { // Entry 604
    0x1.p-1016,
    0x1.0p-1074,
    0x1.dp5
  },
  { // Entry 605
    0x1.p-1015,
    0x1.0p-1074,
    0x1.d80p5
  },
  { // Entry 606
    0x1.p-1014,
    0x1.0p-1074,
    0x1.ep5
  },
  { // Entry 607
    0x1.p-1013,
    0x1.0p-1074,
    0x1.e80p5
  },
  { // Entry 608
    0x1.p-1012,
    0x1.0p-1074,
    0x1.fp5
  },
  { // Entry 609
    0x1.p-1011,
    0x1.0p-1074,
    0x1.f80p5
  },
  { // Entry 610
    0x1.p-1010,
    0x1.0p-1074,
    0x1.0p6
  },
  { // Entry 611
    0x1.p-1009,
    0x1.0p-1074,
    0x1.040p6
  },
  { // Entry 612
    0x1.p-1008,
    0x1.0p-1074,
    0x1.080p6
  },
  { // Entry 613
    0x1.p-1007,
    0x1.0p-1074,
    0x1.0c0p6
  },
  { // Entry 614
    0x1.p-1006,
    0x1.0p-1074,
    0x1.1p6
  },
  { // Entry 615
    0x1.p-1005,
    0x1.0p-1074,
    0x1.140p6
  },
  { // Entry 616
    0x1.p-1004,
    0x1.0p-1074,
    0x1.180p6
  },
  { // Entry 617
    0x1.p-1003,
    0x1.0p-1074,
    0x1.1c0p6
  },
  { // Entry 618
    0x1.p-1002,
    0x1.0p-1074,
    0x1.2p6
  },
  { // Entry 619
    0x1.p-1001,
    0x1.0p-1074,
    0x1.240p6
  },
  { // Entry 620
    0x1.p-1000,
    0x1.0p-1074,
    0x1.280p6
  },
  { // Entry 621
    0x1.p-999,
    0x1.0p-1074,
    0x1.2c0p6
  },
  { // Entry 622
    0x1.p-998,
    0x1.0p-1074,
    0x1.3p6
  },
  { // Entry 623
    0x1.p-997,
    0x1.0p-1074,
    0x1.340p6
  },
  { // Entry 624
    0x1.p-996,
    0x1.0p-1074,
    0x1.380p6
  },
  { // Entry 625
    0x1.p-995,
    0x1.0p-1074,
    0x1.3c0p6
  },
  { // Entry 626
    0x1.p-994,
    0x1.0p-1074,
    0x1.4p6
  },
  { // Entry 627
    0x1.p-993,
    0x1.0p-1074,
    0x1.440p6
  },
  { // Entry 628
    0x1.p-992,
    0x1.0p-1074,
    0x1.480p6
  },
  { // Entry 629
    0x1.p-991,
    0x1.0p-1074,
    0x1.4c0p6
  },
  { // Entry 630
    0x1.p-990,
    0x1.0p-1074,
    0x1.5p6
  },
  { // Entry 631
    0x1.p-989,
    0x1.0p-1074,
    0x1.540p6
  },
  { // Entry 632
    0x1.p-988,
    0x1.0p-1074,
    0x1.580p6
  },
  { // Entry 633
    0x1.p-987,
    0x1.0p-1074,
    0x1.5c0p6
  },
  { // Entry 634
    0x1.p-986,
    0x1.0p-1074,
    0x1.6p6
  },
  { // Entry 635
    0x1.p-985,
    0x1.0p-1074,
    0x1.640p6
  },
  { // Entry 636
    0x1.p-984,
    0x1.0p-1074,
    0x1.680p6
  },
  { // Entry 637
    0x1.p-983,
    0x1.0p-1074,
    0x1.6c0p6
  },
  { // Entry 638
    0x1.p-982,
    0x1.0p-1074,
    0x1.7p6
  },
  { // Entry 639
    0x1.p-981,
    0x1.0p-1074,
    0x1.740p6
  },
  { // Entry 640
    0x1.p-980,
    0x1.0p-1074,
    0x1.780p6
  },
  { // Entry 641
    0x1.p-979,
    0x1.0p-1074,
    0x1.7c0p6
  },
  { // Entry 642
    0x1.p-978,
    0x1.0p-1074,
    0x1.8p6
  },
  { // Entry 643
    0x1.p-977,
    0x1.0p-1074,
    0x1.840p6
  },
  { // Entry 644
    0x1.p-976,
    0x1.0p-1074,
    0x1.880p6
  },
  { // Entry 645
    0x1.p-975,
    0x1.0p-1074,
    0x1.8c0p6
  },
  { // Entry 646
    0x1.p-974,
    0x1.0p-1074,
    0x1.9p6
  },
  { // Entry 647
    0x1.p-973,
    0x1.0p-1074,
    0x1.940p6
  },
  { // Entry 648
    0x1.p-972,
    0x1.0p-1074,
    0x1.980p6
  },
  { // Entry 649
    0x1.p-971,
    0x1.0p-1074,
    0x1.9c0p6
  },
  { // Entry 650
    0x1.p-970,
    0x1.0p-1074,
    0x1.ap6
  },
  { // Entry 651
    0x1.p-969,
    0x1.0p-1074,
    0x1.a40p6
  },
  { // Entry 652
    0x1.p-968,
    0x1.0p-1074,
    0x1.a80p6
  },
  { // Entry 653
    0x1.p-967,
    0x1.0p-1074,
    0x1.ac0p6
  },
  { // Entry 654
    0x1.p-966,
    0x1.0p-1074,
    0x1.bp6
  },
  { // Entry 655
    0x1.p-965,
    0x1.0p-1074,
    0x1.b40p6
  },
  { // Entry 656
    0x1.p-964,
    0x1.0p-1074,
    0x1.b80p6
  },
  { // Entry 657
    0x1.p-963,
    0x1.0p-1074,
    0x1.bc0p6
  },
  { // Entry 658
    0x1.p-962,
    0x1.0p-1074,
    0x1.cp6
  },
  { // Entry 659
    0x1.p-961,
    0x1.0p-1074,
    0x1.c40p6
  },
  { // Entry 660
    0x1.p-960,
    0x1.0p-1074,
    0x1.c80p6
  },
  { // Entry 661
    0x1.p-959,
    0x1.0p-1074,
    0x1.cc0p6
  },
  { // Entry 662
    0x1.p-958,
    0x1.0p-1074,
    0x1.dp6
  },
  { // Entry 663
    0x1.p-957,
    0x1.0p-1074,
    0x1.d40p6
  },
  { // Entry 664
    0x1.p-956,
    0x1.0p-1074,
    0x1.d80p6
  },
  { // Entry 665
    0x1.p-955,
    0x1.0p-1074,
    0x1.dc0p6
  },
  { // Entry 666
    0x1.p-954,
    0x1.0p-1074,
    0x1.ep6
  },
  { // Entry 667
    0x1.p-953,
    0x1.0p-1074,
    0x1.e40p6
  },
  { // Entry 668
    0x1.p-952,
    0x1.0p-1074,
    0x1.e80p6
  },
  { // Entry 669
    0x1.p-951,
    0x1.0p-1074,
    0x1.ec0p6
  },
  { // Entry 670
    0x1.p-950,
    0x1.0p-1074,
    0x1.fp6
  },
  { // Entry 671
    0x1.p-949,
    0x1.0p-1074,
    0x1.f40p6
  },
  { // Entry 672
    0x1.p-948,
    0x1.0p-1074,
    0x1.f80p6
  },
  { // Entry 673
    0x1.p-947,
    0x1.0p-1074,
    0x1.fc0p6
  },
  { // Entry 674
    0x1.p-946,
    0x1.0p-1074,
    0x1.0p7
  },
  { // Entry 675
    0x1.p-945,
    0x1.0p-1074,
    0x1.020p7
  },
  { // Entry 676
    0x1.p-944,
    0x1.0p-1074,
    0x1.040p7
  },
  { // Entry 677
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0.0
  },
  { // Entry 678
    0x1.ffffffffffffe0p-1022,
    0x1.ffffffffffffep-1023,
    0x1.0p0
  },
  { // Entry 679
    0x1.ffffffffffffe0p-1021,
    0x1.ffffffffffffep-1023,
    0x1.0p1
  },
  { // Entry 680
    0x1.ffffffffffffe0p-1020,
    0x1.ffffffffffffep-1023,
    0x1.8p1
  },
  { // Entry 681
    0x1.ffffffffffffe0p-1019,
    0x1.ffffffffffffep-1023,
    0x1.0p2
  },
  { // Entry 682
    0x1.ffffffffffffe0p-1018,
    0x1.ffffffffffffep-1023,
    0x1.4p2
  },
  { // Entry 683
    0x1.ffffffffffffe0p-1017,
    0x1.ffffffffffffep-1023,
    0x1.8p2
  },
  { // Entry 684
    0x1.ffffffffffffe0p-1016,
    0x1.ffffffffffffep-1023,
    0x1.cp2
  },
  { // Entry 685
    0x1.ffffffffffffe0p-1015,
    0x1.ffffffffffffep-1023,
    0x1.0p3
  },
  { // Entry 686
    0x1.ffffffffffffe0p-1014,
    0x1.ffffffffffffep-1023,
    0x1.2p3
  },
  { // Entry 687
    0x1.ffffffffffffe0p-1013,
    0x1.ffffffffffffep-1023,
    0x1.4p3
  },
  { // Entry 688
    0x1.ffffffffffffe0p-1012,
    0x1.ffffffffffffep-1023,
    0x1.6p3
  },
  { // Entry 689
    0x1.ffffffffffffe0p-1011,
    0x1.ffffffffffffep-1023,
    0x1.8p3
  },
  { // Entry 690
    0x1.ffffffffffffe0p-1010,
    0x1.ffffffffffffep-1023,
    0x1.ap3
  },
  { // Entry 691
    0x1.ffffffffffffe0p-1009,
    0x1.ffffffffffffep-1023,
    0x1.cp3
  },
  { // Entry 692
    0x1.ffffffffffffe0p-1008,
    0x1.ffffffffffffep-1023,
    0x1.ep3
  },
  { // Entry 693
    0x1.ffffffffffffe0p-1007,
    0x1.ffffffffffffep-1023,
    0x1.0p4
  },
  { // Entry 694
    0x1.ffffffffffffe0p-1006,
    0x1.ffffffffffffep-1023,
    0x1.1p4
  },
  { // Entry 695
    0x1.ffffffffffffe0p-1005,
    0x1.ffffffffffffep-1023,
    0x1.2p4
  },
  { // Entry 696
    0x1.ffffffffffffe0p-1004,
    0x1.ffffffffffffep-1023,
    0x1.3p4
  },
  { // Entry 697
    0x1.ffffffffffffe0p-1003,
    0x1.ffffffffffffep-1023,
    0x1.4p4
  },
  { // Entry 698
    0x1.ffffffffffffe0p-1002,
    0x1.ffffffffffffep-1023,
    0x1.5p4
  },
  { // Entry 699
    0x1.ffffffffffffe0p-1001,
    0x1.ffffffffffffep-1023,
    0x1.6p4
  },
  { // Entry 700
    0x1.ffffffffffffe0p-1000,
    0x1.ffffffffffffep-1023,
    0x1.7p4
  },
  { // Entry 701
    0x1.ffffffffffffe0p-999,
    0x1.ffffffffffffep-1023,
    0x1.8p4
  },
  { // Entry 702
    0x1.ffffffffffffe0p-998,
    0x1.ffffffffffffep-1023,
    0x1.9p4
  },
  { // Entry 703
    0x1.ffffffffffffe0p-997,
    0x1.ffffffffffffep-1023,
    0x1.ap4
  },
  { // Entry 704
    0x1.ffffffffffffe0p-996,
    0x1.ffffffffffffep-1023,
    0x1.bp4
  },
  { // Entry 705
    0x1.ffffffffffffe0p-995,
    0x1.ffffffffffffep-1023,
    0x1.cp4
  },
  { // Entry 706
    0x1.ffffffffffffe0p-994,
    0x1.ffffffffffffep-1023,
    0x1.dp4
  },
  { // Entry 707
    0x1.ffffffffffffe0p-993,
    0x1.ffffffffffffep-1023,
    0x1.ep4
  },
  { // Entry 708
    0x1.ffffffffffffe0p-992,
    0x1.ffffffffffffep-1023,
    0x1.fp4
  },
  { // Entry 709
    0x1.ffffffffffffe0p-991,
    0x1.ffffffffffffep-1023,
    0x1.0p5
  },
  { // Entry 710
    0x1.ffffffffffffe0p-990,
    0x1.ffffffffffffep-1023,
    0x1.080p5
  },
  { // Entry 711
    0x1.ffffffffffffe0p-989,
    0x1.ffffffffffffep-1023,
    0x1.1p5
  },
  { // Entry 712
    0x1.ffffffffffffe0p-988,
    0x1.ffffffffffffep-1023,
    0x1.180p5
  },
  { // Entry 713
    0x1.ffffffffffffe0p-987,
    0x1.ffffffffffffep-1023,
    0x1.2p5
  },
  { // Entry 714
    0x1.ffffffffffffe0p-986,
    0x1.ffffffffffffep-1023,
    0x1.280p5
  },
  { // Entry 715
    0x1.ffffffffffffe0p-985,
    0x1.ffffffffffffep-1023,
    0x1.3p5
  },
  { // Entry 716
    0x1.ffffffffffffe0p-984,
    0x1.ffffffffffffep-1023,
    0x1.380p5
  },
  { // Entry 717
    0x1.ffffffffffffe0p-983,
    0x1.ffffffffffffep-1023,
    0x1.4p5
  },
  { // Entry 718
    0x1.ffffffffffffe0p-982,
    0x1.ffffffffffffep-1023,
    0x1.480p5
  },
  { // Entry 719
    0x1.ffffffffffffe0p-981,
    0x1.ffffffffffffep-1023,
    0x1.5p5
  },
  { // Entry 720
    0x1.ffffffffffffe0p-980,
    0x1.ffffffffffffep-1023,
    0x1.580p5
  },
  { // Entry 721
    0x1.ffffffffffffe0p-979,
    0x1.ffffffffffffep-1023,
    0x1.6p5
  },
  { // Entry 722
    0x1.ffffffffffffe0p-978,
    0x1.ffffffffffffep-1023,
    0x1.680p5
  },
  { // Entry 723
    0x1.ffffffffffffe0p-977,
    0x1.ffffffffffffep-1023,
    0x1.7p5
  },
  { // Entry 724
    0x1.ffffffffffffe0p-976,
    0x1.ffffffffffffep-1023,
    0x1.780p5
  },
  { // Entry 725
    0x1.ffffffffffffe0p-975,
    0x1.ffffffffffffep-1023,
    0x1.8p5
  },
  { // Entry 726
    0x1.ffffffffffffe0p-974,
    0x1.ffffffffffffep-1023,
    0x1.880p5
  },
  { // Entry 727
    0x1.ffffffffffffe0p-973,
    0x1.ffffffffffffep-1023,
    0x1.9p5
  },
  { // Entry 728
    0x1.ffffffffffffe0p-972,
    0x1.ffffffffffffep-1023,
    0x1.980p5
  },
  { // Entry 729
    0x1.ffffffffffffe0p-971,
    0x1.ffffffffffffep-1023,
    0x1.ap5
  },
  { // Entry 730
    0x1.ffffffffffffe0p-970,
    0x1.ffffffffffffep-1023,
    0x1.a80p5
  },
  { // Entry 731
    0x1.ffffffffffffe0p-969,
    0x1.ffffffffffffep-1023,
    0x1.bp5
  },
  { // Entry 732
    0x1.ffffffffffffe0p-968,
    0x1.ffffffffffffep-1023,
    0x1.b80p5
  },
  { // Entry 733
    0x1.ffffffffffffe0p-967,
    0x1.ffffffffffffep-1023,
    0x1.cp5
  },
  { // Entry 734
    0x1.ffffffffffffe0p-966,
    0x1.ffffffffffffep-1023,
    0x1.c80p5
  },
  { // Entry 735
    0x1.ffffffffffffe0p-965,
    0x1.ffffffffffffep-1023,
    0x1.dp5
  },
  { // Entry 736
    0x1.ffffffffffffe0p-964,
    0x1.ffffffffffffep-1023,
    0x1.d80p5
  },
  { // Entry 737
    0x1.ffffffffffffe0p-963,
    0x1.ffffffffffffep-1023,
    0x1.ep5
  },
  { // Entry 738
    0x1.ffffffffffffe0p-962,
    0x1.ffffffffffffep-1023,
    0x1.e80p5
  },
  { // Entry 739
    0x1.ffffffffffffe0p-961,
    0x1.ffffffffffffep-1023,
    0x1.fp5
  },
  { // Entry 740
    0x1.ffffffffffffe0p-960,
    0x1.ffffffffffffep-1023,
    0x1.f80p5
  },
  { // Entry 741
    0x1.ffffffffffffe0p-959,
    0x1.ffffffffffffep-1023,
    0x1.0p6
  },
  { // Entry 742
    0x1.ffffffffffffe0p-958,
    0x1.ffffffffffffep-1023,
    0x1.040p6
  },
  { // Entry 743
    0x1.ffffffffffffe0p-957,
    0x1.ffffffffffffep-1023,
    0x1.080p6
  },
  { // Entry 744
    0x1.ffffffffffffe0p-956,
    0x1.ffffffffffffep-1023,
    0x1.0c0p6
  },
  { // Entry 745
    0x1.ffffffffffffe0p-955,
    0x1.ffffffffffffep-1023,
    0x1.1p6
  },
  { // Entry 746
    0x1.ffffffffffffe0p-954,
    0x1.ffffffffffffep-1023,
    0x1.140p6
  },
  { // Entry 747
    0x1.ffffffffffffe0p-953,
    0x1.ffffffffffffep-1023,
    0x1.180p6
  },
  { // Entry 748
    0x1.ffffffffffffe0p-952,
    0x1.ffffffffffffep-1023,
    0x1.1c0p6
  },
  { // Entry 749
    0x1.ffffffffffffe0p-951,
    0x1.ffffffffffffep-1023,
    0x1.2p6
  },
  { // Entry 750
    0x1.ffffffffffffe0p-950,
    0x1.ffffffffffffep-1023,
    0x1.240p6
  },
  { // Entry 751
    0x1.ffffffffffffe0p-949,
    0x1.ffffffffffffep-1023,
    0x1.280p6
  },
  { // Entry 752
    0x1.ffffffffffffe0p-948,
    0x1.ffffffffffffep-1023,
    0x1.2c0p6
  },
  { // Entry 753
    0x1.ffffffffffffe0p-947,
    0x1.ffffffffffffep-1023,
    0x1.3p6
  },
  { // Entry 754
    0x1.ffffffffffffe0p-946,
    0x1.ffffffffffffep-1023,
    0x1.340p6
  },
  { // Entry 755
    0x1.ffffffffffffe0p-945,
    0x1.ffffffffffffep-1023,
    0x1.380p6
  },
  { // Entry 756
    0x1.ffffffffffffe0p-944,
    0x1.ffffffffffffep-1023,
    0x1.3c0p6
  },
  { // Entry 757
    0x1.ffffffffffffe0p-943,
    0x1.ffffffffffffep-1023,
    0x1.4p6
  },
  { // Entry 758
    0x1.ffffffffffffe0p-942,
    0x1.ffffffffffffep-1023,
    0x1.440p6
  },
  { // Entry 759
    0x1.ffffffffffffe0p-941,
    0x1.ffffffffffffep-1023,
    0x1.480p6
  },
  { // Entry 760
    0x1.ffffffffffffe0p-940,
    0x1.ffffffffffffep-1023,
    0x1.4c0p6
  },
  { // Entry 761
    0x1.ffffffffffffe0p-939,
    0x1.ffffffffffffep-1023,
    0x1.5p6
  },
  { // Entry 762
    0x1.ffffffffffffe0p-938,
    0x1.ffffffffffffep-1023,
    0x1.540p6
  },
  { // Entry 763
    0x1.ffffffffffffe0p-937,
    0x1.ffffffffffffep-1023,
    0x1.580p6
  },
  { // Entry 764
    0x1.ffffffffffffe0p-936,
    0x1.ffffffffffffep-1023,
    0x1.5c0p6
  },
  { // Entry 765
    0x1.ffffffffffffe0p-935,
    0x1.ffffffffffffep-1023,
    0x1.6p6
  },
  { // Entry 766
    0x1.ffffffffffffe0p-934,
    0x1.ffffffffffffep-1023,
    0x1.640p6
  },
  { // Entry 767
    0x1.ffffffffffffe0p-933,
    0x1.ffffffffffffep-1023,
    0x1.680p6
  },
  { // Entry 768
    0x1.ffffffffffffe0p-932,
    0x1.ffffffffffffep-1023,
    0x1.6c0p6
  },
  { // Entry 769
    0x1.ffffffffffffe0p-931,
    0x1.ffffffffffffep-1023,
    0x1.7p6
  },
  { // Entry 770
    0x1.ffffffffffffe0p-930,
    0x1.ffffffffffffep-1023,
    0x1.740p6
  },
  { // Entry 771
    0x1.ffffffffffffe0p-929,
    0x1.ffffffffffffep-1023,
    0x1.780p6
  },
  { // Entry 772
    0x1.ffffffffffffe0p-928,
    0x1.ffffffffffffep-1023,
    0x1.7c0p6
  },
  { // Entry 773
    0x1.ffffffffffffe0p-927,
    0x1.ffffffffffffep-1023,
    0x1.8p6
  },
  { // Entry 774
    0x1.ffffffffffffe0p-926,
    0x1.ffffffffffffep-1023,
    0x1.840p6
  },
  { // Entry 775
    0x1.ffffffffffffe0p-925,
    0x1.ffffffffffffep-1023,
    0x1.880p6
  },
  { // Entry 776
    0x1.ffffffffffffe0p-924,
    0x1.ffffffffffffep-1023,
    0x1.8c0p6
  },
  { // Entry 777
    0x1.ffffffffffffe0p-923,
    0x1.ffffffffffffep-1023,
    0x1.9p6
  },
  { // Entry 778
    0x1.ffffffffffffe0p-922,
    0x1.ffffffffffffep-1023,
    0x1.940p6
  },
  { // Entry 779
    0x1.ffffffffffffe0p-921,
    0x1.ffffffffffffep-1023,
    0x1.980p6
  },
  { // Entry 780
    0x1.ffffffffffffe0p-920,
    0x1.ffffffffffffep-1023,
    0x1.9c0p6
  },
  { // Entry 781
    0x1.ffffffffffffe0p-919,
    0x1.ffffffffffffep-1023,
    0x1.ap6
  },
  { // Entry 782
    0x1.ffffffffffffe0p-918,
    0x1.ffffffffffffep-1023,
    0x1.a40p6
  },
  { // Entry 783
    0x1.ffffffffffffe0p-917,
    0x1.ffffffffffffep-1023,
    0x1.a80p6
  },
  { // Entry 784
    0x1.ffffffffffffe0p-916,
    0x1.ffffffffffffep-1023,
    0x1.ac0p6
  },
  { // Entry 785
    0x1.ffffffffffffe0p-915,
    0x1.ffffffffffffep-1023,
    0x1.bp6
  },
  { // Entry 786
    0x1.ffffffffffffe0p-914,
    0x1.ffffffffffffep-1023,
    0x1.b40p6
  },
  { // Entry 787
    0x1.ffffffffffffe0p-913,
    0x1.ffffffffffffep-1023,
    0x1.b80p6
  },
  { // Entry 788
    0x1.ffffffffffffe0p-912,
    0x1.ffffffffffffep-1023,
    0x1.bc0p6
  },
  { // Entry 789
    0x1.ffffffffffffe0p-911,
    0x1.f
```
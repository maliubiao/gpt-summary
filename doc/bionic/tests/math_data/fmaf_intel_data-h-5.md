Response:
Let's break down the thought process for answering the request about `fmaf_intel_data.handroid`.

**1. Understanding the Core Request:**

The central task is to understand the *function* of the provided C code snippet. The surrounding context (directory path, description of bionic) gives crucial hints. The code resides in a `tests` directory, specifically for `math_data`, and involves `fmaf`. This strongly suggests it's *test data* for the `fmaf` function.

**2. Identifying Key Elements:**

The code consists of a large array of structures. Each structure contains four floating-point values. The names like `HUGE_VALF` and the hexadecimal representation of floating-point numbers are characteristic of math library test cases. The `// Entry NNNN` comments further confirm this structure as a sequence of test entries.

**3. Formulating the Primary Function:**

Based on the above, the primary function is to provide input and expected output values for testing the `fmaf` (fused multiply-add float) function. Each entry represents a test case with three inputs (presumably the operands of `fmaf`) and one expected output.

**4. Connecting to Android/Bionic:**

* **Bionic's Role:** The file belongs to bionic, Android's C library. This means it's part of the standard math library implementation used by Android.
* **`fmaf`'s Purpose:**  Recall what `fmaf` does: `a * b + c`. The four values in each entry likely correspond to `a`, `b`, `c`, and the expected result of `fmaf(a, b, c)`.
* **Android Functionality:**  Any Android component using floating-point arithmetic, especially those needing high precision or performance (e.g., graphics, audio processing, sensor calculations), might indirectly rely on the correctness of `fmaf`.

**5. Explaining `libc` Functions:**

While the provided code *itself* doesn't *implement* any `libc` functions, it's related to testing the `fmaf` function, which *is* a `libc` function. Therefore, the explanation should focus on the generic purpose and implementation considerations of `fmaf`. Key aspects to cover include:
    * Its mathematical operation.
    * Its advantage (accuracy and potential performance).
    * How it's typically implemented in hardware (if the target architecture supports it).
    * Fallback software implementations.

**6. Addressing Dynamic Linking:**

The provided code is *data*, not executable code. Therefore, it doesn't directly involve the dynamic linker. However, the *`fmaf` function itself* is part of `libc.so`, which *is* dynamically linked. The explanation should cover:
    * A typical `libc.so` layout.
    * The dynamic linking process in general (locating, loading, resolving symbols).
    * How the `fmaf` symbol would be resolved.

**7. Logic, Assumptions, and Input/Output:**

The code inherently represents logic: the expected output for given inputs. The assumption is that the first three floats are inputs to `fmaf` and the fourth is the expected output. Examples can be created by picking specific entries and stating the input and expected output.

**8. Common Usage Errors:**

Since this is test data, common usage errors relate to *using `fmaf` incorrectly* or *misinterpreting its behavior*. Examples include:
    * Assuming `(a * b) + c` is always equivalent due to floating-point precision issues.
    * Incorrectly handling edge cases like NaN, Infinity, or very small numbers.

**9. Android Framework/NDK Integration and Frida Hooking:**

This requires tracing how an Android application (either through the framework or NDK) might eventually execute the `fmaf` function that this data tests.
    * **Framework Example:**  A simple graphics operation involving matrix multiplication could lead to `fmaf` calls.
    * **NDK Example:**  A native library performing numerical computations using `fmaf`.
    * **Frida Hook:** Demonstrate how to intercept calls to `fmaf` and log its arguments and return value. This helps verify if the test data is relevant to real-world usage.

**10. Summarizing the Function (Part 6 of 7):**

The core function is providing test data for verifying the correctness of the `fmaf` function in bionic's math library. This data covers a wide range of input values, including normal numbers, edge cases (infinity, NaN, subnormal numbers, zero), and different sign combinations, ensuring robust testing.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Maybe this file contains different implementations of `fmaf` for different architectures. **Correction:** The directory name `intel_data` suggests it's specific test data for Intel-based architectures. The data itself is numerical, not code.
* **Focusing too much on the "how" of `fmaf`'s low-level implementation:**  While relevant, the primary focus should be on the *purpose* of the data file. The implementation details are secondary.
* **Overcomplicating the dynamic linking aspect:**  Keep it concise and focused on the concept of symbol resolution for `fmaf` within `libc.so`. Avoid getting bogged down in all the nuances of the dynamic linker unless specifically asked.

By following this structured thought process, addressing each point in the request systematically, and making necessary corrections along the way, a comprehensive and accurate answer can be generated.
好的，我们来归纳一下这个代码片段的功能。

**功能归纳：**

这段C代码定义了一个用于测试 `fmaf` 函数（浮点数的融合乘加运算）的大型测试数据集。这个数据集位于 Android Bionic 库的数学测试数据目录下，很明显它是为了验证 Bionic 库中 `fmaf` 函数的正确性而准备的。

**具体来说，这个代码片段的功能可以总结为：**

1. **提供 `fmaf` 函数的输入和预期输出值：**  代码中定义了一个匿名结构体数组，每个结构体包含四个 `float` 类型的成员。前三个成员很可能是 `fmaf` 函数的三个输入参数 (a, b, c)，而第四个成员则是使用这三个输入参数调用 `fmaf(a, b, c)` 后预期的正确返回值。

2. **覆盖多种浮点数场景：**  测试数据中包含了各种各样的浮点数值，包括：
    * **正常值：**  例如 `0x1.fffffdffffffffffffffffffffffffffp127`
    * **特殊值：**
        * `HUGE_VALF` (正无穷大)
        * `-HUGE_VALF` (负无穷大)
        * `0.0f` (正零)
        * `-0.0f` (负零)
        * 非常接近零的小数 (例如 `-0x1.p-149`)
        * 极大值和极小值
    * **不同的符号组合：**  测试了输入参数为正数、负数、正零、负零的各种组合。

3. **针对 Intel 架构进行测试：**  文件名 `fmaf_intel_data.handroid` 暗示了这个测试数据集是专门为 Intel 架构上的 `fmaf` 实现准备的。这可能是因为不同架构的浮点数运算可能存在细微差别，需要针对性地进行测试。

**与 Android 功能的关系举例：**

`fmaf` 函数是 C 标准库 `<math.h>` 中的函数，在 Android 中由 Bionic 库提供实现。 任何 Android 应用或系统服务，只要涉及到浮点数的乘法和加法运算，并且需要更高的精度或性能，都可能间接地使用到 `fmaf` 函数。

**举例说明：**

* **图形渲染：** 在进行 3D 图形变换时，经常需要进行矩阵运算，其中就包含大量的乘法和加法。使用 `fmaf` 可以提高计算精度，减少舍入误差，从而提升渲染质量。
* **音频处理：** 音频信号处理算法中，例如滤波、混响等，也会涉及到大量的浮点数运算。`fmaf` 可以提高这些算法的精度和效率。
* **科学计算类应用：**  Android 上的一些科学计算应用，例如物理模拟、数据分析等，对浮点数运算的精度要求很高，`fmaf` 可以提供帮助。

**详细解释 `libc` 函数的功能是如何实现的：**

`fmaf` 函数 (fused multiply-add float) 的功能是计算 `(x * y) + z`，并返回该结果。 关键在于 "fused" (融合)，这意味着乘法和加法运算是在一个单独的步骤中完成的，中间结果没有进行舍入。

**实现方式：**

* **硬件支持：** 现代 CPU，特别是 Intel 的 CPU，通常都提供了硬件级别的 `FMA` (Fused Multiply-Add) 指令。Bionic 库中的 `fmaf` 实现会尽可能利用这些硬件指令，以获得最高的性能和精度。
* **软件模拟：** 如果目标 CPU 没有硬件 FMA 指令，Bionic 库会提供一个软件模拟的实现。这种实现通常会使用更高精度的内部表示来模拟融合操作，以尽可能减少精度损失。

**对于涉及 dynamic linker 的功能：**

虽然这个数据文件本身不涉及动态链接，但 `fmaf` 函数的实现位于 `libc.so` 这个动态链接库中。

**`libc.so` 布局样本：**

一个简化的 `libc.so` 的布局可能如下所示：

```
libc.so:
    .text          # 代码段
        _start:     # 入口点
        ...
        fmaf:       # fmaf 函数的实现代码
        ...
        sinf:       # sinf 函数的实现代码
        ...
    .rodata        # 只读数据段
        ...
        一些字符串常量
        ...
    .data          # 可读写数据段
        ...
        全局变量
        ...
    .dynsym        # 动态符号表
        fmaf
        sinf
        ...
    .dynstr        # 动态字符串表
        fmaf
        sinf
        ...
    .rel.dyn      # 重定位表
        ...
```

**链接的处理过程：**

1. **加载 `libc.so`：** 当一个应用程序启动时，Android 的动态链接器 (linker，通常是 `linker` 或 `linker64`) 会负责加载应用程序依赖的动态链接库，包括 `libc.so`。

2. **查找符号：** 当应用程序调用 `fmaf` 函数时，编译器会生成对 `fmaf` 符号的引用。动态链接器会在 `libc.so` 的 `.dynsym` (动态符号表) 中查找名为 `fmaf` 的符号。

3. **解析地址：** 找到 `fmaf` 符号后，动态链接器会根据 `.rel.dyn` (重定位表) 中的信息，将应用程序中对 `fmaf` 的引用地址更新为 `libc.so` 中 `fmaf` 函数的实际地址。

4. **执行代码：** 一旦链接完成，应用程序就可以正确地调用 `libc.so` 中的 `fmaf` 函数了。

**逻辑推理、假设输入与输出：**

假设我们取代码片段中的一个 Entry：

```c
  { // Entry 1721
    HUGE_VALF,
    -0x1.p-149,
    0.0f,
    0.0f
  },
```

* **假设输入：**
    * 第一个参数 (a): `HUGE_VALF` (正无穷大)
    * 第二个参数 (b): `-0x1.p-149` (一个非常小的负数)
    * 第三个参数 (c): `0.0f` (正零)

* **逻辑推理：**
    * `a * b` 的结果是 `正无穷大 * 一个非常小的负数`，根据浮点数运算规则，结果应该是 `负无穷大`。
    * `(a * b) + c` 的结果是 `负无穷大 + 正零`，结果仍然是 `负无穷大`。

* **预期输出：**  根据 Entry 的定义，预期的输出是 `0.0f`。

**注意：** 这个例子揭示了测试数据可能覆盖了一些边界情况或特殊情况，在这些情况下，浮点数运算的结果可能不是直观想象的那样。例如，这里可能是在测试特定平台或 `fmaf` 实现对于无穷大和极小值的处理方式。

**用户或编程常见的使用错误：**

1. **精度误解：**  开发者可能认为 `fmaf(a, b, c)` 等价于 `(a * b) + c`，但实际上 `fmaf` 由于中间结果不舍入，通常具有更高的精度。如果开发者在对精度要求较高的场景下没有使用 `fmaf`，可能会导致累积误差。

2. **性能考虑不足：** 在某些情况下，使用 `fmaf` 可能比单独的乘法和加法运算更高效，特别是在支持硬件 FMA 指令的平台上。开发者可能没有意识到这一点，从而错失性能优化的机会。

3. **特殊值处理错误：**  在处理 NaN (非数值)、无穷大等特殊浮点数时，`fmaf` 的行为可能与其他运算有所不同。开发者如果没有充分理解这些特殊情况，可能会导致程序出现意外行为。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida Hook 示例调试这些步骤：**

**Android Framework 示例：**

假设一个使用 Canvas API 进行绘制的应用，其中涉及到矩阵变换：

1. **Java 代码调用 Framework API：**

   ```java
   Matrix matrix = new Matrix();
   matrix.scale(2.0f, 2.0f);
   matrix.postTranslate(10.0f, 20.0f);
   canvas.concat(matrix); // 将矩阵应用到 Canvas
   canvas.drawRect(0, 0, 100, 100, paint);
   ```

2. **Framework 层处理：** `canvas.concat(matrix)` 最终会调用到 Skia 图形库的 native 代码。

3. **Skia 库执行矩阵运算：** Skia 库在进行矩阵乘法等操作时，可能会使用到底层的浮点数运算，包括 `fmaf`。

4. **Bionic 库提供 `fmaf` 实现：**  当 Skia 库调用 `fmaf` 时，最终会链接到 Bionic 库 (`libc.so`) 中 `fmaf` 的实现。

**NDK 示例：**

一个使用 NDK 开发的 OpenGL ES 应用：

1. **Native 代码调用 OpenGL ES API：**

   ```c++
   // NDK 代码
   #include <GLES3/gl3.h>
   // ... 设置模型视图投影矩阵
   float matrix[16];
   // ... 计算矩阵的值，可能涉及到浮点数乘加
   glUniformMatrix4fv(location, 1, GL_FALSE, matrix);
   glDrawArrays(GL_TRIANGLES, 0, 3);
   ```

2. **OpenGL ES 驱动处理：** `glUniformMatrix4fv` 将矩阵数据传递给 OpenGL ES 驱动。

3. **驱动程序执行着色器代码：**  顶点着色器或片段着色器中可能包含大量的浮点数运算，例如矩阵向量乘法，这些运算在底层可能会利用 `fmaf` 来提高效率。

**Frida Hook 示例：**

可以使用 Frida Hook `fmaf` 函数来观察其调用情况：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

package_name = "你的应用包名"  # 替换成你要调试的应用包名

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 找不到应用: {package_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fmaf"), {
    onEnter: function(args) {
        send({
            "type": "fmaf_call",
            "a": args[0].toFloat(),
            "b": args[1].toFloat(),
            "c": args[2].toFloat()
        });
    },
    onLeave: function(retval) {
        send({
            "type": "fmaf_return",
            "result": retval.toFloat()
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 工作原理：**

1. **连接到目标应用：** Frida 通过 USB 连接到运行在 Android 设备上的目标应用。
2. **查找 `fmaf` 函数地址：** `Module.findExportByName("libc.so", "fmaf")`  在 `libc.so` 库中查找 `fmaf` 函数的导出地址。
3. **拦截函数调用：** `Interceptor.attach`  在 `fmaf` 函数的入口和出口处设置 Hook。
4. **`onEnter` 回调：** 当 `fmaf` 函数被调用时，`onEnter` 回调函数会被执行，它可以访问函数的参数 (`args`)。这里我们将三个参数的值以浮点数形式发送到 Frida 客户端。
5. **`onLeave` 回调：** 当 `fmaf` 函数执行完毕并即将返回时，`onLeave` 回调函数会被执行，它可以访问函数的返回值 (`retval`)。这里我们将返回值以浮点数形式发送到 Frida 客户端。
6. **客户端接收消息：** Python 脚本中的 `on_message` 函数接收来自 Frida Hook 的消息，并打印出来，从而可以观察 `fmaf` 函数的调用参数和返回值。

通过这样的 Frida Hook，你可以在应用运行时动态地观察 `fmaf` 函数的调用情况，验证是否与测试数据中的某些场景相符。

希望以上详细的解释能够帮助你理解这个代码片段的功能以及它在 Android 系统中的作用。

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
这是第6部分，共7部分，请归纳一下它的功能

"""
9,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 1722
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 1723
    HUGE_VALF,
    -0x1.p-149,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1724
    -HUGE_VALF,
    -0x1.p-149,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1725
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1726
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1727
    -0x1.fffffdffffffffffffffffffffp-22,
    -0x1.p-149,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1728
    -0x1.fffffe00000000000000000001p-22,
    -0x1.p-149,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1729
    -0x1.fffffdffffffffffffffffffff000002p-22,
    -0x1.p-149,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1730
    -0x1.fffffe00000000000000000000fffffep-22,
    -0x1.p-149,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1731
    -0x1.fffffdfffffffffffffffffffffffffep-22,
    -0x1.p-149,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1732
    -0x1.fffffe00000000000000000000000002p-22,
    -0x1.p-149,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1733
    -0x1.fffffep-22,
    -0x1.p-149,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1734
    -0x1.fffffep-22,
    -0x1.p-149,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1735
    HUGE_VALF,
    -0x1.p-149,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1736
    -HUGE_VALF,
    -0x1.p-149,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1737
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1738
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1739
    0x1.fffffe00000000000000000001p-22,
    -0x1.p-149,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1740
    0x1.fffffdffffffffffffffffffffp-22,
    -0x1.p-149,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1741
    0x1.fffffe00000000000000000000fffffep-22,
    -0x1.p-149,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1742
    0x1.fffffdffffffffffffffffffff000002p-22,
    -0x1.p-149,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1743
    0x1.fffffe00000000000000000000000002p-22,
    -0x1.p-149,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1744
    0x1.fffffdfffffffffffffffffffffffffep-22,
    -0x1.p-149,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1745
    0x1.fffffep-22,
    -0x1.p-149,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1746
    0x1.fffffep-22,
    -0x1.p-149,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1747
    HUGE_VALF,
    -0x1.p-149,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1748
    -HUGE_VALF,
    -0x1.p-149,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1749
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1750
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1751
    0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1752
    -0x1.p-126,
    -0x1.p-149,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1753
    0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1754
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1755
    0.0f,
    -0x1.p-149,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1756
    -0x1.00000000000000000000000000000004p-149,
    -0x1.p-149,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1757
    -0.0f,
    -0x1.p-149,
    0x1.p-126,
    0.0f
  },
  { // Entry 1758
    -0.0f,
    -0x1.p-149,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1759
    HUGE_VALF,
    -0x1.p-149,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1760
    -HUGE_VALF,
    -0x1.p-149,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1761
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1762
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1763
    0x1.p-126,
    -0x1.p-149,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1764
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1765
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1766
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1767
    0x1.00000000000000000000000000000004p-149,
    -0x1.p-149,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1768
    -0.0f,
    -0x1.p-149,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1769
    0.0f,
    -0x1.p-149,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1770
    0.0f,
    -0x1.p-149,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1771
    HUGE_VALF,
    -0x1.p-149,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1772
    -HUGE_VALF,
    -0x1.p-149,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1773
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1774
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1775
    0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1776
    -0x1.p-126,
    -0x1.p-149,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1777
    0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1778
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1779
    0.0f,
    -0x1.p-149,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1780
    -0x1.00000000000000000000000000000003p-149,
    -0x1.p-149,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1781
    -0.0f,
    -0x1.p-149,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1782
    -0.0f,
    -0x1.p-149,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1783
    HUGE_VALF,
    -0x1.p-149,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1784
    -HUGE_VALF,
    -0x1.p-149,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1785
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1786
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1787
    0x1.p-126,
    -0x1.p-149,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1788
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1789
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1790
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1791
    0x1.00000000000000000000000000000003p-149,
    -0x1.p-149,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1792
    -0.0f,
    -0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1793
    0.0f,
    -0x1.p-149,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1794
    0.0f,
    -0x1.p-149,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1795
    HUGE_VALF,
    -0x1.p-149,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1796
    -HUGE_VALF,
    -0x1.p-149,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1797
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1798
    -0x1.fffffep127,
    -0x1.p-149,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1799
    0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1800
    -0x1.p-126,
    -0x1.p-149,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1801
    0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1802
    -0x1.fffffcp-127,
    -0x1.p-149,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1803
    0.0f,
    -0x1.p-149,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1804
    -0x1.p-149,
    -0x1.p-149,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1805
    -0.0f,
    -0x1.p-149,
    0x1.p-149,
    0.0f
  },
  { // Entry 1806
    -0.0f,
    -0x1.p-149,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1807
    HUGE_VALF,
    -0x1.p-149,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1808
    -HUGE_VALF,
    -0x1.p-149,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1809
    0x1.fffffep127,
    -0x1.p-149,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1810
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1811
    0x1.p-126,
    -0x1.p-149,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1812
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1813
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1814
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-149,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1815
    0x1.p-149,
    -0x1.p-149,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1816
    -0.0f,
    -0x1.p-149,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1817
    0.0f,
    -0x1.p-149,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1818
    0.0f,
    -0x1.p-149,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1819
    HUGE_VALF,
    -0x1.p-149,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1820
    -HUGE_VALF,
    -0x1.p-149,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1821
    0x1.fffffep127,
    -0x1.p-149,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1822
    -0x1.fffffep127,
    -0x1.p-149,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1823
    0x1.p-126,
    -0x1.p-149,
    0.0f,
    0x1.p-126
  },
  { // Entry 1824
    -0x1.p-126,
    -0x1.p-149,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1825
    0x1.fffffcp-127,
    -0x1.p-149,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1826
    -0x1.fffffcp-127,
    -0x1.p-149,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1827
    0x1.p-149,
    -0x1.p-149,
    0.0f,
    0x1.p-149
  },
  { // Entry 1828
    -0x1.p-149,
    -0x1.p-149,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1829
    0.0,
    -0x1.p-149,
    0.0f,
    0.0f
  },
  { // Entry 1830
    -0.0,
    -0x1.p-149,
    0.0f,
    -0.0f
  },
  { // Entry 1831
    HUGE_VALF,
    -0x1.p-149,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1832
    -HUGE_VALF,
    -0x1.p-149,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1833
    0x1.fffffep127,
    -0x1.p-149,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1834
    -0x1.fffffep127,
    -0x1.p-149,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1835
    0x1.p-126,
    -0x1.p-149,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1836
    -0x1.p-126,
    -0x1.p-149,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1837
    0x1.fffffcp-127,
    -0x1.p-149,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1838
    -0x1.fffffcp-127,
    -0x1.p-149,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1839
    0x1.p-149,
    -0x1.p-149,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1840
    -0x1.p-149,
    -0x1.p-149,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1841
    0.0,
    -0x1.p-149,
    -0.0f,
    0.0f
  },
  { // Entry 1842
    0.0,
    -0x1.p-149,
    -0.0f,
    -0.0f
  },
  { // Entry 1843
    HUGE_VALF,
    0.0f,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1844
    -HUGE_VALF,
    0.0f,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1845
    0x1.fffffep127,
    0.0f,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1846
    -0x1.fffffep127,
    0.0f,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1847
    0x1.p-126,
    0.0f,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1848
    -0x1.p-126,
    0.0f,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1849
    0x1.fffffcp-127,
    0.0f,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1850
    -0x1.fffffcp-127,
    0.0f,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1851
    0x1.p-149,
    0.0f,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1852
    -0x1.p-149,
    0.0f,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1853
    0.0,
    0.0f,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1854
    0.0,
    0.0f,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1855
    HUGE_VALF,
    0.0f,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1856
    -HUGE_VALF,
    0.0f,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1857
    0x1.fffffep127,
    0.0f,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1858
    -0x1.fffffep127,
    0.0f,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1859
    0x1.p-126,
    0.0f,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1860
    -0x1.p-126,
    0.0f,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1861
    0x1.fffffcp-127,
    0.0f,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1862
    -0x1.fffffcp-127,
    0.0f,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1863
    0x1.p-149,
    0.0f,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1864
    -0x1.p-149,
    0.0f,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1865
    0.0,
    0.0f,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1866
    -0.0,
    0.0f,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1867
    HUGE_VALF,
    0.0f,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1868
    -HUGE_VALF,
    0.0f,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1869
    0x1.fffffep127,
    0.0f,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1870
    -0x1.fffffep127,
    0.0f,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1871
    0x1.p-126,
    0.0f,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1872
    -0x1.p-126,
    0.0f,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1873
    0x1.fffffcp-127,
    0.0f,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1874
    -0x1.fffffcp-127,
    0.0f,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1875
    0x1.p-149,
    0.0f,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1876
    -0x1.p-149,
    0.0f,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1877
    0.0,
    0.0f,
    0x1.p-126,
    0.0f
  },
  { // Entry 1878
    0.0,
    0.0f,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1879
    HUGE_VALF,
    0.0f,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1880
    -HUGE_VALF,
    0.0f,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1881
    0x1.fffffep127,
    0.0f,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1882
    -0x1.fffffep127,
    0.0f,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1883
    0x1.p-126,
    0.0f,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1884
    -0x1.p-126,
    0.0f,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1885
    0x1.fffffcp-127,
    0.0f,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1886
    -0x1.fffffcp-127,
    0.0f,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1887
    0x1.p-149,
    0.0f,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1888
    -0x1.p-149,
    0.0f,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1889
    0.0,
    0.0f,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1890
    -0.0,
    0.0f,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1891
    HUGE_VALF,
    0.0f,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1892
    -HUGE_VALF,
    0.0f,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1893
    0x1.fffffep127,
    0.0f,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1894
    -0x1.fffffep127,
    0.0f,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1895
    0x1.p-126,
    0.0f,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1896
    -0x1.p-126,
    0.0f,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1897
    0x1.fffffcp-127,
    0.0f,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1898
    -0x1.fffffcp-127,
    0.0f,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1899
    0x1.p-149,
    0.0f,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1900
    -0x1.p-149,
    0.0f,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1901
    0.0,
    0.0f,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1902
    0.0,
    0.0f,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1903
    HUGE_VALF,
    0.0f,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1904
    -HUGE_VALF,
    0.0f,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1905
    0x1.fffffep127,
    0.0f,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1906
    -0x1.fffffep127,
    0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1907
    0x1.p-126,
    0.0f,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1908
    -0x1.p-126,
    0.0f,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1909
    0x1.fffffcp-127,
    0.0f,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1910
    -0x1.fffffcp-127,
    0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1911
    0x1.p-149,
    0.0f,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1912
    -0x1.p-149,
    0.0f,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1913
    0.0,
    0.0f,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1914
    -0.0,
    0.0f,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1915
    HUGE_VALF,
    0.0f,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1916
    -HUGE_VALF,
    0.0f,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1917
    0x1.fffffep127,
    0.0f,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1918
    -0x1.fffffep127,
    0.0f,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1919
    0x1.p-126,
    0.0f,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1920
    -0x1.p-126,
    0.0f,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1921
    0x1.fffffcp-127,
    0.0f,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1922
    -0x1.fffffcp-127,
    0.0f,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1923
    0x1.p-149,
    0.0f,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1924
    -0x1.p-149,
    0.0f,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1925
    0.0,
    0.0f,
    0x1.p-149,
    0.0f
  },
  { // Entry 1926
    0.0,
    0.0f,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1927
    HUGE_VALF,
    0.0f,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1928
    -HUGE_VALF,
    0.0f,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1929
    0x1.fffffep127,
    0.0f,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1930
    -0x1.fffffep127,
    0.0f,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1931
    0x1.p-126,
    0.0f,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1932
    -0x1.p-126,
    0.0f,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1933
    0x1.fffffcp-127,
    0.0f,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1934
    -0x1.fffffcp-127,
    0.0f,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1935
    0x1.p-149,
    0.0f,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1936
    -0x1.p-149,
    0.0f,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1937
    0.0,
    0.0f,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1938
    -0.0,
    0.0f,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1939
    HUGE_VALF,
    0.0f,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1940
    -HUGE_VALF,
    0.0f,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1941
    0x1.fffffep127,
    0.0f,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1942
    -0x1.fffffep127,
    0.0f,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1943
    0x1.p-126,
    0.0f,
    0.0f,
    0x1.p-126
  },
  { // Entry 1944
    -0x1.p-126,
    0.0f,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1945
    0x1.fffffcp-127,
    0.0f,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1946
    -0x1.fffffcp-127,
    0.0f,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1947
    0x1.p-149,
    0.0f,
    0.0f,
    0x1.p-149
  },
  { // Entry 1948
    -0x1.p-149,
    0.0f,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1949
    0.0,
    0.0f,
    0.0f,
    0.0f
  },
  { // Entry 1950
    0.0,
    0.0f,
    0.0f,
    -0.0f
  },
  { // Entry 1951
    HUGE_VALF,
    0.0f,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1952
    -HUGE_VALF,
    0.0f,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1953
    0x1.fffffep127,
    0.0f,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1954
    -0x1.fffffep127,
    0.0f,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1955
    0x1.p-126,
    0.0f,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1956
    -0x1.p-126,
    0.0f,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1957
    0x1.fffffcp-127,
    0.0f,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1958
    -0x1.fffffcp-127,
    0.0f,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1959
    0x1.p-149,
    0.0f,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1960
    -0x1.p-149,
    0.0f,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1961
    0.0,
    0.0f,
    -0.0f,
    0.0f
  },
  { // Entry 1962
    -0.0,
    0.0f,
    -0.0f,
    -0.0f
  },
  { // Entry 1963
    HUGE_VALF,
    -0.0f,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1964
    -HUGE_VALF,
    -0.0f,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1965
    0x1.fffffep127,
    -0.0f,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1966
    -0x1.fffffep127,
    -0.0f,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1967
    0x1.p-126,
    -0.0f,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1968
    -0x1.p-126,
    -0.0f,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1969
    0x1.fffffcp-127,
    -0.0f,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1970
    -0x1.fffffcp-127,
    -0.0f,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1971
    0x1.p-149,
    -0.0f,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1972
    -0x1.p-149,
    -0.0f,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1973
    0.0,
    -0.0f,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1974
    -0.0,
    -0.0f,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1975
    HUGE_VALF,
    -0.0f,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1976
    -HUGE_VALF,
    -0.0f,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1977
    0x1.fffffep127,
    -0.0f,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1978
    -0x1.fffffep127,
    -0.0f,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1979
    0x1.p-126,
    -0.0f,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1980
    -0x1.p-126,
    -0.0f,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1981
    0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1982
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1983
    0x1.p-149,
    -0.0f,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1984
    -0x1.p-149,
    -0.0f,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1985
    0.0,
    -0.0f,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1986
    0.0,
    -0.0f,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1987
    HUGE_VALF,
    -0.0f,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1988
    -HUGE_VALF,
    -0.0f,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1989
    0x1.fffffep127,
    -0.0f,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1990
    -0x1.fffffep127,
    -0.0f,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1991
    0x1.p-126,
    -0.0f,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1992
    -0x1.p-126,
    -0.0f,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1993
    0x1.fffffcp-127,
    -0.0f,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1994
    -0x1.fffffcp-127,
    -0.0f,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1995
    0x1.p-149,
    -0.0f,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1996
    -0x1.p-149,
    -0.0f,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1997
    0.0,
    -0.0f,
    0x1.p-126,
    0.0f
  },
  { // Entry 1998
    -0.0,
    -0.0f,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1999
    HUGE_VALF,
    -0.0f,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 2000
    -HUGE_VALF,
    -0.0f,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 2001
    0x1.fffffep127,
    -0.0f,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 2002
    -0x1.fffffep127,
    -0.0f,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 2003
    0x1.p-126,
    -0.0f,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 2004
    -0x1.p-126,
    -0.0f,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 2005
    0x1.fffffcp-127,
    -0.0f,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 2006
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 2007
    0x1.p-149,
    -0.0f,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 2008
    -0x1.p-149,
    -0.0f,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 2009
    0.0,
    -0.0f,
    -0x1.p-126,
    0.0f
  },
  { // Entry 2010
    0.0,
    -0.0f,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 2011
    HUGE_VALF,
    -0.0f,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 2012
    -HUGE_VALF,
    -0.0f,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 2013
    0x1.fffffep127,
    -0.0f,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 2014
    -0x1.fffffep127,
    -0.0f,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 2015
    0x1.p-126,
    -0.0f,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 2016
    -0x1.p-126,
    -0.0f,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 2017
    0x1.fffffcp-127,
    -0.0f,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 2018
    -0x1.fffffcp-127,
    -0.0f,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 2019
    0x1.p-149,
    -0.0f,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 2020
    -0x1.p-149,
    -0.0f,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 2021
    0.0,
    -0.0f,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 2022
    -0.0,
    -0.0f,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 2023
    HUGE_VALF,
    -0.0f,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 2024
    -HUGE_VALF,
    -0.0f,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 2025
    0x1.fffffep127,
    -0.0f,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 2026
    -0x1.fffffep127,
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 2027
    0x1.p-126,
    -0.0f,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 2028
    -0x1.p-126,
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 2029
    0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 2030
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 2031
    0x1.p-149,
    -0.0f,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 2032
    -0x1.p-149,
    -0.0f,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 2033
    0.0,
    -0.0f,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 2034
    0.0,
    -0.0f,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 2035
    HUGE_VALF,
    -0.0f,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 2036
    -HUGE_VALF,
    -0.0f,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 2037
    0x1.fffffep127,
    -0.0f,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 2038
    -0x1.fffffep127,
    -0.0f,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 2039
    0x1.p-126,
    -0.0f,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 2040
    -0x1.p-126,
    -0.0f,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 2041
    0x1.fffffcp-127,
    -0.0f,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 2042
    -0x1.fffffcp-127,
    -0.0f,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 2043
    0x1.p-149,
    -0.0f,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 2044
    -0x1.p-149,
    -0.0f,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 2045
    0.0,
    -0.0f,
    0x1.p-149,
    0.0f
  },
  { // Entry 2046
    -0.0,
    -0.0f,
    0x1.p-149,
    -0.0f
  },
  { // Entry 2047
    HUGE_VALF,
    -0.0f,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 2048
    -HUGE_VALF,
    -0.0f,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 2049
    0x1.fffffep127,
    -0.0f,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 2050
    -0x1.fffffep127,
    -0.0f,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 2051
    0x1.p-126,
    -0.0f,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 2052
    -0x1.p-126,
    -0.0f,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 2053
    0x1.fffffcp-127,
    -0.0f,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 2054
    -0x1.fffffcp-127,
    -0.0f,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 2055
    0x1.p-149,
    -0.0f,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 2056
    -0x1.p-149,
    -0.0f,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 2057
    0.0,
    -0.0f,
    -0x1.p-149,
    0.0f
  },
  { // Entry 2058
    0.0,
    -0.0f,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 2059
    HUGE_VALF,
    -0.0f,
    0.0f,
    HUGE_VALF
  },
  { // Entry 2060
    -HUGE_VALF,
    -0.0f,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 2061
    0x1.fffffep127,
    -0.0f,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 2062
    -0x1.fffffep127,
    -0.0f,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 2063
    0x1.p-126,
    -0.0f,
    0.0f,
    0x1.p-126
  },
  { // Entry 2064
    -0x1.p-126,
    -0.0f,
    0.0f,
    -0x1.p-126
  },
  { // Entry 2065
    0x1.fffffcp-127,
    -0.0f,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 2066
    -0x1.fffffcp-127,
    -0.0f,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 2067
    0x1.p-149,
    -0.0f,
    0.0f,
    0x1.p-149
  },
  { // Entry 2068
    -0x1.p-149,
    -0.0f,
    0.0f,
    -0x1.p-149
  },
  { // Entry 2069
    0.0,
    -0.0f,
    0.0f,
    0.0f
  },
  { // Entry 2070
    -0.0,
    -0.0f,
    0.0f,
    -0.0f
  },
  { // Entry 2071
    HUGE_VALF,
    -0.0f,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 2072
    -HUGE_VALF,
    -0.0f,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 2073
    0x1.fffffep127,
    -0.0f,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 2074
    -0x1.fffffep127,
    -0.0f,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 2075
    0x1.p-126,
    -0.0f,
    -0.0f,
    0x1.p-126
  },
  { // Entry 2076
    -0x1.p-126,
    -0.0f,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 2077
    0x1.fffffcp-127,
    -0.0f,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 2078
    -0x1.fffffcp-127,
    -0.0f,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 2079
    0x1.p-149,
    -0.0f,
    -0.0f,
    0x1.p-149
  },
  { // Entry 2080
    -0x1.p-149,
    -0.0f,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 2081
    0.0,
    -0.0f,
    -0.0f,
    0.0f
  },
  { // Entry 2082
    0.0,
    -0.0f,
    -0.0f,
    -0.0f
  },
  { // Entry 2083
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 2084
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 2085
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 2086
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 2087
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 2088
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 2089
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 2090
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 2091
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 2092
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    0.0f
  },
  { // Entry 2093
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 2094
    -HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 2095
    -HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 2096
    -HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 2097
    -HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 2098
    -HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 2099
    -HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF,
    0x1.fffffcp-127
  }
"""


```
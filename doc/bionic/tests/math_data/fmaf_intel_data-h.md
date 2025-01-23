Response:
Let's break down the thought process for analyzing this C code snippet.

1. **Initial Understanding of the Context:** The prompt states this is part of Android's bionic library, specifically within the `tests/math_data` directory, and the file is named `fmaf_intel_data.handroid`. The "handroid" suffix suggests these are likely test data specifically tailored for Android's math library on architectures where Intel's fused multiply-add (FMA) instruction might be used or tested.

2. **Identify the Core Data Structure:** The code immediately presents a static array `g_fmaf_intel_data`. The type of this array is `data_1_3_t<float, float, float, float>`. This is a template instantiation, meaning `data_1_3_t` is likely a structure or class template defined elsewhere. The key here is to recognize that each element of the array holds *four* floating-point values.

3. **Infer the Purpose of the Data:**  Given the filename and the data structure, the most likely purpose is to provide input and expected output values for testing the `fmaf` function. `fmaf` stands for "fused multiply-add float," which calculates `a * b + c` with a single rounding operation. The four floats in each entry likely represent:
    * Input operand 1 (a)
    * Input operand 2 (b)
    * Input operand 3 (c)
    * Expected result of `fmaf(a, b, c)`

4. **Confirm the Inference (Mental Check):**  Scan a few entries. The first entry:
   ```c
   { // Entry 0
     -0x1.800002fffffffffffd80p73,
     -0x1.000002p72,
     0x1.80p1,
     0x1.40p2
   }
   ```
   The hexadecimal floating-point notation confirms these are indeed floating-point numbers. The structure suggests that the first three are inputs, and the last is the expected outcome of the FMA operation.

5. **Consider the "tests" directory context:** The file is in a `tests` directory. This reinforces the idea that the data is used for automated testing.

6. **Address the Specific Questions from the Prompt:** Now, go through each point in the request systematically:

   * **功能 (Functionality):**  The primary function is to provide test data for the `fmaf` function. This data includes input values and expected outputs.

   * **与 Android 功能的关系 (Relationship with Android functionality):** The `fmaf` function is a standard math function, and its correct implementation is crucial for many Android functionalities that rely on floating-point calculations. Examples include graphics rendering, physics simulations in games, and even calculations within system services.

   * **详细解释 libc 函数的功能是如何实现的 (Detailed explanation of libc function implementation):** This file *doesn't* contain the *implementation* of `fmaf`. It contains *test data* for it. It's important to distinguish between test data and the actual function code. The thought here is to explicitly state what the file *doesn't* do.

   * **涉及 dynamic linker 的功能 (Dynamic linker functionality):**  This file has nothing to do with the dynamic linker. It's pure data. Again, explicitly state the lack of connection.

   * **逻辑推理，假设输入与输出 (Logical reasoning, assumed input and output):** The structure of the data itself provides the "assumed input and output." The first three floats are the assumed inputs to `fmaf`, and the fourth is the assumed output. Give an example entry and map the values.

   * **用户或编程常见的使用错误 (Common user/programming errors):** This file itself doesn't cause user errors. However, *incorrectly generated* or *interpreted* test data could lead to false positives or negatives in tests. Thinking about the *purpose* of the file helps answer this.

   * **Android framework or ndk 如何到达这里 (How Android framework/NDK reaches here):**  This is related to the testing process. The Android build system would likely compile the tests, and during execution, these data files would be accessed to provide the test cases. For NDK, if a native developer uses `fmaf` from `<math.h>`, the underlying bionic implementation (which these tests verify) will be used. A simplified Frida hook example could show how to intercept calls to `fmaf` and potentially log the input values being tested.

7. **归纳功能 (Summarize functionality):** Combine the key points identified earlier. The file provides a set of test cases for the `fmaf` function in bionic.

8. **Structure and Language:** Organize the answers clearly, using Chinese as requested. Use bullet points or numbered lists to make the information easy to read. Maintain a neutral and informative tone.

Essentially, the process is: understand the context -> identify the core element -> infer its purpose -> confirm the inference -> address each specific question -> synthesize the findings. It's crucial to be precise about what the file *does* and *doesn't* do.
好的，让我们来归纳一下 `bionic/tests/math_data/fmaf_intel_data.handroid` 这个源代码文件的功能。

**功能归纳：**

这个 C 源代码文件定义了一个静态的全局数组 `g_fmaf_intel_data`，该数组包含了一系列用于测试 `fmaf` 函数的浮点数测试数据。

更具体地说，这个数组的每个元素都是一个结构体，该结构体包含了四个 `float` 类型的数值。根据代码中的注释和命名习惯，这四个浮点数很可能代表了 `fmaf` 函数的输入参数和预期的输出结果。

*   **前三个 `float` 值：** 很可能代表了 `fmaf` 函数的三个输入参数。`fmaf(a, b, c)` 函数计算的是 `(a * b) + c` 的值，并进行一次最终的舍入。
*   **最后一个 `float` 值：** 很可能代表了使用前三个输入参数调用 `fmaf` 函数后，预期得到的正确结果。

**总结来说，这个文件的主要功能是为 `fmaf` 函数提供了一组预定义的测试用例，用于验证 `fmaf` 函数在特定平台（这里暗示了是 Intel 架构的 Android 设备）上的实现是否正确。**

**与 Android 功能的关系举例说明：**

`fmaf` 函数是 C 标准库 `<math.h>` 中定义的一个数学函数，用于执行浮点数的融合乘加运算。在 Android 系统中，很多底层功能和上层应用都会依赖于精确的浮点数运算。

*   **图形渲染 (Graphics Rendering):**  Android 的图形系统 (例如 SurfaceFlinger) 和应用层的图形库 (例如 OpenGL ES) 在进行复杂的 3D 变换、光照计算等操作时，会大量使用浮点数运算。`fmaf` 可以提高这些运算的效率和精度。
*   **游戏开发 (Game Development):** 游戏中的物理引擎、动画系统、碰撞检测等模块都离不开浮点数运算。精确的 `fmaf` 实现可以保证游戏逻辑的正确性。
*   **科学计算和工程应用 (Scientific Computing and Engineering Applications):**  如果用户在 Android 设备上运行科学计算或工程相关的应用，这些应用很可能需要进行大量的浮点数运算。

**详细解释每一个 libc 函数的功能是如何实现的：**

**需要强调的是，这个文件 *本身并不包含任何 libc 函数的实现代码*。** 它仅仅是一个包含测试数据的静态数组。 `fmaf` 函数的实际实现代码位于 bionic 库的其他源文件中（通常是针对特定架构优化的汇编代码或 C 代码）。

因此，我们无法在这个文件中找到 `fmaf` 函数的实现细节。要了解 `fmaf` 的具体实现，需要查看 bionic 库中与数学函数相关的源代码文件。

**对于涉及 dynamic linker 的功能：**

这个文件与 dynamic linker (动态链接器) 的功能没有任何直接关系。它只是一个包含静态数据的 C 源文件，编译后数据会被嵌入到生成的库文件中。

**so 布局样本以及链接的处理过程（与此文件无关）：**

由于此文件不涉及 dynamic linker，我们无法提供与其相关的 so 布局样本和链接处理过程。不过，为了说明 dynamic linker 的一般工作方式，这里提供一个简化的例子：

假设我们有一个名为 `libexample.so` 的动态链接库，它依赖于 `libc.so`。

**`libexample.so` 的布局可能包含：**

*   **.text 段：** 包含可执行代码。
*   **.data 段：** 包含已初始化的全局变量和静态变量。
*   **.rodata 段：** 包含只读数据。
*   **.bss 段：** 包含未初始化的全局变量和静态变量。
*   **.dynsym 段：** 动态符号表，列出导出的和导入的符号（函数名、变量名等）。
*   **.dynstr 段：** 动态字符串表，存储符号名称的字符串。
*   **.plt 段：** 程序链接表 (Procedure Linkage Table)，用于延迟绑定导入的函数。
*   **.got 段：** 全局偏移表 (Global Offset Table)，用于存储全局变量的地址。
*   **.dynamic 段：** 包含描述动态链接信息的结构体，例如依赖的库、符号表位置等。

**链接的处理过程（简化）：**

1. **加载时：** 当 Android 系统加载包含 `libexample.so` 的应用程序时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会被激活。
2. **查找依赖：** dynamic linker 解析 `libexample.so` 的 `.dynamic` 段，找到其依赖的库（例如 `libc.so`）。
3. **加载依赖：** dynamic linker 尝试加载这些依赖库到内存中。
4. **符号解析 (Symbol Resolution)：**
    *   当 `libexample.so` 中调用了 `libc.so` 中定义的函数（例如 `fmaf`）时，编译器会生成一个 PLT 条目。
    *   第一次调用该函数时，会跳转到 PLT 条目，PLT 条目会跳转到 GOT 条目。
    *   GOT 条目最初包含的是 dynamic linker 的地址。
    *   dynamic linker 会根据 PLT 条目中的信息，在 `libc.so` 的动态符号表中查找 `fmaf` 函数的地址。
    *   找到地址后，dynamic linker 会更新 GOT 条目，使其指向 `fmaf` 函数的实际地址。
    *   后续对 `fmaf` 的调用会直接跳转到 GOT 条目中存储的 `fmaf` 地址，从而实现函数的调用。

**逻辑推理，假设输入与输出：**

虽然这个文件是测试数据，但我们可以根据其结构来理解它所代表的逻辑推理。 例如，对于第一个数据条目：

```c
{ // Entry 0
  -0x1.800002fffffffffffd80p73,
  -0x1.000002p72,
  0x1.80p1,
  0x1.40p2
}
```

**假设输入：**

*   参数 `a` (第一个 `float`)： `-0x1.800002fffffffffffd80p73` (这是一个十六进制浮点数表示法)
*   参数 `b` (第二个 `float`)： `-0x1.000002p72`
*   参数 `c` (第三个 `float`)： `0x1.80p1`

**预期输出：**

*   `fmaf(a, b, c)` 的预期结果 (第四个 `float`)： `0x1.40p2`

这个条目实际上是在断言：当使用上述 `a`、`b`、`c` 的值调用 `fmaf` 函数时，结果应该精确地等于 `0x1.40p2`。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

虽然这个文件本身不会导致用户错误，但与 `fmaf` 函数相关的常见使用错误包括：

1. **误解 `fmaf` 的作用：** 开发者可能不清楚 `fmaf` 执行的是 `(a * b) + c` 并只进行一次舍入，而不是先计算 `a * b` 舍入一次，再与 `c` 相加又舍入一次。这会导致精度上的差异。

    **错误示例：** 认为 `fmaf(a, b, c)` 等价于 `(float)((float)a * (float)b) + c;`  （这种写法会进行两次舍入）。

2. **不必要的 `fmaf` 使用：** 在某些情况下，直接使用乘法和加法可能就足够了，过度使用 `fmaf` 可能不会带来明显的性能提升，反而可能使代码可读性降低。

3. **精度问题：** 虽然 `fmaf` 提供了更高的精度，但在某些极端情况下，浮点数的精度仍然有限。开发者需要理解浮点数运算的特性，避免因精度损失导致错误。

4. **平台兼容性：** 早期的处理器可能不支持 FMA 指令，使用 `fmaf` 可能会导致性能下降或需要软件模拟。现代 Android 设备通常都支持 FMA 指令。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 开发使用 `fmaf`：**  假设一个 NDK 开发的应用程序需要在 Native 代码中使用 `fmaf` 函数进行高性能的浮点数运算。

    ```c++
    #include <cmath>
    #include <android/log.h>

    extern "C" JNIEXPORT jfloat JNICALL
    Java_com_example_myapp_MainActivity_calculateFMA(JNIEnv* env, jobject /* this */, jfloat a, jfloat b, jfloat c) {
        float result = fmaf(a, b, c);
        __android_log_print(ANDROID_LOG_DEBUG, "MyApp", "fmaf(%f, %f, %f) = %f", a, b, c, result);
        return result;
    }
    ```

2. **编译和链接：** 当 NDK 代码被编译时，编译器会识别 `fmaf` 函数，并将其链接到 Android 系统提供的 `libc.so` 动态链接库。

3. **运行时加载：** 当应用程序在 Android 设备上运行时，Android 的动态链接器会将 `libc.so` 加载到进程的内存空间。

4. **`fmaf` 调用：** 当 Native 代码执行到 `fmaf(a, b, c)` 时，实际上会调用 `libc.so` 中实现的 `fmaf` 函数。

5. **测试数据的作用：** 在 Android 系统或 bionic 库的开发和测试过程中，`bionic/tests/math_data/fmaf_intel_data.handroid` 文件中的数据会被用于编写自动化测试用例，以验证 `libc.so` 中 `fmaf` 函数在 Intel 架构上的实现是否符合标准，并且能够针对各种边界情况和特殊输入产生正确的输出。

**Frida Hook 示例：**

可以使用 Frida 来 Hook `fmaf` 函数的调用，观察其输入参数和返回值。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: The process '{package_name}' was not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fmaf"), {
    onEnter: function(args) {
        var a = args[0];
        var b = args[1];
        var c = args[2];
        send(`Called fmaf with a=${a}, b=${b}, c=${c}`);
    },
    onLeave: function(retval) {
        send(`fmaf returned ${retval}`);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
print("[*] Script loaded. Press Ctrl+C to detach.")
sys.stdin.read()
```

**工作原理：**

1. Frida 连接到目标 Android 应用程序的进程。
2. Frida 脚本使用 `Interceptor.attach` 函数 Hook 了 `libc.so` 中的 `fmaf` 函数。
3. `onEnter` 函数在 `fmaf` 函数被调用时执行，打印出传入的参数 `a`、`b` 和 `c` 的值。
4. `onLeave` 函数在 `fmaf` 函数执行完毕并返回时执行，打印出返回值。

通过运行这个 Frida 脚本，你可以实时观察到你的应用程序在调用 `fmaf` 函数时传递的参数，这可以帮助你理解数据是如何一步步到达 `fmaf` 函数的，并进行调试和分析。

这是对 `bionic/tests/math_data/fmaf_intel_data.handroid` 文件功能的归纳，以及它在 Android 系统中的相关性说明。后续部分将深入探讨更多细节。

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
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

static data_1_3_t<float, float, float, float> g_fmaf_intel_data[] = {
  { // Entry 0
    -0x1.800002fffffffffffd80p73,
    -0x1.000002p72,
    0x1.80p1,
    0x1.40p2
  },
  { // Entry 1
    -0x1.e66666p0,
    0x1.p-149,
    -0x1.ccccccp-1,
    -0x1.e66666p0
  },
  { // Entry 2
    0x1.15f153ffffffffffffffffffffffffffp-2,
    0x1.p-149,
    -0x1.ccccccp-1,
    0x1.15f154p-2
  },
  { // Entry 3
    0x1.000005fffffffffffffffffffff0ccccp-41,
    0x1.p-149,
    -0x1.e66666p-1,
    0x1.000006p-41
  },
  { // Entry 4
    -0x1.e66665ffffffffffffffffffffffffffp0,
    0x1.p-149,
    0x1.075070p-3,
    -0x1.e66666p0
  },
  { // Entry 5
    0x1.00000600000000000000000000014444p-41,
    0x1.p-149,
    0x1.444424p-4,
    0x1.000006p-41
  },
  { // Entry 6
    0x1.c9999906666680p0,
    0x1.000002p-3,
    -0x1.ccccccp-1,
    0x1.e66666p0
  },
  { // Entry 7
    0x1.880156fffffffffefbbcp14,
    0x1.0000e0p7,
    0x1.88p7,
    -0x1.0444p-50
  },
  { // Entry 8
    0x1.2b3335p-43,
    0x1.08p-41,
    -0x1.8df6b0p-1,
    0x1.18p-41
  },
  { // Entry 9
    0x1.9af704000001p-1,
    0x1.43969cp-3,
    0x1.62e42ep-1,
    0x1.62e42ep-1
  },
  { // Entry 10
    0x1.7eed9900000080p-1,
    0x1.43969cp-4,
    0x1.62e42ep-1,
    0x1.62e42ep-1
  },
  { // Entry 11
    -0x1.5229cafffffffffc6de498p59,
    0x1.88p60,
    -0x1.b9aec0p-2,
    0x1.c90db4p-4
  },
  { // Entry 12
    0x1.678c8dffffffb0p-1,
    0x1.ae0ef4p-7,
    0x1.62e42ep-1,
    0x1.62e42ep-1
  },
  { // Entry 13
    0x1.ffffee000010p-1,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 14
    0x1.fffff0000010p-1,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.p0
  },
  { // Entry 15
    0x1.fffff4000010p-1,
    0x1.fffffep127,
    -0x1.p-149,
    0x1.000002p0
  },
  { // Entry 16
    0x1.fffffep-1,
    0x1.fffffep127,
    0.0,
    0x1.fffffep-1
  },
  { // Entry 17
    0x1.p0,
    0x1.fffffep127,
    0.0,
    0x1.p0
  },
  { // Entry 18
    0x1.000002p0,
    0x1.fffffep127,
    0.0,
    0x1.000002p0
  },
  { // Entry 19
    0x1.000006fffff8p0,
    0x1.fffffep127,
    0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 20
    0x1.000007fffff8p0,
    0x1.fffffep127,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 21
    0x1.000009fffff8p0,
    0x1.fffffep127,
    0x1.p-149,
    0x1.000002p0
  },
  { // Entry 22
    0x1.ffffee000020p-2,
    0x1.fffffcp126,
    -0x1.p-149,
    0x1.fffffep-2
  },
  { // Entry 23
    0x1.fffff0000020p-2,
    0x1.fffffcp126,
    -0x1.p-149,
    0x1.p-1
  },
  { // Entry 24
    0x1.fffff4000020p-2,
    0x1.fffffcp126,
    -0x1.p-149,
    0x1.000002p-1
  },
  { // Entry 25
    0x1.fffffep-2,
    0x1.fffffcp126,
    0.0,
    0x1.fffffep-2
  },
  { // Entry 26
    0x1.p-1,
    0x1.fffffcp126,
    0.0,
    0x1.p-1
  },
  { // Entry 27
    0x1.000002p-1,
    0x1.fffffcp126,
    0.0,
    0x1.000002p-1
  },
  { // Entry 28
    0x1.000006fffff0p-1,
    0x1.fffffcp126,
    0x1.p-149,
    0x1.fffffep-2
  },
  { // Entry 29
    0x1.000007fffff0p-1,
    0x1.fffffcp126,
    0x1.p-149,
    0x1.p-1
  },
  { // Entry 30
    0x1.000009fffff0p-1,
    0x1.fffffcp126,
    0x1.p-149,
    0x1.000002p-1
  },
  { // Entry 31
    0x1.ffffee000010p-2,
    0x1.fffffep126,
    -0x1.p-149,
    0x1.fffffep-2
  },
  { // Entry 32
    0x1.fffff0000010p-2,
    0x1.fffffep126,
    -0x1.p-149,
    0x1.p-1
  },
  { // Entry 33
    0x1.fffff4000010p-2,
    0x1.fffffep126,
    -0x1.p-149,
    0x1.000002p-1
  },
  { // Entry 34
    0x1.fffffep-2,
    0x1.fffffep126,
    0.0,
    0x1.fffffep-2
  },
  { // Entry 35
    0x1.p-1,
    0x1.fffffep126,
    0.0,
    0x1.p-1
  },
  { // Entry 36
    0x1.000002p-1,
    0x1.fffffep126,
    0.0,
    0x1.000002p-1
  },
  { // Entry 37
    0x1.000006fffff8p-1,
    0x1.fffffep126,
    0x1.p-149,
    0x1.fffffep-2
  },
  { // Entry 38
    0x1.000007fffff8p-1,
    0x1.fffffep126,
    0x1.p-149,
    0x1.p-1
  },
  { // Entry 39
    0x1.000009fffff8p-1,
    0x1.fffffep126,
    0x1.p-149,
    0x1.000002p-1
  },
  { // Entry 40
    0x1.ffffeep-2,
    0x1.p127,
    -0x1.p-149,
    0x1.fffffep-2
  },
  { // Entry 41
    0x1.fffff0p-2,
    0x1.p127,
    -0x1.p-149,
    0x1.p-1
  },
  { // Entry 42
    0x1.fffff4p-2,
    0x1.p127,
    -0x1.p-149,
    0x1.000002p-1
  },
  { // Entry 43
    0x1.fffffep-2,
    0x1.p127,
    0.0,
    0x1.fffffep-2
  },
  { // Entry 44
    0x1.p-1,
    0x1.p127,
    0.0,
    0x1.p-1
  },
  { // Entry 45
    0x1.000002p-1,
    0x1.p127,
    0.0,
    0x1.000002p-1
  },
  { // Entry 46
    0x1.000007p-1,
    0x1.p127,
    0x1.p-149,
    0x1.fffffep-2
  },
  { // Entry 47
    0x1.000008p-1,
    0x1.p127,
    0x1.p-149,
    0x1.p-1
  },
  { // Entry 48
    0x1.00000ap-1,
    0x1.p127,
    0x1.p-149,
    0x1.000002p-1
  },
  { // Entry 49
    0x1.fffff6000010p-1,
    0x1.fffffcp126,
    -0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 50
    0x1.fffff8000010p-1,
    0x1.fffffcp126,
    -0x1.p-149,
    0x1.p0
  },
  { // Entry 51
    0x1.fffffc000010p-1,
    0x1.fffffcp126,
    -0x1.p-149,
    0x1.000002p0
  },
  { // Entry 52
    0x1.fffffep-1,
    0x1.fffffcp126,
    0.0,
    0x1.fffffep-1
  },
  { // Entry 53
    0x1.p0,
    0x1.fffffcp126,
    0.0,
    0x1.p0
  },
  { // Entry 54
    0x1.000002p0,
    0x1.fffffcp126,
    0.0,
    0x1.000002p0
  },
  { // Entry 55
    0x1.000002fffff8p0,
    0x1.fffffcp126,
    0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 56
    0x1.000003fffff8p0,
    0x1.fffffcp126,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 57
    0x1.000005fffff8p0,
    0x1.fffffcp126,
    0x1.p-149,
    0x1.000002p0
  },
  { // Entry 58
    0x1.fffff6000008p-1,
    0x1.fffffep126,
    -0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 59
    0x1.fffff8000008p-1,
    0x1.fffffep126,
    -0x1.p-149,
    0x1.p0
  },
  { // Entry 60
    0x1.fffffc000008p-1,
    0x1.fffffep126,
    -0x1.p-149,
    0x1.000002p0
  },
  { // Entry 61
    0x1.fffffep-1,
    0x1.fffffep126,
    0.0,
    0x1.fffffep-1
  },
  { // Entry 62
    0x1.p0,
    0x1.fffffep126,
    0.0,
    0x1.p0
  },
  { // Entry 63
    0x1.000002p0,
    0x1.fffffep126,
    0.0,
    0x1.000002p0
  },
  { // Entry 64
    0x1.000002fffffcp0,
    0x1.fffffep126,
    0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 65
    0x1.000003fffffcp0,
    0x1.fffffep126,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 66
    0x1.000005fffffcp0,
    0x1.fffffep126,
    0x1.p-149,
    0x1.000002p0
  },
  { // Entry 67
    0x1.fffff6p-1,
    0x1.p127,
    -0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 68
    0x1.fffff8p-1,
    0x1.p127,
    -0x1.p-149,
    0x1.p0
  },
  { // Entry 69
    0x1.fffffcp-1,
    0x1.p127,
    -0x1.p-149,
    0x1.000002p0
  },
  { // Entry 70
    0x1.fffffep-1,
    0x1.p127,
    0.0,
    0x1.fffffep-1
  },
  { // Entry 71
    0x1.p0,
    0x1.p127,
    0.0,
    0x1.p0
  },
  { // Entry 72
    0x1.000002p0,
    0x1.p127,
    0.0,
    0x1.000002p0
  },
  { // Entry 73
    0x1.000003p0,
    0x1.p127,
    0x1.p-149,
    0x1.fffffep-1
  },
  { // Entry 74
    0x1.000004p0,
    0x1.p127,
    0x1.p-149,
    0x1.p0
  },
  { // Entry 75
    0x1.000006p0,
    0x1.p127,
    0x1.p-149,
    0x1.000002p0
  },
  { // Entry 76
    0x1.fffffc000001ffffffffffffffffffffp-2,
    0x1.fffffep-2,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 77
    0x1.fffffc000002p-2,
    0x1.fffffep-2,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 78
    0x1.fffffc000002p-2,
    0x1.fffffep-2,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 79
    0x1.fffffdffffffffffffffffffffffffffp-2,
    0x1.fffffep-2,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 80
    0x1.fffffep-2,
    0x1.fffffep-2,
    0x1.p0,
    0.0
  },
  { // Entry 81
    0x1.fffffep-2,
    0x1.fffffep-2,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 82
    0x1.000000fffffdffffffffffffffffffffp-1,
    0x1.fffffep-2,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 83
    0x1.000000fffffep-1,
    0x1.fffffep-2,
    0x1.000002p0,
    0.0
  },
  { // Entry 84
    0x1.000000fffffep-1,
    0x1.fffffep-2,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 85
    0x1.fffffdffffffffffffffffffffffffffp-2,
    0x1.p-1,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 86
    0x1.fffffep-2,
    0x1.p-1,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 87
    0x1.fffffep-2,
    0x1.p-1,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 88
    0x1.ffffffffffffffffffffffffffffffffp-2,
    0x1.p-1,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 89
    0x1.p-1,
    0x1.p-1,
    0x1.p0,
    0.0
  },
  { // Entry 90
    0x1.p-1,
    0x1.p-1,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 91
    0x1.000001ffffffffffffffffffffffffffp-1,
    0x1.p-1,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 92
    0x1.000002p-1,
    0x1.p-1,
    0x1.000002p0,
    0.0
  },
  { // Entry 93
    0x1.000002p-1,
    0x1.p-1,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 94
    0x1.000000fffffdffffffffffffffffffffp-1,
    0x1.000002p-1,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 95
    0x1.000000fffffep-1,
    0x1.000002p-1,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 96
    0x1.000000fffffep-1,
    0x1.000002p-1,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 97
    0x1.000001ffffffffffffffffffffffffffp-1,
    0x1.000002p-1,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 98
    0x1.000002p-1,
    0x1.000002p-1,
    0x1.p0,
    0.0
  },
  { // Entry 99
    0x1.000002p-1,
    0x1.000002p-1,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 100
    0x1.000004000003ffffffffffffffffffffp-1,
    0x1.000002p-1,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 101
    0x1.000004000004p-1,
    0x1.000002p-1,
    0x1.000002p0,
    0.0
  },
  { // Entry 102
    0x1.000004000004p-1,
    0x1.000002p-1,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 103
    0x1.000001fffffdp-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.fffffep-24
  },
  { // Entry 104
    0x1.000002000001p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.p-23
  },
  { // Entry 105
    0x1.000002000009p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.000002p-23
  },
  { // Entry 106
    0x1.000002fffffcp-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.fffffep-24
  },
  { // Entry 107
    0x1.000003p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.p-23
  },
  { // Entry 108
    0x1.000003000008p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.000002p-23
  },
  { // Entry 109
    0x1.000004fffffap-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.fffffep-24
  },
  { // Entry 110
    0x1.000004fffffep-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.p-23
  },
  { // Entry 111
    0x1.000005000006p-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.000002p-23
  },
  { // Entry 112
    0x1.000002fffffcp-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.fffffep-24
  },
  { // Entry 113
    0x1.000003p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.p-23
  },
  { // Entry 114
    0x1.000003000008p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.000002p-23
  },
  { // Entry 115
    0x1.000003fffffcp-1,
    0x1.p0,
    0x1.p-1,
    0x1.fffffep-24
  },
  { // Entry 116
    0x1.000004p-1,
    0x1.p0,
    0x1.p-1,
    0x1.p-23
  },
  { // Entry 117
    0x1.000004000008p-1,
    0x1.p0,
    0x1.p-1,
    0x1.000002p-23
  },
  { // Entry 118
    0x1.000005fffffcp-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.fffffep-24
  },
  { // Entry 119
    0x1.000006p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.p-23
  },
  { // Entry 120
    0x1.000006000008p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.000002p-23
  },
  { // Entry 121
    0x1.000004fffffap-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.fffffep-24
  },
  { // Entry 122
    0x1.000004fffffep-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.p-23
  },
  { // Entry 123
    0x1.000005000006p-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.000002p-23
  },
  { // Entry 124
    0x1.000005fffffcp-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.fffffep-24
  },
  { // Entry 125
    0x1.000006p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.p-23
  },
  { // Entry 126
    0x1.000006000008p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.000002p-23
  },
  { // Entry 127
    0x1.000008p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.fffffep-24
  },
  { // Entry 128
    0x1.000008000004p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.p-23
  },
  { // Entry 129
    0x1.00000800000cp-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.000002p-23
  },
  { // Entry 130
    0x1.000001fffffdp-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.fffffep-24
  },
  { // Entry 131
    0x1.000002000001p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.p-23
  },
  { // Entry 132
    0x1.000002000009p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.000002p-23
  },
  { // Entry 133
    0x1.000002fffffcp-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.fffffep-24
  },
  { // Entry 134
    0x1.000003p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.p-23
  },
  { // Entry 135
    0x1.000003000008p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.000002p-23
  },
  { // Entry 136
    0x1.000004fffffap-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.fffffep-24
  },
  { // Entry 137
    0x1.000004fffffep-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.p-23
  },
  { // Entry 138
    0x1.000005000006p-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.000002p-23
  },
  { // Entry 139
    0x1.000002fffffcp-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.fffffep-24
  },
  { // Entry 140
    0x1.000003p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.p-23
  },
  { // Entry 141
    0x1.000003000008p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.000002p-23
  },
  { // Entry 142
    0x1.000003fffffcp-1,
    0x1.p0,
    0x1.p-1,
    0x1.fffffep-24
  },
  { // Entry 143
    0x1.000004p-1,
    0x1.p0,
    0x1.p-1,
    0x1.p-23
  },
  { // Entry 144
    0x1.000004000008p-1,
    0x1.p0,
    0x1.p-1,
    0x1.000002p-23
  },
  { // Entry 145
    0x1.000005fffffcp-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.fffffep-24
  },
  { // Entry 146
    0x1.000006p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.p-23
  },
  { // Entry 147
    0x1.000006000008p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.000002p-23
  },
  { // Entry 148
    0x1.000004fffffap-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.fffffep-24
  },
  { // Entry 149
    0x1.000004fffffep-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.p-23
  },
  { // Entry 150
    0x1.000005000006p-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.000002p-23
  },
  { // Entry 151
    0x1.000005fffffcp-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.fffffep-24
  },
  { // Entry 152
    0x1.000006p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.p-23
  },
  { // Entry 153
    0x1.000006000008p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.000002p-23
  },
  { // Entry 154
    0x1.000008p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.fffffep-24
  },
  { // Entry 155
    0x1.000008000004p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.p-23
  },
  { // Entry 156
    0x1.00000800000cp-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.000002p-23
  },
  { // Entry 157
    0x1.00000dfffff1p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.fffffep-22
  },
  { // Entry 158
    0x1.00000e000001p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.p-21
  },
  { // Entry 159
    0x1.00000e000021p-1,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.000002p-21
  },
  { // Entry 160
    0x1.00000efffff0p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.fffffep-22
  },
  { // Entry 161
    0x1.00000fp-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.p-21
  },
  { // Entry 162
    0x1.00000f000020p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.000002p-21
  },
  { // Entry 163
    0x1.000010ffffeep-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.fffffep-22
  },
  { // Entry 164
    0x1.000010fffffep-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.p-21
  },
  { // Entry 165
    0x1.00001100001ep-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.000002p-21
  },
  { // Entry 166
    0x1.00000efffff0p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.fffffep-22
  },
  { // Entry 167
    0x1.00000fp-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.p-21
  },
  { // Entry 168
    0x1.00000f000020p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.000002p-21
  },
  { // Entry 169
    0x1.00000ffffff0p-1,
    0x1.p0,
    0x1.p-1,
    0x1.fffffep-22
  },
  { // Entry 170
    0x1.000010p-1,
    0x1.p0,
    0x1.p-1,
    0x1.p-21
  },
  { // Entry 171
    0x1.000010000020p-1,
    0x1.p0,
    0x1.p-1,
    0x1.000002p-21
  },
  { // Entry 172
    0x1.000011fffff0p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.fffffep-22
  },
  { // Entry 173
    0x1.000012p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.p-21
  },
  { // Entry 174
    0x1.000012000020p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.000002p-21
  },
  { // Entry 175
    0x1.000010ffffeep-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.fffffep-22
  },
  { // Entry 176
    0x1.000010fffffep-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.p-21
  },
  { // Entry 177
    0x1.00001100001ep-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.000002p-21
  },
  { // Entry 178
    0x1.000011fffff0p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.fffffep-22
  },
  { // Entry 179
    0x1.000012p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.p-21
  },
  { // Entry 180
    0x1.000012000020p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.000002p-21
  },
  { // Entry 181
    0x1.000013fffff4p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.fffffep-22
  },
  { // Entry 182
    0x1.000014000004p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.p-21
  },
  { // Entry 183
    0x1.000014000024p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.000002p-21
  },
  { // Entry 184
    0x1.fffffep-2,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.fffffep-26
  },
  { // Entry 185
    0x1.fffffe000002p-2,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.p-25
  },
  { // Entry 186
    0x1.fffffe000006p-2,
    0x1.fffffep-1,
    0x1.fffffep-2,
    0x1.000002p-25
  },
  { // Entry 187
    0x1.fffffffffffep-2,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.fffffep-26
  },
  { // Entry 188
    0x1.p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.p-25
  },
  { // Entry 189
    0x1.000000000002p-1,
    0x1.fffffep-1,
    0x1.p-1,
    0x1.000002p-25
  },
  { // Entry 190
    0x1.000001fffffdp-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.fffffep-26
  },
  { // Entry 191
    0x1.000001fffffep-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.p-25
  },
  { // Entry 192
    0x1.000002p-1,
    0x1.fffffep-1,
    0x1.000002p-1,
    0x1.000002p-25
  },
  { // Entry 193
    0x1.fffffffffffep-2,
    0x1.p0,
    0x1.fffffep-2,
    0x1.fffffep-26
  },
  { // Entry 194
    0x1.p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.p-25
  },
  { // Entry 195
    0x1.000000000002p-1,
    0x1.p0,
    0x1.fffffep-2,
    0x1.000002p-25
  },
  { // Entry 196
    0x1.000000ffffffp-1,
    0x1.p0,
    0x1.p-1,
    0x1.fffffep-26
  },
  { // Entry 197
    0x1.000001p-1,
    0x1.p0,
    0x1.p-1,
    0x1.p-25
  },
  { // Entry 198
    0x1.000001000002p-1,
    0x1.p0,
    0x1.p-1,
    0x1.000002p-25
  },
  { // Entry 199
    0x1.000002ffffffp-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.fffffep-26
  },
  { // Entry 200
    0x1.000003p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.p-25
  },
  { // Entry 201
    0x1.000003000002p-1,
    0x1.p0,
    0x1.000002p-1,
    0x1.000002p-25
  },
  { // Entry 202
    0x1.000001fffffdp-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.fffffep-26
  },
  { // Entry 203
    0x1.000001fffffep-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.p-25
  },
  { // Entry 204
    0x1.000002p-1,
    0x1.000002p0,
    0x1.fffffep-2,
    0x1.000002p-25
  },
  { // Entry 205
    0x1.000002ffffffp-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.fffffep-26
  },
  { // Entry 206
    0x1.000003p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.p-25
  },
  { // Entry 207
    0x1.000003000002p-1,
    0x1.000002p0,
    0x1.p-1,
    0x1.000002p-25
  },
  { // Entry 208
    0x1.000005000003p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.fffffep-26
  },
  { // Entry 209
    0x1.000005000004p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.p-25
  },
  { // Entry 210
    0x1.000005000006p-1,
    0x1.000002p0,
    0x1.000002p-1,
    0x1.000002p-25
  },
  { // Entry 211
    0x1.fffffc000001ffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 212
    0x1.fffffc000002p127,
    0x1.fffffep127,
    0x1.fffffep-1,
    0.0
  },
  { // Entry 213
    0x1.fffffc000002p127,
    0x1.fffffep127,
    0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 214
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.p0,
    -0x1.p-149
  },
  { // Entry 215
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.p0,
    0.0
  },
  { // Entry 216
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.p0,
    0x1.p-149
  },
  { // Entry 217
    HUGE_VALF,
    0x1.fffffep127,
    0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 218
    HUGE_VALF,
    0x1.fffffep127,
    0x1.000002p0,
    0.0
  },
  { // Entry 219
    HUGE_VALF,
    0x1.fffffep127,
    0x1.000002p0,
    0x1.p-149
  },
  { // Entry 220
    -0x1.fffffep103,
    0x1.fffffep127,
    0x1.fffffep-1,
    -0x1.fffffep127
  },
  { // Entry 221
    0.0,
    0x1.fffffep127,
    0x1.p0,
    -0x1.fffffep127
  },
  { // Entry 222
    0x1.fffffep104,
    0x1.fffffep127,
    0x1.000002p0,
    -0x1.fffffep127
  },
  { // Entry 223
    0x1.fffffa000003ffffffffffffffffffffp127,
    0x1.fffffep63,
    0x1.fffffcp63,
    -0x1.p-149
  },
  { // Entry 224
    0x1.fffffa000004p127,
    0x1.fffffep63,
    0x1.fffffcp63,
    0.0
  },
  { // Entry 225
    0x1.fffffa000004p127,
    0x1.fffffep63,
    0x1.fffffcp63,
    0x1.p-149
  },
  { // Entry 226
    0x1.fffffc000001ffffffffffffffffffffp127,
    0x1.fffffep63,
    0x1.fffffep63,
    -0x1.p-149
  },
  { // Entry 227
    0x1.fffffc000002p127,
    0x1.fffffep63,
    0x1.fffffep63,
    0.0
  },
  { // Entry 228
    0x1.fffffc000002p127,
    0x1.fffffep63,
    0x1.fffffep63,
    0x1.p-149
  },
  { // Entry 229
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep63,
    0x1.p64,
    -0x1.p-149
  },
  { // Entry 230
    0x1.fffffep127,
    0x1.fffffep63,
    0x1.p64,
    0.0
  },
  { // Entry 231
    0x1.fffffep127,
    0x1.fffffep63,
    0x1.p64,
    0x1.p-149
  },
  { // Entry 232
    -0x1.7ffffep105,
    0x1.fffffcp63,
    0x1.fffffcp63,
    -0x1.fffffep127
  },
  { // Entry 233
    -0x1.fffffep104,
    0x1.fffffcp63,
    0x1.fffffep63,
    -0x1.fffffep127
  },
  { // Entry 234
    -0x1.p104,
    0x1.fffffcp63,
    0x1.p64,
    -0x1.fffffep127
  },
  { // Entry 235
    -0x1.fffffep104,
    0x1.fffffep63,
    0x1.fffffcp63,
    -0x1.fffffep127
  },
  { // Entry 236
    -0x1.fffffep103,
    0x1.fffffep63,
    0x1.fffffep63,
    -0x1.fffffep127
  },
  { // Entry 237
    0.0,
    0x1.fffffep63,
    0x1.p64,
    -0x1.fffffep127
  },
  { // Entry 238
    -0x1.p104,
    0x1.p64,
    0x1.fffffcp63,
    -0x1.fffffep127
  },
  { // Entry 239
    0.0,
    0x1.p64,
    0x1.fffffep63,
    -0x1.fffffep127
  },
  { // Entry 240
    0x1.p104,
    0x1.p64,
    0x1.p64,
    -0x1.fffffep127
  },
  { // Entry 241
    -0x1.fffff8p103,
    0x1.fffffcp126,
    -0x1.000002p1,
    0x1.fffffep127
  },
  { // Entry 242
    0x1.p104,
    0x1.fffffcp126,
    -0x1.p1,
    0x1.fffffep127
  },
  { // Entry 243
    0x1.fffffep104,
    0x1.fffffcp126,
    -0x1.fffffep0,
    0x1.fffffep127
  },
  { // Entry 244
    -0x1.fffffep104,
    0x1.fffffep126,
    -0x1.000002p1,
    0x1.fffffep127
  },
  { // Entry 245
    0.0,
    0x1.fffffep126,
    -0x1.p1,
    0x1.fffffep127
  },
  { // Entry 246
    0x1.fffffep103,
    0x1.fffffep126,
    -0x1.fffffep0,
    0x1.fffffep127
  },
  { // Entry 247
    -0x1.80p105,
    0x1.p127,
    -0x1.000002p1,
    0x1.fffffep127
  },
  { // Entry 248
    -0x1.p104,
    0x1.p127,
    -0x1.p1,
    0x1.fffffep127
  },
  { // Entry 249
    0.0,
    0x1.p127,
    -0x1.fffffep0,
    0x1.fffffep127
  },
  { // Entry 250
    -HUGE_VALF,
    0x1.fffffcp126,
    -0x1.000002p1,
    -0x1.p-149
  },
  { // Entry 251
    -HUGE_VALF,
    0x1.fffffcp126,
    -0x1.000002p1,
    0.0
  },
  { // Entry 252
    -HUGE_VALF,
    0x1.fffffcp126,
    -0x1.000002p1,
    0x1.p-149
  },
  { // Entry 253
    -0x1.fffffcp127,
    0x1.fffffcp126,
    -0x1.p1,
    -0x1.p-149
  },
  { // Entry 254
    -0x1.fffffcp127,
    0x1.fffffcp126,
    -0x1.p1,
    0.0
  },
  { // Entry 255
    -0x1.fffffbffffffffffffffffffffffffffp127,
    0x1.fffffcp126,
    -0x1.p1,
    0x1.p-149
  },
  { // Entry 256
    -0x1.fffffa000004p127,
    0x1.fffffcp126,
    -0x1.fffffep0,
    -0x1.p-149
  },
  { // Entry 257
    -0x1.fffffa000004p127,
    0x1.fffffcp126,
    -0x1.fffffep0,
    0.0
  },
  { // Entry 258
    -0x1.fffffa000003ffffffffffffffffffffp127,
    0x1.fffffcp126,
    -0x1.fffffep0,
    0x1.p-149
  },
  { // Entry 259
    -HUGE_VALF,
    0x1.fffffep126,
    -0x1.000002p1,
    -0x1.p-149
  },
  { // Entry 260
    -HUGE_VALF,
    0x1.fffffep126,
    -0x1.000002p1,
    0.0
  },
  { // Entry 261
    -HUGE_VALF,
    0x1.fffffep126,
    -0x1.000002p1,
    0x1.p-149
  },
  { // Entry 262
    -0x1.fffffep127,
    0x1.fffffep126,
    -0x1.p1,
    -0x1.p-149
  },
  { // Entry 263
    -0x1.fffffep127,
    0x1.fffffep126,
    -0x1.p1,
    0.0
  },
  { // Entry 264
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep126,
    -0x1.p1,
    0x1.p-149
  },
  { // Entry 265
    -0x1.fffffc000002p127,
    0x1.fffffep126,
    -0x1.fffffep0,
    -0x1.p-149
  },
  { // Entry 266
    -0x1.fffffc000002p127,
    0x1.fffffep126,
    -0x1.fffffep0,
    0.0
  },
  { // Entry 267
    -0x1.fffffc000001ffffffffffffffffffffp127,
    0x1.fffffep126,
    -0x1.fffffep0,
    0x1.p-149
  },
  { // Entry 268
    -HUGE_VALF,
    0x1.p127,
    -0x1.000002p1,
    -0x1.p-149
  },
  { // Entry 269
    -HUGE_VALF,
    0x1.p127,
    -0x1.000002p1,
    0.0
  },
  { // Entry 270
    -HUGE_VALF,
    0x1.p127,
    -0x1.000002p1,
    0x1.p-149
  },
  { // Entry 271
    -HUGE_VALF,
    0x1.p127,
    -0x1.p1,
    -0x1.p-149
  },
  { // Entry 272
    -HUGE_VALF,
    0x1.p127,
    -0x1.p1,
    0.0
  },
  { // Entry 273
    -HUGE_VALF,
    0x1.p127,
    -0x1.p1,
    0x1.p-149
  },
  { // Entry 274
    -0x1.fffffep127,
    0x1.p127,
    -0x1.fffffep0,
    -0x1.p-149
  },
  { // Entry 275
    -0x1.fffffep127,
    0x1.p127,
    -0x1.fffffep0,
    0.0
  },
  { // Entry 276
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p127,
    -0x1.fffffep0,
    0x1.p-149
  },
  { // Entry 277
    0x1.7ffffc800001p127,
    0x1.fffffcp126,
    0x1.fffffep-2,
    0x1.fffffcp126
  },
  { // Entry 278
    0x1.7ffffd800001p127,
    0x1.fffffcp126,
    0x1.fffffep-2,
    0x1.fffffep126
  },
  { // Entry 279
    0x1.7ffffe800001p127,
    0x1.fffffcp126,
    0x1.fffffep-2,
    0x1.p127
  },
  { // Entry 280
    0x1.7ffffdp127,
    0x1.fffffcp126,
    0x1.p-1,
    0x1.fffffcp126
  },
  { // Entry 281
    0x1.7ffffep127,
    0x1.fffffcp126,
    0x1.p-1,
    0x1.fffffep126
  },
  { // Entry 282
    0x1.7fffffp127,
    0x1.fffffcp126,
    0x1.p-1,
    0x1.p127
  },
  { // Entry 283
    0x1.7ffffdfffffep127,
    0x1.fffffcp126,
    0x1.000002p-1,
    0x1.fffffcp126
  },
  { // Entry 284
    0x1.7ffffefffffep127,
    0x1.fffffcp126,
    0x1.000002p-1,
    0x1.fffffep126
  },
  { // Entry 285
    0x1.7ffffffffffep127,
    0x1.fffffcp126,
    0x1.000002p-1,
    0x1.p127
  },
  { // Entry 286
    0x1.7ffffd00000080p127,
    0x1.fffffep126,
    0x1.fffffep-2,
    0x1.fffffcp126
  },
  { // Entry 287
    0x1.7ffffe00000080p127,
    0x1.fffffep126,
    0x1.fffffep-2,
    0x1.fffffep126
  },
  { // Entry 288
    0x1.7fffff00000080p127,
    0x1.fffffep126,
    0x1.fffffep-2,
    0x1.p127
  },
  { // Entry 289
    0x1.7ffffd80p127,
    0x1.fffffep126,
    0x1.p-1,
    0x1.fffffcp126
  },
  { // Entry 290
    0x1.7ffffe80p127,
    0x1.fffffep126,
    0x1.p-1,
    0x1.fffffep126
  },
  { // Entry 291
    0x1.7fffff80p127,
    0x1.fffffep126,
    0x1.p-1,
    0x1.p127
  },
  { // Entry 292
    0x1.7ffffe7fffffp127,
    0x1.fffffep126,
    0x1.000002p-1,
    0x1.fffffcp126
  },
  { // Entry 293
    0x1.7fffff7fffffp127,
    0x1.fffffep126,
    0x1.000002p-1,
    0x1.fffffep126
  },
  { // Entry 294
    0x1.8000007fffffp127,
    0x1.fffffep126,
    0x1.000002p-1,
    0x1.p127
  },
  { // Entry 295
    0x1.7ffffd80p127,
    0x1.p127,
    0x1.fffffep-2,
    0x1.fffffcp126
  },
  { // Entry 296
    0x1.7ffffe80p127,
    0x1.p127,
    0x1.fffffep-2,
    0x1.fffffep126
  },
  { // Entry 297
    0x1.7fffff80p127,
    0x1.p127,
    0x1.fffffep-2,
    0x1.p127
  },
  { // Entry 298
    0x1.7ffffep127,
    0x1.p127,
    0x1.p-1,
    0x1.fffffcp126
  },
  { // Entry 299
    0x1.7fffffp127,
    0x1.p127,
    0x1.p-1,
    0x1.fffffep126
  },
  { // Entry 300
    0x1.80p127,
    0x1.p127,
    0x1.p-1,
    0x1.p127
  },
  { // Entry 301
    0x1.7fffffp127,
    0x1.p127,
    0x1.000002p-1,
    0x1.fffffcp126
  },
  { // Entry 302
    0x1.80p127,
    0x1.p127,
    0x1.000002p-1,
    0x1.fffffep126
  },
  { // Entry 303
    0x1.800001p127,
    0x1.p127,
    0x1.000002p-1,
    0x1.p127
  },
  { // Entry 304
    0x1.fffffb000002p127,
    0x1.fffffcp126,
    0x1.fffffep-1,
    0x1.fffffcp126
  },
  { // Entry 305
    0x1.fffffc000002p127,
    0x1.fffffcp126,
    0x1.fffffep-1,
    0x1.fffffep126
  },
  { // Entry 306
    0x1.fffffd000002p127,
    0x1.fffffcp126,
    0x1.fffffep-1,
    0x1.p127
  },
  { // Entry 307
    0x1.fffffcp127,
    0x1.fffffcp126,
    0x1.p0,
    0x1.fffffcp126
  },
  { // Entry 308
    0x1.fffffdp127,
    0x1.fffffcp126,
    0x1.p0,
    0x1.fffffep126
  },
  { // Entry 309
    0x1.fffffep127,
    0x1.fffffcp126,
    0x1.p0,
    0x1.p127
  },
  { // Entry 310
    0x1.fffffdfffffcp127,
    0x1.fffffcp126,
    0x1.000002p0,
    0x1.fffffcp126
  },
  { // Entry 311
    0x1.fffffefffffcp127,
    0x1.fffffcp126,
    0x1.000002p0,
    0x1.fffffep126
  },
  { // Entry 312
    HUGE_VALF,
    0x1.fffffcp126,
    0x1.000002p0,
    0x1.p127
  },
  { // Entry 313
    0x1.fffffc000001p127,
    0x1.fffffep126,
    0x1.fffffep-1,
    0x1.fffffcp126
  },
  { // Entry 314
    0x1.fffffd000001p127,
    0x1.fffffep126,
    0x1.fffffep-1,
    0x1.fffffep126
  },
  { // Entry 315
    0x1.fffffe000001p127,
    0x1.fffffep126,
    0x1.fffffep-1,
    0x1.p127
  },
  { // Entry 316
    0x1.fffffdp127,
    0x1.fffffep126,
    0x1.p0,
    0x1.fffffcp126
  },
  { // Entry 317
    0x1.fffffep127,
    0x1.fffffep126,
    0x1.p0,
    0x1.fffffep126
  },
  { // Entry 318
    HUGE_VALF,
    0x1.fffffep126,
    0x1.p0,
    0x1.p127
  },
  { // Entry 319
    0x1.fffffefffffep127,
    0x1.fffffep126,
    0x1.000002p0,
    0x1.fffffcp126
  },
  { // Entry 320
    HUGE_VALF,
    0x1.fffffep126,
    0x1.000002p0,
    0x1.fffffep126
  },
  { // Entry 321
    HUGE_VALF,
    0x1.fffffep126,
    0x1.000002p0,
    0x1.p127
  },
  { // Entry 322
    0x1.fffffdp127,
    0x1.p127,
    0x1.fffffep-1,
    0x1.fffffcp126
  },
  { // Entry 323
    0x1.fffffep127,
    0x1.p127,
    0x1.fffffep-1,
    0x1.fffffep126
  },
  { // Entry 324
    HUGE_VALF,
    0x1.p127,
    0x1.fffffep-1,
    0x1.p127
  },
  { // Entry 325
    0x1.fffffep127,
    0x1.p127,
    0x1.p0,
    0x1.fffffcp126
  },
  { // Entry 326
    HUGE_VALF,
    0x1.p127,
    0x1.p0,
    0x1.fffffep126
  },
  { // Entry 327
    HUGE_VALF,
    0x1.p127,
    0x1.p0,
    0x1.p127
  },
  { // Entry 328
    HUGE_VALF,
    0x1.p127,
    0x1.000002p0,
    0x1.fffffcp126
  },
  { // Entry 329
    HUGE_VALF,
    0x1.p127,
    0x1.000002p0,
    0x1.fffffep126
  },
  { // Entry 330
    HUGE_VALF,
    0x1.p127,
    0x1.000002p0,
    0x1.p127
  },
  { // Entry 331
    0x1.fffffb000002p127,
    0x1.fffffcp126,
    0x1.fffffep-1,
    0x1.fffffcp126
  },
  { // Entry 332
    0x1.fffffc000002p127,
    0x1.fffffcp126,
    0x1.fffffep-1,
    0x1.fffffep126
  },
  { // Entry 333
    0x1.fffffd000002p127,
    0x1.fffffcp126,
    0x1.fffffep-1,
    0x1.p127
  },
  { // Entry 334
    0x1.fffffcp127,
    0x1.fffffcp126,
    0x1.p0,
    0x1.fffffcp126
  },
  { // Entry 335
    0x1.fffffdp127,
    0x1.fffffcp126,
    0x1.p0,
    0x1.fffffep126
  },
  { // Entry 336
    0x1.fffffep127,
    0x1.fffffcp126,
    0x1.p0,
    0x1.p127
  },
  { // Entry 337
    0x1.fffffdfffffcp127,
    0x1.fffffcp126,
    0x1.000002p0,
    0x1.fffffcp126
  },
  { // Entry 338
    0x1.fffffefffffcp127,
    0x1.ff
```
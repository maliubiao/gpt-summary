Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Task:**

The request is about analyzing a C source code file containing test data for the `nextafterf` function within Android's Bionic library. The core goal is to understand the purpose of the file, its connection to Android, how the underlying function works, and how it's used in the Android ecosystem.

**2. Deconstructing the Request's Specific Questions:**

The request poses several distinct questions that need to be addressed systematically:

* **Functionality of the file:** What is the purpose of this data file?
* **Relationship to Android:** How does this relate to the broader Android system?
* **`nextafterf` implementation:** How does the `nextafterf` function work internally?
* **Dynamic Linker implications:** Are there any dynamic linking aspects, and how do they work?
* **Logic/Assumptions:** Can we infer input/output behavior from the data?
* **Common Errors:** What mistakes do programmers often make when using related functions?
* **Android Framework/NDK Journey:** How does execution reach this point from higher levels?
* **Frida Hooking:** How can we debug this using Frida?

**3. Analyzing the Code:**

The provided code snippet is a C array named `g_nextafterf_intel_data`. Each element of the array is a structure containing three `float` values. The comments clearly indicate this is test data for the `nextafterf` function. The naming convention `_intel_data.handroid` hints at architecture-specific testing.

**4. Addressing Each Question Systematically:**

* **Functionality:**  The most obvious function is to provide test cases. These test cases are likely used in unit tests to verify the correctness of the `nextafterf` implementation on Intel/x86 Android devices. The data structure suggests input values and the expected output.

* **Relationship to Android:** Bionic is Android's C library. The `nextafterf` function is a standard math function provided by Bionic. This file directly supports the reliability and correctness of the Android system's mathematical capabilities. Examples of Android components that *might* use this (though not directly invoking *this data file*) include graphics rendering, sensor processing, and any app performing floating-point calculations.

* **`nextafterf` Implementation:** This requires knowledge of the standard C library. `nextafterf(x, y)` returns the next representable floating-point value after `x` in the direction of `y`. The explanation needs to cover the behavior for different scenarios: normal numbers, subnormal numbers, zero, infinity, and NaN. It involves manipulating the underlying bit representation of floating-point numbers.

* **Dynamic Linker:**  This file itself doesn't directly involve the dynamic linker. However, `nextafterf` is part of `libc.so`, which is a shared library loaded by the dynamic linker. Explaining the dynamic linking process is necessary, including SO structure (ELF), symbol tables, relocation, and the dynamic linker's role. A simplified SO layout example is needed.

* **Logic/Assumptions (Input/Output):**  The data array itself *is* the input and expected output. Each `{input1, input2, expected_output}` tuple provides a test case for `nextafterf(input1, input2)`. We can list a few examples from the data.

* **Common Errors:** This requires knowledge of how programmers use floating-point functions. Common errors include misunderstanding the direction argument, issues with precision, and edge cases like NaN and infinity.

* **Android Framework/NDK Journey:**  This involves tracing the execution flow. A user-level app (Java/Kotlin) might use the NDK to call C/C++ code. The NDK then links against Bionic's `libc.so`. When the C/C++ code calls `nextafterf`, the Bionic implementation is invoked. The test data file is used during the *development and testing* of Bionic, not during regular app execution.

* **Frida Hooking:**  Frida can be used to intercept calls to `nextafterf`. A simple Frida script would involve getting the address of the function and replacing its implementation with a custom one or simply logging the arguments and return value.

**5. Structuring the Answer:**

Organize the answer clearly, addressing each question in a separate section. Use headings and bullet points to improve readability. Provide code examples where appropriate (like the Frida script). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file is directly used by the dynamic linker.
* **Correction:** Realized this is test *data* for a math function, not directly involved in linking. The dynamic linker loads the library containing the function.
* **Initial thought:** Focus only on the `nextafterf` implementation details.
* **Refinement:**  Recognized the need to explain the broader context of Bionic, testing, and dynamic linking, as the request explicitly asked for these connections.
* **Initial thought:**  Provide a very detailed explanation of floating-point representation.
* **Refinement:**  Keep the explanation concise but informative, focusing on the key aspects relevant to `nextafterf`. Refer to standard knowledge about floating-point numbers.

By following this structured approach and iteratively refining the understanding, a comprehensive and accurate answer can be generated.
这是一个位于 `bionic/tests/math_data/nextafterf_intel_data.handroid` 的源代码文件。根据路径和文件名，我们可以推断出以下几点：

* **`bionic`:**  表明这是 Android Bionic 库的一部分，Bionic 包含了 Android 的 C 库 (`libc`)、数学库 (`libm`) 和动态链接器 (`linker`)。
* **`tests`:**  说明这是一个测试相关的目录。
* **`math_data`:**  进一步说明这个文件包含用于数学函数测试的数据。
* **`nextafterf_intel_data`:**  指示这个文件包含用于测试 `nextafterf` 函数（单精度浮点版本）的数据，并且可能特定于 Intel 架构 (`intel`)。
* **`.handroid`:**  这可能是 Android 特定的文件扩展名，暗示了其在 Android 测试环境中的用途。

**功能:**

这个文件的主要功能是为 `nextafterf` 函数提供测试数据。  具体来说，它包含一个 C 数组 `g_nextafterf_intel_data`，该数组的每个元素都是一个结构体，包含了三个 `float` 类型的值。  根据命名 `data_1_2_t` 和数组内容，我们可以推断出这三个值分别代表：

1. **第一个浮点数 (x):**  作为 `nextafterf` 函数的第一个输入参数。
2. **第二个浮点数 (y):**  作为 `nextafterf` 函数的第二个输入参数，指示逼近的方向。
3. **期望的输出 (result):**  当调用 `nextafterf(x, y)` 时，期望返回的浮点数值。

因此，这个文件是用于单元测试 `nextafterf` 函数的，通过提供一系列预定义的输入和期望输出，来验证 `nextafterf` 函数在各种情况下的行为是否正确。 特别是，文件名中的 `intel` 暗示了这些测试数据可能是针对 Intel (x86 或 x86_64) 架构进行了特别设计或优化。`handroid` 则表明这是 Android 特定的测试数据。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 系统中数学运算的正确性和稳定性。`nextafterf` 是一个标准的 C 库函数，用于查找浮点数在特定方向上的下一个可表示值。 确保这个函数在 Android 平台上（特别是 Intel 架构的 Android 设备上）的实现是正确的，对于依赖精确浮点运算的应用至关重要。

**举例说明:**

* **图形渲染:**  OpenGL ES 或 Vulkan 等图形 API 内部可能会使用浮点数进行大量的计算，例如坐标变换、光照计算等。如果 `nextafterf` 的实现有误，可能会导致渲染结果出现细微的错误或不一致。
* **传感器数据处理:**  Android 设备上的传感器（如加速度计、陀螺仪）产生的数据通常是浮点数。  处理这些数据可能涉及到一些数学运算，正确的 `nextafterf` 实现有助于保证数据处理的精度。
* **科学计算类应用:**  如果 Android 设备上运行科学计算相关的应用，它们通常会大量使用浮点运算。  `nextafterf` 在某些特定的数值算法中可能会被用到，以控制精度或处理边界情况。

**详细解释 `libc` 函数 `nextafterf` 的功能和实现:**

`nextafterf(float x, float y)` 函数的功能是返回在浮点数表示中，从 `x` 开始沿着 `y` 的方向移动一步所到达的下一个可表示的浮点数值。

**实现原理：**

`nextafterf` 的实现通常涉及到对浮点数的底层位表示进行操作。 IEEE 754 标准定义了浮点数的表示方式，包括符号位、指数位和尾数位。

1. **处理特殊情况:** 首先，函数会处理一些特殊情况：
   * 如果 `x` 等于 `y`，则直接返回 `y` (或 `x`)。
   * 如果 `x` 是 NaN (Not a Number)，则返回 NaN。
   * 如果 `y` 是 NaN，则返回 NaN。

2. **确定方向:**  比较 `x` 和 `y` 的值来确定移动的方向：
   * 如果 `y > x`，则需要找到大于 `x` 的下一个可表示的浮点数。
   * 如果 `y < x`，则需要找到小于 `x` 的下一个可表示的浮点数。

3. **操作位表示:**  根据确定的方向，操作 `x` 的底层位表示：
   * **向正无穷方向移动 (y > x):**
     * 如果 `x` 是正无穷，则返回正无穷。
     * 如果 `x` 是零或正数，通常会增加 `x` 的尾数部分的最低有效位。如果尾数溢出，则需要调整指数。
     * 如果 `x` 是负零，则下一个可表示的值是最小的正浮点数。
     * 如果 `x` 是负数，则下一个可表示的值是通过减小 `x` 的绝对值得到的，这通常意味着减少其尾数的位，并可能调整指数。

   * **向负无穷方向移动 (y < x):**
     * 如果 `x` 是负无穷，则返回负无穷。
     * 如果 `x` 是零或负数，通常会减小 `x` 的尾数部分的最低有效位。如果尾数需要借位，则需要调整指数。
     * 如果 `x` 是正零，则下一个可表示的值是最小的负浮点数。
     * 如果 `x` 是正数，则下一个可表示的值是通过减小 `x` 得到的，这通常意味着减少其尾数的位，并可能调整指数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程。**

这个特定的数据文件 **不直接涉及** 动态链接器的功能。 它只是用于测试 `nextafterf` 函数的数据，而 `nextafterf` 函数的实现位于 `libc.so` (Android 的 C 库) 中，该库由动态链接器加载。

**SO 布局样本 (`libc.so`)：**

一个简化的 `libc.so` 的布局可能如下所示（基于 ELF 文件格式）：

```
ELF Header
Program Headers
Section Headers

.text      (可执行代码段)
   ...
   nextafterf 函数的机器码实现
   ...

.rodata    (只读数据段)
   ...
   一些常量数据
   ...

.data      (已初始化的可读写数据段)
   ...
   全局变量
   ...

.bss       (未初始化的可读写数据段)
   ...
   未初始化的全局变量
   ...

.dynsym    (动态符号表)
   ...
   nextafterf 的符号信息 (函数名，地址等)
   ...

.dynstr    (动态字符串表)
   ...
   包含 "nextafterf" 等字符串
   ...

.rel.dyn   (动态重定位表)
   ...
   关于需要在加载时进行地址修正的信息
   ...

.plt       (程序链接表)
   ...
   用于延迟绑定外部符号
   ...

.got       (全局偏移表)
   ...
   用于存储外部符号的实际地址
   ...
```

**链接的处理过程：**

当一个应用程序需要使用 `nextafterf` 函数时，会发生以下链接过程：

1. **编译时链接:** 编译器在编译应用程序的 C/C++ 代码时，会找到 `nextafterf` 函数的声明，并生成对该函数的调用指令。此时，编译器并不知道 `nextafterf` 的具体内存地址。

2. **动态链接器介入:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载应用程序依赖的共享库，包括 `libc.so`。

3. **加载 `libc.so`:** 动态链接器会将 `libc.so` 加载到内存中的某个地址空间。

4. **符号解析:** 动态链接器会读取 `libc.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，找到 `nextafterf` 函数的符号信息，获取其在 `libc.so` 内部的相对地址。

5. **重定位:** 应用程序的代码中对 `nextafterf` 的调用指令包含一个占位符地址。动态链接器会读取 `libc.so` 的动态重定位表 (`.rel.dyn`)，找到需要修正的地址，并根据 `libc.so` 的加载基址以及 `nextafterf` 在 `libc.so` 中的相对地址，计算出 `nextafterf` 在内存中的实际地址，并更新应用程序代码中的占位符地址。

6. **延迟绑定 (可能):**  在一些情况下，为了优化启动性能，外部符号的解析和重定位可能会延迟到第一次使用时进行。这涉及到程序链接表 (`.plt`) 和全局偏移表 (`.got`)。  第一次调用 `nextafterf` 时，会跳转到 `.plt` 中的一个桩代码，该桩代码会调用动态链接器来解析 `nextafterf` 的地址，并将该地址存储在 `.got` 中。后续对 `nextafterf` 的调用将直接从 `.got` 中获取地址，避免重复解析。

**如果做了逻辑推理，请给出假设输入与输出。**

根据提供的 `nextafterf_intel_data.handroid` 文件中的数据，我们可以进行逻辑推理。 每个 `{input1, input2, expected_output}` 条目都是一个测试用例。

**假设输入与输出示例：**

* **Entry 0:** `{ -0x1.p-149, -0x1.p-149, -0x1.p-149 }`
   * **输入 `x`:**  -0x1.p-149 (这是一个非常小的负数)
   * **输入 `y`:**  -0x1.p-149
   * **预期输出:** -0x1.p-149
   * **推理:** 当 `x` 等于 `y` 时，`nextafterf` 应该返回 `y`。

* **Entry 1:** `{ -0.0, -0x1.p-149, 0.0 }`
   * **输入 `x`:**  -0.0 (负零)
   * **输入 `y`:**  -0x1.p-149 (一个小的负数)
   * **预期输出:** 0.0 (正零)
   * **推理:** 从负零开始，向 `-0x1.p-149` 的方向移动（即向更大的负数方向），下一个可表示的值是正零。这是因为负零和正零在浮点数表示中是不同的。

* **Entry 11:** `{ 0x1.p0, 0x1.fffffep-1, 0x1.000002p0 }`
   * **输入 `x`:**  0x1.p0 (1.0)
   * **输入 `y`:**  0x1.fffffep-1 (非常接近 1.0 的一个较小的值)
   * **预期输出:** 0x1.000002p0 (稍微大于 1.0 的下一个可表示的值)
   * **推理:** 从 1.0 开始，向小于 1.0 的方向移动，下一个可表示的值应该是略小于 1.0 的值。  这里似乎有个错误，因为 `y` 小于 `x`，预期输出应该是比 `x` 小的值。 **这里需要注意，我对这个条目的理解可能存在偏差，需要仔细核对 `nextafterf` 的定义。** 实际上，`nextafterf(x, y)` 是找到从 `x` 指向 `y` 的方向的下一个可表示的浮点数。所以，当 `y` 小于 `x` 时，结果应该小于 `x`。 仔细看，我理解反了，`y` 指示方向，所以从 `x` 向 `y` 的方向移动。 如果 `y` 比 `x` 小，那下一个可表示的值也应该比 `x` 小。

* **Entry 14:** `{ 0x1.000002p0, 0x1.p0, 0x1.000002p0 }`
   * **输入 `x`:** 0x1.000002p0 (稍微大于 1.0 的值)
   * **输入 `y`:** 0x1.p0 (1.0)
   * **预期输出:** 0x1.000002p0
   * **推理:** 从稍微大于 1.0 的值开始，向 1.0 的方向移动，由于已经很接近，下一个可表示的值仍然是它自身，因为在它和 1.0 之间没有其他的可表示的单精度浮点数。 **这个理解也有误，如果 `y` 小于 `x`，那么结果应该是小于 `x` 的值。 仔细看，当 `x` 等于预期输出时，意味着在 `x` 和 `y` 之间没有其他的可表示的单精度浮点数。**

**如果涉及用户或者编程常见的使用错误，请举例说明。**

使用 `nextafterf` (以及相关的浮点数操作) 时，常见的错误包括：

1. **误解逼近方向:**  不清楚第二个参数 `y` 是指定逼近的目标值，而不是步长。 容易错误地认为 `nextafterf(x, delta)` 是在 `x` 的基础上增加或减少一个 `delta` 值。

   ```c
   float x = 1.0f;
   float delta = 0.1f;
   // 错误的想法：获取比 x 大 0.1 的下一个可表示值
   float next_val = nextafterf(x, x + delta);
   // 正确的做法：
   float very_large_float = HUGE_VALF; // 或者一个比 x 大很多的数
   float next_val_correct = nextafterf(x, very_large_float);
   ```

2. **精度问题:**  期望通过多次调用 `nextafterf` 来实现精确的步进，但浮点数的表示是离散的，步长可能不均匀。

   ```c
   float start = 0.0f;
   float end = 1.0f;
   float current = start;
   while (current < end) {
       current = nextafterf(current, end);
       // 循环次数可能不是预期的，因为步长不一致
   }
   ```

3. **处理特殊值:**  没有正确处理 NaN 和无穷大的情况。 `nextafterf` 在这些情况下的行为需要特别注意。

   ```c
   float x = NAN;
   float y = 1.0f;
   float result = nextafterf(x, y); // result 将是 NAN
   // 没有检查 result 是否为 NAN 可能会导致后续计算错误
   ```

4. **忽略浮点数的有限精度:**  期望在两个非常接近的浮点数之间找到更多可表示的值，但实际上可能没有。

   ```c
   float a = 1.0f;
   float b = nextafterf(a, HUGE_VALF); // b 是大于 a 的下一个可表示值
   float next = nextafterf(a, b); // next 仍然可能是 b，因为 a 和 b 之间没有其他可表示的单精度浮点数
   ```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用:**
   * **Android Framework:**  在 Java/Kotlin 代码中，如果需要进行底层的、对性能敏感的数学运算，可能会通过 JNI (Java Native Interface) 调用 NDK 编写的 C/C++ 代码。
   * **NDK:**  开发者使用 NDK 编写 C/C++ 代码，这些代码会链接到 Android 的 Bionic 库 (`libc.so` 或 `libm.so`)。

2. **调用 `nextafterf`:** NDK 代码中直接调用 `nextafterf` 函数。

   ```c++
   #include <cmath>

   float my_float_operation(float value, float direction) {
       return std::nextafterf(value, direction);
   }
   ```

3. **动态链接:** 当包含上述 NDK 代码的应用程序运行时，动态链接器会加载包含 `nextafterf` 实现的共享库 (`libm.so`，它通常会依赖于 `libc.so`)。

4. **执行 `nextafterf`:**  当执行到 `my_float_operation` 函数时，会调用 `std::nextafterf`，这实际上会调用 Bionic 库中的 `nextafterf` 实现。

**Frida Hook 示例：**

可以使用 Frida 来 hook `nextafterf` 函数的调用，以观察其参数和返回值。

```python
import frida
import sys

package_name = "your.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "nextafterf"), {
    onEnter: function(args) {
        var x = args[0];
        var y = args[1];
        send({
            type: "input",
            x: x.readFloat(),
            y: y.readFloat()
        });
    },
    onLeave: function(retval) {
        send({
            type: "output",
            retval: retval.readFloat()
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
print("[*] Running, press Ctrl+C to exit.")
sys.stdin.read()
```

**Frida Hook 调试步骤：**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务 (`frida-server`)。
2. **安装 Frida:** 在你的开发机器上安装 Frida (`pip install frida-tools`).
3. **运行目标应用:** 启动你想要调试的 Android 应用。
4. **运行 Frida 脚本:** 将上面的 Python 脚本保存为 `hook_nextafterf.py`，并将 `your.package.name` 替换为你的应用包名，然后在终端中运行 `python hook_nextafterf.py`。
5. **操作应用:** 在你的 Android 应用中执行会调用 `nextafterf` 的操作。
6. **观察输出:** Frida 脚本会拦截对 `nextafterf` 的调用，并打印出输入参数 `x` 和 `y` 以及返回值。

通过 Frida Hook，你可以实时观察 `nextafterf` 函数在应用运行时的行为，验证其参数和返回值是否符合预期，从而帮助理解 Android Framework 或 NDK 是如何逐步调用到这个 Bionic 库函数的。

### 提示词
```
这是目录为bionic/tests/math_data/nextafterf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
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

static data_1_2_t<float, float, float> g_nextafterf_intel_data[] = {
  { // Entry 0
    -0x1.p-149,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1
    -0.0,
    -0x1.p-149,
    0.0
  },
  { // Entry 2
    -0.0,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 3
    -0x1.p-149,
    0.0,
    -0x1.p-149
  },
  { // Entry 4
    0.0,
    0.0,
    0.0
  },
  { // Entry 5
    0x1.p-149,
    0.0,
    0x1.p-149
  },
  { // Entry 6
    0.0,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 7
    0.0,
    0x1.p-149,
    0.0
  },
  { // Entry 8
    0x1.p-149,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 9
    0x1.fffffep-1,
    0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 10
    0x1.p0,
    0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 11
    0x1.p0,
    0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 12
    0x1.fffffep-1,
    0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 13
    0x1.p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 14
    0x1.000002p0,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 15
    0x1.p0,
    0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 16
    0x1.p0,
    0x1.000002p0,
    0x1.p0
  },
  { // Entry 17
    0x1.000002p0,
    0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 18
    0x1.fffffcp-1,
    0x1.fffffep-1,
    -0x1.000002p0
  },
  { // Entry 19
    0x1.fffffcp-1,
    0x1.fffffep-1,
    -0x1.p0
  },
  { // Entry 20
    0x1.fffffcp-1,
    0x1.fffffep-1,
    -0x1.fffffep-1
  },
  { // Entry 21
    0x1.fffffep-1,
    0x1.p0,
    -0x1.000002p0
  },
  { // Entry 22
    0x1.fffffep-1,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 23
    0x1.fffffep-1,
    0x1.p0,
    -0x1.fffffep-1
  },
  { // Entry 24
    0x1.p0,
    0x1.000002p0,
    -0x1.000002p0
  },
  { // Entry 25
    0x1.p0,
    0x1.000002p0,
    -0x1.p0
  },
  { // Entry 26
    0x1.p0,
    0x1.000002p0,
    -0x1.fffffep-1
  },
  { // Entry 27
    -0x1.p0,
    -0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 28
    -0x1.p0,
    -0x1.000002p0,
    0x1.p0
  },
  { // Entry 29
    -0x1.p0,
    -0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 30
    -0x1.fffffep-1,
    -0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 31
    -0x1.fffffep-1,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 32
    -0x1.fffffep-1,
    -0x1.p0,
    0x1.000002p0
  },
  { // Entry 33
    -0x1.fffffcp-1,
    -0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 34
    -0x1.fffffcp-1,
    -0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 35
    -0x1.fffffcp-1,
    -0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 36
    -0x1.000002p0,
    -0x1.000002p0,
    -0x1.000002p0
  },
  { // Entry 37
    -0x1.p0,
    -0x1.000002p0,
    -0x1.p0
  },
  { // Entry 38
    -0x1.p0,
    -0x1.000002p0,
    -0x1.fffffep-1
  },
  { // Entry 39
    -0x1.000002p0,
    -0x1.p0,
    -0x1.000002p0
  },
  { // Entry 40
    -0x1.p0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 41
    -0x1.fffffep-1,
    -0x1.p0,
    -0x1.fffffep-1
  },
  { // Entry 42
    -0x1.p0,
    -0x1.fffffep-1,
    -0x1.000002p0
  },
  { // Entry 43
    -0x1.p0,
    -0x1.fffffep-1,
    -0x1.p0
  },
  { // Entry 44
    -0x1.fffffep-1,
    -0x1.fffffep-1,
    -0x1.fffffep-1
  },
  { // Entry 45
    0x1.fffffep0,
    0x1.fffffep0,
    0x1.fffffep0
  },
  { // Entry 46
    0x1.p1,
    0x1.fffffep0,
    0x1.p1
  },
  { // Entry 47
    0x1.p1,
    0x1.fffffep0,
    0x1.000002p1
  },
  { // Entry 48
    0x1.fffffep0,
    0x1.p1,
    0x1.fffffep0
  },
  { // Entry 49
    0x1.p1,
    0x1.p1,
    0x1.p1
  },
  { // Entry 50
    0x1.000002p1,
    0x1.p1,
    0x1.000002p1
  },
  { // Entry 51
    0x1.p1,
    0x1.000002p1,
    0x1.fffffep0
  },
  { // Entry 52
    0x1.p1,
    0x1.000002p1,
    0x1.p1
  },
  { // Entry 53
    0x1.000002p1,
    0x1.000002p1,
    0x1.000002p1
  },
  { // Entry 54
    0x1.fffffcp0,
    0x1.fffffep0,
    -0x1.000002p1
  },
  { // Entry 55
    0x1.fffffcp0,
    0x1.fffffep0,
    -0x1.p1
  },
  { // Entry 56
    0x1.fffffcp0,
    0x1.fffffep0,
    -0x1.fffffep0
  },
  { // Entry 57
    0x1.fffffep0,
    0x1.p1,
    -0x1.000002p1
  },
  { // Entry 58
    0x1.fffffep0,
    0x1.p1,
    -0x1.p1
  },
  { // Entry 59
    0x1.fffffep0,
    0x1.p1,
    -0x1.fffffep0
  },
  { // Entry 60
    0x1.p1,
    0x1.000002p1,
    -0x1.000002p1
  },
  { // Entry 61
    0x1.p1,
    0x1.000002p1,
    -0x1.p1
  },
  { // Entry 62
    0x1.p1,
    0x1.000002p1,
    -0x1.fffffep0
  },
  { // Entry 63
    -0x1.p1,
    -0x1.000002p1,
    0x1.fffffep0
  },
  { // Entry 64
    -0x1.p1,
    -0x1.000002p1,
    0x1.p1
  },
  { // Entry 65
    -0x1.p1,
    -0x1.000002p1,
    0x1.000002p1
  },
  { // Entry 66
    -0x1.fffffep0,
    -0x1.p1,
    0x1.fffffep0
  },
  { // Entry 67
    -0x1.fffffep0,
    -0x1.p1,
    0x1.p1
  },
  { // Entry 68
    -0x1.fffffep0,
    -0x1.p1,
    0x1.000002p1
  },
  { // Entry 69
    -0x1.fffffcp0,
    -0x1.fffffep0,
    0x1.fffffep0
  },
  { // Entry 70
    -0x1.fffffcp0,
    -0x1.fffffep0,
    0x1.p1
  },
  { // Entry 71
    -0x1.fffffcp0,
    -0x1.fffffep0,
    0x1.000002p1
  },
  { // Entry 72
    -0x1.000002p1,
    -0x1.000002p1,
    -0x1.000002p1
  },
  { // Entry 73
    -0x1.p1,
    -0x1.000002p1,
    -0x1.p1
  },
  { // Entry 74
    -0x1.p1,
    -0x1.000002p1,
    -0x1.fffffep0
  },
  { // Entry 75
    -0x1.000002p1,
    -0x1.p1,
    -0x1.000002p1
  },
  { // Entry 76
    -0x1.p1,
    -0x1.p1,
    -0x1.p1
  },
  { // Entry 77
    -0x1.fffffep0,
    -0x1.p1,
    -0x1.fffffep0
  },
  { // Entry 78
    -0x1.p1,
    -0x1.fffffep0,
    -0x1.000002p1
  },
  { // Entry 79
    -0x1.p1,
    -0x1.fffffep0,
    -0x1.p1
  },
  { // Entry 80
    -0x1.fffffep0,
    -0x1.fffffep0,
    -0x1.fffffep0
  },
  { // Entry 81
    0x1.fffffep9,
    0x1.fffffep9,
    0x1.fffffep9
  },
  { // Entry 82
    0x1.p10,
    0x1.fffffep9,
    0x1.p10
  },
  { // Entry 83
    0x1.p10,
    0x1.fffffep9,
    0x1.000002p10
  },
  { // Entry 84
    0x1.fffffep9,
    0x1.p10,
    0x1.fffffep9
  },
  { // Entry 85
    0x1.p10,
    0x1.p10,
    0x1.p10
  },
  { // Entry 86
    0x1.000002p10,
    0x1.p10,
    0x1.000002p10
  },
  { // Entry 87
    0x1.p10,
    0x1.000002p10,
    0x1.fffffep9
  },
  { // Entry 88
    0x1.p10,
    0x1.000002p10,
    0x1.p10
  },
  { // Entry 89
    0x1.000002p10,
    0x1.000002p10,
    0x1.000002p10
  },
  { // Entry 90
    0x1.fffffcp9,
    0x1.fffffep9,
    -0x1.000002p10
  },
  { // Entry 91
    0x1.fffffcp9,
    0x1.fffffep9,
    -0x1.p10
  },
  { // Entry 92
    0x1.fffffcp9,
    0x1.fffffep9,
    -0x1.fffffep9
  },
  { // Entry 93
    0x1.fffffep9,
    0x1.p10,
    -0x1.000002p10
  },
  { // Entry 94
    0x1.fffffep9,
    0x1.p10,
    -0x1.p10
  },
  { // Entry 95
    0x1.fffffep9,
    0x1.p10,
    -0x1.fffffep9
  },
  { // Entry 96
    0x1.p10,
    0x1.000002p10,
    -0x1.000002p10
  },
  { // Entry 97
    0x1.p10,
    0x1.000002p10,
    -0x1.p10
  },
  { // Entry 98
    0x1.p10,
    0x1.000002p10,
    -0x1.fffffep9
  },
  { // Entry 99
    -0x1.p10,
    -0x1.000002p10,
    0x1.fffffep9
  },
  { // Entry 100
    -0x1.p10,
    -0x1.000002p10,
    0x1.p10
  },
  { // Entry 101
    -0x1.p10,
    -0x1.000002p10,
    0x1.000002p10
  },
  { // Entry 102
    -0x1.fffffep9,
    -0x1.p10,
    0x1.fffffep9
  },
  { // Entry 103
    -0x1.fffffep9,
    -0x1.p10,
    0x1.p10
  },
  { // Entry 104
    -0x1.fffffep9,
    -0x1.p10,
    0x1.000002p10
  },
  { // Entry 105
    -0x1.fffffcp9,
    -0x1.fffffep9,
    0x1.fffffep9
  },
  { // Entry 106
    -0x1.fffffcp9,
    -0x1.fffffep9,
    0x1.p10
  },
  { // Entry 107
    -0x1.fffffcp9,
    -0x1.fffffep9,
    0x1.000002p10
  },
  { // Entry 108
    -0x1.000002p10,
    -0x1.000002p10,
    -0x1.000002p10
  },
  { // Entry 109
    -0x1.p10,
    -0x1.000002p10,
    -0x1.p10
  },
  { // Entry 110
    -0x1.p10,
    -0x1.000002p10,
    -0x1.fffffep9
  },
  { // Entry 111
    -0x1.000002p10,
    -0x1.p10,
    -0x1.000002p10
  },
  { // Entry 112
    -0x1.p10,
    -0x1.p10,
    -0x1.p10
  },
  { // Entry 113
    -0x1.fffffep9,
    -0x1.p10,
    -0x1.fffffep9
  },
  { // Entry 114
    -0x1.p10,
    -0x1.fffffep9,
    -0x1.000002p10
  },
  { // Entry 115
    -0x1.p10,
    -0x1.fffffep9,
    -0x1.p10
  },
  { // Entry 116
    -0x1.fffffep9,
    -0x1.fffffep9,
    -0x1.fffffep9
  },
  { // Entry 117
    0x1.fffffep99,
    0x1.fffffep99,
    0x1.fffffep99
  },
  { // Entry 118
    0x1.p100,
    0x1.fffffep99,
    0x1.p100
  },
  { // Entry 119
    0x1.p100,
    0x1.fffffep99,
    0x1.000002p100
  },
  { // Entry 120
    0x1.fffffep99,
    0x1.p100,
    0x1.fffffep99
  },
  { // Entry 121
    0x1.p100,
    0x1.p100,
    0x1.p100
  },
  { // Entry 122
    0x1.000002p100,
    0x1.p100,
    0x1.000002p100
  },
  { // Entry 123
    0x1.p100,
    0x1.000002p100,
    0x1.fffffep99
  },
  { // Entry 124
    0x1.p100,
    0x1.000002p100,
    0x1.p100
  },
  { // Entry 125
    0x1.000002p100,
    0x1.000002p100,
    0x1.000002p100
  },
  { // Entry 126
    0x1.fffffcp99,
    0x1.fffffep99,
    -0x1.000002p100
  },
  { // Entry 127
    0x1.fffffcp99,
    0x1.fffffep99,
    -0x1.p100
  },
  { // Entry 128
    0x1.fffffcp99,
    0x1.fffffep99,
    -0x1.fffffep99
  },
  { // Entry 129
    0x1.fffffep99,
    0x1.p100,
    -0x1.000002p100
  },
  { // Entry 130
    0x1.fffffep99,
    0x1.p100,
    -0x1.p100
  },
  { // Entry 131
    0x1.fffffep99,
    0x1.p100,
    -0x1.fffffep99
  },
  { // Entry 132
    0x1.p100,
    0x1.000002p100,
    -0x1.000002p100
  },
  { // Entry 133
    0x1.p100,
    0x1.000002p100,
    -0x1.p100
  },
  { // Entry 134
    0x1.p100,
    0x1.000002p100,
    -0x1.fffffep99
  },
  { // Entry 135
    -0x1.p100,
    -0x1.000002p100,
    0x1.fffffep99
  },
  { // Entry 136
    -0x1.p100,
    -0x1.000002p100,
    0x1.p100
  },
  { // Entry 137
    -0x1.p100,
    -0x1.000002p100,
    0x1.000002p100
  },
  { // Entry 138
    -0x1.fffffep99,
    -0x1.p100,
    0x1.fffffep99
  },
  { // Entry 139
    -0x1.fffffep99,
    -0x1.p100,
    0x1.p100
  },
  { // Entry 140
    -0x1.fffffep99,
    -0x1.p100,
    0x1.000002p100
  },
  { // Entry 141
    -0x1.fffffcp99,
    -0x1.fffffep99,
    0x1.fffffep99
  },
  { // Entry 142
    -0x1.fffffcp99,
    -0x1.fffffep99,
    0x1.p100
  },
  { // Entry 143
    -0x1.fffffcp99,
    -0x1.fffffep99,
    0x1.000002p100
  },
  { // Entry 144
    -0x1.000002p100,
    -0x1.000002p100,
    -0x1.000002p100
  },
  { // Entry 145
    -0x1.p100,
    -0x1.000002p100,
    -0x1.p100
  },
  { // Entry 146
    -0x1.p100,
    -0x1.000002p100,
    -0x1.fffffep99
  },
  { // Entry 147
    -0x1.000002p100,
    -0x1.p100,
    -0x1.000002p100
  },
  { // Entry 148
    -0x1.p100,
    -0x1.p100,
    -0x1.p100
  },
  { // Entry 149
    -0x1.fffffep99,
    -0x1.p100,
    -0x1.fffffep99
  },
  { // Entry 150
    -0x1.p100,
    -0x1.fffffep99,
    -0x1.000002p100
  },
  { // Entry 151
    -0x1.p100,
    -0x1.fffffep99,
    -0x1.p100
  },
  { // Entry 152
    -0x1.fffffep99,
    -0x1.fffffep99,
    -0x1.fffffep99
  },
  { // Entry 153
    0x1.fffffcp127,
    0x1.fffffcp127,
    0x1.fffffcp127
  },
  { // Entry 154
    0x1.fffffep127,
    0x1.fffffcp127,
    0x1.fffffep127
  },
  { // Entry 155
    0x1.fffffep127,
    0x1.fffffcp127,
    0x1.fffffep127
  },
  { // Entry 156
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.fffffcp127
  },
  { // Entry 157
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 158
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 159
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.fffffcp127
  },
  { // Entry 160
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 161
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 162
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 163
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0x1.fffffcp127
  },
  { // Entry 164
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0x1.fffffap127
  },
  { // Entry 165
    -0x1.fffffep127,
    -0x1.fffffcp127,
    -0x1.fffffep127
  },
  { // Entry 166
    -0x1.fffffcp127,
    -0x1.fffffcp127,
    -0x1.fffffcp127
  },
  { // Entry 167
    -0x1.fffffap127,
    -0x1.fffffcp127,
    -0x1.fffffap127
  },
  { // Entry 168
    -0x1.fffffcp127,
    -0x1.fffffap127,
    -0x1.fffffep127
  },
  { // Entry 169
    -0x1.fffffcp127,
    -0x1.fffffap127,
    -0x1.fffffcp127
  },
  { // Entry 170
    -0x1.fffffap127,
    -0x1.fffffap127,
    -0x1.fffffap127
  },
  { // Entry 171
    0x1.fffffap127,
    0x1.fffffcp127,
    -0x1.fffffep127
  },
  { // Entry 172
    0x1.fffffap127,
    0x1.fffffcp127,
    -0x1.fffffcp127
  },
  { // Entry 173
    0x1.fffffap127,
    0x1.fffffcp127,
    -0x1.fffffap127
  },
  { // Entry 174
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 175
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffcp127
  },
  { // Entry 176
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffap127
  },
  { // Entry 177
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 178
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffcp127
  },
  { // Entry 179
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffap127
  },
  { // Entry 180
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.fffffcp127
  },
  { // Entry 181
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 182
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 183
    -0x1.fffffap127,
    -0x1.fffffcp127,
    0x1.fffffcp127
  },
  { // Entry 184
    -0x1.fffffap127,
    -0x1.fffffcp127,
    0x1.fffffep127
  },
  { // Entry 185
    -0x1.fffffap127,
    -0x1.fffffcp127,
    0x1.fffffep127
  },
  { // Entry 186
    -0x1.fffff8p127,
    -0x1.fffffap127,
    0x1.fffffcp127
  },
  { // Entry 187
    -0x1.fffff8p127,
    -0x1.fffffap127,
    0x1.fffffep127
  },
  { // Entry 188
    -0x1.fffff8p127,
    -0x1.fffffap127,
    0x1.fffffep127
  },
  { // Entry 189
    0x1.fffffap127,
    0x1.fffffcp127,
    -0x1.p-149
  },
  { // Entry 190
    0x1.fffffap127,
    0x1.fffffcp127,
    0.0
  },
  { // Entry 191
    0x1.fffffap127,
    0x1.fffffcp127,
    0x1.p-149
  },
  { // Entry 192
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 193
    0x1.fffffcp127,
    0x1.fffffep127,
    0.0
  },
  { // Entry 194
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 195
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 196
    0x1.fffffcp127,
    0x1.fffffep127,
    0.0
  },
  { // Entry 197
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 198
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 199
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0.0
  },
  { // Entry 200
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 201
    -0x1.fffffap127,
    -0x1.fffffcp127,
    -0x1.p-149
  },
  { // Entry 202
    -0x1.fffffap127,
    -0x1.fffffcp127,
    0.0
  },
  { // Entry 203
    -0x1.fffffap127,
    -0x1.fffffcp127,
    0x1.p-149
  },
  { // Entry 204
    -0x1.fffff8p127,
    -0x1.fffffap127,
    -0x1.p-149
  },
  { // Entry 205
    -0x1.fffff8p127,
    -0x1.fffffap127,
    0.0
  },
  { // Entry 206
    -0x1.fffff8p127,
    -0x1.fffffap127,
    0x1.p-149
  },
  { // Entry 207
    -0.0,
    -0x1.p-149,
    0x1.fffffcp127
  },
  { // Entry 208
    -0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 209
    -0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 210
    0x1.p-149,
    0.0,
    0x1.fffffcp127
  },
  { // Entry 211
    0x1.p-149,
    0.0,
    0x1.fffffep127
  },
  { // Entry 212
    0x1.p-149,
    0.0,
    0x1.fffffep127
  },
  { // Entry 213
    0x1.p-148,
    0x1.p-149,
    0x1.fffffcp127
  },
  { // Entry 214
    0x1.p-148,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 215
    0x1.p-148,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 216
    -0x1.p-148,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 217
    -0x1.p-148,
    -0x1.p-149,
    -0x1.fffffcp127
  },
  { // Entry 218
    -0x1.p-148,
    -0x1.p-149,
    -0x1.fffffap127
  },
  { // Entry 219
    -0x1.p-149,
    0.0,
    -0x1.fffffep127
  },
  { // Entry 220
    -0x1.p-149,
    0.0,
    -0x1.fffffcp127
  },
  { // Entry 221
    -0x1.p-149,
    0.0,
    -0x1.fffffap127
  },
  { // Entry 222
    0.0,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 223
    0.0,
    0x1.p-149,
    -0x1.fffffcp127
  },
  { // Entry 224
    0.0,
    0x1.p-149,
    -0x1.fffffap127
  },
  { // Entry 225
    HUGE_VALF,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 226
    0x1.fffffep127,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 227
    0x1.fffffep127,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 228
    0x1.fffffep127,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 229
    0x1.fffffep127,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 230
    0x1.fffffep127,
    HUGE_VALF,
    0.0f
  },
  { // Entry 231
    0x1.fffffep127,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 232
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 233
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 234
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 235
    0x1.fffffep127,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 236
    0x1.fffffep127,
    HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 237
    HUGE_VALF,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 238
    0x1.fffffep127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 239
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 240
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 241
    0x1.fffffcp127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 242
    0x1.fffffcp127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 243
    0x1.fffffcp127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 244
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 245
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 246
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 247
    0x1.fffffcp127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 248
    0x1.fffffcp127,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 249
    0x1.000002p-126,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 250
    0x1.000002p-126,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 251
    0x1.p-126,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 252
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 253
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 254
    0x1.fffffcp-127,
    0x1.p-126,
    0.0f
  },
  { // Entry 255
    0x1.fffffcp-127,
    0x1.p-126,
    -0.0f
  },
  { // Entry 256
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 257
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 258
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 259
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 260
    0x1.fffffcp-127,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 261
    0x1.p-126,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 262
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 263
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 264
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 265
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 266
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 267
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 268
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 269
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 270
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 271
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 272
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 273
    0x1.p-148,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 274
    0x1.p-148,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 275
    0x1.p-148,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 276
    0x1.p-148,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 277
    0x1.p-149,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 278
    0.0,
    0x1.p-149,
    0.0f
  },
  { // Entry 279
    0.0,
    0x1.p-149,
    -0.0f
  },
  { // Entry 280
    0.0,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 281
    0.0,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 282
    0.0,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 283
    0.0,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 284
    0.0,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 285
    0x1.p-149,
    0.0f,
    HUGE_VALF
  },
  { // Entry 286
    0x1.p-149,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 287
    0x1.p-149,
    0.0f,
    0x1.p-126
  },
  { // Entry 288
    0x1.p-149,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 289
    0x1.p-149,
    0.0f,
    0x1.p-149
  },
  { // Entry 290
    0.0,
    0.0f,
    0.0f
  },
  { // Entry 291
    -0.0,
    0.0f,
    -0.0f
  },
  { // Entry 292
    -0x1.p-149,
    0.0f,
    -0x1.p-149
  },
  { // Entry 293
    -0x1.p-149,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 294
    -0x1.p-149,
    0.0f,
    -0x1.p-126
  },
  { // Entry 295
    -0x1.p-149,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 296
    -0x1.p-149,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 297
    0x1.p-149,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 298
    0x1.p-149,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 299
    0x1.p-149,
    -0.0f,
    0x1.p-126
  },
  { // Entry 300
    0x1.p-149,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 301
    0x1.p-149,
    -0.0f,
    0x1.p-149
  },
  { // Entry 302
    0.0,
    -0.0f,
    0.0f
  },
  { // Entry 303
    -0.0,
    -0.0f,
    -0.0f
  },
  { // Entry 304
    -0x1.p-149,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 305
    -0x1.p-149,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 306
    -0x1.p-149,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 307
    -0x1.p-149,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 308
    -0x1.p-149,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 309
    -0.0,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 310
    -0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 311
    -0.0,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 312
    -0.0,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 313
    -0.0,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 314
    -0.0,
    -0x1.p-149,
    0.0f
  },
  { // Entry 315
    -0.0,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 316
    -0x1.p-149,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 317
    -0x1.p-148,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 318
    -0x1.p-148,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 319
    -0x1.p-148,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 320
    -0x1.p-148,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 321
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 322
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 323
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 324
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 325
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 326
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 327
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 328
    -0x1.fffff8p-127,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 329
    -0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 330
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 331
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 332
    -0x1.p-126,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 333
    -0x1.fffffcp-127,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 334
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 335
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 336
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 337
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 338
    -0x1.fffffcp-127,
    -0x1.p-126,
    0.0f
  },
  { // Entry 339
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 340
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 341
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 342
    -0x1.p-126,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 343
    -0x1.000002p-126,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 344
    -0x1.000002p-126,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 345
    -0x1.fffffcp127,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 346
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 347
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 348
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 349
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 350
    -0x1.fffffcp127,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 351
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 352
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 353
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 354
    -0x1.fffffcp127,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 355
    -0x1.fffffep127,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 356
    -HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 357
    -0x1.fffffep127,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 358
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 359
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 360
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 361
    -0x1.fffffep127,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 362
    -0x1.fffffep127,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 363
    -0x1.fffffep127,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 364
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 365
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 366
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 367
    -0x1.fffffep127,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 368
    -HUGE_VALF,
    -HUGE_VALF,
    -HUGE_VALF
  }
};
```
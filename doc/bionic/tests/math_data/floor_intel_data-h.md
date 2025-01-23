Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Task:**

The initial request is to analyze a C source code file containing test data for the `floor` function within Android's Bionic library. The key is to extract information about its purpose, its relation to Android, and its technical details.

**2. Initial Scrutiny of the Code:**

The first step is to read through the code. Even without understanding every single numerical value, the structure is clear:

*   It's a C file.
*   It defines a static array named `g_floor_intel_data`.
*   The array's elements are of type `data_1_1_t<double, double>`. This strongly suggests it's a set of input/output pairs for testing a function that takes a double and returns a double.
*   The array name includes "floor" and "intel," implying it's test data specifically for the `floor` function and potentially targeting Intel architectures.
*   The data is presented in hexadecimal floating-point notation, which is common in low-level math libraries for precise representation.

**3. Identifying the Functionality:**

Based on the array name and the data structure, the primary function of this file is to provide test cases for the `floor` function. These test cases likely cover edge cases, boundary conditions, and general scenarios to ensure the `floor` implementation is correct.

**4. Connecting to Android Functionality:**

The file is located within Bionic, Android's C library. Therefore, it directly relates to the `floor` function provided by Bionic. This function is a standard C library function, used throughout Android's codebase, including the framework and native applications.

**5. Explaining the `floor` Function:**

The next step is to explain what the `floor` function does: it takes a floating-point number and returns the largest integer less than or equal to that number. Simple examples like `floor(3.7) = 3.0` and `floor(-3.7) = -4.0` are crucial for clarity.

**6. Addressing Dynamic Linker Aspects:**

The prompt asks about the dynamic linker. While this *specific* file doesn't directly involve the dynamic linker's functionality, the `floor` function itself is part of `libc.so`, which *is* handled by the dynamic linker. Therefore, the explanation needs to cover:

*   The role of the dynamic linker in loading shared libraries like `libc.so`.
*   A simplified `libc.so` layout example, showing the `.text` (code) and `.data` (data) sections.
*   The linking process: how the application finds and uses the `floor` function within `libc.so`.

**7. Logical Reasoning and Input/Output:**

The data in the file *is* the logical reasoning and input/output examples. Each `{input, output}` pair demonstrates the expected behavior of the `floor` function for a specific input. Highlighting a few diverse examples, like positive/negative numbers, numbers close to integers, and zero, is important.

**8. Common Usage Errors:**

Common errors when using `floor` include:

*   Misunderstanding the behavior with negative numbers.
*   Forgetting that the return value is still a floating-point number.
*   Potential precision issues if not handled carefully.

**9. Tracing the Path from Android Framework/NDK:**

This requires outlining how a call to `floor` might originate:

*   Android Framework (Java):  Using `java.lang.Math.floor()`, which internally calls a native method.
*   NDK (C/C++):  Directly calling `floor()` from the `<math.h>` header.
*   Illustrating with a simplified NDK example is helpful.

**10. Frida Hook Example:**

A practical demonstration of how to intercept calls to `floor` using Frida is essential for understanding runtime behavior. The example should show how to hook the function, log arguments and return values, and potentially modify them.

**11. Language and Formatting:**

The request specifies Chinese. Using clear and concise language is crucial. Formatting the answer with headings, bullet points, and code blocks improves readability.

**Self-Correction/Refinement during the process:**

*   **Initial thought:** Focus *only* on what the file contains.
*   **Correction:**  Realize that the file's purpose is to test a function, so explaining the function itself is vital. Also, even if the file doesn't directly use the dynamic linker, the function it tests *does* reside in a shared library, making that aspect relevant.
*   **Initial thought:** Provide very technical, low-level details about floating-point representation.
*   **Correction:** While the data uses hex floats, the explanation should be more accessible. Focus on the *behavior* of `floor` rather than the intricate details of IEEE 754 unless specifically requested.
*   **Initial thought:** Just list the Frida code.
*   **Correction:**  Explain *what* the Frida code is doing and *why* it's useful for debugging.

By following this structured approach and refining the explanations along the way, we arrive at a comprehensive and informative answer that addresses all aspects of the prompt.
这个文件 `bionic/tests/math_data/floor_intel_data.handroid` 是 Android Bionic 库中用于测试 `floor` 函数的数据文件。`floor` 函数是一个标准的 C 库数学函数，它返回不大于其参数的最大整数值。

**功能列举:**

1. **提供 `floor` 函数的测试数据:**  该文件定义了一个静态数组 `g_floor_intel_data`，其中包含了多组 `double` 类型的输入值和期望的输出值。这些数据用于测试 `floor` 函数在各种输入情况下的正确性。
2. **针对特定架构的测试数据:** 文件名中的 "intel" 表明这些测试数据可能特别关注在 Intel 架构上的 `floor` 函数实现。这可能是因为不同架构在浮点数运算上可能存在细微差异，需要针对性测试。
3. **覆盖各种边界和特殊情况:**  观察数组中的数据，可以发现它覆盖了正数、负数、零、非常小的值、非常大的值、以及接近整数的值等各种情况，旨在全面测试 `floor` 函数的鲁棒性和精度。

**与 Android 功能的关系及举例说明:**

`floor` 函数是标准 C 库的一部分，而 Bionic 是 Android 系统的 C 库。因此，任何在 Android 上运行的 native 代码（使用 NDK 开发的应用）或 Android 系统框架本身都可能使用到 `floor` 函数。

*   **Android Framework:**  例如，在图形界面处理中，计算某个 View 的位置或大小可能需要将浮点数转换为整数，这时就可能使用 `floor` 函数。假设一个动画计算出 View 的 Y 坐标为 10.7 像素，那么在实际绘制时，可能需要使用 `floor(10.7)` 得到 10，以便将 View 绘制在屏幕上的整数像素位置。
*   **NDK 应用:**  一个游戏开发者使用 NDK 开发了一个物理引擎，其中计算物体的碰撞位置时得到一个浮点数坐标 5.3。为了确定物体实际所在的网格单元（假设网格是整数坐标），可以使用 `floor(5.3)` 得到 5。

**详细解释 `libc` 函数 `floor` 的功能是如何实现的:**

`floor` 函数的实现通常依赖于硬件的浮点数运算单元 (FPU) 或软件模拟。其基本思想是找到小于或等于输入浮点数的最大整数。

以下是 `floor` 函数一种可能的实现逻辑（简化版）：

1. **处理特殊情况:**
    *   如果输入是 NaN (Not a Number)，则返回 NaN。
    *   如果输入是正无穷大，则返回正无穷大。
    *   如果输入是负无穷大，则返回负无穷大。
    *   如果输入是正零或负零，则返回正零或负零。
2. **检查是否已经是整数:** 如果输入浮点数的 fractional part（小数部分）为零，则直接返回该浮点数。
3. **处理正数:** 如果输入是正数，则简单地截断小数部分即可。例如，对于 3.7，截断后得到 3.0。
4. **处理负数:** 如果输入是负数，则需要向负无穷方向取整。例如，对于 -3.7，截断后是 -3.0，但 `floor(-3.7)` 应该返回 -4.0。因此，对于负数，通常先截断，然后减去 1。

**注意:** 实际的 `floor` 实现会考虑各种优化和精度问题，并且可能直接利用硬件指令来完成。

**涉及 dynamic linker 的功能:**

虽然这个特定的数据文件不直接涉及 dynamic linker 的功能，但 `floor` 函数本身是 `libc.so` 共享库的一部分，它的加载和链接是由 dynamic linker 负责的。

**so 布局样本:**

假设 `libc.so` 的一个简化布局如下：

```
libc.so:
    .text:  // 存放代码段
        ...
        floor:   // floor 函数的机器码
            ...
        ...
    .data:  // 存放已初始化的全局变量和静态变量
        ...
    .bss:   // 存放未初始化的全局变量和静态变量
        ...
    .dynsym: // 动态符号表，包含导出的符号信息，如 floor 函数
        ...
        floor
        ...
    .dynstr: // 动态字符串表，存储符号名称等字符串
        ...
        floor
        ...
    .rel.dyn: // 动态重定位表
        ...
```

**链接的处理过程:**

1. **应用启动:** 当一个 Android 应用启动时，操作系统会加载应用的 executable 文件。
2. **依赖查找:**  Executable 文件中会记录它依赖的共享库，例如 `libc.so`。Dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会被调用来加载这些依赖库。
3. **加载共享库:** Dynamic linker 会找到 `libc.so` 文件，将其加载到内存中。
4. **符号解析:** 当应用代码调用 `floor` 函数时，链接器需要找到 `floor` 函数在 `libc.so` 中的地址。这个过程称为符号解析。
    *   应用的 executable 文件中会有一个 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table)。
    *   第一次调用 `floor` 时，会通过 PLT 跳转到链接器。
    *   链接器在 `libc.so` 的 `.dynsym` 中查找 `floor` 符号，获取其在 `.text` 段中的地址。
    *   链接器将 `floor` 函数的地址写入 GOT 中对应的条目。
    *   后续对 `floor` 的调用会直接通过 GOT 跳转到 `floor` 函数的实际地址。

**假设输入与输出 (逻辑推理):**

这个数据文件本身就是一系列的假设输入和期望输出。例如：

*   **假设输入:** `-0x1.p0` (表示 -1.0)
    *   **预期输出:** `-0x1.0p-1074` (一个非常接近 -0 的值，可能代表某些特殊处理或精度问题)
*   **假设输入:** `0.0`
    *   **预期输出:** `0x1.0p-1074` (一个非常接近 0 的值，可能代表某些特殊处理或精度问题)
*   **假设输入:** `0x1.p0` (表示 1.0)
    *   **预期输出:** `0x1.0p0` (表示 1.0)
*   **假设输入:** `-0x1.p1` (表示 -2.0)
    *   **预期输出:** `-0x1.0p1` (表示 -2.0)
*   **假设输入:** `0x1.fffffff8p30` (一个接近 2<sup>30+1</sup> 的值)
    *   **预期输出:** `0x1.fffffffbfffffp30` (比输入略大的值，说明 `floor` 会向下取整)

**用户或编程常见的使用错误:**

1. **对负数的理解错误:** 很多初学者可能会认为 `floor(-3.7)` 应该返回 -3，但实际上返回的是 -4。
2. **类型转换问题:** 有时用户可能会忘记 `floor` 函数返回的是 `double` 类型，即使结果是整数。如果直接将结果赋值给 `int` 类型，可能会发生截断，例如 `int x = floor(3.7);`  `x` 的值将是 3。
3. **精度问题:** 虽然 `floor` 本身不会引入精度问题，但在进行浮点数运算时，可能会因为精度损失导致 `floor` 的结果不是预期的。例如，如果一个计算结果本应是 3.0，但由于精度问题变成了 2.99999，那么 `floor(2.99999)` 将会是 2。

**Android Framework 或 NDK 如何一步步到达这里:**

**Android Framework 示例 (Java):**

```java
// 假设在某个 Android Framework 的 Java 代码中
double yCoordinate = calculateViewY(); // 计算得到一个浮点数 Y 坐标
int flooredY = (int) Math.floor(yCoordinate); // 使用 Math.floor 进行向下取整
```

1. **`java.lang.Math.floor(double a)`:**  Java 中的 `Math.floor` 方法会被调用。
2. **Native Method 调用:** `java.lang.Math.floor` 是一个 native 方法，它会通过 JNI (Java Native Interface) 调用到 Android 运行时的 native 代码。
3. **`libjavacore.so` 或相关库:**  在 Android 运行时中，可能会调用到 `libjavacore.so` 或其他相关库中实现的 `Math.floor` 的 native 版本。
4. **Bionic `floor` 调用:**  `libjavacore.so` 中的实现最终会调用到 Bionic 提供的 `floor` 函数（位于 `libc.so` 中）。

**NDK 示例 (C++):**

```c++
// 假设在 NDK 开发的 C++ 代码中
#include <cmath>

double position = 5.3;
int cellIndex = static_cast<int>(std::floor(position));
```

1. **包含头文件:**  开发者需要在 C++ 代码中包含 `<cmath>` 头文件以使用 `std::floor` 函数。
2. **调用 `std::floor`:**  代码中直接调用了 `std::floor` 函数。
3. **Bionic `floor` 调用:**  `std::floor` 通常是 `floor` 函数的一个封装或者直接就是 `floor` 函数，最终会链接到 Bionic 的 `floor` 实现。

**Frida Hook 示例调试步骤:**

```python
import frida
import sys

package_name = "your.package.name"  # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "floor"), {
    onEnter: function(args) {
        var input = args[0];
        console.log("[Floor Hook] Input: " + input);
        this.input = input;
    },
    onLeave: function(retval) {
        console.log("[Floor Hook] Output: " + retval + ", Input: " + this.input);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 调试步骤说明:**

1. **导入 Frida 库:**  导入 `frida` 和 `sys` 库。
2. **指定包名:** 将 `your.package.name` 替换为你要调试的 Android 应用的包名。
3. **连接设备并附加进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的应用进程。
4. **编写 Frida 脚本:**
    *   `Module.findExportByName("libc.so", "floor")`:  找到 `libc.so` 库中导出的 `floor` 函数的地址。
    *   `Interceptor.attach(...)`:  拦截对 `floor` 函数的调用。
    *   `onEnter`:  在 `floor` 函数被调用之前执行，记录输入参数。
    *   `onLeave`:  在 `floor` 函数返回之后执行，记录返回值和输入参数。
5. **创建和加载脚本:** 使用 `session.create_script(script_code)` 创建脚本，并通过 `script.load()` 加载到目标进程中。
6. **监听消息:**  `script.on('message', on_message)` 设置消息处理函数，用于接收脚本输出的日志。
7. **保持运行:** `sys.stdin.read()` 使脚本保持运行状态，直到手动停止。

运行此 Frida 脚本后，当目标应用调用 `floor` 函数时，你将在终端看到 Hook 到的输入参数和返回值，从而可以调试 `floor` 函数的调用情况。 这可以帮助理解 Framework 或 NDK 代码如何一步步地调用到 Bionic 的 `floor` 实现，以及传递的参数值。

### 提示词
```
这是目录为bionic/tests/math_data/floor_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_floor_intel_data[] = {
  { // Entry 0
    -0x1.p0,
    -0x1.0p-1074
  },
  { // Entry 1
    -0.0,
    -0.0
  },
  { // Entry 2
    0.0,
    0x1.0p-1074
  },
  { // Entry 3
    0.0,
    0x1.fffffffffffffp-2
  },
  { // Entry 4
    0.0,
    0x1.0p-1
  },
  { // Entry 5
    0.0,
    0x1.0000000000001p-1
  },
  { // Entry 6
    0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 7
    0x1.p0,
    0x1.0p0
  },
  { // Entry 8
    0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 9
    0x1.p0,
    0x1.7ffffffffffffp0
  },
  { // Entry 10
    0x1.p0,
    0x1.8p0
  },
  { // Entry 11
    0x1.p0,
    0x1.8000000000001p0
  },
  { // Entry 12
    0x1.p0,
    0x1.fffffffffffffp0
  },
  { // Entry 13
    0x1.p1,
    0x1.0p1
  },
  { // Entry 14
    0x1.p1,
    0x1.0000000000001p1
  },
  { // Entry 15
    0x1.p1,
    0x1.3ffffffffffffp1
  },
  { // Entry 16
    0x1.p1,
    0x1.4p1
  },
  { // Entry 17
    0x1.p1,
    0x1.4000000000001p1
  },
  { // Entry 18
    0x1.8cp6,
    0x1.8ffffffffffffp6
  },
  { // Entry 19
    0x1.90p6,
    0x1.9p6
  },
  { // Entry 20
    0x1.90p6,
    0x1.9000000000001p6
  },
  { // Entry 21
    0x1.90p6,
    0x1.91fffffffffffp6
  },
  { // Entry 22
    0x1.90p6,
    0x1.920p6
  },
  { // Entry 23
    0x1.90p6,
    0x1.9200000000001p6
  },
  { // Entry 24
    0x1.f380p9,
    0x1.f3fffffffffffp9
  },
  { // Entry 25
    0x1.f4p9,
    0x1.f40p9
  },
  { // Entry 26
    0x1.f4p9,
    0x1.f400000000001p9
  },
  { // Entry 27
    0x1.f4p9,
    0x1.f43ffffffffffp9
  },
  { // Entry 28
    0x1.f4p9,
    0x1.f44p9
  },
  { // Entry 29
    0x1.f4p9,
    0x1.f440000000001p9
  },
  { // Entry 30
    0x1.ffffffffffff80p49,
    0x1.fffffffffffffp49
  },
  { // Entry 31
    0x1.p50,
    0x1.0p50
  },
  { // Entry 32
    0x1.p50,
    0x1.0000000000001p50
  },
  { // Entry 33
    0x1.ffffffffffffc0p50,
    0x1.fffffffffffffp50
  },
  { // Entry 34
    0x1.p51,
    0x1.0p51
  },
  { // Entry 35
    0x1.p51,
    0x1.0000000000001p51
  },
  { // Entry 36
    0x1.ffffffffffffe0p51,
    0x1.fffffffffffffp51
  },
  { // Entry 37
    0x1.p52,
    0x1.0p52
  },
  { // Entry 38
    0x1.00000000000010p52,
    0x1.0000000000001p52
  },
  { // Entry 39
    0x1.fffffffffffff0p52,
    0x1.fffffffffffffp52
  },
  { // Entry 40
    0x1.p53,
    0x1.0p53
  },
  { // Entry 41
    0x1.00000000000010p53,
    0x1.0000000000001p53
  },
  { // Entry 42
    0x1.fffffffffffff0p53,
    0x1.fffffffffffffp53
  },
  { // Entry 43
    0x1.p54,
    0x1.0p54
  },
  { // Entry 44
    0x1.00000000000010p54,
    0x1.0000000000001p54
  },
  { // Entry 45
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 46
    -0x1.p0,
    -0x1.0000000000001p-1
  },
  { // Entry 47
    -0x1.p0,
    -0x1.0p-1
  },
  { // Entry 48
    -0x1.p0,
    -0x1.fffffffffffffp-2
  },
  { // Entry 49
    -0x1.p1,
    -0x1.0000000000001p0
  },
  { // Entry 50
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 51
    -0x1.p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 52
    -0x1.p1,
    -0x1.8000000000001p0
  },
  { // Entry 53
    -0x1.p1,
    -0x1.8p0
  },
  { // Entry 54
    -0x1.p1,
    -0x1.7ffffffffffffp0
  },
  { // Entry 55
    -0x1.80p1,
    -0x1.0000000000001p1
  },
  { // Entry 56
    -0x1.p1,
    -0x1.0p1
  },
  { // Entry 57
    -0x1.p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 58
    -0x1.80p1,
    -0x1.4000000000001p1
  },
  { // Entry 59
    -0x1.80p1,
    -0x1.4p1
  },
  { // Entry 60
    -0x1.80p1,
    -0x1.3ffffffffffffp1
  },
  { // Entry 61
    -0x1.94p6,
    -0x1.9000000000001p6
  },
  { // Entry 62
    -0x1.90p6,
    -0x1.9p6
  },
  { // Entry 63
    -0x1.90p6,
    -0x1.8ffffffffffffp6
  },
  { // Entry 64
    -0x1.94p6,
    -0x1.9200000000001p6
  },
  { // Entry 65
    -0x1.94p6,
    -0x1.920p6
  },
  { // Entry 66
    -0x1.94p6,
    -0x1.91fffffffffffp6
  },
  { // Entry 67
    -0x1.f480p9,
    -0x1.f400000000001p9
  },
  { // Entry 68
    -0x1.f4p9,
    -0x1.f40p9
  },
  { // Entry 69
    -0x1.f4p9,
    -0x1.f3fffffffffffp9
  },
  { // Entry 70
    -0x1.f480p9,
    -0x1.f440000000001p9
  },
  { // Entry 71
    -0x1.f480p9,
    -0x1.f44p9
  },
  { // Entry 72
    -0x1.f480p9,
    -0x1.f43ffffffffffp9
  },
  { // Entry 73
    -0x1.00000000000040p50,
    -0x1.0000000000001p50
  },
  { // Entry 74
    -0x1.p50,
    -0x1.0p50
  },
  { // Entry 75
    -0x1.p50,
    -0x1.fffffffffffffp49
  },
  { // Entry 76
    -0x1.00000000000020p51,
    -0x1.0000000000001p51
  },
  { // Entry 77
    -0x1.p51,
    -0x1.0p51
  },
  { // Entry 78
    -0x1.p51,
    -0x1.fffffffffffffp50
  },
  { // Entry 79
    -0x1.00000000000010p52,
    -0x1.0000000000001p52
  },
  { // Entry 80
    -0x1.p52,
    -0x1.0p52
  },
  { // Entry 81
    -0x1.p52,
    -0x1.fffffffffffffp51
  },
  { // Entry 82
    -0x1.00000000000010p53,
    -0x1.0000000000001p53
  },
  { // Entry 83
    -0x1.p53,
    -0x1.0p53
  },
  { // Entry 84
    -0x1.fffffffffffff0p52,
    -0x1.fffffffffffffp52
  },
  { // Entry 85
    -0x1.00000000000010p54,
    -0x1.0000000000001p54
  },
  { // Entry 86
    -0x1.p54,
    -0x1.0p54
  },
  { // Entry 87
    -0x1.fffffffffffff0p53,
    -0x1.fffffffffffffp53
  },
  { // Entry 88
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 89
    0x1.fffffff8p29,
    0x1.fffffffffffffp29
  },
  { // Entry 90
    0x1.p30,
    0x1.0p30
  },
  { // Entry 91
    0x1.p30,
    0x1.0000000000001p30
  },
  { // Entry 92
    0x1.fffffff4p30,
    0x1.fffffff7ffffep30
  },
  { // Entry 93
    0x1.fffffff4p30,
    0x1.fffffff7fffffp30
  },
  { // Entry 94
    0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 95
    0x1.fffffff8p30,
    0x1.fffffff800001p30
  },
  { // Entry 96
    0x1.fffffff8p30,
    0x1.fffffff800002p30
  },
  { // Entry 97
    0x1.fffffff8p30,
    0x1.fffffff9ffffep30
  },
  { // Entry 98
    0x1.fffffff8p30,
    0x1.fffffff9fffffp30
  },
  { // Entry 99
    0x1.fffffff8p30,
    0x1.fffffffa0p30
  },
  { // Entry 100
    0x1.fffffff8p30,
    0x1.fffffffa00001p30
  },
  { // Entry 101
    0x1.fffffff8p30,
    0x1.fffffffa00002p30
  },
  { // Entry 102
    0x1.fffffff8p30,
    0x1.fffffffbffffep30
  },
  { // Entry 103
    0x1.fffffff8p30,
    0x1.fffffffbfffffp30
  },
  { // Entry 104
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 105
    0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 106
    0x1.fffffffcp30,
    0x1.fffffffc00002p30
  },
  { // Entry 107
    0x1.fffffffcp30,
    0x1.fffffffdffffep30
  },
  { // Entry 108
    0x1.fffffffcp30,
    0x1.fffffffdfffffp30
  },
  { // Entry 109
    0x1.fffffffcp30,
    0x1.fffffffe0p30
  },
  { // Entry 110
    0x1.fffffffcp30,
    0x1.fffffffe00001p30
  },
  { // Entry 111
    0x1.fffffffcp30,
    0x1.fffffffe00002p30
  },
  { // Entry 112
    0x1.fffffffcp30,
    0x1.ffffffffffffep30
  },
  { // Entry 113
    0x1.fffffffcp30,
    0x1.fffffffffffffp30
  },
  { // Entry 114
    0x1.p31,
    0x1.0p31
  },
  { // Entry 115
    0x1.p31,
    0x1.0000000000001p31
  },
  { // Entry 116
    0x1.p31,
    0x1.0000000000002p31
  },
  { // Entry 117
    0x1.p31,
    0x1.00000000ffffep31
  },
  { // Entry 118
    0x1.p31,
    0x1.00000000fffffp31
  },
  { // Entry 119
    0x1.p31,
    0x1.000000010p31
  },
  { // Entry 120
    0x1.p31,
    0x1.0000000100001p31
  },
  { // Entry 121
    0x1.p31,
    0x1.0000000100002p31
  },
  { // Entry 122
    0x1.ffffffe0p30,
    0x1.ffffffep30
  },
  { // Entry 123
    0x1.ffffffe4p30,
    0x1.ffffffe40p30
  },
  { // Entry 124
    0x1.ffffffe8p30,
    0x1.ffffffe80p30
  },
  { // Entry 125
    0x1.ffffffecp30,
    0x1.ffffffec0p30
  },
  { // Entry 126
    0x1.fffffff0p30,
    0x1.fffffffp30
  },
  { // Entry 127
    0x1.fffffff4p30,
    0x1.fffffff40p30
  },
  { // Entry 128
    0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 129
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 130
    0x1.p31,
    0x1.0p31
  },
  { // Entry 131
    0x1.00000002p31,
    0x1.000000020p31
  },
  { // Entry 132
    -0x1.00000004p30,
    -0x1.0000000000001p30
  },
  { // Entry 133
    -0x1.p30,
    -0x1.0p30
  },
  { // Entry 134
    -0x1.p30,
    -0x1.fffffffffffffp29
  },
  { // Entry 135
    -0x1.fffffffcp30,
    -0x1.fffffff800002p30
  },
  { // Entry 136
    -0x1.fffffffcp30,
    -0x1.fffffff800001p30
  },
  { // Entry 137
    -0x1.fffffff8p30,
    -0x1.fffffff80p30
  },
  { // Entry 138
    -0x1.fffffff8p30,
    -0x1.fffffff7fffffp30
  },
  { // Entry 139
    -0x1.fffffff8p30,
    -0x1.fffffff7ffffep30
  },
  { // Entry 140
    -0x1.fffffffcp30,
    -0x1.fffffffa00002p30
  },
  { // Entry 141
    -0x1.fffffffcp30,
    -0x1.fffffffa00001p30
  },
  { // Entry 142
    -0x1.fffffffcp30,
    -0x1.fffffffa0p30
  },
  { // Entry 143
    -0x1.fffffffcp30,
    -0x1.fffffff9fffffp30
  },
  { // Entry 144
    -0x1.fffffffcp30,
    -0x1.fffffff9ffffep30
  },
  { // Entry 145
    -0x1.p31,
    -0x1.fffffffc00002p30
  },
  { // Entry 146
    -0x1.p31,
    -0x1.fffffffc00001p30
  },
  { // Entry 147
    -0x1.fffffffcp30,
    -0x1.fffffffc0p30
  },
  { // Entry 148
    -0x1.fffffffcp30,
    -0x1.fffffffbfffffp30
  },
  { // Entry 149
    -0x1.fffffffcp30,
    -0x1.fffffffbffffep30
  },
  { // Entry 150
    -0x1.p31,
    -0x1.fffffffe00002p30
  },
  { // Entry 151
    -0x1.p31,
    -0x1.fffffffe00001p30
  },
  { // Entry 152
    -0x1.p31,
    -0x1.fffffffe0p30
  },
  { // Entry 153
    -0x1.p31,
    -0x1.fffffffdfffffp30
  },
  { // Entry 154
    -0x1.p31,
    -0x1.fffffffdffffep30
  },
  { // Entry 155
    -0x1.00000002p31,
    -0x1.0000000000002p31
  },
  { // Entry 156
    -0x1.00000002p31,
    -0x1.0000000000001p31
  },
  { // Entry 157
    -0x1.p31,
    -0x1.0p31
  },
  { // Entry 158
    -0x1.p31,
    -0x1.fffffffffffffp30
  },
  { // Entry 159
    -0x1.p31,
    -0x1.ffffffffffffep30
  },
  { // Entry 160
    -0x1.00000002p31,
    -0x1.0000000100002p31
  },
  { // Entry 161
    -0x1.00000002p31,
    -0x1.0000000100001p31
  },
  { // Entry 162
    -0x1.00000002p31,
    -0x1.000000010p31
  },
  { // Entry 163
    -0x1.00000002p31,
    -0x1.00000000fffffp31
  },
  { // Entry 164
    -0x1.00000002p31,
    -0x1.00000000ffffep31
  },
  { // Entry 165
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 166
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 167
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 168
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 169
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 170
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 171
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 172
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 173
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 174
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 175
    0x1.ffffffffffffe0p61,
    0x1.ffffffffffffep61
  },
  { // Entry 176
    0x1.fffffffffffff0p61,
    0x1.fffffffffffffp61
  },
  { // Entry 177
    0x1.p62,
    0x1.0p62
  },
  { // Entry 178
    0x1.00000000000010p62,
    0x1.0000000000001p62
  },
  { // Entry 179
    0x1.00000000000020p62,
    0x1.0000000000002p62
  },
  { // Entry 180
    0x1.ffffffffffffe0p62,
    0x1.ffffffffffffep62
  },
  { // Entry 181
    0x1.fffffffffffff0p62,
    0x1.fffffffffffffp62
  },
  { // Entry 182
    0x1.p63,
    0x1.0p63
  },
  { // Entry 183
    0x1.00000000000010p63,
    0x1.0000000000001p63
  },
  { // Entry 184
    0x1.00000000000020p63,
    0x1.0000000000002p63
  },
  { // Entry 185
    0x1.ffffffffffffe0p63,
    0x1.ffffffffffffep63
  },
  { // Entry 186
    0x1.fffffffffffff0p63,
    0x1.fffffffffffffp63
  },
  { // Entry 187
    0x1.p64,
    0x1.0p64
  },
  { // Entry 188
    0x1.00000000000010p64,
    0x1.0000000000001p64
  },
  { // Entry 189
    0x1.00000000000020p64,
    0x1.0000000000002p64
  },
  { // Entry 190
    -0x1.00000000000020p62,
    -0x1.0000000000002p62
  },
  { // Entry 191
    -0x1.00000000000010p62,
    -0x1.0000000000001p62
  },
  { // Entry 192
    -0x1.p62,
    -0x1.0p62
  },
  { // Entry 193
    -0x1.fffffffffffff0p61,
    -0x1.fffffffffffffp61
  },
  { // Entry 194
    -0x1.ffffffffffffe0p61,
    -0x1.ffffffffffffep61
  },
  { // Entry 195
    -0x1.00000000000020p63,
    -0x1.0000000000002p63
  },
  { // Entry 196
    -0x1.00000000000010p63,
    -0x1.0000000000001p63
  },
  { // Entry 197
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 198
    -0x1.fffffffffffff0p62,
    -0x1.fffffffffffffp62
  },
  { // Entry 199
    -0x1.ffffffffffffe0p62,
    -0x1.ffffffffffffep62
  },
  { // Entry 200
    -0x1.00000000000020p64,
    -0x1.0000000000002p64
  },
  { // Entry 201
    -0x1.00000000000010p64,
    -0x1.0000000000001p64
  },
  { // Entry 202
    -0x1.p64,
    -0x1.0p64
  },
  { // Entry 203
    -0x1.fffffffffffff0p63,
    -0x1.fffffffffffffp63
  },
  { // Entry 204
    -0x1.ffffffffffffe0p63,
    -0x1.ffffffffffffep63
  },
  { // Entry 205
    0x1.p62,
    0x1.0p62
  },
  { // Entry 206
    0x1.p63,
    0x1.0p63
  },
  { // Entry 207
    -0x1.p62,
    -0x1.0p62
  },
  { // Entry 208
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 209
    0x1.fffffff8p30,
    0x1.fffffffbfffffp30
  },
  { // Entry 210
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 211
    0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 212
    -0x1.00000002p31,
    -0x1.0000000000001p31
  },
  { // Entry 213
    -0x1.p31,
    -0x1.0p31
  },
  { // Entry 214
    -0x1.p31,
    -0x1.fffffffffffffp30
  },
  { // Entry 215
    0x1.80p1,
    0x1.fffffffffffffp1
  },
  { // Entry 216
    0x1.p2,
    0x1.0p2
  },
  { // Entry 217
    0x1.p2,
    0x1.0000000000001p2
  },
  { // Entry 218
    0x1.c0p2,
    0x1.fffffffffffffp2
  },
  { // Entry 219
    0x1.p3,
    0x1.0p3
  },
  { // Entry 220
    0x1.p3,
    0x1.0000000000001p3
  },
  { // Entry 221
    0x1.e0p3,
    0x1.fffffffffffffp3
  },
  { // Entry 222
    0x1.p4,
    0x1.0p4
  },
  { // Entry 223
    0x1.p4,
    0x1.0000000000001p4
  },
  { // Entry 224
    0x1.f0p4,
    0x1.fffffffffffffp4
  },
  { // Entry 225
    0x1.p5,
    0x1.0p5
  },
  { // Entry 226
    0x1.p5,
    0x1.0000000000001p5
  },
  { // Entry 227
    0x1.f8p5,
    0x1.fffffffffffffp5
  },
  { // Entry 228
    0x1.p6,
    0x1.0p6
  },
  { // Entry 229
    0x1.p6,
    0x1.0000000000001p6
  },
  { // Entry 230
    0x1.fcp6,
    0x1.fffffffffffffp6
  },
  { // Entry 231
    0x1.p7,
    0x1.0p7
  },
  { // Entry 232
    0x1.p7,
    0x1.0000000000001p7
  },
  { // Entry 233
    0x1.fep7,
    0x1.fffffffffffffp7
  },
  { // Entry 234
    0x1.p8,
    0x1.0p8
  },
  { // Entry 235
    0x1.p8,
    0x1.0000000000001p8
  },
  { // Entry 236
    0x1.ffp8,
    0x1.fffffffffffffp8
  },
  { // Entry 237
    0x1.p9,
    0x1.0p9
  },
  { // Entry 238
    0x1.p9,
    0x1.0000000000001p9
  },
  { // Entry 239
    0x1.ff80p9,
    0x1.fffffffffffffp9
  },
  { // Entry 240
    0x1.p10,
    0x1.0p10
  },
  { // Entry 241
    0x1.p10,
    0x1.0000000000001p10
  },
  { // Entry 242
    0x1.ffc0p10,
    0x1.fffffffffffffp10
  },
  { // Entry 243
    0x1.p11,
    0x1.0p11
  },
  { // Entry 244
    0x1.p11,
    0x1.0000000000001p11
  },
  { // Entry 245
    0x1.ffe0p11,
    0x1.fffffffffffffp11
  },
  { // Entry 246
    0x1.p12,
    0x1.0p12
  },
  { // Entry 247
    0x1.p12,
    0x1.0000000000001p12
  },
  { // Entry 248
    0x1.p2,
    0x1.1ffffffffffffp2
  },
  { // Entry 249
    0x1.p2,
    0x1.2p2
  },
  { // Entry 250
    0x1.p2,
    0x1.2000000000001p2
  },
  { // Entry 251
    0x1.p3,
    0x1.0ffffffffffffp3
  },
  { // Entry 252
    0x1.p3,
    0x1.1p3
  },
  { // Entry 253
    0x1.p3,
    0x1.1000000000001p3
  },
  { // Entry 254
    0x1.p4,
    0x1.07fffffffffffp4
  },
  { // Entry 255
    0x1.p4,
    0x1.080p4
  },
  { // Entry 256
    0x1.p4,
    0x1.0800000000001p4
  },
  { // Entry 257
    0x1.p5,
    0x1.03fffffffffffp5
  },
  { // Entry 258
    0x1.p5,
    0x1.040p5
  },
  { // Entry 259
    0x1.p5,
    0x1.0400000000001p5
  },
  { // Entry 260
    0x1.p6,
    0x1.01fffffffffffp6
  },
  { // Entry 261
    0x1.p6,
    0x1.020p6
  },
  { // Entry 262
    0x1.p6,
    0x1.0200000000001p6
  },
  { // Entry 263
    0x1.p7,
    0x1.00fffffffffffp7
  },
  { // Entry 264
    0x1.p7,
    0x1.010p7
  },
  { // Entry 265
    0x1.p7,
    0x1.0100000000001p7
  },
  { // Entry 266
    0x1.p8,
    0x1.007ffffffffffp8
  },
  { // Entry 267
    0x1.p8,
    0x1.008p8
  },
  { // Entry 268
    0x1.p8,
    0x1.0080000000001p8
  },
  { // Entry 269
    0x1.p9,
    0x1.003ffffffffffp9
  },
  { // Entry 270
    0x1.p9,
    0x1.004p9
  },
  { // Entry 271
    0x1.p9,
    0x1.0040000000001p9
  },
  { // Entry 272
    0x1.p10,
    0x1.001ffffffffffp10
  },
  { // Entry 273
    0x1.p10,
    0x1.002p10
  },
  { // Entry 274
    0x1.p10,
    0x1.0020000000001p10
  },
  { // Entry 275
    0x1.0040p10,
    0x1.005ffffffffffp10
  },
  { // Entry 276
    0x1.0040p10,
    0x1.006p10
  },
  { // Entry 277
    0x1.0040p10,
    0x1.0060000000001p10
  },
  { // Entry 278
    0x1.p11,
    0x1.000ffffffffffp11
  },
  { // Entry 279
    0x1.p11,
    0x1.001p11
  },
  { // Entry 280
    0x1.p11,
    0x1.0010000000001p11
  },
  { // Entry 281
    0x1.p12,
    0x1.0007fffffffffp12
  },
  { // Entry 282
    0x1.p12,
    0x1.00080p12
  },
  { // Entry 283
    0x1.p12,
    0x1.0008000000001p12
  },
  { // Entry 284
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 285
    -HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 286
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 287
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 288
    0x1.ffffffffffffe0p1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 289
    -0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 290
    0x1.80p1,
    0x1.921fb54442d18p1
  },
  { // Entry 291
    -0x1.p2,
    -0x1.921fb54442d18p1
  },
  { // Entry 292
    0x1.p0,
    0x1.921fb54442d18p0
  },
  { // Entry 293
    -0x1.p1,
    -0x1.921fb54442d18p0
  },
  { // Entry 294
    0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 295
    -0x1.p1,
    -0x1.0000000000001p0
  },
  { // Entry 296
    0x1.p0,
    0x1.0p0
  },
  { // Entry 297
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 298
    0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 299
    -0x1.p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 300
    0.0,
    0x1.921fb54442d18p-1
  },
  { // Entry 301
    -0x1.p0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 302
    0.0,
    0x1.0000000000001p-1022
  },
  { // Entry 303
    -0x1.p0,
    -0x1.0000000000001p-1022
  },
  { // Entry 304
    0.0,
    0x1.0p-1022
  },
  { // Entry 305
    -0x1.p0,
    -0x1.0p-1022
  },
  { // Entry 306
    0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 307
    -0x1.p0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 308
    0.0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 309
    -0x1.p0,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 310
    0.0,
    0x1.0p-1073
  },
  { // Entry 311
    -0x1.p0,
    -0x1.0p-1073
  },
  { // Entry 312
    0.0,
    0x1.0p-1074
  },
  { // Entry 313
    -0x1.p0,
    -0x1.0p-1074
  },
  { // Entry 314
    0.0,
    0.0
  },
  { // Entry 315
    -0.0,
    -0.0
  },
  { // Entry 316
    0x1.p0,
    0x1.8p0
  },
  { // Entry 317
    -0x1.p1,
    -0x1.8p0
  },
  { // Entry 318
    0x1.p1,
    0x1.4p1
  },
  { // Entry 319
    -0x1.80p1,
    -0x1.4p1
  },
  { // Entry 320
    0.0,
    0x1.fffffp-2
  },
  { // Entry 321
    0.0,
    0x1.0p-1
  },
  { // Entry 322
    0.0,
    0x1.00001p-1
  },
  { // Entry 323
    -0x1.p0,
    -0x1.fffffp-2
  },
  { // Entry 324
    -0x1.p0,
    -0x1.0p-1
  },
  { // Entry 325
    -0x1.p0,
    -0x1.00001p-1
  },
  { // Entry 326
    0x1.p0,
    0x1.80001p0
  },
  { // Entry 327
    0x1.p0,
    0x1.7ffffp0
  },
  { // Entry 328
    -0x1.p1,
    -0x1.80001p0
  },
  { // Entry 329
    -0x1.p1,
    -0x1.7ffffp0
  }
};
```
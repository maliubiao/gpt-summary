Response:
Let's break down the thought process to answer the user's request about the `copysign_intel_data.handroid` file.

**1. Understanding the Request:**

The user wants a comprehensive analysis of the provided C code snippet, specifically the `g_copysign_intel_data` array. They are interested in:

* **Functionality:** What does this data array represent?
* **Android Relation:** How does it relate to Android's functionalities?
* **`libc` Function Implementation:** How is the `copysign` function implemented in `libc`?  (Even though the file *itself* doesn't implement `copysign`, it's clearly related, so addressing this is key).
* **Dynamic Linker (if applicable):** How does the dynamic linker play a role? (Initially, I might think this file has little to do with the dynamic linker, but the file's location within `bionic` hints at a connection to testing the `copysign` function *provided* by `libc`, which is loaded by the dynamic linker).
* **Logical Reasoning:** What are the expected inputs and outputs based on the data?
* **Common Usage Errors:** What mistakes might programmers make when using `copysign`?
* **Android Framework/NDK Path:** How does data end up being tested this way?  What's the chain of events?
* **Frida Hooking:** How can we observe this in action?

**2. Initial Code Analysis:**

The code defines a static array `g_copysign_intel_data` of a template type `data_1_2_t<double, double, double>`. Each element of the array is an initializer list containing three double-precision floating-point numbers. The comments `// Entry N` suggest these are test cases.

The naming `copysign_intel_data` strongly indicates these are test vectors specifically for the `copysign` function, likely targeting Intel architectures. The `.handroid` suffix likely signifies this is part of the Android testing infrastructure.

**3. Inferring Functionality:**

Based on the name and the structure of the data (three doubles), it's highly probable that:

* The first double in each entry is the *input value*.
* The second double is the *sign source*.
* The third double is the *expected output* of the `copysign` function.

The `copysign(x, y)` function returns `x` with the sign of `y`. This aligns perfectly with the three-double structure.

**4. Android Relationship:**

This data is part of Bionic, Android's C library. Therefore, it's directly related to how Android handles mathematical functions. The `copysign` function is a standard C math function, and Bionic provides its implementation. This data is used for *testing* that implementation.

**5. `libc` Function Implementation (Deeper Dive):**

While the data file itself doesn't *implement* `copysign`, the request prompts for its implementation. I need to think about how `copysign` works at a low level.

* **Bit Manipulation:** The most efficient way to change the sign of a floating-point number is by manipulating its sign bit.
* **IEEE 754:**  Double-precision floats follow the IEEE 754 standard. The sign bit is the most significant bit.
* **Implementation Strategy:** The `copysign` implementation likely involves:
    1. Extracting the sign bit of the second argument (`y`).
    2. Masking out the sign bit of the first argument (`x`).
    3. Combining the masked `x` with the sign bit of `y`.

**6. Dynamic Linker Connection:**

Although this *specific file* isn't directly involved in dynamic linking, it's testing a function (`copysign`) that resides within `libc.so`. The dynamic linker is responsible for loading `libc.so` into a process's memory space and resolving function calls to their correct addresses.

* **`libc.so` Layout:**  I should sketch a simplified `libc.so` structure showing code sections (.text) and data sections (.data, .rodata) where `copysign`'s code and potentially related data reside.
* **Linking Process:**  When an application calls `copysign`, the dynamic linker ensures the call is directed to the correct `copysign` implementation within `libc.so`. This involves symbol resolution.

**7. Logical Reasoning (Examples):**

I can take a few entries from the array and explain the expected behavior:

* `{-0x1.p-10, -0x1.0p-10, -0x1.0p-10}`: Input is negative, sign source is negative, output is negative.
* `{0x1.p-10, -0x1.0p-10, 0x1.0p-10}`: Input is positive, sign source is negative, output is positive with the negative sign applied.
* `{0.0, -0.0, 0x1.0p-1074}`: This seems *wrong* based on the definition of `copysign`. This highlights the importance of these test cases – they can reveal potential bugs or edge cases (like how implementations handle signed zeros). I should note this discrepancy and question if the "expected output" is actually intended for a different purpose in the test setup. (Further reflection: it's possible this test case is specifically designed to verify how `copysign` handles signed zero, and the "expected" value might be used in a comparison with a small epsilon, not for direct equality).

**8. Common Usage Errors:**

Programmers might misunderstand `copysign` and think it just returns the sign of the second argument or performs some other operation. Providing a simple example of incorrect usage clarifies this.

**9. Android Framework/NDK Path:**

How does this testing happen in Android development?

* **NDK:** Developers using the NDK might call `copysign` in their native code.
* **Framework:**  The Android framework itself, written in Java/Kotlin, might indirectly rely on `copysign` through native libraries.
* **Testing:**  Bionic has its own test suite. This data file is part of that suite. When Bionic is built and tested, these data points are used to verify the correctness of the `copysign` implementation.

**10. Frida Hooking:**

To demonstrate how this works at runtime, I can provide a Frida script that intercepts calls to `copysign` and logs the input arguments and the result. This allows observation of the function in action.

**11. Structuring the Answer:**

Finally, I need to organize the information logically, using clear headings and examples. I should address each part of the user's request directly. I should start with a high-level overview and then delve into specifics. Using code formatting for examples is also important.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption about `copysign` Output:**  I initially assumed the "expected output" was for strict equality. However, for edge cases like signed zero, I realized it might be used in a fuzzy comparison. This requires a more nuanced explanation.
* **Dynamic Linker Detail:** I initially thought the connection to the dynamic linker was minimal. However, realizing that `copysign` comes from `libc.so` made the connection more significant and worth explaining.
* **Frida Hooking Specifics:**  I need to ensure the Frida script is practical and demonstrates the relevant information (input arguments and return value).

By following this thought process, breaking down the request, analyzing the code, and making logical deductions, I can generate a comprehensive and accurate answer to the user's query.
这个文件 `bionic/tests/math_data/copysign_intel_data.handroid` 的主要功能是为 `copysign` 函数提供测试数据。它是一个静态数据数组，用于测试在 Intel 架构的 Android 设备上 `copysign` 函数的实现是否正确。

**功能列举：**

1. **提供 `copysign` 函数的测试用例：** 文件中定义了一个名为 `g_copysign_intel_data` 的静态数组，该数组包含了大量的测试用例。每个用例由三个 `double` 类型的值组成，分别代表 `copysign` 函数的第一个参数、第二个参数以及期望的返回值。
2. **针对 Intel 架构：** 文件名中的 `intel` 表明这些测试用例可能特别关注 Intel 处理器的特性或潜在问题。
3. **自动化测试：** 这些数据被用于自动化测试框架中，以确保 `copysign` 函数在各种输入情况下都能返回正确的结果。

**与 Android 功能的关系及举例说明：**

这个文件直接关系到 Android 系统中 C 标准库 (libc) 的数学函数实现。`copysign` 是 C 标准库 `<math.h>` 中定义的一个函数，其功能是将第一个参数的绝对值与第二个参数的符号组合起来。

* **libc 的一部分：**  Bionic 是 Android 的 C 库，包含了标准 C 库的实现，其中包括 `copysign` 函数。
* **数学运算的基础：** `copysign` 函数在很多数值计算中都很有用，例如在处理有符号数值、复数运算等场景。
* **确保平台一致性：** 通过大量的测试用例（例如这个文件提供的），Android 开发者可以确保 `copysign` 函数在不同的 Android 设备上（特别是 Intel 架构的设备）行为一致且正确。

**libc 函数 `copysign` 的功能实现：**

`copysign(x, y)` 函数的功能是返回一个数值，该数值的绝对值等于 `x` 的绝对值，而符号与 `y` 的符号相同。

**实现原理 (通常基于位操作)：**

由于浮点数在内存中是以 IEEE 754 标准格式存储的，`copysign` 的高效实现通常会利用位操作来直接修改浮点数的符号位。

1. **提取 `y` 的符号位：**  读取 `y` 的二进制表示，提取出符号位（通常是最高位）。
2. **清除 `x` 的符号位：** 读取 `x` 的二进制表示，将符号位清除（设置为正号）。
3. **组合符号位和绝对值：** 将 `y` 的符号位设置到清除了符号位的 `x` 上。

**假设输入与输出 (基于文件中的数据)：**

* **假设输入：** `x = -0x1.p-10`, `y = -0x1.0p-10`
* **期望输出：** `-0x1.0p-10` (与 `x` 的绝对值相同，符号与 `y` 相同)

* **假设输入：** `x = 0x1.p-10`, `y = -0x1.0p-10`
* **期望输出：** `0x1.0p-10` (与 `x` 的绝对值相同，符号与 `y` 相同)  **注意这里实际上是期望输出是负数，因为要和y的符号一致，文件中数据有误**

* **假设输入：** `x = -0.0`, `y = -0.0`
* **期望输出：** `-0.0`

* **假设输入：** `x = 0.0`, `y = -0.0`
* **期望输出：** `0.0`  **注意文件中该条数据的期望输出为 `0x1.0p-1074`，这可能是一个测试边界情况或者存在错误。通常 `copysign(0.0, -0.0)` 应该返回 `-0.0`。**

**涉及 dynamic linker 的功能 (虽然此文件本身不直接涉及)：**

虽然这个数据文件本身不涉及动态链接器的代码，但它测试的 `copysign` 函数是 `libc.so` (共享库) 的一部分，而 `libc.so` 的加载和链接是由动态链接器负责的。

**so 布局样本 (简化)：**

```
libc.so:
    .plt         // Procedure Linkage Table (用于延迟绑定)
        copysign@plt: ...
    .got.plt     // Global Offset Table (plt 部分)
        ...地址指向 copysign 的实际地址...
    .text        // 代码段
        copysign:
            ; ... copysign 函数的实现 ...
    .data        // 数据段
        ...
    .rodata      // 只读数据段
        ...
```

**链接的处理过程：**

1. **编译时：** 当应用程序或库链接到 `libc` 时，编译器会生成对 `copysign` 的调用，并将其放入代码段中。由于是外部符号，这里会使用 PLT 条目作为占位符。
2. **加载时：** 当 Android 系统加载应用程序时，动态链接器 (`linker64` 或 `linker`) 会负责加载所有依赖的共享库，包括 `libc.so`。
3. **符号解析：** 动态链接器会解析应用程序中对 `copysign` 的引用，找到 `libc.so` 中 `copysign` 函数的实际地址。
4. **GOT/PLT 重写：** 动态链接器会将 `copysign@plt` 对应的 GOT 条目更新为 `copysign` 函数在内存中的实际地址。
5. **函数调用：** 当程序执行到 `copysign` 的调用时，会先跳转到 PLT 条目，PLT 条目会通过 GOT 表找到函数的实际地址并跳转过去。这通常发生在第一次调用时（延迟绑定）。

**用户或编程常见的使用错误：**

1. **误解 `copysign` 的作用：**  可能错误地认为 `copysign` 只是简单地返回第二个参数的符号，而忽略了它会保持第一个参数的绝对值。
   ```c
   double x = 5.0;
   double y = -2.0;
   double result = copysign(y, x); // 错误理解：result 应该是正数
   // 正确结果：result 是 2.0 (abs(y) with sign of x)
   ```
2. **处理特殊值不当：**  对于 NaN (Not a Number) 和无穷大，`copysign` 的行为需要注意。例如，`copysign(NaN, -1.0)` 会返回负的 NaN。
3. **符号零的混淆：**  `copysign` 可以区分正零和负零。`copysign(1.0, -0.0)` 会返回 `-1.0`，而 `copysign(1.0, 0.0)` 返回 `1.0`。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **NDK 开发：** 开发者使用 NDK (Native Development Kit) 编写 C/C++ 代码，这些代码可能会调用 `copysign` 函数。
2. **编译 NDK 代码：** NDK 编译工具链会将 C/C++ 代码编译成机器码，并链接到 Android 系统的 `libc.so`。
3. **Framework 调用 Native 层：** Android Framework (Java/Kotlin 代码) 有时候需要执行一些底层操作，会通过 JNI (Java Native Interface) 调用 Native 层 (C/C++) 的代码。如果 Native 代码中使用了 `copysign`，最终会执行到 Bionic 库中的实现。
4. **Bionic 的构建和测试：** 在 Android 系统的构建过程中，Bionic 库会被编译，并且会运行各种测试用例来验证其正确性。这个 `copysign_intel_data.handroid` 文件就用于这个测试过程。
   - 构建系统会编译 Bionic 的测试代码。
   - 测试代码会读取 `copysign_intel_data.handroid` 中的数据。
   - 对于每个测试用例，测试代码会调用 Bionic 的 `copysign` 函数，并将其返回值与文件中期望的返回值进行比较。

**Frida hook 示例调试步骤：**

假设你想 hook `copysign` 函数来观察其输入和输出：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "copysign"), {
    onEnter: function(args) {
        this.arg0 = args[0];
        this.arg1 = args[1];
        send(`copysign called with arg0: ${args[0]}, arg1: ${args[1]}`);
    },
    onLeave: function(retval) {
        send(`copysign returned: ${retval}, arg0: ${this.arg0}, arg1: ${this.arg1}`);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤解释：**

1. **导入 Frida 库。**
2. **指定要调试的 Android 应用的包名。**
3. **定义消息处理函数 `on_message`，用于打印 Frida 发送的消息。**
4. **连接到 USB 设备上的目标应用进程。**
5. **编写 Frida 脚本：**
   - `Interceptor.attach`: 拦截对 `libc.so` 中 `copysign` 函数的调用。
   - `onEnter`: 在 `copysign` 函数被调用时执行。
     - 记录参数 `args[0]` 和 `args[1]`。
     - 使用 `send()` 函数发送消息，包含函数名和参数值。
   - `onLeave`: 在 `copysign` 函数返回时执行。
     - 记录返回值 `retval` 以及之前的参数值 (通过 `this`)。
     - 使用 `send()` 函数发送消息，包含函数名、参数值和返回值。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到用户按下 Ctrl+D。**

**运行这个 Frida 脚本后，当目标应用中的代码调用 `copysign` 函数时，你将在控制台上看到类似以下的输出：**

```
[*] copysign called with arg0: -0.125, arg1: -2
[*] copysign returned: -0.125, arg0: -0.125, arg1: -2
```

通过这种方式，你可以动态地观察 `copysign` 函数的输入和输出，从而帮助理解其行为和验证测试数据的正确性。

总而言之，`bionic/tests/math_data/copysign_intel_data.handroid` 文件是 Android 系统中用于测试 `copysign` 函数在 Intel 架构设备上实现正确性的重要组成部分，它体现了 Android 对系统库质量和平台一致性的严格要求。

### 提示词
```
这是目录为bionic/tests/math_data/copysign_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_2_t<double, double, double> g_copysign_intel_data[] = {
  { // Entry 0
    -0x1.p-10,
    -0x1.0p-10,
    -0x1.0p-10
  },
  { // Entry 1
    0x1.p-10,
    -0x1.0p-10,
    0x1.0p-10
  },
  { // Entry 2
    -0x1.p-10,
    0x1.0p-10,
    -0x1.0p-10
  },
  { // Entry 3
    0x1.p-10,
    0x1.0p-10,
    0x1.0p-10
  },
  { // Entry 4
    -0x1.40p3,
    -0x1.4p3,
    -0x1.4p3
  },
  { // Entry 5
    0x1.40p3,
    -0x1.4p3,
    0x1.4p3
  },
  { // Entry 6
    -0x1.40p3,
    0x1.4p3,
    -0x1.4p3
  },
  { // Entry 7
    0x1.40p3,
    0x1.4p3,
    0x1.4p3
  },
  { // Entry 8
    -0x1.p-1073,
    -0x1.0p-1073,
    -0x1.0p-1074
  },
  { // Entry 9
    -0x1.p-1073,
    -0x1.0p-1073,
    -0.0
  },
  { // Entry 10
    0x1.p-1073,
    -0x1.0p-1073,
    0x1.0p-1074
  },
  { // Entry 11
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 12
    -0x1.p-1074,
    -0x1.0p-1074,
    -0.0
  },
  { // Entry 13
    0x1.p-1074,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 14
    -0.0,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 15
    -0.0,
    -0.0,
    -0.0
  },
  { // Entry 16
    0.0,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 17
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 18
    -0x1.p-1074,
    0x1.0p-1074,
    -0.0
  },
  { // Entry 19
    0x1.p-1074,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 20
    -0x1.p-1073,
    0x1.0p-1073,
    -0x1.0p-1074
  },
  { // Entry 21
    -0x1.p-1073,
    0x1.0p-1073,
    -0.0
  },
  { // Entry 22
    0x1.p-1073,
    0x1.0p-1073,
    0x1.0p-1074
  },
  { // Entry 23
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 24
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 25
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 26
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 27
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 28
    -0.0,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 29
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 30
    0x1.p-1074,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 31
    0.0,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 32
    0x1.p-1074,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 33
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 34
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 35
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 36
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 37
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 38
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 39
    0x1.00000000000020p-1023,
    -0x1.0000000000002p-1023,
    0x1.ffffffffffffcp-1024
  },
  { // Entry 40
    0x1.00000000000020p-1023,
    -0x1.0000000000002p-1023,
    0x1.0p-1023
  },
  { // Entry 41
    0x1.00000000000020p-1023,
    -0x1.0000000000002p-1023,
    0x1.0000000000002p-1023
  },
  { // Entry 42
    0x1.p-1023,
    -0x1.0p-1023,
    0x1.ffffffffffffcp-1024
  },
  { // Entry 43
    0x1.p-1023,
    -0x1.0p-1023,
    0x1.0p-1023
  },
  { // Entry 44
    0x1.p-1023,
    -0x1.0p-1023,
    0x1.0000000000002p-1023
  },
  { // Entry 45
    0x1.ffffffffffffc0p-1024,
    -0x1.ffffffffffffcp-1024,
    0x1.ffffffffffffcp-1024
  },
  { // Entry 46
    0x1.ffffffffffffc0p-1024,
    -0x1.ffffffffffffcp-1024,
    0x1.0p-1023
  },
  { // Entry 47
    0x1.ffffffffffffc0p-1024,
    -0x1.ffffffffffffcp-1024,
    0x1.0000000000002p-1023
  },
  { // Entry 48
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 49
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 50
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 51
    0x1.p0,
    -0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 52
    0x1.p0,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 53
    0x1.p0,
    -0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 54
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 55
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 56
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 57
    0x1.00000000000010p1023,
    -0x1.0000000000001p1023,
    0x1.fffffffffffffp1022
  },
  { // Entry 58
    0x1.00000000000010p1023,
    -0x1.0000000000001p1023,
    0x1.0p1023
  },
  { // Entry 59
    0x1.00000000000010p1023,
    -0x1.0000000000001p1023,
    0x1.0000000000001p1023
  },
  { // Entry 60
    0x1.p1023,
    -0x1.0p1023,
    0x1.fffffffffffffp1022
  },
  { // Entry 61
    0x1.p1023,
    -0x1.0p1023,
    0x1.0p1023
  },
  { // Entry 62
    0x1.p1023,
    -0x1.0p1023,
    0x1.0000000000001p1023
  },
  { // Entry 63
    0x1.fffffffffffff0p1022,
    -0x1.fffffffffffffp1022,
    0x1.fffffffffffffp1022
  },
  { // Entry 64
    0x1.fffffffffffff0p1022,
    -0x1.fffffffffffffp1022,
    0x1.0p1023
  },
  { // Entry 65
    0x1.fffffffffffff0p1022,
    -0x1.fffffffffffffp1022,
    0x1.0000000000001p1023
  },
  { // Entry 66
    -0x1.ffffffffffffc0p-1024,
    0x1.ffffffffffffcp-1024,
    -0x1.0000000000002p-1023
  },
  { // Entry 67
    -0x1.ffffffffffffc0p-1024,
    0x1.ffffffffffffcp-1024,
    -0x1.0p-1023
  },
  { // Entry 68
    -0x1.ffffffffffffc0p-1024,
    0x1.ffffffffffffcp-1024,
    -0x1.ffffffffffffcp-1024
  },
  { // Entry 69
    -0x1.p-1023,
    0x1.0p-1023,
    -0x1.0000000000002p-1023
  },
  { // Entry 70
    -0x1.p-1023,
    0x1.0p-1023,
    -0x1.0p-1023
  },
  { // Entry 71
    -0x1.p-1023,
    0x1.0p-1023,
    -0x1.ffffffffffffcp-1024
  },
  { // Entry 72
    -0x1.00000000000020p-1023,
    0x1.0000000000002p-1023,
    -0x1.0000000000002p-1023
  },
  { // Entry 73
    -0x1.00000000000020p-1023,
    0x1.0000000000002p-1023,
    -0x1.0p-1023
  },
  { // Entry 74
    -0x1.00000000000020p-1023,
    0x1.0000000000002p-1023,
    -0x1.ffffffffffffcp-1024
  },
  { // Entry 75
    -0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 76
    -0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 77
    -0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 78
    -0x1.p0,
    0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 79
    -0x1.p0,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 80
    -0x1.p0,
    0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 81
    -0x1.00000000000010p0,
    0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 82
    -0x1.00000000000010p0,
    0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 83
    -0x1.00000000000010p0,
    0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 84
    -0x1.fffffffffffff0p1022,
    0x1.fffffffffffffp1022,
    -0x1.0000000000001p1023
  },
  { // Entry 85
    -0x1.fffffffffffff0p1022,
    0x1.fffffffffffffp1022,
    -0x1.0p1023
  },
  { // Entry 86
    -0x1.fffffffffffff0p1022,
    0x1.fffffffffffffp1022,
    -0x1.fffffffffffffp1022
  },
  { // Entry 87
    -0x1.p1023,
    0x1.0p1023,
    -0x1.0000000000001p1023
  },
  { // Entry 88
    -0x1.p1023,
    0x1.0p1023,
    -0x1.0p1023
  },
  { // Entry 89
    -0x1.p1023,
    0x1.0p1023,
    -0x1.fffffffffffffp1022
  },
  { // Entry 90
    -0x1.00000000000010p1023,
    0x1.0000000000001p1023,
    -0x1.0000000000001p1023
  },
  { // Entry 91
    -0x1.00000000000010p1023,
    0x1.0000000000001p1023,
    -0x1.0p1023
  },
  { // Entry 92
    -0x1.00000000000010p1023,
    0x1.0000000000001p1023,
    -0x1.fffffffffffffp1022
  },
  { // Entry 93
    HUGE_VAL,
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 94
    HUGE_VAL,
    HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 95
    HUGE_VAL,
    HUGE_VAL,
    0x1.0p-1022
  },
  { // Entry 96
    HUGE_VAL,
    HUGE_VAL,
    0x1.ffffffffffffep-1023
  },
  { // Entry 97
    HUGE_VAL,
    HUGE_VAL,
    0x1.0p-1074
  },
  { // Entry 98
    HUGE_VAL,
    HUGE_VAL,
    0.0
  },
  { // Entry 99
    -HUGE_VAL,
    HUGE_VAL,
    -0.0
  },
  { // Entry 100
    -HUGE_VAL,
    HUGE_VAL,
    -0x1.0p-1074
  },
  { // Entry 101
    -HUGE_VAL,
    HUGE_VAL,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 102
    -HUGE_VAL,
    HUGE_VAL,
    -0x1.0p-1022
  },
  { // Entry 103
    -HUGE_VAL,
    HUGE_VAL,
    -0x1.0p0
  },
  { // Entry 104
    -HUGE_VAL,
    HUGE_VAL,
    -0x1.fffffffffffffp1023
  },
  { // Entry 105
    -HUGE_VAL,
    HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 106
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    HUGE_VAL
  },
  { // Entry 107
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 108
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1022
  },
  { // Entry 109
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 110
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 111
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0.0
  },
  { // Entry 112
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 113
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 114
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 115
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p-1022
  },
  { // Entry 116
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.0p0
  },
  { // Entry 117
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 118
    -0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    -HUGE_VAL
  },
  { // Entry 119
    0x1.p-1022,
    0x1.0p-1022,
    HUGE_VAL
  },
  { // Entry 120
    0x1.p-1022,
    0x1.0p-1022,
    0x1.fffffffffffffp1023
  },
  { // Entry 121
    0x1.p-1022,
    0x1.0p-1022,
    0x1.0p-1022
  },
  { // Entry 122
    0x1.p-1022,
    0x1.0p-1022,
    0x1.ffffffffffffep-1023
  },
  { // Entry 123
    0x1.p-1022,
    0x1.0p-1022,
    0x1.0p-1074
  },
  { // Entry 124
    0x1.p-1022,
    0x1.0p-1022,
    0.0
  },
  { // Entry 125
    -0x1.p-1022,
    0x1.0p-1022,
    -0.0
  },
  { // Entry 126
    -0x1.p-1022,
    0x1.0p-1022,
    -0x1.0p-1074
  },
  { // Entry 127
    -0x1.p-1022,
    0x1.0p-1022,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 128
    -0x1.p-1022,
    0x1.0p-1022,
    -0x1.0p-1022
  },
  { // Entry 129
    -0x1.p-1022,
    0x1.0p-1022,
    -0x1.0p0
  },
  { // Entry 130
    -0x1.p-1022,
    0x1.0p-1022,
    -0x1.fffffffffffffp1023
  },
  { // Entry 131
    -0x1.p-1022,
    0x1.0p-1022,
    -HUGE_VAL
  },
  { // Entry 132
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    HUGE_VAL
  },
  { // Entry 133
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 134
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0x1.0p-1022
  },
  { // Entry 135
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 136
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0x1.0p-1074
  },
  { // Entry 137
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    0.0
  },
  { // Entry 138
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -0.0
  },
  { // Entry 139
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.0p-1074
  },
  { // Entry 140
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 141
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.0p-1022
  },
  { // Entry 142
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.0p0
  },
  { // Entry 143
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 144
    -0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023,
    -HUGE_VAL
  },
  { // Entry 145
    0x1.p-1074,
    0x1.0p-1074,
    HUGE_VAL
  },
  { // Entry 146
    0x1.p-1074,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 147
    0x1.p-1074,
    0x1.0p-1074,
    0x1.0p-1022
  },
  { // Entry 148
    0x1.p-1074,
    0x1.0p-1074,
    0x1.ffffffffffffep-1023
  },
  { // Entry 149
    0x1.p-1074,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 150
    0x1.p-1074,
    0x1.0p-1074,
    0.0
  },
  { // Entry 151
    -0x1.p-1074,
    0x1.0p-1074,
    -0.0
  },
  { // Entry 152
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 153
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 154
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.0p-1022
  },
  { // Entry 155
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.0p0
  },
  { // Entry 156
    -0x1.p-1074,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 157
    -0x1.p-1074,
    0x1.0p-1074,
    -HUGE_VAL
  },
  { // Entry 158
    0.0,
    0.0,
    HUGE_VAL
  },
  { // Entry 159
    0.0,
    0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 160
    0.0,
    0.0,
    0x1.0p-1022
  },
  { // Entry 161
    0.0,
    0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 162
    0.0,
    0.0,
    0x1.0p-1074
  },
  { // Entry 163
    0.0,
    0.0,
    0.0
  },
  { // Entry 164
    -0.0,
    0.0,
    -0.0
  },
  { // Entry 165
    -0.0,
    0.0,
    -0x1.0p-1074
  },
  { // Entry 166
    -0.0,
    0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 167
    -0.0,
    0.0,
    -0x1.0p-1022
  },
  { // Entry 168
    -0.0,
    0.0,
    -0x1.0p0
  },
  { // Entry 169
    -0.0,
    0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 170
    -0.0,
    0.0,
    -HUGE_VAL
  },
  { // Entry 171
    0.0,
    -0.0,
    HUGE_VAL
  },
  { // Entry 172
    0.0,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 173
    0.0,
    -0.0,
    0x1.0p-1022
  },
  { // Entry 174
    0.0,
    -0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 175
    0.0,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 176
    0.0,
    -0.0,
    0.0
  },
  { // Entry 177
    -0.0,
    -0.0,
    -0.0
  },
  { // Entry 178
    -0.0,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 179
    -0.0,
    -0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 180
    -0.0,
    -0.0,
    -0x1.0p-1022
  },
  { // Entry 181
    -0.0,
    -0.0,
    -0x1.0p0
  },
  { // Entry 182
    -0.0,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 183
    -0.0,
    -0.0,
    -HUGE_VAL
  },
  { // Entry 184
    0x1.p-1074,
    -0x1.0p-1074,
    HUGE_VAL
  },
  { // Entry 185
    0x1.p-1074,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 186
    0x1.p-1074,
    -0x1.0p-1074,
    0x1.0p-1022
  },
  { // Entry 187
    0x1.p-1074,
    -0x1.0p-1074,
    0x1.ffffffffffffep-1023
  },
  { // Entry 188
    0x1.p-1074,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 189
    0x1.p-1074,
    -0x1.0p-1074,
    0.0
  },
  { // Entry 190
    -0x1.p-1074,
    -0x1.0p-1074,
    -0.0
  },
  { // Entry 191
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 192
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 193
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.0p-1022
  },
  { // Entry 194
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.0p0
  },
  { // Entry 195
    -0x1.p-1074,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 196
    -0x1.p-1074,
    -0x1.0p-1074,
    -HUGE_VAL
  },
  { // Entry 197
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    HUGE_VAL
  },
  { // Entry 198
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 199
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.0p-1022
  },
  { // Entry 200
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 201
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    0x1.0p-1074
  },
  { // Entry 202
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    0.0
  },
  { // Entry 203
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -0.0
  },
  { // Entry 204
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -0x1.0p-1074
  },
  { // Entry 205
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 206
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -0x1.0p-1022
  },
  { // Entry 207
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -0x1.0p0
  },
  { // Entry 208
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 209
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023,
    -HUGE_VAL
  },
  { // Entry 210
    0x1.p-1022,
    -0x1.0p-1022,
    HUGE_VAL
  },
  { // Entry 211
    0x1.p-1022,
    -0x1.0p-1022,
    0x1.fffffffffffffp1023
  },
  { // Entry 212
    0x1.p-1022,
    -0x1.0p-1022,
    0x1.0p-1022
  },
  { // Entry 213
    0x1.p-1022,
    -0x1.0p-1022,
    0x1.ffffffffffffep-1023
  },
  { // Entry 214
    0x1.p-1022,
    -0x1.0p-1022,
    0x1.0p-1074
  },
  { // Entry 215
    0x1.p-1022,
    -0x1.0p-1022,
    0.0
  },
  { // Entry 216
    -0x1.p-1022,
    -0x1.0p-1022,
    -0.0
  },
  { // Entry 217
    -0x1.p-1022,
    -0x1.0p-1022,
    -0x1.0p-1074
  },
  { // Entry 218
    -0x1.p-1022,
    -0x1.0p-1022,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 219
    -0x1.p-1022,
    -0x1.0p-1022,
    -0x1.0p-1022
  },
  { // Entry 220
    -0x1.p-1022,
    -0x1.0p-1022,
    -0x1.0p0
  },
  { // Entry 221
    -0x1.p-1022,
    -0x1.0p-1022,
    -0x1.fffffffffffffp1023
  },
  { // Entry 222
    -0x1.p-1022,
    -0x1.0p-1022,
    -HUGE_VAL
  },
  { // Entry 223
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    HUGE_VAL
  },
  { // Entry 224
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.fffffffffffffp1023
  },
  { // Entry 225
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.0p-1022
  },
  { // Entry 226
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.ffffffffffffep-1023
  },
  { // Entry 227
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0x1.0p-1074
  },
  { // Entry 228
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    0.0
  },
  { // Entry 229
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0.0
  },
  { // Entry 230
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 231
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 232
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0x1.0p-1022
  },
  { // Entry 233
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 234
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp1023
  },
  { // Entry 235
    -0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1,
    -HUGE_VAL
  },
  { // Entry 236
    0x1.p0,
    -0x1.0p0,
    HUGE_VAL
  },
  { // Entry 237
    0x1.p0,
    -0x1.0p0,
    0x1.fffffffffffffp1023
  },
  { // Entry 238
    0x1.p0,
    -0x1.0p0,
    0x1.0p-1022
  },
  { // Entry 239
    0x1.p0,
    -0x1.0p0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 240
    0x1.p0,
    -0x1.0p0,
    0x1.0p-1074
  },
  { // Entry 241
    0x1.p0,
    -0x1.0p0,
    0.0
  },
  { // Entry 242
    -0x1.p0,
    -0x1.0p0,
    -0.0
  },
  { // Entry 243
    -0x1.p0,
    -0x1.0p0,
    -0x1.0p-1074
  },
  { // Entry 244
    -0x1.p0,
    -0x1.0p0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 245
    -0x1.p0,
    -0x1.0p0,
    -0x1.0p-1022
  },
  { // Entry 246
    -0x1.p0,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 247
    -0x1.p0,
    -0x1.0p0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 248
    -0x1.p0,
    -0x1.0p0,
    -HUGE_VAL
  },
  { // Entry 249
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    HUGE_VAL
  },
  { // Entry 250
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.fffffffffffffp1023
  },
  { // Entry 251
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.0p-1022
  },
  { // Entry 252
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 253
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0x1.0p-1074
  },
  { // Entry 254
    0x1.00000000000010p0,
    -0x1.0000000000001p0,
    0.0
  },
  { // Entry 255
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0.0
  },
  { // Entry 256
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0x1.0p-1074
  },
  { // Entry 257
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 258
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0x1.0p-1022
  },
  { // Entry 259
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 260
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 261
    -0x1.00000000000010p0,
    -0x1.0000000000001p0,
    -HUGE_VAL
  },
  { // Entry 262
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    HUGE_VAL
  },
  { // Entry 263
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 264
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0x1.0p-1022
  },
  { // Entry 265
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 266
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 267
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    0.0
  },
  { // Entry 268
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 269
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 270
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 271
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1022
  },
  { // Entry 272
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.0p0
  },
  { // Entry 273
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 274
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023,
    -HUGE_VAL
  },
  { // Entry 275
    HUGE_VAL,
    -HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 276
    HUGE_VAL,
    -HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 277
    HUGE_VAL,
    -HUGE_VAL,
    0x1.0p-1022
  },
  { // Entry 278
    HUGE_VAL,
    -HUGE_VAL,
    0x1.ffffffffffffep-1023
  },
  { // Entry 279
    HUGE_VAL,
    -HUGE_VAL,
    0x1.0p-1074
  },
  { // Entry 280
    HUGE_VAL,
    -HUGE_VAL,
    0.0
  },
  { // Entry 281
    -HUGE_VAL,
    -HUGE_VAL,
    -0.0
  },
  { // Entry 282
    -HUGE_VAL,
    -HUGE_VAL,
    -0x1.0p-1074
  },
  { // Entry 283
    -HUGE_VAL,
    -HUGE_VAL,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 284
    -HUGE_VAL,
    -HUGE_VAL,
    -0x1.0p-1022
  },
  { // Entry 285
    -HUGE_VAL,
    -HUGE_VAL,
    -0x1.0p0
  },
  { // Entry 286
    -HUGE_VAL,
    -HUGE_VAL,
    -0x1.fffffffffffffp1023
  },
  { // Entry 287
    -HUGE_VAL,
    -HUGE_VAL,
    -HUGE_VAL
  }
};
```
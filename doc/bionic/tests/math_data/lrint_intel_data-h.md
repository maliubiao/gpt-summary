Response:
Let's break down the thought process for answering the request about the `lrint_intel_data.handroid` file.

**1. Understanding the Core Request:**

The user provided a C source code file and asked several specific questions about its functionality, relationship to Android, implementation details (especially `libc` functions), dynamic linking, error handling, and how it's accessed within Android. The request emphasizes detailed explanations and examples.

**2. Initial Analysis of the Code:**

The first thing that jumps out is the data structure: `static data_long_1_t<double> g_lrint_intel_data[]`. This strongly suggests test data. The structure contains pairs of values: a `long int` and a `double`. The naming `lrint_intel_data` further hints that this data is used for testing the `lrint` function, likely on Intel architectures. The `.handroid` suffix probably signifies that these are Android-specific test data.

**3. Addressing the "Functionality" Question:**

Based on the data structure and file name, the most likely function is to provide test cases for the `lrint` family of functions. These functions convert floating-point numbers to the nearest integer. Therefore, the file's function is:

* **Providing test data for `lrint`:**  This is the primary function.
* **Specific to Intel architectures:** The "intel" in the filename indicates this.
* **Part of Android's Bionic library testing:** The file path confirms this.

**4. Relating to Android Functionality:**

Since it's part of Bionic's testing, it directly supports the reliability and correctness of the standard C library functions provided by Android. This is crucial for all Android applications, whether written in Java/Kotlin (through the NDK) or native C/C++.

* **Example:** A game using floating-point calculations needs reliable conversion to integers for indexing arrays or determining UI element positions. This test data helps ensure `lrint` works correctly.

**5. Explaining `libc` Function Implementation:**

The key here is to understand what `lrint` does. It's a standard C library function defined in `<math.h>`. Its core purpose is to convert a floating-point number to the *nearest* integer, rounding to the even integer in case of a tie (banker's rounding).

* **Implementation details:**  While the *exact* low-level implementation varies by architecture and compiler, the general steps involve:
    * Extracting the sign, exponent, and mantissa of the floating-point number.
    * Adjusting the mantissa based on the exponent to represent the full value.
    * Performing the rounding operation based on the fractional part and the rounding mode (in this case, nearest even).
    * Converting the rounded value to a `long int`.
    * Handling edge cases like NaN, infinity, and values outside the representable range of `long int`.

**6. Dynamic Linker Aspects:**

This particular data file *doesn't directly involve the dynamic linker*. It's just data. However, to address the user's question, it's essential to explain how the `lrint` function *itself* is linked:

* **SO Layout:** Explain the typical structure of a shared library (`.so`) containing `libc` functions. Include sections like `.text` (code), `.data` (initialized data), `.rodata` (read-only data), `.bss` (uninitialized data), and the symbol table.
* **Linking Process:** Describe how the dynamic linker resolves symbols (like `lrint`) at runtime. Mention the role of the symbol table, relocation entries, and the `DT_NEEDED` entries in the ELF header.

**7. Logical Inference (Input/Output):**

Go through several examples from the data file and explain the expected output of `lrint`. Focus on different scenarios:

* Positive and negative numbers.
* Numbers very close to integers.
* Numbers exactly halfway between integers (demonstrating banker's rounding).
* Very small numbers rounding to 0.
* Large numbers.

**8. Common Usage Errors:**

Highlight potential pitfalls developers might encounter when using `lrint`:

* **Overflow:**  Converting very large floating-point numbers that exceed the range of `long int`.
* **Loss of Precision:**  Implicit conversion from `double` to `long int` truncates, unlike `lrint`. This can lead to unexpected results if the developer expects rounding.
* **Assuming Truncation:**  Developers might mistakenly believe it always rounds down or towards zero.

**9. Android Framework/NDK Path and Frida Hooking:**

This is the most complex part. Trace the execution flow from an Android app calling a math function that might eventually use `lrint`.

* **Java/Kotlin App:**  Start with a simple Android app that needs to convert a `double` to an integer.
* **NDK:**  Show how to achieve this using JNI to call a C++ function.
* **`libm.so`:** Explain that math functions like `lrint` are typically in `libm.so`.
* **Bionic:** Emphasize that `libm.so` is part of Bionic.
* **`lrint_intel_data.handroid`:** Explain that this data file is used during Bionic's internal testing to ensure the correct implementation of `lrint`. While the *app* doesn't directly access this file, the *system's testing process* does.
* **Frida Hooking:** Provide a Frida script to demonstrate hooking the `lrint` function in `libm.so`. Show how to intercept calls, log arguments and return values. This helps in understanding how `lrint` behaves at runtime.

**10. Structuring the Answer:**

Organize the information logically using headings and subheadings to make it easy to read and understand. Use code blocks for examples and formatting to highlight key points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps this file *directly* influences the dynamic linker. **Correction:**  On closer inspection, it's just test *data*. The dynamic linker is involved in loading the *code* that uses this data (i.e., the `lrint` implementation).
* **Over-complicating `lrint` implementation:**  Focus on the *general* principles rather than getting bogged down in architecture-specific assembly details.
* **Clarifying the Android framework path:** Ensure a clear connection between a user-level app and the low-level Bionic library. Emphasize the role of the NDK.

By following this thought process, breaking down the request into smaller, manageable parts, and providing clear explanations and examples, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析一下 `bionic/tests/math_data/lrint_intel_data.handroid` 这个文件。

**文件功能:**

这个文件 `lrint_intel_data.handroid` 的主要功能是**为 `lrint` 函数提供测试数据**。

* **`lrint` 函数:**  `lrint` 是 C 标准库 `<math.h>` 中定义的一个函数，用于将浮点数（`double` 类型）**舍入到最接近的 `long int` 型整数**。如果浮点数正好在两个整数中间，则舍入到偶数。
* **测试数据:**  该文件包含一个静态数组 `g_lrint_intel_data`，其中存储了一系列预定义的输入 (`double`) 和期望的输出 (`long int`) 对。这些数据用于测试 `lrint` 函数在各种输入情况下的行为是否符合预期。
* **`intel_data`:** 文件名中的 "intel" 可能意味着这些测试数据是针对 Intel 架构的特定行为或边缘情况设计的。不同的处理器架构在浮点数处理上可能存在细微差异。
* **`.handroid`:** 这个后缀表明该文件是 Android Bionic 库测试套件的一部分。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 系统中数学计算的正确性和可靠性。`lrint` 函数是 Bionic (Android 的 C 库) 提供的一部分，被 Android 系统和应用程序广泛使用。

**举例说明:**

假设一个 Android 应用需要将一个表示温度的 `double` 值转换为整数进行显示。

```c++
#include <cmath>
#include <iostream>

int main() {
  double temperature = 25.7;
  long int rounded_temperature = lrint(temperature);
  std::cout << "Rounded temperature: " << rounded_temperature << std::endl; // 输出 26
  return 0;
}
```

在这个例子中，`lrint(25.7)` 应该返回 `26`。 `lrint_intel_data.handroid` 中的数据就是用来测试 Bionic 库提供的 `lrint` 函数是否能正确处理各种 `double` 输入并返回正确的 `long int` 结果。例如，文件中的 Entry 7 `{ (long int)0x1.p0, 0x1.0p0 }` 就测试了 `lrint(1.0)` 是否返回 `1`。

**详细解释 `libc` 函数的功能是如何实现的 (`lrint`)**

`lrint` 函数的实现通常涉及以下步骤：

1. **处理特殊值:** 首先检查输入是否为 NaN (Not a Number) 或无穷大。如果是 NaN，`lrint` 可能会返回未指定的值或者引发浮点异常。如果是无穷大，结果将是未定义的或者会引发溢出异常。
2. **提取符号、指数和尾数:**  将输入的 `double` 类型的浮点数分解为符号位、指数部分和尾数部分。
3. **根据指数确定整数部分:** 指数部分决定了浮点数的小数点位置。通过指数可以确定浮点数的整数部分。
4. **舍入处理:** 这是 `lrint` 的核心部分。
   * **查找最接近的整数:** 根据浮点数的小数部分，找到最接近的两个整数。
   * **处理中间值:** 如果浮点数正好位于两个整数中间（例如 2.5），`lrint` 会舍入到偶数。也就是说，`lrint(2.5)` 会返回 `2`，而 `lrint(3.5)` 会返回 `4`。
5. **转换为 `long int`:** 将舍入后的整数值转换为 `long int` 类型。
6. **处理溢出:** 如果舍入后的整数值超出了 `long int` 类型的表示范围，则行为是未定义的，可能会引发溢出异常。

**具体实现细节:**

Bionic 库的 `lrint` 函数的具体实现会依赖于底层的硬件架构和编译器。通常会使用汇编指令来高效地完成浮点数的舍入和类型转换。例如，在 Intel 架构上，可能会使用 `ROUNDSD` 指令来进行舍入。

**对于涉及 dynamic linker 的功能 (本文件不直接涉及，但我们可以讨论 `lrint` 函数的链接):**

`lrint_intel_data.handroid` 文件本身不涉及 dynamic linker 的功能。它只是一个包含测试数据的文件。但是，`lrint` 函数作为 `libc` 的一部分，在程序运行时是通过 dynamic linker 加载和链接的。

**SO 布局样本 (针对包含 `lrint` 的 `libc.so`)：**

```
libc.so:
    .text         # 包含可执行代码，包括 lrint 的实现
    .rodata       # 包含只读数据，例如字符串常量
    .data         # 包含已初始化的全局变量和静态变量
    .bss          # 包含未初始化的全局变量和静态变量
    .plt          # Procedure Linkage Table，用于延迟绑定
    .got.plt      # Global Offset Table，用于存储外部符号的地址
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .hash         # 符号哈希表
    ...
```

**链接的处理过程：**

1. **编译时链接:** 当你编译包含 `lrint` 函数调用的代码时，编译器会生成对 `lrint` 函数的未解析引用。
2. **动态链接时:** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 `libc.so`。
3. **符号解析:** dynamic linker 会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `lrint` 函数的符号。
4. **重定位:** dynamic linker 会更新程序的 Global Offset Table (`.got.plt`) 中的条目，将 `lrint` 函数的实际地址填入。这样，程序在调用 `lrint` 时，就能跳转到 `libc.so` 中正确的代码位置。
5. **延迟绑定 (通常使用):** 为了提高启动速度，通常使用延迟绑定。这意味着 `lrint` 函数的地址不会在程序启动时立即解析，而是在第一次调用 `lrint` 时才解析。这通过 Procedure Linkage Table (`.plt`) 和 Global Offset Table (`.got.plt`) 机制实现。

**假设输入与输出 (基于 `lrint_intel_data.handroid` 中的示例):**

文件中的每一项都是一个测试用例，可以看作一个假设的输入和输出。例如：

* **假设输入:** `-0x1.0p-1074` (一个非常小的负数，接近于 0)
   * **预期输出:** `(long int)0.0`，即 `0`

* **假设输入:** `0x1.fffffffffffffp-2` (接近 0.5 的正数)
   * **预期输出:** `(long int)0.0`，即 `0` (舍入到偶数)

* **假设输入:** `0x1.7ffffffffffffp0` (接近 1.999...)
   * **预期输出:** `(long int)0x1.p0`，即 `1`

* **假设输入:** `0x1.8p0` (等于 1.5)
   * **预期输出:** `(long int)0x1.p1`，即 `2` (舍入到偶数)

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **精度丢失:** 直接将 `double` 赋值给 `long int` 会发生截断，而不是舍入。

   ```c++
   double value = 2.9;
   long int truncated_value = (long int)value; // truncated_value 将是 2
   long int rounded_value = lrint(value);     // rounded_value 将是 3
   ```

2. **溢出:** 当 `double` 值超出 `long int` 的表示范围时，`lrint` 的行为是未定义的。

   ```c++
   double very_large_value = 9e18; // 大于 long int 的最大值
   long int result = lrint(very_large_value); // 行为未定义，可能崩溃或返回错误的值
   ```

3. **未处理 NaN 或无穷大:**  `lrint` 对 NaN 和无穷大的处理可能不是所有平台都一致的。依赖特定的行为可能导致移植性问题。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework / 应用层:**  一个 Android 应用可能需要进行一些数学运算，涉及到浮点数到整数的转换。这可以通过 Java 或 Kotlin 代码实现，或者通过 NDK 调用本地代码。

2. **NDK (Native Development Kit):** 如果使用 NDK，Java/Kotlin 代码会通过 JNI (Java Native Interface) 调用 C/C++ 代码。

   ```java
   // Java 代码
   public class MyMath {
       public native long roundDoubleToLong(double value);
   }
   ```

   ```c++
   // C++ 代码 (my_math.cpp)
   #include <jni.h>
   #include <cmath>

   extern "C" JNIEXPORT jlong JNICALL
   Java_com_example_myapp_MyMath_roundDoubleToLong(JNIEnv *env, jobject /* this */, jdouble value) {
       return lrint(value);
   }
   ```

3. **Bionic 库 (`libc.so` 或 `libm.so`):**  `lrint` 函数的实现位于 Bionic 库中。通常，数学函数在 `libm.so` 中，但也可能在 `libc.so` 中。当 `lrint` 被调用时，它实际上调用的是 Bionic 库提供的实现。

4. **`lrint_intel_data.handroid` (测试阶段):**  `lrint_intel_data.handroid` 文件不会在正常的应用运行过程中被直接访问。它是 Android 系统构建和测试过程的一部分。在 Bionic 库的开发和测试阶段，会运行测试用例，其中就包括使用 `lrint_intel_data.handroid` 中的数据来验证 `lrint` 函数的实现是否正确。

**Frida Hook 示例:**

可以使用 Frida hook `lrint` 函数来观察其行为，例如打印输入和输出值。

```python
import frida
import sys

package_name = "your.app.package.name" # 替换你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "lrint"), {
    onEnter: function(args) {
        console.log("[+] lrint called with argument: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[+] lrint returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上面的 Python 脚本保存为 `hook_lrint.py`。
2. 将你的 Android 设备连接到电脑，并确保 Frida 服务正在运行。
3. 将 `your.app.package.name` 替换为你想要调试的 Android 应用的包名。
4. 运行脚本： `python hook_lrint.py`
5. 运行你的 Android 应用，当应用中调用到 `lrint` 函数时，Frida 会拦截并打印相关的日志信息。

**调试步骤:**

1. **启动应用:** 运行你想要调试的 Android 应用。
2. **触发 `lrint` 调用:** 在应用中执行某些操作，使得代码路径会调用到 `lrint` 函数（例如，进行一些浮点数到整数的转换）。
3. **观察 Frida 输出:** 查看 Frida 脚本的输出，你应该能看到 `lrint` 函数被调用的日志，包括传入的参数和返回的值。

通过这种方式，你可以验证 `lrint` 函数在你的应用中的实际行为，并观察其与 `lrint_intel_data.handroid` 中测试数据的一致性。

总结来说，`bionic/tests/math_data/lrint_intel_data.handroid` 是 Android Bionic 库中用于测试 `lrint` 函数正确性的关键数据文件。它不直接参与应用的运行时，但保证了 Android 系统提供的数学运算的可靠性。通过 NDK 和 Frida，开发者可以深入了解和调试这些底层的库函数。

### 提示词
```
这是目录为bionic/tests/math_data/lrint_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

static data_long_1_t<double> g_lrint_intel_data[] = {
  { // Entry 0
    (long int)0.0,
    -0x1.0p-1074
  },
  { // Entry 1
    (long int)0.0,
    -0.0
  },
  { // Entry 2
    (long int)0.0,
    0x1.0p-1074
  },
  { // Entry 3
    (long int)0.0,
    0x1.fffffffffffffp-2
  },
  { // Entry 4
    (long int)0.0,
    0x1.0p-1
  },
  { // Entry 5
    (long int)0x1.p0,
    0x1.0000000000001p-1
  },
  { // Entry 6
    (long int)0x1.p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 7
    (long int)0x1.p0,
    0x1.0p0
  },
  { // Entry 8
    (long int)0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 9
    (long int)0x1.p0,
    0x1.7ffffffffffffp0
  },
  { // Entry 10
    (long int)0x1.p1,
    0x1.8p0
  },
  { // Entry 11
    (long int)0x1.p1,
    0x1.8000000000001p0
  },
  { // Entry 12
    (long int)0x1.p1,
    0x1.fffffffffffffp0
  },
  { // Entry 13
    (long int)0x1.p1,
    0x1.0p1
  },
  { // Entry 14
    (long int)0x1.p1,
    0x1.0000000000001p1
  },
  { // Entry 15
    (long int)0x1.p1,
    0x1.3ffffffffffffp1
  },
  { // Entry 16
    (long int)0x1.p1,
    0x1.4p1
  },
  { // Entry 17
    (long int)0x1.80p1,
    0x1.4000000000001p1
  },
  { // Entry 18
    (long int)0x1.90p6,
    0x1.8ffffffffffffp6
  },
  { // Entry 19
    (long int)0x1.90p6,
    0x1.9p6
  },
  { // Entry 20
    (long int)0x1.90p6,
    0x1.9000000000001p6
  },
  { // Entry 21
    (long int)0x1.90p6,
    0x1.91fffffffffffp6
  },
  { // Entry 22
    (long int)0x1.90p6,
    0x1.920p6
  },
  { // Entry 23
    (long int)0x1.94p6,
    0x1.9200000000001p6
  },
  { // Entry 24
    (long int)0x1.f4p9,
    0x1.f3fffffffffffp9
  },
  { // Entry 25
    (long int)0x1.f4p9,
    0x1.f40p9
  },
  { // Entry 26
    (long int)0x1.f4p9,
    0x1.f400000000001p9
  },
  { // Entry 27
    (long int)0x1.f4p9,
    0x1.f43ffffffffffp9
  },
  { // Entry 28
    (long int)0x1.f4p9,
    0x1.f44p9
  },
  { // Entry 29
    (long int)0x1.f480p9,
    0x1.f440000000001p9
  },
  { // Entry 30
    (long int)-0x1.p0,
    -0x1.0000000000001p-1
  },
  { // Entry 31
    (long int)0.0,
    -0x1.0p-1
  },
  { // Entry 32
    (long int)0.0,
    -0x1.fffffffffffffp-2
  },
  { // Entry 33
    (long int)-0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 34
    (long int)-0x1.p0,
    -0x1.0p0
  },
  { // Entry 35
    (long int)-0x1.p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 36
    (long int)-0x1.p1,
    -0x1.8000000000001p0
  },
  { // Entry 37
    (long int)-0x1.p1,
    -0x1.8p0
  },
  { // Entry 38
    (long int)-0x1.p0,
    -0x1.7ffffffffffffp0
  },
  { // Entry 39
    (long int)-0x1.p1,
    -0x1.0000000000001p1
  },
  { // Entry 40
    (long int)-0x1.p1,
    -0x1.0p1
  },
  { // Entry 41
    (long int)-0x1.p1,
    -0x1.fffffffffffffp0
  },
  { // Entry 42
    (long int)-0x1.80p1,
    -0x1.4000000000001p1
  },
  { // Entry 43
    (long int)-0x1.p1,
    -0x1.4p1
  },
  { // Entry 44
    (long int)-0x1.p1,
    -0x1.3ffffffffffffp1
  },
  { // Entry 45
    (long int)-0x1.90p6,
    -0x1.9000000000001p6
  },
  { // Entry 46
    (long int)-0x1.90p6,
    -0x1.9p6
  },
  { // Entry 47
    (long int)-0x1.90p6,
    -0x1.8ffffffffffffp6
  },
  { // Entry 48
    (long int)-0x1.94p6,
    -0x1.9200000000001p6
  },
  { // Entry 49
    (long int)-0x1.90p6,
    -0x1.920p6
  },
  { // Entry 50
    (long int)-0x1.90p6,
    -0x1.91fffffffffffp6
  },
  { // Entry 51
    (long int)-0x1.f4p9,
    -0x1.f400000000001p9
  },
  { // Entry 52
    (long int)-0x1.f4p9,
    -0x1.f40p9
  },
  { // Entry 53
    (long int)-0x1.f4p9,
    -0x1.f3fffffffffffp9
  },
  { // Entry 54
    (long int)-0x1.f480p9,
    -0x1.f440000000001p9
  },
  { // Entry 55
    (long int)-0x1.f4p9,
    -0x1.f44p9
  },
  { // Entry 56
    (long int)-0x1.f4p9,
    -0x1.f43ffffffffffp9
  },
  { // Entry 57
    (long int)0x1.p30,
    0x1.fffffffffffffp29
  },
  { // Entry 58
    (long int)0x1.p30,
    0x1.0p30
  },
  { // Entry 59
    (long int)0x1.p30,
    0x1.0000000000001p30
  },
  { // Entry 60
    (long int)0x1.fffffff8p30,
    0x1.fffffff7ffffep30
  },
  { // Entry 61
    (long int)0x1.fffffff8p30,
    0x1.fffffff7fffffp30
  },
  { // Entry 62
    (long int)0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 63
    (long int)0x1.fffffff8p30,
    0x1.fffffff800001p30
  },
  { // Entry 64
    (long int)0x1.fffffff8p30,
    0x1.fffffff800002p30
  },
  { // Entry 65
    (long int)0x1.fffffff8p30,
    0x1.fffffff9ffffep30
  },
  { // Entry 66
    (long int)0x1.fffffff8p30,
    0x1.fffffff9fffffp30
  },
  { // Entry 67
    (long int)0x1.fffffff8p30,
    0x1.fffffffa0p30
  },
  { // Entry 68
    (long int)0x1.fffffffcp30,
    0x1.fffffffa00001p30
  },
  { // Entry 69
    (long int)0x1.fffffffcp30,
    0x1.fffffffa00002p30
  },
  { // Entry 70
    (long int)0x1.fffffffcp30,
    0x1.fffffffbffffep30
  },
  { // Entry 71
    (long int)0x1.fffffffcp30,
    0x1.fffffffbfffffp30
  },
  { // Entry 72
    (long int)0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 73
    (long int)0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 74
    (long int)0x1.fffffffcp30,
    0x1.fffffffc00002p30
  },
  { // Entry 75
    (long int)0x1.fffffffcp30,
    0x1.fffffffdffffep30
  },
  { // Entry 76
    (long int)0x1.fffffffcp30,
    0x1.fffffffdfffffp30
  },
  { // Entry 77
    (long int)0x1.ffffffe0p30,
    0x1.ffffffep30
  },
  { // Entry 78
    (long int)0x1.ffffffe4p30,
    0x1.ffffffe40p30
  },
  { // Entry 79
    (long int)0x1.ffffffe8p30,
    0x1.ffffffe80p30
  },
  { // Entry 80
    (long int)0x1.ffffffecp30,
    0x1.ffffffec0p30
  },
  { // Entry 81
    (long int)0x1.fffffff0p30,
    0x1.fffffffp30
  },
  { // Entry 82
    (long int)0x1.fffffff4p30,
    0x1.fffffff40p30
  },
  { // Entry 83
    (long int)0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 84
    (long int)0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 85
    (long int)-0x1.p30,
    -0x1.0000000000001p30
  },
  { // Entry 86
    (long int)-0x1.p30,
    -0x1.0p30
  },
  { // Entry 87
    (long int)-0x1.p30,
    -0x1.fffffffffffffp29
  },
  { // Entry 88
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff800002p30
  },
  { // Entry 89
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff800001p30
  },
  { // Entry 90
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff80p30
  },
  { // Entry 91
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff7fffffp30
  },
  { // Entry 92
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff7ffffep30
  },
  { // Entry 93
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffa00002p30
  },
  { // Entry 94
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffa00001p30
  },
  { // Entry 95
    (long int)-0x1.fffffff8p30,
    -0x1.fffffffa0p30
  },
  { // Entry 96
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff9fffffp30
  },
  { // Entry 97
    (long int)-0x1.fffffff8p30,
    -0x1.fffffff9ffffep30
  },
  { // Entry 98
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffc00002p30
  },
  { // Entry 99
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffc00001p30
  },
  { // Entry 100
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffc0p30
  },
  { // Entry 101
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffbfffffp30
  },
  { // Entry 102
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffbffffep30
  },
  { // Entry 103
    (long int)-0x1.p31,
    -0x1.fffffffe00002p30
  },
  { // Entry 104
    (long int)-0x1.p31,
    -0x1.fffffffe00001p30
  },
  { // Entry 105
    (long int)-0x1.p31,
    -0x1.fffffffe0p30
  },
  { // Entry 106
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffdfffffp30
  },
  { // Entry 107
    (long int)-0x1.fffffffcp30,
    -0x1.fffffffdffffep30
  },
  { // Entry 108
    (long int)-0x1.p31,
    -0x1.0000000000002p31
  },
  { // Entry 109
    (long int)-0x1.p31,
    -0x1.0000000000001p31
  },
  { // Entry 110
    (long int)-0x1.p31,
    -0x1.0p31
  },
  { // Entry 111
    (long int)-0x1.p31,
    -0x1.fffffffffffffp30
  },
  { // Entry 112
    (long int)-0x1.p31,
    -0x1.ffffffffffffep30
  },
  { // Entry 113
    (long int)-0x1.p31,
    -0x1.000000010p31
  },
  { // Entry 114
    (long int)-0x1.p31,
    -0x1.00000000fffffp31
  },
  { // Entry 115
    (long int)-0x1.p31,
    -0x1.00000000ffffep31
  },
  { // Entry 116
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 117
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 118
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 119
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 120
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 121
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 122
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 123
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 124
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 125
    (long int)-0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 126
    (long int)0x1.fffffffcp30,
    0x1.fffffffbfffffp30
  },
  { // Entry 127
    (long int)0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 128
    (long int)0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 129
    (long int)-0x1.p31,
    -0x1.0000000000001p31
  },
  { // Entry 130
    (long int)-0x1.p31,
    -0x1.0p31
  },
  { // Entry 131
    (long int)-0x1.p31,
    -0x1.fffffffffffffp30
  },
  { // Entry 132
    (long int)0x1.p2,
    0x1.fffffffffffffp1
  },
  { // Entry 133
    (long int)0x1.p2,
    0x1.0p2
  },
  { // Entry 134
    (long int)0x1.p2,
    0x1.0000000000001p2
  },
  { // Entry 135
    (long int)0x1.p3,
    0x1.fffffffffffffp2
  },
  { // Entry 136
    (long int)0x1.p3,
    0x1.0p3
  },
  { // Entry 137
    (long int)0x1.p3,
    0x1.0000000000001p3
  },
  { // Entry 138
    (long int)0x1.p4,
    0x1.fffffffffffffp3
  },
  { // Entry 139
    (long int)0x1.p4,
    0x1.0p4
  },
  { // Entry 140
    (long int)0x1.p4,
    0x1.0000000000001p4
  },
  { // Entry 141
    (long int)0x1.p5,
    0x1.fffffffffffffp4
  },
  { // Entry 142
    (long int)0x1.p5,
    0x1.0p5
  },
  { // Entry 143
    (long int)0x1.p5,
    0x1.0000000000001p5
  },
  { // Entry 144
    (long int)0x1.p6,
    0x1.fffffffffffffp5
  },
  { // Entry 145
    (long int)0x1.p6,
    0x1.0p6
  },
  { // Entry 146
    (long int)0x1.p6,
    0x1.0000000000001p6
  },
  { // Entry 147
    (long int)0x1.p7,
    0x1.fffffffffffffp6
  },
  { // Entry 148
    (long int)0x1.p7,
    0x1.0p7
  },
  { // Entry 149
    (long int)0x1.p7,
    0x1.0000000000001p7
  },
  { // Entry 150
    (long int)0x1.p8,
    0x1.fffffffffffffp7
  },
  { // Entry 151
    (long int)0x1.p8,
    0x1.0p8
  },
  { // Entry 152
    (long int)0x1.p8,
    0x1.0000000000001p8
  },
  { // Entry 153
    (long int)0x1.p9,
    0x1.fffffffffffffp8
  },
  { // Entry 154
    (long int)0x1.p9,
    0x1.0p9
  },
  { // Entry 155
    (long int)0x1.p9,
    0x1.0000000000001p9
  },
  { // Entry 156
    (long int)0x1.p10,
    0x1.fffffffffffffp9
  },
  { // Entry 157
    (long int)0x1.p10,
    0x1.0p10
  },
  { // Entry 158
    (long int)0x1.p10,
    0x1.0000000000001p10
  },
  { // Entry 159
    (long int)0x1.p11,
    0x1.fffffffffffffp10
  },
  { // Entry 160
    (long int)0x1.p11,
    0x1.0p11
  },
  { // Entry 161
    (long int)0x1.p11,
    0x1.0000000000001p11
  },
  { // Entry 162
    (long int)0x1.p12,
    0x1.fffffffffffffp11
  },
  { // Entry 163
    (long int)0x1.p12,
    0x1.0p12
  },
  { // Entry 164
    (long int)0x1.p12,
    0x1.0000000000001p12
  },
  { // Entry 165
    (long int)0x1.p2,
    0x1.1ffffffffffffp2
  },
  { // Entry 166
    (long int)0x1.p2,
    0x1.2p2
  },
  { // Entry 167
    (long int)0x1.40p2,
    0x1.2000000000001p2
  },
  { // Entry 168
    (long int)0x1.p3,
    0x1.0ffffffffffffp3
  },
  { // Entry 169
    (long int)0x1.p3,
    0x1.1p3
  },
  { // Entry 170
    (long int)0x1.20p3,
    0x1.1000000000001p3
  },
  { // Entry 171
    (long int)0x1.p4,
    0x1.07fffffffffffp4
  },
  { // Entry 172
    (long int)0x1.p4,
    0x1.080p4
  },
  { // Entry 173
    (long int)0x1.10p4,
    0x1.0800000000001p4
  },
  { // Entry 174
    (long int)0x1.p5,
    0x1.03fffffffffffp5
  },
  { // Entry 175
    (long int)0x1.p5,
    0x1.040p5
  },
  { // Entry 176
    (long int)0x1.08p5,
    0x1.0400000000001p5
  },
  { // Entry 177
    (long int)0x1.p6,
    0x1.01fffffffffffp6
  },
  { // Entry 178
    (long int)0x1.p6,
    0x1.020p6
  },
  { // Entry 179
    (long int)0x1.04p6,
    0x1.0200000000001p6
  },
  { // Entry 180
    (long int)0x1.p7,
    0x1.00fffffffffffp7
  },
  { // Entry 181
    (long int)0x1.p7,
    0x1.010p7
  },
  { // Entry 182
    (long int)0x1.02p7,
    0x1.0100000000001p7
  },
  { // Entry 183
    (long int)0x1.p8,
    0x1.007ffffffffffp8
  },
  { // Entry 184
    (long int)0x1.p8,
    0x1.008p8
  },
  { // Entry 185
    (long int)0x1.01p8,
    0x1.0080000000001p8
  },
  { // Entry 186
    (long int)0x1.p9,
    0x1.003ffffffffffp9
  },
  { // Entry 187
    (long int)0x1.p9,
    0x1.004p9
  },
  { // Entry 188
    (long int)0x1.0080p9,
    0x1.0040000000001p9
  },
  { // Entry 189
    (long int)0x1.p10,
    0x1.001ffffffffffp10
  },
  { // Entry 190
    (long int)0x1.p10,
    0x1.002p10
  },
  { // Entry 191
    (long int)0x1.0040p10,
    0x1.0020000000001p10
  },
  { // Entry 192
    (long int)0x1.0040p10,
    0x1.005ffffffffffp10
  },
  { // Entry 193
    (long int)0x1.0080p10,
    0x1.006p10
  },
  { // Entry 194
    (long int)0x1.0080p10,
    0x1.0060000000001p10
  },
  { // Entry 195
    (long int)0x1.p11,
    0x1.000ffffffffffp11
  },
  { // Entry 196
    (long int)0x1.p11,
    0x1.001p11
  },
  { // Entry 197
    (long int)0x1.0020p11,
    0x1.0010000000001p11
  },
  { // Entry 198
    (long int)0x1.p12,
    0x1.0007fffffffffp12
  },
  { // Entry 199
    (long int)0x1.p12,
    0x1.00080p12
  },
  { // Entry 200
    (long int)0x1.0010p12,
    0x1.0008000000001p12
  },
  { // Entry 201
    (long int)0x1.80p1,
    0x1.921fb54442d18p1
  },
  { // Entry 202
    (long int)-0x1.80p1,
    -0x1.921fb54442d18p1
  },
  { // Entry 203
    (long int)0x1.p1,
    0x1.921fb54442d18p0
  },
  { // Entry 204
    (long int)-0x1.p1,
    -0x1.921fb54442d18p0
  },
  { // Entry 205
    (long int)0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 206
    (long int)-0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 207
    (long int)0x1.p0,
    0x1.0p0
  },
  { // Entry 208
    (long int)-0x1.p0,
    -0x1.0p0
  },
  { // Entry 209
    (long int)0x1.p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 210
    (long int)-0x1.p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 211
    (long int)0x1.p0,
    0x1.921fb54442d18p-1
  },
  { // Entry 212
    (long int)-0x1.p0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 213
    (long int)0.0,
    0x1.0000000000001p-1022
  },
  { // Entry 214
    (long int)0.0,
    -0x1.0000000000001p-1022
  },
  { // Entry 215
    (long int)0.0,
    0x1.0p-1022
  },
  { // Entry 216
    (long int)0.0,
    -0x1.0p-1022
  },
  { // Entry 217
    (long int)0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 218
    (long int)0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 219
    (long int)0.0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 220
    (long int)0.0,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 221
    (long int)0.0,
    0x1.0p-1073
  },
  { // Entry 222
    (long int)0.0,
    -0x1.0p-1073
  },
  { // Entry 223
    (long int)0.0,
    0x1.0p-1074
  },
  { // Entry 224
    (long int)0.0,
    -0x1.0p-1074
  },
  { // Entry 225
    (long int)0.0,
    0.0
  },
  { // Entry 226
    (long int)0.0,
    -0.0
  },
  { // Entry 227
    (long int)0x1.p1,
    0x1.8p0
  },
  { // Entry 228
    (long int)-0x1.p1,
    -0x1.8p0
  },
  { // Entry 229
    (long int)0x1.p1,
    0x1.4p1
  },
  { // Entry 230
    (long int)-0x1.p1,
    -0x1.4p1
  },
  { // Entry 231
    (long int)0.0,
    0x1.fffffp-2
  },
  { // Entry 232
    (long int)0.0,
    0x1.0p-1
  },
  { // Entry 233
    (long int)0x1.p0,
    0x1.00001p-1
  },
  { // Entry 234
    (long int)0.0,
    -0x1.fffffp-2
  },
  { // Entry 235
    (long int)0.0,
    -0x1.0p-1
  },
  { // Entry 236
    (long int)-0x1.p0,
    -0x1.00001p-1
  },
  { // Entry 237
    (long int)0x1.p1,
    0x1.80001p0
  },
  { // Entry 238
    (long int)0x1.p0,
    0x1.7ffffp0
  },
  { // Entry 239
    (long int)-0x1.p1,
    -0x1.80001p0
  },
  { // Entry 240
    (long int)-0x1.p0,
    -0x1.7ffffp0
  }
};
```
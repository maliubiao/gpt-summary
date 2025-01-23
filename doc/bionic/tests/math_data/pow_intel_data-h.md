Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The user has provided a code snippet from an Android bionic library test file and wants to understand its purpose, relationship to Android, implementation details (especially libc and dynamic linker), potential errors, and how it's reached in the Android system. The request emphasizes the need for a Chinese response and specifically asks for a summary of the file's functionality in this first part.

2. **Initial Analysis of the Code:**  I scan the code and immediately notice the following:
    * **Copyright and License:** Standard Apache 2.0 license header, indicating it's part of an open-source project (Android).
    * **`static data_1_2_t<double, double, double> g_pow_intel_data[]`:**  This is the crucial part. It declares a static array named `g_pow_intel_data`.
    * **`data_1_2_t` Template:** The template name suggests it holds two input values and one output value. The `<double, double, double>` instantiation confirms they are double-precision floating-point numbers.
    * **Hexadecimal Floating-Point Literals:**  The array is populated with a large number of entries, each containing three hexadecimal floating-point literals (e.g., `0x1.p0`, `-0x1.0p-10`, `0.0`). This strongly suggests these are test cases.
    * **`HUGE_VAL`:**  This macro is used, indicating the tests cover boundary conditions and special values.

3. **Formulate the Core Functionality:** Based on the code analysis, the primary function of this file is to provide test data for the `pow` function (likely the `pow(double base, double exponent)` function). The `intel_data` part of the filename hints that these tests might be specific to Intel architectures or generated using Intel's math libraries for comparison.

4. **Address the "List Functionality" Requirement:**  I directly state the main function: providing test data for the `pow` function.

5. **Address the "Relationship with Android" Requirement:**  I connect this file to Android's bionic library, which provides the standard C library functions, including math functions like `pow`. I explain that this test data ensures the correctness of the `pow` implementation on Android devices.

6. **Address the "Examples of Android Functionality" Requirement:** I provide a simple example of how the `pow` function might be used in an Android application (calculating powers) and link it back to the test data ensuring this function works correctly.

7. **Defer Detailed Implementation Questions:** The prompt asks for detailed explanations of `libc` functions, dynamic linker functionality, etc. I recognize that this *specific file* doesn't *implement* those things; it *tests* a `libc` function. Therefore, I acknowledge these questions but explain that this particular file primarily contains test data and the implementation details reside elsewhere in the bionic library. I avoid going into detail about the dynamic linker since this file doesn't directly involve it.

8. **Address "Logical Reasoning" and "Assumed Inputs/Outputs":** I explain that the data itself *is* the assumed input and expected output for the `pow` function. I provide a simple example of how one test entry could be interpreted.

9. **Address "Common Usage Errors":**  I link potential errors to the correct usage of the `pow` function in general, such as providing invalid input (NaN, infinity, etc.), as these are the types of scenarios the test data likely aims to cover.

10. **Address "Android Framework/NDK Path":** I provide a high-level explanation of how an Android application using the NDK would eventually call the `pow` function in bionic, thus indirectly involving this test data (through the testing process).

11. **Address "Frida Hook":** I provide a basic Frida hook example targeting the `pow` function to demonstrate how one could observe its behavior and potentially verify the correctness of its results against the data in this file.

12. **Address the "Summarize Functionality (Part 1)" Requirement:**  I reiterate the core function of the file: providing test data for the `pow` function in bionic, emphasizing its role in quality assurance.

13. **Structure and Language:** I ensure the entire response is in Chinese, using clear and concise language. I structure the answer to address each part of the prompt logically. I use headings and bullet points to improve readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Should I try to explain how `pow` is implemented?  **Correction:** No, this file *tests* `pow`, it doesn't implement it. Focus on the testing aspect.
* **Initial thought:** Should I detail the dynamic linking process? **Correction:** This file doesn't directly involve dynamic linking. Acknowledge the question but keep the explanation brief and high-level.
* **Initial thought:**  Should I explain hexadecimal floating-point notation in detail? **Correction:**  A brief explanation is sufficient. The main point is that these are floating-point values used for testing.
* **Clarity:** Ensure the Chinese is natural and avoids overly technical jargon where possible, while still being accurate.

By following this process, I can systematically address all aspects of the user's request, focusing on the information relevant to the provided code snippet and avoiding unnecessary tangents. The emphasis is on understanding the *purpose* of this specific file within the larger context of the Android bionic library.
好的，这是对你提供的代码片段 `bionic/tests/math_data/pow_intel_data.handroid` 的第一部分的分析和功能归纳。

**文件功能归纳（第一部分）**

该文件 `pow_intel_data.handroid` 的主要功能是为 `pow` 函数（即计算幂的函数）提供测试数据。 这些数据被设计用来测试 Android 系统 bionic 库中 `pow` 函数在特定输入情况下的行为和结果的正确性。

更具体地说，该文件定义了一个静态数组 `g_pow_intel_data`，其元素类型为 `data_1_2_t<double, double, double>`。  这意味着数组中的每个元素都包含三个 `double` 类型的数值，很可能分别代表 `pow` 函数的**底数 (base)**、**指数 (exponent)** 和 **期望的返回值 (expected result)**。

文件名中的 "intel_data" 暗示这些测试数据可能是基于 Intel 架构的特性或者使用 Intel 相关的数学库生成的，用于对比和验证 Android 系统的 `pow` 函数实现。 "handroid" 则明确指出这是 Android 平台使用的测试数据。

**与 Android 功能的关系及举例说明**

`pow` 函数是标准 C 库（libc）中的一个基本数学函数，而 bionic 是 Android 系统的 C 库实现。 因此，这个测试数据文件直接关系到 Android 系统的核心功能。

**举例说明：**

假设一个 Android 应用程序需要计算 2 的 10 次方。它会调用 bionic 库中的 `pow(2.0, 10.0)` 函数。  为了确保这个函数在各种情况下都能正确工作，包括一些边缘情况或特殊数值，Android 的开发者会使用类似 `pow_intel_data.handroid` 这样的文件来测试 `pow` 函数的实现。

例如，文件中的第一个条目：

```c
{ // Entry 0
  0x1.p0,
  -0x1.0p-10, 0.0
},
```

* `0x1.p0` 代表底数 1.0。
* `-0x1.0p-10` 代表指数 -2<sup>-10</sup>，即 -1/1024。
* `0.0` 代表当底数为 1.0，指数为 -1/1024 时，`pow` 函数的期望返回值是 0.0。

Android 的测试框架会读取这些数据，并用底数和指数作为输入来调用 bionic 的 `pow` 函数，然后将实际的返回值与期望的返回值进行比较，以验证 `pow` 函数的正确性。

**每一个 libc 函数的功能是如何实现的**

这个文件本身并没有实现任何 libc 函数。 它仅仅是 `pow` 函数的测试数据。 `pow` 函数的具体实现位于 bionic 库的源代码中，通常会涉及到复杂的浮点数运算，包括：

* **处理特殊情况：** 例如，底数为 0，指数为负数；底数为负数，指数为非整数等。
* **利用数学恒等式：** 例如，x<sup>y</sup> 可以计算为 e<sup>(y * ln(x))</sup>，其中 `ln` 是自然对数函数，`exp` 是指数函数。
* **使用查找表或逼近算法：** 为了提高效率和精度，可能预先计算一些常用的值并存储在表中，或者使用泰勒级数等方法进行逼近计算。
* **处理浮点数的精度问题：**  浮点数运算存在精度限制，实现需要考虑如何保证计算结果的精度。

**涉及 dynamic linker 的功能**

这个文件主要关注数学函数的测试数据，不直接涉及 dynamic linker 的功能。 Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 到进程的内存空间，并解析和处理库之间的依赖关系，包括符号的查找和重定位。

**so 布局样本和链接的处理过程：**

一个典型的 Android 应用的 `.so` 文件布局可能如下：

```
LOAD 0x... // 可执行代码段
LOAD 0x... // 只读数据段 (.rodata, 包括字符串常量等)
LOAD 0x... // 可读写数据段 (.data, .bss)
DYNAMIC       // 动态链接信息段
```

**链接的处理过程：**

1. **加载：** 当应用启动或需要使用某个共享库时，dynamic linker 会将该 `.so` 文件加载到内存中。
2. **依赖解析：** Dynamic linker 读取 `.so` 文件的 `DYNAMIC` 段，找到它所依赖的其他共享库。
3. **加载依赖：**  递归地加载所有依赖的共享库。
4. **符号解析：** Dynamic linker 查找 `.so` 文件中未定义的符号（通常是函数或全局变量），并在其依赖的库中寻找这些符号的定义。
5. **重定位：**  由于共享库加载到内存的地址可能不是编译时的地址，Dynamic linker 需要修改代码和数据段中的地址引用，使其指向正确的内存地址。  例如，对 `pow` 函数的调用就需要被重定位到 bionic 库中 `pow` 函数的实际地址。

**假设输入与输出 (逻辑推理)**

该文件中的每一行数据都可以被看作一个假设的输入和预期的输出。 例如：

**假设输入：** 底数 = `0x1.9241b707f6dadff955fd89193b67d331p-76` (约等于 1.637e-23), 指数 = `-0x1.0000000000009p0` (约等于 -1.0)
**预期输出：**  `-0x1.7364d9364d93ep54` (约等于 -2.034e+16)

测试框架会使用这些假设的输入来调用 `pow` 函数，并检查实际输出是否与预期输出一致。

**用户或编程常见的使用错误**

使用 `pow` 函数时常见的错误包括：

* **底数为负数，指数为非整数：**  `pow(-2.0, 0.5)`  在实数范围内是无意义的，会导致 `NaN` (Not a Number) 的结果。
* **底数为零，指数为负数：** `pow(0.0, -2.0)`  会导致无穷大。
* **溢出：**  当结果超出浮点数可以表示的范围时，会导致正无穷大或负无穷大。
* **精度损失：** 浮点数运算本身存在精度损失，尤其是在进行多次运算时。

**Android framework or ndk 是如何一步步的到达这里**

1. **Android 应用开发 (Java/Kotlin):**  如果一个 Android 应用程序使用 Java 或 Kotlin 开发，需要进行数学运算，可能会使用 `java.lang.Math.pow()` 方法。
2. **Framework 层调用:** `java.lang.Math.pow()` 的实现最终会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 或 Dalvik 虚拟机中的本地代码。
3. **NDK 开发 (C/C++):** 如果开发者使用 Android NDK 进行 C/C++ 开发，可以直接调用 bionic 库中的 `pow` 函数，包含 `<math.h>` 头文件即可。
4. **Bionic 库:** 无论是 Framework 层的调用还是 NDK 的直接调用，最终都会链接到 bionic 库中的 `pow` 函数实现。
5. **测试数据的使用:**  在 bionic 库的开发和测试过程中，像 `pow_intel_data.handroid` 这样的文件会被用于自动化测试，确保 `pow` 函数在各种输入情况下的正确性。 这些测试通常在 Android 系统的构建过程中运行。

**Frida hook 示例调试这些步骤**

可以使用 Frida hook `pow` 函数来观察其输入和输出，从而理解代码是如何到达这里的。

**NDK 应用的 Frida Hook 示例:**

假设你有一个使用 NDK 并且调用了 `pow` 函数的 Android 应用。你可以使用 Frida hook bionic 库中的 `pow` 函数：

```python
import frida
import sys

package_name = "你的应用包名"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 '{package_name}' 未运行，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "pow"), {
    onEnter: function(args) {
        console.log("[*] Calling pow with base: " + args[0] + ", exponent: " + args[1]);
        this.base = args[0];
        this.exponent = args[1];
    },
    onLeave: function(retval) {
        console.log("[*] pow returned: " + retval + " for base: " + this.base + ", exponent: " + this.exponent);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

1. **`frida.get_usb_device().attach(package_name)`:**  连接到 USB 连接的设备上正在运行的目标应用进程。
2. **`Module.findExportByName("libc.so", "pow")`:**  在 `libc.so` 库中查找 `pow` 函数的地址。
3. **`Interceptor.attach(...)`:** 拦截 `pow` 函数的调用。
4. **`onEnter`:** 在 `pow` 函数被调用之前执行，打印输入的底数和指数。
5. **`onLeave`:** 在 `pow` 函数返回之后执行，打印返回值以及对应的输入。

运行这个 Frida 脚本，当你操作你的 Android 应用并触发 `pow` 函数的调用时，你将在 Frida 的输出中看到 `pow` 函数的输入和输出，从而验证其行为。

**总结**

总而言之，`bionic/tests/math_data/pow_intel_data.handroid` 文件是一个关键的测试数据文件，用于验证 Android 系统 bionic 库中 `pow` 函数实现的正确性。它通过提供一系列预定义的底数、指数和期望返回值，帮助确保 Android 平台的数学运算功能可靠且符合预期。

### 提示词
```
这是目录为bionic/tests/math_data/pow_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
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

static data_1_2_t<double, double, double> g_pow_intel_data[] = {
  { // Entry 0
    0x1.p0,
    -0x1.0p-10, 0.0
  },
  { // Entry 1
    0x1.p0,
    -0x1.0p-20, 0.0
  },
  { // Entry 2
    -HUGE_VAL,
    -HUGE_VAL, 0x1.0000000000001p52
  },
  { // Entry 3
    -0x1.ffffffffffffe0000000000001ffffffp20,
    -0x1.0000000000001p-21, -0x1.0p0
  },
  { // Entry 4
    0x1.p0,
    -0x1.0000000000001p-41, 0.0
  },
  { // Entry 5
    0x1.000000000000a000000000002dp-410,
    -0x1.0000000000001p-41, 0x1.4p3
  },
  { // Entry 6
    0x1.9241b707f6dadff955fd89193b67d331p-76,
    -0x1.0000000000009p0, -0x1.7364d9364d93ep54
  },
  { // Entry 7
    0x1.ffffe00000fffffabaaabeffffc3b111p-1,
    -0x1.0000000000010p0, -0x1.0p28
  },
  { // Entry 8
    -0x1.fffffeffac00403b0c6d424acd900953p964,
    -0x1.00000000220p-1, -0x1.e28p9
  },
  { // Entry 9
    0x1.ffe88f898fad6805ef5425ca3572f1e8p705,
    -0x1.0000044p-1, -0x1.610p9
  },
  { // Entry 10
    -0x1.fff0007ffc001fff0007ffc001fff0p40,
    -0x1.00080p-41, -0x1.0p0
  },
  { // Entry 11
    0x1.ff601b7c9059582e9c5cd4bde021f462p409,
    -0x1.00080p-41, -0x1.4p3
  },
  { // Entry 12
    -0x1.002802801400500080p200,
    -0x1.00080p40, 0x1.4p2
  },
  { // Entry 13
    0x1.ffa00a7f14c337fcecffc107244f96dfp245,
    -0x1.0008000000f14p-41, -0x1.8p2
  },
  { // Entry 14
    0x1.ff8011fd3be577fec85ffc5d60b0334ep-321,
    -0x1.000800000e484p40, -0x1.0p3
  },
  { // Entry 15
    0x1.6b3c46415430c004e9fd0b35f8ec6fd5p-1,
    -0x1.046e8bfffffc2p0, -0x1.4p4
  },
  { // Entry 16
    0.0,
    -0x1.518p-1065, 0x1.0p1023
  },
  { // Entry 17
    0x1.20000060000008p-81,
    -0x1.8000004p-41, 0x1.0p1
  },
  { // Entry 18
    0x1.c3d6a2157b623407e8c821289ebac2b6p-1,
    -0x1.fffffbfffffffp-1, 0x1.0p20
  },
  { // Entry 19
    -0x1.00000060000030000011000006300002p0,
    -0x1.ffffffbffffffp-1, -0x1.8p1
  },
  { // Entry 20
    -0x1.000000e00000a8000062000033a00018p35,
    -0x1.ffffffbffffffp-6, -0x1.cp2
  },
  { // Entry 21
    -0x1.000000e00000a8000062000033a00018p280,
    -0x1.ffffffbffffffp-41, -0x1.cp2
  },
  { // Entry 22
    -0x1.000000e00000a8000062000033a00018p-287,
    -0x1.ffffffbffffffp40, -0x1.cp2
  },
  { // Entry 23
    -0x1.fffffe40000038000030fffff49ffffdp286,
    -0x1.ffffffbffffffp40, 0x1.cp2
  },
  { // Entry 24
    0x1.ffffff80000008p-21,
    -0x1.ffffffcp-11, 0x1.0p1
  },
  { // Entry 25
    -0x1.000000000100080000010010004001p40,
    -0x1.fffffffffdfffp-41, -0x1.0p0
  },
  { // Entry 26
    -0x1.00000000000c98000000009e9a40p40,
    -0x1.ffffffffffe6dp-41, -0x1.0p0
  },
  { // Entry 27
    -0x1.fffffffdffffe00100000fffaaaaaaaap-1,
    -0x1.ffffffffffffep-1, 0x1.00001p20
  },
  { // Entry 28
    -0x1.0000000000000800000000000040p0,
    -0x1.fffffffffffffp-1, -0x1.0p0
  },
  { // Entry 29
    -HUGE_VAL,
    -0x1.fffffffffffffp1023, 0x1.0000000000001p52
  },
  { // Entry 30
    0x1.fda6a1be3e9d47fc84293281e77aa21ap-1,
    0x1.0p-2, 0x1.b2cb2cb2cb2d0p-9
  },
  { // Entry 31
    0.0,
    0x1.0p-512, 0x1.0ccp1
  },
  { // Entry 32
    0x1.f9b3a3820980938687e8bf7ff06bc42cp-914,
    0x1.0p-1035, 0x1.c3a83a83a83a5p-1
  },
  { // Entry 33
    0.0,
    0x1.0p-1074, 0x1.0p1023
  },
  { // Entry 34
    0.0,
    0x1.0p-1074, 0x1.0000000000001p0
  },
  { // Entry 35
    0x1.51cb453b954f5305fd8d61e650e8d0d5p-967,
    0x1.0p-1074, 0x1.cccccccccccccp-1
  },
  { // Entry 36
    0x1.fffffffd3a37a022a4bdf9482171d56fp1023,
    0x1.0p1, 0x1.ffffffffff0p9
  },
  { // Entry 37
    0x1.00000000000007ffffffffffffe0p-5,
    0x1.0000000000001p-10, 0x1.0p-1
  },
  { // Entry 38
    0x1.ae89f995ad5887ff46dd2362be6a8f23p-204,
    0x1.0000000000001p-271, 0x1.7fffffffffffdp-1
  },
  { // Entry 39
    0x1.2611186bae6a380002e6202c31b04d13p-38,
    0x1.0000000000001p-462, 0x1.4f2094f2094f0p-4
  },
  { // Entry 40
    0x1.6a09e667f3ecd2adb67223f9564b3422p-392,
    0x1.0000000000001p-522, 0x1.7fffffffffffdp-1
  },
  { // Entry 41
    0x1.9fdf8bcce543547d611ef13904022b8bp-493,
    0x1.0000000000001p-547, 0x1.cccccccccccccp-1
  },
  { // Entry 42
    0x1.91b501c2db5c8ffe81cc3effffe282e8p-290,
    0x1.0000000000001p-643, 0x1.ccccccccccccap-2
  },
  { // Entry 43
    0x1.a830fd0547202479c70c80b72a325d2fp-408,
    0x1.0000000000001p-731, 0x1.1d41d41d41d44p-1
  },
  { // Entry 44
    0x1.a9335df38e6e64cbdaa57750a0cfd5eep-291,
    0x1.0000000000001p-733, 0x1.95810624dd2f7p-2
  },
  { // Entry 45
    0x1.6a09e667f3d192a27b73577484a86dcdp-761,
    0x1.0000000000001p-845, 0x1.cccccccccccccp-1
  },
  { // Entry 46
    0x1.bdb8cdadbe60a56dd61c4e04350cfa9ap-569,
    0x1.0000000000001p-947, 0x1.3333333333331p-1
  },
  { // Entry 47
    0x1.6a09e66d72c9c801840532577e605e07p904,
    0x1.0000000000001p-1005, -0x1.cccccccccfa81p-1
  },
  { // Entry 48
    0x1.fffffffffffaea6e0622a45b3589d771p1023,
    0x1.0000000000001p1, 0x1.ffffffffffffdp9
  },
  { // Entry 49
    0x1.e6102ba465044814b28a0a49216ef667p-349,
    0x1.0000000000001p663, -0x1.0cccccccccccfp-1
  },
  { // Entry 50
    0x1.ffffffffffd75b6d85de8fb3a7e2e826p-703,
    0x1.0000000000001p936, -0x1.8000000000001p-1
  },
  { // Entry 51
    0x1.ffffffffffffe0000000000001ffffffp-1024,
    0x1.0000000000001p1023, -0x1.0p0
  },
  { // Entry 52
    0x1.fffffffffffaea6e0622a4573589d771p1023,
    0x1.0000000000002p2, 0x1.ffffffffffffdp8
  },
  { // Entry 53
    0x1.000000000000080000000000029fffffp0,
    0x1.0000000000004p0, 0x1.0000000000007p-3
  },
  { // Entry 54
    0x1.00000000000007ffffffffff3920p0,
    0x1.0000000000004p0, 0x1.ffffffffffce8p-4
  },
  { // Entry 55
    0x1.fffffffffffaea6e0622a44f3589d771p1023,
    0x1.0000000000004p4, 0x1.ffffffffffffdp7
  },
  { // Entry 56
    0x1.fb9540d99258a80f86b71925aaf4421ep80,
    0x1.0000000000007p1023, 0x1.4444444444430p-4
  },
  { // Entry 57
    0x1.df905ef8e2507fd852712ed6cea98963p833,
    0x1.0000000000011p1, 0x1.a0f3ea0697a0bp9
  },
  { // Entry 58
    0x1.00000000000097ffffffffffd2e0p3,
    0x1.0000000000013p6, 0x1.0p-1
  },
  { // Entry 59
    0x1.000000000000d7ffffffffff77e0p0,
    0x1.0000000000021p0, 0x1.a2e8ba2e8ba2ep-2
  },
  { // Entry 60
    0x1.9476504b9baf343e3f75a2bd2e4caddbp738,
    0x1.0000000000080p0, 0x1.0p54
  },
  { // Entry 61
    0x1.fffff4e95e1f3fdcdd5e3d928f3a47f5p1023,
    0x1.00000000000ffp1, 0x1.fffffffc0p9
  },
  { // Entry 62
    0x1.ffffffff8e4de8083ac63f95bcb525fcp1023,
    0x1.00000000000ffp2, 0x1.ffffffffffcp8
  },
  { // Entry 63
    0x1.9476504b433552adbf253ad5a9e61e68p738,
    0x1.00000000004p0, 0x1.0p51
  },
  { // Entry 64
    0x1.6247eb03578637ff2cb93c93fe2f2473p-129,
    0x1.00000000007p1, -0x1.011p7
  },
  { // Entry 65
    0x1.87cea2e506d2ea9b21823d7557663fbap427,
    0x1.00000000020p1023, 0x1.ac083126e978cp-2
  },
  { // Entry 66
    0x1.ffffff2b0338080b257df31bb02ff70ap767,
    0x1.000000000ffffp-1, -0x1.7fffffffd5ce2p9
  },
  { // Entry 67
    0x1.ffd931035b394087164501473df23095p1023,
    0x1.000000001p1, 0x1.fffff1fffffffp9
  },
  { // Entry 68
    0x1.912b6dd6652df7fa0fbaffbc7b32d62ap953,
    0x1.000000001b1efp-1, -0x1.dcd2f3ea06995p9
  },
  { // Entry 69
    0x1.fffffff800000020c0003f7b7ffe8216p-1,
    0x1.000000040p0, -0x1.ffffffffcffffp-1
  },
  { // Entry 70
    0x1.ffffffc0000027fffff70000039ffffep-1024,
    0x1.0000001ffffffp1023, -0x1.0p0
  },
  { // Entry 71
    0x1.705df34f84e31387148153c7cf783a53p-1,
    0x1.0000004p1, -0x1.e66666666666bp-2
  },
  { // Entry 72
    0x1.1a16744c2ec0d8042410bf3e3a9014acp1,
    0x1.0000004p2, 0x1.23d70a3d70a3bp-1
  },
  { // Entry 73
    0x1.fff8001002b417ef588e21c5092e20c7p1023,
    0x1.0000010p-1, -0x1.ffffffffffff9p9
  },
  { // Entry 74
    0x1.a12f806c39105800d5ac38f6cb88d374p-2,
    0x1.000001cp3, -0x1.ba2e8ba2e8ba2p-2
  },
  { // Entry 75
    0x1.d72f7f354d86d0206ad7c9be9b478c7cp-885,
    0x1.0000044p-1, 0x1.ba0f61c9107c9p9
  },
  { // Entry 76
    0x1.915d1955b15fc08191e000bc8a9c8262p738,
    0x1.00020p0, 0x1.0000040p24
  },
  { // Entry 77
    0x1.ffc0043cbc5db7fed905ea267724cd86p47,
    0x1.000200000c0e4p-3, -0x1.fffffffff3fffp3
  },
  { // Entry 78
    0x1.03861c0f25f0b7fdd7db988fc50e8ac5p896,
    0x1.00070p7, 0x1.00000000880p7
  },
  { // Entry 79
    0x1.735f4cae6fd5e7ec9ec93923f339e951p-242,
    0x1.0007fdep0, -0x1.4f1b77c278dc0p20
  },
  { // Entry 80
    0x1.b6bdcdafd5582823b4d361cb7bf02f0bp0,
    0x1.0007ffffff18cp-3, -0x1.094f2094f2094p-2
  },
  { // Entry 81
    0x1.ee9de3815589f8020429c850502a73cep0,
    0x1.00080p1, 0x1.e666666666666p-1
  },
  { // Entry 82
    0x1.fc4e957ad3cff80df14d5383bd09a83ap1023,
    0x1.001febebccd42p0, 0x1.63d8aa986a9eap20
  },
  { // Entry 83
    0x1.fbddf46d6b62882b4c4e659bf0212df4p1023,
    0x1.001fef1cc4193p0, 0x1.63b500c83689dp20
  },
  { // Entry 84
    0x1.fba7f9318c5dc81b1e178865147202f3p1023,
    0x1.001ff069d2a6bp0, 0x1.63a676c8493e8p20
  },
  { // Entry 85
    0x1.f61661b7000d32d1f698e0fa2f889d35p69,
    0x1.00804025213dep-7, -0x1.4p3
  },
  { // Entry 86
    0x1.e109bdcca01fb7ffbbe4f50c82d0ec62p15,
    0x1.010p-1, -0x1.ffffffff9ffffp3
  },
  { // Entry 87
    0x1.1e49c51473ff37dc1ad27264312c37b5p-1011,
    0x1.021eeaa6d270dp1, -0x1.f37971758e257p9
  },
  { // Entry 88
    0x1.eb41321e136b37fffbb99027ffc8514bp-21,
    0x1.02f178bc5e2c1p3, -0x1.a99999999999ap2
  },
  { // Entry 89
    0x1.080ffffff79cb800d4fa4351d8e63171p-2,
    0x1.040p-1, 0x1.00000000060p1
  },
  { // Entry 90
    0x1.cf2b19acfd538820cd62b9762fbd07d8p-1018,
    0x1.0493cda7be452p1, -0x1.efe4b242071abp9
  },
  { // Entry 91
    0x1.6692c05b09baba2ea48d785ad4a4575dp135,
    0x1.05ebf8248a734p99, 0x1.5e3b32a2a9fb0p0
  },
  { // Entry 92
    0x1.810f2f53980577f6663abfa1f774291bp70,
    0x1.0aaaaaaaaaaabp7, 0x1.4p3
  },
  { // Entry 93
    0x1.fffee335368ea0008aa6b3b006354625p-1,
    0x1.0e4f938c0e0bbp-482, 0x1.b4838aa70d025p-26
  },
  { // Entry 94
    0x1.cfc470cc939227fa970b58b91572f724p-40,
    0x1.13bd11bcfaa50p-5, 0x1.0p3
  },
  { // Entry 95
    0x1.ec33ea55afd33ad219aa2aec083397dfp-1,
    0x1.1501f44659e54p0, -0x1.0p-1
  },
  { // Entry 96
    0x1.f648a0ead82f6001daf0d46abd018b77p-1,
    0x1.1555555555555p-1, 0x1.0000000000007p-5
  },
  { // Entry 97
    0x1.fe7eb68734b5e825e94d6de454cde18ep6,
    0x1.1745d1745da71p-1, -0x1.0000000000007p3
  },
  { // Entry 98
    0x1.a5a00c77c65bf5b0592a61407b2bc79fp-39,
    0x1.1973b102ffddbp-6, 0x1.a1d84f6a3b934p2
  },
  { // Entry 99
    0x1.e7e26745f50fe800d14145ff80133761p-2,
    0x1.19eedeb102d84p2, -0x1.0p-1
  },
  { // Entry 100
    0x1.a73f9acbf4125a89020110a29c39bbd2p103,
    0x1.24765a0cdd454p7, 0x1.cd81edfd6d5b8p3
  },
  { // Entry 101
    0x1.445ae390f4b5369c1426f9fe8b8a1751p615,
    0x1.2492492492492p-5, -0x1.ffffffffffff8p6
  },
  { // Entry 102
    0x1.e4e045205527f33f0c9768dcb7f13fabp-616,
    0x1.2492492492492p-5, 0x1.ffc7fffffffffp6
  },
  { // Entry 103
    0x1.2dd17dc7293dc8001e1986a14875be95p122,
    0x1.3150a12f25c8dp-41, -0x1.8p1
  },
  { // Entry 104
    0x1.52c58cdbac4cb7feb761e24bbde99b85p-534,
    0x1.3333333333333p-2, 0x1.333333333ce97p8
  },
  { // Entry 105
    0x1.bc7f056ec71ff0000104808c9990ae9fp-2,
    0x1.33333346cf8bap-2, 0x1.62e42fefa39efp-1
  },
  { // Entry 106
    0x1.a2c9dc7bb2e724ae746c7a0a076b129bp-291,
    0x1.38abf82ee6986p-1, 0x1.980p8
  },
  { // Entry 107
    0x1.b4f60e5795b5e8088c1865ab9e0e2694p0,
    0x1.3ec984cb36701p0, 0x1.38018879b2ba8p1
  },
  { // Entry 108
    0x1.8fcf301c2b46532fffb6a06cc43dec91p-667,
    0x1.4p-1070, 0x1.3ef368eb04327p-1
  },
  { // Entry 109
    0x1.00003f65cce8080000ffef6e02bfe509p0,
    0x1.4p4, 0x1.529a1574c0c72p-20
  },
  { // Entry 110
    0x1.90000000000028000000000001p4,
    0x1.4000000000001p2, 0x1.0p1
  },
  { // Entry 111
    0x1.43015cf74d6e07ff3666305ddffb5f4ep1,
    0x1.43e743ba79c41p-1, -0x1.02c30b80eb514p1
  },
  { // Entry 112
    0x1.a36e1c3c700b7a416fad641bfc031adbp-10,
    0x1.47ae147ae147bp-5, 0x1.000001cp1
  },
  { // Entry 113
    0x1.e5eccf1b3a05dcf7adca8d47f937dac7p-985,
    0x1.4e91b0e91b0f1p-1, 0x1.90c9714fbcd9bp10
  },
  { // Entry 114
    0x1.95335bfb76c6c7fe38526cde1c16edbdp-3,
    0x1.5152b7c373368p-22, 0x1.bb38288a0a6p-4
  },
  { // Entry 115
    0x1.ffffffffffffb01e21a404429e88cfd6p-1,
    0x1.51758790b4181p-4, 0x1.0p-52
  },
  { // Entry 116
    0x1.702ebfa1ff2013f2438cfd1935b73099p101,
    0x1.5555555555555p-2, -0x1.00380p6
  },
  { // Entry 117
    0x1.ba30a127f6dd5fd9c60a7f010d9ca125p202,
    0x1.5555555555555p-2, -0x1.ffc7fffffffffp6
  },
  { // Entry 118
    0x1.7ffffe8eddc49a0bb74c9b3942e5eb0bp1,
    0x1.5555555555555p-2, -0x1.fffffe3ffffffp-1
  },
  { // Entry 119
    0x1.8aa8808647d07b8819b686a448174076p586,
    0x1.5555555555555p-5, -0x1.ffc7fffffffffp6
  },
  { // Entry 120
    0x1.7a0a9108e1d1884c584a9ab81fc3f3d1p-294,
    0x1.5555555555555p-5, 0x1.000000000e0p6
  },
  { // Entry 121
    0x1.ad3d5033217a047c2602ed9b3c0a9644p-461,
    0x1.58a26121f46f6p-2, 0x1.24f45f5fd4f79p8
  },
  { // Entry 122
    0x1.1104fb8cf786c800ffc735889a531fa3p0,
    0x1.6130984c02017p0, 0x1.999999999999ap-3
  },
  { // Entry 123
    0x1.1e952b19cc33672f1cdd3ec50e0b3df2p-1023,
    0x1.622e8ba2e8b9dp-1, 0x1.e0f83e0f83e0cp10
  },
  { // Entry 124
    0x1.ceafd8c0385bd8abbd5744704bf13d4ep-1023,
    0x1.671111111110cp-1, 0x1.f333333333324p10
  },
  { // Entry 125
    0x1.6a09e667f3ba12f93247a76d74374418p-1,
    0x1.6a09e667f3b9ep-1, 0x1.ffffffffffff3p-1
  },
  { // Entry 126
    0x1.a887293fd6f30a11e9f3aab161b0d41fp0,
    0x1.745d1745d1746p-2, -0x1.ffffffffffff8p-2
  },
  { // Entry 127
    0x1.917499900fda07fed49796d8256cbeadp-40,
    0x1.745d1745d1746p-3, 0x1.fffffe3ffffffp3
  },
  { // Entry 128
    0x1.f46e967980e048c59fd0fbea1e57781cp967,
    0x1.7a0p7, 0x1.fffffffefffffp6
  },
  { // Entry 129
    0x1.99ce45b7e28fc7ff2d3cfb4617742d7ap-1,
    0x1.7bf0b2348b0a8p2, -0x1.0p-3
  },
  { // Entry 130
    0x1.fe9d3facecdb482e52a2026f0d0fcbabp0,
    0x1.8p-1, -0x1.33333333333c0p1
  },
  { // Entry 131
    0x1.96c3a864d92cc8242fa6a056bb08b3cfp-1,
    0x1.85e85e85e85eap-1, 0x1.b073ecade3053p-1
  },
  { // Entry 132
    0x1.f2d80cf8cc08b7ffffeea79f95c3a9bap-1,
    0x1.87d872441eabbp9, -0x1.fffffffffffeep-9
  },
  { // Entry 133
    0x1.ffffffffffff701f8afb9aa06bad33c1p-1,
    0x1.89e36ef84f19dp1, -0x1.0000000000011p-50
  },
  { // Entry 134
    0x1.0000000000000fffb750f07593ac0fefp0,
    0x1.8d600b7696862p-96, -0x1.efae61f60f6e8p-59
  },
  { // Entry 135
    0x1.e8f15565ed43a82e052236ac3f8a1f09p77,
    0x1.98d2fe5c53f34p-39, -0x1.044a002d50ad8p1
  },
  { // Entry 136
    0x1.0f4b118a10e49fffff00ae7357d87c94p-1,
    0x1.999999a637f10p-2, 0x1.62e42fefa39efp-1
  },
  { // Entry 137
    0x1.d2515c49d64157fef62efe37aa7d4e57p-44,
    0x1.9c0133cdb0856p-5, 0x1.4p3
  },
  { // Entry 138
    0x1.fb85e9f13f076753450e315695d239e9p-1023,
    0x1.9f0ed4f930522p-1, 0x1.a5db8a1755e9cp11
  },
  { // Entry 139
    0x1.01ab8f2671b6e8000096349ab8974ec5p0,
    0x1.9fcfe7f3fa181p-1, -0x1.0p-5
  },
  { // Entry 140
    0x1.69c73824fbabf8066c0f38487c600c72p9,
    0x1.a043274b705cep3, 0x1.487e31cce6468p1
  },
  { // Entry 141
    0x1.d20088f4eeb8a52ff029ff7e476e3b67p-582,
    0x1.a5d1745d1746ep-1, 0x1.03e0f83e0f83cp11
  },
  { // Entry 142
    0x1.c4beedf3151e2803e049bb5161d1272dp-272,
    0x1.aa4ce8ed526b1p-1, 0x1.00880p10
  },
  { // Entry 143
    0x1.7173062b74c217fea6b41e6a7fb48dd6p-711,
    0x1.ab99d36091bc0p97, -0x1.d136ee8e59573p2
  },
  { // Entry 144
    0x1.86c1b49a551097fe78399c00d0157d92p-2,
    0x1.b782218c3fdb4p2, -0x1.0p-1
  },
  { // Entry 145
    0x1.5b6a74499d637804b9aa28f9b766c3ccp-1,
    0x1.bceb771a02bdep2, -0x1.999999999999ap-3
  },
  { // Entry 146
    0x1.fdde6d7d992d4ffcd0a2446a9572b791p-1,
    0x1.bfffffffffffdp-1, 0x1.ffc7fffffffffp-6
  },
  { // Entry 147
    0x1.2492492492492f05397829cbc1ade69fp-1023,
    0x1.bffffffffffffp1022, -0x1.0p0
  },
  { // Entry 148
    0x1.cca34d8d609542352dfeaace528cb7a1p-818,
    0x1.cp-1033, 0x1.9555555555552p-1
  },
  { // Entry 149
    0x1.55cb805d3b6ab5c7675ce288db179f2bp-981,
    0x1.cp-1033, 0x1.e666666666662p-1
  },
  { // Entry 150
    0x1.97a3fcbacebe5d86d4f9675d3b8208f8p861,
    0x1.cp-1059, -0x1.a0ea0ea0ea0eap-1
  },
  { // Entry 151
    0x1.e926f3342729d100beab22b5029fa692p-956,
    0x1.cp-1071, 0x1.c8ebd48ebd498p-1
  },
  { // Entry 152
    0x1.f1668a877c3020c8505c45ae994bd358p-1002,
    0x1.cp-1071, 0x1.deeabb7884549p-1
  },
  { // Entry 153
    0x1.24924924924597829cbc14f0e93c746ep-1023,
    0x1.c000000000057p1022, -0x1.0p0
  },
  { // Entry 154
    0x1.c65c2cf3962da8013d40ee8c3b46bf1dp96,
    0x1.c25c268491610p-44, -0x1.1efeff5a273ecp1
  },
  { // Entry 155
    0x1.970c10d6b0a59a7fadf1e21e5ab677bep77,
    0x1.c25c268497682p-44, -0x1.cc6b93abbb074p0
  },
  { // Entry 156
    0x1.8583c2489a50380006c9c7205b5a54fep-1,
    0x1.c2e170b85c994p-2, 0x1.5555555555555p-2
  },
  { // Entry 157
    0x1.7e4573015bc63bd267679aab2cd89f66p-1,
    0x1.cb3c9484e2ad0p0, -0x1.0p-1
  },
  { // Entry 158
    0x1.7e3e719ce5b797fe885815bc3b2457f2p-1,
    0x1.cb4d69eb4f4b9p0, -0x1.0p-1
  },
  { // Entry 159
    0x1.fd4250a871c7fe00d5f51039c57dde6fp-624,
    0x1.ccc4c0fd63cb6p-1, 0x1.0p12
  },
  { // Entry 160
    0x1.5dc285d5b5f16800f6d7dc5ffdcf8d16p-1,
    0x1.d1745d1749883p-1, 0x1.ffc7fffffffffp1
  },
  { // Entry 161
    0x1.fea595d5c04f881438f7f5f10dbb0297p-2,
    0x1.d555555555552p-1, 0x1.ffc7fffffffffp2
  },
  { // Entry 162
    0x1.0000000000007ff04a26678b633a133ep0,
    0x1.d872441ec3905p2, 0x1.0000000000011p-50
  },
  { // Entry 163
    0x1.a63f4bd797f82805919b09d2b62da1e1p-1,
    0x1.da60a1f2ec608p-2, 0x1.007cd9524d3f4p-2
  },
  { // Entry 164
    0x1.a82e1469025c850c1448a19c2af67fe4p-500,
    0x1.db6db6db6db72p-2, 0x1.c30c30c30c3p8
  },
  { // Entry 165
    0x1.779a06bc3880e2c39dfc679749e470a5p-2,
    0x1.dbb0e0aa2dd0ep2, -0x1.0p-1
  },
  { // Entry 166
    0x1.f55b41ab4a675405b542703d9b037ae7p-408,
    0x1.dda95a95a95b1p-1, 0x1.fc0p11
  },
  { // Entry 167
    0x1.767fbad219a208018d6b81f7f3a2051bp2,
    0x1.de7f154838537p-6, -0x1.0p-1
  },
  { // Entry 168
    0x1.711d602ffb27f80209043d6d8f283cf8p-10,
    0x1.e66666666666bp-1, 0x1.ffffffffffff8p6
  },
  { // Entry 169
    0x1.ff5697396af157ffead748859ae3c9cbp1,
    0x1.eeeeeeeeeeeeep2, 0x1.5aaaaaaaaaaabp-1
  },
  { // Entry 170
    0x1.fe961a3ccd3c281ad0333d6806927b2bp-1,
    0x1.f07c1f07c1f07p-14, 0x1.40a57eb50296dp-12
  },
  { // Entry 171
    0x1.dac0c7cfbef05bd65a0e6ea2477f47fap778,
    0x1.f1a17d079e24fp-3, -0x1.7d9c0b5f3a960p8
  },
  { // Entry 172
    0x1.6ea69bd85b67cc85be83fa977dc123cap-1,
    0x1.f333333333324p0, -0x1.0p-1
  },
  { // Entry 173
    0x1.715bf92f43f00b403049e0c3e51153f8p-16,
    0x1.f664984b8a152p-21, 0x1.8b852ce2219f0p-1
  },
  { // Entry 174
    0x1.74368094efbfb380bb2df2e20e2a7a17p-85,
    0x1.f6ded8bc3fa43p-7, 0x1.c083595c2b1bcp3
  },
  { // Entry 175
    0x1.b0ef556006207718d3da08a90136726dp721,
    0x1.f83e0f83e0b8ap-1, -0x1.00000002b658ep15
  },
  { // Entry 176
    0x1.b0ef4cd94f8f8a8e603ff658f61fefb1p721,
    0x1.f83e0f83e0ba5p-1, -0x1.00000000221efp15
  },
  { // Entry 177
    0x1.b0ef4cd82f1387d76580a9eeaba656f6p721,
    0x1.f83e0f83e0bcfp-1, -0x1.00000000221efp15
  },
  { // Entry 178
    0x1.b0ef4cfb1cec37d64f37ea375597b740p721,
    0x1.f83e0f83e0bcfp-1, -0x1.000000002cb09p15
  },
  { // Entry 179
    0x1.b0ef555e269c6774a18b56af36947d82p721,
    0x1.f83e0f83e0bcfp-1, -0x1.00000002b6573p15
  },
  { // Entry 180
    0x1.b1c3042fe76ec74eb631776ea90c3cc6p721,
    0x1.f83e0f83e0bcfp-1, -0x1.00004000221efp15
  },
  { // Entry 181
    0x1.f2e92477d64c86fa54f6215ec8de5896p827,
    0x1.f83e0f83e0bcfp-1, -0x1.25ab6f7bced93p15
  },
  { // Entry 182
    0x1.b0ef4c04ab6f97a529350915504c0074p721,
    0x1.f83e0f83e0bcfp-1, -0x1.ffffffffc43dep14
  },
  { // Entry 183
    0x1.b0ef555b1dbe97d276d196306ba00051p721,
    0x1.f83e0f83e0c26p-1, -0x1.00000002b620fp15
  },
  { // Entry 184
    0x1.b0ef4cbe6dee68f697fc5885e43a3545p721,
    0x1.f83e0f83e0f80p-1, -0x1.00000000220p15
  },
  { // Entry 185
    0x1.661db242e13f78760f3385c48de6e14dp-716,
    0x1.f84f1b77aa61ep-1, 0x1.0000044p15
  },
  { // Entry 186
    0x1.6cc056593b1897fe7294556e85a7fccap-1,
    0x1.f869b10e1646ep0, -0x1.0p-1
  },
  { // Entry 187
    0x1.96ec199c8283280dcde1bf0a6bdf18ddp-33,
    0x1.f86d6f63aa049p-1, 0x1.780p10
  },
  { // Entry 188
    0x1.8d3575c5a08217e96d2baccd92102101p612,
    0x1.f96860afcb452p-1, -0x1.0000043fffeedp15
  },
  { // Entry 189
    0x1.8d3575c52ea31fea3d0799f8cf8523e3p612,
    0x1.f96860afcb468p-1, -0x1.0000043ffff85p15
  },
  { // Entry 190
    0x1.8d3575c472f0c863c06a976e22a25c6dp612,
    0x1.f96860afcb489p-1, -0x1.0000044p15
  },
  { // Entry 191
    0x1.8d3575c35aacefea95c885439d49bd99p612,
    0x1.f96860afcb4bbp-1, -0x1.00000440000d4p15
  },
  { // Entry 192
    0x1.8d3575c0cfc461bbe5ee3644cc6d77c2p612,
    0x1.f96860afcb506p-1, -0x1.0000043fffc79p15
  },
  { // Entry 193
    0x1.8d3575c1667df1163979824d863cc571p612,
    0x1.f96860afcb506p-1, -0x1.0000044000022p15
  },
  { // Entry 194
    0x1.8d3575b4fec588e56f1ba4bb2cde3d37p612,
    0x1.f96860afcb714p-1, -0x1.0000044000353p15
  },
  { // Entry 195
    0x1.8d3575ac3ff49ee0044041951d20706bp612,
    0x1.f96860afcb858p-1, -0x1.0000043fffe6dp15
  },
  { // Entry 196
    0x1.671986dbe53f56acd36ddaeec97277aap-46,
    0x1.f985f7cbf0059p-7, 0x1.e3fa3018bde08p2
  },
  { // Entry 197
    0x1.eec73eb3ed9247940e87750e7fc49479p1019,
    0x1.fa81a5e7d412cp-1, -0x1.000007ffef0p16
  },
  { // Entry 198
    0x1.6afc2b3669cafd8b04be07637cb8ce5ep-1,
    0x1.fd557019f1cd0p0, -0x1.0p-1
  },
  { // Entry 199
    0x1.c4f91d24e5c3e86f73ea68132bda4b8ap1002,
    0x1.fdfffffffffffp-3, -0x1.f3fffffffffffp8
  },
  { // Entry 200
    0x1.6a93b7f04694ad66b9aa64f76ba1fa38p-2,
    0x1.fe7b0ee6afa3cp2, -0x1.0p-1
  },
  { // Entry 201
    0x1.e1776bde16643808a38caf050f5cb630p-966,
    0x1.ff3e9ae3033aep-1, 0x1.ba6c13bf005ecp18
  },
  { // Entry 202
    0x1.d4ef5ecd754cd7f6e7016453994c21d5p-943,
    0x1.ff433a02ec964p-1, 0x1.ba7a347cdffebp18
  },
  { // Entry 203
    0x1.fe9bbdc161abd7fd9b32dbbc2d748438p-915,
    0x1.ff48e2b4a5d7ep-1, 0x1.ba8b810f5507fp18
  },
  { // Entry 204
    0x1.de52aa6a5ecaf8067797c9e2a281b23ep-905,
    0x1.ff4ae0e440fb6p-1, 0x1.ba9198ab03cd4p18
  },
  { // Entry 205
    0x1.76bc52dc7431f800000536a94bc3d305p133,
    0x1.ff77fffffffffp15, 0x1.0b1fdcd7590abp3
  },
  { // Entry 206
    0x1.5c1c2ded7213d991836fd2aa8dff4df7p-1023,
    0x1.ff7ffffffffffp0, -0x1.00000000cp10
  },
  { // Entry 207
    0x1.7a2b4d72ccfab7febb68ab3ac422cda7p-613,
    0x1.ff85796e4f063p-1, 0x1.bb44b86ca0928p18
  },
  { // Entry 208
    0x1.18a2faf8b5f6e8032837e7d87abcfa58p-410,
    0x1.ffae13ebf1872p-1, 0x1.bbc0d7c3a882cp18
  },
  { // Entry 209
    0x1.39e7d84a8958282053666d8c41938466p-739,
    0x1.fff0000006071p-1, 0x1.0000140p22
  },
  { // Entry 210
    0x1.e6ce6f49ea6028016050f5f38aefc204p795,
    0x1.fff800000e483p1023, 0x1.8df6b0df6b0e0p-1
  },
  { // Entry 211
    0x1.9aaa3cdd12dc05e246b234654b8dc76fp-442,
    0x1.fffffe7fffffep-1023, 0x1.ba2e8ba2e8ba4p-2
  },
  { // Entry 212
    0x1.f663278f73044832a2c1c5820c51cde7p-1,
    0x1.ffffff3ffffffp-8, 0x1.000000ep-8
  },
  { // Entry 213
    0x1.ffffffcd55554801c722bf7f371564d7p-1,
    0x1.ffffffbffffffp-1, 0x1.9555555555552p-1
  },
  { // Entry 214
    0x1.61c50ac8e0257000ca0d8b938dfe79abp567,
    0x1.ffffffbffffffp1023, 0x1.1bbbbbbbbbbb9p-1
  },
  { // Entry 215
    0x1.ffffff80000008p-199,
    0x1.ffffffcp-100, 0x1.0p1
  },
  { // Entry 216
    0x1.ffffff85291c6803b8547332d01f63b1p1023,
    0x1.ffffffff8ffffp7, 0x1.ffffffffe7e49p6
  },
  { // Entry 217
    0x1.ffffffc7fff45f951f3a78dcb59a7fa5p-897,
    0x1.ffffffffeffffp-2, 0x1.bffffffffffffp9
  },
  { // Entry 218
    0x1.7b29358d45f41a2f23ee22f80bb6fd08p508,
    0x1.fffffffff3ffep-1023, -0x1.fd8fd8fd8fd8ep-2
  },
  { // Entry 219
    0x1.e3437e70fec24558c1079cade561e276p-810,
    0x1.fffffffffbffep-1023, 0x1.9555555555552p-1
  },
  { // Entry 220
    0x1.fffffffffdfff7fffffeff97fe6ffeffp-1,
    0x1.fffffffffbfffp-1, 0x1.0000000000003p-1
  },
  { // Entry 221
    0x1.f6697c7afa0ac827d45b428b9c13ea46p77,
    0x1.ffffffffff0d6p952, 0x1.4f2094f2094f0p-4
  },
  { // Entry 222
    0x1.ffffffffffbc37ffffffff82436fffffp-1,
    0x1.ffffffffffb4bp-1, 0x1.cccccccccccccp-1
  },
  { // Entry 223
    0x1.ffffffffffcfe7ffffffffe232cfffffp-1,
    0x1.ffffffffffcd6p-1, 0x1.e666666666666p-1
  },
  { // Entry 224
    0x1.fffffffffff377ffffffffdbdfefffffp-1,
    0x1.ffffffffffe6fp-1, 0x1.ffffffffffff8p-2
  },
  { // Entry 225
    0x1.000000000003c7ffffffffeb431fffffp0,
    0x1.fffffffffff0ep-1, -0x1.ffffffffffe9bp-2
  },
  { // Entry 226
    0x1.000000000012d800000000ecb980p-3,
    0x1.fffffffffff37p0, -0x1.8p1
  },
  { // Entry 227
    0x1.ae89f995aaa93b8abea2c7b7cbcdc5e2p378,
    0x1.fffffffffff9fp2, 0x1.f8fffffffffffp6
  },
  { // Entry 228
    0x1.000000000193480000013fd6b24000aap-1015,
    0x1.fffffffffffa7p6, -0x1.220p7
  },
  { // Entry 229
    0x1.fffffffffffd07ffffffffffec4fffffp-1,
    0x1.fffffffffffcep-1, 0x1.e666666666666p-1
  },
  { // Entry 230
    0x1.ffffffffff1ce485fdf4a5fd3e671ea9p-1023,
    0x1.fffffffffffefp-5, 0x1.fefffffffffffp7
  },
  { // Entry 231
    0x1.00000000000047ffffffffffffffffffp0,
    0x1.ffffffffffff7p-1, -0x1.ffffffffffff7p-1
  },
  { // Entry 232
    0x1.0000000000002800000000000640p-1023,
    0x1.ffffffffffffbp1022, -0x1.0p0
  },
  { // Entry 233
    0x1.fffffffffffff8000006ffffffd0p-1,
    0x1.ffffffffffffcp-1, 0x1.fffffe3ffffffp-4
  },
  { // Entry 234
    0x1.fffffffffff17217f7d1cf8da0cc77cbp1023,
    0x1.ffffffffffffdp0, 0x1.0000000000002p10
  },
  { // Entry 235
    0x1.fffffffffff8b90bfbe8e7bf932596dfp1023,
    0x1.ffffffffffffdp1, 0x1.0000000000001p9
  },
  { // Entry 236
    0x1.00000000000007ffffffffffffdfffffp0,
    0x1.ffffffffffffep-1, -0x1.ffffffffffffep-2
  },
  { // Entry 237
    0x1.9fdf8bcce5346004c5f8fe1fe52b1115p56,
    0x1.ffffffffffffep-64, -0x1.ccccccccccccdp-1
  },
  { // Entry 238
    0x1.3354053613975801e1f18c607d9f7c96p-55,
    0x1.ffffffffffffep-224, 0x1.f6b0df6b0df6ap-3
  },
  { // Entry 239
    0x1.4337cd6b11bd77ff1dfb16e77447ef8ep157,
    0x1.ffffffffffffep-642, -0x1.f6b0df6b0df6cp-3
  },
  { // Entry 240
    0x1.9fdf8bcce571fb3c9561f337c9c427d4p278,
    0x1.ffffffffffffep-930, -0x1.3333333333337p-2
  },
  { // Entry 241
    0x1.ddb680117ab968057796e81914e78595p909,
    0x1.ffffffffffffep-1012, -0x1.ccccccccccccdp-1
  },
  { // Entry 242
    0x1.2387a6e756233000b49c3b0bf9c54982p1,
    0x1.ffffffffffffep4, 0x1.e66666666665cp-3
  },
  { // Entry 243
    0x1.a5adb8c8e32c1807a7da92b43f7cc90cp54,
    0x1.ffffffffffffep75, 0x1.70a3d70a3d70fp-1
  },
  { // Entry 244
    0x1.ec1deabbe3a9eae29bde56f88e8ef4eep627,
    0x1.ffffffffffffep813, 0x1.8af8af8af8af8p-1
  },
  { // Entry 245
    0x1.ffffffffff8f9dccd52d470a882669c3p647,
    0x1.ffffffffffffep863, 0x1.7fffffffffffdp-1
  },
  { // Entry 246
    0x1.00000004da20a7d2821cdfd4f6347dd0p128,
    0x1.fffffffffffffp-3, -0x1.000000000e0p6
  },
  { // Entry 247
    0x1.44ce541b60346c98094443b9faa84abdp10,
    0x1.fffffffffffffp1023, 0x1.4afd6a052c0e2p-7
  },
  { // Entry 248
    0x1.cb720dcef90691503cbd1e949db761d9p-1,
    0x1.0p-5, 0x1.0p-5
  },
  { // Entry 249
    0x1.p-5,
    0x1.0p-5, 0x1.0p0
  },
  { // Entry 250
    0x1.p0,
    0x1.0p0, 0x1.0p-5
  },
  { // Entry 251
    0x1.p0,
    0x1.0p0, 0x1.0p0
  },
  { // Entry 252
    0x1.p-40,
    0x1.0p-5, 0x1.0p3
  },
  { // Entry 253
    0x1.p-160,
    0x1.0p-5, 0x1.0p5
  },
  { // Entry 254
    0x1.p0,
    0x1.0p0, 0x1.0p3
  },
  { // Entry 255
    0x1.p0,
    0x1.0p0, 0x1.0p5
  },
  { // Entry 256
    0.0,
    0x1.0p-5, 0x1.0p10
  },
  { // Entry 257
    0.0,
    0x1.0p-5, 0x1.0p12
  },
  { // Entry 258
    0x1.p0,
    0x1.0p0, 0x1.0p10
  },
  { // Entry 259
    0x1.p0,
    0x1.0p0, 0x1.0p12
  },
  { // Entry 260
    0x1.11301d0125b50a4ebbf1aed9318ceac5p0,
    0x1.0p3, 0x1.0p-5
  },
  { // Entry 261
    0x1.p3,
    0x1.0p3, 0x1.0p0
  },
  { // Entry 262
    0x1.1d4873168b9aa7805b8028990f07a98bp0,
    0x1.0p5, 0x1.0p-5
  },
  { // Entry 263
    0x1.p5,
    0x1.0p5, 0x1.0p0
  },
  { // Entry 264
    0x1.p24,
    0x1.0p3, 0x1.0p3
  },
  { // Entry 265
    0x1.p96,
    0x1.0p3, 0x1.0p5
  },
  { // Entry 266
    0x1.p40,
    0x1.0p5, 0x1.0p3
  },
  { // Entry 267
    0x1.p160,
    0x1.0p5, 0x1.0p5
  },
  { // Entry 268
    HUGE_VAL,
    0x1.0p3, 0x1.0p10
  },
  { // Entry 269
    HUGE_VAL,
    0x1.0p3, 0x1.0p12
  },
  { // Entry 270
    HUGE_VAL,
    0x1.0p5, 0x1.0p10
  },
  { // Entry 271
    HUGE_VAL,
    0x1.0p5, 0x1.0p12
  },
  { // Entry 272
    0x1.3dea64c12342235b41223e13d773fba2p0,
    0x1.0p10, 0x1.0p-5
  },
  { // Entry 273
    0x1.p10,
    0x1.0p10, 0x1.0p0
  },
  { // Entry 274
    0x1.4bfdad5362a271d4397afec42e20e036p0,
    0x1.0p12, 0x1.0p-5
  },
  { // Entry 275
    0x1.p12,
    0x1.0p12, 0x1.0p0
  },
  { // Entry 276
    0x1.p80,
    0x1.0p10, 0x1.0p3
  },
  { // Entry 277
    0x1.p320,
    0x1.0p10, 0x1.0p5
  },
  { // Entry 278
    0x1.p96,
    0x1.0p12, 0x1.0p3
  },
  { // Entry 279
    0x1.p384,
    0x1.0p12, 0x1.0p5
  },
  { // Entry 280
    0x1.000000000000198d4d0da05571e9ad47p2,
    0x1.6a09e667f3bccp-1, -0x1.0p2
  },
  { // Entry 281
    0x1.ffffffffffffcce565e4bf5521467385p-3,
    0x1.6a09e667f3bccp-1, 0x1.0p2
  },
  { // Entry 282
    0x1.000000000000198d4d0da05571e9ad47p-2,
    0x1.6a09e667f3bccp0, -0x1.0p2
  },
  { // Entry 283
    0x1.ffffffffffffcce565e4bf5521467385p1,
    0x1.6a09e667f3bccp0, 0x1.0p2
  },
  { // Entry 284
    0x1.000000000000198d4d0da05571e9ad47p2,
    0x1.6a09e667f3bccp-1, -0x1.0p2
  },
  { // Entry 285
    0x1.ffffffffffffcce565e4bf5521467385p-3,
    0x1.6a09e667f3bccp-1, 0x1.0p2
  },
  { // Entry 286
    0x1.000000000000198d4d0da05571e9ad47p-2,
    0x1.6a09e667f3bccp0, -0x1.0p2
  },
  { // Entry 287
    0x1.ffffffffffffcce565e4bf5521467385p1,
    0x1.6a09e667f3bccp0, 0x1.0p2
  },
  { // Entry 288
    0x1.00162f3904051fa2c1b4e853746b6f04p0,
    0x1.6a09e667f3bccp-1, -0x1.0p-10
  },
  { // Entry 289
    0x1.ffd3a565efb64ea88a80d8a52554a3a0p-1,
    0x1.6a09e667f3bccp-1, 0x1.0p-10
  },
  { // Entry 290
    0x1.ffd3a565efb64eaeed467183b8d46a96p-1,
    0x1.6a09e667f3bccp0, -0x1.0p-10
  },
  { // Entry 291
    0x1.00162f3904051f9f8fc46b3743f85cbep0,
    0x1.6a09e667f3bccp0, 0x1.0p-10
  },
  { // Entry 292
    0x1.948b0fcd6e9e06522c3f35ba781948b0p1,
    0x1.8p-1, -0x1.0p2
  },
  { // Entry 293
    0x1.44p-2,
    0x1.8p-1, 0x1.0p2
  },
  { // Entry 294
    0x1.948b0fcd6e9e06522c3f35ba781948b0p-3,
    0x1.8p0, -0x1.0p2
  },
  { // Entry 295
    0x1.44p2,
    0x1.8p0, 0x1.0p2
  },
  { // Entry 296
    0x1.279a74590331c4d218f81e4afb257d06p0,
    0x1.8p-1, -0x1.0p-1
  },
  { // Entry 297
    0x1.bb67ae8584caa73b25742d7078b83b89p-1,
    0x1.8p-1, 0x1.0p-1
  },
  { // Entry 298
    0x1.a20bd700c2c3dfc042cc1aed7871db45p-1,
    0x1.8p0, -0x1.0p-1
  },
  { // Entry 299
    0x1.3988e1409212e7d0321914321a556473p0,
    0x1.8p0, 0x1.0p-1
  },
  { // Entry 300
    0x1.00126a0b93db294cabe33da735437f51p0,
    0x1.8p-1, -0x1.0p-10
  },
  { // Entry 301
    0x1.ffdb2e8ed2a1fe71bd59fdd610313046p-1,
    0x1.8p-1, 0x1.0p-10
  },
  { // Entry 302
    0x1.ffcc1c5973b2129a5b1424e0c88786b8p-1,
    0x1.8p0, -0x1.0p-10
  },
  { // Entry 303
    0x1.0019f474aa190038c6af775d92f1d725p0,
    0x1.8p0, 0x1.0p-10
  },
  { // Entry 304
    0x1.p0,
    0x1.0p0, -0x1.0p2
  },
  { // Entry 305
    0x1.p0,
    0x1.0p0, 0x1.0p2
  },
  { // Entry 306
    0x1.p-4,
    0x1.0p1, -0x1.0p2
  },
  { // Entry 307
    0x1.p4,
    0x1.0p1, 0x1.0p2
  },
  { // Entry 308
    0x1.p0,
    0x1.0p0, -0x1.0p-1
  },
  { // Entry 309
    0x1.p0,
    0x1.0p0, 0x1.0p-1
  },
  { // Entry 310
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1,
    0x1.0p1, -0x1.0p-1
  },
  { // Entry 311
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p1, 0x1.0p-1
  },
  { // Entry 312
    0x1.p0,
    0x1.0p0, -0x1.0p-10
  },
  { // Entry 313
    0x1.p0,
    0x1.0p0, 0x1.0p-10
  },
  { // Entry 314
    0x1.ffa74ea381efc217a773f15c025f7c0dp-1,
    0x1.0p1, -0x1.0p-10
  },
  { // Entry 315
    0x1.002c605e2e8cec506d21bfc89a23a010p0,
    0x1.0p1, 0x1.0p-10
  },
  { // Entry 316
    0x1.p40,
    0x1.0p-10, -0x1.0p2
  },
  { // Entry 317
    0x1.p-40,
    0x1.0p-10, 0x1.0p2
  },
  { // Entry 318
    0x1.fe013f6045e40a7c41499223b4a38ce8p-1,
    0x1.004p0, -0x1.0p2
  },
  { // Entry 319
    0x1.0100601001p0
```
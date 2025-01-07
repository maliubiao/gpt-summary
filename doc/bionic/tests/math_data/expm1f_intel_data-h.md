Response:
Let's break down the thought process for answering the request about `expm1f_intel_data.handroid`.

**1. Understanding the Core Request:**

The fundamental question is: "What is this file, what does it do, and how does it relate to Android?"  The path `bionic/tests/math_data/expm1f_intel_data.handroid` is a strong clue.

* **`bionic`:** This immediately signals that the file is related to Android's C library, math library, and dynamic linker.
* **`tests`:** This suggests the file is for testing purposes, not core functionality.
* **`math_data`:**  This points to data used for mathematical function tests.
* **`expm1f`:** This strongly suggests the data is related to the `expm1f` function, which calculates `e^x - 1`.
* **`intel_data`:**  This implies the data is specific to Intel architectures or was generated or chosen based on Intel's behavior.
* **`.handroid`:** This is likely a custom file extension indicating Android-specific test data.

**2. Identifying the File's Function:**

Given the path and the data structure (`data_1_1_t<float, float>`), it's clear the file provides test cases for the `expm1f` function. Each entry contains an input (`float`) and the expected output (`float`). The structure `data_1_1_t` strongly hints at a test framework that uses input-output pairs for verification.

**3. Connecting to Android Functionality:**

The `expm1f` function is part of the standard C math library (`libm`). In Android, this library is implemented by Bionic. Therefore, this test data is used to ensure the Bionic implementation of `expm1f` (specifically the single-precision version) works correctly on Android devices, particularly those with Intel processors.

**4. Explaining `libc` Functions (Specifically `expm1f`):**

The request asks for details on how the `libc` function is implemented. Since the *data* file is provided, not the source code of `expm1f` itself, the focus should be on what the function *does* conceptually.

* **Core functionality:**  `expm1f(x)` calculates `e^x - 1`.
* **Why `expm1f` exists:** For small values of `x`, calculating `e^x - 1` directly can lead to loss of precision because `e^x` is very close to 1. `expm1f` uses a more numerically stable approach (e.g., Taylor series expansion around 0) to avoid this.

**5. Addressing Dynamic Linker Aspects:**

This specific file doesn't directly involve the dynamic linker. It's just data. However, since the request asks about it:

* **`so` layout sample:** A simple example with `libm.so` containing `expm1f` is sufficient.
* **Linking process:** Briefly describe how the dynamic linker resolves the symbol `expm1f` when a program uses it.

**6. Logical Reasoning and Assumptions:**

The primary logical inference is that each entry in the array represents a test case. The input is the first `float`, and the expected output is the second. This allows for automated testing of the `expm1f` implementation.

* **Assumption:** The test framework reads this data and compares the actual output of `expm1f` against the expected output.

**7. Common Usage Errors:**

Consider how a programmer might misuse `expm1f` or related functions.

* **Incorrect function:** Using `expf(x) - 1.0f` for small `x`.
* **Input range:**  Understanding the function's domain (all representable floats).
* **Precision:** Being aware of the limitations of floating-point numbers.

**8. Android Framework/NDK Call Chain and Frida Hook:**

This requires understanding how an application might end up calling `expm1f`.

* **Framework/NDK:**  An app using the NDK could directly call `expm1f`. Framework components might indirectly use it.
* **Call chain:** A simplified example focusing on the NDK call path is good.
* **Frida Hook:** Demonstrate hooking `expm1f` to observe its input and output. This shows a practical debugging technique.

**9. Structuring the Answer:**

Organize the information logically, following the points raised in the request. Use clear headings and formatting for readability. Since the request is in Chinese, the answer should also be in Chinese.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:** Maybe this file contains lookup tables for `expm1f`.
* **Correction:** The `data_1_1_t` structure strongly suggests test inputs and expected outputs. Lookup tables are less likely for a function like `expm1f`.
* **Clarification:**  Emphasize that the provided file is *test data*, not the implementation of `expm1f` itself. This directly addresses a key part of the request.
* **Dynamic Linker Relevance:** Acknowledge that while this file isn't *directly* about the dynamic linker, the `expm1f` function it tests *is* part of a shared library loaded by the dynamic linker. This provides a relevant connection.

By following this thought process, breaking down the request into smaller parts, and considering the context of Android and Bionic, a comprehensive and accurate answer can be constructed.
这个文件 `bionic/tests/math_data/expm1f_intel_data.handroid` 是 Android Bionic 库中用于测试 `expm1f` 函数的数据文件。具体来说，它包含了针对 Intel 架构优化的 `expm1f` 函数的测试用例。

**功能列举:**

1. **提供 `expm1f` 函数的测试数据:** 该文件定义了一个名为 `g_expm1f_intel_data` 的数组，该数组存储了一系列 `data_1_1_t<float, float>` 类型的结构体。每个结构体包含一对 `float` 值：第一个值是 `expm1f` 函数的输入，第二个值是对应的预期输出。
2. **针对 Intel 架构:** 文件名中的 `intel_data` 表明这些测试用例可能是专门为了验证在 Intel 架构处理器上 `expm1f` 函数的正确性而设计的，可能包含了 Intel 架构上容易出现精度问题或者边界情况的测试。
3. **自动化测试的一部分:** 这个文件位于 `bionic/tests` 目录下，说明它是 Bionic 库自动化测试框架的一部分。测试框架会读取这个文件中的数据，并将输入值传递给 `expm1f` 函数，然后将函数的实际输出与文件中提供的预期输出进行比较，以验证函数的正确性。

**与 Android 功能的关系及举例:**

`expm1f(x)` 函数计算的是 e<sup>x</sup> - 1 的值。它是标准 C 库 `<math.h>` 中的一个函数，在 Android 的 Bionic 库中也有实现。这个函数在很多科学计算、金融计算、以及图形处理等领域都有应用。

**举例说明:**

* **Android Framework:** Android Framework 中的一些模块，例如与传感器数据处理、动画计算、或者高性能计算相关的部分，可能会间接地使用到 `expm1f` 或其他数学函数。例如，在计算指数衰减的动画效果时，可能会用到类似的功能。
* **Android NDK:** 使用 Android NDK 开发的应用程序可以直接调用 Bionic 库提供的 `expm1f` 函数。例如，一个进行科学计算的 NDK 应用可能需要计算 `expm1f` 来获得更高的精度，尤其是在 `x` 的值接近于 0 的时候。

**详细解释 `libc` 函数 `expm1f` 的功能是如何实现的:**

`expm1f(float x)` 函数计算 e<sup>x</sup> - 1，其中 `x` 是一个单精度浮点数。直接计算 e<sup>x</sup> - 1 当 `x` 非常接近 0 时可能会导致精度损失，因为 e<sup>x</sup> 会非常接近 1，相减会消去有效数字。因此，`expm1f` 通常采用更精确的算法，例如：

1. **针对小 `x` 值:** 当 `x` 的绝对值很小时，可以使用泰勒级数展开来近似计算 e<sup>x</sup> - 1：
   e<sup>x</sup> - 1 ≈ x + x<sup>2</sup>/2! + x<sup>3</sup>/3! + ...
   这种方法可以避免直接计算接近于 1 的值再相减造成的精度损失。

2. **针对较大 `x` 值:** 当 `x` 的绝对值较大时，可以直接计算 `expf(x) - 1.0f`。在这种情况下，精度损失通常不是主要问题。

3. **特殊情况处理:**  实现中还会处理一些特殊情况，例如：
   * `x` 为正无穷大：返回正无穷大。
   * `x` 为负无穷大：返回 -1.0。
   * `x` 为 NaN：返回 NaN。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`expm1f` 函数属于 `libm.so` (Math Library) 这个共享库。

**`libm.so` 布局样本 (简化):**

```
libm.so:
    .text:
        ... // 其他函数的代码
        expm1f:
            ; expm1f 函数的机器码
            ...
        ...
    .data:
        ... // 可能包含一些常量数据
    .dynsym:
        ...
        expm1f  // expm1f 符号
        ...
    .dynstr:
        ...
        expm1f  // expm1f 字符串
        ...
```

**链接的处理过程:**

1. **编译时:** 当一个程序（例如 NDK 应用）调用 `expm1f` 函数时，编译器会将这个函数调用标记为一个外部符号。链接器在链接这个程序时，会记录下对 `expm1f` 符号的引用，但此时并不知道 `expm1f` 的具体地址。

2. **运行时加载:** 当 Android 系统加载这个程序时，动态链接器 (`linker64` 或 `linker`) 负责加载程序依赖的共享库，包括 `libm.so`。

3. **符号解析 (Symbol Resolution):** 动态链接器会扫描已加载的共享库的符号表 (`.dynsym`)，查找程序中引用的外部符号。当找到 `libm.so` 中的 `expm1f` 符号时，动态链接器就找到了 `expm1f` 函数的实际地址。

4. **重定位 (Relocation):** 动态链接器会修改程序代码中的 `expm1f` 函数调用指令，将目标地址更新为 `libm.so` 中 `expm1f` 函数的实际地址。这样，当程序执行到调用 `expm1f` 的地方时，就能正确跳转到 `libm.so` 中的代码执行。

**如果做了逻辑推理，请给出假设输入与输出:**

该文件本身就是测试数据，已经包含了假设的输入和预期的输出。例如，查看文件内容：

```
{ // Entry 0
  -0x1.fffff00000555554000004444438e38ep-21,
  -0x1.p-20
},
```

* **假设输入:** `-0x1.fffff00000555554000004444438e38ep-21` (这是一个十六进制表示的浮点数，约等于 -1.9999998807907104e-07)
* **预期输出:** `-0x1.p-20` (这是一个十六进制表示的浮点数，等于 -9.5367431640625e-07)

这意味着当 `expm1f` 函数的输入是 `-0x1.fffff00000555554000004444438e38ep-21` 时，测试框架期望函数的输出是 `-0x1.p-20`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **精度问题:** 直接使用 `expf(x) - 1.0f` 计算当 `x` 非常接近 0 时，可能会因为浮点数精度问题导致结果不准确。应该使用 `expm1f` 来避免这种问题。

   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       float x = 1e-8f;
       float result1 = expf(x) - 1.0f;
       float result2 = expm1f(x);
       printf("expf(x) - 1.0f: %e\n", result1); // 可能精度较低
       printf("expm1f(x):      %e\n", result2); // 精度更高
       return 0;
   }
   ```

2. **误解函数功能:** 错误地认为 `expm1f(x)` 就是计算 e<sup>x</sup>。

3. **未包含头文件:** 在使用 `expm1f` 函数时，忘记包含 `<math.h>` 头文件。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `expm1f` 的路径 (间接调用):**

1. **Java Framework 调用:** Android Framework 中的某个 Java 类，例如负责动画计算的类，可能会调用 Native 代码 (JNI)。
2. **JNI 调用:** 这个 Java 类对应的 Native 代码会调用 Bionic 库中的某个函数。
3. **Bionic 库内部调用:**  这个 Bionic 库函数在实现其功能时，可能会调用 `libm.so` 中的 `expm1f` 函数。例如，一个复杂的数学计算或物理模拟模块可能会用到。

**Android NDK 到达 `expm1f` 的路径 (直接调用):**

1. **NDK 应用代码:**  开发者在 NDK 应用的 C/C++ 代码中直接调用 `expm1f` 函数。
2. **编译链接:** NDK 编译工具链会将该调用链接到 `libm.so` 中的 `expm1f` 函数。
3. **运行时加载:**  Android 系统在加载 NDK 应用时，动态链接器会将应用链接到 `libm.so`，从而使 `expm1f` 可以被调用。

**Frida Hook 示例:**

可以使用 Frida hook `expm1f` 函数来观察其输入和输出。

```python
import frida
import sys

# 要 hook 的目标进程，替换为你的应用包名或进程名
package_name = "your.package.name"

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName("libm.so", "expm1f"), {
    onEnter: function(args) {
        console.log("expm1f called with argument:", args[0]);
        console.log("Argument value:", parseFloat(args[0]));
    },
    onLeave: function(retval) {
        console.log("expm1f returned:", retval);
        console.log("Return value:", parseFloat(retval));
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script = session.create_script(hook_script)
script.on('message', on_message)
script.load()

print(f"[*] Hooking 'expm1f' in '{package_name}'. Press Ctrl+C to stop.")
sys.stdin.read()
```

**使用方法:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Frida 客户端 (`pip install frida-tools`).
2. **运行 Android 应用:** 运行你想要调试的 Android 应用，该应用需要调用 `expm1f` 函数。
3. **运行 Frida 脚本:** 将上面的 Python 代码保存为一个文件（例如 `hook_expm1f.py`），并将 `package_name` 替换为你的应用的包名或进程名。然后在终端中运行 `python hook_expm1f.py`。
4. **观察输出:** 当你的 Android 应用调用 `expm1f` 函数时，Frida 脚本会在终端中打印出 `expm1f` 函数的输入参数和返回值。

**调试步骤示例:**

假设你有一个 NDK 应用，其 C 代码中调用了 `expm1f`:

```c++
#include <jni.h>
#include <cmath>
#include <android/log.h>

#define LOG_TAG "MyNDKApp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jfloat JNICALL
Java_com_example_myapp_MainActivity_calculateExpm1f(JNIEnv *env, jobject /* this */, jfloat x) {
    float result = expm1f(x);
    LOGI("expm1f(%f) = %f", x, result);
    return result;
}
```

在你的 Java 代码中调用 `calculateExpm1f` 方法。运行 Frida 脚本后，当你触发 `calculateExpm1f` 的调用时，你将在终端看到类似以下的输出：

```
[*] Hooking 'expm1f' in 'com.example.myapp'. Press Ctrl+C to stop.
[*] expm1f called with argument: 0x40490fd0
[*] Argument value: 3.1415927410125732
[*] expm1f returned: 0x40c90fdb
[*] Return value: 22.414104461669922
```

这表明 `expm1f` 函数被调用，输入参数的浮点数值约为 3.1415927，返回值约为 22.4141044。通过 Frida Hook，你可以方便地观察函数的行为，用于调试和分析。

Prompt: 
```
这是目录为bionic/tests/math_data/expm1f_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
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

static data_1_1_t<float, float> g_expm1f_intel_data[] = {
  { // Entry 0
    -0x1.fffff00000555554000004444438e38ep-21,
    -0x1.p-20
  },
  { // Entry 1
    -0x1.fffff800001555552aaaaaeeeeee93e9p-22,
    -0x1.p-21
  },
  { // Entry 2
    -0x1.ffffff00000055555540000004444443p-25,
    -0x1.p-24
  },
  { // Entry 3
    -0x1.fffff40000155555bffffd99999b8e38p-21,
    -0x1.000002p-20
  },
  { // Entry 4
    -0x1.000000fffffcaaaaaa55555acccccb6cp-23,
    -0x1.000002p-23
  },
  { // Entry 5
    -0x1.92ead6fcef62fa8ffd6dddea52cb775dp-2,
    -0x1.0001p-1
  },
  { // Entry 6
    -0x1.0003ffffff7ffbfff8002aacaab2aaaap-40,
    -0x1.0004p-40
  },
  { // Entry 7
    -0x1.43eb2700073d423819fa85ce534f3bf1p-1,
    -0x1.005fp0
  },
  { // Entry 8
    -0x1.c59998f074353c5d0492e23cfecbc1f5p-3,
    -0x1.0060p-2
  },
  { // Entry 9
    -0x1.f48a2ae5cc72d28e4ff5d3940c608146p-5,
    -0x1.023ep-4
  },
  { // Entry 10
    -0x1.f2be57002fc371093dd9623ec6cdcf88p-4,
    -0x1.09e940p-3
  },
  { // Entry 11
    -0x1.4b3b8cffff78b97a60ce841d99138e34p-1,
    -0x1.0a866cp0
  },
  { // Entry 12
    -0x1.1e37fafffb5de84ddb61ac58d96c6109p-21,
    -0x1.1e38p-21
  },
  { // Entry 13
    -0x1.c96006fff735d59b28cc8226e99bd811p-2,
    -0x1.2efd0ap-1
  },
  { // Entry 14
    -0x1.d30023003cc4589a4a217749a50959dcp-1,
    -0x1.374118p1
  },
  { // Entry 15
    -0x1.7e8bcef9c4fe9e0ac2d05310f5cbd8f2p-1,
    -0x1.60p0
  },
  { // Entry 16
    -0x1.fffffffffffffffffffffffffffffffbp-1,
    -0x1.60p6
  },
  { // Entry 17
    -0x1.9758b6f38b012949e7b93c7f27202a48p-3,
    -0x1.c62ee0p-3
  },
  { // Entry 18
    -0x1.751b2169ee200a7bb4f26bccb619a80ep-2,
    -0x1.cffffep-2
  },
  { // Entry 19
    -0x1.a066d300130ff4e4fc65bad0a7f72ca1p-3,
    -0x1.d1848cp-3
  },
  { // Entry 20
    -0x1.fffff6ffff2933320eb3310fc95c97a5p-1,
    -0x1.e434dep3
  },
  { // Entry 21
    -0x1.fffff7fffffffffffffffffffffffffcp-127,
    -0x1.fffff8p-127
  },
  { // Entry 22
    -0x1.ffffffffffffffffffffffe6961ed7f0p-1,
    -0x1.fffffcp5
  },
  { // Entry 23
    0x1.0100ab00222d861931c15e39b44e9937p-7,
    0x1.p-7
  },
  { // Entry 24
    0x1.00000400000aaaaac000002222224fa4p-21,
    0x1.p-21
  },
  { // Entry 25
    0x1.bcab8900011ff456b56212f998951e38p0,
    0x1.01c18ep0
  },
  { // Entry 26
    0x1.b61e5ca3a5e30b2f0a03f28af9ce0084p93,
    0x1.04p6
  },
  { // Entry 27
    0x1.c62b1d7eea9cc6f6ea3ff782be73b0cbp0,
    0x1.0534p0
  },
  { // Entry 28
    0x1.aef1abc1b1c54e2429d81ddb79775eefp94,
    0x1.06b4e0p6
  },
  { // Entry 29
    0x1.94c2590c0ac9993e93aa8acaf1046c73p96,
    0x1.0c0040p6
  },
  { // Entry 30
    0x1.2a7938fffec9616b4d631cb33d990160p-3,
    0x1.16a150p-3
  },
  { // Entry 31
    0x1.752a64ffff6149fa0bd6f95bb10bf8e8p-1,
    0x1.184b62p-1
  },
  { // Entry 32
    0x1.37703d00002d814e4605b09d7ef15368p-4,
    0x1.2c2a90p-4
  },
  { // Entry 33
    0x1.44835afffef0f01e2e400989de81bd82p-3,
    0x1.2d3b76p-3
  },
  { // Entry 34
    0x1.021c84fffff5d54e4229ede943f4a168p7,
    0x1.378cb4p2
  },
  { // Entry 35
    0x1.ff2ac4707dee3cd35848bdb4d4296824p124,
    0x1.5a912cp6
  },
  { // Entry 36
    0x1.7ff7f6932445d2e31f1b7c20d7c7d871p126,
    0x1.5ef7bcp6
  },
  { // Entry 37
    0x1.f916467349b058b9c38906911b856052p126,
    0x1.60107cp6
  },
  { // Entry 38
    0x1.f76ba46733f4146a0f94b3d1311494bap127,
    0x1.62d2e2p6
  },
  { // Entry 39
    0x1.fff1086632b0e9b93bc5be44d9c1dea5p127,
    0x1.62e412p6
  },
  { // Entry 40
    0x1.8dbe63000000d7dc67e2e67575c06599p-3,
    0x1.6b7d8ap-3
  },
  { // Entry 41
    0x1.9185a8fffe5a4f000eb5ab63da3bfa3fp-3,
    0x1.6ea6e2p-3
  },
  { // Entry 42
    0x1.e5fa73631c80571bb785e84b1dff0fb4p70,
    0x1.894a52p5
  },
  { // Entry 43
    0x1.dfc5e500a0d64765f069273b7e215719p-2,
    0x1.897ba8p-2
  },
  { // Entry 44
    0x1.9a6e870bbb7b2779cded78be9b91a2dap71,
    0x1.8d7bdep5
  },
  { // Entry 45
    0x1.fb180600000c0175ee1c8855daaebdb6p1,
    0x1.9a0bccp0
  },
  { // Entry 46
    0x1.00f200ffff918c60a6f122a3b475e0fep-1,
    0x1.a074b8p-2
  },
  { // Entry 47
    0x1.c6b4aa00000bf2d58223ca9249b47316p-4,
    0x1.af311ap-4
  },
  { // Entry 48
    0x1.e1bcd4fffe314487556a09bb0c8a7551p-3,
    0x1.b0a4d4p-3
  },
  { // Entry 49
    0x1.d62649fffff82b1e6698411a08145a29p-4,
    0x1.bd11a8p-4
  },
  { // Entry 50
    0x1.05161b00011b9313efed24a09a8cb044p-2,
    0x1.d11ebap-3
  },
  { // Entry 51
    0x1.9a92e90baa2969fa8c71bb3c2be8bb40p85,
    0x1.db1e7ep5
  },
  { // Entry 52
    0x1.e63ebcfffee84008206c45435ee52722p-14,
    0x1.e63786p-14
  },
  { // Entry 53
    0x1.9768d30002d89bbd7f87c2131074c9c5p0,
    0x1.e788b8p-1
  },
  { // Entry 54
    0x1.6e23d980dd2d2fba285ff30446a78914p5,
    0x1.ec2f24p1
  },
  { // Entry 55
    0x1.a664d8ed7cc33ede965392722b0d87bfp22,
    0x1.f7fffep3
  },
  { // Entry 56
    0x1.b6904dfffe42514279db71397b7ffb45p0,
    0x1.ff07cep-1
  },
  { // Entry 57
    0x1.b6b11ea799b7c71cf2f6b9659c8155c6p0,
    0x1.ff1ffep-1
  },
  { // Entry 58
    0x1.3d59d2d8b22b41c2bb6334b9be7be902p92,
    0x1.ffdffep5
  },
  { // Entry 59
    0x1.00000b00000aaaa78fffe97777a4d832p-19,
    0x1.fffff6p-20
  },
  { // Entry 60
    0x1.fffff800000000000000000000000003p-127,
    0x1.fffff8p-127
  },
  { // Entry 61
    0x1.000001fffffaaaaa8ffffff77777fa4fp-21,
    0x1.fffffcp-22
  },
  { // Entry 62
    0x1.4258e1a2c0604eea1e874d7004e6dfb9p92,
    0x1.fffffcp5
  },
  { // Entry 63
    0x1.00000700001aaaaadd55554ccccba7d2p-20,
    0x1.fffffep-21
  },
  { // Entry 64
    0x1.304d1ed9511bf5a69db20e4cdbf6d8ffp69,
    0x1.7ffffep5
  },
  { // Entry 65
    0x1.304d6aeca254b3af43c5d6293d5f65c7p69,
    0x1.80p5
  },
  { // Entry 66
    0x1.304db70006924866b41845097c91e488p69,
    0x1.800002p5
  },
  { // Entry 67
    -0x1.ffffffffffffffffffc0e3377dc96717p-1,
    -0x1.a00002p5
  },
  { // Entry 68
    -0x1.ffffffffffffffffffc0e327b6954da3p-1,
    -0x1.a0p5
  },
  { // Entry 69
    -0x1.ffffffffffffffffffc0e317ef5d4261p-1,
    -0x1.9ffffep5
  },
  { // Entry 70
    0x1.5576f0dcac21787f2d57b14a700204e3p115,
    0x1.3ffffep6
  },
  { // Entry 71
    0x1.55779b984f3eb3c8a503b4a8e2487d98p115,
    0x1.40p6
  },
  { // Entry 72
    0x1.5578465447b9d5f83246af1e48e8025bp115,
    0x1.400002p6
  },
  { // Entry 73
    -0x1.fffffffffffffffffffffffffffffffbp-1,
    -0x1.600002p6
  },
  { // Entry 74
    -0x1.fffffffffffffffffffffffffffffffbp-1,
    -0x1.60p6
  },
  { // Entry 75
    -0x1.fffffffffffffffffffffffffffffffbp-1,
    -0x1.5ffffep6
  },
  { // Entry 76
    0x1.039924428f47511c03c75dd623bc47e1p75,
    0x1.9ffffep5
  },
  { // Entry 77
    0x1.03996528e074bebcfd56416fc2c0eb92p75,
    0x1.a0p5
  },
  { // Entry 78
    0x1.0399a60f41dbc2b085021312f505089dp75,
    0x1.a00002p5
  },
  { // Entry 79
    -0x1.fffffffffffffffff28a2d8657e93e43p-1,
    -0x1.800002p5
  },
  { // Entry 80
    -0x1.fffffffffffffffff28a2a28e2df25a0p-1,
    -0x1.80p5
  },
  { // Entry 81
    -0x1.fffffffffffffffff28a26cb6cfdafa0p-1,
    -0x1.7ffffep5
  },
  { // Entry 82
    0x1.f1047545465f97aad6774dfe16b960dep126,
    0x1.5ffffep6
  },
  { // Entry 83
    0x1.f1056dc7bf22d3de0ed57615bc501f87p126,
    0x1.60p6
  },
  { // Entry 84
    0x1.f106664ab4276b833993050c9aa09a91p126,
    0x1.600002p6
  },
  { // Entry 85
    -0x1.ffffffffffffffffffffffffffffd004p-1,
    -0x1.400002p6
  },
  { // Entry 86
    -0x1.ffffffffffffffffffffffffffffd004p-1,
    -0x1.40p6
  },
  { // Entry 87
    -0x1.ffffffffffffffffffffffffffffd004p-1,
    -0x1.3ffffep6
  },
  { // Entry 88
    -0x1.ffffffffffffffffffffffffffa57347p-1,
    -0x1.274768p6
  },
  { // Entry 89
    -0x1.fffffffffffffffffffffffffffffebdp-1,
    -0x1.4e8ed0p6
  },
  { // Entry 90
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.75d638p6
  },
  { // Entry 91
    -0x1.000000082e308632c06d5d65136575eap-1,
    -0x1.62e430p-1
  },
  { // Entry 92
    -0x1.fffffe105c601cc1e199f9261fc7dbe6p-2,
    -0x1.62e42ep-1
  },
  { // Entry 93
    -0x1.fffffc105c5d2d1e406993e20adc02bfp-2,
    -0x1.62e42cp-1
  },
  { // Entry 94
    -0x1.2bec333baa280850b6bf9111bb873f60p-2,
    -0x1.62e430p-2
  },
  { // Entry 95
    -0x1.2bec31d1a0414ba3511c18f32bb55d63p-2,
    -0x1.62e42ep-2
  },
  { // Entry 96
    -0x1.2bec30679659d9f0f7ed08e4eb06dfefp-2,
    -0x1.62e42cp-2
  },
  { // Entry 97
    -0x1.45d819b70d12db9f1551331188790df6p-3,
    -0x1.62e430p-3
  },
  { // Entry 98
    -0x1.45d81808831913911ad15724d9d51211p-3,
    -0x1.62e42ep-3
  },
  { // Entry 99
    -0x1.45d81659f91edfe0a1d20369bbdaa485p-3,
    -0x1.62e42cp-3
  },
  { // Entry 100
    -0x1.53f391912e7f21ab50219d67aa32363ap-4,
    -0x1.62e430p-4
  },
  { // Entry 101
    -0x1.53f38fbbacf136790727bc2da36b8afcp-4,
    -0x1.62e42ep-4
  },
  { // Entry 102
    -0x1.53f38de62b6310968c6cc9a7616b33cbp-4,
    -0x1.62e42cp-4
  },
  { // Entry 103
    -0x1.5b505d6b19f4b405dbb6b9ef18ad9e35p-5,
    -0x1.62e430p-5
  },
  { // Entry 104
    -0x1.5b505b80cefa7b6523305e22a4c06c28p-5,
    -0x1.62e42ep-5
  },
  { // Entry 105
    -0x1.5b5059968400241fbb0583252b4c1185p-5,
    -0x1.62e42cp-5
  },
  { // Entry 106
    -0x1.5f1349337820aba6ac332ded98347904p-6,
    -0x1.62e430p-6
  },
  { // Entry 107
    -0x1.5f13473e70baed6e4fa19cb1aefb9a04p-6,
    -0x1.62e42ep-6
  },
  { // Entry 108
    -0x1.5f13454969551f8db7e1db11f47dc315p-6,
    -0x1.62e42cp-6
  },
  { // Entry 109
    0x1.66c3485061b3fe6a5d2f2e20f3da3783p-6,
    0x1.62e42cp-6
  },
  { // Entry 110
    0x1.66c34a5b97ce491a4338414cff9666e6p-6,
    0x1.62e42ep-6
  },
  { // Entry 111
    0x1.66c34c66cde8a423da13eb5efee5340ep-6,
    0x1.62e430p-6
  },
  { // Entry 112
    0x1.6ab0d5d6d1d44992503e4b6f3b09f07ep-5,
    0x1.62e42cp-5
  },
  { // Entry 113
    0x1.6ab0d7ed7ce1b7b4c5ee2919ab4f11e6p-5,
    0x1.62e42ep-5
  },
  { // Entry 114
    0x1.6ab0da0427ef4741ec75f440fd4eb0f9p-5,
    0x1.62e430p-5
  },
  { // Entry 115
    0x1.72b838327ae1f9d7e70418a476da480dp-4,
    0x1.62e42cp-4
  },
  { // Entry 116
    0x1.72b83a60d1e9230cb3b52cd1200b8dcdp-4,
    0x1.62e42ep-4
  },
  { // Entry 117
    0x1.72b83c8f28f0920c614fc4456de049fcp-4,
    0x1.62e430p-4
  },
  { // Entry 118
    0x1.837f006a90e2d9adf9b9b9c5850970d1p-3,
    0x1.62e42cp-3
  },
  { // Entry 119
    0x1.837f02cb70a3406e2a79d1750af1d7e2p-3,
    0x1.62e42ep-3
  },
  { // Entry 120
    0x1.837f052c50643f664b66a02ec5ac16dbp-3,
    0x1.62e430p-3
  },
  { // Entry 121
    0x1.a827940eca9f76673e51d2c4569cfb3ap-2,
    0x1.62e42cp-2
  },
  { // Entry 122
    0x1.a82796e2de6a32d180ad0b353267983bp-2,
    0x1.62e42ep-2
  },
  { // Entry 123
    0x1.a82799b6f2365945a8c0fb40a27174dap-2,
    0x1.62e430p-2
  },
  { // Entry 124
    0x1.fffff820b8c9d86525e55f587e34861ap-1,
    0x1.62e42cp-1
  },
  { // Entry 125
    0x1.fffffc20b8c3f91dec78cb8cd53a92e3p-1,
    0x1.62e42ep-1
  },
  { // Entry 126
    0x1.000000105c610ceb57967842bd59f094p0,
    0x1.62e430p-1
  },
  { // Entry 127
    0x1.7ffff820b8d19779692fb0fcc0281246p1,
    0x1.62e42cp0
  },
  { // Entry 128
    0x1.7ffffc20b8c5d8eaff4ac013cf734639p1,
    0x1.62e42ep0
  },
  { // Entry 129
    0x1.80000020b8c21a5c85e8b244ed151cd8p1,
    0x1.62e430p0
  },
  { // Entry 130
    0x1.dffff04171c22b43a28d8088c347bf1fp3,
    0x1.62e42cp1
  },
  { // Entry 131
    0x1.dffff8417193310a429b71e70d792186p3,
    0x1.62e42ep1
  },
  { // Entry 132
    0x1.e0000041718436d066c07ca312f8b318p3,
    0x1.62e430p1
  },
  { // Entry 133
    0x1.fdffe082e40047c89dfa41d09c1e1ef8p7,
    0x1.62e42cp2
  },
  { // Entry 134
    0x1.fdfff082e3445ee55b3fa84a5dd849c9p7,
    0x1.62e42ep2
  },
  { // Entry 135
    0x1.fe000082e30875fe393de286837f485dp7,
    0x1.62e430p2
  },
  { // Entry 136
    0x1.fffdc105c9f0548760a823b0dfdaeb66p15,
    0x1.62e42cp3
  },
  { // Entry 137
    0x1.fffde105c700b10c3e2a549fbdebb0dap15,
    0x1.62e42ep3
  },
  { // Entry 138
    0x1.fffe0105c6110d722173b0ea5050713ap15,
    0x1.62e430p3
  },
  { // Entry 139
    0x1.ffff82099b9fbc6d5dda406ad9f93354p31,
    0x1.62e42cp4
  },
  { // Entry 140
    0x1.ffffc2098fe12f101740ac9653f78fe3p31,
    0x1.62e42ep4
  },
  { // Entry 141
    0x1.00000104c611505d7f74a41433312dp32,
    0x1.62e430p4
  },
  { // Entry 142
    0x1.fffe082f28688d3872ab8aa69f3dc356p127,
    0x1.62e42cp6
  },
  { // Entry 143
    0x1.ffff082e6c7fed1d3fd5cff7e1f6058fp127,
    0x1.62e42ep6
  },
  { // Entry 144
    HUGE_VALF,
    0x1.62e430p6
  },
  { // Entry 145
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.9d1da2p6
  },
  { // Entry 146
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.9d1da0p6
  },
  { // Entry 147
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.9d1d9ep6
  },
  { // Entry 148
    -0x1.c5041b725d705416b9a2fe9ecfd0f12fp-3,
    -0x1.000002p-2
  },
  { // Entry 149
    -0x1.c5041854df7d45e5f51a1b14e4b86234p-3,
    -0x1.p-2
  },
  { // Entry 150
    -0x1.c50416c620832945f52a143b7ab9cc40p-3,
    -0x1.fffffep-3
  },
  { // Entry 151
    -0x1.e14af110ec3368f6b0943acd54603c38p-4,
    -0x1.000002p-3
  },
  { // Entry 152
    -0x1.e14aed893eef3c3c14ed960d0a2b5054p-4,
    -0x1.p-3
  },
  { // Entry 153
    -0x1.e14aebc5684cd12688af02d3c4c33ae5p-4,
    -0x1.fffffep-4
  },
  { // Entry 154
    -0x1.f05407faf2db6e62ca86b906177f8ab4p-5,
    -0x1.000002p-4
  },
  { // Entry 155
    -0x1.f0540438fd5c31a1ce01f9f6ca74502bp-5,
    -0x1.p-4
  },
  { // Entry 156
    -0x1.f0540258029c6629cdc6e0688e0c17d1p-5,
    -0x1.fffffep-5
  },
  { // Entry 157
    -0x1.f8152ecf12fe0f7cc4305325eb3cc27ep-6,
    -0x1.000002p-5
  },
  { // Entry 158
    -0x1.f8152aee9450dd69fea80d113b1945c7p-6,
    -0x1.p-5
  },
  { // Entry 159
    -0x1.f81528fe54fa2d1da3d441866c2e2c68p-6,
    -0x1.fffffep-6
  },
  { // Entry 160
    -0x1.fc0553f461432629324524f0e3968455p-7,
    -0x1.000002p-6
  },
  { // Entry 161
    -0x1.fc055004416db60bbd08aac54a956e76p-7,
    -0x1.p-6
  },
  { // Entry 162
    -0x1.fc054e0c3182f22ca2e9fdd61fb3c4d6p-7,
    -0x1.fffffep-7
  },
  { // Entry 163
    -0x1.fe0158a2f6d2d965d520469a1b630418p-8,
    -0x1.000002p-7
  },
  { // Entry 164
    -0x1.fe0154aaeed83401a07666b3bbde908fp-8,
    -0x1.p-7
  },
  { // Entry 165
    -0x1.fe0152aeeadadb5b7a2976ba2d283634p-8,
    -0x1.fffffep-8
  },
  { // Entry 166
    -0x1.ff00593c0642dfd6d7680bd2846289e8p-9,
    -0x1.000002p-8
  },
  { // Entry 167
    -0x1.ff00554004438e52e1ee7b503e63818cp-9,
    -0x1.p-8
  },
  { // Entry 168
    -0x1.ff0053420343e293e5b233ee2249277bp-9,
    -0x1.fffffep-9
  },
  { // Entry 169
    -0x1.ff801950ab6ed1ed50ba61050b26a7c2p-10,
    -0x1.000002p-9
  },
  { // Entry 170
    -0x1.ff801552aaeee93efbe93ef05c2dcb20p-10,
    -0x1.p-9
  },
  { // Entry 171
    -0x1.ff801353aaaef3689150b624e4d2f2dap-10,
    -0x1.fffffep-10
  },
  { // Entry 172
    -0x1.ffc009540024406c8302028c7714cceap-11,
    -0x1.000002p-10
  },
  { // Entry 173
    -0x1.ffc0055500044416c30c23c298990114p-11,
    -0x1.p-10
  },
  { // Entry 174
    -0x1.ffc003557ff4452c130b34ed9d5c017ep-11,
    -0x1.fffffep-11
  },
  { // Entry 175
    -0x1.fff80415352b2acd9a413af860684c9cp-14,
    -0x1.000002p-13
  },
  { // Entry 176
    -0x1.fff80015552aaaeeee93e9a69a01a076p-14,
    -0x1.p-13
  },
  { // Entry 177
    -0x1.fff7fe15652a6ae7997d3dfdfecc3a6bp-14,
    -0x1.fffffep-14
  },
  { // Entry 178
    0x1.22d78dc6ea7dff08931d74663f93346dp-2,
    0x1.fffffep-3
  },
  { // Entry 179
    0x1.22d78f0fa06199d9ef0eda6eaaf94d3bp-2,
    0x1.p-2
  },
  { // Entry 180
    0x1.22d791a10c29c60511d91ff00eb6fedap-2,
    0x1.000002p-2
  },
  { // Entry 181
    0x1.10b021b964e233996eb974cb64f11f96p-3,
    0x1.fffffep-4
  },
  { // Entry 182
    0x1.10b022db7ae67ce76b441c27035c6a13p-3,
    0x1.p-3
  },
  { // Entry 183
    0x1.10b0251fa6ef7c4ba6003cf91fe85dc9p-3,
    0x1.000002p-3
  },
  { // Entry 184
    0x1.082b566cb2380e0be0d559a0150172f7p-4,
    0x1.fffffep-5
  },
  { // Entry 185
    0x1.082b577d34ed7d5b1a019e225c9a951bp-4,
    0x1.p-4
  },
  { // Entry 186
    0x1.082b599e3a588f120e61af4869c98421p-4,
    0x1.000002p-4
  },
  { // Entry 187
    0x1.040abf1a2f8334cf7c9ee0b1d34ae144p-5,
    0x1.fffffep-6
  },
  { // Entry 188
    0x1.040ac0224fd931c17a1075750192f4d5p-5,
    0x1.p-5
  },
  { // Entry 189
    0x1.040ac232908544687d03fabf568a3de2p-5,
    0x1.000002p-5
  },
  { // Entry 190
    0x1.0202ac5370d9ab5845b0e78f0b42a783p-6,
    0x1.fffffep-7
  },
  { // Entry 191
    0x1.0202ad5778e45eae192cfa41139ad15bp-6,
    0x1.p-6
  },
  { // Entry 192
    0x1.0202af5f88f9d18a20a5b04c4fc86c51p-6,
    0x1.000002p-6
  },
  { // Entry 193
    0x1.0100a9fe202c311aef67a75b93d0aff7p-7,
    0x1.fffffep-8
  },
  { // Entry 194
    0x1.0100ab00222d861931c15e39b44e9937p-7,
    0x1.p-7
  },
  { // Entry 195
    0x1.0100ad0426303621c27cd3ff977212f4p-7,
    0x1.000002p-7
  },
  { // Entry 196
    0x1.008029b456f7a855530b151055fcccd9p-8,
    0x1.fffffep-9
  },
  { // Entry 197
    0x1.00802ab55777d28a2a42d26aa9ee67bcp-8,
    0x1.p-8
  },
  { // Entry 198
    0x1.00802cb7587829f6da32ce4058b94099p-8,
    0x1.000002p-8
  },
  { // Entry 199
    0x1.004009ab80021fe4a3a269b377bf18d6p-9,
    0x1.fffffep-10
  },
  { // Entry 200
    0x1.00400aac002224fa83ab7ae5e991e737p-9,
    0x1.p-9
  },
  { // Entry 201
    0x1.00400cad006230a703eda58bed592121p-9,
    0x1.000002p-9
  },
  { // Entry 202
    0x1.002001aa954f77038c5ec3e966c711f3p-10,
    0x1.fffffep-11
  },
  { // Entry 203
    0x1.002002aad557778e39b3a1ba49dea952p-10,
    0x1.p-10
  },
  { // Entry 204
    0x1.002004ab55677963c4635dec1c0ebe87p-10,
    0x1.000002p-10
  },
  { // Entry 205
    0x1.0003ff0aa2bfe025cd19a5ad38b10c96p-13,
    0x1.fffffep-14
  },
  { // Entry 206
    0x1.0004000aaac00022224fa52e531931c1p-13,
    0x1.p-13
  },
  { // Entry 207
    0x1.0004020abac04032cd7ba730cfeb8c1ep-13,
    0x1.000002p-13
  },
  { // Entry 208
    -0x1.ffffffffffffffffffffffe6963841c5p-1,
    -0x1.000002p6
  },
  { // Entry 209
    -0x1.ffffffffffffffffffffffe6962b8cdep-1,
    -0x1.p6
  },
  { // Entry 210
    -0x1.ffffffffffffffffffffffe696253268p-1,
    -0x1.fffffep5
  },
  { // Entry 211
    -0x1.fffffffffff8dee88a6dbd53498e13ccp-1,
    -0x1.000002p5
  },
  { // Entry 212
    -0x1.fffffffffff8dee6c227a6e5f875997fp-1,
    -0x1.p5
  },
  { // Entry 213
    -0x1.fffffffffff8dee5de0470e8ba3e9067p-1,
    -0x1.fffffep4
  },
  { // Entry 214
    -0x1.fffffc3955017796a5082c3f27acd321p-1,
    -0x1.000002p4
  },
  { // Entry 215
    -0x1.fffffc395488a22f46a4b3411819a2eep-1,
    -0x1.p4
  },
  { // Entry 216
    -0x1.fffffc39544c3775ed71e1eab18a7021p-1,
    -0x1.fffffep3
  },
  { // Entry 217
    -0x1.ffd407c0b763bb2c6c6d1f372c7be8d8p-1,
    -0x1.000002p3
  },
  { // Entry 218
    -0x1.ffd407bdf7dfb0a688065730fe0231c2p-1,
    -0x1.p3
  },
  { // Entry 219
    -0x1.ffd407bc981d9ae67d3bdf5125871e80p-1,
    -0x1.fffffep2
  },
  { // Entry 220
    -0x1.f69f556ef4b73a33a7188427d84778e4p-1,
    -0x1.000002p2
  },
  { // Entry 221
    -0x1.f69f5523ef6185c40ba87f669ea8ee15p-1,
    -0x1.p2
  },
  { // Entry 222
    -0x1.f69f54fe6cb5ca7c3a7b03828a0e81ebp-1,
    -0x1.fffffep1
  },
  { // Entry 223
    -0x1.bab556862ca0e3235d497e670376d71fp-1,
    -0x1.000002p1
  },
  { // Entry 224
    -0x1.bab5557101f8d1809224547b4bf5aa38p-1,
    -0x1.p1
  },
  { // Entry 225
    -0x1.bab554e66ca328ef2e4cf602f5709f13p-1,
    -0x1.fffffep0
  },
  { // Entry 226
    -0x1.43a54fc74de82be41b573089f7ac0364p-1,
    -0x1.000002p0
  },
  { // Entry 227
    -0x1.43a54e4e988641ca8a4270fadf560de4p-1,
    -0x1.p0
  },
  { // Entry 228
    -0x1.43a54d923dd43235b78c235547ec9cdcp-1,
    -0x1.fffffep-1
  },
  { // Entry 229
    0x1.4259323902dbc6e62e3e07be26cd904cp92,
    0x1.fffffep5
  },
  { // Entry 230
    0x1.425982cf597cd205ce3d5b3edb031756p92,
    0x1.p6
  },
  { // Entry 231
    0x1.425a23fc432fb5d556006a3d8e7ee11bp92,
    0x1.000002p6
  },
  { // Entry 232
    0x1.1f43d8dc3904b8ed87a5abd50621706ap46,
    0x1.fffffep4
  },
  { // Entry 233
    0x1.1f43fcc4b65ec7d84788401842174074p46,
    0x1.p5
  },
  { // Entry 234
    0x1.1f444495be8a1616a1e5e388779bc146p46,
    0x1.000002p5
  },
  { // Entry 235
    0x1.0f2eaa1794b8f3edb5c10d26a51f420fp23,
    0x1.fffffep3
  },
  { // Entry 236
    0x1.0f2ebb0a8002049223f170882b5ee5efp23,
    0x1.p4
  },
  { // Entry 237
    0x1.0f2edcf059c1b22312bed964006ee633p23,
    0x1.000002p4
  },
  { // Entry 238
    0x1.747e9c2f7bb6cf5a276ee08236c2d6c3p11,
    0x1.fffffep2
  },
  { // Entry 239
    0x1.747ea7d470c6df0be00e084a815d1de6p11,
    0x1.p3
  },
  { // Entry 240
    0x1.747ebf1e5bfe757019de4e22b113fde9p11,
    0x1.000002p3
  },
  { // Entry 241
    0x1.acc8fc0f4fa7a2f2459a6ef53c315f0fp5,
    0x1.fffffep1
  },
  { // Entry 242
    0x1.acc902e273a58678d6d3bfdb93db96d0p5,
    0x1.p2
  },
  { // Entry 243
    0x1.acc91088bbf33336f0ee52b1ad858e43p5,
    0x1.000002p2
  },
  { // Entry 244
    0x1.98e647db814773f419262ee477a98616p2,
    0x1.fffffep0
  },
  { // Entry 245
    0x1.98e64b8d4ddadcc33a3ba206b68abba8p2,
    0x1.p1
  },
  { // Entry 246
    0x1.98e652f0e717d92d15cd610022ae51e3p2,
    0x1.000002p1
  },
  { // Entry 247
    0x1.b7e14eaaa99d23d07a843854f80eb965p0,
    0x1.fffffep-1
  },
  { // Entry 248
    0x1.b7e151628aed2a6abf7158809cf4f3c7p0,
    0x1.p0
  },
  { // Entry 249
    0x1.b7e156d24d955f43402b1af2d27591c2p0,
    0x1.000002p0
  },
  { // Entry 250
    HUGE_VALF,
    0x1.p124
  },
  { // Entry 251
    HUGE_VALF,
    0x1.99999ap124
  },
  { // Entry 252
    HUGE_VALF,
    0x1.19999ap125
  },
  { // Entry 253
    HUGE_VALF,
    0x1.666668p125
  },
  { // Entry 254
    HUGE_VALF,
    0x1.b33334p125
  },
  { // Entry 255
    HUGE_VALF,
    0x1.p126
  },
  { // Entry 256
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 257
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 258
    -0x1.p0,
    -HUGE_VALF
  },
  { // Entry 259
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 260
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffep127
  },
  { // Entry 261
    HUGE_VALF,
    0x1.fffffcp127
  },
  { // Entry 262
    -0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.fffffcp127
  },
  { // Entry 263
    0x1.6240490a165620d9b922aaa22a8e4c09p4,
    0x1.921fb6p1
  },
  { // Entry 264
    -0x1.e9dfdda51a16cb6a6c29449e73dceabap-1,
    -0x1.921fb6p1
  },
  { // Entry 265
    0x1.e7bdbace4109994c2555657347d02f77p1,
    0x1.921fb6p0
  },
  { // Entry 266
    -0x1.9590cf323040b06ca55a506162a742f5p-1,
    -0x1.921fb6p0
  },
  { // Entry 267
    0x1.b7e156d24d955f43402b1af2d27591c2p0,
    0x1.000002p0
  },
  { // Entry 268
    -0x1.43a54fc74de82be41b573089f7ac0364p-1,
    -0x1.000002p0
  },
  { // Entry 269
    0x1.b7e151628aed2a6abf7158809cf4f3c7p0,
    0x1.p0
  },
  { // Entry 270
    -0x1.43a54e4e988641ca8a4270fadf560de4p-1,
    -0x1.p0
  },
  { // Entry 271
    0x1.b7e14eaaa99d23d07a843854f80eb965p0,
    0x1.fffffep-1
  },
  { // Entry 272
    -0x1.43a54d923dd43235b78c235547ec9cdcp-1,
    -0x1.fffffep-1
  },
  { // Entry 273
    0x1.317acdf6c5663201980ec69bd74868acp0,
    0x1.921fb6p-1
  },
  { // Entry 274
    -0x1.168f476e16a8feaa2183b486fed0e5cep-1,
    -0x1.921fb6p-1
  },
  { // Entry 275
    0x1.00000200000000000000000000000002p-126,
    0x1.000002p-126
  },
  { // Entry 276
    -0x1.000001fffffffffffffffffffffffffdp-126,
    -0x1.000002p-126
  },
  { // Entry 277
    0x1.00000000000000000000000000000002p-126,
    0x1.p-126
  },
  { // Entry 278
    -0x1.fffffffffffffffffffffffffffffffcp-127,
    -0x1.p-126
  },
  { // Entry 279
    0x1.fffffc00000000000000000000000003p-127,
    0x1.fffffcp-127
  },
  { // Entry 280
    -0x1.fffffbfffffffffffffffffffffffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 281
    0x1.fffff800000000000000000000000003p-127,
    0x1.fffff8p-127
  },
  { // Entry 282
    -0x1.fffff7fffffffffffffffffffffffffcp-127,
    -0x1.fffff8p-127
  },
  { // Entry 283
    0x1.p-148,
    0x1.p-148
  },
  { // Entry 284
    -0x1.ffffffffffffffffffffffffffffffffp-149,
    -0x1.p-148
  },
  { // Entry 285
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 286
    -0.0f,
    -0x1.p-149
  },
  { // Entry 287
    0.0,
    0.0f
  },
  { // Entry 288
    -0.0,
    -0.0f
  },
  { // Entry 289
    0x1.ffff082e6c7fed1d3fd5cff7e1f6058fp127,
    0x1.62e42ep6
  },
  { // Entry 290
    HUGE_VALF,
    0x1.62e430p6
  }
};

"""

```
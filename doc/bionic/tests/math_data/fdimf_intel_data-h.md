Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The central task is to analyze the provided C code snippet, which is a data file for testing the `fdimf` function within Android's Bionic library. The request asks for the file's function, its relation to Android, how `fdimf` works, dynamic linking aspects (if any), logic inference, common errors, and how to reach this code from higher levels (Android Framework/NDK).

**2. Initial Assessment of the Code:**

The code is a static array `g_fdimf_intel_data` of a struct-like template `data_1_2_t`. Each element of the array contains three floating-point numbers. The file name `fdimf_intel_data.handroid` strongly suggests it's test data for the `fdimf` function, specifically targeting Intel architectures (hence "intel") and used in Android. The ".handroid" suffix likely signifies a specific test configuration or data set for Android.

**3. Identifying the Key Function:**

The filename directly points to the `fdimf` function. It's crucial to understand what `fdimf` does. A quick search (or prior knowledge) reveals that `fdimf(x, y)` returns `max(x - y, 0.0f)`.

**4. Analyzing the Data Structure:**

The `data_1_2_t<float, float, float>` template likely represents test cases. The first two `float` values are probably inputs to `fdimf`, and the third `float` is the expected output. This immediately gives the file's primary function: providing test vectors for `fdimf`.

**5. Connecting to Android:**

Since the file resides within `bionic/tests`, it's clearly part of Android's testing infrastructure. Bionic is Android's C library, so `fdimf` is a standard math function available to Android applications via the NDK. This connection needs to be explicitly stated with examples.

**6. Explaining `fdimf`'s Implementation:**

The request asks for a detailed explanation of `fdimf`. While the *exact* low-level assembly implementation isn't in this file, we can describe the logical implementation in C (as `return x > y ? x - y : 0.0f;`). It's also important to mention potential optimizations and platform-specific implementations within Bionic. No dynamic linking is directly evident in this *data* file.

**7. Dynamic Linking Aspects:**

Because `fdimf` is part of `libc.so`, dynamic linking is involved when an Android app uses it. This requires:
    * **SO Layout:** A conceptual layout of how `libc.so` (containing `fdimf`) would be loaded into memory.
    * **Linking Process:**  A high-level description of how the dynamic linker resolves the symbol `fdimf` at runtime. This involves looking up the symbol in the GOT and PLT.

**8. Logic Inference (Input/Output):**

The data file *is* the logic inference. Each entry provides a specific input pair and the expected output. It's good to pick a few examples and show how `fdimf` would calculate the result for those inputs. Mentioning the hexadecimal representation and its conversion to decimal is important for accuracy.

**9. Common Usage Errors:**

Think about how developers might misuse `fdimf`. Forgetting to include the necessary header (`<math.h>`), passing incorrect data types (although less likely with `fdimf`), or misunderstanding its behavior are common errors. Provide simple code examples illustrating these.

**10. Tracing the Execution Flow (Android Framework/NDK):**

This is about explaining how an application's call to `fdimf` reaches this test data (indirectly). The path is:
    * **Android Framework/NDK:**  App uses `std::fdim` or `<cmath>` which internally calls `fdimf`.
    * **libc.so:**  The `fdimf` implementation resides here.
    * **Testing:**  The `fdimf_intel_data.handroid` file is used during Bionic's *internal testing* to verify the correctness of the `fdimf` implementation. This file isn't directly used by apps at runtime.

**11. Frida Hooking:**

To demonstrate tracing, provide a Frida script that hooks the `fdimf` function. This script should log the input arguments and the return value, showing the interaction with `fdimf` at runtime. Explain *where* the hook is placed (in `libc.so`).

**12. Structuring the Answer:**

Organize the information logically, using clear headings and subheadings to address each part of the request. Use code blocks for code examples and ensure the language is clear and concise. Use markdown formatting for better readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this file directly used by applications?  **Correction:** No, it's test data for the library itself.
* **Consider:** How detailed should the dynamic linking explanation be? **Decision:**  Keep it at a high level, focusing on the GOT/PLT mechanism without delving into the linker's internal algorithms.
* **Realization:** The hexadecimal representation of floats is important for understanding the data. Include an explanation.
* **Ensure:** The Frida example is practical and demonstrates the intended point (observing `fdimf` calls).

By following this systematic approach, addressing each part of the prompt, and iteratively refining the explanations, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析一下 `bionic/tests/math_data/fdimf_intel_data.handroid` 这个文件。

**1. 文件的功能**

这个文件的主要功能是为 `fdimf` 函数提供测试数据。

* **`fdimf` 函数：**  `fdimf(x, y)` 是 C 标准库 `<math.h>` 中的一个数学函数，用于计算两个浮点数 `x` 和 `y` 的正差值，即 `max(x - y, 0.0f)`。换句话说，如果 `x > y`，则返回 `x - y`，否则返回 `0.0f`。
* **测试数据：** 文件中定义了一个静态数组 `g_fdimf_intel_data`，数组的元素是 `data_1_2_t<float, float, float>` 类型的结构体。每个结构体包含三个 `float` 类型的成员。
    * 前两个 `float` 成员很可能是 `fdimf` 函数的输入参数 `x` 和 `y`。
    * 第三个 `float` 成员很可能是针对给定输入参数 `x` 和 `y`，`fdimf` 函数的预期输出结果。
* **`_intel_data` 和 `.handroid` 后缀：**
    * `_intel_data` 表明这些测试数据可能针对的是 Intel 架构的处理器，因为不同的处理器架构在浮点数运算上可能存在细微差异，需要针对性地进行测试。
    * `.handroid`  通常表示这些数据是为 Android 平台定制或使用的。

**总结：** 该文件是一个测试数据集，用于验证 `fdimf` 函数在 Android 平台上（特别是 Intel 架构上）的实现是否正确。它包含一系列输入值和对应的预期输出值。

**2. 与 Android 功能的关系及举例说明**

这个文件直接关系到 Android 底层的数学库功能。

* **Bionic 库：**  该文件位于 `bionic/tests` 目录下，说明它是 Android 系统 C 库 Bionic 的一部分。Bionic 库提供了 Android 系统运行所需的基本 C 库函数，包括数学函数。
* **NDK (Native Development Kit)：** Android 应用程序可以通过 NDK 使用 C 和 C++ 代码。NDK 提供的 C 标准库实现就是 Bionic。因此，开发者在 NDK 代码中调用 `<math.h>` 中的 `fdimf` 函数时，最终会调用到 Bionic 库中实现的 `fdimf`。
* **Framework 层使用：** Android Framework 的某些底层组件，例如与图形、音频处理相关的 Native 代码，也可能直接使用 Bionic 提供的数学函数。

**举例说明：**

假设一个使用 NDK 开发的 Android 应用需要计算两个浮点数的正差值，它可以这样写：

```c++
#include <cmath>
#include <android/log.h>

#define TAG "FDimfTest"

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MainActivity_testFdimf(JNIEnv* env, jobject /* this */, float a, float b) {
    float result = std::fdim(a, b);
    __android_log_print(ANDROID_LOG_INFO, TAG, "fdimf(%f, %f) = %f", a, b, result);
}
```

在这个例子中，`std::fdim` 最终会调用 Bionic 库中的 `fdimf` 函数。而 `fdimf_intel_data.handroid` 这个文件中的数据，就在 Bionic 的测试过程中被用来验证 `fdimf` 的实现是否正确，以确保 NDK 开发的应用能够得到正确的计算结果。

**3. 详细解释 `libc` 函数的功能是如何实现的**

`fdimf` 函数的功能是计算正差值。其典型的 C 语言实现方式如下：

```c
#include <math.h>

float fdimf(float x, float y) {
  return x > y ? x - y : 0.0f;
}
```

**详细解释：**

1. **包含头文件：** 首先需要包含 `<math.h>` 头文件，该头文件声明了 `fdimf` 函数。
2. **函数签名：**  `float fdimf(float x, float y)` 定义了函数名、参数类型和返回类型。它接收两个 `float` 类型的参数 `x` 和 `y`，并返回一个 `float` 类型的值。
3. **条件判断：**  `x > y ? x - y : 0.0f;`  使用三元运算符进行条件判断。
    * **如果 `x > y` 为真：**  则执行 `x - y`，计算 `x` 和 `y` 的差值，并将结果作为函数的返回值。
    * **如果 `x > y` 为假（即 `x <= y`）：** 则执行 `0.0f`，函数返回浮点数零。

**Bionic 中的实现：**

Bionic 作为 Android 的 C 库，其 `fdimf` 的具体实现可能会更加复杂，包含针对特定架构的优化，例如使用 SIMD 指令 (SSE, AVX 等) 来提高浮点数运算的效率。但其核心逻辑仍然是上述的条件判断和减法运算。  查看 Bionic 的源代码（如果可以访问），可以找到更底层的汇编实现。

**4. 涉及 dynamic linker 的功能，so 布局样本和链接处理过程**

虽然 `fdimf_intel_data.handroid` 文件本身是静态数据，并不直接涉及 dynamic linker，但 `fdimf` 函数作为 `libc.so` 的一部分，其加载和链接过程与 dynamic linker 密切相关。

**SO 布局样本 (以 `libc.so` 为例):**

一个简化的 `libc.so` 内存布局可能如下所示：

```
地址范围      | 内容
-------------|------------------------------------
0xXXXXXXXX000 | .text (代码段，包含 fdimf 的机器码)
0xXXXXXXXXYYY | .rodata (只读数据段，例如字符串常量)
0xXXXXXXXXZZZ | .data (已初始化数据段，例如全局变量)
0xXXXXXXXXWWW | .bss (未初始化数据段，例如未初始化的全局变量)
0xAAAAAAAA000 | .plt (Procedure Linkage Table，过程链接表)
0xAAAAAAAA100 | .got (Global Offset Table，全局偏移表)
...           | 其他段 (例如 .symtab, .strtab 等符号表信息)
```

* **`.text` (代码段):** 包含 `fdimf` 函数的机器指令。
* **`.plt` (过程链接表):** 当程序首次调用外部共享库的函数时使用。`fdimf` 的 PLT 条目会指向 GOT 中相应的条目。
* **`.got` (全局偏移表):**  在程序运行时被 dynamic linker 填充，包含外部共享库函数的实际内存地址。最初，GOT 条目指向 PLT 中的一段代码，用于触发动态链接。

**链接的处理过程 (当应用调用 `fdimf` 时):**

1. **编译链接时：** 编译器在编译 NDK 代码时，如果遇到对 `fdimf` 的调用，会在生成的目标文件中生成对 `fdimf` 的未解析引用。链接器在链接这些目标文件生成最终的可执行文件或共享库时，会将对 `fdimf` 的引用记录下来，并将其放入 PLT 和 GOT 中。
2. **加载时：** 当 Android 系统加载应用程序时，dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，包括 `libc.so`。
3. **符号解析 (Lazy Binding 默认情况):** 默认情况下，动态链接是延迟发生的。当程序第一次调用 `fdimf` 时：
    * 程序跳转到 `fdimf` 在 PLT 中的条目。
    * PLT 条目会跳转到 GOT 中对应的条目。
    * **第一次调用时，GOT 条目指向 PLT 中的一段代码。** 这段代码会调用 dynamic linker 的解析函数。
    * Dynamic linker 在 `libc.so` 的符号表中查找 `fdimf` 的地址。
    * Dynamic linker 将 `fdimf` 在内存中的实际地址写入到 GOT 表中对应的条目。
    * Dynamic linker 将控制权返回给应用程序。
4. **后续调用：**  后续对 `fdimf` 的调用会直接跳转到 PLT 条目，然后 PLT 条目会直接跳转到 GOT 表中已经解析好的 `fdimf` 的实际地址，从而直接调用 `fdimf` 函数，避免了重复的符号解析过程。

**5. 逻辑推理 (假设输入与输出)**

`fdimf_intel_data.handroid` 文件本身就包含了逻辑推理的结果。让我们选取其中几个条目来解释：

* **Entry 0:**
    * 输入 `x`: `0x1.861861p-14` (十进制约为 9.999994e-05)
    * 输入 `y`: `-0x1.86187ep-15` (十进制约为 -1.000004e-05)
    * 输出: `-0x1.249250p-13` (十进制约为 -1.500003e-04)

    **分析：** 这里的预期输出是负数，这与 `fdimf` 的定义 `max(x - y, 0.0f)` 相矛盾。这可能表示该测试用例**预期 `fdimf` 的实现存在错误**，或者该测试数据用于**验证某些特定的错误处理场景**，例如输入为 NaN 或无穷大等。 仔细看注释 `/* Copyright (C) 2014 The Android Open Source Project */`,  这个文件是很老的代码，可能当时对 `fdimf` 的理解或者测试方式有所不同。

* **Entry 8:**
    * 输入 `x`: `0x1.p1` (十进制 2.0)
    * 输入 `y`: `0x1.p-149` (一个非常小的正数)
    * 输出: `-0x1.p1` (十进制 -2.0)

    **分析：** 同样，预期输出为负数，与 `fdimf` 的定义不符。 再次表明这可能是一个负面测试用例，或者历史遗留问题。

* **Entry 51:**
    * 输入 `x`: `0.0`
    * 输入 `y`: `0.0`
    * 输出: `0.0`

    **分析：**  `fdimf(0.0, 0.0) = max(0.0 - 0.0, 0.0) = max(0.0, 0.0) = 0.0`，符合 `fdimf` 的定义。

* **Entry 178:**
    * 输入 `x`: `0x1.fffffep127` (接近 float 的最大正值)
    * 输入 `y`: `0x1.fffffep127` (接近 float 的最大正值)
    * 输出: `0.0f`

    **分析：** `fdimf(max_float, max_float) = max(max_float - max_float, 0.0) = max(0.0, 0.0) = 0.0`，符合 `fdimf` 的定义。

**结论：**  虽然大多数测试用例符合 `fdimf` 的定义，但也有一些条目的预期输出为负数，这可能是用于测试错误处理或者历史遗留的负面测试用例。

**6. 用户或编程常见的使用错误及举例说明**

* **忘记包含头文件：** 如果在使用 `fdimf` 前没有包含 `<cmath>` (C++) 或 `<math.h>` (C) 头文件，会导致编译错误。

    ```c++
    // 错误示例：缺少头文件
    float a = 5.0f;
    float b = 3.0f;
    float diff = std::fdim(a, b); // 编译错误
    ```

* **参数类型错误：** `fdimf` 期望的参数类型是 `float`。如果传递了其他类型的参数，可能会发生隐式类型转换，导致精度损失或意外行为。虽然现代编译器通常会给出警告，但仍需注意。

    ```c++
    int a = 5;
    int b = 3;
    float diff = std::fdim((float)a, (float)b); // 显式转换更安全
    ```

* **误解 `fdimf` 的作用：**  新手可能会误以为 `fdimf` 就是简单的计算两个数的差值，而忽略了它返回的是正差值。

    ```c++
    float a = 3.0f;
    float b = 5.0f;
    float diff = std::fdim(a, b); // diff 的值为 0.0f，而不是 -2.0f
    ```

* **在需要绝对差值时使用 `fdimf`：** 如果目的是计算两个数的绝对差值，应该使用 `fabs(x - y)` 或 `std::abs(x - y)`，而不是 `fdimf`。

    ```c++
    float a = 3.0f;
    float b = 5.0f;
    float abs_diff = std::fabs(a - b); // abs_diff 的值为 2.0f
    ```

**7. 说明 Android Framework 或 NDK 是如何一步步到达这里的，给出 Frida hook 示例调试这些步骤**

1. **NDK 应用调用 `fdimf`：**  开发者在 NDK 代码中调用 `<cmath>` 中的 `std::fdim` 或 `<math.h>` 中的 `fdimf` 函数。
2. **Bionic `libc.so` 中的 `fdimf` 实现：** NDK 应用最终链接到 Android 系统的 `libc.so` 库，其中包含了 `fdimf` 的具体实现。
3. **`fdimf` 的执行：** 当应用运行到调用 `fdimf` 的代码时，会执行 `libc.so` 中 `fdimf` 的机器码。
4. **`fdimf_intel_data.handroid` 的使用（仅限测试）：**  **`fdimf_intel_data.handroid` 文件并不会在应用程序运行时被直接调用。**  它是在 Android 系统编译和测试 Bionic 库的过程中使用的。Bionic 的开发者会编写测试程序，读取这个文件中的数据，然后调用 Bionic 的 `fdimf` 函数，并将结果与文件中预期的输出进行比较，以验证 `fdimf` 的实现是否正确。

**Frida Hook 示例：**

我们可以使用 Frida 来 hook `libc.so` 中的 `fdimf` 函数，观察其输入参数和返回值。

```javascript
// frida hook 脚本

if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const fdimf = Module.findExportByName("libc.so", "fdimf");
    if (fdimf) {
        Interceptor.attach(fdimf, {
            onEnter: function (args) {
                this.arg0 = args[0].readFloat();
                this.arg1 = args[1].readFloat();
                console.log(`Called fdimf with arguments: ${this.arg0}, ${this.arg1}`);
            },
            onLeave: function (retval) {
                const result = retval.readFloat();
                console.log(`fdimf returned: ${result}`);
            }
        });
        console.log("Successfully hooked fdimf");
    } else {
        console.log("Failed to find fdimf in libc.so");
    }
} else {
    console.log("Frida script designed for arm64 or x64 architectures.");
}
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `hook_fdimf.js`。
2. 确保你的 Android 设备或模拟器上运行着目标应用，并且安装了 Frida 服务。
3. 使用 Frida 命令运行 hook 脚本，替换 `com.example.myapp` 为你的应用进程名：

   ```bash
   frida -U -f com.example.myapp -l hook_fdimf.js --no-pause
   ```

   或者，如果应用已经在运行：

   ```bash
   frida -U com.example.myapp -l hook_fdimf.js
   ```

**预期输出：**

当你的 Android 应用调用 `std::fdim` 或 `fdimf` 时，Frida 会拦截该调用并在控制台输出以下信息：

```
Called fdimf with arguments: 5.0, 3.0
fdimf returned: 2.0
Called fdimf with arguments: 3.0, 5.0
fdimf returned: 0.0
```

**说明：**

* `Module.findExportByName("libc.so", "fdimf")` 用于在 `libc.so` 库中查找 `fdimf` 函数的地址。
* `Interceptor.attach()` 用于拦截对 `fdimf` 函数的调用。
* `onEnter` 函数在 `fdimf` 函数被调用之前执行，可以访问函数的参数。
* `onLeave` 函数在 `fdimf` 函数返回之后执行，可以访问函数的返回值。
* `args[0].readFloat()` 和 `args[1].readFloat()` 用于读取 `fdimf` 的浮点数参数。
* `retval.readFloat()` 用于读取 `fdimf` 的浮点数返回值。

通过 Frida hook，你可以动态地观察 Android 系统中 `fdimf` 函数的调用情况，这对于调试和理解底层库的行为非常有帮助。

希望这个详细的分析能够解答你的问题!

Prompt: 
```
这是目录为bionic/tests/math_data/fdimf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_2_t<float, float, float> g_fdimf_intel_data[] = {
  { // Entry 0
    0x1.861861p-14,
    -0x1.86187ep-15,
    -0x1.249250p-13
  },
  { // Entry 1
    0x1.334d69p-2,
    -0x1.99999ep-3,
    -0x1.000d1cp-1
  },
  { // Entry 2
    0x1.99b3d1p-2,
    -0x1.99999ep-3,
    -0x1.334050p-1
  },
  { // Entry 3
    0x1.999999p-12,
    -0x1.99999ep-13,
    -0x1.333334p-11
  },
  { // Entry 4
    0x1.111e2bp-1,
    -0x1.dddde2p-2,
    -0x1.00068ep0
  },
  { // Entry 5
    0x1.111e29p-1,
    -0x1.dddde6p-2,
    -0x1.00068ep0
  },
  { // Entry 6
    0x1.04a781p-11,
    -0x1.f6b0fep-12,
    -0x1.p-10
  },
  { // Entry 7
    0x1.02960bp-11,
    -0x1.fad3eap-12,
    -0x1.p-10
  },
  { // Entry 8
    0x1.p1,
    0x1.p-149,
    -0x1.p1
  },
  { // Entry 9
    0x1.000001fffffffffffff286bac0p73,
    0x1.000002p73,
    0x1.af28a8p-4
  },
  { // Entry 10
    0x1.249269p-2,
    0x1.08p-21,
    -0x1.249248p-2
  },
  { // Entry 11
    0x1.af2851p-4,
    0x1.08p-23,
    -0x1.af2830p-4
  },
  { // Entry 12
    0x1.000021p-24,
    0x1.08p-43,
    -0x1.p-24
  },
  { // Entry 13
    0x1.4ff4d3p3,
    0x1.083d28p2,
    -0x1.97ac7ep2
  },
  { // Entry 14
    0x1.fffffcp127,
    0x1.fffffcp127,
    -0x1.90p-143
  },
  { // Entry 15
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 16
    0.0,
    -0x1.40p3,
    -0x1.40p3
  },
  { // Entry 17
    0x1.p1,
    -0x1.p3,
    -0x1.40p3
  },
  { // Entry 18
    0x1.p2,
    -0x1.80p2,
    -0x1.40p3
  },
  { // Entry 19
    0x1.80p2,
    -0x1.p2,
    -0x1.40p3
  },
  { // Entry 20
    0x1.p3,
    -0x1.p1,
    -0x1.40p3
  },
  { // Entry 21
    0x1.40p3,
    0.0,
    -0x1.40p3
  },
  { // Entry 22
    0x1.80p3,
    0x1.p1,
    -0x1.40p3
  },
  { // Entry 23
    0x1.c0p3,
    0x1.p2,
    -0x1.40p3
  },
  { // Entry 24
    0x1.p4,
    0x1.80p2,
    -0x1.40p3
  },
  { // Entry 25
    0x1.20p4,
    0x1.p3,
    -0x1.40p3
  },
  { // Entry 26
    0x1.40p4,
    0x1.40p3,
    -0x1.40p3
  },
  { // Entry 27
    0.0,
    -0x1.80p-148,
    -0x1.80p-148
  },
  { // Entry 28
    0.0,
    -0x1.80p-148,
    -0x1.p-148
  },
  { // Entry 29
    0.0,
    -0x1.80p-148,
    -0x1.p-149
  },
  { // Entry 30
    0.0,
    -0x1.80p-148,
    0.0
  },
  { // Entry 31
    0.0,
    -0x1.80p-148,
    0x1.p-149
  },
  { // Entry 32
    0.0,
    -0x1.80p-148,
    0x1.p-148
  },
  { // Entry 33
    0.0,
    -0x1.80p-148,
    0x1.80p-148
  },
  { // Entry 34
    0x1.p-149,
    -0x1.p-148,
    -0x1.80p-148
  },
  { // Entry 35
    0.0,
    -0x1.p-148,
    -0x1.p-148
  },
  { // Entry 36
    0.0,
    -0x1.p-148,
    -0x1.p-149
  },
  { // Entry 37
    0.0,
    -0x1.p-148,
    0.0
  },
  { // Entry 38
    0.0,
    -0x1.p-148,
    0x1.p-149
  },
  { // Entry 39
    0.0,
    -0x1.p-148,
    0x1.p-148
  },
  { // Entry 40
    0.0,
    -0x1.p-148,
    0x1.80p-148
  },
  { // Entry 41
    0x1.p-148,
    -0x1.p-149,
    -0x1.80p-148
  },
  { // Entry 42
    0x1.p-149,
    -0x1.p-149,
    -0x1.p-148
  },
  { // Entry 43
    0.0,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 44
    0.0,
    -0x1.p-149,
    0.0
  },
  { // Entry 45
    0.0,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 46
    0.0,
    -0x1.p-149,
    0x1.p-148
  },
  { // Entry 47
    0.0,
    -0x1.p-149,
    0x1.80p-148
  },
  { // Entry 48
    0x1.80p-148,
    0.0,
    -0x1.80p-148
  },
  { // Entry 49
    0x1.p-148,
    0.0,
    -0x1.p-148
  },
  { // Entry 50
    0x1.p-149,
    0.0,
    -0x1.p-149
  },
  { // Entry 51
    0.0,
    0.0,
    0.0
  },
  { // Entry 52
    0.0,
    0.0,
    0x1.p-149
  },
  { // Entry 53
    0.0,
    0.0,
    0x1.p-148
  },
  { // Entry 54
    0.0,
    0.0,
    0x1.80p-148
  },
  { // Entry 55
    0x1.p-147,
    0x1.p-149,
    -0x1.80p-148
  },
  { // Entry 56
    0x1.80p-148,
    0x1.p-149,
    -0x1.p-148
  },
  { // Entry 57
    0x1.p-148,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 58
    0x1.p-149,
    0x1.p-149,
    0.0
  },
  { // Entry 59
    0.0,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 60
    0.0,
    0x1.p-149,
    0x1.p-148
  },
  { // Entry 61
    0.0,
    0x1.p-149,
    0x1.80p-148
  },
  { // Entry 62
    0x1.40p-147,
    0x1.p-148,
    -0x1.80p-148
  },
  { // Entry 63
    0x1.p-147,
    0x1.p-148,
    -0x1.p-148
  },
  { // Entry 64
    0x1.80p-148,
    0x1.p-148,
    -0x1.p-149
  },
  { // Entry 65
    0x1.p-148,
    0x1.p-148,
    0.0
  },
  { // Entry 66
    0x1.p-149,
    0x1.p-148,
    0x1.p-149
  },
  { // Entry 67
    0.0,
    0x1.p-148,
    0x1.p-148
  },
  { // Entry 68
    0.0,
    0x1.p-148,
    0x1.80p-148
  },
  { // Entry 69
    0x1.80p-147,
    0x1.80p-148,
    -0x1.80p-148
  },
  { // Entry 70
    0x1.40p-147,
    0x1.80p-148,
    -0x1.p-148
  },
  { // Entry 71
    0x1.p-147,
    0x1.80p-148,
    -0x1.p-149
  },
  { // Entry 72
    0x1.80p-148,
    0x1.80p-148,
    0.0
  },
  { // Entry 73
    0x1.p-148,
    0x1.80p-148,
    0x1.p-149
  },
  { // Entry 74
    0x1.p-149,
    0x1.80p-148,
    0x1.p-148
  },
  { // Entry 75
    0.0,
    0x1.80p-148,
    0x1.80p-148
  },
  { // Entry 76
    0.0,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 77
    0.0,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 78
    0.0,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 79
    0.0,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 80
    0x1.p-148,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 81
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 82
    0x1.fffffep127,
    0x1.fffffep127,
    0.0
  },
  { // Entry 83
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 84
    0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 85
    0.0,
    0.0,
    0x1.fffffep127
  },
  { // Entry 86
    0.0,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 87
    0x1.fffffep127,
    0x1.fffffep126,
    -0x1.fffffep126
  },
  { // Entry 88
    0.0,
    0x1.fffff8p-128,
    0x1.fffff8p-128
  },
  { // Entry 89
    0.0,
    0x1.fffff8p-128,
    0x1.p-127
  },
  { // Entry 90
    0.0,
    0x1.fffff8p-128,
    0x1.000004p-127
  },
  { // Entry 91
    0x1.p-149,
    0x1.p-127,
    0x1.fffff8p-128
  },
  { // Entry 92
    0.0,
    0x1.p-127,
    0x1.p-127
  },
  { // Entry 93
    0.0,
    0x1.p-127,
    0x1.000004p-127
  },
  { // Entry 94
    0x1.p-148,
    0x1.000004p-127,
    0x1.fffff8p-128
  },
  { // Entry 95
    0x1.p-149,
    0x1.000004p-127,
    0x1.p-127
  },
  { // Entry 96
    0.0,
    0x1.000004p-127,
    0x1.000004p-127
  },
  { // Entry 97
    0.0,
    0x1.fffffep-51,
    0x1.fffffep-51
  },
  { // Entry 98
    0.0,
    0x1.fffffep-51,
    0x1.p-50
  },
  { // Entry 99
    0.0,
    0x1.fffffep-51,
    0x1.000002p-50
  },
  { // Entry 100
    0x1.p-74,
    0x1.p-50,
    0x1.fffffep-51
  },
  { // Entry 101
    0.0,
    0x1.p-50,
    0x1.p-50
  },
  { // Entry 102
    0.0,
    0x1.p-50,
    0x1.000002p-50
  },
  { // Entry 103
    0x1.80p-73,
    0x1.000002p-50,
    0x1.fffffep-51
  },
  { // Entry 104
    0x1.p-73,
    0x1.000002p-50,
    0x1.p-50
  },
  { // Entry 105
    0.0,
    0x1.000002p-50,
    0x1.000002p-50
  },
  { // Entry 106
    0.0,
    0x1.fffffep-11,
    0x1.fffffep-11
  },
  { // Entry 107
    0.0,
    0x1.fffffep-11,
    0x1.p-10
  },
  { // Entry 108
    0.0,
    0x1.fffffep-11,
    0x1.000002p-10
  },
  { // Entry 109
    0x1.p-34,
    0x1.p-10,
    0x1.fffffep-11
  },
  { // Entry 110
    0.0,
    0x1.p-10,
    0x1.p-10
  },
  { // Entry 111
    0.0,
    0x1.p-10,
    0x1.000002p-10
  },
  { // Entry 112
    0x1.80p-33,
    0x1.000002p-10,
    0x1.fffffep-11
  },
  { // Entry 113
    0x1.p-33,
    0x1.000002p-10,
    0x1.p-10
  },
  { // Entry 114
    0.0,
    0x1.000002p-10,
    0x1.000002p-10
  },
  { // Entry 115
    0.0,
    0x1.fffffep-2,
    0x1.fffffep-2
  },
  { // Entry 116
    0.0,
    0x1.fffffep-2,
    0x1.p-1
  },
  { // Entry 117
    0.0,
    0x1.fffffep-2,
    0x1.000002p-1
  },
  { // Entry 118
    0x1.p-25,
    0x1.p-1,
    0x1.fffffep-2
  },
  { // Entry 119
    0.0,
    0x1.p-1,
    0x1.p-1
  },
  { // Entry 120
    0.0,
    0x1.p-1,
    0x1.000002p-1
  },
  { // Entry 121
    0x1.80p-24,
    0x1.000002p-1,
    0x1.fffffep-2
  },
  { // Entry 122
    0x1.p-24,
    0x1.000002p-1,
    0x1.p-1
  },
  { // Entry 123
    0.0,
    0x1.000002p-1,
    0x1.000002p-1
  },
  { // Entry 124
    0.0,
    0x1.fffffep0,
    0x1.fffffep0
  },
  { // Entry 125
    0.0,
    0x1.fffffep0,
    0x1.p1
  },
  { // Entry 126
    0.0,
    0x1.fffffep0,
    0x1.000002p1
  },
  { // Entry 127
    0x1.p-23,
    0x1.p1,
    0x1.fffffep0
  },
  { // Entry 128
    0.0,
    0x1.p1,
    0x1.p1
  },
  { // Entry 129
    0.0,
    0x1.p1,
    0x1.000002p1
  },
  { // Entry 130
    0x1.80p-22,
    0x1.000002p1,
    0x1.fffffep0
  },
  { // Entry 131
    0x1.p-22,
    0x1.000002p1,
    0x1.p1
  },
  { // Entry 132
    0.0,
    0x1.000002p1,
    0x1.000002p1
  },
  { // Entry 133
    0.0,
    0x1.fffffep9,
    0x1.fffffep9
  },
  { // Entry 134
    0.0,
    0x1.fffffep9,
    0x1.p10
  },
  { // Entry 135
    0.0,
    0x1.fffffep9,
    0x1.000002p10
  },
  { // Entry 136
    0x1.p-14,
    0x1.p10,
    0x1.fffffep9
  },
  { // Entry 137
    0.0,
    0x1.p10,
    0x1.p10
  },
  { // Entry 138
    0.0,
    0x1.p10,
    0x1.000002p10
  },
  { // Entry 139
    0x1.80p-13,
    0x1.000002p10,
    0x1.fffffep9
  },
  { // Entry 140
    0x1.p-13,
    0x1.000002p10,
    0x1.p10
  },
  { // Entry 141
    0.0,
    0x1.000002p10,
    0x1.000002p10
  },
  { // Entry 142
    0.0,
    0x1.fffffep49,
    0x1.fffffep49
  },
  { // Entry 143
    0.0,
    0x1.fffffep49,
    0x1.p50
  },
  { // Entry 144
    0.0,
    0x1.fffffep49,
    0x1.000002p50
  },
  { // Entry 145
    0x1.p26,
    0x1.p50,
    0x1.fffffep49
  },
  { // Entry 146
    0.0,
    0x1.p50,
    0x1.p50
  },
  { // Entry 147
    0.0,
    0x1.p50,
    0x1.000002p50
  },
  { // Entry 148
    0x1.80p27,
    0x1.000002p50,
    0x1.fffffep49
  },
  { // Entry 149
    0x1.p27,
    0x1.000002p50,
    0x1.p50
  },
  { // Entry 150
    0.0,
    0x1.000002p50,
    0x1.000002p50
  },
  { // Entry 151
    0.0,
    0x1.fffffep126,
    0x1.fffffep126
  },
  { // Entry 152
    0.0,
    0x1.fffffep126,
    0x1.p127
  },
  { // Entry 153
    0.0,
    0x1.fffffep126,
    0x1.000002p127
  },
  { // Entry 154
    0x1.p103,
    0x1.p127,
    0x1.fffffep126
  },
  { // Entry 155
    0.0,
    0x1.p127,
    0x1.p127
  },
  { // Entry 156
    0.0,
    0x1.p127,
    0x1.000002p127
  },
  { // Entry 157
    0x1.80p104,
    0x1.000002p127,
    0x1.fffffep126
  },
  { // Entry 158
    0x1.p104,
    0x1.000002p127,
    0x1.p127
  },
  { // Entry 159
    0.0,
    0x1.000002p127,
    0x1.000002p127
  },
  { // Entry 160
    0.0,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 161
    HUGE_VALF,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 162
    HUGE_VALF,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 163
    HUGE_VALF,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 164
    HUGE_VALF,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 165
    HUGE_VALF,
    HUGE_VALF,
    0.0f
  },
  { // Entry 166
    HUGE_VALF,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 167
    HUGE_VALF,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 168
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 169
    HUGE_VALF,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 170
    HUGE_VALF,
    HUGE_VALF,
    -0x1.p0
  },
  { // Entry 171
    HUGE_VALF,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 172
    HUGE_VALF,
    HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 173
    0.0,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 174
    0.0,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 175
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 176
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 177
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 178
    0x1.fffffep127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 179
    0x1.fffffep127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 180
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 181
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 182
    0x1.fffffep127,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 183
    0x1.fffffe00000000000000000000000002p127,
    0x1.fffffep127,
    -0x1.p0
  },
  { // Entry 184
    HUGE_VALF,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 185
    HUGE_VALF,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 186
    0.0,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 187
    0.0,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 188
    0.0,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 189
    0x1.p-149,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 190
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 191
    0x1.p-126,
    0x1.p-126,
    0.0f
  },
  { // Entry 192
    0x1.p-126,
    0x1.p-126,
    -0.0f
  },
  { // Entry 193
    0x1.000002p-126,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 194
    0x1.fffffep-126,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 195
    0x1.p-125,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 196
    0x1.00000000000000000000000000000004p0,
    0x1.p-126,
    -0x1.p0
  },
  { // Entry 197
    0x1.fffffep127,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 198
    HUGE_VALF,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 199
    0.0,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 200
    0.0,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 201
    0.0,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 202
    0.0,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 203
    0x1.fffff8p-127,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 204
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 205
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 206
    0x1.p-126,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 207
    0x1.fffffcp-126,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 208
    0x1.fffffep-126,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 209
    0x1.00000000000000000000000000000003p0,
    0x1.fffffcp-127,
    -0x1.p0
  },
  { // Entry 210
    0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 211
    HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 212
    0.0,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 213
    0.0,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 214
    0.0,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 215
    0.0,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 216
    0.0,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 217
    0x1.p-149,
    0x1.p-149,
    0.0f
  },
  { // Entry 218
    0x1.p-149,
    0x1.p-149,
    -0.0f
  },
  { // Entry 219
    0x1.p-148,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 220
    0x1.p-126,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 221
    0x1.000002p-126,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 222
    0x1.p0,
    0x1.p-149,
    -0x1.p0
  },
  { // Entry 223
    0x1.fffffep127,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 224
    HUGE_VALF,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 225
    0.0,
    0.0f,
    HUGE_VALF
  },
  { // Entry 226
    0.0,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 227
    0.0,
    0.0f,
    0x1.p-126
  },
  { // Entry 228
    0.0,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 229
    0.0,
    0.0f,
    0x1.p-149
  },
  { // Entry 230
    0.0,
    0.0f,
    0.0f
  },
  { // Entry 231
    0.0,
    0.0f,
    -0.0f
  },
  { // Entry 232
    0x1.p-149,
    0.0f,
    -0x1.p-149
  },
  { // Entry 233
    0x1.fffffcp-127,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 234
    0x1.p-126,
    0.0f,
    -0x1.p-126
  },
  { // Entry 235
    0x1.p0,
    0.0f,
    -0x1.p0
  },
  { // Entry 236
    0x1.fffffep127,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 237
    HUGE_VALF,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 238
    0.0,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 239
    0.0,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 240
    0.0,
    -0.0f,
    0x1.p-126
  },
  { // Entry 241
    0.0,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 242
    0.0,
    -0.0f,
    0x1.p-149
  },
  { // Entry 243
    0.0,
    -0.0f,
    0.0f
  },
  { // Entry 244
    0.0,
    -0.0f,
    -0.0f
  },
  { // Entry 245
    0x1.p-149,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 246
    0x1.fffffcp-127,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 247
    0x1.p-126,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 248
    0x1.p0,
    -0.0f,
    -0x1.p0
  },
  { // Entry 249
    0x1.fffffep127,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 250
    HUGE_VALF,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 251
    0.0,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 252
    0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 253
    0.0,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 254
    0.0,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 255
    0.0,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 256
    0.0,
    -0x1.p-149,
    0.0f
  },
  { // Entry 257
    0.0,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 258
    0.0,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 259
    0x1.fffff8p-127,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 260
    0x1.fffffcp-127,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 261
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.p-149,
    -0x1.p0
  },
  { // Entry 262
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 263
    HUGE_VALF,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 264
    0.0,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 265
    0.0,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 266
    0.0,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 267
    0.0,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 268
    0.0,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 269
    0.0,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 270
    0.0,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 271
    0.0,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 272
    0.0,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 273
    0x1.p-149,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 274
    0x1.fffffffffffffffffffffffffffffff8p-1,
    -0x1.fffffcp-127,
    -0x1.p0
  },
  { // Entry 275
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 276
    HUGE_VALF,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 277
    0.0,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 278
    0.0,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 279
    0.0,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 280
    0.0,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 281
    0.0,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 282
    0.0,
    -0x1.p-126,
    0.0f
  },
  { // Entry 283
    0.0,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 284
    0.0,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 285
    0.0,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 286
    0.0,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 287
    0x1.fffffffffffffffffffffffffffffff8p-1,
    -0x1.p-126,
    -0x1.p0
  },
  { // Entry 288
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 289
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 290
    0.0,
    -0x1.fffffep-1,
    HUGE_VALF
  },
  { // Entry 291
    0.0,
    -0x1.fffffep-1,
    0x1.fffffep127
  },
  { // Entry 292
    0.0,
    -0x1.fffffep-1,
    0x1.p-126
  },
  { // Entry 293
    0.0,
    -0x1.fffffep-1,
    0x1.fffffcp-127
  },
  { // Entry 294
    0.0,
    -0x1.fffffep-1,
    0x1.p-149
  },
  { // Entry 295
    0.0,
    -0x1.fffffep-1,
    0.0f
  },
  { // Entry 296
    0.0,
    -0x1.fffffep-1,
    -0.0f
  },
  { // Entry 297
    0.0,
    -0x1.fffffep-1,
    -0x1.p-149
  },
  { // Entry 298
    0.0,
    -0x1.fffffep-1,
    -0x1.fffffcp-127
  },
  { // Entry 299
    0.0,
    -0x1.fffffep-1,
    -0x1.p-126
  },
  { // Entry 300
    0x1.p-24,
    -0x1.fffffep-1,
    -0x1.p0
  },
  { // Entry 301
    0x1.fffffdfffffffffffffffffffffffffep127,
    -0x1.fffffep-1,
    -0x1.fffffep127
  },
  { // Entry 302
    HUGE_VALF,
    -0x1.fffffep-1,
    -HUGE_VALF
  },
  { // Entry 303
    0.0,
    -0x1.p0,
    HUGE_VALF
  },
  { // Entry 304
    0.0,
    -0x1.p0,
    0x1.fffffep127
  },
  { // Entry 305
    0.0,
    -0x1.p0,
    0x1.p-126
  },
  { // Entry 306
    0.0,
    -0x1.p0,
    0x1.fffffcp-127
  },
  { // Entry 307
    0.0,
    -0x1.p0,
    0x1.p-149
  },
  { // Entry 308
    0.0,
    -0x1.p0,
    0.0f
  },
  { // Entry 309
    0.0,
    -0x1.p0,
    -0.0f
  },
  { // Entry 310
    0.0,
    -0x1.p0,
    -0x1.p-149
  },
  { // Entry 311
    0.0,
    -0x1.p0,
    -0x1.fffffcp-127
  },
  { // Entry 312
    0.0,
    -0x1.p0,
    -0x1.p-126
  },
  { // Entry 313
    0.0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 314
    0x1.fffffdfffffffffffffffffffffffffep127,
    -0x1.p0,
    -0x1.fffffep127
  },
  { // Entry 315
    HUGE_VALF,
    -0x1.p0,
    -HUGE_VALF
  },
  { // Entry 316
    0.0,
    -0x1.000002p0,
    HUGE_VALF
  },
  { // Entry 317
    0.0,
    -0x1.000002p0,
    0x1.fffffep127
  },
  { // Entry 318
    0.0,
    -0x1.000002p0,
    0x1.p-126
  },
  { // Entry 319
    0.0,
    -0x1.000002p0,
    0x1.fffffcp-127
  },
  { // Entry 320
    0.0,
    -0x1.000002p0,
    0x1.p-149
  },
  { // Entry 321
    0.0,
    -0x1.000002p0,
    0.0f
  },
  { // Entry 322
    0.0,
    -0x1.000002p0,
    -0.0f
  },
  { // Entry 323
    0.0,
    -0x1.000002p0,
    -0x1.p-149
  },
  { // Entry 324
    0.0,
    -0x1.000002p0,
    -0x1.fffffcp-127
  },
  { // Entry 325
    0.0,
    -0x1.000002p0,
    -0x1.p-126
  },
  { // Entry 326
    0.0,
    -0x1.000002p0,
    -0x1.p0
  },
  { // Entry 327
    0x1.fffffdfffffffffffffffffffffffffdp127,
    -0x1.000002p0,
    -0x1.fffffep127
  },
  { // Entry 328
    HUGE_VALF,
    -0x1.000002p0,
    -HUGE_VALF
  },
  { // Entry 329
    0.0,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 330
    0.0,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 331
    0.0,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 332
    0.0,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 333
    0.0,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 334
    0.0,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 335
    0.0,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 336
    0.0,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 337
    0.0,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 338
    0.0,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 339
    0.0,
    -0x1.fffffep127,
    -0x1.p0
  },
  { // Entry 340
    0.0,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 341
    HUGE_VALF,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 342
    0.0,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 343
    0.0,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 344
    0.0,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 345
    0.0,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 346
    0.0,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 347
    0.0,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 348
    0.0,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 349
    0.0,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 350
    0.0,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 351
    0.0,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 352
    0.0,
    -HUGE_VALF,
    -0x1.p0
  },
  { // Entry 353
    0.0,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 354
    0.0,
    -HUGE_VALF,
    -HUGE_VALF
  }
};

"""

```
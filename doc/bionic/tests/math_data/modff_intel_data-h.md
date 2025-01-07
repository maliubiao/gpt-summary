Response:
Let's break down the thought process for answering the request about the `modff_intel_data.handroid` file.

**1. Initial Understanding of the Request:**

The request is about a specific file in Android's Bionic library, focusing on its function, relationship to Android, implementation details, dynamic linking aspects, potential errors, and how it's accessed. The key is to extract meaningful information from the given C code snippet.

**2. Analyzing the Code Snippet:**

The code defines a static array `g_modff_intel_data`. Each element in this array appears to be a structure containing three `float` values. The naming convention `data_2_1_t` and the structure of the data points suggest it's a test dataset. The name `modff_intel_data` strongly implies it's test data for the `modff` function, likely tailored for Intel architectures.

**3. Inferring the Function's Purpose:**

Given the file name and the structure of the data, the primary function of this file is to provide test cases for the `modff` function. The three floats in each entry likely represent:

*   Input value for `modff`.
*   Expected integral part returned by `modff`.
*   Expected fractional part returned by `modff`.

The data points cover a wide range of floating-point values, including positive and negative numbers, very small numbers, numbers with fractional parts, and edge cases like zero and large numbers. This is characteristic of thorough test data.

**4. Connecting to Android Functionality:**

Since the file resides within Bionic's test directory, it directly relates to the testing and validation of Android's C library. `modff` is a standard C library function for splitting a floating-point number into its integral and fractional parts. Android's Bionic library needs to provide a correct implementation of this function, and this test data helps ensure that the implementation (likely optimized for Intel architectures) behaves as expected across various inputs.

**5. Explaining `libc` Function Implementation (Focus on `modff`):**

While the *data* file itself doesn't contain the *implementation* of `modff`, the request asks for an explanation. So, the next step is to describe how `modff` generally works. This involves:

*   Understanding its purpose: separating integral and fractional parts.
*   Considering different approaches: casting to integer, subtracting, using bit manipulation for performance (especially relevant for architecture-specific optimizations).
*   Highlighting potential edge cases and considerations: handling negative numbers, large numbers, NaN, infinity.

**6. Addressing Dynamic Linking (Indirectly Related):**

This specific data file doesn't directly involve dynamic linking. However, since it's part of Bionic, which *does* involve dynamic linking, it's necessary to explain the *context*. This includes:

*   Explaining the role of the dynamic linker (`linker64` or `linker`).
*   Describing the typical layout of shared libraries (`.so` files) in memory.
*   Outlining the linking process (symbol resolution, relocation).

A sample `so` layout is useful for illustration. It's important to emphasize that this *specific* data file would be *inside* a compiled `.o` file, which is then linked into `libc.so`.

**7. Logical Reasoning (Based on Test Data):**

The test data itself *is* the logical reasoning. Each entry represents a specific input and the expected output. Examples should be extracted from the data to demonstrate the behavior of `modff` for different input types.

**8. Common Usage Errors:**

Think about how developers might misuse `modff` or misunderstand its behavior. This could include:

*   Ignoring the output parameters (not capturing the integral part).
*   Assuming specific behavior for NaN or infinity without checking.
*   Not understanding the difference between `modf` (double) and `modff` (float).

**9. Android Framework/NDK Access and Frida Hooking:**

This requires tracing the path from user code to the underlying `libc` function.

*   **Android Framework:**  Explain how higher-level Android components (Java code) might indirectly rely on native libraries that use `modff`. An example like graphics or complex calculations could be used.
*   **NDK:**  The NDK provides a direct way for developers to call `modff` from C/C++ code.
*   **Frida Hooking:**  Provide a practical Frida script to demonstrate how to intercept calls to `modff` and inspect arguments and return values. This makes the explanation concrete.

**Self-Correction/Refinement During Thought Process:**

*   **Initial thought:**  Maybe this file contains the actual `modff` implementation. **Correction:**  The file name and data structure strongly suggest it's test data, not implementation.
*   **Initial thought:** Focus only on the `modff` function. **Correction:**  The broader context of Bionic and dynamic linking is important, even if this specific file doesn't directly involve dynamic linking.
*   **Initial thought:**  Provide very technical details about floating-point representation. **Correction:**  Keep the explanation accessible and focus on the *behavior* of `modff` as demonstrated by the test data. Technical details can be included but shouldn't overshadow the core concepts.
*   **Initial thought:**  Assume the user is an expert. **Correction:**  Explain concepts clearly and provide examples, assuming a general understanding of programming and C/C++.

By following these steps, organizing the information logically, and providing concrete examples (especially the Frida hook), a comprehensive and helpful answer can be generated.
这个文件 `bionic/tests/math_data/modff_intel_data.handroid` 是 Android Bionic 库中用于测试 `modff` 函数的数据文件，并且特别针对 Intel 架构进行了优化或测试。

**它的功能:**

1. **提供测试用例:** 该文件包含一系列预定义的输入值和期望的输出值，用于测试 `modff` 函数的正确性。
2. **针对 Intel 架构:** 文件名中的 "intel_data" 表明这些测试用例可能特别关注 Intel 处理器的特性，例如其浮点运算单元的精度、性能或特定行为。
3. **验证 Bionic 库的 `modff` 实现:**  这些数据用于驱动 Bionic 库中 `modff` 函数的单元测试，确保其在 Intel 架构上能够正确地分离浮点数的整数部分和小数部分。

**与 Android 功能的关系及举例:**

`modff` 是一个标准的 C 库函数，属于 `math.h` 头文件。它用于将一个浮点数分解为整数部分和小数部分。Android 作为操作系统，其底层系统库（Bionic）需要提供标准 C 库的实现，包括 `modff`。

**举例说明:**

假设一个 Android 应用需要进行一些数学计算，例如：

*   **图形渲染:**  可能需要处理坐标，而坐标可能包含小数。需要分离整数部分进行像素定位，小数部分可能用于子像素渲染。
*   **物理模拟:**  计算物体的位置或速度时，经常会得到浮点数结果，可能需要分离整数部分和小数部分用于不同的逻辑处理。
*   **金融计算:**  处理货币金额时，需要分离整数部分和小数部分表示元和分。

在这些场景下，应用可能会调用 Bionic 提供的 `modff` 函数。`modff_intel_data.handroid` 文件中的测试用例就是用来确保 Bionic 提供的 `modff` 函数在各种输入情况下都能正确工作，保证了这些应用功能的正确性。

**详细解释 `libc` 函数 `modff` 的功能是如何实现的:**

`modff` 函数的原型如下：

```c
float modff(float x, float *iptr);
```

功能：将浮点数 `x` 分解为整数部分和小数部分。

*   **参数 `x`:**  要分解的浮点数。
*   **参数 `iptr`:** 指向一个 `float` 变量的指针，用于存储 `x` 的整数部分。
*   **返回值:** `x` 的带符号的小数部分。

**实现原理（通常的实现方式）：**

1. **提取符号:** 首先确定输入 `x` 的符号。
2. **取绝对值:** 对 `x` 取绝对值，方便后续处理。
3. **转换为整数:** 将绝对值后的 `x` 强制转换为整数类型（例如 `int` 或 `long`）。这个过程会截断小数部分。
4. **存储整数部分:** 将转换后的整数值转换为 `float` 类型，并存储到 `iptr` 指向的内存位置。
5. **计算小数部分:**  用原始的 `x` 减去存储在 `iptr` 中的整数部分，得到小数部分。
6. **恢复符号:**  根据原始 `x` 的符号，为小数部分添加正确的符号。
7. **返回小数部分:** 返回计算得到的小数部分。

**针对 Intel 架构的可能优化或考虑:**

Intel 处理器通常具有强大的浮点运算单元。`modff` 的实现可能会利用 Intel 特定的指令集（如 SSE、AVX）来提高性能。例如，可以使用位操作来快速提取浮点数的指数和尾数，从而更高效地分离整数和小数部分。

**假设输入与输出（基于 `modff_intel_data.handroid`）：**

文件中的每一项 `g_modff_intel_data` 结构体都代表一个测试用例：

```c
template <typename Input, typename ExpectedIntegral, typename ExpectedFractional>
struct data_2_1_t {
  Input input;
  ExpectedIntegral expected_integral;
  ExpectedFractional expected_fractional;
};
```

因此，对于 `g_modff_intel_data[]` 中的每一项：

*   `input` 是传递给 `modff` 的输入值。
*   `expected_integral` 是期望 `modff` 将整数部分存储到 `iptr` 指向的内存中的值。
*   `expected_fractional` 是 `modff` 函数期望返回的小数部分。

**例如，查看文件中的一些条目：**

*   `{ -0x1.p-149, -0.0, -0x1.p-149 }`:
    *   假设输入: `x = -0x1.p-149` （一个非常小的负数）
    *   期望整数部分: `-0.0`
    *   期望小数部分: `-0x1.p-149`
*   `{ 0x1.fffffep-2, 0.0, 0x1.fffffep-2 }`:
    *   假设输入: `x = 0x1.fffffep-2`
    *   期望整数部分: `0.0`
    *   期望小数部分: `0x1.fffffep-2`
*   `{ 0x1.p-23, 0x1.p0, 0x1.000002p0 }`:  **注意这里有错误，期望的整数部分和实际行为不符。** 应该修正为：
    *   假设输入: `x = 0x1.p-23`
    *   期望整数部分: `0x1.p0`  **这里应该是 1.0**
    *   期望小数部分: `0x1.000002p0` **这里应该是 `x - 1.0` 的值**

**对于涉及 dynamic linker 的功能:**

`modff_intel_data.handroid` 本身不直接涉及 dynamic linker 的功能。它是一个静态数据文件，会被编译到包含 `modff` 函数实现的共享库 (`libc.so`) 中。

**`libc.so` 布局样本:**

一个简化的 `libc.so` 内存布局可能如下所示：

```
[加载地址]
    .dynamic 段 (包含动态链接信息)
    .hash 段 (符号哈希表)
    .gnu.hash 段 (GNU 风格的符号哈希表)
    .dynsym 段 (动态符号表)
    .dynstr 段 (动态字符串表)
    .rel.plt 或 .rela.plt 段 (PLT 重定位表)
    .rel.dyn 或 .rela.dyn 段 (DATA 重定位表)
    .text 段 (可执行代码，包含 modff 的实现)
    .rodata 段 (只读数据，可能包含 modff_intel_data)
    .data 段 (已初始化的可写数据)
    .bss 段 (未初始化的可写数据)
```

**链接的处理过程:**

1. **编译:**  `modff.c` 的源代码（包含 `modff` 的实现）会被编译器编译成目标文件 (`.o`)。`modff_intel_data.handroid` 中的数据会被编译到该目标文件的 `.rodata` 段中。
2. **链接:**  链接器 (e.g., `ld`) 将多个目标文件链接成共享库 `libc.so`。
3. **符号解析:** 链接器会解析符号引用，例如 `modff` 函数的定义和测试代码中对该数据的引用。
4. **重定位:** 由于共享库的加载地址在运行时才能确定，链接器会生成重定位信息，指示动态链接器在加载时如何修改代码和数据中的地址。例如，测试代码中访问 `g_modff_intel_data` 的地址需要被重定位。
5. **运行时加载:** 当 Android 应用启动并加载 `libc.so` 时，动态链接器 (`linker64` 或 `linker`) 会将 `libc.so` 加载到内存中，并根据重定位信息修正地址。

**用户或编程常见的使用错误:**

1. **错误地理解 `modff` 的作用:** 可能会认为 `modff` 只是简单地去除小数部分，而忽略了它会返回带符号的小数部分，并将整数部分存储到指针指向的位置。
2. **忘记处理整数部分指针:**  调用 `modff` 后，必须访问 `iptr` 指向的内存才能获取整数部分。
3. **类型不匹配:**  虽然有 `modff` (float) 和 `modf` (double) 两个版本，但如果类型不匹配可能会导致精度损失或编译错误。
4. **对特殊值的处理不当:** 需要注意 `NaN`（非数字）和无穷大等特殊值，`modff` 对这些值的处理遵循 IEEE 754 标准。

**例如：**

```c
#include <stdio.h>
#include <math.h>

int main() {
    float num = 3.14159;
    float intPart;
    float fracPart = modff(num, &intPart);

    printf("原始数字: %f\n", num);
    printf("整数部分: %f\n", intPart);
    printf("小数部分: %f\n", fracPart);

    // 常见错误：忽略整数部分指针
    float onlyFrac = modff(num, NULL); // 行为未定义，可能崩溃或产生错误结果
    printf("仅小数部分 (错误示范): %f\n", onlyFrac);

    return 0;
}
```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `modff` 的路径：**

1. **Java 代码:** Android Framework 的高级部分通常是用 Java 编写的。
2. **JNI (Java Native Interface):** 如果 Framework 需要执行底层的、性能敏感的或与硬件交互的操作，可能会调用 Native 代码（C/C++）。
3. **NDK (Native Development Kit):**  开发者可以使用 NDK 编写 C/C++ 代码，并编译成共享库 (`.so`)。
4. **System Calls 或 Libc:** NDK 库最终会调用 Bionic 库提供的函数，包括 `modff`。例如，一个图形渲染库可能在内部使用 `modff` 来处理浮点坐标。

**NDK 到 `modff` 的路径：**

1. **NDK C/C++ 代码:**  开发者直接在 NDK 代码中调用 `modff` 函数。
2. **编译和链接:** NDK 编译器将代码编译成目标文件，然后链接器将目标文件与 Bionic 库链接，生成最终的共享库。
3. **运行时加载:** 当应用加载包含这段 NDK 代码的共享库时，对 `modff` 的调用会直接指向 Bionic 库中的实现。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `modff` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    var modffPtr = Module.findExportByName("libc.so", "modff");

    if (modffPtr) {
        Interceptor.attach(modffPtr, {
            onEnter: function (args) {
                this.x = args[0].readFloat();
                console.log("[modff] 输入: " + this.x);
            },
            onLeave: function (retval) {
                var intPtr = this.context.sp.add(8 * (Process.arch === 'arm64' ? 1 : 0)); // Adjust for stack layout
                var intVal = ptr(intPtr).readFloat();
                var fracVal = retval.readFloat();
                console.log("[modff] 整数部分: " + intVal + ", 小数部分: " + fracVal);
            }
        });
        console.log("已 Hook modff");
    } else {
        console.log("未找到 modff 函数");
    }
} else {
    console.log("Frida Hook 示例仅适用于 arm64 和 x64 架构");
}
```

**解释 Frida Hook 代码：**

1. **检查架构:**  代码首先检查进程架构是否为 `arm64` 或 `x64`，因为栈布局在不同架构上可能不同。
2. **查找 `modff` 函数地址:** `Module.findExportByName("libc.so", "modff")` 用于在 `libc.so` 中查找 `modff` 函数的地址。
3. **拦截 `modff`:** `Interceptor.attach()` 用于拦截对 `modff` 函数的调用。
4. **`onEnter`:** 在 `modff` 函数被调用之前执行。
    *   `args[0]` 包含了第一个参数（要分解的浮点数 `x`）。
    *   `readFloat()` 读取该参数的浮点数值。
    *   打印输入值。
5. **`onLeave`:** 在 `modff` 函数即将返回时执行。
    *   **获取整数部分:** 由于 `modff` 将整数部分存储到第二个参数（指针）指向的内存，我们需要根据架构的调用约定从栈上读取该值。
    *   **获取小数部分:** `retval` 包含了 `modff` 函数的返回值（小数部分）。
    *   `readFloat()` 读取返回值和栈上的整数部分。
    *   打印整数部分和小数部分。

**调试步骤：**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 和 Frida Server。
2. **运行目标应用:** 启动你想要分析的 Android 应用。
3. **运行 Frida Hook 脚本:** 使用 Frida 命令行工具将上述 JavaScript 代码注入到目标应用进程中：
    ```bash
    frida -U -f <你的应用包名> -l your_hook_script.js --no-pause
    ```
    将 `<你的应用包名>` 替换为实际的应用包名，`your_hook_script.js` 替换为保存 Frida 脚本的文件名。
4. **触发 `modff` 调用:** 在应用中执行某些操作，这些操作会触发对 `modff` 函数的调用。例如，进行涉及浮点数计算的操作。
5. **查看 Frida 输出:** Frida 会在控制台中打印出每次 `modff` 函数被调用时的输入值、计算出的整数部分和小数部分。

通过这个 Frida Hook 示例，你可以实时观察 `modff` 函数的调用情况，验证其输入和输出，从而调试相关的逻辑。

Prompt: 
```
这是目录为bionic/tests/math_data/modff_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_2_1_t<float, float, float> g_modff_intel_data[] = {
  { // Entry 0
    -0x1.p-149,
    -0.0,
    -0x1.p-149
  },
  { // Entry 1
    0.0,
    0.0,
    0.0
  },
  { // Entry 2
    0x1.p-149,
    0.0,
    0x1.p-149
  },
  { // Entry 3
    0x1.fffffep-2,
    0.0,
    0x1.fffffep-2
  },
  { // Entry 4
    0x1.p-1,
    0.0,
    0x1.p-1
  },
  { // Entry 5
    0x1.000002p-1,
    0.0,
    0x1.000002p-1
  },
  { // Entry 6
    0x1.fffffep-1,
    0.0,
    0x1.fffffep-1
  },
  { // Entry 7
    0.0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 8
    0x1.p-23,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 9
    0x1.fffff8p-2,
    0x1.p0,
    0x1.7ffffep0
  },
  { // Entry 10
    0x1.p-1,
    0x1.p0,
    0x1.80p0
  },
  { // Entry 11
    0x1.000004p-1,
    0x1.p0,
    0x1.800002p0
  },
  { // Entry 12
    0x1.fffffcp-1,
    0x1.p0,
    0x1.fffffep0
  },
  { // Entry 13
    0.0,
    0x1.p1,
    0x1.p1
  },
  { // Entry 14
    0x1.p-22,
    0x1.p1,
    0x1.000002p1
  },
  { // Entry 15
    0x1.fffff0p-2,
    0x1.p1,
    0x1.3ffffep1
  },
  { // Entry 16
    0x1.p-1,
    0x1.p1,
    0x1.40p1
  },
  { // Entry 17
    0x1.000008p-1,
    0x1.p1,
    0x1.400002p1
  },
  { // Entry 18
    0x1.ffffp-1,
    0x1.8cp6,
    0x1.8ffffep6
  },
  { // Entry 19
    0.0,
    0x1.90p6,
    0x1.90p6
  },
  { // Entry 20
    0x1.p-17,
    0x1.90p6,
    0x1.900002p6
  },
  { // Entry 21
    0x1.fffep-2,
    0x1.90p6,
    0x1.91fffep6
  },
  { // Entry 22
    0x1.p-1,
    0x1.90p6,
    0x1.92p6
  },
  { // Entry 23
    0x1.0001p-1,
    0x1.90p6,
    0x1.920002p6
  },
  { // Entry 24
    0x1.fff8p-1,
    0x1.f380p9,
    0x1.f3fffep9
  },
  { // Entry 25
    0.0,
    0x1.f4p9,
    0x1.f4p9
  },
  { // Entry 26
    0x1.p-14,
    0x1.f4p9,
    0x1.f40002p9
  },
  { // Entry 27
    0x1.fff0p-2,
    0x1.f4p9,
    0x1.f43ffep9
  },
  { // Entry 28
    0x1.p-1,
    0x1.f4p9,
    0x1.f440p9
  },
  { // Entry 29
    0x1.0008p-1,
    0x1.f4p9,
    0x1.f44002p9
  },
  { // Entry 30
    0x1.c0p-1,
    0x1.fffff0p20,
    0x1.fffffep20
  },
  { // Entry 31
    0.0,
    0x1.p21,
    0x1.p21
  },
  { // Entry 32
    0x1.p-2,
    0x1.p21,
    0x1.000002p21
  },
  { // Entry 33
    0x1.80p-1,
    0x1.fffff8p21,
    0x1.fffffep21
  },
  { // Entry 34
    0.0,
    0x1.p22,
    0x1.p22
  },
  { // Entry 35
    0x1.p-1,
    0x1.p22,
    0x1.000002p22
  },
  { // Entry 36
    0x1.p-1,
    0x1.fffffcp22,
    0x1.fffffep22
  },
  { // Entry 37
    0.0,
    0x1.p23,
    0x1.p23
  },
  { // Entry 38
    0.0,
    0x1.000002p23,
    0x1.000002p23
  },
  { // Entry 39
    0.0,
    0x1.fffffep23,
    0x1.fffffep23
  },
  { // Entry 40
    0.0,
    0x1.p24,
    0x1.p24
  },
  { // Entry 41
    0.0,
    0x1.000002p24,
    0x1.000002p24
  },
  { // Entry 42
    0.0,
    0x1.fffffep24,
    0x1.fffffep24
  },
  { // Entry 43
    0.0,
    0x1.p25,
    0x1.p25
  },
  { // Entry 44
    0.0,
    0x1.000002p25,
    0x1.000002p25
  },
  { // Entry 45
    0.0,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 46
    -0x1.000002p-1,
    -0.0,
    -0x1.000002p-1
  },
  { // Entry 47
    -0x1.p-1,
    -0.0,
    -0x1.p-1
  },
  { // Entry 48
    -0x1.fffffep-2,
    -0.0,
    -0x1.fffffep-2
  },
  { // Entry 49
    -0x1.p-23,
    -0x1.p0,
    -0x1.000002p0
  },
  { // Entry 50
    -0.0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 51
    -0x1.fffffep-1,
    -0.0,
    -0x1.fffffep-1
  },
  { // Entry 52
    -0x1.000004p-1,
    -0x1.p0,
    -0x1.800002p0
  },
  { // Entry 53
    -0x1.p-1,
    -0x1.p0,
    -0x1.80p0
  },
  { // Entry 54
    -0x1.fffff8p-2,
    -0x1.p0,
    -0x1.7ffffep0
  },
  { // Entry 55
    -0x1.p-22,
    -0x1.p1,
    -0x1.000002p1
  },
  { // Entry 56
    -0.0,
    -0x1.p1,
    -0x1.p1
  },
  { // Entry 57
    -0x1.fffffcp-1,
    -0x1.p0,
    -0x1.fffffep0
  },
  { // Entry 58
    -0x1.000008p-1,
    -0x1.p1,
    -0x1.400002p1
  },
  { // Entry 59
    -0x1.p-1,
    -0x1.p1,
    -0x1.40p1
  },
  { // Entry 60
    -0x1.fffff0p-2,
    -0x1.p1,
    -0x1.3ffffep1
  },
  { // Entry 61
    -0x1.p-17,
    -0x1.90p6,
    -0x1.900002p6
  },
  { // Entry 62
    -0.0,
    -0x1.90p6,
    -0x1.90p6
  },
  { // Entry 63
    -0x1.ffffp-1,
    -0x1.8cp6,
    -0x1.8ffffep6
  },
  { // Entry 64
    -0x1.0001p-1,
    -0x1.90p6,
    -0x1.920002p6
  },
  { // Entry 65
    -0x1.p-1,
    -0x1.90p6,
    -0x1.92p6
  },
  { // Entry 66
    -0x1.fffep-2,
    -0x1.90p6,
    -0x1.91fffep6
  },
  { // Entry 67
    -0x1.p-14,
    -0x1.f4p9,
    -0x1.f40002p9
  },
  { // Entry 68
    -0.0,
    -0x1.f4p9,
    -0x1.f4p9
  },
  { // Entry 69
    -0x1.fff8p-1,
    -0x1.f380p9,
    -0x1.f3fffep9
  },
  { // Entry 70
    -0x1.0008p-1,
    -0x1.f4p9,
    -0x1.f44002p9
  },
  { // Entry 71
    -0x1.p-1,
    -0x1.f4p9,
    -0x1.f440p9
  },
  { // Entry 72
    -0x1.fff0p-2,
    -0x1.f4p9,
    -0x1.f43ffep9
  },
  { // Entry 73
    -0x1.p-2,
    -0x1.p21,
    -0x1.000002p21
  },
  { // Entry 74
    -0.0,
    -0x1.p21,
    -0x1.p21
  },
  { // Entry 75
    -0x1.c0p-1,
    -0x1.fffff0p20,
    -0x1.fffffep20
  },
  { // Entry 76
    -0x1.p-1,
    -0x1.p22,
    -0x1.000002p22
  },
  { // Entry 77
    -0.0,
    -0x1.p22,
    -0x1.p22
  },
  { // Entry 78
    -0x1.80p-1,
    -0x1.fffff8p21,
    -0x1.fffffep21
  },
  { // Entry 79
    -0.0,
    -0x1.000002p23,
    -0x1.000002p23
  },
  { // Entry 80
    -0.0,
    -0x1.p23,
    -0x1.p23
  },
  { // Entry 81
    -0x1.p-1,
    -0x1.fffffcp22,
    -0x1.fffffep22
  },
  { // Entry 82
    -0.0,
    -0x1.000002p24,
    -0x1.000002p24
  },
  { // Entry 83
    -0.0,
    -0x1.p24,
    -0x1.p24
  },
  { // Entry 84
    -0.0,
    -0x1.fffffep23,
    -0x1.fffffep23
  },
  { // Entry 85
    -0.0,
    -0x1.000002p25,
    -0x1.000002p25
  },
  { // Entry 86
    -0.0,
    -0x1.p25,
    -0x1.p25
  },
  { // Entry 87
    -0.0,
    -0x1.fffffep24,
    -0x1.fffffep24
  },
  { // Entry 88
    -0.0,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 89
    0.0,
    0x1.fffffep29,
    0x1.fffffep29
  },
  { // Entry 90
    0.0,
    0x1.p30,
    0x1.p30
  },
  { // Entry 91
    0.0,
    0x1.000002p30,
    0x1.000002p30
  },
  { // Entry 92
    0.0,
    0x1.fffffap30,
    0x1.fffffap30
  },
  { // Entry 93
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 94
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 95
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 96
    0.0,
    0x1.000002p31,
    0x1.000002p31
  },
  { // Entry 97
    0.0,
    0x1.000004p31,
    0x1.000004p31
  },
  { // Entry 98
    0.0,
    0x1.000006p31,
    0x1.000006p31
  },
  { // Entry 99
    0.0,
    0x1.fffffap30,
    0x1.fffffap30
  },
  { // Entry 100
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 101
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 102
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 103
    0.0,
    0x1.000002p31,
    0x1.000002p31
  },
  { // Entry 104
    0.0,
    0x1.000004p31,
    0x1.000004p31
  },
  { // Entry 105
    0.0,
    0x1.000006p31,
    0x1.000006p31
  },
  { // Entry 106
    0.0,
    0x1.fffffap30,
    0x1.fffffap30
  },
  { // Entry 107
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 108
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 109
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 110
    0.0,
    0x1.000002p31,
    0x1.000002p31
  },
  { // Entry 111
    0.0,
    0x1.000004p31,
    0x1.000004p31
  },
  { // Entry 112
    0.0,
    0x1.000006p31,
    0x1.000006p31
  },
  { // Entry 113
    0.0,
    0x1.fffffap30,
    0x1.fffffap30
  },
  { // Entry 114
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 115
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 116
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 117
    0.0,
    0x1.000002p31,
    0x1.000002p31
  },
  { // Entry 118
    0.0,
    0x1.000004p31,
    0x1.000004p31
  },
  { // Entry 119
    0.0,
    0x1.000006p31,
    0x1.000006p31
  },
  { // Entry 120
    0.0,
    0x1.fffffap30,
    0x1.fffffap30
  },
  { // Entry 121
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 122
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 123
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 124
    0.0,
    0x1.000002p31,
    0x1.000002p31
  },
  { // Entry 125
    0.0,
    0x1.000004p31,
    0x1.000004p31
  },
  { // Entry 126
    0.0,
    0x1.000006p31,
    0x1.000006p31
  },
  { // Entry 127
    0.0,
    0x1.fffffap30,
    0x1.fffffap30
  },
  { // Entry 128
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 129
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 130
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 131
    0.0,
    0x1.000002p31,
    0x1.000002p31
  },
  { // Entry 132
    0.0,
    0x1.000004p31,
    0x1.000004p31
  },
  { // Entry 133
    0.0,
    0x1.000006p31,
    0x1.000006p31
  },
  { // Entry 134
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 135
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 136
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 137
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 138
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 139
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 140
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 141
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 142
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 143
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 144
    -0.0,
    -0x1.000002p30,
    -0x1.000002p30
  },
  { // Entry 145
    -0.0,
    -0x1.p30,
    -0x1.p30
  },
  { // Entry 146
    -0.0,
    -0x1.fffffep29,
    -0x1.fffffep29
  },
  { // Entry 147
    -0.0,
    -0x1.000006p31,
    -0x1.000006p31
  },
  { // Entry 148
    -0.0,
    -0x1.000004p31,
    -0x1.000004p31
  },
  { // Entry 149
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 150
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 151
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 152
    -0.0,
    -0x1.fffffcp30,
    -0x1.fffffcp30
  },
  { // Entry 153
    -0.0,
    -0x1.fffffap30,
    -0x1.fffffap30
  },
  { // Entry 154
    -0.0,
    -0x1.000006p31,
    -0x1.000006p31
  },
  { // Entry 155
    -0.0,
    -0x1.000004p31,
    -0x1.000004p31
  },
  { // Entry 156
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 157
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 158
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 159
    -0.0,
    -0x1.fffffcp30,
    -0x1.fffffcp30
  },
  { // Entry 160
    -0.0,
    -0x1.fffffap30,
    -0x1.fffffap30
  },
  { // Entry 161
    -0.0,
    -0x1.000006p31,
    -0x1.000006p31
  },
  { // Entry 162
    -0.0,
    -0x1.000004p31,
    -0x1.000004p31
  },
  { // Entry 163
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 164
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 165
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 166
    -0.0,
    -0x1.fffffcp30,
    -0x1.fffffcp30
  },
  { // Entry 167
    -0.0,
    -0x1.fffffap30,
    -0x1.fffffap30
  },
  { // Entry 168
    -0.0,
    -0x1.000006p31,
    -0x1.000006p31
  },
  { // Entry 169
    -0.0,
    -0x1.000004p31,
    -0x1.000004p31
  },
  { // Entry 170
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 171
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 172
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 173
    -0.0,
    -0x1.fffffcp30,
    -0x1.fffffcp30
  },
  { // Entry 174
    -0.0,
    -0x1.fffffap30,
    -0x1.fffffap30
  },
  { // Entry 175
    -0.0,
    -0x1.000006p31,
    -0x1.000006p31
  },
  { // Entry 176
    -0.0,
    -0x1.000004p31,
    -0x1.000004p31
  },
  { // Entry 177
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 178
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 179
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 180
    -0.0,
    -0x1.fffffcp30,
    -0x1.fffffcp30
  },
  { // Entry 181
    -0.0,
    -0x1.fffffap30,
    -0x1.fffffap30
  },
  { // Entry 182
    -0.0,
    -0x1.000006p31,
    -0x1.000006p31
  },
  { // Entry 183
    -0.0,
    -0x1.000004p31,
    -0x1.000004p31
  },
  { // Entry 184
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 185
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 186
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 187
    -0.0,
    -0x1.fffffcp30,
    -0x1.fffffcp30
  },
  { // Entry 188
    -0.0,
    -0x1.fffffap30,
    -0x1.fffffap30
  },
  { // Entry 189
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 190
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 191
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 192
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 193
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 194
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 195
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 196
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 197
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 198
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 199
    0.0,
    0x1.fffffap61,
    0x1.fffffap61
  },
  { // Entry 200
    0.0,
    0x1.fffffcp61,
    0x1.fffffcp61
  },
  { // Entry 201
    0.0,
    0x1.fffffep61,
    0x1.fffffep61
  },
  { // Entry 202
    0.0,
    0x1.p62,
    0x1.p62
  },
  { // Entry 203
    0.0,
    0x1.000002p62,
    0x1.000002p62
  },
  { // Entry 204
    0.0,
    0x1.000004p62,
    0x1.000004p62
  },
  { // Entry 205
    0.0,
    0x1.000006p62,
    0x1.000006p62
  },
  { // Entry 206
    0.0,
    0x1.fffffap62,
    0x1.fffffap62
  },
  { // Entry 207
    0.0,
    0x1.fffffcp62,
    0x1.fffffcp62
  },
  { // Entry 208
    0.0,
    0x1.fffffep62,
    0x1.fffffep62
  },
  { // Entry 209
    0.0,
    0x1.p63,
    0x1.p63
  },
  { // Entry 210
    0.0,
    0x1.000002p63,
    0x1.000002p63
  },
  { // Entry 211
    0.0,
    0x1.000004p63,
    0x1.000004p63
  },
  { // Entry 212
    0.0,
    0x1.000006p63,
    0x1.000006p63
  },
  { // Entry 213
    0.0,
    0x1.fffffap63,
    0x1.fffffap63
  },
  { // Entry 214
    0.0,
    0x1.fffffcp63,
    0x1.fffffcp63
  },
  { // Entry 215
    0.0,
    0x1.fffffep63,
    0x1.fffffep63
  },
  { // Entry 216
    0.0,
    0x1.p64,
    0x1.p64
  },
  { // Entry 217
    0.0,
    0x1.000002p64,
    0x1.000002p64
  },
  { // Entry 218
    0.0,
    0x1.000004p64,
    0x1.000004p64
  },
  { // Entry 219
    0.0,
    0x1.000006p64,
    0x1.000006p64
  },
  { // Entry 220
    -0.0,
    -0x1.000006p62,
    -0x1.000006p62
  },
  { // Entry 221
    -0.0,
    -0x1.000004p62,
    -0x1.000004p62
  },
  { // Entry 222
    -0.0,
    -0x1.000002p62,
    -0x1.000002p62
  },
  { // Entry 223
    -0.0,
    -0x1.p62,
    -0x1.p62
  },
  { // Entry 224
    -0.0,
    -0x1.fffffep61,
    -0x1.fffffep61
  },
  { // Entry 225
    -0.0,
    -0x1.fffffcp61,
    -0x1.fffffcp61
  },
  { // Entry 226
    -0.0,
    -0x1.fffffap61,
    -0x1.fffffap61
  },
  { // Entry 227
    -0.0,
    -0x1.000006p63,
    -0x1.000006p63
  },
  { // Entry 228
    -0.0,
    -0x1.000004p63,
    -0x1.000004p63
  },
  { // Entry 229
    -0.0,
    -0x1.000002p63,
    -0x1.000002p63
  },
  { // Entry 230
    -0.0,
    -0x1.p63,
    -0x1.p63
  },
  { // Entry 231
    -0.0,
    -0x1.fffffep62,
    -0x1.fffffep62
  },
  { // Entry 232
    -0.0,
    -0x1.fffffcp62,
    -0x1.fffffcp62
  },
  { // Entry 233
    -0.0,
    -0x1.fffffap62,
    -0x1.fffffap62
  },
  { // Entry 234
    -0.0,
    -0x1.000006p64,
    -0x1.000006p64
  },
  { // Entry 235
    -0.0,
    -0x1.000004p64,
    -0x1.000004p64
  },
  { // Entry 236
    -0.0,
    -0x1.000002p64,
    -0x1.000002p64
  },
  { // Entry 237
    -0.0,
    -0x1.p64,
    -0x1.p64
  },
  { // Entry 238
    -0.0,
    -0x1.fffffep63,
    -0x1.fffffep63
  },
  { // Entry 239
    -0.0,
    -0x1.fffffcp63,
    -0x1.fffffcp63
  },
  { // Entry 240
    -0.0,
    -0x1.fffffap63,
    -0x1.fffffap63
  },
  { // Entry 241
    0.0,
    0x1.p62,
    0x1.p62
  },
  { // Entry 242
    0.0,
    0x1.40p62,
    0x1.40p62
  },
  { // Entry 243
    0.0,
    0x1.80p62,
    0x1.80p62
  },
  { // Entry 244
    0.0,
    0x1.c0p62,
    0x1.c0p62
  },
  { // Entry 245
    0.0,
    0x1.p63,
    0x1.p63
  },
  { // Entry 246
    0.0,
    0x1.p63,
    0x1.p63
  },
  { // Entry 247
    0.0,
    0x1.40p63,
    0x1.40p63
  },
  { // Entry 248
    0.0,
    0x1.80p63,
    0x1.80p63
  },
  { // Entry 249
    0.0,
    0x1.c0p63,
    0x1.c0p63
  },
  { // Entry 250
    0.0,
    0x1.p64,
    0x1.p64
  },
  { // Entry 251
    -0.0,
    -0x1.p62,
    -0x1.p62
  },
  { // Entry 252
    -0.0,
    -0x1.40p62,
    -0x1.40p62
  },
  { // Entry 253
    -0.0,
    -0x1.80p62,
    -0x1.80p62
  },
  { // Entry 254
    -0.0,
    -0x1.c0p62,
    -0x1.c0p62
  },
  { // Entry 255
    -0.0,
    -0x1.p63,
    -0x1.p63
  },
  { // Entry 256
    -0.0,
    -0x1.p63,
    -0x1.p63
  },
  { // Entry 257
    -0.0,
    -0x1.40p63,
    -0x1.40p63
  },
  { // Entry 258
    -0.0,
    -0x1.80p63,
    -0x1.80p63
  },
  { // Entry 259
    -0.0,
    -0x1.c0p63,
    -0x1.c0p63
  },
  { // Entry 260
    -0.0,
    -0x1.p64,
    -0x1.p64
  },
  { // Entry 261
    0.0,
    0x1.fffffcp30,
    0x1.fffffcp30
  },
  { // Entry 262
    0.0,
    0x1.fffffep30,
    0x1.fffffep30
  },
  { // Entry 263
    0.0,
    0x1.p31,
    0x1.p31
  },
  { // Entry 264
    -0.0,
    -0x1.000002p31,
    -0x1.000002p31
  },
  { // Entry 265
    -0.0,
    -0x1.p31,
    -0x1.p31
  },
  { // Entry 266
    -0.0,
    -0x1.fffffep30,
    -0x1.fffffep30
  },
  { // Entry 267
    0x1.fffff8p-1,
    0x1.80p1,
    0x1.fffffep1
  },
  { // Entry 268
    0.0,
    0x1.p2,
    0x1.p2
  },
  { // Entry 269
    0x1.p-21,
    0x1.p2,
    0x1.000002p2
  },
  { // Entry 270
    0x1.fffff0p-1,
    0x1.c0p2,
    0x1.fffffep2
  },
  { // Entry 271
    0.0,
    0x1.p3,
    0x1.p3
  },
  { // Entry 272
    0x1.p-20,
    0x1.p3,
    0x1.000002p3
  },
  { // Entry 273
    0x1.ffffe0p-1,
    0x1.e0p3,
    0x1.fffffep3
  },
  { // Entry 274
    0.0,
    0x1.p4,
    0x1.p4
  },
  { // Entry 275
    0x1.p-19,
    0x1.p4,
    0x1.000002p4
  },
  { // Entry 276
    0x1.ffffc0p-1,
    0x1.f0p4,
    0x1.fffffep4
  },
  { // Entry 277
    0.0,
    0x1.p5,
    0x1.p5
  },
  { // Entry 278
    0x1.p-18,
    0x1.p5,
    0x1.000002p5
  },
  { // Entry 279
    0x1.ffff80p-1,
    0x1.f8p5,
    0x1.fffffep5
  },
  { // Entry 280
    0.0,
    0x1.p6,
    0x1.p6
  },
  { // Entry 281
    0x1.p-17,
    0x1.p6,
    0x1.000002p6
  },
  { // Entry 282
    0x1.ffffp-1,
    0x1.fcp6,
    0x1.fffffep6
  },
  { // Entry 283
    0.0,
    0x1.p7,
    0x1.p7
  },
  { // Entry 284
    0x1.p-16,
    0x1.p7,
    0x1.000002p7
  },
  { // Entry 285
    0x1.fffep-1,
    0x1.fep7,
    0x1.fffffep7
  },
  { // Entry 286
    0.0,
    0x1.p8,
    0x1.p8
  },
  { // Entry 287
    0x1.p-15,
    0x1.p8,
    0x1.000002p8
  },
  { // Entry 288
    0x1.fffcp-1,
    0x1.ffp8,
    0x1.fffffep8
  },
  { // Entry 289
    0.0,
    0x1.p9,
    0x1.p9
  },
  { // Entry 290
    0x1.p-14,
    0x1.p9,
    0x1.000002p9
  },
  { // Entry 291
    0x1.fff8p-1,
    0x1.ff80p9,
    0x1.fffffep9
  },
  { // Entry 292
    0.0,
    0x1.p10,
    0x1.p10
  },
  { // Entry 293
    0x1.p-13,
    0x1.p10,
    0x1.000002p10
  },
  { // Entry 294
    0x1.fff0p-1,
    0x1.ffc0p10,
    0x1.fffffep10
  },
  { // Entry 295
    0.0,
    0x1.p11,
    0x1.p11
  },
  { // Entry 296
    0x1.p-12,
    0x1.p11,
    0x1.000002p11
  },
  { // Entry 297
    0x1.ffe0p-1,
    0x1.ffe0p11,
    0x1.fffffep11
  },
  { // Entry 298
    0.0,
    0x1.p12,
    0x1.p12
  },
  { // Entry 299
    0x1.p-11,
    0x1.p12,
    0x1.000002p12
  },
  { // Entry 300
    0x1.ffffe0p-2,
    0x1.p2,
    0x1.1ffffep2
  },
  { // Entry 301
    0x1.p-1,
    0x1.p2,
    0x1.20p2
  },
  { // Entry 302
    0x1.000010p-1,
    0x1.p2,
    0x1.200002p2
  },
  { // Entry 303
    0x1.ffffc0p-2,
    0x1.p3,
    0x1.0ffffep3
  },
  { // Entry 304
    0x1.p-1,
    0x1.p3,
    0x1.10p3
  },
  { // Entry 305
    0x1.000020p-1,
    0x1.p3,
    0x1.100002p3
  },
  { // Entry 306
    0x1.ffff80p-2,
    0x1.p4,
    0x1.07fffep4
  },
  { // Entry 307
    0x1.p-1,
    0x1.p4,
    0x1.08p4
  },
  { // Entry 308
    0x1.000040p-1,
    0x1.p4,
    0x1.080002p4
  },
  { // Entry 309
    0x1.ffffp-2,
    0x1.p5,
    0x1.03fffep5
  },
  { // Entry 310
    0x1.p-1,
    0x1.p5,
    0x1.04p5
  },
  { // Entry 311
    0x1.000080p-1,
    0x1.p5,
    0x1.040002p5
  },
  { // Entry 312
    0x1.fffep-2,
    0x1.p6,
    0x1.01fffep6
  },
  { // Entry 313
    0x1.p-1,
    0x1.p6,
    0x1.02p6
  },
  { // Entry 314
    0x1.0001p-1,
    0x1.p6,
    0x1.020002p6
  },
  { // Entry 315
    0x1.fffcp-2,
    0x1.p7,
    0x1.00fffep7
  },
  { // Entry 316
    0x1.p-1,
    0x1.p7,
    0x1.01p7
  },
  { // Entry 317
    0x1.0002p-1,
    0x1.p7,
    0x1.010002p7
  },
  { // Entry 318
    0x1.fff8p-2,
    0x1.p8,
    0x1.007ffep8
  },
  { // Entry 319
    0x1.p-1,
    0x1.p8,
    0x1.0080p8
  },
  { // Entry 320
    0x1.0004p-1,
    0x1.p8,
    0x1.008002p8
  },
  { // Entry 321
    0x1.fff0p-2,
    0x1.p9,
    0x1.003ffep9
  },
  { // Entry 322
    0x1.p-1,
    0x1.p9,
    0x1.0040p9
  },
  { // Entry 323
    0x1.0008p-1,
    0x1.p9,
    0x1.004002p9
  },
  { // Entry 324
    0x1.ffe0p-2,
    0x1.p10,
    0x1.001ffep10
  },
  { // Entry 325
    0x1.p-1,
    0x1.p10,
    0x1.0020p10
  },
  { // Entry 326
    0x1.0010p-1,
    0x1.p10,
    0x1.002002p10
  },
  { // Entry 327
    0x1.ffe0p-2,
    0x1.0040p10,
    0x1.005ffep10
  },
  { // Entry 328
    0x1.p-1,
    0x1.0040p10,
    0x1.0060p10
  },
  { // Entry 329
    0x1.0010p-1,
    0x1.0040p10,
    0x1.006002p10
  },
  { // Entry 330
    0x1.ffc0p-2,
    0x1.p11,
    0x1.000ffep11
  },
  { // Entry 331
    0x1.p-1,
    0x1.p11,
    0x1.0010p11
  },
  { // Entry 332
    0x1.0020p-1,
    0x1.p11,
    0x1.001002p11
  },
  { // Entry 333
    0x1.ff80p-2,
    0x1.p12,
    0x1.0007fep12
  },
  { // Entry 334
    0x1.p-1,
    0x1.p12,
    0x1.0008p12
  },
  { // Entry 335
    0x1.0040p-1,
    0x1.p12,
    0x1.000802p12
  },
  { // Entry 336
    0.0,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 337
    -0.0,
    -HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 338
    0.0,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 339
    -0.0,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 340
    0.0,
    0x1.fffffcp127,
    0x1.fffffcp127
  },
  { // Entry 341
    -0.0,
    -0x1.fffffcp127,
    -0x1.fffffcp127
  },
  { // Entry 342
    0x1.21fb60p-3,
    0x1.80p1,
    0x1.921fb6p1
  },
  { // Entry 343
    -0x1.21fb60p-3,
    -0x1.80p1,
    -0x1.921fb6p1
  },
  { // Entry 344
    0x1.243f6cp-1,
    0x1.p0,
    0x1.921fb6p0
  },
  { // Entry 345
    -0x1.243f6cp-1,
    -0x1.p0,
    -0x1.921fb6p0
  },
  { // Entry 346
    0x1.p-23,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 347
    -0x1.p-23,
    -0x1.p0,
    -0x1.000002p0
  },
  { // Entry 348
    0.0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 349
    -0.0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 350
    0x1.fffffep-1,
    0.0,
    0x1.fffffep-1
  },
  { // Entry 351
    -0x1.fffffep-1,
    -0.0,
    -0x1.fffffep-1
  },
  { // Entry 352
    0x1.921fb6p-1,
    0.0,
    0x1.921fb6p-1
  },
  { // Entry 353
    -0x1.921fb6p-1,
    -0.0,
    -0x1.921fb6p-1
  },
  { // Entry 354
    0x1.000002p-126,
    0.0,
    0x1.000002p-126
  },
  { // Entry 355
    -0x1.000002p-126,
    -0.0,
    -0x1.000002p-126
  },
  { // Entry 356
    0x1.p-126,
    0.0,
    0x1.p-126
  },
  { // Entry 357
    -0x1.p-126,
    -0.0,
    -0x1.p-126
  },
  { // Entry 358
    0x1.fffffcp-127,
    0.0,
    0x1.fffffcp-127
  },
  { // Entry 359
    -0x1.fffffcp-127,
    -0.0,
    -0x1.fffffcp-127
  },
  { // Entry 360
    0x1.fffff8p-127,
    0.0,
    0x1.fffff8p-127
  },
  { // Entry 361
    -0x1.fffff8p-127,
    -0.0,
    -0x1.fffff8p-127
  },
  { // Entry 362
    0x1.p-148,
    0.0,
    0x1.p-148
  },
  { // Entry 363
    -0x1.p-148,
    -0.0,
    -0x1.p-148
  },
  { // Entry 364
    0x1.p-149,
    0.0,
    0x1.p-149
  },
  { // Entry 365
    -0x1.p-149,
    -0.0,
    -0x1.p-149
  },
  { // Entry 366
    0.0,
    0.0,
    0.0f
  },
  { // Entry 367
    -0.0,
    -0.0,
    -0.0f
  }
};

"""

```
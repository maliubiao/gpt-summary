Response:
Let's break down the thought process for answering the request about the `modf_intel_data.handroid` file.

**1. Initial Understanding of the File:**

The first and most crucial step is to recognize what the file *is*. The prompt clearly states it's a C++ source file located within the `bionic/tests/math_data` directory. The comment block at the top confirms it's part of the Android Open Source Project (AOSP) and relates to math functions. The name `modf_intel_data` strongly suggests it contains test data specifically for the `modf` function, and the `_intel_data` part hints at platform-specific or Intel-optimized data. The `.handroid` extension is likely a custom convention within the AOSP build system for data files related to Android.

**2. Deconstructing the Data Structure:**

The core of the file is the `g_modf_intel_data` array. Recognizing the `data_2_1_t<double, double, double>` structure is key. This tells us each entry in the array contains three `double` values. The comments within the array initialization (`// Entry N`) are helpful for referencing specific test cases.

**3. Inferring the Functionality (Based on the Data):**

Looking at the values within the data structure is crucial to understanding the file's purpose. The pattern of three doubles per entry, and the names of the file and the array, directly point to testing the `modf` function. The `modf` function is known to take a floating-point number and separate it into its integer and fractional parts. Therefore, the three `double` values in each entry likely represent:

* **Input Value:** The number being passed to `modf`.
* **Integer Part (Expected Output):** The expected integer portion returned by `modf`.
* **Fractional Part (Expected Output):** The expected fractional portion returned by `modf`.

The various numerical representations (decimal, hexadecimal with exponents like `0x1.p-1074`) are used to cover a wide range of floating-point values, including edge cases like zero, very small numbers, and numbers close to powers of two.

**4. Connecting to Android Functionality:**

The prompt asks about the relationship to Android. Since this file is within `bionic`, Android's C library, it directly relates to the mathematical functions provided by the operating system. The `modf` function is part of the standard C library (`libc`), which is a fundamental component of Android. Examples of Android using math functions include:

* **Graphics/UI:** Calculating positions, scaling, rotations.
* **Sensors:** Processing sensor data.
* **Media:** Audio and video processing.
* **Networking:**  Potentially for time calculations or data manipulation.

**5. Explaining `libc` Function Implementation:**

The prompt requests details on the `libc` function's implementation. While this specific *data* file doesn't *contain* the implementation of `modf`, it's used to *test* it. Therefore, the answer should describe the general principle of how `modf` likely works at a low level: inspecting the floating-point representation, separating the integer and fractional parts based on the exponent, and handling signs correctly. It's important to note that the exact implementation can vary across architectures and compiler versions, but the core logic remains the same.

**6. Dynamic Linker and SO Layout (Not Directly Relevant but Address the Request):**

The `modf_intel_data.handroid` file itself doesn't directly involve the dynamic linker. It's static test data. However, the *`modf` function itself* is part of `libc.so`, which *is* loaded by the dynamic linker. Therefore, a basic explanation of SO layout and the linking process is necessary. The key points are:

* **SO Layout:** Code, data (.rodata for constants like this test data), BSS.
* **Linking:** Finding the `modf` symbol in `libc.so` during application startup.

A simple SO layout example and a description of the linking process are sufficient here, emphasizing that this specific data file is *part of* `libc.so`'s data segment.

**7. Logical Reasoning and Assumptions:**

The primary logical reasoning here is the inference of the data's meaning based on the file name, location, and the structure of the data itself. The assumption is that the three `double` values represent the input to `modf` and its expected outputs.

**8. Common Usage Errors:**

For `modf`, common errors include:

* **Ignoring the return value:** `modf` returns the fractional part and modifies a provided pointer for the integer part. Forgetting to use the integer part pointer leads to incorrect results.
* **Passing `NULL` for the integer part pointer:** This will cause a crash.

**9. Android Framework/NDK Path and Frida Hooking:**

This part requires tracing how an application might end up using `modf` and how to use Frida to observe this.

* **Framework/NDK Path:** Start with a high-level API that might use math (e.g., `android.graphics.Matrix` or NDK math functions). Then, show how this might eventually call the `modf` function in `libc.so`.
* **Frida Hooking:** Provide a basic Frida script that hooks the `modf` function, logs its arguments and return values, demonstrating how to inspect its behavior. This involves finding the address of `modf` in `libc.so`.

**10. Language and Tone:**

The request specifies a response in Chinese, so the entire answer needs to be in Chinese. The tone should be informative and explanatory, clearly addressing each part of the prompt.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:**  Maybe this file contains assembly code for optimized `modf`.
* **Correction:**  The `.handroid` extension and the C++ structure suggest it's data, not code. The `_intel_data` part points to data tailored for Intel platforms, likely for testing accuracy.
* **Initial thought:** Explain the *exact* assembly implementation of `modf`.
* **Refinement:**  Focus on the general principles of how `modf` likely works, as the specific implementation isn't in this file and can vary. Emphasize the separation of integer and fractional parts.
* **Initial thought:** Go deep into dynamic linking internals.
* **Refinement:** Keep the dynamic linking explanation concise and focused on the relevance to `libc.so` and the location of the test data within its data segment.

By following this structured thought process, breaking down the request into smaller parts, and making necessary refinements, a comprehensive and accurate answer can be constructed.
这个目录 `bionic/tests/math_data/modf_intel_data.handroid` 下的源代码文件 `modf_intel_data.handroid` 的主要功能是 **为 `modf` 函数提供测试数据**。

**功能列举:**

1. **存储预定义的测试用例:**  该文件包含一个名为 `g_modf_intel_data` 的静态数组，该数组的元素类型为 `data_2_1_t<double, double, double>`。每个数组元素代表一个测试用例，包含 `modf` 函数的输入值以及预期的输出值。
2. **覆盖多种输入场景:**  这些测试用例覆盖了各种 `double` 类型的输入，包括：
    * 非常小的值（接近于零）
    * 零
    * 非常接近于整数的值
    * 正数和负数
    * 具有不同精度的值
    * 接近于2的幂次的值
    * 特殊值，如 `HUGE_VAL`
3. **用于验证 `modf` 函数的正确性:** 在 bionic 的测试框架中，这个数据文件会被用来驱动对 `modf` 函数的测试，确保该函数在不同输入下能够返回正确的结果。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 的底层 C 库 (bionic) 中的数学库。 `modf` 是一个标准的 C 库函数，用于将浮点数分解为整数部分和小数部分。

**举例说明:**

在 Android 系统中，很多地方会用到浮点数运算，因此 `modf` 函数及其正确性至关重要。以下是一些可能的应用场景：

* **图形渲染:**  在处理图形坐标、缩放、旋转等操作时，可能需要将浮点数坐标分解为整数部分和小数部分，以便进行像素级别的绘制或者判断。例如，将一个浮点数的 X 坐标分解为整数部分（像素列号）和小数部分（用于亚像素渲染）。
* **动画效果:** 在创建动画时，可能需要计算物体在每一帧的精确位置，这可能涉及到浮点数运算。`modf` 可以用来提取位移的整数部分和小数部分，分别用于不同的计算或渲染步骤。
* **传感器数据处理:**  Android 设备上的传感器（如加速度计、陀螺仪）产生的数据通常是浮点数。在某些算法中，可能需要将这些浮点数数据分解为整数和小数部分进行处理。
* **音频处理:** 音频采样率和缓冲区大小等参数可能以浮点数形式存在，`modf` 可以用于处理这些参数。

**详细解释 `libc` 函数 `modf` 的功能是如何实现的:**

`modf` 函数的定义如下：

```c
double modf(double x, double *iptr);
```

**功能:**

`modf` 函数将浮点数 `x` 分解为整数部分和小数部分。它将 `x` 的**带符号的整数部分**存储在 `iptr` 指向的 `double` 类型变量中，并返回 `x` 的**带符号的小数部分**。

**实现原理 (通常的实现方式):**

`modf` 的实现通常依赖于浮点数的内部表示 (IEEE 754)。其大致步骤如下：

1. **处理符号:** 首先确定输入 `x` 的符号，并将其保存。后续操作可以针对其绝对值进行，并在最后为结果添加符号。
2. **提取指数和尾数:**  从 `x` 的浮点数表示中提取指数部分和尾数部分。
3. **判断整数部分:**  根据指数的值，判断 `x` 的整数部分。
    * 如果指数非常小，表示 `x` 的绝对值小于 1，则整数部分为 0，小数部分为 `x` 本身。
    * 如果指数足够大，表示 `x` 的绝对值很大，则小数部分为 0，整数部分为 `x` 本身。
    * 如果指数在中间范围，则需要构造整数部分。
4. **构造整数部分:**  根据指数，将尾数部分进行移位操作，以构建出 `x` 的整数部分。这通常涉及位运算。
5. **计算小数部分:**  小数部分可以通过 `x` 减去整数部分得到。需要注意浮点数精度问题。
6. **设置 `iptr`:** 将计算出的整数部分通过指针 `iptr` 写入到指定的内存位置。
7. **返回小数部分:** 函数返回计算出的小数部分。

**代码层面 (概念性示例):**

```c
double modf(double x, double *iptr) {
    double abs_x = fabs(x);
    int exponent;
    double mantissa = frexp(abs_x, &exponent); // frexp 获取尾数和指数

    double integer_part;
    double fractional_part;

    if (exponent <= 0) {
        integer_part = 0.0;
        fractional_part = x; // x 本身小于 1
    } else if (exponent > 52) { // double 的尾数位数是 52
        integer_part = x;
        fractional_part = 0.0;
    } else {
        // 根据指数和尾数构造整数部分
        // (具体实现涉及位运算和浮点数表示)
        // ...

        fractional_part = x - integer_part;
    }

    *iptr = (x >= 0) ? integer_part : -integer_part; // 恢复符号
    return (x >= 0) ? fractional_part : -fractional_part; // 恢复符号
}
```

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`modf_intel_data.handroid` 文件本身 **不涉及** dynamic linker 的功能。它仅仅是静态的数据文件，会被编译进包含 `modf` 函数实现的共享库中（通常是 `libc.so`）。

`modf` 函数的实现位于 `libc.so` 中。当一个 Android 应用程序需要使用 `modf` 函数时，链接过程会涉及 dynamic linker。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text          (代码段 - 包含 modf 函数的机器码)
        ...
        modf:
            push   rbp
            mov    rbp, rsp
            ... (modf 函数的实现)
            pop    rbp
            ret
        ...
    .rodata        (只读数据段 - 可能包含字符串常量等)
        ...
    .data          (可读写数据段 - 可能包含全局变量)
        g_modf_intel_data:
            // 测试数据，实际存储的是 double 类型的二进制表示
            0xbfc0000000000000, 0x0000000000000000, 0xbfc0000000000001,
            ...
    .bss           (未初始化数据段)
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序的代码被编译时，编译器会识别到对 `modf` 函数的调用。由于 `modf` 是标准 C 库函数，编译器会假设它在运行时可以通过链接器找到。
2. **运行时链接 (Dynamic Linking):**
   * 当 Android 系统启动应用程序时，`dalvikvm` (或 ART) 会加载应用程序的可执行文件。
   * 可执行文件头中包含了它依赖的共享库信息，其中就包括 `libc.so`。
   * **Dynamic Linker (`/system/bin/linker64` 或 `/system/bin/linker`)** 会被操作系统调用，负责加载应用程序依赖的共享库。
   * Dynamic Linker 会根据应用程序的依赖信息找到 `libc.so`，并将其加载到内存中。
   * **符号解析:** Dynamic Linker 会解析应用程序中对 `modf` 等外部符号的引用，并在 `libc.so` 的符号表 (symbol table) 中查找这些符号的地址。
   * **重定位:**  Dynamic Linker 会更新应用程序代码中的地址，将对 `modf` 函数的调用地址指向 `libc.so` 中 `modf` 函数的实际内存地址。
   * 最终，当应用程序执行到调用 `modf` 的代码时，它会跳转到 `libc.so` 中 `modf` 函数的实现。

**假设输入与输出 (基于文件内容):**

文件中的每个 `Entry` 都代表一个测试用例。我们以 `Entry 0` 为例：

**假设输入:** `x = -0x1.p-1074` (这是一个十六进制表示的浮点数，相当于 -0.5 * 2^-1074)

**预期输出:**
* `modf` 函数返回的小数部分: `-0x1.0p-1074`
* `iptr` 指向的整数部分: `-0.0`

**编程常见的使用错误举例说明:**

1. **忘记接收整数部分:** `modf` 函数通过修改传入的指针来返回整数部分。如果程序员忘记声明并传递指针，或者忽略了指针指向的值，将无法获取到整数部分。

   ```c
   #include <stdio.h>
   #include <math.h>

   int main() {
       double value = 3.14;
       double fractional_part = modf(value, NULL); // 错误：传递 NULL 指针

       printf("Fractional part: %f\n", fractional_part);
       return 0;
   }
   ```
   **错误说明:**  传递 `NULL` 作为 `iptr` 会导致程序崩溃（段错误），因为 `modf` 会尝试解引用空指针。

2. **未初始化整数部分指针:** 如果声明了指针但未初始化就传递给 `modf`，其行为是未定义的。

   ```c
   #include <stdio.h>
   #include <math.h>

   int main() {
       double value = 3.14;
       double integer_part_ptr; // 错误：未初始化
       double fractional_part = modf(value, &integer_part_ptr);

       printf("Fractional part: %f, Integer part: %f\n", fractional_part, integer_part_ptr); // 读取未初始化的内存
       return 0;
   }
   ```
   **错误说明:**  `integer_part_ptr` 指向的内存位置的值是不确定的，打印出来的值也是随机的。

3. **类型不匹配:**  虽然 `modf` 的第二个参数是 `double *`，但如果传递了其他类型的指针，会导致类型不匹配，可能产生未定义的行为或编译警告/错误。

**说明 Android framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

要到达 `modf` 函数，通常是从 Android framework 或 NDK 中的某个组件开始，最终调用到 bionic 的 C 库函数。

**Android Framework 示例 (假设场景：处理图形坐标):**

1. **`android.graphics.Matrix`:**  Framework 中的 `Matrix` 类用于进行图形变换（平移、旋转、缩放等）。这些变换通常涉及到浮点数运算。
2. **Native 代码:** `Matrix` 类的一些操作可能在 native 层实现，例如通过 JNI 调用到 C++ 代码。
3. **OpenGL ES 或 Skia:** 底层的图形渲染可能使用 OpenGL ES 或 Skia 库，这些库在进行坐标变换时可能会用到浮点数运算。
4. **数学函数:** 在 OpenGL ES 或 Skia 的实现中，可能会直接或间接地调用到 `modf` 或其他数学函数，例如在进行坐标归一化或像素对齐时。

**NDK 示例 (假设场景：自定义图像处理):**

1. **NDK C/C++ 代码:**  开发者使用 NDK 编写 native 代码进行图像处理。
2. **浮点数运算:** 图像处理算法中可能包含大量的浮点数运算，例如像素值的归一化、滤波等。
3. **调用 `modf`:** 开发者可能直接或间接地调用 `modf` 函数。例如，将浮点数像素坐标分解为整数部分和小数部分用于插值计算。

**Frida Hook 示例:**

假设我们想 hook `libc.so` 中的 `modf` 函数，观察其输入和输出。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "modf"), {
    onEnter: function(args) {
        this.x = args[0];
        this.iptr = args[1];
        console.log("[Modf] Input x:", this.x);
    },
    onLeave: function(retval) {
        var integerPart = this.iptr.readDouble();
        console.log("[Modf] Fractional part (return):", retval, "Integer part (ptr):", integerPart);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定目标应用:**  设置 `package_name` 为要调试的 Android 应用的包名。
3. **连接到设备和进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的目标应用进程。
4. **Frida Script:**
   * `Interceptor.attach`:  拦截 `libc.so` 中名为 `modf` 的导出函数。
   * `onEnter`: 在 `modf` 函数被调用之前执行。
     * `args[0]`:  获取第一个参数 (double x)。
     * `args[1]`:  获取第二个参数 (double *iptr)。
     * 打印输入值 `x`。
   * `onLeave`: 在 `modf` 函数执行完毕并即将返回时执行。
     * `this.iptr.readDouble()`: 读取 `iptr` 指向的内存位置的 `double` 值（整数部分）。
     * `retval`: 获取函数的返回值（小数部分）。
     * 打印返回值和整数部分。
5. **创建和加载 Script:** 创建 Frida script 并加载到目标进程中。
6. **保持运行:** `sys.stdin.read()` 使脚本保持运行状态，直到手动停止。

**运行 Frida Hook 的步骤:**

1. 确保你的电脑上安装了 Frida 和 adb，并且 Android 设备已通过 USB 连接并启用了 USB 调试。
2. 启动你要调试的 Android 应用。
3. 运行上面的 Python Frida 脚本。
4. 当目标应用中的代码调用 `modf` 函数时，Frida 脚本会在控制台打印出 `modf` 函数的输入和输出值。

通过这种方式，你可以监控 `modf` 函数的调用，验证其行为，并理解 Android framework 或 NDK 如何逐步使用到这个底层的 C 库函数。

Prompt: 
```
这是目录为bionic/tests/math_data/modf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_2_1_t<double, double, double> g_modf_intel_data[] = {
  { // Entry 0
    -0x1.p-1074,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 1
    -0.0,
    -0.0,
    -0.0
  },
  { // Entry 2
    0x1.p-1074,
    0.0,
    0x1.0p-1074
  },
  { // Entry 3
    0x1.fffffffffffff0p-2,
    0.0,
    0x1.fffffffffffffp-2
  },
  { // Entry 4
    0x1.p-1,
    0.0,
    0x1.0p-1
  },
  { // Entry 5
    0x1.00000000000010p-1,
    0.0,
    0x1.0000000000001p-1
  },
  { // Entry 6
    0x1.fffffffffffff0p-1,
    0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 7
    0.0,
    0x1.p0,
    0x1.0p0
  },
  { // Entry 8
    0x1.p-52,
    0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 9
    0x1.ffffffffffffc0p-2,
    0x1.p0,
    0x1.7ffffffffffffp0
  },
  { // Entry 10
    0x1.p-1,
    0x1.p0,
    0x1.8p0
  },
  { // Entry 11
    0x1.00000000000020p-1,
    0x1.p0,
    0x1.8000000000001p0
  },
  { // Entry 12
    0x1.ffffffffffffe0p-1,
    0x1.p0,
    0x1.fffffffffffffp0
  },
  { // Entry 13
    0.0,
    0x1.p1,
    0x1.0p1
  },
  { // Entry 14
    0x1.p-51,
    0x1.p1,
    0x1.0000000000001p1
  },
  { // Entry 15
    0x1.ffffffffffff80p-2,
    0x1.p1,
    0x1.3ffffffffffffp1
  },
  { // Entry 16
    0x1.p-1,
    0x1.p1,
    0x1.4p1
  },
  { // Entry 17
    0x1.00000000000040p-1,
    0x1.p1,
    0x1.4000000000001p1
  },
  { // Entry 18
    0x1.fffffffffff8p-1,
    0x1.8cp6,
    0x1.8ffffffffffffp6
  },
  { // Entry 19
    0.0,
    0x1.90p6,
    0x1.9p6
  },
  { // Entry 20
    0x1.p-46,
    0x1.90p6,
    0x1.9000000000001p6
  },
  { // Entry 21
    0x1.fffffffffff0p-2,
    0x1.90p6,
    0x1.91fffffffffffp6
  },
  { // Entry 22
    0x1.p-1,
    0x1.90p6,
    0x1.920p6
  },
  { // Entry 23
    0x1.000000000008p-1,
    0x1.90p6,
    0x1.9200000000001p6
  },
  { // Entry 24
    0x1.ffffffffffc0p-1,
    0x1.f380p9,
    0x1.f3fffffffffffp9
  },
  { // Entry 25
    0.0,
    0x1.f4p9,
    0x1.f40p9
  },
  { // Entry 26
    0x1.p-43,
    0x1.f4p9,
    0x1.f400000000001p9
  },
  { // Entry 27
    0x1.ffffffffff80p-2,
    0x1.f4p9,
    0x1.f43ffffffffffp9
  },
  { // Entry 28
    0x1.p-1,
    0x1.f4p9,
    0x1.f44p9
  },
  { // Entry 29
    0x1.000000000040p-1,
    0x1.f4p9,
    0x1.f440000000001p9
  },
  { // Entry 30
    0x1.c0p-1,
    0x1.ffffffffffff80p49,
    0x1.fffffffffffffp49
  },
  { // Entry 31
    0.0,
    0x1.p50,
    0x1.0p50
  },
  { // Entry 32
    0x1.p-2,
    0x1.p50,
    0x1.0000000000001p50
  },
  { // Entry 33
    0x1.80p-1,
    0x1.ffffffffffffc0p50,
    0x1.fffffffffffffp50
  },
  { // Entry 34
    0.0,
    0x1.p51,
    0x1.0p51
  },
  { // Entry 35
    0x1.p-1,
    0x1.p51,
    0x1.0000000000001p51
  },
  { // Entry 36
    0x1.p-1,
    0x1.ffffffffffffe0p51,
    0x1.fffffffffffffp51
  },
  { // Entry 37
    0.0,
    0x1.p52,
    0x1.0p52
  },
  { // Entry 38
    0.0,
    0x1.00000000000010p52,
    0x1.0000000000001p52
  },
  { // Entry 39
    0.0,
    0x1.fffffffffffff0p52,
    0x1.fffffffffffffp52
  },
  { // Entry 40
    0.0,
    0x1.p53,
    0x1.0p53
  },
  { // Entry 41
    0.0,
    0x1.00000000000010p53,
    0x1.0000000000001p53
  },
  { // Entry 42
    0.0,
    0x1.fffffffffffff0p53,
    0x1.fffffffffffffp53
  },
  { // Entry 43
    0.0,
    0x1.p54,
    0x1.0p54
  },
  { // Entry 44
    0.0,
    0x1.00000000000010p54,
    0x1.0000000000001p54
  },
  { // Entry 45
    0.0,
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 46
    -0x1.00000000000010p-1,
    -0.0,
    -0x1.0000000000001p-1
  },
  { // Entry 47
    -0x1.p-1,
    -0.0,
    -0x1.0p-1
  },
  { // Entry 48
    -0x1.fffffffffffff0p-2,
    -0.0,
    -0x1.fffffffffffffp-2
  },
  { // Entry 49
    -0x1.p-52,
    -0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 50
    -0.0,
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 51
    -0x1.fffffffffffff0p-1,
    -0.0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 52
    -0x1.00000000000020p-1,
    -0x1.p0,
    -0x1.8000000000001p0
  },
  { // Entry 53
    -0x1.p-1,
    -0x1.p0,
    -0x1.8p0
  },
  { // Entry 54
    -0x1.ffffffffffffc0p-2,
    -0x1.p0,
    -0x1.7ffffffffffffp0
  },
  { // Entry 55
    -0x1.p-51,
    -0x1.p1,
    -0x1.0000000000001p1
  },
  { // Entry 56
    -0.0,
    -0x1.p1,
    -0x1.0p1
  },
  { // Entry 57
    -0x1.ffffffffffffe0p-1,
    -0x1.p0,
    -0x1.fffffffffffffp0
  },
  { // Entry 58
    -0x1.00000000000040p-1,
    -0x1.p1,
    -0x1.4000000000001p1
  },
  { // Entry 59
    -0x1.p-1,
    -0x1.p1,
    -0x1.4p1
  },
  { // Entry 60
    -0x1.ffffffffffff80p-2,
    -0x1.p1,
    -0x1.3ffffffffffffp1
  },
  { // Entry 61
    -0x1.p-46,
    -0x1.90p6,
    -0x1.9000000000001p6
  },
  { // Entry 62
    -0.0,
    -0x1.90p6,
    -0x1.9p6
  },
  { // Entry 63
    -0x1.fffffffffff8p-1,
    -0x1.8cp6,
    -0x1.8ffffffffffffp6
  },
  { // Entry 64
    -0x1.000000000008p-1,
    -0x1.90p6,
    -0x1.9200000000001p6
  },
  { // Entry 65
    -0x1.p-1,
    -0x1.90p6,
    -0x1.920p6
  },
  { // Entry 66
    -0x1.fffffffffff0p-2,
    -0x1.90p6,
    -0x1.91fffffffffffp6
  },
  { // Entry 67
    -0x1.p-43,
    -0x1.f4p9,
    -0x1.f400000000001p9
  },
  { // Entry 68
    -0.0,
    -0x1.f4p9,
    -0x1.f40p9
  },
  { // Entry 69
    -0x1.ffffffffffc0p-1,
    -0x1.f380p9,
    -0x1.f3fffffffffffp9
  },
  { // Entry 70
    -0x1.000000000040p-1,
    -0x1.f4p9,
    -0x1.f440000000001p9
  },
  { // Entry 71
    -0x1.p-1,
    -0x1.f4p9,
    -0x1.f44p9
  },
  { // Entry 72
    -0x1.ffffffffff80p-2,
    -0x1.f4p9,
    -0x1.f43ffffffffffp9
  },
  { // Entry 73
    -0x1.p-2,
    -0x1.p50,
    -0x1.0000000000001p50
  },
  { // Entry 74
    -0.0,
    -0x1.p50,
    -0x1.0p50
  },
  { // Entry 75
    -0x1.c0p-1,
    -0x1.ffffffffffff80p49,
    -0x1.fffffffffffffp49
  },
  { // Entry 76
    -0x1.p-1,
    -0x1.p51,
    -0x1.0000000000001p51
  },
  { // Entry 77
    -0.0,
    -0x1.p51,
    -0x1.0p51
  },
  { // Entry 78
    -0x1.80p-1,
    -0x1.ffffffffffffc0p50,
    -0x1.fffffffffffffp50
  },
  { // Entry 79
    -0.0,
    -0x1.00000000000010p52,
    -0x1.0000000000001p52
  },
  { // Entry 80
    -0.0,
    -0x1.p52,
    -0x1.0p52
  },
  { // Entry 81
    -0x1.p-1,
    -0x1.ffffffffffffe0p51,
    -0x1.fffffffffffffp51
  },
  { // Entry 82
    -0.0,
    -0x1.00000000000010p53,
    -0x1.0000000000001p53
  },
  { // Entry 83
    -0.0,
    -0x1.p53,
    -0x1.0p53
  },
  { // Entry 84
    -0.0,
    -0x1.fffffffffffff0p52,
    -0x1.fffffffffffffp52
  },
  { // Entry 85
    -0.0,
    -0x1.00000000000010p54,
    -0x1.0000000000001p54
  },
  { // Entry 86
    -0.0,
    -0x1.p54,
    -0x1.0p54
  },
  { // Entry 87
    -0.0,
    -0x1.fffffffffffff0p53,
    -0x1.fffffffffffffp53
  },
  { // Entry 88
    -0.0,
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 89
    0x1.fffffcp-1,
    0x1.fffffff8p29,
    0x1.fffffffffffffp29
  },
  { // Entry 90
    0.0,
    0x1.p30,
    0x1.0p30
  },
  { // Entry 91
    0x1.p-22,
    0x1.p30,
    0x1.0000000000001p30
  },
  { // Entry 92
    0x1.ffffe8p-1,
    0x1.fffffff4p30,
    0x1.fffffff7ffffdp30
  },
  { // Entry 93
    0x1.fffff0p-1,
    0x1.fffffff4p30,
    0x1.fffffff7ffffep30
  },
  { // Entry 94
    0x1.fffff8p-1,
    0x1.fffffff4p30,
    0x1.fffffff7fffffp30
  },
  { // Entry 95
    0.0,
    0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 96
    0x1.p-22,
    0x1.fffffff8p30,
    0x1.fffffff800001p30
  },
  { // Entry 97
    0x1.p-21,
    0x1.fffffff8p30,
    0x1.fffffff800002p30
  },
  { // Entry 98
    0x1.80p-21,
    0x1.fffffff8p30,
    0x1.fffffff800003p30
  },
  { // Entry 99
    0x1.ffffd0p-2,
    0x1.fffffff8p30,
    0x1.fffffff9ffffdp30
  },
  { // Entry 100
    0x1.ffffe0p-2,
    0x1.fffffff8p30,
    0x1.fffffff9ffffep30
  },
  { // Entry 101
    0x1.fffff0p-2,
    0x1.fffffff8p30,
    0x1.fffffff9fffffp30
  },
  { // Entry 102
    0x1.p-1,
    0x1.fffffff8p30,
    0x1.fffffffa0p30
  },
  { // Entry 103
    0x1.000008p-1,
    0x1.fffffff8p30,
    0x1.fffffffa00001p30
  },
  { // Entry 104
    0x1.000010p-1,
    0x1.fffffff8p30,
    0x1.fffffffa00002p30
  },
  { // Entry 105
    0x1.000018p-1,
    0x1.fffffff8p30,
    0x1.fffffffa00003p30
  },
  { // Entry 106
    0x1.ffffe8p-1,
    0x1.fffffff8p30,
    0x1.fffffffbffffdp30
  },
  { // Entry 107
    0x1.fffff0p-1,
    0x1.fffffff8p30,
    0x1.fffffffbffffep30
  },
  { // Entry 108
    0x1.fffff8p-1,
    0x1.fffffff8p30,
    0x1.fffffffbfffffp30
  },
  { // Entry 109
    0.0,
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 110
    0x1.p-22,
    0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 111
    0x1.p-21,
    0x1.fffffffcp30,
    0x1.fffffffc00002p30
  },
  { // Entry 112
    0x1.80p-21,
    0x1.fffffffcp30,
    0x1.fffffffc00003p30
  },
  { // Entry 113
    0x1.ffffd0p-2,
    0x1.fffffffcp30,
    0x1.fffffffdffffdp30
  },
  { // Entry 114
    0x1.ffffe0p-2,
    0x1.fffffffcp30,
    0x1.fffffffdffffep30
  },
  { // Entry 115
    0x1.fffff0p-2,
    0x1.fffffffcp30,
    0x1.fffffffdfffffp30
  },
  { // Entry 116
    0x1.p-1,
    0x1.fffffffcp30,
    0x1.fffffffe0p30
  },
  { // Entry 117
    0x1.000008p-1,
    0x1.fffffffcp30,
    0x1.fffffffe00001p30
  },
  { // Entry 118
    0x1.000010p-1,
    0x1.fffffffcp30,
    0x1.fffffffe00002p30
  },
  { // Entry 119
    0x1.000018p-1,
    0x1.fffffffcp30,
    0x1.fffffffe00003p30
  },
  { // Entry 120
    0x1.ffffe8p-1,
    0x1.fffffffcp30,
    0x1.ffffffffffffdp30
  },
  { // Entry 121
    0x1.fffff0p-1,
    0x1.fffffffcp30,
    0x1.ffffffffffffep30
  },
  { // Entry 122
    0x1.fffff8p-1,
    0x1.fffffffcp30,
    0x1.fffffffffffffp30
  },
  { // Entry 123
    0.0,
    0x1.p31,
    0x1.0p31
  },
  { // Entry 124
    0x1.p-21,
    0x1.p31,
    0x1.0000000000001p31
  },
  { // Entry 125
    0x1.p-20,
    0x1.p31,
    0x1.0000000000002p31
  },
  { // Entry 126
    0x1.80p-20,
    0x1.p31,
    0x1.0000000000003p31
  },
  { // Entry 127
    0x1.ffffa0p-2,
    0x1.p31,
    0x1.00000000ffffdp31
  },
  { // Entry 128
    0x1.ffffc0p-2,
    0x1.p31,
    0x1.00000000ffffep31
  },
  { // Entry 129
    0x1.ffffe0p-2,
    0x1.p31,
    0x1.00000000fffffp31
  },
  { // Entry 130
    0x1.p-1,
    0x1.p31,
    0x1.000000010p31
  },
  { // Entry 131
    0x1.000010p-1,
    0x1.p31,
    0x1.0000000100001p31
  },
  { // Entry 132
    0x1.000020p-1,
    0x1.p31,
    0x1.0000000100002p31
  },
  { // Entry 133
    0x1.000030p-1,
    0x1.p31,
    0x1.0000000100003p31
  },
  { // Entry 134
    0.0,
    0x1.ffffffe0p30,
    0x1.ffffffep30
  },
  { // Entry 135
    0.0,
    0x1.ffffffe4p30,
    0x1.ffffffe40p30
  },
  { // Entry 136
    0.0,
    0x1.ffffffe8p30,
    0x1.ffffffe80p30
  },
  { // Entry 137
    0.0,
    0x1.ffffffecp30,
    0x1.ffffffec0p30
  },
  { // Entry 138
    0.0,
    0x1.fffffff0p30,
    0x1.fffffffp30
  },
  { // Entry 139
    0.0,
    0x1.fffffff4p30,
    0x1.fffffff40p30
  },
  { // Entry 140
    0.0,
    0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 141
    0.0,
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 142
    0.0,
    0x1.p31,
    0x1.0p31
  },
  { // Entry 143
    0.0,
    0x1.00000002p31,
    0x1.000000020p31
  },
  { // Entry 144
    -0x1.p-22,
    -0x1.p30,
    -0x1.0000000000001p30
  },
  { // Entry 145
    -0.0,
    -0x1.p30,
    -0x1.0p30
  },
  { // Entry 146
    -0x1.fffffcp-1,
    -0x1.fffffff8p29,
    -0x1.fffffffffffffp29
  },
  { // Entry 147
    -0x1.80p-21,
    -0x1.fffffff8p30,
    -0x1.fffffff800003p30
  },
  { // Entry 148
    -0x1.p-21,
    -0x1.fffffff8p30,
    -0x1.fffffff800002p30
  },
  { // Entry 149
    -0x1.p-22,
    -0x1.fffffff8p30,
    -0x1.fffffff800001p30
  },
  { // Entry 150
    -0.0,
    -0x1.fffffff8p30,
    -0x1.fffffff80p30
  },
  { // Entry 151
    -0x1.fffff8p-1,
    -0x1.fffffff4p30,
    -0x1.fffffff7fffffp30
  },
  { // Entry 152
    -0x1.fffff0p-1,
    -0x1.fffffff4p30,
    -0x1.fffffff7ffffep30
  },
  { // Entry 153
    -0x1.ffffe8p-1,
    -0x1.fffffff4p30,
    -0x1.fffffff7ffffdp30
  },
  { // Entry 154
    -0x1.000018p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffa00003p30
  },
  { // Entry 155
    -0x1.000010p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffa00002p30
  },
  { // Entry 156
    -0x1.000008p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffa00001p30
  },
  { // Entry 157
    -0x1.p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffa0p30
  },
  { // Entry 158
    -0x1.fffff0p-2,
    -0x1.fffffff8p30,
    -0x1.fffffff9fffffp30
  },
  { // Entry 159
    -0x1.ffffe0p-2,
    -0x1.fffffff8p30,
    -0x1.fffffff9ffffep30
  },
  { // Entry 160
    -0x1.ffffd0p-2,
    -0x1.fffffff8p30,
    -0x1.fffffff9ffffdp30
  },
  { // Entry 161
    -0x1.80p-21,
    -0x1.fffffffcp30,
    -0x1.fffffffc00003p30
  },
  { // Entry 162
    -0x1.p-21,
    -0x1.fffffffcp30,
    -0x1.fffffffc00002p30
  },
  { // Entry 163
    -0x1.p-22,
    -0x1.fffffffcp30,
    -0x1.fffffffc00001p30
  },
  { // Entry 164
    -0.0,
    -0x1.fffffffcp30,
    -0x1.fffffffc0p30
  },
  { // Entry 165
    -0x1.fffff8p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffbfffffp30
  },
  { // Entry 166
    -0x1.fffff0p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffbffffep30
  },
  { // Entry 167
    -0x1.ffffe8p-1,
    -0x1.fffffff8p30,
    -0x1.fffffffbffffdp30
  },
  { // Entry 168
    -0x1.000018p-1,
    -0x1.fffffffcp30,
    -0x1.fffffffe00003p30
  },
  { // Entry 169
    -0x1.000010p-1,
    -0x1.fffffffcp30,
    -0x1.fffffffe00002p30
  },
  { // Entry 170
    -0x1.000008p-1,
    -0x1.fffffffcp30,
    -0x1.fffffffe00001p30
  },
  { // Entry 171
    -0x1.p-1,
    -0x1.fffffffcp30,
    -0x1.fffffffe0p30
  },
  { // Entry 172
    -0x1.fffff0p-2,
    -0x1.fffffffcp30,
    -0x1.fffffffdfffffp30
  },
  { // Entry 173
    -0x1.ffffe0p-2,
    -0x1.fffffffcp30,
    -0x1.fffffffdffffep30
  },
  { // Entry 174
    -0x1.ffffd0p-2,
    -0x1.fffffffcp30,
    -0x1.fffffffdffffdp30
  },
  { // Entry 175
    -0x1.80p-20,
    -0x1.p31,
    -0x1.0000000000003p31
  },
  { // Entry 176
    -0x1.p-20,
    -0x1.p31,
    -0x1.0000000000002p31
  },
  { // Entry 177
    -0x1.p-21,
    -0x1.p31,
    -0x1.0000000000001p31
  },
  { // Entry 178
    -0.0,
    -0x1.p31,
    -0x1.0p31
  },
  { // Entry 179
    -0x1.fffff8p-1,
    -0x1.fffffffcp30,
    -0x1.fffffffffffffp30
  },
  { // Entry 180
    -0x1.fffff0p-1,
    -0x1.fffffffcp30,
    -0x1.ffffffffffffep30
  },
  { // Entry 181
    -0x1.ffffe8p-1,
    -0x1.fffffffcp30,
    -0x1.ffffffffffffdp30
  },
  { // Entry 182
    -0x1.000030p-1,
    -0x1.p31,
    -0x1.0000000100003p31
  },
  { // Entry 183
    -0x1.000020p-1,
    -0x1.p31,
    -0x1.0000000100002p31
  },
  { // Entry 184
    -0x1.000010p-1,
    -0x1.p31,
    -0x1.0000000100001p31
  },
  { // Entry 185
    -0x1.p-1,
    -0x1.p31,
    -0x1.000000010p31
  },
  { // Entry 186
    -0x1.ffffe0p-2,
    -0x1.p31,
    -0x1.00000000fffffp31
  },
  { // Entry 187
    -0x1.ffffc0p-2,
    -0x1.p31,
    -0x1.00000000ffffep31
  },
  { // Entry 188
    -0x1.ffffa0p-2,
    -0x1.p31,
    -0x1.00000000ffffdp31
  },
  { // Entry 189
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 190
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 191
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 192
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 193
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 194
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 195
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 196
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 197
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 198
    -0.0,
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 199
    0.0,
    0x1.ffffffffffffd0p61,
    0x1.ffffffffffffdp61
  },
  { // Entry 200
    0.0,
    0x1.ffffffffffffe0p61,
    0x1.ffffffffffffep61
  },
  { // Entry 201
    0.0,
    0x1.fffffffffffff0p61,
    0x1.fffffffffffffp61
  },
  { // Entry 202
    0.0,
    0x1.p62,
    0x1.0p62
  },
  { // Entry 203
    0.0,
    0x1.00000000000010p62,
    0x1.0000000000001p62
  },
  { // Entry 204
    0.0,
    0x1.00000000000020p62,
    0x1.0000000000002p62
  },
  { // Entry 205
    0.0,
    0x1.00000000000030p62,
    0x1.0000000000003p62
  },
  { // Entry 206
    0.0,
    0x1.ffffffffffffd0p62,
    0x1.ffffffffffffdp62
  },
  { // Entry 207
    0.0,
    0x1.ffffffffffffe0p62,
    0x1.ffffffffffffep62
  },
  { // Entry 208
    0.0,
    0x1.fffffffffffff0p62,
    0x1.fffffffffffffp62
  },
  { // Entry 209
    0.0,
    0x1.p63,
    0x1.0p63
  },
  { // Entry 210
    0.0,
    0x1.00000000000010p63,
    0x1.0000000000001p63
  },
  { // Entry 211
    0.0,
    0x1.00000000000020p63,
    0x1.0000000000002p63
  },
  { // Entry 212
    0.0,
    0x1.00000000000030p63,
    0x1.0000000000003p63
  },
  { // Entry 213
    0.0,
    0x1.ffffffffffffd0p63,
    0x1.ffffffffffffdp63
  },
  { // Entry 214
    0.0,
    0x1.ffffffffffffe0p63,
    0x1.ffffffffffffep63
  },
  { // Entry 215
    0.0,
    0x1.fffffffffffff0p63,
    0x1.fffffffffffffp63
  },
  { // Entry 216
    0.0,
    0x1.p64,
    0x1.0p64
  },
  { // Entry 217
    0.0,
    0x1.00000000000010p64,
    0x1.0000000000001p64
  },
  { // Entry 218
    0.0,
    0x1.00000000000020p64,
    0x1.0000000000002p64
  },
  { // Entry 219
    0.0,
    0x1.00000000000030p64,
    0x1.0000000000003p64
  },
  { // Entry 220
    -0.0,
    -0x1.00000000000030p62,
    -0x1.0000000000003p62
  },
  { // Entry 221
    -0.0,
    -0x1.00000000000020p62,
    -0x1.0000000000002p62
  },
  { // Entry 222
    -0.0,
    -0x1.00000000000010p62,
    -0x1.0000000000001p62
  },
  { // Entry 223
    -0.0,
    -0x1.p62,
    -0x1.0p62
  },
  { // Entry 224
    -0.0,
    -0x1.fffffffffffff0p61,
    -0x1.fffffffffffffp61
  },
  { // Entry 225
    -0.0,
    -0x1.ffffffffffffe0p61,
    -0x1.ffffffffffffep61
  },
  { // Entry 226
    -0.0,
    -0x1.ffffffffffffd0p61,
    -0x1.ffffffffffffdp61
  },
  { // Entry 227
    -0.0,
    -0x1.00000000000030p63,
    -0x1.0000000000003p63
  },
  { // Entry 228
    -0.0,
    -0x1.00000000000020p63,
    -0x1.0000000000002p63
  },
  { // Entry 229
    -0.0,
    -0x1.00000000000010p63,
    -0x1.0000000000001p63
  },
  { // Entry 230
    -0.0,
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 231
    -0.0,
    -0x1.fffffffffffff0p62,
    -0x1.fffffffffffffp62
  },
  { // Entry 232
    -0.0,
    -0x1.ffffffffffffe0p62,
    -0x1.ffffffffffffep62
  },
  { // Entry 233
    -0.0,
    -0x1.ffffffffffffd0p62,
    -0x1.ffffffffffffdp62
  },
  { // Entry 234
    -0.0,
    -0x1.00000000000030p64,
    -0x1.0000000000003p64
  },
  { // Entry 235
    -0.0,
    -0x1.00000000000020p64,
    -0x1.0000000000002p64
  },
  { // Entry 236
    -0.0,
    -0x1.00000000000010p64,
    -0x1.0000000000001p64
  },
  { // Entry 237
    -0.0,
    -0x1.p64,
    -0x1.0p64
  },
  { // Entry 238
    -0.0,
    -0x1.fffffffffffff0p63,
    -0x1.fffffffffffffp63
  },
  { // Entry 239
    -0.0,
    -0x1.ffffffffffffe0p63,
    -0x1.ffffffffffffep63
  },
  { // Entry 240
    -0.0,
    -0x1.ffffffffffffd0p63,
    -0x1.ffffffffffffdp63
  },
  { // Entry 241
    0.0,
    0x1.p62,
    0x1.0p62
  },
  { // Entry 242
    0.0,
    0x1.40p62,
    0x1.4p62
  },
  { // Entry 243
    0.0,
    0x1.80p62,
    0x1.8p62
  },
  { // Entry 244
    0.0,
    0x1.c0p62,
    0x1.cp62
  },
  { // Entry 245
    0.0,
    0x1.p63,
    0x1.0p63
  },
  { // Entry 246
    0.0,
    0x1.p63,
    0x1.0p63
  },
  { // Entry 247
    0.0,
    0x1.40p63,
    0x1.4p63
  },
  { // Entry 248
    0.0,
    0x1.80p63,
    0x1.8p63
  },
  { // Entry 249
    0.0,
    0x1.c0p63,
    0x1.cp63
  },
  { // Entry 250
    0.0,
    0x1.p64,
    0x1.0p64
  },
  { // Entry 251
    -0.0,
    -0x1.p62,
    -0x1.0p62
  },
  { // Entry 252
    -0.0,
    -0x1.40p62,
    -0x1.4p62
  },
  { // Entry 253
    -0.0,
    -0x1.80p62,
    -0x1.8p62
  },
  { // Entry 254
    -0.0,
    -0x1.c0p62,
    -0x1.cp62
  },
  { // Entry 255
    -0.0,
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 256
    -0.0,
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 257
    -0.0,
    -0x1.40p63,
    -0x1.4p63
  },
  { // Entry 258
    -0.0,
    -0x1.80p63,
    -0x1.8p63
  },
  { // Entry 259
    -0.0,
    -0x1.c0p63,
    -0x1.cp63
  },
  { // Entry 260
    -0.0,
    -0x1.p64,
    -0x1.0p64
  },
  { // Entry 261
    0x1.fffff8p-1,
    0x1.fffffff8p30,
    0x1.fffffffbfffffp30
  },
  { // Entry 262
    0.0,
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 263
    0x1.p-22,
    0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 264
    -0x1.p-21,
    -0x1.p31,
    -0x1.0000000000001p31
  },
  { // Entry 265
    -0.0,
    -0x1.p31,
    -0x1.0p31
  },
  { // Entry 266
    -0x1.fffff8p-1,
    -0x1.fffffffcp30,
    -0x1.fffffffffffffp30
  },
  { // Entry 267
    0x1.ffffffffffffc0p-1,
    0x1.80p1,
    0x1.fffffffffffffp1
  },
  { // Entry 268
    0.0,
    0x1.p2,
    0x1.0p2
  },
  { // Entry 269
    0x1.p-50,
    0x1.p2,
    0x1.0000000000001p2
  },
  { // Entry 270
    0x1.ffffffffffff80p-1,
    0x1.c0p2,
    0x1.fffffffffffffp2
  },
  { // Entry 271
    0.0,
    0x1.p3,
    0x1.0p3
  },
  { // Entry 272
    0x1.p-49,
    0x1.p3,
    0x1.0000000000001p3
  },
  { // Entry 273
    0x1.ffffffffffffp-1,
    0x1.e0p3,
    0x1.fffffffffffffp3
  },
  { // Entry 274
    0.0,
    0x1.p4,
    0x1.0p4
  },
  { // Entry 275
    0x1.p-48,
    0x1.p4,
    0x1.0000000000001p4
  },
  { // Entry 276
    0x1.fffffffffffep-1,
    0x1.f0p4,
    0x1.fffffffffffffp4
  },
  { // Entry 277
    0.0,
    0x1.p5,
    0x1.0p5
  },
  { // Entry 278
    0x1.p-47,
    0x1.p5,
    0x1.0000000000001p5
  },
  { // Entry 279
    0x1.fffffffffffcp-1,
    0x1.f8p5,
    0x1.fffffffffffffp5
  },
  { // Entry 280
    0.0,
    0x1.p6,
    0x1.0p6
  },
  { // Entry 281
    0x1.p-46,
    0x1.p6,
    0x1.0000000000001p6
  },
  { // Entry 282
    0x1.fffffffffff8p-1,
    0x1.fcp6,
    0x1.fffffffffffffp6
  },
  { // Entry 283
    0.0,
    0x1.p7,
    0x1.0p7
  },
  { // Entry 284
    0x1.p-45,
    0x1.p7,
    0x1.0000000000001p7
  },
  { // Entry 285
    0x1.fffffffffff0p-1,
    0x1.fep7,
    0x1.fffffffffffffp7
  },
  { // Entry 286
    0.0,
    0x1.p8,
    0x1.0p8
  },
  { // Entry 287
    0x1.p-44,
    0x1.p8,
    0x1.0000000000001p8
  },
  { // Entry 288
    0x1.ffffffffffe0p-1,
    0x1.ffp8,
    0x1.fffffffffffffp8
  },
  { // Entry 289
    0.0,
    0x1.p9,
    0x1.0p9
  },
  { // Entry 290
    0x1.p-43,
    0x1.p9,
    0x1.0000000000001p9
  },
  { // Entry 291
    0x1.ffffffffffc0p-1,
    0x1.ff80p9,
    0x1.fffffffffffffp9
  },
  { // Entry 292
    0.0,
    0x1.p10,
    0x1.0p10
  },
  { // Entry 293
    0x1.p-42,
    0x1.p10,
    0x1.0000000000001p10
  },
  { // Entry 294
    0x1.ffffffffff80p-1,
    0x1.ffc0p10,
    0x1.fffffffffffffp10
  },
  { // Entry 295
    0.0,
    0x1.p11,
    0x1.0p11
  },
  { // Entry 296
    0x1.p-41,
    0x1.p11,
    0x1.0000000000001p11
  },
  { // Entry 297
    0x1.ffffffffffp-1,
    0x1.ffe0p11,
    0x1.fffffffffffffp11
  },
  { // Entry 298
    0.0,
    0x1.p12,
    0x1.0p12
  },
  { // Entry 299
    0x1.p-40,
    0x1.p12,
    0x1.0000000000001p12
  },
  { // Entry 300
    0x1.ffffffffffffp-2,
    0x1.p2,
    0x1.1ffffffffffffp2
  },
  { // Entry 301
    0x1.p-1,
    0x1.p2,
    0x1.2p2
  },
  { // Entry 302
    0x1.00000000000080p-1,
    0x1.p2,
    0x1.2000000000001p2
  },
  { // Entry 303
    0x1.fffffffffffep-2,
    0x1.p3,
    0x1.0ffffffffffffp3
  },
  { // Entry 304
    0x1.p-1,
    0x1.p3,
    0x1.1p3
  },
  { // Entry 305
    0x1.000000000001p-1,
    0x1.p3,
    0x1.1000000000001p3
  },
  { // Entry 306
    0x1.fffffffffffcp-2,
    0x1.p4,
    0x1.07fffffffffffp4
  },
  { // Entry 307
    0x1.p-1,
    0x1.p4,
    0x1.080p4
  },
  { // Entry 308
    0x1.000000000002p-1,
    0x1.p4,
    0x1.0800000000001p4
  },
  { // Entry 309
    0x1.fffffffffff8p-2,
    0x1.p5,
    0x1.03fffffffffffp5
  },
  { // Entry 310
    0x1.p-1,
    0x1.p5,
    0x1.040p5
  },
  { // Entry 311
    0x1.000000000004p-1,
    0x1.p5,
    0x1.0400000000001p5
  },
  { // Entry 312
    0x1.fffffffffff0p-2,
    0x1.p6,
    0x1.01fffffffffffp6
  },
  { // Entry 313
    0x1.p-1,
    0x1.p6,
    0x1.020p6
  },
  { // Entry 314
    0x1.000000000008p-1,
    0x1.p6,
    0x1.0200000000001p6
  },
  { // Entry 315
    0x1.ffffffffffe0p-2,
    0x1.p7,
    0x1.00fffffffffffp7
  },
  { // Entry 316
    0x1.p-1,
    0x1.p7,
    0x1.010p7
  },
  { // Entry 317
    0x1.000000000010p-1,
    0x1.p7,
    0x1.0100000000001p7
  },
  { // Entry 318
    0x1.ffffffffffc0p-2,
    0x1.p8,
    0x1.007ffffffffffp8
  },
  { // Entry 319
    0x1.p-1,
    0x1.p8,
    0x1.008p8
  },
  { // Entry 320
    0x1.000000000020p-1,
    0x1.p8,
    0x1.0080000000001p8
  },
  { // Entry 321
    0x1.ffffffffff80p-2,
    0x1.p9,
    0x1.003ffffffffffp9
  },
  { // Entry 322
    0x1.p-1,
    0x1.p9,
    0x1.004p9
  },
  { // Entry 323
    0x1.000000000040p-1,
    0x1.p9,
    0x1.0040000000001p9
  },
  { // Entry 324
    0x1.ffffffffffp-2,
    0x1.p10,
    0x1.001ffffffffffp10
  },
  { // Entry 325
    0x1.p-1,
    0x1.p10,
    0x1.002p10
  },
  { // Entry 326
    0x1.000000000080p-1,
    0x1.p10,
    0x1.0020000000001p10
  },
  { // Entry 327
    0x1.ffffffffffp-2,
    0x1.0040p10,
    0x1.005ffffffffffp10
  },
  { // Entry 328
    0x1.p-1,
    0x1.0040p10,
    0x1.006p10
  },
  { // Entry 329
    0x1.000000000080p-1,
    0x1.0040p10,
    0x1.0060000000001p10
  },
  { // Entry 330
    0x1.fffffffffep-2,
    0x1.p11,
    0x1.000ffffffffffp11
  },
  { // Entry 331
    0x1.p-1,
    0x1.p11,
    0x1.001p11
  },
  { // Entry 332
    0x1.0000000001p-1,
    0x1.p11,
    0x1.0010000000001p11
  },
  { // Entry 333
    0x1.fffffffffcp-2,
    0x1.p12,
    0x1.0007fffffffffp12
  },
  { // Entry 334
    0x1.p-1,
    0x1.p12,
    0x1.00080p12
  },
  { // Entry 335
    0x1.0000000002p-1,
    0x1.p12,
    0x1.0008000000001p12
  },
  { // Entry 336
    0.0,
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 337
    -0.0,
    -HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 338
    0.0,
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 339
    -0.0,
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 340
    0.0,
    0x1.ffffffffffffe0p1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 341
    -0.0,
    -0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 342
    0x1.21fb54442d18p-3,
    0x1.80p1,
    0x1.921fb54442d18p1
  },
  { // Entry 343
    -0x1.21fb54442d18p-3,
    -0x1.80p1,
    -0x1.921fb54442d18p1
  },
  { // Entry 344
    0x1.243f6a8885a3p-1,
    0x1.p0,
    0x1.921fb54442d18p0
  },
  { // Entry 345
    -0x1.243f6a8885a3p-1,
    -0x1.p0,
    -0x1.921fb54442d18p0
  },
  { // Entry 346
    0x1.p-52,
    0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 347
    -0x1.p-52,
    -0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 348
    0.0,
    0x1.p0,
    0x1.0p0
  },
  { // Entry 349
    -0.0,
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 350
    0x1.fffffffffffff0p-1,
    0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 351
    -0x1.fffffffffffff0p-1,
    -0.0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 352
    0x1.921fb54442d180p-1,
    0.0,
    0x1.921fb54442d18p-1
  },
  { // Entry 353
    -0x1.921fb54442d180p-1,
    -0.0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 354
    0x1.00000000000010p-1022,
    0.0,
    0x1.0000000000001p-1022
  },
  { // Entry 355
    -0x1.00000000000010p-1022,
    -0.0,
    -0x1.0000000000001p-1022
  },
  { // Entry 356
    0x1.p-1022,
    0.0,
    0x1.0p-1022
  },
  { // Entry 357
    -0x1.p-1022,
    -0.0,
    -0x1.0p-1022
  },
  { // Entry 358
    0x1.ffffffffffffe0p-1023,
    0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 359
    -0x1.ffffffffffffe0p-1023,
    -0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 360
    0x1.ffffffffffffc0p-1023,
    0.0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 361
    -0x1.ffffffffffffc0p-1023,
    -0.0,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 362
    0x1.p-1073,
    0.0,
    0x1.0p-1073
  },
  { // Entry 363
    -0x1.p-1073,
    -0.0,
    -0x1.0p-1073
  },
  { // Entry 364
    0x1.p-1074,
    0.0,
    0x1.0p-1074
  },
  { // Entry 365
    -0x1.p-1074,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 366
    0.0,
    0.0,
    0.0
  },
  { // Entry 367
    -0.0,
    -0.0,
    -0.0
  }
};

"""

```
Response:
Let's break down the thought process for answering the request about `ilogbf_intel_data.handroid`.

1. **Understand the Core Question:** The user wants to understand the purpose and functionality of this specific file within the broader context of Android's Bionic library.

2. **Identify the File Type and Location:** The path `bionic/tests/math_data/ilogbf_intel_data.handroid` clearly indicates this is a *test data file*. The `math_data` directory suggests it's related to mathematical functions. The `.handroid` extension is a clue that it's specific to Android's testing infrastructure.

3. **Analyze the File Content:** The file contains an array `g_ilogbf_intel_data` of a custom type `data_int_1_t<float>`. Each element in the array is a struct (or class) containing an `int` and a `float`. The hexadecimal floating-point notation (e.g., `0x1.90p6`) is a key indicator that these are specific test cases for floating-point operations.

4. **Infer the Purpose:** Given the file name and content, the primary function is to provide **test data** for the `ilogbf` function. The `_intel_data` part might suggest it's designed to test specific behavior or edge cases related to Intel architectures or perhaps specific implementation details of `ilogbf`.

5. **Connect to `ilogbf` Function:**  The name `ilogbf` is a standard C library function. Recall or look up its definition: it returns the integer binary logarithm of the absolute value of a floating-point number. The test data likely provides input `float` values and the corresponding expected `int` result.

6. **Relate to Android:**  Bionic is Android's standard C library. Therefore, this test data is used to verify the correctness of Bionic's implementation of `ilogbf`. This is crucial for ensuring the reliability of applications using math functions on Android.

7. **Address Each Part of the Request:**  Now, go through each specific question in the prompt:

    * **功能列举:** Focus on the core purpose: providing test data for `ilogbf`. Mention the input and expected output format.
    * **与 Android 功能的关系:** Explain that Bionic *is* Android's C library and that this data validates its math functions.
    * **libc 函数的功能实现 (ilogbf):** Explain what `ilogbf` does mathematically. While the *implementation details* aren't in this data file, explain the *purpose* of the function. Acknowledge the platform-specific nature of the implementation.
    * **Dynamic Linker 功能:**  The provided file *doesn't* directly involve the dynamic linker. State this clearly. Provide a *general* explanation of the dynamic linker's role and an example SO layout and linking process, even though it's not directly relevant to *this specific file*. This demonstrates broader knowledge of Bionic.
    * **逻辑推理 (假设输入/输出):**  Pick a few entries from the data and explain how the input `float` would map to the output `int` according to the definition of `ilogbf`.
    * **常见使用错误:** Think about how developers might misuse `ilogbf` (e.g., passing NaN, infinity, zero). Explain the expected behavior in these cases.
    * **Android Framework/NDK 到达这里:** Explain the typical path: App calls a math function, which links to Bionic. Bionic's tests (including those using this data) are part of its development and validation.
    * **Frida Hook 示例:** Provide a basic Frida hook example that could intercept calls to `ilogbf` to demonstrate how to interact with this function at runtime. Crucially, point out that hooking the *test data* itself isn't usually the goal; you'd hook the *function*.

8. **Structure and Language:** Organize the answer logically with clear headings. Use precise and accurate Chinese terminology. Provide enough detail to be informative but avoid unnecessary jargon.

9. **Review and Refine:**  Read through the answer to ensure it's accurate, complete, and addresses all parts of the prompt. Check for clarity and conciseness. For instance, initially, I might have focused too much on the "intel" part of the filename. But the data structure and the overall context strongly suggest its primary function is general `ilogbf` testing, perhaps with some focus on Intel-specific cases. The answer should reflect this balance.

By following this thought process, we can generate a comprehensive and accurate answer that addresses the user's request effectively.
这个文件 `bionic/tests/math_data/ilogbf_intel_data.handroid` 是 Android Bionic 库中用于测试 `ilogbf` 函数的数据文件。Bionic 是 Android 的 C 库，提供了诸如标准 C 库函数、数学库函数以及动态链接器等核心功能。

**功能列举:**

这个文件的主要功能是提供一系列预定义的输入值和对应的预期输出值，用于测试 `ilogbf` 函数在特定平台（可能是 Intel 架构，但更可能指代一种测试配置）上的实现是否正确。具体来说，它包含一个名为 `g_ilogbf_intel_data` 的数组，数组中的每个元素都包含了以下信息：

* **预期输出 (int):**  对 `ilogbf` 函数输入特定浮点数后，预期的整数返回值。这个返回值表示输入浮点数的绝对值的以 2 为底的指数。
* **输入值 (float):** 作为 `ilogbf` 函数的输入参数的浮点数。

**与 Android 功能的关系：**

这个文件直接关系到 Android 系统的稳定性和正确性。`ilogbf` 是一个标准的 C 库数学函数，用于获取浮点数的指数部分。许多 Android 系统服务、应用程序以及 NDK 开发的 native 代码都可能依赖于这个函数进行数值计算。

举例说明：

* **图形渲染：** 图形引擎可能使用浮点数来表示坐标、颜色等信息，并可能需要使用 `ilogbf` 来进行某些精度相关的计算或优化。
* **音频处理：** 音频编解码器和处理算法中也常常涉及到浮点数运算，`ilogbf` 可能用于分析音频信号的动态范围。
* **传感器数据处理：**  从加速度计、陀螺仪等传感器获取的数据通常以浮点数形式表示，对这些数据进行归一化或分析时可能用到 `ilogbf`。

**详细解释 libc 函数的功能是如何实现的 (以 `ilogbf` 为例)：**

`ilogbf(float x)` 函数的功能是计算浮点数 `x` 的绝对值的以 2 为底的指数。更精确地说，如果 `|x|` 可以表示为 `mantissa * 2^exponent`，其中 `1 <= mantissa < 2`，那么 `ilogbf(x)` 的返回值就是 `exponent`。

`ilogbf` 的实现通常依赖于底层硬件的浮点数表示方式（IEEE 754 标准）。其实现步骤大致如下：

1. **处理特殊情况：**
   * 如果 `x` 是 0，`ilogbf(x)` 的返回值通常是 `FP_ILOGB0`（定义在 `<math.h>` 中，通常是一个很大的负数，例如 `INT_MIN`），并且可能会触发浮点异常。
   * 如果 `x` 是无穷大（Infinity），`ilogbf(x)` 的返回值通常是 `FP_ILOGBNAN`（定义在 `<math.h>` 中，通常是一个很大的正数，例如 `INT_MAX`）。
   * 如果 `x` 是 NaN（Not a Number），`ilogbf(x)` 的返回值也是 `FP_ILOGBNAN`。

2. **获取浮点数的指数部分：**
   * 对于非特殊情况的浮点数，`ilogbf` 的实现通常会直接访问浮点数在内存中的二进制表示，提取出表示指数的位字段。IEEE 754 标准规定了浮点数的存储格式，其中一部分位用于存储指数。
   * 为了避免直接操作内存，一些实现可能会使用联合体 (union) 来访问浮点数的各个组成部分，或者使用位运算来提取指数位。

3. **处理非规范化数 (Subnormal numbers)：**
   * 非规范化数的指数位全部为 0。对于这些数，`ilogbf` 需要进行特殊处理，通常会返回最小的规范化指数减去一个偏移量。

4. **返回指数值：**
   * 将提取出的指数值（可能需要进行一些调整）作为 `int` 类型返回。

**对于涉及 dynamic linker 的功能：**

这个特定的数据文件 `ilogbf_intel_data.handroid` **不直接涉及** dynamic linker 的功能。它的作用是为 `ilogbf` 函数的测试提供数据。动态链接器负责在程序运行时加载和链接共享库（.so 文件）。

**如果 `ilogbf` 函数本身位于一个共享库中，那么动态链接器会参与加载这个库并解析对 `ilogbf` 的调用。**

**SO 布局样本：**

假设 `ilogbf` 函数实现在 `libm.so` (数学库) 中，一个典型的 SO 布局可能如下：

```
libm.so:
    .text          # 存放代码段
        ...
        ilogbf:    # ilogbf 函数的实现代码
            ...
        ...
    .data          # 存放已初始化的全局变量
        ...
    .bss           # 存放未初始化的全局变量
        ...
    .dynsym        # 动态符号表 (包含导出的和导入的符号)
        ...
        ilogbf      # 导出的 ilogbf 符号
        ...
    .dynstr        # 动态字符串表 (存储符号名称等字符串)
        ...
        ilogbf
        ...
    .plt           # 程序链接表 (用于延迟绑定)
        ...
    .got.plt       # 全局偏移表 (用于存储外部符号的地址)
        ...
```

**链接的处理过程：**

1. **编译时：** 当应用程序或共享库的代码中调用了 `ilogbf` 函数时，编译器会生成一个对 `ilogbf` 的未解析引用。
2. **链接时：** 静态链接器会在编译时将应用程序需要的一些库链接在一起。对于共享库，只会记录对外部符号的引用。
3. **运行时：** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载应用程序依赖的共享库。
4. **加载共享库：** 动态链接器会读取应用程序的 ELF 头信息，找到其依赖的共享库列表，并加载这些库到内存中。
5. **符号解析：** 动态链接器会遍历加载的共享库的动态符号表 (`.dynsym`)，查找应用程序中未解析的符号。当找到与应用程序中 `ilogbf` 调用匹配的符号时，动态链接器会将 `ilogbf` 在 `libm.so` 中的实际地址写入到全局偏移表 (`.got.plt`) 中对应的条目。
6. **延迟绑定 (Lazy Binding)：**  通常，为了提高启动速度，符号解析采用延迟绑定的方式。最初，`ilogbf` 的 `.got.plt` 条目指向 `.plt` 中的一段代码。当第一次调用 `ilogbf` 时，会跳转到 `.plt` 中的代码，该代码会调用动态链接器的解析函数来解析 `ilogbf` 的地址，并更新 `.got.plt`。后续对 `ilogbf` 的调用将直接通过 `.got.plt` 跳转到 `libm.so` 中 `ilogbf` 的实际地址。

**逻辑推理（假设输入与输出）：**

让我们看几个 `ilogbf_intel_data.handroid` 中的例子：

* **输入:** `0x1.90p6` (浮点数表示：1.5625 * 2^6 = 100)
   **输出:** `0x1.p100` (整数表示：100)。 逻辑：`ilogbf(100)` 应该返回 6 (因为 100 大约是 2^6)。 **注意：这里的数据似乎有误解，`ilogbf` 返回的是指数部分，而不是乘以 2 的幂后的值。 对于输入 `0x1.90p6`，其指数部分是 6，所以预期输出应该是 6，而不是 100。**

* **输入:** `0x1.p100` (浮点数表示：1 * 2^100)
   **输出:** `(int)0x1.90p6` (整数表示：6)。 逻辑：`ilogbf(2^100)` 应该返回 100。 **同样，这里的数据含义需要更仔细理解。 预期输出是针对 `ilogbf` 的返回值，即输入浮点数的指数部分。**

**更正的逻辑推理：**

`data_int_1_t<float>` 的结构表明，第一个成员是 `ilogbf` 的预期返回值 (int)，第二个成员是 `ilogbf` 的输入参数 (float)。

* **Entry 0:**
    * **输入:** `0x1.p100` (2^100)
    * **预期输出:** `(int)0x1.90p6` (十进制 6)。 逻辑：`ilogbf(2^100)` 应该返回 100。 **这里预期输出的 0x1.90p6 看起来像是对浮点数的十六进制表示，但它被转换为 int，这可能是测试框架的一种表示方式，表示整数 6。**

* **Entry 11:**
    * **输入:** `-0x1.p101` (-2^101)
    * **预期输出:** `(int)0x1.94p6` (十进制 6)。 逻辑：`ilogbf(-2^101)` 应该返回 101。 **同样，预期输出 0x1.94p6 可能表示整数 6。**

**假设输入与输出的正确解释：**

数组中的每个元素定义了一个测试用例，结构如下：

```c++
{ // Entry N
  (int)expected_ilogbf_result,
  input_float_value
}
```

所以，对于 Entry 0：

* **输入 (float):** `0x1.p100` (表示浮点数 2<sup>100</sup>)
* **预期输出 (int):** `(int)0x1.90p6`  (这里 `0x1.90p6` 作为一个 `int` 被解释，它的值是 6)。  这意味着，当输入是 2<sup>100</sup> 时，`ilogbf` 应该返回 100。 **注意：这里仍然存在歧义，预期输出看起来像是对整数的浮点数表示，但类型是 `int`。 最可能的解释是测试框架使用这种方式来表示整数值。**

**结论：`ilogbf_intel_data.handroid` 存储的是 `ilogbf` 函数的输入浮点数及其对应的预期整数返回值。**

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **输入为零：**
   ```c
   #include <math.h>
   #include <stdio.h>
   #include <float.h>

   int main() {
       float x = 0.0f;
       int result = ilogbf(x);
       printf("ilogbf(%f) = %d\n", x, result); // 输出可能是 INT_MIN
       return 0;
   }
   ```
   **错误原因：** `ilogbf` 对 0 的行为是未定义的或者返回一个特定的错误值。用户可能没有考虑到输入为 0 的情况。

2. **输入为 NaN 或无穷大：**
   ```c
   #include <math.h>
   #include <stdio.h>
   #include <float.h>

   int main() {
       float nan_val = NAN;
       float inf_val = INFINITY;
       printf("ilogbf(NaN) = %d\n", ilogbf(nan_val)); // 输出可能是 FP_ILOGBNAN
       printf("ilogbf(Inf) = %d\n", ilogbf(inf_val)); // 输出可能是 FP_ILOGBNAN
       return 0;
   }
   ```
   **错误原因：**  `ilogbf` 对 NaN 和无穷大的行为是返回特定的值，用户可能没有正确处理这些特殊情况。

3. **忽略返回值可能为特殊值：** 用户可能假设 `ilogbf` 总是返回一个正常的整数指数，而没有检查返回值是否为 `FP_ILOGB0` 或 `FP_ILOGBNAN`。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用数学函数：**
   * **Framework:**  例如，一个图形相关的系统服务可能在计算过程中调用了 `powf` 函数，而 `powf` 的实现内部可能依赖于其他数学函数，或者在某些优化的路径上可能会使用到与指数相关的操作。
   * **NDK:**  开发者使用 NDK 编写的 native 代码可以直接调用 Bionic 提供的数学函数，例如 `ilogbf`。

2. **链接到 Bionic 库：**
   * **Framework:**  系统服务通常链接到 Bionic 提供的共享库，如 `libc.so` 或 `libm.so`。
   * **NDK:**  NDK 构建系统会将 native 代码链接到 Bionic 提供的共享库。

3. **调用 `ilogbf` 函数：**  当程序执行到调用 `ilogbf` 的代码时，会跳转到 `libm.so` 中 `ilogbf` 的实现。

4. **测试数据的使用：**  `ilogbf_intel_data.handroid` 这个文件主要用于 **Bionic 库的单元测试**。在 Bionic 的开发过程中，测试框架会读取这个文件，将输入值传递给 `ilogbf` 函数，并比较函数的返回值与文件中预期的输出值，以验证 `ilogbf` 函数的实现是否正确。 **应用程序运行时不会直接读取这个数据文件。**

**Frida Hook 示例：**

可以使用 Frida 来 hook `ilogbf` 函数的调用，观察其输入和输出。

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const ilogbf = Module.findExportByName("libm.so", "ilogbf");

  if (ilogbf) {
    Interceptor.attach(ilogbf, {
      onEnter: function (args) {
        const input = args[0].readFloat();
        console.log("[ilogbf] Input:", input);
      },
      onLeave: function (retval) {
        const output = retval.toInt32();
        console.log("[ilogbf] Output:", output);
      }
    });
    console.log("Attached to ilogbf");
  } else {
    console.error("ilogbf not found in libm.so");
  }
} else {
  console.log("Frida hook for ilogbf is only supported on ARM/ARM64");
}
```

**使用步骤：**

1. 将上述 JavaScript 代码保存为 `hook_ilogbf.js`。
2. 找到你想要调试的 Android 进程的进程 ID (PID)。
3. 使用 Frida 命令连接到目标进程并执行 hook 脚本：
   ```bash
   frida -U -f <package_name> -l hook_ilogbf.js --no-pause
   # 或者如果进程已经在运行
   frida -U <package_name_or_pid> -l hook_ilogbf.js
   ```
   将 `<package_name>` 替换为目标应用的包名。

**Frida Hook 的作用：**

当目标应用执行到调用 `ilogbf` 函数的代码时，Frida hook 会拦截这次调用，打印出 `ilogbf` 函数的输入浮点数和返回值，从而帮助你理解 `ilogbf` 在实际运行时的行为。

**总结：**

`ilogbf_intel_data.handroid` 是 Bionic 库中用于测试 `ilogbf` 函数的测试数据文件。它定义了一系列输入输出对，用于验证 `ilogbf` 函数在特定平台上的实现是否符合预期。这个文件在 Bionic 的开发和测试过程中起着重要的作用，确保了 Android 系统底层数学运算的正确性。 应用程序在运行时不会直接使用这个数据文件，但其正确性直接影响到依赖 `ilogbf` 函数的上层应用和服务的稳定性。

### 提示词
```
这是目录为bionic/tests/math_data/ilogbf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_int_1_t<float> g_ilogbf_intel_data[] = {
  { // Entry 0
    (int)0x1.90p6,
    0x1.p100
  },
  { // Entry 1
    (int)0x1.90p6,
    0x1.19999ap100
  },
  { // Entry 2
    (int)0x1.90p6,
    0x1.333334p100
  },
  { // Entry 3
    (int)0x1.90p6,
    0x1.4ccccep100
  },
  { // Entry 4
    (int)0x1.90p6,
    0x1.666668p100
  },
  { // Entry 5
    (int)0x1.90p6,
    0x1.800002p100
  },
  { // Entry 6
    (int)0x1.90p6,
    0x1.99999cp100
  },
  { // Entry 7
    (int)0x1.90p6,
    0x1.b33336p100
  },
  { // Entry 8
    (int)0x1.90p6,
    0x1.ccccd0p100
  },
  { // Entry 9
    (int)0x1.90p6,
    0x1.e6666ap100
  },
  { // Entry 10
    (int)0x1.94p6,
    0x1.p101
  },
  { // Entry 11
    (int)0x1.94p6,
    -0x1.p101
  },
  { // Entry 12
    (int)0x1.90p6,
    -0x1.e66666p100
  },
  { // Entry 13
    (int)0x1.90p6,
    -0x1.ccccccp100
  },
  { // Entry 14
    (int)0x1.90p6,
    -0x1.b33332p100
  },
  { // Entry 15
    (int)0x1.90p6,
    -0x1.999998p100
  },
  { // Entry 16
    (int)0x1.90p6,
    -0x1.7ffffep100
  },
  { // Entry 17
    (int)0x1.90p6,
    -0x1.666664p100
  },
  { // Entry 18
    (int)0x1.90p6,
    -0x1.4ccccap100
  },
  { // Entry 19
    (int)0x1.90p6,
    -0x1.333330p100
  },
  { // Entry 20
    (int)0x1.90p6,
    -0x1.199996p100
  },
  { // Entry 21
    (int)0x1.90p6,
    -0x1.p100
  },
  { // Entry 22
    (int)0x1.50p4,
    0x1.p21
  },
  { // Entry 23
    (int)0x1.50p4,
    0x1.19999ap21
  },
  { // Entry 24
    (int)0x1.50p4,
    0x1.333334p21
  },
  { // Entry 25
    (int)0x1.50p4,
    0x1.4ccccep21
  },
  { // Entry 26
    (int)0x1.50p4,
    0x1.666668p21
  },
  { // Entry 27
    (int)0x1.50p4,
    0x1.800002p21
  },
  { // Entry 28
    (int)0x1.50p4,
    0x1.99999cp21
  },
  { // Entry 29
    (int)0x1.50p4,
    0x1.b33336p21
  },
  { // Entry 30
    (int)0x1.50p4,
    0x1.ccccd0p21
  },
  { // Entry 31
    (int)0x1.50p4,
    0x1.e6666ap21
  },
  { // Entry 32
    (int)0x1.60p4,
    0x1.p22
  },
  { // Entry 33
    (int)0x1.60p4,
    0x1.p22
  },
  { // Entry 34
    (int)0x1.60p4,
    0x1.19999ap22
  },
  { // Entry 35
    (int)0x1.60p4,
    0x1.333334p22
  },
  { // Entry 36
    (int)0x1.60p4,
    0x1.4ccccep22
  },
  { // Entry 37
    (int)0x1.60p4,
    0x1.666668p22
  },
  { // Entry 38
    (int)0x1.60p4,
    0x1.800002p22
  },
  { // Entry 39
    (int)0x1.60p4,
    0x1.99999cp22
  },
  { // Entry 40
    (int)0x1.60p4,
    0x1.b33336p22
  },
  { // Entry 41
    (int)0x1.60p4,
    0x1.ccccd0p22
  },
  { // Entry 42
    (int)0x1.60p4,
    0x1.e6666ap22
  },
  { // Entry 43
    (int)0x1.70p4,
    0x1.p23
  },
  { // Entry 44
    (int)0x1.70p4,
    0x1.p23
  },
  { // Entry 45
    (int)0x1.70p4,
    0x1.19999ap23
  },
  { // Entry 46
    (int)0x1.70p4,
    0x1.333334p23
  },
  { // Entry 47
    (int)0x1.70p4,
    0x1.4ccccep23
  },
  { // Entry 48
    (int)0x1.70p4,
    0x1.666668p23
  },
  { // Entry 49
    (int)0x1.70p4,
    0x1.800002p23
  },
  { // Entry 50
    (int)0x1.70p4,
    0x1.99999cp23
  },
  { // Entry 51
    (int)0x1.70p4,
    0x1.b33336p23
  },
  { // Entry 52
    (int)0x1.70p4,
    0x1.ccccd0p23
  },
  { // Entry 53
    (int)0x1.70p4,
    0x1.e6666ap23
  },
  { // Entry 54
    (int)0x1.80p4,
    0x1.p24
  },
  { // Entry 55
    (int)0x1.80p4,
    0x1.p24
  },
  { // Entry 56
    (int)0x1.80p4,
    0x1.19999ap24
  },
  { // Entry 57
    (int)0x1.80p4,
    0x1.333334p24
  },
  { // Entry 58
    (int)0x1.80p4,
    0x1.4ccccep24
  },
  { // Entry 59
    (int)0x1.80p4,
    0x1.666668p24
  },
  { // Entry 60
    (int)0x1.80p4,
    0x1.800002p24
  },
  { // Entry 61
    (int)0x1.80p4,
    0x1.99999cp24
  },
  { // Entry 62
    (int)0x1.80p4,
    0x1.b33336p24
  },
  { // Entry 63
    (int)0x1.80p4,
    0x1.ccccd0p24
  },
  { // Entry 64
    (int)0x1.80p4,
    0x1.e6666ap24
  },
  { // Entry 65
    (int)0x1.90p4,
    0x1.p25
  },
  { // Entry 66
    (int)-0x1.04p7,
    0x1.p-130
  },
  { // Entry 67
    (int)-0x1.p7,
    0x1.d33330p-128
  },
  { // Entry 68
    (int)-0x1.fcp6,
    0x1.b33330p-127
  },
  { // Entry 69
    (int)-0x1.f8p6,
    0x1.3e6664p-126
  },
  { // Entry 70
    (int)-0x1.f8p6,
    0x1.a33330p-126
  },
  { // Entry 71
    (int)-0x1.f4p6,
    0x1.03fffep-125
  },
  { // Entry 72
    (int)-0x1.f4p6,
    0x1.366664p-125
  },
  { // Entry 73
    (int)-0x1.f4p6,
    0x1.68cccap-125
  },
  { // Entry 74
    (int)-0x1.f4p6,
    0x1.9b3330p-125
  },
  { // Entry 75
    (int)-0x1.f4p6,
    0x1.cd9996p-125
  },
  { // Entry 76
    (int)-0x1.f4p6,
    0x1.fffffcp-125
  },
  { // Entry 77
    (int)0x1.50p4,
    0x1.fffffep21
  },
  { // Entry 78
    (int)0x1.60p4,
    0x1.p22
  },
  { // Entry 79
    (int)0x1.60p4,
    0x1.000002p22
  },
  { // Entry 80
    (int)0x1.60p4,
    0x1.fffffep22
  },
  { // Entry 81
    (int)0x1.70p4,
    0x1.p23
  },
  { // Entry 82
    (int)0x1.70p4,
    0x1.000002p23
  },
  { // Entry 83
    (int)0x1.70p4,
    0x1.fffffep23
  },
  { // Entry 84
    (int)0x1.80p4,
    0x1.p24
  },
  { // Entry 85
    (int)0x1.80p4,
    0x1.000002p24
  },
  { // Entry 86
    (int)0x1.60p4,
    -0x1.000002p22
  },
  { // Entry 87
    (int)0x1.60p4,
    -0x1.p22
  },
  { // Entry 88
    (int)0x1.50p4,
    -0x1.fffffep21
  },
  { // Entry 89
    (int)0x1.70p4,
    -0x1.000002p23
  },
  { // Entry 90
    (int)0x1.70p4,
    -0x1.p23
  },
  { // Entry 91
    (int)0x1.60p4,
    -0x1.fffffep22
  },
  { // Entry 92
    (int)0x1.80p4,
    -0x1.000002p24
  },
  { // Entry 93
    (int)0x1.80p4,
    -0x1.p24
  },
  { // Entry 94
    (int)0x1.70p4,
    -0x1.fffffep23
  },
  { // Entry 95
    (int)0x1.fcp6,
    0x1.fffffep127
  },
  { // Entry 96
    (int)0x1.fcp6,
    -0x1.fffffep127
  },
  { // Entry 97
    (int)-0x1.c0p2,
    0x1.fffffep-7
  },
  { // Entry 98
    (int)-0x1.80p2,
    0x1.p-6
  },
  { // Entry 99
    (int)-0x1.80p2,
    0x1.000002p-6
  },
  { // Entry 100
    (int)-0x1.80p2,
    0x1.fffffep-6
  },
  { // Entry 101
    (int)-0x1.40p2,
    0x1.p-5
  },
  { // Entry 102
    (int)-0x1.40p2,
    0x1.000002p-5
  },
  { // Entry 103
    (int)-0x1.40p2,
    0x1.fffffep-5
  },
  { // Entry 104
    (int)-0x1.p2,
    0x1.p-4
  },
  { // Entry 105
    (int)-0x1.p2,
    0x1.000002p-4
  },
  { // Entry 106
    (int)-0x1.p2,
    0x1.fffffep-4
  },
  { // Entry 107
    (int)-0x1.80p1,
    0x1.p-3
  },
  { // Entry 108
    (int)-0x1.80p1,
    0x1.000002p-3
  },
  { // Entry 109
    (int)-0x1.80p1,
    0x1.fffffep-3
  },
  { // Entry 110
    (int)-0x1.p1,
    0x1.p-2
  },
  { // Entry 111
    (int)-0x1.p1,
    0x1.000002p-2
  },
  { // Entry 112
    (int)-0x1.p1,
    0x1.fffffep-2
  },
  { // Entry 113
    (int)-0x1.p0,
    0x1.p-1
  },
  { // Entry 114
    (int)-0x1.p0,
    0x1.000002p-1
  },
  { // Entry 115
    (int)-0x1.2ap7,
    -0x1.p-149
  },
  { // Entry 116
    (int)-0x1.fffffffcp30,
    0.0
  },
  { // Entry 117
    (int)-0x1.2ap7,
    0x1.p-149
  },
  { // Entry 118
    (int)-0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 119
    (int)0.0,
    0x1.p0
  },
  { // Entry 120
    (int)0.0,
    0x1.000002p0
  },
  { // Entry 121
    (int)0.0,
    0x1.fffffep0
  },
  { // Entry 122
    (int)0x1.p0,
    0x1.p1
  },
  { // Entry 123
    (int)0x1.p0,
    0x1.000002p1
  },
  { // Entry 124
    (int)0x1.p0,
    0x1.fffffep1
  },
  { // Entry 125
    (int)0x1.p1,
    0x1.p2
  },
  { // Entry 126
    (int)0x1.p1,
    0x1.000002p2
  },
  { // Entry 127
    (int)0x1.p1,
    0x1.fffffep2
  },
  { // Entry 128
    (int)0x1.80p1,
    0x1.p3
  },
  { // Entry 129
    (int)0x1.80p1,
    0x1.000002p3
  },
  { // Entry 130
    (int)0x1.80p1,
    0x1.fffffep3
  },
  { // Entry 131
    (int)0x1.p2,
    0x1.p4
  },
  { // Entry 132
    (int)0x1.p2,
    0x1.000002p4
  },
  { // Entry 133
    (int)0x1.p2,
    0x1.fffffep4
  },
  { // Entry 134
    (int)0x1.40p2,
    0x1.p5
  },
  { // Entry 135
    (int)0x1.40p2,
    0x1.000002p5
  },
  { // Entry 136
    (int)0x1.40p2,
    0x1.fffffep5
  },
  { // Entry 137
    (int)0x1.80p2,
    0x1.p6
  },
  { // Entry 138
    (int)0x1.80p2,
    0x1.000002p6
  },
  { // Entry 139
    (int)0x1.80p2,
    0x1.fffffep6
  },
  { // Entry 140
    (int)0x1.c0p2,
    0x1.p7
  },
  { // Entry 141
    (int)0x1.c0p2,
    0x1.000002p7
  },
  { // Entry 142
    (int)0x1.fffffffcp30,
    HUGE_VALF
  },
  { // Entry 143
    (int)0x1.fffffffcp30,
    -HUGE_VALF
  },
  { // Entry 144
    (int)-0x1.fffffffcp30,
    0.0f
  },
  { // Entry 145
    (int)-0x1.fffffffcp30,
    -0.0f
  },
  { // Entry 146
    (int)0x1.fcp6,
    0x1.fffffep127
  },
  { // Entry 147
    (int)0x1.fcp6,
    -0x1.fffffep127
  },
  { // Entry 148
    (int)0x1.fcp6,
    0x1.fffffcp127
  },
  { // Entry 149
    (int)0x1.fcp6,
    -0x1.fffffcp127
  },
  { // Entry 150
    (int)0x1.p0,
    0x1.921fb6p1
  },
  { // Entry 151
    (int)0x1.p0,
    -0x1.921fb6p1
  },
  { // Entry 152
    (int)0.0,
    0x1.921fb6p0
  },
  { // Entry 153
    (int)0.0,
    -0x1.921fb6p0
  },
  { // Entry 154
    (int)0.0,
    0x1.000002p0
  },
  { // Entry 155
    (int)0.0,
    -0x1.000002p0
  },
  { // Entry 156
    (int)0.0,
    0x1.p0
  },
  { // Entry 157
    (int)0.0,
    -0x1.p0
  },
  { // Entry 158
    (int)-0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 159
    (int)-0x1.p0,
    -0x1.fffffep-1
  },
  { // Entry 160
    (int)-0x1.p0,
    0x1.921fb6p-1
  },
  { // Entry 161
    (int)-0x1.p0,
    -0x1.921fb6p-1
  },
  { // Entry 162
    (int)-0x1.f8p6,
    0x1.000002p-126
  },
  { // Entry 163
    (int)-0x1.f8p6,
    -0x1.000002p-126
  },
  { // Entry 164
    (int)-0x1.f8p6,
    0x1.p-126
  },
  { // Entry 165
    (int)-0x1.f8p6,
    -0x1.p-126
  },
  { // Entry 166
    (int)-0x1.fcp6,
    0x1.fffffcp-127
  },
  { // Entry 167
    (int)-0x1.fcp6,
    -0x1.fffffcp-127
  },
  { // Entry 168
    (int)-0x1.fcp6,
    0x1.fffff8p-127
  },
  { // Entry 169
    (int)-0x1.fcp6,
    -0x1.fffff8p-127
  },
  { // Entry 170
    (int)-0x1.28p7,
    0x1.p-148
  },
  { // Entry 171
    (int)-0x1.28p7,
    -0x1.p-148
  },
  { // Entry 172
    (int)-0x1.2ap7,
    0x1.p-149
  },
  { // Entry 173
    (int)-0x1.2ap7,
    -0x1.p-149
  }
};
```
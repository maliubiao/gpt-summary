Response:
Let's break down the thought process for answering the request about `fabs_intel_data.handroid`.

1. **Understanding the Core Question:** The fundamental question is about the *purpose* and *context* of this specific file. It's located in `bionic/tests/math_data/`, suggesting it's related to testing the math library (`bionic`). The filename `fabs_intel_data.handroid` strongly hints it's test data for the `fabs` function, specifically targeting Intel architectures (indicated by "intel_data"). The `.handroid` suffix likely signifies it's used in the Android environment.

2. **Deconstructing the Request:**  The request asks for several things:
    * **Functionality:** What does this file *do*?
    * **Relationship to Android:** How does it fit within the Android ecosystem?
    * **libc Function Details:**  How is `fabs` implemented?
    * **Dynamic Linker (if applicable):** Is the dynamic linker involved, and if so, how?
    * **Logic and Examples:** Provide input/output examples.
    * **Common Errors:**  What mistakes do programmers make?
    * **Android Integration:** How does it get used in the Android framework/NDK?
    * **Frida Hooking:** How can we observe its execution?

3. **Initial Analysis of the File Content:** The file contains a C++ array named `g_fabs_intel_data`. Each element in the array is a structure (likely named `data_1_1_t`) containing two `double` values. The comments indicate "Entry [number]". The values are represented in hexadecimal floating-point notation (e.g., `0x1.p-10`). This format is used to represent floating-point numbers precisely. The presence of both positive and negative input values, along with the corresponding expected positive output, strongly confirms this is test data for `fabs`. The inclusion of special values like `0.0`, `-0.0`, `HUGE_VAL` reinforces this conclusion.

4. **Addressing Each Part of the Request:**

    * **Functionality:** Based on the file content and name, the primary function is to provide test cases for the `fabs()` function within the Android `bionic` math library, specifically for Intel architectures. It aims to cover various input ranges and edge cases.

    * **Relationship to Android:** This file is *part* of the Android operating system's core C library. It ensures the correct implementation of fundamental math functions. Android apps built using the NDK (Native Development Kit) might indirectly use `fabs`. The framework itself uses `bionic`.

    * **libc Function Details (`fabs`):**  `fabs` calculates the absolute value of a floating-point number. The implementation is generally straightforward: check the sign bit of the floating-point representation and clear it if it's set (meaning the number is negative). For special cases like NaN (Not a Number), it typically returns the input unchanged.

    * **Dynamic Linker:** The dynamic linker is *not directly involved* with the *data* in this file. The data is statically linked into the test executable. The dynamic linker is responsible for loading the *code* of the `fabs` function from `libm.so` at runtime. To illustrate the dynamic linker, we need to imagine how `fabs` itself is used, not just the test data. A sample SO layout would show `libm.so` containing the `fabs` implementation. The linking process involves resolving the symbol `fabs` from the application's or a library's import table to the actual address in `libm.so`.

    * **Logic and Examples:** The test data provides the input and expected output. If the input is `-5.0`, the expected output is `5.0`. If the input is `3.14`, the expected output is `3.14`. The hexadecimal notation in the file allows for very precise testing of edge cases.

    * **Common Errors:** Programmers often misuse `fabs` when dealing with comparisons involving floating-point numbers due to precision issues. Directly comparing `fabs(a - b) == 0` is problematic. The correct approach is to use a small tolerance (epsilon).

    * **Android Integration:**  An Android app using the NDK can call `fabs` directly. The NDK provides the necessary header files (`math.h`). The framework uses `fabs` internally for various calculations. The path from an Android framework call or NDK call involves system calls, loading libraries (`libm.so`), and finally executing the `fabs` code.

    * **Frida Hooking:**  Frida allows intercepting function calls. To hook `fabs`, you'd target the `fabs` function in `libm.so`. The Frida script would intercept the call, print the arguments (input value), and the return value (output of `fabs`).

5. **Structuring the Answer:** Organize the information logically, following the order of the request. Use clear headings and bullet points to improve readability. Explain technical terms (like hexadecimal floating-point notation) briefly.

6. **Refinement and Review:**  Read through the answer to ensure accuracy, completeness, and clarity. Are the examples relevant? Is the explanation of the dynamic linker clear in its distinction from the test data itself? Is the Frida example correct?  Make sure to use Chinese as requested.

By following this detailed thought process, we arrive at a comprehensive and accurate answer to the user's request. The key is to understand the nature of the file, break down the request into smaller parts, and then address each part systematically, providing context and examples where needed.
## 对 bionic/tests/math_data/fabs_intel_data.handroid 源代码文件的分析

这个文件 `fabs_intel_data.handroid` 是 Android Bionic 库中用于测试 `fabs` (浮点数绝对值) 函数的数据文件。它包含了一系列预定义的输入和预期输出，用于验证 `fabs` 函数在 Intel 架构上的正确性。

**文件功能:**

1. **提供 `fabs` 函数的测试用例:**  该文件定义了一个名为 `g_fabs_intel_data` 的数组，该数组的每个元素都包含一对 `double` 类型的值。第一个值是 `fabs` 函数的输入，第二个值是期望的输出。
2. **针对 Intel 架构的测试数据:** 文件名中的 `intel_data` 表明这些测试用例可能针对 Intel 处理器的一些特定行为或优化。
3. **自动化测试的一部分:**  这些数据文件通常被用于自动化测试框架，以便快速且重复地验证 `fabs` 函数在各种输入情况下的行为是否符合预期。

**与 Android 功能的关系:**

这个文件直接关系到 Android 的底层数学库 `bionic` 的质量和可靠性。

* **确保 `fabs` 函数的正确性:** `fabs` 是一个基础的数学函数，被 Android 系统和应用程序广泛使用。例如：
    * **音频处理:** 计算音频信号的幅度。
    * **图形渲染:** 计算距离或向量的长度。
    * **传感器数据处理:**  处理传感器返回的可能为负值的数据。
    * **通用计算:**  在各种算法和逻辑中需要获取绝对值。
* **影响 NDK 开发:** 使用 Android NDK 进行原生开发的应用程序会依赖 `bionic` 提供的 `fabs` 函数。这个数据文件确保了 NDK 开发人员使用的 `fabs` 函数是正确的。
* **系统稳定性:**  底层库的正确性直接关系到 Android 系统的稳定性和性能。如果 `fabs` 函数出现错误，可能会导致依赖它的应用程序出现不可预测的行为。

**`libc` 函数 (`fabs`) 的功能实现:**

`fabs` 函数的功能是返回一个浮点数的绝对值。其实现通常非常直接，主要依赖于对浮点数二进制表示的理解。

对于 IEEE 754 标准的双精度浮点数（`double`）：

1. **检查符号位:**  `double` 类型的浮点数使用 64 位表示，其中最高位是符号位 (0 表示正数，1 表示负数)。
2. **清除符号位:** 如果符号位为 1，则将其设置为 0。这样就得到了该浮点数的绝对值。
3. **特殊情况处理:**
    * **正零和负零:**  `fabs(0.0)` 和 `fabs(-0.0)` 都应该返回 `0.0`。
    * **NaN (Not a Number):** `fabs(NaN)` 应该返回 `NaN`。
    * **无穷大:** `fabs(INFINITY)` 应该返回 `INFINITY`，`fabs(-INFINITY)` 应该返回 `INFINITY`。

**C 代码实现 (简化示例):**

```c
double fabs(double x) {
  // 获取浮点数的二进制表示
  union {
    double f;
    uint64_t i;
  } u = {x};

  // 清除符号位 (将最高位设置为 0)
  u.i &= ~(1ULL << 63);

  return u.f;
}
```

**逻辑推理 (假设输入与输出):**

从 `fabs_intel_data.handroid` 文件中的数据可以看出，它覆盖了各种输入情况：

* **正数输入:** 输入为正数时，输出保持不变。例如：输入 `0x1.p-10`，输出 `0x1.0p-10` (两者表示相同的正数)。
* **负数输入:** 输入为负数时，输出变为其对应的正数。例如：输入 `-0x1.0p-10`，输出 `0x1.0p-10`。
* **零输入:** 输入为正零或负零时，输出为正零。例如：输入 `-0.0`，输出 `0.0`。
* **接近极限的值:** 文件中包含接近浮点数表示范围边界的值，例如 `0x1.p-1074` (最小正数) 和 `HUGE_VAL` (最大正数)。
* **精度边缘的值:**  包含一些非常接近但略有不同的正负数，用于测试精度。例如：输入 `0x1.fffffffffffff0p999` 和 `-0x1.fffffffffffffp999`。

**涉及 dynamic linker 的功能:**

这个数据文件本身并不直接涉及 dynamic linker 的功能。Dynamic linker 的主要职责是在程序运行时加载和链接共享库 (`.so` 文件)。

但是，`fabs` 函数的 *代码实现* 位于 `libm.so` (数学库) 中。当一个应用程序 (无论是 Java 层面的 APK 还是 Native 层面的可执行文件) 调用 `fabs` 函数时，dynamic linker 负责将该函数调用链接到 `libm.so` 中 `fabs` 函数的实际代码地址。

**`so` 布局样本:**

假设一个简单的 Native 应用程序 `my_app` 链接了 `libm.so`：

```
/system/lib64/libm.so  (假设是 64 位系统)
    ... (其他函数)
    fabs  (fabs 函数的代码)
    ...

/data/app/com.example.my_app/lib/arm64-v8a/libmy_app.so
    ... (应用程序自身的代码)
    import symbol: fabs from libm.so
    ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译 `libmy_app.so` 时，会记录下它需要使用 `fabs` 函数，并将其标记为一个需要从 `libm.so` 导入的符号。
2. **加载时:** 当 Android 系统启动 `my_app` 时，dynamic linker (例如 `linker64`) 会被调用。
3. **加载依赖库:** Dynamic linker 首先加载 `libmy_app.so`，然后解析其依赖关系，发现它需要 `libm.so`。
4. **查找和加载 `libm.so`:** Dynamic linker 在预定义的路径 (例如 `/system/lib64`) 中查找 `libm.so` 并将其加载到内存中。
5. **符号解析 (Symbol Resolution):** Dynamic linker 扫描 `libm.so` 的符号表，找到 `fabs` 函数的地址。
6. **重定位 (Relocation):** Dynamic linker 将 `libmy_app.so` 中所有对 `fabs` 函数的调用地址，替换为在 `libm.so` 中找到的 `fabs` 函数的实际内存地址。
7. **执行:**  当 `my_app` 的代码执行到调用 `fabs` 函数的地方时，程序会跳转到 `libm.so` 中 `fabs` 函数的实际代码执行。

**用户或编程常见的使用错误:**

* **误解浮点数精度:**  直接比较浮点数的绝对值是否相等可能存在精度问题。应该使用一个小的误差范围 (epsilon) 来进行比较。
    ```c
    double a = -3.14;
    if (fabs(a) == 3.14) { // 可能会因为精度问题导致比较失败
        // ...
    }

    double epsilon = 1e-9;
    if (fabs(fabs(a) - 3.14) < epsilon) { // 正确的做法
        // ...
    }
    ```
* **对特殊值的处理不当:** 没有考虑到 `NaN` 和无穷大的情况，导致程序出现意外行为。
    ```c
    double x = sqrt(-1.0); // x 是 NaN
    if (fabs(x) > 0) { //  NaN 与任何数值比较都返回 false
        // 这里的代码不会被执行
    }

    if (isnan(fabs(x))) { // 正确的检查 NaN 的方式
        // ...
    }
    ```
* **性能考虑 (对于循环密集型计算):** 虽然 `fabs` 函数本身很快，但在对大量数据进行绝对值计算时，也需要考虑潜在的性能影响。在某些特定的硬件架构上，可能会有更优化的绝对值计算方法。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**
   - 某些 Framework API 可能会间接地调用到 Native 层的数学函数。例如，处理动画、图形效果或者物理模拟的组件。
   - Java 层的 `Math.abs()` 方法在某些情况下可能会委托给 Native 层的实现。

2. **Android NDK (C/C++ 层):**
   - 使用 NDK 开发的应用程序可以直接包含 `<math.h>` 头文件，并调用 `fabs()` 函数。
   - 当 NDK 应用调用 `fabs()` 时，链接器会将该调用链接到 `bionic` 提供的 `libm.so` 中的实现。

**Frida Hook 示例调试步骤:**

假设你想 hook `fabs` 函数来观察其输入和输出：

1. **准备环境:** 安装 Frida 和 Python 的 Frida 模块。确保你的 Android 设备已 root，并且 Frida server 正在运行。

2. **编写 Frida 脚本 (JavaScript):**

```javascript
// hook_fabs.js
if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const fabs = Module.findExportByName('libm.so', 'fabs');

  if (fabs) {
    Interceptor.attach(fabs, {
      onEnter: function (args) {
        const input = args[0].toDouble();
        console.log(`[Fabs Hook] Input: ${input}`);
      },
      onLeave: function (retval) {
        const output = retval.toDouble();
        console.log(`[Fabs Hook] Output: ${output}`);
      }
    });
    console.log('[Fabs Hook] Successfully hooked fabs');
  } else {
    console.log('[Fabs Hook] Failed to find fabs in libm.so');
  }
} else {
  console.log('[Fabs Hook] Architecture not supported for this script.');
}
```

3. **运行 Frida 脚本:**

   ```bash
   frida -U -f <your_app_package_name> -l hook_fabs.js
   ```

   或者，如果你的应用程序已经在运行：

   ```bash
   frida -U <your_app_package_name> -l hook_fabs.js
   ```

   将 `<your_app_package_name>` 替换为你要监控的 Android 应用程序的包名。

4. **执行应用程序并观察输出:** 当被 hook 的应用程序调用 `fabs` 函数时，Frida 会拦截该调用，并打印出输入参数和返回值。

**调试步骤解释:**

* **`Process.arch`:** 检查当前进程的架构 (arm64 或 x64)，因为 `libm.so` 的位置和符号可能因架构而异。
* **`Module.findExportByName('libm.so', 'fabs')`:**  在 `libm.so` 模块中查找导出的符号 `fabs` 的地址。
* **`Interceptor.attach(fabs, { ... })`:**  将一个拦截器附加到 `fabs` 函数的入口和出口。
* **`onEnter`:**  在 `fabs` 函数被调用之前执行。`args[0]` 包含了第一个参数 (即要计算绝对值的浮点数)。`toDouble()` 将参数转换为 `double` 类型。
* **`onLeave`:** 在 `fabs` 函数返回之后执行。`retval` 包含了函数的返回值。
* **输出:**  Frida 会将 hook 的信息打印到你的终端。

通过这种方式，你可以动态地观察 `fabs` 函数在 Android 应用程序中的行为，验证其输入和输出是否符合预期。这对于理解应用程序的内部工作原理和调试数学相关的错误非常有用。

Prompt: 
```
这是目录为bionic/tests/math_data/fabs_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_fabs_intel_data[] = {
  { // Entry 0
    0x1.p-10,
    -0x1.0p-10
  },
  { // Entry 1
    0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 2
    0.0,
    -0.0
  },
  { // Entry 3
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 4
    0x1.fffffffffffff0p999,
    0x1.fffffffffffffp999
  },
  { // Entry 5
    0x1.p1000,
    0x1.0p1000
  },
  { // Entry 6
    0x1.00000000000010p1000,
    0x1.0000000000001p1000
  },
  { // Entry 7
    0x1.fffffffffffff0p199,
    0x1.fffffffffffffp199
  },
  { // Entry 8
    0x1.p200,
    0x1.0p200
  },
  { // Entry 9
    0x1.00000000000010p200,
    0x1.0000000000001p200
  },
  { // Entry 10
    0x1.fffffffffffff0p99,
    0x1.fffffffffffffp99
  },
  { // Entry 11
    0x1.p100,
    0x1.0p100
  },
  { // Entry 12
    0x1.00000000000010p100,
    0x1.0000000000001p100
  },
  { // Entry 13
    0x1.fffffffffffff0p19,
    0x1.fffffffffffffp19
  },
  { // Entry 14
    0x1.p20,
    0x1.0p20
  },
  { // Entry 15
    0x1.00000000000010p20,
    0x1.0000000000001p20
  },
  { // Entry 16
    0x1.fffffffffffff0p14,
    0x1.fffffffffffffp14
  },
  { // Entry 17
    0x1.p15,
    0x1.0p15
  },
  { // Entry 18
    0x1.00000000000010p15,
    0x1.0000000000001p15
  },
  { // Entry 19
    0x1.fffffffffffff0p9,
    0x1.fffffffffffffp9
  },
  { // Entry 20
    0x1.p10,
    0x1.0p10
  },
  { // Entry 21
    0x1.00000000000010p10,
    0x1.0000000000001p10
  },
  { // Entry 22
    0x1.fffffffffffff0p8,
    0x1.fffffffffffffp8
  },
  { // Entry 23
    0x1.p9,
    0x1.0p9
  },
  { // Entry 24
    0x1.00000000000010p9,
    0x1.0000000000001p9
  },
  { // Entry 25
    0x1.fffffffffffff0p6,
    0x1.fffffffffffffp6
  },
  { // Entry 26
    0x1.p7,
    0x1.0p7
  },
  { // Entry 27
    0x1.00000000000010p7,
    0x1.0000000000001p7
  },
  { // Entry 28
    0x1.fffffffffffff0p4,
    0x1.fffffffffffffp4
  },
  { // Entry 29
    0x1.p5,
    0x1.0p5
  },
  { // Entry 30
    0x1.00000000000010p5,
    0x1.0000000000001p5
  },
  { // Entry 31
    0x1.fffffffffffff0p3,
    0x1.fffffffffffffp3
  },
  { // Entry 32
    0x1.p4,
    0x1.0p4
  },
  { // Entry 33
    0x1.00000000000010p4,
    0x1.0000000000001p4
  },
  { // Entry 34
    0x1.fffffffffffff0p2,
    0x1.fffffffffffffp2
  },
  { // Entry 35
    0x1.p3,
    0x1.0p3
  },
  { // Entry 36
    0x1.00000000000010p3,
    0x1.0000000000001p3
  },
  { // Entry 37
    0x1.fffffffffffff0p1,
    0x1.fffffffffffffp1
  },
  { // Entry 38
    0x1.p2,
    0x1.0p2
  },
  { // Entry 39
    0x1.00000000000010p2,
    0x1.0000000000001p2
  },
  { // Entry 40
    0x1.fffffffffffff0p0,
    0x1.fffffffffffffp0
  },
  { // Entry 41
    0x1.p1,
    0x1.0p1
  },
  { // Entry 42
    0x1.00000000000010p1,
    0x1.0000000000001p1
  },
  { // Entry 43
    0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 44
    0x1.p0,
    0x1.0p0
  },
  { // Entry 45
    0x1.00000000000010p0,
    0x1.0000000000001p0
  },
  { // Entry 46
    0x1.fffffffffffff0p-2,
    0x1.fffffffffffffp-2
  },
  { // Entry 47
    0x1.p-1,
    0x1.0p-1
  },
  { // Entry 48
    0x1.00000000000010p-1,
    0x1.0000000000001p-1
  },
  { // Entry 49
    0x1.fffffffffffff0p-3,
    0x1.fffffffffffffp-3
  },
  { // Entry 50
    0x1.p-2,
    0x1.0p-2
  },
  { // Entry 51
    0x1.00000000000010p-2,
    0x1.0000000000001p-2
  },
  { // Entry 52
    0x1.fffffffffffff0p-4,
    0x1.fffffffffffffp-4
  },
  { // Entry 53
    0x1.p-3,
    0x1.0p-3
  },
  { // Entry 54
    0x1.00000000000010p-3,
    0x1.0000000000001p-3
  },
  { // Entry 55
    0x1.fffffffffffff0p-5,
    0x1.fffffffffffffp-5
  },
  { // Entry 56
    0x1.p-4,
    0x1.0p-4
  },
  { // Entry 57
    0x1.00000000000010p-4,
    0x1.0000000000001p-4
  },
  { // Entry 58
    0x1.fffffffffffff0p-6,
    0x1.fffffffffffffp-6
  },
  { // Entry 59
    0x1.p-5,
    0x1.0p-5
  },
  { // Entry 60
    0x1.00000000000010p-5,
    0x1.0000000000001p-5
  },
  { // Entry 61
    0x1.fffffffffffff0p-8,
    0x1.fffffffffffffp-8
  },
  { // Entry 62
    0x1.p-7,
    0x1.0p-7
  },
  { // Entry 63
    0x1.00000000000010p-7,
    0x1.0000000000001p-7
  },
  { // Entry 64
    0x1.fffffffffffff0p-10,
    0x1.fffffffffffffp-10
  },
  { // Entry 65
    0x1.p-9,
    0x1.0p-9
  },
  { // Entry 66
    0x1.00000000000010p-9,
    0x1.0000000000001p-9
  },
  { // Entry 67
    0x1.fffffffffffff0p-11,
    0x1.fffffffffffffp-11
  },
  { // Entry 68
    0x1.p-10,
    0x1.0p-10
  },
  { // Entry 69
    0x1.00000000000010p-10,
    0x1.0000000000001p-10
  },
  { // Entry 70
    0x1.fffffffffffff0p-16,
    0x1.fffffffffffffp-16
  },
  { // Entry 71
    0x1.p-15,
    0x1.0p-15
  },
  { // Entry 72
    0x1.00000000000010p-15,
    0x1.0000000000001p-15
  },
  { // Entry 73
    0x1.fffffffffffff0p-21,
    0x1.fffffffffffffp-21
  },
  { // Entry 74
    0x1.p-20,
    0x1.0p-20
  },
  { // Entry 75
    0x1.00000000000010p-20,
    0x1.0000000000001p-20
  },
  { // Entry 76
    0x1.fffffffffffff0p-101,
    0x1.fffffffffffffp-101
  },
  { // Entry 77
    0x1.p-100,
    0x1.0p-100
  },
  { // Entry 78
    0x1.00000000000010p-100,
    0x1.0000000000001p-100
  },
  { // Entry 79
    0x1.fffffffffffff0p-201,
    0x1.fffffffffffffp-201
  },
  { // Entry 80
    0x1.p-200,
    0x1.0p-200
  },
  { // Entry 81
    0x1.00000000000010p-200,
    0x1.0000000000001p-200
  },
  { // Entry 82
    0x1.fffffffffffff0p-1001,
    0x1.fffffffffffffp-1001
  },
  { // Entry 83
    0x1.p-1000,
    0x1.0p-1000
  },
  { // Entry 84
    0x1.00000000000010p-1000,
    0x1.0000000000001p-1000
  },
  { // Entry 85
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 86
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 87
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 88
    HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 89
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 90
    0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 91
    0x1.ffffffffffffe0p1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 92
    0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 93
    0x1.921fb54442d180p1,
    0x1.921fb54442d18p1
  },
  { // Entry 94
    0x1.921fb54442d180p1,
    -0x1.921fb54442d18p1
  },
  { // Entry 95
    0x1.921fb54442d180p0,
    0x1.921fb54442d18p0
  },
  { // Entry 96
    0x1.921fb54442d180p0,
    -0x1.921fb54442d18p0
  },
  { // Entry 97
    0x1.00000000000010p0,
    0x1.0000000000001p0
  },
  { // Entry 98
    0x1.00000000000010p0,
    -0x1.0000000000001p0
  },
  { // Entry 99
    0x1.p0,
    0x1.0p0
  },
  { // Entry 100
    0x1.p0,
    -0x1.0p0
  },
  { // Entry 101
    0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 102
    0x1.fffffffffffff0p-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 103
    0x1.921fb54442d180p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 104
    0x1.921fb54442d180p-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 105
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 106
    0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 107
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 108
    0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 109
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 110
    0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 111
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 112
    0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 113
    0x1.p-1073,
    0x1.0p-1073
  },
  { // Entry 114
    0x1.p-1073,
    -0x1.0p-1073
  },
  { // Entry 115
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 116
    0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 117
    0.0,
    0.0
  },
  { // Entry 118
    0.0,
    -0.0
  }
};

"""

```
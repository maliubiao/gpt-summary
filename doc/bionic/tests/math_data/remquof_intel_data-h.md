Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The request asks for a detailed analysis of a C source code file containing test data for the `remquof` function within Android's Bionic library. Key aspects include understanding the data's purpose, its relationship to Android, how the corresponding libc function works, dynamic linker involvement, potential errors, and how this code is reached from higher levels of Android.

**2. Initial Analysis of the Code:**

The code defines a static array `g_remquof_intel_data` of a custom structure `data_1_int_2_t`. This structure appears to hold three floats and one integer. The naming suggests it's test data specifically for the `remquof` function and tailored for Intel architectures. The `handroid` part of the filename hints at specific handling for Android.

**3. Identifying the Core Functionality:**

The file's primary purpose is to provide test cases for the `remquof` function. `remquof` computes the remainder and part of the quotient of the division of two floating-point numbers. The integer part of the quotient is stored in an integer variable passed by reference.

**4. Connecting to Android Functionality:**

* **Bionic:**  The file resides within the Bionic library, which is Android's standard C library. This immediately establishes a direct connection to core Android functionality.
* **NDK:**  Developers using the Android NDK can call standard C library functions, including math functions like `remquof`. This makes the tests relevant to NDK-based apps.
* **Framework:**  The Android framework itself, written in Java and native code, relies on Bionic's math functions internally.

**5. Explaining the `remquof` Libc Function:**

This requires detailing the mathematical operation. The key is to explain that it's not just a simple modulo operation for floats. It also extracts the integer quotient, which is crucial. The standard signature `float remquof(float x, float y, int *quo);` should be mentioned, along with the roles of the input parameters and the output.

**6. Dynamic Linker Aspects:**

The prompt specifically asks about the dynamic linker. Here's the thought process:

* **No Direct Linker Code:** The provided file *itself* doesn't contain dynamic linking code. It's just data.
* **Indirect Linker Involvement:** The `remquof` function, which this data tests, *is* part of a shared library (libc.so). When an Android app or service calls `remquof`, the dynamic linker is responsible for loading `libc.so` and resolving the symbol.
* **SO Layout Sample:**  To illustrate, a simplified `libc.so` layout is needed, showing sections like `.text` (code), `.data` (initialized data, where this test data would reside conceptually for a real test), `.bss` (uninitialized data), and the GOT/PLT for function calls.
* **Linking Process:** Describe the steps: symbol lookup, GOT/PLT interaction, address resolution.

**7. Logical Deduction and Test Case Analysis:**

The data entries provide input values and expected outputs for `remquof`.

* **Structure Understanding:** Each entry has an input `x`, an input `y`, an *expected* integer quotient, and an *expected* remainder.
* **Manual Calculation (Simple Cases):** For a few entries (like Entry 252), mentally perform the `remquof` operation to confirm understanding. For example, -1.0 / 2.0 = -0.5. The integer part is -0, or 0 if we round towards zero. The remainder is -1.0 - (0 * 2.0) = -1.0. However, the provided data gives an integer quotient of 1 and a remainder of 1.5. This suggests the integer part is influenced by the rounding mode or specific implementation details of `remquof`. This highlights the value of having test data!
* **Identifying Edge Cases:** Notice entries with zero, very small numbers, very large numbers (like `HUGE_VALF`), and infinities. These are important for robust testing.
* **Hypothetical Input/Output:** Create a simple example:  Input 5.0 and 2.0. The expected quotient is 2, and the remainder is 1.0.

**8. Common Usage Errors:**

Focus on programmer mistakes when using `remquof`:

* **Incorrect Pointer:** Passing a null or invalid pointer for the integer quotient.
* **Ignoring the Quotient:** Not using the returned integer quotient when it's needed.
* **Misunderstanding Remainder Sign:** The sign of the remainder can be implementation-dependent.

**9. Tracing the Execution Flow and Frida Hooking:**

* **Android Framework/NDK to Libc:** Explain the path:
    * Java code in the framework might call native methods (JNI).
    * NDK developers directly call libc functions.
    * These calls go through the dynamic linker to `libc.so`.
* **Frida Hooking:** Provide a basic Frida script to intercept calls to `remquof`. The script should log the input arguments and the results (remainder and quotient).

**10. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use code formatting for the data structure and Frida script. Explain technical terms clearly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  The file contains the *implementation* of `remquof`. **Correction:**  It's *test data* for `remquof`.
* **Overemphasis on direct linker code:**  Recognize that the file is data, but the *function being tested* relies on the dynamic linker. Shift focus accordingly.
* **Simplifying SO layout:**  Avoid getting bogged down in extreme detail about all sections of a shared object. Focus on the relevant parts.
* **Clarifying remainder sign:** Explicitly mention the potential for implementation-defined behavior regarding the sign of the remainder.

By following this structured thinking process and iterating on the understanding of the code and the request, a comprehensive and accurate answer can be generated.
这个文件 `bionic/tests/math_data/remquof_intel_data.handroid` 是 Android Bionic 库中用于 `remquof` 函数的测试数据文件，特别是针对 Intel 架构的 Android 设备。Bionic 库是 Android 系统的核心 C 库，提供了诸如标准 C 库函数、数学函数和动态链接器等功能。

**文件功能列举:**

1. **提供 `remquof` 函数的测试用例:**  这个文件的核心功能是存储一系列预定义的输入值和期望的输出值，用于测试 `remquof` 函数在不同输入下的行为是否正确。
2. **针对 Intel 架构优化:** 文件名中的 `intel` 表明这些测试用例可能特别关注或包含了在 Intel 架构上可能出现的特殊情况或性能考量。
3. **Android Bionic 库的一部分:** 作为 Bionic 库的组成部分，它确保了 Android 系统及其应用程序中使用的基础数学函数的正确性和可靠性。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 系统中数学运算的正确性。`remquof` 函数通常用于需要同时获得浮点数除法的余数和部分商的场景。

**举例说明:**

* **图形渲染:**  在图形渲染中，可能会用到浮点数计算，例如计算纹理坐标或光照模型。如果 `remquof` 函数计算不正确，可能会导致渲染结果出现错误。
* **音频处理:** 音频处理算法中也经常使用浮点数运算。错误的 `remquof` 可能导致音频输出失真或产生其他非预期效果。
* **科学计算应用:**  运行在 Android 上的科学计算应用会大量使用数学函数，`remquof` 的正确性直接影响计算结果的准确性。

**详细解释 `remquof` libc 函数的功能是如何实现的:**

`remquof` 是 C 标准库 `<math.h>` 中定义的函数，用于计算浮点数 `x` 除以 `y` 的余数，并将商的特定部分存储在由 `*quo` 指向的整数中。其函数签名通常为：

```c
float remquof(float x, float y, int *quo);
```

**功能:**

1. **计算余数:**  计算 `x - n * y`，其中 `n` 是最接近 `x / y` 的整数。
2. **存储商的部分:** 将商 `x / y` 的低位比特存储在 `*quo` 指向的整数中。存储的具体位数可能因实现而异，但通常是使 `*quo` 能够表示商的符号和几个低位比特，用于区分不同的余数。

**实现原理（通用概念，实际实现可能因架构和库而异）:**

1. **处理特殊情况:** 首先处理诸如除数为零、输入为 NaN 或无穷大的情况。
2. **计算近似商:** 使用浮点数除法计算 `x / y` 的一个近似值。
3. **确定整数商:** 根据近似商确定最接近的整数 `n`。这可能涉及到舍入操作。
4. **计算余数:** 使用公式 `x - n * y` 计算余数。
5. **提取商的低位比特:**  将原始商 `x / y` 的低位比特提取出来，并根据其符号进行调整，存储到 `*quo` 中。这个过程通常涉及到位运算。

**假设输入与输出（基于文件内容推断）：**

文件中的每个条目定义了一组输入和预期的输出，可以看作是 `remquof` 函数的假设输入与输出。例如，对于第一个条目：

* **假设输入:** `x = 0x1.72c2c0p18` (浮点数), `y = (int)-0x1.b37d2b60p28` (浮点数，注意这里被转换为 `int` 类型，这可能是测试用例的特殊处理，实际 `remquof` 的第二个参数是浮点数), `*quo` 指针指向的整数变量
* **预期输出:** `remquof` 返回 `-0x1.285308p99` (余数), `*quo` 指向的整数变量的值被设置为 `0x1.7a4110p19` (注意，这里的值看起来像一个浮点数的十六进制表示，但由于 `quo` 是 `int*` 类型，这应该是商的某种编码表示)。

**请注意:** 文件中的第二个输入看起来像是被错误地标记为 `int` 类型，这可能是测试数据生成脚本的特殊处理，用于覆盖某些特定的边缘情况或者测试 `remquof` 函数如何处理类型转换。在实际的 `remquof` 函数调用中，第二个参数通常是 `float` 类型。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`remquof` 函数位于 `libc.so` 共享库中。当应用程序调用 `remquof` 时，动态链接器负责加载 `libc.so` 并解析 `remquof` 的符号地址。

**`libc.so` 布局样本（简化）：**

```
libc.so:
  .interp         # 指向动态链接器
  .note.android.ident
  .dynsym         # 动态符号表
  .dynstr         # 动态字符串表
  .hash           # 符号哈希表
  .gnu.version    # 版本信息
  .gnu.version_r  # 版本需求
  .rel.dyn        # 重定位信息 (数据段)
  .rel.plt        # 重定位信息 (PLT)
  .plt            # 过程链接表 (Procedure Linkage Table)
  .text           # 代码段 (包含 remquof 的实现)
  .rodata         # 只读数据段
  .data           # 已初始化数据段 (可能包含全局变量等)
  .bss            # 未初始化数据段
```

**链接的处理过程:**

1. **应用程序启动:** 当一个 Android 应用程序启动时，操作系统会加载应用程序的可执行文件。
2. **解析 ELF 头:** 操作系统读取可执行文件的 ELF 头，找到 `.interp` 段，该段指定了动态链接器的路径 (通常是 `/system/bin/linker64` 或 `/system/bin/linker`)。
3. **加载动态链接器:** 操作系统加载动态链接器到内存中。
4. **动态链接器接管:** 动态链接器开始执行，负责加载应用程序依赖的共享库，例如 `libc.so`。
5. **查找依赖库:** 动态链接器读取应用程序 ELF 头的动态段，找到应用程序依赖的共享库列表。
6. **加载 `libc.so`:** 动态链接器在系统路径中查找 `libc.so`，并将其加载到内存中的某个地址。
7. **符号解析 (Symbol Resolution):**
   - 当应用程序代码调用 `remquof` 时，编译器会生成一个对 `remquof` 的符号引用。
   - 在链接时，这个符号引用不会被解析为具体的内存地址，而是在 `.plt` 段中创建一个条目。
   - 当第一次执行到 `remquof` 的调用时，会跳转到 `.plt` 段对应的条目。
   - `.plt` 条目中的代码会调用动态链接器来解析 `remquof` 的实际地址。
   - 动态链接器在 `libc.so` 的 `.dynsym` (动态符号表) 中查找 `remquof` 的符号。
   - 如果找到该符号，动态链接器会获取 `remquof` 在 `libc.so` 中的实际内存地址。
   - 动态链接器将解析出的地址更新到全局偏移表 (GOT) 中与 `remquof` 相关的条目。
   - 后续对 `remquof` 的调用将直接通过 GOT 跳转到其真实的内存地址，避免重复解析。

**如果做了逻辑推理，请给出假设输入与输出:**

上面的“假设输入与输出”部分已经基于文件内容进行了逻辑推理。文件本身就是一系列的测试用例，代表了对 `remquof` 函数行为的预期。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **传递空指针给 `quo`:**

   ```c
   float x = 5.0f;
   float y = 2.0f;
   float remainder;
   remainder = remquof(x, y, NULL); // 错误：传递了空指针
   ```

   **后果:** 导致程序崩溃，因为 `remquof` 尝试写入空地址。

2. **未初始化 `quo` 指向的变量:**

   ```c
   float x = 5.0f;
   float y = 2.0f;
   float remainder;
   int quotient; // 未初始化
   remainder = remquof(x, y, &quotient);
   // quotient 的值是未定义的
   ```

   **后果:** 虽然不会立即崩溃，但 `quotient` 的值是不可预测的，导致程序逻辑错误。

3. **误解 `quo` 返回的值:** 开发者可能误以为 `quo` 返回的是完整的商，而实际上它只返回商的一部分信息（通常是低位比特和符号）。

4. **类型不匹配:**  虽然 `remquof` 的参数是 `float`，但如果错误地传递了其他类型的变量，可能会导致精度损失或未定义的行为。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `remquof` 的路径:**

1. **Java Framework 调用:** Android Framework 的 Java 代码 (例如，在 `android.graphics` 或其他模块中) 可能会调用 Native 方法 (通过 JNI)。
2. **JNI 调用:** 这些 Native 方法通常是用 C/C++ 编写的，位于 Framework 的 Native 库中 (例如，位于 `/system/lib64` 或 `/system/lib` 下的 `.so` 文件)。
3. **Native 代码调用 `remquof`:** Framework 的 Native 代码中，在执行某些数学运算时，可能会直接或间接地调用 Bionic 库提供的 `remquof` 函数。
4. **动态链接:** 当 Native 代码首次调用 `remquof` 时，动态链接器会介入，找到并加载 `libc.so`，然后解析 `remquof` 的地址。
5. **执行 `remquof`:**  最终执行 `libc.so` 中 `remquof` 函数的代码。

**NDK 到 `remquof` 的路径:**

1. **NDK 应用调用:** 使用 Android NDK 开发的应用程序可以直接调用 Bionic 提供的 C 标准库函数，包括 `remquof`。
2. **编译和链接:** NDK 编译器会将应用程序的 C/C++ 代码编译成包含对 `remquof` 符号引用的机器码。链接器会将应用程序与必要的 Bionic 库链接。
3. **加载和动态链接:** 当 NDK 应用启动时，动态链接器会加载应用程序依赖的库，包括 `libc.so`，并解析 `remquof` 的地址。
4. **执行 `remquof`:**  应用程序代码执行到调用 `remquof` 的地方时，会跳转到 `libc.so` 中 `remquof` 的实现。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `remquof` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const remquofPtr = Module.findExportByName("libc.so", "remquof");

  if (remquofPtr) {
    Interceptor.attach(remquofPtr, {
      onEnter: function (args) {
        const x = parseFloat(args[0]);
        const y = parseFloat(args[1]);
        const quoPtr = ptr(args[2]);
        console.log("[remquof] Called with x =", x, ", y =", y, ", quoPtr =", quoPtr);
      },
      onLeave: function (retval) {
        const remainder = parseFloat(retval);
        const quoPtr = this.context.sp.add(8 * 2); // Adjust based on architecture and calling convention
        const quo = Memory.readS32(quoPtr);
        console.log("[remquof] Returned remainder =", remainder, ", *quo =", quo);
      }
    });
    console.log("[Frida] Hooked remquof at", remquofPtr);
  } else {
    console.log("[Frida] Failed to find remquof in libc.so");
  }
} else {
  console.log("[Frida] This script is designed for ARM/ARM64 architectures.");
}
```

**代码解释:**

1. **查找 `remquof` 地址:** 使用 `Module.findExportByName` 在 `libc.so` 中查找 `remquof` 函数的地址。
2. **拦截调用:** 使用 `Interceptor.attach` 拦截对 `remquof` 函数的调用。
3. **`onEnter`:** 在函数调用之前执行。
   - `args[0]` 和 `args[1]` 分别是 `x` 和 `y` 的值。
   - `args[2]` 是指向 `quo` 整数变量的指针。
   - 打印输入参数。
4. **`onLeave`:** 在函数返回之后执行。
   - `retval` 是函数的返回值（余数）。
   - 通过读取栈上的值（需要根据架构和调用约定调整偏移量）来获取 `quo` 指向的整数值。
   - 打印返回值和 `quo` 的值.

**使用 Frida Hook 调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 Root，并且安装了 Frida 服务。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_remquof.js`。
3. **运行 Frida:** 使用 Frida 命令行工具将脚本注入到目标进程中。你需要找到目标进程的进程 ID 或进程名称。

   ```bash
   frida -U -f <package_name> -l hook_remquof.js --no-pause
   # 或者，如果已知进程 ID
   frida -U <process_id> -l hook_remquof.js
   ```

   将 `<package_name>` 替换为你想监控的应用程序的包名。

4. **触发 `remquof` 调用:** 在目标应用程序中执行会导致调用 `remquof` 函数的操作。
5. **查看 Frida 输出:** Frida 会在终端上输出拦截到的 `remquof` 函数的调用信息，包括输入参数和返回值。

通过 Frida Hook，你可以动态地观察 `remquof` 函数的调用情况，验证其输入和输出，从而帮助理解其行为和调试相关问题。

### 提示词
```
这是目录为bionic/tests/math_data/remquof_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_int_2_t<float, float, float> g_remquof_intel_data[] = {
  { // Entry 0
    0x1.72c2c0p18,
    (int)-0x1.b37d2b60p28,
    -0x1.285308p99,
    0x1.7a4110p19
  },
  { // Entry 1
    -0x1.96dfb0p13,
    (int)0x1.212d5d58p30,
    0x1.0295fap117,
    0x1.0cede2p15
  },
  { // Entry 2
    0x1.fd0030p20,
    (int)-0x1.007ff8p22,
    0x1.ffffe6p127,
    -0x1.000006p22
  },
  { // Entry 3
    0x1.4782b0p2,
    (int)0x1.4323c158p30,
    0x1.fffff8p127,
    0x1.dffffep4
  },
  { // Entry 4
    -0x1.p-11,
    (int)0x1.ffffc0p30,
    0x1.fffffap127,
    0x1.fffffcp-1
  },
  { // Entry 5
    -0.0,
    (int)0x1.p0,
    -0x1.p-117,
    -0x1.p-117
  },
  { // Entry 6
    -0.0,
    (int)-0x1.p0,
    -0x1.p-117,
    0x1.p-117
  },
  { // Entry 7
    0.0,
    (int)-0x1.p0,
    0x1.p-117,
    -0x1.p-117
  },
  { // Entry 8
    0.0,
    (int)0x1.p0,
    0x1.p-117,
    0x1.p-117
  },
  { // Entry 9
    -0x1.p-117,
    (int)0.0,
    -0x1.p-117,
    0x1.p15
  },
  { // Entry 10
    -0x1.p-117,
    (int)0.0,
    -0x1.p-117,
    0x1.p16
  },
  { // Entry 11
    0x1.p-117,
    (int)0.0,
    0x1.p-117,
    0x1.p15
  },
  { // Entry 12
    0x1.p-117,
    (int)0.0,
    0x1.p-117,
    0x1.p16
  },
  { // Entry 13
    -0x1.p-117,
    (int)0.0,
    -0x1.p-117,
    0x1.p117
  },
  { // Entry 14
    -0x1.p-117,
    (int)0.0,
    -0x1.p-117,
    0x1.p118
  },
  { // Entry 15
    0x1.p-117,
    (int)0.0,
    0x1.p-117,
    0x1.p117
  },
  { // Entry 16
    0x1.p-117,
    (int)0.0,
    0x1.p-117,
    0x1.p118
  },
  { // Entry 17
    0.0,
    (int)0.0,
    0x1.p15,
    -0x1.p-117
  },
  { // Entry 18
    0.0,
    (int)0.0,
    0x1.p15,
    0x1.p-117
  },
  { // Entry 19
    0.0,
    (int)0.0,
    0x1.p16,
    -0x1.p-117
  },
  { // Entry 20
    0.0,
    (int)0.0,
    0x1.p16,
    0x1.p-117
  },
  { // Entry 21
    0.0,
    (int)0x1.p0,
    0x1.p15,
    0x1.p15
  },
  { // Entry 22
    0x1.p15,
    (int)0.0,
    0x1.p15,
    0x1.p16
  },
  { // Entry 23
    0.0,
    (int)0x1.p1,
    0x1.p16,
    0x1.p15
  },
  { // Entry 24
    0.0,
    (int)0x1.p0,
    0x1.p16,
    0x1.p16
  },
  { // Entry 25
    0x1.p15,
    (int)0.0,
    0x1.p15,
    0x1.p117
  },
  { // Entry 26
    0x1.p15,
    (int)0.0,
    0x1.p15,
    0x1.p118
  },
  { // Entry 27
    0x1.p16,
    (int)0.0,
    0x1.p16,
    0x1.p117
  },
  { // Entry 28
    0x1.p16,
    (int)0.0,
    0x1.p16,
    0x1.p118
  },
  { // Entry 29
    0.0,
    (int)0.0,
    0x1.p117,
    -0x1.p-117
  },
  { // Entry 30
    0.0,
    (int)0.0,
    0x1.p117,
    0x1.p-117
  },
  { // Entry 31
    0.0,
    (int)0.0,
    0x1.p118,
    -0x1.p-117
  },
  { // Entry 32
    0.0,
    (int)0.0,
    0x1.p118,
    0x1.p-117
  },
  { // Entry 33
    0.0,
    (int)0.0,
    0x1.p117,
    0x1.p15
  },
  { // Entry 34
    0.0,
    (int)0.0,
    0x1.p117,
    0x1.p16
  },
  { // Entry 35
    0.0,
    (int)0.0,
    0x1.p118,
    0x1.p15
  },
  { // Entry 36
    0.0,
    (int)0.0,
    0x1.p118,
    0x1.p16
  },
  { // Entry 37
    0.0,
    (int)0x1.p0,
    0x1.p117,
    0x1.p117
  },
  { // Entry 38
    0x1.p117,
    (int)0.0,
    0x1.p117,
    0x1.p118
  },
  { // Entry 39
    0.0,
    (int)0x1.p1,
    0x1.p118,
    0x1.p117
  },
  { // Entry 40
    0.0,
    (int)0x1.p0,
    0x1.p118,
    0x1.p118
  },
  { // Entry 41
    0.0,
    (int)0x1.40p3,
    0x1.90p6,
    0x1.40p3
  },
  { // Entry 42
    0x1.p0,
    (int)0x1.20p3,
    0x1.90p6,
    0x1.60p3
  },
  { // Entry 43
    0x1.p2,
    (int)0x1.p3,
    0x1.90p6,
    0x1.80p3
  },
  { // Entry 44
    0x1.p0,
    (int)0x1.40p3,
    0x1.94p6,
    0x1.40p3
  },
  { // Entry 45
    0x1.p1,
    (int)0x1.20p3,
    0x1.94p6,
    0x1.60p3
  },
  { // Entry 46
    0x1.40p2,
    (int)0x1.p3,
    0x1.94p6,
    0x1.80p3
  },
  { // Entry 47
    0x1.p1,
    (int)0x1.40p3,
    0x1.98p6,
    0x1.40p3
  },
  { // Entry 48
    0x1.80p1,
    (int)0x1.20p3,
    0x1.98p6,
    0x1.60p3
  },
  { // Entry 49
    0x1.80p2,
    (int)0x1.p3,
    0x1.98p6,
    0x1.80p3
  },
  { // Entry 50
    0x1.80p1,
    (int)0x1.40p3,
    0x1.9cp6,
    0x1.40p3
  },
  { // Entry 51
    0x1.p2,
    (int)0x1.20p3,
    0x1.9cp6,
    0x1.60p3
  },
  { // Entry 52
    -0x1.40p2,
    (int)0x1.20p3,
    0x1.9cp6,
    0x1.80p3
  },
  { // Entry 53
    0x1.p2,
    (int)0x1.40p3,
    0x1.a0p6,
    0x1.40p3
  },
  { // Entry 54
    0x1.40p2,
    (int)0x1.20p3,
    0x1.a0p6,
    0x1.60p3
  },
  { // Entry 55
    -0x1.p2,
    (int)0x1.20p3,
    0x1.a0p6,
    0x1.80p3
  },
  { // Entry 56
    0x1.40p2,
    (int)0x1.40p3,
    0x1.a4p6,
    0x1.40p3
  },
  { // Entry 57
    -0x1.40p2,
    (int)0x1.40p3,
    0x1.a4p6,
    0x1.60p3
  },
  { // Entry 58
    -0x1.80p1,
    (int)0x1.20p3,
    0x1.a4p6,
    0x1.80p3
  },
  { // Entry 59
    -0x1.p2,
    (int)0x1.60p3,
    0x1.a8p6,
    0x1.40p3
  },
  { // Entry 60
    -0x1.p2,
    (int)0x1.40p3,
    0x1.a8p6,
    0x1.60p3
  },
  { // Entry 61
    -0x1.p1,
    (int)0x1.20p3,
    0x1.a8p6,
    0x1.80p3
  },
  { // Entry 62
    -0x1.80p1,
    (int)0x1.60p3,
    0x1.acp6,
    0x1.40p3
  },
  { // Entry 63
    -0x1.80p1,
    (int)0x1.40p3,
    0x1.acp6,
    0x1.60p3
  },
  { // Entry 64
    -0x1.p0,
    (int)0x1.20p3,
    0x1.acp6,
    0x1.80p3
  },
  { // Entry 65
    -0x1.p1,
    (int)0x1.60p3,
    0x1.b0p6,
    0x1.40p3
  },
  { // Entry 66
    -0x1.p1,
    (int)0x1.40p3,
    0x1.b0p6,
    0x1.60p3
  },
  { // Entry 67
    0.0,
    (int)0x1.20p3,
    0x1.b0p6,
    0x1.80p3
  },
  { // Entry 68
    -0x1.p0,
    (int)0x1.60p3,
    0x1.b4p6,
    0x1.40p3
  },
  { // Entry 69
    -0x1.p0,
    (int)0x1.40p3,
    0x1.b4p6,
    0x1.60p3
  },
  { // Entry 70
    0x1.p0,
    (int)0x1.20p3,
    0x1.b4p6,
    0x1.80p3
  },
  { // Entry 71
    0.0,
    (int)0x1.60p3,
    0x1.b8p6,
    0x1.40p3
  },
  { // Entry 72
    0.0,
    (int)0x1.40p3,
    0x1.b8p6,
    0x1.60p3
  },
  { // Entry 73
    0x1.p1,
    (int)0x1.20p3,
    0x1.b8p6,
    0x1.80p3
  },
  { // Entry 74
    -0.0,
    (int)0x1.p0,
    -0x1.000002p0,
    -0x1.000002p0
  },
  { // Entry 75
    -0x1.p-23,
    (int)0x1.p0,
    -0x1.000002p0,
    -0x1.p0
  },
  { // Entry 76
    -0x1.80p-23,
    (int)0x1.p0,
    -0x1.000002p0,
    -0x1.fffffep-1
  },
  { // Entry 77
    0x1.p-23,
    (int)0x1.p0,
    -0x1.p0,
    -0x1.000002p0
  },
  { // Entry 78
    -0.0,
    (int)0x1.p0,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 79
    -0x1.p-24,
    (int)0x1.p0,
    -0x1.p0,
    -0x1.fffffep-1
  },
  { // Entry 80
    0x1.80p-23,
    (int)0x1.p0,
    -0x1.fffffep-1,
    -0x1.000002p0
  },
  { // Entry 81
    0x1.p-24,
    (int)0x1.p0,
    -0x1.fffffep-1,
    -0x1.p0
  },
  { // Entry 82
    -0.0,
    (int)0x1.p0,
    -0x1.fffffep-1,
    -0x1.fffffep-1
  },
  { // Entry 83
    -0x1.80p-23,
    (int)-0x1.p0,
    -0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 84
    -0x1.p-23,
    (int)-0x1.p0,
    -0x1.000002p0,
    0x1.p0
  },
  { // Entry 85
    -0.0,
    (int)-0x1.p0,
    -0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 86
    -0x1.p-24,
    (int)-0x1.p0,
    -0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 87
    -0.0,
    (int)-0x1.p0,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 88
    0x1.p-23,
    (int)-0x1.p0,
    -0x1.p0,
    0x1.000002p0
  },
  { // Entry 89
    -0.0,
    (int)-0x1.p0,
    -0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 90
    0x1.p-24,
    (int)-0x1.p0,
    -0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 91
    0x1.80p-23,
    (int)-0x1.p0,
    -0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 92
    -0x1.80p-23,
    (int)-0x1.p0,
    0x1.fffffep-1,
    -0x1.000002p0
  },
  { // Entry 93
    -0x1.p-24,
    (int)-0x1.p0,
    0x1.fffffep-1,
    -0x1.p0
  },
  { // Entry 94
    0.0,
    (int)-0x1.p0,
    0x1.fffffep-1,
    -0x1.fffffep-1
  },
  { // Entry 95
    -0x1.p-23,
    (int)-0x1.p0,
    0x1.p0,
    -0x1.000002p0
  },
  { // Entry 96
    0.0,
    (int)-0x1.p0,
    0x1.p0,
    -0x1.p0
  },
  { // Entry 97
    0x1.p-24,
    (int)-0x1.p0,
    0x1.p0,
    -0x1.fffffep-1
  },
  { // Entry 98
    0.0,
    (int)-0x1.p0,
    0x1.000002p0,
    -0x1.000002p0
  },
  { // Entry 99
    0x1.p-23,
    (int)-0x1.p0,
    0x1.000002p0,
    -0x1.p0
  },
  { // Entry 100
    0x1.80p-23,
    (int)-0x1.p0,
    0x1.000002p0,
    -0x1.fffffep-1
  },
  { // Entry 101
    0.0,
    (int)0x1.p0,
    0x1.fffffep-1,
    0x1.fffffep-1
  },
  { // Entry 102
    -0x1.p-24,
    (int)0x1.p0,
    0x1.fffffep-1,
    0x1.p0
  },
  { // Entry 103
    -0x1.80p-23,
    (int)0x1.p0,
    0x1.fffffep-1,
    0x1.000002p0
  },
  { // Entry 104
    0x1.p-24,
    (int)0x1.p0,
    0x1.p0,
    0x1.fffffep-1
  },
  { // Entry 105
    0.0,
    (int)0x1.p0,
    0x1.p0,
    0x1.p0
  },
  { // Entry 106
    -0x1.p-23,
    (int)0x1.p0,
    0x1.p0,
    0x1.000002p0
  },
  { // Entry 107
    0x1.80p-23,
    (int)0x1.p0,
    0x1.000002p0,
    0x1.fffffep-1
  },
  { // Entry 108
    0x1.p-23,
    (int)0x1.p0,
    0x1.000002p0,
    0x1.p0
  },
  { // Entry 109
    0.0,
    (int)0x1.p0,
    0x1.000002p0,
    0x1.000002p0
  },
  { // Entry 110
    -0.0,
    (int)-0x1.p0,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 111
    0.0,
    (int)0.0,
    0.0,
    0x1.p-149
  },
  { // Entry 112
    0.0,
    (int)0x1.p0,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 113
    -0.0,
    (int)0x1.p0,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 114
    0.0,
    (int)0.0,
    0.0,
    -0x1.p-149
  },
  { // Entry 115
    0.0,
    (int)-0x1.p0,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 116
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 117
    0.0,
    (int)0.0,
    0.0,
    0x1.fffffep127
  },
  { // Entry 118
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 119
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 120
    0.0,
    (int)0.0,
    0.0,
    -0x1.fffffep127
  },
  { // Entry 121
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 122
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 123
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 124
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 125
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 126
    0.0,
    (int)0.0,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 127
    -0.0,
    (int)0.0,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 128
    -0.0,
    (int)0.0,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 129
    0.0,
    (int)0.0,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 130
    0.0,
    (int)0x1.p0,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 131
    0.0,
    (int)-0x1.p0,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 132
    -0.0,
    (int)-0x1.p0,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 133
    -0.0,
    (int)0x1.p0,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 134
    0x1.fffff8p-3,
    (int)-0x1.000004p22,
    -0x1.000002p22,
    0x1.fffffep-1
  },
  { // Entry 135
    -0x1.p-1,
    (int)-0x1.p22,
    -0x1.000002p22,
    0x1.p0
  },
  { // Entry 136
    -0.0,
    (int)-0x1.p22,
    -0x1.000002p22,
    0x1.000002p0
  },
  { // Entry 137
    -0x1.p-2,
    (int)-0x1.p22,
    -0x1.p22,
    0x1.fffffep-1
  },
  { // Entry 138
    -0.0,
    (int)-0x1.p22,
    -0x1.p22,
    0x1.p0
  },
  { // Entry 139
    0x1.p-1,
    (int)-0x1.p22,
    -0x1.p22,
    0x1.000002p0
  },
  { // Entry 140
    -0.0,
    (int)-0x1.p22,
    -0x1.fffffep21,
    0x1.fffffep-1
  },
  { // Entry 141
    0x1.p-2,
    (int)-0x1.p22,
    -0x1.fffffep21,
    0x1.p0
  },
  { // Entry 142
    -0x1.000008p-2,
    (int)-0x1.fffff8p21,
    -0x1.fffffep21,
    0x1.000002p0
  },
  { // Entry 143
    0.0,
    (int)0x1.p23,
    0x1.fffffep22,
    0x1.fffffep-1
  },
  { // Entry 144
    -0x1.p-1,
    (int)0x1.p23,
    0x1.fffffep22,
    0x1.p0
  },
  { // Entry 145
    -0x1.fffff8p-2,
    (int)0x1.fffffcp22,
    0x1.fffffep22,
    0x1.000002p0
  },
  { // Entry 146
    -0x1.fffffcp-2,
    (int)0x1.000002p23,
    0x1.p23,
    0x1.fffffep-1
  },
  { // Entry 147
    0.0,
    (int)0x1.p23,
    0x1.p23,
    0x1.p0
  },
  { // Entry 148
    0x1.p-23,
    (int)0x1.fffffcp22,
    0x1.p23,
    0x1.000002p0
  },
  { // Entry 149
    -0x1.fffff8p-2,
    (int)0x1.000004p23,
    0x1.000002p23,
    0x1.fffffep-1
  },
  { // Entry 150
    0.0,
    (int)0x1.000002p23,
    0x1.000002p23,
    0x1.p0
  },
  { // Entry 151
    0.0,
    (int)0x1.p23,
    0x1.000002p23,
    0x1.000002p0
  },
  { // Entry 152
    -0x1.80p-23,
    (int)-0x1.000003p24,
    -0x1.000002p24,
    0x1.fffffep-1
  },
  { // Entry 153
    -0.0,
    (int)-0x1.000002p24,
    -0x1.000002p24,
    0x1.p0
  },
  { // Entry 154
    -0.0,
    (int)-0x1.p24,
    -0x1.000002p24,
    0x1.000002p0
  },
  { // Entry 155
    -0x1.p-24,
    (int)-0x1.000001p24,
    -0x1.p24,
    0x1.fffffep-1
  },
  { // Entry 156
    -0.0,
    (int)-0x1.p24,
    -0x1.p24,
    0x1.p0
  },
  { // Entry 157
    -0x1.p-22,
    (int)-0x1.fffffcp23,
    -0x1.p24,
    0x1.000002p0
  },
  { // Entry 158
    -0.0,
    (int)-0x1.p24,
    -0x1.fffffep23,
    0x1.fffffep-1
  },
  { // Entry 159
    -0.0,
    (int)-0x1.fffffep23,
    -0x1.fffffep23,
    0x1.p0
  },
  { // Entry 160
    -0x1.80p-22,
    (int)-0x1.fffffap23,
    -0x1.fffffep23,
    0x1.000002p0
  },
  { // Entry 161
    0.0,
    (int)0x1.p22,
    0x1.fffffep21,
    0x1.fffffep-1
  },
  { // Entry 162
    -0x1.p-2,
    (int)0x1.p22,
    0x1.fffffep21,
    0x1.p0
  },
  { // Entry 163
    0x1.000008p-2,
    (int)0x1.fffff8p21,
    0x1.fffffep21,
    0x1.000002p0
  },
  { // Entry 164
    0x1.p-2,
    (int)0x1.p22,
    0x1.p22,
    0x1.fffffep-1
  },
  { // Entry 165
    0.0,
    (int)0x1.p22,
    0x1.p22,
    0x1.p0
  },
  { // Entry 166
    -0x1.p-1,
    (int)0x1.p22,
    0x1.p22,
    0x1.000002p0
  },
  { // Entry 167
    -0x1.fffff8p-3,
    (int)0x1.000004p22,
    0x1.000002p22,
    0x1.fffffep-1
  },
  { // Entry 168
    0x1.p-1,
    (int)0x1.p22,
    0x1.000002p22,
    0x1.p0
  },
  { // Entry 169
    0.0,
    (int)0x1.p22,
    0x1.000002p22,
    0x1.000002p0
  },
  { // Entry 170
    0.0,
    (int)0x1.p23,
    0x1.fffffep22,
    0x1.fffffep-1
  },
  { // Entry 171
    -0x1.p-1,
    (int)0x1.p23,
    0x1.fffffep22,
    0x1.p0
  },
  { // Entry 172
    -0x1.fffff8p-2,
    (int)0x1.fffffcp22,
    0x1.fffffep22,
    0x1.000002p0
  },
  { // Entry 173
    -0x1.fffffcp-2,
    (int)0x1.000002p23,
    0x1.p23,
    0x1.fffffep-1
  },
  { // Entry 174
    0.0,
    (int)0x1.p23,
    0x1.p23,
    0x1.p0
  },
  { // Entry 175
    0x1.p-23,
    (int)0x1.fffffcp22,
    0x1.p23,
    0x1.000002p0
  },
  { // Entry 176
    -0x1.fffff8p-2,
    (int)0x1.000004p23,
    0x1.000002p23,
    0x1.fffffep-1
  },
  { // Entry 177
    0.0,
    (int)0x1.000002p23,
    0x1.000002p23,
    0x1.p0
  },
  { // Entry 178
    0.0,
    (int)0x1.p23,
    0x1.000002p23,
    0x1.000002p0
  },
  { // Entry 179
    -0.0,
    (int)0x1.p24,
    -0x1.000002p24,
    -0x1.000002p0
  },
  { // Entry 180
    -0.0,
    (int)0x1.000002p24,
    -0x1.000002p24,
    -0x1.p0
  },
  { // Entry 181
    -0x1.80p-23,
    (int)0x1.000003p24,
    -0x1.000002p24,
    -0x1.fffffep-1
  },
  { // Entry 182
    -0x1.p-22,
    (int)0x1.fffffcp23,
    -0x1.p24,
    -0x1.000002p0
  },
  { // Entry 183
    -0.0,
    (int)0x1.p24,
    -0x1.p24,
    -0x1.p0
  },
  { // Entry 184
    -0x1.p-24,
    (int)0x1.000001p24,
    -0x1.p24,
    -0x1.fffffep-1
  },
  { // Entry 185
    -0x1.80p-22,
    (int)0x1.fffffap23,
    -0x1.fffffep23,
    -0x1.000002p0
  },
  { // Entry 186
    -0.0,
    (int)0x1.fffffep23,
    -0x1.fffffep23,
    -0x1.p0
  },
  { // Entry 187
    -0.0,
    (int)0x1.p24,
    -0x1.fffffep23,
    -0x1.fffffep-1
  },
  { // Entry 188
    0x1.fffffep127,
    (int)0.0,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 189
    -0x1.fffffep127,
    (int)0.0,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 190
    0x1.fffffep127,
    (int)0.0,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 191
    -0x1.fffffep127,
    (int)0.0,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 192
    0x1.p-126,
    (int)0.0,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 193
    -0x1.p-126,
    (int)0.0,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 194
    0x1.p-126,
    (int)0.0,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 195
    -0x1.p-126,
    (int)0.0,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 196
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 197
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 198
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 199
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 200
    0.0,
    (int)0.0,
    0.0f,
    HUGE_VALF
  },
  { // Entry 201
    -0.0,
    (int)0.0,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 202
    0.0,
    (int)0.0,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 203
    -0.0,
    (int)0.0,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 204
    0.0,
    (int)0x1.p0,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 205
    0.0,
    (int)-0x1.p0,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 206
    -0.0,
    (int)-0x1.p0,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 207
    -0.0,
    (int)0x1.p0,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 208
    0.0,
    (int)0.0,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 209
    0.0,
    (int)0.0,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 210
    -0.0,
    (int)0.0,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 211
    -0.0,
    (int)0.0,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 212
    0.0,
    (int)0.0,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 213
    0.0,
    (int)0.0,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 214
    -0.0,
    (int)0.0,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 215
    -0.0,
    (int)0.0,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 216
    0x1.p-126,
    (int)0.0,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 217
    -0x1.p-126,
    (int)0.0,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 218
    0x1.p-126,
    (int)0.0,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 219
    -0x1.p-126,
    (int)0.0,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 220
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 221
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 222
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 223
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 224
    0.0,
    (int)0.0,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 225
    -0.0,
    (int)0.0,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 226
    0.0,
    (int)0.0,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 227
    -0.0,
    (int)0.0,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 228
    0.0,
    (int)0x1.p0,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 229
    0.0,
    (int)-0x1.p0,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 230
    -0.0,
    (int)-0x1.p0,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 231
    -0.0,
    (int)0x1.p0,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 232
    0.0,
    (int)0x1.p23,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 233
    0.0,
    (int)-0x1.p23,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 234
    -0.0,
    (int)-0x1.p23,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 235
    -0.0,
    (int)0x1.p23,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 236
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 237
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 238
    0x1.p-149,
    (int)0.0,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 239
    -0x1.p-149,
    (int)0.0,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 240
    0.0,
    (int)0.0,
    0.0f,
    0x1.p-126
  },
  { // Entry 241
    -0.0,
    (int)0.0,
    -0.0f,
    0x1.p-126
  },
  { // Entry 242
    0.0,
    (int)0.0,
    0.0f,
    -0x1.p-126
  },
  { // Entry 243
    -0.0,
    (int)0.0,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 244
    0.0,
    (int)0x1.p0,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 245
    -0.0,
    (int)-0x1.p0,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 246
    0.0,
    (int)-0x1.p0,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 247
    -0.0,
    (int)0x1.p0,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 248
    0.0,
    (int)0.0,
    0.0f,
    0x1.p-149
  },
  { // Entry 249
    -0.0,
    (int)0.0,
    -0.0f,
    0x1.p-149
  },
  { // Entry 250
    0.0,
    (int)0.0,
    0.0f,
    -0x1.p-149
  },
  { // Entry 251
    -0.0,
    (int)0.0,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 252
    -0x1.p0,
    (int)0x1.p1,
    0x1.80p1,
    0x1.p1
  },
  { // Entry 253
    0x1.p0,
    (int)-0x1.p1,
    -0x1.80p1,
    0x1.p1
  },
  { // Entry 254
    -0x1.p0,
    (int)-0x1.p1,
    0x1.80p1,
    -0x1.p1
  },
  { // Entry 255
    0x1.p0,
    (int)0x1.p1,
    -0x1.80p1,
    -0x1.p1
  },
  { // Entry 256
    0x1.p0,
    (int)0x1.p1,
    0x1.40p2,
    0x1.p1
  },
  { // Entry 257
    -0x1.p0,
    (int)-0x1.p1,
    -0x1.40p2,
    0x1.p1
  },
  { // Entry 258
    0x1.p0,
    (int)-0x1.p1,
    0x1.40p2,
    -0x1.p1
  },
  { // Entry 259
    -0x1.p0,
    (int)0x1.p1,
    -0x1.40p2,
    -0x1.p1
  }
};
```
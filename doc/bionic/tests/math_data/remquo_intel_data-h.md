Response:
Let's break down the thought process to answer the request about the `remquo_intel_data.handroid` file.

1. **Understanding the Core Request:** The request is to analyze a C source code file, understand its purpose, relate it to Android, explain the functions, discuss dynamic linking, provide examples, and explain how to reach this code from Android.

2. **Initial File Analysis:** The file is named `remquo_intel_data.handroid`. The path `bionic/tests/math_data/` is a strong hint that this file contains *test data* for a math function. The name `remquo` strongly suggests it's related to the `remquo` function in the C standard library. The suffix `.handroid` might indicate it's specific to the Android environment or a variant of the data for a particular architecture. The copyright notice confirms it's part of the Android Open Source Project.

3. **Identifying the Data Structure:**  The code declares a static array `g_remquo_intel_data` of type `data_1_int_2_t<double, double, double>`. This is a template, likely defined elsewhere, but its structure is clear: it holds three `double` values and one `int`. Looking at the initialization, each element in the array represents a test case.

4. **Inferring the Purpose:** Each element in `g_remquo_intel_data` has the following structure based on the template instantiation:
   - `double` (input 1)
   - `int` (expected quotient sign and last bits)
   - `double` (input 2 - divisor)
   - `double` (expected remainder)

   This structure directly matches the inputs and outputs of the `remquo` function, which calculates both the remainder and a part of the quotient. Therefore, this file holds test data to verify the correctness of the `remquo` function. The "intel" part of the filename likely suggests these tests might be specific to Intel architectures or derived from Intel's math library.

5. **Connecting to Android:** The file is part of Bionic, Android's C library. The `remquo` function is a standard C library function that Bionic must provide. This file is directly used to test the Bionic implementation of `remquo`.

6. **Explaining `remquo` Functionality:**
   - **Core Function:** Calculate the remainder of a division.
   - **Key Difference from `%`:** `remquo` *also* provides a part of the quotient's sign and some of its least significant bits.
   - **Use Cases:** Situations where both the remainder and some information about the quotient are needed simultaneously for efficiency or specific algorithm requirements.

7. **Dynamic Linker Aspect (Initial Thought - Later Refined):**  Initially, one might think this file itself doesn't directly involve the dynamic linker. It's just data. However, the *execution* of the `remquo` function, which this data tests, *does* involve the dynamic linker. The `remquo` function is part of `libc.so`, and when a program calls it, the dynamic linker resolves the symbol and loads the library (if it's not already loaded).

8. **Dynamic Linker Details (Refined and Added):**
   - **SO Layout:**  Need to visualize how `libc.so` is laid out in memory. It will contain sections like `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), `.dynsym` (dynamic symbols), etc.
   - **Linking Process:**  Explain the steps: symbol resolution, relocation, etc.

9. **Logic and Examples:**
   - Provide a concrete example of a test case from the file and how it relates to the `remquo` function's inputs and outputs. Explain the interpretation of the integer quotient part.

10. **Common Usage Errors:**
    - Incorrectly assuming `remquo` is the same as the modulo operator (`%`).
    - Ignoring the integer quotient output.
    - Not handling potential floating-point exceptions.

11. **Android Framework/NDK Path and Frida Hook:**
    - **Framework:** A high-level Java app calling a native method via JNI. The native method then calls `remquo`.
    - **NDK:** Direct C/C++ code calling `remquo`.
    - **Frida Hook:** Demonstrate how to intercept the `remquo` call and inspect the arguments and return values. This requires knowing the function signature.

12. **Structuring the Answer:**  Organize the information logically with clear headings and explanations for each part of the request. Use code blocks for the example and Frida snippet.

13. **Refinement and Review:** Read through the answer to ensure accuracy, clarity, and completeness. For instance, double-check the explanation of the integer quotient returned by `remquo`. Ensure the dynamic linking explanation is accurate and relevant. Make sure the Frida example is functional and understandable. Initially, I might have focused too much on the *data file* and not enough on the *function* being tested, so the refinement step helps correct that balance. Also, ensure all parts of the original request are addressed. For example, the request explicitly asks about the *implementation* of the libc function, which would involve pointing to the source code of `remquo` in Bionic (though the data file itself doesn't contain the implementation).

This iterative process of analyzing the code, inferring its purpose, connecting it to Android concepts, explaining related functionalities, and providing concrete examples leads to the comprehensive answer provided previously.
这个目录 `bionic/tests/math_data/remquo_intel_data.handroid` 下的源代码文件，名为 `remquo_intel_data.handroid`，其主要功能是 **提供 `remquo` 函数的测试数据**。

**功能列举:**

1. **存储测试用例:** 该文件定义了一个静态数组 `g_remquo_intel_data`，其中包含了大量的测试用例。
2. **测试 `remquo` 函数:** 这些测试用例旨在验证 `bionic` 库中 `remquo` 函数的正确性。
3. **覆盖不同输入:**  测试用例覆盖了 `remquo` 函数可能接收的各种输入值，包括正常值、边界值（如 0, 正负无穷大，NaN）、极小值等。
4. **预期结果:** 每个测试用例都包含了预期的输出结果，用于与 `remquo` 函数的实际输出进行比较，从而判断函数是否正确。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 的底层 C 库 `bionic` 的功能。`remquo` 是一个标准的 C 库函数，用于计算浮点数的余数和部分商。Android 应用和系统服务在底层进行数学运算时，可能会间接或直接地调用 `remquo` 函数。

**举例说明:**

假设一个 Android 应用需要实现一个复杂的动画效果，其中涉及到角度的计算和规范化。`remquo` 函数可以用来计算角度对 360 度的余数，并同时获取部分商的符号信息，这在某些算法中可能很有用。虽然开发者通常不会直接调用 `remquo`，但底层的图形库或数学库可能会使用它。

**详细解释 `libc` 函数 `remquo` 的功能及实现:**

`remquo` 函数的功能是计算 `x / y` 的浮点余数，并返回该余数。同时，它还会将商的最低几位（至少三位）的符号存储在 `*quo` 指向的整数中。

**函数签名:**

```c
double remquo(double x, double y, int *quo);
```

**参数:**

* `x`: 被除数 (double)。
* `y`: 除数 (double)。
* `quo`: 指向一个整数的指针，用于存储部分商的符号信息。

**返回值:**

* `x` 除以 `y` 的浮点余数。余数的绝对值小于除数 `y` 的绝对值。余数的符号与被除数 `x` 的符号相同。

**实现原理 (在 `bionic` 中):**

由于 `remquo_intel_data.handroid` 是测试数据，它本身不包含 `remquo` 函数的实现。`remquo` 函数的具体实现位于 `bionic` 库的其他源文件中 (例如 `bionic/libc/math/remquo.c` 或其架构相关的变体)。

`remquo` 的实现通常会涉及以下步骤：

1. **处理特殊情况:**  处理 `y` 为 0，`x` 或 `y` 为无穷大或 NaN 等特殊情况。
2. **计算精确商:** 计算 `x / y` 的精确商。
3. **确定整数商:**  根据需要返回的商的位数，将精确商舍入到最接近的整数。
4. **计算余数:** 使用公式 `remainder = x - quotient * y` 计算余数。
5. **存储部分商:** 将整数商的最低几位（通常使用位运算）和符号存储到 `*quo` 指向的内存中。

**对于涉及 dynamic linker 的功能：**

这个特定的数据文件 `remquo_intel_data.handroid` 本身不直接涉及 dynamic linker 的功能。它的作用是在测试阶段验证已经链接到程序中的 `remquo` 函数的正确性。

但是，`remquo` 函数本身位于 `libc.so` 中，当一个程序调用 `remquo` 时，dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 负责将 `libc.so` 加载到进程的地址空间，并解析 `remquo` 函数的符号。

**so 布局样本 (libc.so 的部分布局):**

```
libc.so:
    LOAD 0x... // 可执行代码段
        .text:  // 包含 remquo 等函数的机器码
            remquo:
                ... // remquo 函数的指令
    LOAD 0x... // 数据段
        .data:  // 已初始化的全局变量
        .bss:   // 未初始化的全局变量
    DYNAMIC: // 动态链接信息
        NEEDED libc++.so
        SONAME libc.so
        SYMTAB  // 符号表
            remquo (address)
        STRTAB  // 字符串表
            remquo
            ...
```

**链接的处理过程:**

1. **程序加载:** 当 Android 启动一个应用或进程时，操作系统加载可执行文件。
2. **依赖分析:**  dynamic linker 分析可执行文件的 `PT_DYNAMIC` 段，找到其依赖的共享库，例如 `libc.so`。
3. **加载共享库:** dynamic linker 将 `libc.so` 加载到进程的地址空间。
4. **符号解析:** 当程序调用 `remquo` 函数时，dynamic linker 在 `libc.so` 的符号表 (`.dynsym`) 中查找 `remquo` 的地址。
5. **重定位:**  由于共享库在内存中的加载地址可能每次都不同，dynamic linker 需要修改程序中对 `remquo` 的调用地址，使其指向 `libc.so` 中 `remquo` 的实际地址。这个过程称为重定位。
6. **执行:**  完成链接后，程序就可以成功调用 `libc.so` 中的 `remquo` 函数。

**逻辑推理、假设输入与输出:**

该文件中的每个条目都是一个测试用例，可以看作一个假设输入和预期的输出。例如，对于第一个条目：

**假设输入:**

* 被除数 `x`: `0x1.42967268315ap-13` (十进制约 0.000152587890625)
* 除数 `y`: `-0x1.p1` (十进制 -2.0)

**预期输出:**

* 余数: `0x1.2852ce4d062b4p-11` (十进制约 0.000445556640625)
* 部分商 (存储在 `quo` 中): `-1`

**逻辑推理:**

`0.000152587890625 / -2.0` 的商非常小且为负数。余数的计算遵循浮点数余数的定义。部分商 `-1` 表示最接近的整数商是 `-1` 或 `0`，具体取决于 `remquo` 的实现方式，通常会选择使余数与被除数符号相同的商。

**用户或编程常见的使用错误:**

1. **误解 `remquo` 和 `%` 运算符的区别:**  `%` 运算符用于整数的模运算，而 `remquo` 用于浮点数。它们的功能不同。
2. **忽略 `quo` 参数:** 开发者可能只关注余数，而忽略了 `remquo` 提供的部分商信息，导致错过一些有用的信息。
3. **假设 `quo` 的所有位都有意义:**  `remquo` 只保证 `quo` 中存储的是部分商的最低几位，具体位数取决于实现。开发者不应该假设可以从中提取出完整的商。
4. **精度问题:** 浮点数运算本身存在精度问题，使用 `remquo` 时需要注意这些问题，并避免进行严格的相等性比较。

**Android framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 层):**
   - 开发者可能使用 Java 中的 `Math` 类进行一些数学运算，但 `Math` 类本身并没有直接对应 `remquo` 的方法。
   - 更可能的情况是，Framework 中的某些底层组件（例如图形渲染、物理引擎等）在 Native 层使用了 `remquo`。

2. **NDK (Native 层 - C/C++):**
   - 使用 NDK 开发的 App 或库可以直接调用 `remquo` 函数。
   - 开发者需要包含 `<math.h>` 头文件。
   - 当编译 Native 代码时，链接器会将代码链接到 `libc.so`，其中包含了 `remquo` 的实现。

**Frida hook 示例调试这些步骤:**

假设我们想 hook Android 系统库中的 `remquo` 函数，查看其输入和输出。以下是一个 Frida hook 的示例：

```javascript
// hook_remquo.js

if (Process.arch === 'arm64') {
  var remquoPtr = Module.findExportByName("libc.so", "remquo");

  if (remquoPtr) {
    Interceptor.attach(remquoPtr, {
      onEnter: function(args) {
        this.x = args[0].readDouble();
        this.y = args[1].readDouble();
        console.log("[remquo] Entering: x = " + this.x + ", y = " + this.y);
      },
      onLeave: function(retval) {
        var quoPtr = this.context.sp.add(8 * 2); // quo 参数在栈上的位置 (arm64)
        var quo = quoPtr.readS32();
        var remainder = retval.readDouble();
        console.log("[remquo] Leaving: remainder = " + remainder + ", *quo = " + quo);
      }
    });
    console.log("[Frida] Hooked remquo at " + remquoPtr);
  } else {
    console.log("[Frida] Failed to find remquo in libc.so");
  }
} else {
  console.log("[Frida] This script is for arm64 architecture.");
}
```

**使用方法:**

1. 将上述代码保存为 `hook_remquo.js`。
2. 使用 Frida 连接到目标 Android 进程 (例如，一个正在进行复杂数学运算的 App)：
   ```bash
   frida -U -f <package_name> -l hook_remquo.js --no-pause
   ```
   或者连接到正在运行的进程：
   ```bash
   frida -U <process_id> -l hook_remquo.js
   ```
3. 当目标进程调用 `remquo` 函数时，Frida 将会拦截调用，并打印出输入参数 (`x`, `y`) 和返回值 (`remainder`) 以及 `quo` 指向的值。

**解释 Frida hook 代码:**

* **`Process.arch === 'arm64'`:** 检查当前进程的架构，这里假设是 `arm64`。
* **`Module.findExportByName("libc.so", "remquo")`:** 在 `libc.so` 中查找 `remquo` 函数的地址。
* **`Interceptor.attach(remquoPtr, { ... })`:**  拦截 `remquo` 函数的调用。
* **`onEnter`:** 在函数调用前执行，读取 `x` 和 `y` 的值。
* **`onLeave`:** 在函数调用后执行，读取返回值（余数）和 `quo` 指向的整数值。由于 ABI 的不同，`quo` 参数通常通过寄存器或栈传递，这里针对 `arm64` 架构，假设它位于栈上的特定位置。你需要根据目标架构的调用约定调整获取 `quo` 值的方式。
* **`console.log`:** 打印调试信息。

这个 Frida 示例可以帮助我们理解在 Android 平台上，哪些应用或系统组件在底层使用了 `remquo` 函数，并观察其具体的输入和输出，从而进行更深入的调试和分析。

### 提示词
```
这是目录为bionic/tests/math_data/remquo_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_int_2_t<double, double, double> g_remquo_intel_data[] = {
  { // Entry 0
    0x1.42967268315ap-13,
    (int)-0x1.p1,
    -0x1.0p-10,
    0x1.2852ce4d062b4p-11
  },
  { // Entry 1
    0x1.1ab75504464440p14,
    (int)0x1.6a3b3618p30,
    0x1.0295fad40a57fp117,
    0x1.45d1745d17465p15
  },
  { // Entry 2
    -0x1.d1a777081861p18,
    (int)-0x1.0f62d4b8p30,
    0x1.11f783ee89b08p99,
    -0x1.fd6ef47d96f1cp19
  },
  { // Entry 3
    -0x1.b0p3,
    (int)-0x1.afe501b0p29,
    0x1.ffffffffffffbp1023,
    -0x1.001p10
  },
  { // Entry 4
    -0x1.7d9165c00024p9,
    (int)0x1.dd000030p29,
    0x1.ffffffffffffbp1023,
    0x1.0000000000003p14
  },
  { // Entry 5
    -0x1.p-17,
    (int)0.0,
    0x1.ffffffffffffdp1023,
    0x1.ffffffffffffep-2
  },
  { // Entry 6
    -0.0,
    (int)0x1.p0,
    -0x1.0p-117,
    -0x1.0p-117
  },
  { // Entry 7
    -0.0,
    (int)-0x1.p0,
    -0x1.0p-117,
    0x1.0p-117
  },
  { // Entry 8
    0.0,
    (int)-0x1.p0,
    0x1.0p-117,
    -0x1.0p-117
  },
  { // Entry 9
    0.0,
    (int)0x1.p0,
    0x1.0p-117,
    0x1.0p-117
  },
  { // Entry 10
    -0x1.p-117,
    (int)0.0,
    -0x1.0p-117,
    0x1.0p15
  },
  { // Entry 11
    -0x1.p-117,
    (int)0.0,
    -0x1.0p-117,
    0x1.0p16
  },
  { // Entry 12
    0x1.p-117,
    (int)0.0,
    0x1.0p-117,
    0x1.0p15
  },
  { // Entry 13
    0x1.p-117,
    (int)0.0,
    0x1.0p-117,
    0x1.0p16
  },
  { // Entry 14
    -0x1.p-117,
    (int)0.0,
    -0x1.0p-117,
    0x1.0p117
  },
  { // Entry 15
    -0x1.p-117,
    (int)0.0,
    -0x1.0p-117,
    0x1.0p118
  },
  { // Entry 16
    0x1.p-117,
    (int)0.0,
    0x1.0p-117,
    0x1.0p117
  },
  { // Entry 17
    0x1.p-117,
    (int)0.0,
    0x1.0p-117,
    0x1.0p118
  },
  { // Entry 18
    0.0,
    (int)0.0,
    0x1.0p15,
    -0x1.0p-117
  },
  { // Entry 19
    0.0,
    (int)0.0,
    0x1.0p15,
    0x1.0p-117
  },
  { // Entry 20
    0.0,
    (int)0.0,
    0x1.0p16,
    -0x1.0p-117
  },
  { // Entry 21
    0.0,
    (int)0.0,
    0x1.0p16,
    0x1.0p-117
  },
  { // Entry 22
    0.0,
    (int)0x1.p0,
    0x1.0p15,
    0x1.0p15
  },
  { // Entry 23
    0x1.p15,
    (int)0.0,
    0x1.0p15,
    0x1.0p16
  },
  { // Entry 24
    0.0,
    (int)0x1.p1,
    0x1.0p16,
    0x1.0p15
  },
  { // Entry 25
    0.0,
    (int)0x1.p0,
    0x1.0p16,
    0x1.0p16
  },
  { // Entry 26
    0x1.p15,
    (int)0.0,
    0x1.0p15,
    0x1.0p117
  },
  { // Entry 27
    0x1.p15,
    (int)0.0,
    0x1.0p15,
    0x1.0p118
  },
  { // Entry 28
    0x1.p16,
    (int)0.0,
    0x1.0p16,
    0x1.0p117
  },
  { // Entry 29
    0x1.p16,
    (int)0.0,
    0x1.0p16,
    0x1.0p118
  },
  { // Entry 30
    0.0,
    (int)0.0,
    0x1.0p117,
    -0x1.0p-117
  },
  { // Entry 31
    0.0,
    (int)0.0,
    0x1.0p117,
    0x1.0p-117
  },
  { // Entry 32
    0.0,
    (int)0.0,
    0x1.0p118,
    -0x1.0p-117
  },
  { // Entry 33
    0.0,
    (int)0.0,
    0x1.0p118,
    0x1.0p-117
  },
  { // Entry 34
    0.0,
    (int)0.0,
    0x1.0p117,
    0x1.0p15
  },
  { // Entry 35
    0.0,
    (int)0.0,
    0x1.0p117,
    0x1.0p16
  },
  { // Entry 36
    0.0,
    (int)0.0,
    0x1.0p118,
    0x1.0p15
  },
  { // Entry 37
    0.0,
    (int)0.0,
    0x1.0p118,
    0x1.0p16
  },
  { // Entry 38
    0.0,
    (int)0x1.p0,
    0x1.0p117,
    0x1.0p117
  },
  { // Entry 39
    0x1.p117,
    (int)0.0,
    0x1.0p117,
    0x1.0p118
  },
  { // Entry 40
    0.0,
    (int)0x1.p1,
    0x1.0p118,
    0x1.0p117
  },
  { // Entry 41
    0.0,
    (int)0x1.p0,
    0x1.0p118,
    0x1.0p118
  },
  { // Entry 42
    0.0,
    (int)0x1.40p3,
    0x1.9p6,
    0x1.4p3
  },
  { // Entry 43
    0x1.p0,
    (int)0x1.20p3,
    0x1.9p6,
    0x1.6p3
  },
  { // Entry 44
    0x1.p2,
    (int)0x1.p3,
    0x1.9p6,
    0x1.8p3
  },
  { // Entry 45
    0x1.p0,
    (int)0x1.40p3,
    0x1.940p6,
    0x1.4p3
  },
  { // Entry 46
    0x1.p1,
    (int)0x1.20p3,
    0x1.940p6,
    0x1.6p3
  },
  { // Entry 47
    0x1.40p2,
    (int)0x1.p3,
    0x1.940p6,
    0x1.8p3
  },
  { // Entry 48
    0x1.p1,
    (int)0x1.40p3,
    0x1.980p6,
    0x1.4p3
  },
  { // Entry 49
    0x1.80p1,
    (int)0x1.20p3,
    0x1.980p6,
    0x1.6p3
  },
  { // Entry 50
    0x1.80p2,
    (int)0x1.p3,
    0x1.980p6,
    0x1.8p3
  },
  { // Entry 51
    0x1.80p1,
    (int)0x1.40p3,
    0x1.9c0p6,
    0x1.4p3
  },
  { // Entry 52
    0x1.p2,
    (int)0x1.20p3,
    0x1.9c0p6,
    0x1.6p3
  },
  { // Entry 53
    -0x1.40p2,
    (int)0x1.20p3,
    0x1.9c0p6,
    0x1.8p3
  },
  { // Entry 54
    0x1.p2,
    (int)0x1.40p3,
    0x1.ap6,
    0x1.4p3
  },
  { // Entry 55
    0x1.40p2,
    (int)0x1.20p3,
    0x1.ap6,
    0x1.6p3
  },
  { // Entry 56
    -0x1.p2,
    (int)0x1.20p3,
    0x1.ap6,
    0x1.8p3
  },
  { // Entry 57
    0x1.40p2,
    (int)0x1.40p3,
    0x1.a40p6,
    0x1.4p3
  },
  { // Entry 58
    -0x1.40p2,
    (int)0x1.40p3,
    0x1.a40p6,
    0x1.6p3
  },
  { // Entry 59
    -0x1.80p1,
    (int)0x1.20p3,
    0x1.a40p6,
    0x1.8p3
  },
  { // Entry 60
    -0x1.p2,
    (int)0x1.60p3,
    0x1.a80p6,
    0x1.4p3
  },
  { // Entry 61
    -0x1.p2,
    (int)0x1.40p3,
    0x1.a80p6,
    0x1.6p3
  },
  { // Entry 62
    -0x1.p1,
    (int)0x1.20p3,
    0x1.a80p6,
    0x1.8p3
  },
  { // Entry 63
    -0x1.80p1,
    (int)0x1.60p3,
    0x1.ac0p6,
    0x1.4p3
  },
  { // Entry 64
    -0x1.80p1,
    (int)0x1.40p3,
    0x1.ac0p6,
    0x1.6p3
  },
  { // Entry 65
    -0x1.p0,
    (int)0x1.20p3,
    0x1.ac0p6,
    0x1.8p3
  },
  { // Entry 66
    -0x1.p1,
    (int)0x1.60p3,
    0x1.bp6,
    0x1.4p3
  },
  { // Entry 67
    -0x1.p1,
    (int)0x1.40p3,
    0x1.bp6,
    0x1.6p3
  },
  { // Entry 68
    0.0,
    (int)0x1.20p3,
    0x1.bp6,
    0x1.8p3
  },
  { // Entry 69
    -0x1.p0,
    (int)0x1.60p3,
    0x1.b40p6,
    0x1.4p3
  },
  { // Entry 70
    -0x1.p0,
    (int)0x1.40p3,
    0x1.b40p6,
    0x1.6p3
  },
  { // Entry 71
    0x1.p0,
    (int)0x1.20p3,
    0x1.b40p6,
    0x1.8p3
  },
  { // Entry 72
    0.0,
    (int)0x1.60p3,
    0x1.b80p6,
    0x1.4p3
  },
  { // Entry 73
    0.0,
    (int)0x1.40p3,
    0x1.b80p6,
    0x1.6p3
  },
  { // Entry 74
    0x1.p1,
    (int)0x1.20p3,
    0x1.b80p6,
    0x1.8p3
  },
  { // Entry 75
    -0.0,
    (int)0x1.p0,
    -0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 76
    -0x1.p-52,
    (int)0x1.p0,
    -0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 77
    -0x1.80p-52,
    (int)0x1.p0,
    -0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 78
    0x1.p-52,
    (int)0x1.p0,
    -0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 79
    -0.0,
    (int)0x1.p0,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 80
    -0x1.p-53,
    (int)0x1.p0,
    -0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 81
    0x1.80p-52,
    (int)0x1.p0,
    -0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 82
    0x1.p-53,
    (int)0x1.p0,
    -0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 83
    -0.0,
    (int)0x1.p0,
    -0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 84
    -0x1.80p-52,
    (int)-0x1.p0,
    -0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 85
    -0x1.p-52,
    (int)-0x1.p0,
    -0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 86
    -0.0,
    (int)-0x1.p0,
    -0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 87
    -0x1.p-53,
    (int)-0x1.p0,
    -0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 88
    -0.0,
    (int)-0x1.p0,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 89
    0x1.p-52,
    (int)-0x1.p0,
    -0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 90
    -0.0,
    (int)-0x1.p0,
    -0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 91
    0x1.p-53,
    (int)-0x1.p0,
    -0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 92
    0x1.80p-52,
    (int)-0x1.p0,
    -0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 93
    -0x1.80p-52,
    (int)-0x1.p0,
    0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 94
    -0x1.p-53,
    (int)-0x1.p0,
    0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 95
    0.0,
    (int)-0x1.p0,
    0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 96
    -0x1.p-52,
    (int)-0x1.p0,
    0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 97
    0.0,
    (int)-0x1.p0,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 98
    0x1.p-53,
    (int)-0x1.p0,
    0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 99
    0.0,
    (int)-0x1.p0,
    0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 100
    0x1.p-52,
    (int)-0x1.p0,
    0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 101
    0x1.80p-52,
    (int)-0x1.p0,
    0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 102
    0.0,
    (int)0x1.p0,
    0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 103
    -0x1.p-53,
    (int)0x1.p0,
    0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 104
    -0x1.80p-52,
    (int)0x1.p0,
    0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 105
    0x1.p-53,
    (int)0x1.p0,
    0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 106
    0.0,
    (int)0x1.p0,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 107
    -0x1.p-52,
    (int)0x1.p0,
    0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 108
    0x1.80p-52,
    (int)0x1.p0,
    0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 109
    0x1.p-52,
    (int)0x1.p0,
    0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 110
    0.0,
    (int)0x1.p0,
    0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 111
    -0.0,
    (int)-0x1.p0,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 112
    -0.0,
    (int)0.0,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 113
    0.0,
    (int)0x1.p0,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 114
    -0.0,
    (int)0x1.p0,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 115
    -0.0,
    (int)0.0,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 116
    0.0,
    (int)-0x1.p0,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 117
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 118
    -0.0,
    (int)0.0,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 119
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 120
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 121
    -0.0,
    (int)0.0,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 122
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 123
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 124
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 125
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 126
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 127
    0.0,
    (int)0.0,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 128
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 129
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 130
    0.0,
    (int)0.0,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 131
    0.0,
    (int)0x1.p0,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 132
    0.0,
    (int)-0x1.p0,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 133
    -0.0,
    (int)-0x1.p0,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 134
    -0.0,
    (int)0x1.p0,
    -0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 135
    0x1.ffffffffffffc0p-3,
    (int)-0x1.p0,
    -0x1.0000000000001p51,
    0x1.fffffffffffffp-1
  },
  { // Entry 136
    -0x1.p-1,
    (int)0.0,
    -0x1.0000000000001p51,
    0x1.0p0
  },
  { // Entry 137
    -0.0,
    (int)0.0,
    -0x1.0000000000001p51,
    0x1.0000000000001p0
  },
  { // Entry 138
    -0x1.p-2,
    (int)0.0,
    -0x1.0p51,
    0x1.fffffffffffffp-1
  },
  { // Entry 139
    -0.0,
    (int)0.0,
    -0x1.0p51,
    0x1.0p0
  },
  { // Entry 140
    0x1.p-1,
    (int)0.0,
    -0x1.0p51,
    0x1.0000000000001p0
  },
  { // Entry 141
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp50,
    0x1.fffffffffffffp-1
  },
  { // Entry 142
    0x1.p-2,
    (int)0.0,
    -0x1.fffffffffffffp50,
    0x1.0p0
  },
  { // Entry 143
    -0x1.00000000000040p-2,
    (int)-0x1.fffffffcp30,
    -0x1.fffffffffffffp50,
    0x1.0000000000001p0
  },
  { // Entry 144
    0.0,
    (int)0.0,
    0x1.fffffffffffffp51,
    0x1.fffffffffffffp-1
  },
  { // Entry 145
    -0x1.p-1,
    (int)0.0,
    0x1.fffffffffffffp51,
    0x1.0p0
  },
  { // Entry 146
    -0x1.ffffffffffffc0p-2,
    (int)0x1.fffffffcp30,
    0x1.fffffffffffffp51,
    0x1.0000000000001p0
  },
  { // Entry 147
    -0x1.ffffffffffffe0p-2,
    (int)0x1.p0,
    0x1.0p52,
    0x1.fffffffffffffp-1
  },
  { // Entry 148
    0.0,
    (int)0.0,
    0x1.0p52,
    0x1.0p0
  },
  { // Entry 149
    0x1.p-52,
    (int)0x1.fffffffcp30,
    0x1.0p52,
    0x1.0000000000001p0
  },
  { // Entry 150
    -0x1.ffffffffffffc0p-2,
    (int)0x1.p1,
    0x1.0000000000001p52,
    0x1.fffffffffffffp-1
  },
  { // Entry 151
    0.0,
    (int)0x1.p0,
    0x1.0000000000001p52,
    0x1.0p0
  },
  { // Entry 152
    0.0,
    (int)0.0,
    0x1.0000000000001p52,
    0x1.0000000000001p0
  },
  { // Entry 153
    -0x1.80p-52,
    (int)-0x1.80p1,
    -0x1.0000000000001p53,
    0x1.fffffffffffffp-1
  },
  { // Entry 154
    -0.0,
    (int)-0x1.p1,
    -0x1.0000000000001p53,
    0x1.0p0
  },
  { // Entry 155
    -0.0,
    (int)0.0,
    -0x1.0000000000001p53,
    0x1.0000000000001p0
  },
  { // Entry 156
    -0x1.p-53,
    (int)-0x1.p0,
    -0x1.0p53,
    0x1.fffffffffffffp-1
  },
  { // Entry 157
    -0.0,
    (int)0.0,
    -0x1.0p53,
    0x1.0p0
  },
  { // Entry 158
    -0x1.p-51,
    (int)-0x1.fffffff8p30,
    -0x1.0p53,
    0x1.0000000000001p0
  },
  { // Entry 159
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp52,
    0x1.fffffffffffffp-1
  },
  { // Entry 160
    -0.0,
    (int)-0x1.fffffffcp30,
    -0x1.fffffffffffffp52,
    0x1.0p0
  },
  { // Entry 161
    -0x1.80p-51,
    (int)-0x1.fffffff4p30,
    -0x1.fffffffffffffp52,
    0x1.0000000000001p0
  },
  { // Entry 162
    0.0,
    (int)0.0,
    0x1.fffffffffffffp50,
    0x1.fffffffffffffp-1
  },
  { // Entry 163
    -0x1.p-2,
    (int)0.0,
    0x1.fffffffffffffp50,
    0x1.0p0
  },
  { // Entry 164
    0x1.00000000000040p-2,
    (int)0x1.fffffffcp30,
    0x1.fffffffffffffp50,
    0x1.0000000000001p0
  },
  { // Entry 165
    0x1.p-2,
    (int)0.0,
    0x1.0p51,
    0x1.fffffffffffffp-1
  },
  { // Entry 166
    0.0,
    (int)0.0,
    0x1.0p51,
    0x1.0p0
  },
  { // Entry 167
    -0x1.p-1,
    (int)0.0,
    0x1.0p51,
    0x1.0000000000001p0
  },
  { // Entry 168
    -0x1.ffffffffffffc0p-3,
    (int)0x1.p0,
    0x1.0000000000001p51,
    0x1.fffffffffffffp-1
  },
  { // Entry 169
    0x1.p-1,
    (int)0.0,
    0x1.0000000000001p51,
    0x1.0p0
  },
  { // Entry 170
    0.0,
    (int)0.0,
    0x1.0000000000001p51,
    0x1.0000000000001p0
  },
  { // Entry 171
    0.0,
    (int)0.0,
    0x1.fffffffffffffp51,
    0x1.fffffffffffffp-1
  },
  { // Entry 172
    -0x1.p-1,
    (int)0.0,
    0x1.fffffffffffffp51,
    0x1.0p0
  },
  { // Entry 173
    -0x1.ffffffffffffc0p-2,
    (int)0x1.fffffffcp30,
    0x1.fffffffffffffp51,
    0x1.0000000000001p0
  },
  { // Entry 174
    -0x1.ffffffffffffe0p-2,
    (int)0x1.p0,
    0x1.0p52,
    0x1.fffffffffffffp-1
  },
  { // Entry 175
    0.0,
    (int)0.0,
    0x1.0p52,
    0x1.0p0
  },
  { // Entry 176
    0x1.p-52,
    (int)0x1.fffffffcp30,
    0x1.0p52,
    0x1.0000000000001p0
  },
  { // Entry 177
    -0x1.ffffffffffffc0p-2,
    (int)0x1.p1,
    0x1.0000000000001p52,
    0x1.fffffffffffffp-1
  },
  { // Entry 178
    0.0,
    (int)0x1.p0,
    0x1.0000000000001p52,
    0x1.0p0
  },
  { // Entry 179
    0.0,
    (int)0.0,
    0x1.0000000000001p52,
    0x1.0000000000001p0
  },
  { // Entry 180
    -0.0,
    (int)0.0,
    -0x1.0000000000001p53,
    -0x1.0000000000001p0
  },
  { // Entry 181
    -0.0,
    (int)0x1.p1,
    -0x1.0000000000001p53,
    -0x1.0p0
  },
  { // Entry 182
    -0x1.80p-52,
    (int)0x1.80p1,
    -0x1.0000000000001p53,
    -0x1.fffffffffffffp-1
  },
  { // Entry 183
    -0x1.p-51,
    (int)0x1.fffffff8p30,
    -0x1.0p53,
    -0x1.0000000000001p0
  },
  { // Entry 184
    -0.0,
    (int)0.0,
    -0x1.0p53,
    -0x1.0p0
  },
  { // Entry 185
    -0x1.p-53,
    (int)0x1.p0,
    -0x1.0p53,
    -0x1.fffffffffffffp-1
  },
  { // Entry 186
    -0x1.80p-51,
    (int)0x1.fffffff4p30,
    -0x1.fffffffffffffp52,
    -0x1.0000000000001p0
  },
  { // Entry 187
    -0.0,
    (int)0x1.fffffffcp30,
    -0x1.fffffffffffffp52,
    -0x1.0p0
  },
  { // Entry 188
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp52,
    -0x1.fffffffffffffp-1
  },
  { // Entry 189
    0x1.fffffffffffff0p1023,
    (int)0.0,
    0x1.fffffffffffffp1023,
    HUGE_VAL
  },
  { // Entry 190
    -0x1.fffffffffffff0p1023,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    HUGE_VAL
  },
  { // Entry 191
    0x1.fffffffffffff0p1023,
    (int)0.0,
    0x1.fffffffffffffp1023,
    -HUGE_VAL
  },
  { // Entry 192
    -0x1.fffffffffffff0p1023,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    -HUGE_VAL
  },
  { // Entry 193
    0x1.p-1022,
    (int)0.0,
    0x1.0p-1022,
    HUGE_VAL
  },
  { // Entry 194
    -0x1.p-1022,
    (int)0.0,
    -0x1.0p-1022,
    HUGE_VAL
  },
  { // Entry 195
    0x1.p-1022,
    (int)0.0,
    0x1.0p-1022,
    -HUGE_VAL
  },
  { // Entry 196
    -0x1.p-1022,
    (int)0.0,
    -0x1.0p-1022,
    -HUGE_VAL
  },
  { // Entry 197
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    HUGE_VAL
  },
  { // Entry 198
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    HUGE_VAL
  },
  { // Entry 199
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    -HUGE_VAL
  },
  { // Entry 200
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    -HUGE_VAL
  },
  { // Entry 201
    0.0,
    (int)0.0,
    0.0,
    HUGE_VAL
  },
  { // Entry 202
    -0.0,
    (int)0.0,
    -0.0,
    HUGE_VAL
  },
  { // Entry 203
    0.0,
    (int)0.0,
    0.0,
    -HUGE_VAL
  },
  { // Entry 204
    -0.0,
    (int)0.0,
    -0.0,
    -HUGE_VAL
  },
  { // Entry 205
    0.0,
    (int)0x1.p0,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 206
    0.0,
    (int)-0x1.p0,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 207
    -0.0,
    (int)-0x1.p0,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 208
    -0.0,
    (int)0x1.p0,
    -0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 209
    0.0,
    (int)0.0,
    0x1.fffffffffffffp1023,
    0x1.0p-1022
  },
  { // Entry 210
    0.0,
    (int)0.0,
    0x1.fffffffffffffp1023,
    -0x1.0p-1022
  },
  { // Entry 211
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    0x1.0p-1022
  },
  { // Entry 212
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1022
  },
  { // Entry 213
    0.0,
    (int)0.0,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 214
    0.0,
    (int)0.0,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 215
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 216
    -0.0,
    (int)0.0,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 217
    0x1.p-1022,
    (int)0.0,
    0x1.0p-1022,
    0x1.fffffffffffffp1023
  },
  { // Entry 218
    -0x1.p-1022,
    (int)0.0,
    -0x1.0p-1022,
    0x1.fffffffffffffp1023
  },
  { // Entry 219
    0x1.p-1022,
    (int)0.0,
    0x1.0p-1022,
    -0x1.fffffffffffffp1023
  },
  { // Entry 220
    -0x1.p-1022,
    (int)0.0,
    -0x1.0p-1022,
    -0x1.fffffffffffffp1023
  },
  { // Entry 221
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 222
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 223
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 224
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 225
    0.0,
    (int)0.0,
    0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 226
    -0.0,
    (int)0.0,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 227
    0.0,
    (int)0.0,
    0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 228
    -0.0,
    (int)0.0,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 229
    0.0,
    (int)0x1.p0,
    0x1.0p-1022,
    0x1.0p-1022
  },
  { // Entry 230
    0.0,
    (int)-0x1.p0,
    0x1.0p-1022,
    -0x1.0p-1022
  },
  { // Entry 231
    -0.0,
    (int)-0x1.p0,
    -0x1.0p-1022,
    0x1.0p-1022
  },
  { // Entry 232
    -0.0,
    (int)0x1.p0,
    -0x1.0p-1022,
    -0x1.0p-1022
  },
  { // Entry 233
    0.0,
    (int)0.0,
    0x1.0p-1022,
    0x1.0p-1074
  },
  { // Entry 234
    0.0,
    (int)0.0,
    0x1.0p-1022,
    -0x1.0p-1074
  },
  { // Entry 235
    -0.0,
    (int)0.0,
    -0x1.0p-1022,
    0x1.0p-1074
  },
  { // Entry 236
    -0.0,
    (int)0.0,
    -0x1.0p-1022,
    -0x1.0p-1074
  },
  { // Entry 237
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    0x1.0p-1022
  },
  { // Entry 238
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    0x1.0p-1022
  },
  { // Entry 239
    0x1.p-1074,
    (int)0.0,
    0x1.0p-1074,
    -0x1.0p-1022
  },
  { // Entry 240
    -0x1.p-1074,
    (int)0.0,
    -0x1.0p-1074,
    -0x1.0p-1022
  },
  { // Entry 241
    0.0,
    (int)0.0,
    0.0,
    0x1.0p-1022
  },
  { // Entry 242
    -0.0,
    (int)0.0,
    -0.0,
    0x1.0p-1022
  },
  { // Entry 243
    0.0,
    (int)0.0,
    0.0,
    -0x1.0p-1022
  },
  { // Entry 244
    -0.0,
    (int)0.0,
    -0.0,
    -0x1.0p-1022
  },
  { // Entry 245
    0.0,
    (int)0x1.p0,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 246
    -0.0,
    (int)-0x1.p0,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 247
    0.0,
    (int)-0x1.p0,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 248
    -0.0,
    (int)0x1.p0,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 249
    0.0,
    (int)0.0,
    0.0,
    0x1.0p-1074
  },
  { // Entry 250
    -0.0,
    (int)0.0,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 251
    0.0,
    (int)0.0,
    0.0,
    -0x1.0p-1074
  },
  { // Entry 252
    -0.0,
    (int)0.0,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 253
    -0x1.p0,
    (int)0x1.p1,
    0x1.8p1,
    0x1.0p1
  },
  { // Entry 254
    0x1.p0,
    (int)-0x1.p1,
    -0x1.8p1,
    0x1.0p1
  },
  { // Entry 255
    -0x1.p0,
    (int)-0x1.p1,
    0x1.8p1,
    -0x1.0p1
  },
  { // Entry 256
    0x1.p0,
    (int)0x1.p1,
    -0x1.8p1,
    -0x1.0p1
  },
  { // Entry 257
    0x1.p0,
    (int)0x1.p1,
    0x1.4p2,
    0x1.0p1
  },
  { // Entry 258
    -0x1.p0,
    (int)-0x1.p1,
    -0x1.4p2,
    0x1.0p1
  },
  { // Entry 259
    0x1.p0,
    (int)-0x1.p1,
    0x1.4p2,
    -0x1.0p1
  },
  { // Entry 260
    -0x1.p0,
    (int)0x1.p1,
    -0x1.4p2,
    -0x1.0p1
  }
};
```
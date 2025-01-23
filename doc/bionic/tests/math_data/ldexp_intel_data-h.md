Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The central request is to analyze the provided C code snippet, specifically the `ldexp_intel_data.handroid` file, and explain its purpose and related concepts within the Android bionic library. The request explicitly asks for the function's purpose, its relation to Android, explanations of relevant libc functions, dynamic linker aspects, logical reasoning, common user errors, and how Android framework/NDK reaches this point, along with Frida hooking. It also asks for a summary of the file's function in this first part.

**2. Initial Code Analysis (Skimming and Identifying Key Elements):**

The first step is to quickly skim the code. Key observations:

* **Comment Header:**  The initial comments clearly state this file is part of Android's bionic library, specifically for math testing, and relates to the `ldexp` function.
* **`static data_1_2_t<double, double, int> g_ldexp_intel_data[]`:** This declares a static array named `g_ldexp_intel_data`. The type `data_1_2_t` suggests it's a template structure holding three values: two doubles and an integer.
* **Data Structure:** The array is initialized with numerous entries, each enclosed in `{}`. Each entry appears to contain three values. The values look like floating-point numbers (some in hexadecimal scientific notation like `0x1.0p-1074`) and integers.
* **`HUGE_VAL`:** This macro is used in some entries, indicating potential boundary or special case testing.

**3. Deducing the Function's Purpose:**

Based on the filename (`ldexp_intel_data`), the array name (`g_ldexp_intel_data`), and the structure of the data, the core function is likely to provide *test data* for the `ldexp` function. The `intel_data` part might suggest it's tailored for Intel architectures or based on Intel's behavior for `ldexp`. The "handroid" part further reinforces its specific use within the Android context.

**4. Relating to Android Functionality:**

Since bionic is Android's C library, this test data directly relates to the correctness and robustness of the `ldexp` implementation used by Android. `ldexp` is a standard math function, so any Android application using math operations could potentially rely on this implementation.

**5. Planning the Explanation of `ldexp`:**

The request asks for a detailed explanation of `ldexp`. This requires:

* **Basic Definition:**  Explaining what `ldexp(x, exp)` does (multiplies `x` by 2 raised to the power of `exp`).
* **Use Cases:**  Providing examples of where it's used (scaling numbers, working with binary representations, avoiding overflow/underflow).
* **Implementation Details (High-Level):**  Mentioning how it might be implemented at a low level (manipulating the exponent bits of floating-point numbers). *Initially, I might consider going deeper into bit manipulation, but given the context of a test data file, a high-level explanation is more appropriate for this section. Deeper dives would fit better when discussing the actual `ldexp` implementation, which isn't in this file.*
* **Connection to the Test Data:**  Emphasizing that this file provides inputs and expected outputs for verifying the `ldexp` implementation.

**6. Addressing Dynamic Linking (Anticipating Future Parts):**

The request mentions dynamic linking. While this specific file doesn't directly *implement* dynamic linking, it's part of a library that *is* dynamically linked. So, acknowledging the role of the dynamic linker in loading and linking the bionic math library is important, even if a detailed explanation and SO layout come later in subsequent parts.

**7. Logical Reasoning and Examples:**

The data in the file itself provides examples. The logical reasoning is that for a given input `x` and exponent `exp`, the `ldexp` function should produce the expected output `y`. Picking a few example entries and explaining the relationship is crucial.

**8. Common User Errors (Anticipating Future Parts):**

Although not directly apparent in the data file, thinking about common mistakes users make with `ldexp` is useful for future parts. Examples include providing non-integer exponents or exceeding the valid range of exponents.

**9. Android Framework/NDK and Frida Hooking (Anticipating Future Parts):**

This requires understanding the call stack. High-level: Android app uses Java Framework -> Framework uses native libraries (through JNI) -> Native libraries in bionic contain the `ldexp` implementation. Frida can be used to intercept calls at the native level. This will be detailed in later parts.

**10. Focusing on the "归纳一下它的功能" (Summarize its Function) for Part 1:**

For this specific part, the core function is providing test data for the `ldexp` function in the bionic library. This data helps ensure the correctness of the `ldexp` implementation on Android.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:**  Should I explain the binary representation of floating-point numbers in detail?  **Correction:** While relevant to `ldexp`'s implementation, it's not the primary function of *this* file. Keep it higher-level for now and save the detailed implementation for later if the prompt requires it.
* **Initial thought:** Should I provide a detailed explanation of dynamic linking right now? **Correction:** The file itself doesn't *perform* dynamic linking. Acknowledge its context within a dynamically linked library and promise more details later.
* **Emphasis:**  Make sure to repeatedly connect the data back to the testing and verification of `ldexp`.

By following these steps, focusing on the specific request for Part 1 while also anticipating the requirements of later parts, we arrive at a comprehensive and well-structured answer.
好的，我们来分析一下 `bionic/tests/math_data/ldexp_intel_data.handroid` 这个源代码文件的功能。

**文件功能归纳 (Part 1):**

这个 C 源代码文件 `ldexp_intel_data.handroid` 的主要功能是**为 `ldexp` 函数提供测试数据**。

更具体地说：

1. **存储测试用例:** 它定义了一个静态数组 `g_ldexp_intel_data`，该数组包含了大量的结构体元素。每个结构体元素 (`data_1_2_t<double, double, int>`) 存储了三个值：一个双精度浮点数输入 (`double`)，一个双精度浮点数期望输出 (`double`)，以及一个整数类型的指数 (`int`)。

2. **用于验证 `ldexp` 函数的正确性:**  这些数据被设计用来测试 `ldexp` 函数在不同输入值和指数下的行为是否符合预期。测试框架会使用这些输入值调用 `ldexp` 函数，并将实际的输出结果与数组中预期的输出值进行比较，从而验证 `ldexp` 函数的实现是否正确。

3. **针对特定架构 (Intel) 和平台 (Android):** 文件名中的 `intel_data` 表明这些测试数据可能特别关注在 Intel 架构上的 `ldexp` 函数行为。`handroid` 则明确指出这是 Android 平台使用的测试数据。这暗示了不同架构或平台可能在浮点数运算的某些边缘情况下存在差异，因此需要针对性地进行测试。

**接下来，我们来详细展开您提出的其他问题，即使这些信息在代码本身中没有直接体现，但与理解文件的上下文至关重要。**

**与 Android 功能的关系及举例说明:**

`ldexp` 是一个标准的 C 语言数学库函数，定义在 `math.h` 中。它是 Android Bionic Libc (C 标准库) 的一部分。

* **功能:** `ldexp(double x, int exp)` 函数将浮点数 `x` 乘以 2 的 `exp` 次幂，即 `x * 2^exp`。

* **与 Android 的关系:**
    * **基础数学运算:** Android 系统以及其上的应用程序，包括 Framework 和 Native 代码，都会进行各种数学运算。`ldexp` 作为基础的数学函数之一，被广泛使用。
    * **图形图像处理:** 例如，在图形渲染、图像处理等领域，经常需要进行数值缩放，`ldexp` 可以高效地完成这项任务。
    * **音频处理:** 音频编解码、音频特效等也可能用到 `ldexp` 进行增益调整等操作。
    * **科学计算应用:** 一些科学计算类的 Android 应用会直接或间接地使用到 `ldexp`。

* **举例说明:**
    * 假设一个音频应用需要将音频采样值放大 8 倍。可以使用 `ldexp(sample, 3)`，因为 2 的 3 次幂是 8。
    * 在图形渲染中，如果需要将一个颜色的亮度值乘以 0.5，可以使用 `ldexp(brightness, -1)`。

**详细解释 `ldexp` libc 函数的功能是如何实现的:**

`ldexp` 函数的实现通常利用了浮点数在计算机中的二进制表示方式。对于 IEEE 754 双精度浮点数（`double` 类型），其结构通常包括：

1. **符号位 (Sign bit):** 1 位，表示正数或负数。
2. **指数 (Exponent):** 11 位，表示 2 的幂次。
3. **尾数 (Mantissa/Significand):** 52 位，表示有效数字。

`ldexp(x, exp)` 的实现通常会直接操作 `x` 的指数部分：

1. **提取指数:** 从 `x` 的二进制表示中提取出指数部分的值。
2. **加上指数偏移:** 将传入的指数 `exp` 加到提取出的指数值上。
3. **处理溢出和下溢:**
    * 如果新的指数值超出了双精度浮点数指数的表示范围（通常是 -1022 到 1023），则会发生溢出（结果为无穷大）或下溢（结果为零或极小的非零数）。
    * 特殊情况，例如输入为 0、无穷大或 NaN (Not a Number)，需要特殊处理。
4. **组合新的浮点数:** 将修改后的指数值与原始的符号位和尾数部分重新组合成新的浮点数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `ldexp_intel_data.handroid` 本身不涉及动态链接，但它所属的 `libm.so` (数学库) 是一个动态链接库。

**SO 布局样本 (`libm.so`):**

```
libm.so:
    .note.android.ident  // Android 标识
    .hash                // 符号哈希表
    .gnu.hash            // GNU 符号哈希表
    .dynsym              // 动态符号表
    .dynstr              // 动态字符串表
    .gnu.version         // 版本信息
    .gnu.version_r       // 版本需求信息
    .rela.dyn            // 重定位表（针对数据段）
    .rela.plt            // 重定位表（针对过程链接表）
    .plt                 // 过程链接表
    .text                // 代码段 (包含 ldexp 的实现)
        ldexp:
            ; ldexp 函数的代码
            ...
    .rodata              // 只读数据段 (可能包含一些数学常量)
    .data                // 已初始化数据段
    .bss                 // 未初始化数据段
```

**链接的处理过程:**

1. **编译和链接:** 当一个应用程序或共享库依赖于 `libm.so` 中的 `ldexp` 函数时，链接器（在编译时）会在其动态符号表中记录对 `ldexp` 的引用。
2. **加载时链接 (Dynamic Linking):**
   * 当 Android 启动应用程序或加载共享库时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载所需的共享库，例如 `libm.so`。
   * 动态链接器会解析应用程序或共享库的依赖关系，找到 `libm.so`。
   * `libm.so` 会被加载到内存中的某个地址。
   * **符号解析和重定位:** 动态链接器会遍历应用程序或共享库的重定位表 (`.rela.dyn` 和 `.rela.plt`)。
     * 对于对 `ldexp` 的引用，动态链接器会在 `libm.so` 的动态符号表 (`.dynsym`) 中查找 `ldexp` 的地址。
     * 找到 `ldexp` 的地址后，动态链接器会更新应用程序或共享库中对 `ldexp` 的调用地址，使其指向 `libm.so` 中 `ldexp` 函数的实际地址。这个过程称为**重定位**。
   * **过程链接表 (PLT) 和全局偏移表 (GOT):**  通常，对外部函数的调用会通过 PLT 进行。PLT 中的每个条目对应一个外部函数。第一次调用外部函数时，PLT 条目会跳转到动态链接器，由动态链接器解析函数地址并更新 GOT (全局偏移表)。后续调用会直接通过 GOT 跳转到已解析的函数地址，提高效率。

**如果做了逻辑推理，请给出假设输入与输出:**

基于 `ldexp` 的功能和代码中的数据，我们可以进行一些逻辑推理和给出假设输入输出。例如：

* **假设输入:** `x = 3.0`, `exp = 2`
* **预期输出:** `3.0 * 2^2 = 3.0 * 4.0 = 12.0`

再看代码中的一些例子：

* **Entry 0:**
    * 输入 `x = -0.0`
    * 指数 `exp = -10`
    * 预期输出 `-0x1.0p-1074` (这是最小的负非零双精度浮点数，乘以一个很小的 2 的负幂次，结果仍然接近于零)
    * **逻辑推理:** 负零乘以任何有限的 2 的幂次仍然是负零，但由于浮点数表示的精度限制，测试数据可能验证的是下溢到最小负数的边界情况。

* **Entry 10:**
    * 输入 `x = HUGE_VAL` (表示正无穷大)
    * 指数 `exp = 2147483647` (整数的最大值)
    * 预期输出 `0x1.8e147ae147ae1p0`
    * **逻辑推理:** 这里可能是在测试 `ldexp` 对无穷大的处理。乘以一个非常大的 2 的幂次，理论上结果应该仍然是无穷大。但这里的预期输出是一个有限值，这可能暗示了测试的重点在于当指数非常大时，`ldexp` 函数的某种特定行为或平台相关的实现细节。需要注意的是，`HUGE_VAL` 乘以任何大于 1 的值仍然是 `HUGE_VAL`。这个测试用例可能在验证特定的平台行为或者测试数据有误。

* **Entry 21:**
    * 输入 `x = -0x1.p-10`
    * 指数 `exp = -10`
    * 预期输出 `-0x1.0p0`
    * **逻辑推理:** `-0x1.p-10` 等价于 `-1 * 2^-10`。乘以 `2^-10`，结果应该是 `-1 * 2^-20`，而不是 `-1 * 2^0`。这里可能存在笔误，或者测试的目的是验证某些特定的舍入或边界情况。 *（经过仔细检查，我之前的推理有误，`ldexp` 的作用是将第一个参数乘以 2 的第二个参数次幂。所以 `-0x1.p-10 * 2^-10` 应该是 `-1 * 2^-10 * 2^-10 = -1 * 2^-20`。预期输出 `-0x1.0p0` 意味着测试的逻辑可能存在问题，或者期望 `ldexp` 在某些情况下返回一个标准化后的值。）*

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **指数类型错误:**  `ldexp` 的第二个参数要求是 `int` 类型。如果传入其他类型，可能会导致编译错误或运行时错误。
   ```c
   double result = ldexp(2.0, 3.5); // 错误：指数应为 int
   ```

* **指数超出范围:** 虽然 `int` 的范围很大，但如果指数非常大或非常小，导致结果超出 `double` 的表示范围，会发生溢出或下溢。
   ```c
   double large_result = ldexp(1.0, 2000); // 可能溢出
   double small_result = ldexp(1.0, -2000); // 可能下溢
   ```

* **对特殊值的误解:** 用户可能不清楚 `ldexp` 对 0、无穷大或 NaN 的处理方式。
   ```c
   double zero_result = ldexp(0.0, 10);   // 结果为 0.0
   double inf_result = ldexp(HUGE_VAL, 5); // 结果为 HUGE_VAL
   double nan_result = ldexp(NAN, -2);     // 结果为 NaN
   ```

* **精度问题:** 浮点数运算存在精度限制，连续使用 `ldexp` 可能累积误差。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用:**
   * **Java Framework:** Android Framework 中的某些类，例如 `android.graphics.Color` 或进行复杂数学运算的类，其底层实现可能会调用 Native 代码。
   * **NDK 应用:** 使用 NDK 开发的 C/C++ 应用可以直接调用 Bionic Libc 提供的 `ldexp` 函数。

2. **JNI (Java Native Interface) 调用:**
   * 如果是 Framework 调用，Java 代码会通过 JNI 调用到 Native 代码。
   * JNI 提供了一种机制，允许 Java 代码调用 Native 共享库中导出的函数。

3. **链接到 `libm.so`:**
   * Native 代码在编译时需要链接到 `libm.so` 共享库，该库包含了 `ldexp` 的实现。
   * 链接器会处理符号的解析，确保在运行时能够找到 `ldexp` 函数。

4. **动态链接器加载 `libm.so`:**
   * 当 Native 代码被加载到内存中时，动态链接器会加载其依赖的共享库，包括 `libm.so`。

5. **调用 `ldexp` 函数:**
   * Native 代码中调用 `ldexp` 函数时，实际执行的是 `libm.so` 中实现的 `ldexp` 代码。
   * 为了确保 `ldexp` 实现的正确性，就会使用到像 `ldexp_intel_data.handroid` 这样的测试数据进行验证。

**Frida Hook 示例:**

假设我们要 hook `ldexp` 函数的调用，可以使用 Frida 的 JavaScript API：

```javascript
// hook ldexp 函数
Interceptor.attach(Module.findExportByName("libm.so", "ldexp"), {
  onEnter: function(args) {
    // 打印调用 ldexp 时的参数
    console.log("ldexp called with:");
    console.log("  x =", args[0]); // 第一个参数 (double)
    console.log("  exp =", args[1]); // 第二个参数 (int)
  },
  onLeave: function(retval) {
    // 打印 ldexp 函数的返回值
    console.log("ldexp returned:", retval);
  }
});
```

**使用步骤:**

1. **启动目标 Android 应用。**
2. **运行 Frida 脚本，将脚本附加到目标应用的进程。**
3. **在应用中触发会调用 `ldexp` 函数的操作。**
4. **Frida 会拦截对 `ldexp` 的调用，并打印出参数和返回值。**

**总结 `ldexp_intel_data.handroid` 的功能 (针对 Part 1):**

总而言之，`bionic/tests/math_data/ldexp_intel_data.handroid` 这个文件的核心功能是**提供了一组精心设计的测试用例，用于验证 Android Bionic Libc 中 `ldexp` 函数在 Intel 架构上的实现是否正确**。这些测试数据覆盖了各种输入值和指数，包括边界情况和特殊值，旨在确保 `ldexp` 函数的稳定性和可靠性，从而保证 Android 系统及应用程序中涉及浮点数乘幂运算的正确性。

### 提示词
```
这是目录为bionic/tests/math_data/ldexp_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_2_t<double, double, int> g_ldexp_intel_data[] = {
  { // Entry 0
    -0.0,
    -0x1.0p-1074,
    (int)-10
  },
  { // Entry 1
    -0x1.55555555555560p-1024,
    -0x1.5555555555556p-2,
    (int)-1022
  },
  { // Entry 2
    -0x1.6db6db6db6db70p-1023,
    -0x1.6db6db6db6db7p-1,
    (int)-1022
  },
  { // Entry 3
    -0x1.8e38e38e38e390p-1023,
    -0x1.8e38e38e38e39p-1,
    (int)-1022
  },
  { // Entry 4
    0.0,
    0x1.0p-1074,
    (int)-1
  },
  { // Entry 5
    0.0,
    0x1.0p-1074,
    (int)-10
  },
  { // Entry 6
    0.0,
    0x1.0p-1074,
    (int)-47
  },
  { // Entry 7
    0x1.p-1064,
    0x1.0p-1074,
    (int)10
  },
  { // Entry 8
    0x1.p-51,
    0x1.0p-1074,
    (int)1023
  },
  { // Entry 9
    0x1.29e4129e4129e0p-1024,
    0x1.29e4129e4129ep-7,
    (int)-1017
  },
  { // Entry 10
    HUGE_VAL,
    0x1.8e147ae147ae1p0,
    (int)2147483647
  },
  { // Entry 11
    0.0,
    0x1.dddddddddddddp-2,
    (int)-1073
  },
  { // Entry 12
    0x1.e0p-48,
    0x1.ep-1071,
    (int)1023
  },
  { // Entry 13
    0.0,
    0x1.f7df7df7df7dfp-2,
    (int)-1073
  },
  { // Entry 14
    0.0,
    0x1.ffffffffffff0p-2,
    (int)-1073
  },
  { // Entry 15
    0x1.ffffffffffffc0p-1033,
    0x1.ffffffffffffcp-1023,
    (int)-10
  },
  { // Entry 16
    0x1.ffffffffffffc0p-1022,
    0x1.ffffffffffffcp-1023,
    (int)1
  },
  { // Entry 17
    0x1.ffffffffffffe0p-1070,
    0x1.ffffffffffffep-1023,
    (int)-47
  },
  { // Entry 18
    0x1.ffffffffffffe0p-1022,
    0x1.ffffffffffffep-1023,
    (int)1
  },
  { // Entry 19
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    (int)2147483647
  },
  { // Entry 20
    HUGE_VAL,
    0x1.fffffffffffffp1023,
    (int)2147483647
  },
  { // Entry 21
    -0x1.p-10,
    -0x1.0p0,
    (int)-10
  },
  { // Entry 22
    -0x1.p-9,
    -0x1.0p0,
    (int)-9
  },
  { // Entry 23
    -0x1.p-8,
    -0x1.0p0,
    (int)-8
  },
  { // Entry 24
    -0x1.p-7,
    -0x1.0p0,
    (int)-7
  },
  { // Entry 25
    -0x1.p-6,
    -0x1.0p0,
    (int)-6
  },
  { // Entry 26
    -0x1.p-5,
    -0x1.0p0,
    (int)-5
  },
  { // Entry 27
    -0x1.p-4,
    -0x1.0p0,
    (int)-4
  },
  { // Entry 28
    -0x1.p-3,
    -0x1.0p0,
    (int)-3
  },
  { // Entry 29
    -0x1.p-2,
    -0x1.0p0,
    (int)-2
  },
  { // Entry 30
    -0x1.p-1,
    -0x1.0p0,
    (int)-1
  },
  { // Entry 31
    -0x1.p0,
    -0x1.0p0,
    (int)0
  },
  { // Entry 32
    -0x1.p1,
    -0x1.0p0,
    (int)1
  },
  { // Entry 33
    -0x1.p2,
    -0x1.0p0,
    (int)2
  },
  { // Entry 34
    -0x1.p3,
    -0x1.0p0,
    (int)3
  },
  { // Entry 35
    -0x1.p4,
    -0x1.0p0,
    (int)4
  },
  { // Entry 36
    -0x1.p5,
    -0x1.0p0,
    (int)5
  },
  { // Entry 37
    -0x1.p6,
    -0x1.0p0,
    (int)6
  },
  { // Entry 38
    -0x1.p7,
    -0x1.0p0,
    (int)7
  },
  { // Entry 39
    -0x1.p8,
    -0x1.0p0,
    (int)8
  },
  { // Entry 40
    -0x1.p9,
    -0x1.0p0,
    (int)9
  },
  { // Entry 41
    -0x1.p10,
    -0x1.0p0,
    (int)10
  },
  { // Entry 42
    -0x1.d1745d1745d170p-11,
    -0x1.d1745d1745d17p-1,
    (int)-10
  },
  { // Entry 43
    -0x1.d1745d1745d170p-10,
    -0x1.d1745d1745d17p-1,
    (int)-9
  },
  { // Entry 44
    -0x1.d1745d1745d170p-9,
    -0x1.d1745d1745d17p-1,
    (int)-8
  },
  { // Entry 45
    -0x1.d1745d1745d170p-8,
    -0x1.d1745d1745d17p-1,
    (int)-7
  },
  { // Entry 46
    -0x1.d1745d1745d170p-7,
    -0x1.d1745d1745d17p-1,
    (int)-6
  },
  { // Entry 47
    -0x1.d1745d1745d170p-6,
    -0x1.d1745d1745d17p-1,
    (int)-5
  },
  { // Entry 48
    -0x1.d1745d1745d170p-5,
    -0x1.d1745d1745d17p-1,
    (int)-4
  },
  { // Entry 49
    -0x1.d1745d1745d170p-4,
    -0x1.d1745d1745d17p-1,
    (int)-3
  },
  { // Entry 50
    -0x1.d1745d1745d170p-3,
    -0x1.d1745d1745d17p-1,
    (int)-2
  },
  { // Entry 51
    -0x1.d1745d1745d170p-2,
    -0x1.d1745d1745d17p-1,
    (int)-1
  },
  { // Entry 52
    -0x1.d1745d1745d170p-1,
    -0x1.d1745d1745d17p-1,
    (int)0
  },
  { // Entry 53
    -0x1.d1745d1745d170p0,
    -0x1.d1745d1745d17p-1,
    (int)1
  },
  { // Entry 54
    -0x1.d1745d1745d170p1,
    -0x1.d1745d1745d17p-1,
    (int)2
  },
  { // Entry 55
    -0x1.d1745d1745d170p2,
    -0x1.d1745d1745d17p-1,
    (int)3
  },
  { // Entry 56
    -0x1.d1745d1745d170p3,
    -0x1.d1745d1745d17p-1,
    (int)4
  },
  { // Entry 57
    -0x1.d1745d1745d170p4,
    -0x1.d1745d1745d17p-1,
    (int)5
  },
  { // Entry 58
    -0x1.d1745d1745d170p5,
    -0x1.d1745d1745d17p-1,
    (int)6
  },
  { // Entry 59
    -0x1.d1745d1745d170p6,
    -0x1.d1745d1745d17p-1,
    (int)7
  },
  { // Entry 60
    -0x1.d1745d1745d170p7,
    -0x1.d1745d1745d17p-1,
    (int)8
  },
  { // Entry 61
    -0x1.d1745d1745d170p8,
    -0x1.d1745d1745d17p-1,
    (int)9
  },
  { // Entry 62
    -0x1.d1745d1745d170p9,
    -0x1.d1745d1745d17p-1,
    (int)10
  },
  { // Entry 63
    -0x1.a2e8ba2e8ba2e0p-11,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-10
  },
  { // Entry 64
    -0x1.a2e8ba2e8ba2e0p-10,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-9
  },
  { // Entry 65
    -0x1.a2e8ba2e8ba2e0p-9,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-8
  },
  { // Entry 66
    -0x1.a2e8ba2e8ba2e0p-8,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-7
  },
  { // Entry 67
    -0x1.a2e8ba2e8ba2e0p-7,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-6
  },
  { // Entry 68
    -0x1.a2e8ba2e8ba2e0p-6,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-5
  },
  { // Entry 69
    -0x1.a2e8ba2e8ba2e0p-5,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-4
  },
  { // Entry 70
    -0x1.a2e8ba2e8ba2e0p-4,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-3
  },
  { // Entry 71
    -0x1.a2e8ba2e8ba2e0p-3,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-2
  },
  { // Entry 72
    -0x1.a2e8ba2e8ba2e0p-2,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)-1
  },
  { // Entry 73
    -0x1.a2e8ba2e8ba2e0p-1,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)0
  },
  { // Entry 74
    -0x1.a2e8ba2e8ba2e0p0,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)1
  },
  { // Entry 75
    -0x1.a2e8ba2e8ba2e0p1,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)2
  },
  { // Entry 76
    -0x1.a2e8ba2e8ba2e0p2,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)3
  },
  { // Entry 77
    -0x1.a2e8ba2e8ba2e0p3,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)4
  },
  { // Entry 78
    -0x1.a2e8ba2e8ba2e0p4,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)5
  },
  { // Entry 79
    -0x1.a2e8ba2e8ba2e0p5,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)6
  },
  { // Entry 80
    -0x1.a2e8ba2e8ba2e0p6,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)7
  },
  { // Entry 81
    -0x1.a2e8ba2e8ba2e0p7,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)8
  },
  { // Entry 82
    -0x1.a2e8ba2e8ba2e0p8,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)9
  },
  { // Entry 83
    -0x1.a2e8ba2e8ba2e0p9,
    -0x1.a2e8ba2e8ba2ep-1,
    (int)10
  },
  { // Entry 84
    -0x1.745d1745d17450p-11,
    -0x1.745d1745d1745p-1,
    (int)-10
  },
  { // Entry 85
    -0x1.745d1745d17450p-10,
    -0x1.745d1745d1745p-1,
    (int)-9
  },
  { // Entry 86
    -0x1.745d1745d17450p-9,
    -0x1.745d1745d1745p-1,
    (int)-8
  },
  { // Entry 87
    -0x1.745d1745d17450p-8,
    -0x1.745d1745d1745p-1,
    (int)-7
  },
  { // Entry 88
    -0x1.745d1745d17450p-7,
    -0x1.745d1745d1745p-1,
    (int)-6
  },
  { // Entry 89
    -0x1.745d1745d17450p-6,
    -0x1.745d1745d1745p-1,
    (int)-5
  },
  { // Entry 90
    -0x1.745d1745d17450p-5,
    -0x1.745d1745d1745p-1,
    (int)-4
  },
  { // Entry 91
    -0x1.745d1745d17450p-4,
    -0x1.745d1745d1745p-1,
    (int)-3
  },
  { // Entry 92
    -0x1.745d1745d17450p-3,
    -0x1.745d1745d1745p-1,
    (int)-2
  },
  { // Entry 93
    -0x1.745d1745d17450p-2,
    -0x1.745d1745d1745p-1,
    (int)-1
  },
  { // Entry 94
    -0x1.745d1745d17450p-1,
    -0x1.745d1745d1745p-1,
    (int)0
  },
  { // Entry 95
    -0x1.745d1745d17450p0,
    -0x1.745d1745d1745p-1,
    (int)1
  },
  { // Entry 96
    -0x1.745d1745d17450p1,
    -0x1.745d1745d1745p-1,
    (int)2
  },
  { // Entry 97
    -0x1.745d1745d17450p2,
    -0x1.745d1745d1745p-1,
    (int)3
  },
  { // Entry 98
    -0x1.745d1745d17450p3,
    -0x1.745d1745d1745p-1,
    (int)4
  },
  { // Entry 99
    -0x1.745d1745d17450p4,
    -0x1.745d1745d1745p-1,
    (int)5
  },
  { // Entry 100
    -0x1.745d1745d17450p5,
    -0x1.745d1745d1745p-1,
    (int)6
  },
  { // Entry 101
    -0x1.745d1745d17450p6,
    -0x1.745d1745d1745p-1,
    (int)7
  },
  { // Entry 102
    -0x1.745d1745d17450p7,
    -0x1.745d1745d1745p-1,
    (int)8
  },
  { // Entry 103
    -0x1.745d1745d17450p8,
    -0x1.745d1745d1745p-1,
    (int)9
  },
  { // Entry 104
    -0x1.745d1745d17450p9,
    -0x1.745d1745d1745p-1,
    (int)10
  },
  { // Entry 105
    -0x1.45d1745d1745c0p-11,
    -0x1.45d1745d1745cp-1,
    (int)-10
  },
  { // Entry 106
    -0x1.45d1745d1745c0p-10,
    -0x1.45d1745d1745cp-1,
    (int)-9
  },
  { // Entry 107
    -0x1.45d1745d1745c0p-9,
    -0x1.45d1745d1745cp-1,
    (int)-8
  },
  { // Entry 108
    -0x1.45d1745d1745c0p-8,
    -0x1.45d1745d1745cp-1,
    (int)-7
  },
  { // Entry 109
    -0x1.45d1745d1745c0p-7,
    -0x1.45d1745d1745cp-1,
    (int)-6
  },
  { // Entry 110
    -0x1.45d1745d1745c0p-6,
    -0x1.45d1745d1745cp-1,
    (int)-5
  },
  { // Entry 111
    -0x1.45d1745d1745c0p-5,
    -0x1.45d1745d1745cp-1,
    (int)-4
  },
  { // Entry 112
    -0x1.45d1745d1745c0p-4,
    -0x1.45d1745d1745cp-1,
    (int)-3
  },
  { // Entry 113
    -0x1.45d1745d1745c0p-3,
    -0x1.45d1745d1745cp-1,
    (int)-2
  },
  { // Entry 114
    -0x1.45d1745d1745c0p-2,
    -0x1.45d1745d1745cp-1,
    (int)-1
  },
  { // Entry 115
    -0x1.45d1745d1745c0p-1,
    -0x1.45d1745d1745cp-1,
    (int)0
  },
  { // Entry 116
    -0x1.45d1745d1745c0p0,
    -0x1.45d1745d1745cp-1,
    (int)1
  },
  { // Entry 117
    -0x1.45d1745d1745c0p1,
    -0x1.45d1745d1745cp-1,
    (int)2
  },
  { // Entry 118
    -0x1.45d1745d1745c0p2,
    -0x1.45d1745d1745cp-1,
    (int)3
  },
  { // Entry 119
    -0x1.45d1745d1745c0p3,
    -0x1.45d1745d1745cp-1,
    (int)4
  },
  { // Entry 120
    -0x1.45d1745d1745c0p4,
    -0x1.45d1745d1745cp-1,
    (int)5
  },
  { // Entry 121
    -0x1.45d1745d1745c0p5,
    -0x1.45d1745d1745cp-1,
    (int)6
  },
  { // Entry 122
    -0x1.45d1745d1745c0p6,
    -0x1.45d1745d1745cp-1,
    (int)7
  },
  { // Entry 123
    -0x1.45d1745d1745c0p7,
    -0x1.45d1745d1745cp-1,
    (int)8
  },
  { // Entry 124
    -0x1.45d1745d1745c0p8,
    -0x1.45d1745d1745cp-1,
    (int)9
  },
  { // Entry 125
    -0x1.45d1745d1745c0p9,
    -0x1.45d1745d1745cp-1,
    (int)10
  },
  { // Entry 126
    -0x1.1745d1745d1730p-11,
    -0x1.1745d1745d173p-1,
    (int)-10
  },
  { // Entry 127
    -0x1.1745d1745d1730p-10,
    -0x1.1745d1745d173p-1,
    (int)-9
  },
  { // Entry 128
    -0x1.1745d1745d1730p-9,
    -0x1.1745d1745d173p-1,
    (int)-8
  },
  { // Entry 129
    -0x1.1745d1745d1730p-8,
    -0x1.1745d1745d173p-1,
    (int)-7
  },
  { // Entry 130
    -0x1.1745d1745d1730p-7,
    -0x1.1745d1745d173p-1,
    (int)-6
  },
  { // Entry 131
    -0x1.1745d1745d1730p-6,
    -0x1.1745d1745d173p-1,
    (int)-5
  },
  { // Entry 132
    -0x1.1745d1745d1730p-5,
    -0x1.1745d1745d173p-1,
    (int)-4
  },
  { // Entry 133
    -0x1.1745d1745d1730p-4,
    -0x1.1745d1745d173p-1,
    (int)-3
  },
  { // Entry 134
    -0x1.1745d1745d1730p-3,
    -0x1.1745d1745d173p-1,
    (int)-2
  },
  { // Entry 135
    -0x1.1745d1745d1730p-2,
    -0x1.1745d1745d173p-1,
    (int)-1
  },
  { // Entry 136
    -0x1.1745d1745d1730p-1,
    -0x1.1745d1745d173p-1,
    (int)0
  },
  { // Entry 137
    -0x1.1745d1745d1730p0,
    -0x1.1745d1745d173p-1,
    (int)1
  },
  { // Entry 138
    -0x1.1745d1745d1730p1,
    -0x1.1745d1745d173p-1,
    (int)2
  },
  { // Entry 139
    -0x1.1745d1745d1730p2,
    -0x1.1745d1745d173p-1,
    (int)3
  },
  { // Entry 140
    -0x1.1745d1745d1730p3,
    -0x1.1745d1745d173p-1,
    (int)4
  },
  { // Entry 141
    -0x1.1745d1745d1730p4,
    -0x1.1745d1745d173p-1,
    (int)5
  },
  { // Entry 142
    -0x1.1745d1745d1730p5,
    -0x1.1745d1745d173p-1,
    (int)6
  },
  { // Entry 143
    -0x1.1745d1745d1730p6,
    -0x1.1745d1745d173p-1,
    (int)7
  },
  { // Entry 144
    -0x1.1745d1745d1730p7,
    -0x1.1745d1745d173p-1,
    (int)8
  },
  { // Entry 145
    -0x1.1745d1745d1730p8,
    -0x1.1745d1745d173p-1,
    (int)9
  },
  { // Entry 146
    -0x1.1745d1745d1730p9,
    -0x1.1745d1745d173p-1,
    (int)10
  },
  { // Entry 147
    -0x1.d1745d1745d140p-12,
    -0x1.d1745d1745d14p-2,
    (int)-10
  },
  { // Entry 148
    -0x1.d1745d1745d140p-11,
    -0x1.d1745d1745d14p-2,
    (int)-9
  },
  { // Entry 149
    -0x1.d1745d1745d140p-10,
    -0x1.d1745d1745d14p-2,
    (int)-8
  },
  { // Entry 150
    -0x1.d1745d1745d140p-9,
    -0x1.d1745d1745d14p-2,
    (int)-7
  },
  { // Entry 151
    -0x1.d1745d1745d140p-8,
    -0x1.d1745d1745d14p-2,
    (int)-6
  },
  { // Entry 152
    -0x1.d1745d1745d140p-7,
    -0x1.d1745d1745d14p-2,
    (int)-5
  },
  { // Entry 153
    -0x1.d1745d1745d140p-6,
    -0x1.d1745d1745d14p-2,
    (int)-4
  },
  { // Entry 154
    -0x1.d1745d1745d140p-5,
    -0x1.d1745d1745d14p-2,
    (int)-3
  },
  { // Entry 155
    -0x1.d1745d1745d140p-4,
    -0x1.d1745d1745d14p-2,
    (int)-2
  },
  { // Entry 156
    -0x1.d1745d1745d140p-3,
    -0x1.d1745d1745d14p-2,
    (int)-1
  },
  { // Entry 157
    -0x1.d1745d1745d140p-2,
    -0x1.d1745d1745d14p-2,
    (int)0
  },
  { // Entry 158
    -0x1.d1745d1745d140p-1,
    -0x1.d1745d1745d14p-2,
    (int)1
  },
  { // Entry 159
    -0x1.d1745d1745d140p0,
    -0x1.d1745d1745d14p-2,
    (int)2
  },
  { // Entry 160
    -0x1.d1745d1745d140p1,
    -0x1.d1745d1745d14p-2,
    (int)3
  },
  { // Entry 161
    -0x1.d1745d1745d140p2,
    -0x1.d1745d1745d14p-2,
    (int)4
  },
  { // Entry 162
    -0x1.d1745d1745d140p3,
    -0x1.d1745d1745d14p-2,
    (int)5
  },
  { // Entry 163
    -0x1.d1745d1745d140p4,
    -0x1.d1745d1745d14p-2,
    (int)6
  },
  { // Entry 164
    -0x1.d1745d1745d140p5,
    -0x1.d1745d1745d14p-2,
    (int)7
  },
  { // Entry 165
    -0x1.d1745d1745d140p6,
    -0x1.d1745d1745d14p-2,
    (int)8
  },
  { // Entry 166
    -0x1.d1745d1745d140p7,
    -0x1.d1745d1745d14p-2,
    (int)9
  },
  { // Entry 167
    -0x1.d1745d1745d140p8,
    -0x1.d1745d1745d14p-2,
    (int)10
  },
  { // Entry 168
    -0x1.745d1745d17420p-12,
    -0x1.745d1745d1742p-2,
    (int)-10
  },
  { // Entry 169
    -0x1.745d1745d17420p-11,
    -0x1.745d1745d1742p-2,
    (int)-9
  },
  { // Entry 170
    -0x1.745d1745d17420p-10,
    -0x1.745d1745d1742p-2,
    (int)-8
  },
  { // Entry 171
    -0x1.745d1745d17420p-9,
    -0x1.745d1745d1742p-2,
    (int)-7
  },
  { // Entry 172
    -0x1.745d1745d17420p-8,
    -0x1.745d1745d1742p-2,
    (int)-6
  },
  { // Entry 173
    -0x1.745d1745d17420p-7,
    -0x1.745d1745d1742p-2,
    (int)-5
  },
  { // Entry 174
    -0x1.745d1745d17420p-6,
    -0x1.745d1745d1742p-2,
    (int)-4
  },
  { // Entry 175
    -0x1.745d1745d17420p-5,
    -0x1.745d1745d1742p-2,
    (int)-3
  },
  { // Entry 176
    -0x1.745d1745d17420p-4,
    -0x1.745d1745d1742p-2,
    (int)-2
  },
  { // Entry 177
    -0x1.745d1745d17420p-3,
    -0x1.745d1745d1742p-2,
    (int)-1
  },
  { // Entry 178
    -0x1.745d1745d17420p-2,
    -0x1.745d1745d1742p-2,
    (int)0
  },
  { // Entry 179
    -0x1.745d1745d17420p-1,
    -0x1.745d1745d1742p-2,
    (int)1
  },
  { // Entry 180
    -0x1.745d1745d17420p0,
    -0x1.745d1745d1742p-2,
    (int)2
  },
  { // Entry 181
    -0x1.745d1745d17420p1,
    -0x1.745d1745d1742p-2,
    (int)3
  },
  { // Entry 182
    -0x1.745d1745d17420p2,
    -0x1.745d1745d1742p-2,
    (int)4
  },
  { // Entry 183
    -0x1.745d1745d17420p3,
    -0x1.745d1745d1742p-2,
    (int)5
  },
  { // Entry 184
    -0x1.745d1745d17420p4,
    -0x1.745d1745d1742p-2,
    (int)6
  },
  { // Entry 185
    -0x1.745d1745d17420p5,
    -0x1.745d1745d1742p-2,
    (int)7
  },
  { // Entry 186
    -0x1.745d1745d17420p6,
    -0x1.745d1745d1742p-2,
    (int)8
  },
  { // Entry 187
    -0x1.745d1745d17420p7,
    -0x1.745d1745d1742p-2,
    (int)9
  },
  { // Entry 188
    -0x1.745d1745d17420p8,
    -0x1.745d1745d1742p-2,
    (int)10
  },
  { // Entry 189
    -0x1.1745d1745d17p-12,
    -0x1.1745d1745d170p-2,
    (int)-10
  },
  { // Entry 190
    -0x1.1745d1745d17p-11,
    -0x1.1745d1745d170p-2,
    (int)-9
  },
  { // Entry 191
    -0x1.1745d1745d17p-10,
    -0x1.1745d1745d170p-2,
    (int)-8
  },
  { // Entry 192
    -0x1.1745d1745d17p-9,
    -0x1.1745d1745d170p-2,
    (int)-7
  },
  { // Entry 193
    -0x1.1745d1745d17p-8,
    -0x1.1745d1745d170p-2,
    (int)-6
  },
  { // Entry 194
    -0x1.1745d1745d17p-7,
    -0x1.1745d1745d170p-2,
    (int)-5
  },
  { // Entry 195
    -0x1.1745d1745d17p-6,
    -0x1.1745d1745d170p-2,
    (int)-4
  },
  { // Entry 196
    -0x1.1745d1745d17p-5,
    -0x1.1745d1745d170p-2,
    (int)-3
  },
  { // Entry 197
    -0x1.1745d1745d17p-4,
    -0x1.1745d1745d170p-2,
    (int)-2
  },
  { // Entry 198
    -0x1.1745d1745d17p-3,
    -0x1.1745d1745d170p-2,
    (int)-1
  },
  { // Entry 199
    -0x1.1745d1745d17p-2,
    -0x1.1745d1745d170p-2,
    (int)0
  },
  { // Entry 200
    -0x1.1745d1745d17p-1,
    -0x1.1745d1745d170p-2,
    (int)1
  },
  { // Entry 201
    -0x1.1745d1745d17p0,
    -0x1.1745d1745d170p-2,
    (int)2
  },
  { // Entry 202
    -0x1.1745d1745d17p1,
    -0x1.1745d1745d170p-2,
    (int)3
  },
  { // Entry 203
    -0x1.1745d1745d17p2,
    -0x1.1745d1745d170p-2,
    (int)4
  },
  { // Entry 204
    -0x1.1745d1745d17p3,
    -0x1.1745d1745d170p-2,
    (int)5
  },
  { // Entry 205
    -0x1.1745d1745d17p4,
    -0x1.1745d1745d170p-2,
    (int)6
  },
  { // Entry 206
    -0x1.1745d1745d17p5,
    -0x1.1745d1745d170p-2,
    (int)7
  },
  { // Entry 207
    -0x1.1745d1745d17p6,
    -0x1.1745d1745d170p-2,
    (int)8
  },
  { // Entry 208
    -0x1.1745d1745d17p7,
    -0x1.1745d1745d170p-2,
    (int)9
  },
  { // Entry 209
    -0x1.1745d1745d17p8,
    -0x1.1745d1745d170p-2,
    (int)10
  },
  { // Entry 210
    -0x1.745d1745d173d0p-13,
    -0x1.745d1745d173dp-3,
    (int)-10
  },
  { // Entry 211
    -0x1.745d1745d173d0p-12,
    -0x1.745d1745d173dp-3,
    (int)-9
  },
  { // Entry 212
    -0x1.745d1745d173d0p-11,
    -0x1.745d1745d173dp-3,
    (int)-8
  },
  { // Entry 213
    -0x1.745d1745d173d0p-10,
    -0x1.745d1745d173dp-3,
    (int)-7
  },
  { // Entry 214
    -0x1.745d1745d173d0p-9,
    -0x1.745d1745d173dp-3,
    (int)-6
  },
  { // Entry 215
    -0x1.745d1745d173d0p-8,
    -0x1.745d1745d173dp-3,
    (int)-5
  },
  { // Entry 216
    -0x1.745d1745d173d0p-7,
    -0x1.745d1745d173dp-3,
    (int)-4
  },
  { // Entry 217
    -0x1.745d1745d173d0p-6,
    -0x1.745d1745d173dp-3,
    (int)-3
  },
  { // Entry 218
    -0x1.745d1745d173d0p-5,
    -0x1.745d1745d173dp-3,
    (int)-2
  },
  { // Entry 219
    -0x1.745d1745d173d0p-4,
    -0x1.745d1745d173dp-3,
    (int)-1
  },
  { // Entry 220
    -0x1.745d1745d173d0p-3,
    -0x1.745d1745d173dp-3,
    (int)0
  },
  { // Entry 221
    -0x1.745d1745d173d0p-2,
    -0x1.745d1745d173dp-3,
    (int)1
  },
  { // Entry 222
    -0x1.745d1745d173d0p-1,
    -0x1.745d1745d173dp-3,
    (int)2
  },
  { // Entry 223
    -0x1.745d1745d173d0p0,
    -0x1.745d1745d173dp-3,
    (int)3
  },
  { // Entry 224
    -0x1.745d1745d173d0p1,
    -0x1.745d1745d173dp-3,
    (int)4
  },
  { // Entry 225
    -0x1.745d1745d173d0p2,
    -0x1.745d1745d173dp-3,
    (int)5
  },
  { // Entry 226
    -0x1.745d1745d173d0p3,
    -0x1.745d1745d173dp-3,
    (int)6
  },
  { // Entry 227
    -0x1.745d1745d173d0p4,
    -0x1.745d1745d173dp-3,
    (int)7
  },
  { // Entry 228
    -0x1.745d1745d173d0p5,
    -0x1.745d1745d173dp-3,
    (int)8
  },
  { // Entry 229
    -0x1.745d1745d173d0p6,
    -0x1.745d1745d173dp-3,
    (int)9
  },
  { // Entry 230
    -0x1.745d1745d173d0p7,
    -0x1.745d1745d173dp-3,
    (int)10
  },
  { // Entry 231
    -0x1.745d1745d17340p-14,
    -0x1.745d1745d1734p-4,
    (int)-10
  },
  { // Entry 232
    -0x1.745d1745d17340p-13,
    -0x1.745d1745d1734p-4,
    (int)-9
  },
  { // Entry 233
    -0x1.745d1745d17340p-12,
    -0x1.745d1745d1734p-4,
    (int)-8
  },
  { // Entry 234
    -0x1.745d1745d17340p-11,
    -0x1.745d1745d1734p-4,
    (int)-7
  },
  { // Entry 235
    -0x1.745d1745d17340p-10,
    -0x1.745d1745d1734p-4,
    (int)-6
  },
  { // Entry 236
    -0x1.745d1745d17340p-9,
    -0x1.745d1745d1734p-4,
    (int)-5
  },
  { // Entry 237
    -0x1.745d1745d17340p-8,
    -0x1.745d1745d1734p-4,
    (int)-4
  },
  { // Entry 238
    -0x1.745d1745d17340p-7,
    -0x1.745d1745d1734p-4,
    (int)-3
  },
  { // Entry 239
    -0x1.745d1745d17340p-6,
    -0x1.745d1745d1734p-4,
    (int)-2
  },
  { // Entry 240
    -0x1.745d1745d17340p-5,
    -0x1.745d1745d1734p-4,
    (int)-1
  },
  { // Entry 241
    -0x1.745d1745d17340p-4,
    -0x1.745d1745d1734p-4,
    (int)0
  },
  { // Entry 242
    -0x1.745d1745d17340p-3,
    -0x1.745d1745d1734p-4,
    (int)1
  },
  { // Entry 243
    -0x1.745d1745d17340p-2,
    -0x1.745d1745d1734p-4,
    (int)2
  },
  { // Entry 244
    -0x1.745d1745d17340p-1,
    -0x1.745d1745d1734p-4,
    (int)3
  },
  { // Entry 245
    -0x1.745d1745d17340p0,
    -0x1.745d1745d1734p-4,
    (int)4
  },
  { // Entry 246
    -0x1.745d1745d17340p1,
    -0x1.745d1745d1734p-4,
    (int)5
  },
  { // Entry 247
    -0x1.745d1745d17340p2,
    -0x1.745d1745d1734p-4,
    (int)6
  },
  { // Entry 248
    -0x1.745d1745d17340p3,
    -0x1.745d1745d1734p-4,
    (int)7
  },
  { // Entry 249
    -0x1.745d1745d17340p4,
    -0x1.745d1745d1734p-4,
    (int)8
  },
  { // Entry 250
    -0x1.745d1745d17340p5,
    -0x1.745d1745d1734p-4,
    (int)9
  },
  { // Entry 251
    -0x1.745d1745d17340p6,
    -0x1.745d1745d1734p-4,
    (int)10
  },
  { // Entry 252
    0x1.20p-62,
    0x1.2p-52,
    (int)-10
  },
  { // Entry 253
    0x1.20p-61,
    0x1.2p-52,
    (int)-9
  },
  { // Entry 254
    0x1.20p-60,
    0x1.2p-52,
    (int)-8
  },
  { // Entry 255
    0x1.20p-59,
    0x1.2p-52,
    (int)-7
  },
  { // Entry 256
    0x1.20p-58,
    0x1.2p-52,
    (int)-6
  },
  { // Entry 257
    0x1.20p-57,
    0x1.2p-52,
    (int)-5
  },
  { // Entry 258
    0x1.20p-56,
    0x1.2p-52,
    (int)-4
  },
  { // Entry 259
    0x1.20p-55,
    0x1.2p-52,
    (int)-3
  },
  { // Entry 260
    0x1.20p-54,
    0x1.2p-52,
    (int)-2
  },
  { // Entry 261
    0x1.20p-53,
    0x1.2p-52,
    (int)-1
  },
  { // Entry 262
    0x1.20p-52,
    0x1.2p-52,
    (int)0
  },
  { // Entry 263
    0x1.20p-51,
    0x1.2p-52,
    (int)1
  },
  { // Entry 264
    0x1.20p-50,
    0x1.2p-52,
    (int)2
  },
  { // Entry 265
    0x1.20p-49,
    0x1.2p-52,
    (int)3
  },
  { // Entry 266
    0x1.20p-48,
    0x1.2p-52,
    (int)4
  },
  { // Entry 267
    0x1.20p-47,
    0x1.2p-52,
    (int)5
  },
  { // Entry 268
    0x1.20p-46,
    0x1.2p-52,
    (int)6
  },
  { // Entry 269
    0x1.20p-45,
    0x1.2p-52,
    (int)7
  },
  { // Entry 270
    0x1.20p-44,
    0x1.2p-52,
    (int)8
  },
  { // Entry 271
    0x1.20p-43,
    0x1.2p-52,
    (int)9
  },
  { // Entry 272
    0x1.20p-42,
    0x1.2p-52,
    (int)10
  },
  { // Entry 273
    0x1.745d1745d17580p-14,
    0x1.745d1745d1758p-4,
    (int)-10
  },
  { // Entry 274
    0x1.745d1745d17580p-13,
    0x1.745d1745d1758p-4,
    (int)-9
  },
  { // Entry 275
    0x1.745d1745d17580p-12,
    0x1.745d1745d1758p-4,
    (int)-8
  },
  { // Entry 276
    0x1.745d1745d17580p-11,
    0x1.745d1745d1758p-4,
    (int)-7
  },
  { // Entry 277
    0x1.745d1745d17580p-10,
    0x1.745d1745d1758p-4,
    (int)-6
  },
  { // Entry 278
    0x1.745d1745d17580p-9,
    0x1.745d1745d1758p-4,
    (int)-5
  },
  { // Entry 279
    0x1.745d1745d17580p-8,
    0x1.745d1745d1758p-4,
    (int)-4
  },
  { // Entry 280
    0x1.745d1745d17580p-7,
    0x1.745d1745d1758p-4,
    (int)-3
  },
  { // Entry 281
    0x1.745d1745d17580p-6,
    0x1.745d1745d1758p-4,
    (int)-2
  },
  { // Entry 282
    0x1.745d1745d17580p-5,
    0x1.745d1745d1758p-4,
    (int)-1
  },
  { // Entry 283
    0x1.745d1745d17580p-4,
    0x1.745d1745d1758p-4,
    (int)0
  },
  { // Entry 284
    0x1.745d1745d17580p-3,
    0x1.745d1745d1758p-4,
    (int)1
  },
  { // Entry 285
    0x1.745d1745d17580p-2,
    0x1.745d1745d1758p-4,
    (int)2
  },
  { // Entry 286
    0x1.745d1745d17580p-1,
    0x1.745d1745d1758p-4,
    (int)3
  },
  { // Entry 287
    0x1.745d1745d17580p0,
    0x1.745d1745d1758p-4,
    (int)4
  },
  { // Entry 288
    0x1.745d1745d17580p1,
    0x1.745d1745d1758p-4,
    (int)5
  },
  { // Entry 289
    0x1.745d1745d17580p2,
    0x1.745d1745d1758p-4,
    (int)6
  },
  { // Entry 290
    0x1.745d1745d17580p3,
    0x1.745d1745d1758p-4,
    (int)7
  },
  { // Entry 291
    0x1.745d1745d17580p4,
    0x1.745d1745d1758p-4,
    (int)8
  },
  { // Entry 292
    0x1.745d1745d17580p5,
    0x1.745d1745d1758p-4,
    (int)9
  },
  { // Entry 293
    0x1.745d1745d17580p6,
    0x1.745d1745d1758p-4,
    (int)10
  },
  { // Entry 294
    0x1.745d1745d174f0p-13,
    0x1.745d1745d174fp-3,
    (int)-10
  },
  { // Entry 295
    0x1.745d1745d174f0p-12,
    0x1.745d1745d174fp-3,
    (int)-9
  },
  { // Entry 296
    0x1.745d1745d174f0p-11,
    0x1.745d1745d174fp-3,
    (int)-8
  },
  { // Entry 297
    0x1.745d1745d174f0p-10,
    0x1.745d1745d174fp-3,
    (int)-7
  },
  { // Entry 298
    0x1.745d1745d174f0p-9,
    0x1.745d1745d174fp-3,
    (int)-6
  },
  { // Entry 299
    0x1.745d1745d174f0p-8,
    0x1.745d1745d174fp-3,
    (int)-5
  },
  { // Entry 300
    0x1.745d1745d174f0p-7,
    0x1.745d1745d174fp-3,
    (int)-4
  },
  { // Entry 301
    0x1.745d1745d174f0p-6,
    0x1.745d1745d174fp-3,
    (int)-3
  },
  { // Entry 302
    0x1.745d1745d174f0p-5,
    0x1.745d1745d174fp-3,
    (int)-2
  },
  { // Entry 303
    0x1.745d1745d174f0p-4,
    0x1.745d1745d174fp-3,
    (int)-1
  },
  { // Entry 304
    0x1.745d1745d174f0p-3,
    0x1.745d1745d174fp-3,
    (int)0
  },
  { // Entry 305
    0x1.745d1745d174f0p-2,
    0x1.745d1745d174fp-3,
    (int)1
  },
  { // Entry 306
    0x1.745d1745d174f0p-1,
    0x1.745d1745d174fp-3,
    (int)2
  },
  { // Entry 307
    0x1.745d1745d174f0p0,
    0x1.745d1745d174fp-3,
    (int)3
  },
  { // Entry 308
    0x1.745d1745d174f0p1,
    0x1.745d1745d174fp-3,
    (int)4
  },
  { // Entry 309
    0x1.745d1745d174f0p2,
    0x1.745d1745d174fp-3,
    (int)5
  },
  { // Entry 310
    0x1.745d1745d174f0p3,
    0x1.745d1745d174fp-3,
    (int)6
  },
  { // Entry 311
    0x1.745d1745d174f0p4,
    0x1.745d1745d174fp-3,
    (int)7
  },
  { // Entry 312
    0x1.745d1745d174f0p5,
    0x1.745d1745d174fp-3,
    (int)8
  },
  { // Entry 313
    0x1.745d1745d174f0p6,
    0x1.745d1745d174fp-3,
    (int)9
  },
  { // Entry 314
    0x1.745d1745d174f0p7,
    0x1.745d1745d174fp-3,
    (int)10
  },
  { // Entry 315
    0x1.1745d1745d1790p-12,
    0x1.1745d1745d179p-2,
    (int)-10
  },
  { // Entry 316
    0x1.1745d1745d1790p-11,
    0x1.1745d1745d179p-2,
    (int)-9
  },
  { // Entry 317
    0x1.1745d1745d1790p-10,
    0x1.1745d1745d179p-2,
    (int)-8
  },
  { // Entry 318
    0x1.1745d1745d1790p-9,
    0x1.1745d1745d179p-2,
    (int)-7
  },
  { // Entry 319
    0x1.1745d1745d1790p-8,
    0x1.1745d1745d179p-2,
    (int)-6
  },
  { // Entry 320
    0x1.1745d1745d1790p-7,
    0x1.1745d1745d179p-2,
    (int)-5
  },
  { // Entry 321
    0x1.1745d1745d1790p-6,
    0x1.1745d1745d179p-2,
    (int)-4
  },
  { // Entry 322
    0x1.1745d1745d1790p-5,
    0x1.1745d1745d179p-2,
    (int)-3
  },
  { // Entry 323
    0x1.1745d1745d1790p-4,
    0x1.1745d1745d179p-2,
    (int)-2
  },
  { // Entry 324
    0x1.1745d1745d1790p-3,
    0x1.1745d1745d179p-2,
    (int)-1
  },
  { // Entry 325
    0x1.1745d1745d1790p-2,
    0x1.1745d1745d179p-2,
    (int)0
  },
  { // Entry 326
    0x1.1745d1745d1790p-1,
    0x1.1745d1745d179p-2,
    (int)1
  },
  { // Entry 327
    0x1.1745d1745d1790p0,
    0x1.1745d1745d179p-2,
    (int)2
  },
  { // Entry 328
    0x1.1745d1745d1790p1,
    0x1.1745d1745d179p-2,
    (int)3
  },
  { // Entry 329
    0x1.1745d1745d1790p2,
    0x1.1745d1745d179p-2,
    (int)4
  },
  { // Entry 330
    0x1.1745d1745d1790p3,
    0x1.1745d1745d179p-2,
    (int)5
  },
  { // Entry 331
    0x1.1745d1745d1790p4,
    0x1.1745d1745d179p-2,
    (int)6
  },
  { // Entry 332
    0x1.1745d1745d1790p5,
    0x1.1745d1745d179p-2,
    (int)7
  },
  { // Entry 333
    0x1.1745d1745d1790p6,
    0x1.1745d1745d179p-2,
    (int)8
  },
  { // Entry 334
    0x1.1745d1745d1790p7,
    0x1.1745d1745d179p-2,
    (int)9
  },
  { // Entry 335
    0x1.1745d1745d1790p8,
    0x1.1745d1745d179p-2,
    (int)10
  },
  { // Entry 336
    0x1.745d1745d174a0p-12,
    0x1.745d1745d174ap-2,
    (int)-10
  },
  { // Entry 337
    0x1.745d1745d174a0p-11,
    0x1.745d1745d174ap-2,
    (int)-9
  },
  { // Entry 338
    0x1.745d1745d174a0p-10,
    0x1.745d1745d174ap-2,
    (int)-8
  },
  { // Entry 339
    0x1.745d1745d174a0p-9,
    0x1.745d1745d174ap-2,
    (int)-7
  },
  { // Entry 340
    0x1.745d1745d174a0p-8,
    0x1.745d1745d174ap-2,
    (int)-6
  },
  { // Entry 341
    0x1.745d1745d174a0p-7,
    0x1.745d1745d174ap-2,
    (int)-5
  },
  { // Entry 342
    0x1.745d1745d174a0p-6,
    0x1.745d1745d174ap-2,
    (int)-4
  },
  { // Entry 343
    0x1.745d1745d174a0p-5,
    0x1.745d1745d174ap-2,
    (int)-3
  },
  { // Entry 344
    0x1.745d1745d174a0p-4,
    0x1.745d1745d174ap-2,
    (int)-2
  },
  { // Entry 345
    0x1.745d1745d174a0p-3,
    0x1.745d1745d174ap-2,
    (int)-1
  },
  { // Entry 346
    0x1.745d1745d174a0p-2,
    0x1.745d1745d174ap-2,
    (int)0
  },
  { // Entry 347
    0x1.745d1745d174a0p-1,
    0x1.745d1745d174ap-2,
    (int)1
  },
  { // Entry 348
    0x1.745d1745d174a0p0,
    0x1.745d1745d174ap-2,
    (int)2
  },
  { // Entry 349
    0x1.745d1745d174a0p1,
    0x1.745d1745d174ap-2,
    (int)3
  },
  { // Entry 350
    0x1.745d1745d174a0p2,
    0x1.745d1745d174ap-2,
    (int)4
  },
  { // Entry 351
    0x1.745d1745d174a0p3,
    0x1.745d1745d174ap-2,
    (int)5
  },
  { // Entry 352
    0x1.745d1745d174a0p4,
    0x1.745d1745d174ap-2,
    (int)6
  },
  { // Entry 353
    0x1.745d1745d174a0p5,
    0x1.745d1745d174ap-2,
    (int)7
  },
  { // Entry 354
    0x1.745d1745d174a0p6,
    0x1.745d1745d174ap-2,
    (int)8
  },
  { // Entry 355
    0x1.745d1745d174a0p7,
    0x1.745d1745d174ap-2,
    (int)9
  },
  { // Entry 356
    0x1.745d1745d174a0p8,
    0x1.745d1745d174ap-2,
    (int)10
  },
  { // Entry 357
    0x1.d1745d1745d1c0p-12,
    0x1.d1745d1745d1cp-2,
    (int)-10
  },
  { // Entry 358
    0x1.d1745d1745d1c0p-11,
    0x1.d1745d1745d1cp-2,
    (int)-9
  },
  { // Entry 359
    0x1.d1745d1745d1c0p-10,
    0x1.d1745d1745d1cp-2,
    (int)-8
  },
  { // Entry 360
    0x1.d1745d1745d1c0p-9,
    0x1.d1745d1745d1cp-2,
    (int)-7
  },
  { // Entry 361
    0x1.d1745d1745d1c0p-8,
    0x1.d1745d1745d1cp-2,
    (int)-6
  },
  { // Entry 362
    0x1.d1745d1745d1c0p-7,
    0x1.d1745d1745d1cp-2,
    (int)-5
  },
  { // Entry 363
    0x1.d1745d1745d1c0p-6,
    0x1.d1745d1745d1cp-2,
    (int)-4
  },
  { // Entry 364
    0x1.d1745d1745d1c0p-5,
    0x1.d1745d1745d1cp-2,
    (int)-3
  },
  { // Entry 365
    0x1.d1745d1745d1c0p-4,
    0x1.d1745d1745d1cp-2,
    (int)-2
  },
  { // Entry 366
    0x1.d1745d1745d1c0p-3,
    0x1.d1745d1745d1cp-2,
    (int)-1
  },
  { // Entry 367
    0x1.d1745d1745d1c0p-2,
    0x1.d1745d1745d1cp-2,
    (int)0
  },
  { // Entry 368
    0x1.d1745d1745d1c0p-1,
    0x1.d1745d1745d1cp-2,
    (int)1
  },
  { // Entry 369
    0x1.d1745d1745d1c0p0,
    0x1.d1745d1745d1cp-2,
    (int)2
  },
  { // Entry 370
    0x1.d1745d1745d1c0p1,
    0x1.d1745d1745d1cp-2,
    (int)3
  },
  { // Entry 371
    0x1.d1745d1745d1c0p2,
    0x1.d1745d1745d1cp-2,
    (int)4
  },
  { // Entry 372
    0x1.d1745d1745d1c0p3,
    0x1.d1745d1745d1cp-2,
    (int)5
  },
  { // Entry 373
    0x1.d1745d1745d1c0p4,
    0x1.d1745d1745d1cp-2,
    (int)6
  },
  { // Entry 374
    0x1.d1745d1745d1c0p5,
    0x1.d1745d1745d1cp-2,
    (int)7
  },
  { // Entry 375
    0x1.d1745d1745d1c0p6,
    0x1.d1745d1745d1cp-2,
    (int)8
  },
  { // Entry 376
    0x1.d1745d1745d1c0p7,
    0x1.d1745d1745d1cp-2,
    (int)9
  },
  { // Entry 377
    0x1.d1745d1745d1c0p8,
    0x1.d1745d1745d1cp-2,
    (int)10
  },
  { // Entry 378
    0x1.1745d1745d1770p-11,
    0x1.1745d1745d177p-1,
    (int)-10
  },
  { // Entry 379
    0x1.1745d1745d1770p-10,
    0x1.1745d1745d177p-1,
    (int)-9
  },
  { // Entry 380
    0x1.1745d1745d1770p-9,
    0x1.1745d1745d177p-1,
    (int)-8
  },
  { // Entry 381
    0x1.1745d1745d1770p-8,
    0x1.1745d1745d177p
```
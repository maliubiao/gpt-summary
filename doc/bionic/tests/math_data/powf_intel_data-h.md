Response:
Let's break down the thought process for analyzing this C code snippet.

**1. Understanding the Context:**

The initial prompt provides crucial context:

* **File path:** `bionic/tests/math_data/powf_intel_data.handroid`
* **Project:** bionic (Android's C library, math library, and dynamic linker)
* **Programming Language:** C (indicated by `.handroid` extension and C-style comments)
* **Purpose:** Data for testing the `powf` function (floating-point power).
* **Architecture:** "intel" in the filename suggests these tests are specific to Intel architectures.
* **Format:**  The data is presented as an array of structs.

**2. Initial Code Scan and Interpretation:**

A quick scan reveals the following:

* **Copyright and License:** Standard Apache 2.0 license, indicating open-source nature.
* **`static` keyword:** The `g_powf_intel_data` array is only visible within this compilation unit. This is a good practice for test data.
* **`data_1_2_t<float, float, float>`:**  This is a template or typedef defining the structure of each data entry. It holds three floats.
* **Array Initialization:** The code initializes a global array named `g_powf_intel_data` with numerous entries.
* **Hexadecimal Floating-Point Literals:**  Values like `0x1.p0`, `-0x1.000002p-1` are hexadecimal representations of floating-point numbers. This is common in low-level math libraries for precise specification.
* **`HUGE_VALF`:** This likely represents positive infinity for floats.

**3. Deducing Functionality:**

Based on the file name and the data structure, the primary function is clear:

* **Test Data for `powf`:** The array likely contains sets of input values for `powf(base, exponent)` and the expected `result`.

**4. Connecting to Android Functionality:**

* **`bionic` Library:** The file is part of Android's core C library (`bionic`). This means the `powf` function being tested is the one provided by Android.
* **NDK Usage:** Developers using the Android NDK (Native Development Kit) would indirectly use this `powf` implementation when performing floating-point exponentiation in their native code.

**5. Inferring `libc` and Dynamic Linker Roles (Anticipatory):**

While this specific file *is data*, its existence implies a larger context:

* **`libc` (`bionic`):**  The `powf` function itself is a standard C library function, and its implementation resides within `bionic`. This data is used to verify the correctness of that implementation.
* **Dynamic Linker:** When an Android app (or a native library) uses `powf`, the dynamic linker is responsible for resolving the symbol and linking the application to the correct `powf` implementation in `bionic`. Although this file doesn't directly *demonstrate* dynamic linking, its purpose is tied to the functionality of a linked library.

**6. Analyzing Data Structure and Interpretation (Logical Reasoning):**

The `data_1_2_t<float, float, float>` structure strongly suggests:

* **Input 1 (Base):** The first float value in each entry.
* **Input 2 (Exponent):** The second float value.
* **Output (Expected Result):** The third float value.

**7. Considering Potential Usage Errors (Anticipatory):**

While this file *isn't code that users directly call*, it tests a function that users *do* call. Therefore, common errors related to `powf` are relevant:

* **Domain Errors:**  Raising a negative base to a non-integer power.
* **Overflow/Underflow:**  Results too large or too small to represent.
* **NaN (Not a Number):**  Invalid operations (e.g., 0 raised to a negative power, negative infinity raised to a fractional power).

**8. Thinking About Frida Hooks and Debugging (Anticipatory):**

To debug `powf`'s implementation, one could hook the function using Frida:

* **Hooking `powf`:** Intercept calls to the `powf` function.
* **Examining Arguments:**  Log the input `base` and `exponent` values.
* **Examining Return Value:** Log the calculated result.
* **Tracing Execution:** Step through the `powf` implementation in a debugger.

**9. Structuring the Response (Based on the Prompt's Requirements):**

The prompt specifically asked for:

* **Functionality:** Describe what the file does.
* **Android Relevance:** Explain its connection to Android.
* **`libc` Function Explanation:**  Normally, this would involve detailing the `powf` implementation, but this file is just *data*. So, focus on the *purpose* of `powf`.
* **Dynamic Linker:** Discuss how `powf` is linked (though this file doesn't show the linking process itself).
* **Logical Reasoning (Input/Output):**  Explain the structure of the test data.
* **Common Errors:**  Relate to `powf` usage.
* **Android Framework/NDK and Frida:** Explain how calls reach `powf` and how to debug.

**10. Refining and Summarizing:**

Finally, synthesize all the information into a clear, concise, and well-organized response, addressing each point of the prompt. The "归纳一下它的功能" (summarize its functionality) part requires extracting the core purpose: providing test data for `powf`.

This detailed breakdown illustrates how to approach analyzing a seemingly simple code snippet by considering its context, purpose, and implications within a larger system like Android. Even though the provided code is just data, understanding its role in testing allows for a comprehensive analysis.
好的，这是对给定源代码文件 `bionic/tests/math_data/powf_intel_data.handroid` 的分析和功能归纳。

**功能归纳:**

该文件定义了一个静态的 C 结构体数组 `g_powf_intel_data`，其主要功能是作为 **针对 `powf` 函数在 Intel 架构上的测试数据集合**。

具体来说，这个数组中的每一个元素都包含了三个 `float` 类型的值，分别代表了 `powf` 函数的：

1. **底数 (base)**
2. **指数 (exponent)**
3. **期望的计算结果 (expected result)**

这些数据被设计用来覆盖 `powf` 函数在不同输入情况下的行为，包括：

* **特殊值:**  例如 `HUGE_VALF` (正无穷)、0.0f、-0.0f 等。
* **正常值:**  各种正数、负数、小数、整数的组合。
* **边界值:**  接近零、接近无穷大、以及一些可能导致特殊情况的值。
* **不同数量级的数值:**  以测试 `powf` 在处理大数和小数时的精度和正确性。

**与 Android 功能的关系及举例说明:**

* **`powf` 函数的测试:**  `powf` 是 C 标准库 `<math.h>` 中定义的计算浮点数幂的函数。在 Android 中，这个函数由 `bionic` 库提供实现。此数据文件是 `bionic` 库的一部分，专门用于测试其 `powf` 函数的正确性。
* **确保数学库的正确性:**  Android 系统依赖于 `bionic` 库提供的数学函数来进行各种计算。确保这些函数的正确性对于系统的稳定性和应用程序的准确性至关重要。这个数据文件通过提供大量的测试用例来验证 `powf` 函数的实现是否符合预期。
* **特定于 Intel 架构的测试:** 文件名中的 "intel" 表明这些测试数据可能是为了覆盖 `powf` 函数在 Intel 架构上的特定行为或潜在问题。不同的处理器架构在浮点数运算上可能存在细微的差异，因此需要针对不同的架构进行测试。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件本身 **不包含任何 `libc` 函数的实现代码**，它仅仅是用于测试 `powf` 函数的数据。  `powf` 函数的实现通常是一个复杂的算法，可能涉及到以下步骤：

1. **处理特殊情况:**  例如底数为 1 或 0，指数为 0 或 1，或者底数或指数为无穷大或 NaN (Not a Number)。
2. **处理底数为负数的情况:**  如果指数是整数，则可以直接计算；如果指数是小数，则结果通常是 NaN。
3. **对于正数底数:**
   * 将底数取对数 (通常使用自然对数 `log`)。
   * 将对数结果乘以指数。
   * 计算指数的结果 (通常使用指数函数 `exp`)。
   * 公式：`powf(base, exponent) = exp(exponent * log(base))`

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个数据文件本身 **不直接涉及 dynamic linker 的功能**。Dynamic linker 的作用是在程序运行时将可执行文件或共享库加载到内存中，并解析和链接程序中引用的符号。

当一个 Android 应用或 Native 库调用 `powf` 函数时，链接过程如下：

1. **编译时:** 编译器遇到 `powf` 函数调用时，会在目标文件中记录一个对 `powf` 符号的未解析引用。
2. **链接时:** 链接器将应用程序的代码和所需的共享库（通常是 `libc.so` 或其变体）组合在一起。链接器会查找 `libc.so` 中 `powf` 符号的定义，并将应用程序中的引用指向 `libc.so` 中的 `powf` 实现。
3. **运行时:** 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会加载必要的共享库，包括 `libc.so`。Dynamic linker 会根据链接时建立的符号引用关系，将应用程序中对 `powf` 的调用指向 `libc.so` 中 `powf` 函数的实际代码地址。

**so 布局样本:**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
  .text:  // 包含可执行代码
    ...
    powf:  // powf 函数的实现代码
      ...
    ...
  .data:  // 包含已初始化的全局变量
    ...
  .bss:   // 包含未初始化的全局变量
    ...
  .dynsym: // 动态符号表，包含导出的符号 (例如 powf)
    ...
    powf (地址)
    ...
  .dynstr: // 动态字符串表，包含符号名称
    ...
    powf
    ...
  ...
```

**链接的处理过程:**

当应用程序加载时，dynamic linker 会扫描其依赖的共享库 (`libc.so`) 的 `.dynsym` 和 `.dynstr` 段，找到 `powf` 符号的地址。然后，它会更新应用程序中对 `powf` 的引用，使其指向 `libc.so` 中 `powf` 函数的实际内存地址。

**如果做了逻辑推理，请给出假设输入与输出:**

这个文件中的数据本身就是逻辑推理的结果，它预设了各种输入和期望的输出。 例如：

* **假设输入:** 底数为 `HUGE_VALF` (正无穷)，指数为 `-0.0`。
* **期望输出:** `-0x1.000002p-1` (一个非常小的负数，接近 -0.5)。  这可能是在定义中，正无穷的负零次幂被定义为接近0的负数。

* **假设输入:** 底数为 `0.0f`，指数为 `-0x1.p-5` (非常小的负数)。
* **期望输出:** `0x1.e0p4` (十进制 30720)。这表示接近于 0 的数的负数次幂会趋向于无穷大。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然这个文件是测试数据，但它反映了 `powf` 函数可能遇到的各种情况，其中一些对应于用户或编程的常见错误：

* **底数为负数，指数为非整数:**  `powf(-2.0f, 0.5f)` 将返回 NaN (Not a Number)，因为负数的非整数次幂在实数范围内没有定义。
* **底数为零，指数为负数:** `powf(0.0f, -2.0f)` 将导致无穷大，这可能在某些应用场景下是错误的行为。
* **结果溢出或下溢:**  对于非常大或非常小的底数和指数，`powf` 的结果可能会超出浮点数的表示范围，导致溢出 (返回 `HUGE_VALF`) 或下溢 (返回 0)。例如，`powf(10.0f, 100.0f)` 可能会溢出。
* **精度问题:**  浮点数运算本身存在精度问题。对于某些特定的输入，`powf` 的计算结果可能与理论值存在细微的差别。这些测试数据也可能用于验证 `powf` 在各种情况下的精度是否在可接受的范围内。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用 `powf`:**
   * **Framework:** Android Framework 本身是用 Java 编写的，不太可能直接调用 `powf`。但是，Framework 可能会调用 Native 代码，而 Native 代码中可能会使用 `powf`。
   * **NDK:** 使用 NDK 开发的 Native 应用可以直接调用 `powf` 函数。例如，一个图形渲染引擎或者一个科学计算应用可能会使用 `powf` 进行计算。

2. **NDK 调用 `powf` 的过程:**
   * C/C++ 代码中包含 `<math.h>` 头文件并调用 `powf` 函数。
   * 编译器将 `powf` 编译为对该符号的外部引用。
   * 链接器将 Native 库与 `libc.so` 链接，解析 `powf` 符号。
   * 在 Android 设备上，当 Native 库被加载时，dynamic linker 将 `powf` 的调用链接到 `bionic` 库中的实现。

3. **Frida Hook 示例:**

   你可以使用 Frida 来 hook `powf` 函数，查看其输入和输出，从而间接验证这些测试数据的作用。

   **JavaScript Frida Hook 代码:**

   ```javascript
   if (Process.arch === 'arm64' || Process.arch === 'x64') {
       const powf = Module.findExportByName("libc.so", "powf");
       if (powf) {
           Interceptor.attach(powf, {
               onEnter: function (args) {
                   const base = args[0].readFloat();
                   const exponent = args[1].readFloat();
                   console.log(`[powf] base: ${base}, exponent: ${exponent}`);
               },
               onLeave: function (retval) {
                   const result = retval.readFloat();
                   console.log(`[powf] result: ${result}`);
               }
           });
           console.log("Attached to powf");
       } else {
           console.error("powf not found in libc.so");
       }
   } else {
       console.log("Skipping powf hook on 32-bit architecture (arguments might be different).");
   }
   ```

   **使用方法:**

   1. 将上述 JavaScript 代码保存为 `hook_powf.js`。
   2. 使用 Frida 连接到目标 Android 进程 (例如，你的 NDK 应用的进程):
      ```bash
      frida -U -f <your_package_name> -l hook_powf.js --no-pause
      ```
      或者，如果进程已经在运行：
      ```bash
      frida -U <your_package_name> -l hook_powf.js
      ```

   **调试步骤:**

   当你的 NDK 应用调用 `powf` 函数时，Frida hook 会拦截该调用，并打印出 `powf` 的底数、指数和返回值。你可以通过观察这些值来了解 `powf` 的行为，并与 `powf_intel_data.handroid` 文件中的预期结果进行对比。

**总结:**

`bionic/tests/math_data/powf_intel_data.handroid` 文件是一个关键的组成部分，用于确保 Android 系统中 `powf` 函数在 Intel 架构上的正确实现。它通过提供大量的测试用例，覆盖了 `powf` 函数可能遇到的各种输入情况，帮助开发者验证 `bionic` 库的数学运算功能的可靠性。虽然它本身不包含可执行代码，但它在软件测试和质量保证方面发挥着重要的作用。

Prompt: 
```
这是目录为bionic/tests/math_data/powf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

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

static data_1_2_t<float, float, float> g_powf_intel_data[] = {
  { // Entry 0
    HUGE_VALF,
    -0.0, -0x1.000002p-1
  },
  { // Entry 1
    0.0f,
    -0x1.p-5, 0x1.e0p4
  },
  { // Entry 2
    -0.0f,
    -0x1.p-30, 0x1.40p2
  },
  { // Entry 3
    0x1.p0,
    -0x1.p0, 0x1.000002p32
  },
  { // Entry 4
    0x1.p0,
    -0x1.000002p-41, 0.0
  },
  { // Entry 5
    0x1.d1a029128778fca3f9a261be1cb86be7p-121,
    -0x1.000006p0, -0x1.bc1ee2p27
  },
  { // Entry 6
    0x1.da6e3ff202da752de523f9846303c0b5p-124,
    -0x1.00000ap0, -0x1.111112p27
  },
  { // Entry 7
    0x1.eb70a2fbb8b2489b8d838eb65ed676acp-91,
    -0x1.00000ap0, -0x1.8f83e4p26
  },
  { // Entry 8
    HUGE_VALF,
    -0x1.000028p0, 0x1.20p44
  },
  { // Entry 9
    0x1.002001p-4,
    -0x1.0010p-2, 0x1.p1
  },
  { // Entry 10
    0x1.002001p-82,
    -0x1.0010p-41, 0x1.p1
  },
  { // Entry 11
    0x1.004004p-82,
    -0x1.0020p-41, 0x1.p1
  },
  { // Entry 12
    0x1.006009p-12,
    -0x1.0030p-6, 0x1.p1
  },
  { // Entry 13
    -0x1.fb859adbdb7df6974c5c9a5489e6972ap53,
    -0x1.0040p-6, -0x1.20p3
  },
  { // Entry 14
    0x1.008010p-82,
    -0x1.0040p-41, 0x1.p1
  },
  { // Entry 15
    0x1.00e031p-40,
    -0x1.0070p-20, 0x1.p1
  },
  { // Entry 16
    0x1.31e452ffffec96a3d5a882fe244f8c63p-1,
    -0x1.046ef4p0, -0x1.e0p4
  },
  { // Entry 17
    0x1.33e8f304p-36,
    -0x1.08p-6, 0x1.80p2
  },
  { // Entry 18
    0x1.d82001fe9d6bdbba98638def8d37e50bp-124,
    -0x1.1ec38cp0, -0x1.78p9
  },
  { // Entry 19
    -0x1.45f3bdeaa5f60d121c3fa751dbd758adp36,
    -0x1.bffffep-6, -0x1.c0p2
  },
  { // Entry 20
    0x1.df41ae7ef4e15e8ad45c7293ddc3fe7dp61,
    -0x1.fffffap-1, -0x1.c9b244p27
  },
  { // Entry 21
    0x1.df46f26f1f129a54922022f9b653a99fp61,
    -0x1.fffffap-1, -0x1.c9b262p27
  },
  { // Entry 22
    -0x1.00000300000900001b0000510000f3p21,
    -0x1.fffffap-22, -0x1.p0
  },
  { // Entry 23
    -0x1.00000300000900001b0000510000f3p-99,
    -0x1.fffffap98, -0x1.p0
  },
  { // Entry 24
    -0x1.78b55ef8aecb0b7c5b8865e27157d824p-2,
    -0x1.fffffcp-1, 0x1.000002p23
  },
  { // Entry 25
    -0x1.fffffep-41,
    -0x1.fffffep-41, 0x1.p0
  },
  { // Entry 26
    0x1.p71,
    0x1.p-2, -0x1.1cp5
  },
  { // Entry 27
    0x1.d580710e38463c3dd62fce98f203b471p-1,
    0x1.p-2, 0x1.0007p-4
  },
  { // Entry 28
    0x1.p-15,
    0x1.p-2, 0x1.e0p2
  },
  { // Entry 29
    0.0f,
    0x1.p-3, 0x1.8ffffep5
  },
  { // Entry 30
    0x1.p-40,
    0x1.p-5, 0x1.p3
  },
  { // Entry 31
    0x1.p40,
    0x1.p-10, -0x1.p2
  },
  { // Entry 32
    0x1.ecfff0b449d7c9a5d494c884c717f9cdp-88,
    0x1.p-144, 0x1.3586fep-1
  },
  { // Entry 33
    0x1.ecfff0b449d7c9a5d494c884c717f9cdp-106,
    0x1.p-144, 0x1.7586fep-1
  },
  { // Entry 34
    HUGE_VALF,
    0x1.p-149, -0x1.ccacccp-1
  },
  { // Entry 35
    HUGE_VALF,
    0x1.p-149, -0x1.e6e666p-1
  },
  { // Entry 36
    0x1.e8e101355bd975bfec3fb5ed3757777dp-1,
    0x1.000002p-2, 0x1.1111p-5
  },
  { // Entry 37
    0x1.ddb64347a55e452ed04d6a173ca5b56cp99,
    0x1.000002p-111, -0x1.ccccccp-1
  },
  { // Entry 38
    0x1.558e990004a8ebb3e8176275ba9f1052p52,
    0x1.000002p-112, -0x1.df3b5ap-2
  },
  { // Entry 39
    0x1.fffffd0000053ffff66000120bffddb6p92,
    0x1.000002p-124, -0x1.80p-1
  },
  { // Entry 40
    0x1.fffffffffff800000800000555554555p-1,
    0x1.000002p0, -0x1.p-23
  },
  { // Entry 41
    0x1.fffffffffff9000007000002eaaaa02ap-1,
    0x1.000002p0, -0x1.c0p-24
  },
  { // Entry 42
    0x1.ddb6530d485b7badb441a4460ca54c62p9,
    0x1.000002p11, 0x1.ccccc6p-1
  },
  { // Entry 43
    0x1.d901790cd9d1b9d8cdf616296479022fp-14,
    0x1.000002p17, -0x1.8af8b0p-1
  },
  { // Entry 44
    0x1.e6d3f90d414447b2f2467d4c214496bdp30,
    0x1.000002p42, 0x1.7904a4p-1
  },
  { // Entry 45
    0x1.000012ffffd68004fa7fb159108ec97dp0,
    0x1.00001cp0, 0x1.5b6dbap-1
  },
  { // Entry 46
    0x1.d174810e1e4527f011547dfc4dc6b48cp-3,
    0x1.00001cp3, -0x1.6ccccep-1
  },
  { // Entry 47
    0x1.d581970e8b4ccc9dbc28899bd1848e24p-1,
    0x1.00002ep-2, 0x1.ffffcep-5
  },
  { // Entry 48
    0x1.000455000312cc6e79ced653c38d7e2ap0,
    0x1.000038p-50, -0x1.fff77ep-20
  },
  { // Entry 49
    0x1.00480900a807e03f01500480090008p-81,
    0x1.0008p-9, 0x1.20p3
  },
  { // Entry 50
    0x1.ffc004ffb0045fc8029fe20149f2408ep39,
    0x1.0008p-10, -0x1.p2
  },
  { // Entry 51
    0x1.fec1bb35b5a826526101adab0695d1d3p-1,
    0x1.00e0p0, -0x1.6ccccep-1
  },
  { // Entry 52
    0x1.fadbde187acba5b3a6c4cde78e1bbb4ap45,
    0x1.01fffcp0, 0x1.p12
  },
  { // Entry 53
    0x1.ff1fb6ff79a5e0391b1d7dfb14de7de6p22,
    0x1.01fffep0, 0x1.000cb6p11
  },
  { // Entry 54
    0x1.6cbbc2fff64c73aab0033df757f3808dp11,
    0x1.0220p0, 0x1.e295f2p9
  },
  { // Entry 55
    0x1.f81f5312ba449421bd9393ad8df53aaep-1,
    0x1.04p0, -0x1.0006p0
  },
  { // Entry 56
    0x1.ffe88affffff33e933cfaad5f0ee2678p-1,
    0x1.08c7eep-16, 0x1.0f94b2p-16
  },
  { // Entry 57
    0x1.0000dcffffc6fee7e4aac09a3d9fb9a1p0,
    0x1.0ep-20, -0x1.000cdcp-20
  },
  { // Entry 58
    0x1.70ce05e629803c0ca47482392a882debp-3,
    0x1.0ep3, -0x1.9b91bap-1
  },
  { // Entry 59
    0x1.5a8926e473f6148a5a383bfa1ed0b335p-90,
    0x1.0ffffep0, -0x1.0000fep10
  },
  { // Entry 60
    0x1.8ec5b2e1606728f21cf2c90c2e4d2a9bp-93,
    0x1.0ffffep0, -0x1.07fffep10
  },
  { // Entry 61
    0x1.a47dd4ffffe25486314351413837b2fdp4,
    0x1.1624p-4, -0x1.3720c0p0
  },
  { // Entry 62
    0x1.442401p0,
    0x1.2010p0, 0x1.p1
  },
  { // Entry 63
    0x1.e7aaf2ffffbce86a4fd2cf9cb53d7e55p-1,
    0x1.253264p0, -0x1.6f826ep-2
  },
  { // Entry 64
    0x1.4d63290052d4d2d894b4635cb9b98130p-39,
    0x1.2711c8p-6, 0x1.aa804ep2
  },
  { // Entry 65
    0x1.b20168da0fc1fca6d3c1b8c23fdcaf39p49,
    0x1.2aaaaap-1, -0x1.fff1fep5
  },
  { // Entry 66
    0x1.ee26c12ebf5b649bef95484ece113007p2,
    0x1.2f7dc0p-23, -0x1.0967c0p-3
  },
  { // Entry 67
    0x1.bc90590000002ee11763c6fe2418730cp-2,
    0x1.334478p-2, 0x1.62e42ep-1
  },
  { // Entry 68
    0x1.8c8c8300308cee7c1a41b09294323cfbp-82,
    0x1.3ffffep-1, 0x1.e0p6
  },
  { // Entry 69
    0x1.643d4efffe606e056e4035b0becc20fdp-5,
    0x1.3ffffep-40, 0x1.d2f190p-4
  },
  { // Entry 70
    0x1.f8148914d4ea3af94ee724572f2ee8ffp-1,
    0x1.41d420p20, -0x1.22p-10
  },
  { // Entry 71
    0x1.cd6e9100038c93a7dce72a113ca56c70p-2,
    0x1.443a42p-2, 0x1.62e42ep-1
  },
  { // Entry 72
    0x1.f895910f392f3b8fcc641ae87164d684p-1,
    0x1.45a2a8p1, -0x1.p-6
  },
  { // Entry 73
    0x1.e3dff8fff6e9efd4f167a7b91eb882afp-1,
    0x1.45d174p-1, 0x1.00001cp-3
  },
  { // Entry 74
    0x1.d332f0fffc83128a7fc7bd56be27e755p-2,
    0x1.4a1704p-2, 0x1.62e42ep-1
  },
  { // Entry 75
    0x1.d5ae790003cb17cf83deb5e2cc0ea01cp-2,
    0x1.4c9f94p-2, 0x1.62e42ep-1
  },
  { // Entry 76
    0x1.ca8ec6ed5df39f991f808d94dd5c8834p88,
    0x1.4e9cc2p-30, -0x1.80p1
  },
  { // Entry 77
    0x1.d9b648fffc167ed8b917b64f747e6270p-2,
    0x1.50bfc8p-2, 0x1.62e42ep-1
  },
  { // Entry 78
    0x1.da95070001a3799fee02ea034357a8c2p-2,
    0x1.51a450p-2, 0x1.62e42ep-1
  },
  { // Entry 79
    0x1.fe957b38c5b6959bb0ea80e43c709ecap-1,
    0x1.679286p-11, 0x1.8ea824p-12
  },
  { // Entry 80
    0x1.aca91b5f3882f36dcdab2a8d641c0ab5p-56,
    0x1.745d18p-4, 0x1.ff1ffep3
  },
  { // Entry 81
    0x1.f82eb711ff0066ee591658258b692331p-1,
    0x1.77fffep-120, 0x1.85bc7ap-13
  },
  { // Entry 82
    0x1.d98c8300003e83fd25b95381f702161cp-1,
    0x1.7a3d0ep0, -0x1.99999ap-3
  },
  { // Entry 83
    0x1.f82cef13a11a5f5a0562fe52c88207bdp-1,
    0x1.7c9a16p-2, 0x1.fddffep-7
  },
  { // Entry 84
    0x1.d0d014fffe715e2732b6d1ced96adb76p19,
    0x1.7e9bb0p-8, -0x1.569828p1
  },
  { // Entry 85
    0x1.8518e2fffdea301062ac6a29c6e53df6p-1,
    0x1.851ebap-1, 0x1.000ep0
  },
  { // Entry 86
    0x1.2da1e8fffe1350e4daf5553e75dca020p-4,
    0x1.861862p-4, 0x1.1cp0
  },
  { // Entry 87
    0x1.dd037a2c561bfe1824p-11,
    0x1.8ce632p-4, 0x1.80p1
  },
  { // Entry 88
    0x1.f81fa713d2b23eac52a36f4b3a33023ep-1,
    0x1.8f86aap-1, 0x1.0000e0p-4
  },
  { // Entry 89
    0x1.03f14b095ae687525a7e377e3505e587p0,
    0x1.90p5, 0x1.0008p-8
  },
  { // Entry 90
    0x1.36395100005cc4113b220d6ce672e165p0,
    0x1.95578ep1, 0x1.555556p-3
  },
  { // Entry 91
    0x1.f83249134e77a21bf811350c6a931beep-1,
    0x1.98p5, -0x1.000002p-8
  },
  { // Entry 92
    0x1.9f628b3cfd06f417f86e1ca8edc1469ep117,
    0x1.99999cp3, 0x1.p5
  },
  { // Entry 93
    0x1.d4851ccedafdd1cbc79a6a6b3dbb1cbep119,
    0x1.9a66d0p-14, -0x1.20p3
  },
  { // Entry 94
    0x1.2536270001fab70a29d68e60feb11211p-11,
    0x1.9ffffep41, -0x1.094f1cp-2
  },
  { // Entry 95
    0x1.d08ae8fffdc7029e0bd02c871606a01cp0,
    0x1.a57becp1, 0x1.p-1
  },
  { // Entry 96
    0x1.b83638ffb21561a23ec9b8a7b0ba7b52p15,
    0x1.aaaaaep-1, -0x1.e0p5
  },
  { // Entry 97
    0x1.c198860000001c1cee146e451365eae1p-10,
    0x1.ad1d1cp-14, 0x1.62e42ep-1
  },
  { // Entry 98
    0x1.cd0c6eefc33dfc2ef3d2beb81ad568cap30,
    0x1.b13b1cp-1, -0x1.ffff1ep6
  },
  { // Entry 99
    0x1.6228e4fef882769ba040164fc4bca0cbp-81,
    0x1.b7ffd8p-1, 0x1.705394p8
  },
  { // Entry 100
    0x1.ae9d756c84b4063f238dd151bec30e0bp-99,
    0x1.be0d7cp-1, 0x1.ede448p8
  },
  { // Entry 101
    0x1.913f68f101ebe490d29d873d1e0fd828p-85,
    0x1.be0f70p-1, 0x1.a8147ap8
  },
  { // Entry 102
    0x1.b1e7215c128082aab49edab1641919a8p-99,
    0x1.be0f70p-1, 0x1.ede5d8p8
  },
  { // Entry 103
    0x1.dc574183f03d7a333c18fc6916daa859p-96,
    0x1.bff0d0p-1, 0x1.ed2fb4p8
  },
  { // Entry 104
    0x1.da6fcd00020da659e4a50ba993a71d92p6,
    0x1.bffffep1, 0x1.e7f782p1
  },
  { // Entry 105
    HUGE_VALF,
    0x1.c25c26p-44, -0x1.40p3
  },
  { // Entry 106
    0x1.951dfaf0d0341097e50f8d51fb5b0b2ap-72,
    0x1.c4ec74p-1, 0x1.935234p8
  },
  { // Entry 107
    0x1.fb1c6cfffef199884e78c26fef057fc3p4,
    0x1.c76380p0, 0x1.80087cp2
  },
  { // Entry 108
    0x1.d82d7dffffefc26e1f09e6d73a276d81p-10,
    0x1.cc8d06p-14, 0x1.62e42ep-1
  },
  { // Entry 109
    0x1.997e0eef7bb3d4eda40dc43c72a53167p-70,
    0x1.d1cdccp-1, 0x1.fc2640p8
  },
  { // Entry 110
    0x1.fe82dd381a8d3056a4c554f1e1764f9dp-1,
    0x1.d40a66p-3, 0x1.02964cp-9
  },
  { // Entry 111
    0x1.f3ab1937169c9ab7aac67b94894ede10p-1,
    0x1.d55552p-2, 0x1.000038p-5
  },
  { // Entry 112
    0x1.fe805f37b89bc0c8b0163db7c11f48f2p-1,
    0x1.da12f0p-1, 0x1.38p-5
  },
  { // Entry 113
    0x1.c27937000f6c15a86f8eb042a0895566p-73,
    0x1.df0a82p-1, 0x1.77fbc0p9
  },
  { // Entry 114
    0x1.c64b0d000027dbefa1e3233ef53619b7p105,
    0x1.dffffep52, 0x1.00087cp1
  },
  { // Entry 115
    0x1.0847b080e10a3f33ba599a218b630ffbp0,
    0x1.e06b8cp-1, -0x1.p-1
  },
  { // Entry 116
    0x1.eff5716fa057c0db02972e5b51a95899p-1,
    0x1.e06b8cp-1, 0x1.p-1
  },
  { // Entry 117
    0x1.083f7f587cdb6cc005ee70abb128067cp0,
    0x1.e08956p-1, -0x1.p-1
  },
  { // Entry 118
    0x1.f004d186653df746f46ac1da51e68817p-1,
    0x1.e08956p-1, 0x1.p-1
  },
  { // Entry 119
    0x1.2e78986ce71690689a17b09e2fd01256p0,
    0x1.e0ee8ap-1, -0x1.5515p1
  },
  { // Entry 120
    0x1.34e306ebdacb3fb249efb92c5df50a30p0,
    0x1.e0ee8ap-1, -0x1.80p1
  },
  { // Entry 121
    0x1.1a22a2b284843cef729aa7923200616bp0,
    0x1.e0ee8ap-1, -0x1.8d89d8p0
  },
  { // Entry 122
    0x1.1d8befed03f9ed8d628e72acfd5846f2p0,
    0x1.e0ee8ap-1, -0x1.beb050p0
  },
  { // Entry 123
    0x1.e9e518fb1617eceb976b420930a3ce51p-1,
    0x1.e0ee8ap-1, 0x1.68f880p-1
  },
  { // Entry 124
    0x1.a0bdbae7d1b95d1adb05939aefcd35f2p-93,
    0x1.e13d0ep-1, 0x1.0220p10
  },
  { // Entry 125
    0x1.8789269c3d7361f6464f369baecd358fp-90,
    0x1.e1f07ep-1, 0x1.p10
  },
  { // Entry 126
    0x1.f67dcb0d034ec28a4309c4415565f9ecp1,
    0x1.e4000ep5, 0x1.55555ap-2
  },
  { // Entry 127
    0x1.e65785986fb7af1219234980dca4ef34p-93,
    0x1.e6f314p-1, 0x1.3e0f80p10
  },
  { // Entry 128
    0x1.e9a57691f06acbd3893901e376830537p-125,
    0x1.e97470p-1, 0x1.dd67c0p10
  },
  { // Entry 129
    0x1.866ec900017d689ca5deb18c4769effbp-2,
    0x1.f040c8p-1, 0x1.eddbacp4
  },
  { // Entry 130
    0x1.f839d5101bcf305e04c187afb53a6c53p-1,
    0x1.f091e2p-1, 0x1.p-1
  },
  { // Entry 131
    0x1.a374c2b00b62172cd4678df5e503b6f1p-13,
    0x1.f60c04p-14, 0x1.e2e42ep-1
  },
  { // Entry 132
    0x1.f8479b115561f17028b236fb8f2c173fp-1,
    0x1.ff174ap-1, 0x1.119996p3
  },
  { // Entry 133
    0x1.f947cf0debb3f5149df66e08396f65c5p3,
    0x1.ff1ffep3, 0x1.fddffep-1
  },
  { // Entry 134
    0x1.f3ae6b36c3163cd2d42f1eddf4e95886p-1,
    0x1.ff7ffep0, -0x1.203c88p-5
  },
  { // Entry 135
    0x1.f842b5127e562bf4cc2fb2aa30312393p-1,
    0x1.ffbffep-10, 0x1.3ffffep-9
  },
  { // Entry 136
    0x1.fc042cfcabd3d00c3fd7e9d168a20182p-1,
    0x1.ffc0p-1, 0x1.ffc7fep3
  },
  { // Entry 137
    0x1.f836cd12927fe3ea2eb9810462c208dcp-1,
    0x1.fff77ep100, -0x1.cb0968p-13
  },
  { // Entry 138
    0x1.fff3fd0c0608c60d8c3c9f07648607d5p14,
    0x1.fff7fep9, 0x1.80p0
  },
  { // Entry 139
    0x1.f811d3140d17296dc633cd00bfd96387p-1,
    0x1.fff8p-1, 0x1.ff80p7
  },
  { // Entry 140
    0x1.fe9d9738d0ca9f11f97a71b1a366145ap-1,
    0x1.fffefep1, -0x1.fffff8p-10
  },
  { // Entry 141
    0x1.f202b300003069a7a886e44fbf6073c2p72,
    0x1.ffff3ep127, 0x1.23d714p-1
  },
  { // Entry 142
    0x1.b834a192875d72ac81b7915cf8979690p-96,
    0x1.ffffbep-1, 0x1.p25
  },
  { // Entry 143
    0x1.ffffed000029bffddef5495e5603ce3bp-1,
    0x1.ffffe2p-1, 0x1.44443ep-1
  },
  { // Entry 144
    0x1.d6ab5d0e7ae03433ad824616d0db8b03p15,
    0x1.ffffeep-40, -0x1.a0ea0cp-2
  },
  { // Entry 145
    0x1.000002fffffffffff27fffe4ffffebc0p0,
    0x1.fffffap-1, -0x1.fffffap-1
  },
  { // Entry 146
    0x1.00000000000400000400000d55556d55p0,
    0x1.fffffcp-1, -0x1.p-23
  },
  { // Entry 147
    0x1.00000000000380000380000acaaabdeap0,
    0x1.fffffcp-1, -0x1.c0p-24
  },
  { // Entry 148
    0x1.ee8fc930954d29b3e28c5c1eafb9f7fdp4,
    0x1.fffffcp-67, -0x1.33334ep-4
  },
  { // Entry 149
    0x1.6a0a0cfff3ffa00e753af84c0100fbf0p13,
    0x1.fffffcp-106, -0x1.075078p-3
  },
  { // Entry 150
    0x1.9aaabcfff2ae3e7c84e87085640355e4p48,
    0x1.fffffcp-120, -0x1.a2e8bep-2
  },
  { // Entry 151
    0x1.f5777afffe2b46a4da98759043de4862p-52,
    0x1.fffffcp80, -0x1.428f58p-1
  },
  { // Entry 152
    0x1.73d3321e7f247def1ed4c816c824c77dp-67,
    0x1.fffffcp119, -0x1.1b91b4p-1
  },
  { // Entry 153
    0x1.000001000001000001000001000001p10,
    0x1.fffffep-11, -0x1.p0
  },
  { // Entry 154
    0x1.fffffeffffffbfffffdfffffebfffff1p0,
    0x1.fffffep1, 0x1.p-1
  },
  { // Entry 155
    0x1.cb5a0d0002f5169a13de39863bb5f91dp-2,
    0x1.421efap-2, 0x1.62e42ep-1
  },
  { // Entry 156
    0x1.cb720dcef90691503cbd1e949db761d9p-1,
    0x1.p-5, 0x1.p-5
  },
  { // Entry 157
    0x1.p-5,
    0x1.p-5, 0x1.p0
  },
  { // Entry 158
    0x1.p0,
    0x1.p0, 0x1.p-5
  },
  { // Entry 159
    0x1.p0,
    0x1.p0, 0x1.p0
  },
  { // Entry 160
    0x1.p-40,
    0x1.p-5, 0x1.p3
  },
  { // Entry 161
    0.0f,
    0x1.p-5, 0x1.p5
  },
  { // Entry 162
    0x1.p0,
    0x1.p0, 0x1.p3
  },
  { // Entry 163
    0x1.p0,
    0x1.p0, 0x1.p5
  },
  { // Entry 164
    0.0f,
    0x1.p-5, 0x1.p10
  },
  { // Entry 165
    0.0f,
    0x1.p-5, 0x1.p12
  },
  { // Entry 166
    0x1.p0,
    0x1.p0, 0x1.p10
  },
  { // Entry 167
    0x1.p0,
    0x1.p0, 0x1.p12
  },
  { // Entry 168
    0x1.11301d0125b50a4ebbf1aed9318ceac5p0,
    0x1.p3, 0x1.p-5
  },
  { // Entry 169
    0x1.p3,
    0x1.p3, 0x1.p0
  },
  { // Entry 170
    0x1.1d4873168b9aa7805b8028990f07a98bp0,
    0x1.p5, 0x1.p-5
  },
  { // Entry 171
    0x1.p5,
    0x1.p5, 0x1.p0
  },
  { // Entry 172
    0x1.p24,
    0x1.p3, 0x1.p3
  },
  { // Entry 173
    0x1.p96,
    0x1.p3, 0x1.p5
  },
  { // Entry 174
    0x1.p40,
    0x1.p5, 0x1.p3
  },
  { // Entry 175
    HUGE_VALF,
    0x1.p5, 0x1.p5
  },
  { // Entry 176
    HUGE_VALF,
    0x1.p3, 0x1.p10
  },
  { // Entry 177
    HUGE_VALF,
    0x1.p3, 0x1.p12
  },
  { // Entry 178
    HUGE_VALF,
    0x1.p5, 0x1.p10
  },
  { // Entry 179
    HUGE_VALF,
    0x1.p5, 0x1.p12
  },
  { // Entry 180
    0x1.3dea64c12342235b41223e13d773fba2p0,
    0x1.p10, 0x1.p-5
  },
  { // Entry 181
    0x1.p10,
    0x1.p10, 0x1.p0
  },
  { // Entry 182
    0x1.4bfdad5362a271d4397afec42e20e036p0,
    0x1.p12, 0x1.p-5
  },
  { // Entry 183
    0x1.p12,
    0x1.p12, 0x1.p0
  },
  { // Entry 184
    0x1.p80,
    0x1.p10, 0x1.p3
  },
  { // Entry 185
    HUGE_VALF,
    0x1.p10, 0x1.p5
  },
  { // Entry 186
    0x1.p96,
    0x1.p12, 0x1.p3
  },
  { // Entry 187
    HUGE_VALF,
    0x1.p12, 0x1.p5
  },
  { // Entry 188
    0x1.00000126055cfd443c5376930d169f32p2,
    0x1.6a09e6p-1, -0x1.p2
  },
  { // Entry 189
    0x1.fffffdb3f548a8d827b65c88p-3,
    0x1.6a09e6p-1, 0x1.p2
  },
  { // Entry 190
    0x1.00000126055cfd443c5376930d169f32p-2,
    0x1.6a09e6p0, -0x1.p2
  },
  { // Entry 191
    0x1.fffffdb3f548a8d827b65c88p1,
    0x1.6a09e6p0, 0x1.p2
  },
  { // Entry 192
    0x1.00000126055cfd443c5376930d169f32p2,
    0x1.6a09e6p-1, -0x1.p2
  },
  { // Entry 193
    0x1.fffffdb3f548a8d827b65c88p-3,
    0x1.6a09e6p-1, 0x1.p2
  },
  { // Entry 194
    0x1.00000126055cfd443c5376930d169f32p-2,
    0x1.6a09e6p0, -0x1.p2
  },
  { // Entry 195
    0x1.fffffdb3f548a8d827b65c88p1,
    0x1.6a09e6p0, 0x1.p2
  },
  { // Entry 196
    0x1.00162f3916670d119697154ae3512c2dp0,
    0x1.6a09e6p-1, -0x1.p-10
  },
  { // Entry 197
    0x1.ffd3a565caf8d230dae1250693a55f23p-1,
    0x1.6a09e6p-1, 0x1.p-10
  },
  { // Entry 198
    0x1.ffd3a5661473cb269f894b40d6cf9bacp-1,
    0x1.6a09e6p0, -0x1.p-10
  },
  { // Entry 199
    0x1.00162f38f1a33230bc340bd3752fc094p0,
    0x1.6a09e6p0, 0x1.p-10
  },
  { // Entry 200
    0x1.948b0fcd6e9e06522c3f35ba781948b0p1,
    0x1.80p-1, -0x1.p2
  },
  { // Entry 201
    0x1.44p-2,
    0x1.80p-1, 0x1.p2
  },
  { // Entry 202
    0x1.948b0fcd6e9e06522c3f35ba781948b0p-3,
    0x1.80p0, -0x1.p2
  },
  { // Entry 203
    0x1.44p2,
    0x1.80p0, 0x1.p2
  },
  { // Entry 204
    0x1.279a74590331c4d218f81e4afb257d06p0,
    0x1.80p-1, -0x1.p-1
  },
  { // Entry 205
    0x1.bb67ae8584caa73b25742d7078b83b89p-1,
    0x1.80p-1, 0x1.p-1
  },
  { // Entry 206
    0x1.a20bd700c2c3dfc042cc1aed7871db45p-1,
    0x1.80p0, -0x1.p-1
  },
  { // Entry 207
    0x1.3988e1409212e7d0321914321a556473p0,
    0x1.80p0, 0x1.p-1
  },
  { // Entry 208
    0x1.00126a0b93db294cabe33da735437f51p0,
    0x1.80p-1, -0x1.p-10
  },
  { // Entry 209
    0x1.ffdb2e8ed2a1fe71bd59fdd610313046p-1,
    0x1.80p-1, 0x1.p-10
  },
  { // Entry 210
    0x1.ffcc1c5973b2129a5b1424e0c88786b8p-1,
    0x1.80p0, -0x1.p-10
  },
  { // Entry 211
    0x1.0019f474aa190038c6af775d92f1d725p0,
    0x1.80p0, 0x1.p-10
  },
  { // Entry 212
    0x1.p0,
    0x1.p0, -0x1.p2
  },
  { // Entry 213
    0x1.p0,
    0x1.p0, 0x1.p2
  },
  { // Entry 214
    0x1.p-4,
    0x1.p1, -0x1.p2
  },
  { // Entry 215
    0x1.p4,
    0x1.p1, 0x1.p2
  },
  { // Entry 216
    0x1.p0,
    0x1.p0, -0x1.p-1
  },
  { // Entry 217
    0x1.p0,
    0x1.p0, 0x1.p-1
  },
  { // Entry 218
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1,
    0x1.p1, -0x1.p-1
  },
  { // Entry 219
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.p1, 0x1.p-1
  },
  { // Entry 220
    0x1.p0,
    0x1.p0, -0x1.p-10
  },
  { // Entry 221
    0x1.p0,
    0x1.p0, 0x1.p-10
  },
  { // Entry 222
    0x1.ffa74ea381efc217a773f15c025f7c0dp-1,
    0x1.p1, -0x1.p-10
  },
  { // Entry 223
    0x1.002c605e2e8cec506d21bfc89a23a010p0,
    0x1.p1, 0x1.p-10
  },
  { // Entry 224
    0x1.p40,
    0x1.p-10, -0x1.p2
  },
  { // Entry 225
    0x1.p-40,
    0x1.p-10, 0x1.p2
  },
  { // Entry 226
    0x1.fe013f6045e40a7c41499223b4a38ce8p-1,
    0x1.0040p0, -0x1.p2
  },
  { // Entry 227
    0x1.0100601001p0,
    0x1.0040p0, 0x1.p2
  },
  { // Entry 228
    0x1.p5,
    0x1.p-10, -0x1.p-1
  },
  { // Entry 229
    0x1.p-5,
    0x1.p-10, 0x1.p-1
  },
  { // Entry 230
    0x1.ffc00bfd808be0873653647448220fdfp-1,
    0x1.0040p0, -0x1.p-1
  },
  { // Entry 231
    0x1.001ffe003ff601bfac107ca6b29a0c31p0,
    0x1.0040p0, 0x1.p-1
  },
  { // Entry 232
    0x1.01bd1e77170b415e7626621eb5aaff61p0,
    0x1.p-10, -0x1.p-10
  },
  { // Entry 233
    0x1.fc8bc4866e8ad2b963e1828b0761cbc6p-1,
    0x1.p-10, 0x1.p-10
  },
  { // Entry 234
    0x1.ffffe0040055355844443df8680a8e05p-1,
    0x1.0040p0, -0x1.p-10
  },
  { // Entry 235
    0x1.00000ffe00d5256285340e4f3ad36287p0,
    0x1.0040p0, 0x1.p-10
  },
  { // Entry 236
    0x1.000001000001000001000001000001p-128,
    0x1.fffffep127, -0x1.p0
  },
  { // Entry 237
    0x1.fffffep127,
    0x1.fffffep127, 0x1.p0
  },
  { // Entry 238
    HUGE_VALF,
    0x1.p-149, -0x1.e66666p-1
  },
  { // Entry 239
    0x1.5db4ecab3e1cb942fc90a003e77da282p-142,
    0x1.p-149, 0x1.e66666p-1
  },
  { // Entry 240
    0.0f,
    0x1.fffffep-7, 0x1.fffffep5
  },
  { // Entry 241
    0.0f,
    0x1.fffffep-7, 0x1.p6
  },
  { // Entry 242
    0.0f,
    0x1.fffffep-7, 0x1.000002p6
  },
  { // Entry 243
    0.0f,
    0x1.p-6, 0x1.fffffep5
  },
  { // Entry 244
    0.0f,
    0x1.p-6, 0x1.p6
  },
  { // Entry 245
    0.0f,
    0x1.p-6, 0x1.000002p6
  },
  { // Entry 246
    0.0f,
    0x1.000002p-6, 0x1.fffffep5
  },
  { // Entry 247
    0.0f,
    0x1.000002p-6, 0x1.p6
  },
  { // Entry 248
    0.0f,
    0x1.000002p-6, 0x1.000002p6
  },
  { // Entry 249
    0.0f,
    0x1.fffffep-6, 0x1.fffffep4
  },
  { // Entry 250
    0.0f,
    0x1.fffffep-6, 0x1.p5
  },
  { // Entry 251
    0.0f,
    0x1.fffffep-6, 0x1.000002p5
  },
  { // Entry 252
    0.0f,
    0x1.p-5, 0x1.fffffep4
  },
  { // Entry 253
    0.0f,
    0x1.p-5, 0x1.p5
  },
  { // Entry 254
    0.0f,
    0x1.p-5, 0x1.000002p5
  },
  { // Entry 255
    0.0f,
    0x1.000002p-5, 0x1.fffffep4
  },
  { // Entry 256
    0.0f,
    0x1.000002p-5, 0x1.p5
  },
  { // Entry 257
    0.0f,
    0x1.000002p-5, 0x1.000002p5
  },
  { // Entry 258
    0x1.00001c5c879823e3af39baa221df84b0p-64,
    0x1.fffffep-5, 0x1.fffffep3
  },
  { // Entry 259
    0x1.ffffe00000effffba0000e37ffdde0p-65,
    0x1.fffffep-5, 0x1.p4
  },
  { // Entry 260
    0x1.ffff2e8e128f07f8aa95fb8b35d72ea4p-65,
    0x1.fffffep-5, 0x1.000002p4
  },
  { // Entry 261
    0x1.00002c5c89d5ec6ca4d7c8acc017b7c9p-64,
    0x1.p-4, 0x1.fffffep3
  },
  { // Entry 262
    0x1.p-64,
    0x1.p-4, 0x1.p4
  },
  { // Entry 263
    0x1.ffff4e8e06c7e8a2a84daed8ec56d6c3p-65,
    0x1.p-4, 0x1.000002p4
  },
  { // Entry 264
    0x1.00004c5c91217e02a4592ba7ad5df32ep-64,
    0x1.000002p-4, 0x1.fffffep3
  },
  { // Entry 265
    0x1.0000200001e00011800071c002220007p-64,
    0x1.000002p-4, 0x1.p4
  },
  { // Entry 266
    0x1.ffff8e8df4d9a8351320c05d3d814f9fp-65,
    0x1.000002p-4, 0x1.000002p4
  },
  { // Entry 267
    0x1.000008a2b26884f1068b81889467d67fp-24,
    0x1.fffffep-4, 0x1.fffffep2
  },
  { // Entry 268
    0x1.fffff0000037ffff9000008bffff90p-25,
    0x1.fffffep-4, 0x1.p3
  },
  { // Entry 269
    0x1.ffffad753d825dfcdd65e4ea54ccceb5p-25,
    0x1.fffffep-4, 0x1.000002p3
  },
  { // Entry 270
    0x1.000010a2b2c99a85707e8f13dc648710p-24,
    0x1.p-3, 0x1.fffffep2
  },
  { // Entry 271
    0x1.p-24,
    0x1.p-3, 0x1.p3
  },
  { // Entry 272
    0x1.ffffbd753b5607da2c260064823b30a7p-25,
    0x1.p-3, 0x1.000002p3
  },
  { // Entry 273
    0x1.000020a2b433c5b91729fe0493321d3fp-24,
    0x1.000002p-3, 0x1.fffffep2
  },
  { // Entry 274
    0x1.0000100000700001c00004600007p-24,
    0x1.000002p-3, 0x1.p3
  },
  { // Entry 275
    0x1.ffffdd75384d5b715e9437699534883bp-25,
    0x1.000002p-3, 0x1.000002p3
  },
  { // Entry 276
    0x1.0000018b90c2f02a80f3bb82aa12e95dp-8,
    0x1.fffffep-3, 0x1.fffffep1
  },
  { // Entry 277
    0x1.fffff800000bfffff8000002p-9,
    0x1.fffffep-3, 0x1.p2
  },
  { // Entry 278
    0x1.ffffe1d1bdd0bdc6b46ea64a42b1bad2p-9,
    0x1.fffffep-3, 0x1.000002p2
  },
  { // Entry 279
    0x1.0000058b90cf1e6d97f9ca14dbcc1628p-8,
    0x1.p-2, 0x1.fffffep1
  },
  { // Entry 280
    0x1.p-8,
    0x1.p-2, 0x1.p2
  },
  { // Entry 281
    0x1.ffffe9d1bd7c04bc4825147a8c0e63e3p-9,
    0x1.p-2, 0x1.000002p2
  },
  { // Entry 282
    0x1.00000d8b910b7af451a642e6d0b66b06p-8,
    0x1.000002p-2, 0x1.fffffep1
  },
  { // Entry 283
    0x1.000008000018000020000010p-8,
    0x1.000002p-2, 0x1.p2
  },
  { // Entry 284
    0x1.fffff9d1bd1a92a5d11088ed17417f41p-9,
    0x1.000002p-2, 0x1.000002p2
  },
  { // Entry 285
    0x1.fffffec5c8623fb25d7d06ac61a3063fp-3,
    0x1.fffffep-2, 0x1.fffffep0
  },
  { // Entry 286
    0x1.fffffc000002p-3,
    0x1.fffffep-2, 0x1.p1
  },
  { // Entry 287
    0x1.fffff6746f4d088289b880fe02adbfdep-3,
    0x1.fffffep-2, 0x1.000002p1
  },
  { // Entry 288
    0x1.00000162e430e5a18f6119e3c02282a5p-2,
    0x1.p-1, 0x1.fffffep0
  },
  { // Entry 289
    0x1.p-2,
    0x1.p-1, 0x1.p1
  },
  { // Entry 290
    0x1.fffffa746f47f160fcf890e3b801aeddp-3,
    0x1.p-1, 0x1.000002p1
  },
  { // Entry 291
    0x1.00000562e436713246f7a0134c8287eap-2,
    0x1.000002p-1, 0x1.fffffep0
  },
  { // Entry 292
    0x1.000004000004p-2,
    0x1.000002p-1, 0x1.p1
  },
  { // Entry 293
    0x1.0000013a37a4e18f0519a603954a5b0bp-2,
    0x1.000002p-1, 0x1.000002p1
  },
  { // Entry 294
    0x1.fffffe000001ffffff000000aaaaaa80p-1,
    0x1.fffffep-1, 0x1.fffffep-1
  },
  { // Entry 295
    0x1.fffffep-1,
    0x1.fffffep-1, 0x1.p0
  },
  { // Entry 296
    0x1.fffffdfffffc000002000004aaaaaaffp-1,
    0x1.fffffep-1, 0x1.000002p0
  },
  { // Entry 297
    0x1.p0,
    0x1.p0, 0x1.fffffep-1
  },
  { // Entry 298
    0x1.p0,
    0x1.p0, 0x1.p0
  },
  { // Entry 299
    0x1.p0,
    0x1.p0, 0x1.000002p0
  },
  { // Entry 300
    0x1.000001fffffdfffffe000003555553ffp0,
    0x1.000002p0, 0x1.fffffep-1
  },
  { // Entry 301
    0x1.000002p0,
    0x1.000002p0, 0x1.p0
  },
  { // Entry 302
    0x1.000002000004000004000005555558p0,
    0x1.000002p0, 0x1.000002p0
  },
  { // Entry 303
    0x1.6a09e53575b123625cc1968a665581a4p0,
    0x1.fffffep0, 0x1.fffffep-2
  },
  { // Entry 304
    0x1.6a09e5b2eec967cd97b2eff75f471493p0,
    0x1.fffffep0, 0x1.p-1
  },
  { // Entry 305
    0x1.6a09e6ade0fa7319052c4948dea48a76p0,
    0x1.fffffep0, 0x1.000002p-1
  },
  { // Entry 306
    0x1.6a09e5ea7aa390dbf868b7278b744829p0,
    0x1.p1, 0x1.fffffep-2
  },
  { // Entry 307
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.p1, 0x1.p-1
  },
  { // Entry 308
    0x1.6a09e762e5efbbd7217018250a3ab194p0,
    0x1.p1, 0x1.000002p-1
  },
  { // Entry 309
    0x1.6a09e75484875c47c3cee01d9f348bd8p0,
    0x1.000002p1, 0x1.fffffep-2
  },
  { // Entry 310
    0x1.6a09e7d1fda27bf77d45272dd2d83a4bp0,
    0x1.000002p1, 0x1.p-1
  },
  { // Entry 311
    0x1.6a09e8ccefd93dcbecf54d233ea8265bp0,
    0x1.000002p1, 0x1.000002p-1
  },
  { // Entry 312
    0x1.6a09e58ff82a4ecedb73f766d3d0758dp0,
    0x1.fffffep1, 0x1.fffffep-3
  },
  { // Entry 313
    0x1.6a09e60d71430d1ad61b45d5d1abdf15p0,
    0x1.fffffep1, 0x1.p-2
  },
  { // Entry 314
    0x1.6a09e70863750c27c3dd5c0ecdce5271p0,
    0x1.fffffep1, 0x1.000002p-2
  },
  { // Entry 315
    0x1.6a09e5ea7aa390dbf868b7278b744829p0,
    0x1.p2, 0x1.fffffep-3
  },
  { // Entry 316
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.p2, 0x1.p-2
  },
  { // Entry 317
    0x1.6a09e762e5efbbd7217018250a3ab194p0,
    0x1.p2, 0x1.000002p-2
  },
  { // Entry 318
    0x1.6a09e69f7f954950a1fce0a1b2c362d0p0,
    0x1.000002p2, 0x1.fffffep-3
  },
  { // Entry 319
    0x1.6a09e71cf8af753edb9700ad906c9cd9p0,
    0x1.000002p2, 0x1.p-2
  },
  { // Entry 320
    0x1.6a09e817eae44f9049d532cda2a90cb6p0,
    0x1.000002p2, 0x1.000002p-2
  },
  { // Entry 321
    0x1.4bfdacd3978adf9f3b64fe01f40593aep0,
    0x1.fffffep2, 0x1.fffffep-4
  },
  { // Entry 322
    0x1.4bfdad29e2ecb54005a6dbec67c5e413p0,
    0x1.fffffep2, 0x1.p-3
  },
  { // Entry 323
    0x1.4bfdadd679b0a3cc40ecb60afdc4a552p0,
    0x1.fffffep2, 0x1.000002p-3
  },
  { // Entry 324
    0x1.4bfdacfd174067ea4d43f8b09f974d86p0,
    0x1.p3, 0x1.fffffep-4
  },
  { // Entry 325
    0x1.4bfdad5362a271d4397afec42e20e036p0,
    0x1.p3, 0x1.p-3
  },
  { // Entry 326
    0x1.4bfdadfff966c8f2b8f44b137fbfaa96p0,
    0x1.p3, 0x1.000002p-3
  },
  { // Entry 327
    0x1.4bfdad5016ab0b9134e0574abca78b7ap0,
    0x1.000002p3, 0x1.fffffep-4
  },
  { // Entry 328
    0x1.4bfdada6620d7e0d6487fd9be64887a3p0,
    0x1.000002p3, 0x1.p-3
  },
  { // Entry 329
    0x1.4bfdae52f8d2a6506b74ce232fdcd291p0,
    0x1.000002p3, 0x1.000002p-3
  },
  { // Entry 330
    0x1.306fe05b533131c27612cfff7a0ffdb0p0,
    0x1.fffffep3, 0x1.fffffep-5
  },
  { // Entry 331
    0x1.306fe09014733fc18f2a8e5bc8a30cdcp0,
    0x1.fffffep3, 0x1.p-4
  },
  { // Entry 332
    0x1.306fe0f996f7772c9a94c16083446262p0,
    0x1.fffffep3, 0x1.000002p-4
  },
  { // Entry 333
    0x1.306fe06e5a2f2e8c620f7e55cc803dbap0,
    0x1.p4, 0x1.fffffep-5
  },
  { // Entry 334
    0x1.306fe0a31b7152de8d5a46305c85edecp0,
    0x1.p4, 0x1.p-4
  },
  { // Entry 335
    0x1.306fe10c9df5b6efbd400b7806005fa9p0,
    0x1.p4, 0x1.000002p-4
  },
  { // Entry 336
    0x1.306fe094682af29c8fe9f735fb1c4081p0,
    0x1.000002p4, 0x1.fffffep-5
  },
  { // Entry 337
    0x1.306fe0c9296d4394df5f99b9bd1a47d2p0,
    0x1.000002p4, 0x1.p-4
  },
  { // Entry 338
    0x1.306fe132abf200f257c612e07f149aa3p0,
    0x1.000002p4, 0x1.000002p-4
  },
  { // Entry 339
    0x1.1d4872eebb9da03bbac5af79b0cf9409p0,
    0x1.fffffep4, 0x1.fffffep-6
  },
  { // Entry 340
    0x1.1d48730da1570a7a85ea1fc1fcf88fddp0,
    0x1.fffffep4, 0x1.p-5
  },
  { // Entry 341
    0x1.1d48734b6cc9e902148fafcefa9eaa06p0,
    0x1.fffffep4, 0x1.000002p-5
  },
  { // Entry 342
    0x1.1d4872f7a5e133601ef3b495f3f89a12p0,
    0x1.p5, 0x1.fffffep-6
  },
  { // Entry 343
    0x1.1d4873168b9aa7805b8028990f07a98bp0,
    0x1.p5, 0x1.p-5
  },
  { // Entry 344
    0x1.1d487354570d99caccfbdb7e35ff0df1p0,
    0x1.p5, 0x1.000002p-5
  },
  { // Entry 345
    0x1.1d4873097a683fc01308d4a71615b820p0,
    0x1.000002p5, 0x1.fffffep-6
  },
  { // Entry 346
    0x1.1d4873286021c7a332496ee4ad91ade9p0,
    0x1.000002p5, 0x1.p-5
  },
  { // Entry 347
    0x1.1d4873662b94e1736939a503d83c5e42p0,
    0x1.000002p5, 0x1.000002p-5
  },
  { // Entry 348
    0x1.11301ceb20541ff3f655e3bd12271b3ep0,
    0x1.fffffep5, 0x1.fffffep-7
  },
  { // Entry 349
    0x1.11301cfce0f494304e630799fc8b181fp0,
    0x1.fffffep5, 0x1.p-6
  },
  { // Entry 350
    0x1.11301d206235801ef5580894354f900cp0,
    0x1.fffffep5, 0x1.000002p-6
  },
  { // Entry 351
    0x1.11301cef65149186a0ecb60713565b45p0,
    0x1.p6, 0x1.fffffep-7
  },
  { // Entry 352
    0x1.11301d0125b50a4ebbf1aed9318ceac5p0,
    0x1.p6, 0x1.p-6
  },
  { // Entry 353
    0x1.11301d24a6f5ff54e8d811a4b978b54fp0,
    0x1.p6, 0x1.000002p-6
  },
  { // Entry 354
    0x1.11301cf7ee956810edd94d1c7697f34bp0,
    0x1.000002p6, 0x1.fffffep-7
  },
  { // Entry 355
    0x1.11301d09af35e9f08ec0b6564cfd4d3ap0,
    0x1.000002p6, 0x1.p-6
  },
  { // Entry 356
    0x1.11301d2d3076f125c76f69bf107f4052p0,
    0x1.000002p6, 0x1.000002p-6
  },
  { // Entry 357
    0x1.fffc9d1eaff1e2bc708fbb9fc141d186p127,
    0x1.fffffcp0, 0x1.fffffcp6
  },
  { // Entry 358
    0x1.fffd4e8fb83933cbf5f827e2581f20dcp127,
    0x1.fffffcp0, 0x1.fffffep6
  },
  { // Entry 359
    0x1.fffe0000fdffaca81458f80ec301a2c8p127,
    0x1.fffffcp0, 0x1.p7
  },
  { // Entry 360
    0x1.ffff62e4420a6b06d702f4e2aaffa4e5p127,
    0x1.fffffcp0, 0x1.000002p7
  },
  { // Entry 361
    HUGE_VALF,
    0x1.fffffcp0, 0x1.000004p7
  },
  { // Entry 362
    0x1.fffd9d1d3e00d99bdfe3619f05f2ecc1p127,
    0x1.fffffep0, 0x1.fffffcp6
  },
  { // Entry 363
    0x1.fffe4e8ea000c3f99d84d886c03811fap127,
    0x1.fffffep0, 0x1.fffffep6
  },
  { // Entry 364
    0x1.ffff00003f7ff59501458fa07615868bp127,
    0x1.fffffep0, 0x1.p7
  },
  { // Entry 365
    HUGE_VALF,
    0x1.fffffep0, 0x1.000002p7
  },
  { // Entry 366
    HUGE_VALF,
    0x1.fffffep0, 0x1.000004p7
  },
  { // Entry 367
    0x1.fffe9d1c4b0f37f413d44c66c0481834p127,
    0x1.p1, 0x1.fffffcp6
  },
  { // Entry 368
    0x1.ffff4e8e06c7e8a2a84daed8ec56d6c3p127,
    0x1.p1, 0x1.fffffep6
  },
  { // Entry 369
    HUGE_VALF,
    0x1.p1, 0x1.p7
  },
  { // Entry 370
    HUGE_VALF,
    0x1.p1, 0x1.000002p7
  },
  { // Entry 371
    HUGE_VALF,
    0x1.p1, 0x1.000004p7
  },
  { // Entry 372
    HUGE_VALF,
    0x1.000002p1, 0x1.fffffcp6
  },
  { // Entry 373
    HUGE_VALF,
    0x1.000002p1, 0x1.fffffep6
  },
  { // Entry 374
    HUGE_VALF,
    0x1.000002p1, 0x1.p7
  },
  { // Entry 375
    HUGE_VALF,
    0x1.000
"""


```
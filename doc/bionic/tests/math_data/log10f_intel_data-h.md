Response:
Let's break down the thought process for analyzing this C code snippet and generating the comprehensive response.

**1. Understanding the Core Task:**

The first step is to recognize the context: a data file for testing the `log10f` function in Android's `bionic` library. The request asks for the file's function, relationship to Android, implementation details (though it's *data*, not code), dynamic linker aspects, examples, usage errors, and how Android frameworks reach this point.

**2. Initial Analysis of the Code:**

* **Data Structure:**  The code defines a static array `g_log10f_intel_data` of type `data_1_1_t<float, float>`. This immediately suggests that it's a collection of input-output pairs for testing.
* **Data Type:** `float` indicates single-precision floating-point numbers.
* **Values:** The data entries contain pairs of hexadecimal floating-point numbers. The comments "// Entry N" help identify each entry.
* **Copyright and License:** Standard Apache 2.0 license header, indicating open-source nature.

**3. Deconstructing the Request - Identifying Key Areas:**

The request has several distinct parts, each requiring a specific approach:

* **Functionality:** What is this *data* used for? (Testing `log10f`)
* **Android Relationship:** How does this data fit into Android's ecosystem? (Testing the C library's math function)
* **`libc` Function Implementation:**  This is a bit of a misdirection. The file *doesn't* implement `log10f`. It *tests* it. The answer needs to clarify this and explain the general purpose of `log10f`.
* **Dynamic Linker:** Does this data file directly involve the dynamic linker?  No, but the *`log10f` function itself* does when it's part of a shared library. The answer should discuss this indirect connection.
* **Logic/Inference:** Are there patterns in the data? Can we infer anything?  Yes, the pairs are likely input values and their expected `log10f` outputs.
* **Usage Errors:** Can this *data* itself be misused? Not really. The errors would occur when *using* the `log10f` function or when the test setup is incorrect.
* **Android Framework/NDK:** How does code in higher layers eventually trigger the use of `log10f` (and thus potentially this test data)? This involves tracing the call stack.
* **Frida Hook:** How can we observe this in action using Frida? Provide examples of hooking the `log10f` function.

**4. Addressing Each Area Systematically:**

* **Functionality:**  Easy. The data is for testing the `log10f` function. Specifically, it seems to be for testing against results from Intel's implementation, suggesting cross-platform consistency checks.
* **Android Relationship:** `log10f` is a standard math function provided by `libc` (bionic in Android). It's fundamental to many Android components. Examples: calculator apps, graphics rendering, scientific applications.
* **`libc` Function Implementation:**  Crucially, emphasize that this file is *data*, not the implementation. Explain the *purpose* of `log10f` (calculating base-10 logarithms). Briefly mention common implementation techniques (Taylor series, lookup tables, etc.).
* **Dynamic Linker:**  Explain that `log10f` resides in `libc.so`. Provide a typical `libc.so` layout with relevant sections (.text, .data, .bss, etc.). Describe the linking process: finding the symbol, resolving dependencies, PLT/GOT.
* **Logic/Inference:** The assumption is that the first float in each pair is an input to `log10f`, and the second is the expected output. Illustrate with a simple example, converting the hexadecimal floats to decimal. Highlight potential edge cases like negative inputs or zero.
* **Usage Errors:** Focus on errors *when using `log10f`*, not with the data file itself. Examples: passing negative numbers (domain error), NaNs, infinities.
* **Android Framework/NDK:**  Start with high-level examples (Java code using `Math.log10`, NDK C++ code using `<cmath>`). Explain how the calls go through the Android runtime and eventually reach the native `log10f` in `libc.so`. Illustrate with a simplified call stack.
* **Frida Hook:** Provide concrete JavaScript code snippets to hook the `log10f` function, logging input arguments and return values. Explain how to use Frida to attach to an Android process and execute the script.

**5. Refining the Response:**

* **Language:** Use clear and concise Chinese.
* **Structure:** Organize the information logically, using headings and bullet points.
* **Accuracy:** Ensure technical correctness in explanations of floating-point numbers, dynamic linking, and Frida.
* **Completeness:** Address all aspects of the original request.
* **Examples:** Provide concrete examples to illustrate abstract concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this file *contains* the implementation of `log10f`. **Correction:** Closer inspection reveals it's *data* for testing.
* **Overemphasis on Data Misuse:**  Thinking about how the *data file itself* could be misused. **Correction:** The more relevant errors are those related to the *usage* of the `log10f` function.
* **Dynamic Linker Depth:**  Deciding how much detail to provide about the dynamic linker. **Correction:** Focus on the key concepts relevant to `libc.so` and symbol resolution, avoiding overly technical details about relocation types, etc.
* **Frida Hook Specificity:** Initial thoughts on general Frida usage. **Correction:** Provide concrete, copy-pastable code examples for hooking `log10f`.

By following this structured approach and continually refining the understanding and the response, we arrive at a comprehensive and accurate answer.
这个文件 `log10f_intel_data.handroid` 是 Android Bionic 库中用于测试 `log10f` 函数的数据文件。它包含了大量的浮点数输入和预期的浮点数输出，用于验证 `log10f` 函数在各种输入情况下的正确性。

**功能列举:**

1. **测试数据:** 该文件主要功能是作为 `log10f` 函数的测试数据。它提供了一系列精心挑选的浮点数输入值，以及对应的由 Intel 平台计算出的预期 `log10f` 的结果。
2. **回归测试:** 这些数据可以用于回归测试，确保对 `log10f` 函数的修改或优化不会引入新的错误，或者导致在某些输入上产生不正确的结果。
3. **跨平台验证:**  由于文件名中包含 "intel_data"，这暗示了该数据是基于 Intel 平台的 `log10f` 实现生成的。这可以用于验证 Android 的 `log10f` 实现与其他平台的兼容性或一致性。
4. **覆盖各种情况:**  数据中包含了正数、负数、接近零的数、非常大的数等各种边界情况和典型场景，以确保测试的覆盖率。

**与 Android 功能的关系及举例说明:**

`log10f` 是一个标准的 C 语言数学库函数，用于计算以 10 为底的浮点数的对数。它是 Android 系统中许多功能的基础。

* **应用程序开发:** Android 应用程序，特别是那些涉及到科学计算、图形处理、音频处理等领域的应用，可能会直接或间接地使用 `log10f` 函数。例如，一个计算器应用需要计算对数，音频处理可能需要将线性幅度转换为分贝（使用对数），图形渲染中某些光照模型也可能用到对数。
* **Android Framework:** Android Framework 的某些组件在底层也可能使用到 `log10f`。例如，某些性能分析工具或系统监控组件可能需要对数值进行对数转换后再进行分析或展示。
* **NDK 开发:** 使用 NDK 进行原生开发的开发者可以直接调用 `log10f` 函数，进行高性能的数学运算。

**举例说明:**

假设一个 Android 应用需要计算一个声音强度的分贝值。分贝的计算公式是 `10 * log10(I/I0)`，其中 `I` 是声音强度，`I0` 是参考强度。在这个过程中，就需要调用 `log10f` 函数来计算以 10 为底的对数。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件本身**不是** `libc` 函数的实现代码，而是用于测试 `libc` 中 `log10f` 函数的**数据**。  `log10f` 函数的实现通常涉及以下几种技术：

1. **范围归约 (Range Reduction):** 将任意输入值 `x` 转换到一个较小的、易于处理的范围内。这通常涉及到将 `x` 表示为 `m * 10^e` 的形式，然后对尾数 `m` 进行操作。
2. **多项式逼近或查找表:**
   * **多项式逼近:** 在归约后的范围内，使用一个精心选择的多项式来逼近 `log10(x)` 的值。这种方法需要在精度和计算复杂度之间进行权衡。
   * **查找表:**  预先计算一些关键点的 `log10` 值并存储在一个查找表中。对于给定的输入，可以通过查找表中的值进行插值来获得结果。
3. **特殊情况处理:**  需要处理一些特殊情况，如输入为 0、负数、无穷大、NaN (Not a Number) 等。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`log10f` 函数位于 `libc.so` (在 Android 上是 `/system/lib[64]/libc.so`) 中。当一个应用程序或共享库需要使用 `log10f` 时，动态链接器负责找到并加载包含该函数的共享库，并将调用地址重定向到 `libc.so` 中 `log10f` 函数的实际地址。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .dynsym:  // 动态符号表
    ...
    log10f  ADDRESS_OF_LOG10F  // 包含 log10f 的符号和地址
    ...
  .text:    // 代码段
    ...
    ADDRESS_OF_LOG10F:  // log10f 函数的实际代码
      <log10f 函数的机器码>
    ...
  .data:    // 已初始化数据段
    ...
  .bss:     // 未初始化数据段
    ...
  .plt:     // 程序链接表 (Procedure Linkage Table)
    ...
    条目指向 log10f 的 GOT 表项
    ...
  .got:     // 全局偏移量表 (Global Offset Table)
    ...
    log10f 的地址 (初始时可能是一个占位符，运行时被动态链接器填充)
    ...
```

**链接的处理过程:**

1. **编译时:** 当程序或共享库引用了 `log10f` 时，编译器会在其目标文件中生成一个对 `log10f` 的未解析引用。
2. **链接时:** 静态链接器并不解析对 `log10f` 的引用，而是将其标记为需要动态链接。并在可执行文件或共享库的 `.plt` 和 `.got` 段中生成相应的条目。
3. **加载时:** 当操作系统加载可执行文件或共享库时，动态链接器 (在 Android 上是 `linker` 或 `linker64`) 负责处理动态链接。
4. **符号查找:** 当程序首次调用 `log10f` 时，控制权会转移到 `.plt` 中的桩代码。这个桩代码会通过 `.got` 表找到动态链接器的地址。
5. **动态链接器介入:** 动态链接器会搜索已加载的共享库，查找包含 `log10f` 符号的库 (即 `libc.so`)。
6. **地址解析:** 动态链接器找到 `libc.so` 中的 `log10f` 函数的实际地址，并将该地址填充到 `.got` 表中对应 `log10f` 的条目。
7. **重定向:**  后续对 `log10f` 的调用将直接通过 `.plt` 和 `.got` 表，跳转到 `libc.so` 中 `log10f` 的实际地址执行。

**假设输入与输出 (基于数据文件):**

该数据文件已经包含了假设的输入和输出。例如：

* **假设输入:** `-0x1.fe8bfdffff13dd47512c048f491f9b43p3` (十六进制浮点数，表示一个负数)
* **预期输出:** `0x1.000022p-53` (十六进制浮点数，表示 `log10f` 的结果)

**需要注意的是，`log10f` 对于负数输入是未定义的，会产生 NaN 或引发错误。因此，数据文件中负数输入的情况可能是用于测试错误处理或特定平台行为的。**

**用户或者编程常见的使用错误:**

1. **传递负数给 `log10f`:**  根据数学定义，负数没有实数对数。在 C 语言中，`log10f` 对于负数输入通常会返回 NaN，并可能设置 `errno` 为 `EDOM` (定义域错误)。
   ```c
   #include <math.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       float x = -1.0f;
       float result = log10f(x);
       if (isnan(result)) {
           perror("log10f failed");
           if (errno == EDOM) {
               printf("Error: Domain error (negative input).\n");
           }
       } else {
           printf("log10f(%f) = %f\n", x, result);
       }
       return 0;
   }
   ```
2. **传递零给 `log10f`:** `log10(0)` 趋向于负无穷大。`log10f(0.0f)` 通常会返回负无穷大 (`-INFINITY`)，并可能设置 `errno` 为 `ERANGE` (值域错误)。
3. **溢出或下溢:**  对于非常大或非常小的正数，`log10f` 的结果可能会超出浮点数的表示范围，导致溢出（返回正无穷大）或下溢（返回接近零的值）。
4. **精度问题:** 浮点数运算本身存在精度问题。过度依赖浮点数 `log10f` 的精确比较可能会导致错误。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `log10f` 的调用路径示例:**

1. **Java 代码:**  在 Android 应用的 Java 代码中，可能会使用 `java.lang.Math.log10(double)` 方法。
   ```java
   double value = 100.0;
   double result = Math.log10(value);
   ```
2. **Android Runtime (ART):** `java.lang.Math.log10(double)` 是一个 native 方法，其实现位于 ART 虚拟机中。
3. **JNI 调用:** ART 会通过 Java Native Interface (JNI) 调用到对应的 native 实现。
4. **`libm.so` (或 `libc.so`):**  在 Android 的早期版本中，`log10` 等数学函数可能位于 `libm.so` 中。现在，它们通常直接位于 `libc.so` 中。ART 的 native 实现最终会调用到 `libc.so` 中的 `log10f` (或者 `log10`，然后内部可能调用 `log10f`)。

**NDK 到 `log10f` 的调用路径示例:**

1. **C/C++ 代码:** 使用 NDK 进行开发的 C/C++ 代码可以直接包含 `<cmath>` 或 `<math.h>` 头文件，并调用 `log10f` 函数。
   ```cpp
   #include <cmath>
   #include <cstdio>

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_myapp_MainActivity_calculateLog(JNIEnv *env, jobject /* this */, jfloat value) {
       float result = std::log10(value); // 或使用 log10f(value);
       printf("log10f(%f) = %f\n", value, result);
   }
   ```
2. **动态链接:** 当包含这段代码的 native 库被加载时，动态链接器会将对 `log10f` 的引用链接到 `libc.so` 中的实际实现。

**Frida Hook 示例:**

可以使用 Frida 来 hook `log10f` 函数，观察其输入和输出，从而调试调用路径。

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const log10f = Module.findExportByName("libc.so", "log10f");
  if (log10f) {
    Interceptor.attach(log10f, {
      onEnter: function (args) {
        const input = args[0].readFloat();
        console.log("[log10f] Input:", input);
      },
      onLeave: function (retval) {
        const output = retval.readFloat();
        console.log("[log10f] Output:", output);
      }
    });
    console.log("Attached to log10f");
  } else {
    console.log("log10f not found in libc.so");
  }
} else {
  console.log("Frida hook for log10f is only implemented for ARM architectures in this example.");
}
```

**使用步骤:**

1. **安装 Frida:** 确保你的开发机器上安装了 Frida 和 Frida-tools。
2. **找到目标进程:** 运行你的 Android 应用，并找到其进程 ID (PID)。
3. **运行 Frida 脚本:** 使用 Frida 命令将上述 JavaScript 代码注入到目标进程中。例如：
   ```bash
   frida -U -f <your_app_package_name> -l hook_log10f.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_pid> -l hook_log10f.js
   ```
4. **观察输出:** 当应用中涉及到 `log10f` 的代码被执行时，Frida 会在控制台上打印出 `log10f` 函数的输入参数和返回值。

**注意:**

* 上述 Frida 脚本假设 `log10f` 位于 `libc.so` 中。在某些旧版本的 Android 或特定的设备上，它可能位于 `libm.so` 中，需要相应地修改 `Module.findExportByName` 的参数。
* Hook 系统函数可能需要 root 权限或者在可调试的应用上进行。

总而言之，`log10f_intel_data.handroid` 是一个关键的测试数据文件，用于保证 Android 系统中 `log10f` 函数的正确性和可靠性，这对于许多依赖数学运算的 Android 功能至关重要。 通过理解其功能和与 Android 系统的联系，我们可以更好地理解 Android 底层库的质量保证过程。

### 提示词
```
这是目录为bionic/tests/math_data/log10f_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_log10f_intel_data[] = {
  { // Entry 0
    -0x1.fe8bfdffff13dd47512c048f491f9b43p3,
    0x1.000022p-53
  },
  { // Entry 1
    -0x1.815170ed4e086e755171000a21e4418ap2,
    0x1.0000a0p-20
  },
  { // Entry 2
    -0x1.fe8beafff5736c97130c9ced1f57d1a3p3,
    0x1.000180p-53
  },
  { // Entry 3
    -0x1.343e0effe0b2cf5c4261140f67bbb9dbp-2,
    0x1.0001d0p-1
  },
  { // Entry 4
    0x1.bc41b9006f9ea191f8d77992988148e8p-11,
    0x1.007ffep0
  },
  { // Entry 5
    0x1.286d48f2328d1c51bb42649f1e36f51cp-10,
    0x1.00aadcp0
  },
  { // Entry 6
    0x1.3c3724fff9a66a1fc88c62753a01a093p-10,
    0x1.00b648p0
  },
  { // Entry 7
    0x1.b41066a765c47c650e3f2b65383836c5p-10,
    0x1.00fb80p0
  },
  { // Entry 8
    0x1.b4ede8ab7383b8e1ac6403842ab125e1p-10,
    0x1.00fcp0
  },
  { // Entry 9
    0x1.b606409a66ace2644d565b3bbe495b4bp-10,
    0x1.00fca2p0
  },
  { // Entry 10
    0x1.361702fff27220603ff5a74b9a7278a1p-2,
    0x1.010fp1
  },
  { // Entry 11
    0x1.30ecd6fe9803b26443d0a8c84cf88f49p-9,
    0x1.0160p0
  },
  { // Entry 12
    0x1.ad1561043e238a54f2968308b5b84a0ap-9,
    0x1.01efdep0
  },
  { // Entry 13
    0x1.add67b049b9eccb589d59f2e94044d4cp-9,
    0x1.01f0bep0
  },
  { // Entry 14
    0x1.b4181727e525aa3c9fe9bb81a1ea32f2p-9,
    0x1.01f8p0
  },
  { // Entry 15
    0x1.ba90af0300546714c91e69807716244bp-9,
    0x1.01ff82p0
  },
  { // Entry 16
    0x1.bf75c6fdd387cfc33e178c7140ff4a43p-9,
    0x1.020530p0
  },
  { // Entry 17
    0x1.c160fcfb3f11263df6c5479a7fc1f96ep-9,
    0x1.02076ap0
  },
  { // Entry 18
    0x1.c3b396fb7cc17548094cdeed806812d7p-9,
    0x1.020a1cp0
  },
  { // Entry 19
    0x1.041e5efff8637a181cab5a487e534f1cp5,
    0x1.0220p108
  },
  { // Entry 20
    0x1.deaf41009dde64cb85f68d09d2edf173p-9,
    0x1.02296ep0
  },
  { // Entry 21
    0x1.ecf47efdaeb10f5ade28ff93f4f44527p-9,
    0x1.023ap0
  },
  { // Entry 22
    0x1.f514f89756d667a2094b9aa6f5425a94p-8,
    0x1.048cp0
  },
  { // Entry 23
    -0x1.31add3ffcf191eb75b949d0c4b25562ep0,
    0x1.06p-4
  },
  { // Entry 24
    0x1.5d5eb8fffce13ef5613f5c26350b3ef3p-7,
    0x1.065cd2p0
  },
  { // Entry 25
    0x1.b02afb003def304a513c84d809f21238p-7,
    0x1.07e4bcp0
  },
  { // Entry 26
    0x1.e8296b002bba062b42b25642380152e2p-7,
    0x1.08ef12p0
  },
  { // Entry 27
    0x1.e9c5e90021ec01c297e475abe4ba42p-7,
    0x1.08f6c0p0
  },
  { // Entry 28
    -0x1.7d2b50ffff0186373287a99f0cecd28ep0,
    0x1.09bcp-5
  },
  { // Entry 29
    0x1.3a62cbffff2834d75a70360f6b9d64cfp0,
    0x1.0e83a0p4
  },
  { // Entry 30
    -0x1.7aa2bc000221055273bfa7fee62d0379p0,
    0x1.0fdcp-5
  },
  { // Entry 31
    0x1.d5bbd4fffd35c403bb0a652e9334f1e4p0,
    0x1.1180p6
  },
  { // Entry 32
    0x1.ef425287c21feec9c54e178d894354edp-6,
    0x1.1274p0
  },
  { // Entry 33
    -0x1.29297dffff901bb8ac5190eca10186b9p0,
    0x1.1adcp-4
  },
  { // Entry 34
    0x1.817dc8fccbc0fb5087e88f554f1908fdp-5,
    0x1.1d4cp0
  },
  { // Entry 35
    0x1.96aaacfefcf3bb8dcf3d8c94eb1423cap-5,
    0x1.1fp0
  },
  { // Entry 36
    0x1.a2d9334a67417635918aaf61a00994f0p-5,
    0x1.1ffcp0
  },
  { // Entry 37
    0x1.e32d32fa5c9d38509a7ba3e2bfb93574p-5,
    0x1.253d24p0
  },
  { // Entry 38
    0x1.55811effbe311325be81852b0556032cp-1,
    0x1.294a50p2
  },
  { // Entry 39
    -0x1.d7dae0fffee85f639c44d1f94b88a9aap-3,
    0x1.2d363ap-1
  },
  { // Entry 40
    -0x1.9ba71b0001bcb89106e975a5735cc54cp1,
    0x1.3ecf84p-11
  },
  { // Entry 41
    0x1.p0,
    0x1.40p3
  },
  { // Entry 42
    0x1.879ecefffff999362de3e56a2a6ed238p2,
    0x1.412668p20
  },
  { // Entry 43
    0x1.c10343057f36be857e8738b6dfecd5dep-4,
    0x1.498152p0
  },
  { // Entry 44
    0x1.f237b389b8afaac4cac40f2695df7209p-4,
    0x1.52bf2ap0
  },
  { // Entry 45
    -0x1.e0e8f9e4b17e517c0a47404130e68838p-2,
    0x1.5b43e2p-2
  },
  { // Entry 46
    0x1.bce8b0000212bd563ade9f93343779fbp-2,
    0x1.5c17p1
  },
  { // Entry 47
    -0x1.d30fa3d9517968762410807be9c7cb7ep-2,
    0x1.663fe0p-2
  },
  { // Entry 48
    0x1.ca3f98fffffea806640e073c5b17da75p-2,
    0x1.66b06ap1
  },
  { // Entry 49
    -0x1.81bbccfffeb10074d0f87e9e6ab68f3fp-1,
    0x1.695dp-3
  },
  { // Entry 50
    -0x1.3442891155fedc1531e5c4a593f0e2f0p-3,
    0x1.6a095cp-1
  },
  { // Entry 51
    0x1.f28489002d32f29f766276e96f7f21aap4,
    0x1.6aaaaap103
  },
  { // Entry 52
    -0x1.7d9722fffffee06829536561f0f13e07p-1,
    0x1.7028e2p-3
  },
  { // Entry 53
    0x1.e39e45d51ccc5ba793598e2a5b79a0dfp-2,
    0x1.7bbf06p1
  },
  { // Entry 54
    -0x1.ffbfcbff9b381c31b8783059f0acf062p-4,
    0x1.7ffffep-1
  },
  { // Entry 55
    -0x1.ffbfc2bbc780375837c4b0b84f38a14ap-4,
    0x1.80p-1
  },
  { // Entry 56
    -0x1.b40dd238181b3a9e0aacd04028af4a80p-2,
    0x1.801e82p-2
  },
  { // Entry 57
    -0x1.f9043300033a2fda0c9e8b664d0dfae2p-4,
    0x1.8174c4p-1
  },
  { // Entry 58
    -0x1.530ccb00030817c37d1894f62c055194p0,
    0x1.8421p-5
  },
  { // Entry 59
    -0x1.e2278820b34cd516815ccd9af00ec36cp-4,
    0x1.867124p-1
  },
  { // Entry 60
    -0x1.db11ed766abf432dc3c1bb4167a6eb47p-4,
    0x1.88p-1
  },
  { // Entry 61
    0x1.eb76a4317f935066a9dd258d69495f3bp-3,
    0x1.bcd946p0
  },
  { // Entry 62
    -0x1.e5a7d2fffbde5faba9ad1dafa9f8e25ep-1,
    0x1.cd1eb6p-4
  },
  { // Entry 63
    -0x1.e3e2e8000003707015334e8f6d4e1baep-1,
    0x1.d0cdb4p-4
  },
  { // Entry 64
    -0x1.46b528fff19f0db93b31ce66c94d4faap-1,
    0x1.d739cep-3
  },
  { // Entry 65
    -0x1.ffd158bd0b2827904af6cec4c6e1bbe4p-6,
    0x1.dc7710p-1
  },
  { // Entry 66
    0x1.c00806bb584a81d2425a4c449277a3c0p-1,
    0x1.dffffep2
  },
  { // Entry 67
    -0x1.a0ed34fffc666da4d52ec02aeafec305p-6,
    0x1.e2dc9ap-1
  },
  { // Entry 68
    0x1.e61002ffffc2d1e0983851bf24c9ce23p4,
    0x1.e339a2p100
  },
  { // Entry 69
    -0x1.3a6ae8fffd0faf4aca1345a2b412cb11p-6,
    0x1.e9de50p-1
  },
  { // Entry 70
    -0x1.9775a6e35532e99d0cf2384ab86d5473p-7,
    0x1.f18c60p-1
  },
  { // Entry 71
    -0x1.81f977002634432665d65d78d2968a65p2,
    0x1.f40e5ep-21
  },
  { // Entry 72
    -0x1.f62251ffffff968db3edbd69bcf5cfdcp1,
    0x1.f4e26ap-14
  },
  { // Entry 73
    -0x1.14f03effe1727a0c4e49b2a6bad88689p-7,
    0x1.f621f6p-1
  },
  { // Entry 74
    -0x1.f7c3f8ffbdab13a6cac3e1e31df4ebbfp-8,
    0x1.f7047cp-1
  },
  { // Entry 75
    -0x1.f63efaafb8883e9793490850e59689c5p-8,
    0x1.f70b5cp-1
  },
  { // Entry 76
    -0x1.f37d18ffb9ef3b0fef577217ed18e097p-8,
    0x1.f717d6p-1
  },
  { // Entry 77
    -0x1.def364ad9e50296b41e69bbd93d4b89dp-8,
    0x1.f774cep-1
  },
  { // Entry 78
    -0x1.d980a30635055b8d9b54edd672c858a3p-10,
    0x1.fddffep-1
  },
  { // Entry 79
    -0x1.be7cd6ffc9f63979c62763b7424b91b8p-10,
    0x1.fdfef8p-1
  },
  { // Entry 80
    -0x1.a0d0f2971f8c3359f07a6bb4fccab210p-10,
    0x1.fe21p-1
  },
  { // Entry 81
    -0x1.bd2a7f88f7e22e1fbeda7c34e78c5fbfp-11,
    0x1.fefffep-1
  },
  { // Entry 82
    -0x1.ad17eafff3e585f32e96d0e7c6897eaep-11,
    0x1.ff093ap-1
  },
  { // Entry 83
    -0x1.e1b20eab03fb3a4a3c1ca58716aa04d8p2,
    0x1.ff1ffep-26
  },
  { // Entry 84
    -0x1.bd42c8df31e3d447244cc720bd67faadp-12,
    0x1.ff7fe8p-1
  },
  { // Entry 85
    -0x1.bdb1f6cd42c7c46d6967bb003016e45bp-13,
    0x1.ffbfe0p-1
  },
  { // Entry 86
    -0x1.ca749c8706de8e46ee3cf5bf9a96ab1bp-14,
    0x1.ffdf04p-1
  },
  { // Entry 87
    -0x1.c600bcbce645991d16979edbbc0c311fp-14,
    0x1.ffdf56p-1
  },
  { // Entry 88
    -0x1.bd34cc84be200f8cb449c26c3f6763d1p-14,
    0x1.ffdff8p-1
  },
  { // Entry 89
    -0x1.bce164dc339f92c17cc22cb9a07458d6p-14,
    0x1.ffdffep-1
  },
  { // Entry 90
    -0x1.3443d0ffc8b4e8b31ed055e579024a80p-1,
    0x1.fff9fep-3
  },
  { // Entry 91
    -0x1.72de800001549031af6ca96747c1126fp4,
    0x1.fffc7ep-78
  },
  { // Entry 92
    0x1.344134ff8b51b7a013d2358e0089d30dp5,
    0x1.fffffap127
  },
  { // Entry 93
    -0x1.bcb7b30f2604868dab81d79e1f40443cp-25,
    0x1.fffffcp-1
  },
  { // Entry 94
    -0x1.3441360959c2bf17a59af37357663f09p-3,
    0x1.6a09e6p-1
  },
  { // Entry 95
    -0x1.8e271d6ab5d7ee84106f48e33b8cb8e0p-4,
    0x1.995256p-1
  },
  { // Entry 96
    -0x1.9762ba2f4a2198a2ce8974450be1661fp-5,
    0x1.c89ac6p-1
  },
  { // Entry 97
    -0x1.c694764682002f79a74b22bb7570477ep-8,
    0x1.f7e336p-1
  },
  { // Entry 98
    0x1.064661197381c71f1a9f9ac21e313749p-5,
    0x1.1395d2p0
  },
  { // Entry 99
    0x1.158bedc46861d0d27c114033f3db9a96p-4,
    0x1.2b3a0ap0
  },
  { // Entry 100
    0x1.9cd10befe72cc8a8ecfeacd70aed874ap-4,
    0x1.42de42p0
  },
  { // Entry 101
    0x1.0d42f94d71eab1a45a4e19f5a1d78fcbp-3,
    0x1.5a827ap0
  },
  { // Entry 102
    0x1.47f707c940c69c0e2b81a883c7fcf3e2p-3,
    0x1.7226b2p0
  },
  { // Entry 103
    0x1.7f08567d056a15ac18992a2573074fc1p-3,
    0x1.89caeap0
  },
  { // Entry 104
    0x1.b2e37e3ec1bd60c78ec0b821ea37604dp-3,
    0x1.a16f22p0
  },
  { // Entry 105
    0x1.e3e3215b7afa3355ef4ed63c72685ff3p-3,
    0x1.b9135ap0
  },
  { // Entry 106
    0x1.0929d68063288eaf1594278eb7b2fc8ep-2,
    0x1.d0b792p0
  },
  { // Entry 107
    0x1.1f3b15ea121ed378638c6e76b1a3108fp-2,
    0x1.e85bcap0
  },
  { // Entry 108
    0x1.34413509f79fef311f12b35816f922f0p-2,
    0x1.p1
  },
  { // Entry 109
    -0x1.3441360959c2bf17a59af37357663f09p-3,
    0x1.6a09e6p-1
  },
  { // Entry 110
    -0x1.edc7b7d1726b9d3a32996762d45e780ap-4,
    0x1.83e608p-1
  },
  { // Entry 111
    -0x1.7af97b7bce8afc77122afb0375a2da53p-4,
    0x1.9dc22ap-1
  },
  { // Entry 112
    -0x1.0f219957375a31be41be4c43a6916104p-4,
    0x1.b79e4cp-1
  },
  { // Entry 113
    -0x1.52e86324d08348db62a1b30a19674a5cp-5,
    0x1.d17a6ep-1
  },
  { // Entry 114
    -0x1.2519f3a5667aea40e1f962a1f5d85c21p-6,
    0x1.eb5690p-1
  },
  { // Entry 115
    0x1.1f80654567c5aa07e1d9578dfde75b1fp-8,
    0x1.02995ap0
  },
  { // Entry 116
    0x1.a30a884b48ced10372c3c1f79d81055bp-6,
    0x1.0f876cp0
  },
  { // Entry 117
    0x1.7706deccbe15df9c9101690cc9b736b0p-5,
    0x1.1c757ep0
  },
  { // Entry 118
    0x1.0a965f582ad2d2cc3962364e72fabf4bp-4,
    0x1.296390p0
  },
  { // Entry 119
    0x1.564ba4450402b6d51b22231ee30056ecp-4,
    0x1.3651a2p0
  },
  { // Entry 120
    0x1.9ee99d1f81cea5262e8e5fa8308a4f10p-4,
    0x1.433fb4p0
  },
  { // Entry 121
    0x1.e4ae6049c4561ba2e5b54e4aef7ec1f7p-4,
    0x1.502dc6p0
  },
  { // Entry 122
    0x1.13e87df00be5c8e58f5f6baa00a8e9a8p-3,
    0x1.5d1bd8p0
  },
  { // Entry 123
    0x1.3441340a957d1f4a988a733cd68c06d7p-3,
    0x1.6a09e6p0
  },
  { // Entry 124
    -0x1.ffbfc2bbc780375837c4b0b84f38a14ap-4,
    0x1.80p-1
  },
  { // Entry 125
    -0x1.5634641a3fd51681f12d3df90719aed0p-4,
    0x1.a66666p-1
  },
  { // Entry 126
    -0x1.76d86fdd61d0265fd8416f7297bd494fp-5,
    0x1.ccccccp-1
  },
  { // Entry 127
    -0x1.684c1a332d5dc3307d73c7ba25168d0fp-7,
    0x1.f33332p-1
  },
  { // Entry 128
    0x1.5b2a4774a2de2143d8ff5f649a50863bp-6,
    0x1.0cccccp0
  },
  { // Entry 129
    0x1.a30a9d609efe9c281982d7df7ae69259p-5,
    0x1.20p0
  },
  { // Entry 130
    0x1.445392859c560c3c9ed56125e21ba584p-4,
    0x1.333334p0
  },
  { // Entry 131
    0x1.b02b7b4804d6e3346e6f30fb0ed80ed8p-4,
    0x1.466668p0
  },
  { // Entry 132
    0x1.0aec747738c557211b21410621b26f8fp-3,
    0x1.59999cp0
  },
  { // Entry 133
    0x1.3b03516d50b3544158f589c768f946e6p-3,
    0x1.6cccd0p0
  },
  { // Entry 134
    0x1.68a288b60b7fc2b622430e540655f53bp-3,
    0x1.80p0
  },
  { // Entry 135
    0.0,
    0x1.p0
  },
  { // Entry 136
    0x1.e1a5e2df92e9e5bcc08d3839a3e54697p4,
    0x1.p100
  },
  { // Entry 137
    0x1.e24f6e426a8bf8a9e67a7799f8b17451p4,
    0x1.19999ap100
  },
  { // Entry 138
    0x1.e2ea367218863bc8fd2c0d9ac9c7623cp4,
    0x1.333334p100
  },
  { // Entry 139
    0x1.e3789929b904e81bc6f0e5158f365203p4,
    0x1.4ccccep100
  },
  { // Entry 140
    0x1.e3fc6d41682d18d8c703d601ddc1fa20p4,
    0x1.666668p100
  },
  { // Entry 141
    0x1.e47727fa42d490cc96bad253a3656436p4,
    0x1.800002p100
  },
  { // Entry 142
    0x1.e4e9f63a9eb204cd2dcd94b7ceca28a7p4,
    0x1.99999cp100
  },
  { // Entry 143
    0x1.e555ce20504ed691954bc10e175867a8p4,
    0x1.b33336p100
  },
  { // Entry 144
    0x1.e5bb7b8b3d22f0a25afb3f6c6877e417p4,
    0x1.ccccd0p100
  },
  { // Entry 145
    0x1.e61ba942b928956af0bafc1ad04f0b20p4,
    0x1.e6666ap100
  },
  { // Entry 146
    0x1.e676e7b3bac865798509830704412b23p4,
    0x1.p101
  },
  { // Entry 147
    -0x1.bcb7bf382c6fb3df0029e1e6c04e5b04p-22,
    0x1.ffffe0p-1
  },
  { // Entry 148
    -0x1.15f2d18a6400ab03be90bfceaa5447fbp-23,
    0x1.fffff6p-1
  },
  { // Entry 149
    0x1.4d89c115357d535c8f9533338e6883eap-23,
    0x1.000006p0
  },
  { // Entry 150
    0x1.bcb7a36cb15a8cec0c39b0a7cf2d7858p-22,
    0x1.000010p0
  },
  { // Entry 151
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 152
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 153
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 154
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 155
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 156
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 157
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 158
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 159
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 160
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 161
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 162
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 163
    0x1.344135067e308acf8abe721a7991fdb7p5,
    0x1.fffffep127
  },
  { // Entry 164
    -0x1.66d3e7bd9a402c6f2e2bc4c48abe02abp5,
    0x1.p-149
  },
  { // Entry 165
    -0x1.34413af333ae8c86c135ab5278494452p-3,
    0x1.6a09e4p-1
  },
  { // Entry 166
    -0x1.3441360959c2bf17a59af37357663f09p-3,
    0x1.6a09e6p-1
  },
  { // Entry 167
    -0x1.3441311f7fdde48753477d6b1af5d93dp-3,
    0x1.6a09e8p-1
  },
  { // Entry 168
    0x1.34412f20bb9151db7cefbb5db5a9018ep-3,
    0x1.6a09e4p0
  },
  { // Entry 169
    0x1.3441340a957d1f4a988a733cd68c06d7p-3,
    0x1.6a09e6p0
  },
  { // Entry 170
    0x1.344138f46f61f9daeadde94512fc6ca3p-3,
    0x1.6a09e8p0
  },
  { // Entry 171
    -0x1.344136c6af521ffb49335226ca8bbf4ap-2,
    0x1.fffffep-2
  },
  { // Entry 172
    -0x1.34413509f79fef311f12b35816f922f0p-2,
    0x1.p-1
  },
  { // Entry 173
    -0x1.344131908840c3c3db4f515285b11c22p-2,
    0x1.000002p-1
  },
  { // Entry 174
    -0x1.ffbfcbff9b381c31b8783059f0acf062p-4,
    0x1.7ffffep-1
  },
  { // Entry 175
    -0x1.ffbfc2bbc780375837c4b0b84f38a14ap-4,
    0x1.80p-1
  },
  { // Entry 176
    -0x1.ffbfb977f3d4acee4eb0b360dbc6ec48p-4,
    0x1.800002p-1
  },
  { // Entry 177
    0x1.68a2841421a3d04961e94e83359bcdafp-3,
    0x1.7ffffep0
  },
  { // Entry 178
    0x1.68a288b60b7fc2b622430e540655f53bp-3,
    0x1.80p0
  },
  { // Entry 179
    0x1.68a28d57f55587eb16cd0cffc00ecfbcp-3,
    0x1.800002p0
  },
  { // Entry 180
    0x1.28132fbb336f7bcb34b70b00867dc9d5p-10,
    0x1.00aaa8p0
  },
  { // Entry 181
    0x1.2816a6db3131b6eda414e69eae447c9dp-10,
    0x1.00aaaap0
  },
  { // Entry 182
    0x1.281a1dfb280a4dd9abcda3a702e5258dp-10,
    0x1.00aaacp0
  },
  { // Entry 183
    0x1.3441342b9bc6d6cc0a0263f0bd2fd4c3p-1,
    0x1.fffffep1
  },
  { // Entry 184
    0x1.34413509f79fef311f12b35816f922f0p-1,
    0x1.p2
  },
  { // Entry 185
    0x1.344136c6af4f84e7c0f4645adf9d2657p-1,
    0x1.000002p2
  },
  { // Entry 186
    0x1.3441334d3fedbe66f4f2148963668696p-2,
    0x1.fffffep0
  },
  { // Entry 187
    0x1.34413509f79fef311f12b35816f922f0p-2,
    0x1.p1
  },
  { // Entry 188
    0x1.3441388366ff1a9e62d6155da84129bep-2,
    0x1.000002p1
  },
  { // Entry 189
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 190
    0.0,
    0x1.p0
  },
  { // Entry 191
    0x1.bcb7af95b6a1e1b102c8a40366dc2f73p-25,
    0x1.000002p0
  },
  { // Entry 192
    -0x1.344136c6af521ffb49335226ca8bbf4ap-2,
    0x1.fffffep-2
  },
  { // Entry 193
    -0x1.34413509f79fef311f12b35816f922f0p-2,
    0x1.p-1
  },
  { // Entry 194
    -0x1.344131908840c3c3db4f515285b11c22p-2,
    0x1.000002p-1
  },
  { // Entry 195
    -0x1.344135e853790796342302bf70c2711dp-1,
    0x1.fffffep-3
  },
  { // Entry 196
    -0x1.34413509f79fef311f12b35816f922f0p-1,
    0x1.p-2
  },
  { // Entry 197
    -0x1.3441334d3ff0597a7d3102554e551f89p-1,
    0x1.000002p-2
  },
  { // Entry 198
    -0x1.ce61d06d4f48ff2ec3ac5c6b7c3f0295p-1,
    0x1.fffffep-4
  },
  { // Entry 199
    -0x1.ce61cf8ef36fe6c9ae9c0d042275b468p-1,
    0x1.p-3
  },
  { // Entry 200
    -0x1.ce61cdd23bc051130cba5c0159d1b101p-1,
    0x1.000002p-3
  },
  { // Entry 201
    -0x1.34413579258c7b63a99adb0bc3ddca06p0,
    0x1.fffffep-5
  },
  { // Entry 202
    -0x1.34413509f79fef311f12b35816f922f0p0,
    0x1.p-4
  },
  { // Entry 203
    -0x1.3441342b9bc82455ce21dad6b2a7213cp0,
    0x1.000002p-4
  },
  { // Entry 204
    -0x1.815182bba374772ff15f87e1c99c12c2p0,
    0x1.fffffep-6
  },
  { // Entry 205
    -0x1.8151824c7587eafd66d7602e1cb76bacp0,
    0x1.p-5
  },
  { // Entry 206
    -0x1.8151816e19b0202215e687acb86569f8p0,
    0x1.000002p-5
  },
  { // Entry 207
    -0x1.ce61cffe215c72fc392434b7cf5a5b7ep0,
    0x1.fffffep-7
  },
  { // Entry 208
    -0x1.ce61cf8ef36fe6c9ae9c0d042275b468p0,
    0x1.p-6
  },
  { // Entry 209
    -0x1.ce61ceb097981bee5dab3482be23b2b5p0,
    0x1.000002p-6
  },
  { // Entry 210
    -0x1.0db90ea04fa23764407470c6ea8c521dp1,
    0x1.fffffep-8
  },
  { // Entry 211
    -0x1.0db90e68b8abf14afb305ced1419fe92p1,
    0x1.p-7
  },
  { // Entry 212
    -0x1.0db90df98ac00bdd52b7f0ac61f0fdb8p1,
    0x1.000002p-7
  },
  { // Entry 213
    -0x1.344135418e96354a6456c731ed6b767bp1,
    0x1.fffffep-9
  },
  { // Entry 214
    -0x1.34413509f79fef311f12b35816f922f0p1,
    0x1.p-8
  },
  { // Entry 215
    -0x1.3441349ac9b409c3769a471764d02216p1,
    0x1.000002p-8
  },
  { // Entry 216
    -0x1.5ac95be2cd8a333088391d9cf04a9ad9p1,
    0x1.fffffep-10
  },
  { // Entry 217
    -0x1.5ac95bab3693ed1742f509c319d8474ep1,
    0x1.p-9
  },
  { // Entry 218
    -0x1.5ac95b3c08a807a99a7c9d8267af4674p1,
    0x1.000002p-9
  },
  { // Entry 219
    -0x1.815182840c7e3116ac1b7407f329bf37p1,
    0x1.fffffep-11
  },
  { // Entry 220
    -0x1.8151824c7587eafd66d7602e1cb76bacp1,
    0x1.p-10
  },
  { // Entry 221
    -0x1.815181dd479c058fbe5ef3ed6a8e6ad2p1,
    0x1.000002p-10
  },
  { // Entry 222
    -0x1.f4e9f667c95a2ac917c27748fbc72c51p1,
    0x1.fffffep-14
  },
  { // Entry 223
    -0x1.f4e9f6303263e4afd27e636f2554d8c6p1,
    0x1.p-13
  },
  { // Entry 224
    -0x1.f4e9f5c10477ff422a05f72e732bd7ecp1,
    0x1.000002p-13
  },
  { // Entry 225
    -0x1.f4e9f667c95a2ac917c27748fbc72c51p1,
    0x1.fffffep-14
  },
  { // Entry 226
    -0x1.f4e9f6303263e4afd27e636f2554d8c6p1,
    0x1.p-13
  },
  { // Entry 227
    -0x1.f4e9f5c10477ff422a05f72e732bd7ecp1,
    0x1.000002p-13
  },
  { // Entry 228
    -0x1.ce61d06d4f48ff2ec3ac5c6b7c3f0295p-1,
    0x1.fffffep-4
  },
  { // Entry 229
    -0x1.ce61cf8ef36fe6c9ae9c0d042275b468p-1,
    0x1.p-3
  },
  { // Entry 230
    -0x1.ce61cdd23bc051130cba5c0159d1b101p-1,
    0x1.000002p-3
  },
  { // Entry 231
    -0x1.db11fd5867f8ff1cca049f4cb4fd8694p-5,
    0x1.bffffep-1
  },
  { // Entry 232
    -0x1.db11ed766abf432dc3c1bb4167a6eb47p-5,
    0x1.c0p-1
  },
  { // Entry 233
    -0x1.db11dd946d97ae16f51ada8f25bd4cc1p-5,
    0x1.c00002p-1
  },
  { // Entry 234
    -0x1.34413579258c7b63a99adb0bc3ddca06p0,
    0x1.fffffep-5
  },
  { // Entry 235
    -0x1.34413509f79fef311f12b35816f922f0p0,
    0x1.p-4
  },
  { // Entry 236
    -0x1.3441342b9bc82455ce21dad6b2a7213cp0,
    0x1.000002p-4
  },
  { // Entry 237
    -0x1.cb391a7364ac9eed883817f1ffc2150cp-6,
    0x1.dffffep-1
  },
  { // Entry 238
    -0x1.cb38fccd8bfdb696b29463658b991237p-6,
    0x1.e0p-1
  },
  { // Entry 239
    -0x1.cb38df27b36e6e15dbf9aa6e26e0527bp-6,
    0x1.e00002p-1
  },
  { // Entry 240
    -0x1.815182bba374772ff15f87e1c99c12c2p0,
    0x1.fffffep-6
  },
  { // Entry 241
    -0x1.8151824c7587eafd66d7602e1cb76bacp0,
    0x1.p-5
  },
  { // Entry 242
    -0x1.8151816e19b0202215e687acb86569f8p0,
    0x1.000002p-5
  },
  { // Entry 243
    -0x1.c3d0bcd98b3edf45205cfdbb6aed1917p-7,
    0x1.effffep-1
  },
  { // Entry 244
    -0x1.c3d0837784c409cbf85d4dd61d426e1bp-7,
    0x1.f0p-1
  },
  { // Entry 245
    -0x1.c3d04a157e84703859e1417a8c326212p-7,
    0x1.f00002p-1
  },
  { // Entry 246
    -0x1.ce61cffe215c72fc392434b7cf5a5b7ep0,
    0x1.fffffep-7
  },
  { // Entry 247
    -0x1.ce61cf8ef36fe6c9ae9c0d042275b468p0,
    0x1.p-6
  },
  { // Entry 248
    -0x1.ce61ceb097981bee5dab3482be23b2b5p0,
    0x1.000002p-6
  },
  { // Entry 249
    -0x1.c03af1a0115fb694dfc7e5305e350297p-8,
    0x1.f7fffep-1
  },
  { // Entry 250
    -0x1.c03a80ae5e05382d51f71b0f6602c76ap-8,
    0x1.f8p-1
  },
  { // Entry 251
    -0x1.c03a0fbcab1d766b7c26660812478675p-8,
    0x1.f80002p-1
  },
  { // Entry 252
    -0x1.0db90ea04fa23764407470c6ea8c521dp1,
    0x1.fffffep-8
  },
  { // Entry 253
    -0x1.0db90e68b8abf14afb305ced1419fe92p1,
    0x1.p-7
  },
  { // Entry 254
    -0x1.0db90df98ac00bdd52b7f0ac61f0fdb8p1,
    0x1.000002p-7
  },
  { // Entry 255
    -0x1.be779d93c637ed8142930d32c760672cp-9,
    0x1.fbfffep-1
  },
  { // Entry 256
    -0x1.be76bd77b4fc30d6cb5e729fc0bd5fa5p-9,
    0x1.fcp-1
  },
  { // Entry 257
    -0x1.be75dd5ba4a253fcbfcde28906782f81p-9,
    0x1.fc0002p-1
  },
  { // Entry 258
    -0x1.344135418e96354a6456c731ed6b767bp1,
    0x1.fffffep-9
  },
  { // Entry 259
    -0x1.34413509f79fef311f12b35816f922f0p1,
    0x1.p-8
  },
  { // Entry 260
    -0x1.3441349ac9b409c3769a471764d02216p1,
    0x1.000002p-8
  },
  { // Entry 261
    -0x1.bd98604e0225c5f5bcfcaf2d317a9cb8p-10,
    0x1.fdfffep-1
  },
  { // Entry 262
    -0x1.bd96a1d7d9cbc28d1ed88eb987048038p-10,
    0x1.fep-1
  },
  { // Entry 263
    -0x1.bd94e361b331f5825874683d16a4fa02p-10,
    0x1.fe0002p-1
  },
  { // Entry 264
    -0x1.5ac95be2cd8a333088391d9cf04a9ad9p1,
    0x1.fffffep-10
  },
  { // Entry 265
    -0x1.5ac95bab3693ed1742f509c319d8474ep1,
    0x1.p-9
  },
  { // Entry 266
    -0x1.5ac95b3c08a807a99a7c9d8267af4674p1,
    0x1.000002p-9
  },
  { // Entry 267
    -0x1.bd2a7f88f7e22e1fbeda7c34e78c5fbfp-11,
    0x1.fefffep-1
  },
  { // Entry 268
    -0x1.bd27045bfd024b0eb5a690199f7d311fp-11,
    0x1.ffp-1
  },
  { // Entry 269
    -0x1.bd23892f059f536c854c6b13c5a3b7bfp-11,
    0x1.ff0002p-1
  },
  { // Entry 270
    -0x1.815182840c7e3116ac1b7407f329bf37p1,
    0x1.fffffep-11
  },
  { // Entry 271
    -0x1.8151824c7587eafd66d7602e1cb76bacp1,
    0x1.p-10
  },
  { // Entry 272
    -0x1.815181dd479c058fbe5ef3ed6a8e6ad2p1,
    0x1.000002p-10
  },
  { // Entry 273
    -0x1.bcf6462a1921118a3b66f92fb7c60797p-12,
    0x1.ff7ffep-1
  },
  { // Entry 274
    -0x1.bcef518e29611a506bc6531e97655414p-12,
    0x1.ff80p-1
  },
  { // Entry 275
    -0x1.bce85cf240977c99419983a95dfa8d28p-12,
    0x1.ff8002p-1
  },
  { // Entry 276
    -0x1.f4e9f667c95a2ac917c27748fbc72c51p1,
    0x1.fffffep-14
  },
  { // Entry 277
    -0x1.f4e9f6303263e4afd27e636f2554d8c6p1,
    0x1.p-13
  },
  { // Entry 278
    -0x1.f4e9f5c10477ff422a05f72e732bd7ecp1,
    0x1.000002p-13
  },
  { // Entry 279
    -0x1.bcf63d094f7a45ef4f9d2bcde45ded2fp-15,
    0x1.ffeffep-1
  },
  { // Entry 280
    -0x1.bcbea45643c7c4b46503e30e59b7dd28p-15,
    0x1.fff0p-1
  },
  { // Entry 281
    -0x1.bc870ba36fafb33cddcf17f055436437p-15,
    0x1.fff002p-1
  },
  { // Entry 282
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 283
    0x1.344135067e308acf8abe721a7991fdb7p5,
    0x1.fffffep127
  },
  { // Entry 284
    0x1.3441350304c122f48700992168f1c477p5,
    0x1.fffffcp127
  },
  { // Entry 285
    0x1.fd14dc015a2443dc8d1c9a7a4ead7c44p-2,
    0x1.921fb6p1
  },
  { // Entry 286
    0x1.91a74deec508a956dc13ce446f68b2a7p-3,
    0x1.921fb6p0
  },
  { // Entry 287
    0x1.bcb7af95b6a1e1b102c8a40366dc2f73p-25,
    0x1.000002p0
  },
  { // Entry 288
    0.0,
    0x1.p0
  },
  { // Entry 289
    -0x1.bcb7b230ca2a209eceb3929c5a02ff59p-26,
    0x1.fffffep-1
  },
  { // Entry 290
    -0x1.adb6384a546e6a16c42330d77d132671p-4,
    0x1.921fb6p-1
  },
  { // Entry 291
    -0x1.2f70302edce2b11d800ee1c6ab7aae56p5,
    0x1.000002p-126
  },
  { // Entry 292
    -0x1.2f703035cfc16f745a96688ab69d3e64p5,
    0x1.p-126
  },
  { // Entry 293
    -0x1.2f70303cc2a03bb0f2a882c164a49cddp5,
    0x1.fffffcp-127
  },
  { // Entry 294
    -0x1.2f703043b57f15d3487cc76186a378f6p5,
    0x1.fffff8p-127
  },
  { // Entry 295
    -0x1.646b65538650ec90cbed9f5dda901065p5,
    0x1.p-148
  },
  { // Entry 296
    -0x1.66d3e7bd9a402c6f2e2bc4c48abe02abp5,
    0x1.p-149
  },
  { // Entry 297
    -HUGE_VALF,
    0.0f
  },
  { // Entry 298
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 299
    0x1.p0,
    0x1.40p3
  },
  { // Entry 300
    0x1.p1,
    0x1.90p6
  },
  { // Entry 301
    0x1.80p1,
    0x1.f4p9
  }
};
```
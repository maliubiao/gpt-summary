Response:
Let's break down the thought process for answering the request about `exp2_intel_data.handroid`.

**1. Understanding the Core Request:**

The request is to analyze a specific data file within the Android Bionic library. The key here is recognizing it's *data*, not executable code. This immediately sets the direction for the analysis. The request also asks about its function, relation to Android, libc functions, dynamic linker, usage errors, and how Android reaches this point.

**2. Initial Analysis of the File Content:**

Scanning the file, the most obvious thing is the structure: an array named `g_exp2_intel_data` containing elements of type `data_1_1_t<double, double>`. Each element is a pair of double-precision floating-point numbers. The comments `// Entry N` suggest these are test cases or data points. The numbers themselves are in hexadecimal floating-point format.

**3. Deducing the File's Purpose:**

Given the filename (`exp2_intel_data`) and the data structure, the most logical conclusion is that this file contains test data for the `exp2` function (2 raised to the power of x). The "intel_data" part likely indicates these are specifically tailored or observed on Intel architectures. The presence of input and expected output pairs reinforces this idea. The "handroid" part likely signifies it's part of a set of hand-crafted test cases for Android.

**4. Addressing Specific Questions:**

* **功能 (Function):**  The primary function is to provide test data for the `exp2` function. It's used for verifying the correctness of the `exp2` implementation in Bionic's math library.

* **与 Android 的关系 (Relationship with Android):** This data directly supports the functionality and stability of Android's math library. It ensures that `exp2` behaves correctly on Android devices, especially those with Intel processors. Examples include scientific calculations, graphics rendering, and any application using exponential functions.

* **libc 函数的功能实现 (Implementation of libc functions):** This file *doesn't implement* any libc functions. It *tests* one (`exp2`). Therefore, the explanation needs to focus on the conceptual implementation of `exp2` (using Taylor series, range reduction, etc.) without going into the specific Bionic source code (which isn't provided in the data file).

* **Dynamic Linker 功能 (Dynamic Linker Functionality):** This data file is *static data*. It's embedded within the compiled library. The dynamic linker is involved in loading the math library containing the `exp2` implementation, but it doesn't directly interact with this data file at runtime. The explanation should focus on the dynamic linking of the math library itself and how functions like `exp2` become available to applications. A basic shared object layout example is relevant here.

* **逻辑推理 (Logical Inference):** The pairs of numbers strongly suggest input-output relationships. Given an input (the first double), the second double is the expected output of `exp2`. Examples should be chosen to illustrate positive, negative, zero, and edge cases (like very small or large numbers, NaN, Infinity).

* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Focus on errors related to using `exp2` or exponential functions in general, such as overflow, underflow, and incorrect assumptions about precision.

* **Android Framework/NDK 到达这里 (How Android Framework/NDK reaches here):** Trace the path from an application using `std::pow` or `powf`/`powl` (NDK) or higher-level Android APIs that might rely on exponential calculations down to the underlying Bionic `exp2` implementation and how this test data is used during development and testing.

* **Frida Hook 示例 (Frida Hook Example):** Provide practical examples of using Frida to intercept calls to `exp2` or related functions to observe inputs and outputs, which helps in debugging or understanding the flow.

**5. Structuring the Answer:**

Organize the answer according to the questions in the request. Use clear headings and bullet points for readability. Provide concrete examples and avoid overly technical jargon where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file contains optimized assembly code for `exp2` on Intel.
* **Correction:**  No, the structure clearly indicates data. The name suggests it's *for* Intel, not necessarily code *on* Intel.
* **Initial thought:** Explain the assembly implementation of `exp2`.
* **Correction:** The file doesn't provide the implementation. Focus on the *general* approach and how test data helps verify *any* implementation.
* **Initial thought:** Detail the complex linking process of all libraries.
* **Correction:** Focus on the linking of the math library (`libm.so`) as it's the most relevant context.

By following this structured thought process, considering the nature of the file, and addressing each part of the request, we arrive at a comprehensive and accurate answer.
这个文件 `bionic/tests/math_data/exp2_intel_data.handroid` 是 Android Bionic 库中的一个数据文件，用于测试 `exp2` 函数的正确性。`exp2(x)` 函数的功能是计算 2 的 x 次方 (2<sup>x</sup>)。

**功能列举:**

1. **提供测试用例：** 该文件包含一系列预定义的输入和预期输出值对，用于测试 `exp2` 函数在不同输入下的精度和正确性。
2. **针对 Intel 架构：** 文件名中的 "intel_data" 表明这些测试用例可能是针对 Intel 架构的特性或潜在问题而设计的。
3. **自动化测试的一部分：**  在 Android Bionic 的构建和测试过程中，这些数据会被用来自动验证 `exp2` 函数的实现是否符合预期。

**与 Android 功能的关系及举例说明:**

`exp2` 函数是 C 标准数学库 (`math.h`) 的一部分，在 Android 中由 Bionic 库提供实现。它在许多 Android 系统和应用程序的功能中都有应用，例如：

* **图形渲染：** 在 OpenGL ES 等图形库中，指数运算常用于计算光照衰减、动画缓动效果等。
* **音频处理：** 在音频编解码、均衡器等算法中，指数运算可以用来调整音量、频率响应等。
* **科学计算应用：**  各种科学计算、工程计算类的 Android 应用会直接或间接地使用 `exp2` 或相关的指数函数。
* **机器学习和人工智能：** 许多机器学习模型，特别是神经网络，会使用指数函数作为激活函数。

**举例说明:** 假设一个 Android 游戏需要实现一个光照效果，光照强度随距离指数衰减。游戏引擎可能会调用 `exp2` 函数来计算衰减因子。例如，如果距离为 `d`，衰减因子可能是 `pow(0.5, d)`，这等价于 `exp2(-d)`。

**libc 函数的功能实现 (针对 `exp2`)：**

`exp2(double x)` 函数的常见实现方法涉及到以下步骤：

1. **参数预处理 (Range Reduction)：**
   - 将输入 `x` 分解为整数部分 `n` 和小数部分 `f`，即 `x = n + f`，其中 `n` 是整数，`-0.5 <= f < 0.5` 或其他合适的范围。
   - 利用指数的性质：2<sup>x</sup> = 2<sup>n+f</sup> = 2<sup>n</sup> * 2<sup>f</sup>。
   - 整数部分 `n` 可以通过简单的位运算来实现 2<sup>n</sup> 的计算（左移 `n` 位或右移 `-n` 位）。
   - 关键在于如何高效且精确地计算 2<sup>f</sup>，其中 `f` 是一个较小的分数。

2. **多项式逼近 (Polynomial Approximation)：**
   - 对于小数部分 `f`，可以使用多项式来逼近 2<sup>f</sup>。常见的逼近方法是使用泰勒级数展开或切比雪夫多项式逼近。
   - 例如，2<sup>f</sup> 的泰勒级数展开为：1 + f*ln(2) + (f*ln(2))^2 / 2! + (f*ln(2))^3 / 3! + ...
   - 实际实现中，为了精度和性能考虑，通常会选择有限项的多项式，并针对 `f` 的不同范围使用不同的多项式。

3. **结果组合：**
   - 将步骤 1 中计算得到的 2<sup>n</sup> 和步骤 2 中计算得到的 2<sup>f</sup> 相乘，得到最终结果 2<sup>x</sup>。

4. **特殊情况处理：**
   - 处理特殊输入值，例如正无穷、负无穷、NaN (非数字) 等，根据 IEEE 754 标准返回相应的结果。

**对于涉及 dynamic linker 的功能：**

这个数据文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的作用是在应用程序启动时加载所需的共享库 (`.so` 文件)，并将应用程序代码中调用的库函数链接到库的实际地址。

**so 布局样本:**

一个典型的包含 `exp2` 函数的 `libm.so` (Android 的数学库) 的布局可能如下：

```
libm.so:
    .text:  # 包含可执行代码
        exp2:  # exp2 函数的机器码
            ...
        sin:
            ...
        cos:
            ...
        ...
    .data:  # 包含已初始化的全局变量
        一些数学常量
    .rodata: # 包含只读数据
        一些查找表 (可能用于 exp2 的多项式逼近)
    .dynsym: # 动态符号表，列出库中可被外部引用的符号
        exp2
        sin
        cos
        ...
    .dynstr: # 动态字符串表，存储符号名
        "exp2"
        "sin"
        "cos"
        ...
    .plt:    # 程序链接表，用于延迟绑定
        ...
    .got:    # 全局偏移表，存储外部符号的地址
        ...
```

**链接的处理过程:**

1. **应用程序发起调用：** 应用程序代码中调用了 `exp2` 函数。由于 `exp2` 位于 `libm.so` 中，这最初是一个未解析的符号。
2. **加载器介入：** 操作系统加载应用程序时，会解析应用程序依赖的共享库，包括 `libm.so`。
3. **动态链接：** Dynamic linker 读取 `libm.so` 的动态符号表 (`.dynsym`) 和字符串表 (`.dynstr`)，找到 `exp2` 符号。
4. **重定位：** Dynamic linker 将应用程序中对 `exp2` 的调用重定向到 `libm.so` 中 `exp2` 函数的实际内存地址。这通常通过修改应用程序的全局偏移表 (`.got`) 或程序链接表 (`.plt`) 来实现。
5. **执行：** 当程序执行到 `exp2` 调用时，会跳转到 `libm.so` 中 `exp2` 的代码执行。

**逻辑推理 (假设输入与输出):**

该文件中的每一项 `data_1_1_t<double, double>` 都可以看作一个测试用例，第一个 `double` 是输入，第二个 `double` 是预期的输出。

例如，对于第一个条目：

```
{ // Entry 0
  0x1.7550685a42c638000000000000845a47p0,
  0x1.16a76ec41b516p-1
}
```

* **假设输入:** `0x1.7550685a42c638000000000000845a47p0` (十六进制浮点数表示，等于十进制的 1.7099999999999999689890608022864)
* **预期输出:** `0x1.16a76ec41b516p-1` (十六进制浮点数表示，等于十进制的 0.5499999999999999778159711320805)

这意味着测试的目标是验证 `exp2(1.7099999999999999689890608022864)` 的结果是否接近 `0.5499999999999999778159711320805`。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **溢出 (Overflow)：** 当输入 `x` 过大时，2<sup>x</sup> 的结果会超出 `double` 类型的表示范围，导致结果为正无穷 (`HUGE_VAL`)。
   ```c
   #include <cmath>
   #include <iostream>

   int main() {
       double x = 1024.0; // 一个较大的值
       double result = exp2(x);
       std::cout << "exp2(" << x << ") = " << result << std::endl; // 输出可能为 inf
       return 0;
   }
   ```

2. **下溢 (Underflow)：** 当输入 `x` 非常小时（负数且绝对值很大），2<sup>x</sup> 的结果会非常接近于 0，可能低于 `double` 类型的最小正规数，导致结果为 0 或非常小的非零值。
   ```c
   #include <cmath>
   #include <iostream>

   int main() {
       double x = -1100.0; // 一个很小的负值
       double result = exp2(x);
       std::cout << "exp2(" << x << ") = " << result << std::endl; // 输出可能为 0
       return 0;
   }
   ```

3. **精度问题：**  浮点数运算存在精度限制。对于某些输入，`exp2` 的计算结果可能与理论值存在微小的误差。测试数据中的预期输出通常会考虑这些精度限制。

4. **错误的输入类型：** 虽然 `exp2` 接受 `double` 类型的参数，但如果将其他类型（例如 `int`）隐式转换为 `double`，可能会因为类型转换的精度损失而导致细微的差异。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用：**  应用程序可以通过 Java Framework 或 Native Development Kit (NDK) 调用与指数运算相关的函数。
   * **Java Framework:**  例如，`java.lang.Math.pow(2.0, x)` 会在底层调用 native 方法，最终可能间接调用到 Bionic 的 `exp2` (对于以 2 为底的情况，可能会有优化)。
   * **NDK:** C/C++ 代码可以直接使用 `<cmath>` 头文件中的 `exp2(double x)` 函数。

2. **NDK 到 Bionic libc:** 当 NDK 代码调用 `exp2` 时，链接器会将该调用链接到 Android 系统提供的 `libc.so` (或者更具体的 `libm.so`) 中的 `exp2` 实现。

3. **Bionic `libm.so` 中的 `exp2` 实现：** Bionic 的 `libm.so` 包含了 `exp2` 函数的具体实现代码。这个实现可能会使用各种优化技巧，并需要保证精度和性能。

4. **测试数据的使用：**  `bionic/tests/math_data/exp2_intel_data.handroid` 文件在 Bionic 的测试阶段被使用。开发者会编写测试程序，读取这个文件中的数据，然后调用 Bionic 的 `exp2` 函数，并将结果与文件中预期的输出进行比较，以验证 `exp2` 的实现是否正确。

**Frida Hook 示例调试步骤:**

假设你想 hook NDK 中调用的 `exp2` 函数，可以按照以下步骤使用 Frida：

1. **准备环境：** 确保你的 Android 设备已 root，并安装了 Frida 服务端。在 PC 上安装了 Frida 客户端。

2. **编写 Frida 脚本 (JavaScript)：**

   ```javascript
   if (Process.arch === 'arm64') {
       var exp2Ptr = Module.findExportByName("libm.so", "exp2");
       if (exp2Ptr) {
           Interceptor.attach(exp2Ptr, {
               onEnter: function (args) {
                   this.x = args[0].toDouble();
                   console.log("[+] Calling exp2(" + this.x + ")");
               },
               onLeave: function (retval) {
                   console.log("[+] exp2 returned: " + retval.toDouble());
               }
           });
       } else {
           console.log("[-] exp2 not found in libm.so");
       }
   } else {
       console.log("[-] Script is for arm64 architecture.");
   }
   ```

3. **运行 Frida 脚本：**

   ```bash
   frida -U -f <your_app_package_name> -l your_script.js
   ```

   将 `<your_app_package_name>` 替换为你要调试的 Android 应用的包名，`your_script.js` 替换为你的 Frida 脚本文件名。

**Frida Hook 示例说明:**

* **`Process.arch === 'arm64'`:**  检查进程架构是否为 arm64，因为 `exp2` 的符号和地址可能因架构而异。
* **`Module.findExportByName("libm.so", "exp2")`:** 在 `libm.so` 模块中查找导出的 `exp2` 函数的地址。
* **`Interceptor.attach(exp2Ptr, ...)`:**  拦截对 `exp2` 函数的调用。
* **`onEnter`:** 在 `exp2` 函数被调用前执行，记录并打印输入参数。
* **`onLeave`:** 在 `exp2` 函数执行完毕后执行，记录并打印返回值。

通过运行这个 Frida 脚本，当目标 Android 应用调用 `exp2` 函数时，你可以在 Frida 的控制台中看到函数的输入参数和返回值，从而帮助你调试和理解代码的执行流程。这个过程可以让你验证 Android Framework 或 NDK 的调用最终是否到达了 Bionic 的 `exp2` 实现，并观察其行为。

总结来说，`bionic/tests/math_data/exp2_intel_data.handroid` 是一个重要的测试数据文件，用于保证 Android 系统中 `exp2` 函数的正确性和精度，它在 Android 的开发和测试流程中扮演着关键角色。

### 提示词
```
这是目录为bionic/tests/math_data/exp2_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_exp2_intel_data[] = {
  { // Entry 0
    0x1.7550685a42c638000000000000845a47p0,
    0x1.16a76ec41b516p-1
  },
  { // Entry 1
    0x1.89d948a94fe16fffffffffffff2cd3bdp0,
    0x1.3e34fa6ab969ep-1
  },
  { // Entry 2
    0x1.90661da12d5288000000000000b1b5f1p0,
    0x1.4a63ff1d53f53p-1
  },
  { // Entry 3
    0x1.cd6b37edeceaf7ffffffffffff7681d4p0,
    0x1.b32a6c92d1185p-1
  },
  { // Entry 4
    0x1.1ba39ff28e3e9fffffffffffffc69c44p1,
    0x1.25dd9eedac79ap0
  },
  { // Entry 5
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 6
    0x1.fffffffe9d1bd010d75fee7817e4dfc0p-1,
    -0x1.0000000000001p-32
  },
  { // Entry 7
    0x1.ffffffffffa746f404171ff3199aeed7p-1025,
    -0x1.0000000000001p10
  },
  { // Entry 8
    0x1.fe9d96b2a23d882193f7b993586f2602p-1,
    -0x1.000000000006ap-8
  },
  { // Entry 9
    0x1.ffffffff8a2a3c157c3b7f18ebab642dp-1025,
    -0x1.0000000000154p10
  },
  { // Entry 10
    0x1.ea4afa2a47b9bffeb53a92123e2892d5p-1,
    -0x1.000000001p-4
  },
  { // Entry 11
    0x1.6a09d3c7fa7857ffff5d816eb683ef4bp-1,
    -0x1.000025fffffafp-1
  },
  { // Entry 12
    0x1.fe9d966c1fb8a82de91ee9a29410d9a9p-1,
    -0x1.0000330p-8
  },
  { // Entry 13
    0x1.fa764417ff7da7fd252560ea61130296p-1,
    -0x1.011p-6
  },
  { // Entry 14
    0x1.e3ef96693f8579bbc20fc1cbf9decfc3p-1031,
    -0x1.01853479d6414p10
  },
  { // Entry 15
    0x1.171354a3dac90fb1c06ced94bc098564p-1058,
    -0x1.0878080p10
  },
  { // Entry 16
    0x1.00000000018f40b5ed994a2726414d06p-1074,
    -0x1.0c7fffffffff7p10
  },
  { // Entry 17
    0x1.00000000002c5c85fdf477b662b26945p-1074,
    -0x1.0c7ffffffffffp10
  },
  { // Entry 18
    0.0,
    -0x1.0c80000000001p10
  },
  { // Entry 19
    0.0,
    -0x1.0c80400000001p10
  },
  { // Entry 20
    0.0,
    -0x1.0cbffffffffffp10
  },
  { // Entry 21
    0.0,
    -0x1.0ccp10
  },
  { // Entry 22
    0x1.5fa21f48b380a7ff88e685255cd2b0b9p-68,
    -0x1.0e2b14f637093p6
  },
  { // Entry 23
    0x1.fffff3deb381580911bb0a338d5013d3p-1,
    -0x1.180p-21
  },
  { // Entry 24
    0x1.f220c9bfc3e5e802d3d2299f1c0cb896p-1,
    -0x1.44ap-5
  },
  { // Entry 25
    0x1.d2c416640bb58800000302d88dd4794dp-6,
    -0x1.488a5a88d8627p2
  },
  { // Entry 26
    0x1.7477fe65ed9eb801fb78e9f8195947dep-6,
    -0x1.5d60a85cec862p2
  },
  { // Entry 27
    0x1.fffffffffe01d7fb1785c9ab108f85f0p-1,
    -0x1.7p-40
  },
  { // Entry 28
    0x1.f710064ffbdf6800ff354e934260dd45p-1,
    -0x1.a04p-6
  },
  { // Entry 29
    0x1.81db2699d647e80119a5ff6578562368p-1,
    -0x1.a1ep-2
  },
  { // Entry 30
    0x1.18a82c07fc46d8033bd0fd06418f1d83p-1,
    -0x1.bc137c829fe3fp-1
  },
  { // Entry 31
    0x1.ffffd71ab8e1c7ffc23bb97e6431b6fep-1,
    -0x1.d7ffep-20
  },
  { // Entry 32
    0x1.b23dd2fbd9253801d5963064eb734a2fp-1,
    -0x1.e6b30cdff66eap-3
  },
  { // Entry 33
    0x1.9afdae5fa109f7fffb555a32c170d8b1p-32,
    -0x1.f512959c9fef8p4
  },
  { // Entry 34
    0x1.6ae5f40c2d268001595637d720fdaa90p-1,
    -0x1.fc7f1fc7f1fc8p-2
  },
  { // Entry 35
    0x1.aed49b5eb5803001fcd049a3732b31f0p-1,
    -0x1.fdfffffffffffp-3
  },
  { // Entry 36
    0x1.0000000d6a752800a91630539c6e7b0fp-1022,
    -0x1.fefffffff6529p9
  },
  { // Entry 37
    0x1.0000000c0790f7ff6249d8418e1b82c0p-1022,
    -0x1.fefffffff7529p9
  },
  { // Entry 38
    0x1.5ab07dd4854a1800e36cd5ae47a685bep-256,
    -0x1.ff1ffffffffffp7
  },
  { // Entry 39
    0x1.6a0bdc4db4d7b1f4e35e43dfc85817a7p-1,
    -0x1.fff7fffffffffp-2
  },
  { // Entry 40
    0x1.ffffffffffffffffffffffffe9d20bc1p-1,
    -0x1.fff8e61eadd48p-101
  },
  { // Entry 41
    0x1.ffd3a5705a0a3800003de8f068ba8fddp-1,
    -0x1.ffff87bffffffp-12
  },
  { // Entry 42
    0x1.fffff4e8de9f48000386a775899517eap-1,
    -0x1.ffffffff07fffp-22
  },
  { // Entry 43
    0x1.ffffd3a37bee1800966e6c9e9bb48496p-1,
    -0x1.ffffffff3ffffp-20
  },
  { // Entry 44
    0x1.0000000b561edfff7762203e6d954ab4p-1024,
    -0x1.fffffffff7d29p9
  },
  { // Entry 45
    0x1.00000004da8277ffff5d73afe24f21c3p-512,
    -0x1.fffffffff8ff7p8
  },
  { // Entry 46
    0x1.000000003851761b6d88f829becd3315p-1024,
    -0x1.ffffffffffd76p9
  },
  { // Entry 47
    0x1.000000001e533f989be7040824423450p-1024,
    -0x1.ffffffffffea2p9
  },
  { // Entry 48
    0x1.000000001111998e372040e1786d816fp-1024,
    -0x1.fffffffffff3bp9
  },
  { // Entry 49
    0x1.0000000004550915cce8b2fc4d47a539p-1024,
    -0x1.fffffffffffcep9
  },
  { // Entry 50
    0x1.0000000001fe2804e87d30cf8acc59c7p-1024,
    -0x1.fffffffffffe9p9
  },
  { // Entry 51
    0x1.0000000001205966f2b5938a5a957ce4p-1024,
    -0x1.ffffffffffff3p9
  },
  { // Entry 52
    0x1.fffffffffe9d1bd0105cdc21cead428cp-1,
    -0x1.ffffffffffffep-41
  },
  { // Entry 53
    0x1.ffffffffffa746f404171ff8a52bae95p-1,
    -0x1.ffffffffffffep-43
  },
  { // Entry 54
    0x1.0000000000162e42fefa3ae53369388cp-1024,
    -0x1.fffffffffffffp9
  },
  { // Entry 55
    0x1.p0,
    0x1.0p-1074
  },
  { // Entry 56
    0x1.6a09e667f3bcd0e0448ff2152c56bf1fp0,
    0x1.0000000000001p-1
  },
  { // Entry 57
    0x1.00000000b17217f80f4f00c1ff23da21p0,
    0x1.0000000000001p-32
  },
  { // Entry 58
    0x1.00000000b17217f80f4f434cc820f6eep0,
    0x1.0000000000007p-32
  },
  { // Entry 59
    0x1.02c9a3e7780fe800c728e7d486fcf31cp0,
    0x1.0000000003838p-6
  },
  { // Entry 60
    0x1.6a09e66cc184b000004ee13300eefeedp0,
    0x1.00000009cd189p-1
  },
  { // Entry 61
    0x1.00b1afde7b1cb801287776b699278174p0,
    0x1.000051bcd60e7p-8
  },
  { // Entry 62
    0x1.0058c89a0da927ffd4f54c7681eb068dp0,
    0x1.00007ffffffaep-9
  },
  { // Entry 63
    0x1.059b67dbb73747ffc7559f37ef913157p0,
    0x1.000ffffc0p-5
  },
  { // Entry 64
    0x1.6b14ea048ba6b4a8a77fd275a20dcb27p0,
    0x1.022p-1
  },
  { // Entry 65
    0x1.002d711c9fe27ffffff45a9e519be99fp0,
    0x1.0624de0b877a9p-10
  },
  { // Entry 66
    0x1.002d711dd65f77fffff9a30e18baff60p0,
    0x1.0624e50a0bee1p-10
  },
  { // Entry 67
    0x1.002d711f4c5b7800000671d15bb60667p0,
    0x1.0624ed76bb986p-10
  },
  { // Entry 68
    0x1.1a7c0713c14c2fffff5e7085d7140701p4,
    0x1.0916fbd16a4a4p2
  },
  { // Entry 69
    0x1.0005f0eeca476ff5746e77918f305622p0,
    0x1.1244912449101p-13
  },
  { // Entry 70
    0x1.7550685a42c638000000000000845a47p0,
    0x1.16a76ec41b516p-1
  },
  { // Entry 71
    0x1.76e219f44e8077fffbf691327e18a6a6p0,
    0x1.19c09494b839ep-1
  },
  { // Entry 72
    0x1.3738d72e851d08007f94aec04e720143p0,
    0x1.2090482412080p-2
  },
  { // Entry 73
    0x1.5ebcb0c3a5e8cfffff403cfc89af025dp2,
    0x1.3a24bc9f747a4p1
  },
  { // Entry 74
    0x1.eff948ab8687f801d8c0b52d4fd1abc4p4,
    0x1.3d104d551d81cp2
  },
  { // Entry 75
    0x1.f662aa67062f68312afcbb64ee7a0cacp19,
    0x1.3f8ffa3f6c716p4
  },
  { // Entry 76
    0x1.3dc642457d0857ff16fb3b9bc0c86814p1,
    0x1.4fd6031ce2f59p0
  },
  { // Entry 77
    0x1.0000000075571ffffe9287b8913490cap0,
    0x1.529297e4d4730p-33
  },
  { // Entry 78
    0x1.428a2f98d728980287cd19f22ba23342p0,
    0x1.555555555554fp-2
  },
  { // Entry 79
    0x1.0792c37435e5b801a9bae4219f11a6a9p0,
    0x1.588f0a4eac13ep-5
  },
  { // Entry 80
    0x1.e0eaa5e12b62b7feff0ae982bc9b0e20p2,
    0x1.746f2dac4c4aep1
  },
  { // Entry 81
    0x1.e8f597a375b908310b9fd1892b940fddp2,
    0x1.777f3eb118644p1
  },
  { // Entry 82
    0x1.e212d1cd92af580000065ae4d335fcd5p5,
    0x1.7a70623a65055p2
  },
  { // Entry 83
    0x1.6e176769832437ff0078b13791381962p1,
    0x1.841c84bf02c93p0
  },
  { // Entry 84
    0x1.0000000010e578000152b56232aab68ep0,
    0x1.86055129c133fp-36
  },
  { // Entry 85
    0x1.1f98e30b070717f047944e564fb68949p6,
    0x1.8abef85ac27cap2
  },
  { // Entry 86
    0x1.29f209f62cd1bfffffb442fc666ab002p6,
    0x1.8e0287eb30572p2
  },
  { // Entry 87
    0x1.2e6eb60fef9e9801a703d7b8b727760dp50,
    0x1.91ec7b1ec7c3dp5
  },
  { // Entry 88
    0x1.125fbee3a8f4b000006b01ac6c39fae3p0,
    0x1.999999b6966b1p-4
  },
  { // Entry 89
    0x1.125fbef60d23f7fffff990af4ad356dep0,
    0x1.99999b42b010ep-4
  },
  { // Entry 90
    0x1.2df89d68ecd817feffbc8a02489a2c31p3,
    0x1.9e7f87cd813d0p1
  },
  { // Entry 91
    0x1.7b0837a01c4bf7fffb4b24ca92057ec8p844,
    0x1.a64878765d9c6p9
  },
  { // Entry 92
    0x1.279417bd1ee58000d657c88e959aa30ap0,
    0x1.a8cp-3
  },
  { // Entry 93
    0x1.24e4cfa950d85801e4e97cf588eae855p858,
    0x1.ad18dca75151cp9
  },
  { // Entry 94
    0x1.c9d7d9b687fd58033eb56233acd2e743p858,
    0x1.ad6b5ad6b5ad6p9
  },
  { // Entry 95
    0x1.099ad18ba452580179e84b9f367c24fcp0,
    0x1.b34cc4566d0b8p-5
  },
  { // Entry 96
    0x1.75db048626cc9801fdd8328e5e7c2ed3p55,
    0x1.bc5ee5fb5abdfp5
  },
  { // Entry 97
    0x1.04eb9df9467ea8006ec2ae40fe4aa9a2p0,
    0x1.c20p-6
  },
  { // Entry 98
    0x1.7336a662f7a3080000321c761912bb4dp3,
    0x1.c49f19020be99p1
  },
  { // Entry 99
    0x1.00051180218ca7fffffa98a0aca1602bp0,
    0x1.d3f4cfa7e9e54p-14
  },
  { // Entry 100
    0x1.0000146bb81ea0003b62e3d6d908a708p0,
    0x1.d76p-20
  },
  { // Entry 101
    0x1.e7ede8155f4148013c4232abc7194d4dp0,
    0x1.dc6e371b8dcp-1
  },
  { // Entry 102
    0x1.e96b5624c8f3e80004759e1237e298dfp1,
    0x1.ef57627bcd18dp0
  },
  { // Entry 103
    0x1.661bd0e767ee37ffff6f19dcbf13f733p0,
    0x1.efe02bcccc3e0p-2
  },
  { // Entry 104
    0x1.0b216e27ad0157ffb7b07aee744bc64bp0,
    0x1.f70p-5
  },
  { // Entry 105
    0x1.fbda9b237a1437feffee12944ccc2abep1,
    0x1.fcff3fcff3fccp0
  },
  { // Entry 106
    0x1.f0f5d9e1ab4cc825f655007e8ce8352fp7,
    0x1.fd3f46397c92cp2
  },
  { // Entry 107
    0x1.fc52e836980af7fffb69887832df36bep1,
    0x1.fd56b236e47b0p0
  },
  { // Entry 108
    0x1.fe974a46f07b082d32ce3627adbe734bp1,
    0x1.fefb71b3e5192p0
  },
  { // Entry 109
    0x1.30558126879a682ff3f16fbfef12a959p0,
    0x1.fefffffffffffp-3
  },
  { // Entry 110
    0x1.ea4afa2a3e59980143381c0d66f06241p511,
    0x1.ffeffffffff7fp8
  },
  { // Entry 111
    0x1.ffd9308364f08f6f2617da7d0b994aeep1023,
    0x1.fffff1fffffffp9
  },
  { // Entry 112
    0x1.ffffffffaa55e7ffffaa8e6b5f871352p0,
    0x1.ffffffff84699p-1
  },
  { // Entry 113
    0x1.p0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 114
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1,
    -0x1.0p-1
  },
  { // Entry 115
    0x1.7b29358d41a6466f059badebc0f3ef2ap-1,
    -0x1.bbbbbbbbbbbbcp-2
  },
  { // Entry 116
    0x1.8d17d2b770067dd0b560997d709462f2p-1,
    -0x1.7777777777778p-2
  },
  { // Entry 117
    0x1.9fdf8bcce533d3850499cd91b4fe1b45p-1,
    -0x1.3333333333334p-2
  },
  { // Entry 118
    0x1.b38aa5682153ea10ec6aaf03b1e19a17p-1,
    -0x1.ddddddddddde0p-3
  },
  { // Entry 119
    0x1.c823e074ec128dd3e5a22665f53de430p-1,
    -0x1.5555555555558p-3
  },
  { // Entry 120
    0x1.ddb680117ab119ddf7de23abf70a974ap-1,
    -0x1.999999999999fp-4
  },
  { // Entry 121
    0x1.f44e4fb6c55d6f8461f0c24a6561e8cfp-1,
    -0x1.111111111111cp-5
  },
  { // Entry 122
    0x1.05fbd4d5b4d597517f2f14990c7c1d74p0,
    0x1.1111111111106p-5
  },
  { // Entry 123
    0x1.125fbee250663e39a600925ecaf87e7ap0,
    0x1.9999999999994p-4
  },
  { // Entry 124
    0x1.1f59ac3c7d6bf83c0aac08f864d917a0p0,
    0x1.5555555555552p-3
  },
  { // Entry 125
    0x1.2cf0b5245e8f288fd79fb13137352d3cp0,
    0x1.ddddddddddddap-3
  },
  { // Entry 126
    0x1.3b2c47bff8328699545ebbc1b8224569p0,
    0x1.3333333333331p-2
  },
  { // Entry 127
    0x1.4a142c2b2e71dbfc2b446735ddfe02fep0,
    0x1.7777777777775p-2
  },
  { // Entry 128
    0x1.59b088b8f29ed26e4afc853d2242f3dcp0,
    0x1.bbbbbbbbbbbb9p-2
  },
  { // Entry 129
    0x1.6a09e667f3bcbd45589bc56188452388p0,
    0x1.ffffffffffffdp-2
  },
  { // Entry 130
    0x1.p48,
    0x1.8p5
  },
  { // Entry 131
    0x1.51cb453b953666ae8a73c377e704a131p48,
    0x1.8333333333333p5
  },
  { // Entry 132
    0x1.bdb8cdadbe110aebd2ba26668f1a053fp48,
    0x1.8666666666666p5
  },
  { // Entry 133
    0x1.2611186bae6654d144153826a8cbde6ap49,
    0x1.8999999999999p5
  },
  { // Entry 134
    0x1.8406003b2ae41864a49eea54994df36fp49,
    0x1.8ccccccccccccp5
  },
  { // Entry 135
    0x1.fffffffffffd3a37a020b8c4054cb869p49,
    0x1.8ffffffffffffp5
  },
  { // Entry 136
    0x1.51cb453b953492665c6d2fb15083f6e2p50,
    0x1.9333333333332p5
  },
  { // Entry 137
    0x1.bdb8cdadbe0ea104fa428cab0d5125a2p50,
    0x1.9666666666665p5
  },
  { // Entry 138
    0x1.2611186bae64bd27820627b1e4c3f179p51,
    0x1.9999999999998p5
  },
  { // Entry 139
    0x1.8406003b2ae1fe7a7a4c90ae9e7a858ep51,
    0x1.9cccccccccccbp5
  },
  { // Entry 140
    0x1.fffffffffffa746f4041718be29130c3p51,
    0x1.9fffffffffffep5
  },
  { // Entry 141
    0x1.p-52,
    -0x1.ap5
  },
  { // Entry 142
    0x1.51cb453b953666ae8a73c377e704a131p-52,
    -0x1.9cccccccccccdp5
  },
  { // Entry 143
    0x1.bdb8cdadbe110aebd2ba26668f1a053fp-52,
    -0x1.999999999999ap5
  },
  { // Entry 144
    0x1.2611186bae6654d144153826a8cbde6ap-51,
    -0x1.9666666666667p5
  },
  { // Entry 145
    0x1.8406003b2ae41864a49eea54994df36fp-51,
    -0x1.9333333333334p5
  },
  { // Entry 146
    0x1.fffffffffffd3a37a020b8c4054cb869p-51,
    -0x1.9000000000001p5
  },
  { // Entry 147
    0x1.51cb453b953492665c6d2fb15083f6e2p-50,
    -0x1.8cccccccccccep5
  },
  { // Entry 148
    0x1.bdb8cdadbe0ea104fa428cab0d5125a2p-50,
    -0x1.899999999999bp5
  },
  { // Entry 149
    0x1.2611186bae64bd27820627b1e4c3f179p-49,
    -0x1.8666666666668p5
  },
  { // Entry 150
    0x1.8406003b2ae1fe7a7a4c90ae9e7a858ep-49,
    -0x1.8333333333335p5
  },
  { // Entry 151
    0x1.fffffffffffa746f4041718be29130c3p-49,
    -0x1.8000000000002p5
  },
  { // Entry 152
    0x1.p768,
    0x1.8p9
  },
  { // Entry 153
    0x1.p-896,
    -0x1.cp9
  },
  { // Entry 154
    HUGE_VAL,
    0x1.4p12
  },
  { // Entry 155
    0.0,
    -0x1.6p12
  },
  { // Entry 156
    0x1.ffffffffffd3a37a020b8e0d90ed7f3fp1023,
    0x1.fffffffffffffp9
  },
  { // Entry 157
    0x1.p-1074,
    -0x1.0c8p10
  },
  { // Entry 158
    0x1.ffffffffffa746f404171ff3199aeed7p-1025,
    -0x1.0000000000001p10
  },
  { // Entry 159
    0x1.p-1024,
    -0x1.0p10
  },
  { // Entry 160
    0x1.0000000000162e42fefa3ae53369388cp-1024,
    -0x1.fffffffffffffp9
  },
  { // Entry 161
    0x1.ffffffffffd3a37a020b8e0d90ed7f3fp-513,
    -0x1.0000000000001p9
  },
  { // Entry 162
    0x1.p-512,
    -0x1.0p9
  },
  { // Entry 163
    0x1.00000000000b17217f7d1d351a389d40p-512,
    -0x1.fffffffffffffp8
  },
  { // Entry 164
    0x1.ffffffffffe9d1bd0105c68bc97ec194p-257,
    -0x1.0000000000001p8
  },
  { // Entry 165
    0x1.p-256,
    -0x1.0p8
  },
  { // Entry 166
    0x1.0000000000058b90bfbe8e8b2d3d4edep-256,
    -0x1.fffffffffffffp7
  },
  { // Entry 167
    0x1.fffffffffff4e8de8082e32725016147p-129,
    -0x1.0000000000001p7
  },
  { // Entry 168
    0x1.p-128,
    -0x1.0p7
  },
  { // Entry 169
    0x1.000000000002c5c85fdf4741bea6e77fp-128,
    -0x1.fffffffffffffp6
  },
  { // Entry 170
    0x1.fffffffffffa746f4041718be29130c3p-65,
    -0x1.0000000000001p6
  },
  { // Entry 171
    0x1.p-64,
    -0x1.0p6
  },
  { // Entry 172
    0x1.00000000000162e42fefa39fe95583c3p-64,
    -0x1.fffffffffffffp5
  },
  { // Entry 173
    0x1.fffffffffffd3a37a020b8c4054cb869p-33,
    -0x1.0000000000001p5
  },
  { // Entry 174
    0x1.p-32,
    -0x1.0p5
  },
  { // Entry 175
    0x1.000000000000b17217f7d1cfb72b45e2p-32,
    -0x1.fffffffffffffp4
  },
  { // Entry 176
    0x1.fffffffffffe9d1bd0105c6187a76436p-17,
    -0x1.0000000000001p4
  },
  { // Entry 177
    0x1.p-16,
    -0x1.0p4
  },
  { // Entry 178
    0x1.00000000000058b90bfbe8e7cc35c3f1p-16,
    -0x1.fffffffffffffp3
  },
  { // Entry 179
    0x1.ffffffffffff4e8de8082e30a513f41bp-9,
    -0x1.0000000000001p3
  },
  { // Entry 180
    0x1.p-8,
    -0x1.0p3
  },
  { // Entry 181
    0x1.0000000000002c5c85fdf473e242ea38p-8,
    -0x1.fffffffffffffp2
  },
  { // Entry 182
    0x1.ffffffffffffa746f40417184ada0a8ep-5,
    -0x1.0000000000001p2
  },
  { // Entry 183
    0x1.p-4,
    -0x1.0p2
  },
  { // Entry 184
    0x1.000000000000162e42fefa39f02b772cp-4,
    -0x1.fffffffffffffp1
  },
  { // Entry 185
    0x1.ffffffffffffd3a37a020b8c23810967p-3,
    -0x1.0000000000001p1
  },
  { // Entry 186
    0x1.p-2,
    -0x1.0p1
  },
  { // Entry 187
    0x1.0000000000000b17217f7d1cf7d83c1ap-2,
    -0x1.fffffffffffffp0
  },
  { // Entry 188
    0x1.ffffffffffffe9d1bd0105c6114585bbp-2,
    -0x1.0000000000001p0
  },
  { // Entry 189
    0x1.p-1,
    -0x1.0p0
  },
  { // Entry 190
    0x1.000000000000058b90bfbe8e7bdcbe2ep-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 191
    0x1.ffffffffffe9d1bd0105c68bc97ec194p511,
    0x1.fffffffffffffp8
  },
  { // Entry 192
    0x1.p512,
    0x1.0p9
  },
  { // Entry 193
    0x1.0000000000162e42fefa3ae53369388cp512,
    0x1.0000000000001p9
  },
  { // Entry 194
    0x1.fffffffffff4e8de8082e32725016147p255,
    0x1.fffffffffffffp7
  },
  { // Entry 195
    0x1.p256,
    0x1.0p8
  },
  { // Entry 196
    0x1.00000000000b17217f7d1d351a389d40p256,
    0x1.0000000000001p8
  },
  { // Entry 197
    0x1.fffffffffffa746f4041718be29130c3p127,
    0x1.fffffffffffffp6
  },
  { // Entry 198
    0x1.p128,
    0x1.0p7
  },
  { // Entry 199
    0x1.0000000000058b90bfbe8e8b2d3d4edep128,
    0x1.0000000000001p7
  },
  { // Entry 200
    0x1.fffffffffffd3a37a020b8c4054cb869p63,
    0x1.fffffffffffffp5
  },
  { // Entry 201
    0x1.p64,
    0x1.0p6
  },
  { // Entry 202
    0x1.000000000002c5c85fdf4741bea6e77fp64,
    0x1.0000000000001p6
  },
  { // Entry 203
    0x1.fffffffffffe9d1bd0105c6187a76436p31,
    0x1.fffffffffffffp4
  },
  { // Entry 204
    0x1.p32,
    0x1.0p5
  },
  { // Entry 205
    0x1.00000000000162e42fefa39fe95583c3p32,
    0x1.0000000000001p5
  },
  { // Entry 206
    0x1.ffffffffffff4e8de8082e30a513f41bp15,
    0x1.fffffffffffffp3
  },
  { // Entry 207
    0x1.p16,
    0x1.0p4
  },
  { // Entry 208
    0x1.000000000000b17217f7d1cfb72b45e2p16,
    0x1.0000000000001p4
  },
  { // Entry 209
    0x1.ffffffffffffa746f40417184ada0a8ep7,
    0x1.fffffffffffffp2
  },
  { // Entry 210
    0x1.p8,
    0x1.0p3
  },
  { // Entry 211
    0x1.00000000000058b90bfbe8e7cc35c3f1p8,
    0x1.0000000000001p3
  },
  { // Entry 212
    0x1.ffffffffffffd3a37a020b8c23810967p3,
    0x1.fffffffffffffp1
  },
  { // Entry 213
    0x1.p4,
    0x1.0p2
  },
  { // Entry 214
    0x1.0000000000002c5c85fdf473e242ea38p4,
    0x1.0000000000001p2
  },
  { // Entry 215
    0x1.ffffffffffffe9d1bd0105c6114585bbp1,
    0x1.fffffffffffffp0
  },
  { // Entry 216
    0x1.p2,
    0x1.0p1
  },
  { // Entry 217
    0x1.000000000000162e42fefa39f02b772cp2,
    0x1.0000000000001p1
  },
  { // Entry 218
    0x1.fffffffffffff4e8de8082e30884031fp0,
    0x1.fffffffffffffp-1
  },
  { // Entry 219
    0x1.p1,
    0x1.0p0
  },
  { // Entry 220
    0x1.0000000000000b17217f7d1cf7d83c1ap1,
    0x1.0000000000001p0
  },
  { // Entry 221
    0x1.6a09e667f3bcc131216634b8a8ffb7b0p-1,
    -0x1.0000000000001p-1
  },
  { // Entry 222
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1,
    -0x1.0p-1
  },
  { // Entry 223
    0x1.6a09e667f3bcccf47bc582be0b70aea4p-1,
    -0x1.fffffffffffffp-2
  },
  { // Entry 224
    0x1.ae89f995ad3ad13ebe2fd437cdc4d86bp-1,
    -0x1.0000000000001p-2
  },
  { // Entry 225
    0x1.ae89f995ad3ad5e8734d1773205a7fbcp-1,
    -0x1.0p-2
  },
  { // Entry 226
    0x1.ae89f995ad3ad83d4ddbb910c9aa2c84p-1,
    -0x1.fffffffffffffp-3
  },
  { // Entry 227
    0x1.d5818dcfba486fd2c0b58591353e1431p-1,
    -0x1.0000000000001p-3
  },
  { // Entry 228
    0x1.d5818dcfba48725da05aeb66e0dca9f5p-1,
    -0x1.0p-3
  },
  { // Entry 229
    0x1.d5818dcfba4873a3102d9e51b6ad4734p-1,
    -0x1.fffffffffffffp-4
  },
  { // Entry 230
    0x1.ea4afa2a490d97051edfd6f5de84f1fep-1,
    -0x1.0000000000001p-4
  },
  { // Entry 231
    0x1.ea4afa2a490d9858f73a18f5db301f86p-1,
    -0x1.0p-4
  },
  { // Entry 232
    0x1.ea4afa2a490d9902e36739f5d9860ea0p-1,
    -0x1.fffffffffffffp-5
  },
  { // Entry 233
    0x1.f50765b6e45405c75396b27147029cc0p-1,
    -0x1.0000000000001p-5
  },
  { // Entry 234
    0x1.f50765b6e4540674f84b762862baff99p-1,
    -0x1.0p-5
  },
  { // Entry 235
    0x1.f50765b6e45406cbcaa5d803f0974796p-1,
    -0x1.fffffffffffffp-6
  },
  { // Entry 236
    0x1.fa7c1819e90d8291461c9eac38e21676p-1,
    -0x1.0000000000001p-6
  },
  { // Entry 237
    0x1.fa7c1819e90d82e90a7e74b263c1dc06p-1,
    -0x1.0p-6
  },
  { // Entry 238
    0x1.fa7c1819e90d8314ecaf5fb57931c482p-1,
    -0x1.fffffffffffffp-7
  },
  { // Entry 239
    0x1.fd3c22b8f71f106b3c73a454f80c00ecp-1,
    -0x1.0000000000001p-7
  },
  { // Entry 240
    0x1.fd3c22b8f71f10975ba4b32bcf3a5e12p-1,
    -0x1.0p-7
  },
  { // Entry 241
    0x1.fd3c22b8f71f10ad6b3d3a973ad18e15p-1,
    -0x1.fffffffffffffp-8
  },
  { // Entry 242
    0x1.fe9d96b2a23d9134414ed15eb175bc62p-1,
    -0x1.0000000000001p-8
  },
  { // Entry 243
    0x1.fe9d96b2a23d914a6037442fde31baf8p-1,
    -0x1.0p-8
  },
  { // Entry 244
    0x1.fe9d96b2a23d91556fab7d98748fba9fp-1,
    -0x1.fffffffffffffp-9
  },
  { // Entry 245
    0x1.ff4eaca4391b5d982b2a046646772a87p-1,
    -0x1.0000000000001p-9
  },
  { // Entry 246
    0x1.ff4eaca4391b5da33e743691f7298b12p-1,
    -0x1.0p-9
  },
  { // Entry 247
    0x1.ff4eaca4391b5da8c8194fa7cf82bb6ep-1,
    -0x1.fffffffffffffp-10
  },
  { // Entry 248
    0x1.ffa74ea381efc2121cd91a3e6475a7d8p-1,
    -0x1.0000000000001p-10
  },
  { // Entry 249
    0x1.ffa74ea381efc217a773f15c025f7c0dp-1,
    -0x1.0p-10
  },
  { // Entry 250
    0x1.ffa74ea381efc21a6cc15cead154662dp-1,
    -0x1.fffffffffffffp-11
  },
  { // Entry 251
    0x1.fff4e8fd40080cc795b0e5e46a91f0ffp-1,
    -0x1.0000000000001p-13
  },
  { // Entry 252
    0x1.fff4e8fd40080cc8471f25ef2480b00bp-1,
    -0x1.0p-13
  },
  { // Entry 253
    0x1.fff4e8fd40080cc89fd645f481780f90p-1,
    -0x1.fffffffffffffp-14
  },
  { // Entry 254
    0x1.6a09e667f3bcc51cea30a40fc9c52aecp0,
    0x1.fffffffffffffp-2
  },
  { // Entry 255
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p-1
  },
  { // Entry 256
    0x1.6a09e667f3bcd0e0448ff2152c56bf1fp0,
    0x1.0000000000001p-1
  },
  { // Entry 257
    0x1.306fe0a31b7151388348ff0de074c5a3p0,
    0x1.fffffffffffffp-3
  },
  { // Entry 258
    0x1.306fe0a31b7152de8d5a46305c85edecp0,
    0x1.0p-2
  },
  { // Entry 259
    0x1.306fe0a31b71562aa17cd47554af19b4p0,
    0x1.0000000000001p-2
  },
  { // Entry 260
    0x1.172b83c7d517ad0c7647240cbf259d0dp0,
    0x1.fffffffffffffp-4
  },
  { // Entry 261
    0x1.172b83c7d517adcdf7c8c50eb14a7920p0,
    0x1.0p-3
  },
  { // Entry 262
    0x1.172b83c7d517af50facc07129595c3a8p0,
    0x1.0000000000001p-3
  },
  { // Entry 263
    0x1.0b5586cf9890f5cce4ef0d92edf98f81p0,
    0x1.fffffffffffffp-5
  },
  { // Entry 264
    0x1.0b5586cf9890f6298b92b71842a98364p0,
    0x1.0p-4
  },
  { // Entry 265
    0x1.0b5586cf9890f6e2d8da0a22ec09cb7dp0,
    0x1.0000000000001p-4
  },
  { // Entry 266
    0x1.059b0d31585743812721a46bbd07f042p0,
    0x1.fffffffffffffp-6
  },
  { // Entry 267
    0x1.059b0d31585743ae7c548eb68ca417fep0,
    0x1.0p-5
  },
  { // Entry 268
    0x1.059b0d315857440926ba634c2bdc7f06p0,
    0x1.0000000000001p-5
  },
  { // Entry 269
    0x1.02c9a3e778060ed08bb2bf3a4c4bffddp0,
    0x1.fffffffffffffp-7
  },
  { // Entry 270
    0x1.02c9a3e778060ee6f7caca4f7a29bde9p0,
    0x1.0p-6
  },
  { // Entry 271
    0x1.02c9a3e778060f13cffae079d5e53fd5p0,
    0x1.0000000000001p-6
  },
  { // Entry 272
    0x1.0163da9fb33356cd23daa2a4de92b010p0,
    0x1.fffffffffffffp-8
  },
  { // Entry 273
    0x1.0163da9fb33356d84a66ae336dcdfa40p0,
    0x1.0p-7
  },
  { // Entry 274
    0x1.0163da9fb33356ee977ec5508c449011p0,
    0x1.0000000000001p-7
  },
  { // Entry 275
    0x1.00b1afa5abcbed5b9a41071a509ceaf7p0,
    0x1.fffffffffffffp-9
  },
  { // Entry 276
    0x1.00b1afa5abcbed6129ab13ec11dc9544p0,
    0x1.0p-8
  },
  { // Entry 277
    0x1.00b1afa5abcbed6c487f2d8f945bea39p0,
    0x1.0000000000001p-8
  },
  { // Entry 278
    0x1.0058c86da1c09e9f385b4a201180af89p0,
    0x1.fffffffffffffp-10
  },
  { // Entry 279
    0x1.0058c86da1c09ea1ff19d294cf2f679cp0,
    0x1.0p-9
  },
  { // Entry 280
    0x1.0058c86da1c09ea78c96e37e4a8cd7d8p0,
    0x1.0000000000001p-9
  },
  { // Entry 281
    0x1.002c605e2e8cec4f0a000b089708b90dp0,
    0x1.fffffffffffffp-11
  },
  { // Entry 282
    0x1.002c605e2e8cec506d21bfc89a23a010p0,
    0x1.0p-10
  },
  { // Entry 283
    0x1.002c605e2e8cec5333652948a0596e1cp0,
    0x1.0000000000001p-10
  },
  { // Entry 284
    0x1.00058ba01fb9f96d404f58b2f213c6ccp0,
    0x1.fffffffffffffp-14
  },
  { // Entry 285
    0x1.00058ba01fb9f96d6cacd4b180917c3ep0,
    0x1.0p-13
  },
  { // Entry 286
    0x1.00058ba01fb9f96dc567ccae9d8ce721p0,
    0x1.0000000000001p-13
  },
  { // Entry 287
    0.0,
    -0x1.0c80000000001p10
  },
  { // Entry 288
    0x1.p-1074,
    -0x1.0c8p10
  },
  { // Entry 289
    0x1.00000000002c5c85fdf477b662b26945p-1074,
    -0x1.0c7ffffffffffp10
  },
  { // Entry 290
    0.0,
    -0x1.0cc0000000001p10
  },
  { // Entry 291
    0.0,
    -0x1.0ccp10
  },
  { // Entry 292
    0.0,
    -0x1.0cbffffffffffp10
  },
  { // Entry 293
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 294
    0.0,
    -HUGE_VAL
  },
  { // Entry 295
    HUGE_VAL,
    0x1.fffffffffffffp1023
  },
  { // Entry 296
    0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 297
    0x1.1a6637e666f82e1bf9bdc293e110c586p3,
    0x1.921fb54442d18p1
  },
  { // Entry 298
    0x1.d0231bd5e9cfd1c56d8c57fb9adc16e1p-4,
    -0x1.921fb54442d18p1
  },
  { // Entry 299
    0x1.7c3f73e5e9df4955e51db2c96c4cd483p1,
    0x1.921fb54442d18p0
  },
  { // Entry 300
    0x1.58b3940afed165e46fbb76d0cb01dd87p-2,
    -0x1.921fb54442d18p0
  },
  { // Entry 301
    0x1.0000000000000b17217f7d1cf7d83c1ap1,
    0x1.0000000000001p0
  },
  { // Entry 302
    0x1.ffffffffffffe9d1bd0105c6114585bbp-2,
    -0x1.0000000000001p0
  },
  { // Entry 303
    0x1.p1,
    0x1.0p0
  },
  { // Entry 304
    0x1.p-1,
    -0x1.0p0
  },
  { // Entry 305
    0x1.fffffffffffff4e8de8082e30884031fp0,
    0x1.fffffffffffffp-1
  },
  { // Entry 306
    0x1.000000000000058b90bfbe8e7bdcbe2ep-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 307
    0x1.b93bbf8582e129341e24ff465142adfap0,
    0x1.921fb54442d18p-1
  },
  { // Entry 308
    0x1.290ee6a5e83cf78da063060a3f50cc7fp-1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 309
    0x1.p0,
    0x1.0p-1022
  },
  { // Entry 310
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1022
  },
  { // Entry 311
    0x1.p0,
    0x1.0000000000001p-1022
  },
  { // Entry 312
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0000000000001p-1022
  },
  { // Entry 313
    0x1.p0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 314
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 315
    0x1.p0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 316
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 317
    0x1.p0,
    0x1.0p-1073
  },
  { // Entry 318
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1073
  },
  { // Entry 319
    0x1.p0,
    0x1.0p-1074
  },
  { // Entry 320
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074
  },
  { // Entry 321
    0x1.p0,
    0.0
  },
  { // Entry 322
    0x1.p0,
    -0.0
  },
  { // Entry 323
    0x1.ffffffffffd3a37a020b8e0d90ed7f3fp1023,
    0x1.fffffffffffffp9
  },
  { // Entry 324
    HUGE_VAL,
    0x1.0p10
  },
  { // Entry 325
    0x1.p-1022,
    -0x1.ff0p9
  },
  { // Entry 326
    0x1.ffffffffffd3a37a020b8e0d90ed7f3fp-1023,
    -0x1.ff00000000001p9
  },
  { // Entry 327
    0x1.p125,
    0x1.f40p6
  },
  { // Entry 328
    0x1.p-125,
    -0x1.f40p6
  },
  { // Entry 329
    0x1.p2,
    0x1.0p1
  },
  { // Entry 330
    0x1.p-2,
    -0x1.0p1
  }
};
```
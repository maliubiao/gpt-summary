Response:
Let's break down the thought process for answering this complex request.

1. **Understanding the Core Request:** The central task is to analyze the provided C code snippet, which is a data array named `g_acos_intel_data`. The prompt asks for its function, relation to Android, implementation details, dynamic linking aspects, usage examples, debugging methods, and connections to the Android framework/NDK.

2. **Initial Code Inspection:**  The first step is to quickly read through the code. Key observations:
    * It's a `static` array of a custom struct `data_1_1_t`.
    * The struct holds two `double` values.
    * The array is named `g_acos_intel_data` and resides in the `bionic/tests/math_data/` directory.
    * The copyright notice indicates it's part of the Android Open Source Project.

3. **Deducing the Functionality:** Based on the name, data types, and location, the most logical conclusion is that this array contains test data for the `acos` (arccosine) function. The two `double` values likely represent input and expected output pairs for testing the accuracy of the `acos` implementation. The "intel_data" part might suggest it was generated or validated against Intel's `acos` implementation.

4. **Relating to Android:**  Since it's in the `bionic` directory, and `bionic` is Android's C library, this data is directly used for testing the `acos` function within Android's math library (`libm`). This is crucial for ensuring the correctness of mathematical operations on Android devices.

5. **Implementation Details of `acos` (libc function):**  This requires some general knowledge of how mathematical functions are implemented in `libc`. The core idea involves:
    * **Range Reduction:** Transforming the input to a smaller, manageable range (often [-1, 1] for `acos`).
    * **Polynomial Approximation:**  Using a polynomial to approximate the function in the reduced range. Common techniques include Chebyshev polynomials or minimax approximations.
    * **Error Handling:**  Dealing with invalid inputs (e.g., values outside [-1, 1]).
    * **Edge Cases:** Handling special values like -1, 0, and 1.

6. **Dynamic Linker (if applicable):**  While the provided code itself doesn't directly involve dynamic linking, it's important to consider how `libm` (where `acos` resides) is linked.
    * **SO Layout:** Describe a typical `.so` structure (ELF header, code, data, symbol table, etc.).
    * **Linking Process:** Explain the steps involved (symbol resolution, relocation). Since the code is a static data array, it would be placed in the `.data` or `.rodata` section of `libm.so`. The `acos` function in `libm.so` would access this data during its execution (although the provided code is *test* data, not the `acos` implementation itself).

7. **Logical Reasoning and Examples:** Provide concrete examples of input and expected output based on the data in the array. For instance, taking the first entry, the input is `0x1.c8a538ae83d1f7ffffffffffffcef091p-1` and the expected output is `0x1.4182199998587p-1`. Explain that these are hexadecimal floating-point representations.

8. **Common Usage Errors:**  Think about how a programmer might misuse the `acos` function:
    * Passing values outside the [-1, 1] range.
    * Assuming perfect precision (floating-point errors can occur).

9. **Android Framework/NDK Connection and Frida Hooking:** This requires tracing the execution flow.
    * **Framework:**  A high-level framework component (e.g., an animation or graphics rendering) might indirectly call a native method via JNI.
    * **NDK:** An NDK developer would directly call `acos` from their C/C++ code.
    * **Reaching the Data:** Explain that when `acos` is called, the underlying implementation in `libm.so` might use data structures (like lookup tables or coefficients) that could be similar in nature to the provided test data, though not necessarily this exact array.
    * **Frida Hook:** Provide a Frida script to hook the `acos` function. This demonstrates how to intercept calls and inspect arguments and return values, which can be helpful for debugging or understanding the function's behavior.

10. **Structuring the Answer:** Organize the information logically using headings and subheadings to make it easy to read and understand. Use clear and concise language. Explain technical terms where necessary.

11. **Review and Refinement:**  Read through the entire answer to ensure accuracy, completeness, and clarity. Correct any errors or omissions. Make sure all parts of the original request are addressed. For example, initially, I might focus too much on the `acos` implementation and forget to explicitly state that the provided code is *test data*. Reviewing helps catch such issues.

This step-by-step approach, starting with basic code analysis and gradually delving into more complex aspects like dynamic linking and debugging, is crucial for tackling such a comprehensive question. The key is to break down the problem into smaller, manageable parts and connect them logically.
## 对 bionic/tests/math_data/acos_intel_data.handroid 的分析

你提供的文件 `bionic/tests/math_data/acos_intel_data.handroid` 是 Android Bionic 库中用于测试 `acos` (反余弦) 函数的数据文件。它包含了一系列预定义的输入和预期输出值对，用于验证 `acos` 函数在不同输入下的精度和正确性。

**功能:**

该文件的主要功能是为 Bionic 的 `acos` 函数提供测试数据。具体来说，它：

1. **定义测试用例：**  `g_acos_intel_data` 数组中的每一个元素都是一个测试用例。每个测试用例包含一个 `double` 类型的输入值 (即 `acos` 函数的参数) 和一个预期的 `double` 类型的输出值 (即 `acos` 函数应该返回的结果)。
2. **覆盖不同的输入范围：** 数据中的输入值覆盖了 `acos` 函数定义域 [-1, 1] 的不同部分，包括边界值、正常值以及一些特殊值。这有助于全面测试 `acos` 函数在各种情况下的表现。
3. **提供精度验证的基准：**  预期输出值通常是通过高精度计算或其他可靠的 `acos` 实现获得的，作为验证 Bionic `acos` 函数精度的标准。
4. **自动化测试：** 这些数据可以被集成到 Bionic 的自动化测试框架中。测试程序会读取这些输入值，调用 Bionic 的 `acos` 函数，并将实际输出与预期输出进行比较，以判断 `acos` 函数是否正确工作。

**与 Android 功能的关系及举例说明:**

`acos` 函数是 C 标准库 `<math.h>` 中的一个函数，属于 Android 系统基础库 Bionic 的一部分。它在 Android 的各种功能中都有广泛应用，尤其是在涉及到角度计算的场景中：

* **图形渲染 (Graphics Rendering):** 在 2D 或 3D 图形渲染中，计算向量之间的夹角、旋转角度等都需要用到 `acos` 函数。例如，在 OpenGL ES 中，可能需要使用 `acos` 来计算光照角度或动画插值。
* **物理模拟 (Physics Simulation):**  在游戏开发或物理引擎中，计算物体运动轨迹、碰撞角度等会使用到 `acos`。例如，计算两个碰撞物体的法向量夹角来确定反弹方向。
* **传感器数据处理 (Sensor Data Processing):**  处理来自加速度计、陀螺仪等传感器的原始数据时，可能需要使用 `acos` 将向量转换成角度。例如，计算设备相对于水平面的倾斜角度。
* **地理位置计算 (Geolocation Calculation):** 在地图应用中，计算两个地理坐标之间的方位角可能需要用到 `acos`。

**举例说明:** 假设一个 Android 应用需要计算用户触摸屏幕的点与屏幕中心点之间的角度。这需要计算两个向量之间的夹角，而计算向量夹角就需要用到 `acos` 函数。

**详细解释 libc 函数 `acos` 的功能是如何实现的:**

`acos` 函数的实现通常涉及以下步骤：

1. **输入检查和范围缩减:**
   - 检查输入 `x` 是否在 [-1, 1] 的有效范围内。如果超出范围，则设置 `errno` 为 `EDOM` (domain error) 并返回 NaN (Not a Number)。
   - 对于一些特殊输入值，可以直接返回结果：
     - 如果 `x` 为 1，则返回 0。
     - 如果 `x` 为 -1，则返回 π。
     - 如果 `x` 为 0，则返回 π/2。

2. **处理绝对值接近 1 的情况:** 当 `|x|` 非常接近 1 时，直接使用 `acos(x)` 计算可能会损失精度。为了提高精度，可以利用以下恒等式进行转换：
   - 如果 `x` 接近 1，可以使用 `acos(x) = 2 * asin(sqrt((1 - x) / 2))`。
   - 如果 `x` 接近 -1，可以使用 `acos(x) = π - 2 * asin(sqrt((1 + x) / 2))`。
   其中 `asin` 是反正弦函数，`sqrt` 是平方根函数。

3. **使用泰勒级数或其他近似方法:** 对于一般的 `x` 值，`acos` 函数通常使用泰勒级数展开或其他多项式近似方法来计算。例如，可以使用以下级数展开：
   ```
   acos(x) = π/2 - arcsin(x)
   arcsin(x) = x + (1/2) * (x^3/3) + (1*3)/(2*4) * (x^5/5) + (1*3*5)/(2*4*6) * (x^7/7) + ...
   ```
   为了提高收敛速度和精度，通常会对输入 `x` 进行变换，例如使用变量替换。

4. **查表法 (Lookup Table):** 在一些实现中，为了提高性能，可能会预先计算一部分 `acos` 的值并存储在查找表中。对于给定的输入，可以先在查找表中找到近似值，然后使用插值或其他方法进行微调。

5. **组合使用多种方法:**  为了在不同输入范围内获得最佳的精度和性能，实际的 `acos` 实现可能会组合使用多种方法。例如，对于接近边界的值使用特殊处理，对于中间范围的值使用多项式近似，并可能辅以查找表。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

尽管 `acos_intel_data.handroid` 文件本身不直接涉及动态链接，但 `acos` 函数的实现代码位于 `libm.so` (math library) 中，它是一个共享库，需要通过动态链接器来加载和链接。

**`libm.so` 布局样本 (简化):**

```
libm.so:
  ELF Header:
    ...
  Program Headers:
    LOAD: [内存加载地址] [文件偏移] [大小] [权限: R_E (可读可执行)]
    LOAD: [内存加载地址] [文件偏移] [大小] [权限: R_W (可读可写)]
    DYNAMIC: ...
  Section Headers:
    .text: [代码段]
    .rodata: [只读数据段，例如包含数学常数和查找表]
    .data: [可读写数据段]
    .bss: [未初始化数据段]
    .symtab: [符号表]
    .strtab: [字符串表]
    .dynsym: [动态符号表]
    .dynstr: [动态字符串表]
    .rel.dyn: [动态重定位表]
    .rel.plt: [PLT 重定位表]
    ...
```

在这个布局中：

* **`.text` 段:** 包含 `acos` 函数的机器码指令。
* **`.rodata` 段:** 可能包含 `acos` 实现中使用的常量 (如 π/2) 或查找表。
* **`.symtab` 和 `.dynsym`:**  包含符号信息，例如 `acos` 函数的名称和地址。动态符号表 `.dynsym` 用于动态链接。

**链接的处理过程:**

1. **加载:** 当一个 Android 应用启动或加载一个依赖于 `libm.so` 的共享库时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责加载 `libm.so` 到内存中。

2. **符号解析 (Symbol Resolution):**  如果应用代码或依赖库中调用了 `acos` 函数，动态链接器会查找 `libm.so` 的动态符号表 `.dynsym`，找到 `acos` 符号对应的地址。

3. **重定位 (Relocation):** 由于共享库被加载到内存的地址可能不是编译时的预定地址，动态链接器需要修改代码和数据中的地址引用，使其指向正确的内存位置。例如，如果 `acos` 函数内部引用了 `.rodata` 段中的某个常量，这个引用需要被重定位。

4. **绑定 (Binding):**  对于延迟绑定的符号 (通过 PLT - Procedure Linkage Table 实现)，第一次调用 `acos` 时，会通过 PLT 跳转到链接器，由链接器完成符号解析和地址绑定。后续调用会直接跳转到 `acos` 的实际地址。

**假设输入与输出 (逻辑推理):**

基于 `acos` 函数的定义域和值域，我们可以给出一些假设的输入和输出：

| 输入 (十六进制)           | 输入 (十进制) | 预期输出 (十六进制)       | 预期输出 (十进制) |
|----------------------------|-------------|----------------------------|-------------|
| `0x1.0000000000000p+0`   | 1.0         | `0x0.0000000000000p+0`   | 0.0         |
| `-0x1.0000000000000p+0`  | -1.0        | `0x1.921fb54442d18p+1`   | 3.141592653589793 |
| `0x0.0000000000000p+0`   | 0.0         | `0x1.921fb54442d18p-1`   | 1.570796326794897 |
| `0x1.8000000000000p-1`   | 0.75        | `0x1.06a0b8d3b1334p-1`   | 0.722734255441784 |
| `-0x1.8000000000000p-1`  | -0.75       | `0x1.277f472c4ecb0p+0`   | 2.418858398148009 |

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **输入值超出范围:** `acos` 函数的定义域是 [-1, 1]。如果用户传入超出此范围的值，`acos` 会返回 NaN，并可能设置 `errno` 为 `EDOM`。
   ```c
   #include <math.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       double x = 2.0;
       double result = acos(x);
       if (isnan(result)) {
           perror("acos error");
       }
       return 0;
   }
   ```

2. **误解返回值单位:** `acos` 函数返回的是弧度值，而不是角度值。有些用户可能会忘记将弧度值转换为角度值 (通过乘以 180/π)。
   ```c
   #include <math.h>
   #include <stdio.h>

   #define PI 3.141592653589793

   int main() {
       double x = 0.5;
       double radians = acos(x);
       double degrees = radians * 180.0 / PI;
       printf("acos(0.5) in radians: %f\n", radians);
       printf("acos(0.5) in degrees: %f\n", degrees);
       return 0;
   }
   ```

3. **精度问题:** 浮点数运算存在精度问题。用户不应期望 `acos` 返回绝对精确的结果，而应考虑一定的误差容忍度。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Bionic `acos` 的路径 (示例):**

1. **Android Framework (Java):**  Android Framework 中某个组件，例如 `android.graphics.Camera` 或 `android.view.animation.RotateAnimation`，可能需要进行角度计算。
2. **JNI 调用:** Framework 组件会通过 Java Native Interface (JNI) 调用相应的 Native 方法 (通常是 C/C++ 代码)。
3. **Native 代码 (C/C++):** Native 代码中，如果需要计算反余弦，会调用 `<math.h>` 中的 `acos` 函数。
4. **Bionic `libm.so`:**  这个 `acos` 函数的实现位于 Bionic 的 `libm.so` 共享库中。
5. **`acos_intel_data.handroid` (间接):**  在 `libm.so` 的开发和测试过程中，会使用 `acos_intel_data.handroid` 文件中的数据来验证 `acos` 函数的正确性。实际运行时，`acos` 函数本身不会直接读取这个文件，但会依赖其测试结果保证代码的正确性。

**NDK 到 Bionic `acos` 的路径:**

1. **NDK 开发 (C/C++):**  使用 Android NDK 进行开发的开发者可以直接在他们的 C/C++ 代码中包含 `<math.h>` 并调用 `acos` 函数。
2. **编译链接:**  NDK 编译工具链会将开发者的代码与 Bionic 的共享库链接起来，包括 `libm.so`。
3. **运行时加载:** 当应用运行时，动态链接器会加载 `libm.so`，使得开发者调用的 `acos` 函数指向 Bionic 提供的实现。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `acos` 函数来观察其输入和输出，从而验证上述路径。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const acos = Module.findExportByName("libm.so", "acos");

  if (acos) {
    Interceptor.attach(acos, {
      onEnter: function (args) {
        const input = args[0].toDouble();
        console.log("[+] Called acos with input:", input);
      },
      onLeave: function (retval) {
        const output = retval.toDouble();
        console.log("[+] acos returned:", output);
      }
    });
    console.log("[+] Hooked acos in libm.so");
  } else {
    console.log("[-] acos not found in libm.so");
  }
} else {
  console.log("[-] Hooking acos is only supported on ARM architectures for this example.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 和 frida-server。
2. **运行 Frida Server:** 在 Android 设备上启动 frida-server。
3. **运行目标应用:** 运行你想要调试的 Android 应用。
4. **运行 Frida Hook 脚本:** 在你的电脑上，使用 Frida 连接到目标应用并运行上述 Hook 脚本。
   ```bash
   frida -U -f <your_package_name> -l acos_hook.js --no-pause
   ```
   将 `<your_package_name>` 替换为你的应用的包名，`acos_hook.js` 是保存上述 Frida 脚本的文件名。
5. **触发 `acos` 调用:** 在你的应用中执行会导致调用 `acos` 函数的操作。
6. **观察输出:**  Frida 会在控制台中打印 `acos` 函数的输入和输出值，你可以据此了解 `acos` 的调用情况。

**注意:**

* Frida Hook 主要用于运行时调试和分析，不能直接访问 `acos_intel_data.handroid` 文件。
*  `acos_intel_data.handroid` 是测试数据，在实际的 `acos` 函数执行过程中，不会直接加载这个文件。它的作用是在 Bionic 库的构建和测试阶段确保 `acos` 函数的实现符合预期。

希望以上分析能够帮助你理解 `bionic/tests/math_data/acos_intel_data.handroid` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/math_data/acos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_acos_intel_data[] = {
  { // Entry 0
    0x1.c8a538ae83d1f7ffffffffffffcef091p-1,
    0x1.4182199998587p-1
  },
  { // Entry 1
    0x1.520dc553f6b23800000000000226b93cp-2,
    0x1.e45a1c93651ecp-1
  },
  { // Entry 2
    0x1.91e006d41d8d8fffffffffffffffe4aep0,
    0x1.fd737be914578p-11
  },
  { // Entry 3
    0x1.efeef61d39ac1ffffffffffff8244904p-3,
    0x1.f10fc61e2c78fp-1
  },
  { // Entry 4
    0x1.0c152382d8f1bff4e139b41e4025d0fcp1,
    -0x1.00000000060p-1
  },
  { // Entry 5
    0x1.0c152382e0732be923fe009ea0c7355dp1,
    -0x1.000000002p-1
  },
  { // Entry 6
    0x1.d2cf5cbe8a4768000d63bae9c7297bcfp0,
    -0x1.00000100001p-2
  },
  { // Entry 7
    0x1.0c164c45aca25370b59ffdf4a18d65a1p1,
    -0x1.0004040p-1
  },
  { // Entry 8
    0x1.a222e1630a32c8001e3ce23da074be9bp0,
    -0x1.0007ffffffffep-4
  },
  { // Entry 9
    0x1.0c75b731b9c0ceed0fc3f7c5f98c5e1bp1,
    -0x1.014e445bdcf7dp-1
  },
  { // Entry 10
    0x1.0c8df00b6a96b44b4bbb209fc767369fp1,
    -0x1.01a2037b1bac4p-1
  },
  { // Entry 11
    0x1.0de4edea718bd2db5b8f1e8d95da11f5p1,
    -0x1.064p-1
  },
  { // Entry 12
    0x1.0e4b7c84d10ff2cdc09d8629c37c6bf9p1,
    -0x1.07ap-1
  },
  { // Entry 13
    0x1.0f2e40d09060f1a3d94731a6ca70a8ddp1,
    -0x1.0aa7f71e6e71cp-1
  },
  { // Entry 14
    0x1.0f43445ef5606fffa32df1d88ff691efp1,
    -0x1.0aefb502023b6p-1
  },
  { // Entry 15
    0x1.101adb881a80b24d6b78dbda9f109728p1,
    -0x1.0dce1b9c37387p-1
  },
  { // Entry 16
    0x1.10e62fa769e6534e688c4e0e33eca505p1,
    -0x1.108p-1
  },
  { // Entry 17
    0x1.11c33797afddabbea24dc3547594c5c0p1,
    -0x1.136ae890a0b29p-1
  },
  { // Entry 18
    0x1.1bae2535eaee0c1296c6eab12d27114ap1,
    -0x1.340p-1
  },
  { // Entry 19
    0x1.238d4f63c0137461ca7c6635fd0225bcp1,
    -0x1.4c8df30e0f9f9p-1
  },
  { // Entry 20
    0x1.bd4c060e9d4fa8000ae2414e49c449dep0,
    -0x1.57cp-3
  },
  { // Entry 21
    0x1.f3739df16d5810008dbb8f86206274e3p0,
    -0x1.7c0p-2
  },
  { // Entry 22
    0x1.359d26f93b6c08001b822971ead56e4cp1,
    -0x1.7fffffffffff9p-1
  },
  { // Entry 23
    0x1.f4aa0ecbe9ca07ff5383e6cbdeda0e6fp0,
    -0x1.808p-2
  },
  { // Entry 24
    0x1.3f176283f912f4d5c7129ad9f5141c1dp1,
    -0x1.980p-1
  },
  { // Entry 25
    0x1.92398cd07734cfff8e4658afba76b963p0,
    -0x1.9d78c29270c37p-12
  },
  { // Entry 26
    0x1.0241ccc7797b28001d8b3ed530288167p1,
    -0x1.ba7c5af7cd988p-2
  },
  { // Entry 27
    0x1.a0fad7a0ff6ff7ff77e44ec7b5ef9ba3p0,
    -0x1.db2p-5
  },
  { // Entry 28
    0x1.921fb54442d18469898cc51711854bddp0,
    -0x1.f9a2475d37a04p-101
  },
  { // Entry 29
    0x1.921fb54442d18469898cc517119368e5p0,
    -0x1.fb65e86dc7e52p-101
  },
  { // Entry 30
    0x1.821f3cbecf0a577f98d9122b4f7b3737p1,
    -0x1.fc01190c5f1d4p-1
  },
  { // Entry 31
    0x1.931eb46e6d8fd80019cf2ec002d1ea6ep0,
    -0x1.fdfdfffffffffp-9
  },
  { // Entry 32
    0x1.d2bdcdea4bbff28ee1513ce0581e6b80p0,
    -0x1.ff77fffffffffp-3
  },
  { // Entry 33
    0x1.b235294c376f9ffbe3cda85efb67c658p0,
    -0x1.ffff7ffffffffp-4
  },
  { // Entry 34
    0x1.0c1523808801280001696015d499795fp1,
    -0x1.ffffffeffffe1p-2
  },
  { // Entry 35
    0x1.9a200aa3332ca8002dd33eda52daa3b5p0,
    -0x1.ffffffffff8ffp-6
  },
  { // Entry 36
    0x1.0c152382d7340fff11bb3dc1f95c2689p1,
    -0x1.fffffffffff03p-2
  },
  { // Entry 37
    0x1.9a200aa3332e67f83053ef04d0a4eb45p0,
    -0x1.ffffffffffffep-6
  },
  { // Entry 38
    0x1.921fb54442d18869898cc517019839a2p0,
    -0x1.fffffffffffffp-55
  },
  { // Entry 39
    0x1.720a392c1d8527f0766bdc231b390704p0,
    0x1.00000000008p-3
  },
  { // Entry 40
    0x1.51700e0c1325b800d16de8911c74de7dp0,
    0x1.00000000060p-2
  },
  { // Entry 41
    0x1.720a392c198d30009edc2a4283eae411p0,
    0x1.000000002p-3
  },
  { // Entry 42
    0x1.0c1523804a159000007341c4be8459a3p0,
    0x1.000000046b404p-1
  },
  { // Entry 43
    0x1.0c15235de3e7cb9bd2348617696fafccp0,
    0x1.0000004p-1
  },
  { // Entry 44
    0x1.51700cf3291357ffa4ca332eb644f0f6p0,
    0x1.0000044p-2
  },
  { // Entry 45
    0x1.911fb1199613980023854405784aadecp0,
    0x1.0004000000050p-8
  },
  { // Entry 46
    0x1.512df2849c580e80a384e0df8f8e5a29p0,
    0x1.010p-2
  },
  { // Entry 47
    0x1.0a2f22b4aaf4137fd551484ed58a9734p0,
    0x1.0347f8edc9a96p-1
  },
  { // Entry 48
    0x1.4e34727b36618e7b44a67aa702c53623p0,
    0x1.0c8p-2
  },
  { // Entry 49
    0x1.04bc2567dc9f8cd86255dcf4fafa7693p0,
    0x1.0c9e8916420b6p-1
  },
  { // Entry 50
    0x1.04014982d9ce73c468c55eb187532cd7p0,
    0x1.0ddc68b675658p-1
  },
  { // Entry 51
    0x1.81385760faf0f7fe7fd9d1f793eb6e9bp0,
    0x1.0e4390e4390e1p-4
  },
  { // Entry 52
    0x1.4d7407811e5f8f522dfdeb46952e8762p0,
    0x1.0f6671d3cee5ep-2
  },
  { // Entry 53
    0x1.4d4c369ec6516bd075addb99a8f1fdc7p0,
    0x1.0ffffffe0p-2
  },
  { // Entry 54
    0x1.899f4edc942ce80055c005582a9d9f5fp0,
    0x1.100000004p-5
  },
  { // Entry 55
    0x1.02bb48da5f7b9308fc7983b9f555bdf9p0,
    0x1.1005a3ac6f054p-1
  },
  { // Entry 56
    0x1.028b1af46d959324ee19f46a706b7d35p0,
    0x1.1057411e5735ap-1
  },
  { // Entry 57
    0x1.020b51b1f72a8c2e4de9ec5488de7857p0,
    0x1.112f8a27ba5d5p-1
  },
  { // Entry 58
    0x1.01e697d61109f3bbb99fe25e8efaf83fp0,
    0x1.116da6bf8b495p-1
  },
  { // Entry 59
    0x1.017d9b789233f3964f1c62e3d1f18bb8p0,
    0x1.121f157cb6c0ap-1
  },
  { // Entry 60
    0x1.0176c4d6b5631326381f276a1cf5aff2p0,
    0x1.122aa2913636cp-1
  },
  { // Entry 61
    0x1.00d2160daa60f2dc9c5d2070d90ff117p0,
    0x1.134093e8f975bp-1
  },
  { // Entry 62
    0x1.0067819bc0a6131b2515e089e5ffead6p0,
    0x1.13f438738f770p-1
  },
  { // Entry 63
    0x1.005af0d670a69300326d1f919e90e37ep0,
    0x1.1409633da0018p-1
  },
  { // Entry 64
    0x1.0006aaab22f953446798783c17afa73ap0,
    0x1.149748a9f1e12p-1
  },
  { // Entry 65
    0x1.8dc1a761fc3e27ffddbace0c08f7d931p0,
    0x1.178p-6
  },
  { // Entry 66
    0x1.faedbe5d362f77e0e37df0ba380d6bf2p-1,
    0x1.18e37509b64bfp-1
  },
  { // Entry 67
    0x1.f723c85457f23e048017ebac9828f74ap-1,
    0x1.1c0c71b0d77b4p-1
  },
  { // Entry 68
    0x1.f40045aa068255be54395b26191ca6ecp-1,
    0x1.1ea7972fc8124p-1
  },
  { // Entry 69
    0x1.f3e4a7973ba9f5bc588023272bfd8fefp-1,
    0x1.1ebe78e20b1c4p-1
  },
  { // Entry 70
    0x1.f35b18d9133df5c3286ad7c7f3a599ebp-1,
    0x1.1f306490c5782p-1
  },
  { // Entry 71
    0x1.edf06e518f1d7e7d6318864553757b63p-1,
    0x1.23a83d7649788p-1
  },
  { // Entry 72
    0x1.edae9bcb630d4d2d95081b152b6797a3p-1,
    0x1.23de545deeef6p-1
  },
  { // Entry 73
    0x1.eb59d70c979f2da8249d5a4f58755b8fp-1,
    0x1.25c7dcb26a9cap-1
  },
  { // Entry 74
    0x1.ea55cf128780505242c68838513032e7p-1,
    0x1.269cae16c3f63p-1
  },
  { // Entry 75
    0x1.e0c7b682b6a8581abfbc77e99954db72p-1,
    0x1.2e6p-1
  },
  { // Entry 76
    0x1.d9b299bbb4e537ac6ff62206d2da36b3p-1,
    0x1.340fb2423c6b3p-1
  },
  { // Entry 77
    0x1.d538889085d30e4ca3abe981c9888d22p-1,
    0x1.37a0130f68f6ap-1
  },
  { // Entry 78
    0x1.8d4034388cd22fff892e9180c4337f63p0,
    0x1.37db709c37bf5p-6
  },
  { // Entry 79
    0x1.c8a538ae83d1f7ffffffffffffcef091p-1,
    0x1.4182199998587p-1
  },
  { // Entry 80
    0x1.3ea71520cf3d37faeb955cf605d0a7dbp0,
    0x1.480p-2
  },
  { // Entry 81
    0x1.be76e54ddede3ffe867c8817e7c6e06fp-1,
    0x1.495e1625f7b6fp-1
  },
  { // Entry 82
    0x1.921562b09cf0e8004c5a81cf221a6e56p0,
    0x1.4a5274a529496p-13
  },
  { // Entry 83
    0x1.af9fdabd59d9e658ff0e5e8c0c145370p-1,
    0x1.5496e087b338fp-1
  },
  { // Entry 84
    0x1.91f48e0a5cec37ffff970d899abc38d6p0,
    0x1.5939cd8c9fbedp-11
  },
  { // Entry 85
    0x1.a5282161b01857fa74d0820197a14f5ep-1,
    0x1.5c55572447fb8p-1
  },
  { // Entry 86
    0x1.9c0c4195064df7ffd3c667633bf7a651p-1,
    0x1.62f42a09bce1dp-1
  },
  { // Entry 87
    0x1.91c4c20a0ea7f800004eb45095fd191ap0,
    0x1.6bcce1297373ep-10
  },
  { // Entry 88
    0x1.339d18f59afb880000d2fbce3d9c08c2p0,
    0x1.7182fc23eb316p-2
  },
  { // Entry 89
    0x1.7ad4c5762d7b6800001a3adffeded5f4p0,
    0x1.742b66dcd4308p-4
  },
  { // Entry 90
    0x1.32882c24236038000cd47b0b46bba64ep0,
    0x1.758b345cb9f3ep-2
  },
  { // Entry 91
    0x1.7f46927c463a28062e3b1b0c16ac1bdbp-1,
    0x1.771e38e0af4fcp-1
  },
  { // Entry 92
    0x1.782ebe246cbe37e3fb6a1ef678b064bfp-1,
    0x1.7be8d3908cb27p-1
  },
  { // Entry 93
    0x1.7a40db57e99637fea04162825b2bc181p0,
    0x1.7d6p-4
  },
  { // Entry 94
    0x1.720a392c1d9517f0970e86dd5de5b635p-1,
    0x1.8000000000002p-1
  },
  { // Entry 95
    0x1.2e038f4737dfb7f94f31df896ea0ac7ap0,
    0x1.864fbb7b12ad6p-2
  },
  { // Entry 96
    0x1.657df1f3a0bc08338a7af19c234dfc3ap-1,
    0x1.882efd2dd4220p-1
  },
  { // Entry 97
    0x1.85cea1911701e80000bca0371b899679p0,
    0x1.89fb8a6df15e2p-5
  },
  { // Entry 98
    0x1.2a202393ed2377fd5857f95af8665161p0,
    0x1.94a5294a52948p-2
  },
  { // Entry 99
    0x1.781e4389c0b36fff9c101747cda30edcp0,
    0x1.9f6p-4
  },
  { // Entry 100
    0x1.5d318bf3e390e7fff88af7a5da604d3ap0,
    0x1.a46e97f496ea3p-3
  },
  { // Entry 101
    0x1.1b5148dd9e1bd7b01791138f3f325580p-1,
    0x1.b397a5f961839p-1
  },
  { // Entry 102
    0x1.1a583fd138fb37a3f6d2f07dbf3ec7b3p-1,
    0x1.b41a53773a4e3p-1
  },
  { // Entry 103
    0x1.14823c2657c87f555ecd15bb19387e6bp-1,
    0x1.b721cf87383f3p-1
  },
  { // Entry 104
    0x1.1301fd2ab34e480181c3a283011497c5p-1,
    0x1.b7e6e68840de9p-1
  },
  { // Entry 105
    0x1.12e096afcb7de8799b39619a4d425055p-1,
    0x1.b7f7fc997bfe3p-1
  },
  { // Entry 106
    0x1.05b944cc4600b7f611b44550901f0ceep-1,
    0x1.be8cd7678f521p-1
  },
  { // Entry 107
    0x1.8e9f6e1d3decc7fff55630ea5ccfd289p0,
    0x1.c01ffffffffffp-7
  },
  { // Entry 108
    0x1.ffc7ad9153ff2fd7a788766680d9a358p-2,
    0x1.c16p-1
  },
  { // Entry 109
    0x1.1dc2cb388dc96800004b1ca5a21af6b0p0,
    0x1.c196ba7c38699p-2
  },
  { // Entry 110
    0x1.fb29d815d149880a7b959c1fb8374fd0p-2,
    0x1.c27a04ea38cddp-1
  },
  { // Entry 111
    0x1.fb0f38754a0cf7f96b7417b739fd6712p-2,
    0x1.c280586977fd3p-1
  },
  { // Entry 112
    0x1.f1884288008e97f81e1bbdd955287e5bp-2,
    0x1.c4bed345ea41ap-1
  },
  { // Entry 113
    0x1.eb974d89e1c136026c6858b963f4f0d2p-2,
    0x1.c62p-1
  },
  { // Entry 114
    0x1.e297da83df05f62c3022324c50ec1611p-2,
    0x1.c82f6b1c3d906p-1
  },
  { // Entry 115
    0x1.589c2963846ca801074a478b55f6b7cap0,
    0x1.c84p-3
  },
  { // Entry 116
    0x1.cdd9f8d6e777f7ffff853f09a06b5911p-2,
    0x1.ccccccd442bf9p-1
  },
  { // Entry 117
    0x1.c42907c37d1b27cc0fa3350a28179421p-2,
    0x1.cee437c4d6115p-1
  },
  { // Entry 118
    0x1.bf05da450c97f7f8826c8bfaa9e0af95p-2,
    0x1.cffbbf702a732p-1
  },
  { // Entry 119
    0x1.bedf70d3703617fac6520f0337bf4a56p-2,
    0x1.d003ddf5923bap-1
  },
  { // Entry 120
    0x1.b5d5824cd5a5b7f84e927113df50ca1dp-2,
    0x1.d1e84213079a0p-1
  },
  { // Entry 121
    0x1.a858c231190e17fa9b20a3d037ec0e43p-2,
    0x1.d4a9c16b6b42ep-1
  },
  { // Entry 122
    0x1.9f6c7fe8723777fb3d256621194eb6f1p-2,
    0x1.d6711059b2ce3p-1
  },
  { // Entry 123
    0x1.9d5978ef2047b7f97b093ad7540b39b8p-2,
    0x1.d6d99a0c90a6ap-1
  },
  { // Entry 124
    0x1.9cb189645b2df7f79b30cb75dff78e0bp-2,
    0x1.d6fa8f01023cfp-1
  },
  { // Entry 125
    0x1.97b574226c7d77fd9b3bd3bc8ba77dd9p-2,
    0x1.d7f35e4f0e194p-1
  },
  { // Entry 126
    0x1.9613e250da73e8056bef22e9fe299078p-2,
    0x1.d8442a16f8a05p-1
  },
  { // Entry 127
    0x1.95e4749133f2a806cc1561ec93381a09p-2,
    0x1.d84d5271eccedp-1
  },
  { // Entry 128
    0x1.858c8c0e0f34bf9b87be908d0e8cd365p-2,
    0x1.db658d47a4f02p-1
  },
  { // Entry 129
    0x1.6bf38913626aa7ff1b8b15b0481456e5p-2,
    0x1.e00000007ffffp-1
  },
  { // Entry 130
    0x1.3c2328dda8571001f1fa3a4b1b738ab2p-2,
    0x1.e7cb07ba8097ap-1
  },
  { // Entry 131
    0x1.37fa7f88bd54d0023b864b207af0307cp-2,
    0x1.e86bbf35007dfp-1
  },
  { // Entry 132
    0x1.29ce7191cc2fe7ff1aee4a298866fa12p-2,
    0x1.ea7feaf29d558p-1
  },
  { // Entry 133
    0x1.1cedf22edfdaee581a28423c374a63e9p-2,
    0x1.ec4e9a59613acp-1
  },
  { // Entry 134
    0x1.110e9a3d93e5d3b661dc886b7dfc0145p0,
    0x1.eeac200629b5dp-2
  },
  { // Entry 135
    0x1.ffd3bf06ed2642f1bf646de4dfb90f14p-3,
    0x1.f018068f84bdep-1
  },
  { // Entry 136
    0x1.106ef026ab7e73cb6256ab29382a05f3p0,
    0x1.f0daf154de72cp-2
  },
  { // Entry 137
    0x1.ecd91ecf5a9e8000fcf0fe2a481676b9p-3,
    0x1.f13efac234068p-1
  },
  { // Entry 138
    0x1.d75772546bfc7f3d87511ce008b8b8c3p-3,
    0x1.f28p-1
  },
  { // Entry 139
    0x1.d5b9693237ace821fe875ccefd4cc418p-3,
    0x1.f297929fe63cap-1
  },
  { // Entry 140
    0x1.af6c2d4b59de08016fcef2f0148a746dp-3,
    0x1.f4ae875c6bacbp-1
  },
  { // Entry 141
    0x1.a6be0361001ee8060af2ba4dd0c50aa9p-3,
    0x1.f5218a91baa07p-1
  },
  { // Entry 142
    0x1.0ee85baa5eb7f3fbe1fccd08bc3b4492p0,
    0x1.f62ec3b97b60cp-2
  },
  { // Entry 143
    0x1.0e9a941b232133fa63772cc6a091171bp0,
    0x1.f73dcf73dcf70p-2
  },
  { // Entry 144
    0x1.6c424b343238b7c44b51bd77c7190160p-3,
    0x1.f7ec434d201d1p-1
  },
  { // Entry 145
    0x1.6a83017dfb54de59e9192470188662cfp-3,
    0x1.f80p-1
  },
  { // Entry 146
    0x1.90252d2c42cd97ffe9be50f9322516ccp0,
    0x1.fa86cd7cf3513p-8
  },
  { // Entry 147
    0x1.0d58a360c87c4bbf3d29d0f4a82169bbp0,
    0x1.fb9dc5ca73720p-2
  },
  { // Entry 148
    0x1.fa6c651bf32d78660fb62ba8468a8cc0p-4,
    0x1.fc1775dbef1abp-1
  },
  { // Entry 149
    0x1.f7c328cf834cd87de2b639509dda5de1p-4,
    0x1.fc21ef3b98990p-1
  },
  { // Entry 150
    0x1.f3c8ed27ef9f283f2ac70ec9d6098d19p-4,
    0x1.fc317cd691f52p-1
  },
  { // Entry 151
    0x1.eea6e96b75ead807baca906e58bb8059p-4,
    0x1.fc4560a02d712p-1
  },
  { // Entry 152
    0x1.0d1a4cf1b1fd73b9c4a8b5017d645f3bp0,
    0x1.fc76453e6bae8p-2
  },
  { // Entry 153
    0x1.df3494c7556a03ecf756bf4c5c1d24b7p-4,
    0x1.fc7ffffffffffp-1
  },
  { // Entry 154
    0x1.0d05103b42c9940e6e6c705d65e17858p0,
    0x1.fccp-2
  },
  { // Entry 155
    0x1.9c9bb5b4c94c8001b817fedb0eaca0ecp-4,
    0x1.fd678a5a7385ep-1
  },
  { // Entry 156
    0x1.f4f3987cd68ff86900930a2b99148f4fp-5,
    0x1.ff0b016f7cb8bp-1
  },
  { // Entry 157
    0x1.b96fe9afa4c148152f48dd9ea74565d6p-5,
    0x1.ff41bf1886212p-1
  },
  { // Entry 158
    0x1.a38189360e584c2c315c37b74a8de324p-5,
    0x1.ff542d4af33e4p-1
  },
  { // Entry 159
    0x1.def2feb427f5869945b1e63446daac8ep-6,
    0x1.ffc7fffffffffp-1
  },
  { // Entry 160
    0x1.911fb919aa13a80003dab66eeb93af47p0,
    0x1.fff7ffep-9
  },
  { // Entry 161
    0x1.7bb96d689be7ca1030e43bc3fecb819ap-8,
    0x1.fffdccc1d701fp-1
  },
  { // Entry 162
    0x1.b95e54541a071ffcc559e575e1c45d84p-9,
    0x1.ffff41c283750p-1
  },
  { // Entry 163
    0x1.9464bc1fea5e476fc7c730847ef2072cp-9,
    0x1.ffff604c81f35p-1
  },
  { // Entry 164
    0x1.2380ce33ccc5d81a1da42a66818b51f4p-9,
    0x1.ffffad047cd7bp-1
  },
  { // Entry 165
    0x1.0c1524bceb518c3bb68d2d3c320fc558p0,
    0x1.fffffbbffffffp-2
  },
  { // Entry 166
    0x1.feffc038c368f967261955172b2d21e2p-12,
    0x1.fffffc03fffffp-1
  },
  { // Entry 167
    0x1.821d0973b4a0b0016c6b1edfcc06b6ffp0,
    0x1.fffffe3ffffffp-5
  },
  { // Entry 168
    0x1.9eb04d49b225986a90691720b967589ap-13,
    0x1.ffffff5810533p-1
  },
  { // Entry 169
    0x1.3988e15f98f3dd3665a7a72d97547617p-13,
    0x1.ffffff9ffffffp-1
  },
  { // Entry 170
    0x1.bb67aed2e237162c8ad96b5482f602bep-14,
    0x1.ffffffcffffffp-1
  },
  { // Entry 171
    0x1.6514ba909fbbf3226dfd735dfdf42191p-14,
    0x1.ffffffe0ded2ep-1
  },
  { // Entry 172
    0x1.911fb519a01327ffffaff63cfe51a6ffp0,
    0x1.fffffff001050p-9
  },
  { // Entry 173
    0x1.0c152386e1d2f41799a6b289b1db9e6cp0,
    0x1.fffffff1fffffp-2
  },
  { // Entry 174
    0x1.3988e7c8d4f60f003e750e7129eb31cdp-16,
    0x1.fffffffe7ffffp-1
  },
  { // Entry 175
    0x1.deeeb2316401cb2cb77ada03ca8dd431p-17,
    0x1.ffffffff1ffffp-1
  },
  { // Entry 176
    0x1.752ea8a9db933d7df1d6cffb00007a5ap-18,
    0x1.ffffffffddfffp-1
  },
  { // Entry 177
    0x1.deefb2c32530bab30cf8bbb0a6928f4cp-19,
    0x1.fffffffff1fffp-1
  },
  { // Entry 178
    0x1.0c152382daad2c41d08ab091f9f43ac6p0,
    0x1.fffffffff3fffp-2
  },
  { // Entry 179
    0x1.b000000000cd0800000106bc80666823p-19,
    0x1.fffffffff49c0p-1
  },
  { // Entry 180
    0x1.0c152382d7c177dbb5c7b51c4e876e71p0,
    0x1.fffffffffe1e1p-2
  },
  { // Entry 181
    0x1.911fb5199813a8003eb04539417cd403p0,
    0x1.fffffffffffd0p-9
  },
  { // Entry 182
    0x1.0c152382d736ab69cc6c36f54e0a958bp0,
    0x1.fffffffffffeep-2
  },
  { // Entry 183
    0x1.8000000000000900000000000091ccccp-25,
    0x1.ffffffffffff7p-1
  },
  { // Entry 184
    0x1.0c152382d73673fcd69b865c0010cf96p0,
    0x1.ffffffffffffap-2
  },
  { // Entry 185
    0x1.4d5341b00be8a7fed4c5dfdc2eee1ccbp-2,
    0x1.e51cfe3b1ba8bp-1
  },
  { // Entry 186
    0x1.0c152382d73658465bb32e0f567ad116p0,
    0x1.0p-1
  },
  { // Entry 187
    0x1.0c152382d73658465bb32e0f567ad116p0,
    0x1.0p-1
  },
  { // Entry 188
    0x1.da22859b2d5c27c2d45ce750728c8805p-1,
    0x1.33b645a1cac08p-1
  },
  { // Entry 189
    0x1.921fb54442d1913030139541b9b839a2p-1,
    0x1.6a09e667f3bccp-1
  },
  { // Entry 190
    0x1.921fb54442d1913030139541b9b839a2p-1,
    0x1.6a09e667f3bccp-1
  },
  { // Entry 191
    0x1.359d26f93b6c32551ad5cf63b6549b57p1,
    -0x1.8p-1
  },
  { // Entry 192
    0x1.0c152382d73666bca69b88f04790b76cp-1,
    0x1.bb67ae8584caap-1
  },
  { // Entry 193
    0x1.0c152382d73666bca69b88f04790b76cp-1,
    0x1.bb67ae8584caap-1
  },
  { // Entry 194
    0x1.9e7c9b89260e3bcb44d14a8fdac1fd70p-8,
    0x1.fffd60e94ee39p-1
  },
  { // Entry 195
    0x1.921fb54442d18469898c851701b839a2p0,
    0x1.0p-82
  },
  { // Entry 196
    0x1.921fb54442d18461898cc51701b839a2p0,
    0x1.0p-61
  },
  { // Entry 197
    0x1.921fb54442918469898cc51701b839a1p0,
    0x1.0p-42
  },
  { // Entry 198
    0x1.921fb14442d184697ee21a6c570d422ap0,
    0x1.0p-22
  },
  { // Entry 199
    0x1.916ab041f915522c7a634527690e82a5p0,
    0x1.6a09e667f3bcbp-9
  },
  { // Entry 200
    0x1.916ab041f91552247a614526a90e32a5p0,
    0x1.6a09e667f3bccp-9
  },
  { // Entry 201
    0x1.916ab041f915521c7a5f4525e90de2a5p0,
    0x1.6a09e667f3bcdp-9
  },
  { // Entry 202
    0x1.90b5aae52c79b2aa66b36d577b951ab5p0,
    0x1.6a09e667f3bcbp-8
  },
  { // Entry 203
    0x1.90b5aae52c79b29a66a36d3f7b6d1a70p0,
    0x1.6a09e667f3bccp-8
  },
  { // Entry 204
    0x1.90b5aae52c79b28a66936d277b451a2ap0,
    0x1.6a09e667f3bcdp-8
  },
  { // Entry 205
    0x1.8f4b9db1f59a78450728d07fcec82844p0,
    0x1.6a09e667f3bcbp-7
  },
  { // Entry 206
    0x1.8f4b9db1f59a782506a8cd7fbac79c4cp0,
    0x1.6a09e667f3bccp-7
  },
  { // Entry 207
    0x1.8f4b9db1f59a78050628ca7fa6c71049p0,
    0x1.6a09e667f3bcdp-7
  },
  { // Entry 208
    0x1.8c776f7d7291f51392f5b98b4f9ef640p0,
    0x1.6a09e667f3bcbp-6
  },
  { // Entry 209
    0x1.8c776f7d7291f4d38ef559814e86d71dp0,
    0x1.6a09e667f3bccp-6
  },
  { // Entry 210
    0x1.8c776f7d7291f4938af4f9774d6eb79fp0,
    0x1.6a09e667f3bcdp-6
  },
  { // Entry 211
    0x1.86ce747eb5cb996caf44709717fef092p0,
    0x1.6a09e667f3bcbp-5
  },
  { // Entry 212
    0x1.86ce747eb5cb98ec8f386b94e7027fe1p0,
    0x1.6a09e667f3bccp-5
  },
  { // Entry 213
    0x1.86ce747eb5cb986c6f2c6692b6060c5ap0,
    0x1.6a09e667f3bcdp-5
  },
  { // Entry 214
    0x1.7b77852c631c38160912d4bff04e41e2p0,
    0x1.6a09e667f3bcbp-4
  },
  { // Entry 215
    0x1.7b77852c631c37150790505801c3579cp0,
    0x1.6a09e667f3bccp-4
  },
  { // Entry 216
    0x1.7b77852c631c3614060dcbf013385671p0,
    0x1.6a09e667f3bcdp-4
  },
  { // Entry 217
    0x1.64a144217a8f043112de5f55544e1c28p0,
    0x1.6a09e667f3bcbp-3
  },
  { // Entry 218
    0x1.64a144217a8f0228e1955e7984b3f71bp0,
    0x1.6a09e667f3bccp-3
  },
  { // Entry 219
    0x1.64a144217a8f0020b04c5d9db5191435p0,
    0x1.6a09e667f3bcdp-3
  },
  { // Entry 220
    0x1.359d26f93b6c3905e6d6ef5eb0f574adp0,
    0x1.6a09e667f3bcbp-2
  },
  { // Entry 221
    0x1.359d26f93b6c34bf331d9755a68a7afcp0,
    0x1.6a09e667f3bccp-2
  },
  { // Entry 222
    0x1.359d26f93b6c30787f643f4c9c1897fdp0,
    0x1.6a09e667f3bcdp-2
  },
  { // Entry 223
    0x1.91420151498adc61fb274f09e54f1937p0,
    0x1.bb67ae8584ca9p-9
  },
  { // Entry 224
    0x1.91420151498adc59fb244f08354e0b37p0,
    0x1.bb67ae8584caap-9
  },
  { // Entry 225
    0x1.91420151498adc51fb214f06854cfd36p0,
    0x1.bb67ae8584cabp-9
  },
  { // Entry 226
    0x1.90644cb8084a289e0fdaf319a3d72d0bp0,
    0x1.bb67ae8584ca9p-8
  },
  { // Entry 227
    0x1.90644cb8084a288e0fc2f2e3a3502baap0,
    0x1.bb67ae8584caap-8
  },
  { // Entry 228
    0x1.90644cb8084a287e0faaf2ada2c92a48p0,
    0x1.bb67ae8584cabp-8
  },
  { // Entry 229
    0x1.8ea8def973a3419f8672de627481cc16p0,
    0x1.bb67ae8584ca9p-7
  },
  { // Entry 230
    0x1.8ea8def973a3417f85b2d7a230ff0745p0,
    0x1.bb67ae8584caap-7
  },
  { // Entry 231
    0x1.8ea8def973a3415f84f2d0e1ed7c4267p0,
    0x1.bb67ae8584cabp-7
  },
  { // Entry 232
    0x1.8b31df18893670912b1c1be4889884efp0,
    0x1.bb67ae8584ca9p-6
  },
  { // Entry 233
    0x1.8b31df1889367051251b43c2c30e15fcp0,
    0x1.bb67ae8584caap-6
  },
  { // Entry 234
    0x1.8b31df18893670111f1a6ba0fd83a699p0,
    0x1.bb67ae8584cabp-6
  },
  { // Entry 235
    0x1.8442bbd27f036dec946a1fbdbfe07d8fp0,
    0x1.bb67ae8584ca9p-5
  },
  { // Entry 236
    0x1.8442bbd27f036d6c644f0ed2a561b9aap0,
    0x1.bb67ae8584caap-5
  },
  { // Entry 237
    0x1.8442bbd27f036cec3433fde78ae2f24bp0,
    0x1.bb67ae8584cabp-5
  },
  { // Entry 238
    0x1.765b4c48040219666b2fef59fcb0d2d4p0,
    0x1.bb67ae8584ca9p-4
  },
  { // Entry 239
    0x1.765b4c4804021864e7c768f7896df8efp0,
    0x1.bb67ae8584caap-4
  },
  { // Entry 240
    0x1.765b4c4804021763645ee295162b02d4p0,
    0x1.bb67ae8584cabp-4
  },
  { // Entry 241
    0x1.5a417dae31bf8205988e1afc294b93e7p0,
    0x1.bb67ae8584ca9p-3
  },
  { // Entry 242
    0x1.5a417dae31bf7ff92827db161a0e0411p0,
    0x1.bb67ae8584caap-3
  },
  { // Entry 243
    0x1.5a417dae31bf7decb7c19b300acf85f9p0,
    0x1.bb67ae8584cabp-3
  },
  { // Entry 244
    0x1.1f7a90695ca9046f7f711f3c5271788dp0,
    0x1.bb67ae8584ca9p-2
  },
  { // Entry 245
    0x1.1f7a90695ca8ffff78c910422d09179bp0,
    0x1.bb67ae8584caap-2
  },
  { // Entry 246
    0x1.1f7a90695ca8fb8f72210148079740eep0,
    0x1.bb67ae8584cabp-2
  },
  { // Entry 247
    0x1.921fb54442d18469898cc51701b839a0p0,
    0x1.fffffffffffffp-128
  },
  { // Entry 248
    0x1.921fb54442d18469898cc51701b839a0p0,
    0x1.0p-127
  },
  { // Entry 249
    0x1.921fb54442d18469898cc51701b839a0p0,
    0x1.0000000000001p-127
  },
  { // Entry 250
    0x1.921fb54442d18469898cc51701b8399ep0,
    0x1.fffffffffffffp-127
  },
  { // Entry 251
    0x1.921fb54442d18469898cc51701b8399ep0,
    0x1.0p-126
  },
  { // Entry 252
    0x1.921fb54442d18469898cc51701b8399ep0,
    0x1.0000000000001p-126
  },
  { // Entry 253
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0000000000001p-1022
  },
  { // Entry 254
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1022
  },
  { // Entry 255
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 256
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1074
  },
  { // Entry 257
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0.0
  },
  { // Entry 258
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1074
  },
  { // Entry 259
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 260
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1022
  },
  { // Entry 261
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0000000000001p-1022
  },
  { // Entry 262
    0x1.921fb54042d18469898ce50c570d8ef7p0,
    0x1.fffffffffffffp-31
  },
  { // Entry 263
    0x1.921fb54042d18469898cc50c570d8ef7p0,
    0x1.0p-30
  },
  { // Entry 264
    0x1.921fb54042d18469898c850c570d8ef7p0,
    0x1.0000000000001p-30
  },
  { // Entry 265
    0x1.921fb52442d18469898dafc1ac62e44cp0,
    0x1.fffffffffffffp-28
  },
  { // Entry 266
    0x1.921fb52442d18469898cafc1ac62e44cp0,
    0x1.0p-27
  },
  { // Entry 267
    0x1.921fb52442d18469898aafc1ac62e44cp0,
    0x1.0000000000001p-27
  },
  { // Entry 268
    0x1.921fb4c442d18469898b6fc1ac62e44cp0,
    0x1.fffffffffffffp-26
  },
  { // Entry 269
    0x1.921fb4c442d1846989876fc1ac62e44cp0,
    0x1.0p-25
  },
  { // Entry 270
    0x1.921fb4c442d18469897f6fc1ac62e44bp0,
    0x1.0000000000001p-25
  },
  { // Entry 271
    0x1.921bb54442c6d9befe954da08765547fp0,
    0x1.fffffffffffffp-15
  },
  { // Entry 272
    0x1.921bb54442c6d9bede954d9f87655473p0,
    0x1.0p-14
  },
  { // Entry 273
    0x1.921bb54442c6d9be9e954d9d8765545bp0,
    0x1.0000000000001p-14
  },
  { // Entry 274
    0x1.8e1faa994b5731853e59876423331a32p0,
    0x1.fffffffffffffp-7
  },
  { // Entry 275
    0x1.8e1faa994b5731653d597b63832a59bcp0,
    0x1.0p-6
  },
  { // Entry 276
    0x1.8e1faa994b5731253b5963624318d8a0p0,
    0x1.0000000000001p-6
  },
  { // Entry 277
    0x1.8a1f5fe55274a09adac41ad9214797d8p0,
    0x1.fffffffffffffp-6
  },
  { // Entry 278
    0x1.8a1f5fe55274a05ad2c29a890fc3a730p0,
    0x1.0p-5
  },
  { // Entry 279
    0x1.8a1f5fe552749fdac2bf99e8ecbbc462p0,
    0x1.0000000000001p-5
  },
  { // Entry 280
    0x1.821d0965ad9b6ba3be317b82a5a09c93p0,
    0x1.fffffffffffffp-5
  },
  { // Entry 281
    0x1.821d0965ad9b6b237e01535f8603a3acp0,
    0x1.0p-4
  },
  { // Entry 282
    0x1.821d0965ad9b6a22fda1031946c9a5cep0,
    0x1.0000000000001p-4
  },
  { // Entry 283
    0x1.720a392c1d954953c0f01dccd7296f92p0,
    0x1.fffffffffffffp-4
  },
  { // Entry 284
    0x1.720a392c1d954851badbd6cd2d8e792cp0,
    0x1.0p-3
  },
  { // Entry 285
    0x1.720a392c1d95464daeb348cdda582a13p0,
    0x1.0000000000001p-3
  },
  { // Entry 286
    0x1.51700e0c14b25200dff9b6fda0f736e3p0,
    0x1.fffffffffffffp-3
  },
  { // Entry 287
    0x1.51700e0c14b24ff015655c5ec5a7aaa3p0,
    0x1.0p-2
  },
  { // Entry 288
    0x1.51700e0c14b24bce803ca7210f054413p0,
    0x1.0000000000001p-2
  },
  { // Entry 289
    0x1.0c152382d7365ce4c584921c1d87f0edp0,
    0x1.fffffffffffffp-2
  },
  { // Entry 290
    0x1.0c152382d73658465bb32e0f567ad116p0,
    0x1.0p-1
  },
  { // Entry 291
    0x1.0c152382d7364f09881065f5c83b9e1ap0,
    0x1.0000000000001p-1
  },
  { // Entry 292
    0x1.00000000000000aaaaaaaaaaaaabddddp-26,
    0x1.fffffffffffffp-1
  },
  { // Entry 293
    0.0,
    0x1.0p0
  },
  { // Entry 294
    0x1.921fb54442d1be716ce093b94fb839a2p-1,
    0x1.6a09e667f3bcap-1
  },
  { // Entry 295
    0x1.921fb54442d1a7d0ce7a147d853839a2p-1,
    0x1.6a09e667f3bcbp-1
  },
  { // Entry 296
    0x1.921fb54442d1913030139541b9b839a2p-1,
    0x1.6a09e667f3bccp-1
  },
  { // Entry 297
    0x1.921fb54442d17a8f91ad1605ed3839a2p-1,
    0x1.6a09e667f3bcdp-1
  },
  { // Entry 298
    0x1.921fb54442d163eef34696ca1fb839a2p-1,
    0x1.6a09e667f3bcep-1
  },
  { // Entry 299
    0x1.0c152382d736a6bca69b88f03d8186d0p-1,
    0x1.bb67ae8584ca8p-1
  },
  { // Entry 300
    0x1.0c152382d73686bca69b88f0444486cdp-1,
    0x1.bb67ae8584ca9p-1
  },
  { // Entry 301
    0x1.0c152382d73666bca69b88f04790b76cp-1,
    0x1.bb67ae8584caap-1
  },
  { // Entry 302
    0x1.0c152382d73646bca69b88f0476618afp-1,
    0x1.bb67ae8584cabp-1
  },
  { // Entry 303
    0x1.0c152382d73626bca69b88f043c4aa95p-1,
    0x1.bb67ae8584cacp-1
  },
  { // Entry 304
    0.0,
    0x1.0p0
  },
  { // Entry 305
    0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.0p0
  },
  { // Entry 306
    0x1.00000000000000aaaaaaaaaaaaabddddp-26,
    0x1.fffffffffffffp-1
  },
  { // Entry 307
    0x1.921fb52442d18469898cafc1ac62e44cp1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 308
    0x1.55bcf3c4a46940e467961a6926261188p-1,
    0x1.921fb54442d18p-1
  },
  { // Entry 309
    0x1.3cb0785319b734306fa73e7cb82eb540p1,
    -0x1.921fb54442d18p-1
  },
  { // Entry 310
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0000000000001p-1022
  },
  { // Entry 311
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0000000000001p-1022
  },
  { // Entry 312
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1022
  },
  { // Entry 313
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1022
  },
  { // Entry 314
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 315
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 316
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 317
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 318
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1073
  },
  { // Entry 319
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1073
  },
  { // Entry 320
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1074
  },
  { // Entry 321
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1074
  },
  { // Entry 322
    0x1.921fb54442d18469898cc51701b839a2p0,
    0.0
  },
  { // Entry 323
    0x1.921fb54442d18469898cc51701b839a2p0,
    -0.0
  }
};

"""

```
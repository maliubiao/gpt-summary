Response:
Let's break down the thought process for answering the request about the `log2f_intel_data.handroid` file.

**1. Understanding the Core Request:**

The initial prompt asks for the functionality of the provided C code, its relationship to Android, explanations of libc functions, dynamic linker aspects, logical reasoning, common errors, and how Android framework/NDK reaches this code, along with a Frida hook example.

**2. Initial Analysis of the Code:**

The first thing I noticed is that the code doesn't contain any actual *logic* or *functions*. It's a static array of structures (`data_1_1_t`). Each structure holds two `float` values. The naming `g_log2f_intel_data` strongly suggests this is *test data* for a `log2f` function, likely optimized for Intel architectures. The comments `// Entry N` reinforce this idea. The hexadecimal representation of the floating-point numbers also indicates low-level, precise test cases.

**3. Addressing the "Functionality" Question:**

Since it's data, its primary function is to provide inputs and expected outputs for testing the `log2f` function. This is the most direct and accurate answer.

**4. Connecting to Android Functionality:**

The file's location within `bionic/tests/math_data` immediately links it to the Android C library's math functions. `log2f` is a standard math function. The `_intel_data` suffix suggests architecture-specific testing or data generation. Therefore, this data is used to ensure the correctness of the `log2f` implementation on Android devices with Intel processors.

**5. Addressing the "libc Function Implementation" Question:**

This is a key point where careful interpretation is needed. The *file itself* doesn't implement any libc functions. It *tests* one. The answer should focus on the *purpose* of `log2f` (calculating the base-2 logarithm) and broadly describe how such functions are typically implemented (using polynomial approximations, lookup tables, etc.). Going into extreme detail about the *exact* implementation within bionic would require accessing and analyzing the *actual* `log2f` source code, which isn't provided in this file. It's crucial to distinguish between the test data and the function being tested.

**6. Addressing the "Dynamic Linker" Question:**

Again, the *data file* doesn't directly involve the dynamic linker. However, the `log2f` function *itself* is part of `libc.so`, which is loaded by the dynamic linker. Therefore, the answer should describe the basic process of the dynamic linker loading shared libraries (`.so` files), including a simplified `libc.so` layout and the steps of symbol resolution.

**7. "Logical Reasoning" and "Hypothetical Input/Output":**

The data itself *is* the logical reasoning and the expected input/output pairs. Each entry represents a test case. The first float is the input to `log2f`, and the second float is the expected output. Providing a few examples directly from the data is the best way to illustrate this.

**8. "Common Usage Errors":**

Since it's test data, users don't directly *use* this file in their code. The errors are more relevant to *developers testing the `log2f` implementation*. Examples include incorrect test data, insufficient test coverage, or misinterpreting test results.

**9. "Android Framework/NDK Path and Frida Hook":**

This requires understanding how a user-space application eventually uses `log2f`. The path involves:

* **Application Code:**  The user calls `log2f`.
* **NDK:** If using the NDK, the call goes through the NDK's headers and libraries.
* **System Calls (Indirectly):** Eventually, the call leads to the `libc.so`.
* **Dynamic Linker:**  The dynamic linker loaded `libc.so` at startup.
* **`log2f` Implementation:** The actual `log2f` code in `libc.so` is executed.
* **Test Data:** The provided data file is used *during the testing phase* of the bionic library development.

The Frida hook example should target the `log2f` function within the `libc.so` library to intercept its calls and arguments.

**10. Structuring the Answer:**

A clear and organized structure is essential. Using headings and bullet points makes the information easier to digest. Following the order of the questions in the prompt is a good starting point.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps this file contains some helper functions for generating test data.
* **Correction:**  Closer examination reveals it's the data itself, not code to generate it.

* **Initial thought:** Explain the intricacies of `log2f`'s implementation.
* **Refinement:**  Focus on the *general* principles of math function implementation since the specific `log2f` source isn't provided. Emphasize that this file is *testing* the function, not *defining* it.

* **Initial thought:** Provide a very complex `libc.so` layout.
* **Refinement:** Keep the `libc.so` layout and dynamic linking explanation concise and focused on the relevant concepts. Avoid unnecessary details.

By following these steps and constantly refining the understanding of the request and the provided code, I arrived at the comprehensive and accurate answer. The key is to carefully distinguish between the test data, the function being tested, and the broader context of the Android operating system and its libraries.
好的，让我们来详细分析一下 `bionic/tests/math_data/log2f_intel_data.handroid` 这个文件。

**文件功能：**

这个文件 `log2f_intel_data.handroid` 是 bionic (Android 的 C 库) 中用于测试 `log2f` 函数的数据文件。具体来说，它包含了大量的测试用例，每个用例由一对浮点数组成：

* **输入 (第一个浮点数):**  这是 `log2f` 函数的输入值。
* **预期输出 (第二个浮点数):** 这是对于给定输入，`log2f` 函数应该返回的正确结果。

这些数据是针对 Intel 架构的，文件名中的 `intel` 表明了这一点。  `handroid` 可能是指手动创建或验证过的 Android 测试数据。

**与 Android 功能的关系及举例说明：**

这个文件直接关系到 Android 操作系统中提供的数学库功能。 `log2f(x)` 函数计算以 2 为底的 `x` 的对数。它是标准 C 库 `<math.h>` 的一部分，在 Android 上由 bionic 提供。

**举例说明：**

在 Android 应用或系统组件中，如果需要计算以 2 为底的对数，开发者会调用 `log2f()` 函数。  例如，在音频处理、图像处理、或者科学计算相关的应用中，可能会用到这个函数。

```c
#include <math.h>
#include <stdio.h>

int main() {
  float input = 8.0f;
  float result = log2f(input);
  printf("log2f(%f) = %f\n", input, result); // 预期输出： log2f(8.000000) = 3.000000
  return 0;
}
```

这个测试数据文件就是用来确保 bionic 库中的 `log2f` 函数在各种输入情况下都能返回正确的结果。例如，文件中的第一个条目：

```c
{ // Entry 0
  0x1.715419fdb96231bd1fa15f37bfa42910p-17,
  0x1.000080p0
}
```

表示当 `log2f` 的输入是 `0x1.715419fdb96231bd1fa15f37bfa42910p-17` (一个非常小的正数) 时，预期的输出是 `0x1.000080p0` (接近 0 的值)。 这种使用十六进制浮点数表示是为了保证精度。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个数据文件本身并没有实现任何 libc 函数，它只是测试数据。 `log2f` 函数的实现通常会涉及到以下技术：

1. **范围缩减 (Range Reduction):** 将任意正数 `x` 转换为一个较小范围内的数，通常是 `[1, 2)` 或 `[sqrt(2)/2, sqrt(2)]`。 这可以通过提取 `x` 的指数部分来实现。例如，可以将 `x` 表示为 `m * 2^e`，其中 `m` 在 `[1, 2)` 范围内。  那么 `log2f(x) = log2f(m * 2^e) = log2f(m) + e`。 这样，只需要计算 `log2f(m)`，其中 `m` 的范围有限。

2. **多项式逼近 (Polynomial Approximation):** 在缩减后的范围内，使用多项式来逼近 `log2f(m)`。  常用的方法有 minimax 逼近或 Chebyshev 逼近。  这种方法需要预先计算好的多项式系数。

3. **查找表 (Lookup Tables):** 对于某些平台或者特定的精度要求，可以使用查找表来存储一些预先计算好的对数值。  这可以提高计算速度，但会占用更多的内存。

4. **特殊情况处理:**  `log2f` 需要处理一些特殊情况，例如：
   * 输入为 0：返回负无穷大 (`-HUGE_VALF`).
   * 输入为负数：返回 NaN (Not a Number)。
   * 输入为正无穷大：返回正无穷大 (`HUGE_VALF`).

在 bionic 中，`log2f` 的具体实现可能会根据目标架构 (例如 Intel) 进行优化，利用特定的 CPU 指令或算法来提高性能。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个数据文件本身不直接涉及动态链接器。 然而，`log2f` 函数是 `libc.so` 共享库的一部分，这个库是由动态链接器在程序运行时加载的。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text:  // 代码段
    _start:       // 程序入口点 (如果 libc 作为主程序)
    malloc:
    free:
    printf:
    log2f:        // log2f 函数的机器码
    // ... 其他 libc 函数 ...
  .rodata: // 只读数据段
    __libc_version: "..."
    // ... 其他只读数据 ...
  .data:  // 可读写数据段
    __errno_location:
    // ... 其他可读写数据 ...
  .dynsym: // 动态符号表 (包含导出的符号，如 log2f)
    log2f
    malloc
    // ...
  .dynstr: // 动态字符串表 (存储符号名称)
    "log2f"
    "malloc"
    // ...
  .rel.dyn: // 动态重定位表 (用于在加载时修正地址)
    // ...
```

**链接的处理过程：**

1. **编译时链接：** 当你的程序调用 `log2f` 时，编译器在编译阶段会查找 `log2f` 的声明，并将其标记为需要外部链接。

2. **动态链接器介入：** 在程序启动时，操作系统会加载程序的执行文件，并启动动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`)。

3. **加载依赖库：** 动态链接器会分析程序依赖的共享库 (例如 `libc.so`)，并将其加载到内存中。

4. **符号查找和重定位：**
   * 当程序执行到调用 `log2f` 的地方时，由于 `log2f` 的实际地址在编译时未知，需要动态链接器来完成。
   * 动态链接器会在已加载的共享库 (`libc.so`) 的 `.dynsym` (动态符号表) 中查找名为 "log2f" 的符号。
   * 找到符号后，动态链接器会获取 `log2f` 在 `libc.so` 中的实际内存地址。
   * 动态链接器会使用 `.rel.dyn` (动态重定位表) 中的信息，修改程序中调用 `log2f` 的指令，将其指向 `log2f` 在内存中的实际地址。这个过程称为重定位。

5. **执行 `log2f`：** 一旦重定位完成，程序就可以成功调用 `libc.so` 中的 `log2f` 函数。

**如果做了逻辑推理，请给出假设输入与输出：**

这个文件本身就是一系列的输入和预期输出的对应关系，体现了逻辑推理的过程。 例如：

* **假设输入:** `0x1.0p0` (十进制 1.0)
* **逻辑推理:** `log2(1.0)` 应该等于 `0.0`。
* **预期输出:** `0x0.0p0` (十进制 0.0)。  你可以从文件中找到对应的条目（虽然文件中没有明确的 1.0，但接近的值是存在的）。

* **假设输入:** `0x1.0p1` (十进制 2.0)
* **逻辑推理:** `log2(2.0)` 应该等于 `1.0`。
* **预期输出:** `0x1.0p0` (十进制 1.0)。  文件中 `Entry 110` 有 `{ 0x1.p0, 0x1.p1 }`, 这里输入是 `1.0`, 输出是 `2.0`, 看起来像是对数底数是输入，结果是 2 的输入次幂。但仔细看注释，`// Entry 110`，其输入是 `0x1.p0`也就是 1.0， 对应输出是 `0x1.p1`也就是 2.0， 这不符合 log2f 的定义。  **这是一个需要注意的地方，可能数据有误或者理解方式需要调整。 仔细观察整个数据文件，发现第二个 `float` 值看起来像是 `log2` 的结果，但是其指数部分被移动了。 比如 `Entry 0`，输入的指数是 `-17`，输出的指数是 `0`， 差了 `17`。  再看输出的值 `0x1.000080p0`，这个值略大于 1。 这暗示输出可能经过了某种变换或缩放。**

**经过更仔细的分析，我之前的理解有偏差。  这些数据似乎不是直接的 `input` 和 `log2f(input)` 的对应。  更可能的解释是，这些数据用于测试 `log2f` 函数实现中的某些 *中间步骤* 或 *特定算法*，或者用于评估特定精度下的结果。**  例如，输入可能是一个经过预处理的值，而输出是 `log2f` 计算过程中的一个中间结果或者最终结果的某种编码形式。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

虽然用户不会直接操作这个数据文件，但在使用 `log2f` 函数时，常见的错误包括：

1. **输入为负数或零：**
   ```c
   float result1 = log2f(-1.0f); // 结果为 NaN
   float result2 = log2f(0.0f);  // 结果为 -无穷大
   ```
   开发者需要在使用 `log2f` 之前确保输入是正数。

2. **忘记包含头文件：** 如果没有包含 `<math.h>`，编译器可能无法识别 `log2f` 函数。

3. **类型不匹配：** 虽然 `log2f` 接受 `float` 类型，但如果传递了 `double` 类型的参数，可能会发生隐式类型转换，在某些情况下可能导致精度损失。  建议使用与函数签名匹配的类型。

4. **误解对数的底：**  `log2f` 是以 2 为底的对数，开发者可能会错误地认为是以 10 或自然对数为底。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **应用层调用 (Android Framework 或 NDK):**
   * **Java (Android Framework):**  在 Java 代码中，可以使用 `java.lang.Math.log()` 函数，它计算的是自然对数。如果要计算以 2 为底的对数，可以手动计算： `Math.log(x) / Math.log(2)`. 或者，如果通过 JNI 调用了 native 代码，native 代码中可以直接使用 `log2f`.
   * **Native (NDK):** 在 C/C++ 代码中，通过 NDK 开发，可以直接包含 `<math.h>` 并调用 `log2f()`。

2. **系统调用 (间接):**  `log2f` 是 `libc.so` 提供的函数，当应用调用 `log2f` 时，实际上是执行了 `libc.so` 中对应的代码。这通常不需要显式的系统调用，因为 `libc` 函数是在用户空间执行的。

3. **bionic libc (`libc.so`):**  `log2f` 的实现位于 Android 的 C 库 bionic 中的 `libc.so` 共享库中。

4. **测试数据 (`log2f_intel_data.handroid`):**  这个数据文件在 **bionic 库的开发和测试阶段** 使用。  Android 的开发者会运行测试程序，这些测试程序会读取这个数据文件，并将文件中的输入值传递给 `log2f` 函数，然后比较函数的输出与文件中预期的输出值，以此来验证 `log2f` 函数的正确性。

**Frida Hook 示例：**

假设你想 hook `libc.so` 中的 `log2f` 函数，你可以使用 Frida：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "log2f"), {
  onEnter: function(args) {
    console.log("[+] log2f called with argument: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("[+] log2f returned: " + retval);
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. **安装 Frida 和 adb。**
2. **确保你的 Android 设备已 root，并且安装了 frida-server。**
3. **将上面的 Python 脚本保存为 `hook_log2f.py`，并将 `"你的应用包名"` 替换为你想要监控的应用的包名。**
4. **运行应用。**
5. **在 PC 上运行 `python hook_log2f.py`。**

当被 hook 的应用调用 `log2f` 函数时，Frida 会拦截调用，并打印出输入参数和返回值。  这个例子展示了如何监控 `log2f` 函数的调用，但 **这个 hook 不会直接涉及到读取 `log2f_intel_data.handroid` 文件**。 该文件主要用于库的内部测试。

总结来说，`log2f_intel_data.handroid` 是 bionic 库中 `log2f` 函数的测试数据，用于确保该函数在 Android 平台上能正确运行。 它在库的开发和测试阶段发挥作用，与应用程序的运行时动态链接过程间接相关。

### 提示词
```
这是目录为bionic/tests/math_data/log2f_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<float, float> g_log2f_intel_data[] = {
  { // Entry 0
    0x1.715419fdb96231bd1fa15f37bfa42910p-17,
    0x1.000080p0
  },
  { // Entry 1
    0x1.14fe88ff5753fa56dc27bca056285672p-15,
    0x1.000180p0
  },
  { // Entry 2
    0x1.715305002e4ae466ed064a01ae55204ep-15,
    0x1.0002p0
  },
  { // Entry 3
    0x1.4327b20433837a3e2c610a392bbd295ap-14,
    0x1.000380p0
  },
  { // Entry 4
    0x1.64531effed17eb9b0a93b3ccaa24f82bp-13,
    0x1.0007b8p0
  },
  { // Entry 5
    -0x1.ffe7a4ffff5f125cad7f0468b55a873cp2,
    0x1.004390p-8
  },
  { // Entry 6
    -0x1.4fdd63002e000ea74a80c91b771feb2ep4,
    0x1.0181p-21
  },
  { // Entry 7
    0x1.61382d01166a5f656628676dd57287c3p-7,
    0x1.01eb80p0
  },
  { // Entry 8
    0x1.67ea1b041aeef5d06d27db173c4a8ec3p-7,
    0x1.01f4dap0
  },
  { // Entry 9
    0x1.6f089703fa8b836209e806374014eeeap-7,
    0x1.01feccp0
  },
  { // Entry 10
    0x1.d8c5b9000072814ba11dc07e3e55730cp-6,
    0x1.052cp0
  },
  { // Entry 11
    0x1.65ad73003698ae3b6629d42d6d969d65p-5,
    0x1.07ddb4p0
  },
  { // Entry 12
    0x1.671b720031bff18c21d3c6680b607a97p-5,
    0x1.07e5e0p0
  },
  { // Entry 13
    -0x1.bd01820013d2bdf2e708a03b63cad894p2,
    0x1.0870p-7
  },
  { // Entry 14
    0x1.bc8a3f002d49ff2fff61bbc88ca84366p-5,
    0x1.09d0p0
  },
  { // Entry 15
    0x1.d15cfd000ba18b834668273db43a54f4p-5,
    0x1.0a48p0
  },
  { // Entry 16
    0x1.254503fffff2c7469f0c551c58628c75p-4,
    0x1.0d0686p0
  },
  { // Entry 17
    0x1.8972445dbe2011fbaf76774ecaa1886bp-4,
    0x1.11a0p0
  },
  { // Entry 18
    -0x1.4e0dddfffd1fadff896c773a983cb069p4,
    0x1.1684p-21
  },
  { // Entry 19
    -0x1.6d9f4300000188d5e28bf9ecd7eb48a3p1,
    0x1.1ac9bcp-3
  },
  { // Entry 20
    0x1.3e8666fed9e0919054d1723c7bfa2a2ep-3,
    0x1.1d24p0
  },
  { // Entry 21
    -0x1.a9967dfffdea2f22e87a3d2cfb4653e0p-1,
    0x1.1fc530p-1
  },
  { // Entry 22
    -0x1.ac7b430000002b16a835260d35f73f3bp0,
    0x1.40f572p-2
  },
  { // Entry 23
    -0x1.50fd36ffff7b1fe211b2f1e467a808c6p1,
    0x1.4a37aap-3
  },
  { // Entry 24
    -0x1.68e3e700011eed1c8bdf78a5004ec845p4,
    0x1.5c5780p-23
  },
  { // Entry 25
    -0x1.14c560fe68af880e0a0f337d55565281p-1,
    0x1.60p-1
  },
  { // Entry 26
    0x1.eee0f9e9bd541c2161fbaa601ad44f9dp-2,
    0x1.65ddfap0
  },
  { // Entry 27
    0x1.ffff6b715e229192074dd520e800523dp-2,
    0x1.6a09c2p0
  },
  { // Entry 28
    0x1.ffffb4e49986d923a4e540f03b1da0dap-2,
    0x1.6a09d4p0
  },
  { // Entry 29
    -0x1.000008fd564a8532198fd9c602596351p-1,
    0x1.6a09e2p-1
  },
  { // Entry 30
    -0x1.5e7df5fe538ab34efb515ac93b443d55p2,
    0x1.70p-6
  },
  { // Entry 31
    0x1.3719d8ffda8ee27c20ca5d36ce40a19bp3,
    0x1.a63c60p9
  },
  { // Entry 32
    -0x1.95152a001cb0000297a418bc58741cd8p6,
    0x1.a86a40p-102
  },
  { // Entry 33
    -0x1.a86d52000000dde9cc8582ca6f4adf02p3,
    0x1.aa932cp-14
  },
  { // Entry 34
    -0x1.a65bf4fffdc2eb6e2bba1e155731485cp3,
    0x1.be1dacp-14
  },
  { // Entry 35
    0x1.19e96affffe46969e091319af39bf01dp3,
    0x1.c0be08p8
  },
  { // Entry 36
    -0x1.6b2194fffbcc473e6b408598b11c0b76p-3,
    0x1.c4c990p-1
  },
  { // Entry 37
    -0x1.b0747afff09129e7c27981832371a2b7p-4,
    0x1.dbde6cp-1
  },
  { // Entry 38
    -0x1.a31d90fffdc06fa674e6c77e0d27325ep3,
    0x1.de9690p-14
  },
  { // Entry 39
    -0x1.7d61ebfff707baf0a4babc7a455fdedap-4,
    0x1.dfffdep-1
  },
  { // Entry 40
    -0x1.8be3350000129024f1746df09b18e1c0p1,
    0x1.e01448p-4
  },
  { // Entry 41
    -0x1.2dab68ffff653aa0f522110f165fc6cdp-4,
    0x1.e684aep-1
  },
  { // Entry 42
    -0x1.1ddc06ffe493eb9e838bc57f1692f071p-5,
    0x1.f3c3c0p-1
  },
  { // Entry 43
    -0x1.fe5c28b51763fd9e597b74b77eaef363p-6,
    0x1.f5104cp-1
  },
  { // Entry 44
    -0x1.fb46c8ffb297bc8b36ec72bf8f845dafp-6,
    0x1.f52108p-1
  },
  { // Entry 45
    -0x1.83a4382bc0ca76ba53a02f5c39dd1105p1,
    0x1.f600a8p-4
  },
  { // Entry 46
    -0x1.c5685effd6dc60c465f6d4566400ea1bp-6,
    0x1.f645bcp-1
  },
  { // Entry 47
    -0x1.c0daa2ffe3fde42c220d9cdd6dba636bp-6,
    0x1.f65e82p-1
  },
  { // Entry 48
    -0x1.a0ab3effb22b2baa230d01d368f486cfp-6,
    0x1.f70dbep-1
  },
  { // Entry 49
    -0x1.9993e6b5eebc60c6416982df9bf027cdp-6,
    0x1.f73462p-1
  },
  { // Entry 50
    -0x1.90db40b3d98bebe6e068b72646536233p-6,
    0x1.f763ecp-1
  },
  { // Entry 51
    -0x1.805ce6d1eec4e554c05d1277b7a61f1ep-6,
    0x1.f7bde0p-1
  },
  { // Entry 52
    -0x1.71c5270003e7400a82571e14d211b1abp-9,
    0x1.fefff2p-1
  },
  { // Entry 53
    -0x1.4fd0950000f9ea163e3b6b379b806a27p-9,
    0x1.ff1770p-1
  },
  { // Entry 54
    -0x1.802e2bfffffc33f278fa52402320f10ap1,
    0x1.ff800cp-4
  },
  { // Entry 55
    -0x1.718867c39aac5ee37685394fe9bfd749p-13,
    0x1.ffeffep-1
  },
  { // Entry 56
    -0x1.72c684e5cfc146d2275210812c0c7f68p-16,
    0x1.fffdfep-1
  },
  { // Entry 57
    -0x1.71552efd6e75c155bd4e4ed94f59a26ap-16,
    0x1.fffep-1
  },
  { // Entry 58
    -0x1.48ef5e00535d9165bbb9b9a8c056f797p-18,
    0x1.ffff8ep-1
  },
  { // Entry 59
    -0x1.71547935612438aa6af6b5495892e719p-22,
    0x1.fffff8p-1
  },
  { // Entry 60
    -0x1.715477c40ca820a04d97be4efccd95a9p-23,
    0x1.fffffcp-1
  },
  { // Entry 61
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 62
    -0x1.000000d4175ddebaa6cc9d6112365229p-1,
    0x1.6a09e6p-1
  },
  { // Entry 63
    -0x1.561462846d15350ee6248ecd4c1b002bp-2,
    0x1.962b60p-1
  },
  { // Entry 64
    -0x1.7b67dba86e896c0a53d2c939ef0d29bfp-3,
    0x1.c24cdap-1
  },
  { // Entry 65
    -0x1.9cab66c58143f2a800e68dbb02f54331p-5,
    0x1.ee6e54p-1
  },
  { // Entry 66
    0x1.2ae054380d16d8f59673a7e3928246cdp-4,
    0x1.0d47e6p0
  },
  { // Entry 67
    0x1.7e23503264c4ad371b8f163c4f9aef26p-3,
    0x1.2358a2p0
  },
  { // Entry 68
    0x1.2aebb187ce6ee362d3103a2200b286e2p-2,
    0x1.39695ep0
  },
  { // Entry 69
    0x1.8f6e7a2697b530fad3d12a9d6a8f1d3ap-2,
    0x1.4f7a1ap0
  },
  { // Entry 70
    0x1.ed899b07eb9cb8af2c927ecf12ec7cbep-2,
    0x1.658ad6p0
  },
  { // Entry 71
    0x1.2300cb4606615b744653e167d86f2813p-1,
    0x1.7b9b92p0
  },
  { // Entry 72
    0x1.4cbccc36deb50dd3e00c1a4eca18d57ep-1,
    0x1.91ac4ep0
  },
  { // Entry 73
    0x1.743d4cb7d92562e1484f862b688a46fbp-1,
    0x1.a7bd0ap0
  },
  { // Entry 74
    0x1.99bc5947999b190ccc67cef041311282p-1,
    0x1.bdcdc6p0
  },
  { // Entry 75
    0x1.bd6b934775bef13a6359e331efe67a11p-1,
    0x1.d3de82p0
  },
  { // Entry 76
    0x1.df75be8ef439ce361ebbb13fff3a7b53p-1,
    0x1.e9ef3ep0
  },
  { // Entry 77
    0x1.fffff758052d13b69dd6c8d6740a3357p-1,
    0x1.fffffap0
  },
  { // Entry 78
    -0x1.000000d4175ddebaa6cc9d6112365229p-1,
    0x1.6a09e6p-1
  },
  { // Entry 79
    -0x1.73324a9b9d2895d79d8ddf07a502bep-2,
    0x1.8e3e16p-1
  },
  { // Entry 80
    -0x1.e54e432361189c3353cc06c2dd27d736p-3,
    0x1.b27246p-1
  },
  { // Entry 81
    -0x1.f19de909d7e63fd264a2c312d0c1789dp-4,
    0x1.d6a676p-1
  },
  { // Entry 82
    -0x1.dd89b738d21d0221c908b8a0c32f1212p-7,
    0x1.fadaa6p-1
  },
  { // Entry 83
    0x1.5c01921d594ace74709e134409d4ed24p-4,
    0x1.0f876cp0
  },
  { // Entry 84
    0x1.6cb0eb0cc03326cfabdb68ecee7aba40p-3,
    0x1.21a184p0
  },
  { // Entry 85
    0x1.0fe8503e467106a65788ddb3a15f5375p-2,
    0x1.33bb9cp0
  },
  { // Entry 86
    0x1.64594511e637e6f93b5cb2912b99abedp-2,
    0x1.45d5b4p0
  },
  { // Entry 87
    0x1.b4392815bf92113e75eb0dd2b26fd740p-2,
    0x1.57efccp0
  },
  { // Entry 88
    0x1.fffff62e925d61652c914504dc3ee2cep-2,
    0x1.6a09e4p0
  },
  { // Entry 89
    -0x1.a8ff971810a5e1817fd3b7d7e5d148bbp-2,
    0x1.80p-1
  },
  { // Entry 90
    -0x1.1c31df37d71943eb77829a1feb37b99ap-2,
    0x1.a66666p-1
  },
  { // Entry 91
    -0x1.374d6afb125968a0c493df15bf69e438p-3,
    0x1.ccccccp-1
  },
  { // Entry 92
    -0x1.2b386cc87f9a4eee785d4a5dbce887b7p-5,
    0x1.f33332p-1
  },
  { // Entry 93
    0x1.20507dbe3011bddb9a9b123c4341bc4cp-4,
    0x1.0cccccp0
  },
  { // Entry 94
    0x1.5c01a39fbd6879fa00b120a068badd12p-3,
    0x1.20p0
  },
  { // Entry 95
    0x1.0d58e803fedbad8f59d5947b2a21a425p-2,
    0x1.333334p0
  },
  { // Entry 96
    0x1.66e8c754261d0ebda20c00ad74e85091p-2,
    0x1.466668p0
  },
  { // Entry 97
    0x1.bb59c03d54eb4b10a384046c38ed39fdp-2,
    0x1.59999cp0
  },
  { // Entry 98
    0x1.059cd374571eb31852640bb553677c83p-1,
    0x1.6cccd0p0
  },
  { // Entry 99
    0x1.2b803473f7ad0f3f401624140d175ba2p-1,
    0x1.80p0
  },
  { // Entry 100
    0.0,
    0x1.p0
  },
  { // Entry 101
    0x1.199b76bf23e221a6231fc33bca41b607p-3,
    0x1.19999ap0
  },
  { // Entry 102
    0x1.0d58e803fedbad8f59d5947b2a21a425p-2,
    0x1.333334p0
  },
  { // Entry 103
    0x1.8398925fcd61fbf1aa81ef798b08bb2cp-2,
    0x1.4ccccep0
  },
  { // Entry 104
    0x1.f113c1858de496d814a68e82919d673bp-2,
    0x1.666668p0
  },
  { // Entry 105
    0x1.2b80384cd8e605e99a5cd99f34293888p-1,
    0x1.800002p0
  },
  { // Entry 106
    0x1.5b2c41f5948361383f498e179a6dd347p-1,
    0x1.99999cp0
  },
  { // Entry 107
    0x1.87f43057c707ec89ca00835fb95f66d7p-1,
    0x1.b33336p0
  },
  { // Entry 108
    0x1.b22cabaab2c8964911abde220f5f415cp-1,
    0x1.ccccd0p0
  },
  { // Entry 109
    0x1.da1c9dfd31a7706146ef266c16ed655dp-1,
    0x1.e6666ap0
  },
  { // Entry 110
    0x1.p0,
    0x1.p1
  },
  { // Entry 111
    0x1.90p6,
    0x1.p100
  },
  { // Entry 112
    0x1.908ccdbb5f91f110d3118fe19de520dbp6,
    0x1.19999ap100
  },
  { // Entry 113
    0x1.910d58e803fedbad8f59d5947b2a21a4p6,
    0x1.333334p100
  },
  { // Entry 114
    0x1.918398925fcd61fbf1aa81ef798b08bbp6,
    0x1.4ccccep100
  },
  { // Entry 115
    0x1.91f113c1858de496d814a68e82919d67p6,
    0x1.666668p100
  },
  { // Entry 116
    0x1.9257007099b1cc0bd334b9b33e685271p6,
    0x1.800002p100
  },
  { // Entry 117
    0x1.92b65883eb2906c2707e931c2f34dba6p6,
    0x1.99999cp100
  },
  { // Entry 118
    0x1.930fe860af8e0fd913940106bf72becdp6,
    0x1.b33336p100
  },
  { // Entry 119
    0x1.936459575565912c922357bc441ebe82p6,
    0x1.ccccd0p100
  },
  { // Entry 120
    0x1.93b4393bfa634ee0c28dde4cd82ddacap6,
    0x1.e6666ap100
  },
  { // Entry 121
    0x1.94p6,
    0x1.p101
  },
  { // Entry 122
    -0x1.715481dd5c5d93663255eca7ba82aeb6p-20,
    0x1.ffffe0p-1
  },
  { // Entry 123
    -0x1.71547c180a27f362d17a1f59be1bb55dp-21,
    0x1.fffff0p-1
  },
  { // Entry 124
    0.0,
    0x1.p0
  },
  { // Entry 125
    0x1.7154708d66755d9fe119ed1e85c13f40p-21,
    0x1.000008p0
  },
  { // Entry 126
    0x1.71546ac814f867d7a99ac240f177d35fp-20,
    0x1.000010p0
  },
  { // Entry 127
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 128
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 129
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 130
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 131
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 132
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 133
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 134
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 135
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 136
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 137
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 138
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 139
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 140
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 141
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 142
    0x1.fffffffa3aae23d27651e8410cc825cbp6,
    0x1.fffffep127
  },
  { // Entry 143
    -0x1.2ap7,
    0x1.p-149
  },
  { // Entry 144
    -0x1.000004e8b6d14f4d69b75d7d91e08e98p-1,
    0x1.6a09e4p-1
  },
  { // Entry 145
    -0x1.000000d4175ddebaa6cc9d6112365229p-1,
    0x1.6a09e6p-1
  },
  { // Entry 146
    -0x1.fffff97eefe066f380fa3704987b9811p-2,
    0x1.6a09e8p-1
  },
  { // Entry 147
    0x1.fffff62e925d61652c914504dc3ee2cep-2,
    0x1.6a09e4p0
  },
  { // Entry 148
    0x1.fffffe57d144428ab266c53ddb935bacp-2,
    0x1.6a09e6p0
  },
  { // Entry 149
    0x1.00000340880fcc863f82e47db3c233f7p-1,
    0x1.6a09e8p0
  },
  { // Entry 150
    -0x1.0000017154770b626b85efbccdf68d2ep0,
    0x1.fffffep-2
  },
  { // Entry 151
    -0x1.p0,
    0x1.p-1
  },
  { // Entry 152
    -0x1.fffffa3aae2c7a711213405fc20a11b8p-1,
    0x1.000002p-1
  },
  { // Entry 153
    -0x1.a8ff9ec9d322112ed31f244bceb1ec85p-2,
    0x1.7ffffep-1
  },
  { // Entry 154
    -0x1.a8ff971810a5e1817fd3b7d7e5d148bbp-2,
    0x1.80p-1
  },
  { // Entry 155
    -0x1.a8ff8f664e33f42ccb464cc197ad8eefp-2,
    0x1.800002p-1
  },
  { // Entry 156
    0x1.2b80309b166ef76896706dda18a709bdp-1,
    0x1.7ffffep0
  },
  { // Entry 157
    0x1.2b803473f7ad0f3f401624140d175ba2p-1,
    0x1.80p0
  },
  { // Entry 158
    0x1.2b80384cd8e605e99a5cd99f34293888p-1,
    0x1.800002p0
  },
  { // Entry 159
    0x1.ebc51464ccd66f10e7d234a2a0ce225fp-9,
    0x1.00aaa8p0
  },
  { // Entry 160
    0x1.ebcad5e05d58c6ddfd6c09c193fb3e3ep-9,
    0x1.00aaaap0
  },
  { // Entry 161
    0x1.ebd0975be25fcf1843facabaa7aa7b51p-9,
    0x1.00aaacp0
  },
  { // Entry 162
    0x1.fffffe8eab88f49d947a1043320972d1p0,
    0x1.fffffep1
  },
  { // Entry 163
    0x1.p1,
    0x1.p2
  },
  { // Entry 164
    0x1.000001715474e163bb7b2fe80f7d7b91p1,
    0x1.000002p2
  },
  { // Entry 165
    0x1.fffffd1d5711e93b28f420866412e5a2p-1,
    0x1.fffffep0
  },
  { // Entry 166
    0x1.p0,
    0x1.p1
  },
  { // Entry 167
    0x1.000002e2a8e9c2c776f65fd01efaf723p0,
    0x1.000002p1
  },
  { // Entry 168
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 169
    0.0,
    0x1.p0
  },
  { // Entry 170
    0x1.715474e163bb7b2fe80f7d7b91f1851cp-23,
    0x1.000002p0
  },
  { // Entry 171
    -0x1.0000017154770b626b85efbccdf68d2ep0,
    0x1.fffffep-2
  },
  { // Entry 172
    -0x1.p0,
    0x1.p-1
  },
  { // Entry 173
    -0x1.fffffa3aae2c7a711213405fc20a11b8p-1,
    0x1.000002p-1
  },
  { // Entry 174
    -0x1.000000b8aa3b85b135c2f7de66fb4697p1,
    0x1.fffffep-3
  },
  { // Entry 175
    -0x1.p1,
    0x1.p-2
  },
  { // Entry 176
    -0x1.fffffd1d57163d388909a02fe10508dcp0,
    0x1.000002p-2
  },
  { // Entry 177
    -0x1.800000b8aa3b85b135c2f7de66fb4697p1,
    0x1.fffffep-4
  },
  { // Entry 178
    -0x1.80p1,
    0x1.p-3
  },
  { // Entry 179
    -0x1.7ffffe8eab8b1e9c4484d017f082846ep1,
    0x1.000002p-3
  },
  { // Entry 180
    -0x1.0000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-5
  },
  { // Entry 181
    -0x1.p2,
    0x1.p-4
  },
  { // Entry 182
    -0x1.fffffe8eab8b1e9c4484d017f082846ep1,
    0x1.000002p-4
  },
  { // Entry 183
    -0x1.4000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-6
  },
  { // Entry 184
    -0x1.40p2,
    0x1.p-5
  },
  { // Entry 185
    -0x1.3fffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-5
  },
  { // Entry 186
    -0x1.8000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-7
  },
  { // Entry 187
    -0x1.80p2,
    0x1.p-6
  },
  { // Entry 188
    -0x1.7fffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-6
  },
  { // Entry 189
    -0x1.c000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-8
  },
  { // Entry 190
    -0x1.c0p2,
    0x1.p-7
  },
  { // Entry 191
    -0x1.bfffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-7
  },
  { // Entry 192
    -0x1.0000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-9
  },
  { // Entry 193
    -0x1.p3,
    0x1.p-8
  },
  { // Entry 194
    -0x1.ffffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-8
  },
  { // Entry 195
    -0x1.2000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-10
  },
  { // Entry 196
    -0x1.20p3,
    0x1.p-9
  },
  { // Entry 197
    -0x1.1fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-9
  },
  { // Entry 198
    -0x1.4000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-11
  },
  { // Entry 199
    -0x1.40p3,
    0x1.p-10
  },
  { // Entry 200
    -0x1.3fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-10
  },
  { // Entry 201
    -0x1.a000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-14
  },
  { // Entry 202
    -0x1.a0p3,
    0x1.p-13
  },
  { // Entry 203
    -0x1.9fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-13
  },
  { // Entry 204
    -0x1.a000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-14
  },
  { // Entry 205
    -0x1.a0p3,
    0x1.p-13
  },
  { // Entry 206
    -0x1.9fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-13
  },
  { // Entry 207
    -0x1.800000b8aa3b85b135c2f7de66fb4697p1,
    0x1.fffffep-4
  },
  { // Entry 208
    -0x1.80p1,
    0x1.p-3
  },
  { // Entry 209
    -0x1.7ffffe8eab8b1e9c4484d017f082846ep1,
    0x1.000002p-3
  },
  { // Entry 210
    -0x1.8a898ddcb6efed6595efafc5e077a1cbp-3,
    0x1.bffffep-1
  },
  { // Entry 211
    -0x1.8a8980abfbd32666a9b7e2df60d2bdc6p-3,
    0x1.c0p-1
  },
  { // Entry 212
    -0x1.8a89737b40c57286b134031126c9c7edp-3,
    0x1.c00002p-1
  },
  { // Entry 213
    -0x1.0000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-5
  },
  { // Entry 214
    -0x1.p2,
    0x1.p-4
  },
  { // Entry 215
    -0x1.fffffe8eab8b1e9c4484d017f082846ep1,
    0x1.000002p-4
  },
  { // Entry 216
    -0x1.7d60620c36d87cfcd8babf751edc0c8bp-4,
    0x1.dffffep-1
  },
  { // Entry 217
    -0x1.7d60496cfbb4c673b4511f8c2b4e4fb7p-4,
    0x1.e0p-1
  },
  { // Entry 218
    -0x1.7d6030cdc0ab535cca1fd50552237b1ep-4,
    0x1.e00002p-1
  },
  { // Entry 219
    -0x1.4000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-6
  },
  { // Entry 220
    -0x1.40p2,
    0x1.p-5
  },
  { // Entry 221
    -0x1.3fffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-5
  },
  { // Entry 222
    -0x1.77397c4562d9e54641f615a6ca2b27bap-5,
    0x1.effffep-1
  },
  { // Entry 223
    -0x1.77394c9d958d55de5c380fe0871d757fp-5,
    0x1.f0p-1
  },
  { // Entry 224
    -0x1.77391cf5c871f7ce6a0d60c3fcc8c0a3p-5,
    0x1.f00002p-1
  },
  { // Entry 225
    -0x1.8000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-7
  },
  { // Entry 226
    -0x1.80p2,
    0x1.p-6
  },
  { // Entry 227
    -0x1.7fffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-6
  },
  { // Entry 228
    -0x1.743f462e4254f5e2be25b8506028d08ap-6,
    0x1.f7fffep-1
  },
  { // Entry 229
    -0x1.743ee861f3556365483611f7c0bf059fp-6,
    0x1.f8p-1
  },
  { // Entry 230
    -0x1.743e8a95a4b51a5c74be0d5ae65aab1bp-6,
    0x1.f80002p-1
  },
  { // Entry 231
    -0x1.c000005c551dc2d89ae17bef337da34bp2,
    0x1.fffffep-8
  },
  { // Entry 232
    -0x1.c0p2,
    0x1.p-7
  },
  { // Entry 233
    -0x1.bfffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-7
  },
  { // Entry 234
    -0x1.72c8743f6fa9cfbe1e287ad19aca6d67p-7,
    0x1.fbfffep-1
  },
  { // Entry 235
    -0x1.72c7ba20f73275b5d184a2c615b70ad4p-7,
    0x1.fcp-1
  },
  { // Entry 236
    -0x1.72c700027f76b150e530a12360d1566ap-7,
    0x1.fc0002p-1
  },
  { // Entry 237
    -0x1.0000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-9
  },
  { // Entry 238
    -0x1.p3,
    0x1.p-8
  },
  { // Entry 239
    -0x1.ffffff4755c58f4e2242680bf8414237p2,
    0x1.000002p-8
  },
  { // Entry 240
    -0x1.720f0ecde68050a44c9a2eb30002eb02p-8,
    0x1.fdfffep-1
  },
  { // Entry 241
    -0x1.720d9c06a835ea6ef18f977e5d8a37abp-8,
    0x1.fep-1
  },
  { // Entry 242
    -0x1.720c293f6b5fbfb29fd6cb29447e6957p-8,
    0x1.fe0002p-1
  },
  { // Entry 243
    -0x1.2000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-10
  },
  { // Entry 244
    -0x1.20p3,
    0x1.p-9
  },
  { // Entry 245
    -0x1.1fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-9
  },
  { // Entry 246
    -0x1.71b3ce5de192eae3e822586249ef1031p-9,
    0x1.fefffep-1
  },
  { // Entry 247
    -0x1.71b0ea42e5fda261dbbd1a498f533398p-9,
    0x1.ffp-1
  },
  { // Entry 248
    -0x1.71ae0627ed4de7a0d25affc95a315118p-9,
    0x1.ff0002p-1
  },
  { // Entry 249
    -0x1.4000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-11
  },
  { // Entry 250
    -0x1.40p3,
    0x1.p-10
  },
  { // Entry 251
    -0x1.3fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-10
  },
  { // Entry 252
    -0x1.71886f5843ade047bd2d072e96484a61p-10,
    0x1.ff7ffep-1
  },
  { // Entry 253
    -0x1.7182a894b69c595f7920cea1619c6e57p-10,
    0x1.ff80p-1
  },
  { // Entry 254
    -0x1.717ce1d12f53080ec86587c1ed76029bp-10,
    0x1.ff8002p-1
  },
  { // Entry 255
    -0x1.a000002e2a8ee16c4d70bdf799bed1a5p3,
    0x1.fffffep-14
  },
  { // Entry 256
    -0x1.a0p3,
    0x1.p-13
  },
  { // Entry 257
    -0x1.9fffffa3aae2c7a711213405fc20a11bp3,
    0x1.000002p-13
  },
  { // Entry 258
    -0x1.718867c39aac5ee37685394fe9bfd749p-13,
    0x1.ffeffep-1
  },
  { // Entry 259
    -0x1.715a3bc3593d4d4a2a239745f6427420p-13,
    0x1.fff0p-1
  },
  { // Entry 260
    -0x1.712c0fc345fbad46c2c9f3884df7233ep-13,
    0x1.fff002p-1
  },
  { // Entry 261
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 262
    0x1.fffffffa3aae23d27651e8410cc825cbp6,
    0x1.fffffep127
  },
  { // Entry 263
    0x1.fffffff4755c41df9abefafd93420d88p6,
    0x1.fffffcp127
  },
  { // Entry 264
    0x1.a6c873f5fb93d2711418c769ccf4818ap0,
    0x1.921fb6p1
  },
  { // Entry 265
    0x1.4d90e7ebf727a4e228318ed399e90315p-1,
    0x1.921fb6p0
  },
  { // Entry 266
    0x1.715474e163bb7b2fe80f7d7b91f1851cp-23,
    0x1.000002p0
  },
  { // Entry 267
    0.0,
    0x1.p0
  },
  { // Entry 268
    -0x1.7154770b626b85efbccdf68d2e9789f9p-24,
    0x1.fffffep-1
  },
  { // Entry 269
    -0x1.64de302811b0b63baf9ce258cc2df9d5p-2,
    0x1.921fb6p-1
  },
  { // Entry 270
    -0x1.f7fffff4755c58f4e2242680bf841423p6,
    0x1.000002p-126
  },
  { // Entry 271
    -0x1.f8p6,
    0x1.p-126
  },
  { // Entry 272
    -0x1.f800000b8aa3be20654105026cbdf277p6,
    0x1.fffffcp-127
  },
  { // Entry 273
    -0x1.f80000171547935612438aa6af6b5495p6,
    0x1.fffff8p-127
  },
  { // Entry 274
    -0x1.28p7,
    0x1.p-148
  },
  { // Entry 275
    -0x1.2ap7,
    0x1.p-149
  },
  { // Entry 276
    -HUGE_VALF,
    0.0f
  },
  { // Entry 277
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 278
    0x1.f4p6,
    0x1.p125
  },
  { // Entry 279
    -0x1.fcp6,
    0x1.p-127
  },
  { // Entry 280
    0x1.p0,
    0x1.p1
  },
  { // Entry 281
    0x1.p1,
    0x1.p2
  },
  { // Entry 282
    -0x1.p0,
    0x1.p-1
  }
};
```
Response:
Let's break down the thought process for answering the user's request about the `frexpf_intel_data.handroid` file.

**1. Initial Understanding and Scope:**

The first step is to understand what the file *is*. The path `bionic/tests/math_data/frexpf_intel_data.handroid` immediately gives us key information:

* **`bionic`:** This is Android's C library. This means the file is related to core system functionality in Android.
* **`tests`:** This strongly suggests the file isn't core code, but rather data used for testing.
* **`math_data`:**  Confirms it's data for mathematical functions.
* **`frexpf_intel_data`:**  This gives us the crucial function name: `frexpf`. The `intel_data` part hints it might be specific to Intel architectures or used for cross-platform testing.
* **`.handroid`:** This likely indicates a format specific to Android's testing infrastructure.

**2. Identifying the Core Function:**

The filename points to `frexpf`. The next step is to understand what `frexpf` does. A quick mental check or a search for "C library frexpf" reveals its purpose:

* **Function:**  `frexpf` (and its double precision counterpart `frexp`) decomposes a floating-point number into a normalized fraction and an integer exponent of 2.

**3. Analyzing the Data Structure:**

The C++ code defines `g_frexpf_intel_data` as an array of `data_1_int_1_t<float, float>`. Looking at the structure of the data, each element is a triplet:

```c++
{ input_float, expected_exponent_as_int, expected_fraction_float }
```

The floating-point numbers are represented in hexadecimal floating-point notation (e.g., `0x1.p-1`). This notation is precise and avoids issues with decimal representation.

**4. Connecting to Android Functionality:**

Knowing that `frexpf` is a standard C library function, its presence in Android's bionic is expected. It's a fundamental building block for more complex mathematical operations. The testing aspect indicates a focus on ensuring correctness and robustness on Android.

**5. Explaining `frexpf` Implementation (Conceptual):**

Since the file is *test data*, it doesn't contain the *implementation* of `frexpf`. However, the request asks for an explanation of how it *works*. The key idea is to:

* **Extract the sign, exponent, and mantissa** from the floating-point number's bit representation.
* **Normalize the mantissa:**  Adjust the exponent until the mantissa is in the range [0.5, 1) or [1, 2), depending on the convention. The standard convention for `frexpf` is [0.5, 1).
* **Return the normalized mantissa and the adjusted exponent.**

**6. Dynamic Linker Aspect (Addressing the Request Even if Not Directly Relevant):**

While this specific data file doesn't directly involve the dynamic linker, the request specifically asks about it. Therefore, a general explanation of how the dynamic linker handles libc functions is needed:

* **Shared Objects (.so):**  `libc.so` is the core C library shared object.
* **Linking Process:** When an application uses `frexpf`, the dynamic linker resolves the symbol to the implementation within `libc.so`.
* **PLT/GOT:** Briefly explain the role of the Procedure Linkage Table (PLT) and Global Offset Table (GOT) in lazy binding.

**7. Logic Inference and Examples:**

The data itself provides examples of input and expected output. We can pick a few entries and manually verify the `frexpf` behavior. For instance:

* **Input:** `0x1.p-1` (0.5)
* **Expected Exponent:** 0 (since 0.5 * 2<sup>0</sup> = 0.5)
* **Expected Fraction:** `0x1.p-1` (0.5)  -- Here the mantissa is already normalized to [0.5, 1).

Another example:

* **Input:** `0x1.99999cp-1` (slightly more than 0.5)
* **Expected Exponent:** 0
* **Expected Fraction:**  The input value itself as it's already within the normalized range.

**8. Common Usage Errors:**

Think about how a programmer might misuse `frexpf`:

* **Incorrect Interpretation of the Exponent:** Not understanding that the exponent is a power of 2.
* **Ignoring the Fraction:**  Only using the exponent and discarding the fractional part when it might be important.
* **Assuming Integer Input:**  Trying to use `frexpf` on an integer type.

**9. Android Framework/NDK Path and Frida Hook:**

Trace how a call to `frexpf` might originate:

* **Java Framework:**  Potentially through JNI calls to native code.
* **NDK:** Directly from C/C++ code using the standard `<math.h>` header.
* **System Services:**  Android system services (written in C++) also use libc functions.

A Frida hook example needs to target the `frexpf` function within the `libc.so` library.

**10. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Address each part of the user's request.

**Self-Correction/Refinement During the Process:**

* **Initially, I might have focused too much on the "intel_data" part.**  Realizing this is likely just a naming convention for a set of test data is important. The core functionality is still `frexpf`.
* **I need to be careful not to confuse the *test data* with the *implementation* of `frexpf`.** The file provides input/output pairs, not the code itself.
* **The dynamic linker part requires a general explanation**, as this specific file doesn't directly demonstrate dynamic linking in action. It's about how `frexpf` *itself* is linked.
* **Frida hook examples need to be concrete and target the right library.**

By following these steps, and constantly refining the understanding and the explanation, we arrive at a comprehensive and accurate answer to the user's complex query.
这个 `bionic/tests/math_data/frexpf_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `frexpf` 函数的数据集。它包含了一系列预定义的输入值以及对应的预期输出值，用于验证 `frexpf` 函数在不同输入情况下的正确性。

**功能:**

1. **测试 `frexpf` 函数的正确性:**  该文件提供了大量的测试用例，涵盖了 `frexpf` 函数可能遇到的各种输入，包括正数、负数、接近零的数、接近无穷大的数等等。
2. **回归测试:**  当 Bionic 库的 `frexpf` 函数被修改后，可以使用这个数据集进行回归测试，确保修改没有引入新的错误。
3. **跨平台测试（可能）:** 文件名中的 "intel_data" 可能暗示这个数据集最初是为了在 Intel 架构上测试而创建的，或者用于对比不同架构下 `frexpf` 的行为。然而，从文件的内容来看，它主要关注 `frexpf` 的通用行为，而不一定只针对 Intel 特性。

**与 Android 功能的关系及举例说明:**

`frexpf` 是一个标准的 C 库函数，属于 `math.h` 头文件的一部分。它在 Android 系统中被广泛使用，因为它提供了将浮点数分解为规范化尾数和 2 的幂次方的功能。这在很多底层数学运算和数值处理中非常有用。

**举例说明:**

* **图形渲染:**  图形库在进行坐标变换、光照计算等操作时，可能会用到 `frexpf` 来提取浮点数的指数部分，以便进行快速的缩放和调整。
* **音频处理:**  音频编解码器在处理音频信号时，可能需要对浮点数表示的音频样本进行规范化，`frexpf` 可以用于此目的。
* **科学计算:**  任何涉及到浮点数运算的 Android 应用，例如进行物理模拟、数据分析等的应用，都可能间接地使用到 `frexpf`。

**详细解释 `frexpf` 函数的功能是如何实现的:**

`frexpf` 函数的原型如下：

```c
float frexpf(float x, int *exponent);
```

它的功能是将浮点数 `x` 分解为一个介于 0.5（包含）到 1.0（不包含）之间的规范化尾数（mantissa）和一个整数指数 `exponent`，使得 `x = mantissa * 2^exponent`。

**实现原理（概念性解释）：**

1. **处理特殊情况:** 首先，`frexpf` 会处理一些特殊情况，例如：
   * 如果 `x` 是 0，则尾数为 0，指数为 0。
   * 如果 `x` 是无穷大或 NaN (Not a Number)，则尾数不变，指数未定义（通常设置为 0 或保持原值）。

2. **提取符号、指数和尾数:** 对于非特殊情况，`frexpf` 会访问浮点数 `x` 的内存表示（通常符合 IEEE 754 标准），提取其符号位、指数部分和尾数部分。

3. **规范化尾数:**  提取出的尾数可能不是规范化的（即小数点不在最高有效位之后）。`frexpf` 会调整指数，并相应地移动尾数的小数点，直到尾数落在 [0.5, 1.0) 区间内。

   * 例如，如果 `x` 的二进制表示为 `1.something * 2^n`，`frexpf` 需要将其转换为 `0.something_adjusted * 2^(n+k)` 的形式，其中 `0.something_adjusted` 在 0.5 到 1.0 之间。

4. **设置指数:**  调整后的指数值会存储到 `exponent` 指针指向的内存位置。

5. **返回规范化尾数:**  函数返回计算出的规范化尾数。

**示例：**

假设输入 `x = 12.0f`。

1. `12.0f` 的二进制表示大致为 `1.100 * 2^3`。
2. `frexpf` 会将尾数规范化为 `0.1100`（二进制），相当于十进制的 `0.75`。
3. 为了保持值不变，指数需要调整为 `3 + 1 = 4`。
4. 因此，`frexpf(12.0f, &exponent)` 会返回 `0.75`，并且 `exponent` 指向的内存会存储值 `4`。

**涉及 dynamic linker 的功能 (虽然此文件本身不涉及):**

`frexpf` 函数的实现位于 `libc.so` 这个动态链接库中。当一个 Android 应用或系统组件调用 `frexpf` 时，动态链接器负责将该调用链接到 `libc.so` 中 `frexpf` 函数的实际代码。

**so 布局样本:**

```
/system/lib/libc.so:
    ... (其他代码段) ...
    .text:
        ...
        <frexpf 函数的机器码>
        ...
    .data:
        ...
    .bss:
        ...
    .dynsym:  // 动态符号表
        ...
        frexpf  // 指向 .text 段中 frexpf 函数的入口地址
        ...
    .dynstr:  // 动态字符串表
        ...
        frexpf
        ...
    .plt:     // 程序链接表 (Procedure Linkage Table)
        ...
        <frexpf 的 PLT 条目>
        ...
    .got:     // 全局偏移表 (Global Offset Table)
        ...
        <frexpf 的 GOT 条目>
        ...
```

**链接的处理过程:**

1. **编译时:** 编译器遇到 `frexpf` 函数调用时，会生成一个对该函数的外部引用。
2. **链接时:** 静态链接器在生成可执行文件或共享库时，会将这些外部引用记录下来，并生成相应的 PLT 和 GOT 条目。
3. **运行时:** 当程序首次执行到 `frexpf` 的调用时：
   * **PLT 条目被执行:** PLT 条目中的代码会跳转到与其关联的 GOT 条目。
   * **GOT 条目初始状态:**  最初，GOT 条目中存储的是动态链接器的地址。
   * **动态链接器介入:** 跳转到动态链接器后，动态链接器会查找 `libc.so` 中 `frexpf` 函数的实际地址。
   * **地址解析和更新:** 动态链接器将 `frexpf` 的实际地址写入到 `frexpf` 对应的 GOT 条目中。
   * **跳转到目标函数:** 动态链接器最终跳转到 `frexpf` 函数的实际代码执行。
   * **后续调用:**  后续对 `frexpf` 的调用会直接通过 GOT 条目跳转到其真实地址，避免了重复的动态链接过程 (这称为延迟绑定或懒加载)。

**逻辑推理、假设输入与输出:**

文件中的每一项都是一个逻辑推理的例子，它假设了特定的输入，并给出了 `frexpf` 函数应该产生的输出。

**例如，Entry 0:**

* **假设输入:** `0x1.p-1` (十六进制浮点数表示，等于 0.5)
* **预期输出（尾数）:** `0x1.p100` (注意这里理解有误，应该是 0.5 或者用十六进制表示 `0x1.0p-1`)。 这个数据文件似乎将尾数部分做了某种转换，但其根本意义仍是代表规范化的尾数。
* **预期输出（指数，作为整数存储）:** `(int)0x1.94p6` (这个值看起来很奇怪，并不像是直接的指数值。  通常 `frexpf` 返回的指数是整数，代表 2 的幂次方。  **这里需要特别注意，`frexpf_intel_data.handroid` 的结构 `<float, int, float>`，第二个 `float` 字段实际上是测试用例的 *原始输入值*，而不是 `frexpf` 的尾数输出。  而 `int` 字段是期望的指数。**)

**正确的理解 Entry 0:**

* **输入浮点数:** `0x1.p-1` (0.5)
* **预期输出指数:** `(int)0x1.94p6` (这个值很可能是一个经过编码或转换的期望指数值，或者测试框架特定的标记。 **需要查看测试代码才能确定其确切含义。  但根据 `frexpf` 的定义，期望的指数应该是 0。**)
* **用于验证的另一个浮点数:** `0x1.p100` (这个值可能是基于输入和预期指数计算出来的，用于后续的验证步骤，例如验证 `ldexpf` 的行为，`ldexpf` 是 `frexpf` 的逆操作)。

**重新审视数据结构:**

```c++
static data_1_int_1_t<float, float> g_frexpf_intel_data[] = {
  { // Entry 0
    0x1.p-1, // 输入值
    (int)0x1.94p6, // 预期输出指数 (经过某种编码或转换)
    0x1.p100  // 用于验证或对比的值
  },
  ...
};
```

**结论：** 该数据文件并非直接存储 `frexpf` 的输入和输出尾数，而是存储了输入值、某种形式的预期指数，以及可能用于后续验证步骤的其他值。  要完全理解预期指数的含义，需要查看使用这个数据文件的测试代码。

**涉及用户或编程常见的使用错误:**

1. **不理解指数的含义:** 开发者可能会错误地认为 `frexpf` 返回的指数是 10 的幂次方，而不是 2 的幂次方。
2. **忽略尾数的范围:**  开发者可能忘记 `frexpf` 返回的尾数在 0.5 到 1.0 之间，导致后续计算错误。
3. **错误地使用返回值:**  有时开发者可能混淆了 `frexpf` 的返回值（尾数）和通过指针传递的指数。
4. **不处理特殊情况:**  未能正确处理输入为 0、无穷大或 NaN 的情况。

**Frida hook 示例调试步骤:**

假设你想 hook `frexpf` 函数，查看其输入和输出。

**Frida hook 代码示例:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

session = frida.get_usb_device().attach('目标进程')  # 将 '目标进程' 替换为你的应用进程名或 PID

script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "frexpf"), {
  onEnter: function(args) {
    this.x = args[0]; // 保存输入值
    console.log("\\n[*] Calling frexpf with input: " + this.x);
  },
  onLeave: function(retval) {
    var exponentPtr = this.context.r1; // 或根据架构使用 sp+offset 等方式获取 exponent 指针
    var exponent = Memory.readS32(exponentPtr);
    console.log("[*] frexpf returned mantissa: " + retval + ", exponent: " + exponent);
  }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **确定目标进程:**  找到你想调试的应用的进程名或 PID。
2. **编写 Frida hook 脚本:**  使用 `Interceptor.attach` 监听 `libc.so` 中导出的 `frexpf` 函数。
3. **`onEnter`:** 在 `frexpf` 函数被调用前执行，可以获取输入参数。
4. **`onLeave`:** 在 `frexpf` 函数执行完毕后执行，可以获取返回值和通过指针修改的 `exponent` 值。  **注意，获取指针指向的值需要根据目标架构和调用约定来确定如何读取内存。 上面的示例假设 `exponent` 指针作为第二个参数传递，并且在 ARM 架构下可能存储在 `r1` 寄存器中。 这需要根据实际情况调整。** 更可靠的方式是通过分析函数的参数传递方式，例如在 ARM64 中，参数通常放在 x0, x1 等寄存器中，而指针类型的参数则指向内存地址。
5. **运行 Frida 脚本:**  使用 `frida -U -f 你的应用包名` 或 `frida -U 目标进程` 运行脚本。
6. **触发 `frexpf` 调用:**  在目标应用中执行一些操作，使其调用到 `frexpf` 函数。
7. **查看 Frida 输出:**  Frida 会打印出 `frexpf` 的输入和输出，帮助你理解函数的行为。

**更精确的 Frida hook (通用性更强):**

```python
import frida
import sys
import struct

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

session = frida.get_usb_device().attach('目标进程')

script = session.create_script("""
var frexpfPtr = Module.findExportByName("libc.so", "frexpf");

Interceptor.attach(frexpfPtr, {
  onEnter: function(args) {
    this.x = args[0].readFloat();
    this.exponentPtr = ptr(args[1]);
    console.log("\\n[*] Calling frexpf with input: " + this.x);
  },
  onLeave: function(retval) {
    var exponent = this.exponentPtr.readS32();
    console.log("[*] frexpf returned mantissa: " + retval + ", exponent: " + exponent);
  }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个更精确的示例直接读取了 `float` 类型的输入参数，并使用 `ptr()` 将 `args[1]` 转换为 Frida 的 `NativePointer` 对象，然后读取其指向的整数值。这更符合 `frexpf` 的函数签名。

希望以上详细解释能够帮助你理解 `bionic/tests/math_data/frexpf_intel_data.handroid` 文件以及 `frexpf` 函数在 Android 系统中的作用和调试方法。

### 提示词
```
这是目录为bionic/tests/math_data/frexpf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_int_1_t<float, float> g_frexpf_intel_data[] = {
  { // Entry 0
    0x1.p-1,
    (int)0x1.94p6,
    0x1.p100
  },
  { // Entry 1
    0x1.19999ap-1,
    (int)0x1.94p6,
    0x1.19999ap100
  },
  { // Entry 2
    0x1.333334p-1,
    (int)0x1.94p6,
    0x1.333334p100
  },
  { // Entry 3
    0x1.4ccccep-1,
    (int)0x1.94p6,
    0x1.4ccccep100
  },
  { // Entry 4
    0x1.666668p-1,
    (int)0x1.94p6,
    0x1.666668p100
  },
  { // Entry 5
    0x1.800002p-1,
    (int)0x1.94p6,
    0x1.800002p100
  },
  { // Entry 6
    0x1.99999cp-1,
    (int)0x1.94p6,
    0x1.99999cp100
  },
  { // Entry 7
    0x1.b33336p-1,
    (int)0x1.94p6,
    0x1.b33336p100
  },
  { // Entry 8
    0x1.ccccd0p-1,
    (int)0x1.94p6,
    0x1.ccccd0p100
  },
  { // Entry 9
    0x1.e6666ap-1,
    (int)0x1.94p6,
    0x1.e6666ap100
  },
  { // Entry 10
    0x1.p-1,
    (int)0x1.98p6,
    0x1.p101
  },
  { // Entry 11
    -0x1.p-1,
    (int)0x1.98p6,
    -0x1.p101
  },
  { // Entry 12
    -0x1.e66666p-1,
    (int)0x1.94p6,
    -0x1.e66666p100
  },
  { // Entry 13
    -0x1.ccccccp-1,
    (int)0x1.94p6,
    -0x1.ccccccp100
  },
  { // Entry 14
    -0x1.b33332p-1,
    (int)0x1.94p6,
    -0x1.b33332p100
  },
  { // Entry 15
    -0x1.999998p-1,
    (int)0x1.94p6,
    -0x1.999998p100
  },
  { // Entry 16
    -0x1.7ffffep-1,
    (int)0x1.94p6,
    -0x1.7ffffep100
  },
  { // Entry 17
    -0x1.666664p-1,
    (int)0x1.94p6,
    -0x1.666664p100
  },
  { // Entry 18
    -0x1.4ccccap-1,
    (int)0x1.94p6,
    -0x1.4ccccap100
  },
  { // Entry 19
    -0x1.333330p-1,
    (int)0x1.94p6,
    -0x1.333330p100
  },
  { // Entry 20
    -0x1.199996p-1,
    (int)0x1.94p6,
    -0x1.199996p100
  },
  { // Entry 21
    -0x1.p-1,
    (int)0x1.94p6,
    -0x1.p100
  },
  { // Entry 22
    0x1.p-1,
    (int)0x1.60p4,
    0x1.p21
  },
  { // Entry 23
    0x1.19999ap-1,
    (int)0x1.60p4,
    0x1.19999ap21
  },
  { // Entry 24
    0x1.333334p-1,
    (int)0x1.60p4,
    0x1.333334p21
  },
  { // Entry 25
    0x1.4ccccep-1,
    (int)0x1.60p4,
    0x1.4ccccep21
  },
  { // Entry 26
    0x1.666668p-1,
    (int)0x1.60p4,
    0x1.666668p21
  },
  { // Entry 27
    0x1.800002p-1,
    (int)0x1.60p4,
    0x1.800002p21
  },
  { // Entry 28
    0x1.99999cp-1,
    (int)0x1.60p4,
    0x1.99999cp21
  },
  { // Entry 29
    0x1.b33336p-1,
    (int)0x1.60p4,
    0x1.b33336p21
  },
  { // Entry 30
    0x1.ccccd0p-1,
    (int)0x1.60p4,
    0x1.ccccd0p21
  },
  { // Entry 31
    0x1.e6666ap-1,
    (int)0x1.60p4,
    0x1.e6666ap21
  },
  { // Entry 32
    0x1.p-1,
    (int)0x1.70p4,
    0x1.p22
  },
  { // Entry 33
    0x1.p-1,
    (int)0x1.70p4,
    0x1.p22
  },
  { // Entry 34
    0x1.19999ap-1,
    (int)0x1.70p4,
    0x1.19999ap22
  },
  { // Entry 35
    0x1.333334p-1,
    (int)0x1.70p4,
    0x1.333334p22
  },
  { // Entry 36
    0x1.4ccccep-1,
    (int)0x1.70p4,
    0x1.4ccccep22
  },
  { // Entry 37
    0x1.666668p-1,
    (int)0x1.70p4,
    0x1.666668p22
  },
  { // Entry 38
    0x1.800002p-1,
    (int)0x1.70p4,
    0x1.800002p22
  },
  { // Entry 39
    0x1.99999cp-1,
    (int)0x1.70p4,
    0x1.99999cp22
  },
  { // Entry 40
    0x1.b33336p-1,
    (int)0x1.70p4,
    0x1.b33336p22
  },
  { // Entry 41
    0x1.ccccd0p-1,
    (int)0x1.70p4,
    0x1.ccccd0p22
  },
  { // Entry 42
    0x1.e6666ap-1,
    (int)0x1.70p4,
    0x1.e6666ap22
  },
  { // Entry 43
    0x1.p-1,
    (int)0x1.80p4,
    0x1.p23
  },
  { // Entry 44
    0x1.p-1,
    (int)0x1.80p4,
    0x1.p23
  },
  { // Entry 45
    0x1.19999ap-1,
    (int)0x1.80p4,
    0x1.19999ap23
  },
  { // Entry 46
    0x1.333334p-1,
    (int)0x1.80p4,
    0x1.333334p23
  },
  { // Entry 47
    0x1.4ccccep-1,
    (int)0x1.80p4,
    0x1.4ccccep23
  },
  { // Entry 48
    0x1.666668p-1,
    (int)0x1.80p4,
    0x1.666668p23
  },
  { // Entry 49
    0x1.800002p-1,
    (int)0x1.80p4,
    0x1.800002p23
  },
  { // Entry 50
    0x1.99999cp-1,
    (int)0x1.80p4,
    0x1.99999cp23
  },
  { // Entry 51
    0x1.b33336p-1,
    (int)0x1.80p4,
    0x1.b33336p23
  },
  { // Entry 52
    0x1.ccccd0p-1,
    (int)0x1.80p4,
    0x1.ccccd0p23
  },
  { // Entry 53
    0x1.e6666ap-1,
    (int)0x1.80p4,
    0x1.e6666ap23
  },
  { // Entry 54
    0x1.p-1,
    (int)0x1.90p4,
    0x1.p24
  },
  { // Entry 55
    0x1.p-1,
    (int)0x1.90p4,
    0x1.p24
  },
  { // Entry 56
    0x1.19999ap-1,
    (int)0x1.90p4,
    0x1.19999ap24
  },
  { // Entry 57
    0x1.333334p-1,
    (int)0x1.90p4,
    0x1.333334p24
  },
  { // Entry 58
    0x1.4ccccep-1,
    (int)0x1.90p4,
    0x1.4ccccep24
  },
  { // Entry 59
    0x1.666668p-1,
    (int)0x1.90p4,
    0x1.666668p24
  },
  { // Entry 60
    0x1.800002p-1,
    (int)0x1.90p4,
    0x1.800002p24
  },
  { // Entry 61
    0x1.99999cp-1,
    (int)0x1.90p4,
    0x1.99999cp24
  },
  { // Entry 62
    0x1.b33336p-1,
    (int)0x1.90p4,
    0x1.b33336p24
  },
  { // Entry 63
    0x1.ccccd0p-1,
    (int)0x1.90p4,
    0x1.ccccd0p24
  },
  { // Entry 64
    0x1.e6666ap-1,
    (int)0x1.90p4,
    0x1.e6666ap24
  },
  { // Entry 65
    0x1.p-1,
    (int)0x1.a0p4,
    0x1.p25
  },
  { // Entry 66
    0x1.p-1,
    (int)-0x1.02p7,
    0x1.p-130
  },
  { // Entry 67
    0x1.d33330p-1,
    (int)-0x1.fcp6,
    0x1.d33330p-128
  },
  { // Entry 68
    0x1.b33330p-1,
    (int)-0x1.f8p6,
    0x1.b33330p-127
  },
  { // Entry 69
    0x1.3e6664p-1,
    (int)-0x1.f4p6,
    0x1.3e6664p-126
  },
  { // Entry 70
    0x1.a33330p-1,
    (int)-0x1.f4p6,
    0x1.a33330p-126
  },
  { // Entry 71
    0x1.03fffep-1,
    (int)-0x1.f0p6,
    0x1.03fffep-125
  },
  { // Entry 72
    0x1.366664p-1,
    (int)-0x1.f0p6,
    0x1.366664p-125
  },
  { // Entry 73
    0x1.68cccap-1,
    (int)-0x1.f0p6,
    0x1.68cccap-125
  },
  { // Entry 74
    0x1.9b3330p-1,
    (int)-0x1.f0p6,
    0x1.9b3330p-125
  },
  { // Entry 75
    0x1.cd9996p-1,
    (int)-0x1.f0p6,
    0x1.cd9996p-125
  },
  { // Entry 76
    0x1.fffffcp-1,
    (int)-0x1.f0p6,
    0x1.fffffcp-125
  },
  { // Entry 77
    0x1.fffffep-1,
    (int)0x1.60p4,
    0x1.fffffep21
  },
  { // Entry 78
    0x1.p-1,
    (int)0x1.70p4,
    0x1.p22
  },
  { // Entry 79
    0x1.000002p-1,
    (int)0x1.70p4,
    0x1.000002p22
  },
  { // Entry 80
    0x1.fffffep-1,
    (int)0x1.70p4,
    0x1.fffffep22
  },
  { // Entry 81
    0x1.p-1,
    (int)0x1.80p4,
    0x1.p23
  },
  { // Entry 82
    0x1.000002p-1,
    (int)0x1.80p4,
    0x1.000002p23
  },
  { // Entry 83
    0x1.fffffep-1,
    (int)0x1.80p4,
    0x1.fffffep23
  },
  { // Entry 84
    0x1.p-1,
    (int)0x1.90p4,
    0x1.p24
  },
  { // Entry 85
    0x1.000002p-1,
    (int)0x1.90p4,
    0x1.000002p24
  },
  { // Entry 86
    -0x1.000002p-1,
    (int)0x1.70p4,
    -0x1.000002p22
  },
  { // Entry 87
    -0x1.p-1,
    (int)0x1.70p4,
    -0x1.p22
  },
  { // Entry 88
    -0x1.fffffep-1,
    (int)0x1.60p4,
    -0x1.fffffep21
  },
  { // Entry 89
    -0x1.000002p-1,
    (int)0x1.80p4,
    -0x1.000002p23
  },
  { // Entry 90
    -0x1.p-1,
    (int)0x1.80p4,
    -0x1.p23
  },
  { // Entry 91
    -0x1.fffffep-1,
    (int)0x1.70p4,
    -0x1.fffffep22
  },
  { // Entry 92
    -0x1.000002p-1,
    (int)0x1.90p4,
    -0x1.000002p24
  },
  { // Entry 93
    -0x1.p-1,
    (int)0x1.90p4,
    -0x1.p24
  },
  { // Entry 94
    -0x1.fffffep-1,
    (int)0x1.80p4,
    -0x1.fffffep23
  },
  { // Entry 95
    0x1.fffffep-1,
    (int)0x1.p7,
    0x1.fffffep127
  },
  { // Entry 96
    -0x1.fffffep-1,
    (int)0x1.p7,
    -0x1.fffffep127
  },
  { // Entry 97
    0x1.fffffep-1,
    (int)-0x1.80p2,
    0x1.fffffep-7
  },
  { // Entry 98
    0x1.p-1,
    (int)-0x1.40p2,
    0x1.p-6
  },
  { // Entry 99
    0x1.000002p-1,
    (int)-0x1.40p2,
    0x1.000002p-6
  },
  { // Entry 100
    0x1.fffffep-1,
    (int)-0x1.40p2,
    0x1.fffffep-6
  },
  { // Entry 101
    0x1.p-1,
    (int)-0x1.p2,
    0x1.p-5
  },
  { // Entry 102
    0x1.000002p-1,
    (int)-0x1.p2,
    0x1.000002p-5
  },
  { // Entry 103
    0x1.fffffep-1,
    (int)-0x1.p2,
    0x1.fffffep-5
  },
  { // Entry 104
    0x1.p-1,
    (int)-0x1.80p1,
    0x1.p-4
  },
  { // Entry 105
    0x1.000002p-1,
    (int)-0x1.80p1,
    0x1.000002p-4
  },
  { // Entry 106
    0x1.fffffep-1,
    (int)-0x1.80p1,
    0x1.fffffep-4
  },
  { // Entry 107
    0x1.p-1,
    (int)-0x1.p1,
    0x1.p-3
  },
  { // Entry 108
    0x1.000002p-1,
    (int)-0x1.p1,
    0x1.000002p-3
  },
  { // Entry 109
    0x1.fffffep-1,
    (int)-0x1.p1,
    0x1.fffffep-3
  },
  { // Entry 110
    0x1.p-1,
    (int)-0x1.p0,
    0x1.p-2
  },
  { // Entry 111
    0x1.000002p-1,
    (int)-0x1.p0,
    0x1.000002p-2
  },
  { // Entry 112
    0x1.fffffep-1,
    (int)-0x1.p0,
    0x1.fffffep-2
  },
  { // Entry 113
    0x1.p-1,
    (int)0.0,
    0x1.p-1
  },
  { // Entry 114
    0x1.000002p-1,
    (int)0.0,
    0x1.000002p-1
  },
  { // Entry 115
    -0x1.p-1,
    (int)-0x1.28p7,
    -0x1.p-149
  },
  { // Entry 116
    0.0,
    (int)0.0,
    0.0
  },
  { // Entry 117
    0x1.p-1,
    (int)-0x1.28p7,
    0x1.p-149
  },
  { // Entry 118
    0x1.fffffep-1,
    (int)0.0,
    0x1.fffffep-1
  },
  { // Entry 119
    0x1.p-1,
    (int)0x1.p0,
    0x1.p0
  },
  { // Entry 120
    0x1.000002p-1,
    (int)0x1.p0,
    0x1.000002p0
  },
  { // Entry 121
    0x1.fffffep-1,
    (int)0x1.p0,
    0x1.fffffep0
  },
  { // Entry 122
    0x1.p-1,
    (int)0x1.p1,
    0x1.p1
  },
  { // Entry 123
    0x1.000002p-1,
    (int)0x1.p1,
    0x1.000002p1
  },
  { // Entry 124
    0x1.fffffep-1,
    (int)0x1.p1,
    0x1.fffffep1
  },
  { // Entry 125
    0x1.p-1,
    (int)0x1.80p1,
    0x1.p2
  },
  { // Entry 126
    0x1.000002p-1,
    (int)0x1.80p1,
    0x1.000002p2
  },
  { // Entry 127
    0x1.fffffep-1,
    (int)0x1.80p1,
    0x1.fffffep2
  },
  { // Entry 128
    0x1.p-1,
    (int)0x1.p2,
    0x1.p3
  },
  { // Entry 129
    0x1.000002p-1,
    (int)0x1.p2,
    0x1.000002p3
  },
  { // Entry 130
    0x1.fffffep-1,
    (int)0x1.p2,
    0x1.fffffep3
  },
  { // Entry 131
    0x1.p-1,
    (int)0x1.40p2,
    0x1.p4
  },
  { // Entry 132
    0x1.000002p-1,
    (int)0x1.40p2,
    0x1.000002p4
  },
  { // Entry 133
    0x1.fffffep-1,
    (int)0x1.40p2,
    0x1.fffffep4
  },
  { // Entry 134
    0x1.p-1,
    (int)0x1.80p2,
    0x1.p5
  },
  { // Entry 135
    0x1.000002p-1,
    (int)0x1.80p2,
    0x1.000002p5
  },
  { // Entry 136
    0x1.fffffep-1,
    (int)0x1.80p2,
    0x1.fffffep5
  },
  { // Entry 137
    0x1.p-1,
    (int)0x1.c0p2,
    0x1.p6
  },
  { // Entry 138
    0x1.000002p-1,
    (int)0x1.c0p2,
    0x1.000002p6
  },
  { // Entry 139
    0x1.fffffep-1,
    (int)0x1.c0p2,
    0x1.fffffep6
  },
  { // Entry 140
    0x1.p-1,
    (int)0x1.p3,
    0x1.p7
  },
  { // Entry 141
    0x1.000002p-1,
    (int)0x1.p3,
    0x1.000002p7
  },
  { // Entry 142
    HUGE_VALF,
    (int)0,
    HUGE_VALF
  },
  { // Entry 143
    -HUGE_VALF,
    (int)0,
    -HUGE_VALF
  },
  { // Entry 144
    0.0,
    (int)0.0,
    0.0f
  },
  { // Entry 145
    -0.0,
    (int)0.0,
    -0.0f
  },
  { // Entry 146
    0x1.fffffep-1,
    (int)0x1.p7,
    0x1.fffffep127
  },
  { // Entry 147
    -0x1.fffffep-1,
    (int)0x1.p7,
    -0x1.fffffep127
  },
  { // Entry 148
    0x1.fffffcp-1,
    (int)0x1.p7,
    0x1.fffffcp127
  },
  { // Entry 149
    -0x1.fffffcp-1,
    (int)0x1.p7,
    -0x1.fffffcp127
  },
  { // Entry 150
    0x1.921fb6p-1,
    (int)0x1.p1,
    0x1.921fb6p1
  },
  { // Entry 151
    -0x1.921fb6p-1,
    (int)0x1.p1,
    -0x1.921fb6p1
  },
  { // Entry 152
    0x1.921fb6p-1,
    (int)0x1.p0,
    0x1.921fb6p0
  },
  { // Entry 153
    -0x1.921fb6p-1,
    (int)0x1.p0,
    -0x1.921fb6p0
  },
  { // Entry 154
    0x1.000002p-1,
    (int)0x1.p0,
    0x1.000002p0
  },
  { // Entry 155
    -0x1.000002p-1,
    (int)0x1.p0,
    -0x1.000002p0
  },
  { // Entry 156
    0x1.p-1,
    (int)0x1.p0,
    0x1.p0
  },
  { // Entry 157
    -0x1.p-1,
    (int)0x1.p0,
    -0x1.p0
  },
  { // Entry 158
    0x1.fffffep-1,
    (int)0.0,
    0x1.fffffep-1
  },
  { // Entry 159
    -0x1.fffffep-1,
    (int)0.0,
    -0x1.fffffep-1
  },
  { // Entry 160
    0x1.921fb6p-1,
    (int)0.0,
    0x1.921fb6p-1
  },
  { // Entry 161
    -0x1.921fb6p-1,
    (int)0.0,
    -0x1.921fb6p-1
  },
  { // Entry 162
    0x1.000002p-1,
    (int)-0x1.f4p6,
    0x1.000002p-126
  },
  { // Entry 163
    -0x1.000002p-1,
    (int)-0x1.f4p6,
    -0x1.000002p-126
  },
  { // Entry 164
    0x1.p-1,
    (int)-0x1.f4p6,
    0x1.p-126
  },
  { // Entry 165
    -0x1.p-1,
    (int)-0x1.f4p6,
    -0x1.p-126
  },
  { // Entry 166
    0x1.fffffcp-1,
    (int)-0x1.f8p6,
    0x1.fffffcp-127
  },
  { // Entry 167
    -0x1.fffffcp-1,
    (int)-0x1.f8p6,
    -0x1.fffffcp-127
  },
  { // Entry 168
    0x1.fffff8p-1,
    (int)-0x1.f8p6,
    0x1.fffff8p-127
  },
  { // Entry 169
    -0x1.fffff8p-1,
    (int)-0x1.f8p6,
    -0x1.fffff8p-127
  },
  { // Entry 170
    0x1.p-1,
    (int)-0x1.26p7,
    0x1.p-148
  },
  { // Entry 171
    -0x1.p-1,
    (int)-0x1.26p7,
    -0x1.p-148
  },
  { // Entry 172
    0x1.p-1,
    (int)-0x1.28p7,
    0x1.p-149
  },
  { // Entry 173
    -0x1.p-1,
    (int)-0x1.28p7,
    -0x1.p-149
  }
};
```
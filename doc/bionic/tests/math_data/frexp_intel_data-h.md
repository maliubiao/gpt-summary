Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The central task is to analyze the provided C code snippet (`frexp_intel_data.handroid`) and explain its purpose, its relationship to Android, the underlying implementation of related libc functions (specifically `frexp`), and any connections to the dynamic linker. It also requires providing examples of usage, errors, and debugging, along with how Android reaches this code.

**2. Initial Analysis of the Code:**

The code defines a static array `g_frexp_intel_data` of a template type `data_1_int_1_t<double, double>`. Each element of the array is an initializer list containing three values. The comments like `// Entry 0`, `// Entry 1`, etc., clearly indicate this is test data. The values within each entry are represented in hexadecimal floating-point format (e.g., `0x1.p-1`).

**3. Connecting to `frexp`:**

The filename "frexp_intel_data" strongly suggests this data is used for testing the `frexp` function. `frexp` is a standard C library function that decomposes a floating-point number into its normalized fraction and an integer exponent. The structure of the data entries – three values – hints at the input and the two outputs of `frexp`: the input floating-point number, the resulting integer exponent, and the resulting normalized fraction.

**4. Inferring the Purpose of the Test Data:**

The data appears to be a series of test cases for `frexp`. Each entry likely represents:

* **Input:** The first `double` value is the input to the `frexp` function.
* **Expected Exponent:** The second `int` value is the expected integer exponent returned by `frexp`.
* **Expected Significand (Fraction):** The third `double` value is the expected normalized fraction (significand) returned by `frexp`.

The variety of input values (positive, negative, different magnitudes, special values like 0 and HUGE_VAL) further supports this interpretation as a comprehensive test suite. The "intel_data" part likely refers to the specific architecture or scenarios the data targets.

**5. Addressing the "Android Functionality" Aspect:**

Since this code is located within the `bionic/tests/math_data` directory, and bionic is Android's C library, the direct relationship is that this data is *used to test* the implementation of `frexp` within Android's libc. This ensures the correctness and robustness of the math library on Android devices.

**6. Explaining `frexp` Implementation:**

This requires a more detailed explanation of how `frexp` *generally* works. The explanation should cover:

* **Decomposition:**  Breaking down the floating-point number into significand and exponent.
* **Normalization:** Ensuring the significand is within a specific range (typically [0.5, 1) or [1, 2)).
* **Exponent Adjustment:** Adjusting the exponent accordingly during normalization.
* **Handling Special Cases:**  Explaining how `frexp` deals with 0, infinity, and NaN.

It's important to acknowledge that the *exact* implementation might vary depending on the architecture and compiler optimizations, but the core logic remains the same. Since the question mentioned "libc function," focusing on the general principle is key.

**7. Dynamic Linker Considerations:**

The provided code *itself* doesn't directly involve the dynamic linker. It's just static test data. However, the *`frexp` function itself*, as part of the C library, *is* linked dynamically. Therefore, the explanation should cover:

* **Shared Objects (.so):** Where the libc is located (e.g., `libc.so`).
* **Linking Process:** How the dynamic linker resolves the `frexp` symbol when an application uses it. This includes looking up symbols in shared libraries.
* **SO Layout Example:**  A simplified illustration of how `libc.so` might be structured.

**8. Logical Reasoning with Hypothetical Inputs and Outputs:**

To illustrate the functionality, it's beneficial to provide examples. Pick a few entries from the test data and explain how `frexp` would process the input and generate the expected output. This helps solidify the understanding of the function's behavior.

**9. Common Usage Errors:**

Consider typical mistakes developers might make when using `frexp`:

* **Incorrectly interpreting the exponent:** Misunderstanding the bias or the base of the exponent.
* **Ignoring special cases:** Not handling the results for 0, infinity, or NaN.
* **Assuming a specific significand range:**  While common, the exact range might differ slightly across implementations.

**10. Tracing the Call Path and Frida Hooking:**

This involves explaining how a high-level Android function call eventually leads to the execution of `frexp` within the libc. A simplified example could be:

* **Java Framework:**  A high-level math operation in the Android framework.
* **NDK Call:** This might translate to a call to a native function via the NDK.
* **libc Call:** The native function might then call `frexp` from the C library.

The Frida hook example should demonstrate how to intercept the `frexp` function call, log its arguments and return values, enabling inspection of the function's behavior during runtime.

**11. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use formatting (bold text, code blocks) to improve readability. Ensure the language is clear, concise, and accurate. Address each part of the original request comprehensively.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file *implements* `frexp`. **Correction:** The filename and directory suggest it's *test data* for `frexp`.
* **Considering the dynamic linker:** The file itself is static data, but the *function* being tested is part of a dynamically linked library. Therefore, focus on the dynamic linking of `libc` and the `frexp` function.
* **Frida example:** Make sure the Frida script is simple and directly relevant to hooking `frexp`.

By following this structured thought process, addressing each aspect of the prompt methodically, and incorporating necessary background knowledge, one can construct a comprehensive and accurate answer.
好的，让我们详细分析一下这个 `frexp_intel_data.handroid` 文件。

**功能列举**

这个文件定义了一个静态的 C++ 数组 `g_frexp_intel_data`。这个数组的元素类型是 `data_1_int_1_t<double, double>`，这意味着每个元素都包含三个成员：一个 `double` 类型，一个 `int` 类型，和一个 `double` 类型。

从数组名称 `frexp_intel_data` 和数组元素的值（使用十六进制浮点数表示）可以推断出，这个数组很可能是用于测试 `frexp` 函数的测试数据。

`frexp` 函数是 C 标准库 `<math.h>` 中定义的函数，它的功能是将一个浮点数分解为规格化的尾数（mantissa，或称有效数 significand）和一个 2 的幂指数（exponent）。

具体来说，对于一个非零浮点数 `value`，`frexp` 函数会返回一个介于 0.5 (包含) 和 1.0 (不包含) 之间的 `double` 型尾数 `significand`，并且将一个整数值存储在 `exponent` 指针指向的位置，使得 `value = significand * 2^exponent`。

因此，`g_frexp_intel_data` 数组的每一个元素很可能代表一个 `frexp` 函数的测试用例：

* 第一个 `double` 值是 `frexp` 函数的输入值。
* `int` 值是期望的 `frexp` 函数返回的指数部分。
* 第二个 `double` 值是期望的 `frexp` 函数返回的规格化尾数部分。

文件名中包含 "intel_data" 可能表示这些测试数据是针对 Intel 架构的浮点数实现特性设计的，或者最初是在 Intel 平台上生成的。

**与 Android 功能的关系及举例说明**

这个文件是 Android Bionic 库的一部分，Bionic 是 Android 系统的 C 库，提供了与标准 C 库兼容的接口，但也针对 Android 系统的特性进行了优化。`frexp` 函数作为 C 标准库的一部分，自然也在 Bionic 中被实现。

`bionic/tests/math_data` 目录表明这个文件是 Bionic 库中数学函数测试套件的一部分。Android 系统中的各种组件，包括 Framework 层和使用 NDK 开发的 Native 代码，在进行浮点数运算时，最终都会调用 Bionic 库提供的数学函数，包括 `frexp`。

**举例说明：**

假设一个 Android 应用的 Native 代码需要将一个浮点数分解为尾数和指数进行处理。开发者可能会使用 `<cmath>` 头文件中的 `std::frexp` 函数，或者直接使用 `<math.h>` 中的 `frexp` 函数。  Bionic 库会提供这些函数的具体实现。

例如，以下 C++ 代码在 Android NDK 应用中调用了 `frexp`:

```c++
#include <cmath>
#include <android/log.h>

#define TAG "FrexpTest"

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MainActivity_testFrexp(JNIEnv* env, jobject /* this */, double value) {
    int exponent;
    double significand = std::frexp(value, &exponent);
    __android_log_print(ANDROID_LOG_INFO, TAG, "frexp(%f) = %f * 2^%d", value, significand, exponent);
}
```

当这个 Native 函数被 Android Framework 调用时，`std::frexp` 的实现最终会是 Bionic 库中 `frexp` 的实现。  `frexp_intel_data.handroid` 中的数据会被用来测试 Bionic 中 `frexp` 实现的正确性，确保它在各种输入情况下都能返回预期的尾数和指数。

**详细解释 `libc` 函数 `frexp` 的功能是如何实现的**

`frexp` 函数的实现通常涉及到以下步骤：

1. **处理特殊值:** 首先检查输入值 `value` 是否为 0，无穷大 (infinity)，或者 NaN (Not a Number)。
   * 如果 `value` 是 0，则尾数置为 0，指数置为 0。
   * 如果 `value` 是无穷大或 NaN，则尾数保持不变（无穷大或 NaN），指数值未定义或置为 0。

2. **获取符号:** 确定输入值 `value` 的符号，并保存下来。后续处理可以针对绝对值进行，最后再将符号添加到尾数。

3. **提取指数和尾数 (原始形式):**  浮点数在内存中通常以 IEEE 754 标准存储，包含符号位、指数部分和尾数部分。`frexp` 需要提取这些部分。这通常可以通过位操作或者类型双关 (type punning) 的方式实现，将 `double` 类型的内存表示解释为整数类型，然后通过位掩码和移位操作提取指数和尾数。

4. **规格化尾数:**  IEEE 754 标准中，除了 denormalized numbers（极小值）外，normalized numbers 的尾数部分有一个隐含的前导 '1'。  `frexp` 需要将尾数调整到 0.5 到 1.0 之间。这通常涉及对尾数进行移位，并相应地调整指数。

   * 如果尾数是 `1.xxxxx...` 的形式（二进制），则 `frexp` 需要将其转换为 `0.1xxxxx... * 2^1` 的形式。  例如，如果尾数是 `1.101`，`frexp` 会返回 `0.1101`，并将指数增加 1。

5. **设置指数:** 计算并设置最终的指数值。初始的指数是从浮点数表示中提取的，然后根据尾数的规格化过程进行调整。

6. **返回结果:** 将规格化后的尾数作为函数返回值返回，并将计算出的指数存储到传入的 `int *exponent` 指针指向的内存位置。

**示例实现 (简化概念，实际实现可能更复杂):**

```c
#include <math.h>

double my_frexp(double value, int *exponent) {
    if (value == 0.0) {
        *exponent = 0;
        return 0.0;
    }

    // 假设使用 IEEE 754 双精度浮点数
    union {
        double f;
        unsigned long long i;
    } pun;
    pun.f = fabs(value);

    // 提取指数部分 (11 bits) 并去除偏移 (bias)
    int raw_exponent = ((pun.i >> 52) & 0x7FF) - 1023;

    // 提取尾数部分 (52 bits) 并加上隐含的 1
    double significand = 1.0;
    for (int i = 0; i < 52; ++i) {
        if ((pun.i >> (51 - i)) & 1) {
            significand += pow(2.0, -(i + 1));
        }
    }

    // 规格化尾数到 0.5 <= |尾数| < 1.0
    while (significand >= 1.0) {
        significand /= 2.0;
        raw_exponent++;
    }
    while (significand < 0.5 && significand != 0.0) {
        significand *= 2.0;
        raw_exponent--;
    }

    *exponent = raw_exponent;
    return (value > 0.0) ? significand : -significand;
}
```

**涉及 dynamic linker 的功能**

`frexp_intel_data.handroid` 文件本身不直接涉及 dynamic linker 的功能。它只是静态的数据。但是，`frexp` 函数的实现代码位于 Bionic 库的共享对象 (`.so`) 文件中，通常是 `libc.so`。

**SO 布局样本:**

假设 `libc.so` 的布局如下（简化）：

```
libc.so:
    .text:  # 存放可执行代码
        ...
        [frexp 函数的机器码]
        ...
    .data:  # 存放已初始化的全局变量
        ...
    .bss:   # 存放未初始化的全局变量
        ...
    .dynsym: # 动态符号表 (包含导出的函数和变量)
        ...
        frexp (地址指向 .text 段中的 frexp 函数)
        ...
    .dynstr: # 动态字符串表 (存放符号名称)
        ...
        frexp
        ...
    .plt:   # Procedure Linkage Table (过程链接表)
        ...
    .got:   # Global Offset Table (全局偏移表)
        ...
```

**链接的处理过程:**

1. **编译链接阶段:** 当一个 Android 应用的 Native 代码调用 `frexp` 函数时，编译器在链接阶段会生成对 `frexp` 符号的未解析引用。

2. **加载时动态链接:** 当 Android 系统加载应用的可执行文件（通常是一个 `.apk` 包中的 Native 共享库）时，动态链接器 (linker，通常是 `linker` 或 `linker64`) 会介入。

3. **查找共享库:** 动态链接器会检查应用依赖的共享库列表，找到包含 `frexp` 实现的 `libc.so`。

4. **符号解析:** 动态链接器会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `frexp` 符号。

5. **重定位:** 找到 `frexp` 符号后，动态链接器会更新应用的 GOT (Global Offset Table) 中与 `frexp` 相关的条目，将其指向 `libc.so` 中 `frexp` 函数的实际地址。  后续应用代码调用 `frexp` 时，会通过 GOT 跳转到正确的地址。

**假设输入与输出**

根据 `frexp_intel_data.handroid` 中的数据，我们可以给出一些假设的输入和输出：

* **假设输入:** `1.5`
   * **预期输出 (根据 `frexp` 定义):** 尾数接近 `0.75` (因为 `1.5 = 0.75 * 2^1`)，指数为 `1`。  查看 Entry 1，输入是 `0x1.8p+0` (即 1.5)，预期尾数是 `0x1.8p-1` (即 0.75)，指数是 `1` (`0x1p+1`)。

* **假设输入:** `0.125`
   * **预期输出:** 尾数接近 `0.5` (因为 `0.125 = 0.5 * 2^-1`)，指数为 `-1`。 查看 Entry 0，输入接近 `0.5` (`0x1p-1`)，预期尾数是 `0x1p+0` (即 1.0，规格化后)，指数是 `-1` (`-0x1p+0`)。 注意这里的测试数据展示的是 `frexp` 的逆运算，即 `significand * 2^exponent` 得到输入值。

* **假设输入:** `-12.0`
   * **预期输出:** 尾数接近 `-0.75` (因为 `-12.0 = -0.75 * 2^4`)，指数为 `4`。 查看 Entry 34，输入是 `-0x1.8p+3` (-12.0)，预期尾数是 `-0x1.8p-1` (-0.75)，指数是 `4` (`0x1p+2`)。

**用户或编程常见的使用错误**

1. **未正确理解尾数的范围:**  `frexp` 返回的尾数在 `[0.5, 1.0)` 范围内。 开发者可能会错误地假设尾数在其他范围内。

   ```c
   double value = 3.14;
   int exponent;
   double significand = frexp(value, &exponent);
   // 错误假设：significand 的值接近 3.14 / 2^exponent
   ```

2. **忘记处理指数指针:** `frexp` 通过指针返回指数，如果未提供有效的指针，会导致程序崩溃。

   ```c
   double value = 2.718;
   double significand = frexp(value, nullptr); // 潜在的空指针解引用
   ```

3. **将 `frexp` 与 `ldexp` 混淆:** `ldexp` 函数执行相反的操作，即将尾数和指数组合成浮点数。

4. **对特殊值的处理不当:**  没有考虑到输入值为 0、无穷大或 NaN 的情况。

5. **精度问题:** 浮点数运算存在精度问题，直接比较 `frexp` 的结果可能不准确，应该使用误差范围进行比较。

**Android Framework 或 NDK 如何到达这里**

1. **Java Framework 层:**  Android Framework 中涉及到浮点数运算的 Java API，例如 `java.lang.Math` 类中的某些方法，其底层实现可能会调用 Native 代码。

2. **NDK 调用:**  开发者使用 NDK 编写 Native 代码，可以直接调用 C 标准库函数，包括 `frexp`。

3. **JNI 边界:** 当 Java 代码需要调用 Native 代码时，会通过 JNI (Java Native Interface) 进行跨语言调用。

4. **Native 代码执行:** Native 代码中调用 `<math.h>` 中的 `frexp` 函数。

5. **Bionic 库:**  Native 代码中调用的 `frexp` 函数实际上是 Bionic 库提供的实现。当程序加载时，动态链接器会将 Native 库链接到 Bionic 库。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 调试 `frexp` 函数的示例：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const frexpPtr = libc.getExportByName("frexp");

  if (frexpPtr) {
    Interceptor.attach(frexpPtr, {
      onEnter: function (args) {
        const value = args[0].readDouble();
        this.exponentPtr = args[1];
        console.log(`[Freida] Calling frexp(${value})`);
      },
      onLeave: function (retval) {
        const significand = retval.readDouble();
        const exponent = this.exponentPtr.readS32();
        console.log(`[Frida] frexp returned: significand=${significand}, exponent=${exponent}`);
      }
    });
    console.log("[Frida] Attached to frexp");
  } else {
    console.log("[Frida] Could not find frexp in libc.so");
  }
} else {
  console.log("[Frida] This script is for Android.");
}
```

**调试步骤：**

1. **准备环境:** 确保已安装 Frida 和 Python，并配置好 adb 连接到 Android 设备或模拟器。
2. **找到目标进程:** 确定你想要调试的 Android 应用的进程 ID 或进程名称。
3. **运行 Frida 脚本:** 使用 Frida 命令将上述 JavaScript 脚本注入到目标进程中。例如：
   ```bash
   frida -U -f <your_app_package_name> -l your_script.js --no-pause
   ```
   或者，如果已经运行了应用：
   ```bash
   frida -U <process_name_or_pid> -l your_script.js
   ```
4. **触发 `frexp` 调用:** 在你的 Android 应用中执行会调用 `frexp` 函数的操作。例如，如果你的应用有使用浮点数的计算逻辑，或者你之前编写的 NDK 测试代码。
5. **查看 Frida 输出:** Frida 会拦截对 `frexp` 函数的调用，并在控制台上打印出调用时的参数（输入的浮点数）和返回结果（尾数和指数）。

**示例 Frida 输出：**

```
[Frida] Attached to frexp
[Freida] Calling frexp(3.140000104904175)
[Frida] frexp returned: significand=0.7850000262260437, exponent=2
[Freida] Calling frexp(0.125)
[Frida] frexp returned: significand=0.5, exponent=-2
```

这个 Frida 脚本可以帮助你实时观察 `frexp` 函数的调用情况，验证其输入输出，从而辅助调试和理解其行为。

希望以上详细的解答能够帮助你理解 `frexp_intel_data.handroid` 文件及其相关的 Android 技术。

Prompt: 
```
这是目录为bionic/tests/math_data/frexp_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_int_1_t<double, double> g_frexp_intel_data[] = {
  { // Entry 0
    0x1.p-1,
    (int)0x1.94p6,
    0x1.0p100
  },
  { // Entry 1
    0x1.199999999999a0p-1,
    (int)0x1.94p6,
    0x1.199999999999ap100
  },
  { // Entry 2
    0x1.33333333333340p-1,
    (int)0x1.94p6,
    0x1.3333333333334p100
  },
  { // Entry 3
    0x1.4ccccccccccce0p-1,
    (int)0x1.94p6,
    0x1.4cccccccccccep100
  },
  { // Entry 4
    0x1.66666666666680p-1,
    (int)0x1.94p6,
    0x1.6666666666668p100
  },
  { // Entry 5
    0x1.80000000000020p-1,
    (int)0x1.94p6,
    0x1.8000000000002p100
  },
  { // Entry 6
    0x1.999999999999c0p-1,
    (int)0x1.94p6,
    0x1.999999999999cp100
  },
  { // Entry 7
    0x1.b3333333333360p-1,
    (int)0x1.94p6,
    0x1.b333333333336p100
  },
  { // Entry 8
    0x1.cccccccccccdp-1,
    (int)0x1.94p6,
    0x1.cccccccccccd0p100
  },
  { // Entry 9
    0x1.e66666666666a0p-1,
    (int)0x1.94p6,
    0x1.e66666666666ap100
  },
  { // Entry 10
    0x1.p-1,
    (int)0x1.98p6,
    0x1.0p101
  },
  { // Entry 11
    0x1.p-1,
    (int)0x1.92p7,
    0x1.0p200
  },
  { // Entry 12
    0x1.199999999999a0p-1,
    (int)0x1.92p7,
    0x1.199999999999ap200
  },
  { // Entry 13
    0x1.33333333333340p-1,
    (int)0x1.92p7,
    0x1.3333333333334p200
  },
  { // Entry 14
    0x1.4ccccccccccce0p-1,
    (int)0x1.92p7,
    0x1.4cccccccccccep200
  },
  { // Entry 15
    0x1.66666666666680p-1,
    (int)0x1.92p7,
    0x1.6666666666668p200
  },
  { // Entry 16
    0x1.80000000000020p-1,
    (int)0x1.92p7,
    0x1.8000000000002p200
  },
  { // Entry 17
    0x1.999999999999c0p-1,
    (int)0x1.92p7,
    0x1.999999999999cp200
  },
  { // Entry 18
    0x1.b3333333333360p-1,
    (int)0x1.92p7,
    0x1.b333333333336p200
  },
  { // Entry 19
    0x1.cccccccccccdp-1,
    (int)0x1.92p7,
    0x1.cccccccccccd0p200
  },
  { // Entry 20
    0x1.e66666666666a0p-1,
    (int)0x1.92p7,
    0x1.e66666666666ap200
  },
  { // Entry 21
    0x1.p-1,
    (int)0x1.94p7,
    0x1.0p201
  },
  { // Entry 22
    0x1.p-1,
    (int)0x1.f480p9,
    0x1.0p1000
  },
  { // Entry 23
    0x1.199999999999a0p-1,
    (int)0x1.f480p9,
    0x1.199999999999ap1000
  },
  { // Entry 24
    0x1.33333333333340p-1,
    (int)0x1.f480p9,
    0x1.3333333333334p1000
  },
  { // Entry 25
    0x1.4ccccccccccce0p-1,
    (int)0x1.f480p9,
    0x1.4cccccccccccep1000
  },
  { // Entry 26
    0x1.66666666666680p-1,
    (int)0x1.f480p9,
    0x1.6666666666668p1000
  },
  { // Entry 27
    0x1.80000000000020p-1,
    (int)0x1.f480p9,
    0x1.8000000000002p1000
  },
  { // Entry 28
    0x1.999999999999c0p-1,
    (int)0x1.f480p9,
    0x1.999999999999cp1000
  },
  { // Entry 29
    0x1.b3333333333360p-1,
    (int)0x1.f480p9,
    0x1.b333333333336p1000
  },
  { // Entry 30
    0x1.cccccccccccdp-1,
    (int)0x1.f480p9,
    0x1.cccccccccccd0p1000
  },
  { // Entry 31
    0x1.e66666666666a0p-1,
    (int)0x1.f480p9,
    0x1.e66666666666ap1000
  },
  { // Entry 32
    0x1.p-1,
    (int)0x1.f5p9,
    0x1.0p1001
  },
  { // Entry 33
    -0x1.p-1,
    (int)0x1.98p6,
    -0x1.0p101
  },
  { // Entry 34
    -0x1.e6666666666660p-1,
    (int)0x1.94p6,
    -0x1.e666666666666p100
  },
  { // Entry 35
    -0x1.ccccccccccccc0p-1,
    (int)0x1.94p6,
    -0x1.cccccccccccccp100
  },
  { // Entry 36
    -0x1.b3333333333320p-1,
    (int)0x1.94p6,
    -0x1.b333333333332p100
  },
  { // Entry 37
    -0x1.99999999999980p-1,
    (int)0x1.94p6,
    -0x1.9999999999998p100
  },
  { // Entry 38
    -0x1.7fffffffffffe0p-1,
    (int)0x1.94p6,
    -0x1.7fffffffffffep100
  },
  { // Entry 39
    -0x1.66666666666640p-1,
    (int)0x1.94p6,
    -0x1.6666666666664p100
  },
  { // Entry 40
    -0x1.4ccccccccccca0p-1,
    (int)0x1.94p6,
    -0x1.4cccccccccccap100
  },
  { // Entry 41
    -0x1.333333333333p-1,
    (int)0x1.94p6,
    -0x1.3333333333330p100
  },
  { // Entry 42
    -0x1.19999999999960p-1,
    (int)0x1.94p6,
    -0x1.1999999999996p100
  },
  { // Entry 43
    -0x1.p-1,
    (int)0x1.94p6,
    -0x1.0p100
  },
  { // Entry 44
    -0x1.p-1,
    (int)0x1.94p7,
    -0x1.0p201
  },
  { // Entry 45
    -0x1.e6666666666660p-1,
    (int)0x1.92p7,
    -0x1.e666666666666p200
  },
  { // Entry 46
    -0x1.ccccccccccccc0p-1,
    (int)0x1.92p7,
    -0x1.cccccccccccccp200
  },
  { // Entry 47
    -0x1.b3333333333320p-1,
    (int)0x1.92p7,
    -0x1.b333333333332p200
  },
  { // Entry 48
    -0x1.99999999999980p-1,
    (int)0x1.92p7,
    -0x1.9999999999998p200
  },
  { // Entry 49
    -0x1.7fffffffffffe0p-1,
    (int)0x1.92p7,
    -0x1.7fffffffffffep200
  },
  { // Entry 50
    -0x1.66666666666640p-1,
    (int)0x1.92p7,
    -0x1.6666666666664p200
  },
  { // Entry 51
    -0x1.4ccccccccccca0p-1,
    (int)0x1.92p7,
    -0x1.4cccccccccccap200
  },
  { // Entry 52
    -0x1.333333333333p-1,
    (int)0x1.92p7,
    -0x1.3333333333330p200
  },
  { // Entry 53
    -0x1.19999999999960p-1,
    (int)0x1.92p7,
    -0x1.1999999999996p200
  },
  { // Entry 54
    -0x1.p-1,
    (int)0x1.92p7,
    -0x1.0p200
  },
  { // Entry 55
    -0x1.p-1,
    (int)0x1.f5p9,
    -0x1.0p1001
  },
  { // Entry 56
    -0x1.e6666666666660p-1,
    (int)0x1.f480p9,
    -0x1.e666666666666p1000
  },
  { // Entry 57
    -0x1.ccccccccccccc0p-1,
    (int)0x1.f480p9,
    -0x1.cccccccccccccp1000
  },
  { // Entry 58
    -0x1.b3333333333320p-1,
    (int)0x1.f480p9,
    -0x1.b333333333332p1000
  },
  { // Entry 59
    -0x1.99999999999980p-1,
    (int)0x1.f480p9,
    -0x1.9999999999998p1000
  },
  { // Entry 60
    -0x1.7fffffffffffe0p-1,
    (int)0x1.f480p9,
    -0x1.7fffffffffffep1000
  },
  { // Entry 61
    -0x1.66666666666640p-1,
    (int)0x1.f480p9,
    -0x1.6666666666664p1000
  },
  { // Entry 62
    -0x1.4ccccccccccca0p-1,
    (int)0x1.f480p9,
    -0x1.4cccccccccccap1000
  },
  { // Entry 63
    -0x1.333333333333p-1,
    (int)0x1.f480p9,
    -0x1.3333333333330p1000
  },
  { // Entry 64
    -0x1.19999999999960p-1,
    (int)0x1.f480p9,
    -0x1.1999999999996p1000
  },
  { // Entry 65
    -0x1.p-1,
    (int)0x1.f480p9,
    -0x1.0p1000
  },
  { // Entry 66
    0x1.p-1,
    (int)0x1.98p5,
    0x1.0p50
  },
  { // Entry 67
    0x1.199999999999a0p-1,
    (int)0x1.98p5,
    0x1.199999999999ap50
  },
  { // Entry 68
    0x1.33333333333340p-1,
    (int)0x1.98p5,
    0x1.3333333333334p50
  },
  { // Entry 69
    0x1.4ccccccccccce0p-1,
    (int)0x1.98p5,
    0x1.4cccccccccccep50
  },
  { // Entry 70
    0x1.66666666666680p-1,
    (int)0x1.98p5,
    0x1.6666666666668p50
  },
  { // Entry 71
    0x1.80000000000020p-1,
    (int)0x1.98p5,
    0x1.8000000000002p50
  },
  { // Entry 72
    0x1.999999999999c0p-1,
    (int)0x1.98p5,
    0x1.999999999999cp50
  },
  { // Entry 73
    0x1.b3333333333360p-1,
    (int)0x1.98p5,
    0x1.b333333333336p50
  },
  { // Entry 74
    0x1.cccccccccccdp-1,
    (int)0x1.98p5,
    0x1.cccccccccccd0p50
  },
  { // Entry 75
    0x1.e66666666666a0p-1,
    (int)0x1.98p5,
    0x1.e66666666666ap50
  },
  { // Entry 76
    0x1.p-1,
    (int)0x1.a0p5,
    0x1.0p51
  },
  { // Entry 77
    0x1.p-1,
    (int)0x1.a0p5,
    0x1.0p51
  },
  { // Entry 78
    0x1.199999999999a0p-1,
    (int)0x1.a0p5,
    0x1.199999999999ap51
  },
  { // Entry 79
    0x1.33333333333340p-1,
    (int)0x1.a0p5,
    0x1.3333333333334p51
  },
  { // Entry 80
    0x1.4ccccccccccce0p-1,
    (int)0x1.a0p5,
    0x1.4cccccccccccep51
  },
  { // Entry 81
    0x1.66666666666680p-1,
    (int)0x1.a0p5,
    0x1.6666666666668p51
  },
  { // Entry 82
    0x1.80000000000020p-1,
    (int)0x1.a0p5,
    0x1.8000000000002p51
  },
  { // Entry 83
    0x1.999999999999c0p-1,
    (int)0x1.a0p5,
    0x1.999999999999cp51
  },
  { // Entry 84
    0x1.b3333333333360p-1,
    (int)0x1.a0p5,
    0x1.b333333333336p51
  },
  { // Entry 85
    0x1.cccccccccccdp-1,
    (int)0x1.a0p5,
    0x1.cccccccccccd0p51
  },
  { // Entry 86
    0x1.e66666666666a0p-1,
    (int)0x1.a0p5,
    0x1.e66666666666ap51
  },
  { // Entry 87
    0x1.p-1,
    (int)0x1.a8p5,
    0x1.0p52
  },
  { // Entry 88
    0x1.p-1,
    (int)0x1.a8p5,
    0x1.0p52
  },
  { // Entry 89
    0x1.199999999999a0p-1,
    (int)0x1.a8p5,
    0x1.199999999999ap52
  },
  { // Entry 90
    0x1.33333333333340p-1,
    (int)0x1.a8p5,
    0x1.3333333333334p52
  },
  { // Entry 91
    0x1.4ccccccccccce0p-1,
    (int)0x1.a8p5,
    0x1.4cccccccccccep52
  },
  { // Entry 92
    0x1.66666666666680p-1,
    (int)0x1.a8p5,
    0x1.6666666666668p52
  },
  { // Entry 93
    0x1.80000000000020p-1,
    (int)0x1.a8p5,
    0x1.8000000000002p52
  },
  { // Entry 94
    0x1.999999999999c0p-1,
    (int)0x1.a8p5,
    0x1.999999999999cp52
  },
  { // Entry 95
    0x1.b3333333333360p-1,
    (int)0x1.a8p5,
    0x1.b333333333336p52
  },
  { // Entry 96
    0x1.cccccccccccdp-1,
    (int)0x1.a8p5,
    0x1.cccccccccccd0p52
  },
  { // Entry 97
    0x1.e66666666666a0p-1,
    (int)0x1.a8p5,
    0x1.e66666666666ap52
  },
  { // Entry 98
    0x1.p-1,
    (int)0x1.b0p5,
    0x1.0p53
  },
  { // Entry 99
    0x1.p-1,
    (int)0x1.b0p5,
    0x1.0p53
  },
  { // Entry 100
    0x1.199999999999a0p-1,
    (int)0x1.b0p5,
    0x1.199999999999ap53
  },
  { // Entry 101
    0x1.33333333333340p-1,
    (int)0x1.b0p5,
    0x1.3333333333334p53
  },
  { // Entry 102
    0x1.4ccccccccccce0p-1,
    (int)0x1.b0p5,
    0x1.4cccccccccccep53
  },
  { // Entry 103
    0x1.66666666666680p-1,
    (int)0x1.b0p5,
    0x1.6666666666668p53
  },
  { // Entry 104
    0x1.80000000000020p-1,
    (int)0x1.b0p5,
    0x1.8000000000002p53
  },
  { // Entry 105
    0x1.999999999999c0p-1,
    (int)0x1.b0p5,
    0x1.999999999999cp53
  },
  { // Entry 106
    0x1.b3333333333360p-1,
    (int)0x1.b0p5,
    0x1.b333333333336p53
  },
  { // Entry 107
    0x1.cccccccccccdp-1,
    (int)0x1.b0p5,
    0x1.cccccccccccd0p53
  },
  { // Entry 108
    0x1.e66666666666a0p-1,
    (int)0x1.b0p5,
    0x1.e66666666666ap53
  },
  { // Entry 109
    0x1.p-1,
    (int)0x1.b8p5,
    0x1.0p54
  },
  { // Entry 110
    0x1.p-1,
    (int)-0x1.0040p10,
    0x1.0p-1026
  },
  { // Entry 111
    0x1.d3333333333340p-1,
    (int)-0x1.ff80p9,
    0x1.d333333333334p-1024
  },
  { // Entry 112
    0x1.b3333333333340p-1,
    (int)-0x1.ffp9,
    0x1.b333333333334p-1023
  },
  { // Entry 113
    0x1.3e666666666670p-1,
    (int)-0x1.fe80p9,
    0x1.3e66666666667p-1022
  },
  { // Entry 114
    0x1.a3333333333340p-1,
    (int)-0x1.fe80p9,
    0x1.a333333333334p-1022
  },
  { // Entry 115
    0x1.04p-1,
    (int)-0x1.fep9,
    0x1.040p-1021
  },
  { // Entry 116
    0x1.36666666666660p-1,
    (int)-0x1.fep9,
    0x1.3666666666666p-1021
  },
  { // Entry 117
    0x1.68ccccccccccc0p-1,
    (int)-0x1.fep9,
    0x1.68cccccccccccp-1021
  },
  { // Entry 118
    0x1.9b333333333320p-1,
    (int)-0x1.fep9,
    0x1.9b33333333332p-1021
  },
  { // Entry 119
    0x1.cd999999999980p-1,
    (int)-0x1.fep9,
    0x1.cd99999999998p-1021
  },
  { // Entry 120
    0x1.ffffffffffffe0p-1,
    (int)-0x1.fep9,
    0x1.ffffffffffffep-1021
  },
  { // Entry 121
    0x1.fffffffffffff0p-1,
    (int)0x1.98p5,
    0x1.fffffffffffffp50
  },
  { // Entry 122
    0x1.p-1,
    (int)0x1.a0p5,
    0x1.0p51
  },
  { // Entry 123
    0x1.00000000000010p-1,
    (int)0x1.a0p5,
    0x1.0000000000001p51
  },
  { // Entry 124
    0x1.fffffffffffff0p-1,
    (int)0x1.a0p5,
    0x1.fffffffffffffp51
  },
  { // Entry 125
    0x1.p-1,
    (int)0x1.a8p5,
    0x1.0p52
  },
  { // Entry 126
    0x1.00000000000010p-1,
    (int)0x1.a8p5,
    0x1.0000000000001p52
  },
  { // Entry 127
    0x1.fffffffffffff0p-1,
    (int)0x1.a8p5,
    0x1.fffffffffffffp52
  },
  { // Entry 128
    0x1.p-1,
    (int)0x1.b0p5,
    0x1.0p53
  },
  { // Entry 129
    0x1.00000000000010p-1,
    (int)0x1.b0p5,
    0x1.0000000000001p53
  },
  { // Entry 130
    -0x1.00000000000010p-1,
    (int)0x1.a0p5,
    -0x1.0000000000001p51
  },
  { // Entry 131
    -0x1.p-1,
    (int)0x1.a0p5,
    -0x1.0p51
  },
  { // Entry 132
    -0x1.fffffffffffff0p-1,
    (int)0x1.98p5,
    -0x1.fffffffffffffp50
  },
  { // Entry 133
    -0x1.00000000000010p-1,
    (int)0x1.a8p5,
    -0x1.0000000000001p52
  },
  { // Entry 134
    -0x1.p-1,
    (int)0x1.a8p5,
    -0x1.0p52
  },
  { // Entry 135
    -0x1.fffffffffffff0p-1,
    (int)0x1.a0p5,
    -0x1.fffffffffffffp51
  },
  { // Entry 136
    -0x1.00000000000010p-1,
    (int)0x1.b0p5,
    -0x1.0000000000001p53
  },
  { // Entry 137
    -0x1.p-1,
    (int)0x1.b0p5,
    -0x1.0p53
  },
  { // Entry 138
    -0x1.fffffffffffff0p-1,
    (int)0x1.a8p5,
    -0x1.fffffffffffffp52
  },
  { // Entry 139
    0x1.fffffffffffff0p-1,
    (int)0x1.p10,
    0x1.fffffffffffffp1023
  },
  { // Entry 140
    -0x1.fffffffffffff0p-1,
    (int)0x1.p10,
    -0x1.fffffffffffffp1023
  },
  { // Entry 141
    0x1.fffffffffffff0p-1,
    (int)-0x1.80p2,
    0x1.fffffffffffffp-7
  },
  { // Entry 142
    0x1.p-1,
    (int)-0x1.40p2,
    0x1.0p-6
  },
  { // Entry 143
    0x1.00000000000010p-1,
    (int)-0x1.40p2,
    0x1.0000000000001p-6
  },
  { // Entry 144
    0x1.fffffffffffff0p-1,
    (int)-0x1.40p2,
    0x1.fffffffffffffp-6
  },
  { // Entry 145
    0x1.p-1,
    (int)-0x1.p2,
    0x1.0p-5
  },
  { // Entry 146
    0x1.00000000000010p-1,
    (int)-0x1.p2,
    0x1.0000000000001p-5
  },
  { // Entry 147
    0x1.fffffffffffff0p-1,
    (int)-0x1.p2,
    0x1.fffffffffffffp-5
  },
  { // Entry 148
    0x1.p-1,
    (int)-0x1.80p1,
    0x1.0p-4
  },
  { // Entry 149
    0x1.00000000000010p-1,
    (int)-0x1.80p1,
    0x1.0000000000001p-4
  },
  { // Entry 150
    0x1.fffffffffffff0p-1,
    (int)-0x1.80p1,
    0x1.fffffffffffffp-4
  },
  { // Entry 151
    0x1.p-1,
    (int)-0x1.p1,
    0x1.0p-3
  },
  { // Entry 152
    0x1.00000000000010p-1,
    (int)-0x1.p1,
    0x1.0000000000001p-3
  },
  { // Entry 153
    0x1.fffffffffffff0p-1,
    (int)-0x1.p1,
    0x1.fffffffffffffp-3
  },
  { // Entry 154
    0x1.p-1,
    (int)-0x1.p0,
    0x1.0p-2
  },
  { // Entry 155
    0x1.00000000000010p-1,
    (int)-0x1.p0,
    0x1.0000000000001p-2
  },
  { // Entry 156
    0x1.fffffffffffff0p-1,
    (int)-0x1.p0,
    0x1.fffffffffffffp-2
  },
  { // Entry 157
    0x1.p-1,
    (int)0.0,
    0x1.0p-1
  },
  { // Entry 158
    0x1.00000000000010p-1,
    (int)0.0,
    0x1.0000000000001p-1
  },
  { // Entry 159
    -0x1.p-1,
    (int)-0x1.0c40p10,
    -0x1.0p-1074
  },
  { // Entry 160
    -0.0,
    (int)0.0,
    -0.0
  },
  { // Entry 161
    0x1.p-1,
    (int)-0x1.0c40p10,
    0x1.0p-1074
  },
  { // Entry 162
    0x1.fffffffffffff0p-1,
    (int)0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 163
    0x1.p-1,
    (int)0x1.p0,
    0x1.0p0
  },
  { // Entry 164
    0x1.00000000000010p-1,
    (int)0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 165
    0x1.fffffffffffff0p-1,
    (int)0x1.p0,
    0x1.fffffffffffffp0
  },
  { // Entry 166
    0x1.p-1,
    (int)0x1.p1,
    0x1.0p1
  },
  { // Entry 167
    0x1.00000000000010p-1,
    (int)0x1.p1,
    0x1.0000000000001p1
  },
  { // Entry 168
    0x1.fffffffffffff0p-1,
    (int)0x1.p1,
    0x1.fffffffffffffp1
  },
  { // Entry 169
    0x1.p-1,
    (int)0x1.80p1,
    0x1.0p2
  },
  { // Entry 170
    0x1.00000000000010p-1,
    (int)0x1.80p1,
    0x1.0000000000001p2
  },
  { // Entry 171
    0x1.fffffffffffff0p-1,
    (int)0x1.80p1,
    0x1.fffffffffffffp2
  },
  { // Entry 172
    0x1.p-1,
    (int)0x1.p2,
    0x1.0p3
  },
  { // Entry 173
    0x1.00000000000010p-1,
    (int)0x1.p2,
    0x1.0000000000001p3
  },
  { // Entry 174
    0x1.fffffffffffff0p-1,
    (int)0x1.p2,
    0x1.fffffffffffffp3
  },
  { // Entry 175
    0x1.p-1,
    (int)0x1.40p2,
    0x1.0p4
  },
  { // Entry 176
    0x1.00000000000010p-1,
    (int)0x1.40p2,
    0x1.0000000000001p4
  },
  { // Entry 177
    0x1.fffffffffffff0p-1,
    (int)0x1.40p2,
    0x1.fffffffffffffp4
  },
  { // Entry 178
    0x1.p-1,
    (int)0x1.80p2,
    0x1.0p5
  },
  { // Entry 179
    0x1.00000000000010p-1,
    (int)0x1.80p2,
    0x1.0000000000001p5
  },
  { // Entry 180
    0x1.fffffffffffff0p-1,
    (int)0x1.80p2,
    0x1.fffffffffffffp5
  },
  { // Entry 181
    0x1.p-1,
    (int)0x1.c0p2,
    0x1.0p6
  },
  { // Entry 182
    0x1.00000000000010p-1,
    (int)0x1.c0p2,
    0x1.0000000000001p6
  },
  { // Entry 183
    0x1.fffffffffffff0p-1,
    (int)0x1.c0p2,
    0x1.fffffffffffffp6
  },
  { // Entry 184
    0x1.p-1,
    (int)0x1.p3,
    0x1.0p7
  },
  { // Entry 185
    0x1.00000000000010p-1,
    (int)0x1.p3,
    0x1.0000000000001p7
  },
  { // Entry 186
    HUGE_VAL,
    (int)0,
    HUGE_VAL
  },
  { // Entry 187
    -HUGE_VAL,
    (int)0,
    -HUGE_VAL
  },
  { // Entry 188
    0.0,
    (int)0.0,
    0.0
  },
  { // Entry 189
    -0.0,
    (int)0.0,
    -0.0
  },
  { // Entry 190
    0x1.fffffffffffff0p-1,
    (int)0x1.p10,
    0x1.fffffffffffffp1023
  },
  { // Entry 191
    -0x1.fffffffffffff0p-1,
    (int)0x1.p10,
    -0x1.fffffffffffffp1023
  },
  { // Entry 192
    0x1.ffffffffffffe0p-1,
    (int)0x1.p10,
    0x1.ffffffffffffep1023
  },
  { // Entry 193
    -0x1.ffffffffffffe0p-1,
    (int)0x1.p10,
    -0x1.ffffffffffffep1023
  },
  { // Entry 194
    0x1.921fb54442d180p-1,
    (int)0x1.p1,
    0x1.921fb54442d18p1
  },
  { // Entry 195
    -0x1.921fb54442d180p-1,
    (int)0x1.p1,
    -0x1.921fb54442d18p1
  },
  { // Entry 196
    0x1.921fb54442d180p-1,
    (int)0x1.p0,
    0x1.921fb54442d18p0
  },
  { // Entry 197
    -0x1.921fb54442d180p-1,
    (int)0x1.p0,
    -0x1.921fb54442d18p0
  },
  { // Entry 198
    0x1.00000000000010p-1,
    (int)0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 199
    -0x1.00000000000010p-1,
    (int)0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 200
    0x1.p-1,
    (int)0x1.p0,
    0x1.0p0
  },
  { // Entry 201
    -0x1.p-1,
    (int)0x1.p0,
    -0x1.0p0
  },
  { // Entry 202
    0x1.fffffffffffff0p-1,
    (int)0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 203
    -0x1.fffffffffffff0p-1,
    (int)0.0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 204
    0x1.921fb54442d180p-1,
    (int)0.0,
    0x1.921fb54442d18p-1
  },
  { // Entry 205
    -0x1.921fb54442d180p-1,
    (int)0.0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 206
    0x1.00000000000010p-1,
    (int)-0x1.fe80p9,
    0x1.0000000000001p-1022
  },
  { // Entry 207
    -0x1.00000000000010p-1,
    (int)-0x1.fe80p9,
    -0x1.0000000000001p-1022
  },
  { // Entry 208
    0x1.p-1,
    (int)-0x1.fe80p9,
    0x1.0p-1022
  },
  { // Entry 209
    -0x1.p-1,
    (int)-0x1.fe80p9,
    -0x1.0p-1022
  },
  { // Entry 210
    0x1.ffffffffffffe0p-1,
    (int)-0x1.ffp9,
    0x1.ffffffffffffep-1023
  },
  { // Entry 211
    -0x1.ffffffffffffe0p-1,
    (int)-0x1.ffp9,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 212
    0x1.ffffffffffffc0p-1,
    (int)-0x1.ffp9,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 213
    -0x1.ffffffffffffc0p-1,
    (int)-0x1.ffp9,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 214
    0x1.p-1,
    (int)-0x1.0cp10,
    0x1.0p-1073
  },
  { // Entry 215
    -0x1.p-1,
    (int)-0x1.0cp10,
    -0x1.0p-1073
  },
  { // Entry 216
    0x1.p-1,
    (int)-0x1.0c40p10,
    0x1.0p-1074
  },
  { // Entry 217
    -0x1.p-1,
    (int)-0x1.0c40p10,
    -0x1.0p-1074
  }
};

"""

```
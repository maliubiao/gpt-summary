Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The primary goal is to analyze a C source file containing test data for the `atanh` function in Android's `bionic` library. The request has several sub-components:

* **Functionality:** What does this *specific file* do?
* **Android Relevance:** How does this relate to broader Android functionality?
* **Libc Function Implementation:** Detailed explanation of `atanh`. (Even though this file *is not* the implementation, the question asks about it.)
* **Dynamic Linker:** How does this relate to loading and linking, and provide an example.
* **Logic & I/O:**  What are the inputs and outputs *of the test data itself*?
* **Common Errors:** How might a developer misuse `atanh`?
* **Android Framework/NDK Hooking:** How to trace the path to this data using Frida.
* **Summary (Part 2):**  A concise overview of this file's purpose.

**2. Initial Analysis of the File:**

The file contains a large C array named `__test_atanh_data`. Each element in the array is a struct (or an anonymous struct in C) with two `double` values. The comments like "// Entry 356" suggest this is a set of test cases. The naming convention `atanh_intel_data.handroid` hints that these are likely specific test cases, potentially tailored for Intel architectures ("intel") within the Android context ("handroid").

**3. Addressing Each Sub-Request Systematically:**

* **Functionality (File):**  This is the easiest part. The file's function is to provide test data for the `atanh` function. The data consists of input values and their expected output values.

* **Android Relevance:**  The `atanh` function is part of the standard C math library (`libc`). Android applications, whether written in Java/Kotlin or C/C++ (using the NDK), can use this function. The test data ensures the `atanh` implementation in `bionic` (Android's `libc`) works correctly across various inputs.

* **Libc Function Implementation (atanh):**  This requires understanding the mathematical definition of `atanh(x)`. The key insight is that `atanh(x) = 0.5 * ln((1 + x) / (1 - x))`. This formula provides the basis for explaining the implementation. Points to cover include:
    * Domain of `atanh`: -1 < x < 1.
    * Handling edge cases like +/- 1 and values close to +/- 1.
    * Potential use of look-up tables or polynomial approximations for performance.
    * Error handling (e.g., for inputs outside the domain).

* **Dynamic Linker:** While this specific file doesn't *directly* involve the dynamic linker, `atanh` is *part of* `libc.so`, which *is* managed by the dynamic linker. Therefore, an explanation of the dynamic linker's role in loading `libc.so` and resolving symbols like `atanh` is necessary. The example SO layout should demonstrate how symbols are exposed and resolved. The linking process involves symbol lookup in the dependency tree.

* **Logic & I/O (Test Data):** The "input" is the first `double` in each array element, and the "output" is the second. The logic being tested is `atanh(input) == output`. The test data covers a range of input values, including positive, negative, very small, very large (approaching +/- 1), and special values like zero.

* **Common Errors:**  The most common error is providing an input outside the valid domain (-1, 1). This will typically result in a `NaN` (Not a Number).

* **Android Framework/NDK Hooking (Frida):** This requires knowledge of how Android apps call native code. The typical path is: Java/Kotlin code -> JNI call -> Native C/C++ code (in a `.so` library) -> call to `atanh` in `libc.so`. The Frida hook should demonstrate intercepting the `atanh` call. The key is identifying the correct library (`libc.so`) and the function name.

* **Summary (Part 2):** This is a condensed version of the file's purpose: it's a test data file for the `atanh` function in Android's `bionic` library.

**4. Pre-computation and Pre-analysis (Internal):**

Even though the prompt provides the data,  mentally (or through a quick script), one would observe:

* **Pairs:** The data is in pairs of input and expected output.
* **Symmetry:** Many entries have a positive and a corresponding negative input/output pair, indicating testing of the odd function property of `atanh`.
* **Special Values:** Presence of `HUGE_VAL`, 0.0, -0.0, and values with different exponents (powers of 2) suggests testing boundary conditions and precision.
* **Hexadecimal Floating-Point Notation:** The data uses hexadecimal floating-point representation, which is common in low-level numerical code for precision.

**5. Structuring the Answer:**

Organize the answer logically, addressing each part of the request clearly with headings and subheadings. Use code blocks for the SO layout and Frida script. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file *implements* `atanh`. **Correction:** The filename and the data structure strongly suggest it's *test data*, not the implementation.
* **Dynamic Linker Focus:** Initially, I might overemphasize complex linking scenarios. **Refinement:**  Focus on the basic case of linking against `libc.so` and symbol resolution for `atanh`.
* **Frida Script Specificity:**  The Frida script needs to be practical and target the `atanh` function in `libc.so`. Generic hooking examples are less helpful.

By following these steps, the comprehensive and detailed answer provided earlier can be constructed. The key is to break down the problem into manageable parts and apply relevant knowledge to each part.
好的，让我们来归纳一下 `bionic/tests/math_data/atanh_intel_data.handroid` 这个源代码文件的功能。

**功能归纳：**

这个 C 源代码文件 `atanh_intel_data.handroid` 的主要功能是 **提供了一组用于测试 `atanh` (反双曲正切) 数学函数的测试数据。**

具体来说，它包含一个名为 `__test_atanh_data` 的常量数组。这个数组的每个元素都是一个匿名结构体，包含两个 `double` 类型的浮点数：

1. **输入值 (x):** 用于传递给 `atanh` 函数的输入参数。
2. **预期输出值 (atanh(x)):**  `atanh` 函数针对该输入值应该返回的正确结果。

**与 Android 功能的关系举例说明：**

* **测试 `bionic` 库的正确性：** `bionic` 是 Android 的 C 库，包含了标准的 C 库函数，包括数学函数。这个测试数据文件是 `bionic` 自身测试套件的一部分，用于验证 `bionic` 库中 `atanh` 函数的实现是否正确，能否在各种不同的输入情况下返回预期的结果。
* **确保应用使用 `atanh` 的准确性：** Android 上的应用程序，特别是使用 NDK (Native Development Kit) 开发的 C/C++ 应用，可能会调用 `atanh` 函数进行数学计算。这些测试数据可以帮助开发者和 Android 系统工程师确保在 Android 设备上运行的 `atanh` 函数是精确可靠的。例如，一个图形渲染引擎或科学计算应用可能会依赖 `atanh` 函数进行角度或速度的计算。

**详细解释 `atanh` libc 函数的功能是如何实现的：**

`atanh(x)` 函数计算的是给定值 `x` 的反双曲正切。数学上，它定义为使得 `tanh(y) = x` 的 `y` 值。 其公式为：

`atanh(x) = 0.5 * ln((1 + x) / (1 - x))`

其中 `ln` 是自然对数。

**实现方式通常会考虑以下几点：**

1. **输入范围检查：** `atanh(x)` 的定义域是 (-1, 1)。实现需要检查输入 `x` 是否在这个范围内。如果超出范围，通常会返回 `NaN` (Not a Number) 并设置 `errno` 为 `EDOM` (domain error)。
2. **特殊值处理：**
   * 如果 `x` 为 0，则 `atanh(x)` 为 0。
   * 如果 `x` 非常接近 1 或 -1，则 `atanh(x)` 的绝对值会非常大，可能会返回 `+/-HUGE_VAL` 并设置 `errno` 为 `ERANGE` (range error)。
3. **数值计算方法：**
   * **直接使用公式：** 在输入值不太接近 +/-1 时，可以直接使用上面的公式计算。
   * **级数展开：** 当输入值接近 0 时，可以使用泰勒级数展开来提高计算精度和效率。`atanh(x) = x + x^3/3 + x^5/5 + ...`
   * **查找表和插值：** 对于某些架构，可能会使用预先计算好的查找表，然后使用插值法来逼近结果，以提高性能。
   * **组合方法：** 实际的实现可能会结合多种方法，根据输入值的不同范围选择最合适的计算方式，以兼顾精度和性能。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

尽管这个数据文件本身不涉及 dynamic linker 的功能，但 `atanh` 函数的实现位于 `libc.so` 共享库中。当一个应用程序需要使用 `atanh` 函数时，dynamic linker 负责加载 `libc.so` 并解析对 `atanh` 函数的引用。

**`libc.so` 布局样本（简化）：**

```
libc.so:
  地址区间: 0xb7000000 - 0xb7800000
  ...
  .symtab (符号表):
    ...
    0xb7123456  T  atanh  (函数地址)
    ...
  .dynsym (动态符号表):
    ...
    0xb7123456  T  atanh
    ...
  .plt (过程链接表):
    ...
    atanh@plt:
      jmp *GOT[atanh_index]
    ...
  .got (全局偏移表):
    ...
    GOT[atanh_index]: 0x0  (初始为空，等待 dynamic linker 填充)
    ...
  ...
```

**链接的处理过程：**

1. **加载：** 当应用程序启动时，操作系统会加载应用程序的可执行文件。如果应用程序依赖于 `libc.so`，dynamic linker (通常是 `/system/bin/linker` 或 `/system/bin/linker64`) 也会被加载。
2. **依赖项解析：** Dynamic linker 会解析应用程序的依赖项，找到需要加载的共享库，例如 `libc.so`。
3. **加载共享库：** Dynamic linker 将 `libc.so` 加载到进程的地址空间中。
4. **重定位：** 由于共享库在不同进程中加载的地址可能不同，dynamic linker 需要进行重定位，调整共享库中的某些地址引用。
5. **符号解析（链接）：** 当应用程序调用 `atanh` 函数时，实际上会跳转到 `atanh@plt` (过程链接表) 中的代码。
   * 第一次调用时，`GOT[atanh_index]` 的值是空的或指向 PLT 中的另一段代码。
   * PLT 中的代码会调用 dynamic linker 的解析函数。
   * Dynamic linker 在 `libc.so` 的动态符号表 (`.dynsym`) 中查找名为 `atanh` 的符号。
   * 找到 `atanh` 的地址 (例如 `0xb7123456`) 后，dynamic linker 将该地址写入 `GOT[atanh_index]`。
   * 然后，控制权跳转到 `atanh` 的实际地址。
   * 后续对 `atanh` 的调用将直接通过 `GOT[atanh_index]` 跳转到 `atanh` 的实现，因为地址已经被解析并缓存了。

**假设输入与输出 (逻辑推理)：**

这个数据文件本身就是一系列的假设输入和预期输出。例如：

* **假设输入:** `0x1.3c9c79bc850a0b52fa4dacd910d12a32p-1` (十六进制浮点数表示，大约等于 0.85)
* **预期输出:** `0x1.199999999999bp-1` (大约等于 0.7)

这意味着测试代码会调用 `atanh(0.85)`，并断言其返回值是否非常接近 `0.7`。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **超出定义域的输入：**
   ```c
   #include <math.h>
   #include <stdio.h>

   int main() {
       double x = 1.5; // 超出 (-1, 1)
       double result = atanh(x);
       printf("atanh(%f) = %f\n", x, result); // 输出 NaN
       return 0;
   }
   ```
   在这种情况下，`atanh(1.5)` 是未定义的，会返回 `NaN`。开发者需要确保传递给 `atanh` 的值在 (-1, 1) 范围内。

2. **精度问题：**
   ```c
   #include <math.h>
   #include <stdio.h>
   #include <float.h>

   int main() {
       double x = 0.9999999999999;
       double expected = 2.6459456867;
       double result = atanh(x);
       if (fabs(result - expected) > DBL_EPSILON) {
           printf("精度不匹配: expected = %f, result = %f\n", expected, result);
       }
       return 0;
   }
   ```
   对于接近定义域边界的值，`atanh` 的结果变化非常快。开发者需要理解浮点数的精度限制，并根据实际需求进行合理的精度比较，而不是直接使用 `==`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java/Kotlin 层):**
   * Android 应用的 Java 或 Kotlin 代码可能需要执行一些数学运算。
   * 如果需要使用 `atanh`，但 Android Framework 本身没有直接提供这个函数，开发者可能会选择使用 NDK 调用 C/C++ 代码。

2. **NDK (Native 层):**
   * 开发者使用 NDK 编写 C/C++ 代码，并在其中调用 `atanh` 函数。
   * 编译时，NDK 工具链会将 C/C++ 代码编译成共享库 (`.so` 文件)。
   * 在 C/C++ 代码中包含 `<math.h>` 头文件即可使用 `atanh`。

3. **Dynamic Linker 加载 `libc.so`:**
   * 当包含 `atanh` 调用的 `.so` 文件被加载时，dynamic linker 会发现它依赖于 `libc.so`。
   * Dynamic linker 加载 `libc.so` 并解析 `atanh` 符号。

4. **执行 `atanh`:**
   * 当程序执行到调用 `atanh` 的地方时，会跳转到 `libc.so` 中 `atanh` 函数的实现。

5. **测试数据的使用 (间接):**
   *  这个 `atanh_intel_data.handroid` 文件主要用于 `bionic` 自身的测试。在应用运行时，通常不会直接访问这个数据文件。
   *  但是，`bionic` 的开发者会使用这些测试数据来确保 `atanh` 的实现是正确的，从而间接地保证了应用程序调用 `atanh` 的准确性。

**Frida Hook 示例：**

假设你想 hook 应用程序中对 `atanh` 的调用，你可以使用 Frida 脚本：

```javascript
// hook_atanh.js

if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const libc = Module.findExportByName(null, "atanh");
  if (libc) {
    Interceptor.attach(libc, {
      onEnter: function (args) {
        console.log("[atanh] Entering atanh");
        const input = args[0].readDouble();
        console.log("[atanh] Input:", input);
        this.input = input;
      },
      onLeave: function (retval) {
        const output = retval.readDouble();
        console.log("[atanh] Output:", output);
        console.log("[atanh] Exiting atanh");
      }
    });
  } else {
    console.log("[atanh] atanh not found in loaded modules.");
  }
} else {
  console.log("[atanh] Skipping hook on 32-bit architecture (implementation might differ).");
}
```

**使用 Frida 运行脚本：**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. 找到你要调试的应用程序的进程 ID 或包名。
3. 运行 Frida 命令：
   ```bash
   frida -U -f <package_name> -l hook_atanh.js --no-pause
   # 或者
   frida -U <process_id> -l hook_atanh.js --no-pause
   ```

**Frida Hook 脚本解释：**

* **`Process.arch`:**  检查进程的架构 (arm64 或 x64)。
* **`Module.findExportByName(null, "atanh")`:**  在所有已加载的模块中查找名为 `atanh` 的导出函数。通常 `atanh` 在 `libc.so` 中。
* **`Interceptor.attach(libc, ...)`:**  如果找到了 `atanh` 函数，则附加一个拦截器。
* **`onEnter`:** 在 `atanh` 函数被调用时执行。
    * `args[0]` 包含了 `atanh` 的第一个参数 (double 类型的输入值)。
    * `readDouble()` 读取该参数的 double 值。
* **`onLeave`:** 在 `atanh` 函数执行完毕即将返回时执行。
    * `retval` 包含了 `atanh` 函数的返回值 (double 类型的结果)。
    * `readDouble()` 读取返回值。

通过这个 Frida hook，你可以在应用程序调用 `atanh` 函数时，实时观察其输入和输出值，从而进行调试和分析。

希望以上归纳和解释能够帮助你理解这个测试数据文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/math_data/atanh_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
1,
    -0x1.1111111111112p-1
  },
  { // Entry 356
    0x1.3c9c79bc850a0b52fa4dacd910d12a32p-1,
    0x1.199999999999bp-1
  },
  { // Entry 357
    -0x1.3c9c79bc850a0b52fa4dacd910d12a32p-1,
    -0x1.199999999999bp-1
  },
  { // Entry 358
    0x1.4902c08bec8cd75f11102da30f1f78d7p-1,
    0x1.2222222222224p-1
  },
  { // Entry 359
    -0x1.4902c08bec8cd75f11102da30f1f78d7p-1,
    -0x1.2222222222224p-1
  },
  { // Entry 360
    0x1.55c2a141bd929027179a90e1bcdc1a2dp-1,
    0x1.2aaaaaaaaaaadp-1
  },
  { // Entry 361
    -0x1.55c2a141bd929027179a90e1bcdc1a2dp-1,
    -0x1.2aaaaaaaaaaadp-1
  },
  { // Entry 362
    0x1.62e42fefa39f395793c767300da3ed5ep-1,
    0x1.3333333333336p-1
  },
  { // Entry 363
    -0x1.62e42fefa39f395793c767300da3ed5ep-1,
    -0x1.3333333333336p-1
  },
  { // Entry 364
    0x1.7070827f1c80536feb7673dd88b946ecp-1,
    0x1.3bbbbbbbbbbbfp-1
  },
  { // Entry 365
    -0x1.7070827f1c80536feb7673dd88b946ecp-1,
    -0x1.3bbbbbbbbbbbfp-1
  },
  { // Entry 366
    0x1.7e71ded66461d753e33ac2ff618644e0p-1,
    0x1.4444444444448p-1
  },
  { // Entry 367
    -0x1.7e71ded66461d753e33ac2ff618644e0p-1,
    -0x1.4444444444448p-1
  },
  { // Entry 368
    0x1.8cf3f3b791751f845062c18f4b0d7fe7p-1,
    0x1.4ccccccccccd1p-1
  },
  { // Entry 369
    -0x1.8cf3f3b791751f845062c18f4b0d7fe7p-1,
    -0x1.4ccccccccccd1p-1
  },
  { // Entry 370
    0x1.9c041f7ed8d3bd1645de0b7c8544b713p-1,
    0x1.555555555555ap-1
  },
  { // Entry 371
    -0x1.9c041f7ed8d3bd1645de0b7c8544b713p-1,
    -0x1.555555555555ap-1
  },
  { // Entry 372
    0x1.abb1c90658273b62b26c47dabd2b16cap-1,
    0x1.5dddddddddde3p-1
  },
  { // Entry 373
    -0x1.abb1c90658273b62b26c47dabd2b16cap-1,
    -0x1.5dddddddddde3p-1
  },
  { // Entry 374
    0x1.bc0ed0947fbf4018f189a9725a0c8214p-1,
    0x1.666666666666cp-1
  },
  { // Entry 375
    -0x1.bc0ed0947fbf4018f189a9725a0c8214p-1,
    -0x1.666666666666cp-1
  },
  { // Entry 376
    0x1.cd302116f50c8745aed84bd751fb575cp-1,
    0x1.6eeeeeeeeeef5p-1
  },
  { // Entry 377
    -0x1.cd302116f50c8745aed84bd751fb575cp-1,
    -0x1.6eeeeeeeeeef5p-1
  },
  { // Entry 378
    0x1.df2e6d6e5fbb884c684c52df3b260c38p-1,
    0x1.777777777777ep-1
  },
  { // Entry 379
    -0x1.df2e6d6e5fbb884c684c52df3b260c38p-1,
    -0x1.777777777777ep-1
  },
  { // Entry 380
    0x1.f2272ae325a67546f69496cf861be046p-1,
    0x1.8000000000007p-1
  },
  { // Entry 381
    -0x1.f2272ae325a67546f69496cf861be046p-1,
    -0x1.8000000000007p-1
  },
  { // Entry 382
    0x1.031ef11090f8818c48703199fec1433ap0,
    0x1.8888888888890p-1
  },
  { // Entry 383
    -0x1.031ef11090f8818c48703199fec1433ap0,
    -0x1.8888888888890p-1
  },
  { // Entry 384
    0x1.0dcefea4d0270295d8d877b36ea1c0e3p0,
    0x1.9111111111119p-1
  },
  { // Entry 385
    -0x1.0dcefea4d0270295d8d877b36ea1c0e3p0,
    -0x1.9111111111119p-1
  },
  { // Entry 386
    0x1.193ea7aad03164214ec438001cc9b599p0,
    0x1.99999999999a2p-1
  },
  { // Entry 387
    -0x1.193ea7aad03164214ec438001cc9b599p0,
    -0x1.99999999999a2p-1
  },
  { // Entry 388
    0x1.258fdae8372ce27963c75835d46b66e6p0,
    0x1.a22222222222bp-1
  },
  { // Entry 389
    -0x1.258fdae8372ce27963c75835d46b66e6p0,
    -0x1.a22222222222bp-1
  },
  { // Entry 390
    0x1.32ee3b77f375afd8dd11ce3f9e4b9287p0,
    0x1.aaaaaaaaaaab4p-1
  },
  { // Entry 391
    -0x1.32ee3b77f375afd8dd11ce3f9e4b9287p0,
    -0x1.aaaaaaaaaaab4p-1
  },
  { // Entry 392
    0x1.41933b0e44649943f09224fce382c799p0,
    0x1.b33333333333dp-1
  },
  { // Entry 393
    -0x1.41933b0e44649943f09224fce382c799p0,
    -0x1.b33333333333dp-1
  },
  { // Entry 394
    0x1.51cca16d7bbbc179603c253505b36b7ap0,
    0x1.bbbbbbbbbbbc6p-1
  },
  { // Entry 395
    -0x1.51cca16d7bbbc179603c253505b36b7ap0,
    -0x1.bbbbbbbbbbbc6p-1
  },
  { // Entry 396
    0x1.640775d4dd9a4337400b58abfdea644fp0,
    0x1.c44444444444fp-1
  },
  { // Entry 397
    -0x1.640775d4dd9a4337400b58abfdea644fp0,
    -0x1.c44444444444fp-1
  },
  { // Entry 398
    0x1.78e360604b349eb43d8e7eb37a3c01b6p0,
    0x1.cccccccccccd8p-1
  },
  { // Entry 399
    -0x1.78e360604b349eb43d8e7eb37a3c01b6p0,
    -0x1.cccccccccccd8p-1
  },
  { // Entry 400
    0x1.9157dfdd1b4148ea63817356fc04c13bp0,
    0x1.d555555555561p-1
  },
  { // Entry 401
    -0x1.9157dfdd1b4148ea63817356fc04c13bp0,
    -0x1.d555555555561p-1
  },
  { // Entry 402
    0x1.af038cbcdfe4dcf0e5a000b57077d005p0,
    0x1.dddddddddddeap-1
  },
  { // Entry 403
    -0x1.af038cbcdfe4dcf0e5a000b57077d005p0,
    -0x1.dddddddddddeap-1
  },
  { // Entry 404
    0x1.d4ef968880e16e7c57738ee1cab27657p0,
    0x1.e666666666673p-1
  },
  { // Entry 405
    -0x1.d4ef968880e16e7c57738ee1cab27657p0,
    -0x1.e666666666673p-1
  },
  { // Entry 406
    0x1.04f65f9c729aa8b4082276b069b6c479p1,
    0x1.eeeeeeeeeeefcp-1
  },
  { // Entry 407
    -0x1.04f65f9c729aa8b4082276b069b6c479p1,
    -0x1.eeeeeeeeeeefcp-1
  },
  { // Entry 408
    0x1.31dd28c89d64f3513ea98f014ae7630cp1,
    0x1.f777777777777p-1
  },
  { // Entry 409
    -0x1.31dd28c89d64f3513ea98f014ae7630cp1,
    -0x1.f777777777777p-1
  },
  { // Entry 410
    -0x1.2b708872320e1d31e4b03f1086a9c047p4,
    -0x1.fffffffffffffp-1
  },
  { // Entry 411
    0x1.2b708872320e1d31e4b03f1086a9c047p4,
    0x1.fffffffffffffp-1
  },
  { // Entry 412
    -0x1.25e4f7b2737fa14486612173c6896892p4,
    -0x1.ffffffffffffep-1
  },
  { // Entry 413
    0x1.25e4f7b2737fa14486612173c6896892p4,
    0x1.ffffffffffffep-1
  },
  { // Entry 414
    -0x1.22a69334db8c97a62f8f72a5de7de462p4,
    -0x1.ffffffffffffdp-1
  },
  { // Entry 415
    0x1.22a69334db8c97a62f8f72a5de7de462p4,
    0x1.ffffffffffffdp-1
  },
  { // Entry 416
    0x1.2b708872320e1d31e4b03f1086a9c047p4,
    0x1.fffffffffffffp-1
  },
  { // Entry 417
    -0x1.2b708872320e1d31e4b03f1086a9c047p4,
    -0x1.fffffffffffffp-1
  },
  { // Entry 418
    0x1.25e4f7b2737fa14486612173c6896892p4,
    0x1.ffffffffffffep-1
  },
  { // Entry 419
    -0x1.25e4f7b2737fa14486612173c6896892p4,
    -0x1.ffffffffffffep-1
  },
  { // Entry 420
    0x1.22a69334db8c97a62f8f72a5de7de462p4,
    0x1.ffffffffffffdp-1
  },
  { // Entry 421
    -0x1.22a69334db8c97a62f8f72a5de7de462p4,
    -0x1.ffffffffffffdp-1
  },
  { // Entry 422
    0x1.4a851baf27b6d549b7c524fbd91644b2p-3,
    0x1.47ae147ae147ap-3
  },
  { // Entry 423
    -0x1.4a851baf27b6d549b7c524fbd91644b2p-3,
    -0x1.47ae147ae147ap-3
  },
  { // Entry 424
    0x1.4a851baf27b6e5b55490996c8137296ap-3,
    0x1.47ae147ae147bp-3
  },
  { // Entry 425
    -0x1.4a851baf27b6e5b55490996c8137296ap-3,
    -0x1.47ae147ae147bp-3
  },
  { // Entry 426
    0x1.4a851baf27b6f620f15c0ddd2962d721p-3,
    0x1.47ae147ae147cp-3
  },
  { // Entry 427
    -0x1.4a851baf27b6f620f15c0ddd2962d721p-3,
    -0x1.47ae147ae147cp-3
  },
  { // Entry 428
    -0x1.4a851baf27b6f620f15c0ddd2962d721p-3,
    -0x1.47ae147ae147cp-3
  },
  { // Entry 429
    0x1.4a851baf27b6f620f15c0ddd2962d721p-3,
    0x1.47ae147ae147cp-3
  },
  { // Entry 430
    -0x1.4a851baf27b6e5b55490996c8137296ap-3,
    -0x1.47ae147ae147bp-3
  },
  { // Entry 431
    0x1.4a851baf27b6e5b55490996c8137296ap-3,
    0x1.47ae147ae147bp-3
  },
  { // Entry 432
    -0x1.4a851baf27b6d549b7c524fbd91644b2p-3,
    -0x1.47ae147ae147ap-3
  },
  { // Entry 433
    0x1.4a851baf27b6d549b7c524fbd91644b2p-3,
    0x1.47ae147ae147ap-3
  },
  { // Entry 434
    0x1.193ea7aad0309ecbf96ee2aa5aad43d2p-1,
    0x1.fffffffffffffp-2
  },
  { // Entry 435
    -0x1.193ea7aad0309ecbf96ee2aa5aad43d2p-1,
    -0x1.fffffffffffffp-2
  },
  { // Entry 436
    0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    0x1.0p-1
  },
  { // Entry 437
    -0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    -0x1.0p-1
  },
  { // Entry 438
    0x1.193ea7aad030becbf96ee2aa5b029927p-1,
    0x1.0000000000001p-1
  },
  { // Entry 439
    -0x1.193ea7aad030becbf96ee2aa5b029927p-1,
    -0x1.0000000000001p-1
  },
  { // Entry 440
    0x1.058aefa8114511e9ee33a6f97bb76f0ap-2,
    0x1.fffffffffffffp-3
  },
  { // Entry 441
    -0x1.058aefa8114511e9ee33a6f97bb76f0ap-2,
    -0x1.fffffffffffffp-3
  },
  { // Entry 442
    0x1.058aefa811451a7276bc2f82043b6a7dp-2,
    0x1.0p-2
  },
  { // Entry 443
    -0x1.058aefa811451a7276bc2f82043b6a7dp-2,
    -0x1.0p-2
  },
  { // Entry 444
    0x1.058aefa811452b8387cd4093155eafe4p-2,
    0x1.0000000000001p-2
  },
  { // Entry 445
    -0x1.058aefa811452b8387cd4093155eafe4p-2,
    -0x1.0000000000001p-2
  },
  { // Entry 446
    0x1.015891c9eaef6e78c471eee9894ceabdp-3,
    0x1.fffffffffffffp-4
  },
  { // Entry 447
    -0x1.015891c9eaef6e78c471eee9894ceabdp-3,
    -0x1.fffffffffffffp-4
  },
  { // Entry 448
    0x1.015891c9eaef7699467a0f6b916c6494p-3,
    0x1.0p-3
  },
  { // Entry 449
    -0x1.015891c9eaef7699467a0f6b916c6494p-3,
    -0x1.0p-3
  },
  { // Entry 450
    0x1.015891c9eaef86da4a8a506fa1b18969p-3,
    0x1.0000000000001p-3
  },
  { // Entry 451
    -0x1.015891c9eaef86da4a8a506fa1b18969p-3,
    -0x1.0000000000001p-3
  },
  { // Entry 452
    0x1.005588ad375ac5c30b0a9d5bbe7d5dd7p-4,
    0x1.fffffffffffffp-5
  },
  { // Entry 453
    -0x1.005588ad375ac5c30b0a9d5bbe7d5dd7p-4,
    -0x1.fffffffffffffp-5
  },
  { // Entry 454
    0x1.005588ad375acdcb1312a563c685255ep-4,
    0x1.0p-4
  },
  { // Entry 455
    -0x1.005588ad375acdcb1312a563c685255ep-4,
    -0x1.0p-4
  },
  { // Entry 456
    0x1.005588ad375adddb2322b573d6963771p-4,
    0x1.0000000000001p-4
  },
  { // Entry 457
    -0x1.005588ad375adddb2322b573d6963771p-4,
    -0x1.0000000000001p-4
  },
  { // Entry 458
    0x1.001558891aee1cb29d53ddbdb46e79d9p-5,
    0x1.fffffffffffffp-6
  },
  { // Entry 459
    -0x1.001558891aee1cb29d53ddbdb46e79d9p-5,
    -0x1.fffffffffffffp-6
  },
  { // Entry 460
    0x1.001558891aee24b49dd3fdc5b66ee9f1p-5,
    0x1.0p-5
  },
  { // Entry 461
    -0x1.001558891aee24b49dd3fdc5b66ee9f1p-5,
    -0x1.0p-5
  },
  { // Entry 462
    0x1.001558891aee34b89ed43dd5ba702a52p-5,
    0x1.0000000000001p-5
  },
  { // Entry 463
    -0x1.001558891aee34b89ed43dd5ba702a52p-5,
    -0x1.0000000000001p-5
  },
  { // Entry 464
    0x1.000555888ad1c18d8d3255aac6d2acadp-6,
    0x1.fffffffffffffp-7
  },
  { // Entry 465
    -0x1.000555888ad1c18d8d3255aac6d2acadp-6,
    -0x1.fffffffffffffp-7
  },
  { // Entry 466
    0x1.000555888ad1c98e0d3a562aced328b5p-6,
    0x1.0p-6
  },
  { // Entry 467
    -0x1.000555888ad1c98e0d3a562aced328b5p-6,
    -0x1.0p-6
  },
  { // Entry 468
    0x1.000555888ad1d98f0d4a572aded438c7p-6,
    0x1.0000000000001p-6
  },
  { // Entry 469
    -0x1.000555888ad1d98f0d4a572aded438c7p-6,
    -0x1.0000000000001p-6
  },
  { // Entry 470
    0x1.000155588891a53723d0cfc25d992fd2p-7,
    0x1.fffffffffffffp-8
  },
  { // Entry 471
    -0x1.000155588891a53723d0cfc25d992fd2p-7,
    -0x1.fffffffffffffp-8
  },
  { // Entry 472
    0x1.000155588891ad3743d14fc45da12ef2p-7,
    0x1.0p-7
  },
  { // Entry 473
    -0x1.000155588891ad3743d14fc45da12ef2p-7,
    -0x1.0p-7
  },
  { // Entry 474
    0x1.000155588891bd3783d24fc85db13332p-7,
    0x1.0000000000001p-7
  },
  { // Entry 475
    -0x1.000155588891bd3783d24fc85db13332p-7,
    -0x1.0000000000001p-7
  },
  { // Entry 476
    0x1.000055558888a51ae61ef133fc078f9ap-8,
    0x1.fffffffffffffp-9
  },
  { // Entry 477
    -0x1.000055558888a51ae61ef133fc078f9ap-8,
    -0x1.fffffffffffffp-9
  },
  { // Entry 478
    0x1.000055558888ad1aee1ef9340407975ap-8,
    0x1.0p-8
  },
  { // Entry 479
    -0x1.000055558888ad1aee1ef9340407975ap-8,
    -0x1.0p-8
  },
  { // Entry 480
    0x1.000055558888bd1afe1f09341407a85bp-8,
    0x1.0000000000001p-8
  },
  { // Entry 481
    -0x1.000055558888bd1afe1f09341407a85bp-8,
    -0x1.0000000000001p-8
  },
  { // Entry 482
    0x1.000015555888811acfc98c1e9ae230fcp-9,
    0x1.fffffffffffffp-10
  },
  { // Entry 483
    -0x1.000015555888811acfc98c1e9ae230fcp-9,
    -0x1.fffffffffffffp-10
  },
  { // Entry 484
    0x1.000015555888891ad1c98c9e9b0230f4p-9,
    0x1.0p-9
  },
  { // Entry 485
    -0x1.000015555888891ad1c98c9e9b0230f4p-9,
    -0x1.0p-9
  },
  { // Entry 486
    0x1.000015555888991ad5c98d9e9b423144p-9,
    0x1.0000000000001p-9
  },
  { // Entry 487
    -0x1.000015555888991ad5c98d9e9b423144p-9,
    -0x1.0000000000001p-9
  },
  { // Entry 488
    0x1.000005555588808ad12d373b75ab20a3p-10,
    0x1.fffffffffffffp-11
  },
  { // Entry 489
    -0x1.000005555588808ad12d373b75ab20a3p-10,
    -0x1.fffffffffffffp-11
  },
  { // Entry 490
    0x1.000005555588888ad1ad374375aba09fp-10,
    0x1.0p-10
  },
  { // Entry 491
    -0x1.000005555588888ad1ad374375aba09fp-10,
    -0x1.0p-10
  },
  { // Entry 492
    0x1.000005555588988ad2ad375375aca0afp-10,
    0x1.0000000000001p-10
  },
  { // Entry 493
    -0x1.000005555588988ad2ad375375aca0afp-10,
    -0x1.0000000000001p-10
  },
  { // Entry 494
    0x1.0000000555554d8888880ad1ad12ee1ep-14,
    0x1.fffffffffffffp-15
  },
  { // Entry 495
    -0x1.0000000555554d8888880ad1ad12ee1ep-14,
    -0x1.fffffffffffffp-15
  },
  { // Entry 496
    0x1.000000055555558888888ad1ad1aee1ep-14,
    0x1.0p-14
  },
  { // Entry 497
    -0x1.000000055555558888888ad1ad1aee1ep-14,
    -0x1.0p-14
  },
  { // Entry 498
    0x1.000000055555658888898ad1ad2aee1ep-14,
    0x1.0000000000001p-14
  },
  { // Entry 499
    -0x1.000000055555658888898ad1ad2aee1ep-14,
    -0x1.0000000000001p-14
  },
  { // Entry 500
    0x1.fffffffffffff0aaaaaaaaaaaa9b1111p-29,
    0x1.fffffffffffffp-29
  },
  { // Entry 501
    -0x1.fffffffffffff0aaaaaaaaaaaa9b1111p-29,
    -0x1.fffffffffffffp-29
  },
  { // Entry 502
    0x1.00000000000000555555555555558888p-28,
    0x1.0p-28
  },
  { // Entry 503
    -0x1.00000000000000555555555555558888p-28,
    -0x1.0p-28
  },
  { // Entry 504
    0x1.00000000000010555555555555658888p-28,
    0x1.0000000000001p-28
  },
  { // Entry 505
    -0x1.00000000000010555555555555658888p-28,
    -0x1.0000000000001p-28
  },
  { // Entry 506
    0x1.fffffffffffff00aaaaaaaaaaaa9ab11p-31,
    0x1.fffffffffffffp-31
  },
  { // Entry 507
    -0x1.fffffffffffff00aaaaaaaaaaaa9ab11p-31,
    -0x1.fffffffffffffp-31
  },
  { // Entry 508
    0x1.00000000000000055555555555555588p-30,
    0x1.0p-30
  },
  { // Entry 509
    -0x1.00000000000000055555555555555588p-30,
    -0x1.0p-30
  },
  { // Entry 510
    0x1.00000000000010055555555555565588p-30,
    0x1.0000000000001p-30
  },
  { // Entry 511
    -0x1.00000000000010055555555555565588p-30,
    -0x1.0000000000001p-30
  },
  { // Entry 512
    -0x1.193ea7aad030becbf96ee2aa5b029927p-1,
    -0x1.0000000000001p-1
  },
  { // Entry 513
    0x1.193ea7aad030becbf96ee2aa5b029927p-1,
    0x1.0000000000001p-1
  },
  { // Entry 514
    -0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    -0x1.0p-1
  },
  { // Entry 515
    0x1.193ea7aad030a976a4198d55053b7cb5p-1,
    0x1.0p-1
  },
  { // Entry 516
    -0x1.193ea7aad0309ecbf96ee2aa5aad43d2p-1,
    -0x1.fffffffffffffp-2
  },
  { // Entry 517
    0x1.193ea7aad0309ecbf96ee2aa5aad43d2p-1,
    0x1.fffffffffffffp-2
  },
  { // Entry 518
    -0x1.058aefa811452b8387cd4093155eafe4p-2,
    -0x1.0000000000001p-2
  },
  { // Entry 519
    0x1.058aefa811452b8387cd4093155eafe4p-2,
    0x1.0000000000001p-2
  },
  { // Entry 520
    -0x1.058aefa811451a7276bc2f82043b6a7dp-2,
    -0x1.0p-2
  },
  { // Entry 521
    0x1.058aefa811451a7276bc2f82043b6a7dp-2,
    0x1.0p-2
  },
  { // Entry 522
    -0x1.058aefa8114511e9ee33a6f97bb76f0ap-2,
    -0x1.fffffffffffffp-3
  },
  { // Entry 523
    0x1.058aefa8114511e9ee33a6f97bb76f0ap-2,
    0x1.fffffffffffffp-3
  },
  { // Entry 524
    -0x1.015891c9eaef86da4a8a506fa1b18969p-3,
    -0x1.0000000000001p-3
  },
  { // Entry 525
    0x1.015891c9eaef86da4a8a506fa1b18969p-3,
    0x1.0000000000001p-3
  },
  { // Entry 526
    -0x1.015891c9eaef7699467a0f6b916c6494p-3,
    -0x1.0p-3
  },
  { // Entry 527
    0x1.015891c9eaef7699467a0f6b916c6494p-3,
    0x1.0p-3
  },
  { // Entry 528
    -0x1.015891c9eaef6e78c471eee9894ceabdp-3,
    -0x1.fffffffffffffp-4
  },
  { // Entry 529
    0x1.015891c9eaef6e78c471eee9894ceabdp-3,
    0x1.fffffffffffffp-4
  },
  { // Entry 530
    -0x1.005588ad375adddb2322b573d6963771p-4,
    -0x1.0000000000001p-4
  },
  { // Entry 531
    0x1.005588ad375adddb2322b573d6963771p-4,
    0x1.0000000000001p-4
  },
  { // Entry 532
    -0x1.005588ad375acdcb1312a563c685255ep-4,
    -0x1.0p-4
  },
  { // Entry 533
    0x1.005588ad375acdcb1312a563c685255ep-4,
    0x1.0p-4
  },
  { // Entry 534
    -0x1.005588ad375ac5c30b0a9d5bbe7d5dd7p-4,
    -0x1.fffffffffffffp-5
  },
  { // Entry 535
    0x1.005588ad375ac5c30b0a9d5bbe7d5dd7p-4,
    0x1.fffffffffffffp-5
  },
  { // Entry 536
    -0x1.001558891aee34b89ed43dd5ba702a52p-5,
    -0x1.0000000000001p-5
  },
  { // Entry 537
    0x1.001558891aee34b89ed43dd5ba702a52p-5,
    0x1.0000000000001p-5
  },
  { // Entry 538
    -0x1.001558891aee24b49dd3fdc5b66ee9f1p-5,
    -0x1.0p-5
  },
  { // Entry 539
    0x1.001558891aee24b49dd3fdc5b66ee9f1p-5,
    0x1.0p-5
  },
  { // Entry 540
    -0x1.001558891aee1cb29d53ddbdb46e79d9p-5,
    -0x1.fffffffffffffp-6
  },
  { // Entry 541
    0x1.001558891aee1cb29d53ddbdb46e79d9p-5,
    0x1.fffffffffffffp-6
  },
  { // Entry 542
    -0x1.000555888ad1d98f0d4a572aded438c7p-6,
    -0x1.0000000000001p-6
  },
  { // Entry 543
    0x1.000555888ad1d98f0d4a572aded438c7p-6,
    0x1.0000000000001p-6
  },
  { // Entry 544
    -0x1.000555888ad1c98e0d3a562aced328b5p-6,
    -0x1.0p-6
  },
  { // Entry 545
    0x1.000555888ad1c98e0d3a562aced328b5p-6,
    0x1.0p-6
  },
  { // Entry 546
    -0x1.000555888ad1c18d8d3255aac6d2acadp-6,
    -0x1.fffffffffffffp-7
  },
  { // Entry 547
    0x1.000555888ad1c18d8d3255aac6d2acadp-6,
    0x1.fffffffffffffp-7
  },
  { // Entry 548
    -0x1.000155588891bd3783d24fc85db13332p-7,
    -0x1.0000000000001p-7
  },
  { // Entry 549
    0x1.000155588891bd3783d24fc85db13332p-7,
    0x1.0000000000001p-7
  },
  { // Entry 550
    -0x1.000155588891ad3743d14fc45da12ef2p-7,
    -0x1.0p-7
  },
  { // Entry 551
    0x1.000155588891ad3743d14fc45da12ef2p-7,
    0x1.0p-7
  },
  { // Entry 552
    -0x1.000155588891a53723d0cfc25d992fd2p-7,
    -0x1.fffffffffffffp-8
  },
  { // Entry 553
    0x1.000155588891a53723d0cfc25d992fd2p-7,
    0x1.fffffffffffffp-8
  },
  { // Entry 554
    -0x1.000055558888bd1afe1f09341407a85bp-8,
    -0x1.0000000000001p-8
  },
  { // Entry 555
    0x1.000055558888bd1afe1f09341407a85bp-8,
    0x1.0000000000001p-8
  },
  { // Entry 556
    -0x1.000055558888ad1aee1ef9340407975ap-8,
    -0x1.0p-8
  },
  { // Entry 557
    0x1.000055558888ad1aee1ef9340407975ap-8,
    0x1.0p-8
  },
  { // Entry 558
    -0x1.000055558888a51ae61ef133fc078f9ap-8,
    -0x1.fffffffffffffp-9
  },
  { // Entry 559
    0x1.000055558888a51ae61ef133fc078f9ap-8,
    0x1.fffffffffffffp-9
  },
  { // Entry 560
    -0x1.000015555888991ad5c98d9e9b423144p-9,
    -0x1.0000000000001p-9
  },
  { // Entry 561
    0x1.000015555888991ad5c98d9e9b423144p-9,
    0x1.0000000000001p-9
  },
  { // Entry 562
    -0x1.000015555888891ad1c98c9e9b0230f4p-9,
    -0x1.0p-9
  },
  { // Entry 563
    0x1.000015555888891ad1c98c9e9b0230f4p-9,
    0x1.0p-9
  },
  { // Entry 564
    -0x1.000015555888811acfc98c1e9ae230fcp-9,
    -0x1.fffffffffffffp-10
  },
  { // Entry 565
    0x1.000015555888811acfc98c1e9ae230fcp-9,
    0x1.fffffffffffffp-10
  },
  { // Entry 566
    -0x1.000005555588988ad2ad375375aca0afp-10,
    -0x1.0000000000001p-10
  },
  { // Entry 567
    0x1.000005555588988ad2ad375375aca0afp-10,
    0x1.0000000000001p-10
  },
  { // Entry 568
    -0x1.000005555588888ad1ad374375aba09fp-10,
    -0x1.0p-10
  },
  { // Entry 569
    0x1.000005555588888ad1ad374375aba09fp-10,
    0x1.0p-10
  },
  { // Entry 570
    -0x1.000005555588808ad12d373b75ab20a3p-10,
    -0x1.fffffffffffffp-11
  },
  { // Entry 571
    0x1.000005555588808ad12d373b75ab20a3p-10,
    0x1.fffffffffffffp-11
  },
  { // Entry 572
    -0x1.000000055555658888898ad1ad2aee1ep-14,
    -0x1.0000000000001p-14
  },
  { // Entry 573
    0x1.000000055555658888898ad1ad2aee1ep-14,
    0x1.0000000000001p-14
  },
  { // Entry 574
    -0x1.000000055555558888888ad1ad1aee1ep-14,
    -0x1.0p-14
  },
  { // Entry 575
    0x1.000000055555558888888ad1ad1aee1ep-14,
    0x1.0p-14
  },
  { // Entry 576
    -0x1.0000000555554d8888880ad1ad12ee1ep-14,
    -0x1.fffffffffffffp-15
  },
  { // Entry 577
    0x1.0000000555554d8888880ad1ad12ee1ep-14,
    0x1.fffffffffffffp-15
  },
  { // Entry 578
    -0x1.00000000000010555555555555658888p-28,
    -0x1.0000000000001p-28
  },
  { // Entry 579
    0x1.00000000000010555555555555658888p-28,
    0x1.0000000000001p-28
  },
  { // Entry 580
    -0x1.00000000000000555555555555558888p-28,
    -0x1.0p-28
  },
  { // Entry 581
    0x1.00000000000000555555555555558888p-28,
    0x1.0p-28
  },
  { // Entry 582
    -0x1.fffffffffffff0aaaaaaaaaaaa9b1111p-29,
    -0x1.fffffffffffffp-29
  },
  { // Entry 583
    0x1.fffffffffffff0aaaaaaaaaaaa9b1111p-29,
    0x1.fffffffffffffp-29
  },
  { // Entry 584
    -0x1.00000000000010055555555555565588p-30,
    -0x1.0000000000001p-30
  },
  { // Entry 585
    0x1.00000000000010055555555555565588p-30,
    0x1.0000000000001p-30
  },
  { // Entry 586
    -0x1.00000000000000055555555555555588p-30,
    -0x1.0p-30
  },
  { // Entry 587
    0x1.00000000000000055555555555555588p-30,
    0x1.0p-30
  },
  { // Entry 588
    -0x1.fffffffffffff00aaaaaaaaaaaa9ab11p-31,
    -0x1.fffffffffffffp-31
  },
  { // Entry 589
    0x1.fffffffffffff00aaaaaaaaaaaa9ab11p-31,
    0x1.fffffffffffffp-31
  },
  { // Entry 590
    HUGE_VAL,
    0x1.0p0
  },
  { // Entry 591
    -HUGE_VAL,
    -0x1.0p0
  },
  { // Entry 592
    0x1.2b708872320e1d31e4b03f1086a9c047p4,
    0x1.fffffffffffffp-1
  },
  { // Entry 593
    -0x1.2b708872320e1d31e4b03f1086a9c047p4,
    -0x1.fffffffffffffp-1
  },
  { // Entry 594
    0x1.0f2eb070230688149a25318fd8d4ea0fp0,
    0x1.921fb54442d18p-1
  },
  { // Entry 595
    -0x1.0f2eb070230688149a25318fd8d4ea0fp0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 596
    0x1.00000000000010p-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 597
    -0x1.00000000000010p-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 598
    0x1.p-1022,
    0x1.0p-1022
  },
  { // Entry 599
    -0x1.p-1022,
    -0x1.0p-1022
  },
  { // Entry 600
    0x1.ffffffffffffe0p-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 601
    -0x1.ffffffffffffe0p-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 602
    0x1.ffffffffffffc0p-1023,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 603
    -0x1.ffffffffffffc0p-1023,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 604
    0x1.p-1073,
    0x1.0p-1073
  },
  { // Entry 605
    -0x1.p-1073,
    -0x1.0p-1073
  },
  { // Entry 606
    0x1.p-1074,
    0x1.0p-1074
  },
  { // Entry 607
    -0x1.p-1074,
    -0x1.0p-1074
  },
  { // Entry 608
    0.0,
    0.0
  },
  { // Entry 609
    -0.0,
    -0.0
  }
};
```
Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Task:**

The central task is to analyze a data file (`fmaf_intel_data.handroid`) containing floating-point numbers and infer its purpose within the Android bionic library, specifically concerning the `fmaf` function. The prompt asks for functionality, Android relevance, libc/dynamic linker details (if applicable), logical reasoning, common errors, and how to reach this code from higher levels, culminating in a summary for part 4.

**2. Initial Observations and Deductions:**

* **File Type and Location:** The file is a `.handroid` file in a `tests/math_data` directory within bionic. This strongly suggests it's test data for mathematical functions.
* **Data Structure:** The data is a C++ array of structs (or similar aggregate type). Each element of the array contains four floating-point numbers.
* **Number Format:** The numbers are represented in hexadecimal floating-point format (e.g., `0x1.fffffdffffffffffffffffffffffffffp127`). This is common in low-level math libraries for precise representation.
* **`fmaf` in the Filename:** The filename includes `fmaf`, which is the standard C library function for fused multiply-add. This is a significant clue.
* **"Intel Data":** This suggests the data might be specifically designed or sourced from Intel's testing or specifications related to `fmaf`.

**3. Inferring Functionality (Core Purpose):**

Based on the observations, the primary function of this file is to provide test cases for the `fmaf` function. Each entry likely represents a specific set of inputs and the expected output for `fmaf(a, b, c)`.

**4. Connecting to Android Functionality:**

* **Bionic's Role:** Bionic is Android's standard C library, so its math functions are directly used by Android at all levels (framework, NDK, system services).
* **`fmaf` Usage:** The `fmaf` function is used for performance and accuracy in floating-point calculations. Examples include graphics processing, scientific computing, audio/video processing, and even general application logic. Specifically mentioning OpenGL and audio processing provides concrete examples.

**5. Addressing libc and Dynamic Linker:**

* **libc `fmaf` Implementation:** The request asks about the implementation. Since this is *test data*, this file itself doesn't *implement* `fmaf`. The actual implementation would be in a separate source file (likely in `bionic/libc/math`). The answer correctly notes that the implementation would vary by architecture and potentially leverage hardware instructions.
* **Dynamic Linker:** This data file doesn't directly involve the dynamic linker. It's statically compiled into the test executable. Therefore, the answer correctly states that no specific SO layout or linking process is directly relevant to *this file*. However, it's important to acknowledge that the `fmaf` *function itself* resides in `libc.so` and would be linked dynamically.

**6. Logical Reasoning (Input/Output Assumptions):**

The assumption is that each four-element entry `[a, b, c, expected_result]` is a test case for `fmaf(a, b, c)`. The answer gives examples of how `fmaf` works, combining multiplication and addition with a single rounding. This justifies the structure of the test data.

**7. Common Usage Errors:**

Relating to `fmaf`, common errors include:
* Misunderstanding its behavior (not realizing it's a *fused* operation).
* Incorrectly using it when standard multiplication and addition would suffice (overcomplicating).
* Not considering potential floating-point precision issues, although `fmaf` generally improves accuracy.

**8. Reaching the Code (Android Framework/NDK):**

This requires tracing the execution path. The answer correctly outlines a potential path:

1. **Application Code (Java/Kotlin or NDK):**  The starting point is usually an app calling some API.
2. **Framework (If Applicable):** The framework might use native code for performance-critical operations.
3. **NDK (Direct Native Calls):** If the app uses the NDK, it can directly call `fmaf`.
4. **libc.so:** The `fmaf` function resides in `libc.so`.
5. **`fmaf_intel_data.handroid`:** This file is used during testing of the `fmaf` implementation.

The Frida hook example targets the `fmaf` function in `libc.so`, demonstrating how to intercept and inspect calls to it. It's crucial to hook the *function*, not the data file itself.

**9. Summarizing Functionality (Part 4):**

The summary should concisely reiterate the main purpose of the file within the context of the broader task. It should highlight that this is *test data* specifically for `fmaf`, used for verification and quality assurance.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Could this be some kind of precomputed lookup table for `fmaf`?  **Correction:** The size and structure suggest it's more likely test data for various input combinations, rather than a comprehensive lookup.
* **Clarifying Dynamic Linker:**  While the file itself isn't directly involved in dynamic linking, the `fmaf` function it tests *is* part of a dynamically linked library. It's important to make this distinction clear.
* **Frida Hook Target:** Initially, one might think of hooking something related to the data file. **Correction:** The Frida hook should target the `fmaf` *function* in `libc.so` to observe its execution with this test data (or any other input).

By following these steps and engaging in some self-correction, a comprehensive and accurate answer can be generated.
好的，让我们来归纳一下这个代码片段的功能。

**代码片段功能归纳：**

这段代码是 `bionic/tests/math_data/fmaf_intel_data.handroid` 文件的一部分，它定义了一个C++数组，用于存储一系列用于测试 `fmaf` (浮点数乘加运算) 函数的测试用例数据。

**更具体地说：**

* **存储测试数据:**  该数组的每个元素都是一个包含四个 `float` 类型数值的结构体（或者可以理解为一个包含四个 `float` 的数组）。
* **`fmaf` 函数的测试:**  这些数据用于测试 `fmaf` 函数在各种输入情况下的行为。 `fmaf(a, b, c)` 计算 `(a * b) + c`，但使用单次舍入，这在某些情况下可以提高精度。
* **Intel 数据:**  文件名中的 "intel_data" 表明这些测试用例可能来源于 Intel 提供的或基于 Intel 处理器的特性设计的。

**与 Android 功能的关系：**

这个数据文件直接关系到 Android 的底层数学库 `bionic` 的质量保证。`fmaf` 是一个标准的 C99 数学库函数，在 Android 中被广泛使用，尤其是在需要高性能和精确浮点运算的场景中。

**举例说明：**

1. **图形处理 (OpenGL ES):**  图形渲染管线中会进行大量的矩阵和向量运算，其中可能用到 `fmaf` 来提高计算效率和精度。例如，在计算光照模型时。
2. **音频/视频处理:**  音频和视频编解码器中也会涉及到复杂的浮点运算，`fmaf` 可以用于优化这些计算过程。
3. **科学计算和机器学习库 (通过 NDK):**  如果 Android 应用通过 NDK 使用了底层的科学计算库或机器学习库，这些库很可能会调用 `fmaf` 来执行数值计算。

**libc 函数功能解释 (不直接涉及，但相关):**

这个数据文件本身并不直接实现任何 libc 函数。它提供的是 *测试数据*，用于验证 libc 中 `fmaf` 函数的实现是否正确。

`fmaf(float x, float y, float z)` 的功能是计算 `(x * y) + z`，并返回结果。  其关键在于 "fuse" (融合) 的概念，即乘法和加法操作在一个步骤内完成，中间结果不进行舍入。这与先计算乘法再计算加法，各自进行舍入的方式不同。`fmaf` 可以提供更高的精度，尤其是在中间结果有很多有效数字的情况下。

**Dynamic Linker 功能 (不直接涉及):**

这个数据文件是静态数据，会被编译到测试可执行文件中。它不涉及动态链接。  `fmaf` 函数的实现位于 `libc.so` 中，这是一个会被动态链接的共享库。

**SO 布局样本 (与 `fmaf` 相关):**

```
libc.so:
    ...
    .text:00010000 T fmaf     ; 函数 fmaf 的代码
    ...
    .data:000A0000 D some_global_data
    ...
```

**链接的处理过程 (与 `fmaf` 相关):**

1. **编译时:** 当一个使用 `fmaf` 的程序被编译时，编译器会在其目标文件中记录对 `fmaf` 的未定义引用。
2. **链接时:** 链接器 (在 Android 上通常是 `lld`) 会查找 `fmaf` 函数的定义。如果在静态库中找不到，链接器会在指定的共享库 (`libc.so`) 中查找。
3. **运行时:** 当程序启动时，动态链接器 (`linker64` 或 `linker`) 会加载 `libc.so` 到内存中。然后，它会解析程序中对 `fmaf` 的未定义引用，并将其指向 `libc.so` 中 `fmaf` 函数的实际地址。

**逻辑推理 (假设输入与输出):**

例如，考虑 Entry 1057:

```c++
  { // Entry 1057
    0.0f,
    0x1.p-126,
    -0x1.p-126,
    0x1.p-149
  },
```

* **假设输入:** `a = 0.0f`, `b = 0x1.p-126` (一个很小的正数), `c = -0x1.p-126` (与 `b` 大小相同但符号相反)
* **预期输出:** `0x1.p-149` (一个非常小的正数)

**推理:**

`fmaf(0.0f, 0x1.p-126, -0x1.p-126)` 应该计算 `(0.0f * 0x1.p-126) + (-0x1.p-126)`。

1. `0.0f * 0x1.p-126` 的结果是 `0.0f`。
2. `0.0f + (-0x1.p-126)` 的结果是 `-0x1.p-126`。

**这里可能存在一个错误或者需要更深入的理解 `fmaf` 的行为，特别是当涉及到零和非常小的数字时。预期输出 `0x1.p-149` 表明测试用例可能旨在检查某些边界情况或精度问题。**

**常见使用错误:**

1. **不必要的精度要求:** 有些开发者可能在不需要高精度的情况下也使用 `fmaf`，这可能会增加代码复杂性，但实际收益不大。
2. **误解 `fmaf` 的语义:**  可能没有理解 `fmaf` 的融合乘加特性，认为它与普通的乘法和加法没有区别。
3. **忽略浮点数的特殊值:** 在使用 `fmaf` 时，没有考虑到 NaN (非数字)、无穷大等特殊浮点值可能导致的结果。

**Android Framework 或 NDK 如何到达这里:**

1. **应用层 (Java/Kotlin):** 应用程序调用 Android Framework 提供的 API，例如用于图形渲染、音频处理或进行数值计算的 API。
2. **Framework 层 (C++/Java):** Framework 层的代码在执行这些 API 时，可能会调用底层的 native 代码 (C/C++) 来完成一些性能敏感的任务.
3. **NDK (Native Development Kit):**  如果开发者使用 NDK 直接编写 native 代码，他们可以直接调用 `fmaf` 函数，该函数位于 `libc.so` 中。
4. **libc.so:**  当 native 代码调用 `fmaf` 时，实际上会链接到 `bionic` 提供的 `libc.so` 中的 `fmaf` 实现。
5. **测试 (开发/构建阶段):**  在 `bionic` 的开发和测试阶段，会运行各种测试用例来验证 `fmaf` 函数的实现是否正确。`fmaf_intel_data.handroid` 文件中的数据就是用于这些测试。

**Frida Hook 示例调试步骤:**

假设你想在 Android 应用中使用 Frida hook 来观察对 `fmaf` 的调用和参数：

```python
import frida
import sys

# 连接到设备上的应用
process_name = "your.application.package.name"
session = frida.attach(process_name)

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fmaf"), {
    onEnter: function(args) {
        console.log("Called fmaf with arguments:");
        console.log("  arg0 (x): " + args[0]);
        console.log("  arg1 (y): " + args[1]);
        console.log("  arg2 (z): " + args[2]);
        // 可以选择读取内存中的浮点数值
        console.log("  x value: " + ptr(args[0]).readFloat());
        console.log("  y value: " + ptr(args[1]).readFloat());
        console.log("  z value: " + ptr(args[2]).readFloat());
    },
    onLeave: function(retval) {
        console.log("fmaf returned: " + retval);
        console.log("  Return value: " + ptr(retval).readFloat());
    }
});
"""

# 创建 Frida 脚本
script = session.create_script(script_code)

# 加载脚本
script.load()

# 等待用户输入退出
print("Script loaded. Press Enter to exit.")
sys.stdin.read()

# 卸载脚本和断开连接
session.detach()
```

**解释：**

1. **连接到进程:**  指定要 hook 的 Android 应用的包名，Frida 会连接到该应用的进程。
2. **查找 `fmaf` 函数:**  `Module.findExportByName("libc.so", "fmaf")` 用于在 `libc.so` 中查找 `fmaf` 函数的地址。
3. **Hook `onEnter`:**  当 `fmaf` 函数被调用时，`onEnter` 函数会被执行。你可以访问 `args` 数组来获取传递给 `fmaf` 的参数指针。
4. **读取浮点数值:**  使用 `ptr(args[i]).readFloat()` 可以读取指针指向的内存中的浮点数值。
5. **Hook `onLeave`:**  当 `fmaf` 函数执行完毕并返回时，`onLeave` 函数会被执行。你可以访问 `retval` 来获取返回值指针。
6. **读取返回值:**  使用 `ptr(retval).readFloat()` 可以读取返回值指针指向的浮点数值。

通过运行这个 Frida 脚本，你可以在应用运行过程中观察到对 `fmaf` 函数的调用，并打印出其参数和返回值，从而帮助你调试相关的逻辑。

希望以上归纳和解释能够帮助你理解这个代码片段的功能及其在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/math_data/fmaf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-126,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1052
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1053
    0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.p-126,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1054
    -0x1.00000000000000000000000000000004p-126,
    0x1.p-126,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1055
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.p-126,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1056
    -0x1.fffffc00000000000000000000000008p-127,
    0x1.p-126,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1057
    0.0f,
    0x1.p-126,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1058
    -0x1.00000000000000000000000002p-149,
    0x1.p-126,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1059
    -0.0f,
    0x1.p-126,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1060
    -0.0f,
    0x1.p-126,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1061
    HUGE_VALF,
    0x1.p-126,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1062
    -HUGE_VALF,
    0x1.p-126,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1063
    0x1.fffffep127,
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1064
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-126,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1065
    0x1.00000000000000000000000000000003p-126,
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1066
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.p-126,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1067
    0x1.fffffc00000000000000000000000007p-127,
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1068
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.p-126,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1069
    0x1.00000000000000000000000001fffffcp-149,
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1070
    -0.0f,
    0x1.p-126,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1071
    0.0f,
    0x1.p-126,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1072
    0.0f,
    0x1.p-126,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1073
    HUGE_VALF,
    0x1.p-126,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1074
    -HUGE_VALF,
    0x1.p-126,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1075
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-126,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1076
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1077
    0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.p-126,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1078
    -0x1.00000000000000000000000000000003p-126,
    0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1079
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.p-126,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1080
    -0x1.fffffc00000000000000000000000007p-127,
    0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1081
    0.0f,
    0x1.p-126,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1082
    -0x1.00000000000000000000000001fffffcp-149,
    0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1083
    -0.0f,
    0x1.p-126,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1084
    -0.0f,
    0x1.p-126,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1085
    HUGE_VALF,
    0x1.p-126,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1086
    -HUGE_VALF,
    0x1.p-126,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1087
    0x1.fffffep127,
    0x1.p-126,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1088
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-126,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1089
    0x1.p-126,
    0x1.p-126,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1090
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1091
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1092
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-126,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1093
    0x1.00000000000000000000000000000004p-149,
    0x1.p-126,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1094
    -0.0f,
    0x1.p-126,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1095
    0.0f,
    0x1.p-126,
    0x1.p-149,
    0.0f
  },
  { // Entry 1096
    0.0f,
    0x1.p-126,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1097
    HUGE_VALF,
    0x1.p-126,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1098
    -HUGE_VALF,
    0x1.p-126,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1099
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.p-126,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1100
    -0x1.fffffep127,
    0x1.p-126,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1101
    0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.p-126,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1102
    -0x1.p-126,
    0x1.p-126,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1103
    0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.p-126,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1104
    -0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1105
    0.0f,
    0x1.p-126,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1106
    -0x1.00000000000000000000000000000004p-149,
    0x1.p-126,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1107
    -0.0f,
    0x1.p-126,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1108
    -0.0f,
    0x1.p-126,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1109
    HUGE_VALF,
    0x1.p-126,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1110
    -HUGE_VALF,
    0x1.p-126,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1111
    0x1.fffffep127,
    0x1.p-126,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1112
    -0x1.fffffep127,
    0x1.p-126,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1113
    0x1.p-126,
    0x1.p-126,
    0.0f,
    0x1.p-126
  },
  { // Entry 1114
    -0x1.p-126,
    0x1.p-126,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1115
    0x1.fffffcp-127,
    0x1.p-126,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1116
    -0x1.fffffcp-127,
    0x1.p-126,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1117
    0x1.p-149,
    0x1.p-126,
    0.0f,
    0x1.p-149
  },
  { // Entry 1118
    -0x1.p-149,
    0x1.p-126,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1119
    0.0,
    0x1.p-126,
    0.0f,
    0.0f
  },
  { // Entry 1120
    0.0,
    0x1.p-126,
    0.0f,
    -0.0f
  },
  { // Entry 1121
    HUGE_VALF,
    0x1.p-126,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1122
    -HUGE_VALF,
    0x1.p-126,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1123
    0x1.fffffep127,
    0x1.p-126,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1124
    -0x1.fffffep127,
    0x1.p-126,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1125
    0x1.p-126,
    0x1.p-126,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1126
    -0x1.p-126,
    0x1.p-126,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1127
    0x1.fffffcp-127,
    0x1.p-126,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1128
    -0x1.fffffcp-127,
    0x1.p-126,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1129
    0x1.p-149,
    0x1.p-126,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1130
    -0x1.p-149,
    0x1.p-126,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1131
    0.0,
    0x1.p-126,
    -0.0f,
    0.0f
  },
  { // Entry 1132
    -0.0,
    0x1.p-126,
    -0.0f,
    -0.0f
  },
  { // Entry 1133
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 1134
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1135
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1136
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1137
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1138
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1139
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1140
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1141
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1142
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    0.0f
  },
  { // Entry 1143
    -HUGE_VALF,
    -0x1.p-126,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 1144
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 1145
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1146
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1147
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1148
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1149
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1150
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1151
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1152
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1153
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 1154
    HUGE_VALF,
    -0x1.p-126,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 1155
    HUGE_VALF,
    -0x1.p-126,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1156
    -HUGE_VALF,
    -0x1.p-126,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1157
    0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.p-126,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1158
    -0x1.fffffe00000000000000000000000007p127,
    -0x1.p-126,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1159
    -0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.p-126,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1160
    -0x1.fffffe00000000000000000000000002p1,
    -0x1.p-126,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1161
    -0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.p-126,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1162
    -0x1.fffffe00000000000000000000000001p1,
    -0x1.p-126,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1163
    -0x1.fffffdffffffffffffffffffffffffffp1,
    -0x1.p-126,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1164
    -0x1.fffffep1,
    -0x1.p-126,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1165
    -0x1.fffffep1,
    -0x1.p-126,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1166
    -0x1.fffffep1,
    -0x1.p-126,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1167
    HUGE_VALF,
    -0x1.p-126,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1168
    -HUGE_VALF,
    -0x1.p-126,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1169
    0x1.fffffe00000000000000000000000007p127,
    -0x1.p-126,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1170
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    -0x1.p-126,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1171
    0x1.fffffe00000000000000000000000002p1,
    -0x1.p-126,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1172
    0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.p-126,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1173
    0x1.fffffe00000000000000000000000001p1,
    -0x1.p-126,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1174
    0x1.fffffdfffffffffffffffffffffffffep1,
    -0x1.p-126,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1175
    0x1.fffffep1,
    -0x1.p-126,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1176
    0x1.fffffdffffffffffffffffffffffffffp1,
    -0x1.p-126,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1177
    0x1.fffffep1,
    -0x1.p-126,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1178
    0x1.fffffep1,
    -0x1.p-126,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1179
    HUGE_VALF,
    -0x1.p-126,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1180
    -HUGE_VALF,
    -0x1.p-126,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1181
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1182
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1183
    0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1184
    -0x1.00000000000000000000000000000004p-126,
    -0x1.p-126,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1185
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1186
    -0x1.fffffc00000000000000000000000008p-127,
    -0x1.p-126,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1187
    0.0f,
    -0x1.p-126,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1188
    -0x1.00000000000000000000000002p-149,
    -0x1.p-126,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1189
    -0.0f,
    -0x1.p-126,
    0x1.p-126,
    0.0f
  },
  { // Entry 1190
    -0.0f,
    -0x1.p-126,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1191
    HUGE_VALF,
    -0x1.p-126,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1192
    -HUGE_VALF,
    -0x1.p-126,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1193
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1194
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1195
    0x1.00000000000000000000000000000004p-126,
    -0x1.p-126,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1196
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1197
    0x1.fffffc00000000000000000000000008p-127,
    -0x1.p-126,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1198
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1199
    0x1.00000000000000000000000002p-149,
    -0x1.p-126,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1200
    -0.0f,
    -0x1.p-126,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1201
    0.0f,
    -0x1.p-126,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1202
    0.0f,
    -0x1.p-126,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1203
    HUGE_VALF,
    -0x1.p-126,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1204
    -HUGE_VALF,
    -0x1.p-126,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1205
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1206
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1207
    0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1208
    -0x1.00000000000000000000000000000003p-126,
    -0x1.p-126,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1209
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1210
    -0x1.fffffc00000000000000000000000007p-127,
    -0x1.p-126,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1211
    0.0f,
    -0x1.p-126,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1212
    -0x1.00000000000000000000000001fffffcp-149,
    -0x1.p-126,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1213
    -0.0f,
    -0x1.p-126,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1214
    -0.0f,
    -0x1.p-126,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1215
    HUGE_VALF,
    -0x1.p-126,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1216
    -HUGE_VALF,
    -0x1.p-126,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1217
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1218
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1219
    0x1.00000000000000000000000000000003p-126,
    -0x1.p-126,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1220
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1221
    0x1.fffffc00000000000000000000000007p-127,
    -0x1.p-126,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1222
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1223
    0x1.00000000000000000000000001fffffcp-149,
    -0x1.p-126,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1224
    -0.0f,
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1225
    0.0f,
    -0x1.p-126,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1226
    0.0f,
    -0x1.p-126,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1227
    HUGE_VALF,
    -0x1.p-126,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1228
    -HUGE_VALF,
    -0x1.p-126,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1229
    0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1230
    -0x1.fffffep127,
    -0x1.p-126,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1231
    0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1232
    -0x1.p-126,
    -0x1.p-126,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1233
    0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-126,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1234
    -0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1235
    0.0f,
    -0x1.p-126,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1236
    -0x1.00000000000000000000000000000004p-149,
    -0x1.p-126,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1237
    -0.0f,
    -0x1.p-126,
    0x1.p-149,
    0.0f
  },
  { // Entry 1238
    -0.0f,
    -0x1.p-126,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1239
    HUGE_VALF,
    -0x1.p-126,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1240
    -HUGE_VALF,
    -0x1.p-126,
    -0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1241
    0x1.fffffep127,
    -0x1.p-126,
    -0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1242
    -0x1.fffffdffffffffffffffffffffffffffp127,
    -0x1.p-126,
    -0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1243
    0x1.p-126,
    -0x1.p-126,
    -0x1.p-149,
    0x1.p-126
  },
  { // Entry 1244
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    -0x1.p-126,
    -0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1245
    0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1246
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    -0x1.p-126,
    -0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1247
    0x1.00000000000000000000000000000004p-149,
    -0x1.p-126,
    -0x1.p-149,
    0x1.p-149
  },
  { // Entry 1248
    -0.0f,
    -0x1.p-126,
    -0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1249
    0.0f,
    -0x1.p-126,
    -0x1.p-149,
    0.0f
  },
  { // Entry 1250
    0.0f,
    -0x1.p-126,
    -0x1.p-149,
    -0.0f
  },
  { // Entry 1251
    HUGE_VALF,
    -0x1.p-126,
    0.0f,
    HUGE_VALF
  },
  { // Entry 1252
    -HUGE_VALF,
    -0x1.p-126,
    0.0f,
    -HUGE_VALF
  },
  { // Entry 1253
    0x1.fffffep127,
    -0x1.p-126,
    0.0f,
    0x1.fffffep127
  },
  { // Entry 1254
    -0x1.fffffep127,
    -0x1.p-126,
    0.0f,
    -0x1.fffffep127
  },
  { // Entry 1255
    0x1.p-126,
    -0x1.p-126,
    0.0f,
    0x1.p-126
  },
  { // Entry 1256
    -0x1.p-126,
    -0x1.p-126,
    0.0f,
    -0x1.p-126
  },
  { // Entry 1257
    0x1.fffffcp-127,
    -0x1.p-126,
    0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1258
    -0x1.fffffcp-127,
    -0x1.p-126,
    0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1259
    0x1.p-149,
    -0x1.p-126,
    0.0f,
    0x1.p-149
  },
  { // Entry 1260
    -0x1.p-149,
    -0x1.p-126,
    0.0f,
    -0x1.p-149
  },
  { // Entry 1261
    0.0,
    -0x1.p-126,
    0.0f,
    0.0f
  },
  { // Entry 1262
    -0.0,
    -0x1.p-126,
    0.0f,
    -0.0f
  },
  { // Entry 1263
    HUGE_VALF,
    -0x1.p-126,
    -0.0f,
    HUGE_VALF
  },
  { // Entry 1264
    -HUGE_VALF,
    -0x1.p-126,
    -0.0f,
    -HUGE_VALF
  },
  { // Entry 1265
    0x1.fffffep127,
    -0x1.p-126,
    -0.0f,
    0x1.fffffep127
  },
  { // Entry 1266
    -0x1.fffffep127,
    -0x1.p-126,
    -0.0f,
    -0x1.fffffep127
  },
  { // Entry 1267
    0x1.p-126,
    -0x1.p-126,
    -0.0f,
    0x1.p-126
  },
  { // Entry 1268
    -0x1.p-126,
    -0x1.p-126,
    -0.0f,
    -0x1.p-126
  },
  { // Entry 1269
    0x1.fffffcp-127,
    -0x1.p-126,
    -0.0f,
    0x1.fffffcp-127
  },
  { // Entry 1270
    -0x1.fffffcp-127,
    -0x1.p-126,
    -0.0f,
    -0x1.fffffcp-127
  },
  { // Entry 1271
    0x1.p-149,
    -0x1.p-126,
    -0.0f,
    0x1.p-149
  },
  { // Entry 1272
    -0x1.p-149,
    -0x1.p-126,
    -0.0f,
    -0x1.p-149
  },
  { // Entry 1273
    0.0,
    -0x1.p-126,
    -0.0f,
    0.0f
  },
  { // Entry 1274
    0.0,
    -0x1.p-126,
    -0.0f,
    -0.0f
  },
  { // Entry 1275
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    HUGE_VALF
  },
  { // Entry 1276
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1277
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1278
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1279
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1280
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1281
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1282
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1283
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1284
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    0.0f
  },
  { // Entry 1285
    HUGE_VALF,
    0x1.fffffcp-127,
    HUGE_VALF,
    -0.0f
  },
  { // Entry 1286
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    -HUGE_VALF
  },
  { // Entry 1287
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.fffffep127
  },
  { // Entry 1288
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.fffffep127
  },
  { // Entry 1289
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.p-126
  },
  { // Entry 1290
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.p-126
  },
  { // Entry 1291
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.fffffcp-127
  },
  { // Entry 1292
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.fffffcp-127
  },
  { // Entry 1293
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    0x1.p-149
  },
  { // Entry 1294
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    -0x1.p-149
  },
  { // Entry 1295
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    0.0f
  },
  { // Entry 1296
    -HUGE_VALF,
    0x1.fffffcp-127,
    -HUGE_VALF,
    -0.0f
  },
  { // Entry 1297
    HUGE_VALF,
    0x1.fffffcp-127,
    0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1298
    -HUGE_VALF,
    0x1.fffffcp-127,
    0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1299
    0x1.fffffe00000000000000000000000007p127,
    0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1300
    -0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1301
    0x1.fffffa00000400000000000000000002p1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1302
    0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1303
    0x1.fffffa00000400000000000000000001p1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1304
    0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1305
    0x1.fffffa000004p1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1306
    0x1.fffffa000003ffffffffffffffffffffp1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1307
    0x1.fffffa000004p1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    0.0f
  },
  { // Entry 1308
    0x1.fffffa000004p1,
    0x1.fffffcp-127,
    0x1.fffffep127,
    -0.0f
  },
  { // Entry 1309
    HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    HUGE_VALF
  },
  { // Entry 1310
    -HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -HUGE_VALF
  },
  { // Entry 1311
    0x1.fffffdfffffffffffffffffffffffff8p127,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.fffffep127
  },
  { // Entry 1312
    -0x1.fffffe00000000000000000000000007p127,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.fffffep127
  },
  { // Entry 1313
    -0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.p-126
  },
  { // Entry 1314
    -0x1.fffffa00000400000000000000000002p1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.p-126
  },
  { // Entry 1315
    -0x1.fffffa000003fffffffffffffffffffep1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.fffffcp-127
  },
  { // Entry 1316
    -0x1.fffffa00000400000000000000000001p1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.fffffcp-127
  },
  { // Entry 1317
    -0x1.fffffa000003ffffffffffffffffffffp1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    0x1.p-149
  },
  { // Entry 1318
    -0x1.fffffa000004p1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -0x1.p-149
  },
  { // Entry 1319
    -0x1.fffffa000004p1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    0.0f
  },
  { // Entry 1320
    -0x1.fffffa000004p1,
    0x1.fffffcp-127,
    -0x1.fffffep127,
    -0.0f
  },
  { // Entry 1321
    HUGE_VALF,
    0x1.fffffcp-127,
    0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1322
    -HUGE_VALF,
    0x1.fffffcp-127,
    0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1323
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1324
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1325
    0x1.00000000000000000000000000000003p-126,
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-126
  },
  { // Entry 1326
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1327
    0x1.fffffc00000000000000000000000007p-127,
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1328
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1329
    0x1.00000000000000000000000001fffffcp-149,
    0x1.fffffcp-127,
    0x1.p-126,
    0x1.p-149
  },
  { // Entry 1330
    -0.0f,
    0x1.fffffcp-127,
    0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1331
    0.0f,
    0x1.fffffcp-127,
    0x1.p-126,
    0.0f
  },
  { // Entry 1332
    0.0f,
    0x1.fffffcp-127,
    0x1.p-126,
    -0.0f
  },
  { // Entry 1333
    HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.p-126,
    HUGE_VALF
  },
  { // Entry 1334
    -HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.p-126,
    -HUGE_VALF
  },
  { // Entry 1335
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffcp-127,
    -0x1.p-126,
    0x1.fffffep127
  },
  { // Entry 1336
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.fffffep127
  },
  { // Entry 1337
    0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-126
  },
  { // Entry 1338
    -0x1.00000000000000000000000000000003p-126,
    0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.p-126
  },
  { // Entry 1339
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    -0x1.p-126,
    0x1.fffffcp-127
  },
  { // Entry 1340
    -0x1.fffffc00000000000000000000000007p-127,
    0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.fffffcp-127
  },
  { // Entry 1341
    0.0f,
    0x1.fffffcp-127,
    -0x1.p-126,
    0x1.p-149
  },
  { // Entry 1342
    -0x1.00000000000000000000000001fffffcp-149,
    0x1.fffffcp-127,
    -0x1.p-126,
    -0x1.p-149
  },
  { // Entry 1343
    -0.0f,
    0x1.fffffcp-127,
    -0x1.p-126,
    0.0f
  },
  { // Entry 1344
    -0.0f,
    0x1.fffffcp-127,
    -0x1.p-126,
    -0.0f
  },
  { // Entry 1345
    HUGE_VALF,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1346
    -HUGE_VALF,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1347
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1348
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1349
    0x1.00000000000000000000000000000003p-126,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1350
    -0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1351
    0x1.fffffc00000000000000000000000007p-127,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1352
    -0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1353
    0x1.00000000000000000000000001fffff8p-149,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1354
    -0.0f,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1355
    0.0f,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1356
    0.0f,
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1357
    HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    HUGE_VALF
  },
  { // Entry 1358
    -HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -HUGE_VALF
  },
  { // Entry 1359
    0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.fffffep127
  },
  { // Entry 1360
    -0x1.fffffep127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.fffffep127
  },
  { // Entry 1361
    0x1.fffffffffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.p-126
  },
  { // Entry 1362
    -0x1.00000000000000000000000000000003p-126,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.p-126
  },
  { // Entry 1363
    0x1.fffffbfffffffffffffffffffffffff8p-127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.fffffcp-127
  },
  { // Entry 1364
    -0x1.fffffc00000000000000000000000007p-127,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.fffffcp-127
  },
  { // Entry 1365
    0.0f,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0x1.p-149
  },
  { // Entry 1366
    -0x1.00000000000000000000000001fffff8p-149,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0x1.p-149
  },
  { // Entry 1367
    -0.0f,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    0.0f
  },
  { // Entry 1368
    -0.0f,
    0x1.fffffcp-127,
    -0x1.fffffcp-127,
    -0.0f
  },
  { // Entry 1369
    HUGE_VALF,
    0x1.fffffcp-127,
    0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1370
    -HUGE_VALF,
    0x1.fffffcp-127,
    0x1.p-149,
    -HUGE_VALF
  },
  { // Entry 1371
    0x1.fffffep127,
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.fffffep127
  },
  { // Entry 1372
    -0x1.fffffdffffffffffffffffffffffffffp127,
    0x1.fffffcp-127,
    0x1.p-149,
    -0x1.fffffep127
  },
  { // Entry 1373
    0x1.p-126,
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.p-126
  },
  { // Entry 1374
    -0x1.ffffffffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127,
    0x1.p-149,
    -0x1.p-126
  },
  { // Entry 1375
    0x1.fffffcp-127,
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.fffffcp-127
  },
  { // Entry 1376
    -0x1.fffffbffffffffffffffffffffffffffp-127,
    0x1.fffffcp-127,
    0x1.p-149,
    -0x1.fffffcp-127
  },
  { // Entry 1377
    0x1.00000000000000000000000000000003p-149,
    0x1.fffffcp-127,
    0x1.p-149,
    0x1.p-149
  },
  { // Entry 1378
    -0.0f,
    0x1.fffffcp-127,
    0x1.p-149,
    -0x1.p-149
  },
  { // Entry 1379
    0.0f,
    0x1.fffffcp-127,
    0x1.p-149,
    0.0f
  },
  { // Entry 1380
    0.0f,
    0x1.fffffcp-127,
    0x1.p-149,
    -0.0f
  },
  { // Entry 1381
    HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.p-149,
    HUGE_VALF
  },
  { // Entry 1382
    -HUGE_VALF,
    0x1.fffffcp-127,
    -0x1.p-149,
```
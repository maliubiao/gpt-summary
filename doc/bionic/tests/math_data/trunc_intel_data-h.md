Response:
Let's break down the thought process to answer the user's request about the `trunc_intel_data.handroid` file.

**1. Understanding the Context:**

The prompt clearly states the file's location: `bionic/tests/math_data/trunc_intel_data.handroid`. It also mentions that `bionic` is Android's C library, math library, and dynamic linker. This immediately tells us:

* **Purpose:** The file is related to mathematical operations within Android's core libraries.
* **Testing:** The `tests` directory indicates this file is used for testing purposes.
* **Data-Driven:** The `_data` and the structure `data_1_1_t<double, double>` strongly suggest this file contains test data.
* **`trunc`:** The filename hints at the mathematical function being tested: `trunc()`.
* **`intel`:**  This suggests the data might be specifically relevant to Intel architectures or potentially some optimization/variation related to Intel's floating-point behavior.
* **`.handroid`:** This suffix is likely a convention within the Android build system or test infrastructure. It doesn't necessarily imply a drastically different file format compared to a `.c` or `.h` file containing similar data.

**2. Analyzing the File Content:**

The file contains a static array named `g_trunc_intel_data`. Each element in the array is a structure containing two `double` values. The comments like "// Entry 0", "// Entry 1", etc., are simple index markers. The hexadecimal floating-point literals (e.g., `-0x1.0p-1074`) are key.

**3. Inferring Functionality:**

Based on the filename and data structure, the primary function is to provide test cases for the `trunc()` function. Each entry in the array likely represents an input value (the second `double`) and the expected output of `trunc()` for that input (the first `double`).

**4. Connecting to Android Functionality:**

The `trunc()` function is a standard C library function (from `math.h` or `cmath`). In Android, this function is implemented within `bionic`. This file is a *test* for that implementation. The data likely aims to cover various edge cases, including:

* Positive and negative values
* Values close to zero
* Large and small values
* Integer and fractional parts
* Edge cases related to floating-point representation (like subnormal numbers).

**5. Explaining `libc` Functions:**

The core function here is `trunc()`. The explanation should focus on its mathematical definition: rounding a floating-point number towards zero. It should also highlight the difference between `trunc()`, `floor()`, and `ceil()`.

**6. Dynamic Linker Aspects:**

While this specific file doesn't *directly* involve the dynamic linker, it's part of `bionic`, which includes the dynamic linker. The explanation should cover the basics of dynamic linking, shared objects (.so files), the linker's role in resolving symbols, and a simple example of how an application would link against `libc.so`.

**7. Logical Reasoning and Assumptions:**

The core assumption is that the first `double` in each entry is the *expected* result of applying `trunc()` to the second `double`. We can test this by manually applying the definition of `trunc()` to some of the input values.

* **Example:** Input: `0x1.fffffffffffffp-2` (approximately 0.999...). `trunc()` should round towards zero, so the output is `0.0`. The data confirms this in Entry 3.

**8. Common Usage Errors:**

The most common errors would be related to misunderstanding how `trunc()` behaves, especially with negative numbers. Providing examples is crucial.

**9. Android Framework/NDK Path and Frida Hook:**

This requires tracing how a call to `trunc()` might originate. A simplified path would be:

* **Java (Android Framework):** A higher-level math operation might eventually call a native method via JNI.
* **NDK (C/C++):** An NDK application directly calls `trunc()` from `<math.h>`.
* **`libc.so`:** The call is resolved to the `trunc()` implementation in `libc.so`.

The Frida hook example needs to target the `trunc()` function within `libc.so`.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:**  Is this file a performance benchmark? While the data could be used for that, the naming and structure strongly point to functional testing.
* **Clarification:** The hexadecimal floating-point notation might be unfamiliar to some. A brief explanation is helpful.
* **Dynamic Linker Emphasis:** Initially, I might have overlooked the "dynamic linker" part of the prompt. It's important to include it, even if the file itself doesn't directly demonstrate dynamic linking in action. Focus on how `libc.so` and the `trunc()` function within it are involved.
* **Frida Hook Specificity:** The Frida hook example needs to be concrete, targeting the correct library and function name. Providing input and output examples in the hook makes it more understandable.

By following these steps and continuously refining the understanding based on the provided information and general knowledge of Android and C/C++, we can construct a comprehensive and accurate answer to the user's request.
这个文件 `bionic/tests/math_data/trunc_intel_data.handroid` 是 Android Bionic 库中用于测试 `trunc()` 函数的数据文件。Bionic 是 Android 系统的核心 C 库，提供了例如标准 C 库函数、数学库函数和动态链接器等功能。

**功能:**

这个文件的主要功能是为 `trunc()` 函数提供测试用例。它包含一个名为 `g_trunc_intel_data` 的静态数组，该数组的每个元素都是一个结构体，包含两个 `double` 类型的值。

* **测试数据:** 文件中的每一对 `double` 值都代表一个测试用例。第一个 `double` 值是期望的 `trunc()` 函数的返回值，第二个 `double` 值是 `trunc()` 函数的输入值。
* **覆盖率:** 这些测试用例旨在覆盖 `trunc()` 函数的各种输入情况，包括正数、负数、零、非常大和非常小的数、以及接近整数边界的数。文件名中的 "intel" 可能暗示这些测试用例特别关注 Intel 架构上的浮点数行为，或者可能源自 Intel 提供的测试数据。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 系统中 `trunc()` 函数的正确性。`trunc()` 函数是标准 C 库的数学函数，用于将一个浮点数截断为最接近于零的整数。

* **libc 函数的实现:** Android 的 libc (Bionic) 实现了 `trunc()` 函数。这个数据文件用于验证 Bionic 中 `trunc()` 函数的实现是否符合标准，并且在各种边界条件下都能返回正确的结果。
* **Android Framework/NDK 的使用:** Android Framework 或 NDK 中的代码可能会调用 `trunc()` 函数进行数学运算。例如，在图形渲染、音频处理或科学计算相关的代码中，可能需要使用 `trunc()` 来处理浮点数。

**详细解释 `libc` 函数 `trunc()` 的功能是如何实现的:**

`trunc(double x)` 函数的功能是返回不大于 `x` 且最接近于 `x` 的整数（向零舍入）。

**实现逻辑：**

1. **提取符号位:**  首先判断输入浮点数 `x` 的符号。
2. **提取整数部分:** 将浮点数 `x` 的整数部分提取出来。这可以通过多种方式实现，例如：
   * **类型转换:**  将 `double` 类型强制转换为 `int` 类型（或更大的整数类型，如 `long long`），这会自动丢弃小数部分。但是需要注意溢出问题。
   * **使用 `floor()` 或 `ceil()`:**
     * 如果 `x` 是正数或零，`trunc(x)` 等价于 `floor(x)`。`floor(x)` 返回小于或等于 `x` 的最大整数。
     * 如果 `x` 是负数，`trunc(x)` 等价于 `ceil(x)`。`ceil(x)` 返回大于或等于 `x` 的最小整数。
3. **根据符号调整:**
   * 如果 `x` 是正数或零，直接返回提取的整数部分。
   * 如果 `x` 是负数，也直接返回提取的整数部分（因为类型转换或者 `ceil()` 已经处理了向零舍入）。

**示例实现 (简化版):**

```c
double trunc(double x) {
  if (x >= 0.0) {
    return floor(x); // 或者 (double)(long long)x; 需要注意溢出
  } else {
    return ceil(x);  // 或者 (double)(long long)x; 需要注意溢出
  }
}
```

**涉及 dynamic linker 的功能:**

这个数据文件本身并不直接涉及动态链接器的功能。然而，`trunc()` 函数的实现位于 `libc.so` 这个共享库中，应用程序在运行时需要通过动态链接器加载和链接 `libc.so` 才能使用 `trunc()` 函数。

**so 布局样本:**

假设一个简单的 Android 应用 `my_app` 使用了 `trunc()` 函数。其依赖的共享库布局可能如下：

```
/system/bin/linker64 (或 linker)  // 动态链接器
/system/lib64/libc.so             // Bionic C 库，包含 trunc() 的实现
/data/app/com.example.my_app/lib/arm64-v8a/libnative.so // 应用自己的 native 库
/apex/com.android.runtime/lib64/bionic/libdl.so // 动态链接器库
```

**链接的处理过程:**

1. **加载:** 当 `my_app` 启动时，Android 系统首先加载动态链接器 (`linker64` 或 `linker`)。
2. **解析:** 动态链接器解析 `my_app` 的可执行文件头，找到其依赖的共享库，例如 `libc.so` 和 `libnative.so`。
3. **加载共享库:** 动态链接器加载这些共享库到内存中。
4. **符号解析 (Symbol Resolution):** 当 `libnative.so` 中调用了 `trunc()` 函数时，动态链接器会在其依赖的共享库中查找 `trunc()` 函数的地址。由于 `trunc()` 函数在 `libc.so` 中定义，动态链接器会将 `libnative.so` 中对 `trunc()` 的调用链接到 `libc.so` 中 `trunc()` 函数的实际地址。这通常通过 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table) 来实现。
5. **重定位 (Relocation):** 动态链接器会修改加载的共享库中的某些地址，以便它们在当前的内存布局中正确指向目标位置。

**假设输入与输出 (逻辑推理):**

根据 `trunc()` 函数的定义，我们可以推断一些测试用例的输入和预期输出：

* **假设输入:** `3.14`  **预期输出:** `3.0`
* **假设输入:** `-3.14` **预期输出:** `-3.0`
* **假设输入:** `0.0`   **预期输出:** `0.0`
* **假设输入:** `-0.0`  **预期输出:** `-0.0`
* **假设输入:** `5.0`   **预期输出:** `5.0`
* **假设输入:** `-5.0`  **预期输出:** `-5.0`

查看 `trunc_intel_data.handroid` 中的部分数据可以验证这一点：

* ` { -0.0, -0.0 }`  输入 `-0.0`，预期输出 `-0.0`。
* ` { 3.0, 3.14 }`  输入 `3.14` (近似)，预期输出 `3.0`。
* ` { -3.0, -3.14 }` 输入 `-3.14` (近似)，预期输出 `-3.0`。

**用户或编程常见的使用错误:**

1. **误解 `trunc()` 与 `round()` 的区别:** `trunc()` 是向零舍入，而 `round()` 是四舍五入到最接近的整数。
   * **错误示例:** 用户可能期望 `trunc(3.9)` 返回 `4.0`，但实际上 `trunc(3.9)` 返回 `3.0`。
   * **错误示例:** 用户可能期望 `trunc(-3.9)` 返回 `-4.0`，但实际上 `trunc(-3.9)` 返回 `-3.0`。

2. **在需要四舍五入时使用 `trunc()`:**  如果需要将浮点数四舍五入到最接近的整数，应该使用 `round()` 函数。

3. **忽略负数的截断行为:**  新手程序员可能会忘记 `trunc()` 对负数的处理是向零靠近的，导致逻辑错误。

**Android Framework 或 NDK 如何一步步到达这里:**

假设一个 Android 应用的 Native 代码中调用了 `trunc()` 函数：

1. **NDK 代码调用:**  开发者在 NDK (Native Development Kit) 编写的 C/C++ 代码中包含了 `<math.h>` 头文件，并调用了 `trunc(double value)` 函数。
   ```c++
   #include <math.h>

   double process_value(double input) {
       return trunc(input);
   }
   ```

2. **编译和链接:** 使用 NDK 编译工具链编译该 Native 代码，生成共享库 (`.so` 文件)，例如 `libnative.so`。在链接阶段，链接器会将对 `trunc()` 的调用标记为需要外部符号解析。

3. **应用加载:** 当 Android 应用启动并加载包含这段 Native 代码的共享库时，动态链接器开始工作。

4. **动态链接:** 动态链接器在加载 `libnative.so` 时，会发现它依赖于 `libc.so`，因为 `trunc()` 函数在 `libc.so` 中。

5. **符号查找:** 动态链接器在 `libc.so` 中查找 `trunc()` 函数的符号地址。

6. **调用 `trunc()`:** 当 Native 代码执行到 `trunc(input)` 时，实际上会跳转到 `libc.so` 中 `trunc()` 函数的实现代码执行。

7. **测试 `trunc()` (回到数据文件):**  在 Android 系统开发和测试阶段，为了确保 `libc.so` 中 `trunc()` 函数的实现正确无误，开发者会运行各种测试，包括使用 `bionic/tests/math_data/trunc_intel_data.handroid` 中定义的数据。这些测试会针对 `libc.so` 中的 `trunc()` 实现进行验证，确保对于给定的输入，返回的输出与预期值一致。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来观察 `trunc()` 函数的调用和行为。以下是一个简单的 Frida Hook 示例：

```python
import frida
import sys

package_name = "com.example.my_app"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "trunc"), {
    onEnter: function(args) {
        var input = args[0];
        send({
            type: "trunc_call",
            input: input.readDouble()
        });
        console.log("Called trunc with input: " + input.readDouble());
    },
    onLeave: function(retval) {
        send({
            type: "trunc_return",
            output: retval.readDouble()
        });
        console.log("trunc returned: " + retval.readDouble());
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida 和 Python 绑定:** 确保你的系统上安装了 Frida 和它的 Python 绑定 (`pip install frida-tools`).
2. **找到目标进程:** 运行你想要调试的 Android 应用 (`com.example.my_app`).
3. **运行 Frida 脚本:**  将上面的 Python 代码保存为 `hook_trunc.py`，然后在终端中运行 `python hook_trunc.py`。
4. **观察输出:** 当应用中调用 `trunc()` 函数时，Frida 会拦截调用，并打印出输入参数和返回值。

**预期输出示例:**

```
[*] {"type": "trunc_call", "input": 3.141592653589793}
Called trunc with input: 3.141592653589793
[*] {"type": "trunc_return", "output": 3.0}
trunc returned: 3
```

这个 Frida Hook 示例可以帮助你动态地观察 `trunc()` 函数在 Android 应用中的实际行为，验证其输入和输出，从而辅助理解其功能和可能的错误。

### 提示词
```
这是目录为bionic/tests/math_data/trunc_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

static data_1_1_t<double, double> g_trunc_intel_data[] = {
  { // Entry 0
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 1
    -0.0,
    -0.0
  },
  { // Entry 2
    0.0,
    0x1.0p-1074
  },
  { // Entry 3
    0.0,
    0x1.fffffffffffffp-2
  },
  { // Entry 4
    0.0,
    0x1.0p-1
  },
  { // Entry 5
    0.0,
    0x1.0000000000001p-1
  },
  { // Entry 6
    0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 7
    0x1.p0,
    0x1.0p0
  },
  { // Entry 8
    0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 9
    0x1.p0,
    0x1.7ffffffffffffp0
  },
  { // Entry 10
    0x1.p0,
    0x1.8p0
  },
  { // Entry 11
    0x1.p0,
    0x1.8000000000001p0
  },
  { // Entry 12
    0x1.p0,
    0x1.fffffffffffffp0
  },
  { // Entry 13
    0x1.p1,
    0x1.0p1
  },
  { // Entry 14
    0x1.p1,
    0x1.0000000000001p1
  },
  { // Entry 15
    0x1.p1,
    0x1.3ffffffffffffp1
  },
  { // Entry 16
    0x1.p1,
    0x1.4p1
  },
  { // Entry 17
    0x1.p1,
    0x1.4000000000001p1
  },
  { // Entry 18
    0x1.8cp6,
    0x1.8ffffffffffffp6
  },
  { // Entry 19
    0x1.90p6,
    0x1.9p6
  },
  { // Entry 20
    0x1.90p6,
    0x1.9000000000001p6
  },
  { // Entry 21
    0x1.90p6,
    0x1.91fffffffffffp6
  },
  { // Entry 22
    0x1.90p6,
    0x1.920p6
  },
  { // Entry 23
    0x1.90p6,
    0x1.9200000000001p6
  },
  { // Entry 24
    0x1.f380p9,
    0x1.f3fffffffffffp9
  },
  { // Entry 25
    0x1.f4p9,
    0x1.f40p9
  },
  { // Entry 26
    0x1.f4p9,
    0x1.f400000000001p9
  },
  { // Entry 27
    0x1.f4p9,
    0x1.f43ffffffffffp9
  },
  { // Entry 28
    0x1.f4p9,
    0x1.f44p9
  },
  { // Entry 29
    0x1.f4p9,
    0x1.f440000000001p9
  },
  { // Entry 30
    0x1.ffffffffffff80p49,
    0x1.fffffffffffffp49
  },
  { // Entry 31
    0x1.p50,
    0x1.0p50
  },
  { // Entry 32
    0x1.p50,
    0x1.0000000000001p50
  },
  { // Entry 33
    0x1.ffffffffffffc0p50,
    0x1.fffffffffffffp50
  },
  { // Entry 34
    0x1.p51,
    0x1.0p51
  },
  { // Entry 35
    0x1.p51,
    0x1.0000000000001p51
  },
  { // Entry 36
    0x1.ffffffffffffe0p51,
    0x1.fffffffffffffp51
  },
  { // Entry 37
    0x1.p52,
    0x1.0p52
  },
  { // Entry 38
    0x1.00000000000010p52,
    0x1.0000000000001p52
  },
  { // Entry 39
    0x1.fffffffffffff0p52,
    0x1.fffffffffffffp52
  },
  { // Entry 40
    0x1.p53,
    0x1.0p53
  },
  { // Entry 41
    0x1.00000000000010p53,
    0x1.0000000000001p53
  },
  { // Entry 42
    0x1.fffffffffffff0p53,
    0x1.fffffffffffffp53
  },
  { // Entry 43
    0x1.p54,
    0x1.0p54
  },
  { // Entry 44
    0x1.00000000000010p54,
    0x1.0000000000001p54
  },
  { // Entry 45
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 46
    -0.0,
    -0x1.0000000000001p-1
  },
  { // Entry 47
    -0.0,
    -0x1.0p-1
  },
  { // Entry 48
    -0.0,
    -0x1.fffffffffffffp-2
  },
  { // Entry 49
    -0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 50
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 51
    -0.0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 52
    -0x1.p0,
    -0x1.8000000000001p0
  },
  { // Entry 53
    -0x1.p0,
    -0x1.8p0
  },
  { // Entry 54
    -0x1.p0,
    -0x1.7ffffffffffffp0
  },
  { // Entry 55
    -0x1.p1,
    -0x1.0000000000001p1
  },
  { // Entry 56
    -0x1.p1,
    -0x1.0p1
  },
  { // Entry 57
    -0x1.p0,
    -0x1.fffffffffffffp0
  },
  { // Entry 58
    -0x1.p1,
    -0x1.4000000000001p1
  },
  { // Entry 59
    -0x1.p1,
    -0x1.4p1
  },
  { // Entry 60
    -0x1.p1,
    -0x1.3ffffffffffffp1
  },
  { // Entry 61
    -0x1.90p6,
    -0x1.9000000000001p6
  },
  { // Entry 62
    -0x1.90p6,
    -0x1.9p6
  },
  { // Entry 63
    -0x1.8cp6,
    -0x1.8ffffffffffffp6
  },
  { // Entry 64
    -0x1.90p6,
    -0x1.9200000000001p6
  },
  { // Entry 65
    -0x1.90p6,
    -0x1.920p6
  },
  { // Entry 66
    -0x1.90p6,
    -0x1.91fffffffffffp6
  },
  { // Entry 67
    -0x1.f4p9,
    -0x1.f400000000001p9
  },
  { // Entry 68
    -0x1.f4p9,
    -0x1.f40p9
  },
  { // Entry 69
    -0x1.f380p9,
    -0x1.f3fffffffffffp9
  },
  { // Entry 70
    -0x1.f4p9,
    -0x1.f440000000001p9
  },
  { // Entry 71
    -0x1.f4p9,
    -0x1.f44p9
  },
  { // Entry 72
    -0x1.f4p9,
    -0x1.f43ffffffffffp9
  },
  { // Entry 73
    -0x1.p50,
    -0x1.0000000000001p50
  },
  { // Entry 74
    -0x1.p50,
    -0x1.0p50
  },
  { // Entry 75
    -0x1.ffffffffffff80p49,
    -0x1.fffffffffffffp49
  },
  { // Entry 76
    -0x1.p51,
    -0x1.0000000000001p51
  },
  { // Entry 77
    -0x1.p51,
    -0x1.0p51
  },
  { // Entry 78
    -0x1.ffffffffffffc0p50,
    -0x1.fffffffffffffp50
  },
  { // Entry 79
    -0x1.00000000000010p52,
    -0x1.0000000000001p52
  },
  { // Entry 80
    -0x1.p52,
    -0x1.0p52
  },
  { // Entry 81
    -0x1.ffffffffffffe0p51,
    -0x1.fffffffffffffp51
  },
  { // Entry 82
    -0x1.00000000000010p53,
    -0x1.0000000000001p53
  },
  { // Entry 83
    -0x1.p53,
    -0x1.0p53
  },
  { // Entry 84
    -0x1.fffffffffffff0p52,
    -0x1.fffffffffffffp52
  },
  { // Entry 85
    -0x1.00000000000010p54,
    -0x1.0000000000001p54
  },
  { // Entry 86
    -0x1.p54,
    -0x1.0p54
  },
  { // Entry 87
    -0x1.fffffffffffff0p53,
    -0x1.fffffffffffffp53
  },
  { // Entry 88
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 89
    0x1.fffffff8p29,
    0x1.fffffffffffffp29
  },
  { // Entry 90
    0x1.p30,
    0x1.0p30
  },
  { // Entry 91
    0x1.p30,
    0x1.0000000000001p30
  },
  { // Entry 92
    0x1.fffffff4p30,
    0x1.fffffff7ffffep30
  },
  { // Entry 93
    0x1.fffffff4p30,
    0x1.fffffff7fffffp30
  },
  { // Entry 94
    0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 95
    0x1.fffffff8p30,
    0x1.fffffff800001p30
  },
  { // Entry 96
    0x1.fffffff8p30,
    0x1.fffffff800002p30
  },
  { // Entry 97
    0x1.fffffff8p30,
    0x1.fffffff9ffffep30
  },
  { // Entry 98
    0x1.fffffff8p30,
    0x1.fffffff9fffffp30
  },
  { // Entry 99
    0x1.fffffff8p30,
    0x1.fffffffa0p30
  },
  { // Entry 100
    0x1.fffffff8p30,
    0x1.fffffffa00001p30
  },
  { // Entry 101
    0x1.fffffff8p30,
    0x1.fffffffa00002p30
  },
  { // Entry 102
    0x1.fffffff8p30,
    0x1.fffffffbffffep30
  },
  { // Entry 103
    0x1.fffffff8p30,
    0x1.fffffffbfffffp30
  },
  { // Entry 104
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 105
    0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 106
    0x1.fffffffcp30,
    0x1.fffffffc00002p30
  },
  { // Entry 107
    0x1.fffffffcp30,
    0x1.fffffffdffffep30
  },
  { // Entry 108
    0x1.fffffffcp30,
    0x1.fffffffdfffffp30
  },
  { // Entry 109
    0x1.fffffffcp30,
    0x1.fffffffe0p30
  },
  { // Entry 110
    0x1.fffffffcp30,
    0x1.fffffffe00001p30
  },
  { // Entry 111
    0x1.fffffffcp30,
    0x1.fffffffe00002p30
  },
  { // Entry 112
    0x1.fffffffcp30,
    0x1.ffffffffffffep30
  },
  { // Entry 113
    0x1.fffffffcp30,
    0x1.fffffffffffffp30
  },
  { // Entry 114
    0x1.p31,
    0x1.0p31
  },
  { // Entry 115
    0x1.p31,
    0x1.0000000000001p31
  },
  { // Entry 116
    0x1.p31,
    0x1.0000000000002p31
  },
  { // Entry 117
    0x1.p31,
    0x1.00000000ffffep31
  },
  { // Entry 118
    0x1.p31,
    0x1.00000000fffffp31
  },
  { // Entry 119
    0x1.p31,
    0x1.000000010p31
  },
  { // Entry 120
    0x1.p31,
    0x1.0000000100001p31
  },
  { // Entry 121
    0x1.p31,
    0x1.0000000100002p31
  },
  { // Entry 122
    0x1.ffffffe0p30,
    0x1.ffffffep30
  },
  { // Entry 123
    0x1.ffffffe4p30,
    0x1.ffffffe40p30
  },
  { // Entry 124
    0x1.ffffffe8p30,
    0x1.ffffffe80p30
  },
  { // Entry 125
    0x1.ffffffecp30,
    0x1.ffffffec0p30
  },
  { // Entry 126
    0x1.fffffff0p30,
    0x1.fffffffp30
  },
  { // Entry 127
    0x1.fffffff4p30,
    0x1.fffffff40p30
  },
  { // Entry 128
    0x1.fffffff8p30,
    0x1.fffffff80p30
  },
  { // Entry 129
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 130
    0x1.p31,
    0x1.0p31
  },
  { // Entry 131
    0x1.00000002p31,
    0x1.000000020p31
  },
  { // Entry 132
    -0x1.p30,
    -0x1.0000000000001p30
  },
  { // Entry 133
    -0x1.p30,
    -0x1.0p30
  },
  { // Entry 134
    -0x1.fffffff8p29,
    -0x1.fffffffffffffp29
  },
  { // Entry 135
    -0x1.fffffff8p30,
    -0x1.fffffff800002p30
  },
  { // Entry 136
    -0x1.fffffff8p30,
    -0x1.fffffff800001p30
  },
  { // Entry 137
    -0x1.fffffff8p30,
    -0x1.fffffff80p30
  },
  { // Entry 138
    -0x1.fffffff4p30,
    -0x1.fffffff7fffffp30
  },
  { // Entry 139
    -0x1.fffffff4p30,
    -0x1.fffffff7ffffep30
  },
  { // Entry 140
    -0x1.fffffff8p30,
    -0x1.fffffffa00002p30
  },
  { // Entry 141
    -0x1.fffffff8p30,
    -0x1.fffffffa00001p30
  },
  { // Entry 142
    -0x1.fffffff8p30,
    -0x1.fffffffa0p30
  },
  { // Entry 143
    -0x1.fffffff8p30,
    -0x1.fffffff9fffffp30
  },
  { // Entry 144
    -0x1.fffffff8p30,
    -0x1.fffffff9ffffep30
  },
  { // Entry 145
    -0x1.fffffffcp30,
    -0x1.fffffffc00002p30
  },
  { // Entry 146
    -0x1.fffffffcp30,
    -0x1.fffffffc00001p30
  },
  { // Entry 147
    -0x1.fffffffcp30,
    -0x1.fffffffc0p30
  },
  { // Entry 148
    -0x1.fffffff8p30,
    -0x1.fffffffbfffffp30
  },
  { // Entry 149
    -0x1.fffffff8p30,
    -0x1.fffffffbffffep30
  },
  { // Entry 150
    -0x1.fffffffcp30,
    -0x1.fffffffe00002p30
  },
  { // Entry 151
    -0x1.fffffffcp30,
    -0x1.fffffffe00001p30
  },
  { // Entry 152
    -0x1.fffffffcp30,
    -0x1.fffffffe0p30
  },
  { // Entry 153
    -0x1.fffffffcp30,
    -0x1.fffffffdfffffp30
  },
  { // Entry 154
    -0x1.fffffffcp30,
    -0x1.fffffffdffffep30
  },
  { // Entry 155
    -0x1.p31,
    -0x1.0000000000002p31
  },
  { // Entry 156
    -0x1.p31,
    -0x1.0000000000001p31
  },
  { // Entry 157
    -0x1.p31,
    -0x1.0p31
  },
  { // Entry 158
    -0x1.fffffffcp30,
    -0x1.fffffffffffffp30
  },
  { // Entry 159
    -0x1.fffffffcp30,
    -0x1.ffffffffffffep30
  },
  { // Entry 160
    -0x1.p31,
    -0x1.0000000100002p31
  },
  { // Entry 161
    -0x1.p31,
    -0x1.0000000100001p31
  },
  { // Entry 162
    -0x1.p31,
    -0x1.000000010p31
  },
  { // Entry 163
    -0x1.p31,
    -0x1.00000000fffffp31
  },
  { // Entry 164
    -0x1.p31,
    -0x1.00000000ffffep31
  },
  { // Entry 165
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 166
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 167
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 168
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 169
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 170
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 171
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 172
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 173
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 174
    -0x1.ffffffe0p30,
    -0x1.ffffffep30
  },
  { // Entry 175
    0x1.ffffffffffffe0p61,
    0x1.ffffffffffffep61
  },
  { // Entry 176
    0x1.fffffffffffff0p61,
    0x1.fffffffffffffp61
  },
  { // Entry 177
    0x1.p62,
    0x1.0p62
  },
  { // Entry 178
    0x1.00000000000010p62,
    0x1.0000000000001p62
  },
  { // Entry 179
    0x1.00000000000020p62,
    0x1.0000000000002p62
  },
  { // Entry 180
    0x1.ffffffffffffe0p62,
    0x1.ffffffffffffep62
  },
  { // Entry 181
    0x1.fffffffffffff0p62,
    0x1.fffffffffffffp62
  },
  { // Entry 182
    0x1.p63,
    0x1.0p63
  },
  { // Entry 183
    0x1.00000000000010p63,
    0x1.0000000000001p63
  },
  { // Entry 184
    0x1.00000000000020p63,
    0x1.0000000000002p63
  },
  { // Entry 185
    0x1.ffffffffffffe0p63,
    0x1.ffffffffffffep63
  },
  { // Entry 186
    0x1.fffffffffffff0p63,
    0x1.fffffffffffffp63
  },
  { // Entry 187
    0x1.p64,
    0x1.0p64
  },
  { // Entry 188
    0x1.00000000000010p64,
    0x1.0000000000001p64
  },
  { // Entry 189
    0x1.00000000000020p64,
    0x1.0000000000002p64
  },
  { // Entry 190
    -0x1.00000000000020p62,
    -0x1.0000000000002p62
  },
  { // Entry 191
    -0x1.00000000000010p62,
    -0x1.0000000000001p62
  },
  { // Entry 192
    -0x1.p62,
    -0x1.0p62
  },
  { // Entry 193
    -0x1.fffffffffffff0p61,
    -0x1.fffffffffffffp61
  },
  { // Entry 194
    -0x1.ffffffffffffe0p61,
    -0x1.ffffffffffffep61
  },
  { // Entry 195
    -0x1.00000000000020p63,
    -0x1.0000000000002p63
  },
  { // Entry 196
    -0x1.00000000000010p63,
    -0x1.0000000000001p63
  },
  { // Entry 197
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 198
    -0x1.fffffffffffff0p62,
    -0x1.fffffffffffffp62
  },
  { // Entry 199
    -0x1.ffffffffffffe0p62,
    -0x1.ffffffffffffep62
  },
  { // Entry 200
    -0x1.00000000000020p64,
    -0x1.0000000000002p64
  },
  { // Entry 201
    -0x1.00000000000010p64,
    -0x1.0000000000001p64
  },
  { // Entry 202
    -0x1.p64,
    -0x1.0p64
  },
  { // Entry 203
    -0x1.fffffffffffff0p63,
    -0x1.fffffffffffffp63
  },
  { // Entry 204
    -0x1.ffffffffffffe0p63,
    -0x1.ffffffffffffep63
  },
  { // Entry 205
    0x1.p62,
    0x1.0p62
  },
  { // Entry 206
    0x1.p63,
    0x1.0p63
  },
  { // Entry 207
    -0x1.p62,
    -0x1.0p62
  },
  { // Entry 208
    -0x1.p63,
    -0x1.0p63
  },
  { // Entry 209
    0x1.fffffff8p30,
    0x1.fffffffbfffffp30
  },
  { // Entry 210
    0x1.fffffffcp30,
    0x1.fffffffc0p30
  },
  { // Entry 211
    0x1.fffffffcp30,
    0x1.fffffffc00001p30
  },
  { // Entry 212
    -0x1.p31,
    -0x1.0000000000001p31
  },
  { // Entry 213
    -0x1.p31,
    -0x1.0p31
  },
  { // Entry 214
    -0x1.fffffffcp30,
    -0x1.fffffffffffffp30
  },
  { // Entry 215
    0x1.80p1,
    0x1.fffffffffffffp1
  },
  { // Entry 216
    0x1.p2,
    0x1.0p2
  },
  { // Entry 217
    0x1.p2,
    0x1.0000000000001p2
  },
  { // Entry 218
    0x1.c0p2,
    0x1.fffffffffffffp2
  },
  { // Entry 219
    0x1.p3,
    0x1.0p3
  },
  { // Entry 220
    0x1.p3,
    0x1.0000000000001p3
  },
  { // Entry 221
    0x1.e0p3,
    0x1.fffffffffffffp3
  },
  { // Entry 222
    0x1.p4,
    0x1.0p4
  },
  { // Entry 223
    0x1.p4,
    0x1.0000000000001p4
  },
  { // Entry 224
    0x1.f0p4,
    0x1.fffffffffffffp4
  },
  { // Entry 225
    0x1.p5,
    0x1.0p5
  },
  { // Entry 226
    0x1.p5,
    0x1.0000000000001p5
  },
  { // Entry 227
    0x1.f8p5,
    0x1.fffffffffffffp5
  },
  { // Entry 228
    0x1.p6,
    0x1.0p6
  },
  { // Entry 229
    0x1.p6,
    0x1.0000000000001p6
  },
  { // Entry 230
    0x1.fcp6,
    0x1.fffffffffffffp6
  },
  { // Entry 231
    0x1.p7,
    0x1.0p7
  },
  { // Entry 232
    0x1.p7,
    0x1.0000000000001p7
  },
  { // Entry 233
    0x1.fep7,
    0x1.fffffffffffffp7
  },
  { // Entry 234
    0x1.p8,
    0x1.0p8
  },
  { // Entry 235
    0x1.p8,
    0x1.0000000000001p8
  },
  { // Entry 236
    0x1.ffp8,
    0x1.fffffffffffffp8
  },
  { // Entry 237
    0x1.p9,
    0x1.0p9
  },
  { // Entry 238
    0x1.p9,
    0x1.0000000000001p9
  },
  { // Entry 239
    0x1.ff80p9,
    0x1.fffffffffffffp9
  },
  { // Entry 240
    0x1.p10,
    0x1.0p10
  },
  { // Entry 241
    0x1.p10,
    0x1.0000000000001p10
  },
  { // Entry 242
    0x1.ffc0p10,
    0x1.fffffffffffffp10
  },
  { // Entry 243
    0x1.p11,
    0x1.0p11
  },
  { // Entry 244
    0x1.p11,
    0x1.0000000000001p11
  },
  { // Entry 245
    0x1.ffe0p11,
    0x1.fffffffffffffp11
  },
  { // Entry 246
    0x1.p12,
    0x1.0p12
  },
  { // Entry 247
    0x1.p12,
    0x1.0000000000001p12
  },
  { // Entry 248
    0x1.p2,
    0x1.1ffffffffffffp2
  },
  { // Entry 249
    0x1.p2,
    0x1.2p2
  },
  { // Entry 250
    0x1.p2,
    0x1.2000000000001p2
  },
  { // Entry 251
    0x1.p3,
    0x1.0ffffffffffffp3
  },
  { // Entry 252
    0x1.p3,
    0x1.1p3
  },
  { // Entry 253
    0x1.p3,
    0x1.1000000000001p3
  },
  { // Entry 254
    0x1.p4,
    0x1.07fffffffffffp4
  },
  { // Entry 255
    0x1.p4,
    0x1.080p4
  },
  { // Entry 256
    0x1.p4,
    0x1.0800000000001p4
  },
  { // Entry 257
    0x1.p5,
    0x1.03fffffffffffp5
  },
  { // Entry 258
    0x1.p5,
    0x1.040p5
  },
  { // Entry 259
    0x1.p5,
    0x1.0400000000001p5
  },
  { // Entry 260
    0x1.p6,
    0x1.01fffffffffffp6
  },
  { // Entry 261
    0x1.p6,
    0x1.020p6
  },
  { // Entry 262
    0x1.p6,
    0x1.0200000000001p6
  },
  { // Entry 263
    0x1.p7,
    0x1.00fffffffffffp7
  },
  { // Entry 264
    0x1.p7,
    0x1.010p7
  },
  { // Entry 265
    0x1.p7,
    0x1.0100000000001p7
  },
  { // Entry 266
    0x1.p8,
    0x1.007ffffffffffp8
  },
  { // Entry 267
    0x1.p8,
    0x1.008p8
  },
  { // Entry 268
    0x1.p8,
    0x1.0080000000001p8
  },
  { // Entry 269
    0x1.p9,
    0x1.003ffffffffffp9
  },
  { // Entry 270
    0x1.p9,
    0x1.004p9
  },
  { // Entry 271
    0x1.p9,
    0x1.0040000000001p9
  },
  { // Entry 272
    0x1.p10,
    0x1.001ffffffffffp10
  },
  { // Entry 273
    0x1.p10,
    0x1.002p10
  },
  { // Entry 274
    0x1.p10,
    0x1.0020000000001p10
  },
  { // Entry 275
    0x1.0040p10,
    0x1.005ffffffffffp10
  },
  { // Entry 276
    0x1.0040p10,
    0x1.006p10
  },
  { // Entry 277
    0x1.0040p10,
    0x1.0060000000001p10
  },
  { // Entry 278
    0x1.p11,
    0x1.000ffffffffffp11
  },
  { // Entry 279
    0x1.p11,
    0x1.001p11
  },
  { // Entry 280
    0x1.p11,
    0x1.0010000000001p11
  },
  { // Entry 281
    0x1.p12,
    0x1.0007fffffffffp12
  },
  { // Entry 282
    0x1.p12,
    0x1.00080p12
  },
  { // Entry 283
    0x1.p12,
    0x1.0008000000001p12
  },
  { // Entry 284
    HUGE_VAL,
    HUGE_VAL
  },
  { // Entry 285
    -HUGE_VAL,
    -HUGE_VAL
  },
  { // Entry 286
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 287
    -0x1.fffffffffffff0p1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 288
    0x1.ffffffffffffe0p1023,
    0x1.ffffffffffffep1023
  },
  { // Entry 289
    -0x1.ffffffffffffe0p1023,
    -0x1.ffffffffffffep1023
  },
  { // Entry 290
    0x1.80p1,
    0x1.921fb54442d18p1
  },
  { // Entry 291
    -0x1.80p1,
    -0x1.921fb54442d18p1
  },
  { // Entry 292
    0x1.p0,
    0x1.921fb54442d18p0
  },
  { // Entry 293
    -0x1.p0,
    -0x1.921fb54442d18p0
  },
  { // Entry 294
    0x1.p0,
    0x1.0000000000001p0
  },
  { // Entry 295
    -0x1.p0,
    -0x1.0000000000001p0
  },
  { // Entry 296
    0x1.p0,
    0x1.0p0
  },
  { // Entry 297
    -0x1.p0,
    -0x1.0p0
  },
  { // Entry 298
    0.0,
    0x1.fffffffffffffp-1
  },
  { // Entry 299
    -0.0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 300
    0.0,
    0x1.921fb54442d18p-1
  },
  { // Entry 301
    -0.0,
    -0x1.921fb54442d18p-1
  },
  { // Entry 302
    0.0,
    0x1.0000000000001p-1022
  },
  { // Entry 303
    -0.0,
    -0x1.0000000000001p-1022
  },
  { // Entry 304
    0.0,
    0x1.0p-1022
  },
  { // Entry 305
    -0.0,
    -0x1.0p-1022
  },
  { // Entry 306
    0.0,
    0x1.ffffffffffffep-1023
  },
  { // Entry 307
    -0.0,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 308
    0.0,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 309
    -0.0,
    -0x1.ffffffffffffcp-1023
  },
  { // Entry 310
    0.0,
    0x1.0p-1073
  },
  { // Entry 311
    -0.0,
    -0x1.0p-1073
  },
  { // Entry 312
    0.0,
    0x1.0p-1074
  },
  { // Entry 313
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 314
    0.0,
    0.0
  },
  { // Entry 315
    -0.0,
    -0.0
  },
  { // Entry 316
    0x1.p0,
    0x1.8p0
  },
  { // Entry 317
    -0x1.p0,
    -0x1.8p0
  },
  { // Entry 318
    0x1.p1,
    0x1.4p1
  },
  { // Entry 319
    -0x1.p1,
    -0x1.4p1
  },
  { // Entry 320
    0.0,
    0x1.fffffp-2
  },
  { // Entry 321
    0.0,
    0x1.0p-1
  },
  { // Entry 322
    0.0,
    0x1.00001p-1
  },
  { // Entry 323
    -0.0,
    -0x1.fffffp-2
  },
  { // Entry 324
    -0.0,
    -0x1.0p-1
  },
  { // Entry 325
    -0.0,
    -0x1.00001p-1
  },
  { // Entry 326
    0x1.p0,
    0x1.80001p0
  },
  { // Entry 327
    0x1.p0,
    0x1.7ffffp0
  },
  { // Entry 328
    -0x1.p0,
    -0x1.80001p0
  },
  { // Entry 329
    -0x1.p0,
    -0x1.7ffffp0
  }
};
```
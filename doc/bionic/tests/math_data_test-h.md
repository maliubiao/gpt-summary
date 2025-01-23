Response:
Let's break down the thought process for answering the request about `math_data_test.handroid`.

1. **Understanding the Core Request:** The primary goal is to analyze the provided C++ code snippet and explain its purpose and function within the Android bionic library. The request also specifically asks about its relationship to Android, libc function implementations, dynamic linker aspects, potential errors, and how it's invoked within the Android ecosystem.

2. **Initial Code Scan and Identification of Key Elements:**  The first step is to skim the code and identify the most important parts. This includes:
    * **Includes:** `<gtest/gtest.h>`, `<math.h>`, `<fenv.h>`. This immediately suggests it's a unit test file for mathematical functions, using Google Test as the testing framework. `<fenv.h>` indicates involvement with floating-point environment control.
    * **Templates for Data Structures:**  `data_1_1_t`, `data_int_1_t`, `data_1_2_t`, etc. These clearly define structures for holding test data: expected results and input values. The naming convention (e.g., `data_1_2_t` for one expected result and two inputs) is a strong clue to their purpose.
    * **`fp_u` Union:** This union is crucial. It's a way to access the raw bit representation of floating-point numbers (float, double, long double). The bitfield members (`frac`, `exp`, `sign`) directly expose the IEEE 754 floating-point structure.
    * **`SignAndMagnitudeToBiased` Function:** This function manipulates the bit representation of floating-point numbers. The name suggests it's converting a sign-magnitude representation to a biased representation, likely for comparing floating-point numbers.
    * **`UlpDistance` Function:**  This function calculates the Units in the Last Place (ULP) distance between two floating-point numbers. This is a standard way to measure the precision of floating-point calculations.
    * **`FpUlpEq` Structure:** This is a custom Google Test predicate for comparing floating-point numbers within a specified ULP tolerance.
    * **`DoMathDataTest` Functions:** These are templated functions that iterate through arrays of test data and call the corresponding math function, comparing the results against the expected values using the `FpUlpEq` predicate. The various overloads handle functions with different numbers of inputs and outputs.

3. **Inferring the Overall Functionality:** Based on the identified elements, the core functionality becomes clear: This file defines a framework for testing the accuracy of mathematical functions in the Android bionic library. It uses pre-defined test data and a ULP-based comparison to verify the results.

4. **Connecting to Android:** Since the file path is `bionic/tests/math_data_test.handroid`, and bionic is Android's C library, the connection is direct. This test file is part of the testing infrastructure for the math functions provided by Android's libc.

5. **Explaining libc Function Implementation (and Recognizing Limitations):** The code *doesn't* show the implementation of the libc functions themselves. It *tests* them. It's crucial to make this distinction. The explanation should focus on *how* the tests are structured to verify the *accuracy* of these functions. A general explanation of how libc functions *might* be implemented (e.g., using algorithms, looking up tables, hardware instructions) is appropriate, but avoid claiming this file *contains* those implementations.

6. **Addressing Dynamic Linker Aspects (and Recognizing Absence):**  A careful examination reveals no direct interaction with the dynamic linker in *this specific file*. The testing framework calls the math functions directly. Therefore, the explanation needs to state this clearly. However, since the request specifically mentions the dynamic linker, it's important to explain *how* the dynamic linker is generally involved in loading and linking shared libraries (like libc.so) where these math functions reside. Providing a basic example of a shared library layout and the linking process is helpful.

7. **Logic and Assumptions:** The logic is straightforward: compare the output of a math function with a known correct value within a tolerance. The main assumption is that the `data` arrays contain accurate "golden" values for various inputs. A simple input-output example for one of the `DoMathDataTest` functions would illustrate this.

8. **Common Usage Errors:** The most common errors would be related to setting up the test data incorrectly (wrong expected values, wrong input types) or misconfiguring the testing environment. An example of an incorrect data entry would be helpful.

9. **Android Framework/NDK Invocation and Frida Hooking:** This requires understanding the Android build process and how tests are typically run. The explanation should outline the path from framework/NDK usage of math functions down to the bionic library and how these tests are likely executed (e.g., as part of the Android Compatibility Test Suite - CTS). A Frida hook example should target a specific math function called within a regular Android app to demonstrate interception at the libc level.

10. **Structure and Language:**  The final step is to organize the information logically and present it clearly in Chinese, as requested. Use clear headings and bullet points to break down the information. Ensure accurate terminology and avoid jargon where possible.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this file contains optimized implementations of math functions for specific architectures. **Correction:** The includes and the structure clearly point towards a *testing* framework, not an implementation file.
* **Initial thought:**  Focus heavily on the bit manipulation within `fp_u`. **Correction:** While important for understanding ULP calculations, the primary focus should be on the overall testing methodology.
* **Initial thought:** Explain the detailed mathematical algorithms behind each libc function. **Correction:** This file doesn't provide those details. Focus on the testing approach instead. A brief, general explanation of how these functions *might* be implemented is sufficient.
* **Double-check:** Ensure all parts of the request are addressed, including dynamic linking (even if the file doesn't directly use it), common errors, and the Android framework/NDK connection.

By following this structured thought process, including identifying key elements, inferring functionality, and addressing each aspect of the request systematically, a comprehensive and accurate answer can be generated. The self-correction aspect is important for avoiding misinterpretations and staying focused on the actual content and purpose of the provided code.
这个文件 `bionic/tests/math_data_test.handroid` 是 Android Bionic 库中数学库的测试数据定义文件。它的主要功能是为 Bionic 提供的各种数学函数提供测试用例数据。这些数据用于驱动测试程序，验证数学函数的正确性和精度。

**主要功能:**

1. **定义测试数据结构:**  文件中定义了多种模板结构体，用于组织测试数据。这些结构体包括：
    * `data_1_1_t`: 用于测试接受一个输入参数并返回一个结果的函数 (例如 `sin`, `cos`, `sqrt`)。
    * `data_int_1_t`: 用于测试接受一个输入参数并返回一个整型结果的函数 (例如 `ilogb`)。
    * `data_long_1_t`: 用于测试接受一个输入参数并返回一个长整型结果的函数 (例如 `lrint`)。
    * `data_llong_1_t`: 用于测试接受一个输入参数并返回一个长长整型结果的函数 (例如 `llrint`)。
    * `data_1_2_t`: 用于测试接受两个输入参数并返回一个结果的函数 (例如 `pow`, `atan2`)。
    * `data_2_1_t`: 用于测试接受一个输入参数并返回两个结果的函数 (例如 `sincos`, `modf`)。
    * `data_1_int_1_t`: 用于测试接受一个输入参数并返回一个结果和一个整型结果的函数 (例如 `frexp`)。
    * `data_1_int_2_t`: 用于测试接受两个输入参数并返回一个结果和一个整型结果的函数 (例如 `remquo`)。
    * `data_1_3_t`: 用于测试接受三个输入参数并返回一个结果的函数 (例如 `fma`)。

2. **定义浮点数联合体 (`fp_u`)**:  定义了一个名为 `fp_u` 的联合体，用于以不同的方式访问浮点数的内部表示 (float, double, long double)。这使得可以访问浮点数的符号位、指数和尾数，用于进行底层的位操作和比较，例如在 `SignAndMagnitudeToBiased` 和 `UlpDistance` 函数中使用。

3. **提供浮点数比较的辅助函数:**
    * `SignAndMagnitudeToBiased`:  将浮点数的符号和幅度表示转换为一种有偏的表示，用于简化浮点数的比较。
    * `UlpDistance`: 计算两个浮点数之间的 ULP（Units in the Last Place）距离。ULP 是衡量浮点数精度的一种标准方法，表示两个浮点数之间相隔多少个最小可区分的单位。
    * `FpUlpEq`:  一个 Google Test 的谓词，用于判断两个浮点数是否在指定的 ULP 范围内相等。这允许在测试中进行容错比较，因为浮点运算可能存在舍入误差。

4. **提供通用测试运行函数 (`DoMathDataTest`)**:  定义了一系列重载的 `DoMathDataTest` 函数模板，用于根据不同的测试数据结构和被测试函数的签名，遍历测试数据并执行测试。这些函数会调用被测试的数学函数，并使用 `FpUlpEq` 或 `EXPECT_EQ` 来断言结果是否符合预期。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 系统的基础数学功能。Android 的应用程序和系统服务在进行各种计算时，会依赖 Bionic 库提供的标准 C 数学函数（例如 `sin`, `cos`, `pow`, `sqrt` 等）。`math_data_test.handroid` 中定义的测试数据确保了这些数学函数在 Android 系统中的正确性和可靠性。

**举例说明:**

假设 Android 的一个图形渲染模块需要计算一个旋转角度的余弦值。它会调用 `cos()` 函数，这个函数的实现位于 Bionic 库中。为了确保 `cos()` 函数在各种输入角度下都能返回正确的余弦值，开发者会使用类似于 `math_data_test.handroid` 中定义的数据来进行测试。

例如，可能存在一个测试用例：

```c++
data_1_1_t<double, double> cos_test_data[] = {
  { 1.0, 0.0 },
  { 0.7071067811865475, M_PI / 4.0 },
  { 0.0, M_PI / 2.0 },
  { -1.0, M_PI },
  // ... 更多测试用例
};

TEST(MathTest, Cos) {
  DoMathDataTest<4, double, double, std::size(cos_test_data)>(cos_test_data, cos);
}
```

这个测试用例定义了一组输入角度和期望的余弦值。`DoMathDataTest` 函数会遍历这些数据，调用 `cos()` 函数，并将结果与期望值进行比较，允许一定的 ULP 误差。

**详细解释每一个 libc 函数的功能是如何实现的:**

`math_data_test.handroid` **本身并不包含 libc 函数的实现**。它仅仅是测试数据。libc 函数的实际实现位于 Bionic 库的其他源文件中，例如 `bionic/libc/arch-${ARCH}/src/math/` 目录下。

libc 数学函数的实现通常涉及：

* **算法实现:**  使用各种数学算法来计算函数的值，例如泰勒级数展开、CORDIC 算法等。
* **查表法:**  对于某些函数和特定的输入范围，可以使用预先计算好的表格来快速查找结果。
* **硬件指令优化:** 利用特定 CPU 架构提供的硬件浮点运算指令来提高性能。
* **特殊情况处理:**  处理 NaN (Not a Number)、无穷大、零等特殊输入值。
* **精度控制:**  确保计算结果在一定的精度范围内。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**`math_data_test.handroid` 文件本身不直接涉及 dynamic linker 的功能。** 它的作用是测试已经链接到进程中的数学函数。

然而，Bionic 库作为一个共享库 (`libc.so`)，它的数学函数是通过 dynamic linker 加载和链接到应用程序或系统服务的。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text:  // 代码段
    cos:         // cos 函数的代码
    sin:         // sin 函数的代码
    pow:         // pow 函数的代码
    // ... 其他数学函数代码

  .data:  // 初始化数据段
    // ... 全局变量

  .rodata: // 只读数据段
    // ... 常量数据 (例如数学常数)

  .dynsym: // 动态符号表 (包含导出的符号，例如 cos, sin, pow)
    cos
    sin
    pow
    // ...

  .dynstr: // 动态字符串表 (包含符号名称的字符串)
    "cos"
    "sin"
    "pow"
    // ...

  .plt:    // 程序链接表 (用于延迟绑定)
    // ...

  .got:    // 全局偏移表 (用于存储外部符号的地址)
    // ...
```

**链接的处理过程:**

1. **加载:** 当一个 Android 应用或服务启动时，zygote 进程（或 init 进程）会使用 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 加载需要的共享库，包括 `libc.so`。

2. **符号解析:**  Dynamic linker 会解析应用程序和共享库中的符号引用。当应用程序调用 `cos()` 函数时，dynamic linker 需要找到 `libc.so` 中 `cos` 函数的地址。

3. **重定位:**  由于共享库被加载到内存的哪个地址是不确定的（地址空间布局随机化 - ASLR），dynamic linker 需要修改代码和数据中的地址，使其指向正确的内存位置。这包括更新 GOT (Global Offset Table) 中的条目，使其指向 `libc.so` 中 `cos` 函数的实际地址。

4. **延迟绑定 (Lazy Binding):** 为了提高启动速度，Android 通常使用延迟绑定。这意味着在第一次调用某个动态链接的函数时，dynamic linker 才会真正解析和重定位该函数的地址。PLT (Procedure Linkage Table) 和 GOT 用于实现延迟绑定。第一次调用 `cos()` 时，会跳转到 PLT 中的一段代码，该代码会调用 dynamic linker 来解析 `cos` 的地址，并将结果存储在 GOT 中。后续对 `cos()` 的调用将直接通过 GOT 跳转到其真实地址。

**如果做了逻辑推理，请给出假设输入与输出:**

`math_data_test.handroid` 中的测试用例本质上就是逻辑推理的体现。它假设对于给定的输入，数学函数应该产生特定的输出（在一定的精度范围内）。

**假设输入与输出 (以 `cos` 函数为例):**

* **假设输入:** `0.0`
* **预期输出:** `1.0`

* **假设输入:** `M_PI / 2.0` (π/2)
* **预期输出:** `0.0`

* **假设输入:** `M_PI` (π)
* **预期输出:** `-1.0`

这些假设输入和输出被编码在 `data_1_1_t` 结构体中，然后 `DoMathDataTest` 函数会验证实际的 `cos()` 函数是否符合这些预期。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然 `math_data_test.handroid` 是测试代码，但它反映了用户或程序员在使用数学函数时可能犯的错误：

1. **精度问题:**  直接使用 `==` 比较浮点数的结果，而不是允许一定的误差范围。由于浮点运算的精度限制，直接比较可能会失败。`math_data_test.handroid` 使用 ULP 比较来避免这个问题。

   **错误示例:**
   ```c++
   double result = cos(M_PI / 2.0);
   if (result == 0.0) { // 这样比较可能失败
       // ...
   }
   ```

   **正确做法 (类似于 `math_data_test.handroid` 的做法):**
   ```c++
   double expected = 0.0;
   double result = cos(M_PI / 2.0);
   if (std::abs(result - expected) < 1e-9) { // 允许一个小的误差范围
       // ...
   }
   ```

2. **输入值超出定义域:**  某些数学函数对输入值有特定的要求。例如，`sqrt()` 函数不能接受负数作为输入（在实数范围内）。

   **错误示例:**
   ```c++
   double result = sqrt(-1.0); // 这会导致 NaN
   ```

3. **未处理特殊情况 (NaN, 无穷大):**  浮点运算可能会产生 NaN 或无穷大。程序员需要正确处理这些特殊情况。

4. **误用整型和浮点型函数:**  例如，使用 `floor()` 函数（返回不大于输入值的最大整数）来代替四舍五入。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework/NDK 调用数学函数:**
   * **Android Framework:**  Android Framework 的 Java 代码 (例如，在 `android.graphics` 或 `android.animation` 包中) 可能会通过 JNI (Java Native Interface) 调用到 Native 代码中，而 Native 代码中可能会使用 Bionic 提供的数学函数。
   * **NDK:**  使用 NDK 开发的 Android 应用，其 C/C++ 代码可以直接调用 Bionic 库中的数学函数，只需要包含 `<math.h>` 头文件。

2. **Bionic 库的链接:**  当应用程序或系统服务加载时，Android 的动态链接器会将 `libc.so` 链接到进程的地址空间。

3. **调用数学函数:**  应用程序或系统服务的 Native 代码执行时，当遇到对数学函数的调用时，会跳转到 `libc.so` 中对应函数的实现代码。

**Frida Hook 示例:**

假设我们想 hook `cos` 函数，查看其输入和输出。

```python
import frida
import sys

package_name = "your.target.package" # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "cos"), {
    onEnter: function(args) {
        console.log("[cos] Input: " + args[0]);
        this.input = args[0];
    },
    onLeave: function(retval) {
        console.log("[cos] Output: " + retval);
        console.log("[cos] Input was: " + this.input);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释:**

1. **导入 Frida 库:** 导入必要的 Frida 库。
2. **指定目标应用:**  设置要 hook 的目标 Android 应用的包名。
3. **连接到设备和进程:** 使用 Frida 连接到 USB 设备，并附加到目标应用的进程。
4. **编写 Frida Hook 代码:**
   * `Interceptor.attach`: 使用 Frida 的 `Interceptor` API 来拦截对 `cos` 函数的调用。
   * `Module.findExportByName("libc.so", "cos")`:  找到 `libc.so` 库中导出的 `cos` 函数的地址。
   * `onEnter`: 在 `cos` 函数被调用之前执行。打印输入参数 `args[0]` (double 类型)。将输入参数保存到 `this.input` 方便在 `onLeave` 中使用。
   * `onLeave`: 在 `cos` 函数返回之后执行。打印返回值 `retval` (double 类型)。打印之前保存的输入值。
5. **创建和加载 Frida 脚本:** 创建 Frida 脚本对象，并设置消息回调函数，用于接收来自脚本的日志。然后加载脚本到目标进程。
6. **保持脚本运行:**  `sys.stdin.read()` 阻止 Python 脚本退出，保持 Hook 持续有效。

**运行此 Frida 脚本后，当目标应用调用 `cos` 函数时，你将在终端看到类似以下的输出:**

```
[*] [cos] Input: 1.5707963267948966
[*] [cos] Output: 6.123233995736766e-17
[*] [cos] Input was: 1.5707963267948966
```

这表明 `cos` 函数被调用，输入值为近似 π/2，输出值接近于 0 (由于浮点精度)。

这个 Frida 示例展示了如何拦截 Bionic 库中的数学函数调用，从而调试 Android Framework 或 NDK 如何一步步地使用这些底层库。通过 Hook 其他相关的函数，可以更详细地追踪调用链和数据流动。

### 提示词
```
这是目录为bionic/tests/math_data_test.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <gtest/gtest.h>

#include <math.h>
#include <fenv.h>

template <typename RT, typename T1>
struct data_1_1_t {
  RT expected;
  T1 input;
};

template <typename T1>
struct data_int_1_t {
  int expected;
  T1 input;
};

template <typename T1>
struct data_long_1_t {
  long expected;
  T1 input;
};

template <typename T1>
struct data_llong_1_t {
  long long expected;
  T1 input;
};

template <typename RT, typename T1, typename T2>
struct data_1_2_t {
  RT expected;
  T1 input1;
  T2 input2;
};

template <typename RT1, typename RT2, typename T>
struct data_2_1_t {
  RT1 expected1;
  RT2 expected2;
  T input;
};

template <typename RT1, typename T>
struct data_1_int_1_t {
  RT1 expected1;
  int expected2;
  T input;
};

template <typename RT1, typename T1, typename T2>
struct data_1_int_2_t {
  RT1 expected1;
  int expected2;
  T1 input1;
  T2 input2;
};

template <typename RT, typename T1, typename T2, typename T3>
struct data_1_3_t {
  RT expected;
  T1 input1;
  T2 input2;
  T3 input3;
};

template <typename T> union fp_u;

template <> union fp_u<float> {
  float value;
  struct {
    unsigned frac:23;
    unsigned exp:8;
    unsigned sign:1;
  } bits;
  uint32_t sign_magnitude;
};

template <> union fp_u<double> {
  double value;
  struct {
    unsigned fracl;
    unsigned frach:20;
    unsigned exp:11;
    unsigned sign:1;
  } bits;
  uint64_t sign_magnitude;
};

template <> union fp_u<long double> {
  long double value;
#if defined(__LP64__)
  struct {
    unsigned fracl;
    unsigned fraclm;
    unsigned frachm;
    unsigned frach:16;
    unsigned exp:15;
    unsigned sign:1;
  } bits;
  __int128_t sign_magnitude;
#else
  struct {
      unsigned fracl;
      unsigned frach:20;
      unsigned exp:11;
      unsigned sign:1;
  } bits;
  uint64_t sign_magnitude;
#endif
};

template <typename T>
static inline auto SignAndMagnitudeToBiased(const T& value) -> decltype(fp_u<T>::sign_magnitude) {
  fp_u<T> u;
  u.value = value;
  if (u.bits.sign) {
    return ~u.sign_magnitude + 1;
  } else {
    u.bits.sign = 1;
    return u.sign_magnitude;
  }
}

// Based on the existing googletest implementation, which uses a fixed 4 ulp bound.
template <typename T>
size_t UlpDistance(T lhs, T rhs) {
  const auto biased1 = SignAndMagnitudeToBiased(lhs);
  const auto biased2 = SignAndMagnitudeToBiased(rhs);
  return (biased1 >= biased2) ? (biased1 - biased2) : (biased2 - biased1);
}

template <size_t ULP, typename T>
struct FpUlpEq {
  ::testing::AssertionResult operator()(const char* /* expected_expression */,
                                        const char* /* actual_expression */,
                                        T expected,
                                        T actual) {
    if (!isnan(expected) && !isnan(actual) && UlpDistance(expected, actual) <= ULP) {
      return ::testing::AssertionSuccess();
    }

    return ::testing::AssertionFailure()
        << "expected (" << std::hexfloat << expected << ") != actual (" << actual << ")";
  }
};

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the result is within ULP ulps of the expected value.
// For testing a (double) -> double function like sin(3).
template <size_t ULP, typename RT, typename T, size_t N>
void DoMathDataTest(data_1_1_t<RT, T> (&data)[N], RT f(T)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT> predicate;
  for (size_t i = 0; i < N; ++i) {
    EXPECT_PRED_FORMAT2(predicate,
                        data[i].expected, f(data[i].input)) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the result is within ULP ulps of the expected value.
// For testing a (double) -> int function like ilogb(3).
template <size_t ULP, typename T, size_t N>
void DoMathDataTest(data_int_1_t<T> (&data)[N], int f(T)) {
  fesetenv(FE_DFL_ENV);
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(data[i].expected, f(data[i].input)) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the result is within ULP ulps of the expected value.
// For testing a (double) -> long int function like lrint(3).
template <size_t ULP, typename T, size_t N>
void DoMathDataTest(data_long_1_t<T> (&data)[N], long f(T)) {
  fesetenv(FE_DFL_ENV);
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(data[i].expected, f(data[i].input)) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the result is within ULP ulps of the expected value.
// For testing a (double) -> long long int function like llrint(3).
template <size_t ULP, typename T, size_t N>
void DoMathDataTest(data_llong_1_t<T> (&data)[N], long long f(T)) {
  fesetenv(FE_DFL_ENV);
  for (size_t i = 0; i < N; ++i) {
    EXPECT_EQ(data[i].expected, f(data[i].input)) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the pairs of input values
// and asserting that the result is within ULP ulps of the expected value.
// For testing a (double, double) -> double function like pow(3).
template <size_t ULP, typename RT, typename T1, typename T2, size_t N>
void DoMathDataTest(data_1_2_t<RT, T1, T2> (&data)[N], RT f(T1, T2)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT> predicate;
  for (size_t i = 0; i < N; ++i) {
    EXPECT_PRED_FORMAT2(predicate,
                        data[i].expected, f(data[i].input1, data[i].input2)) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the results are within ULP ulps of the expected values.
// For testing a (double, double*, double*) -> void function like sincos(3).
template <size_t ULP, typename RT1, typename RT2, typename T1, size_t N>
void DoMathDataTest(data_2_1_t<RT1, RT2, T1> (&data)[N], void f(T1, RT1*, RT2*)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT1> predicate1;
  FpUlpEq<ULP, RT2> predicate2;
  for (size_t i = 0; i < N; ++i) {
    RT1 out1;
    RT2 out2;
    f(data[i].input, &out1, &out2);
    EXPECT_PRED_FORMAT2(predicate1, data[i].expected1, out1) << "Failed on element " << i;
    EXPECT_PRED_FORMAT2(predicate2, data[i].expected2, out2) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the results are within ULP ulps of the expected values.
// For testing a (double, double*) -> double function like modf(3).
template <size_t ULP, typename RT1, typename RT2, typename T1, size_t N>
void DoMathDataTest(data_2_1_t<RT1, RT2, T1> (&data)[N], RT1 f(T1, RT2*)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT1> predicate1;
  FpUlpEq<ULP, RT2> predicate2;
  for (size_t i = 0; i < N; ++i) {
    RT1 out1;
    RT2 out2;
    out1 = f(data[i].input, &out2);
    EXPECT_PRED_FORMAT2(predicate1, data[i].expected1, out1) << "Failed on element " << i;
    EXPECT_PRED_FORMAT2(predicate2, data[i].expected2, out2) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the results are within ULP ulps of the expected values.
// For testing a (double, int*) -> double function like frexp(3).
template <size_t ULP, typename RT1, typename T1, size_t N>
void DoMathDataTest(data_1_int_1_t<RT1, T1> (&data)[N], RT1 f(T1, int*)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT1> predicate1;
  for (size_t i = 0; i < N; ++i) {
    RT1 out1;
    int out2;
    out1 = f(data[i].input, &out2);
    EXPECT_PRED_FORMAT2(predicate1, data[i].expected1, out1) << "Failed on element " << i;
    EXPECT_EQ(data[i].expected2, out2) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the input values
// and asserting that the results are within ULP ulps of the expected values.
// For testing a (double, double, int*) -> double function like remquo(3).
template <size_t ULP, typename RT1, typename T1, typename T2, size_t N>
void DoMathDataTest(data_1_int_2_t<RT1, T1, T2> (&data)[N], RT1 f(T1, T2, int*)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT1> predicate1;
  for (size_t i = 0; i < N; ++i) {
    RT1 out1;
    int out2;
    out1 = f(data[i].input1, data[i].input2, &out2);
    EXPECT_PRED_FORMAT2(predicate1, data[i].expected1, out1) << "Failed on element " << i;
    EXPECT_EQ(data[i].expected2, out2) << "Failed on element " << i;
  }
}

// Runs through the array 'data' applying 'f' to each of the pairs of input values
// and asserting that the result is within ULP ulps of the expected value.
// For testing a (double, double, double) -> double function like fma(3).
template <size_t ULP, typename RT, typename T1, typename T2, typename T3, size_t N>
void DoMathDataTest(data_1_3_t<RT, T1, T2, T3> (&data)[N], RT f(T1, T2, T3)) {
  fesetenv(FE_DFL_ENV);
  FpUlpEq<ULP, RT> predicate;
  for (size_t i = 0; i < N; ++i) {
    EXPECT_PRED_FORMAT2(predicate,
                        data[i].expected, f(data[i].input1, data[i].input2, data[i].input3)) << "Failed on element " << i;
  }
}
```
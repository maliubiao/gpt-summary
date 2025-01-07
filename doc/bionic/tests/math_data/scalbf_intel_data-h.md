Response:
Let's break down the thought process for answering this complex question about the `scalbf_intel_data.handroid` file.

**1. Understanding the Core Request:**

The fundamental goal is to understand the *purpose* of this specific data file within the Android bionic library. The decomposed questions are designed to guide the analysis towards this core purpose.

**2. Initial Analysis of the File Content:**

The first thing to notice is the structure of the data: an array of structs (`data_1_2_t<float, float, float>`). Each struct has three `float` members. The names of the data array (`g_scalbf_intel_data`) and the directory (`bionic/tests/math_data`) provide initial clues.

* **`scalbf`**: This strongly suggests a connection to the `scalbf` math function.
* **`intel_data`**:  Indicates that this data might be specific to Intel architectures or used for testing on Intel.
* **`tests/math_data`**:  Confirms that this file is part of the testing infrastructure for the math library.
* **`handroid`**:  Points towards Android-specific testing.

**3. Formulating the Core Function:**

Based on the file content and its location, the primary function is clearly to provide test data for the `scalbf` function. This immediately answers the initial request of summarizing the file's functionality.

**4. Connecting to Android Functionality:**

The `scalbf` function itself is part of the standard C math library (`math.h`) and is used in Android through its bionic libc implementation. Therefore, the data file directly supports the correct and robust implementation of `scalbf` in Android.

* **Example:**  An Android app using `scalbf` relies on the bionic library, and this data helps ensure that bionic's `scalbf` works correctly.

**5. Addressing the Libc Function Explanation:**

Since the file *contains data* for testing `scalbf`, it *doesn't implement* the function itself. The explanation needs to reflect this. Mentioning the standard definition of `scalbf` and its purpose (multiplying a floating-point number by a power of 2) is crucial.

**6. Dynamic Linker Aspects:**

This data file has no direct interaction with the dynamic linker. It's static data embedded within the bionic library. The answer must state this clearly and explain *why* it's not involved with the dynamic linker (it's not executable code or a shared library).

**7. Logical Inference, Assumptions, and Input/Output:**

The "logical inference" here is about how the test data is used.

* **Assumption:** The test suite iterates through the `g_scalbf_intel_data` array.
* **Input:**  The first two `float` values in each struct are likely the inputs to a `scalbf` implementation (the number and the power of 2).
* **Output:** The third `float` value is the expected result.

**8. Common Usage Errors:**

Because this is test data, common usage errors are *not directly related* to this file. Instead, the errors would relate to *using the `scalbf` function incorrectly*. Examples include passing invalid arguments or misunderstanding its behavior.

**9. Android Framework/NDK Path and Frida Hooking:**

This requires tracing how a call to `scalbf` in an Android app would reach the bionic library and how one might use Frida to inspect the process.

* **Framework/NDK Path:**
    * An app using the NDK calls `scalbf`.
    * This call is linked to the bionic libc.so.
    * Bionic's `scalbf` implementation is executed.
    * The tests (which use this data file) are run separately during the build process or by developers.
* **Frida Hook:**  Demonstrating how to hook `scalbf` in `libc.so` using Frida shows how to inspect its arguments and return value at runtime. This helps understand how the function behaves in a real application context, even though the data file itself isn't directly used at runtime.

**10. Summarizing the Functionality (Part 1):**

The final step for Part 1 is to condense all the information into a concise summary that answers the original question directly. Emphasize the role of the file as *test data* for the `scalbf` function within the Android bionic library.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file contains different implementations of `scalbf` for different Intel architectures?  **Correction:**  The naming suggests test *data*, not different implementations.
* **Considering dynamic linking:** Could this data be loaded dynamically? **Correction:** It's statically defined within the source code, so the dynamic linker isn't involved in its loading. The linker *is* involved in linking the application to `libc.so`, which contains the `scalbf` implementation.
* **Frida details:**  Initially, I might have focused on hooking the test execution itself. **Refinement:**  Hooking the actual `scalbf` function in `libc.so` provides a more general and useful example for developers.

By following this structured analysis and self-correction process, a comprehensive and accurate answer can be constructed. The key is to link the specific file content and its location within the broader context of the Android operating system and its build/testing processes.
好的，让我们来分析一下 `bionic/tests/math_data/scalbf_intel_data.handroid` 这个源代码文件的功能，并解答您提出的问题。

**文件功能归纳（第 1 部分）：**

`bionic/tests/math_data/scalbf_intel_data.handroid` 文件主要的功能是 **提供用于测试 `scalbf` 函数（single-precision scale by power of two）的一组预定义测试数据**。

具体来说：

* **测试数据定义:**  该文件定义了一个名为 `g_scalbf_intel_data` 的静态数组。
* **数据结构:** 数组中的每个元素都是一个 `data_1_2_t<float, float, float>` 类型的结构体。这个结构体显然是为了测试目的设计的，它的三个 `float` 成员很可能分别代表 `scalbf` 函数的输入参数和预期输出结果。
* **测试场景覆盖:**  数组中包含多个测试用例，每个用例针对 `scalbf` 函数的不同输入组合，包括正常值、边界值（如 0.0f、HUGE_VALF）、正负数以及不同的指数。  从文件名中的 "intel_data" 可以推测，这些数据可能是针对 Intel 架构的浮点数运算特性设计的或经过验证的。

**详细解释和关联性分析：**

1. **与 Android 功能的关系及举例说明：**

   * **`scalbf` 函数:** `scalbf` 是标准 C 语言数学库 `math.h` 中定义的函数，用于将一个浮点数乘以 2 的整数次幂。在 Android 的 C 库 bionic 中，也提供了 `scalbf` 的实现。
   * **测试的重要性:**  Android 系统底层库的正确性和稳定性至关重要。`scalbf_intel_data.handroid` 文件作为测试数据，其目的是验证 bionic 库中 `scalbf` 函数在各种输入情况下的行为是否符合预期。这确保了使用该函数的 Android 应用程序能够得到正确的计算结果。
   * **举例说明:** 假设一个 Android 应用需要进行图形渲染，其中涉及到对坐标进行缩放操作。如果该应用使用了 `scalbf` 函数来高效地进行 2 的幂次缩放，那么 `scalbf` 函数的正确性直接影响到渲染结果的准确性。`scalbf_intel_data.handroid` 中的测试数据就是用来保证 `scalbf` 在这种场景下能够正常工作。

2. **详细解释每一个 libc 函数的功能是如何实现的：**

   * **本文件不涉及 libc 函数的实现。**  `scalbf_intel_data.handroid` 文件本身是一个数据文件，它不包含任何 C 语言函数的实现代码。它只是为 `scalbf` 函数的测试提供输入和预期输出。
   * **`scalbf` 函数的实现原理:**  `scalbf(float x, int n)` 的典型实现会直接操作浮点数的内部表示（符号位、指数位、尾数位）。将 `x` 乘以 2 的 `n` 次幂，本质上是对 `x` 的指数部分进行加 `n` 的操作。需要注意的是，实现中会处理溢出、下溢、特殊值（NaN, Inf）等情况。

3. **对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

   * **本文件不涉及 dynamic linker 的功能。**  这个数据文件是静态编译到测试程序中的，不需要动态链接器加载。
   * **`scalbf` 函数的动态链接:**  虽然此文件不涉及，但 `scalbf` 函数本身是 libc 的一部分，它位于 `libc.so` 共享库中。
   * **`libc.so` 布局样本 (简化)：**
     ```
     libc.so:
         .text:  // 存放代码段
             ...
             scalbf:  // `scalbf` 函数的机器码
             ...
         .data:  // 存放已初始化的全局变量和静态变量
             ...
         .bss:   // 存放未初始化的全局变量和静态变量
             ...
         .symtab: // 符号表，记录导出的符号（如 `scalbf`）
             ...
     ```
   * **链接处理过程 (简化)：**
     1. **编译时:** 当编译包含 `scalbf` 函数调用的代码时，编译器会在目标文件（.o 文件）中记录下对 `scalbf` 的未定义引用。
     2. **链接时:** 链接器将所有的目标文件以及需要的库（如 `libc.so`）链接在一起。链接器会查找 `libc.so` 的符号表，找到 `scalbf` 的定义，并将目标文件中的未定义引用指向 `libc.so` 中 `scalbf` 的地址。
     3. **运行时:** 当程序启动时，动态链接器（`linker` 或 `ld-linux.so`）会将程序依赖的共享库加载到内存中。当程序执行到 `scalbf` 调用时，会跳转到 `libc.so` 中 `scalbf` 函数的实际地址执行。

4. **如果做了逻辑推理，请给出假设输入与输出：**

   * 本文件中的数据本身就是逻辑推理的体现。例如，Entry 0：
     * **假设输入:** `x = -0.0f`, `n = -0x1.p-149` (这是一个浮点数，在 `scalbf` 函数中，第二个参数应该是整数。这里可能是测试数据生成脚本的某种表示，最终会被转换成整数。假设实际测试中会取其整型部分，或者这是另一个相关函数的测试数据)
     * **预期输出:** `-0x1.40p3`

   * 假设 `scalbf` 的行为是将第一个 `float` 参数乘以 2 的第二个参数的整数次幂。

   * **更正假设（基于 `scalbf` 函数定义）:** 数组 `g_scalbf_intel_data` 的结构很可能对应于测试用例的 **输入 `x`，输入 `n`（作为乘以 2 的幂次），以及预期的输出结果**。

   * **重新分析 Entry 0:**
     * **输入 `x`:** `-0.0f`
     * **输入 `n` (乘以 2 的幂次):** `-0x1.p-149`  这仍然像是一个浮点数。  **一个更合理的假设是，这里的第二个 `float` 值代表了 `scalbf` 的第二个参数，但可能在测试代码中会被转换为一个整数。** 例如，如果测试代码是 `EXPECT_EQ(scalbf(input_x, (int)input_n), expected_output);` 那么 `input_n` 就会被强制转换为整数。
     * **预期输出:** `-0x1.40p3`

   * **Entry 25:**
     * **输入 `x`:** `-0x1.p0` (-1.0f)
     * **输入 `n`:** `-0x1.p0`  （假设转换为整数后为 -1）
     * **预期输出:** `0.0` (-1.0f * 2^-1 = -0.5f，这里预期输出为 0.0，可能需要结合具体的测试代码来理解。可能是测试了非常小的数的情况，接近于 0）

   * **Entry 26:**
     * **输入 `x`:** `-0x1.p1` (-2.0f)
     * **输入 `n`:** `-0x1.p0` （假设转换为整数后为 -1）
     * **预期输出:** `0x1.p0` (1.0f)  (-2.0f * 2^-1 = -1.0f， 预期输出为正数，可能测试了某些特殊情况或者存在一些隐式的转换或处理)

   **总结：**  这些数据条目旨在覆盖 `scalbf` 函数在各种浮点数和指数组合下的行为，包括特殊值和边界情况。具体的解释需要参考使用这些数据的测试代码。

5. **如果涉及用户或者编程常见的使用错误，请举例说明：**

   * **本文件是测试数据，不涉及用户直接使用错误。**  错误会发生在用户 *使用 `scalbf` 函数* 时。
   * **常见使用错误示例:**
     * **第二个参数不是整数:** `scalbf(3.14f, 2.5);`  `scalbf` 的第二个参数类型是 `int`，传入非整数值会导致类型转换，可能不是预期的结果。
     * **指数过大或过小导致溢出/下溢:** `scalbf(1.0f, 1000);` 或 `scalbf(1.0f, -1000);`  指数过大会导致结果超出浮点数的表示范围（无穷大），指数过小会导致结果接近于零。
     * **误解 `scalbf` 的作用:**  将 `scalbf` 误认为一般的乘法运算，而没有意识到它是乘以 2 的幂次。

6. **说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

   * **通常情况下，Android Framework 或 NDK 不会直接访问这个数据文件。**  这个文件是 bionic 库的内部测试数据。
   * **NDK 调用 `scalbf` 的路径:**
     1. **NDK 代码:**  开发者在 Native 代码 (C/C++) 中调用 `scalbf` 函数。
     2. **编译链接:** NDK 编译工具链将 Native 代码编译成机器码，并将 `scalbf` 函数的调用链接到 Android 系统的 `libc.so` 库。
     3. **运行时加载:** 当 Android 应用运行时，系统加载 `libc.so` 到进程的内存空间。
     4. **`scalbf` 执行:** 当 Native 代码执行到 `scalbf` 调用时，会跳转到 `libc.so` 中 `scalbf` 函数的实现代码执行。
   * **Frida Hook 示例:**  可以使用 Frida 来 hook `scalbf` 函数，观察其输入参数和返回值。

     ```python
     import frida
     import sys

     package_name = "your.package.name"  # 替换为你的应用包名

     def on_message(message, data):
         if message['type'] == 'send':
             print("[*] {}".format(message['payload']))
         else:
             print(message)

     try:
         session = frida.get_usb_device().attach(package_name)
     except frida.ProcessNotFoundError:
         print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
         sys.exit()

     script_code = """
     Interceptor.attach(Module.findExportByName("libc.so", "scalbf"), {
         onEnter: function(args) {
             var x = parseFloat(args[0]);
             var n = parseInt(args[1]);
             send({from: "scalbf", event: "enter", x: x, n: n});
             console.log("scalbf called with x = " + x + ", n = " + n);
         },
         onLeave: function(retval) {
             var result = parseFloat(retval);
             send({from: "scalbf", event: "leave", result: result});
             console.log("scalbf returned " + result);
         }
     });
     """

     script = session.create_script(script_code)
     script.on('message', on_message)
     script.load()
     input() # Keep the script running
     ```

     **使用方法:**

     1. 确保已安装 Frida 和 Python 的 Frida 模块。
     2. 将 `your.package.name` 替换为你要调试的 Android 应用的包名。
     3. 运行该 Python 脚本。
     4. 在 Android 设备上运行目标应用，并触发调用 `scalbf` 函数的代码路径。
     5. Frida 会拦截对 `scalbf` 的调用，并打印出输入参数和返回值。

**总结（针对第 1 部分）：**

总而言之，`bionic/tests/math_data/scalbf_intel_data.handroid` 是 Android bionic 库中用于测试 `scalbf` 函数的静态测试数据集。它包含了各种预定义的输入和预期输出，旨在验证 `scalbf` 函数在不同场景下的正确性。该文件本身不涉及动态链接或 libc 函数的实现，而是作为测试基础设施的一部分来保障底层数学运算的可靠性。

Prompt: 
```
这是目录为bionic/tests/math_data/scalbf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

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

static data_1_2_t<float, float, float> g_scalbf_intel_data[] = {
  { // Entry 0
    -0.0f,
    -0x1.p-149,
    -0x1.40p3
  },
  { // Entry 1
    -0x1.555554p-128,
    -0x1.555554p-2,
    -0x1.f8p6
  },
  { // Entry 2
    -0x1.6db6dcp-128,
    -0x1.6db6dcp-1,
    -0x1.fcp6
  },
  { // Entry 3
    -0x1.8e38e4p-128,
    -0x1.8e38e4p-1,
    -0x1.fcp6
  },
  { // Entry 4
    0.0f,
    0x1.p-149,
    -0x1.p0
  },
  { // Entry 5
    0.0f,
    0x1.p-149,
    -0x1.40p3
  },
  { // Entry 6
    0x1.5464b0p-130,
    0x1.5464b0p-2,
    -0x1.p7
  },
  { // Entry 7
    0.0f,
    0x1.dddddep-2,
    -0x1.28p7
  },
  { // Entry 8
    0x1.ecb7e8p-129,
    0x1.ecb7e8p-1,
    -0x1.p7
  },
  { // Entry 9
    0.0f,
    0x1.ffff60p-127,
    -0x1.70p4
  },
  { // Entry 10
    0.0f,
    0x1.ffff84p-127,
    -0x1.70p4
  },
  { // Entry 11
    0x1.fffff8p-137,
    0x1.fffff8p-127,
    -0x1.40p3
  },
  { // Entry 12
    0.0f,
    0x1.fffffep127,
    -0x1.p31
  },
  { // Entry 13
    HUGE_VALF,
    0x1.fffffep127,
    0x1.p31
  },
  { // Entry 14
    HUGE_VALF,
    0x1.fffffep127,
    0x1.p31
  },
  { // Entry 15
    -0x1.p-10,
    -0x1.p0,
    -0x1.40p3
  },
  { // Entry 16
    -0x1.p-9,
    -0x1.p0,
    -0x1.20p3
  },
  { // Entry 17
    -0x1.p-8,
    -0x1.p0,
    -0x1.p3
  },
  { // Entry 18
    -0x1.p-7,
    -0x1.p0,
    -0x1.c0p2
  },
  { // Entry 19
    -0x1.p-6,
    -0x1.p0,
    -0x1.80p2
  },
  { // Entry 20
    -0x1.p-5,
    -0x1.p0,
    -0x1.40p2
  },
  { // Entry 21
    -0x1.p-4,
    -0x1.p0,
    -0x1.p2
  },
  { // Entry 22
    -0x1.p-3,
    -0x1.p0,
    -0x1.80p1
  },
  { // Entry 23
    -0x1.p-2,
    -0x1.p0,
    -0x1.p1
  },
  { // Entry 24
    -0x1.p-1,
    -0x1.p0,
    -0x1.p0
  },
  { // Entry 25
    -0x1.p0,
    -0x1.p0,
    0.0
  },
  { // Entry 26
    -0x1.p1,
    -0x1.p0,
    0x1.p0
  },
  { // Entry 27
    -0x1.p2,
    -0x1.p0,
    0x1.p1
  },
  { // Entry 28
    -0x1.p3,
    -0x1.p0,
    0x1.80p1
  },
  { // Entry 29
    -0x1.p4,
    -0x1.p0,
    0x1.p2
  },
  { // Entry 30
    -0x1.p5,
    -0x1.p0,
    0x1.40p2
  },
  { // Entry 31
    -0x1.p6,
    -0x1.p0,
    0x1.80p2
  },
  { // Entry 32
    -0x1.p7,
    -0x1.p0,
    0x1.c0p2
  },
  { // Entry 33
    -0x1.p8,
    -0x1.p0,
    0x1.p3
  },
  { // Entry 34
    -0x1.p9,
    -0x1.p0,
    0x1.20p3
  },
  { // Entry 35
    -0x1.p10,
    -0x1.p0,
    0x1.40p3
  },
  { // Entry 36
    -0x1.d1745cp-11,
    -0x1.d1745cp-1,
    -0x1.40p3
  },
  { // Entry 37
    -0x1.d1745cp-10,
    -0x1.d1745cp-1,
    -0x1.20p3
  },
  { // Entry 38
    -0x1.d1745cp-9,
    -0x1.d1745cp-1,
    -0x1.p3
  },
  { // Entry 39
    -0x1.d1745cp-8,
    -0x1.d1745cp-1,
    -0x1.c0p2
  },
  { // Entry 40
    -0x1.d1745cp-7,
    -0x1.d1745cp-1,
    -0x1.80p2
  },
  { // Entry 41
    -0x1.d1745cp-6,
    -0x1.d1745cp-1,
    -0x1.40p2
  },
  { // Entry 42
    -0x1.d1745cp-5,
    -0x1.d1745cp-1,
    -0x1.p2
  },
  { // Entry 43
    -0x1.d1745cp-4,
    -0x1.d1745cp-1,
    -0x1.80p1
  },
  { // Entry 44
    -0x1.d1745cp-3,
    -0x1.d1745cp-1,
    -0x1.p1
  },
  { // Entry 45
    -0x1.d1745cp-2,
    -0x1.d1745cp-1,
    -0x1.p0
  },
  { // Entry 46
    -0x1.d1745cp-1,
    -0x1.d1745cp-1,
    0.0
  },
  { // Entry 47
    -0x1.d1745cp0,
    -0x1.d1745cp-1,
    0x1.p0
  },
  { // Entry 48
    -0x1.d1745cp1,
    -0x1.d1745cp-1,
    0x1.p1
  },
  { // Entry 49
    -0x1.d1745cp2,
    -0x1.d1745cp-1,
    0x1.80p1
  },
  { // Entry 50
    -0x1.d1745cp3,
    -0x1.d1745cp-1,
    0x1.p2
  },
  { // Entry 51
    -0x1.d1745cp4,
    -0x1.d1745cp-1,
    0x1.40p2
  },
  { // Entry 52
    -0x1.d1745cp5,
    -0x1.d1745cp-1,
    0x1.80p2
  },
  { // Entry 53
    -0x1.d1745cp6,
    -0x1.d1745cp-1,
    0x1.c0p2
  },
  { // Entry 54
    -0x1.d1745cp7,
    -0x1.d1745cp-1,
    0x1.p3
  },
  { // Entry 55
    -0x1.d1745cp8,
    -0x1.d1745cp-1,
    0x1.20p3
  },
  { // Entry 56
    -0x1.d1745cp9,
    -0x1.d1745cp-1,
    0x1.40p3
  },
  { // Entry 57
    -0x1.a2e8b8p-11,
    -0x1.a2e8b8p-1,
    -0x1.40p3
  },
  { // Entry 58
    -0x1.a2e8b8p-10,
    -0x1.a2e8b8p-1,
    -0x1.20p3
  },
  { // Entry 59
    -0x1.a2e8b8p-9,
    -0x1.a2e8b8p-1,
    -0x1.p3
  },
  { // Entry 60
    -0x1.a2e8b8p-8,
    -0x1.a2e8b8p-1,
    -0x1.c0p2
  },
  { // Entry 61
    -0x1.a2e8b8p-7,
    -0x1.a2e8b8p-1,
    -0x1.80p2
  },
  { // Entry 62
    -0x1.a2e8b8p-6,
    -0x1.a2e8b8p-1,
    -0x1.40p2
  },
  { // Entry 63
    -0x1.a2e8b8p-5,
    -0x1.a2e8b8p-1,
    -0x1.p2
  },
  { // Entry 64
    -0x1.a2e8b8p-4,
    -0x1.a2e8b8p-1,
    -0x1.80p1
  },
  { // Entry 65
    -0x1.a2e8b8p-3,
    -0x1.a2e8b8p-1,
    -0x1.p1
  },
  { // Entry 66
    -0x1.a2e8b8p-2,
    -0x1.a2e8b8p-1,
    -0x1.p0
  },
  { // Entry 67
    -0x1.a2e8b8p-1,
    -0x1.a2e8b8p-1,
    0.0
  },
  { // Entry 68
    -0x1.a2e8b8p0,
    -0x1.a2e8b8p-1,
    0x1.p0
  },
  { // Entry 69
    -0x1.a2e8b8p1,
    -0x1.a2e8b8p-1,
    0x1.p1
  },
  { // Entry 70
    -0x1.a2e8b8p2,
    -0x1.a2e8b8p-1,
    0x1.80p1
  },
  { // Entry 71
    -0x1.a2e8b8p3,
    -0x1.a2e8b8p-1,
    0x1.p2
  },
  { // Entry 72
    -0x1.a2e8b8p4,
    -0x1.a2e8b8p-1,
    0x1.40p2
  },
  { // Entry 73
    -0x1.a2e8b8p5,
    -0x1.a2e8b8p-1,
    0x1.80p2
  },
  { // Entry 74
    -0x1.a2e8b8p6,
    -0x1.a2e8b8p-1,
    0x1.c0p2
  },
  { // Entry 75
    -0x1.a2e8b8p7,
    -0x1.a2e8b8p-1,
    0x1.p3
  },
  { // Entry 76
    -0x1.a2e8b8p8,
    -0x1.a2e8b8p-1,
    0x1.20p3
  },
  { // Entry 77
    -0x1.a2e8b8p9,
    -0x1.a2e8b8p-1,
    0x1.40p3
  },
  { // Entry 78
    -0x1.745d14p-11,
    -0x1.745d14p-1,
    -0x1.40p3
  },
  { // Entry 79
    -0x1.745d14p-10,
    -0x1.745d14p-1,
    -0x1.20p3
  },
  { // Entry 80
    -0x1.745d14p-9,
    -0x1.745d14p-1,
    -0x1.p3
  },
  { // Entry 81
    -0x1.745d14p-8,
    -0x1.745d14p-1,
    -0x1.c0p2
  },
  { // Entry 82
    -0x1.745d14p-7,
    -0x1.745d14p-1,
    -0x1.80p2
  },
  { // Entry 83
    -0x1.745d14p-6,
    -0x1.745d14p-1,
    -0x1.40p2
  },
  { // Entry 84
    -0x1.745d14p-5,
    -0x1.745d14p-1,
    -0x1.p2
  },
  { // Entry 85
    -0x1.745d14p-4,
    -0x1.745d14p-1,
    -0x1.80p1
  },
  { // Entry 86
    -0x1.745d14p-3,
    -0x1.745d14p-1,
    -0x1.p1
  },
  { // Entry 87
    -0x1.745d14p-2,
    -0x1.745d14p-1,
    -0x1.p0
  },
  { // Entry 88
    -0x1.745d14p-1,
    -0x1.745d14p-1,
    0.0
  },
  { // Entry 89
    -0x1.745d14p0,
    -0x1.745d14p-1,
    0x1.p0
  },
  { // Entry 90
    -0x1.745d14p1,
    -0x1.745d14p-1,
    0x1.p1
  },
  { // Entry 91
    -0x1.745d14p2,
    -0x1.745d14p-1,
    0x1.80p1
  },
  { // Entry 92
    -0x1.745d14p3,
    -0x1.745d14p-1,
    0x1.p2
  },
  { // Entry 93
    -0x1.745d14p4,
    -0x1.745d14p-1,
    0x1.40p2
  },
  { // Entry 94
    -0x1.745d14p5,
    -0x1.745d14p-1,
    0x1.80p2
  },
  { // Entry 95
    -0x1.745d14p6,
    -0x1.745d14p-1,
    0x1.c0p2
  },
  { // Entry 96
    -0x1.745d14p7,
    -0x1.745d14p-1,
    0x1.p3
  },
  { // Entry 97
    -0x1.745d14p8,
    -0x1.745d14p-1,
    0x1.20p3
  },
  { // Entry 98
    -0x1.745d14p9,
    -0x1.745d14p-1,
    0x1.40p3
  },
  { // Entry 99
    -0x1.45d170p-11,
    -0x1.45d170p-1,
    -0x1.40p3
  },
  { // Entry 100
    -0x1.45d170p-10,
    -0x1.45d170p-1,
    -0x1.20p3
  },
  { // Entry 101
    -0x1.45d170p-9,
    -0x1.45d170p-1,
    -0x1.p3
  },
  { // Entry 102
    -0x1.45d170p-8,
    -0x1.45d170p-1,
    -0x1.c0p2
  },
  { // Entry 103
    -0x1.45d170p-7,
    -0x1.45d170p-1,
    -0x1.80p2
  },
  { // Entry 104
    -0x1.45d170p-6,
    -0x1.45d170p-1,
    -0x1.40p2
  },
  { // Entry 105
    -0x1.45d170p-5,
    -0x1.45d170p-1,
    -0x1.p2
  },
  { // Entry 106
    -0x1.45d170p-4,
    -0x1.45d170p-1,
    -0x1.80p1
  },
  { // Entry 107
    -0x1.45d170p-3,
    -0x1.45d170p-1,
    -0x1.p1
  },
  { // Entry 108
    -0x1.45d170p-2,
    -0x1.45d170p-1,
    -0x1.p0
  },
  { // Entry 109
    -0x1.45d170p-1,
    -0x1.45d170p-1,
    0.0
  },
  { // Entry 110
    -0x1.45d170p0,
    -0x1.45d170p-1,
    0x1.p0
  },
  { // Entry 111
    -0x1.45d170p1,
    -0x1.45d170p-1,
    0x1.p1
  },
  { // Entry 112
    -0x1.45d170p2,
    -0x1.45d170p-1,
    0x1.80p1
  },
  { // Entry 113
    -0x1.45d170p3,
    -0x1.45d170p-1,
    0x1.p2
  },
  { // Entry 114
    -0x1.45d170p4,
    -0x1.45d170p-1,
    0x1.40p2
  },
  { // Entry 115
    -0x1.45d170p5,
    -0x1.45d170p-1,
    0x1.80p2
  },
  { // Entry 116
    -0x1.45d170p6,
    -0x1.45d170p-1,
    0x1.c0p2
  },
  { // Entry 117
    -0x1.45d170p7,
    -0x1.45d170p-1,
    0x1.p3
  },
  { // Entry 118
    -0x1.45d170p8,
    -0x1.45d170p-1,
    0x1.20p3
  },
  { // Entry 119
    -0x1.45d170p9,
    -0x1.45d170p-1,
    0x1.40p3
  },
  { // Entry 120
    -0x1.1745ccp-11,
    -0x1.1745ccp-1,
    -0x1.40p3
  },
  { // Entry 121
    -0x1.1745ccp-10,
    -0x1.1745ccp-1,
    -0x1.20p3
  },
  { // Entry 122
    -0x1.1745ccp-9,
    -0x1.1745ccp-1,
    -0x1.p3
  },
  { // Entry 123
    -0x1.1745ccp-8,
    -0x1.1745ccp-1,
    -0x1.c0p2
  },
  { // Entry 124
    -0x1.1745ccp-7,
    -0x1.1745ccp-1,
    -0x1.80p2
  },
  { // Entry 125
    -0x1.1745ccp-6,
    -0x1.1745ccp-1,
    -0x1.40p2
  },
  { // Entry 126
    -0x1.1745ccp-5,
    -0x1.1745ccp-1,
    -0x1.p2
  },
  { // Entry 127
    -0x1.1745ccp-4,
    -0x1.1745ccp-1,
    -0x1.80p1
  },
  { // Entry 128
    -0x1.1745ccp-3,
    -0x1.1745ccp-1,
    -0x1.p1
  },
  { // Entry 129
    -0x1.1745ccp-2,
    -0x1.1745ccp-1,
    -0x1.p0
  },
  { // Entry 130
    -0x1.1745ccp-1,
    -0x1.1745ccp-1,
    0.0
  },
  { // Entry 131
    -0x1.1745ccp0,
    -0x1.1745ccp-1,
    0x1.p0
  },
  { // Entry 132
    -0x1.1745ccp1,
    -0x1.1745ccp-1,
    0x1.p1
  },
  { // Entry 133
    -0x1.1745ccp2,
    -0x1.1745ccp-1,
    0x1.80p1
  },
  { // Entry 134
    -0x1.1745ccp3,
    -0x1.1745ccp-1,
    0x1.p2
  },
  { // Entry 135
    -0x1.1745ccp4,
    -0x1.1745ccp-1,
    0x1.40p2
  },
  { // Entry 136
    -0x1.1745ccp5,
    -0x1.1745ccp-1,
    0x1.80p2
  },
  { // Entry 137
    -0x1.1745ccp6,
    -0x1.1745ccp-1,
    0x1.c0p2
  },
  { // Entry 138
    -0x1.1745ccp7,
    -0x1.1745ccp-1,
    0x1.p3
  },
  { // Entry 139
    -0x1.1745ccp8,
    -0x1.1745ccp-1,
    0x1.20p3
  },
  { // Entry 140
    -0x1.1745ccp9,
    -0x1.1745ccp-1,
    0x1.40p3
  },
  { // Entry 141
    -0x1.d17452p-12,
    -0x1.d17452p-2,
    -0x1.40p3
  },
  { // Entry 142
    -0x1.d17452p-11,
    -0x1.d17452p-2,
    -0x1.20p3
  },
  { // Entry 143
    -0x1.d17452p-10,
    -0x1.d17452p-2,
    -0x1.p3
  },
  { // Entry 144
    -0x1.d17452p-9,
    -0x1.d17452p-2,
    -0x1.c0p2
  },
  { // Entry 145
    -0x1.d17452p-8,
    -0x1.d17452p-2,
    -0x1.80p2
  },
  { // Entry 146
    -0x1.d17452p-7,
    -0x1.d17452p-2,
    -0x1.40p2
  },
  { // Entry 147
    -0x1.d17452p-6,
    -0x1.d17452p-2,
    -0x1.p2
  },
  { // Entry 148
    -0x1.d17452p-5,
    -0x1.d17452p-2,
    -0x1.80p1
  },
  { // Entry 149
    -0x1.d17452p-4,
    -0x1.d17452p-2,
    -0x1.p1
  },
  { // Entry 150
    -0x1.d17452p-3,
    -0x1.d17452p-2,
    -0x1.p0
  },
  { // Entry 151
    -0x1.d17452p-2,
    -0x1.d17452p-2,
    0.0
  },
  { // Entry 152
    -0x1.d17452p-1,
    -0x1.d17452p-2,
    0x1.p0
  },
  { // Entry 153
    -0x1.d17452p0,
    -0x1.d17452p-2,
    0x1.p1
  },
  { // Entry 154
    -0x1.d17452p1,
    -0x1.d17452p-2,
    0x1.80p1
  },
  { // Entry 155
    -0x1.d17452p2,
    -0x1.d17452p-2,
    0x1.p2
  },
  { // Entry 156
    -0x1.d17452p3,
    -0x1.d17452p-2,
    0x1.40p2
  },
  { // Entry 157
    -0x1.d17452p4,
    -0x1.d17452p-2,
    0x1.80p2
  },
  { // Entry 158
    -0x1.d17452p5,
    -0x1.d17452p-2,
    0x1.c0p2
  },
  { // Entry 159
    -0x1.d17452p6,
    -0x1.d17452p-2,
    0x1.p3
  },
  { // Entry 160
    -0x1.d17452p7,
    -0x1.d17452p-2,
    0x1.20p3
  },
  { // Entry 161
    -0x1.d17452p8,
    -0x1.d17452p-2,
    0x1.40p3
  },
  { // Entry 162
    -0x1.745d0cp-12,
    -0x1.745d0cp-2,
    -0x1.40p3
  },
  { // Entry 163
    -0x1.745d0cp-11,
    -0x1.745d0cp-2,
    -0x1.20p3
  },
  { // Entry 164
    -0x1.745d0cp-10,
    -0x1.745d0cp-2,
    -0x1.p3
  },
  { // Entry 165
    -0x1.745d0cp-9,
    -0x1.745d0cp-2,
    -0x1.c0p2
  },
  { // Entry 166
    -0x1.745d0cp-8,
    -0x1.745d0cp-2,
    -0x1.80p2
  },
  { // Entry 167
    -0x1.745d0cp-7,
    -0x1.745d0cp-2,
    -0x1.40p2
  },
  { // Entry 168
    -0x1.745d0cp-6,
    -0x1.745d0cp-2,
    -0x1.p2
  },
  { // Entry 169
    -0x1.745d0cp-5,
    -0x1.745d0cp-2,
    -0x1.80p1
  },
  { // Entry 170
    -0x1.745d0cp-4,
    -0x1.745d0cp-2,
    -0x1.p1
  },
  { // Entry 171
    -0x1.745d0cp-3,
    -0x1.745d0cp-2,
    -0x1.p0
  },
  { // Entry 172
    -0x1.745d0cp-2,
    -0x1.745d0cp-2,
    0.0
  },
  { // Entry 173
    -0x1.745d0cp-1,
    -0x1.745d0cp-2,
    0x1.p0
  },
  { // Entry 174
    -0x1.745d0cp0,
    -0x1.745d0cp-2,
    0x1.p1
  },
  { // Entry 175
    -0x1.745d0cp1,
    -0x1.745d0cp-2,
    0x1.80p1
  },
  { // Entry 176
    -0x1.745d0cp2,
    -0x1.745d0cp-2,
    0x1.p2
  },
  { // Entry 177
    -0x1.745d0cp3,
    -0x1.745d0cp-2,
    0x1.40p2
  },
  { // Entry 178
    -0x1.745d0cp4,
    -0x1.745d0cp-2,
    0x1.80p2
  },
  { // Entry 179
    -0x1.745d0cp5,
    -0x1.745d0cp-2,
    0x1.c0p2
  },
  { // Entry 180
    -0x1.745d0cp6,
    -0x1.745d0cp-2,
    0x1.p3
  },
  { // Entry 181
    -0x1.745d0cp7,
    -0x1.745d0cp-2,
    0x1.20p3
  },
  { // Entry 182
    -0x1.745d0cp8,
    -0x1.745d0cp-2,
    0x1.40p3
  },
  { // Entry 183
    -0x1.1745c6p-12,
    -0x1.1745c6p-2,
    -0x1.40p3
  },
  { // Entry 184
    -0x1.1745c6p-11,
    -0x1.1745c6p-2,
    -0x1.20p3
  },
  { // Entry 185
    -0x1.1745c6p-10,
    -0x1.1745c6p-2,
    -0x1.p3
  },
  { // Entry 186
    -0x1.1745c6p-9,
    -0x1.1745c6p-2,
    -0x1.c0p2
  },
  { // Entry 187
    -0x1.1745c6p-8,
    -0x1.1745c6p-2,
    -0x1.80p2
  },
  { // Entry 188
    -0x1.1745c6p-7,
    -0x1.1745c6p-2,
    -0x1.40p2
  },
  { // Entry 189
    -0x1.1745c6p-6,
    -0x1.1745c6p-2,
    -0x1.p2
  },
  { // Entry 190
    -0x1.1745c6p-5,
    -0x1.1745c6p-2,
    -0x1.80p1
  },
  { // Entry 191
    -0x1.1745c6p-4,
    -0x1.1745c6p-2,
    -0x1.p1
  },
  { // Entry 192
    -0x1.1745c6p-3,
    -0x1.1745c6p-2,
    -0x1.p0
  },
  { // Entry 193
    -0x1.1745c6p-2,
    -0x1.1745c6p-2,
    0.0
  },
  { // Entry 194
    -0x1.1745c6p-1,
    -0x1.1745c6p-2,
    0x1.p0
  },
  { // Entry 195
    -0x1.1745c6p0,
    -0x1.1745c6p-2,
    0x1.p1
  },
  { // Entry 196
    -0x1.1745c6p1,
    -0x1.1745c6p-2,
    0x1.80p1
  },
  { // Entry 197
    -0x1.1745c6p2,
    -0x1.1745c6p-2,
    0x1.p2
  },
  { // Entry 198
    -0x1.1745c6p3,
    -0x1.1745c6p-2,
    0x1.40p2
  },
  { // Entry 199
    -0x1.1745c6p4,
    -0x1.1745c6p-2,
    0x1.80p2
  },
  { // Entry 200
    -0x1.1745c6p5,
    -0x1.1745c6p-2,
    0x1.c0p2
  },
  { // Entry 201
    -0x1.1745c6p6,
    -0x1.1745c6p-2,
    0x1.p3
  },
  { // Entry 202
    -0x1.1745c6p7,
    -0x1.1745c6p-2,
    0x1.20p3
  },
  { // Entry 203
    -0x1.1745c6p8,
    -0x1.1745c6p-2,
    0x1.40p3
  },
  { // Entry 204
    -0x1.745dp-13,
    -0x1.745dp-3,
    -0x1.40p3
  },
  { // Entry 205
    -0x1.745dp-12,
    -0x1.745dp-3,
    -0x1.20p3
  },
  { // Entry 206
    -0x1.745dp-11,
    -0x1.745dp-3,
    -0x1.p3
  },
  { // Entry 207
    -0x1.745dp-10,
    -0x1.745dp-3,
    -0x1.c0p2
  },
  { // Entry 208
    -0x1.745dp-9,
    -0x1.745dp-3,
    -0x1.80p2
  },
  { // Entry 209
    -0x1.745dp-8,
    -0x1.745dp-3,
    -0x1.40p2
  },
  { // Entry 210
    -0x1.745dp-7,
    -0x1.745dp-3,
    -0x1.p2
  },
  { // Entry 211
    -0x1.745dp-6,
    -0x1.745dp-3,
    -0x1.80p1
  },
  { // Entry 212
    -0x1.745dp-5,
    -0x1.745dp-3,
    -0x1.p1
  },
  { // Entry 213
    -0x1.745dp-4,
    -0x1.745dp-3,
    -0x1.p0
  },
  { // Entry 214
    -0x1.745dp-3,
    -0x1.745dp-3,
    0.0
  },
  { // Entry 215
    -0x1.745dp-2,
    -0x1.745dp-3,
    0x1.p0
  },
  { // Entry 216
    -0x1.745dp-1,
    -0x1.745dp-3,
    0x1.p1
  },
  { // Entry 217
    -0x1.745dp0,
    -0x1.745dp-3,
    0x1.80p1
  },
  { // Entry 218
    -0x1.745dp1,
    -0x1.745dp-3,
    0x1.p2
  },
  { // Entry 219
    -0x1.745dp2,
    -0x1.745dp-3,
    0x1.40p2
  },
  { // Entry 220
    -0x1.745dp3,
    -0x1.745dp-3,
    0x1.80p2
  },
  { // Entry 221
    -0x1.745dp4,
    -0x1.745dp-3,
    0x1.c0p2
  },
  { // Entry 222
    -0x1.745dp5,
    -0x1.745dp-3,
    0x1.p3
  },
  { // Entry 223
    -0x1.745dp6,
    -0x1.745dp-3,
    0x1.20p3
  },
  { // Entry 224
    -0x1.745dp7,
    -0x1.745dp-3,
    0x1.40p3
  },
  { // Entry 225
    -0x1.745ce8p-14,
    -0x1.745ce8p-4,
    -0x1.40p3
  },
  { // Entry 226
    -0x1.745ce8p-13,
    -0x1.745ce8p-4,
    -0x1.20p3
  },
  { // Entry 227
    -0x1.745ce8p-12,
    -0x1.745ce8p-4,
    -0x1.p3
  },
  { // Entry 228
    -0x1.745ce8p-11,
    -0x1.745ce8p-4,
    -0x1.c0p2
  },
  { // Entry 229
    -0x1.745ce8p-10,
    -0x1.745ce8p-4,
    -0x1.80p2
  },
  { // Entry 230
    -0x1.745ce8p-9,
    -0x1.745ce8p-4,
    -0x1.40p2
  },
  { // Entry 231
    -0x1.745ce8p-8,
    -0x1.745ce8p-4,
    -0x1.p2
  },
  { // Entry 232
    -0x1.745ce8p-7,
    -0x1.745ce8p-4,
    -0x1.80p1
  },
  { // Entry 233
    -0x1.745ce8p-6,
    -0x1.745ce8p-4,
    -0x1.p1
  },
  { // Entry 234
    -0x1.745ce8p-5,
    -0x1.745ce8p-4,
    -0x1.p0
  },
  { // Entry 235
    -0x1.745ce8p-4,
    -0x1.745ce8p-4,
    0.0
  },
  { // Entry 236
    -0x1.745ce8p-3,
    -0x1.745ce8p-4,
    0x1.p0
  },
  { // Entry 237
    -0x1.745ce8p-2,
    -0x1.745ce8p-4,
    0x1.p1
  },
  { // Entry 238
    -0x1.745ce8p-1,
    -0x1.745ce8p-4,
    0x1.80p1
  },
  { // Entry 239
    -0x1.745ce8p0,
    -0x1.745ce8p-4,
    0x1.p2
  },
  { // Entry 240
    -0x1.745ce8p1,
    -0x1.745ce8p-4,
    0x1.40p2
  },
  { // Entry 241
    -0x1.745ce8p2,
    -0x1.745ce8p-4,
    0x1.80p2
  },
  { // Entry 242
    -0x1.745ce8p3,
    -0x1.745ce8p-4,
    0x1.c0p2
  },
  { // Entry 243
    -0x1.745ce8p4,
    -0x1.745ce8p-4,
    0x1.p3
  },
  { // Entry 244
    -0x1.745ce8p5,
    -0x1.745ce8p-4,
    0x1.20p3
  },
  { // Entry 245
    -0x1.745ce8p6,
    -0x1.745ce8p-4,
    0x1.40p3
  },
  { // Entry 246
    0x1.80p-33,
    0x1.80p-23,
    -0x1.40p3
  },
  { // Entry 247
    0x1.80p-32,
    0x1.80p-23,
    -0x1.20p3
  },
  { // Entry 248
    0x1.80p-31,
    0x1.80p-23,
    -0x1.p3
  },
  { // Entry 249
    0x1.80p-30,
    0x1.80p-23,
    -0x1.c0p2
  },
  { // Entry 250
    0x1.80p-29,
    0x1.80p-23,
    -0x1.80p2
  },
  { // Entry 251
    0x1.80p-28,
    0x1.80p-23,
    -0x1.40p2
  },
  { // Entry 252
    0x1.80p-27,
    0x1.80p-23,
    -0x1.p2
  },
  { // Entry 253
    0x1.80p-26,
    0x1.80p-23,
    -0x1.80p1
  },
  { // Entry 254
    0x1.80p-25,
    0x1.80p-23,
    -0x1.p1
  },
  { // Entry 255
    0x1.80p-24,
    0x1.80p-23,
    -0x1.p0
  },
  { // Entry 256
    0x1.80p-23,
    0x1.80p-23,
    0.0
  },
  { // Entry 257
    0x1.80p-22,
    0x1.80p-23,
    0x1.p0
  },
  { // Entry 258
    0x1.80p-21,
    0x1.80p-23,
    0x1.p1
  },
  { // Entry 259
    0x1.80p-20,
    0x1.80p-23,
    0x1.80p1
  },
  { // Entry 260
    0x1.80p-19,
    0x1.80p-23,
    0x1.p2
  },
  { // Entry 261
    0x1.80p-18,
    0x1.80p-23,
    0x1.40p2
  },
  { // Entry 262
    0x1.80p-17,
    0x1.80p-23,
    0x1.80p2
  },
  { // Entry 263
    0x1.80p-16,
    0x1.80p-23,
    0x1.c0p2
  },
  { // Entry 264
    0x1.80p-15,
    0x1.80p-23,
    0x1.p3
  },
  { // Entry 265
    0x1.80p-14,
    0x1.80p-23,
    0x1.20p3
  },
  { // Entry 266
    0x1.80p-13,
    0x1.80p-23,
    0x1.40p3
  },
  { // Entry 267
    0x1.745d48p-14,
    0x1.745d48p-4,
    -0x1.40p3
  },
  { // Entry 268
    0x1.745d48p-13,
    0x1.745d48p-4,
    -0x1.20p3
  },
  { // Entry 269
    0x1.745d48p-12,
    0x1.745d48p-4,
    -0x1.p3
  },
  { // Entry 270
    0x1.745d48p-11,
    0x1.745d48p-4,
    -0x1.c0p2
  },
  { // Entry 271
    0x1.745d48p-10,
    0x1.745d48p-4,
    -0x1.80p2
  },
  { // Entry 272
    0x1.745d48p-9,
    0x1.745d48p-4,
    -0x1.40p2
  },
  { // Entry 273
    0x1.745d48p-8,
    0x1.745d48p-4,
    -0x1.p2
  },
  { // Entry 274
    0x1.745d48p-7,
    0x1.745d48p-4,
    -0x1.80p1
  },
  { // Entry 275
    0x1.745d48p-6,
    0x1.745d48p-4,
    -0x1.p1
  },
  { // Entry 276
    0x1.745d48p-5,
    0x1.745d48p-4,
    -0x1.p0
  },
  { // Entry 277
    0x1.745d48p-4,
    0x1.745d48p-4,
    0.0
  },
  { // Entry 278
    0x1.745d48p-3,
    0x1.745d48p-4,
    0x1.p0
  },
  { // Entry 279
    0x1.745d48p-2,
    0x1.745d48p-4,
    0x1.p1
  },
  { // Entry 280
    0x1.745d48p-1,
    0x1.745d48p-4,
    0x1.80p1
  },
  { // Entry 281
    0x1.745d48p0,
    0x1.745d48p-4,
    0x1.p2
  },
  { // Entry 282
    0x1.745d48p1,
    0x1.745d48p-4,
    0x1.40p2
  },
  { // Entry 283
    0x1.745d48p2,
    0x1.745d48p-4,
    0x1.80p2
  },
  { // Entry 284
    0x1.745d48p3,
    0x1.745d48p-4,
    0x1.c0p2
  },
  { // Entry 285
    0x1.745d48p4,
    0x1.745d48p-4,
    0x1.p3
  },
  { // Entry 286
    0x1.745d48p5,
    0x1.745d48p-4,
    0x1.20p3
  },
  { // Entry 287
    0x1.745d48p6,
    0x1.745d48p-4,
    0x1.40p3
  },
  { // Entry 288
    0x1.745d30p-13,
    0x1.745d30p-3,
    -0x1.40p3
  },
  { // Entry 289
    0x1.745d30p-12,
    0x1.745d30p-3,
    -0x1.20p3
  },
  { // Entry 290
    0x1.745d30p-11,
    0x1.745d30p-3,
    -0x1.p3
  },
  { // Entry 291
    0x1.745d30p-10,
    0x1.745d30p-3,
    -0x1.c0p2
  },
  { // Entry 292
    0x1.745d30p-9,
    0x1.745d30p-3,
    -0x1.80p2
  },
  { // Entry 293
    0x1.745d30p-8,
    0x1.745d30p-3,
    -0x1.40p2
  },
  { // Entry 294
    0x1.745d30p-7,
    0x1.745d30p-3,
    -0x1.p2
  },
  { // Entry 295
    0x1.745d30p-6,
    0x1.745d30p-3,
    -0x1.80p1
  },
  { // Entry 296
    0x1.745d30p-5,
    0x1.745d30p-3,
    -0x1.p1
  },
  { // Entry 297
    0x1.745d30p-4,
    0x1.745d30p-3,
    -0x1.p0
  },
  { // Entry 298
    0x1.745d30p-3,
    0x1.745d30p-3,
    0.0
  },
  { // Entry 299
    0x1.745d30p-2,
    0x1.745d30p-3,
    0x1.p0
  },
  { // Entry 300
    0x1.745d30p-1,
    0x1.745d30p-3,
    0x1.p1
  },
  { // Entry 301
    0x1.745d30p0,
    0x1.745d30p-3,
    0x1.80p1
  },
  { // Entry 302
    0x1.745d30p1,
    0x1.745d30p-3,
    0x1.p2
  },
  { // Entry 303
    0x1.745d30p2,
    0x1.745d30p-3,
    0x1.40p2
  },
  { // Entry 304
    0x1.745d30p3,
    0x1.745d30p-3,
    0x1.80p2
  },
  { // Entry 305
    0x1.745d30p4,
    0x1.745d30p-3,
    0x1.c0p2
  },
  { // Entry 306
    0x1.745d30p5,
    0x1.745d30p-3,
    0x1.p3
  },
  { // Entry 307
    0x1.745d30p6,
    0x1.745d30p-3,
    0x1.20p3
  },
  { // Entry 308
    0x1.745d30p7,
    0x1.745d30p-3,
    0x1.40p3
  },
  { // Entry 309
    0x1.1745dep-12,
    0x1.1745dep-2,
    -0x1.40p3
  },
  { // Entry 310
    0x1.1745dep-11,
    0x1.1745dep-2,
    -0x1.20p3
  },
  { // Entry 311
    0x1.1745dep-10,
    0x1.1745dep-2,
    -0x1.p3
  },
  { // Entry 312
    0x1.1745dep-9,
    0x1.1745dep-2,
    -0x1.c0p2
  },
  { // Entry 313
    0x1.1745dep-8,
    0x1.1745dep-2,
    -0x1.80p2
  },
  { // Entry 314
    0x1.1745dep-7,
    0x1.1745dep-2,
    -0x1.40p2
  },
  { // Entry 315
    0x1.1745dep-6,
    0x1.1745dep-2,
    -0x1.p2
  },
  { // Entry 316
    0x1.1745dep-5,
    0x1.1745dep-2,
    -0x1.80p1
  },
  { // Entry 317
    0x1.1745dep-4,
    0x1.1745dep-2,
    -0x1.p1
  },
  { // Entry 318
    0x1.1745dep-3,
    0x1.1745dep-2,
    -0x1.p0
  },
  { // Entry 319
    0x1.1745dep-2,
    0x1.1745dep-2,
    0.0
  },
  { // Entry 320
    0x1.1745dep-1,
    0x1.1745dep-2,
    0x1.p0
  },
  { // Entry 321
    0x1.1745dep0,
    0x1.1745dep-2,
    0x1.p1
  },
  { // Entry 322
    0x1.1745dep1,
    0x1.1745dep-2,
    0x1.80p1
  },
  { // Entry 323
    0x1.1745dep2,
    0x1.1745dep-2,
    0x1.p2
  },
  { // Entry 324
    0x1.1745dep3,
    0x1.1745dep-2,
    0x1.40p2
  },
  { // Entry 325
    0x1.1745dep4,
    0x1.1745dep-2,
    0x1.80p2
  },
  { // Entry 326
    0x1.1745dep5,
    0x1.1745dep-2,
    0x1.c0p2
  },
  { // Entry 327
    0x1.1745dep6,
    0x1.1745dep-2,
    0x1.p3
  },
  { // Entry 328
    0x1.1745dep7,
    0x1.1745dep-2,
    0x1.20p3
  },
  { // Entry 329
    0x1.1745dep8,
    0x1.1745dep-2,
    0x1.40p3
  },
  { // Entry 330
    0x1.745d24p-12,
    0x1.745d24p-2,
    -0x1.40p3
  },
  { // Entry 331
    0x1.745d24p-11,
    0x1.745d24p-2,
    -0x1.20p3
  },
  { // Entry 332
    0x1.745d24p-10,
    0x1.745d24p-2,
    -0x1.p3
  },
  { // Entry 333
    0x1.745d24p-9,
    0x1.745d24p-2,
    -0x1.c0p2
  },
  { // Entry 334
    0x1.745d24p-8,
    0x1.745d24p-2,
    -0x1.80p2
  },
  { // Entry 335
    0x1.745d24p-7,
    0x1.745d24p-2,
    -0x1.40p2
  },
  { // Entry 336
    0x1.745d24p-6,
    0x1.745d24p-2,
    -0x1.p2
  },
  { // Entry 337
    0x1.745d24p-5,
    0x1.745d24p-2,
    -0x1.80p1
  },
  { // Entry 338
    0x1.745d24p-4,
    0x1.745d24p-2,
    -0x1.p1
  },
  { // Entry 339
    0x1.745d24p-3,
    0x1.745d24p-2,
    -0x1.p0
  },
  { // Entry 340
    0x1.745d24p-2,
    0x1.745d24p-2,
    0.0
  },
  { // Entry 341
    0x1.745d24p-1,
    0x1.745d24p-2,
    0x1.p0
  },
  { // Entry 342
    0x1.745d24p0,
    0x1.745d24p-2,
    0x1.p1
  },
  { // Entry 343
    0x1.745d24p1,
    0x1.745d24p-2,
    0x1.80p1
  },
  { // Entry 344
    0x1.745d24p2,
    0x1.745d24p-2,
    0x1.p2
  },
  { // Entry 345
    0x1.745d24p3,
    0x1.745d24p-2,
    0x1.40p2
  },
  { // Entry 346
    0x1.745d24p4,
    0x1.745d24p-2,
    0x1.80p2
  },
  { // Entry 347
    0x1.745d24p5,
    0x1.745d24p-2,
    0x1.c0p2
  },
  { // Entry 348
    0x1.745d24p6,
    0x1.745d24p-2,
    0x1.p3
  },
  { // Entry 349
    0x1.745d24p7,
    0x1.745d24p-2,
    0x1.20p3
  },
  { // Entry 350
    0x1.745d24p8,
    0x1.745d24p-2,
    0x1.40p3
  },
  { // Entry 351
    0x1.d1746ap-12,
    0x1.d1746ap-2,
    -0x1.40p3
  },
  { // Entry 352
    0x1.d1746ap-11,
    0x1.d1746ap-2,
    -0x1.20p3
  },
  { // Entry 353
    0x1.d1746ap-10,
    0x1.d1746ap-2,
    -0x1.p3
  },
  { // Entry 354
    0x1.d1746ap-9,
    0x1.d1746ap-2,
    -0x1.c0p2
  },
  { // Entry 355
    0x1.d1746ap-8,
    0x1.d1746ap-2,
    -0x1.80p2
  },
  { // Entry 356
    0x1.d1746ap-7,
    0x1.d1746ap-2,
    -0x1.40p2
  },
  { // Entry 357
    0x1.d1746ap-6,
    0x1.d1746ap-2,
    -0x1.p2
  },
  { // Entry 358
    0x1.d1746ap-5,
    0x1.d1746ap-2,
    -0x1.80p1
  },
  { // Entry 359
    0x1.d1746ap-4,
    0x1.d1746ap-2,
    -0x1.p1
  },
  { // Entry 360
    0x1.d1746ap-3,
    0x1.d1746ap-2,
    -0x1.p0
  },
  { // Entry 361
    0x1.d1746ap-2,
    0x1.d1746ap-2,
    0.0
  },
  { // Entry 362
    0x1.d1746ap-1,
    0x1.d1746ap-2,
    0x1.p0
  },
  { // Entry 363
    0x1.d1746ap0,
    0x1.d1746ap-2,
    0x1.p1
  },
  { // Entry 364
    0x1.d1746ap1,
    0x1.d1746ap-2,
    0x1.80p1
  },
  { // Entry 365
    0x1.d1746ap2,
    0x1.d1746ap-2,
    0x1.p2
  },
  { // Entry 366
    0x1.d1746ap3,
    0x1.d1746ap-2,
    0x1.40p2
  },
  { // Entry 367
    0x1.d1746ap4,
    0x1.d1746ap-2,
    0x1.80p2
  },
  { // Entry 368
    0x1.d1746ap5,
    0x1.d1746ap-2,
    0x1.c0p2
  },
  { // Entry 369
    0x1.d1746ap6,
    0x1.d1746ap-2,
    0x1.p3
  },
  { // Entry 370
    0x1.d1746ap7,
    0x1.d1746ap-2,
    0x1.20p3
  },
  { // Entry 371
    0x1.d1746ap8,
    0x1.d1746ap-2,
    0x1.40p3
  },
  { // Entry 372
    0x1.1745d8p-11,
    0x1.1745d8p-1,
    -0x1.40p3
  },
  { // Entry 373
    0x1.1745d8p-10,
    0x1.1745d8p-1,
    -0x1.20p3
  },
  { // Entry 374
    0x1.1745d8p-9,
    0x1.1745d8p-1,
    -0x1.p3
  },
  { // Entry 375
    0x1.1745d8p-8,
    0x1.1745d8p-1,
    -0x1.c0p2
  },
  { // Entry 376
    0x1.1745d8p-7,
    0x1.1745d8p-1,
    -0x1.80p2
  },
  { // Entry 377
    0x1.1745d8p-6,
    0x1.1745d8p-1,
    -0x1.40p2
  },
  { // Entry 378
    0x1.1745d8p-5,
    0x1.1745d8p-1,
    -0x1.p2
  },
  { // Entry 379
    0x1.1745d8p-4,
    0x1.1745d8p-1,
    -0x1.80p1
  },
  { // Entry 380
    0x1.1745d8p-3,
    0x1.1745d8p-1,
    -0x1.p1
  },
  { // Entry 381
    0x1.1745d8p-2,
    0x1.1745d8p-1,
    -0x1.p0
  },
  { // Entry 382
    0x1.1745d8p-1,
    0x1.1745d8p-1,
    0.0
  },
  { // Entry 383
    0x1.1745d8p0,
    0x1.1745d8p-1,
    0x1.p0
  },
  { // Entry 384
    0x1.1745d8p1,
    0x1.1745d8p-1,
    0x1.p1
  },
  { // Entry 385
    0x1.1745d8p2,
    0x1.1745d8p-1,
    0x1.80p1
  },
  { // Entry 386
    0x1.1745d8p3,
    0x1.1745d8p-1,
    0x1.p2
  },
  { // Entry 387
    0x1.1745d8p4,
    0x1.1745d8p-1,
    0x1.40p2
  },
  { // Entry 388
    0x1.1745d8p5,
    0x1.1745d8p-1,
    0x1.80p2
  },
  { // Entry 389
    0x1.1745d8p6,
    0x1.1745d8p-1,
    0x1.c0p2
  },
  { // Entry 390
    0x1.1745d8p7,
    0x1.1745d8p-1,
    0x1.p3
  },
  { // Entry 391
    0x1.1745d8p8,
    0x1.1745d8p-1,
    0x1.20p3
  },
  { // Entry 392
    0x1.1745d8p9,
    0x1.1745d8p-1,
    0x1.40p3
  },
  { // Entry 393
    0x1.45d17cp-11,
    0x1.45d17cp-1,
    -0x1.40p3
  },
  { // Entry 394
    0x1.45d17cp-10,
    0x1.45d17cp-1,
    -0x1.20p3
  },
  { // Entry 395
    0x1.45d17cp-9,
    0x1.45d17cp-1,
    -0x1.p3
  },
  { // Entry 396
    0x1.45d17cp-8,
    0x1.45d17cp-1,
    -0x1.c0p2
  },
  { // Entry 397
    0x1.45d17cp-7,
    0x1.45d17cp-1,
    -0x1.80p2
  },
  { // Entry 398
    0x1.45d17cp-6,
    0x1.45d17cp-1,
    -0x1.40p2
  },
  { // Entry 399
    0x1.45d17cp-5,
    0x1.45d17cp-1,
    -0x1.p2
  },
  { // Entry 400
    0x1.45d17cp-4,
    0x1.45d17cp-1,
    -0x1.80p1
  },
  { // Entry 401
    0x1.45d17cp-3,
    0x1.45d17cp-1,
    -0x1.p1
  },
  { // Entry 402
    0x1.45d17cp-2,
    0x1.45d17cp-1,
    -0x1.p0
  },
  { // Entry 403
    0x1.45d17cp-1,
    0x1.45d17cp-1,
    0.0
  },
  { // Entry 404
    0x1.45d17cp0,
    0x1.45d17cp-1,
    0x1.p0
  },
  { // Entry 405
    0x1.45d17cp1,
    0x1.45d17cp-1,
    0x1.p1
  },
  { // Entry 406
    0x1.45d17cp2,
    0x1.45d17cp-1,
    0x1.80p1
  },
  { // Entry 407
    0x1.45d17cp3,
    0x1.45d17cp-1,
    0x1.p2
  },
  { // Entry 408
    0x1.45d17cp4,
    0x1.45d17cp-1,
    0x1.40p2
  },
  { // Entry 409
    0x1.45d17cp5,
    0x1.45d17cp-1,
    0x1.80p2
  },
  { // Entry 410
    0x1.45d17cp6,
    0x1.45d17cp-1,
    0x1.c0p2
  },
  { // Entry 411
    0x1.45d17cp7,
    0x1.45d17cp-1,
    0x1.p3
  },
  { // Entry 412
    0x1.45d17cp8,
    0x1.45d17cp-1,
    0x1.20p3
  },
  { // Entry 413
    0x1.45d17cp9,
    0x1.45d17cp-1,
    0x1.40p3
  },
  { // Entry 414
    0x1.745d20p-11,
    0x1.745d20p-1,
    -0x1.40p3
  },
  { // Entry 415
    0x1.745d20p-10,
    0x1.745d20p-1,
    -0x1.20p3
  },
  { // Entry 416
    0x1.745d20p-9,
    0x1.745d20p-1,
    -0x1.p3
  },
  { // Entry 417
    0x1.745d20p-8,
    0x1.745d20p-1,
    -0x1.c0p2
  },
  { // Entry 418
    0x1.745d20p-7,
    0x1.745d20p-1,
    -0x1.80p2
  },
  { // Entry 419
    0x1.745d20p-6,
    0x1.745d20p-1,
    -0x1.40p2
  },
  { // Entry 420
    0x1.745d20p-5,
    0x1.745d20p-1,
    -0x1.p2
  },
  { // Entry 421
    0x1.745d20p-4,
    0x1.745d20p-1,
    -0x1.80p1
  },
  { // Entry 422
    0x1.745d20p-3,
    0x1.745d20p-1,
    -0x1.p1
  },
  { // Entry 423
    0x1.745d20p-2,
    0x1.745d20p-1,
    -0x1.p0
  },
  { // Entry 424
    0x1.745d20p-1,
    0x1.745d20p-1,
    0.0
  },
  { // Entry 425
    0x1.745d20p0,
    0x1.745d20p-1,
    0x1.p0
  },
  { // Entry 426
    0x1.745d20p1,
    0x1.745d20p-1,
    0x1.p1
  },
  { // Entry 427
    0x1.745d20p2,
    0x1.745d20p-1,
    0x1.80p1
  },
  { // Entry 428
    0x1.745d20p3,
    0x1.745d20p-1,
    0x1.p2
  },
  { // Entry 429
    0x1.745d20p4,
    0x1.745d20p-1,
    0x1.40p2
  },
  { // Entry 430
    0x1.745d20p5,
    0x1.745d20p-1,
    0x1.80p2
  },
  { // Entry 431
    0x1.745d20p6,
    0x1.745d20p-1,
    0x1.c0p2
  },
  { // Entry 432
    0x1.745d20p7,
    0x1.745d20p-1,
    0x1.p3
  },
  { // Entry 433
    0x1.745d20p8,
    0x1.745d20p-1,
    0x1.20p3
  },
  { // Entry 434
    0x1.745d20p9,
    0x1.745d20p-1,
    0x1.40p3
  },
  { // Entry 435
    0x1.a2e8c4p-11,
    0x1.a2e8c4p-1,
    -0x1.40p3
  },
  { // Entry 436
    0x1.a2e8c4p-10,
    0x1.a2e8c4p-1,
    -0x1.20p3
  },
  { // Entry 437
    0x1.a2e8c4p-9,
    0x1.a2e8c4p-1,
    -0x1.p3
  },
  { // Entry 438
    0x1.a2e8c4p-8,
    0x1.a2e8c4p-1,
    -0x1.c0p2
  },
  { // Entry 439
    0x1.a2e8c4p-7,
    0x1.a2e8c4p-1,
    -0x1.80p2
  },
  { // Entry 440
    0x1.a2e8c4p-6,
    0x1.a2e8c4p-1,
    -0x1.40p2
  },
  { // Entry 441
    0x1.a2e8c4p-5,
    0x1.a2e8c4p-1,
    -0x1.p2
  },
  { // Entry 442
    0x1.a2e8c4p-4,
    0x1.a2e8c4p-1,
    -0x1.80p1
  },
  { // Entry 443
    0x1.a2e8c4p-3,
    0x1.a2e8c4p-1,
    -0x1.p1
  },
  { // Entry 444
    0x1.a2e8c4p-2,
    0x1.a2e8c4p-1,
    -0x1.p0
  },
  { // Entry 445
    0x1.a2e8c4p-1,
    0x1.a2e8c4p-1,
    0.0
  },
  { // Entry 446
    0x1.a2e8c4p0,
    0x1.a2e8
"""


```
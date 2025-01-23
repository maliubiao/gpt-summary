Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Task:** The primary goal is to analyze the provided C code snippet and describe its function within the context of Android's bionic library, specifically the math library. The prompt emphasizes *hypot* and the data being for *Intel* architecture.

2. **Identify Key Information:** The code defines a static array `g_hypot_intel_data` of a specific data structure `data_1_2_t<double, double, double>`. Each element in the array appears to represent a test case for the `hypot` function. Each test case contains three doubles, which I can infer are likely input x, input y, and the expected result of `hypot(x, y)`. The negative signs on some inputs and outputs are important to note. The naming convention `hypot_intel_data` strongly suggests this data is used for testing the `hypot` function specifically on Intel architectures.

3. **Focus on the `hypot` Function:**  The filename and variable name explicitly mention `hypot`. My initial thought is that this data file is used for testing the correctness of the `hypot` function implementation within bionic's math library.

4. **Infer the Testing Purpose:**  The structure of the data as a series of inputs and expected outputs points towards a test suite. This data is likely used by a testing framework to verify the `hypot` implementation.

5. **Consider Android Context:**  Since the file path includes "bionic" and "handroid", it's clear this is related to Android's C library. The `hypot` function is a standard math function, and Android needs a correct implementation of it. This data likely ensures the Intel-specific implementation is accurate.

6. **Formulate the High-Level Function:** Based on the above, the primary function is to provide test data for the `hypot` function in Android's bionic math library, specifically targeting Intel architectures.

7. **Address Specific Instructions (Part 1):**

   * **列举一下它的功能 (List its functions):**  This directly translates to the testing purpose. The function is to provide test cases for the `hypot` function.

   * **如果它与android的功能有关系，请做出对应的举例说明 (If it's related to Android's function, give corresponding examples):**  The `hypot` function is a standard C library function used in many Android components and applications. Examples include calculating distances, vector magnitudes in graphics/games, and any scenario involving the square root of the sum of squares.

   * **详细解释每一个libc函数的功能是如何实现的 (Explain in detail how each libc function is implemented):** This instruction is impossible to answer based *solely* on the provided data file. This file *tests* `hypot`, it doesn't *implement* it. I need to state this limitation. I can briefly explain what the `hypot` function *does* (calculates the hypotenuse) but not *how* it's implemented based on this file alone.

   * **对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程 (For functions involving the dynamic linker, give corresponding so layout examples and the linking process):** This data file doesn't directly involve the dynamic linker. It's static test data. I need to state this. Hypot itself, being part of `libc.so`, *is* linked, so I can provide a *general* explanation of dynamic linking and an example of how `libc.so` might be laid out.

   * **如果做了逻辑推理，请给出假设输入与输出 (If logical reasoning is done, give assumed inputs and outputs):** The provided data *is* the input and expected output. I can re-iterate that the structure is input x, input y, and expected `hypot(x, y)`.

   * **如果涉及用户或者编程常见的使用错误，请举例说明 (If it involves common user or programming errors, give examples):**  Common errors with `hypot` (or math functions in general) include passing incorrect data types, expecting integer results when the output is float/double, or not handling potential overflow/underflow (though `hypot` is designed to be more robust against these).

   * **说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤 (Explain how the Android framework or NDK reaches this point step by step, and provide a Frida hook example to debug these steps):**  This requires tracing the execution path. I need to explain that an Android app using `hypot` through the NDK would eventually call the bionic's `hypot` implementation. I can then provide a basic Frida hook example targeting the `hypot` function in `libc.so`.

   * **用中文回复 (Respond in Chinese):**  Ensure the entire response is in Chinese.

   * **这是第1部分，共2部分，请归纳一下它的功能 (This is Part 1 of 2, please summarize its function):** This requires a concise summary of the primary purpose of the data file.

8. **Structure the Response:** Organize the information logically, addressing each point in the prompt. Start with the high-level function and then delve into specifics.

9. **Refine and Elaborate:** Expand on the initial points with more details where necessary. For instance, explain *why* test data is important (ensuring correctness, catching regressions).

10. **Review and Correct:** Double-check the response for accuracy, clarity, and completeness. Ensure the Chinese is natural and grammatically correct. Make sure to explicitly state when an instruction cannot be fully answered based on the provided code alone.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request, while acknowledging the limitations imposed by only having the test data file and not the actual `hypot` implementation.
好的，我们来分析一下 `bionic/tests/math_data/hypot_intel_data.handroid` 这个文件的功能。

**功能归纳：**

这个 C 源代码文件定义了一个静态的、全局的数组 `g_hypot_intel_data`。这个数组包含了大量的测试用例，用于测试 `hypot` 函数在 Android Bionic 库中的实现，并且是针对 Intel 架构优化的版本。  每个数组元素都包含三个 `double` 类型的值，分别代表 `hypot` 函数的两个输入参数以及预期的输出结果。

**详细功能解释：**

1. **提供 `hypot` 函数的测试数据:**  这个文件最主要的功能是提供测试数据。`hypot` 函数用于计算直角三角形的斜边长度，即 `sqrt(x^2 + y^2)`。 数组中的每一项都代表一个特定的测试场景，包含了两个输入值（直角边）以及对应的预期斜边长度。

2. **针对 Intel 架构:** 文件名中的 "intel" 表明这些测试数据可能针对 Intel 架构的特定实现或优化进行了设计。不同的处理器架构可能在浮点数运算的精度和性能上有所差异，因此需要针对特定架构进行测试。

3. **Bionic 库的一部分:** 文件路径 `bionic/tests/math_data/` 明确指出这是 Android Bionic 库中数学库的测试数据。Bionic 是 Android 的 C 库，包含了标准 C 库的实现以及一些 Android 特有的功能。

**与 Android 功能的关系及举例说明：**

`hypot` 函数是标准 C 库的一部分，在 Android 系统和应用开发中被广泛使用。

* **NDK 开发:**  使用 Android NDK 进行原生 C/C++ 开发时，开发者可以直接调用 `hypot` 函数。例如，在开发游戏引擎、图形渲染库或者进行科学计算时，经常需要计算距离或向量的模长，这时就会用到 `hypot` 函数。
    ```c++
    #include <cmath>

    double calculate_distance(double x1, double y1, double x2, double y2) {
      return std::hypot(x2 - x1, y2 - y1);
    }
    ```

* **Android Framework:** 虽然 Android Framework 主要使用 Java 或 Kotlin 编写，但在底层，很多系统服务和组件的实现仍然依赖于原生代码。例如，在处理传感器数据、进行物理模拟或者进行图形计算时，底层的原生代码可能会调用 `hypot` 函数。

* **系统库和组件:** Android 的各种系统库（如 OpenGL ES 库、媒体库等）的实现中，也可能使用到 `hypot` 函数进行计算。

**libc 函数的功能实现：**

`hypot` 函数的实现目标是计算 `sqrt(x^2 + y^2)`，但其实现需要考虑一些特殊情况以提高精度和避免溢出：

* **避免溢出:** 当 `x` 和 `y` 的绝对值非常大时，直接计算 `x^2` 和 `y^2` 可能会导致溢出。`hypot` 的实现通常会先将 `x` 和 `y` 缩放到一个合适的范围内，计算结果后再进行相应的放大，从而避免溢出。

* **处理特殊值:** `hypot` 的实现需要正确处理特殊的浮点数值，如无穷大 (infinity) 和 NaN (Not a Number)。例如，`hypot(infinity, y)` 应该返回 `infinity`。

* **精度优化:**  在不同的数值范围内，可能采用不同的计算方法以保证精度。

**由于我们只看到了测试数据，无法直接了解 Bionic 中 `hypot` 函数的具体实现细节。**  要查看其实现，你需要查看 Bionic 库中 `cmath` 或 `math.h` 相关的源代码文件（通常是 `bionic/libc/math/` 目录下的文件）。

**涉及 dynamic linker 的功能：**

这个数据文件本身不涉及 dynamic linker 的功能。Dynamic linker (在 Android 中通常是 `linker` 或 `linker64`) 的作用是在程序启动时加载共享库 (SO 文件)，并解析和链接程序中使用的符号。

* **SO 布局样本：**  `hypot` 函数通常实现在 `libc.so` 这个共享库中。一个简化的 `libc.so` 布局可能如下：

```
libc.so:
  .text (代码段)
    ...
    hypot:  // hypot 函数的代码
      指令1
      指令2
      ...
    ...
  .data (数据段)
    ...
  .rodata (只读数据段)
    ...
  .dynamic (动态链接信息)
    SONAME: libc.so
    NEEDED: ... (依赖的其他库)
    SYMTAB: ... (符号表)
    STRTAB: ... (字符串表)
    ...
```

* **链接的处理过程：**
    1. **加载:** 当一个应用程序启动并需要使用 `hypot` 函数时，操作系统会加载应用程序的可执行文件。
    2. **依赖解析:** Dynamic linker 会检查应用程序依赖的共享库，发现依赖了 `libc.so`。
    3. **加载共享库:** Dynamic linker 加载 `libc.so` 到内存中。
    4. **符号解析 (Symbol Resolution):** 当应用程序调用 `hypot` 函数时，dynamic linker 会在 `libc.so` 的符号表中查找 `hypot` 符号的地址。
    5. **重定位 (Relocation):**  如果 `hypot` 函数的代码中引用了其他全局变量或函数（例如，`sqrt`），dynamic linker 会根据这些符号在内存中的实际地址来修改 `hypot` 函数的代码。
    6. **绑定 (Binding):** 最终，应用程序中的 `hypot` 函数调用会被绑定到 `libc.so` 中 `hypot` 函数的实际内存地址。

**假设输入与输出 (基于文件内容)：**

文件中的每一项都代表一个测试用例。例如，第一项：

* **假设输入:** `x = 0x1.74334f2872bf324a8b6c0ffaf2f4ee3dp0` (这是一个十六进制浮点数表示) 和 `y = -0x1.0b2502b3f7656p0`
* **预期输出:** `0x1.032a74c8e2bbdp0`

这些十六进制浮点数表示可以直接转换为 `double` 类型进行计算验证。

**用户或编程常见的使用错误：**

* **传递错误的参数类型:**  `hypot` 期望接收 `double` 类型的参数。如果传递了 `int` 或其他不兼容的类型，可能会导致编译错误或运行时错误。
* **误解返回值:** `hypot` 返回的是 `double` 类型的结果。如果将其赋值给 `int` 类型变量，会发生截断。
* **没有包含头文件:** 使用 `hypot` 函数需要包含 `<cmath>` (C++) 或 `<math.h>` (C) 头文件。
* **精度问题:** 虽然 `hypot` 的实现已经考虑了精度，但在某些极端情况下，浮点数运算仍然可能存在精度损失。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例：**

1. **NDK 调用路径:**
   * Android 应用的 Java/Kotlin 代码通过 JNI (Java Native Interface) 调用 Native 代码。
   * Native 代码中包含了对 `std::hypot` 或 `hypot` 函数的调用。
   * 编译时，链接器将 Native 代码链接到 `libc.so`。
   * 运行时，dynamic linker 加载 `libc.so`，并将 Native 代码中的 `hypot` 调用绑定到 `libc.so` 中的实现。

2. **Frida Hook 示例:**

   ```python
   import frida
   import sys

   package_name = "your.app.package.name"  # 替换为你的应用包名

   def on_message(message, data):
       if message['type'] == 'send':
           print(f"[*] {message['payload']}")
       else:
           print(message)

   try:
       session = frida.get_usb_device().attach(package_name)
   except frida.ProcessNotFoundError:
       print(f"应用 {package_name} 未运行，请先启动应用")
       sys.exit()

   script_code = """
   Interceptor.attach(Module.findExportByName("libc.so", "hypot"), {
       onEnter: function(args) {
           console.log("[*] hypot called");
           console.log("arg0 (double): " + args[0]);
           console.log("arg1 (double): " + args[1]);
       },
       onLeave: function(retval) {
           console.log("retval (double): " + retval);
           console.log("[*] hypot returns");
       }
   });
   """

   script = session.create_script(script_code)
   script.on('message', on_message)
   script.load()
   input("Press Enter to detach from the process...\n")
   session.detach()
   ```

   **解释:**

   * 这个 Frida 脚本会附加到指定的 Android 应用程序进程。
   * `Module.findExportByName("libc.so", "hypot")` 用于查找 `libc.so` 中 `hypot` 函数的地址。
   * `Interceptor.attach` 用于拦截对 `hypot` 函数的调用。
   * `onEnter` 函数在 `hypot` 函数被调用时执行，可以访问函数的参数。
   * `onLeave` 函数在 `hypot` 函数返回时执行，可以访问函数的返回值。
   * 运行这个脚本后，当应用程序调用 `hypot` 函数时，Frida 会打印出相关的日志信息，包括输入参数和返回值。

**总结：**

`bionic/tests/math_data/hypot_intel_data.handroid` 文件是 Android Bionic 库中用于测试 `hypot` 函数（特别是 Intel 架构优化版本）的测试数据集合。它包含了大量的输入和预期输出，用于验证 `hypot` 函数实现的正确性。这个文件是 Bionic 库质量保证的重要组成部分。

### 提示词
```
这是目录为bionic/tests/math_data/hypot_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
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

static data_1_2_t<double, double, double> g_hypot_intel_data[] = {
  { // Entry 0
    0x1.74334f2872bf324a8b6c0ffaf2f4ee3dp0,
    -0x1.0b2502b3f7656p0,
    0x1.032a74c8e2bbdp0
  },
  { // Entry 1
    0x1.21c9123e6cbbf812953910371e275dc7p3,
    -0x1.21c9107b0e488p3,
    0x1.ff77fffffffffp-9
  },
  { // Entry 2
    0x1.ad09d0c85a9b738fbeb590492c45108fp-21,
    -0x1.3db5af72d9074p-21,
    0x1.2054976e47184p-21
  },
  { // Entry 3
    0x1.6a1f7b584e052800e5d5eb2c842defa6p-1,
    -0x1.47200db32f88cp-1,
    -0x1.36a049ab1eee0p-2
  },
  { // Entry 4
    0x1.893eff10a04aed61358d3d5b6481eebcp-425,
    -0x1.5a9c9453941a0p-426,
    -0x1.60ff7b7326510p-425
  },
  { // Entry 5
    0x1.94c583ada5b5218962e6ed1568fead12p0,
    -0x1.7ffffffffffffp0,
    0x1.0000000000003p-1
  },
  { // Entry 6
    0x1.97cfe6e25cd448cf5dbcb52213679796p-11,
    -0x1.8e38e38e38e37p-11,
    -0x1.5fad40a57eb38p-13
  },
  { // Entry 7
    0x1.9e661829e5ee17ffba1d22ecf0580873p421,
    -0x1.9897fbb0fa747p418,
    0x1.9b3d45740c34cp421
  },
  { // Entry 8
    0x1.c7653d4e9e6c77fe2eb3fc6720505db6p-11,
    -0x1.bbbbbbbbbbbbcp-11,
    -0x1.9999999999c33p-13
  },
  { // Entry 9
    0x1.ddffe6e5a3a8384016ed35f115bc095ep-11,
    -0x1.e9131abf0b717p-14,
    0x1.da12f684bda24p-11
  },
  { // Entry 10
    0x1.7158b50ca33488012d796eb6f1a7589bp0,
    -0x1.f5723be0cafb4p-1,
    0x1.0f35b6d1e4e0fp0
  },
  { // Entry 11
    0x1.00007fffdffff7ffe2000dfff64007afp0,
    -0x1.ffffffffffffdp-1,
    0x1.ffffffffffffcp-9
  },
  { // Entry 12
    0x1.fffffffep-1043,
    0.0,
    0x1.fffffffe0p-1043
  },
  { // Entry 13
    0x1.199999999999a0p0,
    0x1.0p-1074,
    -0x1.199999999999ap0
  },
  { // Entry 14
    0x1.aaaaaaaaaaaaa0p0,
    0x1.0p-1074,
    -0x1.aaaaaaaaaaaaap0
  },
  { // Entry 15
    0x1.b87065d24cee52b080d32543ca9cfc19p-1,
    0x1.0000000000001p-1,
    -0x1.6666666666668p-1
  },
  { // Entry 16
    0x1.43596ffaa74788558d1fbef5bc6654e5p0,
    0x1.0000000000001p-2,
    -0x1.3cf3cf3cf3cf4p0
  },
  { // Entry 17
    0x1.4ccccccccccd08000000000000627627p-2,
    0x1.0000000000001p-3,
    -0x1.3333333333337p-2
  },
  { // Entry 18
    0x1.801554bda99c72d8de8e8d0810523d56p0,
    0x1.0000000000001p-5,
    0x1.8000000000001p0
  },
  { // Entry 19
    0x1.74b50ce2454308015045eece9494acfbp-3,
    0x1.0000000000001p-7,
    -0x1.745d1745d0e18p-3
  },
  { // Entry 20
    0x1.28ff91ab72d727facf9be8fbd129e05ep-2,
    0x1.0000000000080p-3,
    0x1.0c0p-2
  },
  { // Entry 21
    0x1.000033d5ab09e8017b9fe870280d1247p9,
    0x1.0000000000aeep9,
    0x1.45d1745d1745ep0
  },
  { // Entry 22
    0x1.07e0f670c16e48e1e7c24e5939e31f55p-3,
    0x1.00000009880p-3,
    0x1.ffffff8cfffffp-6
  },
  { // Entry 23
    0x1.b596b5878e25800001094dfd216cf693p-1,
    0x1.00000040ed435p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 24
    0x1.0008ffd80967981d0efdf34de42be658p-4,
    0x1.0000007ffffdep-10,
    0x1.0000fffffffffp-4
  },
  { // Entry 25
    0x1.6a09e8e19116080994af0efbde159838p-20,
    0x1.0000037ffffdfp-20,
    0x1.00000000110p-20
  },
  { // Entry 26
    0x1.00009ec452a8c81c490f9ba38768ce7cp-3,
    0x1.0000043ffffdfp-3,
    0x1.19453808ca296p-11
  },
  { // Entry 27
    0x1.b879b2c3faae37fe5d8254c1a9443fd6p-1,
    0x1.000fffffff6c8p-1,
    -0x1.6666666666668p-1
  },
  { // Entry 28
    0x1.6b9824a5d9fefc6fac3c06f2beba6d16p0,
    0x1.001p0,
    0x1.0222222222223p0
  },
  { // Entry 29
    0x1.6b1dc233c08aacf04d42b3d293e12a49p0,
    0x1.0016f5e74bfddp0,
    -0x1.016eb68415ab1p0
  },
  { // Entry 30
    0x1.778d27690518dd41bd73ad488f2a2174p-27,
    0x1.00a436e9442ddp-27,
    0x1.122dc42e12491p-27
  },
  { // Entry 31
    0x1.6c9ed56d3e093800300f2c229b359a3dp0,
    0x1.01b59372d3dp0,
    -0x1.01f11caa0d8fap0
  },
  { // Entry 32
    0x1.62e44823f6c828019d99f2ea6e42b44dp-1,
    0x1.0624dd41fac87p-10,
    0x1.62e42fefa39efp-1
  },
  { // Entry 33
    0x1.62e44823f6c9980000fc0f85b3c55a79p-1,
    0x1.0624dd49c38c9p-10,
    0x1.62e42fefa39efp-1
  },
  { // Entry 34
    0x1.086b948a12d8c800cf1808a10a5174d9p3,
    0x1.086ac9804c16fp3,
    0x1.47ae147ae1488p-5
  },
  { // Entry 35
    0x1.74334f2872bf324a8b6c0ffaf2f4ee3dp0,
    0x1.0b2502b3f7656p0,
    -0x1.032a74c8e2bbdp0
  },
  { // Entry 36
    0x1.b174e26559df6801e67982110c79e921p0,
    0x1.0dadec75407d1p0,
    0x1.53594d6535950p0
  },
  { // Entry 37
    0x1.0fa6ab587be3f81316d103dd56845189p2,
    0x1.0dc27b7edad61p2,
    -0x1.fffffffffffdfp-2
  },
  { // Entry 38
    0x1.0e00000001e77800795b3317cdb8cf48p-1,
    0x1.0e0p-1,
    0x1.00880p-20
  },
  { // Entry 39
    0x1.1e643a24dde918108702a958a34659bdp1,
    0x1.17261d1fbe70fp1,
    -0x1.0p-1
  },
  { // Entry 40
    0x1.00009ec452a8c81c490f9ba38768ce7cp-3,
    0x1.19453808ca296p-11,
    0x1.0000043ffffdfp-3
  },
  { // Entry 41
    0x1.1f7648cb9c2928102f301b4e2a6da7f8p3,
    0x1.1f6fb7dbedf31p3,
    -0x1.eb851eb851eb2p-4
  },
  { // Entry 42
    0x1.3fc168b1ba65f7fefcba8c51c9dceebep1,
    0x1.333333334955dp1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 43
    0x1.d561dc6bbc69b7fffefd4eef36bb45cep-1,
    0x1.33333336ffb33p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 44
    0x1.b6d63492d208b7fe66769600852b12d8p7,
    0x1.3845636425767p7,
    0x1.34534564561d4p7
  },
  { // Entry 45
    0x1.b6d63492cf6ddfff7a4bf179a9f2d6cap7,
    0x1.3845636425776p7,
    0x1.3453456452673p7
  },
  { // Entry 46
    0x1.853a0d5122cef456b05a1510fbead643p6,
    0x1.3bbd9e1fa27b4p6,
    0x1.c7372b6a514bcp5
  },
  { // Entry 47
    0x1.3fba0ae4ce08b810e8f56ddaf12a7f4fp3,
    0x1.3e1f0f87c3dd1p3,
    -0x1.fffffffffffdfp-1
  },
  { // Entry 48
    0x1.b71be4215a53283d71f5b110a870e894p-11,
    0x1.484e2afe0bbc6p-13,
    -0x1.af5ebd7af5ec0p-11
  },
  { // Entry 49
    0x1.56d07f9feb80d804781ae4305058b676p2,
    0x1.550fe1779c5p2,
    -0x1.14f2805f85d24p-1
  },
  { // Entry 50
    0x1.a52df5c24c89489d50528533a7f35763p2,
    0x1.5555555555556p0,
    0x1.9c71c71c71c69p2
  },
  { // Entry 51
    0x1.b993cc4482b447ff4f74030e8ba14870p-1,
    0x1.57354071c6426p-3,
    -0x1.b1293f6f53880p-1
  },
  { // Entry 52
    0x1.a7e2abc57f0e380a70c24d675241f120p0,
    0x1.5b2d96cb65bp0,
    -0x1.e666666666664p-1
  },
  { // Entry 53
    0x1.e44d26303c8e703260adac35beb0201ap421,
    0x1.600ec23b7b61ep421,
    -0x1.4c92148cef14ap421
  },
  { // Entry 54
    0x1.f8611701969ccfffff045c3f99fe48f7p-1,
    0x1.6666666dac2fap-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 55
    0x1.6cc93c4d65368802345842af2282a5eap1,
    0x1.6cc93a754133ep1,
    0x1.257430139p-10
  },
  { // Entry 56
    0x1.6cc93c4d653688025c9147b5b60441e9p1,
    0x1.6cc93a754133ep1,
    0x1.25743013900c8p-10
  },
  { // Entry 57
    0x1.6cc93c4d653688025e2d2930daa313d5p1,
    0x1.6cc93a754133ep1,
    0x1.25743013900d0p-10
  },
  { // Entry 58
    0x1.d488ac97053f37fbba277d07ac43cad5p-20,
    0x1.7p-20,
    0x1.220p-20
  },
  { // Entry 59
    0x1.400000004cccc800052f1bc6a6c17e88p-1,
    0x1.7ffffffffffffp-2,
    0x1.000000006p-1
  },
  { // Entry 60
    0x1.ffee8df9517ff7fe75600bb975e5ce61p0,
    0x1.81792910a5db1p-1,
    -0x1.da43b5dce0b18p0
  },
  { // Entry 61
    0x1.9b0a5736513fc7ffab037ae75d04e99ap2,
    0x1.88a4522914881p2,
    0x1.e666666666667p0
  },
  { // Entry 62
    0x1.a5fa08a755b5c900f2d5cc6751e1ecf9p2,
    0x1.88cb3c9484e2ap0,
    0x1.9a6449e59bb5dp2
  },
  { // Entry 63
    0x1.8befefed027e87ff6c70308e205c2a19p6,
    0x1.8beea4e1a0873p6,
    -0x1.0p-1
  },
  { // Entry 64
    0x1.96991a72bfd0100000868ffe3e831279p1,
    0x1.8cccccce3bcbdp1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 65
    0x1.bf7cd9d02c7e220c699cc834fdd4fb41p-4,
    0x1.8ddf4152067fcp-4,
    -0x1.999999999999ap-5
  },
  { // Entry 66
    0x1.76e7ba8bc745280094a71daf10d4a68ep25,
    0x1.97fe3896c80f0p2,
    0x1.76e7ba8bc741bp25
  },
  { // Entry 67
    0x1.0efacef2e4e81ffffefe587f1ae783b6p0,
    0x1.999999a0c0a0bp-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 68
    0x1.715e867859a8580001048a1e9e9dff7cp-1,
    0x1.999999b9ce793p-3,
    0x1.62e42fefa39efp-1
  },
  { // Entry 69
    0x1.6690cd7c39fa4800010745dc1f901919p-1,
    0x1.999999da8ed7ap-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 70
    0x1.f65294baeb7788330decefa598e273d5p-11,
    0x1.9dbcc48676f94p-15,
    0x1.f5a814afd6a11p-11
  },
  { // Entry 71
    0x1.c26cb730864d698c82db5769586bd519p0,
    0x1.a2882f7660c18p-2,
    0x1.b61a64501888ap0
  },
  { // Entry 72
    0x1.209f4f2c5979e816bf99efe18e6f1cdap1,
    0x1.b8f22f033c872p-3,
    0x1.1f4db533bcddcp1
  },
  { // Entry 73
    0x1.50225479d4b157fe785588557cc66cdep-10,
    0x1.bd8caaaf99090p-11,
    -0x1.f76b23986ff44p-11
  },
  { // Entry 74
    0x1.060db00245bf781048c529e4efff0afbp25,
    0x1.bffffffffffffp22,
    0x1.0000027ffffdfp25
  },
  { // Entry 75
    0x1.c8c25b45aba168f0187bb5c3abbc3d16p-11,
    0x1.c06b09e919d94p-11,
    -0x1.5b911048a3310p-13
  },
  { // Entry 76
    0x1.f53b21b5c40249b92a9c223bae43323bp0,
    0x1.c81e6f7fe3993p-2,
    -0x1.e8167b6df2ee0p0
  },
  { // Entry 77
    0x1.f5950f056e39e90cbaac1f89ab36b40ap2,
    0x1.cba2e8ba2e8b7p0,
    0x1.e83e0f83e0f76p2
  },
  { // Entry 78
    0x1.ddffe6e5a3a8384016ed35f115bc095ep-11,
    0x1.da12f684bda24p-11,
    -0x1.e9131abf0b717p-14
  },
  { // Entry 79
    0x1.7941bb05a39ca7ff5e4553b1fc4d7db9p-423,
    0x1.f8d7bbd7ce920p-426,
    -0x1.73f0fd4fd9fd0p-423
  },
  { // Entry 80
    0x1.b13fad7cb7c50801dede1905f3f366a1p9,
    0x1.f91b91b91b905p2,
    0x1.b13b13b13b130p9
  },
  { // Entry 81
    0x1.69fd85887947900071fbc08183b8ab23p0,
    0x1.fcf76c540d958p-1,
    -0x1.017098d82f95ep0
  },
  { // Entry 82
    0x1.21c9123e6cbbf812953910371e275dc7p3,
    0x1.ff77fffffffffp-9,
    -0x1.21c9107b0e488p3
  },
  { // Entry 83
    0x1.c66addfec91c411f38e2aacb6ea06a91p-3,
    0x1.ffeffffffffffp-4,
    -0x1.7777777777774p-3
  },
  { // Entry 84
    0x1.4eb522b24186e8254574c77b5f914855p-1,
    0x1.ffeffffffffffp-4,
    0x1.488888888888ap-1
  },
  { // Entry 85
    0x1.002caffe59b0a7feeda747a94b176ccap4,
    0x1.ffeffffffffffp3,
    -0x1.4888888888888p-1
  },
  { // Entry 86
    0x1.fff28f6f00e797fec43eb25e08b861abp3,
    0x1.ffeffffffffffp3,
    -0x1.99999999a7508p-4
  },
  { // Entry 87
    0x1.00000001fffff7fe0007f00400100ff6p20,
    0x1.fffffbfffffffp4,
    0x1.0p20
  },
  { // Entry 88
    0x1.0082de91198ee8170bcff2900895b92ap2,
    0x1.ffffffffffdffp-3,
    0x1.0002fffffffdfp2
  },
  { // Entry 89
    0x1.6a09e667f3c5125ab5042ba7be436cbbp-2,
    0x1.ffffffffffff7p-3,
    0x1.00000000000c0p-2
  },
  { // Entry 90
    0x1.ffffffffffffb0p500,
    0x1.ffffffffffffbp500,
    0x1.ffffffffffffbp-1
  },
  { // Entry 91
    0x1.333574eb66a002798d20bb2ca70862e4p-1,
    0x1.ffffffffffffep-3,
    0x1.1745d1745d177p-1
  },
  { // Entry 92
    0x1.745d1745d17557ffffffffffc41ap-3,
    0x1.ffffffffffffep-28,
    0x1.745d1745d1750p-3
  },
  { // Entry 93
    0x1.00000000000000007fffffffffffefffp1,
    0x1.ffffffffffffep-32,
    -0x1.0p1
  },
  { // Entry 94
    0x1.7777777777780000015d1745d1745c6cp-4,
    0x1.ffffffffffffep-40,
    0x1.7777777777780p-4
  },
  { // Entry 95
    0x1.01c5967e49cb581b1ce389659d8f68ecp2,
    0x1.ffffffffffffep1,
    -0x1.e2be2be2be2c3p-2
  },
  { // Entry 96
    0x1.0058d424f448e820225d2e7a25abc0ebp4,
    0x1.ffffffffffffep3,
    -0x1.aaaaaaaaaaaa8p-1
  },
  { // Entry 97
    0x1.6a09e667f3bcdfa9516192a2b726086dp0,
    -0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 98
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    -0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 99
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    -0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 100
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    -0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 101
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 102
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    -0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 103
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    -0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 104
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    -0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 105
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p0,
    -0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 106
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    -0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 107
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    -0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 108
    0x1.6a09e667f3bcdfa9516192a2b726086dp0,
    -0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 109
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    -0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 110
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 111
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    -0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 112
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p0,
    -0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 113
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    -0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 114
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    -0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 115
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    0x1.fffffffffffffp-1,
    -0x1.0000000000001p0
  },
  { // Entry 116
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    0x1.fffffffffffffp-1,
    -0x1.0p0
  },
  { // Entry 117
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p0,
    0x1.fffffffffffffp-1,
    -0x1.fffffffffffffp-1
  },
  { // Entry 118
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    0x1.0p0,
    -0x1.0000000000001p0
  },
  { // Entry 119
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 120
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    0x1.0p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 121
    0x1.6a09e667f3bcdfa9516192a2b726086dp0,
    0x1.0000000000001p0,
    -0x1.0000000000001p0
  },
  { // Entry 122
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    0x1.0000000000001p0,
    -0x1.0p0
  },
  { // Entry 123
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    0x1.0000000000001p0,
    -0x1.fffffffffffffp-1
  },
  { // Entry 124
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p0,
    0x1.fffffffffffffp-1,
    0x1.fffffffffffffp-1
  },
  { // Entry 125
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    0x1.fffffffffffffp-1,
    0x1.0p0
  },
  { // Entry 126
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    0x1.fffffffffffffp-1,
    0x1.0000000000001p0
  },
  { // Entry 127
    0x1.6a09e667f3bcc3608b617397f77caac1p0,
    0x1.0p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 128
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 129
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    0x1.0p0,
    0x1.0000000000001p0
  },
  { // Entry 130
    0x1.6a09e667f3bcceb0da94b335de1f72d2p0,
    0x1.0000000000001p0,
    0x1.fffffffffffffp-1
  },
  { // Entry 131
    0x1.6a09e667f3bcd459022e5304d10b0412p0,
    0x1.0000000000001p0,
    0x1.0p0
  },
  { // Entry 132
    0x1.6a09e667f3bcdfa9516192a2b726086dp0,
    0x1.0000000000001p0,
    0x1.0000000000001p0
  },
  { // Entry 133
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 134
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 135
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 136
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 137
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 138
    0x1.01fe03f61bad04b1068572febc925ad1p3,
    0x1.0p0,
    0x1.0p3
  },
  { // Entry 139
    0x1.01fe03f61bad04b1068572febc925ad1p3,
    0x1.0p3,
    0x1.0p0
  },
  { // Entry 140
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep3,
    0x1.0p3,
    0x1.0p3
  },
  { // Entry 141
    0x1.00001ffffe00003ffff60001bfffacp9,
    0x1.0p0,
    0x1.0p9
  },
  { // Entry 142
    0x1.000007ffffe00000fffff600006ffffap10,
    0x1.0p0,
    0x1.0p10
  },
  { // Entry 143
    0x1.0007ffe000fff6006ffac041fca62cadp9,
    0x1.0p3,
    0x1.0p9
  },
  { // Entry 144
    0x1.0001fffe0003fff6001bffac0107fca6p10,
    0x1.0p3,
    0x1.0p10
  },
  { // Entry 145
    0x1.p100,
    0x1.0p0,
    0x1.0p100
  },
  { // Entry 146
    0x1.p101,
    0x1.0p0,
    0x1.0p101
  },
  { // Entry 147
    0x1.p100,
    0x1.0p3,
    0x1.0p100
  },
  { // Entry 148
    0x1.p101,
    0x1.0p3,
    0x1.0p101
  },
  { // Entry 149
    0x1.00001ffffe00003ffff60001bfffacp9,
    0x1.0p9,
    0x1.0p0
  },
  { // Entry 150
    0x1.0007ffe000fff6006ffac041fca62cadp9,
    0x1.0p9,
    0x1.0p3
  },
  { // Entry 151
    0x1.000007ffffe00000fffff600006ffffap10,
    0x1.0p10,
    0x1.0p0
  },
  { // Entry 152
    0x1.0001fffe0003fff6001bffac0107fca6p10,
    0x1.0p10,
    0x1.0p3
  },
  { // Entry 153
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep9,
    0x1.0p9,
    0x1.0p9
  },
  { // Entry 154
    0x1.1e3779b97f4a7c15f39cc0605cedc834p10,
    0x1.0p9,
    0x1.0p10
  },
  { // Entry 155
    0x1.1e3779b97f4a7c15f39cc0605cedc834p10,
    0x1.0p10,
    0x1.0p9
  },
  { // Entry 156
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep10,
    0x1.0p10,
    0x1.0p10
  },
  { // Entry 157
    0x1.p100,
    0x1.0p9,
    0x1.0p100
  },
  { // Entry 158
    0x1.p101,
    0x1.0p9,
    0x1.0p101
  },
  { // Entry 159
    0x1.p100,
    0x1.0p10,
    0x1.0p100
  },
  { // Entry 160
    0x1.p101,
    0x1.0p10,
    0x1.0p101
  },
  { // Entry 161
    0x1.p100,
    0x1.0p100,
    0x1.0p0
  },
  { // Entry 162
    0x1.p100,
    0x1.0p100,
    0x1.0p3
  },
  { // Entry 163
    0x1.p101,
    0x1.0p101,
    0x1.0p0
  },
  { // Entry 164
    0x1.p101,
    0x1.0p101,
    0x1.0p3
  },
  { // Entry 165
    0x1.p100,
    0x1.0p100,
    0x1.0p9
  },
  { // Entry 166
    0x1.p100,
    0x1.0p100,
    0x1.0p10
  },
  { // Entry 167
    0x1.p101,
    0x1.0p101,
    0x1.0p9
  },
  { // Entry 168
    0x1.p101,
    0x1.0p101,
    0x1.0p10
  },
  { // Entry 169
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep100,
    0x1.0p100,
    0x1.0p100
  },
  { // Entry 170
    0x1.1e3779b97f4a7c15f39cc0605cedc834p101,
    0x1.0p100,
    0x1.0p101
  },
  { // Entry 171
    0x1.1e3779b97f4a7c15f39cc0605cedc834p101,
    0x1.0p101,
    0x1.0p100
  },
  { // Entry 172
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep101,
    0x1.0p101,
    0x1.0p101
  },
  { // Entry 173
    0x1.ad5336963eefa83d75cf889be3a34d14p2,
    0x1.7ffffffffffffp2,
    0x1.7ffffffffffffp1
  },
  { // Entry 174
    0x1.ad5336963eefabd15a8840999ed93d89p2,
    0x1.7ffffffffffffp2,
    0x1.8p1
  },
  { // Entry 175
    0x1.ad5336963eefaf653f40f8975a2db59ep2,
    0x1.7ffffffffffffp2,
    0x1.8000000000001p1
  },
  { // Entry 176
    0x1.ad5336963eefb68d08b26892d04d4378p2,
    0x1.8p2,
    0x1.7ffffffffffffp1
  },
  { // Entry 177
    0x1.ad5336963eefba20ed6b20908b64ac4ep2,
    0x1.8p2,
    0x1.8p1
  },
  { // Entry 178
    0x1.ad5336963eefbdb4d223d88e469a9cc3p2,
    0x1.8p2,
    0x1.8000000000001p1
  },
  { // Entry 179
    0x1.ad5336963eefc4dc9b954889bd15c17dp2,
    0x1.8000000000001p2,
    0x1.7ffffffffffffp1
  },
  { // Entry 180
    0x1.ad5336963eefc870804e0087780ea2b2p2,
    0x1.8000000000001p2,
    0x1.8p1
  },
  { // Entry 181
    0x1.ad5336963eefcc046506b88533260b87p2,
    0x1.8000000000001p2,
    0x1.8000000000001p1
  },
  { // Entry 182
    0x1.fffffffffffff0p1023,
    0x1.fffffffffffffp1023,
    0.0
  },
  { // Entry 183
    0x1.6a09e667f3bc9bc7762e14ef517466dep-1022,
    0x1.ffffffffffffcp-1023,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 184
    0x1.6a09e667f3bca717c561548d37e9edb3p-1022,
    0x1.ffffffffffffcp-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 185
    0x1.6a09e667f3bcb2681494942b1eb9f701p-1022,
    0x1.ffffffffffffcp-1023,
    0x1.0p-1022
  },
  { // Entry 186
    0x1.6a09e667f3bca717c561548d37e9edb3p-1022,
    0x1.ffffffffffffep-1023,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 187
    0x1.6a09e667f3bcb2681494942b1e04f20ep-1022,
    0x1.ffffffffffffep-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 188
    0x1.6a09e667f3bcbdb863c7d3c9047a78e3p-1022,
    0x1.ffffffffffffep-1023,
    0x1.0p-1022
  },
  { // Entry 189
    0x1.6a09e667f3bcb2681494942b1eb9f701p-1022,
    0x1.0p-1022,
    0x1.ffffffffffffcp-1023
  },
  { // Entry 190
    0x1.6a09e667f3bcbdb863c7d3c9047a78e3p-1022,
    0x1.0p-1022,
    0x1.ffffffffffffep-1023
  },
  { // Entry 191
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1022,
    0x1.0p-1022,
    0x1.0p-1022
  },
  { // Entry 192
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1074,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 193
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p512,
    0x1.fffffffffffffp511,
    0x1.fffffffffffffp511
  },
  { // Entry 194
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p512,
    0x1.fffffffffffffp511,
    0x1.fffffffffffffp511
  },
  { // Entry 195
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p501,
    0x1.fffffffffffffp500,
    0x1.fffffffffffffp500
  },
  { // Entry 196
    0x1.6a09e667f3bcc3608b617397f77caac1p501,
    0x1.fffffffffffffp500,
    0x1.0p501
  },
  { // Entry 197
    0x1.6a09e667f3bcceb0da94b335de1f72d2p501,
    0x1.fffffffffffffp500,
    0x1.0000000000001p501
  },
  { // Entry 198
    0x1.6a09e667f3bcc3608b617397f77caac1p501,
    0x1.0p501,
    0x1.fffffffffffffp500
  },
  { // Entry 199
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep501,
    0x1.0p501,
    0x1.0p501
  },
  { // Entry 200
    0x1.6a09e667f3bcd459022e5304d10b0412p501,
    0x1.0p501,
    0x1.0000000000001p501
  },
  { // Entry 201
    0x1.6a09e667f3bcceb0da94b335de1f72d2p501,
    0x1.0000000000001p501,
    0x1.fffffffffffffp500
  },
  { // Entry 202
    0x1.6a09e667f3bcd459022e5304d10b0412p501,
    0x1.0000000000001p501,
    0x1.0p501
  },
  { // Entry 203
    0x1.6a09e667f3bcdfa9516192a2b726086dp501,
    0x1.0000000000001p501,
    0x1.0000000000001p501
  },
  { // Entry 204
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p-501,
    0x1.fffffffffffffp-502,
    0x1.fffffffffffffp-502
  },
  { // Entry 205
    0x1.6a09e667f3bcc3608b617397f77caac1p-501,
    0x1.fffffffffffffp-502,
    0x1.0p-501
  },
  { // Entry 206
    0x1.6a09e667f3bcceb0da94b335de1f72d2p-501,
    0x1.fffffffffffffp-502,
    0x1.0000000000001p-501
  },
  { // Entry 207
    0x1.6a09e667f3bcc3608b617397f77caac1p-501,
    0x1.0p-501,
    0x1.fffffffffffffp-502
  },
  { // Entry 208
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-501,
    0x1.0p-501,
    0x1.0p-501
  },
  { // Entry 209
    0x1.6a09e667f3bcd459022e5304d10b0412p-501,
    0x1.0p-501,
    0x1.0000000000001p-501
  },
  { // Entry 210
    0x1.6a09e667f3bcceb0da94b335de1f72d2p-501,
    0x1.0000000000001p-501,
    0x1.fffffffffffffp-502
  },
  { // Entry 211
    0x1.6a09e667f3bcd459022e5304d10b0412p-501,
    0x1.0000000000001p-501,
    0x1.0p-501
  },
  { // Entry 212
    0x1.6a09e667f3bcdfa9516192a2b726086dp-501,
    0x1.0000000000001p-501,
    0x1.0000000000001p-501
  },
  { // Entry 213
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.fffffffffffffp-502
  },
  { // Entry 214
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.0p-501
  },
  { // Entry 215
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.0000000000001p-501
  },
  { // Entry 216
    0x1.p501,
    0x1.0p501,
    0x1.fffffffffffffp-502
  },
  { // Entry 217
    0x1.p501,
    0x1.0p501,
    0x1.0p-501
  },
  { // Entry 218
    0x1.p501,
    0x1.0p501,
    0x1.0000000000001p-501
  },
  { // Entry 219
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.fffffffffffffp-502
  },
  { // Entry 220
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.0p-501
  },
  { // Entry 221
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.0000000000001p-501
  },
  { // Entry 222
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    -0x1.0p-1074
  },
  { // Entry 223
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    -0.0
  },
  { // Entry 224
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.0p-1074
  },
  { // Entry 225
    0x1.p501,
    0x1.0p501,
    -0x1.0p-1074
  },
  { // Entry 226
    0x1.p501,
    0x1.0p501,
    -0.0
  },
  { // Entry 227
    0x1.p501,
    0x1.0p501,
    0x1.0p-1074
  },
  { // Entry 228
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    -0x1.0p-1074
  },
  { // Entry 229
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    -0.0
  },
  { // Entry 230
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.0p-1074
  },
  { // Entry 231
    0x1.fffffffffffff0p-502,
    0x1.fffffffffffffp-502,
    -0x1.0p-1074
  },
  { // Entry 232
    0x1.fffffffffffff0p-502,
    0x1.fffffffffffffp-502,
    -0.0
  },
  { // Entry 233
    0x1.fffffffffffff0p-502,
    0x1.fffffffffffffp-502,
    0x1.0p-1074
  },
  { // Entry 234
    0x1.p-501,
    0x1.0p-501,
    -0x1.0p-1074
  },
  { // Entry 235
    0x1.p-501,
    0x1.0p-501,
    -0.0
  },
  { // Entry 236
    0x1.p-501,
    0x1.0p-501,
    0x1.0p-1074
  },
  { // Entry 237
    0x1.00000000000010p-501,
    0x1.0000000000001p-501,
    -0x1.0p-1074
  },
  { // Entry 238
    0x1.00000000000010p-501,
    0x1.0000000000001p-501,
    -0.0
  },
  { // Entry 239
    0x1.00000000000010p-501,
    0x1.0000000000001p-501,
    0x1.0p-1074
  },
  { // Entry 240
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.fffffffffffffp-1
  },
  { // Entry 241
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.0p0
  },
  { // Entry 242
    0x1.fffffffffffff0p500,
    0x1.fffffffffffffp500,
    0x1.0000000000001p0
  },
  { // Entry 243
    0x1.p501,
    0x1.0p501,
    0x1.fffffffffffffp-1
  },
  { // Entry 244
    0x1.p501,
    0x1.0p501,
    0x1.0p0
  },
  { // Entry 245
    0x1.p501,
    0x1.0p501,
    0x1.0000000000001p0
  },
  { // Entry 246
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.fffffffffffffp-1
  },
  { // Entry 247
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.0p0
  },
  { // Entry 248
    0x1.00000000000010p501,
    0x1.0000000000001p501,
    0x1.0000000000001p0
  },
  { // Entry 249
    0x1.fffffffffffff0p-1,
    0x1.fffffffffffffp-502,
    0x1.fffffffffffffp-1
  },
  { // Entry 250
    0x1.p0,
    0x1.fffffffffffffp-502,
    0x1.0p0
  },
  { // Entry 251
    0x1.00000000000010p0,
    0x1.fffffffffffffp-502,
    0x1.0000000000001p0
  },
  { // Entry 252
    0x1.fffffffffffff0p-1,
    0x1.0p-501,
    0x1.fffffffffffffp-1
  },
  { // Entry 253
    0x1.p0,
    0x1.0p-501,
    0x1.0p0
  },
  { // Entry 254
    0x1.00000000000010p0,
    0x1.0p-501,
    0x1.0000000000001p0
  },
  { // Entry 255
    0x1.fffffffffffff0p-1,
    0x1.0000000000001p-501,
    0x1.fffffffffffffp-1
  },
  { // Entry 256
    0x1.p0,
    0x1.0000000000001p-501,
    0x1.0p0
  },
  { // Entry 257
    0x1.00000000000010p0,
    0x1.0000000000001p-501,
    0x1.0000000000001p0
  },
  { // Entry 258
    0x1.fffffffffffff000000000000fffffffp49,
    0x1.fffffffffffffp49,
    0x1.fffffffffffffp-1
  },
  { // Entry 259
    0x1.fffffffffffff0000000000010p49,
    0x1.fffffffffffffp49,
    0x1.0p0
  },
  { // Entry 260
    0x1.fffffffffffff0000000000010p49,
    0x1.fffffffffffffp49,
    0x1.0000000000001p0
  },
  { // Entry 261
    0x1.00000000000000000000000007ffffffp50,
    0x1.0p50,
    0x1.fffffffffffffp-1
  },
  { // Entry 262
    0x1.00000000000000000000000007ffffffp50,
    0x1.0p50,
    0x1.0p0
  },
  { // Entry 263
    0x1.00000000000000000000000008p50,
    0x1.0p50,
    0x1.0000000000001p0
  },
  { // Entry 264
    0x1.00000000000010000000000007ffffffp50,
    0x1.0000000000001p50,
    0x1.fffffffffffffp-1
  },
  { // Entry 265
    0x1.00000000000010000000000007ffffffp50,
    0x1.0000000000001p50,
    0x1.0p0
  },
  { // Entry 266
    0x1.00000000000010000000000008p50,
    0x1.0000000000001p50,
    0x1.0000000000001p0
  },
  { // Entry 267
    0x1.fffffffffffff0000000000003ffffffp50,
    0x1.fffffffffffffp50,
    0x1.fffffffffffffp-1
  },
  { // Entry 268
    0x1.fffffffffffff0000000000004p50,
    0x1.fffffffffffffp50,
    0x1.0p0
  },
  { // Entry 269
    0x1.fffffffffffff0000000000004p50,
    0x1.fffffffffffffp50,
    0x1.0000000000001p0
  },
  { // Entry 270
    0x1.00000000000000000000000001ffffffp51,
    0x1.0p51,
    0x1.fffffffffffffp-1
  },
  { // Entry 271
    0x1.00000000000000000000000001ffffffp51,
    0x1.0p51,
    0x1.0p0
  },
  { // Entry 272
    0x1.00000000000000000000000002p51,
    0x1.0p51,
    0x1.0000000000001p0
  },
  { // Entry 273
    0x1.00000000000010000000000001ffffffp51,
    0x1.0000000000001p51,
    0x1.fffffffffffffp-1
  },
  { // Entry 274
    0x1.00000000000010000000000001ffffffp51,
    0x1.0000000000001p51,
    0x1.0p0
  },
  { // Entry 275
    0x1.00000000000010000000000002p51,
    0x1.0000000000001p51,
    0x1.0000000000001p0
  },
  { // Entry 276
    0x1.fffffffffffff0000000000000ffffffp51,
    0x1.fffffffffffffp51,
    0x1.fffffffffffffp-1
  },
  { // Entry 277
    0x1.fffffffffffff0000000000001p51,
    0x1.fffffffffffffp51,
    0x1.0p0
  },
  { // Entry 278
    0x1.fffffffffffff0000000000001p51,
    0x1.fffffffffffffp51,
    0x1.0000000000001p0
  },
  { // Entry 279
    0x1.000000000000000000000000007fffffp52,
    0x1.0p52,
    0x1.fffffffffffffp-1
  },
  { // Entry 280
    0x1.000000000000000000000000007fffffp52,
    0x1.0p52,
    0x1.0p0
  },
  { // Entry 281
    0x1.0000000000000000000000000080p52,
    0x1.0p52,
    0x1.0000000000001p0
  },
  { // Entry 282
    0x1.000000000000100000000000007fffffp52,
    0x1.0000000000001p52,
    0x1.fffffffffffffp-1
  },
  { // Entry 283
    0x1.000000000000100000000000007fffffp52,
    0x1.0000000000001p52,
    0x1.0p0
  },
  { // Entry 284
    0x1.0000000000001000000000000080p52,
    0x1.0000000000001p52,
    0x1.0000000000001p0
  },
  { // Entry 285
    0x1.fffffffffffff00000000000003fffffp52,
    0x1.fffffffffffffp52,
    0x1.fffffffffffffp-1
  },
  { // Entry 286
    0x1.fffffffffffff000000000000040p52,
    0x1.fffffffffffffp52,
    0x1.0p0
  },
  { // Entry 287
    0x1.fffffffffffff000000000000040p52,
    0x1.fffffffffffffp52,
    0x1.0000000000001p0
  },
  { // Entry 288
    0x1.000000000000000000000000001fffffp53,
    0x1.0p53,
    0x1.fffffffffffffp-1
  },
  { // Entry 289
    0x1.000000000000000000000000001fffffp53,
    0x1.0p53,
    0x1.0p0
  },
  { // Entry 290
    0x1.0000000000000000000000000020p53,
    0x1.0p53,
    0x1.0000000000001p0
  },
  { // Entry 291
    0x1.000000000000100000000000001fffffp53,
    0x1.0000000000001p53,
    0x1.fffffffffffffp-1
  },
  { // Entry 292
    0x1.000000000000100000000000001fffffp53,
    0x1.0000000000001p53,
    0x1.0p0
  },
  { // Entry 293
    0x1.0000000000001000000000000020p53,
    0x1.0000000000001p53,
    0x1.0000000000001p0
  },
  { // Entry 294
    0x1.fffffffffffff00000000000000fffffp53,
    0x1.fffffffffffffp53,
    0x1.fffffffffffffp-1
  },
  { // Entry 295
    0x1.fffffffffffff000000000000010p53,
    0x1.fffffffffffffp53,
    0x1.0p0
  },
  { // Entry 296
    0x1.fffffffffffff000000000000010p53,
    0x1.fffffffffffffp53,
    0x1.0000000000001p0
  },
  { // Entry 297
    0x1.0000000000000000000000000007ffffp54,
    0x1.0p54,
    0x1.fffffffffffffp-1
  },
  { // Entry 298
    0x1.0000000000000000000000000007ffffp54,
    0x1.0p54,
    0x1.0p0
  },
  { // Entry 299
    0x1.0000000000000000000000000008p54,
    0x1.0p54,
    0x1.0000000000001p0
  },
  { // Entry 300
    0x1.0000000000001000000000000007ffffp54,
    0x1.0000000000001p54,
    0x1.fffffffffffffp-1
  },
  { // Entry 301
    0x1.0000000000001000000000000007ffffp54,
    0x1.0000000000001p54,
    0x1.0p0
  },
  { // Entry 302
    0x1.0000000000001000000000000008p54,
    0x1.0000000000001p54,
    0x1.0000000000001p0
  },
  { // Entry 303
    0x1.6a09e667f3bcbdb863c7d3c9044d37a6p-500,
    0x1.fffffffffffffp-501,
    0x1.fffffffffffffp-501
  },
  { // Entry 304
    0x1.6a09e667f3bcc3608b617397f77caac1p-500,
    0x1.fffffffffffffp-501,
    0x1.0p-500
  },
  { // Entry 305
    0x1.6a09e667f3bcceb0da94b335de1f72d2p-500,
    0x1.fffffffffffffp-501,
    0x1.0000000000001p-500
  },
  { // Entry 306
    0x1.6a09e667f3bcc3608b617397f77caac1p-500,
    0x1.0p-500,
    0x1.fffffffffffffp-501
  },
  { // Entry 307
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-500,
    0x1.0p-500,
    0x1.0p-500
  },
```
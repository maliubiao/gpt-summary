Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The primary goal is to analyze the provided C code snippet, which is a data table, and explain its purpose and context within the Android Bionic library. The request has several sub-parts, asking about functionality, relation to Android, libc functions, dynamic linker, logical reasoning, common errors, and how Android reaches this code. Finally, it asks for a summary of the functionality specifically for this first part.

2. **Initial Code Analysis:** I first recognize the code as a static array (`g_atan_intel_data`) of a custom struct type (`data_1_1_t<double, double>`). Each element of the array contains two `double` values. The names of the array and the data type strongly suggest that this data is related to the `atan` (arctangent) mathematical function. The "intel_data" part further suggests that these are likely pre-computed values used for optimization on Intel architectures. The hexadecimal representation of floating-point numbers confirms this.

3. **Infer Functionality:** Based on the array name and data structure, I can infer the primary function: **This file provides test data for the `atan` function in the Bionic math library.**  Each entry likely represents an input value for `atan` and its corresponding expected output. The presence of both positive and negative inputs suggests the test data covers different quadrants of the input domain.

4. **Relate to Android:**  Bionic is the standard C library for Android. The math library within Bionic provides essential mathematical functions used throughout the Android system and by apps developed using the NDK. Therefore, this test data directly contributes to the correctness and robustness of the `atan` function in Android. Examples include graphics rendering, physics simulations, and general-purpose calculations within apps.

5. **Address libc Function Details (Preemptive - as requested for the *whole* file):**  While this specific *file* doesn't implement a libc function, it provides *data* for one. I need to keep in mind that the full request asks for details about how `atan` is implemented. My thought here is to *note* that this file isn't the implementation, but rather supporting data for testing the implementation. I will address the actual `atan` implementation in later parts if provided, or acknowledge its general approximation nature.

6. **Consider Dynamic Linker (Preemptive - as requested for the *whole* file):** Similarly, this data file doesn't directly involve the dynamic linker. The dynamic linker is involved in loading and linking shared libraries (like the math library). I'll note that this file itself isn't a shared object. I'll address the dynamic linker's role in loading the math library in later parts or acknowledge its role in making `atan` available.

7. **Logical Reasoning (Input/Output):** The structure of the array `{input, output}` is a straightforward logical pairing. Given an input `x` (the first `double` in an entry), the expected output of `atan(x)` is the second `double` in the same entry.

8. **Common Usage Errors (Preemptive - as requested for the *whole* file):**  While this data file itself doesn't have usage errors, the *use* of the `atan` function can have errors. I'll think about common errors like passing invalid inputs (though `atan` handles most inputs gracefully), expecting perfect precision (floating-point math has inherent limitations), or using degrees instead of radians (though `atan` works with radians). I will address these in later parts if more code is provided.

9. **Android Framework/NDK Path (Preemptive - as requested for the *whole* file):**  I'll outline a general path. An Android app (Java/Kotlin) might use the NDK to call native code. That native code might use the `atan` function, which resides in the Bionic math library (`libm.so`). The dynamic linker loads `libm.so`, and the `atan` implementation might use data from this file (or a related generated file).

10. **Frida Hook (Preemptive - as requested for the *whole* file):**  I'll consider how to hook the `atan` function using Frida. A simple hook would intercept calls to `atan` and log the input and output. More sophisticated hooks could examine the data being accessed within the `atan` implementation, potentially including looking at this test data (though it might be compiled into the library). I will provide a basic example in later parts.

11. **Focus on Part 1 Summary:**  For this *first part*, I need to summarize the core function of the provided code snippet. The most accurate and concise summary is that it's **test data for the `atan` function within Android's Bionic math library.**

12. **Structure the Response:**  I will organize my response according to the sub-questions in the request, even if some answers are preliminary or acknowledging that the information isn't directly in *this* code snippet. This ensures I address all aspects of the request.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative answer, even for this first part of a larger request. I anticipate refining some of the preemptive answers in subsequent parts as more code is provided.
好的，这是对你提供的代码文件 `bionic/tests/math_data/atan_intel_data.handroid` 的第一部分分析和功能归纳：

**功能归纳（针对提供的代码片段）：**

这个代码文件定义了一个静态的 C++ 数组 `g_atan_intel_data`，该数组包含了用于测试 `atan` (反正切) 函数的数据。更具体地说：

* **测试数据:** 该数组存储了一系列预先计算好的 `atan` 函数的输入和期望输出值。
* **双精度浮点数:**  数据类型为 `data_1_1_t<double, double>`，表明输入和输出都是双精度浮点数 (`double`)。
* **Intel 架构特定:** 文件名中的 `intel_data` 暗示这些数据可能是针对 Intel 架构优化或测试的。 `handroid` 可能表示这是为 Android 平台手动（hand-crafted）创建的数据。
* **覆盖不同输入范围:** 数组中的数据点覆盖了 `atan` 函数输入值的不同范围，包括正数和负数，以及不同的数量级。 这有助于确保 `atan` 函数在各种输入情况下都能正确工作。
* **用于单元测试:**  这种形式的数据通常用于单元测试中，用来验证 `atan` 函数的实现是否符合预期。

**更详细的解释：**

1. **功能:**

   * **存储 `atan` 函数的测试用例:**  每个数组元素都是一个结构体，包含一对 `double` 值。第一个值是 `atan` 函数的输入，第二个值是该输入对应的预期输出。
   * **用于验证 `atan` 函数的正确性:**  测试框架可以使用这些数据来调用 `atan` 函数，并将函数的返回值与数组中存储的期望值进行比较。如果两者之间的差异在可接受的范围内，则认为测试通过。
   * **针对特定架构的优化或测试:**  `atan_intel_data` 的命名暗示这些数据可能特别用于测试或验证在 Intel 架构处理器上的 `atan` 函数实现。这可能是因为不同架构在浮点数运算上可能存在细微差异，需要针对性测试。

2. **与 Android 功能的关系举例:**

   * **图形渲染:** Android 的图形系统（如 Skia）大量使用三角函数，包括 `atan`，来计算角度、旋转和进行各种几何变换。例如，当用户触摸屏幕进行手势操作时，计算滑动角度可能就会用到 `atan`。
   * **传感器数据处理:**  Android 设备上的传感器（如陀螺仪、加速度计）会产生角度和方向信息。在处理这些数据时，可能会使用 `atan` 或 `atan2` 函数进行角度转换和计算。
   * **游戏开发:**  使用 NDK 开发的 Android 游戏经常需要进行复杂的数学运算，`atan` 用于计算物体的运动轨迹、视角方向等。
   * **定位服务:**  计算设备方位、地图上的角度等也可能间接用到基于 `atan` 的计算。

   **例子：** 假设一个 Android 应用需要根据两个触摸点的坐标计算它们之间的连线与水平方向的夹角。这可以使用 `atan2(y2 - y1, x2 - x1)` 来实现，而 `atan2` 的实现通常会依赖于 `atan`。  `atan_intel_data.handroid` 中的数据可以用来测试 `atan` 的实现，确保这个角度计算的准确性。

3. **详细解释 `libc` 函数的功能是如何实现的:**

   **注意：**  `atan_intel_data.handroid` 文件本身 **不包含** `atan` 函数的实现代码。它仅仅是测试数据。

   `atan` 函数的实现通常采用以下方法：

   * **泰勒级数展开:**  当输入值接近 0 时，可以使用泰勒级数展开来近似计算 `atan(x) = x - x^3/3 + x^5/5 - x^7/7 + ...`。
   * **切比雪夫逼近:**  为了提高效率和精度，通常会使用切比雪夫多项式来逼近 `atan` 函数在不同区间的取值。
   * **查表法:**  对于某些特定的输入值，可以预先计算好结果并存储在表中（类似于这里提供的测试数据），直接查表获取结果。但这通常只用于辅助，而非主要的计算方法。
   * **区间缩减:**  利用 `atan` 的性质（例如 `atan(-x) = -atan(x)`，`atan(x) + atan(1/x) = pi/2`），可以将输入值缩减到一个较小的区间，在较小的区间内使用多项式逼近或查表法计算，然后再将结果转换回原始输入对应的结果。
   * **CORDIC 算法:**  在一些嵌入式系统中，可能会使用 CORDIC (Coordinate Rotation Digital Computer) 算法来迭代计算三角函数。

   **假设性解释：** 假设 `bionic` 中 `atan` 的实现使用了区间缩减和切比雪夫逼近。  它可能会先将输入 `x` 缩减到 `[0, 1]` 区间内。然后，使用预先计算好的切比雪夫多项式系数，根据缩减后的 `x` 计算出一个近似值。 `atan_intel_data.handroid` 中的数据可以用来验证这个近似计算在不同输入值下是否足够精确。

4. **对于涉及 dynamic linker 的功能:**

   **注意：**  `atan_intel_data.handroid` 文件本身 **不直接涉及** dynamic linker 的功能。它是一个静态数据文件。

   Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 的主要职责是：

   * **加载共享库 (.so 文件):** 当一个程序需要使用共享库中的函数时，dynamic linker 负责将这些库加载到内存中。
   * **符号解析:**  程序中调用的函数（例如 `atan`）在编译时只是一个符号。Dynamic linker 需要在运行时找到该符号对应的实际内存地址。
   * **重定位:**  共享库中的代码和数据可能需要在加载时调整其内存地址，dynamic linker 负责进行这些调整。

   **SO 布局样本 (libm.so，包含 `atan` 的数学库):**

   ```
   LOAD 0x00000000  0x00000000  r-x  1000   [代码段]
   LOAD 0x00001000  0x00001000  r--  0100   [只读数据段，可能包含常量，例如近似计算的系数]
   LOAD 0x00002000  0x00002000  rw-  0200   [读写数据段]
   ```

   * **链接的处理过程:**
      1. **应用启动:**  当一个 Android 应用启动并调用了使用 `atan` 的代码时。
      2. **查找依赖:**  系统会检查应用的依赖库，发现需要 `libm.so` (或者包含数学函数的其他库)。
      3. **加载库:**  Dynamic linker 在指定的路径（通常是 `/system/lib64` 或 `/vendor/lib64`）中查找 `libm.so`，并将其加载到内存中。
      4. **符号查找:**  当执行到调用 `atan` 的指令时，dynamic linker 会在 `libm.so` 的符号表中查找 `atan` 符号对应的地址。
      5. **重定位:**  如果 `libm.so` 在加载时被加载到非预期地址，dynamic linker 会更新代码中对 `atan` 地址的引用。
      6. **执行:**  程序跳转到 `atan` 函数的实际内存地址执行。

   **与 `atan_intel_data.handroid` 的关系:** 尽管 dynamic linker 不直接处理这个数据文件，但它负责加载包含 `atan` 函数实现的共享库，而 `atan` 的实现可能会使用到类似 `atan_intel_data.handroid` 这样的数据进行测试或甚至作为其实现的一部分（例如，用于某些特殊情况的快速查找）。

5. **逻辑推理，给出假设输入与输出:**

   数组中的每一项都代表一个输入和期望输出的对应关系。

   **假设输入与输出示例:**

   * **输入:** `0x1.0fb06ede9973a00000000000007cc060p-5` (表示浮点数 0.03289999999999999)
   * **输出:** `0x1.0fc9f1fabe658p-5` (表示浮点数 0.032999999999999995)

   这意味着，如果将 `0.03289999999999999` 作为 `atan` 函数的输入，我们期望得到的输出是 `0.032999999999999995`。

   **其他例子:**

   * **输入:** `-0x1.46ac37224353600000000000000f8ab8p-1`
   * **输出:** `-0x1.7ba49f739829fp-1`

   * **输入:** `0x1.921fb54442d18469898cc516ef921439p0`
   * **输出:** `0x1.c35fe0cc9d0e4p99`

6. **如果涉及用户或者编程常见的使用错误，请举例说明:**

   虽然这个数据文件本身不容易产生使用错误，但使用 `atan` 函数时常见的错误包括：

   * **单位错误:**  `atan` 函数的输入和输出通常是弧度。用户可能会错误地使用角度值，导致计算结果不正确。
   * **精度问题:**  浮点数运算存在精度限制。用户可能期望得到非常精确的结果，但由于浮点数的表示方式，结果可能存在微小的误差。
   * **输入范围错误:**  虽然 `atan` 函数对所有实数都有定义，但在某些应用场景中，输入值可能超出预期范围，导致结果不符合逻辑。例如，在计算角度时，输入值可能由于某些错误而变得非常大或非常小。
   * **混淆 `atan` 和 `atan2`:**  `atan(y/x)` 只能返回 `(-pi/2, pi/2)` 范围内的角度，而 `atan2(y, x)` 可以根据 `x` 和 `y` 的符号返回 `(-pi, pi)` 范围内的完整角度。用户可能会在需要完整角度信息时错误地使用 `atan`。

   **例子:**  一个开发者在 Android 应用中使用 `atan` 计算两个触点之间的角度，但忘记将坐标差值 `dy` 和 `dx` 的顺序搞反了，使用了 `atan(dx / dy)` 而不是 `atan(dy / dx)`，导致计算出的角度与预期不符。

7. **说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

   * **Android Framework (Java/Kotlin):**
      1. **应用层调用:**  Android 应用（Java 或 Kotlin 代码）可能需要进行一些数学计算，例如在自定义 View 中绘制图形或处理用户输入。
      2. **NDK 调用 (可选):**  如果性能要求较高，或者需要使用一些底层的库，应用可能会通过 JNI (Java Native Interface) 调用 Native 代码（C/C++）。
   * **NDK (C/C++):**
      1. **调用 `atan` 函数:**  Native 代码中会直接调用 `math.h` 或 `cmath` 头文件中声明的 `atan` 函数。
      2. **链接到 `libm.so`:**  在编译 Native 代码时，链接器会将代码链接到 Android 的数学库 `libm.so`。
      3. **Dynamic Linker 加载:**  当应用运行时，dynamic linker 会加载 `libm.so` 到进程的内存空间。
      4. **`atan` 实现执行:**  当执行到 `atan` 函数调用时，会执行 `libm.so` 中 `atan` 的具体实现。
      5. **测试数据使用 (可能):**  `atan` 的实现内部可能会使用类似 `atan_intel_data.handroid` 这样的测试数据来验证其算法的正确性，或者在某些情况下作为计算的一部分（例如，初始近似值的查找）。

   **Frida Hook 示例:**

   ```python
   import frida
   import sys

   package_name = "your.package.name"  # 替换成你的应用包名

   def on_message(message, data):
       if message['type'] == 'send':
           print("[*] {}".format(message['payload']))
       else:
           print(message)

   session = frida.attach(package_name)

   script_source = """
   Interceptor.attach(Module.findExportByName("libm.so", "atan"), {
       onEnter: function(args) {
           console.log("[+] atan called with argument: " + args[0]);
       },
       onLeave: function(retval) {
           console.log("[+] atan returned: " + retval);
       }
   });
   """

   script = session.create_script(script_source)
   script.on('message', on_message)
   script.load()
   sys.stdin.read()
   ```

   **解释:**

   1. **`frida.attach(package_name)`:**  连接到目标 Android 应用的进程。
   2. **`Module.findExportByName("libm.so", "atan")`:**  在 `libm.so` 库中查找 `atan` 函数的导出地址。
   3. **`Interceptor.attach(...)`:**  拦截对 `atan` 函数的调用。
   4. **`onEnter`:**  在 `atan` 函数被调用之前执行，打印传入的参数。
   5. **`onLeave`:**  在 `atan` 函数执行完毕后执行，打印返回值。

   运行这个 Frida 脚本，当你的 Android 应用调用 `atan` 函数时，你将在 Frida 的控制台看到函数的输入参数和返回值，从而可以调试和观察 `atan` 函数的执行过程。  虽然这个 hook 不会直接显示是否使用了 `atan_intel_data.handroid`，但它可以帮助你验证应用是否以及何时调用了 `atan`，并且可以结合查看 Bionic 的源代码来推断数据的使用情况。

**总结（针对提供的代码片段）:**

`bionic/tests/math_data/atan_intel_data.handroid` 文件包含了用于测试 Android Bionic 库中 `atan` (反正切) 函数实现的数据。它是一个静态数组，存储了 `atan` 函数的输入值以及对应的预期输出值，主要用于单元测试和验证 `atan` 函数在 Intel 架构上的正确性。这个文件本身不包含 `atan` 的实现，也不直接涉及动态链接，但它是保证 Android 底层数学库质量的重要组成部分。

Prompt: 
```
这是目录为bionic/tests/math_data/atan_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共4部分，请归纳一下它的功能

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

static data_1_1_t<double, double> g_atan_intel_data[] = {
  { // Entry 0
    0x1.0fb06ede9973a00000000000007cc060p-5,
    0x1.0fc9f1fabe658p-5
  },
  { // Entry 1
    -0x1.0fb06ede9973a00000000000007cc060p-5,
    -0x1.0fc9f1fabe658p-5
  },
  { // Entry 2
    0x1.1ba1951db1d6dfffffffffffffb8f174p-5,
    0x1.1bbe9c255698dp-5
  },
  { // Entry 3
    -0x1.1ba1951db1d6dfffffffffffffb8f174p-5,
    -0x1.1bbe9c255698dp-5
  },
  { // Entry 4
    0x1.8d8d2d4bd6fa2fffffffffffffb52a01p-5,
    0x1.8ddd25ab90ca1p-5
  },
  { // Entry 5
    -0x1.8d8d2d4bd6fa2fffffffffffffb52a01p-5,
    -0x1.8ddd25ab90ca1p-5
  },
  { // Entry 6
    0x1.52c39ef070cad0000000000000397b8dp-4,
    0x1.5389e6df41979p-4
  },
  { // Entry 7
    -0x1.52c39ef070cad0000000000000397b8dp-4,
    -0x1.5389e6df41979p-4
  },
  { // Entry 8
    0x1.a33f32ac5ceb4ffffffffffffff62c0ep-3,
    0x1.a933fe176b375p-3
  },
  { // Entry 9
    -0x1.a33f32ac5ceb4ffffffffffffff62c0ep-3,
    -0x1.a933fe176b375p-3
  },
  { // Entry 10
    0x1.09544b71ad4a6800000000000013a8d4p-2,
    0x1.0f6e5d9960397p-2
  },
  { // Entry 11
    -0x1.09544b71ad4a6800000000000013a8d4p-2,
    -0x1.0f6e5d9960397p-2
  },
  { // Entry 12
    0x1.46ac37224353600000000000000f8ab8p-1,
    0x1.7ba49f739829fp-1
  },
  { // Entry 13
    -0x1.46ac37224353600000000000000f8ab8p-1,
    -0x1.7ba49f739829fp-1
  },
  { // Entry 14
    -0x1.93d0d4b4b1dee82cea5b0c37054b40e2p-1,
    -0x1.01b28f7519ab5p0
  },
  { // Entry 15
    0x1.93d0d4b4b1dee82cea5b0c37054b40e2p-1,
    0x1.01b28f7519ab5p0
  },
  { // Entry 16
    -0x1.8e373c766a9cb7fff0093d26a3e96fdcp0,
    -0x1.05ffffffff0p6
  },
  { // Entry 17
    0x1.8e373c766a9cb7fff0093d26a3e96fdcp0,
    0x1.05ffffffff0p6
  },
  { // Entry 18
    -0x1.9a66b77f370938283db745fa4d8f6929p-1,
    -0x1.086a05172c159p0
  },
  { // Entry 19
    0x1.9a66b77f370938283db745fa4d8f6929p-1,
    0x1.086a05172c159p0
  },
  { // Entry 20
    -0x1.a1f29496a63eb7fed7941742ac25c0bcp-1,
    -0x1.10556f1497661p0
  },
  { // Entry 21
    0x1.a1f29496a63eb7fed7941742ac25c0bcp-1,
    0x1.10556f1497661p0
  },
  { // Entry 22
    -0x1.a46a24d34e9b282810adb188827a9af1p-1,
    -0x1.12fa0d6901526p0
  },
  { // Entry 23
    0x1.a46a24d34e9b282810adb188827a9af1p-1,
    0x1.12fa0d6901526p0
  },
  { // Entry 24
    -0x1.fd7343117fa575c550dcdff0fd642410p-2,
    -0x1.160dc317bf87cp-1
  },
  { // Entry 25
    0x1.fd7343117fa575c550dcdff0fd642410p-2,
    0x1.160dc317bf87cp-1
  },
  { // Entry 26
    -0x1.abdcc74821485ffb3dce2c471f1d9ccdp-1,
    -0x1.1b2p0
  },
  { // Entry 27
    0x1.abdcc74821485ffb3dce2c471f1d9ccdp-1,
    0x1.1b2p0
  },
  { // Entry 28
    -0x1.1b6b00f64692b8157a322d05add170c4p-2,
    -0x1.22e245c48b894p-2
  },
  { // Entry 29
    0x1.1b6b00f64692b8157a322d05add170c4p-2,
    0x1.22e245c48b894p-2
  },
  { // Entry 30
    -0x1.76f5ddc3a8b508ed9f137dea6b81e90fp0,
    -0x1.2c72f995b1d2ep3
  },
  { // Entry 31
    0x1.76f5ddc3a8b508ed9f137dea6b81e90fp0,
    0x1.2c72f995b1d2ep3
  },
  { // Entry 32
    -0x1.1e00babdefd447d7cd293fd8818ded16p-1,
    -0x1.3fffffffffe01p-1
  },
  { // Entry 33
    0x1.1e00babdefd447d7cd293fd8818ded16p-1,
    0x1.3fffffffffe01p-1
  },
  { // Entry 34
    -0x1.257cf8f86aae37fd89007cddd9fbedadp-1,
    -0x1.4a818adf4d00cp-1
  },
  { // Entry 35
    0x1.257cf8f86aae37fd89007cddd9fbedadp-1,
    0x1.4a818adf4d00cp-1
  },
  { // Entry 36
    -0x1.30ac945137336cee6dcf73db648cfcb8p-1,
    -0x1.5a95192041f9ep-1
  },
  { // Entry 37
    0x1.30ac945137336cee6dcf73db648cfcb8p-1,
    0x1.5a95192041f9ep-1
  },
  { // Entry 38
    -0x1.dfc9b7f9ab42d803453edb4156b22fe0p-1,
    -0x1.5c634cb1dfe6bp0
  },
  { // Entry 39
    0x1.dfc9b7f9ab42d803453edb4156b22fe0p-1,
    0x1.5c634cb1dfe6bp0
  },
  { // Entry 40
    -0x1.6bf3302a984a8a006c4478c0e763fab9p-2,
    -0x1.7c1756ec12b23p-2
  },
  { // Entry 41
    0x1.6bf3302a984a8a006c4478c0e763fab9p-2,
    0x1.7c1756ec12b23p-2
  },
  { // Entry 42
    -0x1.7f747c370c0727fccfb9495ede110579p-5,
    -0x1.7fbc3df2ed276p-5
  },
  { // Entry 43
    0x1.7f747c370c0727fccfb9495ede110579p-5,
    0x1.7fbc3df2ed276p-5
  },
  { // Entry 44
    -0x1.fdda4aef81e8e7fffd547e56ce08f36dp-1,
    -0x1.8b0adc528bce4p0
  },
  { // Entry 45
    0x1.fdda4aef81e8e7fffd547e56ce08f36dp-1,
    0x1.8b0adc528bce4p0
  },
  { // Entry 46
    -0x1.91cf060a572547ff8e8e829b167593fcp0,
    -0x1.962000000000bp9
  },
  { // Entry 47
    0x1.91cf060a572547ff8e8e829b167593fcp0,
    0x1.962000000000bp9
  },
  { // Entry 48
    -0x1.47c28e8c40ec280000020808fdc90264p0,
    -0x1.ac2e0862e543ep1
  },
  { // Entry 49
    0x1.47c28e8c40ec280000020808fdc90264p0,
    0x1.ac2e0862e543ep1
  },
  { // Entry 50
    -0x1.921fb54442d18469898cc516ef921439p0,
    -0x1.c35fe0cc9d0e4p99
  },
  { // Entry 51
    0x1.921fb54442d18469898cc516ef921439p0,
    0x1.c35fe0cc9d0e4p99
  },
  { // Entry 52
    -0x1.fee2431215606f9db22d52fc7e731b98p-6,
    -0x1.ff0caaae31790p-6
  },
  { // Entry 53
    0x1.fee2431215606f9db22d52fc7e731b98p-6,
    0x1.ff0caaae31790p-6
  },
  { // Entry 54
    -0x1.1b6ae5e70d57a0024825b0cee86fd415p0,
    -0x1.ffeffffffffffp0
  },
  { // Entry 55
    0x1.1b6ae5e70d57a0024825b0cee86fd415p0,
    0x1.ffeffffffffffp0
  },
  { // Entry 56
    -0x1.f5aa32d8a6d177fffad61b5dca0be8bfp-3,
    -0x1.fff2007ffffffp-3
  },
  { // Entry 57
    0x1.f5aa32d8a6d177fffad61b5dca0be8bfp-3,
    0x1.fff2007ffffffp-3
  },
  { // Entry 58
    -0x1.f5b39f92578e003ce025445d5448c723p-3,
    -0x1.fffc03fffffffp-3
  },
  { // Entry 59
    0x1.f5b39f92578e003ce025445d5448c723p-3,
    0x1.fffc03fffffffp-3
  },
  { // Entry 60
    0x1.fd5ba9aac2f7f7f74a4ac2f7962ea006p-4,
    0x1.0000000000009p-3
  },
  { // Entry 61
    -0x1.fd5ba9aac2f7f7f74a4ac2f7962ea006p-4,
    -0x1.0000000000009p-3
  },
  { // Entry 62
    0x1.1b6e192ebbe4b3939e676eed13ecdea5p0,
    0x1.0000000000011p1
  },
  { // Entry 63
    -0x1.1b6e192ebbe4b3939e676eed13ecdea5p0,
    -0x1.0000000000011p1
  },
  { // Entry 64
    0x1.fd5ba9aac3301779426a44d6216c0127p-4,
    0x1.00000000001d1p-3
  },
  { // Entry 65
    -0x1.fd5ba9aac3301779426a44d6216c0127p-4,
    -0x1.00000000001d1p-3
  },
  { // Entry 66
    0x1.f5b75f92c8e0a8fdae620b51cd9aff12p-3,
    0x1.00000000007p-2
  },
  { // Entry 67
    -0x1.f5b75f92c8e0a8fdae620b51cd9aff12p-3,
    -0x1.00000000007p-2
  },
  { // Entry 68
    0x1.ffd55bba9d69a8ad651d71aec988dad0p-6,
    0x1.0000000003047p-5
  },
  { // Entry 69
    -0x1.ffd55bba9d69a8ad651d71aec988dad0p-6,
    -0x1.0000000003047p-5
  },
  { // Entry 70
    0x1.911fb5999813a8003c879b1793966ea1p0,
    0x1.0000000020017p8
  },
  { // Entry 71
    -0x1.911fb5999813a8003c879b1793966ea1p0,
    -0x1.0000000020017p8
  },
  { // Entry 72
    0x1.921fb54472d18469850cc517020039a2p-1,
    0x1.000000003p0
  },
  { // Entry 73
    -0x1.921fb54472d18469850cc517020039a2p-1,
    -0x1.000000003p0
  },
  { // Entry 74
    0x1.f5b75f959ae0a8fd6e9ac1e84bceca57p-3,
    0x1.000000018p-2
  },
  { // Entry 75
    -0x1.f5b75f959ae0a8fd6e9ac1e84bceca57p-3,
    -0x1.000000018p-2
  },
  { // Entry 76
    0x1.f5b7671a4f939829143782fc6e124ccap-3,
    0x1.0000040p-2
  },
  { // Entry 77
    -0x1.f5b7671a4f939829143782fc6e124ccap-3,
    -0x1.0000040p-2
  },
  { // Entry 78
    0x1.fd5bb18b417c48ac848521bb0772d9a1p-4,
    0x1.00000400004p-3
  },
  { // Entry 79
    -0x1.fd5bb18b417c48ac848521bb0772d9a1p-4,
    -0x1.00000400004p-3
  },
  { // Entry 80
    0x1.921fc4440248282d290a616b8bd2a40fp-1,
    0x1.00000effbfe72p0
  },
  { // Entry 81
    -0x1.921fc4440248282d290a616b8bd2a40fp-1,
    -0x1.00000effbfe72p0
  },
  { // Entry 82
    0x1.921fcb4efe8b9800001979c3c14ae647p-1,
    0x1.0000160abcad0p0
  },
  { // Entry 83
    -0x1.921fcb4efe8b9800001979c3c14ae647p-1,
    -0x1.0000160abcad0p0
  },
  { // Entry 84
    0x1.fd5d9dd9fe4877fd578f460dcb83a068p-4,
    0x1.0000fe0p-3
  },
  { // Entry 85
    -0x1.fd5d9dd9fe4877fd578f460dcb83a068p-4,
    -0x1.0000fe0p-3
  },
  { // Entry 86
    0x1.1b6fb2c336d49314eac9f9c98fd7e33cp0,
    0x1.00040p1
  },
  { // Entry 87
    -0x1.1b6fb2c336d49314eac9f9c98fd7e33cp0,
    -0x1.00040p1
  },
  { // Entry 88
    0x1.8e200a90cc63080337bb5f472303d0cbp0,
    0x1.000ffffffffe1p6
  },
  { // Entry 89
    -0x1.8e200a90cc63080337bb5f472303d0cbp0,
    -0x1.000ffffffffe1p6
  },
  { // Entry 90
    0x1.924fb0c48ad183a74183edd5362486dfp-1,
    0x1.003p0
  },
  { // Entry 91
    -0x1.924fb0c48ad183a74183edd5362486dfp-1,
    -0x1.003p0
  },
  { // Entry 92
    0x1.fedc5f6aeb98186a3b0d3b954d70911cp-4,
    0x1.00c35e9758e2cp-3
  },
  { // Entry 93
    -0x1.fedc5f6aeb98186a3b0d3b954d70911cp-4,
    -0x1.00c35e9758e2cp-3
  },
  { // Entry 94
    0x1.921fb3466091e7ffbc9b8e5c6d88ce22p0,
    0x1.011p23
  },
  { // Entry 95
    -0x1.921fb3466091e7ffbc9b8e5c6d88ce22p0,
    -0x1.011p23
  },
  { // Entry 96
    0x1.1c2100958558dfff915395a5bfb4e4f7p0,
    0x1.01c1b75a29198p1
  },
  { // Entry 97
    -0x1.1c2100958558dfff915395a5bfb4e4f7p0,
    -0x1.01c1b75a29198p1
  },
  { // Entry 98
    0x1.941da6b976112800ae50a79244b2f00fp-1,
    0x1.01fffp0
  },
  { // Entry 99
    -0x1.941da6b976112800ae50a79244b2f00fp-1,
    -0x1.01fffp0
  },
  { // Entry 100
    0x1.95412c14caec68368d2352262e205e29p-1,
    0x1.032667b38fd63p0
  },
  { // Entry 101
    -0x1.95412c14caec68368d2352262e205e29p-1,
    -0x1.032667b38fd63p0
  },
  { // Entry 102
    0x1.954797156907ffe8d43c56fed8806cbap-1,
    0x1.032ce7209e936p0
  },
  { // Entry 103
    -0x1.954797156907ffe8d43c56fed8806cbap-1,
    -0x1.032ce7209e936p0
  },
  { // Entry 104
    0x1.03fe926deb87dea036ae0e5000a78179p-7,
    0x1.03fff80p-7
  },
  { // Entry 105
    -0x1.03fe926deb87dea036ae0e5000a78179p-7,
    -0x1.03fff80p-7
  },
  { // Entry 106
    0x1.fd61e4326c1e17f9be5c0e96b9e245b5p-3,
    0x1.041391b4f6773p-2
  },
  { // Entry 107
    -0x1.fd61e4326c1e17f9be5c0e96b9e245b5p-3,
    -0x1.041391b4f6773p-2
  },
  { // Entry 108
    0x1.9690e7465847a7ddc153bc6798d1b82bp-1,
    0x1.047b2d5ac8ccbp0
  },
  { // Entry 109
    -0x1.9690e7465847a7ddc153bc6798d1b82bp-1,
    -0x1.047b2d5ac8ccbp0
  },
  { // Entry 110
    0x1.96c8ea639f68cc09d44584196295df93p-1,
    0x1.04b43403953b0p0
  },
  { // Entry 111
    -0x1.96c8ea639f68cc09d44584196295df93p-1,
    -0x1.04b43403953b0p0
  },
  { // Entry 112
    0x1.96c95ba7df84f7fecf841f04a5386a95p-1,
    0x1.04b4a761a073bp0
  },
  { // Entry 113
    -0x1.96c95ba7df84f7fecf841f04a5386a95p-1,
    -0x1.04b4a761a073bp0
  },
  { // Entry 114
    0x1.ff956a68e5f5d7fa26829ba0a3287227p-3,
    0x1.053f96b868b40p-2
  },
  { // Entry 115
    -0x1.ff956a68e5f5d7fa26829ba0a3287227p-3,
    -0x1.053f96b868b40p-2
  },
  { // Entry 116
    0x1.98b0c3c0dd8917febe21b582e45bf32ap-1,
    0x1.06a6fdd8c9be8p0
  },
  { // Entry 117
    -0x1.98b0c3c0dd8917febe21b582e45bf32ap-1,
    -0x1.06a6fdd8c9be8p0
  },
  { // Entry 118
    0x1.e7e3d0910807efff992c7a274fdbed8cp-2,
    0x1.084p-1
  },
  { // Entry 119
    -0x1.e7e3d0910807efff992c7a274fdbed8cp-2,
    -0x1.084p-1
  },
  { // Entry 120
    0x1.09882f0fd878b7fc750c23c0417aa352p-5,
    0x1.09ap-5
  },
  { // Entry 121
    -0x1.09882f0fd878b7fc750c23c0417aa352p-5,
    -0x1.09ap-5
  },
  { // Entry 122
    0x1.a057e3cb74245802b71c5786bd3bf5a9p-1,
    0x1.0ea1281786681p0
  },
  { // Entry 123
    -0x1.a057e3cb74245802b71c5786bd3bf5a9p-1,
    -0x1.0ea1281786681p0
  },
  { // Entry 124
    0x1.a057e3cb7428100cde6242b3bf2d75e7p-1,
    0x1.0ea12817866c0p0
  },
  { // Entry 125
    -0x1.a057e3cb7428100cde6242b3bf2d75e7p-1,
    -0x1.0ea12817866c0p0
  },
  { // Entry 126
    0x1.09544b71ad4a6800000000000013a8d4p-2,
    0x1.0f6e5d9960397p-2
  },
  { // Entry 127
    -0x1.09544b71ad4a6800000000000013a8d4p-2,
    -0x1.0f6e5d9960397p-2
  },
  { // Entry 128
    0x1.921fb4cd9c6767fffffe6051bf1c3fecp0,
    0x1.142c69b7200b4p25
  },
  { // Entry 129
    -0x1.921fb4cd9c6767fffffe6051bf1c3fecp0,
    -0x1.142c69b7200b4p25
  },
  { // Entry 130
    0x1.a908afa5b1d49d450834540fee9c3c24p-1,
    0x1.180p0
  },
  { // Entry 131
    -0x1.a908afa5b1d49d450834540fee9c3c24p-1,
    -0x1.180p0
  },
  { // Entry 132
    0x1.abdcc74821485ffb3dce2c471f1d9ccdp-1,
    0x1.1b2p0
  },
  { // Entry 133
    -0x1.abdcc74821485ffb3dce2c471f1d9ccdp-1,
    -0x1.1b2p0
  },
  { // Entry 134
    0x1.1ffffffffff868000000005c43999999p-22,
    0x1.2p-22
  },
  { // Entry 135
    -0x1.1ffffffffff868000000005c43999999p-22,
    -0x1.2p-22
  },
  { // Entry 136
    0x1.1231f3cf3b64080110ff41eaf08e7f52p-1,
    0x1.2fcf7444bde76p-1
  },
  { // Entry 137
    -0x1.1231f3cf3b64080110ff41eaf08e7f52p-1,
    -0x1.2fcf7444bde76p-1
  },
  { // Entry 138
    0x1.14e89198860627ffffe8602275519490p-1,
    0x1.337d9db6d7c12p-1
  },
  { // Entry 139
    -0x1.14e89198860627ffffe8602275519490p-1,
    -0x1.337d9db6d7c12p-1
  },
  { // Entry 140
    0x1.91eae7e474234800ffed4579e939b69ep0,
    0x1.364a2f134fcc8p10
  },
  { // Entry 141
    -0x1.91eae7e474234800ffed4579e939b69ep0,
    -0x1.364a2f134fcc8p10
  },
  { // Entry 142
    0x1.921fb53da9afc7ff8a7b36e49887a88cp0,
    0x1.3663986f82220p29
  },
  { // Entry 143
    -0x1.921fb53da9afc7ff8a7b36e49887a88cp0,
    -0x1.3663986f82220p29
  },
  { // Entry 144
    0x1.78c56b92f190e84a323bd5804a1c5ba6p0,
    0x1.4210842108420p3
  },
  { // Entry 145
    -0x1.78c56b92f190e84a323bd5804a1c5ba6p0,
    -0x1.4210842108420p3
  },
  { // Entry 146
    0x1.78d751494898372d0fe3af3a7837ff8fp0,
    0x1.42f5ff15ddc08p3
  },
  { // Entry 147
    -0x1.78d751494898372d0fe3af3a7837ff8fp0,
    -0x1.42f5ff15ddc08p3
  },
  { // Entry 148
    0x1.31ce4da037f1542340ee4c61421bba5ap0,
    0x1.43fff80p1
  },
  { // Entry 149
    -0x1.31ce4da037f1542340ee4c61421bba5ap0,
    -0x1.43fff80p1
  },
  { // Entry 150
    0x1.31ce4fc9313474e69b41306d82deceb0p0,
    0x1.440p1
  },
  { // Entry 151
    -0x1.31ce4fc9313474e69b41306d82deceb0p0,
    -0x1.440p1
  },
  { // Entry 152
    0x1.26b3d211bc3faaf8f037dd3421d9f962p-1,
    0x1.4c3a987530ea6p-1
  },
  { // Entry 153
    -0x1.26b3d211bc3faaf8f037dd3421d9f962p-1,
    -0x1.4c3a987530ea6p-1
  },
  { // Entry 154
    0x1.351779f072846800a9bb18d72a79814ep0,
    0x1.5094250942508p1
  },
  { // Entry 155
    -0x1.351779f072846800a9bb18d72a79814ep0,
    -0x1.5094250942508p1
  },
  { // Entry 156
    0x1.58fcecb696d827ec66c4a7bfd8ed327bp-8,
    0x1.58fdbd8ddbbf8p-8
  },
  { // Entry 157
    -0x1.58fcecb696d827ec66c4a7bfd8ed327bp-8,
    -0x1.58fdbd8ddbbf8p-8
  },
  { // Entry 158
    0x1.63398f6da2f1a7fffff2d311886948c5p0,
    0x1.596de8ca11ae6p2
  },
  { // Entry 159
    -0x1.63398f6da2f1a7fffff2d311886948c5p0,
    -0x1.596de8ca11ae6p2
  },
  { // Entry 160
    0x1.3424a0066e6a8d6e3d6901f99034cde1p-1,
    0x1.5faa0cbf48e56p-1
  },
  { // Entry 161
    -0x1.3424a0066e6a8d6e3d6901f99034cde1p-1,
    -0x1.5faa0cbf48e56p-1
  },
  { // Entry 162
    0x1.5ff223a639d5bfce7ae1cfb7516d26adp-6,
    0x1.6p-6
  },
  { // Entry 163
    -0x1.5ff223a639d5bfce7ae1cfb7516d26adp-6,
    -0x1.6p-6
  },
  { // Entry 164
    0x1.345f01cce38c8d8be40cc12c58240e15p-1,
    0x1.600000000018dp-1
  },
  { // Entry 165
    -0x1.345f01cce38c8d8be40cc12c58240e15p-1,
    -0x1.600000000018dp-1
  },
  { // Entry 166
    0x1.367cb24fdff2146a3c6863d233ff09fep-1,
    0x1.632p-1
  },
  { // Entry 167
    -0x1.367cb24fdff2146a3c6863d233ff09fep-1,
    -0x1.632p-1
  },
  { // Entry 168
    0x1.57baeb9c51db490f8249f6679768741fp-2,
    0x1.654p-2
  },
  { // Entry 169
    -0x1.57baeb9c51db490f8249f6679768741fp-2,
    -0x1.654p-2
  },
  { // Entry 170
    0x1.395006b0fd682d86f4a40f69e4dad1f3p-1,
    0x1.675370cc217f1p-1
  },
  { // Entry 171
    -0x1.395006b0fd682d86f4a40f69e4dad1f3p-1,
    -0x1.675370cc217f1p-1
  },
  { // Entry 172
    0x1.695a2c268e1e57ffee0cb8c88986dfefp-12,
    0x1.695a2d168b440p-12
  },
  { // Entry 173
    -0x1.695a2c268e1e57ffee0cb8c88986dfefp-12,
    -0x1.695a2d168b440p-12
  },
  { // Entry 174
    0x1.90b6fc0474fec7fe12f524f1b420b184p0,
    0x1.6b5ad6b5aceb4p7
  },
  { // Entry 175
    -0x1.90b6fc0474fec7fe12f524f1b420b184p0,
    -0x1.6b5ad6b5aceb4p7
  },
  { // Entry 176
    0x1.3b8f3306167a8baa368daae0bf08e86cp0,
    0x1.6c0p1
  },
  { // Entry 177
    -0x1.3b8f3306167a8baa368daae0bf08e86cp0,
    -0x1.6c0p1
  },
  { // Entry 178
    0x1.5f6bae189b51098a86d90c98da4cc877p-2,
    0x1.6de63b148cf0bp-2
  },
  { // Entry 179
    -0x1.5f6bae189b51098a86d90c98da4cc877p-2,
    -0x1.6de63b148cf0bp-2
  },
  { // Entry 180
    0x1.3de18703d42d69f55b3e6c4d1fe5629dp-1,
    0x1.6e30022cb4501p-1
  },
  { // Entry 181
    -0x1.3de18703d42d69f55b3e6c4d1fe5629dp-1,
    -0x1.6e30022cb4501p-1
  },
  { // Entry 182
    0x1.ebe5401364d0c802b6d52ee2cdf2086ep-1,
    0x1.6e3b1e21b27ddp0
  },
  { // Entry 183
    -0x1.ebe5401364d0c802b6d52ee2cdf2086ep-1,
    -0x1.6e3b1e21b27ddp0
  },
  { // Entry 184
    0x1.6310721e8d7bc04e2ae4e8cce87a1ec0p-2,
    0x1.72036f889e86fp-2
  },
  { // Entry 185
    -0x1.6310721e8d7bc04e2ae4e8cce87a1ec0p-2,
    -0x1.72036f889e86fp-2
  },
  { // Entry 186
    0x1.685c82be1d6fa902b238e87716c3bbfbp-2,
    0x1.7803718434620p-2
  },
  { // Entry 187
    -0x1.685c82be1d6fa902b238e87716c3bbfbp-2,
    -0x1.7803718434620p-2
  },
  { // Entry 188
    0x1.68c3b08c20af09be807f598cbca32cb9p-2,
    0x1.78788d320d639p-2
  },
  { // Entry 189
    -0x1.68c3b08c20af09be807f598cbca32cb9p-2,
    -0x1.78788d320d639p-2
  },
  { // Entry 190
    0x1.6b35cbad026009f12d00003f84c29caep-2,
    0x1.7b3fe92e2fd63p-2
  },
  { // Entry 191
    -0x1.6b35cbad026009f12d00003f84c29caep-2,
    -0x1.7b3fe92e2fd63p-2
  },
  { // Entry 192
    0x1.6c4b3610c42b29eabeaa35cc1b8067ecp-2,
    0x1.7c7b80a9d788bp-2
  },
  { // Entry 193
    -0x1.6c4b3610c42b29eabeaa35cc1b8067ecp-2,
    -0x1.7c7b80a9d788bp-2
  },
  { // Entry 194
    0x1.6eed6ff6cd99ca02c4d88c9aa595d5cfp-2,
    0x1.7f7b8c648a650p-2
  },
  { // Entry 195
    -0x1.6eed6ff6cd99ca02c4d88c9aa595d5cfp-2,
    -0x1.7f7b8c648a650p-2
  },
  { // Entry 196
    0x1.7fffffffffffb80000000000184cccccp-25,
    0x1.8p-25
  },
  { // Entry 197
    -0x1.7fffffffffffb80000000000184cccccp-25,
    -0x1.8p-25
  },
  { // Entry 198
    0x1.7fffffffffffc800000000000f4cccccp-25,
    0x1.8000000000001p-25
  },
  { // Entry 199
    -0x1.7fffffffffffc800000000000f4cccccp-25,
    -0x1.8000000000001p-25
  },
  { // Entry 200
    0x1.7fffffffffffd80000000000064cccccp-25,
    0x1.8000000000002p-25
  },
  { // Entry 201
    -0x1.7fffffffffffd80000000000064cccccp-25,
    -0x1.8000000000002p-25
  },
  { // Entry 202
    0x1.f7b9ef3dc65408000005e3f91e816063p-1,
    0x1.80df4b28b5a84p0
  },
  { // Entry 203
    -0x1.f7b9ef3dc65408000005e3f91e816063p-1,
    -0x1.80df4b28b5a84p0
  },
  { // Entry 204
    0x1.90ce0249811008006638702db8ae59e2p0,
    0x1.8421084210846p7
  },
  { // Entry 205
    -0x1.90ce0249811008006638702db8ae59e2p0,
    -0x1.8421084210846p7
  },
  { // Entry 206
    0x1.fb3c57dab5afa80a506e91f92e6a8df9p-1,
    0x1.86a71395bc9b5p0
  },
  { // Entry 207
    -0x1.fb3c57dab5afa80a506e91f92e6a8df9p-1,
    -0x1.86a71395bc9b5p0
  },
  { // Entry 208
    0x1.68d94312ca7f17ffeed1dd16ec2d35e6p0,
    0x1.898p2
  },
  { // Entry 209
    -0x1.68d94312ca7f17ffeed1dd16ec2d35e6p0,
    -0x1.898p2
  },
  { // Entry 210
    0x1.ff69d0cefa8a27ebf8cbf5ec1cc78342p-1,
    0x1.8db18047c8944p0
  },
  { // Entry 211
    -0x1.ff69d0cefa8a27ebf8cbf5ec1cc78342p-1,
    -0x1.8db18047c8944p0
  },
  { // Entry 212
    0x1.983e285453b3f000002efc9d654c6a32p-4,
    0x1.999999c022342p-4
  },
  { // Entry 213
    -0x1.983e285453b3f000002efc9d654c6a32p-4,
    -0x1.999999c022342p-4
  },
  { // Entry 214
    0x1.94441feb7be7180000005c46362b16d8p-3,
    0x1.999999f951960p-3
  },
  { // Entry 215
    -0x1.94441feb7be7180000005c46362b16d8p-3,
    -0x1.999999f951960p-3
  },
  { // Entry 216
    0x1.9a6a8e96c86047fffe94ba49799c011fp-3,
    0x1.9ffffffffffddp-3
  },
  { // Entry 217
    -0x1.9a6a8e96c86047fffe94ba49799c011fp-3,
    -0x1.9ffffffffffddp-3
  },
  { // Entry 218
    0x1.9e94153cfe4dc80036c037e172b7cee9p-4,
    0x1.a0000000008p-4
  },
  { // Entry 219
    -0x1.9e94153cfe4dc80036c037e172b7cee9p-4,
    -0x1.a0000000008p-4
  },
  { // Entry 220
    0x1.9fd8a4d9973e57fc465de41ddc4cbae2p-4,
    0x1.a147eb4c17006p-4
  },
  { // Entry 221
    -0x1.9fd8a4d9973e57fc465de41ddc4cbae2p-4,
    -0x1.a147eb4c17006p-4
  },
  { // Entry 222
    0x1.62e23d7da5f6d8010d5496a08573e188p-1,
    0x1.a94678821f0e9p-1
  },
  { // Entry 223
    -0x1.62e23d7da5f6d8010d5496a08573e188p-1,
    -0x1.a94678821f0e9p-1
  },
  { // Entry 224
    0x1.096fe22081e2b800007e36c682109058p0,
    0x1.b102342163952p0
  },
  { // Entry 225
    -0x1.096fe22081e2b800007e36c682109058p0,
    -0x1.b102342163952p0
  },
  { // Entry 226
    0x1.0a471736b923b1f18885a17308e12beep0,
    0x1.b445c1ad3cad1p0
  },
  { // Entry 227
    -0x1.0a471736b923b1f18885a17308e12beep0,
    -0x1.b445c1ad3cad1p0
  },
  { // Entry 228
    0x1.0a66d6f646e8d37662253bd9155a84dep0,
    0x1.b4c1d0c10cca9p0
  },
  { // Entry 229
    -0x1.0a66d6f646e8d37662253bd9155a84dep0,
    -0x1.b4c1d0c10cca9p0
  },
  { // Entry 230
    0x1.a3ad60e89da8b6f1dd20c69213b7612ap-2,
    0x1.bcde6f379bcdep-2
  },
  { // Entry 231
    -0x1.a3ad60e89da8b6f1dd20c69213b7612ap-2,
    -0x1.bcde6f379bcdep-2
  },
  { // Entry 232
    0x1.0e04a23e7337930371d81f0cf4d7e9dcp0,
    0x1.c34p0
  },
  { // Entry 233
    -0x1.0e04a23e7337930371d81f0cf4d7e9dcp0,
    -0x1.c34p0
  },
  { // Entry 234
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.c77250c52a4c4p994
  },
  { // Entry 235
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.c77250c52a4c4p994
  },
  { // Entry 236
    0x1.ad00f5422058b7f130ce2474b9fbbdf8p-2,
    0x1.c80p-2
  },
  { // Entry 237
    -0x1.ad00f5422058b7f130ce2474b9fbbdf8p-2,
    -0x1.c80p-2
  },
  { // Entry 238
    0x1.4c50697afe3227fd6af96ad804191fc4p0,
    0x1.c9b26c9b26cb2p1
  },
  { // Entry 239
    -0x1.4c50697afe3227fd6af96ad804191fc4p0,
    -0x1.c9b26c9b26cb2p1
  },
  { // Entry 240
    0x1.c287b5672b66d828ebaf4756e4f60ad1p-3,
    0x1.c9f0f1fe648bfp-3
  },
  { // Entry 241
    -0x1.c287b5672b66d828ebaf4756e4f60ad1p-3,
    -0x1.c9f0f1fe648bfp-3
  },
  { // Entry 242
    0x1.ce35e40b0af2980007f47f44f1179e69p-5,
    0x1.ceb39ce739ce2p-5
  },
  { // Entry 243
    -0x1.ce35e40b0af2980007f47f44f1179e69p-5,
    -0x1.ceb39ce739ce2p-5
  },
  { // Entry 244
    0x1.ca5072830899e807a46fd46deed06c13p-3,
    0x1.d21f1bc07ff10p-3
  },
  { // Entry 245
    -0x1.ca5072830899e807a46fd46deed06c13p-3,
    -0x1.d21f1bc07ff10p-3
  },
  { // Entry 246
    0x1.d757ad6321e1b7ff10e2bc2deea40152p-7,
    0x1.d76p-7
  },
  { // Entry 247
    -0x1.d757ad6321e1b7ff10e2bc2deea40152p-7,
    -0x1.d76p-7
  },
  { // Entry 248
    0x1.bc568fd6eb58f751409b945717d9554ap-2,
    0x1.da8p-2
  },
  { // Entry 249
    -0x1.bc568fd6eb58f751409b945717d9554ap-2,
    -0x1.da8p-2
  },
  { // Entry 250
    0x1.dcb58cdb206477fea2ac612eafe90af0p-6,
    0x1.dcd80p-6
  },
  { // Entry 251
    -0x1.dcb58cdb206477fea2ac612eafe90af0p-6,
    -0x1.dcd80p-6
  },
  { // Entry 252
    0x1.4fefc9638a79f51094053a972023f6c2p0,
    0x1.e3fffffffffffp1
  },
  { // Entry 253
    -0x1.4fefc9638a79f51094053a972023f6c2p0,
    -0x1.e3fffffffffffp1
  },
  { // Entry 254
    0x1.e559f77b3d1bc7fe0f0af62001c4d64ap-4,
    0x1.e7a2c68ca3bbep-4
  },
  { // Entry 255
    -0x1.e559f77b3d1bc7fe0f0af62001c4d64ap-4,
    -0x1.e7a2c68ca3bbep-4
  },
  { // Entry 256
    0x1.507316595911cbbe475d6a0d0c879007p0,
    0x1.e7f3f9fcfe780p1
  },
  { // Entry 257
    -0x1.507316595911cbbe475d6a0d0c879007p0,
    -0x1.e7f3f9fcfe780p1
  },
  { // Entry 258
    0x1.df110864c9d9d03004ee274a70c0ae22p-3,
    0x1.e7fffffffffffp-3
  },
  { // Entry 259
    -0x1.df110864c9d9d03004ee274a70c0ae22p-3,
    -0x1.e7fffffffffffp-3
  },
  { // Entry 260
    0x1.7145eac2088a38096a1a13357d2f5f02p0,
    0x1.fp2
  },
  { // Entry 261
    -0x1.7145eac2088a38096a1a13357d2f5f02p0,
    -0x1.fp2
  },
  { // Entry 262
    0x1.f2d88602d915b7a920d38c9f9cff16e8p-6,
    0x1.f30p-6
  },
  { // Entry 263
    -0x1.f2d88602d915b7a920d38c9f9cff16e8p-6,
    -0x1.f30p-6
  },
  { // Entry 264
    0x1.f8cda64a08edafa2039d9d8a93546545p-6,
    0x1.f8f68ec9e17eep-6
  },
  { // Entry 265
    -0x1.f8cda64a08edafa2039d9d8a93546545p-6,
    -0x1.f8f68ec9e17eep-6
  },
  { // Entry 266
    0x1.8e1199d0ffd197fffe93ecafbc7df2e1p0,
    0x1.f8ffffeffffaep5
  },
  { // Entry 267
    -0x1.8e1199d0ffd197fffe93ecafbc7df2e1p0,
    -0x1.f8ffffeffffaep5
  },
  { // Entry 268
    0x1.efc20ff0ea4347fb09f751f06225cf3ep-3,
    0x1.f9ac87c22c381p-3
  },
  { // Entry 269
    -0x1.efc20ff0ea4347fb09f751f06225cf3ep-3,
    -0x1.f9ac87c22c381p-3
  },
  { // Entry 270
    0x1.fa55579e0ba577fe929dc83eb7995abcp-6,
    0x1.fa7e9fa7e9f89p-6
  },
  { // Entry 271
    -0x1.fa55579e0ba577fe929dc83eb7995abcp-6,
    -0x1.fa7e9fa7e9f89p-6
  },
  { // Entry 272
    0x1.fa55579e0ba6f7a0b740d8dad80c76dep-6,
    0x1.fa7e9fa7e9fa1p-6
  },
  { // Entry 273
    -0x1.fa55579e0ba6f7a0b740d8dad80c76dep-6,
    -0x1.fa7e9fa7e9fa1p-6
  },
  { // Entry 274
    0x1.fdb067638eb577993194616b1f02253ep-6,
    0x1.fdda82fef66eep-6
  },
  { // Entry 275
    -0x1.fdb067638eb577993194616b1f02253ep-6,
    -0x1.fdda82fef66eep-6
  },
  { // Entry 276
    0x1.f58a3225d517f7b85d014640f929635dp-3,
    0x1.ffcffffffffffp-3
  },
  { // Entry 277
    -0x1.f58a3225d517f7b85d014640f929635dp-3,
    -0x1.ffcffffffffffp-3
  },
  { // Entry 278
    0x1.f5a8507ca2e7f74fe8389718208bcb16p-3,
    0x1.ffeffffffffffp-3
  },
  { // Entry 279
    -0x1.f5a8507ca2e7f74fe8389718208bcb16p-3,
    -0x1.ffeffffffffffp-3
  },
  { // Entry 280
    0x1.1b6ae5e70d57a0024825b0cee86fd415p0,
    0x1.ffeffffffffffp0
  },
  { // Entry 281
    -0x1.1b6ae5e70d57a0024825b0cee86fd415p0,
    -0x1.ffeffffffffffp0
  },
  { // Entry 282
    0x1.822487e434a688433f85f4d9d59f5c91p0,
    0x1.ffeffffffffffp3
  },
  { // Entry 283
    -0x1.822487e434a688433f85f4d9d59f5c91p0,
    -0x1.ffeffffffffffp3
  },
  { // Entry 284
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fff8e61eadcf7p1021
  },
  { // Entry 285
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fff8e61eadcf7p1021
  },
  { // Entry 286
    0x1.f5b39f92578e003ce025445d5448c723p-3,
    0x1.fffc03fffffffp-3
  },
  { // Entry 287
    -0x1.f5b39f92578e003ce025445d5448c723p-3,
    -0x1.fffc03fffffffp-3
  },
  { // Entry 288
    0x1.1b6e0f9521925801d32b4375d240e5b1p0,
    0x1.ffffcffffffffp0
  },
  { // Entry 289
    -0x1.1b6e0f9521925801d32b4375d240e5b1p0,
    -0x1.ffffcffffffffp0
  },
  { // Entry 290
    0x1.f5b75ded226447fe90c6cb904987f275p-3,
    0x1.fffffe3ffffbfp-3
  },
  { // Entry 291
    -0x1.f5b75ded226447fe90c6cb904987f275p-3,
    -0x1.fffffe3ffffbfp-3
  },
  { // Entry 292
    0x1.8a205fd5287ff7ff262bad6513207543p0,
    0x1.fffffff3fffffp4
  },
  { // Entry 293
    -0x1.8a205fd5287ff7ff262bad6513207543p0,
    -0x1.fffffff3fffffp4
  },
  { // Entry 294
    0x1.ffd55bba962df799aa0c3a5a5edf7631p-6,
    0x1.fffffffffecb6p-6
  },
  { // Entry 295
    -0x1.ffd55bba962df799aa0c3a5a5edf7631p-6,
    -0x1.fffffffffecb6p-6
  },
  { // Entry 296
    0x1.ffd55bba972df799aa0c3a87739a477dp-6,
    0x1.ffffffffffcbap-6
  },
  { // Entry 297
    -0x1.ffd55bba972df799aa0c3a87739a477dp-6,
    -0x1.ffffffffffcbap-6
  },
  { // Entry 298
    0x1.dac670561bb3768adfc88bd930751a06p-2,
    0x1.fffffffffffe2p-2
  },
  { // Entry 299
    -0x1.dac670561bb3768adfc88bd930751a06p-2,
    -0x1.fffffffffffe2p-2
  },
  { // Entry 300
    0x1.8a205fd55873f800459be65852624b5fp0,
    0x1.ffffffffffff3p4
  },
  { // Entry 301
    -0x1.8a205fd55873f800459be65852624b5fp0,
    -0x1.ffffffffffff3p4
  },
  { // Entry 302
    0x1.fffff55555bb3bb73172cf8cfdef50f9p-11,
    0x1.ffffffffffff8p-11
  },
  { // Entry 303
    -0x1.fffff55555bb3bb73172cf8cfdef50f9p-11,
    -0x1.ffffffffffff8p-11
  },
  { // Entry 304
    0x1.f5b75f92c80db80cbd711fcdd109b918p-3,
    0x1.ffffffffffffep-3
  },
  { // Entry 305
    -0x1.f5b75f92c80db80cbd711fcdd109b918p-3,
    -0x1.ffffffffffffep-3
  },
  { // Entry 306
    0x1.ffffffffffffb5555555555563bbbbbbp-26,
    0x1.ffffffffffffep-26
  },
  { // Entry 307
    -0x1.ffffffffffffb5555555555563bbbbbbp-26,
    -0x1.ffffffffffffep-26
  },
  { // Entry 308
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 309
    0.0,
    0x1.0p-1074
  },
  { // Entry 310
    -0.0,
    -0.0
  },
  { // Entry 311
    0.0,
    0x1.0p-1074
  },
  { // Entry 312
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 313
    -0x1.0000000000000fffffffffffffffffffp-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 314
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 315
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    -0x1.0p-1022
  },
  { // Entry 316
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.0p-1022
  },
  { // Entry 317
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 318
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 319
    0x1.ffffffffffffdfffffffffffffffffffp-1023,
    0x1.ffffffffffffep-1023
  },
  { // Entry 320
    -0x1.ffffffffffffdfffffffffffffffffffp-1023,
    -0x1.ffffffffffffep-1023
  },
  { // Entry 321
    0x1.ffffffffffffffffffffffffffffffffp-1023,
    0x1.0p-1022
  },
  { // Entry 322
    -0x1.ffffffffffffffffffffffffffffffffp-1023,
    -0x1.0p-1022
  },
  { // Entry 323
    0x1.0000000000000fffffffffffffffffffp-1022,
    0x1.0000000000001p-1022
  },
  { // Entry 324
    -0x1.0000000000000fffffffffffffffffffp-1022,
    -0x1.0000000000001p-1022
  },
  { // Entry 325
    0x1.9999994237fab1da64992a310312505ep-13,
    0x1.999999999999ap-13
  },
  { // Entry 326
    -0x1.9999994237fab1da64992a310312505ep-13,
    -0x1.999999999999ap-13
  },
  { // Entry 327
    0x1.9999983c131f7a10c5dd5d6e7ce3cb81p-12,
    0x1.999999999999ap-12
  },
  { // Entry 328
    -0x1.9999983c131f7a10c5dd5d6e7ce3cb81p-12,
    -0x1.999999999999ap-12
  },
  { // Entry 329
    0x1.333330e560498c727e4d6265bd2ffec8p-11,
    0x1.3333333333334p-11
  },
  { // Entry 330
    -0x1.333330e560498c727e4d6265bd2ffec8p-11,
    -0x1.3333333333334p-11
  },
  { // Entry 331
    0x1.999994237fca32b5a26ff8f7d9bd8d35p-11,
    0x1.999999999999ap-11
  },
  { // Entry 332
    -0x1.999994237fca32b5a26ff8f7d9bd8d35p-11,
    -0x1.999999999999ap-11
  },
  { // Entry 333
    0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    0x1.0p-10
  },
  { // Entry 334
    -0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    -0x1.0p-10
  },
  { // Entry 335
    0x1.333329fbe7ebeef09e51711b44f86539p-10,
    0x1.3333333333333p-10
  },
  { // Entry 336
    -0x1.333329fbe7ebeef09e51711b44f86539p-10,
    -0x1.3333333333333p-10
  },
  { // Entry 337
    0x1.666657c3edf5fc60e8ee22a4cfe0569cp-10,
    0x1.6666666666666p-10
  },
  { // Entry 338
    -0x1.666657c3edf5fc60e8ee22a4cfe0569cp-10,
    -0x1.6666666666666p-10
  },
  { // Entry 339
    0x1.999983c133ee81d417cae21e440492ffp-10,
    0x1.9999999999999p-10
  },
  { // Entry 340
    -0x1.999983c133ee81d417cae21e440492ffp-10,
    -0x1.9999999999999p-10
  },
  { // Entry 341
    0x1.ccccadb230d5be2055f8f3b668d57c61p-10,
    0x1.cccccccccccccp-10
  },
  { // Entry 342
    -0x1.ccccadb230d5be2055f8f3b668d57c61p-10,
    -0x1.cccccccccccccp-10
  },
  { // Entry 343
    0x1.0664f6d5e1b55939fa39d3978354fb08p-7,
    0x1.0666666666666p-7
  },
  { // Entry 344
    -0x1.0664f6d5e1b55939fa39d3978354fb08p-7,
    -0x1.0666666666666p-7
  },
  { // Entry 345
    0x1.ccc506615256b4d660acbe5536614bc0p-7,
    0x1.cccccccccccccp-7
  },
  { // Entry 346
    -0x1.ccc506615256b4d660acbe5536614bc0p-7,
    -0x1.cccccccccccccp-7
  },
  { // Entry 347
    0x1.498e385e62b42d40708322b65b9a92a2p-6,
    0x1.4999999999999p-6
  },
  { // Entry 348
    -0x1.498e385e62b42d40708322b65b9a92a2p-6,
    -0x1.4999999999999p-6
  },
  { // Entry 349
    0x1.acb3bf2888fd253cde72a65ff6b5a5edp-6,
    0x1.accccccccccccp-6
  },
  { // Entry 350
    -0x1.acb3bf2888fd253cde72a65ff6b5a5edp-6,
    -0x1.accccccccccccp-6
  },
  { // Entry 351
    0x1.07e89e3abee7df5bc22b883856e5d802p-5,
    0x1.080p-5
  },
  { // Entry 352
    -0x1.07e89e3abee7df5bc22b883856e5d802p-5,
    -0x1.080p-5
  },
  { // Entry 353
    0x1.39726b096afb5657f037d44ceabacfdep-5,
    0x1.399999999999ap-5
  },
  { // Entry 354
    -0x1.39726b096afb5657f037d44ceabacfdep-5,
    -0x1.399999999999ap-5
  },
  { // Entry 355
    0x1.6af659752a8e90e79823616d18922d06p-5,
    0x1.6b33333333334p-5
  },
  { // Entry 356
    -0x1.6af659752a8e90
"""


```
Response:
Let's break down the thought process for analyzing this C code snippet and generating the summary.

**1. Initial Understanding of the File's Purpose:**

The prompt explicitly states: "这是目录为bionic/tests/math_data/atan2_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker."  This immediately tells us several key things:

* **Location:**  It's part of the Android Bionic library, specifically within the testing framework, under math data.
* **Purpose:** The filename `atan2_intel_data.handroid` strongly suggests this file contains data related to the `atan2` function. The `_intel_data` part further implies it might be specific to Intel architectures or testing data generated on Intel. The `.handroid` extension is likely a custom extension used within the Bionic test suite.
* **Data Format:** The code itself confirms this. It declares a static array `g_atan2_intel_data` of type `data_1_2_t<double, double, double>`. This indicates a collection of test cases for `atan2`, where each test case likely provides input values and the expected output.

**2. Analyzing the Data Structure (`data_1_2_t`):**

While the definition of `data_1_2_t` isn't provided in this snippet, the way the array is initialized gives us a strong clue. Each element in the array is initialized with three floating-point numbers. Given the context of `atan2`, it's highly probable that:

* The first `double` is the `y` input to `atan2(y, x)`.
* The second `double` is the `x` input to `atan2(y, x)`.
* The third `double` is the expected result of `atan2(y, x)`.

The comments like "// Entry 0", "// Entry 1", etc., simply enumerate the test cases.

**3. Inferring the File's Functionality:**

Based on the above analysis, the primary function of this file is clearly to provide a set of test data for the `atan2` function in Bionic's math library. This data is likely used by test programs to verify the correctness and accuracy of the `atan2` implementation, especially on Intel architectures.

**4. Connecting to Android Functionality:**

The `atan2` function itself is a standard mathematical function, but its presence in Bionic is crucial for various Android components and applications. Any Android code that needs to calculate the angle of a vector or perform coordinate transformations would likely use `atan2`. Examples include:

* **Graphics and UI:** Determining the angle of rotation for animations or touch events.
* **Sensors:** Calculating the orientation based on accelerometer and magnetometer readings.
* **Location Services:** Converting between Cartesian and polar coordinates.
* **Game Development:** Implementing character movement and object interactions.

**5. Considering Other Aspects (Even if Not Explicitly Asked in the *Summary*):**

Even though the prompt only asks for a summary in this first part, it's helpful to mentally note potential areas for the subsequent parts:

* **`libc` Function Implementation:**  The `atan2` function is part of `libm` (the math library), which is part of `libc`. The actual implementation of `atan2` would involve numerical algorithms (like Taylor series expansions, CORDIC, or lookup tables).
* **Dynamic Linker:**  When an Android app uses `atan2`, the dynamic linker (`linker64` or `linker`) is responsible for loading `libm.so` into the process's memory and resolving the symbol for `atan2`.
* **Error Handling:**  Common errors when using `atan2` involve passing invalid inputs (like NaN or infinity), or misunderstanding the order of arguments (it's `atan2(y, x)`, not `atan2(x, y)`).
* **Android Framework/NDK Interaction:**  Applications using the NDK can directly call `atan2`. Framework components might use it indirectly through other APIs.
* **Frida Hooking:** Frida can be used to intercept calls to `atan2` to inspect arguments and return values for debugging.

**6. Drafting the Summary (Focusing on the Request):**

Now, focusing on the "归纳一下它的功能" (summarize its functionality) requirement:

* Start with the core purpose: "这个C源代码文件定义了一个名为 `g_atan2_intel_data` 的静态数组。"
* Explain the array's contents: "这个数组的元素类型是 `data_1_2_t<double, double, double>`，这意味着数组中的每个元素都包含了三个双精度浮点数。"
* Connect the data to the `atan2` function: "根据文件名 `atan2_intel_data.handroid` 和数组元素的数量，可以推断出这个文件是为 `atan2` 函数提供测试数据的。"
* Elaborate on the data's purpose: "具体来说，数组中的每一项都可能代表一个测试用例，包含 `atan2` 函数的两个输入参数（`y` 和 `x`）以及预期的输出结果。"
* Mention the testing context: "这个文件很可能是 Android Bionic 库中用于测试 `atan2` 函数在特定输入下的正确性的数据集合。"
* Briefly mention the architecture specificity: "文件名中的 `intel` 暗示这些测试数据可能专门针对 Intel 架构的处理器。"

**7. Refining and Finalizing:**

Review the drafted summary for clarity, accuracy, and completeness (within the scope of a summary). Ensure the language is clear and concise. The provided example answer is well-structured and covers the essential points.

This step-by-step approach, starting with high-level understanding and gradually drilling down into specifics, helps to systematically analyze the code and formulate a comprehensive summary. Even anticipating the content of subsequent parts aids in understanding the overall context and purpose of the file.
好的，我们来归纳一下这个C源代码文件的功能。

**功能归纳：**

这个C源代码文件定义了一个名为 `g_atan2_intel_data` 的静态数组。这个数组的元素类型是 `data_1_2_t<double, double, double>`，这意味着数组中的每个元素都包含了三个双精度浮点数。

根据文件名 `atan2_intel_data.handroid` 和数组元素的数量，可以推断出这个文件是为 `atan2` 函数提供测试数据的。具体来说，数组中的每一项都可能代表一个测试用例，包含 `atan2` 函数的两个输入参数（`y` 和 `x`）以及预期的输出结果。

这个文件很可能是 Android Bionic 库中用于测试 `atan2` 函数在特定输入下的正确性的数据集合。文件名中的 `intel` 暗示这些测试数据可能专门针对 Intel 架构的处理器。

**更详细的解释：**

1. **测试数据存储:**  该文件的核心功能是存储一系列预定义的测试用例数据。这些数据用于验证 `atan2` 函数的实现是否正确。

2. **针对 `atan2` 函数:** 文件名和数组名都明确指向 `atan2` 函数。`atan2(y, x)` 是一个标准 C 库函数，用于计算给定直角坐标 `(x, y)` 的反正切值，并考虑了象限，返回值的范围是 `[-π, π]` 弧度。

3. **双精度浮点数:**  数组中的数据类型是 `double`，表示测试用例针对的是 `atan2` 函数的双精度浮点数版本。

4. **测试用例结构:**  推测 `data_1_2_t<double, double, double>` 结构体包含三个 `double` 类型的成员，分别对应 `atan2` 函数的 `y` 输入、`x` 输入以及期望的输出结果。例如，对于第一个元素：
   - `y` 输入: `-0x1.ffffffffffff20000000000061fffd55p-60`
   - `x` 输入: `-0x1.0p-100`
   - 期望输出: `0x1.0000000000007p-41`

5. **`handroid` 后缀:**  `.handroid` 可能是 Android Bionic 测试框架内部使用的一种文件后缀，用于标记特定类型的测试数据文件。

6. **`intel` 指示:** 文件名中的 `intel` 可能意味着这组测试数据是针对 Intel 处理器架构的，或者是在 Intel 平台上生成和验证的。不同的处理器架构在浮点数运算上可能存在细微差别，因此需要针对特定架构进行测试。

**与 Android 功能的关系举例：**

`atan2` 函数在 Android 系统中有广泛的应用，例如：

* **图形渲染:** 在 OpenGL ES 中，计算向量的角度、旋转角度等需要使用 `atan2`。例如，计算两个触控点之间的角度来判断旋转手势。
* **传感器处理:**  在处理来自加速度计、陀螺仪、磁力计等传感器的数据时，经常需要使用 `atan2` 来计算设备的姿态和方向。例如，计算手机相对于地磁北极的方向。
* **定位服务:** 在地图应用中，计算两个经纬度坐标之间的方位角需要使用 `atan2`。
* **动画和 UI:**  创建自定义动画效果时，可能需要计算角度来实现特定的运动轨迹。

**关于 libc 函数的实现，dynamic linker 的功能，用户错误，以及 framework/NDK 如何到达这里，将在后续的第2、3、4部分进行详细解释。**

**假设输入与输出 (基于代码推断):**

假设存在一个测试程序读取这个数据文件并调用 `atan2` 函数进行测试。对于 `g_atan2_intel_data[0]` 这个条目：

* **假设输入:** `y = -0x1.ffffffffffff20000000000061fffd55p-60`, `x = -0x1.0p-100`
* **预期输出:** `0x1.0000000000007p-41`

测试程序会计算 `atan2(-0x1.ffffffffffff20000000000061fffd55p-60, -0x1.0p-100)`，并将结果与 `0x1.0000000000007p-41` 进行比较，以判断 `atan2` 的实现是否正确。

**用户或编程常见的使用错误 (现在可以简单提及，后续会详细解释):**

* **参数顺序错误:** 误写成 `atan2(x, y)` 而不是 `atan2(y, x)`。
* **单位理解错误:**  `atan2` 返回的是弧度值，用户可能需要将其转换为角度。
* **边界情况处理不当:** 对于 `x` 或 `y` 为零的情况，需要理解 `atan2` 的返回值。

总而言之，这个文件是 Android Bionic 库中用于测试 `atan2` 函数在 Intel 架构上正确性的关键组成部分，它提供了一系列精心设计的测试用例。

### 提示词
```
这是目录为bionic/tests/math_data/atan2_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共4部分，请归纳一下它的功能
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

static data_1_2_t<double, double, double> g_atan2_intel_data[] = {
  { // Entry 0
    -0x1.ffffffffffff20000000000061fffd55p-60,
    -0x1.0p-100,
    0x1.0000000000007p-41
  },
  { // Entry 1
    0x1.ffffffffffff20000000000061fffd55p-60,
    0x1.0p-100,
    0x1.0000000000007p-41
  },
  { // Entry 2
    -0.0,
    -0x1.0p-1073,
    0x1.0000000000001p1
  },
  { // Entry 3
    0.0,
    0x1.0p-1073,
    0x1.0000000000001p1
  },
  { // Entry 4
    -0x1.cd648010e76317fd25f197c89894a747p-1,
    -0x1.0p10,
    0x1.955555555555ep9
  },
  { // Entry 5
    0x1.cd648010e76317fd25f197c89894a747p-1,
    0x1.0p10,
    0x1.955555555555ep9
  },
  { // Entry 6
    -0x1.0000000000000800000000000040p-924,
    -0x1.0p100,
    0x1.fffffffffffffp1023
  },
  { // Entry 7
    0x1.0000000000000800000000000040p-924,
    0x1.0p100,
    0x1.fffffffffffffp1023
  },
  { // Entry 8
    -0x1.0945ca475762680110c86c82f4007bdap1,
    -0x1.0000000000001p0,
    -0x1.18cd584e6112bp-1
  },
  { // Entry 9
    0x1.0945ca475762680110c86c82f4007bdap1,
    0x1.0000000000001p0,
    -0x1.18cd584e6112bp-1
  },
  { // Entry 10
    -0x1.f9ca0e1dd954324b96732f0ae9c1c8ffp-3,
    -0x1.0222222222222p0,
    0x1.ffeffffffffffp1
  },
  { // Entry 11
    0x1.f9ca0e1dd954324b96732f0ae9c1c8ffp-3,
    0x1.0222222222222p0,
    0x1.ffeffffffffffp1
  },
  { // Entry 12
    -0x1.fff9653e6201f888937cfc2d716b4d44p-2,
    -0x1.14171f06bfb89p-2,
    0x1.f96902dccd29ap-2
  },
  { // Entry 13
    0x1.fff9653e6201f888937cfc2d716b4d44p-2,
    0x1.14171f06bfb89p-2,
    0x1.f96902dccd29ap-2
  },
  { // Entry 14
    -0x1.ff572aded0be932feeb4707dcb65336dp0,
    -0x1.1999999999998p-2,
    -0x1.0000000000001p-3
  },
  { // Entry 15
    0x1.ff572aded0be932feeb4707dcb65336dp0,
    0x1.1999999999998p-2,
    -0x1.0000000000001p-3
  },
  { // Entry 16
    -0x1.ff542758ef05b8e7de0d70e2d341ed67p0,
    -0x1.1999999999999p-1,
    -0x1.ffeffffffffffp-3
  },
  { // Entry 17
    0x1.ff542758ef05b8e7de0d70e2d341ed67p0,
    0x1.1999999999999p-1,
    -0x1.ffeffffffffffp-3
  },
  { // Entry 18
    -0x1.2fffffffffffffffffffffffffffffffp-1071,
    -0x1.3p-1070,
    0x1.0p1
  },
  { // Entry 19
    0x1.2fffffffffffffffffffffffffffffffp-1071,
    0x1.3p-1070,
    0x1.0p1
  },
  { // Entry 20
    -0x1.85539729ef1727fed15784b60b91b2ecp-1,
    -0x1.3cf3cf3cf3cf4p9,
    0x1.4d34d34d34d34p9
  },
  { // Entry 21
    0x1.85539729ef1727fed15784b60b91b2ecp-1,
    0x1.3cf3cf3cf3cf4p9,
    0x1.4d34d34d34d34p9
  },
  { // Entry 22
    -0x1.40000000000008000000000000fffd65p-59,
    -0x1.3fffffffffffep42,
    0x1.ffffffffffffcp100
  },
  { // Entry 23
    0x1.40000000000008000000000000fffd65p-59,
    0x1.3fffffffffffep42,
    0x1.ffffffffffffcp100
  },
  { // Entry 24
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.4p-1072,
    -0x1.fffffffffffffp1023
  },
  { // Entry 25
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.4p-1072,
    -0x1.fffffffffffffp1023
  },
  { // Entry 26
    -0x1.3fffffffffffffffffffffffffffffffp-1073,
    -0x1.4p-1072,
    0x1.0p1
  },
  { // Entry 27
    0x1.3fffffffffffffffffffffffffffffffp-1073,
    0x1.4p-1072,
    0x1.0p1
  },
  { // Entry 28
    -0x1.5ffe7c27a5cf37fef15668ed8bfdc92cp-1,
    -0x1.6477c84a032cep-1,
    0x1.b21f69ae030b0p-1
  },
  { // Entry 29
    0x1.5ffe7c27a5cf37fef15668ed8bfdc92cp-1,
    0x1.6477c84a032cep-1,
    0x1.b21f69ae030b0p-1
  },
  { // Entry 30
    -0x1.66719908f7c3b796d84184977c923894p-12,
    -0x1.6666666665b64p-1,
    0x1.ffeffffffffffp10
  },
  { // Entry 31
    0x1.66719908f7c3b796d84184977c923894p-12,
    0x1.6666666665b64p-1,
    0x1.ffeffffffffffp10
  },
  { // Entry 32
    -0x1.667199f33acd08010011a82e9838500dp-52,
    -0x1.6666666666668p-1,
    0x1.ffeffffff924fp50
  },
  { // Entry 33
    0x1.667199f33acd08010011a82e9838500dp-52,
    0x1.6666666666668p-1,
    0x1.ffeffffff924fp50
  },
  { // Entry 34
    -0x1.48ef86a5d674e7fe626345caa6dea1adp0,
    -0x1.6e589292a58a8p3,
    0x1.aebd9564499f0p1
  },
  { // Entry 35
    0x1.48ef86a5d674e7fe626345caa6dea1adp0,
    0x1.6e589292a58a8p3,
    0x1.aebd9564499f0p1
  },
  { // Entry 36
    -0x1.69412651b663880102057ffe2b6916e7p-2,
    -0x1.7906fe92593dcp-2,
    0x1.0p0
  },
  { // Entry 37
    0x1.69412651b663880102057ffe2b6916e7p-2,
    0x1.7906fe92593dcp-2,
    0x1.0p0
  },
  { // Entry 38
    -0x1.7fffffffffff97ffb800000013803a80p-33,
    -0x1.7fffffffffffep0,
    0x1.0000000000003p33
  },
  { // Entry 39
    0x1.7fffffffffff97ffb800000013803a80p-33,
    0x1.7fffffffffffep0,
    0x1.0000000000003p33
  },
  { // Entry 40
    -0x1.7fffffffee0020000184c84cd0a5bfb7p-18,
    -0x1.7ffffffffffffp0,
    0x1.ffffffffffffcp17
  },
  { // Entry 41
    0x1.7fffffffee0020000184c84cd0a5bfb7p-18,
    0x1.7ffffffffffffp0,
    0x1.ffffffffffffcp17
  },
  { // Entry 42
    -0x1.01b7ead625912801099d55f3bb6d9b74p0,
    -0x1.8e38e38e38e39p9,
    0x1.f7df7df7df7dep8
  },
  { // Entry 43
    0x1.01b7ead625912801099d55f3bb6d9b74p0,
    0x1.8e38e38e38e39p9,
    0x1.f7df7df7df7dep8
  },
  { // Entry 44
    -0x1.119e0f7084d96bc18bbf2e7a08cfe5adp1,
    -0x1.9249249249246p-2,
    -0x1.001p-2
  },
  { // Entry 45
    0x1.119e0f7084d96bc18bbf2e7a08cfe5adp1,
    0x1.9249249249246p-2,
    -0x1.001p-2
  },
  { // Entry 46
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.99999999999a8p-4,
    0x1.0p-1074
  },
  { // Entry 47
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.99999999999a8p-4,
    0x1.0p-1074
  },
  { // Entry 48
    -0x1.37626c23803aec7d7a70f700585852f4p-1,
    -0x1.a77569dd5a776p8,
    0x1.301ecc07b301ep9
  },
  { // Entry 49
    0x1.37626c23803aec7d7a70f700585852f4p-1,
    0x1.a77569dd5a776p8,
    0x1.301ecc07b301ep9
  },
  { // Entry 50
    -0x1.0ca7cc2d0d7fd03164ee3af269e6bf79p1,
    -0x1.b6db6db6db6e0p-1,
    -0x1.0000000000003p-1
  },
  { // Entry 51
    0x1.0ca7cc2d0d7fd03164ee3af269e6bf79p1,
    0x1.b6db6db6db6e0p-1,
    -0x1.0000000000003p-1
  },
  { // Entry 52
    -0x1.a271f63e34fb2fff42b98e7a5ab17eafp-2,
    -0x1.bb67ae8584c96p-1,
    0x1.0000000000008p1
  },
  { // Entry 53
    0x1.a271f63e34fb2fff42b98e7a5ab17eafp-2,
    0x1.bb67ae8584c96p-1,
    0x1.0000000000008p1
  },
  { // Entry 54
    -0x1.f0845de317dae782ac3e8a7eb1fadd63p-2,
    -0x1.bed61bed61be4p7,
    0x1.a814afd6a053bp8
  },
  { // Entry 55
    0x1.f0845de317dae782ac3e8a7eb1fadd63p-2,
    0x1.bed61bed61be4p7,
    0x1.a814afd6a053bp8
  },
  { // Entry 56
    -0x1.3a51f5f0cb5d33de07ac24a32621878dp-1,
    -0x1.c18f9c18f9c3ep7,
    0x1.3ef368eb04334p8
  },
  { // Entry 57
    0x1.3a51f5f0cb5d33de07ac24a32621878dp-1,
    0x1.c18f9c18f9c3ep7,
    0x1.3ef368eb04334p8
  },
  { // Entry 58
    -0x1.fcb510cd5b6bbb8cde13f46dbeeb3110p-3,
    -0x1.d26a2bad98d68p-2,
    0x1.cbbd407a7a5b0p0
  },
  { // Entry 59
    0x1.fcb510cd5b6bbb8cde13f46dbeeb3110p-3,
    0x1.d26a2bad98d68p-2,
    0x1.cbbd407a7a5b0p0
  },
  { // Entry 60
    -0x1.cd5de97a2e3e1859fc3e2517de7a0880p-3,
    -0x1.d555555555555p0,
    0x1.0000000000003p3
  },
  { // Entry 61
    0x1.cd5de97a2e3e1859fc3e2517de7a0880p-3,
    0x1.d555555555555p0,
    0x1.0000000000003p3
  },
  { // Entry 62
    -0x1.337d175e088fb7fa32fafca382768a15p-3,
    -0x1.db8a874640569p-3,
    0x1.88eed10e75135p0
  },
  { // Entry 63
    0x1.337d175e088fb7fa32fafca382768a15p-3,
    0x1.db8a874640569p-3,
    0x1.88eed10e75135p0
  },
  { // Entry 64
    -0x1.f9d28f3da09c8864390cd924ac658d33p0,
    -0x1.ddddddddddde0p-2,
    -0x1.99ce075f6fd27p-3
  },
  { // Entry 65
    0x1.f9d28f3da09c8864390cd924ac658d33p0,
    0x1.ddddddddddde0p-2,
    -0x1.99ce075f6fd27p-3
  },
  { // Entry 66
    -0x1.ae127b4fb5a7e81cc14c8d0627d18c73p-8,
    -0x1.eccd7fdf96454p10,
    0x1.255608e135d80p18
  },
  { // Entry 67
    0x1.ae127b4fb5a7e81cc14c8d0627d18c73p-8,
    0x1.eccd7fdf96454p10,
    0x1.255608e135d80p18
  },
  { // Entry 68
    -0x1.09121b4b0fb15403f902f2d06a8f1034p1,
    -0x1.f5a814afd6a05p9,
    -0x1.1219dbcc48673p9
  },
  { // Entry 69
    0x1.09121b4b0fb15403f902f2d06a8f1034p1,
    0x1.f5a814afd6a05p9,
    -0x1.1219dbcc48673p9
  },
  { // Entry 70
    -0x1.ffd55bba97625a80f03aaeebb3192417p-6,
    -0x1.ffffffffffffdp-1,
    0x1.ffffffffffffcp4
  },
  { // Entry 71
    0x1.ffd55bba97625a80f03aaeebb3192417p-6,
    0x1.ffffffffffffdp-1,
    0x1.ffffffffffffcp4
  },
  { // Entry 72
    0x1.ffffffffffffe0000000000001fffffdp-64,
    0x1.0p-53,
    0x1.0000000000001p10
  },
  { // Entry 73
    -0x1.ffffffffffffe0000000000001fffffdp-64,
    -0x1.0p-53,
    0x1.0000000000001p10
  },
  { // Entry 74
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.0p-1074,
    -0x1.745d1745d173cp-3
  },
  { // Entry 75
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.0p-1074,
    -0x1.745d1745d173cp-3
  },
  { // Entry 76
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.0p-1074,
    -0x1.99999999999a8p-4
  },
  { // Entry 77
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.0p-1074,
    -0x1.99999999999a8p-4
  },
  { // Entry 78
    0.0,
    0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 79
    -0.0,
    -0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 80
    0x1.ffffffffffffe0000000000001ffffffp-1074,
    0x1.0p-1074,
    0x1.0000000000001p-1
  },
  { // Entry 81
    -0x1.ffffffffffffe0000000000001ffffffp-1074,
    -0x1.0p-1074,
    0x1.0000000000001p-1
  },
  { // Entry 82
    0.0,
    0x1.0p-1074,
    0x1.0222222222223p0
  },
  { // Entry 83
    -0.0,
    -0x1.0p-1074,
    0x1.0222222222223p0
  },
  { // Entry 84
    0.0,
    0x1.0p-1074,
    0x1.03126e978d4fep0
  },
  { // Entry 85
    -0.0,
    -0x1.0p-1074,
    0x1.03126e978d4fep0
  },
  { // Entry 86
    0.0,
    0x1.0p-1074,
    0x1.0a3d70a3d70a3p0
  },
  { // Entry 87
    -0.0,
    -0x1.0p-1074,
    0x1.0a3d70a3d70a3p0
  },
  { // Entry 88
    0x1.0b833be165ccd3f3660d385792d30b1fp1,
    0x1.0000000000001p-2,
    -0x1.24924924924aap-3
  },
  { // Entry 89
    -0x1.0b833be165ccd3f3660d385792d30b1fp1,
    -0x1.0000000000001p-2,
    -0x1.24924924924aap-3
  },
  { // Entry 90
    0x1.5522d16b2f5a7d52fbf6dd4ea12734c4p-5,
    0x1.0000000000001p-4,
    0x1.8000000000001p0
  },
  { // Entry 91
    -0x1.5522d16b2f5a7d52fbf6dd4ea12734c4p-5,
    -0x1.0000000000001p-4,
    0x1.8000000000001p0
  },
  { // Entry 92
    0x1.7ffffffedfffe80184cd02ca5ef0e59ap-16,
    0x1.0000000000001p-17,
    0x1.5555555555558p-2
  },
  { // Entry 93
    -0x1.7ffffffedfffe80184cd02ca5ef0e59ap-16,
    -0x1.0000000000001p-17,
    0x1.5555555555558p-2
  },
  { // Entry 94
    0x1.00000000000017ffaaaaaaaaab6a92aap-32,
    0x1.0000000000001p-31,
    0x1.fffffffffffffp0
  },
  { // Entry 95
    -0x1.00000000000017ffaaaaaaaaab6a92aap-32,
    -0x1.0000000000001p-31,
    0x1.fffffffffffffp0
  },
  { // Entry 96
    0x1.00000000000027ffffffaaaaae6aaaaap-40,
    0x1.0000000000001p-41,
    0x1.ffffffffffffdp-2
  },
  { // Entry 97
    -0x1.00000000000027ffffffaaaaae6aaaaap-40,
    -0x1.0000000000001p-41,
    0x1.ffffffffffffdp-2
  },
  { // Entry 98
    0x1.000000000000680000000000103faaaap-56,
    0x1.0000000000004p1,
    0x1.ffffffffffffbp56
  },
  { // Entry 99
    -0x1.000000000000680000000000103faaaap-56,
    -0x1.0000000000004p1,
    0x1.ffffffffffffbp56
  },
  { // Entry 100
    0x1.fd5ba9aac2f7c8b4561b80036f0e165cp-4,
    0x1.0000000000007p3,
    0x1.fffffffffffffp5
  },
  { // Entry 101
    -0x1.fd5ba9aac2f7c8b4561b80036f0e165cp-4,
    -0x1.0000000000007p3,
    0x1.fffffffffffffp5
  },
  { // Entry 102
    0x1.ff55bb72cfe2e821e203716e1d97a257p-5,
    0x1.000000000001cp-3,
    0x1.ffffffffffff3p0
  },
  { // Entry 103
    -0x1.ff55bb72cfe2e821e203716e1d97a257p-5,
    -0x1.000000000001cp-3,
    0x1.ffffffffffff3p0
  },
  { // Entry 104
    0x1.38e36745aef6d7ab02058b0c0c876fc8p-9,
    0x1.00000000004d6p-8,
    0x1.a2e8ba2e8ba30p0
  },
  { // Entry 105
    -0x1.38e36745aef6d7ab02058b0c0c876fc8p-9,
    -0x1.00000000004d6p-8,
    0x1.a2e8ba2e8ba30p0
  },
  { // Entry 106
    0x1.3ff4325a8437500000286dff86bc02adp-1,
    0x1.00000009f0205p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 107
    -0x1.3ff4325a8437500000286dff86bc02adp-1,
    -0x1.00000009f0205p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 108
    0x1.b4f5f236308b48037fe229608c1d81fbp-2,
    0x1.001p-1,
    0x1.199999999999ap0
  },
  { // Entry 109
    -0x1.b4f5f236308b48037fe229608c1d81fbp-2,
    -0x1.001p-1,
    0x1.199999999999ap0
  },
  { // Entry 110
    0x1.9242e6442d4317ff2531ceafca8af0f4p0,
    0x1.001p10,
    -0x1.1999999999999p-1
  },
  { // Entry 111
    -0x1.9242e6442d4317ff2531ceafca8af0f4p0,
    -0x1.001p10,
    -0x1.1999999999999p-1
  },
  { // Entry 112
    0x1.046862a40cbe6ab9070021df9e1e411bp1,
    0x1.0175fcd4ab261p1,
    -0x1.01749ca942943p0
  },
  { // Entry 113
    -0x1.046862a40cbe6ab9070021df9e1e411bp1,
    -0x1.0175fcd4ab261p1,
    -0x1.01749ca942943p0
  },
  { // Entry 114
    0x1.9b2bb7e10b2677febb378df81a94d587p-1,
    0x1.066b3f39ae7a1p0,
    0x1.fa9c4b9f46842p-1
  },
  { // Entry 115
    -0x1.9b2bb7e10b2677febb378df81a94d587p-1,
    -0x1.066b3f39ae7a1p0,
    0x1.fa9c4b9f46842p-1
  },
  { // Entry 116
    0x1.e897850a716e4889a143afe6cdae77d1p-2,
    0x1.08b1d3b97c955p-2,
    0x1.0p-1
  },
  { // Entry 117
    -0x1.e897850a716e4889a143afe6cdae77d1p-2,
    -0x1.08b1d3b97c955p-2,
    0x1.0p-1
  },
  { // Entry 118
    0x1.13e7bb06113d680135e98e8c2e9c9628p-92,
    0x1.09d89d89d89d8p9,
    0x1.ed55555555573p100
  },
  { // Entry 119
    -0x1.13e7bb06113d680135e98e8c2e9c9628p-92,
    -0x1.09d89d89d89d8p9,
    0x1.ed55555555573p100
  },
  { // Entry 120
    0x1.ff572aded0be7136f236315e3c9eccb7p0,
    0x1.199999999999cp-1,
    -0x1.ffffffffffffep-3
  },
  { // Entry 121
    -0x1.ff572aded0be7136f236315e3c9eccb7p0,
    -0x1.199999999999cp-1,
    -0x1.ffffffffffffep-3
  },
  { // Entry 122
    0x1.196ba6878b92680ebe4a5666ff18a384p-5,
    0x1.199999999999cp-2,
    0x1.001p3
  },
  { // Entry 123
    -0x1.196ba6878b92680ebe4a5666ff18a384p-5,
    -0x1.199999999999cp-2,
    0x1.001p3
  },
  { // Entry 124
    0x1.1b4a29a02a9c87fffdb48e539399967ap-3,
    0x1.1adec7d06a010p-2,
    0x1.fbfa204c8234cp0
  },
  { // Entry 125
    -0x1.1b4a29a02a9c87fffdb48e539399967ap-3,
    -0x1.1adec7d06a010p-2,
    0x1.fbfa204c8234cp0
  },
  { // Entry 126
    0x1.19dcd054169247fffd4cc05900e64848p-2,
    0x1.213422ec61f53p-3,
    0x1.0p-1
  },
  { // Entry 127
    -0x1.19dcd054169247fffd4cc05900e64848p-2,
    -0x1.213422ec61f53p-3,
    0x1.0p-1
  },
  { // Entry 128
    0x1.b3b95bdcb30277fec23bb4be90b63531p-1,
    0x1.2776fe2145bd5p0,
    0x1.0306216790738p0
  },
  { // Entry 129
    -0x1.b3b95bdcb30277fec23bb4be90b63531p-1,
    -0x1.2776fe2145bd5p0,
    0x1.0306216790738p0
  },
  { // Entry 130
    0x1.ee0c54984cb15edcdcb239dbfffd57dep-4,
    0x1.27fb7de0e57c8p12,
    0x1.313f9061390p15
  },
  { // Entry 131
    -0x1.ee0c54984cb15edcdcb239dbfffd57dep-4,
    -0x1.27fb7de0e57c8p12,
    0x1.313f9061390p15
  },
  { // Entry 132
    0x1.27ff4834766d779860765d14b68788cep-8,
    0x1.27fb7de0e57c8p12,
    0x1.fff88d6e2d934p19
  },
  { // Entry 133
    -0x1.27ff4834766d779860765d14b68788cep-8,
    -0x1.27fb7de0e57c8p12,
    0x1.fff88d6e2d934p19
  },
  { // Entry 134
    0x1.f9c6b238c6435777790ced0df81049e2p0,
    0x1.2aaaaaaaaaaabp0,
    -0x1.0000000000003p-1
  },
  { // Entry 135
    -0x1.f9c6b238c6435777790ced0df81049e2p0,
    -0x1.2aaaaaaaaaaabp0,
    -0x1.0000000000003p-1
  },
  { // Entry 136
    0x1.2aaaaaaaaaaa77ff787e6b74f9b2d658p-32,
    0x1.2aaaaaaaaaaabp0,
    0x1.0000000000003p32
  },
  { // Entry 137
    -0x1.2aaaaaaaaaaa77ff787e6b74f9b2d658p-32,
    -0x1.2aaaaaaaaaaabp0,
    0x1.0000000000003p32
  },
  { // Entry 138
    0x1.edae91ebbfb8780006f7e9144583c7b3p0,
    0x1.2d66ca857bf9ap0,
    -0x1.c28f5c28f5c28p-2
  },
  { // Entry 139
    -0x1.edae91ebbfb8780006f7e9144583c7b3p0,
    -0x1.2d66ca857bf9ap0,
    -0x1.c28f5c28f5c28p-2
  },
  { // Entry 140
    0x1.9d5a77d67cf1d7febab338e68f258f5ap-1,
    0x1.2e12530a85951p2,
    0x1.211a7b9611a7bp2
  },
  { // Entry 141
    -0x1.9d5a77d67cf1d7febab338e68f258f5ap-1,
    -0x1.2e12530a85951p2,
    0x1.211a7b9611a7bp2
  },
  { // Entry 142
    0x1.a244e21ebefa8fffffbfabeaba9e67acp-2,
    0x1.3333333d813abp-2,
    0x1.62e42fefa39efp-1
  },
  { // Entry 143
    -0x1.a244e21ebefa8fffffbfabeaba9e67acp-2,
    -0x1.3333333d813abp-2,
    0x1.62e42fefa39efp-1
  },
  { // Entry 144
    0x1.90a08b292067f00094284270c3b75547p-4,
    0x1.3deb308a9c960p-4,
    0x1.9500a27c6a82ep-1
  },
  { // Entry 145
    -0x1.90a08b292067f00094284270c3b75547p-4,
    -0x1.3deb308a9c960p-4,
    0x1.9500a27c6a82ep-1
  },
  { // Entry 146
    0x1.a896592d6fdb57b63fa6ed728b91fe47p-5,
    0x1.420bc59c42c7cp2,
    0x1.83fffffffffffp6
  },
  { // Entry 147
    -0x1.a896592d6fdb57b63fa6ed728b91fe47p-5,
    -0x1.420bc59c42c7cp2,
    0x1.83fffffffffffp6
  },
  { // Entry 148
    0x1.25e3010ff1ed37fe769fa76dea43608cp1,
    0x1.494b48acbe5b0p-9,
    -0x1.23da61f087530p-9
  },
  { // Entry 149
    -0x1.25e3010ff1ed37fe769fa76dea43608cp1,
    -0x1.494b48acbe5b0p-9,
    -0x1.23da61f087530p-9
  },
  { // Entry 150
    0x1.6d0d1984633eb80e098b6dc91f083a06p-3,
    0x1.51ff85f2ba468p0,
    0x1.d50692986b95dp2
  },
  { // Entry 151
    -0x1.6d0d1984633eb80e098b6dc91f083a06p-3,
    -0x1.51ff85f2ba468p0,
    0x1.d50692986b95dp2
  },
  { // Entry 152
    0x1.ccadda48d08027ff92d1bd814812ce8cp-1,
    0x1.5412e00233d75p-1,
    0x1.0dff2d1714940p-1
  },
  { // Entry 153
    -0x1.ccadda48d08027ff92d1bd814812ce8cp-1,
    -0x1.5412e00233d75p-1,
    0x1.0dff2d1714940p-1
  },
  { // Entry 154
    0x1.3f2496d84ac34801117f6f830c0fb201p-90,
    0x1.5555555554c2ep8,
    0x1.11ccccccccccdp98
  },
  { // Entry 155
    -0x1.3f2496d84ac34801117f6f830c0fb201p-90,
    -0x1.5555555554c2ep8,
    0x1.11ccccccccccdp98
  },
  { // Entry 156
    0x1.555555555555aaaaaaaaaaaab5555555p-1021,
    0x1.5555555555558p-2,
    0x1.ffffffffffffcp1018
  },
  { // Entry 157
    -0x1.555555555555aaaaaaaaaaaab5555555p-1021,
    -0x1.5555555555558p-2,
    0x1.ffffffffffffcp1018
  },
  { // Entry 158
    0x1.88134cb8d04e88985007b92a62b1fd1ap-8,
    0x1.5711ef5ee1eecp-5,
    0x1.c000000000302p2
  },
  { // Entry 159
    -0x1.88134cb8d04e88985007b92a62b1fd1ap-8,
    -0x1.5711ef5ee1eecp-5,
    0x1.c000000000302p2
  },
  { // Entry 160
    0x1.94a470782907f800006a4822bc94bc23p-1,
    0x1.666666688d411p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 161
    -0x1.94a470782907f800006a4822bc94bc23p-1,
    -0x1.666666688d411p-1,
    0x1.62e42fefa39efp-1
  },
  { // Entry 162
    0x1.d7d7b672ee30c85d01819b25305f3230p-10,
    0x1.6c9b26c9b26cap0,
    0x1.8ba2e8ba2e8cap9
  },
  { // Entry 163
    -0x1.d7d7b672ee30c85d01819b25305f3230p-10,
    -0x1.6c9b26c9b26cap0,
    0x1.8ba2e8ba2e8cap9
  },
  { // Entry 164
    0x1.7fffffffee0030000184c60cd2a5c008p-18,
    0x1.8p-53,
    0x1.ffffffffffffcp-36
  },
  { // Entry 165
    -0x1.7fffffffee0030000184c60cd2a5c008p-18,
    -0x1.8p-53,
    0x1.ffffffffffffcp-36
  },
  { // Entry 166
    0x1.e7c8952cb26158012b54b9a61c08f431p-2,
    0x1.8c46231188cp0,
    0x1.8p1
  },
  { // Entry 167
    -0x1.e7c8952cb26158012b54b9a61c08f431p-2,
    -0x1.8c46231188cp0,
    0x1.8p1
  },
  { // Entry 168
    0x1.2b854f022de7a93cb621cb2462f86074p0,
    0x1.8d79435e50d71p2,
    0x1.50d79435e50d9p1
  },
  { // Entry 169
    -0x1.2b854f022de7a93cb621cb2462f86074p0,
    -0x1.8d79435e50d71p2,
    0x1.50d79435e50d9p1
  },
  { // Entry 170
    0x1.42a76a164c39c800e4405027c490bdfbp-1,
    0x1.8dd3d2235ad60p-1,
    0x1.10b5d1e78459cp0
  },
  { // Entry 171
    -0x1.42a76a164c39c800e4405027c490bdfbp-1,
    -0x1.8dd3d2235ad60p-1,
    0x1.10b5d1e78459cp0
  },
  { // Entry 172
    0x1.e3240e993ab957f9d76dde4a50896826p-3,
    0x1.9p0,
    0x1.9fffffffffffbp2
  },
  { // Entry 173
    -0x1.e3240e993ab957f9d76dde4a50896826p-3,
    -0x1.9p0,
    0x1.9fffffffffffbp2
  },
  { // Entry 174
    0x1.a335efd4da90a804f7a6dad4434f5ba0p-2,
    0x1.920d799fda713p-3,
    0x1.cf4cdc48f3536p-2
  },
  { // Entry 175
    -0x1.a335efd4da90a804f7a6dad4434f5ba0p-2,
    -0x1.920d799fda713p-3,
    0x1.cf4cdc48f3536p-2
  },
  { // Entry 176
    0x1.ed87f9c729d17ffe9d2f47e2fe9ecb40p-1,
    0x1.95fad40a57ec6p9,
    0x1.19dbcc48676f6p9
  },
  { // Entry 177
    -0x1.ed87f9c729d17ffe9d2f47e2fe9ecb40p-1,
    -0x1.95fad40a57ec6p9,
    0x1.19dbcc48676f6p9
  },
  { // Entry 178
    0x1.0bfa5f3f099e68000068d82232dc4cc7p-1,
    0x1.9999999e37c24p-2,
    0x1.62e42fefa39efp-1
  },
  { // Entry 179
    -0x1.0bfa5f3f099e68000068d82232dc4cc7p-1,
    -0x1.9999999e37c24p-2,
    0x1.62e42fefa39efp-1
  },
  { // Entry 180
    0x1.1fa6ac30d066d800006a5c239e5188f2p-2,
    0x1.999999bb09140p-3,
    0x1.62e42fefa39efp-1
  },
  { // Entry 181
    -0x1.1fa6ac30d066d800006a5c239e5188f2p-2,
    -0x1.999999bb09140p-3,
    0x1.62e42fefa39efp-1
  },
  { // Entry 182
    0x1.2570742fa4989fffff9e946c986117d9p-3,
    0x1.999999c2f3b55p-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 183
    -0x1.2570742fa4989fffff9e946c986117d9p-3,
    -0x1.999999c2f3b55p-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 184
    0x1.257074378653a7ffffffb78db995aafcp-3,
    0x1.999999ce1b18ap-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 185
    -0x1.257074378653a7ffffffb78db995aafcp-3,
    -0x1.999999ce1b18ap-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 186
    0x1.25707437a1476000006169ddb5dabdd7p-3,
    0x1.999999ce413ccp-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 187
    -0x1.25707437a1476000006169ddb5dabdd7p-3,
    -0x1.999999ce413ccp-4,
    0x1.62e42fefa39efp-1
  },
  { // Entry 188
    0x1.b6a03b0f1ff0d7fd08e9f5846ec5a75bp-1,
    0x1.9c5c97530cc21p0,
    0x1.6563fa1d6f518p0
  },
  { // Entry 189
    -0x1.b6a03b0f1ff0d7fd08e9f5846ec5a75bp-1,
    -0x1.9c5c97530cc21p0,
    0x1.6563fa1d6f518p0
  },
  { // Entry 190
    0x1.b80aa068167f97558972ecfed6777774p-19,
    0x1.9f5aeae03799dp-18,
    0x1.e346d9b2ad73ep0
  },
  { // Entry 191
    -0x1.b80aa068167f97558972ecfed6777774p-19,
    -0x1.9f5aeae03799dp-18,
    0x1.e346d9b2ad73ep0
  },
  { // Entry 192
    0x1.e5ef7b22c83b27ad34bbfda6c2383d23p-2,
    0x1.a4d269349b66cp-3,
    0x1.999999999999ap-2
  },
  { // Entry 193
    -0x1.e5ef7b22c83b27ad34bbfda6c2383d23p-2,
    -0x1.a4d269349b66cp-3,
    0x1.999999999999ap-2
  },
  { // Entry 194
    0x1.5e82cb51676728011e1c6ba75f3339a7p-91,
    0x1.ad5aa6ff6335ep9,
    0x1.3995880de757ap100
  },
  { // Entry 195
    -0x1.5e82cb51676728011e1c6ba75f3339a7p-91,
    -0x1.ad5aa6ff6335ep9,
    0x1.3995880de757ap100
  },
  { // Entry 196
    0x1.95ac93504f319fefb1b5148792dab412p-1,
    0x1.b1427cd988b8cp-2,
    0x1.ab4adeaf1a3eap-2
  },
  { // Entry 197
    -0x1.95ac93504f319fefb1b5148792dab412p-1,
    -0x1.b1427cd988b8cp-2,
    0x1.ab4adeaf1a3eap-2
  },
  { // Entry 198
    0x1.921fd1f09f928801088a93fc7dbba1cap0,
    0x1.bbd49acc58d98p10,
    -0x1.8db0a4ab22e7ep-9
  },
  { // Entry 199
    -0x1.921fd1f09f928801088a93fc7dbba1cap0,
    -0x1.bbd49acc58d98p10,
    -0x1.8db0a4ab22e7ep-9
  },
  { // Entry 200
    0x1.43e54975fb8bc8012953e9ef023f67b3p-100,
    0x1.c37dac37dac3cp0,
    0x1.64d9364d93659p100
  },
  { // Entry 201
    -0x1.43e54975fb8bc8012953e9ef023f67b3p-100,
    -0x1.c37dac37dac3cp0,
    0x1.64d9364d93659p100
  },
  { // Entry 202
    0x1.ab78c13521cfc80117f7fae57836356ep-98,
    0x1.c9b26c9b26ca0p2,
    0x1.1219dbcc48679p100
  },
  { // Entry 203
    -0x1.ab78c13521cfc80117f7fae57836356ep-98,
    -0x1.c9b26c9b26ca0p2,
    0x1.1219dbcc48679p100
  },
  { // Entry 204
    0x1.77e467d5ff6337f84f880eb86f426f87p-1,
    0x1.ce0d5078ae3d0p0,
    0x1.0p1
  },
  { // Entry 205
    -0x1.77e467d5ff6337f84f880eb86f426f87p-1,
    -0x1.ce0d5078ae3d0p0,
    0x1.0p1
  },
  { // Entry 206
    0x1.7ccd882d8fdbe8010d0be61f023186a5p-1,
    0x1.dbcc48676f32ap7,
    0x1.0295fad40a58bp8
  },
  { // Entry 207
    -0x1.7ccd882d8fdbe8010d0be61f023186a5p-1,
    -0x1.dbcc48676f32ap7,
    0x1.0295fad40a58bp8
  },
  { // Entry 208
    0x1.2d3a87e24eb319156ef615caa7abe128p0,
    0x1.e052bf5a814b6p2,
    0x1.8f83e0f83e0f1p1
  },
  { // Entry 209
    -0x1.2d3a87e24eb319156ef615caa7abe128p0,
    -0x1.e052bf5a814b6p2,
    0x1.8f83e0f83e0f1p1
  },
  { // Entry 210
    0x1.eb0df42c36a5f7fe1df8c86bed0a28a0p-1,
    0x1.e0547e40e4cc8p-2,
    0x1.50eebc195bb24p-2
  },
  { // Entry 211
    -0x1.eb0df42c36a5f7fe1df8c86bed0a28a0p-1,
    -0x1.e0547e40e4cc8p-2,
    0x1.50eebc195bb24p-2
  },
  { // Entry 212
    0x1.c7fe1dbd95349778458697fe195e4a58p-8,
    0x1.e666666666668p1,
    0x1.111111111196dp9
  },
  { // Entry 213
    -0x1.c7fe1dbd95349778458697fe195e4a58p-8,
    -0x1.e666666666668p1,
    0x1.111111111196dp9
  },
  { // Entry 214
    0x1.38927ede67216800006a39bb49e9c0f4p0,
    0x1.e666666b987f5p0,
    0x1.62e42fefa39efp-1
  },
  { // Entry 215
    -0x1.38927ede67216800006a39bb49e9c0f4p0,
    -0x1.e666666b987f5p0,
    0x1.62e42fefa39efp-1
  },
  { // Entry 216
    0x1.39fed5699428b3b69a7339d36bb044abp-1,
    0x1.e91ee78afd1e6p-3,
    0x1.5b7c32b32bde0p-2
  },
  { // Entry 217
    -0x1.39fed5699428b3b69a7339d36bb044abp-1,
    -0x1.e91ee78afd1e6p-3,
    0x1.5b7c32b32bde0p-2
  },
  { // Entry 218
    0x1.a127224010cba803945f315e1d0ee4b5p-1,
    0x1.f166e1dc4499bp2,
    0x1.d50692986b98fp2
  },
  { // Entry 219
    -0x1.a127224010cba803945f315e1d0ee4b5p-1,
    -0x1.f166e1dc4499bp2,
    0x1.d50692986b98fp2
  },
  { // Entry 220
    0x1.f1f32aa6acb70801dd4349d43d3d4c25p-3,
    0x1.fbfffffffffffp-2,
    0x1.ffffffffe7fffp0
  },
  { // Entry 221
    -0x1.f1f32aa6acb70801dd4349d43d3d4c25p-3,
    -0x1.fbfffffffffffp-2,
    0x1.ffffffffe7fffp0
  },
  { // Entry 222
    0x1.079c41361b6ab8115015e4f32dcfe4b3p1,
    0x1.ff4b7c848cde6p-1,
    -0x1.0fd6c7f44f588p-1
  },
  { // Entry 223
    -0x1.079c41361b6ab8115015e4f32dcfe4b3p1,
    -0x1.ff4b7c848cde6p-1,
    -0x1.0fd6c7f44f588p-1
  },
  { // Entry 224
    0x1.da4c6912789968011f1b516f595d868ep-2,
    0x1.ff677ffffffffp-6,
    0x1.ffffffff19fffp-5
  },
  { // Entry 225
    -0x1.da4c6912789968011f1b516f595d868ep-2,
    -0x1.ff677ffffffffp-6,
    0x1.ffffffff19fffp-5
  },
  { // Entry 226
    0x1.fffc80021ffc480225fc1d822a9bc5e0p-58,
    0x1.fffc7ffffffffp-50,
    0x1.fffffffddffffp7
  },
  { // Entry 227
    -0x1.fffc80021ffc480225fc1d822a9bc5e0p-58,
    -0x1.fffc7ffffffffp-50,
    0x1.fffffffddffffp7
  },
  { // Entry 228
    0x1.66666666666617fffffffffff8b72015p-50,
    0x1.ffffffffffffcp50,
    0x1.6db6db6db6db9p100
  },
  { // Entry 229
    -0x1.66666666666617fffffffffff8b72015p-50,
    -0x1.ffffffffffffcp50,
    0x1.6db6db6db6db9p100
  },
  { // Entry 230
    0x1.ff55d35ae8e467ce77407069ad013ab5p-5,
    0x1.ffffffffffffep-3,
    0x1.ffffe7fffffffp1
  },
  { // Entry 231
    -0x1.ff55d35ae8e467ce77407069ad013ab5p-5,
    -0x1.ffffffffffffep-3,
    0x1.ffffe7fffffffp1
  },
  { // Entry 232
    0x1.b4ddd66a37b3b335a2a5b11ceb9a4c56p-2,
    0x1.ffffffffffffep-4,
    0x1.199999999999cp-2
  },
  { // Entry 233
    -0x1.b4ddd66a37b3b335a2a5b11ceb9a4c56p-2,
    -0x1.ffffffffffffep-4,
    0x1.199999999999cp-2
  },
  { // Entry 234
    0x1.90e6d4253517c8010321aeae887990a9p1,
    0x1.ffffffffffffep-7,
    -0x1.a2e8ba2e97a22p0
  },
  { // Entry 235
    -0x1.90e6d4253517c8010321aeae887990a9p1,
    -0x1.ffffffffffffep-7,
    -0x1.a2e8ba2e97a22p0
  },
  { // Entry 236
    0x1.b6db6db6db6d281ddaaea5b12cced2a1p-25,
    0x1.ffffffffffffep-25,
    0x1.2aaaaaaaaaaabp0
  },
  { // Entry 237
    -0x1.b6db6db6db6d281ddaaea5b12cced2a1p-25,
    -0x1.ffffffffffffep-25,
    0x1.2aaaaaaaaaaabp0
  },
  { // Entry 238
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.ffffffffffffep-807,
    -0x1.745d1745d173cp-3
  },
  { // Entry 239
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.ffffffffffffep-807,
    -0x1.745d1745d173cp-3
  },
  { // Entry 240
    0x1.096d05371b1c54c40f9a06c6cf2db981p1,
    0x1.ffffffffffffep0,
    -0x1.199999999999ap0
  },
  { // Entry 241
    -0x1.096d05371b1c54c40f9a06c6cf2db981p1,
    -0x1.ffffffffffffep0,
    -0x1.199999999999ap0
  },
  { // Entry 242
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    0x1.4p-1072
  },
  { // Entry 243
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    0x1.4p-1072
  },
  { // Entry 244
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 245
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 246
    -0x1.f4f3b198c0f168030e9490be1ea559e8p-4,
    -0x1.08de20fafe4a2p0,
    0x1.0d5ba77adf969p3
  },
  { // Entry 247
    0x1.f4f3b198c0f168030e9490be1ea559e8p-4,
    0x1.08de20fafe4a2p0,
    0x1.0d5ba77adf969p3
  },
  { // Entry 248
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 249
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 250
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 251
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 252
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.0p0,
    -0x1.0p0
  },
  { // Entry 253
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.0p0,
    -0x1.0p0
  },
  { // Entry 254
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 255
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 256
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p0,
    0x1.0p0
  },
  { // Entry 257
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p0,
    0x1.0p0
  },
  { // Entry 258
    0x1.fd5ba9aac2f6dc65912f313e7d111defp-4,
    0x1.0p0,
    0x1.0p3
  },
  { // Entry 259
    -0x1.fd5ba9aac2f6dc65912f313e7d111defp-4,
    -0x1.0p0,
    0x1.0p3
  },
  { // Entry 260
    0x1.7249faa996a216a33079d20319e727c3p0,
    0x1.0p3,
    0x1.0p0
  },
  { // Entry 261
    -0x1.7249faa996a216a33079d20319e727c3p0,
    -0x1.0p3,
    0x1.0p0
  },
  { // Entry 262
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p3,
    0x1.0p3
  },
  { // Entry 263
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p3,
    0x1.0p3
  },
  { // Entry 264
    0x1.ffffd5555bbbba9729ab7aac089473a3p-10,
    0x1.0p0,
    0x1.0p9
  },
  { // Entry 265
    -0x1.ffffd5555bbbba9729ab7aac089473a3p-10,
    -0x1.0p0,
    0x1.0p9
  },
  { // Entry 266
    0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    0x1.0p0,
    0x1.0p10
  },
  { // Entry 267
    -0x1.fffff55555bbbbb72972d00cfde752f9p-11,
    -0x1.0p0,
    0x1.0p10
  },
  { // Entry 268
    0x1.fff555bbb729ab77cf18ac802beec090p-7,
    0x1.0p3,
    0x1.0p9
  },
  { // Entry 269
    -0x1.fff555bbb729ab77cf18ac802beec090p-7,
    -0x1.0p3,
    0x1.0p9
  },
  { // Entry 270
    0x1.fffd555bbba972d00c46a3f77cc15e8ep-8,
    0x1.0p3,
    0x1.0p10
  },
  { // Entry 271
    -0x1.fffd555bbba972d00c46a3f77cc15e8ep-8,
    -0x1.0p3,
    0x1.0p10
  },
  { // Entry 272
    0x1.ffffffffffffffffffffffffffffffffp-101,
    0x1.0p0,
    0x1.0p100
  },
  { // Entry 273
    -0x1.ffffffffffffffffffffffffffffffffp-101,
    -0x1.0p0,
    0x1.0p100
  },
  { // Entry 274
    0x1.ffffffffffffffffffffffffffffffffp-102,
    0x1.0p0,
    0x1.0p101
  },
  { // Entry 275
    -0x1.ffffffffffffffffffffffffffffffffp-102,
    -0x1.0p0,
    0x1.0p101
  },
  { // Entry 276
    0x1.ffffffffffffffffffffffffffffffffp-98,
    0x1.0p3,
    0x1.0p100
  },
  { // Entry 277
    -0x1.ffffffffffffffffffffffffffffffffp-98,
    -0x1.0p3,
    0x1.0p100
  },
  { // Entry 278
    0x1.ffffffffffffffffffffffffffffffffp-99,
    0x1.0p3,
    0x1.0p101
  },
  { // Entry 279
    -0x1.ffffffffffffffffffffffffffffffffp-99,
    -0x1.0p3,
    0x1.0p101
  },
  { // Entry 280
    0x1.919fb54eed7a957ae3c25a3856b61485p0,
    0x1.0p9,
    0x1.0p0
  },
  { // Entry 281
    -0x1.919fb54eed7a957ae3c25a3856b61485p0,
    -0x1.0p9,
    0x1.0p0
  },
  { // Entry 282
    0x1.8e1fca98cb63311299ee93be01605c21p0,
    0x1.0p9,
    0x1.0p3
  },
  { // Entry 283
    -0x1.8e1fca98cb63311299ee93be01605c21p0,
    -0x1.0p9,
    0x1.0p3
  },
  { // Entry 284
    0x1.91dfb5459826ccf212a796bd00187cb7p0,
    0x1.0p10,
    0x1.0p0
  },
  { // Entry 285
    -0x1.91dfb5459826ccf212a796bd00187cb7p0,
    -0x1.0p10,
    0x1.0p0
  },
  { // Entry 286
    0x1.901fb7eee715daf6b9807e730a3b7843p0,
    0x1.0p10,
    0x1.0p3
  },
  { // Entry 287
    -0x1.901fb7eee715daf6b9807e730a3b7843p0,
    -0x1.0p10,
    0x1.0p3
  },
  { // Entry 288
    0
```
Response:
Let's break down the thought process for analyzing this C code snippet and generating the comprehensive response.

**1. Initial Understanding and Keyword Extraction:**

* **File Information:** The first step is to understand the context: `bionic/tests/math_data/powf_intel_data.handroid`. This tells us:
    * `bionic`:  Part of Android's core C library.
    * `tests`: This file is likely used for testing.
    * `math_data`:  The data relates to mathematical functions.
    * `powf`:  Specifically related to the `powf` function (floating-point power).
    * `intel_data`:  Potentially optimized or specific to Intel architectures.
    * `.handroid`: This suffix might indicate Android-specific test data or a format used within Android's testing infrastructure.
* **Data Structure:** The code defines a constant array named `data` of a structure. Each element of the array seems to represent a test case for the `powf` function.
* **Structure Members:** Each structure has three `float` members. Based on the context of `powf`, these likely represent:
    * Expected Result
    * Base (x in x<sup>y</sup>)
    * Exponent (y in x<sup>y</sup>)

**2. Functionality Identification:**

Based on the identified keywords and the structure of the data, the primary function of this file is clearly to provide test data for the `powf` function. It contains various input values (base and exponent) and their corresponding expected output values. This is a common practice in software development for verifying the correctness of mathematical functions.

**3. Relationship to Android:**

* **Bionic:**  The file's location within the `bionic` directory immediately establishes a strong connection to Android. Bionic is Android's standard C library, akin to `glibc` on Linux. This means the `powf` function being tested is *the* `powf` function used by Android applications.
* **Testing:** The `tests` directory reinforces this. Android needs to ensure its core libraries function correctly across various hardware and scenarios. These data files are part of that testing process.
* **NDK:** The NDK (Native Development Kit) allows developers to write native code (C/C++) for Android. When an NDK application calls `powf`, it's ultimately calling the implementation in Bionic, and the correctness of that implementation is validated partly through data like this.

**4. Libc Function Explanation (powf):**

The request asks for a detailed explanation of `powf`. The thought process here would involve:

* **Standard Definition:**  Recall the standard C library definition of `powf(float base, float exponent)`. It calculates `base` raised to the power of `exponent`.
* **Implementation Complexity:** Recognize that a direct implementation using repeated multiplication is inefficient and prone to precision errors for floating-point numbers and non-integer exponents.
* **Common Techniques:**  Think about the mathematical properties that can be used for efficient implementation:
    * **Logarithms and Exponents:**  The fundamental relationship: `x^y = exp(y * log(x))`. This is a primary approach.
    * **Special Cases:**  Consider edge cases and optimizations for specific inputs (e.g., exponent is 0, 1, 2, -1; base is 0, 1, negative). These often have simpler, faster solutions.
    * **Range Reduction:** For trigonometric functions, angles are often reduced to a smaller range (e.g., 0 to pi/2). While not directly applicable to `powf` in the same way, the *principle* of handling different input ranges differently applies (e.g., small exponents vs. large exponents).
* **Bionic Specifics (Hypothetical):** Since this is an Android file, consider potential optimizations or platform-specific handling within Bionic's `powf` implementation (though without the actual source code, this remains speculation). This might involve using specific CPU instructions (like SIMD) or different algorithms depending on the input range.

**5. Dynamic Linker:**

The dynamic linker is crucial for loading and linking shared libraries (`.so` files). The thought process here:

* **Shared Libraries:**  Realize that `libc.so` (or a similar name on Android) contains the implementation of `powf`. Applications don't have this code directly compiled in.
* **Linking Process:**  Describe the basic steps:
    * When an app starts, the dynamic linker (like `linker64` on 64-bit Android) is invoked.
    * It parses the app's executable and identifies required shared libraries.
    * It loads these `.so` files into memory.
    * It resolves symbols: When the app calls `powf`, the linker finds the actual address of the `powf` function within `libc.so`. This involves looking at symbol tables within the `.so` file.
    * Relocation:  Addresses within the shared library might need adjustments based on where it's loaded in memory.
* **SO Layout:**  Sketch a simple memory layout of an app and `libc.so` to illustrate how they reside in separate address spaces but are linked.
* **Hypothetical Linkage:** Describe how the call from the app to `powf` is redirected through the Global Offset Table (GOT) and Procedure Linkage Table (PLT) (these are common mechanisms in dynamic linking).

**6. Input/Output and Edge Cases:**

* **Test Data as Examples:**  The provided data *itself* serves as input/output examples. Pick a few entries and explain what they represent in terms of `powf`'s behavior.
* **Common Errors:** Think about typical mistakes developers make when using `powf`:
    * Domain Errors: Raising a negative number to a non-integer power.
    * Overflow/Underflow:  Extremely large or small results.
    * Precision Issues:  Floating-point inaccuracies.
    * Incorrect Data Types: Passing the wrong types of arguments (though the compiler usually catches this in modern C).

**7. Android Framework/NDK and Frida Hooking:**

* **Framework Call Chain:**  Trace a hypothetical path from a high-level Android framework function down to `powf`. This involves understanding layers of abstraction: Java framework calls native methods, which call into the C library. A simplified example is sufficient.
* **NDK Usage:** Explain how an NDK app directly calls `powf` from its C/C++ code.
* **Frida Hooking:**  Provide practical Frida examples to intercept calls to `powf`, showing how to inspect arguments and the return value. This requires basic Frida syntax.

**8. Part 2 Summarization:**

Finally, synthesize the information from the analysis to provide a concise summary of the file's purpose and key characteristics.

**Self-Correction/Refinement During the Process:**

* **Initially might focus too much on specific assembly-level details of `powf`:**  Realize that without the actual Bionic source, this is speculative and a higher-level explanation of common techniques is more appropriate.
* **Consider the audience:** The request implies a need for both technical depth and clear explanations. Balance technical jargon with understandable language.
* **Ensure all parts of the prompt are addressed:**  Double-check that each question in the original request is answered comprehensively.
* **Use the provided data effectively:** Refer back to the data entries to illustrate points and provide concrete examples.

By following this structured approach, combining domain knowledge (C libraries, Android, dynamic linking, testing), and applying a bit of educated guessing where necessary (like the internal implementation of `powf`), it's possible to generate a detailed and accurate response to the prompt.
好的，让我们归纳一下 `bionic/tests/math_data/powf_intel_data.handroid` 这个文件的功能。

**功能归纳:**

这个 C 源代码文件，`powf_intel_data.handroid`，是 Android Bionic 库中用于测试 `powf` 函数（单精度浮点数幂运算）的一组测试数据集合。  它的主要功能是：

1. **提供测试用例:** 文件中定义了一个名为 `data` 的常量结构体数组。每个结构体包含三个 `float` 类型的成员，分别代表 `powf` 函数的预期返回值、底数和指数。

2. **验证 `powf` 函数的正确性:**  这些测试用例旨在覆盖 `powf` 函数的不同输入情况，包括正常值、边界值、特殊值（如无穷大、零、NaN 等），以及不同数量级和精度的数值。通过将 `powf` 函数的实际计算结果与这些预期的返回值进行比较，可以验证 `powf` 函数在 Intel 架构上的实现是否正确。

3. **回归测试:**  作为测试数据，这个文件可以用于回归测试。当 Bionic 库中的 `powf` 函数被修改或优化后，可以重新运行这些测试用例，以确保修改没有引入新的错误，并保持其原有的正确性。

4. **性能测试（间接):**  虽然主要目的是功能测试，但大量的测试用例也可以在一定程度上反映 `powf` 函数的性能。如果测试运行时间过长，可能暗示 `powf` 函数的实现效率不高。

**与 Android 功能的关系举例:**

Android 系统和运行在其上的应用程序广泛使用 `powf` 函数进行各种数学计算，例如：

* **图形渲染:**  计算光照、阴影、纹理坐标等可能涉及幂运算。
* **游戏开发:**  角色移动、物理模拟、特效处理等 часто используют幂函数。
* **科学计算应用:**  各种科学计算，如物理、化学、工程等领域的模型计算。
* **机器学习和人工智能:**  一些算法中会用到幂运算。

例如，一个 Android 游戏可能需要计算一个物体在特定速度和时间下的运动轨迹，其中可能涉及到 `powf` 来计算指数衰减或者加速。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件中并没有直接实现任何 libc 函数。它仅仅是 `powf` 函数的测试数据。  `powf` 函数本身的实现位于 Bionic 库的其他源文件中（例如 `bionic/libm/upstream-freebsd/lib/msun/src/s_powf.c`）。

`powf(float x, float y)` 函数的实现通常会考虑以下情况和方法：

1. **特殊情况处理:**
   * 如果 `y` 是 0，返回 1。
   * 如果 `x` 是 1，返回 1。
   * 如果 `x` 是 -1，且 `y` 是整数，根据 `y` 的奇偶性返回 1 或 -1。如果 `y` 不是整数，则结果是 NaN。
   * 如果 `x` 是 0，且 `y` 是正数，返回 0。
   * 如果 `x` 是 0，且 `y` 是负数，返回无穷大（正或负取决于 `y`）。
   * 如果 `x` 是正无穷大，且 `y` 是正数，返回正无穷大。
   * 如果 `x` 是正无穷大，且 `y` 是负数，返回 0。
   * 如果 `x` 是 0，且 `y` 是正数，返回 0。
   * 如果 `x` 是 0，且 `y` 是负数，则抛出 domain error 或返回 NaN。
   * 如果 `x` 是负数，且 `y` 不是整数，则返回 NaN。

2. **基于对数和指数的计算:** 对于一般情况，`powf(x, y)` 可以通过以下公式计算：
   `powf(x, y) = expf(y * logf(fabsf(x)))`

   * `fabsf(x)`: 计算 `x` 的绝对值。
   * `logf(z)`: 计算 `z` 的自然对数。
   * `expf(w)`: 计算 `e` 的 `w` 次方。

3. **整数指数的优化:** 如果 `y` 是整数，可以使用更高效的算法，如**平方乘算法**（Exponentiation by squaring），避免多次调用 `logf` 和 `expf`，提高精度和性能。

4. **微调和精度处理:**  由于浮点数的精度限制，实际实现中可能需要进行一些微调和误差补偿，以确保结果的准确性。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个数据文件本身不涉及 dynamic linker 的功能。Dynamic linker 的工作是在程序运行时加载和链接共享库。`powf` 函数的实现位于 `libc.so` (或 Android 版本对应的库名称)。

**SO 布局样本:**

假设一个简单的 Android 应用程序使用了 `powf` 函数，其内存布局可能如下所示（简化）：

```
[应用程序的内存空间]
---------------------
|  .text (代码段)   |  // 应用程序自身的代码
---------------------
|  .rodata (只读数据) |
---------------------
|  .data (数据段)   |
---------------------
|  .bss (未初始化数据) |
---------------------
|  Stack (栈)       |
---------------------
|  Heap (堆)        |
---------------------
|  [libc.so 的内存映射] |
---------------------
|  libc.so .text    |  // libc.so 的代码，包含 powf 的实现
---------------------
|  libc.so .rodata  |
---------------------
|  libc.so .data    |
---------------------
|  ...               |
---------------------
```

**链接的处理过程:**

1. **编译时:** 当应用程序的代码中调用了 `powf` 函数时，编译器会生成一个对外部符号 `powf` 的引用。链接器（静态链接器或在 Android 上更多是动态链接器参与的链接过程）会记录这个引用。

2. **运行时:**
   * 当应用程序启动时，Android 的 **动态链接器 (linker)** (例如 `linker` 或 `linker64`) 负责加载应用程序依赖的共享库，包括 `libc.so`。
   * 动态链接器会解析应用程序的可执行文件头部，找到所需的共享库列表。
   * 动态链接器将 `libc.so` 加载到进程的地址空间中。
   * **符号解析 (Symbol Resolution):** 动态链接器会查找 `libc.so` 的符号表，找到 `powf` 函数的地址。
   * **重定位 (Relocation):**  由于共享库被加载到内存中的地址可能不是编译时预期的地址，动态链接器需要修改应用程序代码中对 `powf` 函数的引用，将其指向 `libc.so` 中 `powf` 函数的实际加载地址。这通常通过 **GOT (Global Offset Table)** 和 **PLT (Procedure Linkage Table)** 机制来实现。
     * 当应用程序第一次调用 `powf` 时，会跳转到 PLT 中的一个桩代码。
     * 这个桩代码会调用动态链接器来解析 `powf` 的实际地址。
     * 动态链接器将 `powf` 的地址写入 GOT 中对应的条目。
     * 下次调用 `powf` 时，会直接从 GOT 中获取地址，而不需要再次调用动态链接器，提高了效率。

**如果做了逻辑推理，请给出假设输入与输出:**

这个文件中的数据就是预设的输入和期望的输出。 例如：

* **假设输入:** 底数为 `HUGE_VALF` (正无穷大)，指数为 `0x1.000002p7` (十进制大约 128.00003)。
* **预期输出:**  `HUGE_VALF` (正无穷大)，因为正无穷大的正数次幂仍然是正无穷大。

* **假设输入:** 底数为 `0.0f`，指数为 `0x1.fffffcp0` (接近 2.0)。
* **预期输出:** `0.0f`，因为 0 的正数次幂是 0。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然这个文件是测试数据，但可以反推用户在使用 `powf` 时可能遇到的错误：

1. **Domain Error (定义域错误):**
   * **错误示例:**  计算负数的非整数次幂，例如 `powf(-2.0f, 0.5f)`。这在实数域中没有定义，`powf` 通常会返回 NaN 或引发错误。
   * **此文件中对应的测试用例:** 可能存在底数为负数，指数为非整数的用例，预期输出为 NaN。

2. **Overflow/Underflow (溢出/下溢):**
   * **错误示例:** 计算一个非常大的数的非常大的次方，导致结果超出 `float` 类型的表示范围（溢出），或者计算一个非常小的正数的非常大的负次方，导致结果非常接近于零（下溢）。
   * **此文件中对应的测试用例:**  存在底数和指数都很大的用例，预期输出为 `HUGE_VALF` (正无穷大)，或者底数很小，指数很大且为负数的用例，预期输出为接近 0 的值。

3. **精度问题:** 浮点数计算本身存在精度问题。
   * **错误示例:** 期望得到一个精确的结果，但由于浮点数的表示限制，实际结果可能存在微小的误差。
   * **此文件中对应的测试用例:**  很多用例的预期输出和输入都精确到浮点数的表示精度，用于验证 `powf` 的实现是否在可接受的误差范围内。

4. **参数类型错误:** 虽然 C 编译器通常会捕获这种错误，但有时也可能因为类型转换等问题导致意外结果。
   * **错误示例:** 将整数类型传递给 `powf`，虽然会隐式转换为 `float`，但在某些极端情况下可能导致非预期的行为。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `powf` 的路径 (示例):**

1. **Java Framework 层:**  Android 应用通常使用 Java API。例如，可能在 `android.graphics.Color` 类的某些计算中涉及到幂运算，或者在自定义 View 的动画效果计算中。

2. **JNI (Java Native Interface):** 如果 Java Framework 需要进行高性能的数学计算，可能会通过 JNI 调用 Native 代码 (C/C++)。

3. **NDK (Native Development Kit):**  开发者可以使用 NDK 编写 C/C++ 代码，这些代码可以直接调用 Bionic 库中的函数，包括 `powf`。

4. **Bionic Libc (`libc.so`):**  NDK 代码中对 `powf` 的调用最终会链接到 Bionic 库中的 `powf` 实现。

**NDK 直接调用 `powf`:**

如果一个应用是使用 NDK 开发的，它可以直接在 C/C++ 代码中调用 `powf`:

```c++
#include <cmath>
#include <android/log.h>

#define TAG "PowfTest"

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MainActivity_calculatePower(
        JNIEnv* env,
        jobject /* this */,
        jfloat base,
        jfloat exponent) {
    float result = powf(base, exponent);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "powf(%f, %f) = %f", base, exponent, result);
}
```

**Frida Hook 示例:**

可以使用 Frida hook NDK 代码或 Bionic 库中的 `powf` 函数，来观察其输入和输出。

**Hook NDK 中的 `powf` 调用:**

假设你有一个 NDK 应用，并且你想 hook 上面 `calculatePower` 函数中对 `powf` 的调用。你需要找到你的应用的 native 库以及 `calculatePower` 函数的地址。

```javascript
Java.perform(function() {
    var MainActivity = Java.use("com.example.myapp.MainActivity");
    MainActivity.calculatePower.implementation = function(base, exponent) {
        console.log("Hooking MainActivity.calculatePower");
        console.log("Base:", base);
        console.log("Exponent:", exponent);
        var result = this.calculatePower(base, exponent);
        console.log("Result:", result);
        return result;
    };
});
```

**Hook Bionic 库中的 `powf` 函数:**

要 hook Bionic 库中的 `powf` 函数，你需要找到 `libc.so` 的加载地址以及 `powf` 函数的偏移量。

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "powf"), {
    onEnter: function(args) {
        console.log("Calling powf with base:", args[0], "and exponent:", args[1]);
    },
    onLeave: function(retval) {
        console.log("powf returned:", retval);
    }
});
```

**注意:** Hook 系统库函数可能需要 root 权限或者使用特定的 Frida 配置。你需要根据你的具体环境和需求调整 Frida 脚本。

总结来说，`bionic/tests/math_data/powf_intel_data.handroid` 是一个至关重要的测试数据文件，用于确保 Android 系统核心数学库函数 `powf` 在 Intel 架构上的正确性和可靠性。它间接地影响着运行在 Android 上的各种应用程序的数学计算精度和稳定性。

### 提示词
```
这是目录为bionic/tests/math_data/powf_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
002p1, 0x1.000002p7
  },
  { // Entry 376
    HUGE_VALF,
    0x1.000002p1, 0x1.000004p7
  },
  { // Entry 377
    HUGE_VALF,
    0x1.000004p1, 0x1.fffffcp6
  },
  { // Entry 378
    HUGE_VALF,
    0x1.000004p1, 0x1.fffffep6
  },
  { // Entry 379
    HUGE_VALF,
    0x1.000004p1, 0x1.p7
  },
  { // Entry 380
    HUGE_VALF,
    0x1.000004p1, 0x1.000002p7
  },
  { // Entry 381
    HUGE_VALF,
    0x1.000004p1, 0x1.000004p7
  },
  { // Entry 382
    0.0f,
    0x1.fffffcp0, -0x1.2c0004p7
  },
  { // Entry 383
    0.0f,
    0x1.fffffcp0, -0x1.2c0002p7
  },
  { // Entry 384
    0.0f,
    0x1.fffffcp0, -0x1.2cp7
  },
  { // Entry 385
    0.0f,
    0x1.fffffcp0, -0x1.2bfffep7
  },
  { // Entry 386
    0.0f,
    0x1.fffffcp0, -0x1.2bfffcp7
  },
  { // Entry 387
    0.0f,
    0x1.fffffep0, -0x1.2c0004p7
  },
  { // Entry 388
    0.0f,
    0x1.fffffep0, -0x1.2c0002p7
  },
  { // Entry 389
    0.0f,
    0x1.fffffep0, -0x1.2cp7
  },
  { // Entry 390
    0.0f,
    0x1.fffffep0, -0x1.2bfffep7
  },
  { // Entry 391
    0.0f,
    0x1.fffffep0, -0x1.2bfffcp7
  },
  { // Entry 392
    0.0f,
    0x1.p1, -0x1.2c0004p7
  },
  { // Entry 393
    0.0f,
    0x1.p1, -0x1.2c0002p7
  },
  { // Entry 394
    0.0f,
    0x1.p1, -0x1.2cp7
  },
  { // Entry 395
    0.0f,
    0x1.p1, -0x1.2bfffep7
  },
  { // Entry 396
    0.0f,
    0x1.p1, -0x1.2bfffcp7
  },
  { // Entry 397
    0.0f,
    0x1.000002p1, -0x1.2c0004p7
  },
  { // Entry 398
    0.0f,
    0x1.000002p1, -0x1.2c0002p7
  },
  { // Entry 399
    0.0f,
    0x1.000002p1, -0x1.2cp7
  },
  { // Entry 400
    0.0f,
    0x1.000002p1, -0x1.2bfffep7
  },
  { // Entry 401
    0.0f,
    0x1.000002p1, -0x1.2bfffcp7
  },
  { // Entry 402
    0.0f,
    0x1.000004p1, -0x1.2c0004p7
  },
  { // Entry 403
    0.0f,
    0x1.000004p1, -0x1.2c0002p7
  },
  { // Entry 404
    0.0f,
    0x1.000004p1, -0x1.2cp7
  },
  { // Entry 405
    0.0f,
    0x1.000004p1, -0x1.2bfffep7
  },
  { // Entry 406
    0.0f,
    0x1.000004p1, -0x1.2bfffcp7
  },
  { // Entry 407
    0.0f,
    0x1.db6db2p-2, 0x1.c30c2cp8
  },
  { // Entry 408
    0.0f,
    0x1.db6db2p-2, 0x1.c30c2ep8
  },
  { // Entry 409
    0.0f,
    0x1.db6db2p-2, 0x1.c30c30p8
  },
  { // Entry 410
    0.0f,
    0x1.db6db2p-2, 0x1.c30c32p8
  },
  { // Entry 411
    0.0f,
    0x1.db6db2p-2, 0x1.c30c34p8
  },
  { // Entry 412
    0.0f,
    0x1.db6db4p-2, 0x1.c30c2cp8
  },
  { // Entry 413
    0.0f,
    0x1.db6db4p-2, 0x1.c30c2ep8
  },
  { // Entry 414
    0.0f,
    0x1.db6db4p-2, 0x1.c30c30p8
  },
  { // Entry 415
    0.0f,
    0x1.db6db4p-2, 0x1.c30c32p8
  },
  { // Entry 416
    0.0f,
    0x1.db6db4p-2, 0x1.c30c34p8
  },
  { // Entry 417
    0.0f,
    0x1.db6db6p-2, 0x1.c30c2cp8
  },
  { // Entry 418
    0.0f,
    0x1.db6db6p-2, 0x1.c30c2ep8
  },
  { // Entry 419
    0.0f,
    0x1.db6db6p-2, 0x1.c30c30p8
  },
  { // Entry 420
    0.0f,
    0x1.db6db6p-2, 0x1.c30c32p8
  },
  { // Entry 421
    0.0f,
    0x1.db6db6p-2, 0x1.c30c34p8
  },
  { // Entry 422
    0.0f,
    0x1.db6db8p-2, 0x1.c30c2cp8
  },
  { // Entry 423
    0.0f,
    0x1.db6db8p-2, 0x1.c30c2ep8
  },
  { // Entry 424
    0.0f,
    0x1.db6db8p-2, 0x1.c30c30p8
  },
  { // Entry 425
    0.0f,
    0x1.db6db8p-2, 0x1.c30c32p8
  },
  { // Entry 426
    0.0f,
    0x1.db6db8p-2, 0x1.c30c34p8
  },
  { // Entry 427
    0.0f,
    0x1.db6dbap-2, 0x1.c30c2cp8
  },
  { // Entry 428
    0.0f,
    0x1.db6dbap-2, 0x1.c30c2ep8
  },
  { // Entry 429
    0.0f,
    0x1.db6dbap-2, 0x1.c30c30p8
  },
  { // Entry 430
    0.0f,
    0x1.db6dbap-2, 0x1.c30c32p8
  },
  { // Entry 431
    0.0f,
    0x1.db6dbap-2, 0x1.c30c34p8
  },
  { // Entry 432
    -0x1.fffffc000007fffff000001fffffc0p-1,
    -0x1.000002p0, -0x1.p0
  },
  { // Entry 433
    -0x1.p0,
    -0x1.p0, -0x1.p0
  },
  { // Entry 434
    -0x1.000001000001000001000001000001p0,
    -0x1.fffffep-1, -0x1.p0
  },
  { // Entry 435
    HUGE_VALF,
    0x1.p1, 0x1.p10
  },
  { // Entry 436
    HUGE_VALF,
    0x1.p2, 0x1.p9
  },
  { // Entry 437
    0.0f,
    0x1.fffffep-2, 0x1.fffffep9
  },
  { // Entry 438
    0.0f,
    0x1.fffffep-2, 0x1.p10
  },
  { // Entry 439
    0.0f,
    0x1.fffffep-2, 0x1.000002p10
  },
  { // Entry 440
    0.0f,
    0x1.p-1, 0x1.fffffep9
  },
  { // Entry 441
    0.0f,
    0x1.p-1, 0x1.p10
  },
  { // Entry 442
    0.0f,
    0x1.p-1, 0x1.000002p10
  },
  { // Entry 443
    0.0f,
    0x1.000002p-1, 0x1.fffffep9
  },
  { // Entry 444
    0.0f,
    0x1.000002p-1, 0x1.p10
  },
  { // Entry 445
    0.0f,
    0x1.000002p-1, 0x1.000002p10
  },
  { // Entry 446
    0x1.00020467109547572fa8f3f653eda548p-149,
    0x1.p-149, 0x1.fffff6p-1
  },
  { // Entry 447
    0x1.00019d1eed21f448f2c6217eab3d9c55p-149,
    0x1.p-149, 0x1.fffff8p-1
  },
  { // Entry 448
    0x1.000135d6f3596e086d463376a9dbd1e2p-149,
    0x1.p-149, 0x1.fffffap-1
  },
  { // Entry 449
    0x1.0000ce8f233ba3c64adc5667a7b0b245p-149,
    0x1.p-149, 0x1.fffffcp-1
  },
  { // Entry 450
    0x1.000067477cc884b33e03d0bb77571150p-149,
    0x1.p-149, 0x1.fffffep-1
  },
  { // Entry 451
    0x1.p-149,
    0x1.p-149, 0x1.p0
  },
  { // Entry 452
    0.0f,
    0x1.p-149, 0x1.000002p0
  },
  { // Entry 453
    0.0f,
    0x1.p-149, 0x1.000004p0
  },
  { // Entry 454
    0.0f,
    0x1.p-149, 0x1.000006p0
  },
  { // Entry 455
    0.0f,
    0x1.p-149, 0x1.000008p0
  },
  { // Entry 456
    0.0f,
    0x1.p-149, 0x1.00000ap0
  },
  { // Entry 457
    0x1.000200efcf25bab1c7cd22827341ab63p-148,
    0x1.p-148, 0x1.fffff6p-1
  },
  { // Entry 458
    0x1.00019a59204c82fe060cf6d320f15433p-148,
    0x1.p-148, 0x1.fffff8p-1
  },
  { // Entry 459
    0x1.000133c29a8f64f204da13b72ebc56edp-148,
    0x1.p-148, 0x1.fffffap-1
  },
  { // Entry 460
    0x1.0000cd2c3dee501480729506593fd68bp-148,
    0x1.p-148, 0x1.fffffcp-1
  },
  { // Entry 461
    0x1.000066960a6933ec3bae8cab9ccfd543p-148,
    0x1.p-148, 0x1.fffffep-1
  },
  { // Entry 462
    0x1.p-148,
    0x1.p-148, 0x1.p0
  },
  { // Entry 463
    0x1.fffe65a8cd021dedd55a40c272dc8acap-149,
    0x1.p-148, 0x1.000002p0
  },
  { // Entry 464
    0x1.fffccb52e2e1f2602021820ab47036fep-149,
    0x1.p-148, 0x1.000004p0
  },
  { // Entry 465
    0x1.fffb30fe419e75c552c074b75e9e132dp-149,
    0x1.p-148, 0x1.000006p0
  },
  { // Entry 466
    0x1.fff996aae936a08cb2de3b831326836cp-149,
    0x1.p-148, 0x1.000008p0
  },
  { // Entry 467
    0x1.fff7fc58d9a96b26595dc1b91aab1065p-149,
    0x1.p-148, 0x1.00000ap0
  },
  { // Entry 468
    0x1.8002fe5d326e1910dcf5adadc4fb80bap-148,
    0x1.80p-148, 0x1.fffff6p-1
  },
  { // Entry 469
    0x1.80026516e130410cbc34d6be1f314af3p-148,
    0x1.80p-148, 0x1.fffff8p-1
  },
  { // Entry 470
    0x1.8001cbd0cd20048dc0041aae6853f414p-148,
    0x1.80p-148, 0x1.fffffap-1
  },
  { // Entry 471
    0x1.8001328af63d4b28b93bac168d323776p-148,
    0x1.80p-148, 0x1.fffffcp-1
  },
  { // Entry 472
    0x1.800099455c87fc728272d7993c3c0ed2p-148,
    0x1.80p-148, 0x1.fffffep-1
  },
  { // Entry 473
    0x1.80p-148,
    0x1.80p-148, 0x1.p0
  },
  { // Entry 474
    0x1.7ffecd75fe779c39da312a0ae6575aaep-148,
    0x1.80p-148, 0x1.000002p0
  },
  { // Entry 475
    0x1.7ffd9aecf1a35c7e2d6f67b9177b8bc8p-148,
    0x1.80p-148, 0x1.000004p0
  },
  { // Entry 476
    0x1.7ffc6864d9827d757b4b6001d0c80a9bp-148,
    0x1.80p-148, 0x1.000006p0
  },
  { // Entry 477
    0x1.7ffb35ddb6143bc8e145a6d616a1b551p-148,
    0x1.80p-148, 0x1.000008p0
  },
  { // Entry 478
    0x1.7ffa03578757d42218ce40a578c74476p-148,
    0x1.80p-148, 0x1.00000ap0
  },
  { // Entry 479
    0x1.000000a0cf65eb1817a7095d9a0443a7p0,
    0x1.p-29, -0x1.p-29
  },
  { // Entry 480
    0x1.ffffff5f309a60aad5c2309f81f90defp-1,
    0x1.p-29, 0x1.p-30
  },
  { // Entry 481
    0x1.fffffd9e07cf07767a55afbe9acae93ep-1,
    0x1.p55, -0x1.p-29
  },
  { // Entry 482
    0x1.000000987e0cc66344d89b494e1f43b3p0,
    0x1.p55, 0x1.p-30
  },
  { // Entry 483
    0x1.fffffd669427cf159515873887c17cf2p-1,
    0x1.p60, -0x1.p-29
  },
  { // Entry 484
    0x1.000000a65af6ae61be88ea2558790cd7p0,
    0x1.p60, 0x1.p-30
  },
  { // Entry 485
    0x1.ffc003ffb55aaa4cd34f3431ea5b77f1p-1,
    0x1.fffffep-1, 0x1.p13
  },
  { // Entry 486
    0x1.fe00ffa9c0fb3bf28c8a9b2b3d2d7daap-1,
    0x1.fffffep-1, 0x1.p16
  },
  { // Entry 487
    0x1.p0,
    0x1.p0, 0x1.p13
  },
  { // Entry 488
    0x1.p0,
    0x1.p0, 0x1.p16
  },
  { // Entry 489
    0x1.004008006aa554332b8fed09d8ed29f3p0,
    0x1.000002p0, 0x1.p13
  },
  { // Entry 490
    0x1.02020153fc405b123b33a73cb93a3648p0,
    0x1.000002p0, 0x1.p16
  },
  { // Entry 491
    0x1.2c15603269407006b8f35e8e4f1497bap-6,
    -0x1.000002p0, -0x1.p25
  },
  { // Entry 492
    0x1.c846887ee379c5af637c7349afc9f699p-47,
    -0x1.000002p0, -0x1.p28
  },
  { // Entry 493
    0x1.p0,
    -0x1.p0, -0x1.p25
  },
  { // Entry 494
    0x1.p0,
    -0x1.p0, -0x1.p28
  },
  { // Entry 495
    0x1.d8e64d66342891c86fb3c87d1ed6d5c5p2,
    -0x1.fffffep-1, -0x1.p25
  },
  { // Entry 496
    0x1.0f2ec583f611e4b8fc1cc7b50efbb738p23,
    -0x1.fffffep-1, -0x1.p28
  },
  { // Entry 497
    0x1.d8e64d66342891c86fb3c87d1ed6d5c5p2,
    0x1.fffffep-1, -0x1.p25
  },
  { // Entry 498
    0x1.0f2ec583f611e4b8fc1cc7b50efbb738p23,
    0x1.fffffep-1, -0x1.p28
  },
  { // Entry 499
    0x1.p0,
    0x1.p0, -0x1.p25
  },
  { // Entry 500
    0x1.p0,
    0x1.p0, -0x1.p28
  },
  { // Entry 501
    0x1.2c15603269407006b8f35e8e4f1497bap-6,
    0x1.000002p0, -0x1.p25
  },
  { // Entry 502
    0x1.c846887ee379c5af637c7349afc9f699p-47,
    0x1.000002p0, -0x1.p28
  },
  { // Entry 503
    HUGE_VALF,
    -0x1.p15, 0x1.p63
  },
  { // Entry 504
    HUGE_VALF,
    0.0f, -0x1.80p1
  },
  { // Entry 505
    -HUGE_VALF,
    -0.0f, -0x1.80p1
  },
  { // Entry 506
    HUGE_VALF,
    0.0f, -0x1.p0
  },
  { // Entry 507
    -HUGE_VALF,
    -0.0f, -0x1.p0
  },
  { // Entry 508
    HUGE_VALF,
    0.0f, -0x1.fffffep127
  },
  { // Entry 509
    HUGE_VALF,
    0.0f, -0x1.80p2
  },
  { // Entry 510
    HUGE_VALF,
    0.0f, -0x1.p1
  },
  { // Entry 511
    HUGE_VALF,
    0.0f, -0x1.000002p0
  },
  { // Entry 512
    HUGE_VALF,
    0.0f, -0x1.fffffep-1
  },
  { // Entry 513
    HUGE_VALF,
    0.0f, -0x1.p-126
  },
  { // Entry 514
    HUGE_VALF,
    0.0f, -0x1.p-149
  },
  { // Entry 515
    HUGE_VALF,
    -0.0f, -0x1.fffffep127
  },
  { // Entry 516
    HUGE_VALF,
    -0.0f, -0x1.80p2
  },
  { // Entry 517
    HUGE_VALF,
    -0.0f, -0x1.p1
  },
  { // Entry 518
    HUGE_VALF,
    -0.0f, -0x1.000002p0
  },
  { // Entry 519
    HUGE_VALF,
    -0.0f, -0x1.fffffep-1
  },
  { // Entry 520
    HUGE_VALF,
    -0.0f, -0x1.p-126
  },
  { // Entry 521
    HUGE_VALF,
    -0.0f, -0x1.p-149
  },
  { // Entry 522
    HUGE_VALF,
    0.0f, -HUGE_VALF
  },
  { // Entry 523
    HUGE_VALF,
    -0.0f, -HUGE_VALF
  },
  { // Entry 524
    0.0,
    0.0f, 0x1.80p1
  },
  { // Entry 525
    -0.0,
    -0.0f, 0x1.80p1
  },
  { // Entry 526
    0.0,
    0.0f, 0x1.p0
  },
  { // Entry 527
    -0.0,
    -0.0f, 0x1.p0
  },
  { // Entry 528
    0.0,
    0.0f, HUGE_VALF
  },
  { // Entry 529
    0.0,
    0.0f, 0x1.fffffep127
  },
  { // Entry 530
    0.0,
    0.0f, 0x1.80p2
  },
  { // Entry 531
    0.0,
    0.0f, 0x1.p1
  },
  { // Entry 532
    0.0,
    0.0f, 0x1.000002p0
  },
  { // Entry 533
    0.0,
    0.0f, 0x1.fffffep-1
  },
  { // Entry 534
    0.0,
    0.0f, 0x1.p-126
  },
  { // Entry 535
    0.0,
    0.0f, 0x1.p-149
  },
  { // Entry 536
    0.0,
    -0.0f, HUGE_VALF
  },
  { // Entry 537
    0.0,
    -0.0f, 0x1.fffffep127
  },
  { // Entry 538
    0.0,
    -0.0f, 0x1.80p2
  },
  { // Entry 539
    0.0,
    -0.0f, 0x1.p1
  },
  { // Entry 540
    0.0,
    -0.0f, 0x1.000002p0
  },
  { // Entry 541
    0.0,
    -0.0f, 0x1.fffffep-1
  },
  { // Entry 542
    0.0,
    -0.0f, 0x1.p-126
  },
  { // Entry 543
    0.0,
    -0.0f, 0x1.p-149
  },
  { // Entry 544
    0x1.p0,
    -0x1.p0, HUGE_VALF
  },
  { // Entry 545
    0x1.p0,
    -0x1.p0, -HUGE_VALF
  },
  { // Entry 546
    0x1.p0,
    0x1.p0, HUGE_VALF
  },
  { // Entry 547
    0x1.p0,
    0x1.p0, -HUGE_VALF
  },
  { // Entry 548
    0x1.p0,
    0x1.p0, 0x1.fffffep127
  },
  { // Entry 549
    0x1.p0,
    0x1.p0, -0x1.fffffep127
  },
  { // Entry 550
    0x1.p0,
    -0x1.p0, 0x1.fffffep127
  },
  { // Entry 551
    0x1.p0,
    -0x1.p0, -0x1.fffffep127
  },
  { // Entry 552
    0x1.p0,
    0x1.p0, 0x1.p-1
  },
  { // Entry 553
    0x1.p0,
    0x1.p0, -0x1.p-1
  },
  { // Entry 554
    0x1.p0,
    0x1.p0, 0x1.p-126
  },
  { // Entry 555
    0x1.p0,
    0x1.p0, -0x1.p-126
  },
  { // Entry 556
    0x1.p0,
    0x1.p0, 0x1.fffffcp-127
  },
  { // Entry 557
    0x1.p0,
    0x1.p0, -0x1.fffffcp-127
  },
  { // Entry 558
    0x1.p0,
    0x1.p0, 0x1.p-149
  },
  { // Entry 559
    0x1.p0,
    0x1.p0, -0x1.p-149
  },
  { // Entry 560
    0x1.p0,
    0x1.p0, 0.0f
  },
  { // Entry 561
    0x1.p0,
    0x1.p0, -0.0f
  },
  { // Entry 562
    0x1.p0,
    HUGE_VALF, 0.0f
  },
  { // Entry 563
    0x1.p0,
    HUGE_VALF, -0.0f
  },
  { // Entry 564
    0x1.p0,
    0x1.fffffep127, 0.0f
  },
  { // Entry 565
    0x1.p0,
    0x1.fffffep127, -0.0f
  },
  { // Entry 566
    0x1.p0,
    0x1.p-126, 0.0f
  },
  { // Entry 567
    0x1.p0,
    0x1.p-126, -0.0f
  },
  { // Entry 568
    0x1.p0,
    0x1.p-149, 0.0f
  },
  { // Entry 569
    0x1.p0,
    0x1.p-149, -0.0f
  },
  { // Entry 570
    0x1.p0,
    0.0f, 0.0f
  },
  { // Entry 571
    0x1.p0,
    0.0f, -0.0f
  },
  { // Entry 572
    0x1.p0,
    -0.0f, 0.0f
  },
  { // Entry 573
    0x1.p0,
    -0.0f, -0.0f
  },
  { // Entry 574
    0x1.p0,
    -0x1.p-149, 0.0f
  },
  { // Entry 575
    0x1.p0,
    -0x1.p-149, -0.0f
  },
  { // Entry 576
    0x1.p0,
    -0x1.p-126, 0.0f
  },
  { // Entry 577
    0x1.p0,
    -0x1.p-126, -0.0f
  },
  { // Entry 578
    0x1.p0,
    -0x1.fffffep127, 0.0f
  },
  { // Entry 579
    0x1.p0,
    -0x1.fffffep127, -0.0f
  },
  { // Entry 580
    0x1.p0,
    -HUGE_VALF, 0.0f
  },
  { // Entry 581
    0x1.p0,
    -HUGE_VALF, -0.0f
  },
  { // Entry 582
    HUGE_VALF,
    0x1.p-126, -HUGE_VALF
  },
  { // Entry 583
    HUGE_VALF,
    0x1.p-149, -HUGE_VALF
  },
  { // Entry 584
    HUGE_VALF,
    -0x1.p-149, -HUGE_VALF
  },
  { // Entry 585
    HUGE_VALF,
    -0x1.p-126, -HUGE_VALF
  },
  { // Entry 586
    0.0,
    HUGE_VALF, -HUGE_VALF
  },
  { // Entry 587
    0.0,
    0x1.fffffep127, -HUGE_VALF
  },
  { // Entry 588
    0.0,
    0x1.80p0, -HUGE_VALF
  },
  { // Entry 589
    0.0,
    -0x1.80p0, -HUGE_VALF
  },
  { // Entry 590
    0.0,
    -0x1.fffffep127, -HUGE_VALF
  },
  { // Entry 591
    0.0,
    -HUGE_VALF, -HUGE_VALF
  },
  { // Entry 592
    0.0,
    0x1.p-126, HUGE_VALF
  },
  { // Entry 593
    0.0,
    0x1.p-149, HUGE_VALF
  },
  { // Entry 594
    0.0,
    0.0f, HUGE_VALF
  },
  { // Entry 595
    0.0,
    -0.0f, HUGE_VALF
  },
  { // Entry 596
    0.0,
    -0x1.p-149, HUGE_VALF
  },
  { // Entry 597
    0.0,
    -0x1.p-126, HUGE_VALF
  },
  { // Entry 598
    HUGE_VALF,
    HUGE_VALF, HUGE_VALF
  },
  { // Entry 599
    HUGE_VALF,
    0x1.fffffep127, HUGE_VALF
  },
  { // Entry 600
    HUGE_VALF,
    0x1.80p0, HUGE_VALF
  },
  { // Entry 601
    HUGE_VALF,
    -0x1.80p0, HUGE_VALF
  },
  { // Entry 602
    HUGE_VALF,
    -0x1.fffffep127, HUGE_VALF
  },
  { // Entry 603
    HUGE_VALF,
    -HUGE_VALF, HUGE_VALF
  },
  { // Entry 604
    -0.0,
    -HUGE_VALF, -0x1.80p1
  },
  { // Entry 605
    -0.0,
    -HUGE_VALF, -0x1.p0
  },
  { // Entry 606
    0.0,
    -HUGE_VALF, -HUGE_VALF
  },
  { // Entry 607
    0.0,
    -HUGE_VALF, -0x1.921fb6p1
  },
  { // Entry 608
    0.0,
    -HUGE_VALF, -0x1.921fb6p0
  },
  { // Entry 609
    0.0,
    -HUGE_VALF, -0x1.fffffep127
  },
  { // Entry 610
    0.0,
    -HUGE_VALF, -0x1.80p2
  },
  { // Entry 611
    0.0,
    -HUGE_VALF, -0x1.p1
  },
  { // Entry 612
    0.0,
    -HUGE_VALF, -0x1.p-126
  },
  { // Entry 613
    0.0,
    -HUGE_VALF, -0x1.p-149
  },
  { // Entry 614
    -HUGE_VALF,
    -HUGE_VALF, 0x1.80p1
  },
  { // Entry 615
    -HUGE_VALF,
    -HUGE_VALF, 0x1.40p2
  },
  { // Entry 616
    HUGE_VALF,
    -HUGE_VALF, HUGE_VALF
  },
  { // Entry 617
    HUGE_VALF,
    -HUGE_VALF, 0x1.921fb6p1
  },
  { // Entry 618
    HUGE_VALF,
    -HUGE_VALF, 0x1.921fb6p0
  },
  { // Entry 619
    HUGE_VALF,
    -HUGE_VALF, 0x1.fffffep127
  },
  { // Entry 620
    HUGE_VALF,
    -HUGE_VALF, 0x1.80p2
  },
  { // Entry 621
    HUGE_VALF,
    -HUGE_VALF, 0x1.p1
  },
  { // Entry 622
    HUGE_VALF,
    -HUGE_VALF, 0x1.p-126
  },
  { // Entry 623
    HUGE_VALF,
    -HUGE_VALF, 0x1.p-149
  },
  { // Entry 624
    0.0,
    HUGE_VALF, -0x1.p-149
  },
  { // Entry 625
    0.0,
    HUGE_VALF, -0x1.p-126
  },
  { // Entry 626
    0.0,
    HUGE_VALF, -0x1.fffffep127
  },
  { // Entry 627
    0.0,
    HUGE_VALF, -HUGE_VALF
  },
  { // Entry 628
    HUGE_VALF,
    HUGE_VALF, HUGE_VALF
  },
  { // Entry 629
    HUGE_VALF,
    HUGE_VALF, 0x1.fffffep127
  },
  { // Entry 630
    HUGE_VALF,
    HUGE_VALF, 0x1.p-126
  },
  { // Entry 631
    HUGE_VALF,
    HUGE_VALF, 0x1.p-149
  },
  { // Entry 632
    HUGE_VALF,
    0x1.fffffep127, 0x1.fffffep127
  },
  { // Entry 633
    0.0f,
    0x1.p-126, 0x1.p1
  },
  { // Entry 634
    0.0f,
    -0x1.p-126, 0x1.p1
  },
  { // Entry 635
    0.0f,
    0x1.p-149, 0x1.p1
  },
  { // Entry 636
    0.0f,
    -0x1.p-149, 0x1.p1
  },
  { // Entry 637
    HUGE_VALF,
    HUGE_VALF, 0x1.p-1
  },
  { // Entry 638
    0x1.fffffeffffffbfffffdfffffebfffff1p63,
    0x1.fffffep127, 0x1.p-1
  },
  { // Entry 639
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1,
    0x1.p-1, 0x1.p-1
  },
  { // Entry 640
    0x1.p-63,
    0x1.p-126, 0x1.p-1
  },
  { // Entry 641
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-75,
    0x1.p-149, 0x1.p-1
  },
  { // Entry 642
    0.0,
    0.0f, 0x1.p-1
  },
  { // Entry 643
    0.0,
    -0.0f, 0x1.p-1
  },
  { // Entry 644
    HUGE_VALF,
    -HUGE_VALF, 0x1.p-1
  },
  { // Entry 645
    0.0,
    HUGE_VALF, -0x1.p-1
  },
  { // Entry 646
    0x1.0000008000006000005000004600003fp-64,
    0x1.fffffep127, -0x1.p-1
  },
  { // Entry 647
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.p-1, -0x1.p-1
  },
  { // Entry 648
    0x1.p63,
    0x1.p-126, -0x1.p-1
  },
  { // Entry 649
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep74,
    0x1.p-149, -0x1.p-1
  },
  { // Entry 650
    HUGE_VALF,
    0.0f, -0x1.p-1
  },
  { // Entry 651
    HUGE_VALF,
    -0.0f, -0x1.p-1
  },
  { // Entry 652
    0.0,
    -HUGE_VALF, -0x1.p-1
  },
  { // Entry 653
    0.0,
    0x1.p-1, HUGE_VALF
  },
  { // Entry 654
    0.0f,
    0x1.p-1, 0x1.fffffep127
  },
  { // Entry 655
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep-1,
    0x1.p-1, 0x1.p-1
  },
  { // Entry 656
    0x1.fffffffffffffffffffffffffffffffap-1,
    0x1.p-1, 0x1.p-126
  },
  { // Entry 657
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.p-1, 0x1.p-149
  },
  { // Entry 658
    0x1.p0,
    0x1.p-1, 0.0f
  },
  { // Entry 659
    0x1.p0,
    0x1.p-1, -0.0f
  },
  { // Entry 660
    0x1.p0,
    0x1.p-1, -0x1.p-149
  },
  { // Entry 661
    0x1.00000000000000000000000000000002p0,
    0x1.p-1, -0x1.p-126
  },
  { // Entry 662
    0x1.6a09e667f3bcc908b2fb1366ea957d3ep0,
    0x1.p-1, -0x1.p-1
  },
  { // Entry 663
    HUGE_VALF,
    0x1.p-1, -0x1.fffffep127
  },
  { // Entry 664
    HUGE_VALF,
    0x1.p-1, -HUGE_VALF
  },
  { // Entry 665
    0.0,
    -0x1.p-1, HUGE_VALF
  },
  { // Entry 666
    0.0f,
    -0x1.p-1, 0x1.fffffep127
  },
  { // Entry 667
    0x1.p0,
    -0x1.p-1, 0.0f
  },
  { // Entry 668
    0x1.p0,
    -0x1.p-1, -0.0f
  },
  { // Entry 669
    HUGE_VALF,
    -0x1.p-1, -0x1.fffffep127
  },
  { // Entry 670
    HUGE_VALF,
    -0x1.p-1, -HUGE_VALF
  },
  { // Entry 671
    0x1.p1,
    0x1.p2, 0x1.p-1
  },
  { // Entry 672
    0x1.80p1,
    0x1.20p3, 0x1.p-1
  },
  { // Entry 673
    0x1.p2,
    0x1.p4, 0x1.p-1
  },
  { // Entry 674
    0x1.p-1,
    0x1.p2, -0x1.p-1
  },
  { // Entry 675
    0x1.p-2,
    0x1.p4, -0x1.p-1
  },
  { // Entry 676
    0x1.p-3,
    0x1.p6, -0x1.p-1
  },
  { // Entry 677
    HUGE_VALF,
    0x1.fffffep-1, -0x1.74910cp62
  },
  { // Entry 678
    0.0f,
    0x1.fffffep-1, 0x1.74910cp62
  },
  { // Entry 679
    0x1.p2,
    0x1.p1, 0x1.p1
  },
  { // Entry 680
    0x1.p-2,
    0x1.p1, -0x1.p1
  },
  { // Entry 681
    0x1.p2,
    -0x1.p1, 0x1.p1
  },
  { // Entry 682
    0x1.p-2,
    -0x1.p1, -0x1.p1
  },
  { // Entry 683
    0x1.b0p4,
    0x1.80p1, 0x1.80p1
  },
  { // Entry 684
    0x1.86a0p11,
    0x1.40p2, 0x1.40p2
  },
  { // Entry 685
    0x1.921ee0p19,
    0x1.c0p2, 0x1.c0p2
  },
  { // Entry 686
    0x1.2a05f2p33,
    0x1.40p3, 0x1.40p3
  },
};
```
Response:
Let's break down the thought process to answer the user's request about the `sincosf_input.cpp` file.

**1. Understanding the Core Request:**

The user wants to know what this code *does*, particularly within the context of Android's Bionic library. They also want to understand the low-level implementation details, especially regarding libc and the dynamic linker. The "Part 3" designation suggests this is the concluding part of a series, so a summary is crucial.

**2. Initial Analysis of the Code:**

The code clearly defines:

* **A large array of hexadecimal floating-point numbers (`sincosf_input0` to `sincosf_input7`):** These look like input values for a `sin` and `cos` function. The hexadecimal representation suggests precision and potential testing of edge cases or specific bit patterns.
* **A `struct sincosf_range`:** This structure groups a label (string describing a range) and a `std::vector<float>` of values.
* **A `std::vector<sincosf_range>` called `sincosf_input`:** This vector organizes the input values into different ranges.

**3. Connecting to `sincosf`:**

The filename and the structure of the data strongly suggest that these are *input values* used to test the `sincosf` function (the single-precision floating-point version of `sin` and `cos`). The ranges imply that the testing strategy involves covering different magnitudes of input.

**4. Addressing the Specific Questions:**

Now, let's go through each of the user's points systematically:

* **Functionality:** The primary function is to provide a set of input values for benchmarking the `sincosf` function in Bionic. The ranges indicate a structured testing approach.

* **Relationship to Android:** This file is *directly* related to Android. It's part of the Bionic library, which is Android's C library. `sincosf` is a standard math function needed by Android apps and the system itself. Examples of use in Android include graphics rendering, game engines, and scientific applications.

* **Libc Function Implementation:**  The question asks how `sincosf` is implemented. This is a deep dive!  A good answer involves:
    * **Reduction:** Explaining the range reduction technique to bring the input into a manageable interval (usually around 0).
    * **Approximation:** Mentioning polynomial or rational approximations (like Chebyshev polynomials) using pre-computed coefficients.
    * **Hardware Acceleration (if applicable):** Briefly touching on the possibility of using CPU instructions.
    * **Accuracy:**  Highlighting the importance of meeting accuracy requirements and handling edge cases (NaN, infinity).

* **Dynamic Linker:**  This is a separate but related area. The prompt asks for a SO layout and symbol resolution.
    * **SO Layout:** A basic layout includes sections like `.text`, `.data`, `.bss`, `.plt`, `.got`.
    * **Symbol Processing:** Describe the role of the `.dynsym` table, hash tables for lookups, and the linking process (relocations, GOT patching, PLT creation).

* **Logical Reasoning (Input/Output):** Since this file *provides input*, the logical reasoning is about how the *test program* using these inputs would behave. The output would be the calculated `sin` and `cos` values for each input. Assuming a perfect `sincosf`, the output can be predicted. However, the *point* of testing is to find deviations.

* **Common User Errors:**  This focuses on how *developers* might misuse math functions. Examples include assuming angles are in degrees instead of radians, ignoring potential loss of precision with very large numbers, and not handling edge cases appropriately.

* **Android Framework/NDK Debugging:**  This traces the path from a high-level Android component down to this low-level test. Starting with an app using the NDK, then the NDK linking to Bionic's `libm.so`, and finally, the execution potentially running these benchmarks during development or testing.

* **Summary of Functionality (Part 3):**  This should be a concise recap of the core purpose: providing benchmark inputs for `sincosf` within Android's Bionic library, categorized by input ranges.

**5. Structuring the Answer:**

A well-structured answer is essential. Using headings and bullet points makes it easier for the user to read and understand. The order of the answer should generally follow the order of the questions.

**6. Refining and Adding Detail:**

After drafting the initial answer, review it for clarity and completeness. For example, when explaining `sincosf` implementation, mentioning specific techniques like CORDIC (though less common for standard `sin/cos`) or look-up tables could add value. For the dynamic linker, mentioning lazy binding could be a useful detail.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the file contains the *implementation* of `sincosf`. **Correction:** The filename and data structure strongly suggest it's *input* for testing.
* **Focusing too much on the specific numbers:**  While the numbers are the data, the *purpose* of the data is more important for the high-level understanding.
* **Assuming too much technical knowledge:**  The explanation should be accessible even to someone with a moderate understanding of system programming. Avoid overly jargon-filled explanations without defining terms.

By following these steps, the detailed and comprehensive answer provided earlier can be constructed. The key is to break down the request, analyze the code, connect it to the broader context of Android, and address each specific question with relevant details.
好的，让我们来详细分析一下 `bionic/benchmarks/sincosf_input.cpp` 这个文件。

**功能归纳 (第3部分):**

这个文件的核心功能是**定义了一系列单精度浮点数 (float) 的输入值，用于对 Android Bionic 库中的 `sincosf` 函数进行性能基准测试。** 这些输入值被组织成不同的范围，以便更全面地测试 `sincosf` 在各种输入条件下的性能表现。

**详细分析：**

**1. 文件功能:**

* **提供 `sincosf` 函数的测试输入:**  该文件定义了多个静态常量数组 (`sincosf_input0` 到 `sincosf_input7`)，每个数组都包含大量的 `float` 类型数值。这些数值以十六进制浮点数表示，可以精确地表示浮点数的值，包括特殊值和边界值。
* **组织输入到不同的范围:**  `sincosf_input` 是一个 `std::vector`，其元素是 `sincosf_range` 结构体。每个 `sincosf_range` 包含一个描述范围的字符串 (`label`) 和一个包含该范围内输入值的 `std::vector<float>` (`values`)。 这样可以将输入值按照数量级或特定区间进行分组，方便针对不同输入范围测试 `sincosf` 的性能。

**2. 与 Android 功能的关系 (举例说明):**

`sincosf` 函数是 C 标准库的数学函数，用于同时计算给定角度（弧度）的正弦和余弦值。在 Android 中，许多组件和应用程序都会用到这个函数：

* **图形渲染 (Android Framework):**  例如，在绘制动画、进行 3D 变换时，需要计算角度的正弦和余弦值来确定顶点的位置。Android Framework 中的 Skia 图形库底层就依赖于 Bionic 的数学函数。
* **游戏开发 (NDK):** 使用 Android NDK 开发的游戏常常需要进行复杂的数学运算，包括三角函数。游戏引擎会频繁调用 `sincosf` 来处理物体旋转、角色动画等。
* **科学计算和工程应用 (NDK):**  一些使用 NDK 开发的科学计算或工程应用，例如信号处理、物理模拟等，也会用到 `sincosf`。
* **系统服务 (Android System):**  Android 系统内部的一些服务，例如传感器数据处理、定位计算等，在某些情况下也可能间接使用到三角函数。

**3. libc 函数的功能实现 (以 `sincosf` 为例):**

`sincosf` 的实现通常涉及以下几个步骤：

1. **参数规范化 (Argument Reduction):**
   - 由于正弦和余弦函数是周期函数，可以将输入角度 `x` 减去 `2 * PI` 的整数倍，将其范围缩小到 `[0, 2*PI)` 或 `[-PI, PI]`。这可以通过整数除法和取模运算来实现。
   - 对于非常大的输入值，可能需要更精细的规范化方法来避免精度损失。

2. **象限判断:**  根据规范化后的角度，确定其所在的象限（第一、第二、第三或第四象限）。

3. **范围缩减 (Range Reduction):**
   - 将角度进一步缩减到更小的范围，例如 `[0, PI/2]`。 这可以使用三角函数的对称性和周期性来实现。例如，如果角度在第二象限，可以将其转换为 `PI - x'`，其中 `x'` 是在第一象限的角度。

4. **多项式逼近或查表法:**
   - **多项式逼近:**  在缩减后的范围内，使用多项式（例如泰勒级数、切比雪夫多项式）来逼近正弦和余弦函数。 逼近的精度取决于多项式的阶数和系数。Bionic 的 `libm.so` 可能会使用高度优化的多项式逼近方法，并预先计算好系数。
   - **查表法结合插值:** 对于一些实现，可能会使用预先计算好的正弦和余弦值表（查找表）。对于给定的输入角度，先在表中找到最接近的值，然后使用插值法（例如线性插值）来获得更精确的结果。这种方法在精度和性能之间需要权衡。

5. **符号确定:** 根据原始角度所在的象限，确定正弦和余弦值的符号。

6. **特殊值处理:**  处理特殊输入值，例如 NaN（非数字）、正负无穷大。

**代码示例 (简化的伪代码):**

```c
float sincosf(float x, float *cos_val) {
  const float PI = 3.14159265358979323846f;
  // 1. 参数规范化
  float normalized_x = fmodf(x, 2 * PI);
  if (normalized_x < 0) {
    normalized_x += 2 * PI;
  }

  // 2. 象限判断
  int quadrant = (int)(normalized_x / (PI / 2.0f));

  // 3. 范围缩减
  float reduced_x;
  switch (quadrant) {
    case 0: reduced_x = normalized_x; break;
    case 1: reduced_x = PI - normalized_x; break;
    case 2: reduced_x = normalized_x - PI; break;
    case 3: reduced_x = 2 * PI - normalized_x; break;
  }
  if (reduced_x < 0) reduced_x = -reduced_x; // 取绝对值

  // 4. 多项式逼近 (简化示例)
  float sin_val;
  if (reduced_x < 0.5f) {
    sin_val = reduced_x - (reduced_x * reduced_x * reduced_x) / 6.0f; // 泰勒级数近似
  } else {
    // ... 更精确的逼近方法
  }

  // 5. 符号确定
  switch (quadrant) {
    case 0: *cos_val =  sqrtf(1.0f - sin_val * sin_val); break;
    case 1: *cos_val = -sqrtf(1.0f - sin_val * sin_val); break;
    case 2: sin_val = -sin_val; *cos_val = -sqrtf(1.0f - sin_val * sin_val); break;
    case 3: sin_val = -sin_val; *cos_val =  sqrtf(1.0f - sin_val * sin_val); break;
  }

  return sin_val;
}
```

**注意:** 实际的 `sincosf` 实现会更加复杂和优化，使用更高阶的多项式或更精密的查表方法，并考虑性能和精度的平衡。

**4. dynamic linker 的功能 (so 布局样本及符号处理):**

Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 的主要职责是在程序运行时加载共享库 (SO, Shared Object)，并解析和链接库中使用的符号。

**SO 布局样本:**

一个典型的 SO 文件（例如 `libm.so`，包含 `sincosf` 函数）的布局可能如下：

```
.text         # 包含可执行代码的段
.rodata       # 包含只读数据的段 (例如字符串常量、多项式系数)
.data         # 包含已初始化的全局变量和静态变量的段
.bss          # 包含未初始化的全局变量和静态变量的段
.symtab       # 符号表，包含库中定义的符号信息 (函数名、变量名等)
.strtab       # 字符串表，存储符号表中符号名称的字符串
.dynsym       # 动态符号表，包含需要动态链接的符号信息
.dynstr       # 动态字符串表，存储动态符号表中符号名称的字符串
.rel.dyn      # 动态重定位表，用于在加载时修改数据段中的地址
.rel.plt      # PLT (Procedure Linkage Table) 重定位表，用于延迟绑定函数调用
.plt          # Procedure Linkage Table，用于延迟绑定外部函数
.got          # Global Offset Table，用于存储全局变量和函数的地址
.hash         # 符号哈希表，用于加速符号查找
```

**符号处理过程:**

1. **加载 SO 文件:** 当程序需要使用共享库时，dynamic linker 会将 SO 文件加载到内存中的某个地址空间。

2. **解析 ELF 头:** Dynamic linker 解析 SO 文件的 ELF (Executable and Linkable Format) 头，获取关于段、符号表、重定位表等信息。

3. **加载依赖库:** 如果 SO 文件依赖于其他共享库，dynamic linker 会递归地加载这些依赖库。

4. **符号查找:** 当程序调用一个在共享库中定义的函数（例如 `sincosf`）时：
   - **延迟绑定 (Lazy Binding):** 默认情况下，Android 使用延迟绑定。第一次调用该函数时，会通过 PLT 中的一个跳转指令跳转到 dynamic linker 的解析例程。
   - **查找符号:** Dynamic linker 在 SO 文件的 `.dynsym` 和其依赖库的动态符号表中查找名为 `sincosf` 的符号。符号查找通常使用哈希表 (`.hash`) 来提高效率。
   - **获取地址:** 找到符号后，dynamic linker 从符号表中获取 `sincosf` 函数在库中的相对地址。

5. **重定位:**
   - **GOT (Global Offset Table) 更新:** Dynamic linker 将 `sincosf` 函数的实际加载地址写入到 GOT 中对应的条目。
   - **PLT (Procedure Linkage Table) 更新:** Dynamic linker 修改 PLT 中与 `sincosf` 对应的条目，使其直接跳转到 GOT 中存储的实际地址。

6. **后续调用:**  后续对 `sincosf` 的调用将直接跳转到 GOT 中存储的地址，而无需再次经过 dynamic linker 的解析过程，从而提高性能。

**假设输入与输出 (针对基准测试):**

假设有一个简单的基准测试程序，它会遍历 `sincosf_input.cpp` 中定义的输入值，并调用 `sincosf` 函数：

**假设输入:**

```c++
#include <cmath>
#include <vector>
#include <iostream>

// ... (包含 sincosf_input.cpp 中的数据定义) ...

int main() {
  for (const auto& range : sincosf_input) {
    std::cout << "Testing range: " << range.label << std::endl;
    for (float val : range.values) {
      float sin_val, cos_val;
      sin_val = sinf(val);
      cos_val = cosf(val);
      // 或者使用 sincosf
      // sincosf(val, &cos_val);
      // std::cout << "sin(" << val << ") = " << sin_val << ", cos(" << val << ") = " << cos_val << std::endl;
    }
  }
  return 0;
}
```

**预期输出:**

基准测试程序通常不会直接输出 `sin` 和 `cos` 的值，而是会测量执行时间或其他性能指标。  例如，输出可能是：

```
Testing range: 0.0 <= x < 0.1
Time taken for this range: 0.005 seconds
Testing range: 0.1 <= x < 0.7
Time taken for this range: 0.012 seconds
...
```

如果需要验证 `sincosf` 的正确性，则可以比较计算结果与高精度计算结果或预期值。

**用户或编程常见的使用错误:**

* **角度单位错误:** 忘记 `sinf` 和 `cosf` 接受的参数是弧度而不是角度。
   ```c++
   float angle_degrees = 90.0f;
   // 错误：直接将角度传给 sinf
   float sin_val = sinf(angle_degrees); 
   // 正确：将角度转换为弧度
   float angle_radians = angle_degrees * M_PI / 180.0f;
   float sin_val_correct = sinf(angle_radians);
   ```
* **精度问题:** 对于非常大或非常小的输入值，浮点数的精度可能受到限制。
* **特殊值处理不当:** 没有正确处理 NaN 或无穷大等特殊输入值。
* **性能考虑不足:** 在性能敏感的代码中，频繁调用 `sinf` 和 `cosf` 可能会成为瓶颈。考虑使用查找表或其他优化方法。

**Android Framework 或 NDK 如何到达这里 (调试线索):**

1. **应用程序代码:**  Android 应用程序（Java/Kotlin）或使用 NDK 开发的 Native 代码可能会调用需要三角函数的 API。
2. **Android Framework API (Java):** 例如，`android.graphics.Canvas.rotate(float degrees)` 内部会将角度转换为弧度并使用底层的图形库进行旋转，最终可能调用到 Bionic 的 `sinf` 和 `cosf`。
3. **NDK (Native 代码):**  Native 代码可以直接调用 `<cmath>` 头文件中声明的 `sinf` 和 `cosf` 函数。
4. **C++ 标准库 (libc++) 或 Bionic (libm.so):**  NDK 应用程序链接到 C++ 标准库 `libc++.so` 和 Bionic C 库 `libc.so` 以及数学库 `libm.so`。 `sinf` 和 `cosf` 的实现位于 `libm.so` 中。
5. **Dynamic Linker:**  当应用程序加载时，或者在运行时首次调用 `sinf` 或 `cosf` 时，dynamic linker 负责加载 `libm.so` 并解析符号。
6. **`sincosf_input.cpp` (基准测试):** 在 Android 系统的开发和测试阶段，为了确保 `libm.so` 中 `sincosf` 函数的性能，会运行基准测试程序，该程序会读取 `sincosf_input.cpp` 中定义的输入值来衡量性能。

**调试线索:**

* **使用 Profiler:**  可以使用 Android Studio 的 Profiler 工具来查看应用程序的 CPU 使用情况，找出哪些函数被频繁调用，包括 `sinf` 和 `cosf`。
* **使用 Systrace 或 Perfetto:** 这些工具可以跟踪系统调用和函数调用，帮助了解 Android Framework 或系统服务如何使用 Bionic 的数学函数。
* **GDB 调试 (NDK):**  对于 NDK 开发的应用程序，可以使用 GDB 进行调试，设置断点在 `sinf` 或 `cosf` 函数入口，查看调用堆栈。
* **查看 Bionic 源代码:**  可以查看 Bionic 的源代码 (例如在 AOSP 仓库中) 来了解 `sinf` 和 `cosf` 的具体实现。

希望以上详细的分析能够帮助你理解 `bionic/benchmarks/sincosf_input.cpp` 文件的功能和它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/benchmarks/sincosf_input.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
0x1.8c8c2ep+124,
  0x1.a06c4cp+127,
  0x1.461f2ep+126,
  0x1.03f9bep+126,
  0x1.fd18a6p+127,
  0x1.afa5f4p+127,
  0x1.1b5642p+126,
  0x1.c096b4p+123,
  0x1.e7d78p+127,
  0x1.6e2fcap+127,
  0x1.66067ep+126,
  0x1.d251f8p+127,
  0x1.439466p+127,
  0x1.1dc904p+126,
  0x1.79bbe6p+127,
  0x1.52a2bap+127,
  0x1.399754p+125,
  0x1.b22b3ap+125,
  0x1.83fea6p+124,
  0x1.d90378p+125,
  0x1.9e8dc8p+127,
  0x1.5e4b2p+127,
  0x1.72387ep+126,
  0x1.79b6acp+126,
  0x1.cefefp+127,
  0x1.caa272p+122,
  0x1.40a71ep+125,
  0x1.bde272p+126,
  0x1.08ff4cp+127,
  0x1.0ba12ap+126,
  0x1.df8588p+124,
  0x1.76f3dp+125,
  0x1.f71cf6p+127,
  0x1.c65e7cp+127,
  0x1.1b9ef6p+126,
  0x1.87492ap+127,
  0x1.222382p+126,
  0x1.5b8b52p+126,
  0x1.d17fb8p+125,
  0x1.d75a96p+124,
  0x1.c30d16p+127,
  0x1.e7bdd4p+125,
  0x1.83d51cp+127,
  0x1.a2a116p+127,
  0x1.cd4302p+127,
  0x1.9a8598p+126,
  0x1.b970e8p+126,
  0x1.d7876ap+127,
  0x1.74717ep+127,
  0x1.1fcf9ap+126,
  0x1.af6684p+125,
  0x1.b1df4ap+127,
  0x1.8725bcp+127,
  0x1.ab4962p+126,
  0x1.2fb354p+127,
  0x1.c3e7cep+123,
  0x1.d9e8fcp+125,
  0x1.a09a8cp+126,
  0x1.8e18dep+126,
  0x1.e80d9p+126,
  0x1.3cadf4p+127,
  0x1.3bc8ccp+127,
  0x1.50343p+127,
  0x1.336d7cp+126,
  0x1.e2c9aep+127,
  0x1.5dae1ap+124,
  0x1.83978ep+125,
  0x1.2c773ep+127,
  0x1.749a88p+127,
  0x1.173132p+127,
  0x1.be29c8p+127,
  0x1.8e5086p+127,
  0x1.f72e64p+126,
  0x1.3eca7p+126,
  0x1.f0a142p+126,
  0x1.5b3f8p+126,
  0x1.d55e42p+127,
  0x1.c81a8cp+127,
  0x1.b79606p+127,
  0x1.fc6f04p+127,
  0x1.58063ap+127,
  0x1.0d1a22p+127,
  0x1.069758p+126,
  0x1.62cd96p+126,
  0x1.281e62p+127,
  0x1.ce0452p+127,
  0x1.96091ep+127,
  0x1.aaf09cp+127,
  0x1.396d14p+127,
  0x1.22b532p+127,
  0x1.96bef6p+126,
  0x1.133f7ap+127,
  0x1.56a378p+127,
  0x1.4cac76p+124,
  0x1.5a9982p+127,
  0x1.1fec6cp+126,
  0x1.617aep+127,
  0x1.fb6e1ap+125,
  0x1.fbf4c2p+127,
  0x1.682c3ap+127,
  0x1.1b423ep+126,
  0x1.54b2a8p+127,
  0x1.220266p+126,
  0x1.28a24ep+127,
  0x1.0e7a56p+127,
  0x1.31abbap+126,
  0x1.1751b4p+127,
  0x1.ecfebap+125,
  0x1.f4bb3p+127,
  0x1.82e5ap+127,
  0x1.42668p+127,
  0x1.68f3fp+126,
  0x1.bcad04p+127,
  0x1.8d1a48p+127,
  0x1.d89f28p+125,
  0x1.14ed08p+127,
  0x1.b1e278p+126,
  0x1.aabd4ep+126,
  0x1.bb2f9ep+126,
  0x1.e3a244p+125,
  0x1.74b5e8p+126,
  0x1.4bb0ap+126,
  0x1.d306d8p+126,
  0x1.f9ccc4p+127,
  0x1.457a3p+126,
  0x1.3e3f22p+127,
  0x1.d2c572p+125,
  0x1.06614p+127,
  0x1.d620fep+127,
  0x1.edeedep+126,
  0x1.f38ebcp+124,
  0x1.d4c7d6p+124,
  0x1.2c215ep+125,
  0x1.82a0cp+127,
  0x1.374cc4p+127,
  0x1.6b78d6p+127,
  0x1.ec3888p+124,
  0x1.13ff7cp+125,
  0x1.fe7da4p+127,
  0x1.fe2b78p+127,
  0x1.93caa6p+127,
  0x1.9bfb5cp+126,
  0x1.d429cep+127,
  0x1.bac4eep+126,
  0x1.65e5c4p+127,
  0x1.b4c75p+127,
  0x1.005f34p+127,
  0x1.62c18p+127,
  0x1.2bb578p+126,
  0x1.5819d4p+127,
  0x1.f14b7ep+125,
  0x1.c12884p+127,
  0x1.ea20e4p+127,
  0x1.b39a3p+125,
  0x1.d1484cp+125,
  0x1.4a010ep+127,
  0x1.f61a9p+125,
  0x1.eba3f8p+127,
  0x1.c44ac2p+127,
  0x1.c85236p+126,
  0x1.373ef6p+126,
  0x1.b65944p+127,
  0x1.dfd602p+122,
  0x1.d1182ap+123,
  0x1.2e5376p+127,
  0x1.8719d6p+127,
  0x1.bc20eep+124,
  0x1.d275a6p+126,
  0x1.1ef032p+126,
  0x1.c50fb4p+127,
  0x1.34195cp+126,
  0x1.a0d1d6p+127,
  0x1.e5ee3ap+127,
  0x1.4c6afp+126,
  0x1.1c5a1cp+126,
  0x1.e4113p+124,
  0x1.ab666p+127,
  0x1.2ca26ap+124,
  0x1.86565cp+122,
  0x1.ba16ep+126,
  0x1.f21cd2p+126,
  0x1.f53658p+125,
  0x1.e5e022p+124,
  0x1.b070dap+125,
  0x1.7b9098p+127,
  0x1.b1ad22p+124,
  0x1.742ee6p+126,
  0x1.dcf93ep+127,
  0x1.c1ac14p+127,
  0x1.f81038p+124,
  0x1.4d8ffap+125,
  0x1.a8fdf4p+125,
  0x1.d4332ap+127,
  0x1.78dbacp+126,
  0x1.7cfcfp+125,
  0x1.464bcep+127,
  0x1.171a04p+123,
  0x1.fb2d7ep+127,
  0x1.2340bep+123,
  0x1.a53a92p+127,
  0x1.d0daaap+127,
  0x1.ba199cp+123,
  0x1.9c7d52p+126,
  0x1.a928ep+126,
  0x1.9fa44ep+127,
  0x1.8d2d1ap+127,
  0x1.81fdb6p+126,
  0x1.54129ep+126,
  0x1.e976f8p+126,
  0x1.bc0c0cp+127,
  0x1.42729cp+126,
  0x1.a24a0cp+125,
  0x1.170858p+125,
  0x1.66fa7ep+125,
  0x1.2007e2p+121,
  0x1.83ab7cp+127,
  0x1.dfe674p+127,
  0x1.1de1c4p+124,
  0x1.d19682p+127,
  0x1.e7e5f4p+126,
  0x1.638758p+127,
  0x1.49092p+127,
  0x1.fb0d18p+125,
  0x1.cca50ep+127,
  0x1.abc118p+127,
  0x1.e4d062p+127,
  0x1.abc75p+127,
  0x1.b0b0aep+127,
  0x1.2c9a02p+125,
  0x1.0ead8p+126,
  0x1.9cca28p+126,
  0x1.55554p+127,
  0x1.0c3d7ep+126,
  0x1.ef554p+126,
  0x1.ae6b4p+127,
  0x1.c48e9p+126,
  0x1.c4852p+127,
  0x1.f3e0ap+126,
  0x1.995e64p+127,
  0x1.3d5c84p+126,
  0x1.e9d07cp+125,
  0x1.13b1c4p+125,
  0x1.3102d4p+127,
  0x1.6b21b6p+127,
  0x1.73214ep+125,
  0x1.2a1bdcp+126,
  0x1.9deacep+126,
  0x1.8dfd08p+126,
  0x1.3e2074p+126,
  0x1.a6a1dap+127,
  0x1.45f596p+126,
  0x1.7a8c1p+126,
  0x1.b44ee4p+123,
  0x1.36b1a6p+125,
  0x1.cd9f7ap+125,
  0x1.55782ep+126,
  0x1.39db98p+127,
  0x1.d02d7p+127,
  0x1.b7d9d6p+127,
  0x1.51885cp+126,
  0x1.42465cp+127,
  0x1.9cdb78p+127,
  0x1.a112p+127,
  0x1.3f6248p+124,
  0x1.d926cep+124,
  0x1.c7058ep+126,
  0x1.f70d24p+127,
  0x1.df4ef2p+127,
  0x1.f1cafp+123,
  0x1.52ee0ap+127,
  0x1.48ed9ap+127,
  0x1.16408p+127,
  0x1.af82b2p+127,
  0x1.c37f68p+127,
  0x1.1b503ap+124,
  0x1.abde4p+127,
  0x1.8f1a12p+127,
  0x1.306a8ap+127,
  0x1.edee2p+125,
  0x1.da924ep+125,
  0x1.b4f604p+126,
  0x1.c0e08ep+127,
  0x1.f4f7d2p+126,
  0x1.555576p+127,
  0x1.aea3e8p+125,
  0x1.ca5122p+126,
  0x1.60b16p+127,
  0x1.d8b02p+125,
  0x1.96786ap+126,
  0x1.25c324p+127,
  0x1.aa5fd8p+124,
  0x1.c0ae5ap+127,
  0x1.fbc3cp+125,
  0x1.3f976ep+126,
  0x1.2995cep+127,
  0x1.a0f2a8p+127,
  0x1.7f21bcp+126,
  0x1.aab454p+127,
  0x1.45d4bep+124,
  0x1.d80dd4p+127,
  0x1.48884ep+126,
  0x1.90647ap+126,
  0x1.81aa7cp+125,
  0x1.29cdcep+126,
  0x1.bb5cd4p+125,
  0x1.b0b04ep+126,
  0x1.1d6ea8p+127,
  0x1.65a3d4p+127,
  0x1.ac1d1ep+126,
  0x1.83abf4p+127,
  0x1.79669ep+126,
  0x1.6e405ap+127,
  0x1.00c8e4p+124,
  0x1.cb928ep+125,
  0x1.5a588p+126,
  0x1.128eecp+126,
  0x1.c71488p+127,
  0x1.a9e0bap+127,
  0x1.895c98p+127,
  0x1.090fcp+127,
  0x1.3bf3eep+125,
  0x1.03fa94p+125,
  0x1.c0da42p+126,
  0x1.f2066cp+126,
  0x1.1d3bdcp+127,
  0x1.5d19fcp+124,
  0x1.2abe36p+127,
  0x1.ffd886p+127,
  0x1.82fdb2p+125,
  0x1.9b47ecp+124,
  0x1.85087p+127,
  0x1.fe5428p+127,
  0x1.fe18dcp+127,
  0x1.bf922ap+126,
  0x1.bb3ccep+127,
  0x1.c16f2ep+124,
  0x1.04d8f8p+127,
  0x1.29647p+127,
  0x1.1cedc2p+127,
  0x1.125f86p+126,
  0x1.c11efcp+124,
  0x1.7deff6p+124,
  0x1.9e7ccp+126,
  0x1.4f74ap+126,
  0x1.a7c806p+126,
  0x1.1ad406p+127,
  0x1.c149f8p+127,
  0x1.9d425ap+125,
  0x1.5ee562p+127,
  0x1.6c4072p+126,
  0x1.b2297cp+126,
  0x1.2c16bap+126,
  0x1.110888p+126,
  0x1.e65c8cp+125,
  0x1.aeb1f4p+126,
  0x1.3276cap+123,
  0x1.088156p+123,
  0x1.ea93fap+127,
  0x1.305792p+127,
  0x1.c5f63p+127,
  0x1.d4c652p+125,
  0x1.be1e4ap+126,
  0x1.50ae42p+127,
  0x1.0b6732p+124,
  0x1.70f1aap+125,
  0x1.6d715p+127,
  0x1.9edc2p+127,
  0x1.9c5ffcp+124,
  0x1.b60a9ap+127,
  0x1.53de68p+127,
  0x1.8388dp+127,
  0x1.4391d6p+124,
  0x1.e9c01ap+127,
  0x1.a4f264p+127,
  0x1.e94ab4p+126,
  0x1.9368c4p+127,
  0x1.19d3f2p+124,
  0x1.5dbe48p+126,
  0x1.85d08ep+127,
  0x1.9fcd96p+125,
  0x1.e69374p+126,
  0x1.6dc07p+127,
  0x1.8147c6p+124,
  0x1.4af02p+127,
  0x1.bac7p+127,
  0x1.0e6264p+127,
  0x1.5a8062p+127,
  0x1.9085dcp+127,
  0x1.9d2418p+126,
  0x1.56f498p+127,
  0x1.18d804p+127,
  0x1.5ecb68p+126,
  0x1.852936p+124,
  0x1.5132a8p+127,
  0x1.5557f6p+127,
};

struct sincosf_range {
  const char *label;
  std::vector<float> values;
};

static const std::vector<sincosf_range> sincosf_input = {
  {"0.0 <= x < 0.1", sincosf_input0},
  {"0.1 <= x < 0.7", sincosf_input1},
  {"0.7 <= x < 3.1", sincosf_input2},
  {"-3.1 <= x < 3.1", sincosf_input3},
  {"3.3 <= x < 33.3", sincosf_input4},
  {"100.0 <= x < 1000.0", sincosf_input5},
  {"1e6 <= x < 1e32", sincosf_input6},
  {"1e32 <= x < inf", sincosf_input7},
};
```
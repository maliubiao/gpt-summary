Response:
Let's break down the thought process to analyze the `math_benchmark.cpp` file.

1. **Understanding the Goal:** The first and most crucial step is to understand the purpose of the file. The comment at the top clearly states it's a benchmark file for the math library within Android's Bionic. Benchmarks are designed to measure performance.

2. **High-Level Structure Analysis:**  Skim the code to identify the main components. Notice the inclusion of headers (`fenv.h`, `math.h`, `benchmark/benchmark.h`, `util.h`). The presence of `benchmark::State` and `BIONIC_BENCHMARK` macros immediately signals that this code uses a benchmarking framework. Also, observe the naming convention `BM_math_*`, which suggests individual benchmarks for different math functions.

3. **Analyzing Individual Benchmarks (Iterative Approach):**  Pick a few representative benchmarks and analyze them in detail.

    * **`BM_math_sqrt`:** This is a simple example. It initializes `d` and `v`, then enters a loop that runs as long as `state.KeepRunning()` is true. Inside the loop, it performs `d += sqrt(v)`. The `volatile` keyword is a hint about preventing compiler optimizations. The `BIONIC_BENCHMARK` macro registers this function as a benchmark.

    * **`BM_math_log10`, `BM_math_logb`:** These are structurally similar to `BM_math_sqrt`, just using different math functions. This suggests the file tests the performance of various mathematical operations.

    * **`BM_math_isfinite_macro`, `BM_math_isfinite`:**  These are interesting because they seem to benchmark the same functionality (`isfinite`) but potentially in different ways (macro vs. function call). The `BIONIC_BENCHMARK_WITH_ARG` and `SetLabel` hints towards testing different input values. Looking at the `values` array confirms this: it includes normal values, NaN, and infinity to test boundary conditions.

    * **`BM_math_sin_fast`, `BM_math_sin_feupdateenv`, `BM_math_sin_fesetenv`:**  This group highlights the impact of floating-point environment control (`fenv.h`). The different versions (`feupdateenv`, `fesetenv`) suggest performance comparisons based on how the floating-point environment is handled.

    * **Benchmarks with `_speccpu20xx` suffixes:** These clearly indicate benchmarks using input data derived from the SPEC CPU benchmark suite. This means the tests are using realistic, standardized workloads. The `_latency` suffix suggests variations that might focus on the time taken for a single operation in a sequence.

4. **Identifying Common Patterns and Features:**  As you analyze more benchmarks, look for recurring elements:

    * **`volatile` keyword:**  Used consistently to prevent unwanted compiler optimizations.
    * **`benchmark::State`:** The core object for controlling the benchmark loop and providing information.
    * **`state.KeepRunning()`:** The standard way to control the benchmark loop.
    * **`BIONIC_BENCHMARK` and `BIONIC_BENCHMARK_WITH_ARG`:**  Macros for registering benchmarks.
    * **`SetLabel`:** Used for providing descriptive names for benchmark variations, often based on input data.
    * **Input data arrays (e.g., `values`, `expf_input`, `powf_input`, `sincosf_input`):**  Demonstrates that the benchmarks use different sets of inputs to cover various scenarios.
    * **`zero` and `zerod`:** Used in `_latency` benchmarks, likely to force sequential execution and measure individual operation time.

5. **Relating to Android Functionality:**  Recognize that Bionic is the foundation of Android's C library. The math functions being benchmarked here are fundamental functions used throughout the Android system, from framework components to native applications. Think about how things like game engines, graphics libraries, and even some system services might rely on these math functions.

6. **Logic and Assumptions:**  When encountering code like the `isfinite` benchmarks, make explicit the assumptions about inputs and expected outputs. For example, `isfinite(1234.0)` should return true (or a non-zero value), `isfinite(nan(""))` should return false (or zero), etc.

7. **Common Usage Errors:** Consider how developers might misuse these functions. For example, not checking for NaN or infinity before using the result of a math function can lead to unexpected behavior. Incorrectly handling floating-point exceptions is another potential issue.

8. **Tracing the Execution Path (Debugging Clue):** Think about the layers involved in an Android application calling a math function. Start with the application code (Java or Kotlin), then the NDK (if it's a native app), then the system calls which eventually lead to the Bionic library. This path helps understand how the benchmark code is ultimately exercised.

9. **Structuring the Answer:** Organize the findings into logical sections, covering functionality, Android relevance, input/output examples, common errors, and the execution path. Use clear and concise language.

10. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For example, initially, I might not have emphasized the SPEC CPU benchmark usage enough and would go back to improve that section.
这个文件 `bionic/benchmarks/math_benchmark.cpp` 是 Android Bionic 库中用于测试和衡量数学函数性能的基准测试代码。它使用 Google Benchmark 框架来执行和报告测试结果。

**它的主要功能可以归纳为：**

1. **性能测试 (Benchmarking):**  该文件定义了一系列针对不同 C 标准库数学函数的性能测试用例。这些测试用例旨在测量这些函数在不同输入情况下的执行速度。

2. **覆盖多种数学函数:**  文件中包含了对多种常见数学函数的基准测试，例如：
    * `sqrt` (平方根)
    * `log10` (以 10 为底的对数)
    * `logb` (提取浮点数的指数)
    * `isfinite`, `isinf`, `isnan`, `isnormal` (浮点数分类宏和函数)
    * `sin` (正弦)
    * `fpclassify` (浮点数分类)
    * `signbit` (获取符号位)
    * `fabs` (绝对值)
    * `sincos` (同时计算正弦和余弦)
    * `expf`, `exp` (指数函数)
    * `exp2f`, `exp2` (以 2 为底的指数函数)
    * `powf`, `pow` (幂函数)
    * `logf`, `log` (自然对数)
    * `log2f`, `log2` (以 2 为底的对数)
    * `sinf`, `cosf`, `sincosf` (单精度浮点数版本的三角函数)

3. **测试不同输入:**  对于某些函数（例如 `isfinite`, `isinf`, `isnan`, `isnormal`, `fpclassify`, `signbit`, `fabs`），基准测试会使用预定义的 `values` 数组进行测试，该数组包含正常值、NaN (Not a Number)、无穷大 (HUGE_VAL) 和零，以覆盖不同的输入情况。这有助于评估函数处理特殊情况的性能。

4. **区分宏和函数:**  对于一些浮点数分类函数，代码同时测试了宏版本（例如 `isfinite(v)`）和函数版本（例如 `(isfinite)(v)`），以便比较它们的性能差异。

5. **考虑浮点环境:**  对于 `sin` 函数，代码包含了考虑浮点环境影响的基准测试 (`BM_math_sin_feupdateenv`, `BM_math_sin_fesetenv`)。这涉及到保存和恢复浮点环境，以模拟更真实的应用场景。

6. **使用 SPEC CPU 输入:**  一些基准测试用例（例如带有 `_speccpu20xx` 后缀的测试）使用了从 SPEC CPU 基准测试套件中提取的输入数据。这旨在使用更贴近实际应用场景的输入来评估性能。

7. **测量延迟 (Latency):**  带有 `_latency` 后缀的基准测试用例，例如 `BM_math_expf_speccpu2017_latency`，通过使用之前计算的结果作为下一个计算的输入（例如 `f = expf(f * zero + *cin);`），来模拟依赖关系并更准确地测量单个操作的延迟。

**与 Android 功能的关系和举例说明：**

这些数学函数是 Android 操作系统和应用程序的基础构建块。它们被广泛用于：

* **图形渲染:**  OpenGL ES 库和 Android 的图形框架使用这些函数进行矩阵运算、向量计算、光照模型计算等。例如，在绘制一个旋转的 3D 模型时，`sin` 和 `cos` 函数会被大量使用。
* **音频处理:**  音频编解码器、音频效果处理等需要进行傅里叶变换、滤波等操作，这些操作会用到三角函数、对数函数等。
* **传感器数据处理:**  处理来自加速度计、陀螺仪、GPS 等传感器的数据可能需要进行角度计算、距离计算等，涉及到数学函数。
* **游戏开发:**  游戏引擎广泛使用这些函数进行物理模拟、碰撞检测、AI 算法等。
* **科学计算应用:**  Android 设备上的科学计算应用会直接或间接地使用这些底层的数学函数。

**逻辑推理的假设输入与输出：**

以 `BM_math_isfinite` 为例：

* **假设输入:**  `values` 数组中的不同值：`1234.0`, `nan("")`, `HUGE_VAL`, `0.0`
* **逻辑:**  `isfinite(double x)` 函数判断浮点数 `x` 是否是有限的（既不是无穷大也不是 NaN）。
* **预期输出:**
    * `isfinite(1234.0)` 应该返回一个非零值（表示真）。
    * `isfinite(nan(""))` 应该返回 0（表示假）。
    * `isfinite(HUGE_VAL)` 应该返回 0（表示假）。
    * `isfinite(0.0)` 应该返回一个非零值（表示真）。

**用户或编程常见的使用错误举例说明：**

* **未检查 NaN 或无穷大:**  程序员可能会在没有检查结果是否为 NaN 或无穷大的情况下，直接使用数学函数的返回值进行后续计算，这可能导致程序崩溃或产生不可预测的结果。
    ```c++
    double x = sqrt(-1.0); // x is NaN
    double y = x + 5.0;    // y is also NaN, 但可能没有被预期到
    ```
* **浮点数比较的精度问题:** 直接使用 `==` 比较两个浮点数是否相等通常是不可靠的，因为浮点数的表示存在精度问题。应该使用一个小的误差范围进行比较。
    ```c++
    double a = 0.1 + 0.2;
    double b = 0.3;
    if (a == b) { // 很有可能不成立
        // ...
    }
    // 应该使用类似 fabs(a - b) < epsilon 的方式比较
    ```
* **处理除零错误:**  尽管数学库通常会处理除零的情况（返回无穷大或 NaN），但程序员仍然需要意识到这一点，并避免在代码中显式地进行除零操作，或者在需要时进行适当的处理。

**Android Framework 或 NDK 如何一步步到达这里（调试线索）：**

1. **Android Framework 或 Native App 调用数学函数:**
   * **Java 代码 (Framework):** Android Framework 的 Java 代码可能会调用 `java.lang.Math` 类中的静态方法，例如 `Math.sqrt()`, `Math.sin()` 等。这些 Java 方法最终会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 中的本地代码。
   * **Kotlin 代码 (Framework/App):** Kotlin 代码也会调用类似的 `kotlin.math` 包中的函数，同样会通过某种机制（可能直接编译为本地代码或通过 JVM 调用）到达底层。
   * **NDK (Native App):**  使用 NDK 开发的 C/C++ 应用可以直接包含 `<math.h>` 头文件，并调用标准 C 数学库中的函数，例如 `sqrt()`, `sin()`。

2. **Android Runtime (ART) 或 Bionic 链接器:**
   * 当 ART 执行 Java/Kotlin 代码中的 `Math` 方法时，它会查找对应的本地实现。
   * 当 Native App 调用 C 数学函数时，链接器（在 Android 中主要是 `linker`）负责在运行时将应用程序与 Bionic 库（`libc.so` 或 `libm.so`，数学函数通常在 `libm.so` 中）链接起来。

3. **Bionic 库 (`libm.so`):**  最终，这些调用会到达 Bionic 库中的数学函数实现。`math_benchmark.cpp` 文件中的代码就是针对 `libm.so` 中这些函数的性能进行测试。

**调试线索:**

* **Java/Kotlin 代码:** 如果问题出在 Java/Kotlin 代码中调用的数学函数，可以使用 Android Studio 的调试器来断点跟踪代码的执行，查看传递给 `Math` 类方法的参数和返回值。
* **JNI 调用:** 如果怀疑问题发生在 JNI 调用过程中，可以使用 JNI 相关的调试技巧，例如打印 JNI 参数和返回值，或者使用 специальный JNI 调试器。
* **Native 代码 (NDK):** 如果问题出在 Native 代码中，可以使用 LLDB 或 gdb 连接到设备或模拟器上的进程，设置断点在调用的数学函数上，查看函数的输入和输出，以及执行过程中的变量值。
* **Bionic 库源码:** 如果需要深入了解 Bionic 数学函数的实现细节，可以查看 Android 源代码仓库中 `bionic/libm` 目录下的相关代码。

总而言之，`bionic/benchmarks/math_benchmark.cpp` 是一个底层的性能测试文件，它直接测试了 Android 系统中核心的数学函数库的效率，而这些数学函数又被 Android 框架和应用程序广泛使用。 理解这个文件的作用有助于我们更好地理解 Android 系统的底层工作原理以及如何进行性能优化。

Prompt: 
```
这是目录为bionic/benchmarks/math_benchmark.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <fenv.h>
#include <math.h>

#include <benchmark/benchmark.h>
#include "util.h"

static const double values[] = { 1234.0, nan(""), HUGE_VAL, 0.0 };
static const char* names[] = { "1234.0", "nan", "HUGE_VAL", "0.0" };

static void SetLabel(benchmark::State& state) {
  state.SetLabel(names[state.range(0)]);
}

// Avoid optimization.
volatile double d;
volatile double v;
volatile float f;

static float zero = 0.0f;
static double zerod = 0.0f;

static void BM_math_sqrt(benchmark::State& state) {
  d = 0.0;
  v = 2.0;
  while (state.KeepRunning()) {
    d += sqrt(v);
  }
}
BIONIC_BENCHMARK(BM_math_sqrt);

static void BM_math_log10(benchmark::State& state) {
  d = 0.0;
  v = 1234.0;
  while (state.KeepRunning()) {
    d += log10(v);
  }
}
BIONIC_BENCHMARK(BM_math_log10);

static void BM_math_logb(benchmark::State& state) {
  d = 0.0;
  v = 1234.0;
  while (state.KeepRunning()) {
    d += logb(v);
  }
}
BIONIC_BENCHMARK(BM_math_logb);

static void BM_math_isfinite_macro(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += isfinite(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isfinite_macro, "MATH_COMMON");

static void BM_math_isfinite(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += isfinite(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isfinite, "MATH_COMMON");

static void BM_math_isinf_macro(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += isinf(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isinf_macro, "MATH_COMMON");

static void BM_math_isinf(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += (isinf)(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isinf, "MATH_COMMON");

static void BM_math_isnan_macro(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += isnan(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isnan_macro, "MATH_COMMON");

static void BM_math_isnan(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += (isnan)(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isnan, "MATH_COMMON");

static void BM_math_isnormal_macro(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += isnormal(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isnormal_macro, "MATH_COMMON");

static void BM_math_isnormal(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += isnormal(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_isnormal, "MATH_COMMON");

static void BM_math_sin_fast(benchmark::State& state) {
  d = 1.0;
  while (state.KeepRunning()) {
    d += sin(d);
  }
}
BIONIC_BENCHMARK(BM_math_sin_fast);

static void BM_math_sin_feupdateenv(benchmark::State& state) {
  d = 1.0;
  while (state.KeepRunning()) {
    fenv_t __libc_save_rm;
    feholdexcept(&__libc_save_rm);
    fesetround(FE_TONEAREST);
    d += sin(d);
    feupdateenv(&__libc_save_rm);
  }
}
BIONIC_BENCHMARK(BM_math_sin_feupdateenv);

static void BM_math_sin_fesetenv(benchmark::State& state) {
  d = 1.0;
  while (state.KeepRunning()) {
    fenv_t __libc_save_rm;
    feholdexcept(&__libc_save_rm);
    fesetround(FE_TONEAREST);
    d += sin(d);
    fesetenv(&__libc_save_rm);
  }
}
BIONIC_BENCHMARK(BM_math_sin_fesetenv);

static void BM_math_fpclassify(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += fpclassify(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_fpclassify, "MATH_COMMON");

static void BM_math_signbit_macro(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += signbit(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_signbit_macro, "MATH_COMMON");

static void BM_math_signbit(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += signbit(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_signbit, "MATH_COMMON");

static void BM_math_fabs_macro(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += fabs(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_fabs_macro, "MATH_COMMON");

static void BM_math_fabs(benchmark::State& state) {
  d = 0.0;
  v = values[state.range(0)];
  while (state.KeepRunning()) {
    d += (fabs)(v);
  }
  SetLabel(state);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_fabs, "MATH_COMMON");

static void BM_math_sincos(benchmark::State& state) {
  d = 1.0;
  while (state.KeepRunning()) {
    double s, c;
    sincos(d, &s, &c);
    d += s + c;
  }
}
BIONIC_BENCHMARK(BM_math_sincos);

#include "expf_input.cpp"

static void BM_math_expf_speccpu2017(benchmark::State& state) {
  f = 0.0;
  auto cin = expf_input.cbegin();
  for (auto _ : state) {
    f = expf(*cin);
    if (++cin == expf_input.cend())
      cin = expf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_expf_speccpu2017);

static void BM_math_expf_speccpu2017_latency(benchmark::State& state) {
  f = 0.0;
  auto cin = expf_input.cbegin();
  for (auto _ : state) {
    f = expf(f * zero + *cin);
    if (++cin == expf_input.cend())
      cin = expf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_expf_speccpu2017_latency);

// Create a double version of expf_input to avoid overhead of float to
// double conversion.
static const std::vector<double> exp_input (expf_input.begin(),
                                            expf_input.end());

static void BM_math_exp_speccpu2017(benchmark::State& state) {
  d = 0.0;
  auto cin = exp_input.cbegin();
  for (auto _ : state) {
    d = exp(*cin);
    if (++cin == exp_input.cend())
      cin = exp_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_exp_speccpu2017);

static void BM_math_exp_speccpu2017_latency(benchmark::State& state) {
  d = 0.0;
  auto cin = exp_input.cbegin();
  for (auto _ : state) {
    d = exp(d * zerod + *cin);
    if (++cin == exp_input.cend())
      cin = exp_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_exp_speccpu2017_latency);

static void BM_math_exp2f_speccpu2017(benchmark::State& state) {
  f = 0.0;
  auto cin = expf_input.cbegin();
  for (auto _ : state) {
    f = exp2f(*cin);
    if (++cin == expf_input.cend())
      cin = expf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_exp2f_speccpu2017);

static void BM_math_exp2f_speccpu2017_latency(benchmark::State& state) {
  f = 0.0;
  auto cin = expf_input.cbegin();
  for (auto _ : state) {
    f = exp2f(f * zero + *cin);
    if (++cin == expf_input.cend())
      cin = expf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_exp2f_speccpu2017_latency);

static void BM_math_exp2_speccpu2017(benchmark::State& state) {
  d = 0.0;
  auto cin = exp_input.cbegin();
  for (auto _ : state) {
    f = exp2(*cin);
    if (++cin == exp_input.cend())
      cin = exp_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_exp2_speccpu2017);

static void BM_math_exp2_speccpu2017_latency(benchmark::State& state) {
  d = 0.0;
  auto cin = exp_input.cbegin();
  for (auto _ : state) {
    f = exp2(d * zero + *cin);
    if (++cin == exp_input.cend())
      cin = exp_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_exp2_speccpu2017_latency);

#include "powf_input.cpp"

static const std::vector<std::pair<double, double>> pow_input
  (powf_input.begin(), powf_input.end());

static void BM_math_powf_speccpu2006(benchmark::State& state) {
  f = 0.0;
  auto cin = powf_input.cbegin();
  for (auto _ : state) {
    f = powf(cin->first, cin->second);
    if (++cin == powf_input.cend())
      cin = powf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_powf_speccpu2006);

static void BM_math_powf_speccpu2017_latency(benchmark::State& state) {
  f = 0.0;
  auto cin = powf_input.cbegin();
  for (auto _ : state) {
    f = powf(f * zero + cin->first, cin->second);
    if (++cin == powf_input.cend())
      cin = powf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_powf_speccpu2017_latency);

static void BM_math_pow_speccpu2006(benchmark::State& state) {
  d = 0.0;
  auto cin = pow_input.cbegin();
  for (auto _ : state) {
    f = pow(cin->first, cin->second);
    if (++cin == pow_input.cend())
      cin = pow_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_pow_speccpu2006);

static void BM_math_pow_speccpu2017_latency(benchmark::State& state) {
  d = 0.0;
  auto cin = pow_input.cbegin();
  for (auto _ : state) {
    d = powf(d * zero + cin->first, cin->second);
    if (++cin == pow_input.cend())
      cin = pow_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_pow_speccpu2017_latency);

#include "logf_input.cpp"

static const std::vector<double> log_input (logf_input.begin(),
                                            logf_input.end());

static void BM_math_logf_speccpu2017(benchmark::State& state) {
  f = 0.0;
  auto cin = logf_input.cbegin();
  for (auto _ : state) {
    f = logf(*cin);
    if (++cin == logf_input.cend())
      cin = logf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_logf_speccpu2017);

static void BM_math_logf_speccpu2017_latency(benchmark::State& state) {
  f = 0.0;
  auto cin = logf_input.cbegin();
  for (auto _ : state) {
    f = logf(f * zero + *cin);
    if (++cin == logf_input.cend())
      cin = logf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_logf_speccpu2017_latency);

static void BM_math_log_speccpu2017(benchmark::State& state) {
  d = 0.0;
  auto cin = log_input.cbegin();
  for (auto _ : state) {
    d = log(*cin);
    if (++cin == log_input.cend())
      cin = log_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_log_speccpu2017);

static void BM_math_log_speccpu2017_latency(benchmark::State& state) {
  d = 0.0;
  auto cin = log_input.cbegin();
  for (auto _ : state) {
    d = log(d * zerod + *cin);
    if (++cin == log_input.cend())
      cin = log_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_log_speccpu2017_latency);

static void BM_math_log2f_speccpu2017(benchmark::State& state) {
  f = 0.0;
  auto cin = logf_input.cbegin();
  for (auto _ : state) {
    f = log2f(*cin);
    if (++cin == logf_input.cend())
      cin = logf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_log2f_speccpu2017);

static void BM_math_log2_speccpu2017_latency(benchmark::State& state) {
  d = 0.0;
  auto cin = log_input.cbegin();
  for (auto _ : state) {
    d = log2(d * zerod + *cin);
    if (++cin == log_input.cend())
      cin = log_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_log2_speccpu2017_latency);

static void BM_math_log2_speccpu2017(benchmark::State& state) {
  d = 0.0;
  auto cin = log_input.cbegin();
  for (auto _ : state) {
    d = log2(*cin);
    if (++cin == log_input.cend())
      cin = log_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_log2_speccpu2017);

static void BM_math_log2f_speccpu2017_latency(benchmark::State& state) {
  f = 0.0;
  auto cin = logf_input.cbegin();
  for (auto _ : state) {
    f = log2f(f * zero + *cin);
    if (++cin == logf_input.cend())
      cin = logf_input.cbegin();
  }
}
BIONIC_BENCHMARK(BM_math_log2f_speccpu2017_latency);

// Four ranges of values are checked:
// * 0.0 <= x < 0.1
// * 0.1 <= x < 0.7
// * 0.7 <= x < 3.1
// * -3.1 <= x < 3.1
// * 3.3 <= x < 33.3
// * 100.0 <= x < 1000.0
// * 1e6 <= x < 1e32
// * 1e32 < x < FLT_MAX

#include "sincosf_input.cpp"

static void BM_math_sinf(benchmark::State& state) {
  auto range = sincosf_input[state.range(0)];
  auto cin = range.values.cbegin();
  f = 0.0;
  for (auto _ : state) {
    f = sinf(*cin);
    if (++cin == range.values.cend())
      cin = range.values.cbegin();
  }
  state.SetLabel(range.label);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_sinf, "MATH_SINCOS_COMMON");

static void BM_math_sinf_latency(benchmark::State& state) {
  auto range = sincosf_input[state.range(0)];
  auto cin = range.values.cbegin();
  f = 0.0;
  for (auto _ : state) {
    f = sinf(f * zero + *cin);
    if (++cin == range.values.cend())
      cin = range.values.cbegin();
  }
  state.SetLabel(range.label);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_sinf_latency, "MATH_SINCOS_COMMON");

static void BM_math_cosf(benchmark::State& state) {
  auto range = sincosf_input[state.range(0)];
  auto cin = range.values.cbegin();
  f = 0.0;
  for (auto _ : state) {
    f = cosf(*cin);
    if (++cin == range.values.cend())
      cin = range.values.cbegin();
  }
  state.SetLabel(range.label);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_cosf, "MATH_SINCOS_COMMON");

static void BM_math_cosf_latency(benchmark::State& state) {
  auto range = sincosf_input[state.range(0)];
  auto cin = range.values.cbegin();
  f = 0.0;
  for (auto _ : state) {
    f = cosf(f * zero + *cin);
    if (++cin == range.values.cend())
      cin = range.values.cbegin();
  }
  state.SetLabel(range.label);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_cosf_latency, "MATH_SINCOS_COMMON");

static void BM_math_sincosf(benchmark::State& state) {
  auto range = sincosf_input[state.range(0)];
  auto cin = range.values.cbegin();
  f = 0.0;
  for (auto _ : state) {
    float s, c;
    sincosf(*cin, &s, &c);
    f += s;
    if (++cin == range.values.cend())
      cin = range.values.cbegin();
  }
  state.SetLabel(range.label);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_sincosf, "MATH_SINCOS_COMMON");

static void BM_math_sincosf_latency(benchmark::State& state) {
  auto range = sincosf_input[state.range(0)];
  auto cin = range.values.cbegin();
  f = 0.0;
  for (auto _ : state) {
    float s, c;
    sincosf(f * zero + *cin, &s, &c);
    f += s;
    if (++cin == range.values.cend())
      cin = range.values.cbegin();
  }
  state.SetLabel(range.label);
}
BIONIC_BENCHMARK_WITH_ARG(BM_math_sincosf_latency, "MATH_SINCOS_COMMON");

"""

```
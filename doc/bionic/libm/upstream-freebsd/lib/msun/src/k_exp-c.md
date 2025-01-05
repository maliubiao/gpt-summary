Response:
Let's break down the thought process for analyzing the `k_exp.c` file. The request asks for a comprehensive understanding, covering functionality, relation to Android, implementation details, dynamic linking aspects, potential errors, and debugging.

**1. Initial Understanding of the File:**

* **Title and Location:** "k_exp.c in bionic/libm/upstream-freebsd/lib/msun/src/". This immediately tells us it's part of Android's math library (`libm`), specifically leveraging code from FreeBSD's `msun` (math software in C). The `k_` prefix often suggests a kernel or core implementation, but in this context, it's just a file name convention within the FreeBSD source.
* **License:** BSD-2-Clause license – important for understanding usage rights and attributions.
* **Copyright:**  Attribution to David Schultz and FreeBSD.
* **Includes:** `complex.h`, `math.h`, `math_private.h`. This indicates it deals with both real and complex number exponentials and relies on internal math library definitions.

**2. Core Functionality Identification:**

* **Comments:** The comments are crucial. They explicitly state the purpose of `__frexp_exp`, `__ldexp_exp`, and `__ldexp_cexp`.
    * `__frexp_exp`: Computes `exp(x)` scaled to avoid overflow, returning a separate exponent.
    * `__ldexp_exp`: Computes `exp(x) * 2**expt` for large real `x`.
    * `__ldexp_cexp`: Computes `exp(z) * 2**expt` for large complex `z`.
* **Key Constants:** `k` and `kln2` are used for the reduction technique in `__frexp_exp`. The comment explains the purpose of this reduction: minimizing the error when approximating `exp(k*ln2)` with `2**k`.
* **High-Level Logic:** The code focuses on handling large input values to the exponential function to avoid overflow or loss of precision. It achieves this by:
    * **Reduction:**  Subtracting a multiple of `ln(2)` (`kln2`) from the input and then multiplying by the corresponding power of 2.
    * **Scaling:**  Explicitly managing the exponent to keep intermediate results within a manageable range.

**3. Relating to Android:**

* **`libm`'s Role:**  Recognize that `libm` is fundamental for any application performing mathematical calculations on Android. This includes scientific apps, games, graphics libraries, and even core system components.
* **NDK Usage:** The NDK allows developers to use C/C++ code in Android apps. Functions from `libm`, including these exponential functions, are directly accessible via the NDK.
* **Framework Indirect Use:** The Android Framework, written in Java/Kotlin, often relies on native libraries for performance-critical tasks. Mathematical operations might be delegated down to `libm`.

**4. Detailed Implementation Analysis:**

* **`__frexp_exp`:**
    * **Reduction:** `exp(x - kln2)` is the core of the computation.
    * **Exponent Extraction:**  `GET_HIGH_WORD` and bit manipulation are used to extract the exponent of the initial `exp_x` and adjust it. The goal is to separate the mantissa and the exponent.
    * **Exponent Manipulation:** `SET_HIGH_WORD` sets the exponent to `MAX_EXP` (implicitly 1023) to prevent denormalization issues when the result is later multiplied by a small scaling factor.
* **`__ldexp_exp`:**
    * **Calling `__frexp_exp`:**  Leverages the work done in the previous function.
    * **Exponent Adjustment:**  Adds the provided `expt` to the exponent calculated by `__frexp_exp`.
    * **Scaling:**  Constructs a scaling factor (`scale`) by directly manipulating its bit representation to achieve the desired power of 2. This is more efficient than using a general power function.
* **`__ldexp_cexp`:**
    * **Complex Number Handling:** Extracts the real and imaginary parts.
    * **Real Part Exponential:** Calls `__frexp_exp` on the real part.
    * **Trigonometric Calculation:** Uses `sincos` to compute the sine and cosine of the imaginary part.
    * **Scaling for Complex Numbers:** Splits the exponent into two parts (`scale1`, `scale2`) to avoid potential overflow issues during intermediate calculations. This clever optimization leverages the property that multiplication is associative.
    * **Complex Result Construction:** Combines the scaled exponential of the real part with the sine and cosine of the imaginary part to form the complex exponential result.

**5. Dynamic Linker Aspects:**

* **SO Layout:** Describe the typical structure of a shared library (`.so` file), including sections like `.text`, `.data`, `.bss`, `.dynsym`, `.plt`, `.got`.
* **Symbol Resolution:** Explain the difference between defined symbols (exported by the library) and undefined symbols (imported by the library). Detail the roles of the `.dynsym`, `.plt`, and `.got` in resolving these symbols at runtime. Distinguish between direct linking and lazy linking.

**6. Logical Reasoning and Examples:**

* **Hypothetical Inputs/Outputs:** Choose simple cases to illustrate how the functions might behave, especially the scaling aspect. For example, show how a large input to `__frexp_exp` results in a scaled mantissa and an adjusted exponent.
* **Common Errors:** Focus on misuse related to:
    * **Overflow/Underflow:**  Passing extremely large or small values.
    * **Incorrect Argument Types:**  Mixing up real and complex numbers.
    * **Ignoring Return Values:** Not checking for potential errors (although these functions don't explicitly signal errors in the provided code).

**7. Debugging Path:**

* **NDK Call:** Start with a simple NDK example calling `exp()` or `cexp()`.
* **`strace`:** Use `strace` to observe system calls and library loading.
* **Debugger (GDB/LLDB):** Set breakpoints within `libm`, specifically in `k_exp.c`, to trace execution flow and inspect variables.
* **Source Code Navigation:** Use tools like `grep` or IDE features to find the source code and related functions. Understanding the call stack is crucial.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:** "Is `k_exp.c` really kernel-related?"  **Correction:** The `k_` is likely just a naming convention from FreeBSD.
* **Initial thought:**  "The scaling might be about performance." **Refinement:** The primary reason for scaling is to *avoid overflow* with large inputs and to *prevent loss of precision due to denormalization* with small intermediate results. Performance is a secondary benefit.
* **Initial thought:**  "Just explain the basic `exp()` function." **Refinement:** The code specifically deals with large arguments, so the explanation should focus on the techniques used for this scenario (reduction and explicit exponent management).
* **Dynamic Linking Details:** Initially might have oversimplified. **Refinement:** Need to clearly distinguish between `.dynsym`, `.plt`, and `.got` and their roles in symbol resolution. Also, explain lazy binding.

By following this structured thought process, combining code analysis with understanding the surrounding context (Android, `libm`, dynamic linking), and anticipating potential questions, we can arrive at a comprehensive and accurate explanation of the `k_exp.c` file.
好的，让我们深入分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/k_exp.c` 这个文件。

**文件功能：**

这个文件 `k_exp.c` 包含了 `libm` 库中用于计算指数函数 `exp(x)` 和复数指数函数 `cexp(z)` 的一些辅助函数，尤其针对处理大数值输入以避免溢出和提高精度。  主要包含以下三个函数：

1. **`__frexp_exp(double x, int *expt)`:**
   - **功能:** 计算 `exp(x)` 并进行缩放，以避免在后续计算中发生溢出。它返回一个被缩放的值，并将实际的指数部分存储在 `expt` 指针指向的整数中。
   - **核心思想:** 利用 `exp(x) = exp(x - k * ln(2)) * 2^k` 的性质，其中 `k` 是一个精心选择的常数。这样可以将指数计算分解为计算一个较小值的指数和一个简单的 2 的幂次。  同时，它将返回结果的指数部分调整到一个较大的值（`MAX_EXP`，即 1023），以便后续可以乘以一个很小的数而不会因反常化（denormalization）损失精度。

2. **`__ldexp_exp(double x, int expt)`:**
   - **功能:** 计算 `exp(x) * 2**expt`，主要用于处理实数部分很大的情况，以避免溢出。
   - **核心思想:** 它首先调用 `__frexp_exp` 获取缩放后的指数值和相应的指数部分，然后将传入的 `expt` 与从 `__frexp_exp` 获取的指数部分相加，最后通过构造一个合适的比例因子（`scale`）来实现乘以 2 的 `expt` 次方。  直接操作浮点数的位表示来构造 `scale` 比使用 `pow` 函数更高效。

3. **`__ldexp_cexp(double complex z, int expt)`:**
   - **功能:** 计算 `exp(z) * 2**expt`，其中 `z` 是一个复数。同样用于处理实部很大的情况。
   - **核心思想:**  对于复数 `z = x + iy`，`exp(z) = exp(x) * (cos(y) + i * sin(y)) = exp(x) * cis(y)`。  该函数首先调用 `__frexp_exp` 计算 `exp(x)` 并获取其指数部分。然后，它计算 `cos(y)` 和 `sin(y)`。为了乘以 `2**expt`，它将 `expt` 分成两部分，分别构造两个比例因子 `scale1` 和 `scale2`，使得 `scale1 * scale2 = 2**expt`。这样做是为了避免在中间计算过程中发生溢出。最后，它将各项相乘得到复数结果。

**与 Android 功能的关系：**

这个文件是 Android C 库 `bionic` 的一部分，`libm` 提供了标准的数学函数。这些函数被 Android 系统和应用程序广泛使用：

* **Android Framework:** Android Framework 中使用 Java 或 Kotlin 编写的类库和组件，在底层可能会调用 Native 代码（C/C++）来实现一些数学运算，例如图形渲染、动画、传感器数据处理等。这些 Native 代码最终可能会调用 `libm` 中的函数。
    * **举例:**  在进行图形变换时，例如旋转、缩放，会涉及到三角函数和指数函数的计算，这些计算最终可能通过 JNI 调用到 `libm` 库中的相应函数。
* **Android NDK (Native Development Kit):** NDK 允许开发者使用 C 和 C++ 编写 Android 应用的部分代码。使用 NDK 的应用程序可以直接调用 `libm` 提供的数学函数，包括这里的 `__ldexp_exp` 和 `__ldexp_cexp` (尽管这些是内部函数，通常用户会调用 `exp` 和 `cexp`，而 `libm` 内部会根据情况使用这些辅助函数)。
    * **举例:**  一个游戏引擎使用 C++ 开发，在计算物理模拟、特效或者 AI 时，可能会用到复杂的数学运算，直接调用 `exp()` 或 `cexp()`，而 `libm` 最终可能会使用 `k_exp.c` 中的函数。

**libc 函数的实现细节：**

这里讨论的不是标准的 libc 函数（如 `exp` 或 `cexp`）的完整实现，而是它们的辅助函数。标准的 `exp` 和 `cexp` 函数可能会根据输入参数的不同范围和精度要求，选择不同的计算方法。对于大数值输入，它们可能会调用 `k_exp.c` 中提供的函数来避免溢出。

* **`__frexp_exp` 实现细节:**
    1. **常数 `k` 和 `kln2`:** `k` 是一个精心选择的整数，使得 `k * ln(2)` 非常接近一个整数，这有助于减小误差。`kln2` 预先计算好了 `k * ln(2)` 的值。
    2. **指数缩减:** `exp_x = exp(x - kln2);`  通过减去 `kln2`，将指数的计算范围缩小，避免直接计算大数值的指数。
    3. **提取和调整指数:** 使用位操作 (`GET_HIGH_WORD`, `SET_HIGH_WORD`) 来提取浮点数的最高有效字（包含符号、指数和部分尾数）。通过调整指数部分，将 `exp_x` 的指数设置为一个较大的固定值，并将真实的指数差值存储在 `expt` 中。这样做是为了防止后续乘以小数值时出现精度损失。
* **`__ldexp_exp` 实现细节:**
    1. **调用 `__frexp_exp`:**  复用 `__frexp_exp` 的缩放功能。
    2. **指数累加:** 将传入的 `expt` 与从 `__frexp_exp` 获取的指数 `ex_expt` 相加，得到最终的指数。
    3. **构造比例因子:**  使用位操作直接构造一个表示 `2**expt` 的浮点数 `scale`。  `INSERT_WORDS` 用于将指定的两个 32 位字组合成一个 64 位双精度浮点数。`(0x3ff + expt) << 20` 将指数部分设置为 `expt`。
    4. **相乘:** 将缩放后的指数值 `exp_x` 乘以比例因子 `scale`，得到最终结果。
* **`__ldexp_cexp` 实现细节:**
    1. **分离实部和虚部:** 从复数 `z` 中提取实部 `x` 和虚部 `y`。
    2. **计算实部指数:** 调用 `__frexp_exp` 计算 `exp(x)` 并获取指数部分。
    3. **计算三角函数:** 使用 `sincos(y, &s, &c)` 同时计算 `sin(y)` 和 `cos(y)`，提高效率。
    4. **分割指数和构造比例因子:**  为了避免中间计算溢出，将 `expt` 分成两半 (`half_expt`)，并分别构造两个比例因子 `scale1` 和 `scale2`。
    5. **计算复数指数:**  根据公式 `exp(z) = exp(x) * (cos(y) + i * sin(y))` 进行计算。

**dynamic linker 的功能和符号处理：**

dynamic linker (在 Android 上是 `linker` 或 `linker64`) 负责在程序运行时加载共享库（`.so` 文件）并将程序中对共享库函数的调用链接到库中实际的函数地址。

**SO 布局样本:**

一个典型的 `.so` 文件（例如 `libm.so`）的布局可能包含以下部分：

* **`.text` (代码段):** 包含可执行的机器指令，例如 `__frexp_exp`, `__ldexp_exp`, `__ldexp_cexp` 的代码。
* **`.rodata` (只读数据段):** 包含只读数据，例如字符串常量、全局常量，可能包含 `kln2` 的值。
* **`.data` (已初始化数据段):** 包含已初始化的全局变量和静态变量。
* **`.bss` (未初始化数据段):** 包含未初始化的全局变量和静态变量。
* **`.dynsym` (动态符号表):** 包含共享库导出的和导入的符号信息（函数名、变量名等）。
* **`.plt` (过程链接表):** 用于延迟绑定（lazy binding），存储外部函数的跳转指令的占位符。
* **`.got` (全局偏移表):** 存储外部函数的实际地址，由 dynamic linker 在运行时填充。
* **其他段:**  例如 `.dynamic` (包含 dynamic linker 的信息), `.symtab` (符号表), `.strtab` (字符串表) 等。

**符号处理过程:**

1. **程序启动:** 当 Android 启动一个使用共享库的应用程序时，dynamic linker 会被加载到进程空间。
2. **加载共享库:**  dynamic linker 根据程序依赖关系加载所需的共享库（例如 `libm.so`）。
3. **符号查找:**
   - **导出符号:** `libm.so` 会将其导出的函数（例如 `exp`, `cexp`，以及一些内部符号如 `__frexp_exp` 等，尽管内部符号通常不会直接导出给外部使用）的信息添加到其 `.dynsym` 表中。
   - **导入符号:** 如果 `libm.so` 依赖于其他共享库的函数，这些函数会被列为导入符号。
4. **重定位:**
   - **GOT (Global Offset Table):**  对于程序中调用共享库函数的地方，编译器会生成通过 GOT 跳转的代码。GOT 中的每个条目最初指向 `.plt` 中的一段代码。
   - **PLT (Procedure Linkage Table):**  当程序第一次调用一个外部函数时，会跳转到 PLT 中对应的条目。
   - **延迟绑定 (Lazy Binding):** 默认情况下，dynamic linker 使用延迟绑定。PLT 中的代码会调用 dynamic linker 的一个函数来解析符号。dynamic linker 会在 `.dynsym` 中查找被调用函数的地址，并将该地址更新到 GOT 中对应的条目。之后，对该函数的后续调用会直接通过 GOT 跳转到实际的函数地址，而无需再次解析。
   - **非延迟绑定 (Eager Binding):**  也可以配置为非延迟绑定，此时 dynamic linker 会在库加载时就解析所有符号。
5. **符号绑定:** dynamic linker 将程序中对共享库函数的调用与共享库中实际的函数地址绑定起来。

**示例:**

假设程序 `my_app` 调用了 `libm.so` 中的 `exp()` 函数。

1. 编译器在 `my_app` 的代码中生成调用 `exp()` 的指令，这会跳转到 `libm.so` 的 PLT 中 `exp@plt` 的条目。
2. 第一次调用 `exp()` 时，`exp@plt` 中的代码会调用 dynamic linker。
3. dynamic linker 在 `libm.so` 的 `.dynsym` 中查找 `exp` 的地址。
4. dynamic linker 将 `exp` 的实际地址写入 `libm.so` 的 GOT 中 `exp@got` 的条目。
5. 后续对 `exp()` 的调用会直接跳转到 `exp@got` 指向的地址，即 `libm.so` 中 `exp()` 函数的实际地址。

**逻辑推理、假设输入与输出:**

假设我们调用 `__frexp_exp(710.0, &expt)`：

* **假设输入:** `x = 710.0`
* **计算 `x - kln2`:** `710.0 - 1799 * ln(2)` 大约等于 `710.0 - 1246.97 = -536.97`。
* **计算 `exp(x - kln2)`:** `exp(-536.97)` 是一个非常小的数。
* **提取指数并设置:** `__frexp_exp` 会提取 `exp(x - kln2)` 的指数，并将其缩放到 `MAX_EXP` (1023)。
* **`expt` 的值:** `expt` 会被设置为一个值，使得 `2**expt` 乘以返回的缩放后的值约等于 `exp(710.0)`。 具体来说，`expt` 大概是  `原指数 - 1023 + k`。
* **输出:** `__frexp_exp` 返回一个介于 `[2^1023, 2^1024)` 之间的值，`expt` 指向的整数存储着计算出的指数。

假设我们调用 `__ldexp_exp(scaled_exp_val, saved_expt)`，其中 `scaled_exp_val` 是上面 `__frexp_exp` 的返回值，`saved_expt` 是上面计算出的 `expt` 值，并且 `expt` 参数为 0：

* **假设输入:** `x = scaled_exp_val`, `expt = 0`, `ex_expt = saved_expt`
* **指数累加:** `0 + saved_expt = saved_expt`
* **构造比例因子:** `scale` 将表示 `2**saved_expt`。
* **输出:**  `scaled_exp_val * 2**saved_expt`，这应该近似等于原始的 `exp(710.0)`。

**用户或编程常见的使用错误：**

1. **直接调用内部函数:** 用户不应该直接调用像 `__frexp_exp` 这样的内部函数。这些函数是 `libm` 内部使用的，其接口和行为可能在不同版本之间发生变化，不保证 API 稳定性。应该使用标准的 `exp()` 和 `cexp()` 函数。
2. **误解参数含义:**  如果用户错误地理解了 `__ldexp_exp` 的 `expt` 参数的含义，可能会导致计算结果错误。例如，错误地认为 `expt` 是最终的指数，而没有考虑到内部的指数调整。
3. **忽略溢出或下溢:**  即使 `libm` 内部做了处理，对于非常极端的大或小数值，仍然可能发生溢出或下溢。程序员应该根据应用场景合理地处理这些情况。
4. **精度问题:** 浮点数运算本身存在精度问题。直接比较浮点数是否相等是不可靠的。应该使用误差范围进行比较。
5. **在不适用的场景下使用:** 开发者可能在不需要处理大数值的情况下使用了这些内部函数（如果他们错误地认为这样做会带来性能提升）。

**Android Framework 或 NDK 如何到达这里 (调试线索):**

1. **NDK 应用调用 `exp()`:**
   - 使用 NDK 开发的 C/C++ 代码中调用了 `std::exp()` 或 `cexp()`.
   - 编译器会将这些调用链接到 `libm.so` 中对应的符号。
   - 当程序运行时，dynamic linker 加载 `libm.so`。
   - 调用 `exp()` 或 `cexp()` 时，`libm` 的实现可能会根据输入参数的范围和精度要求，最终调用到 `k_exp.c` 中的 `__frexp_exp`, `__ldexp_exp`, 或 `__ldexp_cexp`。
   - **调试:**
     - 使用 GDB 或 LLDB 连接到正在运行的 Android 进程。
     - 在 `exp` 或 `cexp` 函数入口处设置断点。
     - 单步执行，观察调用堆栈，可以逐步进入 `libm` 的内部实现，最终到达 `k_exp.c`。
     - 也可以在 `k_exp.c` 中的函数入口处设置断点，看是否被调用。

2. **Android Framework 调用 (通过 JNI):**
   - Android Framework 中 Java/Kotlin 代码需要执行一些底层的数学运算。
   - Framework 会通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++) 来实现这些运算.
   - 这些 Native 代码可能链接到 `libm.so`，并调用 `exp()` 或 `cexp()`.
   - **调试:**
     - 如果可以修改 Framework 代码（通常需要 AOSP 编译），可以在 JNI 调用处添加日志或断点。
     - 使用 `adb logcat` 观察 Framework 的日志输出。
     - 可以尝试使用 Android Studio 的 Profiler 工具来分析 CPU 使用情况，找到性能瓶颈，并可能定位到 `libm` 的调用。
     - 也可以使用 Systrace 或 Perf 这样的性能分析工具来跟踪系统调用和函数调用。

**逐步到达 `k_exp.c` 的过程 (NDK 示例):**

```c++
// my_app.cpp (使用 NDK)
#include <cmath>
#include <complex>
#include <android/log.h>

#define LOG_TAG "MyApp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" int main(int argc, char** argv) {
  double x = 710.0;
  double result_exp = std::exp(x);
  LOGI("exp(%f) = %f", x, result_exp);

  std::complex<double> z(710.0, 1.0);
  std::complex<double> result_cexp = std::exp(z);
  LOGI("cexp(%f + %fi) = %f + %fi", z.real(), z.imag(), result_cexp.real(), result_cexp.imag());

  return 0;
}
```

**调试步骤:**

1. **编译并运行 NDK 应用。**
2. **使用 `adb shell` 连接到 Android 设备。**
3. **找到应用的进程 ID (PID)。**
4. **使用 GDB 或 LLDB 连接到该进程:**
   ```bash
   gdbserver :5039 --attach <PID>
   adb forward tcp:5039 tcp:5039
   gdbclient :5039
   ```
5. **在 `exp` 函数入口处设置断点:**
   ```gdb
   b exp
   或者 (如果知道是 libm 的 exp)
   b libm.so!exp
   ```
6. **继续执行 (`continue` 或 `c`)，程序会停在 `exp` 函数入口。**
7. **查看调用堆栈 (`bt` 或 `backtrace`)，可以看到 `exp` 函数是被 `std::exp` 调用的。**
8. **单步执行 (`next` 或 `n`， `step` 或 `s`)，可以观察 `exp` 函数内部的执行流程。**
9. **在 `k_exp.c` 中的函数 (`__frexp_exp`, `__ldexp_exp` 等) 设置断点:**
   ```gdb
   b libm.so!__frexp_exp
   ```
10. **继续执行，如果 `exp` 的实现逻辑需要处理大数值，最终会调用到 `k_exp.c` 中的函数。**

通过以上分析和调试方法，可以深入理解 `bionic/libm/upstream-freebsd/lib/msun/src/k_exp.c` 的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/k_exp.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 David Schultz <das@FreeBSD.ORG>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <complex.h>

#include "math.h"
#include "math_private.h"

static const uint32_t k = 1799;		/* constant for reduction */
static const double kln2 =  1246.97177782734161156;	/* k * ln2 */

/*
 * Compute exp(x), scaled to avoid spurious overflow.  An exponent is
 * returned separately in 'expt'.
 *
 * Input:  ln(DBL_MAX) <= x < ln(2 * DBL_MAX / DBL_MIN_DENORM) ~= 1454.91
 * Output: 2**1023 <= y < 2**1024
 */
static double
__frexp_exp(double x, int *expt)
{
	double exp_x;
	uint32_t hx;

	/*
	 * We use exp(x) = exp(x - kln2) * 2**k, carefully chosen to
	 * minimize |exp(kln2) - 2**k|.  We also scale the exponent of
	 * exp_x to MAX_EXP so that the result can be multiplied by
	 * a tiny number without losing accuracy due to denormalization.
	 */
	exp_x = exp(x - kln2);
	GET_HIGH_WORD(hx, exp_x);
	*expt = (hx >> 20) - (0x3ff + 1023) + k;
	SET_HIGH_WORD(exp_x, (hx & 0xfffff) | ((0x3ff + 1023) << 20));
	return (exp_x);
}

/*
 * __ldexp_exp(x, expt) and __ldexp_cexp(x, expt) compute exp(x) * 2**expt.
 * They are intended for large arguments (real part >= ln(DBL_MAX))
 * where care is needed to avoid overflow.
 *
 * The present implementation is narrowly tailored for our hyperbolic and
 * exponential functions.  We assume expt is small (0 or -1), and the caller
 * has filtered out very large x, for which overflow would be inevitable.
 */

double
__ldexp_exp(double x, int expt)
{
	double exp_x, scale;
	int ex_expt;

	exp_x = __frexp_exp(x, &ex_expt);
	expt += ex_expt;
	INSERT_WORDS(scale, (0x3ff + expt) << 20, 0);
	return (exp_x * scale);
}

double complex
__ldexp_cexp(double complex z, int expt)
{
	double c, exp_x, s, scale1, scale2, x, y;
	int ex_expt, half_expt;

	x = creal(z);
	y = cimag(z);
	exp_x = __frexp_exp(x, &ex_expt);
	expt += ex_expt;

	/*
	 * Arrange so that scale1 * scale2 == 2**expt.  We use this to
	 * compensate for scalbn being horrendously slow.
	 */
	half_expt = expt / 2;
	INSERT_WORDS(scale1, (0x3ff + half_expt) << 20, 0);
	half_expt = expt - half_expt;
	INSERT_WORDS(scale2, (0x3ff + half_expt) << 20, 0);

	sincos(y, &s, &c);
	return (CMPLX(c * exp_x * scale1 * scale2,
	    s * exp_x * scale1 * scale2));
}

"""

```
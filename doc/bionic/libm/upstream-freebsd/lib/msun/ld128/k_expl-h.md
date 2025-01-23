Response:
Let's break down the thought process for analyzing this C code snippet. The request is quite comprehensive, touching on various aspects of the code and its relation to Android.

**1. Initial Understanding & Core Functionality:**

* **Identify the File and Location:** The prompt clearly states the file is `k_expl.handroid` within the `bionic/libm` directory. This immediately tells us it's part of Android's math library and likely deals with some optimized, low-level mathematical operation.
* **Recognize the Core Operation:** The filename and the comments mentioning `expl(x)` and `exp2l()` immediately suggest this code is about calculating the exponential function (e<sup>x</sup>). The `k_` prefix often indicates a kernel or helper function within a larger implementation. The `ld128` part signals it's specifically for `long double` (128-bit) precision.
* **Note the FreeBSD Origin:** The `/* from: FreeBSD ... */` comment is crucial. It indicates that Android's `libm` (at least parts of it) are derived from FreeBSD's math library. This helps understand the code's likely structure and quality.

**2. Deconstructing the Code - Top-Down Approach:**

* **Macros and Constants:** Start by looking at the `#define` directives and the `static const` variables. These define important parameters and constants used in the calculations.
    * `INTERVALS`, `LOG2_INTERVALS`, `BIAS`:  These suggest a table-based approach with interval reduction. The `BIAS` relates to the exponent representation of floating-point numbers.
    * `INV_L`, `L2`, `L1`: These constants likely relate to the natural logarithm of 2 (ln(2)), used for reducing the input `x`. The `hi`/`lo` naming suggests a high-precision decomposition.
    * `A2` through `A10`: These are coefficients for a polynomial approximation of the exponential function around zero (Maclaurin series).
    * `tbl`: This is a crucial table of precomputed values. The comments hint at its role in the interval reduction and the `hi`/`lo` decomposition for increased precision.
* **Functions:** Identify the functions defined:
    * `__k_expl`:  This is the core kernel function. Its name (double underscore) often indicates it's an internal, non-public function.
    * `k_hexpl`: This function calls `__k_expl` and then scales the result. The `h` likely stands for "hybrid" or some variant.
    * `hexpl`: This is the higher-level function that likely provides the main interface for calculating `expl(x)`.
    * `__ldexp_cexpl`: This function handles the complex exponential case.
* **Code Structure within `__k_expl`:** Analyze the steps involved in the core kernel function:
    * **Reduction:** The code calculates `fn` and `n`, suggesting an interval reduction using ln(2).
    * **Polynomial Approximation:** The calculation of `q` using the `A` coefficients indicates a polynomial approximation of `exp(r)`.
    * **Table Lookup and Combination:** The code accesses the `tbl` and combines it with the polynomial result.

**3. Connecting to Android and libc:**

* **`libm` Role:**  Immediately recognize this code is part of Android's math library (`libm`), responsible for providing standard mathematical functions.
* **NDK Usage:**  Consider how developers using the Android NDK would access these functions. They would include `<math.h>` and call functions like `expl()`. The NDK provides the headers and libraries necessary for using these functions in native code.
* **Framework Connection:**  Think about how the Android framework itself might use these functions. Animations, graphics calculations, and physics simulations are potential areas.

**4. Addressing Specific Prompts:**

* **Functionality:** Summarize the purpose of each function based on the code and comments.
* **Android Relation:** Provide concrete examples of how the `expl()` function is used within Android (NDK, framework).
* **libc Function Implementation:** Explain the mathematical techniques used: interval reduction, polynomial approximation, and the role of the lookup table.
* **Dynamic Linker:** This requires understanding how shared libraries (`.so` files) are loaded and how symbols are resolved.
    * **SO Layout:** Describe the typical sections in an SO file (`.text`, `.data`, `.bss`, `.symtab`, `.dynsym`, `.rel.dyn`, `.rel.plt`).
    * **Symbol Resolution:** Explain the difference between static and dynamic linking, global and local symbols, and how the dynamic linker resolves symbols at runtime.
* **Logical Reasoning (Hypothetical Input/Output):** Choose simple inputs for `expl()` and trace the (simplified) execution flow to illustrate the output.
* **Common Usage Errors:** Think about typical mistakes programmers make when using math functions (overflow, underflow, incorrect input types).
* **Debugging Lineage:**  Trace the path from the Android framework or NDK down to this specific code within `libm`. This involves understanding the layers of the Android system.

**5. Refinement and Detail:**

* **Precision:** Emphasize the `ld128` aspect and the techniques used for high-precision calculations (hi/lo decomposition).
* **Optimization:**  Note the comments about optimization (Bruce D. Evans).
* **Potential Issues:**  Mention the comments about potentially unrounded coefficients and the historical reasons for certain design choices.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a simple exp function."  **Correction:**  Realize the complexity due to high precision requirements and the use of table lookups and polynomial approximations.
* **Initial thought:** "The dynamic linker is just magic." **Correction:**  Recall the basic principles of dynamic linking and symbol resolution.
* **While explaining the table:**  Initially focus only on the `hi` part. **Correction:** Realize the importance of the `lo` part for maintaining precision.

By following this structured approach, starting with a high-level understanding and then progressively drilling down into the details, while constantly connecting the code to the Android context, it's possible to generate a comprehensive and accurate analysis of the provided C code snippet.
这个目录 `bionic/libm/upstream-freebsd/lib/msun/ld128/k_expl.handroid` 下的源代码文件 `k_expl.handroid` 是 Android 的 C 标准库 `bionic` 中数学库 `libm` 的一部分，它源自 FreeBSD 的 `libm` 库。这个文件专门针对 `long double` (128位) 类型的浮点数实现了指数函数 `exp(x)` 的核心计算逻辑，通常被称为“kernel”。

**它的功能:**

1. **实现高精度指数函数的核心计算:** 该文件中的函数 `__k_expl` 是计算 `exp(x)` 的核心部分，它接收一个 `long double` 类型的输入 `x`，并计算出 `exp(x)` 的高精度结果，通常以两个 `long double` 数 `hip` (high part) 和 `lop` (low part) 的形式返回，用于表示结果的高低部分，以提高精度。
2. **利用查表和多项式逼近:** 为了提高计算效率和精度，该实现采用了查表法和多项式逼近相结合的技术。
    * **查表 (tbl):**  预先计算了一系列指数函数的近似值存储在 `tbl` 数组中，对应于将输入范围划分成若干个小区间后的端点值。
    * **多项式逼近 (A2-A10):** 对于输入值 `x` 经过区间归约后得到的小值，使用一个低阶多项式来逼近指数函数 `exp(r)`，这里的 `r` 是归约后的小值。
3. **处理 `long double` 类型:** 该文件专门针对 `long double` 类型进行了优化，利用其更高的精度进行计算。
4. **辅助函数:**  文件中还包含一些辅助函数，如 `k_hexpl` 和 `hexpl`，它们调用核心的 `__k_expl` 函数，并进行一些额外的处理，比如调整指数部分。
5. **复数指数函数的支持 (ifdef _COMPLEX_H):**  如果定义了宏 `_COMPLEX_H`，该文件还包含一个用于计算复数指数函数的函数 `__ldexp_cexpl`。

**与 Android 功能的关系及举例说明:**

Android 作为一个操作系统，其底层和应用层都广泛使用数学函数。`libm` 库是 Android 系统提供这些基本数学功能的核心组件。`k_expl.handroid` 作为 `libm` 的一部分，直接支持了需要高精度指数函数计算的场景。

* **NDK 开发:** 使用 Android NDK 进行原生 C/C++ 开发时，开发者可以直接调用 `exp()` 或 `expl()` 函数（对于 `long double` 类型）。`libm` 库中的这个文件就是这些函数实现的一部分。例如，在进行物理模拟、图形渲染、科学计算等需要高精度的场景中，可能会用到 `long double` 类型的指数函数。
    ```c++
    #include <cmath>
    #include <iostream>

    int main() {
        long double x = 2.0L;
        long double result = expl(x); // 调用 long double 版本的指数函数
        std::cout << "expl(" << x << ") = " << result << std::endl;
        return 0;
    }
    ```
    当这段代码在 Android 设备上运行时，`expl(x)` 的计算最终会涉及到 `k_expl.handroid` 中的代码。

* **Framework 层:** 虽然 Framework 层主要使用 Java 语言，但在一些底层或性能敏感的模块，可能会通过 JNI (Java Native Interface) 调用到底层的 C/C++ 代码，进而使用 `libm` 中的函数。例如，一些动画计算或图形处理的底层实现可能会用到指数函数。

**详细解释每一个 libc 函数的功能是如何实现的:**

1. **`__k_expl(long double x, long double *hip, long double *lop, int *kp)`:**
   * **功能:**  计算 `exp(x)` 的核心逻辑。
   * **实现:**
      * **区间归约:** 将输入 `x` 减去 `n * ln(2)`，其中 `n` 是一个整数，使得剩余的值 `r` 落在 `[-ln(2)/2, ln(2)/2]` 附近的一个小区间内。这里使用了预先计算好的 `INV_L`（近似于 `1/ln(2)`）和 `L1`, `L2`（`ln(2)/INTERVALS` 的高低部分）来进行高效的归约。
      * **查表:**  根据归约过程中得到的整数 `n`，计算出 `n % INTERVALS` 作为索引，从 `tbl` 数组中取出预先计算好的 `exp(endpoint[n2])` 的高低部分 `tbl[n2].hi` 和 `tbl[n2].lo`，其中 `endpoint[n2]` 是该小区间的起始点。
      * **多项式逼近:** 对于归约后的小值 `r`，使用泰勒级数展开的近似多项式来计算 `exp(r)`，即 `1 + r + r^2/2! + r^3/3! + ...`。代码中使用了霍纳scheme来高效地计算多项式的值，系数为 `A2` 到 `A10`。
      * **结果组合:** 将查表得到的值和多项式逼近的结果相乘，得到最终的 `exp(x)` 的近似值。由于使用了高低两部分表示，乘法也需要考虑精度，代码中将多项式结果 `q` 和 `r1` 组合后与 `tbl[n2].hi` 和 `tbl[n2].lo` 进行组合，得到最终的高低部分 `*hip` 和 `*lop`。
      * **指数调整:**  通过 `*kp = n >> LOG2_INTERVALS` 计算出一个指数调整量 `k`，用于后续调整结果的指数部分。

2. **`k_hexpl(long double x, long double *hip, long double *lop)`:**
   * **功能:**  调用 `__k_expl` 计算 `exp(x)`，并对结果进行指数部分的调整。
   * **实现:**
      * 调用 `__k_expl` 获取 `exp(x)` 的高低部分和指数调整量 `k`。
      * 使用 `SET_FLOAT_WORD` 宏构造一个浮点数 `twopkm1`，其值为 `2^(k-1)`。
      * 将 `__k_expl` 返回的高低部分 `*hip` 和 `*lop` 都乘以 `twopkm1`，相当于将结果的指数部分调整了 `k-1`。

3. **`hexpl(long double x)`:**
   * **功能:**  提供一个更方便的接口来计算 `exp(x)`。
   * **实现:**
      * 调用 `__k_expl` 获取 `exp(x)` 的高低部分和指数调整量 `k`。
      * 构造一个 `long double` 类型的数 `twopkm2`，其值为 `2^(k-2)`。
      * 将 `__k_expl` 返回的高低部分相加 `(lo + hi)`，然后乘以 2 和 `twopkm2`，最终返回 `exp(x)` 的结果。

4. **`__ldexp_cexpl(long double complex z, int expt)` (当定义了 `_COMPLEX_H`):**
   * **功能:**  计算复数 `z` 的指数函数 `exp(z) = exp(x + iy) = exp(x) * (cos(y) + i * sin(y))`。
   * **实现:**
      * 分离复数 `z` 的实部 `x` 和虚部 `y`。
      * 调用 `__k_expl` 计算实部 `x` 的指数函数 `exp(x)` 的高低部分，并获取指数调整量 `k`。
      * 计算 `exp(x)` 的近似值 `exp_x`，并根据 `k` 调整指数。
      * 使用 `sincosl(y, &s, &c)` 计算虚部 `y` 的正弦 `s` 和余弦 `c` 值。
      * 根据公式 `exp(z) = exp(x) * (cos(y) + i * sin(y))`，将 `exp_x`、`c` 和 `s` 组合起来，得到复数指数函数的结果。这里还考虑了 `expt` 参数，用于进一步的指数调整。

**对于 dynamic linker 的功能，请给 so 布局样本，以及每种符号如何的处理过程:**

`k_expl.handroid` 属于 `libm.so` 动态链接库的一部分。一个典型的 `.so` 文件布局如下：

```
.text         # 存放可执行的机器指令
.rodata       # 存放只读数据，例如字符串字面量、常量
.data         # 存放已初始化的全局变量和静态变量
.bss          # 存放未初始化的全局变量和静态变量
.symtab       # 符号表，包含所有符号的定义和引用信息
.strtab       # 字符串表，存储符号表中使用的字符串
.dynsym       # 动态符号表，包含动态链接需要的符号信息
.dynstr       # 动态字符串表，存储动态符号表中使用的字符串
.rel.dyn      # 重定位表，用于处理数据段的重定位
.rel.plt      # 重定位表，用于处理过程链接表 (PLT) 的重定位
.hash         # 用于加速符号查找的哈希表
.plt          # 过程链接表，用于延迟绑定
.got.plt      # 全局偏移量表，存储外部函数的地址
```

**符号处理过程:**

1. **静态链接期间:**
   - 编译器和链接器会将程序代码和静态链接库的代码合并成一个可执行文件。
   - 所有符号的地址在链接时就已经确定。

2. **动态链接期间:**
   - **编译时:** 编译器生成可重定位的目标文件，其中包含了对外部符号的引用信息。
   - **加载时:** 当程序启动时，Android 的动态链接器 (e.g., `linker64`) 负责加载程序依赖的动态链接库 (`.so` 文件）。
   - **符号查找:**
      - 当程序中遇到对动态库中符号的引用时，动态链接器会查找相应的符号定义。
      - 首先查找全局符号表 (`.dynsym`)。
      - 查找过程会利用哈希表 (`.hash`) 来加速。
   - **符号绑定 (解析):**
      - **延迟绑定 (Lazy Binding, 默认):**  对于函数符号，通常采用延迟绑定。第一次调用该函数时，会触发动态链接器进行符号解析和地址绑定。过程链接表 (`.plt`) 和全局偏移量表 (`.got.plt`) 协同工作实现延迟绑定。
         1. 第一次调用 `expl` 时，会跳转到 `libm.so` 的 `expl` 在 `.plt` 中的条目。
         2. `.plt` 条目会跳转到 `.got.plt` 中对应的位置。
         3. 初始时，`.got.plt` 中存放的是一个指向动态链接器的地址。
         4. 动态链接器解析 `expl` 符号，找到其在 `libm.so` 中的实际地址。
         5. 动态链接器将 `expl` 的实际地址写入 `.got.plt` 中。
         6. 后续对 `expl` 的调用将直接通过 `.plt` 跳转到 `.got.plt` 中存储的实际地址，不再需要动态链接器的介入。
      - **立即绑定 (Now Binding):**  可以通过环境变量或链接器选项设置为立即绑定，即在动态库加载时就解析所有符号。
   - **重定位:**  动态链接库被加载到内存中的地址可能不是其编译时的地址，因此需要进行重定位，调整代码和数据中引用的地址。`.rel.dyn` 和 `.rel.plt` 包含了重定位信息。
      - `.rel.dyn` 用于重定位数据段中需要动态链接的符号地址。
      - `.rel.plt` 用于重定位过程链接表中的条目。
   - **符号类型处理:**
      - **全局符号 (Global Symbols):**  在动态库中定义的全局符号可以被其他动态库或可执行文件引用。例如，`expl` 函数就是一个全局符号。
      - **本地符号 (Local Symbols):**  在动态库中定义的本地符号仅在库内部可见，不能被外部引用。`__k_expl` 通常是本地符号。
      - **未定义符号 (Undefined Symbols):**  在编译或链接过程中，如果引用了某个未定义的符号，链接器会报错。在动态链接中，未定义的符号通常是指需要在运行时才能找到定义的符号。

**so 布局样本:**

假设 `libm.so` 中包含 `expl` 和 `__k_expl` 两个符号：

```
libm.so:
  .text:
    expl:        # 指数函数的入口点
      ...
      call    plt[index_of___k_expl]  # 调用 __k_expl (可能通过 PLT)
      ...
    __k_expl:    # 核心计算函数
      ...
  .rodata:
    tbl:         # 指数函数查找表
      ...
  .dynsym:
    expl (GLOBAL, FUNCTION, ...): address  # 全局函数符号
  .symtab:
    expl (GLOBAL, FUNCTION, ...): address
    __k_expl (LOCAL, FUNCTION, ...): address # 本地函数符号
    ... (其他符号)
  .rel.plt:
    offset:  # 需要重定位的 PLT 条目的偏移量
      type:   # 重定位类型 (e.g., JUMP_SLOT)
      symbol: expl  # 需要重定位的符号
```

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们调用 `expl(1.0L)`：

1. **输入:** `x = 1.0L` (long double)
2. **`__k_expl` 的处理 (简化):**
   - **区间归约:**  `1.0 / ln(2)` 大约是 `1.44`，假设 `INTERVALS` 足够大，可能会选择 `n = 1`。
   - **查表:**  根据 `n % INTERVALS` 访问 `tbl` 数组，取出对应的值。
   - **多项式逼近:** 计算 `r = 1.0 - ln(2)`，然后使用多项式 `A2*r^2 + A3*r^3 + ...` 逼近 `exp(r) - 1`。
   - **结果组合:** 将查表值和多项式结果组合。
3. **`hexpl` 的处理:** 将 `__k_expl` 返回的高低部分相加并调整指数。
4. **输出:** 最终结果应接近自然常数 `e` 的值，即 `2.718281828459045...` (高精度 long double)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **类型错误:**
   ```c++
   #include <cmath>
   #include <iostream>

   int main() {
       double x = 2.0;
       long double result = expl(x); // 隐式将 double 转换为 long double，可能损失精度或导致意外行为
       std::cout << "expl(" << x << ") = " << result << std::endl;
       return 0;
   }
   ```
   应该确保传递给 `expl` 的参数类型是 `long double`，避免隐式类型转换。

2. **溢出或下溢:**
   ```c++
   #include <cmath>
   #include <limits>
   #include <iostream>

   int main() {
       long double x_large = std::numeric_limits<long double>::max_exponentL; // 非常大的正数
       long double result_overflow = expl(x_large); // 导致溢出，结果可能是无穷大或 NaN

       long double x_small = -std::numeric_limits<long double>::max_exponentL; // 非常小的负数
       long double result_underflow = expl(x_small); // 导致下溢，结果可能是 0

       std::cout << "expl(large) = " << result_overflow << std::endl;
       std::cout << "expl(small) = " << result_underflow << std::endl;
       return 0;
   }
   ```
   用户需要注意输入值的范围，避免导致指数函数结果超出 `long double` 的表示范围。

3. **忽略 `long double` 的特殊性:**  如果程序中混合使用了 `double` 和 `long double`，可能会因为精度差异导致计算结果不符合预期。

**说明 android framework or ndk 是如何一步步的到达这里，作为调试线索:**

1. **Android Framework (Java):**
   - 假设 Framework 层某个 Java 代码需要计算指数函数，但精度要求较高。
   - Framework 开发者可能会选择使用 JNI 调用 Native 代码来实现。
   - Java 代码调用 JNI 方法，该方法声明在 Native 代码中。

2. **NDK (Native 代码):**
   - Native 代码（C/C++）中包含了 JNI 方法的实现。
   - 该 Native 代码会 `#include <cmath>` 头文件，并调用 `expl(x)` 函数。
   - 编译 Native 代码时，链接器会将代码链接到 `libm.so` 动态库。

3. **`libm.so` 的 `expl` 函数:**
   - 当程序运行时，调用 `expl(x)` 时，会跳转到 `libm.so` 中 `expl` 函数的实现。
   - `libm.so` 中的 `expl` 函数可能会根据输入参数的范围和精度要求，选择不同的实现路径。
   - 对于 `long double` 类型的输入，很可能会调用到 `k_expl.handroid` 中定义的函数。

4. **`k_expl.handroid` 中的函数:**
   - `expl` 函数可能会直接或间接地调用 `__k_expl`，这是进行核心指数计算的函数。
   - `__k_expl` 函数会使用查表和多项式逼近等方法来计算高精度的指数值。

**调试线索:**

* **断点:** 在 Android Studio 中，可以为 Native 代码设置断点，例如在 `expl` 函数或 `__k_expl` 函数的入口处设置断点，以便观察执行流程和变量值。
* **日志:** 在 Native 代码中使用 `__android_log_print` 打印日志信息，可以帮助跟踪函数的调用路径和中间结果。
* **反汇编:** 使用 `objdump` 或类似的工具可以查看 `libm.so` 的汇编代码，了解 `expl` 函数是如何调用 `__k_expl` 的。
* **源码阅读:**  阅读 `bionic` 的源码，可以深入理解 `expl` 函数的实现细节，以及 `k_expl.handroid` 在整个 `libm` 库中的作用。
* **性能分析工具:**  使用 Android 提供的性能分析工具（如 Simpleperf）可以分析 `expl` 函数的性能瓶颈，有助于理解其内部实现的效率。

总而言之，`k_expl.handroid` 是 Android `libm` 库中实现高精度 `long double` 指数函数的核心组件，它通过查表和多项式逼近等技术来提供高效且精确的计算。理解其功能和实现方式，有助于深入理解 Android 底层数学库的工作原理。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/k_expl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/* from: FreeBSD: head/lib/msun/ld128/s_expl.c 251345 2013-06-03 20:09:22Z kargl */

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2009-2013 Steven G. Kargl
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Optimized by Bruce D. Evans.
 */

/*
 * ld128 version of k_expl.h.  See ../ld80/s_expl.c for most comments.
 *
 * See ../src/e_exp.c and ../src/k_exp.h for precision-independent comments
 * about the secondary kernels.
 */

#define	INTERVALS	128
#define	LOG2_INTERVALS	7
#define	BIAS	(LDBL_MAX_EXP - 1)

static const double
/*
 * ln2/INTERVALS = L1+L2 (hi+lo decomposition for multiplication).  L1 must
 * have at least 22 (= log2(|LDBL_MIN_EXP-extras|) + log2(INTERVALS)) lowest
 * bits zero so that multiplication of it by n is exact.
 */
INV_L = 1.8466496523378731e+2,		/*  0x171547652b82fe.0p-45 */
L2 = -1.0253670638894731e-29;		/* -0x1.9ff0342542fc3p-97 */
static const long double
/* 0x1.62e42fefa39ef35793c768000000p-8 */
L1 =  5.41521234812457272982212595914567508e-3L;

/*
 * XXX values in hex in comments have been lost (or were never present)
 * from here.
 */
static const long double
/*
 * Domain [-0.002708, 0.002708], range ~[-2.4021e-38, 2.4234e-38]:
 * |exp(x) - p(x)| < 2**-124.9
 * (0.002708 is ln2/(2*INTERVALS) rounded up a little).
 *
 * XXX the coeffs aren't very carefully rounded, and I get 3.6 more bits.
 */
A2  =  0.5,
A3  =  1.66666666666666666666666666651085500e-1L,
A4  =  4.16666666666666666666666666425885320e-2L,
A5  =  8.33333333333333333334522877160175842e-3L,
A6  =  1.38888888888888888889971139751596836e-3L;

static const double
A7  =  1.9841269841269470e-4,		/*  0x1.a01a01a019f91p-13 */
A8  =  2.4801587301585286e-5,		/*  0x1.71de3ec75a967p-19 */
A9  =  2.7557324277411235e-6,		/*  0x1.71de3ec75a967p-19 */
A10 =  2.7557333722375069e-7;		/*  0x1.27e505ab56259p-22 */

static const struct {
	/*
	 * hi must be rounded to at most 106 bits so that multiplication
	 * by r1 in expm1l() is exact, but it is rounded to 88 bits due to
	 * historical accidents.
	 *
	 * XXX it is wasteful to use long double for both hi and lo.  ld128
	 * exp2l() uses only float for lo (in a very differently organized
	 * table; ld80 exp2l() is different again.  It uses 2 doubles in a
	 * table organized like this one.  1 double and 1 float would
	 * suffice).  There are different packing/locality/alignment/caching
	 * problems with these methods.
	 *
	 * XXX C's bad %a format makes the bits unreadable.  They happen
	 * to all line up for the hi values 1 before the point and 88
	 * in 22 nybbles, but for the low values the nybbles are shifted
	 * randomly.
	 */
	long double	hi;
	long double	lo;
} tbl[INTERVALS] = {
	0x1p0L, 0x0p0L,
	0x1.0163da9fb33356d84a66aep0L, 0x3.36dcdfa4003ec04c360be2404078p-92L,
	0x1.02c9a3e778060ee6f7cacap0L, 0x4.f7a29bde93d70a2cabc5cb89ba10p-92L,
	0x1.04315e86e7f84bd738f9a2p0L, 0xd.a47e6ed040bb4bfc05af6455e9b8p-96L,
	0x1.059b0d31585743ae7c548ep0L, 0xb.68ca417fe53e3495f7df4baf84a0p-92L,
	0x1.0706b29ddf6ddc6dc403a8p0L, 0x1.d87b27ed07cb8b092ac75e311753p-88L,
	0x1.0874518759bc808c35f25cp0L, 0x1.9427fa2b041b2d6829d8993a0d01p-88L,
	0x1.09e3ecac6f3834521e060cp0L, 0x5.84d6b74ba2e023da730e7fccb758p-92L,
	0x1.0b5586cf9890f6298b92b6p0L, 0x1.1842a98364291408b3ceb0a2a2bbp-88L,
	0x1.0cc922b7247f7407b705b8p0L, 0x9.3dc5e8aac564e6fe2ef1d431fd98p-92L,
	0x1.0e3ec32d3d1a2020742e4ep0L, 0x1.8af6a552ac4b358b1129e9f966a4p-88L,
	0x1.0fb66affed31af232091dcp0L, 0x1.8a1426514e0b627bda694a400a27p-88L,
	0x1.11301d0125b50a4ebbf1aep0L, 0xd.9318ceac5cc47ab166ee57427178p-92L,
	0x1.12abdc06c31cbfb92bad32p0L, 0x4.d68e2f7270bdf7cedf94eb1cb818p-92L,
	0x1.1429aaea92ddfb34101942p0L, 0x1.b2586d01844b389bea7aedd221d4p-88L,
	0x1.15a98c8a58e512480d573cp0L, 0x1.d5613bf92a2b618ee31b376c2689p-88L,
	0x1.172b83c7d517adcdf7c8c4p0L, 0x1.0eb14a792035509ff7d758693f24p-88L,
	0x1.18af9388c8de9bbbf70b9ap0L, 0x3.c2505c97c0102e5f1211941d2840p-92L,
	0x1.1a35beb6fcb753cb698f68p0L, 0x1.2d1c835a6c30724d5cfae31b84e5p-88L,
	0x1.1bbe084045cd39ab1e72b4p0L, 0x4.27e35f9acb57e473915519a1b448p-92L,
	0x1.1d4873168b9aa7805b8028p0L, 0x9.90f07a98b42206e46166cf051d70p-92L,
	0x1.1ed5022fcd91cb8819ff60p0L, 0x1.121d1e504d36c47474c9b7de6067p-88L,
	0x1.2063b88628cd63b8eeb028p0L, 0x1.50929d0fc487d21c2b84004264dep-88L,
	0x1.21f49917ddc962552fd292p0L, 0x9.4bdb4b61ea62477caa1dce823ba0p-92L,
	0x1.2387a6e75623866c1fadb0p0L, 0x1.c15cb593b0328566902df69e4de2p-88L,
	0x1.251ce4fb2a63f3582ab7dep0L, 0x9.e94811a9c8afdcf796934bc652d0p-92L,
	0x1.26b4565e27cdd257a67328p0L, 0x1.d3b249dce4e9186ddd5ff44e6b08p-92L,
	0x1.284dfe1f5638096cf15cf0p0L, 0x3.ca0967fdaa2e52d7c8106f2e262cp-92L,
	0x1.29e9df51fdee12c25d15f4p0L, 0x1.a24aa3bca890ac08d203fed80a07p-88L,
	0x1.2b87fd0dad98ffddea4652p0L, 0x1.8fcab88442fdc3cb6de4519165edp-88L,
	0x1.2d285a6e4030b40091d536p0L, 0xd.075384589c1cd1b3e4018a6b1348p-92L,
	0x1.2ecafa93e2f5611ca0f45cp0L, 0x1.523833af611bdcda253c554cf278p-88L,
	0x1.306fe0a31b7152de8d5a46p0L, 0x3.05c85edecbc27343629f502f1af2p-92L,
	0x1.32170fc4cd8313539cf1c2p0L, 0x1.008f86dde3220ae17a005b6412bep-88L,
	0x1.33c08b26416ff4c9c8610cp0L, 0x1.96696bf95d1593039539d94d662bp-88L,
	0x1.356c55f929ff0c94623476p0L, 0x3.73af38d6d8d6f9506c9bbc93cbc0p-92L,
	0x1.371a7373aa9caa7145502ep0L, 0x1.4547987e3e12516bf9c699be432fp-88L,
	0x1.38cae6d05d86585a9cb0d8p0L, 0x1.bed0c853bd30a02790931eb2e8f0p-88L,
	0x1.3a7db34e59ff6ea1bc9298p0L, 0x1.e0a1d336163fe2f852ceeb134067p-88L,
	0x1.3c32dc313a8e484001f228p0L, 0xb.58f3775e06ab66353001fae9fca0p-92L,
	0x1.3dea64c12342235b41223ep0L, 0x1.3d773fba2cb82b8244267c54443fp-92L,
	0x1.3fa4504ac801ba0bf701aap0L, 0x4.1832fb8c1c8dbdff2c49909e6c60p-92L,
	0x1.4160a21f72e29f84325b8ep0L, 0x1.3db61fb352f0540e6ba05634413ep-88L,
	0x1.431f5d950a896dc7044394p0L, 0x1.0ccec81e24b0caff7581ef4127f7p-92L,
	0x1.44e086061892d03136f408p0L, 0x1.df019fbd4f3b48709b78591d5cb5p-88L,
	0x1.46a41ed1d005772512f458p0L, 0x1.229d97df404ff21f39c1b594d3a8p-88L,
	0x1.486a2b5c13cd013c1a3b68p0L, 0x1.062f03c3dd75ce8757f780e6ec99p-88L,
	0x1.4a32af0d7d3de672d8bcf4p0L, 0x6.f9586461db1d878b1d148bd3ccb8p-92L,
	0x1.4bfdad5362a271d4397afep0L, 0xc.42e20e0363ba2e159c579f82e4b0p-92L,
	0x1.4dcb299fddd0d63b36ef1ap0L, 0x9.e0cc484b25a5566d0bd5f58ad238p-92L,
	0x1.4f9b2769d2ca6ad33d8b68p0L, 0x1.aa073ee55e028497a329a7333dbap-88L,
	0x1.516daa2cf6641c112f52c8p0L, 0x4.d822190e718226177d7608d20038p-92L,
	0x1.5342b569d4f81df0a83c48p0L, 0x1.d86a63f4e672a3e429805b049465p-88L,
	0x1.551a4ca5d920ec52ec6202p0L, 0x4.34ca672645dc6c124d6619a87574p-92L,
	0x1.56f4736b527da66ecb0046p0L, 0x1.64eb3c00f2f5ab3d801d7cc7272dp-88L,
	0x1.58d12d497c7fd252bc2b72p0L, 0x1.43bcf2ec936a970d9cc266f0072fp-88L,
	0x1.5ab07dd48542958c930150p0L, 0x1.91eb345d88d7c81280e069fbdb63p-88L,
	0x1.5c9268a5946b701c4b1b80p0L, 0x1.6986a203d84e6a4a92f179e71889p-88L,
	0x1.5e76f15ad21486e9be4c20p0L, 0x3.99766a06548a05829e853bdb2b52p-92L,
	0x1.605e1b976dc08b076f592ap0L, 0x4.86e3b34ead1b4769df867b9c89ccp-92L,
	0x1.6247eb03a5584b1f0fa06ep0L, 0x1.d2da42bb1ceaf9f732275b8aef30p-88L,
	0x1.6434634ccc31fc76f8714cp0L, 0x4.ed9a4e41000307103a18cf7a6e08p-92L,
	0x1.66238825522249127d9e28p0L, 0x1.b8f314a337f4dc0a3adf1787ff74p-88L,
	0x1.68155d44ca973081c57226p0L, 0x1.b9f32706bfe4e627d809a85dcc66p-88L,
	0x1.6a09e667f3bcc908b2fb12p0L, 0x1.66ea957d3e3adec17512775099dap-88L,
	0x1.6c012750bdabeed76a9980p0L, 0xf.4f33fdeb8b0ecd831106f57b3d00p-96L,
	0x1.6dfb23c651a2ef220e2cbep0L, 0x1.bbaa834b3f11577ceefbe6c1c411p-92L,
	0x1.6ff7df9519483cf87e1b4ep0L, 0x1.3e213bff9b702d5aa477c12523cep-88L,
	0x1.71f75e8ec5f73dd2370f2ep0L, 0xf.0acd6cb434b562d9e8a20adda648p-92L,
	0x1.73f9a48a58173bd5c9a4e6p0L, 0x8.ab1182ae217f3a7681759553e840p-92L,
	0x1.75feb564267c8bf6e9aa32p0L, 0x1.a48b27071805e61a17b954a2dad8p-88L,
	0x1.780694fde5d3f619ae0280p0L, 0x8.58b2bb2bdcf86cd08e35fb04c0f0p-92L,
	0x1.7a11473eb0186d7d51023ep0L, 0x1.6cda1f5ef42b66977960531e821bp-88L,
	0x1.7c1ed0130c1327c4933444p0L, 0x1.937562b2dc933d44fc828efd4c9cp-88L,
	0x1.7e2f336cf4e62105d02ba0p0L, 0x1.5797e170a1427f8fcdf5f3906108p-88L,
	0x1.80427543e1a11b60de6764p0L, 0x9.a354ea706b8e4d8b718a672bf7c8p-92L,
	0x1.82589994cce128acf88afap0L, 0xb.34a010f6ad65cbbac0f532d39be0p-92L,
	0x1.8471a4623c7acce52f6b96p0L, 0x1.c64095370f51f48817914dd78665p-88L,
	0x1.868d99b4492ec80e41d90ap0L, 0xc.251707484d73f136fb5779656b70p-92L,
	0x1.88ac7d98a669966530bcdep0L, 0x1.2d4e9d61283ef385de170ab20f96p-88L,
	0x1.8ace5422aa0db5ba7c55a0p0L, 0x1.92c9bb3e6ed61f2733304a346d8fp-88L,
	0x1.8cf3216b5448bef2aa1cd0p0L, 0x1.61c55d84a9848f8c453b3ca8c946p-88L,
	0x1.8f1ae991577362b982745cp0L, 0x7.2ed804efc9b4ae1458ae946099d4p-92L,
	0x1.9145b0b91ffc588a61b468p0L, 0x1.f6b70e01c2a90229a4c4309ea719p-88L,
	0x1.93737b0cdc5e4f4501c3f2p0L, 0x5.40a22d2fc4af581b63e8326efe9cp-92L,
	0x1.95a44cbc8520ee9b483694p0L, 0x1.a0fc6f7c7d61b2b3a22a0eab2cadp-88L,
	0x1.97d829fde4e4f8b9e920f8p0L, 0x1.1e8bd7edb9d7144b6f6818084cc7p-88L,
	0x1.9a0f170ca07b9ba3109b8cp0L, 0x4.6737beb19e1eada6825d3c557428p-92L,
	0x1.9c49182a3f0901c7c46b06p0L, 0x1.1f2be58ddade50c217186c90b457p-88L,
	0x1.9e86319e323231824ca78ep0L, 0x6.4c6e010f92c082bbadfaf605cfd4p-92L,
	0x1.a0c667b5de564b29ada8b8p0L, 0xc.ab349aa0422a8da7d4512edac548p-92L,
	0x1.a309bec4a2d3358c171f76p0L, 0x1.0daad547fa22c26d168ea762d854p-88L,
	0x1.a5503b23e255c8b424491cp0L, 0xa.f87bc8050a405381703ef7caff50p-92L,
	0x1.a799e1330b3586f2dfb2b0p0L, 0x1.58f1a98796ce8908ae852236ca94p-88L,
	0x1.a9e6b5579fdbf43eb243bcp0L, 0x1.ff4c4c58b571cf465caf07b4b9f5p-88L,
	0x1.ac36bbfd3f379c0db966a2p0L, 0x1.1265fc73e480712d20f8597a8e7bp-88L,
	0x1.ae89f995ad3ad5e8734d16p0L, 0x1.73205a7fbc3ae675ea440b162d6cp-88L,
	0x1.b0e07298db66590842acdep0L, 0x1.c6f6ca0e5dcae2aafffa7a0554cbp-88L,
	0x1.b33a2b84f15faf6bfd0e7ap0L, 0x1.d947c2575781dbb49b1237c87b6ep-88L,
	0x1.b59728de559398e3881110p0L, 0x1.64873c7171fefc410416be0a6525p-88L,
	0x1.b7f76f2fb5e46eaa7b081ap0L, 0xb.53c5354c8903c356e4b625aacc28p-92L,
	0x1.ba5b030a10649840cb3c6ap0L, 0xf.5b47f297203757e1cc6eadc8bad0p-92L,
	0x1.bcc1e904bc1d2247ba0f44p0L, 0x1.b3d08cd0b20287092bd59be4ad98p-88L,
	0x1.bf2c25bd71e088408d7024p0L, 0x1.18e3449fa073b356766dfb568ff4p-88L,
	0x1.c199bdd85529c2220cb12ap0L, 0x9.1ba6679444964a36661240043970p-96L,
	0x1.c40ab5fffd07a6d14df820p0L, 0xf.1828a5366fd387a7bdd54cdf7300p-92L,
	0x1.c67f12e57d14b4a2137fd2p0L, 0xf.2b301dd9e6b151a6d1f9d5d5f520p-96L,
	0x1.c8f6d9406e7b511acbc488p0L, 0x5.c442ddb55820171f319d9e5076a8p-96L,
	0x1.cb720dcef90691503cbd1ep0L, 0x9.49db761d9559ac0cb6dd3ed599e0p-92L,
	0x1.cdf0b555dc3f9c44f8958ep0L, 0x1.ac51be515f8c58bdfb6f5740a3a4p-88L,
	0x1.d072d4a07897b8d0f22f20p0L, 0x1.a158e18fbbfc625f09f4cca40874p-88L,
	0x1.d2f87080d89f18ade12398p0L, 0x9.ea2025b4c56553f5cdee4c924728p-92L,
	0x1.d5818dcfba48725da05aeap0L, 0x1.66e0dca9f589f559c0876ff23830p-88L,
	0x1.d80e316c98397bb84f9d04p0L, 0x8.805f84bec614de269900ddf98d28p-92L,
	0x1.da9e603db3285708c01a5ap0L, 0x1.6d4c97f6246f0ec614ec95c99392p-88L,
	0x1.dd321f301b4604b695de3cp0L, 0x6.30a393215299e30d4fb73503c348p-96L,
	0x1.dfc97337b9b5eb968cac38p0L, 0x1.ed291b7225a944efd5bb5524b927p-88L,
	0x1.e264614f5a128a12761fa0p0L, 0x1.7ada6467e77f73bf65e04c95e29dp-88L,
	0x1.e502ee78b3ff6273d13014p0L, 0x1.3991e8f49659e1693be17ae1d2f9p-88L,
	0x1.e7a51fbc74c834b548b282p0L, 0x1.23786758a84f4956354634a416cep-88L,
	0x1.ea4afa2a490d9858f73a18p0L, 0xf.5db301f86dea20610ceee13eb7b8p-92L,
	0x1.ecf482d8e67f08db0312fap0L, 0x1.949cef462010bb4bc4ce72a900dfp-88L,
	0x1.efa1bee615a27771fd21a8p0L, 0x1.2dac1f6dd5d229ff68e46f27e3dfp-88L,
	0x1.f252b376bba974e8696fc2p0L, 0x1.6390d4c6ad5476b5162f40e1d9a9p-88L,
	0x1.f50765b6e4540674f84b76p0L, 0x2.862baff99000dfc4352ba29b8908p-92L,
	0x1.f7bfdad9cbe138913b4bfep0L, 0x7.2bd95c5ce7280fa4d2344a3f5618p-92L,
	0x1.fa7c1819e90d82e90a7e74p0L, 0xb.263c1dc060c36f7650b4c0f233a8p-92L,
	0x1.fd3c22b8f71f10975ba4b2p0L, 0x1.2bcf3a5e12d269d8ad7c1a4a8875p-88L
};

/*
 * Kernel for expl(x).  x must be finite and not tiny or huge.
 * "tiny" is anything that would make us underflow (|A6*x^6| < ~LDBL_MIN).
 * "huge" is anything that would make fn*L1 inexact (|x| > ~2**17*ln2).
 */
static inline void
__k_expl(long double x, long double *hip, long double *lop, int *kp)
{
	long double q, r, r1, t;
	double dr, fn, r2;
	int n, n2;

	/* Reduce x to (k*ln2 + endpoint[n2] + r1 + r2). */
	fn = rnint((double)x * INV_L);
	n = irint(fn);
	n2 = (unsigned)n % INTERVALS;
	/* Depend on the sign bit being propagated: */
	*kp = n >> LOG2_INTERVALS;
	r1 = x - fn * L1;
	r2 = fn * -L2;
	r = r1 + r2;

	/* Evaluate expl(endpoint[n2] + r1 + r2) = tbl[n2] * expl(r1 + r2). */
	dr = r;
	q = r2 + r * r * (A2 + r * (A3 + r * (A4 + r * (A5 + r * (A6 +
	    dr * (A7 + dr * (A8 + dr * (A9 + dr * A10))))))));
	t = tbl[n2].lo + tbl[n2].hi;
	*hip = tbl[n2].hi;
	*lop = tbl[n2].lo + t * (q + r1);
}

/*
 * XXX: the rest of the functions are identical for ld80 and ld128.
 * However, we should use scalbnl() for ld128, since long double
 * multiplication was very slow on sparc64 and no new evaluation has
 * been made for aarch64 and/or riscv.
 */

static inline void
k_hexpl(long double x, long double *hip, long double *lop)
{
	float twopkm1;
	int k;

	__k_expl(x, hip, lop, &k);
	SET_FLOAT_WORD(twopkm1, 0x3f800000 + ((k - 1) << 23));
	*hip *= twopkm1;
	*lop *= twopkm1;
}

static inline long double
hexpl(long double x)
{
	long double hi, lo, twopkm2;
	int k;

	twopkm2 = 1;
	__k_expl(x, &hi, &lo, &k);
	SET_LDBL_EXPSIGN(twopkm2, BIAS + k - 2);
	return (lo + hi) * 2 * twopkm2;
}

#ifdef _COMPLEX_H
/*
 * See ../src/k_exp.c for details.
 */
static inline long double complex
__ldexp_cexpl(long double complex z, int expt)
{
	long double c, exp_x, hi, lo, s;
	long double x, y, scale1, scale2;
	int half_expt, k;

	x = creall(z);
	y = cimagl(z);
	__k_expl(x, &hi, &lo, &k);

	exp_x = (lo + hi) * 0x1p16382L;
	expt += k - 16382;

	scale1 = 1;
	half_expt = expt / 2;
	SET_LDBL_EXPSIGN(scale1, BIAS + half_expt);
	scale2 = 1;
	SET_LDBL_EXPSIGN(scale2, BIAS + expt - half_expt);

	sincosl(y, &s, &c);
	return (CMPLXL(c * exp_x * scale1 * scale2,
	    s * exp_x * scale1 * scale2));
}
#endif /* _COMPLEX_H */
```
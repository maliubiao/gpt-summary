Response:
Let's break down the thought process for analyzing the provided C code snippet. The goal is to understand its function, its relevance to Android, how it works internally, and potential usage scenarios and pitfalls.

**1. Initial Understanding & Context:**

* **File Path:** The path `bionic/libm/upstream-freebsd/lib/msun/src/k_sincosl.handroid` immediately tells us several things:
    * `bionic`: This is the Android C library.
    * `libm`: This indicates the math library.
    * `upstream-freebsd`: Android's `libm` is based on FreeBSD's `libm`.
    * `lib/msun/src`:  Standard location for math function source code.
    * `k_sincosl.handroid`:  The `k_` prefix often suggests a kernel or core implementation, and `sincosl` likely means a function calculating both sine and cosine for `long double` types. The `.handroid` extension might indicate Android-specific modifications or optimizations.
* **Copyright Notice:** Confirms the FreeBSD origin and the contributions of specific individuals.
* **`#if LDBL_MANT_DIG == ...`:** This clearly signals that the code is designed to handle different representations of `long double`, likely due to variations in hardware and compiler implementations. The two common cases, 64-bit and 113-bit mantissas, are explicitly handled.

**2. Deeper Code Analysis - Functionality:**

* **`__kernel_sincosl` function:**  The core of the code. The name suggests an internal kernel function.
* **Inputs:** `long double x`, `long double y`, `int iy`, `long double *sn`, `long double *cs`.
    * `x`: The angle for which sine and cosine are calculated.
    * `y`: Seems related to handling cases where `iy` is non-zero. Needs closer inspection.
    * `iy`:  Acts as a flag (0 or non-zero) to select slightly different calculation paths for sine.
    * `*sn`, `*cs`: Pointers to store the calculated sine and cosine values, respectively.
* **Constants:** Several `static const` variables (`C1`, `C2`, `S1`, `S2`, etc.). These are clearly coefficients for Taylor series expansions or similar approximations of sine and cosine. The suffixes `hi` and `lo` for the 64-bit case suggest double-double arithmetic for increased precision.
* **Calculations:** The code uses polynomial approximations (likely Taylor series) to calculate sine and cosine.
    * `z = x * x`:  The squared angle is a recurring term in Taylor series.
    * `v = z * x`: The cubed angle.
    * The loops calculating `r` involve accumulating terms of the Taylor series.
    * The `if (iy == 0)` and `else` blocks handle the sine calculation differently based on `iy`.
    * The cosine calculation is more straightforward.
* **Double-Double Arithmetic (64-bit case):**  The `C1hi`, `C1lo`, `S1hi`, `S1lo` constants and the `#define C1 ((long double)C1hi + C1lo)` and `#define S1 ((long double)S1hi + S1lo)` lines explicitly show the use of double-double arithmetic to represent long double values with higher precision when the native long double is only 80 bits.

**3. Connecting to Android:**

* **`libm` is fundamental:**  The math library is crucial for many Android components, from graphics rendering and game development to scientific applications and even core system functions.
* **NDK Usage:** Developers using the Native Development Kit (NDK) can directly call functions from `libm`.
* **Framework Usage:** The Android Framework (written in Java/Kotlin) relies on native code for performance-critical operations. Math functions are often used indirectly by framework components.

**4. Explaining `libc` Functions (Specifically `__kernel_sincosl`):**

* **No Standard `libc` Function:**  `__kernel_sincosl` is *not* a standard POSIX `libc` function. The double underscore `__` prefix strongly suggests it's an internal implementation detail of `libm`. Users would typically call `sincosl`.
* **Implementation Strategy:** The implementation uses Taylor series approximations. This is a common technique for calculating trigonometric functions. The constants are pre-calculated coefficients of these series. The number of terms determines the accuracy. The code is optimized by pre-computing `z` and `v`.

**5. Dynamic Linker Aspects:**

* **Focus on Symbols:** The dynamic linker's job is to resolve symbols (function and variable names) at runtime.
* **SO Layout (Simplified):**
    ```
    [ELF Header]
    [Program Headers (LOAD segments)]
        .text (code)
        .rodata (read-only data, including constants)
        .data (initialized data)
        .bss (uninitialized data)
    [Section Headers]
        .symtab (symbol table)
        .strtab (string table)
        .dynsym (dynamic symbol table)
        .dynstr (dynamic string table)
        .rel.dyn (relocations for .data)
        .rel.plt (relocations for PLT)
    ```
* **Symbol Processing:**
    * **Exported Symbols (e.g., `sincosl`):**
        1. When a program (or another SO) calls `sincosl`, the linker checks its dynamic dependencies.
        2. It loads the necessary SOs (like `libm.so`).
        3. It looks up the symbol `sincosl` in `libm.so`'s `.dynsym`.
        4. It resolves the address of `sincosl` and updates the calling code (via the PLT - Procedure Linkage Table).
    * **Internal Symbols (e.g., `__kernel_sincosl`, constants):**
        1. These symbols are typically in the `.symtab` but might not be in `.dynsym`.
        2. They are used internally within `libm.so` and don't need external resolution.
        3. The compiler and linker handle their addresses within the SO's memory space.

**6. Logical Reasoning (Assumptions & Outputs):**

* **Assumption:** The input angle `x` is within a reasonable range (not excessively large) where the Taylor series converges quickly enough for the number of terms used.
* **Input:** `x = 0.5`, `y = 0.0`, `iy = 0`
* **Expected Output (approximate):**
    * `*sn` (sin(0.5)) ≈ 0.4794255386
    * `*cs` (cos(0.5)) ≈ 0.8775825618
* **The internal calculations would proceed by substituting `x` into the polynomial formulas.**

**7. Common Usage Errors:**

* **Incorrect Data Type:** Passing a `float` or `double` to a function expecting `long double` (or vice-versa) can lead to precision loss or incorrect results.
* **Large Input Values:** For very large input angles, the Taylor series might converge slowly, leading to inaccuracies or performance issues. `libm` functions often have argument reduction techniques to handle this, but incorrect usage might bypass these.
* **Assuming Exact Results:** Floating-point calculations inherently have some level of imprecision. Comparing floating-point numbers for exact equality is often a mistake.

**8. Android Framework/NDK Call Path:**

* **NDK:**
    1. C/C++ code in an NDK module calls a `sincosl` function (either directly or indirectly through another math function).
    2. The linker resolves `sincosl` to the implementation in `libm.so`.
    3. `sincosl` (likely another function in the same source file or a related one) will eventually call `__kernel_sincosl` to perform the core calculation.
* **Framework:**
    1. An Android Framework component (e.g., graphics rendering in `SurfaceFlinger`) needs to calculate sines and cosines.
    2. Java/Kotlin code might call a method that internally uses native code (JNI).
    3. The native code uses `libm` functions, potentially reaching `__kernel_sincosl`.
* **Debugging:**  To trace the call path:
    1. **Logging:** Add `ALOG` statements in the native code.
    2. **Debugger (gdb/lldb):** Attach a debugger to the Android process and set breakpoints in `libm.so`, starting with `sincosl` and stepping into the code.
    3. **System Tracing (systrace):** Can provide a high-level view of system calls and function calls.

This detailed thought process involves examining the code, understanding its context within Android, and thinking about how it interacts with other parts of the system, including the dynamic linker and user-level code. It also involves anticipating potential issues and outlining debugging strategies.
这个文件 `k_sincosl.handroid` 是 Android Bionic 库中 `libm`（数学库）的一部分，它提供了用于计算 `long double` 类型（扩展精度浮点数）的 **正弦 (sine)** 和 **余弦 (cosine)** 值的核心实现。

**功能列举:**

1. **高效计算 `long double` 类型的正弦和余弦值:**  这是该文件的主要功能。它针对不同的 `long double` 精度（由 `LDBL_MANT_DIG` 定义，通常为 64 位或 113 位）提供了不同的实现。
2. **基于泰勒级数展开:**  代码中使用了泰勒级数的展开式来逼近正弦和余弦函数。可以看到大量的常数 `C1`, `C2`, `S1`, `S2` 等，这些是泰勒级数展开式的系数。
3. **针对特定架构的优化:**  代码中 `#if defined(__amd64__) || defined(__i386__)`  部分表明，对于 x86 架构，使用了不同的常量定义方法，可能是为了优化性能或解决特定架构上的 `long double` 问题。
4. **内部使用函数:**  `__kernel_sincosl` 函数名中的双下划线 `__` 表明这是一个内部使用的函数，通常不直接暴露给用户。它被更高层的 `sincosl` 函数调用。

**与 Android 功能的关系及举例:**

`libm` 是 Android 系统底层的重要组成部分，许多 Android 的功能都依赖于它提供的数学运算。`k_sincosl.handroid` 提供的 `long double` 精度的正弦和余弦计算，虽然不如 `double` 类型常用，但在以下场景中可能被用到：

* **高精度科学计算应用:**  一些需要极高精度的科学计算应用（例如，天文、物理模拟等）可能会使用 `long double` 类型，并间接调用到这里的实现。
* **图形渲染引擎:**  在一些对精度要求较高的图形渲染算法中，尤其是在涉及到几何变换、光线追踪等计算时，`long double` 可能会提供更好的精度，从而减少误差。虽然 Android 框架层面通常使用 `float` 或 `double`，但底层的 native 代码如果需要更高的精度，可能会用到。
* **NDK 开发:**  使用 Android NDK 进行原生开发的开发者可以直接使用 `libm` 提供的函数，包括 `sincosl`，从而间接使用到这里的实现。

**示例:** 假设一个 NDK 开发的应用需要计算非常小的角度的正弦值，并且对精度要求极高。开发者可能会使用 `long double` 类型和 `sincosl` 函数，如下所示：

```c++
#include <cmath>
#include <iostream>

int main() {
  long double angle = 1.0e-10L; // 一个非常小的角度
  long double sin_val, cos_val;
  sincosl(angle, &sin_val, &cos_val);
  std::cout << "sin(" << angle << ") = " << sin_val << std::endl;
  std::cout << "cos(" << angle << ") = " << cos_val << std::endl;
  return 0;
}
```

在这个例子中，`sincosl` 的实现最终会调用到 `k_sincosl.handroid` 中的 `__kernel_sincosl` 函数来完成计算。

**详细解释 `libc` 函数的功能是如何实现的:**

这里的 `libc` 函数主要是指 `__kernel_sincosl`。它实现了计算 `long double` 类型正弦和余弦的核心逻辑。

1. **输入参数:** 接收角度 `x`，一个辅助变量 `y`（用于某些特殊情况），一个整数标志 `iy`，以及指向存储正弦和余弦结果的 `long double` 指针 `sn` 和 `cs`。

2. **角度平方计算:**  首先计算 `z = x * x`，这是泰勒级数展开中常用的项。

3. **正弦计算:**
   - 根据 `iy` 的值选择不同的计算路径。
   - **如果 `iy == 0`:** 使用泰勒级数展开式的前几项来逼近正弦值。可以看到使用了预定义的常数 `S1`, `S2`, `S3` 等作为系数。  `r = S2 + z * (S3 + ...)` 计算了高阶项的和。最终的 `*sn = x + v * (S1 + z * r)` 将一次项和高阶项组合起来。
   - **如果 `iy != 0`:** 使用了略微不同的公式，可能用于处理某些特殊情况或者优化精度。  公式 `*sn = x - ((z * (y / 2 - v * r) - y) - v * S1)`  看起来像是对标准泰勒级数的某种变形或重排。

4. **余弦计算:**
   - 首先计算 `hz = z / 2`。
   - 使用泰勒级数展开式的前几项来逼近余弦值。可以看到使用了预定义的常数 `C1`, `C2`, `C3` 等作为系数。 `r = z * (C1 + z * (C2 + ...))` 计算了高阶项的和。
   - 最终的 `*cs = w + (((1 - w) - hz) + (z * r - x * y))` 将常数项（1）和高阶项组合起来。这里 `w = 1 - hz` 是余弦泰勒展开的头两项。

5. **精度处理:**  对于 `LDBL_MANT_DIG == 64` 的情况（通常是 x86 架构），代码中使用了 `double` 类型的 `C1hi`, `C1lo`, `S1hi`, `S1lo`，并通过 `#define` 将它们组合成 `long double`，这是一种常见的 **双精度算法 (double-double arithmetic)** 技术，用于在硬件不支持原生高精度浮点数时，通过两个 `double` 组合来模拟更高的精度。

**dynamic linker 的功能，so 布局样本，以及每种符号如何的处理过程:**

Dynamic Linker (在 Android 上主要是 `linker64` 或 `linker`) 的主要功能是在程序运行时加载共享库 (`.so` 文件) 并解析符号引用。

**SO 布局样本 (简化):**

```
.so 文件 (例如 libm.so)
├── ELF Header
├── Program Headers
│   ├── LOAD (可加载段，包含代码和数据)
│   │   ├── .text (代码段，包含 __kernel_sincosl 等函数的机器码)
│   │   ├── .rodata (只读数据段，包含 C1, S1 等常量)
│   │   ├── .data (可读写数据段)
│   │   └── .bss (未初始化数据段)
│   └── ... (其他段)
├── Section Headers
│   ├── .symtab (符号表，包含所有符号的定义和引用信息)
│   ├── .strtab (字符串表，存储符号名称)
│   ├── .dynsym (动态符号表，包含导出的动态符号)
│   ├── .dynstr (动态字符串表，存储动态符号名称)
│   ├── .rel.dyn (数据段重定位信息)
│   └── .rel.plt (PLT (Procedure Linkage Table) 重定位信息)
└── ... (其他信息)
```

**符号处理过程:**

1. **未定义的符号 (Undefined Symbols):** 当一个 `.so` 文件引用了在自身内部未定义的符号时，dynamic linker 需要在其他已加载的共享库中找到这些符号的定义。例如，如果 `k_sincosl.handroid` 所在的编译单元调用了其他 `libm` 内部的函数，那些函数就可能作为未定义的符号存在。

2. **导出的符号 (Exported Symbols):** `libm.so` 会导出一些公共的数学函数，例如 `sincosl`。这些符号会被添加到 `.dynsym` 中，使得其他共享库或可执行文件可以找到并调用它们。

3. **局部符号 (Local Symbols):**  像 `__kernel_sincosl` 和 `C1`, `S1` 这样的静态函数和变量，默认情况下是局部符号，它们的作用域限制在 `libm.so` 内部。这些符号通常存在于 `.symtab` 中，但不一定在 `.dynsym` 中，因为它们不需要被外部链接。

4. **符号解析 (Symbol Resolution):** 当程序启动或加载共享库时，dynamic linker 会遍历所有已加载的共享库的 `.dynsym`，查找未定义的符号的匹配项。一旦找到匹配的符号，dynamic linker 会更新调用点的地址，使其指向符号的实际地址。这通常通过 **PLT (Procedure Linkage Table)** 和 **GOT (Global Offset Table)** 来实现。

   - **PLT:**  包含外部函数的桩代码。第一次调用外部函数时，PLT 会跳转到 dynamic linker，由 dynamic linker 解析符号并更新 GOT 中的地址。后续调用将直接跳转到 GOT 中已解析的地址。
   - **GOT:**  包含全局变量和外部函数的地址。dynamic linker 在运行时填充 GOT 中的地址。

**假设输入与输出 (逻辑推理):**

假设 `LDBL_MANT_DIG == 64`，并且我们调用 `__kernel_sincosl` 函数：

**假设输入:**
- `x = 0.1L`
- `y = 0.0L`
- `iy = 0`

**推理过程:**
- `z = x * x = 0.01L`
- 计算 `r = S2 + z * (S3 + ...)`，将 `z` 和预定义的 `S` 系列常量代入计算。
- 计算 `*sn = x + v * (S1 + z * r)`，其中 `v = z * x`。
- 计算 `hz = z / 2 = 0.005L`
- 计算 `w = 1 - hz = 0.995L`
- 计算 `r = z * (C1 + z * (C2 + ...))`，将 `z` 和预定义的 `C` 系列常量代入计算。
- 计算 `*cs = w + (((1 - w) - hz) + (z * r - x * y))`。

**预期输出 (近似值):**
- `*sn` (sin(0.1)) ≈ 0.09983341664682815L
- `*cs` (cos(0.1)) ≈ 0.9950041652780258L

**用户或者编程常见的使用错误:**

1. **传递错误的数据类型:**  如果用户期望计算 `double` 的正弦但传递了 `long double` 的值给期望 `double` 的函数（或者反过来），可能会导致类型不匹配或精度损失。
2. **忽略精度问题:**  浮点数运算存在精度限制。直接比较浮点数的相等性通常是错误的。用户应该使用一个小的误差范围进行比较。
3. **大角度输入:**  对于非常大的角度，直接使用泰勒级数展开可能会收敛很慢或者精度不高。通常 `libm` 的高层函数会进行角度规约 (argument reduction) 来处理这种情况，但直接调用底层的 `__kernel_sincosl` 可能需要用户自己处理。
4. **误用内部函数:**  直接调用 `__kernel_sincosl` 而不是使用标准的 `sincosl` 函数可能会导致未定义的行为或依赖于特定的实现细节。用户应该使用 `libm` 提供的公共接口。

**Android framework or ndk 是如何一步步的到达这里，作为调试线索:**

**从 Android Framework 到 `k_sincosl.handroid`:**

1. **Java/Kotlin 代码调用 Math 类或相关 API:**  例如，一个 Canvas 的绘制操作可能需要计算角度的正弦或余弦。
2. **Framework 层调用 Native 代码 (JNI):**  `java.lang.Math` 类中的一些方法或者 Android 图形相关的 API 最终会调用到 native 代码实现。
3. **Native 代码调用 `libm` 函数:**  在 native 代码中，可能会调用 `sinl`, `cosl`, 或 `sincosl` 函数。这些函数是 `libm` 提供的公共接口。
4. **`sincosl` 函数内部调用 `__kernel_sincosl`:**  `libm` 中 `sincosl` 的实现通常会根据输入参数的范围和精度要求，最终调用到像 `__kernel_sincosl` 这样的底层核心函数来执行实际的计算。

**从 NDK 到 `k_sincosl.handroid`:**

1. **NDK 应用代码调用 `<cmath>` 中的函数:**  开发者在 C/C++ 代码中包含 `<cmath>` 头文件，并调用 `std::sinl`, `std::cosl`, 或 `std::sincosl`。
2. **链接到 `libm.so`:**  NDK 构建系统会将应用链接到 `libm.so` 共享库。
3. **动态链接器加载 `libm.so`:**  当应用运行时，动态链接器会加载 `libm.so`。
4. **调用 `sincosl` 并最终到达 `__kernel_sincosl`:**  当 NDK 应用调用 `sincosl` 时，会执行 `libm.so` 中对应的实现，该实现最终会调用到 `__kernel_sincosl`。

**调试线索:**

1. **使用 `adb logcat` 查看日志:**  可以在 Java/Kotlin 或 native 代码中添加日志输出，查看函数调用栈或变量值。
2. **使用 Android Studio 的 Debugger:**  可以 attach 到正在运行的 Android 进程，设置断点在 native 代码中（例如 `sincosl` 或 `__kernel_sincosl`），单步执行代码，查看变量值。需要配置好符号文件。
3. **使用 `perfetto` 或 `systrace` 进行系统跟踪:**  可以捕获系统级别的函数调用和事件，帮助理解调用流程。
4. **使用 `lldb` 进行 native 代码调试:**  对于更底层的调试，可以使用 `lldb` 连接到 Android 设备，手动设置断点、查看内存等。
5. **查看 `libm` 的源代码:**  理解 `libm` 中函数的实现细节，可以帮助定位问题。

总而言之，`k_sincosl.handroid` 是 Android 数学库中用于高精度正弦和余弦计算的核心组件，它通过泰勒级数展开等数学方法来实现功能，并在 Android 系统和 NDK 开发中扮演着重要的角色。 理解其功能和调用路径对于调试与数学运算相关的 Android 问题至关重要。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/k_sincosl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*-
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2008 Steven G. Kargl, David Schultz, Bruce D. Evans.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice 
 * is preserved.
 * ====================================================
 *
 * k_sinl.c and k_cosl.c merged by Steven G. Kargl
 */

#if LDBL_MANT_DIG == 64		/* ld80 version of k_sincosl.c. */

#if defined(__amd64__) || defined(__i386__)
/* Long double constants are slow on these arches, and broken on i386. */
static const volatile double
C1hi = 0.041666666666666664,		/*  0x15555555555555.0p-57 */
C1lo = 2.2598839032744733e-18,		/*  0x14d80000000000.0p-111 */
S1hi = -0.16666666666666666,		/* -0x15555555555555.0p-55 */
S1lo = -9.2563760475949941e-18;		/* -0x15580000000000.0p-109 */
#define	S1	((long double)S1hi + S1lo)
#define	C1	((long double)C1hi + C1lo)
#else
static const long double
C1 =  0.0416666666666666666136L,	/*  0xaaaaaaaaaaaaaa9b.0p-68 */
S1 = -0.166666666666666666671L;		/* -0xaaaaaaaaaaaaaaab.0p-66 */
#endif

static const double
C2 = -0.0013888888888888874,		/* -0x16c16c16c16c10.0p-62 */
C3 =  0.000024801587301571716,		/*  0x1a01a01a018e22.0p-68 */
C4 = -0.00000027557319215507120,	/* -0x127e4fb7602f22.0p-74 */
C5 =  0.0000000020876754400407278,	/*  0x11eed8caaeccf1.0p-81 */
C6 = -1.1470297442401303e-11,		/* -0x19393412bd1529.0p-89 */
C7 =  4.7383039476436467e-14,		/*  0x1aac9d9af5c43e.0p-97 */
S2 =  0.0083333333333333332,		/*  0x11111111111111.0p-59 */
S3 = -0.00019841269841269427,		/* -0x1a01a01a019f81.0p-65 */
S4 =  0.0000027557319223597490,		/*  0x171de3a55560f7.0p-71 */
S5 = -0.000000025052108218074604,	/* -0x1ae64564f16cad.0p-78 */
S6 =  1.6059006598854211e-10,		/*  0x161242b90243b5.0p-85 */
S7 = -7.6429779983024564e-13,		/* -0x1ae42ebd1b2e00.0p-93 */
S8 =  2.6174587166648325e-15;		/*  0x179372ea0b3f64.0p-101 */

static inline void
__kernel_sincosl(long double x, long double y, int iy, long double *sn,
    long double *cs)
{
	long double hz, r, v, w, z;

	z = x * x;
	v = z * x;
	/*
	 * XXX Replace Horner scheme with an algorithm suitable for CPUs
	 * with more complex pipelines.
	 */
	r = S2 + z * (S3 + z * (S4 + z * (S5 + z * (S6 + z * (S7 + z * S8)))));

	if (iy == 0)
		*sn = x + v * (S1 + z * r);
	else
		*sn = x - ((z * (y / 2 - v * r) - y) - v * S1);

	hz = z / 2;
	w = 1 - hz;
	r = z * (C1 + z * (C2 + z * (C3 + z * (C4 + z * (C5 + z * (C6 +
	    z * C7))))));
	*cs = w + (((1 - w) - hz) + (z * r - x * y));
}

#elif LDBL_MANT_DIG == 113	/* ld128 version of k_sincosl.c. */

static const long double
S1 = -0.16666666666666666666666666666666666606732416116558L,
S2 =  0.0083333333333333333333333333333331135404851288270047L,
S3 = -0.00019841269841269841269841269839935785325638310428717L,
S4 =  0.27557319223985890652557316053039946268333231205686e-5L,
S5 = -0.25052108385441718775048214826384312253862930064745e-7L,
S6 =  0.16059043836821614596571832194524392581082444805729e-9L,
S7 = -0.76471637318198151807063387954939213287488216303768e-12L,
S8 =  0.28114572543451292625024967174638477283187397621303e-14L;

static const double
S9  = -0.82206352458348947812512122163446202498005154296863e-17,
S10 =  0.19572940011906109418080609928334380560135358385256e-19,
S11 = -0.38680813379701966970673724299207480965452616911420e-22,
S12 =  0.64038150078671872796678569586315881020659912139412e-25;

static const long double
C1 =  4.16666666666666666666666666666666667e-02L,
C2 = -1.38888888888888888888888888888888834e-03L,
C3 =  2.48015873015873015873015873015446795e-05L,
C4 = -2.75573192239858906525573190949988493e-07L,
C5 =  2.08767569878680989792098886701451072e-09L,
C6 = -1.14707455977297247136657111139971865e-11L,
C7 =  4.77947733238738518870113294139830239e-14L,
C8 = -1.56192069685858079920640872925306403e-16L,
C9 =  4.11031762320473354032038893429515732e-19L,
C10= -8.89679121027589608738005163931958096e-22L,
C11=  1.61171797801314301767074036661901531e-24L,
C12= -2.46748624357670948912574279501044295e-27L;

static inline void
__kernel_sincosl(long double x, long double y, int iy, long double *sn, 
    long double *cs)
{
	long double hz, r, v, w, z;

	z = x * x;
	v = z * x;
	/*
	 * XXX Replace Horner scheme with an algorithm suitable for CPUs
	 * with more complex pipelines.
	 */
	r = S2 + z * (S3 + z * (S4 + z * (S5 + z * (S6 + z * (S7 + z * (S8 +
	    z * (S9 + z * (S10 + z * (S11 + z * S12)))))))));

	if (iy == 0)
		*sn = x + v * (S1 + z * r);
	else
		*sn = x - ((z * (y / 2 - v * r) - y) - v * S1);

	hz = z / 2;
	w = 1 - hz;
	r = z * (C1 + z * (C2 + z * (C3 + z * (C4 + z * (C5 + z * (C6 + 
	    z * (C7 + z * (C8 + z * (C9 + z * (C10 + z * (C11+z*C12)))))))))));

	*cs =  w + (((1 - w) - hz) + (z * r - x * y));
}
#else
#error "Unsupported long double format"
#endif

"""

```
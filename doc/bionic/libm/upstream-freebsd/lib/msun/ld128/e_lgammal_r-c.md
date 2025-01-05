Response:
Let's break down the thought process for analyzing this C code and generating the detailed response.

**1. Understanding the Request:**

The core request is to analyze the `e_lgammal_r.c` file from Android's Bionic library. This involves understanding its function, its relation to Android, how the underlying libc functions work, dynamic linking aspects (though this file itself isn't a dynamic linker component), potential user errors, and how it's reached during execution.

**2. Initial Code Examination and Key Function Identification:**

The first step is to read through the code, paying attention to:

* **Copyright and Comments:**  Indicate the origin and purpose. The comment "See e_lgamma_r.c for complete comments" suggests this is a specific implementation for `long double` and that a more general version exists.
* **Includes:** `fpmath.h`, `math.h`, `math_private.h` hint at the mathematical nature of the code and access to internal math library functions.
* **Constants:** The large number of `static const` variables (like `pi`, `a0`, `tc`, `w0`) are a strong indicator of polynomial or rational function approximations used in the implementation. The names often suggest their role (e.g., `a` for coefficients, `tc` for a central point).
* **`lgammal_r` function:** This is the main function being analyzed, evident from the filename. The `_r` suffix often indicates a reentrant version or a version that provides additional information (in this case, the sign of the Gamma function).
* **`sin_pil` function:** This helper function calculates the sine of pi times a number, likely used for handling negative arguments.
* **`__kernel_sinl` and `__kernel_cosl`:** These are likely low-level, optimized sine and cosine implementations within the math library.

**3. Functionality Determination (Focus on `lgammal_r`):**

Based on the function name and the mathematical constants, it's clear the primary function is to compute the natural logarithm of the absolute value of the Gamma function (lgamma) for a `long double` (extended precision floating-point) input `x`. The `signgamp` output parameter will store the sign of the Gamma function.

**4. Relating to Android:**

* **Core Math Library:** Recognize that `lgammal_r` is part of Android's foundational math library (`libm`), crucial for numerical computations in various Android components and applications.
* **NDK and Framework:**  Consider how Android developers using the NDK or framework components might indirectly call this function through standard C math library functions.

**5. Deconstructing `lgammal_r` Implementation:**

This involves analyzing the code's structure and logic:

* **Argument Handling:**  Check for NaN, infinity, zero, and very small inputs. These are standard checks in robust numerical implementations.
* **Sign Handling:**  The logic for negative inputs using `sin_pil` is important. The Gamma function has alternating signs for negative integers, and this part handles that.
* **Special Cases:** Handling the cases for `x = 1` and `x = 2` directly optimizes these common inputs.
* **Range Reduction and Approximations:** The code divides the input domain into several intervals. For each interval, it uses different sets of pre-calculated constants (`a`, `t`, `u`, `s`, `w`) and polynomial or rational function approximations. This is a common technique in math library implementations to achieve high accuracy and efficiency across a wide range of inputs. The comments within the code provide hints about the domain and range of these approximations.
* **Large Argument Handling:** The separate logic for large `x` leverages the asymptotic expansion of the Gamma function.

**6. Explaining Helper Functions (`sin_pil`):**

* Understand its purpose: calculating `sin(pi * x)`.
* Analyze its approach: range reduction using modulo operations, then calling the kernel sine and cosine functions. This leverages trigonometric identities.

**7. Addressing Dynamic Linking (Important Clarification):**

Crucially, recognize that `e_lgammal_r.c` itself *implements* a function within a shared library (`libm.so`), but it's *not* part of the dynamic linker. Therefore, focus on how *this function* is placed within the shared library and how symbols are resolved *to this function*.

* **SO Layout:** Describe the general structure of a shared object file.
* **Symbol Resolution:** Explain how the linker resolves symbols (like `lgammal_r`) using the symbol table. Differentiate between global and local symbols.

**8. Input/Output Examples and Logical Reasoning:**

Choose simple yet illustrative examples to demonstrate the function's behavior for positive and negative inputs, including integer cases.

**9. Common User Errors:**

Think about typical mistakes programmers might make when using `lgamma`, such as passing invalid input or ignoring the sign information.

**10. Debugging Path (Android Framework/NDK):**

Trace the potential call flow:

* **NDK:** A developer uses `<cmath>` or `<math.h>` and calls `lgammal`. The linker links against `libm.so`, and the call is directed to the implemented function.
* **Framework:**  Higher-level Java code might use JNI to call native C/C++ code that uses `lgamma`. Alternatively, framework components might use it directly. Provide concrete examples (like Renderscript or native system services).

**11. Review and Refine:**

Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that need further explanation. For instance, initially, I might have focused too much on the dynamic linker itself, but the key is to connect it to how the *function within the file* gets linked. Also, ensure that the explanations of the mathematical approximations are at an appropriate level of detail (avoiding overly complex mathematical jargon).
好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/ld128/e_lgammal_r.c` 这个文件。

**功能列举**

`e_lgammal_r.c` 文件实现了 `lgammal_r` 函数，其主要功能是计算长双精度浮点数 `x` 的自然对数伽玛函数 `ln(|Γ(x)|)`，并同时返回伽玛函数 `Γ(x)` 的符号。

更具体地说，`lgammal_r(x, signgamp)` 执行以下操作：

1. **计算 `ln(|Γ(x)|)`:**  返回输入值 `x` 的伽玛函数绝对值的自然对数。
2. **返回 `Γ(x)` 的符号:** 将伽玛函数的符号存储在 `signgamp` 指向的整数中。如果 `Γ(x)` 为正，则 `*signgamp` 为 1；如果为负，则 `*signgamp` 为 -1。

**与 Android 功能的关系及举例说明**

`lgammal_r` 是 Android 系统 C 库 `bionic` 的一部分，属于数学库 `libm`。数学库提供了各种常用的数学函数，供系统组件、应用以及通过 NDK 开发的本地代码使用。

**举例说明：**

* **科学计算应用:** 一个 Android 应用如果进行复杂的科学计算，例如统计分析、概率模型建立、物理模拟等，可能需要计算伽玛函数。`lgammal_r` 提供了高精度的计算能力。
* **图形渲染:**  某些图形渲染算法中可能涉及到需要伽玛校正或其他与伽玛函数相关的计算。
* **机器学习库:**  底层的机器学习库（例如 TensorFlow Lite 的某些操作）可能使用到伽玛函数及其对数形式。
* **系统服务:** Android 框架的某些底层系统服务在进行资源管理、性能优化等操作时，可能需要进行数值计算，间接用到 `libm` 中的函数。

**libc 函数的功能实现解释**

`e_lgammal_r.c` 中实现的 `lgammal_r` 函数，为了保证精度和性能，采用了分段逼近的方法。它根据输入值 `x` 的范围，使用不同的多项式或有理函数逼近 `lgamma(x)`。

**详细解释：**

1. **参数处理和特殊值处理：**
   - 首先，函数检查输入 `x` 是否为 `NaN`（非数字）或无穷大。如果是，则直接返回 `x * x`（根据 IEEE 754 标准，这样做可以传播 `NaN`）。
   - 接着，处理 `x` 为 0 或非常小的正数的情况。对于这些情况，`lgamma(x)` 趋于无穷大，因此返回 `one/vzero` (表示正无穷大)。同时设置 `signgamp` 为 1。
   - 处理负数的情况。对于负数，伽玛函数的符号是交替的。函数使用 `sin_pil(x)` 计算 `sin(πx)`，并根据其符号来确定 `Γ(x)` 的符号。同时，利用 `Γ(x) = Γ(x+1)/x` 的性质，将负数的情况转化为正数的情况进行计算。

2. **分段逼近：**
   - 函数将正数 `x` 的范围划分为多个区间，并在每个区间内使用不同的逼近方法。这主要是为了在保证精度的前提下，提高计算效率。
   - **小值区域 (x < 2)：**
     - 对于非常小的正数（例如 `x <= 8.9999961853027344e-01`），直接计算 `-logl(x)`。
     - 对于其他小值，根据 `x` 的不同范围（接近 1 或 2），使用不同的多项式逼近，例如：
       - 使用以 0 为中心的幂级数展开逼近 `lgamma(2 - y)`。
       - 使用以 `tc` (接近 1.5) 为中心的泰勒展开逼近 `lgamma(x)`。
       - 使用有理函数逼近 `lgamma(1 + y)`。
   - **中等值区域 (2 < x <= 8)：**
     - 将 `x` 分解为整数部分 `i` 和小数部分 `y`。
     - 使用多项式或有理函数逼近 `lgamma(y+2)`，然后利用伽玛函数的递推公式 `Γ(x+1) = xΓ(x)`，通过累乘将结果调整为 `lgamma(x)`。
   - **较大值区域 (8 <= x)：**
     - 对于较大的 `x`，使用斯特林公式（Stirling's approximation）的展开式来逼近 `lgamma(x)`：
       `lgamma(x) ≈ (x - 0.5) * (log(x) - 1) + w(1/x)`
       其中 `w(1/x)` 是一个关于 `1/x` 的多项式。
   - **非常大的值区域 (x >= 2**(p+3))**：
     - 对于非常大的 `x`，直接使用简化的斯特林公式：
       `lgamma(x) ≈ x * (logl(x) - 1)`

3. **`sin_pil(long double x)` 函数:**
   - 这是一个辅助函数，用于计算 `sin(πx)`。
   - 它利用三角函数的周期性和对称性，将 `πx` 的范围规约到 `[0, π/4]` 或 `[π/4, π/2]`。
   - 然后调用 `__kernel_sinl` 或 `__kernel_cosl` 等底层优化的内核函数进行计算。

4. **内核函数 (`__kernel_sinl`, `__kernel_cosl`):**
   - 这些函数通常是汇编语言实现或者高度优化的 C 代码，用于高效且精确地计算基本的三角函数。它们通常使用查表法、多项式逼近或其他高效算法。由于这些函数在 `e_lgammal_r.c` 中被调用，但其实现并不在此文件中，我们无法直接看到其具体实现细节。它们通常位于 Bionic 数学库的其他文件中。

**Dynamic Linker 的功能**

`e_lgammal_r.c` 文件本身是 `libm.so` 的一个源代码文件，它会被编译成机器码并链接到 `libm.so` 中。动态链接器（在 Android 中主要是 `linker64` 或 `linker`）负责在程序运行时加载共享库，并将程序中对共享库函数的调用链接到实际的函数地址。

**SO 布局样本：**

一个典型的 `libm.so` 的布局可能如下：

```
libm.so:
    .text          # 包含可执行的机器码
        lgammal_r:  # lgammal_r 函数的机器码
        sin_pil:    # sin_pil 函数的机器码
        ...          # 其他数学函数的机器码
        __kernel_sinl: # 内核 sin 函数的机器码
        __kernel_cosl: # 内核 cos 函数的机器码
    .rodata        # 包含只读数据，例如常量
        pi:
        a0:
        ...
    .data          # 包含可读写的数据
    .bss           # 包含未初始化的静态数据
    .symtab        # 符号表，包含导出的符号信息
        lgammal_r (global, function): address
        sin_pil (static, function): address (通常不会导出)
        ...
    .strtab        # 字符串表，存储符号名称
    .rel.dyn       # 动态重定位表
    ...
```

**每种符号的处理过程：**

1. **全局符号 (Global Symbols):**
   - 例如 `lgammal_r`。
   - 动态链接器在加载 `libm.so` 时，会将这些全局符号添加到全局符号表中。
   - 当其他共享库或可执行文件需要调用 `lgammal_r` 时，动态链接器会在全局符号表中查找该符号的地址，并进行重定向，将调用指令的目标地址设置为 `lgammal_r` 在 `libm.so` 中的实际地址。

2. **本地符号 (Local Symbols):**
   - 例如 `sin_pil`（如果它是 `static` 的）。
   - 这些符号的作用域仅限于定义它们的编译单元（即 `e_lgammal_r.c` 编译后的目标文件）。
   - 动态链接器通常不会将这些符号导出到全局符号表。
   - 这些符号的地址在链接 `libm.so` 内部时就已经确定。

3. **未定义符号 (Undefined Symbols):**
   - 例如 `__kernel_sinl` 和 `__kernel_cosl` 在 `e_lgammal_r.c` 中是调用的，但其实现不在这个文件中。
   - 在链接 `libm.so` 时，这些符号是未定义的。
   - 动态链接器会在其他已加载的共享库中查找这些符号的定义。如果 `__kernel_sinl` 和 `__kernel_cosl` 在 `libm.so` 的其他部分实现，链接器会将调用指令重定向到这些实现的地址。

**逻辑推理：假设输入与输出**

假设输入 `x = 2.5`：

1. 函数首先会检查 `x` 的范围，确定其位于中等值区域 (2 < x <= 8)。
2. 计算 `y = x - 2 = 0.5`。
3. 使用预定义的常量 `s0` 到 `s11` 和 `r1` 到 `r11` 计算多项式 `p` 和 `q`。
4. 计算 `r = y/2 + p/q`。
5. 因为 `i = 2`，`z = 1`。
6. 返回 `r + logl(z) = r + logl(1) = r`.
7. `signgamp` 将被设置为 1，因为 `Γ(2.5)` 是正数。

假设输入 `x = -0.5`：

1. 函数检测到 `x` 是负数。
2. 调用 `sin_pil(-0.5)` 计算 `sin(-0.5π) = -1`。
3. `t` 将为 -1，因此 `*signgamp` 将设置为 -1。
4. 计算 `nadj = logl(pi / abs((-1) * (-0.5))) = logl(2π)`。
5. 将 `x` 更新为 `abs(x) = 0.5`。
6. 由于 `x < 1`，会进入小值区域的相应分支。
7. 使用相应的多项式逼近计算 `lgamma(0.5)`。
8. 最终返回 `nadj - lgamma(0.5)`。

**用户或编程常见的使用错误**

1. **传入 `NaN` 或无穷大而不进行检查:**  虽然 `lgammal_r` 可以处理这些值，但依赖其返回值可能导致不可预测的行为。建议在使用前检查输入。
2. **忽略 `signgamp` 的值:** 如果只关心 `lgamma` 的绝对值，可能会忽略 `signgamp`，但在某些需要知道伽玛函数符号的场景下，这会导致错误。
3. **误解 `lgamma` 的定义:**  `lgamma` 计算的是伽玛函数绝对值的自然对数，而不是伽玛函数本身。如果需要伽玛函数的值，需要使用 `expl(lgammal_r(...))`。
4. **精度问题:** 虽然 `long double` 提供了更高的精度，但在某些极端情况下，仍然可能存在精度损失。用户应该了解浮点运算的局限性。
5. **性能问题:** 对于需要大量计算伽玛函数的场景，频繁调用 `lgammal_r` 可能会影响性能。可以考虑使用缓存或其他优化策略。

**Android Framework 或 NDK 如何到达这里，作为调试线索**

1. **NDK 开发:**
   - 一个使用 NDK 进行本地开发的 Android 应用，其 C/C++ 代码中包含了 `<cmath>` 或 `<math.h>` 头文件，并调用了 `lgammal` 函数。
   - 编译时，NDK 的工具链会将该调用链接到 Android 系统提供的 `libm.so`。
   - 运行时，当执行到调用 `lgammal` 的代码时，动态链接器会加载 `libm.so`，并将调用重定向到 `libm.so` 中 `lgammal_r` 的实现。

   **调试线索：**
   - 使用 GDB 或 LLDB 等调试器，在本地代码中设置断点。
   - 逐步执行代码，观察 `lgammal` 函数的调用栈，可以追踪到是否进入了 `libm.so` 中的 `lgammal_r` 函数。

2. **Android Framework:**
   - Android Framework 的某些组件可能使用到 JNI 调用本地代码，而这些本地代码中调用了 `lgammal`。
   - 某些系统服务（例如涉及科学计算或统计的）可能直接或间接地调用了 `libm` 中的函数。

   **调试线索：**
   - 如果怀疑 Framework 层面的代码调用了 `lgammal_r`，可以使用 `adb shell dumpsys` 命令查看系统服务的状态和日志。
   - 可以尝试在 Framework 的 Java 代码中找到可能的 JNI 调用点，然后在本地代码中设置断点进行调试。
   - 对于纯 Native 的系统服务，可以使用 GDB 或 LLDB 直接附加到该进程进行调试。

3. **RenderScript:**
   - RenderScript 是一种用于高性能计算的框架。RenderScript 内核代码可以使用标准 C 数学函数，包括 `lgamma`。
   - 当 RenderScript 内核被执行时，对 `lgamma` 的调用会被链接到 `libm.so`。

   **调试线索：**
   - 可以使用 Android Studio 的 RenderScript 调试功能，设置断点并单步执行 RenderScript 内核代码，观察 `lgamma` 的调用。

**总结**

`e_lgammal_r.c` 是 Android 系统中计算长双精度伽玛函数对数的关键组成部分。它通过精巧的数学逼近方法实现了高精度和效率。理解其功能和实现方式，以及与 Android 系统和 NDK 的联系，对于进行底层开发、性能优化和问题排查都非常有帮助。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/e_lgammal_r.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * See e_lgamma_r.c for complete comments.
 *
 * Converted to long double by Steven G. Kargl.
 */

#include "fpmath.h"
#include "math.h"
#include "math_private.h"

static const volatile double vzero = 0;

static const double
zero=  0,
half=  0.5,
one =  1;

static const long double
pi  =  3.14159265358979323846264338327950288e+00L;
/*
 * Domain y in [0x1p-119, 0.28], range ~[-1.4065e-36, 1.4065e-36]:
 * |(lgamma(2 - y) + y / 2) / y - a(y)| < 2**-119.1
 */
static const long double
a0  =  7.72156649015328606065120900824024296e-02L,
a1  =  3.22467033424113218236207583323018498e-01L,
a2  =  6.73523010531980951332460538330282217e-02L,
a3  =  2.05808084277845478790009252803463129e-02L,
a4  =  7.38555102867398526627292839296001626e-03L,
a5  =  2.89051033074152328576829509522483468e-03L,
a6  =  1.19275391170326097618357349881842913e-03L,
a7  =  5.09669524743042462515256340206203019e-04L,
a8  =  2.23154758453578096143609255559576017e-04L,
a9  =  9.94575127818397632126978731542755129e-05L,
a10 =  4.49262367375420471287545895027098145e-05L,
a11 =  2.05072127845117995426519671481628849e-05L,
a12 =  9.43948816959096748454087141447939513e-06L,
a13 =  4.37486780697359330303852050718287419e-06L,
a14 =  2.03920783892362558276037363847651809e-06L,
a15 =  9.55191070057967287877923073200324649e-07L,
a16 =  4.48993286185740853170657139487620560e-07L,
a17 =  2.13107543597620911675316728179563522e-07L,
a18 =  9.70745379855304499867546549551023473e-08L,
a19 =  5.61889970390290257926487734695402075e-08L,
a20 =  6.42739653024130071866684358960960951e-09L,
a21 =  3.34491062143649291746195612991870119e-08L,
a22 = -1.57068547394315223934653011440641472e-08L,
a23 =  1.30812825422415841213733487745200632e-08L;
/*
 * Domain x in [tc-0.24, tc+0.28], range ~[-6.3201e-37, 6.3201e-37]:
 * |(lgamma(x) - tf) - t(x - tc)| < 2**-120.3.
 */
static const long double
tc  =  1.46163214496836234126265954232572133e+00L,
tf  = -1.21486290535849608095514557177691584e-01L,
tt  =  1.57061739945077675484237837992951704e-36L,
t0  = -1.99238329499314692728655623767019240e-36L,
t1  = -6.08453430711711404116887457663281416e-35L,
t2  =  4.83836122723810585213722380854828904e-01L,
t3  = -1.47587722994530702030955093950668275e-01L,
t4  =  6.46249402389127526561003464202671923e-02L,
t5  = -3.27885410884813055008502586863748063e-02L,
t6  =  1.79706751152103942928638276067164935e-02L,
t7  = -1.03142230366363872751602029672767978e-02L,
t8  =  6.10053602051788840313573150785080958e-03L,
t9  = -3.68456960831637325470641021892968954e-03L,
t10 =  2.25976482322181046611440855340968560e-03L,
t11 = -1.40225144590445082933490395950664961e-03L,
t12 =  8.78232634717681264035014878172485575e-04L,
t13 = -5.54194952796682301220684760591403899e-04L,
t14 =  3.51912956837848209220421213975000298e-04L,
t15 = -2.24653443695947456542669289367055542e-04L,
t16 =  1.44070395420840737695611929680511823e-04L,
t17 = -9.27609865550394140067059487518862512e-05L,
t18 =  5.99347334438437081412945428365433073e-05L,
t19 = -3.88458388854572825603964274134801009e-05L,
t20 =  2.52476631610328129217896436186551043e-05L,
t21 = -1.64508584981658692556994212457518536e-05L,
t22 =  1.07434583475987007495523340296173839e-05L,
t23 = -7.03070407519397260929482550448878399e-06L,
t24 =  4.60968590693753579648385629003100469e-06L,
t25 = -3.02765473778832036018438676945512661e-06L,
t26 =  1.99238771545503819972741288511303401e-06L,
t27 = -1.31281299822614084861868817951788579e-06L,
t28 =  8.60844432267399655055574642052370223e-07L,
t29 = -5.64535486432397413273248363550536374e-07L,
t30 =  3.99357783676275660934903139592727737e-07L,
t31 = -2.95849029193433121795495215869311610e-07L,
t32 =  1.37790144435073124976696250804940384e-07L;
/*
 * Domain y in [-0.1, 0.232], range ~[-1.4046e-37, 1.4181e-37]:
 * |(lgamma(1 + y) + 0.5 * y) / y - u(y) / v(y)| < 2**-122.8
 */
static const long double
u0  = -7.72156649015328606065120900824024311e-02L,
u1  =  4.24082772271938167430983113242482656e-01L,
u2  =  2.96194003481457101058321977413332171e+00L,
u3  =  6.49503267711258043997790983071543710e+00L,
u4  =  7.40090051288150177152835698948644483e+00L,
u5  =  4.94698036296756044610805900340723464e+00L,
u6  =  2.00194224610796294762469550684947768e+00L,
u7  =  4.82073087750608895996915051568834949e-01L,
u8  =  6.46694052280506568192333848437585427e-02L,
u9  =  4.17685526755100259316625348933108810e-03L,
u10 =  9.06361003550314327144119307810053410e-05L,
v1  =  5.15937098592887275994320496999951947e+00L,
v2  =  1.14068418766251486777604403304717558e+01L,
v3  =  1.41164839437524744055723871839748489e+01L,
v4  =  1.07170702656179582805791063277960532e+01L,
v5  =  5.14448694179047879915042998453632434e+00L,
v6  =  1.55210088094585540637493826431170289e+00L,
v7  =  2.82975732849424562719893657416365673e-01L,
v8  =  2.86424622754753198010525786005443539e-02L,
v9  =  1.35364253570403771005922441442688978e-03L,
v10 =  1.91514173702398375346658943749580666e-05L,
v11 = -3.25364686890242327944584691466034268e-08L;
/*
 * Domain x in (2, 3], range ~[-1.3341e-36, 1.3536e-36]:
 * |(lgamma(y+2) - 0.5 * y) / y - s(y)/r(y)| < 2**-120.1
 * with y = x - 2.
 */
static const long double
s0  = -7.72156649015328606065120900824024297e-02L,
s1  =  1.23221687850916448903914170805852253e-01L,
s2  =  5.43673188699937239808255378293820020e-01L,
s3  =  6.31998137119005233383666791176301800e-01L,
s4  =  3.75885340179479850993811501596213763e-01L,
s5  =  1.31572908743275052623410195011261575e-01L,
s6  =  2.82528453299138685507186287149699749e-02L,
s7  =  3.70262021550340817867688714880797019e-03L,
s8  =  2.83374000312371199625774129290973648e-04L,
s9  =  1.15091830239148290758883505582343691e-05L,
s10 =  2.04203474281493971326506384646692446e-07L,
s11 =  9.79544198078992058548607407635645763e-10L,
r1  =  2.58037466655605285937112832039537492e+00L,
r2  =  2.86289413392776399262513849911531180e+00L,
r3  =  1.78691044735267497452847829579514367e+00L,
r4  =  6.89400381446725342846854215600008055e-01L,
r5  =  1.70135865462567955867134197595365343e-01L,
r6  =  2.68794816183964420375498986152766763e-02L,
r7  =  2.64617234244861832870088893332006679e-03L,
r8  =  1.52881761239180800640068128681725702e-04L,
r9  =  4.63264813762296029824851351257638558e-06L,
r10 =  5.89461519146957343083848967333671142e-08L,
r11 =  1.79027678176582527798327441636552968e-10L;
/*
 * Domain z in [8, 0x1p70], range ~[-9.8214e-35, 9.8214e-35]:
 * |lgamma(x) - (x - 0.5) * (log(x) - 1) - w(1/x)| < 2**-113.0
 */
static const long double
w0  =  4.18938533204672741780329736405617738e-01L,
w1  =  8.33333333333333333333333333332852026e-02L,
w2  = -2.77777777777777777777777727810123528e-03L,
w3  =  7.93650793650793650791708939493907380e-04L,
w4  = -5.95238095238095234390450004444370959e-04L,
w5  =  8.41750841750837633887817658848845695e-04L,
w6  = -1.91752691752396849943172337347259743e-03L,
w7  =  6.41025640880333069429106541459015557e-03L,
w8  = -2.95506530801732133437990433080327074e-02L,
w9  =  1.79644237328444101596766586979576927e-01L,
w10 = -1.39240539108367641920172649259736394e+00L,
w11 =  1.33987701479007233325288857758641761e+01L,
w12 = -1.56363596431084279780966590116006255e+02L,
w13 =  2.14830978044410267201172332952040777e+03L,
w14 = -3.28636067474227378352761516589092334e+04L,
w15 =  5.06201257747865138432663574251462485e+05L,
w16 = -6.79720123352023636706247599728048344e+06L,
w17 =  6.57556601705472106989497289465949255e+07L,
w18 = -3.26229058141181783534257632389415580e+08L;

static long double
sin_pil(long double x)
{
	volatile long double vz;
	long double y,z;
	uint64_t lx, n;
	uint16_t hx;

	y = -x;

	vz = y+0x1.p112;
	z = vz-0x1.p112;
	if (z == y)
	    return zero;

	vz = y+0x1.p110;
	EXTRACT_LDBL128_WORDS(hx,lx,n,vz);
	z = vz-0x1.p110;
	if (z > y) {
	    z -= 0.25;
	    n--;
	}
	n &= 7;
	y = y - z + n * 0.25;

	switch (n) {
	    case 0:   y =  __kernel_sinl(pi*y,zero,0); break;
	    case 1:
	    case 2:   y =  __kernel_cosl(pi*(0.5-y),zero); break;
	    case 3:
	    case 4:   y =  __kernel_sinl(pi*(one-y),zero,0); break;
	    case 5:
	    case 6:   y = -__kernel_cosl(pi*(y-1.5),zero); break;
	    default:  y =  __kernel_sinl(pi*(y-2.0),zero,0); break;
	    }
	return -y;
}

long double
lgammal_r(long double x, int *signgamp)
{
	long double nadj,p,p1,p2,p3,q,r,t,w,y,z;
	uint64_t llx,lx;
	int i;
	uint16_t hx,ix;

	EXTRACT_LDBL128_WORDS(hx,lx,llx,x);

    /* purge +-Inf and NaNs */
	*signgamp = 1;
	ix = hx&0x7fff;
	if(ix==0x7fff) return x*x;

   /* purge +-0 and tiny arguments */
	*signgamp = 1-2*(hx>>15);
	if(ix<0x3fff-116) {		/* |x|<2**-(p+3), return -log(|x|) */
	    if((ix|lx|llx)==0)
		return one/vzero;
	    return -logl(fabsl(x));
	}

    /* purge negative integers and start evaluation for other x < 0 */
	if(hx&0x8000) {
	    *signgamp = 1;
	    if(ix>=0x3fff+112) 		/* |x|>=2**(p-1), must be -integer */
		return one/vzero;
	    t = sin_pil(x);
	    if(t==zero) return one/vzero;
	    nadj = logl(pi/fabsl(t*x));
	    if(t<zero) *signgamp = -1;
	    x = -x;
	}

    /* purge 1 and 2 */
	if((ix==0x3fff || ix==0x4000) && (lx|llx)==0) r = 0;
    /* for x < 2.0 */
	else if(ix<0x4000) {
	    if(x<=8.9999961853027344e-01) {
		r = -logl(x);
		if(x>=7.3159980773925781e-01) {y = 1-x; i= 0;}
		else if(x>=2.3163998126983643e-01) {y= x-(tc-1); i=1;}
	  	else {y = x; i=2;}
	    } else {
		r = 0;
	        if(x>=1.7316312789916992e+00) {y=2-x;i=0;}
	        else if(x>=1.2316322326660156e+00) {y=x-tc;i=1;}
		else {y=x-1;i=2;}
	    }
	    switch(i) {
	      case 0:
		z = y*y;
		p1 = a0+z*(a2+z*(a4+z*(a6+z*(a8+z*(a10+z*(a12+z*(a14+z*(a16+
		    z*(a18+z*(a20+z*a22))))))))));
		p2 = z*(a1+z*(a3+z*(a5+z*(a7+z*(a9+z*(a11+z*(a13+z*(a15+
		    z*(a17+z*(a19+z*(a21+z*a23)))))))))));
		p  = y*p1+p2;
		r  += p-y/2; break;
	      case 1:
		p = t0+y*t1+tt+y*y*(t2+y*(t3+y*(t4+y*(t5+y*(t6+y*(t7+y*(t8+
		    y*(t9+y*(t10+y*(t11+y*(t12+y*(t13+y*(t14+y*(t15+y*(t16+
		    y*(t17+y*(t18+y*(t19+y*(t20+y*(t21+y*(t22+y*(t23+
		    y*(t24+y*(t25+y*(t26+y*(t27+y*(t28+y*(t29+y*(t30+
		    y*(t31+y*t32))))))))))))))))))))))))))))));
		r += tf + p; break;
	      case 2:
		p1 = y*(u0+y*(u1+y*(u2+y*(u3+y*(u4+y*(u5+y*(u6+y*(u7+
		    y*(u8+y*(u9+y*u10))))))))));
		p2 = one+y*(v1+y*(v2+y*(v3+y*(v4+y*(v5+y*(v6+y*(v7+
		    y*(v8+y*(v9+y*(v10+y*v11))))))))));
		r += p1/p2-y/2;
	    }
	}
    /* x < 8.0 */
	else if(ix<0x4002) {
	    i = x;
	    y = x-i;
	    p = y*(s0+y*(s1+y*(s2+y*(s3+y*(s4+y*(s5+y*(s6+y*(s7+y*(s8+
		y*(s9+y*(s10+y*s11)))))))))));
	    q = one+y*(r1+y*(r2+y*(r3+y*(r4+y*(r5+y*(r6+y*(r7+y*(r8+
		y*(r9+y*(r10+y*r11))))))))));
	    r = y/2+p/q;
	    z = 1;	/* lgamma(1+s) = log(s) + lgamma(s) */
	    switch(i) {
	    case 7: z *= (y+6);		/* FALLTHRU */
	    case 6: z *= (y+5);		/* FALLTHRU */
	    case 5: z *= (y+4);		/* FALLTHRU */
	    case 4: z *= (y+3);		/* FALLTHRU */
	    case 3: z *= (y+2);		/* FALLTHRU */
		    r += logl(z); break;
	    }
    /* 8.0 <= x < 2**(p+3) */
	} else if (ix<0x3fff+116) {
	    t = logl(x);
	    z = one/x;
	    y = z*z;
	    w = w0+z*(w1+y*(w2+y*(w3+y*(w4+y*(w5+y*(w6+y*(w7+y*(w8+
		y*(w9+y*(w10+y*(w11+y*(w12+y*(w13+y*(w14+y*(w15+y*(w16+
		y*(w17+y*w18)))))))))))))))));
	    r = (x-half)*(t-one)+w;
    /* 2**(p+3) <= x <= inf */
	} else 
	    r =  x*(logl(x)-1);
	if(hx&0x8000) r = nadj - r;
	return r;
}

"""

```
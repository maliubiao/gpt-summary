Response:
Let's break down the thought process for analyzing this `k_tanl.c` file.

**1. Initial Understanding & Context:**

* **File Name & Path:** `bionic/libm/upstream-freebsd/lib/msun/ld128/k_tanl.c`. This immediately tells us:
    * **`bionic`:** It's part of Android's core C library.
    * **`libm`:** It's in the math library.
    * **`upstream-freebsd`:**  The code originates from FreeBSD's math library. This is a crucial point –  Android's `libm` often incorporates well-tested, high-quality code from other projects.
    * **`ld128`:** This indicates it's specifically for `long double` (128-bit floating-point) precision.
    * **`k_tanl.c`:**  The `k_` prefix often signifies a "kernel" function or a low-level helper function within a larger mathematical operation. The `tanl` strongly suggests it's related to the tangent function for `long double`.

* **Copyright Notice:** Confirms the FreeBSD origin and licensing.

* **Comments:**  The initial comments are very important. They tell us:
    * It's the `ld128` version, referencing a similar file `../src/k_tan.c`. This hints at code reuse and variations for different precisions.
    * The intended domain and range of the function.
    * A key accuracy goal related to the polynomial approximation.
    * A reference to `../ld80/k_cosl.c`, suggesting similar polynomial approximation techniques are used.

**2. Functionality Identification:**

* The code defines a single function: `long double __kernel_tanl(long double x, long double y, int iy)`.
* The name `__kernel_tanl` reinforces the idea of a helper function. The double underscore often implies an internal or implementation-specific function.
* The parameters `x` and `y` (both `long double`) and `iy` (an integer) need further investigation.
* The core of the function seems to involve polynomial calculations based on `x` and `z = x * x`. This strongly points to a Taylor series or Chebyshev polynomial approximation of the tangent function.

**3. Relating to Android:**

* This function is part of `libm`, which is fundamental to Android. Any code using mathematical functions (e.g., games, scientific apps, even some system components) could potentially rely on this code path when calculating tangents of high-precision values.
* **Example:** An augmented reality app calculating precise angles for object placement might indirectly use `tanl` if it uses `long double` for its calculations.

**4. Detailed Explanation of the `libc` Function (`__kernel_tanl`):**

* **Parameter Analysis:**
    * `x`: The input angle.
    * `y`: Seems to be a high-precision correction term, likely used when the input is reduced.
    * `iy`:  A flag (likely -1 or 1) to handle quadrant adjustments or different parts of the tangent calculation. The comment "XXX recover original interface" suggests this is a way to adapt the FreeBSD code.

* **Core Logic Breakdown:**
    * **Domain Reduction:** The `if (fabsl(x) >= 0.67434)` block suggests a domain reduction technique. If `|x|` is large, it transforms the problem using the identity `tan(pi/4 - x) = (1 - tan(x))/(1 + tan(x))` or a related trigonometric identity. The constants `pio4` and `pio4lo` strongly suggest this reduction uses `pi/4`.
    * **Polynomial Approximation:** The series of `T` constants (`T3`, `T5`, etc.) are the coefficients of the polynomial approximation. The nested multiplications efficiently calculate the polynomial value using Horner's method. The comments mention the desired accuracy, which is achieved through this careful selection of coefficients.
    * **Handling the `iy` Flag:** The `if (i == 1)` and subsequent `if (iy == 1)`/`else` blocks handle the cases after domain reduction. The logic involves inverting the tangent or making further adjustments based on the initial quadrant.

**5. Dynamic Linker Aspects (Hypothetical - `k_tanl.c` itself isn't directly involved):**

* **SO Layout Sample:**
   ```
   .note.android.ident
   .dynsym
   .hash
   .gnu.hash
   .gnu.version
   .gnu.version_r
   .rel.dyn
   .rel.plt
   .plt
   .text         <-- __kernel_tanl code resides here
   .rodata       <-- Constants like T3, T5, pio4 are here
   .data
   .bss
   ```

* **Symbol Processing:**
    * **`__kernel_tanl` (Global, Hidden/Internal):** The dynamic linker would record this symbol in the `.dynsym` table. Since it's likely an internal helper, it might have hidden visibility, meaning it's not intended for direct linking by other shared libraries.
    * **Constants (Local):** Symbols like `T3`, `T5`, etc., would typically be local to the shared object and not visible externally.

**6. Logic Reasoning (with Assumptions):**

* **Assumption:** The input `x` is within the domain where the polynomial approximation is valid after potential domain reduction.
* **Input:** `x = 0.1L`, `y = 0.0L`, `iy = 1`
* **Output:**  The function will calculate `tan(0.1)` using the polynomial approximation. The `if (fabsl(x) >= 0.67434)` condition will be false, so the domain reduction won't happen. The result will be close to `0.1` (since `tan(x) ~ x` for small `x`). The final `if (iy == 1)` will return `w`, which is `x + r`.

**7. Common Usage Errors (Indirect, as users don't call `__kernel_tanl` directly):**

* **Incorrect Precision:**  If a user expects higher precision than `long double` provides, they might encounter limitations.
* **Domain Errors (for higher-level `tanl`):**  While `__kernel_tanl` handles a reduced domain, the higher-level `tanl` function needs to handle cases where the input is near `pi/2 + k*pi`, where the tangent approaches infinity. This is where overflow or division by zero errors could occur if not handled correctly in the calling function.

**8. Android Framework/NDK Call Chain (Debugging Clues):**

1. **NDK:** A developer uses a math function like `tanl()` from `<cmath>` in their C/C++ NDK code.
2. **`libm.so`:** When the application runs, the dynamic linker loads `libm.so`.
3. **Symbol Resolution:** When `tanl()` is called, the dynamic linker resolves it to the implementation within `libm.so`.
4. **`tanl()` Implementation:** The standard `tanl()` function in `libm` (likely in a file like `tanl.c` or similar) will perform initial checks (e.g., handling special cases like NaN, infinity, and domain reduction for larger angles).
5. **`__kernel_tanl()` Call:** For inputs within the domain handled by the polynomial approximation, the main `tanl()` function will call the internal helper function `__kernel_tanl()` to perform the core calculation.

**Debugging Scenario:** If a developer suspects an issue with the precision of `tanl()`, they might:

* **Use a debugger (like GDB):** Set breakpoints within `libm.so`, specifically in `tanl()` and `__kernel_tanl()`, to examine the intermediate values and see if the calculation matches their expectations.
* **Compare with other implementations:** Compare the results with the output of `tanl()` from other math libraries or online calculators with higher precision.
* **Examine the input values:** Ensure the input `long double` values have the expected precision and are not being truncated or corrupted earlier in the calculation.

This detailed thought process allows for a comprehensive analysis of the provided code snippet and its role within the Android ecosystem. The key is to understand the context, identify the function's purpose, and then delve into the implementation details while considering the broader implications for Android and potential debugging scenarios.
好的，让我们深入分析一下 `bionic/libm/upstream-freebsd/lib/msun/ld128/k_tanl.c` 这个文件。

**功能列举:**

该文件定义了一个函数 `__kernel_tanl`，其核心功能是**计算 `long double` 类型（128位浮点数）的 tan(x) 值**，但针对的是一个**较小的输入范围**。更具体地说，它是在已知输入 `x` 已经通过某种程度的 **范围缩减 (range reduction)** 处理后被调用的。

从代码中的注释和常量可以看出，它使用了**多项式逼近**的方法来计算正切值。这种方法在数学库中非常常见，用于在特定范围内高效且精确地计算超越函数。

具体功能细分：

1. **针对小范围输入:**  `Domain [-0.67434, 0.67434]` 表明此函数被设计为处理已经过范围缩减的输入。这意味着调用者（通常是 `tanl` 函数本身）会先将任意角度缩减到这个范围内，再调用 `__kernel_tanl` 进行计算。
2. **多项式逼近:**  `T3` 到 `T57` 这些常量是多项式逼近的系数。代码使用霍纳 (Horner) 算法或其他类似的方法，根据这些系数计算多项式的值，以此来逼近 `tan(x) / x` 的值。
3. **高精度计算:**  针对 `long double` 类型，保证了计算结果的精度。
4. **处理 `y` 和 `iy` 参数:** 除了 `x`，函数还接收 `y` 和 `iy` 两个参数。
    * `y`:  很可能是在范围缩减过程中产生的“低位”或“余项”，用于进一步提高精度。当原始的 `x` 被缩减时，可能会分离出一个主要部分和一个小的余项，`y` 就可能代表这个余项。
    * `iy`:  一个整数标志，从注释 `/* XXX recover original interface */` 可以看出，这可能是为了兼容或者适配原始接口而保留的。在代码中，`iy = (iy == 1 ? -1 : 1);` 将其值在 -1 和 1 之间切换，并在后面的条件判断中使用，这可能与处理不同的象限或三角恒等变换有关。
5. **可选的三角恒等变换:**  `if (fabsl(x) >= 0.67434)` 这段代码表明，即使输入在 [-0.67434, 0.67434] 范围内，对于接近边界的值，它也可能使用三角恒等式 `tan(pi/4 - x)` 来计算，这有助于提高精度或避免在特定角度附近出现数值问题。

**与 Android 功能的关系及举例:**

`__kernel_tanl` 是 Android 系统库 `libm` 的一部分。`libm` 提供了各种数学函数，供 Android 应用程序和系统组件使用。

**举例说明:**

* **游戏开发:**  一个使用 NDK 开发的 3D 游戏，在计算角色或物体的旋转角度时，可能会用到 `tanl` 函数进行精确计算。`tanl` 内部会调用 `__kernel_tanl` 来完成核心计算。
* **科学计算 App:**  一个进行复杂数学运算的 Android 应用，如果需要高精度的正切值，会使用 `tanl`，进而调用 `__kernel_tanl`。
* **图形图像处理:**  一些图像处理算法可能涉及到角度计算，也会间接使用到 `tanl`。

**详细解释 `libc` 函数 (`__kernel_tanl`) 的实现:**

1. **参数处理:**
   - `iy` 的值被转换为 -1 或 1。
   - `osign` 记录了 `x` 的符号，这在某些情况下可能需要用到。
   - 如果 `x` 的绝对值大于等于 0.67434，则进行三角恒等变换：
     - 如果 `x` 是负数，则取其相反数，`y` 也取相反数。
     - 计算 `z = pio4 - x` 和 `w = pio4lo - y`，其中 `pio4` 和 `pio4lo` 分别是 π/4 的高位和低位部分。
     - 更新 `x` 和 `y` 的值，并设置标志 `i = 1`，表示进行了变换。

2. **多项式计算:**
   - 计算 `z = x * x` 和 `w = z * z`，用于优化多项式计算。
   - 使用霍纳算法或其他嵌套乘法的方式，根据预定义的系数 `T5` 到 `T57` 计算两个多项式 `r` 和 `v`。这两个多项式是对 `tan(x)/x` 的不同部分的逼近。
   - 计算 `s = z * x`。
   - 更新 `r` 的值，将 `y` 和多项式计算结果结合起来。
   - 加上 `T3 * s`，完成主要的逼近。
   - 计算 `w = x + r`，这是 `tan(x)` 的一个初步结果。

3. **根据 `i` 和 `iy` 返回结果:**
   - 如果 `i == 1` (进行了三角恒等变换)：
     - 根据 `iy` 的值，使用公式 `osign * (v - 2.0 * (x - (w * w / (w + v) - r)))` 计算并返回结果。这里的 `v` 是 `iy` 转换后的值 (-1 或 1)。这个公式是根据 `tan(pi/4 - x)` 的展开得到的。
   - 如果 `i == 0` (未进行三角恒等变换)：
     - 如果 `iy == 1`，则直接返回 `w`。
     - 如果 `iy != 1`，则需要计算 `-1.0 / (x + r)`，这里为了保证精度，使用了更复杂的计算方式，避免直接除法可能带来的精度损失。

**Dynamic Linker 的功能：SO 布局样本和符号处理**

虽然 `k_tanl.c` 本身是 C 代码，不直接涉及动态链接器的操作，但它编译后会成为共享库 (`.so`) 的一部分。

**SO 布局样本 (`libm.so` 的部分布局):**

```
ELF Header
...
Program Headers
...
Section Headers:
  [Nr] Name              Type            Address          Offset
       Size              EntSize          Flags  Link  Info  Align
  ...
  [ .text ]          PROGBITS        0xXXXXXXXXXXXX     0xYYYYYYYY
       0xZZZZZZZZ       0x00             AX       0     0     16
  [ .rodata ]        PROGBITS        0xAAAAAAAAAAAA     0xBBBBBBBB
       0xCCCCCCCC       0x00             A        0     0     8
  [ .data ]          PROGBITS        0xDDDDDDDDDDDD     0xEEEEEEEE
       0xFFFFFFFF       0x00             WA       0     0     8
  [ .bss ]           NOBITS          0x111111111111     0x22222222
       0x33333333       0x00             WA       0     0     32
  [ .symtab ]        SYMTAB          0x444444444444     0x55555555
       0x66666666       0x18             S        27    108   8
  [ .strtab ]        STRTAB          0x777777777777     0x88888888
       0x99999999       0x00             S        0     0     1
  [ .dynsym ]        DYNSYM          0xABCDEFGHIJKL     0xMNOPQRST
       0xUVWXYZ01       0x18             A        28    1     8
  [ .dynstr ]        DYNSTR          0x234567890ABC     0xDEF01234
       0x567890DE       0x00             A        0     0     1
  [ .rel.dyn ]       REL             0xFEDCBA987654     0x3210FEDC
       0xBA987654       0x08             A        27    .dynsym 8
  [ .rel.plt ]       REL             0x9876543210FE     0xDCBA9876
       0x543210FE       0x08             AP       27    .plt    8
  [ .plt ]           PROGBITS        0x1029384756FE     0xCDEFAB90
       0x78901234       0x10             AX       0     0     16
  ...
```

**每种符号的处理过程:**

1. **`.text` 段:**  `__kernel_tanl` 函数的机器码指令会放在 `.text` (代码段) 中。动态链接器会将这个段加载到内存中可执行的位置。
2. **`.rodata` 段:**  像 `T3`, `T5`, `pio4`, `pio4lo` 这样的常量会放在 `.rodata` (只读数据段) 中。动态链接器会将这个段加载到内存中只读的位置。
3. **`.symtab` 和 `.strtab`:**  `.symtab` (符号表) 包含了库中定义的各种符号的信息，例如函数名、变量名、地址等。`.strtab` (字符串表) 存储了这些符号的名字字符串。`__kernel_tanl` 的符号信息会在这里。
4. **`.dynsym` 和 `.dynstr`:**  `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表) 类似于 `.symtab` 和 `.strtab`，但它们主要用于动态链接。当一个程序或库依赖于 `libm.so` 时，动态链接器会使用这些表来解析和重定位外部符号的引用。如果 `__kernel_tanl` 是一个供库内部使用的符号，它可能不会出现在 `.dynsym` 中，或者可能具有隐藏的可见性。通常，像 `tanl` 这样的公共函数才会在 `.dynsym` 中。
5. **`.rel.dyn` 和 `.rel.plt`:**  这些是重定位表。由于代码和数据在不同的加载地址可能会变化 (地址空间布局随机化 ASLR)，动态链接器需要修改代码中对外部符号或全局数据的引用。
    - `.rel.dyn` 用于重定位数据段中的引用。
    - `.rel.plt` (Procedure Linkage Table) 用于延迟绑定函数调用。当程序第一次调用 `tanl` 时，PLT 中的代码会调用动态链接器来解析 `tanl` 的实际地址，并更新 PLT 表项。

**对于 `__kernel_tanl` 这样的内部函数：**

- 它很可能只在 `libm.so` 内部被调用，因此可能不会作为导出的动态符号出现在 `.dynsym` 中。
- 它的符号信息会出现在 `.symtab` 中，方便库内部的链接和调试。

**逻辑推理：假设输入与输出**

**假设输入:** `x = 0.1`, `y = 0.0`, `iy = 1`

**推理过程:**

1. `fabsl(0.1) < 0.67434`，所以不会进入三角恒等变换的分支。
2. `i` 保持为 0。
3. 计算 `z = 0.1 * 0.1 = 0.01`。
4. 计算 `w = z * z = 0.0001`。
5. 根据多项式系数 `T5` 到 `T57` 计算 `r` 和 `v`。由于 `z` 和 `w` 很小，高阶项的贡献会很小。`r` 大致会是 `z * T7` 加上更高阶的项。`v` 大致会是 `z * T7` 加上更高阶的项。
6. 计算 `s = z * x = 0.001`。
7. 更新 `r` 的值。
8. 加上 `T3 * s`。
9. 计算 `w = x + r = 0.1 + r`。由于 `r` 很小，`w` 会非常接近 0.1。
10. 因为 `i == 0` 且 `iy == 1`，函数返回 `w`。

**预期输出:**  一个非常接近 `tan(0.1)` 的 `long double` 值，大约为 `0.10033467208545070943`。

**涉及用户或编程常见的使用错误:**

由于 `__kernel_tanl` 是一个内部函数，用户通常不会直接调用它。常见错误会发生在调用更高级的 `tanl` 函数时：

1. **输入参数超出范围:**  如果传递给 `tanl` 的角度接近 `π/2 + kπ`（奇数倍的 π/2），正切值会趋于无穷大，可能导致溢出或得到 `inf` 或 `NaN` 的结果。
   ```c
   #include <cmath>
   #include <iostream>
   #include <limits>

   int main() {
       long double x = std::numbers::pi_v<long double> / 2.0L;
       long double result = std::tanl(x);
       std::cout << "tan(" << x << ") = " << result << std::endl; // 输出 inf 或类似值
       return 0;
   }
   ```

2. **精度误解:**  用户可能错误地认为 `long double` 可以提供无限的精度。虽然 `long double` 比 `double` 提供更高的精度，但仍然是有限的。对于非常需要高精度的计算，可能需要使用任意精度算术库。

3. **忽略特殊值:**  没有正确处理 `tanl` 返回的特殊值，例如 `NaN`（Not a Number）。如果输入是 `NaN`，`tanl` 会返回 `NaN`，如果不做检查，可能会导致后续计算出错。

**Android Framework 或 NDK 如何一步步到达这里（调试线索）:**

1. **NDK 代码调用 `tanl`:**  开发者在 NDK (Native Development Kit) 代码中使用 `<cmath>` 头文件中的 `tanl` 函数。
   ```c++
   #include <cmath>
   long double angle = ...;
   long double tangent = std::tanl(angle);
   ```

2. **链接到 `libm.so`:**  编译 NDK 代码时，链接器会将代码与 Android 系统库 `libm.so` 链接起来。`libm.so` 包含了 `tanl` 的实现。

3. **动态链接器加载 `libm.so`:**  当 Android 应用启动时，动态链接器 (`linker64` 或 `linker`) 会加载所有依赖的共享库，包括 `libm.so`。

4. **`tanl` 函数被调用:**  当 NDK 代码执行到调用 `std::tanl(angle)` 时，实际上会跳转到 `libm.so` 中 `tanl` 函数的实现。

5. **`tanl` 内部实现:**  `libm.so` 中 `tanl` 的实现可能会包含以下步骤：
   - **参数检查和特殊值处理:** 检查输入是否为 `NaN`、无穷大等特殊值。
   - **范围缩减 (Range Reduction):** 如果输入角度较大，`tanl` 会使用三角恒等式将其缩减到一个较小的范围内，例如 `[-π/4, π/4]` 或 `[0, π/4]`。这一步可能会产生 `__rem_pio2l` 或类似的函数调用来计算 `x mod (pi/2)`。
   - **调用 `__kernel_tanl`:**  对于缩减后的输入，`tanl` 会调用 `__kernel_tanl` 来进行基于多项式逼近的核心计算。可能会根据范围缩减的结果传递适当的 `y` 和 `iy` 参数。
   - **结果处理:**  `tanl` 可能会对 `__kernel_tanl` 的结果进行进一步处理，例如根据原始角度的象限调整符号。

**调试线索:**

- **使用 `adb shell` 和 `gdbserver` 或 `lldb`:**  可以在 Android 设备上运行 `gdbserver` 或 `lldb-server`，然后从主机连接进行调试。可以设置断点在 `tanl` 函数内部，逐步跟踪其执行流程，查看何时以及如何调用 `__kernel_tanl`。
- **查看 `libm.so` 的符号表:**  使用 `readelf -s /system/lib64/libm.so` (或 `/system/lib/libm.so` for 32-bit) 可以查看 `libm.so` 中定义的符号，包括 `tanl` 和 `__kernel_tanl` 的地址。
- **反汇编 `libm.so`:**  使用 `objdump -d /system/lib64/libm.so` 可以反汇编 `libm.so` 的代码段，查看 `tanl` 和 `__kernel_tanl` 的具体实现。
- **使用 `strace`:**  可以使用 `strace` 命令跟踪应用的系统调用，虽然不太可能直接看到 `libm` 内部的函数调用，但可以观察到与动态链接和加载库相关的操作。

通过这些方法，开发者可以深入了解 `tanl` 的调用链，确认 `__kernel_tanl` 是否被调用，以及输入参数的值，从而诊断与数学函数相关的精度或逻辑问题。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/ld128/k_tanl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * ====================================================
 * Copyright 2004 Sun Microsystems, Inc.  All Rights Reserved.
 * Copyright (c) 2008 Steven G. Kargl, David Schultz, Bruce D. Evans.
 *
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */

/*
 * ld128 version of k_tan.c.  See ../src/k_tan.c for most comments.
 */

#include "math.h"
#include "math_private.h"

/*
 * Domain [-0.67434, 0.67434], range ~[-3.37e-36, 1.982e-37]
 * |tan(x)/x - t(x)| < 2**-117.8 (XXX should be ~1e-37)
 *
 * See ../ld80/k_cosl.c for more details about the polynomial.
 */
static const long double
T3 = 0x1.5555555555555555555555555553p-2L,
T5 = 0x1.1111111111111111111111111eb5p-3L,
T7 = 0x1.ba1ba1ba1ba1ba1ba1ba1b694cd6p-5L,
T9 = 0x1.664f4882c10f9f32d6bbe09d8bcdp-6L,
T11 = 0x1.226e355e6c23c8f5b4f5762322eep-7L,
T13 = 0x1.d6d3d0e157ddfb5fed8e84e27b37p-9L,
T15 = 0x1.7da36452b75e2b5fce9ee7c2c92ep-10L,
T17 = 0x1.355824803674477dfcf726649efep-11L,
T19 = 0x1.f57d7734d1656e0aceb716f614c2p-13L,
T21 = 0x1.967e18afcb180ed942dfdc518d6cp-14L,
T23 = 0x1.497d8eea21e95bc7e2aa79b9f2cdp-15L,
T25 = 0x1.0b132d39f055c81be49eff7afd50p-16L,
T27 = 0x1.b0f72d33eff7bfa2fbc1059d90b6p-18L,
T29 = 0x1.5ef2daf21d1113df38d0fbc00267p-19L,
T31 = 0x1.1c77d6eac0234988cdaa04c96626p-20L,
T33 = 0x1.cd2a5a292b180e0bdd701057dfe3p-22L,
T35 = 0x1.75c7357d0298c01a31d0a6f7d518p-23L,
T37 = 0x1.2f3190f4718a9a520f98f50081fcp-24L,
pio4 = 0x1.921fb54442d18469898cc51701b8p-1L,
pio4lo = 0x1.cd129024e088a67cc74020bbea60p-116L;

static const double
T39 =  0.000000028443389121318352,	/*  0x1e8a7592977938.0p-78 */
T41 =  0.000000011981013102001973,	/*  0x19baa1b1223219.0p-79 */
T43 =  0.0000000038303578044958070,	/*  0x107385dfb24529.0p-80 */
T45 =  0.0000000034664378216909893,	/*  0x1dc6c702a05262.0p-81 */
T47 = -0.0000000015090641701997785,	/* -0x19ecef3569ebb6.0p-82 */
T49 =  0.0000000029449552300483952,	/*  0x194c0668da786a.0p-81 */
T51 = -0.0000000022006995706097711,	/* -0x12e763b8845268.0p-81 */
T53 =  0.0000000015468200913196612,	/*  0x1a92fc98c29554.0p-82 */
T55 = -0.00000000061311613386849674,	/* -0x151106cbc779a9.0p-83 */
T57 =  1.4912469681508012e-10;		/*  0x147edbdba6f43a.0p-85 */

long double
__kernel_tanl(long double x, long double y, int iy) {
	long double z, r, v, w, s;
	long double osign;
	int i;

	iy = (iy == 1 ? -1 : 1);	/* XXX recover original interface */
	osign = (x >= 0 ? 1.0 : -1.0);	/* XXX slow, probably wrong for -0 */
	if (fabsl(x) >= 0.67434) {
		if (x < 0) {
			x = -x;
			y = -y;
		}
		z = pio4 - x;
		w = pio4lo - y;
		x = z + w;
		y = 0.0;
		i = 1;
	} else
		i = 0;
	z = x * x;
	w = z * z;
	r = T5 + w * (T9 + w * (T13 + w * (T17 + w * (T21 +
	    w * (T25 + w * (T29 + w * (T33 +
	    w * (T37 + w * (T41 + w * (T45 + w * (T49 + w * (T53 +
	    w * T57))))))))))));
	v = z * (T7 + w * (T11 + w * (T15 + w * (T19 + w * (T23 +
	    w * (T27 + w * (T31 + w * (T35 +
	    w * (T39 + w * (T43 + w * (T47 + w * (T51 + w * T55))))))))))));
	s = z * x;
	r = y + z * (s * (r + v) + y);
	r += T3 * s;
	w = x + r;
	if (i == 1) {
		v = (long double) iy;
		return osign *
			(v - 2.0 * (x - (w * w / (w + v) - r)));
	}
	if (iy == 1)
		return w;
	else {
		/*
		 * if allow error up to 2 ulp, simply return
		 * -1.0 / (x+r) here
		 */
		/* compute -1.0 / (x+r) accurately */
		long double a, t;
		z = w;
		z = z + 0x1p32 - 0x1p32;
		v = r - (z - x);	/* z+v = r+x */
		t = a = -1.0 / w;	/* a = -1.0/w */
		t = t + 0x1p32 - 0x1p32;
		s = 1.0 + t * z;
		return t + a * (s + t * v);
	}
}
```
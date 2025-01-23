Response:
Let's break down the thought process for analyzing the `e_atan2.c` code.

**1. Understanding the Request:**

The request asks for a detailed explanation of the `atan2` function in Android's Bionic library. Key aspects to cover include:

* **Functionality:** What does `atan2` do?
* **Android Relevance:** How does it relate to the Android ecosystem?
* **Implementation Details:**  A deep dive into the code.
* **Dynamic Linking:** If applicable, how does dynamic linking work here?
* **Logic and Examples:**  Hypothetical inputs and outputs.
* **Common Errors:** How might developers misuse this function?
* **Tracing:** How to find this code in Android and debug it.

**2. Initial Code Analysis (Skimming and Key Observations):**

* **Copyright:**  It's from Sun Microsystems, indicating it's based on a well-established implementation.
* **Function Signature:** `double atan2(double y, double x)` - Takes two doubles and returns a double. Immediately suggests it calculates the angle in radians.
* **Method Comment:** Mentions reducing `y` and `x` to positive, using `arctan(y/x)` and `pi - arctan[y/(-x)]`. This reveals the core logic of handling different quadrants.
* **Special Cases:**  A long list of special cases for NaN, zero, infinity. This is crucial for robust mathematical functions.
* **Constants:** Definitions for `tiny`, `zero`, `pi_o_4`, `pi_o_2`, `pi`, `pi_lo`. These are used for precision and special case handling.
* **Includes:** `<float.h>`, `"math.h"`, `"math_private.h"`. Standard math stuff and Bionic-specific private headers.
* **EXTRACT_WORDS Macro:**  This is a strong indicator of low-level manipulation of the double-precision floating-point representation.
* **`__weak_reference`:**  Suggests a long double version might exist and this is a weak symbol.

**3. Detailed Code Walkthrough (Step-by-Step):**

* **Extracting Words:**  `EXTRACT_WORDS(hx,lx,x)` and `EXTRACT_WORDS(hy,ly,y)` are the first key steps. Recognize this as accessing the high and low 32-bit words of the 64-bit double. This is often done for efficient bitwise operations and handling special floating-point values.
* **NaN Check:** The complex `if` condition with bitwise operations checks for NaN. Deconstruct it: `(lx|-lx)>>31` is a trick to check if `lx` is zero. If `lx` is not zero, the result is 0; if `lx` is zero, the result is -1 (all ones in binary). The `|` and comparisons with `0x7ff00000` (the exponent part for infinity/NaN) confirm this.
* **x == 1.0 Optimization:** A specific check for `x == 1.0` allowing direct use of `atan(y)`. This is an optimization.
* **Quadrant Determination:** `m = ((hy>>31)&1)|((hx>>30)&2);` This cleverly encodes the quadrant based on the signs of `x` and `y`.
* **Handling y = 0:** Special cases for when `y` is zero, returning 0, pi, or -pi based on the sign of `x`.
* **Handling x = 0:** Special cases for when `x` is zero, returning +/- pi/2 based on the sign of `y`.
* **Handling x = INF:** Special cases for when `x` is infinity, considering the sign of `y` and returning +/- pi/4, +/- 3pi/4, or +/- 0/pi.
* **Handling y = INF:** Special cases for when `y` is infinity, returning +/- pi/2.
* **Calculating y/x:**  The code handles potential overflow/underflow by checking the difference in exponents (`k`). If `|y/x|` is very large or very small, it uses approximations or returns 0 directly. Otherwise, it calculates `atan(fabs(y/x))`.
* **Applying Quadrant Correction:** The `switch (m)` statement applies the correct adjustment based on the quadrant, adding or subtracting pi or using the calculated `z`.

**4. Addressing Specific Request Points:**

* **Functionality:** Clearly state the purpose of `atan2(y, x)`.
* **Android Relevance:** Think about where angles are used in Android (graphics, sensors, animations, etc.).
* **Libc Functions:**  Focus on `atan`, `nan_mix`, and how they are likely implemented (though detailed internal implementations might be in other files).
* **Dynamic Linker:** Consider if `atan2` directly uses dynamic linking features. In this case, it's more about *being part of* a dynamically linked library. The example SO layout is generic. Explain the linking process conceptually.
* **Logic and Examples:**  Create concrete input/output examples for different quadrants and special cases.
* **User Errors:** Think about common mistakes like incorrect argument order.
* **Android Framework/NDK:** Trace how a high-level function might eventually call `atan2` (e.g., through OpenGL or sensor APIs).
* **Frida Hook:** Provide a simple Frida script to demonstrate how to intercept calls to `atan2`.

**5. Structuring the Response:**

Organize the information logically with clear headings and bullet points. Use code blocks for code snippets. Explain technical terms. Be precise and avoid ambiguity.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the bit manipulation. **Correction:** While important, balance it with the higher-level mathematical concepts.
* **Initial thought:**  Try to guess the exact implementation of `atan`. **Correction:**  Acknowledge it's likely another function but avoid going into unnecessary detail without the source.
* **Initial thought:**  Overcomplicate the dynamic linking explanation. **Correction:** Keep it concise and focused on the core concepts.
* **Initial thought:**  Forget to mention the `__weak_reference`. **Correction:**  Add this in as it's a relevant detail about symbol visibility.

By following this structured approach, combining code analysis with an understanding of the request's requirements, and incorporating self-correction, we can generate a comprehensive and accurate explanation of the `e_atan2.c` code.
好的，我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/e_atan2.c` 这个文件。

**功能列举:**

`e_atan2.c` 文件实现了 `atan2(y, x)` 函数，这个函数的功能是计算坐标 `(x, y)` 对应的反正切值，返回的角度以弧度表示。 与 `atan(y/x)` 不同，`atan2` 函数考虑了 `x` 的符号，能够确定角度所在的象限，因此返回值范围是 `[-π, π]`。

更具体地说，`atan2(y, x)` 的功能可以概括为：

1. **计算极坐标角度:** 将笛卡尔坐标 `(x, y)` 转换为极坐标 `(r, θ)`，其中 `θ` 就是 `atan2(y, x)` 的返回值。
2. **确定象限:**  根据 `x` 和 `y` 的符号，准确判断角度所在的象限，从而返回正确的角度值。
3. **处理特殊情况:**  针对 `x` 或 `y` 为 0、无穷大 (INF)、非数字 (NaN) 等特殊情况，返回预定义的值或 NaN。

**与 Android 功能的关系及举例说明:**

`atan2` 函数是基础的数学函数，在 Android 系统的许多方面都有应用：

1. **图形渲染 (Graphics Rendering):**
   - 在 OpenGL ES 或 Vulkan 等图形 API 中，计算向量之间的角度、旋转变换等会用到 `atan2`。
   - 例如，在计算两个 2D 点构成的向量与 X 轴的夹角时，可以使用 `atan2(y2 - y1, x2 - x1)`。

2. **传感器 (Sensors):**
   - 在处理来自加速度计、陀螺仪、磁力计等传感器的数据时，可能需要计算设备在空间中的朝向和角度，`atan2` 可以用于将传感器的输出值转换为角度信息。
   - 例如，根据磁力计和加速度计的数据计算设备的方位角 (azimuth)。

3. **动画 (Animations):**
   - 在创建动画效果时，可能需要根据目标位置计算运动的方向和角度，`atan2` 可以用于确定物体应该朝哪个方向移动或旋转。

4. **定位与地图 (Location and Maps):**
   - 在地图应用中，计算两个地理坐标之间的方位角时，会使用到 `atan2`。

**libc 函数功能实现详解:**

现在我们来详细解释 `e_atan2.c` 中 `atan2` 函数的实现逻辑：

1. **包含头文件:**
   - `#include <float.h>`: 提供了浮点数相关的常量，如 `LDBL_MANT_DIG` (长双精度浮点数的尾数位数)。
   - `#include "math.h"`: 包含了标准数学函数的声明，例如 `atan`。
   - `#include "math_private.h"`:  包含了 Bionic 内部使用的数学函数和宏定义，例如 `EXTRACT_WORDS` 和 `nan_mix`。

2. **定义静态变量:**
   - `tiny = 1.0e-300;`: 一个很小的正数，用于处理某些边界情况，避免正好等于 pi 的情况。
   - `zero = 0.0;`: 零值。
   - `pi_o_4`, `pi_o_2`, `pi`: 圆周率的四分之一、二分之一和完整值，预先计算好的常量，提高效率。
   - `pi_lo`:  `pi` 的低位部分，用于提高计算精度。

3. **`atan2(double y, double x)` 函数主体:**
   - **变量声明:**
     - `z`: 用于存储中间计算结果。
     - `k`, `m`, `hx`, `hy`, `ix`, `iy`: 整型变量，用于存储浮点数的符号位和指数部分。
     - `lx`, `ly`: 无符号整型变量，用于存储浮点数的低位部分。

   - **提取浮点数的组成部分:**
     - `EXTRACT_WORDS(hx, lx, x);`: 这是一个宏，用于将双精度浮点数 `x` 的高 32 位存储到 `hx`，低 32 位存储到 `lx`。
     - `ix = hx & 0x7fffffff;`:  提取 `x` 的指数和尾数部分，清除符号位。
     - 类似地，提取 `y` 的组成部分。

   - **处理 NaN:**
     - `if (((ix | ((lx - lx) >> 31)) > 0x7ff00000) || ((iy | ((ly - ly) >> 31)) > 0x7ff00000))`:  这段代码检查 `x` 或 `y` 是否为 NaN。`((lx - lx) >> 31)`  是一种巧妙的方式来判断 `lx` 是否为零。如果 `lx` 为零，结果为 -1（所有位都是 1）；否则为 0。与 `ix` 或 `iy` 进行或运算后，如果结果大于 `0x7ff00000` (表示指数部分全部为 1，且尾数不为零)，则说明是 NaN。
     - `return nan_mix(x, y);`: 如果 `x` 或 `y` 是 NaN，则返回 NaN。`nan_mix` 函数可能用于混合两个 NaN 的位模式（虽然结果仍然是 NaN）。

   - **优化：当 x = 1.0 时:**
     - `if (hx == 0x3ff00000 && lx == 0) return atan(y);`: 如果 `x` 等于 1.0，则 `atan2(y, 1.0)` 等价于 `atan(y)`，直接调用 `atan` 函数可以提高效率。

   - **确定象限:**
     - `m = ((hy >> 31) & 1) | ((hx >> 30) & 2);`:  根据 `x` 和 `y` 的符号位确定象限。
       - `(hy >> 31) & 1`:  `y` 的符号位 (0 表示正，1 表示负)。
       - `(hx >> 30) & 2`:  `x` 的符号位 (如果 `hx` 的第 31 位是 0，则 `x` 为正，结果为 0；如果 `hx` 的第 31 位是 1，则 `x` 为负，右移一位后第 30 位为 1，与 2 进行与运算结果为 2)。
       - `m` 的取值：
         - 0: `y >= 0`, `x > 0` (第一象限)
         - 1: `y < 0`, `x > 0` (第四象限)
         - 2: `y >= 0`, `x < 0` (第二象限)
         - 3: `y < 0`, `x < 0` (第三象限)

   - **处理 y = 0 的情况:**
     - `if ((iy | ly) == 0)`: 检查 `y` 是否为正零或负零。
     - 根据 `m` 的值返回相应的角度：
       - `case 0, 1`: `atan(+-0, +anything) = +-0`
       - `case 2`: `atan(+0, -anything) = pi`
       - `case 3`: `atan(-0, -anything) = -pi`

   - **处理 x = 0 的情况:**
     - `if ((ix | lx) == 0) return (hy < 0) ? -pi_o_2 - tiny : pi_o_2 + tiny;`: 检查 `x` 是否为正零或负零。返回 `+/- pi/2`，加上 `tiny` 是为了避免正好等于 `pi/2`。

   - **处理 x 为无穷大的情况:**
     - `if (ix == 0x7ff00000)`: 检查 `x` 是否为正无穷或负无穷。
     - 进一步判断 `y` 是否为无穷大，根据 `m` 的值返回相应的角度 (`+/- pi/4` 或 `+/- 3pi/4`)。
     - 如果 `y` 不是无穷大，则根据 `m` 的值返回 `0` 或 `+/- pi`。

   - **处理 y 为无穷大的情况:**
     - `if (iy == 0x7ff00000) return (hy < 0) ? -pi_o_2 - tiny : pi_o_2 + tiny;`: 检查 `y` 是否为正无穷或负无穷。返回 `+/- pi/2`。

   - **计算 y/x 并调用 atan:**
     - `k = (iy - ix) >> 20;`: 计算 `y` 和 `x` 的指数部分的差值，用于判断 `|y/x|` 的大小。
     - `if (k > 60)`: 如果 `|y/x| > 2^60`，则 `atan2` 的值接近 `+/- pi/2`。使用近似值 `pi_o_2 + 0.5 * pi_lo`。
     - `else if (hx < 0 && k < -60)`: 如果 `x` 是负数且 `0 > |y|/x > -2^-60`，则 `atan2` 的值接近 0。
     - `else z = atan(fabs(y / x));`: 在安全范围内，计算 `|y/x|` 的反正切值。

   - **根据象限调整结果:**
     - `switch (m)`: 根据之前计算的象限值 `m`，调整 `atan(fabs(y/x))` 的结果，得到最终的 `atan2(y, x)` 值。
       - `case 0`: 第一象限，返回 `z`。
       - `case 1`: 第四象限，返回 `-z`。
       - `case 2`: 第二象限，返回 `pi - (z - pi_lo)`。使用 `pi_lo` 提高精度。
       - `default`: (case 3) 第三象限，返回 `(z - pi_lo) - pi`。

4. **`__weak_reference(atan2, atan2l);`:**
   - 这是一个宏，用于创建一个弱符号 `atan2l`，它引用了 `atan2` 函数。这通常用于提供 `long double` 版本的 `atan2` 函数，如果系统中存在 `atan2l` 的更精确实现，则会优先使用该实现；否则，会使用 `atan2` 的 `double` 版本。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程:**

`e_atan2.c` 本身不直接涉及 dynamic linker 的功能。它是 `libm.so` 库中的一个源文件。`libm.so` 是一个共享库，在程序运行时被动态链接器加载。

**so 布局样本:**

```
libm.so:
    ... (其他代码段) ...
    .text:  # 存放可执行代码
        ...
        atan2:  # atan2 函数的代码
            ...
        ...
    .rodata: # 存放只读数据，如常量
        ...
        pi_o_4: ...
        pi_o_2: ...
        pi:     ...
        ...
    .data:  # 存放已初始化的全局变量和静态变量
        ...
        tiny:   ...
        zero:   ...
        ...
    ... (其他段) ...
```

**链接处理过程:**

1. **编译:** `e_atan2.c` 被编译成目标文件 (`.o` 文件)。
2. **链接:** 目标文件被链接器 (如 `ld`) 与其他 `libm` 的目标文件一起链接成共享库 `libm.so`。链接器会处理符号引用，确保 `atan2` 函数的地址在库中是确定的。
3. **动态链接:** 当一个 Android 应用或 Native 代码调用 `atan2` 函数时：
   - **加载:** 动态链接器 (如 `linker64` 或 `linker`) 会在程序启动或首次调用 `libm.so` 中的函数时加载 `libm.so` 到内存中。
   - **符号解析:** 动态链接器会解析对 `atan2` 函数的引用，找到 `libm.so` 中 `atan2` 函数的实际地址。这通常通过查找符号表完成。
   - **重定位:** 如果需要，动态链接器会修改指令中的地址，使其指向 `atan2` 函数在内存中的实际位置。
   - **调用:** 程序执行时，当遇到 `atan2` 函数调用时，会跳转到动态链接器解析出的地址执行 `atan2` 函数的代码。

**逻辑推理、假设输入与输出:**

| 输入 y    | 输入 x    | 预期输出 (近似值) | 推理                                                                                                                               |
| --------- | --------- | --------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 1.0       | 0.0       | 1.5708 (π/2)    | x 为 0，y 为正，角度为 +π/2                                                                                                      |
| -1.0      | 0.0       | -1.5708 (-π/2)   | x 为 0，y 为负，角度为 -π/2                                                                                                      |
| 1.0       | 1.0       | 0.7854 (π/4)    | x 和 y 均为正，角度在第一象限，`atan(1/1) = atan(1) = π/4`                                                                         |
| 1.0       | -1.0      | 2.3562 (3π/4)   | x 为负，y 为正，角度在第二象限，`pi - atan(1/1) = pi - π/4 = 3π/4`                                                                |
| -1.0      | -1.0      | -2.3562 (-3π/4)  | x 和 y 均为负，角度在第三象限，`-pi + atan(1/1) = -pi + π/4 = -3π/4`                                                               |
| -1.0      | 1.0       | -0.7854 (-π/4)   | x 为正，y 为负，角度在第四象限，`atan(-1/1) = atan(-1) = -π/4`                                                                    |
| 0.0       | 1.0       | 0.0             | y 为 0，x 为正，角度为 0                                                                                                          |
| 0.0       | -1.0      | 3.1416 (π)      | y 为 0，x 为负，角度为 π                                                                                                          |
| Infinity  | 1.0       | 1.5708 (π/2)    | y 为正无穷，角度接近 +π/2                                                                                                        |
| -Infinity | 1.0       | -1.5708 (-π/2)   | y 为负无穷，角度接近 -π/2                                                                                                        |
| 1.0       | Infinity  | 0.0             | x 为正无穷，角度接近 0                                                                                                          |
| 1.0       | -Infinity | 3.1416 (π)      | x 为负无穷，角度接近 π                                                                                                          |
| Infinity  | Infinity  | 0.7854 (π/4)    | x 和 y 均为正无穷，角度接近 π/4                                                                                                  |
| -Infinity | -Infinity | -2.3562 (-3π/4)  | x 和 y 均为负无穷，角度接近 -3π/4                                                                                                 |
| NaN       | 1.0       | NaN             | 任意一个输入为 NaN，结果为 NaN                                                                                                     |
| 1.0       | NaN       | NaN             | 任意一个输入为 NaN，结果为 NaN                                                                                                     |

**用户或编程常见的使用错误:**

1. **参数顺序错误:**  容易将 `atan2(y, x)` 的参数顺序写反，写成 `atan2(x, y)`。这会导致计算出错误的角度。
   ```c
   double angle = atan2(x, y); // 错误！应该使用 atan2(y, x)
   ```
   正确的用法是 `atan2(y, x)`，其中 `y` 是 y 坐标，`x` 是 x 坐标。

2. **返回值单位理解错误:** `atan2` 返回的角度单位是弧度 (radians)，而不是角度 (degrees)。如果需要在角度制下使用，需要进行转换。
   ```c
   double radians = atan2(y, x);
   double degrees = radians * 180.0 / M_PI; // 将弧度转换为角度
   ```

3. **处理特殊值不当:**  没有充分考虑输入为 0、无穷大或 NaN 的情况，可能导致程序出现未预期的行为或错误。应该根据需求对这些特殊情况进行处理。

4. **精度问题:**  浮点数运算存在精度限制。在对精度要求很高的应用中，需要注意浮点数误差带来的影响。

**Android Framework 或 NDK 如何到达这里:**

从 Android Framework 或 NDK 到达 `e_atan2.c` 的路径通常是这样的：

1. **Android Framework (Java/Kotlin):**
   - 在 Framework 层，一些涉及到角度计算的 API 最终可能会调用到 Native 代码。例如，`android.graphics.PointF.atan2(PointF)` 方法在内部可能会调用到 Native 层的数学函数。
   - 假设你有一个 `android.graphics.PointF` 对象 `p1` 和 `p2`，你想计算 `p2 - p1` 向量与 X 轴的夹角：
     ```java
     float deltaY = p2.y - p1.y;
     float deltaX = p2.x - p1.x;
     double angleRadians = Math.atan2(deltaY, deltaX); // 这里会调用到 Native 的 atan2
     ```
   - `java.lang.Math.atan2(double a, double b)` 是一个 Native 方法，它的实现会委托给底层的 C/C++ 库，也就是 `libm.so` 中的 `atan2` 函数。

2. **Android NDK (C/C++):**
   - 在 NDK 代码中，可以直接调用标准 C 数学库的函数，包括 `atan2`。
   ```c++
   #include <cmath>

   double calculateAngle(double y, double x) {
       return std::atan2(y, x); // 这会调用 libm.so 中的 atan2
   }
   ```
   - 当 NDK 代码被编译和链接时，链接器会将对 `std::atan2` 或 `atan2` 的调用链接到 `libm.so` 中相应的函数实现。

**Frida Hook 示例作为调试线索:**

可以使用 Frida Hook 来拦截对 `atan2` 函数的调用，以便查看其输入参数和返回值，帮助调试。

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const atan2Ptr = Module.findExportByName("libm.so", "atan2");
    if (atan2Ptr) {
        Interceptor.attach(atan2Ptr, {
            onEnter: function (args) {
                const y = parseFloat(args[0]);
                const x = parseFloat(args[1]);
                console.log(`[atan2 Hook] y: ${y}, x: ${x}`);
            },
            onLeave: function (retval) {
                const result = parseFloat(retval);
                console.log(`[atan2 Hook] Result: ${result}`);
            }
        });
        console.log("atan2 hook installed!");
    } else {
        console.error("Failed to find atan2 in libm.so");
    }
} else {
    console.warn("Frida hook for atan2 is only applicable for ARM/ARM64 architectures.");
}
```

**解释 Frida Hook 代码:**

1. **检查架构:** `Process.arch === 'arm64' || Process.arch === 'arm'` 确保 Hook 只在 ARM 或 ARM64 架构上运行，因为 `libm.so` 的位置和名称可能因架构而异。
2. **查找导出函数:** `Module.findExportByName("libm.so", "atan2")` 尝试在 `libm.so` 库中找到名为 `atan2` 的导出函数的地址。
3. **附加拦截器:** `Interceptor.attach(atan2Ptr, { ... })` 将一个拦截器附加到 `atan2` 函数的入口和出口。
   - **`onEnter`:** 在 `atan2` 函数被调用之前执行。
     - `args[0]` 和 `args[1]` 分别是 `atan2` 函数的第一个和第二个参数（`y` 和 `x`），使用 `parseFloat` 将它们转换为浮点数。
     - 打印出 `y` 和 `x` 的值。
   - **`onLeave`:** 在 `atan2` 函数执行完毕并即将返回时执行。
     - `retval` 是 `atan2` 函数的返回值，使用 `parseFloat` 转换为浮点数。
     - 打印出返回值。
4. **安装状态:** 打印消息表明 Hook 是否成功安装。

通过运行这个 Frida 脚本，当任何 Android 代码调用 `atan2` 函数时，你将在 Frida 的控制台中看到 `atan2` 的输入参数和返回值，这对于理解代码行为和调试非常有用。

希望以上详细的解释能够帮助你理解 `e_atan2.c` 文件的功能和在 Android 系统中的应用。

### 提示词
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/e_atan2.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例作为调试线索。
用中文回复。
```

### 源代码
```c
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice 
 * is preserved.
 * ====================================================
 *
 */

/* atan2(y,x)
 * Method :
 *	1. Reduce y to positive by atan2(y,x)=-atan2(-y,x).
 *	2. Reduce x to positive by (if x and y are unexceptional): 
 *		ARG (x+iy) = arctan(y/x)   	   ... if x > 0,
 *		ARG (x+iy) = pi - arctan[y/(-x)]   ... if x < 0,
 *
 * Special cases:
 *
 *	ATAN2((anything), NaN ) is NaN;
 *	ATAN2(NAN , (anything) ) is NaN;
 *	ATAN2(+-0, +(anything but NaN)) is +-0  ;
 *	ATAN2(+-0, -(anything but NaN)) is +-pi ;
 *	ATAN2(+-(anything but 0 and NaN), 0) is +-pi/2;
 *	ATAN2(+-(anything but INF and NaN), +INF) is +-0 ;
 *	ATAN2(+-(anything but INF and NaN), -INF) is +-pi;
 *	ATAN2(+-INF,+INF ) is +-pi/4 ;
 *	ATAN2(+-INF,-INF ) is +-3pi/4;
 *	ATAN2(+-INF, (anything but,0,NaN, and INF)) is +-pi/2;
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following 
 * constants. The decimal values may be used, provided that the 
 * compiler will convert from decimal to binary accurately enough 
 * to produce the hexadecimal values shown.
 */

#include <float.h>

#include "math.h"
#include "math_private.h"

static volatile double
tiny  = 1.0e-300;
static const double
zero  = 0.0,
pi_o_4  = 7.8539816339744827900E-01, /* 0x3FE921FB, 0x54442D18 */
pi_o_2  = 1.5707963267948965580E+00, /* 0x3FF921FB, 0x54442D18 */
pi      = 3.1415926535897931160E+00; /* 0x400921FB, 0x54442D18 */
static volatile double
pi_lo   = 1.2246467991473531772E-16; /* 0x3CA1A626, 0x33145C07 */

double
atan2(double y, double x)
{
	double z;
	int32_t k,m,hx,hy,ix,iy;
	u_int32_t lx,ly;

	EXTRACT_WORDS(hx,lx,x);
	ix = hx&0x7fffffff;
	EXTRACT_WORDS(hy,ly,y);
	iy = hy&0x7fffffff;
	if(((ix|((lx|-lx)>>31))>0x7ff00000)||
	   ((iy|((ly|-ly)>>31))>0x7ff00000))	/* x or y is NaN */
	    return nan_mix(x, y);
	if(hx==0x3ff00000&&lx==0) return atan(y);   /* x=1.0 */
	m = ((hy>>31)&1)|((hx>>30)&2);	/* 2*sign(x)+sign(y) */

    /* when y = 0 */
	if((iy|ly)==0) {
	    switch(m) {
		case 0: 
		case 1: return y; 	/* atan(+-0,+anything)=+-0 */
		case 2: return  pi+tiny;/* atan(+0,-anything) = pi */
		case 3: return -pi-tiny;/* atan(-0,-anything) =-pi */
	    }
	}
    /* when x = 0 */
	if((ix|lx)==0) return (hy<0)?  -pi_o_2-tiny: pi_o_2+tiny;
	    
    /* when x is INF */
	if(ix==0x7ff00000) {
	    if(iy==0x7ff00000) {
		switch(m) {
		    case 0: return  pi_o_4+tiny;/* atan(+INF,+INF) */
		    case 1: return -pi_o_4-tiny;/* atan(-INF,+INF) */
		    case 2: return  3.0*pi_o_4+tiny;/*atan(+INF,-INF)*/
		    case 3: return -3.0*pi_o_4-tiny;/*atan(-INF,-INF)*/
		}
	    } else {
		switch(m) {
		    case 0: return  zero  ;	/* atan(+...,+INF) */
		    case 1: return -zero  ;	/* atan(-...,+INF) */
		    case 2: return  pi+tiny  ;	/* atan(+...,-INF) */
		    case 3: return -pi-tiny  ;	/* atan(-...,-INF) */
		}
	    }
	}
    /* when y is INF */
	if(iy==0x7ff00000) return (hy<0)? -pi_o_2-tiny: pi_o_2+tiny;

    /* compute y/x */
	k = (iy-ix)>>20;
	if(k > 60) {		 	/* |y/x| >  2**60 */
	    z=pi_o_2+0.5*pi_lo;
	    m&=1;
	}
	else if(hx<0&&k<-60) z=0.0; 	/* 0 > |y|/x > -2**-60 */
	else z=atan(fabs(y/x));		/* safe to do y/x */
	switch (m) {
	    case 0: return       z  ;	/* atan(+,+) */
	    case 1: return      -z  ;	/* atan(-,+) */
	    case 2: return  pi-(z-pi_lo);/* atan(+,-) */
	    default: /* case 3 */
	    	    return  (z-pi_lo)-pi;/* atan(-,-) */
	}
}

#if LDBL_MANT_DIG == 53
__weak_reference(atan2, atan2l);
#endif
```
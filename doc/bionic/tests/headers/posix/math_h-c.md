Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to know about the `math_h.c` file in Android's Bionic library. Specifically, they want to know its purpose, its relationship to Android, details about the listed libc functions, dynamic linking aspects, common usage errors, and how it's accessed by Android framework/NDK, including a Frida hook example.

2. **Initial Analysis of the Code:** The provided C code is not a direct implementation of math functions. It's a *header check* file. The primary purpose is to ensure that the `math.h` header file defines the expected types, macros, and function declarations. The `#if !defined(...) #error ... #endif` structure is the giveaway. This is a compile-time assertion.

3. **Address the Core Functionality:**  The first and most important step is to clearly state that this file is a header test, not the implementation of math functions. This directly answers the "列举一下它的功能" part of the request.

4. **Explain the Android Relationship:**  Since this file verifies `math.h`, it's crucial for ensuring the correctness and consistency of the math library within Android. I need to explain how this contributes to the overall stability and functionality of the Android platform.

5. **Handle the libc Function Detail Request:** The user specifically asks about the implementation of each listed libc function. Since this file *doesn't* implement them, I need to explain *where* these functions are implemented (likely in assembly and other C files within Bionic) and provide a general description of their purpose based on standard math library documentation. Trying to provide a detailed implementation from this header check file is impossible and incorrect.

6. **Address Dynamic Linking:**  The prompt asks about dynamic linking. While this file itself doesn't directly involve dynamic linking, the `math.h` functions *are* part of the dynamically linked `libc.so`. Therefore, I need to explain the role of `libc.so`, provide a basic layout example, and describe the linking process.

7. **Handle Logical Reasoning and I/O:**  Because this is a header check, there's no real logical reasoning with input and output *during runtime*. However, the *compilation* process involves the preprocessor evaluating the `#if` conditions. I can frame the "input" as the `math.h` header file's content, and the "output" as either a successful compilation or a compilation error.

8. **Address Common Usage Errors:** Even though this is a test file, common mistakes developers make when *using* the functions declared in `math.h` are relevant. I should list some typical errors, such as passing incorrect types or forgetting to handle potential errors like NaN or infinity.

9. **Explain Android Framework/NDK Access:**  I need to trace the path from an Android application to these math functions. This involves explaining how the NDK provides access to C standard libraries, and how the framework itself might indirectly use these functions.

10. **Provide a Frida Hook Example:**  The user specifically requested a Frida hook. I should provide an example that demonstrates how to intercept a `math.h` function call. A simple example like hooking `sin()` is a good starting point.

11. **Structure and Language:**  The user requested a Chinese response. I need to ensure the language is natural and accurate. Using bullet points, headings, and clear explanations will improve readability. It's important to directly address each part of the user's request.

12. **Review and Refine:** After drafting the answer, I need to review it for accuracy, completeness, and clarity. I should ensure that I haven't misinterpreted the purpose of the `math_h.c` file and that the explanations are easy to understand.

By following these steps, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request, even when the initial assumption about the file's purpose is incorrect. The key is to correctly identify the file as a header check and then provide context around that understanding.
这是一个位于 `bionic/tests/headers/posix/` 目录下的名为 `math_h.c` 的 C 源代码文件，属于 Android Bionic 项目。Bionic 是 Android 的 C 库、数学库和动态链接器。

**它的主要功能是：**

这个 `math_h.c` 文件本身 **不是** 用于实现 `math.h` 中声明的数学函数。它的主要功能是作为一个 **测试文件**，用于 **验证** `bionic/libc/include/math.h` 头文件是否正确地定义了预期的宏、类型和函数声明。

具体来说，它通过一系列的 `#if !defined(...) #error ... #endif` 预处理指令来检查 `math.h` 中是否定义了特定的宏（如 `M_PI`、`INFINITY`）、类型（如 `float_t`、`double_t`）和声明了特定的函数（如 `sin`、`cos`）。 如果某个预期的定义或声明缺失，编译过程将会因为 `#error` 指令而失败，从而表明 `math.h` 文件存在问题。

**与 Android 功能的关系举例说明：**

`math.h` 中定义的数学函数是 Android 系统和应用程序开发的基础组成部分。Android 平台上的许多功能都依赖于这些数学运算，例如：

* **图形渲染：** 计算 3D 模型的变换、光照效果等需要大量的三角函数、指数函数等。Android 的图形库（如 OpenGL ES）底层就依赖于 `libm.so`（Bionic 的数学库）。
* **传感器数据处理：**  加速度计、陀螺仪等传感器的数据处理可能涉及到向量运算、角度计算等。
* **游戏开发：** 物理引擎、动画、碰撞检测等都离不开精确的数学计算。
* **音频处理：** 音频信号的分析、合成、滤波等需要傅里叶变换等复杂的数学运算。
* **科学计算类应用：**  这类应用直接使用 `math.h` 中的函数进行各种数值计算。

例如，一个简单的 Android 游戏可能需要计算两个游戏对象之间的距离，这会用到 `sqrt` 函数（求平方根），该函数在 `math.h` 中声明，并在 `libm.so` 中实现。

**详细解释每一个 libc 函数的功能是如何实现的：**

**这个 `math_h.c` 文件本身并不实现任何 `libc` 函数。**  它只是检查这些函数是否被声明了。

`math.h` 中声明的函数的实际实现位于 Bionic 的数学库 `libm.so` 中。 这些函数的实现通常是高度优化的，并且可能包含以下技术：

* **汇编语言优化：** 对于性能关键的函数（如 `sin`, `cos`, `sqrt`），通常会使用汇编语言编写，以便充分利用特定 CPU 架构的指令集。
* **查表法：** 对于一些函数，可以在一定精度范围内预先计算好结果并存储在表格中，通过查表来加速计算。
* **多项式逼近：** 使用多项式来逼近函数的值，例如泰勒级数展开。
* **迭代算法：** 使用迭代算法逐步逼近函数的精确值，例如牛顿迭代法用于求平方根。
* **特殊情况处理：**  需要处理各种特殊输入情况，例如 NaN (Not a Number)、无穷大、零等。

要了解具体函数的实现细节，需要查看 `bionic/libm/` 目录下的源代码文件（通常是 `.c` 或 `.S` 文件）。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`math.h` 中声明的函数最终链接到动态链接库 `libm.so` 中。当一个 Android 应用或系统服务需要使用这些函数时，动态链接器负责将 `libm.so` 加载到进程的地址空间，并将函数调用重定向到 `libm.so` 中对应的函数地址。

**`libm.so` 的 SO 布局样本：**

```
libm.so:
    .text          # 存放可执行代码
        sin:      # sin 函数的代码
            ...
        cos:      # cos 函数的代码
            ...
        sqrt:     # sqrt 函数的代码
            ...
        ...

    .rodata        # 存放只读数据 (例如数学常数)
        M_PI:     # π 的值
        ...

    .data          # 存放已初始化的全局变量

    .bss           # 存放未初始化的全局变量

    .dynsym        # 动态符号表 (包含导出的符号，如函数名)
        sin
        cos
        sqrt
        ...

    .dynstr        # 动态字符串表 (存放符号名称的字符串)
        "sin"
        "cos"
        "sqrt"
        ...

    .plt           # 程序链接表 (用于延迟绑定)
        sin@plt:
            jmp *sin@GOT(...)

    .got.plt      # 全局偏移表 (存放动态链接的函数地址)
        sin@GOT:
            0x... # 实际的 sin 函数地址 (在加载时由动态链接器填充)

    ...           # 其他段
```

**链接的处理过程：**

1. **编译时：** 当编译器遇到对 `math.h` 中声明的函数的调用时，它会生成一个指向该函数名的符号引用。
2. **链接时：** 静态链接器（在 NDK 构建过程中）或动态链接器（在 Android 运行时）会处理这些符号引用。对于动态链接，编译器会生成对 `.plt` 和 `.got.plt` 中条目的引用。
3. **加载时：** 当应用程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责加载所有必要的共享库，包括 `libm.so`。
4. **符号解析：** 动态链接器会遍历所有加载的共享库的动态符号表 (`.dynsym`)，找到与应用程序中未解析符号匹配的符号。
5. **重定位：** 动态链接器会将找到的函数地址写入到应用程序的全局偏移表 (`.got.plt`) 中对应的条目。
6. **首次调用（延迟绑定）：** 当程序首次调用 `sin` 函数时，会跳转到 `.plt` 中的 `sin@plt` 条目。该条目会先跳转到 `.got.plt` 中的 `sin@GOT`。由于 `sin@GOT` 尚未被填充实际地址，它会触发动态链接器进行符号解析和重定位。
7. **后续调用：**  一旦 `sin@GOT` 被填充了 `libm.so` 中 `sin` 函数的实际地址，后续对 `sin` 的调用将直接跳转到该地址，避免了重复的符号解析开销。

**如果做了逻辑推理，请给出假设输入与输出：**

由于 `math_h.c` 是一个测试文件，它本身不执行逻辑推理来处理输入并产生输出。 它的 "输入" 是 `math.h` 文件的内容，而 "输出" 是编译过程的成功或失败。

* **假设输入：** `bionic/libc/include/math.h` 文件中 **正确** 定义了 `sin` 函数的声明：
  ```c
  double sin(double x);
  ```
* **预期输出：**  `math_h.c` 能够成功编译，不会产生任何错误。

* **假设输入：** `bionic/libc/include/math.h` 文件中 **缺少** `sin` 函数的声明：
  ```c
  // 缺少 sin 函数的声明
  ```
* **预期输出：**  编译 `math_h.c` 时会因为 `#if !defined(sin) #error sin #endif` 而产生编译错误，提示 `sin` 未定义。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

尽管 `math_h.c` 是一个测试文件，但使用 `math.h` 中声明的函数时，常见的错误包括：

1. **类型不匹配：**  `math.h` 中存在针对 `float`、`double` 和 `long double` 的重载版本。如果传递的参数类型与函数期望的类型不匹配，可能会导致精度损失或编译错误（取决于是否发生隐式类型转换）。

   ```c
   float angle = 30.0f;
   double result = sin(angle); // 可能会有精度损失，建议使用 sinf(angle)
   ```

2. **忘记处理特殊值：** 数学函数可能返回特殊值，例如 `NaN`（Not a Number）或 `INFINITY`。  没有正确处理这些值可能导致程序行为异常。

   ```c
   double x = 0.0;
   double result = 1.0 / x; // result 将为 INFINITY
   if (isinf(result)) {
       // 处理无穷大的情况
   }
   ```

3. **误用角度单位：**  三角函数通常期望输入为弧度，而开发者可能使用角度。

   ```c
   double angle_degrees = 90.0;
   double angle_radians = angle_degrees * M_PI / 180.0;
   double result = sin(angle_radians); // 正确
   double wrong_result = sin(angle_degrees); // 错误
   ```

4. **浮点数比较的陷阱：** 直接使用 `==` 比较浮点数是否相等通常是不可靠的，因为浮点数运算存在精度误差。应该使用一个小的容差值进行比较。

   ```c
   double a = 0.1 + 0.2;
   double b = 0.3;
   if (fabs(a - b) < 1e-9) { // 使用容差值比较
       // 认为 a 和 b 相等
   }
   ```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `math.h` 的路径：**

1. **Java 代码调用 Framework API：** Android Framework 的 Java 代码（例如，在 `android.graphics` 包中的 Canvas 或 Matrix 类）可能会调用 Native 代码来实现某些功能，这些 Native 代码可能需要使用数学函数。

2. **JNI 调用 Native 代码：**  Java 代码通过 Java Native Interface (JNI) 调用 C/C++ 编写的 Native 代码。

3. **Native 代码使用 `math.h` 函数：**  Native 代码中包含了 `#include <math.h>`，并且调用了 `math.h` 中声明的函数。

4. **链接到 `libm.so`：**  在编译 Native 代码时，链接器会将 Native 库链接到 `libm.so`，这样在运行时就可以找到 `math.h` 函数的实现。

**NDK 到 `math.h` 的路径：**

1. **NDK 开发：**  开发者使用 NDK (Native Development Kit) 编写 C/C++ 代码，这些代码可以包含 `#include <math.h>` 并调用其中的函数。

2. **编译 NDK 代码：**  NDK 的构建系统 (通常基于 CMake 或 ndk-build) 会编译 C/C++ 代码，并将其链接到一个共享库 (`.so`)。

3. **链接到 `libm.so`：**  NDK 构建系统会自动将生成的共享库链接到 Android 系统的 `libm.so`。

4. **APK 打包和部署：**  编译后的共享库会被打包到 APK 文件中，并部署到 Android 设备上。

5. **运行时加载和链接：** 当应用程序运行时，Android 的动态链接器会加载应用程序的共享库以及 `libm.so`，并将函数调用连接起来。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `sin` 函数调用的示例：

```python
import frida
import sys

package_name = "your.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "sin"), {
    onEnter: function(args) {
        console.log("[+] Calling sin with argument: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[+] sin returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. **安装 Frida：**  确保你的开发机器上安装了 Frida 和 frida-tools。
2. **找到目标进程：**  将 `your.package.name` 替换为你想要调试的 Android 应用的包名。
3. **运行 Frida 脚本：**  运行上面的 Python 脚本。
4. **触发 `sin` 函数调用：**  在你的 Android 应用中执行某些操作，使其调用 `sin` 函数。
5. **查看 Frida 输出：**  Frida 会拦截对 `sin` 函数的调用，并在控制台上打印出函数的参数和返回值。

**调试步骤说明：**

* **`frida.get_usb_device().attach(package_name)`:**  连接到通过 USB 连接的 Android 设备上的目标应用进程。
* **`Module.findExportByName("libm.so", "sin")`:**  在 `libm.so` 库中查找导出的 `sin` 函数的地址。
* **`Interceptor.attach(...)`:**  在 `sin` 函数的入口和出口处设置拦截器。
* **`onEnter: function(args)`:**  在 `sin` 函数被调用时执行，`args` 数组包含了函数的参数。
* **`onLeave: function(retval)`:**  在 `sin` 函数返回时执行，`retval` 是函数的返回值。
* **`console.log(...)`:**  在 Frida 的上下文中打印日志信息。

通过这个 Frida Hook 示例，你可以观察到当 Android 应用或 Framework 调用 `sin` 函数时，拦截器会被触发，并可以查看函数的输入和输出，从而帮助你理解代码的执行流程和调试问题。

### 提示词
```
这是目录为bionic/tests/headers/posix/math_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <math.h>

#include "header_checks.h"

static void math_h() {
  TYPE(float_t);
  TYPE(double_t);

#if !defined(fpclassify)
#error fpclassify
#endif
#if !defined(isfinite)
#error isfinite
#endif
#if !defined(isgreater)
#error isgreater
#endif
#if !defined(isgreaterequal)
#error isgreaterequal
#endif
#if !defined(isinf)
#error isinf
#endif
#if !defined(isless)
#error isless
#endif
#if !defined(islessequal)
#error islessequal
#endif
#if !defined(islessgreater)
#error islessgreater
#endif
#if !defined(isnan)
#error isnan
#endif
#if !defined(isnormal)
#error isnormal
#endif
#if !defined(isunordered)
#error isunordered
#endif
#if !defined(signbit)
#error signbit
#endif

  MACRO(M_E);
  MACRO(M_LOG2E);
  MACRO(M_LOG10E);
  MACRO(M_LN2);
  MACRO(M_LN10);
  MACRO(M_PI);
  MACRO(M_PI_2);
  MACRO(M_PI_4);
  MACRO(M_1_PI);
  MACRO(M_2_PI);
  MACRO(M_2_SQRTPI);
  MACRO(M_SQRT2);
  MACRO(M_SQRT1_2);

  MACRO(MAXFLOAT);

  MACRO(HUGE_VAL);
  MACRO(HUGE_VALF);
  MACRO(HUGE_VALL);
  MACRO(INFINITY);
  MACRO(NAN);

  MACRO(FP_INFINITE);
  MACRO(FP_NAN);
  MACRO(FP_NORMAL);
  MACRO(FP_SUBNORMAL);
  MACRO(FP_ZERO);

#if defined(FP_FAST_FMA) && FP_FAST_FMA != 1
#error FP_FAST_FMA
#endif
#if defined(FP_FAST_FMAF) && FP_FAST_FMAF != 1
#error FP_FAST_FMAF
#endif
#if defined(FP_FAST_FMAL) && FP_FAST_FMAL != 1
#error FP_FAST_FMAL
#endif

  MACRO(FP_ILOGB0);
  MACRO(FP_ILOGBNAN);

  MACRO_VALUE(MATH_ERRNO, 1);
  MACRO_VALUE(MATH_ERREXCEPT, 2);

#if !defined(math_errhandling)
#error math_errhandling
#endif
  MACRO_TYPE(int, math_errhandling);

  FUNCTION(acos, double (*f)(double));
  FUNCTION(acosf, float (*f)(float));
  FUNCTION(acosh, double (*f)(double));
  FUNCTION(acoshf, float (*f)(float));
  FUNCTION(acoshl, long double (*f)(long double));
  FUNCTION(acosl, long double (*f)(long double));

  FUNCTION(asin, double (*f)(double));
  FUNCTION(asinf, float (*f)(float));
  FUNCTION(asinh, double (*f)(double));
  FUNCTION(asinhf, float (*f)(float));
  FUNCTION(asinhl, long double (*f)(long double));
  FUNCTION(asinl, long double (*f)(long double));

  FUNCTION(atan, double (*f)(double));
  FUNCTION(atan2, double (*f)(double, double));
  FUNCTION(atan2f, float (*f)(float, float));
  FUNCTION(atan2l, long double (*f)(long double, long double));
  FUNCTION(atanf, float (*f)(float));
  FUNCTION(atanh, double (*f)(double));
  FUNCTION(atanhf, float (*f)(float));
  FUNCTION(atanhl, long double (*f)(long double));
  FUNCTION(atanl, long double (*f)(long double));

  FUNCTION(cbrt, double (*f)(double));
  FUNCTION(cbrtf, float (*f)(float));
  FUNCTION(cbrtl, long double (*f)(long double));

  FUNCTION(ceil, double (*f)(double));
  FUNCTION(ceilf, float (*f)(float));
  FUNCTION(ceill, long double (*f)(long double));

  FUNCTION(copysign, double (*f)(double, double));
  FUNCTION(copysignf, float (*f)(float, float));
  FUNCTION(copysignl, long double (*f)(long double, long double));

  FUNCTION(cos, double (*f)(double));
  FUNCTION(cosf, float (*f)(float));
  FUNCTION(cosh, double (*f)(double));
  FUNCTION(coshf, float (*f)(float));
  FUNCTION(coshl, long double (*f)(long double));
  FUNCTION(cosl, long double (*f)(long double));

  FUNCTION(erf, double (*f)(double));
  FUNCTION(erfc, double (*f)(double));
  FUNCTION(erfcf, float (*f)(float));
  FUNCTION(erfcl, long double (*f)(long double));
  FUNCTION(erff, float (*f)(float));
  FUNCTION(erfl, long double (*f)(long double));

  FUNCTION(exp, double (*f)(double));
  FUNCTION(exp2, double (*f)(double));
  FUNCTION(exp2f, float (*f)(float));
  FUNCTION(exp2l, long double (*f)(long double));
  FUNCTION(expf, float (*f)(float));
  FUNCTION(expl, long double (*f)(long double));
  FUNCTION(expm1, double (*f)(double));
  FUNCTION(expm1f, float (*f)(float));
  FUNCTION(expm1l, long double (*f)(long double));

  FUNCTION(fabs, double (*f)(double));
  FUNCTION(fabsf, float (*f)(float));
  FUNCTION(fabsl, long double (*f)(long double));

  FUNCTION(fdim, double (*f)(double, double));
  FUNCTION(fdimf, float (*f)(float, float));
  FUNCTION(fdiml, long double (*f)(long double, long double));

  FUNCTION(floor, double (*f)(double));
  FUNCTION(floorf, float (*f)(float));
  FUNCTION(floorl, long double (*f)(long double));

  FUNCTION(fma, double (*f)(double, double, double));
  FUNCTION(fmaf, float (*f)(float, float, float));
  FUNCTION(fmal, long double (*f)(long double, long double, long double));

  FUNCTION(fmax, double (*f)(double, double));
  FUNCTION(fmaxf, float (*f)(float, float));
  FUNCTION(fmaxl, long double (*f)(long double, long double));

  FUNCTION(fmin, double (*f)(double, double));
  FUNCTION(fminf, float (*f)(float, float));
  FUNCTION(fminl, long double (*f)(long double, long double));

  FUNCTION(fmod, double (*f)(double, double));
  FUNCTION(fmodf, float (*f)(float, float));
  FUNCTION(fmodl, long double (*f)(long double, long double));

  FUNCTION(frexp, double (*f)(double, int*));
  FUNCTION(frexpf, float (*f)(float, int*));
  FUNCTION(frexpl, long double (*f)(long double, int*));

  FUNCTION(hypot, double (*f)(double, double));
  FUNCTION(hypotf, float (*f)(float, float));
  FUNCTION(hypotl, long double (*f)(long double, long double));

  FUNCTION(ilogb, int (*f)(double));
  FUNCTION(ilogbf, int (*f)(float));
  FUNCTION(ilogbl, int (*f)(long double));

  FUNCTION(j0, double (*f)(double));
  FUNCTION(j1, double (*f)(double));
  FUNCTION(jn, double (*f)(int, double));

  FUNCTION(ldexp, double (*f)(double, int));
  FUNCTION(ldexpf, float (*f)(float, int));
  FUNCTION(ldexpl, long double (*f)(long double, int));

  FUNCTION(lgamma, double (*f)(double));
  FUNCTION(lgammaf, float (*f)(float));
  FUNCTION(lgammal, long double (*f)(long double));

  FUNCTION(llrint, long long (*f)(double));
  FUNCTION(llrintf, long long (*f)(float));
  FUNCTION(llrintl, long long (*f)(long double));

  FUNCTION(llround, long long (*f)(double));
  FUNCTION(llroundf, long long (*f)(float));
  FUNCTION(llroundl, long long (*f)(long double));

  FUNCTION(log, double (*f)(double));
  FUNCTION(log10, double (*f)(double));
  FUNCTION(log10f, float (*f)(float));
  FUNCTION(log10l, long double (*f)(long double));
  FUNCTION(log1p, double (*f)(double));
  FUNCTION(log1pf, float (*f)(float));
  FUNCTION(log1pl, long double (*f)(long double));
  FUNCTION(log2, double (*f)(double));
  FUNCTION(log2f, float (*f)(float));
  FUNCTION(log2l, long double (*f)(long double));
  FUNCTION(logb, double (*f)(double));
  FUNCTION(logbf, float (*f)(float));
  FUNCTION(logbl, long double (*f)(long double));
  FUNCTION(logf, float (*f)(float));
  FUNCTION(logl, long double (*f)(long double));

  FUNCTION(lrint, long (*f)(double));
  FUNCTION(lrintf, long (*f)(float));
  FUNCTION(lrintl, long (*f)(long double));

  FUNCTION(lround, long (*f)(double));
  FUNCTION(lroundf, long (*f)(float));
  FUNCTION(lroundl, long (*f)(long double));

  FUNCTION(modf, double (*f)(double, double*));
  FUNCTION(modff, float (*f)(float, float*));
  FUNCTION(modfl, long double (*f)(long double, long double*));

  FUNCTION(nan, double (*f)(const char*));
  FUNCTION(nanf, float (*f)(const char*));
  FUNCTION(nanl, long double (*f)(const char*));

  FUNCTION(nearbyint, double (*f)(double));
  FUNCTION(nearbyintf, float (*f)(float));
  FUNCTION(nearbyintl, long double (*f)(long double));

  FUNCTION(nextafter, double (*f)(double, double));
  FUNCTION(nextafterf, float (*f)(float, float));
  FUNCTION(nextafterl, long double (*f)(long double, long double));

  FUNCTION(nexttoward, double (*f)(double, long double));
  FUNCTION(nexttowardf, float (*f)(float, long double));
  FUNCTION(nexttowardl, long double (*f)(long double, long double));

  FUNCTION(pow, double (*f)(double, double));
  FUNCTION(powf, float (*f)(float, float));
  FUNCTION(powl, long double (*f)(long double, long double));

  FUNCTION(remainder, double (*f)(double, double));
  FUNCTION(remainderf, float (*f)(float, float));
  FUNCTION(remainderl, long double (*f)(long double, long double));

  FUNCTION(remquo, double (*f)(double, double, int*));
  FUNCTION(remquof, float (*f)(float, float, int*));
  FUNCTION(remquol, long double (*f)(long double, long double, int*));

  FUNCTION(rint, double (*f)(double));
  FUNCTION(rintf, float (*f)(float));
  FUNCTION(rintl, long double (*f)(long double));

  FUNCTION(round, double (*f)(double));
  FUNCTION(roundf, float (*f)(float));
  FUNCTION(roundl, long double (*f)(long double));

  FUNCTION(scalbln, double (*f)(double, long));
  FUNCTION(scalblnf, float (*f)(float, long));
  FUNCTION(scalblnl, long double (*f)(long double, long));

  FUNCTION(scalbn, double (*f)(double, int));
  FUNCTION(scalbnf, float (*f)(float, int));
  FUNCTION(scalbnl, long double (*f)(long double, int));

  FUNCTION(sin, double (*f)(double));
  FUNCTION(sinf, float (*f)(float));
  FUNCTION(sinh, double (*f)(double));
  FUNCTION(sinhf, float (*f)(float));
  FUNCTION(sinhl, long double (*f)(long double));
  FUNCTION(sinl, long double (*f)(long double));

  FUNCTION(sqrt, double (*f)(double));
  FUNCTION(sqrtf, float (*f)(float));
  FUNCTION(sqrtl, long double (*f)(long double));

  FUNCTION(tan, double (*f)(double));
  FUNCTION(tanf, float (*f)(float));
  FUNCTION(tanh, double (*f)(double));
  FUNCTION(tanhf, float (*f)(float));
  FUNCTION(tanhl, long double (*f)(long double));
  FUNCTION(tanl, long double (*f)(long double));

  FUNCTION(tgamma, double (*f)(double));
  FUNCTION(tgammaf, float (*f)(float));
  FUNCTION(tgammal, long double (*f)(long double));

  FUNCTION(trunc, double (*f)(double));
  FUNCTION(truncf, float (*f)(float));
  FUNCTION(truncl, long double (*f)(long double));

  FUNCTION(y0, double (*f)(double));
  FUNCTION(y1, double (*f)(double));
  FUNCTION(yn, double (*f)(int, double));

  int s = signgam;
}
```
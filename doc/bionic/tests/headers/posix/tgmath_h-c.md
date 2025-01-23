Response:
Let's break down the thought process to answer the request about `bionic/tests/headers/posix/tgmath_h.c`.

**1. Understanding the Core Question:**

The central question is about the purpose and functionality of this specific C file within the Android Bionic library. The request asks for an explanation of its function, its relation to Android, details about the libc functions it uses, how it interacts with the dynamic linker (if at all), potential usage errors, and how Android framework/NDK might reach this code, including a Frida hook example.

**2. Initial Analysis of the Source Code:**

The first step is to carefully examine the provided C code. Key observations:

* **`#include <tgmath.h>`:** This immediately tells us the file is related to the `<tgmath.h>` header, which provides type-generic math macros.
* **`#include "header_checks.h"`:** This suggests the file is part of a test suite or validation process for header file correctness.
* **Macro Definitions (TGMATH, TGMATHC, etc.):** These macros are used to systematically call various math functions with different floating-point types (float, double, long double, and their complex counterparts). This hints at the primary function being *testing* the `<tgmath.h>` implementation.
* **`static void tgmath_h() { ... }`:** The core logic resides within this function. It declares variables of different floating-point types and then calls a multitude of math functions using the defined macros.
* **No Explicit System Calls or Dynamic Linking Code:**  A quick scan reveals no direct calls to functions like `dlopen`, `dlsym`, or any system calls related to process creation or memory management. This suggests the file's primary purpose isn't directly interacting with the dynamic linker.

**3. Formulating the Core Functionality:**

Based on the code analysis, the primary function of `tgmath_h.c` is to **test the correctness of the `<tgmath.h>` header implementation in Bionic**. It does this by:

* **Including `<tgmath.h>`:** Ensuring the header itself compiles without errors.
* **Calling various type-generic math macros:** Verifying that the macros expand correctly and call the appropriate underlying math functions based on the argument types.
* **Implicitly checking for compiler errors:** If the `<tgmath.h>` implementation has errors, the compilation of this test file would likely fail.

**4. Relating to Android Functionality:**

The `<tgmath.h>` header is part of the standard C library, which is a fundamental component of any operating system, including Android. Therefore, `tgmath_h.c` plays a crucial role in ensuring the stability and correctness of the math functions available to Android applications and the system itself. Examples of Android components relying on these math functions include graphics libraries, game engines, scientific applications, and even core system services.

**5. Explaining libc Function Implementations:**

The request asks for detailed explanations of each libc function. While it's tempting to dive into the assembly code of each function, the context of `tgmath_h.c` provides a shortcut. *This file doesn't implement the functions; it merely calls them.*  Therefore, the explanation should focus on the *purpose* of each function as defined by the C standard and briefly mention that Bionic provides the actual implementations. Listing the functions and their basic descriptions is sufficient.

**6. Addressing Dynamic Linker Involvement:**

The initial code analysis revealed no direct dynamic linker interaction. The key here is to recognize that *while this specific file doesn't directly use the dynamic linker, the underlying math functions it calls do*. When an Android application (or any executable) uses a math function, the linker resolves the symbol to the implementation within the shared library (likely `libm.so` in Bionic).

To address the dynamic linker aspect, the answer should explain:

* **Indirect Linker Usage:**  `tgmath_h.c` tests functions that are *provided* by shared libraries.
* **`libm.so`:**  Identify `libm.so` as the likely location of the math function implementations.
* **Linking Process:** Briefly describe how the dynamic linker resolves symbols at runtime.
* **SO Layout Example:**  Provide a simple example of how `libm.so` might be structured.

**7. Logical Reasoning, Assumptions, and I/O:**

This file is primarily for testing, so logical reasoning involves understanding the expected behavior of the type-generic math macros. The assumption is that if the code compiles and runs without errors, the `<tgmath.h>` implementation is likely correct for the tested cases. The "input" is the compilation and execution of the test file, and the "output" is ideally a successful compilation and execution. If there were errors in `<tgmath.h>`, the compilation would likely fail.

**8. Common Usage Errors:**

Since `tgmath_h.c` is a test file, common *user* errors are less directly relevant. However, it's important to consider errors related to *using* the `<tgmath.h>` macros correctly in application code. Examples include:

* **Incorrectly assuming type deduction:** Users might expect certain behavior without fully understanding the type promotion rules.
* **Mixing complex and real numbers unintentionally:**  The type-generic nature can sometimes lead to unexpected conversions if the user isn't careful.

**9. Android Framework/NDK Path and Frida Hook:**

To trace how Android reaches this test file, consider the development and testing process:

* **Bionic Development:**  This file is part of Bionic's source code, used during its development and testing.
* **NDK:** While NDK developers don't directly *execute* this test file, they benefit from its existence because it helps ensure the correctness of the math functions they use.
* **Android Framework:** Similarly, framework developers rely on a correct and stable C library.

A Frida hook example needs to target a function *called* by `tgmath_h()`, not `tgmath_h()` itself (as it's a test function). Choosing a common math function like `cos` and demonstrating how to hook it and log its arguments and return value is a good approach.

**10. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the original request. Use clear headings and bullet points for readability. Provide code examples where appropriate (like the Frida hook and SO layout). Maintain a concise and informative tone.

By following these steps, we can arrive at a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to analyze the code, understand its context within Bionic, and connect it to broader Android development concepts.
这是一个位于 Android Bionic 库中的源代码文件 `bionic/tests/headers/posix/tgmath_h.c`。它的主要功能是**测试 `<tgmath.h>` 头文件的正确性**。

**功能列举:**

1. **头文件包含测试:**  它包含了 `<tgmath.h>` 头文件，这是检查该头文件是否存在以及基本语法是否正确的第一步。
2. **类型泛型宏测试:**  `tgmath.h` 定义了一组类型泛型的数学宏，允许在不显式指定函数版本（如 `sinf`, `sin`, `sinl`）的情况下调用相应的函数，编译器会根据参数类型自动选择合适的版本。这个文件通过定义一系列宏 (`TGMATH`, `TGMATHC`, `TGMATH2` 等) 并使用不同的浮点类型（`float`, `double`, `long double` 以及它们的复数版本）调用这些宏，来测试这些类型泛型宏是否能正确展开并调用正确的底层数学函数。
3. **覆盖多种数学函数:**  测试覆盖了 `<tgmath.h>` 中定义的大部分数学函数，包括三角函数、指数函数、对数函数、幂函数、平方根函数、绝对值函数等等，以及它们的复数版本。
4. **静态检查:**  通过编译这个测试文件，可以进行静态检查，确保 `<tgmath.h>` 的定义和宏展开不会导致编译错误。

**与 Android 功能的关系及举例说明:**

`tgmath_h.c` 是 Android Bionic 库的一部分，因此它直接关系到 Android 系统的基础功能。Bionic 提供了 Android 系统和应用程序运行所需的 C 标准库。

* **提供基础数学运算:**  `<tgmath.h>` 中定义的数学函数是许多 Android 组件和应用程序的基础。例如：
    * **图形渲染:**  OpenGL ES 和 Vulkan 等图形 API 依赖于三角函数（`sin`, `cos` 等）进行几何变换和计算。
    * **游戏开发:**  游戏引擎广泛使用各种数学函数，例如距离计算（`hypot`）、角度计算（`atan2`）、物理模拟等。
    * **科学计算和数据分析:**  Android 设备上的科学计算应用程序和库会使用到更高级的数学函数，例如指数、对数、幂函数等。
    * **系统服务:**  一些底层系统服务可能也会用到基本的数学运算。

**libc 函数的功能实现解释:**

`tgmath_h.c` 文件本身并不实现这些 libc 函数，它只是 *调用* 这些函数来测试 `<tgmath.h>` 的宏定义是否正确。  这些函数的具体实现位于 Bionic 库的其他源文件中，通常在 `bionic/libm` 目录下。

简单解释一下 `tgmath_h.c` 中涉及的一些 libc 函数的功能：

* **三角函数:**
    * `acos(x)`: 反余弦函数，返回值为弧度。
    * `asin(x)`: 反正弦函数，返回值为弧度。
    * `atan(x)`: 反正切函数，返回值为弧度。
    * `cos(x)`: 余弦函数，输入为弧度。
    * `sin(x)`: 正弦函数，输入为弧度。
    * `tan(x)`: 正切函数，输入为弧度。
    * `acosh(x)`: 反双曲余弦函数。
    * `asinh(x)`: 反双曲正弦函数。
    * `atanh(x)`: 反双曲正切函数。
    * `cosh(x)`: 双曲余弦函数。
    * `sinh(x)`: 双曲正弦函数。
    * `tanh(x)`: 双曲正切函数。
* **指数和对数函数:**
    * `exp(x)`: 指数函数，计算 e 的 x 次方。
    * `log(x)`: 自然对数函数，计算 x 的自然对数（以 e 为底）。
    * `log10(x)`: 常用对数函数，计算 x 的常用对数（以 10 为底）。
    * `log1p(x)`: 计算 1+x 的自然对数，对于接近 0 的 x 更精确。
    * `log2(x)`: 以 2 为底的对数。
    * `exp2(x)`: 计算 2 的 x 次方。
    * `expm1(x)`: 计算 e 的 x 次方减 1，对于接近 0 的 x 更精确。
* **幂和根函数:**
    * `pow(x, y)`: 计算 x 的 y 次方。
    * `sqrt(x)`: 计算 x 的平方根。
    * `cbrt(x)`: 计算 x 的立方根。
    * `hypot(x, y)`: 计算 sqrt(x^2 + y^2)，避免溢出。
* **绝对值和符号函数:**
    * `fabs(x)`: 计算 x 的绝对值。
    * `copysign(x, y)`: 返回一个大小等于 x，符号等于 y 的值。
* **取整函数:**
    * `ceil(x)`: 返回大于或等于 x 的最小整数。
    * `floor(x)`: 返回小于或等于 x 的最大整数。
    * `round(x)`: 返回最接近 x 的整数，四舍五入。
    * `trunc(x)`: 返回 x 的整数部分，直接截断小数。
    * `nearbyint(x)`: 返回最接近 x 的整数，根据当前的舍入模式。
    * `rint(x)`: 类似 `nearbyint`，但可能会引发浮点异常。
    * `lround(x)`: 返回最接近 x 的 long int 整数，四舍五入。
    * `llround(x)`: 返回最接近 x 的 long long int 整数，四舍五入。
    * `lrint(x)`: 返回最接近 x 的 long int 整数，根据当前的舍入模式。
    * `llrint(x)`: 返回最接近 x 的 long long int 整数，根据当前的舍入模式。
* **其他数学函数:**
    * `atan2(y, x)`: 计算 y/x 的反正切值，返回值范围为 [-π, π]，可以确定象限。
    * `fdim(x, y)`: 返回 max(x - y, 0)。
    * `fmax(x, y)`: 返回 x 和 y 中的较大值。
    * `fmin(x, y)`: 返回 x 和 y 中的较小值。
    * `fmod(x, y)`: 计算 x 除以 y 的浮点余数，符号与 x 相同。
    * `remainder(x, y)`: 计算 x 除以 y 的余数，结果接近 0。
    * `remquo(x, y, *quo)`: 计算 x 除以 y 的余数和商，商存储在 `*quo` 中。
    * `frexp(x, *exponent)`: 将浮点数分解为规格化的小数部分（0.5 <= |mantissa| < 1）和 2 的幂指数。
    * `ldexp(x, exponent)`: 计算 x 乘以 2 的 exponent 次方。
    * `ilogb(x)`: 返回 x 的二进制指数（以 2 为底）。
    * `logb(x)`: 返回 x 的浮点数格式的指数（基数由实现定义）。
    * `scalbn(x, n)`: 计算 x 乘以 FLT_RADIX 的 n 次方。
    * `scalbln(x, n)`: 计算 x 乘以 FLT_RADIX 的 n 次方（n 为 long int）。
    * `erf(x)`: 误差函数。
    * `erfc(x)`: 余误差函数。
    * `tgamma(x)`: 伽玛函数。
    * `lgamma(x)`: 伽玛函数的自然对数。
    * `nextafter(x, y)`: 返回朝向 y 的下一个可表示的浮点数。
    * `nexttoward(x, y)`: 类似于 `nextafter`，但 `y` 可以是 long double 类型。
* **复数函数 (带 `c` 前缀):**  这些函数对复数进行操作，例如 `cabs` (复数模), `carg` (复数辐角), `cimag` (复数虚部), `creal` (复数实部), `conj` (复数共轭), `cproj` (复数投影到 Riemann 球面上) 等。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程:**

`tgmath_h.c` 本身是一个测试文件，不直接涉及动态链接器的功能。但是，它所测试的 `<tgmath.h>` 中声明的数学函数的实现，最终会链接到共享库 `libm.so` (在 Android 中通常是这样)。

**SO 布局样本 (简化):**

```
libm.so:
    符号表:
        sin:  (地址)
        cos:  (地址)
        pow:  (地址)
        ...
        csin: (地址)
        ccos: (地址)
        cpow: (地址)
        ...
```

**链接处理过程:**

1. **编译时:** 当一个应用程序或共享库（例如，使用 `<tgmath.h>` 中函数的其他 Bionic 库）被编译时，编译器遇到对 `sin`、`cos` 等函数的调用。
2. **链接时:** 链接器（在 Android 中主要是 `lld`）会查找这些符号的定义。由于这些函数是标准 C 库的一部分，链接器知道它们应该在 `libm.so` 中。
3. **动态链接时:** 当应用程序在 Android 设备上运行时，动态链接器 (`linker64` 或 `linker`) 会负责加载所需的共享库，并将应用程序中对 `sin`、`cos` 等符号的引用解析到 `libm.so` 中对应的函数地址。这个过程称为符号解析或重定位。
4. **`tgmath.h` 的作用:** `<tgmath.h>` 通过宏定义，在编译时根据参数类型选择合适的函数版本（例如，如果参数是 `float`，则调用 `sinf`；如果参数是 `double`，则调用 `sin`；如果参数是 `long double`，则调用 `sinl`）。 这些 `sinf`, `sin`, `sinl` 等函数最终都会链接到 `libm.so` 中。

**逻辑推理、假设输入与输出:**

这个文件主要是测试，所以逻辑推理集中在 `<tgmath.h>` 宏的展开是否正确。

**假设输入:** 编译器成功编译了 `tgmath_h.c`。

**逻辑推理:**

* 宏 `TGMATH(f_)` 会展开为 `f_(f1); f_(d1); f_(ld1);`。
* 当 `f_` 为 `sin` 时，会展开为 `sin(f1); sin(d1); sin(ld1);`。
* 由于 `f1` 是 `float`，`d1` 是 `double`，`ld1` 是 `long double`，根据 `<tgmath.h>` 的定义，这些调用应该分别解析为 `sinf(f1)`, `sin(d1)`, 和 `sinl(ld1)`。
* 类似的推理适用于其他宏和函数。

**预期输出:**  如果 `<tgmath.h>` 的实现正确，并且 `libm.so` 中相应的数学函数实现也正确，那么 `tgmath_h.c` 中的所有函数调用都应该能够顺利执行，不会产生运行时错误或崩溃。这个测试文件的成功编译和运行，暗示了 `<tgmath.h>` 行为的正确性。

**用户或编程常见的使用错误:**

* **不理解类型泛型:**  用户可能会错误地认为 `tgmath.h` 中的宏会进行隐式类型转换，而忽略了参数类型的重要性。例如，如果将一个 `int` 类型的变量传递给 `sin` 宏，它会被转换为 `double` 类型，而不是 `float`。
* **与传统数学函数混淆:**  一些程序员可能习惯于直接调用 `sinf`, `sin`, `sinl` 等函数，而没有意识到可以使用更方便的类型泛型宏。
* **对复数类型的误用:**  在使用复数版本的函数时，如果参数类型不匹配，可能会导致编译错误或运行时错误。
* **链接错误:** 虽然不太常见，但在某些特殊构建配置下，如果 `libm.so` 没有正确链接，可能会导致符号未定义的链接错误。

**示例说明:**

```c
#include <tgmath.h>
#include <stdio.h>

int main() {
  float f = 1.0f;
  double d = 2.0;
  long double ld = 3.0l;
  float complex fc = 1.0f + 2.0fi;
  double complex dc = 3.0 + 4.0i;

  // 正确使用，根据类型自动选择 sinf, sin, sinl
  printf("sin(f) = %f\n", sin(f));
  printf("sin(d) = %f\n", sin(d));
  printf("sin(ld) = %Lf\n", sin(ld));

  // 正确使用复数函数
  printf("csin(fc) = %f + %fi\n", creal(csin(fc)), cimag(csin(fc)));
  printf("csin(dc) = %f + %fi\n", creal(csin(dc)), cimag(csin(dc)));

  // 常见错误：将整数直接传递给需要浮点数的函数 (虽然可以隐式转换，但不推荐)
  int i = 5;
  printf("sin(i) = %f\n", sin(i)); // 可能会有精度损失

  return 0;
}
```

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用数学函数:**  无论是 Java 代码通过 JNI 调用 NDK 中的 C/C++ 代码，还是 NDK 代码自身，都可能调用到 `<tgmath.h>` 中定义的数学函数。

2. **NDK 中的 C/C++ 代码:**  NDK 开发者可以直接包含 `<tgmath.h>` 并使用其中的宏。例如，一个游戏引擎可能会调用 `sin` 和 `cos` 来计算旋转角度。

3. **Bionic 库:**  当 NDK 代码被编译链接时，对 `sin` 等函数的调用会被链接到 Bionic 库的 `libm.so`。

4. **`tgmath.h` 头文件:**  编译器会解析 `#include <tgmath.h>`，并根据宏定义将 `sin(float)` 展开为 `sinf(float)`，`sin(double)` 展开为 `sin(double)` 等。

5. **`libm.so` 中的函数实现:**  最终，程序会执行 `libm.so` 中 `sinf`、`sin` 或 `sinl` 的具体实现。

**Frida Hook 示例:**

假设我们想 hook `sin` 函数（`double` 版本）的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['from'], message['payload']['data']))
    else:
        print(message)

package_name = "your.android.package" # 替换成你的应用包名
function_name = "sin"
library_name = "libm.so"

session = frida.attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName("{lib}", "{func}"), {
    onEnter: function(args) {
        console.log("[*] Hooking {func}");
        console.log("[*] Argument (double): " + args[0]);
        this.arg = args[0];
    },
    onLeave: function(retval) {
        console.log("[*] Return Value: " + retval);
        send({{ from: "{func}", data: "Input: " + this.arg + ", Output: " + retval }});
    }
});
""".format(lib=library_name, func=function_name)

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **`frida.attach(package_name)`:** 连接到目标 Android 应用程序。
2. **`Module.findExportByName("libm.so", "sin")`:**  找到 `libm.so` 中 `sin` 函数的地址。
3. **`Interceptor.attach(...)`:**  拦截对 `sin` 函数的调用。
4. **`onEnter`:** 在 `sin` 函数被调用之前执行，打印输入参数。
5. **`onLeave`:** 在 `sin` 函数执行完毕之后执行，打印返回值，并通过 `send` 函数发送信息给 Python 脚本。

**如何一步步到达 `tgmath_h.c` 的测试:**

实际上，你无法直接通过 Android Framework 或 NDK 的运行时执行路径 "到达" `tgmath_h.c` 这个测试文件。`tgmath_h.c` 是 Bionic 库的测试代码，它主要在 Bionic 库的开发和测试阶段被使用。

1. **Bionic 库的构建和测试:**  Android 平台的构建系统（通常是 Soong）会编译 Bionic 库。作为编译过程的一部分，会执行 Bionic 库的测试，包括 `bionic/tests/headers/posix/tgmath_h.c`。
2. **开发者运行测试:**  Bionic 库的开发者和维护者会运行这些测试来确保代码的正确性。
3. **集成测试:**  在 Android 系统的持续集成 (CI) 流程中，这些测试会被自动化执行，以保证每次代码更改后 Bionic 库的质量。

**总结:**

`bionic/tests/headers/posix/tgmath_h.c` 是一个关键的测试文件，用于验证 Android Bionic 库中 `<tgmath.h>` 头文件的实现是否符合标准。它通过调用各种数学函数并覆盖不同的数据类型，来确保类型泛型宏的正确展开和底层数学函数的正常工作，从而保证了 Android 系统中基础数学运算的可靠性。 虽然普通应用程序开发者不会直接运行或接触到这个测试文件，但它的存在对于保证 Android 系统的稳定性和正确性至关重要。

### 提示词
```
这是目录为bionic/tests/headers/posix/tgmath_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <tgmath.h>

#include "header_checks.h"

#define TGMATH(f_) f_(f1); f_(d1); f_(ld1);
#define TGMATHC(f_) f_(f1); f_(d1); f_(ld1); f_(fc1); f_(dc1); f_(ldc1);
#define TGMATHCONLY(f_) f_(fc1); f_(dc1); f_(ldc1);
#define TGMATH2(f_) f_(f1, f2); f_(d1, d2); f_(ld1, ld2);
#define TGMATH2C(f_) f_(f1, f2); f_(d1, d2); f_(ld1, ld2); f_(fc1, fc2); f_(dc1, dc2); f_(ldc1, ldc2);
#define TGMATH3(f_) f_(f1, f2, f3); f_(d1, d2, d3); f_(ld1, ld2, ld3);

static void tgmath_h() {
  float f1, f2, f3;
  f1 = f2 = f3 = 0;
  float complex fc1, fc2, fc3;
  fc1 = fc2 = fc3 = 0;
  double d1, d2, d3;
  d1 = d2 = d3 = 0;
  double complex dc1, dc2, dc3;
  dc1 = dc2 = dc3 = 0;
  long double ld1, ld2, ld3;
  ld1 = ld2 = ld3 = 0;
  long double complex ldc1, ldc2, ldc3;
  ldc1 = ldc2 = ldc3 = 0;
  int i = 0;
  long l = 0;

  TGMATHC(acos);
  TGMATHC(asin);
  TGMATHC(atan);
  TGMATHC(acosh);
  TGMATHC(asinh);
  TGMATHC(atanh);
  TGMATHC(cos);
  TGMATHC(sin);
  TGMATHC(tan);
  TGMATHC(cosh);
  TGMATHC(sinh);
  TGMATHC(tanh);
  TGMATHC(exp);
  TGMATHC(log);
  TGMATH2C(pow);
  TGMATHC(sqrt);
  TGMATHC(fabs);

  TGMATH2(atan2);
  TGMATH(cbrt);
  TGMATH(ceil);
  TGMATH2(copysign);
  TGMATH(erf);
  TGMATH(erfc);
  TGMATH(exp2);
  TGMATH(expm1);
  TGMATH2(fdim);
  TGMATH(floor);
  TGMATH3(fma);
  TGMATH2(fmax);
  TGMATH2(fmin);
  TGMATH2(fmod);
  frexp(f1, &i); frexp(d1, &i); frexp(ld1, &i);
  TGMATH2(hypot);
  TGMATH(ilogb);
  ldexp(f1, i); ldexp(d1, i); ldexp(ld1, i);
  TGMATH(lgamma);
  TGMATH(llrint);
  TGMATH(llround);
  TGMATH(log10);
  TGMATH(log1p);
  TGMATH(log2);
  TGMATH(logb);
  TGMATH(lrint);
  TGMATH(lround);
  TGMATH(nearbyint);
  TGMATH2(nextafter);
  TGMATH2(nexttoward);
  TGMATH2(remainder);
  remquo(f1, f2, &i); remquo(d1, d2, &i); remquo(ld1, ld2, &i);
  TGMATH(rint);
  TGMATH(round);
  scalbln(f1, l); scalbln(d1, l); scalbln(ld1, l);
  scalbn(f1, i); scalbn(d1, i); scalbn(ld1, i);
  TGMATH(tgamma);
  TGMATH(trunc);

  TGMATHCONLY(carg);
  TGMATHCONLY(cimag);
  TGMATHCONLY(conj);
  TGMATHCONLY(cproj);
  TGMATHCONLY(creal);
}
```
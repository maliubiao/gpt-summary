Response:
Let's break down the thought process for answering the request about `s_ccoshf.c`.

**1. Understanding the Core Task:**

The fundamental goal is to analyze the provided C source code for `ccoshf` and `ccosf` and explain their functionality within the Android Bionic context. This involves dissecting the code, identifying key functionalities, connecting them to Android's ecosystem, and providing relevant examples and debugging strategies.

**2. Initial Code Analysis (Skimming and Identifying Key Areas):**

First, I'd quickly read through the code, looking for:

* **Include Headers:** `complex.h`, `math.h`, `math_private.h`. This tells me it's dealing with complex numbers and likely uses standard math functions. The `math_private.h` hints at internal Bionic math library details.
* **Function Signatures:**  `float complex ccoshf(float complex z)` and `float complex ccosf(float complex z)`. Clearly, these are functions operating on and returning single-precision complex numbers.
* **Constants:** `static const float huge = 0x1p127;`. This suggests handling of potential overflows.
* **Macros:** `GET_FLOAT_WORD`. This is likely a platform-specific way to access the raw bit representation of a float, indicating optimization or handling of special floating-point values (like NaN or infinity).
* **Conditional Logic:** A significant portion of the code uses `if` and `else if` statements based on the real and imaginary parts of the input (`x` and `y`). This suggests handling different ranges and special cases.
* **Standard Math Functions:** Calls to `coshf`, `sinhf`, `cosf`, `fabsf`, `expf`, `copysignf`. These are the building blocks of the complex hyperbolic cosine.
* **Internal Bionic Functions:** `__ldexp_cexpf`. The `__` prefix usually indicates an internal function. `ldexp` is for scaling by powers of 2, and `cexp` likely means complex exponential.
* **Special Case Handling:** Checks for `iy == 0`, `ix == 0`, and comparisons with `0x7f800000` (the bit pattern for infinity) indicate careful handling of edge cases and potential errors.
* **The `ccosf` Function:**  It directly calls `ccoshf` with a transformed input. This immediately suggests a relationship between the two functions (trigonometric and hyperbolic).

**3. Deeper Dive and Functional Decomposition:**

Now, I'd go through the code more methodically, commenting on each block and trying to understand its purpose. For example:

* **Extracting Real and Imaginary Parts:**  `x = crealf(z); y = cimagf(z);` is straightforward.
* **Getting the Raw Bits:** `GET_FLOAT_WORD(hx, x); GET_FLOAT_WORD(hy, y);`  I'd recognize this as low-level manipulation.
* **Isolating Magnitude Bits:** `ix = 0x7fffffff & hx; iy = 0x7fffffff & hy;` masks off the sign bit, focusing on the magnitude.
* **Normal Case:** The `ix < 0x7f800000 && iy < 0x7f800000` block deals with finite, non-infinite inputs.
* **Special Case: Imaginary Part is Zero:** `if (iy == 0)` handles the case where the complex number is real. The result is simply `coshf(x)`. The imaginary part `x * y` becomes zero.
* **Small Real Part:** `if (ix < 0x41100000)` uses the standard formula for `cosh(x+iy)`.
* **Larger Real Part (Approximation):** The code then handles cases where `|x|` is larger, using approximations like `cosh(x) ~= exp(|x|) / 2`.
* **Overflow Prevention:** The sections with `__ldexp_cexpf` and the `huge` constant clearly aim to prevent overflow by scaling the calculations.
* **Handling Infinity and NaN:** The subsequent `if` blocks meticulously handle cases where the real or imaginary parts are zero, infinity, or NaN.

**4. Connecting to Android Bionic:**

The key here is understanding that this code *is* part of Android's math library. I'd emphasize that:

* **Core Math Functionality:** `ccoshf` is a fundamental mathematical function needed by many applications.
* **NDK Usage:** Developers using the NDK can directly call this function.
* **Framework Dependency:** Higher-level Android framework components might indirectly rely on it through other libraries or system calls.
* **Dynamic Linking:** This code resides within a shared library (`libm.so`), which is dynamically linked to applications.

**5. Explaining Implementation Details:**

For each block of code, I'd explain *why* it's there and *how* it achieves its goal. This involves:

* **Describing the Mathematical Formulas:** Explain the relationship between `ccosh(x+iy)` and `cosh(x)cos(y) + i sinh(x)sin(y)`.
* **Explaining Optimization Techniques:** Discuss the use of approximations for large `|x|` to avoid expensive calculations.
* **Highlighting Overflow Handling:** Explain how the code scales values or uses the `huge` constant to manage potential overflows.
* **Detailing Special Case Handling:**  Clarify why specific checks for zero, infinity, and NaN are necessary.

**6. Dynamic Linker Aspects:**

This requires understanding how shared libraries work in Android:

* **`.so` Layout:** Describe the typical sections (e.g., `.text`, `.data`, `.bss`, `.symtab`, `.dynsym`, `.rel.dyn`, `.plt`, `.got`).
* **Linking Process:** Explain the role of the dynamic linker (`/system/bin/linker64` or `/system/bin/linker`), symbol resolution, relocation, and the PLT/GOT.

**7. Examples, Errors, and Debugging:**

* **Illustrative Examples:** Provide simple cases to show how `ccoshf` behaves.
* **Common Errors:** Point out pitfalls like passing very large or infinite values and not checking for potential overflows (though the library aims to handle these gracefully).
* **Frida Hook:** Provide a practical example of using Frida to intercept calls to `ccoshf`, allowing developers to inspect arguments and return values.

**8. Tracing the Call Path (Framework/NDK):**

This requires thinking about how a call might originate:

* **NDK:** Direct call from C/C++ code using the `<complex.h>` and `<math.h>` headers.
* **Framework (Indirect):**  Imagine a Java API that needs complex number calculations. This might involve JNI calls to native code that uses `ccoshf`. Examples could include graphics processing, signal processing, or scientific applications.

**9. Review and Refinement:**

Finally, I'd review the entire explanation for clarity, accuracy, and completeness. I'd make sure the language is understandable and that all parts of the request are addressed. I'd also double-check the code snippets and explanations for correctness.

This structured approach, moving from a high-level understanding to detailed analysis and then connecting it to the broader Android ecosystem, allows for a comprehensive and informative answer. The iterative nature of the process (skimming, deeper dive, connecting, explaining) is crucial for tackling complex code analysis tasks.好的，让我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/s_ccoshf.c` 这个文件。这个文件是 Android Bionic 库中实现复数双曲余弦函数 `ccoshf` 和复数余弦函数 `ccosf` 的源代码。

**功能列举:**

1. **`ccoshf(float complex z)`:** 计算单精度复数 `z` 的双曲余弦值。
2. **`ccosf(float complex z)`:** 计算单精度复数 `z` 的余弦值。

**与 Android 功能的关系及举例:**

* **基础数学运算:** 这两个函数是底层数学库的一部分，为 Android 系统和应用程序提供了基础的复数运算能力。许多上层功能，包括图形处理、信号处理、科学计算等，都可能间接地依赖于这些函数。
* **NDK 支持:** Android NDK 允许开发者使用 C/C++ 编写应用程序。这些函数可以通过 `<complex.h>` 和 `<math.h>` 头文件在 NDK 应用中使用。
    * **举例:** 一个进行傅里叶变换的 NDK 应用可能会使用复数运算，从而间接地调用 `ccoshf` 或 `ccosf`。例如，在计算某些核函数时，可能会涉及到复数双曲余弦。
* **Framework 间接使用:**  虽然 Android Framework 主要使用 Java 编写，但在一些底层或性能敏感的模块中，可能会使用 Native 代码，进而调用到这些数学函数。
    * **举例:**  例如，某些图像处理算法在 Native 层实现时，可能需要进行复数运算。

**libc 函数的功能实现细节:**

**1. `ccoshf(float complex z)` 的实现:**

该函数根据复数 `z = x + iy` 的实部 `x` 和虚部 `y` 来计算 `cosh(z)`。复数双曲余弦的定义是：

`cosh(x + iy) = cosh(x)cos(y) + i sinh(x)sin(y)`

函数实现中，为了处理不同的数值范围和避免溢出，采用了以下策略：

* **获取实部和虚部:** `x = crealf(z); y = cimagf(z);`  分别获取复数 `z` 的实部和虚部。
* **获取浮点数的位表示:** `GET_FLOAT_WORD(hx, x); GET_FLOAT_WORD(hy, y);`  这是一个宏，用于直接访问浮点数的二进制表示，方便进行位操作，例如提取符号位和指数部分。
* **处理特殊情况 (NaN 和 Infinity):** 代码首先检查输入是否为 NaN 或无穷大。
* **实部和虚部都较小的情况 (`ix < 0x7f800000 && iy < 0x7f800000`)**:
    * **虚部为零 (`iy == 0`)**: 如果虚部为零，则复数变为实数，`ccoshf(x + 0i) = coshf(x) + i * 0`。代码中直接返回 `CMPLXF(coshf(x), x * y)`，由于 `y` 是 0，所以虚部为 0。
    * **实部绝对值较小 (`ix < 0x41100000`, 即 `|x| < 9`)**: 使用复数双曲余弦的定义公式 `CMPLXF(coshf(x) * cosf(y), sinhf(x) * sinf(y))` 直接计算。
    * **实部绝对值较大 (`|x| >= 9`)**: 由于 `cosh(x)` 接近于 `exp(|x|) / 2`，为了防止溢出，代码采用了不同的计算方法：
        * **实部较小 (`ix < 0x42b17218`, 即 `x < 88.7`)**: 计算 `h = expf(fabsf(x)) * 0.5F`，然后使用近似公式 `CMPLXF(h * cosf(y), copysignf(h, x) * sinf(y))`。`copysignf` 用于保持虚部的符号与 `x` 相同。
        * **实部中等 (`ix < 0x4340b1e7`, 即 `x < 192.7`)**: 为了避免 `expf` 溢出，使用 `__ldexp_cexpf` 函数。这个函数可能是一个内部函数，用于计算 `exp(z) * 2^n`，这里 `n` 为 -1，相当于除以 2。计算 `cexpf` 后的实部和虚部会被取出并组合。
        * **实部非常大 (`x >= 192.7`)**: 结果将溢出。使用一个很大的数 `huge` 来表示溢出，并进行相应的计算。
* **处理特殊的无穷大和 NaN 情况:** 代码中剩余的部分处理了输入为无穷大或 NaN 的情况，返回相应的结果。例如，如果实部为无穷大，结果的实部也会是无穷大。

**2. `ccosf(float complex z)` 的实现:**

该函数通过调用 `ccoshf` 来计算复数余弦。利用了以下恒等式：

`cos(z) = cosh(iz)`

将 `z = x + iy` 代入，得到 `iz = -y + ix`。因此，`cos(x + iy) = cosh(-y + ix)`。

代码中直接调用 `ccoshf(CMPLXF(-cimagf(z), crealf(z)))`，即 `ccoshf(-y + ix)`，实现了这个转换。

**dynamic linker 的功能与处理过程:**

`s_ccoshf.c` 本身不直接涉及 dynamic linker 的功能，它是一个数学函数的实现。但是，这个函数最终会被编译到 `libm.so` 共享库中，并通过 dynamic linker 加载和链接到应用程序。

**`libm.so` 布局样本:**

一个简化的 `libm.so` 布局可能如下所示：

```
libm.so:
    .text:  # 包含可执行代码
        ccoshf:  # ccoshf 函数的代码
        ccosf:   # ccosf 函数的代码
        ... 其他数学函数 ...
    .rodata: # 包含只读数据，例如常量
        ... 数学常量 ...
    .data:   # 包含已初始化的全局变量
        ...
    .bss:    # 包含未初始化的全局变量
        ...
    .symtab: # 符号表，包含导出的和本地符号的信息
        ccoshf (function, global)
        ccosf  (function, global)
        ...
    .dynsym: # 动态符号表，包含需要在运行时链接的符号信息
        ccoshf
        ccosf
        ...
    .rel.dyn: # 动态重定位表，用于在加载时调整地址
        ...
    .plt:    # 程序链接表，用于延迟绑定
        ccoshf@plt
        ccosf@plt
        ...
    .got:    # 全局偏移表，用于存储外部符号的地址
        ccoshf@got
        ccosf@got
        ...
```

**链接的处理过程:**

1. **编译和链接:** 当一个应用程序需要使用 `ccoshf` 或 `ccosf` 时，编译器会将对这些函数的调用标记为需要动态链接。链接器会在生成可执行文件时，将对这些外部符号的引用放入可执行文件的 `.plt` (Procedure Linkage Table) 和 `.got` (Global Offset Table)。
2. **加载时链接:** 当 Android 系统加载应用程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载应用程序依赖的共享库，包括 `libm.so`。
3. **符号查找:** Dynamic linker 会在 `libm.so` 的 `.dynsym` 中查找 `ccoshf` 和 `ccosf` 的符号。
4. **重定位:** Dynamic linker 会修改应用程序的 `.got` 表项，将 `ccoshf` 和 `ccosf` 的实际地址填入。
5. **延迟绑定 (Lazy Binding):** 默认情况下，Android 使用延迟绑定。这意味着只有在第一次调用 `ccoshf` 或 `ccosf` 时，dynamic linker 才会解析其地址。
    * 当第一次调用 `ccoshf@plt` 时，会跳转到一段特殊的代码，这段代码会调用 dynamic linker 来解析 `ccoshf` 的实际地址。
    * Dynamic linker 找到 `ccoshf` 的地址后，会更新 `ccoshf@got` 表项，并将控制权转移到 `ccoshf` 的实际代码。
    * 后续对 `ccoshf` 的调用将直接通过 `.got` 表跳转到其实现，无需再次进行链接。

**逻辑推理的假设输入与输出:**

**假设输入:** `z = 1.0 + 1.0i`

* **`ccoshf(1.0 + 1.0i)`:**
    * `cosh(1) ≈ 1.543`
    * `cos(1) ≈ 0.540`
    * `sinh(1) ≈ 1.175`
    * `sin(1) ≈ 0.841`
    * `ccoshf(1 + i) ≈ 1.543 * 0.540 + i * 1.175 * 0.841 ≈ 0.833 + 0.988i`
* **`ccosf(1.0 + 1.0i)`:**
    * 相当于 `ccoshf(-1.0 + 1.0i)`
    * `cosh(-1) = cosh(1) ≈ 1.543`
    * `cos(1) ≈ 0.540`
    * `sinh(-1) = -sinh(1) ≈ -1.175`
    * `sin(1) ≈ 0.841`
    * `ccosf(1 + i) ≈ 1.543 * 0.540 + i * (-1.175) * 0.841 ≈ 0.833 - 0.988i`

**用户或编程常见的使用错误:**

1. **误解复数运算规则:**  不清楚复数双曲余弦和余弦的定义，导致使用错误。
2. **忽略精度问题:** 单精度浮点数 `float` 的精度有限，在进行多次运算后可能会累积误差。
3. **未处理溢出和下溢:** 虽然 `ccoshf` 内部有处理溢出的逻辑，但在某些极端情况下，仍然可能导致问题。程序员需要根据应用场景考虑可能的数值范围。
4. **类型不匹配:**  将 `double complex` 类型的复数传递给 `ccoshf` 或 `ccosf`，可能导致类型转换错误或精度损失。应该使用 `ccosh` 和 `ccos` 处理双精度复数。

**举例说明常见错误:**

```c
#include <complex.h>
#include <stdio.h>
#include <math.h>

int main() {
    float complex z = 100.0f + 100.0fi;
    float complex result_cosh = ccoshf(z);
    float complex result_cos = ccosf(z);

    // 可能由于输入值过大导致精度问题或接近溢出
    printf("ccoshf(100 + 100i) = %f + %fi\n", crealf(result_cosh), cimagf(result_cosh));
    printf("ccosf(100 + 100i) = %f + %fi\n", crealf(result_cos), cimagf(result_cos));

    // 错误的类型使用
    double complex dz = 1.0 + 1.0i;
    // 可能会有警告或精度损失
    float complex wrong_cosh = ccoshf(dz);
    printf("ccoshf(double complex) = %f + %fi\n", crealf(wrong_cosh), cimagf(wrong_cosh));

    return 0;
}
```

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 应用直接调用:**
   * NDK 开发者在 C/C++ 代码中包含 `<complex.h>` 和 `<math.h>`。
   * 调用 `ccoshf(z)` 或 `ccosf(z)` 函数。
   * 编译器将生成对这些函数的外部引用。
   * 在运行时，dynamic linker 加载 `libm.so` 并解析这些符号。

2. **Android Framework 间接调用 (JNI):**
   * Android Framework 的 Java 代码可能需要进行复数运算。
   * 通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。
   * Native 代码中调用了 `ccoshf` 或 `ccosf`。

**Frida Hook 示例作为调试线索:**

可以使用 Frida 来 hook `ccoshf` 函数，查看其输入参数和返回值，帮助调试。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为你的目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "ccoshf"), {
    onEnter: function(args) {
        var real = args[0].readFloat();
        var imag = args[4].readFloat(); // 假设复数的虚部紧跟在实部之后，可能需要根据ABI调整
        send({type: 'input', real: real, imag: imag});
        console.log("Called ccoshf with real: " + real + ", imag: " + imag);
    },
    onLeave: function(retval) {
        var real_ret = retval.readFloat();
        var imag_ret = retval.add(4).readFloat(); // 假设复数的虚部紧跟在实部之后
        send({type: 'output', real: real_ret, imag: imag_ret});
        console.log("ccoshf returned real: " + real_ret + ", imag: " + imag_ret);
    }
});

Interceptor.attach(Module.findExportByName("libm.so", "ccosf"), {
    onEnter: function(args) {
        var real = args[0].readFloat();
        var imag = args[4].readFloat(); // 假设复数的虚部紧跟在实部之后
        send({type: 'input', real: real, imag: imag});
        console.log("Called ccosf with real: " + real + ", imag: " + imag);
    },
    onLeave: function(retval) {
        var real_ret = retval.readFloat();
        var imag_ret = retval.add(4).readFloat(); // 假设复数的虚部紧跟在实部之后
        send({type: 'output', real: real_ret, imag: imag_ret});
        console.log("ccosf returned real: " + real_ret + ", imag: " + imag_ret);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 示例:**

* **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上的目标 Android 应用。
* **`Interceptor.attach(Module.findExportByName("libm.so", "ccoshf"), ...)`:**  拦截 `libm.so` 中导出的 `ccoshf` 函数的调用。
* **`onEnter`:** 在 `ccoshf` 函数被调用之前执行。
    * `args[0]` 指向第一个参数，即复数的实部。`args[4]` 指向复数的虚部 (假设结构体中实部和虚部相邻，大小为 4 字节的 float)。这可能需要根据具体的 ABI 进行调整。
    * `readFloat()` 读取浮点数值。
    * `send()` 函数将信息发送回 Frida 主机。
    * `console.log()` 在目标应用进程的日志中输出信息。
* **`onLeave`:** 在 `ccoshf` 函数返回之后执行。
    * `retval` 指向返回值，即计算结果的复数。
    * 读取返回值的实部和虚部。
* **类似地，对 `ccosf` 函数进行 hook。**

通过这个 Frida 脚本，你可以在目标应用调用 `ccoshf` 或 `ccosf` 时，实时观察其输入参数和返回值，从而进行调试和分析。

希望以上详细的解释能够帮助你理解 `s_ccoshf.c` 文件的功能、与 Android 的关系、实现细节以及如何进行调试。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/s_ccoshf.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例作为调试线索。
用中文回复。

"""
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005 Bruce D. Evans and Steven G. Kargl
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
 */

/*
 * Float version of ccosh().  See s_ccosh.c for details.
 */

#include <complex.h>
#include <math.h>

#include "math_private.h"

static const float huge = 0x1p127;

float complex
ccoshf(float complex z)
{
	float x, y, h;
	int32_t hx, hy, ix, iy;

	x = crealf(z);
	y = cimagf(z);

	GET_FLOAT_WORD(hx, x);
	GET_FLOAT_WORD(hy, y);

	ix = 0x7fffffff & hx;
	iy = 0x7fffffff & hy;

	if (ix < 0x7f800000 && iy < 0x7f800000) {
		if (iy == 0)
			return (CMPLXF(coshf(x), x * y));
		if (ix < 0x41100000)	/* |x| < 9: normal case */
			return (CMPLXF(coshf(x) * cosf(y), sinhf(x) * sinf(y)));

		/* |x| >= 9, so cosh(x) ~= exp(|x|) */
		if (ix < 0x42b17218) {
			/* x < 88.7: expf(|x|) won't overflow */
			h = expf(fabsf(x)) * 0.5F;
			return (CMPLXF(h * cosf(y), copysignf(h, x) * sinf(y)));
		} else if (ix < 0x4340b1e7) {
			/* x < 192.7: scale to avoid overflow */
			z = __ldexp_cexpf(CMPLXF(fabsf(x), y), -1);
			return (CMPLXF(crealf(z), cimagf(z) * copysignf(1, x)));
		} else {
			/* x >= 192.7: the result always overflows */
			h = huge * x;
			return (CMPLXF(h * h * cosf(y), h * sinf(y)));
		}
	}

	if (ix == 0)			/* && iy >= 0x7f800000 */
		return (CMPLXF(y - y, x * copysignf(0, y)));

	if (iy == 0)			/* && ix >= 0x7f800000 */
		return (CMPLXF(x * x, copysignf(0, x) * y));

	if (ix < 0x7f800000)		/* && iy >= 0x7f800000 */
		return (CMPLXF(y - y, x * (y - y)));

	if (ix == 0x7f800000) {
		if (iy >= 0x7f800000)
			return (CMPLXF(INFINITY, x * (y - y)));
		return (CMPLXF(INFINITY * cosf(y), x * sinf(y)));
	}

	return (CMPLXF(((long double)x * x) * (y - y),
	    ((long double)x + x) * (y - y)));
}

float complex
ccosf(float complex z)
{

	return (ccoshf(CMPLXF(-cimagf(z), crealf(z))));
}

"""

```
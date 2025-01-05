Response:
Let's break down the thought process for analyzing this `catrigl.c` file.

**1. Initial Understanding & Context:**

* **The Core Task:** The prompt asks for an analysis of the C code, specifically focusing on its functions, relationships to Android, implementation details, dynamic linking aspects, potential errors, and how it's accessed in Android.
* **Key Information:** The prompt explicitly states this file belongs to `bionic/libm/upstream-freebsd/lib/msun/src/catrigl.c`. This immediately tells us:
    * It's part of Android's `libm` (math library).
    * It originates from upstream FreeBSD, suggesting it implements standard math functions.
    * The filename `catrigl.c` hints at complex arctrigonometric functions (the 'c' likely stands for 'complex', 'atr' for arctrig, and 'l' for `long double`).
* **Copyright Notice:**  The copyright notice confirms the FreeBSD origin and the license under which it's distributed. This is good to note for licensing considerations, although not directly relevant to its *functionality*.

**2. Identifying Functions and Their Purpose (Code Scan):**

* **Keyword Search:**  Look for function definitions. These are easily identified by the return type followed by the function name. A quick scan reveals: `casinhl`, `casinl`, `cacosl`, `cacoshl`, `clog_for_large_values`, `catanhl`, `catanl`.
* **Function Naming Convention:** The naming convention `c<trigonometric function name>l` is consistent with complex long double math functions. This helps in quickly understanding the purpose of each function.
* **Internal Helpers:**  Notice the `static` keyword before some function definitions (`clog_for_large_values`, `do_hard_work`, `f`, `sum_squares`, `real_part_reciprocal`). These are internal helper functions not meant to be directly called from outside the library.
* **Inline Functions:**  The `static inline` keyword indicates functions that the compiler might inline for performance.

**3. Analyzing Individual Function Functionality (Detailed Examination):**

* **Start with Public Functions:**  Focus on the publicly accessible functions first (`casinhl`, `casinl`, `cacosl`, `cacoshl`, `catanhl`, `catanl`).
* **Look for Core Logic:** Inside each function, understand the steps involved:
    * **Input Extraction:**  Extract real and imaginary parts (`creall`, `cimagl`).
    * **Special Case Handling:**  Check for `NaN`, `Infinity`, and edge cases (e.g., `x == 0 && y == 0`).
    * **Algorithm Implementation:**  Notice comments referencing an academic paper. While the comments are sparse, the code itself contains clues. Look for key variables and their transformations.
    * **Helper Function Calls:**  Note the calls to internal helper functions.
    * **Return Value Construction:** Construct the complex result using `CMPLXL`.
* **Analyze Helper Functions:** Once the public functions are understood, delve into the helper functions:
    * **`clog_for_large_values`:**  Its name suggests handling complex logarithms for large magnitude inputs.
    * **`do_hard_work`:** This function seems to be the core algorithmic part for calculating some intermediate values used in several arctrigonometric functions. The variable names (`R`, `S`, `A`, `B`) might offer hints about the mathematical formulas being used.
    * **`f`:**  A small helper function likely performing a specific mathematical operation.
    * **`sum_squares` and `real_part_reciprocal`:** These appear to be utility functions for handling specific calculations related to complex numbers, potentially optimized for certain input ranges.
* **Data Structures and Constants:** Pay attention to defined constants and structures. The `union IEEEl2bits` is likely used for direct manipulation of floating-point representations. The various constant values (e.g., `A_crossover`, `B_crossover`, `RECIP_EPSILON`) are thresholds or magic numbers related to the algorithm's implementation and accuracy.

**4. Connecting to Android Functionality:**

* **`libm` Role:** Recognize that this code is part of `libm`, the standard math library in Android. Any application performing complex number calculations using standard C math functions will eventually rely on code like this.
* **NDK Usage:** Developers using the Android NDK can directly call these functions.
* **Framework Indirect Usage:** The Android framework (written in Java/Kotlin) might indirectly use these functions through native calls when performing math-intensive operations.

**5. Dynamic Linking and SO Layout:**

* **`libm.so`:**  Understand that `libm` is a shared library (`.so` file).
* **Linking Process:** When an Android application uses math functions, the dynamic linker resolves the symbols (function names) and links the application to `libm.so` at runtime.
* **SO Layout Example:**  Sketch a simplified layout showing the `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and symbol table within `libm.so`.

**6. Common Errors and Debugging:**

* **Incorrect Input:**  Highlight the importance of valid inputs for math functions and potential issues with overflow or underflow.
* **Frida Hooks:** Explain how Frida can be used to intercept calls to these functions, inspect arguments, and modify behavior for debugging. Provide concrete Frida code examples.

**7. Addressing Specific Prompt Requirements:**

* **"详细解释每一个libc函数的功能是如何实现的":**  Go into more detail about the algorithms used, especially in `do_hard_work`. Mention the paper referenced in the comments. Explain the purpose of the various constants and thresholds.
* **"对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程":**  Elaborate on the dynamic linking steps, including symbol resolution and relocation.
* **"如果做了逻辑推理，请给出假设输入与输出":**  Provide examples of function calls with specific inputs and the expected outputs, covering normal cases and edge cases.

**8. Structuring the Response:**

* **Organize by Topic:** Group related information together (e.g., function descriptions, Android integration, dynamic linking).
* **Use Clear Headings:** Make the response easy to read and understand.
* **Provide Code Examples:** Illustrate concepts with relevant code snippets (especially for Frida).
* **Maintain Technical Accuracy:**  Ensure the explanations are correct and use appropriate terminology.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus only on the public functions.
* **Correction:** Realized that understanding the helper functions is crucial for a comprehensive analysis.
* **Initial thought:** Briefly mention dynamic linking.
* **Correction:** Decided to provide a more detailed explanation of the linking process and a simplified SO layout.
* **Initial thought:**  Give general examples of common errors.
* **Correction:** Included specific examples related to the domain of complex number calculations (e.g., issues with magnitude).

By following this structured thought process, including self-correction and attention to the specific requirements of the prompt, we can generate a detailed and accurate analysis of the `catrigl.c` file.
好的，我们来详细分析一下 `bionic/libm/upstream-freebsd/lib/msun/src/catrigl.c` 这个文件。

**功能概述**

`catrigl.c` 文件实现了针对 `long double complex` 类型的复数反三角函数，主要包括以下功能：

* **`casinhl(long double complex z)`:**  计算复数 `z` 的反双曲正弦 (inverse hyperbolic sine)。
* **`casinl(long double complex z)`:**  计算复数 `z` 的反三角正弦 (inverse sine)。
* **`cacosl(long double complex z)`:**  计算复数 `z` 的反三角余弦 (inverse cosine)。
* **`cacoshl(long double complex z)`:** 计算复数 `z` 的反双曲余弦 (inverse hyperbolic cosine)。
* **`catanhl(long double complex z)`:** 计算复数 `z` 的反双曲正切 (inverse hyperbolic tangent)。
* **`catanl(long double complex z)`:**  计算复数 `z` 的反三角正切 (inverse tangent)。

此外，该文件还包含一些静态辅助函数，用于支持上述复数反三角函数的计算，例如 `clog_for_large_values`, `do_hard_work`, `f`, `sum_squares`, `real_part_reciprocal` 等。

**与 Android 功能的关系**

`catrigl.c` 是 Android Bionic 库的一部分，Bionic 库是 Android 系统的 C 标准库、数学库和动态链接器。因此，`catrigl.c` 提供的复数反三角函数是 Android 系统底层数学计算能力的重要组成部分。

**举例说明：**

* **NDK 开发：** 当 Android 开发者使用 NDK (Native Development Kit) 进行原生 C/C++ 开发时，如果他们的应用需要进行复数运算，并且涉及到反三角函数，那么他们就可以直接调用 `libm.so` 中提供的这些函数，例如 `casinhl` 等。
* **Framework 层调用：**  Android Framework 层虽然主要使用 Java 或 Kotlin 编写，但在一些底层的、性能敏感的模块中，也可能会使用 JNI (Java Native Interface) 调用到 native 代码，间接地使用到 `libm.so` 提供的数学函数。例如，一些图形处理、音频处理或科学计算相关的 Framework 组件可能会用到复数运算。

**libc 函数的实现详解**

我们以 `casinhl(long double complex z)` 为例，详细解释其实现逻辑：

1. **输入处理：**
   - 从复数 `z` 中提取实部 `x` 和虚部 `y`。
   - 计算实部和虚部的绝对值 `ax` 和 `ay`。
   - 处理 `NaN` (非数字) 和无穷大 (`Infinity`) 的特殊情况。如果输入包含 `NaN`，则返回 `NaN`；如果实部或虚部是无穷大，则返回相应的无穷大复数。

2. **大数值优化 (`clog_for_large_values`)：**
   - 如果输入复数的模非常大（`ax > RECIP_EPSILON` 或 `ay > RECIP_EPSILON`），则调用 `clog_for_large_values` 函数来计算复数的自然对数，并基于对数结果计算反双曲正弦。这种优化避免了直接计算大数值的平方根等可能导致溢出的操作。
   - `clog_for_large_values` 的实现会根据实部和虚部的大小关系以及绝对值的大小采取不同的计算策略，以保证精度和避免溢出。

3. **小数值优化：**
   - 如果输入复数的实部和虚部都非常小（`ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4`），则直接返回输入 `z`，因为对于接近于零的值，`asinh(z)` 近似等于 `z`。

4. **核心计算 (`do_hard_work`)：**
   - 对于一般情况，调用 `do_hard_work` 函数执行核心的计算逻辑。
   - `do_hard_work` 函数的实现基于引用的论文 "Implementing the complex arcsine and arccosine functions using exception handling"。它通过计算一系列中间变量 (`R`, `S`, `A`, `B`, `sqrt_A2my2`) 来逼近结果。
   - 函数内部会根据不同的输入范围采用不同的计算方法，例如：
     - 当 `A` 较小时，会根据 `x` 和 `y` 的相对大小选择不同的公式计算 `rx` (结果的实部绝对值)。
     - 当 `y` 很小时，会设置一个标志 `B_is_usable` 来指示是否可以使用变量 `B` 进行后续计算。
     - 如果 `B` 的值超过某个阈值，也会调整计算策略。

5. **结果计算：**
   - 根据 `do_hard_work` 计算出的中间结果，计算反双曲正弦的实部 `rx` 和虚部 `ry`。
   - 如果 `B_is_usable` 为真，则使用 `asinl(B)` 计算虚部 `ry`。
   - 否则，使用 `atan2l(new_y, sqrt_A2my2)` 计算虚部 `ry`。
   - 使用 `copysignl` 函数根据输入 `z` 的实部和虚部的符号来确定结果的实部和虚部的符号。

6. **返回结果：**
   - 使用 `CMPLXL` 宏构造复数结果并返回。

其他复数反三角函数的实现也类似，会根据其数学定义调用 `do_hard_work` 或其他辅助函数进行计算，并处理各种特殊情况。

**动态链接功能及处理过程**

`catrigl.c` 本身不直接涉及动态链接的代码，但它编译后生成的代码会包含在 `libm.so` 共享库中，而 `libm.so` 的加载和链接是由 Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 负责的。

**`libm.so` 布局样本：**

```
libm.so:
  .text          # 存放机器指令
    ...
    casinhl 的机器码
    casinl 的机器码
    cacosl 的机器码
    ...
    clog_for_large_values 的机器码
    ...
  .rodata        # 存放只读数据，例如字符串常量、全局常量
    ...
    A_crossover 的值
    B_crossover 的值
    ...
  .data          # 存放已初始化的全局变量和静态变量
    ...
  .bss           # 存放未初始化的全局变量和静态变量
    ...
  .dynamic       # 存放动态链接信息，例如依赖库、符号表位置等
    ...
  .symtab        # 符号表，包含导出的函数和变量的名称和地址
    ...
    casinhl 的符号
    casinl 的符号
    cacosl 的符号
    ...
  .strtab        # 字符串表，存放符号表中使用的字符串
    ...
  ...
```

**链接处理过程：**

1. **加载：** 当一个应用程序（例如使用 NDK 开发的应用）启动并尝试调用 `casinhl` 函数时，如果该函数不在应用程序自身的代码中，则操作系统会检查应用程序依赖的共享库列表。
2. **查找：** 动态链接器会查找 `libm.so` 库，如果尚未加载，则将其加载到内存中。
3. **符号解析：** 动态链接器会在 `libm.so` 的符号表 (`.symtab`) 中查找 `casinhl` 函数的符号。
4. **重定位：**  一旦找到符号，动态链接器会更新应用程序代码中对 `casinhl` 函数的调用地址，使其指向 `libm.so` 中 `casinhl` 函数的实际地址。这个过程称为重定位。
5. **调用：** 应用程序最终成功调用 `libm.so` 中实现的 `casinhl` 函数。

**逻辑推理、假设输入与输出**

**假设输入：** `z = 1.0 + 1.0i`  (实部为 1.0，虚部为 1.0 的复数)

**调用函数：** `casinhl(z)`

**逻辑推理：**

- 由于输入的实部和虚部都不是很大，也不会很小，`casinhl` 函数会调用 `do_hard_work` 进行核心计算。
- `do_hard_work` 会计算中间变量 `R` 和 `S`：
  - `R = hypotl(1.0, 1.0 + 1.0) = hypotl(1.0, 2.0) = sqrt(1^2 + 2^2) = sqrt(5)`
  - `S = hypotl(1.0, 1.0 - 1.0) = hypotl(1.0, 0.0) = sqrt(1^2 + 0^2) = 1`
- 计算 `A = (R + S) / 2 = (sqrt(5) + 1) / 2`
- 根据 `A` 的值选择不同的计算路径。
- 最终会计算出 `rx` 和 `ry`，并根据输入 `z` 的符号确定结果的符号。

**假设输出（近似值）：** `casinhl(1.0 + 1.0i) ≈ 1.061275061905037 - 0.6662394324925153i`

**用户或编程常见的使用错误**

1. **输入参数类型错误：**  将 `float complex` 或 `double complex` 类型的复数传递给需要 `long double complex` 的函数，可能导致精度损失或编译错误。
2. **忽略 NaN 和无穷大：**  没有正确处理输入为 `NaN` 或无穷大的情况，可能导致程序崩溃或产生非预期的结果。例如：
   ```c
   #include <complex.h>
   #include <stdio.h>

   int main() {
       long double complex z = CMPLXL(INFINITY, 1.0);
       long double complex result = casinhl(z);
       printf("casinhl(infinity + 1.0i) = %Lf + %Lfi\n", creall(result), cimagl(result)); // 可能输出 inf + infi
       return 0;
   }
   ```
3. **精度问题：**  在对精度要求较高的场景中，可能需要仔细考虑 `long double` 的精度限制。
4. **误解反三角函数的定义域和值域：**  例如，反余弦函数 `acos` 的值域是 `[0, π]`，反双曲正弦函数 `asinh` 的值域是实数域。对于复数反三角函数，其值域更加复杂，需要查阅相关文档。

**Android Framework 或 NDK 如何到达这里**

**NDK 路径：**

1. **NDK 应用代码：** 开发者在 NDK 项目中使用 `<complex.h>` 头文件，并调用 `casinhl` 等函数。
   ```c++
   #include <complex.h>
   #include <stdio.h>

   int main() {
       long double complex z = 1.0 + 1.0i;
       long double complex result = casinhl(z);
       printf("casinhl(1.0 + 1.0i) = %Lf + %Lfi\n", creall(result), cimagl(result));
       return 0;
   }
   ```
2. **编译链接：** NDK 的构建系统（通常使用 CMake 或 ndk-build）会将 C++ 代码编译成机器码，并链接到 Android 系统提供的共享库，包括 `libm.so`。链接器会解析对 `casinhl` 等符号的引用。
3. **运行时加载：** 当应用在 Android 设备上运行时，Android 的动态链接器会加载 `libm.so`，并将应用代码中对 `casinhl` 的调用链接到 `libm.so` 中 `catrigl.o` 编译生成的代码。

**Framework 路径（示例，较为间接）：**

1. **Java/Kotlin Framework 代码：** Android Framework 中某个组件（例如，处理音频或图形的 native 代码）可能需要进行复数运算。
2. **JNI 调用：** Framework 通过 JNI 调用到 native 代码。
3. **Native 代码调用 libm：**  Native 代码中包含了对 `casinhl` 等函数的调用。
4. **动态链接：**  与 NDK 应用类似，这些调用最终会通过动态链接器链接到 `libm.so` 中的实现。

**Frida Hook 示例**

可以使用 Frida 来 hook `casinhl` 函数，查看其输入和输出，或者修改其行为：

```python
import frida
import sys

package_name = "your.application.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libm.so", "casinhl"), {
    onEnter: function(args) {
        this.z = {
            real: args[0],
            imag: args[1]
        };
        console.log("[*] Called casinhl with z = " + this.z.real + " + " + this.z.imag + "i");
    },
    onLeave: function(retval) {
        console.log("[*] casinhl returned: " + retval.real + " + " + retval.imag + "i");
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释：**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到运行在 USB 设备上的目标应用进程。
2. **`Module.findExportByName("libm.so", "casinhl")`:**  在 `libm.so` 模块中查找名为 `casinhl` 的导出函数。
3. **`Interceptor.attach(...)`:**  拦截对 `casinhl` 函数的调用。
4. **`onEnter`:** 在 `casinhl` 函数执行之前调用，可以访问函数参数。对于复数函数，参数通常是两个 `long double`，分别表示实部和虚部。
5. **`onLeave`:** 在 `casinhl` 函数执行之后调用，可以访问返回值。返回值通常也是两个 `long double`，表示结果的实部和虚部。
6. **`console.log(...)`:**  在 Frida 的控制台中打印信息。

通过这个 Frida 脚本，你可以监控你的应用在调用 `casinhl` 函数时的输入和输出，从而进行调试和分析。

希望以上详细的解释能够帮助你理解 `bionic/libm/upstream-freebsd/lib/msun/src/catrigl.c` 文件的功能、与 Android 的关系、实现细节以及调试方法。

Prompt: 
```
这是目录为bionic/libm/upstream-freebsd/lib/msun/src/catrigl.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (c) 2012 Stephen Montgomery-Smith <stephen@FreeBSD.ORG>
 * Copyright (c) 2017 Mahdi Mokhtari <mmokhi@FreeBSD.org>
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

/*
 * The algorithm is very close to that in "Implementing the complex arcsine
 * and arccosine functions using exception handling" by T. E. Hull, Thomas F.
 * Fairgrieve, and Ping Tak Peter Tang, published in ACM Transactions on
 * Mathematical Software, Volume 23 Issue 3, 1997, Pages 299-335,
 * http://dl.acm.org/citation.cfm?id=275324.
 *
 * See catrig.c for complete comments.
 *
 * XXX comments were removed automatically, and even short ones on the right
 * of statements were removed (all of them), contrary to normal style.  Only
 * a few comments on the right of declarations remain.
 */

#include <complex.h>
#include <float.h>

#include "invtrig.h"
#include "math.h"
#include "math_private.h"

#undef isinf
#define isinf(x)	(fabsl(x) == INFINITY)
#undef isnan
#define isnan(x)	((x) != (x))
#define	raise_inexact()	do { volatile float junk __unused = 1 + tiny; } while(0)
#undef signbit
#define signbit(x)	(__builtin_signbitl(x))

#if LDBL_MAX_EXP != 0x4000
#error "Unsupported long double format"
#endif

static const long double
A_crossover =		10,
B_crossover =		0.6417,
FOUR_SQRT_MIN =		0x1p-8189L,
HALF_MAX =		0x1p16383L,
QUARTER_SQRT_MAX =	0x1p8189L,
RECIP_EPSILON =		1 / LDBL_EPSILON,
SQRT_MIN =		0x1p-8191L;

#if LDBL_MANT_DIG == 64
static const union IEEEl2bits
um_e =		LD80C(0xadf85458a2bb4a9b,  1, 2.71828182845904523536e+0L),
um_ln2 =	LD80C(0xb17217f7d1cf79ac, -1, 6.93147180559945309417e-1L);
#define		m_e	um_e.e
#define		m_ln2	um_ln2.e
static const long double
/* The next 2 literals for non-i386.  Misrounding them on i386 is harmless. */
SQRT_3_EPSILON = 5.70316273435758915310e-10,	/*  0x9cc470a0490973e8.0p-94 */
SQRT_6_EPSILON = 8.06549008734932771664e-10;	/*  0xddb3d742c265539e.0p-94 */
#elif LDBL_MANT_DIG == 113
static const long double
m_e =		2.71828182845904523536028747135266250e0L,	/* 0x15bf0a8b1457695355fb8ac404e7a.0p-111 */
m_ln2 =		6.93147180559945309417232121458176568e-1L,	/* 0x162e42fefa39ef35793c7673007e6.0p-113 */
SQRT_3_EPSILON = 2.40370335797945490975336727199878124e-17,	/*  0x1bb67ae8584caa73b25742d7078b8.0p-168 */
SQRT_6_EPSILON = 3.39934988877629587239082586223300391e-17;	/*  0x13988e1409212e7d0321914321a55.0p-167 */
#else
#error "Unsupported long double format"
#endif

static const volatile float
tiny =			0x1p-100;

static long double complex clog_for_large_values(long double complex z);

static inline long double
f(long double a, long double b, long double hypot_a_b)
{
	if (b < 0)
		return ((hypot_a_b - b) / 2);
	if (b == 0)
		return (a / 2);
	return (a * a / (hypot_a_b + b) / 2);
}

static inline void
do_hard_work(long double x, long double y, long double *rx, int *B_is_usable,
    long double *B, long double *sqrt_A2my2, long double *new_y)
{
	long double R, S, A;
	long double Am1, Amy;

	R = hypotl(x, y + 1);
	S = hypotl(x, y - 1);

	A = (R + S) / 2;
	if (A < 1)
		A = 1;

	if (A < A_crossover) {
		if (y == 1 && x < LDBL_EPSILON * LDBL_EPSILON / 128) {
			*rx = sqrtl(x);
		} else if (x >= LDBL_EPSILON * fabsl(y - 1)) {
			Am1 = f(x, 1 + y, R) + f(x, 1 - y, S);
			*rx = log1pl(Am1 + sqrtl(Am1 * (A + 1)));
		} else if (y < 1) {
			*rx = x / sqrtl((1 - y) * (1 + y));
		} else {
			*rx = log1pl((y - 1) + sqrtl((y - 1) * (y + 1)));
		}
	} else {
		*rx = logl(A + sqrtl(A * A - 1));
	}

	*new_y = y;

	if (y < FOUR_SQRT_MIN) {
		*B_is_usable = 0;
		*sqrt_A2my2 = A * (2 / LDBL_EPSILON);
		*new_y = y * (2 / LDBL_EPSILON);
		return;
	}

	*B = y / A;
	*B_is_usable = 1;

	if (*B > B_crossover) {
		*B_is_usable = 0;
		if (y == 1 && x < LDBL_EPSILON / 128) {
			*sqrt_A2my2 = sqrtl(x) * sqrtl((A + y) / 2);
		} else if (x >= LDBL_EPSILON * fabsl(y - 1)) {
			Amy = f(x, y + 1, R) + f(x, y - 1, S);
			*sqrt_A2my2 = sqrtl(Amy * (A + y));
		} else if (y > 1) {
			*sqrt_A2my2 = x * (4 / LDBL_EPSILON / LDBL_EPSILON) * y /
			    sqrtl((y + 1) * (y - 1));
			*new_y = y * (4 / LDBL_EPSILON / LDBL_EPSILON);
		} else {
			*sqrt_A2my2 = sqrtl((1 - y) * (1 + y));
		}
	}
}

long double complex
casinhl(long double complex z)
{
	long double x, y, ax, ay, rx, ry, B, sqrt_A2my2, new_y;
	int B_is_usable;
	long double complex w;

	x = creall(z);
	y = cimagl(z);
	ax = fabsl(x);
	ay = fabsl(y);

	if (isnan(x) || isnan(y)) {
		if (isinf(x))
			return (CMPLXL(x, y + y));
		if (isinf(y))
			return (CMPLXL(y, x + x));
		if (y == 0)
			return (CMPLXL(x + x, y));
		return (CMPLXL(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON) {
		if (signbit(x) == 0)
			w = clog_for_large_values(z) + m_ln2;
		else
			w = clog_for_large_values(-z) + m_ln2;
		return (CMPLXL(copysignl(creall(w), x),
		    copysignl(cimagl(w), y)));
	}

	if (x == 0 && y == 0)
		return (z);

	raise_inexact();

	if (ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4)
		return (z);

	do_hard_work(ax, ay, &rx, &B_is_usable, &B, &sqrt_A2my2, &new_y);
	if (B_is_usable)
		ry = asinl(B);
	else
		ry = atan2l(new_y, sqrt_A2my2);
	return (CMPLXL(copysignl(rx, x), copysignl(ry, y)));
}

long double complex
casinl(long double complex z)
{
	long double complex w;

	w = casinhl(CMPLXL(cimagl(z), creall(z)));
	return (CMPLXL(cimagl(w), creall(w)));
}

long double complex
cacosl(long double complex z)
{
	long double x, y, ax, ay, rx, ry, B, sqrt_A2mx2, new_x;
	int sx, sy;
	int B_is_usable;
	long double complex w;

	x = creall(z);
	y = cimagl(z);
	sx = signbit(x);
	sy = signbit(y);
	ax = fabsl(x);
	ay = fabsl(y);

	if (isnan(x) || isnan(y)) {
		if (isinf(x))
			return (CMPLXL(y + y, -INFINITY));
		if (isinf(y))
			return (CMPLXL(x + x, -y));
		if (x == 0)
			return (CMPLXL(pio2_hi + pio2_lo, y + y));
		return (CMPLXL(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON) {
		w = clog_for_large_values(z);
		rx = fabsl(cimagl(w));
		ry = creall(w) + m_ln2;
		if (sy == 0)
			ry = -ry;
		return (CMPLXL(rx, ry));
	}

	if (x == 1 && y == 0)
		return (CMPLXL(0, -y));

	raise_inexact();

	if (ax < SQRT_6_EPSILON / 4 && ay < SQRT_6_EPSILON / 4)
		return (CMPLXL(pio2_hi - (x - pio2_lo), -y));

	do_hard_work(ay, ax, &ry, &B_is_usable, &B, &sqrt_A2mx2, &new_x);
	if (B_is_usable) {
		if (sx == 0)
			rx = acosl(B);
		else
			rx = acosl(-B);
	} else {
		if (sx == 0)
			rx = atan2l(sqrt_A2mx2, new_x);
		else
			rx = atan2l(sqrt_A2mx2, -new_x);
	}
	if (sy == 0)
		ry = -ry;
	return (CMPLXL(rx, ry));
}

long double complex
cacoshl(long double complex z)
{
	long double complex w;
	long double rx, ry;

	w = cacosl(z);
	rx = creall(w);
	ry = cimagl(w);
	if (isnan(rx) && isnan(ry))
		return (CMPLXL(ry, rx));
	if (isnan(rx))
		return (CMPLXL(fabsl(ry), rx));
	if (isnan(ry))
		return (CMPLXL(ry, ry));
	return (CMPLXL(fabsl(ry), copysignl(rx, cimagl(z))));
}

static long double complex
clog_for_large_values(long double complex z)
{
	long double x, y;
	long double ax, ay, t;

	x = creall(z);
	y = cimagl(z);
	ax = fabsl(x);
	ay = fabsl(y);
	if (ax < ay) {
		t = ax;
		ax = ay;
		ay = t;
	}

	if (ax > HALF_MAX)
		return (CMPLXL(logl(hypotl(x / m_e, y / m_e)) + 1,
		    atan2l(y, x)));

	if (ax > QUARTER_SQRT_MAX || ay < SQRT_MIN)
		return (CMPLXL(logl(hypotl(x, y)), atan2l(y, x)));

	return (CMPLXL(logl(ax * ax + ay * ay) / 2, atan2l(y, x)));
}

static inline long double
sum_squares(long double x, long double y)
{

	if (y < SQRT_MIN)
		return (x * x);

	return (x * x + y * y);
}

static inline long double
real_part_reciprocal(long double x, long double y)
{
	long double scale;
	uint16_t hx, hy;
	int16_t ix, iy;

	GET_LDBL_EXPSIGN(hx, x);
	ix = hx & 0x7fff;
	GET_LDBL_EXPSIGN(hy, y);
	iy = hy & 0x7fff;
#define	BIAS	(LDBL_MAX_EXP - 1)
#define	CUTOFF	(LDBL_MANT_DIG / 2 + 1)
	if (ix - iy >= CUTOFF || isinf(x))
		return (1 / x);
	if (iy - ix >= CUTOFF)
		return (x / y / y);
	if (ix <= BIAS + LDBL_MAX_EXP / 2 - CUTOFF)
		return (x / (x * x + y * y));
	scale = 1;
	SET_LDBL_EXPSIGN(scale, 0x7fff - ix);
	x *= scale;
	y *= scale;
	return (x / (x * x + y * y) * scale);
}

long double complex
catanhl(long double complex z)
{
	long double x, y, ax, ay, rx, ry;

	x = creall(z);
	y = cimagl(z);
	ax = fabsl(x);
	ay = fabsl(y);

	if (y == 0 && ax <= 1)
		return (CMPLXL(atanhl(x), y));

	if (x == 0)
		return (CMPLXL(x, atanl(y)));

	if (isnan(x) || isnan(y)) {
		if (isinf(x))
			return (CMPLXL(copysignl(0, x), y + y));
		if (isinf(y))
			return (CMPLXL(copysignl(0, x),
			    copysignl(pio2_hi + pio2_lo, y)));
		return (CMPLXL(nan_mix(x, y), nan_mix(x, y)));
	}

	if (ax > RECIP_EPSILON || ay > RECIP_EPSILON)
		return (CMPLXL(real_part_reciprocal(x, y),
		    copysignl(pio2_hi + pio2_lo, y)));

	if (ax < SQRT_3_EPSILON / 2 && ay < SQRT_3_EPSILON / 2) {
		raise_inexact();
		return (z);
	}

	if (ax == 1 && ay < LDBL_EPSILON)
		rx = (m_ln2 - logl(ay)) / 2;
	else
		rx = log1pl(4 * ax / sum_squares(ax - 1, ay)) / 4;

	if (ax == 1)
		ry = atan2l(2, -ay) / 2;
	else if (ay < LDBL_EPSILON)
		ry = atan2l(2 * ay, (1 - ax) * (1 + ax)) / 2;
	else
		ry = atan2l(2 * ay, (1 - ax) * (1 + ax) - ay * ay) / 2;

	return (CMPLXL(copysignl(rx, x), copysignl(ry, y)));
}

long double complex
catanl(long double complex z)
{
	long double complex w;

	w = catanhl(CMPLXL(cimagl(z), creall(z)));
	return (CMPLXL(cimagl(w), creall(w)));
}

"""

```
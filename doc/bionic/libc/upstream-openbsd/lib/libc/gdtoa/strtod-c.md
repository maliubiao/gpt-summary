Response:
Let's break down the thought process for analyzing the `strtod.c` code.

**1. Understanding the Core Request:**

The main goal is to understand the functionality of this specific `strtod.c` file within the Android Bionic library. This involves identifying its purpose, explaining its implementation details, noting Android-specific connections, discussing dynamic linking, addressing common errors, and providing debugging strategies.

**2. Initial Code Inspection and Keyword Identification:**

The first step is to quickly scan the code, looking for familiar keywords, function names, and patterns. This immediately reveals:

* **`strtod` function signature:** This confirms the primary function is string-to-double conversion.
* **Include headers:**  `gdtoaimp.h`, `fenv.h`, `locale.h`. These hints at dependencies related to floating-point arithmetic, environment flags, and locale settings.
* **Preprocessor directives:**  `#ifdef`, `#ifndef`, `#define`. These indicate conditional compilation, suggesting different build configurations or platform-specific behavior. Keywords like `IEEE_Arith`, `Avoid_Underflow`, `USE_LOCALE`, `Honor_FLT_ROUNDS` stand out as significant flags.
* **Floating-point constants and types:**  `double`, `Long`, `ULong`, `U`, `Bigint`, and constants like `Exp_mask`, `Frac_mask`, `DBL_DIG`, `DBL_MAX_EXP`. This confirms the focus on precise floating-point conversion.
* **Error handling:**  References to `errno` and `ERANGE`.
* **Function calls within `strtod`:**  `localeconv()`, `strlen()`, `strdup()`, `gethex()`, `s2b()`, `d2b()`, `i2b()`, `pow5mult()`, `mult()`, `lshift()`, `diff()`, `cmp()`, `ratio()`, `ulp()`, `sulp()`. These are internal helper functions or standard library functions crucial for the conversion process.

**3. High-Level Functionality Identification:**

Based on the function signature and the keywords, it's clear that `strtod` converts a string representation to a `double` (double-precision floating-point) number.

**4. Deeper Dive into Implementation Details:**

The next step is to analyze the code blocks within `strtod`, focusing on the different stages of the conversion:

* **Initial whitespace and sign handling:** The code skips leading whitespace and identifies the sign (+ or -).
* **Hexadecimal number parsing (optional):** The code checks for "0x" or "0X" and calls `gethex` if found. This is an Android-specific enhancement from OpenBSD.
* **Decimal number parsing:** This is the main part. The code separates the integer part, the fractional part (if any), and handles the decimal point.
* **Exponent parsing:**  It looks for 'e' or 'E' followed by an optional sign and exponent value.
* **Special values (Infinity and NaN):**  The code checks for "inf", "infinity", and "nan".
* **Conversion to floating-point:**  This is the most complex part, involving multiple steps:
    * **Initial approximation:** A quick conversion using built-in `double` types.
    * **Handling large exponents:**  Multiplying or dividing by powers of 10.
    * **Precise conversion using `Bigint`:**  For higher accuracy, the code uses arbitrary-precision integers (`Bigint`) to represent the parsed number and the current floating-point value. This helps handle cases where direct `double` operations might lose precision.
    * **Error calculation and adjustment:**  The code calculates the difference between the precise value and the current approximation, then adjusts the approximation using functions like `ratio` and `ulp` (units in the last place) to achieve the correct rounding according to the current floating-point rounding mode. This involves careful consideration of different rounding modes (round to nearest even, round towards zero, round up, round down).
    * **Underflow and overflow handling:** The code checks for potential underflow and overflow conditions and sets the appropriate result (0.0 or infinity).

**5. Identifying Android-Specific Connections:**

The most obvious connection is that this `strtod.c` *is* part of Android's C library (Bionic). Specific examples include:

* **Bionic as the C library:**  Emphasize that Bionic provides the standard C library functions.
* **Dynamic linker involvement:**  Mention that `strtod` is a library function and thus loaded and linked by the dynamic linker.
* **`gethex` function:** Note that the inclusion of hexadecimal floating-point parsing is an Android addition.

**6. Explaining `libc` Functions:**

The core of the explanation involves detailing the purpose and implementation of the internal helper functions like `s2b`, `d2b`, `i2b`, `pow5mult`, `mult`, `lshift`, `diff`, `cmp`, `ratio`, `ulp`, and `sulp`. This requires understanding:

* **`Bigint` representation:** How arbitrary-precision integers are stored.
* **Conversion between string and `Bigint` (`s2b`).**
* **Conversion between `double` and `Bigint` (`d2b`).**
* **Basic `Bigint` arithmetic:** Multiplication, shifting, difference, comparison.
* **Calculating the unit in the last place (`ulp`).**

**7. Dynamic Linker Aspects:**

This involves explaining how `strtod` is loaded and linked at runtime:

* **SO layout:** Describe a typical `.so` file structure with sections like `.text`, `.data`, `.bss`, `.dynsym`, `.plt`, `.got`.
* **Linking process:** Explain symbol resolution, relocation, and how the Global Offset Table (GOT) and Procedure Linkage Table (PLT) facilitate dynamic linking.

**8. Common Errors and Examples:**

Brainstorm potential user errors when using `strtod`:

* **Invalid input format:**  Strings that cannot be parsed as numbers.
* **Overflow/underflow:**  Numbers too large or too small to represent.
* **Locale issues:**  Incorrect decimal separators.

Provide concrete code examples for each error.

**9. Android Framework/NDK and Frida Hooking:**

Trace how a call to `strtod` might originate in Android:

* **Framework:**  Example scenarios like parsing configuration files or handling user input.
* **NDK:**  C/C++ code using standard library functions.
* **Frida:**  Demonstrate how to hook `strtod`, inspect arguments, and modify the return value using a JavaScript example.

**10. Structuring the Output:**

Organize the information logically with clear headings and subheadings. Use bullet points, code blocks, and explanations to enhance readability. Ensure the language is clear and concise.

**Self-Correction/Refinement during the process:**

* **Initial scope:** Might initially focus too much on the overall `libc`. Refocus on the *specific* `strtod.c` file.
* **Technical depth:** Adjust the level of detail based on the presumed audience. Provide more detailed explanations for complex concepts like `Bigint` arithmetic and dynamic linking if needed.
* **Android specifics:** Ensure the examples and explanations are relevant to the Android context.
* **Clarity and accuracy:** Review the explanations for technical accuracy and ensure the language is easy to understand. Double-check code examples for correctness.

By following this systematic approach, one can thoroughly analyze and explain the functionality of a complex piece of code like `strtod.c`.
这个文件 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/strtod.c` 是 Android Bionic C 库中的一个源代码文件，其核心功能是将一个字符串转换为一个双精度浮点数 (`double`)。 这个实现是从 OpenBSD 的 `libc` 中上游引入的。

下面我将详细列举它的功能，并结合 Android 的特性进行说明：

**1. 核心功能：字符串到 `double` 的转换**

* **功能描述:**  `strtod(const char *nptr, char **endptr)` 函数接受一个字符串 `nptr` 作为输入，尝试将其解析为一个 `double` 类型的浮点数。它会跳过前导的空白字符，然后尝试解析可选的正负号，以及数字部分（包括整数部分和小数部分），以及可选的指数部分。
* **Android 关联:** Android 上的任何需要将用户输入、配置文件或者其他字符串数据转换为 `double` 类型的场景都会用到这个函数。例如：
    * **Java 层通过 JNI 调用本地代码:** Java 代码可以使用 `Double.parseDouble()` 方法将字符串转换为 `double`，而这个方法在底层很可能会通过 JNI 调用到 Bionic 库中的 `strtod`。
    * **NDK 开发:** 使用 Android NDK 进行 C/C++ 开发时，可以使用标准 C 库的 `strtod` 函数。
    * **系统服务和守护进程:** Android 系统中的各种服务和守护进程在解析配置文件或处理命令行参数时，可能会使用 `strtod` 来转换数字字符串。

**2. 支持多种数字格式**

* **功能描述:**  `strtod` 不仅能解析标准的十进制浮点数，还能处理：
    * **可选的正负号:**  允许字符串以 `+` 或 `-` 开头。
    * **整数和小数部分:**  正确解析小数点前后的数字。
    * **指数部分:**  支持 `e` 或 `E` 后跟可选符号的指数。例如 "1.23e+4"。
    * **前导零:**  能够处理前导零，例如 "00123"。
    * **无穷大 (Infinity):**  识别 "inf" 或 "infinity"（忽略大小写）。
    * **非数字 (NaN):**  识别 "nan"（忽略大小写）。
    * **十六进制浮点数 (Android 扩展):**  这个版本包含了对十六进制浮点数的支持，格式为 "0x" 或 "0X" 开头，后跟十六进制数字和可选的二进制指数。例如 "0x1.ffffp10"。 这是与上游 OpenBSD 相比，Android Bionic 的一个显著增强。
* **Android 关联:**  对十六进制浮点数的支持在某些特定的底层编程或硬件相关的场景可能有用，例如处理硬件返回的特定格式的浮点数。虽然不如十进制浮点数常用，但扩展了 `strtod` 的适用范围。

**3. 错误处理**

* **功能描述:**
    * **`endptr` 参数:** 如果 `endptr` 不是 `NULL`，函数会将解析停止的位置的指针写入 `*endptr`。这允许调用者检查是否有未解析的尾部字符。
    * **溢出和下溢:** 当转换结果超出 `double` 类型的表示范围时，会返回 `HUGE_VAL`（正溢出）或 `-HUGE_VAL`（负溢出），并设置全局变量 `errno` 为 `ERANGE`。当结果非常接近零以至于无法用 `double` 精确表示时，会返回 0.0，并可能设置 `errno` 为 `ERANGE`（下溢）。
    * **无法转换:** 如果字符串的起始部分不是有效的数字，则返回 0.0，并且 `*endptr` 的值将等于 `nptr`。
* **Android 关联:**  Android 应用和底层系统代码可以依赖 `strtod` 的错误处理机制来判断输入字符串是否有效，并采取相应的措施。

**4. 本地化支持 (可选)**

* **功能描述:**  代码中包含了对 `locale.h` 的引用，以及 `USE_LOCALE` 相关的宏。这表明 `strtod` 可以根据当前的本地化设置来解析数字，特别是小数点的表示方式。
* **Android 关联:** Android 支持多语言和地区设置。`strtod` 理论上应该能够根据用户的语言设置来识别小数点（例如，某些地区使用逗号作为小数点）。然而，需要注意的是，Android Bionic 中对本地化的支持可能与 glibc 等其他 C 库有所不同，具体行为可能需要进一步测试验证。

**5. 浮点数舍入模式的考虑**

* **功能描述:** 代码中存在 `Honor_FLT_ROUNDS` 宏以及对浮点数舍入模式 (`FE_TOWARDZERO`, `FE_UPWARD`, `FE_DOWNWARD`) 的处理。这表明 `strtod` 的实现考虑了不同的浮点数舍入模式，以确保转换的精度符合 IEEE 754 标准。
* **Android 关联:**  Android 运行的硬件平台和软件环境可能支持不同的浮点数舍入模式。`strtod` 试图尊重这些设置，以提供更精确和可预测的浮点数转换结果。

**详细解释 libc 函数的实现:**

`strtod` 的实现是一个复杂的过程，它涉及到：

1. **预处理:** 跳过空白字符，处理正负号。
2. **数字解析:**  
   - 区分整数部分和小数部分。
   - 处理小数点。
   - 将数字字符转换为数值。
3. **指数解析:**
   - 识别 'e' 或 'E'。
   - 解析指数符号和数值。
4. **特殊值处理:**
   - 识别 "inf"、"infinity" 和 "nan"。
5. **核心转换算法:**
   - **快速路径:** 对于简单的、可以直接用 `double` 类型精确表示的数字，会进行快速转换。
   - **高精度转换:** 对于需要更高精度的数字，`strtod` 使用了 `gdtoa` (Grisu3 Double-To-Ascii) 库（虽然名字是 Double-To-Ascii，但其内部也有用于解析的代码），利用 `Bigint` (大整数) 数据结构进行精确的计算，以避免浮点数运算中的精度损失。
   - **乘以/除以 10 的幂:**  根据指数值，将解析得到的数字乘以或除以 10 的相应幂。为了避免直接进行可能导致精度损失的浮点数乘除法，`strtod` 内部会预先计算好一些常用的 10 的幂的精确表示。
6. **舍入:**  根据当前的浮点数舍入模式，将高精度计算的结果舍入到最接近的 `double` 值。
7. **错误处理:**  检查溢出、下溢和无效输入，并设置 `errno` 和返回相应的值。

**涉及 dynamic linker 的功能:**

`strtod` 是 `libc.so` (或在较新版本 Android 中可能是 `libbase.so` 或其他拆分后的库) 中的一个导出函数。当程序调用 `strtod` 时，动态链接器负责以下处理：

**so 布局样本:**

一个简化的 `libc.so` 布局可能如下：

```
libc.so:
    .text          # 存放可执行代码
        strtod:   # strtod 函数的代码
        ...        # 其他 libc 函数的代码
    .data          # 存放已初始化的全局变量和静态变量
        ...
    .bss           # 存放未初始化的全局变量和静态变量
        ...
    .rodata        # 存放只读数据，例如字符串常量
        ...
    .dynsym        # 动态符号表，包含导出的和导入的符号
        strtod
        ...
    .dynstr        # 动态字符串表，存储符号名称
        strtod
        ...
    .plt           # Procedure Linkage Table，用于延迟绑定
        strtod@plt
        ...
    .got           # Global Offset Table，存储全局变量的地址
        strtod@got
        ...
```

**链接的处理过程:**

1. **编译时:**  当程序代码中调用了 `strtod` 时，编译器会在生成的目标文件中记录下对 `strtod` 的外部符号引用。
2. **链接时:**  链接器（通常是 `lld` 在 Android 上）在创建可执行文件或共享库时，会将所有目标文件链接在一起。对于外部符号，链接器会查找提供这些符号的共享库。
3. **运行时:**
   - **加载:** 当程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会加载程序依赖的共享库，包括 `libc.so`。
   - **符号解析 (延迟绑定):** 默认情况下，Android 使用延迟绑定来提高启动速度。当程序第一次调用 `strtod` 时：
     - 程序会跳转到 `strtod@plt` 中的一段代码。
     - `strtod@plt` 中的代码会跳转到 `strtod@got` 中。最初，`strtod@got` 中存放的是动态链接器的一些辅助代码的地址。
     - 动态链接器被调用，查找 `libc.so` 的 `.dynsym` 表，找到 `strtod` 的实际地址。
     - 动态链接器将 `strtod` 的实际地址写入 `strtod@got`。
     - 程序的调用最终跳转到 `strtod` 的实际代码。
   - **后续调用:**  后续对 `strtod` 的调用会直接跳转到 `strtod@got` 中存储的实际地址，而无需再次进行符号解析。

**假设输入与输出:**

* **输入:** `"123.45"`
   **输出:** `123.45`
* **输入:** `"-0.001"`
   **输出:** `-0.001`
* **输入:** `"1.23e+5"`
   **输出:** `123000.0`
* **输入:** `"inf"`
   **输出:** `HUGE_VAL` (正无穷大)
* **输入:** `"nan"`
   **输出:**  表示 NaN 的 `double` 值
* **输入:** `"0x1.8p+3"` (Android 支持的十六进制浮点数)
   **输出:** `12.0` (因为 1.5 * 2^3 = 1.5 * 8 = 12)
* **输入:** `"invalid"`
   **输出:** `0.0`，`endptr` 指向 `"invalid"` 的起始位置。
* **输入:** `"1.0e1000"` (超出 `double` 表示范围)
   **输出:** `HUGE_VAL`，`errno` 被设置为 `ERANGE`。

**用户或编程常见的使用错误:**

1. **未检查 `endptr`:** 用户可能假设 `strtod` 会完全解析整个字符串，而没有检查 `endptr` 来判断是否有无效的尾部字符。
   ```c
   char *str = "123.45abc";
   double val = strtod(str, NULL); // 错误：未检查 endptr
   // 假设 val 为 123.45，但 "abc" 没有被处理
   ```
   **正确做法:**
   ```c
   char *str = "123.45abc";
   char *endptr;
   double val = strtod(str, &endptr);
   if (str == endptr) {
       // 没有数字被转换
       fprintf(stderr, "转换失败\n");
   } else if (*endptr != '\0') {
       // 存在未转换的尾部字符
       fprintf(stderr, "部分转换，剩余字符串: %s\n", endptr);
   } else {
       printf("转换成功，值为: %f\n", val);
   }
   ```

2. **忽略溢出和下溢:** 用户可能没有检查 `errno` 的值，从而忽略了转换过程中发生的溢出或下溢错误。
   ```c
   char *str_overflow = "1.0e1000";
   double val_overflow = strtod(str_overflow, NULL);
   if (val_overflow == HUGE_VAL || val_overflow == -HUGE_VAL) {
       if (errno == ERANGE) {
           fprintf(stderr, "发生溢出\n");
       }
   }

   char *str_underflow = "1.0e-1000";
   double val_underflow = strtod(str_underflow, NULL);
   if (val_underflow == 0.0 && errno == ERANGE) {
       fprintf(stderr, "发生下溢\n");
   }
   ```

3. **假设特定的本地化设置:**  如果代码没有明确处理本地化，可能会在不同的地区设置下产生不同的解析结果。虽然 Android Bionic 的 `strtod` 应该考虑本地化，但依赖于特定的本地化行为可能导致跨平台问题。

**Android Framework 或 NDK 如何到达这里，Frida hook 示例:**

**Android Framework:**

1. **Java 代码:** Android Framework 中的 Java 代码，例如处理用户输入或解析配置文件时，可能会使用 `Double.parseDouble()`。
2. **JNI 调用:** `Double.parseDouble()` 方法最终会通过 Java Native Interface (JNI) 调用到 Android Runtime (ART) 或 Dalvik 虚拟机中的本地代码。
3. **`libjavacrypto.so` 或其他库:**  虚拟机内部或者其他 Framework 相关的本地库可能会调用到 Bionic 的 `strtod`。

**NDK:**

1. **C/C++ 代码:** NDK 开发的应用可以直接在 C/C++ 代码中调用标准 C 库的 `strtod` 函数。
2. **链接到 `libc.so`:**  NDK 构建系统会将应用链接到 Bionic 的 `libc.so` 或相关的库。
3. **运行时调用:** 当应用执行到调用 `strtod` 的代码时，动态链接器会加载 `libc.so` 并解析 `strtod` 的地址，然后执行 `strtod` 的代码。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `strtod` 函数的 JavaScript 示例：

```javascript
if (Process.platform === 'android') {
  const strtodPtr = Module.findExportByName("libc.so", "strtod");
  if (strtodPtr) {
    Interceptor.attach(strtodPtr, {
      onEnter: function (args) {
        const nptr = args[0].readCString();
        console.log(`[strtod] Called with string: ${nptr}`);
        this.nptr = nptr; // 保存输入字符串
      },
      onLeave: function (retval) {
        console.log(`[strtod] Returning value: ${retval}`);
        // 可以修改返回值
        // retval.replace(parseFloat(this.nptr) + 1.0);
      }
    });
    console.log("[Frida] strtod hooked successfully!");
  } else {
    console.error("[Frida] Failed to find strtod in libc.so");
  }
} else {
  console.log("[Frida] This script is for Android only.");
}
```

**解释 Frida Hook 代码:**

1. **检查平台:**  `Process.platform === 'android'` 确保脚本只在 Android 环境下运行。
2. **查找 `strtod` 地址:** `Module.findExportByName("libc.so", "strtod")` 尝试在 `libc.so` 中找到 `strtod` 函数的地址。
3. **附加 Interceptor:** `Interceptor.attach()` 用于在 `strtod` 函数的入口和出口处执行自定义的 JavaScript 代码。
4. **`onEnter` 函数:**
   - `args[0]` 是 `strtod` 的第一个参数 `nptr` 的地址。
   - `args[0].readCString()` 读取 `nptr` 指向的 C 字符串。
   - 打印调用信息，并保存输入字符串到 `this.nptr`，以便在 `onLeave` 中使用。
5. **`onLeave` 函数:**
   - `retval` 是 `strtod` 的返回值地址。
   - 打印返回值。
   - 可以使用 `retval.replace()` 修改返回值（例如，将返回值替换为输入值加 1.0）。
6. **错误处理:**  检查是否成功找到 `strtod` 函数。

通过这个 Frida 脚本，你可以在 Android 应用运行时拦截对 `strtod` 的调用，查看传递给它的字符串参数以及它返回的浮点数值，甚至可以动态修改其行为，这对于调试和逆向工程非常有用。

总结来说，`bionic/libc/upstream-openbsd/lib/libc/gdtoa/strtod.c` 文件在 Android 中扮演着至关重要的角色，负责将字符串转换为 `double` 类型，并且考虑了多种数字格式、错误处理和浮点数舍入模式。理解其功能和实现细节对于 Android 开发人员和安全研究人员都非常有价值。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/strtod.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/****************************************************************

The author of this software is David M. Gay.

Copyright (C) 1998-2001 by Lucent Technologies
All Rights Reserved

Permission to use, copy, modify, and distribute this software and
its documentation for any purpose and without fee is hereby
granted, provided that the above copyright notice appear in all
copies and that both that the copyright notice and this
permission notice and warranty disclaimer appear in supporting
documentation, and that the name of Lucent or any of its entities
not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

LUCENT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL LUCENT OR ANY OF ITS ENTITIES BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

****************************************************************/

/* Please send bug reports to David M. Gay (dmg at acm dot org,
 * with " at " changed at "@" and " dot " changed to ".").	*/

#include "gdtoaimp.h"
#ifndef NO_FENV_H
#include <fenv.h>
#endif

#ifdef USE_LOCALE
#include "locale.h"
#endif

#ifdef IEEE_Arith
#ifndef NO_IEEE_Scale
#define Avoid_Underflow
#undef tinytens
/* The factor of 2^106 in tinytens[4] helps us avoid setting the underflow */
/* flag unnecessarily.  It leads to a song and dance at the end of strtod. */
static CONST double tinytens[] = { 1e-16, 1e-32, 1e-64, 1e-128,
		9007199254740992.*9007199254740992.e-256
		};
#endif
#endif

#ifdef Honor_FLT_ROUNDS
#undef Check_FLT_ROUNDS
#define Check_FLT_ROUNDS
#else
#define Rounding Flt_Rounds
#endif

#ifdef Avoid_Underflow /*{*/
 static double
sulp
#ifdef KR_headers
	(x, scale) U *x; int scale;
#else
	(U *x, int scale)
#endif
{
	U u;
	double rv;
	int i;

	rv = ulp(x);
	if (!scale || (i = 2*P + 1 - ((word0(x) & Exp_mask) >> Exp_shift)) <= 0)
		return rv; /* Is there an example where i <= 0 ? */
	word0(&u) = Exp_1 + (i << Exp_shift);
	word1(&u) = 0;
	return rv * u.d;
	}
#endif /*}*/

 double
strtod
#ifdef KR_headers
	(s00, se) CONST char *s00; char **se;
#else
	(CONST char *s00, char **se)
#endif
{
#ifdef Avoid_Underflow
	int scale;
#endif
	int bb2, bb5, bbe, bd2, bd5, bbbits, bs2, c, decpt, dsign,
		 e, e1, esign, i, j, k, nd, nd0, nf, nz, nz0, sign;
	CONST char *s, *s0, *s1;
	double aadj;
	Long L;
	U adj, aadj1, rv, rv0;
	ULong y, z;
	Bigint *bb = NULL, *bb1, *bd = NULL, *bd0 = NULL, *bs = NULL, *delta = NULL;
#ifdef Avoid_Underflow
	ULong Lsb, Lsb1;
#endif
#ifdef SET_INEXACT
	int inexact, oldinexact;
#endif
#ifdef USE_LOCALE /*{{*/
#ifdef NO_LOCALE_CACHE
	char *decimalpoint = localeconv()->decimal_point;
	int dplen = strlen(decimalpoint);
#else
	char *decimalpoint;
	static char *decimalpoint_cache;
	static int dplen;
	if (!(s0 = decimalpoint_cache)) {
		s0 = localeconv()->decimal_point;
		decimalpoint_cache = strdup(s0);
		dplen = strlen(s0);
		}
	decimalpoint = (char*)s0;
#endif /*NO_LOCALE_CACHE*/
#else  /*USE_LOCALE}{*/
#define dplen 1
#endif /*USE_LOCALE}}*/

#ifdef Honor_FLT_ROUNDS /*{*/
	int Rounding;
#ifdef Trust_FLT_ROUNDS /*{{ only define this if FLT_ROUNDS really works! */
	Rounding = Flt_Rounds;
#else /*}{*/
	Rounding = 1;
	switch(fegetround()) {
	  case FE_TOWARDZERO:	Rounding = 0; break;
	  case FE_UPWARD:	Rounding = 2; break;
	  case FE_DOWNWARD:	Rounding = 3;
	  }
#endif /*}}*/
#endif /*}*/

	sign = nz0 = nz = decpt = 0;
	dval(&rv) = 0.;
	for(s = s00;;s++) switch(*s) {
		case '-':
			sign = 1;
			/* no break */
		case '+':
			if (*++s)
				goto break2;
			/* no break */
		case 0:
			goto ret0;
		case '\t':
		case '\n':
		case '\v':
		case '\f':
		case '\r':
		case ' ':
			continue;
		default:
			goto break2;
		}
 break2:
	if (*s == '0') {
#ifndef NO_HEX_FP /*{*/
		{
		static FPI fpi = { 53, 1-1023-53+1, 2046-1023-53+1, 1, SI };
		Long exp;
		ULong bits[2];
		switch(s[1]) {
		  case 'x':
		  case 'X':
			{
#ifdef Honor_FLT_ROUNDS
			FPI fpi1 = fpi;
			fpi1.rounding = Rounding;
#else
#define fpi1 fpi
#endif
			switch((i = gethex(&s, &fpi1, &exp, &bb, sign)) & STRTOG_Retmask) {
			  case STRTOG_NoMemory:
				goto ovfl;
			  case STRTOG_NoNumber:
				s = s00;
				sign = 0;
			  case STRTOG_Zero:
				break;
			  default:
				if (bb) {
					copybits(bits, fpi.nbits, bb);
					Bfree(bb);
					}
				ULtod(((U*)&rv)->L, bits, exp, i);
			  }}
			goto ret;
		  }
		}
#endif /*}*/
		nz0 = 1;
		while(*++s == '0') ;
		if (!*s)
			goto ret;
		}
	s0 = s;
	y = z = 0;
	for(nd = nf = 0; (c = *s) >= '0' && c <= '9'; nd++, s++)
		if (nd < 9)
			y = 10*y + c - '0';
		else if (nd < 16)
			z = 10*z + c - '0';
	nd0 = nd;
#ifdef USE_LOCALE
	if (c == *decimalpoint) {
		for(i = 1; decimalpoint[i]; ++i)
			if (s[i] != decimalpoint[i])
				goto dig_done;
		s += i;
		c = *s;
#else
	if (c == '.') {
		c = *++s;
#endif
		decpt = 1;
		if (!nd) {
			for(; c == '0'; c = *++s)
				nz++;
			if (c > '0' && c <= '9') {
				s0 = s;
				nf += nz;
				nz = 0;
				goto have_dig;
				}
			goto dig_done;
			}
		for(; c >= '0' && c <= '9'; c = *++s) {
 have_dig:
			nz++;
			if (c -= '0') {
				nf += nz;
				for(i = 1; i < nz; i++)
					if (nd++ < 9)
						y *= 10;
					else if (nd <= DBL_DIG + 1)
						z *= 10;
				if (nd++ < 9)
					y = 10*y + c;
				else if (nd <= DBL_DIG + 1)
					z = 10*z + c;
				nz = 0;
				}
			}
		}/*}*/
 dig_done:
	e = 0;
	if (c == 'e' || c == 'E') {
		if (!nd && !nz && !nz0) {
			goto ret0;
			}
		s00 = s;
		esign = 0;
		switch(c = *++s) {
			case '-':
				esign = 1;
			case '+':
				c = *++s;
			}
		if (c >= '0' && c <= '9') {
			while(c == '0')
				c = *++s;
			if (c > '0' && c <= '9') {
				L = c - '0';
				s1 = s;
				while((c = *++s) >= '0' && c <= '9')
					L = 10*L + c - '0';
				if (s - s1 > 8 || L > 19999)
					/* Avoid confusion from exponents
					 * so large that e might overflow.
					 */
					e = 19999; /* safe for 16 bit ints */
				else
					e = (int)L;
				if (esign)
					e = -e;
				}
			else
				e = 0;
			}
		else
			s = s00;
		}
	if (!nd) {
		if (!nz && !nz0) {
#ifdef INFNAN_CHECK
			/* Check for Nan and Infinity */
			ULong bits[2];
			static FPI fpinan =	/* only 52 explicit bits */
				{ 52, 1-1023-53+1, 2046-1023-53+1, 1, SI };
			if (!decpt)
			 switch(c) {
			  case 'i':
			  case 'I':
				if (match(&s,"nf")) {
					--s;
					if (!match(&s,"inity"))
						++s;
					word0(&rv) = 0x7ff00000;
					word1(&rv) = 0;
					goto ret;
					}
				break;
			  case 'n':
			  case 'N':
				if (match(&s, "an")) {
#ifndef No_Hex_NaN
					if (*s == '(' /*)*/
					 && hexnan(&s, &fpinan, bits)
							== STRTOG_NaNbits) {
						word0(&rv) = 0x7ff00000 | bits[1];
						word1(&rv) = bits[0];
						}
					else {
#endif
						word0(&rv) = NAN_WORD0;
						word1(&rv) = NAN_WORD1;
#ifndef No_Hex_NaN
						}
#endif
					goto ret;
					}
			  }
#endif /* INFNAN_CHECK */
 ret0:
			s = s00;
			sign = 0;
			}
		goto ret;
		}
	e1 = e -= nf;

	/* Now we have nd0 digits, starting at s0, followed by a
	 * decimal point, followed by nd-nd0 digits.  The number we're
	 * after is the integer represented by those digits times
	 * 10**e */

	if (!nd0)
		nd0 = nd;
	k = nd < DBL_DIG + 1 ? nd : DBL_DIG + 1;
	dval(&rv) = y;
	if (k > 9) {
#ifdef SET_INEXACT
		if (k > DBL_DIG)
			oldinexact = get_inexact();
#endif
		dval(&rv) = tens[k - 9] * dval(&rv) + z;
		}
	if (nd <= DBL_DIG
#ifndef RND_PRODQUOT
#ifndef Honor_FLT_ROUNDS
		&& Flt_Rounds == 1
#endif
#endif
			) {
		if (!e)
			goto ret;
#ifndef ROUND_BIASED_without_Round_Up
		if (e > 0) {
			if (e <= Ten_pmax) {
#ifdef VAX
				goto vax_ovfl_check;
#else
#ifdef Honor_FLT_ROUNDS
				/* round correctly FLT_ROUNDS = 2 or 3 */
				if (sign) {
					rv.d = -rv.d;
					sign = 0;
					}
#endif
				/* rv = */ rounded_product(dval(&rv), tens[e]);
				goto ret;
#endif
				}
			i = DBL_DIG - nd;
			if (e <= Ten_pmax + i) {
				/* A fancier test would sometimes let us do
				 * this for larger i values.
				 */
#ifdef Honor_FLT_ROUNDS
				/* round correctly FLT_ROUNDS = 2 or 3 */
				if (sign) {
					rv.d = -rv.d;
					sign = 0;
					}
#endif
				e -= i;
				dval(&rv) *= tens[i];
#ifdef VAX
				/* VAX exponent range is so narrow we must
				 * worry about overflow here...
				 */
 vax_ovfl_check:
				word0(&rv) -= P*Exp_msk1;
				/* rv = */ rounded_product(dval(&rv), tens[e]);
				if ((word0(&rv) & Exp_mask)
				 > Exp_msk1*(DBL_MAX_EXP+Bias-1-P))
					goto ovfl;
				word0(&rv) += P*Exp_msk1;
#else
				/* rv = */ rounded_product(dval(&rv), tens[e]);
#endif
				goto ret;
				}
			}
#ifndef Inaccurate_Divide
		else if (e >= -Ten_pmax) {
#ifdef Honor_FLT_ROUNDS
			/* round correctly FLT_ROUNDS = 2 or 3 */
			if (sign) {
				rv.d = -rv.d;
				sign = 0;
				}
#endif
			/* rv = */ rounded_quotient(dval(&rv), tens[-e]);
			goto ret;
			}
#endif
#endif /* ROUND_BIASED_without_Round_Up */
		}
	e1 += nd - k;

#ifdef IEEE_Arith
#ifdef SET_INEXACT
	inexact = 1;
	if (k <= DBL_DIG)
		oldinexact = get_inexact();
#endif
#ifdef Avoid_Underflow
	scale = 0;
#endif
#ifdef Honor_FLT_ROUNDS
	if (Rounding >= 2) {
		if (sign)
			Rounding = Rounding == 2 ? 0 : 2;
		else
			if (Rounding != 2)
				Rounding = 0;
		}
#endif
#endif /*IEEE_Arith*/

	/* Get starting approximation = rv * 10**e1 */

	if (e1 > 0) {
		if ( (i = e1 & 15) !=0)
			dval(&rv) *= tens[i];
		if (e1 &= ~15) {
			if (e1 > DBL_MAX_10_EXP) {
 ovfl:
				/* Can't trust HUGE_VAL */
#ifdef IEEE_Arith
#ifdef Honor_FLT_ROUNDS
				switch(Rounding) {
				  case 0: /* toward 0 */
				  case 3: /* toward -infinity */
					word0(&rv) = Big0;
					word1(&rv) = Big1;
					break;
				  default:
					word0(&rv) = Exp_mask;
					word1(&rv) = 0;
				  }
#else /*Honor_FLT_ROUNDS*/
				word0(&rv) = Exp_mask;
				word1(&rv) = 0;
#endif /*Honor_FLT_ROUNDS*/
#ifdef SET_INEXACT
				/* set overflow bit */
				dval(&rv0) = 1e300;
				dval(&rv0) *= dval(&rv0);
#endif
#else /*IEEE_Arith*/
				word0(&rv) = Big0;
				word1(&rv) = Big1;
#endif /*IEEE_Arith*/
 range_err:
				if (bd0) {
					Bfree(bb);
					Bfree(bd);
					Bfree(bs);
					Bfree(bd0);
					Bfree(delta);
					}
#ifndef NO_ERRNO
				errno = ERANGE;
#endif
				goto ret;
				}
			e1 >>= 4;
			for(j = 0; e1 > 1; j++, e1 >>= 1)
				if (e1 & 1)
					dval(&rv) *= bigtens[j];
		/* The last multiplication could overflow. */
			word0(&rv) -= P*Exp_msk1;
			dval(&rv) *= bigtens[j];
			if ((z = word0(&rv) & Exp_mask)
			 > Exp_msk1*(DBL_MAX_EXP+Bias-P))
				goto ovfl;
			if (z > Exp_msk1*(DBL_MAX_EXP+Bias-1-P)) {
				/* set to largest number */
				/* (Can't trust DBL_MAX) */
				word0(&rv) = Big0;
				word1(&rv) = Big1;
				}
			else
				word0(&rv) += P*Exp_msk1;
			}
		}
	else if (e1 < 0) {
		e1 = -e1;
		if ( (i = e1 & 15) !=0)
			dval(&rv) /= tens[i];
		if (e1 >>= 4) {
			if (e1 >= 1 << n_bigtens)
				goto undfl;
#ifdef Avoid_Underflow
			if (e1 & Scale_Bit)
				scale = 2*P;
			for(j = 0; e1 > 0; j++, e1 >>= 1)
				if (e1 & 1)
					dval(&rv) *= tinytens[j];
			if (scale && (j = 2*P + 1 - ((word0(&rv) & Exp_mask)
						>> Exp_shift)) > 0) {
				/* scaled rv is denormal; zap j low bits */
				if (j >= 32) {
					word1(&rv) = 0;
					if (j >= 53)
					 word0(&rv) = (P+2)*Exp_msk1;
					else
					 word0(&rv) &= 0xffffffff << (j-32);
					}
				else
					word1(&rv) &= 0xffffffff << j;
				}
#else
			for(j = 0; e1 > 1; j++, e1 >>= 1)
				if (e1 & 1)
					dval(&rv) *= tinytens[j];
			/* The last multiplication could underflow. */
			dval(&rv0) = dval(&rv);
			dval(&rv) *= tinytens[j];
			if (!dval(&rv)) {
				dval(&rv) = 2.*dval(&rv0);
				dval(&rv) *= tinytens[j];
#endif
				if (!dval(&rv)) {
 undfl:
					dval(&rv) = 0.;
					goto range_err;
					}
#ifndef Avoid_Underflow
				word0(&rv) = Tiny0;
				word1(&rv) = Tiny1;
				/* The refinement below will clean
				 * this approximation up.
				 */
				}
#endif
			}
		}

	/* Now the hard part -- adjusting rv to the correct value.*/

	/* Put digits into bd: true value = bd * 10^e */

	bd0 = s2b(s0, nd0, nd, y, dplen);
	if (bd0 == NULL)
		goto ovfl;

	for(;;) {
		bd = Balloc(bd0->k);
		if (bd == NULL)
			goto ovfl;
		Bcopy(bd, bd0);
		bb = d2b(dval(&rv), &bbe, &bbbits);	/* rv = bb * 2^bbe */
		if (bb == NULL)
			goto ovfl;
		bs = i2b(1);
		if (bs == NULL)
			goto ovfl;

		if (e >= 0) {
			bb2 = bb5 = 0;
			bd2 = bd5 = e;
			}
		else {
			bb2 = bb5 = -e;
			bd2 = bd5 = 0;
			}
		if (bbe >= 0)
			bb2 += bbe;
		else
			bd2 -= bbe;
		bs2 = bb2;
#ifdef Honor_FLT_ROUNDS
		if (Rounding != 1)
			bs2++;
#endif
#ifdef Avoid_Underflow
		Lsb = LSB;
		Lsb1 = 0;
		j = bbe - scale;
		i = j + bbbits - 1;	/* logb(rv) */
		j = P + 1 - bbbits;
		if (i < Emin) {	/* denormal */
			i = Emin - i;
			j -= i;
			if (i < 32)
				Lsb <<= i;
			else
				Lsb1 = Lsb << (i-32);
			}
#else /*Avoid_Underflow*/
#ifdef Sudden_Underflow
#ifdef IBM
		j = 1 + 4*P - 3 - bbbits + ((bbe + bbbits - 1) & 3);
#else
		j = P + 1 - bbbits;
#endif
#else /*Sudden_Underflow*/
		j = bbe;
		i = j + bbbits - 1;	/* logb(&rv) */
		if (i < Emin)	/* denormal */
			j += P - Emin;
		else
			j = P + 1 - bbbits;
#endif /*Sudden_Underflow*/
#endif /*Avoid_Underflow*/
		bb2 += j;
		bd2 += j;
#ifdef Avoid_Underflow
		bd2 += scale;
#endif
		i = bb2 < bd2 ? bb2 : bd2;
		if (i > bs2)
			i = bs2;
		if (i > 0) {
			bb2 -= i;
			bd2 -= i;
			bs2 -= i;
			}
		if (bb5 > 0) {
			bs = pow5mult(bs, bb5);
			if (bs == NULL)
				goto ovfl;
			bb1 = mult(bs, bb);
			if (bb1 == NULL)
				goto ovfl;
			Bfree(bb);
			bb = bb1;
			}
		if (bb2 > 0) {
			bb = lshift(bb, bb2);
			if (bb == NULL)
				goto ovfl;
			}
		if (bd5 > 0) {
			bd = pow5mult(bd, bd5);
			if (bd == NULL)
				goto ovfl;
			}
		if (bd2 > 0) {
			bd = lshift(bd, bd2);
			if (bd == NULL)
				goto ovfl;
			}
		if (bs2 > 0) {
			bs = lshift(bs, bs2);
			if (bs == NULL)
				goto ovfl;
			}
		delta = diff(bb, bd);
		if (delta == NULL)
			goto ovfl;
		dsign = delta->sign;
		delta->sign = 0;
		i = cmp(delta, bs);
#ifdef Honor_FLT_ROUNDS
		if (Rounding != 1) {
			if (i < 0) {
				/* Error is less than an ulp */
				if (!delta->x[0] && delta->wds <= 1) {
					/* exact */
#ifdef SET_INEXACT
					inexact = 0;
#endif
					break;
					}
				if (Rounding) {
					if (dsign) {
						dval(&adj) = 1.;
						goto apply_adj;
						}
					}
				else if (!dsign) {
					dval(&adj) = -1.;
					if (!word1(&rv)
					 && !(word0(&rv) & Frac_mask)) {
						y = word0(&rv) & Exp_mask;
#ifdef Avoid_Underflow
						if (!scale || y > 2*P*Exp_msk1)
#else
						if (y)
#endif
						  {
						  delta = lshift(delta,Log2P);
						  if (delta == NULL)
							goto ovfl;
						  if (cmp(delta, bs) <= 0)
							dval(&adj) = -0.5;
						  }
						}
 apply_adj:
#ifdef Avoid_Underflow
					if (scale && (y = word0(&rv) & Exp_mask)
						<= 2*P*Exp_msk1)
					  word0(&adj) += (2*P+1)*Exp_msk1 - y;
#else
#ifdef Sudden_Underflow
					if ((word0(&rv) & Exp_mask) <=
							P*Exp_msk1) {
						word0(&rv) += P*Exp_msk1;
						dval(&rv) += adj*ulp(&rv);
						word0(&rv) -= P*Exp_msk1;
						}
					else
#endif /*Sudden_Underflow*/
#endif /*Avoid_Underflow*/
					dval(&rv) += adj.d*ulp(&rv);
					}
				break;
				}
			dval(&adj) = ratio(delta, bs);
			if (adj.d < 1.)
				dval(&adj) = 1.;
			if (adj.d <= 0x7ffffffe) {
				/* dval(&adj) = Rounding ? ceil(&adj) : floor(&adj); */
				y = adj.d;
				if (y != adj.d) {
					if (!((Rounding>>1) ^ dsign))
						y++;
					dval(&adj) = y;
					}
				}
#ifdef Avoid_Underflow
			if (scale && (y = word0(&rv) & Exp_mask) <= 2*P*Exp_msk1)
				word0(&adj) += (2*P+1)*Exp_msk1 - y;
#else
#ifdef Sudden_Underflow
			if ((word0(&rv) & Exp_mask) <= P*Exp_msk1) {
				word0(&rv) += P*Exp_msk1;
				dval(&adj) *= ulp(&rv);
				if (dsign)
					dval(&rv) += adj;
				else
					dval(&rv) -= adj;
				word0(&rv) -= P*Exp_msk1;
				goto cont;
				}
#endif /*Sudden_Underflow*/
#endif /*Avoid_Underflow*/
			dval(&adj) *= ulp(&rv);
			if (dsign) {
				if (word0(&rv) == Big0 && word1(&rv) == Big1)
					goto ovfl;
				dval(&rv) += adj.d;
				}
			else
				dval(&rv) -= adj.d;
			goto cont;
			}
#endif /*Honor_FLT_ROUNDS*/

		if (i < 0) {
			/* Error is less than half an ulp -- check for
			 * special case of mantissa a power of two.
			 */
			if (dsign || word1(&rv) || word0(&rv) & Bndry_mask
#ifdef IEEE_Arith
#ifdef Avoid_Underflow
			 || (word0(&rv) & Exp_mask) <= (2*P+1)*Exp_msk1
#else
			 || (word0(&rv) & Exp_mask) <= Exp_msk1
#endif
#endif
				) {
#ifdef SET_INEXACT
				if (!delta->x[0] && delta->wds <= 1)
					inexact = 0;
#endif
				break;
				}
			if (!delta->x[0] && delta->wds <= 1) {
				/* exact result */
#ifdef SET_INEXACT
				inexact = 0;
#endif
				break;
				}
			delta = lshift(delta,Log2P);
			if (delta == NULL)
				goto ovfl;
			if (cmp(delta, bs) > 0)
				goto drop_down;
			break;
			}
		if (i == 0) {
			/* exactly half-way between */
			if (dsign) {
				if ((word0(&rv) & Bndry_mask1) == Bndry_mask1
				 &&  word1(&rv) == (
#ifdef Avoid_Underflow
			(scale && (y = word0(&rv) & Exp_mask) <= 2*P*Exp_msk1)
		? (0xffffffff & (0xffffffff << (2*P+1-(y>>Exp_shift)))) :
#endif
						   0xffffffff)) {
					/*boundary case -- increment exponent*/
					if (word0(&rv) == Big0 && word1(&rv) == Big1)
						goto ovfl;
					word0(&rv) = (word0(&rv) & Exp_mask)
						+ Exp_msk1
#ifdef IBM
						| Exp_msk1 >> 4
#endif
						;
					word1(&rv) = 0;
#ifdef Avoid_Underflow
					dsign = 0;
#endif
					break;
					}
				}
			else if (!(word0(&rv) & Bndry_mask) && !word1(&rv)) {
 drop_down:
				/* boundary case -- decrement exponent */
#ifdef Sudden_Underflow /*{{*/
				L = word0(&rv) & Exp_mask;
#ifdef IBM
				if (L <  Exp_msk1)
#else
#ifdef Avoid_Underflow
				if (L <= (scale ? (2*P+1)*Exp_msk1 : Exp_msk1))
#else
				if (L <= Exp_msk1)
#endif /*Avoid_Underflow*/
#endif /*IBM*/
					goto undfl;
				L -= Exp_msk1;
#else /*Sudden_Underflow}{*/
#ifdef Avoid_Underflow
				if (scale) {
					L = word0(&rv) & Exp_mask;
					if (L <= (2*P+1)*Exp_msk1) {
						if (L > (P+2)*Exp_msk1)
							/* round even ==> */
							/* accept rv */
							break;
						/* rv = smallest denormal */
						goto undfl;
						}
					}
#endif /*Avoid_Underflow*/
				L = (word0(&rv) & Exp_mask) - Exp_msk1;
#endif /*Sudden_Underflow}}*/
				word0(&rv) = L | Bndry_mask1;
				word1(&rv) = 0xffffffff;
#ifdef IBM
				goto cont;
#else
				break;
#endif
				}
#ifndef ROUND_BIASED
#ifdef Avoid_Underflow
			if (Lsb1) {
				if (!(word0(&rv) & Lsb1))
					break;
				}
			else if (!(word1(&rv) & Lsb))
				break;
#else
			if (!(word1(&rv) & LSB))
				break;
#endif
#endif
			if (dsign)
#ifdef Avoid_Underflow
				dval(&rv) += sulp(&rv, scale);
#else
				dval(&rv) += ulp(&rv);
#endif
#ifndef ROUND_BIASED
			else {
#ifdef Avoid_Underflow
				dval(&rv) -= sulp(&rv, scale);
#else
				dval(&rv) -= ulp(&rv);
#endif
#ifndef Sudden_Underflow
				if (!dval(&rv))
					goto undfl;
#endif
				}
#ifdef Avoid_Underflow
			dsign = 1 - dsign;
#endif
#endif
			break;
			}
		if ((aadj = ratio(delta, bs)) <= 2.) {
			if (dsign)
				aadj = dval(&aadj1) = 1.;
			else if (word1(&rv) || word0(&rv) & Bndry_mask) {
#ifndef Sudden_Underflow
				if (word1(&rv) == Tiny1 && !word0(&rv))
					goto undfl;
#endif
				aadj = 1.;
				dval(&aadj1) = -1.;
				}
			else {
				/* special case -- power of FLT_RADIX to be */
				/* rounded down... */

				if (aadj < 2./FLT_RADIX)
					aadj = 1./FLT_RADIX;
				else
					aadj *= 0.5;
				dval(&aadj1) = -aadj;
				}
			}
		else {
			aadj *= 0.5;
			dval(&aadj1) = dsign ? aadj : -aadj;
#ifdef Check_FLT_ROUNDS
			switch(Rounding) {
				case 2: /* towards +infinity */
					dval(&aadj1) -= 0.5;
					break;
				case 0: /* towards 0 */
				case 3: /* towards -infinity */
					dval(&aadj1) += 0.5;
				}
#else
			if (Flt_Rounds == 0)
				dval(&aadj1) += 0.5;
#endif /*Check_FLT_ROUNDS*/
			}
		y = word0(&rv) & Exp_mask;

		/* Check for overflow */

		if (y == Exp_msk1*(DBL_MAX_EXP+Bias-1)) {
			dval(&rv0) = dval(&rv);
			word0(&rv) -= P*Exp_msk1;
			dval(&adj) = dval(&aadj1) * ulp(&rv);
			dval(&rv) += dval(&adj);
			if ((word0(&rv) & Exp_mask) >=
					Exp_msk1*(DBL_MAX_EXP+Bias-P)) {
				if (word0(&rv0) == Big0 && word1(&rv0) == Big1)
					goto ovfl;
				word0(&rv) = Big0;
				word1(&rv) = Big1;
				goto cont;
				}
			else
				word0(&rv) += P*Exp_msk1;
			}
		else {
#ifdef Avoid_Underflow
			if (scale && y <= 2*P*Exp_msk1) {
				if (aadj <= 0x7fffffff) {
					if ((z = aadj) <= 0)
						z = 1;
					aadj = z;
					dval(&aadj1) = dsign ? aadj : -aadj;
					}
				word0(&aadj1) += (2*P+1)*Exp_msk1 - y;
				}
			dval(&adj) = dval(&aadj1) * ulp(&rv);
			dval(&rv) += dval(&adj);
#else
#ifdef Sudden_Underflow
			if ((word0(&rv) & Exp_mask) <= P*Exp_msk1) {
				dval(&rv0) = dval(&rv);
				word0(&rv) += P*Exp_msk1;
				dval(&adj) = dval(&aadj1) * ulp(&rv);
				dval(&rv) += dval(&adj);
#ifdef IBM
				if ((word0(&rv) & Exp_mask) <  P*Exp_msk1)
#else
				if ((word0(&rv) & Exp_mask) <= P*Exp_msk1)
#endif
					{
					if (word0(&rv0) == Tiny0
					 && word1(&rv0) == Tiny1)
						goto undfl;
					word0(&rv) = Tiny0;
					word1(&rv) = Tiny1;
					goto cont;
					}
				else
					word0(&rv) -= P*Exp_msk1;
				}
			else {
				dval(&adj) = dval(&aadj1) * ulp(&rv);
				dval(&rv) += dval(&adj);
				}
#else /*Sudden_Underflow*/
			/* Compute dval(&adj) so that the IEEE rounding rules will
			 * correctly round rv + dval(&adj) in some half-way cases.
			 * If rv * ulp(&rv) is denormalized (i.e.,
			 * y <= (P-1)*Exp_msk1), we must adjust aadj to avoid
			 * trouble from bits lost to denormalization;
			 * example: 1.2e-307 .
			 */
			if (y <= (P-1)*Exp_msk1 && aadj > 1.) {
				dval(&aadj1) = (double)(int)(aadj + 0.5);
				if (!dsign)
					dval(&aadj1) = -dval(&aadj1);
				}
			dval(&adj) = dval(&aadj1) * ulp(&rv);
			dval(&rv) += adj;
#endif /*Sudden_Underflow*/
#endif /*Avoid_Underflow*/
			}
		z = word0(&rv) & Exp_mask;
#ifndef SET_INEXACT
#ifdef Avoid_Underflow
		if (!scale)
#endif
		if (y == z) {
			/* Can we stop now? */
			L = (Long)aadj;
			aadj -= L;
			/* The tolerances below are conservative. */
			if (dsign || word1(&rv) || word0(&rv) & Bndry_mask) {
				if (aadj < .4999999 || aadj > .5000001)
					break;
				}
			else if (aadj < .4999999/FLT_RADIX)
				break;
			}
#endif
 cont:
		Bfree(bb);
		Bfree(bd);
		Bfree(bs);
		Bfree(delta);
		}
	Bfree(bb);
	Bfree(bd);
	Bfree(bs);
	Bfree(bd0);
	Bfree(delta);
#ifdef SET_INEXACT
	if (inexact) {
		if (!oldinexact) {
			word0(&rv0) = Exp_1 + (70 << Exp_shift);
			word1(&rv0) = 0;
			dval(&rv0) += 1.;
			}
		}
	else if (!oldinexact)
		clear_inexact();
#endif
#ifdef Avoid_Underflow
	if (scale) {
		word0(&rv0) = Exp_1 - 2*P*Exp_msk1;
		word1(&rv0) = 0;
		dval(&rv) *= dval(&rv0);
#ifndef NO_ERRNO
		/* try to avoid the bug of testing an 8087 register value */
#ifdef IEEE_Arith
		if (!(word0(&rv) & Exp_mask))
#else
		if (word0(&rv) == 0 && word1(&rv) == 0)
#endif
			errno = ERANGE;
#endif
		}
#endif /* Avoid_Underflow */
#ifdef SET_INEXACT
	if (inexact && !(word0(&rv) & Exp_mask)) {
		/* set underflow bit */
		dval(&rv0) = 1e-300;
		dval(&rv0) *= dval(&rv0);
		}
#endif
 ret:
	if (se)
		*se = (char *)s;
	return sign ? -dval(&rv) : dval(&rv);
	}
DEF_STRONG(strtod);

"""

```
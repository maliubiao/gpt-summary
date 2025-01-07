Response:
Let's break down the thought process for analyzing the `gdtoaimp.handroid` header file.

**1. Understanding the Context:**

* **File Name and Path:** `bionic/libc/upstream-openbsd/lib/libc/gdtoa/gdtoaimp.handroid`. This immediately tells us:
    * It's part of Bionic, Android's C library.
    * It originates from OpenBSD's libc.
    * It's within the `gdtoa` directory, hinting at its function: converting between floating-point numbers and decimal strings.
    * The `.handroid` suffix likely indicates Android-specific adaptations or configurations.

* **Initial Comments:** The initial comments provide crucial information:
    * Author: David M. Gay. This name is strongly associated with high-quality floating-point conversion routines.
    * Copyright and License: Standard open-source license, allowing use and modification.
    * Core Purpose: Converting arbitrary binary floating-point formats to/from decimal.
    * Internal Mechanism: Uses double-precision arithmetic internally.
    * `#ifdef` Usage: Highlights platform-specific adaptations.
    * `strtod` Focus: Mentions it returns the nearest machine number.
    * Inspiration: William D. Clinger's paper on accurate floating-point number reading.
    * Modifications: Lists key optimizations and differences from Clinger's approach.
    * Numerous `#define` Directives: This is a huge clue that the file is highly configurable based on the target architecture and compiler.

**2. Deconstructing the `#define` Directives:**

This is the most time-consuming but essential part. The `#define` directives control the behavior of the code. The thought process here involves:

* **Categorization:** Grouping the `#define`s by their apparent function:
    * **Architecture-Specific:** `IEEE_8087`, `IEEE_MC68k`, `IBM`, `VAX`. These clearly define the underlying floating-point representation.
    * **Arithmetic Properties:** `Sudden_Underflow`, `ROUND_BIASED`, `Inaccurate_Divide`. These describe the behavior of floating-point operations.
    * **Integer Types:** `Long`, `NO_LONG_LONG`, `Llong`, `ULLong`. These control how large integers are handled.
    * **Memory Management:** `MALLOC`, `FREE`, `Omit_Private_Memory`. These relate to memory allocation.
    * **Error Handling:** `NO_ERRNO`.
    * **String Handling:** `NO_STRING_H`.
    * **Locale:** `USE_LOCALE`.
    * **NaN and Infinity:** `NO_INFNAN_CHECK`, `No_Hex_NaN`.
    * **Threading:** `MULTIPLE_THREADS`.
    * **Precision:** `IMPRECISE_INEXACT`.
    * **Hexadecimal Floating-Point:** `NO_HEX_FP`.
    * **Internal Configuration:** `GDTOAIMP_H_INCLUDED`, `KR_headers`, `Bad_float_h`.

* **Inferring Functionality:**  For each group, deduce the purpose and impact of the directives. For example:
    * Seeing `IEEE_8087` and `IEEE_MC68k` suggests support for different byte orders in IEEE floating-point.
    * `Sudden_Underflow` implies a simpler handling of underflow compared to gradual underflow.
    * `MALLOC` and `FREE` point to customizable memory management.
    * `MULTIPLE_THREADS` clearly indicates thread-safety considerations.

* **Looking for Defaults and Alternatives:**  Note the default behavior if a `#define` is not present. For instance, if `MALLOC` isn't defined, `malloc` is used.

**3. Analyzing the Data Structures and Types:**

* **`union U`:** This union is used to access the raw bits of a `double`. The `L[2]` array represents the two words (on a 32-bit architecture) that make up a `double`. The `#define word0(x)` and `#define word1(x)` directives handle byte order differences.

* **`struct Bigint`:** This structure is clearly for representing arbitrary-precision integers, necessary for handling very large or very precise numbers during the conversion process. The `x[]` array is a flexible way to store the digits.

* **Typedefs:**  `Char`, `Bigint`. These are standard C practices for code clarity.

**4. Examining the Function Declarations (and Macros that act like them):**

* **Naming Conventions:**  The functions have prefixes like `dtoa`, `gdtoa`, `strtodg`, `g_ddfmt`, etc. This helps in grouping related functions. The `__` prefix often indicates internal helper functions. The `_D2A` suffix is a strong indicator of "Double to ASCII" or a similar conversion direction.

* **Function Groups:** Identify the main categories of functions:
    * **Core Conversion:** `dtoa`, `gdtoa`, `strtodg`. These are the primary functions for converting between floating-point and strings.
    * **Formatted Output:** `g_ddfmt`, `g_dfmt`, etc. These seem to handle formatting the output string according to different specifications.
    * **String to Floating-Point (with different precisions):**  `strtoId`, `strtoIdd`, `strtoIf`, etc. The `I`, `Id`, `If` suffixes likely denote `int`, `double`, `float` return types.
    * **Rounded Conversions:** `strtord`, `strtordd`, etc. The `r` suggests rounding is involved.
    * **"Top of Stack" Conversions:** `strtopd`, `strtopdd`, etc. The `top` likely relates to how arguments are passed on certain architectures (like x87).
    * **Big Integer Operations:** `Balloc`, `Bfree`, `ULtoQ`, `mult`, `add`, etc. These functions operate on the `Bigint` structure.
    * **Helper Functions:** `b2d`, `d2b`, `cmp`, `copybits`, `lshift`, `rshift`, etc. These are lower-level utilities used within the conversion process.

* **Inferring Function Purpose:** Based on the names and contexts, make educated guesses about what each function does. For example, `d2b` is likely "double to bigint", `ulp` calculates the unit in the last place.

**5. Connecting to Android (High-Level):**

Knowing this is in Bionic, the immediate connection is:

* **Standard C Library:** These functions are essential parts of a standard C library, providing fundamental number conversion capabilities.
* **NDK Usage:**  Android NDK developers use these functions indirectly through standard C/C++ functions like `sprintf`, `std::to_string`, `strtod`, etc.

**6. Frida Hooking (Conceptual):**

Think about *where* you'd want to intercept these functions. The primary entry points like `strtod` and `dtoa` are the most obvious targets.

**7. Iterative Refinement:**

After the initial pass, go back and refine the descriptions. For example, after seeing the `Bigint` structure, the purpose of functions like `mult` and `add` becomes much clearer. The numerous `#ifdef`s emphasize the platform-dependent nature of floating-point representation.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like just a standard header file."
* **Correction:**  The sheer number of `#define`s and the `handroid` suffix indicate significant platform-specific configuration.
* **Initial thought:** "The functions are probably simple wrappers."
* **Correction:** The comments about Clinger's paper and the mention of handling "hard cases" suggest complex algorithms. The presence of `Bigint` confirms arbitrary precision arithmetic is involved.
* **Initial thought:** "Frida hooking would be complex."
* **Refinement:** Focus on the primary entry points. Lower-level functions are less likely to be directly hooked for general debugging.

By following this structured decomposition and inference process, we can effectively analyze even a complex header file like `gdtoaimp.handroid` and understand its purpose, functionality, and relevance within the Android ecosystem.
这个文件 `gdtoaimp.handroid` 是 Android Bionic 库中用于实现 **浮点数与十进制字符串之间转换** 的核心头文件。它是 OpenBSD `libc` 中 `gdtoa` (general dtoa) 库的一部分，并针对 Android 平台进行了适配。

以下是该文件的功能及其与 Android 功能的关系，以及其他详细解释：

**1. 主要功能：**

* **定义了用于浮点数和十进制字符串之间转换的接口和内部结构:** 它声明了 `dtoa` (double to ASCII), `gdtoa` (general dtoa), `strtod` (string to double) 等函数的接口，并定义了这些函数内部使用的各种数据结构（如 `Bigint` 用于高精度整数运算）和宏。
* **提供了平台相关的配置:** 通过大量的 `#ifdef` 宏，该文件可以根据不同的目标架构（如 IEEE、VAX、IBM）和编译器特性进行定制，以确保在不同平台上浮点数转换的正确性和性能。`gdtoaimp.handroid` 中的 `.handroid` 后缀表明这是针对 Android 平台的特定配置。
* **实现了高精度的转换:**  `gdtoa` 库旨在提供尽可能精确的浮点数和十进制字符串之间的转换，避免因浮点数精度限制而产生误差。
* **处理特殊值:**  它能正确处理浮点数的特殊值，如无穷大 (Infinity) 和 NaN (Not a Number)。
* **支持不同的舍入模式:**  根据 IEEE 标准或其他平台的约定，实现不同的舍入行为。

**2. 与 Android 功能的关系及举例：**

该文件是 Android 核心 C 库的一部分，因此其功能直接或间接地被 Android 系统的许多组件和应用程序所使用。

* **Java Native Interface (JNI):** 当 Java 代码需要与 Native 代码（C/C++）交换浮点数数据时，`gdtoa` 库的函数会被调用。例如，当 Java 代码调用一个返回 `double` 或 `float` 的 Native 方法时，JNI 框架可能会使用 `gdtoa` 将这些浮点数转换为 Java 可以处理的字符串表示，或者反过来，使用 `strtod` 将 Java 传递的字符串转换为 Native 代码中的浮点数。
* **System Libraries 和 Framework:** Android Framework 中的许多底层库和组件（如 OpenGL ES 渲染库、媒体编解码库等）在处理浮点数时会依赖 `libc` 提供的转换功能。
* **NDK 开发:** 使用 Android NDK 进行 Native 开发的应用程序可以直接或间接地使用 `gdtoa` 提供的函数。例如，开发者可以使用 `sprintf` 或 `std::to_string` 等标准 C/C++ 函数将浮点数转换为字符串，这些函数底层会调用 `gdtoa` 或类似的实现。
* **输入输出:**  当应用程序需要将浮点数显示给用户或从用户输入中解析浮点数时，`gdtoa` 的功能至关重要。例如，`scanf` 和 `printf` 函数在处理浮点数格式化输入输出时，会依赖这些转换函数。

**3. libc 函数的实现细节：**

由于该文件是头文件，它主要声明了函数接口和定义了宏，真正的函数实现位于 `.c` 源文件中（例如，`gdtoa.c`, `strtod.c` 等）。不过，我们可以从头文件中的宏和注释中推断一些实现策略：

* **平台相关的处理 (`#ifdef` 宏):**  例如，`IEEE_8087`、`IEEE_MC68k`、`VAX`、`IBM` 等宏定义了不同的浮点数表示方式，代码会根据这些宏选择不同的算法和数据结构。
* **高精度整数运算 (`Bigint` 结构):**  为了实现高精度的转换，需要进行大整数的乘法、加法、除法等运算。`Bigint` 结构用于存储任意大小的整数，相关的 `Balloc`, `Bfree`, `mult`, `sum` 等函数实现了这些运算。
* **查表法 (`bigtens`, `tens`, `tinytens` 数组):**  为了加速乘以或除以 10 的幂的运算，预先计算了一些常用的 10 的幂并存储在数组中。
* **位操作 (`word0`, `word1` 宏):**  用于直接访问浮点数的二进制表示，例如提取符号位、指数位和尾数位。
* **舍入处理 (`Flt_Rounds` 宏):**  根据不同的浮点数舍入模式（例如，向最近偶数舍入、向零舍入等），采用不同的舍入策略。

**4. 涉及 dynamic linker 的功能：**

这个头文件本身不直接涉及 dynamic linker 的功能。它定义的是 C 库中的函数接口和数据结构。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的作用是将动态链接库加载到进程的内存空间，并解析库之间的依赖关系，包括符号的重定位。

* **so 布局样本:**  `gdtoa` 相关的代码会被编译成 `libc.so` (或其变种)。一个简化的 `libc.so` 布局可能如下：

```
libc.so:
    .text          # 存放代码段
        dtoa
        gdtoa
        strtod
        ...
    .data          # 存放已初始化的全局变量
        bigtens
        tens
        ...
    .rodata        # 存放只读数据
        ...
    .bss           # 存放未初始化的全局变量
        ...
    .symtab        # 符号表，包含函数和变量的名称和地址
        dtoa
        gdtoa
        strtod
        ...
    .dynsym        # 动态符号表
        dtoa
        gdtoa
        strtod
        ...
    .rel.dyn       # 动态重定位表
        ...
    .rel.plt       # PLT (Procedure Linkage Table) 重定位表
        ...
```

* **链接的处理过程:**
    1. 当一个应用程序或库需要调用 `dtoa` 等函数时，编译器会在其目标文件中生成一个对该符号的未解析引用。
    2. 在程序启动时，dynamic linker 会加载所有需要的动态链接库，包括 `libc.so`。
    3. Dynamic linker 会遍历每个库的动态符号表 (`.dynsym`)，找到 `dtoa` 等符号的定义。
    4. Dynamic linker 会使用重定位表 (`.rel.dyn` 和 `.rel.plt`) 更新调用者目标文件中的未解析引用，将其指向 `libc.so` 中 `dtoa` 函数的实际地址。
    5. 之后，当程序执行到调用 `dtoa` 的代码时，实际上会跳转到 `libc.so` 中 `dtoa` 的实现。

**5. 逻辑推理、假设输入与输出：**

由于是头文件，这里没有具体的逻辑实现。逻辑推理发生在源文件中。但我们可以根据函数签名推断一些行为：

* **`dtoa(double number, int mode, int ndigits, int *decpt, char **sign)`:**
    * **假设输入:** `number = 123.45`, `mode = 2` (保留指定位数的小数), `ndigits = 2`
    * **可能输出:** `*decpt = 3` (小数点位置), `*sign = ""` (正数), 返回的字符串可能为 `"123.45"`
* **`strtod(const char *str, char **endptr)`:**
    * **假设输入:** `str = "  -1.23e+4"`
    * **可能输出:** 返回值约为 `-12300.0`, `*endptr` 指向 `" "` 之后的字符。

**6. 用户或编程常见的使用错误：**

虽然此文件是库的内部实现，但与它相关的用户错误通常发生在调用使用这些函数的上层 API 时：

* **`strtod` 的使用:**
    * **未检查 `endptr`:**  `strtod` 会将解析停止的位置写入 `endptr`。如果输入字符串不是一个有效的数字，`endptr` 可能指向原始字符串的开头，导致程序逻辑错误。
    * **溢出或下溢:** 输入的字符串表示的数字超出 `double` 的表示范围，导致 `errno` 被设置为 `ERANGE`，需要检查 `errno`。
    * **格式错误:**  输入的字符串格式不符合浮点数的语法规则。
* **`dtoa` 或 `gdtoa` 的使用:**
    * **`mode` 和 `ndigits` 的理解错误:**  对 `mode` 参数的不同含义（如保留有效数字或小数点后位数）理解不当可能导致输出格式不符合预期。
    * **内存管理错误 (在多线程环境下):**  如果 `MULTIPLE_THREADS` 被定义，`dtoa` 返回的字符串需要使用 `freedtoa` 释放，忘记释放会导致内存泄漏。

**7. Android Framework or NDK 如何到达这里，给出 Frida hook 示例调试这些步骤：**

* **Android Framework:**
    1. **Java 代码调用:**  例如，`String.valueOf(double)` 方法会被调用。
    2. **JNI 调用:** `String.valueOf(double)` 底层会调用 Native 代码。
    3. **`libcore` 或 `libjavacrypto` 等库:**  这些库中的 Native 代码可能会调用 `sprintf` 或其他 C 标准库函数。
    4. **`libc.so`:** `sprintf` 等函数最终会调用 `gdtoa` 或 `strtod` 等函数。

* **NDK 开发:**
    1. **NDK 代码调用:**  NDK 开发者直接在 C/C++ 代码中使用 `sprintf`, `std::to_string`, `strtod` 等函数。
    2. **`libc.so`:** 这些函数链接到 `libc.so`，并最终调用 `gdtoa` 或 `strtod`。

**Frida Hook 示例:**

假设我们想 hook `strtod` 函数，查看其输入和输出：

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so");
  if (libc) {
    const strtod = Module.findExportByName(libc.name, "strtod");
    if (strtod) {
      Interceptor.attach(strtod, {
        onEnter: function (args) {
          const strPtr = args[0];
          const str = strPtr.readCString();
          console.log(`strtod called with string: ${str}`);
        },
        onLeave: function (retval) {
          console.log(`strtod returned: ${retval}`);
          // 如果需要，可以修改返回值
          // retval.replace(123.45);
        }
      });
      console.log("strtod hooked!");
    } else {
      console.log("strtod not found in libc.so");
    }
  } else {
    console.log("libc.so not found");
  }
}
```

**解释 Frida Hook 代码:**

1. **`if (Process.platform === 'android')`:**  确保只在 Android 平台上执行。
2. **`Module.findExportByName(null, "libc.so")`:** 查找名为 `libc.so` 的模块。`null` 表示在所有已加载的模块中搜索。
3. **`Module.findExportByName(libc.name, "strtod")`:** 在 `libc.so` 中查找名为 `strtod` 的导出函数。
4. **`Interceptor.attach(strtod, { ... })`:**  附加一个拦截器到 `strtod` 函数。
5. **`onEnter: function (args)`:**  在 `strtod` 函数被调用之前执行。`args` 是一个数组，包含传递给函数的参数。对于 `strtod`，`args[0]` 是指向输入字符串的指针。
6. **`args[0].readCString()`:** 读取指针指向的 C 字符串。
7. **`onLeave: function (retval)`:** 在 `strtod` 函数执行完毕并即将返回时执行。`retval` 是返回值。
8. **`retval.replace(123.45)`:**  （注释部分）演示如何修改返回值。

通过这样的 Frida hook，你可以在 Android 设备上运行时，观察 `strtod` 函数的调用情况，包括传入的字符串和返回的浮点数，从而帮助调试与浮点数转换相关的问题。你可以根据需要 hook 其他相关的函数，例如 `dtoa` 或 `gdtoa`，来观察更底层的转换过程。

总而言之，`gdtoaimp.handroid` 是 Android 系统中处理浮点数与字符串转换的关键组件，它通过平台相关的配置和高精度的算法，确保了浮点数操作的准确性，并被 Android 的各个层次广泛使用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/gdtoaimp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

Copyright (C) 1998-2000 by Lucent Technologies
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

/* This is a variation on dtoa.c that converts arbitrary binary
   floating-point formats to and from decimal notation.  It uses
   double-precision arithmetic internally, so there are still
   various #ifdefs that adapt the calculations to the native
   double-precision arithmetic (any of IEEE, VAX D_floating,
   or IBM mainframe arithmetic).

   Please send bug reports to David M. Gay (dmg at acm dot org,
   with " at " changed at "@" and " dot " changed to ".").
 */

/* On a machine with IEEE extended-precision registers, it is
 * necessary to specify double-precision (53-bit) rounding precision
 * before invoking strtod or dtoa.  If the machine uses (the equivalent
 * of) Intel 80x87 arithmetic, the call
 *	_control87(PC_53, MCW_PC);
 * does this with many compilers.  Whether this or another call is
 * appropriate depends on the compiler; for this to work, it may be
 * necessary to #include "float.h" or another system-dependent header
 * file.
 */

/* strtod for IEEE-, VAX-, and IBM-arithmetic machines.
 *
 * This strtod returns a nearest machine number to the input decimal
 * string (or sets errno to ERANGE).  With IEEE arithmetic, ties are
 * broken by the IEEE round-even rule.  Otherwise ties are broken by
 * biased rounding (add half and chop).
 *
 * Inspired loosely by William D. Clinger's paper "How to Read Floating
 * Point Numbers Accurately" [Proc. ACM SIGPLAN '90, pp. 112-126].
 *
 * Modifications:
 *
 *	1. We only require IEEE, IBM, or VAX double-precision
 *		arithmetic (not IEEE double-extended).
 *	2. We get by with floating-point arithmetic in a case that
 *		Clinger missed -- when we're computing d * 10^n
 *		for a small integer d and the integer n is not too
 *		much larger than 22 (the maximum integer k for which
 *		we can represent 10^k exactly), we may be able to
 *		compute (d*10^k) * 10^(e-k) with just one roundoff.
 *	3. Rather than a bit-at-a-time adjustment of the binary
 *		result in the hard case, we use floating-point
 *		arithmetic to determine the adjustment to within
 *		one bit; only in really hard cases do we need to
 *		compute a second residual.
 *	4. Because of 3., we don't need a large table of powers of 10
 *		for ten-to-e (just some small tables, e.g. of 10^k
 *		for 0 <= k <= 22).
 */

/*
 * #define IEEE_8087 for IEEE-arithmetic machines where the least
 *	significant byte has the lowest address.
 * #define IEEE_MC68k for IEEE-arithmetic machines where the most
 *	significant byte has the lowest address.
 * #define Long int on machines with 32-bit ints and 64-bit longs.
 * #define Sudden_Underflow for IEEE-format machines without gradual
 *	underflow (i.e., that flush to zero on underflow).
 * #define IBM for IBM mainframe-style floating-point arithmetic.
 * #define VAX for VAX-style floating-point arithmetic (D_floating).
 * #define No_leftright to omit left-right logic in fast floating-point
 *	computation of dtoa and gdtoa.  This will cause modes 4 and 5 to be
 *	treated the same as modes 2 and 3 for some inputs.
 * #define Check_FLT_ROUNDS if FLT_ROUNDS can assume the values 2 or 3.
 * #define RND_PRODQUOT to use rnd_prod and rnd_quot (assembly routines
 *	that use extended-precision instructions to compute rounded
 *	products and quotients) with IBM.
 * #define ROUND_BIASED for IEEE-format with biased rounding and arithmetic
 *	that rounds toward +Infinity.
 * #define ROUND_BIASED_without_Round_Up for IEEE-format with biased
 *	rounding when the underlying floating-point arithmetic uses
 *	unbiased rounding.  This prevent using ordinary floating-point
 *	arithmetic when the result could be computed with one rounding error.
 * #define Inaccurate_Divide for IEEE-format with correctly rounded
 *	products but inaccurate quotients, e.g., for Intel i860.
 * #define NO_LONG_LONG on machines that do not have a "long long"
 *	integer type (of >= 64 bits).  On such machines, you can
 *	#define Just_16 to store 16 bits per 32-bit Long when doing
 *	high-precision integer arithmetic.  Whether this speeds things
 *	up or slows things down depends on the machine and the number
 *	being converted.  If long long is available and the name is
 *	something other than "long long", #define Llong to be the name,
 *	and if "unsigned Llong" does not work as an unsigned version of
 *	Llong, #define #ULLong to be the corresponding unsigned type.
 * #define KR_headers for old-style C function headers.
 * #define Bad_float_h if your system lacks a float.h or if it does not
 *	define some or all of DBL_DIG, DBL_MAX_10_EXP, DBL_MAX_EXP,
 *	FLT_RADIX, FLT_ROUNDS, and DBL_MAX.
 * #define MALLOC your_malloc, where your_malloc(n) acts like malloc(n)
 *	if memory is available and otherwise does something you deem
 *	appropriate.  If MALLOC is undefined, malloc will be invoked
 *	directly -- and assumed always to succeed.  Similarly, if you
 *	want something other than the system's free() to be called to
 *	recycle memory acquired from MALLOC, #define FREE to be the
 *	name of the alternate routine.  (FREE or free is only called in
 *	pathological cases, e.g., in a gdtoa call after a gdtoa return in
 *	mode 3 with thousands of digits requested.)
 * #define Omit_Private_Memory to omit logic (added Jan. 1998) for making
 *	memory allocations from a private pool of memory when possible.
 *	When used, the private pool is PRIVATE_MEM bytes long:  2304 bytes,
 *	unless #defined to be a different length.  This default length
 *	suffices to get rid of MALLOC calls except for unusual cases,
 *	such as decimal-to-binary conversion of a very long string of
 *	digits.  When converting IEEE double precision values, the
 *	longest string gdtoa can return is about 751 bytes long.  For
 *	conversions by strtod of strings of 800 digits and all gdtoa
 *	conversions of IEEE doubles in single-threaded executions with
 *	8-byte pointers, PRIVATE_MEM >= 7400 appears to suffice; with
 *	4-byte pointers, PRIVATE_MEM >= 7112 appears adequate.
 * #define NO_INFNAN_CHECK if you do not wish to have INFNAN_CHECK
 *	#defined automatically on IEEE systems.  On such systems,
 *	when INFNAN_CHECK is #defined, strtod checks
 *	for Infinity and NaN (case insensitively).
 *	When INFNAN_CHECK is #defined and No_Hex_NaN is not #defined,
 *	strtodg also accepts (case insensitively) strings of the form
 *	NaN(x), where x is a string of hexadecimal digits (optionally
 *	preceded by 0x or 0X) and spaces; if there is only one string
 *	of hexadecimal digits, it is taken for the fraction bits of the
 *	resulting NaN; if there are two or more strings of hexadecimal
 *	digits, each string is assigned to the next available sequence
 *	of 32-bit words of fractions bits (starting with the most
 *	significant), right-aligned in each sequence.
 *	Unless GDTOA_NON_PEDANTIC_NANCHECK is #defined, input "NaN(...)"
 *	is consumed even when ... has the wrong form (in which case the
 *	"(...)" is consumed but ignored).
 * #define MULTIPLE_THREADS if the system offers preemptively scheduled
 *	multiple threads.  In this case, you must provide (or suitably
 *	#define) two locks, acquired by ACQUIRE_DTOA_LOCK(n) and freed
 *	by FREE_DTOA_LOCK(n) for n = 0 or 1.  (The second lock, accessed
 *	in pow5mult, ensures lazy evaluation of only one copy of high
 *	powers of 5; omitting this lock would introduce a small
 *	probability of wasting memory, but would otherwise be harmless.)
 *	You must also invoke freedtoa(s) to free the value s returned by
 *	dtoa.  You may do so whether or not MULTIPLE_THREADS is #defined.
 * #define IMPRECISE_INEXACT if you do not care about the setting of
 *	the STRTOG_Inexact bits in the special case of doing IEEE double
 *	precision conversions (which could also be done by the strtod in
 *	dtoa.c).
 * #define NO_HEX_FP to disable recognition of C9x's hexadecimal
 *	floating-point constants.
 * #define -DNO_ERRNO to suppress setting errno (in strtod.c and
 *	strtodg.c).
 * #define NO_STRING_H to use private versions of memcpy.
 *	On some K&R systems, it may also be necessary to
 *	#define DECLARE_SIZE_T in this case.
 * #define USE_LOCALE to use the current locale's decimal_point value.
 */

#ifndef GDTOAIMP_H_INCLUDED
#define GDTOAIMP_H_INCLUDED
#include "gdtoa.h"
#include "gd_qnan.h"
#ifdef Honor_FLT_ROUNDS
#include <fenv.h>
#endif

#ifdef DEBUG
#include "stdio.h"
#define Bug(x) {fprintf(stderr, "%s\n", x); exit(1);}
#endif

#include "stdlib.h"
#include "string.h"

#ifdef KR_headers
#define Char char
#else
#define Char void
#endif

#ifdef MALLOC
extern Char *MALLOC ANSI((size_t));
#else
#define MALLOC malloc
#endif

#undef IEEE_Arith
#undef Avoid_Underflow
#ifdef IEEE_MC68k
#define IEEE_Arith
#endif
#ifdef IEEE_8087
#define IEEE_Arith
#endif

#include "errno.h"
#ifdef Bad_float_h

#ifdef IEEE_Arith
#define DBL_DIG 15
#define DBL_MAX_10_EXP 308
#define DBL_MAX_EXP 1024
#define FLT_RADIX 2
#define DBL_MAX 1.7976931348623157e+308
#endif

#ifdef IBM
#define DBL_DIG 16
#define DBL_MAX_10_EXP 75
#define DBL_MAX_EXP 63
#define FLT_RADIX 16
#define DBL_MAX 7.2370055773322621e+75
#endif

#ifdef VAX
#define DBL_DIG 16
#define DBL_MAX_10_EXP 38
#define DBL_MAX_EXP 127
#define FLT_RADIX 2
#define DBL_MAX 1.7014118346046923e+38
#define n_bigtens 2
#endif

#ifndef LONG_MAX
#define LONG_MAX 2147483647
#endif

#else /* ifndef Bad_float_h */
#include "float.h"
#endif /* Bad_float_h */

#ifdef IEEE_Arith
#define Scale_Bit 0x10
#define n_bigtens 5
#endif

#ifdef IBM
#define n_bigtens 3
#endif

#ifdef VAX
#define n_bigtens 2
#endif

#ifndef __MATH_H__
#include "math.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(IEEE_8087) + defined(IEEE_MC68k) + defined(VAX) + defined(IBM) != 1
Exactly one of IEEE_8087, IEEE_MC68k, VAX, or IBM should be defined.
#endif

typedef union { double d; ULong L[2]; } U;

#ifdef IEEE_8087
#define word0(x) (x)->L[1]
#define word1(x) (x)->L[0]
#else
#define word0(x) (x)->L[0]
#define word1(x) (x)->L[1]
#endif
#define dval(x) (x)->d

/* The following definition of Storeinc is appropriate for MIPS processors.
 * An alternative that might be better on some machines is
 * #define Storeinc(a,b,c) (*a++ = b << 16 | c & 0xffff)
 */
#if defined(IEEE_8087) + defined(VAX)
#define Storeinc(a,b,c) (((unsigned short *)a)[1] = (unsigned short)b, \
((unsigned short *)a)[0] = (unsigned short)c, a++)
#else
#define Storeinc(a,b,c) (((unsigned short *)a)[0] = (unsigned short)b, \
((unsigned short *)a)[1] = (unsigned short)c, a++)
#endif

/* #define P DBL_MANT_DIG */
/* Ten_pmax = floor(P*log(2)/log(5)) */
/* Bletch = (highest power of 2 < DBL_MAX_10_EXP) / 16 */
/* Quick_max = floor((P-1)*log(FLT_RADIX)/log(10) - 1) */
/* Int_max = floor(P*log(FLT_RADIX)/log(10) - 1) */

#ifdef IEEE_Arith
#define Exp_shift  20
#define Exp_shift1 20
#define Exp_msk1    0x100000
#define Exp_msk11   0x100000
#define Exp_mask  0x7ff00000
#define P 53
#define Bias 1023
#define Emin (-1022)
#define Exp_1  0x3ff00000
#define Exp_11 0x3ff00000
#define Ebits 11
#define Frac_mask  0xfffff
#define Frac_mask1 0xfffff
#define Ten_pmax 22
#define Bletch 0x10
#define Bndry_mask  0xfffff
#define Bndry_mask1 0xfffff
#define LSB 1
#define Sign_bit 0x80000000
#define Log2P 1
#define Tiny0 0
#define Tiny1 1
#define Quick_max 14
#define Int_max 14

#ifndef Flt_Rounds
#ifdef FLT_ROUNDS
#define Flt_Rounds FLT_ROUNDS
#else
#define Flt_Rounds 1
#endif
#endif /*Flt_Rounds*/

#else /* ifndef IEEE_Arith */
#undef  Sudden_Underflow
#define Sudden_Underflow
#ifdef IBM
#undef Flt_Rounds
#define Flt_Rounds 0
#define Exp_shift  24
#define Exp_shift1 24
#define Exp_msk1   0x1000000
#define Exp_msk11  0x1000000
#define Exp_mask  0x7f000000
#define P 14
#define Bias 65
#define Exp_1  0x41000000
#define Exp_11 0x41000000
#define Ebits 8	/* exponent has 7 bits, but 8 is the right value in b2d */
#define Frac_mask  0xffffff
#define Frac_mask1 0xffffff
#define Bletch 4
#define Ten_pmax 22
#define Bndry_mask  0xefffff
#define Bndry_mask1 0xffffff
#define LSB 1
#define Sign_bit 0x80000000
#define Log2P 4
#define Tiny0 0x100000
#define Tiny1 0
#define Quick_max 14
#define Int_max 15
#else /* VAX */
#undef Flt_Rounds
#define Flt_Rounds 1
#define Exp_shift  23
#define Exp_shift1 7
#define Exp_msk1    0x80
#define Exp_msk11   0x800000
#define Exp_mask  0x7f80
#define P 56
#define Bias 129
#define Emin (-127)
#define Exp_1  0x40800000
#define Exp_11 0x4080
#define Ebits 8
#define Frac_mask  0x7fffff
#define Frac_mask1 0xffff007f
#define Ten_pmax 24
#define Bletch 2
#define Bndry_mask  0xffff007f
#define Bndry_mask1 0xffff007f
#define LSB 0x10000
#define Sign_bit 0x8000
#define Log2P 1
#define Tiny0 0x80
#define Tiny1 0
#define Quick_max 15
#define Int_max 15
#endif /* IBM, VAX */
#endif /* IEEE_Arith */

#ifndef IEEE_Arith
#define ROUND_BIASED
#else
#ifdef ROUND_BIASED_without_Round_Up
#undef  ROUND_BIASED
#define ROUND_BIASED
#endif
#endif

#ifdef RND_PRODQUOT
#define rounded_product(a,b) a = rnd_prod(a, b)
#define rounded_quotient(a,b) a = rnd_quot(a, b)
#ifdef KR_headers
extern double rnd_prod(), rnd_quot();
#else
extern double rnd_prod(double, double), rnd_quot(double, double);
#endif
#else
#define rounded_product(a,b) a *= b
#define rounded_quotient(a,b) a /= b
#endif

#define Big0 (Frac_mask1 | Exp_msk1*(DBL_MAX_EXP+Bias-1))
#define Big1 0xffffffff

#undef  Pack_16
#ifndef Pack_32
#define Pack_32
#endif

#ifdef NO_LONG_LONG
#undef ULLong
#ifdef Just_16
#undef Pack_32
#define Pack_16
/* When Pack_32 is not defined, we store 16 bits per 32-bit Long.
 * This makes some inner loops simpler and sometimes saves work
 * during multiplications, but it often seems to make things slightly
 * slower.  Hence the default is now to store 32 bits per Long.
 */
#endif
#else	/* long long available */
#ifndef Llong
#define Llong long long
#endif
#ifndef ULLong
#define ULLong unsigned Llong
#endif
#endif /* NO_LONG_LONG */

#ifdef Pack_32
#define ULbits 32
#define kshift 5
#define kmask 31
#define ALL_ON 0xffffffff
#else
#define ULbits 16
#define kshift 4
#define kmask 15
#define ALL_ON 0xffff
#endif

#ifndef MULTIPLE_THREADS
#define ACQUIRE_DTOA_LOCK(n)	/*nothing*/
#define FREE_DTOA_LOCK(n)	/*nothing*/
#else
#include "thread_private.h"
#define ACQUIRE_DTOA_LOCK(n)	_MUTEX_LOCK(&__dtoa_locks[n])
#define FREE_DTOA_LOCK(n)	_MUTEX_UNLOCK(&__dtoa_locks[n])
#endif

#define Kmax 9

 struct
Bigint {
	struct Bigint *next;
	int k, maxwds, sign, wds;
	ULong x[1];
	};

 typedef struct Bigint Bigint;

#ifdef NO_STRING_H
#ifdef DECLARE_SIZE_T
typedef unsigned int size_t;
#endif
extern void memcpy_D2A ANSI((void*, const void*, size_t));
#define Bcopy(x,y) memcpy_D2A(&x->sign,&y->sign,y->wds*sizeof(ULong) + 2*sizeof(int))
#else /* !NO_STRING_H */
#define Bcopy(x,y) memcpy(&x->sign,&y->sign,y->wds*sizeof(ULong) + 2*sizeof(int))
#endif /* NO_STRING_H */

#define dtoa __dtoa
#define gdtoa __gdtoa
#define freedtoa __freedtoa
#define strtodg __strtodg
#define g_ddfmt __g_ddfmt
#define g_dfmt __g_dfmt
#define g_ffmt __g_ffmt
#define g_Qfmt __g_Qfmt
#define g_xfmt __g_xfmt
#define g_xLfmt __g_xLfmt
#define strtoId __strtoId
#define strtoIdd __strtoIdd
#define strtoIf __strtoIf
#define strtoIQ __strtoIQ
#define strtoIx __strtoIx
#define strtoIxL __strtoIxL
#define strtord __strtord
#define strtordd __strtordd
#define strtorf __strtorf
#define strtorQ __strtorQ
#define strtorx __strtorx
#define strtorxL __strtorxL
#define strtodI __strtodI
#define strtopd __strtopd
#define strtopdd __strtopdd
#define strtopf __strtopf
#define strtopQ __strtopQ
#define strtopx __strtopx
#define strtopxL __strtopxL

#define Balloc __Balloc_D2A
#define Bfree __Bfree_D2A
#define ULtoQ __ULtoQ_D2A
#define ULtof __ULtof_D2A
#define ULtod __ULtod_D2A
#define ULtodd __ULtodd_D2A
#define ULtox __ULtox_D2A
#define ULtoxL __ULtoxL_D2A
#define any_on __any_on_D2A
#define b2d __b2d_D2A
#define bigtens __bigtens_D2A
#define cmp __cmp_D2A
#define copybits __copybits_D2A
#define d2b __d2b_D2A
#define decrement __decrement_D2A
#define diff __diff_D2A
#define dtoa_result __dtoa_result_D2A
#define g__fmt __g__fmt_D2A
#define gethex __gethex_D2A
#define hexdig __hexdig_D2A
#define hexnan __hexnan_D2A
#define hi0bits(x) __hi0bits_D2A((ULong)(x))
#define hi0bits_D2A __hi0bits_D2A
#define i2b __i2b_D2A
#define increment __increment_D2A
#define lo0bits __lo0bits_D2A
#define lshift __lshift_D2A
#define match __match_D2A
#define mult __mult_D2A
#define multadd __multadd_D2A
#define nrv_alloc __nrv_alloc_D2A
#define pow5mult __pow5mult_D2A
#define quorem __quorem_D2A
#define ratio __ratio_D2A
#define rshift __rshift_D2A
#define rv_alloc __rv_alloc_D2A
#define s2b __s2b_D2A
#define set_ones __set_ones_D2A
#define strcp __strcp_D2A
#define strtoIg __strtoIg_D2A
#define sulp __sulp_D2A
#define sum __sum_D2A
#define tens __tens_D2A
#define tinytens __tinytens_D2A
#define tinytens __tinytens_D2A
#define trailz __trailz_D2A
#define ulp __ulp_D2A

__BEGIN_HIDDEN_DECLS
 extern char *dtoa_result;
 extern CONST double bigtens[], tens[], tinytens[];
 extern unsigned char hexdig[];

 extern Bigint *Balloc ANSI((int));
 extern void Bfree ANSI((Bigint*));
 extern void ULtof ANSI((ULong*, ULong*, Long, int));
 extern void ULtod ANSI((ULong*, ULong*, Long, int));
 extern void ULtodd ANSI((ULong*, ULong*, Long, int));
 extern void ULtoQ ANSI((ULong*, ULong*, Long, int));
 extern void ULtox ANSI((UShort*, ULong*, Long, int));
 extern void ULtoxL ANSI((ULong*, ULong*, Long, int));
 extern ULong any_on ANSI((Bigint*, int));
 extern double b2d ANSI((Bigint*, int*));
 extern int cmp ANSI((Bigint*, Bigint*));
 extern void copybits ANSI((ULong*, int, Bigint*));
 extern Bigint *d2b ANSI((double, int*, int*));
 extern void decrement ANSI((Bigint*));
 extern Bigint *diff ANSI((Bigint*, Bigint*));
 extern char *g__fmt ANSI((char*, char*, char*, int, ULong, size_t));
 extern int gethex ANSI((CONST char**, FPI*, Long*, Bigint**, int));
 extern void __hexdig_init_D2A(Void);
 extern int hexnan ANSI((CONST char**, FPI*, ULong*));
 extern int hi0bits_D2A ANSI((ULong));
 extern Bigint *i2b ANSI((int));
 extern Bigint *increment ANSI((Bigint*));
 extern int lo0bits ANSI((ULong*));
 extern Bigint *lshift ANSI((Bigint*, int));
 extern int match ANSI((CONST char**, char*));
 extern Bigint *mult ANSI((Bigint*, Bigint*));
 extern Bigint *multadd ANSI((Bigint*, int, int));
 extern char *nrv_alloc ANSI((char*, char **, int));
 extern Bigint *pow5mult ANSI((Bigint*, int));
 extern int quorem ANSI((Bigint*, Bigint*));
 extern double ratio ANSI((Bigint*, Bigint*));
 extern void rshift ANSI((Bigint*, int));
 extern char *rv_alloc ANSI((int));
 extern Bigint *s2b ANSI((CONST char*, int, int, ULong, int));
 extern Bigint *set_ones ANSI((Bigint*, int));
 extern char *strcp ANSI((char*, const char*));
 extern int strtoIg ANSI((CONST char*, char**, FPI*, Long*, Bigint**, int*));
 extern Bigint *sum ANSI((Bigint*, Bigint*));
 extern int trailz ANSI((Bigint*));
 extern double ulp ANSI((U*));
__END_HIDDEN_DECLS

#ifdef __cplusplus
}
#endif
/*
 * NAN_WORD0 and NAN_WORD1 are only referenced in strtod.c.  Prior to
 * 20050115, they used to be hard-wired here (to 0x7ff80000 and 0,
 * respectively), but now are determined by compiling and running
 * qnan.c to generate gd_qnan.h, which specifies d_QNAN0 and d_QNAN1.
 * Formerly gdtoaimp.h recommended supplying suitable -DNAN_WORD0=...
 * and -DNAN_WORD1=...  values if necessary.  This should still work.
 * (On HP Series 700/800 machines, -DNAN_WORD0=0x7ff40000 works.)
 */
#ifdef IEEE_Arith
#ifndef NO_INFNAN_CHECK
#undef INFNAN_CHECK
#define INFNAN_CHECK
#endif
#ifdef IEEE_MC68k
#define _0 0
#define _1 1
#ifndef NAN_WORD0
#define NAN_WORD0 d_QNAN0
#endif
#ifndef NAN_WORD1
#define NAN_WORD1 d_QNAN1
#endif
#else
#define _0 1
#define _1 0
#ifndef NAN_WORD0
#define NAN_WORD0 d_QNAN1
#endif
#ifndef NAN_WORD1
#define NAN_WORD1 d_QNAN0
#endif
#endif
#else
#undef INFNAN_CHECK
#endif

#undef SI
#ifdef Sudden_Underflow
#define SI 1
#else
#define SI 0
#endif

#endif /* GDTOAIMP_H_INCLUDED */

"""

```
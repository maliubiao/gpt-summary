Response:
Let's break down the thought process for analyzing the `hdtoa.c` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `hdtoa.c` file, focusing on its functionality, relationship to Android, implementation details, dynamic linking aspects, potential errors, and how it's reached within the Android framework. The output should be in Chinese.

**2. Initial Code Examination and High-Level Understanding:**

* **Headers:** The `#include` directives reveal dependencies on standard C library headers (`sys/types.h`, `float.h`, `limits.h`, `math.h`) and a project-specific header (`gdtoaimp.h`). This suggests it's involved in number conversion, specifically dealing with floating-point numbers. The `machine/ieee.h` header points to IEEE 754 floating-point representation.
* **Function Names:** The core functions are `__hdtoa` (for `double`) and `__hldtoa` (for `long double`). The "h" likely stands for hexadecimal, hinting at converting floating-point numbers to hexadecimal string representations. The `dtoa` in the comments reinforces this idea.
* **Constants:**  `INFSTR`, `NANSTR` are clearly for infinity and Not-a-Number representations. `DBL_ADJ` and `LDBL_ADJ` look like adjustments related to the exponent handling of `double` and `long double`.
* **Helper Functions:** `roundup` performs rounding up of a digit string, and `dorounding` implements the rounding logic based on the current floating-point rounding mode.

**3. Deeper Dive into Core Functions (`__hdtoa` and `__hldtoa`):**

* **Input Parameters:**  Both functions take a floating-point number (`double` or `long double`), a string of hexadecimal digits (`xdigs`), the desired number of digits (`ndigits`), and pointers to store the decimal exponent (`decpt`), sign (`sign`), and the end of the digit string (`rve`).
* **Sign Handling:** The sign of the floating-point number is extracted early.
* **Special Cases:** The `switch (fpclassify(d))` block handles special floating-point values like zero, subnormal numbers, infinity, and NaN. This is a crucial part of correctly representing these values.
* **Exponent Calculation:**  For normal and subnormal numbers, the decimal exponent is calculated based on the internal representation of the floating-point number. The adjustments `DBL_ADJ` and `LDBL_ADJ` are applied.
* **Digit Generation:** The code iterates through the mantissa bits, converting them to hexadecimal digits. It works from right to left, filling a buffer.
* **Rounding:**  If `ndigits` is specified, the `dorounding` function is called to round the generated digits.
* **Output Formatting:** The generated hexadecimal digits are placed into the output buffer, and the `decpt`, `sign`, and `rve` pointers are updated.
* **`__hldtoa` Implementation (and the `#if` block):**  The code cleverly reuses `__hdtoa` for `long double` if `LDBL_MANT_DIG` is the same as `DBL_MANT_DIG`. This avoids code duplication.

**4. Connecting to Android and `libc`:**

* **`bionic` Context:** The file path indicates it's part of Android's `bionic` library, the core C library. This means these functions are fundamental for number formatting within the Android system.
* **`gdtoa`:** The subdirectory `gdtoa` suggests this is related to the "Gay Decimal To ASCII" or similar algorithm, a well-known approach for accurate floating-point to string conversion.
* **`libc` Functions:**  These `__hdtoa` and `__hldtoa` functions are likely internal helpers for standard `libc` functions like `sprintf`, `printf`, `snprintf`, and potentially even `std::to_string` in C++.

**5. Dynamic Linking Considerations:**

* **`DEF_STRONG` Macro:** The `DEF_STRONG(__hdtoa)` macro likely makes the function a "strong" symbol for linking. This means it will be preferred over weaker symbols if there are conflicts.
* **SO Layout:**  The functions would reside in `libc.so` (or potentially a math library like `libm.so` depending on the exact Android build).
* **Linking Process:**  When an Android app calls a function like `sprintf` that internally uses `__hdtoa`, the dynamic linker resolves the symbol `__hdtoa` to its address in `libc.so`.

**6. Identifying Potential Errors:**

* **User Errors:**  Incorrectly specifying `ndigits` or providing a null pointer for output parameters are common mistakes.
* **Implementation Details:** The code itself seems robust, but potential issues could arise in memory allocation (`rv_alloc`, `nrv_alloc`) if memory is low. The rounding logic is complex and needs careful implementation.

**7. Tracing the Execution Flow (Android Framework/NDK):**

* **Framework:**  A high-level framework API call (e.g., displaying a floating-point number in a UI) would eventually lead to a call to a formatting function in `libandroid_runtime.so` or similar, which would then call `libc` functions.
* **NDK:** An NDK application directly calling `sprintf` or similar functions would go straight to `libc`.

**8. Frida Hooking (Mental Outline):**

* **Targeting:**  Hooking `__hdtoa` or a higher-level function like `sprintf` would be effective.
* **Parameters:** Log the input floating-point number, `ndigits`, and other parameters.
* **Return Value:** Log the generated string.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe these functions are directly exposed to developers. **Correction:**  More likely internal helpers for higher-level formatting functions.
* **Initial thought:** Focus heavily on the mathematical details of the conversion. **Correction:**  Balance that with the Android context and dynamic linking aspects.
* **Considering the level of detail:** The prompt asks for a *detailed* explanation. So, going beyond just the function's purpose and delving into the implementation, potential issues, and how it fits into the Android ecosystem is crucial.

By following these steps, combining code analysis with an understanding of the Android ecosystem and dynamic linking, a comprehensive and accurate answer can be constructed. The key is to break down the problem into smaller, manageable parts and then synthesize the information.
好的，让我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/hdtoa.c` 这个文件。

**文件功能概览**

`hdtoa.c` 文件实现了将 IEEE 754 标准的浮点数（`double` 和 `long double`）转换为十六进制字符串表示的功能。它提供了两个主要的函数：

* **`__hdtoa(double d, const char *xdigs, int ndigits, int *decpt, int *sign, char **rve)`:** 将 `double` 类型的浮点数 `d` 转换为十六进制字符串。
* **`__hldtoa(long double e, const char *xdigs, int ndigits, int *decpt, int *sign, char **rve)`:** 将 `long double` 类型的浮点数 `e` 转换为十六进制字符串。

这两个函数的功能与 `dtoa()` 函数的模式 2 类似，但做了一些改进和扩展，使其更加灵活和准确。

**与 Android 功能的关系及举例说明**

这个文件是 Android 系统 C 库 `bionic` 的一部分，因此其功能直接服务于 Android 系统的各种底层需求，特别是涉及到浮点数格式化输出的场景。

**举例说明:**

1. **`printf` 和相关函数:**  当 Android 系统或应用程序使用 `printf`、`sprintf`、`snprintf` 等函数格式化输出浮点数，并指定使用十六进制格式（例如 `%a`）时，最终会调用到 `hdtoa.c` 中的函数。

   ```c
   #include <stdio.h>

   int main() {
       double pi = 3.14159265358979323846;
       printf("Pi in hex: %a\n", pi); // 这里会间接调用 __hdtoa
       return 0;
   }
   ```

2. **Java 的 `Double.toHexString()` 和 `Float.toHexString()`:**  Java 层面的浮点数转十六进制字符串的方法，在底层很可能会调用到 Native 代码，而 `bionic` 提供的 `hdtoa` 功能正是实现这一点的关键。

3. **调试器 (Debugger):**  当使用 Android 的调试工具（例如 LLDB）查看浮点数变量的内存表示时，调试器可能会使用类似的转换逻辑来显示十六进制形式的浮点数。

**libc 函数的实现细节**

让我们详细解释 `__hdtoa` 和 `__hldtoa` 的实现：

**1. `__hdtoa` (针对 `double`)**

* **输入参数:**
    * `d`: 要转换的 `double` 类型浮点数。
    * `xdigs`: 指向一个包含十六进制数字字符的字符串，通常是 "0123456789abcdef" 或 "0123456789ABCDEF"。
    * `ndigits`:  指定要生成的十六进制数字的位数。如果小于 0，则生成表示该数所需的所有位数。
    * `decpt`:  指向一个 `int` 变量的指针，用于存储转换后的十进制指数（以 2 为底）。
    * `sign`:  指向一个 `int` 变量的指针，用于存储符号（0 表示正，非 0 表示负）。
    * `rve`:  指向一个 `char*` 变量的指针，用于存储指向生成字符串末尾的指针。

* **实现步骤:**
    1. **处理符号:** 从 `double` 的 IEEE 754 表示中提取符号位。
    2. **处理特殊值:** 使用 `fpclassify()` 检查浮点数是否为正常值、零、次正规数、无穷大或 NaN (Not a Number)。
        * **正常值:**  计算初始指数 `*decpt`。
        * **零:**  直接返回字符串 "0"。
        * **次正规数:**  将其乘以一个大的 2 的幂，使其变成正规数，并调整指数。
        * **无穷大:** 设置 `*decpt` 为 `INT_MAX`，返回 "Infinity"。
        * **NaN:** 设置 `*decpt` 为 `INT_MAX`，返回 "NaN"。
    3. **确定精度:** 如果 `ndigits` 为 0，则设置为 1（为了兼容 `dtoa()`）。如果 `ndigits` 小于 0，则根据需要自动确定精度。
    4. **分配缓冲区:** 分配足够的内存来存储生成的十六进制数字。
    5. **生成十六进制数字:**  从浮点数的尾数部分提取位，并将其转换为十六进制数字（0-f）。这个过程从右向左进行，先填充零填充，然后是尾数的最低有效部分，最后是最高有效部分。
    6. **处理隐含位:**  IEEE 754 的正规数有一个隐含的前导 1，需要将其考虑在内。
    7. **舍入:** 如果生成的位数多于请求的位数，并且需要舍入，则调用 `dorounding()` 函数进行舍入。
    8. **格式化输出:** 将十六进制数字字符写入缓冲区，并在末尾添加 null 终止符。
    9. **返回结果:** 返回指向生成字符串的指针。

**2. `__hldtoa` (针对 `long double`)**

* **输入参数:**  与 `__hdtoa` 类似，但操作的是 `long double` 类型。
* **实现步骤:**
    * 大部分逻辑与 `__hdtoa` 相同，但针对 `long double` 的 IEEE 754 扩展精度格式进行操作。
    * 它使用 `struct ieee_ext` 来访问 `long double` 的组成部分（符号、指数、尾数）。
    * 代码中可以看到针对不同 `long double` 实现中尾数位域 (`EXT_FRACLBITS`, `EXT_FRACLMBITS`, `EXT_FRACHMBITS`, `EXT_FRACHBITS`) 的处理。
    * 如果 `LDBL_MANT_DIG` 等于 `DBL_MANT_DIG`，则直接调用 `__hdtoa`，避免代码重复。

**辅助函数:**

* **`roundup(char *s0, int ndigits)`:**  将给定的数字字符串向上舍入。如果字符串是 "fff...f"，则将其设置为 "100...0" 并返回 1，表示需要调整指数。否则返回 0。
* **`dorounding(char *s0, int ndigits, int sign, int *decpt)`:**  根据当前的浮点数舍入模式，将给定的数字字符串舍入到 `ndigits` 位。如果需要，会调整指数 `*decpt`。它根据 `FLT_ROUNDS` 宏的值来确定舍入模式（向零舍入、向最接近的值舍入、向正无穷舍入、向负无穷舍入）。

**涉及 dynamic linker 的功能**

`hdtoa.c` 本身并不直接涉及 dynamic linker 的操作。它提供的函数是 `libc.so` 的一部分，会被其他库或应用程序通过 dynamic linker 加载和链接。

**SO 布局样本:**

假设一个简化的 `libc.so` 布局：

```
libc.so:
    .text:
        ...
        __hdtoa:  <__hdtoa 函数的代码>
        __hldtoa: <__hldtoa 函数的代码>
        printf:   <printf 函数的代码>
        ...
    .data:
        ...
    .rodata:
        ...
```

**链接的处理过程:**

1. **编译时:** 当一个应用程序（例如上面 `printf` 的例子）调用 `printf` 函数时，编译器会在其目标文件中的符号表中记录对 `printf` 和 `__hdtoa`（如果 `printf` 内部调用了它）的未定义引用。
2. **链接时:** 链接器将应用程序的目标文件与 `libc.so` 链接在一起。链接器会解析应用程序中对 `printf` 和 `__hdtoa` 的未定义引用，将它们指向 `libc.so` 中相应函数的地址。
3. **运行时:** 当应用程序启动时，Android 的 dynamic linker (`linker64` 或 `linker`) 会加载必要的共享库，包括 `libc.so`。dynamic linker 会根据链接时的信息，将应用程序中对 `printf` 和 `__hdtoa` 的调用重定向到 `libc.so` 中这些函数的实际内存地址。

**逻辑推理、假设输入与输出**

**假设输入:**

* `d = 10.5` (double)
* `xdigs = "0123456789abcdef"`
* `ndigits = 0` (自动精度)

**逻辑推理:**

1. `fpclassify(d)` 返回 `FP_NORMAL`。
2. 计算初始指数。
3. 将 `10.5` 的尾数转换为十六进制表示。`10.5` 在 IEEE 754 中表示为 `0x4025000000000000`。尾数部分提取出来并加上隐含的 1，转换为十六进制数字。
4. 因为 `ndigits` 为 0，精度会自动调整。
5. 输出结果会是类似于 "1.5000000000000p+3" 的形式（具体格式可能略有不同，取决于实现细节和是否包含前导 0x）。但由于 `__hdtoa` 的目的是生成十六进制 *数字* 字符串，所以会是 "15000000000000"。
6. `decpt` 会被设置为相应的指数值（以 2 为底），这里是 3 + 4 = 7 （因为小数点左移了 4 位）。
7. `sign` 为 0（正数）。
8. `rve` 指向字符串末尾。

**假设输出:**

* 返回值: 指向字符串 "15000000000000" 的指针
* `*decpt`: 4
* `*sign`: 0

**假设输入:**

* `e = 0.00000000000000000000005` (long double)
* `xdigs = "0123456789ABCDEF"`
* `ndigits = 5`

**逻辑推理:**

1. `fpclassify(e)` 返回 `FP_SUBNORMAL`。
2. 将 `e` 乘以一个大的 2 的幂，使其变成正规数。
3. 提取尾数并转换为大写十六进制数字。
4. 舍入到 5 位。

**假设输出:**

* 返回值: 指向类似于 "B.CDEF" 的字符串的指针（实际数字会根据具体实现和精度有所不同）
* `*decpt`: 负数（表示很小的数）
* `*sign`: 0

**用户或编程常见的使用错误**

1. **`xdigs` 参数错误:** 传递了错误的字符集，导致输出的不是标准的十六进制数字。
2. **`ndigits` 误用:**
   * 传递了非常大的 `ndigits` 值，可能导致分配大量的内存。
   * 期望 `ndigits` 控制小数点后的位数，但实际上它是控制总的有效十六进制数字位数。
3. **未检查返回值:** 如果内存分配失败，`rv_alloc` 可能会返回 `NULL`，如果未检查返回值，可能导致程序崩溃。
4. **不理解 `decpt` 的含义:** `decpt` 返回的是以 2 为底的指数，与十进制的指数不同，容易混淆。

**Android Framework 或 NDK 如何到达这里**

**Android Framework 示例 (Java -> Native):**

1. **Java 代码:**  在 Android Framework 的 Java 代码中，可能需要将一个 `double` 或 `float` 转换为十六进制字符串。例如，`Double.toHexString(double d)` 或 `Float.toHexString(float f)` 被调用。

   ```java
   double value = 123.45;
   String hexString = Double.toHexString(value);
   ```

2. **Native 方法调用:** `Double.toHexString()` 和 `Float.toHexString()` 是 Native 方法，它们会在 Dalvik/ART 虚拟机中调用到对应的 JNI 实现。

3. **`libjavacrypto.so` 或其他 JNI 库:**  这些 JNI 实现可能位于 `libjavacrypto.so` 或其他相关的 Native 库中。

4. **调用 `bionic` 库函数:** 在这些 Native 代码中，最终会调用到 `bionic` 库提供的格式化输出函数，例如 `snprintf`。

5. **`snprintf` 内部调用:** `snprintf` 函数在处理 `%a` 格式说明符时，会调用到 `__hdtoa` 或 `__hldtoa`。

**NDK 示例 (C/C++ 代码):**

1. **NDK 代码:**  使用 NDK 开发的应用程序可以直接调用 C 标准库函数。

   ```c++
   #include <cstdio>

   int main() {
       double value = 123.45;
       char buffer[64];
       snprintf(buffer, sizeof(buffer), "%a", value); // 直接调用 bionic 的 snprintf
       return 0;
   }
   ```

2. **链接到 `libc.so`:** NDK 应用程序在链接时会链接到 `bionic` 提供的 `libc.so`。

3. **直接调用:**  `snprintf` 函数的实现位于 `libc.so` 中，当执行到 `snprintf` 并且格式化字符串包含 `%a` 时，会调用到 `__hdtoa`。

**Frida Hook 示例**

以下是一个使用 Frida Hook 调试 `__hdtoa` 的示例：

```javascript
if (Process.arch === 'arm64') {
    var hdtoa_ptr = Module.findExportByName("libc.so", "__hdtoa");
    if (hdtoa_ptr) {
        Interceptor.attach(hdtoa_ptr, {
            onEnter: function (args) {
                console.log("[__hdtoa] Called");
                console.log("\td =", args[0]); // double
                console.log("\txdigs =", Memory.readUtf8String(args[1]));
                console.log("\tndigits =", args[2].toInt32());
                console.log("\tdecpt =", args[3]);
                console.log("\tsign =", args[4]);
                console.log("\trve =", args[5]);
            },
            onLeave: function (retval) {
                console.log("[__hdtoa] Returned:", retval);
                if (retval) {
                    console.log("\tString:", Memory.readUtf8String(retval));
                }
            }
        });
    } else {
        console.log("[__hdtoa] Not found in libc.so");
    }
}
```

**解释:**

1. **检查架构:**  代码首先检查进程架构是否为 `arm64`，你需要根据目标设备的架构调整。
2. **查找函数地址:** `Module.findExportByName("libc.so", "__hdtoa")` 尝试在 `libc.so` 中查找 `__hdtoa` 函数的地址。
3. **拦截函数:** `Interceptor.attach()` 用于拦截对 `__hdtoa` 函数的调用。
4. **`onEnter`:**  在函数调用前执行，打印输入参数的值。
5. **`onLeave`:** 在函数返回后执行，打印返回值（指向生成的字符串）以及字符串内容。

你可以将这段 JavaScript 代码注入到 Android 进程中，当程序执行到调用 `__hdtoa` 的代码时，Frida 会拦截并打印相关信息，帮助你理解参数传递和返回值。

**总结**

`hdtoa.c` 是 Android 系统中用于将浮点数转换为十六进制字符串的关键底层组件。它被广泛用于各种场景，从基本的格式化输出到更底层的内存表示。理解其功能和实现细节对于深入理解 Android 系统的运行机制至关重要。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/hdtoa.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: hdtoa.c,v 1.5 2020/05/31 12:27:19 mortimer Exp $	*/
/*-
 * Copyright (c) 2004, 2005 David Schultz <das@FreeBSD.ORG>
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

#include <sys/types.h>
#include <machine/ieee.h>
#include <float.h>
#include <limits.h>
#include <math.h>

#include "gdtoaimp.h"

/* Strings values used by dtoa() */
#define	INFSTR	"Infinity"
#define	NANSTR	"NaN"

#define	DBL_ADJ		(DBL_MAX_EXP - 2 + ((DBL_MANT_DIG - 1) % 4))
#define	LDBL_ADJ	(LDBL_MAX_EXP - 2 + ((LDBL_MANT_DIG - 1) % 4))

/*
 * Round up the given digit string.  If the digit string is fff...f,
 * this procedure sets it to 100...0 and returns 1 to indicate that
 * the exponent needs to be bumped.  Otherwise, 0 is returned.
 */
static int
roundup(char *s0, int ndigits)
{
	char *s;

	for (s = s0 + ndigits - 1; *s == 0xf; s--) {
		if (s == s0) {
			*s = 1;
			return (1);
		}
		*s = 0;
	}
	++*s;
	return (0);
}

/*
 * Round the given digit string to ndigits digits according to the
 * current rounding mode.  Note that this could produce a string whose
 * value is not representable in the corresponding floating-point
 * type.  The exponent pointed to by decpt is adjusted if necessary.
 */
static void
dorounding(char *s0, int ndigits, int sign, int *decpt)
{
	int adjust = 0;	/* do we need to adjust the exponent? */

	switch (FLT_ROUNDS) {
	case 0:		/* toward zero */
	default:	/* implementation-defined */
		break;
	case 1:		/* to nearest, halfway rounds to even */
		if ((s0[ndigits] > 8) ||
		    (s0[ndigits] == 8 && s0[ndigits + 1] & 1))
			adjust = roundup(s0, ndigits);
		break;
	case 2:		/* toward +inf */
		if (sign == 0)
			adjust = roundup(s0, ndigits);
		break;
	case 3:		/* toward -inf */
		if (sign != 0)
			adjust = roundup(s0, ndigits);
		break;
	}

	if (adjust)
		*decpt += 4;
}

/*
 * This procedure converts a double-precision number in IEEE format
 * into a string of hexadecimal digits and an exponent of 2.  Its
 * behavior is bug-for-bug compatible with dtoa() in mode 2, with the
 * following exceptions:
 *
 * - An ndigits < 0 causes it to use as many digits as necessary to
 *   represent the number exactly.
 * - The additional xdigs argument should point to either the string
 *   "0123456789ABCDEF" or the string "0123456789abcdef", depending on
 *   which case is desired.
 * - This routine does not repeat dtoa's mistake of setting decpt
 *   to 9999 in the case of an infinity or NaN.  INT_MAX is used
 *   for this purpose instead.
 *
 * Note that the C99 standard does not specify what the leading digit
 * should be for non-zero numbers.  For instance, 0x1.3p3 is the same
 * as 0x2.6p2 is the same as 0x4.cp1.  This implementation chooses the
 * first digit so that subsequent digits are aligned on nibble
 * boundaries (before rounding).
 *
 * Inputs:	d, xdigs, ndigits
 * Outputs:	decpt, sign, rve
 */
char *
__hdtoa(double d, const char *xdigs, int ndigits, int *decpt, int *sign,
    char **rve)
{
	static const int sigfigs = (DBL_MANT_DIG + 3) / 4;
	struct ieee_double *p = (struct ieee_double *)&d;
	char *s, *s0;
	int bufsize;

	*sign = p->dbl_sign;

	switch (fpclassify(d)) {
	case FP_NORMAL:
		*decpt = p->dbl_exp - DBL_ADJ;
		break;
	case FP_ZERO:
		*decpt = 1;
		return (nrv_alloc("0", rve, 1));
	case FP_SUBNORMAL:
		d *= 0x1p514;
		*decpt = p->dbl_exp - (514 + DBL_ADJ);
		break;
	case FP_INFINITE:
		*decpt = INT_MAX;
		return (nrv_alloc(INFSTR, rve, sizeof(INFSTR) - 1));
	case FP_NAN:
		*decpt = INT_MAX;
		return (nrv_alloc(NANSTR, rve, sizeof(NANSTR) - 1));
	default:
		abort();
	}

	/* FP_NORMAL or FP_SUBNORMAL */

	if (ndigits == 0)		/* dtoa() compatibility */
		ndigits = 1;

	/*
	 * For simplicity, we generate all the digits even if the
	 * caller has requested fewer.
	 */
	bufsize = (sigfigs > ndigits) ? sigfigs : ndigits;
	s0 = rv_alloc(bufsize);
	if (s0 == NULL)
		return (NULL);

	/*
	 * We work from right to left, first adding any requested zero
	 * padding, then the least significant portion of the
	 * mantissa, followed by the most significant.  The buffer is
	 * filled with the byte values 0x0 through 0xf, which are
	 * converted to xdigs[0x0] through xdigs[0xf] after the
	 * rounding phase.
	 */
	for (s = s0 + bufsize - 1; s > s0 + sigfigs - 1; s--)
		*s = 0;
	for (; s > s0 + sigfigs - (DBL_FRACLBITS / 4) - 1 && s > s0; s--) {
		*s = p->dbl_fracl & 0xf;
		p->dbl_fracl >>= 4;
	}
	for (; s > s0; s--) {
		*s = p->dbl_frach & 0xf;
		p->dbl_frach >>= 4;
	}

	/*
	 * At this point, we have snarfed all the bits in the
	 * mantissa, with the possible exception of the highest-order
	 * (partial) nibble, which is dealt with by the next
	 * statement.  We also tack on the implicit normalization bit.
	 */
	*s = p->dbl_frach | (1U << ((DBL_MANT_DIG - 1) % 4));

	/* If ndigits < 0, we are expected to auto-size the precision. */
	if (ndigits < 0) {
		for (ndigits = sigfigs; s0[ndigits - 1] == 0; ndigits--)
			;
	}

	if (sigfigs > ndigits && s0[ndigits] != 0)
		dorounding(s0, ndigits, p->dbl_sign, decpt);

	s = s0 + ndigits;
	if (rve != NULL)
		*rve = s;
	*s-- = '\0';
	for (; s >= s0; s--)
		*s = xdigs[(unsigned int)*s];

	return (s0);
}
DEF_STRONG(__hdtoa);

#if (LDBL_MANT_DIG > DBL_MANT_DIG)

/*
 * This is the long double version of __hdtoa().
 */
char *
__hldtoa(long double e, const char *xdigs, int ndigits, int *decpt, int *sign,
    char **rve)
{
	static const int sigfigs = (LDBL_MANT_DIG + 3) / 4;
	struct ieee_ext *p = (struct ieee_ext *)&e;
	char *s, *s0;
	int bufsize;
	int fbits = 0;

	*sign = p->ext_sign;

	switch (fpclassify(e)) {
	case FP_NORMAL:
		*decpt = p->ext_exp - LDBL_ADJ;
		break;
	case FP_ZERO:
		*decpt = 1;
		return (nrv_alloc("0", rve, 1));
	case FP_SUBNORMAL:
		e *= 0x1p514L;
		*decpt = p->ext_exp - (514 + LDBL_ADJ);
		break;
	case FP_INFINITE:
		*decpt = INT_MAX;
		return (nrv_alloc(INFSTR, rve, sizeof(INFSTR) - 1));
	case FP_NAN:
		*decpt = INT_MAX;
		return (nrv_alloc(NANSTR, rve, sizeof(NANSTR) - 1));
	default:
		abort();
	}

	/* FP_NORMAL or FP_SUBNORMAL */

	if (ndigits == 0)		/* dtoa() compatibility */
		ndigits = 1;

	/*
	 * For simplicity, we generate all the digits even if the
	 * caller has requested fewer.
	 */
	bufsize = (sigfigs > ndigits) ? sigfigs : ndigits;
	s0 = rv_alloc(bufsize);
	if (s0 == NULL)
		return (NULL);

	/*
	 * We work from right to left, first adding any requested zero
	 * padding, then the least significant portion of the
	 * mantissa, followed by the most significant.  The buffer is
	 * filled with the byte values 0x0 through 0xf, which are
	 * converted to xdigs[0x0] through xdigs[0xf] after the
	 * rounding phase.
	 */
	for (s = s0 + bufsize - 1; s > s0 + sigfigs - 1; s--)
		*s = 0;

	for (fbits = EXT_FRACLBITS / 4; fbits > 0 && s > s0; s--, fbits--) {
		*s = p->ext_fracl & 0xf;
		p->ext_fracl >>= 4;
	}
#ifdef EXT_FRACLMBITS
	for (fbits = EXT_FRACLMBITS / 4; fbits > 0 && s > s0; s--, fbits--) {
		*s = p->ext_fraclm & 0xf;
		p->ext_fraclm >>= 4;
	}
#endif
#ifdef EXT_FRACHMBITS
	for (fbits = EXT_FRACHMBITS / 4; fbits > 0 && s > s0; s--, fbits--) {
		*s = p->ext_frachm & 0xf;
		p->ext_frachm >>= 4;
	}
#endif
	for (fbits = EXT_FRACHBITS / 4; fbits > 0 && s > s0; s--, fbits--) {
		*s = p->ext_frach & 0xf;
		p->ext_frach >>= 4;
	}

	/*
	 * At this point, we have snarfed all the bits in the
	 * mantissa, with the possible exception of the highest-order
	 * (partial) nibble, which is dealt with by the next
	 * statement.  We also tack on the implicit normalization bit.
	 */
	*s = (p->ext_frach | (1U << ((LDBL_MANT_DIG - 1) % 4))) & 0xf;

	/* If ndigits < 0, we are expected to auto-size the precision. */
	if (ndigits < 0) {
		for (ndigits = sigfigs; s0[ndigits - 1] == 0; ndigits--)
			;
	}

	if (sigfigs > ndigits && s0[ndigits] != 0)
		dorounding(s0, ndigits, p->ext_sign, decpt);

	s = s0 + ndigits;
	if (rve != NULL)
		*rve = s;
	*s-- = '\0';
	for (; s >= s0; s--)
		*s = xdigs[(unsigned int)*s];

	return (s0);
}
DEF_STRONG(__hldtoa);

#else	/* (LDBL_MANT_DIG == DBL_MANT_DIG) */

char *
__hldtoa(long double e, const char *xdigs, int ndigits, int *decpt, int *sign,
    char **rve)
{
	return (__hdtoa((double)e, xdigs, ndigits, decpt, sign, rve));
}
DEF_STRONG(__hldtoa);

#endif	/* (LDBL_MANT_DIG == DBL_MANT_DIG) */

"""

```
Response:
Let's break down the thought process for analyzing the provided header file `gdtoa.h`.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the `gdtoa.h` header file within the context of Android's Bionic libc. Key points to address include:

* **Functionality:** What does this header file define?
* **Android Relevance:** How do these functionalities tie into Android's operations?
* **libc Function Details:**  Explanation of individual function implementations (even though the *implementation* isn't in the header). This implies discussing their purpose and how they *would* be implemented.
* **Dynamic Linking:**  How does this relate to dynamic linking in Android? What's the SO layout?
* **Logic Inference/Examples:**  Provide hypothetical inputs and outputs for functions.
* **Common Errors:** Identify potential pitfalls when using these functions.
* **Android Framework/NDK Usage:** Trace how Android code might reach these functions and provide a Frida hook example.

**2. Initial Analysis of the Header File:**

* **Copyright and Author:**  Recognize the author (David M. Gay) and the copyright information, indicating it's from an external library (likely OpenBSD's `libgdtoa`).
* **Include Guards:**  Note the `#ifndef GDTOA_H_INCLUDED` to prevent multiple inclusions.
* **Includes:** See `<stddef.h>` for `size_t` and `"arith.h"` (which isn't provided, but we can infer it deals with arithmetic types).
* **Type Definitions:**  Observe definitions like `Long`, `ULong`, `UShort`, likely for platform compatibility.
* **ANSI Macros:**  Understand the purpose of `ANSI`, `Void`, and `CONST` for function declarations, likely related to pre-ANSI C compilers.
* **`enum` for `strtodg` return values:**  This is crucial! It defines the possible outcomes of string-to-floating-point conversions, including error conditions and precision information.
* **`struct FPI`:** This structure is key. It defines floating-point representation parameters (number of bits, exponent ranges, rounding mode, etc.). This suggests the library deals with precise control over floating-point conversions.
* **Function Declarations:**  This is the core of the header. Notice the naming conventions (`__dtoa`, `__gdtoa`, `strtof`, `strtod`, etc.). The double underscores often indicate internal or platform-specific functions. Group the functions by their apparent purpose (string to double, long double, generic conversion).
* **`PROTO_NORMAL`:**  This macro is used for forward declarations.
* **`__BEGIN_HIDDEN_DECLS` and `__END_HIDDEN_DECLS`:** These suggest the presence of internal helper functions that are not intended for direct external use.
* **Conditional Compilation (`#if 1`):** Notice the block around `__strtodI`, `__strtopd`, etc. This implies there might be alternative implementations or macro definitions.
* **`extern "C"`:** This is important for C++ compatibility, ensuring C linkage for these functions.

**3. Addressing Specific Requirements:**

* **Functionality:** Based on the function declarations and the `FPI` structure, the primary functionality is **converting strings to floating-point numbers** (doubles, floats, long doubles) with control over precision and rounding. It also includes functions for formatting floating-point numbers into strings (though those declarations are in the "hidden" section).

* **Android Relevance:**  Think about where string-to-floating-point conversion is necessary in Android:
    * **Parsing configuration files:**  Values might be stored as strings.
    * **Network communication:**  Data might be received as strings.
    * **User input:**  Converting text input to numbers.
    * **Graphics and sensor data:** Though often binary, string representations might be used in some contexts.

* **libc Function Details (Conceptual):** Since we don't have the source code, focus on *how* these functions would generally work:
    * **Scanning the input string:** Identifying sign, digits, decimal point, exponent.
    * **Parsing the number:**  Converting the digit sequence to a numerical value.
    * **Handling edge cases:**  Infinity, NaN, underflow, overflow.
    * **Applying rounding:**  According to the specified or default rounding mode.
    * **Setting error flags:**  Indicating problems during conversion.

* **Dynamic Linking:**  Consider how `libc.so` is structured. It contains these functions, and other parts of Android (framework, apps) link against it. Sketch a basic SO layout with segments for code, data, and dynamic linking information. Describe the linker's process of resolving symbols at runtime.

* **Logic Inference/Examples:** Choose a few key functions (`strtod`, `__gdtoa`) and create simple examples with expected inputs and outputs. This helps illustrate their behavior. Think about different scenarios (positive/negative numbers, decimals, exponents, errors).

* **Common Errors:** Focus on typical mistakes when working with string-to-number conversions:
    * **Invalid input:** Strings that aren't valid numbers.
    * **Overflow/Underflow:** Numbers too large or too small to represent.
    * **Ignoring error indicators:** Not checking the return value or the `endptr`.

* **Android Framework/NDK Usage & Frida Hook:**
    * **Framework:**  Trace a likely path, starting with something user-visible (like a text field in an Activity), down through framework layers to where a string conversion might occur. `Float.parseFloat()` or `Double.parseDouble()` are good starting points in Java. Then consider how the native implementation of those Java methods in the Android Runtime (ART) would call into `libc`.
    * **NDK:**  A simpler case – C/C++ code in an NDK app directly calling `strtod` or similar functions.
    * **Frida:** Create a basic Frida script that intercepts a relevant function (like `strtod`) and logs the arguments and return value.

**4. Structuring the Answer:**

Organize the information logically using headings and subheadings as in the provided good example. Start with a general overview of the header file's purpose, then delve into specifics for each requested point.

**5. Refining and Reviewing:**

* **Clarity:** Is the language clear and easy to understand? Avoid jargon where possible, or explain it.
* **Accuracy:**  Double-check the information provided. Even though we don't have the exact implementation, ensure the conceptual explanations are correct.
* **Completeness:**  Have all aspects of the request been addressed?
* **Examples:** Are the examples helpful and illustrative?
* **Code Formatting:**  Present code snippets (like the Frida hook) clearly.

By following these steps, one can effectively analyze a header file and provide a comprehensive explanation within the given context, even without access to the corresponding source code. The key is to understand the *intent* and *purpose* of the declared elements.
这个目录 `bionic/libc/upstream-openbsd/lib/libc/gdtoa/gdtoa.handroid` 下的 `gdtoa.h` 文件是来自 OpenBSD 的 `libgdtoa` 库的头文件，它被包含在 Android 的 Bionic libc 库中。`libgdtoa` 主要用于 **高精度浮点数和字符串之间的转换**。

让我们详细列举一下它的功能，并解释其与 Android 的关系：

**gdtoa.h 的主要功能：**

1. **字符串到浮点数的转换 (String to Floating-Point):**
   - 声明了将字符串转换为 `float`、`double` 和 `long double` 类型的函数。
   - 提供了更底层的、可以控制精度和舍入方式的字符串到浮点数转换函数。

2. **浮点数到字符串的转换 (Floating-Point to String):**
   - 声明了将 `double` 和 `long double` 转换为字符串的函数，可以控制输出格式和精度。
   - 提供了更底层的、可以控制输出格式的浮点数到字符串转换函数。

3. **提供浮点数表示的元数据 (Floating-Point Metadata):**
   - 定义了 `FPI` 结构体，用于描述浮点数的精度、指数范围、舍入模式等信息。
   - 定义了 `enum` 类型，用于表示字符串到浮点数转换的结果状态，例如是否溢出、下溢、是否为 NaN 等。

**与 Android 功能的关系及举例说明：**

`libgdtoa` 在 Android 中扮演着重要的角色，因为它提供了基础的浮点数和字符串之间转换的功能。许多 Android 组件和应用程序都需要进行这些转换。

**举例说明：**

* **`strtod` (字符串转双精度浮点数):**  Android 框架或应用在解析配置文件、网络数据、用户输入等场景时，经常需要将表示浮点数的字符串转换为 `double` 类型。
    * **例如：** 一个应用的设置文件中可能包含一个表示透明度的浮点数值字符串 `"0.8"`。Android 系统会调用 `strtod` 将其转换为 `double` 类型的 `0.8`，以便应用进行后续处理。

* **`strtof` (字符串转单精度浮点数):** 与 `strtod` 类似，但用于转换为 `float` 类型。在对精度要求不高，但对内存占用敏感的场景下使用。
    * **例如：** 在 OpenGL ES 图形渲染中，顶点坐标可能以字符串形式存储，然后使用 `strtof` 转换为 `float` 类型传递给 GPU。

* **`__gdtoa` (通用浮点数到字符串转换):** 这是一个更底层的函数，允许更精细地控制转换过程。Android 的 `printf` 或 `String.format` 等功能在处理浮点数格式化输出时，底层可能会调用 `__gdtoa` 或类似的函数。
    * **例如：** 当使用 `String.format("%.2f", myDouble)` 在 Java 代码中格式化输出一个双精度浮点数时，ART (Android Runtime) 最终会调用到 Bionic libc 中的相关函数，这些函数可能会利用 `libgdtoa` 中的功能。

**详细解释 libc 函数的功能是如何实现的 (基于头文件推断)：**

由于我们只有头文件，无法看到具体的实现代码。但我们可以根据函数声明和常见的实现方式来推断其功能：

* **`strtod(CONST char *nptr, char **endptr)` 和 `strtof(CONST char *nptr, char **endptr)`:**
    - 这两个函数接收一个字符串 `nptr`，尝试将其解析为 `double` 或 `float`。
    - 它们会跳过字符串开头的空白字符。
    - 识别可选的正负号。
    - 解析整数部分和小数部分。
    - 如果存在指数部分（'e' 或 'E' 后跟可选符号和数字），则进行处理。
    - 如果遇到无法解析的字符，解析会停止，并将该字符的地址存储在 `endptr` 指向的位置（如果不为 `NULL`）。
    - 返回解析得到的浮点数值。如果无法解析，返回 0.0 或 0.0f。
    - 可能会设置全局变量 `errno` 以指示错误（例如 `ERANGE` 表示溢出或下溢）。

* **`__dtoa(double d, int mode, int ndigits, int *decpt, int *sign, char **rve)`:**
    - 这个函数将一个 `double` 类型的浮点数 `d` 转换为字符串。
    - `mode` 参数可能控制输出格式（例如，定点表示或科学计数法）。
    - `ndigits` 参数可能指定输出的精度。
    - `decpt` 是一个输出参数，用于存储小数点的位置。
    - `sign` 是一个输出参数，用于指示数值的符号（0 表示正，非 0 表示负）。
    - `rve` 是一个输出参数，可能用于存储指向字符串末尾的指针。

* **`__gdtoa(FPI *fpi, int be, ULong *bits, int *kindp, int mode, int ndigits, int *decpt, char **rve)`:**
    - 这是一个更通用的浮点数到字符串转换函数。
    - `FPI *fpi` 指向一个 `FPI` 结构体，提供了浮点数的表示信息。
    - `be` 和 `bits` 可能是浮点数的内部表示。
    - `kindp` 是一个输出参数，指示浮点数的类型（例如，正常数、零、无穷大、NaN）。
    - 其他参数与 `__dtoa` 类似，控制输出格式和精度。

* **`__strtodg(CONST char* str, char** endptr, FPI* fpi, Long* exp, ULong* sig)`:**
    - 这是一个将字符串转换为自定义浮点数表示的函数。
    - `FPI *fpi` 指定了目标浮点数的格式。
    - `exp` 和 `sig` 是输出参数，用于存储解析后的指数和尾数。
    - 返回值表示转换的状态。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`gdtoa.h` 本身是头文件，不包含动态链接的代码。动态链接发生在编译和加载可执行文件和共享库时。`libgdtoa` 的实现代码会被编译进 `libc.so` 这个共享库中。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text          # 代码段，包含 strtod, __gdtoa 等函数的机器码
    .rodata        # 只读数据段，包含字符串常量等
    .data          # 可读写数据段，包含全局变量等
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表，包含导出的符号 (函数名、变量名)
    .dynstr        # 动态字符串表，存储符号名
    .plt           # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
    .got.plt       # 全局偏移表 (Global Offset Table) 的 PLT 部分
    ... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接：** 当应用程序或共享库的代码中调用了 `strtod` 等函数时，编译器会将这些函数调用标记为需要外部链接。链接器在链接阶段会将这些符号标记为需要从共享库中解析。

2. **运行时链接 (Dynamic Linking)：**
   - 当 Android 系统加载应用程序或共享库时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责解析这些外部符号。
   - 动态链接器会读取可执行文件或共享库的动态段 (`.dynamic`)，其中包含了链接所需的各种信息，例如依赖的共享库列表。
   - 动态链接器会加载应用程序依赖的共享库，例如 `libc.so`。
   - **符号查找：** 对于应用程序中调用的 `strtod` 函数，动态链接器会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找名为 `strtod` 的符号。
   - **重定位：** 找到 `strtod` 的地址后，动态链接器会更新应用程序代码中的 `strtod` 函数调用地址，使其指向 `libc.so` 中 `strtod` 函数的实际地址。这通常通过 `.plt` 和 `.got.plt` 完成（延迟绑定）。
   - **延迟绑定：** 第一次调用 `strtod` 时，会触发 PLT 中的代码，该代码会调用动态链接器来解析符号并更新 GOT 表中的地址。后续对 `strtod` 的调用将直接通过 GOT 表跳转到 `libc.so` 中的函数。

**如果做了逻辑推理，请给出假设输入与输出：**

* **`strtod("123.45", NULL)`:**
    - **输入:** 字符串 `"123.45"`
    - **输出:** `double` 类型的值 `123.45`

* **`strtod("-0.001e2", NULL)`:**
    - **输入:** 字符串 `"-0.001e2"`
    - **输出:** `double` 类型的值 `-0.1`

* **`strtod("  inf  ", NULL)`:**
    - **输入:** 字符串 `"  inf  "`
    - **输出:** `double` 类型的正无穷大 (`INFINITY`)

* **`strtod("nan", NULL)`:**
    - **输入:** 字符串 `"nan"`
    - **输出:** `double` 类型的 NaN (`NAN`)

* **`strtod("invalid", &endptr)`:**
    - **输入:** 字符串 `"invalid"`
    - **输出:** `0.0`
    - `endptr` 指向的地址将是 `"invalid"` 中的 `"i"` 的地址。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **未检查 `endptr`:** 使用 `strtod` 等函数后，应该检查 `endptr` 指向的位置。如果 `*endptr != '\0'`，则说明整个字符串没有被成功解析，可能存在无效字符。

   ```c
   char *endptr;
   double value = strtod("123.45abc", &endptr);
   if (*endptr != '\0') {
       // 错误：字符串包含无效字符
       printf("Error: Invalid characters in string: %s\n", endptr);
   }
   ```

2. **忽略溢出和下溢:** 当解析的数值超出 `double` 或 `float` 的表示范围时，`strtod` 和 `strtof` 可能会返回 `HUGE_VAL` 或 `0.0`，并设置 `errno` 为 `ERANGE`。程序员应该检查 `errno` 的值来处理这些情况。

   ```c
   #include <errno.h>
   #include <float.h>

   char *endptr;
   double value = strtod("1e1000", &endptr); // 溢出
   if (errno == ERANGE) {
       printf("Error: Overflow occurred\n");
   }
   ```

3. **假设输入总是有效:** 盲目地将用户输入或外部数据转换为浮点数而不进行验证，可能导致程序崩溃或产生意外结果。应该对输入进行适当的验证。

4. **精度损失:** 在浮点数和字符串之间进行多次转换时，可能会累积精度损失。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `libgdtoa` 的路径示例 (以 `Double.parseDouble()` 为例):**

1. **Java 代码 (Android Framework 或 App):**
   ```java
   String strValue = "3.14159";
   double doubleValue = Double.parseDouble(strValue);
   ```

2. **Android Runtime (ART):** `Double.parseDouble()` 是一个 Java Native Interface (JNI) 方法，它的实现位于 ART 的本地代码中。

3. **ART Native 代码 (`openjdkjvm/hotspot/src/share/vm/prims/jvm.cpp` 或类似位置):** ART 的 JNI 实现会调用底层的 C/C++ 函数来进行字符串到双精度浮点数的转换。

4. **Bionic libc (`bionic/libc/bionic/`):** ART 会调用 Bionic libc 提供的 `strtod` 函数。

5. **`libgdtoa` (`bionic/libc/upstream-openbsd/lib/libc/gdtoa/`):** Bionic libc 中的 `strtod` 实现实际上是 `libgdtoa` 提供的实现。

**NDK 到 `libgdtoa` 的路径示例:**

1. **C/C++ 代码 (NDK 应用):**
   ```c++
   #include <cstdlib>

   const char* strValue = "2.71828";
   double doubleValue = strtod(strValue, nullptr);
   ```

2. **Bionic libc (`bionic/libc/bionic/`):** NDK 应用直接调用 Bionic libc 提供的 `strtod` 函数。

3. **`libgdtoa` (`bionic/libc/upstream-openbsd/lib/libc/gdtoa/`):**  同样，Bionic libc 的 `strtod` 实现来自 `libgdtoa`。

**Frida Hook 示例:**

可以使用 Frida 来 hook `strtod` 函数，查看其参数和返回值。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please launch the app.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "strtod"), {
    onEnter: function(args) {
        console.log("[*] strtod called");
        console.log("    string: " + Memory.readUtf8String(args[0]));
        this.endptr = args[1];
    },
    onLeave: function(retval) {
        console.log("    return value: " + retval);
        if (this.endptr != 0) {
            console.log("    endptr points to: " + Memory.readUtf8String(this.endptr));
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 将上述 Python 代码保存为 `hook_strtod.py`。
2. 替换 `your.target.package` 为你想要调试的 Android 应用的包名。
3. 确保你的 Android 设备已连接并通过 USB 调试授权。
4. 运行 Frida 服务：确保你的 Android 设备上运行了 Frida server。
5. 运行 Python 脚本：`python hook_strtod.py`
6. 启动或操作目标应用，当应用调用 `strtod` 函数时，Frida 会拦截并打印相关信息，例如传入的字符串和返回值。

这个 Frida hook 示例可以帮助你调试 Android Framework 或 NDK 代码中如何调用到 `strtod` 函数，从而理解 `libgdtoa` 在 Android 中的作用。你可以根据需要修改 hook 的目标函数和输出信息。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/gdtoa/gdtoa.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/****************************************************************

The author of this software is David M. Gay.

Copyright (C) 1998 by Lucent Technologies
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

#ifndef GDTOA_H_INCLUDED
#define GDTOA_H_INCLUDED

#include "arith.h"
#include <stddef.h> /* for size_t */

#ifndef Long
#define Long int
#endif
#ifndef ULong
typedef unsigned Long ULong;
#endif
#ifndef UShort
typedef unsigned short UShort;
#endif

#ifndef ANSI
#ifdef KR_headers
#define ANSI(x) ()
#define Void /*nothing*/
#else
#define ANSI(x) x
#define Void void
#endif
#endif /* ANSI */

#ifndef CONST
#ifdef KR_headers
#define CONST /* blank */
#else
#define CONST const
#endif
#endif /* CONST */

 enum {	/* return values from strtodg */
	STRTOG_Zero	= 0x000,
	STRTOG_Normal	= 0x001,
	STRTOG_Denormal	= 0x002,
	STRTOG_Infinite	= 0x003,
	STRTOG_NaN	= 0x004,
	STRTOG_NaNbits	= 0x005,
	STRTOG_NoNumber	= 0x006,
	STRTOG_NoMemory = 0x007,
	STRTOG_Retmask	= 0x00f,

	/* The following may be or-ed into one of the above values. */

	STRTOG_Inexlo	= 0x010, /* returned result rounded toward zero */
	STRTOG_Inexhi	= 0x020, /* returned result rounded away from zero */
	STRTOG_Inexact	= 0x030,
	STRTOG_Underflow= 0x040,
	STRTOG_Overflow	= 0x080,
	STRTOG_Neg	= 0x100 /* does not affect STRTOG_Inexlo or STRTOG_Inexhi */
	};

 typedef struct
FPI {
	int nbits;
	int emin;
	int emax;
	int rounding;
	int sudden_underflow;
	} FPI;

enum {	/* FPI.rounding values: same as FLT_ROUNDS */
	FPI_Round_zero = 0,
	FPI_Round_near = 1,
	FPI_Round_up = 2,
	FPI_Round_down = 3
	};

#ifdef __cplusplus
extern "C" {
#endif

extern char* __dtoa  ANSI((double d, int mode, int ndigits, int *decpt,
			int *sign, char **rve));
extern char* __gdtoa ANSI((FPI *fpi, int be, ULong *bits, int *kindp,
			int mode, int ndigits, int *decpt, char **rve));
extern void __freedtoa ANSI((char*));
extern float  strtof ANSI((CONST char *, char **));
extern double strtod ANSI((CONST char *, char **));
extern int __strtodg ANSI((CONST char*, char**, FPI*, Long*, ULong*));
char	*__hdtoa(double, const char *, int, int *, int *, char **);
char	*__hldtoa(long double, const char *, int, int *, int *, char **);
char	*__ldtoa(long double *, int, int, int *, int *, char **);

PROTO_NORMAL(__dtoa);
PROTO_NORMAL(__gdtoa);
PROTO_NORMAL(__freedtoa);
PROTO_NORMAL(__hdtoa);
PROTO_NORMAL(__hldtoa);
PROTO_NORMAL(__ldtoa);

__BEGIN_HIDDEN_DECLS
extern char*	__g_ddfmt  ANSI((char*, double*, int, size_t));
extern char*	__g_dfmt   ANSI((char*, double*, int, size_t));
extern char*	__g_ffmt   ANSI((char*, float*,  int, size_t));
extern char*	__g_Qfmt   ANSI((char*, void*,   int, size_t));
extern char*	__g_xfmt   ANSI((char*, void*,   int, size_t));
extern char*	__g_xLfmt  ANSI((char*, void*,   int, size_t));

extern int	__strtoId  ANSI((CONST char*, char**, double*, double*));
extern int	__strtoIdd ANSI((CONST char*, char**, double*, double*));
extern int	__strtoIf  ANSI((CONST char*, char**, float*, float*));
extern int	__strtoIQ  ANSI((CONST char*, char**, void*, void*));
extern int	__strtoIx  ANSI((CONST char*, char**, void*, void*));
extern int	__strtoIxL ANSI((CONST char*, char**, void*, void*));
extern int	__strtord  ANSI((CONST char*, char**, int, double*));
extern int	__strtordd ANSI((CONST char*, char**, int, double*));
extern int	__strtorf  ANSI((CONST char*, char**, int, float*));
extern int	__strtorQ  ANSI((CONST char*, char**, int, void*));
extern int	__strtorx  ANSI((CONST char*, char**, int, void*));
extern int	__strtorxL ANSI((CONST char*, char**, int, void*));
#if 1
extern int	__strtodI  ANSI((CONST char*, char**, double*));
extern int	__strtopd  ANSI((CONST char*, char**, double*));
extern int	__strtopdd ANSI((CONST char*, char**, double*));
extern int	__strtopf  ANSI((CONST char*, char**, float*));
extern int	__strtopQ  ANSI((CONST char*, char**, void*));
extern int	__strtopx  ANSI((CONST char*, char**, void*));
extern int	__strtopxL ANSI((CONST char*, char**, void*));
#else
#define __strtopd(s,se,x) strtord(s,se,1,x)
#define __strtopdd(s,se,x) strtordd(s,se,1,x)
#define __strtopf(s,se,x) strtorf(s,se,1,x)
#define __strtopQ(s,se,x) strtorQ(s,se,1,x)
#define __strtopx(s,se,x) strtorx(s,se,1,x)
#define __strtopxL(s,se,x) strtorxL(s,se,1,x)
#endif
__END_HIDDEN_DECLS

#ifdef __cplusplus
}
#endif
#endif /* GDTOA_H_INCLUDED */
```
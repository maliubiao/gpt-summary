Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `inttypes.h` header file in Android's Bionic libc. Key aspects to address are its purpose, relation to Android, function implementations (even though this file *doesn't* contain function implementations), dynamic linker involvement (which is minimal here), usage examples, common errors, and how Android frameworks/NDK reach this file. Finally, a Frida hook example is requested.

2. **Initial Analysis of the Header File:**  I quickly scanned the provided code. The most prominent feature is the extensive set of macros starting with `PRI` and `SCN`. These are clearly related to formatted input/output operations (like `printf` and `scanf`) for different integer types. The presence of `__LP64__` suggests handling of 32-bit and 64-bit architectures. The inclusion of `stdint.h` is also a strong indicator of its role in defining standard integer types. The presence of `imaxdiv`, `strtoimax`, `strtoumax`, etc., towards the end points to functions dealing with the largest integer types.

3. **Functionality Identification:** Based on the macro names and the overall structure, I deduced the primary function is to provide **format specifier macros** for `printf` and `scanf` family functions, ensuring type safety and portability across different integer types and architectures. It also includes definitions for the largest integer types and related conversion functions.

4. **Relation to Android:** I know Bionic is Android's standard C library. Therefore, `inttypes.h` is fundamental for any C/C++ code running on Android that needs to perform formatted input/output with integer types. The `__LP64__` macro directly relates to Android's 32-bit and 64-bit architecture support.

5. **Detailed Explanation of Macros:** For each macro group (`PRId`, `PRIu`, `SCNd`, `SCNu`, etc.), I explained their purpose: `PRI` for `printf`, `SCN` for `scanf`, followed by the integer type and format specifier character (`d`, `u`, `x`, etc.). I also addressed the prefixes like `l` and `ll` for 64-bit integers.

6. **libc Function Implementations:**  Crucially, I recognized that **this header file only declares the function prototypes**, not the implementations. The implementations reside in other source files within Bionic. Therefore, my explanation focused on the *purpose* of each function (`imaxabs`, `imaxdiv`, `strtoimax`, etc.) rather than the low-level implementation details. I referenced standard C library behavior for these functions.

7. **Dynamic Linker Involvement:**  I considered how `inttypes.h` relates to the dynamic linker. While this specific header doesn't directly *use* dynamic linking, it's *used by* code that will be linked. I explained the general concept of shared libraries (`.so`) and symbol resolution. I provided a simplified `.so` layout example. The connection is that code using the macros and functions defined here will need the Bionic libc to be loaded at runtime.

8. **Usage Examples and Common Errors:** I crafted simple C code snippets demonstrating how to use the `PRI` and `SCN` macros. For common errors, I focused on the mismatches between format specifiers and variable types, as this is the primary area where these macros help prevent errors. I highlighted the risks of using incorrect format specifiers.

9. **Android Framework/NDK Path:** I traced the execution flow from a high-level Android framework component (like a Java activity) down to native code via JNI. I explained how the NDK provides the necessary headers, including `inttypes.h`, for native development.

10. **Frida Hook Example:** I created a basic Frida script to hook a `printf` call and modify its arguments. This demonstrates how to observe the use of these format specifiers in a running Android application.

11. **Review and Refinement:** I reviewed my entire response to ensure clarity, accuracy, and completeness, addressing all aspects of the user's request. I made sure the language was understandable and avoided overly technical jargon where possible. I also emphasized the difference between header file declarations and actual function implementations. I explicitly stated that this file doesn't *contain* dynamic linking logic, but rather is *used by* code that will be dynamically linked.

Essentially, I followed a top-down approach, starting with the overall purpose of the file and then drilling down into specific details. I also tried to connect the information back to the broader context of Android development. Recognizing the limitations of the header file itself (no function implementations, minimal direct dynamic linking) was crucial for providing an accurate and relevant answer.
这是一个位于 Android Bionic C 库中的头文件 `inttypes.h`。它的主要功能是为开发者提供一组用于格式化输入/输出的宏定义，以及一些与最大宽度整数类型相关的函数声明。

让我们详细分解一下：

**1. 功能列举:**

* **定义格式化输入/输出宏:**  `inttypes.h` 定义了 `printf` 和 `scanf` 系列函数使用的格式化说明符宏，用于各种固定宽度整数类型。这些宏以 `PRI` (用于 `printf` 系列) 和 `SCN` (用于 `scanf` 系列) 开头，后跟格式字符 (如 `d`, `u`, `x`) 和类型名称 (如 `FAST32`, `LEAST64`)。
* **提供最大宽度整数类型的相关函数声明:**  声明了处理最大宽度整数类型 `intmax_t` 和 `uintmax_t` 的函数，如 `imaxabs`, `imaxdiv`, `strtoimax`, `strtoumax`, `wcstoimax`, `wcstoumax`。

**2. 与 Android 功能的关系及举例:**

`inttypes.h` 是 Bionic libc 的一部分，因此它直接支持 Android 系统和应用程序的底层功能。任何使用 Bionic libc 进行格式化输入/输出操作的 C/C++ 代码都会间接地用到这个头文件。

**举例说明:**

* **Android 系统服务 (system server):**  许多 Android 系统服务是用 C++ 编写的，它们可能会使用 `printf` 或类似的函数进行日志记录或调试输出。`inttypes.h` 中定义的宏确保了在不同架构 (32 位或 64 位) 下，能够正确地打印各种整数类型的值。例如，一个系统服务可能会打印一个 64 位的进程 ID：

```c++
#include <inttypes.h>
#include <stdio.h>

int main() {
  int64_t pid = 1234567890123;
  printf("Process ID: %" PRId64 "\n", pid);
  return 0;
}
```

* **NDK 开发的应用:** 使用 Android NDK 进行原生开发的应用程序也会用到 `inttypes.h`。例如，一个游戏引擎可能会读取配置文件，其中包含各种整数类型的设置，并使用 `scanf` 系列函数进行解析。

```c++
#include <inttypes.h>
#include <stdio.h>

int main() {
  uint32_t score;
  FILE *fp = fopen("config.txt", "r");
  if (fp != NULL) {
    fscanf(fp, "%" SCNu32, &score);
    printf("High Score: %" PRIu32 "\n", score);
    fclose(fp);
  }
  return 0;
}
```

**3. 详细解释 libc 函数的功能是如何实现的:**

`inttypes.h` 本身 **不包含** 这些函数的实现，它只是声明了这些函数的原型。这些函数的具体实现位于 Bionic libc 的其他源文件中。

* **`imaxabs(intmax_t __i)`:**  返回 `intmax_t` 类型整数 `__i` 的绝对值。
    * **实现:**  通常通过简单的条件判断实现。如果 `__i` 小于 0，则返回 `-__i`，否则返回 `__i`。
* **`imaxdiv(intmax_t __numerator, intmax_t __denominator)`:**  计算 `intmax_t` 类型的被除数 `__numerator` 除以除数 `__denominator` 的商和余数，并将结果存储在 `imaxdiv_t` 结构体中。
    * **实现:**  通过执行除法运算和取模运算实现。`quot` 成员存储商，`rem` 成员存储余数。需要注意处理除数为 0 的情况，这通常会导致未定义行为或程序崩溃。
* **`strtoimax(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, int __base)`:** 将字符串 `__s` 转换为 `intmax_t` 类型的整数。`__base` 指定转换的基数 (例如，10 表示十进制，16 表示十六进制)。`__end_ptr` 是一个可选的指针，指向字符串中停止转换的位置。
    * **实现:**  通常会跳过前导的空白字符，然后解析可选的正负号。接着，根据指定的基数，逐个解析数字字符，直到遇到非法的字符或字符串结束。如果 `__end_ptr` 不为 NULL，则将其设置为停止转换的字符地址。需要处理溢出和下溢的情况，并根据错误情况设置 `errno`。
* **`strtoumax(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, int __base)`:**  与 `strtoimax` 类似，但将字符串转换为 `uintmax_t` 类型的无符号整数。
    * **实现:**  与 `strtoimax` 类似，但不处理负号。需要处理溢出的情况。
* **`wcstoimax(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base)`:**  与 `strtoimax` 类似，但处理宽字符字符串 `__s`。
    * **实现:**  与 `strtoimax` 类似，但需要处理宽字符。
* **`wcstoumax(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base)`:**  与 `strtoumax` 类似，但处理宽字符字符串 `__s`。
    * **实现:**  与 `strtoumax` 类似，但需要处理宽字符。

**4. 涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

`inttypes.h` 头文件本身 **不直接涉及** dynamic linker 的功能。它只是定义了一些宏和声明了一些函数。这些宏和函数会被其他 C/C++ 代码使用，而这些代码最终会被编译成共享库 (`.so`) 文件，并由 dynamic linker 在运行时加载和链接。

**SO 布局样本:**

一个包含使用 `inttypes.h` 中定义的宏或函数的代码的共享库的布局可能如下所示（简化示例）：

```
libmylibrary.so:
    .text          # 包含代码段
        my_function:
            ; ... 使用 printf 和 PRId32 的代码 ...
    .rodata        # 包含只读数据
        format_string: .string "The value is: %d\n"
    .data          # 包含可读写数据
    .bss           # 包含未初始化的数据
    .dynsym        # 动态符号表 (例如，printf)
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程:**

1. **编译阶段:** 当编译包含 `#include <inttypes.h>` 的源文件时，预处理器会将 `inttypes.h` 的内容插入到源文件中。编译器会识别 `PRI*` 和 `SCN*` 宏，并将其替换为相应的格式化字符串。对于 `imaxabs` 等函数，编译器会记录下对这些函数的引用。
2. **链接阶段:**  链接器将编译后的目标文件链接成共享库。当遇到对 `imaxabs` 等 Bionic libc 中函数的引用时，链接器会将这些符号标记为需要外部解析。
3. **动态链接阶段 (运行时):** 当 Android 系统加载 `libmylibrary.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析这些外部符号。
    * **查找共享库:** dynamic linker 会在预定义的路径中查找包含所需符号的共享库，例如 `libc.so`。
    * **符号查找:**  dynamic linker 会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `imaxabs` 等函数的地址。
    * **重定位:** dynamic linker 会根据重定位表 (`.rel.dyn` 和 `.rel.plt`) 修改 `libmylibrary.so` 中的代码和数据，将对外部符号的引用替换为实际的地址。例如，对 `printf` 函数的调用会通过 PLT 跳转到 `printf` 在 `libc.so` 中的地址。

**5. 逻辑推理的假设输入与输出:**

`inttypes.h` 主要提供宏定义，不涉及复杂的逻辑推理。其功能是直接的文本替换。

**假设输入 (代码):**

```c
#include <inttypes.h>
#include <stdio.h>

int main() {
  int32_t value = 123;
  printf("The value is: %" PRId32 "\n", value);
  return 0;
}
```

**输出 (预处理后的代码):**

```c
#include <stdio.h>

int main() {
  int32_t value = 123;
  printf("The value is: %d\n", value);
  return 0;
}
```

在这个例子中，预处理器将 `%" PRId32 "` 替换为 `" %d "`。

**对于 `imaxdiv` 函数的逻辑推理:**

**假设输入:** `__numerator = 10`, `__denominator = 3`

**输出:** `imaxdiv_t` 结构体，其中 `quot = 3`, `rem = 1`

**假设输入:** `__numerator = -10`, `__denominator = 3`

**输出:** `imaxdiv_t` 结构体，其中 `quot = -3`, `rem = -1` (余数的符号与被除数相同)

**6. 用户或编程常见的使用错误:**

* **格式化说明符与变量类型不匹配:** 这是使用 `inttypes.h` 中宏的最常见错误。例如，使用 `%d` 打印一个 `uint64_t` 类型的变量会导致未定义的行为或不正确的输出。应该使用相应的宏，例如 `%" PRIu64 "`。
    ```c
    uint64_t large_number = 123456789012345;
    printf("Number: %d\n", large_number); // 错误: 应该使用 PRIu64
    printf("Number: %" PRIu64 "\n", large_number); // 正确
    ```
* **`scanf` 系列函数使用错误的宏:** 类似于 `printf`，`scanf` 也需要使用与变量类型匹配的 `SCN` 宏。
    ```c
    uint32_t input_value;
    scanf("%d", &input_value); // 错误: 应该使用 SCNu32
    scanf("%" SCNu32, &input_value); // 正确
    ```
* **忘记包含头文件:**  如果使用了 `inttypes.h` 中定义的宏或声明的函数，但忘记包含头文件，会导致编译错误。
* **假设 `imaxdiv` 的余数符号:**  虽然大多数实现中余数的符号与被除数相同，但标准并未强制规定。依赖特定的行为可能导致移植性问题。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `inttypes.h` 的路径:**

1. **Java 代码调用:**  Android Framework 的 Java 代码 (例如，Activity 中的某些逻辑) 可能会通过 JNI (Java Native Interface) 调用 native 代码。
2. **JNI 调用:**  JNI 允许 Java 代码调用 C/C++ 代码。开发者需要在 native 代码中定义相应的函数，并在 Java 代码中使用 `native` 关键字声明。
3. **Native 代码执行:** 被调用的 native 代码 (通常位于 `.so` 文件中) 可能会使用 Bionic libc 的函数，例如 `printf` 进行日志记录。
4. **包含头文件:**  为了使用 `printf` 或 `inttypes.h` 中定义的宏，native 代码需要包含相应的头文件 `#include <stdio.h>` 和 `#include <inttypes.h>`.
5. **Bionic libc 提供实现:**  当 native 代码调用 `printf` 时，实际上调用的是 Bionic libc 中 `printf` 的实现。`printf` 的实现内部会使用传递给它的格式化字符串，其中可能包含 `inttypes.h` 中定义的宏。

**NDK 到 `inttypes.h` 的路径:**

1. **NDK 开发:**  使用 Android NDK 进行原生开发的应用程序，其 C/C++ 代码会直接链接到 Bionic libc。
2. **包含头文件:**  开发者在 NDK 代码中显式地包含 `<inttypes.h>` 头文件以使用其提供的宏和函数声明。
3. **编译链接:** NDK 的构建系统 (通常使用 CMake 或 ndk-build) 会将 NDK 代码编译成共享库，并链接到 Bionic libc。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `printf` 函数调用并查看格式化字符串参数的示例：

```python
import frida
import sys

package_name = "你的应用包名" # 将其替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
except frida.TimedOutError:
    print(f"[-] 无法找到设备或应用 {package_name}")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"[-] 应用 {package_name} 未运行")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "printf"), {
    onEnter: function(args) {
        var format_string = Memory.readUtf8String(args[0]);
        console.log("[printf] Format string:", format_string);
        // 你可以进一步解析 format_string，查看是否使用了 inttypes.h 中的宏
        // 例如，检查是否包含 "%d", "%lld", "%u", "%zx" 等
        for (var i = 1; i < args.length; i++) {
            console.log("[printf] Arg " + (i - 1) + ":", args[i]);
        }
    },
    onLeave: function(retval) {
        // console.log("Return value:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)

try:
    input()
except KeyboardInterrupt:
    session.detach()
    sys.exit()
```

**使用方法:**

1. 确保你的设备已连接并通过 adb 授权。
2. 安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 将 `你的应用包名` 替换为你要调试的 Android 应用的包名。
4. 运行该 Python 脚本。
5. 运行你的 Android 应用，并触发其中可能调用 `printf` 的代码路径。

Frida 脚本会拦截 `libc.so` 中的 `printf` 函数调用，并打印出传递给 `printf` 的格式化字符串以及其他参数。通过查看格式化字符串，你可以确认是否使用了 `inttypes.h` 中定义的宏。

这个例子演示了如何使用 Frida 调试 native 代码中与 `inttypes.h` 相关的部分。你可以根据需要修改 Frida 脚本来 hook 其他函数或执行更复杂的分析。

### 提示词
```
这是目录为bionic/libc/include/inttypes.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: inttypes.h,v 1.9 2006/01/15 00:47:51 millert Exp $	*/

/*
 * Copyright (c) 1997, 2005 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	_INTTYPES_H_
#define	_INTTYPES_H_

#include <sys/cdefs.h>
#include <stdint.h>

#ifdef __LP64__
#define __PRI_64_prefix  "l"
#define __PRI_PTR_prefix "l"
#else
#define __PRI_64_prefix "ll"
#define __PRI_PTR_prefix
#endif
#define __PRI_FAST_prefix __PRI_PTR_prefix

/*
 * 7.8.1 Macros for format specifiers
 *
 * Each of the following object-like macros expands to a string
 * literal containing a conversion specifier, possibly modified by
 * a prefix such as hh, h, l, or ll, suitable for use within the
 * format argument of a formatted input/output function when
 * converting the corresponding integer type.  These macro names
 * have the general form of PRI (character string literals for the
 * fprintf family) or SCN (character string literals for the fscanf
 * family), followed by the conversion specifier, followed by a
 * name corresponding to a similar typedef name.  For example,
 * PRIdFAST32 can be used in a format string to print the value of
 * an integer of type int_fast32_t.
 */

/* fprintf macros for signed integers */
#define	PRId8			"d"		/* int8_t */
#define	PRId16			"d"		/* int16_t */
#define	PRId32			"d"		/* int32_t */
#define	PRId64			__PRI_64_prefix"d"		/* int64_t */

#define	PRIdLEAST8		"d"		/* int_least8_t */
#define	PRIdLEAST16		"d"		/* int_least16_t */
#define	PRIdLEAST32		"d"		/* int_least32_t */
#define	PRIdLEAST64		__PRI_64_prefix"d"		/* int_least64_t */

#define	PRIdFAST8		"d"		/* int_fast8_t */
#define	PRIdFAST16		__PRI_FAST_prefix"d"	/* int_fast16_t */
#define	PRIdFAST32		__PRI_FAST_prefix"d"	/* int_fast32_t */
#define	PRIdFAST64		__PRI_64_prefix"d"		/* int_fast64_t */

#define	PRIdMAX			"jd"		/* intmax_t */
#define	PRIdPTR			__PRI_PTR_prefix"d"		/* intptr_t */

#define	PRIi8			"i"		/* int8_t */
#define	PRIi16			"i"		/* int16_t */
#define	PRIi32			"i"		/* int32_t */
#define	PRIi64			__PRI_64_prefix"i"		/* int64_t */

#define	PRIiLEAST8		"i"		/* int_least8_t */
#define	PRIiLEAST16		"i"		/* int_least16_t */
#define	PRIiLEAST32		"i"		/* int_least32_t */
#define	PRIiLEAST64		__PRI_64_prefix"i"		/* int_least64_t */

#define	PRIiFAST8		"i"		/* int_fast8_t */
#define	PRIiFAST16		__PRI_FAST_prefix"i"	/* int_fast16_t */
#define	PRIiFAST32		__PRI_FAST_prefix"i"	/* int_fast32_t */
#define	PRIiFAST64		__PRI_64_prefix"i"		/* int_fast64_t */

#define	PRIiMAX			"ji"		/* intmax_t */
#define	PRIiPTR			__PRI_PTR_prefix"i"		/* intptr_t */

/* fprintf macros for unsigned integers */
#define	PRIb8			"b"		/* int8_t */
#define	PRIb16			"b"		/* int16_t */
#define	PRIb32			"b"		/* int32_t */
#define	PRIb64			__PRI_64_prefix"b"		/* int64_t */

#define	PRIbLEAST8		"b"		/* int_least8_t */
#define	PRIbLEAST16		"b"		/* int_least16_t */
#define	PRIbLEAST32		"b"		/* int_least32_t */
#define	PRIbLEAST64		__PRI_64_prefix"b"		/* int_least64_t */

#define	PRIbFAST8		"b"		/* int_fast8_t */
#define	PRIbFAST16		__PRI_FAST_prefix"b"	/* int_fast16_t */
#define	PRIbFAST32		__PRI_FAST_prefix"b"	/* int_fast32_t */
#define	PRIbFAST64		__PRI_64_prefix"b"		/* int_fast64_t */

#define	PRIbMAX			"jb"		/* intmax_t */
#define	PRIbPTR			__PRI_PTR_prefix"b"		/* intptr_t */

#define	PRIB8			"B"		/* int8_t */
#define	PRIB16			"B"		/* int16_t */
#define	PRIB32			"B"		/* int32_t */
#define	PRIB64			__PRI_64_prefix"B"		/* int64_t */

#define	PRIBLEAST8		"B"		/* int_least8_t */
#define	PRIBLEAST16		"B"		/* int_least16_t */
#define	PRIBLEAST32		"B"		/* int_least32_t */
#define	PRIBLEAST64		__PRI_64_prefix"B"		/* int_least64_t */

#define	PRIBFAST8		"B"		/* int_fast8_t */
#define	PRIBFAST16		__PRI_FAST_prefix"B"	/* int_fast16_t */
#define	PRIBFAST32		__PRI_FAST_prefix"B"	/* int_fast32_t */
#define	PRIBFAST64		__PRI_64_prefix"B"		/* int_fast64_t */

#define	PRIBMAX			"jB"		/* intmax_t */
#define	PRIBPTR			__PRI_PTR_prefix"B"		/* intptr_t */

#define	PRIo8			"o"		/* int8_t */
#define	PRIo16			"o"		/* int16_t */
#define	PRIo32			"o"		/* int32_t */
#define	PRIo64			__PRI_64_prefix"o"		/* int64_t */

#define	PRIoLEAST8		"o"		/* int_least8_t */
#define	PRIoLEAST16		"o"		/* int_least16_t */
#define	PRIoLEAST32		"o"		/* int_least32_t */
#define	PRIoLEAST64		__PRI_64_prefix"o"		/* int_least64_t */

#define	PRIoFAST8		"o"		/* int_fast8_t */
#define	PRIoFAST16		__PRI_FAST_prefix"o"	/* int_fast16_t */
#define	PRIoFAST32		__PRI_FAST_prefix"o"	/* int_fast32_t */
#define	PRIoFAST64		__PRI_64_prefix"o"		/* int_fast64_t */

#define	PRIoMAX			"jo"		/* intmax_t */
#define	PRIoPTR			__PRI_PTR_prefix"o"		/* intptr_t */

#define	PRIu8			"u"		/* uint8_t */
#define	PRIu16			"u"		/* uint16_t */
#define	PRIu32			"u"		/* uint32_t */
#define	PRIu64			__PRI_64_prefix"u"		/* uint64_t */

#define	PRIuLEAST8		"u"		/* uint_least8_t */
#define	PRIuLEAST16		"u"		/* uint_least16_t */
#define	PRIuLEAST32		"u"		/* uint_least32_t */
#define	PRIuLEAST64		__PRI_64_prefix"u"		/* uint_least64_t */

#define	PRIuFAST8		"u"		/* uint_fast8_t */
#define	PRIuFAST16		__PRI_FAST_prefix"u"	/* uint_fast16_t */
#define	PRIuFAST32		__PRI_FAST_prefix"u"	/* uint_fast32_t */
#define	PRIuFAST64		__PRI_64_prefix"u"		/* uint_fast64_t */

#define	PRIuMAX			"ju"		/* uintmax_t */
#define	PRIuPTR			__PRI_PTR_prefix"u"		/* uintptr_t */

#define	PRIx8			"x"		/* uint8_t */
#define	PRIx16			"x"		/* uint16_t */
#define	PRIx32			"x"		/* uint32_t */
#define	PRIx64			__PRI_64_prefix"x"		/* uint64_t */

#define	PRIxLEAST8		"x"		/* uint_least8_t */
#define	PRIxLEAST16		"x"		/* uint_least16_t */
#define	PRIxLEAST32		"x"		/* uint_least32_t */
#define	PRIxLEAST64		__PRI_64_prefix"x"		/* uint_least64_t */

#define	PRIxFAST8		"x"		/* uint_fast8_t */
#define	PRIxFAST16		__PRI_FAST_prefix"x"	/* uint_fast16_t */
#define	PRIxFAST32		__PRI_FAST_prefix"x"	/* uint_fast32_t */
#define	PRIxFAST64		__PRI_64_prefix"x"		/* uint_fast64_t */

#define	PRIxMAX			"jx"		/* uintmax_t */
#define	PRIxPTR			__PRI_PTR_prefix"x"		/* uintptr_t */

#define	PRIX8			"X"		/* uint8_t */
#define	PRIX16			"X"		/* uint16_t */
#define	PRIX32			"X"		/* uint32_t */
#define	PRIX64			__PRI_64_prefix"X"		/* uint64_t */

#define	PRIXLEAST8		"X"		/* uint_least8_t */
#define	PRIXLEAST16		"X"		/* uint_least16_t */
#define	PRIXLEAST32		"X"		/* uint_least32_t */
#define	PRIXLEAST64		__PRI_64_prefix"X"		/* uint_least64_t */

#define	PRIXFAST8		"X"		/* uint_fast8_t */
#define	PRIXFAST16		__PRI_FAST_prefix"X"	/* uint_fast16_t */
#define	PRIXFAST32		__PRI_FAST_prefix"X"	/* uint_fast32_t */
#define	PRIXFAST64		__PRI_64_prefix"X"		/* uint_fast64_t */

#define	PRIXMAX			"jX"		/* uintmax_t */
#define	PRIXPTR			__PRI_PTR_prefix"X"		/* uintptr_t */

/* fscanf macros for signed integers */
#define	SCNd8			"hhd"		/* int8_t */
#define	SCNd16			"hd"		/* int16_t */
#define	SCNd32			"d"		/* int32_t */
#define	SCNd64			__PRI_64_prefix"d"		/* int64_t */

#define	SCNdLEAST8		"hhd"		/* int_least8_t */
#define	SCNdLEAST16		"hd"		/* int_least16_t */
#define	SCNdLEAST32		"d"		/* int_least32_t */
#define	SCNdLEAST64		__PRI_64_prefix"d"		/* int_least64_t */

#define	SCNdFAST8		"hhd"		/* int_fast8_t */
#define	SCNdFAST16		__PRI_FAST_prefix"d"	/* int_fast16_t */
#define	SCNdFAST32		__PRI_FAST_prefix"d"	/* int_fast32_t */
#define	SCNdFAST64		__PRI_64_prefix"d"		/* int_fast64_t */

#define	SCNdMAX			"jd"		/* intmax_t */
#define	SCNdPTR			__PRI_PTR_prefix"d"		/* intptr_t */

#define	SCNi8			"hhi"		/* int8_t */
#define	SCNi16			"hi"		/* int16_t */
#define	SCNi32			"i"		/* int32_t */
#define	SCNi64			__PRI_64_prefix"i"		/* int64_t */

#define	SCNiLEAST8		"hhi"		/* int_least8_t */
#define	SCNiLEAST16		"hi"		/* int_least16_t */
#define	SCNiLEAST32		"i"		/* int_least32_t */
#define	SCNiLEAST64		__PRI_64_prefix"i"		/* int_least64_t */

#define	SCNiFAST8		"hhi"		/* int_fast8_t */
#define	SCNiFAST16		__PRI_FAST_prefix"i"	/* int_fast16_t */
#define	SCNiFAST32		__PRI_FAST_prefix"i"	/* int_fast32_t */
#define	SCNiFAST64		__PRI_64_prefix"i"		/* int_fast64_t */

#define	SCNiMAX			"ji"		/* intmax_t */
#define	SCNiPTR			__PRI_PTR_prefix"i"		/* intptr_t */

/* fscanf macros for unsigned integers */
#define	SCNb8			"hhb"		/* uint8_t */
#define	SCNb16			"hb"		/* uint16_t */
#define	SCNb32			"b"		/* uint32_t */
#define	SCNb64			__PRI_64_prefix"b"		/* uint64_t */

#define	SCNbLEAST8		"hhb"		/* uint_least8_t */
#define	SCNbLEAST16		"hb"		/* uint_least16_t */
#define	SCNbLEAST32		"b"		/* uint_least32_t */
#define	SCNbLEAST64		__PRI_64_prefix"b"		/* uint_least64_t */

#define	SCNbFAST8		"hhb"		/* uint_fast8_t */
#define	SCNbFAST16		__PRI_FAST_prefix"b"	/* uint_fast16_t */
#define	SCNbFAST32		__PRI_FAST_prefix"b"	/* uint_fast32_t */
#define	SCNbFAST64		__PRI_64_prefix"b"		/* uint_fast64_t */

#define	SCNbMAX			"jb"		/* uintmax_t */
#define	SCNbPTR			__PRI_PTR_prefix"b"		/* uintptr_t */

#define	SCNB8			"hhB"		/* uint8_t */
#define	SCNB16			"hB"		/* uint16_t */
#define	SCNB32			"B"		/* uint32_t */
#define	SCNB64			__PRI_64_prefix"B"		/* uint64_t */

#define	SCNBLEAST8		"hhB"		/* uint_least8_t */
#define	SCNBLEAST16		"hB"		/* uint_least16_t */
#define	SCNBLEAST32		"B"		/* uint_least32_t */
#define	SCNBLEAST64		__PRI_64_prefix"B"		/* uint_least64_t */

#define	SCNBFAST8		"hhB"		/* uint_fast8_t */
#define	SCNBFAST16		__PRI_FAST_prefix"B"	/* uint_fast16_t */
#define	SCNBFAST32		__PRI_FAST_prefix"B"	/* uint_fast32_t */
#define	SCNBFAST64		__PRI_64_prefix"B"		/* uint_fast64_t */

#define	SCNBMAX			"jB"		/* uintmax_t */
#define	SCNBPTR			__PRI_PTR_prefix"B"		/* uintptr_t */

#define	SCNo8			"hho"		/* uint8_t */
#define	SCNo16			"ho"		/* uint16_t */
#define	SCNo32			"o"		/* uint32_t */
#define	SCNo64			__PRI_64_prefix"o"		/* uint64_t */

#define	SCNoLEAST8		"hho"		/* uint_least8_t */
#define	SCNoLEAST16		"ho"		/* uint_least16_t */
#define	SCNoLEAST32		"o"		/* uint_least32_t */
#define	SCNoLEAST64		__PRI_64_prefix"o"		/* uint_least64_t */

#define	SCNoFAST8		"hho"		/* uint_fast8_t */
#define	SCNoFAST16		__PRI_FAST_prefix"o"	/* uint_fast16_t */
#define	SCNoFAST32		__PRI_FAST_prefix"o"	/* uint_fast32_t */
#define	SCNoFAST64		__PRI_64_prefix"o"		/* uint_fast64_t */

#define	SCNoMAX			"jo"		/* uintmax_t */
#define	SCNoPTR			__PRI_PTR_prefix"o"		/* uintptr_t */

#define	SCNu8			"hhu"		/* uint8_t */
#define	SCNu16			"hu"		/* uint16_t */
#define	SCNu32			"u"		/* uint32_t */
#define	SCNu64			__PRI_64_prefix"u"		/* uint64_t */

#define	SCNuLEAST8		"hhu"		/* uint_least8_t */
#define	SCNuLEAST16		"hu"		/* uint_least16_t */
#define	SCNuLEAST32		"u"		/* uint_least32_t */
#define	SCNuLEAST64		__PRI_64_prefix"u"		/* uint_least64_t */

#define	SCNuFAST8		"hhu"		/* uint_fast8_t */
#define	SCNuFAST16		__PRI_FAST_prefix"u"	/* uint_fast16_t */
#define	SCNuFAST32		__PRI_FAST_prefix"u"		/* uint_fast32_t */
#define	SCNuFAST64		__PRI_64_prefix"u"		/* uint_fast64_t */

#define	SCNuMAX			"ju"		/* uintmax_t */
#define	SCNuPTR			__PRI_PTR_prefix"u"		/* uintptr_t */

#define	SCNx8			"hhx"		/* uint8_t */
#define	SCNx16			"hx"		/* uint16_t */
#define	SCNx32			"x"		/* uint32_t */
#define	SCNx64			__PRI_64_prefix"x"		/* uint64_t */

#define	SCNxLEAST8		"hhx"		/* uint_least8_t */
#define	SCNxLEAST16		"hx"		/* uint_least16_t */
#define	SCNxLEAST32		"x"		/* uint_least32_t */
#define	SCNxLEAST64		__PRI_64_prefix"x"		/* uint_least64_t */

#define	SCNxFAST8		"hhx"		/* uint_fast8_t */
#define	SCNxFAST16		__PRI_FAST_prefix"x"	/* uint_fast16_t */
#define	SCNxFAST32		__PRI_FAST_prefix"x"	/* uint_fast32_t */
#define	SCNxFAST64		__PRI_64_prefix"x"		/* uint_fast64_t */

#define	SCNxMAX			"jx"		/* uintmax_t */
#define	SCNxPTR			__PRI_PTR_prefix"x"		/* uintptr_t */

typedef struct {
	intmax_t quot;		/* quotient */
	intmax_t rem;		/* remainder */
} imaxdiv_t;

__BEGIN_DECLS
intmax_t imaxabs(intmax_t __i) __attribute_const__;
imaxdiv_t imaxdiv(intmax_t __numerator, intmax_t __denominator) __attribute_const__;
intmax_t strtoimax(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, int __base);
uintmax_t strtoumax(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, int __base);
intmax_t wcstoimax(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base);
uintmax_t wcstoumax(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base);
__END_DECLS

#endif
```
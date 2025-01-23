Response:
Here's a breakdown of the thinking process to generate the detailed explanation of `vfwprintf.cpp`:

1. **Understand the Core Request:** The primary goal is to analyze the provided C++ source code for `vfwprintf.cpp` in Android's Bionic library and explain its functionality, relationship to Android, implementation details, interactions with the dynamic linker (if any), potential errors, and how it's used in the Android ecosystem.

2. **Identify the Main Function:** The code clearly defines a function named `FUNCTION_NAME`, which due to the `#define` at the top, resolves to `__vfwprintf`. This is the entry point for the functionality.

3. **Determine the Function's Purpose:**  The function signature `int FUNCTION_NAME(FILE* fp, const CHAR_TYPE* fmt0, va_list ap)` strongly suggests a formatted output function similar to `vfprintf`. The `wchar_t` type for `CHAR_TYPE` indicates it handles wide characters, making it the wide-character variant. Therefore, the core purpose is to write formatted output of wide characters to a stream.

4. **Break Down the Code into Sections:**  Divide the code into logical blocks for easier analysis:
    * **Includes and Definitions:** The initial `#define` statements and `#include` directives. These set up the environment and include necessary supporting code.
    * **Variable Declarations:**  A large section declaring various local variables. Understanding the purpose of these variables is key to grasping the implementation.
    * **Initialization:** Setting up initial values for some variables.
    * **Main Loop:** The `for (;;)` loop that iterates through the format string.
    * **Format Specifier Parsing:**  The logic within the loop that handles the '%' character and parses format specifiers (flags, width, precision, length modifiers, conversion specifiers).
    * **Argument Handling:**  Fetching arguments from the `va_list` based on the format specifiers.
    * **Data Conversion:** Converting the arguments to their string representations based on the conversion specifiers (integers, floats, strings, etc.).
    * **Padding and Formatting:** Applying padding, prefixes, and other formatting rules.
    * **Output:** Writing the formatted output to the file stream using `helpers::xfputwc`.
    * **Error Handling:** Checking for errors and setting `errno`.
    * **Cleanup:**  Freeing allocated memory.

5. **Analyze Key Implementation Details:** Focus on how the code handles different format specifiers. For instance:
    * **Integer Handling (`%d`, `%x`, etc.):**  Conversion to `uintmax_t`, base conversion, handling signs, padding, and precision.
    * **Floating-Point Handling (`%f`, `%e`, `%g`, `%a`):** Use of `dtoa` family of functions for converting floating-point numbers to strings, handling different formats, precision, and special values (infinity, NaN).
    * **String Handling (`%s`, `%S`):** Handling both narrow and wide character strings, applying precision.
    * **Character Handling (`%c`, `%C`):**  Converting integer arguments to characters.
    * **Pointer Handling (`%p`):** Formatting memory addresses.

6. **Identify Interactions with Other Components:**
    * **`printf_common.h`:** This header likely contains shared code and macros used by other `printf` family functions.
    * **`helpers` namespace:**  Functions like `xfputwc`, `mbsconv`, and `w_to_flag` are used for output, multibyte conversion, and handling custom 'w' flag.
    * **`__sbprintf`:**  Used as an optimization for unbuffered output streams.
    * **`__find_arguments`:**  Used for handling positional arguments (e.g., `%1$d`).
    * **`__hdtoa`, `__ldtoa`, `__dtoa`, `__freedtoa`:** Functions for converting floating-point numbers to strings. These are likely part of a low-level math library.
    * **`strerror_r`, `strerrorname_np`:** Functions for getting error message strings.
    * **`nl_langinfo(RADIXCHAR)`:**  Retrieving the locale-specific decimal point character.
    * **Dynamic Linker (Indirectly):** While `vfwprintf.cpp` itself doesn't directly call dynamic linker functions, it's part of the Bionic library, which is loaded by the dynamic linker. The functions it calls might reside in other shared libraries linked at runtime.

7. **Address Specific Requirements:**
    * **Relationship to Android:**  `vfwprintf` is a fundamental part of Android's C library, used by various system components and applications for formatted output. Examples include logging, displaying error messages, and writing to files.
    * **Dynamic Linker:** Explain that while not directly interacting, it's part of Bionic, which is loaded by the linker. Provide a basic SO layout example and explain the linking process at a high level.
    * **Assumed Input/Output:**  Create simple examples to illustrate the function's behavior with different format specifiers.
    * **Common Errors:** Highlight typical mistakes like format string mismatches, buffer overflows (though mitigated here), and incorrect usage of length modifiers.
    * **Android Framework/NDK Call Chain and Frida Hook:**  Illustrate how a high-level Android framework call (like `Log.w`) can eventually lead to `vfwprintf` through the NDK and Bionic. Provide a basic Frida hook example to trace the execution.

8. **Structure and Refine the Explanation:** Organize the information logically using headings, bullet points, and code snippets. Ensure clarity, accuracy, and completeness. Use clear and concise language.

9. **Review and Iterate:**  Read through the entire explanation to check for errors, omissions, and areas that could be clearer. For instance, initially, I might have focused too much on the low-level details of the floating-point conversion and needed to step back and provide a broader overview. Similarly, ensuring the Frida hook example was practical and understandable was important.
## 对 bionic/libc/stdio/vfwprintf.cpp 源代码的分析

您提供的源代码文件 `bionic/libc/stdio/vfwprintf.cpp` 是 Android Bionic C 库中 `vfwprintf` 函数的实现。这个函数是 `fwprintf` 的变参版本，用于将格式化的宽字符输出写入到指定的文件流中。

**功能列举:**

1. **格式化宽字符输出:**  `vfwprintf` 接收一个文件指针 (`FILE* fp`)，一个宽字符串格式化字符串 (`const CHAR_TYPE* fmt0`) 和一个参数列表 (`va_list ap`)。它根据格式化字符串中的指令，将参数列表中的值转换为宽字符串并输出到指定的文件流。

2. **支持多种格式化指示符:** 该函数实现了 C 标准库中定义的各种格式化指示符，用于控制不同数据类型的输出格式，例如：
    * **整数:** `%d` (十进制), `%i` (十进制), `%o` (八进制), `%x` (十六进制小写), `%X` (十六进制大写), `%b` (二进制), `%B` (二进制)。
    * **无符号整数:** `%u` (十进制)。
    * **浮点数:** `%f` (定点小数), `%e` (科学计数法小写), `%E` (科学计数法大写), `%g` (自动选择 `%f` 或 `%e`), `%G` (自动选择 `%F` 或 `%E`), `%a` (十六进制浮点数小写), `%A` (十六进制浮点数大写)。
    * **字符:** `%c` (单字符), `%C` (宽字符)。
    * **字符串:** `%s` (窄字符串), `%S` (宽字符串)。
    * **指针:** `%p` (内存地址)。
    * **特殊:** `%%` (输出 `%`), `%n` (写入已输出字符数到指定地址 - **Android 中禁用**), `%m` (输出 `errno` 对应的错误消息)。

3. **支持标志 (flags):**  控制输出的对齐方式、填充字符、符号显示等，例如 `-` (左对齐), `+` (显示正号), ` ` (正数前添加空格), `#` (可选格式), `0` (零填充)。

4. **支持字段宽度和精度:**  允许指定输出字段的最小宽度和精度，用于控制输出的格式。

5. **支持长度修饰符:**  允许指定参数的长度，例如 `h` (short), `l` (long), `ll` (long long), `L` (long double), `j` (intmax_t), `z` (size_t), `t` (ptrdiff_t)。

6. **处理宽字符和多字节字符:**  通过 `CHAR_TYPE` (被定义为 `wchar_t`) 和相关的 helper 函数，支持处理宽字符输出，并能在必要时进行多字节字符转换。

7. **错误处理:**  在写入过程中发生错误时，例如写入只读文件，会设置 `errno` 并返回 `EOF`。

8. **性能优化:**  对于标准错误输出流等无缓冲的文件，会尝试使用更高效的 `__sbprintf` 进行处理。

**与 Android 功能的关系及举例:**

`vfwprintf` 是 Android 系统中非常基础和核心的函数，几乎所有需要进行格式化输出的地方都会间接或直接地用到它。

* **日志系统 (logcat):**  Android 的 `Log` 类（例如 `Log.d()`, `Log.e()`）最终会调用到 native 层的日志函数，这些 native 函数很可能使用 `vfwprintf` 或其类似的函数将格式化的日志信息输出到 `/dev/log/main` 等日志设备。

    **示例 (假设 native 层代码):**
    ```c++
    #include <stdio.h>
    #include <stdarg.h>
    #include <wchar.h>

    void android_log_print(int priority, const wchar_t* tag, const wchar_t* fmt, ...) {
        FILE* log_file = fopen("/dev/log/main", "w");
        if (log_file) {
            va_list args;
            va_start(args, fmt);
            vfwprintf(log_file, fmt, args);
            va_end(args);
            fclose(log_file);
        }
    }

    // ... 在 Java 层的 Log.d("MyApp", "User ID: %d", userId); 被调用时 ...
    android_log_print(3, L"MyApp", L"User ID: %d", userId);
    ```
    在这个例子中，`android_log_print` 函数接收 Java 层传递过来的 tag 和格式化字符串以及参数，然后使用 `vfwprintf` 将它们写入到日志文件。

* **标准输出/标准错误:**  当应用程序或系统进程使用 `printf`、`fprintf` 或 `wprintf` 等函数输出到标准输出或标准错误时，Bionic 的实现最终会调用到 `vfwprintf` 或其对应的窄字符版本 `vfprintf`。

    **示例 (C/C++ NDK 应用):**
    ```c++
    #include <stdio.h>
    #include <wchar.h>

    int main() {
        int user_id = 123;
        const wchar_t* username = L"用户A";
        fwprintf(stdout, L"User ID: %d, Username: %ls\n", user_id, username);
        return 0;
    }
    ```
    这段代码使用 `fwprintf` 将格式化的宽字符输出到标准输出，Bionic 的 `fwprintf` 内部会调用 `vfwprintf` 来完成实际的格式化和输出操作.

* **错误消息显示:**  许多系统调用或库函数在出错时会设置 `errno`，然后程序可能会使用 `perror` 或类似的函数来打印包含错误描述的消息。`vfwprintf` 可以用于实现这些错误消息的格式化输出（通过 `%m` 格式符，虽然这里代码中看到 `%m` 的处理逻辑最终调用了 `strerror_r` 并进行了 UTF-8 转换和输出，但核心思想类似）。

**libc 函数的功能实现解释:**

`vfwprintf.cpp` 的代码非常复杂，因为它需要处理各种不同的格式化指示符和标志。以下是关键部分的解释：

1. **宏定义 (Macros):**  代码开头定义了一些宏，例如 `CHAR_TYPE`, `FUNCTION_NAME`, `PRINT` 等，用于根据宽字符环境进行调整，并简化代码。`PRINT` 宏用于实际的字符输出。

2. **参数解析循环:**  主循环 `for (;;)` 遍历格式化字符串 `fmt0`。当遇到 `%` 字符时，开始解析后续的格式化指示符。

3. **标志、宽度、精度解析:**  在 `reswitch` 标签的 `switch` 语句中，代码逐个字符地解析标志 (` `, `#`, `-`, `+`, `0`), 字段宽度 (`*`, 数字), 精度 (`.`, `*`), 和长度修饰符 (`h`, `l`, `L`, `j`, `z`, `t`).

4. **参数获取:**  使用宏 `GETARG()` 和 `UARG()` 从 `va_list ap` 中获取对应类型的参数。如果使用了位置参数（例如 `%2$d`），则会调用 `__find_arguments` 来预先解析参数。

5. **数据类型处理:**  `switch (ch)` 语句根据转换说明符 (`c`, `d`, `i`, `o`, `u`, `x`, `X`, `f`, `e`, `E`, `g`, `G`, `a`, `A`, `s`, `S`, `p` 等) 进行不同的处理：
    * **整数:** 将整数转换为不同的进制字符串，并处理符号、前导零等。
    * **浮点数:**  调用 `__hdtoa`, `__ldtoa`, `__dtoa` 等函数将浮点数转换为字符串表示，并处理指数、精度等。这些 `dtoa` 函数是 Bionic 库中用于浮点数转换的关键部分，它们实现了复杂的算法来保证精度和性能。
    * **字符串:** 直接使用字符串或根据精度截断字符串。对于窄字符串 `%s`，会使用 `helpers::mbsconv` 转换为宽字符串。
    * **字符:** 直接输出字符。
    * **指针:**  将指针转换为十六进制地址。

6. **格式化和填充:**  根据解析得到的标志、宽度和精度，进行填充操作。例如，如果指定了右对齐和宽度，会在字符串左侧填充空格或零。

7. **输出:**  使用 `PRINT` 宏将格式化后的字符输出到文件流 `fp`。`PRINT` 宏内部调用了 `helpers::xfputwc`，这是一个用于输出宽字符的 helper 函数。

8. **错误处理:**  在输出过程中，如果 `helpers::xfputwc` 返回 `WEOF`，则表示发生错误，设置 `fp->_flags |= __SERR` 并跳转到 `error` 标签进行处理。

9. **内存管理:**  在处理字符串和浮点数转换时，可能会动态分配内存（例如 `convbuf` 和 `dtoaresult`），在函数结束前需要释放这些内存。

**涉及 dynamic linker 的功能及处理过程:**

`vfwprintf.cpp` 本身的代码并没有直接调用动态链接器 (dynamic linker) 的 API。然而，作为 Bionic C 库的一部分，`vfwprintf` 所在的 `libc.so` 是由 dynamic linker 在程序启动时加载的。

**so 布局样本 (简化):**

假设一个简单的 Android 应用 `my_app` 链接了 `libc.so`。

```
/system/bin/linker64 (dynamic linker)
/system/lib64/libc.so (Bionic C 库，包含 vfwprintf)
/apex/com.android.runtime/lib64/bionic/libm.so (数学库，可能包含 dtoa 等函数)
/data/app/com.example.my_app/lib/arm64-v8a/my_app.so (应用自己的 native 库)
```

**链接的处理过程 (简化):**

1. **程序启动:** 当 `my_app` 启动时，Android 系统内核会加载 dynamic linker (`/system/bin/linker64`)。
2. **加载依赖:** Dynamic linker 读取 `my_app.so` 的头部信息，找到它依赖的共享库，例如 `libc.so`。
3. **查找和加载:** Dynamic linker 在预定义的路径中查找 `libc.so`，并将其加载到内存中。
4. **符号解析 (Symbol Resolution):** 当 `my_app.so` 中的代码调用 `printf` 或 `fwprintf` 时，链接器需要找到这些符号在 `libc.so` 中的地址。这个过程称为符号解析。链接器维护着一个符号表，记录了每个共享库导出的符号及其地址。
5. **重定位 (Relocation):**  由于共享库被加载到内存的哪个地址是不确定的，链接器需要修改 `my_app.so` 中对 `printf` 等函数的调用指令，将它们指向 `libc.so` 中 `vfwprintf` (或其他相关函数) 的实际地址。
6. **延迟绑定 (Lazy Binding, 可选):** 为了优化启动速度，Android 通常使用延迟绑定。这意味着在第一次调用某个共享库函数时才进行符号解析和重定位。在第一次调用前，会先跳转到一个 PLT (Procedure Linkage Table) 条目，该条目会调用链接器来解析符号。

**假设输入与输出:**

假设以下代码：

```c++
#include <stdio.h>
#include <wchar.h>

int main() {
    int num = 123;
    double pi = 3.14159;
    const wchar_t* str = L"Hello";
    fwprintf(stdout, L"Number: %d, Pi: %.2f, String: %ls\n", num, pi, str);
    return 0;
}
```

**假设输入:**

* `fp`: 指向标准输出流 `stdout` 的文件指针。
* `fmt0`: 宽字符串 `L"Number: %d, Pi: %.2f, String: %ls\n"`。
* `ap`: 包含三个参数的 `va_list`: `123` (int), `3.14159` (double), `L"Hello"` (wchar_t*)。

**逻辑推理和输出:**

`vfwprintf` 会按照格式化字符串的指示进行处理：

1. `%d`:  提取 `ap` 中的第一个参数 `123`，转换为宽字符串 `"123"`。
2. `Pi: `: 输出宽字符串 `"Pi: "`。
3. `%.2f`: 提取 `ap` 中的第二个参数 `3.14159`，格式化为保留两位小数的浮点数，转换为宽字符串 `"3.14"`。
4. `, `: 输出宽字符串 `", "`。
5. `String: `: 输出宽字符串 `"String: "`。
6. `%ls`: 提取 `ap` 中的第三个参数 `L"Hello"`，直接使用该宽字符串。
7. `\n`: 输出换行符。

**假设输出:**

```
Number: 123, Pi: 3.14, String: Hello
```

**用户或编程常见的使用错误:**

1. **格式化字符串与参数类型不匹配:**  这是最常见的错误，会导致未定义的行为，甚至程序崩溃。
   ```c++
   int num = 123;
   fwprintf(stdout, L"Number: %s\n", num); // 错误：期望字符串，但提供了整数
   ```

2. **忘记提供参数:**
   ```c++
   fwprintf(stdout, L"Number: %d\n"); // 错误：缺少 %d 对应的参数
   ```

3. **使用了 `%n` 格式符:**  虽然 C 标准库支持 `%n`，但 Android Bionic 中为了安全原因禁用了它。尝试使用 `%n` 会导致程序终止。

4. **缓冲区溢出 (虽然 `vfwprintf` 本身会尝试避免，但使用不当仍可能发生):**  如果格式化字符串生成的输出超过了目标缓冲区的大小，可能会导致缓冲区溢出。这在直接使用底层输出函数时需要特别注意。

5. **宽字符和窄字符混用不当:**  在需要宽字符输出的场景下使用了窄字符相关的函数或字符串字面量，会导致乱码或不正确的输出。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例:**

一个典型的调用链可能是这样的：

1. **Android Framework (Java):**  应用程序的 Java 代码调用 `android.util.Log` 类的方法，例如 `Log.w(TAG, "Warning message: %s", warning)`.
2. **Android Runtime (ART):**  ART 将 Java 层的 `Log.w` 调用桥接到 native 代码。
3. **NDK (Native 代码):**  ART 会调用到 `liblog.so` 中的 native 日志函数，例如 `__android_log_write` 或 `__android_log_vprint`.
4. **Bionic (libc.so):**  `liblog.so` 的实现内部会调用 Bionic C 库中的 `vfprintf` 或 `vfwprintf` 来格式化日志消息并输出到日志设备。

**Frida Hook 示例:**

可以使用 Frida hook `vfwprintf` 函数来观察其调用情况和参数。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__vfwprintf"), {
    onEnter: function(args) {
        const fp = new NativePointer(args[0]);
        const format = Memory.readUtf16String(args[1]);
        console.log("[*] __vfwprintf called");
        console.log("    fp:", fp);
        console.log("    format:", format);

        // 可以进一步解析 va_list 中的参数，但这比较复杂
        // 例如，可以根据 format 字符串中的指示符来读取参数
    },
    onLeave: function(retval) {
        console.log("[*] __vfwprintf returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 确保你的 Android 设备已连接并通过 adb 可访问。
2. 安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 将 `com.example.myapp` 替换为你要监控的应用的包名。
4. 运行 Python 脚本。
5. 在你的 Android 应用中触发会调用 `Log` 或其他输出函数的代码。
6. Frida 会拦截对 `__vfwprintf` 的调用，并打印出文件指针和格式化字符串。

这个 Frida 脚本提供了一个基本的 hook 示例，可以帮助你理解 `vfwprintf` 是如何在 Android 系统中被调用的。更复杂的 hook 可以解析 `va_list` 中的参数，以获取更详细的信息。

希望以上详细的分析能够帮助你理解 `bionic/libc/stdio/vfwprintf.cpp` 的功能和实现细节。

### 提示词
```
这是目录为bionic/libc/stdio/vfwprintf.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*	$OpenBSD: vfwprintf.c,v 1.15 2015/12/28 22:08:18 mmcc Exp $ */
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define CHAR_TYPE wchar_t
#define FUNCTION_NAME __vfwprintf
#define CHAR_TYPE_STRLEN wcslen
#define CHAR_TYPE_STRNLEN wcsnlen
#define CHAR_TYPE_INF L"INF"
#define CHAR_TYPE_inf L"inf"
#define CHAR_TYPE_NAN L"NAN"
#define CHAR_TYPE_nan L"nan"
#define CHAR_TYPE_ORIENTATION ORIENT_CHARS

#define PRINT(ptr, len)                                          \
  do {                                                           \
    for (int n3 = 0; n3 < (len); n3++) {                         \
      if ((helpers::xfputwc((ptr)[n3], fp)) == WEOF) goto error; \
    }                                                            \
  } while (0)

#define FLUSH()

#include "printf_common.h"

#define print_utf8(utf8, prec) \
  do { \
    free(convbuf); \
    convbuf = helpers::mbsconv(utf8, prec); \
    if (convbuf == nullptr) { \
      fp->_flags |= __SERR; \
      goto error; \
    } else { \
      cp = convbuf; \
    } \
    goto string; \
  } while (0)

int FUNCTION_NAME(FILE* fp, const CHAR_TYPE* fmt0, va_list ap) {
  int caller_errno = errno;
  int n, n2;
  CHAR_TYPE* cp;   /* handy char pointer (short term usage) */
  CHAR_TYPE sign;  /* sign prefix (' ', '+', '-', or \0) */
  int flags;     /* flags as above */
  int ret;       /* return value accumulator */
  int width;     /* width from format (%8d), or 0 */
  int prec;      /* precision from format; <0 for N/A */
  /*
   * We can decompose the printed representation of floating
   * point numbers into several parts, some of which may be empty:
   *
   * [+|-| ] [0x|0X] MMM . NNN [e|E|p|P] [+|-] ZZ
   *    A       B     ---C---      D       E   F
   *
   * A:	'sign' holds this value if present; '\0' otherwise
   * B:	ox[1] holds the 'x' or 'X'; '\0' if not hexadecimal
   * C:	cp points to the string MMMNNN.  Leading and trailing
   *	zeros are not in the string and must be added.
   * D:	expchar holds this character; '\0' if no exponent, e.g. %f
   * F:	at least two digits for decimal, at least one digit for hex
   */
  char* decimal_point = nullptr;
  int signflag; /* true if float is negative */
  union {       /* floating point arguments %[aAeEfFgG] */
    double dbl;
    long double ldbl;
  } fparg;
  int expt;                      /* integer value of exponent */
  char expchar;                  /* exponent character: [eEpP\0] */
  char* dtoaend;                 /* pointer to end of converted digits */
  int expsize;                   /* character count for expstr */
  int lead;                      /* sig figs before decimal or group sep */
  int ndig;                      /* actual number of digits returned by dtoa */
  CHAR_TYPE expstr[MAXEXPDIG + 2]; /* buffer for exponent string: e+ZZZ */
  char* dtoaresult = nullptr;

  uintmax_t _umax;             /* integer arguments %[diouxX] */
  enum { BIN, OCT, DEC, HEX } base; /* base for %[bBdiouxX] conversion */
  int dprec;                   /* a copy of prec if %[bBdiouxX], 0 otherwise */
  int realsz;                  /* field size expanded by dprec */
  int size;                    /* size of converted field or string */
  const char* xdigs;           /* digits for %[xX] conversion */
#define NIOV 8
  struct __suio uio;       /* output information: summary */
  struct __siov iov[NIOV]; /* ... and individual io vectors */
  struct __siov* iovp; /* for PRINT macro */
  CHAR_TYPE buf[BUF];            /* buffer with space for digits of uintmax_t */
  CHAR_TYPE ox[2];               /* space for 0x; ox[1] is either x, X, or \0 */
  union arg* argtable;         /* args, built due to positional arg */
  union arg statargtable[STATIC_ARG_TBL_SIZE];
  size_t argtablesiz;
  int nextarg;      /* 1-based argument index */
  va_list orgap;    /* original argument pointer */
  CHAR_TYPE* convbuf; /* buffer for wide/multibyte conversion */

  /*
   * Choose PADSIZE to trade efficiency vs. size.  If larger printf
   * fields occur frequently, increase PADSIZE and make the initialisers
   * below longer.
   */
#define PADSIZE 16 /* pad chunk size */
  static const CHAR_TYPE blanks[PADSIZE] = {
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
  };
  static const CHAR_TYPE zeroes[PADSIZE] = {
    '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
  };

  static const char xdigs_lower[] = "0123456789abcdef";
  static const char xdigs_upper[] = "0123456789ABCDEF";

  _SET_ORIENTATION(fp, CHAR_TYPE_ORIENTATION);

  // Writing "" to a read only file returns EOF, not 0.
  if (cantwrite(fp)) {
    errno = EBADF;
    return EOF;
  }

  // Optimize writes to stderr and other unbuffered files).
  if ((fp->_flags & (__SNBF | __SWR | __SRW)) == (__SNBF | __SWR) && fp->_file >= 0) {
    return (__sbprintf(fp, fmt0, ap));
  }

  CHAR_TYPE* fmt = const_cast<CHAR_TYPE*>(fmt0);
  argtable = nullptr;
  nextarg = 1;
  va_copy(orgap, ap);
  uio.uio_iov = iovp = iov;
  uio.uio_resid = 0;
  uio.uio_iovcnt = 0;
  ret = 0;
  convbuf = nullptr;

  /*
   * Scan the format for conversions (`%' character).
   */
  for (;;) {
    int ch;
    for (cp = fmt; (ch = *fmt) != '\0' && ch != '%'; fmt++) continue;
    if (fmt != cp) {
      ptrdiff_t m = fmt - cp;
      if (m < 0 || m > INT_MAX - ret) goto overflow;
      PRINT(cp, m);
      ret += m;
    }
    if (ch == '\0') goto done;
    fmt++; /* skip over '%' */

    flags = 0;
    dprec = 0;
    width = 0;
    prec = -1;
    sign = '\0';
    ox[1] = '\0';

  rflag:
    ch = *fmt++;
  reswitch:
    switch (ch) {
      case ' ':
        /*
         * ``If the space and + flags both appear, the space
         * flag will be ignored.''
         *	-- ANSI X3J11
         */
        if (!sign) sign = ' ';
        goto rflag;
      case '#':
        flags |= ALT;
        goto rflag;
      case '\'':
        /* grouping not implemented */
        goto rflag;
      case '*':
        /*
         * ``A negative field width argument is taken as a
         * - flag followed by a positive field width.''
         *	-- ANSI X3J11
         * They don't exclude field widths read from args.
         */
        GETASTER(width);
        if (width >= 0) goto rflag;
        if (width == INT_MIN) goto overflow;
        width = -width;
        __BIONIC_FALLTHROUGH;
      case '-':
        flags |= LADJUST;
        goto rflag;
      case '+':
        sign = '+';
        goto rflag;
      case '.':
        if ((ch = *fmt++) == '*') {
          GETASTER(n);
          prec = n < 0 ? -1 : n;
          goto rflag;
        }
        n = 0;
        while (is_digit(ch)) {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        }
        if (ch == '$') {
          nextarg = n;
          if (argtable == nullptr) {
            argtable = statargtable;
            if (__find_arguments(fmt0, orgap, &argtable, &argtablesiz) == -1) {
              ret = -1;
              goto error;
            }
          }
          goto rflag;
        }
        prec = n;
        goto reswitch;
      case '0':
        /*
         * ``Note that 0 is taken as a flag, not as the
         * beginning of a field width.''
         *	-- ANSI X3J11
         */
        flags |= ZEROPAD;
        goto rflag;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        n = 0;
        do {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        } while (is_digit(ch));
        if (ch == '$') {
          nextarg = n;
          if (argtable == nullptr) {
            argtable = statargtable;
            if (__find_arguments(fmt0, orgap, &argtable, &argtablesiz) == -1) {
              ret = -1;
              goto error;
            }
          }
          goto rflag;
        }
        width = n;
        goto reswitch;
      case 'L':
        flags |= LONGDBL;
        goto rflag;
      case 'h':
        if (*fmt == 'h') {
          fmt++;
          flags |= CHARINT;
        } else {
          flags |= SHORTINT;
        }
        goto rflag;
      case 'j':
        flags |= MAXINT;
        goto rflag;
      case 'l':
        if (*fmt == 'l') {
          fmt++;
          flags |= LLONGINT;
        } else {
          flags |= LONGINT;
        }
        goto rflag;
      case 'q':
        flags |= LLONGINT;
        goto rflag;
      case 't':
        flags |= PTRINT;
        goto rflag;
      case 'z':
        flags |= SIZEINT;
        goto rflag;
      case 'B':
      case 'b':
        _umax = UARG();
        base = BIN;
        if (flags & ALT && _umax != 0) ox[1] = ch;
        goto nosign;
      case 'C':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'c':
        if (flags & LONGINT)
          *(cp = buf) = (wchar_t)GETARG(wint_t);
        else
          *(cp = buf) = (wchar_t)btowc(GETARG(int));
        size = 1;
        sign = '\0';
        break;
      case 'D':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'd':
      case 'i':
        _umax = SARG();
signed_decimal:
        if ((intmax_t)_umax < 0) {
          _umax = -_umax;
          sign = '-';
        }
        base = DEC;
        goto number;
      case 'a':
      case 'A':
        if (ch == 'a') {
          ox[1] = 'x';
          xdigs = xdigs_lower;
          expchar = 'p';
        } else {
          ox[1] = 'X';
          xdigs = xdigs_upper;
          expchar = 'P';
        }
        if (prec >= 0) prec++;
        if (dtoaresult) __freedtoa(dtoaresult);
        if (flags & LONGDBL) {
          fparg.ldbl = GETARG(long double);
          dtoaresult = __hldtoa(fparg.ldbl, xdigs, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
        } else {
          fparg.dbl = GETARG(double);
          dtoaresult = __hdtoa(fparg.dbl, xdigs, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
        }
        if (prec < 0) prec = dtoaend - dtoaresult;
        if (expt == INT_MAX) ox[1] = '\0';
        goto fp_common;
      case 'e':
      case 'E':
        expchar = ch;
        if (prec < 0) /* account for digit before decpt */
          prec = DEFPREC + 1;
        else
          prec++;
        goto fp_begin;
      case 'f':
      case 'F':
        expchar = '\0';
        goto fp_begin;
      case 'g':
      case 'G':
        expchar = ch - ('g' - 'e');
        if (prec == 0) prec = 1;
      fp_begin:
        if (prec < 0) prec = DEFPREC;
        if (dtoaresult) __freedtoa(dtoaresult);
        if (flags & LONGDBL) {
          fparg.ldbl = GETARG(long double);
          dtoaresult = __ldtoa(&fparg.ldbl, expchar ? 2 : 3, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
        } else {
          fparg.dbl = GETARG(double);
          dtoaresult = __dtoa(fparg.dbl, expchar ? 2 : 3, prec, &expt, &signflag, &dtoaend);
          if (dtoaresult == nullptr) {
            errno = ENOMEM;
            goto error;
          }
          if (expt == 9999) expt = INT_MAX;
        }
      fp_common:
#if CHAR_TYPE_ORIENTATION == ORIENT_BYTES
        cp = dtoaresult;
#else
        free(convbuf);
        cp = convbuf = helpers::mbsconv(dtoaresult, -1);
        if (cp == nullptr) goto error;
#endif
        if (signflag) sign = '-';
        if (expt == INT_MAX) { /* inf or nan */
          if (*cp == 'N') {
            cp = const_cast<CHAR_TYPE*>((ch >= 'a') ? CHAR_TYPE_nan : CHAR_TYPE_NAN);
          } else {
            cp = const_cast<CHAR_TYPE*>((ch >= 'a') ? CHAR_TYPE_inf : CHAR_TYPE_INF);
          }
          size = 3;
          flags &= ~ZEROPAD;
          break;
        }
        flags |= FPT;
        ndig = dtoaend - dtoaresult;
        if (ch == 'g' || ch == 'G') {
          if (expt > -4 && expt <= prec) {
            /* Make %[gG] smell like %[fF] */
            expchar = '\0';
            if (flags & ALT)
              prec -= expt;
            else
              prec = ndig - expt;
            if (prec < 0) prec = 0;
          } else {
            /*
             * Make %[gG] smell like %[eE], but
             * trim trailing zeroes if no # flag.
             */
            if (!(flags & ALT)) prec = ndig;
          }
        }
        if (expchar) {
          expsize = exponent(expstr, expt - 1, expchar);
          size = expsize + prec;
          if (prec > 1 || flags & ALT) ++size;
        } else {
          /* space for digits before decimal point */
          if (expt > 0)
            size = expt;
          else /* "0" */
            size = 1;
          /* space for decimal pt and following digits */
          if (prec || flags & ALT) size += prec + 1;
          lead = expt;
        }
        break;
      case 'n':
        __fortify_fatal("%%n not allowed on Android");
      case 'm':
        if (flags & ALT) {
          const char* name = strerrorname_np(caller_errno);
          if (name) print_utf8(name, prec);
          _umax = caller_errno;
          goto signed_decimal;
        }
        print_utf8(strerror_r(caller_errno, reinterpret_cast<char*>(buf), sizeof(buf)), prec);
      case 'O':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'o':
        _umax = UARG();
        base = OCT;
        goto nosign;
      case 'p':
        /*
         * ``The argument shall be a pointer to void.  The
         * value of the pointer is converted to a sequence
         * of printable characters, in an implementation-
         * defined manner.''
         *	-- ANSI X3J11
         */
        _umax = (u_long)GETARG(void*);
        base = HEX;
        xdigs = xdigs_lower;
        ox[1] = 'x';
        goto nosign;
      case 'S':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 's':
        if (flags & LONGINT) {
          if ((cp = GETARG(wchar_t*)) == nullptr) cp = const_cast<wchar_t*>(L"(null)");
        } else {
          char* mbsarg;
          if ((mbsarg = GETARG(char*)) == nullptr) mbsarg = const_cast<char*>("(null)");
          print_utf8(mbsarg, prec);
        }
  string:
        if (prec >= 0) {
          size = CHAR_TYPE_STRNLEN(cp, prec);
        } else {
          size_t len;

          if ((len = CHAR_TYPE_STRLEN(cp)) > INT_MAX) goto overflow;
          size = (int)len;
        }
        sign = '\0';
        break;
      case 'U':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'u':
        _umax = UARG();
        base = DEC;
        goto nosign;
      case 'w': {
        n = 0;
        bool fast = false;
        ch = *fmt++;
        if (ch == 'f') {
          fast = true;
          ch = *fmt++;
        }
        while (is_digit(ch)) {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        }
        flags |= helpers::w_to_flag(n, fast);
        goto reswitch;
      }
      case 'X':
        xdigs = xdigs_upper;
        goto hex;
      case 'x':
        xdigs = xdigs_lower;
      hex:
        _umax = UARG();
        base = HEX;
        /* leading 0x/X only if non-zero */
        if (flags & ALT && _umax != 0) ox[1] = ch;

        /* unsigned conversions */
      nosign:
        sign = '\0';
        /*
         * ``... diouXx conversions ... if a precision is
         * specified, the 0 flag will be ignored.''
         *	-- ANSI X3J11
         */
      number:
        if ((dprec = prec) >= 0) flags &= ~ZEROPAD;

        /*
         * ``The result of converting a zero value with an
         * explicit precision of zero is no characters.''
         *	-- ANSI X3J11
         */
        cp = buf + BUF;
        if (_umax != 0 || prec != 0) {
          /*
           * Unsigned mod is hard, and unsigned mod
           * by a constant is easier than that by
           * a variable; hence this switch.
           */
          switch (base) {
            case BIN:
              do {
                *--cp = to_char(_umax & 1);
                _umax >>= 1;
              } while (_umax);
              break;

            case OCT:
              do {
                *--cp = to_char(_umax & 7);
                _umax >>= 3;
              } while (_umax);
              /* handle octal leading 0 */
              if (flags & ALT && *cp != '0') *--cp = '0';
              break;

            case DEC:
              /* many numbers are 1 digit */
              while (_umax >= 10) {
                *--cp = to_char(_umax % 10);
                _umax /= 10;
              }
              *--cp = to_char(_umax);
              break;

            case HEX:
              do {
                *--cp = xdigs[_umax & 15];
                _umax >>= 4;
              } while (_umax);
              break;

            default:
              abort();
          }
        }
        size = buf + BUF - cp;
        if (size > BUF) abort(); /* should never happen */
        break;
      default: /* "%?" prints ?, unless ? is NUL */
        if (ch == '\0') goto done;
        /* pretend it was %c with argument ch */
        cp = buf;
        *cp = ch;
        size = 1;
        sign = '\0';
        break;
    }

    /*
     * All reasonable formats wind up here.  At this point, `cp'
     * points to a string which (if not flags&LADJUST) should be
     * padded out to `width' places.  If flags&ZEROPAD, it should
     * first be prefixed by any sign or other prefix; otherwise,
     * it should be blank padded before the prefix is emitted.
     * After any left-hand padding and prefixing, emit zeroes
     * required by a decimal %[bBdiouxX] precision, then print the
     * string proper, then emit zeroes required by any leftover
     * floating precision; finally, if LADJUST, pad with blanks.
     *
     * Compute actual size, so we know how much to pad.
     * size excludes decimal prec; realsz includes it.
     */
    realsz = dprec > size ? dprec : size;
    if (sign) realsz++;
    if (ox[1]) realsz += 2;

    /* right-adjusting blank padding */
    if ((flags & (LADJUST | ZEROPAD)) == 0) PAD(width - realsz, blanks);

    /* prefix */
    if (sign) PRINT(&sign, 1);
    if (ox[1]) { /* ox[1] is either x, X, or \0 */
      ox[0] = '0';
      PRINT(ox, 2);
    }

    /* right-adjusting zero padding */
    if ((flags & (LADJUST | ZEROPAD)) == ZEROPAD) PAD(width - realsz, zeroes);

    /* leading zeroes from decimal precision */
    PAD(dprec - size, zeroes);

    /* the string or number proper */
    if ((flags & FPT) == 0) {
      PRINT(cp, size);
    } else { /* glue together f_p fragments */
      if (decimal_point == nullptr) decimal_point = nl_langinfo(RADIXCHAR);
      if (!expchar) { /* %[fF] or sufficiently short %[gG] */
        CHAR_TYPE* end = cp + ndig;
        if (expt <= 0) {
          PRINT(zeroes, 1);
          if (prec || flags & ALT) PRINT(decimal_point, 1);
          PAD(-expt, zeroes);
          /* already handled initial 0's */
          prec += expt;
        } else {
          PRINTANDPAD(cp, end, lead, zeroes);
          cp += lead;
          if (prec || flags & ALT) PRINT(decimal_point, 1);
        }
        PRINTANDPAD(cp, end, prec, zeroes);
      } else { /* %[eE] or sufficiently long %[gG] */
        if (prec > 1 || flags & ALT) {
          buf[0] = *cp++;
          buf[1] = *decimal_point;
          PRINT(buf, 2);
          PRINT(cp, ndig - 1);
          PAD(prec - ndig, zeroes);
        } else { /* XeYYY */
          PRINT(cp, 1);
        }
        PRINT(expstr, expsize);
      }
    }
    /* left-adjusting padding (always blank) */
    if (flags & LADJUST) PAD(width - realsz, blanks);

    /* finally, adjust ret */
    if (width < realsz) width = realsz;
    if (width > INT_MAX - ret) goto overflow;
    ret += width;

    FLUSH(); /* copy out the I/O vectors */
  }
done:
  FLUSH();
error:
  va_end(orgap);
  if (__sferror(fp)) ret = -1;
  goto finish;

overflow:
  errno = ENOMEM;
  ret = -1;

finish:
  free(convbuf);
  if (dtoaresult) __freedtoa(dtoaresult);
  if (argtable != nullptr && argtable != statargtable) {
    munmap(argtable, argtablesiz);
    argtable = nullptr;
  }
  return (ret);
}
```
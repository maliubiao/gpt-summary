Response:
Let's break down the thought process for analyzing the `parsefloat.c` code.

**1. Understanding the Request:**

The core request is to analyze a specific C source file (`parsefloat.c`) from Android's Bionic library. The analysis should cover functionality, relation to Android, implementation details, dynamic linking aspects, examples, common errors, and how it's reached in the Android framework/NDK, including a Frida hook example.

**2. Initial Code Scan and Identification of Key Functions:**

The first step is to quickly scan the code and identify the main functions. We see two functions: `parsefloat` and `wparsefloat`. The presence of `wparsefloat` immediately suggests that this file handles both standard character streams and wide character streams, likely for internationalization support.

**3. Deconstructing `parsefloat`:**

* **Purpose:** The function name itself (`parsefloat`) strongly suggests its purpose: parsing a floating-point number from an input stream. The function signature `size_t parsefloat(FILE *fp, char *buf, char *end)` reinforces this, indicating it reads from a file (`FILE *fp`), writes the parsed number to a buffer (`char *buf`), and has a buffer end pointer (`char *end`). The `size_t` return type likely represents the number of characters parsed.

* **Core Logic (State Machine):**  The code uses a state machine (`enum { ... } state`) to parse the floating-point number. This is a common technique for parsing structured input. We need to trace the transitions between states to understand the parsing rules.

* **State Analysis:**  Let's go through the states and their purpose:
    * `S_START`: Initial state, expecting a sign or digit.
    * `S_GOTSIGN`: Sign ('+' or '-') has been encountered.
    * `S_INF`: Potentially parsing "infinity" or "INF".
    * `S_NAN`: Potentially parsing "NaN" or "nan(...)".
    * `S_MAYBEHEX`: Saw a '0', might be a hexadecimal number.
    * `S_DIGITS`: Parsing integer part digits.
    * `S_FRAC`: Parsing fractional part digits (after the '.').
    * `S_EXP`:  Encountered 'e' or 'E' (or 'p'/'P' for hex), indicating the exponent.
    * `S_EXPDIGITS`: Parsing exponent digits.

* **Key Variables:**
    * `commit`: This is crucial! It tracks the last point where a valid floating-point number representation was found. This allows for backtracking using `ungetc` if the parsing fails later.
    * `infnanpos`: Tracks progress when parsing "infinity" or "NaN".
    * `gotmantdig`:  Indicates whether any digits have been encountered in the mantissa.
    * `ishex`:  Flag indicating if the number is hexadecimal.

* **Implementation Details:**  The code iterates through the input stream character by character. The `switch` statement based on the `state` determines how to process the current character. `ungetc` is used to push back characters onto the input stream if the parsing goes too far or fails. The buffer `buf` is filled as characters are parsed.

* **Error Handling (Implicit):**  The function doesn't have explicit error codes. The parsing stops when an invalid character is encountered, and the function returns the number of characters successfully parsed up to the last valid point. This behavior is important for functions like `scanf`.

**4. Deconstructing `wparsefloat`:**

After understanding `parsefloat`, `wparsefloat` becomes easier to grasp. The logic is almost identical. The key differences are:

* It works with wide characters (`wchar_t`).
* It uses wide character input/output functions like `__fgetwc_unlock` and `ungetwc`.
* It checks for wide character equivalents of digits, hex digits, etc. (`iswdigit`, `iswxdigit`).

**5. Connecting to Android Functionality:**

* **Core C Library:** `parsefloat` is a fundamental part of the standard C library (`libc`). It's used by other functions that need to parse floating-point numbers from strings or streams.

* **Input/Output:**  Android apps often need to read and process data, including numerical data. `parsefloat` is essential for converting string representations of floating-point numbers (e.g., from user input, configuration files, network data) into actual `float` or `double` values.

* **`scanf` and Related Functions:** The most direct connection is to the `scanf`, `fscanf`, and `sscanf` family of functions. These functions rely on lower-level parsing functions like `parsefloat` to handle the `%f`, `%e`, `%g`, etc., format specifiers.

**6. Dynamic Linking Aspects:**

* **Shared Library:** `parsefloat` resides within `libc.so`, a shared library. This means that multiple processes can use the same code in memory, saving resources.

* **Linking Process:** When an Android app (or native library) uses a function from `libc`, the dynamic linker (`linker64` or `linker`) resolves the symbol (e.g., `parsefloat`) at runtime and sets up the necessary memory addresses.

* **SO Layout:**  The `libc.so` file has a specific structure (ELF format). It contains sections for code (`.text`), data (`.data`, `.rodata`), symbol tables, and more. The dynamic linker uses these tables to find the required functions.

**7. Examples, Errors, and Frida Hooking:**

* **Examples:** Provide simple code snippets demonstrating how `parsefloat` is implicitly used through `scanf`.
* **Common Errors:** Focus on common pitfalls like buffer overflows (though the provided code has a buffer limit) and invalid input formats.
* **Frida Hooking:** Demonstrate how to intercept calls to `parsefloat` using Frida to observe its behavior and arguments. This is a powerful debugging technique.

**8. Android Framework/NDK Path:**

Explain how a call from the Android framework (Java code) or NDK (native code) can eventually lead to the execution of `parsefloat`. Illustrate with a concrete example, such as parsing user input in an Android app.

**9. Structuring the Response:**

Organize the information logically, using headings, bullet points, and code blocks to make it clear and easy to understand. Start with a summary of the function's purpose and then delve into the details. Address each part of the original request comprehensively.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on the bitwise manipulation of floating-point numbers. **Correction:** Realized that `parsefloat` is about *parsing* the string representation, not the low-level representation.
* **Considered explaining the IEEE 754 standard:**  **Correction:** While relevant to floating-point numbers in general, it's not strictly necessary to explain the intricacies of the standard to understand the *parsing* process. Keep the focus on what the code *does*.
* **Initially unsure how to explain the dynamic linking:** **Correction:** Broke it down into the concepts of shared libraries, the linker's role, and the structure of SO files.
* **Frida example initially too complex:** **Correction:** Simplified the Frida script to focus on the essential aspects of hooking the function and printing arguments.

By following this thought process, breaking down the problem into smaller parts, and making adjustments along the way, we can arrive at a comprehensive and accurate analysis of the `parsefloat.c` source code.
好的，让我们来详细分析 `bionic/libc/stdio/parsefloat.c` 这个文件。

**功能概述:**

`parsefloat.c` 文件定义了两个核心函数：`parsefloat` 和 `wparsefloat`。这两个函数的主要功能是从文件流 (`FILE *fp`) 中读取字符，并将读取到的字符解析成一个有效的浮点数（包括正负无穷大和 NaN），然后将这个浮点数的字符串表示形式存储到提供的缓冲区 (`buf`) 中。

* **`parsefloat(FILE *fp, char *buf, char *end)`:**  用于解析窄字符（`char`）流中的浮点数。
* **`wparsefloat(FILE *fp, wchar_t *buf, wchar_t *end)`:** 用于解析宽字符（`wchar_t`）流中的浮点数，这主要用于支持国际化。

这两个函数的设计目标是尽可能多地读取构成有效浮点数的字符，直到遇到不属于浮点数表示的字符为止。它们在解析过程中会识别以下几种浮点数格式：

* **标准十进制浮点数:** 例如 "1.23", "-45.67e+8"。
* **十六进制浮点数:** 例如 "0x1.fp10"。
* **无穷大:** "inf" 或 "infinity" (忽略大小写)。
* **NaN (Not a Number):** "nan" 或 "nan(序列)" (忽略大小写)。

**与 Android 功能的关系及举例:**

`parsefloat.c` 是 Android Bionic C 库的一部分，因此它为 Android 系统和应用程序提供了基础的浮点数解析能力。许多 Android 的核心功能以及通过 NDK 开发的 Native 代码都会间接地或直接地使用到这些函数。

**举例说明:**

1. **`scanf` 系列函数:**  在 C/C++ 代码中，经常使用 `scanf`, `fscanf`, `sscanf` 等函数从输入流或字符串中读取格式化的数据。当这些函数遇到浮点数格式说明符（如 `%f`, `%e`, `%g`）时，它们内部会调用 `parsefloat` (或 `wparsefloat` 对于宽字符流) 来实际解析输入字符串中的浮点数。

   例如，一个 Android 应用的 Native 代码可能包含以下代码：

   ```c
   #include <stdio.h>

   int main() {
       float value;
       printf("请输入一个浮点数: ");
       scanf("%f", &value);
       printf("你输入的浮点数是: %f\n", value);
       return 0;
   }
   ```

   在这个例子中，`scanf("%f", &value)` 内部就会使用 `parsefloat` 来解析用户输入的字符串并将其转换为 `float` 类型。

2. **配置文件解析:** Android 系统或应用可能会读取包含浮点数值的配置文件。在解析这些文件时，可能需要将字符串形式的浮点数转换为数值类型，这时就会用到 `parsefloat`。

3. **数据转换:** 在网络通信或数据处理过程中，可能需要将接收到的字符串数据转换为浮点数进行计算或存储。

**Libc 函数的实现细节:**

现在我们来详细解释 `parsefloat` 和 `wparsefloat` 的实现逻辑。由于两者逻辑基本相同，我们主要以 `parsefloat` 为例进行分析。

**`parsefloat(FILE *fp, char *buf, char *end)` 的实现:**

1. **状态机 (State Machine):**  该函数使用一个状态机 (`enum`) 来跟踪解析过程。不同的状态对应于正在解析的浮点数的不同部分。

   * `S_START`: 解析开始， ожидание знака или цифры.
   * `S_GOTSIGN`: 已读取到符号 ('+' 或 '-')。
   * `S_INF`: 正在解析 "inf" 或 "infinity"。
   * `S_NAN`: 正在解析 "nan" 或 "nan(...)".
   * `S_MAYBEHEX`: 读取到 '0'，可能是十六进制数。
   * `S_DIGITS`: 正在解析整数部分或十六进制数的数字。
   * `S_FRAC`: 正在解析小数部分。
   * `S_EXP`: 遇到了指数符号 ('e', 'E', 'p', 'P')。
   * `S_EXPDIGITS`: 正在解析指数部分的数字。

2. **字符读取与状态转换:** 函数从文件流 `fp` 中逐个读取字符。根据当前状态和读取到的字符，状态机会发生转换。

3. **`commit` 指针:**  `commit` 指针用于记录当前已读取的字符构成一个有效浮点数表示的最后位置。如果后续解析失败，可以通过 `ungetc` 将多读的字符放回输入流，并回退到 `commit` 指针的位置。

4. **`infnanpos` 变量:**  用于跟踪解析 "infinity" 或 "nan(...)" 的进度。

5. **`gotmantdig` 变量:**  标记是否已读取到尾数部分的数字。

6. **`ishex` 变量:**  标记是否正在解析十六进制浮点数。

7. **解析过程详解:**

   * **起始状态 (`S_START`):**  期望读取到符号或数字。
   * **读取符号 (`S_GOTSIGN`):** 如果读取到 '+' 或 '-'，则进入此状态。
   * **解析无穷大 (`S_INF`):** 如果读取到 'I' 或 'i'，则尝试匹配 "infinity"。
   * **解析 NaN (`S_NAN`):** 如果读取到 'N' 或 'n'，则尝试匹配 "nan" 或 "nan(...)"。
   * **可能是十六进制数 (`S_MAYBEHEX`):** 如果读取到 '0'，则检查下一个字符是否为 'x' 或 'X'。
   * **解析数字 (`S_DIGITS`):**  读取整数部分或十六进制数的数字。
   * **解析小数部分 (`S_FRAC`):**  读取小数点后的数字。
   * **解析指数 (`S_EXP`):**  读取指数符号 ('e', 'E', 'p', 'P')。
   * **解析指数数字 (`S_EXPDIGITS`):** 读取指数部分的数字。

8. **回退与结束:** 当遇到不属于当前浮点数格式的字符时，解析停止。函数会使用 `ungetc` 将多读的字符放回输入流，并将缓冲区中 `commit` 指针之后的内容截断，添加 null 终止符，并返回已解析的字符数。

**`wparsefloat` 的实现:**

`wparsefloat` 的实现与 `parsefloat` 非常相似，主要的区别在于它处理的是宽字符 (`wchar_t`) 流，并使用宽字符相关的函数，例如 `iswdigit`, `iswxdigit`, `__fgetwc_unlock`, `ungetwc` 等。

**动态链接功能及 SO 布局样本和链接处理过程:**

`parsefloat` 和 `wparsefloat` 函数都位于 `libc.so` 这个共享库中。当一个 Android 应用程序或 Native 库需要使用这些函数时，动态链接器 (在 Android 上通常是 `linker` 或 `linker64`) 负责在运行时将这些函数的代码加载到进程的内存空间，并解析符号引用。

**SO 布局样本 (`libc.so` 的简化示意):**

```
ELF Header
Program Headers
...
Section Headers:
  .text         段 (包含可执行代码，包括 parsefloat 函数的代码)
  .rodata       段 (包含只读数据，例如字符串常量)
  .data         段 (包含已初始化的全局变量)
  .bss          段 (包含未初始化的全局变量)
  .symtab       段 (符号表，包含函数和变量的名称、地址等信息)
  .strtab       段 (字符串表，包含符号表中名称对应的字符串)
  .dynsym       段 (动态符号表，用于动态链接)
  .dynstr       段 (动态字符串表，用于动态链接)
  .plt          段 (过程链接表，用于延迟绑定)
  .got.plt      段 (全局偏移量表，用于延迟绑定)
...
```

**链接处理过程:**

1. **编译链接时:** 当编译一个使用 `parsefloat` 的 Native 代码时，编译器会生成对 `parsefloat` 的符号引用。链接器会将这些符号引用记录在生成的可执行文件或共享库的动态符号表中。

2. **程序加载时:** 当 Android 系统加载应用程序或 Native 库时，动态链接器会被调用。

3. **符号解析:** 动态链接器会遍历程序或库的依赖关系，找到 `libc.so`。然后，它会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `parsefloat` 的符号。

4. **重定位:** 找到 `parsefloat` 的地址后，动态链接器会更新程序或库中对 `parsefloat` 的引用，将其指向 `libc.so` 中 `parsefloat` 函数的实际地址。这个过程称为重定位。

5. **延迟绑定 (Lazy Binding):**  为了提高加载速度，Android 通常使用延迟绑定。这意味着在程序启动时，动态链接器可能不会立即解析所有符号。而是当第一次调用 `parsefloat` 时，才会通过过程链接表 (`.plt`) 和全局偏移量表 (`.got.plt`) 来解析和绑定符号。

**假设输入与输出 (逻辑推理):**

**`parsefloat` 函数:**

* **假设输入 (`fp` 指向的流):** "  -123.45e+2abc"
* **假设输出 (`buf`):** "-123.45e+2"
* **返回值:** 10 (已解析的字符数)

* **假设输入 (`fp` 指向的流):** "  infinity  "
* **假设输出 (`buf`):** "infinity"
* **返回值:** 8

* **假设输入 (`fp` 指向的流):** "  nan(some_info)  "
* **假设输出 (`buf`):** "nan(some_info)"
* **返回值:** 14

* **假设输入 (`fp` 指向的流):** "  0x1.8p-3  "
* **假设输出 (`buf`):** "0x1.8p-3"
* **返回值:** 8

**`wparsefloat` 函数 (假设宽字符流):**

* **假设输入 (`fp` 指向的流):** L"  -123.45e+2abc"
* **假设输出 (`buf`):** L"-123.45e+2"
* **返回值:** 10

**用户或编程常见的使用错误:**

1. **缓冲区溢出:** 如果提供的缓冲区 `buf` 不够大，无法容纳解析到的浮点数字符串（包括 null 终止符），可能会发生缓冲区溢出。虽然代码中定义了 `BUF` 大小限制，但在其他使用场景下可能存在风险。

2. **未初始化缓冲区:** 如果在使用 `parsefloat` 之前没有初始化缓冲区 `buf`，则缓冲区中可能包含垃圾数据。

3. **错误的输入流:** 如果输入流 `fp` 没有指向有效的文件或数据源，或者输入流中不包含有效的浮点数表示，则 `parsefloat` 可能不会按预期工作。

4. **假设 `parsefloat` 会进行完全的类型转换:** `parsefloat` 只是将浮点数的字符串表示读取出来，并不会将其转换为 `float` 或 `double` 类型。需要使用 `strtof`, `strtod` 或其他函数进行类型转换。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 代码):**
   * Android Framework 中的某些类，例如 `java.util.Scanner` 或处理 XML/JSON 等配置文件的解析器，在内部进行字符串到数字的转换时，最终可能会调用到 Native 代码。
   * 例如，`Float.parseFloat()` 方法的 Native 实现最终会调用到 Bionic 库中的相关函数，而这些函数可能会依赖于底层的字符解析功能。

2. **Android NDK (Native 代码):**
   * 使用 NDK 开发的 Native 代码可以直接调用 C 标准库函数，包括与输入输出相关的函数。
   * 例如，使用 `scanf` 或 `fscanf` 读取浮点数时，就会直接调用 `parsefloat`。
   * 某些 Native 库可能会实现自己的字符串解析逻辑，但为了效率和一致性，通常会使用 Bionic 库提供的函数。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida 来 hook `parsefloat` 函数，以观察其调用时传入的参数和返回值。

**Frida Hook 示例 (假设目标进程中使用了 `parsefloat`):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['content']))
    else:
        print(message)

device = frida.get_usb_device()
pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

if pid is None:
    session = device.attach('com.example.your_app') # 替换为你的应用包名
else:
    session = device.attach(pid)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "parsefloat"), {
    onEnter: function(args) {
        this.fp = args[0];
        this.buf = args[1];
        this.end = args[2];
        console.log("[parsefloat] onEnter");
        console.log("  fp: " + this.fp);
        console.log("  buf: " + this.buf);
        console.log("  end: " + this.end);
        console.log("  Buffer content before: " + Memory.readUtf8String(this.buf));
    },
    onLeave: function(retval) {
        console.log("[parsefloat] onLeave");
        console.log("  retval: " + retval);
        console.log("  Buffer content after: " + Memory.readUtf8String(this.buf));
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida:** 确保你的设备或模拟器上安装了 Frida 服务，并且你的 PC 上安装了 `frida` 和 `frida-tools`。
2. **获取目标进程的 PID:**  运行你的 Android 应用，并找到其进程 ID。你可以使用 `adb shell ps | grep your_app_package_name` 命令来获取。或者，如果直接附加到包名，Frida会自动处理。
3. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `hook_parsefloat.py`，然后在终端中运行 `python hook_parsefloat.py <PID>` 或 `python hook_parsefloat.py` (如果使用包名附加)。
4. **观察输出:** 当目标应用执行到调用 `parsefloat` 的代码时，Frida 脚本会拦截该调用，并打印出 `parsefloat` 函数的参数（`fp`, `buf`, `end` 的地址以及 `buf` 的内容）和返回值，以及 `buf` 修改后的内容。

这个 Frida 脚本可以帮助你理解 `parsefloat` 是如何被调用的，传入了哪些参数，以及它解析的结果是什么。你可以根据需要修改脚本来捕获更多信息。

希望这个详细的分析能够帮助你理解 `bionic/libc/stdio/parsefloat.c` 的功能和实现方式，以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/stdio/parsefloat.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#include <ctype.h>
#include <stdlib.h>

#include "local.h"

#define	BUF		513	/* Maximum length of numeric string. */

size_t parsefloat(FILE *fp, char *buf, char *end) {
	char *commit, *p;
	int infnanpos = 0;
	enum {
		S_START, S_GOTSIGN, S_INF, S_NAN, S_MAYBEHEX,
		S_DIGITS, S_FRAC, S_EXP, S_EXPDIGITS
	} state = S_START;
	unsigned char c;
	int gotmantdig = 0, ishex = 0;

	/*
	 * We set commit = p whenever the string we have read so far
	 * constitutes a valid representation of a floating point
	 * number by itself.  At some point, the parse will complete
	 * or fail, and we will ungetc() back to the last commit point.
	 * To ensure that the file offset gets updated properly, it is
	 * always necessary to read at least one character that doesn't
	 * match; thus, we can't short-circuit "infinity" or "nan(...)".
	 */
	commit = buf - 1;
	for (p = buf; p < end; ) {
		c = *fp->_p;
reswitch:
		switch (state) {
		case S_START:
			state = S_GOTSIGN;
			if (c == '-' || c == '+')
				break;
			else
				goto reswitch;
		case S_GOTSIGN:
			switch (c) {
			case '0':
				state = S_MAYBEHEX;
				commit = p;
				break;
			case 'I':
			case 'i':
				state = S_INF;
				break;
			case 'N':
			case 'n':
				state = S_NAN;
				break;
			default:
				state = S_DIGITS;
				goto reswitch;
			}
			break;
		case S_INF:
			if (infnanpos > 6 ||
			    (c != "nfinity"[infnanpos] &&
			     c != "NFINITY"[infnanpos]))
				goto parsedone;
			if (infnanpos == 1 || infnanpos == 6)
				commit = p;	/* inf or infinity */
			infnanpos++;
			break;
		case S_NAN:
			switch (infnanpos) {
			case -1:	/* XXX kludge to deal with nan(...) */
				goto parsedone;
			case 0:
				if (c != 'A' && c != 'a')
					goto parsedone;
				break;
			case 1:
				if (c != 'N' && c != 'n')
					goto parsedone;
				else
					commit = p;
				break;
			case 2:
				if (c != '(')
					goto parsedone;
				break;
			default:
				if (c == ')') {
					commit = p;
					infnanpos = -2;
				} else if (!isalnum(c) && c != '_')
					goto parsedone;
				break;
			}
			infnanpos++;
			break;
		case S_MAYBEHEX:
			state = S_DIGITS;
			if (c == 'X' || c == 'x') {
				ishex = 1;
				break;
			} else {	/* we saw a '0', but no 'x' */
				gotmantdig = 1;
				goto reswitch;
			}
		case S_DIGITS:
			if ((ishex && isxdigit(c)) || isdigit(c))
				gotmantdig = 1;
			else {
				state = S_FRAC;
				if (c != '.')
					goto reswitch;
			}
			if (gotmantdig)
				commit = p;
			break;
		case S_FRAC:
			if (((c == 'E' || c == 'e') && !ishex) ||
			    ((c == 'P' || c == 'p') && ishex)) {
				if (!gotmantdig)
					goto parsedone;
				else
					state = S_EXP;
			} else if ((ishex && isxdigit(c)) || isdigit(c)) {
				commit = p;
				gotmantdig = 1;
			} else
				goto parsedone;
			break;
		case S_EXP:
			state = S_EXPDIGITS;
			if (c == '-' || c == '+')
				break;
			else
				goto reswitch;
		case S_EXPDIGITS:
			if (isdigit(c))
				commit = p;
			else
				goto parsedone;
			break;
		default:
			abort();
		}
		*p++ = c;
		if (--fp->_r > 0)
			fp->_p++;
		else if (__srefill(fp))
			break;	/* EOF */
	}

parsedone:
	while (commit < --p)
		(void)ungetc(*(unsigned char *)p, fp);
	*++commit = '\0';
	return commit - buf;
}

size_t wparsefloat(FILE *fp, wchar_t *buf, wchar_t *end) {
	wchar_t *commit, *p;
	int infnanpos = 0;
	enum {
		S_START, S_GOTSIGN, S_INF, S_NAN, S_MAYBEHEX,
		S_DIGITS, S_FRAC, S_EXP, S_EXPDIGITS
	} state = S_START;
	wint_t c;
	int gotmantdig = 0, ishex = 0;

	/*
	 * We set commit = p whenever the string we have read so far
	 * constitutes a valid representation of a floating point
	 * number by itself.  At some point, the parse will complete
	 * or fail, and we will ungetc() back to the last commit point.
	 * To ensure that the file offset gets updated properly, it is
	 * always necessary to read at least one character that doesn't
	 * match; thus, we can't short-circuit "infinity" or "nan(...)".
	 */
	commit = buf - 1;
	c = WEOF;
	for (p = buf; p < end; ) {
		if ((c = __fgetwc_unlock(fp)) == WEOF)
			break;
reswitch:
		switch (state) {
		case S_START:
			state = S_GOTSIGN;
			if (c == '-' || c == '+')
				break;
			else
				goto reswitch;
		case S_GOTSIGN:
			switch (c) {
			case '0':
				state = S_MAYBEHEX;
				commit = p;
				break;
			case 'I':
			case 'i':
				state = S_INF;
				break;
			case 'N':
			case 'n':
				state = S_NAN;
				break;
			default:
				state = S_DIGITS;
				goto reswitch;
			}
			break;
		case S_INF:
			if (infnanpos > 6 ||
			    (c != (wint_t)"nfinity"[infnanpos] &&
			     c != (wint_t)"NFINITY"[infnanpos]))
				goto parsedone;
			if (infnanpos == 1 || infnanpos == 6)
				commit = p;	/* inf or infinity */
			infnanpos++;
			break;
		case S_NAN:
			switch (infnanpos) {
			case -1:	/* XXX kludge to deal with nan(...) */
				goto parsedone;
			case 0:
				if (c != 'A' && c != 'a')
					goto parsedone;
				break;
			case 1:
				if (c != 'N' && c != 'n')
					goto parsedone;
				else
					commit = p;
				break;
			case 2:
				if (c != '(')
					goto parsedone;
				break;
			default:
				if (c == ')') {
					commit = p;
					infnanpos = -2;
				} else if (!iswalnum(c) && c != '_')
					goto parsedone;
				break;
			}
			infnanpos++;
			break;
		case S_MAYBEHEX:
			state = S_DIGITS;
			if (c == 'X' || c == 'x') {
				ishex = 1;
				break;
			} else {	/* we saw a '0', but no 'x' */
				gotmantdig = 1;
				goto reswitch;
			}
		case S_DIGITS:
			if ((ishex && iswxdigit(c)) || iswdigit(c))
				gotmantdig = 1;
			else {
				state = S_FRAC;
				if (c != L'.')
					goto reswitch;
			}
			if (gotmantdig)
				commit = p;
			break;
		case S_FRAC:
			if (((c == 'E' || c == 'e') && !ishex) ||
			    ((c == 'P' || c == 'p') && ishex)) {
				if (!gotmantdig)
					goto parsedone;
				else
					state = S_EXP;
			} else if ((ishex && iswxdigit(c)) || iswdigit(c)) {
				commit = p;
				gotmantdig = 1;
			} else
				goto parsedone;
			break;
		case S_EXP:
			state = S_EXPDIGITS;
			if (c == '-' || c == '+')
				break;
			else
				goto reswitch;
		case S_EXPDIGITS:
			if (iswdigit(c))
				commit = p;
			else
				goto parsedone;
			break;
		default:
			abort();
		}
		*p++ = c;
		c = WEOF;
	}

parsedone:
	if (c != WEOF)
		ungetwc(c, fp);
	while (commit < --p)
		ungetwc(*p, fp);
	*++commit = '\0';
	return (int)(commit - buf);
}

"""

```
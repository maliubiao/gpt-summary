Response:
Let's break down the thought process for analyzing this `vfscanf.cpp` file. The request has several distinct parts, so a structured approach is crucial.

**1. Initial Understanding and Goal Setting:**

* **Identify the Core Function:** The filename `vfscanf.cpp` immediately points to the `vfscanf` family of functions. The provided code confirms this with the internal function `__svfscanf`.
* **Recognize the Context:** The prompt explicitly states this is from Android's Bionic libc. This provides important context for understanding its role and potential Android-specific interactions.
* **Break Down the Request:** The prompt asks for several things:
    * Functionality list.
    * Relationship to Android.
    * Detailed explanation of libc functions.
    * Dynamic linker involvement (if any).
    * Logical inference with examples.
    * Common user errors.
    * Android framework/NDK path to this code.
    * Frida hook example.

**2. Functionality Extraction (High-Level):**

* **Scanning Input:**  The core purpose is to parse formatted input from a file stream. Keywords like "scan," "format," and the various conversion specifiers (`%d`, `%s`, etc.) confirm this.
* **Variable Argument List:** The `va_list ap` parameter indicates it handles a variable number of arguments, as expected for `scanf`-like functions.
* **Input Conversion:** The code iterates through the format string, identifies conversion specifiers, and attempts to convert the corresponding input from the file stream.
* **Error Handling:**  The code includes checks for input failures (`__srefill`), match failures, and allocation failures. The return value `nassigned` (number of successfully assigned fields) is also a key part of error reporting.

**3. Deep Dive into Key Components and Code Sections:**

* **Format String Parsing:**  Focus on the loop that iterates through the `fmt` string and the nested `switch` statement handling different format specifiers (`%`, `*`, `h`, `l`, `d`, `s`, `[`, etc.). Understanding how flags are set and how width is parsed is essential.
* **Conversion Logic:** Analyze the `switch` statement based on the extracted conversion type (`CT_INT`, `CT_FLOAT`, `CT_STRING`, `CT_CHAR`, `CT_CCL`). Pay close attention to:
    * How each type handles whitespace.
    * How width is used.
    * How data is read from the file stream (`fread`, character-by-character processing).
    * The use of `strtoimax`, `strtod`, etc., for numeric conversions.
    * The handling of character classes (`__sccl`).
    * The `ALLOCATE` flag (`%m`) and dynamic memory allocation.
* **`__srefill`:** Recognize this as a crucial function for buffering and reading more data from the underlying file descriptor.
* **`__sccl`:** Understand its role in parsing character class specifications within `%[...]`.
* **Error Handling Mechanisms:** Look for `goto input_failure`, `goto match_failure`, `goto allocation_failure`, and how `nassigned` is used.

**4. Connecting to Android (Specific Examples):**

* **Bionic libc:** Emphasize that this *is* the Android C library, making its functions fundamental to almost all native Android code.
* **NDK Usage:**  Consider how developers using the NDK would directly call functions like `scanf`, `fscanf`, or `sscanf`, which internally use `vfscanf`.
* **Framework Interaction (Indirect):**  Think about Android system services or framework components (written in C/C++) that might need to parse configuration files or other text-based data, potentially using these functions internally.

**5. Explaining libc Functions (Implementation Details):**

* **Focus on the "How":**  Don't just say what `fread` does; explain that it reads a specified number of bytes from the file stream's buffer.
* **Detail Key Algorithms:** For example, explain how `__sccl` builds the character class table. For numeric conversions, mention the iterative process of consuming digits.
* **Address Multibyte Characters:** Note the handling of wide characters (`wchar_t`) and the use of `mbrtowc`.

**6. Dynamic Linker Analysis:**

* **Scan for Obvious Linker Interactions:** In this specific code, there's no direct interaction with the dynamic linker (e.g., `dlopen`, `dlsym`). Therefore, the focus should be on *how* this code itself gets linked into an Android process.
* **SO Layout Example:**  Create a simple scenario showing where `libc.so` would be located in memory.
* **Linking Process Explanation:** Describe the general steps the dynamic linker takes to resolve symbols and load shared libraries.

**7. Logical Inference and Examples:**

* **Choose Representative Scenarios:**  Select format strings and input data that illustrate different aspects of `vfscanf`'s functionality (e.g., different conversion specifiers, whitespace handling, error cases).
* **Predict the Output:**  Based on the input and format string, reason about how `vfscanf` will parse the input and what values will be assigned to the variables.

**8. Common User Errors:**

* **Focus on Practical Mistakes:** Think about errors developers commonly make when using `scanf`-like functions (e.g., type mismatches, buffer overflows, incorrect format strings).

**9. Android Framework/NDK Path and Frida Hook:**

* **Trace the Call Stack (Conceptually):**  Start with a high-level Android API call (e.g., reading a file), then move to the NDK (if applicable), then to the C library function.
* **Frida Hook Strategy:** Identify the function to hook (`__svfscanf`). Show how to intercept the call, inspect arguments (especially the format string and file pointer), and potentially modify the behavior.

**10. Structuring the Response:**

* **Organize by Request Point:** Address each part of the prompt clearly.
* **Use Headings and Subheadings:** Improve readability.
* **Provide Code Snippets (Where Applicable):**  Illustrate concepts with small, relevant code examples.
* **Use Clear and Concise Language:** Avoid overly technical jargon where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this code directly interacts with the Binder. *Correction:*  Upon closer inspection, the code is lower-level and focuses on standard input parsing. Binder interaction would likely happen at a higher level in the Android framework.
* **Initial thought:**  Go into extreme detail about every flag and minor code branch. *Correction:* Focus on the most important aspects and provide a good overall understanding without getting bogged down in every edge case.
* **Initial thought:**  The Frida hook needs to be incredibly complex. *Correction:* Keep the Frida hook example relatively simple to demonstrate the basic principles of interception and argument inspection.

By following this structured approach, breaking down the request, analyzing the code systematically, and connecting it to the Android context, a comprehensive and informative response can be generated.
好的，我们来详细分析 `bionic/libc/stdio/vfscanf.cpp` 文件的功能和实现。

**文件功能概述**

`vfscanf.cpp` 文件实现了 `vfscanf` 函数及其相关的内部逻辑。`vfscanf` 是 C 标准库中的一个函数，它类似于 `fscanf`，但接受一个 `va_list` 类型的参数，这使得它可以被其他变参函数（如 `scanf`, `fscanf`, `sscanf` 等）调用来实现格式化输入。

**主要功能：**

1. **格式化输入解析:**  `vfscanf` 的核心功能是根据提供的格式字符串 (`fmt`) 解析从文件流 (`fp`) 中读取的数据。
2. **类型转换:** 它能够根据格式字符串中的转换说明符（例如 `%d`, `%s`, `%f` 等）将输入的字符串转换为不同的数据类型。
3. **数据存储:**  解析和转换后的数据会被存储到通过 `va_list` 传递进来的变量的内存地址中。
4. **错误处理:**  `vfscanf` 会检测输入过程中的错误，例如无法匹配格式、输入结束等，并返回指示成功解析的字段数量或错误代码。
5. **空白字符处理:**  默认情况下，`vfscanf` 会跳过输入中的前导空白字符，除非格式字符串中使用了特定的标志（例如 `%c`, `%[`）。
6. **字段宽度限制:**  可以通过在转换说明符中指定宽度来限制读取的字符数量。
7. **抑制赋值:** 使用 `*` 标志可以使 `vfscanf` 读取输入但不将其赋值给任何变量。
8. **动态内存分配:**  使用 `%m` 标志可以动态分配内存来存储读取的字符串或字符。

**与 Android 功能的关系及举例**

`vfscanf` 是 Android Bionic libc 的一部分，因此它是 Android 系统中进行格式化输入的基础。许多 Android 系统组件和应用程序都间接地或直接地使用了 `vfscanf` 或其相关的函数。

**举例说明：**

* **系统属性读取：** Android 系统使用属性服务来管理系统级别的配置信息。在读取属性值的过程中，可能会使用 `sscanf` 或类似的函数来解析属性字符串。例如，一个属性字符串可能是 "123 456"，可以使用 `sscanf(value, "%d %d", &int1, &int2)` 来解析出两个整数。而 `sscanf` 内部会调用 `vfscanf`。
* **配置文件解析：**  某些 Android 系统服务或守护进程可能需要解析配置文件。这些配置文件通常是文本格式，可以使用 `fscanf` 从文件中读取并解析数据。例如，一个网络配置文件可能包含 "ip_address=192.168.1.1"，可以使用 `fscanf(fp, "ip_address=%s", ip_address_buffer)` 来读取 IP 地址。
* **NDK 开发：** 使用 Android NDK 进行原生 C/C++ 开发时，开发者可以直接调用 `scanf`, `fscanf`, `sscanf` 等函数，这些函数最终会调用到 Bionic libc 中的 `vfscanf` 实现。
* **命令行工具：**  在 Android 的 shell 环境中，一些命令行工具可能会使用格式化输入来处理用户输入或解析文件内容。

**libc 函数的功能实现详解**

`vfscanf.cpp` 中最核心的函数是 `__svfscanf`（内部的、非线程安全的版本）。下面我们详细解释其实现逻辑：

1. **初始化：**
   - 初始化一些局部变量，例如 `width`（字段宽度）、`flags`（格式标志）、`nassigned`（已赋值的字段数）、`nread`（已读取的字符数）等。
   - 设置文件流的字节方向 (`_SET_ORIENTATION(fp, ORIENT_BYTES)`）。

2. **主循环：**
   - 遍历格式字符串 `fmt` 中的每个字符。

3. **处理空白字符：**
   - 如果当前字符是空白字符，则跳过输入流中的连续空白字符。

4. **处理普通字符：**
   - 如果当前字符不是 `%`，则将其与输入流中的下一个字符进行比较。如果匹配，则消耗输入流中的该字符并继续；否则，表示匹配失败。

5. **处理转换说明符（以 `%` 开头）：**
   - **解析标志和宽度：**  解析 `%` 后面的可选标志（`*`, `h`, `l`, `L`, `j`, `z`, `t`, `m`）和字段宽度。
   - **确定转换类型：** 根据转换字符（例如 `d`, `s`, `f`, `c` 等）确定需要进行的类型转换。
   - **读取输入：** 从输入流中读取数据，读取的字符数受字段宽度的限制。
   - **类型转换和赋值：**
     - **整数转换 (`d`, `i`, `o`, `u`, `x`, `X`, `b`)：** 调用 `strtoimax` 或 `strtoumax` 将读取的字符串转换为整数类型。会处理前缀（例如 `0x`, `0b`）。
     - **浮点数转换 (`e`, `E`, `f`, `F`, `g`, `G`, `a`, `A`)：** 调用 `strtof`, `strtod`, 或 `strtold` 将读取的字符串转换为浮点数类型。
     - **字符串转换 (`s`)：** 读取非空白字符序列，直到遇到空白字符或达到字段宽度限制。可以配合 `%m` 进行动态内存分配。
     - **字符转换 (`c`)：** 读取指定数量的字符（默认为 1），即使是空白字符。可以配合 `%m` 进行动态内存分配。
     - **字符集合转换 (`[`)：** 读取符合指定字符集合的字符序列。
     - **指针转换 (`p`)：**  类似于十六进制整数转换。
     - **已读取字符数 (`n`)：** 将当前已读取的字符数存储到指定的变量中。
   - **抑制赋值处理：** 如果设置了 `*` 标志，则读取输入但不会将其赋值给任何变量。
   - **动态内存分配处理 (`m` 标志)：** 如果设置了 `m` 标志，则使用 `malloc` 分配内存来存储读取的字符串或字符，并将分配的内存地址存储到相应的指针变量中。

6. **错误处理：**
   - **输入失败 (`input_failure`)：**  当尝试从文件流读取数据但失败时（例如，到达文件末尾）。
   - **匹配失败 (`match_failure`)：**  当输入的数据与格式字符串不匹配时。
   - **分配失败 (`allocation_failure`)：**  当动态内存分配失败时。

7. **`__sccl` 函数：**
   - `__sccl` 是一个辅助函数，用于解析字符集合转换说明符 (`%[...]`)。
   - 它接收一个字符表 `tab` 和格式字符串中 `[` 之后的部分。
   - 它会根据 `[` 和 `]` 之间的字符定义一个字符集合，并将字符表中对应字符的条目标记为 1。
   - 支持反义字符集合（以 `^` 开头）。
   - 支持字符范围（例如 `a-z`）。

**涉及 dynamic linker 的功能**

在这个 `vfscanf.cpp` 文件中，**没有直接涉及 dynamic linker 的代码**。`vfscanf` 是一个标准的 C 库函数，它的实现不依赖于动态链接器的特定功能。

然而，从更高的层面来看，`vfscanf` 所在的 `libc.so` 本身是由 dynamic linker 加载到进程的内存空间中的。

**SO 布局样本：**

当一个 Android 应用或进程启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载其依赖的共享库，包括 `libc.so`。一个简单的内存布局可能如下所示：

```
Memory Address Space:

[Stack]                                     <-- 栈区
...
[Mapped Libraries]
    /system/lib64/libc.so
        .text (代码段):         0x7800000000
            ... (vfscanf 等函数的代码) ...
        .rodata (只读数据段):   0x7800001000
            ... (字符串常量等) ...
        .data (已初始化数据段): 0x7800002000
            ... (全局变量等) ...
        .bss (未初始化数据段):  0x7800003000
            ...
    /system/lib64/libm.so
    /system/lib64/lib Other Libraries.so
...
[Heap]                                      <-- 堆区
...
[Executable Code]                             <-- 可执行代码
```

**链接的处理过程：**

1. **加载：** Dynamic linker 首先加载可执行文件，并解析其头部信息，找到所需的共享库列表（例如，`libc.so`）。
2. **查找：**  Dynamic linker 在预定义的路径中搜索这些共享库。
3. **加载和映射：**  将找到的共享库加载到进程的内存空间中，并将其代码段、数据段等映射到相应的内存区域。
4. **符号解析（重定位）：**
   - 当 `vfscanf` 这样的函数被调用时，实际执行的是 `libc.so` 中该函数的代码。
   - 如果 `vfscanf` 内部调用了 `libc.so` 或其他共享库中的其他函数（尽管在这个文件中没有明显的例子），dynamic linker 需要解析这些符号的地址，确保函数调用能够正确跳转到目标地址。这个过程称为重定位。
   - 例如，`vfscanf` 可能会调用 `malloc` 进行内存分配，`malloc` 的实现也在 `libc.so` 中。dynamic linker 确保 `vfscanf` 中对 `malloc` 的调用指向 `libc.so` 中 `malloc` 函数的正确地址。

**假设输入与输出**

假设我们有以下代码片段：

```c
#include <stdio.h>

int main() {
  char input[] = "123 abc 4.56";
  int num;
  char str[10];
  float f;

  int assigned = sscanf(input, "%d %s %f", &num, str, &f);

  printf("Assigned: %d\n", assigned);
  printf("num: %d\n", num);
  printf("str: %s\n", str);
  printf("f: %f\n", f);

  return 0;
}
```

**输入：**
`input` 字符串为 "123 abc 4.56"

**输出：**

```
Assigned: 3
num: 123
str: abc
f: 4.560000
```

**逻辑推理：**

1. `sscanf` 调用 `vfscanf`，传入格式字符串 `"%d %s %f"` 和输入字符串 `input`。
2. `"%d"`：`vfscanf` 从 `input` 中读取 "123"，将其转换为整数 123，并赋值给 `num`。
3. `" "`：`vfscanf` 跳过空白字符。
4. `"%s"`：`vfscanf` 读取 "abc"，直到遇到下一个空白字符，并将其存储到 `str` 数组中。
5. `" "`：`vfscanf` 跳过空白字符。
6. `"%f"`：`vfscanf` 读取 "4.56"，将其转换为浮点数 4.56，并赋值给 `f`。
7. `assigned` 的值为 3，表示成功赋值了 3 个字段。

**用户或编程常见的使用错误**

1. **类型不匹配：** 格式字符串中的转换说明符与要存储的变量类型不匹配。
   ```c
   int num;
   sscanf("abc", "%d", &num); // 错误：尝试将字符串 "abc" 解析为整数
   ```
   **后果：** 未定义的行为，可能导致程序崩溃或产生意想不到的结果。

2. **缓冲区溢出：** 使用 `%s` 读取字符串时，如果输入的字符串长度超过缓冲区大小，可能导致缓冲区溢出。
   ```c
   char str[3];
   sscanf("longstring", "%s", str); // 错误：输入字符串 "longstring" 超过 str 的大小
   ```
   **后果：** 覆盖栈上的其他数据，可能导致程序崩溃或安全漏洞。应该使用字段宽度限制，例如 `"%2s"`。

3. **忘记取地址符 `&`：**  在将解析后的值存储到变量时，忘记使用 `&` 运算符获取变量的地址。
   ```c
   int num;
   sscanf("123", "%d", num); // 错误：应该使用 &num
   ```
   **后果：** 尝试将值写入到错误的内存地址，通常会导致程序崩溃。

4. **格式字符串错误：** 格式字符串中的语法错误，例如缺少 `%` 或使用未知的转换说明符。
   ```c
   int num;
   sscanf("123", "d", &num); // 错误：缺少 %
   ```
   **后果：** `vfscanf` 可能无法正确解析格式字符串，导致匹配失败或未定义的行为。

5. **期望的输入格式不正确：** 输入的数据格式与格式字符串期望的格式不符。
   ```c
   int num;
   sscanf("abc", "%d", &num); // 错误：输入不是一个数字
   ```
   **后果：** `vfscanf` 可能返回较少的赋值字段数，表示匹配失败。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework/Application 调用 API：**  例如，一个 Java 应用可能通过 JNI 调用 NDK 中的 C/C++ 代码。
2. **NDK 代码调用 C 标准库函数：**  NDK 代码中可能会调用 `scanf`, `fscanf`, `sscanf` 等函数。
3. **Bionic libc 函数被调用：**  这些标准库函数会路由到 Android Bionic libc 中的相应实现，例如 `sscanf` 会调用 `vfscanf`。
4. **`vfscanf` 执行：**  `vfscanf` 根据提供的格式字符串和输入流执行解析和转换操作。

**Frida Hook 示例**

可以使用 Frida 来 hook `__svfscanf` 函数，以观察其行为和参数。

```python
import frida
import sys

# 连接到设备上的进程
process_name = "com.example.myapp"  # 替换为你的应用进程名
try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{process_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__svfscanf"), {
  onEnter: function(args) {
    console.log("[__svfscanf] Entered");
    console.log("  fp:", args[0]);
    console.log("  fmt:", Memory.readUtf8String(args[1]));
    // 可以根据需要打印 va_list 中的参数，但这比较复杂
  },
  onLeave: function(retval) {
    console.log("[__svfscanf] Left");
    console.log("  Return value:", retval);
  }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**Frida Hook 调试步骤：**

1. **安装 Frida 和 Python 环境。**
2. **找到目标 Android 应用的进程名。**
3. **将上述 Python 脚本保存到一个文件（例如 `hook_vfscanf.py`）。**
4. **将 Android 设备连接到电脑，并确保 adb 可用。**
5. **运行目标 Android 应用。**
6. **在电脑上运行 Frida 脚本：`python hook_vfscanf.py`**
7. **在 Android 应用中触发会调用 `scanf` 或相关函数的代码路径。**
8. **查看 Frida 的输出，它会打印出 `__svfscanf` 函数被调用时的参数（文件指针 `fp`，格式字符串 `fmt`）以及返回值。**

**更复杂的 Hook 场景：**

* **解析 `va_list`：**  要查看传递给 `vfscanf` 的实际变量地址和值，需要更复杂的操作来解析 `va_list`，这通常涉及到架构相关的 ABI 知识。
* **修改参数或返回值：**  Frida 也可以用于修改函数的参数或返回值，以进行更深入的调试或测试。

希望这个详细的解答能够帮助你理解 `bionic/libc/stdio/vfscanf.cpp` 文件的功能和实现！

### 提示词
```
这是目录为bionic/libc/stdio/vfscanf.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: vfscanf.c,v 1.31 2014/03/19 05:17:01 guenther Exp $ */
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

#include "scanf_common.h"

static const unsigned char* __sccl(char*, const unsigned char*);

/*
 * Internal, unlocked version of vfscanf
 */
int __svfscanf(FILE* fp, const char* fmt0, va_list ap) {
  const unsigned char* fmt = reinterpret_cast<const unsigned char*>(fmt0);
  int c;            /* character from format, or conversion */
  size_t width;     /* field width, or 0 */
  char* p;
  wchar_t* wcp;
  size_t n;
  int flags;        /* flags as defined above */
  int nassigned;    /* number of fields assigned */
  int nread;        /* number of characters consumed from fp */
  int base;         /* base argument to strtoimax/strtouimax */
  char ccltab[256]; /* character class table for %[...] */
  char buf[BUF];    /* buffer for numeric conversions */
  size_t nconv;     /* length of multibyte sequence converted */
  mbstate_t mbs;
  void* allocation = nullptr; // Allocated but unassigned result for %mc/%ms/%m[.
  size_t capacity = 0; // Number of char/wchar_t units allocated in `allocation`.

  _SET_ORIENTATION(fp, ORIENT_BYTES);

  nassigned = 0;
  nread = 0;
  for (;;) {
    c = *fmt++;
    if (c == 0) return nassigned;
    if (isspace(c)) {
      while ((fp->_r > 0 || __srefill(fp) == 0) && isspace(*fp->_p)) nread++, fp->_r--, fp->_p++;
      continue;
    }
    if (c != '%') goto literal;
    width = 0;
    flags = 0;
    /*
     * switch on the format.  continue if done;
     * break once format type is derived.
     */
again:
    c = *fmt++;
reswitch:
    switch (c) {
      case '%':
literal:
        if (fp->_r <= 0 && __srefill(fp)) goto input_failure;
        if (*fp->_p != c) goto match_failure;
        fp->_r--, fp->_p++;
        nread++;
        continue;

      case '*':
        flags |= SUPPRESS;
        goto again;
      case 'j':
        flags |= MAXINT;
        goto again;
      case 'L':
        flags |= LONGDBL;
        goto again;
      case 'h':
        if (*fmt == 'h') {
          fmt++;
          flags |= SHORTSHORT;
        } else {
          flags |= SHORT;
        }
        goto again;
      case 'l':
        if (*fmt == 'l') {
          fmt++;
          flags |= LLONG;
        } else {
          flags |= LONG;
        }
        goto again;
      case 'm':
        flags |= ALLOCATE;
        goto again;
      case 'q':
        flags |= LLONG; /* deprecated */
        goto again;
      case 't':
        flags |= PTRINT;
        goto again;
      case 'z':
        flags |= SIZEINT;
        goto again;

      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        width = width * 10 + c - '0';
        goto again;

      /*
       * Conversions.
       * Those marked `compat' are for 4.[123]BSD compatibility.
       */
      case 'b':
        c = CT_INT;
        base = 2;
        flags |= PFBOK; /* enable 0b prefixing */
        break;

      case 'D': /* compat */
        flags |= LONG;
        __BIONIC_FALLTHROUGH;
      case 'd':
        c = CT_INT;
        base = 10;
        break;

      case 'i':
        c = CT_INT;
        base = 0;
        break;

      case 'O': /* compat */
        flags |= LONG;
        __BIONIC_FALLTHROUGH;
      case 'o':
        c = CT_INT;
        flags |= UNSIGNED;
        base = 8;
        break;

      case 'u':
        c = CT_INT;
        flags |= UNSIGNED;
        base = 10;
        break;

      case 'w': {
        int size = 0;
        bool fast = false;
        c = *fmt++;
        if (c == 'f') {
          fast = true;
          c = *fmt++;
        }
        while (is_digit(c)) {
          APPEND_DIGIT(size, c);
          c = *fmt++;
        }
        flags |= w_to_flag(size, fast);
        goto reswitch;
      }

      case 'X':
      case 'x':
        flags |= PFXOK; /* enable 0x prefixing */
        c = CT_INT;
        flags |= UNSIGNED;
        base = 16;
        break;

      case 'e':
      case 'E':
      case 'f':
      case 'F':
      case 'g':
      case 'G':
      case 'a':
      case 'A':
        c = CT_FLOAT;
        break;

      case 's':
        memset(ccltab, 1, 256);
        ccltab['\t'] = ccltab['\n'] = ccltab['\v'] = ccltab['\f'] = ccltab['\r'] = ccltab[' '] = 0;
        c = CT_STRING;
        break;

      case '[':
        fmt = __sccl(ccltab, fmt);
        flags |= NOSKIP;
        c = CT_CCL;
        break;

      case 'c':
        flags |= NOSKIP;
        c = CT_CHAR;
        break;

      case 'p': /* pointer format is like hex */
        flags |= POINTER | PFXOK;
        c = CT_INT;
        flags |= UNSIGNED;
        base = 16;
        break;

      case 'n':
        if (flags & SUPPRESS) continue;
        if (flags & SHORTSHORT) {
          *va_arg(ap, signed char*) = nread;
        } else if (flags & SHORT) {
          *va_arg(ap, short*) = nread;
        } else if (flags & LONG) {
          *va_arg(ap, long*) = nread;
        } else if (flags & SIZEINT) {
          *va_arg(ap, ssize_t*) = nread;
        } else if (flags & PTRINT) {
          *va_arg(ap, ptrdiff_t*) = nread;
        } else if (flags & LLONG) {
          *va_arg(ap, long long*) = nread;
        } else if (flags & MAXINT) {
          *va_arg(ap, intmax_t*) = nread;
        } else {
          *va_arg(ap, int*) = nread;
        }
        continue;

      /*
       * Disgusting backwards compatibility hacks.	XXX
       */
      case '\0': /* compat */
        return EOF;

      default: /* compat */
        if (isupper(c)) flags |= LONG;
        c = CT_INT;
        base = 10;
        break;
    }

    if ((flags & ALLOCATE) != 0 && c > CT_STRING) {
      __fortify_fatal("scanf 'm' only works with %%c/%%s/%%[");
    }
    if ((flags & (ALLOCATE|SUPPRESS)) == (ALLOCATE|SUPPRESS)) {
      __fortify_fatal("scanf 'm' makes no sense with '*'");
    }

    /*
     * We have a conversion that requires input.
     */
    if (fp->_r <= 0 && __srefill(fp)) goto input_failure;

    /*
     * Consume leading white space, except for formats
     * that suppress this.
     */
    if ((flags & NOSKIP) == 0) {
      while (isspace(*fp->_p)) {
        nread++;
        if (--fp->_r > 0) {
          fp->_p++;
        } else if (__srefill(fp)) {
          goto input_failure;
        }
      }
      /*
       * Note that there is at least one character in
       * the buffer, so conversions that do not set NOSKIP
       * ca no longer result in an input failure.
       */
    }

    /*
     * Do the conversion.
     */
    switch (c) {
      case CT_CHAR:
        /* scan arbitrary characters (sets NOSKIP) */
        if (width == 0) width = 1;
        if (flags & LONG) {
          if (flags & ALLOCATE) {
            allocation = wcp = reinterpret_cast<wchar_t*>(malloc(width * sizeof(wchar_t)));
            if (allocation == nullptr) goto allocation_failure;
          } else if (flags & SUPPRESS) {
            wcp = nullptr;
          } else {
            wcp = va_arg(ap, wchar_t*);
          }
          size_t bytes = 0;
          while (width != 0) {
            if (bytes == MB_CUR_MAX) {
              fp->_flags |= __SERR;
              goto input_failure;
            }
            buf[bytes++] = *fp->_p;
            fp->_p++;
            fp->_r--;
            memset(&mbs, 0, sizeof(mbs));
            nconv = mbrtowc(wcp, buf, bytes, &mbs);
            if (nconv == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
              fp->_flags |= __SERR;
              goto input_failure;
            }
            if (nconv == 0 && !(flags & SUPPRESS)) *wcp = L'\0';
            if (nconv != BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
              nread += bytes;
              width--;
              if (!(flags & SUPPRESS)) wcp++;
              bytes = 0;
            }
            if (fp->_r <= 0 && __srefill(fp)) {
              if (bytes != 0) {
                fp->_flags |= __SERR;
                goto input_failure;
              }
              break;
            }
          }
          if (allocation != nullptr) {
            *va_arg(ap, wchar_t**) = reinterpret_cast<wchar_t*>(allocation);
            allocation = nullptr;
          }
          if (!(flags & SUPPRESS)) nassigned++;
        } else if (flags & SUPPRESS) {
          size_t sum = 0;
          for (;;) {
            if ((n = fp->_r) < width) {
              sum += n;
              width -= n;
              fp->_p += n;
              if (__srefill(fp)) {
                if (sum == 0) goto input_failure;
                break;
              }
            } else {
              sum += width;
              fp->_r -= width;
              fp->_p += width;
              break;
            }
          }
          nread += sum;
        } else {
          if (flags & ALLOCATE) {
            allocation = p = reinterpret_cast<char*>(malloc(width));
            if (allocation == nullptr) goto allocation_failure;
          } else {
            p = va_arg(ap, char*);
          }
          size_t r = fread(p, 1, width, fp);
          if (r == 0) goto input_failure;
          if (allocation != nullptr) {
            *va_arg(ap, char**) = reinterpret_cast<char*>(allocation);
            allocation = nullptr;
          }
          nread += r;
          nassigned++;
        }
        break;

      case CT_CCL:
      case CT_STRING:
        // CT_CCL: scan a (nonempty) character class (sets NOSKIP).
        // CT_STRING: like CCL, but zero-length string OK, & no NOSKIP.
        if (width == 0) width = SIZE_MAX;
        if (flags & LONG) {
          // TODO: since no-one cares, replace this with a simple fgetwc loop?
          n = 0;
          if (flags & ALLOCATE) {
            capacity = MIN(width, 32);
            allocation = wcp = reinterpret_cast<wchar_t*>(malloc(sizeof(wchar_t) * capacity));
            if (allocation == nullptr) goto allocation_failure;
          } else if (flags & SUPPRESS) {
            wcp = nullptr;
          } else {
            wcp = va_arg(ap, wchar_t*);
          }
          size_t bytes = 0;
          while ((c == CT_CCL || !isspace(*fp->_p)) && width != 0) {
            if (bytes == MB_CUR_MAX) {
              fp->_flags |= __SERR;
              goto input_failure;
            }
            buf[bytes++] = *fp->_p;
            fp->_p++;
            fp->_r--;
            wchar_t wc = L'\0';
            memset(&mbs, 0, sizeof(mbs));
            nconv = mbrtowc(&wc, buf, bytes, &mbs);
            if (nconv == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
              fp->_flags |= __SERR;
              goto input_failure;
            }
            if (nconv != BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
              if ((c == CT_CCL && wctob(wc) != EOF && !ccltab[wctob(wc)]) || (c == CT_STRING && iswspace(wc))) {
                while (bytes != 0) {
                  bytes--;
                  ungetc(buf[bytes], fp);
                }
                break;
              }
              if (wcp) wcp[n] = wc;
              n++;
              if (allocation != nullptr && n == capacity) {
                capacity *= 2;
                wchar_t* new_allocation =
                    reinterpret_cast<wchar_t*>(realloc(allocation, sizeof(wchar_t) * capacity));
                if (new_allocation == nullptr) goto allocation_failure;
                allocation = wcp = new_allocation;
              }
              nread += bytes;
              width--;
              bytes = 0;
            }
            if (fp->_r <= 0 && __srefill(fp)) {
              if (bytes != 0) {
                fp->_flags |= __SERR;
                goto input_failure;
              }
              break;
            }
          }
          if (c == CT_CCL && bytes != 0) {
            fp->_flags |= __SERR;
            goto input_failure;
          }
          if (allocation != nullptr) {
            *va_arg(ap, wchar_t**) = reinterpret_cast<wchar_t*>(allocation);
            allocation = nullptr;
          }
        } else if (flags & SUPPRESS) {
          n = 0;
          while (ccltab[*fp->_p]) {
            n++, fp->_r--, fp->_p++;
            if (--width == 0) break;
            if (fp->_r <= 0 && __srefill(fp)) {
              if (c == CT_CCL && n == 0) goto input_failure;
              break;
            }
          }
          nread += n;
        } else {
          if (flags & ALLOCATE) {
            capacity = MIN(width, 32);
            allocation = p = reinterpret_cast<char*>(malloc(capacity));
            if (allocation == nullptr) goto allocation_failure;
          } else {
            p = va_arg(ap, char*);
          }
          n = 0;
          while (ccltab[*fp->_p]) {
            fp->_r--;
            p[n++] = *fp->_p++;
            if (allocation != nullptr && n == capacity) {
              capacity *= 2;
              char* new_allocation = reinterpret_cast<char*>(realloc(allocation, capacity));
              if (new_allocation == nullptr) goto allocation_failure;
              allocation = p = new_allocation;
            }
            if (--width == 0) break;
            if (fp->_r <= 0 && __srefill(fp)) {
              if (c == CT_CCL && n == 0) goto input_failure;
              break;
            }
          }
          nread += n;
          if (allocation != nullptr) {
            *va_arg(ap, char**) = reinterpret_cast<char*>(allocation);
            allocation = nullptr;
          }
        }
        if (c == CT_CCL && n == 0) goto match_failure;
        if (!(flags & SUPPRESS)) {
          if (flags & LONG) {
            wcp[n] = L'\0';
          } else {
            p[n] = '\0';
          }
          ++nassigned;
        }
        break;

      case CT_INT:
        /* scan an integer as if by strtoimax/strtoumax */
#ifdef hardway
        if (width == 0 || width > sizeof(buf) - 1) width = sizeof(buf) - 1;
#else
        /* size_t is unsigned, hence this optimisation */
        if (--width > sizeof(buf) - 2) width = sizeof(buf) - 2;
        width++;
#endif
        flags |= SIGNOK | NDIGITS | NZDIGITS;
        for (p = buf; width; width--) {
          c = *fp->_p;
          /*
           * Switch on the character; `goto ok'
           * if we accept it as a part of number.
           */
          switch (c) {
            /*
             * The digit 0 is always legal, but is
             * special.  For %i conversions, if no
             * digits (zero or nonzero) have been
             * scanned (only signs), we will have
             * base==0.  In that case, we should set
             * it to 8 and enable 0b/0x prefixing.
             * Also, if we have not scanned zero digits
             * before this, do not turn off prefixing
             * (someone else will turn it off if we
             * have scanned any nonzero digits).
             */
            case '0':
              if (base == 0) {
                base = 8;
                flags |= PFBOK | PFXOK;
              }
              if (flags & NZDIGITS) {
                flags &= ~(SIGNOK | NZDIGITS | NDIGITS);
              } else {
                flags &= ~(SIGNOK | PFBOK | PFXOK | NDIGITS);
              }
              goto ok;
            case 'B':
            case 'b':
              // Is this 'b' or 'B' potentially part of an "0b" prefix?
              if ((flags & PFBOK) && p == buf + 1 + !!(flags & HAVESIGN)) {
                base = 2;
                flags &= ~PFBOK;
                goto ok;
              }
              // No? Fall through and see if it's a hex digit instead then...
              __BIONIC_FALLTHROUGH;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 'A':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
            case 'a':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
              if (base == 0) base = 10;
              if (base != 16 && (c - '0') >= base) break; /* not legal here */
              flags &= ~(SIGNOK | PFBOK | PFXOK | NDIGITS);
              goto ok;

            /* sign ok only as first character */
            case '+':
            case '-':
              if (flags & SIGNOK) {
                flags &= ~SIGNOK;
                flags |= HAVESIGN;
                goto ok;
              }
              break;

            /*
             * x ok iff flag still set and 2nd char (or
             * 3rd char if we have a sign).
             */
            case 'x':
            case 'X':
              if ((flags & PFXOK) && p == buf + 1 + !!(flags & HAVESIGN)) {
                base = 16; /* if %i */
                flags &= ~PFXOK;
                goto ok;
              }
              break;
          }

          /*
           * If we got here, c is not a legal character
           * for a number.  Stop accumulating digits.
           */
          break;
        ok:
          /*
           * c is legal: store it and look at the next.
           */
          *p++ = c;
          if (--fp->_r > 0)
            fp->_p++;
          else if (__srefill(fp))
            break; /* EOF */
        }
        /*
         * If we had only a sign, it is no good; push back the sign.
         * If the number was `[-+]0[BbXx]`, push back and treat it
         * as `[-+]0`.
         */
        if (flags & NDIGITS) {
          if (p > buf) ungetc(*reinterpret_cast<u_char*>(--p), fp);
          goto match_failure;
        }
        c = reinterpret_cast<u_char*>(p)[-1];
        if ((base == 2 && (c == 'b' || c == 'B')) || c == 'x' || c == 'X') {
          --p;
          (void)ungetc(c, fp);
        }
        if ((flags & SUPPRESS) == 0) {
          uintmax_t res;

          *p = '\0';
          if (flags & UNSIGNED) {
            res = strtoumax(buf, nullptr, base);
          } else {
            res = strtoimax(buf, nullptr, base);
          }
          if (flags & POINTER) {
            *va_arg(ap, void**) = reinterpret_cast<void*>(res);
          } else if (flags & MAXINT) {
            *va_arg(ap, intmax_t*) = res;
          } else if (flags & LLONG) {
            *va_arg(ap, long long*) = res;
          } else if (flags & SIZEINT) {
            *va_arg(ap, ssize_t*) = res;
          } else if (flags & PTRINT) {
            *va_arg(ap, ptrdiff_t*) = res;
          } else if (flags & LONG) {
            *va_arg(ap, long*) = res;
          } else if (flags & SHORT) {
            *va_arg(ap, short*) = res;
          } else if (flags & SHORTSHORT) {
            *va_arg(ap, signed char*) = res;
          } else {
            *va_arg(ap, int*) = res;
          }
          nassigned++;
        }
        nread += p - buf;
        break;

      case CT_FLOAT:
        /* scan a floating point number as if by strtod */
        if (width == 0 || width > sizeof(buf) - 1) width = sizeof(buf) - 1;
        if ((width = parsefloat(fp, buf, buf + width)) == 0) goto match_failure;
        if ((flags & SUPPRESS) == 0) {
          if (flags & LONGDBL) {
            long double res = strtold(buf, &p);
            *va_arg(ap, long double*) = res;
          } else if (flags & LONG) {
            double res = strtod(buf, &p);
            *va_arg(ap, double*) = res;
          } else {
            float res = strtof(buf, &p);
            *va_arg(ap, float*) = res;
          }
          if (static_cast<size_t>(p - buf) != width) abort();
          nassigned++;
        }
        nread += width;
        break;
    }
  }
allocation_failure:
input_failure:
  free(allocation);
  if (nassigned == 0) nassigned = -1;
match_failure:
  return nassigned;
}

/*
 * Fill in the given table from the scanset at the given format
 * (just after `[').  Return a pointer to the character past the
 * closing `]'.  The table has a 1 wherever characters should be
 * considered part of the scanset.
 */
static const unsigned char* __sccl(char* tab, const unsigned char* fmt) {
  int c, n, v;

  /* first `clear' the whole table */
  c = *fmt++; /* first char hat => negated scanset */
  if (c == '^') {
    v = 1;      /* default => accept */
    c = *fmt++; /* get new first char */
  } else {
    v = 0; /* default => reject */
  }
  memset(tab, v, 256);
  if (c == 0) return (fmt - 1); /* format ended before closing ] */

  /*
   * Now set the entries corresponding to the actual scanset
   * to the opposite of the above.
   *
   * The first character may be ']' (or '-') without being special;
   * the last character may be '-'.
   */
  v = 1 - v;
  for (;;) {
    tab[c] = v; /* take character c */
  doswitch:
    n = *fmt++; /* and examine the next */
    switch (n) {
      case 0: /* format ended too soon */
        return (fmt - 1);

      case '-':
        /*
         * A scanset of the form
         *	[01+-]
         * is defined as `the digit 0, the digit 1,
         * the character +, the character -', but
         * the effect of a scanset such as
         *	[a-zA-Z0-9]
         * is implementation defined.  The V7 Unix
         * scanf treats `a-z' as `the letters a through
         * z', but treats `a-a' as `the letter a, the
         * character -, and the letter a'.
         *
         * For compatibility, the `-' is not considerd
         * to define a range if the character following
         * it is either a close bracket (required by ANSI)
         * or is not numerically greater than the character
         * we just stored in the table (c).
         */
        n = *fmt;
        if (n == ']' || n < c) {
          c = '-';
          break; /* resume the for(;;) */
        }
        fmt++;
        do { /* fill in the range */
          tab[++c] = v;
        } while (c < n);
#if 1 /* XXX another disgusting compatibility hack */
        /*
         * Alas, the V7 Unix scanf also treats formats
         * such as [a-c-e] as `the letters a through e'.
         * This too is permitted by the standard....
         */
        goto doswitch;
#else
        c = *fmt++;
        if (c == 0) return (fmt - 1);
        if (c == ']') return (fmt);
#endif
        break;

      case ']': /* end of scanset */
        return fmt;

      default: /* just another character */
        c = n;
        break;
    }
  }
  /* NOTREACHED */
}
```
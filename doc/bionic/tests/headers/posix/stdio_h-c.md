Response:
Let's break down the thought process for answering the user's request about the `stdio_h.c` test file.

**1. Understanding the Request:**

The user provided a C source file (`stdio_h.c`) which is a test file for the `stdio.h` header in Android's Bionic library. They want to know:

* **Functionality of the file:** What does this specific test file do?
* **Relationship to Android:** How does this relate to the overall Android system?
* **Detailed explanation of libc functions:**  How do the `stdio` functions work internally?
* **Dynamic linker involvement:** If any functions rely on the dynamic linker, how does that work?
* **Logic and examples:** Provide examples of usage, inputs, and outputs.
* **Common errors:** What mistakes do developers often make when using these functions?
* **Android framework/NDK path:** How does code execution reach these `stdio` functions?
* **Frida hook examples:** Demonstrate how to use Frida to observe these functions.

This is a multi-faceted question requiring knowledge of C standard library, Android internals, and dynamic linking.

**2. Initial Analysis of the Code:**

The provided `stdio_h.c` file is clearly *not* the implementation of `stdio.h`. It's a *test* file. The structure is evident:

* **Includes:** `stdio.h` and a local `header_checks.h`. This suggests it's verifying the existence and type signatures of elements declared in `stdio.h`.
* **`stdio_h()` function:** This is the core of the test.
* **`TYPE()` macro:**  Checks for the existence of type definitions (e.g., `FILE*`, `size_t`).
* **`MACRO()` macro:** Checks for the existence of macro definitions (e.g., `BUFSIZ`, `EOF`).
* **Direct variable access:** Checks for the existence of global variables (e.g., `P_tmpdir`, `stderr`, `stdin`, `stdout`).
* **`FUNCTION()` macro:**  Checks the existence and function signature of `stdio` functions.

**3. Formulating the Core Functionality Answer:**

Based on the above analysis, the primary function of `stdio_h.c` is to **verify the correctness and completeness of the `stdio.h` header file** in the Android Bionic library. It's a static check to ensure the header exposes the expected types, macros, and functions with the correct signatures.

**4. Connecting to Android:**

The connection is direct. Bionic is Android's C library. `stdio.h` is a fundamental part of any C standard library. This test ensures the Bionic implementation of `stdio.h` is correct, which is crucial for all Android apps and system components written in C/C++.

**5. Addressing Libc Function Implementation (The Tricky Part):**

The test file *doesn't* implement the `stdio` functions. The request asks for details about *how they are implemented*. This requires separate knowledge of how standard C libraries work. The strategy here is to:

* **Acknowledge that the test file doesn't contain the implementations.**
* **Provide a general overview of how `stdio` functions typically work:** System calls, buffering, file descriptors, etc.
* **Give specific examples for a few key functions (like `fopen`, `fread`, `printf`)** to illustrate the underlying concepts. Avoid getting *too* deep into the kernel details, focusing on the libc level.

**6. Dynamic Linker Aspects:**

`stdio` functions are part of `libc.so`, a shared library. The explanation should cover:

* **Shared object (SO) layout:**  A simplified representation of how `libc.so` is structured.
* **Linking process:** How the dynamic linker resolves symbols (function names) at runtime, connecting calls from application code to the implementations in `libc.so`. Mentioning PLT and GOT is important here.

**7. Logic, Assumptions, and Examples:**

Since the test file is primarily for verification, the "logic" is its check for the existence of symbols. The "input" is the compilation of this test file. The "output" is either success (if all checks pass) or compiler errors (if a check fails).

For user-level functions like `fopen`, `printf`, provide simple code snippets demonstrating their usage and expected output.

**8. Common Errors:**

Think about the common pitfalls when using `stdio` functions: forgetting to close files, buffer overflows with `fgets`, using `gets` (which is now deprecated), incorrect format specifiers in `printf`/`scanf`, etc.

**9. Android Framework/NDK Path:**

Explain how an Android app (Java/Kotlin) makes its way to using `stdio` functions:

* **NDK:** Native code directly uses `stdio.h`.
* **Android Framework:**  The framework itself, often written in Java/Kotlin, may call native code that uses `stdio`. Also, underlying system services (written in C++) will heavily rely on `libc`.

**10. Frida Hook Examples:**

Provide concrete Frida scripts to intercept calls to functions like `fopen` and `printf`. This involves:

* Knowing how to use `Interceptor.attach()`.
* Understanding how to access arguments and return values.

**11. Structuring the Answer:**

Organize the information logically, using headings and bullet points to improve readability. Address each part of the user's request systematically.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps try to explain the *implementation* details of *every* `stdio` function. **Correction:** This would be too extensive. Focus on the *purpose* of the test file and give general implementation overviews with key examples.
* **Initial thought:** Provide very low-level details about dynamic linking. **Correction:**  Keep the explanation at a high-level, focusing on the core concepts of symbol resolution and the role of the dynamic linker.
* **Ensure the language is clear and accessible:** Avoid overly technical jargon where possible, or explain it when necessary.

By following this structured thought process, we can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
好的，让我们来详细分析一下 `bionic/tests/headers/posix/stdio_h.c` 这个测试文件。

**文件功能：**

这个 `stdio_h.c` 文件的主要功能是**测试 Android Bionic 库中 `stdio.h` 头文件的正确性和完整性**。  它并不实现 `stdio.h` 中声明的任何函数，而是通过编译时的检查来验证以下内容：

1. **类型定义 (TYPE宏):** 验证 `stdio.h` 中定义了预期的类型，例如 `FILE*`, `fpos_t`, `size_t` 等。如果缺少某个类型定义，编译将会失败。
2. **宏定义 (MACRO宏):** 验证 `stdio.h` 中定义了预期的宏，例如 `BUFSIZ`, `EOF`, `SEEK_SET` 等。如果缺少某个宏定义，编译将会失败。
3. **全局变量:** 验证 `stdio.h` 中声明的全局变量 (通常是指向标准流的变量)，例如 `stderr`, `stdin`, `stdout` 的存在。
4. **函数声明 (FUNCTION宏):** 验证 `stdio.h` 中声明了预期的函数，并检查其函数签名（参数类型和返回类型）是否正确。如果函数声明缺失或者签名不匹配，编译将会失败。

**与 Android 功能的关系及举例：**

`stdio.h` 是 C 标准库中的核心头文件，提供了进行输入/输出操作的函数和类型。由于 Android 系统底层大量使用 C/C++ 编写，Bionic 作为 Android 的 C 库，`stdio.h` 的正确性至关重要。

* **应用程序开发 (NDK):** 使用 Android NDK 进行原生 C/C++ 开发时，开发者会直接包含 `<stdio.h>` 头文件，并使用其中的函数进行文件操作、格式化输出等。例如，使用 `fopen()` 打开文件，使用 `fprintf()` 向文件写入格式化数据，使用 `printf()` 在终端输出信息。如果 `stdio.h` 定义不正确，会导致编译错误或者运行时行为异常。
* **Android Framework:** Android Framework 的许多底层组件和服务也是用 C/C++ 编写的，它们也会使用 `stdio.h` 中的函数进行日志记录、配置文件读取等操作。例如，`logd` 服务可能会使用 `fprintf()` 将日志信息写入到特定的文件。
* **系统工具:** 许多 Android 系统自带的命令行工具 (如 `adb`, `logcat`) 也是用 C/C++ 编写的，它们依赖 `stdio.h` 进行输入输出。

**示例：**

假设 `stdio.h` 中错误地将 `fopen()` 函数的返回值类型定义为 `int` 而不是 `FILE*`，那么在编译 `stdio_h.c` 时，`FUNCTION(fopen, FILE* (*f)(const char*, const char*));` 这一行就会导致编译错误，因为它期望 `fopen` 返回 `FILE*`。

**每一个 libc 函数的功能是如何实现的：**

`stdio_h.c` 文件本身**不包含**任何 libc 函数的实现。它只是一个测试文件，用来验证 `stdio.h` 中声明的接口是否正确。

`stdio.h` 中声明的函数的实际实现位于 Bionic 库的源代码中，通常在 `bionic/libc/stdio` 目录下的一些 `.c` 文件中。

**以下是一些常见 `stdio.h` 函数的实现原理简述：**

* **`fopen(const char *pathname, const char *mode)`:**
    * **功能:** 打开一个文件。
    * **实现:** 调用底层的 `open()` 系统调用，并根据 `mode` 参数设置打开文件的标志（如读、写、追加等）。如果打开成功，会分配一个 `FILE` 结构体，用于维护文件的状态信息（如文件描述符、缓冲区等），并返回指向该结构体的指针；如果打开失败，返回 `NULL`。
* **`fread(void *ptr, size_t size, size_t nmemb, FILE *stream)`:**
    * **功能:** 从指定的文件流读取数据块。
    * **实现:** 首先检查文件流的缓冲区中是否有足够的数据。如果有，直接从缓冲区读取。如果缓冲区数据不足，会调用底层的 `read()` 系统调用从文件中读取更多数据到缓冲区。然后将缓冲区中的数据复制到 `ptr` 指向的内存区域。
* **`fprintf(FILE *stream, const char *format, ...)`:**
    * **功能:** 向指定的文件流写入格式化的数据。
    * **实现:**  解析 `format` 字符串中的格式说明符（如 `%d`, `%s`），并将后面的可变参数按照指定的格式进行转换，然后将格式化后的字符串写入到文件流的缓冲区中。如果缓冲区已满，会将缓冲区的内容刷新（写入到底层文件）后再写入新的数据。最终可能会调用底层的 `write()` 系统调用。
* **`printf(const char *format, ...)`:**
    * **功能:** 向标准输出流 (stdout) 写入格式化的数据。
    * **实现:** 实际上是调用 `fprintf(stdout, format, ...)`。
* **`fclose(FILE *stream)`:**
    * **功能:** 关闭指定的文件流。
    * **实现:** 首先刷新文件流的缓冲区，将缓冲区中未写入的数据写入到底层文件。然后调用底层的 `close()` 系统调用关闭文件描述符，并释放分配给 `FILE` 结构体的内存。

**涉及 dynamic linker 的功能：**

`stdio.h` 中声明的函数都位于 `libc.so` 动态链接库中。当应用程序或系统组件调用这些函数时，需要动态链接器来找到这些函数的实际地址。

**so 布局样本 (简化)：**

```
libc.so:
    .text:  # 代码段
        fopen:  # fopen 函数的机器码
            ...
        fread:  # fread 函数的机器码
            ...
        printf: # printf 函数的机器码
            ...
        ...
    .rodata: # 只读数据段
        一些字符串常量，例如 printf 的格式化字符串部分
    .data:   # 可读写数据段
        一些全局变量，例如标准流的 FILE 结构体
    .got.plt: # 全局偏移量表和过程链接表
        条目指向动态链接器，用于解析外部函数地址
```

**链接的处理过程：**

1. **编译时:** 编译器在编译代码时，遇到对 `stdio` 函数的调用，会在生成的目标文件中生成一个对这些函数的未解析引用（符号）。
2. **链接时:** 静态链接器将目标文件链接成可执行文件或共享库时，会记录这些未解析的符号，并标记它们需要在运行时进行动态链接。
3. **加载时:** 当操作系统加载可执行文件或共享库时，动态链接器 (如 Android 的 `linker64` 或 `linker`) 会被激活。
4. **符号查找:** 当程序第一次调用 `stdio` 函数（例如 `printf`）时，动态链接器会查找 `libc.so` 中 `printf` 函数的地址。
5. **GOT/PLT:**  通常会使用全局偏移量表 (GOT) 和过程链接表 (PLT) 机制。第一次调用时，会通过 PLT 跳转到一个小的桩代码，该桩代码会调用动态链接器去填充 GOT 表中 `printf` 的实际地址。后续的调用会直接通过 GOT 表跳转到 `printf` 的实际地址，避免重复解析。

**假设输入与输出 (针对测试文件 `stdio_h.c`)：**

* **假设输入:** 编译 `bionic/tests/headers/posix/stdio_h.c` 文件。
* **预期输出:** 如果 `stdio.h` 的定义与测试文件中的期望一致，编译成功，不会有任何输出 (或者只有编译器的正常输出信息)。如果 `stdio.h` 的定义有误，例如缺少了某个宏或者函数声明的签名不匹配，编译器会报错，指出具体的错误信息。

**涉及用户或者编程常见的使用错误，请举例说明：**

* **忘记 `fclose()`:**  打开文件后忘记关闭，会导致资源泄漏，可能最终导致文件描述符耗尽。
   ```c
   #include <stdio.h>
   int main() {
       FILE *fp = fopen("myfile.txt", "w");
       if (fp == NULL) {
           perror("Error opening file");
           return 1;
       }
       fprintf(fp, "Hello, world!\n");
       // 忘记 fclose(fp);
       return 0;
   }
   ```
* **缓冲区溢出 (使用 `gets()`):** `gets()` 函数不进行边界检查，容易导致缓冲区溢出。
   ```c
   #include <stdio.h>
   int main() {
       char buffer[10];
       printf("Enter some text: ");
       gets(buffer); // 危险！如果输入超过 9 个字符，会导致缓冲区溢出
       printf("You entered: %s\n", buffer);
       return 0;
   }
   ```
   **注意:** `gets()` 在 C11 标准中已被移除，建议使用 `fgets()` 代替。
* **`scanf()` 格式字符串不匹配:**  如果 `scanf()` 的格式字符串与输入的类型不匹配，可能导致未定义的行为。
   ```c
   #include <stdio.h>
   int main() {
       int num;
       printf("Enter a number: ");
       scanf("%s", &num); // 错误！期望输入整数，但格式字符串是 %s (字符串)
       printf("You entered: %d\n", num);
       return 0;
   }
   ```
* **文件打开模式错误:** 使用不正确的模式打开文件可能导致读写操作失败。例如，尝试以只读模式打开一个不存在的文件进行写入。
* **`printf()` 格式字符串漏洞:** 如果 `printf()` 的格式字符串来源于用户输入，可能存在安全漏洞，攻击者可以利用格式字符串的特性读取或写入内存。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `stdio` 的路径：**

1. **Java/Kotlin 代码:** Android Framework 的上层通常由 Java 或 Kotlin 编写。
2. **JNI 调用:**  当 Framework 需要执行一些底层操作（例如文件 I/O），可能会通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。
3. **Native 代码:** 这些 Native 代码会链接到 Bionic 库，并调用 `stdio.h` 中声明的函数。

**Android NDK 到 `stdio` 的路径：**

1. **NDK 开发:**  开发者使用 NDK 编写 C/C++ 代码。
2. **包含头文件:**  在 C/C++ 代码中包含 `<stdio.h>` 头文件。
3. **调用 `stdio` 函数:**  直接调用 `stdio.h` 中声明的函数。
4. **链接到 `libc.so`:** 编译时，NDK 工具链会将代码链接到 `libc.so` 动态链接库。
5. **运行时动态链接:** 应用程序运行时，动态链接器会将对 `stdio` 函数的调用解析到 `libc.so` 中的实现。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `fopen()` 函数调用的示例：

```python
import frida
import sys

package_name = "your.package.name"  # 替换成你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        var mode = Memory.readUtf8String(args[1]);
        send("fopen called with filename: " + filename + ", mode: " + mode);
    },
    onLeave: function(retval) {
        send("fopen returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. **安装 Frida 和 Python 绑定:** 确保你的电脑上安装了 Frida 和 Python 的 Frida 绑定。
2. **连接设备:**  连接你的 Android 设备并通过 USB 启用调试模式。
3. **运行应用程序:** 启动你想要监控的 Android 应用程序。
4. **替换包名:** 将 `your.package.name` 替换成你想要监控的应用程序的包名。
5. **运行 Frida 脚本:** 运行上面的 Python 脚本。

**调试步骤：**

当你运行应用程序时，Frida 脚本会拦截对 `fopen()` 函数的调用，并打印出 `fopen()` 函数的参数 (文件名和打开模式) 以及返回值 (文件指针)。你可以通过修改 `script_code` 来 Hook 其他的 `stdio` 函数，例如 `printf`, `fread`, `fwrite` 等，从而观察应用程序的文件 I/O 操作。

**Hook `printf` 示例：**

```python
# ... (前面的代码不变)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "printf"), {
    onEnter: function(args) {
        var format = Memory.readUtf8String(args[0]);
        var arg1 = args.length > 1 ? args[1] : null;
        var arg2 = args.length > 2 ? args[2] : null;
        send("printf called with format: " + format + ", arg1: " + arg1 + ", arg2: " + arg2);
    },
    onLeave: function(retval) {
        send("printf returned: " + retval);
    }
});
"""

# ... (后面的代码不变)
```

这个 Hook 示例会拦截 `printf` 函数的调用，并打印出格式化字符串以及前两个参数。你可以根据需要扩展来处理更多参数。

希望以上详细的解释能够帮助你理解 `bionic/tests/headers/posix/stdio_h.c` 文件的功能以及 `stdio.h` 在 Android 系统中的作用和实现方式。

### 提示词
```
这是目录为bionic/tests/headers/posix/stdio_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>

#include "header_checks.h"

static void stdio_h() {
  TYPE(FILE*);
  TYPE(fpos_t);
  TYPE(off_t);
  TYPE(size_t);
  TYPE(ssize_t);
  TYPE(va_list);

  MACRO(BUFSIZ);
  MACRO(L_ctermid);
  MACRO(L_tmpnam);

  MACRO(_IOFBF);
  MACRO(_IOLBF);
  MACRO(_IONBF);

  MACRO(SEEK_CUR);
  MACRO(SEEK_END);
  MACRO(SEEK_SET);

  MACRO(FILENAME_MAX);
  MACRO(FOPEN_MAX);
  MACRO(TMP_MAX);

  MACRO(EOF);

  MACRO(NULL);

  const char* s;
  s = P_tmpdir;

#if !defined(stderr)
#error stderr
#endif
#if !defined(stdin)
#error stdin
#endif
#if !defined(stdout)
#error stdout
#endif
  FILE* fp;
  fp = stderr;
  fp = stdin;
  fp = stdout;

  FUNCTION(clearerr, void (*f)(FILE*));
  FUNCTION(ctermid, char* (*f)(char*));
  FUNCTION(dprintf, int (*f)(int, const char*, ...));
  FUNCTION(fclose, int (*f)(FILE*));
  FUNCTION(fdopen, FILE* (*f)(int, const char*));
  FUNCTION(feof, int (*f)(FILE*));
  FUNCTION(ferror, int (*f)(FILE*));
  FUNCTION(fflush, int (*f)(FILE*));
  FUNCTION(fgetc, int (*f)(FILE*));
  FUNCTION(fgetpos, int (*f)(FILE*, fpos_t*));
  FUNCTION(fgets, char* (*f)(char*, int, FILE*));
  FUNCTION(fileno, int (*f)(FILE*));
  FUNCTION(flockfile, void (*f)(FILE*));
  FUNCTION(fmemopen, FILE* (*f)(void*, size_t, const char*));
  FUNCTION(fopen, FILE* (*f)(const char*, const char*));
  FUNCTION(fprintf, int (*f)(FILE*, const char*, ...));
  FUNCTION(fputc, int (*f)(int, FILE*));
  FUNCTION(fputs, int (*f)(const char*, FILE*));
  FUNCTION(fread, size_t (*f)(void*, size_t, size_t, FILE*));
  FUNCTION(freopen, FILE* (*f)(const char*, const char*, FILE*));
  FUNCTION(fscanf, int (*f)(FILE*, const char*, ...));
  FUNCTION(fseek, int (*f)(FILE*, long, int));
  FUNCTION(fseeko, int (*f)(FILE*, off_t, int));
  FUNCTION(fsetpos, int (*f)(FILE*, const fpos_t*));
  FUNCTION(ftell, long (*f)(FILE*));
  FUNCTION(ftello, off_t (*f)(FILE*));
  FUNCTION(ftrylockfile, int (*f)(FILE*));
  FUNCTION(funlockfile, void (*f)(FILE*));
  FUNCTION(fwrite, size_t (*f)(const void*, size_t, size_t, FILE*));
  FUNCTION(getc, int (*f)(FILE*));
  FUNCTION(getchar, int (*f)(void));
  FUNCTION(getc_unlocked, int (*f)(FILE*));
  FUNCTION(getchar_unlocked, int (*f)(void));
  FUNCTION(getdelim, ssize_t (*f)(char**, size_t*, int, FILE*));
  FUNCTION(getline, ssize_t (*f)(char**, size_t*, FILE*));
  // gets() was removed in C11.
  // FUNCTION(gets, char* (*f)(char*));
  FUNCTION(open_memstream, FILE* (*f)(char**, size_t*));
  FUNCTION(pclose, int (*f)(FILE*));
  FUNCTION(perror, void (*f)(const char*));
  FUNCTION(popen, FILE* (*f)(const char*, const char*));
  FUNCTION(printf, int (*f)(const char*, ...));
  FUNCTION(putc, int (*f)(int, FILE*));
  FUNCTION(putchar, int (*f)(int));
  FUNCTION(putc_unlocked, int (*f)(int, FILE*));
  FUNCTION(putchar_unlocked, int (*f)(int));
  FUNCTION(puts, int (*f)(const char*));
  FUNCTION(remove, int (*f)(const char*));
  FUNCTION(rename, int (*f)(const char*, const char*));
  FUNCTION(renameat, int (*f)(int, const char*, int, const char*));
  FUNCTION(rewind, void (*f)(FILE*));
  FUNCTION(scanf, int (*f)(const char*, ...));
  FUNCTION(setbuf, void (*f)(FILE*, char*));
  FUNCTION(setvbuf, int (*f)(FILE*, char*, int, size_t));
  FUNCTION(snprintf, int (*f)(char*, size_t, const char*, ...));
  FUNCTION(sprintf, int (*f)(char*, const char*, ...));
  FUNCTION(sscanf, int (*f)(const char*, const char*, ...));
  FUNCTION(tempnam, char* (*f)(const char*, const char*));
  FUNCTION(tmpfile, FILE* (*f)(void));
  FUNCTION(tmpnam, char* (*f)(char*));
  FUNCTION(ungetc, int (*f)(int, FILE*));
  FUNCTION(vdprintf, int (*f)(int, const char*, va_list));
  FUNCTION(vfprintf, int (*f)(FILE*, const char*, va_list));
  FUNCTION(vfscanf, int (*f)(FILE*, const char*, va_list));
  FUNCTION(vprintf, int (*f)(const char*, va_list));
  FUNCTION(vscanf, int (*f)(const char*, va_list));
  FUNCTION(vsnprintf, int (*f)(char*, size_t, const char*, va_list));
  FUNCTION(vsprintf, int (*f)(char*, const char*, va_list));
  FUNCTION(vsscanf, int (*f)(const char*, const char*, va_list));
}
```
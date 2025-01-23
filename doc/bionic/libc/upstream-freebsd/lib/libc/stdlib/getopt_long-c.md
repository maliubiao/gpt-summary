Response:
Let's break down the thought process for analyzing this `getopt_long.c` file.

**1. Understanding the Core Functionality:**

The first step is to recognize the purpose of the code. The filename and the initial comments clearly state that it's an implementation of `getopt_long` and `getopt`, functions used for parsing command-line options. This immediately tells us the high-level functionality.

**2. Identifying Key Functions:**

Scanning through the code, I look for function definitions. The main players are:

* `getopt_long`:  The core function for parsing both short and long options.
* `getopt_long_only`:  A variant that only parses long options.
* `getopt`:  The traditional short-option parsing function (with a conditional `REPLACE_GETOPT`).
* `getopt_internal`:  The internal workhorse function shared by the others.
* `parse_long_options`:  Specifically handles the logic for parsing long options.
* `permute_args`:  Deals with rearranging arguments when non-options are encountered.
* `gcd`: A utility function (greatest common divisor), likely used in `permute_args`.

**3. Dissecting `getopt_internal` (The Central Logic):**

This is the heart of the implementation. I'd analyze its flow step-by-step:

* **Initialization and State:**  It manages `optind`, `optarg`, `opterr`, and the `place` pointer to track parsing progress. The `optreset` handling is important for repeated calls.
* **Non-Option Handling:** The code carefully handles arguments that are not options. The `FLAG_PERMUTE` option is crucial here, determining whether non-options are moved to the end.
* **Short Option Parsing:** The loop iterates through the current argument (`place`). It checks if the character is a valid short option (present in the `options` string). It handles required and optional arguments for short options.
* **Long Option Parsing:** If the current argument looks like a long option (`--` or `-` followed by more characters, or if `FLAG_LONGONLY` is set), it calls `parse_long_options`.
* **Error Handling:** The code checks for invalid options, missing arguments, and ambiguous long options, using `warnx` (which will likely use `fprintf` to `stderr`).
* **Return Values:** It returns the option character, `?` for errors, `:` if the options string starts with a colon and an argument is missing, and -1 when there are no more options.

**4. Analyzing `parse_long_options`:**

This function is dedicated to long option parsing:

* **Matching:** It iterates through the `long_options` array, comparing the current argument with the long option names. It handles exact and partial matches.
* **Argument Handling:**  It checks if the long option requires or allows an argument (based on `has_arg`) and extracts the argument if present (either with `=` or in the next argument).
* **Ambiguity Detection:**  It identifies ambiguous partial matches.
* **Flag Setting:** If the `flag` member of the `option` struct is not NULL, it sets the pointed-to variable.
* **Return Values:** It returns the `val` from the `option` struct or an error code.

**5. Understanding `permute_args` and `gcd`:**

`permute_args` is about rearranging the `argv` array. The `gcd` function suggests a cyclic permutation algorithm. I'd mentally trace how the blocks of arguments are swapped.

**6. Connecting to Android (bionic):**

The key here is that this code *is* part of Android's libc. Therefore:

* **Functionality:** It provides the standard command-line parsing for Android utilities and apps.
* **Dynamic Linking:** Any Android executable that uses `getopt` or `getopt_long` will link against `libc.so`. I would think about the structure of `libc.so` and how the linker resolves these symbols.

**7. Considering Usage and Errors:**

I'd think about common mistakes developers make when using `getopt`:

* Incorrectly defining the `options` string.
* Not checking the return value of `getopt`.
* Not handling required arguments correctly.
* Misunderstanding long option syntax.

**8. Tracing the Call Path (Android Framework/NDK):**

This requires understanding how command-line arguments are passed in Android:

* **Framework:**  When an Android app (written in Java/Kotlin) launches a native process (via `Runtime.exec()` or similar), the arguments are passed as strings. These strings become the `argv` for the native executable.
* **NDK:**  NDK developers directly write C/C++ code. When their native library/executable is run, the standard `main(int argc, char** argv)` receives the command-line arguments. They then call `getopt` or `getopt_long` to process them.

**9. Frida Hooking:**

To demonstrate how to intercept these calls, I'd think about what I want to observe:

* Input arguments (`argc`, `argv`, `options`, `long_options`).
* The return value.
* Changes to global variables like `optind`, `optarg`, `optopt`.

This leads to the Frida snippet that intercepts `getopt_long` and prints the relevant information.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `permute_args` is more complex. Realization: The `gcd` hints at an efficient way to handle the swaps.
* **Confusion about `REPLACE_GETOPT`:**  Understanding that in the Android context, this is unlikely to be defined, and the provided `getopt` is probably the one used.
* **Overthinking dynamic linking:**  Focusing on the core concept of symbol resolution rather than getting bogged down in linker implementation details (unless specifically asked).
* **Ensuring clarity in explanations:**  Using simpler language and avoiding overly technical jargon where possible.

By following these steps, systematically analyzing the code, and connecting it to the Android environment, I can construct a comprehensive and accurate answer to the prompt.
这个文件 `bionic/libc/upstream-freebsd/lib/libc/stdlib/getopt_long.c` 是 Android Bionic C 库中 `getopt_long` 函数的源代码。`getopt_long` 及其相关函数 (`getopt`, `getopt_long_only`) 的主要功能是**解析命令行参数**。它允许程序以标准化的方式处理用户在命令行中输入的选项（flags）和参数。

以下是其功能的详细列表：

**核心功能:**

1. **解析短选项:**  处理类似于 `-a`, `-b`, `-c val` 这样的短选项，这些选项通常由单个字符和一个可选的参数组成。
2. **解析长选项:** 处理类似于 `--help`, `--verbose`, `--output=file.txt` 这样的长选项，这些选项通常由两个连字符开头，并可以包含一个等号分隔的参数。
3. **处理选项参数:**  识别选项是否需要参数，并提取该参数。参数可以是紧跟在选项后面（例如 `-ovalue`）或作为下一个命令行参数（例如 `-o value`）。对于长选项，参数可以以等号分隔（例如 `--output=value`）。
4. **处理可选参数:** 允许长选项具有可选的参数。
5. **支持短选项合并:**  允许将多个不带参数的短选项合并为一个（例如 `-abc` 等同于 `-a -b -c`）。
6. **处理非选项参数:**  能够识别命令行中不是选项的参数，并可以根据配置将其移动到参数列表的末尾。
7. **错误处理:**  检测并报告无效的选项、缺少参数等错误。可以通过全局变量 `opterr` 控制是否打印错误信息。
8. **`getopt` 函数:** 提供一个只处理短选项的接口，与传统的 `getopt` 函数兼容。
9. **`getopt_long_only` 函数:** 提供一个只处理长选项的接口。
10. **GNU 兼容性:**  提供一定的 GNU `getopt_long` 的兼容性，例如处理 `-W long-option` 格式。

**与 Android 功能的关系举例说明:**

几乎所有 Android 的命令行工具（如 `adb`, `am`, `pm` 等）以及 Native 开发的应用程序都会使用 `getopt` 或 `getopt_long` 来处理命令行参数。

*   **`adb shell ls -l /sdcard`:**  `adb` 工具会使用 `getopt` 或 `getopt_long` 来解析 `shell` 和 `-l` 选项。
*   **Native NDK 应用:**  一个使用 NDK 开发的命令行工具，例如一个图像处理工具，可能会使用 `getopt_long` 来处理 `--input`, `--output`, `--resize` 等选项。

**libc 函数的实现解释:**

以下是代码中涉及的关键 libc 函数及其功能的实现解释：

1. **`warnx(const char *fmt, ...)` (来自 `<err.h>`):**
    *   **功能:**  类似于 `fprintf(stderr, fmt, ...)`, 但会自动在消息前加上程序名，并且不打印 `errno` 相关的错误信息。
    *   **实现:**  通常会调用底层的 `write` 系统调用向标准错误输出流写入格式化后的字符串。程序名通常在程序启动时从 `argv[0]` 中获取并存储。

2. **`strchr(const char *s, int c)` (来自 `<string.h>`):**
    *   **功能:**  在字符串 `s` 中查找字符 `c` 第一次出现的位置。
    *   **实现:**  通常通过一个循环遍历字符串 `s` 的每个字符，直到找到匹配的字符 `c` 或者到达字符串的末尾。如果找到，返回指向该字符的指针，否则返回 `NULL`。

3. **`strlen(const char *s)` (来自 `<string.h>`):**
    *   **功能:**  计算字符串 `s` 的长度，不包括结尾的空字符 `\0`。
    *   **实现:**  通过一个循环遍历字符串 `s`，直到遇到空字符 `\0`，并返回遍历的字符数。

4. **`strncmp(const char *s1, const char *s2, size_t n)` (来自 `<string.h>`):**
    *   **功能:**  比较字符串 `s1` 的前 `n` 个字符与字符串 `s2` 的前 `n` 个字符。
    *   **实现:**  逐个比较 `s1` 和 `s2` 的字符，直到比较了 `n` 个字符，或者遇到了空字符，或者找到了不匹配的字符。返回一个小于、等于或大于零的整数，分别表示 `s1` 小于、等于或大于 `s2`。

5. **`getenv(const char *name)` (来自 `<stdlib.h>`):**
    *   **功能:**  获取环境变量 `name` 的值。
    *   **实现:**  通常会访问进程的环境变量列表（这是一个字符串数组）。具体实现细节取决于操作系统，但通常会遍历这个列表，查找以 `name=` 开头的字符串。如果找到，返回指向等号后面值的指针，否则返回 `NULL`。

**涉及 dynamic linker 的功能、so 布局样本以及链接处理过程:**

`getopt_long.c` 本身的代码逻辑并不直接涉及 dynamic linker 的具体操作。它是一个提供参数解析功能的 C 代码。但是，当编译成库 (`libc.so`) 并被其他程序使用时，dynamic linker 会参与链接过程。

**so 布局样本 (libc.so 的一部分):**

```
libc.so:
    ...
    .text:  # 包含代码段
        ...
        getopt:          # getopt 函数的代码
        getopt_long:     # getopt_long 函数的代码
        getopt_long_only:# getopt_long_only 函数的代码
        getopt_internal: # 内部实现函数
        parse_long_options: # 解析长选项的函数
        permute_args:    # 重排参数的函数
        gcd:             # 计算最大公约数的函数
        ...
    .data:  # 包含已初始化数据
        opterr:          # 全局变量 opterr
        optind:          # 全局变量 optind
        optopt:          # 全局变量 optopt
        optarg:          # 全局变量 optarg
        ...
    .bss:   # 包含未初始化数据
        ...
    .dynsym: # 动态符号表
        ...
        getopt
        getopt_long
        getopt_long_only
        ...
    .dynstr: # 动态字符串表
        ...
        getopt
        getopt_long
        getopt_long_only
        ...
    ...
```

**链接的处理过程:**

1. **编译:** 当一个程序（例如 `adb`）使用 `getopt_long` 时，编译器会生成对 `getopt_long` 函数的未定义符号的引用。
2. **链接:**  在链接阶段，链接器（在 Android 上通常是 `lld`）会查找包含 `getopt_long` 函数定义的共享库。对于 Android 应用程序和工具，这个共享库通常是 `libc.so`。
3. **动态链接:** 当程序运行时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库（例如 `libc.so`）。
4. **符号解析:** dynamic linker 会解析程序中对 `getopt_long` 的未定义引用，将其指向 `libc.so` 中 `getopt_long` 函数的实际地址。
5. **GOT/PLT:**  通常会使用 Global Offset Table (GOT) 和 Procedure Linkage Table (PLT) 机制来实现延迟绑定。程序首次调用 `getopt_long` 时，PLT 中的代码会调用 dynamic linker 来解析符号并更新 GOT 表中的地址。后续调用将直接通过 GOT 表跳转到 `getopt_long` 的实现。

**逻辑推理 (假设输入与输出):**

假设有以下命令行和选项定义：

```c
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

int main(int argc, char *argv[]) {
    int verbose_flag = 0;
    char *output_file = NULL;
    int c;

    static struct option long_options[] = {
        {"verbose", no_argument,       &verbose_flag, 1},
        {"output",  required_argument, 0,             'o'},
        {"help",    no_argument,       0,             'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    while ((c = getopt_long(argc, argv, "ho:", long_options, &option_index)) != -1) {
        switch (c) {
            case 0:
                if (long_options[option_index].flag != 0)
                    break;
                printf("long option %s", long_options[option_index].name);
                if (optarg)
                    printf(" with arg %s", optarg);
                printf("\n");
                break;
            case 'h':
                printf("Usage: %s [--verbose] [--output FILE] [--help]\n", argv[0]);
                return 0;
            case 'o':
                output_file = optarg;
                printf("output file = %s\n", output_file);
                break;
            case '?':
                // getopt_long already printed an error message
                break;
            default:
                abort();
        }
    }

    if (verbose_flag)
        printf("Verbose mode is on.\n");

    if (output_file)
        printf("Output will be written to: %s\n", output_file);

    return 0;
}
```

**假设输入:**

```bash
./myprogram --verbose --output=log.txt input1 input2
```

**预期输出:**

```
long option verbose
output file = log.txt
Verbose mode is on.
Output will be written to: log.txt
```

**假设输入 (短选项合并):**

```bash
./myprogram -h
```

**预期输出:**

```
Usage: ./myprogram [--verbose] [--output FILE] [--help]
```

**用户或编程常见的使用错误举例说明:**

1. **`options` 字符串与 `long_options` 结构体不一致:**

    *   **错误:**  在 `getopt_long` 的第三个参数 `options` 中指定了某个短选项，但在 `long_options` 结构体中对应的长选项却没有设置 `val` 为该短选项字符。或者反过来。
    *   **示例:** `getopt_long(argc, argv, "v", long_options, &option_index)`，但 `long_options` 中没有长选项将 `val` 设置为 `'v'`。
    *   **后果:**  可能导致短选项无法被正确识别，或者长选项被误认为需要参数。

2. **忘记处理必须的参数:**

    *   **错误:**  某个选项要求有参数，但在解析到该选项后，没有检查 `optarg` 是否为空。
    *   **示例:** 定义了 `--output FILE`，但解析到 `--output` 后没有检查 `optarg` 是否为空，如果用户输入的是 `--output` 而没有提供文件名，程序可能会崩溃或行为异常。
    *   **后果:**  程序可能无法正常工作，甚至崩溃。

3. **混淆 `no_argument`, `required_argument`, `optional_argument`:**

    *   **错误:**  对选项参数类型的定义不正确。例如，将一个需要参数的选项定义为 `no_argument`。
    *   **示例:**  `{"output", no_argument, 0, 'o'}`，但 `--output` 实际上需要一个文件名作为参数。
    *   **后果:**  `getopt_long` 可能不会正确地将下一个参数赋值给 `optarg`，或者会错误地报告缺少参数。

4. **错误地使用全局变量:**

    *   **错误:**  直接修改 `optind` 而不理解其含义，或者在多线程环境下不加同步地访问 `optind`, `optarg` 等全局变量。
    *   **后果:**  可能导致参数解析逻辑混乱，或者在多线程环境下出现竞争条件。

**说明 Android framework 或 ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `getopt_long` 的路径 (间接):**

Android Framework 本身主要使用 Java/Kotlin 编写，处理命令行参数通常不会直接调用 `getopt_long`。但是，Framework 可能会启动一些 Native 可执行文件（例如通过 `Runtime.exec()`），这些 Native 可执行文件可能会使用 `getopt_long`。

1. **Java/Kotlin 代码:**  Framework 中的某个服务或应用需要执行一个 Native 工具，例如执行 shell 命令或调用系统工具。
2. **`ProcessBuilder` 或 `Runtime.exec()`:**  Java 代码使用这些类来创建和执行新的进程。命令行参数会作为字符串数组传递给这些方法。
3. **Native 可执行文件:**  被执行的 Native 可执行文件（通常是 NDK 开发的应用或系统工具）的 `main` 函数接收到这些命令行参数。
4. **调用 `getopt_long`:**  Native 代码中会调用 `getopt_long` 函数来解析这些参数。这个调用会最终链接到 `bionic/libc/upstream-freebsd/lib/libc/stdlib/getopt_long.c` 编译生成的代码。

**NDK 应用到 `getopt_long` 的路径 (直接):**

1. **NDK 开发:**  开发者使用 C/C++ 编写 Native 代码，并在 `main` 函数中接收命令行参数 `argc` 和 `argv`。
2. **调用 `getopt_long`:**  在 `main` 函数中，开发者直接调用 `getopt_long` 函数来处理 `argv` 中的参数。
3. **链接到 libc:**  NDK 构建系统会将 Native 代码链接到 Android 的 C 库 `libc.so`，其中包含了 `getopt_long` 的实现。

**Frida Hook 示例调试步骤:**

假设你想 hook `getopt_long` 函数，查看传递给它的参数和返回值。

**Frida Hook Script (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const getopt_long = libc.getExportByName("getopt_long");

  if (getopt_long) {
    Interceptor.attach(getopt_long, {
      onEnter: function (args) {
        console.log("[+] Called getopt_long");
        console.log("    argc:", args[0].toInt());
        console.log("    argv:", args[1]);
        const argv = new NativePointer(args[1]);
        for (let i = 0; i < args[0].toInt(); i++) {
          const argPtr = argv.add(i * Process.pointerSize).readPointer();
          console.log(`      argv[${i}]:`, argPtr.readCString());
        }
        console.log("    options:", args[2].readCString());
        console.log("    long_options:", args[3]);
        // 遍历 long_options 结构体（需要知道结构体定义）
        console.log("    idx:", args[4]);
      },
      onLeave: function (retval) {
        console.log("[+] getopt_long returned:", retval.toInt());
      }
    });
  } else {
    console.error("[-] getopt_long not found in libc.so");
  }
} else {
  console.log("[!] This script is for Android.");
}
```

**使用 Frida 调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **找到目标进程:** 确定你想要 hook 的进程的名称或 PID。
3. **运行 Frida 命令:** 使用 Frida 的命令行工具 `frida` 或 `frida-trace` 来注入你的 hook 脚本到目标进程。

    ```bash
    frida -U -f <package_name_or_process_name> -l your_script.js --no-pause
    # 或者 attach 到正在运行的进程
    frida -U <package_name_or_process_name> -l your_script.js
    ```

4. **触发 `getopt_long` 调用:**  在目标应用或工具中执行一些操作，使其调用到 `getopt_long` 函数。例如，如果你 hook 的是 `adb shell`，你可以执行 `adb shell ls -l`。
5. **查看 Frida 输出:**  Frida 会打印出 `getopt_long` 被调用时的参数和返回值，帮助你理解参数解析的过程。

这个 Frida 脚本会拦截对 `getopt_long` 的调用，并在控制台上打印出 `argc`、`argv`、`options` 以及返回值。对于 `long_options` 结构体，你需要了解其具体的定义才能更详细地解析其内容。你可以通过分析 `<getopt.h>` 头文件来获取 `option` 结构体的定义。

### 提示词
```
这是目录为bionic/libc/upstream-freebsd/lib/libc/stdlib/getopt_long.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: getopt_long.c,v 1.26 2013/06/08 22:47:56 millert Exp $	*/
/*	$NetBSD: getopt_long.c,v 1.15 2002/01/31 22:43:40 tv Exp $	*/

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */
/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if 0
#if defined(LIBC_SCCS) && !defined(lint)
static char *rcsid = "$OpenBSD: getopt_long.c,v 1.16 2004/02/04 18:17:25 millert Exp $";
#endif /* LIBC_SCCS and not lint */
#endif
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define GNU_COMPATIBLE		/* Be more compatible, configure's use us! */

#if 0				/* we prefer to keep our getopt(3) */
#define	REPLACE_GETOPT		/* use this getopt as the system getopt(3) */
#endif

#ifdef REPLACE_GETOPT
int	opterr = 1;		/* if error message should be printed */
int	optind = 1;		/* index into parent argv vector */
int	optopt = '?';		/* character checked for validity */
int	optreset;		/* reset getopt */
char    *optarg;		/* argument associated with option */
#endif

#define PRINT_ERROR	((opterr) && (*options != ':'))

#define FLAG_PERMUTE	0x01	/* permute non-options to the end of argv */
#define FLAG_ALLARGS	0x02	/* treat non-options as args to option "-1" */
#define FLAG_LONGONLY	0x04	/* operate as getopt_long_only */

/* return values */
#define	BADCH		(int)'?'
#define	BADARG		((*options == ':') ? (int)':' : (int)'?')
#define	INORDER 	(int)1

static char EMSG[] = "";

#ifdef GNU_COMPATIBLE
#define NO_PREFIX	(-1)
#define D_PREFIX	0
#define DD_PREFIX	1
#define W_PREFIX	2
#endif

static int getopt_internal(int, char * const *, const char *,
			   const struct option *, int *, int);
static int parse_long_options(char * const *, const char *,
			      const struct option *, int *, int, int);
static int gcd(int, int);
static void permute_args(int, int, int, char * const *);

static char *place = EMSG; /* option letter processing */

/* XXX: set optreset to 1 rather than these two */
static int nonopt_start = -1; /* first non option argument (for permute) */
static int nonopt_end = -1;   /* first option after non options (for permute) */

/* Error messages */
static const char recargchar[] = "option requires an argument -- %c";
static const char illoptchar[] = "illegal option -- %c"; /* From P1003.2 */
#ifdef GNU_COMPATIBLE
static int dash_prefix = NO_PREFIX;
static const char gnuoptchar[] = "invalid option -- %c";

static const char recargstring[] = "option `%s%s' requires an argument";
static const char ambig[] = "option `%s%.*s' is ambiguous";
static const char noarg[] = "option `%s%.*s' doesn't allow an argument";
static const char illoptstring[] = "unrecognized option `%s%s'";
#else
static const char recargstring[] = "option requires an argument -- %s";
static const char ambig[] = "ambiguous option -- %.*s";
static const char noarg[] = "option doesn't take an argument -- %.*s";
static const char illoptstring[] = "unknown option -- %s";
#endif

/*
 * Compute the greatest common divisor of a and b.
 */
static int
gcd(int a, int b)
{
	int c;

	c = a % b;
	while (c != 0) {
		a = b;
		b = c;
		c = a % b;
	}

	return (b);
}

/*
 * Exchange the block from nonopt_start to nonopt_end with the block
 * from nonopt_end to opt_end (keeping the same order of arguments
 * in each block).
 */
static void
permute_args(int panonopt_start, int panonopt_end, int opt_end,
	char * const *nargv)
{
	int cstart, cyclelen, i, j, ncycle, nnonopts, nopts, pos;
	char *swap;

	/*
	 * compute lengths of blocks and number and size of cycles
	 */
	nnonopts = panonopt_end - panonopt_start;
	nopts = opt_end - panonopt_end;
	ncycle = gcd(nnonopts, nopts);
	cyclelen = (opt_end - panonopt_start) / ncycle;

	for (i = 0; i < ncycle; i++) {
		cstart = panonopt_end+i;
		pos = cstart;
		for (j = 0; j < cyclelen; j++) {
			if (pos >= panonopt_end)
				pos -= nnonopts;
			else
				pos += nopts;
			swap = nargv[pos];
			/* LINTED const cast */
			((char **) nargv)[pos] = nargv[cstart];
			/* LINTED const cast */
			((char **)nargv)[cstart] = swap;
		}
	}
}

/*
 * parse_long_options --
 *	Parse long options in argc/argv argument vector.
 * Returns -1 if short_too is set and the option does not match long_options.
 */
static int
parse_long_options(char * const *nargv, const char *options,
	const struct option *long_options, int *idx, int short_too, int flags)
{
	char *current_argv, *has_equal;
#ifdef GNU_COMPATIBLE
	const char *current_dash;
#endif
	size_t current_argv_len;
	int i, match, exact_match, second_partial_match;

	current_argv = place;
#ifdef GNU_COMPATIBLE
	switch (dash_prefix) {
		case D_PREFIX:
			current_dash = "-";
			break;
		case DD_PREFIX:
			current_dash = "--";
			break;
		case W_PREFIX:
			current_dash = "-W ";
			break;
		default:
			current_dash = "";
			break;
	}
#endif
	match = -1;
	exact_match = 0;
	second_partial_match = 0;

	optind++;

	if ((has_equal = strchr(current_argv, '=')) != NULL) {
		/* argument found (--option=arg) */
		current_argv_len = has_equal - current_argv;
		has_equal++;
	} else
		current_argv_len = strlen(current_argv);

	for (i = 0; long_options[i].name; i++) {
		/* find matching long option */
		if (strncmp(current_argv, long_options[i].name,
		    current_argv_len))
			continue;

		if (strlen(long_options[i].name) == current_argv_len) {
			/* exact match */
			match = i;
			exact_match = 1;
			break;
		}
		/*
		 * If this is a known short option, don't allow
		 * a partial match of a single character.
		 */
		if (short_too && current_argv_len == 1)
			continue;

		if (match == -1)	/* first partial match */
			match = i;
		else if ((flags & FLAG_LONGONLY) ||
			 long_options[i].has_arg !=
			     long_options[match].has_arg ||
			 long_options[i].flag != long_options[match].flag ||
			 long_options[i].val != long_options[match].val)
			second_partial_match = 1;
	}
	if (!exact_match && second_partial_match) {
		/* ambiguous abbreviation */
		if (PRINT_ERROR)
			warnx(ambig,
#ifdef GNU_COMPATIBLE
			     current_dash,
#endif
			     (int)current_argv_len,
			     current_argv);
		optopt = 0;
		return (BADCH);
	}
	if (match != -1) {		/* option found */
		if (long_options[match].has_arg == no_argument
		    && has_equal) {
			if (PRINT_ERROR)
				warnx(noarg,
#ifdef GNU_COMPATIBLE
				     current_dash,
#endif
				     (int)current_argv_len,
				     current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			if (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			else
				optopt = 0;
#ifdef GNU_COMPATIBLE
			return (BADCH);
#else
			return (BADARG);
#endif
		}
		if (long_options[match].has_arg == required_argument ||
		    long_options[match].has_arg == optional_argument) {
			if (has_equal)
				optarg = has_equal;
			else if (long_options[match].has_arg ==
			    required_argument) {
				/*
				 * optional argument doesn't use next nargv
				 */
				optarg = nargv[optind++];
			}
		}
		if ((long_options[match].has_arg == required_argument)
		    && (optarg == NULL)) {
			/*
			 * Missing argument; leading ':' indicates no error
			 * should be generated.
			 */
			if (PRINT_ERROR)
				warnx(recargstring,
#ifdef GNU_COMPATIBLE
				    current_dash,
#endif
				    current_argv);
			/*
			 * XXX: GNU sets optopt to val regardless of flag
			 */
			if (long_options[match].flag == NULL)
				optopt = long_options[match].val;
			else
				optopt = 0;
			--optind;
			return (BADARG);
		}
	} else {			/* unknown option */
		if (short_too) {
			--optind;
			return (-1);
		}
		if (PRINT_ERROR)
			warnx(illoptstring,
#ifdef GNU_COMPATIBLE
			      current_dash,
#endif
			      current_argv);
		optopt = 0;
		return (BADCH);
	}
	if (idx)
		*idx = match;
	if (long_options[match].flag) {
		*long_options[match].flag = long_options[match].val;
		return (0);
	} else
		return (long_options[match].val);
}

/*
 * getopt_internal --
 *	Parse argc/argv argument vector.  Called by user level routines.
 */
static int
getopt_internal(int nargc, char * const *nargv, const char *options,
	const struct option *long_options, int *idx, int flags)
{
	char *oli;				/* option letter list index */
	int optchar, short_too;
	static int posixly_correct = -1;

	if (options == NULL)
		return (-1);

	/*
	 * XXX Some GNU programs (like cvs) set optind to 0 instead of
	 * XXX using optreset.  Work around this braindamage.
	 */
	if (optind == 0)
		optind = optreset = 1;

	/*
	 * Disable GNU extensions if POSIXLY_CORRECT is set or options
	 * string begins with a '+'.
	 */
	if (posixly_correct == -1 || optreset)
		posixly_correct = (getenv("POSIXLY_CORRECT") != NULL);
	if (*options == '-')
		flags |= FLAG_ALLARGS;
	else if (posixly_correct || *options == '+')
		flags &= ~FLAG_PERMUTE;
	if (*options == '+' || *options == '-')
		options++;

	optarg = NULL;
	if (optreset)
		nonopt_start = nonopt_end = -1;
start:
	if (optreset || !*place) {		/* update scanning pointer */
		optreset = 0;
		if (optind >= nargc) {          /* end of argument vector */
			place = EMSG;
			if (nonopt_end != -1) {
				/* do permutation, if we have to */
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			else if (nonopt_start != -1) {
				/*
				 * If we skipped non-options, set optind
				 * to the first of them.
				 */
				optind = nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			return (-1);
		}
		if (*(place = nargv[optind]) != '-' ||
#ifdef GNU_COMPATIBLE
		    place[1] == '\0') {
#else
		    (place[1] == '\0' && strchr(options, '-') == NULL)) {
#endif
			place = EMSG;		/* found non-option */
			if (flags & FLAG_ALLARGS) {
				/*
				 * GNU extension:
				 * return non-option as argument to option 1
				 */
				optarg = nargv[optind++];
				return (INORDER);
			}
			if (!(flags & FLAG_PERMUTE)) {
				/*
				 * If no permutation wanted, stop parsing
				 * at first non-option.
				 */
				return (-1);
			}
			/* do permutation */
			if (nonopt_start == -1)
				nonopt_start = optind;
			else if (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				nonopt_start = optind -
				    (nonopt_end - nonopt_start);
				nonopt_end = -1;
			}
			optind++;
			/* process next argument */
			goto start;
		}
		if (nonopt_start != -1 && nonopt_end == -1)
			nonopt_end = optind;

		/*
		 * If we have "-" do nothing, if "--" we are done.
		 */
		if (place[1] != '\0' && *++place == '-' && place[1] == '\0') {
			optind++;
			place = EMSG;
			/*
			 * We found an option (--), so if we skipped
			 * non-options, we have to permute.
			 */
			if (nonopt_end != -1) {
				permute_args(nonopt_start, nonopt_end,
				    optind, nargv);
				optind -= nonopt_end - nonopt_start;
			}
			nonopt_start = nonopt_end = -1;
			return (-1);
		}
	}

	/*
	 * Check long options if:
	 *  1) we were passed some
	 *  2) the arg is not just "-"
	 *  3) either the arg starts with -- we are getopt_long_only()
	 */
	if (long_options != NULL && place != nargv[optind] &&
	    (*place == '-' || (flags & FLAG_LONGONLY))) {
		short_too = 0;
#ifdef GNU_COMPATIBLE
		dash_prefix = D_PREFIX;
#endif
		if (*place == '-') {
			place++;		/* --foo long option */
			if (*place == '\0')
				return (BADARG);	/* malformed option */
#ifdef GNU_COMPATIBLE
			dash_prefix = DD_PREFIX;
#endif
		} else if (*place != ':' && strchr(options, *place) != NULL)
			short_too = 1;		/* could be short option too */

		optchar = parse_long_options(nargv, options, long_options,
		    idx, short_too, flags);
		if (optchar != -1) {
			place = EMSG;
			return (optchar);
		}
	}

	if ((optchar = (int)*place++) == (int)':' ||
	    (optchar == (int)'-' && *place != '\0') ||
	    (oli = strchr(options, optchar)) == NULL) {
		/*
		 * If the user specified "-" and  '-' isn't listed in
		 * options, return -1 (non-option) as per POSIX.
		 * Otherwise, it is an unknown option character (or ':').
		 */
		if (optchar == (int)'-' && *place == '\0')
			return (-1);
		if (!*place)
			++optind;
#ifdef GNU_COMPATIBLE
		if (PRINT_ERROR)
			warnx(posixly_correct ? illoptchar : gnuoptchar,
			      optchar);
#else
		if (PRINT_ERROR)
			warnx(illoptchar, optchar);
#endif
		optopt = optchar;
		return (BADCH);
	}
	if (long_options != NULL && optchar == 'W' && oli[1] == ';') {
		/* -W long-option */
		if (*place)			/* no space */
			/* NOTHING */;
		else if (++optind >= nargc) {	/* no arg */
			place = EMSG;
			if (PRINT_ERROR)
				warnx(recargchar, optchar);
			optopt = optchar;
			return (BADARG);
		} else				/* white space */
			place = nargv[optind];
#ifdef GNU_COMPATIBLE
		dash_prefix = W_PREFIX;
#endif
		optchar = parse_long_options(nargv, options, long_options,
		    idx, 0, flags);
		place = EMSG;
		return (optchar);
	}
	if (*++oli != ':') {			/* doesn't take argument */
		if (!*place)
			++optind;
	} else {				/* takes (optional) argument */
		optarg = NULL;
		if (*place)			/* no white space */
			optarg = place;
		else if (oli[1] != ':') {	/* arg not optional */
			if (++optind >= nargc) {	/* no arg */
				place = EMSG;
				if (PRINT_ERROR)
					warnx(recargchar, optchar);
				optopt = optchar;
				return (BADARG);
			} else
				optarg = nargv[optind];
		}
		place = EMSG;
		++optind;
	}
	/* dump back option letter */
	return (optchar);
}

#ifdef REPLACE_GETOPT
/*
 * getopt --
 *	Parse argc/argv argument vector.
 *
 * [eventually this will replace the BSD getopt]
 */
int
getopt(int nargc, char * const *nargv, const char *options)
{

	/*
	 * We don't pass FLAG_PERMUTE to getopt_internal() since
	 * the BSD getopt(3) (unlike GNU) has never done this.
	 *
	 * Furthermore, since many privileged programs call getopt()
	 * before dropping privileges it makes sense to keep things
	 * as simple (and bug-free) as possible.
	 */
	return (getopt_internal(nargc, nargv, options, NULL, NULL, 0));
}
#endif /* REPLACE_GETOPT */

/*
 * getopt_long --
 *	Parse argc/argv argument vector.
 */
int
getopt_long(int nargc, char * const *nargv, const char *options,
	const struct option *long_options, int *idx)
{

	return (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE));
}

/*
 * getopt_long_only --
 *	Parse argc/argv argument vector.
 */
int
getopt_long_only(int nargc, char * const *nargv, const char *options,
	const struct option *long_options, int *idx)
{

	return (getopt_internal(nargc, nargv, options, long_options, idx,
	    FLAG_PERMUTE|FLAG_LONGONLY));
}
```
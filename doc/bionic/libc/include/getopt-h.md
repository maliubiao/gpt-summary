Response:
Let's break down the thought process for answering the request. The initial request is quite comprehensive, asking for a detailed explanation of `getopt.h`. Here's a step-by-step thought process to arrive at the detailed answer:

1. **Identify the Core Task:** The fundamental goal is to explain the functionality of the `getopt.h` header file. This involves understanding the purpose of the functions declared within it.

2. **Analyze the Header File Content:**  Carefully read through the provided `getopt.h` source code. Identify the key elements:
    * **Copyright and Licensing:** Note the origin (NetBSD, FreeBSD) and the permissive license. This gives context but isn't a primary function.
    * **Includes:**  See that it includes `<sys/cdefs.h>` and `<bits/getopt.h>`. Realize that `<bits/getopt.h>` will contain the actual implementation details (data structures, internal functions). The current file is primarily declarations.
    * **Macros:** Observe `no_argument`, `required_argument`, and `optional_argument`. Recognize their purpose as flags for argument handling.
    * **`struct option`:** This is a crucial data structure. Analyze its members: `name`, `has_arg`, `flag`, and `val`. Understand how they work together to define a long option.
    * **Function Declarations:** Identify `getopt_long` and `getopt_long_only`. Note the parameters: `argc`, `argv`, `options` (short options), `long_options`, and `long_index`. Understand their roles in option parsing. Recognize the difference between the two functions (the "only" version).
    * **External Variable:**  Spot the declaration of `optreset`. Understand its purpose in resetting the state.
    * **`__BEGIN_DECLS` and `__END_DECLS`:** These are common macros for C/C++ compatibility, ensuring proper linkage.

3. **Address Each Point of the Request Systematically:**  Go through each requirement of the prompt and address it based on the analysis of the header file.

    * **功能列举 (List Functionalities):**  Based on the function declarations, the core functionalities are parsing command-line options (short and long), handling arguments (required, optional, none), and resetting the parser.

    * **与 Android 功能的关系及举例 (Relationship to Android and Examples):**  Recognize that command-line argument parsing is fundamental to any command-line tool. Think about common Android command-line tools (ADB, Fastboot, `pm`, `am`, etc.) and how they use options. Provide concrete examples.

    * **详细解释 libc 函数的功能实现 (Detailed Explanation of libc Function Implementations):** This requires going *beyond* the header. Acknowledge that the header is just declarations. Explain *conceptually* how `getopt_long` likely works (iterating through arguments, matching short and long options, handling arguments). Mention the role of `optarg`, `optind`, `opterr`, and `optopt` (even though they're not directly in *this* header, they're part of the `getopt` family and relevant).

    * **涉及 dynamic linker 的功能 (Dynamic Linker Functionality):** Realize that this header *itself* doesn't directly involve the dynamic linker. However, *using* the functions declared here does. Explain that the dynamic linker loads the `libc.so` containing the implementation. Provide a simplified `libc.so` layout example and explain the linking process. Emphasize symbol resolution.

    * **逻辑推理和假设输入输出 (Logical Reasoning and Hypothetical Input/Output):** Create simple examples demonstrating the usage of `getopt_long` with different options and arguments. Show how it would parse these inputs.

    * **用户或编程常见的使用错误 (Common Usage Errors):** Think about common mistakes developers make when using `getopt`: incorrect option strings, missing required arguments, misunderstanding the return values, forgetting to reset `optind`.

    * **Android Framework/NDK 到达这里的步骤 (Steps from Android Framework/NDK):**  Trace the path from a high-level Android command down to the `getopt` call within `libc`. Use examples like `adb shell` to illustrate this. Explain the role of the shell, the executable, and the eventual call to `getopt`.

    * **Frida Hook 示例 (Frida Hook Example):** Provide practical Frida code to intercept calls to `getopt_long`. Show how to log arguments and the return value. This is a crucial part for demonstrating how to inspect the behavior at runtime.

4. **Structure and Language:** Organize the answer logically using clear headings and bullet points. Use precise language but avoid overly technical jargon where possible. Translate technical terms appropriately into Chinese.

5. **Refine and Review:**  Read through the complete answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or missing information. For example, initially, I might have forgotten to explicitly mention `optarg`, `optind`, etc., and then I'd add them for completeness in the "libc function implementation" section. Similarly, ensure the Frida example is functional and easy to understand.

By following this systematic approach, breaking down the request, and combining knowledge of C programming, Android development, and the purpose of `getopt`, it's possible to generate a comprehensive and accurate answer like the example provided.
```c
/*	$NetBSD: getopt.h,v 1.4 2000/07/07 10:43:54 ad Exp $	*/
/*	$FreeBSD$ */

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
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN AN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

/**
 * @file getopt.h
 * @brief The getopt() and getopt_long() functions.
 */

#include <sys/cdefs.h>

#include <bits/getopt.h>

/** A `has_arg` value for `struct option`. */
#define no_argument 0
/** A `has_arg` value for `struct option`. */
#define required_argument 1
/** A `has_arg` value for `struct option`. */
#define optional_argument 2

struct option {
  /**
   * Name of long option. Options must have a non-NULL name.
   * A NULL name signals the end of the options array.
   */
  const char * _Nullable name;

  /**
   * One of `no_argument`, `required_argument`, or `optional_argument`.
   */
  int has_arg;

  /** If not NULL, set `*flag` to val when option found. */
  int* _Nullable flag;

  /** If `flag` not NULL, the value to assign to `*flag`; otherwise the return value. */
  int val;
};

__BEGIN_DECLS

/**
 * [getopt_long(3)](https://man7.org/linux/man-pages/man3/getopt.3.html) parses command-line options.
 */
int getopt_long(int __argc, char* _Nonnull const* _Nonnull __argv, const char* _Nonnull __options, const struct option* _Nonnull __long_options, int* _Nullable __long_index);

/**
 * [getopt_long_only(3)](https://man7.org/linux/man-pages/man3/getopt.3.html) parses command-line options.
 */
int getopt_long_only(int __argc, char* _Nonnull const* _Nonnull __argv, const char* _Nonnull __options, const struct option* _Nonnull __long_options, int* _Nullable __long_index);

#ifndef _OPTRESET_DECLARED
#define _OPTRESET_DECLARED
/**
 * Must be set to 1 to reset the `getopt` functions before scanning a new argument vector.
 */
extern int optreset;
#endif

__END_DECLS
```

这是一个C语言头文件 `getopt.h`，它定义了用于解析命令行选项的函数和数据结构。由于它位于 `bionic/libc/include` 目录下，并且是 Android 的一部分，因此它在 Android 系统中被广泛使用。

**功能列举:**

1. **定义了 `struct option` 结构体:** 用于描述长选项（例如 `--help` 或 `--verbose`）。这个结构体包含长选项的名称、是否需要参数、一个指向标志变量的指针以及当选项被找到时设置的值。

2. **声明了 `getopt_long()` 函数:**  这个函数是用来解析带有长选项的命令行参数的。它可以同时处理短选项（例如 `-h`）和长选项。

3. **声明了 `getopt_long_only()` 函数:**  类似于 `getopt_long()`，但将以连字符开头的长选项（例如 `-help`）视为长选项，而 `getopt_long()` 默认将其视为短选项。

4. **声明了 `optreset` 外部变量:**  当需要重新开始解析新的参数向量时，需要将此变量设置为 1。

5. **定义了宏 `no_argument`, `required_argument`, `optional_argument`:** 这些宏用于指定长选项是否需要参数以及参数是必须的还是可选的。

**与 Android 功能的关系及举例:**

`getopt.h` 中声明的函数在 Android 系统中被广泛用于各种命令行工具和守护进程中，以处理用户提供的命令行参数。

* **Android Shell 命令:** 许多 Android shell 命令（如 `adb`, `am`, `pm`, `dumpsys` 等）都使用 `getopt_long()` 或类似的机制来解析选项。例如：
    * `adb logcat -v time`:  `adb` 工具使用 `-v` 选项，并传递参数 `time`。
    * `pm install -r my_app.apk`: `pm` (Package Manager) 工具使用 `-r` 选项。
    * `dumpsys wifi`: `dumpsys` 工具使用 `wifi` 作为要转储信息的服务名称。虽然这里不是明显的选项，但更复杂的 `dumpsys` 命令也会使用选项。

* **系统服务和守护进程:**  一些 Android 系统服务和守护进程在启动时也会解析命令行参数来配置其行为。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于这是一个头文件，它只包含函数和数据结构的声明，而没有实现。实际的实现代码位于 `bionic/libc/bionic/getopt.c` (或其他相关的源文件) 中。

**`getopt_long()` 的概念性实现:**

1. **初始化:**  函数会维护一些内部状态，例如当前正在处理的参数索引。
2. **循环遍历 `argv`:** 函数会依次处理 `argv` 中的每个参数。
3. **识别选项:**
   * 如果参数以 `-` 开头，则可能是短选项或长选项。
   * 如果参数以 `--` 开头，则是长选项。
   * 如果参数不是以 `-` 开头，则可能是非选项参数。
4. **处理短选项:**
   * 函数会查找 `options` 字符串中是否存在匹配的短选项字符。
   * 如果短选项需要参数（通过 `options` 字符串中的 `:` 表示），则会从 `argv` 中获取下一个参数作为选项的参数，并将其存储在全局变量 `optarg` 中。
   * 全局变量 `optind` 会更新为下一个要处理的参数的索引。
   * 全局变量 `optopt` 会存储未能识别的选项字符。
   * 全局变量 `opterr` 控制是否在发生错误时打印错误消息。
5. **处理长选项:**
   * 函数会遍历 `long_options` 数组，查找与当前参数匹配的长选项名称。
   * 根据 `struct option` 中的 `has_arg` 字段，判断长选项是否需要参数。
   * 如果长选项定义了 `flag` 字段，则会将 `val` 写入 `*flag` 指向的内存。否则，函数会返回 `val`。
   * 全局变量 `optind` 会更新。
6. **处理非选项参数:**  这些参数通常会保留在 `argv` 中，并可以通过 `optind` 访问。
7. **错误处理:** 如果遇到无法识别的选项或缺少必需的参数，函数会根据 `opterr` 的值进行错误处理。
8. **返回值:** 函数返回匹配到的选项字符（对于短选项）或 `struct option` 中的 `val` 值（对于长选项）。当所有选项都被处理完毕时，返回 -1。

**`getopt_long_only()` 的概念性实现:**

与 `getopt_long()` 类似，主要区别在于如何处理以单个 `-` 开头的长选项。`getopt_long_only()` 会尝试将其解析为长选项，而 `getopt_long()` 默认会将其视为多个短选项的组合。

**涉及 dynamic linker 的功能:**

`getopt.h` 本身不直接涉及动态链接器。但是，当程序调用 `getopt_long()` 或 `getopt_long_only()` 时，这些函数的实现代码位于 `libc.so` 中。动态链接器负责在程序启动时加载 `libc.so`，并将程序中对这些函数的调用链接到 `libc.so` 中相应的函数实现。

**`libc.so` 布局样本:**

```
libc.so:
    .text:  // 存放代码段
        getopt_long:  // getopt_long 函数的机器码
            ...
        getopt_long_only: // getopt_long_only 函数的机器码
            ...
        // 其他 libc 函数的实现
    .data:  // 存放已初始化的全局变量
        opterr: // 全局变量 opterr
            ...
        optind: // 全局变量 optind
            ...
        optopt: // 全局变量 optopt
            ...
    .bss:   // 存放未初始化的全局变量
        optarg: // 全局变量 optarg
            ...
    .dynsym: // 动态符号表
        getopt_long  // 符号 getopt_long 及其地址
        getopt_long_only // 符号 getopt_long_only 及其地址
        // 其他动态符号
    .dynstr: // 动态字符串表
        "getopt_long"
        "getopt_long_only"
        // 其他字符串
```

**链接的处理过程:**

1. **编译时:** 编译器遇到 `getopt_long()` 的调用时，会在生成的目标文件中记录一个对 `getopt_long` 符号的未定义引用。

2. **链接时:** 链接器将所有目标文件链接在一起。它会查找 `libc.so` 中的符号表 (`.dynsym`)，找到 `getopt_long` 符号的地址。链接器会在最终的可执行文件中建立相应的链接关系，使得程序在运行时能够找到 `getopt_long` 的实现。

3. **运行时:** 当可执行文件被加载到内存中时，动态链接器会加载程序依赖的共享库，包括 `libc.so`。动态链接器会解析可执行文件中的动态链接信息，将程序中对 `getopt_long` 的调用重定向到 `libc.so` 中 `getopt_long` 的实际地址。

**逻辑推理和假设输入输出:**

**假设输入:**

```
argc = 4
argv = ["myprogram", "-a", "--verbose", "file.txt"]
options = "a:"
long_options = [
    {"name": "verbose", "has_arg": no_argument, "flag": NULL, "val": 'v'},
    {"name": "output", "has_arg": required_argument, "flag": NULL, "val": 'o'},
    {NULL, 0, NULL, 0}
]
long_index = NULL
```

**预期输出 (多次调用 `getopt_long`):**

* **第一次调用:** 返回 `'a'`。`optarg` 为 `NULL`。`optind` 更新为 2。
* **第二次调用:** 返回 `'v'`。`optarg` 为 `NULL`。`optind` 更新为 3。
* **第三次调用:** 返回 -1。`optind` 更新为 3。

**假设输入:**

```
argc = 5
argv = ["myprogram", "--output", "result.log", "-b", "input.txt"]
options = "b"
long_options = [
    {"name": "output", "has_arg": required_argument, "flag": NULL, "val": 1},
    {NULL, 0, NULL, 0}
]
long_index = NULL
```

**预期输出 (多次调用 `getopt_long`):**

* **第一次调用:** 返回 `1`。`optarg` 为 `"result.log"`。`optind` 更新为 3。
* **第二次调用:** 返回 `'b'`。`optarg` 为 `NULL`。`optind` 更新为 4。
* **第三次调用:** 返回 -1。`optind` 更新为 4。

**用户或者编程常见的使用错误:**

1. **忘记检查返回值:**  开发者可能忘记检查 `getopt_long()` 的返回值，导致程序在没有选项的情况下也执行了选项相关的逻辑。

   ```c
   int opt;
   while ((opt = getopt_long(argc, argv, "ab:", long_options, NULL)) != -1) {
       // 即使没有选项，循环也会执行一次，因为初始值不是 -1
       switch (opt) {
           case 'a':
               // ...
               break;
           case 'b':
               // ...
               break;
           case '?':
               // ...
               break;
       }
   }
   ```

2. **错误的选项字符串:**  在 `getopt_long()` 的 `options` 参数中使用了错误的格式，例如忘记在需要参数的短选项后添加 `:`。

   ```c
   // 错误：选项 'o' 需要参数，但缺少 ':'
   while ((opt = getopt_long(argc, argv, "ao", long_options, NULL)) != -1) {
       // ...
   }
   ```

3. **未正确处理 `optarg`:**  当选项需要参数时，开发者可能忘记检查或使用全局变量 `optarg` 中存储的参数值。

   ```c
   while ((opt = getopt_long(argc, argv, "o:", long_options, NULL)) != -1) {
       switch (opt) {
           case 'o':
               // 错误：忘记使用 optarg
               printf("Output option specified.\n");
               break;
           // ...
       }
   }
   ```

4. **多次调用 `getopt` 未重置 `optind`:**  如果需要多次解析不同的参数向量，必须将全局变量 `optind` 重置为 0，或者设置 `optreset` 为 1。

   ```c
   // 第一次解析
   getopt_long(argc1, argv1, "a", long_options, NULL);

   // 第二次解析，忘记重置 optind
   getopt_long(argc2, argv2, "b", long_options, NULL); // 可能无法正确解析 argv2
   ```

5. **长选项名称错误:** 在 `long_options` 结构体中拼写错误的选项名称将导致 `getopt_long()` 无法识别这些选项。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework/NDK 调用:**  通常，Android Framework 或 NDK 中的组件会执行一个可执行文件，该可执行文件是用 C/C++ 编写的，并且需要解析命令行参数。例如，一个 NDK 应用可能会调用一个本地可执行文件来处理某些任务。

2. **可执行文件中的 `main` 函数:**  该可执行文件的 `main` 函数接收 `argc` 和 `argv` 作为参数，其中 `argv` 包含了命令行参数。

3. **调用 `getopt_long`:**  在 `main` 函数中，或者被 `main` 函数调用的其他函数中，会调用 `getopt_long()` 或 `getopt_long_only()` 来解析 `argv` 中的参数。

   ```c++
   #include <getopt.h>
   #include <stdio.h>

   int main(int argc, char *argv[]) {
       int opt;
       static struct option long_options[] = {
           {"verbose", no_argument, 0, 'v'},
           {"help", no_argument, 0, 'h'},
           {0, 0, 0, 0}
       };
       int option_index = 0;

       while ((opt = getopt_long(argc, argv, "vh", long_options, &option_index)) != -1) {
           switch (opt) {
               case 'v':
                   printf("Verbose mode enabled\n");
                   break;
               case 'h':
                   printf("Usage: ...\n");
                   break;
               case '?':
                   // getopt_long 已经打印了错误消息
                   break;
               default:
                   printf("Unknown option: %c\n", opt);
           }
       }

       // 处理非选项参数
       if (optind < argc) {
           printf("Non-option arguments:\n");
           while (optind < argc) {
               printf("%s\n", argv[optind++]);
           }
       }

       return 0;
   }
   ```

4. **`libc.so` 中的实现:**  当程序执行到 `getopt_long()` 调用时，由于链接器的作用，实际执行的是 `bionic/libc/bionic/getopt.c` 中 `getopt_long` 的实现代码。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `getopt_long` 的示例，用于打印其参数和返回值：

```javascript
if (Process.platform === 'android') {
    const libc = Process.getModuleByName("libc.so");
    const getopt_long = libc.getExportByName("getopt_long");

    if (getopt_long) {
        Interceptor.attach(getopt_long, {
            onEnter: function (args) {
                console.log("[getopt_long] onEnter");
                console.log("  argc:", args[0].toInt());
                const argv = new NativePointer(args[1]);
                for (let i = 0; i < args[0].toInt(); i++) {
                    const argPtr = Memory.readPointer(argv.add(i * Process.pointerSize));
                    console.log(`  argv[${i}]:`, argPtr.readUtf8String());
                }
                console.log("  options:", args[2].readUtf8String());
                const longopts = new NativePointer(args[3]);
                // 遍历 long_options 结构体 (简化，需要根据实际结构体布局进行更精确的解析)
                let i = 0;
                while (true) {
                    const namePtr = Memory.readPointer(longopts.add(i * 16)); // 假设每个结构体 16 字节
                    if (namePtr.isNull()) break;
                    const name = namePtr.readUtf8String();
                    const has_arg = Memory.readInt(longopts.add(i * 16 + Process.pointerSize));
                    const val = Memory.readInt(longopts.add(i * 16 + 2 * Process.pointerSize + Process.pointerSize)); // 假设布局
                    console.log(`  long_options[${i}]: name=${name}, has_arg=${has_arg}, val=${val}`);
                    i++;
                }

                console.log("  long_index:", args[4]);
            },
            onLeave: function (retval) {
                console.log("[getopt_long] onLeave");
                console.log("  Return value:", retval);
            }
        });
    } else {
        console.error("Failed to find getopt_long");
    }
}
```

**使用步骤:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `getopt_hook.js`）。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <包名> -l getopt_hook.js --no-pause` (替换 `<包名>` 为目标应用的包名，如果目标是本地可执行文件，可以使用 `-n <进程名>` 或 `-p <进程ID>`).
3. 当目标进程执行到 `getopt_long` 函数时，Frida 会拦截调用并打印相关信息。

这个 Frida 脚本可以帮助你理解 `getopt_long` 在 Android 系统中的使用方式，以及传递给它的参数。你需要根据实际情况调整 `long_options` 的解析部分，因为结构体的布局可能因 Android 版本和架构而异。

Prompt: 
```
这是目录为bionic/libc/include/getopt.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$NetBSD: getopt.h,v 1.4 2000/07/07 10:43:54 ad Exp $	*/
/*	$FreeBSD$ */

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

#pragma once

/**
 * @file getopt.h
 * @brief The getopt() and getopt_long() functions.
 */

#include <sys/cdefs.h>

#include <bits/getopt.h>

/** A `has_arg` value for `struct option`. */
#define no_argument 0
/** A `has_arg` value for `struct option`. */
#define required_argument 1
/** A `has_arg` value for `struct option`. */
#define optional_argument 2

struct option {
  /**
   * Name of long option. Options must have a non-NULL name.
   * A NULL name signals the end of the options array.
   */
  const char * _Nullable name;

  /**
   * One of `no_argument`, `required_argument`, or `optional_argument`.
   */
  int has_arg;

  /** If not NULL, set `*flag` to val when option found. */
  int* _Nullable flag;

  /** If `flag` not NULL, the value to assign to `*flag`; otherwise the return value. */
  int val;
};

__BEGIN_DECLS

/**
 * [getopt_long(3)](https://man7.org/linux/man-pages/man3/getopt.3.html) parses command-line options.
 */
int getopt_long(int __argc, char* _Nonnull const* _Nonnull __argv, const char* _Nonnull __options, const struct option* _Nonnull __long_options, int* _Nullable __long_index);

/**
 * [getopt_long_only(3)](https://man7.org/linux/man-pages/man3/getopt.3.html) parses command-line options.
 */
int getopt_long_only(int __argc, char* _Nonnull const* _Nonnull __argv, const char* _Nonnull __options, const struct option* _Nonnull __long_options, int* _Nullable __long_index);

#ifndef _OPTRESET_DECLARED
#define _OPTRESET_DECLARED
/**
 * Must be set to 1 to reset the `getopt` functions before scanning a new argument vector.
 */
extern int optreset;
#endif

__END_DECLS

"""

```
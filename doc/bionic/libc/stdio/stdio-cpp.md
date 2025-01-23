Response:
Let's break down the thought process for summarizing the `stdio.cpp` file.

**1. Understanding the Goal:**

The core request is to summarize the functionality of the provided C++ source code for `stdio.cpp` from Android's Bionic library. The summary should cover what the code *does*, not how it's implemented in intricate detail (that's for later parts).

**2. Initial Scan for Keywords and Patterns:**

My first step is to quickly scan the code for recognizable patterns and keywords. I'm looking for things like:

* **Includes:** `<stdio.h>`, `<fcntl.h>`, `<unistd.h>`, etc. These hint at standard input/output operations, file control, and system calls.
* **Data Structures:** `FILE`, `__sfileext`, `glue`. These are likely core structures for managing file streams.
* **Function Definitions:**  `fopen`, `fclose`, `fread`, `fwrite`, `printf`, `scanf`, `fseek`, etc. These are the standard C library functions for input/output.
* **Macros:** `MAKE_STD_STREAM`, `PRINTF_IMPL`. These often simplify or customize common operations.
* **Global Variables:** `__sF`, `stdin`, `stdout`, `stderr`. These are the standard file streams.
* **Mutexes:** `pthread_mutex_t`. Indicates thread safety and potential concurrency issues.
* **Android-Specific Includes:** `<android/fdsan.h>`, `<async_safe/log.h>`. These suggest Android-specific features like file descriptor sanitization and asynchronous logging.

**3. Identifying Core Functionality Areas:**

Based on the initial scan, I can start grouping the functionality into logical categories:

* **File Stream Management:** Creating, opening, closing, and managing `FILE` structures. This includes `fopen`, `fclose`, `fdopen`, `freopen`, `__sfp`, and related data structures like `__sF`, `__sfileext`, and `glue`.
* **Standard Streams:** Handling `stdin`, `stdout`, and `stderr`. The code explicitly initializes these.
* **Basic I/O Operations:** Reading and writing data, including formatted I/O. This includes `fread`, `fwrite`, `fgetc`, `fputc`, `fgets`, `fputs`, `fprintf`, `printf`, `scanf`, etc.
* **Seeking and Positioning:** Moving the read/write position within a file. This includes `fseek`, `ftell`, `rewind`, `fgetpos`, `fsetpos`.
* **Buffering:** Managing how data is read from and written to files. This is hinted at by the `_bf` members of the `FILE` structure and functions like `setbuf`, `setvbuf`, `fflush`.
* **Error Handling:**  Functions like `clearerr`, `feof`, `ferror`, and the use of `errno`.
* **Low-Level I/O:** The `_read`, `_write`, `_seek`, and `_close` function pointers within the `FILE` structure indicate the delegation to lower-level system calls.
* **Pipes and Processes:** The `popen` function deals with creating subprocesses and connecting to them via pipes.
* **Android Integration:** The inclusion of `android/fdsan.h` points to the integration with Android's file descriptor sanitization system.

**4. Focusing on the "What," Not the "How" (for this part):**

The prompt specifically asks for a *summary* of functionality in Part 1. Therefore, I avoid getting bogged down in the detailed implementation of each function. Instead, I focus on the *purpose* of each category and the key functions within it.

**5. Drafting the Summary:**

I start drafting the summary section by section, based on the identified functionality areas. I use clear and concise language, avoiding jargon where possible. For example:

* Instead of saying "allocates a `FILE` structure," I might say "manages the allocation of `FILE` structures."
* Instead of listing every possible formatting specifier for `printf`, I would say "provides formatted output functions."

**6. Highlighting Android-Specific Aspects:**

The prompt explicitly asks to highlight connections to Android. I make sure to mention the integration with `android_fdsan` for file descriptor tracking and the provision of standard C library functions within the Android environment.

**7. Emphasizing Key Data Structures:**

The `FILE` structure is central to the functionality, so I make sure to mention its role and some of its key members. The `glue` structure is also important for managing the pool of `FILE` structures.

**8. Review and Refinement:**

Finally, I review the summary to ensure it's accurate, complete (at a high level), and easy to understand. I check for any redundancy or areas where clarity could be improved. I make sure the summary directly addresses the prompt's request for a functional overview.

**Self-Correction/Refinement Example during the process:**

Initially, I might have focused too much on listing individual functions. During the review, I'd realize that grouping them into categories like "File Stream Management" and "Basic I/O Operations" makes the summary more organized and easier to grasp. I would then adjust the wording to reflect these groupings. I might also initially forget to explicitly mention the Android aspects and would add that in during the review.

By following these steps, I can create a comprehensive yet concise summary of the `stdio.cpp` file's functionality, as demonstrated in the provided good example.
这个是 `bionic/libc/stdio/stdio.cpp` 文件的前一部分内容，它定义了 C 标准库中与标准输入输出 (stdio) 相关的许多核心函数。简单来说，这一部分代码主要负责 **文件流的管理和基本的 I/O 操作**。

以下是更详细的归纳：

**主要功能归纳：**

1. **文件流的创建与管理:**
   - **`__sfp()`:**  寻找并分配一个空闲的 `FILE` 结构体，用于表示一个新的文件流。这是 `fopen` 等函数的基础。
   - **`moreglue()`:** 当现有的 `FILE` 结构体不够用时，动态分配更多的 `FILE` 结构体。
   - **`fopen()`/`fopen64()`:** 打开一个由文件名指定的文件，并返回一个与之关联的文件流 (`FILE*`)。
   - **`fdopen()`:**  将一个已有的文件描述符 (`fd`) 关联到一个文件流。
   - **`freopen()`/`freopen64()`:**  将一个已有的文件流与另一个文件或描述符重新关联。
   - **`fclose()`:** 关闭一个文件流，释放相关的资源。
   - **`__FILE_init()`:** 初始化 `FILE` 结构体的成员，例如文件描述符、标志位、读写函数等。
   - **`struct glue`:**  用于管理一组 `FILE` 结构体，方便动态扩展。
   - **全局变量 `__sF`, `stdin`, `stdout`, `stderr`:**  分别代表标准输入、标准输出和标准错误流。它们在程序启动时被初始化。

2. **基本的输入/输出操作:**
   - **`fgetc()`/`getc()`:** 从文件流中读取一个字符。
   - **`fgets()`:** 从文件流中读取一行字符串。
   - **`fputc()`/`putc()`:** 向文件流中写入一个字符。
   - **`fputs()`:** 向文件流中写入一个字符串。
   - **`fread()`:** 从文件流中读取指定大小和数量的数据块。
   - **`fwrite()`:** 向文件流中写入指定大小和数量的数据块。
   - **`getchar()`:** 从标准输入读取一个字符。
   - **`putchar()`:** 向标准输出写入一个字符。
   - **`puts()`:** 向标准输出写入一个字符串并换行。

3. **文件定位操作:**
   - **`fseeko()`/`fseek()`/`fseeko64()`:**  设置文件流的读写位置。
   - **`ftello()`/`ftell()`/`ftello64()`:** 获取文件流的当前读写位置。
   - **`rewind()`:** 将文件流的读写位置重置到文件开头。
   - **`fgetpos()`/`fgetpos64()`:** 获取文件流的当前位置到一个 `fpos_t` 结构体中。
   - **`fsetpos()`/`fsetpos64()`:**  将文件流的读写位置设置为 `fpos_t` 结构体中保存的位置。

4. **错误处理和状态查询:**
   - **`clearerr()`:** 清除文件流的错误标志和文件尾标志。
   - **`feof()`:** 检查文件流是否到达文件尾。
   - **`ferror()`:** 检查文件流是否发生错误。
   - **`perror()`:** 将给定的错误消息和当前的 `errno` 对应的错误描述输出到标准错误流。

5. **缓冲管理:**
   - **`fflush()`:**  刷新文件流的缓冲区，将缓冲区中的数据写入到文件或清空缓冲区。
   - **`setbuf()`/`setbuffer()`:**  设置文件流的缓冲区。
   - **`setlinebuf()`:** 设置文件流为行缓冲模式。
   - **`fpurge()`:** 清空文件流的缓冲区。

6. **与系统调用的交互:**
   - 代码中直接调用了底层的系统调用，例如 `open()`, `close()`, `read()`, `write()`, `lseek()`, `lseek64()`, `pipe2()`, `socketpair()`, `dup2()`, `vfork()`, `execve()`, `wait4()`, `unlink()`, `rmdir()`. 这些系统调用是文件 I/O 的基础。

7. **`popen()`:** 创建一个子进程执行指定的命令，并返回一个可以读取子进程输出或向子进程输入的文件流。

8. **`funopen()`/`funopen64()`:** 允许用户自定义读、写、定位和关闭函数，创建一个自定义行为的文件流。

9. **线程安全:**
   - 使用互斥锁 (`pthread_mutex_t __stdio_mutex`) 来保护对全局 `FILE` 结构体列表的访问，确保线程安全。
   - `ScopedFileLock` 类用于在访问单个 `FILE` 结构体时进行加锁和解锁操作。

10. **Android 特性集成:**
    - **`android/fdsan.h`:**  集成了 Android 的文件描述符安全 (fdsan) 机制，用于跟踪文件描述符的所有权，防止 double free 等问题。`__get_file_tag()` 和 `android_fdsan_exchange_owner_tag()` 等函数用于与 fdsan 进行交互。
    - **`async_safe/log.h`:** 引入了异步安全的日志功能，但在这部分代码中似乎没有直接使用。

**与 Android 功能的关系和举例说明：**

由于 `bionic` 是 Android 的 C 库，这个文件中的所有功能都是 Android 系统中应用程序进行文件和标准输入输出的基础。

- **应用程序读写文件:** 任何 Android 应用程序，无论是 Java/Kotlin 代码通过 NDK 调用 C/C++ 代码，还是纯 C/C++ 应用程序，如果需要读写文件，都会最终调用到这里的 `fopen`, `fread`, `fwrite`, `fclose` 等函数。 例如，一个图片处理应用需要读取手机存储中的图片文件，就会使用这些函数。
- **标准输入输出:**  当你在 Android 终端 (例如通过 ADB shell) 运行一个命令行工具时，该工具使用的 `printf` 输出到屏幕，`scanf` 从键盘读取输入，都会经过这里的 `stdout` 和 `stdin` 的实现。
- **管道操作:**  在 Android 系统中，进程间通信经常使用管道。`popen` 函数允许创建一个子进程并与其建立管道连接，这在执行一些系统命令或与其他进程交互时非常有用。例如，一个应用可能使用 `popen` 来执行 `ls` 命令并获取文件列表。
- **日志记录:**  虽然这部分代码没有直接使用 `async_safe/log.h`，但 `fprintf(stderr, ...)` 是将错误信息输出到标准错误流的常用方式，这些错误信息可能会被 Android 的日志系统捕获。
- **文件描述符安全:** Android 使用 `fdsan` 来提高系统稳定性，防止文件描述符的滥用。这里的代码集成了 `fdsan`，确保文件描述符的正确管理。

**libc 函数的实现解释：**

由于篇幅限制，这里只解释几个关键函数的实现思路：

- **`fopen(const char* file, const char* mode)`:**
    1. **解析模式:**  `__sflags(mode, &mode_flags)` 函数根据传入的模式字符串 (如 "r", "w", "rb") 解析出对应的文件打开标志 (例如 `O_RDONLY`, `O_WRONLY`, `O_CREAT` 等)。
    2. **打开文件:** 调用底层的 `open(file, mode_flags, DEFFILEMODE)` 系统调用打开指定的文件。如果打开失败，返回 `nullptr`。
    3. **分配文件流:** 调用 `__sfp()` 获取一个空闲的 `FILE` 结构体。
    4. **初始化文件流:** 调用 `__FILE_init()` 初始化 `FILE` 结构体的成员，将文件描述符与文件流关联起来，并设置读写函数等。
    5. **处理追加模式:** 如果模式中包含 'a' (追加)，则使用 `__sseek64(fp, 0, SEEK_END)` 将文件指针移动到文件末尾。
    6. **返回文件流指针:** 返回新创建的 `FILE` 结构体的指针。

- **`fread(void* buf, size_t size, size_t count, FILE* fp)`:**
    1. **参数校验:** 检查 `fp` 是否有效。
    2. **计算总字节数:** 计算需要读取的总字节数 `size * count`，并防止溢出。
    3. **处理零字节读取:** 如果总字节数为 0，直接返回 0。
    4. **设置字节流方向:** 调用 `_SET_ORIENTATION(fp, ORIENT_BYTES)` 确保文件流按字节读取。
    5. **处理缓冲区:**
       - 如果文件流有缓冲区，先从缓冲区中读取数据。
       - 如果缓冲区的数据不足，并且需要读取的数据量大于缓冲区大小，则直接调用底层的 `read()` 系统调用读取数据到用户提供的缓冲区。
       - 否则，调用 `__srefill()` 填充缓冲区，然后再从缓冲区读取数据。
    6. **处理错误:** 如果读取过程中发生错误或到达文件尾，设置文件流的错误标志或文件尾标志。
    7. **返回读取的元素数量:** 返回实际读取的元素数量 (总读取字节数 / `size`)。

- **`popen(const char* cmd, const char* mode)`:**
    1. **创建管道/套接字对:** 根据 `mode` 创建一个管道 (`pipe2`) 或套接字对 (`socketpair`)，用于父子进程间的通信。
    2. **创建子进程:** 使用 `vfork()` 创建子进程。`vfork` 与 `fork` 类似，但子进程共享父进程的内存空间，因此更高效，但也需要注意安全问题。
    3. **子进程操作:**
       - 关闭不需要的文件描述符。
       - 使用 `dup2()` 将管道/套接字的读端或写端重定向到标准输入或标准输出。
       - 调用 `execve()` 执行指定的命令。如果执行失败，调用 `_exit(127)` 退出。
    4. **父进程操作:**
       - 关闭不需要的文件描述符。
       - 调用 `__FILE_init()` 创建一个 `FILE` 结构体，并将管道/套接字的另一端与该文件流关联。
       - 记录子进程的 PID，以便在 `pclose()` 时等待子进程结束。
       - 返回指向文件流的指针。

**涉及 dynamic linker 的功能：**

这部分代码主要关注标准 I/O 功能的实现，并没有直接涉及动态链接器的具体操作。动态链接器 (linker) 的主要职责是加载共享库 (SO 文件) 并解析符号引用。

**SO 布局样本和链接处理过程 (简述):**

假设我们有一个简单的 C 程序 `my_app.c`，它使用了 `stdio.h` 中的 `printf` 函数：

```c
#include <stdio.h>

int main() {
  printf("Hello, world!\n");
  return 0;
}
```

编译这个程序：

```bash
aarch64-linux-android-clang my_app.c -o my_app
```

生成的 `my_app` 可执行文件会依赖于 `libc.so` (Android 的 C 库)。

**SO 布局样本 (libc.so 的部分):**

```
libc.so:
    .text:  // 代码段，包含 printf 等函数的机器码
        ... (printf 函数的机器码) ...
    .data:  // 已初始化数据段，包含全局变量
        ... (__sF, stdin, stdout, stderr 等) ...
    .bss:   // 未初始化数据段
        ...
    .dynamic: // 动态链接信息
        DT_NEEDED: libm.so  // 依赖的共享库
        DT_SYMBOLIC: 1
        ...
    .symtab: // 符号表，包含导出的符号
        ... (printf 符号) ...
    .strtab: // 字符串表，包含符号名等字符串
        ... ("printf") ...
    ...
```

**链接处理过程 (运行时):**

1. **加载器启动:** 当 Android 系统执行 `my_app` 时，内核会启动一个加载器进程 (zygote fork 出的进程)。
2. **加载可执行文件:** 加载器将 `my_app` 的代码和数据加载到内存中。
3. **解析动态链接信息:** 加载器解析 `my_app` 的 `.dynamic` 段，找到它依赖的共享库 (例如 `libc.so`)。
4. **加载共享库:** 加载器将 `libc.so` 加载到内存中。
5. **符号解析 (Linking):**
   - 加载器遍历 `my_app` 中未定义的符号 (例如 `printf`)。
   - 它在 `libc.so` 的符号表 (`.symtab`) 中查找匹配的符号。
   - 找到 `printf` 的定义后，加载器会将 `my_app` 中调用 `printf` 的指令地址重定向到 `libc.so` 中 `printf` 函数的实际地址。这个过程称为 **符号重定位 (Symbol Relocation)**。
6. **执行程序:** 链接完成后，程序开始执行。当执行到 `printf("Hello, world!\n");` 时，实际上会跳转到 `libc.so` 中 `printf` 函数的代码执行。

**假设输入与输出 (逻辑推理):**

假设我们调用 `fopen("test.txt", "w")`:

- **假设输入:**
    - `file`: 指向字符串 "test.txt" 的指针。
    - `mode`: 指向字符串 "w" 的指针。
- **逻辑推理:**
    - `__sflags("w", ...)` 会解析出 `O_WRONLY | O_CREAT | O_TRUNC` 等标志。
    - `open("test.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666)` 系统调用会被执行，创建一个名为 "test.txt" 的新文件，如果文件已存在则清空内容。
    - `__sfp()` 会分配一个新的 `FILE` 结构体。
    - `__FILE_init()` 会初始化这个 `FILE` 结构体，将打开的文件描述符与它关联。
- **预期输出:**
    - 如果文件创建成功，`fopen` 返回一个指向新创建的 `FILE` 结构体的指针。
    - 如果文件创建失败 (例如权限不足)，`fopen` 返回 `nullptr`，并且 `errno` 会被设置为相应的错误码。

**用户或编程常见的使用错误举例：**

1. **忘记检查 `fopen` 的返回值:**

   ```c
   FILE *fp = fopen("myfile.txt", "r");
   // 假设文件不存在，fp 为 NULL
   char buffer[100];
   fgets(buffer, sizeof(buffer), fp); // 错误：尝试访问空指针
   ```

   应该始终检查 `fopen` 的返回值，以确保文件成功打开。

2. **使用错误的 `fopen` 模式:**

   ```c
   FILE *fp = fopen("output.txt", "r"); // 尝试以只读模式打开，如果文件不存在则失败
   fprintf(fp, "Some data");           // 错误：尝试向只读文件写入
   ```

   需要根据文件的用途选择正确的打开模式。

3. **忘记 `fclose` 关闭文件:**

   ```c
   FILE *fp = fopen("temp.txt", "w");
   fprintf(fp, "Data");
   // 忘记 fclose(fp);
   ```

   忘记关闭文件可能会导致数据丢失、资源泄漏等问题。

4. **缓冲区溢出:**

   ```c
   FILE *fp = fopen("input.txt", "r");
   char buffer[10];
   fgets(buffer, sizeof(buffer), fp); // 如果 input.txt 中的一行超过 9 个字符，则会发生缓冲区溢出
   ```

   使用 `fgets` 等函数时，需要确保提供的缓冲区足够大，以防止溢出。

**Android Framework 或 NDK 如何到达这里，给出 Frida Hook 示例调试这些步骤：**

1. **Java/Kotlin 代码使用 `java.io.FileOutputStream` 等类:**
   - 在 Android Framework 中，Java 或 Kotlin 代码通常使用 `java.io.FileOutputStream`, `java.io.FileInputStream`, `java.io.FileWriter`, `java.io.FileReader` 等类进行文件操作。

2. **调用到 Native 代码:**
   - 这些 Java 类最终会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 中的 native 代码。

3. **ART 调用 Bionic libc:**
   - ART 的 native 代码会调用到 `bionic` 库中相应的 C 函数，例如 `open()`, `read()`, `write()`, `close()` 等。

4. **`fdopen` 连接 Java File Descriptor:**
   - 当 Java 代码创建一个文件流时，ART 可能会先获取一个文件描述符，然后使用 `fdopen()` 将这个文件描述符与 `bionic` 的 `FILE` 结构体关联起来。

5. **最终调用 `stdio.cpp` 中的函数:**
   - 当 Java 代码调用 `write()` 或 `read()` 等方法时，最终会通过 ART 调用到 `bionic/libc/stdio/stdio.cpp` 中实现的 `fwrite` 或 `fread` 等函数。

**Frida Hook 示例：**

可以使用 Frida hook `fopen` 函数，查看其被调用的情况：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['function'], message['payload']['args']))
    else:
        print(message)

def main():
    package_name = "your.target.package"  # 替换为目标应用的包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"未找到进程: {package_name}")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var filename = Memory.readUtf8String(args[0]);
            var mode = Memory.readUtf8String(args[1]);
            send({ function: "fopen", args: [filename, mode] });
        },
        onLeave: function(retval) {
            // 可以添加对返回值的处理
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] 运行中，按 Ctrl+C 退出...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法：**

1. 确保你的 Android 设备已连接并启用 USB 调试。
2. 安装 Frida 和 Python 的 Frida 模块。
3. 将 `your.target.package` 替换为你想要监控的 Android 应用的包名。
4. 运行该 Python 脚本。
5. 在你的 Android 设备上操作目标应用，例如进行文件读写操作。
6. Frida 会捕获对 `fopen` 函数的调用，并打印出文件名和打开模式。

通过类似的方式，你可以 hook 其他 `stdio.cpp` 中的函数，例如 `fread`, `fwrite`, `fclose` 等，以调试 Android Framework 或 NDK 如何一步步地调用到这些函数。

### 提示词
```
这是目录为bionic/libc/stdio/stdio.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*	$OpenBSD: findfp.c,v 1.15 2013/12/17 16:33:27 deraadt Exp $ */
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

#define __BIONIC_NO_STDIO_FORTIFY
#include <stdio.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/fdsan.h>

#include <async_safe/log.h>

#include "glue.h"
#include "local.h"
#include "private/ErrnoRestorer.h"
#include "private/FdPath.h"
#include "private/__bionic_get_shell_path.h"
#include "private/bionic_fortify.h"
#include "private/thread_private.h"

#define	NDYNAMIC 10		/* add ten more whenever necessary */

#define PRINTF_IMPL(expr) \
    va_list ap; \
    va_start(ap, fmt); \
    int result = (expr); \
    va_end(ap); \
    return result;

#define MAKE_STD_STREAM(flags, fd)                                          \
  {                                                                         \
    ._flags = flags, ._file = fd, ._cookie = __sF + fd, ._close = __sclose, \
    ._read = __sread, ._write = __swrite, ._ext = {                         \
      ._base = reinterpret_cast<uint8_t*>(__sFext + fd)                     \
    }                                                                       \
  }

static struct __sfileext __sFext[3] = {
    {._lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP,
     ._caller_handles_locking = false,
     ._seek64 = __sseek64,
     ._popen_pid = 0},
    {._lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP,
     ._caller_handles_locking = false,
     ._seek64 = __sseek64,
     ._popen_pid = 0},
    {._lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP,
     ._caller_handles_locking = false,
     ._seek64 = __sseek64,
     ._popen_pid = 0},
};

// __sF is exported for backwards compatibility. Until M, we didn't have symbols
// for stdin/stdout/stderr; they were macros accessing __sF.
FILE __sF[3] = {
    MAKE_STD_STREAM(__SRD, STDIN_FILENO),
    MAKE_STD_STREAM(__SWR, STDOUT_FILENO),
    MAKE_STD_STREAM(__SWR|__SNBF, STDERR_FILENO),
};

FILE* stdin = &__sF[0];
FILE* stdout = &__sF[1];
FILE* stderr = &__sF[2];

static pthread_mutex_t __stdio_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t __get_file_tag(FILE* fp) {
  // Don't use a tag for the standard streams.
  // They don't really own their file descriptors, because the values are well-known, and you're
  // allowed to do things like `close(STDIN_FILENO); open("foo", O_RDONLY)` when single-threaded.
  if (fp == stdin || fp == stderr || fp == stdout) {
    return 0;
  }

  return android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_FILE,
                                        reinterpret_cast<uint64_t>(fp));
}

struct glue __sglue = { nullptr, 3, __sF };
static struct glue* lastglue = &__sglue;

class ScopedFileLock {
 public:
  explicit ScopedFileLock(FILE* fp) : fp_(fp) {
    FLOCKFILE(fp_);
  }
  ~ScopedFileLock() {
    FUNLOCKFILE(fp_);
  }

 private:
  FILE* fp_;
};

static glue* moreglue(int n) {
  char* data = new char[sizeof(glue) +
                        alignof(FILE) + n * sizeof(FILE) +
                        alignof(__sfileext) + n * sizeof(__sfileext)];
  if (data == nullptr) return nullptr;

  glue* g = reinterpret_cast<glue*>(data);
  FILE* p = reinterpret_cast<FILE*>(__builtin_align_up(g + 1, alignof(FILE)));
  __sfileext* pext = reinterpret_cast<__sfileext*>(__builtin_align_up(p + n, alignof(__sfileext)));
  g->next = nullptr;
  g->niobs = n;
  g->iobs = p;
  while (--n >= 0) {
    *p = {};
    _FILEEXT_SETUP(p, pext);
    p++;
    pext++;
  }
  return g;
}

static inline void free_fgetln_buffer(FILE* fp) {
  if (__predict_false(fp->_lb._base != nullptr)) {
    free(fp->_lb._base);
    fp->_lb._base = nullptr;
  }
}

/*
 * Find a free FILE for fopen et al.
 */
FILE* __sfp(void) {
	FILE *fp;
	int n;
	struct glue *g;

	pthread_mutex_lock(&__stdio_mutex);
	for (g = &__sglue; g != nullptr; g = g->next) {
		for (fp = g->iobs, n = g->niobs; --n >= 0; fp++)
			if (fp->_flags == 0)
				goto found;
	}

	/* release lock while mallocing */
	pthread_mutex_unlock(&__stdio_mutex);
	if ((g = moreglue(NDYNAMIC)) == nullptr) return nullptr;
	pthread_mutex_lock(&__stdio_mutex);
	lastglue->next = g;
	lastglue = g;
	fp = g->iobs;
found:
	fp->_flags = 1;		/* reserve this slot; caller sets real flags */
	pthread_mutex_unlock(&__stdio_mutex);
	fp->_p = nullptr;		/* no current pointer */
	fp->_w = 0;		/* nothing to read or write */
	fp->_r = 0;
	fp->_bf._base = nullptr;	/* no buffer */
	fp->_bf._size = 0;
	fp->_lbfsize = 0;	/* not line buffered */
	fp->_file = -1;		/* no file */

	fp->_lb._base = nullptr;	/* no line buffer */
	fp->_lb._size = 0;

	memset(_EXT(fp), 0, sizeof(struct __sfileext));
	_EXT(fp)->_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
	_EXT(fp)->_caller_handles_locking = false;

	// Caller sets cookie, _read/_write etc.
	// We explicitly clear _seek and _seek64 to prevent subtle bugs.
	fp->_seek = nullptr;
	_EXT(fp)->_seek64 = nullptr;

	return fp;
}

int _fwalk(int (*callback)(FILE*)) {
  int result = 0;
  for (glue* g = &__sglue; g != nullptr; g = g->next) {
    FILE* fp = g->iobs;
    for (int n = g->niobs; --n >= 0; ++fp) {
      if (fp->_flags != 0 && (fp->_flags & __SIGN) == 0) {
        result |= (*callback)(fp);
      }
    }
  }
  return result;
}

extern "C" __LIBC_HIDDEN__ void __libc_stdio_cleanup(void) {
  // Equivalent to fflush(nullptr), but without all the locking since we're shutting down anyway.
  _fwalk(__sflush);
}

static FILE* __FILE_init(FILE* fp, int fd, int flags) {
  if (fp == nullptr) return nullptr;

#if !defined(__LP64__)
  if (fd > SHRT_MAX) __fortify_fatal("stdio: fd %d > SHRT_MAX", fd);
#endif

  fp->_file = fd;
  android_fdsan_exchange_owner_tag(fd, 0, __get_file_tag(fp));
  fp->_flags = flags;
  fp->_cookie = fp;
  fp->_read = __sread;
  fp->_write = __swrite;
  fp->_close = __sclose;
  _EXT(fp)->_seek64 = __sseek64;
  return fp;
}

FILE* fopen(const char* file, const char* mode) {
  int mode_flags;
  int flags = __sflags(mode, &mode_flags);
  if (flags == 0) return nullptr;

  int fd = open(file, mode_flags, DEFFILEMODE);
  if (fd == -1) {
    return nullptr;
  }

  FILE* fp = __FILE_init(__sfp(), fd, flags);
  if (fp == nullptr) {
    ErrnoRestorer errno_restorer;
    close(fd);
    return nullptr;
  }

  // For append mode, O_APPEND sets the write position for free, but we need to
  // set the read position manually.
  if ((mode_flags & O_APPEND) != 0) __sseek64(fp, 0, SEEK_END);
  return fp;
}
__strong_alias(fopen64, fopen);

FILE* fdopen(int fd, const char* mode) {
  int mode_flags;
  int flags = __sflags(mode, &mode_flags);
  if (flags == 0) return nullptr;

  // Make sure the mode the user wants is a subset of the actual mode.
  int fd_flags = fcntl(fd, F_GETFL, 0);
  if (fd_flags == -1) return nullptr;
  int tmp = fd_flags & O_ACCMODE;
  if (tmp != O_RDWR && (tmp != (mode_flags & O_ACCMODE))) {
    errno = EINVAL;
    return nullptr;
  }

  // Make sure O_APPEND is set on the underlying fd if our mode has 'a'.
  // POSIX says we just take the current offset of the underlying fd.
  if ((mode_flags & O_APPEND) && !(fd_flags & O_APPEND)) {
    if (fcntl(fd, F_SETFL, fd_flags | O_APPEND) == -1) return nullptr;
  }

  // Make sure O_CLOEXEC is set on the underlying fd if our mode has 'e'.
  if ((mode_flags & O_CLOEXEC) && !((tmp = fcntl(fd, F_GETFD)) & FD_CLOEXEC)) {
    fcntl(fd, F_SETFD, tmp | FD_CLOEXEC);
  }

  return __FILE_init(__sfp(), fd, flags);
}

FILE* freopen(const char* file, const char* mode, FILE* fp) {
  CHECK_FP(fp);

  // POSIX says: "If pathname is a null pointer, the freopen() function shall
  // attempt to change the mode of the stream to that specified by mode, as if
  // the name of the file currently associated with the stream had been used. In
  // this case, the file descriptor associated with the stream need not be
  // closed if the call to freopen() succeeds. It is implementation-defined
  // which changes of mode are permitted (if any), and under what
  // circumstances."
  //
  // Linux is quite restrictive about what changes you can make with F_SETFL,
  // and in particular won't let you touch the access bits. It's easiest and
  // most effective to just rely on /proc/self/fd/...
  FdPath fd_path(fp->_file);
  if (file == nullptr) file = fd_path.c_str();

  int mode_flags;
  int flags = __sflags(mode, &mode_flags);
  if (flags == 0) {
    fclose(fp);
    return nullptr;
  }

  ScopedFileLock sfl(fp);

  // TODO: rewrite this mess completely.

  // There are actually programs that depend on being able to "freopen"
  // descriptors that weren't originally open.  Keep this from breaking.
  // Remember whether the stream was open to begin with, and which file
  // descriptor (if any) was associated with it.  If it was attached to
  // a descriptor, defer closing it; freopen("/dev/stdin", "r", stdin)
  // should work.  This is unnecessary if it was not a Unix file.
  int isopen, wantfd;
  if (fp->_flags == 0) {
    fp->_flags = __SEOF; // Hold on to it.
    isopen = 0;
    wantfd = -1;
  } else {
    // Flush the stream; ANSI doesn't require this.
    if (fp->_flags & __SWR) __sflush(fp);

    // If close is null, closing is a no-op, hence pointless.
    isopen = (fp->_close != nullptr);
    if ((wantfd = fp->_file) < 0 && isopen) {
        (*fp->_close)(fp->_cookie);
        isopen = 0;
    }
  }

  // Get a new descriptor to refer to the new file.
  int fd = open(file, mode_flags, DEFFILEMODE);
  if (fd < 0 && isopen) {
    // If out of fd's close the old one and try again.
    if (errno == ENFILE || errno == EMFILE) {
      (*fp->_close)(fp->_cookie);
      isopen = 0;
      fd = open(file, mode_flags, DEFFILEMODE);
    }
  }

  int sverrno = errno;

  // Finish closing fp.  Even if the open succeeded above, we cannot
  // keep fp->_base: it may be the wrong size.  This loses the effect
  // of any setbuffer calls, but stdio has always done this before.
  if (isopen && fd != wantfd) (*fp->_close)(fp->_cookie);
  if (fp->_flags & __SMBF) free(fp->_bf._base);
  fp->_w = 0;
  fp->_r = 0;
  fp->_p = nullptr;
  fp->_bf._base = nullptr;
  fp->_bf._size = 0;
  fp->_lbfsize = 0;
  if (HASUB(fp)) FREEUB(fp);
  _UB(fp)._size = 0;
  WCIO_FREE(fp);
  free_fgetln_buffer(fp);
  fp->_lb._size = 0;

  if (fd < 0) { // Did not get it after all.
    fp->_flags = 0; // Release.
    errno = sverrno; // Restore errno in case _close clobbered it.
    return nullptr;
  }

  // If reopening something that was open before on a real file, try
  // to maintain the descriptor.  Various C library routines (perror)
  // assume stderr is always fd STDERR_FILENO, even if being freopen'd.
  if (wantfd >= 0 && fd != wantfd) {
    if (dup3(fd, wantfd, mode_flags & O_CLOEXEC) >= 0) {
      close(fd);
      fd = wantfd;
    }
  }

  __FILE_init(fp, fd, flags);

  // For append mode, O_APPEND sets the write position for free, but we need to
  // set the read position manually.
  if ((mode_flags & O_APPEND) != 0) __sseek64(fp, 0, SEEK_END);

  return fp;
}
__strong_alias(freopen64, freopen);

static int __FILE_close(FILE* fp) {
  if (fp->_flags == 0) {
    // Already freed!
    errno = EBADF;
    return EOF;
  }

  ScopedFileLock sfl(fp);
  WCIO_FREE(fp);
  int r = fp->_flags & __SWR ? __sflush(fp) : 0;
  if (fp->_close != nullptr && (*fp->_close)(fp->_cookie) < 0) {
    r = EOF;
  }
  if (fp->_flags & __SMBF) free(fp->_bf._base);
  if (HASUB(fp)) FREEUB(fp);
  free_fgetln_buffer(fp);

  // If we were created by popen(3), wait for the child.
  pid_t pid = _EXT(fp)->_popen_pid;
  if (pid > 0) {
    int status;
    if (TEMP_FAILURE_RETRY(wait4(pid, &status, 0, nullptr)) != -1) {
      r = status;
    }
  }
  _EXT(fp)->_popen_pid = 0;

  // Poison this FILE so accesses after fclose will be obvious.
  fp->_file = -1;
  fp->_r = fp->_w = 0;

  // Release this FILE for reuse.
  fp->_flags = 0;
  return r;
}

int fclose(FILE* fp) {
  CHECK_FP(fp);
  return __FILE_close(fp);
}

int fileno_unlocked(FILE* fp) {
  CHECK_FP(fp);
  int fd = fp->_file;
  if (fd == -1) {
    errno = EBADF;
    return -1;
  }
  return fd;
}

int fileno(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return fileno_unlocked(fp);
}

void clearerr_unlocked(FILE* fp) {
  CHECK_FP(fp);
  return __sclearerr(fp);
}

void clearerr(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  clearerr_unlocked(fp);
}

int feof_unlocked(FILE* fp) {
  CHECK_FP(fp);
  return ((fp->_flags & __SEOF) != 0);
}

int feof(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return feof_unlocked(fp);
}

int ferror_unlocked(FILE* fp) {
  CHECK_FP(fp);
  return __sferror(fp);
}

int ferror(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return ferror_unlocked(fp);
}

int __sflush(FILE* fp) {
  // Flushing a read-only file is a no-op.
  if ((fp->_flags & __SWR) == 0) return 0;

  // Flushing a file without a buffer is a no-op.
  unsigned char* p = fp->_bf._base;
  if (p == nullptr) return 0;

  // Set these immediately to avoid problems with longjmp and to allow
  // exchange buffering (via setvbuf) in user write function.
  int n = fp->_p - p;
  fp->_p = p;
  fp->_w = (fp->_flags & (__SLBF|__SNBF)) ? 0 : fp->_bf._size;

  while (n > 0) {
    int written = (*fp->_write)(fp->_cookie, reinterpret_cast<char*>(p), n);
    if (written <= 0) {
      fp->_flags |= __SERR;
      return EOF;
    }
    n -= written, p += written;
  }
  return 0;
}

int __sflush_locked(FILE* fp) {
  ScopedFileLock sfl(fp);
  return __sflush(fp);
}

int __sread(void* cookie, char* buf, int n) {
  FILE* fp = reinterpret_cast<FILE*>(cookie);
  return TEMP_FAILURE_RETRY(read(fp->_file, buf, n));
}

int __swrite(void* cookie, const char* buf, int n) {
  FILE* fp = reinterpret_cast<FILE*>(cookie);
  return TEMP_FAILURE_RETRY(write(fp->_file, buf, n));
}

fpos_t __sseek(void* cookie, fpos_t offset, int whence) {
  FILE* fp = reinterpret_cast<FILE*>(cookie);
  return TEMP_FAILURE_RETRY(lseek(fp->_file, offset, whence));
}

off64_t __sseek64(void* cookie, off64_t offset, int whence) {
  FILE* fp = reinterpret_cast<FILE*>(cookie);
  return TEMP_FAILURE_RETRY(lseek64(fp->_file, offset, whence));
}

int __sclose(void* cookie) {
  FILE* fp = reinterpret_cast<FILE*>(cookie);
  return android_fdsan_close_with_tag(fp->_file, __get_file_tag(fp));
}

static off64_t __seek_unlocked(FILE* fp, off64_t offset, int whence) {
  // Use `_seek64` if set, but fall back to `_seek`.
  if (_EXT(fp)->_seek64 != nullptr) {
    return (*_EXT(fp)->_seek64)(fp->_cookie, offset, whence);
  } else if (fp->_seek != nullptr) {
    off64_t result = (*fp->_seek)(fp->_cookie, offset, whence);
#if !defined(__LP64__)
    // Avoid sign extension if off64_t is larger than off_t.
    if (result != -1) result &= 0xffffffff;
#endif
    return result;
  } else {
    errno = ESPIPE;
    return -1;
  }
}

static off64_t __ftello64_unlocked(FILE* fp) {
  // Find offset of underlying I/O object, then adjust for buffered bytes.
  __sflush(fp);  // May adjust seek offset on append stream.

  off64_t result = __seek_unlocked(fp, 0, SEEK_CUR);
  if (result == -1) {
    return -1;
  }

  if (fp->_flags & __SRD) {
    // Reading.  Any unread characters (including
    // those from ungetc) cause the position to be
    // smaller than that in the underlying object.
    result -= fp->_r;
    if (HASUB(fp)) result -= fp->_ur;
  } else if (fp->_flags & __SWR && fp->_p != nullptr) {
    // Writing.  Any buffered characters cause the
    // position to be greater than that in the
    // underlying object.
    result += fp->_p - fp->_bf._base;
  }
  return result;
}

int __fseeko64(FILE* fp, off64_t offset, int whence, int off_t_bits) {
  ScopedFileLock sfl(fp);

  // Change any SEEK_CUR to SEEK_SET, and check `whence` argument.
  // After this, whence is either SEEK_SET or SEEK_END.
  if (whence == SEEK_CUR) {
    fpos64_t current_offset = __ftello64_unlocked(fp);
    if (current_offset == -1) {
      return -1;
    }
    offset += current_offset;
    whence = SEEK_SET;
  } else if (whence != SEEK_SET && whence != SEEK_END) {
    errno = EINVAL;
    return -1;
  }

  // If our caller has a 32-bit interface, refuse to go past a 32-bit file offset.
  if (off_t_bits == 32 && offset > LONG_MAX) {
    errno = EOVERFLOW;
    return -1;
  }

  if (fp->_bf._base == nullptr) __smakebuf(fp);

  // Flush unwritten data and attempt the seek.
  if (__sflush(fp) || __seek_unlocked(fp, offset, whence) == -1) {
    return -1;
  }

  // Success: clear EOF indicator and discard ungetc() data.
  if (HASUB(fp)) FREEUB(fp);
  fp->_p = fp->_bf._base;
  fp->_r = 0;
  /* fp->_w = 0; */	/* unnecessary (I think...) */
  fp->_flags &= ~__SEOF;
  return 0;
}

int fseeko(FILE* fp, off_t offset, int whence) {
  CHECK_FP(fp);
  static_assert(sizeof(off_t) == sizeof(long), "sizeof(off_t) != sizeof(long)");
  return __fseeko64(fp, offset, whence, 8*sizeof(off_t));
}
__strong_alias(fseek, fseeko);

int fseeko64(FILE* fp, off64_t offset, int whence) {
  CHECK_FP(fp);
  return __fseeko64(fp, offset, whence, 8*sizeof(off64_t));
}

int fsetpos(FILE* fp, const fpos_t* pos) {
  CHECK_FP(fp);
  return fseeko(fp, *pos, SEEK_SET);
}

int fsetpos64(FILE* fp, const fpos64_t* pos) {
  CHECK_FP(fp);
  return fseeko64(fp, *pos, SEEK_SET);
}

off_t ftello(FILE* fp) {
  CHECK_FP(fp);
  static_assert(sizeof(off_t) == sizeof(long), "sizeof(off_t) != sizeof(long)");
  off64_t result = ftello64(fp);
  if (result > LONG_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  return result;
}
__strong_alias(ftell, ftello);

off64_t ftello64(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return __ftello64_unlocked(fp);
}

int fgetpos(FILE* fp, fpos_t* pos) {
  CHECK_FP(fp);
  *pos = ftello(fp);
  return (*pos == -1) ? -1 : 0;
}

int fgetpos64(FILE* fp, fpos64_t* pos) {
  CHECK_FP(fp);
  *pos = ftello64(fp);
  return (*pos == -1) ? -1 : 0;
}

static FILE* __funopen(const void* cookie,
                       int (*read_fn)(void*, char*, int),
                       int (*write_fn)(void*, const char*, int),
                       int (*close_fn)(void*)) {
  if (read_fn == nullptr && write_fn == nullptr) {
    errno = EINVAL;
    return nullptr;
  }

  FILE* fp = __sfp();
  if (fp == nullptr) return nullptr;

  if (read_fn != nullptr && write_fn != nullptr) {
    fp->_flags = __SRW;
  } else if (read_fn != nullptr) {
    fp->_flags = __SRD;
  } else if (write_fn != nullptr) {
    fp->_flags = __SWR;
  }

  fp->_file = -1;
  fp->_cookie = const_cast<void*>(cookie); // The funopen(3) API is incoherent.
  fp->_read = read_fn;
  fp->_write = write_fn;
  fp->_close = close_fn;

  return fp;
}

FILE* funopen(const void* cookie,
              int (*read_fn)(void*, char*, int),
              int (*write_fn)(void*, const char*, int),
              fpos_t (*seek_fn)(void*, fpos_t, int),
              int (*close_fn)(void*)) {
  FILE* fp = __funopen(cookie, read_fn, write_fn, close_fn);
  if (fp != nullptr) {
    fp->_seek = seek_fn;
  }
  return fp;
}

FILE* funopen64(const void* cookie,
                int (*read_fn)(void*, char*, int),
                int (*write_fn)(void*, const char*, int),
                fpos64_t (*seek_fn)(void*, fpos64_t, int),
                int (*close_fn)(void*)) {
  FILE* fp = __funopen(cookie, read_fn, write_fn, close_fn);
  if (fp != nullptr) {
    _EXT(fp)->_seek64 = seek_fn;
  }
  return fp;
}

int asprintf(char** s, const char* fmt, ...) {
  PRINTF_IMPL(vasprintf(s, fmt, ap));
}

char* ctermid(char* s) {
  return s ? strcpy(s, _PATH_TTY) : const_cast<char*>(_PATH_TTY);
}

int dprintf(int fd, const char* fmt, ...) {
  PRINTF_IMPL(vdprintf(fd, fmt, ap));
}

int fprintf(FILE* fp, const char* fmt, ...) {
  CHECK_FP(fp);
  PRINTF_IMPL(vfprintf(fp, fmt, ap));
}

int fgetc(FILE* fp) {
  CHECK_FP(fp);
  return getc(fp);
}

int fgetc_unlocked(FILE* fp) {
  CHECK_FP(fp);
  return getc_unlocked(fp);
}

char* fgets(char* buf, int n, FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return fgets_unlocked(buf, n, fp);
}

// Reads at most n-1 characters from the given file.
// Stops when a newline has been read, or the count runs out.
// Returns first argument, or nullptr if no characters were read.
// Does not return nullptr if n == 1.
char* fgets_unlocked(char* buf, int n, FILE* fp) {
  if (n <= 0) __fortify_fatal("fgets: buffer size %d <= 0", n);

  _SET_ORIENTATION(fp, ORIENT_BYTES);

  char* s = buf;
  n--; // Leave space for NUL.
  while (n != 0) {
    // If the buffer is empty, refill it.
    if (fp->_r <= 0) {
      if (__srefill(fp)) {
        // EOF/error: stop with partial or no line.
        if (s == buf) return nullptr;
        break;
      }
    }
    size_t len = fp->_r;
    unsigned char* p = fp->_p;

    // Scan through at most n bytes of the current buffer,
    // looking for '\n'.  If found, copy up to and including
    // newline, and stop.  Otherwise, copy entire chunk and loop.
    if (len > static_cast<size_t>(n)) len = n;
    unsigned char* t = static_cast<unsigned char*>(memchr(p, '\n', len));
    if (t != nullptr) {
      len = ++t - p;
      fp->_r -= len;
      fp->_p = t;
      memcpy(s, p, len);
      s[len] = '\0';
      return buf;
    }
    fp->_r -= len;
    fp->_p += len;
    memcpy(s, p, len);
    s += len;
    n -= len;
  }
  *s = '\0';
  return buf;
}

int fputc(int c, FILE* fp) {
  CHECK_FP(fp);
  return putc(c, fp);
}

int fputc_unlocked(int c, FILE* fp) {
  CHECK_FP(fp);
  return putc_unlocked(c, fp);
}

int fputs(const char* s, FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return fputs_unlocked(s, fp);
}

int fputs_unlocked(const char* s, FILE* fp) {
  CHECK_FP(fp);
  size_t length = strlen(s);
  return (fwrite_unlocked(s, 1, length, fp) == length) ? 0 : EOF;
}

int fscanf(FILE* fp, const char* fmt, ...) {
  CHECK_FP(fp);
  PRINTF_IMPL(vfscanf(fp, fmt, ap));
}

int fwprintf(FILE* fp, const wchar_t* fmt, ...) {
  CHECK_FP(fp);
  PRINTF_IMPL(vfwprintf(fp, fmt, ap));
}

int fwscanf(FILE* fp, const wchar_t* fmt, ...) {
  CHECK_FP(fp);
  PRINTF_IMPL(vfwscanf(fp, fmt, ap));
}

int getc(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return getc_unlocked(fp);
}

int getc_unlocked(FILE* fp) {
  CHECK_FP(fp);
  return __sgetc(fp);
}

int getchar_unlocked() {
  return getc_unlocked(stdin);
}

int getchar() {
  return getc(stdin);
}

ssize_t getline(char** buf, size_t* len, FILE* fp) {
  CHECK_FP(fp);
  return getdelim(buf, len, '\n', fp);
}

wint_t getwc(FILE* fp) {
  CHECK_FP(fp);
  return fgetwc(fp);
}

wint_t getwchar() {
  return fgetwc(stdin);
}

void perror(const char* msg) {
  if (msg == nullptr) msg = "";
  fprintf(stderr, "%s%s%m\n", msg, (*msg == '\0') ? "" : ": ");
}

int printf(const char* fmt, ...) {
  PRINTF_IMPL(vfprintf(stdout, fmt, ap));
}

int putc(int c, FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return putc_unlocked(c, fp);
}

int putc_unlocked(int c, FILE* fp) {
  CHECK_FP(fp);
  if (cantwrite(fp)) {
    errno = EBADF;
    return EOF;
  }
  _SET_ORIENTATION(fp, ORIENT_BYTES);
  if (--fp->_w >= 0 || (fp->_w >= fp->_lbfsize && c != '\n')) {
    return (*fp->_p++ = c);
  }
  return (__swbuf(c, fp));
}

int putchar(int c) {
  return putc(c, stdout);
}

int putchar_unlocked(int c) {
  return putc_unlocked(c, stdout);
}

int puts(const char* s) {
  size_t length = strlen(s);
  ScopedFileLock sfl(stdout);
  return (fwrite_unlocked(s, 1, length, stdout) == length &&
          putc_unlocked('\n', stdout) != EOF) ? 0 : EOF;
}

wint_t putwc(wchar_t wc, FILE* fp) {
  CHECK_FP(fp);
  return fputwc(wc, fp);
}

wint_t putwchar(wchar_t wc) {
  return fputwc(wc, stdout);
}

int remove(const char* path) {
  if (unlink(path) != -1) return 0;
  if (errno != EISDIR) return -1;
  return rmdir(path);
}

void rewind(FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  fseek(fp, 0, SEEK_SET);
  clearerr_unlocked(fp);
}

int scanf(const char* fmt, ...) {
  PRINTF_IMPL(vfscanf(stdin, fmt, ap));
}

void setbuf(FILE* fp, char* buf) {
  CHECK_FP(fp);
  setbuffer(fp, buf, BUFSIZ);
}

void setbuffer(FILE* fp, char* buf, int size) {
  CHECK_FP(fp);
  setvbuf(fp, buf, buf ? _IOFBF : _IONBF, size);
}

int setlinebuf(FILE* fp) {
  CHECK_FP(fp);
  return setvbuf(fp, nullptr, _IOLBF, 0);
}

int snprintf(char* s, size_t n, const char* fmt, ...) {
  PRINTF_IMPL(vsnprintf(s, n, fmt, ap));
}

int sprintf(char* s, const char* fmt, ...) {
  PRINTF_IMPL(vsprintf(s, fmt, ap));
}

int sscanf(const char* s, const char* fmt, ...) {
  PRINTF_IMPL(vsscanf(s, fmt, ap));
}

int swprintf(wchar_t* s, size_t n, const wchar_t* fmt, ...) {
  PRINTF_IMPL(vswprintf(s, n, fmt, ap));
}

int swscanf(const wchar_t* s, const wchar_t* fmt, ...) {
  PRINTF_IMPL(vswscanf(s, fmt, ap));
}

int vfprintf(FILE* fp, const char* fmt, va_list ap) {
  ScopedFileLock sfl(fp);
  return __vfprintf(fp, fmt, ap);
}

int vfscanf(FILE* fp, const char* fmt, va_list ap) {
  ScopedFileLock sfl(fp);
  return __svfscanf(fp, fmt, ap);
}

int vfwprintf(FILE* fp, const wchar_t* fmt, va_list ap) {
  ScopedFileLock sfl(fp);
  return __vfwprintf(fp, fmt, ap);
}

int vfwscanf(FILE* fp, const wchar_t* fmt, va_list ap) {
  ScopedFileLock sfl(fp);
  return __vfwscanf(fp, fmt, ap);
}

int vprintf(const char* fmt, va_list ap) {
  return vfprintf(stdout, fmt, ap);
}

int vscanf(const char* fmt, va_list ap) {
  return vfscanf(stdin, fmt, ap);
}

int vsnprintf(char* s, size_t n, const char* fmt, va_list ap) {
  // stdio internals use int rather than size_t.
  static_assert(INT_MAX <= SSIZE_MAX, "SSIZE_MAX too large to fit in int");

  __check_count("vsnprintf", "size", n);

  // Stdio internals do not deal correctly with zero length buffer.
  char one_byte_buffer[1];
  if (n == 0) {
    s = one_byte_buffer;
    n = 1;
  }

  FILE f;
  __sfileext fext;
  _FILEEXT_SETUP(&f, &fext);
  f._file = -1;
  f._flags = __SWR | __SSTR;
  f._bf._base = f._p = reinterpret_cast<unsigned char*>(s);
  f._bf._size = f._w = n - 1;

  int result = __vfprintf(&f, fmt, ap);
  *f._p = '\0';
  return result;
}

int vsprintf(char* s, const char* fmt, va_list ap) {
  return vsnprintf(s, SSIZE_MAX, fmt, ap);
}

int vwprintf(const wchar_t* fmt, va_list ap) {
  return vfwprintf(stdout, fmt, ap);
}

int vwscanf(const wchar_t* fmt, va_list ap) {
  return vfwscanf(stdin, fmt, ap);
}

int wprintf(const wchar_t* fmt, ...) {
  PRINTF_IMPL(vfwprintf(stdout, fmt, ap));
}

int wscanf(const wchar_t* fmt, ...) {
  PRINTF_IMPL(vfwscanf(stdin, fmt, ap));
}

static int fflush_all() {
  return _fwalk(__sflush_locked);
}

int fflush(FILE* fp) {
  if (fp == nullptr) return fflush_all();
  ScopedFileLock sfl(fp);
  return fflush_unlocked(fp);
}

int fflush_unlocked(FILE* fp) {
  if (fp == nullptr) return fflush_all();
  if ((fp->_flags & (__SWR | __SRW)) == 0) {
    errno = EBADF;
    return EOF;
  }
  return __sflush(fp);
}

int fpurge(FILE* fp) {
  CHECK_FP(fp);

  ScopedFileLock sfl(fp);

  if (fp->_flags == 0) {
    // Already freed!
    errno = EBADF;
    return EOF;
  }

  if (HASUB(fp)) FREEUB(fp);
  WCIO_FREE(fp);
  fp->_p = fp->_bf._base;
  fp->_r = 0;
  fp->_w = fp->_flags & (__SLBF | __SNBF) ? 0 : fp->_bf._size;
  return 0;
}
__strong_alias(__fpurge, fpurge);

size_t fread(void* buf, size_t size, size_t count, FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return fread_unlocked(buf, size, count, fp);
}

size_t fread_unlocked(void* buf, size_t size, size_t count, FILE* fp) {
  CHECK_FP(fp);

  size_t desired_total;
  if (__builtin_mul_overflow(size, count, &desired_total)) {
    errno = EOVERFLOW;
    fp->_flags |= __SERR;
    return 0;
  }

  size_t total = desired_total;
  if (total == 0) return 0;

  _SET_ORIENTATION(fp, ORIENT_BYTES);

  // TODO: how can this ever happen?!
  if (fp->_r < 0) fp->_r = 0;

  // Ensure _bf._size is valid.
  if (fp->_bf._base == nullptr) __smakebuf(fp);

  char* dst = static_cast<char*>(buf);

  while (total > 0) {
    // Copy data out of the buffer.
    size_t buffered_bytes = MIN(static_cast<size_t>(fp->_r), total);
    memcpy(dst, fp->_p, buffered_bytes);
    fp->_p += buffered_bytes;
    fp->_r -= buffered_bytes;
    dst += buffered_bytes;
    total -= buffered_bytes;

    // Are we done?
    if (total == 0) goto out;

    // Do we have so much more to read that we should avoid copying it through the buffer?
    if (total > static_cast<size_t>(fp->_bf._size)) break;

    // Less than a buffer to go, so refill the buffer and go around the loop again.
    if (__srefill(fp)) goto out;
  }

  // Read directly into the caller's buffer.
  while (total > 0) {
    // The _read function pointer takes an int instead of a size_t.
    int chunk_size = MIN(total, INT_MAX);
    ssize_t bytes_read = (*fp->_read)(fp->_cookie, dst, chunk_size);
    if (bytes_read <= 0) {
      fp->_flags |= (bytes_read == 0) ? __SEOF : __SERR;
      break;
    }
    dst += bytes_read;
    total -= bytes_read;
  }

out:
  return ((desired_total - total) / size);
}

size_t fwrite(const void* buf, size_t size, size_t count, FILE* fp) {
  CHECK_FP(fp);
  ScopedFileLock sfl(fp);
  return fwrite_unlocked(buf, size, count, fp);
}

size_t fwrite_unlocked(const void* buf, size_t size, size_t count, FILE* fp) {
  CHECK_FP(fp);

  size_t n;
  if (__builtin_mul_overflow(size, count, &n)) {
    errno = EOVERFLOW;
    fp->_flags |= __SERR;
    return 0;
  }

  if (n == 0) return 0;

  __siov iov = { .iov_base = const_cast<void*>(buf), .iov_len = n };
  __suio uio = { .uio_iov = &iov, .uio_iovcnt = 1, .uio_resid = n };

  _SET_ORIENTATION(fp, ORIENT_BYTES);

  // The usual case is success (__sfvwrite returns 0); skip the divide if this happens,
  // since divides are generally slow.
  return (__sfvwrite(fp, &uio) == 0) ? count : ((n - uio.uio_resid) / size);
}

static FILE* __popen_fail(int fds[2]) {
  ErrnoRestorer errno_restorer;
  close(fds[0]);
  close(fds[1]);
  return nullptr;
}

FILE* popen(const char* cmd, const char* mode) {
  // Was the request for a socketpair or just a pipe?
  int fds[2];
  bool bidirectional = false;
  if (strchr(mode, '+') != nullptr) {
    if (socketpair(AF_LOCAL, SOCK_CLOEXEC | SOCK_STREAM, 0, fds) == -1) return nullptr;
    bidirectional = true;
    mode = "r+";
  } else {
    if (pipe2(fds, O_CLOEXEC) == -1) return nullptr;
    mode = strrchr(mode, 'r') ? "r" : "w";
  }

  // If the parent wants to read, the child's fd needs to be stdout.
  int parent, child, desired_child_fd;
  if (*mode == 'r') {
    parent = 0;
    child = 1;
    desired_child_fd = STDOUT_FILENO;
  } else {
    parent = 1;
    child = 0;
    desired_child_fd = STDIN_FILENO;
  }

  // Ensure that the child fd isn't the desired child fd.
  if (fds[child] == desired_child_fd) {
    int new_fd = fcntl(fds[child], F_DUPFD_CLOEXEC, 0);
    if (new_fd == -1) return __popen_fail(fds);
    close(fds[child]);
    fds[child] = new_fd;
  }

  pid_t pid = vfork();
  if (pid == -1) return __popen_fail(fds);

  if (pid == 0) {
    close(fds[parent]);
    // dup2 so that the child fd isn't closed on exec.
    if (dup2(fds[child], desired_child_fd) == -1) _exit(127);
    close(fds[child]);
    if (bidirectional) dup2(STDOUT_FILENO, STDIN
```
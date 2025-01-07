Response:
Let's break down the thought process for analyzing the `setvbuf.c` code.

1. **Understand the Goal:** The primary goal is to analyze the functionality of the `setvbuf` function in the context of Android's Bionic library. This involves explaining its purpose, how it works, its relationship to Android, potential errors, and how it's used.

2. **High-Level Overview (Reading the Code Comments and Signature):** The initial comments and function signature `int setvbuf(FILE *fp, char *buf, int mode, size_t size)` immediately give crucial information. It's about setting buffering for a file stream (`FILE *fp`). The `mode` parameter likely controls the buffering type, and `buf` and `size` suggest the possibility of providing a custom buffer.

3. **Deconstruct the Function Step-by-Step:**  Go through the code line by line, understanding the purpose of each section.

    * **Argument Validation:** The code first checks the `mode` and `size` parameters. This is standard practice for robustness. The `INT_MAX` check for `size` is important.

    * **Flushing and Cleaning Up:** The `__sflush(fp)`, `FREEUB(fp)`, and `WCIO_FREE(fp)` calls suggest cleaning up any existing buffered data or internal state associated with the file stream. The clearing of `_r` and `_lbfsize` confirms this. The handling of `__SMBF` (small malloc'd buffer) indicates the function manages allocated buffers. The clearing of flags related to buffering mode and EOF further clarifies the function's reset behavior.

    * **Unbuffered Mode (`_IONBF`):** The special handling for `_IONBF` provides a clear branch in the logic. If unbuffered, it skips the buffer management.

    * **Optimal I/O Size:** The `__swhatbuf` call hints at an optimization related to the underlying file system's preferred I/O size. This is a performance consideration.

    * **Buffer Allocation:**  The logic for buffer allocation (using `malloc`) and the fallback mechanism if allocation fails is important. The code tries to use the optimal `iosize` if the user doesn't provide a buffer or if the initial allocation fails. The switch to unbuffered mode if all allocations fail is a crucial fallback.

    * **Registration for Exit Flushing:**  The `__sinit()` call when buffering is enabled suggests a mechanism to ensure buffered data is written out when the program exits.

    * **Seek Optimization Check:** The check `size != iosize` and the setting of `__SNPT` indicate a potential optimization for seeks that is disabled if a custom buffer size is used.

    * **Setting File Stream Flags:** The code modifies various flags in the `fp->_flags` structure to indicate the chosen buffering mode (`__SLBF`, `__SNBF`, `__SMBF`) and other properties.

    * **Initializing Buffer Information:** The `fp->_bf._base`, `fp->_p`, and `fp->_bf._size` members are set to point to the buffer and store its size.

    * **Handling Write Operations:** The special handling for write streams (`flags & __SWR`) and the initialization of `fp->_w` and `fp->_lbfsize` are important for understanding how the buffering interacts with output operations.

    * **Locking:** The `FLOCKFILE` and `FUNLOCKFILE` calls indicate thread safety considerations, even though the code itself doesn't explicitly manage threads in this snippet.

4. **Identify Key Concepts:**  As you analyze the code, note down the key concepts involved:

    * **Buffering Modes:**  `_IONBF`, `_IOFBF`, `_IOLBF`.
    * **File Stream Structure (`FILE`):** The function directly manipulates members of the `FILE` structure.
    * **Dynamic Memory Allocation:**  `malloc` and `free`.
    * **File Descriptors (implicitly through `FILE *fp`):** The underlying file descriptor influences buffering behavior.
    * **Flushing:**  Ensuring data is written to the underlying file.
    * **Seek Optimization:** A performance enhancement.
    * **Thread Safety:**  Locking mechanisms.

5. **Connect to Android:**  Consider how this function relates to Android's environment. Since it's part of Bionic, it's used by all Android applications and system services. Think about common scenarios:

    * Reading/writing files.
    * Using standard output/error.
    * Network communication (which might use file descriptors internally).

6. **Address Specific Requirements:** Go back to the prompt and ensure all requirements are addressed:

    * **Functionality:** List the core actions of the function.
    * **Android Relevance:** Provide concrete examples of its use in Android.
    * **Implementation Details:** Explain *how* each part of the function works.
    * **Dynamic Linker:** Recognize that `setvbuf` itself doesn't directly involve the dynamic linker, but the `libc.so` it's part of does. Describe the general role of the dynamic linker and provide a basic `libc.so` layout example.
    * **Logical Inference:** Consider simple input/output scenarios to illustrate the function's behavior.
    * **Common Errors:** Think about mistakes developers might make when using `setvbuf`.
    * **Android Framework/NDK Call Stack:**  Imagine how a call to `printf` or `fopen` might eventually lead to `setvbuf`. Provide a Frida hook example to demonstrate this.

7. **Structure the Answer:** Organize the information logically. Start with a summary of the function's purpose, then delve into the details. Use clear headings and formatting to make the answer easy to read. Address each requirement of the prompt systematically.

8. **Refine and Elaborate:** Review the answer for clarity and completeness. Add more detail where necessary. For example, when explaining the dynamic linker, provide more context about its role. For the Frida hook, ensure the code is correct and clearly explains the target function and the hook's action.

By following this systematic approach, you can thoroughly analyze the given C code and provide a comprehensive and informative answer that addresses all aspects of the prompt. The key is to break down the problem into smaller, manageable parts and to connect the code's functionality to the broader context of the Android operating system.
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdio/setvbuf.c` 这个文件。

**功能概述:**

`setvbuf` 函数用于为一个打开的文件流 (`FILE` 指针) 设置缓冲模式。通过 `setvbuf`，你可以控制文件流是完全缓冲、行缓冲还是无缓冲，并且可以选择是否提供自定义的缓冲区。

**具体功能列举:**

1. **设置缓冲模式:**  允许用户指定三种缓冲模式：
    * `_IOFBF` (Full Buffering):  只有当缓冲区满或显式调用 `fflush` 时才会执行实际的 I/O 操作。
    * `_IOLBF` (Line Buffering):  只有当遇到换行符 (`\n`)、缓冲区满或显式调用 `fflush` 时才会执行实际的 I/O 操作。这通常用于终端输出。
    * `_IONBF` (No Buffering):  每次 I/O 操作都会立即执行，不使用缓冲区。

2. **指定缓冲区:** 允许用户提供自定义的缓冲区 (`buf`) 及其大小 (`size`)。如果 `buf` 为 `NULL`，则由 `setvbuf` 内部使用 `malloc` 分配缓冲区。

3. **清理现有缓冲区:** 在设置新的缓冲模式之前，会清理文件流当前关联的缓冲区，包括刷新缓冲区内容 (使用 `__sflush`)、释放由 `malloc` 分配的旧缓冲区 (如果存在)。

4. **优化 I/O 大小:**  尝试获取文件系统的最佳 I/O 大小 (通过 `__swhatbuf`)，并在用户未指定缓冲区大小或指定大小为 0 时使用该大小作为默认缓冲区大小。

5. **注册退出时刷新:** 当设置了缓冲模式时，会调用 `__sinit()` 来注册一个在程序退出时刷新所有缓冲区的处理程序。

6. **处理错误情况:**  检查参数的有效性，并在分配缓冲区失败时回退到无缓冲模式。

**与 Android 功能的关系及举例:**

`setvbuf` 是标准 C 库的一部分，因此在 Android 的所有 C/C++ 代码中都会用到。它影响着文件 I/O 的效率和行为。

* **性能优化:** Android 应用程序可以使用 `setvbuf` 来优化文件读写性能。例如，对于大文件的读取，使用全缓冲可以减少系统调用的次数，提高效率。
    ```c
    #include <stdio.h>
    #include <stdlib.h>

    int main() {
        FILE *fp = fopen("large_file.txt", "r");
        if (fp == NULL) {
            perror("fopen");
            return 1;
        }

        // 设置全缓冲，缓冲区大小为 8KB
        char *buffer = malloc(8192);
        if (setvbuf(fp, buffer, _IOFBF, 8192) != 0) {
            perror("setvbuf");
            fclose(fp);
            free(buffer);
            return 1;
        }

        char ch;
        while ((ch = fgetc(fp)) != EOF) {
            // 处理文件内容
        }

        fclose(fp);
        free(buffer);
        return 0;
    }
    ```

* **控制输出行为:** 对于需要实时输出的场景，例如日志记录，可以使用行缓冲或无缓冲来确保输出立即显示。
    ```c
    #include <stdio.h>

    int main() {
        // 设置标准输出为行缓冲
        setvbuf(stdout, NULL, _IOLBF, 0);
        printf("This will be printed after a newline.\n");
        printf("This will also be printed after a newline.\n");

        // 设置标准错误为无缓冲，错误信息会立即显示
        setvbuf(stderr, NULL, _IONBF, 0);
        fprintf(stderr, "An error occurred!\n");

        return 0;
    }
    ```

* **NDK 开发:** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的一部分。在 NDK 代码中，可以直接调用 `setvbuf` 来管理文件流的缓冲。

**libc 函数的实现细节:**

现在我们详细解释一下 `setvbuf` 中各个关键步骤的实现：

1. **参数校验:**
   ```c
   if (mode != _IONBF)
       if ((mode != _IOFBF && mode != _IOLBF) || size > INT_MAX)
           return (EOF);
   ```
   这段代码检查传入的 `mode` 是否为三种合法的缓冲模式之一。对于缓冲模式 (`_IOFBF` 或 `_IOLBF`)，还会检查 `size` 是否超过 `INT_MAX`，这是由于该实现使用了 `int` 来表示缓冲区大小。如果参数无效，则返回 `EOF` 表示错误。

2. **清理现有缓冲区:**
   ```c
   FLOCKFILE(fp); // 获取文件流的锁，保证线程安全
   ret = 0;
   (void)__sflush(fp); // 刷新缓冲区，将缓冲区中的数据写入文件
   if (HASUB(fp))
       FREEUB(fp); // 释放由 ungetc 使用的缓冲区
   WCIO_FREE(fp); // 释放宽字符 I/O 相关的缓冲区
   fp->_r = fp->_lbfsize = 0; // 重置读取计数器和行缓冲大小
   flags = fp->_flags;
   if (flags & __SMBF)
       free(fp->_bf._base); // 释放之前用 malloc 分配的缓冲区
   flags &= ~(__SLBF | __SNBF | __SMBF | __SOPT | __SNPT | __SEOF); // 清除与缓冲相关的标志和 EOF 标志
   ```
   在修改缓冲模式之前，必须清理旧的缓冲区和相关状态，以避免数据丢失或状态不一致。`FLOCKFILE` 和 `FUNLOCKFILE` 用于实现线程安全，确保在多线程环境下对文件流的操作是互斥的。`__sflush` 是一个内部函数，用于将缓冲区中的数据写入文件或底层设备。`HASUB` 和 `FREEUB` 处理由 `ungetc` 函数使用的回退缓冲区。`WCIO_FREE` 处理宽字符 I/O 相关的缓冲区。

3. **处理无缓冲模式:**
   ```c
   if (mode == _IONBF)
       goto nbf;
   ```
   如果用户要求无缓冲，则跳转到 `nbf` 标签，跳过缓冲区分配的步骤。

4. **获取最佳 I/O 大小:**
   ```c
   flags |= __swhatbuf(fp, &iosize, &ttyflag);
   if (size == 0) {
       buf = NULL;	/* force local allocation */
       size = iosize;
   }
   ```
   `__swhatbuf` 是一个内部函数，它尝试获取文件描述符对应的设备的最佳 I/O 大小 (`iosize`)。这通常与文件系统的块大小有关，使用此大小作为缓冲区可以提高 I/O 效率。如果用户指定的 `size` 为 0，则强制使用 `iosize`，并设置 `buf` 为 `NULL`，指示需要内部分配缓冲区。`ttyflag` 用于指示是否是终端设备，但在这里被忽略，因为缓冲模式由用户指定。

5. **分配缓冲区:**
   ```c
   if (buf == NULL) {
       if ((buf = malloc(size)) == NULL) {
           ret = EOF;
           if (size != iosize) {
               size = iosize;
               buf = malloc(size);
           }
       }
       if (buf == NULL) {
   nbf:
           fp->_flags = flags | __SNBF;
           fp->_w = 0;
           fp->_bf._base = fp->_p = fp->_nbuf;
           fp->_bf._size = 1;
           FUNLOCKFILE(fp);
           return (ret);
       }
       flags |= __SMBF;
   }
   ```
   如果用户没有提供缓冲区 (`buf == NULL`)，则尝试使用 `malloc` 分配指定大小的缓冲区。如果分配失败，并且之前尝试分配的不是最佳 I/O 大小，则会尝试分配最佳 I/O 大小的缓冲区。如果所有分配都失败，则跳转到 `nbf` 标签，设置为无缓冲模式。在无缓冲模式下，使用 `fp->_nbuf` (一个大小为 1 的静态缓冲区)。`__SMBF` 标志表示使用了由 `malloc` 分配的小缓冲区。

6. **注册退出时刷新:**
   ```c
   if (!__sdidinit)
       __sinit();
   ```
   `__sdidinit` 是一个静态变量，用于跟踪 `__sinit` 函数是否被调用过。`__sinit` 函数会注册一个在程序退出时调用的函数，该函数会刷新所有打开的缓冲文件流，确保数据不会丢失。

7. **禁用 seek 优化:**
   ```c
   if (size != iosize)
       flags |= __SNPT;
   ```
   如果用户提供的缓冲区大小与最佳 I/O 大小不同，则设置 `__SNPT` 标志，禁用某些与 seek 操作相关的优化。这是因为非最佳大小的缓冲区可能导致这些优化失效。

8. **设置文件流字段:**
   ```c
   if (mode == _IOLBF)
       flags |= __SLBF;
   fp->_flags = flags;
   fp->_bf._base = fp->_p = (unsigned char *)buf;
   fp->_bf._size = size;
   if (flags & __SWR) {
       if (flags & __SLBF) {
           fp->_w = 0;
           fp->_lbfsize = -fp->_bf._size;
       } else
           fp->_w = size;
   } else {
       fp->_w = 0;
   }
   FUNLOCKFILE(fp);
   ```
   根据选择的缓冲模式设置 `fp->_flags`。`fp->_bf._base` 指向缓冲区起始地址，`fp->_p` 是当前缓冲区指针，`fp->_bf._size` 是缓冲区大小。对于写操作 (`__SWR`)，会设置 `fp->_w` (可写字节数)。对于行缓冲，`fp->_lbfsize` 被设置为负的缓冲区大小，用于标记行缓冲的特殊处理。最后，释放文件流的锁。

**涉及 dynamic linker 的功能:**

`setvbuf` 函数本身并不直接涉及 dynamic linker 的功能。然而，`setvbuf` 是 `libc.so` 库的一部分，而 dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 负责在程序启动时加载 `libc.so` 以及其他共享库，并将程序代码中对 `setvbuf` 等函数的调用链接到 `libc.so` 中对应的实现。

**so 布局样本:**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text:  // 代码段，包含 setvbuf 等函数的机器码
        ...
        setvbuf:
            <setvbuf 函数的机器码>
        __sflush:
            <__sflush 函数的机器码>
        malloc:
            <malloc 函数的机器码>
        ...
    .data:  // 已初始化数据段，包含全局变量
        __sdidinit: 0  // 静态变量
        ...
    .bss:   // 未初始化数据段，包含未初始化的全局变量
        ...
    .dynamic: // 动态链接信息
        NEEDED libc++.so
        SONAME libc.so
        ...
    .symtab: // 符号表，包含 setvbuf 等函数的符号信息
        setvbuf (address in .text)
        __sflush (address in .text)
        malloc (address in .text)
        ...
    .strtab: // 字符串表，包含符号名称等字符串
        "setvbuf"
        "__sflush"
        "malloc"
        ...
```

**链接的处理过程:**

1. **程序加载:** 当 Android 启动一个应用程序时，操作系统会加载应用程序的可执行文件 (通常是 ELF 格式)。
2. **依赖解析:** 可执行文件的头部信息会指示它依赖哪些共享库，例如 `libc.so`。Dynamic linker 会负责找到这些共享库。
3. **加载共享库:** Dynamic linker 将 `libc.so` 加载到进程的地址空间中。
4. **符号解析 (Linking):**  当程序代码中调用 `setvbuf` 时，编译器会生成一个对 `setvbuf` 的符号引用。Dynamic linker 会在 `libc.so` 的符号表 (`.symtab`) 中查找 `setvbuf` 的地址。
5. **重定位:** Dynamic linker 会修改程序代码中的符号引用，将其指向 `libc.so` 中 `setvbuf` 函数的实际地址。这个过程称为重定位。
6. **执行:** 现在，当程序执行到调用 `setvbuf` 的代码时，实际上会跳转到 `libc.so` 中 `setvbuf` 函数的实现。

**假设输入与输出 (逻辑推理):**

假设我们有以下代码：

```c
#include <stdio.h>

int main() {
    FILE *fp = fopen("test.txt", "w");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    // 设置行缓冲
    setvbuf(fp, NULL, _IOLBF, 0);

    fprintf(fp, "Hello"); // 数据会先缓存在缓冲区
    fprintf(fp, " World!\n"); // 遇到换行符，缓冲区内容会被写入文件

    fclose(fp); // 关闭文件时，缓冲区也会被刷新
    return 0;
}
```

**假设输入:**  在执行程序前，`test.txt` 文件不存在。

**预期输出:**

1. 执行 `fprintf(fp, "Hello");` 后，字符串 "Hello" 会被写入 `fp` 关联的缓冲区，但不会立即写入到 `test.txt` 文件中。
2. 执行 `fprintf(fp, " World!\n");` 后，由于设置了行缓冲，遇到换行符 `\n`，缓冲区中的 "Hello World!\n" 会被写入到 `test.txt` 文件中。
3. 执行 `fclose(fp);` 时，会刷新缓冲区，确保所有未写入的数据都被写入文件。
4. 最终，`test.txt` 文件的内容将是 "Hello World!\n"。

**用户或编程常见的使用错误:**

1. **在文件打开模式不支持缓冲的情况下调用 `setvbuf`:** 例如，以追加模式 (`"a"`) 打开文件后立即设置无缓冲可能没有意义，因为每次写入都会立即追加到文件末尾。

2. **提供的缓冲区大小不合理:**  提供过小或过大的缓冲区可能导致性能下降或内存浪费。最好使用 `setvbuf(fp, NULL, mode, 0)` 让系统自动选择合适的缓冲区大小。

3. **缓冲区生命周期管理不当:** 如果使用 `malloc` 分配了缓冲区，必须确保在文件流关闭之前释放缓冲区，否则可能导致内存泄漏。

4. **在已经有缓冲的情况下再次调用 `setvbuf`:** 虽然 `setvbuf` 会清理旧的缓冲区，但在某些情况下可能会导致意外的行为，应该避免不必要的重复调用。

5. **假设特定的缓冲行为:**  不要过于依赖某种缓冲模式的特定行为，因为不同的操作系统或 libc 实现可能存在细微差别。最好显式地刷新缓冲区 (`fflush`) 来确保数据写入。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework 调用:**  Android Framework (例如 Java 代码中的 `FileOutputStream`) 底层最终会调用 Native 代码 (`libjavacrypto.so`, `libopenjdk.so` 等)。
2. **Native 代码调用:** Native 代码中进行文件 I/O 操作时，会使用标准 C 库函数，例如 `fopen`, `fwrite`, `fprintf` 等。
3. **libc 函数调用:**  例如，`fprintf` 内部会调用更底层的 `fwrite`，而 `fwrite` 在写入数据前会检查文件流的缓冲状态。如果需要设置缓冲，或者在打开文件时默认进行了缓冲，那么 `setvbuf` 可能会被间接调用 (例如，`fopen` 的实现可能会调用 `setvbuf` 来设置默认的缓冲模式)。
4. **系统调用:** 最终，缓冲区的刷新或无缓冲的 I/O 操作会通过系统调用 (例如 `write`) 与内核进行交互。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida Hook `setvbuf` 函数来观察它的调用情况和参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['api'], message['payload']['args']))
    else:
        print(message)

def main():
    package_name = "your.target.app"  # 替换为你的目标应用包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "setvbuf"), {
        onEnter: function(args) {
            var fp = new NativePointer(args[0]);
            var buf = new NativePointer(args[1]);
            var mode = args[2].toInt32();
            var size = args[3].toInt32();

            var modeStr = "";
            if (mode == 0) modeStr = "_IOFBF";
            else if (mode == 1) modeStr = "_IOLBF";
            else if (mode == 2) modeStr = "_IONBF";

            send({
                api: "setvbuf",
                args: [fp, buf, modeStr, size]
            });
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input("[+] Press Enter to detach from process...\n")
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤:**

1. **安装 Frida:** 确保你的开发环境已经安装了 Frida 和 frida-tools。
2. **运行目标应用:** 在 Android 设备或模拟器上运行你想要调试的目标应用。
3. **替换包名:** 将 `your.target.app` 替换为实际的应用包名。
4. **运行 Frida 脚本:** 在终端中运行上述 Python 脚本。
5. **观察输出:** 当目标应用执行到 `setvbuf` 函数时，Frida 会拦截调用并打印出相关信息，包括 `FILE` 指针、缓冲区指针、缓冲模式和大小。

通过这个 Frida Hook 示例，你可以观察到 Android 应用程序在哪些场景下调用了 `setvbuf`，以及设置了什么样的缓冲模式和缓冲区大小，从而更深入地理解文件 I/O 的行为。

希望这个详细的分析能够帮助你理解 `setvbuf` 函数的功能、实现以及在 Android 中的应用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdio/setvbuf.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: setvbuf.c,v 1.15 2022/09/28 16:44:14 gnezdo Exp $ */
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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "local.h"

/*
 * Set one of the three kinds of buffering, optionally including
 * a buffer.
 */
int
setvbuf(FILE *fp, char *buf, int mode, size_t size)
{
	int ret, flags;
	size_t iosize;
	int ttyflag;

	/*
	 * Verify arguments.  The `int' limit on `size' is due to this
	 * particular implementation.  Note, buf and size are ignored
	 * when setting _IONBF.
	 */
	if (mode != _IONBF)
		if ((mode != _IOFBF && mode != _IOLBF) || size > INT_MAX)
			return (EOF);

	/*
	 * Write current buffer, if any.  Discard unread input (including
	 * ungetc data), cancel line buffering, and free old buffer if
	 * malloc()ed.  We also clear any eof condition, as if this were
	 * a seek.
	 */
	FLOCKFILE(fp);
	ret = 0;
	(void)__sflush(fp);
	if (HASUB(fp))
		FREEUB(fp);
	WCIO_FREE(fp);
	fp->_r = fp->_lbfsize = 0;
	flags = fp->_flags;
	if (flags & __SMBF)
		free(fp->_bf._base);
	flags &= ~(__SLBF | __SNBF | __SMBF | __SOPT | __SNPT | __SEOF);

	/* If setting unbuffered mode, skip all the hard work. */
	if (mode == _IONBF)
		goto nbf;

	/*
	 * Find optimal I/O size for seek optimization.  This also returns
	 * a `tty flag' to suggest that we check isatty(fd), but we do not
	 * care since our caller told us how to buffer.
	 */
	flags |= __swhatbuf(fp, &iosize, &ttyflag);
	if (size == 0) {
		buf = NULL;	/* force local allocation */
		size = iosize;
	}

	/* Allocate buffer if needed. */
	if (buf == NULL) {
		if ((buf = malloc(size)) == NULL) {
			/*
			 * Unable to honor user's request.  We will return
			 * failure, but try again with file system size.
			 */
			ret = EOF;
			if (size != iosize) {
				size = iosize;
				buf = malloc(size);
			}
		}
		if (buf == NULL) {
			/* No luck; switch to unbuffered I/O. */
nbf:
			fp->_flags = flags | __SNBF;
			fp->_w = 0;
			fp->_bf._base = fp->_p = fp->_nbuf;
			fp->_bf._size = 1;
			FUNLOCKFILE(fp);
			return (ret);
		}
		flags |= __SMBF;
	}

	/*
	 * We're committed to buffering from here, so make sure we've
	 * registered to flush buffers on exit.
	 */
	if (!__sdidinit)
		__sinit();

	/*
	 * Kill any seek optimization if the buffer is not the
	 * right size.
	 *
	 * SHOULD WE ALLOW MULTIPLES HERE (i.e., ok iff (size % iosize) == 0)?
	 */
	if (size != iosize)
		flags |= __SNPT;

	/*
	 * Fix up the FILE fields, and set __cleanup for output flush on
	 * exit (since we are buffered in some way).
	 */
	if (mode == _IOLBF)
		flags |= __SLBF;
	fp->_flags = flags;
	fp->_bf._base = fp->_p = (unsigned char *)buf;
	fp->_bf._size = size;
	/* fp->_lbfsize is still 0 */
	if (flags & __SWR) {
		/*
		 * Begin or continue writing: see __swsetup().  Note
		 * that __SNBF is impossible (it was handled earlier).
		 */
		if (flags & __SLBF) {
			fp->_w = 0;
			fp->_lbfsize = -fp->_bf._size;
		} else
			fp->_w = size;
	} else {
		/* begin/continue reading, or stay in intermediate state */
		fp->_w = 0;
	}
	FUNLOCKFILE(fp);

	return (ret);
}
DEF_STRONG(setvbuf);

"""

```
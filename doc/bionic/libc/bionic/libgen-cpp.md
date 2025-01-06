Response:
Let's break down the thought process for generating the comprehensive answer about `libgen.cpp`.

**1. Understanding the Request:**

The request asks for a detailed analysis of the provided `libgen.cpp` source code. Key aspects to address include:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it relate to the Android operating system?
* **Implementation Details:**  Explain how each function works internally.
* **Dynamic Linking:**  If relevant, discuss dynamic linking aspects.
* **Logic and Examples:** Provide input/output examples to illustrate function behavior.
* **Common Errors:** Point out potential usage mistakes.
* **Android Integration:**  Explain how the code gets called from higher levels (framework/NDK).
* **Debugging:** Offer a Frida hook example for debugging.

**2. Initial Code Inspection and Function Identification:**

The first step is to read through the code and identify the core functions. Immediately, `basename_r`, `__basename_r`, `dirname_r`, `__dirname_r`, `basename`, and `dirname` stand out. Recognizing the `_r` suffix often indicates reentrant versions of functions.

**3. Functional Decomposition and Purpose:**

* **`basename` and `dirname`:** These are the standard POSIX functions for extracting the base filename and directory name from a path.
* **`basename_r` and `dirname_r`:**  These are reentrant versions, taking a buffer and buffer size as arguments to avoid potential thread-safety issues with static buffers.
* **`__basename_r` and `__dirname_r`:** These are the underlying implementation details for the reentrant functions. The `__` prefix often suggests internal use.

**4. Analyzing Each Function's Implementation (Detailed Walkthrough):**

For each function, a line-by-line or block-by-block analysis is necessary:

* **`__basename_r`:**
    * Handles null or empty paths.
    * Strips trailing slashes.
    * Handles the case of a path consisting only of slashes.
    * Finds the start of the filename by looking for the last `/`.
    * Calculates the length of the filename.
    * Handles the case where the provided buffer is too small, setting `errno` to `ERANGE`.
    * Copies the filename to the buffer.

* **`__dirname_r`:**
    * Handles null or empty paths.
    * Strips trailing slashes.
    * Finds the last `/`.
    * Handles cases where there are no slashes (returns ".") or the path is just a single `/`.
    * Trims trailing slashes from the directory part.
    * Calculates the length of the directory name.
    * Checks for `MAXPATHLEN` overflow.
    * Handles insufficient buffer size, setting `errno` to `ERANGE`.
    * Copies the directory name to the buffer.

* **`basename` and `dirname`:**
    * Use Thread-Local Storage (TLS) to store a static buffer (`basename_buf` and `dirname_buf`). This is a common technique in `libc` to provide thread safety for functions that historically used static buffers.
    * Call the reentrant `_r` versions with the TLS buffer.

**5. Android Relevance and Examples:**

Consider how these functions are used within the Android ecosystem:

* **File system operations:** Any time an Android process interacts with files (opening, creating, etc.), these functions can be implicitly or explicitly used to manipulate paths.
* **Package management:**  Extracting application names or directory structures from APK paths.
* **Command-line tools:**  Android's shell utilities likely use these functions.
* **NDK development:** Native code using standard C library functions will utilize these implementations.

Provide concrete examples showing the input and output of each function with various path scenarios.

**6. Dynamic Linking:**

While the provided code itself doesn't *directly* implement the dynamic linker, it's part of the Bionic `libc`, which is a core dynamically linked library. The key point is that applications don't have these functions compiled directly into their executables; they are linked against `libc.so` at runtime.

* **SO Layout:** Describe a simplified `libc.so` structure containing the relevant symbols (`basename`, `dirname`, etc.).
* **Linking Process:** Briefly explain how the dynamic linker resolves these symbols when an application starts.

**7. Common Usage Errors:**

Think about how developers might misuse these functions:

* **Buffer overflows (for `_r` versions):**  Not providing a sufficiently large buffer.
* **Modifying the returned pointer (for non-_r versions):**  The `basename` and `dirname` functions return pointers to internal buffers, so modifying them is unsafe.
* **Assumptions about path manipulation:**  Misunderstanding how the functions handle edge cases (empty paths, trailing slashes, etc.).

Provide specific code examples illustrating these errors.

**8. Android Framework and NDK Integration:**

Trace how a call might originate from a high-level Android component and eventually reach these `libc` functions:

* **Android Framework:** Start with a user action (e.g., file selection), show how the framework might manipulate file paths, and eventually call NDK functions or system calls.
* **NDK:** Demonstrate a simple NDK function that uses `basename` or `dirname`.
* **System Calls:**  Mention the underlying system calls (like `open`) that might indirectly use path manipulation.

**9. Frida Hooking:**

Create a practical Frida script that demonstrates how to intercept calls to `basename` and `dirname`, allowing inspection of the input path and the returned value. Explain the purpose of each part of the Frida script.

**10. Review and Refinement:**

After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure all aspects of the request are addressed. Pay attention to formatting and language to make the explanation easy to understand. For example, using code blocks, bullet points, and clear headings enhances readability.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the intricacies of the `__get_bionic_tls()` function. However, realizing the request is broader, I would shift the focus to the overall functionality of `basename` and `dirname`, and explain TLS as a mechanism for thread safety without getting bogged down in its implementation details unless specifically asked. Similarly, while dynamic linking is important, the focus should be on how `libc.so` makes these functions available, not a deep dive into the dynamic linker's algorithms. The examples and common errors sections are crucial for practical understanding, so ensuring they are clear and relevant is a key self-correction point.
这个文件 `bionic/libc/bionic/libgen.cpp` 是 Android Bionic C 库的一部分，主要实现了与路径名操作相关的函数，特别是用于提取路径名的目录部分 (`dirname`) 和基本文件名部分 (`basename`)。

**功能列举:**

1. **`basename(const char *path)`:**  返回路径名 `path` 的基本文件名部分。例如，对于路径 `/home/user/file.txt`，`basename` 将返回 `file.txt`。
2. **`dirname(const char *path)`:** 返回路径名 `path` 的目录部分。例如，对于路径 `/home/user/file.txt`，`dirname` 将返回 `/home/user`。
3. **`basename_r(const char *path, char *buffer, size_t buffer_size)`:**  `basename` 的线程安全版本。它将基本文件名复制到用户提供的缓冲区 `buffer` 中，缓冲区大小为 `buffer_size`。
4. **`dirname_r(const char *path, char *buffer, size_t buffer_size)`:** `dirname` 的线程安全版本。它将目录名复制到用户提供的缓冲区 `buffer` 中，缓冲区大小为 `buffer_size`。
5. **内部辅助函数 `__basename_r(const char *path, char *buffer, size_t buffer_size)` 和 `__dirname_r(const char *path, char *buffer, size_t buffer_size)`:** 这是 `basename_r` 和 `dirname_r` 的实际实现。

**与 Android 功能的关系及举例说明:**

这些函数在 Android 系统中被广泛使用，用于处理文件路径和目录结构。

* **文件系统操作:** 当 Android 系统需要解析文件路径时，例如在打开文件、创建文件、删除文件等操作中，这些函数会被调用来提取文件名或目录名。
    * **例子:**  一个应用想要保存一张图片到特定的目录。Android Framework 可能会使用 `dirname` 来获取目标目录，并使用 `basename` 来确定新的文件名（如果需要）。
* **包管理:**  Android 的包管理器 (PackageManager) 在安装、卸载应用时，需要处理 APK 文件的路径。`basename` 可以用于从 APK 完整路径中提取 APK 文件名。
    * **例子:** 当用户下载一个 APK 文件后，系统需要解析其路径以确定应用名。
* **Shell 命令:** Android 的 shell 命令 (例如 `ls`, `cp`, `mv`) 内部也会使用这些函数来处理用户输入的路径。
    * **例子:** 用户在 adb shell 中输入 `ls /sdcard/Pictures`，`dirname` 会被用来提取目录 `/sdcard`。
* **NDK 开发:** 使用 NDK 进行原生开发的程序可以直接调用这些 C 标准库函数来处理文件路径。
    * **例子:** 一个游戏需要加载资源文件，它可能会使用 `dirname` 获取资源目录，然后组合文件名来访问特定资源。

**libc 函数的功能实现:**

**1. `__basename_r(const char *path, char *buffer, size_t buffer_size)`:**

   * **处理空路径或 NULL 路径:** 如果 `path` 为空或 NULL，则将 "." 视为路径，表示当前目录。
   * **去除尾部的斜杠:** 从路径末尾开始去除所有的斜杠。
   * **处理全是斜杠的路径:** 如果去除尾部斜杠后路径只剩下一个斜杠，则返回 "/"。
   * **查找基本文件名的起始位置:** 从路径末尾向前查找，直到遇到斜杠或到达路径起始位置。基本文件名的起始位置是最后一个斜杠的下一个字符（如果找到斜杠），或者路径的起始位置（如果没有找到斜杠）。
   * **计算基本文件名的长度:**  计算从起始位置到路径末尾的长度。
   * **处理缓冲区为空的情况:** 如果 `buffer` 为 NULL，则只返回基本文件名的长度。
   * **检查缓冲区大小:** 如果基本文件名长度超过 `buffer_size - 1`，则将长度截断为 `buffer_size - 1`，设置 `errno` 为 `ERANGE`，并返回 -1。
   * **复制基本文件名到缓冲区:** 如果长度有效，则将基本文件名复制到 `buffer` 中，并在末尾添加 null 终止符。

   **假设输入与输出:**
   * 输入: `path = "/home/user/file.txt"`, `buffer` (足够大)
     输出: `buffer` 中包含 "file.txt"，返回值为 8 (长度)。
   * 输入: `path = "/home/user/"`, `buffer` (足够大)
     输出: `buffer` 中包含 "user"，返回值为 4。
   * 输入: `path = "/"`, `buffer` (足够大)
     输出: `buffer` 中包含 "/"，返回值为 1。
   * 输入: `path = ""`, `buffer` (足够大)
     输出: `buffer` 中包含 "."，返回值为 1。
   * 输入: `path = "/long/path/name"`, `buffer` (太小)
     输出: `buffer` 中包含 "nam"，返回值为 -1，`errno` 设置为 `ERANGE`。

**2. `__dirname_r(const char *path, char *buffer, size_t buffer_size)`:**

   * **处理空路径或 NULL 路径:** 如果 `path` 为空或 NULL，则将 "." 视为路径。
   * **去除尾部的斜杠:** 从路径末尾开始去除所有的斜杠。
   * **查找目录名的结束位置:** 从路径末尾向前查找，直到遇到斜杠或到达路径起始位置。目录名的结束位置是最后一个斜杠的位置。
   * **处理没有斜杠的情况:** 如果没有找到斜杠，则根据路径的第一个字符决定返回 "." 或 "/":
     * 如果第一个字符是 '/', 返回 "/"。
     * 否则返回 "."。
   * **处理只有一个斜杠的情况:** 如果路径是 "/"，则返回 "/"。
   * **计算目录名的长度:** 计算从路径起始位置到最后一个斜杠（不包括斜杠）的长度。
   * **检查路径长度是否超过 MAXPATHLEN:** 如果目录名长度超过 `MAXPATHLEN`，设置 `errno` 为 `ENAMETOOLONG`，并返回 -1。
   * **处理缓冲区为空的情况:** 如果 `buffer` 为 NULL，则只返回目录名的长度。
   * **检查缓冲区大小:** 如果目录名长度超过 `buffer_size - 1`，则将长度截断为 `buffer_size - 1`，设置 `errno` 为 `ERANGE`，并返回 -1。
   * **复制目录名到缓冲区:** 如果长度有效，则将目录名复制到 `buffer` 中，并在末尾添加 null 终止符。

   **假设输入与输出:**
   * 输入: `path = "/home/user/file.txt"`, `buffer` (足够大)
     输出: `buffer` 中包含 "/home/user"，返回值为 9。
   * 输入: `path = "/home/user/"`, `buffer` (足够大)
     输出: `buffer` 中包含 "/home"，返回值为 5。
   * 输入: `path = "/"`, `buffer` (足够大)
     输出: `buffer` 中包含 "/"，返回值为 1。
   * 输入: `path = "file.txt"`, `buffer` (足够大)
     输出: `buffer` 中包含 "."，返回值为 1。
   * 输入: `path = "/very/long/path/"`, `buffer` (太小)
     输出: `buffer` 中包含 "/ver"，返回值为 -1，`errno` 设置为 `ERANGE`。
   * 输入: `path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z"`, 缓冲区足够大，但路径长度超过 `MAXPATHLEN`
     输出: 返回值为 -1，`errno` 设置为 `ENAMETOOLONG`。

**3. `basename(const char *path)` 和 `dirname(const char *path)`:**

   这两个函数是非线程安全的版本。它们内部使用 Thread-Local Storage (TLS) 来存储一个静态缓冲区，避免了在多线程环境下使用共享静态缓冲区导致的问题。

   * **`basename`:** 调用 `__basename_r`，并将结果复制到 TLS 中名为 `basename_buf` 的缓冲区中。返回指向该缓冲区的指针。
   * **`dirname`:** 调用 `__dirname_r`，并将结果复制到 TLS 中名为 `dirname_buf` 的缓冲区中。返回指向该缓冲区的指针。

   由于它们返回的是指向内部静态缓冲区的指针，因此在多线程环境下，不应该长时间持有这个指针，也不应该修改指针指向的内容，因为后续的 `basename` 或 `dirname` 调用可能会覆盖这个缓冲区。

**涉及 dynamic linker 的功能:**

此文件本身并不直接涉及 dynamic linker 的核心功能，但它是 Android Bionic `libc` 的一部分，而 `libc.so` 是一个共享库，需要通过 dynamic linker 加载和链接。

**SO 布局样本:**

```
libc.so
├── .text         // 包含可执行代码
│   ├── basename
│   ├── dirname
│   ├── basename_r
│   ├── dirname_r
│   ├── __basename_r
│   └── __dirname_r
├── .rodata       // 包含只读数据，例如字符串常量
├── .data         // 包含已初始化的全局变量
├── .bss          // 包含未初始化的全局变量
├── .dynsym       // 动态符号表，包含导出的符号
│   ├── basename
│   ├── dirname
│   ├── basename_r
│   └── dirname_r
├── .dynstr       // 动态字符串表，包含符号名称
├── .rel.plt      // PLT (Procedure Linkage Table) 的重定位信息
├── .rel.dyn      // 动态链接段的重定位信息
└── ...
```

**链接的处理过程:**

1. **编译时:** 当编译一个 Android 应用或 NDK 库时，如果代码中使用了 `basename` 或 `dirname` 等函数，编译器会在生成的目标文件中记录对这些符号的未解析引用。
2. **链接时:** 链接器 (通常是 `lld` 在 Android 上) 会将多个目标文件链接成一个可执行文件或共享库。对于来自 `libc.so` 的符号，链接器不会将这些函数的实际代码包含进来，而是生成对这些符号的引用。
3. **运行时:** 当 Android 系统加载一个应用或共享库时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载所有依赖的共享库，包括 `libc.so`。
4. **符号解析:** dynamic linker 会解析未解析的符号引用。它会查找 `libc.so` 的 `.dynsym` 段，找到 `basename` 和 `dirname` 等符号的地址。
5. **重定位:** dynamic linker 会根据 `.rel.plt` 和 `.rel.dyn` 段中的信息，修改可执行文件或共享库中的代码，将对 `basename` 和 `dirname` 的调用指向 `libc.so` 中对应的函数地址。
6. **执行:** 当程序执行到调用 `basename` 或 `dirname` 的地方时，实际上会跳转到 `libc.so` 中对应的函数代码执行。

**用户或编程常见的使用错误:**

1. **`basename_r` 和 `dirname_r` 缓冲区溢出:**  如果提供的缓冲区 `buffer` 不够大，无法容纳结果字符串（包括 null 终止符），会导致缓冲区溢出，可能引发安全问题。
   ```c++
   char buf[5];
   basename_r("/long/path/name", buf, sizeof(buf)); // 错误：buf 太小
   ```

2. **修改 `basename` 或 `dirname` 返回的指针指向的内容:** 这两个函数返回的是指向内部静态缓冲区的指针，修改这些缓冲区的内容可能会导致未定义的行为，影响后续的调用。
   ```c++
   char* base = basename("/path/to/file");
   base[0] = 'X'; // 错误：修改了内部缓冲区
   ```

3. **在多线程环境下长时间持有 `basename` 或 `dirname` 的返回值:** 由于它们使用静态缓冲区，在多线程环境下，一个线程的调用可能会覆盖另一个线程的结果。应该立即复制返回值到线程私有的缓冲区。
   ```c++
   // 线程 1
   char* base1 = basename("/file1");
   sleep(1); // 模拟耗时操作
   printf("%s\n", base1); // 可能输出 "file2"，因为线程 2 可能已经调用了 basename

   // 线程 2
   char* base2 = basename("/file2");
   ```

4. **假设路径操作不会失败:**  `basename_r` 和 `dirname_r` 在缓冲区太小时会返回错误，并设置 `errno`。程序员应该检查返回值并处理错误情况。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤。**

**Android Framework 到 `libgen.cpp` 的路径示例:**

1. **用户操作:**  用户在文件管理器应用中点击一个文件，选择“重命名”。
2. **Framework 调用:** 文件管理器应用 (Java 代码) 会调用 Android Framework 的相关 API，例如 `java.io.File` 或 `android.provider.DocumentsContract` 中的方法来处理文件路径。
3. **JNI 调用:**  Framework 的某些底层实现或 NDK 模块可能会涉及到原生代码。例如，如果涉及到文件系统操作，可能会调用 POSIX 系统调用。
4. **`libc` 函数调用:**  在原生代码中，可能会直接或间接地调用 `basename` 或 `dirname`。例如，一个处理文件路径的工具函数可能会使用 `basename` 来提取文件名。
5. **`libgen.cpp` 执行:**  最终，对 `basename` 或 `dirname` 的调用会路由到 `bionic/libc/bionic/libgen.cpp` 中相应的实现。

**NDK 到 `libgen.cpp` 的路径示例:**

1. **NDK 代码:**  开发者编写了一个使用 C/C++ 的 Android NDK 应用。
2. **直接调用:**  NDK 代码中直接包含了 `<libgen.h>` 并调用了 `basename` 或 `dirname`。
   ```c++
   #include <libgen.h>
   #include <string>
   #include <iostream>

   void processPath(const char* path) {
       char* base = basename(const_cast<char*>(path)); // 注意: basename 可能会修改输入
       char* dir = dirname(const_cast<char*>(path));  // 注意: dirname 可能会修改输入
       std::cout << "Base: " << base << ", Dir: " << dir << std::endl;
   }
   ```
3. **编译链接:**  NDK 工具链会将这段代码编译成共享库 (`.so` 文件)，并链接到 `libc.so`。
4. **运行时加载:**  当 Android 应用加载这个 NDK 库时，dynamic linker 会加载 `libc.so` 并解析符号。
5. **`libgen.cpp` 执行:**  当 NDK 代码调用 `basename` 或 `dirname` 时，会执行 `libgen.cpp` 中的实现。

**Frida Hook 示例:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main(target_process):
    session = frida.attach(target_process)

    script_source = """
    Interceptor.attach(Module.findExportByName("libc.so", "basename"), {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            send("basename called with path: " + path);
            this.path = path;
        },
        onLeave: function(retval) {
            var base = Memory.readUtf8String(retval);
            send("basename returned: " + base + " for path: " + this.path);
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "dirname"), {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            send("dirname called with path: " + path);
            this.path = path;
        },
        onLeave: function(retval) {
            var dir = Memory.readUtf8String(retval);
            send("dirname returned: " + dir + " for path: " + this.path);
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "basename_r"), {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            var buffer = args[1];
            var bufferSize = args[2].toInt();
            this.buffer = buffer;
            this.bufferSize = bufferSize;
            send("basename_r called with path: " + path + ", buffer size: " + bufferSize);
        },
        onLeave: function(retval) {
            if (retval.toInt() >= 0) {
                var base = Memory.readUtf8String(this.buffer);
                send("basename_r wrote: " + base + " to buffer of size: " + this.bufferSize);
            } else {
                send("basename_r failed with return value: " + retval.toInt());
            }
        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "dirname_r"), {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            var buffer = args[1];
            var bufferSize = args[2].toInt();
            this.buffer = buffer;
            this.bufferSize = bufferSize;
            send("dirname_r called with path: " + path + ", buffer size: " + bufferSize);
        },
        onLeave: function(retval) {
            if (retval.toInt() >= 0) {
                var dir = Memory.readUtf8String(this.buffer);
                send("dirname_r wrote: " + dir + " to buffer of size: " + this.bufferSize);
            } else {
                send("dirname_r failed with return value: " + retval.toInt());
            }
        }
    });
    """

    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    input("Press Enter to detach from {}".format(target_process))
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python frida_hook.py <process_name_or_pid>")
        sys.exit(1)

    target = sys.argv[1]
    main(target)
```

**使用说明:**

1. 将上述 Python 代码保存为 `frida_hook.py`。
2. 确保你的 Android 设备或模拟器已连接并通过 adb 可访问。
3. 安装 Frida 和 frida-tools：`pip install frida frida-tools`
4. 运行 Frida 服务端在你的 Android 设备上。
5. 运行 Python 脚本，指定要 hook 的进程名称或 PID：
   ```bash
   python frida_hook.py com.example.myapp  # 替换为你的应用进程名
   # 或
   python frida_hook.py 12345           # 替换为进程 PID
   ```
6. 当目标应用执行到 `basename`、`dirname`、`basename_r` 或 `dirname_r` 时，Frida 会拦截这些调用，并打印出相关的参数和返回值，帮助你调试和理解调用流程。

这个 Frida 脚本会 hook `libc.so` 中的 `basename`, `dirname`, `basename_r`, 和 `dirname_r` 函数。当这些函数被调用时，`onEnter` 函数会记录输入参数（路径），`onLeave` 函数会记录返回值（基本文件名或目录名）或 `basename_r`/`dirname_r` 写入缓冲区的内容。这可以帮助你跟踪路径操作，了解哪些组件在调用这些函数以及传递了哪些参数。

Prompt: 
```
这是目录为bionic/libc/bionic/libgen.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <libgen.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/param.h>

#include "bionic/pthread_internal.h"

static int __basename_r(const char* path, char* buffer, size_t buffer_size) {
  const char* startp = nullptr;
  const char* endp = nullptr;
  int len;
  int result;

  // Empty or NULL string gets treated as ".".
  if (path == nullptr || *path == '\0') {
    startp = ".";
    len = 1;
    goto Exit;
  }

  // Strip trailing slashes.
  endp = path + strlen(path) - 1;
  while (endp > path && *endp == '/') {
    endp--;
  }

  // All slashes becomes "/".
  if (endp == path && *endp == '/') {
    startp = "/";
    len = 1;
    goto Exit;
  }

  // Find the start of the base.
  startp = endp;
  while (startp > path && *(startp - 1) != '/') {
    startp--;
  }

  len = endp - startp +1;

 Exit:
  result = len;
  if (buffer == nullptr) {
    return result;
  }
  if (len > static_cast<int>(buffer_size) - 1) {
    len = buffer_size - 1;
    result = -1;
    errno = ERANGE;
  }

  if (len >= 0) {
    memcpy(buffer, startp, len);
    buffer[len] = 0;
  }
  return result;
}

// Since this is a non-standard symbol, it might be hijacked by a basename_r in the executable.
__LIBC32_LEGACY_PUBLIC__ int basename_r(const char* path, char* buffer, size_t buffer_size) {
  return __basename_r(path, buffer, buffer_size);
}

static int __dirname_r(const char* path, char* buffer, size_t buffer_size) {
  const char* endp = nullptr;
  int len;
  int result;

  // Empty or NULL string gets treated as ".".
  if (path == nullptr || *path == '\0') {
    path = ".";
    len = 1;
    goto Exit;
  }

  // Strip trailing slashes.
  endp = path + strlen(path) - 1;
  while (endp > path && *endp == '/') {
    endp--;
  }

  // Find the start of the dir.
  while (endp > path && *endp != '/') {
    endp--;
  }

  // Either the dir is "/" or there are no slashes.
  if (endp == path) {
    path = (*endp == '/') ? "/" : ".";
    len = 1;
    goto Exit;
  }

  do {
    endp--;
  } while (endp > path && *endp == '/');

  len = endp - path + 1;

 Exit:
  result = len;
  if (len + 1 > MAXPATHLEN) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (buffer == nullptr) {
    return result;
  }

  if (len > static_cast<int>(buffer_size) - 1) {
    len = buffer_size - 1;
    result = -1;
    errno = ERANGE;
  }

  if (len >= 0) {
    memcpy(buffer, path, len);
    buffer[len] = 0;
  }
  return result;
}

// Since this is a non-standard symbol, it might be hijacked by a basename_r in the executable.
__LIBC32_LEGACY_PUBLIC__ int dirname_r(const char* path, char* buffer, size_t buffer_size) {
  return __dirname_r(path, buffer, buffer_size);
}

char* basename(const char* path) {
  char* buf = __get_bionic_tls().basename_buf;
  int rc = __basename_r(path, buf, sizeof(__get_bionic_tls().basename_buf));
  return (rc < 0) ? nullptr : buf;
}

char* dirname(const char* path) {
  char* buf = __get_bionic_tls().dirname_buf;
  int rc = __dirname_r(path, buf, sizeof(__get_bionic_tls().dirname_buf));
  return (rc < 0) ? nullptr : buf;
}

"""

```
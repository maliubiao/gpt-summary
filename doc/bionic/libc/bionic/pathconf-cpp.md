Response:
Let's break down the thought process for generating the comprehensive response to the `pathconf.cpp` analysis request.

**1. Understanding the Core Request:**

The fundamental request is to analyze the `bionic/libc/bionic/pathconf.cpp` file and explain its functionality, its relationship to Android, its internal workings, its interaction with the dynamic linker (if any), potential usage errors, and how to debug it using Frida.

**2. Identifying Key Areas of Analysis:**

Based on the request and the code itself, I immediately identified the following crucial areas to address:

* **Functionality:** What does this code *do*?  What is the purpose of `pathconf` and `fpathconf`?
* **Android Relevance:** How does this code fit into the broader Android operating system?  Where is it used?
* **Internal Implementation:**  How are `pathconf` and `fpathconf` implemented within this file?  What are the helper functions doing?
* **Dynamic Linker:** Does this code directly involve the dynamic linker? If so, how? (Initial scan suggested limited direct involvement but acknowledged potential indirect connections).
* **Usage Errors:** What are common mistakes developers might make when using these functions?
* **Android Framework/NDK Integration:** How does a call originate from an Android app or native code and eventually reach this code?
* **Debugging with Frida:** How can Frida be used to inspect the execution of these functions?

**3. Deconstructing the Code:**

I then proceeded to examine the code snippet line by line:

* **Includes:** `<unistd.h>`, `<errno.h>`, `<limits.h>`, `<sys/vfs.h>`. Recognized these as standard POSIX/Linux headers providing necessary definitions. `sys/vfs.h` is particularly important for file system information.
* **Helper Functions:** Noticed `__filesizebits`, `__link_max`, `__2_symlinks`, and `__pathconf`. These are internal static helper functions. The naming convention (`__`) suggests they are internal implementation details.
* **`__filesizebits`:**  Identified its purpose: determining the file size bit limit based on the file system type. Noted the specific `SUPER_MAGIC` constants.
* **`__link_max`:**  Identified its purpose: determining the maximum number of hard links based on the file system type. Again, noted the specific `SUPER_MAGIC` constants.
* **`__2_symlinks`:** Identified its purpose: determining whether symbolic links are supported based on the file system type.
* **`__pathconf`:** This is the core logic. It takes a `statfs` structure and an integer `name` representing the configuration option. The `switch` statement handles different `_PC_*` constants. Recognized the return values of `-1` and setting `errno` for cases where information is unavailable or invalid.
* **`pathconf`:**  This is the public API. It takes a path string, gets the `statfs` information using `statfs`, and calls `__pathconf`.
* **`fpathconf`:** This is another public API. It takes a file descriptor, gets the `statfs` information using `fstatfs`, and calls `__pathconf`.

**4. Connecting Code to Concepts:**

As I analyzed the code, I linked it to relevant operating system concepts:

* **File Systems:** The use of `statfs` and `SUPER_MAGIC` constants clearly indicates interaction with different file system types.
* **POSIX Standards:** The `_PC_*` constants and the function names (`pathconf`, `fpathconf`) strongly suggest adherence to POSIX standards.
* **Limits:** The purpose of these functions is to retrieve limits and configuration options related to the file system and paths.

**5. Addressing Each Part of the Request:**

With a solid understanding of the code, I started constructing the response, addressing each point in the original request:

* **功能 (Functionality):**  Summarized the purpose of `pathconf` and `fpathconf` as retrieving file system configuration limits.
* **与 Android 的关系 (Relationship to Android):** Explained that it's part of Bionic, Android's C library, and is used by Android's Java framework, native code, and system services. Provided concrete examples like checking path length limits before creating files.
* **libc 函数的实现 (Implementation of libc functions):**  Detailed the steps within `pathconf` and `fpathconf`, explaining how they use `statfs`/`fstatfs` and delegate to `__pathconf`. Explained the logic within each helper function.
* **dynamic linker 的功能 (Dynamic Linker Functionality):**  Concluded that this code doesn't *directly* involve the dynamic linker but acknowledges the general process of how shared libraries are loaded. Provided a basic SO layout and described the linking process. *Initially, I considered whether `statfs` or `fstatfs` might indirectly involve dynamic linking if their implementation resides in a separate library, but decided to focus on the code at hand and mention the general principle.*
* **逻辑推理 (Logical Reasoning):** Created an input/output example to illustrate how `pathconf` might behave for a specific configuration option.
* **用户或编程常见的使用错误 (Common User/Programming Errors):**  Highlighted common mistakes like assuming fixed limits, ignoring error codes, and using incorrect `name` values.
* **Android framework or ndk 如何到达这里 (How Android reaches here):**  Provided a step-by-step explanation of the call flow from Java (using `java.io.File`), through the JNI layer, and into the native `pathconf` function.
* **Frida hook 示例 (Frida Hook Example):**  Provided practical Frida code snippets to demonstrate how to hook and inspect `pathconf` and `fpathconf`, logging arguments and return values.

**6. Refinement and Language:**

Finally, I reviewed and refined the response, ensuring clarity, accuracy, and using appropriate technical terminology. I focused on providing clear explanations and concrete examples. I made sure the language was natural-sounding Chinese.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Should I delve deeper into the implementation of `statfs` and `fstatfs`?  **Decision:** No, focus on the `pathconf.cpp` file itself, but mention that these functions retrieve file system information.
* **Initial thought:** Is the dynamic linker *completely* uninvolved? **Decision:** While not directly used *within this code*, it's essential for loading the shared library containing this code. Clarified this indirect connection.
* **Ensuring clarity:**  Used bullet points and clear headings to structure the information logically. Provided code examples for the Frida section to make it practical.

By following this structured approach, breaking down the request into manageable parts, and carefully analyzing the code, I was able to generate a comprehensive and informative response.
## 针对 `bionic/libc/bionic/pathconf.cpp` 的功能分析

这个 C++ 文件 `pathconf.cpp` 实现了 `pathconf` 和 `fpathconf` 这两个 POSIX 标准中定义的函数。这两个函数用于查询特定文件或目录路径相关的可配置限制。这些限制通常与底层文件系统的特性有关。

**功能列举:**

1. **获取文件系统相关的配置限制:**  `pathconf` 和 `fpathconf` 允许程序在运行时查询与特定路径或文件描述符关联的文件系统的各种限制和属性。
2. **路径相关的限制:**  例如，最大路径长度 (`_PC_PATH_MAX`)，最大文件名长度 (`_PC_NAME_MAX`)。
3. **文件相关的限制:**  例如，文件大小的位数 (`_PC_FILESIZEBITS`)，最大链接数 (`_PC_LINK_MAX`)。
4. **I/O 相关的限制:** 例如，管道缓冲区大小 (`_PC_PIPE_BUF`)，最小/最大/增量传输大小 (`_PC_ALLOC_SIZE_MIN`, `_PC_REC_XFER_ALIGN`, `_PC_REC_MIN_XFER_SIZE`, `_PC_REC_INCR_XFER_SIZE`, `_PC_REC_MAX_XFER_SIZE`)。
5. **其他 POSIX 定义的配置选项:**  例如，是否限制 `chown` 操作 (`_PC_CHOWN_RESTRICTED`)，是否允许截断过长的文件名 (`_PC_NO_TRUNC`)，禁用特殊字符 (`_PC_VDISABLE`)，是否支持同步/异步/优先级 I/O (`_PC_SYNC_IO`, `_PC_ASYNC_IO`, `_PC_PRIO_IO`)，最大符号链接数 (`_PC_SYMLINK_MAX`)，终端规范输入缓冲区最大字节数 (`_PC_MAX_CANON`)，终端输入队列的最大字节数 (`_PC_MAX_INPUT`)，以及是否支持符号链接 (`_PC_2_SYMLINKS`)。

**与 Android 功能的关系及举例说明:**

`pathconf` 和 `fpathconf` 是 Android 系统中非常基础的组成部分，因为它们提供了查询底层文件系统特性的能力。这对于编写跨平台兼容的应用程序非常重要，因为不同的文件系统可能有不同的限制。

* **应用程序开发:** 应用程序可以使用 `pathconf` 来确定给定路径的最大长度，以避免创建路径过长的文件或目录，从而导致错误。例如，一个文件管理应用在创建新文件夹时，可以先调用 `pathconf` 获取 `_PC_PATH_MAX`，然后检查用户输入的路径长度是否超过限制。
* **系统工具:**  像 `mkdir` 或 `touch` 这样的系统工具在创建文件或目录时，也可能间接地使用这些函数来确保操作符合文件系统的限制。
* **动态链接器:** 虽然 `pathconf.cpp` 本身不直接处理动态链接，但动态链接器在加载共享库时，可能会需要检查某些路径的属性，间接依赖于文件系统的特性，而这些特性可以通过 `pathconf` 查询。例如，在确定共享库的搜索路径时。

**libc 函数的实现细节:**

1. **`pathconf(const char* path, int name)`:**
   - 接收一个文件或目录的路径字符串 `path` 和一个指示要查询的配置选项的整数 `name`。
   - 内部首先声明一个 `struct statfs sb` 结构体，用于存储文件系统的信息。
   - 调用 `statfs(path, &sb)` 函数来获取指定路径所在的文件系统的统计信息，并存储在 `sb` 中。如果 `statfs` 调用失败（例如，路径不存在），则返回 -1 并设置 `errno`。
   - 如果 `statfs` 调用成功，则调用内部静态函数 `__pathconf(sb, name)`，将获取到的文件系统信息和配置选项传递给它。

2. **`fpathconf(int fd, int name)`:**
   - 接收一个已打开的文件描述符 `fd` 和一个指示要查询的配置选项的整数 `name`。
   - 内部首先声明一个 `struct statfs sb` 结构体。
   - 调用 `fstatfs(fd, &sb)` 函数来获取与文件描述符关联的文件系统的统计信息，并存储在 `sb` 中。如果 `fstatfs` 调用失败（例如，文件描述符无效），则返回 -1 并设置 `errno`。
   - 如果 `fstatfs` 调用成功，则调用内部静态函数 `__pathconf(sb, name)`，将获取到的文件系统信息和配置选项传递给它。

3. **`__pathconf(const struct statfs& s, int name)`:**
   - 接收一个 `statfs` 结构体 `s` (包含文件系统信息) 和一个配置选项 `name`。
   - 使用 `switch` 语句根据 `name` 的值，返回对应的配置值。
   - **针对具体 `name` 的实现:**
     - `_PC_FILESIZEBITS`: 调用 `__filesizebits(s)`，根据文件系统类型判断文件大小的位数（通常是 32 或 64）。
     - `_PC_LINK_MAX`: 调用 `__link_max(s)`，根据文件系统类型返回最大硬链接数。
     - `_PC_MAX_CANON`: 返回 `MAX_CANON` 宏定义的值，通常与终端规范输入缓冲区大小有关。
     - `_PC_MAX_INPUT`: 返回 `MAX_INPUT` 宏定义的值，通常与终端输入队列大小有关。
     - `_PC_NAME_MAX`: 返回 `s.f_namelen`，即文件系统中文件名的最大长度。
     - `_PC_PATH_MAX`: 返回 `PATH_MAX` 宏定义的值，即最大路径长度。
     - `_PC_PIPE_BUF`: 返回 `PIPE_BUF` 宏定义的值，即管道缓冲区的原子写入大小。
     - `_PC_2_SYMLINKS`: 调用 `__2_symlinks(s)`，根据文件系统类型判断是否支持符号链接。
     - `_PC_ALLOC_SIZE_MIN` 和 `_PC_REC_XFER_ALIGN`: 返回 `s.f_frsize`，通常是文件系统的块大小。
     - `_PC_REC_MIN_XFER_SIZE`: 返回 `s.f_bsize`，通常是文件系统的基本块大小。
     - `_PC_CHOWN_RESTRICTED`: 返回 `_POSIX_CHOWN_RESTRICTED` 宏定义的值，指示是否限制非特权用户更改文件所有者。
     - `_PC_NO_TRUNC`: 返回 `_POSIX_NO_TRUNC` 宏定义的值，指示是否截断过长的文件名。
     - `_PC_VDISABLE`: 返回 `_POSIX_VDISABLE` 宏定义的值，通常是一个用于禁用特殊终端字符的值。
     - 对于 `_PC_ASYNC_IO`、`_PC_PRIO_IO`、`_PC_REC_INCR_XFER_SIZE`、`_PC_REC_MAX_XFER_SIZE`、`_PC_SYMLINK_MAX`、`_PC_SYNC_IO` 这些选项，代码直接返回 -1，表示没有直接的 API 可以获取这些信息，调用者需要尝试操作来判断是否支持。这里**不会**设置 `errno` 为 `EINVAL`，因为代码理解了请求，只是没有直接的答案。
     - 对于未知的 `name` 值，设置 `errno` 为 `EINVAL` 并返回 -1。

4. **辅助静态函数 (`__filesizebits`, `__link_max`, `__2_symlinks`):**
   - 这些函数根据 `statfs` 结构体中 `f_type` 字段（文件系统魔数）来判断文件系统的类型，并根据不同的文件系统类型返回相应的配置值。这些值通常是根据常见文件系统的特性硬编码的。例如，`__filesizebits` 针对 `JFFS2`、`MSDOS` 和 `NCP` 文件系统返回 32，表示文件大小限制为 32 位。

**涉及 dynamic linker 的功能:**

`pathconf.cpp` 本身不直接处理动态链接过程。它的功能是在运行时查询文件系统的属性。然而，可以想象的是，某些查询到的文件系统属性可能会间接影响到动态链接器的行为。

**SO 布局样本和链接处理过程:**

由于 `pathconf.cpp` 属于 `libc.so` (bionic 中的 C 标准库)，其代码会被编译进 `libc.so` 这个共享库中。

**SO 布局样本 (简化):**

```
libc.so:
    .text:  <... 其他 libc 函数的代码 ...>
            pathconf:  <pathconf 函数的代码>
            fpathconf: <fpathconf 函数的代码>
            __pathconf: <__pathconf 函数的代码>
            __filesizebits: <__filesizebits 函数的代码>
            __link_max: <__link_max 函数的代码>
            __2_symlinks: <__2_symlinks 函数的代码>
            <... 其他 libc 函数的代码 ...>
    .data:  <... libc 的全局数据 ...>
    .bss:   <... libc 的未初始化数据 ...>
    .dynamic: <... 动态链接信息 ...>
    .symtab: <... 符号表 ...>
    .strtab: <... 字符串表 ...>
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序或共享库调用 `pathconf` 或 `fpathconf` 时，编译器会在符号表中查找这些函数。由于这些函数在 `libc.so` 中，编译器会生成对这些符号的外部引用。
2. **运行时链接:** 当程序启动或加载共享库时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责解析这些外部引用。
   - 动态链接器会加载 `libc.so` 到内存中。
   - 动态链接器会遍历程序的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table)，找到对 `pathconf` 和 `fpathconf` 的引用。
   - 动态链接器会查找 `libc.so` 的符号表，找到 `pathconf` 和 `fpathconf` 函数的实际地址。
   - 动态链接器会将这些实际地址填入 GOT 或 PLT 中，使得程序在调用这些函数时能够跳转到正确的代码位置。

**逻辑推理 (假设输入与输出):**

假设我们有一个文件 `/sdcard/Documents/my_file.txt` 存在于一个 ext4 文件系统上。

**假设输入:**

```c
const char* path = "/sdcard/Documents/my_file.txt";
int name = _PC_NAME_MAX;
```

**逻辑推理:**

1. 调用 `pathconf("/sdcard/Documents/my_file.txt", _PC_NAME_MAX)`。
2. `pathconf` 内部调用 `statfs("/sdcard/Documents/my_file.txt", &sb)`。
3. `statfs` 系统调用会获取 `/sdcard/Documents` 所在的文件系统 (假设是 ext4) 的信息，并填充到 `sb` 结构体中，其中包括 `sb.f_type` (ext4 的魔数) 和 `sb.f_namelen` (ext4 文件名的最大长度，例如 255)。
4. `pathconf` 接着调用 `__pathconf(sb, _PC_NAME_MAX)`。
5. `__pathconf` 的 `switch` 语句匹配到 `_PC_NAME_MAX`，返回 `sb.f_namelen` 的值。

**预期输出:**

`pathconf` 函数返回 255 (或 ext4 文件系统允许的最大文件名长度)。

**用户或编程常见的使用错误:**

1. **假设固定的限制:**  开发者可能会错误地假设所有文件系统都具有相同的限制，例如最大路径长度总是 256。实际上，不同的文件系统可能有不同的限制。应该使用 `pathconf` 或 `fpathconf` 来动态获取这些信息。
   ```c
   // 错误的做法：
   char buffer[256];
   strcpy(buffer, long_path); // 可能导致缓冲区溢出

   // 正确的做法：
   long path_max = pathconf("/", _PC_PATH_MAX);
   if (path_max == -1) {
       // 处理错误
   } else {
       char* buffer = (char*)malloc(path_max + 1);
       if (buffer) {
           strcpy(buffer, long_path); // 安全
           free(buffer);
       }
   }
   ```

2. **忽略错误返回值:** `pathconf` 和 `fpathconf` 在出错时会返回 -1 并设置 `errno`。开发者应该检查返回值并处理错误。
   ```c
   long max_name_len = pathconf(my_path, _PC_NAME_MAX);
   if (max_name_len == -1) {
       perror("pathconf"); // 输出错误信息
       // 处理错误，例如退出程序或采取其他措施
   } else {
       // 使用 max_name_len
   }
   ```

3. **使用不正确的 `name` 值:** 传递了 `pathconf` 或 `fpathconf` 不支持的 `name` 值会导致返回 -1 并设置 `errno` 为 `EINVAL`。应该查阅文档，确保使用的 `name` 值是有效的。

**Android framework or ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `pathconf` 的调用路径 (示例：创建文件):**

1. **Java Framework:** Android 应用程序通常通过 Java Framework 进行文件操作，例如使用 `java.io.File` 类创建文件。
   ```java
   File file = new File("/sdcard/Documents/new_file.txt");
   try {
       file.createNewFile();
   } catch (IOException e) {
       e.printStackTrace();
   }
   ```

2. **JNI 调用:** `java.io.File.createNewFile()` 最终会调用 native 方法。这个 native 方法位于 Android 运行时 (ART) 或 Dalvik 虚拟机中。

3. **Native 代码 (ART/Dalvik):**  虚拟机中的 native 代码会执行一些必要的检查和准备工作，然后通过 JNI (Java Native Interface) 调用到 Bionic 库中的 C/C++ 函数。对于文件创建，可能会调用到 `open()` 系统调用。

4. **`open()` 系统调用 (通过 Syscall):**  `open()` 系统调用最终会进入 Linux 内核。

5. **内核中的文件系统操作:** 内核中的文件系统代码会执行实际的文件创建操作，这期间可能会需要检查路径长度等限制。

**间接调用 `pathconf` 的可能性:**

虽然上述文件创建流程没有直接调用 `pathconf`，但某些 Java Framework 或 Native 代码在处理文件路径时，为了确保操作的正确性，可能会预先调用 `pathconf` 来获取路径长度限制。例如，在处理用户输入的文件路径时。

**Frida Hook 示例:**

可以使用 Frida 来 hook `pathconf` 和 `fpathconf` 函数，观察它们的调用和参数。

```python
import frida
import sys

package_name = "your.package.name"  # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['function'], message['payload']['args']))
    else:
        print(message)

def main():
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
        sys.exit(1)

    script_code = """
    'use strict';

    rpc.exports = {};

    const pathconfPtr = Module.findExportByName("libc.so", "pathconf");
    const pathconf = new NativeFunction(pathconfPtr, 'long', ['pointer', 'int']);

    const fpathconfPtr = Module.findExportByName("libc.so", "fpathconf");
    const fpathconf = new NativeFunction(fpathconfPtr, 'long', ['int', 'int']);

    Interceptor.attach(pathconfPtr, {
        onEnter: function(args) {
            const path = args[0].readUtf8String();
            const name = args[1].toInt32();
            let nameStr = "UNKNOWN";
            switch (name) {
                case 1: nameStr = "_PC_LINK_MAX"; break;
                case 2: nameStr = "_PC_MAX_CANON"; break;
                case 3: nameStr = "_PC_MAX_INPUT"; break;
                case 4: nameStr = "_PC_NAME_MAX"; break;
                case 5: nameStr = "_PC_PATH_MAX"; break;
                case 6: nameStr = "_PC_PIPE_BUF"; break;
                case 7: nameStr = "_PC_2_SYMLINKS"; break;
                case 8: nameStr = "_PC_ALLOC_SIZE_MIN"; break;
                case 9: nameStr = "_PC_REC_MIN_XFER_SIZE"; break;
                case 10: nameStr = "_PC_REC_MAX_XFER_SIZE"; break;
                case 11: nameStr = "_PC_REC_XFER_ALIGN"; break;
                case 12: nameStr = "_PC_CHOWN_RESTRICTED"; break;
                case 13: nameStr = "_PC_NO_TRUNC"; break;
                case 15: nameStr = "_PC_VDISABLE"; break;
                case 18: nameStr = "_PC_ASYNC_IO"; break;
                case 19: nameStr = "_PC_PRIO_IO"; break;
                case 20: nameStr = "_PC_SYNC_IO"; break;
                case 21: nameStr = "_PC_SYMLINK_MAX"; break;
                case 22: nameStr = "_PC_2_LOCAL_MAX"; break;
                case 23: nameStr = "_PC_2_SW_DEV"; break;
                case 30: nameStr = "_PC_FILESIZEBITS"; break;
                case 31: nameStr = "_PC_REC_INCR_XFER_SIZE"; break;
            }
            this.path = path;
            this.nameStr = nameStr;
            send({ function: "pathconf", args: [path, nameStr] });
        },
        onLeave: function(retval) {
            send({ function: "pathconf", args: [this.path, this.nameStr, "returned", retval.toString()] });
        }
    });

    Interceptor.attach(fpathconfPtr, {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const name = args[1].toInt32();
            let nameStr = "UNKNOWN";
            switch (name) {
                // ... (与 pathconf 相同的 case)
                case 30: nameStr = "_PC_FILESIZEBITS"; break;
                case 31: nameStr = "_PC_REC_INCR_XFER_SIZE"; break;
            }
            this.fd = fd;
            this.nameStr = nameStr;
            send({ function: "fpathconf", args: [fd, nameStr] });
        },
        onLeave: function(retval) {
            send({ function: "fpathconf", args: [this.fd, this.nameStr, "returned", retval.toString()] });
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] 脚本已加载，等待调用...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用说明:**

1. 将 `your.package.name` 替换成你要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试。
3. 运行 Frida 服务：`adb forward tcp:27042 tcp:27042`
4. 运行 Python 脚本。
5. 在你的 Android 应用中执行可能触发 `pathconf` 或 `fpathconf` 的操作 (例如，创建文件、访问文件属性等)。
6. Frida 脚本会拦截对这两个函数的调用，并打印出函数名、参数和返回值。

通过 Frida Hook，你可以观察到 Android Framework 或 NDK 中的哪些组件在何时调用了 `pathconf` 或 `fpathconf`，以及传递了哪些参数，从而更好地理解这些函数在 Android 系统中的使用场景。

### 提示词
```
这是目录为bionic/libc/bionic/pathconf.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <unistd.h>

#include <errno.h>
#include <limits.h>
#include <sys/vfs.h>

static long __filesizebits(const struct statfs& s) {
  switch (s.f_type) {
    case JFFS2_SUPER_MAGIC:
    case MSDOS_SUPER_MAGIC:
    case NCP_SUPER_MAGIC:
      return 32;
  }
  // There won't be any new 32-bit file systems.
  return 64;
}

static long __link_max(const struct statfs& s) {
  // These constant values were taken from kernel headers.
  // They're not available in uapi headers.
  switch (s.f_type) {
    case EXT2_SUPER_MAGIC:
      return 32000;
    case MINIX_SUPER_MAGIC:
      return 250;
    case MINIX2_SUPER_MAGIC:
      return 65530;
    case REISERFS_SUPER_MAGIC:
      return 0xffff - 1000;
    case UFS_MAGIC:
      return 32000;
  }
  return LINK_MAX;
}

static long __2_symlinks(const struct statfs& s) {
  switch (s.f_type) {
    case ADFS_SUPER_MAGIC:
    case BFS_MAGIC:
    case CRAMFS_MAGIC:
    case EFS_SUPER_MAGIC:
    case MSDOS_SUPER_MAGIC:
    case QNX4_SUPER_MAGIC:
      return 0;
  }
  return 1;
}

static long __pathconf(const struct statfs& s, int name) {
  switch (name) {
    case _PC_FILESIZEBITS:
      return __filesizebits(s);

    case _PC_LINK_MAX:
      return __link_max(s);

    case _PC_MAX_CANON:
      return MAX_CANON;

    case _PC_MAX_INPUT:
      return MAX_INPUT;

    case _PC_NAME_MAX:
      return s.f_namelen;

    case _PC_PATH_MAX:
      return PATH_MAX;

    case _PC_PIPE_BUF:
      return PIPE_BUF;

    case _PC_2_SYMLINKS:
      return __2_symlinks(s);

    case _PC_ALLOC_SIZE_MIN:  /* fall through */
    case _PC_REC_XFER_ALIGN:
      return s.f_frsize;

    case _PC_REC_MIN_XFER_SIZE:
      return s.f_bsize;

    case _PC_CHOWN_RESTRICTED:
      return _POSIX_CHOWN_RESTRICTED;

    case _PC_NO_TRUNC:
      return _POSIX_NO_TRUNC;

    case _PC_VDISABLE:
      return _POSIX_VDISABLE;

    case _PC_ASYNC_IO:
    case _PC_PRIO_IO:
    case _PC_REC_INCR_XFER_SIZE:
    case _PC_REC_MAX_XFER_SIZE:
    case _PC_SYMLINK_MAX:
    case _PC_SYNC_IO:
      // No API to answer these: the caller will have to "try it and see".
      // This differs from the next case in not setting errno to EINVAL,
      // since we did understand the question --- we just don't have a
      // good answer.
      return -1;

    default:
      errno = EINVAL;
      return -1;
  }
}

long pathconf(const char* path, int name) {
  struct statfs sb;
  if (statfs(path, &sb) == -1) {
    return -1;
  }
  return __pathconf(sb, name);
}

long fpathconf(int fd, int name) {
  struct statfs sb;
  if (fstatfs(fd, &sb) == -1) {
    return -1;
  }
  return __pathconf(sb, name);
}
```
Response:
Let's break down the thought process for analyzing the `fts.c` code. The request is comprehensive, so a structured approach is essential.

**1. Initial Understanding of the Request:**

The core goal is to analyze the `fts.c` file, a fundamental part of Android's Bionic libc, responsible for file system traversal. The request specifically asks for:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it tie into Android?
* **Detailed Implementation:**  Explain the libc functions within.
* **Dynamic Linking:**  Address aspects related to the dynamic linker.
* **Logic Inference:**  Provide examples of input/output.
* **Common Errors:** Highlight potential user/programmer mistakes.
* **Android Integration:** Show how Android frameworks/NDK reach this code.
* **Debugging:** Give Frida hook examples.

**2. High-Level Code Overview (Skimming and Identifying Key Functions):**

I would start by quickly scanning the code to identify the main functions and data structures. The function names themselves are quite descriptive: `fts_open`, `fts_read`, `fts_close`, `fts_children`, `fts_set`, etc. The `FTS` and `FTSENT` structures are also prominent. This provides a basic understanding of the module's purpose: to open, read, and manipulate a file system traversal.

**3. Core Function Analysis (Focusing on the Public API):**

I'd then delve into the main public functions (`fts_open`, `fts_read`, `fts_close`, `fts_children`, `fts_set`) to understand their roles and interactions.

* **`fts_open`:**  Clearly initializes the traversal. Pay attention to the `options` parameter and how it affects behavior (logical vs. physical, `NOCHDIR`, `FOLLOW`, etc.). The processing of the input `argv` (paths) is also important.
* **`fts_read`:**  The heart of the traversal. It retrieves the next entry. The different `fts_info` values (FTS_D, FTS_F, FTS_SL, FTS_DP, etc.) are key. The handling of `fts_instr` (FTS_SKIP, FTS_FOLLOW, FTS_AGAIN) is also significant.
* **`fts_close`:**  Cleanup and resource release. Returning to the original directory is a key aspect.
* **`fts_children`:**  Specifically for getting the immediate children of a directory. The `FTS_NAMEONLY` option is worth noting.
* **`fts_set`:**  Allows the user to influence the traversal behavior for specific entries.

**4. Detailed Implementation of Libc Functions (Internal Logic):**

Next, I would examine the internal static functions called by the public API. These functions perform the heavy lifting:

* **`fts_build`:** The core logic for reading directory contents and building the linked list of `FTSENT` structures. The handling of `FTS_NOSTAT`, symbolic links, and potential errors is crucial.
* **`fts_stat`:**  Handles the `stat` or `lstat` system calls to get file information. The logic for logical vs. physical traversal is implemented here.
* **`fts_alloc`, `fts_lfree`, `fts_palloc`, `fts_padjust`:** Memory management functions specific to `fts`. Understanding how they allocate and manage the `FTS` and `FTSENT` structures, including the variable-length path buffer, is important.
* **`fts_sort`:**  Implements sorting of directory entries if a comparison function is provided.
* **`fts_safe_changedir`:**  A critical function for ensuring safe directory changes, especially important when dealing with potential race conditions or malicious changes to the file system.

**5. Android Relevance and Examples:**

At this stage, I would start thinking about how these functions are used in the Android ecosystem.

* **File Managers:** Obvious example – they need to traverse the file system.
* **Package Manager:**  Needs to scan directories to find APKs.
* **`find` command (in ADB shell):** Likely uses `fts` internally.
* **NDK file operations:**  Any NDK code interacting with the file system might indirectly use `fts`.

Concrete examples like listing files in `/sdcard` or searching for a specific file are helpful.

**6. Dynamic Linking:**

This requires recognizing that `fts.c` is part of `libc.so`. I need to discuss:

* **`libc.so` layout:**  Basic understanding of how shared libraries are structured (code, data, GOT, PLT).
* **Linking process:** When an application calls `fts_open`, how the dynamic linker resolves this symbol to the implementation in `libc.so`.
* **No direct dynamic linking in `fts.c` itself:**  It's a *provider* of functionality, not a consumer of dynamic libraries. The dynamic linking aspect is about how applications *use* `fts`.

**7. Logic Inference (Input/Output):**

Simple examples of calling `fts_open` with different paths and options, and the expected output from `fts_read`, are needed. Consider edge cases like empty directories, non-existent paths, and symbolic links.

**8. Common Errors:**

Think about the pitfalls developers might encounter when using `fts`:

* **Forgetting to call `fts_close`:** Resource leaks.
* **Misunderstanding logical vs. physical traversal:**  Incorrectly handling symbolic links.
* **Not checking `fts_info` and `fts_errno`:** Missing error conditions.
* **Modifying the file system during traversal:**  Unpredictable behavior.

**9. Android Framework/NDK Integration and Frida Hooks:**

Trace the path from high-level Android APIs down to the native level:

* **Java APIs:** `java.io.File`, `android.content.pm.PackageManager`.
* **JNI:**  The bridge between Java and native code.
* **NDK:**  Directly using `fts.h` in C/C++ code.

Frida examples should focus on hooking key `fts` functions to observe their behavior.

**10. Structuring the Answer:**

Finally, organize the information logically, using headings and bullet points for clarity. Use clear and concise language. Provide code snippets where appropriate. Address each part of the original request.

**Self-Correction/Refinement during the process:**

* **Initial assumption might be too narrow:**  Realize that `fts` isn't just about listing files; it's a general-purpose traversal mechanism.
* **Overlooking details:**  Go back and carefully read the comments and code to catch nuances like the `FTS_SEEDOT` option or the complexities of `fts_build`.
* **Clarifying dynamic linking:**  Ensure the explanation focuses on how applications link to `fts`, not the internals of `fts` linking to other libraries.
* **Improving example clarity:**  Make sure the input/output examples are easy to understand and illustrate specific behaviors.

By following this structured approach, and iteratively refining the understanding, a comprehensive and accurate analysis of the `fts.c` code can be produced.
好的，我们来详细分析一下 `bionic/libc/bionic/fts.c` 这个文件。

**功能概览**

`fts.c` 文件实现了 `fts` (File Tree System) 系列函数，主要用于遍历文件系统目录树。它提供了一种通用的、灵活的方式来访问目录及其子目录下的文件和目录。

核心功能包括：

* **打开文件系统树 (`fts_open`)**: 初始化文件系统遍历，接收要遍历的路径列表和选项。
* **读取下一个条目 (`fts_read`)**:  获取文件系统树中的下一个文件或目录的条目信息。
* **关闭文件系统树 (`fts_close`)**: 清理和释放 `fts_open` 分配的资源。
* **获取子节点 (`fts_children`)**: 获取当前目录的子目录和文件列表。
* **设置指令 (`fts_set`)**: 允许用户在遍历过程中对特定条目设置指令，例如跳过或重新访问。

**与 Android 功能的关系及举例说明**

`fts` 系列函数是 POSIX 标准的一部分，被广泛用于各种需要遍历文件系统的场景。在 Android 中，它们在很多地方被使用：

* **文件管理器**: 文件管理器需要遍历目录结构来显示文件和文件夹。例如，当你打开一个文件管理器应用，浏览 `/sdcard` 目录时，底层的实现很可能就用到了 `fts` 或类似的机制。
* **包管理器 (`pm`)**:  Android 的包管理器在安装、卸载应用时，需要扫描文件系统中的 APK 文件和应用数据目录。
* **`find` 命令 (在 ADB shell 中)**:  当你通过 `adb shell` 使用 `find` 命令来搜索文件时，它很可能依赖于 `fts` 来遍历指定的目录。
* **`du` 命令 (在 ADB shell 中)**:  用于计算目录和文件大小的 `du` 命令，也需要遍历文件系统。
* **备份和恢复工具**:  这些工具需要遍历文件系统来备份和恢复数据。
* **媒体扫描器**: Android 的媒体扫描器扫描设备上的媒体文件（图片、音频、视频），需要遍历目录。

**举例说明**: 假设一个 Android 应用需要列出 `/sdcard/Pictures` 目录下所有 `.jpg` 文件，它可能会通过 NDK 调用 C 标准库的 `opendir`, `readdir`, `closedir` 或者更方便的 `fts` 系列函数来实现。

**libc 函数的实现细节**

下面详细解释 `fts.c` 中实现的 libc 函数：

1. **`fts_open(char * const *argv, int options, int (*compar)(const FTSENT **, const FTSENT **))`**:
   * **功能**: 初始化文件系统遍历。
   * **实现**:
     * 分配 `FTS` 结构体，用于存储遍历状态信息。
     * 检查输入路径 `argv` 是否为空。
     * 根据 `options` 设置遍历选项（如 `FTS_PHYSICAL`、`FTS_LOGICAL`、`FTS_NOCHDIR` 等）。
     * 为每个输入的路径分配 `FTSENT` 结构体，表示文件系统的根节点。
     * 如果提供了比较函数 `compar`，则会对根节点进行排序。
     * 分配一个虚拟的 `FTSENT` 结构体作为起始点，方便 `fts_read` 的处理。
     * 如果没有设置 `FTS_NOCHDIR` 选项，则打开当前目录的文件描述符 `fts_rfd`，以便后续可以返回到初始目录。
   * **选项说明**:
     * `FTS_PHYSICAL`: 物理遍历，不跟随符号链接指向的目录。
     * `FTS_LOGICAL`: 逻辑遍历，跟随符号链接指向的目录。
     * `FTS_NOCHDIR`: 不改变当前工作目录。
     * `FTS_COMFOLLOW`: 如果命令行参数是符号链接，则跟随。
     * `FTS_SEEDOT`: 返回 `.` 和 `..` 目录项。
     * `FTS_XDEV`: 不跨越文件系统边界。
     * `FTS_NOSTAT`: 不获取文件状态信息，提高性能。
     * `FTS_FOR_FTW`: 用于 `ftw` 和 `nftw` 函数。

2. **`fts_read(FTS *sp)`**:
   * **功能**: 获取文件系统树中的下一个条目。
   * **实现**:
     * 检查是否已完成遍历或发生不可恢复的错误。
     * 获取当前节点 `sp->fts_cur`。
     * 处理用户指令 `fts_instr`，例如 `FTS_AGAIN`（重新访问）、`FTS_FOLLOW`（跟随符号链接）、`FTS_SKIP`（跳过）。
     * 如果当前节点是目录 (`FTS_D`)，则根据选项和用户指令，可能跳过、跨越挂载点，或读取子节点。
     * 如果设置了 `FTS_NOCHDIR`，则需要构建完整的绝对路径。
     * 如果遍历到子目录，则递归调用 `fts_build` 来获取子目录的条目。
     * 移动到下一个兄弟节点或父节点。
     * 在后序遍历时，返回目录的 `FTS_DP` 状态。
     * 返回下一个文件或目录的 `FTSENT` 结构体，包含文件信息。

3. **`fts_close(FTS *sp)`**:
   * **功能**: 关闭文件系统遍历，释放资源。
   * **实现**:
     * 释放已分配的 `FTSENT` 结构体链表。
     * 释放子节点链表 `sp->fts_child`。
     * 释放排序数组 `sp->fts_array`。
     * 释放路径缓冲区 `sp->fts_path`。
     * 释放 `FTS` 结构体本身。
     * 如果 `fts_open` 时打开了初始目录的文件描述符 `fts_rfd`，则切换回原始目录并关闭该文件描述符。

4. **`fts_children(FTS *sp, int instr)`**:
   * **功能**: 获取当前目录的子目录和文件列表。
   * **实现**:
     * 检查指令 `instr` 是否有效（目前只支持 `FTS_NAMEONLY`）。
     * 如果当前节点不是目录，则返回 `NULL`。
     * 如果之前已经读取过子节点，则释放旧的子节点列表。
     * 调用 `fts_build` 函数，并传入 `BCHILD` 或 `BNAMES` 标志，以读取子节点。
     * 如果当前目录是相对路径，并且在 `fts_read` 切换到根目录之前调用，则需要先切换到该目录。

5. **`fts_set(FTS *sp, FTSENT *p, int instr)`**:
   * **功能**:  允许用户在遍历过程中对特定的 `FTSENT` 条目设置指令。
   * **实现**:
     * 检查指令 `instr` 是否为有效值 (`FTS_AGAIN`, `FTS_FOLLOW`, `FTS_NOINSTR`, `FTS_SKIP`)。
     * 将指令设置到 `FTSENT` 结构的 `fts_instr` 字段中，供 `fts_read` 函数处理。

**内部静态函数的实现**

* **`fts_build(FTS *sp, int type)`**:  核心函数，用于读取目录内容并构建 `FTSENT` 链表。它处理 `readdir` 的结果，并根据 `options` 和 `type` 决定是否需要调用 `stat` 获取文件信息。
* **`fts_stat(FTS *sp, FTSENT *p, int follow, int dfd)`**:  调用 `stat` 或 `lstat` 系统调用获取文件状态信息。根据 `FTS_LOGICAL` 和 `follow` 参数决定是否跟随符号链接。
* **`fts_alloc(FTS *sp, const char *name, size_t namelen)`**:  分配 `FTSENT` 结构体及其包含的文件名和可能的 `stat` 结构体的内存。
* **`fts_lfree(FTSENT *head)`**:  释放 `FTSENT` 链表。
* **`fts_palloc(FTS *sp, size_t more)`**:  重新分配用于存储文件路径的缓冲区。
* **`fts_padjust(FTS *sp, FTSENT *head)`**:  当路径缓冲区重新分配后，调整 `FTSENT` 结构体中指向路径的指针。
* **`fts_maxarglen(char * const *argv)`**:  计算命令行参数的最大长度，用于初始分配路径缓冲区。
* **`fts_safe_changedir(FTS *sp, FTSENT *p, int fd, const char *path)`**:  安全地切换目录，避免被外部修改文件系统结构所影响。它会检查目标目录的设备号和 inode 号是否与预期一致。

**涉及 dynamic linker 的功能**

`fts.c` 本身并没有直接涉及 dynamic linker 的功能。它是一个被链接到 `libc.so` 中的代码模块，供其他程序调用。当一个 Android 应用调用 `fts_open` 等函数时，dynamic linker 会负责将这些函数符号解析到 `libc.so` 中对应的实现。

**so 布局样本**

假设一个简单的 Android 应用 `my_app` 链接了 `libc.so`，其内存布局可能如下所示（简化）：

```
+-----------------+  <-- 应用程序代码段
|  my_app 代码    |
+-----------------+
|  ...            |
+-----------------+  <-- .plt (Procedure Linkage Table)
|  fts_open@plt   |  <-- 用于外部函数调用的跳转表项
|  fts_read@plt   |
|  ...            |
+-----------------+
|  ...            |
+-----------------+  <-- .got (Global Offset Table)
|  fts_open@got   |  <-- 存放 fts_open 函数实际地址
|  fts_read@got   |
|  ...            |
+-----------------+
|  ...            |
+-----------------+  <-- 应用程序数据段
|  ...            |
+-----------------+

+-----------------+  <-- libc.so 代码段
|  fts_open       |  <-- fts_open 函数的实际代码
|  fts_read       |
|  ...            |
+-----------------+
|  ...            |
+-----------------+  <-- libc.so 数据段
|  ...            |
+-----------------+
```

**链接的处理过程**

1. **编译时**: 编译器遇到 `fts_open` 等函数调用时，会生成对这些外部符号的引用，并在 `.plt` 和 `.got` 中创建相应的条目。`.plt` 中的条目会跳转到 `.got` 中的地址。初始时，`.got` 中的地址指向 `.plt` 中的下一条指令，以便 dynamic linker 可以介入。
2. **加载时**: Android 的加载器（属于 dynamic linker 的一部分）加载 `my_app` 和 `libc.so`。
3. **动态链接**: 当 `my_app` 首次调用 `fts_open` 时：
   * 程序执行到 `fts_open@plt`。
   * `fts_open@plt` 跳转到 `fts_open@got`。
   * 初始时，`fts_open@got` 指向 `.plt` 中的一段代码，这段代码会调用 dynamic linker。
   * Dynamic linker 查找 `libc.so` 中的 `fts_open` 函数的地址。
   * Dynamic linker 将 `fts_open` 函数的实际地址写入 `fts_open@got`。
   * 下次 `my_app` 调用 `fts_open` 时，`fts_open@plt` 会直接跳转到 `fts_open` 在 `libc.so` 中的实际地址。

**逻辑推理：假设输入与输出**

假设我们使用以下代码调用 `fts_open` 和 `fts_read`：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fts.h>
#include <errno.h>

int main() {
    char *paths[] = {"./test_dir", NULL};
    int options = FTS_PHYSICAL;
    FTS *ftsp;
    FTSENT *node;

    // 创建一个测试目录和一些文件
    system("mkdir test_dir");
    system("touch test_dir/file1.txt");
    system("mkdir test_dir/subdir");
    system("touch test_dir/subdir/file2.txt");

    ftsp = fts_open(paths, options, NULL);
    if (ftsp == NULL) {
        perror("fts_open");
        return 1;
    }

    while ((node = fts_read(ftsp)) != NULL) {
        switch (node->fts_info) {
            case FTS_D:
                printf("Dir: %s\n", node->fts_path);
                break;
            case FTS_F:
                printf("File: %s\n", node->fts_path);
                break;
            case FTS_DP:
                printf("Post-order Dir: %s\n", node->fts_path);
                break;
            case FTS_NS:
                printf("Error stating: %s (%s)\n", node->fts_path, strerror(node->fts_errno));
                break;
            default:
                break;
        }
    }

    if (errno != 0) {
        perror("fts_read");
        fts_close(ftsp);
        return 1;
    }

    if (fts_close(ftsp) != 0) {
        perror("fts_close");
        return 1;
    }

    system("rm -rf test_dir"); // 清理测试目录
    return 0;
}
```

**预期输出**:

```
Dir: ./test_dir
File: ./test_dir/file1.txt
Dir: ./test_dir/subdir
File: ./test_dir/subdir/file2.txt
Post-order Dir: ./test_dir/subdir
Post-order Dir: ./test_dir
```

**用户或编程常见的使用错误**

1. **忘记调用 `fts_close`**: 这会导致资源泄漏，特别是当 `fts_open` 成功打开了文件描述符时。
2. **不检查 `fts_info` 和 `fts_errno`**:  `fts_read` 返回的 `FTSENT` 结构体的 `fts_info` 字段指示了当前条目的类型和状态。如果不检查这个字段，可能会错误地处理文件或忽略错误。`fts_errno` 记录了 `stat` 等系统调用失败时的错误码。
3. **混淆 `FTS_PHYSICAL` 和 `FTS_LOGICAL`**:  选择错误的遍历方式可能导致程序行为不符合预期，尤其是在处理符号链接时。
4. **在遍历过程中修改文件系统**:  这可能导致 `fts` 的行为变得不可预测，甚至崩溃。
5. **假设文件总是存在且可访问**:  应该处理 `FTS_NS` 等状态，表示无法获取文件信息。
6. **不正确地使用 `fts_set`**:  对 `fts_set` 设置无效的指令会导致错误。
7. **在多线程环境中使用同一个 `FTS` 结构体**: `FTS` 结构体不是线程安全的。

**Android framework or ndk 如何一步步的到达这里**

1. **Android Framework (Java 层)**: 假设一个文件管理器应用需要列出某个目录下的文件。它可能会使用 `java.io.File` 类来进行操作。

   ```java
   File dir = new File("/sdcard/Download");
   File[] files = dir.listFiles();
   if (files != null) {
       for (File file : files) {
           System.out.println(file.getAbsolutePath());
       }
   }
   ```

2. **JNI (Java Native Interface)**: `java.io.File` 的底层实现最终会调用 Native 代码。例如，`listFiles()` 方法可能会调用 `libjavacrypto.so` 或 `libandroid_runtime.so` 中的 JNI 函数。

3. **NDK (Native Development Kit)**: 这些 JNI 函数可能会直接或间接地调用 C 标准库函数，例如 `opendir`, `readdir`, `closedir`，或者更高级的 `fts` 系列函数。  例如，`android_os_File_listImpl` 函数就可能使用底层的目录遍历机制。

4. **Bionic libc (`libc.so`)**:  最终，对 `fts_open`, `fts_read` 等函数的调用会到达 `bionic/libc/bionic/fts.c` 中的实现。

**Frida hook 示例调试步骤**

我们可以使用 Frida hook `fts_open` 和 `fts_read` 函数来观察其行为。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fts_open"), {
    onEnter: function(args) {
        var paths = new NativePointer(args[0]);
        var options = args[1].toInt();
        var pathArray = [];
        for (var i = 0; ; i++) {
            var pathPtr = paths.readPointer();
            if (pathPtr.isNull())
                break;
            pathArray.push(pathPtr.readCString());
            paths = paths.add(Process.pointerSize);
        }
        console.log("[FTS_OPEN] Paths:", pathArray, "Options:", options.toString(16));
    },
    onLeave: function(retval) {
        console.log("[FTS_OPEN] Returned:", retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "fts_read"), {
    onEnter: function(args) {
        console.log("[FTS_READ] Calling fts_read");
    },
    onLeave: function(retval) {
        if (!retval.isNull()) {
            var ftsent = ptr(retval);
            var pathPtr = ftsent.readPointer(); // 实际是 fts_path，但这里简化
            var info = ftsent.add(Process.pointerSize * 2).readU16(); // fts_info 的偏移量
            var path = pathPtr.readCString();
            console.log("[FTS_READ] Returned FTSENT:", path, "Info:", info);
        } else {
            console.log("[FTS_READ] Returned NULL");
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**调试步骤**:

1. **保存脚本**: 将上面的 Python 代码保存为 `frida_fts_hook.py`。
2. **安装 Frida**: 确保你的系统上安装了 Frida 和 Frida Server (在 Android 设备上运行)。
3. **运行目标应用**: 运行你想要监控的 Android 应用。
4. **执行 Frida 脚本**: 在你的电脑上运行 `python frida_fts_hook.py`。将 `your.target.package` 替换为实际的应用包名。
5. **操作应用**: 在 Android 应用中执行会触发文件系统遍历的操作，例如浏览文件或搜索文件。
6. **查看输出**: Frida 脚本会将 `fts_open` 和 `fts_read` 的调用信息打印到终端，包括传递的路径、选项以及返回的 `FTSENT` 结构体的信息。

这个 Frida 脚本会拦截 `fts_open` 和 `fts_read` 函数，并在函数入口和出口打印相关信息，帮助你理解应用是如何使用这些函数的。

希望以上详细的分析能够帮助你理解 `bionic/libc/bionic/fts.c` 的功能和在 Android 中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/fts.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: fts.c,v 1.60 2021/01/08 16:06:30 tb Exp $	*/

/*-
 * Copyright (c) 1990, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))

static FTSENT	*fts_alloc(FTS *, const char *, size_t);
static FTSENT	*fts_build(FTS *, int);
static void	 fts_lfree(FTSENT *);
static void	 fts_load(FTS *, FTSENT *);
static size_t	 fts_maxarglen(char * const *);
static void	 fts_padjust(FTS *, FTSENT *);
static int	 fts_palloc(FTS *, size_t);
static FTSENT	*fts_sort(FTS *, FTSENT *, int);
static u_short	 fts_stat(FTS *, FTSENT *, int, int);
static int	 fts_safe_changedir(FTS *, FTSENT *, int, const char *);

#define	ISDOT(a)	(a[0] == '.' && (!a[1] || (a[1] == '.' && !a[2])))

#define	CLR(opt)	(sp->fts_options &= ~(opt))
#define	ISSET(opt)	(sp->fts_options & (opt))
#define	SET(opt)	(sp->fts_options |= (opt))

#define	FCHDIR(sp, fd)	(!ISSET(FTS_NOCHDIR) && fchdir(fd))

/* fts_build flags */
#define	BCHILD		1		/* fts_children */
#define	BNAMES		2		/* fts_children, names only */
#define	BREAD		3		/* fts_read */

FTS *
__fts_open(char * const *argv, int options,
    int (*compar)(const FTSENT **, const FTSENT **))
{
	FTS *sp;
	FTSENT *p, *root;
	int nitems;
	FTSENT *parent, *prev;

	/* Android: options check moved to __fts_open() for ftw(). */

	/* At least one path must be specified. */
	if (*argv == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	/* Allocate/initialize the stream */
	if ((sp = calloc(1, sizeof(FTS))) == NULL)
		return (NULL);
	sp->fts_compar = compar;
	sp->fts_options = options;

	/* Logical walks turn on NOCHDIR; symbolic links are too hard. */
	if (ISSET(FTS_LOGICAL))
		SET(FTS_NOCHDIR);

	/*
	 * Start out with 1K of path space, and enough, in any case,
	 * to hold the user's paths.
	 */
	if (fts_palloc(sp, MAXIMUM(fts_maxarglen(argv), PATH_MAX)))
		goto mem1;

	/* Allocate/initialize root's parent. */
	if ((parent = fts_alloc(sp, "", 0)) == NULL)
		goto mem2;
	parent->fts_level = FTS_ROOTPARENTLEVEL;

	/* Allocate/initialize root(s). */
	for (root = prev = NULL, nitems = 0; *argv; ++argv, ++nitems) {
		if ((p = fts_alloc(sp, *argv, strlen(*argv))) == NULL)
			goto mem3;
		p->fts_level = FTS_ROOTLEVEL;
		p->fts_parent = parent;
		p->fts_accpath = p->fts_name;
		p->fts_info = fts_stat(sp, p, ISSET(FTS_COMFOLLOW), -1);

		// Android: for ftw/nftw we need to fail early: http://b/31152735
		if ((options & FTS_FOR_FTW) != 0 && p->fts_info == FTS_NS) goto mem3;

		/* Command-line "." and ".." are real directories. */
		if (p->fts_info == FTS_DOT)
			p->fts_info = FTS_D;

		/*
		 * If comparison routine supplied, traverse in sorted
		 * order; otherwise traverse in the order specified.
		 */
		if (compar) {
			p->fts_link = root;
			root = p;
		} else {
			p->fts_link = NULL;
			if (root == NULL)
				root = p;
			else
				prev->fts_link = p;
			prev = p;
		}
	}
	if (compar && nitems > 1)
		root = fts_sort(sp, root, nitems);

	/*
	 * Allocate a dummy pointer and make fts_read think that we've just
	 * finished the node before the root(s); set p->fts_info to FTS_INIT
	 * so that everything about the "current" node is ignored.
	 */
	if ((sp->fts_cur = fts_alloc(sp, "", 0)) == NULL)
		goto mem3;
	sp->fts_cur->fts_link = root;
	sp->fts_cur->fts_info = FTS_INIT;

	/*
	 * If using chdir(2), grab a file descriptor pointing to dot to ensure
	 * that we can get back here; this could be avoided for some paths,
	 * but almost certainly not worth the effort.  Slashes, symbolic links,
	 * and ".." are all fairly nasty problems.  Note, if we can't get the
	 * descriptor we run anyway, just more slowly.
	 */
	if (!ISSET(FTS_NOCHDIR) &&
	    (sp->fts_rfd = open(".", O_RDONLY | O_CLOEXEC)) == -1)
		SET(FTS_NOCHDIR);

	if (nitems == 0)
		free(parent);

	return (sp);

mem3:	fts_lfree(root);
	free(parent);
mem2:	free(sp->fts_path);
mem1:	free(sp);
	return (NULL);
}
DEF_WEAK(fts_open);

static void
fts_load(FTS *sp, FTSENT *p)
{
	size_t len;
	char *cp;

	/*
	 * Load the stream structure for the next traversal.  Since we don't
	 * actually enter the directory until after the preorder visit, set
	 * the fts_accpath field specially so the chdir gets done to the right
	 * place and the user can access the first node.  From fts_open it's
	 * known that the path will fit.
	 */
	len = p->fts_pathlen = p->fts_namelen;
	memmove(sp->fts_path, p->fts_name, len + 1);
	if ((cp = strrchr(p->fts_name, '/')) && (cp != p->fts_name || cp[1])) {
		len = strlen(++cp);
		memmove(p->fts_name, cp, len + 1);
		p->fts_namelen = len;
	}
	p->fts_accpath = p->fts_path = sp->fts_path;
	sp->fts_dev = p->fts_dev;
}

int
fts_close(FTS *sp)
{
	FTSENT *freep, *p;
	int rfd, error = 0;

	/*
	 * This still works if we haven't read anything -- the dummy structure
	 * points to the root list, so we step through to the end of the root
	 * list which has a valid parent pointer.
	 */
	if (sp->fts_cur) {
		for (p = sp->fts_cur; p->fts_level >= FTS_ROOTLEVEL;) {
			freep = p;
			p = p->fts_link ? p->fts_link : p->fts_parent;
			free(freep);
		}
		free(p);
	}

	/* Stash the original directory fd if needed. */
	rfd = ISSET(FTS_NOCHDIR) ? -1 : sp->fts_rfd;

	/* Free up child linked list, sort array, path buffer, stream ptr.*/
	if (sp->fts_child)
		fts_lfree(sp->fts_child);
	free(sp->fts_array);
	free(sp->fts_path);
	free(sp);

	/* Return to original directory, checking for error. */
	if (rfd != -1) {
		int saved_errno;
		error = fchdir(rfd);
		saved_errno = errno;
		(void)close(rfd);
		errno = saved_errno;
	}

	return (error);
}
DEF_WEAK(fts_close);

/*
 * Special case of "/" at the end of the path so that slashes aren't
 * appended which would cause paths to be written as "....//foo".
 */
#define	NAPPEND(p)							\
	(p->fts_path[p->fts_pathlen - 1] == '/'				\
	    ? p->fts_pathlen - 1 : p->fts_pathlen)

FTSENT *
fts_read(FTS *sp)
{
	FTSENT *p, *tmp;
	int instr;
	char *t;
	int saved_errno;

	/* If finished or unrecoverable error, return NULL. */
	if (sp->fts_cur == NULL || ISSET(FTS_STOP))
		return (NULL);

	/* Set current node pointer. */
	p = sp->fts_cur;

	/* Save and zero out user instructions. */
	instr = p->fts_instr;
	p->fts_instr = FTS_NOINSTR;

	/* Any type of file may be re-visited; re-stat and re-turn. */
	if (instr == FTS_AGAIN) {
		p->fts_info = fts_stat(sp, p, 0, -1);
		return (p);
	}

	/*
	 * Following a symlink -- SLNONE test allows application to see
	 * SLNONE and recover.  If indirecting through a symlink, have
	 * keep a pointer to current location.  If unable to get that
	 * pointer, follow fails.
	 */
	if (instr == FTS_FOLLOW &&
	    (p->fts_info == FTS_SL || p->fts_info == FTS_SLNONE)) {
		p->fts_info = fts_stat(sp, p, 1, -1);
		if (p->fts_info == FTS_D && !ISSET(FTS_NOCHDIR)) {
			if ((p->fts_symfd =
			    open(".", O_RDONLY | O_CLOEXEC)) == -1) {
				p->fts_errno = errno;
				p->fts_info = FTS_ERR;
			} else
				p->fts_flags |= FTS_SYMFOLLOW;
		}
		return (p);
	}

	/* Directory in pre-order. */
	if (p->fts_info == FTS_D) {
		/* If skipped or crossed mount point, do post-order visit. */
		if (instr == FTS_SKIP ||
		    (ISSET(FTS_XDEV) && p->fts_dev != sp->fts_dev)) {
			if (p->fts_flags & FTS_SYMFOLLOW)
				(void)close(p->fts_symfd);
			if (sp->fts_child) {
				fts_lfree(sp->fts_child);
				sp->fts_child = NULL;
			}
			p->fts_info = FTS_DP;
			return (p);
		}

		/* Rebuild if only read the names and now traversing. */
		if (sp->fts_child && ISSET(FTS_NAMEONLY)) {
			CLR(FTS_NAMEONLY);
			fts_lfree(sp->fts_child);
			sp->fts_child = NULL;
		}

		/*
		 * Cd to the subdirectory.
		 *
		 * If have already read and now fail to chdir, whack the list
		 * to make the names come out right, and set the parent errno
		 * so the application will eventually get an error condition.
		 * Set the FTS_DONTCHDIR flag so that when we logically change
		 * directories back to the parent we don't do a chdir.
		 *
		 * If haven't read do so.  If the read fails, fts_build sets
		 * FTS_STOP or the fts_info field of the node.
		 */
		if (sp->fts_child) {
			if (fts_safe_changedir(sp, p, -1, p->fts_accpath)) {
				p->fts_errno = errno;
				p->fts_flags |= FTS_DONTCHDIR;
				for (p = sp->fts_child; p; p = p->fts_link)
					p->fts_accpath =
					    p->fts_parent->fts_accpath;
			}
		} else if ((sp->fts_child = fts_build(sp, BREAD)) == NULL) {
			if (ISSET(FTS_STOP))
				return (NULL);
			return (p);
		}
		p = sp->fts_child;
		sp->fts_child = NULL;
		goto name;
	}

	/* Move to the next node on this level. */
next:	tmp = p;
	if ((p = p->fts_link)) {
		free(tmp);

		/*
		 * If reached the top, return to the original directory (or
		 * the root of the tree), and load the paths for the next root.
		 */
		if (p->fts_level == FTS_ROOTLEVEL) {
			if (FCHDIR(sp, sp->fts_rfd)) {
				SET(FTS_STOP);
				return (NULL);
			}
			fts_load(sp, p);
			return (sp->fts_cur = p);
		}

		/*
		 * User may have called fts_set on the node.  If skipped,
		 * ignore.  If followed, get a file descriptor so we can
		 * get back if necessary.
		 */
		if (p->fts_instr == FTS_SKIP)
			goto next;
		if (p->fts_instr == FTS_FOLLOW) {
			p->fts_info = fts_stat(sp, p, 1, -1);
			if (p->fts_info == FTS_D && !ISSET(FTS_NOCHDIR)) {
				if ((p->fts_symfd =
				    open(".", O_RDONLY | O_CLOEXEC)) == -1) {
					p->fts_errno = errno;
					p->fts_info = FTS_ERR;
				} else
					p->fts_flags |= FTS_SYMFOLLOW;
			}
			p->fts_instr = FTS_NOINSTR;
		}

name:		t = sp->fts_path + NAPPEND(p->fts_parent);
		*t++ = '/';
		memmove(t, p->fts_name, p->fts_namelen + 1);
		return (sp->fts_cur = p);
	}

	/* Move up to the parent node. */
	p = tmp->fts_parent;
	free(tmp);

	if (p->fts_level == FTS_ROOTPARENTLEVEL) {
		/*
		 * Done; free everything up and set errno to 0 so the user
		 * can distinguish between error and EOF.
		 */
		free(p);
		errno = 0;
		return (sp->fts_cur = NULL);
	}

	/* NUL terminate the pathname. */
	sp->fts_path[p->fts_pathlen] = '\0';

	/*
	 * Return to the parent directory.  If at a root node or came through
	 * a symlink, go back through the file descriptor.  Otherwise, cd up
	 * one directory.
	 */
	if (p->fts_level == FTS_ROOTLEVEL) {
		if (FCHDIR(sp, sp->fts_rfd)) {
			SET(FTS_STOP);
			sp->fts_cur = p;
			return (NULL);
		}
	} else if (p->fts_flags & FTS_SYMFOLLOW) {
		if (FCHDIR(sp, p->fts_symfd)) {
			saved_errno = errno;
			(void)close(p->fts_symfd);
			errno = saved_errno;
			SET(FTS_STOP);
			sp->fts_cur = p;
			return (NULL);
		}
		(void)close(p->fts_symfd);
	} else if (!(p->fts_flags & FTS_DONTCHDIR) &&
	    fts_safe_changedir(sp, p->fts_parent, -1, "..")) {
		SET(FTS_STOP);
		sp->fts_cur = p;
		return (NULL);
	}
	p->fts_info = p->fts_errno ? FTS_ERR : FTS_DP;
	return (sp->fts_cur = p);
}
DEF_WEAK(fts_read);

/*
 * Fts_set takes the stream as an argument although it's not used in this
 * implementation; it would be necessary if anyone wanted to add global
 * semantics to fts using fts_set.  An error return is allowed for similar
 * reasons.
 */
int
fts_set(FTS *sp, FTSENT *p, int instr)
{
	if (instr && instr != FTS_AGAIN && instr != FTS_FOLLOW &&
	    instr != FTS_NOINSTR && instr != FTS_SKIP) {
		errno = EINVAL;
		return (1);
	}
	p->fts_instr = instr;
	return (0);
}
DEF_WEAK(fts_set);

FTSENT *
fts_children(FTS *sp, int instr)
{
	FTSENT *p;
	int fd;

	if (instr && instr != FTS_NAMEONLY) {
		errno = EINVAL;
		return (NULL);
	}

	/* Set current node pointer. */
	p = sp->fts_cur;

	/*
	 * Errno set to 0 so user can distinguish empty directory from
	 * an error.
	 */
	errno = 0;

	/* Fatal errors stop here. */
	if (ISSET(FTS_STOP))
		return (NULL);

	/* Return logical hierarchy of user's arguments. */
	if (p->fts_info == FTS_INIT)
		return (p->fts_link);

	/*
	 * If not a directory being visited in pre-order, stop here.  Could
	 * allow FTS_DNR, assuming the user has fixed the problem, but the
	 * same effect is available with FTS_AGAIN.
	 */
	if (p->fts_info != FTS_D /* && p->fts_info != FTS_DNR */)
		return (NULL);

	/* Free up any previous child list. */
	if (sp->fts_child)
		fts_lfree(sp->fts_child);

	if (instr == FTS_NAMEONLY) {
		SET(FTS_NAMEONLY);
		instr = BNAMES;
	} else
		instr = BCHILD;

	/*
	 * If using chdir on a relative path and called BEFORE fts_read does
	 * its chdir to the root of a traversal, we can lose -- we need to
	 * chdir into the subdirectory, and we don't know where the current
	 * directory is, so we can't get back so that the upcoming chdir by
	 * fts_read will work.
	 */
	if (p->fts_level != FTS_ROOTLEVEL || p->fts_accpath[0] == '/' ||
	    ISSET(FTS_NOCHDIR))
		return (sp->fts_child = fts_build(sp, instr));

	if ((fd = open(".", O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	sp->fts_child = fts_build(sp, instr);
	if (fchdir(fd)) {
		(void)close(fd);
		return (NULL);
	}
	(void)close(fd);
	return (sp->fts_child);
}
DEF_WEAK(fts_children);

/*
 * This is the tricky part -- do not casually change *anything* in here.  The
 * idea is to build the linked list of entries that are used by fts_children
 * and fts_read.  There are lots of special cases.
 *
 * The real slowdown in walking the tree is the stat calls.  If FTS_NOSTAT is
 * set and it's a physical walk (so that symbolic links can't be directories),
 * we can do things quickly.  First, if it's a 4.4BSD file system, the type
 * of the file is in the directory entry.  Otherwise, we assume that the number
 * of subdirectories in a node is equal to the number of links to the parent.
 * The former skips all stat calls.  The latter skips stat calls in any leaf
 * directories and for any files after the subdirectories in the directory have
 * been found, cutting the stat calls by about 2/3.
 */
static FTSENT *
fts_build(FTS *sp, int type)
{
	struct dirent *dp;
	FTSENT *p, *head;
	FTSENT *cur, *tail;
	DIR *dirp;
	void *oldaddr;
	size_t len, maxlen;
	int nitems, cderrno, descend, level, nlinks, nostat, doadjust;
	int saved_errno;
	char *cp;

	/* Set current node pointer. */
	cur = sp->fts_cur;

	/*
	 * Open the directory for reading.  If this fails, we're done.
	 * If being called from fts_read, set the fts_info field.
	 */
	if ((dirp = opendir(cur->fts_accpath)) == NULL) {
		if (type == BREAD) {
			cur->fts_info = FTS_DNR;
			cur->fts_errno = errno;
		}
		return (NULL);
	}

	/*
	 * Nlinks is the number of possible entries of type directory in the
	 * directory if we're cheating on stat calls, 0 if we're not doing
	 * any stat calls at all, -1 if we're doing stats on everything.
	 */
	if (type == BNAMES)
		nlinks = 0;
	else if (ISSET(FTS_NOSTAT) && ISSET(FTS_PHYSICAL)) {
		nlinks = cur->fts_nlink - (ISSET(FTS_SEEDOT) ? 0 : 2);
		nostat = 1;
	} else {
		nlinks = -1;
		nostat = 0;
	}

#ifdef notdef
	(void)printf("nlinks == %d (cur: %u)\n", nlinks, cur->fts_nlink);
	(void)printf("NOSTAT %d PHYSICAL %d SEEDOT %d\n",
	    ISSET(FTS_NOSTAT), ISSET(FTS_PHYSICAL), ISSET(FTS_SEEDOT));
#endif
	/*
	 * If we're going to need to stat anything or we want to descend
	 * and stay in the directory, chdir.  If this fails we keep going,
	 * but set a flag so we don't chdir after the post-order visit.
	 * We won't be able to stat anything, but we can still return the
	 * names themselves.  Note, that since fts_read won't be able to
	 * chdir into the directory, it will have to return different path
	 * names than before, i.e. "a/b" instead of "b".  Since the node
	 * has already been visited in pre-order, have to wait until the
	 * post-order visit to return the error.  There is a special case
	 * here, if there was nothing to stat then it's not an error to
	 * not be able to stat.  This is all fairly nasty.  If a program
	 * needed sorted entries or stat information, they had better be
	 * checking FTS_NS on the returned nodes.
	 */
	cderrno = 0;
	if (nlinks || type == BREAD) {
		if (fts_safe_changedir(sp, cur, dirfd(dirp), NULL)) {
			if (nlinks && type == BREAD)
				cur->fts_errno = errno;
			cur->fts_flags |= FTS_DONTCHDIR;
			descend = 0;
			cderrno = errno;
			(void)closedir(dirp);
			dirp = NULL;
		} else
			descend = 1;
	} else
		descend = 0;

	/*
	 * Figure out the max file name length that can be stored in the
	 * current path -- the inner loop allocates more path as necessary.
	 * We really wouldn't have to do the maxlen calculations here, we
	 * could do them in fts_read before returning the path, but it's a
	 * lot easier here since the length is part of the dirent structure.
	 *
	 * If not changing directories set a pointer so that can just append
	 * each new name into the path.
	 */
	len = NAPPEND(cur);
	if (ISSET(FTS_NOCHDIR)) {
		cp = sp->fts_path + len;
		*cp++ = '/';
	}
	len++;
	maxlen = sp->fts_pathlen - len;

	/*
	 * fts_level is signed so we must prevent it from wrapping
	 * around to FTS_ROOTLEVEL and FTS_ROOTPARENTLEVEL.
	 */
	level = cur->fts_level;
	if (level < FTS_MAXLEVEL)
	    level++;

	/* Read the directory, attaching each entry to the `link' pointer. */
	doadjust = 0;
	for (head = tail = NULL, nitems = 0; dirp && (dp = readdir(dirp));) {
		if (!ISSET(FTS_SEEDOT) && ISDOT(dp->d_name))
			continue;

		if (!(p = fts_alloc(sp, dp->d_name, strlen(dp->d_name))))
			goto mem1;
		if (strlen(dp->d_name) >= maxlen) {	/* include space for NUL */
			oldaddr = sp->fts_path;
			if (fts_palloc(sp, strlen(dp->d_name) +len + 1)) {
				/*
				 * No more memory for path or structures.  Save
				 * errno, free up the current structure and the
				 * structures already allocated.
				 */
mem1:				saved_errno = errno;
				free(p);
				fts_lfree(head);
				(void)closedir(dirp);
				cur->fts_info = FTS_ERR;
				SET(FTS_STOP);
				errno = saved_errno;
				return (NULL);
			}
			/* Did realloc() change the pointer? */
			if (oldaddr != sp->fts_path) {
				doadjust = 1;
				if (ISSET(FTS_NOCHDIR))
					cp = sp->fts_path + len;
			}
			maxlen = sp->fts_pathlen - len;
		}

		p->fts_level = level;
		p->fts_parent = sp->fts_cur;
		p->fts_pathlen = len + strlen(dp->d_name);
		if (p->fts_pathlen < len) {
			/*
			 * If we wrap, free up the current structure and
			 * the structures already allocated, then error
			 * out with ENAMETOOLONG.
			 */
			free(p);
			fts_lfree(head);
			(void)closedir(dirp);
			cur->fts_info = FTS_ERR;
			SET(FTS_STOP);
			errno = ENAMETOOLONG;
			return (NULL);
		}

		if (cderrno) {
			if (nlinks) {
				p->fts_info = FTS_NS;
				p->fts_errno = cderrno;
			} else
				p->fts_info = FTS_NSOK;
			p->fts_accpath = cur->fts_accpath;
		} else if (nlinks == 0
#ifdef DT_DIR
		    || (nostat &&
		    dp->d_type != DT_DIR && dp->d_type != DT_UNKNOWN)
#endif
		    ) {
			p->fts_accpath =
			    ISSET(FTS_NOCHDIR) ? p->fts_path : p->fts_name;
			p->fts_info = FTS_NSOK;
		} else {
			/* Build a file name for fts_stat to stat. */
			if (ISSET(FTS_NOCHDIR)) {
				p->fts_accpath = p->fts_path;
				memmove(cp, p->fts_name, p->fts_namelen + 1);
				p->fts_info = fts_stat(sp, p, 0, dirfd(dirp));
			} else {
				p->fts_accpath = p->fts_name;
				p->fts_info = fts_stat(sp, p, 0, -1);
			}

			/* Decrement link count if applicable. */
			if (nlinks > 0 && (p->fts_info == FTS_D ||
			    p->fts_info == FTS_DC || p->fts_info == FTS_DOT))
				--nlinks;
		}

		/* We walk in directory order so "ls -f" doesn't get upset. */
		p->fts_link = NULL;
		if (head == NULL)
			head = tail = p;
		else {
			tail->fts_link = p;
			tail = p;
		}
		++nitems;
	}
	if (dirp)
		(void)closedir(dirp);

	/*
	 * If realloc() changed the address of the path, adjust the
	 * addresses for the rest of the tree and the dir list.
	 */
	if (doadjust)
		fts_padjust(sp, head);

	/*
	 * If not changing directories, reset the path back to original
	 * state.
	 */
	if (ISSET(FTS_NOCHDIR)) {
		if (len == sp->fts_pathlen || nitems == 0)
			--cp;
		*cp = '\0';
	}

	/*
	 * If descended after called from fts_children or after called from
	 * fts_read and nothing found, get back.  At the root level we use
	 * the saved fd; if one of fts_open()'s arguments is a relative path
	 * to an empty directory, we wind up here with no other way back.  If
	 * can't get back, we're done.
	 */
	if (descend && (type == BCHILD || !nitems) &&
	    (cur->fts_level == FTS_ROOTLEVEL ? FCHDIR(sp, sp->fts_rfd) :
	    fts_safe_changedir(sp, cur->fts_parent, -1, ".."))) {
		cur->fts_info = FTS_ERR;
		SET(FTS_STOP);
		return (NULL);
	}

	/* If didn't find anything, return NULL. */
	if (!nitems) {
		if (type == BREAD)
			cur->fts_info = FTS_DP;
		return (NULL);
	}

	/* Sort the entries. */
	if (sp->fts_compar && nitems > 1)
		head = fts_sort(sp, head, nitems);
	return (head);
}

static u_short
fts_stat(FTS *sp, FTSENT *p, int follow, int dfd)
{
	FTSENT *t;
	dev_t dev;
	ino_t ino;
	struct stat *sbp, sb;
	int saved_errno;
	const char *path;

	if (dfd == -1) {
		path = p->fts_accpath;
		dfd = AT_FDCWD;
	} else
		path = p->fts_name;

	/* If user needs stat info, stat buffer already allocated. */
	sbp = ISSET(FTS_NOSTAT) ? &sb : p->fts_statp;

	/*
	 * If doing a logical walk, or application requested FTS_FOLLOW, do
	 * a stat(2).  If that fails, check for a non-existent symlink.  If
	 * fail, set the errno from the stat call.
	 */
	if (ISSET(FTS_LOGICAL) || follow) {
		if (fstatat(dfd, path, sbp, 0)) {
			saved_errno = errno;
			if (!fstatat(dfd, path, sbp, AT_SYMLINK_NOFOLLOW)) {
				errno = 0;
				return (FTS_SLNONE);
			}
			p->fts_errno = saved_errno;
			goto err;
		}
	} else if (fstatat(dfd, path, sbp, AT_SYMLINK_NOFOLLOW)) {
		p->fts_errno = errno;
err:		memset(sbp, 0, sizeof(struct stat));
		return (FTS_NS);
	}

	if (S_ISDIR(sbp->st_mode)) {
		/*
		 * Set the device/inode.  Used to find cycles and check for
		 * crossing mount points.  Also remember the link count, used
		 * in fts_build to limit the number of stat calls.  It is
		 * understood that these fields are only referenced if fts_info
		 * is set to FTS_D.
		 */
		dev = p->fts_dev = sbp->st_dev;
		ino = p->fts_ino = sbp->st_ino;
		p->fts_nlink = sbp->st_nlink;

		if (ISDOT(p->fts_name))
			return (FTS_DOT);

		/*
		 * Cycle detection is done by brute force when the directory
		 * is first encountered.  If the tree gets deep enough or the
		 * number of symbolic links to directories is high enough,
		 * something faster might be worthwhile.
		 */
		for (t = p->fts_parent;
		    t->fts_level >= FTS_ROOTLEVEL; t = t->fts_parent)
			if (ino == t->fts_ino && dev == t->fts_dev) {
				p->fts_cycle = t;
				return (FTS_DC);
			}
		return (FTS_D);
	}
	if (S_ISLNK(sbp->st_mode))
		return (FTS_SL);
	if (S_ISREG(sbp->st_mode))
		return (FTS_F);
	return (FTS_DEFAULT);
}

static FTSENT *
fts_sort(FTS *sp, FTSENT *head, int nitems)
{
	FTSENT **ap, *p;

	/*
	 * Construct an array of pointers to the structures and call qsort(3).
	 * Reassemble the array in the order returned by qsort.  If unable to
	 * sort for memory reasons, return the directory entries in their
	 * current order.  Allocate enough space for the current needs plus
	 * 40 so don't realloc one entry at a time.
	 */
	if (nitems > sp->fts_nitems) {
		struct _ftsent **a;

		if ((a = reallocarray(sp->fts_array,
		    nitems + 40, sizeof(FTSENT *))) == NULL) {
			free(sp->fts_array);
			sp->fts_array = NULL;
			sp->fts_nitems = 0;
			return (head);
		}
		sp->fts_nitems = nitems + 40;
		sp->fts_array = a;
	}
	for (ap = sp->fts_array, p = head; p; p = p->fts_link)
		*ap++ = p;
	qsort(sp->fts_array, nitems, sizeof(FTSENT *), sp->fts_compar);
	for (head = *(ap = sp->fts_array); --nitems; ++ap)
		ap[0]->fts_link = ap[1];
	ap[0]->fts_link = NULL;
	return (head);
}

static FTSENT *
fts_alloc(FTS *sp, const char *name, size_t namelen)
{
	FTSENT *p;
	size_t len;

	/*
	 * The file name is a variable length array and no stat structure is
	 * necessary if the user has set the nostat bit.  Allocate the FTSENT
	 * structure, the file name and the stat structure in one chunk, but
	 * be careful that the stat structure is reasonably aligned.  Since the
	 * fts_name field is declared to be of size 1, the fts_name pointer is
	 * namelen + 2 before the first possible address of the stat structure.
	 *
	 * We can't use the same trick FreeBSD uses here because our fts_name
	 * is a char[1] rather than a char*. This is also the reason we don't
	 * need to say `namelen + 1`. We just assume the worst alignment.
	 */
	len = sizeof(FTSENT) + namelen;
	if (!ISSET(FTS_NOSTAT))
		len += alignof(struct stat) + sizeof(struct stat);
	if ((p = calloc(1, len)) == NULL)
		return (NULL);

	p->fts_path = sp->fts_path;
	p->fts_namelen = namelen;
	p->fts_instr = FTS_NOINSTR;
	if (!ISSET(FTS_NOSTAT))
		p->fts_statp = (struct stat *)__builtin_align_up(p->fts_name + namelen + 2, alignof(struct stat));
	memcpy(p->fts_name, name, namelen);

	return (p);
}

static void
fts_lfree(FTSENT *head)
{
	FTSENT *p;

	/* Free a linked list of structures. */
	while ((p = head)) {
		head = head->fts_link;
		free(p);
	}
}

/*
 * Allow essentially unlimited paths; find, rm, ls should all work on any tree.
 * Most systems will allow creation of paths much longer than PATH_MAX, even
 * though the kernel won't resolve them.  Add the size (not just what's needed)
 * plus 256 bytes so don't realloc the path 2 bytes at a time.
 */
static int
fts_palloc(FTS *sp, size_t more)
{
	char *p;

	/*
	 * Check for possible wraparound.
	 */
	more += 256;
	if (sp->fts_pathlen + more < sp->fts_pathlen) {
		free(sp->fts_path);
		sp->fts_path = NULL;
		errno = ENAMETOOLONG;
		return (1);
	}
	p = recallocarray(sp->fts_path, sp->fts_pathlen,
	    sp->fts_pathlen + more, 1);
	if (p == NULL) {
		free(sp->fts_path);
		sp->fts_path = NULL;
		return (1);
	}
	sp->fts_pathlen += more;
	sp->fts_path = p;
	return (0);
}

/*
 * When the path is realloc'd, have to fix all of the pointers in structures
 * already returned.
 */
static void
fts_padjust(FTS *sp, FTSENT *head)
{
	FTSENT *p;
	char *addr = sp->fts_path;

#define	ADJUST(p) {							\
	if ((p)->fts_accpath != (p)->fts_name) {			\
		(p)->fts_accpath =					\
		    (char *)addr + ((p)->fts_accpath - (p)->fts_path);	\
	}								\
	(p)->fts_path = addr;						\
}
	/* Adjust the current set of children. */
	for (p = sp->fts_child; p; p = p->fts_link)
		ADJUST(p);

	/* Adjust the rest of the tree, including the current level. */
	for (p = head; p->fts_level >= FTS_ROOTLEVEL;) {
		ADJUST(p);
		p = p->fts_link ? p->fts_link : p->fts_parent;
	}
}

static size_t
fts_maxarglen(char * const *argv)
{
	size_t len, max;

	for (max = 0; *argv; ++argv)
		if ((len = strlen(*argv)) > max)
			max = len;
	return (max + 1);
}

/*
 * Change to dir specified by fd or p->fts_accpath without getting
 * tricked by someone changing the world out from underneath us.
 * Assumes p->fts_dev and p->fts_ino are filled in.
 */
static int
fts_safe_changedir(FTS *sp, FTSENT *p, int fd, const char *path)
{
	int ret, oerrno, newfd;
	struct stat sb;

	newfd = fd;
	if (ISSET(FTS_NOCHDIR))
		return (0);
	if (fd == -1 && (newfd = open(path, O_RDONLY|O_DIRECTORY|O_CLOEXEC)) == -1)
		return (-1);
	if (fstat(newfd, &sb) == -1) {
		ret = -1;
		goto bail;
	}
	if (p->fts_dev != sb.st_dev || p->fts_ino != sb.st_ino) {
		errno = ENOENT;		/* disinformation */
		ret = -1;
		goto bail;
	}
	ret = fchdir(newfd);
bail:
	oerrno = errno;
	if (fd == -1)
		(void)close(newfd);
	errno = oerrno;
	return (ret);
}

FTS *
fts_open(char * const *argv, int options,
    int (*compar)(const FTSENT **, const FTSENT **))
{
	// Android needs to an __fts_open() that doesn't make this check
	// so that FTS_FOR_FTW works.
	if (options & ~FTS_OPTIONMASK) {
		errno = EINVAL;
		return (NULL);
	}
	return __fts_open(argv, options, compar);
}
```
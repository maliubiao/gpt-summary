Response:
Let's break down the thought process for analyzing the `fts.h` header file.

**1. Initial Understanding - What is `fts`?**

The prompt itself gives a crucial clue:  "目录为bionic/libc/fts/include/bionic/fts.handroid bionic的源代码文件". This tells us it's part of Android's C library (`libc`), specifically within the `fts` directory. The comments within the file (`$OpenBSD: fts.h...`, `$NetBSD: fts.h...`) immediately suggest it's based on or derived from BSD implementations. This points to its core functionality: file tree traversal.

**2. Core Data Structures - `FTS` and `FTSENT`**

The next step is to identify the key data structures. `FTS` and `FTSENT` stand out because they are defined as `typedef struct`.

*   **`FTS`**:  The comment `/* current node */`, `/* linked list of children */`, `/* sort array */`, `/* path for this descent */`, and `/* compare function */` within the `FTS` structure immediately suggests that this structure represents the *state* of a file tree traversal. It holds information about the current position, children, sorting methods, and overall traversal options.

*   **`FTSENT`**: The comments here are also very helpful. `/* parent directory */`, `/* next file in directory */`, `/* access path */`, `/* root path */`, `/* inode */`, `/* device */`, and especially the `#define` constants like `FTS_D`, `FTS_F`, `FTS_SL`, etc., clearly indicate that `FTSENT` represents a *single entry* encountered during the traversal. It holds details about a file or directory.

**3. Identifying Key Functions**

The `__BEGIN_DECLS` and `__END_DECLS` blocks enclose function declarations. These are the primary operations provided by the `fts` library:

*   `fts_open`:  Likely the initialization function. The name and the parameters (`char* _Nullable const* _Nonnull __path`, `int __options`, `int (* _Nullable __comparator)`) suggest it opens a traversal starting from the given path(s), with specified options and a possible custom sorting function.

*   `fts_read`:  This function probably retrieves the next entry in the traversal.

*   `fts_children`:  This seems to specifically retrieve the children of the current directory.

*   `fts_set`: The name suggests modifying some aspect of the current entry or traversal. The parameters (`FTS* _Nonnull __fts`, `FTSENT* _Nonnull __entry`, `int __options`) confirm it operates on an existing traversal state and entry.

*   `fts_close`: This is the cleanup function, releasing resources.

**4. Analyzing Options and Flags**

The `#define` statements within `FTS` and `FTSENT` are critical for understanding the behavior of the functions. They define various traversal options (like following symlinks, not crossing devices) and flags indicating the type or status of an entry.

*   **`FTS` Options:** `FTS_COMFOLLOW`, `FTS_LOGICAL`, `FTS_NOCHDIR`, `FTS_NOSTAT`, `FTS_PHYSICAL`, `FTS_SEEDOT`, `FTS_XDEV`. These directly influence *how* the traversal is performed.

*   **`FTSENT` Flags/Info:** `FTS_D`, `FTS_F`, `FTS_SL`, `FTS_DNR`, etc. These describe the *nature* of the file or directory encountered.

**5. Considering Android Context**

Since the header is within Android's `libc`, it's important to think about how this functionality might be used in Android. File system traversal is fundamental for many tasks:

*   **File Managers:** Listing directories, searching for files.
*   **Package Management:**  Scanning application directories.
*   **`adb` and Shell Utilities:**  Commands like `find`.
*   **System Services:**  Monitoring file system changes, managing storage.

**6. Linking and Dynamic Linking (Advanced)**

The prompt specifically mentions the dynamic linker. While this header file *itself* doesn't directly involve dynamic linking, the *implementation* of the `fts` functions within `libc.so` will be linked dynamically. To address this, we need to understand the general process of how shared libraries are loaded and symbols are resolved at runtime in Android. This involves concepts like:

*   `libc.so` being loaded by the dynamic linker.
*   Symbol resolution (finding the actual code for `fts_open`, etc.).
*   Relocation (adjusting addresses in the loaded library).

**7. Error Handling and Common Mistakes**

Based on the function names and common C programming practices, we can infer potential error scenarios:

*   `fts_open` might fail if the path doesn't exist or permissions are denied.
*   `fts_read` might return `NULL` when there are no more entries or an error occurs.
*   Incorrect use of options could lead to unexpected traversal behavior.
*   Forgetting to call `fts_close` could lead to resource leaks.

**8. Frida Hooking (Debugging)**

To understand how the `fts` functions are actually used in practice, Frida is a valuable tool. We can hook the `fts_open`, `fts_read`, etc., functions to observe their arguments and return values, tracing the flow of execution.

**Self-Correction/Refinement During Analysis:**

*   **Initial thought:**  Maybe `fts_set` is for modifying file attributes. **Correction:**  Looking closer at the `FTS_AGAIN`, `FTS_FOLLOW`, `FTS_SKIP` options, it seems more about controlling the *traversal* itself.

*   **Initial thought:** The `fts_compar` in `fts_open` is just for sorting the final result. **Correction:** The comment "linked list of children" and "sort array" in the `FTS` structure suggests it's used during the traversal to order the children.

By following these steps, combining the information from the header file with general knowledge of C programming and operating systems (specifically Android), we can arrive at a comprehensive understanding of the `fts` library's purpose and functionality. The detailed explanation in the prompt's answer reflects this kind of structured analysis.
这个头文件 `bionic/libc/fts/include/bionic/fts.handroid` 定义了用于遍历文件系统层次结构的函数和数据结构。它来源于 BSD 系统，并在 Android 的 Bionic C 库中被采用。

**功能列表：**

该头文件主要定义了以下用于文件系统遍历的功能：

1. **`FTS` 结构体：**  这是一个主要的结构体，用于维护文件系统遍历的状态信息，包括当前节点、子节点列表、排序数组、起始设备号、当前路径、根文件描述符、路径长度、排序数组元素数量、比较函数以及各种遍历选项。
2. **`FTSENT` 结构体：**  该结构体表示文件系统遍历中的一个条目（文件或目录）。它包含了关于该条目的各种信息，如父目录、链接、inode 号、设备号、链接计数、层级、文件类型、错误号、文件名、路径、`stat` 结构体等。
3. **`fts_open()` 函数：**  用于初始化文件系统遍历。它接受一个或多个起始路径、遍历选项和一个可选的比较函数。
4. **`fts_read()` 函数：**  用于读取文件系统遍历中的下一个条目。每次调用返回一个 `FTSENT` 结构体指针，指向当前访问的文件或目录。
5. **`fts_children()` 函数：**  用于获取当前目录的子节点列表。
6. **`fts_set()` 函数：**  用于设置遍历中当前条目的指令，例如跳过或重新访问。
7. **`fts_close()` 函数：**  用于关闭文件系统遍历并释放相关资源。

**与 Android 功能的关系及举例说明：**

`fts` 库是 Bionic C 库的一部分，因此它是 Android 系统底层功能的重要组成部分。很多 Android 的系统工具和应用程序都可能在内部使用 `fts` 来遍历文件系统。

*   **`find` 命令的实现：**  Android 的 shell 命令 `find` 很大可能就是基于 `fts` 库实现的。它可以根据各种条件在指定目录下查找文件和目录。
*   **文件管理器应用：**  文件管理器应用需要遍历文件系统来显示目录结构和文件列表。`fts` 库可以提供这种遍历能力。
*   **包管理器 (如 `pm` 命令)：**  在安装、卸载或查询应用程序时，包管理器可能需要遍历应用程序的安装目录。
*   **`adb` 工具：**  `adb push` 和 `adb pull` 等命令在传输文件时，也可能需要遍历本地或设备上的文件系统。
*   **媒体扫描服务：**  Android 的媒体扫描服务需要遍历存储设备上的目录，查找媒体文件（图片、音频、视频）并添加到媒体库中。

**详细解释 libc 函数的功能实现：**

由于这里只提供了头文件，我们无法直接看到 `fts_open`、`fts_read` 等函数的具体实现。但是，我们可以根据头文件中的定义和通用的文件系统遍历算法来推测其实现方式：

*   **`fts_open()` 的实现：**
    1. 分配 `FTS` 结构体，用于存储遍历状态。
    2. 初始化 `FTS` 结构体的成员，例如设置起始设备号、路径、选项等。
    3. 如果提供了比较函数，则保存该函数指针。
    4. 对于每个起始路径，打开目录，读取目录项，并创建初始的 `FTSENT` 结构体。
    5. 根据遍历选项（如 `FTS_LOGICAL` 或 `FTS_PHYSICAL`），处理符号链接。
    6. 如果需要排序，则对初始的 `FTSENT` 列表进行排序。

*   **`fts_read()` 的实现：**
    1. 检查 `FTS` 结构体的当前状态。
    2. 如果当前目录的子节点尚未被处理，则读取该目录下的所有条目，并创建相应的 `FTSENT` 结构体。
    3. 根据遍历选项和可能的排序规则，选择下一个要返回的 `FTSENT`。
    4. 根据 `fts_info` 标志，决定返回的 `FTSENT` 的类型（例如，进入目录前、离开目录后、文件等）。
    5. 更新 `FTS` 结构体的状态，指向下一个要处理的条目。
    6. 返回指向 `FTSENT` 结构体的指针。如果遍历结束或发生错误，则返回 `NULL` 并设置 `fts_errno`。

*   **`fts_children()` 的实现：**
    1. 检查当前 `FTS` 结构体的状态。
    2. 如果当前节点是目录，则读取该目录下的所有条目，并创建相应的 `FTSENT` 结构体。
    3. 如果提供了比较函数，则对子节点进行排序。
    4. 将子节点的 `FTSENT` 结构体以链表或数组的形式返回。

*   **`fts_set()` 的实现：**
    1. 接收一个 `FTS` 结构体和一个 `FTSENT` 结构体指针，以及一个选项参数。
    2. 根据选项参数，修改 `FTSENT` 结构体的 `fts_instr` 成员，该成员指示 `fts_read()` 函数在后续调用中应该如何处理该条目。
    3. 例如，`FTS_SKIP` 会导致 `fts_read()` 跳过该条目及其子树，而 `FTS_AGAIN` 会导致 `fts_read()` 再次返回该条目。

*   **`fts_close()` 的实现：**
    1. 释放 `FTS` 结构体中分配的内存，例如 `fts_path` 和 `fts_array`。
    2. 关闭打开的文件描述符（如 `fts_rfd`）。
    3. 清理与遍历相关的其他资源。

**涉及 dynamic linker 的功能：**

这个头文件本身并不直接涉及 dynamic linker 的功能。`fts` 函数的实现代码位于 `libc.so` 动态链接库中。当程序调用 `fts_open` 等函数时，dynamic linker 负责在运行时找到 `libc.so`，并将其加载到进程的地址空间中，然后解析并链接这些函数的符号。

**so 布局样本：**

```
libc.so:
    ...
    .text:
        ...
        fts_open:  // fts_open 函数的代码
            ...
        fts_read:  // fts_read 函数的代码
            ...
        fts_children: // fts_children 函数的代码
            ...
        fts_set:   // fts_set 函数的代码
            ...
        fts_close: // fts_close 函数的代码
            ...
    .data:
        ...
    .bss:
        ...
    .dynsym:      // 动态符号表，包含 fts_open 等符号
        ...
        fts_open (地址)
        fts_read (地址)
        ...
    .dynstr:      // 动态字符串表，包含符号名称
        ...
        fts_open
        fts_read
        ...
    .rel.dyn:     // 动态重定位表
        ...
```

**链接的处理过程：**

1. **编译时：** 编译器遇到 `fts_open` 等函数调用时，会生成一个未解析的符号引用。链接器在链接可执行文件时，会记录这些未解析的符号，并标记它们需要在运行时由 dynamic linker 解析。
2. **运行时：** 当程序启动时，Android 的 zygote 进程会加载 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
3. **加载共享库：** 当程序尝试调用 `fts_open` 时，dynamic linker 会检查 `libc.so` 是否已经被加载。如果没有，它会找到 `libc.so` 的路径（通常通过 `LD_LIBRARY_PATH` 环境变量或系统默认路径），并将其加载到进程的地址空间中。
4. **符号解析：** dynamic linker 会查找 `libc.so` 的 `.dynsym` (动态符号表) 和 `.dynstr` (动态字符串表)，找到与 `fts_open` 符号名称匹配的条目，并获取其在 `libc.so` 中的地址。
5. **重定位：** dynamic linker 会根据 `.rel.dyn` (动态重定位表) 中的信息，修改程序代码中对 `fts_open` 的调用地址，将其指向 `libc.so` 中 `fts_open` 函数的实际地址。
6. **调用：**  现在，程序可以成功调用 `libc.so` 中的 `fts_open` 函数了。

**逻辑推理、假设输入与输出：**

假设我们使用 `fts_open` 打开当前目录 "."，并使用 `fts_read` 遍历：

**假设输入：**

*   调用 `fts_open({ "." }, FTS_PHYSICAL | FTS_SEEDOT, NULL)`，其中 "." 是当前目录。
*   当前目录下包含文件 `a.txt`、目录 `subdir` 和隐藏文件 `.hidden`。

**预期输出 (多次调用 `fts_read` 的结果)：**

1. `fts_read()` 返回指向表示 "." 的 `FTSENT` 结构体，`fts_info` 为 `FTS_D`。
2. `fts_read()` 返回指向表示 "." 的 `FTSENT` 结构体，`fts_info` 为 `FTS_DOT` (由于 `FTS_SEEDOT`)。
3. `fts_read()` 返回指向表示 ".." 的 `FTSENT` 结构体，`fts_info` 为 `FTS_DOT` (由于 `FTS_SEEDOT`)。
4. `fts_read()` 返回指向表示 `.hidden` 的 `FTSENT` 结构体，`fts_info` 为 `FTS_F`。
5. `fts_read()` 返回指向表示 `a.txt` 的 `FTSENT` 结构体，`fts_info` 为 `FTS_F`。
6. `fts_read()` 返回指向表示 `subdir` 的 `FTSENT` 结构体，`fts_info` 为 `FTS_D`。
7. `fts_read()` 返回指向表示 `subdir` 的 `FTSENT` 结构体，`fts_info` 为 `FTS_DP` (在遍历完 `subdir` 之后)。
8. `fts_read()` 返回 `NULL`，表示遍历结束。

**用户或编程常见的使用错误：**

1. **忘记调用 `fts_close()`：**  这会导致资源泄漏，例如文件描述符没有被关闭。
2. **错误的选项组合：**  例如，同时使用 `FTS_LOGICAL` 和 `FTS_PHYSICAL` 会导致未定义的行为。
3. **假设遍历顺序：**  除非使用了比较函数，否则 `fts_read()` 返回的顺序是不确定的。
4. **没有检查 `fts_read()` 的返回值：**  如果 `fts_read()` 返回 `NULL`，表示遍历结束或发生错误，没有检查会导致程序崩溃或逻辑错误。应该检查 `fts_errno` 来确定是否发生了错误。
5. **在 `fts_compar` 函数中访问无效的内存：**  如果自定义的比较函数不正确，可能会导致程序崩溃。
6. **修改 `FTSENT` 结构体的内容：**  `FTSENT` 结构体的内容由 `fts` 库管理，不应该被用户程序修改。

**Android framework 或 ndk 如何一步步的到达这里：**

1. **Android Framework (Java 层)：**
    *   例如，`java.io.File` 类提供了一些方法来操作文件系统，例如 `listFiles()`。
    *   在 `listFiles()` 的底层实现中，可能会调用 Native 方法（通过 JNI）。

2. **Native 方法 (C/C++ 层)：**
    *   这些 Native 方法通常位于 Android 的运行时库 (如 `libjavacore.so`) 或其他系统库中。
    *   在 Native 方法的实现中，如果需要遍历文件系统，可能会直接调用 `fts_open`、`fts_read` 等 Bionic C 库的函数。

3. **NDK 开发：**
    *   使用 NDK 进行开发的应用程序可以直接调用 Bionic C 库提供的函数，包括 `fts` 系列函数。
    *   开发者可以在自己的 C/C++ 代码中包含 `<fts.h>` 头文件，并调用 `fts_open` 等函数来遍历文件系统。

**Frida hook 示例调试步骤：**

假设我们要 hook `fts_read` 函数，查看其返回的 `FTSENT` 结构体信息：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "fts_read"), {
        onEnter: function (args) {
            console.log("[*] fts_read called");
            this.fts = args[0];
        },
        onLeave: function (retval) {
            if (retval.isNull()) {
                console.log("[*] fts_read returned NULL");
                return;
            }

            const ftsent = ptr(retval);
            const fts_path = ftsent.add(8).readPointer().readCString(); // 假设 fts_path 在偏移 8 的位置
            const fts_name = ftsent.add(offsetof(struct_ftsent, 'fts_name')).readCString();

            console.log("[*] fts_read returned:");
            console.log("    fts_path:", fts_path);
            console.log("    fts_name:", fts_name);
            // 可以继续读取其他 ftsent 成员
        }
    });

    // 定义 struct _ftsent 的结构，方便计算偏移
    const struct_ftsent = {
        'fts_cycle': 'pointer',
        'fts_parent': 'pointer',
        'fts_link': 'pointer',
        'fts_number': 'long',
        'fts_pointer': 'pointer',
        'fts_accpath': 'pointer',
        'fts_path': 'pointer',
        'fts_errno': 'int',
        'fts_symfd': 'int',
        'fts_pathlen': 'ulong',
        'fts_namelen': 'ulong',
        'fts_ino': 'ulong',
        'fts_dev': 'ulong',
        'fts_nlink': 'ulong',
        'fts_level': 'short',
        'fts_info': 'ushort',
        'fts_flags': 'ushort',
        'fts_instr': 'ushort',
        'fts_statp': 'pointer',
        'fts_name': 'byte' // 注意这里只是第一个字节，实际名字是变长的
    };

    function offsetof(struct, member) {
        const dummy = Memory.alloc(Process.pointerSize);
        const struct_ptr = dummy.writeU8(0);
        return struct_ptr.add(member).sub(struct_ptr);
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input("Press Enter to detach...\n")
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤：**

1. 保存上述 Python 代码为 `frida_fts_hook.py`。
2. 找到你想要调试的 Android 进程的名称或 PID。例如，一个正在使用文件系统的文件管理器应用。
3. 运行 Frida hook 脚本：`python frida_fts_hook.py <进程名称或PID>`
4. 在目标应用中执行会触发文件系统遍历的操作。
5. Frida 会拦截对 `fts_read` 的调用，并在控制台上打印相关信息，包括返回的文件路径和文件名。

这个 Frida 脚本演示了如何 hook `fts_read` 函数，并读取返回的 `FTSENT` 结构体中的关键信息。你可以根据需要修改脚本来 hook 其他 `fts` 函数或读取 `FTSENT` 结构体的其他成员。请注意，读取结构体成员时需要根据目标架构（32 位或 64 位）以及 `FTSENT` 结构体的实际内存布局来计算偏移量。

Prompt: 
```
这是目录为bionic/libc/fts/include/bionic/fts.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: fts.h,v 1.12 2009/08/27 16:19:27 millert Exp $	*/
/*	$NetBSD: fts.h,v 1.5 1994/12/28 01:41:50 mycroft Exp $	*/

/*
 * Copyright (c) 1989, 1993
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
 *
 *	@(#)fts.h	8.3 (Berkeley) 8/14/94
 */

#ifndef	_FTS_H_
#define	_FTS_H_

#include <sys/cdefs.h>
#include <sys/types.h>

typedef struct {
	struct _ftsent * _Nullable fts_cur;	/* current node */
	struct _ftsent * _Nullable fts_child;	/* linked list of children */
	struct _ftsent * _Nullable * _Nullable fts_array;	/* sort array */
	dev_t fts_dev;			/* starting device # */
	char * _Nullable fts_path;			/* path for this descent */
	int fts_rfd;			/* fd for root */
	size_t fts_pathlen;		/* sizeof(path) */
	int fts_nitems;			/* elements in the sort array */
	int (* _Nullable fts_compar)();		/* compare function */

#define	FTS_COMFOLLOW	0x0001		/* follow command line symlinks */
#define	FTS_LOGICAL	0x0002		/* logical walk */
#define	FTS_NOCHDIR	0x0004		/* don't change directories */
#define	FTS_NOSTAT	0x0008		/* don't get stat info */
#define	FTS_PHYSICAL	0x0010		/* physical walk */
#define	FTS_SEEDOT	0x0020		/* return dot and dot-dot */
#define	FTS_XDEV	0x0040		/* don't cross devices */
#define	FTS_OPTIONMASK	0x00ff		/* valid user option mask */

#define FTS_NAMEONLY 0x1000  /* (private) child names only */
#define FTS_STOP 0x2000      /* (private) unrecoverable error */
#define FTS_FOR_FTW 0x4000   /* (private) fts is being called by ftw/nftw */
	int fts_options;		/* fts_open options, global flags */
} FTS;

typedef struct _ftsent {
	struct _ftsent * _Nullable fts_cycle;	/* cycle node */
	struct _ftsent * _Nullable fts_parent;	/* parent directory */
	struct _ftsent * _Nullable fts_link;	/* next file in directory */
	long fts_number;	        /* local numeric value */
	void * _Nullable fts_pointer;	        /* local address value */
	char * _Nullable fts_accpath;		/* access path */
	char * _Nullable fts_path;			/* root path */
	int fts_errno;			/* errno for this node */
	int fts_symfd;			/* fd for symlink */
	size_t fts_pathlen;		/* strlen(fts_path) */
	size_t fts_namelen;		/* strlen(fts_name) */

	ino_t fts_ino;			/* inode */
	dev_t fts_dev;			/* device */
	nlink_t fts_nlink;		/* link count */

#define	FTS_ROOTPARENTLEVEL	-1
#define	FTS_ROOTLEVEL		 0
#define	FTS_MAXLEVEL		 0x7fff
	short fts_level;		/* depth (-1 to N) */

#define	FTS_D		 1		/* preorder directory */
#define	FTS_DC		 2		/* directory that causes cycles */
#define	FTS_DEFAULT	 3		/* none of the above */
#define	FTS_DNR		 4		/* unreadable directory */
#define	FTS_DOT		 5		/* dot or dot-dot */
#define	FTS_DP		 6		/* postorder directory */
#define	FTS_ERR		 7		/* error; errno is set */
#define	FTS_F		 8		/* regular file */
#define	FTS_INIT	 9		/* initialized only */
#define	FTS_NS		10		/* stat(2) failed */
#define	FTS_NSOK	11		/* no stat(2) requested */
#define	FTS_SL		12		/* symbolic link */
#define	FTS_SLNONE	13		/* symbolic link without target */
	unsigned short fts_info;	/* user flags for FTSENT structure */

#define	FTS_DONTCHDIR	 0x01		/* don't chdir .. to the parent */
#define	FTS_SYMFOLLOW	 0x02		/* followed a symlink to get here */
	unsigned short fts_flags;	/* private flags for FTSENT structure */

#define	FTS_AGAIN	 1		/* read node again */
#define	FTS_FOLLOW	 2		/* follow symbolic link */
#define	FTS_NOINSTR	 3		/* no instructions */
#define	FTS_SKIP	 4		/* discard node */
	unsigned short fts_instr;	/* fts_set() instructions */

	struct stat * _Nullable fts_statp;		/* stat(2) information */
	char fts_name[1];		/* file name */
} FTSENT;

__BEGIN_DECLS

FTSENT* _Nullable fts_children(FTS* _Nonnull __fts, int __options);
int fts_close(FTS* _Nonnull __fts);
FTS* _Nullable fts_open(char* _Nullable const* _Nonnull __path, int __options, int (* _Nullable __comparator)(const FTSENT* _Nonnull * _Nonnull  __lhs, const FTSENT* _Nonnull * _Nonnull __rhs));
FTSENT* _Nullable fts_read(FTS* _Nonnull __fts);
int fts_set(FTS* _Nonnull __fts, FTSENT* _Nonnull __entry, int __options);

__END_DECLS

#endif /* !_FTS_H_ */

"""

```
Response:
Let's break down the thought process for answering the request about `grp_pwd_file.cpp`.

**1. Understanding the Core Task:**

The request asks for a comprehensive analysis of the provided C++ code. It emphasizes functionality, Android-specific relevance, implementation details of libc functions, dynamic linking aspects, usage errors, and how Android frameworks/NDK lead to this code. Frida hooking is also requested for demonstration.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of its purpose. Key observations:

* **File Handling:** The code deals with reading files, specifically `/etc/passwd` and `/etc/group`.
* **Memory Mapping:**  It uses `mmap` to load these files into memory.
* **Data Structures:**  `PasswdLine` and `GroupLine` structures represent entries in the respective files.
* **Searching:** Functions like `FindById` and `FindByName` suggest searching within the mapped data.
* **No Dynamic Allocation (mostly):** The comments explicitly mention avoiding allocations. This is a strong indicator of performance optimization.
* **Android Specifics:** The `#ifdef __ANDROID__` block points to Android-specific handling of partition prefixes.

**3. Deconstructing the Request into Key Areas:**

To provide a structured answer, it's helpful to organize the analysis based on the prompt's requirements:

* **Functionality:** What does the code *do*?
* **Android Relevance:** How does this fit into the broader Android system?
* **libc Function Implementation:** How do functions like `open`, `mmap`, `munmap`, `fstat`, `strtoul` work in this context?
* **Dynamic Linking:** Does this code interact with dynamic linking? If so, how?
* **Logical Reasoning (Assumptions & I/O):** What are the expected inputs and outputs of the search functions?
* **Common Usage Errors:** What mistakes might a programmer make when using the functionalities exposed by (or related to) this code?
* **Android Framework/NDK Path:** How does a typical Android process end up using this code?
* **Frida Hooking:** How can we use Frida to observe the execution of this code?

**4. Detailed Analysis of Each Area:**

* **Functionality:**  Focus on the core purpose: providing password and group information without dynamic allocation by using memory mapping. List the key classes and their roles (`MmapFile`, `PasswdFile`, `GroupFile`).

* **Android Relevance:** Explain *why* this is important in Android. Mention security, user management, and the separation of concerns between applications and the OS. Emphasize the partition prefix feature as an Android-specific enhancement for Treble compliance.

* **libc Function Implementation:** For each libc function used, briefly explain its standard purpose and how it's used in this specific code. For example, `open` opens the file, `mmap` maps it, `strtoul` converts the UID/GID strings, etc. The key is to connect the generic libc function to its specific application in this file.

* **Dynamic Linking:**  This is where a careful reading of the code reveals that *this specific file doesn't directly perform dynamic linking*. However, it's part of the `libc`, which *is* a dynamically linked library. Therefore, the explanation should focus on the role of `libc.so`, provide a sample `so` layout, and describe the general dynamic linking process (linker, symbol resolution).

* **Logical Reasoning (Assumptions & I/O):** Choose a representative function, like `FindByName`. Provide concrete examples of inputs (filename, username) and the expected output (the `passwd_state_t` structure filled with information). Consider both successful and unsuccessful search scenarios.

* **Common Usage Errors:**  Think about potential pitfalls when dealing with password/group information. Incorrect file paths, assuming null-terminated strings (as highlighted in the comments), and security vulnerabilities if the data is mishandled are good examples.

* **Android Framework/NDK Path:** This requires understanding the layers of the Android system. Start with a user-level app, then trace the call down through the NDK, Bionic (libc), and finally to this specific file. Key components to mention are system calls and the abstraction provided by libc.

* **Frida Hooking:**  Identify key functions to hook, like `PasswdFile::FindByName`. Provide a basic Frida script demonstrating how to intercept the function, print arguments, and potentially modify behavior.

**5. Structuring the Answer:**

Organize the answer clearly using headings and subheadings that correspond to the decomposed request. Use bullet points and code blocks to improve readability.

**6. Writing Style and Language:**

Use clear and concise language. Explain technical concepts in a way that is understandable to someone familiar with C++ and operating system fundamentals. Maintain the requested Chinese language for the response.

**7. Review and Refinement:**

After drafting the answer, review it for accuracy, completeness, and clarity. Ensure that all parts of the original request have been addressed. Double-check code examples for correctness.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *directly* uses `dlopen` or similar. **Correction:** After closer examination, it doesn't. Adjust the "Dynamic Linking" section to reflect the role of `libc.so`.
* **Initial thought:**  Just list the libc functions. **Correction:**  Explain *how* they are used *in this specific context*.
* **Frida Example:** Start with a simple hook and then consider adding more advanced features like argument inspection.

By following these steps, including the self-correction, we arrive at a comprehensive and accurate answer that addresses all aspects of the original prompt. The key is to break down the problem, analyze the code thoroughly, and structure the answer logically.
好的，让我们详细分析一下 `bionic/libc/bionic/grp_pwd_file.cpp` 这个文件。

**文件功能概述**

`grp_pwd_file.cpp` 的主要功能是**高效地读取并解析 `/etc/passwd` 和 `/etc/group` 文件中的用户信息和组信息**。它通过内存映射 (mmap) 的方式读取文件内容，避免了传统读取方式中的多次拷贝和动态内存分配，从而提高了性能。

**主要功能点：**

1. **内存映射 (mmap):** 将 `/etc/passwd` 和 `/etc/group` 文件映射到进程的地址空间，使得可以直接像访问内存一样访问文件内容，无需read/write系统调用，提升效率。
2. **零拷贝读取:** 由于使用了内存映射，数据直接在文件和进程内存之间传递，避免了数据拷贝，这对于读取小文件来说非常高效。
3. **静态数据结构:**  使用栈上分配的固定大小的缓冲区 (`passwd_state_t`, `group_state_t`) 来存储解析后的用户信息和组信息，避免了动态内存分配，降低了内存碎片和分配开销。
4. **字段解析:**  实现了 `ParseLine` 函数，用于解析每一行数据，根据冒号 `:` 分隔字段。
5. **用户信息和组信息查找:** 提供了 `FindById` 和 `FindByName` 函数，可以根据 UID/GID 或用户名/组名在映射的文件中查找对应的记录。
6. **Android 特定处理:** 考虑了 Android 分区的情况，可以指定 `required_prefix`，用于过滤特定分区的用户和组。

**与 Android 功能的关系及举例说明**

这个文件是 Android Bionic C 库的一部分，而 Bionic 是 Android 系统运行的基础。`grp_pwd_file.cpp` 提供的功能是许多 Android 系统服务和应用程序获取用户信息和组信息的关键。

**举例说明：**

* **权限管理:** 当一个应用程序需要访问某个文件或资源时，Android 系统需要检查该应用程序的权限。这通常涉及到查找应用程序运行时的用户 ID (UID) 和组 ID (GID)，然后与文件或资源的权限进行比较。`grp_pwd_file.cpp` 提供的功能就被用来快速查找这些信息。
* **`adb shell`:** 当你通过 `adb shell` 连接到 Android 设备时，你登录的身份是由 `/etc/passwd` 文件中的信息决定的。Bionic 库会使用 `grp_pwd_file.cpp` 来查找你的用户信息。
* **进程管理:**  `ps` 命令显示进程信息时，需要将数字的 UID 和 GID 转换为用户名和组名。Bionic 库会使用这个文件来完成这个转换。
* **文件系统操作:** 当你创建一个文件或目录时，系统会记录创建者的 UID 和 GID。这些信息来源于 `/etc/passwd` 和 `/etc/group`，并通过 Bionic 库中的函数（最终可能调用到这里）获取。
* **NDK 开发:** 使用 NDK 进行 C/C++ 开发时，你可能会调用 `getpwuid`, `getpwnam`, `getgrgid`, `getgrnam` 等标准 POSIX 函数来获取用户信息和组信息。这些函数在 Android 上的实现最终会调用到 `grp_pwd_file.cpp` 中的功能。

**libc 函数的功能实现详解**

以下是 `grp_pwd_file.cpp` 中使用的一些 libc 函数的实现方式：

1. **`open(filename_, O_CLOEXEC | O_NOFOLLOW | O_RDONLY)`:**
   - **功能:** 打开指定路径的文件。
   - **实现:** 这是一个系统调用，由 Linux 内核实现。内核会在文件系统中查找指定的文件，并返回一个文件描述符。
   - **标志位:**
     - `O_CLOEXEC`: 设置 close-on-exec 标志，防止子进程继承该文件描述符，提高安全性。
     - `O_NOFOLLOW`: 如果 `filename_` 是一个符号链接，则 `open` 失败，防止符号链接攻击。
     - `O_RDONLY`: 以只读模式打开文件。

2. **`fstat(fd.get(), &fd_stat)`:**
   - **功能:** 获取与文件描述符关联的文件的状态信息。
   - **实现:** 这是一个系统调用，由 Linux 内核实现。内核会返回一个 `stat` 结构体，其中包含文件的大小、权限、修改时间等信息。
   - **用途:** 在这里用于获取文件的大小 (`fd_stat.st_size`)，以便后续的 `mmap` 调用。

3. **`mmap(nullptr, mmap_size, PROT_READ, MAP_SHARED, fd.get(), 0)`:**
   - **功能:** 将文件或设备映射到内存。
   - **实现:** 这是一个系统调用，由 Linux 内核实现。内核会在进程的地址空间中创建一个映射，该映射对应于指定文件的内容。
   - **参数:**
     - `nullptr`:  让内核选择映射的起始地址。
     - `mmap_size`: 映射的长度，这里是文件的总大小。
     - `PROT_READ`: 设置内存保护属性为只读。
     - `MAP_SHARED`: 指定映射是共享的，对映射区域的修改会反映到原始文件中（尽管这里是只读打开，但这个标志位在某些情况下是必要的）。
     - `fd.get()`: 要映射的文件描述符。
     - `0`: 文件映射的偏移量，这里从文件开头开始映射。
   - **返回值:** 成功时返回映射区域的起始地址，失败时返回 `MAP_FAILED`。

4. **`munmap(const_cast<char*>(start_), size)`:**
   - **功能:** 取消内存映射。
   - **实现:** 这是一个系统调用，由 Linux 内核实现。内核会释放之前通过 `mmap` 创建的内存映射。
   - **参数:**
     - `const_cast<char*>(start_)`: 映射区域的起始地址。需要进行 `const_cast` 是因为 `munmap` 的参数类型是 `void*`。
     - `size`: 映射区域的长度。

5. **`strtoul(field, &end, 0)`:**
   - **功能:** 将字符串转换为无符号长整型数。
   - **实现:**  这是 C 标准库函数。它会尝试将字符串 `field` 转换为无符号长整型数。
   - **参数:**
     - `field`: 要转换的字符串。
     - `&end`: 一个指向 `char*` 的指针，用于存储转换停止的位置。如果转换成功，`*end` 指向第一个非数字字符；如果没有任何数字，则 `*end` 等于 `field`。
     - `0`:  自动检测数字的进制（例如，以 "0x" 开头表示十六进制）。
   - **错误处理:**  `strtoul` 会设置 `errno` 全局变量来指示转换过程中是否发生错误（例如，溢出）。

**涉及 dynamic linker 的功能**

`grp_pwd_file.cpp` 本身并没有直接涉及 dynamic linker 的功能。它是一个静态链接到 `libc.so` 的代码，其运行依赖于 `libc.so` 被动态链接器加载到进程的地址空间。

**`libc.so` 布局样本：**

一个简化的 `libc.so` 的布局可能如下：

```
Program Header:
    LOAD           0x...1000  0x...1000  0x...1000  0x...A000 R E 0x1000
    LOAD           0x...B000  0x...B000  0x...B000  0x...C000 RW  0x1000
    DYNAMIC        0x...Bxxx  0x...Bxxx  0x...Bxxx  0x...Bxxx RW  0x8
    ...

Section Headers:
    .text          0x...1000  0x...1000  0x...1000  0xA000  AX  0x10
    .rodata        0x...9000  0x...9000  0x...9000  0x1000   A  0x10
    .data          0x...B000  0x...B000  0x...B000  0x0800  WA  0x20
    .bss           0x...B800  0x...B800  0x...B800  0x0200  WA  0x20
    .dynsym        0x...C000  0x...C000  0x...C000  0x1000   A  0x4
    .dynstr        0x...D000  0x...D000  0x...D000  0x2000   A  0x1
    .rel.plt       0x...F000  0x...F000  0x...F000  0x0100   A  0x4
    .symtab        ...
    .strtab        ...
    ...
```

**链接的处理过程：**

1. **编译时链接:** 当 `grp_pwd_file.cpp` 被编译成目标文件时，编译器会记录它引用的来自 `libc.so` 的符号（例如 `open`, `mmap` 等）。这些信息存储在目标文件的 `.dynsym` 和 `.rel.plt` 等 section 中。
2. **加载时链接:** 当一个程序启动时，Android 的动态链接器 (linker, 通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，例如 `libc.so`。
3. **符号解析:** 动态链接器会解析程序和 `libc.so` 中的符号表 (`.dynsym`)。对于程序中未定义的符号（例如对 `open` 的调用），链接器会在 `libc.so` 的符号表中查找对应的定义。
4. **重定位:**  由于共享库被加载到内存中的地址是不确定的，链接器需要修改程序和共享库中的某些指令和数据，使其指向正确的内存地址。例如，对 `open` 函数的调用需要被重定位到 `libc.so` 中 `open` 函数的实际地址。
5. **PLT 和 GOT:**  通常使用 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 来实现延迟绑定。第一次调用一个外部函数时，会通过 PLT 跳转到链接器，链接器解析符号并更新 GOT 表项为函数的实际地址，后续调用将直接通过 GOT 跳转到函数。

**逻辑推理，假设输入与输出**

假设我们有以下 `/etc/passwd` 文件内容：

```
root:x:0:0:root:/root:/bin/bash
user1:x:1000:1000:User One:/home/user1:/bin/sh
user2:x:1001:1001:User Two:/home/user2:/bin/zsh
```

如果我们调用 `PasswdFile::FindByName("user1", &passwd_state)`，假设 `PasswdFile` 已经成功映射了 `/etc/passwd` 文件，那么：

**假设输入:**

* `name` (参数传递给 `FindByName`): "user1"
* `/etc/passwd` 文件内容如上所示。

**输出:**

* `passwd_state.passwd_.pw_uid`: 1000
* `passwd_state.passwd_.pw_gid`: 1000
* `passwd_state.passwd_.pw_name`: 指向 `passwd_state.name_buffer_`，内容为 "user1"
* `passwd_state.passwd_.pw_dir`: 指向 `passwd_state.dir_buffer_`，内容为 "/home/user1"
* `passwd_state.passwd_.pw_shell`: 指向 `passwd_state.sh_buffer_`，内容为 "/bin/sh"
* 函数返回 `true`，表示找到匹配项。

如果调用 `PasswdFile::FindByName("nonexistentuser", &passwd_state)`，则函数返回 `false`。

**用户或编程常见的使用错误**

1. **假设字符串以 null 结尾:**  代码注释明确指出，从 mmap 文件中读取的字符串**不是**以 null 结尾的。如果用户代码直接使用这些指针作为 C 风格字符串，可能会导致缓冲区溢出或其他未定义行为。必须使用 `CopyFieldToString` 或类似的方法复制到有 null 结尾的缓冲区。
   ```c++
   // 错误示例：
   const char* username;
   // ... 从 MmapFile 中获取 username 的指针
   printf("Username: %s\n", username); // 可能读取超出预期范围
   ```

2. **不检查返回值:**  `FindById` 和 `FindByName` 返回 `bool` 值指示是否找到匹配项。如果用户代码不检查返回值，可能会访问未初始化的 `passwd_state_t` 或 `group_state_t` 结构体。
   ```c++
   passwd_state_t state;
   passwd_file.FindByName("test", &state);
   printf("UID: %d\n", state.passwd_.pw_uid); // 如果 FindByName 返回 false，则 state 未初始化
   ```

3. **修改 mmap 区域:**  尽管这里以只读方式映射，但如果其他地方有写入映射的操作，用户程序不应该尝试修改 mmap 返回的内存区域，因为这会导致未定义的行为，甚至程序崩溃。

4. **忘记处理错误:**  `open` 和 `mmap` 等系统调用可能会失败。用户代码应该检查这些调用的返回值，并进行适当的错误处理。

**Android Framework 或 NDK 如何一步步到达这里**

以下是一个简化的调用链，展示了 Android Framework 或 NDK 如何最终使用到 `grp_pwd_file.cpp` 中的功能：

1. **Android Framework (Java 层):**  例如，`android.os.Process.getUidForName(String)` 方法用于获取指定用户名的 UID。

2. **System Server (Java 层):**  `getUidForName` 方法通常会通过 Binder IPC 调用到 System Server 进程中的一个服务，例如 `AccountManagerService` 或 `UserManagerService`。

3. **Native 代码桥接 (JNI):**  System Server 中的 Java 代码会调用 JNI 方法，这些方法会调用到 Android 运行时的 native 代码。

4. **Android Runtime (art 或 dalvik):**  ART 或 Dalvik 虚拟机的 native 代码中会实现 `getpwuid`, `getpwnam` 等 POSIX 标准函数。

5. **Bionic libc:**  ART/Dalvik 的 `getpwuid`, `getpwnam` 等函数的实现会调用 Bionic libc 提供的相应函数，这些函数最终会使用 `PasswdFile` 类中的 `FindById` 或 `FindByName` 方法。

6. **`grp_pwd_file.cpp`:** `PasswdFile` 的方法会读取 mmap 映射的 `/etc/passwd` 文件并查找用户信息。

**Frida Hook 示例调试步骤**

我们可以使用 Frida Hook `PasswdFile::FindByName` 函数来观察其行为。

**Frida Hook 脚本 (Python):**

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "_ZN10PasswdFile9FindByNameEPKcPN14passwd_state_tE"), {
    onEnter: function(args) {
        const namePtr = args[1];
        const name = namePtr.readUtf8String();
        console.log(`[*] Calling PasswdFile::FindByName with name: ${name}`);
        this.passwd_state_ptr = args[2];
    },
    onLeave: function(retval) {
        console.log(`[*] PasswdFile::FindByName returned: ${retval}`);
        if (retval) {
            const passwd_state = this.passwd_state_ptr;
            const pw_name = passwd_state.readPointer().readCString();
            const pw_uid = passwd_state.add(Process.pointerSize * 1).readU32();
            const pw_gid = passwd_state.add(Process.pointerSize * 2).readU32();
            const pw_dir = passwd_state.add(Process.pointerSize * 4).readPointer().readCString();
            const pw_shell = passwd_state.add(Process.pointerSize * 5).readPointer().readCString();
            console.log(`[*] Found user: name=${pw_name}, uid=${pw_uid}, gid=${pw_gid}, dir=${pw_dir}, shell=${pw_shell}`);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **找到目标进程:** 运行你想要调试的 Android 应用程序，并记下其进程名称或 PID。
3. **替换包名:** 将 Frida 脚本中的 `package_name` 替换为你的目标应用程序的包名。
4. **运行 Frida 脚本:** 在终端中运行 Frida 脚本：`frida -UF -l your_script.py` (如果只有一个 USB 设备连接) 或 `frida -U -n <process_name> -l your_script.py` 或 `frida -H <device_ip> -p <pid> -l your_script.py`。
5. **触发调用:** 在你的 Android 应用程序中执行一些操作，这些操作可能会导致调用到 `getpwuid` 或 `getpwnam` 等函数，最终触发 `PasswdFile::FindByName` 的执行。例如，尝试获取当前用户信息或访问需要特定用户权限的功能。
6. **观察输出:** Frida 脚本会在终端中打印出 `PasswdFile::FindByName` 函数的调用信息，包括传入的用户名和返回结果，以及如果找到用户时的详细信息。

通过这个 Frida Hook 示例，你可以观察到当 Android 应用程序需要查找用户信息时，是如何一步步调用到 `bionic/libc/bionic/grp_pwd_file.cpp` 中的 `PasswdFile::FindByName` 函数的。这可以帮助你理解 Android 系统底层是如何处理用户和组信息的。

希望这个详细的分析能够帮助你理解 `grp_pwd_file.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/grp_pwd_file.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include "grp_pwd_file.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <async_safe/log.h>

#include "private/ErrnoRestorer.h"
#include "private/ScopedFd.h"

// This file mmap's /*/etc/passwd and /*/etc/group in order to return their contents without any
// allocations.  Note that these files and the strings contained within them are explicitly not
// null-terminated.  ':'s are used to deliminate fields and '\n's are used to deliminate lines.
// There is a check that the file ends with '\n', such that terminating loops at '\n' ensures that
// memory will be not read beyond the mmap region.

namespace {

void CopyFieldToString(char* dest, const char* source, size_t max) {
  while (*source != ':' && *source != '\n' && max > 1) {
    *dest++ = *source++;
    --max;
  }
  *dest = '\0';
}

bool FieldToUid(const char* field, uid_t* uid) {
  if (field == nullptr) {
    return false;
  }

  char* end = nullptr;
  errno = 0;
  uid_t result = strtoul(field, &end, 0);
  if (errno != 0 || field == end || *end != ':') {
    return false;
  }
  *uid = result;
  return true;
}

// Returns a pointer to one past the end of line.
const char* ParseLine(const char* begin, const char* end, const char** fields, size_t num_fields) {
  size_t fields_written = 0;
  const char* position = begin;
  fields[fields_written++] = position;

  while (position < end && fields_written < num_fields) {
    if (*position == '\n') {
      return position + 1;
    }
    if (*position == ':') {
      fields[fields_written++] = position + 1;
    }
    position++;
  }

  while (position < end && *position != '\n') {
    position++;
  }

  return position + 1;
}

struct PasswdLine {
  const char* name() const {
    return fields[0];
  }
  // Password is not supported.
  const char* uid() const {
    return fields[2];
  }
  const char* gid() const {
    return fields[3];
  }
  // User Info is not supported
  const char* dir() const {
    return fields[5];
  }
  const char* shell() const {
    return fields[6];
  }

  bool ToPasswdState(passwd_state_t* passwd_state) {
    if (name() == nullptr || dir() == nullptr || shell() == nullptr) {
      return false;
    }

    uid_t uid;
    if (!FieldToUid(this->uid(), &uid)) {
      return false;
    }

    gid_t gid;
    if (!FieldToUid(this->gid(), &gid)) {
      return false;
    }

    passwd_state->passwd_.pw_uid = uid;
    passwd_state->passwd_.pw_gid = gid;

    CopyFieldToString(passwd_state->name_buffer_, name(), sizeof(passwd_state->name_buffer_));
    passwd_state->passwd_.pw_name = passwd_state->name_buffer_;

    passwd_state->passwd_.pw_passwd = nullptr;

#ifdef __LP64__
    passwd_state->passwd_.pw_gecos = nullptr;
#endif

    CopyFieldToString(passwd_state->dir_buffer_, dir(), sizeof(passwd_state->dir_buffer_));
    passwd_state->passwd_.pw_dir = passwd_state->dir_buffer_;

    CopyFieldToString(passwd_state->sh_buffer_, shell(), sizeof(passwd_state->sh_buffer_));
    passwd_state->passwd_.pw_shell = passwd_state->sh_buffer_;

    return true;
  }

  static constexpr size_t kNumFields = 7;
  const char* fields[kNumFields] = {};
};

struct GroupLine {
  const char* name() const {
    return fields[0];
  }
  // Password is not supported.
  const char* gid() const {
    return fields[2];
  }
  // User list is not supported (returns simply name)

  bool ToGroupState(group_state_t* group_state) {
    if (name() == nullptr || gid() == nullptr) {
      return false;
    }

    gid_t gid;
    if (!FieldToUid(this->gid(), &gid)) {
      return false;
    }

    group_state->group_.gr_gid = gid;

    CopyFieldToString(group_state->group_name_buffer_, name(),
                      sizeof(group_state->group_name_buffer_));
    group_state->group_.gr_name = group_state->group_name_buffer_;

    group_state->group_.gr_passwd = nullptr;

    group_state->group_.gr_mem = group_state->group_members_;
    group_state->group_.gr_mem[0] = group_state->group_.gr_name;
    group_state->group_.gr_mem[1] = nullptr;

    return true;
  }

  static constexpr size_t kNumFields = 4;
  const char* fields[kNumFields] = {};
};

}  // namespace

MmapFile::MmapFile(const char* filename, const char* required_prefix)
    : filename_(filename), required_prefix_(required_prefix) {
  lock_.init(false);
}

void MmapFile::Unmap() {
  if (status_ == FileStatus::Initialized) {
    size_t size = end_ - start_ + 1;
    munmap(const_cast<char*>(start_), size);
    status_ = FileStatus::Uninitialized;
    start_ = nullptr;
    end_ = nullptr;
  }
}

bool MmapFile::GetFile(const char** start, const char** end) {
  LockGuard guard(lock_);
  if (status_ == FileStatus::Initialized) {
    *start = start_;
    *end = end_;
    return true;
  }
  if (status_ == FileStatus::Error) {
    return false;
  }

  if (!DoMmap()) {
    status_ = FileStatus::Error;
    return false;
  }

  status_ = FileStatus::Initialized;
  *start = start_;
  *end = end_;
  return true;
}

bool MmapFile::DoMmap() {
  ScopedFd fd(open(filename_, O_CLOEXEC | O_NOFOLLOW | O_RDONLY));

  struct stat fd_stat;
  if (fstat(fd.get(), &fd_stat) == -1) {
    return false;
  }

  auto mmap_size = fd_stat.st_size;

  void* map_result = mmap(nullptr, mmap_size, PROT_READ, MAP_SHARED, fd.get(), 0);
  if (map_result == MAP_FAILED) {
    return false;
  }

  start_ = static_cast<const char*>(map_result);
  end_ = start_ + mmap_size - 1;

  if (*end_ != '\n') {
    munmap(map_result, mmap_size);
    return false;
  }

  return true;
}

template <typename Line, typename Predicate>
bool MmapFile::Find(Line* line, Predicate predicate) {
  const char* start;
  const char* end;
  if (!GetFile(&start, &end)) {
    return false;
  }

  const char* line_beginning = start;

  while (line_beginning < end) {
    line_beginning = ParseLine(line_beginning, end, line->fields, line->kNumFields);
#if defined(__ANDROID__)
    // To comply with Treble, users/groups from each partition need to be prefixed with
    // the partition name.
    if (required_prefix_ != nullptr) {
      if (strncmp(line->fields[0], required_prefix_, strlen(required_prefix_)) != 0) {
        char name[kGrpPwdBufferSize];
        CopyFieldToString(name, line->fields[0], sizeof(name));
        async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                              "Found user/group name '%s' in '%s' without required prefix '%s'",
                              name, filename_, required_prefix_);
        continue;
      }
    }
#endif
    if (predicate(line)) return true;
  }

  return false;
}

template <typename Line>
bool MmapFile::FindById(uid_t uid, Line* line) {
  return Find(line, [uid](const auto& line) {
    uid_t line_id;
    if (!FieldToUid(line->fields[2], &line_id)) {
      return false;
    }

    return line_id == uid;
  });
}

template <typename Line>
bool MmapFile::FindByName(const char* name, Line* line) {
  return Find(line, [name](const auto& line) {
    const char* line_name = line->fields[0];
    if (line_name == nullptr) {
      return false;
    }

    const char* match_name = name;
    while (*line_name != '\n' && *line_name != ':' && *match_name != '\0') {
      if (*line_name++ != *match_name++) {
        return false;
      }
    }

    return *line_name == ':' && *match_name == '\0';
  });
}

PasswdFile::PasswdFile(const char* filename, const char* required_prefix)
    : mmap_file_(filename, required_prefix) {
}

bool PasswdFile::FindById(uid_t id, passwd_state_t* passwd_state) {
  ErrnoRestorer errno_restorer;
  PasswdLine passwd_line;
  return mmap_file_.FindById(id, &passwd_line) && passwd_line.ToPasswdState(passwd_state);
}

bool PasswdFile::FindByName(const char* name, passwd_state_t* passwd_state) {
  ErrnoRestorer errno_restorer;
  PasswdLine passwd_line;
  return mmap_file_.FindByName(name, &passwd_line) && passwd_line.ToPasswdState(passwd_state);
}

GroupFile::GroupFile(const char* filename, const char* required_prefix)
    : mmap_file_(filename, required_prefix) {
}

bool GroupFile::FindById(gid_t id, group_state_t* group_state) {
  ErrnoRestorer errno_restorer;
  GroupLine group_line;
  return mmap_file_.FindById(id, &group_line) && group_line.ToGroupState(group_state);
}

bool GroupFile::FindByName(const char* name, group_state_t* group_state) {
  ErrnoRestorer errno_restorer;
  GroupLine group_line;
  return mmap_file_.FindByName(name, &group_line) && group_line.ToGroupState(group_state);
}

"""

```
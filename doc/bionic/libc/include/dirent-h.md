Response:
Let's break down the thought process for generating the comprehensive answer about `dirent.handroid`.

**1. Understanding the Request:**

The request is to analyze the provided C header file (`dirent.handroid`) from Android's Bionic library. The key requirements are:

* **List the functions:** Identify each function declared in the header.
* **Explain function functionality:** Describe what each function does.
* **Relate to Android:** Explain how these functions are used in the Android context with examples.
* **Explain libc implementation:**  How are these functions actually implemented at a lower level (system calls)?
* **Dynamic linker relevance:**  Identify if any parts are related to the dynamic linker and explain the linking process with an example.
* **Logic and I/O:** If any function involves logical steps or input/output, provide hypothetical scenarios.
* **Common errors:**  Illustrate common mistakes programmers make when using these functions.
* **Android framework/NDK path:** Trace how a call from the Android framework or NDK might reach these functions.
* **Frida hook examples:** Provide code snippets to demonstrate how to intercept and observe the execution of these functions using Frida.

**2. Initial Analysis of the Header File:**

The first step is to scan the header file and identify the key elements:

* **Include statements:** `<sys/cdefs.h>`, `<stdint.h>`, `<sys/types.h>`. These provide foundational definitions.
* **Macros:** `DT_UNKNOWN`, `DT_FIFO`, etc. These define file types.
* **Structure definitions:** `dirent` and `dirent64`. Notice they are essentially the same in Android's Bionic.
* **Type definitions:** `DIR`. This represents a directory stream.
* **Function declarations:** `opendir`, `fdopendir`, `readdir`, `readdir64`, `closedir`, `rewinddir`, `seekdir`, `telldir`, `dirfd`, `alphasort`, `alphasort64`, `scandir`, `scandir64`, `scandirat`, `scandirat64`.
* **Deprecated functions:** `readdir_r`, `readdir64_r`. Mention these but emphasize their deprecated status.
* **GNU extensions:** Functions like `scandirat` and `scandirat64` are marked as GNU extensions.
* **Availability guards:**  `__BIONIC_AVAILABILITY_GUARD` and `__INTRODUCED_IN` indicate when these functions became available in the Android API.

**3. Categorizing and Explaining Functions:**

Organize the functions into logical groups based on their purpose:

* **Opening/Closing Directories:** `opendir`, `fdopendir`, `closedir`
* **Reading Directory Entries:** `readdir`, `readdir64`
* **Manipulating Directory Stream Position:** `rewinddir`, `seekdir`, `telldir`
* **Getting File Descriptor:** `dirfd`
* **Scanning and Filtering/Sorting:** `scandir`, `scandir64`, `alphasort`, `alphasort64`, `scandirat`, `scandirat64`

For each function, describe its:

* **Purpose:**  What does it do?  Relate it to the user's perspective (e.g., "opens a directory to list its contents").
* **Parameters:** What inputs does it take?
* **Return value:** What does it return on success and failure?  Mention `errno`.
* **Android Relevance:**  Provide concrete examples of how these functions are used in Android. Think about apps listing files, file managers, etc.

**4. Explaining Libc Implementation (System Calls):**

This requires understanding that these C library functions are wrappers around system calls. For the directory functions, the relevant system calls are:

* `open()` (with `O_DIRECTORY` flag) for `opendir` and `fdopendir`.
* `getdents()` or `getdents64()` for `readdir` and `readdir64`.
* `close()` for `closedir`.
* `lseek()` with the directory file descriptor for `rewinddir` and `seekdir`.
*  No direct equivalent for `telldir`; it likely maintains an internal offset.
* `fcntl()` with `F_GETFD` for `dirfd`.
*  `scandir` and `scandirat` would be implemented by internally using `opendir`/`fdopendir`, `readdir`/`readdir64`, filtering, sorting (using `qsort`), and managing memory.

**5. Dynamic Linker Considerations:**

The `dirent.h` header itself doesn't directly involve dynamic linking *in its own implementation*. However, the *use* of these functions happens within applications and libraries that *are* dynamically linked.

* **SO Layout:** Describe a typical Android shared object (`.so`) layout. Include sections like `.text`, `.data`, `.bss`, `.dynamic`, `.dynsym`, `.rel.dyn`, `.rel.plt`.
* **Linking Process:** Explain how the dynamic linker (`linker64` or `linker`) resolves symbols like `opendir` when an application uses it. Mention the GOT and PLT.

**6. Logic, Input, and Output Examples:**

For functions like `scandir` or `scandirat` that involve more complex logic, create simple scenarios:

* **Input:** A directory path, a filter function (e.g., only show files ending in ".txt").
* **Output:** A list of `dirent` structures matching the criteria.

**7. Common Usage Errors:**

Think about the pitfalls programmers often encounter:

* Forgetting to check return values (especially for errors).
* Not closing the `DIR*` with `closedir`, leading to resource leaks.
* Incorrectly using `readdir_r` (now deprecated).
* Misunderstanding the behavior of `seekdir` and `telldir`.
* Buffer overflows if `d_name` is not handled carefully (although the fixed size mitigates this somewhat in this specific header).

**8. Android Framework/NDK Path:**

Trace a high-level call:

* **Framework:**  `java.io.File.list()` in Java.
* **Native Bridge:** This Java call goes down to native code, possibly through JNI.
* **NDK:**  An NDK application directly calls `opendir`, `readdir`, etc.
* **Bionic:** The NDK calls are directly linked against Bionic's libc.
* **System Call:** Bionic functions make the corresponding system calls.
* **Kernel:** The kernel handles the actual file system operations.

**9. Frida Hook Examples:**

Provide concrete Frida code snippets for:

* Hooking `opendir` to log the path being opened.
* Hooking `readdir` to log the name of each directory entry.
* Hooking `closedir` to confirm when the directory stream is closed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the internal data structures of `DIR`. **Correction:** The header file doesn't expose that, so focus on the function signatures and their effects.
* **Initial thought:** Go into extreme detail about the `getdents` system call structure. **Correction:**  Keep it concise and focus on the overall purpose of the system call.
* **Initial thought:**  Overcomplicate the dynamic linking explanation. **Correction:** Provide a clear, high-level overview of the GOT/PLT mechanism relevant to these libc functions.
* **Ensure clarity and structure:** Use headings, bullet points, and code formatting to make the answer easy to read and understand.

By following these steps, systematically analyzing the header file, and considering the different aspects of the request, a comprehensive and accurate answer can be generated. The key is to break down the problem into smaller, manageable parts and then synthesize the information.
这个是 Android Bionic C 库中 `dirent.h` 文件的一部分，它定义了用于目录操作的结构体和函数。这个 `dirent.handroid` 文件很可能是一个特定于 Android 平台或架构的 `dirent.h` 变体。

下面我将详细列举其功能，并尽可能解答你的每一个问题。

**`dirent.h` 的功能：**

这个头文件主要定义了用于遍历和操作目录的接口。它提供了以下关键功能：

1. **定义目录条目结构体 (`dirent` 和 `dirent64`)**:  用于存储从目录中读取的单个条目的信息，例如文件名、inode 编号、文件类型等。在 Android 中，`dirent` 和 `dirent64` 结构体是相同的。
2. **定义文件类型宏 (`DT_UNKNOWN`, `DT_FIFO`, `DT_CHR`, `DT_DIR`, `DT_BLK`, `DT_REG`, `DT_LNK`, `DT_SOCK`, `DT_WHT`)**:  用于表示目录条目的文件类型。
3. **声明打开目录的函数 (`opendir`, `fdopendir`)**:  用于打开一个目录流，以便后续读取目录内容。
4. **声明读取目录条目的函数 (`readdir`, `readdir64`)**:  用于从已打开的目录流中读取下一个目录条目。
5. **声明关闭目录的函数 (`closedir`)**:  用于关闭已打开的目录流，释放相关资源。
6. **声明重置目录流位置的函数 (`rewinddir`)**:  用于将目录流的读取位置重置到开头。
7. **声明定位目录流位置的函数 (`seekdir`, `telldir`)**:  用于在目录流中移动读取位置（需要 API level 23 以上）。
8. **声明获取目录流关联的文件描述符的函数 (`dirfd`)**:  用于获取与已打开目录流关联的文件描述符。
9. **声明用于排序目录条目的函数 (`alphasort`, `alphasort64`)**:  用于 `scandir` 和 `scandir64` 函数的比较器，按字母顺序排序。
10. **声明扫描目录的函数 (`scandir`, `scandir64`, `scandirat`, `scandirat64`)**:  用于扫描整个目录，并可以根据过滤器和比较器对条目进行过滤和排序。

**与 Android 功能的关系及举例说明：**

这些函数是 Android 系统和应用程序进行文件系统操作的基础。它们被广泛用于各种场景，例如：

* **文件管理器应用**: 使用 `opendir` 和 `readdir` 来列出目录中的文件和文件夹。
* **系统服务 (e.g., `installd`)**:  使用这些函数来扫描安装目录，检查应用包等。
* **shell 命令 (e.g., `ls`)**:  底层实现会调用这些 libc 函数来获取目录信息。
* **NDK 开发**:  Native 代码可以直接调用这些函数来操作文件系统。

**举例说明：**

假设一个文件管理器应用需要列出 `/sdcard/Pictures` 目录下的所有文件。它可能会执行以下步骤：

1. 调用 `opendir("/sdcard/Pictures")` 打开目录流。
2. 循环调用 `readdir` 读取目录条目，直到返回 `NULL`。
3. 对于每个读取到的 `dirent` 结构体，获取文件名 (`d_name`) 和文件类型 (`d_type`)。
4. 将文件名显示在用户界面上。
5. 调用 `closedir` 关闭目录流。

**libc 函数的实现原理：**

这些 libc 函数实际上是对 Linux 内核提供的系统调用的封装。当应用程序调用这些函数时，Bionic C 库会将这些调用转换为相应的系统调用，例如：

* `opendir`:  通常会调用 `openat()` 系统调用，并使用 `O_RDONLY` 和 `O_DIRECTORY` 标志。Bionic 内部会维护一个 `DIR` 结构体，用于跟踪目录流的状态。
* `fdopendir`:  直接基于已有的文件描述符创建一个目录流，内部也会维护 `DIR` 结构体。
* `readdir`:  会调用 `getdents()` 或 `getdents64()` 系统调用来从内核读取目录条目。内核会返回一个包含多个 `dirent` 结构体的缓冲区。Bionic 会解析这个缓冲区，并每次调用 `readdir` 返回一个 `dirent` 结构体的指针。Bionic 还需要维护目录流的当前位置。
* `closedir`:  会调用 `close()` 系统调用来关闭与目录流关联的文件描述符，并释放 Bionic 内部维护的 `DIR` 结构体。
* `rewinddir`:  会调用 `lseek()` 系统调用，将目录流的文件偏移量设置为 0，从而回到目录的开头。
* `seekdir`:  会根据 `telldir` 返回的值，使用 `lseek()` 系统调用将文件偏移量设置到指定位置。`telldir` 的实现通常会返回当前目录流的内部偏移量。
* `dirfd`:  会调用 `fcntl()` 系统调用，使用 `F_GETFD` 命令来获取与 `DIR` 结构体关联的文件描述符。
* `scandir`/`scandir64`/`scandirat`/`scandirat64`:  这些函数通常会先调用 `opendir` (或 `fdopendir`) 打开目录，然后循环调用 `readdir` (或 `readdir64`) 读取所有条目，并将符合过滤器条件的条目存储在一个动态分配的数组中。如果提供了比较器，则使用 `qsort` 对数组进行排序。

**涉及 dynamic linker 的功能：**

`dirent.h` 本身定义的是接口，其实现位于 Bionic 的 libc.so 共享库中。当应用程序需要使用这些函数时，dynamic linker 负责在程序启动或运行时将这些函数链接到应用程序的进程空间。

**so 布局样本：**

```
libc.so (典型的共享库布局)
├── .interp        (指向动态链接器的路径)
├── .note.android.ident
├── .note.gnu.build-id
├── .plt            (过程链接表)
├── .plt.got        (过程链接表全局偏移表)
├── .text           (代码段，包含 opendir, readdir 等函数的机器码)
├── .rodata         (只读数据段，包含字符串常量等)
├── .data.rel.ro    (只读的已初始化数据)
├── .data           (可读写的数据段，包含全局变量等)
├── .bss            (未初始化的数据段)
├── .dynamic        (动态链接信息)
├── .symtab         (符号表)
├── .strtab         (字符串表)
├── .shstrtab       (节区头字符串表)
├── .rela.dyn       (动态重定位信息)
├── .rela.plt       (过程链接表重定位信息)
└── ...             (其他节区)
```

**链接的处理过程：**

1. **编译时：** 编译器在编译应用程序的代码时，如果遇到了 `opendir` 等函数调用，会在目标文件中生成对这些符号的未解析引用。
2. **链接时：**  静态链接器（如果存在）或者动态链接器在加载时会查看应用程序依赖的共享库列表。libc.so 是 Android 应用程序默认链接的库之一。
3. **动态链接：** 当应用程序启动时，`linker64` 或 `linker`（取决于架构）会加载应用程序和其依赖的共享库到内存中。
4. **符号解析：** 动态链接器会遍历应用程序的 `.dynamic` 段和 libc.so 的 `.dynsym` (动态符号表)，找到 `opendir` 等符号的定义地址。
5. **重定位：** 动态链接器会修改应用程序的 `.got.plt` (全局偏移表) 中的条目，使其指向 libc.so 中 `opendir` 等函数的实际地址。
6. **调用：** 当应用程序执行到调用 `opendir` 的指令时，会通过 `.plt` (过程链接表) 跳转到 `.got.plt` 中存储的地址，最终执行 libc.so 中的 `opendir` 函数。

**假设输入与输出 (逻辑推理)：**

假设我们调用 `scandir("/tmp", &namelist, NULL, alphasort)`：

* **输入:**
    * `__path`: "/tmp" (要扫描的目录)
    * `__name_list`: 指向 `struct dirent**` 的指针，用于存储结果。
    * `__filter`: `NULL` (接受所有条目)
    * `__comparator`: `alphasort` (按字母顺序排序)
* **输出:**
    * 返回值: 成功时返回扫描到的条目数量，失败时返回 -1 并设置 `errno`。
    * `namelist`: 指向一个动态分配的数组，该数组包含了指向 `struct dirent` 结构体的指针，每个结构体描述了 `/tmp` 目录下的一个条目，并按字母顺序排序。例如，如果 `/tmp` 下有文件 "a.txt", "b.txt", "c.txt" 和目录 "dir1"，则 `namelist` 可能会包含指向描述这些条目的 `dirent` 结构体的指针。

**用户或编程常见的使用错误：**

1. **忘记检查返回值:**  `opendir`, `readdir`, `closedir`, `scandir` 等函数在失败时会返回 `NULL` 或 -1，并设置 `errno`。忘记检查返回值可能导致程序逻辑错误或崩溃。
   ```c
   DIR *dir = opendir("/nonexistent_dir");
   // 错误的做法：直接使用 dir
   readdir(dir); // 可能导致段错误

   // 正确的做法：检查返回值
   if (dir == NULL) {
       perror("opendir failed");
       // 处理错误
   } else {
       // ... 使用 dir
       closedir(dir);
   }
   ```

2. **`opendir` 后忘记 `closedir`:**  打开目录后，如果不调用 `closedir` 关闭目录流，会导致资源泄漏（文件描述符未释放）。
   ```c
   DIR *dir = opendir("/tmp");
   if (dir != NULL) {
       // ... 读取目录
       // 错误的做法：忘记 closedir
   }
   ```

3. **错误地使用 `readdir_r`:**  `readdir_r` 是一个线程安全的版本，但使用起来比较复杂，容易出错。它已被标记为 deprecated，推荐使用 `readdir`。
   ```c
   // 错误的使用示例 (readdir_r 已 deprecated，更推荐使用 readdir)
   DIR *dir = opendir("/tmp");
   struct dirent entry;
   struct dirent *result;
   int ret = readdir_r(dir, &entry, &result);
   if (ret == 0 && result != NULL) {
       // ...
   }
   ```

4. **`scandir` 后忘记释放 `namelist`:** `scandir` 分配内存来存储目录条目，用户需要负责释放这部分内存。
   ```c
   struct dirent **namelist;
   int n = scandir("/tmp", &namelist, NULL, alphasort);
   if (n > 0) {
       for (int i = 0; i < n; i++) {
           // ... 使用 namelist[i]
           free(namelist[i]); // 释放 dirent 结构体的内存 (通常由 scandir 内部分配)
       }
       free(namelist); // 释放 namelist 数组的内存
   } else if (n == -1) {
       perror("scandir failed");
   }
   ```

**Android framework or ndk 是如何一步步的到达这里：**

1. **Android Framework (Java 代码):**  当 Android Framework 中的 Java 代码需要列出目录内容时，例如 `java.io.File.list()` 方法，它最终会调用 Native 方法。

   ```java
   File dir = new File("/sdcard/Download");
   String[] files = dir.list(); // 内部会调用 native 方法
   ```

2. **Native Bridge (JNI):**  Java 代码通过 Java Native Interface (JNI) 调用对应的 Native 方法。在 `java.io.File` 的实现中，可能会调用 `android_nio_File_list` 这样的 Native 函数。

3. **NDK 代码:** 如果是 NDK 开发，开发者可以直接调用 Bionic libc 提供的目录操作函数。

   ```c
   #include <dirent.h>
   #include <stdio.h>

   void list_directory(const char *path) {
       DIR *dir = opendir(path);
       if (dir != NULL) {
           struct dirent *ent;
           while ((ent = readdir(dir)) != NULL) {
               printf("%s\n", ent->d_name);
           }
           closedir(dir);
       } else {
           perror("opendir failed");
       }
   }
   ```

4. **Bionic libc:**  无论是 Framework 调用的 Native 方法还是 NDK 代码，最终都会调用 Bionic libc 中的 `opendir`, `readdir`, `closedir` 等函数实现。

5. **系统调用:** Bionic libc 函数会将这些操作转换为对应的 Linux 系统调用，例如 `openat`, `getdents`, `close` 等，由 Linux 内核处理。

**Frida hook 示例调试这些步骤：**

可以使用 Frida 来 hook 这些 libc 函数，观察其调用过程和参数。

**Hook `opendir`:**

```javascript
if (Process.platform === 'android') {
  const opendirPtr = Module.findExportByName("libc.so", "opendir");
  if (opendirPtr) {
    Interceptor.attach(opendirPtr, {
      onEnter: function (args) {
        const path = Memory.readUtf8String(args[0]);
        console.log(`[opendir] path: ${path}`);
      },
      onLeave: function (retval) {
        console.log(`[opendir] returned: ${retval}`);
      }
    });
  } else {
    console.log("Could not find opendir in libc.so");
  }
}
```

这个脚本会 hook `opendir` 函数，并在其被调用时打印传入的路径参数以及返回值。

**Hook `readdir`:**

```javascript
if (Process.platform === 'android') {
  const readdirPtr = Module.findExportByName("libc.so", "readdir");
  if (readdirPtr) {
    Interceptor.attach(readdirPtr, {
      onEnter: function (args) {
        // args[0] 是 DIR*
      },
      onLeave: function (retval) {
        if (!retval.isNull()) {
          const d_name = Memory.readUtf8String(retval.add(offsetof(dirent, 'd_name')));
          console.log(`[readdir] d_name: ${d_name}`);
        } else {
          console.log("[readdir] returned NULL");
        }
      }
    });

    // 辅助函数，获取 dirent 结构体的字段偏移
    function offsetof(struct, field) {
      const offsets = {
        dirent: {
          d_ino: 0,
          d_off: Process.pointerSize,
          d_reclen: Process.pointerSize * 2,
          d_type: Process.pointerSize * 2 + 2,
          d_name: Process.pointerSize * 2 + 3
        }
      };
      return offsets[struct][field];
    }
  } else {
    console.log("Could not find readdir in libc.so");
  }
}
```

这个脚本会 hook `readdir` 函数，并在其返回非空指针时打印读取到的文件名 (`d_name`)。需要注意的是，`offsetof` 函数的实现依赖于 `dirent` 结构体的布局，可能需要根据实际情况调整。

**Hook `closedir`:**

```javascript
if (Process.platform === 'android') {
  const closedirPtr = Module.findExportByName("libc.so", "closedir");
  if (closedirPtr) {
    Interceptor.attach(closedirPtr, {
      onEnter: function (args) {
        console.log("[closedir]");
      },
      onLeave: function (retval) {
        console.log(`[closedir] returned: ${retval}`);
      }
    });
  } else {
    console.log("Could not find closedir in libc.so");
  }
}
```

这个脚本会 hook `closedir` 函数，并在其被调用时打印信息。

通过这些 Frida hook 示例，你可以观察 Android 应用或系统服务在进行目录操作时调用的具体 libc 函数及其参数，从而更好地理解其工作原理。

### 提示词
```
这是目录为bionic/libc/include/dirent.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file dirent.h
 * @brief Directory entry iteration.
 */

#include <sys/cdefs.h>

#include <stdint.h>
#include <sys/types.h>

__BEGIN_DECLS

/** d_type value when the type is not known. */
#define DT_UNKNOWN 0
/** d_type value for a FIFO. */
#define DT_FIFO 1
/** d_type value for a character device. */
#define DT_CHR 2
/** d_type value for a directory. */
#define DT_DIR 4
/** d_type value for a block device. */
#define DT_BLK 6
/** d_type value for a regular file. */
#define DT_REG 8
/** d_type value for a symbolic link. */
#define DT_LNK 10
/** d_type value for a socket. */
#define DT_SOCK 12
#define DT_WHT 14

#if defined(__LP64__)
#define __DIRENT64_INO_T ino_t
#else
#define __DIRENT64_INO_T uint64_t /* Historical accident. */
#endif

#define __DIRENT64_BODY \
    __DIRENT64_INO_T d_ino; \
    off64_t d_off; \
    unsigned short d_reclen; \
    unsigned char d_type; \
    char d_name[256]; \

/** The structure returned by readdir(). Identical to dirent64 on Android. */
struct dirent { __DIRENT64_BODY };
/** The structure returned by readdir64(). Identical to dirent on Android. */
struct dirent64 { __DIRENT64_BODY };

#undef __DIRENT64_BODY
#undef __DIRENT64_INO_T

/* glibc compatibility. */
#undef _DIRENT_HAVE_D_NAMLEN /* Linux doesn't have a d_namlen field. */
#define _DIRENT_HAVE_D_RECLEN
#define _DIRENT_HAVE_D_OFF
#define _DIRENT_HAVE_D_TYPE

#define d_fileno d_ino

/** The structure returned by opendir()/fopendir(). */
typedef struct DIR DIR;

/**
 * [opendir(3)](https://man7.org/linux/man-pages/man3/opendir.3.html)
 * opens a directory stream for the directory at `__path`.
 *
 * Returns null and sets `errno` on failure.
 */
DIR* _Nullable opendir(const char* _Nonnull __path);

/**
 * [fopendir(3)](https://man7.org/linux/man-pages/man3/opendir.3.html)
 * opens a directory stream for the directory at `__dir_fd`.
 *
 * Returns null and sets `errno` on failure.
 */
DIR* _Nullable fdopendir(int __dir_fd);

/**
 * [readdir(3)](https://man7.org/linux/man-pages/man3/readdir.3.html)
 * returns the next directory entry in the given directory.
 *
 * Returns a pointer to a directory entry on success,
 * or returns null and leaves `errno` unchanged at the end of the directory,
 * or returns null and sets `errno` on failure.
 */
struct dirent* _Nullable readdir(DIR* _Nonnull __dir);

/**
 * [readdir64(3)](https://man7.org/linux/man-pages/man3/readdir.3.html)
 * returns the next directory entry in the given directory.
 *
 * Returns a pointer to a directory entry on success,
 * or returns null and leaves `errno` unchanged at the end of the directory,
 * or returns null and sets `errno` on failure.
 */
struct dirent64* _Nullable readdir64(DIR* _Nonnull __dir);

int readdir_r(DIR* _Nonnull __dir, struct dirent* _Nonnull __entry, struct dirent* _Nullable * _Nonnull __buffer) __attribute__((__deprecated__("readdir_r is deprecated; use readdir instead")));
int readdir64_r(DIR* _Nonnull __dir, struct dirent64* _Nonnull __entry, struct dirent64* _Nullable * _Nonnull __buffer) __attribute__((__deprecated__("readdir64_r is deprecated; use readdir64 instead")));

/**
 * [closedir(3)](https://man7.org/linux/man-pages/man3/closedir.3.html)
 * closes a directory stream.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int closedir(DIR* _Nonnull __dir);

/**
 * [rewinddir(3)](https://man7.org/linux/man-pages/man3/rewinddir.3.html)
 * rewinds a directory stream to the first entry.
 */
void rewinddir(DIR* _Nonnull __dir);

/**
 * [seekdir(3)](https://man7.org/linux/man-pages/man3/seekdir.3.html)
 * seeks a directory stream to the given entry, which must be a value returned
 * by telldir().
 *
 * Available since API level 23.
 */

#if __BIONIC_AVAILABILITY_GUARD(23)
void seekdir(DIR* _Nonnull __dir, long __location) __INTRODUCED_IN(23);

/**
 * [telldir(3)](https://man7.org/linux/man-pages/man3/telldir.3.html)
 * returns a value representing the current position in the directory
 * for use with seekdir().
 *
 * Returns the current position on success and returns -1 and sets `errno` on failure.
 *
 * Available since API level 23.
 */
long telldir(DIR* _Nonnull __dir) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


/**
 * [dirfd(3)](https://man7.org/linux/man-pages/man3/dirfd.3.html)
 * returns the file descriptor backing the given directory stream.
 *
 * Returns a file descriptor on success and returns -1 and sets `errno` on failure.
 */
int dirfd(DIR* _Nonnull __dir);

/**
 * [alphasort](https://man7.org/linux/man-pages/man3/alphasort.3.html) is a
 * comparator for use with scandir() that uses strcoll().
 */
int alphasort(const struct dirent* _Nonnull * _Nonnull __lhs, const struct dirent* _Nonnull * _Nonnull __rhs);

/**
 * [alphasort64](https://man7.org/linux/man-pages/man3/alphasort.3.html) is a
 * comparator for use with scandir64() that uses strcmp().
 */
int alphasort64(const struct dirent64* _Nonnull * _Nonnull __lhs, const struct dirent64* _Nonnull * _Nonnull __rhs);

/**
 * [scandir(3)](https://man7.org/linux/man-pages/man3/scandir.3.html)
 * scans all the directory `__path`, filtering entries with `__filter` and
 * sorting them with qsort() using the given `__comparator`, and storing them
 * into `__name_list`. Passing NULL as the filter accepts all entries.
 * Passing NULL as the comparator skips sorting.
 *
 * Returns the number of entries returned in the list on success,
 * and returns -1 and sets `errno` on failure.
 */
int scandir(const char* _Nonnull __path, struct dirent* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent* _Nonnull), int (* _Nullable __comparator)(const struct dirent* _Nonnull * _Nonnull, const struct dirent* _Nonnull * _Nonnull));

/**
 * [scandir64(3)](https://man7.org/linux/man-pages/man3/scandir.3.html)
 * scans all the directory `__path`, filtering entries with `__filter` and
 * sorting them with qsort() using the given `__comparator`, and storing them
 * into `__name_list`. Passing NULL as the filter accepts all entries.
 * Passing NULL as the comparator skips sorting.
 *
 * Returns the number of entries returned in the list on success,
 * and returns -1 and sets `errno` on failure.
 */
int scandir64(const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent64* _Nonnull), int (* _Nullable __comparator)(const struct dirent64* _Nonnull * _Nonnull, const struct dirent64* _Nonnull * _Nonnull));

#if defined(__USE_GNU)

/**
 * [scandirat64(3)](https://man7.org/linux/man-pages/man3/scandirat.3.html)
 * scans all the directory referenced by the pair of `__dir_fd` and `__path`,
 * filtering entries with `__filter` and sorting them with qsort() using the
 * given `__comparator`, and storing them into `__name_list`. Passing NULL as
 * the filter accepts all entries.
 * Passing NULL as the comparator skips sorting.
 *
 * Returns the number of entries returned in the list on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 24.
 */

#if __BIONIC_AVAILABILITY_GUARD(24)
int scandirat64(int __dir_fd, const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent64* _Nonnull), int (* _Nullable __comparator)(const struct dirent64* _Nonnull * _Nonnull, const struct dirent64* _Nonnull * _Nonnull)) __INTRODUCED_IN(24);

/**
 * [scandirat(3)](https://man7.org/linux/man-pages/man3/scandirat.3.html)
 * scans all the directory referenced by the pair of `__dir_fd` and `__path`,
 * filtering entries with `__filter` and sorting them with qsort() using the
 * given `__comparator`, and storing them into `__name_list`. Passing NULL as
 * the filter accepts all entries.
 * Passing NULL as the comparator skips sorting.
 *
 * Returns the number of entries returned in the list on success,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 24.
 */
int scandirat(int __dir_fd, const char* _Nonnull __path, struct dirent* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent* _Nonnull), int (* _Nullable __comparator)(const struct dirent* _Nonnull * _Nonnull, const struct dirent* _Nonnull * _Nonnull)) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */


#endif

__END_DECLS
```
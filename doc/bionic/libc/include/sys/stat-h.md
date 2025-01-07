Response:
Let's break down the thought process for analyzing this `stat.h` header file.

**1. Initial Understanding of the Request:**

The request asks for a comprehensive analysis of the `stat.h` file, focusing on its functions, their relationship to Android, implementation details (where possible from the header), dynamic linker aspects, potential errors, and how Android components reach this point.

**2. High-Level Overview of `stat.h`:**

The immediate purpose of `stat.h` is evident from the comments: "File status."  It defines structures and function prototypes for retrieving and manipulating file metadata (like permissions, size, timestamps). This is a fundamental aspect of any operating system.

**3. Function Listing and Core Functionality:**

The most straightforward task is to list all the declared functions. This involves scanning the file for lines starting with `int` or `mode_t` followed by a function name and parentheses. For each function, identify its core purpose based on its name and the accompanying comment (which thankfully are present and descriptive).

* **Initial Pass:** `chmod`, `fchmod`, `fchmodat`, `lchmod`, `mkdir`, `mkdirat`, `fstat`, `fstat64`, `fstatat`, `fstatat64`, `lstat`, `lstat64`, `stat`, `stat64`, `mknod`, `mknodat`, `umask`, `mkfifo`, `mkfifoat`, `utimensat`, `futimens`, `statx`.

* **Categorization:**  Group these functions by their general purpose. This helps in understanding the overall functionality of the file.
    * **Permission Manipulation:** `chmod`, `fchmod`, `fchmodat`, `lchmod`
    * **Directory Creation:** `mkdir`, `mkdirat`
    * **File Status Retrieval:** `fstat`, `fstat64`, `fstatat`, `fstatat64`, `lstat`, `lstat64`, `stat`, `stat64`
    * **File Creation (General):** `mknod`, `mknodat`, `mkfifo`, `mkfifoat`
    * **Permission Mask:** `umask`
    * **Timestamp Manipulation:** `utimensat`, `futimens`
    * **Extended Status:** `statx`

**4. Android Relevance and Examples:**

For each function category (or individual function where relevant), consider how it's used in the Android context. Think about common Android development tasks and system operations.

* **Permissions:**  Installing apps requires setting permissions on files. The Package Manager likely uses these functions. Accessing files in the file system by apps relies on these permissions.
* **Directory Creation:** Creating app-specific data directories. The file system structure of Android (e.g., `/data/data/<package name>`).
* **File Status:**  File explorers showing file size and modification times. `adb` commands like `ls -l`. Applications checking if a file exists or its type.
* **File Creation:**  Creating temporary files, named pipes for inter-process communication.
* **Timestamp Manipulation:**  Downloading files and preserving timestamps, updating file modification times.

**5. Implementation Details (from the Header):**

The header file primarily provides *declarations*. The actual implementation of these functions resides in other source files (likely `.c` files within the `bionic` library). However, the header *does* reveal some structural information:

* **`struct stat` and `struct stat64`:** The definitions of these structures are crucial. Notice the conditional compilation (`#if defined(...)`) based on architecture. This indicates that the layout of the `stat` structure can differ across architectures (ARM, x86, etc.) due to alignment and size considerations. The fields themselves are standard file metadata: device ID, inode number, permissions, user/group IDs, size, timestamps, etc.
* **Aliases:** The definitions like `#define st_atime st_atim.tv_sec` show compatibility layers for different POSIX and Linux standards.

**6. Dynamic Linker Aspects:**

This header file itself doesn't directly interact with the dynamic linker. However, the *functions declared here* are part of `libc.so`, which *is* managed by the dynamic linker.

* **SO Layout Example:** Provide a simple example of how `libc.so` might be laid out in memory, including the GOT and PLT. This helps illustrate the linker's role in resolving function calls.
* **Linking Process:** Briefly describe how the dynamic linker resolves calls to functions like `stat()` at runtime. Explain the role of the GOT and PLT.

**7. Logical Reasoning and Examples:**

For some functions, you can create simple scenarios to illustrate their behavior.

* **`chmod`:**  Show how changing permissions affects access. Provide the expected output of `stat` before and after.
* **`mkdir`:** Demonstrate creating a directory and then verifying its existence.

**8. Common Usage Errors:**

Think about common mistakes developers make when working with these functions.

* **Incorrect Permissions:** Setting too restrictive permissions.
* **Path Issues:** Providing incorrect or non-existent paths.
* **Error Handling:** Not checking the return values and `errno`.

**9. Android Framework/NDK Path and Frida Hook:**

This is about tracing the execution flow.

* **Framework Example:** Start with a high-level Android API call (e.g., `java.io.File.exists()`) and explain how it eventually calls down to native code and then to a `stat()`-related function in `libc.so`.
* **NDK Example:**  A simple NDK application using `stat()`.
* **Frida Hook:** Provide concrete Frida code to intercept calls to `stat()` and log arguments and return values. This is practical for debugging.

**10. Language and Formatting:**

The request specifically asks for a Chinese response. Ensure accurate translations and clear formatting (headings, bullet points) for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on implementation details of each function. **Correction:** Realized the header only provides declarations, so shift focus to the declared functionality and broader concepts.
* **Initial thought:**  The dynamic linker isn't directly *in* this file. **Correction:** Emphasize that the *functions declared here* are linked and managed by the dynamic linker.
* **Initial thought:**  Just list the functions. **Correction:** Group functions by category for better organization and understanding.
* **Initial thought:**  Assume the reader has a deep understanding of operating systems. **Correction:** Provide clear explanations and examples, especially for potentially less familiar concepts like the GOT and PLT.

By following this structured approach, breaking down the request into smaller parts, and continuously refining the analysis, a comprehensive and informative response can be generated. The key is to move from the specific details of the header file to the broader context of how these functions are used within the Android ecosystem.
这个文件 `bionic/libc/include/sys/stat.handroid` 是 Android Bionic C 库中的一个头文件，主要定义了与文件和目录状态相关的结构体和函数声明。它基于 POSIX 标准，并针对 Android 平台进行了一些调整和扩展。

**它的主要功能可以概括为：**

1. **定义了文件状态结构体 `stat` 和 `stat64`:**  这两个结构体用于存储文件的各种元数据信息，例如文件类型、权限、大小、所有者、修改时间等。`stat64` 是 `stat` 的扩展版本，用于处理更大的文件大小和设备 ID。

2. **声明了获取文件状态信息的函数:**  包括 `stat()`, `fstat()`, `lstat()`, `fstatat()` 等，这些函数允许程序查询指定文件或目录的元数据，并将结果存储在 `stat` 或 `stat64` 结构体中。

3. **声明了修改文件状态信息的函数:**  包括 `chmod()`, `fchmod()`, `fchmodat()`, `lchmod()` 用于修改文件或目录的权限；`mkdir()` 和 `mkdirat()` 用于创建目录；`mknod()` 和 `mknodat()` 用于创建特殊文件（如设备文件）；`umask()` 用于设置文件创建掩码； `utimensat()` 和 `futimens()` 用于修改文件的访问和修改时间；`mkfifo()` 和 `mkfifoat()` 用于创建命名管道 (FIFO)。

4. **定义了相关的宏和常量:**  例如，用于判断文件类型的宏（如 `S_ISREG()`, `S_ISDIR()` 等），以及用于 `utimensat()` 的特殊时间值 `UTIME_NOW` 和 `UTIME_OMIT`。

**它与 Android 功能的关系及举例说明：**

这个头文件中定义的函数和结构体是 Android 系统底层文件操作的基础，被 Android Framework 和 NDK 大量使用。

* **文件访问权限控制:** Android 的权限模型依赖于文件系统的权限。例如，当一个应用尝试访问另一个应用的文件时，系统会检查文件的权限位，这些权限位的修改和查询就涉及到 `chmod()`、`stat()` 等函数。
    * **例子:**  Package Manager 在安装应用时会设置 APK 文件和应用数据目录的权限，使用的就是 `chmod()` 等函数。

* **文件和目录管理:**  Android 系统需要创建、删除、重命名文件和目录。例如，当应用创建一个新的文件时，底层的实现可能会调用 `open()` 或 `creat()`，而这些操作通常会伴随着权限的设置，这会用到 `chmod()`。创建新的目录则会使用 `mkdir()`。
    * **例子:**  下载管理器在下载文件后，需要在指定目录下创建文件并写入数据。

* **文件信息展示:**  Android 的文件管理器应用需要显示文件的大小、修改时间等信息，这些信息是通过调用 `stat()` 或其变体获取的。
    * **例子:**  当你在文件管理器中查看一个文件的属性时，应用会调用 `stat()` 获取文件大小、修改时间等信息并显示出来。

* **应用安装和卸载:**  Android 系统在安装和卸载应用时，需要创建和删除应用的数据目录，设置相应的权限，这些操作都依赖于这里声明的函数。
    * **例子:**  `installd` 守护进程在安装 APK 时，会创建应用的数据目录，设置权限，并复制 APK 文件。

* **进程间通信 (IPC):**  命名管道 (FIFO) 是一种进程间通信的方式，`mkfifo()` 函数用于创建 FIFO 文件。
    * **例子:**  某些系统服务可能会使用 FIFO 进行通信。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件只包含了函数的声明，具体的实现代码位于 Bionic 库的 C 源代码文件中（通常是 `.c` 文件）。因此，我们无法直接从这个头文件了解每个函数的具体实现细节。

但我们可以推测其大致实现思路：

* **`stat()`, `fstat()`, `lstat()`, `fstatat()`:** 这些函数会发起一个系统调用 (syscall)，将文件路径或文件描述符传递给内核。内核会访问文件系统的元数据，并将结果填充到提供的 `stat` 结构体中。`lstat()` 的特殊之处在于，如果目标是符号链接，它返回符号链接自身的状态，而不是它指向的文件。`fstatat()` 允许相对于一个目录文件描述符来操作路径。

* **`chmod()`, `fchmod()`, `fchmodat()`, `lchmod()`:** 这些函数也会发起系统调用，通知内核修改指定文件的权限位。内核会检查调用进程的权限，然后更新文件系统中的元数据。`lchmod()` 用于修改符号链接自身的权限。

* **`mkdir()`, `mkdirat()`:**  发起系统调用，请求内核创建一个新的目录。内核会在文件系统中分配新的 inode 并设置目录的元数据。`mkdirat()` 允许相对于一个目录文件描述符创建目录。

* **`mknod()`, `mknodat()`:** 发起系统调用，请求内核创建一个新的特殊文件（字符设备、块设备等）。需要指定设备类型和主/次设备号。

* **`umask()`:** 是一个比较特殊的函数，它通常直接在 libc 中实现，或者通过一个轻量级的系统调用来完成。它设置进程的文件创建掩码，这个掩码会影响新创建文件的默认权限。

* **`mkfifo()`, `mkfifoat()`:** 发起系统调用，请求内核创建一个新的 FIFO 文件。

* **`utimensat()`, `futimens()`:** 发起系统调用，请求内核修改文件的访问时间和修改时间。可以设置为特定时间、当前时间 (`UTIME_NOW`) 或保持不变 (`UTIME_OMIT`)。

* **`statx()`:**  是一个更高级的文件状态查询函数，可以获取更详细的元数据，也通过系统调用实现。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `sys/stat.h` 本身不直接涉及 dynamic linker 的代码，但其中声明的函数（例如 `stat()`, `chmod()` 等）都位于 `libc.so` 动态链接库中。当一个可执行文件或共享库调用这些函数时，dynamic linker 负责在运行时将这些函数链接到调用者的地址空间。

**so 布局样本 (`libc.so` 的部分片段):**

```assembly
.text:00010000 T _start           ; 入口点
.text:00010020 T __libc_init
.text:00010100 T stat             ; stat() 函数的实现代码
.text:00010200 T chmod            ; chmod() 函数的实现代码
...
.got:000A0000 D __stack_chk_guard  ; 全局偏移表 (GOT) 条目
.got:000A0008 D stderr
...
.plt:000B0000 jmp *[GOT + stat]   ; 程序链接表 (PLT) 条目，用于调用 stat()
.plt:000B0006 jmp *[GOT + chmod]  ; 程序链接表 (PLT) 条目，用于调用 chmod()
...
```

**链接的处理过程:**

1. **编译时:** 当编译器编译调用 `stat()` 或 `chmod()` 的代码时，它会生成对这些函数的外部引用。在目标文件 (`.o`) 中，这些调用会指向 PLT (Procedure Linkage Table) 中的条目。

2. **链接时:** 静态链接器将多个目标文件链接成一个可执行文件或共享库。对于动态链接的库 (`libc.so` 就是一个)，链接器会在 PLT 中生成跳转指令，并更新 GOT (Global Offset Table) 中的初始值。在 `libc.so` 加载到内存之前，GOT 中的值通常是占位符。

3. **运行时 (Dynamic Linking):** 当程序启动时，dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 会负责加载所有需要的共享库，包括 `libc.so`。

4. **首次调用 (Lazy Binding):** 默认情况下，链接是延迟绑定的。当程序第一次调用 `stat()` 时：
    * 执行流到达 PLT 中的 `jmp *[GOT + stat]` 指令。
    * GOT 中 `stat` 对应的条目仍然包含一个指向 PLT 中另一段代码的地址。
    * PLT 中的这段代码会调用 dynamic linker 的解析函数 (`_dl_runtime_resolve` 或类似的功能)。
    * dynamic linker 会查找 `libc.so` 中 `stat()` 函数的实际地址。
    * dynamic linker 将 `stat()` 的实际地址写入到 GOT 中 `stat` 对应的条目。
    * dynamic linker 将控制权转移到 `stat()` 函数。

5. **后续调用:**  当程序后续再次调用 `stat()` 时：
    * 执行流到达 PLT 中的 `jmp *[GOT + stat]` 指令。
    * 这次，GOT 中 `stat` 对应的条目已经包含了 `stat()` 函数的真实地址。
    * 程序会直接跳转到 `stat()` 函数的实现代码。

**如果做了逻辑推理，请给出假设输入与输出:**

以 `chmod()` 函数为例：

**假设输入:**

* `__path`: "/sdcard/test.txt" (假设存在此文件)
* `__mode`: `S_IRUSR | S_IWUSR` (用户读写权限)

**逻辑推理:**

`chmod()` 函数会尝试修改 `/sdcard/test.txt` 文件的权限，使其只有文件所有者拥有读写权限。

**预期输出:**

* **成功:** 返回 0。可以通过 `stat("/sdcard/test.txt", &buf)` 查看修改后的权限位。
* **失败:** 返回 -1，并设置 `errno` (例如，如果调用进程没有足够的权限修改该文件，或者文件不存在)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **权限不足:** 尝试修改没有权限修改的文件的权限。
    ```c
    chmod("/system/app/SomeApp.apk", 0777); // 可能会失败，因为普通应用没有权限修改 /system 目录下的文件
    ```
    **错误现象:** `chmod()` 返回 -1，`errno` 可能被设置为 `EPERM` (Operation not permitted)。

* **路径错误:**  传递了不存在的文件路径。
    ```c
    chmod("/nonexistent_file.txt", 0777);
    ```
    **错误现象:** `chmod()` 返回 -1，`errno` 可能被设置为 `ENOENT` (No such file or directory)。

* **错误的权限模式:**  使用了无效的 `mode_t` 值。虽然通常 `mode_t` 是一个位掩码，但某些组合可能没有意义。

* **忘记检查返回值:** 没有检查 `chmod()` 等函数的返回值，导致错误发生时无法及时处理。

* **混淆 `stat()` 和 `lstat()`:**  在需要处理符号链接时使用了错误的函数。`stat()` 会跟随符号链接，而 `lstat()` 返回符号链接自身的状态。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `stat()` 的路径示例:**

假设一个 Java 应用想要检查某个文件是否存在，它可能会使用 `java.io.File.exists()` 方法。

1. **Java 代码:**
   ```java
   File file = new File("/sdcard/myfile.txt");
   boolean exists = file.exists();
   ```

2. **Framework 层:** `java.io.File.exists()` 方法最终会调用到 native 方法 `isFile()` 或 `isDirectory()`，这些方法在 `libjavacrypto.so` 或 `libopenjdk.so` 等库中实现。

3. **JNI 调用:** Native 方法会通过 JNI 调用到 Bionic 库中的函数。例如，`isFile()` 可能会调用 `sys/system_properties.h` 中定义的函数来检查文件类型，或者直接调用与文件状态相关的系统调用。更直接地，`exists()` 的实现通常会调用底层的 `access()` 系统调用，而 `access()` 的实现最终可能会使用 `stat()` 来检查文件的存在性和权限。

4. **Bionic Libc:**  Bionic Libc 中的 `access()` 函数（或其他相关函数）会发起 `stat()` 系统调用。

5. **内核:** Linux 内核接收到 `stat()` 系统调用，访问文件系统，获取文件元数据，并将结果返回给 Bionic Libc。

6. **返回 Framework:** Bionic Libc 将结果返回给 Framework 的 native 方法。

7. **返回 Java:** Framework 将结果返回给 Java 代码。

**NDK 到 `stat()` 的路径示例:**

一个使用 NDK 开发的 C/C++ 应用可以直接调用 `stat()` 函数。

1. **NDK 代码:**
   ```c++
   #include <sys/stat.h>
   #include <unistd.h>
   #include <stdio.h>

   int main() {
       struct stat st;
       if (stat("/sdcard/mynativefile.txt", &st) == 0) {
           printf("File exists and size is %lld\n", st.st_size);
       } else {
           perror("stat failed");
       }
       return 0;
   }
   ```

2. **编译和链接:** NDK 工具链会将这段 C++ 代码编译成机器码，并链接到 Bionic Libc。

3. **执行:** 当应用运行时，调用 `stat()` 时，会直接跳转到 Bionic Libc 中 `stat()` 的实现。

4. **Bionic Libc 和内核:**  与 Framework 类似，Bionic Libc 中的 `stat()` 会发起系统调用与内核交互。

**Frida Hook 示例调试步骤:**

可以使用 Frida 来 Hook `stat()` 函数，查看其被调用的情况和参数。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const stat = Module.findExportByName("libc.so", "stat");
  if (stat) {
    Interceptor.attach(stat, {
      onEnter: function (args) {
        const path = Memory.readUtf8String(args[0]);
        console.log(`[stat] Calling stat with path: ${path}`);
      },
      onLeave: function (retval) {
        console.log(`[stat] stat returned: ${retval}`);
      }
    });
    console.log("Hooked stat in libc.so");
  } else {
    console.log("Could not find stat in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**调试步骤:**

1. **准备:** 确保你的 Android 设备已 root，并安装了 Frida 服务端 (`frida-server`)。
2. **运行目标应用:** 启动你想要分析的 Android 应用。
3. **运行 Frida 脚本:** 使用 Frida 命令行工具将脚本附加到目标应用：
   ```bash
   frida -U -f <your_app_package_name> -l your_script.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l your_script.js
   ```
4. **操作应用:** 在你的 Android 应用中执行可能触发 `stat()` 调用的操作，例如访问文件、检查文件是否存在等。
5. **查看 Frida 输出:** Frida 会在控制台中打印出 `stat()` 函数被调用时的路径参数和返回值，帮助你理解哪些操作触发了文件状态查询。

**更详细的 Hook 示例 (包括参数和 `stat` 结构体内容):**

```javascript
if (Process.platform === 'android') {
  const statPtr = Module.findExportByName("libc.so", "stat");
  if (statPtr) {
    const statFunc = new NativeFunction(statPtr, 'int', ['pointer', 'pointer']);

    Interceptor.attach(statPtr, {
      onEnter: function (args) {
        this.path = Memory.readUtf8String(args[0]);
        this.statBuf = args[1];
        console.log(`[stat] Calling stat with path: ${this.path}`);
      },
      onLeave: function (retval) {
        console.log(`[stat] stat returned: ${retval}`);
        if (retval === 0) {
          const statData = {};
          // 根据架构读取 stat 结构体的内容，这里以一种常见的布局为例
          statData.st_dev = this.statBuf.readU64();
          statData.st_ino = this.statBuf.add(8).readU64();
          statData.st_mode = this.statBuf.add(16).readU32();
          statData.st_nlink = this.statBuf.add(20).readU32();
          statData.st_uid = this.statBuf.add(24).readU32();
          statData.st_gid = this.statBuf.add(28).readU32();
          statData.st_rdev = this.statBuf.add(32).readU64();
          statData.st_size = this.statBuf.add(40).readS64();
          // ... 读取更多字段
          console.log("[stat] stat struct:", statData);
        }
      }
    });
    console.log("Hooked stat in libc.so");
  } else {
    console.log("Could not find stat in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**注意:** 读取 `stat` 结构体的字段需要根据目标 Android 设备的架构 (`arm`, `arm64`, `x86`, `x86_64`) 和 Bionic 库的具体实现来确定偏移量和类型。你可能需要参考 `sys/stat.h` 中 `struct stat` 的定义来准确读取结构体内容.

Prompt: 
```
这是目录为bionic/libc/include/sys/stat.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file sys/stat.h
 * @brief File status.
 */

#include <sys/cdefs.h>

#include <bits/timespec.h>
#include <linux/stat.h>
#include <sys/types.h>

__BEGIN_DECLS

#if defined(__aarch64__) || defined(__riscv)
#define __STAT64_BODY \
  dev_t st_dev; \
  ino_t st_ino; \
  mode_t st_mode; \
  nlink_t st_nlink; \
  uid_t st_uid; \
  gid_t st_gid; \
  dev_t st_rdev; \
  unsigned long __pad1; \
  off_t st_size; \
  int st_blksize; \
  int __pad2; \
  long st_blocks; \
  struct timespec st_atim; \
  struct timespec st_mtim; \
  struct timespec st_ctim; \
  unsigned int __unused4; \
  unsigned int __unused5; \

#elif defined(__x86_64__)
#define __STAT64_BODY \
  dev_t st_dev; \
  ino_t st_ino; \
  unsigned long st_nlink; \
  mode_t st_mode; \
  uid_t st_uid; \
  gid_t st_gid; \
  unsigned int __pad0; \
  dev_t st_rdev; \
  off_t st_size; \
  long st_blksize; \
  long st_blocks; \
  struct timespec st_atim; \
  struct timespec st_mtim; \
  struct timespec st_ctim; \
  long __pad3[3]; \

#else /* __arm__ || __i386__ */
#define __STAT64_BODY \
  unsigned long long st_dev; \
  unsigned char __pad0[4]; \
  unsigned long __st_ino; \
  unsigned int st_mode; \
  nlink_t st_nlink; \
  uid_t st_uid; \
  gid_t st_gid; \
  unsigned long long st_rdev; \
  unsigned char __pad3[4]; \
  long long st_size; \
  unsigned long st_blksize; \
  unsigned long long st_blocks; \
  struct timespec st_atim; \
  struct timespec st_mtim; \
  struct timespec st_ctim; \
  unsigned long long st_ino; \

#endif

/** The file information returned by fstat()/fstatat()/lstat()/stat(). */
struct stat { __STAT64_BODY };

/**
 * A synonym for `struct stat` on Android,
 * provided for source compatibility with other systems.
 */
struct stat64 { __STAT64_BODY };

#undef __STAT64_BODY

/* Compatibility with older versions of POSIX. */
#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec
/* Compatibility with glibc. */
#define st_atimensec st_atim.tv_nsec
#define st_mtimensec st_mtim.tv_nsec
#define st_ctimensec st_ctim.tv_nsec
/* Compatibility with Linux headers and old NDKs. */
#define st_atime_nsec st_atim.tv_nsec
#define st_mtime_nsec st_mtim.tv_nsec
#define st_ctime_nsec st_ctim.tv_nsec

#if defined(__USE_BSD)
/* Permission macros provided by glibc for compatibility with BSDs. */
#define ACCESSPERMS (S_IRWXU | S_IRWXG | S_IRWXO) /* 0777 */
#define ALLPERMS    (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO) /* 07777 */
#define DEFFILEMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) /* 0666 */
#endif

#if defined(__USE_BSD) || defined(__USE_GNU)
#define S_IREAD S_IRUSR
#define S_IWRITE S_IWUSR
#define S_IEXEC S_IXUSR
#endif

/* POSIX mandates these, but Linux doesn't implement them as distinct file types. */
#define S_TYPEISMQ(__sb) 0
#define S_TYPEISSEM(__sb) 0
#define S_TYPEISSHM(__sb) 0
#define S_TYPEISTMO(__sb) 0

/**
 * [chmod(2)](https://man7.org/linux/man-pages/man2/chmod.2.html)
 * changes the mode of a file given a path.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int chmod(const char* _Nonnull __path, mode_t __mode);

/**
 * [fchmod(2)](https://man7.org/linux/man-pages/man2/fchmod.2.html)
 * changes the mode of a file given a file descriptor.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int fchmod(int __fd, mode_t __mode);

/**
 * [fchmodat(2)](https://man7.org/linux/man-pages/man2/fchmodat.2.html)
 * changes the mode of a file.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int fchmodat(int __dir_fd, const char* _Nonnull __path, mode_t __mode, int __flags);

/**
 * [chmod(2)](https://man7.org/linux/man-pages/man2/chmod.2.html)
 * changes the mode of a file given a path, without following symlinks.
 *
 * Equivalent to `fchmodat(AT_FDCWD, path, mode, AT_SYMLINK_NOFOLLOW)`.
 *
 * Available since API 36.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(36)
int lchmod(const char* _Nonnull __path, mode_t __mode) __INTRODUCED_IN(36);
#endif /* __BIONIC_AVAILABILITY_GUARD(36) */


/**
 * [mkdir(2)](https://man7.org/linux/man-pages/man2/mkdir.2.html)
 * creates a directory.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int mkdir(const char* _Nonnull __path, mode_t __mode);

/**
 * [mkdirat(2)](https://man7.org/linux/man-pages/man2/mkdirat.2.html)
 * creates a directory.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int mkdirat(int __dir_fd, const char* _Nonnull __path, mode_t __mode);

/**
 * [fstat(2)](https://man7.org/linux/man-pages/man2/fstat.2.html)
 * gets file status given a file descriptor.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int fstat(int __fd, struct stat* _Nonnull __buf);

/** An alias for fstat(). */
int fstat64(int __fd, struct stat64* _Nonnull __buf);

/**
 * [fstatat(2)](https://man7.org/linux/man-pages/man2/fstatat.2.html)
 * gets file status.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int fstatat(int __dir_fd, const char* _Nonnull __path, struct stat* _Nonnull __buf, int __flags);

/** An alias for fstatat(). */
int fstatat64(int __dir_fd, const char* _Nonnull __path, struct stat64* _Nonnull __buf, int __flags);

/**
 * [lstat(2)](https://man7.org/linux/man-pages/man2/lstat.2.html)
 * gets file status given a path, without following symlinks.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int lstat(const char* _Nonnull __path, struct stat* _Nonnull __buf);

/** An alias for lstat(). */
int lstat64(const char* _Nonnull __path, struct stat64* _Nonnull __buf);

/**
 * [stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html)
 * gets file status given a path.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int stat(const char* _Nonnull __path, struct stat* _Nonnull __buf);

/** An alias for stat(). */
int stat64(const char* _Nonnull __path, struct stat64* _Nonnull __buf);

/**
 * [mknod(2)](https://man7.org/linux/man-pages/man2/mknod.2.html)
 * creates a directory, special, or regular file.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int mknod(const char* _Nonnull __path, mode_t __mode, dev_t __dev);

/**
 * [mknodat(2)](https://man7.org/linux/man-pages/man2/mknodat.2.html)
 * creates a directory, special, or regular file.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int mknodat(int __dir_fd, const char* _Nonnull __path, mode_t __mode, dev_t __dev);

/**
 * [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * gets and sets the process-wide file mode creation mask.
 *
 * Returns the previous file mode creation mask.
 */
mode_t umask(mode_t __mask);

#if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
#include <bits/fortify/stat.h>
#endif

/**
 * [mkfifo(2)](https://man7.org/linux/man-pages/man2/mkfifo.2.html)
 * creates a FIFO.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int mkfifo(const char* _Nonnull __path, mode_t __mode);

/**
 * [mkfifoat(2)](https://man7.org/linux/man-pages/man2/mkfifoat.2.html)
 * creates a FIFO.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(23)
int mkfifoat(int __dir_fd, const char* _Nonnull __path, mode_t __mode) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


/**
 * Used in the tv_nsec field of an argument to utimensat()/futimens()
 * to set that time to the current time.
 */
#define UTIME_NOW  ((1L << 30) - 1L)

/**
 * Used in the tv_nsec field of an argument to utimensat()/futimens()
 * to _not_ set that time.
 */
#define UTIME_OMIT ((1L << 30) - 2L)

/**
 * [utimensat(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html) sets
 * file timestamps.
 *
 * Note: Linux supports `__path` being NULL (in which case `__dir_fd` need not
 * be a directory), allowing futimens() to be implemented with utimensat().
 * For normal use of utimensat(), though, `__path` should be non-null.
 *
 * `__times[0]` is the access time (atime), and `__times[1]` the last modification time (mtime).
 * If `__times` is NULL, both times are set to the current time.
 * See also UTIME_NOW and UTIME_OMIT.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int utimensat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, const struct timespec __times[_Nullable 2], int __flags);

/**
 * [futimens(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html) sets
 * the given file descriptor's timestamp.
 *
 * `__times[0]` is the access time (atime), and `__times[1]` the last modification time (mtime).
 * If `__times` is NULL, both times are set to the current time.
 * See also UTIME_NOW and UTIME_OMIT.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int futimens(int __fd, const struct timespec __times[_Nullable 2]);

#if defined(__USE_GNU)
/**
 * [statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html) returns
 * extended file status information.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 *
 * Available since API level 30.
 */

#if __BIONIC_AVAILABILITY_GUARD(30)
int statx(int __dir_fd, const char* _Nullable __path, int __flags, unsigned __mask, struct statx* _Nonnull __buf) __INTRODUCED_IN(30);
#endif /* __BIONIC_AVAILABILITY_GUARD(30) */

#endif

__END_DECLS

"""

```
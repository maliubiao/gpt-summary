Response:
Let's break down the thought process for analyzing the provided C header file for extended attributes in Android's Bionic library.

**1. Initial Understanding and Goal:**

The primary goal is to understand the functionality of the `sys/xattr.h` header file within the context of Android's Bionic library. This involves listing the functions, explaining their purpose, relating them to Android, detailing their implementation (to the extent possible from the header), and addressing dynamic linking, usage errors, and interaction with the Android framework.

**2. Deconstructing the Header File:**

The first step is to systematically go through each function declaration in the header file. For each function, the key information to extract is:

* **Name:**  The function's name (e.g., `fsetxattr`, `getxattr`).
* **Purpose:** The comment directly above the function usually provides a concise explanation. The man page links are invaluable here.
* **Parameters:**  The types and names of the arguments. Pay attention to `__fd`, `__path`, `__name`, `__value`, `__size`, and `__flags`.
* **Return Value:**  Indicates success or failure, often returning 0 for success or -1 for error, setting `errno`. Note the distinction for the `getxattr` family, which returns the size of the attribute.
* **Special Cases:**  The comments mention the behavior when `size` is 0.
* **Flags:**  The comments mention `XATTR_CREATE` and `XATTR_REPLACE`.

**3. Identifying Core Functionality:**

After going through each function, we can group them by their action:

* **Setting Attributes:** `fsetxattr`, `setxattr`, `lsetxattr`
* **Getting Attributes:** `fgetxattr`, `getxattr`, `lgetxattr`
* **Listing Attributes:** `flistxattr`, `listxattr`, `llistxattr`
* **Removing Attributes:** `fremovexattr`, `removexattr`, `lremovexattr`

The prefixes `f`, `l`, and the lack of a prefix indicate the target of the operation: file descriptor, symbolic link, and file path, respectively.

**4. Connecting to Android Functionality:**

This is where domain knowledge about Android is crucial. The core concept of extended attributes is general to Linux, but Android uses them in specific ways. The prompt explicitly asks for examples. Thinking about Android features that involve metadata leads to possibilities like:

* **Security:** SELinux tags are a primary example.
* **App Installation:**  Information about the installer or package source.
* **File Management:**  Tags or metadata used by file manager apps.
* **Cloud Synchronization:**  Metadata related to syncing status.

For each example, it's important to explain *why* extended attributes are suitable. They allow storing metadata *outside* the main file content, avoiding modification of the core file.

**5. Explaining Implementation Details (Within Header Constraints):**

The header file itself doesn't contain the *implementation*. It's just the interface. Therefore, the explanation of implementation must focus on:

* **System Calls:**  The comments point to the underlying Linux system calls (e.g., `fsetxattr(2)`). The Bionic library acts as a wrapper around these system calls.
* **Parameter Passing:**  Briefly describe how the function parameters map to the information needed by the kernel.
* **Error Handling:** Mention the role of `errno`.

It's important *not* to invent implementation details that aren't evident from the header.

**6. Addressing Dynamic Linking:**

The header file *doesn't* directly involve dynamic linking. However, the functions it declares are part of `libc.so`, which *is* a dynamically linked library. Therefore, the explanation needs to cover:

* **`libc.so` as the container:**  State that these functions reside in `libc.so`.
* **SO Layout:** Provide a simple example of how `libc.so` might be organized, including sections like `.text`, `.data`, `.bss`, `.dynsym`, `.dynstr`, `.plt`, and `.got`.
* **Linking Process:** Briefly describe how the dynamic linker resolves symbols at runtime using the `.plt` and `.got`.

**7. Considering Logical Reasoning and Input/Output:**

For each function, consider a simple use case and what the expected input and output would be. This helps solidify understanding. For example, setting an attribute, then getting it, and then listing it.

**8. Identifying Common Usage Errors:**

Think about how a programmer might misuse these functions. Common mistakes include:

* **Incorrect buffer sizes:**  Not allocating enough space when getting or listing attributes.
* **Invalid attribute names:** Using names that don't conform to conventions or are disallowed.
* **Permission issues:**  Not having the necessary permissions to set or remove attributes.
* **Incorrect flags:**  Using `XATTR_CREATE` or `XATTR_REPLACE` inappropriately.

**9. Tracing Android Framework/NDK Interaction:**

This requires understanding how higher-level Android components use lower-level libraries. The typical flow involves:

* **Java Framework:**  Android framework APIs (often in `java.io` or related packages) might have underlying native implementations.
* **JNI:** Java Native Interface is used to bridge the Java and native worlds.
* **NDK:** The Native Development Kit allows developers to write C/C++ code that interacts with the platform.
* **Bionic:** The NDK-compiled code will eventually call functions within Bionic, including the xattr functions.
* **Kernel:** Bionic functions make system calls to the Linux kernel.

Illustrative examples are helpful here, such as how `PackageManager` might use xattrs during app installation.

**10. Providing Frida Hook Examples:**

Frida is a powerful dynamic instrumentation tool. Demonstrate how to hook the xattr functions using JavaScript. The hook should intercept the function calls, log arguments, and potentially modify behavior. Provide examples for both setting and getting attributes.

**11. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use bullet points or numbered lists for clarity. Maintain a consistent and professional tone.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the implementation details within Bionic.**  The header file only provides the interface. The implementation resides in the corresponding `.c` files, which aren't provided. Adjust the focus accordingly.
* **I might need to refine the Android examples.** Make sure the examples are realistic and demonstrate a clear connection to extended attributes.
* **Ensure the Frida hook examples are correct and runnable.** Double-check the syntax and ensure they target the correct function names.

By following these steps, the detailed and comprehensive analysis of the `sys/xattr.h` header file can be generated, addressing all aspects of the prompt.
这个文件 `bionic/libc/include/sys/xattr.h` 定义了用于操作扩展属性 (extended attributes，简称 xattrs) 的 C 接口。扩展属性是一种文件系统的特性，允许用户和内核附加元数据到文件和目录上，而无需修改文件的数据部分。

**它的功能:**

这个头文件定义了一系列函数，用于：

1. **设置扩展属性:**
   - `fsetxattr()`: 基于文件描述符设置扩展属性。
   - `setxattr()`: 基于文件路径设置扩展属性。
   - `lsetxattr()`: 基于文件路径设置扩展属性，但针对符号链接本身而不是其指向的目标。

2. **获取扩展属性:**
   - `fgetxattr()`: 基于文件描述符获取扩展属性的值。
   - `getxattr()`: 基于文件路径获取扩展属性的值。
   - `lgetxattr()`: 基于文件路径获取扩展属性的值，但针对符号链接本身。

3. **列出扩展属性:**
   - `flistxattr()`: 基于文件描述符列出扩展属性的名称。
   - `listxattr()`: 基于文件路径列出扩展属性的名称。
   - `llistxattr()`: 基于文件路径列出扩展属性的名称，但针对符号链接本身。

4. **移除扩展属性:**
   - `fremovexattr()`: 基于文件描述符移除扩展属性。
   - `removexattr()`: 基于文件路径移除扩展属性。
   - `lremovexattr()`: 基于文件路径移除扩展属性，但针对符号链接本身。

**与 Android 功能的关系及举例说明:**

扩展属性在 Android 系统中被广泛使用，用于存储各种与文件相关的元数据。以下是一些例子：

* **安全 (SELinux):** SELinux (Security-Enhanced Linux) 使用扩展属性来存储安全上下文，例如文件的类型和进程的角色。这是 Android 安全模型的基础。例如，当一个应用尝试访问某个文件时，内核会检查该文件的 SELinux 扩展属性，以及运行应用的进程的安全上下文，以决定是否允许访问。
* **应用程序安装:**  Android 的包管理器 (PackageManager) 可能会使用扩展属性来存储有关已安装应用程序的信息，例如安装来源或签名信息。
* **备份和恢复:** 某些备份和恢复工具可能会使用扩展属性来存储文件的额外元数据，以便在恢复时保留这些信息。
* **文件管理器:** 文件管理器应用可能会使用扩展属性来存储用户定义的标签或注释。
* **存储设备标识:** Android 可能使用扩展属性来标记特定存储设备或分区的属性。

**举例说明 (SELinux):**

假设有一个文件 `/data/local/tmp/myfile.txt`，其 SELinux 安全上下文可能存储在名为 `security.selinux` 的扩展属性中。 当一个应用程序试图读取这个文件时，内核会执行以下操作：

1. 获取运行该应用程序的进程的安全上下文。
2. 使用 `getxattr("/data/local/tmp/myfile.txt", "security.selinux", ...)` 获取文件的安全上下文。
3. 将进程的安全上下文与文件的安全上下文进行比较，根据 SELinux 策略决定是否允许访问。

**每一个 libc 函数的功能是如何实现的:**

这些函数是 Bionic libc 提供的系统调用包装器。 它们最终会调用 Linux 内核提供的相应的系统调用 (如 `setxattr(2)`, `getxattr(2)` 等)。

* **`fsetxattr`, `setxattr`, `lsetxattr`:** 这些函数接收文件描述符或路径、属性名称、属性值、属性值大小和标志作为参数。 它们将这些参数传递给内核的 `setxattr` 系统调用。内核负责在文件系统的 inode 中存储扩展属性。`XATTR_CREATE` 标志表示如果属性不存在则创建，如果存在则失败。`XATTR_REPLACE` 标志表示如果属性存在则替换，如果不存在则失败。

* **`fgetxattr`, `getxattr`, `lgetxattr`:** 这些函数接收文件描述符或路径、属性名称以及用于存储属性值的缓冲区和缓冲区大小。 它们调用内核的 `getxattr` 系统调用。内核会查找指定文件的扩展属性，并将值复制到提供的缓冲区中。如果提供的缓冲区太小，`getxattr` 会返回实际所需的大小，应用程序可以重新分配更大的缓冲区并再次调用。如果 `size` 为 0，则函数返回属性的当前长度而不实际读取属性值。

* **`flistxattr`, `listxattr`, `llistxattr`:** 这些函数接收文件描述符或路径以及用于存储属性名称列表的缓冲区和缓冲区大小。 它们调用内核的 `listxattr` 系统调用。内核会返回一个以 null 结尾的属性名称列表。如果 `size` 为 0，则函数返回存储所有属性名称所需的总大小。

* **`fremovexattr`, `removexattr`, `lremovexattr`:** 这些函数接收文件描述符或路径以及要删除的属性名称。 它们调用内核的 `removexattr` 系统调用，内核负责从文件系统的 inode 中删除指定的扩展属性。

**涉及 dynamic linker 的功能:**

这个头文件本身并不直接涉及 dynamic linker 的功能。 这些 `xattr` 函数是 Bionic libc 的一部分，而 libc 是一个共享库 (`libc.so`)，会被 dynamic linker 加载和链接。

**SO 布局样本 (libc.so):**

```
libc.so:
    .text          # 包含函数的可执行代码 (例如 fsetxattr, getxattr 的实现)
    .rodata        # 只读数据，例如字符串常量
    .data          # 可读写的数据
    .bss           # 未初始化的静态数据
    .dynsym        # 动态符号表，包含导出的和导入的符号
    .dynstr        # 动态字符串表，包含符号名称
    .plt           # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
    .got           # 全局偏移表 (Global Offset Table)，用于存储全局变量和函数地址
```

**链接的处理过程:**

当一个应用程序或共享库调用 `fsetxattr` 等函数时，链接过程如下：

1. **编译时:** 编译器遇到对 `fsetxattr` 的调用，生成一个指向 `.plt` 中 `fsetxattr` 条目的指令。
2. **加载时:** dynamic linker (在 Android 上通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会加载应用程序和其依赖的共享库 (包括 `libc.so`)。
3. **符号解析:**  dynamic linker 会解析应用程序中对 `fsetxattr` 的引用。它会在 `libc.so` 的 `.dynsym` 表中查找 `fsetxattr` 的定义。
4. **GOT 和 PLT 的使用:**
   - 初始时，`.got` 中 `fsetxattr` 的条目指向 `.plt` 中对应的代码。
   - 当第一次调用 `fsetxattr` 时，执行 `.plt` 中的代码。这部分代码会将控制权转移给 dynamic linker。
   - dynamic linker 找到 `fsetxattr` 在 `libc.so` 中的实际地址。
   - dynamic linker 将 `fsetxattr` 的实际地址更新到 `.got` 中对应的条目。
   - dynamic linker 将控制权转移到 `fsetxattr` 的实际代码。
   - 后续对 `fsetxattr` 的调用会直接通过 `.got` 跳转到其在 `libc.so` 中的实际地址，而无需再次调用 dynamic linker。这就是延迟绑定的过程。

**假设输入与输出 (逻辑推理):**

**`setxattr()` 示例:**

**假设输入:**
- `__path`: "/tmp/testfile.txt"
- `__name`: "user.my_custom_attribute"
- `__value`: "my_attribute_value"
- `__size`: 18 (strlen("my_attribute_value"))
- `__flags`: 0

**预期输出:**
- 返回值: 0 (成功)
- 文件 "/tmp/testfile.txt" 将会有一个名为 "user.my_custom_attribute" 的扩展属性，其值为 "my_attribute_value"。

**`getxattr()` 示例:**

**假设输入:**
- `__path`: "/tmp/testfile.txt"
- `__name`: "user.my_custom_attribute"
- `__value`: 一个足够大的缓冲区 (例如 `char buffer[100]`)
- `__size`: 100

**预期输出:**
- 返回值: 18 (属性值的实际大小)
- `buffer` 的内容将会是 "my_attribute_value"。

**常见的使用错误举例说明:**

1. **缓冲区太小:**  在使用 `getxattr` 或 `listxattr` 时，如果提供的缓冲区 `__size` 小于实际的属性值或属性名列表的大小，函数会返回 -1 并设置 `errno` 为 `ERANGE`。

   ```c
   char buffer[10];
   ssize_t size = getxattr("/tmp/testfile.txt", "user.my_custom_attribute", buffer, sizeof(buffer));
   if (size == -1 && errno == ERANGE) {
       // 缓冲区太小，需要重新分配更大的缓冲区
   }
   ```

2. **无效的属性名称:** 尝试设置或获取不存在的属性名称，或者使用了格式不正确的属性名称。属性名称通常有命名空间，例如 `user.`, `trusted.`, `security.` 等。尝试访问不属于你的命名空间的属性可能会失败并返回 `EPERM` (Operation not permitted)。

   ```c
   // 假设 "invalid_attribute_name" 不存在
   ssize_t size = getxattr("/tmp/testfile.txt", "invalid_attribute_name", buffer, sizeof(buffer));
   if (size == -1 && errno == ENOATTR) {
       // 属性不存在
   }
   ```

3. **权限问题:** 普通用户可能没有权限设置或删除某些命名空间的扩展属性 (例如 `security.` 命名空间通常只有 root 用户才能操作)。

   ```c
   // 尝试设置 security 命名空间的属性 (非 root 用户)
   int result = setxattr("/tmp/testfile.txt", "security.capability", "some_value", 10, 0);
   if (result == -1 && errno == EPERM) {
       // 没有权限
   }
   ```

4. **错误地使用 `XATTR_CREATE` 和 `XATTR_REPLACE` 标志:**
   - 如果使用 `XATTR_CREATE` 尝试设置一个已经存在的属性，`setxattr` 会失败并返回 `EEXIST`.
   - 如果使用 `XATTR_REPLACE` 尝试设置一个不存在的属性，`setxattr` 会失败并返回 `ENOATTR`.

**Android framework 或 ndk 是如何一步步的到达这里:**

1. **Android Framework (Java):**  Android Framework 中的某些 Java 类可能会调用 Native 方法 (使用 JNI)。 例如，`java.io.File` 类本身没有直接操作扩展属性的方法，但一些底层的系统服务或工具可能会使用。

2. **JNI (Java Native Interface):**  如果 Framework 需要操作扩展属性，可能会调用一个 Native 方法。这个 Native 方法通常在 C 或 C++ 代码中实现，并使用 Android NDK 进行编译。

3. **NDK 代码 (C/C++):**  在 NDK 代码中，开发者会包含 `<sys/xattr.h>` 头文件，并调用其中定义的函数 (如 `setxattr`, `getxattr` 等)。

4. **Bionic libc:**  NDK 代码链接到 Bionic libc (`libc.so`)。当 NDK 代码调用 `setxattr` 时，实际上是调用了 Bionic libc 中 `setxattr` 函数的实现。

5. **系统调用:** Bionic libc 中的 `setxattr` 函数会将参数转换为内核所需的格式，并通过系统调用 (syscall) 指令陷入内核。

6. **Linux 内核:**  Linux 内核接收到系统调用请求，执行相应的内核代码来设置文件的扩展属性。这涉及到文件系统的具体实现。

**Frida hook 示例调试这些步骤:**

以下是一个使用 Frida hook `setxattr` 函数的示例：

```javascript
// attach to the target process
Java.perform(function() {
    // Hook the setxattr function in libc
    var setxattrPtr = Module.findExportByName("libc.so", "setxattr");
    if (setxattrPtr) {
        Interceptor.attach(setxattrPtr, {
            onEnter: function(args) {
                // Log the arguments
                console.log("setxattr called");
                console.log("  path: " + Memory.readUtf8String(args[0]));
                console.log("  name: " + Memory.readUtf8String(args[1]));
                console.log("  value: " + (args[2] ? Memory.readUtf8String(args[2]) : "null"));
                console.log("  size: " + args[3].toInt());
                console.log("  flags: " + args[4].toInt());

                // You can also modify arguments here if needed
                // For example, to prevent setting a specific attribute:
                // if (Memory.readUtf8String(args[1]) === "security.selinux") {
                //     console.log("Blocking setting of security.selinux attribute");
                //     args[0] = NULL; // This would likely cause an error, but demonstrates modification
                // }
            },
            onLeave: function(retval) {
                // Log the return value
                console.log("setxattr returned: " + retval.toInt());
            }
        });
        console.log("setxattr hook installed");
    } else {
        console.log("setxattr not found in libc.so");
    }
});
```

**使用方法:**

1. **启动目标 Android 应用。**
2. **运行 Frida 脚本，将其附加到目标应用的进程。**
3. **在应用中执行可能会调用 `setxattr` 的操作 (例如，安装一个应用，修改文件属性等)。**

Frida 的控制台会输出 `setxattr` 函数被调用时的参数和返回值，帮助你了解哪些组件在操作扩展属性以及传递了哪些信息。你可以根据需要修改脚本来 hook 其他 `xattr` 函数或执行更复杂的操作，例如修改参数或返回值。

通过这种方式，你可以深入了解 Android 系统中扩展属性的使用情况，并调试相关的代码流程。

Prompt: 
```
这是目录为bionic/libc/include/sys/xattr.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2012 The Android Open Source Project
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
 * @file sys/xattr.h
 * @brief Extended attribute functions.
 */

#include <sys/cdefs.h>

#include <linux/xattr.h>
#include <sys/types.h>

__BEGIN_DECLS

/**
 * [fsetxattr(2)](https://man7.org/linux/man-pages/man2/fsetxattr.2.html)
 * sets an extended attribute on the file referred to by the given file
 * descriptor.
 *
 * A `size` of 0 can be used to set an empty value, in which case `value` is
 * ignored and may be null. Setting an xattr to an empty value is not the same
 * as removing an xattr; see removexattr() for the latter operation.
 *
 * Valid flags are `XATTR_CREATE` and `XATTR_REPLACE`.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int fsetxattr(int __fd, const char* _Nonnull __name, const void* _Nullable __value, size_t __size, int __flags);

/**
 * [setxattr(2)](https://man7.org/linux/man-pages/man2/setxattr.2.html)
 * sets an extended attribute on the file referred to by the given path.
 *
 * A `size` of 0 can be used to set an empty value, in which case `value` is
 * ignored and may be null. Setting an xattr to an empty value is not the same
 * as removing an xattr; see removexattr() for the latter operation.
 *
 * Valid flags are `XATTR_CREATE` and `XATTR_REPLACE`.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int setxattr(const char* _Nonnull __path, const char* _Nonnull __name, const void* _Nullable __value, size_t __size, int __flags);

/**
 * [lsetxattr(2)](https://man7.org/linux/man-pages/man2/lsetxattr.2.html)
 * sets an extended attribute on the file referred to by the given path, which
 * is the link itself rather than its target in the case of a symbolic link.
 *
 * A `size` of 0 can be used to set an empty value, in which case `value` is
 * ignored and may be null. Setting an xattr to an empty value is not the same
 * as removing an xattr; see removexattr() for the latter operation.
 *
 * Valid flags are `XATTR_CREATE` and `XATTR_REPLACE`.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int lsetxattr(const char* _Nonnull __path, const char* _Nonnull __name, const void* _Nullable __value, size_t __size, int __flags);

/**
 * [fgetxattr(2)](https://man7.org/linux/man-pages/man2/fgetxattr.2.html)
 * gets an extended attribute on the file referred to by the given file
 * descriptor.
 *
 * A `size` of 0 can be used to query the current length, in which case `value` is ignored and may be null.
 *
 * Returns the non-negative length of the value on success, or
 * returns -1 and sets `errno` on failure.
 */
ssize_t fgetxattr(int __fd, const char* _Nonnull __name, void* _Nullable __value, size_t __size);

/**
 * [getxattr(2)](https://man7.org/linux/man-pages/man2/getxattr.2.html)
 * gets an extended attribute on the file referred to by the given path.
 *
 * A `size` of 0 can be used to query the current length, in which case `value` is ignored and may be null.
 *
 * Returns the non-negative length of the value on success, or
 * returns -1 and sets `errno` on failure.
 */
ssize_t getxattr(const char* _Nonnull __path, const char* _Nonnull __name, void* _Nullable __value, size_t __size);

/**
 * [lgetxattr(2)](https://man7.org/linux/man-pages/man2/lgetxattr.2.html)
 * gets an extended attribute on the file referred to by the given path, which
 * is the link itself rather than its target in the case of a symbolic link.
 *
 * A `size` of 0 can be used to query the current length, in which case `value` is ignored and may be null.
 *
 * Returns the non-negative length of the value on success, or
 * returns -1 and sets `errno` on failure.
 */
ssize_t lgetxattr(const char* _Nonnull __path, const char* _Nonnull __name, void* _Nullable __value, size_t __size);

/**
 * [flistxattr(2)](https://man7.org/linux/man-pages/man2/flistxattr.2.html)
 * lists the extended attributes on the file referred to by the given file
 * descriptor.
 *
 * A `size` of 0 can be used to query the current length, in which case `list` is ignored and may be null.
 *
 * Returns the non-negative length of the list on success, or
 * returns -1 and sets `errno` on failure.
 */
ssize_t flistxattr(int __fd, char* _Nullable __list, size_t __size);

/**
 * [listxattr(2)](https://man7.org/linux/man-pages/man2/listxattr.2.html)
 * lists the extended attributes on the file referred to by the given path.
 *
 * A `size` of 0 can be used to query the current length, in which case `list` is ignored and may be null.
 *
 * Returns the non-negative length of the list on success, or
 * returns -1 and sets `errno` on failure.
 */
ssize_t listxattr(const char* _Nonnull __path, char* _Nullable __list, size_t __size);

/**
 * [llistxattr(2)](https://man7.org/linux/man-pages/man2/llistxattr.2.html)
 * lists the extended attributes on the file referred to by the given path, which
 * is the link itself rather than its target in the case of a symbolic link.
 *
 * A `size` of 0 can be used to query the current length, in which case `list` is ignored and may be null.
 *
 * Returns the non-negative length of the list on success, or
 * returns -1 and sets `errno` on failure.
 */
ssize_t llistxattr(const char* _Nonnull __path, char* _Nullable __list, size_t __size);

/**
 * [fremovexattr(2)](https://man7.org/linux/man-pages/man2/fremovexattr.2.html)
 * removes an extended attribute on the file referred to by the given file
 * descriptor.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int fremovexattr(int __fd, const char* _Nonnull __name);

/**
 * [lremovexattr(2)](https://man7.org/linux/man-pages/man2/lremovexattr.2.html)
 * removes an extended attribute on the file referred to by the given path, which
 * is the link itself rather than its target in the case of a symbolic link.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int lremovexattr(const char* _Nonnull __path, const char* _Nonnull __name);

/**
 * [removexattr(2)](https://man7.org/linux/man-pages/man2/removexattr.2.html)
 * removes an extended attribute on the file referred to by the given path.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int removexattr(const char* _Nonnull __path, const char* _Nonnull __name);

__END_DECLS

"""

```
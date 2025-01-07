Response:
Let's break down the thought process for answering the user's request about `bionic/libc/include/grp.handroid`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `grp.handroid` header file in Android's Bionic library. They're particularly interested in its relationship to Android, the implementation details of the C library functions it declares, any dynamic linker aspects, potential usage errors, and how these functions are reached from higher levels of Android. They also want Frida hooking examples.

**2. Initial Analysis of the Header File:**

* **Copyright:**  Recognize the BSD-style license, indicating it's likely based on standard Unix functionality.
* **`#ifndef _GRP_H_`:** This is a standard include guard, preventing multiple inclusions.
* **`#include <sys/cdefs.h>` and `#include <sys/types.h>`:** These includes suggest the file defines system-level structures and types.
* **`struct group`:** This is the central data structure. Note the fields: `gr_name`, `gr_passwd`, `gr_gid`, and `gr_mem`. These clearly relate to user groups in a Unix-like system.
* **Function Declarations:** The core of the file. List them out and identify their general purpose:
    * `getgrgid`: Get group information by group ID.
    * `getgrnam`: Get group information by group name.
    * `getgrent`, `setgrent`, `endgrent`: Iterate through the group database.
    * `getgrgid_r`, `getgrnam_r`: Reentrant versions of `getgrgid` and `getgrnam`.
    * `getgrouplist`: Get a list of groups a user belongs to.
    * `initgroups`:  Initialize supplementary group access.
* **`__BIONIC_AVAILABILITY_GUARD` and `__INTRODUCED_IN`:** These macros are specific to Bionic and indicate the Android API level at which these functions became available. This is a crucial piece of information for Android-specific relevance.

**3. Addressing Each Part of the User's Request Systematically:**

* **功能 (Functionality):**  Based on the function declarations, summarize the core function: managing and retrieving information about user groups.

* **与 Android 功能的关系 (Relationship to Android):**
    * **Permissions:** Immediately think of Android's permission system and how it relies on user and group IDs for access control. Provide examples like file permissions.
    * **Process Management:**  Mention how Android uses UIDs and GIDs to isolate applications.
    * **Multi-user Support:** Briefly explain how groups can be used in a multi-user environment (though Android's model is somewhat different).

* **libc 函数的实现 (Implementation of libc functions):**
    * **Conceptual Explanation:**  Don't try to reproduce the exact C code (which isn't in the header file). Instead, explain *how* these functions typically work. Mention the `/etc/group` file (or its Android equivalent), how the functions access and parse it, and the purpose of caching.
    * **`_r` (Reentrant) versions:** Explain the importance of reentrancy for thread safety and how these versions use caller-provided buffers.

* **Dynamic Linker 功能 (Dynamic Linker Functionality):**
    * **Identify Relevance:** Recognize that this header file itself doesn't directly *involve* dynamic linking. It *defines interfaces* that *could be implemented* in a shared library.
    * **Hypothetical Scenario:**  Create a plausible scenario where a shared library implements these group functions. This involves inventing a shared object name (`libc.so`) and describing its hypothetical layout, including the `.symtab`, `.strtab`, and `.dynsym` sections.
    * **Linking Process:** Explain the basic steps of symbol resolution by the dynamic linker.

* **逻辑推理 (Logical Reasoning):**
    * **Input/Output for `getgrnam`:** Choose a simple, common function like `getgrnam` and provide a concrete example of input (group name) and the expected output (the `group` structure).

* **常见的使用错误 (Common Usage Errors):**
    * **Buffer Overflow:**  A classic C programming error, especially relevant for the non-reentrant versions.
    * **Missing Error Handling:** Emphasize checking return values.
    * **Incorrect `free()`:** Point out the need to avoid freeing memory returned by these functions.

* **Android Framework/NDK 到达这里的步骤 (Steps from Android Framework/NDK):**
    * **Trace the Path:** Start with a high-level Android API (e.g., accessing file permissions), then describe how it might call down through the framework, native code (using the NDK), and finally into the Bionic `libc`.
    * **Simplified Explanation:**  Acknowledge that the exact path can be complex and might involve caching layers.

* **Frida Hook 示例 (Frida Hook Example):**
    * **Choose a Function:** Select a relatively simple function like `getgrnam`.
    * **Basic Hook Structure:**  Show the fundamental Frida `Interceptor.attach` structure.
    * **Log Arguments and Return Value:** Demonstrate how to access and log the input and output of the hooked function.

**4. Refinement and Language:**

* **Use Clear and Concise Language:** Explain technical concepts in a way that is easy to understand.
* **Provide Concrete Examples:**  Illustrate abstract ideas with practical scenarios.
* **Pay Attention to Detail:** Correctly use terms like "header file," "function declaration," and "shared library."
* **Organize the Answer:** Structure the response to match the user's questions. Use headings and bullet points for clarity.
* **Review and Edit:** Check for any errors or omissions.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe I should dive into the actual source code of `getgrnam`.
* **Correction:** The user only provided the header file. Focusing on the *interface* and general implementation strategies is more appropriate and manageable.
* **Initial Thought:**  Explain dynamic linking in great detail.
* **Correction:** Keep the dynamic linking explanation focused on the specific scenario and the core concepts of symbol resolution. Avoid getting bogged down in advanced linker features.
* **Initial Thought:** Provide a complex Frida hook example.
* **Correction:** Start with a very basic hook to demonstrate the core principle. More complex examples can be confusing for someone new to Frida.

By following this structured approach, considering the user's specific requests, and performing self-correction, it's possible to generate a comprehensive and helpful answer.
这是一个定义了与用户组操作相关的函数和数据结构的C头文件，属于Android Bionic C库的一部分。它提供了在Android系统中管理和查询用户组信息的功能。

**它的功能：**

这个头文件定义了以下功能，用于获取和操作用户组信息：

1. **定义了 `group` 结构体：**  这是存储用户组信息的标准数据结构，包含组名 (`gr_name`), 加密密码 (`gr_passwd`), 组ID (`gr_gid`), 以及组成员列表 (`gr_mem`)。

2. **声明了 `getgrgid()` 函数：**  通过组ID (GID) 获取对应的组信息。

3. **声明了 `getgrnam()` 函数：** 通过组名获取对应的组信息。

4. **声明了 `getgrent()`, `setgrent()`, `endgrent()` 函数 (Android API 26+):**  这些函数用于遍历所有的用户组条目。 `setgrent()` 用于重置遍历的起始位置， `getgrent()` 返回下一个组条目， `endgrent()` 用于结束遍历并释放相关资源。  注意，Android 系统中用户和组的数量可能非常庞大，遍历所有条目可能效率较低。

5. **声明了 `getgrgid_r()` 和 `getgrnam_r()` 函数 (Android API 24+):**  这些是 `getgrgid()` 和 `getgrnam()` 的线程安全版本 (可重入版本)。它们需要调用者提供缓冲区来存储结果，避免了静态缓冲区可能导致的线程安全问题。

6. **声明了 `getgrouplist()` 函数：** 获取指定用户所属的所有组的 GID 列表。

7. **声明了 `initgroups()` 函数：** 初始化当前进程的补充组访问列表。

**与 Android 功能的关系及举例说明：**

这些函数在 Android 系统中扮演着管理用户和权限的关键角色。Android 基于 Linux 内核，继承了其用户和组的概念。

* **权限管理：** Android 的权限系统很大程度上依赖于用户ID (UID) 和组ID (GID)。例如，当一个应用尝试访问某个文件时，系统会检查应用进程的 UID 和 GID 是否与文件的权限设置相符。`getgrgid()` 和 `getgrnam()` 可以用来查询特定 GID 或组名对应的组信息，从而辅助进行权限判断。

* **进程隔离：** Android 使用 UID 和 GID 来隔离不同的应用进程，防止它们互相访问彼此的数据。系统服务可能运行在特定的组下，拥有特定的权限。

* **用户管理 (在一定程度上)：** 虽然 Android 的用户管理模型与传统的 Linux 系统有所不同，但组的概念仍然存在。例如，可以将多个应用或进程归属于同一个组，赋予它们共享某些资源的权限。

**举例说明：**

假设你想知道 GID 为 1015 (通常是 `sdcard_r` 组) 的组名：

```c
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  gid_t gid = 1015;
  struct group* grp = getgrgid(gid);
  if (grp != NULL) {
    printf("Group name for GID %d: %s\n", gid, grp->gr_name);
  } else {
    perror("getgrgid");
  }
  return 0;
}
```

**详细解释每一个 libc 函数的功能是如何实现的：**

这些函数的具体实现位于 Bionic C 库的源代码中，通常与系统底层的用户和组数据库交互。

1. **`getgrgid(gid_t __gid)`:**
   - **功能：**  接收一个组ID (`__gid`) 作为输入，返回指向包含该 GID 信息的 `group` 结构体的指针。如果找不到对应的组，则返回 `NULL`。
   - **实现：**  这个函数通常会打开并读取系统中的用户组数据库文件（在 Android 中，实际的存储位置和格式可能与传统的 `/etc/group` 不同，但逻辑类似）。它会逐行解析文件，查找 `gr_gid` 字段与输入 `__gid` 相匹配的条目。一旦找到匹配项，它会将该条目的信息填充到 `group` 结构体中，并将指向该结构体的指针返回。 为了提高效率，实现中可能会使用缓存来存储最近访问过的组信息。

2. **`getgrnam(const char* _Nonnull __name)`:**
   - **功能：** 接收一个组名 (`__name`) 作为输入，返回指向包含该组名信息的 `group` 结构体的指针。如果找不到对应的组，则返回 `NULL`。
   - **实现：** 类似于 `getgrgid()`，但它会搜索用户组数据库，查找 `gr_name` 字段与输入 `__name` 相匹配的条目。

3. **`getgrent()`:**
   - **功能：**  返回用户组数据库中的下一个组条目，以 `group` 结构体的指针形式返回。当到达数据库末尾时，返回 `NULL`。
   - **实现：**  内部维护一个指向用户组数据库当前读取位置的指针。每次调用时，读取下一行并解析成 `group` 结构体。

4. **`setgrent()`:**
   - **功能：**  重置 `getgrent()` 的读取位置到用户组数据库的开头。
   - **实现：**  关闭当前打开的用户组数据库文件（如果已打开），然后重新打开，将内部读取位置重置到文件开头。

5. **`endgrent()`:**
   - **功能：**  关闭用户组数据库文件，并释放 `getgrent()` 可能分配的资源。
   - **实现：**  关闭内部维护的文件句柄，并释放可能缓存的组信息。

6. **`getgrgid_r(gid_t __gid, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable * _Nonnull __result)`:**
   - **功能：**  `getgrgid()` 的可重入版本。除了组ID (`__gid`)，还需要调用者提供一个预分配的 `group` 结构体 (`__group`) 和一个缓冲区 (`__buf`) 来存储组名和组成员字符串。`__n` 是缓冲区的大小。结果会写入到提供的 `group` 结构体中，并且指向该结构体的指针会赋值给 `__result` 指向的指针。
   - **实现：**  与 `getgrgid()` 类似，但避免使用静态缓冲区，将结果存储到调用者提供的缓冲区中。这使得它在多线程环境下更安全。

7. **`getgrnam_r(const char* _Nonnull __name, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable *_Nonnull __result)`:**
   - **功能：** `getgrnam()` 的可重入版本，参数和实现逻辑与 `getgrgid_r()` 类似。

8. **`getgrouplist(const char* _Nonnull __user, gid_t __group, gid_t* __BIONIC_COMPLICATED_NULLNESS __groups, int* _Nonnull __group_count)`:**
   - **功能：**  获取指定用户 (`__user`) 所属的所有组的 GID 列表。`__group` 是用户的初始组 (通常在 `/etc/passwd` 中指定)。`__groups` 是一个由调用者提供的 GID 数组，用于存储结果。`__group_count` 是一个输入输出参数，输入时指定 `__groups` 数组的大小，输出时返回实际获取到的组数量。
   - **实现：**  它可能需要读取 `/etc/passwd` 文件来获取用户的初始组，然后读取用户组数据库来查找用户是其成员的所有组。

9. **`initgroups(const char* _Nonnull __user, gid_t __group)`:**
   - **功能：** 初始化当前进程的补充组访问列表。这会影响进程可以访问的资源。
   - **实现：**  它会调用 `getgrouplist()` 获取用户的组列表，并将这些组添加到进程的凭据中。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身定义的是接口，其具体的实现通常在 `libc.so` 中。因此，动态链接器需要找到 `libc.so` 并解析其中的符号。

**`libc.so` 布局样本（简化）：**

```
ELF Header
...
Program Headers
...
Section Headers:
  .text         PROGBITS  ... (代码段)
  .rodata       PROGBITS  ... (只读数据)
  .data         PROGBITS  ... (可写数据)
  .bss          NOBITS    ... (未初始化数据)
  .symtab       SYMTAB    ... (符号表)
  .strtab       STRTAB    ... (字符串表)
  .dynsym       DYNSYM    ... (动态符号表)
  .dynstr       DYNSTR    ... (动态字符串表)
  .hash         HASH      ... (符号哈希表)
  .plt          PROGBITS  ... (过程链接表)
  .got.plt      PROGBITS  ... (全局偏移表)
...
```

**链接的处理过程：**

1. **加载 `libc.so`：** 当一个程序（例如一个 Android 应用）需要调用 `getgrnam()` 时，如果该函数不在程序自身的可执行文件中，动态链接器 (linker) 会负责加载包含该函数的共享库 `libc.so`。

2. **符号查找：** 动态链接器会解析 `libc.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)。  当遇到对 `getgrnam` 的未定义引用时，链接器会在 `libc.so` 的 `.dynsym` 中查找名为 `getgrnam` 的符号。

3. **重定位：**  一旦找到符号，链接器需要进行重定位。这意味着将程序中调用 `getgrnam` 的地址指向 `libc.so` 中 `getgrnam` 函数的实际地址。这通常涉及到修改全局偏移表 (`.got.plt`) 中的条目。

4. **过程链接表 (PLT)：**  对于延迟绑定的情况（默认行为），第一次调用 `getgrnam` 时会跳转到过程链接表 (`.plt`) 中的一个桩代码。这个桩代码会调用链接器来解析符号并更新全局偏移表 (`.got.plt`)，然后再次跳转到 `getgrnam` 的实际地址。后续的调用将直接通过 `.got.plt` 跳转到 `getgrnam`。

**逻辑推理，给出假设输入与输出：**

假设用户组数据库中存在以下条目（简化）：

```
root:x:0:root
nobody:x:99:
sdcard_r:x:1015:
```

**假设输入：**

* 调用 `getgrnam("sdcard_r")`

**预期输出：**

返回一个指向 `group` 结构体的指针，该结构体的内容如下：

```c
struct group {
  char* gr_name = "sdcard_r";
  char* gr_passwd = "x";
  gid_t gr_gid = 1015;
  char* gr_mem = NULL; // 假设没有成员
};
```

**假设输入：**

* 调用 `getgrgid(0)`

**预期输出：**

返回一个指向 `group` 结构体的指针，该结构体的内容如下：

```c
struct group {
  char* gr_name = "root";
  char* gr_passwd = "x";
  gid_t gr_gid = 0;
  char* gr_mem = "root"; // 假设 root 用户是 root 组的成员
};
```

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **缓冲区溢出（针对非 `_r` 版本）：**  `getgrnam()` 和 `getgrgid()` 返回的指针指向静态缓冲区。如果在多线程环境下不加保护地使用，可能会发生数据竞争和缓冲区溢出。  推荐使用 `getgrnam_r()` 和 `getgrgid_r()`。

   ```c
   // 不推荐的用法 (线程不安全)
   struct group* grp = getgrnam("sdcard_r");
   if (grp != NULL) {
       // ... 使用 grp ...
   }
   ```

2. **忘记检查返回值：**  如果找不到对应的组，`getgrnam()` 和 `getgrgid()` 会返回 `NULL`。不检查返回值会导致空指针解引用。

   ```c
   struct group* grp = getgrnam("nonexistent_group");
   // 忘记检查 grp 是否为 NULL，直接访问其成员可能导致崩溃
   printf("Group ID: %d\n", grp->gr_gid); // 错误!
   ```

3. **不正确地使用可重入版本：**  使用 `getgrnam_r()` 和 `getgrgid_r()` 时，必须提供足够的缓冲区。如果提供的缓冲区太小，函数可能会返回错误。

   ```c
   char buf[10]; // 缓冲区太小
   struct group grp;
   struct group* result;
   int ret = getgrnam_r("sdcard_r", &grp, buf, sizeof(buf), &result);
   if (ret != 0) {
       perror("getgrnam_r"); // 可能会因为缓冲区太小而失败
   } else if (result != NULL) {
       printf("Group ID: %d\n", result->gr_gid);
   }
   ```

4. **错误地释放内存：** `getgrnam()` 和 `getgrgid()` 返回的指针指向静态分配的内存，不应该由调用者 `free()`。

   ```c
   struct group* grp = getgrnam("sdcard_r");
   if (grp != NULL) {
       // ... 使用 grp ...
       free(grp); // 错误! 不应该释放
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 调用：**  Android Framework 中的某些组件可能需要获取用户组信息。例如，`PackageManagerService` 在处理应用安装和权限时，可能会查询应用的组信息。  Framework 层通常使用 Java API。

2. **JNI 调用：**  Java 代码会通过 JNI (Java Native Interface) 调用到 Native 代码。 例如，Framework 中可能有一个 native 方法来实现获取组信息的功能。

3. **NDK 代码：**  NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 native 代码。Framework 调用的 JNI 方法会在 Bionic C 库中查找相应的函数。

4. **Bionic C 库：**  最终，JNI 调用会到达 Bionic C 库中的 `getgrnam()` 或其他相关函数。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `getgrnam` 函数调用的示例：

```javascript
// frida hook 脚本
Interceptor.attach(Module.findExportByName("libc.so", "getgrnam"), {
  onEnter: function (args) {
    console.log("Called getgrnam with name:", Memory.readUtf8String(args[0]));
  },
  onLeave: function (retval) {
    if (retval.isNull()) {
      console.log("getgrnam returned NULL");
    } else {
      const groupPtr = ptr(retval);
      const gr_name = Memory.readUtf8String(groupPtr.readPointer());
      const gr_gid = groupPtr.add(8).readU32(); // 假设 gid 偏移 8 字节
      console.log("getgrnam returned group name:", gr_name, ", GID:", gr_gid);
    }
  },
});
```

**调试步骤：**

1. **准备环境：**  确保你的 Android 设备已 root，并且安装了 Frida 服务。

2. **编写 Frida 脚本：**  将上面的 JavaScript 代码保存为一个文件，例如 `hook_getgrnam.js`。

3. **确定目标进程：**  找到你想要监控的 Android 进程的进程 ID 或包名。

4. **运行 Frida：**  使用 Frida 命令行工具连接到目标进程并注入你的脚本。

   ```bash
   frida -U -f <目标应用包名> -l hook_getgrnam.js --no-pause
   # 或者
   frida -U <目标进程ID> -l hook_getgrnam.js
   ```

5. **触发调用：**  在目标应用中执行会导致调用 `getgrnam` 的操作。例如，如果目标是 `PackageManagerService`，你可以尝试安装或卸载一个应用。

6. **查看 Frida 输出：**  Frida 控制台会显示 `getgrnam` 被调用时的参数和返回值，从而帮助你理解代码的执行流程。

**注意：** 上面的 Frida 示例假设了 `group` 结构体中字段的内存布局。实际布局可能会因 Android 版本和架构而异，你需要根据具体情况调整偏移量。 你可以使用 `adb shell cat /proc/<pid>/maps` 来查看目标进程加载的库和内存布局，辅助确定偏移量。

总而言之，`grp.handroid` 定义的函数是 Android 系统管理用户组信息的基础，它们被 Android Framework 和 NDK 中的代码广泛使用，以实现权限管理、进程隔离等关键功能。 理解这些函数的功能和使用方法对于深入理解 Android 系统的工作原理至关重要。

Prompt: 
```
这是目录为bionic/libc/include/grp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*-
 * Copyright (c) 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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

#ifndef _GRP_H_
#define _GRP_H_

#include <sys/cdefs.h>
#include <sys/types.h>

struct group {
  char* _Nullable gr_name; /* group name */
  char* _Nullable gr_passwd; /* group password */
  gid_t gr_gid; /* group id */
  char* _Nullable * _Nullable gr_mem; /* group members */
};

__BEGIN_DECLS

struct group* _Nullable getgrgid(gid_t __gid);
struct group* _Nullable getgrnam(const char* _Nonnull __name);

/* Note: Android has thousands and thousands of ids to iterate through. */

#if __BIONIC_AVAILABILITY_GUARD(26)
struct group* _Nullable getgrent(void) __INTRODUCED_IN(26);

void setgrent(void) __INTRODUCED_IN(26);
void endgrent(void) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


#if __BIONIC_AVAILABILITY_GUARD(24)
int getgrgid_r(gid_t __gid, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable * _Nonnull __result) __INTRODUCED_IN(24);
int getgrnam_r(const char* _Nonnull __name, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable *_Nonnull __result) __INTRODUCED_IN(24);
#endif /* __BIONIC_AVAILABILITY_GUARD(24) */

int getgrouplist(const char* _Nonnull __user, gid_t __group, gid_t* __BIONIC_COMPLICATED_NULLNESS __groups, int* _Nonnull __group_count);
int initgroups(const char* _Nonnull __user, gid_t __group);

__END_DECLS

#endif

"""

```
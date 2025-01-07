Response:
Let's break down the thought process to answer the request about `bionic/libc/include/pwd.h`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided header file (`pwd.h`). This includes:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it relate to Android's operation?
* **Function Implementation:**  How are the declared functions likely implemented (without seeing the source)?
* **Dynamic Linking:** If relevant, how does it interact with the dynamic linker?
* **Logic/Input/Output:**  Hypothetical scenarios and their results.
* **Common Errors:** Pitfalls for developers using these functions.
* **Android Integration:** How does Android (framework/NDK) reach this code?
* **Debugging:**  How to use Frida to inspect this code.

**2. Initial Assessment of `pwd.h`:**

The filename and the content (struct `passwd`, functions like `getpwnam`, `getpwuid`) immediately suggest this header deals with *user and group information*. It's the standard POSIX way to access the password database (although Android likely doesn't have a traditional `/etc/passwd` file).

**3. Function-by-Function Analysis:**

I'd go through each declared function and try to infer its purpose:

* **`struct passwd`:**  This is a data structure. It holds information about a user. The fields (`pw_name`, `pw_passwd`, `pw_uid`, `pw_gid`, `pw_gecos`, `pw_dir`, `pw_shell`) are standard UNIX user attributes. The conditional definition of `pw_gecos` hints at architecture differences (LP64 vs. LP32).

* **`getpwnam(const char*)`:**  Looks up user information by username. Returns a pointer to a `passwd` struct.

* **`getpwuid(uid_t)`:** Looks up user information by user ID. Returns a pointer to a `passwd` struct.

* **`getpwent()`:**  Iterates through the user database, returning the next entry. The `__INTRODUCED_IN(26)` annotation is important; it indicates this functionality was added in Android API level 26 (Oreo).

* **`setpwent()`:** Resets the internal pointer used by `getpwent()` to the beginning of the user database. Also introduced in API 26.

* **`endpwent()`:**  Closes any resources used by the `getpwent()` family of functions. Introduced in API 26.

* **`getpwnam_r(...)` and `getpwuid_r(...)`:**  The `_r` suffix typically indicates reentrant versions of functions. These are safer for multi-threaded programs as they require the caller to provide the buffer to store the result, preventing potential race conditions with statically allocated buffers.

**4. Connecting to Android:**

* **No `/etc/passwd`:**  Android doesn't typically use a traditional `/etc/passwd` file. User information is managed differently, often through system services and databases.
* **Android's User Model:** Android has a more complex user model with app-specific UIDs and system UIDs. These functions must interface with Android's internal user management mechanisms.
* **Permissions and Security:**  These functions are crucial for security, determining user identity and permissions.

**5. Implementation Details (Inferred):**

Since we only have the header, we can't see the actual implementation. But we can speculate:

* **`getpwnam` and `getpwuid`:**  Likely involve querying a system service or database based on the provided username or UID. This might involve IPC (Inter-Process Communication).
* **`getpwent`, `setpwent`, `endpwent`:**  Would involve iterating through the underlying user database representation. The API level restriction suggests a change in how this is handled.
* **`_r` functions:**  Would involve the same underlying lookup logic, but with the added step of copying the data into the caller-provided buffer.

**6. Dynamic Linking:**

This header file *declares* functions. The actual *implementation* resides in a shared library (likely `libc.so`). When an application calls one of these functions, the dynamic linker resolves the symbol and loads the corresponding code from `libc.so`.

* **SO Layout:**  Need to imagine the `libc.so` file containing the implementation of these functions.
* **Linking Process:**  Describe how the dynamic linker finds the function's address during program startup or the first time the function is called.

**7. Logic/Input/Output Examples:**

Create simple scenarios to illustrate how the functions work. For example:

* `getpwnam("root")` might return information about the root user.
* `getpwuid(1000)` might return information about the user with UID 1000.

**8. Common Errors:**

Think about typical mistakes developers might make:

* **Forgetting to check for `NULL`:** `getpwnam` and `getpwuid` can return `NULL` if the user isn't found.
* **Buffer overflows (for non-`_r` functions):** Although `getpwnam` and `getpwuid` return pointers to internal buffers, understanding the reentrant versions helps in general.
* **Incorrect buffer size (for `_r` functions):**  Providing too small a buffer to `getpwnam_r` or `getpwuid_r`.
* **Using `getpwent` without proper handling:**  Forgetting to call `setpwent` or `endpwent`.

**9. Android Framework/NDK Path:**

Trace how these functions are used:

* **NDK:**  Native code directly calls these functions in `libc.so`.
* **Framework:**  Java code in the framework might indirectly use these functions through JNI calls to native libraries that use `libc`. Examples include managing user permissions or retrieving user information.

**10. Frida Hooking:**

Provide practical Frida examples to intercept calls to these functions, inspect arguments, and see return values. This gives concrete ways to debug.

**11. Structuring the Answer:**

Organize the information logically with clear headings and bullet points. Use code blocks for examples and commands. Maintain a consistent tone and use clear, concise language.

**Self-Correction/Refinement during the process:**

* **Realization about `/etc/passwd`:**  Early on, it's important to recognize that Android's user management is different.
* **Emphasis on API level:**  Highlight the significance of the `__INTRODUCED_IN(26)` annotation for `getpwent` and related functions.
* **Clarity on dynamic linking:** Ensure the explanation of shared libraries and the linker process is clear.
* **Practicality of Frida examples:**  Make sure the Frida snippets are usable and illustrate key concepts.

By following this structured thought process, addressing each aspect of the request systematically, and incorporating self-correction along the way, I can generate a comprehensive and informative answer like the example provided.
这是一个名为 `pwd.h` 的头文件，位于 Android Bionic 库中。Bionic 是 Android 的 C 库、数学库和动态链接器。`pwd.h` 定义了用于处理用户密码数据库的结构体和函数。

**功能列举：**

这个头文件主要定义了以下内容：

1. **`struct passwd` 结构体:**  用于存储用户密码数据库中的一条记录，包含用户的各种信息。
2. **`getpwnam()` 函数:** 通过用户名查找用户信息。
3. **`getpwuid()` 函数:** 通过用户 ID (UID) 查找用户信息。
4. **`getpwent()` 函数 (API 级别 26+):**  用于遍历用户密码数据库中的所有条目。
5. **`setpwent()` 函数 (API 级别 26+):**  重置 `getpwent()` 的内部指针，使其从头开始遍历。
6. **`endpwent()` 函数 (API 级别 26+):**  关闭 `getpwent()` 打开的任何资源。
7. **`getpwnam_r()` 函数:**  `getpwnam()` 的可重入版本，用于线程安全。
8. **`getpwuid_r()` 函数:**  `getpwuid()` 的可重入版本，用于线程安全。

**与 Android 功能的关系和举例说明：**

虽然 Android 不像传统的 Linux 系统那样依赖 `/etc/passwd` 文件来存储所有用户信息，但这些函数仍然在 Android 系统中扮演着重要的角色，用于管理和识别用户及进程的身份。

* **权限管理:**  Android 的权限系统依赖于 UID 和 GID (组 ID)。当一个应用或进程尝试执行需要特定权限的操作时，系统会检查其 UID/GID 是否具有相应的权限。`getpwuid()` 可以用来获取给定 UID 的用户信息，从而了解该 UID 所属的用户。例如，当系统需要确定一个进程是否拥有访问特定文件的权限时，可能会使用 `getpwuid()` 获取进程的用户信息。
* **进程管理:**  在进程管理中，系统需要跟踪每个进程的所有者。`getpwuid()` 可以用于获取进程所有者的用户名。例如，`ps` 命令在显示进程信息时，会使用这些函数来显示进程的用户名。
* **用户隔离:**  Android 的用户隔离功能依赖于不同的 UID。每个应用通常运行在它自己的 UID 下。这些函数可以用来查询不同 UID 的信息。
* **应用沙箱:**  Android 的应用沙箱机制也与 UID 密切相关。每个应用都有一个唯一的 UID，这有助于隔离不同应用的数据和资源。

**详细解释 libc 函数的功能实现：**

由于只提供了头文件，我们无法直接看到这些函数的具体实现代码。但是，我们可以推测其实现方式：

* **`getpwnam(const char* __name)`:**
    * **假设输入:** 用户名字符串，例如 "root" 或 "nobody"。
    * **逻辑推理:**  函数接收用户名作为输入，然后在 Android 系统内部的用户数据库或服务中查找匹配的条目。这个数据库可能不是传统的文件，而是一个由系统服务管理的数据结构。
    * **输出:** 如果找到匹配的用户，则返回指向 `struct passwd` 结构的指针，该结构包含了该用户的详细信息（用户名、UID、GID 等）。如果未找到，则返回 `NULL`。
    * **Android 实现推测:**  Android 可能通过 Binder IPC 调用系统服务（例如 `UserManagerService`）来获取用户信息。
* **`getpwuid(uid_t __uid)`:**
    * **假设输入:** 用户 ID，例如 0 (root) 或 1000 (第一个安装的应用)。
    * **逻辑推理:** 函数接收 UID 作为输入，然后在 Android 系统内部的用户数据库或服务中查找匹配的条目。
    * **输出:** 如果找到匹配的用户，则返回指向 `struct passwd` 结构的指针。如果未找到，则返回 `NULL`。
    * **Android 实现推测:**  与 `getpwnam()` 类似，可能通过 Binder IPC 调用系统服务。
* **`getpwent()` (API 级别 26+)**:
    * **逻辑推理:**  这个函数用于顺序访问用户数据库中的每个条目。它通常维护一个内部指针来跟踪当前读取的位置。
    * **Android 实现推测:**  Android 的用户管理可能涉及更复杂的数据结构，而不是简单的线性文件。`getpwent()` 的实现可能需要与底层的用户管理服务交互，并逐步返回用户信息。
* **`setpwent()` (API 级别 26+)**:
    * **逻辑推理:**  这个函数将 `getpwent()` 使用的内部指针重置到用户数据库的开头，以便重新开始遍历。
* **`endpwent()` (API 级别 26+)**:
    * **逻辑推理:**  这个函数用于清理 `getpwent()` 可能分配的任何资源，例如关闭打开的文件或释放内存。
* **`getpwnam_r(const char* __name, struct passwd* __pwd, char* __buf, size_t __n, struct passwd* * __result)` 和 `getpwuid_r(uid_t __uid, struct passwd* __pwd, char* __buf, size_t __n, struct passwd* * __result)`:**
    * **功能:** 这些是可重入版本的 `getpwnam()` 和 `getpwuid()`。可重入意味着它们在多线程环境下使用是安全的，因为它们不会使用静态的内部缓冲区。
    * **实现方式:** 调用者需要提供一个用于存储 `passwd` 结构体数据的缓冲区 (`__pwd`) 和一个用于存储字符串数据（如用户名、家目录、shell）的缓冲区 (`__buf`)，以及缓冲区的大小 (`__n`). 函数会将查找到的用户信息写入这些缓冲区中。
    * **输出:**  函数返回一个整数错误码（0 表示成功），并将指向填充后的 `passwd` 结构体的指针写入 `__result` 指向的内存位置。

**涉及 dynamic linker 的功能：**

这个头文件本身不包含动态链接器的功能，它只是声明了一些函数和结构体。这些函数的实际实现代码位于 Bionic 的共享库 `libc.so` 中。当一个程序（例如一个应用或系统服务）调用这些函数时，动态链接器负责找到 `libc.so` 库，并将函数调用链接到库中对应的代码。

**so 布局样本 (libc.so 的简化视图):**

```
libc.so:
    .text:  // 包含可执行代码
        ...
        getpwnam:    // getpwnam 函数的实现代码
            ...
        getpwuid:    // getpwuid 函数的实现代码
            ...
        getpwent:    // getpwent 函数的实现代码 (如果 API 级别 >= 26)
            ...
        setpwent:    // setpwent 函数的实现代码 (如果 API 级别 >= 26)
            ...
        endpwent:    // endpwent 函数的实现代码 (如果 API 级别 >= 26)
            ...
        getpwnam_r:  // getpwnam_r 函数的实现代码
            ...
        getpwuid_r:  // getpwuid_r 函数的实现代码
            ...
    .data:  // 包含已初始化的全局变量
        ...
    .bss:   // 包含未初始化的全局变量
        ...
    .dynsym: // 动态符号表，列出库中导出的符号 (函数和变量名)
        ...
        getpwnam
        getpwuid
        getpwent
        setpwent
        endpwent
        getpwnam_r
        getpwuid_r
        ...
    .dynstr: // 动态字符串表，包含符号表中使用的字符串
        ...
```

**链接的处理过程：**

1. **编译时：** 当一个程序使用 `pwd.h` 中声明的函数时，编译器会将这些函数调用标记为需要外部链接。
2. **加载时：** 当 Android 系统加载这个程序时，动态链接器（`linker` 或 `linker64`）会解析程序依赖的共享库列表。
3. **符号查找：** 动态链接器会查找 `libc.so` 库，并在其动态符号表 (`.dynsym`) 中查找被调用的函数（例如 `getpwnam`）。
4. **地址重定位：** 动态链接器会将程序中对 `getpwnam` 的调用地址重定向到 `libc.so` 中 `getpwnam` 函数的实际地址。
5. **执行：** 当程序执行到 `getpwnam` 调用时，程序会跳转到 `libc.so` 中对应的代码执行。

**用户或编程常见的使用错误：**

* **忘记检查 `NULL` 返回值:** `getpwnam()` 和 `getpwuid()` 在找不到匹配用户时会返回 `NULL`。如果程序没有检查这个返回值，可能会导致空指针解引用错误。
    ```c
    #include <pwd.h>
    #include <stdio.h>

    int main() {
        struct passwd *pwd = getpwnam("nonexistentuser");
        if (pwd != NULL) { // 正确的做法是检查返回值
            printf("User found: %s\n", pwd->pw_name);
        } else {
            printf("User not found.\n");
        }
        return 0;
    }
    ```
* **缓冲区溢出 (对于非 `_r` 版本，虽然返回的是内部指针，但理解缓冲区大小的概念很重要):**  虽然 `getpwnam` 和 `getpwuid` 返回指向 `libc` 内部静态缓冲区的指针，但如果错误地复制这些字符串到固定大小的缓冲区，仍可能导致溢出。 对于 `_r` 版本，如果提供的缓冲区太小，也会导致错误。
    ```c
    #include <pwd.h>
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>

    int main() {
        struct passwd pwd_buf;
        char buf[1024];
        struct passwd *result;

        int ret = getpwnam_r("root", &pwd_buf, buf, sizeof(buf), &result);
        if (ret == 0 && result != NULL) {
            printf("User: %s\n", result->pw_name);
        } else {
            perror("getpwnam_r failed");
        }
        return 0;
    }
    ```
* **错误地使用 `getpwent()` 系列函数:**
    * **忘记调用 `setpwent()`:** 如果需要多次遍历用户数据库，需要在每次开始前调用 `setpwent()`。
    * **忘记调用 `endpwent()`:**  不调用 `endpwent()` 可能会导致资源泄漏。
    ```c
    #include <pwd.h>
    #include <stdio.h>

    int main() {
        setpwent();
        struct passwd *pwd;
        while ((pwd = getpwent()) != NULL) {
            printf("User: %s, UID: %d\n", pwd->pw_name, pwd->pw_uid);
        }
        endpwent();
        return 0;
    }
    ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `pwd.h` 的路径：**

1. **Java Framework API 调用:** Android Framework 中的 Java 代码，例如需要获取用户信息的功能，可能会调用 Android 系统服务，例如 `UserManagerService`。
2. **Binder IPC:**  Java Framework 通过 Binder IPC 机制向系统服务发送请求。
3. **Native 系统服务实现:**  系统服务（例如 `system_server` 进程中的 `UserManagerService`）通常是用 C++ 实现的。
4. **JNI 调用 (可能):** 系统服务的 C++ 代码可能需要访问底层的用户数据。虽然不一定直接调用 `getpwnam` 等函数，但可能会调用其他 Bionic 库中的函数，这些函数内部可能最终会与用户数据交互。
5. **libc.so 中的实现:**  最终，获取用户信息的底层操作会通过 Bionic 库中的函数来实现，这些函数可能直接或间接地使用 `pwd.h` 中声明的函数。

**NDK 到 `pwd.h` 的路径：**

1. **NDK 代码调用:**  使用 NDK 开发的 Native 代码可以直接包含 `pwd.h` 头文件并调用其中的函数。
2. **动态链接:**  当 Native 代码运行时，动态链接器会将对 `getpwnam` 等函数的调用链接到 `libc.so` 中对应的实现。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `getpwnam` 函数调用的示例：

```javascript
if (Process.platform === 'android') {
  const getpwnam = Module.findExportByName('libc.so', 'getpwnam');

  if (getpwnam) {
    Interceptor.attach(getpwnam, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[0]);
        console.log(`[getpwnam] Called with name: ${name}`);
      },
      onLeave: function (retval) {
        if (!retval.isNull()) {
          const passwdPtr = retval;
          const pw_name = Memory.readUtf8String(passwdPtr.readPointer());
          const pw_uid = passwdPtr.add(Process.pointerSize * 2).readU32();
          console.log(`[getpwnam] Returned user: ${pw_name}, UID: ${pw_uid}`);
        } else {
          console.log('[getpwnam] Returned NULL (user not found)');
        }
      },
    });
  } else {
    console.error('Failed to find getpwnam in libc.so');
  }
} else {
  console.warn('This script is designed for Android.');
}
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `hook_getpwnam.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_getpwnam.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_getpwnam.js
   ```
   将 `<package_name>` 替换为你要监控的 Android 应用的包名。

**Frida Hook 说明：**

* **`Process.platform === 'android'`:** 确保脚本只在 Android 平台上运行。
* **`Module.findExportByName('libc.so', 'getpwnam')`:**  查找 `libc.so` 库中导出的 `getpwnam` 函数的地址。
* **`Interceptor.attach(getpwnam, ...)`:**  拦截 `getpwnam` 函数的调用。
* **`onEnter`:**  在 `getpwnam` 函数被调用之前执行。`args[0]` 包含传递给函数的用户名参数。
* **`onLeave`:** 在 `getpwnam` 函数返回之后执行。`retval` 包含函数的返回值（指向 `struct passwd` 的指针）。
* **读取 `struct passwd` 成员:**  如果返回值不为 `NULL`，则读取 `struct passwd` 结构体的成员，例如 `pw_name` 和 `pw_uid`。注意指针偏移量需要根据目标平台的架构（32位或64位）进行调整。

通过这个 Frida Hook，你可以在应用调用 `getpwnam` 时观察到传递的用户名和返回的用户信息，从而调试 Android Framework 或 NDK 如何使用这些函数。你可以根据需要修改脚本来 hook 其他函数，例如 `getpwuid`。

Prompt: 
```
这是目录为bionic/libc/include/pwd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

/*-
 * Portions Copyright(C) 1995, Jason Downs.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PWD_H_
#define _PWD_H_

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

struct passwd {
  char* _Nullable pw_name;
  char* _Nullable pw_passwd;
  uid_t pw_uid;
  gid_t pw_gid;
#ifdef __LP64__
  char* _Nullable pw_gecos;
#else
  /* Note: On LP32, we define pw_gecos to pw_passwd since they're both NULL. */
# define pw_gecos pw_passwd
#endif
  char* _Nullable pw_dir;
  char* _Nullable pw_shell;
};

struct passwd* _Nullable getpwnam(const char* _Nonnull __name);
struct passwd* _Nullable getpwuid(uid_t __uid);

/* Note: Android has thousands and thousands of ids to iterate through */

#if __BIONIC_AVAILABILITY_GUARD(26)
struct passwd* _Nullable getpwent(void) __INTRODUCED_IN(26);

void setpwent(void) __INTRODUCED_IN(26);
void endpwent(void) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


int getpwnam_r(const char* _Nonnull __name, struct passwd* _Nonnull __pwd, char* _Nonnull __buf, size_t __n, struct passwd* _Nullable * _Nonnull __result);
int getpwuid_r(uid_t __uid, struct passwd* _Nonnull __pwd, char* _Nonnull __buf, size_t __n, struct passwd* _Nullable * _Nonnull __result);

__END_DECLS

#endif

"""

```
Response:
Let's break down the thought process for answering the request about `bionic/tests/grp_pwd_test.cpp`.

**1. Understanding the Core Request:**

The fundamental request is to analyze a C++ test file within Android's Bionic library. The file tests the functionality of `grp.h` and `pwd.h`, which deal with user and group information. The request asks for:

* **Functionality:** What does the test file do?
* **Android Relationship:** How does it relate to Android's overall functionality?
* **libc Details:** How are the libc functions implemented (internally)?
* **Dynamic Linker:**  Is the dynamic linker involved, and if so, how?
* **Logic & I/O:**  Are there implicit inputs/outputs?
* **Common Errors:** What mistakes do programmers often make using these functions?
* **Android Journey & Hooking:** How does code reach these functions from Android frameworks/NDK, and how can we debug it?

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code, looking for key elements:

* **Includes:** `<grp.h>`, `<pwd.h>`, `gtest/gtest.h`. This immediately tells us it's a test file for group and password functions.
* **Test Macros:** `TEST(pwd, ...)` and `TEST(grp, ...)`. These define the individual test cases.
* **Assertions/Expectations:** `ASSERT_TRUE`, `EXPECT_STREQ`, `EXPECT_EQ`, `ASSERT_ERRNO`. These are the core of the testing logic, checking if the functions behave as expected.
* **Function Calls:** `getpwuid`, `getpwnam`, `getpwuid_r`, `getpwnam_r`, `getgrgid`, `getgrnam`, `getgrgid_r`, `getgrnam_r`, `setpwent`, `getpwent`, `endpwent`, `setgrent`, `getgrent`, `endgrent`, `getgrouplist`, `initgroups`, `sysconf`. These are the libc functions being tested.
* **Helper Functions:** `check_passwd`, `check_group`, `expect_no_passwd_id`, `expect_no_passwd_name`, `expect_no_group_id`, `expect_no_group_name`. These encapsulate common assertion patterns.
* **Conditional Compilation:** `#if defined(__BIONIC__)`. Indicates some tests are specific to the Bionic library.
* **Android Specifics:** Includes like `<android-base/...>`, `<private/android_filesystem_config.h>`, usage of `android::base::GetProperty`, and the inclusion of `generated_android_ids.h`. These point to the Android context.

**3. Deducing Functionality and Android Relevance:**

Based on the included headers and the test function names (e.g., `getpwnam_platform_ids`, `getgrnam_u0_app_ids`), it becomes clear that the file tests the correct retrieval of user and group information based on names and IDs. The tests cover:

* **Platform IDs:** Standard Linux-like user/group IDs.
* **OEM IDs:** IDs specific to device manufacturers.
* **Application IDs:**  The Android-specific UID/GID allocation scheme (`u<user>_a<app>`).
* **Error Cases:**  Testing that non-existent users/groups are handled correctly.
* **Reentrancy and Alignment:** Testing the thread-safety and memory alignment requirements of the `_r` (reentrant) versions of the functions.
* **Iteration:** Testing the `getpwent` and `getgrent` functions for iterating through all users and groups.

The Android relevance is clear because it tests the functions used by the Android system to manage user and group permissions and identity. Examples like application IDs directly link to Android's security model.

**4. Addressing libc Function Implementation:**

This requires some background knowledge about how these functions are typically implemented. The key is that they usually rely on data stored in `/etc/passwd` and `/etc/group` (or their equivalents). The test code itself *doesn't* show the implementation, but the tests verify that Bionic's implementation correctly parses and interprets this data. The explanation focuses on this typical mechanism.

**5. Dynamic Linker Considerations:**

The test file itself doesn't directly interact with the dynamic linker. However, the functions being tested (`getpwuid`, etc.) are part of `libc.so`, which *is* loaded by the dynamic linker. The explanation highlights this indirect relationship and provides a generic `libc.so` layout. The linking process is the standard process of resolving symbols at runtime.

**6. Logic, Inputs, and Outputs:**

The tests have implicit inputs (the user/group databases, even if mocked or simplified in the test environment) and explicit inputs (the user/group names or IDs passed to the functions). The outputs are the `passwd` and `group` structures or errors. The explanation points out these implicit and explicit aspects and provides concrete examples.

**7. Common User Errors:**

Thinking about common programming mistakes when using these functions leads to errors like:

* **Incorrect Buffer Sizes:** For the `_r` functions.
* **Forgetting to Check Return Values:**  Missing error handling.
* **Assuming Data is Always Present:** Not handling cases where users/groups don't exist.

**8. Android Journey and Frida Hooking:**

This requires understanding the high-level Android architecture. The journey starts from the framework (Java code), potentially goes through JNI to native code, and eventually calls the libc functions. The explanation outlines this path. The Frida example focuses on hooking `getpwuid`, a representative function, to intercept calls and examine arguments and return values.

**9. Structuring the Answer:**

The final step is to organize the information logically, using clear headings and bullet points. The response mirrors the structure of the original request, addressing each point systematically. Using code snippets and concrete examples makes the explanation easier to understand. The language used is clear and concise, avoiding overly technical jargon where possible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps the test directly manipulates `/etc/passwd`. **Correction:** Realized the tests *verify* the behavior based on some underlying data source, but don't necessarily create or modify the files themselves. The focus is on the API's correctness.
* **Initial thought:** Focus heavily on the `generated_android_ids.h` file. **Correction:**  While important for knowing the expected IDs, the core functionality test is about the libc functions, not just the static ID list. The `generated_android_ids.h` is an input for the tests, not the function's core logic.
* **Initial thought:** Go deep into the dynamic linker's implementation details. **Correction:** The test doesn't directly test the dynamic linker. Keep the dynamic linker explanation relevant to how `libc.so` is involved.

By following this thought process, combining code analysis, domain knowledge, and systematic organization, a comprehensive and accurate answer to the request can be constructed.
好的，让我们详细分析一下 `bionic/tests/grp_pwd_test.cpp` 这个文件。

**文件功能概述:**

`bionic/tests/grp_pwd_test.cpp` 是 Android Bionic 库中的一个 C++ 单元测试文件。它的主要功能是测试 `grp.h` 和 `pwd.h` 头文件中定义的与用户和组相关的 C 标准库函数（libc）。这些函数用于获取和操作用户和组的信息，例如用户名、用户 ID (UID)、组名、组 ID (GID) 等。

具体来说，这个测试文件涵盖了以下几个方面的功能测试：

1. **`getpwuid()` 和 `getpwnam()`:**  通过 UID 获取用户信息，通过用户名获取用户信息。
2. **`getpwuid_r()` 和 `getpwnam_r()`:**  `getpwuid()` 和 `getpwnam()` 的线程安全（可重入）版本。
3. **`getpwent()`、`setpwent()` 和 `endpwent()`:**  用于遍历所有用户条目的函数。
4. **`getgrgid()` 和 `getgrnam()`:**  通过 GID 获取组信息，通过组名获取组信息。
5. **`getgrgid_r()` 和 `getgrnam_r()`:**  `getgrgid()` 和 `getgrnam()` 的线程安全版本。
6. **`getgrent()`、`setgrent()` 和 `endgrent()`:**  用于遍历所有组条目的函数。
7. **`getgrouplist()`:** 获取用户所属的组列表。
8. **`initgroups()`:** 初始化用户所属的附加组列表。

**与 Android 功能的关系及举例说明:**

这些函数在 Android 系统中扮演着至关重要的角色，用于管理进程的身份和权限。Android 的安全模型很大程度上依赖于 UID 和 GID 来隔离不同的应用程序和系统服务。

* **进程权限管理:** 当一个应用或服务启动时，系统会为其分配一个唯一的 UID 和一组 GID。操作系统内核会根据这些 ID 来限制进程可以访问的资源（例如文件、网络端口）。
    * **例子:** 当你安装一个应用时，Android 会为其分配一个 UID（例如 10084）。这个应用只能访问其所属 UID 拥有的文件，或者其他用户/组允许其访问的文件。
* **文件系统权限:** 文件系统中的每个文件和目录都关联着所有者 UID 和 GID，以及相应的权限（读、写、执行）。
    * **例子:**  `/data/data/<package_name>` 目录通常属于应用程序的 UID 和 GID，只有该应用才能完全控制该目录下的文件。
* **系统服务身份:** 许多 Android 系统服务也运行在特定的 UID/GID 下，例如 `system` (UID 1000), `radio` (UID 1001) 等。这有助于隔离不同的系统组件。
    * **例子:**  `system_server` 进程以 `system` 用户身份运行，拥有较高的权限来管理系统资源。
* **用户隔离:** 在多用户 Android 设备上，每个用户都有自己独立的 UID 范围，确保用户之间的数据隔离。
    * **例子:**  主用户的应用运行在 UID 10000+ 的范围内，而第二个用户的应用运行在 UID 110000+ 的范围内。

测试用例中就体现了这些关系，例如：

* **`getpwnam_platform_ids` 测试:** 检查像 "root" (UID 0), "system" (UID 1000) 这样的基本系统用户的 UID 是否正确。
* **`getpwnam_u0_app_ids` 测试:** 检查应用用户的 UID 分配，例如 "u0_a0" (UID 10000)。这里的 "u0" 代表主用户，"a0" 代表第一个安装的应用。
* **`getgrnam_u0_app_ids` 测试:** 检查应用组的 GID 分配，例如 "u0_a0_cache" (GID 20000)。

**libc 函数的实现原理:**

这些 libc 函数的实现通常依赖于读取和解析存储用户和组信息的配置文件。在传统的 Linux 系统中，这些文件是 `/etc/passwd` 和 `/etc/group`。

* **`/etc/passwd`:**  包含用户信息，每行代表一个用户，字段之间用冒号分隔。常见的字段包括：用户名、密码（通常是 'x' 或 '*' 表示密码哈希存储在其他地方）、UID、GID、描述信息（gecos）、家目录、登录 Shell。
* **`/etc/group`:** 包含组信息，每行代表一个组，字段之间用冒号分隔。常见的字段包括：组名、密码（很少使用，通常是 'x' 或 '*'）、GID、组成员列表（用户名列表，逗号分隔）。

**Bionic 的实现:**

在 Android Bionic 中，为了提高效率和安全性，用户和组信息可能不会完全依赖传统的 `/etc/passwd` 和 `/etc/group` 文件。Bionic 可能会使用其他数据源或缓存机制。例如：

* **`/system/etc/passwd` 和 `/system/etc/group`:** Android 系统分区下的这些文件可能包含基本的系统用户和组信息。
* **`android_ids` 数组 (generated_android_ids.h):**  测试代码中包含了 `generated_android_ids.h`，这表明 Bionic 可能会预定义一些用户和组 ID，并在运行时查找这些信息。这可以避免每次都解析文件。
* **缓存:** Bionic 可能会缓存用户和组信息，以减少重复读取文件的开销。

**具体 libc 函数的实现逻辑 (推测):**

* **`getpwuid(uid_t uid)`:**
    1. 接收一个 UID 作为参数。
    2. 遍历用户数据库（可能是解析 `/system/etc/passwd` 或查找 `android_ids` 数组）。
    3. 找到匹配给定 UID 的用户条目。
    4. 将用户信息填充到 `passwd` 结构体中并返回指向该结构体的指针。
    5. 如果找不到匹配的用户，则返回 `NULL` 并设置 `errno` 为 `ENOENT`。

* **`getpwnam(const char *name)`:**
    1. 接收一个用户名作为参数。
    2. 遍历用户数据库。
    3. 找到匹配给定用户名的用户条目。
    4. 将用户信息填充到 `passwd` 结构体并返回指针。
    5. 如果找不到匹配的用户，则返回 `NULL` 并设置 `errno` 为 `ENOENT`。

* **`getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t size, struct passwd **result)`:**
    与 `getpwuid()` 类似，但它是可重入的。它使用用户提供的缓冲区 `buf` 来存储字符串数据，并将结果存储在用户提供的 `passwd` 结构体 `pwd` 中。`result` 指向 `pwd`，如果找不到用户则为 `NULL`。

* **`getpwnam_r(...)`:**  与 `getpwnam()` 类似，但也是可重入的。

* **`getpwent()`:**
    1. 维护一个内部指针或索引，指向当前正在处理的用户条目。
    2. 每次调用时，返回下一个用户条目的 `passwd` 结构体指针。
    3. 如果已经遍历完所有用户，则返回 `NULL`。

* **`setpwent()`:**  重置 `getpwent()` 的内部指针或索引到用户数据库的开头。

* **`endpwent()`:**  关闭可能打开的用户数据库文件或其他资源。

组相关的函数 (`getgrgid`, `getgrnam`, `getgrent`, 等) 的实现逻辑与用户相关的函数类似，只是它们操作的是组信息数据库。

**涉及 Dynamic Linker 的功能及处理过程:**

这个测试文件本身并没有直接测试 dynamic linker 的功能。但是，它测试的 libc 函数（如 `getpwuid` 等）是 `libc.so` 共享库的一部分，这个库是由 dynamic linker 在程序启动时加载和链接的。

**so 布局样本 (libc.so 的简化示意):**

```
libc.so:
    .text:  # 代码段
        getpwuid:  # getpwuid 函数的代码
            ...
        getpwnam:  # getpwnam 函数的代码
            ...
        # 其他 libc 函数的代码
    .data:  # 初始化数据段
        # 全局变量
    .bss:   # 未初始化数据段
        # 未初始化的全局变量
    .dynsym: # 动态符号表
        getpwuid  # 导出符号
        getpwnam  # 导出符号
        # 其他导出符号
    .dynstr: # 动态字符串表
        "getpwuid"
        "getpwnam"
        # 其他字符串
    .plt:   # Procedure Linkage Table (过程链接表)
        # 用于延迟绑定
```

**链接的处理过程:**

1. **编译时:**  当编译 `grp_pwd_test.cpp` 时，编译器会看到对 `getpwuid` 等函数的调用。由于这些函数在 `libc.so` 中，编译器会生成对这些符号的外部引用。
2. **链接时:**  链接器会将 `grp_pwd_test` 的目标文件与所需的库（包括 `libc.so`）链接在一起。链接器会解析对 `libc.so` 中符号的引用，但在动态链接的情况下，实际的地址解析会推迟到运行时。
3. **运行时 (Dynamic Linker 的工作):**
    * 当运行 `grp_pwd_test` 可执行文件时，操作系统会加载它，并启动 dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`)。
    * Dynamic linker 会解析可执行文件依赖的共享库列表（这里包括 `libc.so`）。
    * Dynamic linker 会加载 `libc.so` 到内存中的某个地址。
    * **符号解析 (Symbol Resolution):** Dynamic linker 会遍历可执行文件和加载的共享库的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)。当遇到对 `getpwuid` 等符号的未解析引用时，它会在 `libc.so` 的符号表中查找这些符号的地址。
    * **重定位 (Relocation):**  Dynamic linker 会修改可执行文件中的代码，将对 `getpwuid` 等符号的引用替换为 `libc.so` 中这些符号的实际内存地址。这通常通过 Procedure Linkage Table (`.plt`) 和 Global Offset Table (`.got`) 来实现。
    * 完成所有必要的库加载和链接后，dynamic linker 会将控制权交给可执行文件的入口点，然后 `grp_pwd_test` 就可以调用 `libc.so` 中的函数了。

**逻辑推理、假设输入与输出:**

测试代码本身就包含了大量的逻辑推理和假设输入/输出。例如 `TEST(pwd, getpwnam_platform_ids)` 这个测试：

* **假设输入:** 系统中存在名为 "root" 的用户，其 UID 为 0。
* **预期输出:** 调用 `getpwnam("root")` 应该返回一个 `passwd` 结构体指针，并且该结构体的 `pw_uid` 字段的值为 0，`pw_name` 字段的值为 "root"。

再例如 `TEST(pwd, getpwnam_non_exist)` 这个测试：

* **假设输入:** 系统中不存在 UID 为 999 的用户。
* **预期输出:** 调用 `getpwuid(999)` 应该返回 `nullptr`，并且 `errno` 的值应该为 `ENOENT`。

**用户或编程常见的使用错误:**

1. **缓冲区溢出 (对于 `_r` 版本):**  使用 `getpwuid_r` 或 `getpwnam_r` 时，提供的缓冲区 `buf` 的大小不足以存储用户名、家目录、Shell 等字符串信息，可能导致缓冲区溢出。
    ```c
    struct passwd pwd;
    char buf[64]; // 缓冲区太小
    struct passwd *result;
    getpwnam_r("very_long_username", &pwd, buf, sizeof(buf), &result); // 可能溢出
    ```
2. **忘记检查返回值:**  `getpwuid` 和 `getpwnam` 在找不到用户时会返回 `NULL`，`getpwuid_r` 和 `getpwnam_r` 的 `result` 参数会设置为 `NULL`。如果忘记检查返回值，就直接访问返回的结构体指针，会导致段错误。
    ```c
    passwd *pwd = getpwnam("nonexistent_user");
    printf("UID: %d\n", pwd->pw_uid); // 如果 pwd 是 NULL，这里会崩溃
    ```
3. **对可重入函数理解不足:**  错误地认为 `getpwuid` 和 `getpwnam` 在多线程环境下是安全的，而没有使用线程安全的 `_r` 版本。这可能导致数据竞争和不可预测的结果。
4. **假设用户或组总是存在:**  在某些情况下（例如，处理来自外部源的用户/组信息），应该检查用户或组是否存在，而不是直接假设它们存在。
5. **不正确的缓冲区大小计算:**  使用 `sysconf(_SC_GETPW_R_SIZE_MAX)` 或 `sysconf(_SC_GETGR_R_SIZE_MAX)` 获取建议的缓冲区大小，但可能没有正确地分配或使用该大小的缓冲区。

**Android Framework 或 NDK 如何到达这里，给出 Frida Hook 示例调试这些步骤:**

从 Android Framework 或 NDK 到达 `getpwuid` 等 libc 函数通常会经过以下步骤：

1. **Java Framework 层:** Android Framework 的 Java 代码可能需要获取用户信息。例如，`android.os.Process.getUidForName(String str)` 方法内部会调用 native 方法。
2. **JNI (Java Native Interface) 层:**  Java 代码通过 JNI 调用 native 代码。在 Framework 相关的 native 代码中（例如在 `frameworks/base/core/jni` 目录下），可能会有 JNI 函数来桥接 Java 调用到 C/C++ 代码。
3. **Native C/C++ 代码:**  这些 native 代码最终会调用 Bionic 提供的 libc 函数。例如，一个系统服务可能需要检查某个用户的权限，从而调用 `getpwuid`。
4. **libc 函数:**  Bionic 的 `libc.so` 中实现了 `getpwuid` 等函数。

**Frida Hook 示例:**

可以使用 Frida 来 hook `getpwuid` 函数，观察其调用过程和参数。

```javascript
// hook_getpwuid.js

if (Process.platform === 'android') {
  const libc = Module.findExportByName("libc.so", "getpwuid");

  if (libc) {
    Interceptor.attach(libc, {
      onEnter: function (args) {
        const uid = args[0].toInt32();
        console.log("[+] getpwuid called with UID:", uid);
      },
      onLeave: function (retval) {
        if (retval.isNull()) {
          console.log("[+] getpwuid returned NULL");
        } else {
          const passwdPtr = ptr(retval);
          const pw_name = passwdPtr.readCString();
          const pw_uid = passwdPtr.add(Process.pointerSize).readU32(); // 假设 pointerSize 是 4 或 8
          console.log("[+] getpwuid returned passwd struct:");
          console.log("    pw_name:", pw_name);
          console.log("    pw_uid:", pw_uid);
        }
      }
    });
    console.log("[+] Hooked getpwuid in libc.so");
  } else {
    console.log("[-] Could not find getpwuid in libc.so");
  }
} else {
  console.log("[-] This script is for Android only.");
}
```

**使用 Frida 调试步骤:**

1. **确保设备已 root 并且安装了 Frida server。**
2. **将上述 JavaScript 代码保存为 `hook_getpwuid.js`。**
3. **找到你想要监控的 Android 进程的进程 ID (PID)。** 可以使用 `adb shell ps | grep <process_name>` 命令。
4. **运行 Frida 命令来注入 hook:**
   ```bash
   frida -U -f <package_name> -l hook_getpwuid.js
   # 或者，如果进程已经在运行：
   frida -U <process_name> -l hook_getpwuid.js
   # 或者使用 PID:
   frida -U -p <pid> -l hook_getpwuid.js
   ```
5. **在 Frida 的控制台中，你将看到 `getpwuid` 函数被调用时的 UID 参数以及返回的 `passwd` 结构体的信息。**

**示例场景:**

假设你想知道当系统服务 `system_server` 获取 "root" 用户信息时，`getpwuid` 是如何被调用的。你可以：

1. 找到 `system_server` 的 PID。
2. 使用 Frida hook `system_server` 进程并监控 `getpwuid`。
3. 在设备上执行一些可能触发获取用户信息的操作（例如，查看进程列表）。
4. 查看 Frida 控制台的输出，观察 `getpwuid` 是否被调用，以及传入的 UID 是多少（期望是 0，对应 "root" 用户）。

这个测试文件 `bionic/tests/grp_pwd_test.cpp` 通过大量的测试用例，确保了 Android Bionic 库中用户和组管理相关函数的正确性和健壮性，这对于 Android 系统的安全性和功能正常运行至关重要。

Prompt: 
```
这是目录为bionic/tests/grp_pwd_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

// Below are the header files we want to test.
#include <grp.h>
#include <pwd.h>

#include <errno.h>
#include <limits.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <unistd.h>

#include <set>
#include <vector>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <private/android_filesystem_config.h>

#if defined(__BIONIC__)
#include <android/api-level.h>
#include <android-base/properties.h>
#endif

// Generated android_ids array
#include "generated_android_ids.h"

#include "utils.h"

using android::base::Join;
using android::base::ReadFileToString;
using android::base::Split;
using android::base::StartsWith;

using namespace std::literals;

enum uid_type_t {
  TYPE_APP,
  TYPE_SYSTEM,
  TYPE_VENDOR,
};

#if defined(__BIONIC__)

static void check_passwd(const passwd* pwd, const char* username, uid_t uid, uid_type_t uid_type,
                         bool check_username) {
  ASSERT_TRUE(pwd != nullptr);
  if (check_username) {
    EXPECT_STREQ(username, pwd->pw_name);
  }
  EXPECT_EQ(uid, pwd->pw_uid);
  EXPECT_EQ(uid, pwd->pw_gid);
  EXPECT_EQ(nullptr, pwd->pw_passwd);
#ifdef __LP64__
  EXPECT_EQ(nullptr, pwd->pw_gecos);
#endif

  if (uid_type == TYPE_APP) {
    EXPECT_STREQ("/data", pwd->pw_dir);
  } else {
    EXPECT_STREQ("/", pwd->pw_dir);
  }

  // This has changed over time and that causes new GSI + old vendor images testing to fail.
  // This parameter doesn't matter on Android, so simply ignore its value for older vendor images.
  if (android::base::GetIntProperty("ro.product.first_api_level", 0) >= 30) {
    EXPECT_STREQ("/bin/sh", pwd->pw_shell);
  }
}

static void check_getpwuid(const char* username, uid_t uid, uid_type_t uid_type,
                           bool check_username) {
  errno = 0;
  passwd* pwd = getpwuid(uid);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getpwuid");
  check_passwd(pwd, username, uid, uid_type, check_username);
}

static void check_getpwnam(const char* username, uid_t uid, uid_type_t uid_type,
                           bool check_username) {
  errno = 0;
  passwd* pwd = getpwnam(username);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getpwnam");
  check_passwd(pwd, username, uid, uid_type, check_username);
}

static void check_getpwuid_r(const char* username, uid_t uid, uid_type_t uid_type,
                             bool check_username) {
  passwd pwd_storage;
  char buf[512];
  int result;

  errno = 0;
  passwd* pwd = nullptr;
  result = getpwuid_r(uid, &pwd_storage, buf, sizeof(buf), &pwd);
  ASSERT_EQ(0, result);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getpwuid_r");
  check_passwd(pwd, username, uid, uid_type, check_username);
}

static void check_getpwnam_r(const char* username, uid_t uid, uid_type_t uid_type,
                             bool check_username) {
  passwd pwd_storage;
  char buf[512];
  int result;

  errno = 0;
  passwd* pwd = nullptr;
  result = getpwnam_r(username, &pwd_storage, buf, sizeof(buf), &pwd);
  ASSERT_EQ(0, result);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getpwnam_r");
  check_passwd(pwd, username, uid, uid_type, check_username);
}

static void check_get_passwd(const char* username, uid_t uid, uid_type_t uid_type,
                             bool check_username = true) {
  SCOPED_TRACE("username '"s + username + "'");
  check_getpwuid(username, uid, uid_type, check_username);
  check_getpwnam(username, uid, uid_type, check_username);
  check_getpwuid_r(username, uid, uid_type, check_username);
  check_getpwnam_r(username, uid, uid_type, check_username);
}

static void expect_no_passwd_id(uid_t uid) {
  SCOPED_TRACE("uid '" + std::to_string(uid) + "'");
  errno = 0;
  passwd* passwd = nullptr;
  passwd = getpwuid(uid);
  EXPECT_EQ(nullptr, passwd) << "name = '" << passwd->pw_name << "'";
  EXPECT_ERRNO(ENOENT);

  struct passwd passwd_storage;
  char buf[512];
  EXPECT_EQ(ENOENT, getpwuid_r(uid, &passwd_storage, buf, sizeof(buf), &passwd));
  EXPECT_EQ(nullptr, passwd) << "name = '" << passwd->pw_name << "'";
}

static void expect_no_passwd_name(const char* username) {
  SCOPED_TRACE("username '"s + username + "'");
  errno = 0;
  passwd* passwd = nullptr;
  passwd = getpwnam(username);
  EXPECT_EQ(nullptr, passwd) << "name = '" << passwd->pw_name << "'";
  EXPECT_ERRNO(ENOENT);

  struct passwd passwd_storage;
  char buf[512];
  EXPECT_EQ(ENOENT, getpwnam_r(username, &passwd_storage, buf, sizeof(buf), &passwd));
  EXPECT_EQ(nullptr, passwd) << "name = '" << passwd->pw_name << "'";
}

#else // !defined(__BIONIC__)

static void check_get_passwd(const char* /* username */, uid_t /* uid */, uid_type_t /* uid_type */,
                             bool /* check_username */) {
  GTEST_SKIP() << "bionic-only test";
}

static void check_get_passwd(const char* /* username */, uid_t /* uid */, uid_type_t /* uid_type */) {
  GTEST_SKIP() << "bionic-only test";
}

static void expect_no_passwd_id(uid_t /* uid */) {
  GTEST_SKIP() << "bionic-only test";
}

static void expect_no_passwd_name(const char* /* username */) {
  GTEST_SKIP() << "bionic-only test";
}

#endif

TEST(pwd, getpwnam_platform_ids) {
  check_get_passwd("root", 0, TYPE_SYSTEM);
  check_get_passwd("daemon", 1, TYPE_SYSTEM);
  check_get_passwd("bin", 2, TYPE_SYSTEM);

  check_get_passwd("system", 1000, TYPE_SYSTEM);
  check_get_passwd("radio", 1001, TYPE_SYSTEM);

  check_get_passwd("shell", 2000, TYPE_SYSTEM);

  check_get_passwd("nobody", 9999, TYPE_SYSTEM);
}

TEST(pwd, getpwnam_oem_ids) {
  check_get_passwd("oem_2900", 2900, TYPE_VENDOR, false);
  check_get_passwd("oem_2945", 2945, TYPE_VENDOR, false);
  check_get_passwd("oem_2999", 2999, TYPE_VENDOR, false);
  check_get_passwd("oem_5000", 5000, TYPE_VENDOR, false);
  check_get_passwd("oem_5454", 5454, TYPE_VENDOR, false);
  check_get_passwd("oem_5999", 5999, TYPE_VENDOR, false);
}

TEST(pwd, getpwnam_non_exist) {
  expect_no_passwd_id(999);   // End of the system reserved range, unallocated.
  expect_no_passwd_id(1999);  // End of the system reserved range, unallocated.
  expect_no_passwd_id(2899);  // End of the system reserved range, unallocated.

  // These ranges are for GIDs only.
  expect_no_passwd_id(20000);
  expect_no_passwd_id(30000);
  expect_no_passwd_id(40000);
  expect_no_passwd_id(50000);

  // These should not be parsed as users, only as groups.
  expect_no_passwd_name("u0_a9999_cache");
  expect_no_passwd_name("u0_a9999_ext");
  expect_no_passwd_name("u0_a9999_ext_cache");
  expect_no_passwd_name("all_a9999");
}

TEST(pwd, getpwnam_u0_app_ids) {
  check_get_passwd("u0_a0", 10000, TYPE_APP);
  check_get_passwd("u0_a1234", 11234, TYPE_APP);
  check_get_passwd("u0_a9999", 19999, TYPE_APP);

  check_get_passwd("u0_i1", 90001, TYPE_APP);
  check_get_passwd("u0_i4545", 94545, TYPE_APP);
  check_get_passwd("u0_i9999", 99999, TYPE_APP);
}

TEST(pwd, getpwnam_app_id_u1_ids) {
  check_get_passwd("u1_system", 101000, TYPE_SYSTEM);
  check_get_passwd("u1_radio", 101001, TYPE_SYSTEM);

  check_get_passwd("u1_a0", 110000, TYPE_APP);
  check_get_passwd("u1_a1234", 111234, TYPE_APP);
  check_get_passwd("u1_a9999", 119999, TYPE_APP);

  check_get_passwd("u1_i1", 190001, TYPE_APP);
  check_get_passwd("u1_i4545", 194545, TYPE_APP);
  check_get_passwd("u1_i9999", 199999, TYPE_APP);
}

TEST(pwd, getpwnam_app_id_u31_ids) {
  check_get_passwd("u31_system", 3101000, TYPE_SYSTEM);
  check_get_passwd("u31_radio", 3101001, TYPE_SYSTEM);

  check_get_passwd("u31_a0", 3110000, TYPE_APP);
  check_get_passwd("u31_a1234", 3111234, TYPE_APP);
  check_get_passwd("u31_a9999", 3119999, TYPE_APP);

  check_get_passwd("u31_i1", 3190001, TYPE_APP);
  check_get_passwd("u31_i4545", 3194545, TYPE_APP);
  check_get_passwd("u31_i9999", 3199999, TYPE_APP);
}

TEST(pwd, getpwnam_app_id_not_allowed_platform) {
  expect_no_passwd_name("u1_root");
  expect_no_passwd_name("u1_debuggerd");

  expect_no_passwd_name("u31_root");
  expect_no_passwd_name("u31_debuggerd");
}

TEST(pwd, getpwuid_app_id_u1_non_exist) {
  expect_no_passwd_id(100000);  // There is no 'root' for secondary users.
  expect_no_passwd_id(101999);  // End of the system reserved range, unallocated.
  expect_no_passwd_id(102900);  // The OEM ranges were never allocated to secondary users.
  expect_no_passwd_id(105000);  // The OEM ranges were never allocated to secondary users.

  // These ranges are for GIDs only.
  expect_no_passwd_id(120000);
  expect_no_passwd_id(130000);
  expect_no_passwd_id(140000);
  expect_no_passwd_id(150000);
}

TEST(pwd, getpwuid_app_id_u31_non_exist) {
  expect_no_passwd_id(3100000);  // There is no 'root' for secondary users.
  expect_no_passwd_id(3101999);  // End of the system reserved range, unallocated.
  expect_no_passwd_id(3102900);  // The OEM ranges were never allocated to secondary users.
  expect_no_passwd_id(3105000);  // The OEM ranges were never allocated to secondary users.

  // These ranges are for GIDs only.
  expect_no_passwd_id(3120000);
  expect_no_passwd_id(3130000);
  expect_no_passwd_id(3140000);
  expect_no_passwd_id(3150000);
}

TEST(pwd, getpwnam_r_alignment) {
#if defined(__BIONIC__)
  passwd pwd_storage;
  alignas(16) char buf[512];
  passwd* pwd;
  int result = getpwnam_r("root", &pwd_storage, buf + 1, sizeof(buf) - 1, &pwd);
  ASSERT_EQ(0, result);
  check_passwd(pwd, "root", 0, TYPE_SYSTEM, true);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pwd, getpwuid_r_alignment) {
#if defined(__BIONIC__)
  passwd pwd_storage;
  alignas(16) char buf[512];
  passwd* pwd;
  int result = getpwuid_r(0, &pwd_storage, buf + 1, sizeof(buf) - 1, &pwd);
  ASSERT_EQ(0, result);
  check_passwd(pwd, "root", 0, TYPE_SYSTEM, true);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pwd, getpwnam_r_reentrancy) {
#if defined(__BIONIC__)
  passwd pwd_storage[2];
  char buf[2][512];
  passwd* pwd[3];
  int result = getpwnam_r("root", &pwd_storage[0], buf[0], sizeof(buf[0]), &pwd[0]);
  ASSERT_EQ(0, result);
  check_passwd(pwd[0], "root", 0, TYPE_SYSTEM, true);
  pwd[1] = getpwnam("system");
  ASSERT_NE(nullptr, pwd[1]);
  check_passwd(pwd[1], "system", 1000, TYPE_SYSTEM, true);
  result = getpwnam_r("radio", &pwd_storage[1], buf[1], sizeof(buf[1]), &pwd[2]);
  ASSERT_EQ(0, result);
  check_passwd(pwd[2], "radio", 1001, TYPE_SYSTEM, true);
  check_passwd(pwd[0], "root", 0, TYPE_SYSTEM, true);
  check_passwd(pwd[1], "system", 1000, TYPE_SYSTEM, true);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pwd, getpwuid_r_reentrancy) {
#if defined(__BIONIC__)
  passwd pwd_storage[2];
  char buf[2][512];
  passwd* pwd[3];
  int result = getpwuid_r(0, &pwd_storage[0], buf[0], sizeof(buf[0]), &pwd[0]);
  ASSERT_EQ(0, result);
  check_passwd(pwd[0], "root", 0, TYPE_SYSTEM, true);
  pwd[1] = getpwuid(1000);
  ASSERT_NE(nullptr, pwd[1]);
  check_passwd(pwd[1], "system", 1000, TYPE_SYSTEM, true);
  result = getpwuid_r(1001, &pwd_storage[1], buf[1], sizeof(buf[1]), &pwd[2]);
  ASSERT_EQ(0, result);
  check_passwd(pwd[2], "radio", 1001, TYPE_SYSTEM, true);
  check_passwd(pwd[0], "root", 0, TYPE_SYSTEM, true);
  check_passwd(pwd[1], "system", 1000, TYPE_SYSTEM, true);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pwd, getpwnam_r_large_enough_suggested_buffer_size) {
#if defined(__BIONIC__)
  long size = sysconf(_SC_GETPW_R_SIZE_MAX);
  ASSERT_GT(size, 0);
  char buf[size];
  passwd pwd_storage;
  passwd* pwd;
  ASSERT_EQ(0, getpwnam_r("root", &pwd_storage, buf, size, &pwd));
  check_passwd(pwd, "root", 0, TYPE_SYSTEM, true);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

#if defined(__BIONIC__)
template <typename T>
static void expect_ids(T ids, bool is_group) {
  std::set<typename T::key_type> expected_ids;
  // Ensure that all android_ids are iterated through.
  for (size_t n = 0; n < android_id_count; ++n) {
    EXPECT_EQ(1U, ids.count(android_ids[n].aid)) << "android_ids[n].aid: " << android_ids[n].aid;
    expected_ids.emplace(android_ids[n].aid);
  }

  auto expect_range = [&ids, &expected_ids](uid_t start, uid_t end) {
    for (size_t n = start; n <= end; ++n) {
      EXPECT_EQ(1U, ids.count(n)) << "n: " << n;
      expected_ids.emplace(n);
    }
  };

  // Ensure that all reserved ranges are iterated through.
  expect_range(AID_OEM_RESERVED_START, AID_OEM_RESERVED_END);
  expect_range(AID_OEM_RESERVED_2_START, AID_OEM_RESERVED_2_END);
  expect_range(AID_APP_START, AID_APP_END);
  if (is_group) {
    expect_range(AID_CACHE_GID_START, AID_CACHE_GID_END);
    expect_range(AID_EXT_GID_START, AID_EXT_GID_END);
    expect_range(AID_EXT_CACHE_GID_START, AID_EXT_CACHE_GID_END);
    expect_range(AID_SHARED_GID_START, AID_SHARED_GID_END);
  }
  expect_range(AID_ISOLATED_START, AID_ISOLATED_END);

  // Prior to R, we didn't have a mechanism to create vendor AIDs in the system or other non-vendor
  // partitions, therefore we disabled the rest of these checks for older API levels.
  if (android::base::GetIntProperty("ro.product.first_api_level", 0) <= 29) {
    return;
  }

  auto allow_range = [&ids](uid_t start, uid_t end) {
    for (size_t n = start; n <= end; ++n) {
      ids.erase(n);
    }
  };

  allow_range(AID_SYSTEM_RESERVED_START, AID_SYSTEM_EXT_RESERVED_END);

  // Ensure that no other ids were returned.
  auto return_differences = [&ids, &expected_ids] {
    std::vector<typename T::key_type> missing_from_ids;
    std::set_difference(expected_ids.begin(), expected_ids.end(), ids.begin(), ids.end(),
                        std::inserter(missing_from_ids, missing_from_ids.begin()));
    std::vector<typename T::key_type> extra_in_ids;
    std::set_difference(ids.begin(), ids.end(), expected_ids.begin(), expected_ids.end(),
                        std::inserter(extra_in_ids, extra_in_ids.begin()));
    std::string result;
    if (!missing_from_ids.empty()) {
      result += "Missing ids from results: " + Join(missing_from_ids, " ");
    }
    if (!extra_in_ids.empty()) {
      if (!result.empty()) result += ", ";
      result += "Extra ids in results: " + Join(extra_in_ids, " ");
    }
    return result;
  };

  // AID_UPROBESTATS (1093) was added in API level 35, but "trunk stable" means
  // that the 2024Q* builds are tested with the _previous_ release's CTS.
  if (android::base::GetIntProperty("ro.build.version.sdk", 0) == 34) {
#if !defined(AID_UPROBESTATS)
#define AID_UPROBESTATS 1093
#endif
    ids.erase(AID_UPROBESTATS);
    expected_ids.erase(AID_UPROBESTATS);
    if (getpwuid(AID_UPROBESTATS)) {
      EXPECT_STREQ(getpwuid(AID_UPROBESTATS)->pw_name, "uprobestats");
    }
  }
  // AID_VIRTUALMACHINE (3013) was added in API level 35, but "trunk stable" means
  // that the 2024Q* builds are tested with the _previous_ release's CTS.
  if (android::base::GetIntProperty("ro.build.version.sdk", 0) == 34) {
#if !defined(AID_VIRTUALMACHINE)
#define AID_VIRTUALMACHINE 3013
#endif
    ids.erase(AID_VIRTUALMACHINE);
    expected_ids.erase(AID_VIRTUALMACHINE);
    if (getpwuid(AID_VIRTUALMACHINE)) {
      EXPECT_STREQ(getpwuid(AID_VIRTUALMACHINE)->pw_name, "virtualmachine");
    }
  }
  // AID_CROS_EC (1094) was added in API level 36, but "trunk stable" means
  // that the 2024Q* builds are tested with the _previous_ release's CTS.
  if (android::base::GetIntProperty("ro.build.version.sdk", 0) == 35) {
#if !defined(AID_CROS_EC)
#define AID_CROS_EC 1094
#endif
    ids.erase(AID_CROS_EC);
    expected_ids.erase(AID_CROS_EC);
    if (getpwuid(AID_CROS_EC)) {
      EXPECT_STREQ(getpwuid(AID_CROS_EC)->pw_name, "cros_ec");
    }
  }
  // AID_MMD (1095) was added in API level 36, but "trunk stable" means
  // that the 2024Q* builds are tested with the _previous_ release's CTS.
  if (android::base::GetIntProperty("ro.build.version.sdk", 0) == 35) {
#if !defined(AID_MMD)
#define AID_MMD 1095
#endif
    ids.erase(AID_MMD);
    expected_ids.erase(AID_MMD);
    if (getpwuid(AID_MMD)) {
      EXPECT_STREQ(getpwuid(AID_MMD)->pw_name, "mmd");
    }
  }

  EXPECT_EQ(expected_ids, ids) << return_differences();
}
#endif

TEST(pwd, getpwent_iterate) {
#if defined(__BIONIC__)
  passwd* pwd;
  std::set<uid_t> uids;

  setpwent();
  while ((pwd = getpwent()) != nullptr) {
    ASSERT_TRUE(nullptr != pwd->pw_name);

    EXPECT_EQ(pwd->pw_gid, pwd->pw_uid) << "pwd->pw_uid: " << pwd->pw_uid;
    EXPECT_EQ(nullptr, pwd->pw_passwd) << "pwd->pw_uid: " << pwd->pw_uid;
#ifdef __LP64__
    EXPECT_TRUE(nullptr == pwd->pw_gecos) << "pwd->pw_uid: " << pwd->pw_uid;
#endif
    EXPECT_TRUE(nullptr != pwd->pw_shell);
    if (pwd->pw_uid < AID_APP_START || pwd->pw_uid == AID_OVERFLOWUID) {
      EXPECT_STREQ("/", pwd->pw_dir) << "pwd->pw_uid: " << pwd->pw_uid;
    } else {
      EXPECT_STREQ("/data", pwd->pw_dir) << "pwd->pw_uid: " << pwd->pw_uid;
    }

    EXPECT_EQ(0U, uids.count(pwd->pw_uid)) << "pwd->pw_uid: " << pwd->pw_uid;
    uids.emplace(pwd->pw_uid);
  }
  endpwent();

  expect_ids(uids, false);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

static void check_group(const group* grp, const char* group_name, gid_t gid,
                        bool check_groupname = true) {
  ASSERT_TRUE(grp != nullptr);
  if (check_groupname) {
    EXPECT_STREQ(group_name, grp->gr_name);
  }
  EXPECT_EQ(gid, grp->gr_gid);
  ASSERT_TRUE(grp->gr_mem != nullptr);
  if (check_groupname) {
    EXPECT_STREQ(group_name, grp->gr_mem[0]);
  }
  EXPECT_TRUE(grp->gr_mem[1] == nullptr);
}

#if defined(__BIONIC__)

static void check_getgrgid(const char* group_name, gid_t gid, bool check_groupname) {
  errno = 0;
  group* grp = getgrgid(gid);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getgrgid");
  check_group(grp, group_name, gid, check_groupname);
}

static void check_getgrnam(const char* group_name, gid_t gid, bool check_groupname) {
  errno = 0;
  group* grp = getgrnam(group_name);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getgrnam");
  check_group(grp, group_name, gid, check_groupname);
}

static void check_getgrgid_r(const char* group_name, gid_t gid, bool check_groupname) {
  group grp_storage;
  char buf[512];
  group* grp;

  errno = 0;
  int result = getgrgid_r(gid, &grp_storage, buf, sizeof(buf), &grp);
  ASSERT_EQ(0, result);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getgrgid_r");
  check_group(grp, group_name, gid, check_groupname);
}

static void check_getgrnam_r(const char* group_name, gid_t gid, bool check_groupname) {
  group grp_storage;
  char buf[512];
  group* grp;

  errno = 0;
  int result = getgrnam_r(group_name, &grp_storage, buf, sizeof(buf), &grp);
  ASSERT_EQ(0, result);
  ASSERT_ERRNO(0);
  SCOPED_TRACE("getgrnam_r");
  check_group(grp, group_name, gid, check_groupname);
}

static void check_get_group(const char* group_name, gid_t gid, bool check_groupname = true) {
  SCOPED_TRACE("groupname '"s + group_name + "'");
  check_getgrgid(group_name, gid, check_groupname);
  check_getgrnam(group_name, gid, check_groupname);
  check_getgrgid_r(group_name, gid, check_groupname);
  check_getgrnam_r(group_name, gid, check_groupname);
}

static void expect_no_group_id(gid_t gid) {
  SCOPED_TRACE("gid '" + std::to_string(gid) + "'");
  errno = 0;
  group* group = nullptr;
  group = getgrgid(gid);
  EXPECT_EQ(nullptr, group) << "name = '" << group->gr_name << "'";
  EXPECT_ERRNO(ENOENT);

  struct group group_storage;
  char buf[512];
  EXPECT_EQ(ENOENT, getgrgid_r(gid, &group_storage, buf, sizeof(buf), &group));
  EXPECT_EQ(nullptr, group) << "name = '" << group->gr_name << "'";
}

static void expect_no_group_name(const char* groupname) {
  SCOPED_TRACE("groupname '"s + groupname + "'");
  errno = 0;
  group* group = nullptr;
  group = getgrnam(groupname);
  EXPECT_EQ(nullptr, group) << "name = '" << group->gr_name << "'";
  EXPECT_ERRNO(ENOENT);

  struct group group_storage;
  char buf[512];
  EXPECT_EQ(ENOENT, getgrnam_r(groupname, &group_storage, buf, sizeof(buf), &group));
  EXPECT_EQ(nullptr, group) << "name = '" << group->gr_name << "'";
}

#else // !defined(__BIONIC__)

static void check_get_group(const char*, gid_t, bool) {
  GTEST_SKIP() << "bionic-only test";
}

static void check_get_group(const char*, gid_t) {
  GTEST_SKIP() << "bionic-only test";
}

static void expect_no_group_id(gid_t /* gid */) {
  GTEST_SKIP() << "bionic-only test";
}

static void expect_no_group_name(const char* /* groupname */) {
  GTEST_SKIP() << "bionic-only test";
}

#endif

TEST(grp, getgrnam_platform_ids) {
  check_get_group("root", 0);
  check_get_group("daemon", 1);
  check_get_group("bin", 2);

  check_get_group("system", 1000);
  check_get_group("radio", 1001);

  check_get_group("shell", 2000);

  check_get_group("nobody", 9999);
}

TEST(grp, getgrnam_oem_ids) {
  check_get_group("oem_2900", 2900, false);
  check_get_group("oem_2945", 2945, false);
  check_get_group("oem_2999", 2999, false);
  check_get_group("oem_5000", 5000, false);
  check_get_group("oem_5454", 5454, false);
  check_get_group("oem_5999", 5999, false);
}

TEST(grp, getgrnam_non_exist) {
  expect_no_passwd_id(999);   // End of the system reserved range, unallocated.
  expect_no_passwd_id(1999);  // End of the system reserved range, unallocated.
  expect_no_passwd_id(2899);  // End of the system reserved range, unallocated.
}

TEST(grp, getgrnam_u0_app_ids) {
  check_get_group("u0_a0", 10000);
  check_get_group("u0_a1234", 11234);
  check_get_group("u0_a9999", 19999);

  check_get_group("u0_a0_cache", 20000);
  check_get_group("u0_a1234_cache", 21234);
  check_get_group("u0_a9999_cache", 29999);

  check_get_group("u0_a0_ext", 30000);
  check_get_group("u0_a4545_ext", 34545);
  check_get_group("u0_a9999_ext", 39999);

  check_get_group("u0_a0_ext_cache", 40000);
  check_get_group("u0_a4545_ext_cache", 44545);
  check_get_group("u0_a9999_ext_cache", 49999);

  check_get_group("all_a0", 50000);
  check_get_group("all_a4545", 54545);
  check_get_group("all_a9999", 59999);

  check_get_group("u0_i1", 90001);
}

TEST(grp, getgrnam_u1_app_ids) {
  check_get_group("u1_system", 101000);
  check_get_group("u1_radio", 101001);

  check_get_group("u1_a0", 110000);
  check_get_group("u1_a1234", 111234);
  check_get_group("u1_a9999", 119999);

  check_get_group("u1_a0_cache", 120000);
  check_get_group("u1_a1234_cache", 121234);
  check_get_group("u1_a9999_cache", 129999);

  check_get_group("u1_a0_ext", 130000);
  check_get_group("u1_a4545_ext", 134545);
  check_get_group("u1_a9999_ext", 139999);

  check_get_group("u1_a0_ext_cache", 140000);
  check_get_group("u1_a4545_ext_cache", 144545);
  check_get_group("u1_a9999_ext_cache", 149999);

  check_get_group("u1_i1", 190001);
}

TEST(grp, getgrnam_u31_app_ids) {
  check_get_group("u31_system", 3101000);
  check_get_group("u31_radio", 3101001);

  check_get_group("u31_a0", 3110000);
  check_get_group("u31_a1234", 3111234);
  check_get_group("u31_a9999", 3119999);

  check_get_group("u31_a0_cache", 3120000);
  check_get_group("u31_a1234_cache", 3121234);
  check_get_group("u31_a9999_cache", 3129999);

  check_get_group("u31_a0_cache", 3120000);
  check_get_group("u31_a1234_cache", 3121234);
  check_get_group("u31_a9999_cache", 3129999);

  check_get_group("u31_a0_ext", 3130000);
  check_get_group("u31_a4545_ext", 3134545);
  check_get_group("u31_a9999_ext", 3139999);

  check_get_group("u31_a0_ext_cache", 3140000);
  check_get_group("u31_a4545_ext_cache", 3144545);
  check_get_group("u31_a9999_ext_cache", 3149999);

  check_get_group("u31_i1", 3190001);
}

TEST(grp, getpgram_app_id_not_allowed_platform) {
  expect_no_group_name("u1_root");
  expect_no_group_name("u1_debuggerd");

  expect_no_group_name("u31_root");
  expect_no_group_name("u31_debuggerd");
}

TEST(grp, getgrgid_app_id_u1_non_exist) {
  expect_no_group_id(100000);  // There is no 'root' for secondary users.
  expect_no_group_id(101999);  // End of the system reserved range, unallocated.
  expect_no_group_id(102900);  // The OEM ranges were never allocated to secondary users.
  expect_no_group_id(105000);  // The OEM ranges were never allocated to secondary users.

  // The shared range is shared among users, and therefore doesn't exist for secondary users.
  expect_no_group_id(150000);
}

TEST(grp, getgrgid_app_id_u31_non_exist) {
  expect_no_group_id(3100000);  // There is no 'root' for secondary users.
  expect_no_group_id(3101999);  // End of the system reserved range, unallocated.
  expect_no_group_id(3102900);  // The OEM ranges were never allocated to secondary users.
  expect_no_group_id(3105000);  // The OEM ranges were never allocated to secondary users.

  // The shared range is shared among users, and therefore doesn't exist for secondary users.
  expect_no_group_id(3150000);
}

TEST(grp, getgrnam_r_alignment) {
#if defined(__BIONIC__)
  group grp_storage;
  alignas(16) char buf[512];
  group* grp;
  int result = getgrnam_r("root", &grp_storage, buf + 1, sizeof(buf) - 1, &grp);
  ASSERT_EQ(0, result);
  check_group(grp, "root", 0);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(grp, getgrgid_r_alignment) {
#if defined(__BIONIC__)
  group grp_storage;
  alignas(16) char buf[512];
  group* grp;
  int result = getgrgid_r(0, &grp_storage, buf + 1, sizeof(buf) - 1, &grp);
  ASSERT_EQ(0, result);
  check_group(grp, "root", 0);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(grp, getgrnam_r_reentrancy) {
#if defined(__BIONIC__)
  group grp_storage[2];
  char buf[2][512];
  group* grp[3];
  int result = getgrnam_r("root", &grp_storage[0], buf[0], sizeof(buf[0]), &grp[0]);
  ASSERT_EQ(0, result);
  check_group(grp[0], "root", 0);
  grp[1] = getgrnam("system");
  check_group(grp[1], "system", 1000);
  result = getgrnam_r("radio", &grp_storage[1], buf[1], sizeof(buf[1]), &grp[2]);
  ASSERT_EQ(0, result);
  check_group(grp[2], "radio", 1001);
  check_group(grp[0], "root", 0);
  check_group(grp[1], "system", 1000);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(grp, getgrgid_r_reentrancy) {
#if defined(__BIONIC__)
  group grp_storage[2];
  char buf[2][512];
  group* grp[3];
  int result = getgrgid_r(0, &grp_storage[0], buf[0], sizeof(buf[0]), &grp[0]);
  ASSERT_EQ(0, result);
  check_group(grp[0], "root", 0);
  grp[1] = getgrgid(1000);
  check_group(grp[1], "system", 1000);
  result = getgrgid_r(1001, &grp_storage[1], buf[1], sizeof(buf[1]), &grp[2]);
  ASSERT_EQ(0, result);
  check_group(grp[2], "radio", 1001);
  check_group(grp[0], "root", 0);
  check_group(grp[1], "system", 1000);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(grp, getgrnam_r_large_enough_suggested_buffer_size) {
  long size = sysconf(_SC_GETGR_R_SIZE_MAX);
  ASSERT_GT(size, 0);
  char buf[size];
  group grp_storage;
  group* grp;
  ASSERT_EQ(0, getgrnam_r("root", &grp_storage, buf, size, &grp));
  check_group(grp, "root", 0);
}

TEST(grp, getgrent_iterate) {
#if defined(__BIONIC__)
  group* grp;
  std::set<gid_t> gids;

  setgrent();
  while ((grp = getgrent()) != nullptr) {
    ASSERT_TRUE(grp->gr_name != nullptr) << "grp->gr_gid: " << grp->gr_gid;
    ASSERT_TRUE(grp->gr_mem != nullptr) << "grp->gr_gid: " << grp->gr_gid;
    EXPECT_STREQ(grp->gr_name, grp->gr_mem[0]) << "grp->gr_gid: " << grp->gr_gid;
    EXPECT_TRUE(grp->gr_mem[1] == nullptr) << "grp->gr_gid: " << grp->gr_gid;

    EXPECT_EQ(0U, gids.count(grp->gr_gid)) << "grp->gr_gid: " << grp->gr_gid;
    gids.emplace(grp->gr_gid);
  }
  endgrent();

  expect_ids(gids, true);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(grp, getgrouplist) {
#if defined(__BIONIC__)
  // Query the number of groups.
  int ngroups = 0;
  ASSERT_EQ(-1, getgrouplist("root", 123, nullptr, &ngroups));
  ASSERT_EQ(1, ngroups);

  // Query the specific groups (just the one you pass in on Android).
  ngroups = 8;
  gid_t groups[ngroups];
  ASSERT_EQ(1, getgrouplist("root", 123, groups, &ngroups));
  ASSERT_EQ(1, ngroups);
  ASSERT_EQ(123u, groups[0]);
#else
  GTEST_SKIP() << "bionic-only test (groups too unpredictable)";
#endif
}

TEST(grp, initgroups) {
  if (getuid() != 0) GTEST_SKIP() << "test requires root";
  ASSERT_EQ(0, initgroups("root", 0));
}

#if defined(__BIONIC__)
static void TestAidNamePrefix(const std::string& file_path) {
  std::string file_contents;
  if (!ReadFileToString(file_path, &file_contents)) {
    // If we cannot read this file, then there are no vendor defind AID names, in which case this
    // test passes by default.
    return;
  }
  auto lines = Split(file_contents, "\n");
  for (const auto& line : lines) {
    if (line.empty()) continue;
    auto name = Split(line, ":")[0];
    EXPECT_TRUE(StartsWith(name, "vendor_"));
  }
}
#endif

TEST(pwd, vendor_prefix_users) {
#if defined(__BIONIC__)
  if (android::base::GetIntProperty("ro.product.first_api_level", 0) <= 28) {
    return;
  }

  TestAidNamePrefix("/vendor/etc/passwd");
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pwd, vendor_prefix_groups) {
#if defined(__BIONIC__)
  if (android::base::GetIntProperty("ro.product.first_api_level", 0) <= 28) {
    return;
  }

  TestAidNamePrefix("/vendor/etc/group");
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

"""

```
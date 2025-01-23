Response:
Let's break down the thought process for generating the comprehensive analysis of `bionic/libc/bionic/grp_pwd.cpp`.

1. **Understanding the Request:** The request asks for a detailed breakdown of the `grp_pwd.cpp` file, covering its functionality, relationship to Android, implementation details of libc functions, dynamic linking aspects, logical reasoning with examples, common errors, and how the Android framework reaches this code, including a Frida hook example.

2. **Initial Code Scan and Identification of Key Areas:**  The first step is to read through the code, identifying the main sections and data structures. This involves looking for:
    * Includes: What other headers are used? This gives clues about the file's dependencies and potential functionality. `grp.h`, `pwd.h`, `unistd.h`, `sys/system_properties.h` immediately suggest user and group management.
    * Global Data Structures:  `passwd_files`, `group_files`, `android_ids`, `user_ranges`, `group_ranges`. These are central to how the file operates.
    * Function Declarations and Definitions:  Spotting functions like `getpwuid`, `getpwnam`, `getgrgid`, `getgrnam`, `setpwent`, `endpwent`, `getpwent`, `setgrent`, `endgrent`, `getgrent` is crucial. These are standard POSIX functions related to user and group information. Also noting internal helper functions like `android_iinfo_to_passwd`, `app_id_from_name`, etc. is important.
    * Conditional Compilation (`#if defined(__ANDROID__)`):  This highlights platform-specific behavior.
    * Static Assertions:  These provide important constraints and design choices.

3. **Categorizing Functionality:** Based on the initial scan, group the identified elements into logical categories:
    * **User and Group Information Retrieval:** This is the core functionality, driven by the POSIX functions.
    * **Android-Specific User/Group ID Management:**  The `android_ids`, `user_ranges`, `group_ranges`, and related functions fall here. The naming conventions like `uX_aY`, `uX_iY` are also important.
    * **File-Based Lookups:** The `passwd_files` and `group_files` arrays indicate a fallback mechanism to `/etc/passwd` and `/etc/group`.
    * **OEM-Specific Handling:** The `oem_id_from_name` and `oem_id_to_passwd/group` functions form a distinct category.
    * **Internal State Management:** The `group_state_t` and `passwd_state_t` structures and the TLS-based access methods are crucial for thread safety.

4. **Explaining Functionality and Android Relevance:** For each category identified:
    * **Describe the General Purpose:**  What does this part of the code *do*?
    * **Connect to Android:** How does this relate to Android's security model, permission system, and user/application isolation?  Examples are key here (application UIDs, system UIDs, etc.).

5. **Delving into Libc Function Implementation:**  Focus on the standard POSIX functions:
    * **Internal Logic:** Explain how each function works, tracing its steps through the code. For example, `getpwuid` first checks `android_ids`, then OEM IDs, then app IDs, and finally file-based lookups.
    * **Data Structures Involved:**  Point out which global structures and internal state variables are used by each function.
    * **Error Handling:** Note how errors are indicated (e.g., returning `nullptr` and setting `errno`).

6. **Addressing Dynamic Linking:**
    * **Identify Relevant Aspects:**  The code itself doesn't directly perform dynamic linking, but it *is part of* `libc.so`, which *is* dynamically linked.
    * **SO Layout Sample:** Provide a simplified example of how `libc.so` might be structured.
    * **Linking Process:** Explain the general dynamic linking process in Android, focusing on how symbols from `libc.so` are resolved by other processes. *Initially, I might think about specific symbols within this file, but it's more accurate to discuss the linking of the entire `libc.so` library.*

7. **Logical Reasoning and Examples:**
    * **Choose Key Functions:**  Select functions like `app_id_from_name` and `app_id_to_passwd/group` where input-output relationships are clear.
    * **Create Test Cases:** Design scenarios with different inputs (valid and invalid names/IDs) and predict the outputs based on the code's logic.

8. **Common Usage Errors:** Think about how developers might misuse these functions:
    * **Buffer Overflow:**  The `_r` versions are designed to prevent this, so highlight the risk of using the non-`_r` versions incorrectly.
    * **Incorrect Assumptions:**  Misunderstanding the Android UID/GID scheme is a common source of errors.

9. **Android Framework/NDK Path and Frida Hook:**
    * **Trace the Call Stack:**  Start from a high-level Android component (e.g., ActivityManager, PackageManager) and explain how it might need user/group information, eventually leading to calls to the functions in `grp_pwd.cpp`. Mention NDK usage as well.
    * **Frida Hook Example:** Provide a concrete Frida script that intercepts a function like `getpwuid` and logs its arguments and return value. This demonstrates practical debugging.

10. **Review and Refine:**  After drafting the initial analysis, review it for clarity, accuracy, and completeness. Ensure all parts of the request are addressed. Check for any technical inaccuracies or areas that could be explained better. For instance, initially, I might focus too much on the specific details of `android_ids`, but it's important to also explain the broader concepts of dynamic UIDs/GIDs. Also, ensure the language is accessible and well-organized.

By following this structured approach, breaking down the problem into smaller, manageable parts, and focusing on both the general concepts and specific code details, a comprehensive and accurate analysis can be generated. The iterative process of scanning, categorizing, explaining, and refining is crucial.
这个文件 `bionic/libc/bionic/grp_pwd.cpp` 是 Android Bionic C 库中负责处理用户和组信息的关键组成部分。它实现了与用户和组数据库交互的功能，并提供了应用程序查询和操作这些信息的接口。

**它的功能主要包括：**

1. **读取和解析用户和组数据库文件：**
   - 该文件定义了 `passwd_files` 和 `group_files` 数组，指定了系统上存储用户和组信息的文件路径，例如 `/etc/passwd` 和 `/etc/group`。在 Android 中，这些通常是指向 `/system/etc/passwd` 和 `/system/etc/group` 的符号链接，同时也支持从 vendor, odm, product, system_ext 分区读取。
   - 它使用 `PasswdFile` 和 `GroupFile` 类（定义在 `grp_pwd_file.h` 中，此处未提供代码）来解析这些文件的内容。

2. **提供 POSIX 标准的 getpwnam、getpwuid、getpwent、getgrnam、getgrgid、getgrent 等函数：**
   - 这些函数允许程序通过用户名、用户 ID、组名、组 ID 或迭代的方式获取用户和组信息。

3. **处理 Android 特有的用户和组 ID 分配：**
   - Android 使用一套复杂的 UID/GID 分配方案，包括系统 UID/GID、应用 UID/GID、隔离进程 UID/GID 等。
   - 该文件维护了一个 `android_ids` 数组（由 `generated_android_ids.h` 生成），其中包含了预定义的 Android 系统用户和组的信息，例如 `system`, `radio`, `shell` 等。
   - 它定义了 `user_ranges` 和 `group_ranges` 数组，描述了应用 UID/GID 的分配范围，并使用 `is_valid_app_id` 函数来验证 UID/GID 是否属于有效的应用范围。
   - 它实现了 `app_id_from_name` 和 `app_id_to_passwd/group` 等函数，用于在 Android 特有的用户名/组名（例如 `u0_a100`, `u2_i200`) 和 UID/GID 之间进行转换。

4. **处理 OEM 厂商自定义的 UID/GID：**
   - Android 允许 OEM 厂商定义自己的 UID/GID 范围。
   - 该文件提供了 `is_oem_id`, `oem_id_from_name`, `oem_id_to_passwd`, `oem_id_to_group` 等函数来处理这些 OEM 特有的 ID。

5. **线程安全：**
   - 它使用线程局部存储 (TLS) 来存储 `passwd_state_t` 和 `group_state_t` 结构体，确保在多线程环境下访问用户和组信息时的安全性。

**与 Android 功能的关系及举例说明：**

- **权限管理：** Android 的权限系统大量依赖于 UID 和 GID。每个应用程序都运行在独立的 UID 下，系统通过检查进程的 UID 和文件的权限（用户、组、其他用户的读写执行权限）来控制访问。`grp_pwd.cpp` 提供的函数是获取这些 UID 和 GID 信息的基础。
    - **例子：** 当一个应用尝试读取 `/data/data/com.example.myapp/some_file` 时，系统会检查该应用的 UID 是否与文件的所有者 UID 匹配，或者该应用的 GID 是否与文件的所有者 GID 匹配，或者是否具有其他用户的权限。这个过程中，系统可能会调用 `getpwuid` 来查找应用对应的用户名，以便进行日志记录或其他操作。
- **进程隔离：** Android 使用 UID 来隔离不同的应用程序进程，防止它们互相访问彼此的数据。`grp_pwd.cpp` 确保了系统能够正确地识别和管理这些独立的进程。
    - **例子：** 当启动一个新的应用进程时，Zygote 进程会使用 `setuid` 和 `setgid` 系统调用将进程的 UID 和 GID 设置为该应用对应的 UID 和 GID。系统需要知道这个应用的 UID，而这通常涉及到查询用户数据库，`grp_pwd.cpp` 在这个过程中发挥作用。
- **系统服务：** 许多 Android 系统服务（如 `system_server`, `surfaceflinger` 等）以特定的系统 UID/GID 运行。`grp_pwd.cpp` 提供了获取这些系统服务身份信息的能力。
    - **例子：** `system_server` 进程可能需要知道 `radio` 用户的 UID，以便与其相关的进程进行通信或执行需要特定权限的操作。它会调用 `getpwnam("radio")` 来获取 `radio` 用户的相关信息。
- **文件系统权限：** 文件系统中的文件和目录都有所有者（UID）和所属组（GID）。`ls -l` 命令会显示这些信息，而这些信息的解析就依赖于 `getpwuid` 和 `getgrgid` 函数。
- **应用安装和卸载：** PackageManagerService 在安装和卸载应用程序时，会创建和删除相应的用户目录，并设置正确的文件权限，这些操作都需要知道应用程序的 UID。

**详细解释每一个 libc 函数的功能是如何实现的：**

以下是一些关键 libc 函数的实现细节：

- **`getpwuid(uid_t uid)`:**
    1. **查找预定义的 Android 用户：** 首先调用 `find_android_id_info(uid)` 在 `android_ids` 数组中查找与给定 `uid` 匹配的条目。如果找到，则调用 `android_iinfo_to_passwd` 将 `android_id_info` 结构体转换为 `passwd` 结构体。
    2. **查找 OEM 用户：** 如果在 `android_ids` 中未找到，则调用 `oem_id_to_passwd(uid, state)`。该函数遍历 `passwd_files` 指定的文件，使用 `PasswdFile::FindById` 查找匹配的条目。如果找到，则将文件中的信息填充到 `passwd_state_t` 结构体中。如果 `uid` 属于 OEM 保留范围，但未在文件中找到，则根据 `uid` 生成一个默认的 `passwd` 结构体，用户名格式为 `oem_<uid>`。
    3. **查找应用用户：** 如果以上两种方式都未找到，则调用 `app_id_to_passwd(uid, state)`。该函数根据 `uid` 的范围和格式（例如 `u0_a100`）生成相应的用户名、家目录和 shell，并填充到 `passwd` 结构体中。
    4. **错误处理：** 如果所有查找都失败，则设置 `errno` 为 `ENOENT` 并返回 `nullptr`。

- **`getpwnam(const char* login)`:**
    1. **查找预定义的 Android 用户：** 首先调用 `find_android_id_info(login)` 在 `android_ids` 数组中查找与给定用户名 `login` 匹配的条目。如果找到，则调用 `android_iinfo_to_passwd` 进行转换。
    2. **查找文件数据库中的用户：** 遍历 `passwd_files` 指定的文件，使用 `PasswdFile::FindByName` 查找匹配的条目。如果找到，则将文件中的信息填充到 `passwd_state_t` 结构体中。
    3. **查找 OEM 用户：** 调用 `oem_id_from_name(login)` 将用户名转换为 UID，然后调用 `oem_id_to_passwd` 进行查找。
    4. **查找应用用户：** 调用 `app_id_from_name(login, false)` 将用户名转换为 UID，然后调用 `app_id_to_passwd` 进行查找。
    5. **错误处理：** 如果所有查找都失败，则设置 `errno` 为 `ENOENT` 并返回 `nullptr`。

- **`getpwent()`:**
    - 该函数用于迭代获取所有用户条目。
    - 它使用 `passwd_state_t` 结构体中的 `getpwent_idx` 成员来跟踪当前的迭代位置。
    - 它首先遍历 `android_ids` 数组。
    - 然后遍历 OEM 保留的 UID 范围，并尝试使用 `oem_id_to_passwd` 获取用户信息。
    - 接着遍历系统扩展保留的 UID 范围，并尝试获取 OEM 用户信息。
    - 最后遍历应用 UID 范围，使用 `app_id_to_passwd` 获取用户信息。
    - 当所有用户都遍历完毕时，返回 `nullptr`。

- **`getgrgid(gid_t gid)`、`getgrnam(const char* name)`、`getgrent()`:**
    - 这些函数的实现逻辑与 `getpwuid`、`getpwnam`、`getpwent` 类似，只是它们操作的是组信息，并使用 `group_state_t` 结构体和 `group_files` 数组。

- **线程局部存储 (TLS)：**
    - `get_passwd_tls_buffer()` 和 `get_group_tls_buffer()` 函数使用 Bionic 的内部 TLS 机制 (`__get_bionic_tls()`) 来获取当前线程的 `passwd_state_t` 和 `group_state_t` 结构体的指针。
    - 这样做是为了保证每个线程都有自己独立的状态，避免多线程并发访问时的数据竞争问题。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`grp_pwd.cpp` 本身的代码不直接涉及 dynamic linker 的操作。但是，它编译后会链接到 `libc.so` 这个共享库中。当其他程序需要使用 `getpwuid` 等函数时，dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 会负责将这些函数的调用链接到 `libc.so` 中对应的实现。

**`libc.so` 布局样本 (简化)：**

```
libc.so:
  .text:
    ...
    getpwuid:  # getpwuid 函数的机器码
      ...
    getpwnam:  # getpwnam 函数的机器码
      ...
    getpwent:  # getpwent 函数的机器码
      ...
    ...
  .data:
    ...
    passwd_files:  # passwd_files 数组的数据
      ...
    group_files:   # group_files 数组的数据
      ...
    android_ids:   # android_ids 数组的数据
      ...
    ...
  .bss:
    ...
    # TLS 相关的数据，例如 passwd_state_t 和 group_state_t 的模板
    ...
  .dynamic:
    ...
    NEEDED libc.so  # 依赖自身，但这只是概念性的
    SONAME libc.so
    SYMTAB  # 符号表，包含导出的符号（例如 getpwuid）
    STRTAB  # 字符串表，包含符号名称等字符串
    ...
```

**链接的处理过程：**

1. **加载时链接：** 当一个应用程序（例如 `ls` 命令）启动时，操作系统会加载其可执行文件。在加载过程中，dynamic linker 会读取可执行文件的头部信息，找到其依赖的共享库列表（`NEEDED` 条目）。
2. **查找共享库：** dynamic linker 会在预定义的路径中搜索这些依赖的共享库，例如 `/system/lib64` 或 `/system/lib`。
3. **加载共享库：** 找到 `libc.so` 后，dynamic linker 会将其加载到进程的地址空间中。
4. **符号解析：** 当应用程序执行到调用 `getpwuid` 等函数的指令时，这些调用最初指向一个 PLT (Procedure Linkage Table) 条目。
5. **懒加载/立即加载：**  dynamic linker 可以选择懒加载或立即加载符号。
    - **懒加载：** 第一次调用时解析。PLT 条目会跳转到一个 resolver 函数，该函数会查找 `libc.so` 的符号表 (`SYMTAB`)，找到 `getpwuid` 的实际地址，并将该地址更新到 GOT (Global Offset Table) 中，同时更新 PLT 条目直接跳转到 GOT 中的地址。后续调用将直接跳转到 `getpwuid` 的实现。
    - **立即加载：** 在加载共享库时就解析所有符号。
6. **重定位：** 由于共享库被加载到进程地址空间的某个位置，其内部的代码和数据地址可能与编译时不同。dynamic linker 会根据可执行文件和共享库中的重定位信息，调整代码和数据中的地址引用，确保它们指向正确的内存位置。
7. **TLS 的处理：**  对于 `getpwuid` 等函数中访问的 TLS 数据（`passwd_state_t`），dynamic linker 和 C 库的运行时支持会确保每个线程都访问到自己独立的 TLS 副本。

**如果做了逻辑推理，请给出假设输入与输出：**

- **假设输入 (getpwnam)：** `login = "system"`
  - **逻辑推理：** `getpwnam` 首先在 `android_ids` 中查找。由于 "system" 是预定义的 Android 用户，它应该能在 `android_ids` 中找到。
  - **输出：** 返回指向 `passwd` 结构体的指针，该结构体包含 "system" 用户的 UID、GID 等信息。例如，`pw->pw_uid` 可能为 1000 (AID_SYSTEM)，`pw->pw_name` 为 "system"。

- **假设输入 (getpwuid)：** `uid = 1001` (假设 AID_RADIO)
  - **逻辑推理：** `getpwuid` 首先在 `android_ids` 中查找。UID 1001 对应于预定义的 Android 用户 "radio"。
  - **输出：** 返回指向 `passwd` 结构体的指针，包含 "radio" 用户的相关信息。

- **假设输入 (getpwnam)：** `login = "u0_a100"`
  - **逻辑推理：** `getpwnam` 在 `android_ids` 和文件数据库中找不到 "u0_a100"。然后它会调用 `app_id_from_name` 将 "u0_a100" 解析为 UID。根据 `app_id_from_name` 的逻辑，这会转换为 `0 * AID_USER_OFFSET + AID_APP_START + 100`。然后 `app_id_to_passwd` 会根据这个 UID 生成 `passwd` 结构体。
  - **输出：** 返回指向 `passwd` 结构体的指针，其中 `pw->pw_uid` 为计算出的 UID，`pw->pw_name` 为 "u0_a100"，`pw->pw_dir` 为 "/data"，`pw->pw_shell` 为 "/bin/sh"。

- **假设输入 (getpwnam)：** `login = "nonexistentuser"`
  - **逻辑推理：** `getpwnam` 在所有查找路径中都找不到名为 "nonexistentuser" 的用户。
  - **输出：** 返回 `nullptr`，并设置 `errno` 为 `ENOENT`.

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **缓冲区溢出 (使用非 `_r` 版本的函数)：**
   - `getpwnam` 和 `getgrnam` 等函数返回的 `passwd` 和 `group` 结构体中的字符串指针（如 `pw_name`, `gr_name` 等）指向静态分配的缓冲区。这些缓冲区可能是线程局部的，但大小是有限的。
   - **错误示例：**
     ```c
     passwd* pwd = getpwnam("someuser");
     char buffer[20];
     strcpy(buffer, pwd->pw_name); // 如果用户名超过 19 个字符，则会发生缓冲区溢出
     ```
   - **正确做法：** 使用 `getpwnam_r` 和 `getgrnam_r` 等函数，它们允许调用者提供自己的缓冲区，从而避免缓冲区溢出。

2. **忘记检查返回值：**
   - `getpwnam` 和 `getpwuid` 等函数在找不到用户或组时会返回 `nullptr` 并设置 `errno`。
   - **错误示例：**
     ```c
     passwd* pwd = getpwnam("nonexistentuser");
     printf("User ID: %d\n", pwd->pw_uid); // 如果 pwd 为 nullptr，则会解引用空指针
     ```
   - **正确做法：** 始终检查返回值并处理错误情况。

3. **在多线程环境中使用非线程安全的函数 (虽然此文件内部做了线程安全处理，但调用者仍然需要注意)：**
   - 尽管 `grp_pwd.cpp` 内部使用了 TLS 来保证线程安全，但如果调用者在没有适当同步的情况下，仍然可能出现问题，尤其是在修改全局状态或共享资源的情况下（虽然这里的函数主要用于读取）。

4. **假设特定的 UID/GID 值：**
   - Android 的 UID/GID 分配方案可能会在不同的 Android 版本或设备上有所不同。
   - **错误示例：**
     ```c
     if (getuid() == 1000) { // 假设 UID 1000 总是 system 用户
         // ...
     }
     ```
   - **正确做法：** 使用用户名或组名来查找用户或组信息，而不是硬编码 UID/GID 值。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `grp_pwd.cpp` 的路径：**

1. **Android Framework 组件的需求：** Android Framework 中的许多组件，如 ActivityManagerService, PackageManagerService, SystemServer 等，在进行权限检查、进程管理、用户信息查询等操作时，需要获取用户和组的信息。

2. **System API 调用：** Framework 组件通常会调用 Java 层的 API，例如 `android.os.UserHandle.getUserSerialNumber(int userId)` 或 `android.content.pm.PackageManager.getPackageUid(String packageName, int userId)`。

3. **JNI 调用到 Native 代码：** 这些 Java API 的实现最终会通过 JNI (Java Native Interface) 调用到 Android 运行时 (ART) 或 Dalvik 的 native 代码中。

4. **Bionic Libc 函数调用：** Android 运行时或 Framework 的 native 组件会调用 Bionic libc 提供的用户和组信息查询函数，例如 `getpwuid`, `getpwnam`, `getgrgid`, `getgrnam`。

5. **`grp_pwd.cpp` 中的实现：** 这些 Bionic libc 函数的实现就位于 `bionic/libc/bionic/grp_pwd.cpp` 文件中。

**NDK 到 `grp_pwd.cpp` 的路径：**

1. **NDK 应用的需求：** 使用 Android NDK 开发的 native 应用可以直接调用 Bionic libc 提供的标准 C 库函数。

2. **直接调用 Libc 函数：** NDK 应用可以直接调用 `pwd.h` 和 `grp.h` 中声明的函数，例如 `getpwuid(getuid())`。

3. **链接到 `libc.so`：** NDK 应用在编译时会链接到 `libc.so` 共享库。

4. **动态链接：** 当 NDK 应用运行时，dynamic linker 会将对 `getpwuid` 等函数的调用链接到 `libc.so` 中对应的实现，即 `grp_pwd.cpp` 中的代码。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `getpwuid` 函数并打印其参数和返回值的示例：

```javascript
if (Process.platform === 'android') {
  const getpwuidPtr = Module.findExportByName("libc.so", "getpwuid");

  if (getpwuidPtr) {
    Interceptor.attach(getpwuidPtr, {
      onEnter: function (args) {
        const uid = args[0].toInt();
        console.log(`[getpwuid Hook] UID: ${uid}`);
      },
      onLeave: function (retval) {
        if (retval.isNull()) {
          console.log("[getpwuid Hook] Returned NULL");
        } else {
          const passwdPtr = retval;
          const pw_name = passwdPtr.readPointer().readCString();
          const pw_uid = passwdPtr.add(Process.pointerSize).readU32();
          const pw_gid = passwdPtr.add(2 * Process.pointerSize).readU32();
          console.log(`[getpwuid Hook] Returned: { pw_name: "${pw_name}", pw_uid: ${pw_uid}, pw_gid: ${pw_gid} }`);
        }
      },
    });
    console.log("[Frida] getpwuid hook installed");
  } else {
    console.log("[Frida] getpwuid not found in libc.so");
  }
} else {
  console.log("[Frida] This script is for Android only.");
}
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_getpwuid.js`).
2. 确保你的 Android 设备已 root，并且安装了 Frida 和 Frida server。
3. 运行你要调试的目标进程。
4. 使用 Frida 命令将 hook 脚本注入到目标进程：
   ```bash
   frida -U -f <package_name_or_process_name> -l hook_getpwuid.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name_or_process_name> -l hook_getpwuid.js
   ```

**调试步骤：**

1. **运行目标进程：** 启动你想要观察其用户/组信息查询行为的 Android 应用或系统服务。
2. **注入 Frida 脚本：** 使用上述 Frida 命令将 hook 脚本注入到目标进程。
3. **观察输出：** 当目标进程调用 `getpwuid` 函数时，Frida 会拦截该调用，并打印出传递给 `getpwuid` 的 UID 参数以及返回的 `passwd` 结构体的内容（用户名、UID、GID）。
4. **分析调用栈：** 如果你需要更详细的调用路径，可以使用 Frida 的 `Stalker` API 来追踪函数的调用栈。

通过 Frida Hook，你可以动态地观察 Android Framework 或 NDK 应用如何调用 `getpwuid` 等函数，并了解它们在运行时如何获取用户和组信息，从而帮助你理解 Android 的权限管理和安全机制。

### 提示词
```
这是目录为bionic/libc/bionic/grp_pwd.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "private/grp_pwd.h"

#include <android/api-level.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <mntent.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unistd.h>

#include "private/ErrnoRestorer.h"
#include "private/android_filesystem_config.h"
#include "platform/bionic/macros.h"

#if defined(__ANDROID__)
// Generated android_ids array
#include "generated_android_ids.h"
#else
// Empty array for host; everything is from the database files
#include "empty_android_ids.h"
#endif

#include "grp_pwd_file.h"

static PasswdFile passwd_files[] = {
    {"/etc/passwd", "system_"},  // symlinks to /system/etc/passwd in Android
    {"/vendor/etc/passwd", "vendor_"},
    {"/odm/etc/passwd", "odm_"},
    {"/product/etc/passwd", "product_"},
    {"/system_ext/etc/passwd", "system_ext_"},
};

static GroupFile group_files[] = {
    {"/etc/group", "system_"},  // symlinks to /system/etc/group in Android
    {"/vendor/etc/group", "vendor_"},
    {"/odm/etc/group", "odm_"},
    {"/product/etc/group", "product_"},
    {"/system_ext/etc/group", "system_ext_"},
};

// POSIX seems to envisage an implementation where the <pwd.h> functions are
// implemented by brute-force searching with getpwent(3), and the <grp.h>
// functions are implemented similarly with getgrent(3). This means that it's
// okay for all the <grp.h> functions to share state, and all the <passwd.h>
// functions to share state, but <grp.h> functions can't clobber <passwd.h>
// functions' state and vice versa.
#include "bionic/pthread_internal.h"

static void init_group_state(group_state_t* state) {
  memset(state, 0, sizeof(group_state_t) - sizeof(state->getgrent_idx));
  state->group_.gr_name = state->group_name_buffer_;
  state->group_.gr_mem = state->group_members_;
  state->group_.gr_mem[0] = state->group_.gr_name;
}

static group_state_t* get_group_tls_buffer() {
  auto result = &__get_bionic_tls().group;
  init_group_state(result);
  return result;
}

static void init_passwd_state(passwd_state_t* state) {
  memset(state, 0, sizeof(passwd_state_t) - sizeof(state->getpwent_idx));
  state->passwd_.pw_name = state->name_buffer_;
  state->passwd_.pw_dir = state->dir_buffer_;
  state->passwd_.pw_shell = state->sh_buffer_;
}

static passwd_state_t* get_passwd_tls_buffer() {
  auto result = &__get_bionic_tls().passwd;
  init_passwd_state(result);
  return result;
}

static passwd* android_iinfo_to_passwd(passwd_state_t* state,
                                       const android_id_info* iinfo) {
  snprintf(state->name_buffer_, sizeof(state->name_buffer_), "%s", iinfo->name);
  snprintf(state->dir_buffer_, sizeof(state->dir_buffer_), "/");
  snprintf(state->sh_buffer_, sizeof(state->sh_buffer_), "/bin/sh");

  passwd* pw = &state->passwd_;
  pw->pw_uid   = iinfo->aid;
  pw->pw_gid   = iinfo->aid;
  return pw;
}

static group* android_iinfo_to_group(group_state_t* state,
                                     const android_id_info* iinfo) {
  snprintf(state->group_name_buffer_, sizeof(state->group_name_buffer_), "%s", iinfo->name);

  group* gr = &state->group_;
  gr->gr_gid = iinfo->aid;
  return gr;
}

static const android_id_info* find_android_id_info(unsigned id) {
  for (size_t n = 0; n < android_id_count; ++n) {
    if (android_ids[n].aid == id) {
      return &android_ids[n];
    }
  }
  return nullptr;
}

static const android_id_info* find_android_id_info(const char* name) {
  for (size_t n = 0; n < android_id_count; ++n) {
    if (!strcmp(android_ids[n].name, name)) {
      return &android_ids[n];
    }
  }
  return nullptr;
}

// These are a list of the reserved app ranges, and should never contain anything below
// AID_APP_START.  They exist per user, so a given uid/gid modulo AID_USER_OFFSET will map
// to these ranges.
struct IdRange {
  id_t start;
  id_t end;
};

static constexpr IdRange user_ranges[] = {
  { AID_APP_START, AID_APP_END },
  { AID_ISOLATED_START, AID_ISOLATED_END },
};

static constexpr IdRange group_ranges[] = {
  { AID_APP_START, AID_APP_END },
  { AID_CACHE_GID_START, AID_CACHE_GID_END },
  { AID_EXT_GID_START, AID_EXT_GID_END },
  { AID_EXT_CACHE_GID_START, AID_EXT_CACHE_GID_END },
  { AID_SHARED_GID_START, AID_SHARED_GID_END },
  { AID_ISOLATED_START, AID_ISOLATED_END },
};

template <class T, size_t N>
static constexpr bool verify_user_ranges_ascending(T (&ranges)[N]) {
  auto array_size = N;
  if (array_size < 2) return false;

  if (ranges[0].start > ranges[0].end) return false;

  for (size_t i = 1; i < array_size; ++i) {
    if (ranges[i].start > ranges[i].end) return false;
    if (ranges[i - 1].end > ranges[i].start) return false;
  }
  return true;
}

static_assert(verify_user_ranges_ascending(user_ranges), "user_ranges must have ascending ranges");
static_assert(verify_user_ranges_ascending(group_ranges), "user_ranges must have ascending ranges");

// This list comes from PackageManagerService.java, where platform AIDs are added to list of valid
// AIDs for packages via addSharedUserLPw().
static constexpr const id_t secondary_user_platform_ids[] = {
  AID_SYSTEM, AID_RADIO,          AID_LOG,           AID_NFC, AID_BLUETOOTH,
  AID_SHELL,  AID_SECURE_ELEMENT, AID_NETWORK_STACK,
};

static bool platform_id_secondary_user_allowed(id_t id) {
  for (const auto& allowed_id : secondary_user_platform_ids) {
    if (allowed_id == id) {
      return true;
    }
  }
  return false;
}

#if defined(__ANDROID__)
static bool is_valid_app_id(id_t id, bool is_group) {
  id_t appid = id % AID_USER_OFFSET;

  // AID_OVERFLOWUID is never a valid app id, so we explicitly return false to ensure this.
  // This is true across all users, as there is no reason to ever map this id into any user range.
  if (appid == AID_OVERFLOWUID) {
    return false;
  }

  auto ranges_size = is_group ? arraysize(group_ranges) : arraysize(user_ranges);
  auto ranges = is_group ? group_ranges : user_ranges;

  // If we're checking an appid that resolves below the user range, then it's a platform AID for a
  // seconary user. We only allow a reduced set of these, so we must check that it is allowed.
  if (appid < ranges[0].start && platform_id_secondary_user_allowed(appid)) {
    return true;
  }

  // The shared GID range is only valid for the first user.
  if (appid >= AID_SHARED_GID_START && appid <= AID_SHARED_GID_END && appid != id) {
    return false;
  }

  // Otherwise check that the appid is in one of the reserved ranges.
  for (size_t i = 0; i < ranges_size; ++i) {
    if (appid >= ranges[i].start && appid <= ranges[i].end) {
      return true;
    }
  }

  return false;
}
#else
static bool is_valid_app_id(id_t, bool) {
  // Host doesn't have the concept of app_id
  return false;
}
#endif  // if defined(__ANDROID__)

// This provides an iterater for app_ids within the first user's app id's.
static id_t get_next_app_id(id_t current_id, bool is_group) {
  auto ranges_size = is_group ? arraysize(group_ranges) : arraysize(user_ranges);
  auto ranges = is_group ? group_ranges : user_ranges;

  // If current_id is below the first of the ranges, then we're uninitialized, and return the first
  // valid id.
  if (current_id < ranges[0].start) {
    return ranges[0].start;
  }

  id_t incremented_id = current_id + 1;

  // Check to see if our incremented_id is between two ranges, and if so, return the beginning of
  // the next valid range.
  for (size_t i = 1; i < ranges_size; ++i) {
    if (incremented_id > ranges[i - 1].end && incremented_id < ranges[i].start) {
      return ranges[i].start;
    }
  }

  // Check to see if our incremented_id is above final range, and return -1 to indicate that we've
  // completed if so.
  if (incremented_id > ranges[ranges_size - 1].end) {
    return -1;
  }

  // Otherwise the incremented_id is valid, so return it.
  return incremented_id;
}

// Translate a user/group name to the corresponding user/group id.
// all_a1234 -> 0 * AID_USER_OFFSET + AID_SHARED_GID_START + 1234 (group name only)
// u0_a1234_ext_cache -> 0 * AID_USER_OFFSET + AID_EXT_CACHE_GID_START + 1234 (group name only)
// u0_a1234_ext -> 0 * AID_USER_OFFSET + AID_EXT_GID_START + 1234 (group name only)
// u0_a1234_cache -> 0 * AID_USER_OFFSET + AID_CACHE_GID_START + 1234 (group name only)
// u0_a1234 -> 0 * AID_USER_OFFSET + AID_APP_START + 1234
// u2_i1000 -> 2 * AID_USER_OFFSET + AID_ISOLATED_START + 1000
// u1_system -> 1 * AID_USER_OFFSET + android_ids['system']
// returns 0 and sets errno to ENOENT in case of error.
static id_t app_id_from_name(const char* name, bool is_group) {
  char* end;
  unsigned long userid;
  bool is_shared_gid = false;

  if (is_group && name[0] == 'a' && name[1] == 'l' && name[2] == 'l') {
    end = const_cast<char*>(name+3);
    userid = 0;
    is_shared_gid = true;
  } else if (name[0] == 'u' && isdigit(name[1])) {
    userid = strtoul(name+1, &end, 10);
  } else {
    errno = ENOENT;
    return 0;
  }

  if (end[0] != '_' || end[1] == 0) {
    errno = ENOENT;
    return 0;
  }

  unsigned long appid = 0;
  if (end[1] == 'a' && isdigit(end[2])) {
    if (is_shared_gid) {
      // end will point to \0 if the strtoul below succeeds.
      appid = strtoul(end+2, &end, 10) + AID_SHARED_GID_START;
      if (appid > AID_SHARED_GID_END) {
        errno = ENOENT;
        return 0;
      }
    } else {
      // end will point to \0 if the strtoul below succeeds.
      appid = strtoul(end+2, &end, 10);
      if (is_group) {
        if (!strcmp(end, "_ext_cache")) {
          end += 10;
          appid += AID_EXT_CACHE_GID_START;
        } else if (!strcmp(end, "_ext")) {
          end += 4;
          appid += AID_EXT_GID_START;
        } else if (!strcmp(end, "_cache")) {
          end += 6;
          appid += AID_CACHE_GID_START;
        } else {
          appid += AID_APP_START;
        }
      } else {
        appid += AID_APP_START;
      }
    }
  } else if (end[1] == 'i' && isdigit(end[2])) {
    // end will point to \0 if the strtoul below succeeds.
    appid = strtoul(end+2, &end, 10) + AID_ISOLATED_START;
  } else if (auto* android_id_info = find_android_id_info(end + 1); android_id_info != nullptr) {
    appid = android_id_info->aid;
    end += strlen(android_id_info->name) + 1;
    if (!platform_id_secondary_user_allowed(appid)) {
      errno = ENOENT;
      return 0;
    }
  }

  // Check that the entire string was consumed by one of the 3 cases above.
  if (end[0] != 0) {
    errno = ENOENT;
    return 0;
  }

  // Check that user id won't overflow.
  if (userid > 1000) {
    errno = ENOENT;
    return 0;
  }

  // Check that app id is within range.
  if (appid >= AID_USER_OFFSET) {
    errno = ENOENT;
    return 0;
  }

  return (appid + userid*AID_USER_OFFSET);
}

static void print_app_name_from_uid(const uid_t uid, char* buffer, const int bufferlen) {
  const uid_t appid = uid % AID_USER_OFFSET;
  const uid_t userid = uid / AID_USER_OFFSET;
  if (appid >= AID_ISOLATED_START) {
    snprintf(buffer, bufferlen, "u%u_i%u", userid, appid - AID_ISOLATED_START);
  } else if (appid < AID_APP_START) {
    if (auto* android_id_info = find_android_id_info(appid); android_id_info != nullptr) {
      snprintf(buffer, bufferlen, "u%u_%s", userid, android_id_info->name);
    }
  } else {
    snprintf(buffer, bufferlen, "u%u_a%u", userid, appid - AID_APP_START);
  }
}

static void print_app_name_from_gid(const gid_t gid, char* buffer, const int bufferlen) {
  const uid_t appid = gid % AID_USER_OFFSET;
  const uid_t userid = gid / AID_USER_OFFSET;
  if (appid >= AID_ISOLATED_START) {
    snprintf(buffer, bufferlen, "u%u_i%u", userid, appid - AID_ISOLATED_START);
  } else if (userid == 0 && appid >= AID_SHARED_GID_START && appid <= AID_SHARED_GID_END) {
    snprintf(buffer, bufferlen, "all_a%u", appid - AID_SHARED_GID_START);
  } else if (appid >= AID_EXT_CACHE_GID_START && appid <= AID_EXT_CACHE_GID_END) {
    snprintf(buffer, bufferlen, "u%u_a%u_ext_cache", userid, appid - AID_EXT_CACHE_GID_START);
  } else if (appid >= AID_EXT_GID_START && appid <= AID_EXT_GID_END) {
    snprintf(buffer, bufferlen, "u%u_a%u_ext", userid, appid - AID_EXT_GID_START);
  } else if (appid >= AID_CACHE_GID_START && appid <= AID_CACHE_GID_END) {
    snprintf(buffer, bufferlen, "u%u_a%u_cache", userid, appid - AID_CACHE_GID_START);
  } else if (appid < AID_APP_START) {
    if (auto* android_id_info = find_android_id_info(appid); android_id_info != nullptr) {
      snprintf(buffer, bufferlen, "u%u_%s", userid, android_id_info->name);
    }
  } else {
    snprintf(buffer, bufferlen, "u%u_a%u", userid, appid - AID_APP_START);
  }
}

#if defined(__ANDROID__)
static bool device_launched_before_api_29() {
  // Check if ro.product.first_api_level is set to a value > 0 and < 29, if so, this device was
  // launched before API 29 (Q). Any other value is considered to be either in development or
  // launched after.
  // Cache the value as __system_property_get() is expensive and this may be called often.
  static bool result = [] {
    char value[PROP_VALUE_MAX] = { 0 };
    if (__system_property_get("ro.product.first_api_level", value) == 0) {
      return false;
    }
    int value_int = atoi(value);
    return value_int != 0 && value_int < 29;
  }();
  return result;
}

// oem_XXXX -> uid
//  Supported ranges:
//   AID_OEM_RESERVED_START to AID_OEM_RESERVED_END (2900-2999)
//   AID_OEM_RESERVED_2_START to AID_OEM_RESERVED_2_END (5000-5999)
// Check OEM id is within range.
static bool is_oem_id(id_t id) {
  // Upgrading devices launched before API level 29 may not comply with the below check.
  // Due to the difficulty in changing uids after launch, it is waived for these devices.
  // The legacy range:
  // AID_OEM_RESERVED_START to AID_EVERYBODY (2900-9996), excluding builtin AIDs.
  if (device_launched_before_api_29() && id >= AID_OEM_RESERVED_START && id < AID_EVERYBODY &&
      find_android_id_info(id) == nullptr) {
    return true;
  }

  return (id >= AID_OEM_RESERVED_START && id <= AID_OEM_RESERVED_END) ||
         (id >= AID_OEM_RESERVED_2_START && id <= AID_OEM_RESERVED_2_END);
}
#else
static bool is_oem_id(id_t) {
  // no OEM ids in host
  return false;
}
#endif  // if defined(__ANDROID__)

// Translate an OEM name to the corresponding user/group id.
static id_t oem_id_from_name(const char* name) {
  unsigned int id;
  if (sscanf(name, "oem_%u", &id) != 1) {
    return 0;
  }
  if (!is_oem_id(id)) {
    return 0;
  }
  return static_cast<id_t>(id);
}

static passwd* oem_id_to_passwd(uid_t uid, passwd_state_t* state) {
  for (auto& passwd_file : passwd_files) {
    if (passwd_file.FindById(uid, state)) {
      return &state->passwd_;
    }
  }

  if (!is_oem_id(uid)) {
    return nullptr;
  }

  snprintf(state->name_buffer_, sizeof(state->name_buffer_), "oem_%u", uid);
  snprintf(state->dir_buffer_, sizeof(state->dir_buffer_), "/");
  snprintf(state->sh_buffer_, sizeof(state->sh_buffer_), "/bin/sh");

  passwd* pw = &state->passwd_;
  pw->pw_uid   = uid;
  pw->pw_gid   = uid;
  return pw;
}

static group* oem_id_to_group(gid_t gid, group_state_t* state) {
  for (auto& group_file : group_files) {
    if (group_file.FindById(gid, state)) {
      return &state->group_;
    }
  }

  if (!is_oem_id(gid)) {
    return nullptr;
  }

  snprintf(state->group_name_buffer_, sizeof(state->group_name_buffer_),
           "oem_%u", gid);

  group* gr = &state->group_;
  gr->gr_gid = gid;
  return gr;
}

// Translate a uid into the corresponding name.
// 0 to AID_APP_START-1                    -> "system", "radio", etc.
// AID_APP_START to AID_ISOLATED_START-1   -> u0_a1234
// AID_ISOLATED_START to AID_USER_OFFSET-1 -> u0_i1234
// AID_USER_OFFSET+                        -> u1_radio, u1_a1234, u2_i1234, etc.
// returns a passwd structure (sets errno to ENOENT on failure).
static passwd* app_id_to_passwd(uid_t uid, passwd_state_t* state) {
  if (uid < AID_APP_START || !is_valid_app_id(uid, false)) {
    errno = ENOENT;
    return nullptr;
  }

  print_app_name_from_uid(uid, state->name_buffer_, sizeof(state->name_buffer_));

  const uid_t appid = uid % AID_USER_OFFSET;
  if (appid < AID_APP_START) {
      snprintf(state->dir_buffer_, sizeof(state->dir_buffer_), "/");
  } else {
      snprintf(state->dir_buffer_, sizeof(state->dir_buffer_), "/data");
  }

  snprintf(state->sh_buffer_, sizeof(state->sh_buffer_), "/bin/sh");

  passwd* pw = &state->passwd_;
  pw->pw_uid   = uid;
  pw->pw_gid   = uid;
  return pw;
}

// Translate a gid into the corresponding app_<gid>
// group structure (sets errno to ENOENT on failure).
static group* app_id_to_group(gid_t gid, group_state_t* state) {
  if (gid < AID_APP_START || !is_valid_app_id(gid, true)) {
    errno = ENOENT;
    return nullptr;
  }

  print_app_name_from_gid(gid, state->group_name_buffer_, sizeof(state->group_name_buffer_));

  group* gr = &state->group_;
  gr->gr_gid = gid;
  return gr;
}

passwd* getpwuid_internal(uid_t uid, passwd_state_t* state) {
  if (auto* android_id_info = find_android_id_info(uid); android_id_info != nullptr) {
    return android_iinfo_to_passwd(state, android_id_info);
  }

  // Find an entry from the database file
  passwd* pw = oem_id_to_passwd(uid, state);
  if (pw != nullptr) {
    return pw;
  }
  return app_id_to_passwd(uid, state);
}

passwd* getpwuid(uid_t uid) {  // NOLINT: implementing bad function.
  passwd_state_t* state = get_passwd_tls_buffer();
  return getpwuid_internal(uid, state);
}

passwd* getpwnam_internal(const char* login, passwd_state_t* state) {
  if (auto* android_id_info = find_android_id_info(login); android_id_info != nullptr) {
    return android_iinfo_to_passwd(state, android_id_info);
  }

  // Find an entry from the database file
  for (auto& passwd_file : passwd_files) {
    if (passwd_file.FindByName(login, state)) {
      return &state->passwd_;
    }
  }

  // Handle OEM range.
  passwd* pw = oem_id_to_passwd(oem_id_from_name(login), state);
  if (pw != nullptr) {
    return pw;
  }
  return app_id_to_passwd(app_id_from_name(login, false), state);
}

passwd* getpwnam(const char* login) {  // NOLINT: implementing bad function.
  passwd_state_t* state = get_passwd_tls_buffer();
  return getpwnam_internal(login, state);
}

static int getpasswd_r(bool by_name, const char* name, uid_t uid, struct passwd* pwd, char* buf,
                       size_t buflen, struct passwd** result) {
  ErrnoRestorer errno_restorer;
  *result = nullptr;
  char* p =
      reinterpret_cast<char*>(__BIONIC_ALIGN(reinterpret_cast<uintptr_t>(buf), sizeof(uintptr_t)));
  if (p + sizeof(passwd_state_t) > buf + buflen) {
    return ERANGE;
  }
  passwd_state_t* state = reinterpret_cast<passwd_state_t*>(p);
  init_passwd_state(state);
  passwd* retval = (by_name ? getpwnam_internal(name, state) : getpwuid_internal(uid, state));
  if (retval != nullptr) {
    *pwd = *retval;
    *result = pwd;
    return 0;
  }
  return errno;
}

int getpwnam_r(const char* name, passwd* pwd, char* buf, size_t byte_count, passwd** result) {
  return getpasswd_r(true, name, -1, pwd, buf, byte_count, result);
}

int getpwuid_r(uid_t uid, passwd* pwd, char* buf, size_t byte_count, passwd** result) {
  return getpasswd_r(false, nullptr, uid, pwd, buf, byte_count, result);
}

// All users are in just one group, the one passed in.
// In practice, id(1) will show you in a lot more groups, because adbd
// adds you to a lot of supplementary groups when dropping privileges.
int getgrouplist(const char* /*user*/, gid_t group, gid_t* groups, int* ngroups) {
  if (*ngroups < 1) {
    *ngroups = 1;
    return -1;
  }
  groups[0] = group;
  return (*ngroups = 1);
}

// See getgrouplist() to understand why we don't call it.
int initgroups(const char* /*user*/, gid_t group) {
  gid_t groups[] = {group};
  return setgroups(1, groups);
}

char* getlogin() { // NOLINT: implementing bad function.
  passwd *pw = getpwuid(getuid()); // NOLINT: implementing bad function in terms of bad function.
  return pw ? pw->pw_name : nullptr;
}

int getlogin_r(char* buf, size_t size) {
  char* login = getlogin();
  if (login == nullptr) return errno;
  size_t login_length = strlen(login) + 1;
  if (login_length > size) return ERANGE;
  memcpy(buf, login, login_length);
  return 0;
}

void setpwent() {
  passwd_state_t* state = get_passwd_tls_buffer();
  if (state) {
    state->getpwent_idx = 0;
  }
}

void endpwent() {
  setpwent();
}

passwd* getpwent() {
  passwd_state_t* state = get_passwd_tls_buffer();
  if (state->getpwent_idx < 0) {
    return nullptr;
  }

  size_t start = 0;
  ssize_t end = android_id_count;
  if (state->getpwent_idx < end) {
    return android_iinfo_to_passwd(state, android_ids + state->getpwent_idx++);
  }

  start = end;
  end += AID_OEM_RESERVED_END - AID_OEM_RESERVED_START + 1;

  if (state->getpwent_idx < end) {
    return oem_id_to_passwd(
        state->getpwent_idx++ - start + AID_OEM_RESERVED_START, state);
  }

  start = end;
  end += AID_OEM_RESERVED_2_END - AID_OEM_RESERVED_2_START + 1;

  if (state->getpwent_idx < end) {
    return oem_id_to_passwd(
        state->getpwent_idx++ - start + AID_OEM_RESERVED_2_START, state);
  }

  start = end;
  end += AID_SYSTEM_EXT_RESERVED_END - AID_SYSTEM_RESERVED_START + 1;

  if (state->getpwent_idx < end) {
    // No one calls this enough to worry about how inefficient the below is.
    auto* oem_passwd =
        oem_id_to_passwd(state->getpwent_idx++ - start + AID_SYSTEM_RESERVED_START, state);
    while (oem_passwd == nullptr && state->getpwent_idx < end) {
      oem_passwd =
          oem_id_to_passwd(state->getpwent_idx++ - start + AID_SYSTEM_RESERVED_START, state);
    }
    if (oem_passwd != nullptr) {
      return oem_passwd;
    }
  }

  state->getpwent_idx = get_next_app_id(state->getpwent_idx, false);

  if (state->getpwent_idx != -1) {
    return app_id_to_passwd(state->getpwent_idx, state);
  }

  // We are not reporting u1_a* and higher or we will be here forever
  return nullptr;
}

static group* getgrgid_internal(gid_t gid, group_state_t* state) {
  if (auto* android_id_info = find_android_id_info(gid); android_id_info != nullptr) {
    return android_iinfo_to_group(state, android_id_info);
  }

  // Find an entry from the database file
  group* grp = oem_id_to_group(gid, state);
  if (grp != nullptr) {
    return grp;
  }
  return app_id_to_group(gid, state);
}

group* getgrgid(gid_t gid) { // NOLINT: implementing bad function.
  group_state_t* state = get_group_tls_buffer();
  return getgrgid_internal(gid, state);
}

static group* getgrnam_internal(const char* name, group_state_t* state) {
  if (auto* android_id_info = find_android_id_info(name); android_id_info != nullptr) {
    return android_iinfo_to_group(state, android_id_info);
  }

  // Find an entry from the database file
  for (auto& group_file : group_files) {
    if (group_file.FindByName(name, state)) {
      return &state->group_;
    }
  }

  // Handle OEM range.
  group* grp = oem_id_to_group(oem_id_from_name(name), state);
  if (grp != nullptr) {
    return grp;
  }
  return app_id_to_group(app_id_from_name(name, true), state);
}

group* getgrnam(const char* name) { // NOLINT: implementing bad function.
  group_state_t* state = get_group_tls_buffer();
  return getgrnam_internal(name, state);
}

static int getgroup_r(bool by_name, const char* name, gid_t gid, struct group* grp, char* buf,
                      size_t buflen, struct group** result) {
  ErrnoRestorer errno_restorer;
  *result = nullptr;
  char* p = reinterpret_cast<char*>(
      __BIONIC_ALIGN(reinterpret_cast<uintptr_t>(buf), sizeof(uintptr_t)));
  if (p + sizeof(group_state_t) > buf + buflen) {
    return ERANGE;
  }
  group_state_t* state = reinterpret_cast<group_state_t*>(p);
  init_group_state(state);
  group* retval = (by_name ? getgrnam_internal(name, state) : getgrgid_internal(gid, state));
  if (retval != nullptr) {
    *grp = *retval;
    *result = grp;
    return 0;
  }
  return errno;
}

int getgrgid_r(gid_t gid, struct group* grp, char* buf, size_t buflen, struct group** result) {
  return getgroup_r(false, nullptr, gid, grp, buf, buflen, result);
}

int getgrnam_r(const char* name, struct group* grp, char* buf, size_t buflen,
               struct group **result) {
  return getgroup_r(true, name, 0, grp, buf, buflen, result);
}

void setgrent() {
  group_state_t* state = get_group_tls_buffer();
  if (state) {
    state->getgrent_idx = 0;
  }
}

void endgrent() {
  setgrent();
}

group* getgrent() {
  group_state_t* state = get_group_tls_buffer();
  if (state->getgrent_idx < 0) {
    return nullptr;
  }

  size_t start = 0;
  ssize_t end = android_id_count;
  if (state->getgrent_idx < end) {
    return android_iinfo_to_group(state, android_ids + state->getgrent_idx++);
  }

  start = end;
  end += AID_OEM_RESERVED_END - AID_OEM_RESERVED_START + 1;

  if (state->getgrent_idx < end) {
    return oem_id_to_group(
        state->getgrent_idx++ - start + AID_OEM_RESERVED_START, state);
  }

  start = end;
  end += AID_OEM_RESERVED_2_END - AID_OEM_RESERVED_2_START + 1;

  if (state->getgrent_idx < end) {
    return oem_id_to_group(
        state->getgrent_idx++ - start + AID_OEM_RESERVED_2_START, state);
  }

  start = end;
  end += AID_SYSTEM_EXT_RESERVED_END - AID_SYSTEM_RESERVED_START + 1;

  if (state->getgrent_idx < end) {
    // No one calls this enough to worry about how inefficient the below is.
    init_group_state(state);
    auto* oem_group =
        oem_id_to_group(state->getgrent_idx++ - start + AID_SYSTEM_RESERVED_START, state);
    while (oem_group == nullptr && state->getgrent_idx < end) {
      oem_group = oem_id_to_group(state->getgrent_idx++ - start + AID_SYSTEM_RESERVED_START, state);
    }
    if (oem_group != nullptr) {
      return oem_group;
    }
  }

  start = end;
  end += AID_USER_OFFSET - AID_APP_START; // Do not expose higher groups

  state->getgrent_idx = get_next_app_id(state->getgrent_idx, true);

  if (state->getgrent_idx != -1) {
    return app_id_to_group(state->getgrent_idx, state);
  }

  // We are not reporting u1_a* and higher or we will be here forever
  return nullptr;
}
```
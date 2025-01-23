Response:
Let's break down the thought process for answering the user's request about `grp_pwd_file_test.cpp`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the provided C++ test file. Key areas of focus are:

* Functionality of the test file itself.
* Relationship to Android's functionality.
* Detailed explanation of libc functions used.
* Handling of dynamic linking (though the test doesn't directly demonstrate this, the request mentions it as bionic is involved).
* Logical reasoning with input/output examples.
* Common user errors.
* How the code is reached in Android (framework/NDK).
* Frida hooking examples.

**2. Initial Code Analysis (Skimming and Keyword Spotting):**

First, I quickly scanned the code for key elements:

* `#include` directives:  `unistd.h`, `gtest/gtest.h`, `android-base/file.h`, and importantly, the conditional inclusion of `../libc/bionic/grp_pwd_file.cpp`. This immediately tells me this is a unit test specifically for the `grp_pwd_file.cpp` implementation within bionic.
* Class `FileUnmapper`:  This is a RAII helper to ensure `Unmap()` is called on the file object when it goes out of scope. This suggests memory mapping is being used.
* Functions `FindAndCheckPasswdEntry` and `FindAndCheckGroupEntry`: These are helper functions that take a `PasswdFile` or `GroupFile` object and verify if entries exist and have the expected data. They use `ASSERT_TRUE` and `EXPECT_STREQ`/`EXPECT_EQ`, indicating the use of Google Test.
* Test cases using `TEST(grp_pwd_file, ...)`:  These define the actual unit tests for different scenarios (one entry, many entries, required prefix).
* Conditional compilation `#if defined(__BIONIC__)`: This confirms the code is specific to the Bionic library.

**3. Deeper Dive into Functionality:**

Now I start to synthesize what the code *does*:

* **Purpose:** The primary function is to test the `PasswdFile` and `GroupFile` classes. These classes likely handle reading and parsing `/etc/passwd` and `/etc/group` (or similar files) to retrieve user and group information.
* **Testing Strategy:** The tests create temporary files, write specific data to them mimicking the format of `passwd` and `group` files, and then use the `PasswdFile` and `GroupFile` classes to find and verify entries. This includes testing successful lookups by name and ID, as well as failure cases.
* **Prefix Testing:** The `passwd_file_required_prefix` and `group_file_required_prefix` tests indicate that the classes support filtering entries based on a prefix in the username/groupname.

**4. Connecting to Android Functionality:**

Based on the file names and the inclusion of `unistd.h`, I can infer the connection to standard Unix-like user and group management. In Android, these files (or their equivalents/abstractions) are used for:

* User authentication and authorization.
* Setting file permissions.
* Running processes with specific user and group identities.

**5. Examining libc Function Usage:**

* `unistd.h`: Provides basic system calls like `write`. This is used to populate the test files.
* No direct usage of `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid` is visible in *this test file*. However, the *existence* of `PasswdFile` and `GroupFile` strongly suggests that their *implementation* (in `grp_pwd_file.cpp`) will likely use these libc functions internally. Therefore, I need to explain these functions in the context of how `PasswdFile` and `GroupFile` *likely* work.
* `android-base/file.h`: Provides the `TemporaryFile` class, simplifying the creation and cleanup of temporary files for testing.

**6. Addressing Dynamic Linking:**

While this specific *test file* doesn't directly demonstrate dynamic linking, the fact that it's part of *bionic* (the dynamic linker) is crucial. I need to:

* Explain what a shared object (.so) is and its role.
* Provide a basic example of a hypothetical scenario where code using `PasswdFile` or `GroupFile` would link against `libc.so`.
* Briefly describe the linking process.

**7. Providing Logical Reasoning and Examples:**

This involves creating hypothetical scenarios to illustrate how the tests work:

* **Input:** Sample content of a temporary passwd/group file.
* **Processing:** How `PasswdFile` and `GroupFile` would parse and store this data.
* **Output:** The results of `FindByName` and `FindById` calls.

**8. Identifying Common User Errors:**

I need to think about mistakes developers might make when using the underlying functions (or the abstractions provided by `PasswdFile`/`GroupFile`):

* Incorrectly parsing the `/etc/passwd` or `/etc/group` format themselves (if not using the bionic classes).
* Not handling errors when opening or reading these files.
* Security vulnerabilities if sensitive information is not handled carefully.

**9. Tracing the Execution Path:**

This is where I connect the test file back to real Android usage. I need to illustrate a simplified call chain:

* **Android Framework/NDK:**  High-level operations like user authentication or file access.
* **System Services:**  Components like `system_server` that might need user/group information.
* **Bionic Libc:**  Functions like `getpwnam` or, more likely in newer Android versions, the abstractions provided by `PasswdFile`/`GroupFile`.

**10. Frida Hooking Example:**

I need to provide practical examples of how to use Frida to inspect the behavior of these functions at runtime. This involves hooking functions like `PasswdFile::FindByName` and `PasswdFile::FindById` to log arguments and return values.

**11. Structuring the Response:**

Finally, I need to organize all this information into a clear and logical structure, addressing each point of the user's request. Using headings and bullet points makes the response easier to read.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on the `write` calls in the test.
* **Correction:** Realized the *core* functionality being tested is in the `PasswdFile` and `GroupFile` classes, and the `write` calls are just setup. Shifted focus accordingly.
* **Initial thought:**  Provide very detailed explanations of low-level memory operations.
* **Correction:** While understanding is good, the user's request is broader. I needed to balance technical depth with higher-level explanations of purpose and usage.
* **Initial thought:**  Overlook the dynamic linking aspect since the test doesn't directly show it.
* **Correction:**  Recognized that bionic is central to the request, so even if not directly demonstrated, the concept of dynamic linking with `libc.so` needs to be addressed.

By following this structured thought process, moving from high-level understanding to detailed analysis, and constantly refining my approach, I could generate a comprehensive and accurate answer to the user's complex request.
好的，我们来详细分析一下 `bionic/tests/grp_pwd_file_test.cpp` 这个文件。

**文件功能概述**

`grp_pwd_file_test.cpp` 是 Android Bionic 库中的一个单元测试文件。它的主要功能是测试 `bionic/libc/bionic/grp_pwd_file.cpp` 中实现的 `PasswdFile` 和 `GroupFile` 这两个类。这两个类分别用于解析和操作 `/etc/passwd` 和 `/etc/group` 格式的文件，以获取用户信息和组信息。

**与 Android 功能的关系及举例**

这个测试文件直接关系到 Android 系统中用户和组的管理功能。Android 系统依赖于用户和组的概念来进行权限管理和资源隔离。

**举例说明：**

* **用户切换 (`su` 命令):** 当你在 adb shell 中使用 `su` 命令切换用户时，系统需要读取 `/etc/passwd` 文件来查找目标用户的 UID (User ID) 和其他信息，以确保切换操作的正确性。`PasswdFile` 类就是用来处理这个操作的。
* **文件权限控制:**  当系统需要判断一个进程是否有权限访问某个文件时，会检查进程的 UID 和 GID (Group ID)，以及文件的所有者和所属组。这些 UID 和 GID 信息通常来源于 `/etc/passwd` 和 `/etc/group` 文件。`GroupFile` 类在这里发挥作用。
* **应用权限管理:** 虽然 Android 应用的权限管理更多依赖于 Android 的 Framework 层，但在底层，某些操作可能仍然需要查询用户和组信息。例如，当一个应用需要访问特定用户拥有的文件时。

**libc 函数的功能实现**

在这个测试文件中，直接调用的 libc 函数主要是 `unistd.h` 中的 `write` 函数。

* **`write(int fd, const void *buf, size_t count)`:**
    * **功能:**  `write` 函数用于将缓冲区 `buf` 中的 `count` 个字节的数据写入到文件描述符 `fd` 指向的文件中。
    * **实现:**  `write` 是一个系统调用，它的具体实现由 Linux 内核完成。当用户空间的程序调用 `write` 时，会触发一个软中断，控制权转移到内核。内核会根据文件描述符 `fd` 找到对应的文件对象，然后将数据复制到内核的文件缓冲区中。最终，内核会将数据写入到磁盘或者其他存储介质。

虽然测试代码本身只直接使用了 `write`，但被测试的 `grp_pwd_file.cpp` 内部会使用其他的 libc 函数来完成文件读取和解析，例如：

* **`open(const char *pathname, int flags, ...)`:**
    * **功能:** 打开一个文件，返回一个文件描述符。
    * **实现:** 系统调用，内核根据 `pathname` 查找文件，根据 `flags` 设置打开模式（读、写等），分配文件描述符并与文件对象关联。
* **`mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)`:**
    * **功能:** 将文件或设备映射到内存中，提供一种高效访问文件内容的方式。
    * **实现:** 系统调用，内核在进程的地址空间中创建一个映射区域，将文件的部分或全部内容映射到该区域。对映射区域的访问就相当于对文件内容的访问。
* **`munmap(void *addr, size_t length)`:**
    * **功能:** 取消由 `mmap` 创建的内存映射。
    * **实现:** 系统调用，内核释放与指定内存区域的映射关系。
* **`getline(char **lineptr, size_t *n, FILE *stream)`:** (或类似的行读取函数)
    * **功能:** 从流 `stream` 中读取一行数据，并将其存储在 `*lineptr` 指向的缓冲区中。
    * **实现:**  `getline` 通常会动态分配内存来存储读取的行。它会从文件流中读取字符，直到遇到换行符或者文件结束符。

**涉及 dynamic linker 的功能和处理过程**

虽然这个测试文件本身没有直接展示 dynamic linker 的功能，但 `grp_pwd_file.cpp` 作为 Bionic libc 的一部分，在运行时会被动态链接器加载。

**so 布局样本:**

假设一个使用了 `PasswdFile` 类的 Android 应用，其依赖的 so 文件布局可能如下：

```
/system/lib64/libc.so       (包含 PasswdFile 的实现)
/system/lib64/libutils.so   (android-base/file.h 可能依赖)
/data/app/com.example.myapp/lib/arm64-v8a/libnative.so (包含调用 PasswdFile 的本地代码)
```

**链接的处理过程:**

1. **加载 `libnative.so`:** 当应用启动时，Android 的 dynamic linker (`/system/bin/linker64`) 会加载应用的 native 库 `libnative.so`。
2. **解析依赖:** dynamic linker 会解析 `libnative.so` 的依赖项，发现它需要 `libc.so` 和 `libutils.so`。
3. **加载依赖项:** dynamic linker 会在预定义的路径中查找并加载 `libc.so` 和 `libutils.so`。
4. **符号解析 (Symbol Resolution):**  当 `libnative.so` 中的代码调用 `PasswdFile` 的构造函数或成员函数时，dynamic linker 会在已加载的 so 文件中查找这些符号的定义。由于 `PasswdFile` 的实现在 `libc.so` 中，dynamic linker 会将 `libnative.so` 中的调用链接到 `libc.so` 中对应的函数地址。
5. **重定位 (Relocation):** dynamic linker 还会修改 `libnative.so` 和 `libc.so` 中的某些指令和数据，以确保它们在当前进程的地址空间中正确运行。

**逻辑推理，假设输入与输出**

**场景 1：测试 `passwd_file_one_entry`**

* **假设输入 (临时文件内容):**  `name:password:1:2:user_info:dir:shell\n`
* **处理过程:** `PasswdFile` 类会打开这个临时文件，将其内存映射，然后解析这一行数据，提取出用户名 "name"，UID 1，GID 2，家目录 "dir"，Shell 路径 "shell" 等信息。
* **预期输出:** `FindAndCheckPasswdEntry` 函数会成功找到名为 "name" 和 UID 为 1 的用户条目，并断言其各个字段的值与输入一致。`FindByName("not_name", nullptr)` 和 `FindById(3, nullptr)` 应该返回 `false`。

**场景 2：测试 `group_file_many_entries`**

* **假设输入 (临时文件内容):**  包含多个组条目的字符串，例如：
  ```
  first:password:1:one,two,three\n
  middle-ish:def_a_password_that_is_over_32_characters_long:6:\n
  last::800:\n
  ```
* **处理过程:** `GroupFile` 类会打开并解析这个临时文件。
* **预期输出:** `FindAndCheckGroupEntry` 函数会成功找到名为 "first" (GID 1), "middle-ish" (GID 6), 和 "last" (GID 800) 的组条目，并验证其成员信息。查找不存在的组名或 GID 应该返回 `false`。

**用户或编程常见的使用错误**

1. **硬编码文件路径:**  直接使用 `/etc/passwd` 或 `/etc/group` 这样的硬编码路径可能导致在某些受限环境下（例如，应用沙箱）无法正常工作。应该使用 Bionic 提供的接口，让系统决定实际的文件位置。
2. **未处理文件打开或读取错误:**  在实际使用中，打开或读取 `/etc/passwd` 或 `/etc/group` 文件可能会失败（例如，权限不足）。程序需要妥善处理这些错误，避免崩溃。
3. **假设文件格式始终不变:**  虽然 `/etc/passwd` 和 `/etc/group` 的基本格式相对稳定，但某些扩展字段或特殊情况可能会导致解析错误。应该使用健壮的解析逻辑。
4. **性能问题:**  频繁地读取和解析 `/etc/passwd` 或 `/etc/group` 文件可能会影响性能。对于需要频繁查询用户和组信息的场景，可以考虑缓存这些信息。
5. **安全问题:**  不小心泄露 `/etc/passwd` 或 `/etc/group` 文件内容可能会带来安全风险，尽管 shadow 文件存储了密码哈希值。

**Android Framework 或 NDK 如何到达这里**

通常，Android 应用或系统服务不会直接调用 `PasswdFile` 或 `GroupFile` 这样的底层 Bionic 接口。它们会使用更高层的 Android Framework API，而 Framework 内部可能会间接地使用这些 Bionic 接口。

**示例调用链:**

1. **NDK 应用:** 一个使用 NDK 的应用可能需要获取当前用户的用户名。
2. **`getpwuid` 函数:**  NDK 应用可能会调用 POSIX 标准的 `getpwuid(uid)` 函数。
3. **Bionic libc 的 `getpwuid` 实现:** Bionic libc 提供的 `getpwuid` 实现内部会使用 `PasswdFile` 类来读取和解析 `/etc/passwd` 文件，找到匹配 UID 的用户条目。

**Frida Hook 示例调试步骤**

可以使用 Frida 来 hook `PasswdFile` 或 `GroupFile` 的方法，以观察其行为。

**假设我们要 hook `PasswdFile::FindByName` 方法:**

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行，请先启动应用")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "_ZN10PasswdFile10FindByNameEPKcPN12passwd_state_tE"), {
    onEnter: function(args) {
        var name = Memory.readUtf8String(args[1]);
        console.log("[+] PasswdFile::FindByName called with name: " + name);
    },
    onLeave: function(retval) {
        console.log("[+] PasswdFile::FindByName returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定目标应用包名:**  将 `package_name` 替换为你要调试的应用的包名。
3. **定义消息处理函数:** `on_message` 函数用于处理 Frida 发送的消息。
4. **连接到目标应用:** 使用 `frida.get_usb_device().attach(package_name)` 连接到正在运行的目标应用。
5. **编写 Frida Hook 代码:**
   * `Module.findExportByName("libc.so", "_ZN10PasswdFile10FindByNameEPKcPN12passwd_state_tE")`:  找到 `libc.so` 中 `PasswdFile::FindByName` 方法的符号地址。需要注意的是，C++ 方法名会被 mangled，你需要使用 `adb shell "grep FindByName /apex/com.android.runtime/lib64/bionic/symbol/libc.so"` 或类似命令找到 unmangled 的符号。
   * `Interceptor.attach`:  附加一个拦截器到目标函数。
   * `onEnter`:  在函数执行前调用，打印传入的用户名参数。
   * `onLeave`:  在函数执行后调用，打印返回值。
6. **创建和加载 Frida 脚本:** 创建 Frida 脚本并加载到目标进程。
7. **保持脚本运行:** `sys.stdin.read()` 阻止脚本退出，保持 hook 状态。

当目标应用调用 `PasswdFile::FindByName` 时，Frida 会拦截该调用并打印相关信息，帮助你调试和理解其行为。

希望以上详细的解释能够帮助你理解 `bionic/tests/grp_pwd_file_test.cpp` 文件的功能和它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/grp_pwd_file_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include <unistd.h>

#include <gtest/gtest.h>

#include <android-base/file.h>

#if defined(__BIONIC__)
#include "../libc/bionic/grp_pwd_file.cpp"

template <typename T>
class FileUnmapper {
 public:
  explicit FileUnmapper(T& file) : file_(file) {
  }
  ~FileUnmapper() {
    file_.Unmap();
  }

 private:
  T& file_;
};

void FindAndCheckPasswdEntry(PasswdFile* file, const char* name, uid_t uid, gid_t gid,
                             const char* dir, const char* shell) {
  passwd_state_t name_passwd_state;
  ASSERT_TRUE(file->FindByName(name, &name_passwd_state)) << name;

  passwd& name_passwd = name_passwd_state.passwd_;
  EXPECT_STREQ(name, name_passwd.pw_name);
  EXPECT_EQ(nullptr, name_passwd.pw_passwd);
  EXPECT_EQ(uid, name_passwd.pw_uid);
  EXPECT_EQ(gid, name_passwd.pw_gid);
  EXPECT_EQ(nullptr, name_passwd.pw_gecos);
  EXPECT_STREQ(dir, name_passwd.pw_dir);
  EXPECT_STREQ(shell, name_passwd.pw_shell);

  passwd_state_t id_passwd_state;
  ASSERT_TRUE(file->FindById(uid, &id_passwd_state)) << uid;

  passwd& id_passwd = id_passwd_state.passwd_;
  EXPECT_STREQ(name, id_passwd.pw_name);
  EXPECT_EQ(nullptr, id_passwd.pw_passwd);
  EXPECT_EQ(uid, id_passwd.pw_uid);
  EXPECT_EQ(gid, id_passwd.pw_gid);
  EXPECT_EQ(nullptr, id_passwd.pw_gecos);
  EXPECT_STREQ(dir, id_passwd.pw_dir);
  EXPECT_STREQ(shell, id_passwd.pw_shell);
}

void FindAndCheckGroupEntry(GroupFile* file, const char* name, gid_t gid) {
  group_state_t name_group_state;
  ASSERT_TRUE(file->FindByName(name, &name_group_state)) << name;

  group& name_group = name_group_state.group_;
  EXPECT_STREQ(name, name_group.gr_name);
  EXPECT_EQ(nullptr, name_group.gr_passwd);
  EXPECT_EQ(gid, name_group.gr_gid);
  EXPECT_EQ(name_group.gr_name, name_group.gr_mem[0]);
  EXPECT_EQ(nullptr, name_group.gr_mem[1]);

  group_state_t id_group_state;
  ASSERT_TRUE(file->FindById(gid, &id_group_state)) << gid;

  group& id_group = id_group_state.group_;
  EXPECT_STREQ(name, id_group.gr_name);
  EXPECT_EQ(nullptr, id_group.gr_passwd);
  EXPECT_EQ(gid, id_group.gr_gid);
  EXPECT_EQ(id_group.gr_name, id_group.gr_mem[0]);
  EXPECT_EQ(nullptr, id_group.gr_mem[1]);
}

#endif  // __BIONIC__

TEST(grp_pwd_file, passwd_file_one_entry) {
#if defined(__BIONIC__)
  TemporaryFile file;
  ASSERT_NE(-1, file.fd);
  static const char test_string[] = "name:password:1:2:user_info:dir:shell\n";
  write(file.fd, test_string, sizeof(test_string) - 1);

  PasswdFile passwd_file(file.path, nullptr);
  FileUnmapper unmapper(passwd_file);

  FindAndCheckPasswdEntry(&passwd_file, "name", 1, 2, "dir", "shell");

  EXPECT_FALSE(passwd_file.FindByName("not_name", nullptr));
  EXPECT_FALSE(passwd_file.FindById(3, nullptr));

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(grp_pwd_file, group_file_one_entry) {
#if defined(__BIONIC__)
  TemporaryFile file;
  ASSERT_NE(-1, file.fd);
  static const char test_string[] = "name:password:1:one,two,three\n";
  write(file.fd, test_string, sizeof(test_string) - 1);

  GroupFile group_file(file.path, nullptr);
  FileUnmapper unmapper(group_file);

  FindAndCheckGroupEntry(&group_file, "name", 1);

  EXPECT_FALSE(group_file.FindByName("not_name", nullptr));
  EXPECT_FALSE(group_file.FindById(3, nullptr));

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(grp_pwd_file, passwd_file_many_entries) {
#if defined(__BIONIC__)
  TemporaryFile file;
  ASSERT_NE(-1, file.fd);
  static const char test_string[] =
      "first:x:1:2::dir:shell\n"
      "abc1::3:4::def:abc\n"
      "abc2::5:4:abc::abc\n"
      "abc3::7:4:abc:def:\n"
      "abc4::9:4:::abc\n"
      "abc5::11:4:abc:def:abc\n"
      "middle-ish::13:4::/:/system/bin/sh\n"
      "abc7::15:4:abc::\n"
      "abc8::17:4:::\n"
      "abc9::19:4:abc:def:abc\n"
      "abc10::21:4:abc:def:abc\n"
      "abc11::23:4:abc:def:abc\n"
      "abc12::25:4:abc:def:abc\n"
      "abc13::27:4:abc:def:abc\n"
      "last::29:4::last_user_dir:last_user_shell\n";

  write(file.fd, test_string, sizeof(test_string) - 1);

  PasswdFile passwd_file(file.path, nullptr);
  FileUnmapper unmapper(passwd_file);

  FindAndCheckPasswdEntry(&passwd_file, "first", 1, 2, "dir", "shell");
  FindAndCheckPasswdEntry(&passwd_file, "middle-ish", 13, 4, "/", "/system/bin/sh");
  FindAndCheckPasswdEntry(&passwd_file, "last", 29, 4, "last_user_dir", "last_user_shell");

  EXPECT_FALSE(passwd_file.FindByName("not_name", nullptr));
  EXPECT_FALSE(passwd_file.FindById(50, nullptr));

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(grp_pwd_file, group_file_many_entries) {
#if defined(__BIONIC__)
  TemporaryFile file;
  ASSERT_NE(-1, file.fd);
  static const char test_string[] =
      "first:password:1:one,two,three\n"
      "abc:def:2:group1,group2,group3\n"
      "abc:def:3:\n"
      "abc:def:4:\n"
      "abc:def:5:\n"
      "middle-ish:def_a_password_that_is_over_32_characters_long:6:\n"
      "abc:def:7:\n"
      "abc:def:8:\n"
      "abc:def:20:\n"
      "abc:def:25:\n"
      "abc:def:27:\n"
      "abc:def:52:\n"
      "last::800:\n";

  write(file.fd, test_string, sizeof(test_string) - 1);

  GroupFile group_file(file.path, nullptr);
  FileUnmapper unmapper(group_file);

  FindAndCheckGroupEntry(&group_file, "first", 1);
  FindAndCheckGroupEntry(&group_file, "middle-ish", 6);
  FindAndCheckGroupEntry(&group_file, "last", 800);

  EXPECT_FALSE(group_file.FindByName("not_name", nullptr));
  EXPECT_FALSE(group_file.FindById(799, nullptr));

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(grp_pwd_file, passwd_file_required_prefix) {
#if defined(__BIONIC__)
  TemporaryFile file;
  ASSERT_NE(-1, file.fd);
  static const char test_string[] =
      "name:password:1:2:user_info:dir:shell\n"
      "vendor_name:password:3:4:user_info:dir:shell\n";
  write(file.fd, test_string, sizeof(test_string) - 1);

  PasswdFile passwd_file(file.path, "vendor_");
  FileUnmapper unmapper(passwd_file);

  EXPECT_FALSE(passwd_file.FindByName("name", nullptr));
  EXPECT_FALSE(passwd_file.FindById(1, nullptr));

  FindAndCheckPasswdEntry(&passwd_file, "vendor_name", 3, 4, "dir", "shell");

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}

TEST(grp_pwd_file, group_file_required_prefix) {
#if defined(__BIONIC__)
  TemporaryFile file;
  ASSERT_NE(-1, file.fd);
  static const char test_string[] =
      "name:password:1:one,two,three\n"
      "vendor_name:password:2:one,two,three\n";
  write(file.fd, test_string, sizeof(test_string) - 1);

  GroupFile group_file(file.path, "vendor_");
  FileUnmapper unmapper(group_file);

  EXPECT_FALSE(group_file.FindByName("name", nullptr));
  EXPECT_FALSE(group_file.FindById(1, nullptr));

  FindAndCheckGroupEntry(&group_file, "vendor_name", 2);

#else   // __BIONIC__
  GTEST_SKIP() << "bionic-only test";
#endif  // __BIONIC__
}
```
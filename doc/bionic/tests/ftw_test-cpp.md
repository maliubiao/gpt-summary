Response:
Let's break down the thought process for answering the user's request about `bionic/tests/ftw_test.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this specific test file within the broader context of Android's Bionic library. Key areas of interest are:

* **Functionality of the test file itself.** What does it test?
* **Relationship to Android features.** How does this testing relate to how Android works?
* **Detailed explanation of libc functions used.** What do these functions do under the hood?
* **Dynamic linker aspects.**  Are there any dynamic linking implications, and how do they work?
* **Logical inference/examples.**  Can we show how the code might behave with specific inputs?
* **Common user errors.** What mistakes might developers make when using these functions?
* **Tracing the execution flow.** How does the Android framework or NDK lead to this code being executed, and how can we debug it?

**2. Initial Analysis of the Code:**

The first step is to read through the code and identify the key components:

* **Includes:** `<ftw.h>`, standard C libraries (`fcntl.h`, `pwd.h`, `stdio.h`, etc.), Android-specific includes (`android-base/file.h`, `android-base/stringprintf.h`), and the testing framework (`gtest/gtest.h`). This tells us it's a test file for the `ftw` family of functions.
* **Helper Functions:** `MakeTree`, `smoke_test_ftw`, `smoke_test_nftw`, `check_ftw`, `check_ftw64`, `check_nftw`, `check_nftw64`. These are likely for setting up test scenarios and performing assertions.
* **Test Cases:** `TEST(ftw, ftw)`, `TEST(ftw, ftw64_smoke)`, `TEST(ftw, nftw)`, `TEST(ftw, nftw64_smoke)`, `TEST(ftw, bug_28197840)`, `TEST(ftw, ftw_non_existent_ENOENT)`, `TEST(ftw, nftw_non_existent_ENOENT)`, `TEST(ftw, ftw_empty_ENOENT)`, `TEST(ftw, nftw_empty_ENOENT)`. These clearly define the different aspects being tested.
* **Core Testing Logic:** The `ASSERT_*` and `EXPECT_*` macros from Google Test indicate assertions about the behavior of the `ftw` and `nftw` functions.

**3. Identifying the Core Functionality Being Tested:**

The presence of `ftw.h` and the names of the test cases immediately point to the file tree walking functions: `ftw` and `nftw` (and their 64-bit counterparts). The test cases cover various scenarios:

* Basic usage (`ftw`, `nftw` smoke tests).
* Handling of permissions (`bug_28197840`).
* Handling of non-existent files/directories (`ftw_non_existent_ENOENT`, `nftw_non_existent_ENOENT`).
* Handling of empty paths (`ftw_empty_ENOENT`, `nftw_empty_ENOENT`).

**4. Connecting to Android Features:**

The `ftw` and `nftw` functions are part of the standard C library (`libc`), which is a fundamental part of any operating system, including Android. Their relevance to Android lies in:

* **File System Operations:**  Android applications and the system itself need to traverse directory structures for various purposes (file management, installation, searching, etc.).
* **Permissions:**  Android's security model relies heavily on file permissions. Testing how `ftw` handles permissions is crucial.
* **NDK Usage:**  NDK developers who need to interact with the file system directly will use these functions.

**5. Explaining libc Functions:**

For each libc function used in the test file (e.g., `mkdir`, `symlink`, `open`, `close`, `stat`, `lstat`, `access`, `getuid`, `setuid`, `getpwnam`), a detailed explanation of its purpose and implementation is needed. This often involves referring to standard POSIX documentation or Bionic's source code (if available). The focus should be on how these functions interact with the underlying kernel.

**6. Addressing Dynamic Linker Aspects:**

While this specific test file doesn't directly *test* the dynamic linker, the functions it *does* test are part of `libc.so`, which *is* dynamically linked. Therefore, it's important to:

* Explain the role of the dynamic linker in loading shared libraries like `libc.so`.
* Provide a simplified example of the memory layout of a process and how `libc.so` is mapped.
* Briefly describe the linking process (symbol resolution, relocation).

**7. Providing Examples and Inferring Behavior:**

For the test cases, provide concrete examples of what the `MakeTree` function creates and how the assertions in the `check_ftw` and `check_nftw` functions would behave for different file types and permissions. This helps illustrate the expected input and output.

**8. Discussing Common User Errors:**

Think about the typical mistakes developers might make when using `ftw` and `nftw`, such as:

* Not handling errors properly.
* Modifying the directory structure during traversal.
* Incorrectly interpreting the `tflag`.

**9. Tracing Execution and Frida Hooks:**

Explain how an Android application might indirectly call these functions through higher-level APIs or directly through NDK. Demonstrate how Frida can be used to hook the `ftw` or `nftw` functions to observe their execution, arguments, and return values. This involves providing a simple Frida script.

**10. Structuring the Response:**

Organize the information logically using headings and subheadings to make it easy to read and understand. Use clear and concise language, and provide code snippets where necessary. Ensure the response directly addresses all parts of the user's request.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the internal implementation details of `ftw` and `nftw`.
* **Correction:** Realize that the user is asking about the *test file* and its context. Shift focus to explaining *what the tests are testing* and *why it's important for Android*. Provide a higher-level overview of the libc functions and dynamic linking, rather than diving into assembly code.
* **Initial thought:** Provide very technical details about dynamic linking.
* **Correction:** Simplify the explanation of dynamic linking to focus on the key concepts relevant to understanding how `libc.so` is loaded and used. Avoid overly complex technical jargon.
* **Initial thought:**  Only list the libc functions.
* **Correction:**  Explain *how* those libc functions are used *within the context of the `ftw` tests*. For example, explain why `mkdir` is used to set up the directory structure being traversed.

By following this structured thought process and incorporating self-correction, a comprehensive and accurate answer can be generated that addresses all aspects of the user's request.
好的，让我们来详细分析一下 `bionic/tests/ftw_test.cpp` 这个文件。

**文件功能概览:**

`bionic/tests/ftw_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试 `ftw` 和 `nftw` 这两个 POSIX 标准中用于遍历目录树的函数及其 64 位版本 (`ftw64` 和 `nftw64`)。

**与 Android 功能的关系及举例:**

`ftw` 和 `nftw` 函数是 Bionic（Android 的 C 库）提供的标准 C 库函数，它们在 Android 系统中扮演着重要的角色，主要用于进行文件系统的遍历操作。这在许多 Android 功能中都有体现：

* **文件管理器类应用:**  文件管理器需要遍历目录结构来展示文件和文件夹，`ftw` 或 `nftw` 可以用于实现这个功能。例如，当文件管理器扫描某个目录及其子目录下的所有文件时，就可以使用这些函数。
* **软件包管理器 (pm):**  Android 的软件包管理器在安装、卸载或扫描应用时，可能需要遍历文件系统特定的目录（例如 `/data/app`）。
* **媒体扫描器 (Media Scanner):** Android 系统会定期扫描设备上的媒体文件（图片、音频、视频）。媒体扫描器就需要遍历存储设备的目录结构来查找这些文件。
* **开发者工具 (如 `adb push`, `adb pull`):**  这些工具在传输文件或目录时，也可能在内部使用类似遍历目录树的操作。
* **系统服务:** 一些系统服务可能需要监控特定目录下的文件变化或进行定期清理，这时就需要遍历目录。

**举例说明:**

假设一个 Android 应用需要列出某个指定目录下所有 `.txt` 结尾的文件。它可以利用 NDK 调用 Bionic 提供的 `nftw` 函数来实现：

```c++
#include <ftw.h>
#include <string.h>
#include <stdio.h>

int list_txt_files(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    if (typeflag == FTW_F && strstr(fpath, ".txt") != nullptr) {
        printf("Found TXT file: %s\n", fpath);
    }
    return 0;
}

// ... 在 JNI 或 Native 代码中调用
int traverse_directory(const char* directory_path) {
    return nftw(directory_path, list_txt_files, 20, 0);
}
```

在这个例子中，`nftw` 会遍历 `directory_path` 指定的目录，并对每个访问到的文件或目录调用 `list_txt_files` 函数。`list_txt_files` 函数会检查文件类型和文件名后缀，并打印出 `.txt` 文件。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件主要涉及以下 libc 函数：

1. **`ftw(const char *dirpath, int (*fn)(const char *, const struct stat *, int), int nopenfd)` 和 `ftw64(...)`:**
   - **功能:**  这两个函数用于遍历以 `dirpath` 为根的目录树。对于遍历到的每个文件和目录，都会调用用户提供的回调函数 `fn`。
   - **实现:**
     - `ftw` 内部通常使用递归或者栈的方式进行深度优先遍历。
     - 它会打开目录，然后读取目录项（文件名、inode 等信息）。
     - 对于每个目录项，它会调用 `stat` 或 `lstat` 获取文件或目录的详细信息（例如，类型、权限、大小等）。
     - 根据获取的信息和文件类型，`ftw` 会以特定的 `tflag` 参数调用回调函数 `fn`。`tflag` 可以是 `FTW_F` (普通文件), `FTW_D` (目录), `FTW_DP` (目录，在访问其所有子项后), `FTW_NS` (无法获取状态信息的文件), `FTW_SL` (符号链接), `FTW_SLN` (指向不存在目标的符号链接), `FTW_DNR` (无法读取的目录)。
     - `nopenfd` 参数指定了 `ftw` 可以同时打开的最大文件描述符数量，用于控制资源使用。
     - `ftw64` 是 `ftw` 的 64 位版本，用于处理更大的文件和目录。

2. **`nftw(const char *dirpath, int (*fn)(const char *, const struct stat *, int, struct FTW *), int nopenfd, int flags)` 和 `nftw64(...)`:**
   - **功能:**  `nftw` 是 `ftw` 的更灵活的版本，它允许更多的控制，并通过 `flags` 参数提供额外的选项。
   - **实现:**
     - 基本的遍历机制与 `ftw` 类似。
     - 额外的 `flags` 参数允许用户指定：
       - `FTW_PHYS`: 不跟随符号链接，即对符号链接本身进行操作。
       - `FTW_MOUNT`: 遍历时不跨越挂载点。
       - 其他标志，具体可以参考 `man nftw`。
     - 回调函数 `fn` 的签名与 `ftw` 略有不同，它接收一个 `struct FTW *ftwbuf` 参数，其中包含有关当前遍历状态的信息，例如当前路径名相对于根路径的基偏移量 (`base`) 和深度 (`level`)。
     - `nftw64` 是 `nftw` 的 64 位版本。

3. **`mkdir(const char *pathname, mode_t mode)`:**
   - **功能:**  创建一个新的目录，路径名为 `pathname`，权限由 `mode` 指定。
   - **实现:**  系统调用 `mkdirat` 或 `mkdir`。内核会在文件系统中创建一个新的目录条目，分配相应的 inode，并设置权限。

4. **`symlink(const char *target, const char *linkpath)`:**
   - **功能:**  创建一个符号链接，名为 `linkpath`，指向目标 `target`。
   - **实现:**  系统调用 `symlinkat` 或 `symlink`。内核会在文件系统中创建一个特殊的文件类型（符号链接），其内容指向 `target` 字符串。

5. **`open(const char *pathname, int flags, ...)`:**
   - **功能:**  打开一个文件，路径名为 `pathname`，打开模式由 `flags` 指定（例如，读、写、创建）。
   - **实现:**  系统调用 `openat` 或 `open`。内核会在进程的文件描述符表中分配一个条目，指向打开的文件对象。如果文件不存在且指定了创建标志，则会创建一个新文件。

6. **`close(int fd)`:**
   - **功能:**  关闭一个文件描述符 `fd`。
   - **实现:**  系统调用 `close`。内核会释放与该文件描述符关联的资源，并将其从进程的文件描述符表中移除。

7. **`stat(const char *pathname, struct stat *buf)` 和 `lstat(const char *pathname, struct stat *buf)`:**
   - **功能:**  获取文件或目录的状态信息，例如类型、权限、大小等，并将结果存储在 `buf` 指向的 `struct stat` 结构体中。`stat` 会跟随符号链接，而 `lstat` 不会，它返回符号链接自身的状态信息。
   - **实现:**  系统调用 `stat` 或 `lstat` (或它们的 `*at` 版本)。内核会从文件系统中读取指定路径的文件或目录的元数据。

8. **`access(const char *pathname, int mode)`:**
   - **功能:**  检查调用进程是否可以按照 `mode` 指定的方式访问文件（例如，读、写、执行）。
   - **实现:**  系统调用 `faccessat` 或 `access`。内核会根据进程的 UID、GID 以及文件的权限位进行检查。

9. **`getuid(void)`:**
   - **功能:**  获取当前进程的实际用户 ID。
   - **实现:**  系统调用 `getuid`。内核会返回当前进程的 UID。

10. **`setuid(uid_t uid)`:**
    - **功能:** 设置当前进程的实际用户 ID。**需要特权**。
    - **实现:** 系统调用 `setuid`。内核会尝试修改进程的 UID。如果调用者没有足够的权限，则会失败。

11. **`getpwnam(const char *name)`:**
    - **功能:** 根据用户名 `name` 获取用户密码数据库中的信息，返回一个指向 `struct passwd` 的指针。
    - **实现:**  Bionic 会读取 `/etc/passwd` 文件（或通过其他用户数据库机制），查找匹配用户名的条目，并返回包含用户信息的结构体。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `ftw_test.cpp` 本身没有直接测试 dynamic linker 的功能，但它使用的 `ftw`、`nftw` 等函数都位于 `libc.so` 这个共享库中。因此，在运行这个测试时，dynamic linker 会发挥作用。

**so 布局样本 (`libc.so` 的部分布局):**

```
          ... 其他段 ...
LOAD        00001000 rw-p  ... // .text 代码段的起始地址
          ... ftw 函数的代码 ...
          ... nftw 函数的代码 ...
          ... 其他 libc 函数的代码 ...
LOAD        00100000 r--p  ... // .rodata 只读数据段
          ... 常量字符串 ...
LOAD        00200000 rw-p  ... // .data 和 .bss 数据段
          ... 全局变量 ...
          ... 未初始化全局变量 ...
          ... GOT (Global Offset Table) 条目 ...
          ... PLT (Procedure Linkage Table) 条目 ...
          ... 其他段 ...
```

**链接的处理过程:**

1. **加载 `ftw_test` 可执行文件:** 当运行 `ftw_test` 时，操作系统会加载其可执行文件到内存。该可执行文件会标记需要链接的共享库 (`libc.so`)。

2. **Dynamic Linker 介入:** 操作系统会启动 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。

3. **加载 `libc.so`:** Dynamic linker 会找到 `libc.so` 共享库，并将其加载到进程的地址空间中的某个位置（如上面的布局样本所示）。

4. **符号解析:**
   - `ftw_test.cpp` 中调用了 `ftw`、`nftw` 等函数。在编译时，这些函数调用会被转换为对 GOT (Global Offset Table) 中条目的引用。
   - 初始状态下，GOT 中的这些条目可能包含一个特殊的地址，指示该符号尚未解析。
   - 当第一次调用 `ftw` 时，会跳转到 PLT (Procedure Linkage Table) 中与 `ftw` 对应的条目。
   - PLT 中的代码会触发 dynamic linker 解析 `ftw` 符号。
   - Dynamic linker 会在 `libc.so` 的符号表中查找 `ftw` 的地址。
   - 找到 `ftw` 的地址后，dynamic linker 会更新 GOT 中 `ftw` 对应的条目，将其指向 `libc.so` 中 `ftw` 函数的实际地址。

5. **重定位:**  如果 `libc.so` 中的代码或数据引用了全局变量或其他符号，dynamic linker 也会进行重定位，调整这些引用，使其指向正确的内存地址。

6. **执行 `ftw` 函数:**  当 GOT 条目被更新后，后续对 `ftw` 的调用将直接跳转到 `libc.so` 中 `ftw` 函数的实际代码。

**假设输入与输出 (逻辑推理):**

**场景:**  `TEST(ftw, ftw)` 测试用例。

**假设输入:**

- `root.path` 是一个临时目录，例如 `/data/local/tmp/ftw_test_XXXX/`。
- `MakeTree(root.path)` 创建了以下目录结构：
  ```
  /data/local/tmp/ftw_test_XXXX/
  ├── dir
  │   └── sub
  ├── dangler -> /does-not-exist
  ├── regular
  ├── symlink -> dir/sub
  └── unreadable-dir
  ```

**预期输出 (通过 `check_ftw` 回调函数验证):**

- 对于 `/data/local/tmp/ftw_test_XXXX/`: `tflag` 为 `FTW_D`。
- 对于 `/data/local/tmp/ftw_test_XXXX/dir`: `tflag` 为 `FTW_D`。
- 对于 `/data/local/tmp/ftw_test_XXXX/dir/sub`: `tflag` 为 `FTW_D`。
- 对于 `/data/local/tmp/ftw_test_XXXX/dangler`: `tflag` 为 `FTW_SLN` (因为链接目标不存在)。
- 对于 `/data/local/tmp/ftw_test_XXXX/regular`: `tflag` 为 `FTW_F`。
- 对于 `/data/local/tmp/ftw_test_XXXX/symlink`: `tflag` 为 `FTW_SL`。
- 对于 `/data/local/tmp/ftw_test_XXXX/unreadable-dir`: `tflag` 为 `FTW_DNR` (因为没有读取权限)。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **未处理 `ftw` 或 `nftw` 的返回值:**  如果 `ftw` 或 `nftw` 返回非零值，表示发生了错误。用户需要检查错误码 (`errno`) 并进行适当处理。

   ```c++
   // 错误示例
   ftw("/some/path", my_callback, 10); // 未检查返回值

   // 正确示例
   if (ftw("/some/path", my_callback, 10) != 0) {
       perror("ftw failed");
   }
   ```

2. **在回调函数中修改目录结构:**  在 `ftw` 或 `nftw` 的回调函数中添加或删除文件/目录可能会导致未定义的行为，甚至程序崩溃。应该避免在回调函数中修改正在遍历的目录结构。

3. **回调函数中使用了不线程安全的操作:** 如果程序是多线程的，传递给 `ftw` 或 `nftw` 的回调函数需要是线程安全的，避免竞态条件。

4. **对符号链接的处理不当:**  用户需要理解 `FTW_PHYS` 标志的作用，并根据需求选择是否跟随符号链接。如果不小心，可能会陷入无限循环遍历符号链接指向的目录。

5. **`nopenfd` 参数设置不合理:**  `nopenfd` 参数限制了 `ftw` 或 `nftw` 可以同时打开的文件描述符数量。如果设置过小，可能会影响遍历性能；如果设置过大，可能会耗尽文件描述符资源。

6. **假设回调函数会被按特定顺序调用:** `ftw` 和 `nftw` 的遍历顺序不一定保证，用户不应依赖特定的遍历顺序。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `ftw`/`nftw` 的路径 (以文件管理器为例):**

1. **用户交互:** 用户在文件管理器应用中点击浏览某个目录。

2. **Java Framework 层:** 文件管理器应用的 Java 代码会调用 Android Framework 提供的 API，例如 `java.io.File` 类的方法来列出目录内容。

3. **Native 代码 (libjavacrypto.so, libandroid_runtime.so 等):**  `java.io.File` 的底层实现最终会调用到 Native 代码，例如 `libjavacrypto.so` 或 `libandroid_runtime.so` 中的函数。

4. **System Calls:** 这些 Native 代码会调用底层的系统调用，例如 `getdents` (用于读取目录项)。

5. **Bionic `libc.so`:** 一些更高级的文件操作，例如递归遍历目录，可能会在 Native 代码中直接调用 Bionic 提供的 `ftw` 或 `nftw` 函数。

**NDK 到 `ftw`/`nftw` 的路径:**

1. **NDK 应用开发:** 开发者使用 NDK 开发 Android 应用，并在 C/C++ 代码中直接调用 Bionic 提供的标准 C 库函数。

2. **直接调用:** 开发者可以在 NDK 代码中直接包含 `<ftw.h>` 并调用 `ftw` 或 `nftw`。

**Frida Hook 示例:**

假设我们要 hook `nftw` 函数，观察其参数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

def main():
    package_name = "com.android.documentsui" # 例如，Hook 文件管理器
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Process '{package_name}' not found. Please ensure the app is running.")
        sys.exit(1)

    script_source = """
        Interceptor.attach(Module.findExportByName("libc.so", "nftw"), {
            onEnter: function(args) {
                console.log("[+] nftw called");
                console.log("    pathname: " + Memory.readUtf8String(args[0]));
                // args[1] 是回调函数指针，无法直接读取
                console.log("    nopenfd: " + args[2]);
                console.log("    flags: " + args[3]);
            },
            onLeave: function(retval) {
                console.log("[+] nftw returned: " + retval);
            }
        });
    """
    script = session.create_script(script_source)
    script.on('message', on_message)
    script.load()
    print("[*] Hooking, press Ctrl+C to stop...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 确保你的 Android 设备已连接并通过 `adb` 可访问。
2. 安装 Frida 和 Python 的 Frida 模块 (`pip install frida-tools`).
3. 替换 `package_name` 为你想要 hook 的应用的包名（例如，文件管理器 `com.android.documentsui`）。
4. 运行 Python 脚本。
5. 在 Android 设备上操作该应用，触发文件遍历操作。
6. Frida 会打印出 `nftw` 函数被调用时的参数信息。

这个 Frida 脚本会在 `libc.so` 中找到 `nftw` 函数的地址，并在其入口和出口处设置 hook。当目标应用调用 `nftw` 时，`onEnter` 和 `onLeave` 函数会被执行，打印出相关的参数和返回值，从而帮助你调试文件遍历的过程。

希望以上详细的解释能够帮助你理解 `bionic/tests/ftw_test.cpp` 文件的功能及其在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/ftw_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <ftw.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>

#include "utils.h"

static void MakeTree(const char* root) {
  char path[PATH_MAX];

  snprintf(path, sizeof(path), "%s/dir", root);
  ASSERT_EQ(0, mkdir(path, 0755)) << path;
  snprintf(path, sizeof(path), "%s/dir/sub", root);
  ASSERT_EQ(0, mkdir(path, 0555)) << path;
  snprintf(path, sizeof(path), "%s/unreadable-dir", root);
  ASSERT_EQ(0, mkdir(path, 0000)) << path;

  snprintf(path, sizeof(path), "%s/dangler", root);
  ASSERT_EQ(0, symlink("/does-not-exist", path));
  snprintf(path, sizeof(path), "%s/symlink", root);
  ASSERT_EQ(0, symlink("dir/sub", path));

  int fd;
  snprintf(path, sizeof(path), "%s/regular", root);
  ASSERT_NE(-1, fd = open(path, O_CREAT|O_TRUNC, 0666));
  ASSERT_EQ(0, close(fd));
}

void smoke_test_ftw(const char* fpath, const struct stat* sb, int tflag) {
  ASSERT_TRUE(fpath != nullptr);
  ASSERT_TRUE(sb != nullptr);

  // Was it a case where the struct stat we're given is meaningless?
  if (tflag == FTW_NS || tflag == FTW_SLN) {
    // If so, double-check that we really can't stat.
    struct stat sb;
    EXPECT_EQ(-1, stat(fpath, &sb));
    return;
  }

  // Otherwise check that the struct stat matches the type flag.
  if (S_ISDIR(sb->st_mode)) {
    if (access(fpath, R_OK) == 0) {
      EXPECT_TRUE(tflag == FTW_D || tflag == FTW_DP) << fpath << ' ' << tflag;
    } else {
      EXPECT_EQ(FTW_DNR, tflag) << fpath;
    }
  } else if (S_ISLNK(sb->st_mode)) {
    EXPECT_EQ(FTW_SL, tflag) << fpath;
  } else {
    EXPECT_EQ(FTW_F, tflag) << fpath;
  }
}

void smoke_test_nftw(const char* fpath, const struct stat* sb, int tflag, FTW* ftwbuf) {
  smoke_test_ftw(fpath, sb, tflag);
  ASSERT_EQ('/', fpath[ftwbuf->base - 1]) << fpath;
}

int check_ftw(const char* fpath, const struct stat* sb, int tflag) {
  smoke_test_ftw(fpath, sb, tflag);
  return 0;
}

int check_ftw64(const char* fpath, const struct stat64* sb, int tflag) {
  smoke_test_ftw(fpath, reinterpret_cast<const struct stat*>(sb), tflag);
  return 0;
}

int check_nftw(const char* fpath, const struct stat* sb, int tflag, FTW* ftwbuf) {
  smoke_test_nftw(fpath, sb, tflag, ftwbuf);
  return 0;
}

int check_nftw64(const char* fpath, const struct stat64* sb, int tflag, FTW* ftwbuf) {
  smoke_test_nftw(fpath, reinterpret_cast<const struct stat*>(sb), tflag, ftwbuf);
  return 0;
}

TEST(ftw, ftw) {
  TemporaryDir root;
  MakeTree(root.path);
  ASSERT_EQ(0, ftw(root.path, check_ftw, 128));
}

TEST(ftw, ftw64_smoke) {
  TemporaryDir root;
  MakeTree(root.path);
  ASSERT_EQ(0, ftw64(root.path, check_ftw64, 128));
}

TEST(ftw, nftw) {
  TemporaryDir root;
  MakeTree(root.path);
  ASSERT_EQ(0, nftw(root.path, check_nftw, 128, 0));
}

TEST(ftw, nftw64_smoke) {
  TemporaryDir root;
  MakeTree(root.path);
  ASSERT_EQ(0, nftw64(root.path, check_nftw64, 128, 0));
}

template <typename StatT>
static int bug_28197840_ftw(const char* path, const StatT*, int flag) {
  EXPECT_EQ(strstr(path, "unreadable") != nullptr ? FTW_DNR : FTW_D, flag) << path;
  return 0;
}

template <typename StatT>
static int bug_28197840_nftw(const char* path, const StatT* sb, int flag, FTW*) {
  return bug_28197840_ftw(path, sb, flag);
}

TEST(ftw, bug_28197840) {
  // Drop root for this test, because root can still read directories even if
  // permissions would imply otherwise.
  if (getuid() == 0) {
    passwd* pwd = getpwnam("shell");
    ASSERT_EQ(0, setuid(pwd->pw_uid));
  }

  TemporaryDir root;

  std::string path = android::base::StringPrintf("%s/unreadable-directory", root.path);
  ASSERT_EQ(0, mkdir(path.c_str(), 0000)) << path;

  ASSERT_EQ(0, ftw(root.path, bug_28197840_ftw<struct stat>, 128));
  ASSERT_EQ(0, ftw64(root.path, bug_28197840_ftw<struct stat64>, 128));
  ASSERT_EQ(0, nftw(root.path, bug_28197840_nftw<struct stat>, 128, FTW_PHYS));
  ASSERT_EQ(0, nftw64(root.path, bug_28197840_nftw<struct stat64>, 128, FTW_PHYS));
}

template <typename StatT>
static int null_ftw_callback(const char*, const StatT*, int) {
  return 0;
}

template <typename StatT>
static int null_nftw_callback(const char*, const StatT*, int, FTW*) {
  return 0;
}

TEST(ftw, ftw_non_existent_ENOENT) {
  errno = 0;
  ASSERT_EQ(-1, ftw("/does/not/exist", null_ftw_callback<struct stat>, 128));
  ASSERT_ERRNO(ENOENT);
  errno = 0;
  ASSERT_EQ(-1, ftw64("/does/not/exist", null_ftw_callback<struct stat64>, 128));
  ASSERT_ERRNO(ENOENT);
}

TEST(ftw, nftw_non_existent_ENOENT) {
  errno = 0;
  ASSERT_EQ(-1, nftw("/does/not/exist", null_nftw_callback<struct stat>, 128, FTW_PHYS));
  ASSERT_ERRNO(ENOENT);
  errno = 0;
  ASSERT_EQ(-1, nftw64("/does/not/exist", null_nftw_callback<struct stat64>, 128, FTW_PHYS));
  ASSERT_ERRNO(ENOENT);
}

TEST(ftw, ftw_empty_ENOENT) {
  errno = 0;
  ASSERT_EQ(-1, ftw("", null_ftw_callback<struct stat>, 128));
  ASSERT_ERRNO(ENOENT);
  errno = 0;
  ASSERT_EQ(-1, ftw64("", null_ftw_callback<struct stat64>, 128));
  ASSERT_ERRNO(ENOENT);
}

TEST(ftw, nftw_empty_ENOENT) {
  errno = 0;
  ASSERT_EQ(-1, nftw("", null_nftw_callback<struct stat>, 128, FTW_PHYS));
  ASSERT_ERRNO(ENOENT);
  errno = 0;
  ASSERT_EQ(-1, nftw64("", null_nftw_callback<struct stat64>, 128, FTW_PHYS));
  ASSERT_ERRNO(ENOENT);
}
```
Response:
Let's break down the thought process for analyzing the `dirent_test.cpp` file.

**1. Understanding the Goal:**

The core request is to understand the functionality of the provided C++ test file, its connection to Android, the implementation details of the libc functions it tests, and any interactions with the dynamic linker. It also asks for common errors, how Android components reach this code, and debugging using Frida.

**2. Initial Skim and Identification of Key Areas:**

A quick skim of the code immediately reveals:

* **Include Headers:**  `<dirent.h>`, `<errno.h>`, `<fcntl.h>`, etc., indicating this code tests directory-related functions. The presence of `gtest/gtest.h` confirms it's a unit test file using Google Test.
* **Test Functions:**  Functions like `TEST(dirent, ...)` clearly define individual test cases for different `dirent` functionalities.
* **Key libc functions:**  `scandir`, `scandir64`, `scandirat`, `scandirat64`, `fdopendir`, `opendir`, `closedir`, `readdir`, `readdir64`, `readdir_r`, `readdir64_r`, `rewinddir`, `seekdir`, `telldir`.
* **Specific Directory:** The recurring use of `/proc/self` is a strong indicator that the tests are interacting with the process's own view of the system.
* **Conditional Compilation:** The `#if !defined(ANDROID_HOST_MUSL)` suggests platform-specific behavior.

**3. Deconstructing the Functionality (Test by Test):**

The most logical way to analyze the functionality is to go through each `TEST` case. For each test:

* **Identify the libc function(s) being tested.**
* **Determine the core purpose of the test.** What scenario is it trying to verify? (e.g., basic functionality, error handling, 64-bit variants, etc.)
* **Look for assertions (`ASSERT_*`).** These reveal the expected behavior and help understand the test's intent.
* **Consider the setup and teardown.** What resources are being created and cleaned up (e.g., opening/closing directories)?
* **Note any specific data or logic.** For instance, `CheckProcSelf` verifies the presence of specific files in `/proc/self`.

**Example - Analyzing `TEST(dirent, scandir_scandir64)`:**

* **Functions Tested:** `scandir`, `scandir64`.
* **Purpose:**  Verify that `scandir` and `scandir64` return the same results when scanning a directory. Also checks that the results are sorted correctly.
* **Assertions:** `ASSERT_GE`, `ASSERT_EQ`, implying checks for a non-negative return value and equality between counts and the content of the returned directory entries.
* **Setup:** Opens `/proc/self` implicitly through `scandir`.
* **Logic:** Compares the results of `scandir` and `scandir64` by converting the directory entries into sets and sorted vectors.

**4. Connecting to Android:**

As the prompt states, `bionic` is Android's C library. Therefore, these tests directly verify the correctness of the directory manipulation functions implemented in Android's libc. The frequent use of `/proc/self` demonstrates interaction with Android's process model.

**5. Explaining libc Function Implementations:**

This requires more in-depth knowledge of operating system concepts and how these system calls are typically implemented. The thought process here involves:

* **General Knowledge of System Calls:**  Understand that functions like `opendir`, `readdir`, etc., are wrappers around underlying system calls (e.g., `open`, `getdents`).
* **Directory Structure:**  Recall how directories are organized on disk (inode pointers, directory entries).
* **Internal Data Structures:**  Imagine the data structures the libc might use to track opened directories (like the `DIR` structure).
* **Error Handling:**  Consider how errors are reported (setting `errno`).

**6. Addressing Dynamic Linker Aspects:**

This requires understanding how shared libraries (`.so` files) are loaded and linked in Android.

* **Shared Library Concept:**  Know that `dirent.h` functions reside in `libc.so`.
* **Linking Process:**  Understand that the dynamic linker resolves symbols at runtime.
* **PLT/GOT:**  Be aware of the Procedure Linkage Table (PLT) and Global Offset Table (GOT) mechanisms used for lazy binding.

**7. Identifying Common Errors:**

This comes from experience with using these functions. Common pitfalls include:

* **Forgetting to `closedir`:**  Leading to resource leaks.
* **Incorrect error checking:** Not checking `errno` after a function returns an error.
* **Buffer overflows (less relevant here but important in general C/C++).**
* **Misunderstanding `.` and `..` entries.**

**8. Tracing the Path from Framework/NDK:**

This requires understanding the Android architecture:

* **Android Framework (Java):**  Java code uses JNI (Java Native Interface) to call native code.
* **NDK (Native Development Kit):**  Allows developers to write native code that interacts with the Android system.
* **System Calls:**  Both the framework and NDK ultimately rely on system calls provided by the Linux kernel.

**9. Frida Hooking:**

This requires familiarity with Frida's syntax and capabilities. The process involves:

* **Identifying the target function.**
* **Using `Interceptor.attach` to hook the function.**
* **Logging arguments and return values.**

**10. Structuring the Response:**

Finally, organize the information clearly and logically, addressing each part of the prompt. Use headings, bullet points, and code examples to make the explanation easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus too much on the specifics of the test cases without first understanding the general purpose. *Correction:* Start with a high-level overview of the file's purpose and the functions it tests.
* **Overcomplicating libc implementation details:**  Trying to go into too much low-level detail without a clear request for it. *Correction:* Provide a general overview of the typical implementation approach.
* **Forgetting to address all parts of the prompt:**  Missing sections like common errors or Frida hooking initially. *Correction:*  Review the prompt carefully after drafting the initial response to ensure all points are addressed.

By following this structured approach, combining code analysis with general operating system and Android knowledge, and continuously refining the understanding, a comprehensive and accurate answer can be generated.
这个文件 `bionic/tests/dirent_test.cpp` 是 Android Bionic 库中用于测试目录操作相关函数（定义在 `<dirent.h>` 头文件中）的单元测试文件。Bionic 是 Android 系统的 C 标准库、数学库和动态链接器。

**文件功能:**

该文件的主要功能是使用 Google Test 框架对 Bionic 库中与目录操作相关的 libc 函数进行全面的测试，以确保这些函数在 Android 环境下的正确性和稳定性。具体来说，它测试了以下功能：

1. **目录扫描函数:**
   - `scandir()`: 扫描指定目录中的所有条目，并根据用户提供的过滤函数和排序函数进行处理。
   - `scandir64()`: `scandir()` 的 64 位版本，用于处理更大的目录和偏移量。
   - `scandirat()`: 相对于给定的文件描述符扫描目录。
   - `scandirat64()`: `scandirat()` 的 64 位版本。

2. **目录流操作函数:**
   - `opendir()`: 打开一个目录流。
   - `fdopendir()`: 从一个文件描述符创建一个目录流。
   - `readdir()`: 从目录流中读取下一个目录项。
   - `readdir64()`: `readdir()` 的 64 位版本。
   - `readdir_r()`: `readdir()` 的线程安全版本。
   - `readdir64_r()`: `readdir64()` 的线程安全版本。
   - `closedir()`: 关闭一个目录流。
   - `rewinddir()`: 将目录流的位置重置到开头。
   - `seekdir()`: 设置目录流的读取位置。
   - `telldir()`: 获取目录流的当前读取位置。

**与 Android 功能的关系及举例说明:**

这些目录操作函数是 Android 系统底层文件系统操作的基础，被广泛应用于 Android Framework 和 Native 开发中。

* **Android Framework:** Android Framework 的许多组件需要遍历文件系统，例如：
    * **PackageManager:**  扫描 `/data/app` 目录以查找已安装的应用程序。
    * **MediaScanner:** 扫描存储设备上的媒体文件。
    * **各种系统服务:**  读取配置文件或监控特定目录的变化。
    * **例如，PackageManager 在安装 APK 时，会使用 `opendir()`, `readdir()` 等函数来读取 APK 文件中的内容，并使用 `stat()` 等函数获取文件信息。**

* **NDK 开发:** NDK 允许开发者使用 C/C++ 编写 Android 应用的 native 代码。在 native 代码中，开发者可以直接调用这些 libc 函数进行文件和目录操作。
    * **例如，一个文件管理器应用可能会使用 `scandir()` 来获取用户指定目录下的所有文件和文件夹列表。**
    * **再比如，一个下载管理器可能会使用 `opendir()` 和 `readdir()` 来监控下载目录中新文件的出现。**

**libc 函数的实现原理:**

以下分别解释每个被测试的 libc 函数的实现原理（简要说明，具体实现可能因内核版本和架构而异）：

1. **`scandir(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))` 和 `scandir64()`:**
   - **功能:** 读取目录 `dirp` 中的所有目录项，对每个目录项调用 `filter` 函数进行过滤，将通过过滤的目录项存储在 `namelist` 指向的动态分配的数组中，并使用 `compar` 函数对数组进行排序。
   - **实现:**
     - 内部通常会调用底层的 `getdents` 或 `getdents64` 系统调用来读取目录项。
     - 动态分配内存来存储 `dirent` 结构体数组。
     - 遍历读取到的目录项，对每个条目调用 `filter` 函数，如果 `filter` 返回非零值，则将该条目复制到 `namelist` 指向的数组中。
     - 如果提供了 `compar` 函数，则使用 `qsort` 等排序算法对 `namelist` 数组进行排序。
     - 返回成功读取的目录项数量，失败返回 -1 并设置 `errno`。

2. **`scandirat(int dirfd, const char *pathname, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))` 和 `scandirat64()`:**
   - **功能:** 与 `scandir` 类似，但操作的目录由文件描述符 `dirfd` 和相对路径 `pathname` 指定。这允许在不改变当前工作目录的情况下操作其他目录。
   - **实现:**
     - 类似于 `scandir`，但会使用 `openat` 系统调用（如果目录是相对路径）或直接使用 `dirfd` 来操作目录。

3. **`opendir(const char *filename)`:**
   - **功能:** 打开路径名为 `filename` 的目录，返回一个指向 `DIR` 结构的指针，该结构用于后续的目录读取操作。
   - **实现:**
     - 内部调用 `open` 系统调用，并传入 `O_RDONLY` 和 `O_DIRECTORY` 标志，以打开指定目录。
     - 如果打开成功，则分配一个 `DIR` 结构体，并将文件描述符存储在其中。
     - `DIR` 结构体通常还会包含用于缓冲目录项的信息。
     - 失败返回 `NULL` 并设置 `errno`。

4. **`fdopendir(int fd)`:**
   - **功能:** 从一个已经打开的文件描述符 `fd` 创建一个目录流。`fd` 必须是一个打开的目录的文件描述符。
   - **实现:**
     - 检查 `fd` 是否有效，并且是否指向一个目录。
     - 分配一个 `DIR` 结构体，并将 `fd` 复制到该结构体中。
     - 失败返回 `NULL` 并设置 `errno`。

5. **`readdir(DIR *dirp)` 和 `readdir64(DIR *dirp)`:**
   - **功能:** 从 `dirp` 指向的目录流中读取下一个目录项，返回一个指向 `dirent` 结构体的指针。
   - **实现:**
     - 内部通常会调用底层的 `getdents` 或 `getdents64` 系统调用来获取一批目录项。
     - 将读取到的目录项缓存在 `DIR` 结构体中。
     - 每次调用 `readdir` 时，从缓冲区中返回下一个目录项的 `dirent` 结构体指针。
     - 如果到达目录末尾，则返回 `NULL`，但不设置 `errno` (除非之前有错误发生)。

6. **`readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)` 和 `readdir64_r(DIR *dirp, struct dirent64 *entry, struct dirent64 **result)`:**
   - **功能:** `readdir` 的线程安全版本。用户需要提供一个 `dirent` 结构体的指针 `entry` 用于存储读取到的目录项。
   - **实现:**
     - 与 `readdir` 类似，但避免了使用静态缓冲区，从而使其具有线程安全性。
     - 读取到的目录项信息会填充到用户提供的 `entry` 结构体中。
     - 如果读取成功，则将 `entry` 的地址赋值给 `result` 指向的指针；如果到达目录末尾，则将 `result` 指向的指针设置为 `NULL`。
     - 成功返回 0，失败返回错误码。

7. **`closedir(DIR *dirp)`:**
   - **功能:** 关闭 `dirp` 指向的目录流，释放相关的资源。
   - **实现:**
     - 内部调用 `close` 系统调用关闭与该目录流关联的文件描述符。
     - 释放 `DIR` 结构体占用的内存。
     - 成功返回 0，失败返回 -1 并设置 `errno`。

8. **`rewinddir(DIR *dirp)`:**
   - **功能:** 将 `dirp` 指向的目录流的读取位置重置到目录的开头。
   - **实现:**
     - 内部通常会调用底层的 `lseek` 系统调用，将文件偏移量设置为 0。
     - 可能会清除 `DIR` 结构体中的缓冲区信息。

9. **`seekdir(DIR *dirp, long loc)`:**
   - **功能:** 将 `dirp` 指向的目录流的读取位置设置为 `loc`，`loc` 值通常是通过 `telldir` 获取的。
   - **实现:**
     - 内部通常会调用底层的 `lseek` 系统调用，将文件偏移量设置为 `loc`。
     - 需要注意的是，`loc` 的值不一定是简单的文件偏移量，其具体含义取决于文件系统的实现。

10. **`telldir(DIR *dirp)`:**
    - **功能:** 获取 `dirp` 指向的目录流的当前读取位置。
    - **实现:**
      - 返回一个表示当前目录流位置的 `long` 值。这个值可以被传递给 `seekdir` 以便后续重新定位到该位置。
      -  这个返回值并非简单的文件偏移量，其内部表示是操作系统相关的，用于 `seekdir` 正确地定位。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程:**

这个测试文件本身主要测试的是 libc 的功能，与动态链接器的直接交互较少。然而，这些 libc 函数本身是由 `libc.so` 提供的，而动态链接器负责在程序启动时加载和链接这个共享库。

**so 布局样本 (`libc.so` 的部分):**

```
libc.so:
    .text          # 包含代码段，如 scandir, opendir 等函数的实现
    .rodata        # 包含只读数据
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .dynsym        # 动态符号表 (exported symbols)
    .dynstr        # 动态字符串表 (symbol names)
    .plt           # Procedure Linkage Table (用于延迟绑定)
    .got.plt       # Global Offset Table (PLT 部分)
    ...
```

**链接的处理过程:**

1. **编译时:** 当编译使用这些 libc 函数的代码时，编译器会生成对这些函数的外部引用。
2. **链接时:** 静态链接器在链接时会记录这些外部引用，并将它们标记为需要动态链接。
3. **运行时 (动态链接):**
   - 当程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会被加载。
   - 动态链接器会解析程序依赖的共享库，包括 `libc.so`。
   - 动态链接器会加载 `libc.so` 到内存中。
   - **符号解析:** 动态链接器会查找程序中引用的 `scandir`, `opendir` 等符号在 `libc.so` 中的地址。
   - **重定位:** 动态链接器会修改程序代码中的占位符地址，使其指向 `libc.so` 中对应函数的实际地址。这通常通过 PLT 和 GOT 完成：
     - **PLT (Procedure Linkage Table):**  当程序第一次调用 `scandir` 时，会跳转到 PLT 中对应的条目。
     - **GOT (Global Offset Table):** PLT 条目最初指向 GOT 中一个指向链接器自身的地址。
     - **延迟绑定:** 链接器被调用，找到 `scandir` 在 `libc.so` 中的实际地址，并更新 GOT 条目，使其指向 `scandir` 的实际地址。后续调用将直接跳转到 `scandir` 的实际地址。

**假设输入与输出 (逻辑推理):**

以 `TEST(dirent, scandir_scandir64)` 为例：

**假设输入:**

* 当前进程 ID 为 `12345`。
* `/proc/self` 目录下存在以下条目（实际情况会更多）：
    * `.` (当前目录)
    * `..` (父目录)
    * `cmdline`
    * `fd`
    * `stat`

**预期输出:**

* `scandir("/proc/self", ...)` 和 `scandir64("/proc/self", ...)` 都成功返回非负数（表示读取到的条目数量）。
* `scandir` 和 `scandir64` 返回的目录项数量相同。
* 两个函数返回的目录项名称集合（忽略顺序）相同，包含 ".", "..", "cmdline", "fd", "stat" 等。
* 两个函数返回的目录项名称列表（包含顺序）排序后是相同的。
* `CheckProcSelf` 函数的断言都通过，确认了关键条目的存在。

**用户或编程常见的使用错误:**

1. **忘记 `closedir()`:**  打开目录后忘记关闭，导致文件描述符泄漏，最终可能耗尽系统资源。

   ```c++
   DIR* d = opendir("/tmp");
   if (d != nullptr) {
       struct dirent* ent;
       while ((ent = readdir(d)) != nullptr) {
           // 处理目录项
       }
       // 忘记 closedir(d);  <-- 错误！
   }
   ```

2. **`readdir()` 返回 `NULL` 时未正确检查 `errno`:**  `readdir()` 在到达目录末尾时返回 `NULL`，但 `errno` 不会被设置（除非之前有错误发生）。如果错误地认为 `NULL` 总是表示错误，可能会导致逻辑错误。

   ```c++
   DIR* d = opendir("/tmp");
   if (d != nullptr) {
       errno = 0;
       struct dirent* ent;
       while ((ent = readdir(d)) != nullptr) {
           // 处理目录项
       }
       if (errno != 0) { // 错误的做法，到达末尾时 errno 为 0
           perror("readdir error");
       }
       closedir(d);
   }
   ```

3. **假设 `dirent` 结构体中的内容在多次 `readdir()` 调用之间保持不变:**  每次调用 `readdir()` 可能会覆盖之前的 `dirent` 结构体的内容（除非使用 `readdir_r`）。

   ```c++
   DIR* d = opendir("/tmp");
   if (d != nullptr) {
       struct dirent* ent1 = readdir(d);
       struct dirent* ent2 = readdir(d);
       // 假设 ent1 仍然指向第一个目录项的数据是错误的
       printf("%s\n", ent1->d_name); // 可能输出 ent2 的 d_name
       closedir(d);
   }
   ```

4. **传递无效的目录路径给 `opendir()` 或 `scandir()`:**  如果传递的路径不存在或不是目录，这些函数会返回错误并设置 `errno`。

5. **错误地使用 `seekdir()` 和 `telldir()`:**  `telldir()` 返回的值是与实现相关的，不应该被认为是一个简单的字节偏移量，只能用于后续的 `seekdir()` 调用。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

1. **Android Framework 调用:**
   - 假设一个 Java 层的 `File` 对象需要列出某个目录下的文件。
   - `java.io.File.list()` 方法最终会调用 native 方法 `java.io.File.list0()`。
   - `java.io.File.list0()` 方法会通过 JNI 调用 Bionic 库中的 `opendir()` 和 `readdir()` 等函数。

2. **NDK 调用:**
   - Native 代码可以直接包含 `<dirent.h>` 并调用 `opendir()`, `readdir()` 等函数。

**Frida Hook 示例:**

假设我们想 hook `opendir()` 函数，查看 Android Framework 是如何调用它的。

```python
import frida
import sys

package_name = "com.android.systemui" # 例如，hook System UI 进程

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['message']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 {package_name} 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "opendir"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        send({ tag: "opendir", message: "Opening directory: " + path });
    },
    onLeave: function(retval) {
        if (retval.isNull()) {
            send({ tag: "opendir", message: "opendir failed" });
        } else {
            send({ tag: "opendir", message: "opendir successful, DIR*: " + retval });
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 解释:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 连接的设备，并附加到指定的 Android 进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "opendir"), ...)`:**  拦截 `libc.so` 中导出的 `opendir` 函数。
3. **`onEnter`:** 在 `opendir` 函数调用之前执行。
   - `Memory.readUtf8String(args[0])` 读取 `opendir` 的第一个参数（目录路径）。
   - `send(...)` 将信息发送回 Frida 主机。
4. **`onLeave`:** 在 `opendir` 函数调用之后执行。
   - `retval` 是 `opendir` 函数的返回值（`DIR*` 指针）。
   - 根据返回值判断 `opendir` 是否成功。
5. **运行脚本:** 运行此 Frida 脚本后，当目标进程（例如 System UI）调用 `opendir()` 时，你将在 Frida 的输出中看到被打开的目录路径。

通过类似的 Frida hook 技术，你可以拦截其他目录操作函数，并观察 Android Framework 或 NDK 代码在执行文件系统操作时的具体行为和参数。这对于调试和理解 Android 系统的底层工作原理非常有帮助。

### 提示词
```
这是目录为bionic/tests/dirent_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <string>

#include "utils.h"

static void CheckProcSelf(std::set<std::string>& names) {
  // We have a good idea of what should be in /proc/self.
  ASSERT_TRUE(names.contains("."));
  ASSERT_TRUE(names.contains(".."));
  ASSERT_TRUE(names.contains("cmdline"));
  ASSERT_TRUE(names.contains("fd"));
  ASSERT_TRUE(names.contains("stat"));
}

template <typename DirEntT>
void ScanEntries(DirEntT** entries, int entry_count,
                 std::set<std::string>& name_set, std::vector<std::string>& name_list) {
  for (size_t i = 0; i < static_cast<size_t>(entry_count); ++i) {
    name_set.insert(entries[i]->d_name);
    name_list.push_back(entries[i]->d_name);
    free(entries[i]);
  }
  free(entries);
}

TEST(dirent, scandir_scandir64) {
  // Get everything from /proc/self...
  dirent** entries;
  int entry_count = scandir("/proc/self", &entries, nullptr, alphasort);
  ASSERT_GE(entry_count, 0);

  dirent64** entries64;
  int entry_count64 = scandir64("/proc/self", &entries64, nullptr, alphasort64);
  ASSERT_EQ(entry_count, entry_count64);

  // Turn the directory entries into a set and vector of the names.
  std::set<std::string> name_set;
  std::vector<std::string> unsorted_name_list;
  ScanEntries(entries, entry_count, name_set, unsorted_name_list);

  // No duplicates.
  ASSERT_EQ(name_set.size(), unsorted_name_list.size());

  // All entries sorted.
  std::vector<std::string> sorted_name_list(unsorted_name_list);
  std::sort(sorted_name_list.begin(), sorted_name_list.end());
  ASSERT_EQ(sorted_name_list, unsorted_name_list);

  // scandir64 returned the same results as scandir.
  std::set<std::string> name_set64;
  std::vector<std::string> unsorted_name_list64;
  ScanEntries(entries64, entry_count64, name_set64, unsorted_name_list64);
  ASSERT_EQ(name_set, name_set64);
  ASSERT_EQ(unsorted_name_list, unsorted_name_list64);

  CheckProcSelf(name_set);
}

TEST(dirent, scandirat_scandirat64) {
#if !defined(ANDROID_HOST_MUSL)
  // Get everything from /proc/self...
  dirent** entries;
  int entry_count = scandir("/proc/self", &entries, nullptr, alphasort);
  ASSERT_GE(entry_count, 0);

  int proc_fd = open("/proc", O_DIRECTORY);
  ASSERT_NE(-1, proc_fd);

  dirent** entries_at;
  int entry_count_at = scandirat(proc_fd, "self", &entries_at, nullptr, alphasort);
  ASSERT_EQ(entry_count, entry_count_at);

  dirent64** entries_at64;
  int entry_count_at64 = scandirat64(proc_fd, "self", &entries_at64, nullptr, alphasort64);
  ASSERT_EQ(entry_count, entry_count_at64);

  close(proc_fd);

  // scandirat and scandirat64 should return the same results as scandir.
  std::set<std::string> name_set, name_set_at, name_set_at64;
  std::vector<std::string> unsorted_name_list, unsorted_name_list_at, unsorted_name_list_at64;
  ScanEntries(entries, entry_count, name_set, unsorted_name_list);
  ScanEntries(entries_at, entry_count_at, name_set_at, unsorted_name_list_at);
  ScanEntries(entries_at64, entry_count_at64, name_set_at64, unsorted_name_list_at64);

  ASSERT_EQ(name_set, name_set_at);
  ASSERT_EQ(name_set, name_set_at64);
  ASSERT_EQ(unsorted_name_list, unsorted_name_list_at);
  ASSERT_EQ(unsorted_name_list, unsorted_name_list_at64);
#else
  GTEST_SKIP() << "musl doesn't have scandirat or scandirat64";
#endif
}

static int is_version_filter(const dirent* de) {
  return !strcmp(de->d_name, "version");
}

TEST(dirent, scandir_filter) {
  dirent** entries;
  ASSERT_EQ(1, scandir("/proc", &entries, is_version_filter, nullptr));
  ASSERT_STREQ("version", entries[0]->d_name);
  free(entries);
}

TEST(dirent, scandir_ENOENT) {
  dirent** entries;
  errno = 0;
  ASSERT_EQ(-1, scandir("/does-not-exist", &entries, nullptr, nullptr));
  ASSERT_ERRNO(ENOENT);
}

TEST(dirent, scandir64_ENOENT) {
  dirent64** entries;
  errno = 0;
  ASSERT_EQ(-1, scandir64("/does-not-exist", &entries, nullptr, nullptr));
  ASSERT_ERRNO(ENOENT);
}

TEST(dirent, scandirat_ENOENT) {
#if !defined(ANDROID_HOST_MUSL)
  int root_fd = open("/", O_DIRECTORY | O_RDONLY);
  ASSERT_NE(-1, root_fd);
  dirent** entries;
  errno = 0;
  ASSERT_EQ(-1, scandirat(root_fd, "does-not-exist", &entries, nullptr, nullptr));
  ASSERT_ERRNO(ENOENT);
  close(root_fd);
#else
  GTEST_SKIP() << "musl doesn't have scandirat or scandirat64";
#endif
}

TEST(dirent, scandirat64_ENOENT) {
#if !defined(ANDROID_HOST_MUSL)
  int root_fd = open("/", O_DIRECTORY | O_RDONLY);
  ASSERT_NE(-1, root_fd);
  dirent64** entries;
  errno = 0;
  ASSERT_EQ(-1, scandirat64(root_fd, "does-not-exist", &entries, nullptr, nullptr));
  ASSERT_ERRNO(ENOENT);
  close(root_fd);
#else
  GTEST_SKIP() << "musl doesn't have scandirat or scandirat64";
#endif
}

TEST(dirent, fdopendir_invalid) {
  ASSERT_TRUE(fdopendir(-1) == nullptr);
  ASSERT_ERRNO(EBADF);

  int fd = open("/dev/null", O_RDONLY);
  ASSERT_NE(fd, -1);
  ASSERT_TRUE(fdopendir(fd) == nullptr);
  ASSERT_ERRNO(ENOTDIR);
  close(fd);
}

TEST(dirent, fdopendir) {
  int fd = open("/proc/self", O_RDONLY);
  DIR* d = fdopendir(fd);
  ASSERT_TRUE(d != nullptr);
  dirent* e = readdir(d);
  ASSERT_STREQ(e->d_name, ".");
  ASSERT_EQ(closedir(d), 0);

  // fdopendir(3) took ownership, so closedir(3) closed our fd.
  ASSERT_EQ(close(fd), -1);
  ASSERT_ERRNO(EBADF);
}

TEST(dirent, opendir_invalid) {
  errno = 0;
  ASSERT_TRUE(opendir("/does/not/exist") == nullptr);
  ASSERT_ERRNO(ENOENT);

  errno = 0;
  ASSERT_TRUE(opendir("/dev/null") == nullptr);
  ASSERT_ERRNO(ENOTDIR);
}

TEST(dirent, opendir) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  dirent* e = readdir(d);
  ASSERT_STREQ(e->d_name, ".");
  ASSERT_EQ(closedir(d), 0);
}

TEST(dirent, closedir_invalid) {
  DIR* d = nullptr;
  ASSERT_EQ(closedir(d), -1);
  ASSERT_ERRNO(EINVAL);
}

TEST(dirent, closedir) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  ASSERT_EQ(closedir(d), 0);
}

TEST(dirent, readdir) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  std::set<std::string> name_set;
  errno = 0;
  dirent* e;
  while ((e = readdir(d)) != nullptr) {
    name_set.insert(e->d_name);
  }
  // Reading to the end of the directory is not an error.
  // readdir(3) returns NULL, but leaves errno as 0.
  ASSERT_ERRNO(0);
  ASSERT_EQ(closedir(d), 0);

  CheckProcSelf(name_set);
}

TEST(dirent, readdir64_smoke) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  std::set<std::string> name_set;
  errno = 0;
  dirent64* e;
  while ((e = readdir64(d)) != nullptr) {
    name_set.insert(e->d_name);
  }
  // Reading to the end of the directory is not an error.
  // readdir64(3) returns NULL, but leaves errno as 0.
  ASSERT_ERRNO(0);
  ASSERT_EQ(closedir(d), 0);

  CheckProcSelf(name_set);
}

TEST(dirent, readdir_r) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  std::set<std::string> name_set;
  errno = 0;
  dirent storage;
  dirent* e = nullptr;
  while (readdir_r(d, &storage, &e) == 0 && e != nullptr) {
    name_set.insert(e->d_name);
  }
  // Reading to the end of the directory is not an error.
  // readdir_r(3) returns NULL, but leaves errno as 0.
  ASSERT_ERRNO(0);
  ASSERT_EQ(closedir(d), 0);

  CheckProcSelf(name_set);
}

TEST(dirent, readdir64_r_smoke) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  std::set<std::string> name_set;
  errno = 0;
  dirent64 storage;
  dirent64* e = nullptr;
  while (readdir64_r(d, &storage, &e) == 0 && e != nullptr) {
    name_set.insert(e->d_name);
  }
  // Reading to the end of the directory is not an error.
  // readdir64_r(3) returns NULL, but leaves errno as 0.
  ASSERT_ERRNO(0);
  ASSERT_EQ(closedir(d), 0);

  CheckProcSelf(name_set);
}

TEST(dirent, rewinddir) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);

  // Get all the names once...
  std::vector<std::string> pass1;
  dirent* e;
  while ((e = readdir(d)) != nullptr) {
    pass1.push_back(e->d_name);
  }

  // ...rewind...
  rewinddir(d);

  // ...and get all the names again.
  std::vector<std::string> pass2;
  while ((e = readdir(d)) != nullptr) {
    pass2.push_back(e->d_name);
  }

  ASSERT_EQ(closedir(d), 0);

  // We should have seen the same names in the same order both times.
  ASSERT_EQ(pass1.size(), pass2.size());
  for (size_t i = 0; i < pass1.size(); ++i) {
    ASSERT_EQ(pass1[i], pass2[i]);
  }
}

TEST(dirent, seekdir_telldir) {
  DIR* d = opendir("/proc/self");
  ASSERT_TRUE(d != nullptr);
  std::vector<long> offset_list;
  std::vector<std::string> name_list;
  dirent* e = nullptr;

  offset_list.push_back(telldir(d));
  ASSERT_EQ(0L, offset_list.back());

  while ((e = readdir(d)) != nullptr) {
    name_list.push_back(e->d_name);
    offset_list.push_back(telldir(d));
    // Make sure telldir() point to the next entry.
    ASSERT_EQ(e->d_off, offset_list.back());
  }

  long end_offset = telldir(d);
  // telldir() should not pass the end of the file.
  ASSERT_EQ(offset_list.back(), end_offset);
  offset_list.pop_back();

  for (size_t i = 0; i < offset_list.size(); ++i) {
    seekdir(d, offset_list[i]);
    ASSERT_EQ(offset_list[i], telldir(d));
    e = readdir(d);
    ASSERT_TRUE(e != nullptr);
    ASSERT_STREQ(name_list[i].c_str(), e->d_name);
  }
  for (int i = static_cast<int>(offset_list.size()) - 1; i >= 0; --i) {
    seekdir(d, offset_list[i]);
    ASSERT_EQ(offset_list[i], telldir(d));
    e = readdir(d);
    ASSERT_TRUE(e != nullptr);
    ASSERT_STREQ(name_list[i].c_str(), e->d_name);
  }

  // Seek to the end, read NULL.
  seekdir(d, end_offset);
  ASSERT_EQ(end_offset, telldir(d));
  errno = 0;
  ASSERT_EQ(nullptr, readdir(d));
  ASSERT_ERRNO(0);

  ASSERT_EQ(0, closedir(d));
}
```
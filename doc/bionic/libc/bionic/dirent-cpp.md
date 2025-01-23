Response:
Here's a breakdown of the thought process to generate the comprehensive answer:

1. **Understand the Core Task:** The primary goal is to analyze the `dirent.cpp` file and explain its functionality, especially within the Android Bionic context. This includes explaining the individual functions, their interaction with Android, dynamic linking aspects, potential errors, and how the Android framework uses them.

2. **Break Down the File:**  The next step is to dissect the provided C++ code, identifying the key components:
    * **Includes:**  Note the header files (`dirent.h`, `errno.h`, etc.). These hint at the functionality the file implements (directory operations, error handling, file system interactions).
    * **External Function Declaration:**  The `__getdents64` declaration is crucial and needs specific attention regarding its role in fetching directory entries.
    * **`DIR` Structure:** This structure is central to how directory information is managed. Understanding its members (`fd_`, `available_bytes_`, `next_`, `mutex_`, `buff_`, `current_pos_`) is key.
    * **Helper Functions:** Identify functions like `__get_dir_tag`, `__allocate_DIR`, `__fill_DIR`, and `__readdir_locked`. These encapsulate specific logic and contribute to the overall functionality.
    * **Public Functions:** Focus on the standard libc functions like `dirfd`, `opendir`, `readdir`, `readdir_r`, `closedir`, `rewinddir`, `seekdir`, `telldir`, and `alphasort`. These are the main entry points for interacting with directories.
    * **`__strong_alias`:** Recognize these as providing alternative names (e.g., `readdir64`) for compatibility or internal reasons.

3. **Analyze Each Function:**  For each function, consider:
    * **Purpose:** What does this function do?  Relate it back to directory manipulation.
    * **Implementation Details:** How does it achieve its purpose?  Does it use system calls (like `open`, `fstat`, `lseek`, `close`, `__getdents64`)? Does it manipulate the `DIR` structure?
    * **Error Handling:**  Does it check for null pointers or handle errors using `errno`?
    * **Threading:** Does it use mutexes to ensure thread safety?
    * **Android Relevance:** How does this function fit into the broader Android ecosystem?  Think about how applications might use it.

4. **Connect to Android:**  Actively look for connections to Android-specific features:
    * **Bionic:** Explicitly mention that this code *is* part of Bionic.
    * **`android/fdsan.h`:**  Explain the purpose of `fdsan` (file descriptor sanitization) and how it's used for resource tracking.
    * **`private/bionic_fortify.h`:** Mention `__fortify_fatal` for debugging and security.
    * **`private/ErrnoRestorer.h`:** Explain the utility of preserving and restoring `errno`.
    * **Dynamic Linking:** The `__getdents64` function is a prime example of something that might involve the dynamic linker, although in this *specific* file, the interaction is indirect. Focus on explaining what dynamic linking *is* and how system calls often work in that context. The request for SO layout and linking process requires a more generalized explanation since this file doesn't *directly* handle linking.

5. **Consider Dynamic Linking (Even if Indirect):**
    * Even though `dirent.cpp` doesn't perform linking itself, it *uses* functions (like `__getdents64`) that are provided by the kernel and accessed through system calls. The dynamic linker plays a role in setting up this interface.
    * Explain the concept of shared libraries (`.so` files) and how the dynamic linker resolves symbols at runtime. Provide a basic example of SO layout.

6. **Think About Common Errors:**  Imagine how a developer might misuse these functions:
    * Not checking for null returns from `opendir`.
    * Using a `DIR*` after calling `closedir`.
    * Incorrectly handling errors returned by `readdir_r`.

7. **Illustrate Android Framework Usage:**  How does the Android framework (or NDK) reach this code?
    * Start with a high-level example (e.g., a file manager app).
    * Trace the path down through Java APIs (`java.io.File`), native methods, and finally, libc functions like `opendir` and `readdir`.

8. **Provide a Frida Hook Example:**  Create a practical example of using Frida to intercept and inspect calls to `readdir`. This demonstrates how to debug and understand the function's behavior at runtime.

9. **Structure and Language:** Organize the information logically using headings and bullet points. Use clear and concise Chinese. Explain technical terms when necessary. Ensure the language is accessible to developers.

10. **Review and Refine:** Read through the entire answer, checking for accuracy, completeness, and clarity. Ensure all parts of the original request have been addressed. For example, explicitly state the functions provided by the file and their purpose. Make sure the examples are relevant and easy to understand. Initially, I might have focused too much on the `DIR` struct without fully explaining the *purpose* of the functions. Reviewing helps catch such imbalances. Also, double-check that the Frida example is correct and runnable.
好的，让我们来详细分析 `bionic/libc/bionic/dirent.cpp` 这个文件。

**功能概览**

`dirent.cpp` 文件是 Android Bionic C 库中实现目录操作相关函数的源代码文件。它提供了与 POSIX 标准 `dirent.h` 头文件相对应的函数，允许程序遍历和读取目录的内容。主要功能包括：

* **打开目录:**  `opendir()` 和 `fdopendir()` 函数用于打开一个目录，返回一个 `DIR*` 类型的指针，用于后续的目录操作。
* **读取目录项:** `readdir()` 和 `readdir_r()` 函数用于从已打开的目录中读取下一个目录项 (文件或子目录)。
* **关闭目录:** `closedir()` 函数用于关闭已打开的目录，释放相关的资源。
* **重置目录读取位置:** `rewinddir()` 函数用于将目录的读取位置重置到开头。
* **定位目录读取位置:** `seekdir()` 和 `telldir()` 函数用于在目录中设置和获取当前的读取位置。
* **排序目录项:** `alphasort()` 函数用于按照字母顺序比较两个目录项。
* **获取目录的文件描述符:** `dirfd()` 函数用于获取与 `DIR*` 关联的文件描述符。

**与 Android 功能的关系及举例**

这些目录操作函数是 Android 系统和应用程序中非常基础和常用的功能，它们广泛应用于：

* **文件管理器应用:** 文件管理器需要列出目录中的文件和子目录，这会直接使用 `opendir()` 和 `readdir()` 系列函数。
* **包管理器 (PackageManager):**  在安装、卸载或查找应用时，PackageManager 需要扫描应用安装目录、`data` 目录等，会用到这些函数。
* **媒体扫描器 (Media Scanner):**  媒体扫描器需要遍历存储设备上的目录，查找媒体文件（图片、音频、视频），也会使用这些函数。
* **各种系统服务:**  许多系统服务需要监控文件系统的变化或者读取配置文件，都会间接地或直接地使用这些目录操作函数。
* **NDK 开发:** 使用 NDK 进行原生 C/C++ 开发的应用程序可以直接调用这些 libc 函数进行目录操作。

**举例说明:**

假设一个简单的文件管理器应用需要列出 `/sdcard/Pictures` 目录下的所有文件：

```c++
#include <iostream>
#include <dirent.h>
#include <string>

int main() {
  DIR *dir;
  struct dirent *ent;
  std::string path = "/sdcard/Pictures";

  dir = opendir(path.c_str());
  if (dir != nullptr) {
    while ((ent = readdir(dir)) != nullptr) {
      std::cout << ent->d_name << std::endl;
    }
    closedir(dir);
  } else {
    perror("opendir failed");
    return 1;
  }
  return 0;
}
```

在这个例子中，`opendir()` 打开了指定的目录，`readdir()` 循环读取目录项，并打印出文件名，最后 `closedir()` 关闭了目录。

**libc 函数的实现详解**

下面详细解释 `dirent.cpp` 中各个 libc 函数的实现：

1. **`opendir(const char* path)`:**
   - 功能：打开指定路径的目录。
   - 实现：
     - 调用底层的 `open()` 系统调用，并传递 `O_CLOEXEC | O_DIRECTORY | O_RDONLY` 标志。
       - `O_CLOEXEC`:  确保在 `execve` 系统调用后关闭该文件描述符，防止子进程继承。
       - `O_DIRECTORY`: 确保打开的是一个目录，如果不是则返回错误。
       - `O_RDONLY`:  以只读模式打开目录。
     - 如果 `open()` 成功，则调用 `__allocate_DIR()` 函数分配一个 `DIR` 结构体，并将文件描述符存储在 `DIR` 结构体的 `fd_` 成员中。
     - 如果 `open()` 失败，则返回 `nullptr`。

2. **`fdopendir(int fd)`:**
   - 功能：从一个已打开的文件描述符创建一个目录流。
   - 实现：
     - 首先使用 `fstat()` 系统调用获取文件描述符 `fd` 的状态信息。
     - 检查 `fstat()` 返回的 `stat` 结构体的 `st_mode` 成员，确保该文件描述符对应的是一个目录（使用 `S_ISDIR()` 宏）。
     - 如果是目录，则调用 `__allocate_DIR()` 函数分配一个 `DIR` 结构体，并将文件描述符存储在 `DIR` 结构体的 `fd_` 成员中。
     - 如果不是目录或 `fstat()` 失败，则返回 `nullptr` 并设置相应的 `errno`。

3. **`__allocate_DIR(int fd)`:**
   - 功能：分配并初始化一个 `DIR` 结构体。
   - 实现：
     - 使用 `malloc()` 分配 `sizeof(DIR)` 大小的内存。
     - 初始化 `DIR` 结构体的成员：
       - `fd_`:  设置为传入的文件描述符。
       - `available_bytes_`: 初始化为 0，表示缓冲区为空。
       - `next_`: 初始化为 `nullptr`，表示当前没有可用的目录项。
       - `current_pos_`: 初始化为 0，表示当前目录流的位置在开头。
       - `mutex_`: 使用 `pthread_mutex_init()` 初始化互斥锁，用于线程安全。
     - 调用 `android_fdsan_exchange_owner_tag()` 将文件描述符与分配的 `DIR` 结构体关联起来，用于 `fdsan` (file descriptor sanitizer) 的追踪。

4. **`closedir(DIR* d)`:**
   - 功能：关闭一个目录流。
   - 实现：
     - 检查 `d` 是否为 `nullptr`，如果是则设置 `errno` 为 `EINVAL` 并返回 -1。
     - 获取 `DIR` 结构体中的文件描述符 `fd_`。
     - 调用 `pthread_mutex_destroy()` 销毁与该 `DIR` 结构体关联的互斥锁。
     - 调用 `android_fdsan_close_with_tag()` 关闭文件描述符，并使用之前分配的 tag 进行 `fdsan` 的清理。
     - 使用 `free()` 释放 `DIR` 结构体占用的内存。
     - 返回底层 `close()` 系统调用的返回值。

5. **`readdir(DIR* d)`:**
   - 功能：读取目录流中的下一个目录项。
   - 实现：
     - 使用 `CHECK_DIR(d)` 宏检查 `d` 是否为 `nullptr`。
     - 获取与 `DIR` 结构体关联的互斥锁，确保线程安全。
     - 调用 `__readdir_locked(d)` 执行实际的读取操作。
     - 释放互斥锁。
     - 返回 `__readdir_locked()` 的返回值。

6. **`readdir_r(DIR* d, dirent* entry, dirent** result)`:**
   - 功能：`readdir()` 的线程安全版本，将读取到的目录项存储到用户提供的缓冲区中。
   - 实现：
     - 使用 `CHECK_DIR(d)` 宏检查 `d` 是否为 `nullptr`。
     - 初始化 `*result` 为 `nullptr`，并重置 `errno` 为 0。
     - 获取与 `DIR` 结构体关联的互斥锁。
     - 调用 `__readdir_locked(d)` 执行实际的读取操作。
     - 如果 `__readdir_locked()` 返回的 `next` 不为 `nullptr`，则使用 `memcpy()` 将 `next` 指向的目录项数据复制到用户提供的 `entry` 缓冲区中，并将 `*result` 指向 `entry`。
     - 如果发生错误并且 `next` 为 `nullptr`，则返回当前的 `errno` 值。
     - 释放互斥锁。
     - 返回 0 表示成功，否则返回错误码。

7. **`__readdir_locked(DIR* d)`:**
   - 功能：在持有互斥锁的情况下，执行实际的目录项读取操作。
   - 实现：
     - 如果 `d->available_bytes_` 为 0，表示当前缓冲区为空，则调用 `__fill_DIR(d)` 填充缓冲区。如果 `__fill_DIR()` 返回 `false`，则表示没有更多目录项可读，返回 `nullptr`。
     - 获取当前缓冲区中的下一个目录项指针 `entry`，即 `d->next_`。
     - 将 `d->next_` 指针移动到下一个目录项的位置，通过将当前目录项的地址加上其长度 `entry->d_reclen` 计算得到。
     - 更新 `d->available_bytes_`，减去已读取的目录项长度。
     - 更新 `d->current_pos_` 为当前目录项的偏移量 `entry->d_off`。
     - 返回读取到的目录项指针 `entry`。

8. **`__fill_DIR(DIR* d)`:**
   - 功能：使用 `__getdents64()` 系统调用填充 `DIR` 结构体的内部缓冲区。
   - 实现：
     - 调用 `TEMP_FAILURE_RETRY(__getdents64(d->fd_, d->buff_, sizeof(d->buff_)))`。
       - `__getdents64()` 是一个 Linux 系统调用，用于读取目录项。
       - `d->fd_`:  要读取的目录的文件描述符。
       - `d->buff_`:  `DIR` 结构体内部的缓冲区，用于存储读取到的目录项。
       - `sizeof(d->buff_)`:  缓冲区的大小。
       - `TEMP_FAILURE_RETRY()` 是一个宏，用于处理被信号中断的系统调用。
     - 如果 `__getdents64()` 返回值 `rc` 大于 0，表示成功读取到目录项：
       - 将 `d->available_bytes_` 设置为读取到的字节数 `rc`。
       - 将 `d->next_` 指向缓冲区 `d->buff_` 的开头。
       - 返回 `true`。
     - 如果 `__getdents64()` 返回值小于等于 0，表示读取失败或已到达目录末尾，返回 `false`。

9. **`rewinddir(DIR* d)`:**
   - 功能：将目录流的读取位置重置到开头。
   - 实现：
     - 使用 `CHECK_DIR(d)` 宏检查 `d` 是否为 `nullptr`。
     - 获取与 `DIR` 结构体关联的互斥锁。
     - 调用 `lseek(d->fd_, 0, SEEK_SET)` 系统调用，将目录的文件描述符的读写位置设置为开头。
     - 将 `d->available_bytes_` 重置为 0，表示缓冲区为空。
     - 将 `d->current_pos_` 重置为 0。
     - 释放互斥锁。

10. **`seekdir(DIR* d, long offset)`:**
    - 功能：将目录流的读取位置设置为指定的偏移量。
    - 实现：
        - 使用 `CHECK_DIR(d)` 宏检查 `d` 是否为 `nullptr`。
        - 获取与 `DIR` 结构体关联的互斥锁。
        - 调用 `lseek(d->fd_, offset, SEEK_SET)` 系统调用，尝试将目录的文件描述符的读写位置设置为指定的 `offset`。
        - 如果 `lseek()` 成功（返回值不为 -1L），则将 `d->available_bytes_` 重置为 0，表示缓冲区失效，并将 `d->current_pos_` 更新为新的偏移量。
        - 释放互斥锁。

11. **`telldir(DIR* d)`:**
    - 功能：获取目录流的当前读取位置。
    - 实现：
        - 使用 `CHECK_DIR(d)` 宏检查 `d` 是否为 `nullptr`。
        - 直接返回 `d->current_pos_` 的值。

12. **`dirfd(DIR* d)`:**
    - 功能：获取与 `DIR` 结构体关联的文件描述符。
    - 实现：
        - 使用 `CHECK_DIR(d)` 宏检查 `d` 是否为 `nullptr`。
        - 直接返回 `d->fd_` 的值。

13. **`alphasort(const dirent** a, const dirent** b)`:**
    - 功能：使用 `strcoll()` 函数按照本地化字符排序规则比较两个目录项的名称。
    - 实现：
        - 直接调用 `strcoll((*a)->d_name, (*b)->d_name)`，比较两个 `dirent` 结构体中 `d_name` 成员指向的文件名。

**涉及 dynamic linker 的功能**

在 `dirent.cpp` 中，最相关的 dynamic linker 功能体现在对 `__getdents64()` 函数的使用上。

* **`__getdents64()` 的作用:** 这是一个 Linux 内核提供的系统调用，用于读取目录项。它不是 Bionic libc 自身实现的，而是由内核提供。
* **动态链接:**  当程序调用 `readdir()` 等函数时，Bionic libc 最终会调用到 `__getdents64()`。这个调用需要通过动态链接器来完成。
* **SO 布局样本:**  假设一个简单的 Android 应用，它链接了 Bionic libc。

```
/system/lib64/libc.so  (Bionic libc 动态链接库)
/system/bin/app_process64 (Android 运行时进程)
/data/app/com.example.myapp/lib/arm64-v8a/libnative.so (应用的 native 库)
/data/app/com.example.myapp/base.apk (应用的 APK 文件)
```

* **链接的处理过程:**
    1. **编译时:** 编译器在编译链接 `dirent.cpp` 时，会生成对 `__getdents64()` 的外部符号引用。
    2. **加载时:** 当应用启动时，Android 运行时进程 `app_process64` 会加载应用的 native 库 (`libnative.so`) 和 Bionic libc (`libc.so`)。
    3. **动态链接:** 动态链接器 (在 Android 上是 `linker64`) 会解析 `libnative.so` 中对 libc 函数的引用，并将这些引用绑定到 `libc.so` 中相应的函数地址。
    4. **系统调用:**  `__getdents64()` 实际上是一个系统调用，其实现位于 Linux 内核中。Bionic libc 中对 `__getdents64()` 的声明只是一个接口。当 Bionic libc 中的 `__fill_DIR()` 函数调用 `__getdents64()` 时，实际上会触发一个从用户空间到内核空间的切换。

**假设输入与输出**

**`opendir()`:**

* **假设输入:** `path = "/sdcard/Download"`
* **预期输出:** 如果 `/sdcard/Download` 存在且是目录，则返回一个非空的 `DIR*` 指针；否则，返回 `nullptr` 并设置相应的 `errno` (例如 `ENOENT` 如果目录不存在)。

**`readdir()`:**

* **假设输入:**  `DIR* dir` 是通过 `opendir("/sdcard/Pictures")` 成功打开的目录流。
* **预期输出:** 第一次调用返回指向第一个目录项的 `dirent*` 指针，包含文件名、类型等信息。后续调用依次返回后续的目录项，直到目录末尾，此时返回 `nullptr`。

**`closedir()`:**

* **假设输入:**  通过 `opendir()` 获取的有效的 `DIR*` 指针。
* **预期输出:** 返回 0 表示成功关闭目录，并释放相关资源。如果输入是 `nullptr`，则返回 -1 并设置 `errno` 为 `EINVAL`。

**用户或编程常见的使用错误**

1. **未检查 `opendir()` 的返回值:** 如果 `opendir()` 返回 `nullptr`，直接使用返回的 `DIR*` 指针会导致程序崩溃。
   ```c++
   DIR *dir = opendir("/nonexistent_path");
   // 错误：未检查 dir 是否为 nullptr
   struct dirent *ent = readdir(dir);
   ```

2. **在 `closedir()` 后继续使用 `DIR*` 指针:**  关闭目录后，`DIR*` 指针指向的内存可能已经被释放或重用，继续使用会导致未定义行为。
   ```c++
   DIR *dir = opendir("/sdcard");
   // ... 使用 dir ...
   closedir(dir);
   // 错误：在 closedir 之后继续使用 dir
   struct dirent *ent = readdir(dir);
   ```

3. **在多线程环境中使用非线程安全的 `readdir()`:**  `readdir()` 不是线程安全的，在多线程环境下并发调用同一个 `DIR*` 指针可能导致数据竞争。应该使用线程安全的 `readdir_r()`。

4. **忘记调用 `closedir()`:**  打开的目录需要手动关闭，否则会泄露文件描述符，最终可能导致系统资源耗尽。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
   - 当 Java 代码需要访问文件系统目录时，通常会使用 `java.io.File` 类。
   - 例如，`File.listFiles()` 方法会列出指定目录下的文件和目录。
   - `File.listFiles()` 的内部实现最终会通过 JNI (Java Native Interface) 调用到 Android 运行时的 native 代码。

2. **Android 运行时 (Native 代码):**
   - Android 运行时 (如 `libjavacore.so` 或 `libopenjdk.so`) 实现了 `java.io.File` 类对应的 native 方法。
   - 这些 native 方法会调用 Bionic libc 提供的目录操作函数，例如 `opendir()`, `readdir()`, `closedir()`。

3. **NDK 开发:**
   - 使用 NDK 进行原生开发的应用程序可以直接包含 `<dirent.h>` 头文件，并调用 `opendir()`, `readdir()` 等函数。

**Frida Hook 示例调试**

可以使用 Frida Hook 来观察 `readdir()` 函数的调用和参数：

```javascript
// hook_readdir.js
if (ObjC.available) {
    console.log("Objective-C runtime available, but this is a C function hook.");
} else {
    console.log("Objective-C runtime not available.");
}

// 找到 readdir 函数的地址
var readdirPtr = Module.findExportByName("libc.so", "readdir");

if (readdirPtr) {
    console.log("Found readdir at:", readdirPtr);

    Interceptor.attach(readdirPtr, {
        onEnter: function (args) {
            this.dirPtr = args[0];
            console.log("readdir called with DIR*:", this.dirPtr);
        },
        onLeave: function (retval) {
            if (retval.isNull()) {
                console.log("readdir returned NULL (end of directory).");
            } else {
                var dent = ptr(retval);
                var d_name = Memory.readCString(dent.add(offsetof_dirent_d_name));
                console.log("readdir returned:", d_name);
            }
        }
    });
} else {
    console.error("Could not find readdir in libc.so");
}

// 获取 dirent 结构体中 d_name 的偏移量 (需要根据目标架构调整)
// 这是一个简化的假设，实际偏移量可能需要根据目标平台和 Bionic 版本确定
var offsetof_dirent_d_name = Process.pointerSize * 2; // 假设 d_name 是第三个成员
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook_readdir.js`。
2. 找到目标 Android 进程的进程 ID (PID)。
3. 使用 Frida 连接到目标进程并运行脚本：
   ```bash
   frida -U -f <your_package_name> -l hook_readdir.js --no-pause
   # 或者，如果进程已经在运行：
   frida -U <PID> -l hook_readdir.js
   ```

**Frida Hook 说明:**

* 该脚本尝试在 `libc.so` 中找到 `readdir` 函数的地址。
* 使用 `Interceptor.attach()` 拦截 `readdir` 函数的调用。
* `onEnter` 函数在 `readdir` 函数被调用前执行，打印出传入的 `DIR*` 指针。
* `onLeave` 函数在 `readdir` 函数返回后执行，打印出返回的 `dirent*` 指针指向的目录项名称。
* `offsetof_dirent_d_name` 需要根据目标平台的 `dirent` 结构体定义进行调整。可以使用 `adb shell getconf | grep _DIRENT_` 命令查看相关定义。

通过 Frida Hook，你可以实时观察应用程序对目录操作函数的调用，帮助你调试和理解程序的行为。

希望这个详细的分析能够帮助你理解 `bionic/libc/bionic/dirent.cpp` 的功能和实现。

### 提示词
```
这是目录为bionic/libc/bionic/dirent.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <dirent.h>

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android/fdsan.h>

#include "private/bionic_fortify.h"
#include "private/ErrnoRestorer.h"
#include "private/ScopedPthreadMutexLocker.h"

extern "C" int __getdents64(unsigned int, dirent*, unsigned int);

// Apportable decided to copy the data structure from this file
// and use it in their own code, but they also call into readdir.
// In order to avoid a lockup, the structure must be maintained in
// the exact same order as in L and below. New structure members
// need to be added to the end of this structure.
// See b/21037208 for more details.
struct DIR {
  int fd_;
  size_t available_bytes_;
  dirent* next_;
  pthread_mutex_t mutex_;
  dirent buff_[15];
  long current_pos_;
};

#define CHECK_DIR(d) if (d == nullptr) __fortify_fatal("%s: null DIR*", __FUNCTION__)

static uint64_t __get_dir_tag(DIR* dir) {
  return android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_DIR,
                                        reinterpret_cast<uint64_t>(dir));
}

static DIR* __allocate_DIR(int fd) {
  DIR* d = reinterpret_cast<DIR*>(malloc(sizeof(DIR)));
  if (d == nullptr) {
    return nullptr;
  }
  d->fd_ = fd;
  android_fdsan_exchange_owner_tag(fd, 0, __get_dir_tag(d));
  d->available_bytes_ = 0;
  d->next_ = nullptr;
  d->current_pos_ = 0L;
  pthread_mutex_init(&d->mutex_, nullptr);
  return d;
}

int dirfd(DIR* d) {
  CHECK_DIR(d);
  return d->fd_;
}

DIR* fdopendir(int fd) {
  // Is 'fd' actually a directory?
  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    return nullptr;
  }
  if (!S_ISDIR(sb.st_mode)) {
    errno = ENOTDIR;
    return nullptr;
  }

  return __allocate_DIR(fd);
}

DIR* opendir(const char* path) {
  int fd = open(path, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
  return (fd != -1) ? __allocate_DIR(fd) : nullptr;
}

static bool __fill_DIR(DIR* d) {
  CHECK_DIR(d);
  int rc = TEMP_FAILURE_RETRY(__getdents64(d->fd_, d->buff_, sizeof(d->buff_)));
  if (rc <= 0) {
    return false;
  }
  d->available_bytes_ = rc;
  d->next_ = d->buff_;
  return true;
}

static dirent* __readdir_locked(DIR* d) {
  if (d->available_bytes_ == 0 && !__fill_DIR(d)) {
    return nullptr;
  }

  dirent* entry = d->next_;
  d->next_ = reinterpret_cast<dirent*>(reinterpret_cast<char*>(entry) + entry->d_reclen);
  d->available_bytes_ -= entry->d_reclen;
  // The directory entry offset uses 0, 1, 2 instead of real file offset,
  // so the value range of long type is enough.
  d->current_pos_ = static_cast<long>(entry->d_off);
  return entry;
}

dirent* readdir(DIR* d) {
  CHECK_DIR(d);
  ScopedPthreadMutexLocker locker(&d->mutex_);
  return __readdir_locked(d);
}
__strong_alias(readdir64, readdir);

int readdir_r(DIR* d, dirent* entry, dirent** result) {
  CHECK_DIR(d);

  ErrnoRestorer errno_restorer;

  *result = nullptr;
  errno = 0;

  ScopedPthreadMutexLocker locker(&d->mutex_);

  dirent* next = __readdir_locked(d);
  if (errno != 0 && next == nullptr) {
    return errno;
  }

  if (next != nullptr) {
    memcpy(entry, next, next->d_reclen);
    *result = entry;
  }
  return 0;
}
__strong_alias(readdir64_r, readdir_r);

int closedir(DIR* d) {
  if (d == nullptr) {
    errno = EINVAL;
    return -1;
  }

  int fd = d->fd_;
  pthread_mutex_destroy(&d->mutex_);
  int rc = android_fdsan_close_with_tag(fd, __get_dir_tag(d));
  free(d);
  return rc;
}

void rewinddir(DIR* d) {
  CHECK_DIR(d);

  ScopedPthreadMutexLocker locker(&d->mutex_);
  lseek(d->fd_, 0, SEEK_SET);
  d->available_bytes_ = 0;
  d->current_pos_ = 0L;
}

void seekdir(DIR* d, long offset) {
  CHECK_DIR(d);

  ScopedPthreadMutexLocker locker(&d->mutex_);
  off_t ret = lseek(d->fd_, offset, SEEK_SET);
  if (ret != -1L) {
    d->available_bytes_ = 0;
    d->current_pos_ = ret;
  }
}

long telldir(DIR* d) {
  CHECK_DIR(d);

  return d->current_pos_;
}

int alphasort(const dirent** a, const dirent** b) {
  return strcoll((*a)->d_name, (*b)->d_name);
}
__strong_alias(alphasort64, alphasort);
```
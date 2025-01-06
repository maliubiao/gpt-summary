Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The request is to analyze the `bionic/libc/bionic/open.cpp` file, focusing on its functionalities, relationship to Android, implementation details, dynamic linker involvement, potential errors, and how Android frameworks reach this code. The response needs to be in Chinese, and include Frida hooking examples.

**2. Initial Code Scan and Function Identification:**

The first step is to read through the provided C++ code and identify the key functions. We can see the following:

* `creat`: Creates a new file or truncates an existing one.
* `open`: Opens a file, allowing for various flags and potentially creating the file.
* `__open_2`: A variant of `open` that expects the mode to be handled elsewhere.
* `openat`: Opens a file relative to a directory file descriptor.
* `__openat_2`: A variant of `openat` that expects the mode to be handled elsewhere.
* Internal helper functions: `force_O_LARGEFILE` and `needs_mode`.
* Macros: `__strong_alias`.

**3. Categorizing Functionalities:**

Next, group these functions based on their purpose. The primary functionality is file opening and creation. We can also identify helper functions for flag manipulation.

**4. Connecting to Android Functionality:**

Think about how these basic file operations are used in Android. Every app, service, and the system itself interacts with files. Examples include:

* Reading configuration files.
* Writing logs.
* Accessing data in the file system.
* Creating temporary files.
* Interacting with hardware through device files.

This leads to concrete examples like accessing app data in `/data/data/<package name>/`, or writing to log files in `/dev/log/`.

**5. Deconstructing Implementation Details (libc Functions):**

For each exposed libc function (`creat`, `open`, `openat`), dissect its implementation:

* **Parameter Handling:** Note the `pathname`, `flags`, and `mode` parameters. Emphasize the use of `va_args` for optional `mode`.
* **System Call Delegation:**  Recognize the core functionality is delegated to the `__openat` system call (or a related syscall). This is the crucial link to the kernel.
* **Helper Function Usage:** Explain the purpose of `force_O_LARGEFILE` (historical reasons for supporting large files on 32-bit systems) and `needs_mode` (determines if a mode argument is expected).
* **`__strong_alias`:** Explain that this macro provides backward compatibility by aliasing older function names.
* **`FDTRACK_CREATE` and `FDTRACK_CREATE_NAME`:** Note these are for internal Bionic file descriptor tracking, although a full deep dive might not be necessary for the initial explanation.

**6. Addressing Dynamic Linker Involvement:**

The prompt specifically asks about the dynamic linker. While this `open.cpp` file itself doesn't directly *perform* dynamic linking, it's *part of* the libc, which *is* dynamically linked. Therefore:

* Explain the role of the dynamic linker in loading shared libraries like libc.so.
* Create a simple example `so` layout with `libc.so` and an app's executable.
* Illustrate the linking process:  The app calls `open`, the dynamic linker resolves this to the `open` function within `libc.so`, and the code in `open.cpp` is executed.

**7. Identifying Common Usage Errors:**

Consider how developers might misuse these functions:

* Forgetting the `mode` when using `O_CREAT`.
* Incorrect permissions in the `mode`.
* Trying to open a non-existent file without `O_CREAT`.
* Race conditions when multiple processes try to open/create the same file.

Provide code examples to illustrate these errors.

**8. Tracing the Execution Flow (Android Framework/NDK):**

This requires a top-down approach:

* **NDK:** A C/C++ app directly calls `open`. This is the simplest case.
* **Android Framework (Java):**  Methods like `java.io.FileInputStream`, `FileOutputStream`, and `File.createNewFile()` are wrappers around system calls. Trace the path: Java method -> native method in the Android runtime (like `libjavacrypto.so` or `libopenjdk.so`) ->  eventually calling the `open` function in Bionic's libc.

**9. Crafting Frida Hook Examples:**

For each entry point (`open`, `creat`, `openat`), create a concise Frida script:

* Explain how to hook the function.
* Demonstrate logging the arguments (`pathname`, `flags`, `mode`).
* Optionally, show how to modify the behavior (though the request doesn't explicitly demand this, it's a good illustration of Frida's power).

**10. Structuring the Response in Chinese:**

Throughout the process, keep the target language in mind. Translate technical terms accurately and ensure the explanation flows naturally in Chinese. Use clear and concise language.

**11. Review and Refine:**

After drafting the response, reread it carefully:

* Is all the requested information present?
* Are the explanations clear and accurate?
* Are the examples relevant and easy to understand?
* Is the Chinese grammatically correct and natural?

**Self-Correction/Refinement Example During the Process:**

Initially, I might focus too much on the low-level details of the `__openat` syscall. However, realizing the target audience might be developers and not just kernel experts, I would shift the emphasis to the libc functions and their usage, while still mentioning the syscall connection. Also, I might initially forget to explicitly address the dynamic linker's role and would need to add that section. The Frida examples need to be practical and directly demonstrate hooking the relevant functions.
好的，我们来详细分析一下 `bionic/libc/bionic/open.cpp` 这个文件。

**文件功能概述**

`open.cpp` 文件是 Android Bionic C 库中关于文件打开和创建操作的关键组成部分。它实现了以下几个核心的 POSIX 标准 C 库函数：

* **`open()`**:  打开一个文件，可以用于读取、写入或同时进行读写操作。如果指定了 `O_CREAT` 标志，且文件不存在，则会创建该文件。
* **`creat()`**: 创建一个新的文件。它的功能相当于 `open()` 函数，并指定了 `O_CREAT | O_TRUNC | O_WRONLY` 标志，即如果文件存在则截断为零长度，并以只写方式打开。
* **`openat()`**:  与 `open()` 类似，但允许指定一个目录文件描述符 `fd` 作为起始路径，用于打开相对于该目录的文件。这在处理相对路径时非常有用，特别是当需要避免竞态条件时。

此外，该文件还包含一些内部辅助函数和宏：

* **`force_O_LARGEFILE()`**:  确保在 32 位系统上设置 `O_LARGEFILE` 标志，以支持打开大于 2GB 的文件。在 64 位系统上，该标志默认启用，因此该函数直接返回传入的 `flags`。
* **`needs_mode()`**:  检查 `flags` 中是否设置了 `O_CREAT` 或 `O_TMPFILE` 标志。如果设置了，则表示调用者需要在 `open()` 或 `openat()` 函数中提供 `mode` 参数来指定新创建文件的权限。
* **`__openat()`**:  这是一个底层的系统调用包装函数，实际执行文件打开操作。在 Bionic 中，它通常会调用 Linux 内核的 `openat` 系统调用。
* **`__strong_alias`**:  这是一个宏，用于为函数创建强别名。例如，`__strong_alias(creat64, creat)` 表示 `creat64` 函数是 `creat` 函数的强别名，它们指向相同的代码。这通常用于提供 64 位兼容性，尽管在这种情况下，`creat` 和 `creat64` 的实现是相同的。
* **`FDTRACK_CREATE` 和 `FDTRACK_CREATE_NAME`**:  这些宏用于 Bionic 内部的文件描述符跟踪机制，用于调试和资源管理。
* **`__fortify_fatal`**:  用于在检测到潜在的安全漏洞时终止程序。

**与 Android 功能的关系及举例说明**

这些文件操作函数是 Android 系统和应用程序的基础。几乎所有的文件 I/O 操作都会最终调用到这些函数。以下是一些例子：

* **应用程序访问本地存储:** 当一个 Android 应用需要读取或写入设备上的文件时（例如，保存用户设置、缓存数据等），它会使用 Java SDK 提供的 `FileInputStream`、`FileOutputStream` 等类。这些类最终会调用到 Native 代码中的 `open()` 或 `creat()` 函数。
    * **例子:** 一个图片编辑应用需要保存用户编辑后的图片到 `/sdcard/Pictures/` 目录，这个过程会涉及到 `open()` 函数的调用。
* **系统服务管理文件:** Android 系统服务（例如 `system_server`）需要读取配置文件、日志文件等。这些操作也会使用到 `open()` 函数。
    * **例子:** `logd` 服务需要打开 `/dev/log/main` 等日志设备文件，这会调用 `open()`。
* **应用安装和卸载:**  `PackageManagerService` 需要创建和删除应用的数据目录，这会使用到 `open()` 和相关的目录操作函数，但 `open()` 也可能用于创建特定文件。
* **网络通信:**  虽然网络通信主要使用 socket，但在某些情况下，例如使用 Unix domain socket 进行进程间通信，也可能涉及到 `open()` 函数来打开 socket 文件。
* **设备驱动交互:**  Android 系统通过文件系统与设备驱动进行交互。例如，访问摄像头设备可能需要打开 `/dev/video0`，这会调用 `open()`。

**libc 函数的功能实现**

让我们逐个解释 `open.cpp` 中实现的 libc 函数：

**1. `creat(const char* pathname, mode_t mode)`**

* **功能:** 创建一个新的文件。如果指定的文件已存在，则会将其截断为零长度。
* **实现:**
    ```c++
    int creat(const char* pathname, mode_t mode) {
      return open(pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
    }
    ```
    `creat()` 函数的实现非常简单，它直接调用了 `open()` 函数，并传递了预定义的标志：
    * `O_CREAT`: 如果文件不存在则创建它。
    * `O_TRUNC`: 如果文件存在则截断其长度为零。
    * `O_WRONLY`: 以只写模式打开文件。
    `mode` 参数指定了新创建文件的访问权限。

**2. `open(const char* pathname, int flags, ...)`**

* **功能:** 打开指定路径名的文件。可以指定多种标志来控制打开的行为（例如，只读、只写、创建、追加等）。
* **实现:**
    ```c++
    int open(const char* pathname, int flags, ...) {
      mode_t mode = 0;

      if (needs_mode(flags)) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
      }

      return FDTRACK_CREATE(__openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), mode));
    }
    ```
    * **参数处理:**
        * `pathname`: 要打开的文件路径。
        * `flags`:  控制文件打开方式的标志（例如 `O_RDONLY`, `O_WRONLY`, `O_CREAT`, `O_APPEND` 等）。
        * `...`: 可变参数，如果 `flags` 中包含 `O_CREAT` 或 `O_TMPFILE`，则需要传入 `mode_t mode` 参数来指定新创建文件的权限。
    * **`needs_mode(flags)`:**  检查是否需要 `mode` 参数。
    * **可变参数处理:** 使用 `va_list` 宏来处理可变参数，提取出 `mode` 值。
    * **`force_O_LARGEFILE(flags)`:**  确保在 32 位系统上设置 `O_LARGEFILE`。
    * **`__openat(AT_FDCWD, pathname, ..., mode)`:**  调用底层的 `__openat` 函数来执行实际的打开操作。`AT_FDCWD` 表示相对于当前工作目录。
    * **`FDTRACK_CREATE(...)`:**  使用文件描述符跟踪机制记录新创建的文件描述符。

**3. `__open_2(const char* pathname, int flags)`**

* **功能:**  与 `open()` 类似，但假定调用者已经处理了 `mode` 参数，因此不接受可变参数。通常用于内部调用或优化的场景。
* **实现:**
    ```c++
    int __open_2(const char* pathname, int flags) {
      if (needs_mode(flags)) __fortify_fatal("open: called with O_CREAT/O_TMPFILE but no mode");
      return FDTRACK_CREATE_NAME("open", __openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), 0));
    }
    ```
    * **错误检查:** 如果 `flags` 中包含 `O_CREAT` 或 `O_TMPFILE`，但没有提供 `mode`，则调用 `__fortify_fatal` 终止程序，以避免潜在的安全问题。
    * **`FDTRACK_CREATE_NAME(...)`:**  使用文件描述符跟踪机制记录文件描述符，并指定一个名称 "open" 用于标识。

**4. `openat(int fd, const char *pathname, int flags, ...)`**

* **功能:**  打开相对于目录文件描述符 `fd` 的文件。
* **实现:**
    ```c++
    int openat(int fd, const char *pathname, int flags, ...) {
      mode_t mode = 0;

      if (needs_mode(flags)) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
      }

      return FDTRACK_CREATE_NAME("openat", __openat(fd, pathname, force_O_LARGEFILE(flags), mode));
    }
    ```
    * **参数处理:**  与 `open()` 类似，但多了一个 `fd` 参数，表示起始目录的文件描述符。如果 `fd` 为 `AT_FDCWD`，则行为与 `open()` 相同。
    * **`__openat(fd, pathname, ..., mode)`:**  调用底层的 `__openat` 函数，并传递 `fd` 参数。
    * **`FDTRACK_CREATE_NAME(...)`:** 使用文件描述符跟踪机制记录文件描述符，并指定名称 "openat"。

**5. `__openat_2(int fd, const char* pathname, int flags)`**

* **功能:**  与 `openat()` 类似，但假定 `mode` 参数已处理。
* **实现:**
    ```c++
    int __openat_2(int fd, const char* pathname, int flags) {
      if (needs_mode(flags)) __fortify_fatal("open: called with O_CREAT/O_TMPFILE but no mode");
      return FDTRACK_CREATE_NAME("openat", __openat(fd, pathname, force_O_LARGEFILE(flags), 0));
    }
    ```
    * **错误检查:** 与 `__open_2` 类似。

**涉及 dynamic linker 的功能**

虽然 `open.cpp` 本身并没有直接实现 dynamic linker 的功能，但它是 `libc.so` 的一部分，而 `libc.so` 是一个共享库，需要 dynamic linker (在 Android 上是 `linker64` 或 `linker`) 来加载和链接。

**so 布局样本:**

假设有一个简单的 Android 应用程序 `my_app`，它使用了 `open()` 函数。其内存布局可能如下所示：

```
[内存地址范围]   [内容]
------------------------------------
...              ...
[libc.so 的加载地址]
                 libc.so 的代码段 (.text)
                   - open() 函数的代码位于此处
                 libc.so 的数据段 (.data)
                 libc.so 的动态链接信息 (.dynamic)
...
[linker64 的加载地址]
                 linker64 的代码段
                 linker64 的数据段
...
[my_app 的加载地址]
                 my_app 的代码段
                   - 调用 open() 的代码位于此处
                 my_app 的数据段
...
```

**链接的处理过程:**

1. **编译时链接:** 当 `my_app` 被编译时，编译器会记录下它依赖于 `libc.so` 中的 `open()` 函数。这个依赖关系信息会被存储在 `my_app` 的 ELF 文件的动态链接段 (`.dynamic`) 中。
2. **加载时链接:** 当 Android 系统启动 `my_app` 进程时，内核会将 `my_app` 的可执行文件加载到内存中。
3. **dynamic linker 启动:** 内核会启动 dynamic linker (`linker64` 或 `linker`) 来处理 `my_app` 的动态链接需求。
4. **查找依赖:** dynamic linker 读取 `my_app` 的动态链接段，发现它依赖于 `libc.so`。
5. **加载共享库:** dynamic linker 搜索系统路径（例如 `/system/lib64` 或 `/system/lib`）找到 `libc.so`，并将其加载到内存中的某个地址。
6. **符号解析:** dynamic linker 解析 `libc.so` 的符号表，找到 `open()` 函数的地址。
7. **重定位:** dynamic linker 修改 `my_app` 中调用 `open()` 函数的指令，将目标地址更新为 `libc.so` 中 `open()` 函数的实际地址。这个过程称为重定位。
8. **执行:** 当 `my_app` 执行到调用 `open()` 函数的代码时，程序会跳转到 `libc.so` 中 `open()` 函数的地址执行。

**逻辑推理的假设输入与输出**

**假设输入:**

* `pathname`: `/tmp/test.txt`
* `flags`: `O_WRONLY | O_CREAT`
* `mode`: `0644` (八进制，表示文件所有者具有读写权限，其他人只读)

**输出:**

* 如果 `/tmp/test.txt` 不存在，`open()` 函数会创建一个新的文件，并返回一个非负的文件描述符。该文件的权限将被设置为 `0644`。
* 如果 `/tmp/test.txt` 已经存在，`open()` 函数会以只写模式打开该文件，并返回一个非负的文件描述符。
* 如果由于某种原因无法创建或打开文件（例如，权限不足），`open()` 函数会返回 -1，并设置 `errno` 全局变量来指示错误类型。

**用户或编程常见的使用错误**

1. **忘记指定 `mode` 参数:** 当使用 `O_CREAT` 或 `O_TMPFILE` 标志时，必须提供 `mode` 参数来指定新创建文件的权限。忘记提供 `mode` 会导致未定义的行为或安全漏洞。
    ```c++
    // 错误示例：忘记指定 mode
    int fd = open("/tmp/new_file.txt", O_WRONLY | O_CREAT); // 错误！
    ```
    **Bionic 的保护:**  `__open_2` 和 `__openat_2` 函数中的 `if (needs_mode(flags)) __fortify_fatal(...)` 就是为了捕获这种错误，并在运行时终止程序，防止潜在的安全问题。

2. **使用错误的 `mode` 值:**  `mode` 值应该是一个八进制数，表示文件权限。使用十进制或其他格式可能会导致意外的权限设置。
    ```c++
    // 错误示例：使用十进制 mode
    int fd = open("/tmp/new_file.txt", O_WRONLY | O_CREAT, 644); // 错误，应该使用 0644
    ```

3. **没有检查返回值:**  `open()` 和 `creat()` 函数在出错时会返回 -1。没有检查返回值并处理错误可能导致程序崩溃或其他不可预测的行为。
    ```c++
    int fd = open("/nonexistent_file.txt", O_RDONLY);
    // 缺少错误检查
    read(fd, buffer, size); // 如果 open 失败，fd 为 -1，read 会出错
    ```
    **正确的做法:**
    ```c++
    int fd = open("/nonexistent_file.txt", O_RDONLY);
    if (fd == -1) {
      perror("open failed");
      // 处理错误，例如退出程序或返回错误码
    } else {
      read(fd, buffer, size);
      close(fd);
    }
    ```

4. **竞态条件:**  在多线程或多进程环境下，如果多个线程或进程同时尝试创建同一个文件，可能会出现竞态条件。可以使用 `O_EXCL` 标志来避免这种情况。
    ```c++
    // 使用 O_CREAT | O_EXCL 可以确保文件不存在时才创建，如果已存在则 open 失败
    int fd = open("/tmp/my_lock_file", O_CREAT | O_EXCL | O_RDWR, 0666);
    if (fd == -1 && errno == EEXIST) {
      // 文件已存在，其他进程已经持有锁
    } else if (fd != -1) {
      // 成功创建文件，获得锁
      // ... 执行需要互斥的操作 ...
      close(fd);
    } else {
      perror("open failed");
    }
    ```

**Android Framework 或 NDK 如何到达这里**

**1. 从 NDK (Native Development Kit) 调用:**

最直接的方式是使用 NDK 开发的 C/C++ 代码直接调用 `open()` 函数。

```c++
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() {
  const char* filename = "/sdcard/test_ndk.txt";
  int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd == -1) {
    perror("open failed");
    return 1;
  }
  const char* data = "Hello from NDK!";
  write(fd, data, strlen(data));
  close(fd);
  printf("File created successfully!\n");
  return 0;
}
```

当这段 NDK 代码运行时，它会直接链接到 Bionic 的 `libc.so`，并调用其中的 `open()` 函数。

**2. 从 Android Framework (Java) 调用:**

Android Framework 提供了 Java API 来进行文件操作，例如 `java.io.FileInputStream`、`java.io.FileOutputStream`、`java.io.File` 等。这些 Java API 的底层实现会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 中的 native 代码，最终会调用到 Bionic 的 libc 函数。

**调用链示例 (FileOutputStream):**

```
Java 代码:
FileOutputStream fos = new FileOutputStream("/sdcard/test_java.txt");
fos.write("Hello from Java!".getBytes());
fos.close();

-> Android Framework (Java): java.io.FileOutputStream.open(...)
-> Android Runtime (Native):  例如 libjavacrypto.so 或 libopenjdk.so 中的 native 方法，
                           这些方法会处理文件路径、标志等参数。
-> Bionic (Native): open("/sdcard/test_java.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644)  // 最终调用到 bionic/libc/bionic/open.cpp 中的 open 函数
```

**Frida Hook 示例调试步骤**

我们可以使用 Frida 来 Hook `open()` 函数，观察其调用过程和参数。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const openPtr = Module.findExportByName("libc.so", "open");

  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        const pathname = Memory.readUtf8String(args[0]);
        const flags = args[1].toInt();
        let mode = -1;
        if ((flags & 0x00000040 /* O_CREAT */) || (flags & 0x00010000 /* O_TMPFILE */)) {
          mode = args[2].toInt();
        }

        console.log("[open] pathname:", pathname);
        console.log("[open] flags:", flags.toString(16));
        if (mode !== -1) {
          console.log("[open] mode:", mode.toString(8));
        }
      },
      onLeave: function (retval) {
        console.log("[open] returned:", retval.toInt());
      }
    });
  } else {
    console.error("Could not find open function in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端 (`frida-server`)。
2. **启动目标应用:** 运行你想要调试的 Android 应用程序。
3. **运行 Frida 脚本:** 使用 Frida 命令行工具将脚本注入到目标进程中。你需要知道目标应用的进程名称或 PID。

   ```bash
   frida -U -n <目标应用进程名> -l your_script.js
   ```
   或者，如果知道 PID：
   ```bash
   frida -U <PID> -l your_script.js
   ```
4. **执行文件操作:** 在目标应用中执行会调用 `open()` 函数的操作，例如保存文件、读取文件等。
5. **查看 Frida 输出:** Frida 会在控制台上打印出 `open()` 函数被调用时的参数和返回值，包括文件路径、标志和权限模式。

**示例 Frida 输出:**

```
[Pixel 6::目标应用进程名]-> [open] pathname: /data/user/0/com.example.myapp/files/my_data.txt
[Pixel 6::目标应用进程名]-> [open] flags: a2 (O_WRONLY|O_CREAT|O_TRUNC)
[Pixel 6::目标应用进程名]-> [open] mode: 600
[Pixel 6::目标应用进程名]-> [open] returned: 3
```

这个输出表明 `open()` 函数被调用，打开或创建了 `/data/user/0/com.example.myapp/files/my_data.txt` 文件，使用了 `O_WRONLY | O_CREAT | O_TRUNC` 标志，权限模式为 `600`，并返回了文件描述符 `3`。

通过这种方式，你可以详细了解 Android 应用程序在底层是如何使用 `open()` 函数进行文件操作的。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/open.cpp` 的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/open.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "private/bionic_fdtrack.h"
#include "private/bionic_fortify.h"

extern "C" int __openat(int, const char*, int, int);

static inline int force_O_LARGEFILE(int flags) {
#if defined(__LP64__)
  return flags; // No need, and aarch64's strace gets confused.
#else
  return flags | O_LARGEFILE;
#endif
}

static inline bool needs_mode(int flags) {
  return ((flags & O_CREAT) == O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
}

int creat(const char* pathname, mode_t mode) {
  return open(pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
}
__strong_alias(creat64, creat);

int open(const char* pathname, int flags, ...) {
  mode_t mode = 0;

  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  return FDTRACK_CREATE(__openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), mode));
}
__strong_alias(open64, open);

int __open_2(const char* pathname, int flags) {
  if (needs_mode(flags)) __fortify_fatal("open: called with O_CREAT/O_TMPFILE but no mode");
  return FDTRACK_CREATE_NAME("open", __openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), 0));
}

int openat(int fd, const char *pathname, int flags, ...) {
  mode_t mode = 0;

  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  return FDTRACK_CREATE_NAME("openat", __openat(fd, pathname, force_O_LARGEFILE(flags), mode));
}
__strong_alias(openat64, openat);

int __openat_2(int fd, const char* pathname, int flags) {
  if (needs_mode(flags)) __fortify_fatal("open: called with O_CREAT/O_TMPFILE but no mode");
  return FDTRACK_CREATE_NAME("openat", __openat(fd, pathname, force_O_LARGEFILE(flags), 0));
}

"""

```
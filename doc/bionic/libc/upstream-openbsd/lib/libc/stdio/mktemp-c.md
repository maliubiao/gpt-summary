Response:
Let's break down the thought process for analyzing the `mktemp.c` code and generating the detailed explanation.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the `mktemp.c` file within the Android Bionic library. The key aspects to cover are:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it relate to Android?
* **Detailed Implementation:** How does each libc function work?
* **Dynamic Linking:**  Is it involved, and if so, how?
* **Logic & Examples:** Provide input/output scenarios.
* **Common Errors:** What mistakes do programmers often make?
* **Android Integration:** How is it reached from Android frameworks/NDK?  Frida example.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to grasp its core purpose. Keywords like `mktemp`, `mkstemp`, `mkdtemp`, `open`, `mkdir`, `lstat`, and the manipulation of 'X' characters strongly suggest this code is about creating unique temporary file or directory names. The copyright notice at the top confirms it's derived from OpenBSD.

**3. Identifying Core Functions and their Roles:**

* **`mktemp_internal`:** This is clearly the central function, taking parameters for the path, suffix length, mode (file, directory, name), and flags. It's responsible for the core logic of generating and checking temporary names.
* **`_mktemp`:** A wrapper around `mktemp_internal` for creating unique file names (without opening). It's marked as potentially unsafe.
* **`mktemp`:**  Another wrapper, likely for compatibility, directly calling `_mktemp`.
* **`mkostemps`:**  Calls `mktemp_internal` to create and open a temporary file with a specified suffix and flags.
* **`mkstemp`:** A common, safer version to create and open a temporary file. Calls `mktemp_internal`.
* **`mkostemp`:** Similar to `mkostemps` but without a suffix.
* **`mkstemps`:**  Creates and opens a temporary file with a suffix.
* **`mkdtemp`:**  Creates a unique temporary directory.

**4. Deep Dive into `mktemp_internal`:**

This is the most complex function and requires careful examination:

* **Input Validation:** Checks for minimum 'X' characters, valid suffix length, and valid flags.
* **Finding 'X's:** Locates the sequence of 'X' characters that will be replaced.
* **Randomization:** Uses `arc4random_buf` to generate random characters to replace the 'X's.
* **Looping and Retries:** The `do...while` loop handles potential collisions (if a generated name already exists). It retries up to `INT_MAX` times.
* **Mode Handling:** The `switch` statement determines the action based on the `mode`:
    * `MKTEMP_NAME`: Just checks if the name exists using `lstat`.
    * `MKTEMP_FILE`: Creates and opens the file using `open` with `O_CREAT | O_EXCL | O_RDWR` and permissions.
    * `MKTEMP_DIR`: Creates the directory using `mkdir`.
* **Error Handling:** Sets `errno` appropriately and returns -1 on failure.

**5. Analyzing Libc Function Usage:**

For each libc function used, explain its purpose and how it's used in this context:

* **`strlen`:** Get the length of the path.
* **`errno`:**  Used for error reporting.
* **`open`:** Create and open a file. Explain the flags used (`O_CREAT`, `O_EXCL`, `O_RDWR`, other optional flags).
* **`mkdir`:** Create a directory.
* **`lstat`:** Get file status without following symbolic links (important for security).
* **`arc4random_buf`:** Generate cryptographically secure random bytes.
* **`INT_MAX`:** The maximum value of an integer, used for the retry loop.
* **`S_IRUSR`, `S_IWUSR`, `S_IXUSR`:** File permission bits.
* **`memset` (though not directly used, it's good to mention string manipulation functions):**  Initialize memory.
* **`strcpy` (though not directly used):** Copy strings.

**6. Addressing Dynamic Linking:**

* Recognize the `DEF_WEAK` macro. This indicates weak symbols, a dynamic linking concept.
* Explain what weak symbols are and why they are used (allowing overriding by other libraries).
* Create a simple `.so` layout example to illustrate how weak symbols might be resolved. Describe the linker's process of preferring strong symbols over weak ones.

**7. Crafting Examples and Scenarios:**

* **Basic Usage:** Demonstrate simple calls to `mkstemp` and `mkdtemp`.
* **Error Scenarios:** Show what happens with invalid paths (too few 'X's), and when the maximum retry count is reached.
* **Security Concerns:**  Highlight the unsafety of `mktemp` and the preference for `mkstemp`.

**8. Connecting to Android:**

* Explain that this code is part of Bionic, Android's standard C library.
* Provide examples of how Android framework components or NDK developers might use these functions (e.g., creating temporary files for downloads, IPC, etc.).

**9. Frida Hook Example:**

* Choose a relevant function (like `mkstemp`).
* Write a basic Frida script that intercepts the function call, logs the input path, and the generated temporary file path. Explain the steps involved in hooking.

**10. Structuring the Output:**

Organize the information logically with clear headings and subheadings. Use code blocks for examples and code snippets. Maintain a consistent tone and language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the history of `mktemp`'s security issues. **Correction:**  While mentioning the unsafety is crucial, the focus should be on explaining the *current* implementation and how it's used in Android.
* **Initial thought:**  Provide a highly complex dynamic linking scenario. **Correction:** Keep the dynamic linking example simple and focused on the `DEF_WEAK` macro. Overly complex examples might confuse the core concept.
* **Initial thought:**  Include every single libc function. **Correction:** Focus on the *most relevant* libc functions directly used within the code. Mentioning string manipulation functions conceptually is good, but a detailed explanation of every possible function isn't necessary.
* **Initial thought:**  Make the Frida script extremely advanced. **Correction:**  Start with a basic hook to demonstrate the concept. More complex hooking scenarios can be mentioned as possibilities.

By following this structured approach and continually refining the analysis, a comprehensive and accurate explanation of the `mktemp.c` file can be generated.
好的，让我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdio/mktemp.c` 这个文件。

**文件功能概述**

这个文件实现了与创建唯一临时文件名或目录名相关的几个函数。这些函数的主要目的是避免在创建临时文件或目录时发生命名冲突，从而提高安全性和可靠性。

具体来说，它提供了以下几个核心功能：

1. **`mktemp(char *path)`**:  （已过时且不安全）尝试通过替换 `path` 字符串末尾的 "XXXXXX" 模式为随机字符来创建一个唯一的临时文件名。 **强烈不推荐使用**，因为它存在竞态条件，可能被恶意利用。

2. **`_mktemp(char *path)`**:  `mktemp` 函数的内部实现。同样存在安全风险。

3. **`mkstemp(char *path)`**: 创建并打开一个唯一的临时文件。它会替换 `path` 字符串末尾的 "XXXXXX" 模式为随机字符，并尝试创建文件（使用 `O_CREAT | O_EXCL` 标志，保证原子性）。如果成功，返回新创建文件的文件描述符；否则返回 -1 并设置 `errno`。这是 **推荐使用的创建临时文件的方法**。

4. **`mkostemps(char *path, int slen, int flags)`**:  类似于 `mkstemp`，但允许在 "XXXXXX" 模式前指定一个后缀（`slen` 指定后缀长度），并且可以指定额外的 `open()` 标志。

5. **`mkostemp(char *path, int flags)`**:  类似于 `mkstemp`，但可以指定额外的 `open()` 标志，没有后缀。

6. **`mkstemps(char *path, int slen)`**:  类似于 `mkostemps`，但标志默认为 0。

7. **`mkdtemp(char *path)`**: 创建一个唯一的临时目录。它会替换 `path` 字符串末尾的 "XXXXXX" 模式为随机字符，并尝试创建目录。如果成功，返回指向修改后的 `path` 的指针；否则返回 NULL 并设置 `errno`。

**与 Android 功能的关系及举例**

这些函数在 Android 系统中扮演着重要的角色，因为许多应用和系统服务需要创建临时文件或目录来存储临时数据。使用这些函数可以确保临时文件的命名是唯一的，避免与其他进程或自身创建的文件冲突。

**举例说明：**

* **应用缓存:** Android 应用经常需要创建临时文件来缓存从网络下载的数据或处理后的图像。`mkstemp` 可以被用来安全地创建这些缓存文件。
* **进程间通信 (IPC):**  某些 IPC 机制可能需要使用临时文件来传递数据。`mkstemp` 或 `mkdtemp` 可以用来创建临时的命名管道或共享文件。
* **系统服务:**  Android 系统服务（例如包管理器、媒体服务等）在执行某些操作时可能需要创建临时文件来存储中间结果或日志。
* **NDK 开发:** 使用 NDK 进行原生开发的开发者可以使用这些函数来创建临时文件和目录，例如在处理大型数据或执行复杂计算时。

**libc 函数功能详解**

让我们逐个解释 `mktemp.c` 中使用的 libc 函数及其实现方式：

1. **`strlen(const char *s)`**:  计算字符串 `s` 的长度（不包括 null 终止符）。
   * **实现:**  通常通过循环遍历字符串，直到遇到 null 终止符 (`\0`)。

2. **`errno`**:  一个全局变量，用于存储最近一次系统调用或库函数调用失败时的错误代码。
   * **实现:**  `errno` 通常是一个线程局部变量，由操作系统维护。当系统调用失败时，内核会设置 `errno` 的值。

3. **`open(const char *pathname, int flags, mode_t mode)`**: 打开一个文件，或者如果文件不存在且指定了 `O_CREAT`，则创建该文件。
   * **`pathname`**: 要打开或创建的文件路径。
   * **`flags`**:  控制文件访问模式和其他选项的标志，例如：
      * `O_CREAT`: 如果文件不存在则创建文件。
      * `O_EXCL`: 与 `O_CREAT` 一起使用，如果文件已存在则 `open` 失败。这提供了原子性的文件创建。
      * `O_RDWR`: 以读写模式打开文件。
      * `O_APPEND`: 每次写入都在文件末尾追加。
      * `O_CLOEXEC`: 当执行新程序时关闭此文件描述符。
      * `O_DSYNC`: 要求数据写入磁盘。
      * `O_RSYNC`:  类似于 `O_SYNC`，但用于读取。
      * `O_SYNC`: 要求数据和元数据都写入磁盘。
   * **`mode`**:  指定新创建文件的权限（仅在指定 `O_CREAT` 时使用）。`S_IRUSR|S_IWUSR` 表示所有者具有读写权限。
   * **实现:**  `open` 是一个系统调用，由操作系统内核实现。内核会检查文件是否存在、权限是否匹配，并分配一个文件描述符。

4. **`mkdir(const char *pathname, mode_t mode)`**: 创建一个目录。
   * **`pathname`**: 要创建的目录路径。
   * **`mode`**:  指定新创建目录的权限。 `S_IRUSR|S_IWUSR|S_IXUSR` 表示所有者具有读、写和执行权限。
   * **实现:** `mkdir` 是一个系统调用，由操作系统内核实现。内核会检查父目录是否存在和权限，并在文件系统中创建新的目录条目。

5. **`lstat(const char *pathname, struct stat *statbuf)`**: 获取由 `pathname` 指向的文件或目录的状态信息，**但不跟随符号链接**。
   * **`pathname`**: 要获取状态的文件或目录路径。
   * **`statbuf`**:  指向 `struct stat` 结构的指针，用于存储获取到的状态信息。
   * **实现:** `lstat` 是一个系统调用，由操作系统内核实现。内核会查找文件系统中的对应条目并填充 `statbuf` 结构。与 `stat` 的区别在于，如果 `pathname` 是一个符号链接，`lstat` 返回的是符号链接本身的状态，而 `stat` 返回的是符号链接指向的目标文件的状态。

6. **`arc4random_buf(void *buf, size_t n)`**:  用加密安全的伪随机字节填充缓冲区 `buf`。
   * **`buf`**: 指向要填充的缓冲区的指针。
   * **`n`**: 要填充的字节数。
   * **实现:**  这是一个由 libc 提供的函数，通常基于 ChaCha20 流密码或其他类似的加密安全的随机数生成器。它从操作系统提供的熵源（例如，来自设备驱动程序的随机数据）获取种子。

7. **`INT_MAX`**:  一个宏，定义了 `int` 类型可以表示的最大值。定义在 `<limits.h>` 中。
   * **实现:**  其值通常是 `2147483647` (2<sup>31</sup> - 1)。

8. **`S_IRUSR`, `S_IWUSR`, `S_IXUSR`**:  宏，定义了文件权限位。定义在 `<sys/stat.h>` 中。
   * **`S_IRUSR`**: 用户读权限。
   * **`S_IWUSR`**: 用户写权限。
   * **`S_IXUSR`**: 用户执行权限（对于目录，表示可以进入该目录）。

**涉及 dynamic linker 的功能**

在这个 `mktemp.c` 文件中，与 dynamic linker 直接相关的功能是使用了 `DEF_WEAK(mkstemp);` 和 `DEF_WEAK(mkostemp);` 宏。

**`DEF_WEAK` 宏**

`DEF_WEAK` 宏用于声明一个弱符号 (weak symbol)。弱符号的含义是在链接时，如果存在同名的强符号 (strong symbol)，则链接器会优先选择强符号。如果只存在弱符号，则链接器会选择它。

**so 布局样本及链接处理过程**

假设我们有两个共享库 `libmylib.so` 和 `libc.so`。

**`libmylib.so`:**

```c
// mylib.c
#include <stdio.h>
#include <stdlib.h>

int mkstemp(char *path) {
  printf("Custom mkstemp in libmylib.so called for path: %s\n", path);
  // 自定义的 mkstemp 实现
  // ...
  return -1; // 示例
}
```

编译生成 `libmylib.so`:
```bash
gcc -shared -fPIC mylib.c -o libmylib.so
```

**`libc.so` (包含 `mktemp.c` 的实现):**

`libc.so` 中 `mkstemp` 被声明为弱符号：
```c
// bionic/libc/upstream-openbsd/lib/libc/stdio/mktemp.c
int
mkstemp(char *path)
{
	return(mktemp_internal(path, 0, MKTEMP_FILE, 0));
}
DEF_WEAK(mkstemp);
```

**链接处理过程:**

1. **应用程序链接 `libmylib.so`:** 当应用程序链接 `libmylib.so` 时，链接器会注意到 `libmylib.so` 中定义了一个名为 `mkstemp` 的强符号。

2. **链接 `libc.so`:** 随后，当链接器处理 `libc.so` 时，它会发现 `mkstemp` 是一个弱符号。

3. **符号解析:** 由于 `libmylib.so` 中已经存在一个同名的强符号 `mkstemp`，链接器会选择 `libmylib.so` 中的版本，而忽略 `libc.so` 中的弱符号版本。

**结果:** 任何链接了 `libmylib.so` 的应用程序在调用 `mkstemp` 时，都会执行 `libmylib.so` 中自定义的 `mkstemp` 函数，而不是 `libc.so` 提供的默认实现。

**so 布局样本:**

```
/system/lib64/libc.so  (包含弱符号 mkstemp)
/data/local/tmp/libmylib.so (包含强符号 mkstemp)
/data/local/tmp/my_app  (链接了 libmylib.so)
```

当 `my_app` 运行时，它的 `mkstemp` 调用会解析到 `libmylib.so` 中定义的版本。

**弱符号的用途:**

在 `libc` 中将某些函数声明为弱符号，允许开发者或设备制造商提供自定义的实现来覆盖默认行为。这在某些特定的优化或定制场景中可能很有用。然而，滥用弱符号可能会导致兼容性问题和难以追踪的 bug。

**逻辑推理的假设输入与输出**

**假设输入 `mkstemp`:**

```c
char template[] = "/tmp/my_temp_file_XXXXXX";
```

**逻辑推理过程:**

1. `mkstemp` 调用 `mktemp_internal`，`mode` 为 `MKTEMP_FILE`。
2. `mktemp_internal` 找到模板字符串中的 "XXXXXX"。
3. 使用 `arc4random_buf` 生成 6 个随机字符来替换 "XXXXXX"。
4. 假设生成的随机字符是 "abcdef"。
5. 尝试使用 `open("/tmp/my_temp_file_abcdef", O_CREAT | O_EXCL | O_RDWR, S_IRUSR|S_IWUSR)` 创建文件。
6. 如果文件创建成功（返回一个非负的文件描述符），则 `mkstemp` 返回该文件描述符。
7. 如果文件已存在（`open` 返回 -1，`errno` 为 `EEXIST`），则循环继续，生成新的随机字符并重试。

**可能的输出:**

* **成功:** 返回一个大于等于 0 的整数，例如 `3` (表示成功打开的文件描述符)。模板字符串 `template` 被修改为 `/tmp/my_temp_file_abcdef` (或其他生成的随机字符串)。
* **失败:** 返回 -1，并设置 `errno` 为相应的错误代码，例如 `EACCES` (权限不足)、`ENOSPC` (磁盘空间不足) 等。

**假设输入 `mkdtemp`:**

```c
char template[] = "/tmp/my_temp_dir_XXXXXX";
```

**逻辑推理过程:**

1. `mkdtemp` 调用 `mktemp_internal`，`mode` 为 `MKTEMP_DIR`。
2. `mktemp_internal` 找到模板字符串中的 "XXXXXX"。
3. 使用 `arc4random_buf` 生成 6 个随机字符来替换 "XXXXXX"。
4. 假设生成的随机字符是 "ghijkl"。
5. 尝试使用 `mkdir("/tmp/my_temp_dir_ghijkl", S_IRUSR|S_IWUSR|S_IXUSR)` 创建目录。
6. 如果目录创建成功（返回 0），则 `mkdtemp` 返回指向修改后的 `template` 的指针。
7. 如果目录已存在（`mkdir` 返回 -1，`errno` 为 `EEXIST`），则循环继续，生成新的随机字符并重试。

**可能的输出:**

* **成功:** 返回指向 `template` 的指针，其内容被修改为 `/tmp/my_temp_dir_ghijkl` (或其他生成的随机字符串)。
* **失败:** 返回 `NULL`，并设置 `errno` 为相应的错误代码，例如 `EACCES`、`ENOSPC` 等。

**用户或编程常见的使用错误**

1. **使用 `mktemp` 而不是 `mkstemp` 或 `mkdtemp`:** `mktemp` 存在竞态条件，恶意用户可以在 `mktemp` 检查文件不存在后，但在程序创建文件之前创建该文件，导致安全漏洞。

   ```c
   // 不安全的使用方式
   char template[] = "/tmp/unsafe_temp_XXXXXX";
   mktemp(template);
   int fd = open(template, O_CREAT | O_WRONLY, 0600); // 竞态条件
   ```

2. **模板字符串末尾没有足够的 "X" 字符:** `mktemp_internal` 要求模板字符串末尾至少有 6 个 "X" 字符。

   ```c
   char template[] = "/tmp/short_XXXX"; // 错误，少于 6 个 X
   mkstemp(template); // 会返回错误
   ```

3. **忘记检查返回值和 `errno`:**  像 `mkstemp` 和 `mkdtemp` 这样的函数在失败时会返回错误代码并设置 `errno`。不检查返回值会导致程序在错误的情况下继续执行，可能导致不可预测的行为。

   ```c
   char template[] = "/tmp/my_temp_file_XXXXXX";
   mkstemp(template); // 没有检查返回值
   // 假设 mkstemp 失败，template 的内容可能没有被修改
   int fd = open(template, O_RDONLY); // 可能打开了一个不期望的文件
   ```

4. **在多线程环境中使用 `mktemp`:** 由于 `mktemp` 不是线程安全的，在多线程环境中使用它会导致竞态条件。应该使用线程安全的 `mkstemp` 或 `mkdtemp`。

5. **假设生成的临时文件名/目录名的模式是固定的:** 虽然这些函数会替换 "XXXXXX"，但你不应该依赖于生成的随机字符的具体模式。

**Android framework 或 NDK 如何到达这里，给出 frida hook 示例**

**Android Framework 到 `mkstemp` 的路径示例:**

1. **Java Framework:** Android Framework 中的 Java 代码可能需要创建临时文件。例如，`DownloadManager` 在下载文件时会使用临时文件。

2. **JNI 调用:** Java 代码会通过 JNI (Java Native Interface) 调用到 Native 代码。例如，`java.io.File.createTempFile()` 的底层实现会调用 Native 方法。

3. **Native 代码:**  在 Android 的 Native 代码中（通常在 System Server 或其他系统进程中），会调用 Bionic 库提供的 `mkstemp` 或 `mkdtemp` 函数。例如，`libnativehelper.so` 中可能有相关的实现。

**NDK 到 `mkstemp` 的路径示例:**

1. **NDK 应用:** 使用 NDK 开发的 Android 应用可以直接调用 C 标准库函数，包括 `mkstemp` 和 `mkdtemp`。

2. **直接调用:** NDK 代码中可以包含如下代码：

   ```c
   #include <stdio.h>
   #include <stdlib.h>

   void create_temp_file() {
       char template[] = "/data/local/tmp/my_ndk_temp_XXXXXX";
       int fd = mkstemp(template);
       if (fd != -1) {
           // 文件创建成功，可以使用 fd
           close(fd);
       } else {
           perror("mkstemp failed");
       }
   }
   ```

**Frida Hook 示例:**

以下是一个使用 Frida Hook `mkstemp` 函数的示例，它可以拦截 `mkstemp` 的调用并打印出传入的模板字符串和返回的文件描述符。

```javascript
// save as mkstemp_hook.js

if (ObjC.available) {
    console.log("Objective-C runtime detected, but mkstemp is a C function.");
} else {
    console.log("No Objective-C runtime detected.");
}

Interceptor.attach(Module.findExportByName(null, "mkstemp"), {
    onEnter: function (args) {
        this.template = Memory.readCString(args[0]);
        console.log("[mkstemp] Called with template:", this.template);
    },
    onLeave: function (retval) {
        console.log("[mkstemp] Returned file descriptor:", retval.toInt32());
        if (retval.toInt32() !== -1) {
            console.log("[mkstemp] Created temporary file:", this.template);
        } else {
            console.log("[mkstemp] Failed to create temporary file.");
        }
    }
});
```

**使用 Frida 调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida Server。
2. **启动目标应用:** 运行你想要调试的 Android 应用或进程。
3. **运行 Frida 脚本:** 使用 Frida CLI 连接到目标进程并运行 hook 脚本。

   ```bash
   frida -U -f <package_name> -l mkstemp_hook.js --no-pause
   # 或者连接到正在运行的进程
   frida -U <process_name_or_pid> -l mkstemp_hook.js
   ```

   将 `<package_name>` 替换为目标应用的包名，或 `<process_name_or_pid>` 替换为进程名或 PID。

4. **观察输出:** 当目标应用调用 `mkstemp` 时，Frida 脚本会在控制台上打印出相关信息，例如传入的模板字符串和返回的文件描述符。

这个 Frida 示例可以帮助你理解 Android Framework 或 NDK 如何调用到 `mkstemp`，并可以用于调试与临时文件创建相关的行为。你可以根据需要修改脚本来 hook 其他相关函数或执行更复杂的分析。

希望这个详细的分析对你有所帮助！

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdio/mktemp.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
/*	$OpenBSD: mktemp.c,v 1.39 2017/11/28 06:55:49 tb Exp $ */
/*
 * Copyright (c) 1996-1998, 2008 Theo de Raadt
 * Copyright (c) 1997, 2008-2009 Todd C. Miller
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define MKTEMP_NAME	0
#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(sizeof(TEMPCHARS) - 1)
#define MIN_X		6

#define MKOTEMP_FLAGS	(O_APPEND | O_CLOEXEC | O_DSYNC | O_RSYNC | O_SYNC)

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static int
mktemp_internal(char *path, int slen, int mode, int flags)
{
	char *start, *cp, *ep;
	const char tempchars[] = TEMPCHARS;
	unsigned int tries;
	struct stat sb;
	size_t len;
	int fd;

	len = strlen(path);
	if (len < MIN_X || slen < 0 || (size_t)slen > len - MIN_X) {
		errno = EINVAL;
		return(-1);
	}
	ep = path + len - slen;

	for (start = ep; start > path && start[-1] == 'X'; start--)
		;
	if (ep - start < MIN_X) {
		errno = EINVAL;
		return(-1);
	}

	if (flags & ~MKOTEMP_FLAGS) {
		errno = EINVAL;
		return(-1);
	}
	flags |= O_CREAT | O_EXCL | O_RDWR;

	tries = INT_MAX;
	do {
		cp = start;
		do {
			unsigned short rbuf[16];
			unsigned int i;

			/*
			 * Avoid lots of arc4random() calls by using
			 * a buffer sized for up to 16 Xs at a time.
			 */
			arc4random_buf(rbuf, sizeof(rbuf));
			for (i = 0; i < nitems(rbuf) && cp != ep; i++)
				*cp++ = tempchars[rbuf[i] % NUM_CHARS];
		} while (cp != ep);

		switch (mode) {
		case MKTEMP_NAME:
			if (lstat(path, &sb) != 0)
				return(errno == ENOENT ? 0 : -1);
			break;
		case MKTEMP_FILE:
			fd = open(path, flags, S_IRUSR|S_IWUSR);
			if (fd != -1 || errno != EEXIST)
				return(fd);
			break;
		case MKTEMP_DIR:
			if (mkdir(path, S_IRUSR|S_IWUSR|S_IXUSR) == 0)
				return(0);
			if (errno != EEXIST)
				return(-1);
			break;
		}
	} while (--tries);

	errno = EEXIST;
	return(-1);
}

char *
_mktemp(char *path)
{
	if (mktemp_internal(path, 0, MKTEMP_NAME, 0) == -1)
		return(NULL);
	return(path);
}

__warn_references(mktemp,
    "mktemp() possibly used unsafely; consider using mkstemp()");

char *
mktemp(char *path)
{
	return(_mktemp(path));
}

int
mkostemps(char *path, int slen, int flags)
{
	return(mktemp_internal(path, slen, MKTEMP_FILE, flags));
}

int
mkstemp(char *path)
{
	return(mktemp_internal(path, 0, MKTEMP_FILE, 0));
}
DEF_WEAK(mkstemp);

int
mkostemp(char *path, int flags)
{
	return(mktemp_internal(path, 0, MKTEMP_FILE, flags));
}
DEF_WEAK(mkostemp);

int
mkstemps(char *path, int slen)
{
	return(mktemp_internal(path, slen, MKTEMP_FILE, 0));
}

char *
mkdtemp(char *path)
{
	int error;

	error = mktemp_internal(path, 0, MKTEMP_DIR, 0);
	return(error ? NULL : path);
}
```
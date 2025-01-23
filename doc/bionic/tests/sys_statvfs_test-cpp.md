Response:
Let's break down the thought process for generating the comprehensive analysis of `sys_statvfs_test.cpp`.

**1. Understanding the Core Task:**

The initial request asks for an analysis of a C++ test file within Android's Bionic library. The key aspects to address are:

* **Functionality:** What does this test file do?
* **Android Relevance:** How does it relate to Android's workings?
* **Libc Function Internals:** How are the involved libc functions implemented (to a reasonable degree of detail)?
* **Dynamic Linker:** Are there any connections to the dynamic linker, and if so, how do they work?
* **Logic/Reasoning:** Are there any assumptions or logical steps evident in the code?
* **Common Errors:** What mistakes might developers make when using these functions?
* **Android Framework/NDK Connection:** How does a request from a higher level reach this code?
* **Frida Hooking:** How can we use Frida to inspect the execution?

**2. Initial Code Inspection and Keyword Identification:**

The first step is to read through the code and identify key elements:

* **Include Headers:** `<gtest/gtest.h>`, `<sys/statvfs.h>`, `<sys/types.h>`, `<sys/stat.h>`, `<fcntl.h>`, `<string>`. This immediately tells us it's a test file using Google Test and interacting with filesystem information. The core functions are `statvfs`, `statvfs64`, `fstatvfs`, and `fstatvfs64`.
* **Test Names:** `sys_statvfs.statvfs`, `sys_statvfs.statvfs64_smoke`, `sys_statvfs.fstatvfs`, `sys_statvfs.fstatvfs64_smoke`. These clearly indicate tests for different variations of the `statvfs` family of functions.
* **Assertions:** `ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_TRUE`. These are Google Test macros for verifying conditions.
* **Function Calls:** `statvfs`, `statvfs64`, `fstatvfs`, `fstatvfs64`, `open`, `close`, `getpagesize`, `stat`.
* **Constants:** `O_RDONLY`.
* **Conditional Compilation:** `#if defined(__x86_64__)`. This hints at platform-specific behavior.
* **Specific Values:** `0U`, `255U`, `4096`. These likely represent expected values for certain fields.

**3. Understanding the `statvfs` Family:**

Based on the included header `<sys/statvfs.h>`, I know these functions are used to retrieve filesystem statistics. The names themselves suggest the difference between `statvfs` and `statvfs64` is the size of the data structures used (likely to accommodate larger file systems). The 'f' prefix in `fstatvfs` indicates it operates on a file descriptor rather than a pathname.

**4. Analyzing the `Check` Template:**

The `Check` template is crucial. It performs assertions on the `statvfs` struct members. I need to understand what these members represent:

* `f_bsize`: Block size of the filesystem. The code explicitly checks against `getpagesize()` (or a fixed 4096 on x86_64).
* `f_bfree`, `f_ffree`: Free blocks and free inodes. The test expects them to be 0, which is interesting. It suggests this test isn't about checking *available* space, but rather some fundamental properties.
* `f_namemax`: Maximum filename length. Expected to be 255.
* `f_fsid`: Filesystem ID. The code checks if it's non-zero and, if so, compares it to the device ID of `/proc` obtained using `stat`. This is a key observation connecting it to Android's use of `/proc`.
* `f_flag`: Filesystem mount flags. The code specifically checks that a particular internal flag (`ST_VALID`) is *not* set.

**5. Connecting to Android:**

The fact that the tests consistently use `/proc` is a strong indicator of the connection to Android. `/proc` is a virtual filesystem in Linux-based systems (including Android) that provides information about running processes and the kernel. Accessing filesystem information is a fundamental OS operation, and Android applications and the framework rely on this.

**6. Explaining Libc Function Implementations (Conceptual):**

While I don't have the actual source code for the libc implementation, I can describe the general process:

* **`statvfs(path, buf)`:**  This function would involve a system call to the kernel. The kernel would then:
    * Identify the filesystem associated with the given `path`.
    * Retrieve the relevant filesystem metadata (block size, free space, etc.).
    * Populate the `statvfs` structure (`buf`) with this information.
    * Return 0 on success, -1 on error.
* **`fstatvfs(fd, buf)`:** Similar to `statvfs`, but it uses an existing file descriptor (`fd`) to identify the filesystem. This avoids path resolution overhead.
* **`open(path, flags)`:**  This also involves a system call. The kernel finds the file/directory at the given `path`, checks permissions based on the `flags`, and creates a file descriptor if successful.
* **`close(fd)`:** This system call tells the kernel to release the resources associated with the file descriptor.
* **`getpagesize()`:** This system call returns the system's page size.
* **`stat(path, buf)`:** Similar to `statvfs` but retrieves general file/directory information (inode, permissions, timestamps, etc.).

**7. Dynamic Linker Considerations:**

While this specific test file doesn't directly *use* the dynamic linker, the libc functions it calls (`statvfs`, `open`, etc.) *are* part of libc.so, which is loaded by the dynamic linker. To illustrate, I need to provide a simplified scenario of how libc.so is loaded and linked.

**8. Logic and Reasoning:**

The core logic is the assertions within the `Check` template. The assumptions are that:

* The `/proc` filesystem will exist and be accessible.
* Certain fundamental properties of `/proc` (like `f_namemax`) will have consistent values.
* The `f_bfree` and `f_ffree` being 0 is likely a characteristic of how `/proc` reports space (it's a virtual filesystem).
* The handling of `f_fsid` reflects a change in kernel behavior.

**9. Common Errors:**

Thinking about how developers use these functions reveals potential mistakes:

* Not checking return values for errors.
* Using incorrect paths.
* Misinterpreting the meaning of the `statvfs` fields.
* Assuming all filesystems report free space in the same way.

**10. Android Framework/NDK Connection:**

I need to trace how a high-level request could lead to these low-level functions. Examples include:

* **StorageManager:** In the Android framework, the `StorageManager` uses these calls to get information about available storage.
* **`df` command:**  The `df` command relies on `statvfs` to display disk space usage.
* **NDK developers:**  Developers using the NDK can directly call these libc functions.

**11. Frida Hooking:**

Finally, I need to provide practical Frida examples to intercept calls to these functions and inspect their arguments and return values. This helps in debugging and understanding their behavior at runtime.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the zero `f_bfree` and `f_ffree` indicate an error.
* **Correction:**  Realizing that `/proc` is a virtual filesystem, it's more likely that these values are intentionally reported as zero or are not meaningful in this context. The test *expects* them to be zero.
* **Initial thought:** Focus heavily on the exact libc implementation details.
* **Correction:** Shift to a more conceptual explanation, as the specific implementation is hidden within the Android source code and might vary across versions. Focus on the system call interface.
* **Ensuring Clarity:** Use clear and concise language, explaining technical terms where necessary. Structure the answer logically with headings and bullet points.

By following these steps, iteratively analyzing the code, and connecting it to the broader context of Android, I can generate a comprehensive and accurate answer to the original request.
好的，我们来详细分析一下 `bionic/tests/sys_statvfs_test.cpp` 这个文件。

**文件功能概述:**

这个 C++ 文件是 Android Bionic 库中的一个测试文件，专门用于测试 `statvfs` 和 `fstatvfs` 这两个系统调用及其 64 位版本 (`statvfs64` 和 `fstatvfs64`) 的功能是否正常。 简单来说，它的主要目的是验证获取文件系统统计信息的 API 在 Android 平台上的正确性。

**与 Android 功能的关系及举例说明:**

`statvfs` 和 `fstatvfs` 这两个系统调用在 Android 系统中被广泛使用，用于获取文件系统的各种统计信息，例如：

* **可用空间:**  应用程序或系统服务需要知道存储空间是否足够。例如，下载管理器在下载文件前需要检查剩余空间。
* **总空间:** 用于显示磁盘容量信息。例如，设置应用的存储信息界面会显示总存储空间。
* **块大小:** 某些底层操作可能需要知道文件系统的块大小。
* **最大文件名长度:** 限制创建文件时的文件名长度。

**举例说明:**

* **应用安装:** 当你安装一个应用时，Android 系统需要检查是否有足够的可用空间来容纳 APK 文件。这背后就可能涉及到对目标安装目录调用 `statvfs` 或 `fstatvfs` 来获取可用空间信息。
* **`df` 命令:**  在 Android 的 shell 环境中，你可以使用 `df` 命令来查看磁盘空间使用情况。 `df` 命令的实现通常会调用 `statvfs` 或 `fstatvfs` 来获取各个挂载点的统计数据。
* **MediaStore 服务:** Android 的 `MediaStore` 服务负责管理媒体文件。它可能使用 `statvfs` 或 `fstatvfs` 来监控存储设备的健康状况和容量。

**详细解释每一个 libc 函数的功能是如何实现的:**

以下是对文件中使用到的 libc 函数的解释：

1. **`statvfs(const char *path, struct statvfs *buf)` 和 `statvfs64(const char *path, struct statvfs64 *buf)`:**
   * **功能:**  这两个函数用于获取指定路径 `path` 所在文件系统的统计信息，并将信息存储在 `buf` 指向的结构体中。`statvfs64` 是 64 位版本，可以处理更大的文件系统。
   * **实现:**
     * 当应用程序调用 `statvfs` 或 `statvfs64` 时，会触发一个系统调用，进入 Linux 内核。
     * 内核接收到系统调用后，会根据提供的 `path` 解析出对应的文件系统。
     * 内核会读取该文件系统的元数据，包括总块数、可用块数、块大小、inode 总数、可用 inode 数、最大文件名长度等信息。
     * 这些信息被填充到 `struct statvfs` 或 `struct statvfs64` 结构体中。
     * 系统调用返回，`statvfs` 或 `statvfs64` 函数将结果返回给应用程序。
     * **`struct statvfs` 结构体 (部分关键成员):**
       ```c
       struct statvfs {
           unsigned long  f_bsize;    /* 文件系统块大小 */
           unsigned long  f_frsize;   /* 片段大小 (通常与 f_bsize 相同) */
           fsblkcnt_t   f_blocks;   /* 文件系统总块数 */
           fsblkcnt_t   f_bfree;    /* 可用块数 */
           fsblkcnt_t   f_bavail;   /* 非特权用户可用的块数 */
           fsfilcnt_t   f_files;    /* 文件节点总数 */
           fsfilcnt_t   f_ffree;    /* 可用文件节点数 */
           fsfilcnt_t   f_favail;   /* 非特权用户可用的文件节点数 */
           unsigned long  f_fsid;     /* 文件系统 ID */
           unsigned long  f_flag;     /* 挂载标志 */
           unsigned long  f_namemax;  /* 最大文件名长度 */
           // ... 其他成员
       };
       ```

2. **`fstatvfs(int fd, struct statvfs *buf)` 和 `fstatvfs64(int fd, struct statvfs64 *buf)`:**
   * **功能:** 这两个函数与 `statvfs` 和 `statvfs64` 类似，但它们操作的是一个已经打开的文件描述符 `fd` 所关联的文件系统。
   * **实现:**
     * 当应用程序调用 `fstatvfs` 或 `fstatvfs64` 时，会触发一个系统调用。
     * 内核接收到系统调用后，直接利用文件描述符 `fd` 来定位对应的文件系统，无需进行路径解析。
     * 后续的步骤与 `statvfs` / `statvfs64` 类似，读取文件系统的元数据并填充到 `buf` 中。
     * 使用 `fstatvfs` 可以避免路径解析的开销，效率更高。

3. **`open(const char *pathname, int flags)`:**
   * **功能:** 用于打开或创建一个文件，返回一个文件描述符 (非负整数)。
   * **实现:**
     * 当应用程序调用 `open` 时，会触发一个系统调用。
     * 内核接收到系统调用后，会根据 `pathname` 查找对应的文件。
     * 根据 `flags` 参数（例如 `O_RDONLY` 只读打开），内核会进行权限检查。
     * 如果文件存在且权限允许，内核会创建一个新的文件描述符，并将其指向该文件的内核数据结构。
     * 如果文件不存在，并且 `flags` 中指定了创建标志（例如 `O_CREAT`），内核会创建一个新的文件。
     * 系统调用返回新的文件描述符。如果发生错误，返回 -1。

4. **`close(int fd)`:**
   * **功能:** 用于关闭一个打开的文件描述符，释放相关的系统资源。
   * **实现:**
     * 当应用程序调用 `close` 时，会触发一个系统调用。
     * 内核接收到系统调用后，会释放与文件描述符 `fd` 关联的内核资源，例如文件表项、缓冲区等。
     * 文件描述符变为无效，不能再用于访问该文件。

5. **`getpagesize(void)`:**
   * **功能:**  获取系统的内存页大小，单位是字节。
   * **实现:**
     * 当应用程序调用 `getpagesize` 时，会触发一个系统调用。
     * 内核接收到系统调用后，直接返回系统配置的内存页大小。这个值通常在系统启动时确定。在 ARM 架构上通常是 4096 字节 (4KB)，但在某些 x86_64 架构上可能是 16384 字节 (16KB)。

6. **`stat(const char *pathname, struct stat *buf)`:**
   * **功能:** 获取文件或目录的详细信息，例如大小、权限、所有者、修改时间等。
   * **实现:**
     * 当应用程序调用 `stat` 时，会触发一个系统调用。
     * 内核接收到系统调用后，会根据 `pathname` 查找对应的文件或目录。
     * 内核读取该文件或目录的 inode 信息，其中包含了文件的各种元数据。
     * 这些信息被填充到 `struct stat` 结构体中。
     * 系统调用返回。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `sys_statvfs_test.cpp` 本身并没有直接涉及动态链接器的显式操作，但它测试的 `statvfs` 等函数都是 libc.so (Android 的 C 库) 提供的。因此，理解 libc.so 的加载和链接过程对于理解这些函数的运行环境至关重要。

**so 布局样本 (简化的 libc.so):**

```
libc.so:
  .dynsym       # 动态符号表 (包含导出的函数和变量)
    statvfs
    fstatvfs
    open
    close
    getpagesize
    stat
    // ... 其他 libc 函数
  .dynstr       # 动态字符串表 (存储符号名称等字符串)
  .plt          # 程序链接表 (用于延迟绑定)
  .got.plt      # 全局偏移量表 (PLT 入口地址)
  .text         # 代码段 (包含函数实现)
    // statvfs 的代码
    // fstatvfs 的代码
    // open 的代码
    // close 的代码
    // getpagesize 的代码
    // stat 的代码
    // ...
  .data         # 数据段 (包含全局变量)
  // ... 其他段
```

**链接的处理过程:**

1. **加载:** 当一个可执行文件或共享库 (例如你的测试程序) 需要使用 libc.so 中的函数时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 libc.so 到进程的内存空间。
2. **符号查找:**  在加载过程中，动态链接器会解析可执行文件和 libc.so 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)。当遇到对 `statvfs` 等函数的调用时，链接器会查找 libc.so 中对应的符号。
3. **重定位:** 由于 libc.so 被加载到进程的哪个内存地址是不确定的 (地址空间布局随机化 - ASLR)，链接器需要修改代码中的地址引用，使其指向 libc.so 在当前进程中的实际加载地址。这通常通过全局偏移量表 (`.got.plt`) 和程序链接表 (`.plt`) 来实现。
4. **延迟绑定 (Lazy Binding):** 默认情况下，为了提高启动速度，Android 使用延迟绑定。这意味着在程序第一次调用 `statvfs` 时，才会真正解析 `statvfs` 的地址并更新 GOT 表。后续的调用将直接通过 GOT 表跳转到 `statvfs` 的实现。
   * **第一次调用 `statvfs` 的过程:**
     * 程序代码调用 `statvfs`，实际上跳转到 PLT 中的一个桩代码。
     * PLT 桩代码会跳转到 GOT 表中对应的条目。
     * 初始时，GOT 表中的条目指向 `linker` 的某个地址。
     * `linker` 接收到跳转后，会查找 `statvfs` 在 libc.so 中的实际地址。
     * `linker` 将 `statvfs` 的实际地址更新到 GOT 表中。
     * `linker` 再次跳转到 `statvfs` 的实际地址执行。
   * **后续调用:** 程序再次调用 `statvfs` 时，会直接跳转到 GOT 表中已经更新过的 `statvfs` 的实际地址。

**假设输入与输出 (针对测试代码):**

测试代码主要验证在 `/proc` 文件系统上调用 `statvfs` 等函数是否返回预期的结果。

**假设输入:**

* **操作系统:** Android 系统
* **测试路径/文件描述符:**  指向 `/proc` 文件系统
* **`getpagesize()` 的返回值:**  假设为 4096 (常见值)

**预期输出 (基于 `Check` 函数的断言):**

* `sb.f_bsize` (文件系统块大小):  4096 (与 `getpagesize()` 相等)
* `sb.f_bfree`: 0
* `sb.f_ffree`: 0
* `sb.f_namemax`: 255
* `sb.f_fsid`:  非 0 值 (通常与 `/proc` 的设备号相同)
* `sb.f_flag & 0x0020`: 0 (表示特定的内部标志未设置)
* 所有 `ASSERT_EQ` 都会成功返回 0。

**用户或者编程常见的使用错误及举例说明:**

1. **未检查返回值:**  `statvfs` 和 `fstatvfs` 在出错时会返回 -1，并设置 `errno`。开发者可能忘记检查返回值，导致在错误的情况下继续使用未初始化的 `statvfs` 结构体，产生不可预测的结果。

   ```c
   struct statvfs sb;
   statvfs("/nonexistent", &sb); // 假设 /nonexistent 不存在
   // 错误的做法：直接使用 sb 的值
   printf("Free space: %lu\n", sb.f_bfree); // 可能输出垃圾值
   ```

   **正确的做法:**
   ```c
   struct statvfs sb;
   if (statvfs("/nonexistent", &sb) == 0) {
       printf("Free space: %lu\n", sb.f_bfree);
   } else {
       perror("statvfs failed");
   }
   ```

2. **使用错误的路径或文件描述符:** 传递不存在的路径给 `statvfs`，或者传递无效的文件描述符给 `fstatvfs` 会导致错误。

3. **误解 `statvfs` 结构体成员的含义:**  例如，混淆 `f_bfree` (可用块数) 和 `f_bavail` (非特权用户可用的块数)。

4. **假设所有文件系统都返回相同的统计信息:** 不同的文件系统可能有不同的实现细节，返回的统计信息可能不完全相同。例如，虚拟文件系统 (如 `/proc`) 的某些统计信息可能与其他物理文件系统不同。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `statvfs` 的路径示例 (以获取存储空间信息为例):**

1. **Java 代码 (Android Framework):**  例如，`android.os.Environment` 或 `android.os.storage.StorageManager` 中的方法被调用来获取存储空间信息。

   ```java
   // Android Framework (Java)
   File path = Environment.getDataDirectory(); // 获取 /data 目录
   long freeSpace = path.getFreeSpace();
   ```

2. **JNI 调用:**  `path.getFreeSpace()` 等方法最终会通过 JNI (Java Native Interface) 调用到 Native 代码。

   ```c++
   // Frameworks Base (Native) - 示例
   static jlong nativeGetFreeSpace(JNIEnv* env, jobject clazz, jstring path_) {
       const char* path = env->GetStringUTFChars(path_, nullptr);
       struct statvfs sb;
       if (statvfs(path, &sb) == 0) {
           env->ReleaseStringUTFChars(path_, path);
           return (jlong)sb.f_bavail * sb.f_frsize; // 计算可用空间
       } else {
           env->ReleaseStringUTFChars(path_, path);
           return 0; // 或抛出异常
       }
   }
   ```

3. **Bionic Libc:**  上述 Native 代码直接调用了 `statvfs` 函数，该函数由 Bionic 的 `libc.so` 提供。

**NDK 到 `statvfs` 的路径:**

使用 NDK 开发的应用程序可以直接调用 Bionic 提供的 C 标准库函数，包括 `statvfs`。

```c++
// NDK 应用代码
#include <sys/statvfs.h>
#include <stdio.h>

int main() {
  struct statvfs sb;
  if (statvfs("/sdcard", &sb) == 0) {
    printf("Free space on /sdcard: %llu bytes\n", (unsigned long long)sb.f_bavail * sb.f_frsize);
  } else {
    perror("statvfs failed");
  }
  return 0;
}
```

**Frida Hook 示例:**

以下是使用 Frida Hook `statvfs` 函数的示例，可以拦截其调用并查看参数和返回值：

```javascript
// Frida JavaScript 代码
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so"); // 获取 libc.so 的基地址
  if (libc) {
    const statvfsPtr = Module.findExportByName(libc.name, "statvfs");
    if (statvfsPtr) {
      Interceptor.attach(statvfsPtr, {
        onEnter: function (args) {
          const path = Memory.readUtf8String(args[0]);
          console.log(`[statvfs] Path: ${path}`);
        },
        onLeave: function (retval) {
          console.log(`[statvfs] Return value: ${retval}`);
          if (retval === 0) {
            const statvfsBuf = this.context.sp.add(Process.pointerSize); // 获取 statvfs 结构体指针 (假设在栈上)
            const f_bavail = Memory.readU64(statvfsBuf.add(8 * 4)); // 假设 f_bavail 是第 5 个 ulong
            const f_frsize = Memory.readU64(statvfsBuf.add(8 * 1));  // 假设 f_frsize 是第 2 个 ulong
            console.log(`[statvfs] f_bavail: ${f_bavail}, f_frsize: ${f_frsize}`);
          }
        }
      });
    } else {
      console.log("[-] statvfs not found");
    }
  } else {
    console.log("[-] libc.so not found");
  }
} else {
  console.log("[-] Not an Android platform");
}
```

**使用 Frida 调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_statvfs.js`。
3. **运行 Frida:** 使用 Frida 命令行工具将脚本注入到目标进程。你需要找到目标进程的名称或 PID。例如，要 hook 系统服务，可以使用 `frida -U -f system_server -l hook_statvfs.js --no-pause`。要 hook NDK 应用，你需要知道应用的包名或进程名。
4. **观察输出:** 当目标进程调用 `statvfs` 时，Frida 会拦截该调用，并打印出路径、返回值以及 `statvfs` 结构体中的一些关键字段。

通过 Frida Hook，你可以动态地观察 `statvfs` 的调用情况，验证参数是否正确，以及返回值是否符合预期，从而帮助你理解 Android Framework 或 NDK 如何使用这些底层的 Bionic 函数。

希望以上详细的分析能够帮助你理解 `bionic/tests/sys_statvfs_test.cpp` 文件的功能以及相关的 Android 系统知识。

### 提示词
```
这是目录为bionic/tests/sys_statvfs_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

#include <sys/statvfs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string>

template <typename StatVfsT> void Check(StatVfsT& sb) {
#if defined(__x86_64__)
  // On x86_64 based 16kb page size targets, the page size in userspace is simulated to 16kb but
  // the underlying filesystem block size would remain unchanged, i.e., 4kb.
  // For more info:
  // https://source.android.com/docs/core/architecture/16kb-page-size/getting-started-cf-x86-64-pgagnostic
  EXPECT_EQ(4096, static_cast<int>(sb.f_bsize));
#else
  EXPECT_EQ(getpagesize(), static_cast<int>(sb.f_bsize));
#endif
  EXPECT_EQ(0U, sb.f_bfree);
  EXPECT_EQ(0U, sb.f_ffree);
  EXPECT_EQ(255U, sb.f_namemax);

  // Linux 6.7 requires that all filesystems have a non-zero fsid.
  if (sb.f_fsid != 0U) {
    // fs/libfs.c reuses the filesystem's device number.
    struct stat proc_sb;
    ASSERT_EQ(0, stat("/proc", &proc_sb));
    EXPECT_EQ(proc_sb.st_dev, sb.f_fsid);
  } else {
    // Prior to that, the fsid for /proc was just 0.
    EXPECT_EQ(0U, sb.f_fsid);
  }

  // The kernel sets a private bit to indicate that f_flags is valid.
  // This flag is not supposed to be exposed to libc clients.
  static const uint32_t ST_VALID = 0x0020;
  EXPECT_TRUE((sb.f_flag & ST_VALID) == 0) << sb.f_flag;
}

TEST(sys_statvfs, statvfs) {
  struct statvfs sb;
  ASSERT_EQ(0, statvfs("/proc", &sb));
  Check(sb);
}

TEST(sys_statvfs, statvfs64_smoke) {
  struct statvfs64 sb;
  ASSERT_EQ(0, statvfs64("/proc", &sb));
  Check(sb);
}

TEST(sys_statvfs, fstatvfs) {
  struct statvfs sb;
  int fd = open("/proc", O_RDONLY);
  ASSERT_EQ(0, fstatvfs(fd, &sb));
  close(fd);
  Check(sb);
}

TEST(sys_statvfs, fstatvfs64_smoke) {
  struct statvfs64 sb;
  int fd = open("/proc", O_RDONLY);
  ASSERT_EQ(0, fstatvfs64(fd, &sb));
  close(fd);
  Check(sb);
}
```
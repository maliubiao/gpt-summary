Response:
Let's break down the thought process for answering the user's request about the `scandir.cpp` file.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the provided C++ code snippet, which implements `scandir` and `scandirat`. The user wants a comprehensive explanation covering its purpose, relationship to Android, implementation details, dynamic linking aspects (if any), usage errors, and how Android frameworks interact with it.

**2. Deconstructing the Code:**

I'll go through the code section by section, noting key components and their functions:

* **Includes:** `dirent.h`, `assert.h`, `errno.h`, `fcntl.h`, `stdlib.h`, `string.h`, `unistd.h`, `platform/bionic/macros.h`, `private/ScopedReaddir.h`. These indicate interaction with directory entries, error handling, file descriptors, memory allocation, string manipulation, standard Unix functions, and potentially some Android-specific helpers.
* **`ScandirResult` Class:**  This is a crucial element. It manages the dynamic allocation and storage of `dirent` structures. I need to analyze its methods:
    * Constructor and destructor: Initialization and resource cleanup.
    * `size()`: Returns the number of entries.
    * `release()`:  Crucially, this returns the allocated memory and resets the internal state. This is important for memory management.
    * `Add()`: Adds a `dirent` to the internal array, handling resizing if necessary. The `CopyDirent` function within this method is significant.
    * `Sort()`:  Uses `qsort` to sort the entries.
    * `CopyDirent()`:  Allocates memory and copies the `dirent` structure. The size calculation is interesting – rounding up.
    * `BIONIC_DISALLOW_COPY_AND_ASSIGN`: Prevents accidental copying of this class.
* **`scandirat()` Function:** This is the core implementation. It takes a file descriptor, directory name, filter, and comparator as arguments.
    * Handles the `AT_FDCWD` case for `scandir`.
    * Uses `openat` (if `parent_fd` is not `AT_FDCWD`) and `opendir`/`fdopendir` to open the directory.
    * Employs the `ScopedReaddir` class (I need to assume what this does - likely handles `readdir` and closing the directory).
    * Iterates through directory entries using `reader.ReadEntry()`.
    * Applies the `filter` if provided.
    * Adds matching entries to the `ScandirResult`.
    * Sorts the entries using the `comparator` if provided.
    * Returns the size and releases the memory via `names.release()`.
* **`scandir()` Function:** A simpler wrapper around `scandirat` using `AT_FDCWD`.
* **`__strong_alias`:**  Indicates that `scandirat64` and `scandir64` are aliases for the 32-bit versions. This hints at compatibility considerations.

**3. Identifying Key Functionality and Android Relevance:**

* **Listing Directory Contents:** The primary function is clearly to list files and directories within a specified path. This is fundamental for many Android operations.
* **Filtering:** The `filter` function allows selective listing based on criteria. Android might use this for specific file type searches, permission checks, etc.
* **Sorting:** The `comparator` enables ordering of the results, which could be used for displaying files alphabetically or by modification time in file explorers.
* **`scandirat`:**  The existence of `scandirat` is important. It allows operations relative to an open file descriptor, which is crucial for security and avoiding TOCTOU (Time-of-check to time-of-use) vulnerabilities. Android's sandboxing heavily relies on this concept.

**4. Explaining `libc` Functions:**

I need to explain `opendir`, `fdopendir`, `readdir`, `closedir`, `openat`, `malloc`, `realloc`, `memcpy`, `qsort`, `AT_FDCWD`. For each, I'll describe its purpose and how it's used within the context of `scandir.cpp`.

**5. Addressing Dynamic Linking:**

The code itself doesn't *directly* handle dynamic linking. However, it's *part of* the C library, which *is* dynamically linked. I need to explain:

* `libc.so`:  The dynamic library where these functions reside.
* The linker's role in resolving symbols (`opendir`, `malloc`, etc.) at runtime.
* A simple `libc.so` layout example.
* The linking process (symbol lookup, relocation).

**6. Providing Examples (Input/Output, Usage Errors):**

* **Input/Output:** Show how calling `scandir` with a path would return an array of `dirent` pointers.
* **Usage Errors:**  Focus on common mistakes: forgetting to free the returned memory, passing invalid paths, permission issues.

**7. Tracing the Call Path from Android Framework/NDK:**

This requires considering how high-level Android code eventually calls these C library functions. I'll describe a plausible scenario:

* An app uses Java APIs (e.g., `File.listFiles()`).
* These Java APIs call native methods via JNI.
* The native code in the Android framework uses functions like `opendir`, `readdir`, and `closedir` (or potentially `scandir` directly in some cases).
* If using the NDK, developers can directly call `scandir`.

**8. Frida Hook Example:**

Provide a basic Frida script to intercept calls to `scandir` and log its arguments and return value. This demonstrates how to observe its behavior at runtime.

**9. Language and Structure:**

The request specifies Chinese. I'll structure the answer logically with clear headings and explanations for each point. I'll use code blocks for the provided code and the Frida script.

**Self-Correction/Refinement during the thought process:**

* **Initial Thought:** Focus heavily on the `ScandirResult` class. **Correction:** While important, I need to balance it with explaining the standard `libc` functions and the overall flow.
* **Initial Thought:**  Overlook the dynamic linking aspect because it's not directly manipulating the linker. **Correction:** Recognize that `libc` itself is a dynamic library and therefore subject to dynamic linking principles.
* **Initial Thought:**  Provide very detailed explanations of every `libc` function. **Correction:** Focus on the *relevance* of each function within the context of `scandir`. A brief explanation is sufficient.
* **Initial Thought:**  Assume a deep understanding of Android internals. **Correction:** Explain the call path from the Android framework in a way that is accessible to someone with a moderate understanding.

By following these steps and iteratively refining the approach, I can generate a comprehensive and accurate answer to the user's request.
好的，我们来详细分析 `bionic/libc/bionic/scandir.cpp` 这个文件。

**功能列举:**

这个文件主要实现了以下两个POSIX标准C库函数：

1. **`scandir(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))`**:  扫描目录 `dirp`，找到所有满足 `filter` 函数条件（如果不提供 `filter`，则所有条目都满足）的目录项，并使用 `compar` 函数（如果不提供 `compar`，则不排序）对这些目录项进行排序，最后将这些目录项的指针存储在 `namelist` 指向的动态分配的数组中。用户需要负责释放 `namelist` 指向的内存。
2. **`scandirat(int dirfd, const char *pathname, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))`**:  与 `scandir` 功能类似，但它允许相对于一个已经打开的目录文件描述符 `dirfd` 来扫描目录 `pathname`。如果 `dirfd` 的值为 `AT_FDCWD`，则其行为与 `scandir` 完全相同，即相对于当前工作目录。

**与 Android 功能的关系及举例说明:**

`scandir` 和 `scandirat` 是非常基础的系统调用封装，在 Android 系统中被广泛使用，因为几乎任何需要访问文件系统的操作都可能涉及到列出目录内容。

* **文件管理器应用:** 文件管理器需要列出指定目录下的所有文件和子目录，这时就会使用到 `scandir` 或 `scandirat`。例如，当用户打开一个文件夹时，文件管理器会调用相关的 Java API，最终会通过 JNI 调用到 native 代码，并可能使用到 `scandir` 来获取目录内容。
* **软件包管理器 (PackageManager):**  PackageManager 在安装、卸载或者扫描应用信息时，需要遍历特定的目录（例如 `/data/app`），`scandir` 可以帮助它实现这个功能。
* **媒体扫描服务 (Media Scanner):**  媒体扫描服务会扫描设备的存储空间，查找新的媒体文件。它需要遍历各种目录，这时 `scandir` 就派上了用场。
* **Android Debug Bridge (ADB):**  当你在 adb shell 中使用 `ls` 命令时，最终也会调用到 `scandir` 或 `scandirat` 来列出目录内容。

**详细解释每一个 libc 函数的功能是如何实现的:**

1. **`opendir(const char *filename)`**:
   - **功能:** 打开一个目录流。它接收一个目录路径 `filename` 作为参数，并返回一个指向 `DIR` 结构的指针，该结构用于后续读取目录项。如果打开失败，则返回 `NULL` 并设置 `errno`。
   - **实现:**  `opendir` 内部会调用底层的 `open()` 系统调用，并带上 `O_RDONLY` 和 `O_DIRECTORY` 标志，确保打开的是一个只读的目录。成功打开后，会分配一个 `DIR` 结构，并初始化其成员，例如文件描述符 `fd`。

2. **`fdopendir(int fd)`**:
   - **功能:** 从一个已有的文件描述符 `fd` 创建一个目录流。这个文件描述符必须指向一个已打开的目录。
   - **实现:** `fdopendir` 会检查 `fd` 是否有效，并尝试获取与该文件描述符关联的文件类型，确保它是一个目录。如果检查通过，它会分配一个 `DIR` 结构，并将其 `fd` 成员设置为传入的 `fd`。

3. **`readdir(DIR *dirp)`**:
   - **功能:** 从目录流 `dirp` 中读取下一个目录项。它返回一个指向 `dirent` 结构的指针，该结构包含了目录项的信息，例如文件名 `d_name`。如果没有更多的目录项或者发生错误，则返回 `NULL`。
   - **实现:**  `readdir` 内部会调用底层的 `getdents()` 系统调用，该系统调用会从内核读取一批目录项信息到用户空间缓冲区。`readdir` 会解析这些信息，并返回一个 `dirent` 结构。

4. **`closedir(DIR *dirp)`**:
   - **功能:** 关闭由 `opendir` 或 `fdopendir` 打开的目录流，并释放相关的资源。
   - **实现:** `closedir` 内部会调用底层的 `close()` 系统调用来关闭与目录流关联的文件描述符，并释放 `DIR` 结构所占用的内存。

5. **`openat(int dirfd, const char *pathname, int flags, ...)`**:
   - **功能:**  打开一个文件，但路径名 `pathname` 可以是相对于目录文件描述符 `dirfd` 的。如果 `dirfd` 是 `AT_FDCWD`，则 `pathname` 相对于当前工作目录。
   - **实现:** 这是一个系统调用，内核会根据 `dirfd` 和 `pathname` 解析出文件的绝对路径，然后执行打开操作。这对于避免竞态条件（TOCTOU）非常重要。

6. **`malloc(size_t size)`**:
   - **功能:**  在堆上分配指定大小 `size` 的内存块。返回指向分配的内存块的指针，如果分配失败则返回 `NULL`。
   - **实现:**  `malloc` 的实现比较复杂，通常涉及维护一个空闲内存块链表，并根据请求的大小找到合适的空闲块进行分配。bionic 的 `malloc` 实现使用了 jemalloc 的变种。

7. **`realloc(void *ptr, size_t size)`**:
   - **功能:**  重新分配 `ptr` 指向的内存块的大小为 `size`。如果 `ptr` 是 `NULL`，则行为等同于 `malloc(size)`。如果 `size` 是 0 且 `ptr` 非空，则行为等同于 `free(ptr)`。
   - **实现:** `realloc` 可能会在原地扩展或缩小内存块，如果原地无法完成，则会分配一块新的内存，将原有数据拷贝过去，并释放旧的内存块。

8. **`memcpy(void *dest, const void *src, size_t n)`**:
   - **功能:** 将 `src` 指向的内存块的 `n` 个字节拷贝到 `dest` 指向的内存块。
   - **实现:**  这是一个高度优化的函数，通常会使用汇编指令来提高拷贝效率，例如使用 SIMD 指令一次拷贝多个字节。

9. **`qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *))`**:
   - **功能:**  使用快速排序算法对数组进行排序。`base` 是指向数组首元素的指针，`nmemb` 是数组元素的个数，`size` 是每个元素的大小，`compar` 是一个比较函数。
   - **实现:**  `qsort` 的实现通常包括选择一个 pivot 元素，然后将数组划分为小于 pivot 和大于 pivot 的两部分，再递归地对这两部分进行排序。

10. **`AT_FDCWD`**:
    - **功能:**  这是一个特殊的文件描述符值，表示操作应该相对于当前工作目录。
    - **实现:**  在系统调用中，当 `dirfd` 参数为 `AT_FDCWD` 时，内核会将其解释为相对于进程的当前工作目录进行路径解析。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`scandir.cpp` 文件本身并不直接涉及 dynamic linker 的功能，它实现的是 C 库函数。但是，这些函数最终会被链接到动态链接库 `libc.so` 中，供应用程序在运行时加载和使用。

**`libc.so` 布局样本 (简化):**

```
ELF Header:
  ...
Program Headers:
  LOAD           0x...   0x...   r-x ...
  LOAD           0x...   0x...   rwx ...
  DYNAMIC        0x...   0x...   ...
  ...
Section Headers:
  .text          PROGBITS  0x...   ...    # 包含可执行代码，如 scandir 的实现
  .rodata        PROGBITS  0x...   ...    # 只读数据
  .data          PROGBITS  0x...   ...    # 已初始化的全局变量
  .bss           NOBITS    0x...   ...    # 未初始化的全局变量
  .dynsym        DYNSYM    0x...   ...    # 动态符号表
  .dynstr        DYSTR     0x...   ...    # 动态字符串表
  .plt.got      PROGBITS  0x...   ...    # PLT 和 GOT
  ...
```

* **`.text` 段:** 包含 `scandir`、`opendir` 等函数的机器码指令。
* **`.dynsym` (Dynamic Symbol Table):**  包含了 `libc.so` 导出的符号（函数名、变量名）以及它需要从其他库导入的符号。例如，`scandir` 的符号会在这里定义，而它内部调用的系统调用（如 `getdents`）的符号可能会作为导入符号存在。
* **`.dynstr` (Dynamic String Table):**  存储了 `.dynsym` 中符号的字符串名称。
* **`.plt.got` (Procedure Linkage Table and Global Offset Table):**  用于实现延迟绑定。当程序第一次调用 `libc.so` 中的函数时，PLT 中的代码会跳转到 GOT 中对应的条目。最初，GOT 条目包含的是 PLT 中下一条指令的地址。PLT 代码会调用 dynamic linker 来解析函数地址，并将解析后的地址写入 GOT 条目。后续的调用将直接跳转到 GOT 中存储的已解析地址。

**链接的处理过程:**

1. **编译时链接:** 当编译器编译使用了 `scandir` 的代码时，它会在目标文件（.o 文件）中生成对 `scandir` 的未解析引用。
2. **链接时链接:**  链接器（ld）在创建可执行文件或共享库时，会查找 `libc.so` 中的 `scandir` 符号定义，并将对 `scandir` 的引用重定位到 `libc.so` 中 `scandir` 函数的地址。对于动态链接，链接器主要是在可执行文件的动态段中记录依赖关系，并在 PLT 和 GOT 中生成相应的条目。
3. **运行时链接:** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** 当程序首次调用 `scandir` 时，由于延迟绑定，会通过 PLT 跳转到 dynamic linker。Dynamic linker 会在 `libc.so` 的 `.dynsym` 中查找 `scandir` 的地址，并将该地址更新到 GOT 中。
5. **后续调用:**  后续对 `scandir` 的调用将直接通过 GOT 跳转到 `libc.so` 中 `scandir` 的实际代码。

**逻辑推理的假设输入与输出:**

假设我们调用 `scandir` 来列出 `/sdcard/Pictures` 目录下的所有文件，不进行过滤和排序。

**假设输入:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

int main() {
    struct dirent **namelist;
    int n;

    n = scandir("/sdcard/Pictures", &namelist, NULL, NULL);
    if (n < 0) {
        perror("scandir");
        return 1;
    }

    printf("Found %d entries in /sdcard/Pictures:\n", n);
    for (int i = 0; i < n; i++) {
        printf("%s\n", namelist[i]->d_name);
        free(namelist[i]); // 注意释放 dirent 结构
    }
    free(namelist); // 注意释放 namelist 数组
    return 0;
}
```

**假设输出 (可能因设备内容而异):**

```
Found 5 entries in /sdcard/Pictures:
.
..
image1.jpg
image2.png
screenshot.png
```

**用户或编程常见的使用错误及举例说明:**

1. **忘记释放 `namelist` 指向的内存:** `scandir` 会动态分配内存来存储目录项指针，用户需要使用 `free()` 释放这块内存。

   ```c
   struct dirent **namelist;
   int n = scandir("/sdcard/Pictures", &namelist, NULL, NULL);
   // ... 使用 namelist
   // 忘记 free(namelist);  // 内存泄漏
   ```

2. **忘记释放 `dirent` 结构本身指向的内存 (如果需要):**  在某些情况下，`scandir` 的实现可能会复制 `dirent` 结构的内容到新分配的内存中。在 bionic 的实现中，`ScandirResult::Add` 方法会调用 `CopyDirent` 来复制 `dirent` 结构，因此需要释放。

   ```c
   struct dirent **namelist;
   int n = scandir("/sdcard/Pictures", &namelist, NULL, NULL);
   if (n > 0) {
       for (int i = 0; i < n; i++) {
           printf("%s\n", namelist[i]->d_name);
           // 忘记 free(namelist[i]); // 内存泄漏
       }
       free(namelist);
   }
   ```

3. **错误地使用 `filter` 或 `comparator` 函数:**  `filter` 函数应该返回非零值表示接受该目录项，返回零表示拒绝。`comparator` 函数应该遵循 `qsort` 的比较函数规范，返回负数、零或正数。

   ```c
   // 错误的 filter 函数，总是拒绝所有条目
   int my_filter(const struct dirent *entry) {
       return 0;
   }

   struct dirent **namelist;
   int n = scandir("/sdcard/Pictures", &namelist, my_filter, NULL); // n 将为 0
   ```

4. **传递无效的目录路径:** 如果传递给 `scandir` 的路径不存在或者没有访问权限，`scandir` 将返回 -1 并设置 `errno`。

   ```c
   struct dirent **namelist;
   int n = scandir("/non_existent_path", &namelist, NULL, NULL);
   if (n < 0) {
       perror("scandir"); // 输出类似 "scandir: No such file or directory"
   }
   ```

**说明 Android framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `scandir` 的路径 (示例):**

1. **Java 代码:** Android 应用通过 `java.io.File` 类进行文件系统操作。例如，`File.listFiles()` 方法用于获取目录下的文件列表。

   ```java
   File dir = new File("/sdcard/Pictures");
   File[] files = dir.listFiles();
   if (files != null) {
       for (File file : files) {
           System.out.println(file.getName());
       }
   }
   ```

2. **Native 代码 (Framework):** `File.listFiles()` 方法最终会调用到 Android Framework 的 native 代码，通常在 `libjavacrypto.so`、`libandroid_runtime.so` 等库中。这些 native 代码会使用 JNI (Java Native Interface) 调用到 C/C++ 函数。

   在 `libandroid_runtime.so` 中，可能会有类似这样的调用链：
   `android_os_FileUtils_listDir()` ->  内部使用 `opendir()`, `readdir()`, `closedir()` 或者可能直接使用 `scandir()`。

3. **Bionic libc:**  Framework 的 native 代码最终会调用到 bionic libc 提供的 `scandir` 或相关的目录操作函数。

**NDK 到 `scandir` 的路径:**

使用 NDK 开发的 Android 应用可以直接调用 bionic libc 提供的标准 C 库函数，包括 `scandir`。

```c++
// NDK 代码
#include <dirent.h>
#include <cstdlib>
#include <android/log.h>

extern "C" JNIEXPORT void JNICALL
Java_com_example_myapp_MainActivity_listDir(JNIEnv *env, jobject /* this */, jstring path) {
    const char *dir_path = env->GetStringUTFChars(path, 0);
    struct dirent **namelist;
    int n = scandir(dir_path, &namelist, NULL, NULL);
    if (n >= 0) {
        for (int i = 0; i < n; i++) {
            __android_log_print(ANDROID_LOG_INFO, "MyApp", "Found: %s", namelist[i]->d_name);
            free(namelist[i]);
        }
        free(namelist);
    } else {
        __android_log_print(ANDROID_LOG_ERROR, "MyApp", "scandir failed");
    }
    env->ReleaseStringUTFChars(path, dir_path);
}
```

**Frida Hook 示例:**

以下是一个使用 Frida hook `scandir` 函数的示例，用于在 Android 设备上观察其调用：

```javascript
if (Process.platform === 'android') {
  const scandirPtr = Module.findExportByName("libc.so", "scandir");
  if (scandirPtr) {
    Interceptor.attach(scandirPtr, {
      onEnter: function (args) {
        const path = Memory.readUtf8String(args[0]);
        console.log(`[scandir] Entering scandir with path: ${path}`);
      },
      onLeave: function (retval) {
        console.log(`[scandir] Leaving scandir, returned: ${retval}`);
        if (retval.toInt32() >= 0) {
          // 可以进一步解析 namelist 的内容，但需要小心内存管理
          // 例如，读取前几个条目的 d_name
        }
      }
    });
    console.log("[Frida] Hooked scandir in libc.so");
  } else {
    console.log("[Frida] Failed to find scandir in libc.so");
  }
} else {
  console.log("[Frida] This script is for Android.");
}
```

**使用方法:**

1. 将 Frida 安装到你的电脑上。
2. 将 Frida 服务端部署到你的 Android 设备上。
3. 运行你的 Android 应用，该应用会调用到 `scandir`。
4. 运行上述 Frida 脚本，连接到你的 Android 设备上的应用进程。

**预期输出:**

当你运行会调用 `scandir` 的 Android 应用时，Frida 脚本会在控制台中打印出类似以下的日志：

```
[Frida] Hooked scandir in libc.so
[scandir] Entering scandir with path: /sdcard/Pictures
[scandir] Leaving scandir, returned: 5
[scandir] Entering scandir with path: /data/app/com.example.myapp-xxxx/base.apk
[scandir] Leaving scandir, returned: 2
...
```

这个示例可以帮助你理解 `scandir` 函数何时被调用，以及传递了哪些参数。你可以根据需要扩展这个脚本，例如解析 `namelist` 的内容，查看具体的目录项。请注意，在 `onLeave` 中访问 `namelist` 需要特别小心内存管理，确保不会访问已释放的内存。

希望这些详细的解释能够帮助你理解 `bionic/libc/bionic/scandir.cpp` 的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/scandir.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <dirent.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "platform/bionic/macros.h"
#include "private/ScopedReaddir.h"

// A smart pointer to the scandir dirent**.
class ScandirResult {
 public:
  ScandirResult() : names_(nullptr), size_(0), capacity_(0) {
  }

  ~ScandirResult() {
    // We always call release(), so this can't happen.
    if (names_ != nullptr) __assert(__FILE__, __LINE__, "missing call to release()");
  }

  size_t size() {
    return size_;
  }

  dirent** release() {
    dirent** result = names_;
    names_ = nullptr;
    size_ = capacity_ = 0;
    return result;
  }

  bool Add(dirent* entry) {
    if (size_ >= capacity_) {
      size_t new_capacity = capacity_ + 32;
      dirent** new_names =
          reinterpret_cast<dirent**>(realloc(names_, new_capacity * sizeof(dirent*)));
      if (new_names == nullptr) {
        return false;
      }
      names_ = new_names;
      capacity_ = new_capacity;
    }

    dirent* copy = CopyDirent(entry);
    if (copy == nullptr) {
      return false;
    }
    names_[size_++] = copy;
    return true;
  }

  void Sort(int (*comparator)(const dirent**, const dirent**)) {
    qsort(names_, size_, sizeof(dirent*),
          reinterpret_cast<int (*)(const void*, const void*)>(comparator));
  }

 private:
  dirent** names_;
  size_t size_;
  size_t capacity_;

  static dirent* CopyDirent(dirent* original) {
    // Allocate the minimum number of bytes necessary, rounded up to a 4-byte boundary.
    size_t size = ((original->d_reclen + 3) & ~3);
    dirent* copy = reinterpret_cast<dirent*>(malloc(size));
    memcpy(copy, original, original->d_reclen);
    return copy;
  }

  BIONIC_DISALLOW_COPY_AND_ASSIGN(ScandirResult);
};

int scandirat(int parent_fd, const char* dir_name, dirent*** name_list,
              int (*filter)(const dirent*),
              int (*comparator)(const dirent**, const dirent**)) {
  DIR* dir = nullptr;
  if (parent_fd == AT_FDCWD) {
    dir = opendir(dir_name);
  } else {
    int dir_fd = openat(parent_fd, dir_name, O_CLOEXEC | O_DIRECTORY | O_RDONLY);
    if (dir_fd != -1) {
      dir = fdopendir(dir_fd);
    }
  }

  ScopedReaddir reader(dir);
  if (reader.IsBad()) {
    return -1;
  }

  ScandirResult names;
  dirent* entry;
  while ((entry = reader.ReadEntry()) != nullptr) {
    // If we have a filter, skip names that don't match.
    if (filter != nullptr && !(*filter)(entry)) {
      continue;
    }
    names.Add(entry);
  }

  if (comparator != nullptr) {
    names.Sort(comparator);
  }

  size_t size = names.size();
  *name_list = names.release();
  return size;
}
__strong_alias(scandirat64, scandirat);

int scandir(const char* dir_path, dirent*** name_list,
            int (*filter)(const dirent*),
            int (*comparator)(const dirent**, const dirent**)) {
  return scandirat(AT_FDCWD, dir_path, name_list, filter, comparator);
}
__strong_alias(scandir64, scandir);
```
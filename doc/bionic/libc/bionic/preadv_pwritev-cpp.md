Response:
Let's break down the thought process for answering the prompt about `preadv_pwritev.cpp`.

**1. Understanding the Goal:**

The core request is to analyze the provided C++ source code for `preadv_pwritev.cpp` within the context of Android's Bionic library. The analysis should cover functionality, relationship to Android, implementation details, dynamic linking aspects, error handling, usage, and how it's reached by higher-level Android components. A Frida hook example is also requested.

**2. Initial Code Analysis (Static Analysis):**

* **Includes:**  The code includes `<sys/uio.h>`, which hints at operations involving scatter/gather I/O.
* **External "C" Functions:**  The code declares several external "C" functions: `__preadv64`, `__preadv64v2`, `__pwritev64`, `__pwritev64v2`. The double underscores (`__`) convention in C often indicates these are low-level system calls or internal library functions. The `64` suffix suggests they deal with 64-bit offsets. The `v2` likely indicates a later version adding functionality (in this case, flags).
* **Function Definitions:**  The code defines several public functions: `preadv`, `preadv64`, `pwritev`, `pwritev64`, `preadv2`, `preadv64v2`, `pwritev2`, `pwritev64v2`. Notice the pairings: a shorter name version and a `64` version, and then `v2` versions of both.
* **Offset Handling:** A significant part of the code deals with handling the `offset` parameter differently for 32-bit and 64-bit architectures (`#if defined(__LP64__)`). This immediately stands out as a key detail.
* **System Call Mapping:**  The public functions ultimately call the underscored external functions.

**3. Inferring Functionality:**

Based on the function names and the inclusion of `<sys/uio.h>`, it's clear these functions are related to:

* **`preadv` and `pwritev`:**  Read and write operations to a file descriptor at a specific offset *without* changing the file pointer. The `v` suffix suggests "vectorized" or scatter/gather operations.
* **`64` suffix:**  Indicates these functions operate with 64-bit file offsets, allowing access to larger files.
* **`v2` suffix:** Implies the addition of flags to control the behavior of the read/write operations.

**4. Connecting to Android:**

Bionic is Android's standard C library. Therefore, these functions are fundamental building blocks for file I/O within the Android ecosystem. Any Android process that needs to perform I/O at a specific offset without moving the file pointer (and potentially using scatter/gather) will likely use these functions, either directly or indirectly.

**5. Deep Dive into Implementation Details:**

* **System Call Wrappers:** The code acts as a thin wrapper around the underlying Linux system calls (`__preadv64`, etc.). This is a common pattern in C libraries.
* **32-bit vs. 64-bit Offset Handling:**  The `#ifdef __LP64__` block reveals a crucial detail: how 64-bit offsets are passed to the kernel on 32-bit systems. Since 32-bit systems can't directly pass a 64-bit value in a single register, the offset is split into two 32-bit parts (low and high) and passed as two separate `long` arguments. This is a significant implementation detail related to ABI compatibility.

**6. Dynamic Linking Considerations:**

* **Shared Objects:**  Bionic itself is a shared object (`libc.so`). Applications link against `libc.so` to access these functions.
* **Symbol Resolution:**  When an application calls `preadv`, the dynamic linker resolves this symbol to the corresponding function within `libc.so`.
* **SO Layout Example:** A basic mental model of `libc.so`'s structure is needed, highlighting sections for code (.text), read-only data (.rodata), and potentially other segments.

**7. Usage Examples and Common Errors:**

Consider common scenarios where these functions would be used and the potential pitfalls:

* **Web browsers:** Downloading files and writing to specific parts of a file.
* **Database systems:** Reading and writing database records at specific locations.
* **Media players:** Seeking to different parts of a media file.
* **Common errors:** Incorrect file descriptors, invalid offsets, insufficient buffer sizes in `iovec`, negative counts, and using these functions on non-seekable file descriptors (though the functions generally handle this gracefully by returning an error).

**8. Tracing the Call Path (Android Framework/NDK):**

Think about how a request from an Android app would propagate down to these functions:

* **Java Layer:**  The Android framework (written in Java/Kotlin) would likely use `FileInputStream`/`FileOutputStream` or related classes.
* **Native Layer (NDK):**  NDK developers might directly use standard C library functions like `preadv`/`pwritev`.
* **System Calls:** Ultimately, the Java framework and the NDK calls translate to system calls, including the underlying `preadv64`/`pwritev64` system calls.

**9. Frida Hook Example:**

A Frida hook needs to intercept the execution of these functions. Key aspects of the hook:

* **Targeting:** Identify the `libc.so` library and the specific function names.
* **Interception:** Use `Interceptor.attach` to gain control before the original function executes.
* **Parameter Access:** Access the function arguments (file descriptor, `iovec` structure, count, offset). Important to handle the 32-bit/64-bit offset representation.
* **Logging/Modification:** Print the arguments for observation or potentially modify them for testing.
* **Calling the Original:** Use `this.context.pc` to continue execution in the original function if desired.

**10. Structuring the Answer:**

Organize the information logically, addressing each part of the prompt:

* **Functionality:** Start with a high-level description.
* **Android Relevance:** Provide concrete examples.
* **Implementation Details:** Explain the system call wrappers and offset handling.
* **Dynamic Linking:** Discuss `libc.so`, symbol resolution, and provide an SO layout.
* **Logic and Assumptions:**  Explain the 32-bit offset handling as a core logical step.
* **Common Errors:** Give practical examples of misuse.
* **Call Path:** Trace from the Android framework/NDK down to Bionic.
* **Frida Hook:** Provide a clear and functional example.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on the direct functionality of reading/writing at an offset.
* **Correction:** Realize the importance of the scatter/gather aspect (`iovec`) and the 32-bit/64-bit offset handling.
* **Initial thought:**  Assume direct system call mapping.
* **Correction:** Understand that Bionic provides wrappers around the system calls, potentially with additional logic (though in this case, the logic is primarily about offset handling).
* **Initial thought:**  A simple Frida hook example.
* **Correction:** Make sure the Frida hook accurately reflects how to access the arguments, especially the 64-bit offset on 32-bit systems.

By following this structured approach and considering the various aspects of the prompt, a comprehensive and accurate answer can be generated. The process involves a combination of static code analysis, understanding operating system concepts (system calls, memory layout), and familiarity with Android's architecture.
好的，我们来详细分析一下 `bionic/libc/bionic/preadv_pwritev.cpp` 这个文件。

**文件功能概览**

这个文件定义了以下几个用于执行原子性定位读写操作的函数：

* **`preadv` 和 `preadv64`**:  从指定的文件描述符的指定偏移量处读取数据到多个缓冲区（由 `iovec` 结构体数组指定）。`preadv` 使用 `off_t` 类型的偏移量，而 `preadv64` 使用 `off64_t` 类型的偏移量，后者可以处理更大的文件。
* **`pwritev` 和 `pwritev64`**:  将多个缓冲区的数据写入到指定的文件描述符的指定偏移量处。与读取类似，`pwritev` 使用 `off_t`，而 `pwritev64` 使用 `off64_t`。
* **`preadv2` 和 `preadv64v2`**:  与 `preadv` 和 `preadv64` 功能类似，但增加了一个 `flags` 参数，用于修改读取操作的行为。
* **`pwritev2` 和 `pwritev64v2`**: 与 `pwritev` 和 `pwritev64` 功能类似，同样增加了一个 `flags` 参数来修改写入操作的行为。

**与 Android 功能的关系及举例**

这些函数是 Android 系统进行文件 I/O 操作的基础。它们提供了原子性的定位读写能力，这意味着在执行读写操作时，文件的偏移量不会被改变。这在多线程或多进程并发访问同一文件时非常重要，可以避免竞争条件和数据不一致的问题。

**举例说明:**

* **Content Providers:**  Android 的内容提供器 (Content Providers) 可能需要在不同的位置读取或写入数据，例如读取联系人信息、图片数据等。 `preadv` 和 `pwritev` 可以用于高效地访问这些数据，而无需先 `lseek` 到目标位置。
* **Download Manager:**  Android 的下载管理器在下载大文件时，可能会将文件分成多个块并行下载。 `pwritev` 可以用于将下载的块写入到文件的正确偏移量，保证文件内容的完整性，而不会因为多个线程同时写入而产生错乱。
* **Media Framework:**  Android 的媒体框架在播放视频或音频文件时，可能需要随机访问文件的不同部分。 `preadv` 可以用于快速读取特定时间戳的数据块，实现快进、快退等功能。
* **Package Installer:**  Android 的包安装程序 (Package Installer) 在安装应用时，需要读取 APK 文件中的不同部分，例如清单文件 (AndroidManifest.xml)、资源文件等。 `preadv` 可以用于读取这些文件片段。

**每一个 libc 函数的功能实现详解**

这些函数实际上是对 Linux 内核提供的系统调用的封装。

1. **`preadv(int fd, const struct iovec* ios, int count, off_t offset)` 和 `pwritev(int fd, const struct iovec* ios, int count, off_t offset)`:**
   - 这两个函数分别调用了 `preadv64` 和 `pwritev64`，并将 `off_t` 类型的 `offset` 转换为 `off64_t`。在大多数现代 Android 设备上，`off_t` 已经是 64 位的，所以这个转换通常是直接赋值。

2. **`preadv64(int fd, const struct iovec* ios, int count, off64_t offset)` 和 `pwritev64(int fd, const struct iovec* ios, int count, off64_t offset)`:**
   - 这两个函数是核心实现。它们根据目标架构 (32位或64位) 调用相应的底层系统调用：
     - **64 位架构 (`__LP64__`)**: 直接调用 `__preadv64(fd, ios, count, offset, 0)` 或 `__pwritev64(fd, ios, count, offset, 0)`。注意，第二个 `long` 参数被设置为 0，这在 64 位架构上是不需要的，因为 `offset` 已经是 64 位。
     - **32 位架构 (`!__LP64__`)**: 调用 `__preadv64(fd, ios, count, offset, offset >> 32)` 或 `__pwritev64(fd, ios, count, offset, offset >> 32)`。在 32 位架构上，`long` 类型是 32 位的，无法直接传递 64 位的 `offset`。因此，内核系统调用 `__preadv64` 和 `__pwritev64` 接收两个 `long` 类型的参数来表示 64 位的偏移量，低 32 位放在第一个参数，高 32 位放在第二个参数。代码中通过 `offset >> 32` 来获取 `offset` 的高 32 位。

3. **`preadv2(int fd, const struct iovec* ios, int count, off_t offset, int flags)` 和 `pwritev2(int fd, const struct iovec* ios, int count, off_t offset, int flags)`:**
   - 类似于 `preadv` 和 `pwritev`，它们分别调用 `preadv64v2` 和 `pwritev64v2`。

4. **`preadv64v2(int fd, const struct iovec* ios, int count, off64_t offset, int flags)` 和 `pwritev64v2(int fd, const struct iovec* ios, int count, off64_t offset, int flags)`:**
   - 与 `preadv64` 和 `pwritev64` 的实现类似，但它们调用的是带有 `flags` 参数的系统调用 `__preadv64v2` 和 `__pwritev64v2`。`flags` 参数允许用户指定额外的操作标志，例如 `RWF_NOWAIT` (非阻塞 I/O) 或 `RWF_DSYNC` (同步数据写入)。
     - **64 位架构 (`__LP64__`)**: 调用 `__preadv64v2(fd, ios, count, offset, 0, flags)` 或 `__pwritev64v2(fd, ios, count, offset, 0, flags)`。
     - **32 位架构 (`!__LP64__`)**: 调用 `__preadv64v2(fd, ios, count, offset, offset >> 32, flags)` 或 `__pwritev64v2(fd, ios, count, offset, offset >> 32, flags)`。

**涉及 dynamic linker 的功能**

这些函数本身不直接涉及 dynamic linker 的核心功能，但作为 `libc.so` 的一部分，它们的链接过程是 dynamic linker 的工作。

**SO 布局样本:**

```
libc.so:
    .text          # 存放可执行代码
        preadv:
            ...指令...
        preadv64:
            ...指令...
        pwritev:
            ...指令...
        pwritev64:
            ...指令...
        preadv2:
            ...指令...
        preadv64v2:
            ...指令...
        pwritev2:
            ...指令...
        pwritev64v2:
            ...指令...
        __preadv64:   # 底层系统调用封装
            ...指令...
        __pwritev64:  # 底层系统调用封装
            ...指令...
        __preadv64v2: # 底层系统调用封装
            ...指令...
        __pwritev64v2:# 底层系统调用封装
            ...指令...
    .rodata        # 存放只读数据 (例如字符串常量)
    .data          # 存放已初始化的全局变量和静态变量
    .bss           # 存放未初始化的全局变量和静态变量
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.plt       # PLT 重定位表
    .rel.dyn       # 动态重定位表
    ...其他段...
```

**链接的处理过程:**

1. **编译:** 当应用程序或共享库调用 `preadv` 等函数时，编译器会生成对这些符号的未解析引用。
2. **链接:**
   - **静态链接 (不常用):** 如果采用静态链接，`libc.a` (静态库) 的相关代码会被直接复制到最终的可执行文件中。
   - **动态链接 (常用):**  通常采用动态链接。链接器在生成可执行文件或共享库时，会将对 `preadv` 等函数的引用标记为需要动态链接。可执行文件或共享库的头部会包含一些信息，指示它依赖于 `libc.so`。
3. **加载:** 当 Android 系统启动应用程序或加载共享库时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载所有需要的共享库，包括 `libc.so`。
4. **符号解析:** dynamic linker 扫描已加载的共享库的符号表 (`.dynsym`)，查找与未解析引用匹配的符号。例如，当找到 `libc.so` 中的 `preadv` 函数时，就将应用程序或共享库中对 `preadv` 的调用地址重定向到 `libc.so` 中 `preadv` 函数的实际地址。这个过程通常涉及到 **PLT (Procedure Linkage Table)** 和 **GOT (Global Offset Table)**。
   - 当第一次调用 `preadv` 时，会跳转到 PLT 中的一个桩代码。这个桩代码会调用 dynamic linker 的解析函数。
   - dynamic linker 找到 `preadv` 的地址后，会更新 GOT 中对应 `preadv` 的条目，使其指向 `preadv` 的实际地址。
   - 后续对 `preadv` 的调用会直接通过 GOT 跳转到 `preadv` 的实际地址，避免重复的符号解析。

**逻辑推理：32 位架构的偏移量处理**

**假设输入:**

* 一个 32 位 Android 设备。
* 调用 `preadv64`，`offset` 的值为 `0x1234567890abcdefLL` (一个大于 32 位能表示的最大值的 64 位值)。

**处理过程:**

1. `preadv64` 函数检测到是 32 位架构 (`!__LP64__`)。
2. 它调用底层的 `__preadv64` 系统调用，传递以下参数：
   - `fd` (文件描述符)
   - `ios` (iovec 数组指针)
   - `count` (iovec 数组元素个数)
   - `offset` (低 32 位): `0x90abcdef`
   - `offset >> 32` (高 32 位): `0x12345678`

**输出:**

底层系统调用 `__preadv64` 接收到两个 `long` 类型的参数，分别代表 64 位偏移量的低 32 位和高 32 位。内核会将这两个 32 位值组合成完整的 64 位偏移量 `0x1234567890abcdef`，并据此执行读取操作。

**用户或编程常见的使用错误**

1. **错误的 `fd` (文件描述符):** 使用了无效或未打开的文件描述符。这会导致系统调用失败，并返回错误码（通常是 -1）。
   ```c++
   int fd = open("nonexistent_file.txt", O_RDONLY);
   char buffer[100];
   ssize_t bytes_read = preadv(fd, nullptr, 0, 0); // fd 无效
   if (bytes_read == -1) {
       perror("preadv failed"); // 输出错误信息
   }
   ```

2. **`iovec` 数组设置错误:**
   - `iov_base` 指向无效的内存地址。
   - `iov_len` 为负数。
   - `count` 大于允许的最大值。
   ```c++
   struct iovec iov[2];
   iov[0].iov_base = nullptr; // 错误：无效的内存地址
   iov[0].iov_len = 10;
   iov[1].iov_base = buffer;
   iov[1].iov_len = -5;      // 错误：长度为负数
   ssize_t bytes_read = preadv(fd, iov, 2, 0);
   if (bytes_read == -1) {
       perror("preadv failed");
   }
   ```

3. **负数的 `count`:**  `count` 参数表示 `iovec` 数组中元素的个数，不能为负数。

4. **偏移量超出文件大小:** 虽然 `preadv` 和 `pwritev` 允许指定偏移量，但如果偏移量超出了文件的大小，`preadv` 会读取到文件末尾，而 `pwritev` 会扩展文件（如果以写入方式打开）。需要注意处理这些情况，避免读取到意外的数据或写入到错误的位置。

5. **在不可 seek 的文件描述符上使用:**  例如，在管道或套接字上使用 `preadv` 或 `pwritev` 是没有意义的，因为它们没有固定的偏移量。这些操作通常会失败并返回 `ESPIPE` 错误。

**Android framework 或 NDK 如何一步步到达这里**

假设一个 Android 应用需要读取一个大文件的特定部分：

1. **Java 代码 (Android Framework):** 应用程序可能使用 `FileInputStream` 来读取文件。如果需要指定偏移量读取，可能会使用 `FileChannel` 的 `read(ByteBuffer dst, long position)` 方法。
   ```java
   try (FileInputStream fis = new FileInputStream(file)) {
       FileChannel channel = fis.getChannel();
       ByteBuffer buffer = ByteBuffer.allocate(1024);
       long offset = 1024 * 1024; // 偏移量为 1MB
       int bytesRead = channel.read(buffer, offset);
       // ...处理读取的数据...
   } catch (IOException e) {
       e.printStackTrace();
   }
   ```

2. **Native 代码 (NDK):**  或者，应用程序可能通过 JNI 调用 NDK 中的 C/C++ 代码，直接使用标准 C 库函数。
   ```c++
   #include <fcntl.h>
   #include <sys/uio.h>
   #include <unistd.h>

   // ...

   int fd = open(filename, O_RDONLY);
   if (fd != -1) {
       struct iovec iov[1];
       char buffer[1024];
       iov[0].iov_base = buffer;
       iov[0].iov_len = sizeof(buffer);
       off64_t offset = 1024 * 1024;
       ssize_t bytes_read = preadv64(fd, iov, 1, offset);
       if (bytes_read == -1) {
           perror("preadv64 failed");
       }
       close(fd);
   }
   ```

3. **`libcore.io.Posix` (Java Framework 的底层实现):** `FileChannel` 的 `read(ByteBuffer dst, long position)` 方法最终会调用到 `libcore` 库中的本地方法，例如 `libcore.io.Posix.pread64(FileDescriptor fd, long offset, ByteBuffer buffer, int byteCount)`.

4. **JNI 调用:**  `libcore` 中的本地方法会通过 JNI 调用到 Bionic 库 (`libc.so`) 中相应的函数，即 `preadv64`。

5. **系统调用:** `preadv64` 函数会进一步调用 Linux 内核提供的系统调用 `__preadv64` (或 `__preadv64v2`，如果使用了 `preadv2`)。

6. **内核处理:** Linux 内核接收到系统调用请求后，会执行实际的读取操作，将数据从文件系统的指定偏移量读取到用户空间的缓冲区。

**Frida Hook 示例**

以下是一个使用 Frida Hook 拦截 `preadv64` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    const preadv64Ptr = Module.findExportByName("libc.so", "preadv64");
    if (preadv64Ptr) {
        Interceptor.attach(preadv64Ptr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const iovPtr = args[1];
                const count = args[2].toInt32();
                const offset = args[3].toNumber(); // 注意使用 toNumber() 获取 64 位数值

                console.log("Called preadv64:");
                console.log("  fd:", fd);
                console.log("  count:", count);
                console.log("  offset:", offset);

                // 读取 iovec 结构体
                for (let i = 0; i < count; i++) {
                    const iov = Memory.readByteArray(iovPtr.add(i * Process.pointerSize * 2), Process.pointerSize * 2);
                    const basePtr = ptr(iov.slice(0, Process.pointerSize).readPointer());
                    const len = ptr(iov.slice(Process.pointerSize)).readU64().toNumber();
                    console.log(`  iovec[${i}]: base=${basePtr}, len=${len}`);
                    // 可以进一步读取缓冲区内容
                    // if (len > 0) {
                    //     console.log("    Data:", Memory.readByteArray(basePtr, Math.min(len, 64))); // 读取部分数据
                    // }
                }
            },
            onLeave: function (retval) {
                console.log("preadv64 returned:", retval.toInt32());
            }
        });
    } else {
        console.error("Failed to find preadv64 in libc.so");
    }
} else if (Process.arch === 'arm') {
    const preadv64Ptr = Module.findExportByName("libc.so", "__preadv64"); // 32 位架构通常直接调用 __preadv64
    if (preadv64Ptr) {
        Interceptor.attach(preadv64Ptr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const iovPtr = args[1];
                const count = args[2].toInt32();
                const offset_low = args[3].toInt32();
                const offset_high = args[4].toInt32();
                const offset = (BigInt(offset_high) << 32n) | BigInt(offset_low);

                console.log("Called __preadv64 (32-bit):");
                console.log("  fd:", fd);
                console.log("  count:", count);
                console.log("  offset_low:", offset_low);
                console.log("  offset_high:", offset_high);
                console.log("  offset:", offset.toString());

                // 读取 iovec 结构体 (与 64 位类似)
                // ...
            },
            onLeave: function (retval) {
                console.log("__preadv64 returned:", retval.toInt32());
            }
        });
    } else {
        console.error("Failed to find __preadv64 in libc.so");
    }
}
```

**使用说明:**

1. 将上述 JavaScript 代码保存为一个 `.js` 文件（例如 `preadv_hook.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l preadv_hook.js --no-pause
   ```
   或者连接到正在运行的进程：
   ```bash
   frida -U <package_name> -l preadv_hook.js
   ```
3. 当目标应用调用 `preadv64` 或 `__preadv64` 时，Frida 会拦截该调用，并执行 `onEnter` 和 `onLeave` 函数，打印出函数的参数和返回值。

这个 Hook 示例可以帮助你理解 `preadv64` 函数在实际运行时的行为，查看传递给它的参数，以及它返回的结果。对于 32 位架构，需要 hook 底层的 `__preadv64` 并手动将两个 `long` 参数组合成 64 位的偏移量。

希望以上详细的解答能够帮助你理解 `bionic/libc/bionic/preadv_pwritev.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/preadv_pwritev.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <sys/uio.h>

// System calls we need.
extern "C" int __preadv64(int, const struct iovec*, int, long, long);
extern "C" int __preadv64v2(int, const struct iovec*, int, long, long, int);
extern "C" int __pwritev64(int, const struct iovec*, int, long, long);
extern "C" int __pwritev64v2(int, const struct iovec*, int, long, long, int);

// There is no 32-bit off_t preadv/pwritev (even on LP32).
// To avoid 32-bit ABI issues about which register pairs you're allowed
// to pass 64-bit values in, the kernel just takes two `long` arguments --
// which are int32_t for LP32, remember -- and stitches them together.
// It even does this for LP64, taking a second unused always-zero `long`.
// (The first long was int64_t, which is the same as off64_t.)
// The pair is split lo-hi (not hi-lo, as llseek is).

ssize_t preadv(int fd, const struct iovec* ios, int count, off_t offset) {
  return preadv64(fd, ios, count, offset);
}

ssize_t preadv64(int fd, const struct iovec* ios, int count, off64_t offset) {
#if defined(__LP64__)
  return __preadv64(fd, ios, count, offset, 0);
#else
  return __preadv64(fd, ios, count, offset, offset >> 32);
#endif
}

ssize_t pwritev(int fd, const struct iovec* ios, int count, off_t offset) {
  return pwritev64(fd, ios, count, offset);
}

ssize_t pwritev64(int fd, const struct iovec* ios, int count, off64_t offset) {
#if defined(__LP64__)
  return __pwritev64(fd, ios, count, offset, 0);
#else
  return __pwritev64(fd, ios, count, offset, offset >> 32);
#endif
}

ssize_t preadv2(int fd, const struct iovec* ios, int count, off_t offset, int flags) {
  return preadv64v2(fd, ios, count, offset, flags);
}

ssize_t preadv64v2(int fd, const struct iovec* ios, int count, off64_t offset, int flags) {
#if defined(__LP64__)
  return __preadv64v2(fd, ios, count, offset, 0, flags);
#else
  return __preadv64v2(fd, ios, count, offset, offset >> 32, flags);
#endif
}

ssize_t pwritev2(int fd, const struct iovec* ios, int count, off_t offset, int flags) {
  return pwritev64v2(fd, ios, count, offset, flags);
}

ssize_t pwritev64v2(int fd, const struct iovec* ios, int count, off64_t offset, int flags) {
#if defined(__LP64__)
  return __pwritev64v2(fd, ios, count, offset, 0, flags);
#else
  return __pwritev64v2(fd, ios, count, offset, offset >> 32, flags);
#endif
}

"""

```
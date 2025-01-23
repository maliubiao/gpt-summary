Response:
Let's break down the thought process for analyzing this `tmpfile.cpp` file.

**1. Understanding the Request:**

The core request is to analyze a specific C++ source file (`bionic/libc/bionic/tmpfile.cpp`) within the Android Bionic library. The analysis should cover functionality, Android integration, implementation details, dynamic linking, potential errors, and how to trace its execution. The response needs to be in Chinese.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly read through the code, paying attention to function names, included headers, and comments. Key observations from this initial scan:

* **Function Names:** `tmpfile`, `tmpfile64`, `tempnam`, `tmpnam`, `__get_TMPDIR`, `__fd_to_fp`, `__tmpfile_dir_legacy`. These names strongly suggest file system operations, particularly related to temporary files.
* **Included Headers:** `<errno.h>`, `<fcntl.h>`, `<signal.h>`, `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<sys/stat.h>`, `<sys/types.h>`, `<unistd.h>`. These are standard C library headers, confirming the file's role as a basic system utility. The inclusion of `unistd.h` hints at low-level file system interactions. The `private/ErrnoRestorer.h` inclusion indicates some internal error handling mechanism.
* **Comments:**  The copyright notice and the comments explaining the legacy `__tmpfile_dir_legacy` function and the deprecation of `tempnam` and `tmpnam` provide valuable context. The comment about `$TMPDIR` is also important.
* **System Calls:**  Functions like `open`, `mkstemp`, `unlink`, `fstat`, `close`, `fdopen`, `getenv`, `asprintf`, `snprintf`, `mktemp` are clearly system calls or wrappers around them.

**3. Deconstructing Each Function:**

Now, delve into each function individually:

* **`__fd_to_fp(int fd)`:**  This function takes a file descriptor and converts it to a `FILE*`. The `fdopen` function is the key here. The error handling (closing the FD if `fdopen` fails) is crucial.
* **`__tmpfile_dir_legacy(const char* tmp_dir)`:** The comments clearly state this is a fallback for older kernels. The process involves creating a uniquely named file using `mkstemp`, immediately unlinking it, and then converting the FD to a `FILE*`. The `unlink` makes the file temporary (removed when closed). The `fstat` check is a defensive measure to ensure the unlinking behaves as expected on the filesystem.
* **`__get_TMPDIR()`:**  This function retrieves the temporary directory path, prioritizing the `TMPDIR` environment variable and falling back to `/data/local/tmp`. This is Android-specific.
* **`tmpfile()`:** This is the core function. It attempts to use the modern `O_TMPFILE` flag to `open`. If that fails (older kernels), it falls back to `__tmpfile_dir_legacy`. This clearly shows Android's strategy of using newer features when available and providing backward compatibility.
* **`tmpfile64()`:** This is an alias for `tmpfile`. This hints at potential large file support considerations in other parts of the system, even if this particular implementation doesn't explicitly handle 64-bit offsets.
* **`tempnam(const char* dir, const char* prefix)`:** This function is explicitly marked as deprecated. It constructs a temporary file name based on a directory and prefix, ultimately using `mktemp`. The logic around `$TMPDIR` and the default directory mirrors `__get_TMPDIR`.
* **`tmpnam(char* s)`:** Another deprecated function. It creates a temporary file name in a provided buffer (or a static buffer). It relies on `mktemp`.

**4. Identifying Android-Specific Aspects:**

* **`__get_TMPDIR()`'s fallback to `/data/local/tmp`:** This is a clear indication of an Android-specific default temporary directory. This directory is commonly used by apps and the shell on Android.
* **The explanation of `O_TMPFILE` and the legacy fallback:** This highlights the evolution of the Linux kernel and how Android Bionic needs to handle different kernel versions. The comment about Lollipop is a specific timeframe within Android's history.
* **The deprecation warnings for `tempnam` and `tmpnam`:**  While these functions exist in standard C libraries, their discouragement aligns with a general move towards more secure and predictable temporary file handling practices.

**5. Dynamic Linking Considerations:**

Since Bionic is the C library, `tmpfile.cpp` will be compiled into `libc.so`. When an Android process calls `tmpfile`, the dynamic linker (`linker64` or `linker`) will resolve this symbol to the implementation in `libc.so`. This involves looking at the dependencies of the calling process and loading `libc.so` into its address space.

**6. Common Errors and Usage:**

Think about how a programmer might misuse these functions:

* **Ignoring return values:**  Failing to check if `tmpfile`, `tempnam`, or `tmpnam` returns `NULL` can lead to crashes or unexpected behavior.
* **Incorrect usage of deprecated functions:** Using `tempnam` or `tmpnam` without understanding their security implications is a bad practice.
* **Assuming specific locations:** While `__get_TMPDIR` provides a default, applications shouldn't hardcode `/data/local/tmp` as the temporary directory.

**7. Tracing with Frida:**

Consider how to hook `tmpfile`. Frida allows intercepting function calls. The example Frida script shows how to hook the `tmpfile` function, log its return value, and then execute the original function. Similar hooks could be created for other functions in the file.

**8. Structuring the Response (in Chinese):**

Organize the information logically, addressing each part of the request:

* **功能 (Functionality):** Start with a high-level summary of what the file does.
* **与 Android 的关系 (Relationship with Android):**  Focus on the Android-specific aspects, like the default temporary directory and the handling of different kernel versions.
* **libc 函数的实现 (Implementation of libc functions):**  Explain the implementation details of each function, focusing on the system calls involved.
* **动态链接 (Dynamic Linking):** Describe how the dynamic linker resolves calls to these functions, providing an example SO layout.
* **逻辑推理 (Logical Reasoning):**  Provide examples of input and output for key functions.
* **常见错误 (Common Errors):** List potential mistakes developers might make.
* **Android Framework/NDK 调用路径 (Android Framework/NDK call path):**  Illustrate how a call might originate from the Android framework or NDK and eventually reach `tmpfile`.
* **Frida Hook 示例 (Frida Hook Example):**  Provide concrete Frida code to demonstrate how to trace the execution.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the details of each system call. **Correction:**  While important, the focus should be on the *purpose* of each function and how the system calls achieve that purpose.
* **Initial thought:**  Assume the reader has a deep understanding of dynamic linking. **Correction:** Provide a clear and simple explanation of the dynamic linking process in this context.
* **Initial thought:**  Only provide a very basic Frida hook. **Correction:** Make the Frida hook more informative by logging the return value.

By following this structured thought process, the comprehensive and informative analysis provided in the initial example can be generated. The iterative refinement helps to ensure clarity and accuracy.
这是一个关于 Android Bionic 库中 `tmpfile.cpp` 文件的功能分析。该文件实现了与创建临时文件相关的 C 标准库函数。

**功能列举:**

该文件主要实现了以下几个功能，用于在 Android 系统中创建和管理临时文件：

1. **`tmpfile()` 和 `tmpfile64()`:** 创建一个临时二进制文件。该文件在被关闭或程序结束时会自动删除。`tmpfile64` 是 `tmpfile` 的别名，在 Android Bionic 中，它们的功能是相同的。
2. **`tempnam()`:**  创建一个具有唯一文件名的临时文件，允许指定目录和前缀。这个函数已被标记为废弃。
3. **`tmpnam()`:**  创建一个唯一的临时文件名，可以存储在用户提供的缓冲区中。这个函数也被标记为废弃。
4. **`__get_TMPDIR()`:**  获取临时文件存放的目录。它会优先使用环境变量 `TMPDIR`，如果未设置，则回退到 `/data/local/tmp`。
5. **`__fd_to_fp(int fd)`:**  一个内部辅助函数，将一个文件描述符（file descriptor）转换为 `FILE*` 指针，即标准 C 库的文件流。
6. **`__tmpfile_dir_legacy(const char* tmp_dir)`:**  一个内部辅助函数，用于在不支持 `O_TMPFILE` 标志的旧内核上创建临时文件。

**与 Android 功能的关系及举例说明:**

这些函数是 Android 系统中创建临时文件的基础。许多 Android 组件和应用程序可能会使用它们来存储临时数据，例如：

* **系统服务:**  某些系统服务可能需要创建临时文件来处理中间数据或日志。例如，一个处理网络连接的服务可能会使用 `tmpfile()` 来存储下载的临时数据。
* **应用程序:**  应用程序可以使用这些函数来创建临时文件用于缓存、数据处理或者与其他进程交换数据。例如，一个图片编辑应用可能会用 `tmpfile()` 来存储用户编辑的中间状态，直到用户保存最终版本。
* **NDK 开发:** 使用 NDK 开发的应用程序可以直接调用这些 C 标准库函数来创建临时文件。例如，一个游戏引擎可以使用 `tmpfile()` 来存储临时生成的地图数据。
* **Shell 命令:**  在 Android 的 shell 环境中，像 `>` 这样的重定向操作在某些情况下可能会使用临时文件。`__get_TMPDIR()` 返回的路径 `/data/local/tmp` 是 shell 脚本常用的临时目录。

**libc 函数的实现细节:**

1. **`tmpfile()` 和 `tmpfile64()`:**
   - 首先调用 `__get_TMPDIR()` 获取临时文件目录。
   - 尝试使用 `open()` 系统调用，并带上 `O_TMPFILE | O_RDWR` 标志。`O_TMPFILE` 是 Linux 内核提供的特性，用于创建一个匿名临时文件，该文件在所有指向它的文件描述符关闭后会自动删除。`S_IRUSR | S_IWUSR` 设置了文件所有者的读写权限。
   - 如果 `open()` 调用失败（通常是因为内核版本过旧，不支持 `O_TMPFILE`），则会调用 `__tmpfile_dir_legacy()` 函数作为备选方案。
   - 如果 `open()` 成功，则调用内部函数 `__fd_to_fp()` 将文件描述符转换为 `FILE*` 指针并返回。

2. **`tempnam(const char* dir, const char* prefix)`:**
   - 首先检查环境变量 `TMPDIR`，如果设置了则使用它作为临时文件目录。
   - 如果 `dir` 参数为 `nullptr`，且环境变量 `TMPDIR` 也未设置，则使用默认目录 `/data/local/tmp`。
   - 如果 `prefix` 参数为 `nullptr`，则使用默认前缀 "tempnam."。
   - 使用 `asprintf()` 构造一个 `mktemp(3)` 模板字符串，格式为 `目录/前缀XXXXXXXXXX`，其中 `XXXXXXXXXX` 会被替换为随机字符。
   - 调用 `mktemp()` 函数根据模板创建唯一的文件名。`mktemp()` 会修改传入的字符串。
   - 如果 `mktemp()` 失败，则释放分配的内存并返回 `nullptr`。
   - 返回生成的临时文件路径名。**注意：这个函数只生成文件名，不创建文件。**

3. **`tmpnam(char* s)`:**
   - 如果传入的 `s` 指针为 `nullptr`，则使用一个静态缓冲区 `buf`。
   - 使用 `snprintf()` 构造一个 `mktemp(3)` 模板字符串，格式为 `%s/tmpnam.XXXXXXXXXX`，其中 `%s` 是通过 `__get_TMPDIR()` 获取的临时目录。
   - 调用 `mktemp()` 函数根据模板创建唯一的文件名，并将结果写入提供的缓冲区 `s` 或静态缓冲区。
   - 返回生成的临时文件路径名。**注意：这个函数只生成文件名，不创建文件。**

4. **`__get_TMPDIR()`:**
   - 调用 `getenv("TMPDIR")` 获取名为 `TMPDIR` 的环境变量的值。
   - 如果环境变量存在且非空，则返回其值。
   - 否则，返回硬编码的默认路径 `/data/local/tmp`。

5. **`__fd_to_fp(int fd)`:**
   - 调用 `fdopen(fd, "w+")` 函数。`fdopen()` 将一个已存在的文件描述符转换为标准 C 库的文件流 (`FILE*`)。 `"w+"` 模式表示以读写方式打开，如果文件不存在则创建。
   - 如果 `fdopen()` 成功，则返回新创建的 `FILE*` 指针。
   - 如果 `fdopen()` 失败，则记录错误并关闭传入的文件描述符 `fd`，然后返回 `nullptr`。这里使用了 `ErrnoRestorer` 来确保在关闭文件描述符后恢复原始的 `errno` 值。

6. **`__tmpfile_dir_legacy(const char* tmp_dir)`:**
   - 使用 `asprintf()` 构造一个 `mkstemp(3)` 模板字符串，格式为 `临时目录/tmp.XXXXXXXXXX`。
   - 调用 `mkstemp(path)` 函数。`mkstemp()` 会创建一个具有唯一名称的文件，并返回一个打开的文件描述符。它会修改传入的字符串 `path` 为实际创建的文件名。
   - 如果 `mkstemp()` 失败，则释放分配的内存并返回 `nullptr`。
   - 调用 `unlink(path)` 删除刚刚创建的文件。由于文件仍然被文件描述符引用，所以文件的数据不会被立即删除，但文件名会从文件系统中移除。这实现了临时文件的效果：当所有指向该文件的文件描述符关闭后，文件会被自动删除。
   - 调用 `free(path)` 释放分配的文件名字符串内存。
   - 调用 `fstat(fd, &sb)` 获取文件描述符 `fd` 关联的文件状态信息。这是为了检查文件系统是否支持硬链接，因为 `unlink` 的语义依赖于此。如果 `fstat` 失败，则关闭文件描述符并返回 `nullptr`。
   - 最后，调用 `__fd_to_fp(fd)` 将文件描述符转换为 `FILE*` 指针并返回。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

`tmpfile.cpp` 中的函数最终会被编译进 Android 的 C 库 `libc.so`。当一个应用程序或系统服务调用 `tmpfile()` 时，动态链接器会负责找到并加载 `libc.so`，并将函数调用重定向到 `libc.so` 中 `tmpfile()` 的实现。

**so 布局样本 (libc.so 的部分布局):**

```
libc.so:
    ...
    符号表:
        ...
        00012340 T tmpfile  // tmpfile 函数的地址
        00012380 T tmpfile64 // tmpfile64 函数的地址
        000123C0 T tempnam  // tempnam 函数的地址
        00012400 T tmpnam   // tmpnam 函数的地址
        00012440 T __get_TMPDIR // __get_TMPDIR 函数的地址
        ...
    ...
```

**链接的处理过程:**

1. **应用程序调用:** 应用程序的代码中调用了 `tmpfile()` 函数。
2. **链接器介入:**  由于 `tmpfile()` 是一个外部符号，链接器（在程序启动时或首次调用时）会检查应用程序的依赖库列表。
3. **查找 `libc.so`:**  应用程序通常会链接到 `libc.so`。链接器会在系统路径中查找 `libc.so`。
4. **加载 `libc.so`:**  如果找到 `libc.so`，链接器会将 `libc.so` 加载到应用程序的进程地址空间中。
5. **符号解析:** 链接器会查找 `libc.so` 的符号表，找到 `tmpfile()` 函数对应的地址（例如示例中的 `00012340`）。
6. **重定向:** 链接器会将应用程序中对 `tmpfile()` 的调用重定向到 `libc.so` 中找到的地址。
7. **执行:** 当应用程序执行到调用 `tmpfile()` 的代码时，实际上会跳转到 `libc.so` 中 `tmpfile()` 的实现代码。

**逻辑推理，给出假设输入与输出:**

**`tmpfile()`:**

* **假设输入:** 无特定输入。
* **可能输出:** 返回一个 `FILE*` 指针，指向一个新创建的临时文件，例如 `/data/local/tmp/匿名文件`（实际文件名是匿名的）。该文件以读写模式打开。如果创建失败，返回 `nullptr` 并设置相应的 `errno`。

**`tempnam("/sdcard/my_temp_dir", "my_prefix_")`:**

* **假设输入:** `dir` 为 `/sdcard/my_temp_dir`，`prefix` 为 `my_prefix_`。
* **可能输出:** 返回一个指向新生成的临时文件名的字符串，例如 `/sdcard/my_temp_dir/my_prefix_abcdefghij`。**请注意，`tempnam` 只生成文件名，不创建文件。** 如果创建文件名失败，返回 `nullptr`。

**`tmpnam(buffer)` (假设 buffer 是一个足够大的 char 数组):**

* **假设输入:** `buffer` 是一个大小为 `L_tmpnam` 的字符数组。
* **可能输出:** `buffer` 中会包含一个新生成的临时文件名，例如 `/data/local/tmp/tmpnam.klmnopqrstuv`。函数也会返回指向 `buffer` 的指针。**请注意，`tmpnam` 只生成文件名，不创建文件。** 如果创建文件名失败，返回 `nullptr`。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记检查返回值:**
   ```c
   FILE *fp = tmpfile();
   // 忘记检查 fp 是否为 NULL，直接使用可能导致程序崩溃
   fprintf(fp, "临时数据\n");
   fclose(fp);
   ```

2. **误解 `tempnam` 和 `tmpnam` 的作用:**
   ```c
   char *filename = tempnam(NULL, "my_temp_");
   // 以为 tempnam 创建了文件，直接尝试写入
   FILE *fp = fopen(filename, "w"); // 需要显式打开文件
   if (fp) {
       fprintf(fp, "数据\n");
       fclose(fp);
   }
   free(filename); // 记得释放 tempnam 分配的内存
   ```

3. **没有正确处理临时文件的生命周期:**
   ```c
   FILE *fp = tmpfile();
   // ... 使用临时文件 ...
   // 忘记 fclose(fp); 导致资源泄漏，虽然程序结束时会被删除，但长时间运行的程序需要注意
   ```

4. **在多线程环境下使用 `tmpnam` 的静态缓冲区:**
   ```c
   // tmpnam 使用静态缓冲区，在多线程环境下可能产生竞争条件
   char *name1 = tmpnam(NULL);
   // 另一个线程可能同时调用 tmpnam，导致 name1 指向的缓冲区内容被覆盖
   char *name2 = tmpnam(NULL);
   ```

5. **假设临时文件总是创建在特定位置:**  虽然 `__get_TMPDIR()` 提供了默认路径，但用户可以通过设置环境变量来更改临时目录，程序不应该硬编码临时文件路径。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 调用路径示例:**

一个 Android 应用可能会通过 Java Framework 调用 NDK 中的本地代码，而 NDK 代码最终可能调用 `tmpfile()`。例如，一个处理媒体文件的应用可能需要创建临时文件来存储解码后的帧数据：

1. **Java Framework (例如 MediaCodec):**  Java 层的 `MediaCodec` 类可能会调用本地方法来解码视频帧。
2. **NDK 代码 (例如 C++ 解码器):**  NDK 中的 C++ 解码器接收到解码请求。
3. **创建临时文件:** 解码器需要一个临时位置来存储解码后的帧数据，可能会调用 `tmpfile()`。
4. **`libc.so::tmpfile()`:** 调用最终会到达 `bionic/libc/bionic/tmpfile.cpp` 中实现的 `tmpfile()` 函数。

**NDK 直接调用示例:**

一个使用 NDK 开发的游戏可以直接调用 `tmpfile()` 来创建临时文件存储游戏存档的中间状态：

1. **NDK 代码 (C++ 游戏引擎):** 游戏引擎的 C++ 代码需要创建临时文件。
2. **调用 `tmpfile()`:**  直接调用 C 标准库函数 `tmpfile()`。
3. **`libc.so::tmpfile()`:** 调用最终会到达 `bionic/libc/bionic/tmpfile.cpp` 中实现的 `tmpfile()` 函数。

**Frida Hook 示例:**

可以使用 Frida 来 hook `tmpfile()` 函数，以观察其调用和返回值。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到应用 {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "tmpfile"), {
    onEnter: function(args) {
        console.log("[+] tmpfile() 被调用");
    },
    onLeave: function(retval) {
        console.log("[+] tmpfile() 返回值: " + retval);
        if (retval != 0) {
            var fd = ptr(retval).readUsize(); // 假设 FILE* 就是文件描述符
            console.log("[+] 文件描述符: " + fd);
            // 可以尝试读取一些文件信息，但需要注意文件可能已经被 unlink
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "tempnam"), {
    onEnter: function(args) {
        console.log("[+] tempnam() 被调用, dir: " + (args[0] ? Memory.readUtf8String(args[0]) : "NULL") + ", prefix: " + (args[1] ? Memory.readUtf8String(args[1]) : "NULL"));
    },
    onLeave: function(retval) {
        console.log("[+] tempnam() 返回值: " + (retval ? Memory.readUtf8String(retval) : "NULL"));
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "tmpnam"), {
    onEnter: function(args) {
        console.log("[+] tmpnam() 被调用, arg: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[+] tmpnam() 返回值: " + (retval ? Memory.readUtf8String(retval) : "NULL"));
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**使用方法:**

1. 将上面的 Python 代码保存为一个 `.py` 文件，例如 `hook_tmpfile.py`。
2. 确保你的 Android 设备已连接并通过 USB 调试授权，并且安装了 Frida 服务。
3. 将 `你的应用包名` 替换为你要调试的 Android 应用的实际包名。
4. 运行脚本：`python hook_tmpfile.py`
5. 启动或操作你的 Android 应用，当应用调用 `tmpfile`、`tempnam` 或 `tmpnam` 时，Frida 会拦截调用并打印相关信息，包括参数和返回值。

这个 Frida 脚本提供了基本的 hook 功能，你可以根据需要扩展它，例如读取或修改参数，或者在 `tmpfile` 创建的文件中写入数据等。请注意，hook 系统库函数需要 root 权限或在可调试的应用上进行。

### 提示词
```
这是目录为bionic/libc/bionic/tmpfile.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "private/ErrnoRestorer.h"

static FILE* __fd_to_fp(int fd) {
  FILE* fp = fdopen(fd, "w+");
  if (fp != nullptr) return fp;

  ErrnoRestorer errno_restorer;
  close(fd);
  return nullptr;
}

// O_TMPFILE isn't available until Linux 3.11, so we fall back to this on
// older kernels. AOSP was on a new enough kernel in the Lollipop timeframe,
// so this code should be obsolete by 2025.
static FILE* __tmpfile_dir_legacy(const char* tmp_dir) {
  char* path = nullptr;
  if (asprintf(&path, "%s/tmp.XXXXXXXXXX", tmp_dir) == -1) {
    return nullptr;
  }

  int fd = mkstemp(path);
  if (fd == -1) {
    free(path);
    return nullptr;
  }

  // Unlink the file now so that it's removed when closed.
  unlink(path);
  free(path);

  // Can we still use the file now it's unlinked?
  // File systems without hard link support won't have the usual Unix semantics.
  struct stat sb;
  if (fstat(fd, &sb) == -1) {
    ErrnoRestorer errno_restorer;
    close(fd);
    return nullptr;
  }

  return __fd_to_fp(fd);
}

const char* __get_TMPDIR() {
  // Use $TMPDIR if set, or fall back to /data/local/tmp otherwise.
  // Useless for apps, but good enough for the shell.
  const char* tmpdir = getenv("TMPDIR");
  return (tmpdir == nullptr) ? "/data/local/tmp" : tmpdir;
}

FILE* tmpfile() {
  const char* tmpdir = __get_TMPDIR();
  int fd = open(tmpdir, O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd == -1) return __tmpfile_dir_legacy(tmpdir);
  return __fd_to_fp(fd);
}
__strong_alias(tmpfile64, tmpfile);

char* tempnam(const char* dir, const char* prefix) {
  // This function is a terrible idea, marked deprecated in our headers,
  // and marked obsolescent by POSIX.1-2008, but we make some effort anyway
  // since we can't easily remove it...

  // $TMPDIR overrides any directory passed in.
  const char* tmpdir = getenv("TMPDIR");
  if (tmpdir != nullptr) dir = tmpdir;

  // If we still have no directory, we'll give you a default.
  // It's useless for apps, but good enough for the shell.
  if (dir == nullptr) dir = "/data/local/tmp";

  // Default prefix?
  if (prefix == nullptr) prefix = "tempnam.";

  // Make up a mktemp(3) template and defer to it for the real work.
  char* path = nullptr;
  if (asprintf(&path, "%s/%sXXXXXXXXXX", dir, prefix) == -1) return nullptr;
  if (mktemp(path) == nullptr) {
    free(path);
    return nullptr;
  }
  return path;
}

char* tmpnam(char* s) {
  // This function is a terrible idea, marked deprecated in our headers,
  // and marked obsolescent by POSIX-1.2008, but we make some effort anyway
  // since we can't easily remove it...

  // Default buffer?
  static char buf[L_tmpnam];
  if (s == nullptr) s = buf;

  // Make up a mktemp(3) template and defer to it for the real work.
  snprintf(s, L_tmpnam, "%s/tmpnam.XXXXXXXXXX", __get_TMPDIR());
  return mktemp(s);
}
```
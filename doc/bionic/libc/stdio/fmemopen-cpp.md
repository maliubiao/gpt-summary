Response:
Let's break down the thought process for analyzing the `fmemopen.cpp` code and generating the detailed response.

**1. Understanding the Core Functionality:**

The first step is to recognize the purpose of the code. The comments at the beginning explicitly state it implements `fmemopen`. Reading the provided links (opengroup and man7 pages, if I had access to them directly) would further solidify this. Even without those links, the function signature `FILE* fmemopen(void* buf, size_t capacity, const char* mode)` strongly hints at creating a `FILE` stream backed by memory.

**2. Deconstructing the Code - Identifying Key Components:**

Next, I'd systematically go through the code, identifying the main parts:

* **`struct fmemopen_cookie`:**  This immediately stands out as the internal data structure used to manage the memory buffer, its size, capacity, and current position. Understanding its members (`buf`, `allocation`, `capacity`, `size`, `offset`, `append`) is crucial.

* **Static Functions:**  The `fmemopen_read`, `fmemopen_write`, `fmemopen_seek`, and `fmemopen_close` functions are clearly the implementation details of the stream's operations. I'd analyze each of these individually to understand how they interact with the `fmemopen_cookie`.

* **The `fmemopen` Function:** This is the entry point. I'd pay close attention to:
    * How it parses the `mode` string (using `__sflags`).
    * How it allocates and initializes the `fmemopen_cookie`.
    * The conditional allocation of the buffer itself (if `buf` is `nullptr`).
    * The use of `funopen`. This is a key point indicating a custom stream implementation.
    * How the initial state (size, offset, append flag) is set based on the `mode`.

**3. Connecting to Android/Bionic:**

Knowing this is bionic code, I'd think about how this function fits into the broader Android ecosystem. Since bionic is the C library, `fmemopen` is a standard C function provided by Android. Examples of its use would involve scenarios where in-memory buffering is needed.

**4. Explaining Libc Function Implementations:**

For each of the static functions (`fmemopen_read`, `fmemopen_write`, `fmemopen_seek`, `fmemopen_close`), I would trace the logic:

* **`fmemopen_read`:**  Focus on the bounds checking (`n > ck->size - ck->offset`) and the `memmove`.
* **`fmemopen_write`:** Pay attention to the handling of append mode, capacity limits, and the crucial null termination logic.
* **`fmemopen_seek`:** Understand the different `whence` values (SEEK_SET, SEEK_CUR, SEEK_END) and the corresponding calculations for the offset.
* **`fmemopen_close`:**  Simple freeing of allocated memory.

**5. Dynamic Linker Considerations:**

The code itself doesn't directly interact with the dynamic linker. `fmemopen` is a standard C library function. However, the *usage* of this function might involve dynamically linked libraries. I need to explain the general process of how libraries are loaded and linked, and how `fmemopen` within one library can interact with memory owned by another. The SO layout example is helpful here.

**6. Logical Reasoning and Examples:**

To illustrate the functionality, I'd create simple examples with clear inputs and expected outputs for read, write, and seek operations, covering different modes ("r", "w", "a").

**7. Common Usage Errors:**

I'd consider what mistakes a programmer might make when using `fmemopen`, such as incorrect mode strings, exceeding capacity, or misunderstanding append mode.

**8. Android Framework/NDK Integration and Frida Hooking:**

This requires thinking about how user-space code (either through the Android Framework or NDK) eventually calls into the C library. A likely path would involve higher-level Java APIs calling native methods, which in turn use standard C functions like `fmemopen`. The Frida hook example would target the `fmemopen` function directly to observe its behavior.

**Pre-computation and Pre-analysis (Internal Thought Processes):**

* **Keywords:** I'd immediately identify keywords like `fmemopen`, `FILE`, `memory`, `buffer`, `stream`, `bionic`, `libc`, `funopen`.
* **Standard Library Knowledge:**  My existing knowledge of standard C library functions (`calloc`, `free`, `memmove`, `strnlen`, `funopen`, `errno`) is essential.
* **Stream Concepts:** Understanding the concepts of file streams, reading, writing, seeking, and different modes ("r", "w", "a") is crucial.
* **Dynamic Linking Fundamentals:**  A basic understanding of how shared libraries are loaded and linked is needed to address that aspect of the prompt.

**Trial-and-Error/Refinement:**

While generating the response, I'd internally review and refine the explanations. For example, I might initially describe the `fmemopen_cookie` members but then realize I need to explain *why* each member is necessary. Similarly, for the Frida hook, I would ensure the code snippet is practical and targets the correct function.

By following this structured approach, breaking down the problem into smaller, manageable parts, and leveraging my knowledge of C, Android, and dynamic linking, I can generate a comprehensive and accurate answer to the user's request.
好的，我们来详细分析 `bionic/libc/stdio/fmemopen.cpp` 这个文件。

**文件功能概述:**

`fmemopen.cpp` 文件实现了标准 C 库函数 `fmemopen`。这个函数允许程序员将一块内存区域当作一个标准的文件流（`FILE*`）来操作。这意味着你可以像读写文件一样读写这块内存，例如使用 `fread`, `fwrite`, `fprintf`, `fscanf` 等标准 I/O 函数。

**与 Android 功能的关系及举例:**

`fmemopen` 是 Bionic (Android 的 C 库) 提供的一个标准 C 函数，因此它广泛应用于 Android 的各种组件和应用程序中，包括 Java Framework 层、Native 代码（通过 NDK）以及 Android 系统服务。

**举例说明:**

1. **在内存中构建和解析数据:**  一个应用可能需要在内存中构建一个复杂的配置或者数据结构，然后将其作为一个文件流进行格式化输出（例如使用 `fprintf`）。之后，可以再次使用 `fmemopen` 将该内存区域打开为读取流，并使用 `fscanf` 或其他函数解析数据。

2. **进程间通信 (IPC):** 虽然不是 `fmemopen` 的主要用途，但在某些特定的 IPC 场景下，可以将一块共享内存区域通过 `fmemopen` 包装成文件流，方便进行数据交换。但这通常不如专门的 IPC 机制高效和安全。

3. **测试和模拟:**  在单元测试中，可以使用 `fmemopen` 创建一个内存中的“文件”，用于模拟文件读写操作，而无需实际操作磁盘文件，提高测试效率和隔离性。

4. **Android Framework 的使用:** Android Framework 内部的一些组件可能会使用 `fmemopen` 来处理内存中的数据流，例如将资源文件加载到内存后，可以将其当作文件流进行解析。

**libc 函数的实现细节:**

`fmemopen` 的实现依赖于标准 C 库提供的 `funopen` 函数。`funopen` 允许你使用自定义的读、写、定位和关闭函数来创建一个 `FILE` 流。`fmemopen.cpp` 主要的工作是定义这些自定义函数，并管理与内存缓冲区相关的状态。

1. **`struct fmemopen_cookie`:**  这是一个关键的数据结构，用于存储与这个内存文件流相关的信息：
   - `buf`: 指向用户提供的内存缓冲区。
   - `allocation`: 如果用户没有提供缓冲区（`buf` 为 `nullptr`），则由 `fmemopen` 内部 `calloc` 分配的缓冲区地址。
   - `capacity`:  缓冲区的总容量。
   - `size`:  当前缓冲区中有效数据的长度。
   - `offset`:  当前读/写位置的偏移量。
   - `append`:  一个布尔值，指示是否以追加模式打开。

2. **`fmemopen_read(void* cookie, char* buf, int n)`:**
   - **功能:**  从内存缓冲区中读取最多 `n` 个字节的数据到 `buf` 中。
   - **实现:**
     - 首先将 `cookie` 转换为 `fmemopen_cookie*` 以访问缓冲区信息。
     - 检查要读取的字节数 `n` 是否超过剩余可读的数据量 (`ck->size - ck->offset`)，如果超过则调整 `n`。
     - 如果 `n` 大于 0，使用 `memmove` 将数据从缓冲区 (`ck->buf + ck->offset`) 复制到目标缓冲区 `buf`。
     - 更新偏移量 `ck->offset`。
     - 返回实际读取的字节数。

3. **`fmemopen_write(void* cookie, const char* buf, int n)`:**
   - **功能:**  将 `buf` 中的最多 `n` 个字节的数据写入到内存缓冲区中。
   - **实现:**
     - 首先将 `cookie` 转换为 `fmemopen_cookie*`。
     - 计算是否需要额外的空间来添加结尾的空字符 (`\0`)。
     - 如果以追加模式打开 (`ck->append`)，则将偏移量 `ck->offset` 设置为当前有效数据末尾 (`ck->size`)。
     - 检查是否有足够的空间写入数据，如果空间不足，则调整 `n`，并设置 `errno` 为 `ENOSPC` 并返回 -1。
     - 如果 `n` 大于 0，使用 `memmove` 将数据从 `buf` 复制到缓冲区 (`ck->buf + ck->offset`)。
     - 更新偏移量 `ck->offset`。
     - 如果写入后偏移量超过了之前的有效数据长度 (`ck->size`)，则更新 `ck->size`，并在必要时添加结尾的空字符。
     - 返回实际写入的字节数。

4. **`fmemopen_seek(void* cookie, fpos_t offset, int whence)`:**
   - **功能:**  设置内存文件流的读/写位置。
   - **实现:**
     - 首先将 `cookie` 转换为 `fmemopen_cookie*`。
     - 根据 `whence` 的值（`SEEK_SET`, `SEEK_CUR`, `SEEK_END`）计算新的偏移量。
     - 进行边界检查，确保新的偏移量在有效范围内（不会小于 0 或大于缓冲区容量）。
     - 如果偏移量有效，则更新 `ck->offset` 并返回新的偏移量。
     - 如果偏移量无效，则设置 `errno` 为 `EINVAL` 并返回 -1。

5. **`fmemopen_close(void* cookie)`:**
   - **功能:**  关闭内存文件流，释放相关资源。
   - **实现:**
     - 首先将 `cookie` 转换为 `fmemopen_cookie*`。
     - 如果内部有分配缓冲区 (`ck->allocation` 不为 `nullptr`)，则使用 `free` 释放该缓冲区。
     - 使用 `free` 释放 `fmemopen_cookie` 结构体本身。
     - 返回 0 表示成功。

6. **`FILE* fmemopen(void* buf, size_t capacity, const char* mode)`:**
   - **功能:**  创建并返回一个与指定内存缓冲区关联的文件流。
   - **实现:**
     - 使用 `__sflags` 函数解析 `mode` 字符串，获取文件打开的标志（例如读、写、追加等）。
     - 分配 `fmemopen_cookie` 结构体的内存。
     - 如果用户提供了缓冲区 `buf`，则直接使用，否则内部使用 `calloc` 分配缓冲区。
     - 调用 `funopen` 函数，并将 `fmemopen_cookie` 以及上面实现的 `fmemopen_read`、`fmemopen_write`、`fmemopen_seek` 和 `fmemopen_close` 函数指针传递给 `funopen`，从而创建一个自定义行为的 `FILE` 流。
     - 根据 `mode` 的值设置初始的 `size` 和 `offset`，以及 `append` 标志。
     - 返回创建的 `FILE` 指针。

**动态链接器功能:**

`fmemopen.cpp` 本身不直接涉及动态链接器的功能。它是 C 标准库的一部分，编译后会链接到 `libc.so` 中。当应用程序调用 `fmemopen` 时，动态链接器负责找到 `libc.so` 并执行其中的 `fmemopen` 函数。

**SO 布局样本:**

假设一个简单的 Android 应用使用了 `fmemopen`：

```
/system/bin/app_process64  # 应用进程
  /apex/com.android.runtime/bin/linker64  # 动态链接器
  /system/lib64/libc.so               # Bionic C 库
    ... (fmemopen 函数的代码位于此) ...
  /data/app/com.example.myapp/lib/arm64-v8a/libnative.so # 应用的 Native 库 (如果使用了 NDK)
    ... (可能会调用 fmemopen) ...
```

**链接的处理过程:**

1. **编译时:** 当编译应用的 Native 代码时，编译器会识别出 `fmemopen` 函数调用，并将其标记为一个需要外部链接的符号。

2. **链接时:** 链接器会将应用的 Native 库 `libnative.so` 与 Bionic C 库 `libc.so` 链接起来。链接器会找到 `libc.so` 中 `fmemopen` 函数的定义，并将 `libnative.so` 中对 `fmemopen` 的调用指向 `libc.so` 中的实现。

3. **运行时:** 当应用进程启动时，动态链接器 `/apex/com.android.runtime/bin/linker64` 会加载应用依赖的共享库，包括 `libc.so` 和 `libnative.so`。当 `libnative.so` 中的代码执行到 `fmemopen` 函数调用时，程序会跳转到 `libc.so` 中 `fmemopen` 函数的地址执行。

**逻辑推理和假设输入输出:**

**假设输入:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  char buffer[100];
  FILE *fp;

  // 使用 fmemopen 创建一个内存文件流，用于写入
  fp = fmemopen(buffer, sizeof(buffer), "w+");
  if (fp == NULL) {
    perror("fmemopen failed");
    return 1;
  }

  fprintf(fp, "Hello, world!");
  fflush(fp); // 确保数据写入缓冲区

  printf("Buffer content: %s\n", buffer);

  // 将读写位置移动到开头
  fseek(fp, 0, SEEK_SET);

  char read_buffer[20];
  fscanf(fp, "%s", read_buffer);
  printf("Read from buffer: %s\n", read_buffer);

  fclose(fp);
  return 0;
}
```

**预期输出:**

```
Buffer content: Hello, world!
Read from buffer: Hello,
```

**解释:**

- `fmemopen` 使用 "w+" 模式打开，允许读写。
- `fprintf` 将 "Hello, world!" 写入到 `buffer` 中。
- `fflush` 确保数据被写入缓冲区。
- `printf` 打印缓冲区的内容。
- `fseek` 将读写位置移动到缓冲区的开头。
- `fscanf` 从缓冲区读取一个单词 ("Hello,"，注意 `fscanf` 以空格分隔单词)。
- `printf` 打印读取的内容。

**用户或编程常见的使用错误:**

1. **缓冲区溢出:**  如果写入的数据量超过了 `fmemopen` 指定的 `capacity`，`fmemopen_write` 会返回错误（-1）并设置 `errno` 为 `ENOSPC`。用户需要确保写入的数据量不超过缓冲区大小。

   ```c
   char buffer[10];
   FILE *fp = fmemopen(buffer, sizeof(buffer), "w");
   fprintf(fp, "This is a long string"); // 错误：写入的数据超过缓冲区大小
   fclose(fp);
   ```

2. **模式不匹配:**  如果以只读模式打开，尝试写入会导致错误。

   ```c
   char buffer[100];
   FILE *fp = fmemopen(buffer, sizeof(buffer), "r");
   fprintf(fp, "Hello"); // 错误：以只读模式打开，无法写入
   fclose(fp);
   ```

3. **忘记 `fflush`:** 在写入数据后，如果后续需要读取或查看缓冲区内容，需要调用 `fflush` 将缓冲区中的数据刷新到内存中。

4. **错误的 `fseek` 使用:**  `fseek` 的偏移量和 `whence` 参数使用不当可能导致定位到无效的位置。

5. **生命周期管理:** 如果 `fmemopen` 使用了用户提供的缓冲区，那么在 `fclose` 之后，用户仍然需要负责管理该缓冲区的生命周期。如果 `fmemopen` 内部分配了缓冲区，`fclose` 会释放该缓冲区。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例:**

**调用路径 (示例):**

1. **Android Framework (Java):**  假设一个 Java 应用需要处理一些内存中的数据，并使用了 Android SDK 提供的相关类，这些类底层可能会调用 Native 代码。

2. **NDK (Native 代码):**  Java 层可能会调用一个 Native 方法（通过 JNI）。这个 Native 方法是用 C/C++ 编写的。

3. **`fmemopen` 调用:**  在 Native 代码中，可能会使用 `fmemopen` 将一块内存区域当作文件流来处理。

**Frida Hook 示例:**

假设你想 hook `fmemopen` 函数，查看其参数和返回值。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fmemopen"), {
    onEnter: function(args) {
        console.log("[+] fmemopen called");
        console.log("    buf:", args[0]);
        console.log("    capacity:", args[1].toInt());
        console.log("    mode:", Memory.readUtf8String(args[2]));
        this.buf = args[0]; // 保存 buf 参数
    },
    onLeave: function(retval) {
        console.log("[+] fmemopen returned:", retval);
        if (retval.isNull() === false && this.buf !== null) {
            // 如果 fmemopen 成功并且提供了缓冲区，打印前 32 字节的内容
            console.log("    Buffer content (first 32 bytes):", hexdump(this.buf, { length: 32 }));
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

1. **连接目标进程:**  使用 Frida 连接到目标 Android 应用的进程。
2. **查找函数地址:**  使用 `Module.findExportByName("libc.so", "fmemopen")` 找到 `libc.so` 中 `fmemopen` 函数的地址。
3. **拦截 `onEnter`:**  在 `fmemopen` 函数被调用时执行 `onEnter` 函数：
   - 打印 "fmemopen called"。
   - 打印 `buf`、`capacity` 和 `mode` 参数的值。
   - 保存 `buf` 参数到 `this.buf`，以便在 `onLeave` 中使用。
4. **拦截 `onLeave`:** 在 `fmemopen` 函数执行完毕返回时执行 `onLeave` 函数：
   - 打印 "fmemopen returned" 以及返回值。
   - 如果返回值不为空（表示 `fmemopen` 调用成功）并且 `buf` 参数不为空（表示用户提供了缓冲区），则使用 `hexdump` 打印缓冲区的前 32 个字节的内容。

通过这个 Frida 脚本，你可以观察到 `fmemopen` 何时被调用，它的参数是什么，以及返回的 `FILE*` 指针。如果提供了缓冲区，还能看到缓冲区的部分内容。这有助于理解 Android Framework 或 NDK 代码是如何使用 `fmemopen` 的。

希望以上分析能够帮助你理解 `bionic/libc/stdio/fmemopen.cpp` 的功能和实现细节，以及它在 Android 系统中的应用。

Prompt: 
```
这是目录为bionic/libc/stdio/fmemopen.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*-
 * Copyright (C) 2013 Pietro Cerutti <gahr@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "local.h"

// See https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/fmemopen.html
// and https://man7.org/linux/man-pages/man3/fmemopen.3.html for documentation.

struct fmemopen_cookie {
  char* buf;
  char* allocation;
  size_t capacity;
  size_t size;
  size_t offset;
  bool append;
};

static int fmemopen_read(void* cookie, char* buf, int n) {
  fmemopen_cookie* ck = static_cast<fmemopen_cookie*>(cookie);

  if (static_cast<size_t>(n) > ck->size - ck->offset) n = ck->size - ck->offset;

  if (n > 0) {
    memmove(buf, ck->buf + ck->offset, n);
    ck->offset += n;
  }
  return n;
}

static int fmemopen_write(void* cookie, const char* buf, int n) {
  fmemopen_cookie* ck = static_cast<fmemopen_cookie*>(cookie);

  // We don't need to add the trailing NUL if there's already a trailing NUL
  // in the data we're writing.
  size_t space_for_null = (n > 0 && buf[n - 1] != '\0') ? 1 : 0;

  // Undo any seeking/reading on an append-only stream.
  if (ck->append) ck->offset = ck->size;

  // How much can we actually fit?
  if (static_cast<size_t>(n) + space_for_null > ck->capacity - ck->offset) {
    n = ck->capacity - ck->offset - space_for_null;
    // Give up if we don't even have room for one byte of userdata.
    if (n <= 0) {
      errno = ENOSPC;
      return -1;
    }
  }

  if (n > 0) {
    memmove(ck->buf + ck->offset, buf, n);
    ck->offset += n;
    // Is this the furthest we've ever been?
    if (ck->offset >= ck->size) {
      if (buf[n - 1] != '\0') ck->buf[ck->offset] = '\0';
      ck->size = ck->offset;
    }
  }
  return n;
}

static fpos_t fmemopen_seek(void* cookie, fpos_t offset, int whence) {
  fmemopen_cookie* ck = static_cast<fmemopen_cookie*>(cookie);

  if (whence == SEEK_SET && (offset >= 0 && static_cast<size_t>(offset) <= ck->capacity)) {
    return (ck->offset = offset);
  } else if (whence == SEEK_CUR && (ck->offset + offset <= ck->capacity)) {
    return (ck->offset += offset);
  } else if (whence == SEEK_END && (offset <= 0 && static_cast<size_t>(-offset) <= ck->size)) {
    return (ck->offset = ck->size + offset);
  }
  errno = EINVAL;
  return -1;
}

static int fmemopen_close(void* cookie) {
  fmemopen_cookie* ck = static_cast<fmemopen_cookie*>(cookie);
  free(ck->allocation);
  free(ck);
  return 0;
}

FILE* fmemopen(void* buf, size_t capacity, const char* mode) {
  int flags;
  if (__sflags(mode, &flags) == 0) {
    errno = EINVAL;
    return nullptr;
  }

  fmemopen_cookie* ck = static_cast<fmemopen_cookie*>(calloc(sizeof(fmemopen_cookie), 1));
  if (ck == nullptr) return nullptr;

  ck->buf = static_cast<char*>(buf);
  ck->capacity = capacity;

  if (ck->buf == nullptr) ck->buf = ck->allocation = static_cast<char*>(calloc(capacity, 1));
  if (ck->buf == nullptr) {
    free(ck);
    return nullptr;
  }

  FILE* fp = funopen(ck,
                     (flags & O_WRONLY) ? nullptr : fmemopen_read,
                     (flags & O_RDONLY) ? nullptr : fmemopen_write,
                     fmemopen_seek,
                     fmemopen_close);
  if (fp == nullptr) {
    fmemopen_close(ck);
    return nullptr;
  }

  if (mode[0] == 'a') {
    ck->size = strnlen(ck->buf, ck->capacity);
    ck->offset = ck->size;
    ck->append = true;
  } else if (mode[0] == 'r') {
    ck->size = capacity;
    ck->offset = 0;
  } else if (mode[0] == 'w') {
    ck->size = 0;
    ck->offset = 0;
    if (capacity > 0) {
      ck->buf[0] = '\0';
    }
  }

  return fp;
}

"""

```
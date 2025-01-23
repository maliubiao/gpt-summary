Response:
Let's break down the thought process for generating the comprehensive answer about `getentropy.cpp`.

**1. Understanding the Request:**

The request asks for a detailed analysis of the provided C++ code for `getentropy.cpp` within the Android Bionic library. Key aspects to cover include functionality, relation to Android, implementation details of libc functions, dynamic linker involvement, usage errors, how Android reaches this code, and a Frida hook example. The response needs to be in Chinese.

**2. Initial Code Analysis (High-Level):**

First, I read through the code to get a general understanding. I see:

* Inclusion of standard headers (`errno.h`, `fcntl.h`, `sys/random.h`, `unistd.h`).
* Inclusion of a Bionic-specific header (`private/ScopedFd.h`).
* Two functions: `getentropy_urandom` and `getentropy`.
* `getentropy` seems to be the main function, attempting to use `getrandom` first and falling back to `/dev/urandom`.
* Error handling with `errno`.
* A size limit of 256 bytes for `getentropy`.

**3. Deconstructing the Request - Planning the Sections:**

I mentally break down the request into the required sections to ensure all aspects are covered:

* **功能 (Functionality):**  Describe what the code does at a high level.
* **与 Android 的关系 (Relationship with Android):** Explain its role in Android's security and randomness.
* **libc 函数实现 (libc Function Implementation):** Detail how `open`, `read`, and `getrandom` are used.
* **Dynamic Linker (动态链接器):** Analyze if and how the dynamic linker is involved. (Here, the answer is not directly involved in the code, but indirectly through usage of libc functions).
* **逻辑推理 (Logical Inference):** Consider the input and output scenarios.
* **常见使用错误 (Common Usage Errors):** Think about how a programmer might misuse this function.
* **Android 调用路径 (Android Call Path):** Trace how Android framework or NDK calls might reach `getentropy`.
* **Frida Hook 示例 (Frida Hook Example):**  Provide a practical debugging example.

**4. Deep Dive into Functionality and Implementation:**

* **`getentropy`:**  The core function. It prioritizes `getrandom` with `GRND_NONBLOCK`. This suggests a preference for a non-blocking approach using the kernel's entropy pool. The fallback to `/dev/urandom` is important for compatibility with older kernels or situations where `getrandom` might fail. The 256-byte limit is a significant detail.
* **`getentropy_urandom`:**  The fallback mechanism. It opens `/dev/urandom` and reads from it. The use of `TEMP_FAILURE_RETRY` is a crucial Bionic detail for handling signal interrupts safely. `ScopedFd` manages the file descriptor's lifecycle.
* **libc Functions:**
    * `open`: Used to open `/dev/urandom`. The flags `O_RDONLY`, `O_NOFOLLOW`, and `O_CLOEXEC` are important to explain.
    * `read`: Reads data from the file descriptor. The loop ensures that the requested number of bytes is read, handling potential short reads.
    * `getrandom`: The preferred method for obtaining random data. The `GRND_NONBLOCK` flag is key. Explain the possible error conditions.

**5. Addressing Specific Request Points:**

* **Android Relationship:**  Focus on security and the need for strong randomness for cryptographic operations, etc.
* **Dynamic Linker:**  Realize that while the code itself doesn't explicitly invoke the dynamic linker, it *relies* on it to load the libc and kernel system call wrappers. The SO layout explanation should cover this indirect dependency.
* **Logical Inference:**  Consider the buffer and buffer size as inputs. The output is either 0 (success) or -1 (failure with `errno` set).
* **Common Errors:**  Focus on buffer size exceeding 256, incorrect buffer pointers, and misunderstanding the blocking/non-blocking nature (though `getentropy` aims to be non-blocking primarily).
* **Android Call Path:** Think about the layers: Application -> NDK (if used) -> libc. Provide examples of functions that might indirectly call `getentropy`.
* **Frida Hook:** Craft a concise example to intercept calls to `getentropy` and inspect the arguments and return value.

**6. Structuring and Refining the Answer:**

Organize the information logically based on the decomposed request. Use clear headings and bullet points for readability. Ensure the language is precise and accurate. Translate technical terms correctly into Chinese. Provide code snippets and examples where appropriate.

**7. Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I should explain the kernel's entropy pool in detail.
* **Correction:** While relevant, it's not strictly necessary for understanding *this code*. Focus on how the code interacts with the kernel (via `getrandom` and `/dev/urandom`).
* **Initial thought:**  Should I provide all possible `errno` values?
* **Correction:** Focus on the most likely and relevant ones mentioned in the code comments.
* **Initial thought:** The dynamic linker isn't directly called.
* **Correction:**  Acknowledge its *implicit* role in loading the necessary libraries.

By following this systematic process of understanding the request, analyzing the code, planning the structure, deep-diving into the details, addressing specific points, and refining the answer, a comprehensive and accurate response can be generated. The key is to break down the problem into manageable parts and think through each aspect methodically.
好的，让我们来详细分析一下 `bionic/libc/bionic/getentropy.cpp` 这个文件。

**`getentropy.cpp` 的功能**

`getentropy.cpp` 文件实现了 `getentropy` 函数，其主要功能是**获取指定大小的、高质量的随机字节**。  这个函数旨在提供一种安全可靠的方式来获取用于加密和其他安全敏感操作的随机数据。

**与 Android 功能的关系及举例说明**

`getentropy` 是 Android Bionic 库的一部分，这意味着它是 Android 系统中应用程序可以直接调用的一个 C 标准库函数。它在 Android 的安全体系中扮演着重要的角色，因为很多安全相关的操作都需要高质量的随机数。

**举例说明：**

* **生成加密密钥：**  Android 系统或应用需要生成用于数据加密、消息认证等的密钥时，会使用像 `getentropy` 这样的函数来获取种子，以生成强壮的密钥。例如，在生成 TLS/SSL 证书、VPN 密钥、应用加密密钥时都会涉及到。
* **生成随机令牌或 Nonce：**  为了防止重放攻击或增加系统的安全性，Android 应用或系统服务可能会生成随机的令牌或 Nonce (Number used once)。`getentropy` 可以用来生成这些随机值。
* **地址空间布局随机化 (ASLR)：** 虽然 `getentropy` 本身不直接参与 ASLR 的实现，但 Android 内核或其他底层组件在初始化 ASLR 时，可能使用类似的机制（读取 `/dev/urandom` 或使用 `getrandom` 系统调用）来随机化内存布局，这与 `getentropy` 的实现原理类似。
* **`/dev/urandom` 的后端：**  `getentropy` 的实现中可以看到它会尝试使用 `getrandom` 系统调用，如果失败则会回退到读取 `/dev/urandom`。 `/dev/urandom` 在 Linux 系统中是一个重要的随机数生成器，Android 也依赖于它。

**libc 函数的实现细节**

`getentropy.cpp` 中主要涉及以下 libc 函数（以及系统调用）：

1. **`open(const char *pathname, int flags, mode_t mode)`:**
   - **功能:**  打开一个文件或设备。
   - **实现:** 在 `getentropy_urandom` 函数中，`open("/dev/urandom", O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0)` 用于打开 `/dev/urandom` 设备。
     - `"/dev/urandom"`:  要打开的文件路径，表示非阻塞的伪随机数生成器。
     - `O_RDONLY`:  以只读模式打开。
     - `O_NOFOLLOW`:  如果 `pathname` 是一个符号链接，则打开操作失败。这可以防止某些安全漏洞。
     - `O_CLOEXEC`:  在执行新程序时自动关闭这个文件描述符。这可以防止子进程意外地继承这个文件描述符，从而避免潜在的安全问题。
     - `0`:  对于打开设备文件，通常 mode 参数会被忽略。

2. **`read(int fd, void *buf, size_t count)`:**
   - **功能:** 从文件描述符 `fd` 中读取最多 `count` 个字节的数据到缓冲区 `buf` 中。
   - **实现:** 在 `getentropy_urandom` 函数的 `while` 循环中，`read(fd.get(), static_cast<char*>(buffer) + collected, buffer_size - collected)` 被用来从 `/dev/urandom` 读取随机字节到提供的 `buffer` 中。
     - `fd.get()`: 获取 `ScopedFd` 对象管理的打开的文件描述符。
     - `static_cast<char*>(buffer) + collected`:  指向缓冲区中尚未填充数据的起始位置。
     - `buffer_size - collected`:  剩余需要读取的字节数。
   - **循环读取的原因:** `read` 调用可能不会一次性读取请求的所有字节，因此需要循环调用直到读取到足够的字节。

3. **`getrandom(void *buf, size_t buflen, unsigned int flags)` (系统调用)**
   - **功能:** 从内核的随机数池中获取随机字节。这是获取高质量随机数的首选方法。
   - **实现:** 在 `getentropy` 函数中，`TEMP_FAILURE_RETRY(getrandom(static_cast<char*>(buffer) + collected, buffer_size - collected, GRND_NONBLOCK))` 尝试使用 `getrandom` 系统调用。
     - `static_cast<char*>(buffer) + collected`: 指向缓冲区中尚未填充数据的起始位置。
     - `buffer_size - collected`: 剩余需要读取的字节数。
     - `GRND_NONBLOCK`:  如果内核熵池中没有足够的熵，调用不会阻塞，而是立即返回 `EAGAIN` 错误。
   - **错误处理:** 如果 `getrandom` 返回错误（例如 `EAGAIN`, `ENOSYS`, `EINVAL`, `EFAULT`），`getentropy` 会回退到使用 `/dev/urandom`。
     - `EAGAIN`:  表示当前没有足够的熵可用，稍后重试可能成功。
     - `ENOSYS`:  表示系统不支持 `getrandom` 系统调用。
     - `EINVAL`:  表示 `flags` 参数无效。
     - `EFAULT`:  表示 `buffer` 指针指向无效的内存地址。

4. **`TEMP_FAILURE_RETRY(syscall)` 宏:**
   - **功能:**  用于安全地调用可能被信号中断的系统调用。如果系统调用返回 `-1` 并且 `errno` 设置为 `EINTR` (被信号中断)，则会重新执行系统调用。
   - **实现:** 这是一个 Bionic 提供的宏，用于处理由信号引起的临时性失败，确保程序在接收到信号后能够继续正常执行。

5. **`ScopedFd` 类:**
   - **功能:**  一个 RAII (Resource Acquisition Is Initialization) 风格的类，用于自动管理文件描述符的生命周期。当 `ScopedFd` 对象超出作用域时，其析构函数会自动调用 `close()` 关闭关联的文件描述符，避免资源泄露。
   - **实现:**  `ScopedFd fd(...)` 创建一个 `ScopedFd` 对象，其构造函数会尝试打开文件。当 `fd` 不再使用时，其析构函数会自动关闭打开的文件描述符。

**动态链接器的功能以及 SO 布局样本和链接处理过程**

在这个特定的 `getentropy.cpp` 文件中，**并没有直接涉及动态链接器的操作**。  `getentropy` 的实现主要依赖于内核提供的系统调用 (`getrandom`) 和文件操作 (`open`, `read`)。

**间接关联：**

尽管如此，`getentropy` 函数本身是 `libc.so` (Android 的 C 库) 的一部分。动态链接器 (linker，通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 负责在程序启动时加载 `libc.so`，并将程序中对 `getentropy` 的调用链接到 `libc.so` 中对应的函数实现。

**SO 布局样本 (简化):**

```
libc.so:
    地址范围: 0xb7000000 - 0xb7ffffff
    .text (代码段):
        getentropy 函数的代码位于此段
        ...其他 libc 函数的代码...
    .data (数据段):
        全局变量
        ...
    .rodata (只读数据段):
        字符串常量
        ...
    .dynsym (动态符号表):
        包含 getentropy 等导出符号的信息
    .plt (过程链接表):
        用于延迟绑定的条目

应用程序 (APK 进程):
    地址范围: 0xb6000000 - 0xb6ffffff
    .text (代码段):
        main 函数
        调用 getentropy 的代码
        ...
    .plt (过程链接表):
        getentropy@plt 条目
```

**链接处理过程 (简述)：**

1. **编译时链接:**  当应用程序的代码被编译和链接时，如果它调用了 `getentropy`，链接器会记录下对 `getentropy` 的外部引用。
2. **运行时加载:**  当应用程序启动时，Android 的动态链接器会执行以下操作：
   - 加载应用程序本身。
   - 根据应用程序的依赖关系，加载所需的共享库，例如 `libc.so`。
   - **符号解析 (Symbol Resolution):**  动态链接器会查找应用程序中对外部符号（如 `getentropy`) 的引用，并在已加载的共享库中找到对应的符号定义。
   - **重定位 (Relocation):**  动态链接器会更新应用程序代码中的地址，将对 `getentropy@plt` 的调用指向 `libc.so` 中 `getentropy` 函数的实际地址。  这个过程可能使用延迟绑定 (lazy binding)，即第一次调用 `getentropy` 时才进行解析和重定位。

**逻辑推理、假设输入与输出**

**假设输入：**

* `buffer`: 指向一块大小为 128 字节的内存区域的指针。
* `buffer_size`: 128。

**逻辑推理：**

1. `getentropy(buffer, buffer_size)` 被调用。
2. `buffer_size` (128) 小于 256，所以不会立即返回错误。
3. `getentropy` 尝试调用 `getrandom` 系统调用，请求 128 字节的随机数据，并设置 `GRND_NONBLOCK` 标志。
4. **情况 1 (成功):** 如果内核熵池中有足够的熵，`getrandom` 成功返回，`count` 等于 128。`collected` 变为 128，循环结束。`errno` 恢复，函数返回 0。`buffer` 中会被填充 128 字节的随机数据。
5. **情况 2 (失败 - EAGAIN):** 如果内核熵池中没有足够的熵，`getrandom` 返回 -1，并且 `errno` 设置为 `EAGAIN`。
6. **回退到 `/dev/urandom`:** `getentropy` 调用 `getentropy_urandom(buffer, buffer_size, saved_errno)`。
7. **`getentropy_urandom`:**
   - 打开 `/dev/urandom`。
   - 进入 `while` 循环，尝试读取 128 字节。
   - `read` 调用会从 `/dev/urandom` 读取数据，可能需要多次循环才能读取到 128 字节。
   - 读取完成后，`errno` 恢复，`getentropy_urandom` 返回 0。
8. **`getentropy` 返回 0，`buffer` 中会被填充 128 字节的随机数据（由 `/dev/urandom` 生成）。**

**假设输入：**

* `buffer`: 指向一块大小为 512 字节的内存区域的指针。
* `buffer_size`: 512。

**逻辑推理：**

1. `getentropy(buffer, buffer_size)` 被调用。
2. `buffer_size` (512) 大于 256。
3. `getentropy` 函数立即设置 `errno` 为 `EIO` 并返回 -1。

**输出：**

* 返回值: -1
* `errno`: `EIO`

**用户或编程常见的使用错误**

1. **缓冲区大小超过 256 字节:**  这是最直接的错误。如果用户尝试请求超过 256 字节的随机数据，`getentropy` 会返回错误。
   ```c++
   char buf[512];
   if (getentropy(buf, sizeof(buf)) != 0) {
       perror("getentropy failed"); // 输出 "getentropy failed: Input/output error"
   }
   ```
2. **传递空指针或无效的缓冲区指针:**  如果 `buffer` 是 `nullptr` 或指向无效的内存区域，`getrandom` 系统调用会返回 `EFAULT`，导致回退到 `/dev/urandom`。虽然能工作，但应该避免传递无效指针。
   ```c++
   char *buf = nullptr;
   if (getentropy(buf, 128) != 0) {
       perror("getentropy failed"); // 可能不会直接报错，而是走到 /dev/urandom 流程
   }
   ```
3. **不检查返回值:**  和所有可能失败的函数一样，应该检查 `getentropy` 的返回值以确定是否成功获取了随机数据。
   ```c++
   char buf[128];
   getentropy(buf, sizeof(buf)); // 如果失败了，buf 中的数据是未定义的
   // 应该检查返回值
   if (getentropy(buf, sizeof(buf)) != 0) {
       // 处理错误
   } else {
       // 使用 buf 中的随机数据
   }
   ```
4. **误解 `getentropy` 的阻塞特性:** 虽然 `getentropy` 内部优先使用 `getrandom` 的非阻塞模式，但如果回退到 `/dev/urandom`，`read` 调用可能会阻塞，尽管这种情况在现代 Android 系统上不太可能发生。

**Android Framework 或 NDK 如何到达这里**

`getentropy` 是一个标准的 C 库函数，可以通过多种方式被 Android Framework 或 NDK 调用：

**从 NDK (Native Development Kit) 调用：**

1. **C/C++ 代码直接调用:**  使用 NDK 开发的 Native 代码可以直接调用 `getentropy` 函数。
   ```c++
   #include <unistd.h>
   #include <sys/random.h>
   #include <stdio.h>

   int main() {
       char buffer[32];
       if (getentropy(buffer, sizeof(buffer)) == 0) {
           printf("Got random data!\n");
       } else {
           perror("getentropy failed");
       }
       return 0;
   }
   ```

**从 Android Framework 调用 (通过 JNI 或其他 Native 组件):**

1. **Java Framework 调用 Native 方法:**  Android Framework 中某些安全相关的 Java 类可能会通过 JNI (Java Native Interface) 调用 Native 代码，而这些 Native 代码可能会使用 `getentropy`。例如，`java.security.SecureRandom` 的某些实现可能会使用底层的 Native 随机数生成器。
2. **系统服务和守护进程:**  Android 系统服务（如 `keystore` 服务）和守护进程（如 `vold`）是用 C/C++ 编写的，它们可能会直接调用 `getentropy` 来获取随机数。
3. **Bionic 库的其他部分:**  `libc` 库中的其他函数，特别是与安全和加密相关的函数，可能会在内部调用 `getentropy` 或使用类似的机制来获取随机数。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 调试 `getentropy` 函数的示例：

**假设场景：**  你想观察某个 Android 应用调用 `getentropy` 时传入的参数和返回值。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, 'libc.so'); // 找到 libc.so 模块
  if (libc) {
    const getentropyPtr = Module.findExportByName(libc.name, 'getentropy');
    if (getentropyPtr) {
      Interceptor.attach(getentropyPtr, {
        onEnter: function (args) {
          const buffer = args[0];
          const bufferSize = args[1].toInt();
          console.log('[getentropy] Called');
          console.log('[getentropy] Buffer: ' + buffer);
          console.log('[getentropy] Buffer Size: ' + bufferSize);
          // 可以读取 buffer 的内容 (如果 buffer 指向的内存是可读的)
          // console.log('[getentropy] Buffer Content: ' + hexdump(buffer.readByteArray(bufferSize)));
        },
        onLeave: function (retval) {
          console.log('[getentropy] Return Value: ' + retval);
          if (retval.toInt() === 0) {
            console.log('[getentropy] Success!');
          } else {
            const lastError = Process.getModuleByName('libc.so').getExportByName('errno').readS32();
            console.log('[getentropy] Failed, errno: ' + lastError);
          }
        }
      });
      console.log('[+] getentropy hooked!');
    } else {
      console.log('[-] getentropy not found in libc.so');
    }
  } else {
    console.log('[-] libc.so not found');
  }
} else {
  console.log('[-] This script is for Android.');
}
```

**调试步骤：**

1. **安装 Frida 和 frida-tools:** 确保你的电脑上安装了 Frida 和 frida-tools。
2. **连接到 Android 设备/模拟器:**  确保你的 Android 设备或模拟器已连接，并且 Frida 服务正在运行。
3. **确定目标进程:**  找到你想监控的应用的进程名或进程 ID。
4. **运行 Frida Hook 脚本:**  使用 `frida` 命令运行上面的 JavaScript 脚本，替换 `目标进程` 为实际的进程名或进程 ID。
   ```bash
   frida -U -f <目标应用包名> -l your_script.js --no-pause
   # 或者如果已知进程 ID
   frida -U <进程ID> -l your_script.js
   ```
5. **触发 `getentropy` 调用:**  在目标应用中执行某些操作，这些操作可能会导致调用 `getentropy` 函数。例如，某些加密操作、随机数生成等。
6. **查看 Frida 输出:**  Frida 会在控制台上输出 `getentropy` 被调用时的参数（缓冲区地址、大小）和返回值。如果调用失败，还会输出 `errno` 的值。

**Frida Hook 输出示例：**

```
[Pixel 6::目标应用包名]-> [+] getentropy hooked!
[Pixel 6::目标应用包名]-> [getentropy] Called
[Pixel 6::目标应用包名]-> [getentropy] Buffer: NativePointer("0xb4000078d0")
[Pixel 6::目标应用包名]-> [getentropy] Buffer Size: 32
[Pixel 6::目标应用包名]-> [getentropy] Return Value: 0
[Pixel 6::目标应用包名]-> [getentropy] Success!
```

这个例子展示了如何使用 Frida Hook 拦截对 `getentropy` 的调用，并查看其参数和返回值，从而帮助你理解程序是如何使用这个函数的。

希望以上详细的分析能够帮助你理解 `bionic/libc/bionic/getentropy.cpp` 文件的功能和实现细节。

### 提示词
```
这是目录为bionic/libc/bionic/getentropy.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

#include "private/ScopedFd.h"

static int getentropy_urandom(void* buffer, size_t buffer_size, int saved_errno) {
  ScopedFd fd(TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0)));
  if (fd.get() == -1) return -1;

  size_t collected = 0;
  while (collected < buffer_size) {
    ssize_t count = TEMP_FAILURE_RETRY(read(fd.get(), static_cast<char*>(buffer) + collected,
                                            buffer_size - collected));
    if (count == -1) return -1;
    collected += count;
  }

  errno = saved_errno;
  return 0;
}

int getentropy(void* buffer, size_t buffer_size) {
  if (buffer_size > 256) {
    errno = EIO;
    return -1;
  }

  int saved_errno = errno;

  size_t collected = 0;
  while (collected < buffer_size) {
    long count = TEMP_FAILURE_RETRY(getrandom(static_cast<char*>(buffer) + collected,
                                              buffer_size - collected, GRND_NONBLOCK));
    if (count == -1) {
      // EAGAIN: there isn't enough entropy right now.
      // ENOSYS/EINVAL: getrandom(2) or GRND_NONBLOCK isn't supported.
      // EFAULT: `buffer` is invalid.
      // Try /dev/urandom regardless because it can't hurt,
      // and we don't need to optimize the EFAULT case.
      // See http://b/33059407 and http://b/67015565.
      return getentropy_urandom(buffer, buffer_size, saved_errno);
    }
    collected += count;
  }

  errno = saved_errno;
  return 0;
}
```
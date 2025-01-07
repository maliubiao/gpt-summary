Response:
Let's break down the thought process for answering this complex question about `bionic/libc/include/sys/endian.handroid`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file related to endianness in Android's Bionic library. The request asks for:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it tie into Android's operation?
* **Detailed Explanation:**  How are the functions implemented?
* **Dynamic Linking:**  If applicable, how does it relate to the dynamic linker? (This requires recognizing the absence of dynamic linking *within this specific file* but understanding the broader context.)
* **Logic/Examples:** Illustrative examples of usage and potential pitfalls.
* **Android Framework/NDK Tracing:** How does code reach this file, and how can it be debugged?

**2. Initial Analysis of the Code:**

* **Header Guards:** `#ifndef _SYS_ENDIAN_H_`... Standard practice to prevent multiple inclusions.
* **Includes:** `<sys/cdefs.h>`, `<stdint.h>`. These provide compiler definitions and standard integer types, respectively. Crucial for low-level system programming.
* **Endian Definitions:** `_LITTLE_ENDIAN`, `_BIG_ENDIAN`, `_PDP_ENDIAN`, `_BYTE_ORDER`. This is the core purpose of the file – defining byte order. The `_BYTE_ORDER _LITTLE_ENDIAN` strongly suggests Android's primary architecture is little-endian.
* **Bitfield Definition:** `__LITTLE_ENDIAN_BITFIELD`. Indicates how bitfields are laid out in memory.
* **Built-in Byte Swapping Macros:** `__swap16`, `__swap32`, `__swap64`. These are compiler intrinsics for efficient byte order reversal.
* **`htonl`, `htons`, `ntohl`, `ntohs`:**  Standard network byte order conversion functions. The `__attribute_const__` indicates these functions have no side effects and their return value depends only on their input.
* **Macros using `__swap`:** The actual implementation of `htonl`, `htons`, etc., using the built-in swap functions.
* **Bionic Additions:** `htonq`, `ntohq` – likely for 64-bit network byte order conversions.
* **BSD Compatibility:** `LITTLE_ENDIAN`, `BIG_ENDIAN`, etc. Providing compatibility with BSD-style definitions.
* **Macros with Assignment:** `NTOHL(x) = ...`. These modify the input variable in place, which is a slightly less common but valid pattern.
* **Endian-Specific Macros:** `htobe16`, `betoh16`, `htole16`, `letoh16`, etc. These provide explicit conversions to big-endian and little-endian, independent of the host architecture. The `htole` and `letoh` being no-ops reinforces that Android is little-endian.
* **Glibc Compatibility:** `be16toh`, `le16toh`, etc. Aliases for the `htobe` and `htole` functions, providing compatibility with the GNU C library.

**3. Structuring the Answer:**

Based on the analysis, I would structure the answer to address each part of the request systematically.

* **功能 (Functionality):** Start with the main purpose – defining endianness and providing byte order conversion functions.
* **与 Android 的关系 (Android Relevance):** Explain why endianness matters for interoperability and how Android's little-endian nature influences this.
* **libc 函数的实现 (libc Function Implementation):** Detail how the `htonl`, `htons`, etc., functions are implemented using the built-in swap functions. Emphasize the efficiency of these intrinsics.
* **Dynamic Linker:**  Recognize that this *specific* file doesn't directly involve the dynamic linker. However, explain how *other* parts of libc that use these definitions will be linked. Provide a basic example of an SO layout and the linking process.
* **逻辑推理 (Logic/Examples):** Create simple code snippets demonstrating how to use the conversion functions and highlight potential errors (e.g., incorrect function choice).
* **Android Framework/NDK 路径 (Android Framework/NDK Path):** Describe the chain of events from Java/Kotlin code, through the NDK, down to the libc level. Provide a concrete example like network communication.
* **Frida Hook 示例 (Frida Hook Example):** Show how to use Frida to intercept the byte-swapping functions and observe the data transformation. This demonstrates a powerful debugging technique.

**4. Refining the Details:**

* **Clarity and Precision:** Use precise terminology (e.g., "host byte order," "network byte order").
* **Code Examples:** Provide clear and concise code examples.
* **Assumptions:** Explicitly state any assumptions made (e.g., Android is primarily little-endian).
* **Error Handling:** Focus on common errors related to byte order issues.
* **Dynamic Linking Explanation:** Keep the dynamic linking explanation at a high level, focusing on how symbols are resolved. Avoid getting bogged down in the intricate details of the linker.

**5. Iterative Refinement (Self-Correction):**

* **Initial Draft Might Be Too Technical:**  Realize that the audience might have varying levels of understanding. Simplify explanations where needed.
* **Missing Examples:** Ensure each point is illustrated with a practical example.
* **Lack of Connection:**  Ensure the connection between the code and Android's overall architecture is clear.
* **Frida Example Too Complex:**  Simplify the Frida script to focus on the core concept of function hooking.

By following this thought process, breaking down the request, analyzing the code, structuring the answer, and iteratively refining it, you can arrive at a comprehensive and accurate response like the example provided. The key is to be systematic and address each aspect of the prompt thoroughly.
这是一个定义字节序（Endianness）相关的宏和函数的头文件，用于 Bionic C 库。它定义了不同的字节序类型，并提供了一组用于在不同字节序之间转换数据的函数。

**它的功能：**

1. **定义字节序常量:**
   - `_LITTLE_ENDIAN`: 定义小端字节序的常量，值为 1234。
   - `_BIG_ENDIAN`: 定义大端字节序的常量，值为 4321。
   - `_PDP_ENDIAN`: 定义 PDP 字节序的常量，值为 3412（历史用途）。
   - `_BYTE_ORDER`: 定义当前系统的字节序，这里被定义为 `_LITTLE_ENDIAN`，表明 Android 设备通常是小端字节序。

2. **提供字节序宏:**
   - `__LITTLE_ENDIAN_BITFIELD`:  可能用于指示位域在小端系统中的存储方式。
   - `__LITTLE_ENDIAN` 和 `__BIG_ENDIAN`: 提供与上述常量相同的定义。
   - `__BYTE_ORDER`: 提供当前系统字节序的定义。

3. **提供内置的字节交换函数宏:**
   - `__swap16(x)`: 用于交换 16 位整数的字节顺序。
   - `__swap32(x)`: 用于交换 32 位整数的字节顺序。
   - `__swap64(x)`: 用于交换 64 位整数的字节顺序。 这些通常是编译器提供的内置函数，性能很高。

4. **提供与 glibc 兼容的网络字节序转换函数:**
   - `htonl(uint32_t __x)`: 将 32 位主机字节序转换为网络字节序（大端）。
   - `htons(uint16_t __x)`: 将 16 位主机字节序转换为网络字节序（大端）。
   - `ntohl(uint32_t __x)`: 将 32 位网络字节序转换为主机字节序。
   - `ntohs(uint16_t __x)`: 将 16 位网络字节序转换为主机字节序。

5. **提供 Bionic 特有的字节序转换函数:**
   - `htonq(x)`: 将 64 位主机字节序转换为网络字节序（大端）。
   - `ntohq(x)`: 将 64 位网络字节序转换为主机字节序。

6. **提供与 BSD 兼容的字节序宏和转换函数:**
   - `LITTLE_ENDIAN`, `BIG_ENDIAN`, `PDP_ENDIAN`, `BYTE_ORDER`:  提供与 BSD 系统兼容的字节序宏。
   - `NTOHL(x)`, `NTOHS(x)`, `HTONL(x)`, `HTONS(x)`:  提供与 BSD 系统兼容的宏，用于原地转换字节序。

7. **提供显式的大小端转换函数:**
   - `htobe16(x)`, `htobe32(x)`, `htobe64(x)`: 将主机字节序转换为大端字节序。
   - `betoh16(x)`, `betoh32(x)`, `betoh64(x)`: 将大端字节序转换为主机字节序。
   - `htole16(x)`, `htole32(x)`, `htole64(x)`: 将主机字节序转换为小端字节序（在小端系统中，这些是空操作）。
   - `letoh16(x)`, `letoh32(x)`, `letoh64(x)`: 将小端字节序转换为主机字节序（在小端系统中，这些是空操作）。

8. **提供与 glibc 兼容的别名:**
   - `be16toh(x)`, `be32toh(x)`, `be64toh(x)`: `htobe16`, `htobe32`, `htobe64` 的别名。
   - `le16toh(x)`, `le32toh(x)`, `le64toh(x)`: `htole16`, `htole32`, `htole64` 的别名。

**它与 Android 的功能关系及举例说明：**

Android 系统主要运行在 ARM 架构的处理器上，而 ARM 架构通常是小端字节序。这个头文件的定义反映了这一点，`_BYTE_ORDER` 被定义为 `_LITTLE_ENDIAN`。

**例子：网络编程**

在网络编程中，数据在传输时通常使用大端字节序（网络字节序）。如果 Android 应用程序需要与使用不同字节序的系统进行网络通信，就需要进行字节序的转换。

例如，假设一个 Android 应用需要从一个使用大端字节序的服务器接收一个 32 位整数：

```c
#include <sys/endian.h>
#include <stdio.h>

int main() {
  uint32_t network_value = 0x12345678; // 假设从网络接收到的数据是大端
  uint32_t host_value = ntohl(network_value); // 将网络字节序转换为本地主机字节序

  printf("Network value (big-endian): 0x%X\n", network_value);
  printf("Host value (little-endian): 0x%X\n", host_value); // 在小端 Android 上会打印 0x78563412

  return 0;
}
```

在这个例子中，`ntohl()` 函数会将大端字节序的 `network_value` 转换为 Android 设备的本地小端字节序。

**详细解释每一个 libc 函数的功能是如何实现的：**

- **`__swap16(x)`，`__swap32(x)`，`__swap64(x)`:** 这些通常是编译器内置函数（built-in functions 或 intrinsics）。编译器会直接生成高效的指令来交换字节顺序，例如使用汇编指令 `bswap` (byte swap)。

- **`htonl(uint32_t __x)`:**
  ```c
  #define htonl(x) __swap32(x)
  ```
  在 Android 的 Bionic 库中，`htonl` 简单地调用了 `__swap32`，因为 Android 是小端字节序，而网络字节序是大端，所以交换字节顺序即可实现转换。

- **`htons(uint16_t __x)`:**
  ```c
  #define htons(x) __swap16(x)
  ```
  与 `htonl` 类似，`htons` 调用 `__swap16` 来转换 16 位整数的字节序。

- **`ntohl(uint32_t __x)`:**
  ```c
  #define ntohl(x) __swap32(x)
  ```
  `ntohl` 也调用 `__swap32`。因为从网络字节序（大端）转换为主机字节序（小端）也是通过交换字节顺序实现的。

- **`ntohs(uint16_t __x)`:**
  ```c
  #define ntohs(x) __swap16(x)
  ```
  `ntohs` 调用 `__swap16` 来转换 16 位整数的字节序。

- **`htonq(x)` 和 `ntohq(x)`:**
  ```c
  #define htonq(x) __swap64(x)
  #define ntohq(x) __swap64(x)
  ```
  这两个函数分别用于 64 位整数的主机字节序到网络字节序以及网络字节序到主机字节序的转换，同样是通过调用 `__swap64` 来实现字节交换。

- **`HTONL(x)` 等宏:**
  ```c
  #define	HTONL(x) (x) = htonl(__BIONIC_CAST(static_cast,u_int32_t,(x)))
  ```
  这些宏不仅执行字节序转换，还将结果赋值回原始变量 `x`。`__BIONIC_CAST` 用于进行类型转换。

- **`htobe16(x)` 等:**
  ```c
  #define htobe16(x) __swap16(x)
  #define htole16(x) (x)
  ```
  `htobe` 系列函数将主机字节序转换为大端字节序，对于小端系统，这通过字节交换实现。`htole` 系列函数将主机字节序转换为小端字节序，在小端系统中，这实际上是一个空操作，因为已经是小端。

- **`betoh16(x)` 等:**
  ```c
  #define betoh16(x) __swap16(x)
  #define letoh16(x) (x)
  ```
  `betoh` 系列函数将大端字节序转换为主机字节序，在小端系统中需要字节交换。`letoh` 系列函数将小端字节序转换为主机字节序，在小端系统中是空操作。

**对于涉及 dynamic linker 的功能：**

这个头文件本身不直接涉及 dynamic linker 的功能。它定义的是一些常量和内联函数或宏，这些定义会被其他需要进行字节序转换的代码使用。这些代码最终会被编译成目标文件，然后 dynamic linker 在程序运行时负责将这些目标文件链接在一起，并解析符号引用。

**SO 布局样本和链接的处理过程：**

假设有一个名为 `libnetwork.so` 的共享库，其中使用了 `htonl` 函数。

**`libnetwork.so` 的布局样本：**

```
libnetwork.so:
  .text         # 包含代码段
    ...
    call    htonl  # 调用 htonl 函数
    ...
  .rodata       # 包含只读数据
    ...
  .data         # 包含可读写数据
    ...
  .dynsym       # 动态符号表
    ...
    htonl (UND)  # 表明需要链接器解析 htonl 符号
    ...
  .dynstr       # 动态字符串表
    ...
    htonl
    ...
  .plt          # 程序链接表 (Procedure Linkage Table)
    ...
  .got          # 全局偏移表 (Global Offset Table)
    ...
```

**链接的处理过程：**

1. **编译时链接：** 当 `libnetwork.so` 被编译时，编译器看到对 `htonl` 的调用，但 `htonl` 的定义在 `libc.so` 中。因此，在 `libnetwork.so` 的动态符号表中会记录一个未定义的符号 `htonl`。

2. **加载时链接（Dynamic Linking）：** 当 Android 应用程序加载 `libnetwork.so` 时，dynamic linker（例如 `linker64` 或 `linker`）会执行以下步骤：
   - 加载 `libnetwork.so` 到内存。
   - 扫描 `libnetwork.so` 的依赖项，通常是 `libc.so`。
   - 加载 `libc.so` 到内存。
   - 解析 `libnetwork.so` 中未定义的符号。linker 会在 `libc.so` 的动态符号表中查找 `htonl` 的定义。
   - 一旦找到 `htonl` 的定义，linker 会更新 `libnetwork.so` 的全局偏移表（GOT）。对于 `htonl` 的调用，GOT 中会存储 `htonl` 函数在 `libc.so` 中的实际地址。
   - 当程序执行到调用 `htonl` 的指令时，它会通过 GOT 跳转到 `htonl` 的实际代码位置。

**假设输入与输出 (对于字节序转换函数)：**

**`htonl` 假设：**

- **输入：** `uint32_t x = 0x12345678;` (小端主机字节序)
- **输出：** `0x78563412` (大端网络字节序)

**`ntohl` 假设：**

- **输入：** `uint32_t x = 0x78563412;` (大端网络字节序)
- **输出：** `0x12345678` (小端主机字节序)

**用户或编程常见的使用错误：**

1. **在不需要转换的时候进行转换：**  例如，在本地内存操作时错误地使用了字节序转换函数。

   ```c
   uint32_t value = 0x12345678;
   uint32_t wrong_value = htonl(value); // 错误地转换了本地变量
   ```

2. **在应该转换的时候忘记转换：**  例如，在网络编程中发送数据前忘记将主机字节序转换为网络字节序，或者接收数据后忘记从网络字节序转换为主机字节序。

   ```c
   // 发送数据
   uint16_t port = 8080;
   send(sockfd, &port, sizeof(port), 0); // 错误：应该发送 htons(port)

   // 接收数据
   uint32_t received_value;
   recv(sockfd, &received_value, sizeof(received_value), 0);
   // 错误：应该使用 ntohl(received_value)
   ```

3. **对数据结构进行整体的字节序转换：**  有时开发者会尝试对包含多个字段的结构体直接进行字节序转换，这通常是错误的，因为需要针对每个需要转换的字段进行操作。

   ```c
   struct Packet {
       uint16_t id;
       uint32_t sequence;
   };

   struct Packet pkt;
   pkt.id = 1;
   pkt.sequence = 100;

   // 错误的做法：
   // struct Packet network_pkt;
   // network_pkt.id = htons(pkt.id);
   // network_pkt.sequence = htonl(pkt.sequence);
   ```

4. **混淆不同类型的转换函数：**  例如，错误地使用 `htobe` 系列函数代替 `htonl`。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Java/Kotlin 代码发起网络请求 (Android Framework)：**
   - Android 应用的 Java 或 Kotlin 代码使用 `java.net` 包中的类（例如 `Socket`, `URLConnection`）或更高级的网络库（例如 `OkHttp`, `Retrofit`）发起网络请求。

2. **Framework 调用 Native 代码 (Android Framework)：**
   - 这些 Java/Kotlin 网络类最终会调用底层的 Native 代码，通常通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 中的 Native 方法。

3. **Native 代码调用 Bionic libc 函数 (NDK)：**
   - ART 或其他 Native 组件中的网络相关代码（例如在 `/system/lib64/libnetd_client.so` 或 `libnativehelper.so` 中）会调用 Bionic libc 提供的网络函数，例如 `connect`, `send`, `recv`。

4. **网络函数内部使用字节序转换函数 (Bionic libc)：**
   - 在 `send` 函数内部，如果发送的数据涉及到多字节的数值，就需要考虑字节序问题。例如，如果需要发送端口号或 IP 地址，可能会调用 `htons` 或 `htonl`。

**Frida Hook 示例：**

假设我们想 hook `htons` 函数，观察其输入和输出：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

session = frida.attach('com.example.myapp') # 替换为你的应用包名

script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "htons"), {
  onEnter: function(args) {
    console.log("[htons] Input: " + args[0].toInt());
  },
  onLeave: function(retval) {
    console.log("[htons] Output: " + retval.toInt());
  }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释：**

1. **`frida.attach('com.example.myapp')`**: 连接到目标 Android 应用程序。
2. **`Module.findExportByName("libc.so", "htons")`**: 找到 `libc.so` 中导出的 `htons` 函数的地址。
3. **`Interceptor.attach(...)`**: 拦截 `htons` 函数的调用。
4. **`onEnter`**: 在 `htons` 函数调用之前执行，打印输入参数（主机字节序的 16 位整数）。
5. **`onLeave`**: 在 `htons` 函数调用之后执行，打印返回值（网络字节序的 16 位整数）。

**运行 Frida 脚本：**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. 将上述 Python 脚本保存为 `hook_htons.py`。
3. 启动你的目标 Android 应用程序。
4. 在 PC 上运行 `python3 hook_htons.py`。
5. 在 Android 应用中执行触发网络操作的功能。
6. 你将在 Frida 的输出中看到 `htons` 函数的输入和输出值，从而验证字节序转换是否按预期进行。

通过这个 Frida hook 示例，你可以观察到当 Android framework 或 NDK 中的代码进行网络操作时，是如何一步步地调用到 Bionic libc 中的字节序转换函数的。

Prompt: 
```
这是目录为bionic/libc/include/sys/endian.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (c) 1997 Niklas Hallqvist.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_ENDIAN_H_
#define _SYS_ENDIAN_H_

#include <sys/cdefs.h>

#include <stdint.h>

#define _LITTLE_ENDIAN	1234
#define _BIG_ENDIAN	4321
#define _PDP_ENDIAN	3412
#define _BYTE_ORDER _LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#endif
#define __BYTE_ORDER _BYTE_ORDER

#define __swap16 __builtin_bswap16
#define __swap32 __builtin_bswap32
#define __swap64(x) __BIONIC_CAST(static_cast,uint64_t,__builtin_bswap64(x))

/* glibc compatibility. */
__BEGIN_DECLS
uint32_t htonl(uint32_t __x) __attribute_const__;
uint16_t htons(uint16_t __x) __attribute_const__;
uint32_t ntohl(uint32_t __x) __attribute_const__;
uint16_t ntohs(uint16_t __x) __attribute_const__;
__END_DECLS

#define htonl(x) __swap32(x)
#define htons(x) __swap16(x)
#define ntohl(x) __swap32(x)
#define ntohs(x) __swap16(x)

/* Bionic additions */
#define htonq(x) __swap64(x)
#define ntohq(x) __swap64(x)

#if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
#define LITTLE_ENDIAN _LITTLE_ENDIAN
#define BIG_ENDIAN _BIG_ENDIAN
#define PDP_ENDIAN _PDP_ENDIAN
#define BYTE_ORDER _BYTE_ORDER

#define	NTOHL(x) (x) = ntohl(__BIONIC_CAST(static_cast,u_int32_t,(x)))
#define	NTOHS(x) (x) = ntohs(__BIONIC_CAST(static_cast,u_int16_t,(x)))
#define	HTONL(x) (x) = htonl(__BIONIC_CAST(static_cast,u_int32_t,(x)))
#define	HTONS(x) (x) = htons(__BIONIC_CAST(static_cast,u_int16_t,(x)))

#define htobe16(x) __swap16(x)
#define htobe32(x) __swap32(x)
#define htobe64(x) __swap64(x)
#define betoh16(x) __swap16(x)
#define betoh32(x) __swap32(x)
#define betoh64(x) __swap64(x)

#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define letoh16(x) (x)
#define letoh32(x) (x)
#define letoh64(x) (x)

/*
 * glibc-compatible beXXtoh/leXXtoh synonyms for htobeXX/htoleXX.
 * The BSDs export both sets of names, bionic historically only
 * exported the ones above (or on the rhs here), and glibc only
 * exports these names (on the lhs).
 */
#define be16toh(x) htobe16(x)
#define be32toh(x) htobe32(x)
#define be64toh(x) htobe64(x)
#define le16toh(x) htole16(x)
#define le32toh(x) htole32(x)
#define le64toh(x) htole64(x)

#endif

#endif

"""

```
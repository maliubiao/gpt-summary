Response:
Let's break down the thought process for answering the user's request about `inet_ntop.c`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of the `inet_ntop.c` file, specifically within the Android Bionic context. This includes:

* Functionality description.
* Android-specific relevance and examples.
* Detailed explanation of each function's implementation.
* Handling of dynamic linking (if applicable).
* Logic reasoning with examples.
* Common usage errors.
* How Android Framework/NDK leads to this code, including Frida hooking.

**2. Initial Code Analysis and Functional Breakdown:**

First, read through the code to get a general understanding. Identify the key functions: `inet_ntop`, `inet_ntop4`, and `inet_ntop6`. Recognize that `inet_ntop` acts as a dispatcher based on the address family. `inet_ntop4` handles IPv4, and `inet_ntop6` handles IPv6.

* **`inet_ntop`:**  Dispatches to the correct function based on `af` (address family). Handles error for unsupported address families.
* **`inet_ntop4`:** Converts a 4-byte IPv4 address to a string representation (e.g., "192.168.1.1"). Uses `snprintf` for formatting and `strlcpy` for safe copying. Error handling for buffer overflow.
* **`inet_ntop6`:**  More complex. Converts a 16-byte IPv6 address to its string representation (e.g., "2001:db8::1"). Includes logic for compressing consecutive zero blocks ("::"). Handles embedded IPv4 addresses.

**3. Addressing Specific User Questions:**

Now, systematically address each part of the user's request:

* **Functionality:** Summarize the core purpose: converting network address structures to human-readable strings.

* **Android Relevance and Examples:**  Think about where IP address conversion is needed in Android. Network communication is the key. Examples include:
    * Displaying server addresses in network settings.
    * Logging network activity.
    * NDK network programming.

* **Detailed Function Implementation:**  Go through each function line by line, explaining what it does. Focus on:
    * Input parameters and their types.
    * Local variables and their purpose.
    * Key function calls (`snprintf`, `strlcpy`, `memset`).
    * Logic flow (e.g., the IPv6 zero compression algorithm).
    * Error handling (`errno`, return values).

* **Dynamic Linking:**  Recognize the `DEF_WEAK(inet_ntop)` macro. Explain what weak symbols are and how the dynamic linker handles them (allowing overrides). Create a simplified SO layout example showing the weak symbol in `libc.so`. Describe the linking process: during linking, if another object defines `inet_ntop`, that definition is preferred. Otherwise, the weak definition from `libc.so` is used.

* **Logic Reasoning (Hypothetical Input/Output):** Provide simple examples for both IPv4 and IPv6 to illustrate the conversion. Include cases with and without IPv6 zero compression.

* **Common Usage Errors:** Focus on the `size` parameter. Explain the consequences of providing an undersized buffer and how the functions handle it (setting `errno` to `ENOSPC`). Give a code example demonstrating this error.

* **Android Framework/NDK and Frida Hooking:**  Trace the call path from higher levels. Start with an Activity using `java.net.InetAddress`. Show how this eventually calls native code through JNI. Mention NDK usage directly. Provide a basic Frida hook example targeting `inet_ntop` to demonstrate interception and argument/return value manipulation.

**4. Structuring the Answer:**

Organize the information logically, following the user's question structure. Use clear headings and formatting for readability.

**5. Language and Tone:**

Use clear and concise Chinese. Explain technical terms where necessary. Maintain a helpful and informative tone.

**Self-Correction/Refinement during the thought process:**

* **Initial Thought:**  Should I go into extreme detail about the IPv6 zero compression algorithm?
* **Correction:**  Provide a good overview but avoid getting *too* bogged down in implementation minutiae. Focus on the *what* and *why*, rather than every single bitwise operation.

* **Initial Thought:** Should I provide a complex Frida script?
* **Correction:** Keep the Frida example simple and focused on demonstrating the basic hooking mechanism. The user can expand upon it if needed.

* **Initial Thought:** Just list the included headers.
* **Correction:** Explain *why* those headers are included – what functionality they provide (e.g., `sys/socket.h` for socket definitions, `netinet/in.h` for IP address structures).

By following these steps, combining detailed code analysis with a focus on the user's specific questions, a comprehensive and helpful answer can be generated. The key is to break the problem down into smaller, manageable parts and then synthesize the information in a clear and organized way.
好的，让我们详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/net/inet_ntop.c` 这个文件。

**文件功能概述**

`inet_ntop.c` 文件的核心功能是将网络地址从二进制形式（网络字节序）转换为可读的文本表示形式（点分十进制或冒号分隔的十六进制）。它提供了 `inet_ntop` 函数，这是一个通用的地址转换函数，可以处理 IPv4 和 IPv6 地址。

**具体功能分解**

1. **`inet_ntop(int af, const void *src, char *dst, socklen_t size)`**：
   - **功能:** 这是主要的入口函数，用于将网络地址转换为字符串表示。
   - **参数:**
     - `af` (Address Family): 指定地址族，例如 `AF_INET` (IPv4) 或 `AF_INET6` (IPv6)。
     - `src` (Source): 指向包含网络地址的内存区域的指针。对于 IPv4，它指向一个 `struct in_addr` 结构；对于 IPv6，它指向一个 `struct in6_addr` 结构。
     - `dst` (Destination): 指向用于存储转换后字符串的缓冲区的指针。
     - `size`:  `dst` 缓冲区的大小，用于防止缓冲区溢出。
   - **实现:**
     - 根据传入的地址族 `af`，调用相应的转换函数：
       - 如果 `af` 是 `AF_INET`，则调用 `inet_ntop4`。
       - 如果 `af` 是 `AF_INET6`，则调用 `inet_ntop6`。
       - 如果 `af` 是其他值，则设置 `errno` 为 `EAFNOSUPPORT` (不支持的地址族)，并返回 `NULL`。
   - **与 Android 的关系:**  Android 的网络编程接口广泛使用此函数，例如在获取网络连接信息、DNS 解析结果、以及在 `adb` 等工具中显示 IP 地址时。

2. **`inet_ntop4(const u_char *src, char *dst, size_t size)`**：
   - **功能:** 将 IPv4 地址（4 字节）转换为点分十进制字符串。
   - **参数:**
     - `src`: 指向 4 字节 IPv4 地址的指针（以 `unsigned char` 数组形式）。
     - `dst`: 指向用于存储转换后字符串的缓冲区的指针。
     - `size`: `dst` 缓冲区的大小。
   - **实现:**
     - 使用 `snprintf` 函数将 `src` 指向的 4 个字节格式化为 "%u.%u.%u.%u" 的字符串，存储到临时缓冲区 `tmp` 中。
     - 检查 `snprintf` 的返回值 `l`，确保格式化成功且没有超出临时缓冲区的大小。
     - 使用 `strlcpy` 函数将临时缓冲区 `tmp` 的内容安全地复制到目标缓冲区 `dst` 中，防止缓冲区溢出。
     - 如果格式化或复制过程中发生错误（例如，目标缓冲区太小），则设置 `errno` 为 `ENOSPC` (空间不足) 并返回 `NULL`。
   - **与 Android 的关系举例:** 当 Android 应用通过 Java 的 `InetAddress.getHostAddress()` 方法获取 IPv4 地址的字符串表示时，底层最终会调用到这个 `inet_ntop4` 函数。

3. **`inet_ntop6(const u_char *src, char *dst, size_t size)`**：
   - **功能:** 将 IPv6 地址（16 字节）转换为冒号分隔的十六进制字符串，并处理零压缩的情况（例如 "::"）。
   - **参数:**
     - `src`: 指向 16 字节 IPv6 地址的指针（以 `unsigned char` 数组形式）。
     - `dst`: 指向用于存储转换后字符串的缓冲区的指针。
     - `size`: `dst` 缓冲区的大小。
   - **实现:**
     - **预处理:**
       - 将 `src` 指向的 16 字节数据按 2 字节（16 位）为单位复制到 `words` 数组中，进行字节序转换（大端转小端，因为网络字节序是大端）。
       - 查找 `words` 数组中最长的连续零值序列，以便进行 "::" 压缩。
     - **格式化:**
       - 遍历 `words` 数组，将每个 16 位值格式化为十六进制字符串。
       - 如果当前位置位于最长的零值序列中，并且是该序列的起始位置，则输出 "::"。
       - 如果不是零值序列的起始位置，则在每个非零值之间添加冒号 ":"。
       - 特殊处理嵌入的 IPv4 地址的情况（IPv6 地址的最后 4 个字节表示 IPv4 地址），会调用 `inet_ntop4` 来格式化这部分。
     - **收尾:**
       - 检查目标缓冲区是否溢出。
       - 使用 `strlcpy` 将格式化后的字符串复制到目标缓冲区 `dst`。
       - 如果发生错误，设置 `errno` 为 `ENOSPC` 并返回 `NULL`。
   - **与 Android 的关系举例:** 当 Android 应用处理 IPv6 网络连接，例如访问支持 IPv6 的服务器时，`inet_ntop6` 会被用来将服务器的 IPv6 地址转换为字符串以供显示或日志记录。

**libc 函数的实现细节**

* **`snprintf(char *str, size_t size, const char *format, ...)`:**  这是一个格式化输出函数，类似于 `sprintf`，但它接受一个 `size` 参数，用于指定目标缓冲区 `str` 的大小，从而防止缓冲区溢出。`inet_ntop4` 用它来将 IPv4 地址的四个字节格式化为点分十进制字符串。

* **`strlcpy(char *dst, const char *src, size_t size)`:**  这是一个安全字符串复制函数，类似于 `strncpy`，但它保证目标字符串以空字符 `\0` 结尾，并且不会复制超过 `size - 1` 个字符。这可以有效防止缓冲区溢出。`inet_ntop4` 和 `inet_ntop6` 都用它将格式化好的地址字符串复制到最终的目标缓冲区。

* **`memset(void *s, int c, size_t n)`:**  将内存区域 `s` 的前 `n` 个字节设置为特定的值 `c`。在 `inet_ntop6` 中，它被用来初始化 `words` 数组为零。

**涉及 dynamic linker 的功能**

源代码中包含 `DEF_WEAK(inet_ntop);`。

* **`DEF_WEAK` 宏:** 这是一个用于声明弱符号的宏。在链接过程中，如果存在一个同名的强符号定义，链接器会优先使用强符号的定义。如果只存在弱符号的定义，则使用弱符号的定义。

* **与 Android dynamic linker 的关系:**  在 Android 中，`bionic` 充当动态链接器。`libc.so` 中 `inet_ntop` 被声明为弱符号意味着：
    - **可被覆盖:**  其他共享库或可执行文件可以提供自己的 `inet_ntop` 实现，并覆盖 `libc.so` 中的默认实现。这在某些需要定制网络地址转换行为的场景中很有用，但通常不常见。
    - **延迟绑定:**  弱符号的解析可能会延迟到运行时。

**so 布局样本**

假设有以下两个共享库：

**libc.so (部分)**

```
Symbol table '.dynsym' contains ... entries:
   ...
00001000 W   F .text     00000050 inet_ntop  // 'W' 表示弱符号
   ...
```

**mylib.so (可选)**

```
Symbol table '.dynsym' contains ... entries:
   ...
00000500 T   F .text     00000080 inet_ntop  // 'T' 表示强符号
   ...
```

**链接处理过程**

1. **加载时:** 当一个可执行文件或共享库依赖 `libc.so` 时，动态链接器会加载 `libc.so`。如果 `mylib.so` 也被加载，并且它定义了强符号 `inet_ntop`。

2. **符号解析:** 当程序调用 `inet_ntop` 时，动态链接器会查找该符号的定义。
   - **如果 `mylib.so` 存在:** 链接器会找到 `mylib.so` 中强符号 `inet_ntop` 的定义，并使用它。`libc.so` 中的弱符号 `inet_ntop` 会被忽略。
   - **如果 `mylib.so` 不存在:** 链接器会找到 `libc.so` 中弱符号 `inet_ntop` 的定义并使用它。

**逻辑推理和假设输入/输出**

**假设输入 (IPv4):**

- `af`: `AF_INET`
- `src`: 指向包含 IP 地址 `192.168.1.100` 的 `struct in_addr` 的指针 (网络字节序)。
- `dst`: 指向大小为 16 字节的缓冲区。
- `size`: 16

**输出:**

- 返回值: 指向 `dst` 的指针。
- `dst` 的内容: `"192.168.1.100"`

**假设输入 (IPv6):**

- `af`: `AF_INET6`
- `src`: 指向包含 IP 地址 `2001:0db8:0000:0042:0000:8a2e:0370:7334` 的 `struct in6_addr` 的指针 (网络字节序)。
- `dst`: 指向大小为 46 字节的缓冲区。
- `size`: 46

**输出:**

- 返回值: 指向 `dst` 的指针。
- `dst` 的内容: `"2001:db8:0:42::8a2e:370:7334"` (注意零压缩)。

**用户或编程常见的使用错误**

1. **缓冲区溢出:**  `dst` 缓冲区太小，无法容纳转换后的字符串。`inet_ntop` 函数会设置 `errno` 为 `ENOSPC` 并返回 `NULL`。

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <errno.h>

   int main() {
       struct sockaddr_in sa;
       char dst[8]; // 缓冲区太小

       inet_pton(AF_INET, "192.168.1.1", &sa.sin_addr);

       if (inet_ntop(AF_INET, &sa.sin_addr, dst, sizeof(dst)) == NULL) {
           perror("inet_ntop failed");
           if (errno == ENOSPC) {
               printf("错误原因：缓冲区空间不足\n");
           }
           return 1;
       }

       printf("IP 地址: %s\n", dst); // 可能不会执行到这里
       return 0;
   }
   ```

2. **使用了错误的地址族:**  传入的 `af` 与 `src` 指向的地址类型不匹配。`inet_ntop` 会设置 `errno` 为 `EAFNOSUPPORT` 并返回 `NULL`。

   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <sys/socket.h>
   #include <netinet/in6.h>
   #include <arpa/inet.h>
   #include <errno.h>

   int main() {
       struct sockaddr_in6 sa6;
       char dst[INET6_ADDRSTRLEN];

       inet_pton(AF_INET6, "2001:db8::1", &sa6.sin6_addr);

       if (inet_ntop(AF_INET, &sa6.sin6_addr, dst, sizeof(dst)) == NULL) { // 地址族不匹配
           perror("inet_ntop failed");
           if (errno == EAFNOSUPPORT) {
               printf("错误原因：不支持的地址族\n");
           }
           return 1;
       }

       printf("IP 地址: %s\n", dst);
       return 0;
   }
   ```

3. **传递了空指针作为 `src` 或 `dst`:** 这会导致程序崩溃。

**Android Framework 或 NDK 如何到达这里**

**Android Framework (Java 层):**

1. **`java.net.InetAddress`:**  这是 Java 中表示 IP 地址的核心类。它的 `getHostAddress()` 方法用于获取 IP 地址的字符串表示。

2. **JNI 调用:**  `InetAddress.getHostAddress()` 的 native 实现最终会调用到 Android Runtime (ART) 中的 JNI 代码。

3. **`android_net_utility.cpp` 或相关文件:**  在 ART 的 native 代码中，会使用底层的 socket API，例如 `getaddrinfo` 或直接操作 `sockaddr` 结构。

4. **调用 `inet_ntop`:** 当需要将 `sockaddr_in` 或 `sockaddr_in6` 结构中的地址转换为字符串时，会调用 `inet_ntop` 函数。

**Android NDK (C/C++ 层):**

1. **NDK 网络编程 API:**  NDK 提供了直接访问 POSIX socket API 的能力，例如 `socket`, `bind`, `connect`, `accept`, `sendto`, `recvfrom`, `getaddrinfo` 等。

2. **`getaddrinfo`:**  这是一个常用的函数，用于将主机名或服务名转换为 socket 地址结构。它返回的 `addrinfo` 结构体中包含 `sockaddr_in` 或 `sockaddr_in6` 类型的地址。

3. **调用 `inet_ntop`:**  在 NDK 代码中，开发者可以直接调用 `inet_ntop` 函数来将这些 socket 地址结构中的 IP 地址转换为字符串。

**Frida Hook 示例**

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 应用 {package_name} 未运行")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "inet_ntop"), {
    onEnter: function(args) {
        var af = args[0].toInt32();
        var src = args[1];
        var dst = args[2];
        var size = args[3].toInt32();
        var address_str = "";

        if (af === 2) { // AF_INET
            address_str = Memory.readString(src, 4); // 读取 4 字节
        } else if (af === 10) { // AF_INET6
            address_str = Memory.readByteArray(src, 16).map(function(byte) {
                return ('0' + (byte & 0xFF).toString(16)).slice(-2);
            }).join('');
        } else {
            address_str = "Unknown AF";
        }

        console.log("--- inet_ntop called ---");
        console.log("Address Family:", af);
        console.log("Source Address (raw):", address_str);
        console.log("Destination Buffer:", dst);
        console.log("Buffer Size:", size);
    },
    onLeave: function(retval) {
        if (retval.isNull() === false) {
            var result = Memory.readCString(retval);
            console.log("Return Value (String):", result);
        } else {
            console.log("Return Value: NULL");
        }
        console.log("--- inet_ntop end ---\\n");
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到目标 Android 应用程序。
2. **`Module.findExportByName("libc.so", "inet_ntop")`:** 找到 `libc.so` 中 `inet_ntop` 函数的地址。
3. **`Interceptor.attach(...)`:**  拦截 `inet_ntop` 函数的调用。
4. **`onEnter`:**  在 `inet_ntop` 函数执行之前调用。
   - 获取函数参数 `af`, `src`, `dst`, `size`。
   - 根据地址族 `af` 读取 `src` 指向的原始地址数据。
   - 打印参数信息。
5. **`onLeave`:** 在 `inet_ntop` 函数执行之后调用。
   - 获取返回值 `retval`。
   - 如果返回值不为 `NULL`，则读取返回的字符串并打印。
   - 打印返回值信息。

运行此 Frida 脚本，当目标应用程序调用 `inet_ntop` 时，你将在控制台中看到函数的参数和返回值，可以帮助你调试网络相关的操作。

希望以上详细的解释能够帮助你理解 `inet_ntop.c` 文件的功能以及它在 Android 中的应用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/net/inet_ntop.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: inet_ntop.c,v 1.13 2016/09/21 04:38:56 guenther Exp $	*/

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/* const char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *
inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
	switch (af) {
	case AF_INET:
		return (inet_ntop4(src, dst, size));
	case AF_INET6:
		return (inet_ntop6(src, dst, size));
	default:
		errno = EAFNOSUPPORT;
		return (NULL);
	}
	/* NOTREACHED */
}
DEF_WEAK(inet_ntop);

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
	char tmp[sizeof "255.255.255.255"];
	int l;

	l = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u",
	    src[0], src[1], src[2], src[3]);
	if (l <= 0 || l >= size) {
		errno = ENOSPC;
		return (NULL);
	}
	strlcpy(dst, tmp, size);
	return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	char *tp, *ep;
	struct { int base, len; } best, cur;
	u_int words[IN6ADDRSZ / INT16SZ];
	int i;
	int advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + sizeof(tmp);
	for (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base) {
				if (tp + 1 >= ep) {
					errno = ENOSPC;
					return (NULL);
				}
				*tp++ = ':';
			}
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0) {
			if (tp + 1 >= ep) {
				errno = ENOSPC;
				return (NULL);
			}
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!inet_ntop4(src+12, tp, ep - tp))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		advance = snprintf(tp, ep - tp, "%x", words[i]);
		if (advance <= 0 || advance >= ep - tp) {
			errno = ENOSPC;
			return (NULL);
		}
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ)) {
		if (tp + 1 >= ep) {
			errno = ENOSPC;
			return (NULL);
		}
		*tp++ = ':';
	}
	if (tp + 1 >= ep) {
		errno = ENOSPC;
		return (NULL);
	}
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		errno = ENOSPC;
		return (NULL);
	}
	strlcpy(dst, tmp, size);
	return (dst);
}

"""

```
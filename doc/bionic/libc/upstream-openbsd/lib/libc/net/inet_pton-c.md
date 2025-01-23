Response:
Let's break down the thought process for analyzing the `inet_pton.c` code and generating the comprehensive response.

**1. Understanding the Core Request:**

The request asks for a detailed analysis of the `inet_pton.c` file within the Android Bionic library. Key aspects include: functionality, Android relevance, implementation details of libc functions, dynamic linker involvement, logical reasoning (with examples), common usage errors, and how the function is reached from higher Android layers (with Frida examples).

**2. Initial Code Scan and Goal Identification:**

First, I quickly scanned the code to grasp its main purpose. The function names (`inet_pton`, `inet_pton4`, `inet_pton6`) and the included headers (`sys/socket.h`, `netinet/in.h`, `arpa/inet.h`) immediately suggest it deals with converting human-readable IP address strings to their binary network representations. The comments also explicitly state this.

**3. Deconstructing Functionality:**

* **`inet_pton` (Main Function):**  The core function acts as a dispatcher based on the address family (`AF_INET` for IPv4, `AF_INET6` for IPv6). It returns 1 for valid addresses, 0 for invalid ones, and -1 for errors.
* **`inet_pton4` (IPv4):** This function specifically handles dotted-decimal IPv4 addresses (e.g., "192.168.1.1"). It parses the string, validates the numeric ranges (0-255), and converts it to a 4-byte binary representation.
* **`inet_pton6` (IPv6):**  This function handles the more complex IPv6 address format, including hexadecimal representation, colons, and the "::" shorthand. It parses, validates, and converts to a 16-byte binary representation.

**4. Identifying Android Relevance:**

The question specifically asks about Android's connection. Since Bionic *is* Android's C library, this code is fundamental. Any network operation on Android that requires converting a string IP address uses this function (or a higher-level function that calls it). Key areas include:

* **Network Sockets:** Creating and connecting sockets.
* **Network Configuration:** Parsing IP addresses from configuration files or user input.
* **DNS Resolution:** While this function doesn't do DNS resolution itself, it's used to represent the IP addresses returned by DNS.

**5. Detailed Implementation Analysis (libc functions):**

For each libc function used within `inet_pton.c`, I considered its purpose and how it contributes to the overall functionality:

* **`switch` statement:**  Control flow based on address family.
* **`errno = EAFNOSUPPORT`:**  Setting the error code for unsupported address families.
* **`return` statements:**  Returning success or error codes.
* **`strchr`:**  Searching for characters within a string (used to check for digits and hexadecimal characters).
* **`memcpy`:** Copying the validated binary address to the destination buffer.
* **`memset`:** Initializing memory (used in `inet_pton6`).

For each of these, I explained *what* it does and *why* it's used in the context of IP address conversion.

**6. Dynamic Linker and `DEF_WEAK`:**

The `DEF_WEAK(inet_pton);` macro is a crucial point for the dynamic linker. This indicates a *weak symbol*. I explained:

* **Purpose of Weak Symbols:**  Allowing libraries to be overridden at runtime.
* **Android Context:**  This allows for potential customization or replacement of the standard `inet_pton` implementation.
* **SO Layout:** I provided a simplified example of how multiple shared objects might be loaded and how the dynamic linker resolves the weak symbol.
* **Linking Process:**  Explained how the dynamic linker searches for symbols and prefers strong symbols over weak ones.

**7. Logical Reasoning and Examples:**

To demonstrate understanding, I created hypothetical inputs and their corresponding outputs for both `inet_pton4` and `inet_pton6`, covering valid and invalid cases. This reinforces the stated functionality.

**8. Common Usage Errors:**

I thought about common mistakes developers might make when using `inet_pton`:

* **Incorrect Address Family:**  Using `AF_INET` for an IPv6 address or vice versa.
* **Invalid Address Format:**  Providing malformed IP address strings.
* **Insufficient Buffer Size:**  Not allocating enough space for the `dst` buffer.
* **Null Pointers:** Passing `NULL` for `src` or `dst`.

For each error, I provided a code snippet illustrating the mistake and explained the expected behavior.

**9. Android Framework/NDK Path and Frida Hooking:**

This is where I considered how a network request initiated from the Android application layer would eventually lead to `inet_pton`. The path involves several layers:

* **Java Layer:**  Using classes like `InetAddress`.
* **Native Framework:** JNI calls into native code.
* **Bionic/libc:**  The `inet_pton` function.

I outlined a possible call stack and provided a concrete Frida example showing how to hook `inet_pton` to observe its arguments and return value. This demonstrates a practical way to debug and understand the function's behavior in a real Android environment.

**10. Structuring the Response:**

Finally, I organized the information logically with clear headings and subheadings. I used formatting (bold text, code blocks) to improve readability. I aimed for a comprehensive and well-structured answer that addressed all parts of the original request.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the low-level bit manipulation within `inet_pton4` and `inet_pton6`.
* **Correction:**  Shifting focus to the higher-level functionality, Android context, and practical implications.
* **Initial thought:**  Not explicitly mentioning the `DEF_WEAK` macro.
* **Correction:**  Recognizing its importance for dynamic linking and adding a detailed explanation.
* **Initial thought:**  Providing only generic examples of usage errors.
* **Correction:**  Crafting specific code examples to illustrate common mistakes.
* **Initial thought:**  Vaguely describing the Android framework path.
* **Correction:**  Providing a more concrete (though still simplified) call stack and a practical Frida example.

By following this iterative process of understanding the request, analyzing the code, connecting it to the Android context, and refining the explanation, I was able to generate the comprehensive and informative response.
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/net/inet_pton.c` 这个文件。

**功能列举:**

`inet_pton.c` 文件定义了将人类可读的 IP 地址字符串转换为网络字节序二进制格式的功能。它主要包含以下函数：

* **`inet_pton(int af, const char *src, void *dst)`:**  这是主函数，用于将字符串 `src` 表示的 IP 地址转换为网络字节序的二进制格式并存储到 `dst` 指向的内存中。`af` 参数指定了地址族（Address Family），可以是 `AF_INET` (IPv4) 或 `AF_INET6` (IPv6)。
* **`inet_pton4(const char *src, u_char *dst)`:**  辅助函数，专门用于将 IPv4 的点分十进制字符串（例如 "192.168.1.1"）转换为 4 字节的网络字节序二进制格式。
* **`inet_pton6(const char *src, u_char *dst)`:** 辅助函数，专门用于将 IPv6 的字符串表示形式（例如 "2001:db8::1"）转换为 16 字节的网络字节序二进制格式。

**与 Android 功能的关系及举例:**

`inet_pton` 是 Android C 库 (Bionic) 的一部分，因此它直接支持 Android 系统中的网络编程功能。任何需要将 IP 地址字符串转换为二进制格式的操作都会用到这个函数。

**举例说明:**

* **网络套接字编程:** 当 Android 应用程序需要创建一个网络套接字并连接到某个 IP 地址时，通常需要使用 `sockaddr_in` 或 `sockaddr_in6` 结构体来指定目标地址。这些结构体的 `sin_addr` 和 `sin6_addr` 字段需要的是网络字节序的二进制 IP 地址。`inet_pton` 就负责将用户提供的字符串 IP 地址转换为这种格式。

   例如，在 Java 层，你可能会这样写：

   ```java
   InetAddress address = InetAddress.getByName("192.168.1.1");
   ```

   在底层，`InetAddress.getByName()` 会调用 native 代码，最终可能会调用到 `inet_pton` 来解析 IP 地址字符串。

* **网络配置:**  Android 系统在读取网络配置文件（例如 DNS 服务器地址）时，也会使用 `inet_pton` 将字符串形式的 IP 地址转换为二进制格式。

* **NDK 开发:**  使用 Android NDK 进行 C/C++ 开发的开发者可以直接调用 `inet_pton` 函数来进行 IP 地址转换。

**libc 函数的实现细节:**

* **`inet_pton` 的实现:**
    * 它首先根据传入的地址族 `af` 参数进行 `switch` 判断。
    * 如果 `af` 是 `AF_INET`，则调用 `inet_pton4` 进行处理。
    * 如果 `af` 是 `AF_INET6`，则调用 `inet_pton6` 进行处理。
    * 如果 `af` 是其他不支持的值，则设置 `errno` 为 `EAFNOSUPPORT` 并返回 -1。

* **`inet_pton4` 的实现:**
    * 它遍历输入的字符串 `src` 的每个字符。
    * 它使用一个静态字符数组 `digits` 来判断字符是否是数字。
    * 它维护几个变量：`saw_digit` 标记是否遇到了数字，`octets` 记录已解析的段数，`tmp` 数组用于临时存储解析出的字节。
    * 如果遇到数字，则将其累加到当前段的值中。如果当前段的值超过 255，则返回 0（地址无效）。
    * 如果遇到点号 (`.`)，则切换到下一个段。如果点号之前没有数字，或者已经解析了 4 个段，则返回 0。
    * 如果遇到其他字符，则返回 0。
    * 最后，如果解析了 4 个有效的段，则使用 `memcpy` 将 `tmp` 数组的内容拷贝到 `dst` 指向的内存，并返回 1。

* **`inet_pton6` 的实现:**
    * 它使用两个静态字符数组 `xdigits_l` 和 `xdigits_u` 来判断字符是否是十六进制数字（大小写均可）。
    * 它维护了几个关键变量：`tmp` 数组用于存储解析出的 16 字节 IPv6 地址，`tp` 是指向 `tmp` 数组当前写入位置的指针，`endp` 指向 `tmp` 数组的末尾，`colonp` 用于处理双冒号 (`::`) 压缩表示法。
    * 它遍历输入字符串 `src` 的每个字符。
    * 如果遇到十六进制数字，则将其转换为数值并累加到当前段的值中。
    * 如果遇到冒号 (`:`):
        * 如果之前没有遇到过数字，并且已经有 `colonp`，说明出现了多个连续的 `::`，返回 0。
        * 如果之前没有遇到过数字，且没有 `colonp`，则将 `colonp` 指向当前位置，用于标记双冒号的位置。
        * 如果之前遇到了数字，则将当前段的值写入 `tmp` 数组，并重置相关变量。
    * 如果遇到点号 (`.`)，并且后面跟着的是合法的 IPv4 地址，则调用 `inet_pton4` 解析后面的 IPv4 部分，并将结果写入 `tmp` 数组。
    * 处理双冒号压缩表示法：如果在解析过程中遇到了 `::`，则需要在 `tmp` 数组中留出足够的空间。解析完成后，会将 `colonp` 之后的数据移动到数组的末尾，填充 `::` 表示的零值段。
    * 最后，如果成功解析出 16 字节的 IPv6 地址，则使用 `memcpy` 将 `tmp` 数组的内容拷贝到 `dst` 指向的内存，并返回 1。

**涉及 dynamic linker 的功能:**

源代码中包含 `DEF_WEAK(inet_pton);`。这是一个宏，在 Bionic 中通常用于声明弱符号 (weak symbol)。

**弱符号的意义:**

* **允许覆盖:**  弱符号允许在链接时，如果存在一个同名的强符号 (strong symbol)，则优先使用强符号的定义。这为库的扩展和定制提供了灵活性。
* **可选实现:**  某些功能可能在某些平台上不可用，使用弱符号可以避免因缺少某个符号而导致链接失败。

**so 布局样本及链接处理过程:**

假设我们有两个共享库 `libnetwork.so` 和 `libc.so`。

* **`libc.so` (包含 `inet_pton.c`):**
  ```
  lib/libc.so:
      ...
      符号表:
          ...
          00010000 W inet_pton  # 'W' 表示弱符号
          ...
  ```

* **`libnetwork.so`:**
  ```c
  // libnetwork.c
  #include <arpa/inet.h>
  #include <stdio.h>

  int main() {
      struct in_addr addr;
      if (inet_pton(AF_INET, "10.0.0.1", &addr) == 1) {
          printf("Success!\n");
      } else {
          printf("Failed!\n");
      }
      return 0;
  }
  ```

  编译 `libnetwork.so`: `clang -shared -fPIC libnetwork.c -o libnetwork.so`

**链接处理过程:**

1. 当加载器加载 `libnetwork.so` 时，它会查找 `inet_pton` 符号。
2. 加载器会在其依赖项中查找 `inet_pton`。由于 `libnetwork.so` 依赖于 `libc.so`，加载器会在 `libc.so` 中找到 `inet_pton` 的弱符号定义。
3. 如果在其他已加载的共享库中没有找到 `inet_pton` 的强符号定义，则 `libnetwork.so` 将链接到 `libc.so` 中定义的弱符号 `inet_pton`。

**如果存在强符号:**

假设另一个共享库 `libmyinet.so` 提供了自己的 `inet_pton` 实现（强符号）：

* **`libmyinet.so`:**
  ```
  lib/libmyinet.so:
      ...
      符号表:
          ...
          00008000 T inet_pton  # 'T' 表示强符号
          ...
  ```

如果 `libmyinet.so` 在 `libc.so` 之前加载（或者以某种方式被链接器优先考虑），那么 `libnetwork.so` 将会链接到 `libmyinet.so` 中提供的 `inet_pton` 的强符号实现，而不是 `libc.so` 中的弱符号实现。

**Android 中的实际情况:**

在实际的 Android 系统中，`libc.so` 提供的 `inet_pton` 通常是最终使用的实现，因为不太会有其他的共享库去覆盖这个基础的网络函数。弱符号的机制主要用于提供一种扩展和替换的可能性，虽然在 `inet_pton` 这样的核心函数上不太常见直接被替换。

**逻辑推理、假设输入与输出:**

**假设输入与输出 (inet_pton4):**

* **输入 `src`:** "192.168.1.1", `af`: `AF_INET`
* **输出 `dst`:**  `dst` 指向的内存将被写入 `\xC0\xA8\x01\x01` (192, 168, 1, 1 的十六进制表示)，函数返回 1。

* **输入 `src`:** "invalid ip", `af`: `AF_INET`
* **输出 `dst`:** `dst` 指向的内存内容保持不变，函数返回 0。

* **输入 `src`:** "192.168.1.256", `af`: `AF_INET`
* **输出 `dst`:** `dst` 指向的内存内容保持不变，函数返回 0 (因为 256 超出了一个字节的范围)。

**假设输入与输出 (inet_pton6):**

* **输入 `src`:** "2001:db8::1", `af`: `AF_INET6`
* **输出 `dst`:** `dst` 指向的内存将被写入 `\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01`，函数返回 1。

* **输入 `src`:** "invalid ipv6", `af`: `AF_INET6`
* **输出 `dst`:** `dst` 指向的内存内容保持不变，函数返回 0。

**用户或编程常见的使用错误:**

1. **地址族不匹配:**  使用 `AF_INET` 解析 IPv6 地址，或使用 `AF_INET6` 解析 IPv4 地址。

   ```c
   struct in6_addr addr6;
   if (inet_pton(AF_INET, "2001:db8::1", &addr6) == 1) { // 错误：地址族不匹配
       // ...
   }
   ```

2. **IP 地址格式错误:**  提供的 IP 地址字符串不符合规范。

   ```c
   struct in_addr addr;
   if (inet_pton(AF_INET, "192.168.1", &addr) == 1) { // 错误：缺少一个段
       // ...
   }
   ```

3. **目标缓冲区太小:**  提供的 `dst` 缓冲区不足以存储转换后的 IP 地址。虽然 `inet_pton` 本身不会写入超出缓冲区大小的内容，但如果上层调用者没有正确分配缓冲区，可能会导致问题。

4. **传递 NULL 指针:**  向 `inet_pton` 传递 `NULL` 的 `src` 或 `dst` 指针会导致程序崩溃。

   ```c
   struct in_addr addr;
   if (inet_pton(AF_INET, NULL, &addr) == 1) { // 错误：src 为 NULL
       // ...
   }
   ```

**Android Framework 或 NDK 如何到达这里:**

一个典型的流程可能是这样的：

1. **Android 应用 (Java 代码):**  应用发起一个网络请求，例如连接到某个服务器。这可能涉及使用 `java.net.Socket` 或 `java.net.URL` 等类。

   ```java
   InetAddress address = InetAddress.getByName("www.example.com");
   Socket socket = new Socket(address, 80);
   ```

2. **Java Framework (native 代码):** `InetAddress.getByName()` 方法最终会调用到 Android Framework 的 native 代码，通常是通过 JNI (Java Native Interface) 进行调用。

3. **Bionic 库调用:**  Framework 的 native 代码需要将域名解析为 IP 地址（DNS 查询）。在获取到 IP 地址字符串后，会调用 Bionic 库中的函数，例如 `inet_pton`，将 IP 地址字符串转换为网络字节序的二进制格式。

4. **系统调用:**  最终，创建 socket 并连接的操作会涉及到系统调用，例如 `connect()`，这个系统调用需要接收网络字节序的 IP 地址。

**Frida Hook 示例调试:**

可以使用 Frida 来 hook `inet_pton` 函数，观察其参数和返回值。

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名

session = frida.attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "inet_pton"), {
    onEnter: function(args) {
        var af = args[0].toInt32();
        var src = Memory.readUtf8String(args[1]);
        console.log("inet_pton called with af:", af, "src:", src);
    },
    onLeave: function(retval) {
        console.log("inet_pton returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将 `your.app.package` 替换为你要调试的 Android 应用的包名。
2. 确保你的设备或模拟器上安装了 Frida 服务，并且你的电脑上安装了 Frida Python 库。
3. 运行这个 Python 脚本。
4. 在你的 Android 应用中执行会触发 `inet_pton` 调用的操作（例如，访问一个网站）。
5. Frida 会在终端输出 `inet_pton` 被调用时的参数（地址族和 IP 地址字符串）以及返回值。

**这个 Frida 脚本会 hook `libc.so` 中的 `inet_pton` 函数，当该函数被调用时，`onEnter` 函数会记录下地址族和传入的 IP 地址字符串。`onLeave` 函数会记录函数的返回值。**

通过这种方式，你可以观察到 Android 应用在进行网络操作时，是如何调用到 `inet_pton` 函数的，以及传递了哪些参数。这对于理解网络请求的底层实现和调试网络相关问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/net/inet_pton.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: inet_pton.c,v 1.10 2015/09/13 21:36:08 guenther Exp $	*/

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

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static int	inet_pton4(const char *src, u_char *dst);
static int	inet_pton6(const char *src, u_char *dst);

/* int
 * inet_pton(af, src, dst)
 *	convert from presentation format (which usually means ASCII printable)
 *	to network format (which is usually some kind of binary format).
 * return:
 *	1 if the address was valid for the specified address family
 *	0 if the address wasn't valid (`dst' is untouched in this case)
 *	-1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *	Paul Vixie, 1996.
 */
int
inet_pton(int af, const char *src, void *dst)
{
	switch (af) {
	case AF_INET:
		return (inet_pton4(src, dst));
	case AF_INET6:
		return (inet_pton6(src, dst));
	default:
		errno = EAFNOSUPPORT;
		return (-1);
	}
	/* NOTREACHED */
}
DEF_WEAK(inet_pton);

/* int
 * inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *	1 if `src' is a valid dotted quad, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton4(const char *src, u_char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	u_char tmp[INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			u_int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return (0);
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
			*tp = new;
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);

	memcpy(dst, tmp, INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton6(const char *src, u_char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit, count_xdigit;
	u_int val;

	memset((tp = tmp), '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = count_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			if (count_xdigit >= 4)
				return (0);
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			count_xdigit++;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			count_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			count_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + INT16SZ > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, IN6ADDRSZ);
	return (1);
}
```
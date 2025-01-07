Response:
Let's break down the thought process for analyzing this `tls.h` file and generating the comprehensive response.

**1. Understanding the Context:**

The first step is recognizing the context: the file is `tls.h` within the `bionic` library of Android. `bionic` is explicitly stated to be Android's C library, math library, and dynamic linker. This immediately tells us that the content relates to thread-local storage (TLS) and is likely used for secure communication. The "uapi" in the path suggests it's a user-space API definition that mirrors kernel-level structures.

**2. Initial Scan and Keyword Spotting:**

Next, I quickly scanned the content for keywords and patterns. Obvious things jump out:

* `#define`:  Lots of `#define` statements indicating constants and macros.
* `TLS_`:  Prefix used extensively, clearly related to Transport Layer Security (TLS).
* `VERSION`, `CIPHER`, `AES`, `GCM`, `CCM`, `CHACHA20`, `POLY1305`, `SM4`, `ARIA`: These point to TLS versions and specific cryptographic algorithms.
* `IV_SIZE`, `KEY_SIZE`, `SALT_SIZE`, `TAG_SIZE`, `REC_SEQ_SIZE`: Indicate sizes of different components used in the cryptographic algorithms.
* `struct tls_crypto_info`: A structure likely holding general TLS information.
* `struct tls12_crypto_info_*`:  Several structures specific to TLS 1.2 and various cipher suites. These structures seem to encapsulate the parameters for different encryption methods.
* `TLS_TX`, `TLS_RX`, `TLS_TX_ZEROCOPY_RO`, `TLS_RX_EXPECT_NO_PAD`: Flags or options related to TLS transmission and reception.
* `TLS_SET_RECORD_TYPE`, `TLS_GET_RECORD_TYPE`: Constants likely related to ioctl operations for configuring TLS.
* `enum { TLS_INFO_* }`: An enumeration of different types of TLS information.
* `TLS_CONF_*`: Constants related to TLS configuration (software, hardware).

**3. Inferring Functionality from Constants and Structures:**

Based on the spotted keywords and patterns, I started inferring the purpose of different sections:

* **TLS Versions:**  `TLS_1_2_VERSION`, `TLS_1_3_VERSION` and the related macros clearly define supported TLS protocol versions.
* **Cipher Suites:**  The `TLS_CIPHER_*` definitions and the `tls12_crypto_info_*` structures describe specific encryption algorithms (cipher suites) and their parameters (key sizes, IV sizes, etc.). This directly relates to the encryption part of secure communication.
* **Transmission/Reception Flags:** `TLS_TX`, `TLS_RX` likely control the direction of TLS communication. The other flags probably represent optimizations or specific handling requirements.
* **Configuration:** `TLS_CONF_*` suggests different ways TLS can be implemented (software, hardware).
* **Information Retrieval:** `TLS_INFO_*` hints at a mechanism to query various aspects of the TLS connection.

**4. Connecting to Android:**

Knowing that this is in Android's `bionic` library, the next step is to consider how these low-level TLS definitions are used in higher layers:

* **Networking:** TLS is fundamental for secure network communication (HTTPS, etc.). Android apps rely on this for secure data transfer.
* **System Services:** Android system services might also use secure communication channels protected by TLS.
* **NDK:** NDK developers can potentially interact with lower-level network APIs that might utilize these TLS definitions indirectly.

**5. Explaining libc Functions (or Lack Thereof):**

It's important to note that this header file *doesn't define any libc functions directly*. It defines *constants and structures* that are used *by* libc functions (specifically those dealing with sockets and network communication) and potentially by the kernel. The explanation needs to clarify this distinction.

**6. Dynamic Linker Relevance:**

The file itself doesn't *directly* involve the dynamic linker in its definitions. However, the *use* of TLS often involves libraries like `libssl.so` or `libcrypto.so`, which *are* dynamically linked. So the connection is indirect, through the libraries that *use* these TLS definitions. The explanation needs to address this carefully. A basic shared library setup is needed to illustrate this.

**7. Common Usage Errors:**

Thinking about how developers might misuse these definitions is important:

* **Incorrectly setting sizes:** Mismatched buffer sizes when dealing with IVs, keys, etc., can lead to crashes or vulnerabilities.
* **Misunderstanding constants:** Using the wrong constant for a specific cipher or version can lead to negotiation failures.

**8. Android Framework and NDK Path:**

Tracing how an Android app reaches these low-level definitions requires a step-by-step approach:

* **High-level APIs:** Start with something common like `HttpsURLConnection`.
* **Framework layers:**  Trace down through `URLConnection`, `OkHttp` (a common underlying HTTP client), and potentially Android's network stack.
* **Native libraries:**  Eventually, the call will reach native code that interacts with system calls and uses libraries like `libssl.so` which, in turn, uses these `tls.h` definitions.
* **Kernel interaction:**  Ultimately, the kernel handles the actual TLS negotiation and encryption, using the information defined in this header.

**9. Frida Hooking:**

Frida examples should focus on points where these definitions are likely to be used. Hooking system calls related to socket creation (`socket`), TLS setup (`setsockopt` with TLS options), or functions within `libssl.so` that handle encryption/decryption are good candidates.

**10. Structuring the Response:**

Finally, organize the information logically, using clear headings and bullet points. Address each part of the prompt systematically. Use code blocks for code examples (like the Frida script and SO layout). Be precise in language and avoid oversimplification.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file defines libc functions for TLS."  **Correction:** Realized it primarily defines *constants and structures* used by libc and kernel.
* **Initial thought:** "Direct dynamic linker involvement." **Correction:**  The involvement is *indirect* through dynamically linked libraries that *use* these definitions. Needed to clarify this distinction.
* **Frida example:** Initially considered hooking a generic network function. **Refinement:** Focused on more specific points like `setsockopt` with TLS options, as this is where the configuration defined in the header becomes relevant.

By following this structured approach, combining keyword spotting, logical deduction, and knowledge of Android architecture, I could generate a comprehensive and accurate response to the prompt.
这个C头文件 `tls.h` 定义了与Linux内核TLS (Transport Layer Security) 实现相关的用户空间API常量和数据结构。它位于Android的Bionic库中，说明Android的TLS功能在底层是与Linux内核的TLS实现交互的。

**功能列举:**

1. **定义TLS操作类型:**  `TLS_TX`, `TLS_RX`, `TLS_TX_ZEROCOPY_RO`, `TLS_RX_EXPECT_NO_PAD` 定义了TLS数据传输和接收的不同模式。
2. **定义TLS协议版本:** `TLS_1_2_VERSION` 和 `TLS_1_3_VERSION` 定义了支持的TLS协议版本。
3. **定义TLS密码套件:**  `TLS_CIPHER_AES_GCM_128` 等一系列 `TLS_CIPHER_*` 定义了支持的加密算法（密码套件），以及与这些算法相关的参数，如密钥大小、初始化向量 (IV) 大小、盐值大小、认证标签大小和记录序列号大小。
4. **定义TLS配置操作类型:** `TLS_SET_RECORD_TYPE`, `TLS_GET_RECORD_TYPE` 定义了设置和获取TLS记录类型的操作。
5. **定义TLS加密信息结构:** `struct tls_crypto_info` 和一系列 `struct tls12_crypto_info_*` 结构体定义了用于传递TLS加密信息的格式，包括版本、密码类型以及具体的加密参数，例如密钥、IV、盐值和记录序列号。
6. **定义TLS信息类型枚举:** `enum { TLS_INFO_* }` 定义了可以查询的各种TLS信息类型，例如版本、密码套件和配置信息。
7. **定义TLS配置类型:** `TLS_CONF_BASE`, `TLS_CONF_SW`, `TLS_CONF_HW`, `TLS_CONF_HW_RECORD` 定义了不同的TLS配置类型，可能涉及软件实现和硬件加速实现。

**与Android功能的关联和举例说明:**

这个头文件是Android底层网络通信安全的基础。Android应用程序进行安全网络连接 (如 HTTPS) 时，底层的网络库会使用这些定义来配置和操作TLS连接。

**举例说明:**

当一个Android应用使用 `HttpsURLConnection` 或 `OkHttp` 等进行HTTPS请求时，底层的实现最终会涉及到创建socket连接，并在这个socket上启用TLS。这个 `tls.h` 文件中定义的常量（如支持的TLS版本和密码套件）以及数据结构会被用来配置内核的TLS实现。

例如，当协商使用 `TLS_CIPHER_AES_GCM_128` 加密时，内核需要知道该密码套件的密钥大小 (`TLS_CIPHER_AES_GCM_128_KEY_SIZE`)、IV大小 (`TLS_CIPHER_AES_GCM_128_IV_SIZE`) 等信息，这些信息就来源于这个头文件。

**详细解释每一个libc函数的功能是如何实现的:**

**需要明确的是，这个头文件本身并不包含任何libc函数的实现代码。** 它只是定义了一些常量和数据结构。这些定义会被libc中与网络编程相关的函数（如 `socket()`, `setsockopt()`, `read()`, `write()` 等）以及内核的TLS实现所使用。

例如，`setsockopt()` 函数可以用来配置socket的TLS选项。在设置TLS加密信息时，会用到 `struct tls12_crypto_info_*` 这些结构体。

**对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及dynamic linker的功能。但是，实现了TLS功能的库（例如 `libssl.so` 或 `boringssl`，Android 使用的是 BoringSSL）是动态链接库。

**SO 布局样本 (以 `libssl.so` 为例):**

```
libssl.so:
  .interp        // 指向动态链接器
  .note.android.ident
  .note.gnu.build-id
  .gnu.hash
  .dynsym        // 动态符号表
  .dynstr        // 动态字符串表
  .gnu.version
  .gnu.version_r
  .rel.dyn       // 重定位表
  .rel.plt       // PLT重定位表
  .init          // 初始化代码
  .plt           // 程序链接表
  .text          // 代码段 (包含 TLS 相关的实现)
  .fini          // 终止代码
  .rodata        // 只读数据段 (可能包含一些 TLS 常量)
  .data          // 数据段
  .bss           // 未初始化数据段
```

**链接的处理过程:**

1. **应用程序请求:** 当应用程序发起一个需要TLS连接的网络请求时，可能会调用到Android Framework提供的网络API。
2. **Framework 调用:** Android Framework 的网络组件会调用到native层，最终会使用到实现了TLS功能的动态链接库，例如 `libssl.so`。
3. **动态链接:** 动态链接器 (在Android中是 `linker64` 或 `linker`) 负责将 `libssl.so` 加载到进程的内存空间，并解析其依赖关系。
4. **符号解析:** 动态链接器会解析应用程序或其他库对 `libssl.so` 中提供的TLS相关函数的调用。这涉及到在 `libssl.so` 的 `.dynsym` (动态符号表) 中查找对应的函数地址。
5. **重定位:** 动态链接器会根据 `.rel.dyn` 和 `.rel.plt` 中的信息，修改代码段和数据段中的地址，确保函数调用和数据访问指向正确的内存位置。

**在这个过程中，`tls.h` 头文件中定义的常量和数据结构会被 `libssl.so` 中的代码使用。** 例如，在协商TLS版本和密码套件时，`libssl.so` 会用到 `TLS_1_2_VERSION`、`TLS_CIPHER_AES_GCM_128` 等常量，并且会使用 `struct tls12_crypto_info_*` 结构体来存储和传递加密信息。

**逻辑推理、假设输入与输出:**

假设一个场景，应用程序需要使用TLS 1.3和 `TLS_CIPHER_CHACHA20_POLY1305` 密码套件建立连接。

**假设输入:**

* 应用程序发起HTTPS请求。
* 底层网络库尝试建立TLS连接。
* 网络协商过程选择了TLS 1.3 和 `TLS_CIPHER_CHACHA20_POLY1305`。

**逻辑推理:**

1. 底层TLS实现会检查支持的TLS版本，`tls.h` 中定义了 `TLS_1_3_VERSION`，表明支持TLS 1.3。
2. 底层TLS实现会检查支持的密码套件，`tls.h` 中定义了 `TLS_CIPHER_CHACHA20_POLY1305`，表明支持该密码套件。
3. 如果协商成功，内核或TLS库会使用 `tls.h` 中定义的与 `TLS_CIPHER_CHACHA20_POLY1305` 相关的常量，例如 `TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE`，来确定密钥的长度。
4. 在设置加密参数时，可能会使用 `struct tls12_crypto_info_chacha20_poly1305` 结构体来存储密钥、IV、盐值和记录序列号等信息。

**假设输出:**

* TLS连接成功建立，使用TLS 1.3协议和 ChaCha20-Poly1305 加密算法。
* 后续的网络数据传输将使用该协商好的加密方式进行保护。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误地假设支持的TLS版本或密码套件:**  开发者可能错误地假设所有Android设备都支持最新的TLS版本或特定的密码套件。如果服务器强制使用一个客户端不支持的协议或密码套件，连接将会失败。
    * **例子:** 应用程序硬编码只允许TLS 1.3，但在一些旧设备上可能只支持到TLS 1.2，导致连接失败。

2. **不正确的结构体大小使用:**  虽然开发者通常不会直接操作这些底层的结构体，但在一些特定的网络编程场景中，如果需要手动构建或解析TLS相关的数据，错误地假设结构体的大小或成员的偏移量可能会导致内存错误或数据解析失败。
    * **例子:**  在某些底层网络编程中，如果错误地计算了 `struct tls12_crypto_info_aes_gcm_128` 结构体的大小，可能会导致在内存操作时越界。

3. **忽略安全性最佳实践:** 开发者可能会错误地配置TLS选项，例如允许使用不安全的密码套件，或者禁用证书校验，从而引入安全漏洞。虽然这不直接与 `tls.h` 的定义相关，但理解这些底层的常量有助于开发者更好地理解TLS配置的重要性。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

**Android Framework 到达 `tls.h` 的步骤 (以 HTTPS 请求为例):**

1. **应用程序发起 HTTPS 请求:**  应用层使用 `HttpsURLConnection` 或 `OkHttp` 等发起请求。
2. **`HttpsURLConnection` / `OkHttp` 处理:** 这些类会处理URL解析、连接管理等。
3. **`SocketFactory` 创建 Socket:**  `HttpsURLConnection` 或 `OkHttp` 会使用 `SSLSocketFactory` 创建用于TLS/SSL连接的 `SSLSocket`。
4. **`SSLSocketFactory` 和 `SSLSocket` (Java层):**  这些Java层的类是对native层TLS/SSL实现的封装。
5. **Native 代码调用 (BoringSSL):**  `SSLSocket` 的方法最终会调用到Android的native TLS库 BoringSSL (位于 `libssl.so` 和 `libcrypto.so`)。
6. **系统调用:** BoringSSL 库会通过系统调用与内核的TLS实现进行交互，例如使用 `setsockopt()` 配置TLS选项，使用 `read()` 和 `write()` 进行加密数据的传输。
7. **内核 TLS 实现:**  内核根据 `setsockopt()` 设置的选项，以及在握手过程中协商的结果，使用 `tls.h` 中定义的常量和数据结构来管理TLS连接。

**NDK 到达 `tls.h` 的步骤:**

1. **NDK 应用使用 Socket API:** NDK 开发者可以使用 POSIX socket API 进行网络编程。
2. **设置 Socket 选项:**  开发者可以使用 `setsockopt()` 函数来配置socket的TLS选项。
3. **使用 `SOL_TLS` 族和 `TLS_*` 选项:**  在配置TLS时，会使用 `SOL_TLS` socket 族，并设置如 `TLS_TX`, `TLS_RX` 等选项，这些宏定义在 `tls.h` 中。
4. **系统调用:** `setsockopt()` 会触发相应的系统调用。
5. **内核处理:** 内核会解析这些选项，并使用 `tls.h` 中的定义来配置TLS连接。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook 调试 `setsockopt` 函数，观察与 TLS 相关的调用的示例：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "setsockopt"), {
    onEnter: function (args) {
        var sockfd = args[0].toInt32();
        var level = args[1].toInt32();
        var optname = args[2].toInt32();

        console.log("\\n[+] setsockopt called");
        console.log("    sockfd: " + sockfd);
        console.log("    level: " + level);
        console.log("    optname: " + optname);

        if (level === 283) { // SOL_TLS
            console.log("    -> SOL_TLS detected");
            if (optname === 1) { // TLS_SET_RECORD_TYPE
                console.log("    -> TLS_SET_RECORD_TYPE");
            } else if (optname === 2) { // TLS_GET_RECORD_TYPE
                console.log("    -> TLS_GET_RECORD_TYPE");
            } else {
                console.log("    -> Unknown TLS option");
            }
            // 可以进一步解析 optval (args[3]) 来查看具体的 TLS 配置信息
        }
    },
    onLeave: function (retval) {
        console.log("    Return value: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用说明:**

1. **替换包名:** 将 `package_name` 替换为你要调试的应用程序的包名。
2. **运行应用:** 确保你的目标应用正在运行。
3. **运行 Frida 脚本:** 运行这个 Python 脚本。
4. **观察输出:** 当应用程序进行网络请求时，Frida 会捕获 `setsockopt` 函数的调用，并打印相关的参数信息。特别是当 `level` 为 283 ( `SOL_TLS` 的值，需要根据你的系统查找) 时，说明正在设置TLS相关的socket选项。

**进一步调试:**

* 你可以修改 Frida 脚本，进一步解析 `optval` 参数 ( `args[3]` )，查看传递给 `setsockopt` 的具体的TLS配置信息，这可能会涉及到解析 `struct tls_crypto_info` 等结构体。
* 可以尝试 hook BoringSSL 库中的函数，例如与TLS握手、加密解密相关的函数，来更深入地了解TLS的实现细节。
* 可以结合 Wireshark 等网络抓包工具，分析实际的网络数据包，验证你的hook结果。

这个 `tls.h` 文件是Android安全通信的基石，理解其内容对于理解Android的网络安全机制至关重要。虽然开发者通常不会直接操作这些底层的定义，但了解它们可以帮助开发者更好地理解网络编程和安全最佳实践。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/tls.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_TLS_H
#define _UAPI_LINUX_TLS_H
#include <linux/types.h>
#define TLS_TX 1
#define TLS_RX 2
#define TLS_TX_ZEROCOPY_RO 3
#define TLS_RX_EXPECT_NO_PAD 4
#define TLS_VERSION_MINOR(ver) ((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver) (((ver) >> 8) & 0xFF)
#define TLS_VERSION_NUMBER(id) ((((id ##_VERSION_MAJOR) & 0xFF) << 8) | ((id ##_VERSION_MINOR) & 0xFF))
#define TLS_1_2_VERSION_MAJOR 0x3
#define TLS_1_2_VERSION_MINOR 0x3
#define TLS_1_2_VERSION TLS_VERSION_NUMBER(TLS_1_2)
#define TLS_1_3_VERSION_MAJOR 0x3
#define TLS_1_3_VERSION_MINOR 0x4
#define TLS_1_3_VERSION TLS_VERSION_NUMBER(TLS_1_3)
#define TLS_CIPHER_AES_GCM_128 51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE 8
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE 16
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE 4
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8
#define TLS_CIPHER_AES_GCM_256 52
#define TLS_CIPHER_AES_GCM_256_IV_SIZE 8
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_AES_GCM_256_SALT_SIZE 4
#define TLS_CIPHER_AES_GCM_256_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE 8
#define TLS_CIPHER_AES_CCM_128 53
#define TLS_CIPHER_AES_CCM_128_IV_SIZE 8
#define TLS_CIPHER_AES_CCM_128_KEY_SIZE 16
#define TLS_CIPHER_AES_CCM_128_SALT_SIZE 4
#define TLS_CIPHER_AES_CCM_128_TAG_SIZE 16
#define TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE 8
#define TLS_CIPHER_CHACHA20_POLY1305 54
#define TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE 12
#define TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE 32
#define TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE 0
#define TLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE 16
#define TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE 8
#define TLS_CIPHER_SM4_GCM 55
#define TLS_CIPHER_SM4_GCM_IV_SIZE 8
#define TLS_CIPHER_SM4_GCM_KEY_SIZE 16
#define TLS_CIPHER_SM4_GCM_SALT_SIZE 4
#define TLS_CIPHER_SM4_GCM_TAG_SIZE 16
#define TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE 8
#define TLS_CIPHER_SM4_CCM 56
#define TLS_CIPHER_SM4_CCM_IV_SIZE 8
#define TLS_CIPHER_SM4_CCM_KEY_SIZE 16
#define TLS_CIPHER_SM4_CCM_SALT_SIZE 4
#define TLS_CIPHER_SM4_CCM_TAG_SIZE 16
#define TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE 8
#define TLS_CIPHER_ARIA_GCM_128 57
#define TLS_CIPHER_ARIA_GCM_128_IV_SIZE 8
#define TLS_CIPHER_ARIA_GCM_128_KEY_SIZE 16
#define TLS_CIPHER_ARIA_GCM_128_SALT_SIZE 4
#define TLS_CIPHER_ARIA_GCM_128_TAG_SIZE 16
#define TLS_CIPHER_ARIA_GCM_128_REC_SEQ_SIZE 8
#define TLS_CIPHER_ARIA_GCM_256 58
#define TLS_CIPHER_ARIA_GCM_256_IV_SIZE 8
#define TLS_CIPHER_ARIA_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_ARIA_GCM_256_SALT_SIZE 4
#define TLS_CIPHER_ARIA_GCM_256_TAG_SIZE 16
#define TLS_CIPHER_ARIA_GCM_256_REC_SEQ_SIZE 8
#define TLS_SET_RECORD_TYPE 1
#define TLS_GET_RECORD_TYPE 2
struct tls_crypto_info {
  __u16 version;
  __u16 cipher_type;
};
struct tls12_crypto_info_aes_gcm_128 {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
  unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};
struct tls12_crypto_info_aes_gcm_256 {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
  unsigned char key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_AES_GCM_256_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE];
};
struct tls12_crypto_info_aes_ccm_128 {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_AES_CCM_128_IV_SIZE];
  unsigned char key[TLS_CIPHER_AES_CCM_128_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_AES_CCM_128_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE];
};
struct tls12_crypto_info_chacha20_poly1305 {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE];
  unsigned char key[TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE];
};
struct tls12_crypto_info_sm4_gcm {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_SM4_GCM_IV_SIZE];
  unsigned char key[TLS_CIPHER_SM4_GCM_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_SM4_GCM_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE];
};
struct tls12_crypto_info_sm4_ccm {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_SM4_CCM_IV_SIZE];
  unsigned char key[TLS_CIPHER_SM4_CCM_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_SM4_CCM_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE];
};
struct tls12_crypto_info_aria_gcm_128 {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_ARIA_GCM_128_IV_SIZE];
  unsigned char key[TLS_CIPHER_ARIA_GCM_128_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_ARIA_GCM_128_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_ARIA_GCM_128_REC_SEQ_SIZE];
};
struct tls12_crypto_info_aria_gcm_256 {
  struct tls_crypto_info info;
  unsigned char iv[TLS_CIPHER_ARIA_GCM_256_IV_SIZE];
  unsigned char key[TLS_CIPHER_ARIA_GCM_256_KEY_SIZE];
  unsigned char salt[TLS_CIPHER_ARIA_GCM_256_SALT_SIZE];
  unsigned char rec_seq[TLS_CIPHER_ARIA_GCM_256_REC_SEQ_SIZE];
};
enum {
  TLS_INFO_UNSPEC,
  TLS_INFO_VERSION,
  TLS_INFO_CIPHER,
  TLS_INFO_TXCONF,
  TLS_INFO_RXCONF,
  TLS_INFO_ZC_RO_TX,
  TLS_INFO_RX_NO_PAD,
  __TLS_INFO_MAX,
};
#define TLS_INFO_MAX (__TLS_INFO_MAX - 1)
#define TLS_CONF_BASE 1
#define TLS_CONF_SW 2
#define TLS_CONF_HW 3
#define TLS_CONF_HW_RECORD 4
#endif

"""

```
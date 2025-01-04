Response:
Let's break down the thought process for analyzing this C code and answering the prompt's questions.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for familiar keywords and patterns. I see:

* `#ifdef HAVE_NICE`: This immediately tells me this code is conditionally compiled, depending on whether `HAVE_NICE` is defined. This suggests the functionality within is optional or related to a specific feature.
* `#include`:  Standard C includes. The presence of `<openssl/...>`, `<usrsctp.h>`, and `"frida-base.h"` are key. OpenSSL relates to cryptography, `usrsctp` to the SCTP protocol, and `frida-base.h` indicates this is part of the Frida project.
* Function names prefixed with `frida_`: This is a strong indicator of Frida-specific functionality.
* `struct socket *`:  Pointers to socket structures, heavily suggesting network communication.
* `BIO *`:  OpenSSL's BIO (Basic Input/Output) abstraction, used for handling data streams.
* `X509 *`, `EVP_PKEY *`, `RSA *`:  OpenSSL structures for handling X.509 certificates, private keys, and RSA keys, respectively.
* `usrsctp_*`:  Functions from the usrsctp library, confirming the use of SCTP.
* `gchar *`, `guint8 *`, `gint`:  GLib types, common in projects that use GTK or related libraries. This signals a certain architectural style.
* `_frida_*`: Internal Frida functions, not intended for direct external use.

**2. Understanding the Core Functionality:**

Based on the includes and function names, the core purpose seems to be establishing secure, reliable communication using the SCTP protocol. The OpenSSL code points to the generation and handling of TLS certificates, likely for securing the SCTP connection.

**3. Analyzing Key Functions and Sections:**

Now, I start examining specific sections and functions:

* **Certificate Generation (`_frida_generate_certificate`):**  This is straightforward. It uses OpenSSL to create a self-signed X.509 certificate and its corresponding private key. The output is in both DER (binary) and PEM (textual) formats.
* **BIO Handling (`frida_steal_bio_to_string`):** A utility function to extract the content of an OpenSSL BIO into a string. The `g_steal_pointer` suggests memory management is handled by GLib.
* **SCTP Backend Initialization (`_frida_sctp_connection_initialize_sctp_backend`):** This section is crucial. It calls `usrsctp_init_nothreads` to initialize the usrsctp library. The numerous `usrsctp_sysctl_set_*` calls configure various SCTP parameters like buffer sizes, congestion control, and retransmission timeouts. This reveals a focus on fine-tuning SCTP behavior.
* **SCTP Output Callback (`frida_on_connection_output`):** This function is registered with usrsctp. It takes data being sent by the SCTP stack and calls `_frida_sctp_connection_emit_transport_packet`. This likely sends the data over the underlying transport mechanism (which is not explicitly shown in this file but would be elsewhere in Frida's codebase).
* **SCTP Debugging (`frida_on_debug_printf`):** A simple callback for printing SCTP debug messages to stderr.
* **SCTP Socket Creation (`_frida_sctp_connection_create_sctp_socket`):** Creates a usrsctp socket, sets up a callback for events (`frida_on_upcall`), and configures socket options like `SO_LINGER`, `SCTP_NODELAY`, and event notifications. The event notifications are important for receiving updates about the SCTP connection state.
* **SCTP Socket Connection (`_frida_sctp_connection_connect_sctp_socket`):**  Binds and connects the SCTP socket. The address family `AF_CONN` and the way the address is constructed suggest a connection within the same process or a virtualized environment, rather than a traditional network connection.
* **SCTP Upcall Handler (`frida_on_upcall`):** Called by usrsctp when socket events occur. It triggers `_frida_sctp_connection_on_sctp_socket_events_changed`, indicating that Frida's main logic needs to be informed about the event.
* **SCTP Close and Shutdown (`_frida_sctp_connection_close`, `_frida_sctp_connection_shutdown`):** Standard socket closing operations.
* **Querying Socket Events (`_frida_sctp_connection_query_sctp_socket_events`):**  Checks the usrsctp socket for pending read, write, or error events, translating them to GLib's `GIOCondition` flags.
* **Handling Incoming Packets (`_frida_sctp_connection_handle_transport_packet`):** Passes received data to the usrsctp stack for processing.
* **Receiving Data (`_frida_sctp_connection_recv`):** Uses `usrsctp_recvv` to receive data, including stream ID and protocol ID.
* **Sending Data (`_frida_sctp_connection_send`):**  Uses `usrsctp_sendv` to send data, specifying stream ID and protocol ID.
* **Timer Handling (`_frida_sctp_timer_source_get_timeout`, `_frida_sctp_timer_source_process_timers`):**  Integrates with a timer mechanism to allow usrsctp to perform its internal timer-based operations (like retransmissions).

**4. Answering the Prompt's Questions:**

With a good understanding of the code, I can now address each part of the prompt systematically:

* **Functionality:**  Summarize the main purposes of the code, focusing on secure communication using SCTP.
* **Relationship to Reverse Engineering:** Think about how this communication mechanism is relevant to dynamic instrumentation. The key is the ability to send commands to and receive data from the instrumented process. Give concrete examples of typical Frida use cases.
* **Binary/Kernel/Framework Aspects:** Identify areas that directly interact with low-level concepts. Focus on SCTP as a transport protocol, its position relative to TCP/UDP, and the implications of running within a process (using `AF_CONN`). Also mention the OpenSSL interaction for security.
* **Logical Deduction (Assumptions and Outputs):**  Choose a simple function (like the certificate generation) and illustrate how it works with example inputs (though it doesn't take explicit input) and outputs (DER/PEM data).
* **Common User Errors:** Consider scenarios where a developer might misuse the API provided by this code (even though it's internal). Focus on configuration mistakes or incorrect usage of related Frida APIs.
* **User Journey (Debugging):**  Trace the potential steps a user might take that would lead to this code being executed during a debugging session. This involves understanding Frida's architecture and how it connects to target processes.

**5. Refinement and Clarity:**

Finally, review the answers for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. Use precise terminology related to networking, security, and Frida.

This systematic approach, starting with a high-level overview and gradually drilling down into the details, allows for a comprehensive understanding of the code and facilitates answering the specific questions in the prompt. The key is to connect the technical details to the broader context of Frida's functionality and purpose.
这个C源文件 `p2p-glue.c` 是 Frida 动态 instrumentation 工具核心库 (`frida-core`) 的一部分，它主要负责建立和管理点对点 (Peer-to-Peer, P2P) 的通信连接，使用了 SCTP (Stream Control Transmission Protocol) 协议，并通过 OpenSSL 库提供安全连接所需的证书生成功能。

下面详细列举其功能，并根据要求进行说明：

**功能列表:**

1. **生成 TLS 证书和密钥:**
   - `_frida_generate_certificate`:  使用 OpenSSL 库生成自签名 X.509 证书和 RSA 私钥，输出为 DER 编码的证书数据、PEM 格式的证书字符串和 PEM 格式的私钥字符串。这用于在 P2P 连接中建立安全通道。

2. **初始化 SCTP 后端:**
   - `_frida_sctp_connection_initialize_sctp_backend`:  初始化 `usrsctp` 库，这是一个用户空间的 SCTP 协议栈实现。
   - 设置各种 SCTP 相关的系统级参数，例如发送/接收缓冲区大小、拥塞控制、重传超时时间等。

3. **处理 SCTP 连接的输出:**
   - `frida_on_connection_output`:  作为 `usrsctp` 的回调函数，当 SCTP 连接需要发送数据时被调用。它将数据传递给 Frida 的其他部分进行传输。

4. **处理 SCTP 调试信息:**
   - `frida_on_debug_printf`:  作为 `usrsctp` 的回调函数，用于接收和打印 SCTP 协议栈的调试信息。

5. **创建 SCTP 套接字:**
   - `_frida_sctp_connection_create_sctp_socket`:  创建一个 `usrsctp` 的套接字，并进行必要的配置：
     - 注册地址。
     - 设置接收数据的回调函数 `frida_on_upcall`。
     - 设置为非阻塞模式。
     - 设置 `SO_LINGER` 选项。
     - 禁用 Nagle 算法 (`SCTP_NODELAY`)。
     - 启用需要接收的 SCTP 事件通知。
     - 启用流重置和关联变更请求。

6. **连接 SCTP 套接字:**
   - `_frida_sctp_connection_connect_sctp_socket`:  将 SCTP 套接字绑定到指定的端口，并尝试连接到相同的地址和端口。注意这里使用的是 `AF_CONN` 地址族，暗示这可能是在进程内部或者某种虚拟网络环境下的连接。

7. **处理 SCTP 套接字事件:**
   - `frida_on_upcall`:  作为 `usrsctp` 的回调函数，当 SCTP 套接字上有事件发生（如数据到达、连接状态改变）时被调用，通知 Frida 的其他部分。

8. **关闭和关闭 SCTP 连接:**
   - `_frida_sctp_connection_close`:  关闭 SCTP 套接字。
   - `_frida_sctp_connection_shutdown`:  优雅地关闭 SCTP 连接。

9. **查询 SCTP 套接字事件:**
   - `_frida_sctp_connection_query_sctp_socket_events`:  查询 SCTP 套接字上的待处理事件，用于集成到 GLib 的事件循环中。

10. **处理接收到的传输数据包:**
    - `_frida_sctp_connection_handle_transport_packet`: 将接收到的数据包传递给 `usrsctp` 协议栈进行处理。

11. **接收 SCTP 数据:**
    - `_frida_sctp_connection_recv`:  使用 `usrsctp_recvv` 从 SCTP 套接字接收数据，并获取流 ID、协议 ID 和消息标志。

12. **发送 SCTP 数据:**
    - `_frida_sctp_connection_send`:  使用 `usrsctp_sendv` 通过 SCTP 套接字发送数据，可以指定流 ID 和协议 ID。

13. **处理 SCTP 定时器:**
    - `_frida_sctp_timer_source_get_timeout`:  获取 `usrsctp` 需要的定时器超时时间。
    - `_frida_sctp_timer_source_process_timers`:  通知 `usrsctp` 处理到期的定时器事件。

**与逆向方法的关系及举例说明:**

这个文件是 Frida 实现其核心通信机制的关键部分。在动态逆向中，Frida 需要与目标进程建立可靠且安全的通信通道，以便：

* **注入代码:**  将 JavaScript 或其他代码注入到目标进程中执行。
* **拦截函数调用:**  在目标进程的关键函数执行前后插入代码，获取参数、修改返回值等。
* **读取和修改内存:**  访问目标进程的内存空间。
* **接收目标进程的事件:**  监听目标进程的特定事件。

SCTP 作为一个可靠的、面向连接的传输协议，比传统的 TCP 或 UDP 更适合某些场景，因为它支持多宿主、多流等特性。使用 OpenSSL 进行加密确保了通信的安全性，防止敏感信息泄露或被篡改。

**举例说明:**

假设逆向工程师想要拦截 Android 应用中的一个特定函数 `calculateSum(int a, int b)`，并查看其参数和返回值。

1. Frida Agent (通常用 JavaScript 编写) 通过某种方式指示 Frida Core 需要执行拦截操作。
2. Frida Core 内部会使用 `p2p-glue.c` 中实现的 SCTP 连接将拦截请求发送到目标进程中的 Frida Agent。
3. 目标进程中的 Frida Agent 接收到请求后，会在 `calculateSum` 函数入口和出口处设置 hook。
4. 当目标进程调用 `calculateSum` 时，hook 代码会被执行，并将参数 `a` 和 `b` 的值通过 SCTP 连接发送回控制 Frida 的主机。
5. `calculateSum` 执行完毕后，hook 代码会将返回值通过相同的 SCTP 连接发送回主机。
6. 逆向工程师可以在主机上看到拦截到的参数和返回值。

**涉及到二进制底层、Linux、Android内核及框架的知识及举例说明:**

1. **二进制底层:**
   - **内存操作:** 虽然这个文件本身不直接操作目标进程的内存，但它建立的通信通道是 Frida 进行内存读写的基础。例如，逆向工程师可以使用 Frida 读取目标进程中某个对象的成员变量，这个操作最终会通过这里建立的 SCTP 连接发送请求和接收响应。
   - **指令注入:** 同样，将 JavaScript 代码编译成机器码并注入到目标进程，也依赖这个通信通道传递指令。

2. **Linux:**
   - **用户空间网络协议栈 (`usrsctp`):**  `p2p-glue.c` 使用了 `usrsctp` 库，这是一个在用户空间实现的 SCTP 协议栈。这避免了修改内核的需要，使得 Frida 更加灵活和易于部署。
   - **套接字编程:**  代码中使用了标准的套接字 API (尽管是 `usrsctp` 提供的)，例如 `usrsctp_socket`, `usrsctp_bind`, `usrsctp_connect`, `usrsctp_sendv`, `usrsctp_recvv` 等，这些都是 Linux 网络编程的基础概念。
   - **错误处理 (`errno`):**  代码中使用了 `errno` 来获取系统调用的错误码，并使用 `g_strerror` 将其转换为可读的错误信息。

3. **Android 内核及框架:**
   - **进程间通信 (IPC):**  虽然这个文件专注于 P2P 通信，但在 Android 环境下，Frida 可能需要与目标应用的其他组件或服务进行交互，这涉及到 Android 的 Binder 机制等 IPC 技术。虽然 `p2p-glue.c` 不直接处理 Binder，但它为 Frida Agent 与 Frida Core 之间的主要通信提供了基础，而 Frida Agent 可能会使用 Binder 与其他组件交互。
   - **动态链接和加载:** Frida Agent 通常以动态库的形式注入到目标进程中，这涉及到 Android 的动态链接器 (`linker`) 和加载器 (`ClassLoader`)。

**逻辑推理、假设输入与输出:**

考虑函数 `_frida_generate_certificate`:

**假设输入:** 无显式输入参数。该函数依赖于 OpenSSL 库的内部逻辑生成证书。

**逻辑推理:**
1. 创建一个新的 X.509 证书对象。
2. 设置证书的序列号、有效期等基本信息。
3. 设置证书的主题和颁发者信息 (这里都设置为 "Frida" 和 "lolcathost")。
4. 创建 RSA 密钥对。
5. 将公钥设置到证书中。
6. 使用私钥对证书进行签名。
7. 将证书和私钥编码为 DER 和 PEM 格式的字符串。

**输出:**
- `cert_der`:  指向 DER 编码的证书数据的指针。
- `cert_der_length`: DER 编码的证书数据的长度。
- `cert_pem`:  指向 PEM 格式的证书字符串的指针，例如：
  ```pem
  -----BEGIN CERTIFICATE-----
  MII...<base64 encoded certificate data>...
  -----END CERTIFICATE-----
  ```
- `key_pem`: 指向 PEM 格式的私钥字符串的指针，例如：
  ```pem
  -----BEGIN PRIVATE KEY-----
  MII...<base64 encoded private key data>...
  -----END PRIVATE KEY-----
  ```

**涉及用户或编程常见的使用错误及举例说明:**

由于 `p2p-glue.c` 是 Frida 内部的实现细节，普通用户或逆向工程师通常不会直接调用这些函数。然而，如果 Frida 的开发者在使用这些函数时出现错误，可能会导致以下问题：

1. **SCTP 配置错误:**  如果在初始化 SCTP 后端时设置了不合理的参数 (例如，过小的缓冲区大小、过短的重传超时时间)，可能导致连接不稳定、数据丢失或性能下降。
   - **例子:**  错误地设置 `usrsctp_sysctl_set_sctp_rto_min_default` 为一个非常小的值，可能导致不必要的重传，增加网络拥塞。

2. **证书生成错误:**  虽然 `_frida_generate_certificate` 相对简单，但如果 OpenSSL 库出现问题或配置不当，可能导致生成的证书无效或不安全。
   - **例子:**  如果由于某种原因，生成的 RSA 密钥长度不足 (例如，少于 2048 位)，则安全性会降低。

3. **套接字操作错误:**  在创建、连接、发送或接收 SCTP 数据时出现错误，例如忘记绑定地址、连接失败、发送或接收数据时缓冲区大小不匹配等。
   - **例子:**  在调用 `_frida_sctp_connection_send` 时，`data_length` 与实际要发送的数据长度不符，可能导致数据截断或发送错误。

4. **内存管理错误:**  代码中使用了 GLib 的内存管理函数，例如 `g_memdup2` 和 `g_steal_pointer`。如果使用不当，可能导致内存泄漏或 double-free 等问题。
   - **例子:**  如果在 `frida_steal_bio_to_string` 中，`BIO_free` 被调用了两次 (尽管代码中使用了 `g_steal_pointer` 来避免这种情况)，就会导致 double-free。

**用户操作是如何一步步的到达这里，作为调试线索:**

一个典型的用户操作流程，最终会涉及到 `p2p-glue.c` 中的代码执行，可能是这样的：

1. **用户启动 Frida 进行动态 instrumentation:**  用户在终端或通过脚本运行 Frida 命令，例如 `frida -U -f com.example.app`. 这会指示 Frida 连接到目标 Android 设备上的 `com.example.app` 应用。

2. **Frida Core 初始化:**  Frida 核心库开始初始化，其中包括初始化通信机制。如果启用了 P2P 通信 (这通常是默认选项或在特定场景下使用)，则会调用 `_frida_sctp_connection_initialize_sctp_backend` 来设置 SCTP 后端。

3. **生成证书 (首次连接):**  如果这是 Frida 首次连接到目标设备或进程，或者之前的证书已过期，Frida Core 会调用 `_frida_generate_certificate` 生成用于安全通信的 TLS 证书和密钥。

4. **创建 SCTP 连接:**  Frida Core 会调用 `_frida_sctp_connection_create_sctp_socket` 创建一个 SCTP 套接字，并使用 `_frida_sctp_connection_connect_sctp_socket` 尝试连接到目标进程中的 Frida Agent。

5. **Frida Agent 注入:**  Frida 会将 Frida Agent (一个动态链接库) 注入到目标进程中。

6. **建立 P2P 连接:**  注入的 Frida Agent 也会创建一个 SCTP 套接字，并尝试与 Frida Core 创建的套接字建立连接。这个连接的建立过程会涉及到 `frida_on_connection_output` (在发送数据时) 和 `frida_on_upcall` (在接收事件时) 等回调函数的调用。

7. **发送和接收 instrumentation 命令:**  一旦连接建立，用户在主机上通过 Frida 的 API (例如，使用 Python 绑定) 发出的 instrumentation 命令 (例如，hook 函数、读取内存) 会被序列化并通过 SCTP 连接发送到目标进程中的 Frida Agent。这会调用 `_frida_sctp_connection_send`。

8. **处理目标进程的响应:**  目标进程中的 Frida Agent 执行完 instrumentation 操作后，会将结果 (例如，hook 到的函数参数、读取到的内存数据) 通过 SCTP 连接发送回 Frida Core。这会触发 `_frida_sctp_connection_handle_transport_packet` 和 `_frida_sctp_connection_recv`。

9. **用户交互:**  Frida Core 接收到目标进程的响应后，会将结果呈现给用户。

**调试线索:**

如果在 Frida 的使用过程中遇到连接问题、数据传输错误或安全问题，可以考虑以下调试线索，这些都与 `p2p-glue.c` 的功能相关：

- **检查 SCTP 配置:**  查看 Frida 的日志或配置，确认 SCTP 相关的参数是否合理。
- **验证证书:**  检查生成的证书是否有效，是否被信任。
- **监控网络流量:**  使用网络抓包工具 (如 Wireshark) 监控 Frida Core 和 Frida Agent 之间的网络通信，查看 SCTP 连接的建立和数据传输过程。
- **查看 Frida 的调试输出:**  Frida 可能会输出与 SCTP 相关的调试信息 (通过 `frida_on_debug_printf`)，这些信息可以帮助定位问题。
- **检查错误码:**  关注 `_frida_sctp_connection_send` 和 `_frida_sctp_connection_recv` 等函数返回的错误码，以及 `errno` 的值，以了解底层的错误原因。

总而言之，`p2p-glue.c` 是 Frida 实现可靠和安全 P2P 通信的关键组件，它利用了用户空间的 SCTP 协议栈和 OpenSSL 库来满足动态 instrumentation 的需求。理解这个文件的功能有助于深入理解 Frida 的内部工作机制，并为调试相关问题提供线索。

Prompt: 
```
这是目录为frida/subprojects/frida-core/lib/base/p2p-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#ifdef HAVE_NICE

#define OPENSSL_SUPPRESS_DEPRECATED

#include "frida-base.h"

#include <errno.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <usrsctp.h>

static gchar * frida_steal_bio_to_string (BIO ** bio);

static int frida_on_connection_output (void * addr, void * buffer, size_t length, uint8_t tos, uint8_t set_df);
static void frida_on_debug_printf (const char * format, ...);

static void frida_on_upcall (struct socket * sock, void * user_data, int flags);

void
_frida_generate_certificate (guint8 ** cert_der, gint * cert_der_length, gchar ** cert_pem, gchar ** key_pem)
{
  X509 * x509;
  X509_NAME * name;
  EVP_PKEY * pkey;
  BIGNUM * e;
  RSA * rsa;
  BIO * bio;
  guint8 * der;
  long n;

  x509 = X509_new ();

  ASN1_INTEGER_set (X509_get_serialNumber (x509), 1);
  X509_gmtime_adj (X509_get_notBefore (x509), 0);
  X509_gmtime_adj (X509_get_notAfter (x509), 15780000);

  name = X509_get_subject_name (x509);
  X509_NAME_add_entry_by_txt (name, "C", MBSTRING_ASC, (const unsigned char *) "CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt (name, "O", MBSTRING_ASC, (const unsigned char *) "Frida", -1, -1, 0);
  X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC, (const unsigned char *) "lolcathost", -1, -1, 0);
  X509_set_issuer_name (x509, name);

  pkey = EVP_PKEY_new ();
  e = BN_new ();
  BN_set_word (e, RSA_F4);
  rsa = RSA_new ();
  RSA_generate_key_ex (rsa, 2048, e, NULL);
  EVP_PKEY_set1_RSA (pkey, g_steal_pointer (&rsa));
  BN_free (e);
  X509_set_pubkey (x509, pkey);

  X509_sign (x509, pkey, EVP_sha256 ());

  bio = BIO_new (BIO_s_mem ());
  i2d_X509_bio (bio, x509);
  n = BIO_get_mem_data (bio, (guint8 **) &der);
  *cert_der = g_memdup2 (der, n);
  *cert_der_length = n;
  BIO_free (g_steal_pointer (&bio));

  bio = BIO_new (BIO_s_mem ());
  PEM_write_bio_X509 (bio, x509);
  *cert_pem = frida_steal_bio_to_string (&bio);

  bio = BIO_new (BIO_s_mem ());
  PEM_write_bio_PrivateKey (bio, pkey, NULL, NULL, 0, NULL, NULL);
  *key_pem = frida_steal_bio_to_string (&bio);

  EVP_PKEY_free (pkey);
  X509_free (x509);
}

static gchar *
frida_steal_bio_to_string (BIO ** bio)
{
  gchar * result;
  long n;
  char * str;

  n = BIO_get_mem_data (*bio, &str);
  result = g_strndup (str, n);

  BIO_free (g_steal_pointer (bio));

  return result;
}

void
_frida_sctp_connection_initialize_sctp_backend (void)
{
  const int msec_per_sec = 1000;

  usrsctp_init_nothreads (0, frida_on_connection_output, frida_on_debug_printf);

  usrsctp_sysctl_set_sctp_sendspace (256 * 1024);
  usrsctp_sysctl_set_sctp_recvspace (256 * 1024);

  usrsctp_sysctl_set_sctp_ecn_enable (FALSE);
  usrsctp_sysctl_set_sctp_pr_enable (TRUE);
  usrsctp_sysctl_set_sctp_auth_enable (FALSE);
  usrsctp_sysctl_set_sctp_asconf_enable (FALSE);

  usrsctp_sysctl_set_sctp_max_burst_default (10);

  usrsctp_sysctl_set_sctp_max_chunks_on_queue (10 * 1024);

  usrsctp_sysctl_set_sctp_delayed_sack_time_default (20);

  usrsctp_sysctl_set_sctp_heartbeat_interval_default (10 * msec_per_sec);

  usrsctp_sysctl_set_sctp_rto_max_default (10 * msec_per_sec);
  usrsctp_sysctl_set_sctp_rto_min_default (1 * msec_per_sec);
  usrsctp_sysctl_set_sctp_rto_initial_default (1 * msec_per_sec);
  usrsctp_sysctl_set_sctp_init_rto_max_default (10 * msec_per_sec);

  usrsctp_sysctl_set_sctp_init_rtx_max_default (5);
  usrsctp_sysctl_set_sctp_assoc_rtx_max_default (5);
  usrsctp_sysctl_set_sctp_path_rtx_max_default (5);

  usrsctp_sysctl_set_sctp_nr_outgoing_streams_default (1024);

  usrsctp_sysctl_set_sctp_initial_cwnd (10);
}

static int
frida_on_connection_output (void * addr, void * buffer, size_t length, uint8_t tos, uint8_t set_df)
{
  FridaSctpConnection * connection = addr;

  _frida_sctp_connection_emit_transport_packet (connection, buffer, (gint) length);

  return 0;
}

static void
frida_on_debug_printf (const char * format, ...)
{
  g_printerr ("[SCTP] %s\n", format);
}

void *
_frida_sctp_connection_create_sctp_socket (FridaSctpConnection * self)
{
  struct socket * sock;
  struct linger linger;
  int nodelay;
  struct sctp_event ev;
  const uint16_t event_types[] = {
    SCTP_ASSOC_CHANGE,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_REMOTE_ERROR,
    SCTP_SHUTDOWN_EVENT,
    SCTP_ADAPTATION_INDICATION,
    SCTP_STREAM_RESET_EVENT,
    SCTP_SENDER_DRY_EVENT,
    SCTP_STREAM_CHANGE_EVENT,
    SCTP_SEND_FAILED_EVENT,
  };
  guint i;
  int recv_rcvinfo;
  struct sctp_assoc_value assoc;

  usrsctp_register_address (self);

  sock = usrsctp_socket (AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
  usrsctp_set_upcall (sock, frida_on_upcall, self);
  usrsctp_set_non_blocking (sock, TRUE);

  linger.l_onoff = TRUE;
  linger.l_linger = 0;
  usrsctp_setsockopt (sock, SOL_SOCKET, SO_LINGER, &linger, sizeof (linger));

  nodelay = TRUE;
  usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof (nodelay));

  ev.se_assoc_id = SCTP_ALL_ASSOC;
  ev.se_on = TRUE;
  for (i = 0; i != G_N_ELEMENTS (event_types); i++)
  {
    ev.se_type = event_types[i];
    usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof (ev));
  }

  recv_rcvinfo = TRUE;
  usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &recv_rcvinfo, sizeof (recv_rcvinfo));

  assoc.assoc_id = SCTP_ALL_ASSOC;
  assoc.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
  usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc, sizeof (assoc));

  return sock;
}

void
_frida_sctp_connection_connect_sctp_socket (FridaSctpConnection * self, void * sock, guint16 port)
{
  struct sockaddr_conn addr;

#ifdef HAVE_SCONN_LEN
  addr.sconn_len = sizeof (addr);
#endif
  addr.sconn_family = AF_CONN;
  addr.sconn_port = htons (port);
  addr.sconn_addr = self;

  usrsctp_bind (sock, (struct sockaddr *) &addr, sizeof (addr));

  usrsctp_connect (sock, (struct sockaddr *) &addr, sizeof (addr));
}

static void
frida_on_upcall (struct socket * sock, void * user_data, int flags)
{
  FridaSctpConnection * connection = user_data;

  _frida_sctp_connection_on_sctp_socket_events_changed (connection);
}

void
_frida_sctp_connection_close (void * sock)
{
  usrsctp_close (sock);
}

void
_frida_sctp_connection_shutdown (void * sock, FridaSctpShutdownType type, GError ** error)
{
  if (usrsctp_shutdown (sock, type) == -1)
  {
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "%s", g_strerror (errno));
  }
}

GIOCondition
_frida_sctp_connection_query_sctp_socket_events (void * sock)
{
  GIOCondition condition = 0;
  int events;

  events = usrsctp_get_events (sock);

  if ((events & SCTP_EVENT_READ) != 0)
    condition |= G_IO_IN;

  if ((events & SCTP_EVENT_WRITE) != 0)
    condition |= G_IO_OUT;

  if ((events & SCTP_EVENT_ERROR) != 0)
    condition |= G_IO_ERR;

  return condition;
}

void
_frida_sctp_connection_handle_transport_packet (FridaSctpConnection * self, guint8 * data, gint data_length)
{
  usrsctp_conninput (self, data, data_length, 0);
}

gssize
_frida_sctp_connection_recv (void * sock, guint8 * buffer, gint buffer_length, guint16 * stream_id, FridaPayloadProtocolId * protocol_id,
    FridaSctpMessageFlags * message_flags, GError ** error)
{
  gssize n;
  struct sockaddr_conn from;
  socklen_t from_length;
  struct sctp_rcvinfo info;
  socklen_t info_length;
  unsigned int info_type;
  int msg_flags;

  from_length = sizeof (from);
  info_length = sizeof (info);
  info_type = SCTP_RECVV_NOINFO;
  msg_flags = 0;

  n = usrsctp_recvv (sock, buffer, buffer_length, (struct sockaddr *) &from, &from_length, &info, &info_length, &info_type, &msg_flags);
  if (n == -1)
    goto propagate_usrsctp_error;

  if (info_type == SCTP_RECVV_RCVINFO)
  {
    *stream_id = info.rcv_sid;
    *protocol_id = ntohl (info.rcv_ppid);
  }
  else
  {
    *stream_id = 0;
    *protocol_id = FRIDA_PAYLOAD_PROTOCOL_ID_NONE;
  }

  *message_flags = 0;

  if ((msg_flags & MSG_EOR) != 0)
    *message_flags |= FRIDA_SCTP_MESSAGE_FLAGS_END_OF_RECORD;

  if ((msg_flags & MSG_NOTIFICATION) != 0)
    *message_flags |= FRIDA_SCTP_MESSAGE_FLAGS_NOTIFICATION;

  return n;

propagate_usrsctp_error:
  {
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "%s", g_strerror (errno));
    return -1;
  }
}

gssize
_frida_sctp_connection_send (void * sock, guint16 stream_id, FridaPayloadProtocolId protocol_id, guint8 * data, gint data_length,
      GError ** error)
{
  gssize n;
  struct sctp_sendv_spa spa;
  struct sctp_sndinfo * si;

  spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

  si = &spa.sendv_sndinfo;
  si->snd_sid = stream_id;
  si->snd_flags = SCTP_EOR;
  si->snd_ppid = htonl (protocol_id);
  si->snd_context = 0;
  si->snd_assoc_id = 0;

  n = usrsctp_sendv (sock, data, data_length, NULL, 0, &spa, sizeof (spa), SCTP_SENDV_SPA, 0);
  if (n == -1)
    goto propagate_usrsctp_error;

  return n;

propagate_usrsctp_error:
  {
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "%s", g_strerror (errno));
    return -1;
  }
}

gint
_frida_sctp_timer_source_get_timeout (void)
{
  return usrsctp_get_timeout ();
}

void
_frida_sctp_timer_source_process_timers (guint32 elapsed_msec)
{
  usrsctp_handle_timers (elapsed_msec);
}

#endif /* HAVE_NICE */

"""

```
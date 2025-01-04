Response:
The user wants a summary of the functionalities of the `ssl_server_socket_impl.cc` file in the Chromium network stack.

Here's a breakdown of the thought process to generate the response:

1. **Understand the Core Functionality:** The filename `ssl_server_socket_impl.cc` immediately suggests this file implements the server-side logic for establishing and managing SSL/TLS connections. It's the counterpart to a client-side SSL socket implementation.

2. **Identify Key Classes and Methods:** The code defines `SSLServerContextImpl::SocketImpl`, which is the central class implementing the `SSLServerSocket` interface. Its methods reveal the key actions it performs:
    * `Handshake()`:  Negotiates the SSL/TLS connection.
    * `Read()`, `Write()`:  Handles secure data transfer.
    * `ExportKeyingMaterial()`:  Exports keying material for other protocols.
    * Callbacks like `CertVerifyCallback`, `PrivateKeySignCallback`, `ALPNSelectCallback`: These are critical for server-side SSL/TLS behavior, handling certificate verification, private key operations, and ALPN negotiation.

3. **Categorize Functionalities:**  Group the identified functionalities into logical categories:
    * **Core SSL/TLS Management:** Handshake, connection establishment, shutdown.
    * **Data Transfer:** Secure reading and writing of data.
    * **Configuration and Callbacks:** Handling server certificates, private keys, client certificate verification, ALPN negotiation, application settings.
    * **Socket Operations:** Implementing the underlying socket interface (delegating to a `StreamSocket`).
    * **Internal State Management:** Tracking handshake progress, connection status.

4. **Relate to JavaScript (if applicable):** Consider how these server-side functionalities interact with the browser's JavaScript environment. JavaScript uses WebSockets and Fetch API over HTTPS. The server-side SSL/TLS implementation is crucial for establishing the secure connection that these APIs rely on. Crucially, the details *within* this file are mostly abstracted away from JavaScript. JavaScript initiates the connection, but the low-level SSL/TLS mechanics are handled by the browser's networking code, including this component.

5. **Consider Logic and Input/Output (Hypothetical):** Think about how the methods would behave with specific inputs. For example, with `Handshake()`:
    * **Input:** A raw socket connection.
    * **Output (Successful):** A secure, encrypted connection ready for data transfer.
    * **Output (Failure):** An error indicating the handshake couldn't complete (e.g., invalid certificate).
    For `Read()`/`Write()`:
    * **Input (Read):** An empty buffer.
    * **Output (Successful):** The buffer filled with decrypted data.
    * **Input (Write):** A buffer containing data to send.
    * **Output (Successful):** The data sent securely.

6. **Identify Potential User/Programming Errors:** Think about common mistakes developers or users might make that would lead to issues involving this code:
    * Incorrect server certificate configuration.
    * Missing or invalid private key.
    * Mismatched ALPN protocols.
    * Problems with client certificate verification setup.

7. **Trace User Actions to the Code:**  Consider the sequence of steps a user might take in a browser that would lead to this code being executed:
    * User types a URL starting with `https://`.
    * The browser initiates a TCP connection to the server.
    * The browser then starts the TLS handshake. The server-side of that handshake is handled (in part) by this code.

8. **Structure the Response:** Organize the information clearly with headings and bullet points for readability.

9. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Make sure the language is precise and avoids jargon where possible. Specifically for the "Part 1" request, focus on summarizing the *overall* function.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the individual methods.
* **Correction:**  Shift focus to the *purpose* of those methods and how they contribute to the overall goal of establishing a secure server connection.
* **Initial thought:** Provide highly technical details about OpenSSL functions.
* **Correction:**  Keep the explanation at a higher level, focusing on the concepts rather than the specific OpenSSL API calls (unless directly relevant to the functionality description).
* **Initial thought:** Overemphasize the JavaScript connection.
* **Correction:**  Clarify that the direct interaction is limited to initiating the secure connection, and the low-level details are abstracted.
好的，这是对 `net/socket/ssl_server_socket_impl.cc` 文件第一部分的分析和功能归纳：

**文件功能概述:**

`ssl_server_socket_impl.cc` 文件实现了 Chromium 网络栈中 **SSL/TLS 服务器端 Socket** 的具体逻辑。它负责处理服务器端 SSL/TLS 连接的建立（握手）、安全数据的收发以及相关的配置和管理。

**具体功能点:**

1. **实现 `SSLServerSocket` 接口:**  该文件中的 `SSLServerContextImpl::SocketImpl` 类继承并实现了 `SSLServerSocket` 接口，提供了服务器端 SSL Socket 的标准操作方法。

2. **SSL/TLS 握手 (Handshake):**
   -  负责与客户端进行 SSL/TLS 握手协商，包括协议版本、加密套件、证书交换等。
   -  `Handshake()` 方法是握手的入口点。
   -  内部通过 `SSL_set_accept_state()` 将 OpenSSL 的 SSL 对象设置为服务器模式。
   -  `DoHandshakeLoop()` 和 `DoHandshake()` 负责执行握手的状态机流程。
   -  处理异步的私钥操作（签名）通过 `PrivateKeySignCallback` 等回调函数。

3. **安全数据收发 (Read/Write):**
   -  在握手成功后，使用 OpenSSL 提供的 API (`SSL_read`, `SSL_write`) 进行加密数据的读取和发送。
   -  `Read()` 和 `ReadIfReady()` 方法用于从安全连接读取数据。
   -  `Write()` 方法用于向安全连接写入数据。
   -  通过 `SocketBIOAdapter` 将底层的 `StreamSocket` 的 I/O 事件与 OpenSSL 的 BIO 对象关联起来，实现非阻塞的 I/O 操作。
   -  `OnReadReady()` 和 `OnWriteReady()` 方法处理底层 Socket 的可读写事件，驱动 SSL 层的 I/O 操作。

4. **配置和管理:**
   -  初始化 OpenSSL 的 SSL 上下文 (`SSL_CTX`) 和 SSL 对象 (`SSL`)。
   -  设置服务器证书和私钥。
   -  处理 ALPN (应用层协议协商) 通过 `ALPNSelectCallback`。
   -  处理客户端证书验证通过 `CertVerifyCallback`。
   -  支持导出密钥材料 (`ExportKeyingMaterial`)，用于其他安全协议。

5. **连接状态管理:**
   -  维护连接的状态，例如是否已连接 (`IsConnected`)，是否空闲 (`IsConnectedAndIdle`)。
   -  记录协商的协议 (`GetNegotiatedProtocol`)。
   -  获取对端应用层设置 (`GetPeerApplicationSettings`)。
   -  获取 SSL 连接信息 (`GetSSLInfo`)，例如使用的加密套件、协议版本、客户端证书等。

6. **底层 Socket 操作:**
   -  封装了底层的 `StreamSocket`，并将其用于实际的网络数据传输。
   -  实现了 `StreamSocket` 接口中的 `Connect`, `Disconnect`, `GetPeerAddress`, `GetLocalAddress` 等方法，并委托给底层的 `transport_socket_`。

**与 JavaScript 的关系及举例说明:**

`ssl_server_socket_impl.cc` 的功能是服务器端的，直接与 JavaScript 代码没有直接的调用关系。但是，当浏览器中的 JavaScript 代码发起一个安全的 HTTPS 请求或者建立一个安全的 WebSocket 连接时，服务器端会使用这个文件中的代码来处理 SSL/TLS 握手和加密通信。

**举例说明:**

1. **HTTPS 请求:**
   -  当 JavaScript 代码使用 `fetch()` API 请求一个 `https://example.com` 的资源时，浏览器会建立一个到 `example.com` 服务器的安全连接。
   -  服务器端的网络栈会使用 `SSLServerContextImpl::SocketImpl` 来处理与浏览器之间的 TLS 握手，协商加密参数，验证服务器证书。
   -  握手成功后，服务器使用该 Socket 接收来自浏览器的加密 HTTP 请求，解密后处理，并将加密的 HTTP 响应发送回浏览器。

2. **安全 WebSocket 连接 (wss://):**
   -  当 JavaScript 代码创建一个 `WebSocket` 对象连接到 `wss://example.com/socket` 时，也会建立一个安全的 TLS 连接。
   -  服务器端的 `SSLServerContextImpl::SocketImpl` 会参与到 WebSocket 的握手过程中，确保通信的安全性。
   -  后续的 WebSocket 消息的发送和接收都会通过这个安全的连接进行加密和解密。

**逻辑推理，假设输入与输出:**

**假设输入 (针对 `Handshake()` 方法):**

*   一个已建立的 TCP 连接的 `StreamSocket` 对象。
*   服务器配置信息，包括证书、私钥、支持的协议等。

**预期输出 (针对 `Handshake()` 方法):**

*   **成功:** 返回 `net::OK`，内部的 OpenSSL `SSL` 对象状态变为已连接，`completed_handshake_` 标志为 true。后续可以使用 `Read()` 和 `Write()` 进行安全数据传输。
*   **失败:** 返回一个 `net::Error` 代码，例如 `net::ERR_SSL_PROTOCOL_ERROR` (协议错误), `net::ERR_CERT_AUTHORITY_INVALID` (证书无效) 等。

**假设输入 (针对 `Read()` 方法):**

*   一个已连接的 `SSLServerContextImpl::SocketImpl` 对象。
*   一个用于接收数据的 `IOBuffer` 对象。
*   期望读取的数据长度。

**预期输出 (针对 `Read()` 方法):**

*   **成功:** 返回实际读取到的数据长度 (大于 0)。`IOBuffer` 中填充了解密后的数据。
*   **无数据可读 (但连接正常):** 返回 `net::ERR_IO_PENDING` (如果底层是非阻塞 Socket)，或者阻塞等待数据。
*   **连接关闭:** 返回 `net::OK` (表示对端正常关闭) 或其他表示连接错误的 `net::Error` 代码。

**涉及用户或编程常见的使用错误及举例说明:**

1. **服务器证书配置错误:**
   - **错误:** 服务器配置了错误的证书或私钥，例如证书域名与服务器域名不匹配，或者私钥与证书不匹配。
   - **后果:** 客户端连接时会收到证书无效的错误，例如 `net::ERR_CERT_COMMON_NAME_INVALID` 或 `net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH`。
   - **用户操作:** 用户尝试访问 HTTPS 网站时，浏览器会显示安全警告或直接阻止访问。

2. **私钥权限问题:**
   - **错误:** 运行服务器进程的用户没有读取私钥文件的权限。
   - **后果:** 服务器启动失败或在 SSL/TLS 握手过程中无法完成签名操作，导致连接失败。
   - **调试线索:** 服务器日志中可能会出现关于无法访问私钥文件的错误信息。

3. **ALPN 配置不当:**
   - **错误:** 服务器配置的 ALPN 协议与客户端期望的协议不一致。
   - **后果:** 连接可能建立成功，但无法使用特定的应用层协议（例如 HTTP/2 或 HTTP/3）。
   - **调试线索:** 可以通过抓包工具查看客户端和服务器在 TLS 握手过程中协商的 ALPN 协议。

4. **客户端证书验证配置错误:**
   - **错误:** 服务器要求客户端提供证书进行身份验证，但配置的 CA 证书不正确，或者客户端没有配置有效的证书。
   - **后果:** 客户端连接时会被服务器拒绝，返回 `net::ERR_BAD_SSL_CLIENT_AUTH_CERT` 等错误。
   - **用户操作:** 用户尝试访问需要客户端证书认证的网站时，可能会收到证书选择提示，但如果证书无效则无法连接。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入一个 `https://` 开头的网址并回车。**
2. **浏览器解析域名，发起 DNS 查询获取服务器 IP 地址。**
3. **浏览器与服务器建立 TCP 连接 (SYN, SYN-ACK, ACK 三次握手)。**
4. **TCP 连接建立后，浏览器发起 TLS 握手 (Client Hello)。**  服务器端开始使用 `SSLServerContextImpl::SocketImpl` 来处理。
5. **服务器接收 Client Hello，进行处理，例如选择加密套件、发送 Server Hello、Certificate、Server Key Exchange (如果需要)、Server Hello Done。** 这些逻辑都在 `DoHandshake()` 方法中。
6. **如果服务器需要客户端证书验证，会发送 Certificate Request。**
7. **客户端发送 Certificate (如果需要) 和 Client Key Exchange、Change Cipher Spec、Finished。**
8. **服务器验证客户端发送的信息，发送 Change Cipher Spec 和 Finished。**
9. **TLS 握手完成，连接建立 (`completed_handshake_` 为 true)。**
10. **用户后续在网页上的操作，例如点击链接、提交表单，会触发 JavaScript 代码通过 `fetch()` 或其他 API 发起 HTTPS 请求，这些请求的数据会通过 `Write()` 方法进行加密发送，服务器端通过 `Read()` 方法接收解密。**

**调试线索:**

*   **网络抓包:** 使用 Wireshark 等工具抓取网络包，可以查看 TLS 握手的详细过程，包括 Client Hello、Server Hello、证书交换等信息，有助于定位握手失败的原因。
*   **浏览器开发者工具:** 浏览器的开发者工具 (Network 选项卡) 可以查看请求的状态、协议、证书信息等，帮助诊断 SSL/TLS 相关问题。
*   **服务器日志:** 查看服务器的 SSL/TLS 相关日志，可以获取更详细的错误信息，例如证书加载失败、私钥操作失败等。
*   **Chromium NetLog:**  Chromium 提供了 NetLog 功能，可以记录详细的网络事件，包括 SSL/TLS 握手的每一步骤，以及发生的错误信息，是深入调试网络问题的强大工具。

**功能归纳 (针对第 1 部分):**

`ssl_server_socket_impl.cc` 文件的第一部分主要定义了 `SSLServerContextImpl::SocketImpl` 类，该类是服务器端 SSL/TLS Socket 的核心实现。其主要功能包括：

*   **初始化和配置 SSL 连接:** 创建和配置 OpenSSL 的 SSL 对象，设置服务器证书和私钥。
*   **处理 SSL/TLS 握手:** 实现与客户端的握手协商过程，建立安全的加密连接。
*   **实现基本的 Socket 操作:**  封装底层 `StreamSocket`，提供 `Read` 和 `Write` 方法用于安全数据的收发。
*   **处理异步的私钥操作:** 通过回调函数处理需要异步完成的私钥签名等操作。
*   **处理 ALPN 和客户端证书验证:**  提供回调机制来处理应用层协议协商和客户端证书的验证。

总而言之，这部分代码是 Chromium 中负责构建安全服务器端 Socket 的关键组件，它依赖于 OpenSSL 库来实现 SSL/TLS 协议的各种细节。

Prompt: 
```
这是目录为net/socket/ssl_server_socket_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/ssl_server_socket_impl.h"

#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "crypto/rsa_private_key.h"
#include "net/base/completion_once_callback.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/client_cert_verifier.h"
#include "net/cert/x509_util.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/socket_bio_adapter.h"
#include "net/ssl/openssl_ssl_util.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

#define GotoState(s) next_handshake_state_ = s

namespace net {

namespace {

// This constant can be any non-negative/non-zero value (eg: it does not
// overlap with any value of the net::Error range, including net::OK).
const int kSSLServerSocketNoPendingResult = 1;

}  // namespace

class SSLServerContextImpl::SocketImpl : public SSLServerSocket,
                                         public SocketBIOAdapter::Delegate {
 public:
  SocketImpl(SSLServerContextImpl* context,
             std::unique_ptr<StreamSocket> socket);

  SocketImpl(const SocketImpl&) = delete;
  SocketImpl& operator=(const SocketImpl&) = delete;

  ~SocketImpl() override;

  // SSLServerSocket interface.
  int Handshake(CompletionOnceCallback callback) override;

  // SSLSocket interface.
  int ExportKeyingMaterial(std::string_view label,
                           bool has_context,
                           std::string_view context,
                           unsigned char* out,
                           unsigned int outlen) override;

  // Socket interface (via StreamSocket).
  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override;
  int ReadIfReady(IOBuffer* buf,
                  int buf_len,
                  CompletionOnceCallback callback) override;
  int CancelReadIfReady() override;
  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override;
  int SetReceiveBufferSize(int32_t size) override;
  int SetSendBufferSize(int32_t size) override;

  // StreamSocket implementation.
  int Connect(CompletionOnceCallback callback) override;
  void Disconnect() override;
  bool IsConnected() const override;
  bool IsConnectedAndIdle() const override;
  int GetPeerAddress(IPEndPoint* address) const override;
  int GetLocalAddress(IPEndPoint* address) const override;
  const NetLogWithSource& NetLog() const override;
  bool WasEverUsed() const override;
  NextProto GetNegotiatedProtocol() const override;
  std::optional<std::string_view> GetPeerApplicationSettings() const override;
  bool GetSSLInfo(SSLInfo* ssl_info) override;
  int64_t GetTotalReceivedBytes() const override;
  void ApplySocketTag(const SocketTag& tag) override;

  static SocketImpl* FromSSL(SSL* ssl);

  static ssl_verify_result_t CertVerifyCallback(SSL* ssl, uint8_t* out_alert);
  ssl_verify_result_t CertVerifyCallbackImpl(uint8_t* out_alert);

  static const SSL_PRIVATE_KEY_METHOD kPrivateKeyMethod;
  static ssl_private_key_result_t PrivateKeySignCallback(SSL* ssl,
                                                         uint8_t* out,
                                                         size_t* out_len,
                                                         size_t max_out,
                                                         uint16_t algorithm,
                                                         const uint8_t* in,
                                                         size_t in_len);
  static ssl_private_key_result_t PrivateKeyDecryptCallback(SSL* ssl,
                                                            uint8_t* out,
                                                            size_t* out_len,
                                                            size_t max_out,
                                                            const uint8_t* in,
                                                            size_t in_len);
  static ssl_private_key_result_t PrivateKeyCompleteCallback(SSL* ssl,
                                                             uint8_t* out,
                                                             size_t* out_len,
                                                             size_t max_out);

  ssl_private_key_result_t PrivateKeySignCallback(uint8_t* out,
                                                  size_t* out_len,
                                                  size_t max_out,
                                                  uint16_t algorithm,
                                                  const uint8_t* in,
                                                  size_t in_len);
  ssl_private_key_result_t PrivateKeyCompleteCallback(uint8_t* out,
                                                      size_t* out_len,
                                                      size_t max_out);
  void OnPrivateKeyComplete(Error error, const std::vector<uint8_t>& signature);

  static int ALPNSelectCallback(SSL* ssl,
                                const uint8_t** out,
                                uint8_t* out_len,
                                const uint8_t* in,
                                unsigned in_len,
                                void* arg);

  static ssl_select_cert_result_t SelectCertificateCallback(
      const SSL_CLIENT_HELLO* client_hello);

  // SocketBIOAdapter::Delegate implementation.
  void OnReadReady() override;
  void OnWriteReady() override;

 private:
  enum State {
    STATE_NONE,
    STATE_HANDSHAKE,
  };

  void OnHandshakeIOComplete(int result);

  [[nodiscard]] int DoPayloadRead(IOBuffer* buf, int buf_len);
  [[nodiscard]] int DoPayloadWrite();

  [[nodiscard]] int DoHandshakeLoop(int last_io_result);
  [[nodiscard]] int DoHandshake();
  void DoHandshakeCallback(int result);
  void DoReadCallback(int result);
  void DoWriteCallback(int result);

  [[nodiscard]] int Init();
  void ExtractClientCert();

  raw_ptr<SSLServerContextImpl> context_;

  NetLogWithSource net_log_;

  CompletionOnceCallback user_handshake_callback_;
  CompletionOnceCallback user_read_callback_;
  CompletionOnceCallback user_write_callback_;

  // SSLPrivateKey signature.
  int signature_result_;
  std::vector<uint8_t> signature_;

  // Used by Read function.
  scoped_refptr<IOBuffer> user_read_buf_;
  int user_read_buf_len_ = 0;

  // Used by Write function.
  scoped_refptr<IOBuffer> user_write_buf_;
  int user_write_buf_len_ = 0;

  // OpenSSL stuff
  bssl::UniquePtr<SSL> ssl_;

  // Whether we received any data in early data.
  bool early_data_received_ = false;

  // StreamSocket for sending and receiving data.
  std::unique_ptr<StreamSocket> transport_socket_;
  std::unique_ptr<SocketBIOAdapter> transport_adapter_;

  // Certificate for the client.
  scoped_refptr<X509Certificate> client_cert_;

  State next_handshake_state_ = STATE_NONE;
  bool completed_handshake_ = false;

  NextProto negotiated_protocol_ = kProtoUnknown;

  base::WeakPtrFactory<SocketImpl> weak_factory_{this};
};

SSLServerContextImpl::SocketImpl::SocketImpl(
    SSLServerContextImpl* context,
    std::unique_ptr<StreamSocket> transport_socket)
    : context_(context),
      signature_result_(kSSLServerSocketNoPendingResult),
      transport_socket_(std::move(transport_socket)) {}

SSLServerContextImpl::SocketImpl::~SocketImpl() {
  if (ssl_) {
    // Calling SSL_shutdown prevents the session from being marked as
    // unresumable.
    SSL_shutdown(ssl_.get());
    ssl_.reset();
  }
}

// static
const SSL_PRIVATE_KEY_METHOD
    SSLServerContextImpl::SocketImpl::kPrivateKeyMethod = {
        &SSLServerContextImpl::SocketImpl::PrivateKeySignCallback,
        &SSLServerContextImpl::SocketImpl::PrivateKeyDecryptCallback,
        &SSLServerContextImpl::SocketImpl::PrivateKeyCompleteCallback,
};

// static
ssl_private_key_result_t
SSLServerContextImpl::SocketImpl::PrivateKeySignCallback(SSL* ssl,
                                                         uint8_t* out,
                                                         size_t* out_len,
                                                         size_t max_out,
                                                         uint16_t algorithm,
                                                         const uint8_t* in,
                                                         size_t in_len) {
  return FromSSL(ssl)->PrivateKeySignCallback(out, out_len, max_out, algorithm,
                                              in, in_len);
}

// static
ssl_private_key_result_t
SSLServerContextImpl::SocketImpl::PrivateKeyDecryptCallback(SSL* ssl,
                                                            uint8_t* out,
                                                            size_t* out_len,
                                                            size_t max_out,
                                                            const uint8_t* in,
                                                            size_t in_len) {
  // Decrypt is not supported.
  return ssl_private_key_failure;
}

// static
ssl_private_key_result_t
SSLServerContextImpl::SocketImpl::PrivateKeyCompleteCallback(SSL* ssl,
                                                             uint8_t* out,
                                                             size_t* out_len,
                                                             size_t max_out) {
  return FromSSL(ssl)->PrivateKeyCompleteCallback(out, out_len, max_out);
}

ssl_private_key_result_t
SSLServerContextImpl::SocketImpl::PrivateKeySignCallback(uint8_t* out,
                                                         size_t* out_len,
                                                         size_t max_out,
                                                         uint16_t algorithm,
                                                         const uint8_t* in,
                                                         size_t in_len) {
  DCHECK(context_);
  DCHECK(context_->private_key_);
  signature_result_ = ERR_IO_PENDING;
  context_->private_key_->Sign(
      algorithm, base::make_span(in, in_len),
      base::BindOnce(&SSLServerContextImpl::SocketImpl::OnPrivateKeyComplete,
                     weak_factory_.GetWeakPtr()));
  return ssl_private_key_retry;
}

ssl_private_key_result_t
SSLServerContextImpl::SocketImpl::PrivateKeyCompleteCallback(uint8_t* out,
                                                             size_t* out_len,
                                                             size_t max_out) {
  if (signature_result_ == ERR_IO_PENDING)
    return ssl_private_key_retry;
  if (signature_result_ != OK) {
    OpenSSLPutNetError(FROM_HERE, signature_result_);
    return ssl_private_key_failure;
  }
  if (signature_.size() > max_out) {
    OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED);
    return ssl_private_key_failure;
  }
  memcpy(out, signature_.data(), signature_.size());
  *out_len = signature_.size();
  signature_.clear();
  return ssl_private_key_success;
}

void SSLServerContextImpl::SocketImpl::OnPrivateKeyComplete(
    Error error,
    const std::vector<uint8_t>& signature) {
  DCHECK_EQ(ERR_IO_PENDING, signature_result_);
  DCHECK(signature_.empty());

  signature_result_ = error;
  if (signature_result_ == OK)
    signature_ = signature;
  OnHandshakeIOComplete(ERR_IO_PENDING);
}

// static
int SSLServerContextImpl::SocketImpl::ALPNSelectCallback(SSL* ssl,
                                                         const uint8_t** out,
                                                         uint8_t* out_len,
                                                         const uint8_t* in,
                                                         unsigned in_len,
                                                         void* arg) {
  SSLServerContextImpl::SocketImpl* socket = FromSSL(ssl);

  // Iterate over the server protocols in preference order.
  for (NextProto server_proto :
       socket->context_->ssl_server_config_.alpn_protos) {
    const char* server_proto_str = NextProtoToString(server_proto);

    // See if the client advertised the corresponding protocol.
    CBS cbs;
    CBS_init(&cbs, in, in_len);
    while (CBS_len(&cbs) != 0) {
      CBS client_proto;
      if (!CBS_get_u8_length_prefixed(&cbs, &client_proto)) {
        return SSL_TLSEXT_ERR_NOACK;
      }
      if (std::string_view(
              reinterpret_cast<const char*>(CBS_data(&client_proto)),
              CBS_len(&client_proto)) == server_proto_str) {
        *out = CBS_data(&client_proto);
        *out_len = CBS_len(&client_proto);

        const auto& application_settings =
            socket->context_->ssl_server_config_.application_settings;
        auto it = application_settings.find(server_proto);
        if (it != application_settings.end()) {
          const std::vector<uint8_t>& data = it->second;
          SSL_add_application_settings(ssl, CBS_data(&client_proto),
                                       CBS_len(&client_proto), data.data(),
                                       data.size());
        }
        return SSL_TLSEXT_ERR_OK;
      }
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}

ssl_select_cert_result_t
SSLServerContextImpl::SocketImpl::SelectCertificateCallback(
    const SSL_CLIENT_HELLO* client_hello) {
  SSLServerContextImpl::SocketImpl* socket = FromSSL(client_hello->ssl);
  const SSLServerConfig& config = socket->context_->ssl_server_config_;
  if (!config.client_hello_callback_for_testing.is_null() &&
      !config.client_hello_callback_for_testing.Run(client_hello)) {
    return ssl_select_cert_error;
  }
  return ssl_select_cert_success;
}

int SSLServerContextImpl::SocketImpl::Handshake(
    CompletionOnceCallback callback) {
  net_log_.BeginEvent(NetLogEventType::SSL_SERVER_HANDSHAKE);

  // Set up new ssl object.
  int rv = Init();
  if (rv != OK) {
    LOG(ERROR) << "Failed to initialize OpenSSL: rv=" << rv;
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_SERVER_HANDSHAKE,
                                      rv);
    return rv;
  }

  // Set SSL to server mode. Handshake happens in the loop below.
  SSL_set_accept_state(ssl_.get());

  GotoState(STATE_HANDSHAKE);
  rv = DoHandshakeLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_handshake_callback_ = std::move(callback);
  } else {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_SERVER_HANDSHAKE,
                                      rv);
  }

  return rv > OK ? OK : rv;
}

int SSLServerContextImpl::SocketImpl::ExportKeyingMaterial(
    std::string_view label,
    bool has_context,
    std::string_view context,
    unsigned char* out,
    unsigned int outlen) {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  int rv = SSL_export_keying_material(
      ssl_.get(), out, outlen, label.data(), label.size(),
      reinterpret_cast<const unsigned char*>(context.data()), context.length(),
      context.length() > 0);

  if (rv != 1) {
    int ssl_error = SSL_get_error(ssl_.get(), rv);
    LOG(ERROR) << "Failed to export keying material;"
               << " returned " << rv << ", SSL error code " << ssl_error;
    return MapOpenSSLError(ssl_error, err_tracer);
  }
  return OK;
}

int SSLServerContextImpl::SocketImpl::Read(IOBuffer* buf,
                                           int buf_len,
                                           CompletionOnceCallback callback) {
  int rv = ReadIfReady(buf, buf_len, std::move(callback));
  if (rv == ERR_IO_PENDING) {
    user_read_buf_ = buf;
    user_read_buf_len_ = buf_len;
  }
  return rv;
}

int SSLServerContextImpl::SocketImpl::ReadIfReady(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback) {
  DCHECK(user_read_callback_.is_null());
  DCHECK(user_handshake_callback_.is_null());
  DCHECK(!user_read_buf_);
  DCHECK(!callback.is_null());
  DCHECK(completed_handshake_);

  int rv = DoPayloadRead(buf, buf_len);

  if (rv == ERR_IO_PENDING) {
    user_read_callback_ = std::move(callback);
  }

  return rv;
}

int SSLServerContextImpl::SocketImpl::CancelReadIfReady() {
  DCHECK(user_read_callback_);
  DCHECK(!user_read_buf_);

  // Cancel |user_read_callback_|, because caller does not expect the callback
  // to be invoked after they have canceled the ReadIfReady.
  //
  // We do not pass the signal on to |stream_socket_| or |transport_adapter_|.
  // When it completes, it will signal OnReadReady(), which will notice there is
  // no read operation to progress and skip it. Unlike with SSLClientSocket,
  // SSL and transport reads are more aligned, but this avoids making
  // assumptions or breaking the SocketBIOAdapter's state.
  user_read_callback_.Reset();
  return OK;
}

int SSLServerContextImpl::SocketImpl::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(user_write_callback_.is_null());
  DCHECK(!user_write_buf_);
  DCHECK(!callback.is_null());

  user_write_buf_ = buf;
  user_write_buf_len_ = buf_len;

  int rv = DoPayloadWrite();

  if (rv == ERR_IO_PENDING) {
    user_write_callback_ = std::move(callback);
  } else {
    user_write_buf_ = nullptr;
    user_write_buf_len_ = 0;
  }
  return rv;
}

int SSLServerContextImpl::SocketImpl::SetReceiveBufferSize(int32_t size) {
  return transport_socket_->SetReceiveBufferSize(size);
}

int SSLServerContextImpl::SocketImpl::SetSendBufferSize(int32_t size) {
  return transport_socket_->SetSendBufferSize(size);
}

int SSLServerContextImpl::SocketImpl::Connect(CompletionOnceCallback callback) {
  NOTIMPLEMENTED();
  return ERR_NOT_IMPLEMENTED;
}

void SSLServerContextImpl::SocketImpl::Disconnect() {
  transport_socket_->Disconnect();
}

bool SSLServerContextImpl::SocketImpl::IsConnected() const {
  // TODO(wtc): Find out if we should check transport_socket_->IsConnected()
  // as well.
  return completed_handshake_;
}

bool SSLServerContextImpl::SocketImpl::IsConnectedAndIdle() const {
  return completed_handshake_ && transport_socket_->IsConnectedAndIdle();
}

int SSLServerContextImpl::SocketImpl::GetPeerAddress(
    IPEndPoint* address) const {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  return transport_socket_->GetPeerAddress(address);
}

int SSLServerContextImpl::SocketImpl::GetLocalAddress(
    IPEndPoint* address) const {
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  return transport_socket_->GetLocalAddress(address);
}

const NetLogWithSource& SSLServerContextImpl::SocketImpl::NetLog() const {
  return net_log_;
}

bool SSLServerContextImpl::SocketImpl::WasEverUsed() const {
  return transport_socket_->WasEverUsed();
}

NextProto SSLServerContextImpl::SocketImpl::GetNegotiatedProtocol() const {
  return negotiated_protocol_;
}

std::optional<std::string_view>
SSLServerContextImpl::SocketImpl::GetPeerApplicationSettings() const {
  if (!SSL_has_application_settings(ssl_.get())) {
    return std::nullopt;
  }

  const uint8_t* out_data;
  size_t out_len;
  SSL_get0_peer_application_settings(ssl_.get(), &out_data, &out_len);
  return std::string_view{reinterpret_cast<const char*>(out_data), out_len};
}

bool SSLServerContextImpl::SocketImpl::GetSSLInfo(SSLInfo* ssl_info) {
  ssl_info->Reset();
  if (!completed_handshake_)
    return false;

  ssl_info->cert = client_cert_;

  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_.get());
  CHECK(cipher);

  SSLConnectionStatusSetCipherSuite(SSL_CIPHER_get_protocol_id(cipher),
                                    &ssl_info->connection_status);
  SSLConnectionStatusSetVersion(GetNetSSLVersion(ssl_.get()),
                                &ssl_info->connection_status);

  ssl_info->early_data_received = early_data_received_;
  ssl_info->encrypted_client_hello = SSL_ech_accepted(ssl_.get());
  ssl_info->handshake_type = SSL_session_reused(ssl_.get())
                                 ? SSLInfo::HANDSHAKE_RESUME
                                 : SSLInfo::HANDSHAKE_FULL;
  ssl_info->peer_signature_algorithm =
      SSL_get_peer_signature_algorithm(ssl_.get());

  return true;
}

int64_t SSLServerContextImpl::SocketImpl::GetTotalReceivedBytes() const {
  return transport_socket_->GetTotalReceivedBytes();
}

void SSLServerContextImpl::SocketImpl::ApplySocketTag(const SocketTag& tag) {
  NOTIMPLEMENTED();
}

void SSLServerContextImpl::SocketImpl::OnReadReady() {
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
    OnHandshakeIOComplete(OK);
    return;
  }

  // BoringSSL does not support renegotiation as a server, so the only other
  // operation blocked on Read is DoPayloadRead.
  if (!user_read_buf_) {
    if (!user_read_callback_.is_null()) {
      DoReadCallback(OK);
    }
    return;
  }

  int rv = DoPayloadRead(user_read_buf_.get(), user_read_buf_len_);
  if (rv != ERR_IO_PENDING)
    DoReadCallback(rv);
}

void SSLServerContextImpl::SocketImpl::OnWriteReady() {
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
    OnHandshakeIOComplete(OK);
    return;
  }

  // BoringSSL does not support renegotiation as a server, so the only other
  // operation blocked on Read is DoPayloadWrite.
  if (!user_write_buf_)
    return;

  int rv = DoPayloadWrite();
  if (rv != ERR_IO_PENDING)
    DoWriteCallback(rv);
}

void SSLServerContextImpl::SocketImpl::OnHandshakeIOComplete(int result) {
  int rv = DoHandshakeLoop(result);
  if (rv == ERR_IO_PENDING)
    return;

  net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_SERVER_HANDSHAKE, rv);
  if (!user_handshake_callback_.is_null())
    DoHandshakeCallback(rv);
}

int SSLServerContextImpl::SocketImpl::DoPayloadRead(IOBuffer* buf,
                                                    int buf_len) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_handshake_state_);
  DCHECK(buf);
  DCHECK_GT(buf_len, 0);

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_read(ssl_.get(), buf->data(), buf_len);
  if (rv >= 0) {
    if (SSL_in_early_data(ssl_.get()))
      early_data_received_ = true;
    return rv;
  }
  int ssl_error = SSL_get_error(ssl_.get(), rv);
  OpenSSLErrorInfo error_info;
  int net_error =
      MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);
  if (net_error != ERR_IO_PENDING) {
    NetLogOpenSSLError(net_log_, NetLogEventType::SSL_READ_ERROR, net_error,
                       ssl_error, error_info);
  }
  return net_error;
}

int SSLServerContextImpl::SocketImpl::DoPayloadWrite() {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_handshake_state_);
  DCHECK(user_write_buf_);

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_write(ssl_.get(), user_write_buf_->data(), user_write_buf_len_);
  if (rv >= 0)
    return rv;
  int ssl_error = SSL_get_error(ssl_.get(), rv);
  OpenSSLErrorInfo error_info;
  int net_error =
      MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);
  if (net_error != ERR_IO_PENDING) {
    NetLogOpenSSLError(net_log_, NetLogEventType::SSL_WRITE_ERROR, net_error,
                       ssl_error, error_info);
  }
  return net_error;
}

int SSLServerContextImpl::SocketImpl::DoHandshakeLoop(int last_io_result) {
  int rv = last_io_result;
  do {
    // Default to STATE_NONE for next state.
    // (This is a quirk carried over from the windows
    // implementation.  It makes reading the logs a bit harder.)
    // State handlers can and often do call GotoState just
    // to stay in the current state.
    State state = next_handshake_state_;
    GotoState(STATE_NONE);
    switch (state) {
      case STATE_HANDSHAKE:
        rv = DoHandshake();
        break;
      case STATE_NONE:
      default:
        rv = ERR_UNEXPECTED;
        LOG(DFATAL) << "unexpected state " << state;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_handshake_state_ != STATE_NONE);
  return rv;
}

int SSLServerContextImpl::SocketImpl::DoHandshake() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int net_error = OK;
  int rv = SSL_do_handshake(ssl_.get());
  if (rv == 1) {
    const STACK_OF(CRYPTO_BUFFER)* certs =
        SSL_get0_peer_certificates(ssl_.get());
    if (certs) {
      client_cert_ = x509_util::CreateX509CertificateFromBuffers(certs);
      if (!client_cert_)
        return ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT;
    }

    const uint8_t* alpn_proto = nullptr;
    unsigned alpn_len = 0;
    SSL_get0_alpn_selected(ssl_.get(), &alpn_proto, &alpn_len);
    if (alpn_len > 0) {
      std::string_view proto(reinterpret_cast<const char*>(alpn_proto),
                             alpn_len);
      negotiated_protocol_ = NextProtoFromString(proto);
    }

    if (context_->ssl_server_config_.alert_after_handshake_for_testing) {
      SSL_send_fatal_alert(ssl_.get(),
                           context_->ssl_server_config_
                               .alert_after_handshake_for_testing.value());
      return ERR_FAILED;
    }

    completed_handshake_ = true;
  } else {
    int ssl_error = SSL_get_error(ssl_.get(), rv);

    if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
      DCHECK(context_->private_key_);
      GotoState(STATE_HANDSHAKE);
      return ERR_IO_PENDING;
    }

    OpenSSLErrorInfo error_info;
    net_error = MapOpenSSLErrorWithDetails(ssl_error, err_tracer, &error_info);

    // SSL_R_CERTIFICATE_VERIFY_FAILED's mapping is different between client and
    // server.
    if (ERR_GET_LIB(error_info.error_code) == ERR_LIB_SSL &&
        ERR_GET_REASON(error_info.error_code) ==
            SSL_R_CERTIFICATE_VERIFY_FAILED) {
      net_error = ERR_BAD_SSL_CLIENT_AUTH_CERT;
    }

    // If not done, stay in this state
    if (net_error == ERR_IO_PENDING) {
      GotoState(STATE_HANDSHAKE);
    } else {
      LOG(ERROR) << "handshake failed; returned " << rv << ", SSL error code "
                 << ssl_error << ", net_error " << net_error;
      NetLogOpenSSLError(net_log_, NetLogEventType::SSL_HANDSHAKE_ERROR,
                         net_error, ssl_error, error_info);
    }
  }
  return net_error;
}

void SSLServerContextImpl::SocketImpl::DoHandshakeCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  std::move(user_handshake_callback_).Run(rv > OK ? OK : rv);
}

void SSLServerContextImpl::SocketImpl::DoReadCallback(int rv) {
  DCHECK(rv != ERR_IO_PENDING);
  DCHECK(!user_read_callback_.is_null());

  user_read_buf_ = nullptr;
  user_read_buf_len_ = 0;
  std::move(user_read_callback_).Run(rv);
}

void SSLServerContextImpl::SocketImpl::DoWriteCallback(int rv) {
  DCHECK(rv != ERR_IO_PENDING);
  DCHECK(!user_write_callback_.is_null());

  user_write_buf_ = nullptr;
  user_write_buf_len_ = 0;
  std::move(user_write_callback_).Run(rv);
}

int SSLServerContextImpl::SocketImpl::Init() {
  static const int kBufferSize = 17 * 1024;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  ssl_.reset(SSL_new(context_->ssl_ctx_.get()));
  if (!ssl_ || !SSL_set_app_data(ssl_.get(), this)) {
    return ERR_UNEXPECTED;
  }

  SSL_set_shed_handshake_config(ssl_.get(), 1);

  // Set certificate and private key.
  if (context_->pkey_) {
    DCHECK(context_->cert_->cert_buffer());
    if (!SetSSLChainAndKey(ssl_.get(), context_->cert_.get(),
                           context_->pkey_.get(), nullptr)) {
      return ERR_UNEXPECTED;
    }
  } else {
    DCHECK(context_->private_key_);
    if (!SetSSLChainAndKey(ssl_.get(), context_->cert_.get(), nullptr,
                           &kPrivateKeyMethod)) {
      return ERR_UNEXPECTED;
    }
    std::vector<uint16_t> preferences =
        context_->private_key_->GetAlgorithmPreferences();
    SSL_set_signing_algorithm_prefs(ssl_.get(), preferences.data(),
                                    preferences.size());
  }

  if (context_->ssl_server_config_.signature_algorithm_for_testing
          .has_value()) {
    uint16_t id = *context_->ssl_server_config_.signature_algorithm_for_testing;
    CHECK(SSL_set_signing_algorithm_prefs(ssl_.get(), &id, 1));
  }

  const std::vector<int>& curves =
      context_->ssl_server_config_.curves_for_testing;
  if (!curves.empty()) {
    CHECK(SSL_set1_curves(ssl_.get(), curves.data(), curves.size()));
  }

  transport_adapter_ = std::make_unique<SocketBIOAdapter>(
      transport_socket_.get(), kBufferSize, kBufferSize, this);
  BIO* transport_bio = transport_adapter_->bio();

  BIO_up_ref(transport_bio);  // SSL_set0_rbio takes ownership.
  SSL_set0_rbio(ssl_.get(), transport_bio);

  BIO_up_ref(transport_bio);  // SSL_set0_wbio takes ownership.
  SSL_set0_wbio(ssl_.get(), transport_bio);

  return OK;
}

SSLServerContextImpl::SocketImpl* SSLServerContextImpl::SocketImpl::FromSSL(
    SSL* ssl) {
  SocketImpl* socket = reinterpret_cast<SocketImpl*>(SSL_get_app_data(ssl));
  DCHECK(socket);
  return socket;
}

// static
ssl_verify_result_t SSLServerContextImpl::SocketImpl::CertVerifyCallback(
    SSL* ssl,
    uint8_t* out_alert) {
  return FromSSL(ssl)->CertVerifyCallbackImpl(out_alert);
}

ssl_verify_result_t SSLServerContextImpl::SocketImpl::CertVerifyCallbackImpl(
    uint8_t* out_alert) {
  ClientCertVerifier* verifier =
      context_->ssl_server_config_.client_cert_verifier;
  // If a verifier was not supplied, all certificates are accepted.
  if (!verifier)
    return ssl_verify_ok;

  scoped_refptr<X509Certificate> client_cert =
      x509_util::CreateX509CertificateFromBuffers(
          SSL_get0_peer_certificates(ssl_.get()));
  if (!client_cert) {
    *out_alert = SSL_AD_BAD_CERTIFICATE;
    return ssl_verify_invalid;
  }

  // TODO(davidben): Support asynchronous verifiers. http://crbug.com/347402
  std::unique_ptr<ClientCertVerifier::Request> ignore_async;
  int res = verifier->Verify(client_cert.get(), CompletionOnceCallback(),
                             &ignore_async);
  DCHECK_NE(res, ERR_IO_PENDING);

  if (res != OK) {
    // TODO(davidben): Map from certificate verification failure to alert.
    *out_alert = SSL_AD_CERTIFICATE_UNKNOWN;
    return ssl_verify_invalid;
  }
  return ssl_verify_ok;
}

std::unique_ptr<SSLServerContext> CreateSSLServerContext(
    X509Certificate* certificate,
    EVP_PKEY* pkey,
    const SSLServerConfig& ssl_server_config) {
  return std::make_unique<SSLServerContextImpl>(certificate, pkey,
                                                ssl_server_config);
}

std::unique_ptr<SSLServerContext> CreateSSLServerContext(
    X509Certificate* certificate,
    const crypto::RSAPrivateKey& key,
    const SSLServerConfig& ssl_server_config) {
  return std::make_unique<SSLServerContextImpl>(certificate, key.key(),
                                                ssl_server_config);
}

std::unique_ptr<SSLServerContext> CreateSSLServerContext(
    X509Certificate* certificate,
    scoped_refptr<SSLPrivateKey> key,
    const SSLServerConfig& ssl_config) {
  return std::make_unique<SSLServerContextImpl>(certificate, key, ssl_config);
}

SSLServerContextImpl::SSLServerContextImpl(
    X509Certificate* certificate,
    scoped_refptr<net::SSLPrivateKey> key,
    const SSLServerConfig& ssl_server_config)
    : ssl_server_config_(ssl_server_config),
      cert_(certificate),
      private_key_(key) {
  CHECK(private_key_);
  Init();
}

SSLServerContextImpl::SSLServerContextImpl(
    X509Certificate* certificate,
    EVP_PKEY* pkey,
    const SSLServerConfig& ssl_server_config)
    : ssl_server_config_(ssl_server_config), cert_(certificate) {
  CHECK(pkey);
  pkey_ = bssl::UpRef(pkey);
  Init();
}

void SSLServerContextImpl::Init() {
  ssl_ctx_.reset(SSL_CTX_new(TLS_with_buffers_method()));
  SSL_CTX_set_session_cache_mode
"""


```
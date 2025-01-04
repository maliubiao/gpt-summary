Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Initial Understanding of the Request:**

The user wants to understand the functionality of the `QuicCryptoServerStream.cc` file within the Chromium QUIC stack. They're specifically interested in:

* **Functionality:** What does this class do?
* **JavaScript Relationship:** Does it interact with JavaScript? How?
* **Logic Inference (Hypothetical I/O):** Can we devise input/output scenarios?
* **Common Usage Errors:** What mistakes do developers often make when using this class?
* **Debugging Clues (User Journey):** How does a user's action lead to this code being executed?

**2. High-Level Overview of the Code:**

My first step is to skim the code for key identifiers, class names, and method names. I see:

* `QuicCryptoServerStream`: This is the central class. The filename confirms its importance.
* `#include` statements: These point to related QUIC components like `QuicSession`, `QuicCryptoServerConfig`, `CryptoHandshakeMessage`, etc. This suggests the class is involved in the cryptographic handshake process on the server side.
* Methods like `OnHandshakeMessage`, `ProcessClientHello`, `SendServerConfigUpdate`: These clearly relate to the QUIC handshake.
* Mentions of encryption levels (`ENCRYPTION_INITIAL`, `ENCRYPTION_ZERO_RTT`, `ENCRYPTION_FORWARD_SECURE`):  Confirms the cryptographic nature.
* Callbacks:  `ProcessClientHelloCallback`, `ValidateCallback`, `SendServerConfigUpdateCallback`. This indicates asynchronous operations.

**3. Deeper Dive into Functionality:**

Now I'll go through the code section by section, focusing on the public methods and their purpose:

* **Constructor and Destructor:** Sets up and cleans up resources. The destructor cancels outstanding callbacks, which is good practice.
* **`OnHandshakeMessage`:**  This is a crucial entry point. It receives and processes cryptographic handshake messages from the client (`kCHLO`). It handles errors and validates the message.
* **`ProcessClientHello` and related callbacks (`ValidateCallback`, `ProcessClientHelloCallback`):** This section deals with the core logic of handling the initial client handshake message (CHLO). It involves validating the client's request, negotiating parameters, and generating the server's response (SHLO or REJ).
* **`SendServerConfigUpdate`:**  Allows the server to send updated configuration information to the client after the handshake.
* **Getter methods (e.g., `IsZeroRtt`, `IsResumption`, `encryption_established`):** Provide information about the current handshake state.
* **Methods related to encryption (`OnPacketDecrypted`, `GetEncryptionLevelToSendCryptoDataOfSpace`):**  Manage encryption keys and levels.
* **Methods related to address tokens and channel IDs:** Handle security features.
* **Overrides of base class methods:**  Indicates specialization of the base `QuicCryptoServerStreamBase` class.

**4. Identifying Key Responsibilities:**

Based on the detailed examination, I can summarize the key responsibilities:

* **Handling Client Hello (CHLO):** Receiving, validating, and processing the initial handshake message.
* **Negotiating Crypto Parameters:**  Working with `QuicCryptoServerConfig` to agree on encryption algorithms, etc.
* **Generating Server Hello (SHLO) or Reject (REJ):**  Responding to the client's CHLO.
* **Managing Encryption Keys:**  Setting up and managing different encryption levels.
* **Sending Server Configuration Updates (SCUP):**  Providing updated configuration information.
* **Determining Handshake State:**  Tracking whether the handshake is complete, zero-RTT, etc.

**5. Addressing the JavaScript Relationship:**

This is a C++ file in the network stack. It doesn't directly interact with JavaScript at the code level. However, its *functionality* is crucial for establishing secure QUIC connections, which are used by web browsers (which run JavaScript). The connection setup enables secure communication for web pages and applications that execute JavaScript code. So, the relationship is indirect but fundamental. I'll use an example like a user visiting an HTTPS website.

**6. Developing Logic Inference Examples:**

I'll think of simple scenarios:

* **Scenario 1 (Successful Handshake):** Client sends a valid CHLO, server responds with SHLO, connection is established.
* **Scenario 2 (Rejected Handshake):** Client sends an invalid CHLO, server responds with REJ, connection fails.
* **Scenario 3 (Zero-RTT):**  Client attempts a zero-RTT connection, server may accept or reject it.

For each scenario, I'll identify potential input (the client's CHLO) and the expected output (server's response, connection state).

**7. Identifying Common Usage Errors:**

I'll consider what mistakes developers might make *when configuring or using the QUIC server that utilizes this stream*:

* **Incorrect Crypto Configuration:**  Misconfiguring `QuicCryptoServerConfig` could lead to handshake failures.
* **Issues with Proof Source:** Problems with SSL certificates or the proof source implementation.
* **Incompatible Versions:**  Mismatched QUIC versions between client and server.

**8. Tracing the User Journey (Debugging Clues):**

I'll imagine the steps a user takes that would eventually lead to this code being executed:

* User types a URL in the browser.
* Browser initiates a QUIC connection.
* The `QuicCryptoServerStream` is created on the server.
* The client sends a CHLO, which is processed by `OnHandshakeMessage`.

**9. Structuring the Answer:**

Finally, I'll organize my findings into a clear and structured answer, addressing each point in the user's request:

* **Functionality:** Start with a concise summary, then provide more details about key methods and responsibilities.
* **JavaScript Relationship:** Explain the indirect connection through web browsers and HTTPS. Provide an example.
* **Logic Inference:** Present the hypothetical scenarios with input and output.
* **Common Usage Errors:** List common mistakes and explain their potential impact.
* **User Journey:** Describe the steps from user action to code execution.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on individual lines of code.
* **Correction:** Shift focus to the overall purpose and interactions between different parts of the class.
* **Initial thought:**  Overcomplicate the JavaScript relationship.
* **Correction:**  Simplify the explanation to focus on the core idea of secure connection establishment for web content.
* **Initial thought:**  Make the logic inference examples too technical.
* **Correction:**  Keep the examples simple and illustrate the basic handshake flow.

By following these steps, including the refinement process, I can arrive at a comprehensive and accurate answer that addresses all aspects of the user's request.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/quic_crypto_server_stream.cc` 这个文件。

**功能概述:**

`QuicCryptoServerStream` 类是 QUIC 协议服务器端用于处理客户端初始握手（handshake）消息的核心组件。它的主要职责包括：

1. **接收和验证客户端的 Client Hello (CHLO) 消息:**  当客户端尝试建立 QUIC 连接时，首先会发送 CHLO 消息。`QuicCryptoServerStream` 负责接收这个消息，并利用 `QuicCryptoServerConfig` 来验证其有效性，例如检查版本兼容性、服务器配置 ID 等。

2. **处理客户端的握手请求:**  根据 CHLO 消息的内容，`QuicCryptoServerStream` 会执行相应的握手流程。这可能包括：
   - **全握手:**  如果客户端没有可用的会话信息或服务器决定不进行会话恢复，则进行完整的握手过程，包括密钥交换、身份验证等。
   - **0-RTT 握手 (Zero Round Trip Time Resumption):** 如果客户端持有有效的会话密钥和相关信息，它可以尝试在初始的 CHLO 消息中携带应用数据，以减少握手延迟。`QuicCryptoServerStream` 会尝试解密这些数据并进行验证。
   - **会话恢复:** 如果客户端提供了有效的会话信息（例如，服务器 nonce），服务器可以恢复之前的会话，从而跳过一些握手步骤。

3. **生成和发送服务器的 Server Hello (SHLO) 或 Reject (REJ) 消息:**
   - 如果客户端的 CHLO 消息被接受，并且握手成功，`QuicCryptoServerStream` 会生成 SHLO 消息，其中包含服务器选择的参数、加密密钥等信息，并将其发送回客户端。
   - 如果 CHLO 消息无效或服务器决定拒绝连接，则会发送 REJ 消息。

4. **管理加密密钥:**  `QuicCryptoServerStream` 负责在握手过程中协商和管理加密密钥，包括初始密钥、0-RTT 密钥和前向安全密钥。它会将这些密钥提供给底层的加密/解密组件。

5. **发送服务器配置更新 (SCUP):**  在连接建立后，服务器可以使用 `SendServerConfigUpdate` 方法向客户端发送更新的配置信息，例如新的服务器配置 ID、网络参数等。

6. **跟踪握手状态:**  它维护着连接的握手状态，例如是否已建立加密、是否使用了 0-RTT 等。

7. **与 `QuicCryptoServerConfig` 交互:**  `QuicCryptoServerStream` 依赖于 `QuicCryptoServerConfig` 来执行许多关键操作，例如验证 CHLO、生成 SHLO、构建 SCUP 消息等。`QuicCryptoServerConfig` 包含了服务器的加密配置信息。

8. **处理客户端的后续握手消息:**  尽管主要的握手逻辑集中在处理 CHLO 上，但 `QuicCryptoServerStream` 也需要处理客户端可能发送的其他握手消息，直到握手完成。

**与 JavaScript 的关系:**

`QuicCryptoServerStream` 本身是用 C++ 编写的，运行在服务器端，因此它 **不直接** 与 JavaScript 代码交互。 然而，它所承担的功能对于运行在浏览器中的 JavaScript 代码至关重要。

**举例说明:**

当用户在浏览器中访问一个使用 HTTPS (通过 QUIC) 的网站时，浏览器（客户端）会发起与服务器的 QUIC 连接。  以下是涉及 `QuicCryptoServerStream` 的过程：

1. **用户在浏览器地址栏输入 URL 并回车。**
2. **浏览器尝试与服务器建立 QUIC 连接。**
3. **浏览器构建并发送一个 Client Hello (CHLO) 消息。** 这个消息包含了客户端支持的 QUIC 版本、加密套件等信息。
4. **服务器接收到 CHLO 消息。** 服务器端的网络栈会将这个消息传递给相应的 `QuicCryptoServerStream` 实例。
5. **`QuicCryptoServerStream` 接收到 CHLO 消息，并对其进行验证。**  它会检查消息的格式、版本兼容性等。
6. **如果验证通过，服务器会生成一个 Server Hello (SHLO) 消息。** SHLO 消息包含了服务器选择的 QUIC 版本、加密参数以及用于加密连接的密钥信息。
7. **服务器将 SHLO 消息发送回浏览器。**
8. **浏览器接收到 SHLO 消息，并完成握手过程。**  此时，QUIC 连接已经安全地建立起来。
9. **浏览器中的 JavaScript 代码现在可以通过这个安全的 QUIC 连接与服务器进行通信，发送和接收数据。**

在这个过程中，`QuicCryptoServerStream` 确保了连接的安全性，使得运行在浏览器中的 JavaScript 代码可以通过安全通道与服务器交互。 JavaScript 代码本身并不直接调用或操作 `QuicCryptoServerStream` 的方法，但它依赖于 `QuicCryptoServerStream` 成功建立的安全连接。

**逻辑推理 (假设输入与输出):**

**假设输入 (客户端 CHLO 消息):**

```
{
  "ver": "Q050", // QUIC 版本
  "sni": "example.com", // 服务器名称指示 (Server Name Indication)
  "scid": "SomeSessionID", // 会话 ID (用于会话恢复)
  "copt": ["EXPY", "TBBR"], // 客户端选项
  // ... 其他字段
}
```

**假设输出 (服务器 SHLO 消息):**

```
{
  "ver": "Q050", // 服务器接受的 QUIC 版本
  "sver": "Q050", // 服务器确认的 QUIC 版本
  "crypto": {
    "kexs": "C255", // 密钥交换算法
    "aead": "AESG", // AEAD 算法
    "scfg": "...", // 服务器配置数据
    "snonce": "...", // 服务器 Nonce
    // ... 其他加密相关字段
  },
  "sopt": ["TBBR"], // 服务器选择的选项
  // ... 其他字段
}
```

**逻辑推理过程:**

1. `QuicCryptoServerStream` 接收到客户端的 CHLO 消息。
2. 它会检查 `ver` 字段，确认服务器是否支持客户端请求的 QUIC 版本 "Q050"。
3. 它会查找与 `sni` "example.com" 匹配的服务器配置。
4. 如果 `scid` "SomeSessionID" 有效，并且服务器允许会话恢复，则可能会尝试恢复之前的会话。
5. 服务器根据自身配置和客户端的提议，选择合适的加密算法 (例如 "C255" 和 "AESG")。
6. 服务器生成 `scfg` (服务器配置) 和 `snonce` (服务器 Nonce) 等加密材料。
7. 服务器构建 SHLO 消息，并将选择的参数和加密信息包含在其中。
8. 如果客户端请求的选项 "EXPY" 服务器不支持，则不会在 `sopt` 中返回。服务器支持 "TBBR"，因此在 `sopt` 中返回。

**假设输入 (无效的客户端 CHLO 消息):**

```
{
  "ver": "Q049", // 服务器不支持的 QUIC 版本
  "sni": "unknown.com", // 服务器没有配置的域名
  // ... 其他字段
}
```

**假设输出 (服务器 REJ 消息):**

```
{
  "ver": "Q050", // 服务器支持的 QUIC 版本
  "rrej": {
    "vers": ["Q050"], // 服务器支持的版本列表
    "snoroute": true  //  (可能包含，表示找不到匹配的服务器配置)
    // ... 其他拒绝原因
  }
}
```

**逻辑推理过程:**

1. `QuicCryptoServerStream` 接收到客户端的 CHLO 消息。
2. 它检查 `ver` 字段，发现服务器不支持客户端请求的 QUIC 版本 "Q049"。
3. 它查找与 `sni` "unknown.com" 匹配的服务器配置，但找不到。
4. 服务器构建 REJ 消息，指示客户端请求的版本不可用，并可能包含服务器支持的版本列表。

**用户或编程常见的使用错误:**

1. **`QuicCryptoServerConfig` 配置错误:**  这是最常见的问题。如果服务器的加密配置不正确，例如缺少证书、密钥不匹配、支持的 QUIC 版本配置错误等，会导致握手失败。
   - **例子:**  服务器配置了只支持 QUIC 版本 Q046，但客户端发送的 CHLO 消息中只包含 Q050。服务器会发送 REJ 消息，指示版本不匹配。
   - **调试线索:**  检查服务器的日志，查看 `ValidateClientHello` 函数的返回值和错误信息。

2. **ProofSource (证书提供者) 配置错误:**  如果服务器无法正确加载或提供 SSL/TLS 证书，客户端将无法验证服务器的身份。
   - **例子:**  服务器的证书文件路径配置错误，导致 `ProofSource` 无法加载证书。客户端在握手时会收到证书验证错误。
   - **调试线索:**  检查 `QuicCryptoServerConfig` 中 `ProofSource` 的配置，确保证书文件存在且可访问。查看 OpenSSL 相关的错误信息。

3. **客户端和服务器之间的网络问题:**  虽然不是 `QuicCryptoServerStream` 本身的问题，但网络丢包、延迟高等问题可能导致握手消息无法可靠传输，最终导致连接失败。
   - **例子:**  客户端发送的 CHLO 消息在传输过程中丢失，服务器没有收到握手请求。
   - **调试线索:**  使用网络抓包工具（如 Wireshark）分析客户端和服务器之间的网络流量，查看握手消息是否正常发送和接收。

4. **回调函数未正确处理:**  `QuicCryptoServerStream` 使用回调函数来处理异步操作，例如 `ValidateClientHello` 的结果。如果这些回调函数没有正确实现或处理错误，可能会导致程序逻辑错误或崩溃。
   - **例子:**  `ValidateClientHelloCallback::Run` 方法中没有正确处理错误码，导致即使 CHLO 验证失败，程序也继续执行后续逻辑。
   - **调试线索:**  仔细检查回调函数的实现，确保能够处理各种情况，特别是错误情况。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中输入一个以 `https://` 开头的 URL 并尝试访问。**
2. **浏览器解析 URL，识别出需要建立 HTTPS 连接。**
3. **浏览器检查本地是否有该域名的 QUIC 会话信息。**
   - 如果有，浏览器可能会尝试 0-RTT 连接，在初始的 CHLO 消息中携带应用数据。
   - 如果没有，浏览器会发起一个标准的 QUIC 握手。
4. **浏览器构建一个 Client Hello (CHLO) 消息，包含必要的信息，例如支持的 QUIC 版本、服务器名称 (SNI) 等。**
5. **浏览器将 CHLO 消息发送到服务器的 IP 地址和端口。**
6. **服务器的网络栈接收到来自客户端的数据包。**
7. **服务器的网络栈识别出这是一个新的 QUIC 连接请求，并创建一个新的 `QuicSession` 和 `QuicCryptoServerStream` 实例来处理这个连接。**  `QuicCryptoServerStream` 的构造函数会被调用。
8. **接收到的 CHLO 消息被传递给 `QuicCryptoServerStream::OnHandshakeMessage` 方法。** 这是处理客户端握手消息的入口点。
9. **`OnHandshakeMessage` 方法会调用 `crypto_config_->ValidateClientHello` 来验证 CHLO 消息。** 这涉及到与 `QuicCryptoServerConfig` 和 `ProofSource` 的交互。
10. **`crypto_config_->ValidateClientHello` 的结果会通过回调函数 (`QuicCryptoServerStream::ValidateCallback`) 返回给 `QuicCryptoServerStream`。**
11. **根据验证结果，`QuicCryptoServerStream` 可能会调用 `ProcessClientHello` 来进一步处理 CHLO 消息，生成 SHLO 或 REJ 消息，并发送回客户端。**

**调试线索:**

当调试 QUIC 服务器端的握手问题时，以下是一些可以跟踪的线索：

* **服务器日志:**  查看服务器的日志输出，特别是与 QUIC 和加密相关的日志，可以帮助了解 CHLO 验证的结果、服务器选择的参数、发生的错误等。
* **网络抓包:**  使用 Wireshark 等工具抓取客户端和服务器之间的网络包，可以详细分析握手消息的内容，例如 CHLO、SHLO、REJ 等，以及网络延迟和丢包情况。
* **断点调试:**  在 `QuicCryptoServerStream` 的关键方法（例如 `OnHandshakeMessage`, `ProcessClientHello`, `ValidateCallback::Run`) 设置断点，可以逐步跟踪握手过程，查看变量的值，了解代码的执行流程。
* **检查 `QuicCryptoServerConfig`:**  确认服务器的加密配置是否正确，包括证书路径、支持的 QUIC 版本、服务器配置 ID 等。
* **查看客户端的错误信息:**  如果可能，查看客户端的错误日志或开发者工具中的网络请求信息，了解客户端收到的错误代码和原因。

希望这些详细的解释能够帮助你理解 `QuicCryptoServerStream` 的功能以及它在 QUIC 连接建立过程中的作用。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_crypto_server_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_crypto_server_stream.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "openssl/sha.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_testvalue.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {

class QuicCryptoServerStream::ProcessClientHelloCallback
    : public ProcessClientHelloResultCallback {
 public:
  ProcessClientHelloCallback(
      QuicCryptoServerStream* parent,
      const quiche::QuicheReferenceCountedPointer<
          ValidateClientHelloResultCallback::Result>& result)
      : parent_(parent), result_(result) {}

  void Run(
      QuicErrorCode error, const std::string& error_details,
      std::unique_ptr<CryptoHandshakeMessage> message,
      std::unique_ptr<DiversificationNonce> diversification_nonce,
      std::unique_ptr<ProofSource::Details> proof_source_details) override {
    if (parent_ == nullptr) {
      return;
    }

    parent_->FinishProcessingHandshakeMessageAfterProcessClientHello(
        *result_, error, error_details, std::move(message),
        std::move(diversification_nonce), std::move(proof_source_details));
  }

  void Cancel() { parent_ = nullptr; }

 private:
  QuicCryptoServerStream* parent_;
  quiche::QuicheReferenceCountedPointer<
      ValidateClientHelloResultCallback::Result>
      result_;
};

QuicCryptoServerStream::QuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache, QuicSession* session,
    QuicCryptoServerStreamBase::Helper* helper)
    : QuicCryptoServerStreamBase(session),
      QuicCryptoHandshaker(this, session),
      session_(session),
      delegate_(session),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      signed_config_(new QuicSignedServerConfig),
      helper_(helper),
      num_handshake_messages_(0),
      num_handshake_messages_with_server_nonces_(0),
      send_server_config_update_cb_(nullptr),
      num_server_config_update_messages_sent_(0),
      zero_rtt_attempted_(false),
      chlo_packet_size_(0),
      validate_client_hello_cb_(nullptr),
      encryption_established_(false),
      one_rtt_keys_available_(false),
      one_rtt_packet_decrypted_(false),
      crypto_negotiated_params_(new QuicCryptoNegotiatedParameters) {}

QuicCryptoServerStream::~QuicCryptoServerStream() {
  CancelOutstandingCallbacks();
}

void QuicCryptoServerStream::CancelOutstandingCallbacks() {
  // Detach from the validation callback.  Calling this multiple times is safe.
  if (validate_client_hello_cb_ != nullptr) {
    validate_client_hello_cb_->Cancel();
    validate_client_hello_cb_ = nullptr;
  }
  if (send_server_config_update_cb_ != nullptr) {
    send_server_config_update_cb_->Cancel();
    send_server_config_update_cb_ = nullptr;
  }
  if (std::shared_ptr<ProcessClientHelloCallback> cb =
          process_client_hello_cb_.lock()) {
    cb->Cancel();
    process_client_hello_cb_.reset();
  }
}

void QuicCryptoServerStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QuicCryptoHandshaker::OnHandshakeMessage(message);
  ++num_handshake_messages_;
  chlo_packet_size_ = session()->connection()->GetCurrentPacket().length();

  // Do not process handshake messages after the handshake is confirmed.
  if (one_rtt_keys_available_) {
    OnUnrecoverableError(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE,
                         "Unexpected handshake message from client");
    return;
  }

  if (message.tag() != kCHLO) {
    OnUnrecoverableError(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                         "Handshake packet not CHLO");
    return;
  }

  if (validate_client_hello_cb_ != nullptr ||
      !process_client_hello_cb_.expired()) {
    // Already processing some other handshake message.  The protocol
    // does not allow for clients to send multiple handshake messages
    // before the server has a chance to respond.
    OnUnrecoverableError(QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO,
                         "Unexpected handshake message while processing CHLO");
    return;
  }

  chlo_hash_ =
      CryptoUtils::HashHandshakeMessage(message, Perspective::IS_SERVER);

  std::unique_ptr<ValidateCallback> cb(new ValidateCallback(this));
  QUICHE_DCHECK(validate_client_hello_cb_ == nullptr);
  QUICHE_DCHECK(process_client_hello_cb_.expired());
  validate_client_hello_cb_ = cb.get();
  crypto_config_->ValidateClientHello(
      message, GetClientAddress(), session()->connection()->self_address(),
      transport_version(), session()->connection()->clock(), signed_config_,
      std::move(cb));
}

void QuicCryptoServerStream::FinishProcessingHandshakeMessage(
    quiche::QuicheReferenceCountedPointer<
        ValidateClientHelloResultCallback::Result>
        result,
    std::unique_ptr<ProofSource::Details> details) {
  // Clear the callback that got us here.
  QUICHE_DCHECK(validate_client_hello_cb_ != nullptr);
  QUICHE_DCHECK(process_client_hello_cb_.expired());
  validate_client_hello_cb_ = nullptr;

  auto cb = std::make_shared<ProcessClientHelloCallback>(this, result);
  process_client_hello_cb_ = cb;
  ProcessClientHello(result, std::move(details), std::move(cb));
}

void QuicCryptoServerStream::
    FinishProcessingHandshakeMessageAfterProcessClientHello(
        const ValidateClientHelloResultCallback::Result& result,
        QuicErrorCode error, const std::string& error_details,
        std::unique_ptr<CryptoHandshakeMessage> reply,
        std::unique_ptr<DiversificationNonce> diversification_nonce,
        std::unique_ptr<ProofSource::Details> proof_source_details) {
  // Clear the callback that got us here.
  QUICHE_DCHECK(!process_client_hello_cb_.expired());
  QUICHE_DCHECK(validate_client_hello_cb_ == nullptr);
  process_client_hello_cb_.reset();
  proof_source_details_ = std::move(proof_source_details);

  AdjustTestValue("quic::QuicCryptoServerStream::after_process_client_hello",
                  session());

  if (!session()->connection()->connected()) {
    QUIC_CODE_COUNT(quic_crypto_disconnected_after_process_client_hello);
    QUIC_LOG_FIRST_N(INFO, 10)
        << "After processing CHLO, QUIC connection has been closed with code "
        << session()->error() << ", details: " << session()->error_details();
    return;
  }

  const CryptoHandshakeMessage& message = result.client_hello;
  if (error != QUIC_NO_ERROR) {
    OnUnrecoverableError(error, error_details);
    return;
  }

  if (reply->tag() != kSHLO) {
    session()->connection()->set_fully_pad_crypto_handshake_packets(
        crypto_config_->pad_rej());
    // Send REJ in plaintext.
    SendHandshakeMessage(*reply, ENCRYPTION_INITIAL);
    return;
  }

  // If we are returning a SHLO then we accepted the handshake.  Now
  // process the negotiated configuration options as part of the
  // session config.
  QuicConfig* config = session()->config();
  OverrideQuicConfigDefaults(config);
  std::string process_error_details;
  const QuicErrorCode process_error =
      config->ProcessPeerHello(message, CLIENT, &process_error_details);
  if (process_error != QUIC_NO_ERROR) {
    OnUnrecoverableError(process_error, process_error_details);
    return;
  }

  session()->OnConfigNegotiated();

  config->ToHandshakeMessage(reply.get(), session()->transport_version());

  // Receiving a full CHLO implies the client is prepared to decrypt with
  // the new server write key.  We can start to encrypt with the new server
  // write key.
  //
  // NOTE: the SHLO will be encrypted with the new server write key.
  delegate_->OnNewEncryptionKeyAvailable(
      ENCRYPTION_ZERO_RTT,
      std::move(crypto_negotiated_params_->initial_crypters.encrypter));
  delegate_->OnNewDecryptionKeyAvailable(
      ENCRYPTION_ZERO_RTT,
      std::move(crypto_negotiated_params_->initial_crypters.decrypter),
      /*set_alternative_decrypter=*/false,
      /*latch_once_used=*/false);
  delegate_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  delegate_->DiscardOldDecryptionKey(ENCRYPTION_INITIAL);
  session()->connection()->SetDiversificationNonce(*diversification_nonce);

  session()->connection()->set_fully_pad_crypto_handshake_packets(
      crypto_config_->pad_shlo());
  // Send SHLO in ENCRYPTION_ZERO_RTT.
  SendHandshakeMessage(*reply, ENCRYPTION_ZERO_RTT);
  delegate_->OnNewEncryptionKeyAvailable(
      ENCRYPTION_FORWARD_SECURE,
      std::move(crypto_negotiated_params_->forward_secure_crypters.encrypter));
  delegate_->OnNewDecryptionKeyAvailable(
      ENCRYPTION_FORWARD_SECURE,
      std::move(crypto_negotiated_params_->forward_secure_crypters.decrypter),
      /*set_alternative_decrypter=*/true,
      /*latch_once_used=*/false);
  encryption_established_ = true;
  one_rtt_keys_available_ = true;
  delegate_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  delegate_->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
}

void QuicCryptoServerStream::SendServerConfigUpdate(
    const CachedNetworkParameters* cached_network_params) {
  if (!one_rtt_keys_available_) {
    return;
  }

  if (send_server_config_update_cb_ != nullptr) {
    QUIC_DVLOG(1)
        << "Skipped server config update since one is already in progress";
    return;
  }

  std::unique_ptr<SendServerConfigUpdateCallback> cb(
      new SendServerConfigUpdateCallback(this));
  send_server_config_update_cb_ = cb.get();

  crypto_config_->BuildServerConfigUpdateMessage(
      session()->transport_version(), chlo_hash_,
      previous_source_address_tokens_, session()->connection()->self_address(),
      GetClientAddress(), session()->connection()->clock(),
      session()->connection()->random_generator(), compressed_certs_cache_,
      *crypto_negotiated_params_, cached_network_params, std::move(cb));
}

QuicCryptoServerStream::SendServerConfigUpdateCallback::
    SendServerConfigUpdateCallback(QuicCryptoServerStream* parent)
    : parent_(parent) {}

void QuicCryptoServerStream::SendServerConfigUpdateCallback::Cancel() {
  parent_ = nullptr;
}

// From BuildServerConfigUpdateMessageResultCallback
void QuicCryptoServerStream::SendServerConfigUpdateCallback::Run(
    bool ok, const CryptoHandshakeMessage& message) {
  if (parent_ == nullptr) {
    return;
  }
  parent_->FinishSendServerConfigUpdate(ok, message);
}

void QuicCryptoServerStream::FinishSendServerConfigUpdate(
    bool ok, const CryptoHandshakeMessage& message) {
  // Clear the callback that got us here.
  QUICHE_DCHECK(send_server_config_update_cb_ != nullptr);
  send_server_config_update_cb_ = nullptr;

  if (!ok) {
    QUIC_DVLOG(1) << "Server: Failed to build server config update (SCUP)!";
    return;
  }

  QUIC_DVLOG(1) << "Server: Sending server config update: "
                << message.DebugString();

  // Send server config update in ENCRYPTION_FORWARD_SECURE.
  SendHandshakeMessage(message, ENCRYPTION_FORWARD_SECURE);

  ++num_server_config_update_messages_sent_;
}

bool QuicCryptoServerStream::DisableResumption() {
  QUICHE_DCHECK(false) << "Not supported for QUIC crypto.";
  return false;
}

bool QuicCryptoServerStream::IsZeroRtt() const {
  return num_handshake_messages_ == 1 &&
         num_handshake_messages_with_server_nonces_ == 0;
}

bool QuicCryptoServerStream::IsResumption() const {
  // QUIC Crypto doesn't have a non-0-RTT resumption mode.
  return IsZeroRtt();
}

int QuicCryptoServerStream::NumServerConfigUpdateMessagesSent() const {
  return num_server_config_update_messages_sent_;
}

const CachedNetworkParameters*
QuicCryptoServerStream::PreviousCachedNetworkParams() const {
  return previous_cached_network_params_.get();
}

bool QuicCryptoServerStream::ResumptionAttempted() const {
  return zero_rtt_attempted_;
}

bool QuicCryptoServerStream::EarlyDataAttempted() const {
  QUICHE_DCHECK(false) << "Not supported for QUIC crypto.";
  return zero_rtt_attempted_;
}

void QuicCryptoServerStream::SetPreviousCachedNetworkParams(
    CachedNetworkParameters cached_network_params) {
  previous_cached_network_params_.reset(
      new CachedNetworkParameters(cached_network_params));
}

void QuicCryptoServerStream::OnPacketDecrypted(EncryptionLevel level) {
  if (level == ENCRYPTION_FORWARD_SECURE) {
    one_rtt_packet_decrypted_ = true;
    delegate_->NeuterHandshakeData();
  }
}

void QuicCryptoServerStream::OnHandshakeDoneReceived() { QUICHE_DCHECK(false); }

void QuicCryptoServerStream::OnNewTokenReceived(absl::string_view /*token*/) {
  QUICHE_DCHECK(false);
}

std::string QuicCryptoServerStream::GetAddressToken(
    const CachedNetworkParameters* /*cached_network_parameters*/) const {
  QUICHE_DCHECK(false);
  return "";
}

bool QuicCryptoServerStream::ValidateAddressToken(
    absl::string_view /*token*/) const {
  QUICHE_DCHECK(false);
  return false;
}

bool QuicCryptoServerStream::ShouldSendExpectCTHeader() const {
  return signed_config_->proof.send_expect_ct_header;
}

bool QuicCryptoServerStream::DidCertMatchSni() const {
  return signed_config_->proof.cert_matched_sni;
}

const ProofSource::Details* QuicCryptoServerStream::ProofSourceDetails() const {
  return proof_source_details_.get();
}

bool QuicCryptoServerStream::GetBase64SHA256ClientChannelID(
    std::string* output) const {
  if (!encryption_established() ||
      crypto_negotiated_params_->channel_id.empty()) {
    return false;
  }

  const std::string& channel_id(crypto_negotiated_params_->channel_id);
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t*>(channel_id.data()), channel_id.size(),
         digest);

  quiche::QuicheTextUtils::Base64Encode(digest, ABSL_ARRAYSIZE(digest), output);
  return true;
}

ssl_early_data_reason_t QuicCryptoServerStream::EarlyDataReason() const {
  if (IsZeroRtt()) {
    return ssl_early_data_accepted;
  }
  if (zero_rtt_attempted_) {
    return ssl_early_data_session_not_resumed;
  }
  return ssl_early_data_no_session_offered;
}

bool QuicCryptoServerStream::encryption_established() const {
  return encryption_established_;
}

bool QuicCryptoServerStream::one_rtt_keys_available() const {
  return one_rtt_keys_available_;
}

const QuicCryptoNegotiatedParameters&
QuicCryptoServerStream::crypto_negotiated_params() const {
  return *crypto_negotiated_params_;
}

CryptoMessageParser* QuicCryptoServerStream::crypto_message_parser() {
  return QuicCryptoHandshaker::crypto_message_parser();
}

HandshakeState QuicCryptoServerStream::GetHandshakeState() const {
  return one_rtt_packet_decrypted_ ? HANDSHAKE_COMPLETE : HANDSHAKE_START;
}

void QuicCryptoServerStream::SetServerApplicationStateForResumption(
    std::unique_ptr<ApplicationState> /*state*/) {
  // QUIC Crypto doesn't need to remember any application state as part of doing
  // 0-RTT resumption, so this function is a no-op.
}

size_t QuicCryptoServerStream::BufferSizeLimitForLevel(
    EncryptionLevel level) const {
  return QuicCryptoHandshaker::BufferSizeLimitForLevel(level);
}

std::unique_ptr<QuicDecrypter>
QuicCryptoServerStream::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  // Key update is only defined in QUIC+TLS.
  QUICHE_DCHECK(false);
  return nullptr;
}

std::unique_ptr<QuicEncrypter>
QuicCryptoServerStream::CreateCurrentOneRttEncrypter() {
  // Key update is only defined in QUIC+TLS.
  QUICHE_DCHECK(false);
  return nullptr;
}

void QuicCryptoServerStream::ProcessClientHello(
    quiche::QuicheReferenceCountedPointer<
        ValidateClientHelloResultCallback::Result>
        result,
    std::unique_ptr<ProofSource::Details> proof_source_details,
    std::shared_ptr<ProcessClientHelloResultCallback> done_cb) {
  proof_source_details_ = std::move(proof_source_details);
  const CryptoHandshakeMessage& message = result->client_hello;
  std::string error_details;
  if (!helper_->CanAcceptClientHello(
          message, GetClientAddress(), session()->connection()->peer_address(),
          session()->connection()->self_address(), &error_details)) {
    done_cb->Run(QUIC_HANDSHAKE_FAILED, error_details, nullptr, nullptr,
                 nullptr);
    return;
  }

  absl::string_view user_agent_id;
  message.GetStringPiece(quic::kUAID, &user_agent_id);
  if (!session()->user_agent_id().has_value() && !user_agent_id.empty()) {
    session()->SetUserAgentId(std::string(user_agent_id));
  }

  if (!result->info.server_nonce.empty()) {
    ++num_handshake_messages_with_server_nonces_;
  }

  if (num_handshake_messages_ == 1) {
    // Client attempts zero RTT handshake by sending a non-inchoate CHLO.
    absl::string_view public_value;
    zero_rtt_attempted_ = message.GetStringPiece(kPUBS, &public_value);
  }

  // Store the bandwidth estimate from the client.
  if (result->cached_network_params.bandwidth_estimate_bytes_per_second() > 0) {
    previous_cached_network_params_.reset(
        new CachedNetworkParameters(result->cached_network_params));
  }
  previous_source_address_tokens_ = result->info.source_address_tokens;

  QuicConnection* connection = session()->connection();
  crypto_config_->ProcessClientHello(
      result, /*reject_only=*/false, connection->connection_id(),
      connection->self_address(), GetClientAddress(), connection->version(),
      session()->supported_versions(), connection->clock(),
      connection->random_generator(), compressed_certs_cache_,
      crypto_negotiated_params_, signed_config_,
      QuicCryptoStream::CryptoMessageFramingOverhead(
          transport_version(), connection->connection_id()),
      chlo_packet_size_, std::move(done_cb));
}

void QuicCryptoServerStream::OverrideQuicConfigDefaults(
    QuicConfig* /*config*/) {}

QuicCryptoServerStream::ValidateCallback::ValidateCallback(
    QuicCryptoServerStream* parent)
    : parent_(parent) {}

void QuicCryptoServerStream::ValidateCallback::Cancel() { parent_ = nullptr; }

void QuicCryptoServerStream::ValidateCallback::Run(
    quiche::QuicheReferenceCountedPointer<Result> result,
    std::unique_ptr<ProofSource::Details> details) {
  if (parent_ != nullptr) {
    parent_->FinishProcessingHandshakeMessage(std::move(result),
                                              std::move(details));
  }
}

const QuicSocketAddress QuicCryptoServerStream::GetClientAddress() {
  return session()->connection()->peer_address();
}

SSL* QuicCryptoServerStream::GetSsl() const { return nullptr; }

bool QuicCryptoServerStream::IsCryptoFrameExpectedForEncryptionLevel(
    EncryptionLevel /*level*/) const {
  return true;
}

EncryptionLevel
QuicCryptoServerStream::GetEncryptionLevelToSendCryptoDataOfSpace(
    PacketNumberSpace space) const {
  if (space == INITIAL_DATA) {
    return ENCRYPTION_INITIAL;
  }
  if (space == APPLICATION_DATA) {
    return ENCRYPTION_ZERO_RTT;
  }
  QUICHE_DCHECK(false);
  return NUM_ENCRYPTION_LEVELS;
}

}  // namespace quic

"""

```
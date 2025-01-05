Response:
Let's break down the thought process to analyze the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of `tls_chlo_extractor.cc`, its relation to JavaScript, logical reasoning with input/output, common user/programming errors, and debugging steps. The file path hints at its role in the QUIC protocol within the Chromium network stack. The name "TLS CHLO Extractor" strongly suggests it's about extracting information from the ClientHello message during the TLS handshake.

2. **High-Level Overview (Skim the Code):** Quickly read through the code, noting key classes, methods, and included headers. This gives a general idea of the structure and dependencies. Notice the use of OpenSSL (`openssl/ssl.h`), QUIC-specific types (`quic/...`), and Chromium/Quiche utilities (`absl/...`, `quiche/platform/...`).

3. **Identify Key Functionality - State Machine:**  The `State` enum and the `state_` member variable are immediately important. This suggests the class manages a state machine. The different states (`kInitial`, `kParsedPartialChloFragment`, `kParsedFullSinglePacketChlo`, `kParsedFullMultiPacketChlo`, `kUnrecoverableFailure`) clearly indicate the progression of parsing the ClientHello.

4. **Identify Key Functionality - Packet Processing:** The `IngestPacket` method is central. Trace its logic:
    * Checks for errors and version compatibility.
    * Creates a `QuicFramer` if it's the first packet.
    * Calls `framer_->ProcessPacket()`.
    * Updates the state based on whether a CRYPTO frame was parsed.

5. **Identify Key Functionality - CRYPTO Frame Handling:** The `OnCryptoFrame` method is triggered by the `QuicFramer`. It passes the data to the `crypto_stream_sequencer_`. The `OnDataAvailable` method, called by the sequencer, feeds the reassembled data to BoringSSL (`SSL_provide_quic_data`).

6. **Identify Key Functionality - BoringSSL Interaction:** The code heavily uses OpenSSL/BoringSSL functions. The static methods like `SetReadSecretCallback`, `SetWriteSecretCallback`, `WriteMessageCallback`, `FlushFlightCallback`, `SendAlertCallback`, and `SelectCertCallback` are crucial for intercepting and influencing the TLS handshake process. The `SelectCertCallback` is particularly important, as it's where the actual parsing of the ClientHello data happens (`HandleParsedChlo`).

7. **Analyze `HandleParsedChlo`:** This function extracts key information: server name (SNI), ALPN, supported groups, certificate compression algorithms, and whether resumption or early data is attempted. It also stores the raw ClientHello bytes.

8. **Determine JavaScript Relevance:** Consider how this server-side code interacts with client-side behavior, particularly JavaScript in a browser. The extracted information (SNI, ALPN) directly affects which server the browser connects to and the protocol negotiated. JavaScript APIs like `fetch` and WebSocket use TLS, and the server's handling of the CHLO influences the connection setup.

9. **Develop Examples (Input/Output, User Errors):**  Think about realistic scenarios:
    * **Input/Output:**  A raw network packet containing a ClientHello would be the input. The output would be the extracted fields.
    * **User Errors:**  Misconfigured server settings or network issues preventing the initial packets from reaching the server are common.

10. **Trace User Operations:** Consider the steps a user takes to trigger this code:  Opening a website in a browser initiates a TLS handshake, including sending the ClientHello.

11. **Debugging Clues:**  Focus on the state transitions and error handling. Logging within the code (`QUIC_DLOG`, `QUIC_BUG`) provides valuable clues. The state machine itself is a great debugging aid.

12. **Structure the Answer:** Organize the findings into the requested sections: Functionality, JavaScript relevance, logical reasoning, user errors, and debugging.

13. **Refine and Elaborate:**  Expand on the initial points with more detail and context. For example, when discussing JavaScript, mention specific APIs. For user errors, provide concrete examples. For debugging, explain the significance of the state machine.

14. **Review and Verify:** Read through the generated answer to ensure accuracy and clarity. Check if all aspects of the original request have been addressed. For example, ensure the explanation of *how* the code extracts information (using BoringSSL's parsing capabilities) is present. Double-check the assumptions and examples for correctness.
这个C++源代码文件 `tls_chlo_extractor.cc` 的主要功能是从QUIC连接的初始握手包（Initial Packet）中提取 TLS ClientHello（CHLO）消息的关键信息。由于QUIC使用了TLS 1.3进行安全握手，ClientHello是客户端发送的第一个包含TLS握手信息的包。

以下是该文件的详细功能列表：

**核心功能：**

1. **解析 QUIC Initial 包:** 该类通过 `IngestPacket` 方法接收 `QuicReceivedPacket`，并使用 `QuicFramer` 解析 QUIC 帧。它只处理长头部（Long Header）且类型为 Initial 的 QUIC 包。
2. **提取 TLS ClientHello 数据:**  当 `QuicFramer` 解析到 CRYPTO 帧（包含 TLS 握手数据）时，`OnCryptoFrame` 方法会被调用，并将数据传递给 `crypto_stream_sequencer_` 进行重组。
3. **使用 BoringSSL 解析 CHLO:**  一旦 `crypto_stream_sequencer_` 收集到足够的连续数据，`OnDataAvailable` 方法会被调用。该方法会将重组的握手数据提供给 BoringSSL 的 `SSL_provide_quic_data` 函数。
4. **拦截 BoringSSL 的证书选择回调:**  该类注册了一个 `SelectCertCallback`，当 BoringSSL 尝试选择证书时，这个回调会被触发。在这个回调中，`HandleParsedChlo` 方法会被调用，实际执行 CHLO 的解析。
5. **提取关键 CHLO 信息:** `HandleParsedChlo` 方法从 BoringSSL 解析的 `SSL_CLIENT_HELLO` 结构体中提取以下信息：
    * **Server Name Indication (SNI):**  客户端请求连接的服务器名称。
    * **Application-Layer Protocol Negotiation (ALPN):** 客户端支持的应用层协议列表。
    * **Supported Groups:**  客户端支持的椭圆曲线组列表，用于密钥交换。
    * **Certificate Compression Algorithms:** 客户端支持的证书压缩算法列表。
    * **Resumption Attempted:**  指示客户端是否尝试 TLS 会话恢复。
    * **Early Data Attempted:** 指示客户端是否发送了 Early Data (0-RTT 数据)。
    * **Raw ClientHello Bytes:**  完整的 ClientHello 消息的字节流。
6. **状态管理:**  该类维护一个状态机 (`state_`) 来跟踪 CHLO 提取的进度，包括：
    * `kInitial`: 初始状态。
    * `kParsedPartialChloFragment`: 已解析部分 CHLO 数据。
    * `kParsedFullSinglePacketChlo`: 已解析完整的单包 CHLO。
    * `kParsedFullMultiPacketChlo`: 已解析完整的跨多包 CHLO。
    * `kUnrecoverableFailure`:  遇到不可恢复的错误。
7. **错误处理:**  如果解析过程中遇到错误，例如数据不完整或格式错误，该类会切换到 `kUnrecoverableFailure` 状态并记录错误详情。
8. **阻止不期望的 BoringSSL 操作:** 该类通过注册特定的 BoringSSL 回调（例如 `SetReadSecretCallback`, `SetWriteSecretCallback`, `WriteMessageCallback`, `FlushFlightCallback`）并返回错误来阻止 BoringSSL 执行某些操作，因为这个类的目的是只提取 CHLO 信息，而不是完成整个 TLS 握手。

**与 JavaScript 的关系：**

这个 C++ 代码运行在 Chromium 的网络栈中，负责处理底层的网络协议。它不直接与 JavaScript 代码交互。然而，它提取的信息对于基于 Chromium 的浏览器或 Node.js 应用中运行的 JavaScript 代码有间接影响：

* **SNI (Server Name Indication):** JavaScript 发起的网络请求 (例如使用 `fetch` API) 会触发浏览器发送包含 SNI 的 ClientHello。`TlsChloExtractor` 提取的 SNI 信息会被服务器用于选择正确的虚拟主机和证书。
    * **举例:** 当 JavaScript 代码执行 `fetch('https://example.com/api')` 时，Chromium 网络栈会构建一个包含 `example.com` 作为 SNI 的 ClientHello。服务器上的 `TlsChloExtractor` 会提取 `example.com`。
* **ALPN (Application-Layer Protocol Negotiation):** JavaScript 可以通过一些 API (如 `WebSocket`) 间接影响 ALPN。浏览器会根据配置和上下文在 ClientHello 中包含支持的协议列表。服务器通过 `TlsChloExtractor` 提取 ALPN 并选择一个双方都支持的协议。
    * **举例:**  如果 JavaScript 代码创建了一个 WebSocket 连接，并且浏览器支持 HTTP/3，那么 ClientHello 的 ALPN 扩展中可能包含 "h3"。服务器上的 `TlsChloExtractor` 会提取这个信息，如果服务器也支持 HTTP/3，连接可能会升级到 HTTP/3。
* **用户操作影响:** 用户在浏览器地址栏输入 URL，或者 JavaScript 发起网络请求，最终会触发 `TlsChloExtractor` 的工作。

**逻辑推理、假设输入与输出：**

**假设输入:** 一个包含 TLS ClientHello 的 QUIC Initial 包。假设这个包是连接的第一个包，包含完整的 ClientHello 消息。

**输出:**

* `state_` 会变为 `kParsedFullSinglePacketChlo`。
* `server_name_` 会被设置为 ClientHello 中的 SNI 值（例如 "example.com"）。
* `alpns_` 会被设置为 ClientHello 中的 ALPN 列表（例如 `{"h3", "http/1.1"}`）。
* `supported_groups_` 会被设置为 ClientHello 中的支持的组列表（例如 `TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` 的数值表示）。
* `cert_compression_algos_` 会被设置为 ClientHello 中的证书压缩算法列表（如果有）。
* `resumption_attempted_` 会根据 ClientHello 中是否存在 Pre-Shared Key 扩展设置为 `true` 或 `false`。
* `early_data_attempted_` 会根据 ClientHello 中是否存在 Early Data 扩展设置为 `true` 或 `false`。
* `client_hello_bytes_` 会包含原始的 ClientHello 字节流。

**假设输入 (多包 CHLO):** 假设 ClientHello 消息很大，需要多个 QUIC Initial 包来传输。

**输出:**

* 接收到第一个包含部分 CHLO 的包后，`state_` 会变为 `kParsedPartialChloFragment`。
* 只有当接收到所有包含 CHLO 的包并成功重组后，`state_` 才会变为 `kParsedFullMultiPacketChlo`。
* 其他输出信息与单包 CHLO 的情况相同。

**用户或编程常见的使用错误：**

1. **依赖不完整的 CHLO 信息:**  如果在 `TlsChloExtractor` 的状态为非 "已解析完整" 时就尝试访问提取的信息，可能会得到不完整或错误的数据。
    * **例子:**  在状态为 `kParsedPartialChloFragment` 时尝试获取 SNI，如果 SNI 数据尚未到达，`server_name_` 可能为空。
2. **错误的版本处理:**  如果尝试使用 `TlsChloExtractor` 处理非 TLS 1.3 的 QUIC 连接，`IngestPacket` 会直接返回，不会提取任何信息。
    * **例子:**  接收到 QUIC 草案版本的包，由于 `version.handshake_protocol != PROTOCOL_TLS1_3`，包会被忽略。
3. **网络问题导致 CHLO 数据不完整:**  如果由于网络丢包等原因，构成 ClientHello 的 QUIC 包没有全部到达，`TlsChloExtractor` 可能会进入 `kUnrecoverableFailure` 状态。
    * **例子:**  客户端发送了 3 个 Initial 包来传输 CHLO，但第二个包丢失了。`crypto_stream_sequencer_` 会因为数据空洞而报错。
4. **在错误的时机调用方法:** 某些方法（例如获取提取的信息）应该在 `TlsChloExtractor` 完成 CHLO 解析后调用。提前调用可能会导致未定义行为或返回默认值。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 HTTPS URL 或 JavaScript 发起 HTTPS 请求:**  这是最常见的触发场景。
2. **浏览器开始建立与服务器的 QUIC 连接:** 如果浏览器和服务器都支持 QUIC，且满足其他条件（例如协议协商），浏览器会尝试使用 QUIC。
3. **浏览器构造 TLS ClientHello 消息:**  浏览器根据配置（例如用户是否启用了 ECH，支持的 ALPN 协议等）生成 ClientHello。
4. **浏览器将 ClientHello 封装在 QUIC Initial 包中发送给服务器:**  ClientHello 数据会被放在 CRYPTO 帧中。
5. **服务器接收到 QUIC Initial 包:**  Chromium 网络栈接收到该包。
6. **QUIC 连接处理代码将包传递给 `TlsChloExtractor` 的 `IngestPacket` 方法:**  这是 `TlsChloExtractor` 开始工作的入口。
7. **`TlsChloExtractor` 解析 QUIC 头部，识别 Initial 包和 CRYPTO 帧:**  `QuicFramer` 完成此操作。
8. **CRYPTO 帧的数据被添加到 `crypto_stream_sequencer_`:**  用于重组可能分片的 CHLO 数据。
9. **一旦数据足够，BoringSSL 被调用解析 TLS 结构:**  `OnDataAvailable` 触发。
10. **`SelectCertCallback` 被 BoringSSL 调用:**  这是 `TlsChloExtractor` 拦截 CHLO 解析的关键点。
11. **`HandleParsedChlo` 方法提取 CHLO 信息并更新状态。**

**调试线索:**

* **查看 `TlsChloExtractor` 的状态 (`state_`):**  可以确定 CHLO 解析的进度和是否发生错误。
* **检查 `error_details_`:**  如果状态是 `kUnrecoverableFailure`，可以查看具体的错误信息。
* **查看 QUIC 包的内容:**  使用网络抓包工具（如 Wireshark）可以查看客户端发送的 QUIC Initial 包，包括 CRYPTO 帧中的 ClientHello 数据，以验证客户端发送的内容。
* **BoringSSL 的日志:**  虽然代码中没有直接展示，但 BoringSSL 内部的日志（如果启用）可能提供更底层的 TLS 解析信息。
* **`QUIC_DLOG` 输出:**  代码中使用了 `QUIC_DLOG` 进行调试输出，可以查看相关的日志信息。
* **对比不同场景下的 CHLO 内容:**  例如，对比启用和禁用某个 TLS 功能（如 ECH）时提取的 CHLO 信息，可以帮助理解功能的实现原理。

总而言之，`tls_chlo_extractor.cc` 是 Chromium QUIC 实现中一个关键的组件，它负责从初始握手包中高效且安全地提取 TLS ClientHello 的关键信息，为后续的连接处理决策提供依据。虽然它不直接与 JavaScript 交互，但它提取的信息直接影响着基于 Chromium 的浏览器和 Node.js 应用的网络行为。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_chlo_extractor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/tls_chlo_extractor.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/frames/quic_crypto_frame.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {
bool HasExtension(const SSL_CLIENT_HELLO* client_hello, uint16_t extension) {
  const uint8_t* unused_extension_bytes;
  size_t unused_extension_len;
  return 1 == SSL_early_callback_ctx_extension_get(client_hello, extension,
                                                   &unused_extension_bytes,
                                                   &unused_extension_len);
}

std::vector<uint16_t> GetSupportedGroups(const SSL_CLIENT_HELLO* client_hello) {
  const uint8_t* extension_data;
  size_t extension_len;
  int rv = SSL_early_callback_ctx_extension_get(
      client_hello, TLSEXT_TYPE_supported_groups, &extension_data,
      &extension_len);
  if (rv != 1) {
    return {};
  }

  // See https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7 for the
  // format of this extension.
  QuicDataReader named_groups_reader(
      reinterpret_cast<const char*>(extension_data), extension_len);
  uint16_t named_groups_len;
  if (!named_groups_reader.ReadUInt16(&named_groups_len) ||
      named_groups_len + sizeof(uint16_t) != extension_len) {
    QUIC_CODE_COUNT(quic_chlo_supported_groups_invalid_length);
    return {};
  }

  std::vector<uint16_t> named_groups;
  while (!named_groups_reader.IsDoneReading()) {
    uint16_t named_group;
    if (!named_groups_reader.ReadUInt16(&named_group)) {
      QUIC_CODE_COUNT(quic_chlo_supported_groups_odd_length);
      QUIC_LOG_FIRST_N(WARNING, 10) << "Failed to read named groups";
      break;
    }
    named_groups.push_back(named_group);
  }
  return named_groups;
}

std::vector<uint16_t> GetCertCompressionAlgos(
    const SSL_CLIENT_HELLO* client_hello) {
  const uint8_t* extension_data;
  size_t extension_len;
  int rv = SSL_early_callback_ctx_extension_get(
      client_hello, TLSEXT_TYPE_cert_compression, &extension_data,
      &extension_len);
  if (rv != 1) {
    return {};
  }
  // See https://datatracker.ietf.org/doc/html/rfc8879#section-3 for the format
  // of this extension.
  QuicDataReader cert_compression_algos_reader(
      reinterpret_cast<const char*>(extension_data), extension_len);
  uint8_t algos_len;
  if (!cert_compression_algos_reader.ReadUInt8(&algos_len) || algos_len == 0 ||
      algos_len % sizeof(uint16_t) != 0 ||
      algos_len + sizeof(uint8_t) != extension_len) {
    QUIC_CODE_COUNT(quic_chlo_cert_compression_algos_invalid_length);
    return {};
  }

  size_t num_algos = algos_len / sizeof(uint16_t);
  std::vector<uint16_t> cert_compression_algos;
  cert_compression_algos.reserve(num_algos);
  for (size_t i = 0; i < num_algos; ++i) {
    uint16_t cert_compression_algo;
    if (!cert_compression_algos_reader.ReadUInt16(&cert_compression_algo)) {
      QUIC_CODE_COUNT(quic_chlo_fail_to_read_cert_compression_algo);
      return {};
    }
    cert_compression_algos.push_back(cert_compression_algo);
  }
  return cert_compression_algos;
}

}  // namespace

TlsChloExtractor::TlsChloExtractor()
    : crypto_stream_sequencer_(this),
      state_(State::kInitial),
      parsed_crypto_frame_in_this_packet_(false) {}

TlsChloExtractor::TlsChloExtractor(TlsChloExtractor&& other)
    : TlsChloExtractor() {
  *this = std::move(other);
}

TlsChloExtractor& TlsChloExtractor::operator=(TlsChloExtractor&& other) {
  framer_ = std::move(other.framer_);
  if (framer_) {
    framer_->set_visitor(this);
  }
  crypto_stream_sequencer_ = std::move(other.crypto_stream_sequencer_);
  crypto_stream_sequencer_.set_stream(this);
  ssl_ = std::move(other.ssl_);
  if (ssl_) {
    std::pair<SSL_CTX*, int> shared_handles = GetSharedSslHandles();
    int ex_data_index = shared_handles.second;
    const int rv = SSL_set_ex_data(ssl_.get(), ex_data_index, this);
    QUICHE_CHECK_EQ(rv, 1) << "Internal allocation failure in SSL_set_ex_data";
  }
  state_ = other.state_;
  error_details_ = std::move(other.error_details_);
  parsed_crypto_frame_in_this_packet_ =
      other.parsed_crypto_frame_in_this_packet_;
  supported_groups_ = std::move(other.supported_groups_);
  cert_compression_algos_ = std::move(other.cert_compression_algos_);
  alpns_ = std::move(other.alpns_);
  server_name_ = std::move(other.server_name_);
  client_hello_bytes_ = std::move(other.client_hello_bytes_);
  return *this;
}

void TlsChloExtractor::IngestPacket(const ParsedQuicVersion& version,
                                    const QuicReceivedPacket& packet) {
  if (state_ == State::kUnrecoverableFailure) {
    QUIC_DLOG(ERROR) << "Not ingesting packet after unrecoverable error";
    return;
  }
  if (version == UnsupportedQuicVersion()) {
    QUIC_DLOG(ERROR) << "Not ingesting packet with unsupported version";
    return;
  }
  if (version.handshake_protocol != PROTOCOL_TLS1_3) {
    QUIC_DLOG(ERROR) << "Not ingesting packet with non-TLS version " << version;
    return;
  }
  if (framer_) {
    // This is not the first packet we have ingested, check if version matches.
    if (!framer_->IsSupportedVersion(version)) {
      QUIC_DLOG(ERROR)
          << "Not ingesting packet with version mismatch, expected "
          << framer_->version() << ", got " << version;
      return;
    }
  } else {
    // This is the first packet we have ingested, setup parser.
    framer_ = std::make_unique<QuicFramer>(
        ParsedQuicVersionVector{version}, QuicTime::Zero(),
        Perspective::IS_SERVER, /*expected_server_connection_id_length=*/0);
    // Note that expected_server_connection_id_length only matters for short
    // headers and we explicitly drop those so we can pass any value here.
    framer_->set_visitor(this);
  }

  // When the framer parses |packet|, if it sees a CRYPTO frame it will call
  // OnCryptoFrame below and that will set parsed_crypto_frame_in_this_packet_
  // to true.
  parsed_crypto_frame_in_this_packet_ = false;
  const bool parse_success = framer_->ProcessPacket(packet);
  if (state_ == State::kInitial && parsed_crypto_frame_in_this_packet_) {
    // If we parsed a CRYPTO frame but didn't advance the state from initial,
    // then it means that we will need more packets to reassemble the full CHLO,
    // so we advance the state here. This can happen when the first packet
    // received is not the first one in the crypto stream. This allows us to
    // differentiate our state between single-packet CHLO and multi-packet CHLO.
    state_ = State::kParsedPartialChloFragment;
  }

  if (!parse_success) {
    // This could be due to the packet being non-initial for example.
    QUIC_DLOG(ERROR) << "Failed to process packet";
    return;
  }
}

// This is called when the framer parsed the unencrypted parts of the header.
bool TlsChloExtractor::OnUnauthenticatedPublicHeader(
    const QuicPacketHeader& header) {
  if (header.form != IETF_QUIC_LONG_HEADER_PACKET) {
    QUIC_DLOG(ERROR) << "Not parsing non-long-header packet " << header;
    return false;
  }
  if (header.long_packet_type != INITIAL) {
    QUIC_DLOG(ERROR) << "Not parsing non-initial packet " << header;
    return false;
  }
  // QuicFramer is constructed without knowledge of the server's connection ID
  // so it needs to be set up here in order to decrypt the packet.
  //
  // Only call SetInitialObfuscators once for the first ingested packet, whose
  // |header.destination_connection_id| is the original connection ID.
  if (framer_->GetDecrypter(ENCRYPTION_INITIAL) == nullptr) {
    framer_->SetInitialObfuscators(header.destination_connection_id);
  }

  return true;
}

// This is called by the framer if it detects a change in version during
// parsing.
bool TlsChloExtractor::OnProtocolVersionMismatch(ParsedQuicVersion version) {
  // This should never be called because we already check versions in
  // IngestPacket.
  QUIC_BUG(quic_bug_10855_1) << "Unexpected version mismatch, expected "
                             << framer_->version() << ", got " << version;
  return false;
}

// This is called by the QuicStreamSequencer if it encounters an unrecoverable
// error that will prevent it from reassembling the crypto stream data.
void TlsChloExtractor::OnUnrecoverableError(QuicErrorCode error,
                                            const std::string& details) {
  HandleUnrecoverableError(absl::StrCat(
      "Crypto stream error ", QuicErrorCodeToString(error), ": ", details));
}

void TlsChloExtractor::OnUnrecoverableError(
    QuicErrorCode error, QuicIetfTransportErrorCodes ietf_error,
    const std::string& details) {
  HandleUnrecoverableError(absl::StrCat(
      "Crypto stream error ", QuicErrorCodeToString(error), "(",
      QuicIetfTransportErrorCodeString(ietf_error), "): ", details));
}

// This is called by the framer if it sees a CRYPTO frame during parsing.
bool TlsChloExtractor::OnCryptoFrame(const QuicCryptoFrame& frame) {
  if (frame.level != ENCRYPTION_INITIAL) {
    // Since we drop non-INITIAL packets in OnUnauthenticatedPublicHeader,
    // we should never receive any CRYPTO frames at other encryption levels.
    QUIC_BUG(quic_bug_10855_2) << "Parsed bad-level CRYPTO frame " << frame;
    return false;
  }
  // parsed_crypto_frame_in_this_packet_ is checked in IngestPacket to allow
  // advancing our state to track the difference between single-packet CHLO
  // and multi-packet CHLO.
  parsed_crypto_frame_in_this_packet_ = true;
  crypto_stream_sequencer_.OnCryptoFrame(frame);
  return true;
}

// Called by the QuicStreamSequencer when it receives a CRYPTO frame that
// advances the amount of contiguous data we now have starting from offset 0.
void TlsChloExtractor::OnDataAvailable() {
  // Lazily set up BoringSSL handle.
  SetupSslHandle();

  // Get data from the stream sequencer and pass it to BoringSSL.
  struct iovec iov;
  while (crypto_stream_sequencer_.GetReadableRegion(&iov)) {
    const int rv = SSL_provide_quic_data(
        ssl_.get(), ssl_encryption_initial,
        reinterpret_cast<const uint8_t*>(iov.iov_base), iov.iov_len);
    if (rv != 1) {
      HandleUnrecoverableError("SSL_provide_quic_data failed");
      return;
    }
    crypto_stream_sequencer_.MarkConsumed(iov.iov_len);
  }

  // Instruct BoringSSL to attempt parsing a full CHLO from the provided data.
  // We ignore the return value since we know the handshake is going to fail
  // because we explicitly cancel processing once we've parsed the CHLO.
  (void)SSL_do_handshake(ssl_.get());
}

// static
TlsChloExtractor* TlsChloExtractor::GetInstanceFromSSL(SSL* ssl) {
  std::pair<SSL_CTX*, int> shared_handles = GetSharedSslHandles();
  int ex_data_index = shared_handles.second;
  return reinterpret_cast<TlsChloExtractor*>(
      SSL_get_ex_data(ssl, ex_data_index));
}

// static
int TlsChloExtractor::SetReadSecretCallback(
    SSL* ssl, enum ssl_encryption_level_t /*level*/,
    const SSL_CIPHER* /*cipher*/, const uint8_t* /*secret*/,
    size_t /*secret_length*/) {
  GetInstanceFromSSL(ssl)->HandleUnexpectedCallback("SetReadSecretCallback");
  return 0;
}

// static
int TlsChloExtractor::SetWriteSecretCallback(
    SSL* ssl, enum ssl_encryption_level_t /*level*/,
    const SSL_CIPHER* /*cipher*/, const uint8_t* /*secret*/,
    size_t /*secret_length*/) {
  GetInstanceFromSSL(ssl)->HandleUnexpectedCallback("SetWriteSecretCallback");
  return 0;
}

// static
int TlsChloExtractor::WriteMessageCallback(
    SSL* ssl, enum ssl_encryption_level_t /*level*/, const uint8_t* /*data*/,
    size_t /*len*/) {
  GetInstanceFromSSL(ssl)->HandleUnexpectedCallback("WriteMessageCallback");
  return 0;
}

// static
int TlsChloExtractor::FlushFlightCallback(SSL* ssl) {
  GetInstanceFromSSL(ssl)->HandleUnexpectedCallback("FlushFlightCallback");
  return 0;
}

void TlsChloExtractor::HandleUnexpectedCallback(
    const std::string& callback_name) {
  std::string error_details =
      absl::StrCat("Unexpected callback ", callback_name);
  QUIC_BUG(quic_bug_10855_3) << error_details;
  HandleUnrecoverableError(error_details);
}

// static
int TlsChloExtractor::SendAlertCallback(SSL* ssl,
                                        enum ssl_encryption_level_t /*level*/,
                                        uint8_t desc) {
  GetInstanceFromSSL(ssl)->SendAlert(desc);
  return 0;
}

void TlsChloExtractor::SendAlert(uint8_t tls_alert_value) {
  if (tls_alert_value == SSL3_AD_HANDSHAKE_FAILURE && HasParsedFullChlo()) {
    // This is the most common scenario. Since we return an error from
    // SelectCertCallback in order to cancel further processing, BoringSSL will
    // try to send this alert to tell the client that the handshake failed.
    return;
  }
  HandleUnrecoverableError(absl::StrCat(
      "BoringSSL attempted to send alert ", static_cast<int>(tls_alert_value),
      " ", SSL_alert_desc_string_long(tls_alert_value)));
  if (state_ == State::kUnrecoverableFailure) {
    tls_alert_ = tls_alert_value;
  }
}

// static
enum ssl_select_cert_result_t TlsChloExtractor::SelectCertCallback(
    const SSL_CLIENT_HELLO* client_hello) {
  GetInstanceFromSSL(client_hello->ssl)->HandleParsedChlo(client_hello);
  // Always return an error to cancel any further processing in BoringSSL.
  return ssl_select_cert_error;
}

// Extracts the server name and ALPN from the parsed ClientHello.
void TlsChloExtractor::HandleParsedChlo(const SSL_CLIENT_HELLO* client_hello) {
  const char* server_name =
      SSL_get_servername(client_hello->ssl, TLSEXT_NAMETYPE_host_name);
  if (server_name) {
    server_name_ = std::string(server_name);
  }

  resumption_attempted_ =
      HasExtension(client_hello, TLSEXT_TYPE_pre_shared_key);
  early_data_attempted_ = HasExtension(client_hello, TLSEXT_TYPE_early_data);

  QUICHE_DCHECK(client_hello_bytes_.empty());
  client_hello_bytes_.assign(
      client_hello->client_hello,
      client_hello->client_hello + client_hello->client_hello_len);

  const uint8_t* alpn_data;
  size_t alpn_len;
  int rv = SSL_early_callback_ctx_extension_get(
      client_hello, TLSEXT_TYPE_application_layer_protocol_negotiation,
      &alpn_data, &alpn_len);
  if (rv == 1) {
    QuicDataReader alpns_reader(reinterpret_cast<const char*>(alpn_data),
                                alpn_len);
    absl::string_view alpns_payload;
    if (!alpns_reader.ReadStringPiece16(&alpns_payload)) {
      QUIC_CODE_COUNT_N(quic_chlo_alpns_invalid, 1, 2);
      HandleUnrecoverableError("Failed to read alpns_payload");
      return;
    }
    QuicDataReader alpns_payload_reader(alpns_payload);
    while (!alpns_payload_reader.IsDoneReading()) {
      absl::string_view alpn_payload;
      if (!alpns_payload_reader.ReadStringPiece8(&alpn_payload)) {
        QUIC_CODE_COUNT_N(quic_chlo_alpns_invalid, 2, 2);
        HandleUnrecoverableError("Failed to read alpn_payload");
        return;
      }
      alpns_.emplace_back(std::string(alpn_payload));
    }
  }

  supported_groups_ = GetSupportedGroups(client_hello);
  if (GetQuicReloadableFlag(quic_parse_cert_compression_algos_from_chlo)) {
    cert_compression_algos_ = GetCertCompressionAlgos(client_hello);
    if (cert_compression_algos_.empty()) {
      QUIC_RELOADABLE_FLAG_COUNT_N(quic_parse_cert_compression_algos_from_chlo,
                                   1, 2);
    } else {
      QUIC_RELOADABLE_FLAG_COUNT_N(quic_parse_cert_compression_algos_from_chlo,
                                   2, 2);
    }
  }

  // Update our state now that we've parsed a full CHLO.
  if (state_ == State::kInitial) {
    state_ = State::kParsedFullSinglePacketChlo;
  } else if (state_ == State::kParsedPartialChloFragment) {
    state_ = State::kParsedFullMultiPacketChlo;
  } else {
    QUIC_BUG(quic_bug_10855_4)
        << "Unexpected state on successful parse " << StateToString(state_);
  }
}

// static
std::pair<SSL_CTX*, int> TlsChloExtractor::GetSharedSslHandles() {
  // Use a lambda to benefit from C++11 guarantee that static variables are
  // initialized lazily in a thread-safe manner. |shared_handles| is therefore
  // guaranteed to be initialized exactly once and never destructed.
  static std::pair<SSL_CTX*, int>* shared_handles = []() {
    CRYPTO_library_init();
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_with_buffers_method());
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    static const SSL_QUIC_METHOD kQuicCallbacks{
        TlsChloExtractor::SetReadSecretCallback,
        TlsChloExtractor::SetWriteSecretCallback,
        TlsChloExtractor::WriteMessageCallback,
        TlsChloExtractor::FlushFlightCallback,
        TlsChloExtractor::SendAlertCallback};
    SSL_CTX_set_quic_method(ssl_ctx, &kQuicCallbacks);
    SSL_CTX_set_select_certificate_cb(ssl_ctx,
                                      TlsChloExtractor::SelectCertCallback);
    int ex_data_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return new std::pair<SSL_CTX*, int>(ssl_ctx, ex_data_index);
  }();
  return *shared_handles;
}

// Sets up the per-instance SSL handle needed by BoringSSL.
void TlsChloExtractor::SetupSslHandle() {
  if (ssl_) {
    // Handles have already been set up.
    return;
  }

  std::pair<SSL_CTX*, int> shared_handles = GetSharedSslHandles();
  SSL_CTX* ssl_ctx = shared_handles.first;
  int ex_data_index = shared_handles.second;

  ssl_ = bssl::UniquePtr<SSL>(SSL_new(ssl_ctx));
  const int rv = SSL_set_ex_data(ssl_.get(), ex_data_index, this);
  QUICHE_CHECK_EQ(rv, 1) << "Internal allocation failure in SSL_set_ex_data";
  SSL_set_accept_state(ssl_.get());

  // Make sure we use the right TLS extension codepoint.
  int use_legacy_extension = 0;
  if (framer_->version().UsesLegacyTlsExtension()) {
    use_legacy_extension = 1;
  }
  SSL_set_quic_use_legacy_codepoint(ssl_.get(), use_legacy_extension);
}

// Called by other methods to record any unrecoverable failures they experience.
void TlsChloExtractor::HandleUnrecoverableError(
    const std::string& error_details) {
  if (HasParsedFullChlo()) {
    // Ignore errors if we've parsed everything successfully.
    QUIC_DLOG(ERROR) << "Ignoring error: " << error_details;
    return;
  }
  QUIC_DLOG(ERROR) << "Handling error: " << error_details;

  state_ = State::kUnrecoverableFailure;

  if (error_details_.empty()) {
    error_details_ = error_details;
  } else {
    error_details_ = absl::StrCat(error_details_, "; ", error_details);
  }
}

// static
std::string TlsChloExtractor::StateToString(State state) {
  switch (state) {
    case State::kInitial:
      return "Initial";
    case State::kParsedFullSinglePacketChlo:
      return "ParsedFullSinglePacketChlo";
    case State::kParsedFullMultiPacketChlo:
      return "ParsedFullMultiPacketChlo";
    case State::kParsedPartialChloFragment:
      return "ParsedPartialChloFragment";
    case State::kUnrecoverableFailure:
      return "UnrecoverableFailure";
  }
  return absl::StrCat("Unknown(", static_cast<int>(state), ")");
}

std::ostream& operator<<(std::ostream& os,
                         const TlsChloExtractor::State& state) {
  os << TlsChloExtractor::StateToString(state);
  return os;
}

}  // namespace quic

"""

```
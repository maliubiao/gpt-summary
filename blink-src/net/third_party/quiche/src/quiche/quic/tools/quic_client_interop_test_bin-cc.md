Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The primary goal is to understand what this Chromium network stack code does and its potential relationship with JavaScript, along with providing debugging context.

2. **Initial Scan for Keywords and Structure:**  I start by quickly scanning the code for keywords that might give me immediate clues:
    * `#include`:  Shows dependencies on other Quic/Chromium libraries.
    * `DEFINE_QUICHE_COMMAND_LINE_FLAG`: Indicates command-line arguments are being parsed, suggesting this is an executable.
    * `namespace quic`:  Confirms this is part of the QUIC implementation.
    * `class QuicClientInteropRunner`:  A key class, suggesting it's responsible for running interop tests.
    * `AttemptRequest`, `AttemptResumption`, `SendRequest`: These look like core functionalities.
    * `Feature` enum:  This is crucial. It defines the different test scenarios being run.
    * `main` function: The entry point, showing how the program is executed and how the `ServerSupport` function is called.
    * `HttpHeaderBlock`:  Indicates interaction with HTTP/3.
    * `FakeProofVerifier`, `QuicClientSessionCache`: These suggest client-side QUIC behavior.

3. **Deconstruct the `QuicClientInteropRunner` Class:** This class seems central to the functionality. I'll analyze its methods:
    * `InsertFeature`:  Marks a test as successful.
    * `features`: Returns the set of successful tests.
    * `AttemptResumption`:  Specifically tests session resumption.
    * `AttemptRequest`: The main function for making requests and testing different QUIC features. The various boolean parameters are key to understanding the different test cases.
    * `ConstructHeaderBlock`:  Creates HTTP headers for requests.
    * `SendRequest`:  Sends the actual request and checks for `kStreamData`.
    * `OnConnectionCloseFrame`, `OnVersionNegotiationPacket`: These are callbacks for specific QUIC events, used to mark the success of those features.

4. **Analyze the `Feature` Enum:** This enum is critical for understanding the purpose of the code. I'll list each feature and what it likely tests:
    * Version Negotiation, Handshake, Stream Data, Connection Close, Resumption, ZeroRtt, Retry, Quantum, Rebinding, Key Update, Http3, DynamicEntryReferenced.

5. **Examine the `ServerSupport` Function:** This function seems to orchestrate the tests. It takes server information and a QUIC version, creates a `QuicClientInteropRunner`, and calls `AttemptRequest`.

6. **Understand the `main` Function:**
    * Parses command-line flags for host, port, and QUIC version.
    * Optionally parses a URL from the command line.
    * Selects a QUIC version.
    * Calls `ServerSupport` to run the tests.
    * Prints the results based on the successful features.

7. **Identify the Core Functionality:** The primary function of this code is to test the interoperability of a QUIC client implementation against a QUIC server. It systematically attempts various QUIC features and records which ones succeed.

8. **Consider the Relationship with JavaScript:**  This is where I need to think about how browser networking works.
    * **Direct Relationship:**  This C++ code *is* part of Chromium's networking stack, which is the underlying engine that JavaScript uses in browsers (like Chrome) to make network requests.
    * **Indirect Relationship:** JavaScript's `fetch` API or `XMLHttpRequest` ultimately relies on this kind of low-level code to establish connections and transfer data using QUIC.
    * **Example:** A JavaScript `fetch('https://example.com')` call, when using QUIC, would go through a series of steps in the browser's network stack, eventually involving code like this to handle the QUIC handshake, stream management, etc.

9. **Develop Hypothetical Inputs and Outputs:**  To illustrate the logic, I'll create a simple scenario:
    * **Input:** Command-line arguments specifying a server's host and port.
    * **Output:** A string of characters representing the supported QUIC features.

10. **Identify Potential User/Programming Errors:**  Think about common mistakes when using or developing network clients:
    * Incorrect host/port.
    * Firewall blocking.
    * Server not supporting the requested QUIC version.
    * Incorrectly parsing command-line arguments.

11. **Outline the User's Path to This Code (Debugging Context):**  Consider how a developer might end up looking at this file:
    * Running interop tests as part of development.
    * Debugging QUIC connection issues.
    * Investigating specific QUIC feature implementations.

12. **Structure the Response:**  Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the functionalities, explaining the `QuicClientInteropRunner` and the `Feature` enum.
    * Explain the relationship with JavaScript, providing concrete examples.
    * Present the hypothetical input and output scenario.
    * Discuss common errors.
    * Describe the user's path for debugging.

13. **Refine and Elaborate:** Review the generated response for clarity, accuracy, and completeness. Add details and explanations where necessary. For instance, explaining what "interoperability testing" means might be helpful.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and informative response that addresses all aspects of the prompt. The key is to break down the code into manageable parts, understand the purpose of each part, and then connect it to the broader context of web browser networking and JavaScript.
这个文件 `net/third_party/quiche/src/quiche/quic/tools/quic_client_interop_test_bin.cc` 是 Chromium 网络栈中 QUIC 协议实现的互操作性测试客户端的源代码。它的主要功能是**作为一个独立的命令行工具，用于测试 QUIC 客户端在与不同 QUIC 服务器交互时的行为和兼容性。**  它会尝试执行一系列预定义的 QUIC 功能测试，并记录哪些功能成功执行，从而验证客户端的实现是否符合 QUIC 协议规范。

以下是其更详细的功能列表：

1. **连接到指定的 QUIC 服务器:**  根据命令行参数（主机名/IP 地址和端口）连接到目标服务器。
2. **版本协商测试:** 测试客户端是否能正确处理服务器的版本协商响应，并选择双方都支持的 QUIC 版本。
3. **握手测试:** 验证客户端是否能成功完成 QUIC 握手过程，建立加密连接。
4. **流数据传输测试:**  测试客户端是否能发送和接收流数据，并正确处理 ACK 机制。
5. **连接关闭测试:** 验证客户端是否能发起和接收优雅的连接关闭操作。
6. **会话恢复测试 (Resumption):** 测试客户端是否能利用之前会话的信息进行快速连接恢复。
7. **0-RTT 数据发送测试:**  测试客户端是否能在握手完成前发送 0-RTT 数据。
8. **RETRY 包处理测试:** 验证客户端是否能正确处理服务器发送的 `RETRY` 包。
9. **大 ClientHello 测试 (Quantum):**  测试客户端是否能处理跨越多个数据包的 ClientHello。
10. **重新绑定测试 (Rebinding):** 测试客户端在网络地址发生变化后能否重新绑定连接。
11. **密钥更新测试 (Key Update):**  验证客户端是否能发起和处理密钥更新操作。
12. **HTTP/3 测试:**  测试客户端是否能进行基本的 HTTP/3 事务。
13. **动态表引用测试 (Dynamic Entry Referenced):**  验证客户端是否能正确处理 HTTP/3 动态表中的条目引用。
14. **生成互操作性测试报告:**  输出一个简短的字符矩阵，表示哪些 QUIC 功能测试成功。

**与 JavaScript 功能的关系：**

该 C++ 文件本身不包含 JavaScript 代码，但它所实现的功能直接影响到浏览器中 JavaScript 的网络请求行为。当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起 HTTPS 请求时，如果浏览器和服务器协商使用了 QUIC 协议，那么这个 C++ 代码（以及相关的 QUIC 实现）就负责处理底层的 QUIC 连接建立、数据传输、加密和连接管理等操作。

**举例说明：**

假设一个 JavaScript 应用程序使用 `fetch` API 向一个支持 QUIC 的服务器发送一个 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器执行这段代码时，如果浏览器和 `example.com` 服务器都支持并协商使用了 QUIC，那么 `quic_client_interop_test_bin.cc` 中测试的各种 QUIC 功能（例如握手、流数据传输、0-RTT、连接关闭等）的正确性就直接影响到这个 JavaScript 请求是否能成功完成。

* **如果 `kHandshake` 测试失败:** JavaScript 的 `fetch` 请求可能无法建立连接。
* **如果 `kStreamData` 测试失败:** JavaScript 可能无法接收到服务器返回的 JSON 数据。
* **如果 `kZeroRtt` 测试成功:** 在某些情况下，JavaScript 的请求可以更快地发送，因为可以利用 0-RTT 数据。
* **如果 `kResumption` 测试成功:** 后续的 JavaScript `fetch` 请求可能会更快地建立连接。

**逻辑推理、假设输入与输出：**

假设我们使用以下命令行参数运行 `quic_client_interop_test_bin`：

**假设输入：**

```bash
./quic_client_interop_test_bin --host=test.example.com --port=443
```

并且假设 `test.example.com` 是一个运行着 QUIC 服务器的主机，它支持 QUIC 握手、流数据传输和连接关闭，但不完全支持 0-RTT 和会话恢复。

**逻辑推理:**

程序会首先解析命令行参数，然后尝试连接到 `test.example.com:443`。它会尝试进行版本协商，完成握手，发送请求并接收响应，然后尝试关闭连接。它还会尝试会话恢复和 0-RTT，但由于服务器不支持，这些测试可能会失败。

**假设输出：**

输出结果可能类似于：

```
Attempting interop with version QUIC_VERSION_GOES_HERE
Results for test.example.com:443
VHD C
```

这里的 `V` 代表版本协商成功 (`kVersionNegotiation`)，`H` 代表握手成功 (`kHandshake`)，`D` 代表流数据传输成功 (`kStreamData`)，`C` 代表连接关闭成功 (`kConnectionClose`)。由于假设服务器不支持 0-RTT 和会话恢复，所以 `R` 和 `Z` 没有出现。

**用户或编程常见的使用错误：**

1. **指定错误的主机名或 IP 地址：** 如果用户在命令行中输入了无法解析或无法连接的主机名/IP 地址，程序将无法连接到服务器，导致所有测试失败。
   ```bash
   ./quic_client_interop_test_bin --host=invalid.domain.xyz --port=443  # 错误的主机名
   ```
   **现象:** 程序会报错 "Failed to resolve invalid.domain.xyz"。

2. **指定错误的端口号：** 如果服务器没有在指定的端口上监听 QUIC 连接，连接将失败。
   ```bash
   ./quic_client_interop_test_bin --host=test.example.com --port=80  # 错误的端口
   ```
   **现象:** 程序可能超时或收到连接拒绝的错误。

3. **服务器不支持指定的 QUIC 版本：** 如果用户通过 `--quic_version` 标志指定了一个服务器不支持的 QUIC 版本，版本协商可能会失败。
   ```bash
   ./quic_client_interop_test_bin --host=test.example.com --port=443 --quic_version=QUIC_VERSION_43  # 服务器可能不支持 QUIC_VERSION_43
   ```
   **现象:** 版本协商测试 (`kVersionNegotiation`) 可能会失败，或者连接建立失败。

4. **防火墙阻止连接：**  客户端机器的防火墙或网络配置可能阻止与服务器的 QUIC 连接。
   **现象:** 程序可能超时或收到连接被拒绝的错误。

**用户操作如何一步步到达这里，作为调试线索：**

假设一个 Chromium 开发者正在调试一个 QUIC 连接问题，例如，发现某个网站使用 QUIC 时加载缓慢或失败。以下是他们可能到达 `quic_client_interop_test_bin.cc` 的步骤：

1. **发现问题：** 用户（可能是开发者自己或测试人员）报告在 Chrome 浏览器中访问某个网站时出现网络问题。
2. **初步诊断：** 开发者可能会使用 Chrome 的开发者工具 (F12) 的 "Network" 标签来查看请求的详细信息，确认连接是否使用了 QUIC。
3. **怀疑 QUIC 实现问题：** 如果确认使用了 QUIC，并且怀疑是客户端的 QUIC 实现存在问题，导致与某些服务器的互操作性问题。
4. **查找 QUIC 测试工具：** 开发者可能会搜索 Chromium 源代码中与 QUIC 测试相关的工具。他们可能会找到 `quic_client_interop_test_bin.cc` 这个文件。
5. **构建和运行测试工具：** 开发者需要先构建 Chromium 项目，然后编译 `quic_client_interop_test_bin` 这个目标。
6. **使用测试工具进行测试：** 开发者会使用该工具连接到出现问题的服务器，尝试复现问题或验证客户端的 QUIC 实现是否符合预期。他们可能会使用不同的命令行参数来测试特定的 QUIC 功能。
   ```bash
   ./out/Default/quic_client_interop_test_bin --host=problematic.example.com --port=443
   ```
7. **分析测试结果：**  查看输出的测试结果，判断哪些 QUIC 功能测试失败，从而缩小问题范围。例如，如果握手测试失败，可能意味着 TLS 或 QUIC 握手部分存在问题。
8. **查看源代码进行更深入的分析：** 如果测试结果表明某个特定的 QUIC 功能失败，开发者可能会进一步查看 `quic_client_interop_test_bin.cc` 中的相关代码，以及被测试的 QUIC 客户端的具体实现代码，来定位和修复 bug。他们可能会在 `AttemptRequest` 函数中查看不同功能的测试逻辑，以及在 `OnConnectionCloseFrame` 或 `OnVersionNegotiationPacket` 等回调函数中查看如何处理服务器的响应。
9. **使用调试器：**  如果需要更详细的运行时信息，开发者可能会使用 GDB 或 LLDB 等调试器来单步执行 `quic_client_interop_test_bin` 的代码，查看变量的值和程序的执行流程。

总之，`quic_client_interop_test_bin.cc` 是一个重要的工具，用于确保 Chromium 的 QUIC 客户端实现能够正确地与各种 QUIC 服务器进行交互，从而保证基于 QUIC 的网络连接的稳定性和可靠性，最终影响到用户在浏览器中使用 JavaScript 进行网络操作的体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/quic_client_interop_test_bin.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_default_client.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, host, "",
                                "The IP or hostname to connect to.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, quic_version, "",
    "The QUIC version to use. Defaults to most recent IETF QUIC version.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, port, 0, "The port to connect to.");

namespace quic {

enum class Feature {
  // First row of features ("table stakes")
  // A version negotiation response is elicited and acted on.
  kVersionNegotiation,
  // The handshake completes successfully.
  kHandshake,
  // Stream data is being exchanged and ACK'ed.
  kStreamData,
  // The connection close procedcure completes with a zero error code.
  kConnectionClose,
  // The connection was established using TLS resumption.
  kResumption,
  // 0-RTT data is being sent and acted on.
  kZeroRtt,
  // A RETRY packet was successfully processed.
  kRetry,
  // A handshake using a ClientHello that spans multiple packets completed
  // successfully.
  kQuantum,

  // Second row of features (anything else protocol-related)
  // We switched to a different port and the server migrated to it.
  kRebinding,
  // One endpoint can update keys and its peer responds correctly.
  kKeyUpdate,

  // Third row of features (H3 tests)
  // An H3 transaction succeeded.
  kHttp3,
  // One or both endpoints insert entries into dynamic table and subsequenly
  // reference them from header blocks.
  kDynamicEntryReferenced,
};

char MatrixLetter(Feature f) {
  switch (f) {
    case Feature::kVersionNegotiation:
      return 'V';
    case Feature::kHandshake:
      return 'H';
    case Feature::kStreamData:
      return 'D';
    case Feature::kConnectionClose:
      return 'C';
    case Feature::kResumption:
      return 'R';
    case Feature::kZeroRtt:
      return 'Z';
    case Feature::kRetry:
      return 'S';
    case Feature::kQuantum:
      return 'Q';
    case Feature::kRebinding:
      return 'B';
    case Feature::kKeyUpdate:
      return 'U';
    case Feature::kHttp3:
      return '3';
    case Feature::kDynamicEntryReferenced:
      return 'd';
  }
}

class QuicClientInteropRunner : QuicConnectionDebugVisitor {
 public:
  QuicClientInteropRunner() {}

  void InsertFeature(Feature feature) { features_.insert(feature); }

  std::set<Feature> features() const { return features_; }

  // Attempts a resumption using |client| by disconnecting and reconnecting. If
  // resumption is successful, |features_| is modified to add
  // Feature::kResumption to it, otherwise it is left unmodified.
  void AttemptResumption(QuicDefaultClient* client,
                         const std::string& authority);

  void AttemptRequest(QuicSocketAddress addr, std::string authority,
                      QuicServerId server_id, ParsedQuicVersion version,
                      bool test_version_negotiation, bool attempt_rebind,
                      bool attempt_multi_packet_chlo, bool attempt_key_update);

  // Constructs a Http2HeaderBlock containing the pseudo-headers needed to make
  // a GET request to "/" on the hostname |authority|.
  quiche::HttpHeaderBlock ConstructHeaderBlock(const std::string& authority);

  // Sends an HTTP request represented by |header_block| using |client|.
  void SendRequest(QuicDefaultClient* client,
                   const quiche::HttpHeaderBlock& header_block);

  void OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override {
    switch (frame.close_type) {
      case GOOGLE_QUIC_CONNECTION_CLOSE:
        QUIC_LOG(ERROR) << "Received unexpected GoogleQUIC connection close";
        break;
      case IETF_QUIC_TRANSPORT_CONNECTION_CLOSE:
        if (frame.wire_error_code == NO_IETF_QUIC_ERROR) {
          InsertFeature(Feature::kConnectionClose);
        } else {
          QUIC_LOG(ERROR) << "Received transport connection close "
                          << QuicIetfTransportErrorCodeString(
                                 static_cast<QuicIetfTransportErrorCodes>(
                                     frame.wire_error_code));
        }
        break;
      case IETF_QUIC_APPLICATION_CONNECTION_CLOSE:
        if (frame.wire_error_code == 0) {
          InsertFeature(Feature::kConnectionClose);
        } else {
          QUIC_LOG(ERROR) << "Received application connection close "
                          << frame.wire_error_code;
        }
        break;
    }
  }

  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& /*packet*/) override {
    InsertFeature(Feature::kVersionNegotiation);
  }

 private:
  std::set<Feature> features_;
};

void QuicClientInteropRunner::AttemptResumption(QuicDefaultClient* client,
                                                const std::string& authority) {
  client->Disconnect();
  if (!client->Initialize()) {
    QUIC_LOG(ERROR) << "Failed to reinitialize client";
    return;
  }
  if (!client->Connect()) {
    return;
  }

  bool zero_rtt_attempt = !client->session()->OneRttKeysAvailable();

  quiche::HttpHeaderBlock header_block = ConstructHeaderBlock(authority);
  SendRequest(client, header_block);

  if (!client->session()->OneRttKeysAvailable()) {
    return;
  }

  if (static_cast<QuicCryptoClientStream*>(
          test::QuicSessionPeer::GetMutableCryptoStream(client->session()))
          ->IsResumption()) {
    InsertFeature(Feature::kResumption);
  }
  if (static_cast<QuicCryptoClientStream*>(
          test::QuicSessionPeer::GetMutableCryptoStream(client->session()))
          ->EarlyDataAccepted() &&
      zero_rtt_attempt && client->latest_response_code() != -1) {
    InsertFeature(Feature::kZeroRtt);
  }
}

void QuicClientInteropRunner::AttemptRequest(
    QuicSocketAddress addr, std::string authority, QuicServerId server_id,
    ParsedQuicVersion version, bool test_version_negotiation,
    bool attempt_rebind, bool attempt_multi_packet_chlo,
    bool attempt_key_update) {
  ParsedQuicVersionVector versions = {version};
  if (test_version_negotiation) {
    versions.insert(versions.begin(), QuicVersionReservedForNegotiation());
  }

  auto proof_verifier = std::make_unique<FakeProofVerifier>();
  auto session_cache = std::make_unique<QuicClientSessionCache>();
  QuicConfig config;
  QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(20);
  config.SetIdleNetworkTimeout(timeout);
  if (attempt_multi_packet_chlo) {
    // Make the ClientHello span multiple packets by adding a custom transport
    // parameter.
    config.SetDiscardLengthToSend(2000);
  }
  std::unique_ptr<QuicEventLoop> event_loop =
      GetDefaultEventLoop()->Create(QuicDefaultClock::Get());
  auto client = std::make_unique<QuicDefaultClient>(
      addr, server_id, versions, config, event_loop.get(),
      std::move(proof_verifier), std::move(session_cache));
  client->set_connection_debug_visitor(this);
  if (!client->Initialize()) {
    QUIC_LOG(ERROR) << "Failed to initialize client";
    return;
  }
  const bool connect_result = client->Connect();
  QuicConnection* connection = client->session()->connection();
  if (connection == nullptr) {
    QUIC_LOG(ERROR) << "No QuicConnection object";
    return;
  }
  QuicConnectionStats client_stats = connection->GetStats();
  if (client_stats.retry_packet_processed) {
    InsertFeature(Feature::kRetry);
  }
  if (test_version_negotiation && connection->version() == version) {
    InsertFeature(Feature::kVersionNegotiation);
  }
  if (test_version_negotiation && !connect_result) {
    // Failed to negotiate version, retry without version negotiation.
    AttemptRequest(addr, authority, server_id, version,
                   /*test_version_negotiation=*/false, attempt_rebind,
                   attempt_multi_packet_chlo, attempt_key_update);
    return;
  }
  if (!client->session()->OneRttKeysAvailable()) {
    if (attempt_multi_packet_chlo) {
      // Failed to handshake with multi-packet client hello, retry without it.
      AttemptRequest(addr, authority, server_id, version,
                     test_version_negotiation, attempt_rebind,
                     /*attempt_multi_packet_chlo=*/false, attempt_key_update);
      return;
    }
    return;
  }
  InsertFeature(Feature::kHandshake);
  if (attempt_multi_packet_chlo) {
    InsertFeature(Feature::kQuantum);
  }

  quiche::HttpHeaderBlock header_block = ConstructHeaderBlock(authority);
  SendRequest(client.get(), header_block);

  if (!client->connected()) {
    return;
  }

  if (client->latest_response_code() != -1) {
    InsertFeature(Feature::kHttp3);

    if (client->client_session()->dynamic_table_entry_referenced()) {
      InsertFeature(Feature::kDynamicEntryReferenced);
    }

    if (attempt_rebind) {
      // Now make a second request after switching to a different client port.
      if (client->ChangeEphemeralPort()) {
        client->SendRequestAndWaitForResponse(header_block, "", /*fin=*/true);
        if (!client->connected()) {
          // Rebinding does not work, retry without attempting it.
          AttemptRequest(addr, authority, server_id, version,
                         test_version_negotiation, /*attempt_rebind=*/false,
                         attempt_multi_packet_chlo, attempt_key_update);
          return;
        }
        InsertFeature(Feature::kRebinding);

        if (client->client_session()->dynamic_table_entry_referenced()) {
          InsertFeature(Feature::kDynamicEntryReferenced);
        }
      } else {
        QUIC_LOG(ERROR) << "Failed to change ephemeral port";
      }
    }

    if (attempt_key_update) {
      if (connection->IsKeyUpdateAllowed()) {
        if (connection->InitiateKeyUpdate(
                KeyUpdateReason::kLocalForInteropRunner)) {
          client->SendRequestAndWaitForResponse(header_block, "", /*fin=*/true);
          if (!client->connected()) {
            // Key update does not work, retry without attempting it.
            AttemptRequest(addr, authority, server_id, version,
                           test_version_negotiation, attempt_rebind,
                           attempt_multi_packet_chlo,
                           /*attempt_key_update=*/false);
            return;
          }
          InsertFeature(Feature::kKeyUpdate);
        } else {
          QUIC_LOG(ERROR) << "Failed to initiate key update";
        }
      } else {
        QUIC_LOG(ERROR) << "Key update not allowed";
      }
    }
  }

  if (connection->connected()) {
    connection->CloseConnection(
        QUIC_NO_ERROR, "Graceful close",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    InsertFeature(Feature::kConnectionClose);
  }

  AttemptResumption(client.get(), authority);
}

quiche::HttpHeaderBlock QuicClientInteropRunner::ConstructHeaderBlock(
    const std::string& authority) {
  // Construct and send a request.
  quiche::HttpHeaderBlock header_block;
  header_block[":method"] = "GET";
  header_block[":scheme"] = "https";
  header_block[":authority"] = authority;
  header_block[":path"] = "/";
  return header_block;
}

void QuicClientInteropRunner::SendRequest(
    QuicDefaultClient* client, const quiche::HttpHeaderBlock& header_block) {
  client->set_store_response(true);
  client->SendRequestAndWaitForResponse(header_block, "", /*fin=*/true);

  QuicConnection* connection = client->session()->connection();
  if (connection == nullptr) {
    QUIC_LOG(ERROR) << "No QuicConnection object";
    return;
  }
  QuicConnectionStats client_stats = connection->GetStats();
  QuicSentPacketManager* sent_packet_manager =
      test::QuicConnectionPeer::GetSentPacketManager(connection);
  const bool received_forward_secure_ack =
      sent_packet_manager != nullptr &&
      sent_packet_manager->GetLargestAckedPacket(ENCRYPTION_FORWARD_SECURE)
          .IsInitialized();
  if (client_stats.stream_bytes_received > 0 && received_forward_secure_ack) {
    InsertFeature(Feature::kStreamData);
  }
}

std::set<Feature> ServerSupport(std::string dns_host, std::string url_host,
                                int port, ParsedQuicVersion version) {
  std::cout << "Attempting interop with version " << version << std::endl;

  // Build the client, and try to connect.
  QuicSocketAddress addr = tools::LookupAddress(dns_host, absl::StrCat(port));
  if (!addr.IsInitialized()) {
    QUIC_LOG(ERROR) << "Failed to resolve " << dns_host;
    return std::set<Feature>();
  }
  QuicServerId server_id(url_host, port);
  std::string authority = absl::StrCat(url_host, ":", port);

  QuicClientInteropRunner runner;

  runner.AttemptRequest(addr, authority, server_id, version,
                        /*test_version_negotiation=*/true,
                        /*attempt_rebind=*/true,
                        /*attempt_multi_packet_chlo=*/true,
                        /*attempt_key_update=*/true);

  return runner.features();
}

}  // namespace quic

int main(int argc, char* argv[]) {
  quiche::QuicheSystemEventLoop event_loop("quic_client");
  const char* usage = "Usage: quic_client_interop_test [options] [url]";

  std::vector<std::string> args =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);
  if (args.size() > 1) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    exit(1);
  }
  std::string dns_host = quiche::GetQuicheCommandLineFlag(FLAGS_host);
  std::string url_host = "";
  int port = quiche::GetQuicheCommandLineFlag(FLAGS_port);

  if (!args.empty()) {
    quic::QuicUrl url(args[0], "https");
    url_host = url.host();
    if (dns_host.empty()) {
      dns_host = url_host;
    }
    if (port == 0) {
      port = url.port();
    }
  }
  if (port == 0) {
    port = 443;
  }
  if (dns_host.empty()) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    exit(1);
  }
  if (url_host.empty()) {
    url_host = dns_host;
  }

  // Pick QUIC version to use.
  quic::ParsedQuicVersion version = quic::UnsupportedQuicVersion();
  std::string quic_version_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_quic_version);
  if (!quic_version_string.empty()) {
    version = quic::ParseQuicVersionString(quic_version_string);
  } else {
    for (const quic::ParsedQuicVersion& vers : quic::AllSupportedVersions()) {
      // Use the most recent IETF QUIC version.
      if (vers.HasIetfQuicFrames() && vers.UsesHttp3() && vers.UsesTls()) {
        version = vers;
        break;
      }
    }
  }
  QUICHE_CHECK(version.IsKnown());
  QuicEnableVersion(version);

  auto supported_features =
      quic::ServerSupport(dns_host, url_host, port, version);
  std::cout << "Results for " << url_host << ":" << port << std::endl;
  int current_row = 1;
  for (auto feature : supported_features) {
    if (current_row < 2 && feature >= quic::Feature::kRebinding) {
      std::cout << std::endl;
      current_row = 2;
    }
    if (current_row < 3 && feature >= quic::Feature::kHttp3) {
      std::cout << std::endl;
      current_row = 3;
    }
    std::cout << MatrixLetter(feature);
  }
  std::cout << std::endl;
}

"""

```
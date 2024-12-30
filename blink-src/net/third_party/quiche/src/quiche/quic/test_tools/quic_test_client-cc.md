Response:
Let's break down the thought process for analyzing the provided C++ code and answering the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of `quic_test_client.cc`, its relation to JavaScript (if any), potential logical inferences, common usage errors, and how a user might end up interacting with this code. The key is to identify the *purpose* of the code.

**2. Initial Code Scan and Keyword Identification:**

A quick scan reveals several key terms and concepts:

* `quic`: This immediately tells us it's related to the QUIC protocol.
* `test`: This strongly suggests the code is for testing purposes, not production.
* `client`:  This confirms it simulates a QUIC client.
* `MockableQuicClient`, `QuicTestClient`:  These are the main classes to focus on.
* `SendRequest`, `SendMessage`, `SendData`:  These indicate functions for sending data.
* `response_body`, `response_headers`: These suggest the client receives data.
* `Connect`, `Disconnect`: These are lifecycle methods for the client.
* `ProofVerifier`:  This relates to TLS/SSL certificate verification.
* `EventLoop`: This signifies asynchronous operations.
* `HttpHeaderBlock`: This deals with HTTP headers.

**3. Identifying Core Functionality (The "What"):**

Based on the keywords, it's clear this code is about creating a QUIC client specifically designed for testing. It allows users (or test scripts) to:

* **Establish a QUIC connection:** To a specified server.
* **Send HTTP requests:** With custom headers and bodies.
* **Receive HTTP responses:**  Including headers, body, and trailers.
* **Control connection parameters:** Like connection IDs, versions, etc.
* **Simulate network conditions:**  Potentially through the "mockable" aspects.
* **Verify server certificates:** Although it also has a "RecordingProofVerifier" for simplified testing.

**4. JavaScript Relationship (The "Why Not"):**

The prompt specifically asks about JavaScript. A crucial step is to recognize that this is C++ code within the Chromium network stack. QUIC is a network protocol, and this code is implementing a low-level client for that protocol. JavaScript, while used in web browsers, typically interacts with QUIC at a much higher level through browser APIs. Therefore, the direct relationship is minimal. The connection is that *Chromium's JavaScript engine (V8) uses this C++ network stack to make network requests*. It's an indirect, under-the-hood relationship. Avoid overstating the connection.

**5. Logical Inference (The "If/Then"):**

Think about the inputs and outputs of key functions. For example:

* **Input to `SendRequest`:** A URI string.
* **Output of `SendRequest`:** A stream ID (or 0 for failure).
* **Input to `SendMessage`:** HTTP headers and a body.
* **Output of `SendMessage`:** Number of bytes sent.
* **Input to `Connect`:** Server address and ID.
* **Output of `Connect`:** Establishes a QUIC connection (or fails).

Consider simple scenarios. "If I call `SendRequest` with a valid URL, then the client will attempt to send an HTTP GET request to that URL."

**6. Common Usage Errors (The "Oops"):**

Think about how a *programmer* using this testing client might make mistakes:

* **Incorrect Server Address:** Providing the wrong IP or port.
* **Invalid URI:**  Mistyping the URL.
* **Calling methods in the wrong order:** Trying to send data before connecting.
* **Not waiting for responses:**  Sending requests and not checking the `response_complete()` flag or using synchronous methods.
* **Misunderstanding asynchronous behavior:** Assuming actions happen instantly.

**7. Debugging Scenario (The "How Did We Get Here"):**

Imagine a developer is debugging a network issue in Chromium related to QUIC. How might they encounter this `quic_test_client.cc` file?

* **Writing a QUIC unit test:**  They would directly use this class to simulate client behavior.
* **Debugging a Chromium network component:**  They might step through the code and see that other network components use `QuicTestClient` internally for testing.
* **Investigating a bug report:**  A user reports a problem with a website using QUIC. Developers might use this client to reproduce the issue and isolate the cause.

**8. Structuring the Answer:**

Organize the findings logically:

* **Functionality:** Start with a high-level overview and then detail the key capabilities.
* **JavaScript Relationship:** Clearly explain the indirect connection.
* **Logical Inference:** Provide concrete examples with inputs and outputs.
* **Common Errors:**  Focus on programmer errors and give specific scenarios.
* **Debugging Scenario:** Tell a plausible story about how a developer would interact with this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This client directly interacts with JavaScript."  **Correction:**  Realized it's a C++ component, and the interaction is indirect through Chromium's architecture.
* **Initial thought:**  "List every single method." **Correction:** Focus on the most important and representative methods.
* **Initial thought:**  "The debugging scenario could involve a regular user." **Correction:**  While a user might *experience* the effects of bugs this code helps find, the direct interaction with this specific file is by developers.

By following these steps, the analysis becomes more comprehensive and addresses all aspects of the user's request in a structured and understandable way.
好的，让我们来详细分析一下 `net/third_party/quiche/src/quiche/quic/test_tools/quic_test_client.cc` 这个文件。

**文件功能概要:**

`quic_test_client.cc` 文件定义了一个用于测试 QUIC 协议客户端行为的 C++ 类 `QuicTestClient`。 它的主要功能是模拟一个 QUIC 客户端，可以连接到 QUIC 服务器，发送请求，接收响应，并提供了一些便捷的方法来验证客户端的行为和服务器的响应。

更具体地说，`QuicTestClient` 提供了以下功能：

1. **建立 QUIC 连接:**  可以连接到指定的 QUIC 服务器地址和端口。
2. **发送 HTTP/QUIC 请求:**  可以发送带有自定义头部和消息体的 HTTP/QUIC 请求。
3. **接收 HTTP/QUIC 响应:**  可以接收服务器发送的响应头部、消息体和尾部。
4. **管理多个请求/响应:**  可以发送多个请求并等待响应。
5. **模拟不同的客户端行为:**  例如，可以控制连接 ID、发送数据的时机等。
6. **获取连接和流的状态:**  可以查询连接是否已建立、是否有活动的流、错误代码等。
7. **支持同步和异步操作:**  既可以发送请求并同步等待响应，也可以进行异步操作。
8. **集成测试辅助工具:**  它依赖于 `MockableQuicClient`，这是一个可以进行更细粒度控制的 mock 客户端，用于单元测试。
9. **证书验证控制:**  可以自定义证书验证逻辑，甚至可以禁用验证（通过 `RecordingProofVerifier`）。
10. **连接迁移测试:**  支持模拟客户端 IP 地址或端口的迁移。

**与 JavaScript 功能的关系:**

`quic_test_client.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有运行时级别的关系。 但是，它在 Chromium 项目中扮演着重要的角色，而 Chromium 浏览器中使用的 V8 JavaScript 引擎需要通过底层的网络栈来执行网络请求。

**举例说明:**

假设一个开发者正在开发一个使用了 QUIC 协议的 Web 应用。 为了测试该应用在不同网络条件下的行为，或者测试其与特定 QUIC 服务器的交互，他们可能会编写 C++ 测试用例，其中会使用 `QuicTestClient` 来模拟客户端的行为。

虽然 JavaScript 代码本身不会直接调用 `QuicTestClient` 的方法，但是当浏览器中的 JavaScript 代码发起一个使用 QUIC 协议的网络请求时，Chromium 的网络栈（包括 QUIC 实现）会处理这个请求。  `QuicTestClient` 的功能是为了确保这个 C++ 网络栈的 QUIC 部分能够正确工作。

**可以理解为，`QuicTestClient` 是用来测试支撑 JavaScript 网络请求的底层基础设施的工具。**

**逻辑推理 (假设输入与输出):**

假设我们创建了一个 `QuicTestClient` 实例，并进行了以下操作：

**假设输入:**

1. **服务器地址:**  `192.168.1.100:4433`
2. **服务器主机名:** `example.com`
3. **请求 URI:** `/index.html`
4. **请求方法:** GET (默认)
5. **连接成功。**
6. **服务器返回 HTTP 状态码 200 OK。**
7. **服务器返回响应头 `Content-Type: text/html` 和 `Content-Length: 13`。**
8. **服务器返回响应体 `Hello, world!`。**

**输出:**

* `client_->connected()`:  `true` (连接已建立)
* 调用 `SendSynchronousRequest("/index.html")` 后:
    * `response_complete()`: `true`
    * `response_body()`: `"Hello, world!"`
    * `response_headers()`: 包含 `:status: 200`，`content-type: text/html`，`content-length: 13` 等头部信息。
    * `response_body_size()`: `13`
    * `bytes_read()`:  可能包含头部和消息体的总字节数，大于 13。

**如果输入发生变化:**

* **假设输入：服务器返回 HTTP 状态码 404 Not Found。**
    * **输出:** `response_headers()` 中会包含 `:status: 404`。 `response_body()` 的内容取决于服务器的配置。
* **假设输入：请求的 URI 是无效的。**
    * **输出:** `PopulateHeaderBlockFromUrl` 函数会返回 `false`，`SendRequest` 会返回 0。
* **假设输入：连接服务器失败。**
    * **输出:** `client_->connected()`: `false`， `connection_error()` 会返回相应的错误码。

**用户或编程常见的使用错误:**

1. **忘记调用 `Connect()`:**  在发送请求之前没有先建立连接。
   ```c++
   QuicTestClient client(server_address, "example.com", supported_versions);
   client.SendRequest("/index.html"); // 错误：未连接
   ```
   **后果:**  请求无法发送，可能导致程序崩溃或行为异常。

2. **使用错误的服务器地址或主机名:**  导致连接失败。
   ```c++
   QuicTestClient client(QuicSocketAddress("127.0.0.1", 80), "wrong-host.com", supported_versions);
   client.Connect(); // 可能连接到其他服务或连接失败
   ```
   **后果:**  无法连接到目标服务器。

3. **在未完成的请求上再次发送数据:**  可能会导致流的状态错误。
   ```c++
   QuicTestClient client(server_address, "example.com", supported_versions);
   client.Connect();
   client.SendMessage(headers, "part1", false); // 发送部分数据，不结束流
   client.SendMessage(headers2, "part2");       // 尝试在同一个流上发送新的请求，可能出错
   ```
   **后果:**  流可能被重置，请求失败。应该为新的请求创建新的流。

4. **不等待异步请求完成就访问响应数据:**
   ```c++
   QuicTestClient client(server_address, "example.com", supported_versions);
   client.Connect();
   client.SendRequest("/data");
   // ... 一些其他操作 ...
   std::cout << client.response_body() << std::endl; // 错误：响应可能尚未到达
   ```
   **后果:**  访问到的响应数据可能是不完整或空的。应该使用同步方法或等待响应完成的信号。

5. **内存泄漏 (虽然代码本身管理内存，但使用不当仍可能发生):** 如果在复杂场景下，对 `QuicTestClient` 的生命周期管理不当，可能会导致其内部资源的泄漏。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个 Chromium 开发者正在调试一个与 QUIC 协议相关的 bug，例如：

1. **用户报告了一个网站使用 QUIC 时加载缓慢或失败的问题。**
2. **开发者尝试在本地复现该问题。** 他们可能会使用 Chromium 提供的命令行参数来强制使用 QUIC，并访问该网站。
3. **如果问题能够复现，开发者可能会需要深入了解 QUIC 连接的细节。**  他们可能会：
    * **查看 Chrome 的内部日志 (chrome://net-internals/#quic)。**  这可以提供关于 QUIC 连接、数据包交换等的信息。
    * **使用网络抓包工具 (如 Wireshark) 来分析 QUIC 数据包。**
4. **为了更精细地控制和测试 QUIC 客户端的行为，开发者可能会编写 C++ 单元测试或集成测试。** 这时，他们就会用到 `quic_test_client.cc` 中定义的 `QuicTestClient` 类。
5. **在测试代码中，开发者会创建一个 `QuicTestClient` 实例，并配置连接参数，例如服务器地址、端口、QUIC 版本等。**
6. **然后，他们会使用 `SendRequest` 或 `SendMessage` 等方法来模拟客户端发送请求。**
7. **通过检查 `response_body()`、`response_headers()` 等方法返回的值，以及连接的状态，开发者可以验证 QUIC 客户端的行为是否符合预期。**
8. **如果测试失败，开发者可能会需要单步调试 `quic_test_client.cc` 及其相关的 QUIC 代码，以找出问题的根源。** 他们会使用 GDB 或其他调试器，设置断点，查看变量的值，跟踪代码的执行流程。

**总而言之，`quic_test_client.cc` 是 Chromium QUIC 网络栈开发和测试中不可或缺的工具，它帮助开发者验证 QUIC 客户端的正确性，并排查各种网络问题。**  虽然普通用户不会直接接触到这个文件，但它确保了浏览器在使用 QUIC 协议时的稳定性和可靠性，从而间接地影响了用户体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/quic_test_client.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/quic_test_client.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/x509.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/http/quic_spdy_client_stream.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_packet_writer_wrapper.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_stack_trace.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {
namespace test {
namespace {

// RecordingProofVerifier accepts any certificate chain and records the common
// name of the leaf and then delegates the actual verification to an actual
// verifier. If no optional verifier is provided, then VerifyProof will return
// success.
class RecordingProofVerifier : public ProofVerifier {
 public:
  explicit RecordingProofVerifier(std::unique_ptr<ProofVerifier> verifier)
      : verifier_(std::move(verifier)) {}

  // ProofVerifier interface.
  QuicAsyncStatus VerifyProof(
      const std::string& hostname, const uint16_t port,
      const std::string& server_config, QuicTransportVersion transport_version,
      absl::string_view chlo_hash, const std::vector<std::string>& certs,
      const std::string& cert_sct, const std::string& signature,
      const ProofVerifyContext* context, std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    QuicAsyncStatus status = ProcessCerts(certs, cert_sct);
    if (verifier_ == nullptr) {
      return status;
    }
    return verifier_->VerifyProof(hostname, port, server_config,
                                  transport_version, chlo_hash, certs, cert_sct,
                                  signature, context, error_details, details,
                                  std::move(callback));
  }

  QuicAsyncStatus VerifyCertChain(
      const std::string& hostname, const uint16_t port,
      const std::vector<std::string>& certs, const std::string& ocsp_response,
      const std::string& cert_sct, const ProofVerifyContext* context,
      std::string* error_details, std::unique_ptr<ProofVerifyDetails>* details,
      uint8_t* out_alert,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    // Record the cert.
    QuicAsyncStatus status = ProcessCerts(certs, cert_sct);
    if (verifier_ == nullptr) {
      return status;
    }
    return verifier_->VerifyCertChain(hostname, port, certs, ocsp_response,
                                      cert_sct, context, error_details, details,
                                      out_alert, std::move(callback));
  }

  std::unique_ptr<ProofVerifyContext> CreateDefaultContext() override {
    return verifier_ != nullptr ? verifier_->CreateDefaultContext() : nullptr;
  }

  const std::string& common_name() const { return common_name_; }

  const std::string& cert_sct() const { return cert_sct_; }

 private:
  QuicAsyncStatus ProcessCerts(const std::vector<std::string>& certs,
                               const std::string& cert_sct) {
    common_name_.clear();
    if (certs.empty()) {
      return QUIC_FAILURE;
    }

    // Parse the cert into an X509 structure.
    const uint8_t* data;
    data = reinterpret_cast<const uint8_t*>(certs[0].data());
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &data, certs[0].size()));
    if (!cert.get()) {
      return QUIC_FAILURE;
    }

    // Extract the CN field
    X509_NAME* subject = X509_get_subject_name(cert.get());
    const int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (index < 0) {
      return QUIC_FAILURE;
    }
    ASN1_STRING* name_data =
        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index));
    if (name_data == nullptr) {
      return QUIC_FAILURE;
    }

    // Convert the CN to UTF8, in case the cert represents it in a different
    // format.
    unsigned char* buf = nullptr;
    const int len = ASN1_STRING_to_UTF8(&buf, name_data);
    if (len <= 0) {
      return QUIC_FAILURE;
    }
    bssl::UniquePtr<unsigned char> deleter(buf);

    common_name_.assign(reinterpret_cast<const char*>(buf), len);
    cert_sct_ = cert_sct;
    return QUIC_SUCCESS;
  }

  std::unique_ptr<ProofVerifier> verifier_;
  std::string common_name_;
  std::string cert_sct_;
};
}  // namespace

void MockableQuicClientDefaultNetworkHelper::ProcessPacket(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address, const QuicReceivedPacket& packet) {
  QuicClientDefaultNetworkHelper::ProcessPacket(self_address, peer_address,
                                                packet);
  if (track_last_incoming_packet_) {
    last_incoming_packet_ = packet.Clone();
  }
}

SocketFd MockableQuicClientDefaultNetworkHelper::CreateUDPSocket(
    QuicSocketAddress server_address, bool* overflow_supported) {
  SocketFd fd = QuicClientDefaultNetworkHelper::CreateUDPSocket(
      server_address, overflow_supported);
  if (fd < 0) {
    return fd;
  }

  if (socket_fd_configurator_ != nullptr) {
    socket_fd_configurator_(fd);
  }
  return fd;
}

QuicPacketWriter*
MockableQuicClientDefaultNetworkHelper::CreateQuicPacketWriter() {
  QuicPacketWriter* writer =
      QuicClientDefaultNetworkHelper::CreateQuicPacketWriter();
  if (!test_writer_) {
    return writer;
  }
  test_writer_->set_writer(writer);
  return test_writer_;
}

void MockableQuicClientDefaultNetworkHelper::set_socket_fd_configurator(
    quiche::MultiUseCallback<void(SocketFd)> socket_fd_configurator) {
  socket_fd_configurator_ = std::move(socket_fd_configurator);
}

const QuicReceivedPacket*
MockableQuicClientDefaultNetworkHelper::last_incoming_packet() {
  return last_incoming_packet_.get();
}

void MockableQuicClientDefaultNetworkHelper::set_track_last_incoming_packet(
    bool track) {
  track_last_incoming_packet_ = track;
}

void MockableQuicClientDefaultNetworkHelper::UseWriter(
    QuicPacketWriterWrapper* writer) {
  QUICHE_CHECK(test_writer_ == nullptr);
  test_writer_ = writer;
}

void MockableQuicClientDefaultNetworkHelper::set_peer_address(
    const QuicSocketAddress& address) {
  QUICHE_CHECK(test_writer_ != nullptr);
  test_writer_->set_peer_address(address);
}

MockableQuicClient::MockableQuicClient(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    const ParsedQuicVersionVector& supported_versions,
    QuicEventLoop* event_loop)
    : MockableQuicClient(server_address, server_id, QuicConfig(),
                         supported_versions, event_loop) {}

MockableQuicClient::MockableQuicClient(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicEventLoop* event_loop)
    : MockableQuicClient(server_address, server_id, config, supported_versions,
                         event_loop, nullptr) {}

MockableQuicClient::MockableQuicClient(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicEventLoop* event_loop, std::unique_ptr<ProofVerifier> proof_verifier)
    : MockableQuicClient(server_address, server_id, config, supported_versions,
                         event_loop, std::move(proof_verifier), nullptr) {}

MockableQuicClient::MockableQuicClient(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicEventLoop* event_loop, std::unique_ptr<ProofVerifier> proof_verifier,
    std::unique_ptr<SessionCache> session_cache)
    : QuicDefaultClient(
          server_address, server_id, supported_versions, config, event_loop,
          std::make_unique<MockableQuicClientDefaultNetworkHelper>(event_loop,
                                                                   this),
          std::make_unique<RecordingProofVerifier>(std::move(proof_verifier)),
          std::move(session_cache)),
      override_client_connection_id_(EmptyQuicConnectionId()),
      client_connection_id_overridden_(false) {}

MockableQuicClient::~MockableQuicClient() {
  if (connected()) {
    Disconnect();
  }
}

MockableQuicClientDefaultNetworkHelper*
MockableQuicClient::mockable_network_helper() {
  return static_cast<MockableQuicClientDefaultNetworkHelper*>(
      default_network_helper());
}

const MockableQuicClientDefaultNetworkHelper*
MockableQuicClient::mockable_network_helper() const {
  return static_cast<const MockableQuicClientDefaultNetworkHelper*>(
      default_network_helper());
}

QuicConnectionId MockableQuicClient::GetClientConnectionId() {
  if (client_connection_id_overridden_) {
    return override_client_connection_id_;
  }
  if (override_client_connection_id_length_ >= 0) {
    return QuicUtils::CreateRandomConnectionId(
        override_client_connection_id_length_);
  }
  return QuicDefaultClient::GetClientConnectionId();
}

void MockableQuicClient::UseClientConnectionId(
    QuicConnectionId client_connection_id) {
  client_connection_id_overridden_ = true;
  override_client_connection_id_ = client_connection_id;
}

void MockableQuicClient::UseClientConnectionIdLength(
    int client_connection_id_length) {
  override_client_connection_id_length_ = client_connection_id_length;
}

void MockableQuicClient::UseWriter(QuicPacketWriterWrapper* writer) {
  mockable_network_helper()->UseWriter(writer);
}

void MockableQuicClient::set_peer_address(const QuicSocketAddress& address) {
  mockable_network_helper()->set_peer_address(address);
  if (client_session() != nullptr) {
    client_session()->connection()->AddKnownServerAddress(address);
  }
}

const QuicReceivedPacket* MockableQuicClient::last_incoming_packet() {
  return mockable_network_helper()->last_incoming_packet();
}

void MockableQuicClient::set_track_last_incoming_packet(bool track) {
  mockable_network_helper()->set_track_last_incoming_packet(track);
}

QuicTestClient::QuicTestClient(
    QuicSocketAddress server_address, const std::string& server_hostname,
    const ParsedQuicVersionVector& supported_versions)
    : QuicTestClient(server_address, server_hostname, QuicConfig(),
                     supported_versions) {}

QuicTestClient::QuicTestClient(
    QuicSocketAddress server_address, const std::string& server_hostname,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions)
    : event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())),
      client_(std::make_unique<MockableQuicClient>(
          server_address, QuicServerId(server_hostname, server_address.port()),
          config, supported_versions, event_loop_.get())) {
  Initialize();
}

QuicTestClient::QuicTestClient(
    QuicSocketAddress server_address, const std::string& server_hostname,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    std::unique_ptr<ProofVerifier> proof_verifier)
    : event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())),
      client_(std::make_unique<MockableQuicClient>(
          server_address, QuicServerId(server_hostname, server_address.port()),
          config, supported_versions, event_loop_.get(),
          std::move(proof_verifier))) {
  Initialize();
}

QuicTestClient::QuicTestClient(
    QuicSocketAddress server_address, const std::string& server_hostname,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    std::unique_ptr<ProofVerifier> proof_verifier,
    std::unique_ptr<SessionCache> session_cache)
    : event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())),
      client_(std::make_unique<MockableQuicClient>(
          server_address, QuicServerId(server_hostname, server_address.port()),
          config, supported_versions, event_loop_.get(),
          std::move(proof_verifier), std::move(session_cache))) {
  Initialize();
}

QuicTestClient::QuicTestClient(
    QuicSocketAddress server_address, const std::string& server_hostname,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    std::unique_ptr<ProofVerifier> proof_verifier,
    std::unique_ptr<SessionCache> session_cache,
    std::unique_ptr<QuicEventLoop> event_loop)
    : event_loop_(std::move(event_loop)),
      client_(std::make_unique<MockableQuicClient>(
          server_address, QuicServerId(server_hostname, server_address.port()),
          config, supported_versions, event_loop_.get(),
          std::move(proof_verifier), std::move(session_cache))) {
  Initialize();
}

QuicTestClient::QuicTestClient() = default;

QuicTestClient::~QuicTestClient() {
  for (std::pair<QuicStreamId, QuicSpdyClientStream*> stream : open_streams_) {
    stream.second->set_visitor(nullptr);
  }
}

void QuicTestClient::Initialize() {
  priority_ = 3;
  connect_attempted_ = false;
  auto_reconnect_ = false;
  buffer_body_ = true;
  num_requests_ = 0;
  num_responses_ = 0;
  ClearPerConnectionState();
  // As chrome will generally do this, we want it to be the default when it's
  // not overridden.
  if (!client_->config()->HasSetBytesForConnectionIdToSend()) {
    client_->config()->SetBytesForConnectionIdToSend(0);
  }
}

void QuicTestClient::SetUserAgentID(const std::string& user_agent_id) {
  client_->SetUserAgentID(user_agent_id);
}

int64_t QuicTestClient::SendRequest(const std::string& uri) {
  quiche::HttpHeaderBlock headers;
  if (!PopulateHeaderBlockFromUrl(uri, &headers)) {
    return 0;
  }
  return SendMessage(headers, "");
}

int64_t QuicTestClient::SendRequestAndRstTogether(const std::string& uri) {
  quiche::HttpHeaderBlock headers;
  if (!PopulateHeaderBlockFromUrl(uri, &headers)) {
    return 0;
  }

  QuicSpdyClientSession* session = client()->client_session();
  QuicConnection::ScopedPacketFlusher flusher(session->connection());
  int64_t ret = SendMessage(headers, "", /*fin=*/true, /*flush=*/false);

  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalStreamId(
      session->transport_version(), 0);
  session->ResetStream(stream_id, QUIC_STREAM_CANCELLED);
  return ret;
}

void QuicTestClient::SendRequestsAndWaitForResponses(
    const std::vector<std::string>& url_list) {
  for (const std::string& url : url_list) {
    SendRequest(url);
  }
  while (client()->WaitForEvents()) {
  }
}

int64_t QuicTestClient::GetOrCreateStreamAndSendRequest(
    const quiche::HttpHeaderBlock* headers, absl::string_view body, bool fin,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  // Maybe it's better just to overload this.  it's just that we need
  // for the GetOrCreateStream function to call something else...which
  // is icky and complicated, but maybe not worse than this.
  QuicSpdyClientStream* stream = GetOrCreateStream();
  if (stream == nullptr) {
    return 0;
  }
  QuicSpdyStreamPeer::set_ack_listener(stream, ack_listener);

  int64_t ret = 0;
  if (headers != nullptr) {
    quiche::HttpHeaderBlock spdy_headers(headers->Clone());
    if (spdy_headers[":authority"].as_string().empty()) {
      spdy_headers[":authority"] = client_->server_id().host();
    }
    ret = stream->SendRequest(std::move(spdy_headers), body, fin);
    ++num_requests_;
  } else {
    stream->WriteOrBufferBody(std::string(body), fin);
    ret = body.length();
  }
  return ret;
}

int64_t QuicTestClient::SendMessage(const quiche::HttpHeaderBlock& headers,
                                    absl::string_view body) {
  return SendMessage(headers, body, /*fin=*/true);
}

int64_t QuicTestClient::SendMessage(const quiche::HttpHeaderBlock& headers,
                                    absl::string_view body, bool fin) {
  return SendMessage(headers, body, fin, /*flush=*/true);
}

int64_t QuicTestClient::SendMessage(const quiche::HttpHeaderBlock& headers,
                                    absl::string_view body, bool fin,
                                    bool flush) {
  // Always force creation of a stream for SendMessage.
  latest_created_stream_ = nullptr;

  int64_t ret = GetOrCreateStreamAndSendRequest(&headers, body, fin, nullptr);

  if (flush) {
    WaitForWriteToFlush();
  }
  return ret;
}

int64_t QuicTestClient::SendData(const std::string& data, bool last_data) {
  return SendData(data, last_data, nullptr);
}

int64_t QuicTestClient::SendData(
    const std::string& data, bool last_data,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  return GetOrCreateStreamAndSendRequest(nullptr, absl::string_view(data),
                                         last_data, std::move(ack_listener));
}

bool QuicTestClient::response_complete() const { return response_complete_; }

int64_t QuicTestClient::response_body_size() const {
  return response_body_size_;
}

bool QuicTestClient::buffer_body() const { return buffer_body_; }

void QuicTestClient::set_buffer_body(bool buffer_body) {
  buffer_body_ = buffer_body;
}

const std::string& QuicTestClient::response_body() const { return response_; }

std::string QuicTestClient::SendCustomSynchronousRequest(
    const quiche::HttpHeaderBlock& headers, const std::string& body) {
  // Clear connection state here and only track this synchronous request.
  ClearPerConnectionState();
  if (SendMessage(headers, body) == 0) {
    QUIC_DLOG(ERROR) << "Failed the request for: " << headers.DebugString();
    // Set the response_ explicitly.  Otherwise response_ will contain the
    // response from the previously successful request.
    response_ = "";
  } else {
    WaitForResponse();
  }
  return response_;
}

std::string QuicTestClient::SendSynchronousRequest(const std::string& uri) {
  quiche::HttpHeaderBlock headers;
  if (!PopulateHeaderBlockFromUrl(uri, &headers)) {
    return "";
  }
  return SendCustomSynchronousRequest(headers, "");
}

void QuicTestClient::SendConnectivityProbing() {
  QuicConnection* connection = client()->client_session()->connection();
  connection->SendConnectivityProbingPacket(connection->writer(),
                                            connection->peer_address());
}

void QuicTestClient::SetLatestCreatedStream(QuicSpdyClientStream* stream) {
  latest_created_stream_ = stream;
  if (latest_created_stream_ != nullptr) {
    open_streams_[stream->id()] = stream;
    stream->set_visitor(this);
  }
}

QuicSpdyClientStream* QuicTestClient::GetOrCreateStream() {
  if (!connect_attempted_ || auto_reconnect_) {
    if (!connected()) {
      Connect();
    }
    if (!connected()) {
      return nullptr;
    }
  }
  if (open_streams_.empty()) {
    ClearPerConnectionState();
  }
  if (!latest_created_stream_) {
    SetLatestCreatedStream(client_->CreateClientStream());
    if (latest_created_stream_) {
      latest_created_stream_->SetPriority(QuicStreamPriority(
          HttpStreamPriority{priority_, /* incremental = */ false}));
    }
  }

  return latest_created_stream_;
}

QuicErrorCode QuicTestClient::connection_error() const {
  return client()->connection_error();
}

const std::string& QuicTestClient::cert_common_name() const {
  return reinterpret_cast<RecordingProofVerifier*>(client_->proof_verifier())
      ->common_name();
}

const std::string& QuicTestClient::cert_sct() const {
  return reinterpret_cast<RecordingProofVerifier*>(client_->proof_verifier())
      ->cert_sct();
}

const QuicTagValueMap& QuicTestClient::GetServerConfig() const {
  QuicCryptoClientConfig* config = client_->crypto_config();
  const QuicCryptoClientConfig::CachedState* state =
      config->LookupOrCreate(client_->server_id());
  const CryptoHandshakeMessage* handshake_msg = state->GetServerConfig();
  return handshake_msg->tag_value_map();
}

bool QuicTestClient::connected() const { return client_->connected(); }

void QuicTestClient::Connect() {
  if (connected()) {
    QUIC_BUG(quic_bug_10133_1) << "Cannot connect already-connected client";
    return;
  }
  if (!connect_attempted_) {
    client_->Initialize();
  }

  // If we've been asked to override SNI, set it now
  if (override_sni_set_) {
    client_->set_server_id(QuicServerId(override_sni_, address().port()));
  }

  client_->Connect();
  connect_attempted_ = true;
}

void QuicTestClient::ResetConnection() {
  Disconnect();
  Connect();
}

void QuicTestClient::Disconnect() {
  ClearPerConnectionState();
  if (client_->initialized()) {
    client_->Disconnect();
  }
  connect_attempted_ = false;
}

QuicSocketAddress QuicTestClient::local_address() const {
  return client_->network_helper()->GetLatestClientAddress();
}

void QuicTestClient::ClearPerRequestState() {
  stream_error_ = QUIC_STREAM_NO_ERROR;
  response_ = "";
  response_complete_ = false;
  response_headers_complete_ = false;
  response_headers_.clear();
  response_trailers_.clear();
  bytes_read_ = 0;
  bytes_written_ = 0;
  response_body_size_ = 0;
}

bool QuicTestClient::HaveActiveStream() { return !open_streams_.empty(); }

bool QuicTestClient::WaitUntil(
    int timeout_ms, std::optional<quiche::UnretainedCallback<bool()>> trigger) {
  QuicTime::Delta timeout = QuicTime::Delta::FromMilliseconds(timeout_ms);
  const QuicClock* clock = client()->session()->connection()->clock();
  QuicTime end_waiting_time = clock->Now() + timeout;
  while (connected() && !(trigger.has_value() && (*trigger)()) &&
         (timeout_ms < 0 || clock->Now() < end_waiting_time)) {
    event_loop_->RunEventLoopOnce(timeout);
    client_->WaitForEventsPostprocessing();
  }
  ReadNextResponse();
  if (trigger.has_value() && !(*trigger)()) {
    QUIC_VLOG(1) << "Client WaitUntil returning with trigger returning false.";
    return false;
  }
  return true;
}

int64_t QuicTestClient::Send(absl::string_view data) {
  return SendData(std::string(data), false);
}

bool QuicTestClient::response_headers_complete() const {
  for (std::pair<QuicStreamId, QuicSpdyClientStream*> stream : open_streams_) {
    if (stream.second->headers_decompressed()) {
      return true;
    }
  }
  return response_headers_complete_;
}

const quiche::HttpHeaderBlock* QuicTestClient::response_headers() const {
  for (std::pair<QuicStreamId, QuicSpdyClientStream*> stream : open_streams_) {
    if (stream.second->headers_decompressed()) {
      response_headers_ = stream.second->response_headers().Clone();
      break;
    }
  }
  return &response_headers_;
}

const quiche::HttpHeaderBlock& QuicTestClient::response_trailers() const {
  return response_trailers_;
}

int64_t QuicTestClient::response_size() const { return bytes_read(); }

size_t QuicTestClient::bytes_read() const {
  for (std::pair<QuicStreamId, QuicSpdyClientStream*> stream : open_streams_) {
    size_t bytes_read = stream.second->total_body_bytes_read() +
                        stream.second->header_bytes_read();
    if (bytes_read > 0) {
      return bytes_read;
    }
  }
  return bytes_read_;
}

size_t QuicTestClient::bytes_written() const {
  for (std::pair<QuicStreamId, QuicSpdyClientStream*> stream : open_streams_) {
    size_t bytes_written = stream.second->stream_bytes_written() +
                           stream.second->header_bytes_written();
    if (bytes_written > 0) {
      return bytes_written;
    }
  }
  return bytes_written_;
}

absl::string_view QuicTestClient::partial_response_body() const {
  return latest_created_stream_ == nullptr ? ""
                                           : latest_created_stream_->data();
}

void QuicTestClient::OnClose(QuicSpdyStream* stream) {
  if (stream == nullptr) {
    return;
  }
  // Always close the stream, regardless of whether it was the last stream
  // written.
  client()->OnClose(stream);
  ++num_responses_;
  if (open_streams_.find(stream->id()) == open_streams_.end()) {
    return;
  }
  if (latest_created_stream_ == stream) {
    latest_created_stream_ = nullptr;
  }
  QuicSpdyClientStream* client_stream =
      static_cast<QuicSpdyClientStream*>(stream);
  QuicStreamId id = client_stream->id();
  closed_stream_states_.insert(std::make_pair(
      id,
      PerStreamState(
          // Set response_complete to true iff stream is closed while connected.
          client_stream->stream_error(), connected(),
          client_stream->headers_decompressed(),
          client_stream->response_headers(),
          (buffer_body() ? std::string(client_stream->data()) : ""),
          client_stream->received_trailers(),
          // Use NumBytesConsumed to avoid counting retransmitted stream frames.
          client_stream->total_body_bytes_read() +
              client_stream->header_bytes_read(),
          client_stream->stream_bytes_written() +
              client_stream->header_bytes_written(),
          client_stream->data().size())));
  open_streams_.erase(id);
}

void QuicTestClient::UseWriter(QuicPacketWriterWrapper* writer) {
  client_->UseWriter(writer);
}

void QuicTestClient::UseConnectionId(QuicConnectionId server_connection_id) {
  QUICHE_DCHECK(!connected());
  client_->set_server_connection_id_override(server_connection_id);
}

void QuicTestClient::UseConnectionIdLength(
    uint8_t server_connection_id_length) {
  QUICHE_DCHECK(!connected());
  client_->set_server_connection_id_length(server_connection_id_length);
}

void QuicTestClient::UseClientConnectionId(
    QuicConnectionId client_connection_id) {
  QUICHE_DCHECK(!connected());
  client_->UseClientConnectionId(client_connection_id);
}

void QuicTestClient::UseClientConnectionIdLength(
    uint8_t client_connection_id_length) {
  QUICHE_DCHECK(!connected());
  client_->UseClientConnectionIdLength(client_connection_id_length);
}

bool QuicTestClient::MigrateSocket(const QuicIpAddress& new_host) {
  return client_->MigrateSocket(new_host);
}

bool QuicTestClient::MigrateSocketWithSpecifiedPort(
    const QuicIpAddress& new_host, int port) {
  client_->set_local_port(port);
  return client_->MigrateSocket(new_host);
}

QuicIpAddress QuicTestClient::bind_to_address() const {
  return client_->bind_to_address();
}

void QuicTestClient::set_bind_to_address(QuicIpAddress address) {
  client_->set_bind_to_address(address);
}

const QuicSocketAddress& QuicTestClient::address() const {
  return client_->server_address();
}

void QuicTestClient::WaitForWriteToFlush() {
  while (connected() && client()->session()->HasDataToWrite()) {
    client_->WaitForEvents();
  }
}

QuicTestClient::PerStreamState::PerStreamState(const PerStreamState& other)
    : stream_error(other.stream_error),
      response_complete(other.response_complete),
      response_headers_complete(other.response_headers_complete),
      response_headers(other.response_headers.Clone()),
      response(other.response),
      response_trailers(other.response_trailers.Clone()),
      bytes_read(other.bytes_read),
      bytes_written(other.bytes_written),
      response_body_size(other.response_body_size) {}

QuicTestClient::PerStreamState::PerStreamState(
    QuicRstStreamErrorCode stream_error, bool response_complete,
    bool response_headers_complete,
    const quiche::HttpHeaderBlock& response_headers,
    const std::string& response,
    const quiche::HttpHeaderBlock& response_trailers, uint64_t bytes_read,
    uint64_t bytes_written, int64_t response_body_size)
    : stream_error(stream_error),
      response_complete(response_complete),
      response_headers_complete(response_headers_complete),
      response_headers(response_headers.Clone()),
      response(response),
      response_trailers(response_trailers.Clone()),
      bytes_read(bytes_read),
      bytes_written(bytes_written),
      response_body_size(response_body_size) {}

QuicTestClient::PerStreamState::~PerStreamState() = default;

bool QuicTestClient::PopulateHeaderBlockFromUrl(
    const std::string& uri, quiche::HttpHeaderBlock* headers) {
  std::string url;
  if (absl::StartsWith(uri, "https://") || absl::StartsWith(uri, "http://")) {
    url = uri;
  } else if (uri[0] == '/') {
    url = "https://" + client_->server_id().host() + uri;
  } else {
    url = "https://" + uri;
  }
  return SpdyUtils::PopulateHeaderBlockFromUrl(url, headers);
}

void QuicTestClient::ReadNextResponse() {
  if (closed_stream_states_.empty()) {
    return;
  }

  PerStreamState state(closed_stream_states_.front().second);

  stream_error_ = state.stream_error;
  response_ = state.response;
  response_complete_ = state.response_complete;
  response_headers_complete_ = state.response_headers_complete;
  response_headers_ = state.response_headers.Clone();
  response_trailers_ = state.response_trailers.Clone();
  bytes_read_ = state.bytes_read;
  bytes_written_ = state.bytes_written;
  response_body_size_ = state.response_body_size;

  closed_stream_states_.pop_front();
}

void QuicTestClient::ClearPerConnectionState() {
  ClearPerRequestState();
  open_streams_.clear();
  closed_stream_states_.clear();
  latest_created_stream_ = nullptr;
}

void QuicTestClient::WaitForDelayedAcks() {
  // kWaitDuration is a period of time that is long enough for all delayed
  // acks to be sent and received on the other end.
  const QuicTime::Delta kWaitDuration =
      4 * QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());

  const QuicClock* clock = client()->client_session()->connection()->clock();

  QuicTime wait_until = clock->ApproximateNow() + kWaitDuration;
  while (connected() && clock->ApproximateNow() < wait_until) {
    // This waits for up to 50 ms.
    client()->WaitForEvents();
  }
}

}  // namespace test
}  // namespace quic

"""

```
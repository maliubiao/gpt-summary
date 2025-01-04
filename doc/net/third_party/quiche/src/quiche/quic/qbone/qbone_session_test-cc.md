Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request is to understand the functionality of `qbone_session_test.cc`, its relation to JavaScript (if any), its logic (with examples), potential user errors, and how a user might reach this code during debugging.

2. **Initial Scan and Keywords:**  Quickly scan the file for keywords and structure. Recognize `#include` statements indicating dependencies (like `quiche/quic`, `gtest`). See class definitions (`QboneSessionTest`, helper classes like `DataSavingQbonePacketWriter`). Notice the `TEST_P` macros, which immediately flag this as a Google Test (gtest) file. The file name itself strongly suggests it's testing `QboneSession`.

3. **Identify Core Functionality:** Focus on the `QboneSessionTest` class. What are its methods doing?
    * `CreateClientAndServerSessions`:  This clearly sets up the client and server sessions for testing. The parameters hint at testing different handshake scenarios.
    * `StartHandshake`: Initiates the QUIC handshake process.
    * `TestStreamConnection`, `TestMessages`: These are the core test cases, dealing with sending data and messages over the established connection.
    * `TestDisconnectAfterFailedHandshake`, `TestClientRejection`, `TestBadAlpn`, `TestServerRejection`: These are negative test cases, verifying how the system behaves when handshakes fail for various reasons.
    * `CannotCreateDataStreamBeforeHandshake`:  Another negative test case focusing on protocol order.
    * `ControlRequests`:  Tests the sending of control messages.
    * Helper classes like `DataSavingQbonePacketWriter` and `DataSavingQboneControlHandler`: These are for observing the side effects of the session interactions (written packets, control requests).

4. **Infer the System Under Test (SUT):**  Based on the includes and the test class name, it's clear this file is testing the `QboneSession` (both client and server implementations). The "Qbone" prefix suggests it's a specific component within the larger QUIC stack, likely related to how QUIC interacts with a lower-level network (perhaps simulating a tunnel or specialized network).

5. **Analyze Test Case Logic (with Examples):** For each `TEST_P`, try to understand the setup, the action, and the assertion:
    * **`StreamConnection`:** Sets up sessions, starts the handshake, sends data in both directions using raw packets. Asserts that the data is received correctly.
    * **`Messages`:** Similar to `StreamConnection`, but uses QUIC messages instead of raw data streams. This highlights testing different QUIC API functionalities.
    * **`ClientRejection`, `ServerRejection`, `BadAlpn`:** These set up sessions with intentionally failing handshake conditions (e.g., incorrect ALPN, failed proof verification). They assert that the connections are *not* established.
    * **`CannotCreateDataStreamBeforeHandshake`:** Attempts to send data before the handshake is complete. Expects a `QUIC_BUG` (a debug assertion).
    * **`ControlRequests`:** Sends custom control messages back and forth and verifies they are received correctly.

6. **JavaScript Relationship:**  Consider how network interactions in a browser context might relate. While this C++ code isn't directly JavaScript, it forms the *underlying networking layer* that a browser (and thus JavaScript running in the browser) might use. Think about `fetch()` or WebSockets – these JavaScript APIs rely on lower-level network protocols. Qbone might be an internal Chromium mechanism for optimizing or modifying QUIC in certain scenarios. The key here is that JavaScript doesn't *directly* interact with these C++ classes, but indirectly relies on them for network communication.

7. **User/Programming Errors:** Think about common mistakes developers might make when *using* or *testing* this kind of code:
    * Incorrectly configuring the client or server (e.g., wrong ALPN).
    * Trying to send data too early in the connection lifecycle.
    * Misunderstanding the flow of control or the timing of events in an asynchronous system like QUIC.

8. **Debugging Scenario:**  Imagine a scenario where a network connection in Chrome isn't working as expected. How might a developer end up looking at this test file?
    * They might suspect a problem with the QUIC implementation.
    * They might search the Chromium codebase for "qbone" if they suspect this specific component is involved.
    * They might be stepping through network code in a debugger and trace the execution into the QUIC stack.
    * Seeing the tests failing can provide clues about the root cause.

9. **Structure and Refine:** Organize the findings into the categories requested: functionality, JavaScript relation, logic examples, user errors, and debugging context. Use clear and concise language. For logic examples, provide simple input/output scenarios.

10. **Review and Iterate:** Read through the analysis. Are there any ambiguities?  Are the examples clear? Have all parts of the request been addressed?  For example, initially, I might not have explicitly mentioned the role of gtest, but upon review, it's a crucial piece of information to understanding the file's purpose. Similarly, double-checking the JavaScript relationship ensures the explanation is accurate (indirect, not direct interaction).
这个文件 `net/third_party/quiche/src/quiche/quic/qbone/qbone_session_test.cc` 是 Chromium 网络栈中 QUIC 协议栈的 Qbone 组件的会话测试文件。它使用 Google Test 框架 (`gtest`) 来验证 `QboneClientSession` 和 `QboneServerSession` 类的功能。

**主要功能:**

1. **测试 Qbone 会话的建立和握手:**
   - 模拟客户端和服务器之间的 QUIC 连接建立过程，包括 TLS 握手。
   - 测试在握手成功和失败的不同场景下的行为。
   - 验证 ALPN (Application-Layer Protocol Negotiation) 是否正确协商为 "qbone"。

2. **测试 Qbone 会话的数据传输:**
   - 模拟客户端和服务器之间通过 Qbone 会话发送和接收数据包。
   - 测试发送短数据包和长数据包 (大于 QUIC MTU，但小于 QBONE 最大尺寸) 的情况。
   - 区分并测试使用 QUIC Stream (非消息) 和 QUIC Message 两种方式发送数据。
   - 验证当发送超过路径 MTU 的数据包时，是否会收到 ICMPv6 Packet Too Big 消息。

3. **测试 Qbone 控制请求:**
   - 模拟客户端和服务器之间发送和接收 Qbone 特定的控制请求。
   - 使用 `QboneClientRequest` 和 `QboneServerRequest` 协议消息进行测试。
   - 验证控制请求能否成功发送和接收，并携带预期的数据。

4. **测试连接拒绝和错误处理:**
   - 模拟客户端或服务器在握手过程中拒绝连接的情况。
   - 验证在握手失败后，连接是否正确断开。
   - 测试在握手完成前尝试发送数据是否会触发断言 (EXPECT_QUIC_BUG)。

**与 JavaScript 的关系 (间接):**

这个 C++ 测试文件本身与 JavaScript 没有直接的功能关系。然而，它测试的网络协议栈组件是浏览器 (例如 Chrome) 用来实现网络通信的基础。

- **间接关系:** 当 JavaScript 代码 (例如使用 `fetch` API 或 WebSocket) 在浏览器中发起网络请求时，底层的 Chromium 网络栈会使用 QUIC 协议 (如果适用) 来建立连接和传输数据。Qbone 可能是 QUIC 的一个扩展或变体，用于特定的网络环境或优化。因此，这个测试文件确保了 Qbone 会话功能的正确性，从而间接地保证了基于浏览器的 JavaScript 网络请求的可靠性。

**举例说明 (间接关系):**

假设一个网页上的 JavaScript 代码使用 `fetch` API 向服务器请求数据：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个请求发送出去后，如果浏览器决定使用 QUIC 协议进行通信，并且在某些网络条件下可能会使用 Qbone 组件，那么 `qbone_session_test.cc` 中测试的逻辑 (例如数据包的发送和接收、握手过程) 就会在底层被执行。如果这个测试文件检测到并修复了 Qbone 会话中的错误，那么就能保证 JavaScript 的 `fetch` 请求能够更可靠地完成。

**逻辑推理 (假设输入与输出):**

**测试用例: `StreamConnection` (不使用消息)**

* **假设输入 (模拟网络数据包):**
    * 客户端发送数据包 "hello" 给服务器。
    * 客户端发送数据包 "world" 给服务器。
    * 服务器发送数据包 "Hello Again" 给客户端。
    * 服务器发送数据包 "Again" 给客户端。
    * 服务器发送一个长数据包 (接近 QBONE 最大尺寸) 给客户端。
    * 客户端发送一个长数据包 (接近 QBONE 最大尺寸) 给服务器。

* **预期输出 (观察到的行为):**
    * 服务器的 `server_writer_` 收集到来自客户端的 "hello" 和 "world" 数据包 (带有 IPv6 头部).
    * 客户端的 `client_writer_` 收集到来自服务器的 "Hello Again" 和 "Again" 数据包 (带有 IPv6 头部).
    * 客户端的 `client_writer_` 收集到来自服务器的长数据包 (带有 IPv6 头部).
    * 服务器的 `server_writer_` 收集到来自客户端的长数据包 (带有 IPv6 头部).
    * 客户端和服务器的活跃 Stream 数量在数据传输后为 0 (因为是临时 Stream)。
    * `client_peer_->GetNumStreamedPackets()` 和 `server_peer_->GetNumStreamedPackets()` 计数为 1 (因为发送了两个方向的长数据包，每个方向算一个 Stream)。
    * `client_peer_->GetNumEphemeralPackets()` 和 `server_peer_->GetNumEphemeralPackets()` 计数为 2 (因为发送了四个短数据包，每个方向两个)。

**测试用例: `Messages` (使用消息)**

* **假设输入 (模拟网络数据包):**
    * 客户端发送数据包 "hello" 给服务器。
    * 客户端发送数据包 "world" 给服务器。
    * 服务器发送一个长数据包 (超过 QUIC MTU) 给客户端。
    * 客户端发送一个长数据包 (超过 QUIC MTU) 给服务器。

* **预期输出 (观察到的行为):**
    * 服务器的 `server_writer_` 收集到来自客户端的 "hello" 和 "world" 数据包 (带有 IPv6 头部).
    * 客户端的 `client_writer_` 会收到一个 ICMPv6 Packet Too Big 消息，指示服务器发送的长数据包过大。
    * 服务器的 `server_writer_` 会收到一个 ICMPv6 Packet Too Big 消息，指示客户端发送的长数据包过大。
    * `client_peer_->GetNumMessagePackets()` 和 `server_peer_->GetNumMessagePackets()` 计数为 2 (因为每个方向发送了两个消息).

**用户或编程常见的使用错误 (会导致测试失败或运行时问题):**

1. **配置错误的 ALPN:**  如果客户端或服务器配置了错误的 ALPN 字符串 (例如，客户端没有配置 "qbone")，握手会失败。测试用例 `BadAlpn` 就是为了验证这种情况。
2. **在握手完成前尝试发送数据:**  Qbone 会话需要在握手完成后才能安全地传输应用数据。如果在握手完成前尝试发送数据，会导致程序崩溃或未定义的行为。测试用例 `CannotCreateDataStreamBeforeHandshake` 模拟了这种情况并使用了 `EXPECT_QUIC_BUG` 来检查是否触发了预期的断言。
3. **证书验证失败:** 如果客户端配置的证书验证器无法验证服务器提供的证书，握手会失败。测试用例 `ClientRejection` 模拟了这种情况。
4. **服务器配置错误:** 如果服务器的配置存在问题，例如 ProofSource 无法提供有效的证明，握手也会失败。测试用例 `ServerRejection` 模拟了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在 Chromium 中遇到了与 Qbone 组件相关的网络问题，例如：

1. **用户报告了网络连接问题:** 用户可能遇到网页加载缓慢、连接超时等问题，这些问题可能与底层的网络协议栈有关。
2. **开发者定位到 QUIC 协议栈:**  通过分析网络日志或其他调试信息，开发者可能会怀疑问题出在 QUIC 协议栈的某些组件。
3. **怀疑与 QBONE 相关:** 如果问题发生在特定的网络环境下，或者涉及到特定的 QUIC 功能扩展，开发者可能会怀疑是 Qbone 组件引起的。
4. **查看 QBONE 相关代码:** 开发者可能会浏览 `net/third_party/quiche/src/quiche/quic/qbone/` 目录下的源代码，以了解 Qbone 的实现细节。
5. **查看测试用例:** 为了验证自己的理解或者排查问题，开发者会查看 `qbone_session_test.cc` 这样的测试文件，以了解 Qbone 会话的正常工作流程和各种边界情况。
6. **运行测试用例:** 开发者可能会运行这些测试用例，以验证 Qbone 组件是否按预期工作。如果某个测试用例失败，就能提供关于问题所在的更具体的线索。
7. **断点调试:** 开发者可能会在 `qbone_session_test.cc` 或相关的 Qbone 代码中设置断点，逐步执行代码，观察变量的值，以精确定位问题的原因。

总而言之，`qbone_session_test.cc` 是一个关键的测试文件，用于确保 Chromium 的 QUIC 协议栈中 Qbone 组件的会话管理和数据传输功能的正确性和健壮性。它通过模拟各种场景和边界条件，帮助开发者及时发现和修复潜在的错误。虽然与 JavaScript 没有直接的编程接口，但它保证了浏览器底层网络通信的可靠性，从而间接地影响了基于 JavaScript 的网络应用的性能和稳定性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/qbone/qbone_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/proto/crypto_server_config_proto.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/platform/api/quic_test_loopback.h"
#include "quiche/quic/qbone/platform/icmp_packet.h"
#include "quiche/quic/qbone/qbone_client_session.h"
#include "quiche/quic/qbone/qbone_constants.h"
#include "quiche/quic/qbone/qbone_control_placeholder.pb.h"
#include "quiche/quic/qbone/qbone_packet_processor_test_tools.h"
#include "quiche/quic/qbone/qbone_server_session.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/mock_connection_id_generator.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_callbacks.h"

namespace quic {
namespace test {
namespace {

using ::testing::_;
using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Not;

std::string TestPacketIn(const std::string& body) {
  return PrependIPv6HeaderForTest(body, 5);
}

std::string TestPacketOut(const std::string& body) {
  return PrependIPv6HeaderForTest(body, 4);
}

ParsedQuicVersionVector GetTestParams() {
  SetQuicReloadableFlag(quic_disable_version_q046, false);
  return CurrentSupportedVersionsWithQuicCrypto();
}

// Used by QuicCryptoServerConfig to provide server credentials, passes
// everything through to ProofSourceForTesting if success is true,
// and fails otherwise.
class IndirectionProofSource : public ProofSource {
 public:
  explicit IndirectionProofSource(bool success) {
    if (success) {
      proof_source_ = crypto_test_utils::ProofSourceForTesting();
    }
  }

  // ProofSource override.
  void GetProof(const QuicSocketAddress& server_address,
                const QuicSocketAddress& client_address,
                const std::string& hostname, const std::string& server_config,
                QuicTransportVersion transport_version,
                absl::string_view chlo_hash,
                std::unique_ptr<Callback> callback) override {
    if (!proof_source_) {
      QuicCryptoProof proof;
      quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain =
          GetCertChain(server_address, client_address, hostname,
                       &proof.cert_matched_sni);
      callback->Run(/*ok=*/false, chain, proof, /*details=*/nullptr);
      return;
    }
    proof_source_->GetProof(server_address, client_address, hostname,
                            server_config, transport_version, chlo_hash,
                            std::move(callback));
  }

  quiche::QuicheReferenceCountedPointer<Chain> GetCertChain(
      const QuicSocketAddress& server_address,
      const QuicSocketAddress& client_address, const std::string& hostname,
      bool* cert_matched_sni) override {
    if (!proof_source_) {
      return quiche::QuicheReferenceCountedPointer<Chain>();
    }
    return proof_source_->GetCertChain(server_address, client_address, hostname,
                                       cert_matched_sni);
  }

  void ComputeTlsSignature(
      const QuicSocketAddress& server_address,
      const QuicSocketAddress& client_address, const std::string& hostname,
      uint16_t signature_algorithm, absl::string_view in,
      std::unique_ptr<SignatureCallback> callback) override {
    if (!proof_source_) {
      callback->Run(/*ok=*/true, "Signature", /*details=*/nullptr);
      return;
    }
    proof_source_->ComputeTlsSignature(server_address, client_address, hostname,
                                       signature_algorithm, in,
                                       std::move(callback));
  }

  absl::InlinedVector<uint16_t, 8> SupportedTlsSignatureAlgorithms()
      const override {
    if (!proof_source_) {
      return {};
    }
    return proof_source_->SupportedTlsSignatureAlgorithms();
  }

  TicketCrypter* GetTicketCrypter() override { return nullptr; }

 private:
  std::unique_ptr<ProofSource> proof_source_;
};

// Used by QuicCryptoClientConfig to verify server credentials, passes
// everything through to ProofVerifierForTesting is success is true,
// otherwise returns a canned response of QUIC_FAILURE.
class IndirectionProofVerifier : public ProofVerifier {
 public:
  explicit IndirectionProofVerifier(bool success) {
    if (success) {
      proof_verifier_ = crypto_test_utils::ProofVerifierForTesting();
    }
  }

  // ProofVerifier override
  QuicAsyncStatus VerifyProof(
      const std::string& hostname, const uint16_t port,
      const std::string& server_config, QuicTransportVersion transport_version,
      absl::string_view chlo_hash, const std::vector<std::string>& certs,
      const std::string& cert_sct, const std::string& signature,
      const ProofVerifyContext* context, std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* verify_details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    if (!proof_verifier_) {
      return QUIC_FAILURE;
    }
    return proof_verifier_->VerifyProof(
        hostname, port, server_config, transport_version, chlo_hash, certs,
        cert_sct, signature, context, error_details, verify_details,
        std::move(callback));
  }

  QuicAsyncStatus VerifyCertChain(
      const std::string& hostname, const uint16_t port,
      const std::vector<std::string>& certs, const std::string& ocsp_response,
      const std::string& cert_sct, const ProofVerifyContext* context,
      std::string* error_details, std::unique_ptr<ProofVerifyDetails>* details,
      uint8_t* out_alert,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    if (!proof_verifier_) {
      return QUIC_FAILURE;
    }
    return proof_verifier_->VerifyCertChain(
        hostname, port, certs, ocsp_response, cert_sct, context, error_details,
        details, out_alert, std::move(callback));
  }

  std::unique_ptr<ProofVerifyContext> CreateDefaultContext() override {
    if (!proof_verifier_) {
      return nullptr;
    }
    return proof_verifier_->CreateDefaultContext();
  }

 private:
  std::unique_ptr<ProofVerifier> proof_verifier_;
};

class DataSavingQbonePacketWriter : public QbonePacketWriter {
 public:
  void WritePacketToNetwork(const char* packet, size_t size) override {
    data_.push_back(std::string(packet, size));
  }

  const std::vector<std::string>& data() { return data_; }

 private:
  std::vector<std::string> data_;
};

template <class T>
class DataSavingQboneControlHandler : public QboneControlHandler<T> {
 public:
  void OnControlRequest(const T& request) override { data_.push_back(request); }

  void OnControlError() override { error_ = true; }

  const std::vector<T>& data() { return data_; }
  bool error() { return error_; }

 private:
  std::vector<T> data_;
  bool error_ = false;
};

// Single-threaded scheduled task runner based on a MockClock.
//
// Simulates asynchronous execution on a single thread by holding scheduled
// tasks until Run() is called. Performs no synchronization, assumes that
// Schedule() and Run() are called on the same thread.
class FakeTaskRunner {
 public:
  explicit FakeTaskRunner(MockQuicConnectionHelper* helper)
      : tasks_([](const TaskType& l, const TaskType& r) {
          // Items at a later time should run after items at an earlier time.
          // Priority queue comparisons should return true if l appears after r.
          return l->time() > r->time();
        }),
        helper_(helper) {}

  // Runs all tasks in time order.  Executes tasks scheduled at
  // the same in an arbitrary order.
  void Run() {
    while (!tasks_.empty()) {
      tasks_.top()->Run();
      tasks_.pop();
    }
  }

 private:
  class InnerTask {
   public:
    InnerTask(std::function<void()> task, QuicTime time)
        : task_(std::move(task)), time_(time) {}

    void Cancel() { cancelled_ = true; }

    void Run() {
      if (!cancelled_) {
        std::move(task_)();
      }
    }

    QuicTime time() const { return time_; }

   private:
    bool cancelled_ = false;
    quiche::SingleUseCallback<void()> task_;
    QuicTime time_;
  };

 public:
  // Schedules a function to run immediately and advances the time.
  void Schedule(std::function<void()> task) {
    tasks_.push(std::shared_ptr<InnerTask>(
        new InnerTask(std::move(task), helper_->GetClock()->Now())));
    helper_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  }

 private:
  using TaskType = std::shared_ptr<InnerTask>;
  std::priority_queue<
      TaskType, std::vector<TaskType>,
      quiche::UnretainedCallback<bool(const TaskType&, const TaskType&)>>
      tasks_;
  MockQuicConnectionHelper* helper_;
};

class QboneSessionTest : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  QboneSessionTest()
      : supported_versions_({GetParam()}),
        runner_(&helper_),
        compressed_certs_cache_(100) {}

  ~QboneSessionTest() override {
    delete client_connection_;
    delete server_connection_;
  }

  const MockClock* GetClock() const {
    return static_cast<const MockClock*>(helper_.GetClock());
  }

  // The parameters are used to control whether the handshake will success or
  // not.
  void CreateClientAndServerSessions(bool client_handshake_success = true,
                                     bool server_handshake_success = true,
                                     bool send_qbone_alpn = true) {
    // Quic crashes if packets are sent at time 0, and the clock defaults to 0.
    helper_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    event_loop_ = GetDefaultEventLoop()->Create(QuicDefaultClock::Get());
    alarm_factory_ = event_loop_->CreateAlarmFactory();
    client_writer_ = std::make_unique<DataSavingQbonePacketWriter>();
    server_writer_ = std::make_unique<DataSavingQbonePacketWriter>();
    client_handler_ =
        std::make_unique<DataSavingQboneControlHandler<QboneClientRequest>>();
    server_handler_ =
        std::make_unique<DataSavingQboneControlHandler<QboneServerRequest>>();
    QuicSocketAddress server_address(TestLoopback(), 0);
    QuicSocketAddress client_address;
    if (server_address.host().address_family() == IpAddressFamily::IP_V4) {
      client_address = QuicSocketAddress(QuicIpAddress::Any4(), 0);
    } else {
      client_address = QuicSocketAddress(QuicIpAddress::Any6(), 0);
    }

    {
      client_connection_ = new QuicConnection(
          TestConnectionId(), client_address, server_address, &helper_,
          alarm_factory_.get(), new NiceMock<MockPacketWriter>(), true,
          Perspective::IS_CLIENT, supported_versions_,
          connection_id_generator_);
      client_connection_->SetSelfAddress(client_address);
      QuicConfig config;
      client_crypto_config_ = std::make_unique<QuicCryptoClientConfig>(
          std::make_unique<IndirectionProofVerifier>(client_handshake_success));
      if (send_qbone_alpn) {
        client_crypto_config_->set_alpn("qbone");
      }
      client_peer_ = std::make_unique<QboneClientSession>(
          client_connection_, client_crypto_config_.get(),
          /*owner=*/nullptr, config, supported_versions_,
          QuicServerId("test.example.com", 1234), client_writer_.get(),
          client_handler_.get());
    }

    {
      server_connection_ = new QuicConnection(
          TestConnectionId(), server_address, client_address, &helper_,
          alarm_factory_.get(), new NiceMock<MockPacketWriter>(), true,
          Perspective::IS_SERVER, supported_versions_,
          connection_id_generator_);
      server_connection_->SetSelfAddress(server_address);
      QuicConfig config;
      server_crypto_config_ = std::make_unique<QuicCryptoServerConfig>(
          QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
          std::make_unique<IndirectionProofSource>(server_handshake_success),
          KeyExchangeSource::Default());
      QuicCryptoServerConfig::ConfigOptions options;
      QuicServerConfigProtobuf primary_config =
          server_crypto_config_->GenerateConfig(QuicRandom::GetInstance(),
                                                GetClock(), options);
      std::unique_ptr<CryptoHandshakeMessage> message(
          server_crypto_config_->AddConfig(primary_config,
                                           GetClock()->WallNow()));

      server_peer_ = std::make_unique<QboneServerSession>(
          supported_versions_, server_connection_, nullptr, config,
          server_crypto_config_.get(), &compressed_certs_cache_,
          server_writer_.get(), TestLoopback6(), TestLoopback6(), 64,
          server_handler_.get());
    }

    // Hook everything up!
    MockPacketWriter* client_writer = static_cast<MockPacketWriter*>(
        QuicConnectionPeer::GetWriter(client_peer_->connection()));
    ON_CALL(*client_writer, WritePacket(_, _, _, _, _, _))
        .WillByDefault(Invoke([this](const char* buffer, size_t buf_len,
                                     const QuicIpAddress& self_address,
                                     const QuicSocketAddress& peer_address,
                                     PerPacketOptions* option,
                                     const QuicPacketWriterParams& params) {
          char* copy = new char[1024 * 1024];
          memcpy(copy, buffer, buf_len);
          runner_.Schedule([this, copy, buf_len] {
            QuicReceivedPacket packet(copy, buf_len, GetClock()->Now());
            server_peer_->ProcessUdpPacket(server_connection_->self_address(),
                                           client_connection_->self_address(),
                                           packet);
            delete[] copy;
          });
          return WriteResult(WRITE_STATUS_OK, buf_len);
        }));
    MockPacketWriter* server_writer = static_cast<MockPacketWriter*>(
        QuicConnectionPeer::GetWriter(server_peer_->connection()));
    ON_CALL(*server_writer, WritePacket(_, _, _, _, _, _))
        .WillByDefault(Invoke([this](const char* buffer, size_t buf_len,
                                     const QuicIpAddress& self_address,
                                     const QuicSocketAddress& peer_address,
                                     PerPacketOptions* options,
                                     const QuicPacketWriterParams& params) {
          char* copy = new char[1024 * 1024];
          memcpy(copy, buffer, buf_len);
          runner_.Schedule([this, copy, buf_len] {
            QuicReceivedPacket packet(copy, buf_len, GetClock()->Now());
            client_peer_->ProcessUdpPacket(client_connection_->self_address(),
                                           server_connection_->self_address(),
                                           packet);
            delete[] copy;
          });
          return WriteResult(WRITE_STATUS_OK, buf_len);
        }));
  }

  void StartHandshake() {
    server_peer_->Initialize();
    client_peer_->Initialize();
    runner_.Run();
  }

  void ExpectICMPTooBigResponse(const std::vector<std::string>& written_packets,
                                const int mtu, const std::string& packet) {
    auto* header = reinterpret_cast<const ip6_hdr*>(packet.data());
    icmp6_hdr icmp_header{};
    icmp_header.icmp6_type = ICMP6_PACKET_TOO_BIG;
    icmp_header.icmp6_mtu = mtu;

    std::string expected;
    CreateIcmpPacket(header->ip6_dst, header->ip6_src, icmp_header, packet,
                     [&expected](absl::string_view icmp_packet) {
                       expected = std::string(icmp_packet);
                     });

    EXPECT_THAT(written_packets, Contains(expected));
  }

  // Test handshake establishment and sending/receiving of data for two
  // directions.
  void TestStreamConnection(bool use_messages) {
    ASSERT_TRUE(server_peer_->OneRttKeysAvailable());
    ASSERT_TRUE(client_peer_->OneRttKeysAvailable());
    ASSERT_TRUE(server_peer_->IsEncryptionEstablished());
    ASSERT_TRUE(client_peer_->IsEncryptionEstablished());

    // Create an outgoing stream from the client and say hello.
    QUIC_LOG(INFO) << "Sending client -> server";
    client_peer_->ProcessPacketFromNetwork(TestPacketIn("hello"));
    client_peer_->ProcessPacketFromNetwork(TestPacketIn("world"));
    runner_.Run();
    // The server should see the data, the client hasn't received
    // anything yet.
    EXPECT_THAT(server_writer_->data(),
                ElementsAre(TestPacketOut("hello"), TestPacketOut("world")));
    EXPECT_TRUE(client_writer_->data().empty());
    EXPECT_EQ(0u, server_peer_->GetNumActiveStreams());
    EXPECT_EQ(0u, client_peer_->GetNumActiveStreams());

    // Let's pretend some service responds.
    QUIC_LOG(INFO) << "Sending server -> client";
    server_peer_->ProcessPacketFromNetwork(TestPacketIn("Hello Again"));
    server_peer_->ProcessPacketFromNetwork(TestPacketIn("Again"));
    runner_.Run();
    EXPECT_THAT(server_writer_->data(),
                ElementsAre(TestPacketOut("hello"), TestPacketOut("world")));
    EXPECT_THAT(
        client_writer_->data(),
        ElementsAre(TestPacketOut("Hello Again"), TestPacketOut("Again")));
    EXPECT_EQ(0u, server_peer_->GetNumActiveStreams());
    EXPECT_EQ(0u, client_peer_->GetNumActiveStreams());

    // Try to send long payloads that are larger than the QUIC MTU but
    // smaller than the QBONE max size.
    // This should trigger the non-ephemeral stream code path.
    std::string long_data(
        QboneConstants::kMaxQbonePacketBytes - sizeof(ip6_hdr) - 1, 'A');
    QUIC_LOG(INFO) << "Sending server -> client long data";
    server_peer_->ProcessPacketFromNetwork(TestPacketIn(long_data));
    runner_.Run();
    if (use_messages) {
      ExpectICMPTooBigResponse(
          server_writer_->data(),
          server_peer_->connection()->GetGuaranteedLargestMessagePayload(),
          TestPacketOut(long_data));
    } else {
      EXPECT_THAT(client_writer_->data(), Contains(TestPacketOut(long_data)));
    }
    EXPECT_THAT(server_writer_->data(),
                Not(Contains(TestPacketOut(long_data))));
    EXPECT_EQ(0u, server_peer_->GetNumActiveStreams());
    EXPECT_EQ(0u, client_peer_->GetNumActiveStreams());

    QUIC_LOG(INFO) << "Sending client -> server long data";
    client_peer_->ProcessPacketFromNetwork(TestPacketIn(long_data));
    runner_.Run();
    if (use_messages) {
      ExpectICMPTooBigResponse(
          client_writer_->data(),
          client_peer_->connection()->GetGuaranteedLargestMessagePayload(),
          TestPacketIn(long_data));
    } else {
      EXPECT_THAT(server_writer_->data(), Contains(TestPacketOut(long_data)));
    }
    EXPECT_FALSE(client_peer_->EarlyDataAccepted());
    EXPECT_FALSE(client_peer_->ReceivedInchoateReject());
    EXPECT_THAT(client_peer_->GetNumReceivedServerConfigUpdates(), Eq(0));

    if (!use_messages) {
      EXPECT_THAT(client_peer_->GetNumStreamedPackets(), Eq(1));
      EXPECT_THAT(server_peer_->GetNumStreamedPackets(), Eq(1));
    }

    if (use_messages) {
      EXPECT_THAT(client_peer_->GetNumEphemeralPackets(), Eq(0));
      EXPECT_THAT(server_peer_->GetNumEphemeralPackets(), Eq(0));
      EXPECT_THAT(client_peer_->GetNumMessagePackets(), Eq(2));
      EXPECT_THAT(server_peer_->GetNumMessagePackets(), Eq(2));
    } else {
      EXPECT_THAT(client_peer_->GetNumEphemeralPackets(), Eq(2));
      EXPECT_THAT(server_peer_->GetNumEphemeralPackets(), Eq(2));
      EXPECT_THAT(client_peer_->GetNumMessagePackets(), Eq(0));
      EXPECT_THAT(server_peer_->GetNumMessagePackets(), Eq(0));
    }

    // All streams are ephemeral and should be gone.
    EXPECT_EQ(0u, server_peer_->GetNumActiveStreams());
    EXPECT_EQ(0u, client_peer_->GetNumActiveStreams());
  }

  // Test that client and server are not connected after handshake failure.
  void TestDisconnectAfterFailedHandshake() {
    EXPECT_FALSE(client_peer_->IsEncryptionEstablished());
    EXPECT_FALSE(client_peer_->OneRttKeysAvailable());

    EXPECT_FALSE(server_peer_->IsEncryptionEstablished());
    EXPECT_FALSE(server_peer_->OneRttKeysAvailable());
  }

 protected:
  const ParsedQuicVersionVector supported_versions_;
  std::unique_ptr<QuicEventLoop> event_loop_;
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;
  FakeTaskRunner runner_;
  MockQuicConnectionHelper helper_;
  QuicConnection* client_connection_;
  QuicConnection* server_connection_;
  QuicCompressedCertsCache compressed_certs_cache_;

  std::unique_ptr<QuicCryptoClientConfig> client_crypto_config_;
  std::unique_ptr<QuicCryptoServerConfig> server_crypto_config_;
  std::unique_ptr<DataSavingQbonePacketWriter> client_writer_;
  std::unique_ptr<DataSavingQbonePacketWriter> server_writer_;
  std::unique_ptr<DataSavingQboneControlHandler<QboneClientRequest>>
      client_handler_;
  std::unique_ptr<DataSavingQboneControlHandler<QboneServerRequest>>
      server_handler_;

  std::unique_ptr<QboneServerSession> server_peer_;
  std::unique_ptr<QboneClientSession> client_peer_;
  MockConnectionIdGenerator connection_id_generator_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QboneSessionTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QboneSessionTest, StreamConnection) {
  CreateClientAndServerSessions();
  client_peer_->set_send_packets_as_messages(false);
  server_peer_->set_send_packets_as_messages(false);
  StartHandshake();
  TestStreamConnection(false);
}

TEST_P(QboneSessionTest, Messages) {
  CreateClientAndServerSessions();
  client_peer_->set_send_packets_as_messages(true);
  server_peer_->set_send_packets_as_messages(true);
  StartHandshake();
  TestStreamConnection(true);
}

TEST_P(QboneSessionTest, ClientRejection) {
  CreateClientAndServerSessions(false /*client_handshake_success*/,
                                true /*server_handshake_success*/,
                                true /*send_qbone_alpn*/);
  StartHandshake();
  TestDisconnectAfterFailedHandshake();
}

TEST_P(QboneSessionTest, BadAlpn) {
  CreateClientAndServerSessions(true /*client_handshake_success*/,
                                true /*server_handshake_success*/,
                                false /*send_qbone_alpn*/);
  StartHandshake();
  TestDisconnectAfterFailedHandshake();
}

TEST_P(QboneSessionTest, ServerRejection) {
  CreateClientAndServerSessions(true /*client_handshake_success*/,
                                false /*server_handshake_success*/,
                                true /*send_qbone_alpn*/);
  StartHandshake();
  TestDisconnectAfterFailedHandshake();
}

// Test that data streams are not created before handshake.
TEST_P(QboneSessionTest, CannotCreateDataStreamBeforeHandshake) {
  CreateClientAndServerSessions();
  EXPECT_QUIC_BUG(client_peer_->ProcessPacketFromNetwork(TestPacketIn("hello")),
                  "Attempting to send packet before encryption established");
  EXPECT_QUIC_BUG(server_peer_->ProcessPacketFromNetwork(TestPacketIn("hello")),
                  "Attempting to send packet before encryption established");
  EXPECT_EQ(0u, server_peer_->GetNumActiveStreams());
  EXPECT_EQ(0u, client_peer_->GetNumActiveStreams());
}

TEST_P(QboneSessionTest, ControlRequests) {
  CreateClientAndServerSessions();
  StartHandshake();
  EXPECT_TRUE(client_handler_->data().empty());
  EXPECT_FALSE(client_handler_->error());
  EXPECT_TRUE(server_handler_->data().empty());
  EXPECT_FALSE(server_handler_->error());

  QboneClientRequest client_request;
  client_request.SetExtension(client_placeholder, "hello from the server");
  EXPECT_TRUE(server_peer_->SendClientRequest(client_request));
  runner_.Run();
  ASSERT_FALSE(client_handler_->data().empty());
  EXPECT_THAT(client_handler_->data()[0].GetExtension(client_placeholder),
              Eq("hello from the server"));
  EXPECT_FALSE(client_handler_->error());

  QboneServerRequest server_request;
  server_request.SetExtension(server_placeholder, "hello from the client");
  EXPECT_TRUE(client_peer_->SendServerRequest(server_request));
  runner_.Run();
  ASSERT_FALSE(server_handler_->data().empty());
  EXPECT_THAT(server_handler_->data()[0].GetExtension(server_placeholder),
              Eq("hello from the client"));
  EXPECT_FALSE(server_handler_->error());
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```
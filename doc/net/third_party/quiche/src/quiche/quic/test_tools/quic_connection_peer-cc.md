Response:
Let's break down the thought process for analyzing this C++ file and answering the user's request.

**1. Understanding the Core Request:**

The user wants to know the functionality of `net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.cc`. They're also interested in:

* Relationship to JavaScript.
* Logical inferences (input/output).
* Common user/programming errors.
* Debugging context (how a user might reach this code).

**2. Initial Code Examination (Skimming):**

The filename `quic_connection_peer.cc` and the `test_tools` directory immediately suggest this is a helper class for *testing* the `QuicConnection` class. The `#include` directives confirm this, as they include core QUIC components like `QuicConnection`, `QuicAlarm`, `QuicPacketWriter`, etc.

**3. Identifying the Primary Purpose (Deeper Dive):**

Scanning the functions reveals a pattern: most functions are static and take a `QuicConnection*` as an argument. They then access or modify private members of the `QuicConnection` object. This confirms the "peer" aspect: it's a friend class (or simulates friend access) to allow testing of internal state. Keywords like "Set," "Get," and direct member access (e.g., `connection->packet_creator_`) are strong indicators.

**4. Categorizing Functionality:**

To organize the functions, I'll group them by the aspects of `QuicConnection` they interact with:

* **Alarms:** Functions related to triggering or getting alarm objects (`Fire`, `GetAckAlarm`, `GetPingAlarm`, etc.).
* **Packet Management:** Functions dealing with packet creation, sending, and receiving (`GetPacketCreator`, `GetSentPacketManager`, `SetCurrentPacket`).
* **Connection State:** Functions that modify or retrieve connection properties like perspective, addresses, timeouts, and connection status (`SetPerspective`, `SetSelfAddress`, `GetNetworkTimeout`, `TearDownLocalConnectionState`).
* **Cryptography:** Functions related to encrypters (`SwapCrypters`, `GetNumEncryptionLevels`).
* **Congestion Control:** Functions interacting with the send algorithm (`SetSendAlgorithm`, `SetLossAlgorithm`).
* **MTU Discovery:** Functions related to Maximum Transmission Unit discovery (`GetPacketsBetweenMtuProbes`, `ReInitializeMtuDiscoverer`).
* **Connection ID Management:** Functions for accessing and manipulating connection ID managers (`GetRetirePeerIssuedConnectionIdAlarm`, `HasUnusedPeerIssuedConnectionId`).
* **Error Handling/Closing:** Functions related to connection closure (`SendConnectionClosePacket`, `GetConnectionClosePacket`).
* **Blackholing/Idle Detection:** Functions related to network anomaly detection (`GetBlackholeDetector`, `GetIdleNetworkDetector`).
* **Path Validation/Migration:** Functions related to path validation and alternative paths.
* **Internal State Manipulation:**  General functions that directly set internal variables for testing purposes (`SetMaxTrackedPackets`, `SetNegotiatedVersion`).
* **Debugging/Inspection:** Functions to inspect internal state (`GetLastHeader`, `GetStats`).

**5. Addressing the JavaScript Relationship:**

QUIC is a transport protocol typically implemented in lower layers of the network stack. JavaScript, being a high-level language primarily for web browsers and Node.js, doesn't directly interact with QUIC's internal C++ implementation. However, JavaScript (in browsers or Node.js) *uses* QUIC when making network requests (e.g., using `fetch` or `XMLHttpRequest` over HTTP/3). The browser's networking stack handles the QUIC details, and the JavaScript code is abstracted away from this. Therefore, the relationship is indirect: JavaScript triggers network activity that *might* use QUIC, and this C++ code is part of *that* QUIC implementation.

**6. Logical Inferences (Input/Output):**

Since this is a *testing* tool, the logical inferences are primarily about *setting up* specific scenarios for testing `QuicConnection`. The "input" is calling the `QuicConnectionPeer` functions with specific values, and the "output" is the altered internal state of the `QuicConnection` object.

* **Example:**  Calling `QuicConnectionPeer::SetSendAlgorithm(connection, new_algorithm)` with a custom congestion control algorithm as `new_algorithm`. The expected output is that `connection->sent_packet_manager_->send_algorithm_` now points to `new_algorithm`.

**7. Common User/Programming Errors:**

The "user" in this context is a *developer writing tests*. Common errors would involve:

* **Incorrectly setting up test conditions:**  For example, setting a handshake timeout too short, leading to unexpected connection closures during tests.
* **Misunderstanding internal state:**  Assuming a certain internal variable has a specific value without explicitly setting it using `QuicConnectionPeer`.
* **Not cleaning up resources:** Although not directly shown in this file, issues like not deleting dynamically allocated objects used in tests could arise.
* **Relying on default behavior:**  Assuming default values for internal variables instead of explicitly setting them for test isolation.

**8. Debugging Context:**

A developer would likely end up examining this code while:

* **Writing new unit tests for `QuicConnection`:**  They'd need to use `QuicConnectionPeer` to manipulate the connection's state to create specific test cases.
* **Debugging failing unit tests:**  If a test involving a `QuicConnection` is failing, developers might step through the `QuicConnectionPeer` functions to see how the connection's internal state is being manipulated.
* **Understanding QUIC internals:**  Developers might explore this file to understand how different parts of `QuicConnection` work by seeing how the test code interacts with its internals.

**9. Structuring the Answer:**

Finally, I'd organize the information into clear sections as requested by the user, using headings and bullet points for readability. I'd emphasize the "testing tool" aspect and explain the indirect relationship with JavaScript. The input/output examples should be concrete, and the common errors should be phrased from a test developer's perspective. The debugging scenario provides context for *why* someone would look at this code.
这个文件 `net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.cc` 是 Chromium QUIC 库中一个专门用于**测试** `QuicConnection` 类的辅助工具类。 它允许测试代码访问和修改 `QuicConnection` 对象的私有成员和方法，从而方便进行各种边界情况和内部状态的测试。

**功能列表:**

该文件的主要功能是提供静态方法，以便在测试中能够：

1. **操作和检查连接的告警 (Alarms):**
   - `Fire(QuicAlarmProxy alarm)`:  触发指定的告警。
   - `GetAckAlarm()`, `GetPingAlarm()`, `GetRetransmissionAlarm()`, 等等: 获取各种类型的告警对象，以便进行断言或进一步操作。

2. **设置和获取连接的各种属性:**
   - `SetSendAlgorithm()`: 设置连接使用的拥塞控制算法。
   - `SetLossAlgorithm()`: 设置连接使用的丢包检测算法。
   - `GetPacketCreator()`: 获取用于创建 QUIC 包的对象。
   - `GetSentPacketManager()`: 获取用于管理已发送数据包的对象。
   - `GetNetworkTimeout()`, `GetHandshakeTimeout()`: 获取网络空闲超时和握手超时时间。
   - `SetPerspective()`: 设置连接的视角 (客户端或服务端)。
   - `SetSelfAddress()`, `SetPeerAddress()`, `SetEffectivePeerAddress()`: 设置本地和对端地址。
   - `SetCurrentPacket()`: 设置当前正在处理的数据包内容，用于模拟接收数据包。

3. **管理加密器 (Crypters):**
   - `SwapCrypters()`: 交换连接的加密器。

4. **访问连接的辅助对象:**
   - `GetHelper()`: 获取连接的辅助接口。
   - `GetAlarmFactory()`: 获取告警工厂。
   - `GetFramer()`: 获取 QUIC 帧解析器。
   - `GetWriter()`: 获取用于写出数据包的对象。
   - `SetWriter()`: 设置用于写出数据包的对象。

5. **模拟连接状态的改变:**
   - `TearDownLocalConnectionState()`: 模拟本地连接断开。
   - `SetConnectionClose()`:  直接设置连接为关闭状态。

6. **检查连接发送的终止包:**
   - `GetConnectionClosePacket()`: 获取连接发送的 CONNECTION_CLOSE 包。

7. **获取和设置连接的统计信息:**
   - `GetLastHeader()`: 获取最后接收到的数据包头。
   - `GetStats()`: 获取连接的统计信息。
   - `GetPacketsBetweenMtuProbes()`: 获取 MTU 探测包之间的间隔。
   - `ReInitializeMtuDiscoverer()`: 重新初始化 MTU 发现器。
   - `SetAckDecimationDelay()`: 设置 ACK 延迟因子。

8. **检查数据包是否包含可重传帧:**
   - `HasRetransmittableFrames()`: 检查指定包号的数据包是否包含可重传帧。

9. **设置连接的限制:**
   - `SetMaxTrackedPackets()`: 设置跟踪的最大数据包数量。
   - `SetMaxConsecutiveNumPacketsWithNoRetransmittableFrames()`: 设置没有可重传帧的最大连续包数。

10. **检查连接特性:**
    - `SupportsReleaseTime()`: 检查是否支持 Release Time 功能。
    - `GetCurrentPacketContent()`: 获取当前正在处理的数据包内容类型。

11. **模拟接收字节:**
    - `AddBytesReceived()`: 模拟接收到一定数量的字节。
    - `SetAddressValidated()`: 设置地址已验证。

12. **发送连接关闭包:**
    - `SendConnectionClosePacket()`: 模拟发送连接关闭包。

13. **获取加密级别数量:**
    - `GetNumEncryptionLevels()`: 获取连接当前拥有的加密级别数量。

14. **访问和操作黑洞检测器 (Blackhole Detector) 和空闲网络检测器 (Idle Network Detector):**
    - `GetBlackholeDetector()`, `GetBlackholeDetectorAlarm()`, `GetPathDegradingDeadline()`, `GetBlackholeDetectionDeadline()`, `GetPathMtuReductionDetectionDeadline()`
    - `GetIdleNetworkDeadline()`, `GetIdleNetworkDetectorAlarm()`, `GetIdleNetworkDetector()`

15. **操作多端口探测告警:**
    - `GetMultiPortProbingAlarm()`

16. **设置连接ID:**
    - `SetServerConnectionId()`: 设置服务端连接 ID。

17. **获取无法解密的包的数量:**
    - `NumUndecryptablePackets()`

18. **发送 Ping 包:**
    - `SendPing()`

19. **设置最后接收数据包的目的地址:**
    - `SetLastPacketDestinationAddress()`

20. **访问路径验证器 (Path Validator):**
    - `path_validator()`

21. **获取路径上的收发字节数:**
    - `BytesReceivedOnDefaultPath()`, `BytesSentOnAlternativePath()`, `BytesReceivedOnAlternativePath()`

22. **获取备用路径的连接ID:**
    - `GetClientConnectionIdOnAlternativePath()`, `GetServerConnectionIdOnAlternativePath()`

23. **检查路径是否已验证:**
    - `IsAlternativePathValidated()`

24. **判断给定地址是否属于特定路径:**
    - `IsAlternativePath()`, `IsDefaultPath()`

25. **重置 PeerIssuedConnectionIdManager:**
    - `ResetPeerIssuedConnectionIdManager()`

26. **获取和操作连接的路径状态 (PathState):**
    - `GetDefaultPath()`, `GetAlternativePath()`
    - `RetirePeerIssuedConnectionIdsNoLongerOnPath()`

27. **检查是否存在未使用的或待消费的连接ID:**
    - `HasUnusedPeerIssuedConnectionId()`, `HasSelfIssuedConnectionIdToConsume()`

28. **获取 SelfIssuedConnectionIdManager:**
    - `GetSelfIssuedConnectionIdManager()`, `MakeSelfIssuedConnectionIdManager()`

29. **设置最后解密时的加密级别:**
    - `SetLastDecryptedLevel()`

30. **访问和操作 CoalescedPacket:**
    - `GetCoalescedPacket()`, `FlushCoalescedPacket()`

31. **设置是否处于 Probe Timeout 状态:**
    - `SetInProbeTimeOut()`

32. **获取接收到的服务端首选地址:**
    - `GetReceivedServerPreferredAddress()`

33. **测试 `ReceivedPacketInfo` 的默认值:**
    - `TestLastReceivedPacketInfoDefaults()`

34. **禁用 ECN 代码点验证:**
    - `DisableEcnCodepointValidation()`

35. **通知连接取得了前向进展:**
    - `OnForwardProgressMade()`

**与 JavaScript 的关系:**

该 C++ 代码与 JavaScript 的关系是**间接的**。

* **QUIC 协议是底层网络传输协议:**  QUIC 协议在网络堆栈的较低层实现，负责数据在客户端和服务器之间的可靠传输。
* **JavaScript 使用 QUIC:**  在浏览器或 Node.js 环境中，当发起网络请求时 (例如使用 `fetch` API 或 `XMLHttpRequest`)，底层可能会使用 QUIC 协议 (例如，当使用 HTTP/3 时)。
* **此 C++ 代码是 QUIC 库的一部分:**  `quic_connection_peer.cc` 是 Chromium 中 QUIC 协议的具体实现代码的一部分。
* **测试辅助工具:**  这个 `.cc` 文件是为了测试 QUIC 连接的具体实现而存在的。

**举例说明:**

假设你在一个 JavaScript 应用中发起了一个使用 HTTP/3 的 `fetch` 请求：

```javascript
fetch('https://example.com/data', {
  // ... options
});
```

当这个请求发送到服务器时，浏览器底层的网络栈会使用 QUIC 协议来处理。  为了测试 QUIC 连接在各种情况下的行为，Chromium 的开发者可能会编写 C++ 单元测试，并在这些测试中使用 `QuicConnectionPeer` 来模拟各种场景，例如：

* **模拟网络延迟或丢包:** 通过调整连接的告警或拥塞控制算法。
* **测试握手过程:**  通过设置连接的视角和地址，模拟客户端和服务端之间的握手。
* **测试连接迁移:**  通过修改连接的地址信息。
* **测试 MTU 发现:**  通过检查和修改 MTU 相关的参数。

**逻辑推理的假设输入与输出:**

假设我们想要测试当接收到一个特定大小的数据包时，连接是否正确更新了接收字节数。

**假设输入:**

1. 获取一个 `QuicConnection` 对象的指针 `connection`。
2. 调用 `QuicConnectionPeer::AddBytesReceived(connection, 1024);`

**预期输出:**

1. `connection->default_path_.bytes_received_before_address_validation` 的值增加了 1024 (假设在地址验证之前)。

**假设输入:**

1. 获取一个 `QuicConnection` 对象的指针 `connection`。
2. 调用 `QuicConnectionPeer::SetPerspective(connection, Perspective::IS_SERVER);`

**预期输出:**

1. `connection->perspective_` 的值变为 `Perspective::IS_SERVER`。
2. `connection->framer_.perspective_` 的值变为 `Perspective::IS_SERVER` (通过 `QuicFramerPeer::SetPerspective` 设置)。
3. `connection->ping_manager_.perspective_` 的值变为 `Perspective::IS_SERVER`.

**用户或编程常见的使用错误:**

由于 `QuicConnectionPeer` 是一个测试工具，其“用户”主要是编写 QUIC 单元测试的开发者。 常见的使用错误包括：

1. **在非测试代码中使用 `QuicConnectionPeer`:**  这是一个专门为测试设计的工具，不应该在实际的生产代码中使用，因为它暴露了内部实现细节，破坏了封装性。
2. **不了解内部状态导致错误的测试假设:**  例如，假设某个内部变量的默认值是某个特定值，但实际上并非如此，导致测试结果不符合预期。
3. **过度依赖 `QuicConnectionPeer` 进行复杂的逻辑模拟:**  虽然 `QuicConnectionPeer` 提供了很大的灵活性，但过度使用可能会使测试代码难以理解和维护。有时，通过构造更真实的测试场景可能更有效。
4. **忘记清理使用 `QuicConnectionPeer` 修改的状态:**  在某些测试场景中，可能需要在使用 `QuicConnectionPeer` 修改了连接状态后，将其恢复到初始状态，以避免影响后续测试。

**用户操作如何一步步到达这里 (作为调试线索):**

一个开发者可能因为以下原因查看或调试 `quic_connection_peer.cc`：

1. **编写新的 `QuicConnection` 单元测试:** 当需要测试 `QuicConnection` 的某个特定行为或内部状态时，开发者会查找是否有合适的 "peer" 类来辅助测试。他们会查看 `quic_connection_peer.cc` 中是否提供了所需的功能来设置或检查连接的内部状态。

2. **调试失败的 `QuicConnection` 单元测试:** 如果一个涉及 `QuicConnection` 的单元测试失败了，开发者可能会单步执行测试代码，并查看 `QuicConnectionPeer` 的调用，以了解测试是如何设置连接状态的，以及在哪个环节出现了问题。

3. **理解 `QuicConnection` 的内部实现:**  开发者可能为了更深入地了解 `QuicConnection` 的工作原理，查看 `quic_connection_peer.cc`，了解测试代码是如何访问和操作 `QuicConnection` 的内部成员的。这可以帮助他们理解哪些内部状态是重要的，以及如何影响连接的行为。

4. **修改或扩展 QUIC 库的功能:**  当需要添加新的功能或修改现有功能时，开发者可能需要编写新的单元测试来验证这些修改。这时，他们可能会参考或修改 `quic_connection_peer.cc`，以添加新的辅助方法来测试新的内部状态或行为。

总之，`net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.cc` 是一个关键的测试辅助工具，它通过暴露 `QuicConnection` 的内部细节，使得开发者能够编写更全面和深入的单元测试，从而保证 QUIC 库的质量和稳定性。 它与 JavaScript 的关系是间接的，因为它服务于 QUIC 协议的 C++ 实现，而 JavaScript 可以使用 QUIC 协议进行网络通信。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/quic_connection_peer.h"

#include <memory>
#include <string>


#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/quic_connection_alarms.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_received_packet_manager.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/test_tools/quic_connection_id_manager_peer.h"
#include "quiche/quic/test_tools/quic_framer_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {

// static
void QuicConnectionAlarmsPeer::Fire(QuicAlarmProxy alarm) {
  struct {
    void operator()(QuicConnectionAlarmHolder::AlarmProxy alarm) {
      auto* real_alarm = static_cast<TestAlarmFactory::TestAlarm*>(alarm.alarm_);
      real_alarm->Fire();
    }
    void operator()(QuicAlarmMultiplexer::AlarmProxy alarm) {
      alarm.multiplexer_->Fire(alarm.slot_);
    }
  } visitor;
  absl::visit(visitor, alarm.alarm_);
}

// static
void QuicConnectionPeer::SetSendAlgorithm(
    QuicConnection* connection, SendAlgorithmInterface* send_algorithm) {
  GetSentPacketManager(connection)->SetSendAlgorithm(send_algorithm);
}

// static
void QuicConnectionPeer::SetLossAlgorithm(
    QuicConnection* connection, LossDetectionInterface* loss_algorithm) {
  GetSentPacketManager(connection)->loss_algorithm_ = loss_algorithm;
}

// static
QuicPacketCreator* QuicConnectionPeer::GetPacketCreator(
    QuicConnection* connection) {
  return &connection->packet_creator_;
}

// static
QuicSentPacketManager* QuicConnectionPeer::GetSentPacketManager(
    QuicConnection* connection) {
  return &connection->sent_packet_manager_;
}

// static
QuicTime::Delta QuicConnectionPeer::GetNetworkTimeout(
    QuicConnection* connection) {
  return connection->idle_network_detector_.idle_network_timeout_;
}

// static
QuicTime::Delta QuicConnectionPeer::GetHandshakeTimeout(
    QuicConnection* connection) {
  return connection->idle_network_detector_.handshake_timeout_;
}

// static
void QuicConnectionPeer::SetPerspective(QuicConnection* connection,
                                        Perspective perspective) {
  connection->perspective_ = perspective;
  QuicFramerPeer::SetPerspective(&connection->framer_, perspective);
  connection->ping_manager_.perspective_ = perspective;
}

// static
void QuicConnectionPeer::SetSelfAddress(QuicConnection* connection,
                                        const QuicSocketAddress& self_address) {
  connection->default_path_.self_address = self_address;
}

// static
void QuicConnectionPeer::SetPeerAddress(QuicConnection* connection,
                                        const QuicSocketAddress& peer_address) {
  connection->UpdatePeerAddress(peer_address);
}

// static
void QuicConnectionPeer::SetDirectPeerAddress(
    QuicConnection* connection, const QuicSocketAddress& direct_peer_address) {
  connection->direct_peer_address_ = direct_peer_address;
}

// static
void QuicConnectionPeer::SetEffectivePeerAddress(
    QuicConnection* connection,
    const QuicSocketAddress& effective_peer_address) {
  connection->default_path_.peer_address = effective_peer_address;
}

// static
void QuicConnectionPeer::SwapCrypters(QuicConnection* connection,
                                      QuicFramer* framer) {
  QuicFramerPeer::SwapCrypters(framer, &connection->framer_);
}

// static
void QuicConnectionPeer::SetCurrentPacket(QuicConnection* connection,
                                          absl::string_view current_packet) {
  connection->current_packet_data_ = current_packet.data();
  connection->last_received_packet_info_.length = current_packet.size();
}

// static
QuicConnectionHelperInterface* QuicConnectionPeer::GetHelper(
    QuicConnection* connection) {
  return connection->helper_;
}

// static
QuicAlarmFactory* QuicConnectionPeer::GetAlarmFactory(
    QuicConnection* connection) {
  return connection->alarm_factory_;
}

// static
QuicFramer* QuicConnectionPeer::GetFramer(QuicConnection* connection) {
  return &connection->framer_;
}

// static
QuicAlarmProxy QuicConnectionPeer::GetAckAlarm(QuicConnection* connection) {
  return connection->alarms_.ack_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetPingAlarm(QuicConnection* connection) {
  return connection->alarms_.ping_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetRetransmissionAlarm(
    QuicConnection* connection) {
  return connection->alarms_.retransmission_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetSendAlarm(QuicConnection* connection) {
  return connection->alarms_.send_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetMtuDiscoveryAlarm(
    QuicConnection* connection) {
  return connection->alarms_.mtu_discovery_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetProcessUndecryptablePacketsAlarm(
    QuicConnection* connection) {
  return connection->alarms_.process_undecryptable_packets_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetDiscardPreviousOneRttKeysAlarm(
    QuicConnection* connection) {
  return connection->alarms_.discard_previous_one_rtt_keys_alarm();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetDiscardZeroRttDecryptionKeysAlarm(
    QuicConnection* connection) {
  return connection->alarms_.discard_zero_rtt_decryption_keys_alarm();
}

// static
QuicAlarm* QuicConnectionPeer::GetRetirePeerIssuedConnectionIdAlarm(
    QuicConnection* connection) {
  if (connection->peer_issued_cid_manager_ == nullptr) {
    return nullptr;
  }
  return QuicConnectionIdManagerPeer::GetRetirePeerIssuedConnectionIdAlarm(
      connection->peer_issued_cid_manager_.get());
}
// static
QuicAlarm* QuicConnectionPeer::GetRetireSelfIssuedConnectionIdAlarm(
    QuicConnection* connection) {
  if (connection->self_issued_cid_manager_ == nullptr) {
    return nullptr;
  }
  return QuicConnectionIdManagerPeer::GetRetireSelfIssuedConnectionIdAlarm(
      connection->self_issued_cid_manager_.get());
}

// static
QuicPacketWriter* QuicConnectionPeer::GetWriter(QuicConnection* connection) {
  return connection->writer_;
}

// static
void QuicConnectionPeer::SetWriter(QuicConnection* connection,
                                   QuicPacketWriter* writer, bool owns_writer) {
  if (connection->owns_writer_) {
    delete connection->writer_;
  }
  connection->writer_ = writer;
  connection->owns_writer_ = owns_writer;
}

// static
void QuicConnectionPeer::TearDownLocalConnectionState(
    QuicConnection* connection) {
  connection->connected_ = false;
}

// static
const QuicEncryptedPacket* QuicConnectionPeer::GetConnectionClosePacket(
    const QuicConnection* connection) {
  if (!connection->HasTerminationPackets()) {
    return nullptr;
  }
  return connection->termination_info()->termination_packets[0].get();
}

// static
QuicPacketHeader* QuicConnectionPeer::GetLastHeader(
    QuicConnection* connection) {
  return &connection->last_received_packet_info_.header;
}

// static
QuicConnectionStats* QuicConnectionPeer::GetStats(QuicConnection* connection) {
  return &connection->stats_;
}

// static
QuicPacketCount QuicConnectionPeer::GetPacketsBetweenMtuProbes(
    QuicConnection* connection) {
  return connection->mtu_discoverer_.packets_between_probes();
}

// static
void QuicConnectionPeer::ReInitializeMtuDiscoverer(
    QuicConnection* connection, QuicPacketCount packets_between_probes_base,
    QuicPacketNumber next_probe_at) {
  connection->mtu_discoverer_ =
      QuicConnectionMtuDiscoverer(packets_between_probes_base, next_probe_at);
}

// static
void QuicConnectionPeer::SetAckDecimationDelay(QuicConnection* connection,
                                               float ack_decimation_delay) {
  for (auto& received_packet_manager :
       connection->uber_received_packet_manager_.received_packet_managers_) {
    received_packet_manager.ack_decimation_delay_ = ack_decimation_delay;
  }
}

// static
bool QuicConnectionPeer::HasRetransmittableFrames(QuicConnection* connection,
                                                  uint64_t packet_number) {
  return QuicSentPacketManagerPeer::HasRetransmittableFrames(
      GetSentPacketManager(connection), packet_number);
}

// static
void QuicConnectionPeer::SetMaxTrackedPackets(
    QuicConnection* connection, QuicPacketCount max_tracked_packets) {
  connection->max_tracked_packets_ = max_tracked_packets;
}

// static
void QuicConnectionPeer::SetNegotiatedVersion(QuicConnection* connection) {
  connection->version_negotiated_ = true;
}

// static
void QuicConnectionPeer::SetMaxConsecutiveNumPacketsWithNoRetransmittableFrames(
    QuicConnection* connection, size_t new_value) {
  connection->max_consecutive_num_packets_with_no_retransmittable_frames_ =
      new_value;
}

// static
bool QuicConnectionPeer::SupportsReleaseTime(QuicConnection* connection) {
  return connection->supports_release_time_;
}

// static
QuicConnection::PacketContent QuicConnectionPeer::GetCurrentPacketContent(
    QuicConnection* connection) {
  return connection->current_packet_content_;
}

// static
void QuicConnectionPeer::AddBytesReceived(QuicConnection* connection,
                                          size_t length) {
  if (connection->EnforceAntiAmplificationLimit()) {
    connection->default_path_.bytes_received_before_address_validation +=
        length;
  }
}

// static
void QuicConnectionPeer::SetAddressValidated(QuicConnection* connection) {
  connection->default_path_.validated = true;
}

// static
void QuicConnectionPeer::SendConnectionClosePacket(
    QuicConnection* connection, QuicIetfTransportErrorCodes ietf_error,
    QuicErrorCode error, const std::string& details) {
  connection->SendConnectionClosePacket(error, ietf_error, details);
}

// static
size_t QuicConnectionPeer::GetNumEncryptionLevels(QuicConnection* connection) {
  size_t count = 0;
  for (EncryptionLevel level :
       {ENCRYPTION_INITIAL, ENCRYPTION_HANDSHAKE, ENCRYPTION_ZERO_RTT,
        ENCRYPTION_FORWARD_SECURE}) {
    if (connection->framer_.HasEncrypterOfEncryptionLevel(level)) {
      ++count;
    }
  }
  return count;
}

// static
QuicNetworkBlackholeDetector& QuicConnectionPeer::GetBlackholeDetector(
    QuicConnection* connection) {
  return connection->blackhole_detector_;
}

// static
QuicAlarmProxy QuicConnectionPeer::GetBlackholeDetectorAlarm(
    QuicConnection* connection) {
  return connection->alarms_.network_blackhole_detector_alarm();
}

// static
QuicTime QuicConnectionPeer::GetPathDegradingDeadline(
    QuicConnection* connection) {
  return connection->blackhole_detector_.path_degrading_deadline_;
}

// static
QuicTime QuicConnectionPeer::GetBlackholeDetectionDeadline(
    QuicConnection* connection) {
  return connection->blackhole_detector_.blackhole_deadline_;
}

// static
QuicTime QuicConnectionPeer::GetPathMtuReductionDetectionDeadline(
    QuicConnection* connection) {
  return connection->blackhole_detector_.path_mtu_reduction_deadline_;
}

// static
QuicTime QuicConnectionPeer::GetIdleNetworkDeadline(
    QuicConnection* connection) {
  return connection->idle_network_detector_.GetIdleNetworkDeadline();
}

// static
QuicAlarmProxy QuicConnectionPeer::GetIdleNetworkDetectorAlarm(
    QuicConnection* connection) {
  return connection->alarms_.idle_network_detector_alarm();
}

// static
QuicIdleNetworkDetector& QuicConnectionPeer::GetIdleNetworkDetector(
    QuicConnection* connection) {
  return connection->idle_network_detector_;
}

// static
QuicAlarmProxy QuicConnectionPeer::GetMultiPortProbingAlarm(
    QuicConnection* connection) {
  return connection->alarms_.multi_port_probing_alarm();
}

// static
void QuicConnectionPeer::SetServerConnectionId(
    QuicConnection* connection, const QuicConnectionId& server_connection_id) {
  connection->default_path_.server_connection_id = server_connection_id;
  connection->InstallInitialCrypters(server_connection_id);
}

// static
size_t QuicConnectionPeer::NumUndecryptablePackets(QuicConnection* connection) {
  return connection->undecryptable_packets_.size();
}

void QuicConnectionPeer::SetConnectionClose(QuicConnection* connection) {
  connection->connected_ = false;
}

// static
void QuicConnectionPeer::SendPing(QuicConnection* connection) {
  connection->SendPingAtLevel(connection->encryption_level());
}

// static
void QuicConnectionPeer::SetLastPacketDestinationAddress(
    QuicConnection* connection, const QuicSocketAddress& address) {
  connection->last_received_packet_info_.destination_address = address;
}

// static
QuicPathValidator* QuicConnectionPeer::path_validator(
    QuicConnection* connection) {
  return &connection->path_validator_;
}

// static
QuicByteCount QuicConnectionPeer::BytesReceivedOnDefaultPath(
    QuicConnection* connection) {
  return connection->default_path_.bytes_received_before_address_validation;
}

//  static
QuicByteCount QuicConnectionPeer::BytesSentOnAlternativePath(
    QuicConnection* connection) {
  return connection->alternative_path_.bytes_sent_before_address_validation;
}

//  static
QuicByteCount QuicConnectionPeer::BytesReceivedOnAlternativePath(
    QuicConnection* connection) {
  return connection->alternative_path_.bytes_received_before_address_validation;
}

// static
QuicConnectionId QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(
    const QuicConnection* connection) {
  return connection->alternative_path_.client_connection_id;
}

// static
QuicConnectionId QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
    const QuicConnection* connection) {
  return connection->alternative_path_.server_connection_id;
}

// static
bool QuicConnectionPeer::IsAlternativePathValidated(
    QuicConnection* connection) {
  return connection->alternative_path_.validated;
}

// static
bool QuicConnectionPeer::IsAlternativePath(
    QuicConnection* connection, const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address) {
  return connection->IsAlternativePath(self_address, peer_address);
}

// static
QuicByteCount QuicConnectionPeer::BytesReceivedBeforeAddressValidation(
    QuicConnection* connection) {
  return connection->default_path_.bytes_received_before_address_validation;
}

// static
void QuicConnectionPeer::ResetPeerIssuedConnectionIdManager(
    QuicConnection* connection) {
  connection->peer_issued_cid_manager_ = nullptr;
}

// static
QuicConnection::PathState* QuicConnectionPeer::GetDefaultPath(
    QuicConnection* connection) {
  return &connection->default_path_;
}

// static
bool QuicConnectionPeer::IsDefaultPath(QuicConnection* connection,
                                       const QuicSocketAddress& self_address,
                                       const QuicSocketAddress& peer_address) {
  return connection->IsDefaultPath(self_address, peer_address);
}

// static
QuicConnection::PathState* QuicConnectionPeer::GetAlternativePath(
    QuicConnection* connection) {
  return &connection->alternative_path_;
}

// static
void QuicConnectionPeer::RetirePeerIssuedConnectionIdsNoLongerOnPath(
    QuicConnection* connection) {
  connection->RetirePeerIssuedConnectionIdsNoLongerOnPath();
}

// static
bool QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(
    const QuicConnection* connection) {
  return connection->peer_issued_cid_manager_->HasUnusedConnectionId();
}

// static
bool QuicConnectionPeer::HasSelfIssuedConnectionIdToConsume(
    const QuicConnection* connection) {
  return connection->self_issued_cid_manager_->HasConnectionIdToConsume();
}

// static
QuicSelfIssuedConnectionIdManager*
QuicConnectionPeer::GetSelfIssuedConnectionIdManager(
    QuicConnection* connection) {
  return connection->self_issued_cid_manager_.get();
}

// static
std::unique_ptr<QuicSelfIssuedConnectionIdManager>
QuicConnectionPeer::MakeSelfIssuedConnectionIdManager(
    QuicConnection* connection) {
  return connection->MakeSelfIssuedConnectionIdManager();
}

// static
void QuicConnectionPeer::SetLastDecryptedLevel(QuicConnection* connection,
                                               EncryptionLevel level) {
  connection->last_received_packet_info_.decrypted_level = level;
}

// static
QuicCoalescedPacket& QuicConnectionPeer::GetCoalescedPacket(
    QuicConnection* connection) {
  return connection->coalesced_packet_;
}

// static
void QuicConnectionPeer::FlushCoalescedPacket(QuicConnection* connection) {
  connection->FlushCoalescedPacket();
}

// static
void QuicConnectionPeer::SetInProbeTimeOut(QuicConnection* connection,
                                           bool value) {
  connection->in_probe_time_out_ = value;
}

// static
QuicSocketAddress QuicConnectionPeer::GetReceivedServerPreferredAddress(
    QuicConnection* connection) {
  return connection->received_server_preferred_address_;
}

// static
bool QuicConnectionPeer::TestLastReceivedPacketInfoDefaults() {
  QuicConnection::ReceivedPacketInfo info{QuicTime::Zero()};
  QUIC_DVLOG(2)
      << "QuicConnectionPeer::TestLastReceivedPacketInfoDefaults"
      << " dest_addr passed: "
      << (info.destination_address == QuicSocketAddress())
      << " source_addr passed: " << (info.source_address == QuicSocketAddress())
      << " receipt_time passed: " << (info.receipt_time == QuicTime::Zero())
      << " received_bytes_counted passed: " << !info.received_bytes_counted
      << " destination_connection_id passed: "
      << (info.destination_connection_id == QuicConnectionId())
      << " length passed: " << (info.length == 0)
      << " decrypted passed: " << !info.decrypted << " decrypted_level passed: "
      << (info.decrypted_level == ENCRYPTION_INITIAL)
      << " frames.empty passed: " << info.frames.empty()
      << " ecn_codepoint passed: " << (info.ecn_codepoint == ECN_NOT_ECT)
      << " sizeof(ReceivedPacketInfo) passed: "
      << (sizeof(size_t) != 8 ||
          sizeof(QuicConnection::ReceivedPacketInfo) == 280);
  return info.destination_address == QuicSocketAddress() &&
         info.source_address == QuicSocketAddress() &&
         info.receipt_time == QuicTime::Zero() &&
         !info.received_bytes_counted && info.length == 0 &&
         info.destination_connection_id == QuicConnectionId() &&
         !info.decrypted && info.decrypted_level == ENCRYPTION_INITIAL &&
         // There's no simple way to compare all the values of QuicPacketHeader.
         info.frames.empty() && info.ecn_codepoint == ECN_NOT_ECT &&
         info.actual_destination_address == QuicSocketAddress() &&
         // If the condition below fails, the contents of ReceivedPacketInfo
         // have changed. Please add the relevant conditions and update the
         // length below.
         (sizeof(size_t) != 8 ||
          sizeof(QuicConnection::ReceivedPacketInfo) == 280);
}

// static
void QuicConnectionPeer::DisableEcnCodepointValidation(
    QuicConnection* connection) {
  // disable_ecn_codepoint_validation_ doesn't work correctly if the flag
  // isn't set; all tests that don't set the flag should hit this bug.
  QUIC_BUG_IF(quic_bug_518619343_03, !GetQuicRestartFlag(quic_support_ect1))
      << "Test disables ECN validation without setting quic_support_ect1";
  connection->disable_ecn_codepoint_validation_ = true;
}

// static
void QuicConnectionPeer::OnForwardProgressMade(QuicConnection* connection) {
  connection->OnForwardProgressMade();
}

}  // namespace test
}  // namespace quic
```
Response:
The user wants me to analyze a C++ source code file related to Chromium's network stack, specifically `quic_buffered_packet_store_test.cc`.

Here's a breakdown of the requested information:

1. **Functionality:** I need to determine the purpose of this test file. Based on the name, it likely tests the `QuicBufferedPacketStore` class.

2. **Relationship to JavaScript:** I need to assess if this C++ code has any direct or indirect connections to JavaScript. Since it's a low-level networking component, a direct relationship is unlikely, but I should consider indirect connections through web browser APIs.

3. **Logical Reasoning (Input/Output):** For specific test cases, I need to identify the assumed input and the expected output. This usually involves looking at the test functions and their assertions.

4. **Common Usage Errors:** I need to identify potential mistakes developers might make when using the class being tested. This often involves considering edge cases and error conditions.

5. **User Operations Leading to This Code:**  I need to explain how a user's interaction with a web browser might eventually involve this specific code. This requires understanding the context of QUIC and how it's used in web browsing.

6. **Debugging Clues:** I need to provide hints on how this file could be used during debugging, focusing on the types of issues it can help identify.

7. **Summary of Functionality (Part 1):**  I need to condense the identified functionalities based on the code snippet provided.

**Mental Sandbox:**

* I see a lot of Google Test framework usage (`TEST_F`, `EXPECT_EQ`, `ASSERT_EQ`). This confirms it's a unit test file.
* The `#include` directives give clues about the classes being tested (`quic_buffered_packet_store.h`) and its dependencies (`quic_connection_id.h`, `quic_packets.h`, etc.).
* The tests seem to cover scenarios like enqueuing and delivering packets, handling connection ID collisions, managing packet buffers, and dealing with packet expiration.
* The mention of "CHLO" (Client Hello) suggests that buffering might be related to the TLS handshake process in QUIC.
*  JavaScript's interaction is likely indirect through browser APIs that use QUIC for network communication.

**Plan:**

1. **Identify the primary functionality:** Focus on testing the `QuicBufferedPacketStore`.
2. **Examine the test cases:** Analyze each `TEST_F` to understand the specific scenario being tested and deduce the assumed inputs and expected outputs.
3. **Consider JavaScript interaction:** Explain the indirect link through web browser usage of QUIC.
4. **Identify potential usage errors:** Think about scenarios where developers might misuse the `QuicBufferedPacketStore`.
5. **Describe the user journey:** Explain the high-level steps that lead to QUIC being used.
6. **Provide debugging insights:** Focus on what aspects of packet buffering and connection management this file helps test.
7. **Summarize the functionality of the provided part of the code.**

**Confidence Score:** 5/5 - I'm confident I can address all the user's requests based on the code snippet and my knowledge of networking and testing.

Strategizing complete. I will now proceed with generating the response.

这是位于 `net/third_party/quiche/src/quiche/quic/core/quic_buffered_packet_store_test.cc` 的 Chromium 网络栈源代码文件，主要功能是**测试 `QuicBufferedPacketStore` 类的各项功能**。`QuicBufferedPacketStore` 的作用是**缓冲在 QUIC 连接建立早期收到的数据包**，直到连接完全建立或者这些数据包因为超时等原因被丢弃。

以下是根据提供的代码片段对该文件功能的详细列举和分析：

**主要功能:**

1. **数据包的入队和出队 (Enqueue and Deliver Packets):**
   - 测试向 `QuicBufferedPacketStore` 中添加（Enqueue）数据包，并随后根据连接 ID 取回（Deliver）这些数据包。
   - 验证入队的数据包的内容、接收时间、发送方和接收方地址是否被正确保存。
   - 涵盖了在没有收到 Client Hello (CHLO) 前就收到的数据包的缓冲和交付场景。

2. **连接 ID 的管理:**
   - 测试针对特定连接 ID 缓冲数据包的能力。
   - 验证交付数据包后，存储中是否不再包含该连接 ID 的缓冲数据包。

3. **处理来自不同地址的数据包:**
   - 测试在同一连接上收到来自不同源地址的数据包时，存储是否能够正确处理和保存这些数据包。这模拟了网络地址迁移的情况。

4. **处理多个连接的数据包:**
   - 测试同时缓冲和交付多个不同连接的数据包的能力。

5. **限制每个连接缓冲的数据包数量:**
   - 测试 `QuicBufferedPacketStore` 对每个连接可以缓冲的最大数据包数量的限制，并验证超过限制的数据包是否会被拒绝。

6. **限制未收到 CHLO 的连接数量:**
   - 测试 `QuicBufferedPacketStore` 对未收到 CHLO 的连接数量的限制，并验证超过限制的新连接的数据包是否会被拒绝。

7. **整体存储容量限制:**
   - 测试当存储达到最大容量时，新连接的数据包是否会被拒绝，即使这些数据包包含 CHLO。

8. **使用连接 ID 生成器 (Connection ID Generator):**
   - 测试当收到包含 CHLO 的数据包时，`QuicBufferedPacketStore` 是否能够使用提供的连接 ID 生成器。

9. **处理过多的不同连接的 CHLO:**
   - 测试当缓冲了超出限制的未收到 CHLO 的连接的数据包后，再收到新的 CHLO 时，存储的行为。

10. **数据包队列的过期 (Expiration):**
    - 测试长时间未被交付的数据包队列是否会因为超时而被移除。
    - 验证当数据包队列过期时，会调用 `VisitorInterface` 的 `OnExpiredPackets` 方法通知上层。

11. **丢弃数据包 (Discard Packets):**
    - 测试显式丢弃特定连接 ID 的所有缓冲数据包的功能。
    - 涵盖了丢弃包含 CHLO 的数据包的情况。

12. **TLS Client Hello 的提取 (TLS CHLO Extraction):**
    - 测试 `IngestPacketForTlsChloExtraction` 方法，该方法尝试从缓冲的数据包中提取 TLS Client Hello 信息。
    - 验证对于非 TLS CHLO 数据包，该方法返回失败。
    - 测试跨越多个数据包的 TLS CHLO 的提取。

**与 JavaScript 的关系:**

该 C++ 代码本身与 JavaScript 没有直接的功能关系。然而，它所测试的 `QuicBufferedPacketStore` 组件是 Chromium 网络栈的一部分，而网络栈负责处理浏览器与服务器之间的 QUIC 协议通信。

当用户在浏览器中进行网络操作（例如访问一个使用 QUIC 协议的网站）时，底层的网络栈会接收到来自服务器的数据包。如果这些数据包在连接完全建立之前到达，`QuicBufferedPacketStore` 就会将它们缓冲起来。

**举例说明:**

假设用户在浏览器中访问一个启用了 QUIC 的网站。在 TLS 握手完成之前，服务器可能会向客户端发送一些数据包。这些数据包会被浏览器的 QUIC 实现接收，并可能被 `QuicBufferedPacketStore` 缓冲。一旦握手完成，这些缓冲的数据包会被交付给上层处理，最终可能导致网页内容的渲染，而这会影响到 JavaScript 的执行。

**逻辑推理 (假设输入与输出):**

**示例 1: 简单的入队和出队**

* **假设输入:**
    * 一个新的连接 ID：`connection_id = TestConnectionId(1)`
    * 一个数据包 `packet_`
    * 调用 `EnqueuePacketToStore` 将数据包添加到 `connection_id` 对应的缓冲区。
    * 调用 `DeliverPackets(connection_id)` 获取缓冲的数据包。
* **预期输出:**
    * `store_.HasBufferedPackets(connection_id)` 返回 `true`。
    * `store_.DeliverPackets(connection_id).buffered_packets` 返回一个包含该数据包的列表。
    * 数据包的内容、地址和时间戳与输入一致。
    * 再次调用 `DeliverPackets(connection_id)` 返回一个空列表。
    * `store_.HasBufferedPackets(connection_id)` 返回 `false`。

**示例 2: 达到每个连接的数据包缓冲上限**

* **假设输入:**
    * 一个连接 ID：`connection_id = TestConnectionId(1)`
    * 连续添加超过 `kDefaultMaxUndecryptablePackets` 数量的数据包到该连接。
* **预期输出:**
    * 前 `kDefaultMaxUndecryptablePackets` 个数据包成功入队。
    * 尝试添加更多数据包时，`EnqueuePacketToStore` 返回 `EnqueuePacketResult::TOO_MANY_PACKETS`。
    * `store_.DeliverPackets(connection_id).buffered_packets` 的大小为 `kDefaultMaxUndecryptablePackets`。

**用户或编程常见的使用错误:**

1. **忘记设置或错误配置 `VisitorInterface`:** `QuicBufferedPacketStore` 通过 `VisitorInterface` 通知上层过期的数据包和连接 ID 冲突等事件。如果未正确设置或实现 `VisitorInterface`，这些事件可能得不到处理，导致资源泄露或其他问题。

2. **在高负载情况下未考虑缓冲限制:** 如果服务器或网络环境导致大量连接建立请求，`QuicBufferedPacketStore` 的连接和数据包缓冲限制可能会被触发。开发者需要考虑这种情况，并可能需要调整配置或采取其他措施来处理过多的连接请求。

3. **在连接建立后仍然依赖缓冲机制:** `QuicBufferedPacketStore` 主要用于缓冲连接建立早期的包。一旦连接建立完成，新的数据包应该通过正常的连接处理流程。错误地假设连接建立后的数据包也会被缓冲可能导致逻辑错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户访问一个使用 QUIC 的网站，并且网络条件不佳，导致初始握手阶段的某些数据包延迟或乱序到达。以下是可能涉及 `QuicBufferedPacketStore` 的步骤：

1. **用户在浏览器地址栏输入网址或点击链接:** 浏览器开始尝试与服务器建立连接。
2. **浏览器发起 QUIC 连接握手:** 包括发送 Client Initial 数据包。
3. **服务器发送 Server Initial 和其他握手数据包:** 这些数据包可能因为网络延迟或其他原因未能按顺序到达客户端。
4. **客户端接收到乱序或延迟到达的服务器数据包:** 由于连接尚未完全建立，这些数据包无法立即按照正常的连接处理流程进行处理。
5. **QUIC 代码将这些早期到达的数据包交给 `QuicBufferedPacketStore` 进行缓冲:**  `EnqueuePacketToStore` 方法会被调用。
6. **调试时，开发者可能会在 `quic_buffered_packet_store_test.cc` 中编写或运行测试用例，模拟这些场景:** 例如，测试在没有 CHLO 的情况下收到数据包的行为。
7. **如果怀疑是数据包缓冲的问题，开发者可能会查看 `QuicBufferedPacketStore` 的状态，例如缓冲了哪些连接的数据包，每个连接缓冲了多少数据包等。**
8. **通过测试用例，开发者可以验证 `QuicBufferedPacketStore` 是否按照预期工作，例如是否正确处理了乱序到达的数据包，是否遵守了缓冲限制，以及是否在连接建立后正确交付了缓冲的数据包。**

**这是第1部分，共2部分，请归纳一下它的功能:**

根据提供的第一部分代码，`quic_buffered_packet_store_test.cc` 的主要功能是**测试 `QuicBufferedPacketStore` 类在缓冲和管理早期到达的 QUIC 数据包方面的核心功能**，包括：

* **基本的数据包入队和出队操作。**
* **处理来自同一连接但不同地址的数据包。**
* **管理多个连接的缓冲数据包。**
* **强制执行每个连接和总体的缓冲限制。**
* **处理包含和不包含 Client Hello (CHLO) 的数据包。**
* **使用连接 ID 生成器。**
* **数据包队列的过期机制。**
* **显式丢弃缓冲的数据包。**
* **初步测试 TLS Client Hello 的提取功能。**

总而言之，这部分代码主要关注 `QuicBufferedPacketStore` 在接收、存储和管理早期数据包，直到连接建立或数据包过期等关键流程的正确性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_buffered_packet_store_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_buffered_packet_store.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/connection_id_generator.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_frame.h"
#include "quiche/quic/core/frames/quic_padding_frame.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_dispatcher.h"
#include "quiche/quic/core/quic_dispatcher_stats.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/first_flight.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/mock_connection_id_generator.h"
#include "quiche/quic/test_tools/quic_buffered_packet_store_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_endian.h"

namespace quic {
static const size_t kDefaultMaxConnectionsInStore = 100;
static const size_t kMaxConnectionsWithoutCHLO =
    kDefaultMaxConnectionsInStore / 2;

namespace test {
namespace {

const std::optional<ParsedClientHello> kNoParsedChlo;
const std::optional<ParsedClientHello> kDefaultParsedChlo =
    absl::make_optional<ParsedClientHello>();

using BufferedPacket = QuicBufferedPacketStore::BufferedPacket;
using BufferedPacketList = QuicBufferedPacketStore::BufferedPacketList;
using EnqueuePacketResult = QuicBufferedPacketStore::EnqueuePacketResult;
using ::testing::_;
using ::testing::A;
using ::testing::Conditional;
using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::Ne;
using ::testing::Return;
using ::testing::SizeIs;
using ::testing::Truly;

EnqueuePacketResult EnqueuePacketToStore(
    QuicBufferedPacketStore& store, QuicConnectionId connection_id,
    PacketHeaderFormat form, QuicLongHeaderType long_packet_type,
    const QuicReceivedPacket& packet, QuicSocketAddress self_address,
    QuicSocketAddress peer_address, const ParsedQuicVersion& version,
    std::optional<ParsedClientHello> parsed_chlo,
    ConnectionIdGeneratorInterface& connection_id_generator) {
  ReceivedPacketInfo packet_info(self_address, peer_address, packet);
  packet_info.destination_connection_id = connection_id;
  packet_info.form = form;
  packet_info.long_packet_type = long_packet_type;
  packet_info.version = version;
  return store.EnqueuePacket(packet_info, std::move(parsed_chlo),
                             connection_id_generator);
}

class QuicBufferedPacketStoreVisitor
    : public QuicBufferedPacketStore::VisitorInterface {
 public:
  QuicBufferedPacketStoreVisitor() {}

  ~QuicBufferedPacketStoreVisitor() override {}

  void OnExpiredPackets(BufferedPacketList early_arrived_packets) override {
    last_expired_packet_queue_ = std::move(early_arrived_packets);
  }

  HandleCidCollisionResult HandleConnectionIdCollision(
      const QuicConnectionId& /*original_connection_id*/,
      const QuicConnectionId& /*replaced_connection_id*/,
      const QuicSocketAddress& /*self_address*/,
      const QuicSocketAddress& /*peer_address*/, ParsedQuicVersion /*version*/,
      const ParsedClientHello* /*parsed_chlo*/) override {
    return HandleCidCollisionResult::kOk;
  }

  // The packets queue for most recently expirect connection.
  BufferedPacketList last_expired_packet_queue_;
};

class QuicBufferedPacketStoreTest : public QuicTest {
 public:
  QuicBufferedPacketStoreTest()
      : store_(&visitor_, &clock_, &alarm_factory_, stats_),
        self_address_(QuicIpAddress::Any6(), 65535),
        peer_address_(QuicIpAddress::Any6(), 65535),
        packet_content_("some encrypted content"),
        packet_time_(QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(42)),
        packet_(packet_content_.data(), packet_content_.size(), packet_time_),
        invalid_version_(UnsupportedQuicVersion()),
        valid_version_(CurrentSupportedVersions().front()) {}

 protected:
  QuicDispatcherStats stats_;
  QuicBufferedPacketStoreVisitor visitor_;
  MockClock clock_;
  MockAlarmFactory alarm_factory_;
  QuicBufferedPacketStore store_;
  QuicSocketAddress self_address_;
  QuicSocketAddress peer_address_;
  std::string packet_content_;
  QuicTime packet_time_;
  QuicReceivedPacket packet_;
  const ParsedQuicVersion invalid_version_;
  const ParsedQuicVersion valid_version_;
  MockConnectionIdGenerator connection_id_generator_;
};

TEST_F(QuicBufferedPacketStoreTest, SimpleEnqueueAndDeliverPacket) {
  QuicConnectionId connection_id = TestConnectionId(1);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  auto packets = store_.DeliverPackets(connection_id);
  const std::list<BufferedPacket>& queue = packets.buffered_packets;
  ASSERT_EQ(1u, queue.size());
  ASSERT_FALSE(packets.parsed_chlo.has_value());
  // There is no valid version because CHLO has not arrived.
  EXPECT_EQ(invalid_version_, packets.version);
  // Check content of the only packet in the queue.
  EXPECT_EQ(packet_content_, queue.front().packet->AsStringPiece());
  EXPECT_EQ(packet_time_, queue.front().packet->receipt_time());
  EXPECT_EQ(peer_address_, queue.front().peer_address);
  EXPECT_EQ(self_address_, queue.front().self_address);
  // No more packets on connection 1 should remain in the store.
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
}

TEST_F(QuicBufferedPacketStoreTest, SimpleEnqueueAckSent) {
  SetQuicReloadableFlag(quic_ecn_in_first_ack, true);
  QuicConnectionId connection_id = TestConnectionId(1);
  MockPacketWriter writer;
  store_.set_writer(&writer);
  // Build a decryptable Initial packet with PADDING.
  QuicFramer client_framer(ParsedQuicVersionVector{ParsedQuicVersion::RFCv1()},
                           QuicTime::Zero(), Perspective::IS_CLIENT, 8);
  client_framer.SetInitialObfuscators(connection_id);
  QuicPacketHeader header;
  header.destination_connection_id = connection_id;
  header.version_flag = true;
  header.packet_number = QuicPacketNumber(1);
  header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.long_packet_type = INITIAL;
  header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
  QuicFrames frames = {QuicFrame(QuicPaddingFrame(1200))};

  char* buffer = new char[1500];
  EncryptionLevel level = HeaderToEncryptionLevel(header);
  size_t length =
      client_framer.BuildDataPacket(header, frames, buffer, 1500, level);

  ASSERT_GT(length, 0);

  // Re-construct the data packet with data ownership.
  auto data = std::make_unique<QuicPacket>(
      buffer, length, /* owns_buffer */ true,
      GetIncludedDestinationConnectionIdLength(header),
      GetIncludedSourceConnectionIdLength(header), header.version_flag,
      header.nonce != nullptr, header.packet_number_length,
      header.retry_token_length_length, header.retry_token.length(),
      header.length_length);
  unsigned char raw[1500] = {};
  size_t final_size = client_framer.EncryptPayload(
      ENCRYPTION_INITIAL, header.packet_number, *data, (char*)raw, 1500);
  QuicReceivedPacket packet((char*)raw, final_size, QuicTime::Zero(), false, 0,
                            true, nullptr, 0, false, ECN_ECT1);

  EXPECT_CALL(writer, IsWriteBlocked()).WillOnce(Return(false));
  std::unique_ptr<QuicEncryptedPacket> ack_packet;
  EXPECT_CALL(writer, WritePacket(_, _, _, _, _, _))
      .WillOnce(Invoke([&](const char* buffer, size_t buf_len,
                           const QuicIpAddress& /*self_address*/,
                           const QuicSocketAddress& /*peer_address*/,
                           PerPacketOptions* /*options*/,
                           const QuicPacketWriterParams& /*params*/) {
        auto tmp_packet =
            std::make_unique<QuicEncryptedPacket>(buffer, buf_len);
        ack_packet = tmp_packet->Clone();
        return WriteResult(WRITE_STATUS_OK, 1);
      }));
  EXPECT_CALL(writer, Flush());
  EnqueuePacketToStore(store_, connection_id, IETF_QUIC_LONG_HEADER_PACKET,
                       INITIAL, packet, self_address_, peer_address_,
                       ParsedQuicVersion::RFCv1(), kNoParsedChlo,
                       connection_id_generator_);
  const BufferedPacketList* buffered_list = store_.GetPacketList(connection_id);
  ASSERT_NE(buffered_list, nullptr);
  ASSERT_EQ(buffered_list->dispatcher_sent_packets.size(), 1);
  EXPECT_EQ(buffered_list->dispatcher_sent_packets[0].largest_acked,
            QuicPacketNumber(1));

  // Decrypt the packet, and verify it reports ECN.
  MockFramerVisitor mock_framer_visitor;
  client_framer.set_visitor(&mock_framer_visitor);
  EXPECT_CALL(mock_framer_visitor, OnPacket()).Times(1);
  EXPECT_CALL(mock_framer_visitor, OnAckFrameStart(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_framer_visitor, OnAckRange(_, _)).WillOnce(Return(true));
  std::optional<QuicEcnCounts> counts = QuicEcnCounts(0, 1, 0);
  EXPECT_CALL(mock_framer_visitor, OnAckFrameEnd(_, counts))
      .WillOnce(Return(true));
  client_framer.ProcessPacket(*ack_packet);
}

TEST_F(QuicBufferedPacketStoreTest, DifferentPacketAddressOnOneConnection) {
  QuicSocketAddress addr_with_new_port(QuicIpAddress::Any4(), 256);
  QuicConnectionId connection_id = TestConnectionId(1);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       addr_with_new_port, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  std::list<BufferedPacket> queue =
      store_.DeliverPackets(connection_id).buffered_packets;
  ASSERT_EQ(2u, queue.size());
  // The address migration path should be preserved.
  EXPECT_EQ(peer_address_, queue.front().peer_address);
  EXPECT_EQ(addr_with_new_port, queue.back().peer_address);
}

TEST_F(QuicBufferedPacketStoreTest,
       EnqueueAndDeliverMultiplePacketsOnMultipleConnections) {
  size_t num_connections = 10;
  for (uint64_t conn_id = 1; conn_id <= num_connections; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                         INVALID_PACKET_TYPE, packet_, self_address_,
                         peer_address_, invalid_version_, kNoParsedChlo,
                         connection_id_generator_);
    EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                         INVALID_PACKET_TYPE, packet_, self_address_,
                         peer_address_, invalid_version_, kNoParsedChlo,
                         connection_id_generator_);
  }

  // Deliver packets in reversed order.
  for (uint64_t conn_id = num_connections; conn_id > 0; --conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    std::list<BufferedPacket> queue =
        store_.DeliverPackets(connection_id).buffered_packets;
    ASSERT_EQ(2u, queue.size());
  }
}

// Tests that for one connection, only limited number of packets can be
// buffered.
TEST_F(QuicBufferedPacketStoreTest,
       FailToBufferTooManyPacketsOnExistingConnection) {
  // Max number of packets that can be buffered per connection.
  const size_t kMaxPacketsPerConnection = kDefaultMaxUndecryptablePackets;
  QuicConnectionId connection_id = TestConnectionId(1);
  EXPECT_EQ(QuicBufferedPacketStore::SUCCESS,
            EnqueuePacketToStore(store_, connection_id,
                                 IETF_QUIC_LONG_HEADER_PACKET, INITIAL, packet_,
                                 self_address_, peer_address_, valid_version_,
                                 kDefaultParsedChlo, connection_id_generator_));
  for (size_t i = 1; i <= kMaxPacketsPerConnection; ++i) {
    // All packets will be buffered except the last one.
    EnqueuePacketResult result = EnqueuePacketToStore(
        store_, connection_id, GOOGLE_QUIC_PACKET, INVALID_PACKET_TYPE, packet_,
        self_address_, peer_address_, invalid_version_, kNoParsedChlo,
        connection_id_generator_);
    if (i != kMaxPacketsPerConnection) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_PACKETS, result);
    }
  }

  // Verify |kMaxPacketsPerConnection| packets are buffered.
  EXPECT_EQ(store_.DeliverPackets(connection_id).buffered_packets.size(),
            kMaxPacketsPerConnection);
}

TEST_F(QuicBufferedPacketStoreTest, ReachNonChloConnectionUpperLimit) {
  // Tests that store can only keep early arrived packets for limited number of
  // connections.
  const size_t kNumConnections = kMaxConnectionsWithoutCHLO + 1;
  for (uint64_t conn_id = 1; conn_id <= kNumConnections; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EnqueuePacketResult result = EnqueuePacketToStore(
        store_, connection_id, GOOGLE_QUIC_PACKET, INVALID_PACKET_TYPE, packet_,
        self_address_, peer_address_, invalid_version_, kNoParsedChlo,
        connection_id_generator_);
    if (conn_id <= kMaxConnectionsWithoutCHLO) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, result);
    }
  }
  // Store only keeps early arrived packets upto |kNumConnections| connections.
  for (uint64_t conn_id = 1; conn_id <= kNumConnections; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    std::list<BufferedPacket> queue =
        store_.DeliverPackets(connection_id).buffered_packets;
    if (conn_id <= kMaxConnectionsWithoutCHLO) {
      EXPECT_EQ(1u, queue.size());
    } else {
      EXPECT_EQ(0u, queue.size());
    }
  }
}

TEST_F(QuicBufferedPacketStoreTest,
       FullStoreFailToBufferDataPacketOnNewConnection) {
  // Send enough CHLOs so that store gets full before number of connections
  // without CHLO reaches its upper limit.
  size_t num_chlos =
      kDefaultMaxConnectionsInStore - kMaxConnectionsWithoutCHLO + 1;
  for (uint64_t conn_id = 1; conn_id <= num_chlos; ++conn_id) {
    EXPECT_EQ(
        EnqueuePacketResult::SUCCESS,
        EnqueuePacketToStore(store_, TestConnectionId(conn_id),
                             GOOGLE_QUIC_PACKET, INVALID_PACKET_TYPE, packet_,
                             self_address_, peer_address_, valid_version_,
                             kDefaultParsedChlo, connection_id_generator_));
  }

  // Send data packets on another |kMaxConnectionsWithoutCHLO| connections.
  // Store should only be able to buffer till it's full.
  for (uint64_t conn_id = num_chlos + 1;
       conn_id <= (kDefaultMaxConnectionsInStore + 1); ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EnqueuePacketResult result = EnqueuePacketToStore(
        store_, connection_id, GOOGLE_QUIC_PACKET, INVALID_PACKET_TYPE, packet_,
        self_address_, peer_address_, valid_version_, kDefaultParsedChlo,
        connection_id_generator_);
    if (conn_id <= kDefaultMaxConnectionsInStore) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, result);
    }
  }
}

TEST_F(QuicBufferedPacketStoreTest, BasicGeneratorBuffering) {
  EXPECT_EQ(EnqueuePacketResult::SUCCESS,
            EnqueuePacketToStore(
                store_, TestConnectionId(1), GOOGLE_QUIC_PACKET,
                INVALID_PACKET_TYPE, packet_, self_address_, peer_address_,
                valid_version_, kDefaultParsedChlo, connection_id_generator_));
  QuicConnectionId delivered_conn_id;
  BufferedPacketList packet_list =
      store_.DeliverPacketsForNextConnection(&delivered_conn_id);
  EXPECT_EQ(1u, packet_list.buffered_packets.size());
  EXPECT_EQ(delivered_conn_id, TestConnectionId(1));
  EXPECT_EQ(packet_list.connection_id_generator, nullptr);
}

TEST_F(QuicBufferedPacketStoreTest, GeneratorIgnoredForNonChlo) {
  MockConnectionIdGenerator generator2;
  EXPECT_EQ(EnqueuePacketResult::SUCCESS,
            EnqueuePacketToStore(
                store_, TestConnectionId(1), GOOGLE_QUIC_PACKET,
                INVALID_PACKET_TYPE, packet_, self_address_, peer_address_,
                valid_version_, kDefaultParsedChlo, connection_id_generator_));
  EXPECT_EQ(EnqueuePacketResult::SUCCESS,
            EnqueuePacketToStore(store_, TestConnectionId(1),
                                 GOOGLE_QUIC_PACKET, INVALID_PACKET_TYPE,
                                 packet_, self_address_, peer_address_,
                                 valid_version_, kNoParsedChlo, generator2));
  QuicConnectionId delivered_conn_id;
  BufferedPacketList packet_list =
      store_.DeliverPacketsForNextConnection(&delivered_conn_id);
  EXPECT_EQ(2u, packet_list.buffered_packets.size());
  EXPECT_EQ(delivered_conn_id, TestConnectionId(1));
  EXPECT_EQ(packet_list.connection_id_generator, nullptr);
}

TEST_F(QuicBufferedPacketStoreTest, EnqueueChloOnTooManyDifferentConnections) {
  // Buffer data packets on different connections upto limit.
  for (uint64_t conn_id = 1; conn_id <= kMaxConnectionsWithoutCHLO; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EXPECT_EQ(EnqueuePacketResult::SUCCESS,
              // connection_id_generator_ will be ignored because the chlo has
              // not been parsed.
              EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                                   INVALID_PACKET_TYPE, packet_, self_address_,
                                   peer_address_, invalid_version_,
                                   kNoParsedChlo, connection_id_generator_));
  }

  // Buffer CHLOs on other connections till store is full.
  for (size_t i = kMaxConnectionsWithoutCHLO + 1;
       i <= kDefaultMaxConnectionsInStore + 1; ++i) {
    QuicConnectionId connection_id = TestConnectionId(i);
    EnqueuePacketResult rs = EnqueuePacketToStore(
        store_, connection_id, GOOGLE_QUIC_PACKET, INVALID_PACKET_TYPE, packet_,
        self_address_, peer_address_, valid_version_, kDefaultParsedChlo,
        connection_id_generator_);
    if (i <= kDefaultMaxConnectionsInStore) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, rs);
      EXPECT_TRUE(store_.HasChloForConnection(connection_id));
    } else {
      // Last CHLO can't be buffered because store is full.
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, rs);
      EXPECT_FALSE(store_.HasChloForConnection(connection_id));
    }
  }

  // But buffering a CHLO belonging to a connection already has data packet
  // buffered in the store should success. This is the connection should be
  // delivered at last.
  EXPECT_EQ(EnqueuePacketResult::SUCCESS,
            EnqueuePacketToStore(
                store_, TestConnectionId(1), GOOGLE_QUIC_PACKET,
                INVALID_PACKET_TYPE, packet_, self_address_, peer_address_,
                valid_version_, kDefaultParsedChlo, connection_id_generator_));
  EXPECT_TRUE(store_.HasChloForConnection(TestConnectionId(1)));

  QuicConnectionId delivered_conn_id;
  for (size_t i = 0;
       i < kDefaultMaxConnectionsInStore - kMaxConnectionsWithoutCHLO + 1;
       ++i) {
    BufferedPacketList packet_list =
        store_.DeliverPacketsForNextConnection(&delivered_conn_id);
    if (i < kDefaultMaxConnectionsInStore - kMaxConnectionsWithoutCHLO) {
      // Only CHLO is buffered.
      EXPECT_EQ(1u, packet_list.buffered_packets.size());
      EXPECT_EQ(TestConnectionId(i + kMaxConnectionsWithoutCHLO + 1),
                delivered_conn_id);
    } else {
      EXPECT_EQ(2u, packet_list.buffered_packets.size());
      EXPECT_EQ(TestConnectionId(1u), delivered_conn_id);
    }
    EXPECT_EQ(packet_list.connection_id_generator, nullptr);
  }
  EXPECT_FALSE(store_.HasChlosBuffered());
}

// Tests that store expires long-staying connections appropriately for
// connections both with and without CHLOs.
TEST_F(QuicBufferedPacketStoreTest, PacketQueueExpiredBeforeDelivery) {
  QuicConnectionId connection_id = TestConnectionId(1);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EXPECT_EQ(EnqueuePacketResult::SUCCESS,
            EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                                 INVALID_PACKET_TYPE, packet_, self_address_,
                                 peer_address_, valid_version_,
                                 kDefaultParsedChlo, connection_id_generator_));
  QuicConnectionId connection_id2 = TestConnectionId(2);
  EXPECT_EQ(EnqueuePacketResult::SUCCESS,
            EnqueuePacketToStore(store_, connection_id2, GOOGLE_QUIC_PACKET,
                                 INVALID_PACKET_TYPE, packet_, self_address_,
                                 peer_address_, invalid_version_, kNoParsedChlo,
                                 connection_id_generator_));

  // CHLO on connection 3 arrives 1ms later.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  QuicConnectionId connection_id3 = TestConnectionId(3);
  // Use different client address to differentiate packets from different
  // connections.
  QuicSocketAddress another_client_address(QuicIpAddress::Any4(), 255);
  EnqueuePacketToStore(store_, connection_id3, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       another_client_address, valid_version_,
                       kDefaultParsedChlo, connection_id_generator_);

  // Advance clock to the time when connection 1 and 2 expires.
  clock_.AdvanceTime(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline() -
      clock_.ApproximateNow());
  ASSERT_GE(clock_.ApproximateNow(),
            QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline());
  // Fire alarm to remove long-staying connection 1 and 2 packets.
  alarm_factory_.FireAlarm(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_));
  EXPECT_EQ(1u, visitor_.last_expired_packet_queue_.buffered_packets.size());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id2));

  // Try to deliver packets, but packet queue has been removed so no
  // packets can be returned.
  ASSERT_EQ(0u, store_.DeliverPackets(connection_id).buffered_packets.size());
  ASSERT_EQ(0u, store_.DeliverPackets(connection_id2).buffered_packets.size());
  QuicConnectionId delivered_conn_id;
  BufferedPacketList packet_list =
      store_.DeliverPacketsForNextConnection(&delivered_conn_id);

  // Connection 3 is the next to be delivered as connection 1 already expired.
  EXPECT_EQ(connection_id3, delivered_conn_id);
  EXPECT_EQ(packet_list.connection_id_generator, nullptr);
  ASSERT_EQ(1u, packet_list.buffered_packets.size());
  // Packets in connection 3 should use another peer address.
  EXPECT_EQ(another_client_address,
            packet_list.buffered_packets.front().peer_address);

  // Test the alarm is reset by enqueueing 2 packets for 4th connection and wait
  // for them to expire.
  QuicConnectionId connection_id4 = TestConnectionId(4);
  EnqueuePacketToStore(store_, connection_id4, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_id4, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  clock_.AdvanceTime(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline() -
      clock_.ApproximateNow());
  alarm_factory_.FireAlarm(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_));
  // |last_expired_packet_queue_| should be updated.
  EXPECT_EQ(2u, visitor_.last_expired_packet_queue_.buffered_packets.size());
}

TEST_F(QuicBufferedPacketStoreTest, SimpleDiscardPackets) {
  QuicConnectionId connection_id = TestConnectionId(1);

  // Enqueue some packets
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());

  // Dicard the packets
  store_.DiscardPackets(connection_id);

  // No packets on connection 1 should remain in the store
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());

  // Check idempotency
  store_.DiscardPackets(connection_id);
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, DiscardWithCHLOs) {
  QuicConnectionId connection_id = TestConnectionId(1);

  // Enqueue some packets, which include a CHLO
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, valid_version_, kDefaultParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Dicard the packets
  store_.DiscardPackets(connection_id);

  // No packets on connection 1 should remain in the store
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());

  // Check idempotency
  store_.DiscardPackets(connection_id);
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, MultipleDiscardPackets) {
  QuicConnectionId connection_id_1 = TestConnectionId(1);
  QuicConnectionId connection_id_2 = TestConnectionId(2);

  // Enqueue some packets for two connection IDs
  EnqueuePacketToStore(store_, connection_id_1, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_id_1, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo,
                       connection_id_generator_);

  ParsedClientHello parsed_chlo;
  parsed_chlo.alpns.push_back("h3");
  parsed_chlo.sni = TestHostname();
  EnqueuePacketToStore(store_, connection_id_2, IETF_QUIC_LONG_HEADER_PACKET,
                       INITIAL, packet_, self_address_, peer_address_,
                       valid_version_, parsed_chlo, connection_id_generator_);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id_1));
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id_2));
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Discard the packets for connection 1
  store_.DiscardPackets(connection_id_1);

  // No packets on connection 1 should remain in the store
  EXPECT_TRUE(store_.DeliverPackets(connection_id_1).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id_1));
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Packets on connection 2 should remain
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id_2));
  auto packets = store_.DeliverPackets(connection_id_2);
  EXPECT_EQ(1u, packets.buffered_packets.size());
  ASSERT_EQ(1u, packets.parsed_chlo->alpns.size());
  EXPECT_EQ("h3", packets.parsed_chlo->alpns[0]);
  EXPECT_EQ(TestHostname(), packets.parsed_chlo->sni);
  // Since connection_id_2's chlo arrives, verify version is set.
  EXPECT_EQ(valid_version_, packets.version);

  EXPECT_FALSE(store_.HasChlosBuffered());
  // Discard the packets for connection 2
  store_.DiscardPackets(connection_id_2);
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, DiscardPacketsEmpty) {
  // Check that DiscardPackets on an unknown connection ID is safe and does
  // nothing.
  QuicConnectionId connection_id = TestConnectionId(11235);
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
  store_.DiscardPackets(connection_id);
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, IngestPacketForTlsChloExtraction) {
  QuicConnectionId connection_id = TestConnectionId(1);
  std::vector<std::string> alpns;
  std::vector<uint16_t> supported_groups;
  std::vector<uint16_t> cert_compression_algos;
  std::string sni;
  bool resumption_attempted = false;
  bool early_data_attempted = false;
  QuicConfig config;
  std::optional<uint8_t> tls_alert;

  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, packet_, self_address_,
                       peer_address_, valid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));

  // The packet in 'packet_' is not a TLS CHLO packet.
  EXPECT_FALSE(store_.IngestPacketForTlsChloExtraction(
      connection_id, valid_version_, packet_, &supported_groups,
      &cert_compression_algos, &alpns, &sni, &resumption_attempted,
      &early_data_attempted, &tls_alert));

  store_.DiscardPackets(connection_id);

  // Force the TLS CHLO to span multiple packets.
  constexpr auto kCustomParameterId =
      static_cast<TransportParameters::TransportParameterId>(0xff33);
  std::string kCustomParameterValue(2000, '-');
  config.custom_transport_parameters_to_send()[kCustomParameterId] =
      kCustomParameterValue;
  auto packets = GetFirstFlightOfPackets(valid_version_, config);
  ASSERT_EQ(packets.size(), 2u);

  EnqueuePacketToStore(store_, connection_id, GOOGLE_QUIC_PACKET,
                       INVALID_PACKET_TYPE, *packets[0], self_address_,
                       peer_address_, valid_version_, kNoParsedChlo,
                       connection_id_generator_);
  EnqueuePacketToStore(store_, connection_i
"""


```
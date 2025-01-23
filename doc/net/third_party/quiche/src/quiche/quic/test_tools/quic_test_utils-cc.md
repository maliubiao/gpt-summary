Response:
The user wants me to analyze the C++ source code file `net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.cc`.

My analysis should include:
1. **Listing its functionalities.**  This involves identifying the purpose of the various functions, classes, and data structures defined in the code.
2. **Checking for relationships with JavaScript.**  Given the context of a network stack, direct relationships with JavaScript are unlikely, but I need to be aware of potential indirect connections through web APIs or Node.js.
3. **Providing examples of logical reasoning with input and output.**  For some functions, I should illustrate how they operate with specific inputs and the corresponding outputs.
4. **Highlighting common user or programming errors.**  This involves identifying potential pitfalls or misuse of the utilities provided in the file.
5. **Explaining how a user might reach this code during debugging.** This requires outlining user actions that would trigger the execution of this code.
6. **Summarizing the file's overall functionality.**  This should be a concise overview of the purpose of `quic_test_utils.cc`.

Based on the `#include` directives and the code content, it seems this file primarily provides utility functions and mock objects for testing the QUIC protocol implementation within Chromium. It offers tools for creating test packets, simulating network conditions, and setting up mock objects for various QUIC components.

**Functionality Breakdown:**

* **Connection ID utilities:** Functions for creating and manipulating `QuicConnectionId` objects.
* **Stateless Reset Token:** Function to create a test stateless reset token.
* **Server ID:** Function to create a test server ID.
* **ACK frame construction:** Functions for creating and manipulating `QuicAckFrame` objects, including those with specific ACK blocks and gaps.
* **Encryption level determination:**  Function to infer encryption level from packet headers.
* **Packet building:** Functions for constructing `QuicPacket` objects with specified headers and frames.
* **Hashing:**  Function for calculating SHA1 hashes.
* **Frame clearing:** Functions to clear control frames (likely for testing purposes).
* **Random number generation:** A `SimpleRandom` class for generating random numbers, useful for simulating various network events.
* **Mock objects:** Definitions for various mock classes like `MockFramerVisitor`, `MockQuicConnectionVisitor`, `MockQuicConnectionHelper`, `MockQuicConnection`, `MockQuicSession`, `MockQuicCryptoStream`, `MockQuicSpdySession`, `MockPacketWriter`, `MockSendAlgorithm`, `MockLossAlgorithm`, `MockAckListener`, and `MockNetworkChangeVisitor`. These are essential for isolating and testing specific components of the QUIC implementation.
* **Test address and versions:** Functions to get test IP addresses and QUIC versions.
* **Packet construction:** Functions for constructing encrypted QUIC packets with various header configurations.

**JavaScript Relationship:**

While the code is C++, it's part of Chromium's network stack, which interacts with JavaScript in the browser environment. For instance, when a website using the QUIC protocol is accessed, the browser's network stack (including this C++ code during testing) handles the underlying QUIC communication.

**Logical Reasoning Examples:**

* **`TestConnectionIdToUInt64`:**
    * **Input:** A `QuicConnectionId` object (e.g., created by `TestConnectionId(12345)`).
    * **Output:** The `uint64_t` representation of the connection ID (e.g., 12345).
* **`InitAckFrame`:**
    * **Input:** A vector of `QuicAckBlock` (e.g., `{{1, 5}, {7, 10}}`).
    * **Output:** A `QuicAckFrame` object where `ack.packets` contains ranges [1, 5) and [7, 10), and `ack.largest_acked` is 9.

**Common User/Programming Errors:**

* **Incorrectly using mock objects:**  For example, forgetting to set expectations on mock methods or setting up contradictory expectations. This can lead to tests that don't accurately simulate the intended scenarios.
* **Manually constructing packets with incorrect header parameters:**  For instance, setting the wrong connection ID length or packet number length, leading to parsing errors.

**Debugging Scenario:**

1. A web developer reports an issue with a website using QUIC not loading correctly in Chrome.
2. A Chromium engineer investigates the issue.
3. They might run QUIC unit tests or integration tests to isolate the problem.
4. During the execution of a test that involves simulating packet creation or parsing, the code in `quic_test_utils.cc` (specifically functions like `ConstructEncryptedPacket` or mock object setups) might be executed.
5. If the test fails or behaves unexpectedly, the engineer might step through the code in `quic_test_utils.cc` using a debugger to understand how test packets are being created and how mock objects are interacting.

**Summary of Functionality (Part 1):**

This file, `quic_test_utils.cc`, provides a collection of utility functions and mock objects specifically designed for testing the QUIC protocol implementation within the Chromium network stack. It offers tools for creating and manipulating QUIC-related data structures like connection IDs, ACK frames, and packets, as well as simulating various aspects of QUIC communication through mock objects. These utilities are crucial for writing comprehensive and reliable unit and integration tests for the QUIC protocol.

这是文件 `net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.cc` 的第一部分，它主要提供了一系列用于 QUIC 协议测试的工具函数和模拟对象。 总结一下它的功能如下：

**核心功能:**

1. **连接ID辅助功能:**
   - 提供创建不同长度的 `QuicConnectionId` 对象的函数 (`TestConnectionId`, `TestConnectionIdNineBytesLong`).
   - 提供将 `QuicConnectionId` 转换回 `uint64_t` 的函数 (`TestConnectionIdToUInt64`).

2. **无状态重置令牌:**
   - 提供创建用于测试的无状态重置令牌的函数 (`CreateStatelessResetTokenForTest`).

3. **服务器ID:**
   - 提供创建用于测试的 `QuicServerId` 对象的函数 (`TestServerId`).

4. **ACK 帧构造:**
   - 提供多种方法创建 `QuicAckFrame` 对象，包括：
     - 从 `QuicAckBlock` 列表初始化 (`InitAckFrame`).
     - 从最大的已确认包编号初始化 (`InitAckFrame`).
     - 创建具有指定数量 ACK 块的帧 (`MakeAckFrameWithAckBlocks`).
     - 创建包含指定大小和数量间隙的帧 (`MakeAckFrameWithGaps`).

5. **加密级别判断:**
   - 提供根据 `QuicPacketHeader` 判断加密级别的函数 (`HeaderToEncryptionLevel`).

6. **数据包构建:**
   - 提供创建未指定大小的 QUIC 数据包的函数 (`BuildUnsizedDataPacket`).

7. **哈希计算:**
   - 提供计算 SHA1 哈希值的函数 (`Sha1Hash`).

8. **控制帧操作:**
   - 提供清除控制帧的函数 (`ClearControlFrame`, `ClearControlFrameWithTransmissionType`).

9. **随机数生成:**
   - 提供一个简单的随机数生成器类 `SimpleRandom`。

10. **模拟对象:**
    - 定义了一系列用于模拟 QUIC 协议各个组件行为的 Mock 对象，方便进行单元测试：
        - `MockFramerVisitor`: 模拟 QUIC 帧解析器的访问者。
        - `NoOpFramerVisitor`: 一个空的帧解析器访问者，用于不需要具体操作的测试。
        - `MockQuicConnectionVisitor`: 模拟 QUIC 连接的访问者。
        - `MockQuicConnectionHelper`: 模拟 QUIC 连接的助手类，提供时间、随机数等功能。
        - `MockAlarmFactory`: 模拟 QUIC 告警工厂。
        - `MockQuicConnection`: 模拟 QUIC 连接。
        - `PacketSavingConnection`: 继承自 `MockQuicConnection`，用于保存发送的包。
        - `MockQuicSession`: 模拟 QUIC 会话。
        - `MockQuicCryptoStream`: 模拟 QUIC 加密流。
        - `MockQuicSpdySession`: 模拟 QUIC SPDY 会话。
        - `TestQuicSpdyServerSession`: 用于测试的 SPDY 服务端会话。
        - `TestQuicSpdyClientSession`: 用于测试的 SPDY 客户端会话。
        - `MockPacketWriter`: 模拟数据包写入器。
        - `MockSendAlgorithm`: 模拟拥塞控制算法。
        - `MockLossAlgorithm`: 模拟丢包算法。
        - `MockAckListener`: 模拟 ACK 监听器。
        - `MockNetworkChangeVisitor`: 模拟网络变化监听器。

11. **测试地址和版本:**
    - 提供获取测试对端 IP 地址的函数 (`TestPeerIPAddress`).
    - 提供获取最大和最小 QUIC 协议版本的函数 (`QuicVersionMax`, `QuicVersionMin`).
    - 提供禁用使用 TLS 的 QUIC 版本的函数 (`DisableQuicVersionsWithTls`).

12. **加密数据包构造:**
    - 提供多种重载的函数 (`ConstructEncryptedPacket`) 用于构造用于测试的加密 QUIC 数据包，可以灵活地设置连接ID、版本标志、包编号长度等头部信息。

**与 JavaScript 的关系:**

虽然这个文件是 C++ 代码，但它是 Chromium 网络栈的一部分，负责处理底层的 QUIC 协议。 当 JavaScript 代码通过浏览器发起网络请求时，如果使用了 QUIC 协议，最终会调用到这里的 C++ 代码。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 请求一个支持 QUIC 协议的网站：

```javascript
fetch('https://example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

1. **用户操作:** 用户在 Chrome 浏览器中打开一个网页，该网页执行上述 JavaScript 代码，发起了一个到 `https://example.com` 的请求。
2. **浏览器处理:** Chrome 浏览器的网络栈检测到 `example.com` 支持 QUIC 协议。
3. **QUIC 连接建立:** 如果之前没有建立连接，浏览器会尝试与服务器建立 QUIC 连接。
4. **测试代码作用:** 在开发和测试 Chromium 的过程中，工程师可能会使用 `quic_test_utils.cc` 中的函数来模拟客户端或服务器的行为，例如：
   - 使用 `ConstructEncryptedPacket` 创建一个模拟的客户端 Initial 包发送给服务器。
   - 使用 `MockQuicConnection` 和 `MockQuicSession` 来创建一个模拟的 QUIC 连接和会话环境。
   - 使用 `InitAckFrame` 创建一个模拟的 ACK 帧来测试服务器对 ACK 的处理逻辑。

**逻辑推理示例:**

假设我们调用 `TestConnectionId(12345)` 函数：

* **假设输入:** `connection_number = 12345` (类型为 `uint64_t`)
* **内部逻辑:**
    1. 将 `12345` 从主机字节序转换为网络字节序。
    2. 将转换后的 64 位整数通过 `reinterpret_cast` 视为字符数组。
    3. 创建一个 `QuicConnectionId` 对象，其数据指针指向上述字符数组，长度为 8 字节 (sizeof(uint64_t))。
* **预期输出:** 一个 `QuicConnectionId` 对象，其内部数据表示的是网络字节序的 `12345`。

假设我们调用 `InitAckFrame({{1, 5}, {7, 10}})` 函数：

* **假设输入:** `ack_blocks` 为一个包含两个 `QuicAckBlock` 的 `std::vector`:  `{{1, 5}, {7, 10}}`。
* **内部逻辑:**
    1. 遍历 `ack_blocks`。
    2. 对于第一个 block `{1, 5}`，将范围 [1, 5) 添加到 `ack.packets` 中。
    3. 对于第二个 block `{7, 10}`，将范围 [7, 10) 添加到 `ack.packets` 中。
    4. 设置 `ack.largest_acked` 为 `ack.packets` 中的最大值，即 9。
* **预期输出:** 一个 `QuicAckFrame` 对象，其中 `ack.largest_acked` 为 9，并且 `ack.packets` 包含了 1, 2, 3, 4, 7, 8, 9 这些包序号。

**用户或编程常见的使用错误:**

* **在测试中错误地配置 Mock 对象:**  例如，在使用 `MockFramerVisitor` 时，没有正确设置 `EXPECT_CALL` 来模拟预期的帧接收情况，导致测试无法覆盖特定的代码路径。
* **手动构造数据包时，头部参数设置错误:**  例如，在使用 `ConstructEncryptedPacket` 时，错误地设置了连接ID的包含标志，导致数据包无法被正确解析。
* **在使用随机数生成器 `SimpleRandom` 时，没有正确地设置种子:** 这会导致每次运行测试时都使用相同的随机数序列，降低测试的覆盖率和发现潜在问题的能力。

**用户操作到达这里的调试线索:**

1. **网络问题排查:** 用户报告 Chrome 浏览器访问特定网站时速度慢或无法访问。开发人员怀疑是 QUIC 协议层的问题，需要进行调试。
2. **QUIC 功能开发或修改:** 开发人员在实现或修改 QUIC 协议的某个功能（例如拥塞控制、丢包恢复等），需要编写单元测试来验证其正确性。
3. **运行 QUIC 单元测试:**  开发人员运行相关的 QUIC 单元测试。这些测试会大量使用 `quic_test_utils.cc` 中提供的工具函数和 Mock 对象来模拟各种网络场景和协议行为。
4. **断点调试:** 如果某个单元测试失败或行为异常，开发人员可能会在 `quic_test_utils.cc` 的相关函数（例如 `ConstructEncryptedPacket`, Mock 对象的设置等）中设置断点，来检查测试数据的构造和模拟环境的设置是否正确，从而定位问题。

总而言之，`quic_test_utils.cc` 的第一部分是一个为 QUIC 协议测试提供基础设施的关键文件，它提供了创建测试数据、模拟协议行为以及方便进行单元测试的各种工具。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/quic_test_utils.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "openssl/chacha.h"
#include "openssl/sha.h"
#include "quiche/quic/core/crypto/crypto_framer.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/http/quic_spdy_client_session.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_creator.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_endian.h"
#include "quiche/common/simple_buffer_allocator.h"

using testing::_;
using testing::Invoke;
using testing::Return;

namespace quic {
namespace test {

QuicConnectionId TestConnectionId() {
  // Chosen by fair dice roll.
  // Guaranteed to be random.
  return TestConnectionId(42);
}

QuicConnectionId TestConnectionId(uint64_t connection_number) {
  const uint64_t connection_id64_net =
      quiche::QuicheEndian::HostToNet64(connection_number);
  return QuicConnectionId(reinterpret_cast<const char*>(&connection_id64_net),
                          sizeof(connection_id64_net));
}

QuicConnectionId TestConnectionIdNineBytesLong(uint64_t connection_number) {
  const uint64_t connection_number_net =
      quiche::QuicheEndian::HostToNet64(connection_number);
  char connection_id_bytes[9] = {};
  static_assert(
      sizeof(connection_id_bytes) == 1 + sizeof(connection_number_net),
      "bad lengths");
  memcpy(connection_id_bytes + 1, &connection_number_net,
         sizeof(connection_number_net));
  return QuicConnectionId(connection_id_bytes, sizeof(connection_id_bytes));
}

uint64_t TestConnectionIdToUInt64(QuicConnectionId connection_id) {
  QUICHE_DCHECK_EQ(connection_id.length(), kQuicDefaultConnectionIdLength);
  uint64_t connection_id64_net = 0;
  memcpy(&connection_id64_net, connection_id.data(),
         std::min<size_t>(static_cast<size_t>(connection_id.length()),
                          sizeof(connection_id64_net)));
  return quiche::QuicheEndian::NetToHost64(connection_id64_net);
}

std::vector<uint8_t> CreateStatelessResetTokenForTest() {
  static constexpr uint8_t kStatelessResetTokenDataForTest[16] = {
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
      0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};
  return std::vector<uint8_t>(kStatelessResetTokenDataForTest,
                              kStatelessResetTokenDataForTest +
                                  sizeof(kStatelessResetTokenDataForTest));
}

std::string TestHostname() { return "test.example.com"; }

QuicServerId TestServerId() { return QuicServerId(TestHostname(), kTestPort); }

QuicAckFrame InitAckFrame(const std::vector<QuicAckBlock>& ack_blocks) {
  QUICHE_DCHECK_GT(ack_blocks.size(), 0u);

  QuicAckFrame ack;
  QuicPacketNumber end_of_previous_block(1);
  for (const QuicAckBlock& block : ack_blocks) {
    QUICHE_DCHECK_GE(block.start, end_of_previous_block);
    QUICHE_DCHECK_GT(block.limit, block.start);
    ack.packets.AddRange(block.start, block.limit);
    end_of_previous_block = block.limit;
  }

  ack.largest_acked = ack.packets.Max();

  return ack;
}

QuicAckFrame InitAckFrame(uint64_t largest_acked) {
  return InitAckFrame(QuicPacketNumber(largest_acked));
}

QuicAckFrame InitAckFrame(QuicPacketNumber largest_acked) {
  return InitAckFrame({{QuicPacketNumber(1), largest_acked + 1}});
}

QuicAckFrame MakeAckFrameWithAckBlocks(size_t num_ack_blocks,
                                       uint64_t least_unacked) {
  QuicAckFrame ack;
  ack.largest_acked = QuicPacketNumber(2 * num_ack_blocks + least_unacked);
  // Add enough received packets to get num_ack_blocks ack blocks.
  for (QuicPacketNumber i = QuicPacketNumber(2);
       i < QuicPacketNumber(2 * num_ack_blocks + 1); i += 2) {
    ack.packets.Add(i + least_unacked);
  }
  return ack;
}

QuicAckFrame MakeAckFrameWithGaps(uint64_t gap_size, size_t max_num_gaps,
                                  uint64_t largest_acked) {
  QuicAckFrame ack;
  ack.largest_acked = QuicPacketNumber(largest_acked);
  ack.packets.Add(QuicPacketNumber(largest_acked));
  for (size_t i = 0; i < max_num_gaps; ++i) {
    if (largest_acked <= gap_size) {
      break;
    }
    largest_acked -= gap_size;
    ack.packets.Add(QuicPacketNumber(largest_acked));
  }
  return ack;
}

EncryptionLevel HeaderToEncryptionLevel(const QuicPacketHeader& header) {
  if (header.form == IETF_QUIC_SHORT_HEADER_PACKET) {
    return ENCRYPTION_FORWARD_SECURE;
  } else if (header.form == IETF_QUIC_LONG_HEADER_PACKET) {
    if (header.long_packet_type == HANDSHAKE) {
      return ENCRYPTION_HANDSHAKE;
    } else if (header.long_packet_type == ZERO_RTT_PROTECTED) {
      return ENCRYPTION_ZERO_RTT;
    }
  }
  return ENCRYPTION_INITIAL;
}

std::unique_ptr<QuicPacket> BuildUnsizedDataPacket(
    QuicFramer* framer, const QuicPacketHeader& header,
    const QuicFrames& frames) {
  const size_t max_plaintext_size =
      framer->GetMaxPlaintextSize(kMaxOutgoingPacketSize);
  size_t packet_size = GetPacketHeaderSize(framer->transport_version(), header);
  for (size_t i = 0; i < frames.size(); ++i) {
    QUICHE_DCHECK_LE(packet_size, max_plaintext_size);
    bool first_frame = i == 0;
    bool last_frame = i == frames.size() - 1;
    const size_t frame_size = framer->GetSerializedFrameLength(
        frames[i], max_plaintext_size - packet_size, first_frame, last_frame,
        header.packet_number_length);
    QUICHE_DCHECK(frame_size);
    packet_size += frame_size;
  }
  return BuildUnsizedDataPacket(framer, header, frames, packet_size);
}

std::unique_ptr<QuicPacket> BuildUnsizedDataPacket(
    QuicFramer* framer, const QuicPacketHeader& header,
    const QuicFrames& frames, size_t packet_size) {
  char* buffer = new char[packet_size];
  EncryptionLevel level = HeaderToEncryptionLevel(header);
  size_t length =
      framer->BuildDataPacket(header, frames, buffer, packet_size, level);

  if (length == 0) {
    delete[] buffer;
    return nullptr;
  }
  // Re-construct the data packet with data ownership.
  return std::make_unique<QuicPacket>(
      buffer, length, /* owns_buffer */ true,
      GetIncludedDestinationConnectionIdLength(header),
      GetIncludedSourceConnectionIdLength(header), header.version_flag,
      header.nonce != nullptr, header.packet_number_length,
      header.retry_token_length_length, header.retry_token.length(),
      header.length_length);
}

std::string Sha1Hash(absl::string_view data) {
  char buffer[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
       reinterpret_cast<uint8_t*>(buffer));
  return std::string(buffer, ABSL_ARRAYSIZE(buffer));
}

bool ClearControlFrame(const QuicFrame& frame) {
  DeleteFrame(&const_cast<QuicFrame&>(frame));
  return true;
}

bool ClearControlFrameWithTransmissionType(const QuicFrame& frame,
                                           TransmissionType /*type*/) {
  return ClearControlFrame(frame);
}

uint64_t SimpleRandom::RandUint64() {
  uint64_t result;
  RandBytes(&result, sizeof(result));
  return result;
}

void SimpleRandom::RandBytes(void* data, size_t len) {
  uint8_t* data_bytes = reinterpret_cast<uint8_t*>(data);
  while (len > 0) {
    const size_t buffer_left = sizeof(buffer_) - buffer_offset_;
    const size_t to_copy = std::min(buffer_left, len);
    memcpy(data_bytes, buffer_ + buffer_offset_, to_copy);
    data_bytes += to_copy;
    buffer_offset_ += to_copy;
    len -= to_copy;

    if (buffer_offset_ == sizeof(buffer_)) {
      FillBuffer();
    }
  }
}

void SimpleRandom::InsecureRandBytes(void* data, size_t len) {
  RandBytes(data, len);
}

uint64_t SimpleRandom::InsecureRandUint64() { return RandUint64(); }

void SimpleRandom::FillBuffer() {
  uint8_t nonce[12];
  memcpy(nonce, buffer_, sizeof(nonce));
  CRYPTO_chacha_20(buffer_, buffer_, sizeof(buffer_), key_, nonce, 0);
  buffer_offset_ = 0;
}

void SimpleRandom::set_seed(uint64_t seed) {
  static_assert(sizeof(key_) == SHA256_DIGEST_LENGTH, "Key has to be 256 bits");
  SHA256(reinterpret_cast<const uint8_t*>(&seed), sizeof(seed), key_);

  memset(buffer_, 0, sizeof(buffer_));
  FillBuffer();
}

MockFramerVisitor::MockFramerVisitor() {
  // By default, we want to accept packets.
  ON_CALL(*this, OnProtocolVersionMismatch(_))
      .WillByDefault(testing::Return(false));

  // By default, we want to accept packets.
  ON_CALL(*this, OnUnauthenticatedHeader(_))
      .WillByDefault(testing::Return(true));

  ON_CALL(*this, OnUnauthenticatedPublicHeader(_))
      .WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPacketHeader(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnStreamFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnCryptoFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnStopWaitingFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPaddingFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPingFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnRstStreamFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnConnectionCloseFrame(_))
      .WillByDefault(testing::Return(true));

  ON_CALL(*this, OnStopSendingFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPathChallengeFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPathResponseFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnGoAwayFrame(_)).WillByDefault(testing::Return(true));
  ON_CALL(*this, OnMaxStreamsFrame(_)).WillByDefault(testing::Return(true));
  ON_CALL(*this, OnStreamsBlockedFrame(_)).WillByDefault(testing::Return(true));
}

MockFramerVisitor::~MockFramerVisitor() {}

bool NoOpFramerVisitor::OnProtocolVersionMismatch(
    ParsedQuicVersion /*version*/) {
  return false;
}

bool NoOpFramerVisitor::OnUnauthenticatedPublicHeader(
    const QuicPacketHeader& /*header*/) {
  return true;
}

bool NoOpFramerVisitor::OnUnauthenticatedHeader(
    const QuicPacketHeader& /*header*/) {
  return true;
}

bool NoOpFramerVisitor::OnPacketHeader(const QuicPacketHeader& /*header*/) {
  return true;
}

void NoOpFramerVisitor::OnCoalescedPacket(
    const QuicEncryptedPacket& /*packet*/) {}

void NoOpFramerVisitor::OnUndecryptablePacket(
    const QuicEncryptedPacket& /*packet*/, EncryptionLevel /*decryption_level*/,
    bool /*has_decryption_key*/) {}

bool NoOpFramerVisitor::OnStreamFrame(const QuicStreamFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnCryptoFrame(const QuicCryptoFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnAckFrameStart(QuicPacketNumber /*largest_acked*/,
                                        QuicTime::Delta /*ack_delay_time*/) {
  return true;
}

bool NoOpFramerVisitor::OnAckRange(QuicPacketNumber /*start*/,
                                   QuicPacketNumber /*end*/) {
  return true;
}

bool NoOpFramerVisitor::OnAckTimestamp(QuicPacketNumber /*packet_number*/,
                                       QuicTime /*timestamp*/) {
  return true;
}

bool NoOpFramerVisitor::OnAckFrameEnd(
    QuicPacketNumber /*start*/,
    const std::optional<QuicEcnCounts>& /*ecn_counts*/) {
  return true;
}

bool NoOpFramerVisitor::OnStopWaitingFrame(
    const QuicStopWaitingFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnPaddingFrame(const QuicPaddingFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnPingFrame(const QuicPingFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnRstStreamFrame(const QuicRstStreamFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnNewConnectionIdFrame(
    const QuicNewConnectionIdFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnRetireConnectionIdFrame(
    const QuicRetireConnectionIdFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnNewTokenFrame(const QuicNewTokenFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnStopSendingFrame(
    const QuicStopSendingFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnPathChallengeFrame(
    const QuicPathChallengeFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnPathResponseFrame(
    const QuicPathResponseFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnGoAwayFrame(const QuicGoAwayFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnMaxStreamsFrame(
    const QuicMaxStreamsFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnStreamsBlockedFrame(
    const QuicStreamsBlockedFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnBlockedFrame(const QuicBlockedFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnMessageFrame(const QuicMessageFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnHandshakeDoneFrame(
    const QuicHandshakeDoneFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnAckFrequencyFrame(
    const QuicAckFrequencyFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::OnResetStreamAtFrame(
    const QuicResetStreamAtFrame& /*frame*/) {
  return true;
}

bool NoOpFramerVisitor::IsValidStatelessResetToken(
    const StatelessResetToken& /*token*/) const {
  return false;
}

MockQuicConnectionVisitor::MockQuicConnectionVisitor() {
  ON_CALL(*this, GetFlowControlSendWindowSize(_))
      .WillByDefault(Return(std::numeric_limits<QuicByteCount>::max()));
}

MockQuicConnectionVisitor::~MockQuicConnectionVisitor() {}

MockQuicConnectionHelper::MockQuicConnectionHelper() {}

MockQuicConnectionHelper::~MockQuicConnectionHelper() {}

const MockClock* MockQuicConnectionHelper::GetClock() const { return &clock_; }

MockClock* MockQuicConnectionHelper::GetClock() { return &clock_; }

QuicRandom* MockQuicConnectionHelper::GetRandomGenerator() {
  return &random_generator_;
}

QuicAlarm* MockAlarmFactory::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new MockAlarmFactory::TestAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> MockAlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<TestAlarm>(std::move(delegate));
  } else {
    return QuicArenaScopedPtr<TestAlarm>(new TestAlarm(std::move(delegate)));
  }
}

quiche::QuicheBufferAllocator*
MockQuicConnectionHelper::GetStreamSendBufferAllocator() {
  return &buffer_allocator_;
}

void MockQuicConnectionHelper::AdvanceTime(QuicTime::Delta delta) {
  clock_.AdvanceTime(delta);
}

MockQuicConnection::MockQuicConnection(QuicConnectionHelperInterface* helper,
                                       QuicAlarmFactory* alarm_factory,
                                       Perspective perspective)
    : MockQuicConnection(TestConnectionId(),
                         QuicSocketAddress(TestPeerIPAddress(), kTestPort),
                         helper, alarm_factory, perspective,
                         ParsedVersionOfIndex(CurrentSupportedVersions(), 0)) {}

MockQuicConnection::MockQuicConnection(QuicSocketAddress address,
                                       QuicConnectionHelperInterface* helper,
                                       QuicAlarmFactory* alarm_factory,
                                       Perspective perspective)
    : MockQuicConnection(TestConnectionId(), address, helper, alarm_factory,
                         perspective,
                         ParsedVersionOfIndex(CurrentSupportedVersions(), 0)) {}

MockQuicConnection::MockQuicConnection(QuicConnectionId connection_id,
                                       QuicConnectionHelperInterface* helper,
                                       QuicAlarmFactory* alarm_factory,
                                       Perspective perspective)
    : MockQuicConnection(connection_id,
                         QuicSocketAddress(TestPeerIPAddress(), kTestPort),
                         helper, alarm_factory, perspective,
                         ParsedVersionOfIndex(CurrentSupportedVersions(), 0)) {}

MockQuicConnection::MockQuicConnection(
    QuicConnectionHelperInterface* helper, QuicAlarmFactory* alarm_factory,
    Perspective perspective, const ParsedQuicVersionVector& supported_versions)
    : MockQuicConnection(
          TestConnectionId(), QuicSocketAddress(TestPeerIPAddress(), kTestPort),
          helper, alarm_factory, perspective, supported_versions) {}

MockQuicConnection::MockQuicConnection(
    QuicConnectionId connection_id, QuicSocketAddress initial_peer_address,
    QuicConnectionHelperInterface* helper, QuicAlarmFactory* alarm_factory,
    Perspective perspective, const ParsedQuicVersionVector& supported_versions)
    : QuicConnection(
          connection_id,
          /*initial_self_address=*/QuicSocketAddress(QuicIpAddress::Any4(), 5),
          initial_peer_address, helper, alarm_factory,
          new testing::NiceMock<MockPacketWriter>(),
          /* owns_writer= */ true, perspective, supported_versions,
          connection_id_generator_) {
  ON_CALL(*this, OnError(_))
      .WillByDefault(
          Invoke(this, &PacketSavingConnection::QuicConnection_OnError));
  ON_CALL(*this, SendCryptoData(_, _, _))
      .WillByDefault(
          Invoke(this, &MockQuicConnection::QuicConnection_SendCryptoData));

  SetSelfAddress(QuicSocketAddress(QuicIpAddress::Any4(), 5));
}

MockQuicConnection::~MockQuicConnection() {}

void MockQuicConnection::AdvanceTime(QuicTime::Delta delta) {
  static_cast<MockQuicConnectionHelper*>(helper())->AdvanceTime(delta);
}

bool MockQuicConnection::OnProtocolVersionMismatch(
    ParsedQuicVersion /*version*/) {
  return false;
}

PacketSavingConnection::PacketSavingConnection(MockQuicConnectionHelper* helper,
                                               QuicAlarmFactory* alarm_factory,
                                               Perspective perspective)
    : MockQuicConnection(helper, alarm_factory, perspective),
      mock_helper_(helper) {}

PacketSavingConnection::PacketSavingConnection(
    MockQuicConnectionHelper* helper, QuicAlarmFactory* alarm_factory,
    Perspective perspective, const ParsedQuicVersionVector& supported_versions)
    : MockQuicConnection(helper, alarm_factory, perspective,
                         supported_versions),
      mock_helper_(helper) {}

PacketSavingConnection::~PacketSavingConnection() {}

SerializedPacketFate PacketSavingConnection::GetSerializedPacketFate(
    bool /*is_mtu_discovery*/, EncryptionLevel /*encryption_level*/) {
  return SEND_TO_WRITER;
}

void PacketSavingConnection::SendOrQueuePacket(SerializedPacket packet) {
  encrypted_packets_.push_back(std::make_unique<QuicEncryptedPacket>(
      CopyBuffer(packet), packet.encrypted_length, true));
  MockClock& clock = *mock_helper_->GetClock();
  clock.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  // Transfer ownership of the packet to the SentPacketManager and the
  // ack notifier to the AckNotifierManager.
  OnPacketSent(packet.encryption_level, packet.transmission_type);
  QuicConnectionPeer::GetSentPacketManager(this)->OnPacketSent(
      &packet, clock.ApproximateNow(), NOT_RETRANSMISSION,
      HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
}

std::vector<const QuicEncryptedPacket*> PacketSavingConnection::GetPackets()
    const {
  std::vector<const QuicEncryptedPacket*> packets;
  for (size_t i = num_cleared_packets_; i < encrypted_packets_.size(); ++i) {
    packets.push_back(encrypted_packets_[i].get());
  }
  return packets;
}

void PacketSavingConnection::ClearPackets() {
  num_cleared_packets_ = encrypted_packets_.size();
}

MockQuicSession::MockQuicSession(QuicConnection* connection)
    : MockQuicSession(connection, true) {}

MockQuicSession::MockQuicSession(QuicConnection* connection,
                                 bool create_mock_crypto_stream)
    : QuicSession(connection, nullptr, DefaultQuicConfig(),
                  connection->supported_versions(),
                  /*num_expected_unidirectional_static_streams = */ 0) {
  if (create_mock_crypto_stream) {
    crypto_stream_ =
        std::make_unique<testing::NiceMock<MockQuicCryptoStream>>(this);
  }
  ON_CALL(*this, WritevData(_, _, _, _, _, _))
      .WillByDefault(testing::Return(QuicConsumedData(0, false)));
}

MockQuicSession::~MockQuicSession() { DeleteConnection(); }

QuicCryptoStream* MockQuicSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoStream* MockQuicSession::GetCryptoStream() const {
  return crypto_stream_.get();
}

void MockQuicSession::SetCryptoStream(QuicCryptoStream* crypto_stream) {
  crypto_stream_.reset(crypto_stream);
}

QuicConsumedData MockQuicSession::ConsumeData(
    QuicStreamId id, size_t write_length, QuicStreamOffset offset,
    StreamSendingState state, TransmissionType /*type*/,
    std::optional<EncryptionLevel> /*level*/) {
  if (write_length > 0) {
    auto buf = std::make_unique<char[]>(write_length);
    QuicStream* stream = GetOrCreateStream(id);
    QUICHE_DCHECK(stream);
    QuicDataWriter writer(write_length, buf.get(), quiche::HOST_BYTE_ORDER);
    stream->WriteStreamData(offset, write_length, &writer);
  } else {
    QUICHE_DCHECK(state != NO_FIN);
  }
  return QuicConsumedData(write_length, state != NO_FIN);
}

MockQuicCryptoStream::MockQuicCryptoStream(QuicSession* session)
    : QuicCryptoStream(session), params_(new QuicCryptoNegotiatedParameters) {}

MockQuicCryptoStream::~MockQuicCryptoStream() {}

ssl_early_data_reason_t MockQuicCryptoStream::EarlyDataReason() const {
  return ssl_early_data_unknown;
}

bool MockQuicCryptoStream::one_rtt_keys_available() const { return false; }

const QuicCryptoNegotiatedParameters&
MockQuicCryptoStream::crypto_negotiated_params() const {
  return *params_;
}

CryptoMessageParser* MockQuicCryptoStream::crypto_message_parser() {
  return &crypto_framer_;
}

MockQuicSpdySession::MockQuicSpdySession(QuicConnection* connection)
    : MockQuicSpdySession(connection, true) {}

MockQuicSpdySession::MockQuicSpdySession(QuicConnection* connection,
                                         bool create_mock_crypto_stream)
    : QuicSpdySession(connection, nullptr, DefaultQuicConfig(),
                      connection->supported_versions()) {
  if (create_mock_crypto_stream) {
    crypto_stream_ = std::make_unique<MockQuicCryptoStream>(this);
  }

  ON_CALL(*this, WritevData(_, _, _, _, _, _))
      .WillByDefault(testing::Return(QuicConsumedData(0, false)));

  ON_CALL(*this, SendWindowUpdate(_, _))
      .WillByDefault([this](QuicStreamId id, QuicStreamOffset byte_offset) {
        return QuicSpdySession::SendWindowUpdate(id, byte_offset);
      });

  ON_CALL(*this, SendBlocked(_, _))
      .WillByDefault([this](QuicStreamId id, QuicStreamOffset byte_offset) {
        return QuicSpdySession::SendBlocked(id, byte_offset);
      });

  ON_CALL(*this, OnCongestionWindowChange(_)).WillByDefault(testing::Return());
}

MockQuicSpdySession::~MockQuicSpdySession() { DeleteConnection(); }

QuicCryptoStream* MockQuicSpdySession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoStream* MockQuicSpdySession::GetCryptoStream() const {
  return crypto_stream_.get();
}

void MockQuicSpdySession::SetCryptoStream(QuicCryptoStream* crypto_stream) {
  crypto_stream_.reset(crypto_stream);
}

QuicConsumedData MockQuicSpdySession::ConsumeData(
    QuicStreamId id, size_t write_length, QuicStreamOffset offset,
    StreamSendingState state, TransmissionType /*type*/,
    std::optional<EncryptionLevel> /*level*/) {
  if (write_length > 0) {
    auto buf = std::make_unique<char[]>(write_length);
    QuicStream* stream = GetOrCreateStream(id);
    QUICHE_DCHECK(stream);
    QuicDataWriter writer(write_length, buf.get(), quiche::HOST_BYTE_ORDER);
    stream->WriteStreamData(offset, write_length, &writer);
  } else {
    QUICHE_DCHECK(state != NO_FIN);
  }
  return QuicConsumedData(write_length, state != NO_FIN);
}

TestQuicSpdyServerSession::TestQuicSpdyServerSession(
    QuicConnection* connection, const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicServerSessionBase(config, supported_versions, connection, &visitor_,
                            &helper_, crypto_config, compressed_certs_cache) {
  ON_CALL(helper_, CanAcceptClientHello(_, _, _, _, _))
      .WillByDefault(testing::Return(true));
}

TestQuicSpdyServerSession::~TestQuicSpdyServerSession() { DeleteConnection(); }

std::unique_ptr<QuicCryptoServerStreamBase>
TestQuicSpdyServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return CreateCryptoServerStream(crypto_config, compressed_certs_cache, this,
                                  &helper_);
}

QuicCryptoServerStreamBase*
TestQuicSpdyServerSession::GetMutableCryptoStream() {
  return QuicServerSessionBase::GetMutableCryptoStream();
}

const QuicCryptoServerStreamBase* TestQuicSpdyServerSession::GetCryptoStream()
    const {
  return QuicServerSessionBase::GetCryptoStream();
}

TestQuicSpdyClientSession::TestQuicSpdyClientSession(
    QuicConnection* connection, const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
    std::optional<QuicSSLConfig> ssl_config)
    : QuicSpdyClientSessionBase(connection, nullptr, config,
                                supported_versions),
      ssl_config_(std::move(ssl_config)) {
  // TODO(b/153726130): Consider adding SetServerApplicationStateForResumption
  // calls in tests and set |has_application_state| to true.
  crypto_stream_ = std::make_unique<QuicCryptoClientStream>(
      server_id, this, crypto_test_utils::ProofVerifyContextForTesting(),
      crypto_config, this, /*has_application_state = */ false);
  Initialize();
  ON_CALL(*this, OnConfigNegotiated())
      .WillByDefault(
          Invoke(this, &TestQuicSpdyClientSession::RealOnConfigNegotiated));
}

TestQuicSpdyClientSession::~TestQuicSpdyClientSession() {}

QuicCryptoClientStream* TestQuicSpdyClientSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoClientStream* TestQuicSpdyClientSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

void TestQuicSpdyClientSession::RealOnConfigNegotiated() {
  QuicSpdyClientSessionBase::OnConfigNegotiated();
}

MockPacketWriter::MockPacketWriter() {
  ON_CALL(*this, GetMaxPacketSize(_))
      .WillByDefault(testing::Return(kMaxOutgoingPacketSize));
  ON_CALL(*this, IsBatchMode()).WillByDefault(testing::Return(false));
  ON_CALL(*this, GetNextWriteLocation(_, _))
      .WillByDefault(testing::Return(QuicPacketBuffer()));
  ON_CALL(*this, Flush())
      .WillByDefault(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  ON_CALL(*this, SupportsReleaseTime()).WillByDefault(testing::Return(false));
}

MockPacketWriter::~MockPacketWriter() {}

MockSendAlgorithm::MockSendAlgorithm() {
  ON_CALL(*this, PacingRate(_))
      .WillByDefault(testing::Return(QuicBandwidth::Zero()));
  ON_CALL(*this, BandwidthEstimate())
      .WillByDefault(testing::Return(QuicBandwidth::Zero()));
}

MockSendAlgorithm::~MockSendAlgorithm() {}

MockLossAlgorithm::MockLossAlgorithm() {}

MockLossAlgorithm::~MockLossAlgorithm() {}

MockAckListener::MockAckListener() {}

MockAckListener::~MockAckListener() {}

MockNetworkChangeVisitor::MockNetworkChangeVisitor() {}

MockNetworkChangeVisitor::~MockNetworkChangeVisitor() {}

QuicIpAddress TestPeerIPAddress() { return QuicIpAddress::Loopback4(); }

ParsedQuicVersion QuicVersionMax() { return AllSupportedVersions().front(); }

ParsedQuicVersion QuicVersionMin() { return AllSupportedVersions().back(); }

void DisableQuicVersionsWithTls() {
  for (const ParsedQuicVersion& version : AllSupportedVersionsWithTls()) {
    QuicDisableVersion(version);
  }
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId destination_connection_id,
    QuicConnectionId source_connection_id, bool version_flag, bool reset_flag,
    uint64_t packet_number, const std::string& data) {
  return ConstructEncryptedPacket(
      destination_connection_id, source_connection_id, version_flag, reset_flag,
      packet_number, data, CONNECTION_ID_PRESENT, CONNECTION_ID_ABSENT,
      PACKET_4BYTE_PACKET_NUMBER);
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId destination_connection_id,
    QuicConnectionId source_connection_id, bool version_flag, bool reset_flag,
    uint64_t packet_number, const std::string& data,
    QuicConnectionIdIncluded destination_connection_id_included,
    QuicConnectionIdIncluded source_connection_id_included,
    QuicPacketNumberLength packet_number_length) {
  return ConstructEncryptedPacket(
      destination_connection_id, source_connection_id, version_flag, reset_flag,
      packet_number, data, destination_connection_id_included,
      source_connection_id_included, packet_number_length, nullptr);
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId destination_connection_id,
    QuicConnectionId source_connection_id, bool version_flag, bool reset_flag,
    uint64_t packet_number, const std::string& data,
    QuicConnectionIdIncluded destination_connection_id_included,
    QuicConnectionIdIncluded source_connection_id_included,
    QuicPacketNumberLength packet_number_length,
    ParsedQuicVersionVector* versions) {
  return ConstructEncryptedPacket(
      destination_connection_id, source_connection_id, version_flag, reset_flag,
      packet_number, data, false, destination_connection_id_included,
      source_connection_id_included, packet_number_length, versions,
      Perspective::IS_CLIENT);
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId destination_connection_id,
    QuicConnectionId source_connection_id, bool version_flag, bool reset_flag,
    uint64_t packet_number, const std::string& data, bool full_padding,
    QuicConnectionIdIncluded destination_connection_id_included,
    QuicConnectionIdIncluded source_connection_id_included,
    QuicPacketNumberLength packet_number_length,
    ParsedQuicVersionVector* versions) {
  return ConstructEncryptedPacket(
      destination_connection_id, source_connection_id, version_flag, reset_flag,
      packet_number, data, full_padding, destination_connection_id_included,
      source_connection_id_included, packet_number_length, versions,
      Perspective::IS_CLIENT);
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId destination_connection_id,
    QuicConnectionId source_connection_id, bool version_flag, bool reset_flag,
    uint64_t packet_number, const std::string& data, bool full_padding,
    QuicConnectionIdIncluded destination_connection_id_included,
    QuicConnectionIdIncluded source_connection_id_included,
    QuicPacketNumberLength packet_number_length,
    ParsedQuicVersionVector* versions, Perspective perspective) {
  QuicPacketHeader header;
  header.destination_connection_id = destination_connection_id;
  header.destination_connection_id_included =
      destination_connection_id_included;
  header.source_connection_id = source_connection_id;
  header.source_connection_id_included = source_connection_id_included;
  header.version_flag = version_flag;
```
Response:
Let's break down the thought process for analyzing the C++ test file `quic_utils_test.cc`.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Chromium QUIC test file. The key is to understand what the file *does* and how it relates to the broader context of QUIC and potentially even JavaScript. It also asks for examples, assumptions, and debugging information.

**2. Initial Examination (Skimming and Identifying Key Components):**

The first step is to skim the code to get a general idea of its structure and contents. I'd look for:

* **Includes:** What other files and libraries are being used? This gives clues about the functionality being tested. In this case, `quic_utils.h`, `quic_connection_id.h`, `quic_types.h`, `quic_test.h`, and `quic_test_utils.h` are immediately relevant. The `absl` includes suggest usage of the Abseil library for utilities.
* **Namespace:** The code is within `quic::test`. This confirms it's a test file within the QUIC library.
* **Test Fixture:** The `QuicUtilsTest` class inheriting from `QuicTest` tells us this file contains unit tests for something related to `QuicUtils`.
* **`TEST_F` Macros:** These are the individual test cases. Reading the names of these tests is crucial for understanding the specific functionalities being tested. Examples: `DetermineAddressChangeType`, `ReferenceTest`, `IsUnackable`, `RandomConnectionId`, etc.
* **Assertions:**  `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_NE`. These tell us what the tests are checking.
* **Helper Functions/Variables within Tests:**  Look for local variables and how they are being used to set up test scenarios. For instance, in `DetermineAddressChangeType`, the different IP address strings are important.
* **Specific Algorithms/Data Structures:**  The mention of `FNV1a_128_Hash` in `ReferenceTest` and `BitMask` usage at the end are significant.

**3. Deeper Dive into Individual Test Cases:**

Now, I would go through each `TEST_F` individually and understand its purpose:

* **`DetermineAddressChangeType`:**  This clearly tests the `QuicUtils::DetermineAddressChangeType` function by providing different pairs of `QuicSocketAddress` and checking the expected `AddressChangeType`. I'd pay attention to the different scenarios: no change, port change, IPv4 to IPv6, subnet change, etc.
* **`ReferenceTest`:** This test compares the `QuicUtils::FNV1a_128_Hash` function against a "reference" implementation (`IncrementalHashReference`). This suggests they are ensuring the custom hash function produces the correct output.
* **`IsUnackable`:**  This iterates through `SentPacketState` and verifies the behavior of `QuicUtils::IsAckable`.
* **`RetransmissionTypeToPacketState`:** This tests the mapping between `TransmissionType` and `SentPacketState`.
* **`IsIetfPacketHeader`:**  This tests functions related to identifying IETF QUIC packet headers.
* **`RandomConnectionId` and `RandomConnectionIdVariableLength`:** These test the creation of random connection IDs with different lengths.
* **`VariableLengthConnectionId`:**  Checks if variable-length connection IDs are allowed for a specific QUIC version.
* **`StatelessResetToken`:**  Tests the generation and comparison of stateless reset tokens.
* **`EcnCodepointToString`:** Tests the conversion of ECN codepoints to strings.
* **`PosixBasename`:** Tests a utility function for extracting the basename from a path.
* **`QuicBitMaskTest` tests:** This section tests the functionality of the `BitMask` template class.

**4. Identifying Functionality and Purpose of the File:**

Based on the individual tests, I can summarize the overall purpose of `quic_utils_test.cc`: It's a unit test suite for the `quic::QuicUtils` class, verifying various utility functions related to QUIC networking. These functions cover address handling, hashing, packet state management, header identification, connection ID generation, stateless resets, ECN, path manipulation, and bit manipulation.

**5. Checking for JavaScript Relevance:**

This requires understanding where QUIC fits in the broader context. QUIC is a transport protocol used in web browsers (like Chrome) for HTTP/3. Therefore, while this specific C++ code isn't directly *in* JavaScript, it underpins the network communication that JavaScript relies on in web applications.

**6. Providing Examples and Reasoning:**

For each functional area identified, I would think of specific examples to illustrate how the tested functions are used. For instance:

* **Address Change:**  A mobile user switching from Wi-Fi to cellular.
* **Hashing:**  Generating unique identifiers or for data integrity checks.
* **Packet States:**  Managing the lifecycle of sent packets.
* **Connection IDs:**  Uniquely identifying connections.
* **Bitmasks:**  Representing sets of flags or options.

For logical reasoning, I would construct simple input/output scenarios for selected functions.

**7. Identifying Common Usage Errors:**

This involves thinking about how developers might misuse the tested functionalities. Examples include:

* Incorrectly interpreting address change types.
* Misunderstanding the purpose of different packet states.
* Not handling connection ID generation properly.

**8. Tracing User Operations (Debugging Clues):**

This requires linking the C++ code to user actions in a browser. The key is to understand the path from a user action (like visiting a website) to the underlying network operations:

* User types a URL in the browser.
* Browser resolves the domain name to an IP address.
* Browser initiates a QUIC connection to the server.
* The `QuicUtils` functions are used at various stages of the connection setup and data transfer, such as:
    * Determining if the client's IP address changes during the connection.
    * Generating connection IDs.
    * Managing the state of sent and received packets.

**9. Structuring the Output:**

Finally, I would organize the information logically, following the structure requested in the prompt:

* **File Functionality:** A concise summary.
* **Relation to JavaScript:** Explain the indirect connection through the browser's networking stack.
* **Examples with JavaScript:** Illustrate how the underlying QUIC mechanisms affect the JavaScript environment.
* **Logical Reasoning (Input/Output):** Provide clear examples.
* **Common Usage Errors:** Highlight potential pitfalls for programmers.
* **User Operation to Code:** Describe the steps from user action to the code being tested.

This methodical approach ensures that all aspects of the request are addressed comprehensively and accurately. It involves understanding the code's purpose, its relationship to the broader system, and how it might be used and misused.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_utils_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它是一个**单元测试文件**，专门用于测试 `quic_utils.h` 中定义的实用工具函数（Utility functions）。

**它的主要功能是：**

1. **验证 `quic_utils.h` 中各种函数的正确性。** 这些函数通常执行一些通用的、与 QUIC 协议相关的操作，例如：
    * 判断网络地址是否发生变化以及变化的类型。
    * 计算哈希值。
    * 判断数据包是否可以被确认 (ACKable)。
    * 将数据包重传类型转换为数据包状态。
    * 判断数据包头部是否为 IETF QUIC 格式。
    * 生成随机连接 ID。
    * 生成无状态重置令牌 (Stateless Reset Token)。
    * 将 ECN 标记转换为字符串。
    * 获取文件路径的 basename。
    * 提供位掩码 (BitMask) 的实现和测试。

**它与 JavaScript 的功能关系（间接）：**

QUIC 是一种传输层协议，旨在提供比 TCP 更快、更可靠的网络连接。在 Chromium 中，当浏览器需要与支持 QUIC 的服务器建立连接并进行数据传输时，就会使用 QUIC 协议栈。JavaScript 运行在浏览器环境中，它通过浏览器提供的 Web API (例如 `fetch` 或 `XMLHttpRequest`) 发起网络请求。

当 JavaScript 发起一个到支持 HTTP/3 (基于 QUIC) 的服务器的请求时，底层的网络层会使用 QUIC 协议进行通信。`quic_utils.h` 中测试的这些工具函数，在 QUIC 连接的建立、数据传输、拥塞控制、连接迁移等过程中都会被用到。

**举例说明：**

* **地址变化检测 (`DetermineAddressChangeType` 测试):** 当用户在移动设备上从 Wi-Fi 切换到蜂窝网络时，客户端的 IP 地址可能会发生变化。QUIC 协议需要能够检测到这种变化，以便进行连接迁移，保证连接的持续性。`QuicUtils::DetermineAddressChangeType` 函数就用于实现这个功能。虽然 JavaScript 代码本身不会直接调用这个函数，但当用户在网络切换时，底层的 QUIC 实现会使用它来判断地址变化，从而影响到 JavaScript 发起的网络请求是否会中断。

* **随机连接 ID 生成 (`RandomConnectionId` 测试):**  在建立 QUIC 连接时，客户端和服务器需要协商一个连接 ID。这个 ID 用于在网络中唯一标识这个连接。`QuicUtils::CreateRandomConnectionId` 函数用于生成这个随机的连接 ID。JavaScript 发起的第一个请求会触发 QUIC 连接的建立，其中就包含了随机连接 ID 的生成。

**逻辑推理 (假设输入与输出):**

**假设输入 `DetermineAddressChangeType` 测试:**

* `old_address`:  IP 地址为 "192.168.1.1"，端口为 1234 的 Socket 地址。
* `new_address`: IP 地址为 "192.168.1.1"，端口为 5678 的 Socket 地址。

**预期输出:** `PORT_CHANGE` (端口发生了变化)。

**假设输入 `IsAckable` 测试:**

* `packet_state`: `ACKED` (数据包已被确认)。

**预期输出:** `false` (已确认的数据包不需要再次被确认，因此不可 "ACKable")。

**假设输入 `PosixBasename` 测试:**

* `filepath`: "/home/user/documents/report.pdf"

**预期输出:** "report.pdf"

**涉及用户或编程常见的使用错误 (举例说明):**

* **错误地假设地址没有变化：** 程序员可能在实现某些网络逻辑时，没有考虑到网络地址可能发生变化的情况，例如在连接迁移的场景下。如果他们错误地假设地址始终不变，可能会导致连接中断或数据传输失败。`QuicUtils::DetermineAddressChangeType` 的测试可以帮助确保这个判断的准确性，从而避免这类错误。

* **不正确地处理数据包状态：**  程序员如果对 QUIC 协议中数据包的不同状态（例如 `SENT`, `ACKED`, `LOST`, `UNACKABLE`）理解不透彻，可能会在处理数据包确认或重传逻辑时出错。`IsUnackable` 和 `RetransmissionTypeToPacketState` 的测试旨在验证这些状态转换和判断的正确性，从而帮助开发者避免这类错误。

* **依赖固定长度的连接 ID (针对旧版本 QUIC)：** 在早期的 QUIC 版本中，连接 ID 的长度是固定的。如果开发者在处理不同版本的 QUIC 时，没有考虑到连接 ID 长度可能变化的情况，可能会导致解析错误。 `VariableLengthConnectionId` 的测试就与此相关，确保了对可变长度连接 ID 的支持。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 Chrome 浏览器中输入一个 URL 并访问一个支持 HTTP/3 的网站。**
2. **Chrome 浏览器开始与服务器建立 QUIC 连接。**
3. **在 QUIC 连接建立的过程中：**
    * **生成连接 ID:** `QuicUtils::CreateRandomConnectionId` 函数会被调用生成唯一的连接 ID。
    * **判断地址变化 (如果连接已经建立并发生迁移):**  如果用户的网络环境发生变化（例如从 Wi-Fi 切换到移动数据），`QuicUtils::DetermineAddressChangeType` 函数会被调用来判断地址变化的类型。
4. **在 QUIC 连接的数据传输过程中：**
    * **数据包被发送和接收，并标记状态:**  例如，当一个数据包被成功确认时，其状态会变为 `ACKED`。`QuicUtils::IsAckable` 函数可能在某些逻辑中被用来判断是否需要对某个状态的数据包进行处理。
    * **如果数据包丢失，需要进行重传:**  `QuicUtils::RetransmissionTypeToPacketState` 函数会被用来确定重传的数据包应该被标记为什么状态。
5. **如果服务器发送了无状态重置报文:** `QuicUtils::GenerateStatelessResetToken` 相关的逻辑会被触发，用于验证重置报文的合法性。

**作为调试线索，如果开发者在 QUIC 连接的某个环节遇到了问题，例如：**

* **连接无法建立：** 可能需要检查连接 ID 的生成和处理是否正确。可以查看 `RandomConnectionId` 测试覆盖的逻辑。
* **连接意外断开：**  可能与连接迁移失败有关，需要检查地址变化检测的逻辑。可以查看 `DetermineAddressChangeType` 测试。
* **数据包丢失或重复：** 可能与数据包状态管理有关，需要检查 `IsAckable` 和 `RetransmissionTypeToPacketState` 测试覆盖的逻辑。

因此，`quic_utils_test.cc` 这个文件虽然是测试代码，但它覆盖了 `quic_utils.h` 中关键实用函数的各种场景，可以帮助开发者理解这些函数的功能和使用方法，并在调试 QUIC 相关问题时提供有价值的线索。通过查看相关的测试用例，开发者可以更好地理解特定函数在各种情况下的行为，从而定位和解决问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_utils_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_utils.h"

#include <string>
#include <vector>

#include "absl/base/macros.h"
#include "absl/numeric/int128.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
namespace {

class QuicUtilsTest : public QuicTest {};

TEST_F(QuicUtilsTest, DetermineAddressChangeType) {
  const std::string kIPv4String1 = "1.2.3.4";
  const std::string kIPv4String2 = "1.2.3.5";
  const std::string kIPv4String3 = "1.1.3.5";
  const std::string kIPv6String1 = "2001:700:300:1800::f";
  const std::string kIPv6String2 = "2001:700:300:1800:1:1:1:f";
  QuicSocketAddress old_address;
  QuicSocketAddress new_address;
  QuicIpAddress address;

  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.FromString(kIPv4String1));
  old_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  new_address = QuicSocketAddress(address, 5678);
  EXPECT_EQ(PORT_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.FromString(kIPv6String1));
  old_address = QuicSocketAddress(address, 1234);
  new_address = QuicSocketAddress(address, 5678);
  EXPECT_EQ(PORT_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.FromString(kIPv4String1));
  old_address = QuicSocketAddress(address, 1234);
  ASSERT_TRUE(address.FromString(kIPv6String1));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV4_TO_IPV6_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  old_address = QuicSocketAddress(address, 1234);
  ASSERT_TRUE(address.FromString(kIPv4String1));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.FromString(kIPv6String2));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV6_TO_IPV6_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.FromString(kIPv4String1));
  old_address = QuicSocketAddress(address, 1234);
  ASSERT_TRUE(address.FromString(kIPv4String2));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV4_SUBNET_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.FromString(kIPv4String3));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV4_TO_IPV4_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
}

absl::uint128 IncrementalHashReference(const void* data, size_t len) {
  // The two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // hash = 144066263297769815596495629667062367629
  absl::uint128 hash = absl::MakeUint128(UINT64_C(7809847782465536322),
                                         UINT64_C(7113472399480571277));
  // kPrime = 309485009821345068724781371
  const absl::uint128 kPrime = absl::MakeUint128(16777216, 315);
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data);
  for (size_t i = 0; i < len; ++i) {
    hash = hash ^ absl::MakeUint128(0, octets[i]);
    hash = hash * kPrime;
  }
  return hash;
}

TEST_F(QuicUtilsTest, ReferenceTest) {
  std::vector<uint8_t> data(32);
  for (size_t i = 0; i < data.size(); ++i) {
    data[i] = i % 255;
  }
  EXPECT_EQ(IncrementalHashReference(data.data(), data.size()),
            QuicUtils::FNV1a_128_Hash(absl::string_view(
                reinterpret_cast<const char*>(data.data()), data.size())));
}

TEST_F(QuicUtilsTest, IsUnackable) {
  for (size_t i = FIRST_PACKET_STATE; i <= LAST_PACKET_STATE; ++i) {
    if (i == NEVER_SENT || i == ACKED || i == UNACKABLE) {
      EXPECT_FALSE(QuicUtils::IsAckable(static_cast<SentPacketState>(i)));
    } else {
      EXPECT_TRUE(QuicUtils::IsAckable(static_cast<SentPacketState>(i)));
    }
  }
}

TEST_F(QuicUtilsTest, RetransmissionTypeToPacketState) {
  for (size_t i = FIRST_TRANSMISSION_TYPE; i <= LAST_TRANSMISSION_TYPE; ++i) {
    if (i == NOT_RETRANSMISSION) {
      continue;
    }
    SentPacketState state = QuicUtils::RetransmissionTypeToPacketState(
        static_cast<TransmissionType>(i));
    if (i == HANDSHAKE_RETRANSMISSION) {
      EXPECT_EQ(HANDSHAKE_RETRANSMITTED, state);
    } else if (i == LOSS_RETRANSMISSION) {
      EXPECT_EQ(LOST, state);
    } else if (i == ALL_ZERO_RTT_RETRANSMISSION) {
      EXPECT_EQ(UNACKABLE, state);
    } else if (i == PTO_RETRANSMISSION) {
      EXPECT_EQ(PTO_RETRANSMITTED, state);
    } else if (i == PATH_RETRANSMISSION) {
      EXPECT_EQ(NOT_CONTRIBUTING_RTT, state);
    } else if (i == ALL_INITIAL_RETRANSMISSION) {
      EXPECT_EQ(UNACKABLE, state);
    } else {
      QUICHE_DCHECK(false)
          << "No corresponding packet state according to transmission type: "
          << i;
    }
  }
}

TEST_F(QuicUtilsTest, IsIetfPacketHeader) {
  // IETF QUIC short header
  uint8_t first_byte = 0;
  EXPECT_TRUE(QuicUtils::IsIetfPacketHeader(first_byte));
  EXPECT_TRUE(QuicUtils::IsIetfPacketShortHeader(first_byte));

  // IETF QUIC long header
  first_byte |= (FLAGS_LONG_HEADER | FLAGS_DEMULTIPLEXING_BIT);
  EXPECT_TRUE(QuicUtils::IsIetfPacketHeader(first_byte));
  EXPECT_FALSE(QuicUtils::IsIetfPacketShortHeader(first_byte));

  // IETF QUIC long header, version negotiation.
  first_byte = 0;
  first_byte |= FLAGS_LONG_HEADER;
  EXPECT_TRUE(QuicUtils::IsIetfPacketHeader(first_byte));
  EXPECT_FALSE(QuicUtils::IsIetfPacketShortHeader(first_byte));

  // GQUIC
  first_byte = 0;
  first_byte |= PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID;
  EXPECT_FALSE(QuicUtils::IsIetfPacketHeader(first_byte));
  EXPECT_FALSE(QuicUtils::IsIetfPacketShortHeader(first_byte));
}

TEST_F(QuicUtilsTest, RandomConnectionId) {
  MockRandom random(33);
  QuicConnectionId connection_id = QuicUtils::CreateRandomConnectionId(&random);
  EXPECT_EQ(connection_id.length(), sizeof(uint64_t));
  char connection_id_bytes[sizeof(uint64_t)];
  random.RandBytes(connection_id_bytes, ABSL_ARRAYSIZE(connection_id_bytes));
  EXPECT_EQ(connection_id,
            QuicConnectionId(static_cast<char*>(connection_id_bytes),
                             ABSL_ARRAYSIZE(connection_id_bytes)));
  EXPECT_NE(connection_id, EmptyQuicConnectionId());
  EXPECT_NE(connection_id, TestConnectionId());
  EXPECT_NE(connection_id, TestConnectionId(1));
  EXPECT_NE(connection_id, TestConnectionIdNineBytesLong(1));
  EXPECT_EQ(QuicUtils::CreateRandomConnectionId().length(),
            kQuicDefaultConnectionIdLength);
}

TEST_F(QuicUtilsTest, RandomConnectionIdVariableLength) {
  MockRandom random(1337);
  const uint8_t connection_id_length = 9;
  QuicConnectionId connection_id =
      QuicUtils::CreateRandomConnectionId(connection_id_length, &random);
  EXPECT_EQ(connection_id.length(), connection_id_length);
  char connection_id_bytes[connection_id_length];
  random.RandBytes(connection_id_bytes, ABSL_ARRAYSIZE(connection_id_bytes));
  EXPECT_EQ(connection_id,
            QuicConnectionId(static_cast<char*>(connection_id_bytes),
                             ABSL_ARRAYSIZE(connection_id_bytes)));
  EXPECT_NE(connection_id, EmptyQuicConnectionId());
  EXPECT_NE(connection_id, TestConnectionId());
  EXPECT_NE(connection_id, TestConnectionId(1));
  EXPECT_NE(connection_id, TestConnectionIdNineBytesLong(1));
  EXPECT_EQ(QuicUtils::CreateRandomConnectionId(connection_id_length).length(),
            connection_id_length);
}

TEST_F(QuicUtilsTest, VariableLengthConnectionId) {
  EXPECT_FALSE(VersionAllowsVariableLengthConnectionIds(QUIC_VERSION_46));
  EXPECT_TRUE(QuicUtils::IsConnectionIdValidForVersion(
      QuicUtils::CreateZeroConnectionId(QUIC_VERSION_46), QUIC_VERSION_46));
  EXPECT_NE(QuicUtils::CreateZeroConnectionId(QUIC_VERSION_46),
            EmptyQuicConnectionId());
  EXPECT_FALSE(QuicUtils::IsConnectionIdValidForVersion(EmptyQuicConnectionId(),
                                                        QUIC_VERSION_46));
}

TEST_F(QuicUtilsTest, StatelessResetToken) {
  QuicConnectionId connection_id1a = test::TestConnectionId(1);
  QuicConnectionId connection_id1b = test::TestConnectionId(1);
  QuicConnectionId connection_id2 = test::TestConnectionId(2);
  StatelessResetToken token1a =
      QuicUtils::GenerateStatelessResetToken(connection_id1a);
  StatelessResetToken token1b =
      QuicUtils::GenerateStatelessResetToken(connection_id1b);
  StatelessResetToken token2 =
      QuicUtils::GenerateStatelessResetToken(connection_id2);
  EXPECT_EQ(token1a, token1b);
  EXPECT_NE(token1a, token2);
  EXPECT_TRUE(QuicUtils::AreStatelessResetTokensEqual(token1a, token1b));
  EXPECT_FALSE(QuicUtils::AreStatelessResetTokensEqual(token1a, token2));
}

TEST_F(QuicUtilsTest, EcnCodepointToString) {
  EXPECT_EQ(EcnCodepointToString(ECN_NOT_ECT), "Not-ECT");
  EXPECT_EQ(EcnCodepointToString(ECN_ECT0), "ECT(0)");
  EXPECT_EQ(EcnCodepointToString(ECN_ECT1), "ECT(1)");
  EXPECT_EQ(EcnCodepointToString(ECN_CE), "CE");
}

TEST_F(QuicUtilsTest, PosixBasename) {
  EXPECT_EQ("", PosixBasename("/hello/"));
  EXPECT_EQ("hello", PosixBasename("/hello"));
  EXPECT_EQ("world", PosixBasename("hello/world"));
  EXPECT_EQ("", PosixBasename("hello/"));
  EXPECT_EQ("world", PosixBasename("world"));
  EXPECT_EQ("", PosixBasename("/"));
  EXPECT_EQ("", PosixBasename(""));
  // "\\" is not treated as a path separator.
  EXPECT_EQ("C:\\hello", PosixBasename("C:\\hello"));
  EXPECT_EQ("world", PosixBasename("C:\\hello/world"));
}

enum class TestEnumClassBit : uint8_t {
  BIT_ZERO = 0,
  BIT_ONE,
  BIT_TWO,
};

enum TestEnumBit {
  TEST_BIT_0 = 0,
  TEST_BIT_1,
  TEST_BIT_2,
};

TEST(QuicBitMaskTest, EnumClass) {
  BitMask<TestEnumClassBit> mask(
      {TestEnumClassBit::BIT_ZERO, TestEnumClassBit::BIT_TWO});
  EXPECT_TRUE(mask.IsSet(TestEnumClassBit::BIT_ZERO));
  EXPECT_FALSE(mask.IsSet(TestEnumClassBit::BIT_ONE));
  EXPECT_TRUE(mask.IsSet(TestEnumClassBit::BIT_TWO));

  mask.ClearAll();
  EXPECT_FALSE(mask.IsSet(TestEnumClassBit::BIT_ZERO));
  EXPECT_FALSE(mask.IsSet(TestEnumClassBit::BIT_ONE));
  EXPECT_FALSE(mask.IsSet(TestEnumClassBit::BIT_TWO));
}

TEST(QuicBitMaskTest, Enum) {
  BitMask<TestEnumBit> mask({TEST_BIT_1, TEST_BIT_2});
  EXPECT_FALSE(mask.IsSet(TEST_BIT_0));
  EXPECT_TRUE(mask.IsSet(TEST_BIT_1));
  EXPECT_TRUE(mask.IsSet(TEST_BIT_2));

  mask.ClearAll();
  EXPECT_FALSE(mask.IsSet(TEST_BIT_0));
  EXPECT_FALSE(mask.IsSet(TEST_BIT_1));
  EXPECT_FALSE(mask.IsSet(TEST_BIT_2));
}

TEST(QuicBitMaskTest, Integer) {
  BitMask<int> mask({1, 3});
  EXPECT_EQ(mask.Max(), 3);
  mask.Set(3);
  mask.Set({5, 7, 9});
  EXPECT_EQ(mask.Max(), 9);
  EXPECT_FALSE(mask.IsSet(0));
  EXPECT_TRUE(mask.IsSet(1));
  EXPECT_FALSE(mask.IsSet(2));
  EXPECT_TRUE(mask.IsSet(3));
  EXPECT_FALSE(mask.IsSet(4));
  EXPECT_TRUE(mask.IsSet(5));
  EXPECT_FALSE(mask.IsSet(6));
  EXPECT_TRUE(mask.IsSet(7));
  EXPECT_FALSE(mask.IsSet(8));
  EXPECT_TRUE(mask.IsSet(9));
}

TEST(QuicBitMaskTest, NumBits) {
  EXPECT_EQ(64u, BitMask<int>::NumBits());
  EXPECT_EQ(32u, (BitMask<int, uint32_t>::NumBits()));
}

TEST(QuicBitMaskTest, Constructor) {
  BitMask<int> empty_mask;
  for (size_t bit = 0; bit < empty_mask.NumBits(); ++bit) {
    EXPECT_FALSE(empty_mask.IsSet(bit));
  }

  BitMask<int> mask({1, 3});
  BitMask<int> mask2 = mask;
  BitMask<int> mask3(mask2);

  for (size_t bit = 0; bit < mask.NumBits(); ++bit) {
    EXPECT_EQ(mask.IsSet(bit), mask2.IsSet(bit));
    EXPECT_EQ(mask.IsSet(bit), mask3.IsSet(bit));
  }

  EXPECT_TRUE(std::is_trivially_copyable<BitMask<int>>::value);
}

TEST(QuicBitMaskTest, Any) {
  BitMask<int> mask;
  EXPECT_FALSE(mask.Any());
  mask.Set(3);
  EXPECT_TRUE(mask.Any());
  mask.Set(2);
  EXPECT_TRUE(mask.Any());
  mask.ClearAll();
  EXPECT_FALSE(mask.Any());
}

TEST(QuicBitMaskTest, And) {
  using Mask = BitMask<int>;
  EXPECT_EQ(Mask({1, 3, 6}) & Mask({3, 5, 6}), Mask({3, 6}));
  EXPECT_EQ(Mask({1, 2, 4}) & Mask({3, 5}), Mask({}));
  EXPECT_EQ(Mask({1, 2, 3, 4, 5}) & Mask({}), Mask({}));
}

}  // namespace
}  // namespace test
}  // namespace quic
```
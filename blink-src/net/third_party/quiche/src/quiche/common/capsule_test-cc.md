Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The core request is to understand the functionality of the C++ file `capsule_test.cc`, its relation to JavaScript (if any), infer inputs/outputs, identify common user errors, and trace the path to this code.

2. **High-Level Overview:** First, I'd look at the file path and the `#include` statements. `net/third_party/quiche/src/quiche/common/capsule_test.cc` tells us it's a test file for something related to "capsules" within the Quiche library (a QUIC implementation). The includes like `<string>`, `<vector>`, `"quiche/common/capsule.h"`, and `"quiche/web_transport/web_transport.h"` give immediate clues about the core functionality. It likely involves serializing, deserializing, and managing "capsules" of data, potentially related to WebTransport.

3. **Identify Key Components:**  I'd scan the code for important classes and functions:
    * `CapsuleParser`: This is central. It seems to be responsible for taking raw byte streams and parsing them into `Capsule` objects.
    * `Capsule`: This likely represents the fundamental unit of data being handled.
    * `MockCapsuleParserVisitor`: This is a test utility (indicated by "Mock"). It's used to observe the behavior of the `CapsuleParser`. The `OnCapsule` and `OnCapsuleParseFailure` methods are particularly important for understanding how the parser reports its results.
    * `CapsuleTest`: This is the main test fixture, containing individual test cases.
    * `SerializeCapsule`, `SerializeDatagramCapsuleHeader`, etc.: These functions suggest the process of converting `Capsule` objects back into byte streams.

4. **Analyze Individual Tests:** The `TEST_F` macros define individual test cases. Reading through the names and the code within each test case is crucial:
    * **Positive Tests (e.g., `DatagramCapsule`, `CloseWebTransportStreamCapsule`):** These tests demonstrate the successful parsing and serialization of different capsule types. They often involve:
        * Creating a byte string (`capsule_fragment`) representing the serialized capsule.
        * Creating an expected `Capsule` object.
        * Using the `CapsuleParser` to ingest the byte string.
        * Using the `MockCapsuleParserVisitor` to verify that the expected `Capsule` was parsed.
        * Using `TestSerialization` to verify that the `Capsule` can be correctly serialized back into the original byte string.
    * **Negative Tests (e.g., `PartialCapsuleThenError`, `RejectOverlyLongCapsule`):** These tests verify error handling. They check that the parser correctly identifies invalid or incomplete capsule data.

5. **Look for JavaScript Connections:** The prompt specifically asks about JavaScript. I would search for any terms or concepts related to web browsers or client-side scripting. The inclusion of `"quiche/web_transport/web_transport.h"` is a strong indicator. WebTransport is a browser technology, which strongly suggests a link to JavaScript (as it's used in browser contexts). I would note that while the *test code itself* is C++, the *functionality being tested* is used in a context where it interacts with JavaScript.

6. **Infer Inputs and Outputs:**  Based on the tests, I can infer the inputs and outputs of the `CapsuleParser`:
    * **Input:** A stream of bytes (represented as `absl::string_view` or `std::string`).
    * **Output (Success):**  Calls to the `OnCapsule` method of the `CapsuleParser::Visitor`, with a parsed `Capsule` object as the argument.
    * **Output (Failure):** Calls to the `OnCapsuleParseFailure` method of the `CapsuleParser::Visitor`, with an error message.

7. **Identify Potential User Errors:** The negative tests provide direct examples of user errors:
    * Sending incomplete capsules.
    * Sending overly long capsules.

8. **Trace User Operations (Debugging):**  To understand how a user's actions might lead to this code, I would consider the context:
    * **Web Browser:**  The most likely scenario is a web browser using WebTransport to communicate with a server.
    * **Network Communication:** The capsules are being transmitted over a network.
    * **JavaScript API:**  JavaScript code in the browser uses the WebTransport API to send and receive data. This data is likely formatted into these "capsules" at a lower level.

9. **Structure the Response:** Finally, I would organize the findings into the requested sections: functionality, JavaScript relation, input/output, common errors, and debugging. I'd use clear and concise language, referencing specific parts of the code where possible. I would also try to provide concrete examples to illustrate the concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This might be purely low-level network stuff with no JavaScript."
* **Correction:** "Ah, but the `web_transport` includes strongly suggest browser interaction. The C++ code is likely handling the low-level parsing of data that originated from a JavaScript WebTransport API call."
* **Initial thought:** "Just describe what each test does."
* **Refinement:** "Focus on the *purpose* of the tests. Are they testing successful parsing, error handling, or serialization?"
* **Initial thought:** "Just list the possible errors."
* **Refinement:** "Frame the errors in terms of what a *user* or a *programmer* might do incorrectly when working with WebTransport or the underlying network protocols."

By following this thought process, systematically analyzing the code, and focusing on the key elements and their interactions, I can construct a comprehensive and accurate explanation of the `capsule_test.cc` file.
这个文件 `net/third_party/quiche/src/quiche/common/capsule_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它主要用于测试 `quiche/common/capsule.h` 中定义的 **Capsule** 相关的类和功能。Capsule 可以被认为是 WebTransport 协议中用于封装不同类型数据的基本单元。

以下是该文件的功能详细列表：

**主要功能:**

1. **测试 Capsule 的序列化和反序列化:**
   - 该文件包含了针对不同类型 Capsule 的单元测试，例如 `DatagramCapsule`, `CloseWebTransportStreamCapsule`, `AddressAssignCapsule` 等。
   - 每个测试用例都定义了一个预期的 Capsule 结构和对应的二进制表示 (通过十六进制字符串表示)。
   - 测试会使用 `SerializeCapsule` 函数将 Capsule 对象序列化成二进制数据，并与预期的二进制数据进行比较，确保序列化是正确的。
   - 同时，测试也会使用 `CapsuleParser` 类将二进制数据反序列化成 Capsule 对象，并验证反序列化后的 Capsule 对象与预期一致。

2. **测试 CapsuleParser 的解析功能:**
   - `CapsuleParser` 类负责从字节流中解析出一个或多个 Capsule。
   - 测试用例会模拟接收到包含完整或部分 Capsule 的字节流，并使用 `IngestCapsuleFragment` 方法喂给 `CapsuleParser`。
   - 通过 `MockCapsuleParserVisitor` 模拟 CapsuleParser 的回调，验证解析出的 Capsule 类型和内容是否正确。
   - 测试了处理多个 Capsule 的情况，以及分段接收 Capsule 数据的情况。

3. **覆盖各种类型的 Capsule:**
   - 文件中包含了针对 WebTransport 协议定义的各种 Capsule 类型的测试，例如：
     - `DATAGRAM`: 用于传输 HTTP Datagram 数据。
     - `CLOSE_WEBTRANSPORT_STREAM`: 用于关闭 WebTransport 流。
     - `DRAIN_WEBTRANSPORT_STREAM`: 用于通知对端停止发送数据。
     - `ADDRESS_ASSIGN`, `ADDRESS_REQUEST`, `ROUTE_ADVERTISEMENT`:  用于支持 IP 地址分配和路由宣告 (可能用于未来扩展或特定网络环境)。
     - `WT_STREAM`: 用于传输 WebTransport 流的数据。
     - `WT_RESET_STREAM`, `WT_STOP_SENDING`, `WT_MAX_STREAM_DATA`, `WT_MAX_STREAMS`: 用于控制 WebTransport 流的行为。
     - `LEGACY_DATAGRAM`, `LEGACY_DATAGRAM_WITHOUT_CONTEXT`:  可能用于向后兼容旧版本的 Datagram 格式。
     - `Unknown`: 用于处理无法识别的 Capsule 类型。

4. **测试错误处理:**
   - 测试用例 `PartialCapsuleThenError` 验证了当接收到不完整的 Capsule 数据时，`CapsuleParser` 能否正确地检测并报告错误。
   - 测试用例 `RejectOverlyLongCapsule` 验证了 `CapsuleParser` 能否拒绝解析长度过长的 Capsule，防止潜在的缓冲区溢出或其他安全问题。

**与 Javascript 的关系 (举例说明):**

虽然这个 C++ 文件本身不包含任何 Javascript 代码，但它测试的功能直接关系到 WebTransport 协议在浏览器中的实现，而 WebTransport 是可以通过 Javascript API 访问的。

**举例说明:**

假设一个使用 Javascript WebTransport API 的网页应用需要发送一些数据到服务器。

**假设输入 (Javascript 代码):**

```javascript
const transport = new WebTransport("https://example.com");
await transport.ready;

const stream = await transport.createUnidirectionalStream();
const writer = stream.writable.getWriter();
const data = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
await writer.write(data);
await writer.close();
```

**逻辑推理 (C++ 代码中的处理):**

1. 当上述 Javascript 代码调用 `writer.write(data)` 时，浏览器底层会将 `data` 封装成一个 WebTransport 消息。对于小数据量，可能会直接封装成 `DATAGRAM` 类型的 Capsule。对于通过流发送的数据，会被封装成 `WT_STREAM` 类型的 Capsule。

2. `net/third_party/quiche/src/quiche/common/capsule_test.cc` 中的 `WebTransportStreamData` 测试用例就模拟了接收到一个 `WT_STREAM` 类型的 Capsule 的场景。

3. **假设输入 (对应 C++ 测试用例的十六进制表示):**

   ```
   990b4d3b  // WT_STREAM without FIN 的 capsule type
   04        // capsule length (4 字节 payload)
   17        // stream ID (假设为 0x17)
   abcdef    // stream payload (十六进制表示的 [0xab, 0xcd, 0xef])
   ```

4. **输出 (C++ 代码中的解析结果):**

   - `CapsuleParser` 会将上述字节流解析成一个 `Capsule` 对象。
   - `visitor_.OnCapsule` 方法会被调用，传入解析出的 `Capsule` 对象。
   - 该 `Capsule` 对象的类型为 `WebTransportStreamDataCapsule`。
   - `capsule.web_transport_stream_data().stream_id` 的值为 `0x17`。
   - `capsule.web_transport_stream_data().data` 的值为 `"\xab\xcd\xef"`。
   - `capsule.web_transport_stream_data().fin` 的值为 `false` (因为 capsule type 是 `990b4d3b`)。

**用户或编程常见的使用错误 (举例说明):**

1. **发送不完整的 Capsule 数据:**
   - **错误场景:**  网络传输过程中，由于丢包或其他原因，导致 Capsule 的部分数据丢失。
   - **C++ 代码中的测试:** `TEST_F(CapsuleTest, PartialCapsuleThenError)` 模拟了这种情况。
   - **假设输入:**  只发送了 Capsule 的头部和部分 payload：`0008a1a2a3a4` (DATAGRAM 类型，长度 8，但只发送了 4 字节 payload)。
   - **预期输出:**  `capsule_parser_.ErrorIfThereIsRemainingBufferedData()` 会调用 `visitor_.OnCapsuleParseFailure` 并收到错误消息 "Incomplete capsule left at the end of the stream"。

2. **发送长度字段与实际数据不符的 Capsule:**
   - **错误场景:**  程序错误导致 Capsule 的长度字段计算错误。
   - **C++ 代码中没有直接测试这种情况，但 `CapsuleParser` 的实现应该能检测到。**
   - **假设输入:**  `0005a1a2a3a4a5a6` (DATAGRAM 类型，长度声明为 5，但后面有 6 字节数据)。
   - **预期行为:**  `CapsuleParser` 在尝试读取指定长度的数据时可能会遇到问题，并可能触发 `OnCapsuleParseFailure`。 具体错误信息取决于 `CapsuleParser` 的实现细节。

3. **发送过长的 Capsule:**
   - **错误场景:**  恶意攻击或者程序错误导致尝试发送远超协议限制的 Capsule。
   - **C++ 代码中的测试:** `TEST_F(CapsuleTest, RejectOverlyLongCapsule)` 模拟了这种情况。
   - **假设输入:**  `1780123456...` (Unknown 类型，长度字段 `80123456` 表示一个非常大的值)。
   - **预期输出:**  `capsule_parser_.IngestCapsuleFragment` 返回 `false`，并且 `visitor_.OnCapsuleParseFailure` 会收到错误消息 "Refusing to buffer too much capsule data"。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问了一个启用了 WebTransport 的网站。**
2. **网站的 Javascript 代码使用 WebTransport API 创建了一个连接，并尝试发送或接收数据。**
   - 例如，调用 `transport.createUnidirectionalStream()` 或 `transport.send()`。
3. **浏览器底层的网络栈会将 Javascript API 的调用转换为 WebTransport 协议的消息，这些消息会被封装成 Capsule。**
4. **当接收到来自网络的数据时，浏览器的网络栈会尝试解析这些 Capsule。**
5. **`quiche/common/capsule.cc` 中的 `CapsuleParser` 类会被调用，负责解析接收到的字节流。**
6. **如果解析过程中出现错误 (例如，接收到不完整的 Capsule)，则可能会触发 `capsule_test.cc` 中测试的错误处理逻辑。**

**调试线索:**

- **网络抓包:** 使用 Wireshark 或 Chrome 的 DevTools 可以捕获网络数据包，查看实际发送和接收的 Capsule 的二进制内容，与测试用例中的预期数据进行对比。
- **WebTransport API 事件:** 检查 Javascript 代码中 WebTransport 连接的 `connectionstatechange` 和 `incomingdatagrams` / `incomingunidirectionstreams` 事件，看是否有错误发生。
- **Chrome 内部日志:**  Chromium 有内部日志系统，可以查看更底层的网络事件和错误信息。
- **断点调试:** 如果怀疑 Capsule 解析有问题，可以在 `quiche/common/capsule.cc` 和相关的代码中设置断点，逐步跟踪代码执行流程，查看 `CapsuleParser` 的状态和解析过程。

总而言之，`net/third_party/quiche/src/quiche/common/capsule_test.cc` 是一个非常重要的测试文件，它确保了 WebTransport 协议中 Capsule 的正确序列化、反序列化和解析，这对于 WebTransport 功能的稳定性和可靠性至关重要，并且直接关系到使用 Javascript WebTransport API 的开发者。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/capsule_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/capsule.h"

#include <cstddef>
#include <deque>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_ip_address.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/web_transport.h"

using ::testing::_;
using ::testing::InSequence;
using ::testing::Return;
using ::webtransport::StreamType;

namespace quiche {
namespace test {

class CapsuleParserPeer {
 public:
  static std::string* buffered_data(CapsuleParser* capsule_parser) {
    return &capsule_parser->buffered_data_;
  }
};

namespace {

class MockCapsuleParserVisitor : public CapsuleParser::Visitor {
 public:
  MockCapsuleParserVisitor() {
    ON_CALL(*this, OnCapsule(_)).WillByDefault(Return(true));
  }
  ~MockCapsuleParserVisitor() override = default;
  MOCK_METHOD(bool, OnCapsule, (const Capsule& capsule), (override));
  MOCK_METHOD(void, OnCapsuleParseFailure, (absl::string_view error_message),
              (override));
};

class CapsuleTest : public QuicheTest {
 public:
  CapsuleTest() : capsule_parser_(&visitor_) {}

  void ValidateParserIsEmpty() {
    EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
    EXPECT_CALL(visitor_, OnCapsuleParseFailure(_)).Times(0);
    capsule_parser_.ErrorIfThereIsRemainingBufferedData();
    EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
  }

  void TestSerialization(const Capsule& capsule,
                         const std::string& expected_bytes) {
    quiche::QuicheBuffer serialized_capsule =
        SerializeCapsule(capsule, SimpleBufferAllocator::Get());
    quiche::test::CompareCharArraysWithHexError(
        "Serialized capsule", serialized_capsule.data(),
        serialized_capsule.size(), expected_bytes.data(),
        expected_bytes.size());
  }

  ::testing::StrictMock<MockCapsuleParserVisitor> visitor_;
  CapsuleParser capsule_parser_;
};

TEST_F(CapsuleTest, DatagramCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"                 // DATAGRAM capsule type
                             "08"                 // capsule length
                             "a1a2a3a4a5a6a7a8",  // HTTP Datagram payload
                             &capsule_fragment));
  std::string datagram_payload;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload));
  Capsule expected_capsule = Capsule::Datagram(datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, DatagramCapsuleViaHeader) {
  std::string datagram_payload;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload));
  quiche::QuicheBuffer expected_capsule = SerializeCapsule(
      Capsule::Datagram(datagram_payload), SimpleBufferAllocator::Get());
  quiche::QuicheBuffer actual_header = SerializeDatagramCapsuleHeader(
      datagram_payload.size(), SimpleBufferAllocator::Get());
  EXPECT_EQ(expected_capsule.AsStringView(),
            absl::StrCat(actual_header.AsStringView(), datagram_payload));
}

TEST_F(CapsuleTest, LegacyDatagramCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("80ff37a0"  // LEGACY_DATAGRAM capsule type
                             "08"        // capsule length
                             "a1a2a3a4a5a6a7a8",  // HTTP Datagram payload
                             &capsule_fragment));
  std::string datagram_payload;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload));
  Capsule expected_capsule = Capsule::LegacyDatagram(datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, LegacyDatagramWithoutContextCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(absl::HexStringToBytes(
      "80ff37a5"           // LEGACY_DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"                 // capsule length
      "a1a2a3a4a5a6a7a8",  // HTTP Datagram payload
      &capsule_fragment));
  std::string datagram_payload;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload));
  Capsule expected_capsule =
      Capsule::LegacyDatagramWithoutContext(datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, CloseWebTransportStreamCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("6843"  // CLOSE_WEBTRANSPORT_STREAM capsule type
                             "09"    // capsule length
                             "00001234"     // 0x1234 error code
                             "68656c6c6f",  // "hello" error message
                             &capsule_fragment));
  Capsule expected_capsule = Capsule::CloseWebTransportSession(
      /*error_code=*/0x1234, /*error_message=*/"hello");
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, DrainWebTransportStreamCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(absl::HexStringToBytes(
      "800078ae"  // DRAIN_WEBTRANSPORT_STREAM capsule type
      "00",       // capsule length
      &capsule_fragment));
  Capsule expected_capsule = Capsule(DrainWebTransportSessionCapsule());
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, AddressAssignCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(absl::HexStringToBytes(
      "9ECA6A00"  // ADDRESS_ASSIGN capsule type
      "1A"        // capsule length = 26
      // first assigned address
      "00"        // request ID = 0
      "04"        // IP version = 4
      "C000022A"  // 192.0.2.42
      "1F"        // prefix length = 31
      // second assigned address
      "01"                                // request ID = 1
      "06"                                // IP version = 6
      "20010db8123456780000000000000000"  // 2001:db8:1234:5678::
      "40",                               // prefix length = 64
      &capsule_fragment));
  Capsule expected_capsule = Capsule::AddressAssign();
  quiche::QuicheIpAddress ip_address1;
  ip_address1.FromString("192.0.2.42");
  PrefixWithId assigned_address1;
  assigned_address1.request_id = 0;
  assigned_address1.ip_prefix =
      quiche::QuicheIpPrefix(ip_address1, /*prefix_length=*/31);
  expected_capsule.address_assign_capsule().assigned_addresses.push_back(
      assigned_address1);
  quiche::QuicheIpAddress ip_address2;
  ip_address2.FromString("2001:db8:1234:5678::");
  PrefixWithId assigned_address2;
  assigned_address2.request_id = 1;
  assigned_address2.ip_prefix =
      quiche::QuicheIpPrefix(ip_address2, /*prefix_length=*/64);
  expected_capsule.address_assign_capsule().assigned_addresses.push_back(
      assigned_address2);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, AddressRequestCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(absl::HexStringToBytes(
      "9ECA6A01"  // ADDRESS_REQUEST capsule type
      "1A"        // capsule length = 26
      // first requested address
      "00"        // request ID = 0
      "04"        // IP version = 4
      "C000022A"  // 192.0.2.42
      "1F"        // prefix length = 31
      // second requested address
      "01"                                // request ID = 1
      "06"                                // IP version = 6
      "20010db8123456780000000000000000"  // 2001:db8:1234:5678::
      "40",                               // prefix length = 64
      &capsule_fragment));
  Capsule expected_capsule = Capsule::AddressRequest();
  quiche::QuicheIpAddress ip_address1;
  ip_address1.FromString("192.0.2.42");
  PrefixWithId requested_address1;
  requested_address1.request_id = 0;
  requested_address1.ip_prefix =
      quiche::QuicheIpPrefix(ip_address1, /*prefix_length=*/31);
  expected_capsule.address_request_capsule().requested_addresses.push_back(
      requested_address1);
  quiche::QuicheIpAddress ip_address2;
  ip_address2.FromString("2001:db8:1234:5678::");
  PrefixWithId requested_address2;
  requested_address2.request_id = 1;
  requested_address2.ip_prefix =
      quiche::QuicheIpPrefix(ip_address2, /*prefix_length=*/64);
  expected_capsule.address_request_capsule().requested_addresses.push_back(
      requested_address2);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, RouteAdvertisementCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(absl::HexStringToBytes(
      "9ECA6A02"  // ROUTE_ADVERTISEMENT capsule type
      "2C"        // capsule length = 44
      // first IP address range
      "04"        // IP version = 4
      "C0000218"  // 192.0.2.24
      "C000022A"  // 192.0.2.42
      "00"        // ip protocol = 0
      // second IP address range
      "06"                                // IP version = 6
      "00000000000000000000000000000000"  // ::
      "ffffffffffffffffffffffffffffffff"  // all ones IPv6 address
      "01",                               // ip protocol = 1 (ICMP)
      &capsule_fragment));
  Capsule expected_capsule = Capsule::RouteAdvertisement();
  IpAddressRange ip_address_range1;
  ip_address_range1.start_ip_address.FromString("192.0.2.24");
  ip_address_range1.end_ip_address.FromString("192.0.2.42");
  ip_address_range1.ip_protocol = 0;
  expected_capsule.route_advertisement_capsule().ip_address_ranges.push_back(
      ip_address_range1);
  IpAddressRange ip_address_range2;
  ip_address_range2.start_ip_address.FromString("::");
  ip_address_range2.end_ip_address.FromString(
      "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
  ip_address_range2.ip_protocol = 1;
  expected_capsule.route_advertisement_capsule().ip_address_ranges.push_back(
      ip_address_range2);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, WebTransportStreamData) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d3b"  // WT_STREAM without FIN
                             "04"        // capsule length
                             "17"        // stream ID
                             "abcdef",   // stream payload
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportStreamDataCapsule());
  expected_capsule.web_transport_stream_data().stream_id = 0x17;
  expected_capsule.web_transport_stream_data().data = "\xab\xcd\xef";
  expected_capsule.web_transport_stream_data().fin = false;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}
TEST_F(CapsuleTest, WebTransportStreamDataHeader) {
  std::string capsule_fragment;
  ASSERT_TRUE(absl::HexStringToBytes(
      "990b4d3b"  // WT_STREAM without FIN
      "04"        // capsule length
      "17",       // stream ID
                  // three bytes of stream payload implied below
      &capsule_fragment));
  QuicheBufferAllocator* allocator = SimpleBufferAllocator::Get();
  QuicheBuffer capsule_header =
      quiche::SerializeWebTransportStreamCapsuleHeader(0x17, /*fin=*/false, 3,
                                                       allocator);
  EXPECT_EQ(capsule_header.AsStringView(), capsule_fragment);
}
TEST_F(CapsuleTest, WebTransportStreamDataWithFin) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d3c"  // data with FIN
                             "04"        // capsule length
                             "17"        // stream ID
                             "abcdef",   // stream payload
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportStreamDataCapsule());
  expected_capsule.web_transport_stream_data().stream_id = 0x17;
  expected_capsule.web_transport_stream_data().data = "\xab\xcd\xef";
  expected_capsule.web_transport_stream_data().fin = true;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, WebTransportResetStream) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d39"  // WT_RESET_STREAM
                             "02"        // capsule length
                             "17"        // stream ID
                             "07",       // error code
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportResetStreamCapsule());
  expected_capsule.web_transport_reset_stream().stream_id = 0x17;
  expected_capsule.web_transport_reset_stream().error_code = 0x07;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, WebTransportStopSending) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d3a"  // WT_STOP_SENDING
                             "02"        // capsule length
                             "17"        // stream ID
                             "07",       // error code
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportStopSendingCapsule());
  expected_capsule.web_transport_stop_sending().stream_id = 0x17;
  expected_capsule.web_transport_stop_sending().error_code = 0x07;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, WebTransportMaxStreamData) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d3e"  // WT_MAX_STREAM_DATA
                             "02"        // capsule length
                             "17"        // stream ID
                             "10",       // max stream data
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportMaxStreamDataCapsule());
  expected_capsule.web_transport_max_stream_data().stream_id = 0x17;
  expected_capsule.web_transport_max_stream_data().max_stream_data = 0x10;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, WebTransportMaxStreamsBi) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d3f"  // WT_MAX_STREAMS (bidi)
                             "01"        // capsule length
                             "17",       // max streams
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportMaxStreamsCapsule());
  expected_capsule.web_transport_max_streams().stream_type =
      StreamType::kBidirectional;
  expected_capsule.web_transport_max_streams().max_stream_count = 0x17;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, WebTransportMaxStreamsUni) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("990b4d40"  // WT_MAX_STREAMS (unidi)
                             "01"        // capsule length
                             "17",       // max streams
                             &capsule_fragment));
  Capsule expected_capsule = Capsule(WebTransportMaxStreamsCapsule());
  expected_capsule.web_transport_max_streams().stream_type =
      StreamType::kUnidirectional;
  expected_capsule.web_transport_max_streams().max_stream_count = 0x17;
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, UnknownCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("17"  // unknown capsule type of 0x17
                             "08"  // capsule length
                             "a1a2a3a4a5a6a7a8",  // unknown capsule data
                             &capsule_fragment));
  std::string unknown_capsule_data;
  ASSERT_TRUE(
      absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &unknown_capsule_data));
  Capsule expected_capsule = Capsule::Unknown(0x17, unknown_capsule_data);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, TwoCapsules) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"                 // DATAGRAM capsule type
                             "08"                 // capsule length
                             "a1a2a3a4a5a6a7a8"   // HTTP Datagram payload
                             "00"                 // DATAGRAM capsule type
                             "08"                 // capsule length
                             "b1b2b3b4b5b6b7b8",  // HTTP Datagram payload
                             &capsule_fragment));
  std::string datagram_payload1;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload1));
  std::string datagram_payload2;
  ASSERT_TRUE(absl::HexStringToBytes("b1b2b3b4b5b6b7b8", &datagram_payload2));
  Capsule expected_capsule1 = Capsule::Datagram(datagram_payload1);
  Capsule expected_capsule2 = Capsule::Datagram(datagram_payload2);
  {
    InSequence s;
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule1));
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule2));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
}

TEST_F(CapsuleTest, TwoCapsulesPartialReads) {
  std::string capsule_fragment1;
  ASSERT_TRUE(absl::HexStringToBytes(
      "00"         // first capsule DATAGRAM capsule type
      "08"         // first capsule length
      "a1a2a3a4",  // first half of HTTP Datagram payload of first capsule
      &capsule_fragment1));
  std::string capsule_fragment2;
  ASSERT_TRUE(absl::HexStringToBytes(
      "a5a6a7a8"  // second half of HTTP Datagram payload 1
      "00",       // second capsule DATAGRAM capsule type
      &capsule_fragment2));
  std::string capsule_fragment3;
  ASSERT_TRUE(absl::HexStringToBytes(
      "08"                 // second capsule length
      "b1b2b3b4b5b6b7b8",  // HTTP Datagram payload of second capsule
      &capsule_fragment3));
  capsule_parser_.ErrorIfThereIsRemainingBufferedData();
  std::string datagram_payload1;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload1));
  std::string datagram_payload2;
  ASSERT_TRUE(absl::HexStringToBytes("b1b2b3b4b5b6b7b8", &datagram_payload2));
  Capsule expected_capsule1 = Capsule::Datagram(datagram_payload1);
  Capsule expected_capsule2 = Capsule::Datagram(datagram_payload2);
  {
    InSequence s;
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule1));
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule2));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment1));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment2));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment3));
  }
  ValidateParserIsEmpty();
}

TEST_F(CapsuleTest, TwoCapsulesOneByteAtATime) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"                 // DATAGRAM capsule type
                             "08"                 // capsule length
                             "a1a2a3a4a5a6a7a8"   // HTTP Datagram payload
                             "00"                 // DATAGRAM capsule type
                             "08"                 // capsule length
                             "b1b2b3b4b5b6b7b8",  // HTTP Datagram payload
                             &capsule_fragment));
  std::string datagram_payload1;
  ASSERT_TRUE(absl::HexStringToBytes("a1a2a3a4a5a6a7a8", &datagram_payload1));
  std::string datagram_payload2;
  ASSERT_TRUE(absl::HexStringToBytes("b1b2b3b4b5b6b7b8", &datagram_payload2));
  Capsule expected_capsule1 = Capsule::Datagram(datagram_payload1);
  Capsule expected_capsule2 = Capsule::Datagram(datagram_payload2);
  for (size_t i = 0; i < capsule_fragment.size(); i++) {
    if (i < capsule_fragment.size() / 2 - 1) {
      EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
    } else if (i == capsule_fragment.size() / 2 - 1) {
      EXPECT_CALL(visitor_, OnCapsule(expected_capsule1));
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
      EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
    } else if (i < capsule_fragment.size() - 1) {
      EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
    } else {
      EXPECT_CALL(visitor_, OnCapsule(expected_capsule2));
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
      EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
    }
  }
  capsule_parser_.ErrorIfThereIsRemainingBufferedData();
  EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
}

TEST_F(CapsuleTest, PartialCapsuleThenError) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"         // DATAGRAM capsule type
                             "08"         // capsule length
                             "a1a2a3a4",  // first half of HTTP Datagram payload
                             &capsule_fragment));
  EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
  {
    EXPECT_CALL(visitor_, OnCapsuleParseFailure(_)).Times(0);
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  {
    EXPECT_CALL(visitor_,
                OnCapsuleParseFailure(
                    "Incomplete capsule left at the end of the stream"));
    capsule_parser_.ErrorIfThereIsRemainingBufferedData();
  }
}

TEST_F(CapsuleTest, RejectOverlyLongCapsule) {
  std::string capsule_fragment;
  ASSERT_TRUE(
      absl::HexStringToBytes("17"         // unknown capsule type of 0x17
                             "80123456",  // capsule length
                             &capsule_fragment));
  absl::StrAppend(&capsule_fragment, std::string(1111111, '?'));
  EXPECT_CALL(visitor_, OnCapsuleParseFailure(
                            "Refusing to buffer too much capsule data"));
  EXPECT_FALSE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
}

}  // namespace
}  // namespace test
}  // namespace quiche

"""

```
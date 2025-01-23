Response:
Let's break down the thought process for analyzing the C++ test file and generating the comprehensive explanation.

1. **Understand the Goal:** The request asks for the functionality of a specific Chromium network stack test file (`quic_stream_id_manager_test.cc`). It also asks for connections to JavaScript, logical reasoning examples, common user errors, and debugging guidance.

2. **Identify the Core Component:** The filename immediately points to the component being tested: `QuicStreamIdManager`. The presence of `_test.cc` confirms it's a test file.

3. **Examine the Includes:**  The included headers provide crucial context:
    * `quiche/quic/core/quic_stream_id_manager.h`:  This is the header for the class being tested. It tells us the file is about managing QUIC stream IDs.
    * Standard C++ headers (`cstdint`, `string`, `utility`, `vector`): Indicate general C++ usage.
    * `absl/strings/str_cat.h`: Used for string concatenation.
    * `quiche/quic/core/quic_constants.h`: Defines QUIC-related constants.
    * `quiche/quic/core/quic_utils.h`:  Provides utility functions for QUIC.
    * `quiche/quic/core/quic_versions.h`: Deals with QUIC versioning.
    * `quiche/quic/platform/api/...`:  Platform-specific testing utilities.
    * `quiche/quic/test_tools/quic_stream_id_manager_peer.h`:  Likely provides access to internal members of `QuicStreamIdManager` for testing purposes.
    * `testing/...`:  Google Test framework headers.

4. **Analyze the Test Structure:**
    * **`MockDelegate`:**  A mock object using Google Mock. This tells us that `QuicStreamIdManager` has a delegate interface (`QuicStreamIdManager::DelegateInterface`) and that the tests will verify interactions with this delegate. The mock methods `SendMaxStreams` and `CanSendMaxStreams` suggest the manager deals with controlling the number of streams.
    * **`TestParams` struct:**  This struct and the `GetTestParams()` function indicate parameterized testing. The tests are run with different QUIC versions, perspectives (client/server), and stream directionality (unidirectional/bidirectional). This emphasizes the importance of testing different configurations.
    * **`QuicStreamIdManagerTest` class:** This is the main test fixture. It inherits from `QuicTestWithParam`, using the `TestParams`. The constructor initializes a `QuicStreamIdManager` instance.
    * **Helper functions:** `GetNthIncomingStreamId`, `IsUnidirectional`, `perspective` simplify test setup and make the tests more readable.
    * **`INSTANTIATE_TEST_SUITE_P`:**  Connects the test fixture with the parameter generator.
    * **Individual `TEST_P` macros:**  These are the actual test cases. Reading the names of the tests gives a good overview of the functionality being tested (e.g., "Initialization", "CheckMaxStreamsWindowForSingleStream", "ProcessStreamsBlockedOk", etc.).

5. **Infer Functionality from Test Names and Code:** By reading the test names and the code within each test, we can deduce the functionalities being verified:
    * **Initialization:**  Checks initial values.
    * **Max Streams Handling:** Tests setting, limiting, and advertising maximum stream counts. Looks at both outgoing (initiated by the manager) and incoming (initiated by the peer) streams.
    * **STREAMS_BLOCKED Frame Processing:** Tests how the manager reacts to `STREAMS_BLOCKED` frames from the peer, including scenarios where the advertised limit is correct, too high, or too low.
    * **Incoming Stream ID Validation:** Verifies that the manager correctly accepts or rejects incoming stream IDs based on the current limits.
    * **Outgoing Stream Allocation:** Tests the allocation of new outgoing stream IDs.
    * **MAX_STREAMS Frame Generation:** Checks when the manager sends `MAX_STREAMS` frames to inform the peer about increased limits. This includes testing the "sliding window" mechanism.
    * **Stopping Limit Increases:** Tests the `StopIncreasingIncomingMaxStreams()` functionality.
    * **Edge Cases:**  Tests specific scenarios like `STREAMS_BLOCKED` with a count of 0.
    * **Availability of Streams:** Checks if the manager correctly tracks available stream IDs.
    * **Handling Extreme Stream IDs:** Verifies robustness against excessively large stream IDs.

6. **Identify Potential JavaScript Connections (and their limitations):**  The core of this code is about network protocol details. Direct interaction with JavaScript is unlikely. However, we can make connections based on where this code *might* be used:
    * **Chromium Browser:** The network stack is part of the browser. JavaScript running in a web page could indirectly trigger the creation of QUIC connections and streams, leading to this code being executed. The `fetch` API or WebSockets (over QUIC) are examples.
    * **Node.js (with QUIC support):**  Node.js could also use a similar QUIC implementation, and JavaScript code in Node.js could directly interact with QUIC streams.

7. **Construct Logical Reasoning Examples:**  Choose a few test cases and illustrate the input, the logic within the `QuicStreamIdManager`, and the expected output. Focus on clear and simple examples like processing `STREAMS_BLOCKED` frames.

8. **Identify Common User/Programming Errors:** Think about how someone using or interacting with a system like this could make mistakes. Focus on misunderstandings related to stream limits and the consequences of exceeding them.

9. **Describe the User Journey for Debugging:**  Outline a simplified user action in a browser that would eventually lead to this code being involved. This helps understand the context and potential triggers.

10. **Review and Refine:**  Read through the entire explanation. Ensure it's clear, accurate, and addresses all parts of the original request. Check for consistent terminology and good organization. For example, initially, I might have just listed the test names, but then I'd refine it to explain what each test *verifies*. I would also make sure the JavaScript examples are reasonable and clearly state the indirect nature of the connection in most browser scenarios.
这个C++源代码文件 `quic_stream_id_manager_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicStreamIdManager` 类的功能。`QuicStreamIdManager` 的主要职责是管理 QUIC 连接中流 (stream) 的 ID 分配和限制。

以下是 `quic_stream_id_manager_test.cc` 的功能列表：

**主要功能：**

1. **测试 `QuicStreamIdManager` 的初始化:**
   - 验证 `QuicStreamIdManager` 在创建时是否正确设置了初始的流 ID 和最大流数量。
   - 测试不同 QUIC 版本和连接视角（客户端/服务端）下的初始化行为。

2. **测试设置最大打开流数量:**
   - 验证 `SetMaxOpenIncomingStreams` 方法是否能正确设置允许对方打开的最大流数量。
   - 测试设置不同值时，`incoming_actual_max_streams` 和 `incoming_advertised_max_streams` 是否更新正确。

3. **测试对 `STREAMS_BLOCKED` 帧的处理:**
   - 模拟接收到对端发送的 `STREAMS_BLOCKED` 帧，该帧表示对端因为流数量达到限制而无法创建新流。
   - 测试在不同情况下（`STREAMS_BLOCKED` 帧中的流数量小于、等于、大于本地通告的最大流数量）`QuicStreamIdManager` 的反应，包括是否发送 `MAX_STREAMS` 帧以增加流限制。

4. **测试验证接收到的流 ID 的有效性:**
   - 使用 `MaybeIncreaseLargestPeerStreamId` 方法测试接收到的流 ID 是否在允许的范围内。
   - 验证当接收到的流 ID 超出当前允许的最大流数量时，连接是否会被正确关闭，并生成相应的错误信息。

5. **测试分配新的 outgoing 流 ID:**
   - 验证 `MaybeAllowNewOutgoingStreams` 方法是否能正确设置允许本地创建的最大流数量。
   - 测试 `GetNextOutgoingStreamId` 方法是否能按预期分配新的流 ID。
   - 检查当尝试分配超出允许最大流数量的流 ID 时，是否会触发断言 (QUIC-BUG)。

6. **测试 MAX_STREAMS 帧的发送机制 (流控窗口):**
   - 测试当本地关闭一些流后，可用流数量增加到一定阈值时，`QuicStreamIdManager` 是否会自动发送 `MAX_STREAMS` 帧来通知对端可以创建更多流。
   - 测试 `CanSendMaxStreams` 委托方法的作用，模拟无法发送 `MAX_STREAMS` 帧的情况。

7. **测试停止增加接收流的最大数量:**
   - 验证 `StopIncreasingIncomingMaxStreams` 方法是否能阻止 `QuicStreamIdManager` 在流关闭后继续增加允许接收的最大流数量。

8. **测试流的可用性:**
   - 使用 `IsAvailableStream` 方法测试给定的流 ID 是否是可用的（未被使用且在允许的范围内）。

9. **测试处理极大的流 ID:**
   - 验证 `MaybeIncreaseLargestPeerStreamId` 方法是否能正确拒绝超出限制的极大流 ID，防止潜在的溢出或错误。

**与 JavaScript 的关系：**

`quic_stream_id_manager_test.cc` 本身是用 C++ 编写的测试代码，**与 JavaScript 没有直接的功能关系。**  然而，可以从以下间接层面理解它们的关系：

* **Chromium 浏览器:**  Chromium 浏览器使用了这个网络栈来实现 QUIC 协议。当 JavaScript 代码在网页中发起网络请求（例如使用 `fetch` API 或 WebSocket）时，如果底层使用了 QUIC 协议，那么 `QuicStreamIdManager` 就会参与到流的创建和管理过程中。
* **Node.js (可能):** 如果 Node.js 也使用了 Chromium 的 QUIC 实现或者类似的实现，那么运行在 Node.js 环境中的 JavaScript 代码也可能间接地与类似的流 ID 管理逻辑相关。

**举例说明：**

假设一个网页使用 `fetch` API 向服务器发起多个并发请求。

1. **用户操作:** 用户在浏览器中访问一个网页，该网页的 JavaScript 代码使用 `fetch` 发起 10 个并发的图片请求。
2. **底层 QUIC:** 浏览器与服务器建立了一个 QUIC 连接。
3. **`QuicStreamIdManager` 的作用:**  `QuicStreamIdManager` 负责为这 10 个并发的请求分配不同的 QUIC 流 ID。它会根据配置的最大并发流数量来管理这些流 ID 的分配，防止超出限制。
4. **测试验证:** `quic_stream_id_manager_test.cc` 中的测试用例会验证 `QuicStreamIdManager` 在这种场景下是否能正确分配和管理流 ID，例如：
   - 测试能否正确分配前 10 个流 ID。
   - 测试如果服务器发送 `STREAMS_BLOCKED` 帧表示无法接受更多流，`QuicStreamIdManager` 是否能正确处理。
   - 测试当某些请求完成后，`QuicStreamIdManager` 是否会根据情况发送 `MAX_STREAMS` 帧以允许创建更多流。

**逻辑推理的假设输入与输出：**

**场景：测试处理 `STREAMS_BLOCKED` 帧，且帧中的流数量小于本地通告的最大流数量。**

* **假设输入:**
    * `QuicStreamIdManager` 的 `incoming_advertised_max_streams` 为 100。
    * 接收到对端发送的 `QuicStreamsBlockedFrame`，其 `stream_count` 值为 90，`unidirectional` 为 false (双向流)。
    * 假设 `delegate_` (一个模拟对象) 的 `CanSendMaxStreams` 方法返回 true。
* **逻辑推理:**
    * 因为 `STREAMS_BLOCKED` 帧中的 `stream_count` (90) 小于 `incoming_advertised_max_streams` (100)，这意味着对端可能因为一些短暂的原因被阻塞，但本地的流限制仍然有效。
    * `QuicStreamIdManager` 会认为需要重新通告当前的最大流数量，因此会调用 `delegate_->SendMaxStreams(100, false)`。
* **预期输出:**
    * `delegate_->SendMaxStreams` 方法被调用，参数为 100 (当前的 advertised max streams) 和 false (表示双向流)。
    * `OnStreamsBlockedFrame` 方法返回 true，表示处理成功。

**涉及用户或编程常见的使用错误：**

1. **配置的最大流数量过小:**
   - **错误:** 开发者或系统管理员可能将 QUIC 连接的最大流数量配置得过低，导致在高并发场景下频繁触发 `STREAMS_BLOCKED` 帧，影响性能。
   - **调试线索:** 在服务器端或客户端日志中可能会看到频繁的 `STREAMS_BLOCKED` 帧的发送和接收。可以通过增加最大流数量的配置来解决。

2. **误解流 ID 的分配规则:**
   - **错误:** 开发者可能错误地假设流 ID 是连续分配的，或者对客户端和服务端分配流 ID 的奇偶性规则不清楚，导致在实现上出现错误。
   - **调试线索:**  在调试过程中，如果发现尝试使用不符合规则的流 ID，`QuicStreamIdManager` 的 `MaybeIncreaseLargestPeerStreamId` 方法会返回 false，并提供相应的错误信息。

3. **没有正确处理 `STREAMS_BLOCKED` 帧:**
   - **错误:** 在 QUIC 连接的实现中，如果一方收到 `STREAMS_BLOCKED` 帧后没有采取相应的措施（例如，等待一段时间后再尝试创建新流，或者通知上层应用），可能会导致连接阻塞。
   - **调试线索:**  观察网络包，看是否频繁出现 `STREAMS_BLOCKED` 帧，但却没有后续的 `MAX_STREAMS` 帧或者新的流创建尝试。

**用户操作是如何一步步的到达这里，作为调试线索：**

以下是一个用户操作如何最终触发 `QuicStreamIdManager` 相关代码的场景：

1. **用户在 Chrome 浏览器中访问一个使用 HTTPS 的网站。**
2. **浏览器尝试与网站服务器建立连接。**
3. **如果浏览器和服务器都支持 QUIC，且网络条件允许，浏览器可能会选择使用 QUIC 协议建立连接。**
4. **在 QUIC 连接建立的过程中，双方会协商连接参数，包括初始的最大流数量。** 这部分可能涉及到 `QuicStreamIdManager` 的初始化。
5. **用户在网页上执行某些操作，例如点击链接或加载图片，导致浏览器需要向服务器发送多个 HTTP 请求。**
6. **这些 HTTP 请求会被映射到不同的 QUIC 流上。** `QuicStreamIdManager` 负责分配这些流的 ID。
7. **如果用户操作触发了大量的并发请求，可能会接近或达到当前连接允许的最大流数量。**
8. **如果服务器因为某些原因无法立即处理所有的流，可能会向浏览器发送 `STREAMS_BLOCKED` 帧。**
9. **浏览器接收到 `STREAMS_BLOCKED` 帧后，会调用 `QuicStreamIdManager` 的 `OnStreamsBlockedFrame` 方法进行处理。**
10. **`quic_stream_id_manager_test.cc` 中的测试用例就是为了验证 `QuicStreamIdManager` 在上述步骤中的行为是否符合预期。**

**调试线索：**

* **抓包分析:** 使用 Wireshark 等工具抓取网络包，观察 QUIC 连接建立过程中的握手信息，以及后续的 `STREAMS_BLOCKED` 和 `MAX_STREAMS` 帧的交互，可以帮助理解流控机制是否正常工作。
* **Chrome Net-Internals (chrome://net-internals/#quic):** Chrome 浏览器提供了 Net-Internals 工具，可以查看 QUIC 连接的详细信息，包括当前打开的流数量、最大流数量等，帮助分析问题。
* **日志记录:** 在 QUIC 的实现中添加适当的日志记录，可以跟踪 `QuicStreamIdManager` 的状态变化和方法调用，辅助定位问题。

总而言之，`quic_stream_id_manager_test.cc` 是 QUIC 协议实现的关键测试文件，它确保了流 ID 管理的正确性和健壮性，这对于 QUIC 连接的稳定性和性能至关重要。虽然与 JavaScript 没有直接的代码关联，但其功能直接支撑着基于 QUIC 的网络应用（包括 JavaScript 发起的网络请求）的正常运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_id_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "quiche/quic/core/quic_stream_id_manager.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_stream_id_manager_peer.h"

using testing::_;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

class MockDelegate : public QuicStreamIdManager::DelegateInterface {
 public:
  MOCK_METHOD(void, SendMaxStreams,
              (QuicStreamCount stream_count, bool unidirectional), (override));
  MOCK_METHOD(bool, CanSendMaxStreams, (), (override));
};

struct TestParams {
  TestParams(ParsedQuicVersion version, Perspective perspective,
             bool is_unidirectional)
      : version(version),
        perspective(perspective),
        is_unidirectional(is_unidirectional) {}

  ParsedQuicVersion version;
  Perspective perspective;
  bool is_unidirectional;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  return absl::StrCat(
      ParsedQuicVersionToString(p.version), "_",
      (p.perspective == Perspective::IS_CLIENT ? "Client" : "Server"),
      (p.is_unidirectional ? "Unidirectional" : "Bidirectional"));
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (!version.HasIetfQuicFrames()) {
      continue;
    }
    for (Perspective perspective :
         {Perspective::IS_CLIENT, Perspective::IS_SERVER}) {
      for (bool is_unidirectional : {true, false}) {
        params.push_back(TestParams(version, perspective, is_unidirectional));
      }
    }
  }
  return params;
}

class QuicStreamIdManagerTest : public QuicTestWithParam<TestParams> {
 protected:
  QuicStreamIdManagerTest()
      : stream_id_manager_(&delegate_, IsUnidirectional(), perspective(),
                           GetParam().version, 0,
                           kDefaultMaxStreamsPerConnection) {
    QUICHE_DCHECK(VersionHasIetfQuicFrames(transport_version()));
  }

  QuicTransportVersion transport_version() const {
    return GetParam().version.transport_version;
  }

  // Returns the stream ID for the Nth incoming stream (created by the peer)
  // of the corresponding directionality of this manager.
  QuicStreamId GetNthIncomingStreamId(int n) {
    return QuicUtils::StreamIdDelta(transport_version()) * n +
           (IsUnidirectional()
                ? QuicUtils::GetFirstUnidirectionalStreamId(
                      transport_version(),
                      QuicUtils::InvertPerspective(perspective()))
                : QuicUtils::GetFirstBidirectionalStreamId(
                      transport_version(),
                      QuicUtils::InvertPerspective(perspective())));
  }

  bool IsUnidirectional() { return GetParam().is_unidirectional; }
  Perspective perspective() { return GetParam().perspective; }

  StrictMock<MockDelegate> delegate_;
  QuicStreamIdManager stream_id_manager_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicStreamIdManagerTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicStreamIdManagerTest, Initialization) {
  EXPECT_EQ(0u, stream_id_manager_.outgoing_max_streams());

  EXPECT_EQ(kDefaultMaxStreamsPerConnection,
            stream_id_manager_.incoming_actual_max_streams());
  EXPECT_EQ(kDefaultMaxStreamsPerConnection,
            stream_id_manager_.incoming_advertised_max_streams());
  EXPECT_EQ(kDefaultMaxStreamsPerConnection,
            stream_id_manager_.incoming_initial_max_open_streams());
}

// This test checks that the stream advertisement window is set to 1
// if the number of stream ids is 1. This is a special case in the code.
TEST_P(QuicStreamIdManagerTest, CheckMaxStreamsWindowForSingleStream) {
  stream_id_manager_.SetMaxOpenIncomingStreams(1);
  EXPECT_EQ(1u, stream_id_manager_.incoming_initial_max_open_streams());
  EXPECT_EQ(1u, stream_id_manager_.incoming_actual_max_streams());
}

TEST_P(QuicStreamIdManagerTest, CheckMaxStreamsBadValuesOverMaxFailsOutgoing) {
  QuicStreamCount implementation_max = QuicUtils::GetMaxStreamCount();
  // Ensure that the limit is less than the implementation maximum.
  EXPECT_LT(stream_id_manager_.outgoing_max_streams(), implementation_max);

  EXPECT_TRUE(
      stream_id_manager_.MaybeAllowNewOutgoingStreams(implementation_max + 1));
  // Should be pegged at the max.
  EXPECT_EQ(implementation_max, stream_id_manager_.outgoing_max_streams());
}

// Check the case of the stream count in a STREAMS_BLOCKED frame is less than
// the count most recently advertised in a MAX_STREAMS frame.
TEST_P(QuicStreamIdManagerTest, ProcessStreamsBlockedOk) {
  QuicStreamCount stream_count =
      stream_id_manager_.incoming_initial_max_open_streams();
  QuicStreamsBlockedFrame frame(0, stream_count - 1, IsUnidirectional());
  // We have notified peer about current max.
  EXPECT_CALL(delegate_, SendMaxStreams(stream_count, IsUnidirectional()))
      .Times(0);
  std::string error_details;
  EXPECT_TRUE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));
}

// Check the case of the stream count in a STREAMS_BLOCKED frame is equal to the
// count most recently advertised in a MAX_STREAMS frame. No MAX_STREAMS
// should be generated.
TEST_P(QuicStreamIdManagerTest, ProcessStreamsBlockedNoOp) {
  QuicStreamCount stream_count =
      stream_id_manager_.incoming_initial_max_open_streams();
  QuicStreamsBlockedFrame frame(0, stream_count, IsUnidirectional());
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);
}

// Check the case of the stream count in a STREAMS_BLOCKED frame is greater than
// the count most recently advertised in a MAX_STREAMS frame. Expect a
// connection close with an error.
TEST_P(QuicStreamIdManagerTest, ProcessStreamsBlockedTooBig) {
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);
  QuicStreamCount stream_count =
      stream_id_manager_.incoming_initial_max_open_streams() + 1;
  QuicStreamsBlockedFrame frame(0, stream_count, IsUnidirectional());
  std::string error_details;
  EXPECT_FALSE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));
  EXPECT_EQ(
      error_details,
      "StreamsBlockedFrame's stream count 101 exceeds incoming max stream 100");
}

// Same basic tests as above, but calls
// QuicStreamIdManager::MaybeIncreaseLargestPeerStreamId directly, avoiding the
// call chain. The intent is that if there is a problem, the following tests
// will point to either the stream ID manager or the call chain. They also
// provide specific, small scale, tests of a public QuicStreamIdManager method.
// First test make sure that streams with ids below the limit are accepted.
TEST_P(QuicStreamIdManagerTest, IsIncomingStreamIdValidBelowLimit) {
  QuicStreamId stream_id = GetNthIncomingStreamId(
      stream_id_manager_.incoming_actual_max_streams() - 2);
  EXPECT_TRUE(
      stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id, nullptr));
}

// Accept a stream with an ID that equals the limit.
TEST_P(QuicStreamIdManagerTest, IsIncomingStreamIdValidAtLimit) {
  QuicStreamId stream_id = GetNthIncomingStreamId(
      stream_id_manager_.incoming_actual_max_streams() - 1);
  EXPECT_TRUE(
      stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id, nullptr));
}

// Close the connection if the id exceeds the limit.
TEST_P(QuicStreamIdManagerTest, IsIncomingStreamIdInValidAboveLimit) {
  QuicStreamId stream_id =
      GetNthIncomingStreamId(stream_id_manager_.incoming_actual_max_streams());
  std::string error_details;
  EXPECT_FALSE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(
      stream_id, &error_details));
  EXPECT_EQ(error_details,
            absl::StrCat("Stream id ", stream_id,
                         " would exceed stream count limit 100"));
}

TEST_P(QuicStreamIdManagerTest, OnStreamsBlockedFrame) {
  // Get the current maximum allowed incoming stream count.
  QuicStreamCount advertised_stream_count =
      stream_id_manager_.incoming_advertised_max_streams();

  QuicStreamsBlockedFrame frame;

  frame.unidirectional = IsUnidirectional();

  // If the peer is saying it's blocked on the stream count that
  // we've advertised, it's a noop since the peer has the correct information.
  frame.stream_count = advertised_stream_count;
  std::string error_details;
  EXPECT_TRUE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));

  // If the peer is saying it's blocked on a stream count that is larger
  // than what we've advertised, the connection should get closed.
  frame.stream_count = advertised_stream_count + 1;
  EXPECT_FALSE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));
  EXPECT_EQ(
      error_details,
      "StreamsBlockedFrame's stream count 101 exceeds incoming max stream 100");

  // If the peer is saying it's blocked on a count that is less than
  // our actual count, we send a MAX_STREAMS frame and update
  // the advertised value.
  // First, need to bump up the actual max so there is room for the MAX
  // STREAMS frame to send a larger ID.
  QuicStreamCount actual_stream_count =
      stream_id_manager_.incoming_actual_max_streams();

  // Closing a stream will result in the ability to initiate one more
  // stream
  stream_id_manager_.OnStreamClosed(
      QuicStreamIdManagerPeer::GetFirstIncomingStreamId(&stream_id_manager_));
  EXPECT_EQ(actual_stream_count + 1u,
            stream_id_manager_.incoming_actual_max_streams());
  EXPECT_EQ(stream_id_manager_.incoming_actual_max_streams(),
            stream_id_manager_.incoming_advertised_max_streams() + 1u);

  // Now simulate receiving a STREAMS_BLOCKED frame...
  // Changing the actual maximum, above, forces a MAX_STREAMS frame to be
  // sent, so the logic for that (SendMaxStreamsFrame(), etc) is tested.

  // The STREAMS_BLOCKED frame contains the previous advertised count,
  // not the one that the peer would have received as a result of the
  // MAX_STREAMS sent earler.
  frame.stream_count = advertised_stream_count;

  EXPECT_CALL(delegate_, CanSendMaxStreams()).WillOnce(testing::Return(true));
  EXPECT_CALL(delegate_,
              SendMaxStreams(stream_id_manager_.incoming_actual_max_streams(),
                             IsUnidirectional()));

  EXPECT_TRUE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));
  // Check that the saved frame is correct.
  EXPECT_EQ(stream_id_manager_.incoming_actual_max_streams(),
            stream_id_manager_.incoming_advertised_max_streams());
}

TEST_P(QuicStreamIdManagerTest, OnStreamsBlockedFrameCantSend) {
  // Get the current maximum allowed incoming stream count.
  QuicStreamCount advertised_stream_count =
      stream_id_manager_.incoming_advertised_max_streams();

  QuicStreamsBlockedFrame frame;

  frame.unidirectional = IsUnidirectional();

  // First, need to bump up the actual max so there is room for the MAX
  // STREAMS frame to send a larger ID.
  QuicStreamCount actual_stream_count =
      stream_id_manager_.incoming_actual_max_streams();

  // Closing a stream will result in the ability to initiate one more
  // stream
  stream_id_manager_.OnStreamClosed(
      QuicStreamIdManagerPeer::GetFirstIncomingStreamId(&stream_id_manager_));
  EXPECT_EQ(actual_stream_count + 1u,
            stream_id_manager_.incoming_actual_max_streams());
  EXPECT_EQ(stream_id_manager_.incoming_actual_max_streams(),
            stream_id_manager_.incoming_advertised_max_streams() + 1u);

  // Now simulate receiving a STREAMS_BLOCKED frame...
  // Changing the actual maximum, above, forces a MAX_STREAMS frame to be
  // sent, so the logic for that (SendMaxStreamsFrame(), etc) is tested.

  // The STREAMS_BLOCKED frame contains the previous advertised count,
  // not the one that the peer would have received as a result of the
  // MAX_STREAMS sent earler.
  frame.stream_count = advertised_stream_count;

  // Since the delegate returns false, no MAX_STREAMS frame should be sent,
  // and the advertised limit should not increse.
  EXPECT_CALL(delegate_, CanSendMaxStreams()).WillOnce(testing::Return(false));
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);

  const QuicStreamCount advertised_max_streams =
      stream_id_manager_.incoming_advertised_max_streams();
  std::string error_details;
  EXPECT_TRUE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));
  EXPECT_EQ(advertised_max_streams,
            stream_id_manager_.incoming_advertised_max_streams());
}

TEST_P(QuicStreamIdManagerTest, GetNextOutgoingStream) {
  // Number of streams we can open and the first one we should get when
  // opening...
  size_t number_of_streams = kDefaultMaxStreamsPerConnection;

  EXPECT_TRUE(
      stream_id_manager_.MaybeAllowNewOutgoingStreams(number_of_streams));

  QuicStreamId stream_id = IsUnidirectional()
                               ? QuicUtils::GetFirstUnidirectionalStreamId(
                                     transport_version(), perspective())
                               : QuicUtils::GetFirstBidirectionalStreamId(
                                     transport_version(), perspective());

  EXPECT_EQ(number_of_streams, stream_id_manager_.outgoing_max_streams());
  while (number_of_streams) {
    EXPECT_TRUE(stream_id_manager_.CanOpenNextOutgoingStream());
    EXPECT_EQ(stream_id, stream_id_manager_.GetNextOutgoingStreamId());
    stream_id += QuicUtils::StreamIdDelta(transport_version());
    number_of_streams--;
  }

  // If we try to check that the next outgoing stream id is available it should
  // fail.
  EXPECT_FALSE(stream_id_manager_.CanOpenNextOutgoingStream());

  // If we try to get the next id (above the limit), it should cause a quic-bug.
  EXPECT_QUIC_BUG(
      stream_id_manager_.GetNextOutgoingStreamId(),
      "Attempt to allocate a new outgoing stream that would exceed the limit");
}

TEST_P(QuicStreamIdManagerTest, MaybeIncreaseLargestPeerStreamId) {
  QuicStreamId max_stream_id = GetNthIncomingStreamId(
      stream_id_manager_.incoming_actual_max_streams() - 1);
  EXPECT_TRUE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(max_stream_id,
                                                                  nullptr));

  QuicStreamId first_stream_id = GetNthIncomingStreamId(0);
  EXPECT_TRUE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(
      first_stream_id, nullptr));
  // A bad stream ID results in a closed connection.
  std::string error_details;
  EXPECT_FALSE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(
      max_stream_id + QuicUtils::StreamIdDelta(transport_version()),
      &error_details));
  EXPECT_EQ(error_details,
            absl::StrCat(
                "Stream id ",
                max_stream_id + QuicUtils::StreamIdDelta(transport_version()),
                " would exceed stream count limit 100"));
}

TEST_P(QuicStreamIdManagerTest, MaxStreamsWindow) {
  // Open and then close a number of streams to get close to the threshold of
  // sending a MAX_STREAM_FRAME.
  int stream_count = stream_id_manager_.incoming_initial_max_open_streams() /
                         GetQuicFlag(quic_max_streams_window_divisor) -
                     1;

  // Should not get a control-frame transmission since the peer should have
  // "plenty" of stream IDs to use.
  EXPECT_CALL(delegate_, CanSendMaxStreams()).Times(0);
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);

  // Get the first incoming stream ID to try and allocate.
  QuicStreamId stream_id = GetNthIncomingStreamId(0);
  size_t old_available_incoming_streams =
      stream_id_manager_.available_incoming_streams();
  auto i = stream_count;
  while (i) {
    EXPECT_TRUE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id,
                                                                    nullptr));

    // This node should think that the peer believes it has one fewer
    // stream it can create.
    old_available_incoming_streams--;
    EXPECT_EQ(old_available_incoming_streams,
              stream_id_manager_.available_incoming_streams());

    i--;
    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }

  // Now close them, still should get no MAX_STREAMS
  stream_id = GetNthIncomingStreamId(0);
  QuicStreamCount expected_actual_max =
      stream_id_manager_.incoming_actual_max_streams();
  QuicStreamCount expected_advertised_max_streams =
      stream_id_manager_.incoming_advertised_max_streams();
  while (stream_count) {
    stream_id_manager_.OnStreamClosed(stream_id);
    stream_count--;
    stream_id += QuicUtils::StreamIdDelta(transport_version());
    expected_actual_max++;
    EXPECT_EQ(expected_actual_max,
              stream_id_manager_.incoming_actual_max_streams());
    // Advertised maximum should remain the same.
    EXPECT_EQ(expected_advertised_max_streams,
              stream_id_manager_.incoming_advertised_max_streams());
  }

  // This should not change.
  EXPECT_EQ(old_available_incoming_streams,
            stream_id_manager_.available_incoming_streams());

  // Now whenever we close a stream we should get a MAX_STREAMS frame.
  // Above code closed all the open streams, so we have to open/close
  //  EXPECT_CALL(delegate_,
  //  SendMaxStreams(stream_id_manager_.incoming_actual_max_streams(),
  //  IsUnidirectional()));
  EXPECT_CALL(delegate_, CanSendMaxStreams()).WillOnce(testing::Return(true));
  EXPECT_CALL(delegate_, SendMaxStreams(_, IsUnidirectional()));
  EXPECT_TRUE(
      stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id, nullptr));
  stream_id_manager_.OnStreamClosed(stream_id);
}

TEST_P(QuicStreamIdManagerTest, MaxStreamsWindowCantSend) {
  // Open and then close a number of streams to get close to the threshold of
  // sending a MAX_STREAM_FRAME.
  int stream_count = stream_id_manager_.incoming_initial_max_open_streams() /
                         GetQuicFlag(quic_max_streams_window_divisor) -
                     1;

  // Should not get a control-frame transmission since the peer should have
  // "plenty" of stream IDs to use.
  EXPECT_CALL(delegate_, CanSendMaxStreams()).Times(0);
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);

  // Get the first incoming stream ID to try and allocate.
  QuicStreamId stream_id = GetNthIncomingStreamId(0);
  size_t old_available_incoming_streams =
      stream_id_manager_.available_incoming_streams();
  auto i = stream_count;
  while (i) {
    EXPECT_TRUE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id,
                                                                    nullptr));

    // This node should think that the peer believes it has one fewer
    // stream it can create.
    old_available_incoming_streams--;
    EXPECT_EQ(old_available_incoming_streams,
              stream_id_manager_.available_incoming_streams());

    i--;
    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }

  // Now close them, still should get no MAX_STREAMS
  stream_id = GetNthIncomingStreamId(0);
  QuicStreamCount expected_actual_max =
      stream_id_manager_.incoming_actual_max_streams();
  QuicStreamCount expected_advertised_max_streams =
      stream_id_manager_.incoming_advertised_max_streams();
  while (stream_count) {
    stream_id_manager_.OnStreamClosed(stream_id);
    stream_count--;
    stream_id += QuicUtils::StreamIdDelta(transport_version());
    expected_actual_max++;
    EXPECT_EQ(expected_actual_max,
              stream_id_manager_.incoming_actual_max_streams());
    // Advertised maximum should remain the same.
    EXPECT_EQ(expected_advertised_max_streams,
              stream_id_manager_.incoming_advertised_max_streams());
  }

  // This should not change.
  EXPECT_EQ(old_available_incoming_streams,
            stream_id_manager_.available_incoming_streams());

  // Now whenever we close a stream we should get a MAX_STREAMS frame,
  // but since the delegate returns false, no MAX_STREAMS frame should
  // be send and the advertised limit will not change.
  // Above code closed all the open streams, so we have to open/close
  EXPECT_CALL(delegate_, CanSendMaxStreams()).WillOnce(testing::Return(false));
  EXPECT_CALL(delegate_, SendMaxStreams(_, IsUnidirectional())).Times(0);
  EXPECT_TRUE(
      stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id, nullptr));
  stream_id_manager_.OnStreamClosed(stream_id);
  // Advertised maximum should remain the same.
  EXPECT_EQ(expected_advertised_max_streams,
            stream_id_manager_.incoming_advertised_max_streams());
}

TEST_P(QuicStreamIdManagerTest, MaxStreamsWindowStopsIncreasing) {
  // Verify that the incoming stream limit does not increase after
  // StopIncreasingIncomingMaxStreams() is called, even when streams are closed.

  QuicStreamId stream_count =
      stream_id_manager_.incoming_initial_max_open_streams();
  // Open up to the stream limit.
  QuicStreamId stream_id = GetNthIncomingStreamId(0);
  for (QuicStreamCount i = 0; i < stream_count; ++i) {
    EXPECT_TRUE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(stream_id,
                                                                    nullptr));

    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }

  // Prevent max streams from increasing.
  stream_id_manager_.StopIncreasingIncomingMaxStreams();

  // Since the limit does not increase, a MAX_STREAMS frame will not be sent.
  EXPECT_CALL(delegate_, CanSendMaxStreams()).Times(0);
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);

  // Now close them.
  stream_id = GetNthIncomingStreamId(0);
  QuicStreamCount expected_actual_max =
      stream_id_manager_.incoming_actual_max_streams();
  QuicStreamCount expected_advertised_max_streams =
      stream_id_manager_.incoming_advertised_max_streams();
  for (QuicStreamCount i = 0; i < stream_count; ++i) {
    stream_id_manager_.OnStreamClosed(stream_id);
    stream_id += QuicUtils::StreamIdDelta(transport_version());
    // Limits should not change.
    EXPECT_EQ(expected_actual_max,
              stream_id_manager_.incoming_actual_max_streams());
    EXPECT_EQ(expected_advertised_max_streams,
              stream_id_manager_.incoming_advertised_max_streams());
  }
}

TEST_P(QuicStreamIdManagerTest, StreamsBlockedEdgeConditions) {
  QuicStreamsBlockedFrame frame;
  frame.unidirectional = IsUnidirectional();

  // Check that receipt of a STREAMS BLOCKED with stream-count = 0 does nothing
  // when max_allowed_incoming_streams is 0.
  EXPECT_CALL(delegate_, CanSendMaxStreams()).Times(0);
  EXPECT_CALL(delegate_, SendMaxStreams(_, _)).Times(0);
  stream_id_manager_.SetMaxOpenIncomingStreams(0);
  frame.stream_count = 0;
  std::string error_details;
  EXPECT_TRUE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));

  // Check that receipt of a STREAMS BLOCKED with stream-count = 0 invokes a
  // MAX STREAMS, count = 123, when the MaxOpen... is set to 123.
  EXPECT_CALL(delegate_, CanSendMaxStreams()).WillOnce(testing::Return(true));
  EXPECT_CALL(delegate_, SendMaxStreams(123u, IsUnidirectional()));
  QuicStreamIdManagerPeer::set_incoming_actual_max_streams(&stream_id_manager_,
                                                           123);
  frame.stream_count = 0;
  EXPECT_TRUE(stream_id_manager_.OnStreamsBlockedFrame(frame, &error_details));
}

// Test that a MAX_STREAMS frame is generated when half the stream ids become
// available. This has a useful side effect of testing that when streams are
// closed, the number of available stream ids increases.
TEST_P(QuicStreamIdManagerTest, MaxStreamsSlidingWindow) {
  QuicStreamCount first_advert =
      stream_id_manager_.incoming_advertised_max_streams();

  // Open/close enough streams to shrink the window without causing a MAX
  // STREAMS to be generated. The loop
  // will make that many stream IDs available, so the last CloseStream should
  // cause a MAX STREAMS frame to be generated.
  int i =
      static_cast<int>(stream_id_manager_.incoming_initial_max_open_streams() /
                       GetQuicFlag(quic_max_streams_window_divisor));
  QuicStreamId id =
      QuicStreamIdManagerPeer::GetFirstIncomingStreamId(&stream_id_manager_);
  EXPECT_CALL(delegate_, CanSendMaxStreams()).WillOnce(testing::Return(true));
  EXPECT_CALL(delegate_, SendMaxStreams(first_advert + i, IsUnidirectional()));
  while (i) {
    EXPECT_TRUE(
        stream_id_manager_.MaybeIncreaseLargestPeerStreamId(id, nullptr));
    stream_id_manager_.OnStreamClosed(id);
    i--;
    id += QuicUtils::StreamIdDelta(transport_version());
  }
}

TEST_P(QuicStreamIdManagerTest, NewStreamDoesNotExceedLimit) {
  EXPECT_TRUE(stream_id_manager_.MaybeAllowNewOutgoingStreams(100));

  size_t stream_count = stream_id_manager_.outgoing_max_streams();
  EXPECT_NE(0u, stream_count);

  while (stream_count) {
    EXPECT_TRUE(stream_id_manager_.CanOpenNextOutgoingStream());
    stream_id_manager_.GetNextOutgoingStreamId();
    stream_count--;
  }

  EXPECT_EQ(stream_id_manager_.outgoing_stream_count(),
            stream_id_manager_.outgoing_max_streams());
  // Create another, it should fail.
  EXPECT_FALSE(stream_id_manager_.CanOpenNextOutgoingStream());
}

TEST_P(QuicStreamIdManagerTest, AvailableStreams) {
  stream_id_manager_.MaybeIncreaseLargestPeerStreamId(GetNthIncomingStreamId(3),
                                                      nullptr);

  EXPECT_TRUE(stream_id_manager_.IsAvailableStream(GetNthIncomingStreamId(1)));
  EXPECT_TRUE(stream_id_manager_.IsAvailableStream(GetNthIncomingStreamId(2)));
  EXPECT_FALSE(stream_id_manager_.IsAvailableStream(GetNthIncomingStreamId(3)));
  EXPECT_TRUE(stream_id_manager_.IsAvailableStream(GetNthIncomingStreamId(4)));
}

// Tests that if MaybeIncreaseLargestPeerStreamId is given an extremely
// large stream ID (larger than the limit) it is rejected.
// This is a regression for Chromium bugs 909987 and 910040
TEST_P(QuicStreamIdManagerTest, ExtremeMaybeIncreaseLargestPeerStreamId) {
  QuicStreamId too_big_stream_id = GetNthIncomingStreamId(
      stream_id_manager_.incoming_actual_max_streams() + 20);

  std::string error_details;
  EXPECT_FALSE(stream_id_manager_.MaybeIncreaseLargestPeerStreamId(
      too_big_stream_id, &error_details));
  EXPECT_EQ(error_details,
            absl::StrCat("Stream id ", too_big_stream_id,
                         " would exceed stream count limit 100"));
}

}  // namespace
}  // namespace test
}  // namespace quic
```
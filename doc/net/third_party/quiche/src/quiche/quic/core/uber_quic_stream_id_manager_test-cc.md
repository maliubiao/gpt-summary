Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive response.

1. **Understand the Goal:** The primary request is to analyze the given C++ test file for functionality, relationships to JavaScript (if any), logical deductions (with examples), common user/programming errors, and debugging steps.

2. **Initial File Scan:**  Quickly read through the file to get a high-level understanding. Key observations:
    * It's a C++ file (`.cc`).
    * It's a test file (`*_test.cc`).
    * It uses the Google Test framework (`TEST_P`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `MOCK_METHOD`).
    * It includes headers from the `quiche` library (`uber_quic_stream_id_manager.h`, `quic_utils.h`, etc.).
    * It's testing a class called `UberQuicStreamIdManager`.
    * There's a mock delegate (`MockDelegate`) involved.
    * The tests cover various aspects like initialization, setting maximum stream limits, getting next stream IDs, checking stream availability, and handling `StreamsBlockedFrame`.
    * There's parameterized testing using `INSTANTIATE_TEST_SUITE_P` for different QUIC versions and perspectives (client/server).

3. **Identify Core Functionality:**  Based on the file name and the tests, the core functionality of `UberQuicStreamIdManager` is managing QUIC stream IDs. This involves:
    * Allocating and tracking stream IDs for both outgoing and incoming streams.
    * Differentiating between bidirectional and unidirectional streams.
    * Enforcing maximum stream limits.
    * Handling `StreamsBlockedFrame` to trigger sending `MaxStreams` frames.
    * Distinguishing between client-initiated and server-initiated streams.

4. **Analyze Individual Tests:** Go through each test case and understand what it's verifying:
    * `Initialization`: Checks the initial values of the next outgoing stream IDs.
    * `SetMaxOpenOutgoingStreams`: Verifies setting and enforcing the maximum number of outgoing streams (both bidirectional and unidirectional).
    * `SetMaxOpenIncomingStreams`: Verifies setting and enforcing the maximum number of incoming streams. It also checks the error messages when the limit is exceeded.
    * `GetNextOutgoingStreamId`: Confirms that the manager correctly allocates the next available outgoing stream ID.
    * `AvailableStreams`: Checks if the manager can correctly identify available (but not necessarily active) incoming streams.
    * `MaybeIncreaseLargestPeerStreamId`: Tests if the manager correctly updates the largest received stream ID and enforces the maximum incoming stream limit.
    * `OnStreamsBlockedFrame`: Verifies that the manager *doesn't* send `MaxStreams` when a `StreamsBlockedFrame` is received for a stream count below the limit. (Initially, I might have thought it *does* send, but the `Times(0)` makes it clear).
    * `SetMaxOpenOutgoingStreamsPlusFrame`: This test appears to be a duplicate of `SetMaxOpenOutgoingStreams`. This is an important observation.

5. **Look for JavaScript Connections:**  Consider the context: Chromium networking stack and QUIC. Think about where QUIC might interact with JavaScript in a browser:
    * `fetch` API using HTTP/3 (which uses QUIC).
    * WebSockets over HTTP/3.
    * Potentially some internal browser APIs.
    * *Crucially*, the test file itself doesn't directly *use* JavaScript. The connection is at a higher level of the networking stack.

6. **Deduce Logic and Examples:** For each test, try to infer the underlying logic and create illustrative examples:
    * *Example for `SetMaxOpenOutgoingStreams`:* If the limit is 2, calling `GetNextOutgoingBidirectionalStreamId()` twice will succeed, but the third call will be blocked.
    * *Example for `MaybeIncreaseLargestPeerStreamId`:* If the incoming limit is 100, receiving a stream ID of 399 should be allowed, but 401 should be rejected.

7. **Identify Potential Errors:** Think about common mistakes developers might make when *using* the `UberQuicStreamIdManager` or related QUIC components:
    * Setting incorrect maximum stream limits.
    * Not handling the case where `CanOpenNextOutgoingStream()` returns `false`.
    * Misunderstanding the difference between bidirectional and unidirectional streams.
    * Incorrectly interpreting `StreamsBlockedFrame`.

8. **Trace User Actions to the Code:**  Consider how a user action in a browser might lead to this code being executed:
    * User opens multiple tabs/makes multiple requests.
    * The browser uses HTTP/3 (QUIC).
    * The QUIC implementation needs to manage stream IDs.
    * The `UberQuicStreamIdManager` is involved in this management.

9. **Refine and Organize:** Structure the findings into the requested categories: functionality, JavaScript relationship, logical deductions, common errors, and debugging. Use clear and concise language. Highlight key points. Pay attention to the negative constraint about the duplicate test.

10. **Self-Correction/Review:**  Reread the response and compare it with the code. Did I accurately describe the functionality? Are the JavaScript connections reasonable? Are the examples clear? Did I address all parts of the prompt?  For instance, I initially focused only on the positive aspects of `OnStreamsBlockedFrame`, but the `Times(0)` indicates the importance of when it *doesn't* send. I corrected this in my thought process. Recognizing the duplicate test is also a form of self-correction.
这个 C++ 文件 `uber_quic_stream_id_manager_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `UberQuicStreamIdManager` 类的功能。 `UberQuicStreamIdManager` 的核心职责是管理 QUIC 连接中的流 ID（Stream IDs）。

**以下是该文件的功能列表：**

1. **测试 `UberQuicStreamIdManager` 的初始化:** 验证管理器在创建时是否正确设置了初始的下一个可用的流 ID。
2. **测试设置最大可打开的流数量 (outgoing streams):**
   - 验证可以设置允许创建的最大 outgoing 双向流和单向流的数量。
   - 验证在达到最大限制后，尝试创建新的 outgoing 流会被阻止。
3. **测试设置最大可接受的流数量 (incoming streams):**
   - 验证可以设置允许接收的最大 incoming 双向流和单向流的数量。
   - 验证当接收到的流 ID 超过最大限制时，管理器能够正确识别并拒绝。
   - 验证当接收到的流 ID 接近最大限制时，管理器不会触发不必要的 `MaxStreams` 帧的发送。
4. **测试获取下一个可用的 outgoing 流 ID:**
   - 验证管理器能够正确递增并返回下一个可用的 outgoing 双向流和单向流的 ID。
5. **测试判断流 ID 是否可用 (available):**
   - 验证管理器能够正确判断一个 peer 发起的流 ID 是否在允许的范围内，即使该流还没有被完全建立。
6. **测试 `MaybeIncreaseLargestPeerStreamId` 方法:**
   - 验证当接收到 peer 发送的流 ID 时，该方法能够正确更新已知的最大 peer 流 ID。
   - 验证当接收到的流 ID 超过允许的最大 incoming 流数量时，该方法会返回 `false` 并提供相应的错误信息。
7. **测试 `OnStreamsBlockedFrame` 方法:**
   - 验证当收到 `StreamsBlockedFrame` 时，如果请求阻塞的流数量小于当前允许的最大 incoming 流数量，管理器不会触发发送 `MaxStreams` 帧（因为没有必要）。这意味着它在正确处理拥塞控制信号。
8. **使用参数化测试 (Parameterized Testing):**
   - 使用 `INSTANTIATE_TEST_SUITE_P` 针对不同的 QUIC 版本 (由 `AllSupportedVersions()` 提供) 和连接视角 (客户端 `IS_CLIENT` 和服务端 `IS_SERVER`) 运行所有测试用例，确保代码在不同场景下的兼容性和正确性。

**与 JavaScript 的关系：**

虽然此 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能与在浏览器中使用 JavaScript 发起网络请求息息相关。

**举例说明:**

假设一个网页使用 JavaScript 的 `fetch` API 发起多个 HTTP/3 请求。每个请求都会创建一个或多个 QUIC 流。`UberQuicStreamIdManager` 的作用是：

- **当浏览器（客户端）发起请求时：** `UberQuicStreamIdManager` 负责分配新的 outgoing 流 ID。JavaScript 的 `fetch` 调用最终会导致 QUIC 层创建流，而 `UberQuicStreamIdManager` 保证分配的 ID 是有效的、未被使用的。
- **当服务器响应请求时：**  服务器也可能发起新的流（例如用于推送）。浏览器作为 QUIC 连接的另一端，会接收这些 incoming 流的 ID。`UberQuicStreamIdManager` 需要验证这些 ID 是否在允许的范围内。
- **最大流限制：**  如果 JavaScript 代码尝试发起过多的并发请求，可能会触及 QUIC 连接的最大流限制。`UberQuicStreamIdManager` 负责维护这些限制，防止资源耗尽。当达到限制时，会影响 JavaScript 发起的网络请求，可能导致请求被延迟或失败。

**逻辑推理 (假设输入与输出):**

**场景 1: 测试设置最大 outgoing 双向流数量**

* **假设输入:**
    - `max_outgoing_bidirectional_streams` 设置为 3。
    - 客户端尝试创建 4 个双向流。
* **预期输出:**
    - 前 3 个 `GetNextOutgoingBidirectionalStreamId()` 调用返回不同的有效流 ID。
    - 第 4 个 `CanOpenNextOutgoingBidirectionalStream()` 调用返回 `false`。
    - 尝试获取第 4 个流 ID 的操作会被阻止。

**场景 2: 测试接收超过最大 incoming 单向流数量的流 ID**

* **假设输入:**
    - 服务端设置 `max_incoming_unidirectional_streams` 为 2。
    - 客户端（作为测试的 peer）发送了单向流 ID 401, 403, 405 (假设初始单向流 ID 为 400，步长为 2)。
* **预期输出:**
    - `MaybeIncreaseLargestPeerStreamId(401)` 返回 `true`。
    - `MaybeIncreaseLargestPeerStreamId(403)` 返回 `true`。
    - `MaybeIncreaseLargestPeerStreamId(405)` 返回 `false`，并带有类似 "Stream id 405 would exceed stream count limit 2" 的错误信息。

**用户或编程常见的使用错误 (与调试线索):**

1. **配置错误的 `max_streams_per_connection`:**
   - **错误:**  开发者可能在配置 QUIC 连接时设置了一个过小的 `max_streams_per_connection` 值，导致应用在需要更多并发连接时受限。
   - **如何到达这里 (调试线索):**
     - 用户在网页上执行了大量操作，例如同时上传多个文件或打开多个视频流。
     - JavaScript 代码多次调用 `fetch` 或创建 WebSocket 连接。
     - QUIC 连接尝试创建新的流，但 `UberQuicStreamIdManager::CanOpenNextOutgoingBidirectionalStream()` 或 `UberQuicStreamIdManager::CanOpenNextOutgoingUnidirectionalStream()` 返回 `false`。
     - 在 QUIC 连接的调试日志中会看到由于达到最大流数量而无法创建新流的错误信息。可以追溯到 `UberQuicStreamIdManager` 的相关逻辑。

2. **未处理流创建失败的情况:**
   - **错误:**  应用程序的 QUIC 集成代码可能没有正确处理 `UberQuicStreamIdManager` 拒绝创建新流的情况。
   - **如何到达这里 (调试线索):**
     - 用户操作导致需要创建更多流，但应用程序没有检查 `CanOpenNextOutgoingStream()` 的返回值，直接调用 `GetNextOutgoingStreamId()`，可能导致未定义的行为或崩溃（虽然这个测试本身不会直接导致崩溃，但它测试了防止这种情况发生的机制）。
     - 调试时，可能会发现尝试发送数据失败，因为没有可用的流 ID。

3. **对 `StreamsBlockedFrame` 的误解:**
   - **错误:**  开发者可能错误地认为收到 `StreamsBlockedFrame` 意味着可以立即无限制地创建更多流，而实际上这只是对端告知其流资源受限，本地需要考虑降低创建流的速度或等待。
   - **如何到达这里 (调试线索):**
     - 在网络状况不佳的情况下，可能会频繁收到 `StreamsBlockedFrame`。
     - 如果应用程序没有正确处理，可能会继续快速尝试创建流，导致资源竞争或连接不稳定。
     - 调试时可以观察到 `StreamsBlockedFrame` 的发送和接收，以及本地创建流的尝试频率。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用 HTTP/3 (QUIC) 的网站。**
2. **用户执行某些操作，例如：**
   - 点击多个链接打开新标签页。
   - 观看视频。
   - 上传或下载文件。
   - 运行使用 WebSocket 的应用程序。
3. **JavaScript 代码通过 `fetch` API 或 WebSocket API 发起多个网络请求。**
4. **浏览器底层的 QUIC 协议实现需要创建和管理多个流来处理这些并发请求。**
5. **`UberQuicStreamIdManager` 负责分配和跟踪这些流的 ID。**
6. **当需要创建一个新的 outgoing 流时，会调用 `UberQuicStreamIdManager::GetNextOutgoingBidirectionalStreamId()` 或 `UberQuicStreamIdManager::GetNextOutgoingUnidirectionalStreamId()`。**
7. **当接收到 peer 发送的流时，会调用 `UberQuicStreamIdManager::MaybeIncreaseLargestPeerStreamId()` 来更新状态。**
8. **如果对端发送 `StreamsBlockedFrame`，会调用 `UberQuicStreamIdManager::OnStreamsBlockedFrame()`。**

因此，`uber_quic_stream_id_manager_test.cc` 中测试的各种场景，都是为了确保在用户进行各种网络操作时，QUIC 协议栈能够正确地管理流 ID，保证连接的稳定性和效率。通过阅读和理解这些测试用例，可以更好地理解 `UberQuicStreamIdManager` 的工作原理，并有助于排查与 QUIC 流管理相关的网络问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/uber_quic_stream_id_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/uber_quic_stream_id_manager.h"

#include <string>
#include <vector>

#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_stream_id_manager_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

using testing::_;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

struct TestParams {
  explicit TestParams(ParsedQuicVersion version, Perspective perspective)
      : version(version), perspective(perspective) {}

  ParsedQuicVersion version;
  Perspective perspective;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  return absl::StrCat(
      ParsedQuicVersionToString(p.version), "_",
      (p.perspective == Perspective::IS_CLIENT ? "client" : "server"));
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (!version.HasIetfQuicFrames()) {
      continue;
    }
    params.push_back(TestParams(version, Perspective::IS_CLIENT));
    params.push_back(TestParams(version, Perspective::IS_SERVER));
  }
  return params;
}

class MockDelegate : public QuicStreamIdManager::DelegateInterface {
 public:
  MOCK_METHOD(bool, CanSendMaxStreams, (), (override));
  MOCK_METHOD(void, SendMaxStreams,
              (QuicStreamCount stream_count, bool unidirectional), (override));
};

class UberQuicStreamIdManagerTest : public QuicTestWithParam<TestParams> {
 protected:
  UberQuicStreamIdManagerTest()
      : manager_(perspective(), version(), &delegate_, 0, 0,
                 kDefaultMaxStreamsPerConnection,
                 kDefaultMaxStreamsPerConnection) {}

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(transport_version(),
                                                    Perspective::IS_CLIENT) +
           QuicUtils::StreamIdDelta(transport_version()) * n;
  }

  QuicStreamId GetNthClientInitiatedUnidirectionalId(int n) {
    return QuicUtils::GetFirstUnidirectionalStreamId(transport_version(),
                                                     Perspective::IS_CLIENT) +
           QuicUtils::StreamIdDelta(transport_version()) * n;
  }

  QuicStreamId GetNthServerInitiatedBidirectionalId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(transport_version(),
                                                    Perspective::IS_SERVER) +
           QuicUtils::StreamIdDelta(transport_version()) * n;
  }

  QuicStreamId GetNthServerInitiatedUnidirectionalId(int n) {
    return QuicUtils::GetFirstUnidirectionalStreamId(transport_version(),
                                                     Perspective::IS_SERVER) +
           QuicUtils::StreamIdDelta(transport_version()) * n;
  }

  QuicStreamId GetNthPeerInitiatedBidirectionalStreamId(int n) {
    return ((perspective() == Perspective::IS_SERVER)
                ? GetNthClientInitiatedBidirectionalId(n)
                : GetNthServerInitiatedBidirectionalId(n));
  }
  QuicStreamId GetNthPeerInitiatedUnidirectionalStreamId(int n) {
    return ((perspective() == Perspective::IS_SERVER)
                ? GetNthClientInitiatedUnidirectionalId(n)
                : GetNthServerInitiatedUnidirectionalId(n));
  }
  QuicStreamId GetNthSelfInitiatedBidirectionalStreamId(int n) {
    return ((perspective() == Perspective::IS_CLIENT)
                ? GetNthClientInitiatedBidirectionalId(n)
                : GetNthServerInitiatedBidirectionalId(n));
  }
  QuicStreamId GetNthSelfInitiatedUnidirectionalStreamId(int n) {
    return ((perspective() == Perspective::IS_CLIENT)
                ? GetNthClientInitiatedUnidirectionalId(n)
                : GetNthServerInitiatedUnidirectionalId(n));
  }

  QuicStreamId StreamCountToId(QuicStreamCount stream_count,
                               Perspective perspective, bool bidirectional) {
    return ((bidirectional) ? QuicUtils::GetFirstBidirectionalStreamId(
                                  transport_version(), perspective)
                            : QuicUtils::GetFirstUnidirectionalStreamId(
                                  transport_version(), perspective)) +
           ((stream_count - 1) * QuicUtils::StreamIdDelta(transport_version()));
  }

  ParsedQuicVersion version() { return GetParam().version; }
  QuicTransportVersion transport_version() {
    return version().transport_version;
  }

  Perspective perspective() { return GetParam().perspective; }

  testing::StrictMock<MockDelegate> delegate_;
  UberQuicStreamIdManager manager_;
};

INSTANTIATE_TEST_SUITE_P(Tests, UberQuicStreamIdManagerTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(UberQuicStreamIdManagerTest, Initialization) {
  EXPECT_EQ(GetNthSelfInitiatedBidirectionalStreamId(0),
            manager_.next_outgoing_bidirectional_stream_id());
  EXPECT_EQ(GetNthSelfInitiatedUnidirectionalStreamId(0),
            manager_.next_outgoing_unidirectional_stream_id());
}

TEST_P(UberQuicStreamIdManagerTest, SetMaxOpenOutgoingStreams) {
  const size_t kNumMaxOutgoingStream = 123;
  // Set the uni- and bi- directional limits to different values to ensure
  // that they are managed separately.
  EXPECT_TRUE(manager_.MaybeAllowNewOutgoingBidirectionalStreams(
      kNumMaxOutgoingStream));
  EXPECT_TRUE(manager_.MaybeAllowNewOutgoingUnidirectionalStreams(
      kNumMaxOutgoingStream + 1));
  EXPECT_EQ(kNumMaxOutgoingStream,
            manager_.max_outgoing_bidirectional_streams());
  EXPECT_EQ(kNumMaxOutgoingStream + 1,
            manager_.max_outgoing_unidirectional_streams());
  // Check that, for each directionality, we can open the correct number of
  // streams.
  int i = kNumMaxOutgoingStream;
  while (i) {
    EXPECT_TRUE(manager_.CanOpenNextOutgoingBidirectionalStream());
    manager_.GetNextOutgoingBidirectionalStreamId();
    EXPECT_TRUE(manager_.CanOpenNextOutgoingUnidirectionalStream());
    manager_.GetNextOutgoingUnidirectionalStreamId();
    i--;
  }
  // One more unidirectional
  EXPECT_TRUE(manager_.CanOpenNextOutgoingUnidirectionalStream());
  manager_.GetNextOutgoingUnidirectionalStreamId();

  // Both should be exhausted...
  EXPECT_FALSE(manager_.CanOpenNextOutgoingUnidirectionalStream());
  EXPECT_FALSE(manager_.CanOpenNextOutgoingBidirectionalStream());
}

TEST_P(UberQuicStreamIdManagerTest, SetMaxOpenIncomingStreams) {
  const size_t kNumMaxIncomingStreams = 456;
  manager_.SetMaxOpenIncomingUnidirectionalStreams(kNumMaxIncomingStreams);
  // Do +1 for bidirectional to ensure that uni- and bi- get properly set.
  manager_.SetMaxOpenIncomingBidirectionalStreams(kNumMaxIncomingStreams + 1);
  EXPECT_EQ(kNumMaxIncomingStreams + 1,
            manager_.GetMaxAllowdIncomingBidirectionalStreams());
  EXPECT_EQ(kNumMaxIncomingStreams,
            manager_.GetMaxAllowdIncomingUnidirectionalStreams());
  EXPECT_EQ(manager_.max_incoming_bidirectional_streams(),
            manager_.advertised_max_incoming_bidirectional_streams());
  EXPECT_EQ(manager_.max_incoming_unidirectional_streams(),
            manager_.advertised_max_incoming_unidirectional_streams());
  // Make sure that we can create kNumMaxIncomingStreams incoming unidirectional
  // streams and kNumMaxIncomingStreams+1 incoming bidirectional streams.
  size_t i;
  for (i = 0; i < kNumMaxIncomingStreams; i++) {
    EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
        GetNthPeerInitiatedUnidirectionalStreamId(i), nullptr));
    EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
        GetNthPeerInitiatedBidirectionalStreamId(i), nullptr));
  }
  // Should be able to open the next bidirectional stream
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
      GetNthPeerInitiatedBidirectionalStreamId(i), nullptr));

  // We should have exhausted the counts, the next streams should fail
  std::string error_details;
  EXPECT_FALSE(manager_.MaybeIncreaseLargestPeerStreamId(
      GetNthPeerInitiatedUnidirectionalStreamId(i), &error_details));
  EXPECT_EQ(error_details,
            absl::StrCat(
                "Stream id ", GetNthPeerInitiatedUnidirectionalStreamId(i),
                " would exceed stream count limit ", kNumMaxIncomingStreams));
  EXPECT_FALSE(manager_.MaybeIncreaseLargestPeerStreamId(
      GetNthPeerInitiatedBidirectionalStreamId(i + 1), &error_details));
  EXPECT_EQ(error_details,
            absl::StrCat("Stream id ",
                         GetNthPeerInitiatedBidirectionalStreamId(i + 1),
                         " would exceed stream count limit ",
                         kNumMaxIncomingStreams + 1));
}

TEST_P(UberQuicStreamIdManagerTest, GetNextOutgoingStreamId) {
  EXPECT_TRUE(manager_.MaybeAllowNewOutgoingBidirectionalStreams(10));
  EXPECT_TRUE(manager_.MaybeAllowNewOutgoingUnidirectionalStreams(10));
  EXPECT_EQ(GetNthSelfInitiatedBidirectionalStreamId(0),
            manager_.GetNextOutgoingBidirectionalStreamId());
  EXPECT_EQ(GetNthSelfInitiatedBidirectionalStreamId(1),
            manager_.GetNextOutgoingBidirectionalStreamId());
  EXPECT_EQ(GetNthSelfInitiatedUnidirectionalStreamId(0),
            manager_.GetNextOutgoingUnidirectionalStreamId());
  EXPECT_EQ(GetNthSelfInitiatedUnidirectionalStreamId(1),
            manager_.GetNextOutgoingUnidirectionalStreamId());
}

TEST_P(UberQuicStreamIdManagerTest, AvailableStreams) {
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
      GetNthPeerInitiatedBidirectionalStreamId(3), nullptr));
  EXPECT_TRUE(
      manager_.IsAvailableStream(GetNthPeerInitiatedBidirectionalStreamId(1)));
  EXPECT_TRUE(
      manager_.IsAvailableStream(GetNthPeerInitiatedBidirectionalStreamId(2)));

  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
      GetNthPeerInitiatedUnidirectionalStreamId(3), nullptr));
  EXPECT_TRUE(
      manager_.IsAvailableStream(GetNthPeerInitiatedUnidirectionalStreamId(1)));
  EXPECT_TRUE(
      manager_.IsAvailableStream(GetNthPeerInitiatedUnidirectionalStreamId(2)));
}

TEST_P(UberQuicStreamIdManagerTest, MaybeIncreaseLargestPeerStreamId) {
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
      StreamCountToId(manager_.max_incoming_bidirectional_streams(),
                      QuicUtils::InvertPerspective(perspective()),
                      /* bidirectional=*/true),
      nullptr));
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
      StreamCountToId(manager_.max_incoming_bidirectional_streams(),
                      QuicUtils::InvertPerspective(perspective()),
                      /* bidirectional=*/false),
      nullptr));

  std::string expected_error_details =
      perspective() == Perspective::IS_SERVER
          ? "Stream id 400 would exceed stream count limit 100"
          : "Stream id 401 would exceed stream count limit 100";
  std::string error_details;

  EXPECT_FALSE(manager_.MaybeIncreaseLargestPeerStreamId(
      StreamCountToId(manager_.max_incoming_bidirectional_streams() + 1,
                      QuicUtils::InvertPerspective(perspective()),
                      /* bidirectional=*/true),
      &error_details));
  EXPECT_EQ(expected_error_details, error_details);
  expected_error_details =
      perspective() == Perspective::IS_SERVER
          ? "Stream id 402 would exceed stream count limit 100"
          : "Stream id 403 would exceed stream count limit 100";

  EXPECT_FALSE(manager_.MaybeIncreaseLargestPeerStreamId(
      StreamCountToId(manager_.max_incoming_bidirectional_streams() + 1,
                      QuicUtils::InvertPerspective(perspective()),
                      /* bidirectional=*/false),
      &error_details));
  EXPECT_EQ(expected_error_details, error_details);
}

TEST_P(UberQuicStreamIdManagerTest, OnStreamsBlockedFrame) {
  QuicStreamCount stream_count =
      manager_.advertised_max_incoming_bidirectional_streams() - 1;

  QuicStreamsBlockedFrame frame(kInvalidControlFrameId, stream_count,
                                /*unidirectional=*/false);
  EXPECT_CALL(delegate_,
              SendMaxStreams(manager_.max_incoming_bidirectional_streams(),
                             frame.unidirectional))
      .Times(0);
  EXPECT_TRUE(manager_.OnStreamsBlockedFrame(frame, nullptr));

  stream_count = manager_.advertised_max_incoming_unidirectional_streams() - 1;
  frame.stream_count = stream_count;
  frame.unidirectional = true;

  EXPECT_CALL(delegate_,
              SendMaxStreams(manager_.max_incoming_unidirectional_streams(),
                             frame.unidirectional))
      .Times(0);
  EXPECT_TRUE(manager_.OnStreamsBlockedFrame(frame, nullptr));
}

TEST_P(UberQuicStreamIdManagerTest, SetMaxOpenOutgoingStreamsPlusFrame) {
  const size_t kNumMaxOutgoingStream = 123;
  // Set the uni- and bi- directional limits to different values to ensure
  // that they are managed separately.
  EXPECT_TRUE(manager_.MaybeAllowNewOutgoingBidirectionalStreams(
      kNumMaxOutgoingStream));
  EXPECT_TRUE(manager_.MaybeAllowNewOutgoingUnidirectionalStreams(
      kNumMaxOutgoingStream + 1));
  EXPECT_EQ(kNumMaxOutgoingStream,
            manager_.max_outgoing_bidirectional_streams());
  EXPECT_EQ(kNumMaxOutgoingStream + 1,
            manager_.max_outgoing_unidirectional_streams());
  // Check that, for each directionality, we can open the correct number of
  // streams.
  int i = kNumMaxOutgoingStream;
  while (i) {
    EXPECT_TRUE(manager_.CanOpenNextOutgoingBidirectionalStream());
    manager_.GetNextOutgoingBidirectionalStreamId();
    EXPECT_TRUE(manager_.CanOpenNextOutgoingUnidirectionalStream());
    manager_.GetNextOutgoingUnidirectionalStreamId();
    i--;
  }
  // One more unidirectional
  EXPECT_TRUE(manager_.CanOpenNextOutgoingUnidirectionalStream());
  manager_.GetNextOutgoingUnidirectionalStreamId();

  // Both should be exhausted...
  EXPECT_FALSE(manager_.CanOpenNextOutgoingUnidirectionalStream());
  EXPECT_FALSE(manager_.CanOpenNextOutgoingBidirectionalStream());
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```
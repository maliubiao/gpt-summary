Response:
The user is asking for a summary of the provided C++ code, which is a test file for `QuicConnectionIdManager`. The request has several parts: identify the file's function, its relationship to JavaScript (if any), logical reasoning with input/output examples, common usage errors, debugging steps to reach this code, and a general summary.

**Plan:**

1. **Identify the Core Functionality:** The file `quic_connection_id_manager_test.cc` contains unit tests for the `QuicConnectionIdManager` class. This class manages connection IDs in the QUIC protocol. It seems to cover both peer-issued and self-issued connection IDs.

2. **JavaScript Relationship:**  QUIC is a transport protocol. While JavaScript might interact with it indirectly through browser APIs for network requests, this specific C++ code is low-level implementation and unlikely to have a direct functional relationship with JavaScript. I should explain this distinction.

3. **Logical Reasoning (Input/Output):**  The tests demonstrate the logic of the `QuicConnectionIdManager`. I can pick some key test cases and explain the assumed input (method calls, frame data) and the expected output (state changes, error codes, sent frames).

4. **Common Usage Errors:**  Since this is a testing file, the "usage errors" are likely related to misconfigurations or incorrect implementations of the `QuicConnectionIdManager` or related components. I can infer some based on the test cases (e.g., exceeding connection ID limits, using the same connection ID with different sequence numbers).

5. **Debugging Steps:**  Think about how a developer working on network code in Chromium might end up looking at this file. It could be due to debugging QUIC connection establishment, migration, or issues related to connection ID management.

6. **General Summary:**  Provide a concise overview of the file's purpose.

7. **Address "Part 1 of 2":** Since this is part 1, focus on summarizing the functionality covered in this specific code block. The presence of `QuicPeerIssuedConnectionIdManagerTest` and `QuicSelfIssuedConnectionIdManagerTest` suggests the file covers testing of both peer-initiated and self-initiated connection ID management.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第1部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

**Self-Correction/Refinement:**

Initially, I might be tempted to go deep into the QUIC protocol details. However, the request asks for a summary *of the file's function*, which is primarily testing. Therefore, my explanations should focus on what the *tests* are doing and what aspects of the `QuicConnectionIdManager` they are verifying. I need to be mindful of not over-interpreting the purpose of the test file itself. The request to relate it to JavaScript needs to be handled carefully to avoid making incorrect assumptions about direct interaction. It's more about the context of network protocols in web development.
这个C++文件 `quic_connection_id_manager_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicConnectionIdManager` 类的功能。 `QuicConnectionIdManager` 负责管理 QUIC 连接的连接ID（Connection ID）。连接ID 是用于标识 QUIC 连接的，在连接的生命周期中可能会发生变化，尤其是在连接迁移的情况下。

**这个文件的主要功能是：**

1. **测试 `QuicPeerIssuedConnectionIdManager` 的功能：**
   - 模拟接收来自对端的 `NEW_CONNECTION_ID` 帧，并验证连接ID的分配、存储和管理逻辑。
   - 测试在连接迁移成功和失败的不同场景下，连接ID的序列和更新机制。
   - 验证乱序接收 `NEW_CONNECTION_ID` 帧时的处理逻辑。
   - 测试当接收到已访问过的 `NEW_CONNECTION_ID` 帧时的行为（应该被忽略）。
   - 检查当活动连接ID数量超过限制时的错误处理。
   - 验证当接收到相同连接ID但序列号不同时的错误处理。
   - 测试接收到相同序列号的 `NEW_CONNECTION_ID` 帧时的行为（应该被忽略）。
   - 检查当接收到的连接ID序列号之间存在过多间隔时的错误处理。
   - 测试替换现有连接ID的功能。

2. **测试 `QuicSelfIssuedConnectionIdManager` 的功能：**
   - 模拟发送 `NEW_CONNECTION_ID` 帧到对端。
   - 测试接收到对端发送的 `RETIRE_CONNECTION_ID` 帧时的处理逻辑。
   - 验证按顺序和乱序接收 `RETIRE_CONNECTION_ID` 帧时的行为。
   - 测试连接ID的延迟退休机制，确保一次只退休一个连接ID。
   - 验证一次退休多个连接ID的场景。

**它与 JavaScript 的功能的关系：**

这个 C++ 文件是 QUIC 协议栈的底层实现，与 JavaScript 没有直接的功能关系。JavaScript 运行在浏览器环境中，可以通过浏览器提供的 Web API（例如 Fetch API 或 WebSocket API）来发起网络请求。当浏览器使用 QUIC 协议进行通信时，底层的 QUIC 协议栈（包括这里的 `QuicConnectionIdManager`）会处理连接的建立、数据传输和连接管理等细节。

**举例说明：**

假设一个 JavaScript 应用使用 Fetch API 向一个支持 QUIC 的服务器发起请求：

```javascript
fetch('https://example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

当这个请求通过 QUIC 协议发送时，底层的 QUIC 协议栈会涉及到连接ID的管理。`QuicConnectionIdManager` 负责维护当前连接使用的连接ID，并在需要时生成或更新连接ID。例如，如果发生网络切换导致连接迁移，`QuicConnectionIdManager` 会参与新连接ID的协商和更新过程。但这些对于 JavaScript 开发者来说是透明的，他们只需要关注如何使用 Web API 发起请求和处理响应，而不需要关心底层的 QUIC 连接ID管理细节。

**逻辑推理、假设输入与输出：**

**假设 `QuicPeerIssuedConnectionIdManagerTest` 中的一个测试用例 `ConnectionIdSequenceWhenMigrationSucceed`：**

**假设输入：**

1. 初始状态：连接使用连接ID #0。
2. 接收到来自对端的 `NEW_CONNECTION_ID` 帧，包含连接ID #1，序列号为 1，`retire_prior_to` 为 0。
3. 调用 `ConsumeOneUnusedConnectionId()` 获取一个未使用的连接ID（预期为 #1）。
4. 调用 `MaybeRetireUnusedConnectionIds({TestConnectionId(1)})`，表示迁移到连接ID #1 成功，准备退休连接ID #0。
5. 触发退休告警。

**预期输出：**

1. 连接ID #1 被标记为正在使用。
2. `ConsumeOneUnusedConnectionId()` 返回的连接ID是 #1。
3. 退休告警触发后，`most_recent_retired_connection_id_sequence_numbers()` 返回包含 0 的列表，表示序列号为 0 的连接ID被退休。

**假设 `QuicSelfIssuedConnectionIdManagerTest` 中的一个测试用例 `RetireSelfIssuedConnectionIdInOrder`：**

**假设输入：**

1. 初始状态：连接使用初始连接ID #0。
2. 生成新的连接ID #1 并发送给对端。
3. 接收到对端发送的 `RETIRE_CONNECTION_ID` 帧，序列号为 0。

**预期输出：**

1. 内部状态更新，标记连接ID #0 已被对端退休。
2. 可能会触发发送新的 `NEW_CONNECTION_ID` 帧（例如包含连接ID #2），并要求对端退休序列号小于 1 的连接ID。

**用户或编程常见的使用错误：**

由于这是一个测试文件，这里更多的是测试 *可能发生的错误情况*，而不是用户直接使用 `QuicConnectionIdManager` 时的错误。但可以推断出以下一些常见的编程错误或协议违规：

1. **超过连接ID数量限制：**  如果对端发送过多的 `NEW_CONNECTION_ID` 帧，超过了本地允许的最大活动连接ID数量，会导致连接失败。测试用例 `ErrorWhenActiveConnectionIdLimitExceeded` 就是验证这种情况。
2. **连接ID序列号不一致：** 如果对端发送的 `NEW_CONNECTION_ID` 帧中，同一个连接ID 对应了不同的序列号，这违反了 QUIC 协议，会导致连接终止。测试用例 `ErrorWhenTheSameConnectionIdIsSeenWithDifferentSequenceNumbers` 验证了这一点。
3. **过多的连接ID序列号间隔：**  如果接收到的 `NEW_CONNECTION_ID` 帧的序列号之间存在过大的跳跃，可能意味着丢包或恶意行为，会被视为协议违规。测试用例 `ErrorWhenThereAreTooManyGapsInIssuedConnectionIdSequenceNumbers` 对此进行了测试。
4. **重复使用相同的序列号：** 发送 `NEW_CONNECTION_ID` 帧时，不应该重复使用相同的序列号。测试用例 `NewConnectionIdFrameWithTheSameSequenceNumberIsIgnored` 验证了重复使用序列号的帧会被忽略。
5. **在连接迁移后仍然使用旧的连接ID：**  虽然这更多是上层协议逻辑的错误，但连接ID管理器的正确性对于连接迁移至关重要。如果上层协议没有正确地更新连接ID，可能会导致数据包无法正确路由。

**用户操作如何一步步到达这里作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了连接问题，并且怀疑问题可能与 QUIC 协议的连接ID管理有关。作为一名 Chromium 开发者，为了调试这个问题，可能会进行以下步骤：

1. **复现问题：** 尝试重现用户报告的连接问题，例如连接建立失败、连接中断、或者性能异常。
2. **抓取网络日志：** 使用 Chrome 的 `chrome://net-export/` 功能抓取网络日志，查看 QUIC 连接的详细信息，包括连接ID的变更、`NEW_CONNECTION_ID` 和 `RETIRE_CONNECTION_ID` 帧的收发情况。
3. **查看 QUIC 事件日志：** Chromium 内部有 QUIC 的事件日志，可以提供更详细的连接状态信息。
4. **定位到可能的代码模块：** 根据网络日志中的信息，例如看到连接ID频繁变更或收到与连接ID相关的错误，可能会怀疑是连接ID管理模块的问题。
5. **查看 `QuicConnectionIdManager` 相关的代码：**  开发者可能会查看 `quic_connection_id_manager.h` 和 `quic_connection_id_manager.cc` 文件，了解其实现原理。
6. **阅读测试代码 `quic_connection_id_manager_test.cc`：** 为了更深入地理解 `QuicConnectionIdManager` 的行为和各种边界情况的处理方式，开发者会查看其单元测试代码，例如本文件。通过阅读测试用例，可以了解在不同场景下，`QuicConnectionIdManager` 应该如何工作，从而帮助定位实际代码中的 bug。例如，如果怀疑连接迁移时连接ID处理有问题，可能会重点查看 `QuicPeerIssuedConnectionIdManagerTest` 中与连接迁移相关的测试用例。
7. **设置断点和单步调试：**  如果测试代码提供了足够的线索，开发者可能会在 `quic_connection_id_manager.cc` 中设置断点，结合实际的网络请求进行单步调试，观察连接ID的管理流程。

**总结它的功能（第1部分）：**

这个文件的第1部分主要集中在对 `QuicConnectionIdManager` 类中关于**对端发起的连接ID管理** (`QuicPeerIssuedConnectionIdManager`) 和**本地发起的连接ID管理** (`QuicSelfIssuedConnectionIdManager`) 进行单元测试。它通过模拟各种网络场景和帧的交互，验证了连接ID的分配、退休、更新以及错误处理等核心功能是否符合 QUIC 协议的规范。测试覆盖了连接迁移成功和失败的场景，乱序帧的处理，以及各种边界条件和错误情况，旨在确保 `QuicConnectionIdManager` 的稳定性和正确性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_id_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_connection_id_manager.h"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "quiche/quic/core/frames/quic_retire_connection_id_frame.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/mock_connection_id_generator.h"
#include "quiche/quic/test_tools/quic_connection_id_manager_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic::test {
namespace {

using ::quic::test::IsError;
using ::quic::test::IsQuicNoError;
using ::quic::test::QuicConnectionIdManagerPeer;
using ::quic::test::TestConnectionId;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::IsNull;
using ::testing::Return;
using ::testing::StrictMock;

class TestPeerIssuedConnectionIdManagerVisitor
    : public QuicConnectionIdManagerVisitorInterface {
 public:
  void SetPeerIssuedConnectionIdManager(
      QuicPeerIssuedConnectionIdManager* peer_issued_connection_id_manager) {
    peer_issued_connection_id_manager_ = peer_issued_connection_id_manager;
  }

  void OnPeerIssuedConnectionIdRetired() override {
    // Replace current connection Id if it has been retired.
    if (!peer_issued_connection_id_manager_->IsConnectionIdActive(
            current_peer_issued_connection_id_)) {
      current_peer_issued_connection_id_ =
          peer_issued_connection_id_manager_->ConsumeOneUnusedConnectionId()
              ->connection_id;
    }
    // Retire all the to-be-retired connection Ids.
    most_recent_retired_connection_id_sequence_numbers_ =
        peer_issued_connection_id_manager_
            ->ConsumeToBeRetiredConnectionIdSequenceNumbers();
  }

  const std::vector<uint64_t>&
  most_recent_retired_connection_id_sequence_numbers() {
    return most_recent_retired_connection_id_sequence_numbers_;
  }

  void SetCurrentPeerConnectionId(QuicConnectionId cid) {
    current_peer_issued_connection_id_ = cid;
  }

  const QuicConnectionId& GetCurrentPeerConnectionId() {
    return current_peer_issued_connection_id_;
  }

  bool SendNewConnectionId(const QuicNewConnectionIdFrame& /*frame*/) override {
    return false;
  }
  bool MaybeReserveConnectionId(const QuicConnectionId&) override {
    return false;
  }

  void OnSelfIssuedConnectionIdRetired(
      const QuicConnectionId& /*connection_id*/) override {}

 private:
  QuicPeerIssuedConnectionIdManager* peer_issued_connection_id_manager_ =
      nullptr;
  QuicConnectionId current_peer_issued_connection_id_;
  std::vector<uint64_t> most_recent_retired_connection_id_sequence_numbers_;
};

class QuicPeerIssuedConnectionIdManagerTest : public QuicTest {
 public:
  QuicPeerIssuedConnectionIdManagerTest()
      : peer_issued_cid_manager_(
            /*active_connection_id_limit=*/2, initial_connection_id_, &clock_,
            &alarm_factory_, &cid_manager_visitor_, /*context=*/nullptr) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
    cid_manager_visitor_.SetPeerIssuedConnectionIdManager(
        &peer_issued_cid_manager_);
    cid_manager_visitor_.SetCurrentPeerConnectionId(initial_connection_id_);
    retire_peer_issued_cid_alarm_ =
        QuicConnectionIdManagerPeer::GetRetirePeerIssuedConnectionIdAlarm(
            &peer_issued_cid_manager_);
  }

 protected:
  MockClock clock_;
  test::MockAlarmFactory alarm_factory_;
  TestPeerIssuedConnectionIdManagerVisitor cid_manager_visitor_;
  QuicConnectionId initial_connection_id_ = TestConnectionId(0);
  QuicPeerIssuedConnectionIdManager peer_issued_cid_manager_;
  QuicAlarm* retire_peer_issued_cid_alarm_ = nullptr;
  std::string error_details_;
  bool duplicate_frame_ = false;
};

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       ConnectionIdSequenceWhenMigrationSucceed) {
  {
    // Receives CID #1 from peer.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());

    // Start to use CID #1 for alternative path.
    const QuicConnectionIdData* aternative_connection_id_data =
        peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
    ASSERT_THAT(aternative_connection_id_data, testing::NotNull());
    EXPECT_EQ(aternative_connection_id_data->connection_id,
              TestConnectionId(1));
    EXPECT_EQ(aternative_connection_id_data->stateless_reset_token,
              frame.stateless_reset_token);

    // Connection migration succeed. Prepares to retire CID #0.
    peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
        {TestConnectionId(1)});
    cid_manager_visitor_.SetCurrentPeerConnectionId(TestConnectionId(1));
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(0u));
  }

  {
    // Receives CID #2 from peer since CID #0 is retired.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(2);
    frame.sequence_number = 2u;
    frame.retire_prior_to = 1u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    // Start to use CID #2 for alternative path.
    peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
    // Connection migration succeed. Prepares to retire CID #1.
    peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
        {TestConnectionId(2)});
    cid_manager_visitor_.SetCurrentPeerConnectionId(TestConnectionId(2));
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(1u));
  }

  {
    // Receives CID #3 from peer since CID #1 is retired.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(3);
    frame.sequence_number = 3u;
    frame.retire_prior_to = 2u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    // Start to use CID #3 for alternative path.
    peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
    // Connection migration succeed. Prepares to retire CID #2.
    peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
        {TestConnectionId(3)});
    cid_manager_visitor_.SetCurrentPeerConnectionId(TestConnectionId(3));
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(2u));
  }

  {
    // Receives CID #4 from peer since CID #2 is retired.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(4);
    frame.sequence_number = 4u;
    frame.retire_prior_to = 3u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       ConnectionIdSequenceWhenMigrationFail) {
  {
    // Receives CID #1 from peer.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    // Start to use CID #1 for alternative path.
    peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
    // Connection migration fails. Prepares to retire CID #1.
    peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
        {initial_connection_id_});
    // Actually retires CID #1.
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(1u));
  }

  {
    // Receives CID #2 from peer since CID #1 is retired.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(2);
    frame.sequence_number = 2u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    // Start to use CID #2 for alternative path.
    peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
    // Connection migration fails again. Prepares to retire CID #2.
    peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
        {initial_connection_id_});
    // Actually retires CID #2.
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(2u));
  }

  {
    // Receives CID #3 from peer since CID #2 is retired.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(3);
    frame.sequence_number = 3u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    // Start to use CID #3 for alternative path.
    peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
    // Connection migration succeed. Prepares to retire CID #0.
    peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
        {TestConnectionId(3)});
    // After CID #3 is default (i.e., when there is no pending frame to write
    // associated with CID #0), #0 can actually be retired.
    cid_manager_visitor_.SetCurrentPeerConnectionId(TestConnectionId(3));
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(0u));
  }

  {
    // Receives CID #4 from peer since CID #0 is retired.
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(4);
    frame.sequence_number = 4u;
    frame.retire_prior_to = 3u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    EXPECT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    EXPECT_FALSE(retire_peer_issued_cid_alarm_->IsSet());
  }
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       ReceivesNewConnectionIdOutOfOrder) {
  {
    // Receives new CID #1 that retires prior to #0.
    // Outcome: (active: #0 unused: #1)
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    // Start to use CID #1 for alternative path.
    // Outcome: (active: #0 #1 unused: None)
    peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
  }

  {
    // Receives new CID #3 that retires prior to #2.
    // Outcome: (active: None unused: #3)
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(3);
    frame.sequence_number = 3u;
    frame.retire_prior_to = 2u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }

  {
    // Receives new CID #2 that retires prior to #1.
    // Outcome: (active: None unused: #3, #2)
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(2);
    frame.sequence_number = 2u;
    frame.retire_prior_to = 1u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }

  {
    EXPECT_FALSE(
        peer_issued_cid_manager_.IsConnectionIdActive(TestConnectionId(0)));
    EXPECT_FALSE(
        peer_issued_cid_manager_.IsConnectionIdActive(TestConnectionId(1)));
    // When there is no frame associated with #0 and #1 to write, replace the
    // in-use CID with an unused CID (#2) and retires #0 & #1.
    ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
    alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
    EXPECT_THAT(cid_manager_visitor_
                    .most_recent_retired_connection_id_sequence_numbers(),
                ElementsAre(0u, 1u));
    EXPECT_EQ(cid_manager_visitor_.GetCurrentPeerConnectionId(),
              TestConnectionId(2));
    // Get another unused CID for path validation.
    EXPECT_EQ(
        peer_issued_cid_manager_.ConsumeOneUnusedConnectionId()->connection_id,
        TestConnectionId(3));
  }
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       VisitedNewConnectionIdFrameIsIgnored) {
  // Receives new CID #1 that retires prior to #0.
  // Outcome: (active: #0 unused: #1)
  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(1);
  frame.sequence_number = 1u;
  frame.retire_prior_to = 0u;
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                  frame, &error_details_, &duplicate_frame_),
              IsQuicNoError());
  // Start to use CID #1 for alternative path.
  // Outcome: (active: #0 #1 unused: None)
  peer_issued_cid_manager_.ConsumeOneUnusedConnectionId();
  // Prepare to retire CID #1 as path validation fails.
  peer_issued_cid_manager_.MaybeRetireUnusedConnectionIds(
      {initial_connection_id_});
  // Actually retires CID #1.
  ASSERT_TRUE(retire_peer_issued_cid_alarm_->IsSet());
  alarm_factory_.FireAlarm(retire_peer_issued_cid_alarm_);
  EXPECT_THAT(
      cid_manager_visitor_.most_recent_retired_connection_id_sequence_numbers(),
      ElementsAre(1u));
  // Receives the same frame again. Should be a no-op.
  ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                  frame, &error_details_, &duplicate_frame_),
              IsQuicNoError());
  EXPECT_EQ(true, duplicate_frame_);
  EXPECT_THAT(peer_issued_cid_manager_.ConsumeOneUnusedConnectionId(),
              testing::IsNull());
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       ErrorWhenActiveConnectionIdLimitExceeded) {
  {
    // Receives new CID #1 that retires prior to #0.
    // Outcome: (active: #0 unused: #1)
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }

  {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(2);
    frame.sequence_number = 2u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsError(QUIC_CONNECTION_ID_LIMIT_ERROR));
  }
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       ErrorWhenTheSameConnectionIdIsSeenWithDifferentSequenceNumbers) {
  {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }

  {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 2u;
    frame.retire_prior_to = 1u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(TestConnectionId(2));
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsError(IETF_QUIC_PROTOCOL_VIOLATION));
  }
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       NewConnectionIdFrameWithTheSameSequenceNumberIsIgnored) {
  {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(1);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }

  {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(2);
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(TestConnectionId(2));
    EXPECT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
    EXPECT_EQ(true, duplicate_frame_);
    EXPECT_EQ(
        peer_issued_cid_manager_.ConsumeOneUnusedConnectionId()->connection_id,
        TestConnectionId(1));
    EXPECT_THAT(peer_issued_cid_manager_.ConsumeOneUnusedConnectionId(),
                IsNull());
  }
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest,
       ErrorWhenThereAreTooManyGapsInIssuedConnectionIdSequenceNumbers) {
  // Add 20 intervals: [0, 1), [2, 3), ..., [38,39)
  for (int i = 2; i <= 38; i += 2) {
    QuicNewConnectionIdFrame frame;
    frame.connection_id = TestConnectionId(i);
    frame.sequence_number = i;
    frame.retire_prior_to = i;
    frame.stateless_reset_token =
        QuicUtils::GenerateStatelessResetToken(frame.connection_id);
    ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                    frame, &error_details_, &duplicate_frame_),
                IsQuicNoError());
  }

  // Interval [40, 41) goes over the limit.
  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(40);
  frame.sequence_number = 40u;
  frame.retire_prior_to = 40u;
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  ASSERT_THAT(peer_issued_cid_manager_.OnNewConnectionIdFrame(
                  frame, &error_details_, &duplicate_frame_),
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
}

TEST_F(QuicPeerIssuedConnectionIdManagerTest, ReplaceConnectionId) {
  ASSERT_TRUE(
      peer_issued_cid_manager_.IsConnectionIdActive(initial_connection_id_));
  peer_issued_cid_manager_.ReplaceConnectionId(initial_connection_id_,
                                               TestConnectionId(1));
  EXPECT_FALSE(
      peer_issued_cid_manager_.IsConnectionIdActive(initial_connection_id_));
  EXPECT_TRUE(
      peer_issued_cid_manager_.IsConnectionIdActive(TestConnectionId(1)));
}

class TestSelfIssuedConnectionIdManagerVisitor
    : public QuicConnectionIdManagerVisitorInterface {
 public:
  void OnPeerIssuedConnectionIdRetired() override {}

  MOCK_METHOD(bool, SendNewConnectionId,
              (const QuicNewConnectionIdFrame& frame), (override));
  MOCK_METHOD(bool, MaybeReserveConnectionId,
              (const QuicConnectionId& connection_id), (override));
  MOCK_METHOD(void, OnSelfIssuedConnectionIdRetired,
              (const QuicConnectionId& connection_id), (override));
};

class QuicSelfIssuedConnectionIdManagerTest : public QuicTest {
 public:
  QuicSelfIssuedConnectionIdManagerTest()
      : cid_manager_(/*active_connection_id_limit*/ 2, initial_connection_id_,
                     &clock_, &alarm_factory_, &cid_manager_visitor_,
                     /*context=*/nullptr, connection_id_generator_) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
    retire_self_issued_cid_alarm_ =
        QuicConnectionIdManagerPeer::GetRetireSelfIssuedConnectionIdAlarm(
            &cid_manager_);
  }

 protected:
  // Verify that a call to GenerateNewConnectionId() does the right thing.
  QuicConnectionId CheckGenerate(QuicConnectionId old_cid) {
    QuicConnectionId new_cid = old_cid;
    (*new_cid.mutable_data())++;
    // Ready for the actual call.
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(old_cid))
        .WillOnce(Return(new_cid));
    return new_cid;
  }

  MockClock clock_;
  test::MockAlarmFactory alarm_factory_;
  TestSelfIssuedConnectionIdManagerVisitor cid_manager_visitor_;
  QuicConnectionId initial_connection_id_ = TestConnectionId(0);
  StrictMock<QuicSelfIssuedConnectionIdManager> cid_manager_;
  QuicAlarm* retire_self_issued_cid_alarm_ = nullptr;
  std::string error_details_;
  QuicTime::Delta pto_delay_ = QuicTime::Delta::FromMilliseconds(10);
  MockConnectionIdGenerator connection_id_generator_;
};

MATCHER_P3(ExpectedNewConnectionIdFrame, connection_id, sequence_number,
           retire_prior_to, "") {
  return (arg.connection_id == connection_id) &&
         (arg.sequence_number == sequence_number) &&
         (arg.retire_prior_to == retire_prior_to);
}

TEST_F(QuicSelfIssuedConnectionIdManagerTest,
       RetireSelfIssuedConnectionIdInOrder) {
  QuicConnectionId cid0 = initial_connection_id_;
  QuicConnectionId cid1 = CheckGenerate(cid0);
  QuicConnectionId cid2 = CheckGenerate(cid1);
  QuicConnectionId cid3 = CheckGenerate(cid2);
  QuicConnectionId cid4 = CheckGenerate(cid3);
  QuicConnectionId cid5 = CheckGenerate(cid4);

  // Sends CID #1 to peer.
  EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid1))
      .WillOnce(Return(true));
  EXPECT_CALL(cid_manager_visitor_,
              SendNewConnectionId(ExpectedNewConnectionIdFrame(cid1, 1u, 0u)))
      .WillOnce(Return(true));
  cid_manager_.MaybeSendNewConnectionIds();

  {
    // Peer retires CID #0;
    // Sends CID #2 and asks peer to retire CIDs prior to #1.
    // Outcome: (#1, #2) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid2))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid2, 2u, 1u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 0u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #1;
    // Sends CID #3 and asks peer to retire CIDs prior to #2.
    // Outcome: (#2, #3) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid3))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid3, 3u, 2u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 1u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #2;
    // Sends CID #4 and asks peer to retire CIDs prior to #3.
    // Outcome: (#3, #4) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid4))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid4, 4u, 3u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 2u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #3;
    // Sends CID #5 and asks peer to retire CIDs prior to #4.
    // Outcome: (#4, #5) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid5))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid5, 5u, 4u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 3u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }
}

TEST_F(QuicSelfIssuedConnectionIdManagerTest,
       RetireSelfIssuedConnectionIdOutOfOrder) {
  QuicConnectionId cid0 = initial_connection_id_;
  QuicConnectionId cid1 = CheckGenerate(cid0);
  QuicConnectionId cid2 = CheckGenerate(cid1);
  QuicConnectionId cid3 = CheckGenerate(cid2);
  QuicConnectionId cid4 = CheckGenerate(cid3);

  // Sends CID #1 to peer.
  EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid1))
      .WillOnce(Return(true));
  EXPECT_CALL(cid_manager_visitor_,
              SendNewConnectionId(ExpectedNewConnectionIdFrame(cid1, 1u, 0u)))
      .WillOnce(Return(true));
  cid_manager_.MaybeSendNewConnectionIds();

  {
    // Peer retires CID #1;
    // Sends CID #2 and asks peer to retire CIDs prior to #0.
    // Outcome: (#0, #2) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid2))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid2, 2u, 0u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 1u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #1 again. This is a no-op.
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 1u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #0;
    // Sends CID #3 and asks peer to retire CIDs prior to #2.
    // Outcome: (#2, #3) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid3))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid3, 3u, 2u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 0u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #3;
    // Sends CID #4 and asks peer to retire CIDs prior to #2.
    // Outcome: (#2, #4) are active.
    EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(cid4))
        .WillOnce(Return(true));
    EXPECT_CALL(cid_manager_visitor_,
                SendNewConnectionId(ExpectedNewConnectionIdFrame(cid4, 4u, 2u)))
        .WillOnce(Return(true));
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 3u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }

  {
    // Peer retires CID #0 again. This is a no-op.
    QuicRetireConnectionIdFrame retire_cid_frame;
    retire_cid_frame.sequence_number = 0u;
    ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                    retire_cid_frame, pto_delay_, &error_details_),
                IsQuicNoError());
  }
}

TEST_F(QuicSelfIssuedConnectionIdManagerTest,
       ScheduleConnectionIdRetirementOneAtATime) {
  QuicConnectionId cid0 = initial_connection_id_;
  QuicConnectionId cid1 = CheckGenerate(cid0);
  QuicConnectionId cid2 = CheckGenerate(cid1);
  QuicConnectionId cid3 = CheckGenerate(cid2);
  EXPECT_CALL(cid_manager_visitor_, MaybeReserveConnectionId(_))
      .Times(3)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(cid_manager_visitor_, SendNewConnectionId(_))
      .Times(3)
      .WillRepeatedly(Return(true));
  QuicTime::Delta connection_id_expire_timeout = 3 * pto_delay_;
  QuicRetireConnectionIdFrame retire_cid_frame;

  // CID #1 is sent to peer.
  cid_manager_.MaybeSendNewConnectionIds();

  // CID #0's retirement is scheduled and CID #2 is sent to peer.
  retire_cid_frame.sequence_number = 0u;
  ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                  retire_cid_frame, pto_delay_, &error_details_),
              IsQuicNoError());
  // While CID #0's retirement is scheduled, it is not retired yet.
  EXPECT_THAT(cid_manager_.GetUnretiredConnectionIds(),
              ElementsAre(cid0, cid1, cid2));
  EXPECT_TRUE(retire_self_issued_cid_alarm_->IsSet());
  EXPECT_EQ(retire_self_issued_cid_alarm_->deadline(),
            clock_.ApproximateNow() + connection_id_expire_timeout);

  // CID #0 is actually retired.
  EXPECT_CALL(cid_manager_visitor_, OnSelfIssuedConnectionIdRetired(cid0));
  clock_.AdvanceTime(connection_id_expire_timeout);
  alarm_factory_.FireAlarm(retire_self_issued_cid_alarm_);
  EXPECT_THAT(cid_manager_.GetUnretiredConnectionIds(),
              ElementsAre(cid1, cid2));
  EXPECT_FALSE(retire_self_issued_cid_alarm_->IsSet());

  // CID #1's retirement is scheduled and CID #3 is sent to peer.
  retire_cid_frame.sequence_number = 1u;
  ASSERT_THAT(cid_manager_.OnRetireConnectionIdFrame(
                  retire_cid_frame, pto_delay_, &error_details_),
              IsQuicNoError());
  // While CID #1's retirement is scheduled, it is not retired yet.
  EXPECT_THAT(cid_manager_.GetUnretiredConnectionIds(),
              ElementsAre(cid1, cid2, cid3));
  EXPECT_TRUE(retire_self_issued_cid_alarm_->IsSet());
  EXPECT_EQ(retire_self_issued_cid_alarm_->deadline(),
            clock_.ApproximateNow() + connection_id_expire_timeout);

  // CID #1 is actually retired.
  EXPECT_CALL(cid_manager_visitor_, OnSelfIssuedConnectionIdRetired(cid1));
  clock_.AdvanceTime(connection_id_expire_timeout);
  alarm_factory_.FireAlarm(retire_self_issued_cid_alarm_);
  EXPECT_THAT(cid_manager_.GetUnretiredConnectionIds(),
              ElementsAre(cid2, cid3));
  EXPECT_FALSE(retire_self_issued_cid_alarm_->IsSet());
}

TEST_F(QuicSelfIssuedConnectionIdManagerTest,
       ScheduleMultipleConnectionIdRetirement) {
  QuicConnectionId cid0 = initial_connection_id_;
  QuicConnectionId cid1 = CheckGenerate(cid0);
  QuicConnectionId cid2 = CheckGenerate(cid1);
  QuicConnectionId cid3 = CheckGenerate(cid2);
  EXPECT_CALL(cid_manager_visitor_, Ma
"""


```
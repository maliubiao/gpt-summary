Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc`. The request also asks for connections to JavaScript, examples of logical inference with input and output, common user/programming errors, and debugging steps. This is the first of three parts.

**Plan:**

1. **Identify the core purpose of the file:** Based on the file name and common software development practices, this file likely contains unit tests for the `MoqtSession` class.
2. **Analyze the included headers:** These provide clues about the functionalities being tested (e.g., `moqt_session.h`, `moqt_messages.h`, `web_transport/web_transport.h`).
3. **Examine the test cases:**  The `TEST_F` macros define individual test functions. Each test focuses on a specific aspect of the `MoqtSession`'s behavior.
4. **Summarize the tested functionalities:** Based on the test names and their content, categorize the functionalities being verified.
5. **Address the JavaScript connection:** Determine if any of the tested functionalities directly relate to how a web browser or JavaScript might interact with the MoQT protocol.
6. **Address logical inference:** Identify tests where specific inputs to `MoqtSession` methods lead to predictable outputs or state changes.
7. **Address user/programming errors:**  Look for tests that validate error handling or prevent misuse of the `MoqtSession` class.
8. **Address debugging steps:**  Consider how a developer might arrive at this specific test file during debugging.
9. **Focus on summarizing the overall functionality for Part 1.**  Leave the detailed examples for the subsequent parts.
这个C++源代码文件 `net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc` 是 Chromium 网络栈中 QUIC 协议的 MoQT (Media over QUIC Transport) 组件中 `MoqtSession` 类的单元测试文件。

**它的主要功能是：**

1. **验证 `MoqtSession` 类的各种功能和行为是否符合预期。** 这包括但不限于：
    * **会话的建立和关闭:** 测试客户端和服务端如何协商和建立 MoQT 会话，以及如何正常或异常地关闭会话。
    * **控制消息的处理:** 测试 `MoqtSession` 如何发送和接收各种 MoQT 控制消息，例如 `CLIENT_SETUP`, `SERVER_SETUP`, `SUBSCRIBE`, `UNSUBSCRIBE`, `ANNOUNCE` 等，并根据这些消息更新内部状态。
    * **订阅和发布机制:** 测试客户端如何订阅感兴趣的媒体轨道 (track)，服务端如何响应订阅请求，以及如何处理重复订阅或超出订阅限制的情况。
    * **错误处理:** 测试 `MoqtSession` 在遇到各种错误情况时（例如，参数错误、协议违规等）如何报告和处理错误。
    * **优先级管理:** 虽然在这个给定的部分没有明确的测试用例，但从引入的头文件 `moqt_priority.h` 可以推断，测试文件也可能包含对订阅优先级相关功能的测试。
    * **与 WebTransport 的集成:**  由于 MoQT 基于 WebTransport，测试会验证 `MoqtSession` 如何与底层的 `webtransport::Session` 和 `webtransport::Stream` 进行交互。

**与 JavaScript 功能的关系：**

MoQT 协议旨在为 Web 应用程序提供实时的、基于 QUIC 的媒体传输能力。 虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但它所测试的 `MoqtSession` 类是实现 MoQT 协议的关键部分，直接影响到 JavaScript 如何使用 MoQT。

**举例说明:**

假设一个 JavaScript Web 应用程序想要接收一个名为 `foo/bar` 的媒体轨道。  在 JavaScript 中，这可能会通过一个 MoQT 客户端库来完成，该库最终会调用底层的 C++ 代码。

1. **JavaScript 发起订阅:** JavaScript 代码会调用 MoQT 客户端库的订阅方法，指定要订阅的轨道名称 `foo/bar`。
2. **C++ `MoqtSession` 发送 SUBSCRIBE 消息:** 客户端 MoQT 库会将订阅请求转换为 MoQT 的 `SUBSCRIBE` 消息，并由客户端 `MoqtSession` 对象通过 WebTransport 连接发送到服务端。
3. **测试验证 SUBSCRIBE 消息的发送:**  在这个测试文件中，类似 `TEST_F(MoqtSessionTest, AddLocalTrack)` 的测试会模拟接收到 `SUBSCRIBE` 消息的情况，并验证客户端 `MoqtSession` 是否正确地构造并发送了该消息。
4. **服务端 `MoqtSession` 处理 SUBSCRIBE 消息:** 服务端的 `MoqtSession` 接收到 `SUBSCRIBE` 消息后，会根据其内部状态和发布的轨道信息进行处理。
5. **测试验证 SUBSCRIBE 消息的处理:** 这个测试文件中的其他测试，例如 `TEST_F(MoqtSessionTest, SubscribeForPast)` 或 `TEST_F(MoqtSessionTest, TwoSubscribesForTrack)`，会验证服务端 `MoqtSession` 如何根据不同的订阅请求（例如，请求过去的媒体数据，或重复订阅同一个轨道）做出正确的响应（发送 `SUBSCRIBE_OK` 或 `SUBSCRIBE_ERROR` 消息）。
6. **JavaScript 接收媒体数据:** 如果订阅成功，服务端会将媒体数据封装成 MoQT 的数据消息并通过 WebTransport 连接发送给客户端。 客户端的 MoQT 库会将这些数据传递给 JavaScript 应用程序。

**逻辑推理、假设输入与输出：**

考虑 `TEST_F(MoqtSessionTest, OnSessionReady)` 测试用例：

* **假设输入:**  `MoqtSession` 对象作为客户端，并且底层的 `webtransport::Session` 准备就绪（`OnSessionReady` 被调用）。
* **逻辑推理:**  根据 MoQT 协议，客户端在会话建立后应该立即发送 `CLIENT_SETUP` 消息到控制流。
* **预期输出:**
    * `mock_session_.OpenOutgoingBidirectionalStream()` 被调用一次，用于创建控制流。
    * `mock_stream.Writev(_, _)` 被调用一次，并且发送的数据包含一个 `CLIENT_SETUP` 消息。
    * `ExtractMessageType(data[0])` 返回 `MoqtMessageType::kClientSetup`。

**用户或编程常见的使用错误：**

* **订阅 ID 超出限制:** 用户（或者更准确地说，使用 MoQT 客户端库的开发者）可能会尝试发送一个 `SUBSCRIBE` 消息，其 `subscribe_id` 大于服务端允许的最大值。 `TEST_F(MoqtSessionTest, SubscribeIdTooHigh)` 测试用例就是用来验证服务端 `MoqtSession` 是否正确地拒绝了这样的请求并关闭了会话。
* **重复订阅同一个轨道:** 用户可能会在没有取消订阅的情况下再次订阅同一个轨道。 `TEST_F(MoqtSessionTest, TwoSubscribesForTrack)` 测试用例验证了服务端 `MoqtSession` 会检测到这种情况并关闭会话以防止协议违规。
* **过早或过晚地调用 API:**  例如，在会话尚未建立完成时尝试发送订阅请求，或者在会话已经关闭后尝试发送数据。 虽然这个测试文件的片段没有直接测试这些情况，但 `MoqtSession` 的其他部分或相关的测试文件可能会覆盖这些场景。

**用户操作如何一步步的到达这里，作为调试线索：**

假设一个 Web 开发者在使用基于 Chromium 的浏览器开发一个实时媒体应用，该应用使用了 MoQT 协议。

1. **开发者遇到问题:**  应用在尝试订阅某个媒体轨道时失败，或者接收到的数据不正确。
2. **开启调试:** 开发者可能会使用浏览器的开发者工具查看网络请求，发现 MoQT 的控制消息或数据消息存在异常。
3. **定位到 MoQT 组件:** 开发者可能会查阅 Chromium 的源代码，了解 MoQT 组件的实现细节，并发现 `MoqtSession` 是处理会话管理和消息处理的核心类。
4. **查看单元测试:** 为了理解 `MoqtSession` 的预期行为，开发者会查找 `MoqtSession` 的单元测试文件，即 `net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc`。
5. **分析测试用例:** 开发者会查看具体的测试用例，例如 `TEST_F(MoqtSessionTest, AddLocalTrack)` 来理解订阅的流程，或者 `TEST_F(MoqtSessionTest, SubscribeWithError)` 来了解订阅失败时的错误处理。
6. **设置断点和日志:** 开发者可能会在 `MoqtSession` 的源代码中设置断点或添加日志，以便在应用程序运行时观察 `MoqtSession` 的内部状态和消息处理流程，从而定位问题的原因。
7. **参考单元测试进行修复:**  通过理解单元测试的逻辑和预期结果，开发者可以更好地理解 MoQT 协议的规范，并修复应用程序中的错误。

**归纳一下它的功能 (第1部分):**

这个 C++ 源代码文件是 `MoqtSession` 类的单元测试，其主要功能是验证 `MoqtSession` 在客户端和服务端场景下处理各种 MoQT 控制消息、管理会话状态、处理订阅请求和错误的能力。它通过模拟网络交互和消息传递，确保 `MoqtSession` 的实现符合 MoQT 协议的规范，并为开发者提供了一个理解和调试 MoQT 功能的基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>


#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

namespace {

using ::quic::test::MemSliceFromString;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Return;
using ::testing::StrictMock;

constexpr webtransport::StreamId kControlStreamId = 4;
constexpr webtransport::StreamId kIncomingUniStreamId = 15;
constexpr webtransport::StreamId kOutgoingUniStreamId = 14;

// Returns nullopt if there is not enough in |message| to extract a type
static std::optional<MoqtMessageType> ExtractMessageType(
    const absl::string_view message) {
  quic::QuicDataReader reader(message);
  uint64_t value;
  if (!reader.ReadVarInt62(&value)) {
    return std::nullopt;
  }
  return static_cast<MoqtMessageType>(value);
}

static std::shared_ptr<MockTrackPublisher> SetupPublisher(
    FullTrackName track_name, MoqtForwardingPreference forwarding_preference,
    FullSequence largest_sequence) {
  auto publisher = std::make_shared<MockTrackPublisher>(std::move(track_name));
  ON_CALL(*publisher, GetTrackStatus())
      .WillByDefault(Return(MoqtTrackStatusCode::kInProgress));
  ON_CALL(*publisher, GetForwardingPreference())
      .WillByDefault(Return(forwarding_preference));
  ON_CALL(*publisher, GetLargestSequence())
      .WillByDefault(Return(largest_sequence));
  return publisher;
}

}  // namespace

class MoqtSessionPeer {
 public:
  static std::unique_ptr<MoqtControlParserVisitor> CreateControlStream(
      MoqtSession* session, webtransport::test::MockStream* stream) {
    auto new_stream =
        std::make_unique<MoqtSession::ControlStream>(session, stream);
    session->control_stream_ = kControlStreamId;
    ON_CALL(*stream, visitor()).WillByDefault(Return(new_stream.get()));
    webtransport::test::MockSession* mock_session =
        static_cast<webtransport::test::MockSession*>(session->session());
    EXPECT_CALL(*mock_session, GetStreamById(kControlStreamId))
        .Times(AnyNumber())
        .WillRepeatedly(Return(stream));
    return new_stream;
  }

  static std::unique_ptr<MoqtDataParserVisitor> CreateIncomingDataStream(
      MoqtSession* session, webtransport::Stream* stream) {
    auto new_stream =
        std::make_unique<MoqtSession::IncomingDataStream>(session, stream);
    return new_stream;
  }

  // In the test OnSessionReady, the session creates a stream and then passes
  // its unique_ptr to the mock webtransport stream. This function casts
  // that unique_ptr into a MoqtSession::Stream*, which is a private class of
  // MoqtSession, and then casts again into MoqtParserVisitor so that the test
  // can inject packets into that stream.
  // This function is useful for any test that wants to inject packets on a
  // stream created by the MoqtSession.
  static MoqtControlParserVisitor*
  FetchParserVisitorFromWebtransportStreamVisitor(
      MoqtSession* session, webtransport::StreamVisitor* visitor) {
    return static_cast<MoqtSession::ControlStream*>(visitor);
  }

  static void CreateRemoteTrack(MoqtSession* session, const FullTrackName& name,
                                RemoteTrack::Visitor* visitor,
                                uint64_t track_alias) {
    session->remote_tracks_.try_emplace(track_alias, name, track_alias,
                                        visitor);
    session->remote_track_aliases_.try_emplace(name, track_alias);
  }

  static void AddActiveSubscribe(MoqtSession* session, uint64_t subscribe_id,
                                 MoqtSubscribe& subscribe,
                                 RemoteTrack::Visitor* visitor) {
    session->active_subscribes_[subscribe_id] = {subscribe, visitor};
  }

  static MoqtObjectListener* AddSubscription(
      MoqtSession* session, std::shared_ptr<MoqtTrackPublisher> publisher,
      uint64_t subscribe_id, uint64_t track_alias, uint64_t start_group,
      uint64_t start_object) {
    MoqtSubscribe subscribe;
    subscribe.full_track_name = publisher->GetTrackName();
    subscribe.track_alias = track_alias;
    subscribe.subscribe_id = subscribe_id;
    subscribe.start_group = start_group;
    subscribe.start_object = start_object;
    subscribe.subscriber_priority = 0x80;
    session->published_subscriptions_.emplace(
        subscribe_id, std::make_unique<MoqtSession::PublishedSubscription>(
                          session, std::move(publisher), subscribe,
                          /*monitoring_interface=*/nullptr));
    return session->published_subscriptions_[subscribe_id].get();
  }

  static void DeleteSubscription(MoqtSession* session, uint64_t subscribe_id) {
    session->published_subscriptions_.erase(subscribe_id);
  }

  static void UpdateSubscriberPriority(MoqtSession* session,
                                       uint64_t subscribe_id,
                                       MoqtPriority priority) {
    session->published_subscriptions_[subscribe_id]->set_subscriber_priority(
        priority);
  }

  static void set_peer_role(MoqtSession* session, MoqtRole role) {
    session->peer_role_ = role;
  }

  static RemoteTrack& remote_track(MoqtSession* session, uint64_t track_alias) {
    return session->remote_tracks_.find(track_alias)->second;
  }

  static void set_next_subscribe_id(MoqtSession* session, uint64_t id) {
    session->next_subscribe_id_ = id;
  }

  static void set_peer_max_subscribe_id(MoqtSession* session, uint64_t id) {
    session->peer_max_subscribe_id_ = id;
  }
};

class MoqtSessionTest : public quic::test::QuicTest {
 public:
  MoqtSessionTest()
      : session_(&mock_session_,
                 MoqtSessionParameters(quic::Perspective::IS_CLIENT, ""),
                 session_callbacks_.AsSessionCallbacks()) {
    session_.set_publisher(&publisher_);
    MoqtSessionPeer::set_peer_max_subscribe_id(&session_,
                                               kDefaultInitialMaxSubscribeId);
  }
  ~MoqtSessionTest() {
    EXPECT_CALL(session_callbacks_.session_deleted_callback, Call());
  }

  MockSessionCallbacks session_callbacks_;
  StrictMock<webtransport::test::MockSession> mock_session_;
  MoqtSession session_;
  MoqtKnownTrackPublisher publisher_;
};

TEST_F(MoqtSessionTest, Queries) {
  EXPECT_EQ(session_.perspective(), quic::Perspective::IS_CLIENT);
}

// Verify the session sends CLIENT_SETUP on the control stream.
TEST_F(MoqtSessionTest, OnSessionReady) {
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillOnce(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] { return visitor.get(); });
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kClientSetup);
        return absl::OkStatus();
      });
  session_.OnSessionReady();
  EXPECT_TRUE(correct_message);

  // Receive SERVER_SETUP
  MoqtControlParserVisitor* stream_input =
      MoqtSessionPeer::FetchParserVisitorFromWebtransportStreamVisitor(
          &session_, visitor.get());
  // Handle the server setup
  MoqtServerSetup setup = {
      kDefaultMoqtVersion,
      MoqtRole::kPubSub,
  };
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnServerSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnClientSetup) {
  MoqtSession server_session(
      &mock_session_, MoqtSessionParameters(quic::Perspective::IS_SERVER),
      session_callbacks_.AsSessionCallbacks());
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream);
  MoqtClientSetup setup = {
      /*supported_versions=*/{kDefaultMoqtVersion},
      /*role=*/MoqtRole::kPubSub,
      /*path=*/std::nullopt,
  };
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kServerSetup);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream, GetStreamId()).WillOnce(Return(0));
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnClientSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnSessionClosed) {
  bool reported_error = false;
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = true;
        EXPECT_EQ(error_message, "foo");
      });
  session_.OnSessionClosed(webtransport::SessionErrorCode(1), "foo");
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, OnIncomingBidirectionalStream) {
  ::testing::InSequence seq;
  webtransport::test::MockStream mock_stream;
  StrictMock<webtransport::test::MockStreamVisitor> mock_stream_visitor;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, visitor()).WillOnce(Return(&mock_stream_visitor));
  EXPECT_CALL(mock_stream_visitor, OnCanRead()).Times(1);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(nullptr));
  session_.OnIncomingBidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, OnIncomingUnidirectionalStream) {
  ::testing::InSequence seq;
  webtransport::test::MockStream mock_stream;
  StrictMock<webtransport::test::MockStreamVisitor> mock_stream_visitor;
  EXPECT_CALL(mock_session_, AcceptIncomingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, visitor()).WillOnce(Return(&mock_stream_visitor));
  EXPECT_CALL(mock_stream_visitor, OnCanRead()).Times(1);
  EXPECT_CALL(mock_session_, AcceptIncomingUnidirectionalStream())
      .WillOnce(Return(nullptr));
  session_.OnIncomingUnidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, Error) {
  bool reported_error = false;
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kParameterLengthMismatch),
                   "foo"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "foo");
      });
  session_.Error(MoqtError::kParameterLengthMismatch, "foo");
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, AddLocalTrack) {
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  // Request for track returns SUBSCRIBE_ERROR.
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeError);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);

  // Add the track. Now Subscribe should succeed.
  auto track_publisher =
      std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"));
  EXPECT_CALL(*track_publisher, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kStatusNotAvailable));
  publisher_.Add(track_publisher);
  correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithOk) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kAnnounce);
        return absl::OkStatus();
      });
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction());
  EXPECT_TRUE(correct_message);

  MoqtAnnounceOk ok = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        correct_message = true;
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        EXPECT_FALSE(error.has_value());
      });
  stream_input->OnAnnounceOkMessage(ok);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithError) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kAnnounce);
        return absl::OkStatus();
      });
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction());
  EXPECT_TRUE(correct_message);

  MoqtAnnounceError error = {
      /*track_namespace=*/FullTrackName{"foo"},
      /*error_code=*/MoqtAnnounceErrorCode::kInternalError,
      /*reason_phrase=*/"Test error",
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        correct_message = true;
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, MoqtAnnounceErrorCode::kInternalError);
        EXPECT_EQ(error->reason_phrase, "Test error");
      });
  stream_input->OnAnnounceErrorMessage(error);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeForPast) {
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);

  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeError);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, TwoSubscribesForTrack) {
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);

  // Peer subscribes to (11, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/11,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);

  request.subscribe_id = 2;
  request.start_group = 12;
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Duplicate subscribe for track"))
      .Times(1);
  stream_input->OnSubscribeMessage(request);
  ;
}

TEST_F(MoqtSessionTest, UnsubscribeAllowsSecondSubscribe) {
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);

  // Peer subscribes to (11, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/11,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);

  // Peer unsubscribes.
  MoqtUnsubscribe unsubscribe = {
      /*subscribe_id=*/1,
  };
  correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeDone);
        return absl::OkStatus();
      });
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_TRUE(correct_message);

  // Subscribe again, succeeds.
  request.subscribe_id = 2;
  request.start_group = 12;
  correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeIdTooHigh) {
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/kDefaultInitialMaxSubscribeId + 1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kTooManySubscribes),
                           "Received SUBSCRIBE with too large ID"))
      .Times(1);
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, TooManySubscribes) {
  MoqtSessionPeer::set_next_subscribe_id(&session_,
                                         kDefaultInitialMaxSubscribeId);
  MockRemoteTrackVisitor remote_track_visitor;
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  EXPECT_TRUE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                             &remote_track_visitor));
  EXPECT_FALSE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                              &remote_track_visitor));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeWithOk) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MockRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                 &remote_track_visitor);

  MoqtSubscribeOk ok = {
      /*subscribe_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  correct_message = false;
  EXPECT_CALL(remote_track_visitor, OnReply(_, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<absl::string_view> error_message) {
        correct_message = true;
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_FALSE(error_message.has_value());
      });
  stream_input->OnSubscribeOkMessage(ok);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, MaxSubscribeIdChangesResponse) {
  MoqtSessionPeer::set_next_subscribe_id(&session_,
                                         kDefaultInitialMaxSubscribeId + 1);
  MockRemoteTrackVisitor remote_track_visitor;
  EXPECT_FALSE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                              &remote_track_visitor));
  MoqtMaxSubscribeId max_subscribe_id = {
      /*max_subscribe_id=*/kDefaultInitialMaxSubscribeId + 1,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  stream_input->OnMaxSubscribeIdMessage(max_subscribe_id);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  EXPECT_TRUE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                             &remote_track_visitor));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, LowerMaxSubscribeIdIsAnError) {
  MoqtMaxSubscribeId max_subscribe_id = {
      /*max_subscribe_id=*/kDefaultInitialMaxSubscribeId - 1,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                   "MAX_SUBSCRIBE_ID message has lower value than previous"))
      .Times(1);
  stream_input->OnMaxSubscribeIdMessage(max_subscribe_id);
}

TEST_F(MoqtSessionTest, GrantMoreSubscribes) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kMaxSubscribeId);
        return absl::OkStatus();
      });
  session_.GrantMoreSubscribes(1);
  EXPECT_TRUE(correct_message);
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/kDefaultInitialMaxSubscribeId + 1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/10,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  correct_message = false;
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeWithError) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MockRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                 &remote_track_visitor);

  MoqtSubscribeError error = {
      /*subscribe_id=*/0,
      /*error_code=*/SubscribeErrorCode::kInvalidRange,
      /*reason_phrase=*/"deadbeef",
      /*track_alias=*/2,
  };
  correct_message = false;
  EXPECT_CALL(remote_track_visitor, OnReply(_, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<absl::string_view> error_message) {
        correct_message = true;
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_EQ(*error_message, "deadbeef");
      });
  stream_input->OnSubscribeErrorMessage(error);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, ReplyToAnnounce) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtAnnounce announce = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  bool correct_message = false;
  EXPECT_CALL(session_callbacks_.incoming_announce_callback,
        
"""


```
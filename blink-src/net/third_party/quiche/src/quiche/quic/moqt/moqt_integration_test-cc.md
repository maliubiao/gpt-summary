Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Purpose:** The file name `moqt_integration_test.cc` immediately suggests this is for integration testing of the MoQT (Media over QUIC Transport) protocol implementation within Chromium's network stack. Integration tests verify that different components work together correctly.

2. **Identify Key Components:**  Scan the includes and the class names within the file. This reveals the main actors and concepts:
    * `MoqtClientEndpoint`, `MoqtServerEndpoint`:  Represent the client and server sides of a MoQT connection.
    * `MoqtSession`:  Manages the state of a MoQT session.
    * `MoqtTrack`, `MoqtKnownTrackPublisher`, `MoqtOutgoingQueue`: Deal with the concept of "tracks" (media streams) and publishing data.
    * `MockSessionCallbacks`, `MockRemoteTrackVisitor`:  Test doubles used to observe and control the behavior of the MoQT implementation.
    * `quic::simulator::TestHarness`:  A framework for simulating network conditions and interactions.
    * `FullTrackName`: Represents the identifier for a MoQT track.
    * Various `Moqt...` message types (implied by includes like `moqt_messages.h`).

3. **Analyze the Test Fixture (`MoqtIntegrationTest`):** This class sets up the common environment for the tests.
    * `CreateDefaultEndpoints()`:  Instantiates the client and server endpoints.
    * `SetupCallbacks()`:  Assigns the mock callback objects to the client and server sessions. This is crucial for observing events.
    * `WireUpEndpoints()`: Connects the simulated endpoints.
    * `ConnectEndpoints()`: Simulates the QUIC handshake and waits for session establishment.
    * `EstablishSession()`: A convenience function that combines the previous steps.

4. **Examine Individual Tests:** Go through each `TEST_F` function to understand the specific scenario being tested. For each test:
    * **Identify the Goal:** What aspect of MoQT functionality is being validated? (e.g., handshake, version negotiation, announcing tracks, subscribing to tracks, sending data, handling errors).
    * **Trace the Setup:**  How is the test environment configured?  Are mock objects used to control behavior?
    * **Look for Expectations (`EXPECT_CALL`):** These are the core of the tests. They specify what interactions are expected to occur between the client and server, and with the mock objects. Pay close attention to the arguments passed to the mock methods.
    * **Understand the Assertions (`EXPECT_TRUE`, `EXPECT_EQ`, etc.):** These verify that the actual behavior matches the expected behavior.
    * **Consider the `RunUntilWithDefaultTimeout` Call:** This is how the simulation advances and waits for events to occur. The lambda function inside defines the condition for success.

5. **Identify Connections to JavaScript (If Any):** At this level of integration testing in the Chromium network stack, the direct connection to JavaScript is likely *indirect*. MoQT is a lower-level protocol. Think about how JavaScript might *use* MoQT. The most likely scenario is through WebTransport, which can use QUIC as its underlying transport and could potentially be extended to support MoQT. Therefore, the connection is that this code is *part of the infrastructure* that could eventually be exposed to JavaScript via a higher-level API like WebTransport.

6. **Consider Logical Reasoning (Assumptions and Outputs):**  For tests involving specific MoQT interactions (announce, subscribe, send data), consider the input and expected output at the *MoQT message level*. For example, in `AnnounceSuccess`, the assumption is the client sends an ANNOUNCE message for "foo". The expected output on the server is the `incoming_announce_callback` being called with "foo". On the client, the `announce_callback` should be invoked without an error.

7. **Think About User/Programming Errors:**  Common errors in network programming involve things like:
    * **Version mismatches:** The `VersionMismatch` test directly addresses this.
    * **Incorrect track names:** While not explicitly tested with invalid names, the tests implicitly check that valid names are handled correctly.
    * **Trying to subscribe to non-existent tracks:** The `SubscribeError` test demonstrates this scenario.
    * **Incorrect usage of the MoQT API:**  For example, calling `Announce` without a server that supports it.

8. **Trace User Actions to This Code (Debugging Clues):**  Imagine a user streaming media in a browser. The path might look like this:
    * User opens a website that uses a real-time media streaming service.
    * The website's JavaScript code uses WebTransport (or a similar API) to establish a connection to the server.
    * The browser's network stack negotiates the underlying QUIC connection.
    * The application protocol used over QUIC is MoQT.
    * The JavaScript code might initiate an "announce" to publish a media stream or "subscribe" to consume one.
    * These actions translate into MoQT messages being sent over the QUIC connection.
    * This `moqt_integration_test.cc` code simulates this low-level message exchange to ensure the MoQT implementation is correct. A developer debugging a streaming issue might look at these tests to understand how the MoQT layer *should* be behaving.

9. **Refine and Organize:**  Structure the answer logically, using headings and bullet points to make it easy to read and understand. Start with a high-level summary and then go into more detail. Provide concrete examples where possible.
这个文件 `net/third_party/quiche/src/quiche/quic/moqt/moqt_integration_test.cc` 是 Chromium 网络栈中 QUIC 协议的 MoQT (Media over QUIC Transport) 组件的集成测试文件。它的主要功能是：

**主要功能:**

1. **端到端 MoQT 协议流程测试:**  它模拟了客户端和服务器之间的 MoQT 协议交互，涵盖了从连接建立到数据传输的各个阶段，验证了 MoQT 协议实现的正确性和完整性。
2. **连接建立和版本协商:** 测试了客户端和服务器之间建立 MoQT 连接的过程，包括版本协商，以及处理版本不匹配的情况。
3. **ANNOUNCE (声明) 功能测试:**  测试了客户端向服务器声明可用的 track namespace (轨道命名空间) 的功能，包括成功声明和声明失败的情况。
4. **SUBSCRIBE (订阅) 功能测试:** 测试了客户端向服务器订阅特定 track (轨道) 的功能，包括绝对订阅、订阅当前对象和订阅当前组，以及订阅成功和失败的情况。
5. **数据发送功能测试:** 测试了服务器向客户端发送 track 数据的功能，包括发送多个数据对象和分组。
6. **OBJECT_ACK (对象确认) 功能测试:** 测试了客户端确认接收到特定对象的功能，以及服务器如何处理这些确认。
7. **错误处理测试:**  测试了 MoQT 协议中各种错误场景的处理，例如版本不匹配、声明失败、订阅失败等。
8. **不同转发偏好 (Forwarding Preference) 的测试:**  测试了使用不同的转发偏好 (Track, Subgroup, Datagram) 发送数据时的行为。
9. **使用 Mock 对象进行隔离测试:**  使用 `MockSessionCallbacks` 和 `MockRemoteTrackVisitor` 等 Mock 对象来隔离被测试的组件，并验证其行为是否符合预期。
10. **使用模拟器 (Simulator) 进行网络环境模拟:**  使用 `quic::simulator::TestHarness` 来模拟网络环境，控制消息的发送和接收，以及时间推进。

**与 Javascript 功能的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但 MoQT 作为一种应用层协议，其最终目的是为 Web 应用提供高效的实时媒体传输能力。JavaScript 代码可以通过浏览器提供的 WebTransport API 或未来可能出现的其他相关 API 来使用 MoQT 协议。

**举例说明:**

假设一个基于 Web 的实时视频流应用使用了 MoQT 协议：

1. **JavaScript 发起声明 (ANNOUNCE):**  前端 JavaScript 代码可能调用 WebTransport 提供的 API，构建一个 MoQT ANNOUNCE 消息，声明服务器可以提供名为 `live/camera1` 的视频流。这个操作最终会触发 C++ 代码中 `client_->session()->Announce(FullTrackName{"live/camera1"}, ...)` 这样的调用。
2. **JavaScript 发起订阅 (SUBSCRIBE):** 客户端 JavaScript 代码想要观看 `live/camera1` 的视频流，它会调用 WebTransport API 发送一个 MoQT SUBSCRIBE 消息，订阅该 track。这会对应到 C++ 代码中的 `client_->session()->SubscribeCurrentGroup(FullTrackName("live", "camera1"), &client_visitor);`。
3. **服务器发送数据:**  服务器端（也可能使用 C++ 或其他语言实现 MoQT 服务）接收到订阅请求后，会将视频数据封装成 MoQT 的数据对象 (Object)，通过 QUIC 连接发送给客户端。客户端的 C++ 代码接收到这些数据包，并通过 `client_visitor` 的回调函数 (例如 `OnObjectFragment`) 将数据传递给上层。
4. **JavaScript 处理接收到的数据:**  客户端 JavaScript 代码通过 WebTransport API 接收到从 C++ 层传递上来的视频数据，并将其解码显示在网页上。

**逻辑推理 (假设输入与输出):**

**测试用例: `AnnounceSuccess`**

* **假设输入 (客户端操作):**
    * 客户端 MoQT 会话调用 `Announce(FullTrackName{"foo"})`。
* **预期输出 (服务器端行为):**
    * 服务器端的 `incoming_announce_callback` 被调用，参数为 `FullTrackName{"foo"}`。
    * 服务器端返回声明成功的指示 (例如，不返回错误)。
* **预期输出 (客户端行为):**
    * 客户端的 `announce_callback` 被调用，`error_message` 参数为 `std::nullopt` (表示成功)。

**测试用例: `SubscribeAbsoluteOk`**

* **假设输入 (客户端操作):**
    * 客户端 MoQT 会话调用 `SubscribeAbsolute(FullTrackName("foo", "bar"), 0, 0, &client_visitor)`。
    * 服务器端存在一个名为 "foo/bar" 的 track 发布者。
* **预期输出 (服务器端行为):**
    * 服务器端处理订阅请求，并认为订阅是有效的。
* **预期输出 (客户端行为):**
    * 客户端的 `client_visitor` 的 `OnReply` 方法被调用，参数为 `FullTrackName("foo", "bar")` 和 `std::nullopt` (表示订阅成功)。

**用户或编程常见的使用错误及举例说明:**

1. **版本不匹配:**
   * **错误:** 客户端和服务器配置了不同的 MoQT 协议版本。
   * **测试用例对应:** `VersionMismatch` 测试用例模拟了这种情况。
   * **现象:** 连接建立失败，双方会话被终止。
2. **尝试声明已存在的命名空间:** (虽然此测试文件中没有显式测试，但可以推断)
   * **错误:** 客户端尝试声明一个已经被其他发布者声明的 track namespace。
   * **可能现象:** 服务器返回一个错误，例如 `MoqtAnnounceErrorCode::kAlreadyExists`。
3. **订阅不存在的 Track:**
   * **错误:** 客户端尝试订阅一个服务器上没有发布的 track。
   * **测试用例对应:** `SubscribeError` 测试用例模拟了这种情况。
   * **现象:** 服务器返回一个错误，例如 `absl::string_view expected_reason = "No tracks published"`。
4. **不正确的 Track 名称格式:**
   * **错误:** 客户端在声明或订阅时使用了格式错误的 track 名称。
   * **可能现象:** 服务器无法解析 track 名称，返回语法错误或找不到 track 的错误。
5. **过早或过晚发送数据:**
   * **错误:** 发布者在没有收到订阅请求之前就发送数据，或者在订阅结束后仍然发送数据。
   * **可能现象:** 客户端可能无法正确接收或处理这些数据。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用一个在线协作的音视频编辑工具，该工具使用了 MoQT 进行低延迟的媒体同步：

1. **用户打开网页:** 用户在浏览器中输入网址，打开该在线编辑工具的网页。
2. **网页加载 JavaScript 代码:** 浏览器下载并执行网页的 JavaScript 代码。
3. **JavaScript 初始化 MoQT 连接:** JavaScript 代码使用 WebTransport API (或者未来可能出现的 MoQT 相关的 API) 连接到服务器，开始 MoQT 会话的握手过程。
4. **MoQT 版本协商:**  客户端的 MoQT 实现 (C++ 代码) 发送支持的 MoQT 版本给服务器。服务器进行版本匹配，如果版本不一致，就会触发 `moqt_integration_test.cc` 中的 `VersionMismatch` 测试用例所模拟的场景。
5. **用户加入协作会话:** 用户在界面上点击“加入会话”按钮。
6. **JavaScript 发起订阅请求:**  JavaScript 代码根据当前会话的 track 名称 (例如，共享的编辑时间线) 构建一个 MoQT SUBSCRIBE 消息，并发送给服务器。这对应于 `moqt_integration_test.cc` 中的 `SubscribeAbsoluteOk` 或类似的测试用例场景。
7. **服务器发送媒体数据:** 服务器接收到订阅请求后，开始将共享的媒体数据 (例如，音频波形数据、视频帧数据) 分割成 MoQT 对象，并通过 QUIC 连接发送给客户端。
8. **客户端接收并处理数据:** 客户端的 MoQT 实现接收到数据，并通过回调函数将数据传递给 JavaScript 代码。
9. **JavaScript 更新界面:** JavaScript 代码接收到媒体数据后，更新用户界面，例如，实时显示其他用户的编辑操作。

**调试线索:**

如果在上述过程中出现问题，例如：

* **连接建立失败:**  可能是版本不匹配，需要检查客户端和服务器的 MoQT 版本配置 (对应 `VersionMismatch` 测试)。
* **无法看到共享的媒体数据:** 可能是订阅失败，需要检查客户端发送的 SUBSCRIBE 消息是否正确，服务器是否正确处理了订阅请求 (对应 `SubscribeError` 或 `SubscribeAbsoluteOk` 等测试)。
* **数据延迟或丢失:**  可能与数据发送过程中的错误有关，需要检查服务器的数据发布逻辑 (对应 `SendMultipleGroups` 等测试)。
* **对象确认机制问题:** 如果使用了对象确认，需要检查客户端是否正确发送了 ACK 消息，服务器是否正确处理了 ACK 消息 (对应 `ObjectAcks` 测试)。

因此，`moqt_integration_test.cc` 文件中的测试用例可以作为调试时的参考，帮助开发者理解 MoQT 协议的各个环节，并验证 Chromium 中 MoQT 实现的正确性，从而定位和解决用户在使用相关功能时可能遇到的问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_integration_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_generic_session.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_outgoing_queue.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/test_tools/moqt_simulator_harness.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/test_harness.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::test {

namespace {

using ::quic::test::MemSliceFromString;
using ::testing::_;
using ::testing::Assign;
using ::testing::Return;

class MoqtIntegrationTest : public quiche::test::QuicheTest {
 public:
  void CreateDefaultEndpoints() {
    client_ = std::make_unique<MoqtClientEndpoint>(
        &test_harness_.simulator(), "Client", "Server", kDefaultMoqtVersion);
    server_ = std::make_unique<MoqtServerEndpoint>(
        &test_harness_.simulator(), "Server", "Client", kDefaultMoqtVersion);
    SetupCallbacks();
    test_harness_.set_client(client_.get());
    test_harness_.set_server(server_.get());
  }
  void SetupCallbacks() {
    client_->session()->callbacks() = client_callbacks_.AsSessionCallbacks();
    server_->session()->callbacks() = server_callbacks_.AsSessionCallbacks();
  }

  void WireUpEndpoints() { test_harness_.WireUpEndpoints(); }
  void ConnectEndpoints() {
    client_->quic_session()->CryptoConnect();
    bool client_established = false;
    bool server_established = false;
    EXPECT_CALL(client_callbacks_.session_established_callback, Call())
        .WillOnce(Assign(&client_established, true));
    EXPECT_CALL(server_callbacks_.session_established_callback, Call())
        .WillOnce(Assign(&server_established, true));
    bool success = test_harness_.RunUntilWithDefaultTimeout(
        [&]() { return client_established && server_established; });
    QUICHE_CHECK(success);
  }

  void EstablishSession() {
    CreateDefaultEndpoints();
    WireUpEndpoints();
    ConnectEndpoints();
  }

 protected:
  quic::simulator::TestHarness test_harness_;

  MockSessionCallbacks client_callbacks_;
  MockSessionCallbacks server_callbacks_;
  std::unique_ptr<MoqtClientEndpoint> client_;
  std::unique_ptr<MoqtServerEndpoint> server_;
};

TEST_F(MoqtIntegrationTest, Handshake) {
  CreateDefaultEndpoints();
  WireUpEndpoints();

  client_->quic_session()->CryptoConnect();
  bool client_established = false;
  bool server_established = false;
  EXPECT_CALL(client_callbacks_.session_established_callback, Call())
      .WillOnce(Assign(&client_established, true));
  EXPECT_CALL(server_callbacks_.session_established_callback, Call())
      .WillOnce(Assign(&server_established, true));
  bool success = test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return client_established && server_established; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, VersionMismatch) {
  client_ = std::make_unique<MoqtClientEndpoint>(
      &test_harness_.simulator(), "Client", "Server",
      MoqtVersion::kUnrecognizedVersionForTests);
  server_ = std::make_unique<MoqtServerEndpoint>(
      &test_harness_.simulator(), "Server", "Client", kDefaultMoqtVersion);
  SetupCallbacks();
  test_harness_.set_client(client_.get());
  test_harness_.set_server(server_.get());
  WireUpEndpoints();

  client_->quic_session()->CryptoConnect();
  bool client_terminated = false;
  bool server_terminated = false;
  EXPECT_CALL(client_callbacks_.session_established_callback, Call()).Times(0);
  EXPECT_CALL(server_callbacks_.session_established_callback, Call()).Times(0);
  EXPECT_CALL(client_callbacks_.session_terminated_callback, Call(_))
      .WillOnce(Assign(&client_terminated, true));
  EXPECT_CALL(server_callbacks_.session_terminated_callback, Call(_))
      .WillOnce(Assign(&server_terminated, true));
  bool success = test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return client_terminated && server_terminated; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, AnnounceSuccess) {
  EstablishSession();
  EXPECT_CALL(server_callbacks_.incoming_announce_callback,
              Call(FullTrackName{"foo"}))
      .WillOnce(Return(std::nullopt));
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_callback;
  client_->session()->Announce(FullTrackName{"foo"},
                               announce_callback.AsStdFunction());
  bool matches = false;
  EXPECT_CALL(announce_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        matches = true;
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        EXPECT_FALSE(error.has_value());
      });
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return matches; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, AnnounceSuccessSubscribeInResponse) {
  EstablishSession();
  EXPECT_CALL(server_callbacks_.incoming_announce_callback,
              Call(FullTrackName{"foo"}))
      .WillOnce(Return(std::nullopt));
  MockRemoteTrackVisitor server_visitor;
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_callback;
  client_->session()->Announce(FullTrackName{"foo"},
                               announce_callback.AsStdFunction());
  bool matches = false;
  EXPECT_CALL(announce_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        FullTrackName track_name = track_namespace;
        track_name.AddElement("/catalog");
        EXPECT_FALSE(error.has_value());
        server_->session()->SubscribeCurrentGroup(track_name, &server_visitor);
      });
  EXPECT_CALL(server_visitor, OnReply(_, _)).WillOnce([&]() {
    matches = true;
  });
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return matches; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, AnnounceSuccessSendDataInResponse) {
  EstablishSession();

  // Set up the server to subscribe to "data" track for the namespace announce
  // it receives.
  MockRemoteTrackVisitor server_visitor;
  EXPECT_CALL(server_callbacks_.incoming_announce_callback, Call(_))
      .WillOnce([&](FullTrackName track_namespace) {
        FullTrackName track_name = track_namespace;
        track_name.AddElement("data");
        server_->session()->SubscribeAbsolute(
            track_name, /*start_group=*/0, /*start_object=*/0, &server_visitor);
        return std::optional<MoqtAnnounceErrorReason>();
      });

  auto queue = std::make_shared<MoqtOutgoingQueue>(
      FullTrackName{"test", "data"}, MoqtForwardingPreference::kSubgroup);
  MoqtKnownTrackPublisher known_track_publisher;
  known_track_publisher.Add(queue);
  client_->session()->set_publisher(&known_track_publisher);
  queue->AddObject(MemSliceFromString("object data"), /*key=*/true);
  bool received_subscribe_ok = false;
  EXPECT_CALL(server_visitor, OnReply(_, _)).WillOnce([&]() {
    received_subscribe_ok = true;
  });
  client_->session()->Announce(
      FullTrackName{"test"},
      [](FullTrackName, std::optional<MoqtAnnounceErrorReason>) {});

  bool received_object = false;
  EXPECT_CALL(server_visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority /*publisher_priority*/,
                    MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view object, bool end_of_message) {
        EXPECT_EQ(full_track_name, FullTrackName("test", "data"));
        EXPECT_EQ(sequence.group, 0u);
        EXPECT_EQ(sequence.object, 0u);
        EXPECT_EQ(status, MoqtObjectStatus::kNormal);
        EXPECT_EQ(forwarding_preference, MoqtForwardingPreference::kSubgroup);
        EXPECT_EQ(object, "object data");
        EXPECT_TRUE(end_of_message);
        received_object = true;
      });
  bool success = test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return received_object; });
  EXPECT_TRUE(received_subscribe_ok);
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SendMultipleGroups) {
  EstablishSession();
  MoqtKnownTrackPublisher publisher;
  server_->session()->set_publisher(&publisher);

  for (MoqtForwardingPreference forwarding_preference :
       {MoqtForwardingPreference::kTrack, MoqtForwardingPreference::kSubgroup,
        MoqtForwardingPreference::kDatagram}) {
    SCOPED_TRACE(MoqtForwardingPreferenceToString(forwarding_preference));
    MockRemoteTrackVisitor client_visitor;
    std::string name =
        absl::StrCat("pref_", static_cast<int>(forwarding_preference));
    auto queue = std::make_shared<MoqtOutgoingQueue>(
        FullTrackName{"test", name}, MoqtForwardingPreference::kSubgroup);
    publisher.Add(queue);
    queue->AddObject(MemSliceFromString("object 1"), /*key=*/true);
    queue->AddObject(MemSliceFromString("object 2"), /*key=*/false);
    queue->AddObject(MemSliceFromString("object 3"), /*key=*/false);
    queue->AddObject(MemSliceFromString("object 4"), /*key=*/true);
    queue->AddObject(MemSliceFromString("object 5"), /*key=*/false);

    client_->session()->SubscribeCurrentGroup(FullTrackName("test", name),
                                              &client_visitor);
    int received = 0;
    EXPECT_CALL(client_visitor, OnObjectFragment(_, FullSequence{1, 0}, _,
                                                 MoqtObjectStatus::kNormal, _,
                                                 "object 4", true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor, OnObjectFragment(_, FullSequence{1, 1}, _,
                                                 MoqtObjectStatus::kNormal, _,
                                                 "object 5", true))
        .WillOnce([&] { ++received; });
    bool success = test_harness_.RunUntilWithDefaultTimeout(
        [&]() { return received >= 2; });
    EXPECT_TRUE(success);

    queue->AddObject(MemSliceFromString("object 6"), /*key=*/false);
    queue->AddObject(MemSliceFromString("object 7"), /*key=*/true);
    queue->AddObject(MemSliceFromString("object 8"), /*key=*/false);
    EXPECT_CALL(client_visitor, OnObjectFragment(_, FullSequence{1, 2}, _,
                                                 MoqtObjectStatus::kNormal, _,
                                                 "object 6", true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{1, 3}, _,
                                 MoqtObjectStatus::kEndOfGroup, _, "", true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor, OnObjectFragment(_, FullSequence{2, 0}, _,
                                                 MoqtObjectStatus::kNormal, _,
                                                 "object 7", true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor, OnObjectFragment(_, FullSequence{2, 1}, _,
                                                 MoqtObjectStatus::kNormal, _,
                                                 "object 8", true))
        .WillOnce([&] { ++received; });
    success = test_harness_.RunUntilWithDefaultTimeout(
        [&]() { return received >= 6; });
    EXPECT_TRUE(success);
  }
}

// TODO(martinduke): Restore this test when FETCH is implemented.
#if 0
TEST_F(MoqtIntegrationTest, FetchItemsFromPast) {
  EstablishSession();
  MoqtKnownTrackPublisher publisher;
  server_->session()->set_publisher(&publisher);

  for (MoqtForwardingPreference forwarding_preference :
       {MoqtForwardingPreference::kTrack, MoqtForwardingPreference::kSubgroup,
        MoqtForwardingPreference::kDatagram}) {
    SCOPED_TRACE(MoqtForwardingPreferenceToString(forwarding_preference));
    MockRemoteTrackVisitor client_visitor;
    std::string name =
        absl::StrCat("pref_", static_cast<int>(forwarding_preference));
    auto queue = std::make_shared<MoqtOutgoingQueue>(
        FullTrackName{"test", name}, forwarding_preference);
    publisher.Add(queue);
    for (int i = 0; i < 100; ++i) {
      queue->AddObject(MemSliceFromString("object"), /*key=*/true);
    }

    client_->session()->SubscribeAbsolute(FullTrackName("test", name), 0, 0,
                                          &client_visitor);
    int received = 0;
    // Those won't arrive since they have expired.
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{0, 0}, _, _, _, _, true))
        .Times(0);
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{0, 0}, _, _, _, _, true))
        .Times(0);
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{96, 0}, _, _, _, _, true))
        .Times(0);
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{96, 0}, _, _, _, _, true))
        .Times(0);
    // Those are within the "last three groups" window.
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{97, 0}, _, _, _, _, true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{97, 1}, _, _, _, _, true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{98, 0}, _, _, _, _, true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{98, 1}, _, _, _, _, true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{99, 0}, _, _, _, _, true))
        .WillOnce([&] { ++received; });
    EXPECT_CALL(client_visitor,
                OnObjectFragment(_, FullSequence{99, 1}, _, _, _, _, true))
        .Times(0);  // The current group should not be closed yet.
    bool success = test_harness_.RunUntilWithDefaultTimeout(
        [&]() { return received >= 5; });
    EXPECT_TRUE(success);
  }
}
#endif

TEST_F(MoqtIntegrationTest, AnnounceFailure) {
  EstablishSession();
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_callback;
  client_->session()->Announce(FullTrackName{"foo"},
                               announce_callback.AsStdFunction());
  bool matches = false;
  EXPECT_CALL(announce_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        matches = true;
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code,
                  MoqtAnnounceErrorCode::kAnnounceNotSupported);
      });
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return matches; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeAbsoluteOk) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");

  MoqtKnownTrackPublisher publisher;
  server_->session()->set_publisher(&publisher);
  auto track_publisher = std::make_shared<MockTrackPublisher>(full_track_name);
  publisher.Add(track_publisher);

  MockRemoteTrackVisitor client_visitor;
  std::optional<absl::string_view> expected_reason = std::nullopt;
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeAbsolute(full_track_name, 0, 0, &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeCurrentObjectOk) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");

  MoqtKnownTrackPublisher publisher;
  server_->session()->set_publisher(&publisher);
  auto track_publisher = std::make_shared<MockTrackPublisher>(full_track_name);
  publisher.Add(track_publisher);

  MockRemoteTrackVisitor client_visitor;
  std::optional<absl::string_view> expected_reason = std::nullopt;
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeCurrentObject(full_track_name, &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeCurrentGroupOk) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");

  MoqtKnownTrackPublisher publisher;
  server_->session()->set_publisher(&publisher);
  auto track_publisher = std::make_shared<MockTrackPublisher>(full_track_name);
  publisher.Add(track_publisher);

  MockRemoteTrackVisitor client_visitor;
  std::optional<absl::string_view> expected_reason = std::nullopt;
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeCurrentGroup(full_track_name, &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeError) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");
  MockRemoteTrackVisitor client_visitor;
  std::optional<absl::string_view> expected_reason = "No tracks published";
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeCurrentObject(full_track_name, &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, ObjectAcks) {
  CreateDefaultEndpoints();
  WireUpEndpoints();
  client_->session()->set_support_object_acks(true);
  server_->session()->set_support_object_acks(true);
  ConnectEndpoints();

  FullTrackName full_track_name("foo", "bar");
  MockRemoteTrackVisitor client_visitor;

  MoqtKnownTrackPublisher publisher;
  server_->session()->set_publisher(&publisher);
  auto track_publisher = std::make_shared<MockTrackPublisher>(full_track_name);
  publisher.Add(track_publisher);

  MockPublishingMonitorInterface monitoring;
  server_->session()->SetMonitoringInterfaceForTrack(full_track_name,
                                                     &monitoring);

  MoqtObjectAckFunction ack_function = nullptr;
  EXPECT_CALL(client_visitor, OnCanAckObjects(_))
      .WillOnce([&](MoqtObjectAckFunction new_ack_function) {
        ack_function = std::move(new_ack_function);
      });
  EXPECT_CALL(client_visitor, OnReply(_, _))
      .WillOnce([&](const FullTrackName&, std::optional<absl::string_view>) {
        ack_function(10, 20, quic::QuicTimeDelta::FromMicroseconds(-123));
        ack_function(100, 200, quic::QuicTimeDelta::FromMicroseconds(456));
      });

  MoqtSubscribeParameters parameters;
  parameters.object_ack_window = quic::QuicTimeDelta::FromMilliseconds(100);
  client_->session()->SubscribeCurrentObject(full_track_name, &client_visitor,
                                             parameters);
  EXPECT_CALL(monitoring, OnObjectAckSupportKnown(true));
  EXPECT_CALL(
      monitoring,
      OnObjectAckReceived(10, 20, quic::QuicTimeDelta::FromMicroseconds(-123)));
  bool done = false;
  EXPECT_CALL(
      monitoring,
      OnObjectAckReceived(100, 200, quic::QuicTimeDelta::FromMicroseconds(456)))
      .WillOnce([&] { done = true; });
  bool success = test_harness_.RunUntilWithDefaultTimeout([&] { return done; });
  EXPECT_TRUE(success);
}

}  // namespace

}  // namespace moqt::test

"""

```
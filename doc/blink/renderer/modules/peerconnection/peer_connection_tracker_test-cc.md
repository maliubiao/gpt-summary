Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Identify the Core Purpose:** The filename `peer_connection_tracker_test.cc` immediately suggests this file contains unit tests for a class named `PeerConnectionTracker`. The `_test.cc` suffix is a common convention in C++ testing frameworks.

2. **Understand the Tested Class:** The first `#include` statement, `"third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"`, confirms the class being tested is `PeerConnectionTracker`. This hints that the tracker is part of the WebRTC implementation within the Blink rendering engine.

3. **Examine Included Headers:**  The other `#include` statements provide context about the dependencies and functionalities involved:
    * `<memory>`: Standard C++ header for smart pointers (likely used for managing `PeerConnectionTracker`'s lifetime).
    * `"base/run_loop.h"`:  Indicates the tests will involve asynchronous operations and event handling. `base::RunLoop` is used in Chromium for managing the message loop.
    * `"base/types/pass_key.h"`: Suggests a mechanism for controlling access or instantiation of the `PeerConnectionTracker`.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`:  Confirms the use of Google Mock and Google Test for writing the unit tests.
    * `"third_party/blink/public/mojom/peerconnection/peer_connection_tracker.mojom-blink.h"`: This is crucial. The `.mojom` extension strongly indicates this is a Mojo interface definition. Mojo is Chromium's inter-process communication (IPC) system. This suggests `PeerConnectionTracker` likely communicates with other processes (e.g., the browser process). The `Host` suffix in `PeerConnectionTrackerHost` further supports this.
    * Platform-specific headers (starting with `"third_party/blink/renderer/platform/...")`:  These suggest the `PeerConnectionTracker` interacts with lower-level platform abstractions related to WebRTC (e.g., `RTCOfferOptionsPlatform`, `RTCRtpSenderPlatform`).
    * Headers in the `modules/mediastream` and `modules/peerconnection` directories: These reveal the specific WebRTC components the tracker interacts with, such as `MediaConstraints`, `RTCRtpTransceiver`, and the overall peer connection handling.

4. **Analyze the `MockPeerConnectionTrackerHost` Class:** This class is essential for testing. Since `PeerConnectionTracker` likely communicates via Mojo, a mock implementation of the `PeerConnectionTrackerHost` interface is needed to simulate the behavior of the other process. The `MOCK_METHOD` macros from Google Mock are used to define expectations for the calls made by the `PeerConnectionTracker`. The method names (`UpdatePeerConnection`, `AddPeerConnection`, `GetUserMedia`, etc.) provide strong hints about the kind of information the tracker sends.

5. **Examine Helper Functions:**  The `CreateDefaultTransceiver()` function suggests a common pattern in the tests: setting up a default WebRTC transceiver object for scenarios where the specific transceiver details are not the focus of the test.

6. **Analyze the `MockPeerConnectionHandler` Class:** This class mocks the `RTCPeerConnectionHandler`, a core component responsible for managing the underlying WebRTC peer connection. This shows the tests also verify the `PeerConnectionTracker` interacts correctly with the handler.

7. **Understand the Test Fixture (`PeerConnectionTrackerTest`):** The fixture sets up the necessary environment for running the tests, including creating the `MockPeerConnectionTrackerHost` and the `PeerConnectionTracker` itself. The `CreateAndRegisterPeerConnectionHandler()` function further simplifies test setup.

8. **Analyze Individual Tests:**  Each `TEST_F` function focuses on testing a specific aspect of the `PeerConnectionTracker`'s functionality. Pay attention to:
    * The test name (e.g., `TrackCreateOffer`, `OnSuspend`, `AddTransceiverWithOptionalValuesPresent`).
    * The `EXPECT_CALL` statements, which define the expected interactions with the mock objects.
    * The actions performed within the test (e.g., calling `TrackCreateOffer`, `OnSuspend`).
    * The assertions (`EXPECT_EQ`), which verify the actual behavior matches the expected behavior.

9. **Infer Functionality from Test Cases:** By examining the tests, we can deduce the functionalities of the `PeerConnectionTracker`:
    * Tracking the creation of offers and answers.
    * Reporting transceiver additions and modifications.
    * Logging ICE candidate errors.
    * Handling suspend events.
    * Responding to thermal state changes and speed limit changes.
    * Registering and unregistering peer connection handlers.
    * Likely tracking other WebRTC events and statistics (based on the `MockPeerConnectionTrackerHost` methods).

10. **Relate to Web Technologies:** Connect the observed functionalities to JavaScript, HTML, and CSS where applicable:
    * JavaScript APIs like `RTCPeerConnection.createOffer()`, `RTCPeerConnection.addTransceiver()`, `RTCPeerConnection.onicecandidateerror`.
    * HTML elements like `<video>` and `<audio>` which are often used with WebRTC.
    * While CSS doesn't directly interact with the core logic being tested, it plays a role in the presentation of media streams.

11. **Consider User Actions and Debugging:** Think about the sequence of user interactions that would lead to these code paths being executed and how the tracked information would be valuable for debugging.

12. **Formulate Assumptions and Examples:** Create concrete examples of inputs and outputs based on the observed behavior and the mock interactions. Think about potential user errors.

By following these steps, we can systematically analyze the C++ test file and understand the functionality of the `PeerConnectionTracker`, its relationships to web technologies, and its role in the broader WebRTC implementation.
这个C++源代码文件 `peer_connection_tracker_test.cc` 是 Chromium Blink 引擎中 `PeerConnectionTracker` 类的单元测试文件。它的主要功能是**测试 `PeerConnectionTracker` 类的各种功能是否正常工作**。

以下是该文件功能的详细列举：

**1. 测试 `PeerConnectionTracker` 类的核心功能：**

*   **追踪 `RTCPeerConnection` 的生命周期：** 测试 `PeerConnectionTracker` 能否正确地记录 `RTCPeerConnection` 的创建 (`AddPeerConnection`) 和销毁 (`RemovePeerConnection`)。
*   **追踪 `RTCPeerConnection` 的状态变化和操作：** 测试能否记录关键操作，例如 `createOffer`，以及相关的选项参数。
*   **追踪 `RTCRtpTransceiver` 的变化：** 测试能否记录 `RTCRtpTransceiver` 的添加 (`TrackAddTransceiver`) 和修改 (`TrackModifyTransceiver`)，并包含相关的详细信息，例如 `mid`、`kind`、`sender`、`receiver`、`direction` 等。
*   **追踪 `getUserMedia` 和 `getDisplayMedia` 的调用和结果：** 测试能否记录这些媒体获取操作的调用参数（例如音频/视频约束）以及成功或失败的结果。
*   **追踪 ICE candidate 错误：** 测试能否记录 ICE 连接过程中发生的错误信息。
*   **传递 WebRTC 事件日志：** 测试能否将底层的 WebRTC 事件日志传递到上层。
*   **传递标准统计信息：** 测试能否传递 `RTCPeerConnection` 的标准统计信息。
*   **处理系统事件：** 测试能否响应系统的挂起 (`OnSuspend`)、设备温度变化 (`OnThermalStateChange`) 和网络速度限制变化 (`OnSpeedLimitChange`) 事件，并将这些事件传递给相关的 `RTCPeerConnectionHandler`。

**2. 模拟外部依赖：**

*   使用 `MockPeerConnectionTrackerHost` 模拟 `PeerConnectionTrackerHost` Mojo 接口，用于验证 `PeerConnectionTracker` 是否按照预期向该接口发送数据。
*   使用 `MockPeerConnectionHandler` 模拟 `RTCPeerConnectionHandler`，用于验证 `PeerConnectionTracker` 是否按照预期调用 `RTCPeerConnectionHandler` 的方法。
*   使用 `FakeRTCRtpTransceiverImpl`、`FakeRTCRtpSenderImpl` 和 `FakeRTCRtpReceiverImpl` 创建用于测试的假 `RTCRtpTransceiver` 对象。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript、HTML 或 CSS 代码，但它测试的功能与这些 Web 技术密切相关，因为 `PeerConnectionTracker` 负责追踪 WebRTC API 的使用情况，而 WebRTC API 主要在 JavaScript 中被调用。

*   **JavaScript:**
    *   **`RTCPeerConnection` API:**  `PeerConnectionTracker` 追踪 `RTCPeerConnection` 对象的创建、状态变化以及方法的调用，例如 `createOffer()`, `createAnswer()`, `setLocalDescription()`, `setRemoteDescription()`, `addTrack()`, `addTransceiver()`, `getTransceivers()` 等。
        *   **举例：** 当 JavaScript 代码调用 `pc.createOffer(options)` 时，`PeerConnectionTracker` 会捕获这次调用，并将方法名 "createOffer" 以及 `options` 对象（会被序列化成字符串）发送给 `PeerConnectionTrackerHost` 进行记录。
    *   **`getUserMedia()` API:** `PeerConnectionTracker` 追踪 `getUserMedia()` 的调用，包括请求的音频和视频约束。
        *   **举例：** 当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true, audio: false })` 时，`PeerConnectionTracker` 会记录下这是一个 `getUserMedia` 调用，并且请求了视频但没有请求音频。
    *   **`getDisplayMedia()` API:** 类似于 `getUserMedia()`，`PeerConnectionTracker` 追踪屏幕共享的调用。
    *   **`RTCTrackEvent` 和 `RTCRtpTransceiver` API:**  当通过 `addTrack()` 或 `addTransceiver()` 添加媒体轨道时，`PeerConnectionTracker` 会记录相关的 `RTCRtpTransceiver` 信息。
        *   **举例：**  当 JavaScript 代码调用 `pc.addTransceiver('audio', { direction: 'sendonly' })` 时，`PeerConnectionTracker` 会记录一个新的 `RTCRtpTransceiver` 被添加，其 `kind` 为 'audio'，`direction` 为 'sendonly'。

*   **HTML:**
    *   **`<video>` 和 `<audio>` 元素:**  WebRTC 通常与 `<video>` 和 `<audio>` 元素一起使用来显示或播放媒体流。虽然 `PeerConnectionTracker` 不直接操作 HTML 元素，但它追踪的 WebRTC 连接是这些元素能够呈现媒体的基础。

*   **CSS:**
    *   **媒体流的样式:** CSS 可以用于控制 `<video>` 和 `<audio>` 元素的外观和布局。`PeerConnectionTracker` 不直接涉及 CSS，但它追踪的 WebRTC 功能最终会影响用户在网页上看到的媒体呈现。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行了以下操作：

1. `pc = new RTCPeerConnection();`
2. `pc.addTransceiver('audio', { direction: 'sendonly' });`
3. `pc.createOffer();`

**假设输入：**  `RTCPeerConnection` 对象以及相关的 JavaScript API 调用。

**推断过程：**

*   当 `new RTCPeerConnection()` 被调用时，`PeerConnectionTracker` 的 `RegisterPeerConnection` 方法会被调用 (通过底层的 Blink 实现)。
*   当 `addTransceiver()` 被调用时，`PeerConnectionTracker::TrackAddTransceiver` 会被调用，记录新的 `RTCRtpTransceiver` 的属性（`kind`: 'audio', `direction`: 'sendonly' 等）。
*   当 `createOffer()` 被调用时，`PeerConnectionTracker::TrackCreateOffer` 会被调用，记录方法名 "createOffer" 和相关的选项（如果提供了）。

**可能的输出（发送给 `MockPeerConnectionTrackerHost` 的调用）:**

*   `AddPeerConnection(PeerConnectionInfo)`: 记录新的 `RTCPeerConnection` 被创建。
*   `UpdatePeerConnection(peer_connection_id, "transceiverAdded", transceiver_info_string)`:  记录 `addTransceiver` 操作，`transceiver_info_string` 可能类似于：

    ```
    Caused by: addTransceiver
    getTransceivers()[0]:{
      mid:null,
      kind:'audio',
      sender:{
        track:null,
        streams:[],
      },
      receiver:{
        track:null,
        streams:[],
      },
      direction:'sendonly',
      currentDirection:null,
    }
    ```
*   `UpdatePeerConnection(peer_connection_id, "createOffer", "options: {offerToReceiveVideo: 0, offerToReceiveAudio: 0, voiceActivityDetection: false, iceRestart: false}")`: 记录 `createOffer` 操作（假设没有提供特定的选项）。

**用户或编程常见的使用错误 (导致 `PeerConnectionTracker` 记录异常):**

*   **未处理 `getUserMedia` 错误：**  如果 JavaScript 代码调用 `getUserMedia` 但没有正确处理 Promise 的 rejection，可能会导致 `PeerConnectionTracker` 记录 `GetUserMediaFailure` 事件，并包含错误信息。
    *   **举例：** 用户拒绝了摄像头或麦克风的访问权限，但 JavaScript 代码没有捕获这个错误并给出友好的提示。`PeerConnectionTracker` 会记录这次失败，方便开发者调试。
*   **不正确的 `RTCPeerConnection` 配置：**  如果 `RTCPeerConnection` 的配置不当，例如没有提供有效的 ICE 服务器，可能导致 ICE 连接失败，`PeerConnectionTracker` 会记录相关的 ICE candidate 错误。
    *   **举例：** 开发者忘记配置 `iceServers`，导致客户端无法找到合适的网络路径进行连接。`PeerConnectionTracker` 会记录 `icecandidateerror` 事件，包含错误的 URL、地址、端口等信息。
*   **在错误的时机调用 WebRTC API：**  例如，在 `signalingState` 不正确时尝试创建 Offer 或 Answer，可能会导致 `PeerConnectionTracker` 记录异常状态或操作。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户打开一个包含 WebRTC 功能的网页。**
2. **网页的 JavaScript 代码尝试获取用户的媒体设备 (摄像头/麦克风) 通过调用 `navigator.mediaDevices.getUserMedia()` 或进行屏幕共享通过 `navigator.mediaDevices.getDisplayMedia()`。** 这会触发 `PeerConnectionTracker` 记录 `GetUserMedia` 或 `GetDisplayMedia` 事件。
3. **用户允许或拒绝了媒体设备的访问权限。** 这会导致 `PeerConnectionTracker` 记录 `GetUserMediaSuccess` 或 `GetUserMediaFailure` (或者对应的 `GetDisplayMedia` 事件)。
4. **网页的 JavaScript 代码创建了一个 `RTCPeerConnection` 对象。** 这会触发 `PeerConnectionTracker::RegisterPeerConnection`。
5. **网页的 JavaScript 代码调用 `addTransceiver()` 添加媒体轨道，或者调用 `addTrack()` 添加轨道。**  这会触发 `PeerConnectionTracker::TrackAddTransceiver`。
6. **网页的 JavaScript 代码调用 `createOffer()` 或 `createAnswer()` 来创建 SDP 信息。** 这会触发 `PeerConnectionTracker::TrackCreateOffer` 或 `TrackCreateAnswer`。
7. **如果发生网络连接问题，导致 ICE 协商失败，** `PeerConnectionTracker::TrackIceCandidateError` 会被调用记录错误信息。
8. **当浏览器窗口被挂起 (例如，移动设备切换到后台) 时，** 可能会触发 `PeerConnectionTracker::OnSuspend`。
9. **如果设备温度过高或网络速度发生变化，** 操作系统可能会发送相应的通知，`PeerConnectionTracker::OnThermalStateChange` 或 `PeerConnectionTracker::OnSpeedLimitChange` 会被调用。

通过查看 `PeerConnectionTracker` 记录的信息，开发者可以追踪 WebRTC 连接的建立过程、诊断错误、了解用户操作对 WebRTC 连接的影响，并进行性能分析和问题排查。例如，如果 `PeerConnectionTracker` 记录了多次 ICE candidate 错误，开发者可以推断可能是网络配置有问题。如果记录了 `getUserMediaFailure`，开发者可以检查用户是否拒绝了权限。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/peer_connection_tracker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"

#include <memory>

#include "base/run_loop.h"
#include "base/types/pass_key.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/peerconnection/peer_connection_tracker.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/peerconnection/fake_rtc_rtp_transceiver_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_client.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_platform.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_offer_options_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_receiver_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_sender_platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_rtp_transceiver_platform.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

using ::testing::_;

namespace blink {

const char* kDefaultTransceiverString =
    "getTransceivers()[0]:{\n"
    "  mid:null,\n"
    "  kind:'audio',\n"
    "  sender:{\n"
    "    track:'senderTrackId',\n"
    "    streams:['senderStreamId'],\n"
    "  },\n"
    "  receiver:{\n"
    "    track:'receiverTrackId',\n"
    "    streams:['receiverStreamId'],\n"
    "  },\n"
    "  direction:'sendonly',\n"
    "  currentDirection:null,\n"
    "}";

class MockPeerConnectionTrackerHost
    : public blink::mojom::blink::PeerConnectionTrackerHost {
 public:
  MockPeerConnectionTrackerHost() {}
  MOCK_METHOD3(UpdatePeerConnection, void(int, const String&, const String&));
  MOCK_METHOD1(AddPeerConnection,
               void(blink::mojom::blink::PeerConnectionInfoPtr));
  MOCK_METHOD1(RemovePeerConnection, void(int));
  MOCK_METHOD2(OnPeerConnectionSessionIdSet, void(int, const String&));
  MOCK_METHOD5(GetUserMedia,
               void(int, bool, bool, const String&, const String&));
  MOCK_METHOD4(GetUserMediaSuccess,
               void(int, const String&, const String&, const String&));
  MOCK_METHOD3(GetUserMediaFailure, void(int, const String&, const String&));
  MOCK_METHOD5(GetDisplayMedia,
               void(int, bool, bool, const String&, const String&));
  MOCK_METHOD4(GetDisplayMediaSuccess,
               void(int, const String&, const String&, const String&));
  MOCK_METHOD3(GetDisplayMediaFailure, void(int, const String&, const String&));
  MOCK_METHOD2(WebRtcEventLogWrite, void(int, const Vector<uint8_t>&));
  MOCK_METHOD2(AddStandardStats, void(int, base::Value::List));

  mojo::PendingRemote<blink::mojom::blink::PeerConnectionTrackerHost>
  CreatePendingRemoteAndBind() {
    receiver_.reset();
    return receiver_.BindNewPipeAndPassRemote(
        blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  }

  mojo::Receiver<blink::mojom::blink::PeerConnectionTrackerHost> receiver_{
      this};
};

// Creates a transceiver that is expected to be logged as
// |kDefaultTransceiverString|.
//
// This is used in unittests that don't care about the specific attributes of
// the transceiver.
std::unique_ptr<RTCRtpTransceiverPlatform> CreateDefaultTransceiver() {
  std::unique_ptr<RTCRtpTransceiverPlatform> transceiver;
  blink::FakeRTCRtpSenderImpl sender(
      "senderTrackId", {"senderStreamId"},
      blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  blink::FakeRTCRtpReceiverImpl receiver(
      "receiverTrackId", {"receiverStreamId"},
      blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  transceiver = std::make_unique<blink::FakeRTCRtpTransceiverImpl>(
      String(), std::move(sender), std::move(receiver),
      webrtc::RtpTransceiverDirection::kSendOnly /* direction */,
      std::nullopt /* current_direction */);
  return transceiver;
}

namespace {

// TODO(https://crbug.com/868868): Move this into a separate file.
class MockPeerConnectionHandler : public RTCPeerConnectionHandler {
 public:
  MockPeerConnectionHandler()
      : MockPeerConnectionHandler(
            MakeGarbageCollected<MockPeerConnectionDependencyFactory>(),
            MakeGarbageCollected<MockRTCPeerConnectionHandlerClient>()) {}
  MOCK_METHOD0(CloseClientPeerConnection, void());
  MOCK_METHOD1(OnThermalStateChange, void(mojom::blink::DeviceThermalState));
  MOCK_METHOD1(OnSpeedLimitChange, void(int));

 private:
  explicit MockPeerConnectionHandler(
      MockPeerConnectionDependencyFactory* factory,
      MockRTCPeerConnectionHandlerClient* client)
      : RTCPeerConnectionHandler(
            client,
            factory,
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            /*encoded_insertable_streams=*/false),
        factory_(factory),
        client_(client) {}

  Persistent<MockPeerConnectionDependencyFactory> factory_;
  Persistent<MockRTCPeerConnectionHandlerClient> client_;
};

webrtc::PeerConnectionInterface::RTCConfiguration DefaultConfig() {
  webrtc::PeerConnectionInterface::RTCConfiguration config;
  config.sdp_semantics = webrtc::SdpSemantics::kUnifiedPlan;
  return config;
}

}  // namespace

class PeerConnectionTrackerTest : public ::testing::Test {
 public:
  void CreateTrackerWithMocks() {
    mock_host_ = std::make_unique<MockPeerConnectionTrackerHost>();
    tracker_ = MakeGarbageCollected<PeerConnectionTracker>(
        mock_host_->CreatePendingRemoteAndBind(),
        blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
        base::PassKey<PeerConnectionTrackerTest>());
  }

  void CreateAndRegisterPeerConnectionHandler() {
    mock_handler_ = std::make_unique<MockPeerConnectionHandler>();
    EXPECT_CALL(*mock_host_, AddPeerConnection(_));
    tracker_->RegisterPeerConnection(mock_handler_.get(), DefaultConfig(),
                                     nullptr);
    base::RunLoop().RunUntilIdle();
  }

 protected:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<MockPeerConnectionTrackerHost> mock_host_;
  Persistent<PeerConnectionTracker> tracker_;
  std::unique_ptr<MockPeerConnectionHandler> mock_handler_;
};

TEST_F(PeerConnectionTrackerTest, TrackCreateOffer) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();
  // Note: blink::RTCOfferOptionsPlatform is not mockable. So we can't write
  // tests for anything but a null options parameter.
  RTCOfferOptionsPlatform* options =
      MakeGarbageCollected<RTCOfferOptionsPlatform>(0, 0, false, false);
  EXPECT_CALL(
      *mock_host_,
      UpdatePeerConnection(
          _, String("createOffer"),
          String("options: {offerToReceiveVideo: 0, offerToReceiveAudio: 0, "
                 "voiceActivityDetection: false, iceRestart: false}")));
  tracker_->TrackCreateOffer(mock_handler_.get(), options);
  base::RunLoop().RunUntilIdle();
}

TEST_F(PeerConnectionTrackerTest, OnSuspend) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();
  EXPECT_CALL(*mock_handler_, CloseClientPeerConnection());
  tracker_->OnSuspend();
}

TEST_F(PeerConnectionTrackerTest, OnThermalStateChange) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();

  EXPECT_CALL(*mock_handler_,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kUnknown))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kUnknown);

  EXPECT_CALL(*mock_handler_,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kNominal))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kNominal);

  EXPECT_CALL(*mock_handler_,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kFair))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kFair);

  EXPECT_CALL(*mock_handler_,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kSerious))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kSerious);

  EXPECT_CALL(*mock_handler_,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kCritical))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kCritical);
}

TEST_F(PeerConnectionTrackerTest, OnSpeedLimitChange) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();

  EXPECT_CALL(*mock_handler_, OnSpeedLimitChange(22));
  tracker_->OnSpeedLimitChange(22);
  EXPECT_CALL(*mock_handler_, OnSpeedLimitChange(33));
  tracker_->OnSpeedLimitChange(33);
}

TEST_F(PeerConnectionTrackerTest, ReportInitialThermalState) {
  MockPeerConnectionHandler handler0;
  MockPeerConnectionHandler handler1;
  MockPeerConnectionHandler handler2;
  CreateTrackerWithMocks();

  // Nothing is reported by default.
  EXPECT_CALL(handler0, OnThermalStateChange(_)).Times(0);
  EXPECT_CALL(*mock_host_, AddPeerConnection(_)).Times(1);
  tracker_->RegisterPeerConnection(&handler0, DefaultConfig(), nullptr);
  base::RunLoop().RunUntilIdle();

  // Report a known thermal state.
  EXPECT_CALL(handler0,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kNominal))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kNominal);

  // Handlers registered late will get the event upon registering.
  EXPECT_CALL(handler1,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kNominal))
      .Times(1);
  EXPECT_CALL(*mock_host_, AddPeerConnection(_)).Times(1);
  tracker_->RegisterPeerConnection(&handler1, DefaultConfig(), nullptr);
  base::RunLoop().RunUntilIdle();

  // Report the unknown thermal state.
  EXPECT_CALL(handler0,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kUnknown))
      .Times(1);
  EXPECT_CALL(handler1,
              OnThermalStateChange(mojom::blink::DeviceThermalState::kUnknown))
      .Times(1);
  tracker_->OnThermalStateChange(mojom::blink::DeviceThermalState::kUnknown);

  // Handlers registered late get no event.
  EXPECT_CALL(handler2, OnThermalStateChange(_)).Times(0);
  EXPECT_CALL(*mock_host_, AddPeerConnection(_)).Times(1);
  tracker_->RegisterPeerConnection(&handler2, DefaultConfig(), nullptr);
  base::RunLoop().RunUntilIdle();
}

TEST_F(PeerConnectionTrackerTest, AddTransceiverWithOptionalValuesPresent) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();
  blink::FakeRTCRtpTransceiverImpl transceiver(
      "midValue",
      blink::FakeRTCRtpSenderImpl(
          "senderTrackId", {"streamIdA", "streamIdB"},
          blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
      blink::FakeRTCRtpReceiverImpl(
          "receiverTrackId", {"streamIdC"},
          blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
      webrtc::RtpTransceiverDirection::kSendRecv /* direction */,
      webrtc::RtpTransceiverDirection::kInactive /* current_direction */);
  String update_value;
  EXPECT_CALL(*mock_host_,
              UpdatePeerConnection(_, String("transceiverAdded"), _))
      .WillOnce(testing::SaveArg<2>(&update_value));
  tracker_->TrackAddTransceiver(
      mock_handler_.get(),
      PeerConnectionTracker::TransceiverUpdatedReason::kAddTrack, transceiver,
      0u);
  base::RunLoop().RunUntilIdle();
  String expected_value(
      "Caused by: addTrack\n"
      "\n"
      "getTransceivers()[0]:{\n"
      "  mid:'midValue',\n"
      "  kind:'audio',\n"
      "  sender:{\n"
      "    track:'senderTrackId',\n"
      "    streams:['streamIdA','streamIdB'],\n"
      "  },\n"
      "  receiver:{\n"
      "    track:'receiverTrackId',\n"
      "    streams:['streamIdC'],\n"
      "  },\n"
      "  direction:'sendrecv',\n"
      "  currentDirection:'inactive',\n"
      "}");
  EXPECT_EQ(expected_value, update_value);
}

TEST_F(PeerConnectionTrackerTest, AddTransceiverWithOptionalValuesNull) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();
  blink::FakeRTCRtpTransceiverImpl transceiver(
      String(),
      blink::FakeRTCRtpSenderImpl(
          std::nullopt, {},
          blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
      blink::FakeRTCRtpReceiverImpl(
          "receiverTrackId", {},
          blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
      webrtc::RtpTransceiverDirection::kInactive /* direction */,
      std::nullopt /* current_direction */);
  String update_value;
  EXPECT_CALL(*mock_host_,
              UpdatePeerConnection(_, String("transceiverAdded"), _))
      .WillOnce(testing::SaveArg<2>(&update_value));
  tracker_->TrackAddTransceiver(
      mock_handler_.get(),
      PeerConnectionTracker::TransceiverUpdatedReason::kAddTransceiver,
      transceiver, 1u);
  base::RunLoop().RunUntilIdle();
  String expected_value(
      "Caused by: addTransceiver\n"
      "\n"
      "getTransceivers()[1]:{\n"
      "  mid:null,\n"
      "  kind:'audio',\n"
      "  sender:{\n"
      "    track:null,\n"
      "    streams:[],\n"
      "  },\n"
      "  receiver:{\n"
      "    track:'receiverTrackId',\n"
      "    streams:[],\n"
      "  },\n"
      "  direction:'inactive',\n"
      "  currentDirection:null,\n"
      "}");
  EXPECT_EQ(expected_value, update_value);
}

TEST_F(PeerConnectionTrackerTest, ModifyTransceiver) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();
  auto transceiver = CreateDefaultTransceiver();
  String update_value;
  EXPECT_CALL(*mock_host_,
              UpdatePeerConnection(_, String("transceiverModified"), _))
      .WillOnce(testing::SaveArg<2>(&update_value));
  tracker_->TrackModifyTransceiver(
      mock_handler_.get(),
      PeerConnectionTracker::TransceiverUpdatedReason::kSetLocalDescription,
      *transceiver, 0u);
  base::RunLoop().RunUntilIdle();
  String expected_value("Caused by: setLocalDescription\n\n" +
                        String(kDefaultTransceiverString));
  EXPECT_EQ(expected_value, update_value);
}

TEST_F(PeerConnectionTrackerTest, IceCandidateError) {
  CreateTrackerWithMocks();
  CreateAndRegisterPeerConnectionHandler();
  auto transceiver = CreateDefaultTransceiver();
  String update_value;
  EXPECT_CALL(*mock_host_,
              UpdatePeerConnection(_, String("icecandidateerror"), _))
      .WillOnce(testing::SaveArg<2>(&update_value));
  tracker_->TrackIceCandidateError(mock_handler_.get(), "1.1.1.1", 15, "[::1]",
                                   "test url", 404, "test error");
  base::RunLoop().RunUntilIdle();
  String expected_value(
      "url: test url\n"
      "address: 1.1.1.1\n"
      "port: 15\n"
      "host_candidate: [::1]\n"
      "error_text: test error\n"
      "error_code: 404");
  EXPECT_EQ(expected_value, update_value);
}

// TODO(hta): Write tests for the other tracking functions.

}  // namespace blink

"""

```
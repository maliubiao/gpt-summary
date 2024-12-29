Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Goal:** The request asks for a functional breakdown of `mock_peer_connection_impl.cc`, its relationship to web technologies (JS, HTML, CSS), examples of logical reasoning, common errors, and debugging information. The core is understanding what this *mock* implementation does in the context of WebRTC.

2. **Initial Scan and Keywords:**  A quick scan reveals key terms: `Mock`, `PeerConnection`, `RtpSender`, `RtpReceiver`, `DataChannel`, `ICE Candidate`, `SDP`, `MediaStream`. These immediately point to WebRTC concepts being simulated for testing purposes.

3. **Identifying Core Functionality (Verbs/Actions):**  The next step is to look for the class methods. These are the actions the mock object can perform. Grouping related methods helps in understanding the overall behavior:

    * **Connection Management:** `CreateOffer`, `CreateAnswer`, `SetLocalDescription`, `SetRemoteDescription`, `AddIceCandidate`, `SetConfiguration`. These mimic the core signaling process of WebRTC.
    * **Media Handling:** `AddTrack`, `RemoveTrackOrError`, `GetSenders`, `GetReceivers`, `GetTransceivers`, `AddRemoteStream`. These manage the addition and retrieval of audio and video streams.
    * **Data Channels:** `CreateDataChannelOrError`. This deals with establishing data communication channels.
    * **Statistics:** `GetStats`. This provides simulated performance metrics.
    * **Internal State:** `local_description`, `remote_description`. These access the stored SDP information.

4. **Dissecting Key Classes:**  The file defines several auxiliary "mock" classes:

    * `MockStreamCollection`: Simulates a collection of media streams.
    * `MockDtmfSender`: Simulates sending DTMF tones.
    * `FakeRtpSender`:  Represents a simulated RTP sender for audio/video.
    * `FakeRtpReceiver`: Represents a simulated RTP receiver.
    * `FakeRtpTransceiver`: Combines a sender and receiver, simulating the bidirectional nature of media tracks.
    * `FakeDtlsTransport`: A placeholder for a DTLS transport.

5. **Connecting to Web Technologies (JS/HTML/CSS):** This requires understanding *how* WebRTC is used on the web.

    * **JavaScript:**  The `RTCPeerConnection` API in JavaScript is the primary interface for WebRTC. The mock likely simulates the *backend* behavior that would be triggered by JavaScript calls to `createOffer()`, `createAnswer()`, `setLocalDescription()`, `setRemoteDescription()`, `addTrack()`, `addIceCandidate()`, `createDataChannel()`, etc. Examples should map specific mock methods to their corresponding JS API calls.

    * **HTML:** HTML elements like `<video>` and `<audio>` are used to display the received media streams. The mock doesn't directly interact with HTML, but it simulates the *data flow* that eventually populates these elements.

    * **CSS:** CSS styles the visual presentation of the HTML elements. The mock has no direct interaction with CSS.

6. **Identifying Logical Reasoning and Examples:**  Look for conditional logic or actions based on specific inputs.

    * **`GetStats`:** The mock behavior changes based on whether a `track` is provided as input. This is a simple example of conditional logic. The example should clearly show the different outputs based on this input.

7. **Spotting Potential User/Programming Errors:** Think about common mistakes developers make when using WebRTC.

    * **Incorrect Signaling Order:** Calling `setRemoteDescription` before `createOffer` (or similar incorrect sequences) is a common issue. The mock, while not enforcing *strict* ordering, might have default behaviors that assume a typical flow, and deviations could reveal issues in the tested code.
    * **Adding the Same Track Twice:** The `AddTrack` method explicitly checks for this.
    * **Using an Invalid Sender:** The `RemoveTrackOrError` method handles this case.

8. **Tracing User Operations to the Code (Debugging):** This requires understanding the overall architecture and how user actions translate into code execution.

    * A user clicking a "Call" button likely triggers JavaScript code.
    * The JavaScript might create an `RTCPeerConnection` object.
    * Methods on this object (like `createOffer`) would eventually interact with the underlying browser engine (Blink in this case).
    * In a *testing* context, the `MockPeerConnectionImpl` would be used instead of the *real* implementation. This is where breakpoints or logging in the mock file become relevant for debugging.

9. **Structuring the Answer:** Organize the information logically, using clear headings and bullet points. Provide concrete examples for each point.

10. **Refinement and Clarity:** Review the answer for clarity and accuracy. Ensure the examples are easy to understand and directly relate to the code. For instance, instead of just saying "handles adding tracks," explain *how* it handles it (creates a `FakeRtpSender`, etc.). Emphasize that it's a *mock* and therefore has simplified behavior compared to a real implementation.

By following these steps, one can systematically analyze the code and generate a comprehensive and informative response like the example provided in the initial prompt. The key is to connect the code to the larger context of WebRTC and web development.
这个文件 `mock_peer_connection_impl.cc` 是 Chromium Blink 引擎中 `peerconnection` 模块的一部分，它提供了一个 **`RTCPeerConnection` 接口的模拟 (mock) 实现**。  这种 mock 实现主要用于单元测试和集成测试，允许开发者在不依赖真实的 WebRTC 底层实现的情况下，验证 `RTCPeerConnection` 相关的功能和逻辑。

以下是它的主要功能：

1. **模拟 `RTCPeerConnection` 的核心功能:**
   - **创建 Offer 和 Answer:** 模拟 `createOffer` 和 `createAnswer` 方法，虽然在 mock 版本中可能返回预定义的虚拟 SDP (Session Description Protocol)。
   - **设置本地和远程描述 (SDP):** 模拟 `setLocalDescription` 和 `setRemoteDescription` 方法，用于设置和存储本地和远程的会话描述信息。
   - **添加和处理 ICE Candidate:** 模拟 `addIceCandidate` 方法，用于添加和存储 ICE (Interactive Connectivity Establishment) 候选项。
   - **添加和移除媒体轨道 (Tracks):** 模拟 `addTrack` 和 `removeTrack` 方法，用于管理添加到 PeerConnection 的音频和视频轨道。
   - **创建数据通道 (Data Channels):** 模拟 `createDataChannel` 方法，用于创建用于任意数据传输的通道。
   - **获取统计信息 (Stats):** 模拟 `getStats` 方法，返回模拟的性能和状态数据。
   - **获取发送器 (Senders) 和接收器 (Receivers):** 模拟 `getSenders` 和 `getReceivers` 方法，返回与 PeerConnection 关联的发送器和接收器对象。
   - **获取收发器 (Transceivers):** 模拟 `getTransceivers` 方法，返回与 PeerConnection 关联的收发器对象，用于更细粒度的媒体协商和控制。
   - **处理媒体流 (Streams):**  虽然是 mock，但也提供了添加和管理远程媒体流的功能，用于模拟远端发送的流。
   - **设置配置 (Configuration):** 模拟 `setConfiguration` 方法，用于设置 `RTCPeerConnection` 的配置参数。

2. **提供测试所需的辅助类:**
   - `MockStreamCollection`:  一个简单的媒体流集合的 mock 实现。
   - `MockDtmfSender`:  一个 DTMF (Dual-tone multi-frequency signaling) 发送器的 mock 实现。
   - `FakeRtpSender`:  一个 RTP (Real-time Transport Protocol) 发送器的 mock 实现。
   - `FakeRtpReceiver`:  一个 RTP 接收器的 mock 实现。
   - `FakeRtpTransceiver`:  一个 RTP 收发器的 mock 实现。
   - `FakeDtlsTransport`: 一个 DTLS (Datagram Transport Layer Security) 传输的 mock 实现。

**与 JavaScript, HTML, CSS 的关系：**

虽然 `mock_peer_connection_impl.cc` 是 C++ 代码，但它模拟了 WebRTC API 的行为，而 WebRTC API 主要在 JavaScript 中被使用。这意味着这个 mock 实现的目标是模拟当 JavaScript 代码调用 `RTCPeerConnection` 的方法时，浏览器引擎应该如何响应。

**举例说明：**

* **JavaScript `pc.createOffer()` 对应:** 当 JavaScript 代码调用 `peerConnection.createOffer()` 时，在测试环境下，会调用 `MockPeerConnectionImpl::CreateOffer` 方法。这个 mock 方法可能不会执行真实的 SDP 生成逻辑，而是返回一个预设的字符串，例如 `MockPeerConnectionImpl::kDummyOffer`。

  ```javascript
  // JavaScript 代码
  peerConnection.createOffer()
    .then(offer => {
      console.log("Offer SDP:", offer.sdp);
    });
  ```

  **假设输入:**  JavaScript 调用 `createOffer()`。
  **假设输出:**  `MockPeerConnectionImpl::CreateOffer`  设置 `created_sessiondescription_` 为一个包含 `"dummy offer"` 的 mock 对象。 JavaScript 的 Promise 会 resolve，并输出 "Offer SDP: dummy offer"。

* **JavaScript `pc.addTrack(localStream.getVideoTracks()[0], localStream)` 对应:** 当 JavaScript 代码调用 `peerConnection.addTrack()` 添加一个视频轨道时，会调用 `MockPeerConnectionImpl::AddTrack` 方法。 这个 mock 方法会创建一个 `FakeRtpSender` 对象来模拟发送器。

  ```javascript
  // JavaScript 代码
  navigator.mediaDevices.getUserMedia({ video: true, audio: false })
    .then(stream => {
      localStream = stream;
      peerConnection.addTrack(localStream.getVideoTracks()[0], localStream);
    });
  ```

  **逻辑推理:** `MockPeerConnectionImpl::AddTrack` 会接收到 `MediaStreamTrackInterface` 的 mock 实现，并创建一个 `FakeRtpSender` 来持有这个 track，并将其存储在 `senders_` 列表中。

* **HTML `<video>` 元素和接收到的流:** 虽然 mock 代码本身不直接操作 HTML，但它模拟了接收媒体流的过程。  在实际的 WebRTC 应用中，接收到的远程流会被设置为 HTML `<video>` 元素的 `srcObject` 属性，从而显示视频。 Mock 代码中的 `AddRemoteStream` 方法模拟了接收远程流并将其添加到内部状态的过程，测试代码可以断言这个方法被正确调用，从而间接验证了接收流的逻辑。

  ```html
  <video id="remoteVideo" autoplay playsinline></video>

  <script>
  peerConnection.ontrack = (event) => {
    document.getElementById('remoteVideo').srcObject = event.streams[0];
  };
  </script>
  ```

  **用户操作与调试线索:**  假设用户在一个视频通话应用中接听了电话。

  1. **用户点击 "接听" 按钮:**  这通常会触发 JavaScript 代码。
  2. **JavaScript 调用 `peerConnection.setRemoteDescription()`:** 设置接收到的远程 SDP。在测试中，这将调用 `MockPeerConnectionImpl::SetRemoteDescriptionWorker`。
  3. **JavaScript 代码可能监听 `ontrack` 事件:**  当接收到新的媒体轨道时，会触发这个事件。在测试中，模拟接收到 track 可能需要在 mock 代码中手动触发 observer 的回调。
  4. **在 `ontrack` 事件处理函数中，远程流被设置为 `<video>` 元素的 `srcObject`。**  如果调试时发现远程视频没有显示，可以检查以下几点（作为调试线索）：
     -  `MockPeerConnectionImpl::SetRemoteDescriptionWorker` 是否被正确调用，并且接收到了正确的 SDP（在测试中可以断言）。
     -  在测试代码中，是否模拟了远程轨道的添加，以及是否触发了 `RTCPeerConnectionObserver::OnTrack` 回调。
     -  检查 HTML 元素 `remoteVideo` 是否存在，并且 `srcObject` 是否被正确设置。

**用户或编程常见的使用错误举例：**

* **错误的信令顺序:** 用户或程序员可能错误地在 `createOffer` 之前调用 `setRemoteDescription`，或者在 ICE 交换完成之前尝试发送数据。 虽然 mock 实现可能不会严格按照真实流程报错，但可以编写测试用例来验证当应用程序以错误的顺序调用 WebRTC API 时，是否能得到预期的行为或错误处理。
    * **假设输入:** 测试代码先调用 `SetRemoteDescription` 再调用 `CreateOffer`。
    * **预期输出:**  测试可能断言在后续操作中会出现错误，或者状态机进入了不期望的状态。

* **尝试添加已存在的 Track:**  WebRTC 不允许向同一个 `RTCPeerConnection` 多次添加相同的媒体轨道。
    * **假设输入:** 测试代码调用 `AddTrack` 添加一个 track，然后再次使用相同的 track 调用 `AddTrack`。
    * **预期输出:**  `MockPeerConnectionImpl::AddTrack` 内部的检查会发现该 track 已存在，并返回一个表示错误的 `RTCError` 对象 (类型为 `webrtc::RTCErrorType::INVALID_PARAMETER`)。

* **在连接建立之前尝试发送数据到 DataChannel:** 用户可能过早地尝试通过数据通道发送消息，而此时连接可能尚未建立完成。
    * **假设输入:** 测试代码创建 DataChannel 后立即尝试发送消息，而没有模拟连接建立的过程。
    * **预期输出:**  `MockDataChannel` 的 mock 实现可能会返回一个错误状态，或者忽略该消息，模拟真实场景中消息可能丢失的情况。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

以一个简单的视频通话场景为例：

1. **用户 A 点击 "发起通话" 按钮:**
   - **JavaScript 代码开始执行:** 创建 `RTCPeerConnection` 对象。
   - **调用 `createOffer()`:**  这将间接触发 `MockPeerConnectionImpl::CreateOffer`。
   - **设置本地描述 `setLocalDescription()`:**  使用 `createOffer()` 生成的 SDP，触发 `MockPeerConnectionImpl::SetLocalDescriptionWorker`。
   - **通过信令服务器发送 Offer SDP 给用户 B。**
   - **开始收集 ICE 候选者。**

2. **用户 B 收到 Offer SDP:**
   - **JavaScript 代码接收到 Offer SDP。**
   - **调用 `setRemoteDescription()`:**  设置远程描述，触发 `MockPeerConnectionImpl::SetRemoteDescriptionWorker`。
   - **调用 `createAnswer()`:**  生成 Answer SDP，触发 `MockPeerConnectionImpl::CreateAnswer`。
   - **设置本地描述 `setLocalDescription()`:** 使用生成的 Answer SDP，触发 `MockPeerConnectionImpl::SetLocalDescriptionWorker`。
   - **通过信令服务器发送 Answer SDP 给用户 A。**
   - **开始收集 ICE 候选者。**
   - **用户 B 可能在设置远程描述后，开始添加自己的本地媒体轨道 (使用 `addTrack()`)，这将调用 `MockPeerConnectionImpl::AddTrack`。**

3. **用户 A 收到 Answer SDP:**
   - **JavaScript 代码接收到 Answer SDP。**
   - **调用 `setRemoteDescription()`:** 设置远程描述，触发 `MockPeerConnectionImpl::SetRemoteDescriptionWorker`。

4. **ICE 候选者交换:**
   - **双方通过信令服务器交换 ICE 候选者。**
   - **JavaScript 调用 `addIceCandidate()`:**  将接收到的 ICE 候选者添加到 `RTCPeerConnection`，触发 `MockPeerConnectionImpl::AddIceCandidate`。

如果调试时发现 `RTCPeerConnection` 的行为不符合预期，可以：

* **在 `MockPeerConnectionImpl` 的关键方法上设置断点:** 例如 `CreateOffer`, `SetLocalDescriptionWorker`, `AddIceCandidate` 等，查看这些方法是否被调用，参数是否正确。
* **检查 mock 对象的内部状态:** 例如 `local_desc_`, `remote_desc_`, `ice_sdp_`, `senders_`, `receivers_` 等，看是否存储了预期的值。
* **在测试代码中添加断言:**  验证 `MockPeerConnectionImpl` 的方法的返回值和副作用是否符合预期。

总而言之，`mock_peer_connection_impl.cc` 提供了一个用于测试的 `RTCPeerConnection` 模拟实现，它简化了真实的 WebRTC 复杂性，使得开发者可以更方便地进行单元测试和集成测试，验证与 `RTCPeerConnection` 相关的逻辑。理解它的功能以及与 JavaScript API 的对应关系，对于理解 WebRTC 的工作原理和进行相关开发调试至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/mock_peer_connection_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_impl.h"

#include <stddef.h>

#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/containers/contains.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_data_channel_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_peer_connection_dependency_factory.h"
#include "third_party/blink/renderer/modules/peerconnection/mock_rtc_peer_connection_handler_platform.h"
#include "third_party/blink/renderer/platform/allow_discouraged_type.h"
#include "third_party/webrtc/api/rtp_receiver_interface.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

using testing::_;
using webrtc::AudioTrackInterface;
using webrtc::CreateSessionDescriptionObserver;
using webrtc::DtmfSenderInterface;
using webrtc::DtmfSenderObserverInterface;
using webrtc::IceCandidateInterface;
using webrtc::MediaStreamInterface;
using webrtc::PeerConnectionInterface;
using webrtc::SessionDescriptionInterface;
using webrtc::SetSessionDescriptionObserver;

namespace blink {

class MockStreamCollection : public webrtc::StreamCollectionInterface {
 public:
  size_t count() override { return streams_.size(); }
  MediaStreamInterface* at(size_t index) override {
    return streams_[index].get();
  }
  MediaStreamInterface* find(const std::string& id) override {
    for (size_t i = 0; i < streams_.size(); ++i) {
      if (streams_[i]->id() == id)
        return streams_[i].get();
    }
    return nullptr;
  }
  webrtc::MediaStreamTrackInterface* FindAudioTrack(
      const std::string& id) override {
    for (size_t i = 0; i < streams_.size(); ++i) {
      webrtc::MediaStreamTrackInterface* track =
          streams_.at(i)->FindAudioTrack(id).get();
      if (track)
        return track;
    }
    return nullptr;
  }
  webrtc::MediaStreamTrackInterface* FindVideoTrack(
      const std::string& id) override {
    for (size_t i = 0; i < streams_.size(); ++i) {
      webrtc::MediaStreamTrackInterface* track =
          streams_.at(i)->FindVideoTrack(id).get();
      if (track)
        return track;
    }
    return nullptr;
  }
  void AddStream(MediaStreamInterface* stream) {
    streams_.emplace_back(stream);
  }
  void RemoveStream(MediaStreamInterface* stream) {
    auto it = streams_.begin();
    for (; it != streams_.end(); ++it) {
      if (it->get() == stream) {
        streams_.erase(it);
        break;
      }
    }
  }

 protected:
  ~MockStreamCollection() override {}

 private:
  typedef std::vector<rtc::scoped_refptr<MediaStreamInterface>> StreamVector
      ALLOW_DISCOURAGED_TYPE(
          "Avoids conversion when implementing "
          "webrtc::StreamCollectionInterface");
  StreamVector streams_;
};

class MockDtmfSender : public DtmfSenderInterface {
 public:
  void RegisterObserver(DtmfSenderObserverInterface* observer) override {
    observer_ = observer;
  }
  void UnregisterObserver() override { observer_ = nullptr; }
  bool CanInsertDtmf() override { return true; }
  bool InsertDtmf(const std::string& tones,
                  int duration,
                  int inter_tone_gap) override {
    tones_ = tones;
    duration_ = duration;
    inter_tone_gap_ = inter_tone_gap;
    return true;
  }
  std::string tones() const override { return tones_; }
  int duration() const override { return duration_; }
  int inter_tone_gap() const override { return inter_tone_gap_; }

 private:
  raw_ptr<DtmfSenderObserverInterface> observer_ = nullptr;
  std::string tones_;
  int duration_ = 0;
  int inter_tone_gap_ = 0;
};

FakeRtpSender::FakeRtpSender(
    rtc::scoped_refptr<webrtc::MediaStreamTrackInterface> track,
    std::vector<std::string> stream_ids)
    : track_(std::move(track)), stream_ids_(std::move(stream_ids)) {}

FakeRtpSender::~FakeRtpSender() {}

bool FakeRtpSender::SetTrack(webrtc::MediaStreamTrackInterface* track) {
  track_ = track;
  return true;
}

rtc::scoped_refptr<webrtc::MediaStreamTrackInterface> FakeRtpSender::track()
    const {
  return track_;
}

rtc::scoped_refptr<webrtc::DtlsTransportInterface>
FakeRtpSender::dtls_transport() const {
  return transport_;
}

uint32_t FakeRtpSender::ssrc() const {
  NOTIMPLEMENTED();
  return 0;
}

cricket::MediaType FakeRtpSender::media_type() const {
  NOTIMPLEMENTED();
  return cricket::MEDIA_TYPE_AUDIO;
}

std::string FakeRtpSender::id() const {
  NOTIMPLEMENTED();
  return "";
}

std::vector<std::string> FakeRtpSender::stream_ids() const {
  return stream_ids_;
}

void FakeRtpSender::SetStreams(const std::vector<std::string>& stream_ids) {
  stream_ids_ = stream_ids;
}

std::vector<webrtc::RtpEncodingParameters> FakeRtpSender::init_send_encodings()
    const {
  return {};
}

webrtc::RtpParameters FakeRtpSender::GetParameters() const {
  NOTIMPLEMENTED();
  return webrtc::RtpParameters();
}

webrtc::RTCError FakeRtpSender::SetParameters(
    const webrtc::RtpParameters& parameters) {
  NOTIMPLEMENTED();
  return webrtc::RTCError::OK();
}

rtc::scoped_refptr<webrtc::DtmfSenderInterface> FakeRtpSender::GetDtmfSender()
    const {
  return rtc::scoped_refptr<webrtc::DtmfSenderInterface>(
      new rtc::RefCountedObject<MockDtmfSender>());
}

FakeRtpReceiver::FakeRtpReceiver(
    rtc::scoped_refptr<webrtc::MediaStreamTrackInterface> track,
    std::vector<rtc::scoped_refptr<webrtc::MediaStreamInterface>> streams)
    : track_(std::move(track)), streams_(std::move(streams)) {}

FakeRtpReceiver::~FakeRtpReceiver() {}

rtc::scoped_refptr<webrtc::MediaStreamTrackInterface> FakeRtpReceiver::track()
    const {
  return track_;
}

rtc::scoped_refptr<webrtc::DtlsTransportInterface>
FakeRtpReceiver::dtls_transport() const {
  return transport_;
}

std::vector<rtc::scoped_refptr<webrtc::MediaStreamInterface>>
FakeRtpReceiver::streams() const {
  return streams_;
}

std::vector<std::string> FakeRtpReceiver::stream_ids() const {
  std::vector<std::string> stream_ids;
  for (const auto& stream : streams_)
    stream_ids.push_back(stream->id());
  return stream_ids;
}

cricket::MediaType FakeRtpReceiver::media_type() const {
  NOTIMPLEMENTED();
  return cricket::MEDIA_TYPE_AUDIO;
}

std::string FakeRtpReceiver::id() const {
  NOTIMPLEMENTED();
  return "";
}

webrtc::RtpParameters FakeRtpReceiver::GetParameters() const {
  NOTIMPLEMENTED();
  return webrtc::RtpParameters();
}

bool FakeRtpReceiver::SetParameters(const webrtc::RtpParameters& parameters) {
  NOTIMPLEMENTED();
  return false;
}

void FakeRtpReceiver::SetObserver(
    webrtc::RtpReceiverObserverInterface* observer) {
  NOTIMPLEMENTED();
}

void FakeRtpReceiver::SetJitterBufferMinimumDelay(
    std::optional<double> delay_seconds) {
  NOTIMPLEMENTED();
}

std::vector<webrtc::RtpSource> FakeRtpReceiver::GetSources() const {
  NOTIMPLEMENTED();
  return std::vector<webrtc::RtpSource>();
}

FakeRtpTransceiver::FakeRtpTransceiver(
    cricket::MediaType media_type,
    rtc::scoped_refptr<FakeRtpSender> sender,
    rtc::scoped_refptr<FakeRtpReceiver> receiver,
    std::optional<std::string> mid,
    bool stopped,
    webrtc::RtpTransceiverDirection direction,
    std::optional<webrtc::RtpTransceiverDirection> current_direction)
    : media_type_(media_type),
      sender_(std::move(sender)),
      receiver_(std::move(receiver)),
      mid_(std::move(mid)),
      stopped_(stopped),
      direction_(direction),
      current_direction_(current_direction) {}

FakeRtpTransceiver::~FakeRtpTransceiver() = default;

void FakeRtpTransceiver::ReplaceWith(const FakeRtpTransceiver& other) {
  media_type_ = other.media_type_;
  sender_ = other.sender_;
  receiver_ = other.receiver_;
  mid_ = other.mid_;
  stopped_ = other.stopped_;
  direction_ = other.direction_;
  current_direction_ = other.current_direction_;
}

cricket::MediaType FakeRtpTransceiver::media_type() const {
  return media_type_;
}

std::optional<std::string> FakeRtpTransceiver::mid() const {
  return mid_;
}

rtc::scoped_refptr<webrtc::RtpSenderInterface> FakeRtpTransceiver::sender()
    const {
  return sender_;
}

rtc::scoped_refptr<webrtc::RtpReceiverInterface> FakeRtpTransceiver::receiver()
    const {
  return receiver_;
}

bool FakeRtpTransceiver::stopped() const {
  return stopped_;
}

bool FakeRtpTransceiver::stopping() const {
  NOTIMPLEMENTED();
  return false;
}

webrtc::RtpTransceiverDirection FakeRtpTransceiver::direction() const {
  return direction_;
}

std::optional<webrtc::RtpTransceiverDirection>
FakeRtpTransceiver::current_direction() const {
  return current_direction_;
}

void FakeRtpTransceiver::SetTransport(
    rtc::scoped_refptr<webrtc::DtlsTransportInterface> transport) {
  sender_->SetTransport(transport);
  receiver_->SetTransport(transport);
}

FakeDtlsTransport::FakeDtlsTransport() {}

rtc::scoped_refptr<webrtc::IceTransportInterface>
FakeDtlsTransport::ice_transport() {
  return nullptr;
}

webrtc::DtlsTransportInformation FakeDtlsTransport::Information() {
  return webrtc::DtlsTransportInformation(webrtc::DtlsTransportState::kNew);
}

const char MockPeerConnectionImpl::kDummyOffer[] = "dummy offer";
const char MockPeerConnectionImpl::kDummyAnswer[] = "dummy answer";

MockPeerConnectionImpl::MockPeerConnectionImpl(
    MockPeerConnectionDependencyFactory* factory,
    webrtc::PeerConnectionObserver* observer)
    : remote_streams_(new rtc::RefCountedObject<MockStreamCollection>),
      hint_audio_(false),
      hint_video_(false),
      getstats_result_(true),
      sdp_mline_index_(-1),
      observer_(observer) {
  // TODO(hbos): Remove once no longer mandatory to implement.
  ON_CALL(*this, SetLocalDescription(_, _))
      .WillByDefault(testing::Invoke(
          this, &MockPeerConnectionImpl::SetLocalDescriptionWorker));
  ON_CALL(*this, SetLocalDescriptionForMock(_, _))
      .WillByDefault(testing::Invoke(
          [this](
              std::unique_ptr<webrtc::SessionDescriptionInterface>* desc,
              rtc::scoped_refptr<webrtc::SetLocalDescriptionObserverInterface>*
                  observer) {
            SetLocalDescriptionWorker(nullptr, desc->release());
          }));
  // TODO(hbos): Remove once no longer mandatory to implement.
  ON_CALL(*this, SetRemoteDescription(_, _))
      .WillByDefault(testing::Invoke(
          this, &MockPeerConnectionImpl::SetRemoteDescriptionWorker));
  ON_CALL(*this, SetRemoteDescriptionForMock(_, _))
      .WillByDefault(testing::Invoke(
          [this](
              std::unique_ptr<webrtc::SessionDescriptionInterface>* desc,
              rtc::scoped_refptr<webrtc::SetRemoteDescriptionObserverInterface>*
                  observer) {
            SetRemoteDescriptionWorker(nullptr, desc->release());
          }));
}

MockPeerConnectionImpl::~MockPeerConnectionImpl() {}

webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpSenderInterface>>
MockPeerConnectionImpl::AddTrack(
    rtc::scoped_refptr<webrtc::MediaStreamTrackInterface> track,
    const std::vector<std::string>& stream_ids) {
  DCHECK(track);
  DCHECK_EQ(1u, stream_ids.size());
  for (const auto& sender : senders_) {
    if (sender->track() == track)
      return webrtc::RTCError(webrtc::RTCErrorType::INVALID_PARAMETER);
  }
  for (const auto& stream_id : stream_ids) {
    if (!base::Contains(local_stream_ids_, stream_id)) {
      stream_label_ = stream_id;
      local_stream_ids_.push_back(stream_id);
    }
  }
  rtc::scoped_refptr<FakeRtpSender> sender(
      new rtc::RefCountedObject<FakeRtpSender>(track, stream_ids));
  senders_.push_back(sender);
  // This mock is dumb. It creates an audio transceiver without checking the
  // kind of the sender track.
  rtc::scoped_refptr<webrtc::MediaStreamTrackInterface> dummy_receiver_track(
      blink::MockWebRtcAudioTrack::Create("dummy_track").get());
  rtc::scoped_refptr<FakeRtpReceiver> dummy_receiver(
      new rtc::RefCountedObject<FakeRtpReceiver>(dummy_receiver_track));
  rtc::scoped_refptr<FakeRtpTransceiver> transceiver(
      new rtc::RefCountedObject<FakeRtpTransceiver>(
          cricket::MediaType::MEDIA_TYPE_AUDIO, sender, dummy_receiver,
          std::nullopt, false, webrtc::RtpTransceiverDirection::kSendRecv,
          std::nullopt));
  transceivers_.push_back(transceiver);
  return rtc::scoped_refptr<webrtc::RtpSenderInterface>(sender);
}

webrtc::RTCError MockPeerConnectionImpl::RemoveTrackOrError(
    rtc::scoped_refptr<webrtc::RtpSenderInterface> s) {
  rtc::scoped_refptr<FakeRtpSender> sender(
      static_cast<FakeRtpSender*>(s.get()));
  if (!base::Contains(senders_, sender)) {
    return webrtc::RTCError(webrtc::RTCErrorType::INVALID_PARAMETER,
                            "Mock: sender not found in senders");
  }
  sender->SetTrack(nullptr);

  for (const auto& stream_id : sender->stream_ids()) {
    auto local_stream_it = base::ranges::find(local_stream_ids_, stream_id);
    if (local_stream_it != local_stream_ids_.end())
      local_stream_ids_.erase(local_stream_it);
  }
  return webrtc::RTCError::OK();
}

std::vector<rtc::scoped_refptr<webrtc::RtpSenderInterface>>
MockPeerConnectionImpl::GetSenders() const {
  std::vector<rtc::scoped_refptr<webrtc::RtpSenderInterface>> senders;
  for (const auto& sender : senders_)
    senders.push_back(sender);
  return senders;
}

std::vector<rtc::scoped_refptr<webrtc::RtpReceiverInterface>>
MockPeerConnectionImpl::GetReceivers() const {
  std::vector<rtc::scoped_refptr<webrtc::RtpReceiverInterface>> receivers;
  for (size_t i = 0; i < remote_streams_->count(); ++i) {
    for (const auto& audio_track : remote_streams_->at(i)->GetAudioTracks()) {
      receivers.emplace_back(
          new rtc::RefCountedObject<FakeRtpReceiver>(audio_track));
    }
    for (const auto& video_track : remote_streams_->at(i)->GetVideoTracks()) {
      receivers.emplace_back(
          new rtc::RefCountedObject<FakeRtpReceiver>(video_track));
    }
  }
  return receivers;
}

std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>>
MockPeerConnectionImpl::GetTransceivers() const {
  std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>> transceivers;
  for (const auto& transceiver : transceivers_)
    transceivers.push_back(transceiver);
  return transceivers;
}

webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::DataChannelInterface>>
MockPeerConnectionImpl::CreateDataChannelOrError(
    const std::string& label,
    const webrtc::DataChannelInit* config) {
  return rtc::scoped_refptr<webrtc::DataChannelInterface>(
      new rtc::RefCountedObject<blink::MockDataChannel>(label, config));
}

bool MockPeerConnectionImpl::GetStats(webrtc::StatsObserver* observer,
                                      webrtc::MediaStreamTrackInterface* track,
                                      StatsOutputLevel level) {
  if (!getstats_result_)
    return false;

  DCHECK_EQ(kStatsOutputLevelStandard, level);
  webrtc::StatsReport report1(webrtc::StatsReport::NewTypedId(
      webrtc::StatsReport::kStatsReportTypeSsrc, "1234"));
  webrtc::StatsReport report2(webrtc::StatsReport::NewTypedId(
      webrtc::StatsReport::kStatsReportTypeSession, "nontrack"));
  report1.set_timestamp(42);
  report1.AddString(webrtc::StatsReport::kStatsValueNameFingerprint,
                    "trackvalue");

  webrtc::StatsReports reports;
  reports.push_back(&report1);

  // If selector is given, we pass back one report.
  // If selector is not given, we pass back two.
  if (!track) {
    report2.set_timestamp(44);
    report2.AddString(webrtc::StatsReport::kStatsValueNameFingerprintAlgorithm,
                      "somevalue");
    reports.push_back(&report2);
  }

  // Note that the callback is synchronous, not asynchronous; it will
  // happen before the request call completes.
  observer->OnComplete(reports);

  return true;
}

void MockPeerConnectionImpl::GetStats(
    webrtc::RTCStatsCollectorCallback* callback) {
  DCHECK(callback);
  DCHECK(stats_report_);
  callback->OnStatsDelivered(stats_report_);
}

void MockPeerConnectionImpl::GetStats(
    rtc::scoped_refptr<webrtc::RtpSenderInterface> selector,
    rtc::scoped_refptr<webrtc::RTCStatsCollectorCallback> callback) {
  callback->OnStatsDelivered(stats_report_);
}

void MockPeerConnectionImpl::GetStats(
    rtc::scoped_refptr<webrtc::RtpReceiverInterface> selector,
    rtc::scoped_refptr<webrtc::RTCStatsCollectorCallback> callback) {
  callback->OnStatsDelivered(stats_report_);
}

void MockPeerConnectionImpl::SetGetStatsReport(webrtc::RTCStatsReport* report) {
  stats_report_ = report;
}

const webrtc::SessionDescriptionInterface*
MockPeerConnectionImpl::local_description() const {
  return local_desc_.get();
}

const webrtc::SessionDescriptionInterface*
MockPeerConnectionImpl::remote_description() const {
  return remote_desc_.get();
}

void MockPeerConnectionImpl::AddRemoteStream(MediaStreamInterface* stream) {
  remote_streams_->AddStream(stream);
}

void MockPeerConnectionImpl::CreateOffer(
    CreateSessionDescriptionObserver* observer,
    const RTCOfferAnswerOptions& options) {
  DCHECK(observer);
  created_sessiondescription_ =
      MockParsedSessionDescription("unknown", kDummyAnswer).release();
}

void MockPeerConnectionImpl::CreateAnswer(
    CreateSessionDescriptionObserver* observer,
    const RTCOfferAnswerOptions& options) {
  DCHECK(observer);
  created_sessiondescription_ =
      MockParsedSessionDescription("unknown", kDummyAnswer).release();
}

void MockPeerConnectionImpl::SetLocalDescriptionWorker(
    SetSessionDescriptionObserver* observer,
    SessionDescriptionInterface* desc) {
  desc->ToString(&description_sdp_);
  local_desc_.reset(desc);
}

void MockPeerConnectionImpl::SetRemoteDescriptionWorker(
    SetSessionDescriptionObserver* observer,
    SessionDescriptionInterface* desc) {
  desc->ToString(&description_sdp_);
  remote_desc_.reset(desc);
}

webrtc::RTCError MockPeerConnectionImpl::SetConfiguration(
    const RTCConfiguration& configuration) {
  return webrtc::RTCError(setconfiguration_error_type_);
}

bool MockPeerConnectionImpl::AddIceCandidate(
    const IceCandidateInterface* candidate) {
  sdp_mid_ = candidate->sdp_mid();
  sdp_mline_index_ = candidate->sdp_mline_index();
  return candidate->ToString(&ice_sdp_);
}

void MockPeerConnectionImpl::AddIceCandidate(
    std::unique_ptr<webrtc::IceCandidateInterface> candidate,
    std::function<void(webrtc::RTCError)> callback) {
  bool result = AddIceCandidate(candidate.get());
  callback(result
               ? webrtc::RTCError::OK()
               : webrtc::RTCError(webrtc::RTCErrorType::UNSUPPORTED_OPERATION));
}

}  // namespace blink

"""

```
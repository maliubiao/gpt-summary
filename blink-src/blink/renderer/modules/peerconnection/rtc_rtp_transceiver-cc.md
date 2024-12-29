Response:
Let's break down the thought process for analyzing the `rtc_rtp_transceiver.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relationship to web technologies, logical inferences, common usage errors, and debugging tips. This requires a multi-faceted analysis.

2. **Initial Skim for High-Level Purpose:**  Quickly read the file, paying attention to includes, class names, and key methods. The name `RTCRtpTransceiver` immediately suggests involvement in WebRTC's RTP (Real-time Transport Protocol) functionality. The includes point to related classes like `RTCPeerConnection`, `RTCRtpSender`, and `RTCRtpReceiver`. This suggests the file manages the combined sending and receiving aspects of a media stream within a WebRTC connection.

3. **Identify Core Functionality - What does it *do*?:**

    * **Managing Send/Receive:** Look for methods and attributes related to directionality (send, receive, sendrecv, etc.). The `direction()` and `setDirection()` methods, and the `V8RTCRtpTransceiverDirection` enum are key here.
    * **RTP Sender/Receiver Coordination:** The file holds references to `RTCRtpSender` and `RTCRtpReceiver`. This indicates it acts as a central point for these components.
    * **Stopping/Starting Streams:** The `stop()` method is present.
    * **Codec Negotiation:** The `setCodecPreferences()` method strongly suggests handling codec selection.
    * **Header Extension Negotiation:**  The methods `setHeaderExtensionsToNegotiate()` and `getHeaderExtensionsToNegotiate()` clearly relate to RTP header extensions.
    * **Mid (Media ID):** The `mid()` method indicates it manages a unique identifier for the transceiver.
    * **State Management:**  The `currentDirection()` and `stopped()` methods imply tracking the transceiver's state.

4. **Analyze Relationships with Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:** This is the most direct link. Think about how a web developer interacts with WebRTC. They use the `RTCPeerConnection` API, which includes methods like `addTransceiver()`. The `RTCRtpTransceiver` object itself is exposed to JavaScript, allowing developers to control its direction, stop it, and potentially influence codec/header extension negotiation (though direct manipulation of the latter might be less common). The code confirms this by using Blink's binding infrastructure (`V8RTCRtpTransceiverDirection`).
    * **HTML:**  While not directly involved in the *logic* of this file, HTML provides the structure for the web page where the JavaScript using WebRTC runs. Consider scenarios like `<video>` or `<audio>` elements displaying the media streams.
    * **CSS:** CSS styles the HTML elements. It doesn't directly interact with the WebRTC logic in this file, but it affects how the media streams are presented visually.

5. **Logical Inferences (Assumptions and Outputs):**

    * Focus on methods that take input and produce a change or return a value. `setDirection()` is a prime example. Think about valid and invalid inputs and the corresponding outcomes (exceptions or state changes).
    * `TransceiverDirectionToEnum` and `TransceiverDirectionFromEnum` are good examples of simple input/output mappings.

6. **Identify Common Usage Errors:**

    * Think about how a developer might misuse the API related to `RTCRtpTransceiver`.
    * **Setting direction after stopping:**  A common mistake. The code explicitly checks for this.
    * **Invalid direction values:** The code validates the input direction.
    * **Calling methods on a closed `RTCPeerConnection`:** Another common error, handled by the code.
    * **Incorrect codec/header extension formats:** The parsing logic in `setCodecPreferences` and `setHeaderExtensionsToNegotiate` highlights potential format errors.

7. **Debugging Scenario (User Steps):**

    * Start with a basic WebRTC scenario: a user wanting to make a video/audio call.
    * Trace the steps from the user's interaction (e.g., clicking a "call" button) to the point where the `RTCRtpTransceiver` becomes relevant. This involves JavaScript calling WebRTC APIs.
    *  Focus on where the `RTCRtpTransceiver` object is created and how its methods are used during the connection setup and media negotiation process.

8. **Code Snippet Analysis (Detailed Examination):**

    * Go through each function and understand its purpose. Pay attention to error handling, state updates, and interactions with other components (like `platform_transceiver_`).
    * The conversion functions between the Blink/V8 enum and the internal WebRTC enum are crucial.
    * The handling of `webrtc::RTCError` is important for understanding how errors from the underlying WebRTC implementation are propagated.

9. **Structure and Refine:** Organize the findings into the requested categories: functionality, web technology relationship, logical inferences, usage errors, and debugging. Use clear and concise language. Provide concrete examples where possible.

10. **Review and Iterate:**  Read through the generated explanation to ensure accuracy and completeness. Check if the examples are relevant and easy to understand. Are there any missing aspects?  For instance, initially, I might have overlooked the importance of the `platform_transceiver_`. A second pass would help identify such gaps.

By following this structured approach, one can effectively analyze a complex source code file like `rtc_rtp_transceiver.cc` and provide a comprehensive explanation. The key is to combine high-level understanding with detailed code examination.
好的，让我们来分析一下 `blink/renderer/modules/peerconnection/rtc_rtp_transceiver.cc` 这个文件。

**功能概要:**

`RTCRtpTransceiver.cc` 文件定义了 `RTCRtpTransceiver` 类，它是 WebRTC API 中 `RTCRtpTransceiver` 接口在 Blink 渲染引擎中的实现。  `RTCRtpTransceiver` 的核心功能是**管理一个媒体轨道（音频或视频）的发送和接收过程**。  它可以同时处理发送和接收，也可以只发送、只接收或者处于非活动状态。

更具体地说，`RTCRtpTransceiver` 承担以下职责：

1. **封装和管理 `RTCRtpSender` 和 `RTCRtpReceiver`:**  每个 `RTCRtpTransceiver` 实例都包含一个 `RTCRtpSender`（负责发送媒体）和一个 `RTCRtpReceiver`（负责接收媒体）。`RTCRtpTransceiver` 协调它们的操作。
2. **控制媒体的传输方向:**  它允许设置和获取媒体的传输方向，例如 "sendrecv" (发送和接收), "sendonly" (仅发送), "recvonly" (仅接收), "inactive" (不发送也不接收), 以及 "stopped" (已停止)。
3. **管理媒体的中间标识符 (MID):**  `RTCRtpTransceiver` 有一个 `mid` 属性，用于在 SDP (Session Description Protocol) 协商过程中唯一标识这个媒体轨道。
4. **处理编解码器偏好设置:**  它允许设置发送器希望使用的编解码器列表，以便在 SDP 协商时提供建议。
5. **处理 RTP 头部扩展的协商:**  它允许设置和获取需要协商的 RTP 头部扩展，以及获取最终协商确定的扩展。
6. **停止媒体传输:**  它提供了 `stop()` 方法来停止发送和接收媒体。
7. **与底层的平台特定实现交互:**  它使用 `RTCRtpTransceiverPlatform` 抽象类与底层的 WebRTC 实现进行交互，执行实际的媒体发送和接收操作。
8. **状态管理:**  维护 transceiver 的状态，例如当前方向和是否已停止。

**与 JavaScript, HTML, CSS 的关系:**

`RTCRtpTransceiver` 是 WebRTC API 的一部分，因此与 JavaScript 有着直接的关系。  HTML 用于构建网页结构，而 CSS 用于控制网页样式。  `RTCRtpTransceiver` 通过 JavaScript API 被使用，从而影响在 HTML 页面上展示的媒体。

**JavaScript 举例:**

```javascript
// 获取 RTCPeerConnection 对象
const pc = new RTCPeerConnection();

// 添加一个音频 transceiver，初始方向为发送和接收
const audioTransceiver = pc.addTransceiver('audio');

// 获取 transceiver 的 sender 和 receiver
const sender = audioTransceiver.sender;
const receiver = audioTransceiver.receiver;

// 获取 transceiver 的当前方向
console.log(audioTransceiver.direction); // 输出 "sendrecv"

// 改变 transceiver 的方向为只发送
audioTransceiver.direction = 'sendonly';

// 停止 transceiver
audioTransceiver.stop();
```

在这个例子中，JavaScript 代码直接使用了 `RTCRtpTransceiver` API 来创建、配置和控制媒体轨道的传输。

**HTML 举例:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>WebRTC Example</title>
</head>
<body>
  <video id="remoteVideo" autoplay playsinline></video>
  <script src="webrtc_script.js"></script>
</body>
</html>
```

虽然 HTML 本身不直接操作 `RTCRtpTransceiver`，但是通过 JavaScript 代码使用 WebRTC API，接收到的媒体流可以被设置为 HTML `<video>` 或 `<audio>` 元素的 `srcObject`，从而在页面上显示或播放。`RTCRtpTransceiver` 负责管理这个媒体流的接收。

**CSS 举例:**

```css
#remoteVideo {
  width: 640px;
  height: 480px;
}
```

CSS 用于设置 HTML 元素（例如 `<video>`）的样式。  即使 `RTCRtpTransceiver` 负责接收视频流，CSS 决定了该视频在网页上的尺寸和外观。

**逻辑推理 (假设输入与输出):**

假设我们有一个 `RTCRtpTransceiver` 对象 `transceiver`，并且其初始状态如下：

* `direction_`: `V8RTCRtpTransceiverDirection::Enum::kSendrecv`
* `current_direction_`: `std::optional<V8RTCRtpTransceiverDirection::Enum>(V8RTCRtpTransceiverDirection::Enum::kSendrecv)`

**假设输入:** JavaScript 代码调用 `transceiver.setDirection('sendonly')`。

**逻辑推理过程:**

1. `RTCRtpTransceiver::setDirection` 方法被调用，传入 `V8RTCRtpTransceiverDirection::Enum::kSendonly`。
2. `TransceiverDirectionFromEnum` 函数将 JavaScript 传入的枚举值转换为底层的 `webrtc::RtpTransceiverDirection::kSendOnly`。
3. 代码检查 `pc_` 是否已关闭，以及 `current_direction_` 和 `direction_` 是否为 `kStopped`。假设这些检查都通过。
4. 调用底层的 `platform_transceiver_->SetDirection(webrtc::RtpTransceiverDirection::kSendOnly)`。
5. 如果底层的设置成功，`UpdateMembers()` 方法会被调用。
6. 在 `UpdateMembers()` 中，`direction_` 将被更新为 `V8RTCRtpTransceiverDirection::Enum::kSendonly`。
7. `current_direction_` 的值可能会保持不变，也可能根据底层的实际状态更新。

**假设输出 (如果底层设置成功):**

* `transceiver.direction()` 将返回 `V8RTCRtpTransceiverDirection(V8RTCRtpTransceiverDirection::Enum::kSendonly)`。
* `transceiver.currentDirection()` 的返回值取决于底层的状态，可能仍然是 `sendrecv`，直到下一次 SDP 协商完成。

**涉及用户或者编程常见的使用错误:**

1. **在 `RTCPeerConnection` 关闭后尝试操作 `RTCRtpTransceiver`:**

   ```javascript
   const pc = new RTCPeerConnection();
   const transceiver = pc.addTransceiver('video');
   pc.close();
   transceiver.setDirection('sendonly'); // 错误： peer connection is closed
   ```
   **错误信息:**  "The peer connection is closed." (对应代码中的 `exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "The peer connection is closed.");`)

2. **在 transceiver 已经停止后尝试设置方向:**

   ```javascript
   const pc = new RTCPeerConnection();
   const transceiver = pc.addTransceiver('video');
   transceiver.stop();
   transceiver.setDirection('sendonly'); // 错误： transceiver is stopped
   ```
   **错误信息:** "The transceiver is stopped." (对应代码中的 `exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "The transceiver is stopped.");`)

3. **提供无效的 `RTCRtpTransceiverDirection` 值:**

   ```javascript
   const pc = new RTCPeerConnection();
   const transceiver = pc.addTransceiver('video');
   transceiver.direction = 'invalid-direction'; // 错误： Invalid RTCRtpTransceiverDirection.
   ```
   **错误信息:**  "Invalid RTCRtpTransceiverDirection." (对应代码中的 `exception_state.ThrowTypeError("Invalid RTCRtpTransceiverDirection.");`)

4. **尝试设置不支持的编解码器偏好:**

   ```javascript
   const pc = new RTCPeerConnection();
   const transceiver = pc.addTransceiver('video');
   const codecs = [{ mimeType: 'video/H265' }]; // 假设浏览器不支持 H265
   transceiver.setCodecPreferences(codecs); // 可能会抛出异常
   ```
   **错误信息:**  具体的错误信息会根据底层 WebRTC 实现返回，例如 "InvalidModificationError: Setting codec preferences failed"。

5. **尝试设置格式错误的 RTP 头部扩展:**

   ```javascript
   const pc = new RTCPeerConnection();
   const transceiver = pc.addTransceiver('video');
   const extensions = [{ uri: '' }]; // 空 URI 是不允许的
   transceiver.setHeaderExtensionsToNegotiate(extensions); // 抛出 TypeError
   ```
   **错误信息:** "The extension URL cannot be empty."

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户正在使用一个基于 WebRTC 的视频会议应用：

1. **用户打开网页并加入会议:**  用户的浏览器加载 HTML、CSS 和 JavaScript 代码。
2. **JavaScript 代码初始化 `RTCPeerConnection`:**  当用户点击 "加入会议" 按钮时，JavaScript 代码会创建一个 `RTCPeerConnection` 对象。
3. **JavaScript 代码添加 transceiver:**  为了处理本地摄像头或麦克风的媒体流，或者为了接收远端用户的媒体流，JavaScript 代码会调用 `pc.addTransceiver('audio')` 或 `pc.addTransceiver('video')`。  **这时，`RTCRtpTransceiver` 对象在 Blink 渲染引擎中被创建。**
4. **用户允许访问摄像头和麦克风:**  浏览器会提示用户授权访问本地媒体设备。
5. **`RTCRtpSender` 获取本地媒体流:**  如果添加的是发送 transceiver，对应的 `RTCRtpSender` 会获取本地媒体流。
6. **SDP 协商开始:**  `RTCPeerConnection` 会开始与远端进行 SDP 协商，以确定双方都可以接受的媒体格式、编解码器、传输方式等。  `RTCRtpTransceiver` 的 `mid` 属性在这个过程中非常重要。
7. **JavaScript 代码可能会设置 transceiver 的方向:**  根据应用的逻辑，JavaScript 代码可能会动态地修改 transceiver 的方向，例如在静音时将音频 transceiver 的方向设置为 `recvonly` 或 `inactive`。  **这时会调用 `RTCRtpTransceiver::setDirection` 方法。**
8. **用户可能会停止发送或接收媒体:**  例如，点击 "停止共享屏幕" 按钮会调用相应的 JavaScript 代码，可能会导致调用 `transceiver.stop()`。  **这将触发 `RTCRtpTransceiver::stop` 方法。**
9. **在调试过程中:** 如果开发者在 JavaScript 代码中遇到了与 transceiver 相关的错误（例如上述的使用错误），他们需要查看浏览器的开发者工具中的错误信息。  如果需要更深入的调试，他们可能需要查看 Chromium 的源代码，例如 `rtc_rtp_transceiver.cc`，来理解错误是如何产生的，以及内部的状态变化。  设置断点在 `RTCRtpTransceiver` 的方法中，可以帮助理解代码的执行流程和变量的值。

总而言之，`rtc_rtp_transceiver.cc` 文件是 WebRTC 媒体收发功能的核心组成部分，它在 JavaScript API 和底层的媒体传输实现之间架起了桥梁，负责管理媒体轨道的发送和接收过程。 理解其功能和可能的错误场景对于开发和调试 WebRTC 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_rtp_transceiver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_transceiver.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_rtp_header_extension_capability.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_error_util.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_receiver.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_rtp_sender.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"

namespace blink {

namespace {

V8RTCRtpTransceiverDirection::Enum TransceiverDirectionToEnum(
    const webrtc::RtpTransceiverDirection& direction) {
  switch (direction) {
    case webrtc::RtpTransceiverDirection::kSendRecv:
      return V8RTCRtpTransceiverDirection::Enum::kSendrecv;
    case webrtc::RtpTransceiverDirection::kSendOnly:
      return V8RTCRtpTransceiverDirection::Enum::kSendonly;
    case webrtc::RtpTransceiverDirection::kRecvOnly:
      return V8RTCRtpTransceiverDirection::Enum::kRecvonly;
    case webrtc::RtpTransceiverDirection::kInactive:
      return V8RTCRtpTransceiverDirection::Enum::kInactive;
    case webrtc::RtpTransceiverDirection::kStopped:
      return V8RTCRtpTransceiverDirection::Enum::kStopped;
  }
  NOTREACHED();
}

std::optional<V8RTCRtpTransceiverDirection::Enum>
OptionalTransceiverDirectionToEnum(
    const std::optional<webrtc::RtpTransceiverDirection>& direction) {
  if (!direction) {
    return std::nullopt;
  }
  return TransceiverDirectionToEnum(*direction);
}

bool TransceiverDirectionFromEnum(
    V8RTCRtpTransceiverDirection::Enum direction,
    std::optional<webrtc::RtpTransceiverDirection>* direction_out) {
  switch (direction) {
    case V8RTCRtpTransceiverDirection::Enum::kSendrecv:
      *direction_out = webrtc::RtpTransceiverDirection::kSendRecv;
      return true;
    case V8RTCRtpTransceiverDirection::Enum::kSendonly:
      *direction_out = webrtc::RtpTransceiverDirection::kSendOnly;
      return true;
    case V8RTCRtpTransceiverDirection::Enum::kRecvonly:
      *direction_out = webrtc::RtpTransceiverDirection::kRecvOnly;
      return true;
    case V8RTCRtpTransceiverDirection::Enum::kInactive:
      *direction_out = webrtc::RtpTransceiverDirection::kInactive;
      return true;
    case V8RTCRtpTransceiverDirection::Enum::kStopped:
      return false;
  }
  NOTREACHED();
}

bool OptionalTransceiverDirectionFromEnumWithStopped(
    V8RTCRtpTransceiverDirection::Enum direction,
    std::optional<webrtc::RtpTransceiverDirection>* direction_out) {
  if (direction == V8RTCRtpTransceiverDirection::Enum::kStopped) {
    *direction_out = webrtc::RtpTransceiverDirection::kStopped;
    return true;
  }
  return TransceiverDirectionFromEnum(direction, direction_out);
}

}  // namespace

webrtc::RtpTransceiverInit ToRtpTransceiverInit(
    ExecutionContext* context,
    const RTCRtpTransceiverInit* init,
    const String& kind) {
  webrtc::RtpTransceiverInit webrtc_init;
  std::optional<webrtc::RtpTransceiverDirection> direction;
  if (init->hasDirection() &&
      TransceiverDirectionFromEnum(init->direction().AsEnum(), &direction) &&
      direction) {
    webrtc_init.direction = *direction;
  }
  DCHECK(init->hasStreams());
  for (const auto& stream : init->streams()) {
    webrtc_init.stream_ids.push_back(stream->id().Utf8());
  }
  DCHECK(init->hasSendEncodings());
  for (const auto& encoding : init->sendEncodings()) {
    webrtc_init.send_encodings.push_back(
        ToRtpEncodingParameters(context, encoding, kind));
  }
  return webrtc_init;
}

RTCRtpTransceiver::RTCRtpTransceiver(
    RTCPeerConnection* pc,
    std::unique_ptr<RTCRtpTransceiverPlatform> platform_transceiver,
    RTCRtpSender* sender,
    RTCRtpReceiver* receiver)
    : pc_(pc),
      platform_transceiver_(std::move(platform_transceiver)),
      sender_(sender),
      receiver_(receiver),
      fired_direction_(std::nullopt) {
  DCHECK(pc_);
  DCHECK(platform_transceiver_);
  DCHECK(sender_);
  DCHECK(receiver_);
  UpdateMembers();
  sender_->set_transceiver(this);
  receiver_->set_transceiver(this);
}

String RTCRtpTransceiver::mid() const {
  return mid_;
}

RTCRtpSender* RTCRtpTransceiver::sender() const {
  return sender_.Get();
}

RTCRtpReceiver* RTCRtpTransceiver::receiver() const {
  return receiver_.Get();
}

bool RTCRtpTransceiver::stopped() const {
  // Non-standard attribute reflecting being "stopping", whether or not we are
  // "stopped" per current_direction_.
  return direction_ == V8RTCRtpTransceiverDirection::Enum::kStopped;
}

V8RTCRtpTransceiverDirection RTCRtpTransceiver::direction() const {
  return V8RTCRtpTransceiverDirection(direction_);
}

void RTCRtpTransceiver::setDirection(
    const V8RTCRtpTransceiverDirection& direction,
    ExceptionState& exception_state) {
  std::optional<webrtc::RtpTransceiverDirection> webrtc_direction;
  if (!TransceiverDirectionFromEnum(direction.AsEnum(), &webrtc_direction) ||
      !webrtc_direction) {
    exception_state.ThrowTypeError("Invalid RTCRtpTransceiverDirection.");
    return;
  }
  if (pc_->IsClosed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The peer connection is closed.");
    return;
  }
  if (current_direction_ == V8RTCRtpTransceiverDirection::Enum::kStopped) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The transceiver is stopped.");
    return;
  }
  if (direction_ == V8RTCRtpTransceiverDirection::Enum::kStopped) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The transceiver is stopping.");
    return;
  }
  webrtc::RTCError error =
      platform_transceiver_->SetDirection(*webrtc_direction);
  if (!error.ok()) {
    ThrowExceptionFromRTCError(error, exception_state);
    return;
  }
  UpdateMembers();
}

std::optional<V8RTCRtpTransceiverDirection>
RTCRtpTransceiver::currentDirection() const {
  if (!current_direction_) {
    return std::nullopt;
  }
  return V8RTCRtpTransceiverDirection(current_direction_.value());
}

void RTCRtpTransceiver::UpdateMembers() {
  if (current_direction_ == V8RTCRtpTransceiverDirection::Enum::kStopped) {
    // No need to update, stopped is a permanent state. Also: on removal, the
    // state of `platform_transceiver_` becomes obsolete and may not reflect
    // being stopped, so let's not update the members anymore.
    return;
  }
  mid_ = platform_transceiver_->Mid();
  direction_ = TransceiverDirectionToEnum(platform_transceiver_->Direction());
  current_direction_ = OptionalTransceiverDirectionToEnum(
      platform_transceiver_->CurrentDirection());
  fired_direction_ = platform_transceiver_->FiredDirection();
}

void RTCRtpTransceiver::OnTransceiverStopped() {
  receiver_->set_streams(MediaStreamVector());
  mid_ = String();
  direction_ =
      TransceiverDirectionToEnum(webrtc::RtpTransceiverDirection::kStopped);
  current_direction_ =
      TransceiverDirectionToEnum(webrtc::RtpTransceiverDirection::kStopped);
  fired_direction_ = webrtc::RtpTransceiverDirection::kStopped;
}

RTCRtpTransceiverPlatform* RTCRtpTransceiver::platform_transceiver() const {
  return platform_transceiver_.get();
}

std::optional<webrtc::RtpTransceiverDirection>
RTCRtpTransceiver::fired_direction() const {
  return fired_direction_;
}

bool RTCRtpTransceiver::DirectionHasSend() const {
  auto direction = platform_transceiver_->Direction();
  return direction == webrtc::RtpTransceiverDirection::kSendRecv ||
         direction == webrtc::RtpTransceiverDirection::kSendOnly;
}

bool RTCRtpTransceiver::DirectionHasRecv() const {
  auto direction = platform_transceiver_->Direction();
  return direction == webrtc::RtpTransceiverDirection::kSendRecv ||
         direction == webrtc::RtpTransceiverDirection::kRecvOnly;
}

bool RTCRtpTransceiver::FiredDirectionHasRecv() const {
  return fired_direction_ &&
         (*fired_direction_ == webrtc::RtpTransceiverDirection::kSendRecv ||
          *fired_direction_ == webrtc::RtpTransceiverDirection::kRecvOnly);
}

void RTCRtpTransceiver::stop(ExceptionState& exception_state) {
  if (pc_->IsClosed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The peer connection is closed.");
    return;
  }
  webrtc::RTCError error = platform_transceiver_->Stop();
  if (!error.ok()) {
    ThrowExceptionFromRTCError(error, exception_state);
    return;
  }
  // We should become stopping, but negotiation is needed to become stopped.
  UpdateMembers();
}

void RTCRtpTransceiver::setCodecPreferences(
    const HeapVector<Member<RTCRtpCodecCapability>>& codecs,
    ExceptionState& exception_state) {
  Vector<webrtc::RtpCodecCapability> codec_preferences;
  codec_preferences.reserve(codecs.size());
  for (const auto& codec : codecs) {
    codec_preferences.emplace_back();
    auto& webrtc_codec = codec_preferences.back();
    auto slash_position = codec->mimeType().find('/');
    if (slash_position == WTF::kNotFound) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidModificationError, "Invalid codec");
      return;
    }
    auto type = codec->mimeType().Left(slash_position);
    if (type == "video") {
      webrtc_codec.kind = cricket::MEDIA_TYPE_VIDEO;
    } else if (type == "audio") {
      webrtc_codec.kind = cricket::MEDIA_TYPE_AUDIO;
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidModificationError, "Invalid codec");
      return;
    }
    webrtc_codec.name = codec->mimeType().Substring(slash_position + 1).Ascii();
    webrtc_codec.clock_rate = codec->clockRate();
    if (codec->hasChannels()) {
      webrtc_codec.num_channels = codec->channels();
    }
    if (codec->hasSdpFmtpLine()) {
      auto sdpFmtpLine = codec->sdpFmtpLine();
      if (sdpFmtpLine.find('=') == WTF::kNotFound) {
        // Some parameters don't follow the key=value form.
        webrtc_codec.parameters.emplace("", sdpFmtpLine.Ascii());
      } else {
        WTF::Vector<WTF::String> parameters;
        sdpFmtpLine.Split(';', parameters);
        for (const auto& parameter : parameters) {
          auto equal_position = parameter.find('=');
          if (equal_position == WTF::kNotFound) {
            exception_state.ThrowDOMException(
                DOMExceptionCode::kInvalidModificationError, "Invalid codec");
            return;
          }
          auto parameter_name = parameter.Left(equal_position);
          auto parameter_value = parameter.Substring(equal_position + 1);
          webrtc_codec.parameters.emplace(parameter_name.Ascii(),
                                          parameter_value.Ascii());
        }
      }
    }
  }
  auto result = platform_transceiver_->SetCodecPreferences(codec_preferences);
  if (!result.ok()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError, result.message());
  }
}

void RTCRtpTransceiver::setHeaderExtensionsToNegotiate(
    const HeapVector<Member<RTCRtpHeaderExtensionCapability>>& extensions,
    ExceptionState& exception_state) {
  Vector<webrtc::RtpHeaderExtensionCapability> webrtc_hdr_exts;
  auto webrtc_offered_exts =
      platform_transceiver_->GetHeaderExtensionsToNegotiate();
  int id = 1;
  for (const auto& hdr_ext : extensions) {
    // Handle invalid requests for mandatory extensions as per
    // https://w3c.github.io/webrtc-extensions/#rtcrtptransceiver-interface
    // Step 2.1 (not handled on the WebRTC level).
    if (hdr_ext->uri().empty()) {
      exception_state.ThrowTypeError("The extension URL cannot be empty.");
      return;
    }

    std::optional<webrtc::RtpTransceiverDirection> direction;
    if (!OptionalTransceiverDirectionFromEnumWithStopped(
            hdr_ext->direction().AsEnum(), &direction) ||
        !direction) {
      exception_state.ThrowTypeError("Invalid RTCRtpTransceiverDirection.");
      return;
    }
    const int id_to_store = direction ? id++ : 0;
    webrtc_hdr_exts.emplace_back(hdr_ext->uri().Ascii(), id_to_store,
                                 *direction);
  }
  webrtc::RTCError status =
      platform_transceiver_->SetHeaderExtensionsToNegotiate(
          std::move(webrtc_hdr_exts));
  if (status.type() == webrtc::RTCErrorType::UNSUPPORTED_PARAMETER) {
    // TODO(crbug.com/1051821): support DOMExceptionCode::kNotSupportedError in
    // rtc_error_util.h/cc and get rid of this manually handled case.
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      status.message());
    return;
  } else if (status.type() != webrtc::RTCErrorType::NONE) {
    ThrowExceptionFromRTCError(status, exception_state);
    return;
  }
}

HeapVector<Member<RTCRtpHeaderExtensionCapability>>
RTCRtpTransceiver::getHeaderExtensionsToNegotiate() const {
  auto webrtc_exts = platform_transceiver_->GetHeaderExtensionsToNegotiate();
  HeapVector<Member<RTCRtpHeaderExtensionCapability>> exts;
  for (const auto& webrtc_ext : webrtc_exts) {
    auto* ext = MakeGarbageCollected<RTCRtpHeaderExtensionCapability>();
    ext->setDirection(TransceiverDirectionToEnum(webrtc_ext.direction));
    ext->setUri(webrtc_ext.uri.c_str());
    exts.push_back(ext);
  }
  return exts;
}

HeapVector<Member<RTCRtpHeaderExtensionCapability>>
RTCRtpTransceiver::getNegotiatedHeaderExtensions() const {
  auto webrtc_exts = platform_transceiver_->GetNegotiatedHeaderExtensions();
  HeapVector<Member<RTCRtpHeaderExtensionCapability>> exts;
  for (const auto& webrtc_ext : webrtc_exts) {
    auto* ext = MakeGarbageCollected<RTCRtpHeaderExtensionCapability>();
    ext->setDirection(TransceiverDirectionToEnum(webrtc_ext.direction));
    ext->setUri(webrtc_ext.uri.c_str());
    exts.push_back(ext);
  }
  return exts;
}

void RTCRtpTransceiver::Trace(Visitor* visitor) const {
  visitor->Trace(pc_);
  visitor->Trace(sender_);
  visitor->Trace(receiver_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

"""

```
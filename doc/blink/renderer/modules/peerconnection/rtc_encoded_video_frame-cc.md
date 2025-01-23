Response:
Let's break down the thought process for analyzing this C++ file and generating the detailed explanation.

1. **Understanding the Request:** The core request is to analyze a specific Chromium source file (`rtc_encoded_video_frame.cc`) and explain its functionality, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning, common usage errors, and how a user's actions could lead to this code being executed.

2. **Initial Code Scan and Keyword Spotting:**  The first step is to quickly scan the code for important keywords and structures. Things that jump out are:
    * `#include`:  This indicates dependencies on other parts of the Chromium codebase and external libraries (like `webrtc`).
    * `namespace blink`:  This confirms it's part of the Blink rendering engine.
    * `RTCEncodedVideoFrame`:  The central class name, suggesting it deals with encoded video frames.
    * `webrtc`:  Heavy involvement with the WebRTC library.
    * `DOMArrayBuffer`: Interaction with JavaScript's `ArrayBuffer`.
    * `RTCEncodedVideoFrameMetadata`, `RTCEncodedVideoFrameOptions`: Classes related to metadata and options.
    * `SetMetadata`, `getMetadata`, `setData`:  Methods for accessing and modifying frame properties.
    * `TransformableVideoFrameInterface`:  An interface likely from WebRTC for handling video frames.
    * `Create`, `CloneWebRtcFrame`, `PassWebRtcFrame`:  Lifecycle and manipulation methods.
    * `toString`:  A debugging/logging method.
    * `SyncDelegate`:  Indicates a synchronization mechanism with an underlying delegate object.
    * `base::UnguessableToken`: Used for unique identification.
    * `BASE_FEATURE`:  Feature flags for enabling/disabling functionality.

3. **Identifying Core Functionality:** Based on the keywords and class names, the primary function is clearly managing encoded video frames within the WebRTC context in the browser. This involves:
    * Representing an encoded video frame.
    * Holding the encoded data (`DOMArrayBuffer`).
    * Storing metadata about the frame (resolution, timestamps, dependencies, etc.).
    * Interfacing with the underlying WebRTC video frame representation.
    * Providing mechanisms to create, clone, and modify these frames.
    * Supporting the transfer of these frames between different parts of the system.

4. **Analyzing Key Methods:**  Deeper analysis of the methods reveals more details:
    * `Create`:  Constructors for creating new `RTCEncodedVideoFrame` instances, often by cloning existing ones or potentially from underlying WebRTC frames.
    * `getMetadata`:  Retrieves metadata from the underlying WebRTC frame and populates the `RTCEncodedVideoFrameMetadata` object.
    * `SetMetadata`:  Updates the metadata of the frame, including validation to prevent invalid modifications. The presence of the `kAllowRTCEncodedVideoFrameSetMetadataAllFields` feature flag is important.
    * `setData`:  Sets the encoded video data.
    * `PassWebRtcFrame`:  Transfers ownership of the underlying WebRTC frame, potentially detaching the `ArrayBuffer`. This is critical for understanding how the data moves in the WebRTC pipeline.

5. **Connecting to Web Technologies (JavaScript, HTML, CSS):** This is where the "glue" between the C++ code and the web platform comes in.
    * **JavaScript:** The primary connection is through the WebRTC API exposed to JavaScript. The `RTCEncodedVideoFrame` in C++ likely corresponds to an object accessible in JavaScript. Methods like `getMetadata()` and `setMetadata()` have direct counterparts in the JavaScript API. The `data` property corresponds to a JavaScript `ArrayBuffer`. The `type` property maps to a JavaScript enum.
    * **HTML:**  HTML provides the `<video>` element, which is the destination for decoded video streams. While this C++ code doesn't directly manipulate HTML, it's a crucial part of the pipeline that feeds data to the `<video>` element.
    * **CSS:** CSS styles the `<video>` element. Again, this C++ code is not directly involved in styling, but it's part of the system that renders video that CSS can style.

6. **Logical Reasoning and Examples:** This requires thinking about how the methods would be used and the data flow.
    * **Assumption:** A JavaScript application receives an encoded video frame from a remote peer.
    * **Input:** The raw encoded video data, metadata (like timestamp, frame ID).
    * **Output:**  A populated `RTCEncodedVideoFrame` object in C++, ready for further processing or transmission.
    * **Another Example (Metadata Update):**
        * **Input:** An existing `RTCEncodedVideoFrame` and a new `RTCEncodedVideoFrameMetadata` object with updated information.
        * **Output:** The `RTCEncodedVideoFrame`'s internal metadata is updated, potentially after validation.

7. **Common Usage Errors:**  This requires thinking about how developers might misuse the API.
    * Trying to create a frame from an empty frame.
    * Incorrectly modifying metadata (especially when the feature flag is disabled).
    * Detaching the `ArrayBuffer` and then trying to access its data in JavaScript.

8. **Tracing User Actions:** This involves mapping user interactions to the underlying code execution.
    * **Scenario:** A user makes a video call using a web application.
    * The browser uses the WebRTC API.
    * When an encoded video frame is received, the browser's networking layer passes it to the WebRTC implementation.
    *  The `RTCEncodedVideoFrame` class in Blink is used to represent this frame.
    *  JavaScript code might access the frame's `data` or `metadata`.
    *  Eventually, the frame might be decoded and displayed in the `<video>` element.

9. **Structuring the Explanation:**  Organize the information logically using headings and bullet points for clarity. Start with a high-level overview and then delve into more specific details. Provide concrete examples.

10. **Refinement and Review:** After drafting the explanation, review it for accuracy, completeness, and clarity. Ensure that the connections between the C++ code and web technologies are well-explained. Check for any technical jargon that needs clarification. For example, initially, I might have just said "deals with WebRTC frames," but then refined it to mention "representing, manipulating, and managing encoded video frames within the WebRTC context."  Similarly, making the connection to `DOMArrayBuffer` and its JavaScript counterpart is crucial.
这个C++源代码文件 `rtc_encoded_video_frame.cc` 属于 Chromium Blink 引擎的 PeerConnection 模块，它的主要功能是**表示和操作经过编码的视频帧 (Encoded Video Frames)**。这些帧通常是在 WebRTC 通信过程中，通过网络发送或接收的压缩后的视频数据。

下面是它的具体功能和与前端技术的关系：

**1. 表示编码的视频帧:**

*   `RTCEncodedVideoFrame` 类是核心，它封装了一个经过编码的视频帧的数据和元数据。
*   它持有一个指向 `webrtc::TransformableVideoFrameInterface` 的指针，这是 WebRTC 库中用于表示可转换视频帧的接口。Blink 的 `RTCEncodedVideoFrame` 相当于对 WebRTC 视频帧的一个包装。
*   它存储了帧的原始编码数据（通过 `DOMArrayBuffer`）。
*   它维护了与帧相关的元数据，例如时间戳、帧类型（关键帧/Delta 帧）、宽度、高度、空间索引、时间索引、RTP 相关信息（SSRC, CSRC, RTP 时间戳, Payload Type）以及帧依赖关系 (Frame Dependencies)。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:** 这个类直接对应 WebRTC API 中的 `RTCEncodedVideoFrame` 接口，该接口在 JavaScript 中可被访问和操作。
    *   **例 1 (创建):**  在 JavaScript 中，通过 `RTCRtpReceiver.onencodedvideoframe` 事件接收到的编码帧，其实例化后在 Blink 内部就是 `RTCEncodedVideoFrame` 对象。
    ```javascript
    receiver.onencodedvideoframe = (event) => {
      const frame = event.frame; // frame 是一个 RTCEncodedVideoFrame 对象
      console.log(frame.type); // 访问帧的类型 (对应 C++ 中的 RTCEncodedVideoFrame::type())
      console.log(frame.timestamp); // 访问帧的时间戳 (对应 C++ 中的 RTCEncodedVideoFrame::timestamp())
      frame.getMetadata().then(metadata => {
        console.log(metadata.width); // 访问帧的宽度 (对应 C++ 中的 RTCEncodedVideoFrame::getMetadata())
      });
      // ... 可以进一步处理帧数据 frame.data
    };
    ```
*   **HTML:**  `RTCEncodedVideoFrame` 最终的数据会被解码并在 HTML `<video>` 元素中渲染。虽然这个类本身不直接操作 HTML，但它是实现视频播放流程的关键一环。
*   **CSS:** CSS 用于控制 HTML 元素的样式，包括 `<video>` 元素。`RTCEncodedVideoFrame` 不直接与 CSS 交互，但它提供的视频数据是 CSS 可以作用的对象。

**2. 提供访问帧数据和元数据的方法:**

*   `type()`: 返回帧的类型 (例如，关键帧或 Delta 帧)，对应 `V8RTCEncodedVideoFrameType` 枚举。
*   `timestamp()`: 返回帧的 RTP 时间戳。
*   `data()`: 返回包含帧编码数据的 `DOMArrayBuffer` 对象。这个 `ArrayBuffer` 可以被 JavaScript 代码访问。
*   `getMetadata()`: 返回一个 `RTCEncodedVideoFrameMetadata` 对象，其中包含了帧的各种元数据信息。
*   `setMetadata()`: 允许修改帧的元数据。

**与 JavaScript 的关系 (继续):**

*   **例 2 (访问数据):** JavaScript 可以通过 `frame.data` 访问到编码后的视频数据，并进行处理，例如通过 `TransformStream` API 进行进一步的媒体处理。
    ```javascript
    receiver.onencodedvideoframe = (event) => {
      const frame = event.frame;
      const encodedData = frame.data; // encodedData 是一个 ArrayBuffer
      // ... 对 encodedData 进行处理
    };
    ```

**3. 管理帧的生命周期和所有权:**

*   `Create()`: 提供了创建 `RTCEncodedVideoFrame` 对象的方法，可以基于现有的帧进行克隆，也可以根据 `RTCEncodedVideoFrameOptions` 设置元数据。
*   `PassWebRtcFrame()`:  将内部的 `webrtc::TransformableVideoFrameInterface` 对象的所有权转移出去，这在将帧传递给其他处理流程（例如编码器或解码器）时非常重要。

**4. 支持元数据的修改和验证:**

*   `SetMetadata()`:  允许修改帧的元数据，但会对修改进行验证，确保某些关键属性不会被随意更改，除非启用了特定的 Feature Flag (`kAllowRTCEncodedVideoFrameSetMetadataAllFields`)。
*   `ValidateMetadata()`: 内部函数，用于验证新的元数据是否有效。

**逻辑推理和假设输入/输出:**

**假设输入:**  一个接收到的 H.264 编码的视频帧数据包，以及相关的 RTP 头信息。

**处理流程 (简化):**

1. 网络层接收到数据包。
2. WebRTC 模块解析 RTP 头信息，提取时间戳、SSRC 等。
3. 根据数据包负载创建 `webrtc::TransformableVideoFrameInterface` 对象。
4. Blink 创建 `RTCEncodedVideoFrame` 对象，并将 `webrtc::TransformableVideoFrameInterface` 对象封装进去。
5. `RTCEncodedVideoFrame` 的 `data()` 方法会创建一个 `DOMArrayBuffer` 来存储编码后的视频数据。
6. `RTCEncodedVideoFrame` 的 `getMetadata()` 方法会根据 RTP 头信息和可能的帧头信息填充 `RTCEncodedVideoFrameMetadata` 对象，包括时间戳、帧类型等。

**假设输出 (JavaScript 可见):**

```javascript
receiver.onencodedvideoframe = (event) => {
  const frame = event.frame;
  console.log(frame.type); // 输出 "key" (如果是关键帧) 或 "delta"
  console.log(frame.timestamp); // 输出 RTP 时间戳 (例如: 12345)
  frame.getMetadata().then(metadata => {
    console.log(metadata.width); // 输出视频宽度 (例如: 640)
    console.log(metadata.height); // 输出视频高度 (例如: 480)
    console.log(metadata.synchronizationSource); // 输出 SSRC 值
    // ... 其他元数据
  });
  console.log(frame.data.byteLength); // 输出编码后视频数据的字节长度
};
```

**用户或编程常见的使用错误:**

1. **尝试修改不允许修改的元数据字段:** 在 `kAllowRTCEncodedVideoFrameSetMetadataAllFields` Feature Flag 未启用时，尝试修改宽度、高度、空间/时间索引等关键元数据，会导致异常。
    *   **例子:**
        ```javascript
        receiver.onencodedvideoframe = (event) => {
          const frame = event.frame;
          frame.getMetadata().then(metadata => {
            metadata.width = 1280; // 假设原始宽度是 640
            frame.setMetadata(metadata); // 这会抛出 DOMException，因为不允许修改宽度
          });
        };
        ```
    *   **错误信息 (C++ 中生成):** `"invalid modification of RTCEncodedVideoFrameMetadata."`

2. **在 `ArrayBuffer` 被分离后尝试访问数据:**  当 `RTCEncodedVideoFrame` 通过 `PassWebRtcFrame()` 被传递出去时，其内部的 `DOMArrayBuffer` 可能会被分离 (detached)，此时在 JavaScript 中再次访问 `frame.data` 会导致错误。
    *   **例子:**  假设有一个视频处理管道，将编码帧传递给一个 Worker 进行处理。
        ```javascript
        receiver.onencodedvideoframe = async (event) => {
          const frame = event.frame;
          const transferableFrame = frame.pass(); // 假设 pass() 内部调用了 PassWebRtcFrame
          worker.postMessage({ frame: transferableFrame }, [transferableFrame.data.buffer]);

          // 稍后尝试访问 frame.data
          console.log(frame.data.byteLength); // 可能会抛出错误，因为 frame.data 的 ArrayBuffer 已经被分离
        };
        ```

3. **创建 `RTCEncodedVideoFrame` 时传入空帧:**  `RTCEncodedVideoFrame::Create` 方法会检查传入的原始帧是否为空，如果为空则会抛出异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起 WebRTC 通信:** 用户在一个网页上点击按钮，开始视频通话或屏幕共享。
2. **浏览器获取本地视频流:**  用户的摄像头或屏幕内容被捕获，生成本地视频流。
3. **编码器对视频帧进行编码:** 本地视频流的每一帧都会经过视频编码器（例如 H.264, VP8, VP9）进行压缩。
4. **编码后的帧被封装:** 编码后的数据和相关的元数据会被封装成适合网络传输的格式，通常是 RTP 包。
5. **RTP 包被发送到远端:** 封装好的 RTP 包通过网络发送到通话的另一端。
6. **远端浏览器接收 RTP 包:** 远端浏览器的网络层接收到这些 RTP 包。
7. **WebRTC 模块解析 RTP 包:** 远端浏览器的 WebRTC 模块解析接收到的 RTP 包，提取编码后的视频数据和元数据。
8. **创建 `RTCEncodedVideoFrame` 对象:**  在 Blink 引擎中，会创建 `RTCEncodedVideoFrame` 对象来表示接收到的编码视频帧。这个 `rtc_encoded_video_frame.cc` 文件中的代码就会被执行，用于创建和初始化这个对象。
9. **JavaScript 事件触发:**  `RTCRtpReceiver.onencodedvideoframe` 事件被触发，将 `RTCEncodedVideoFrame` 对象传递给 JavaScript 代码。
10. **开发者调试:**  开发者可能会在 `onencodedvideoframe` 事件处理函数中打断点，查看 `event.frame` 对象的属性和方法，从而进入到 `rtc_encoded_video_frame.cc` 相关的代码执行路径。

**总结:**

`rtc_encoded_video_frame.cc` 文件是 Blink 引擎中处理 WebRTC 编码视频帧的核心组件。它负责表示、存储、访问和操作编码后的视频数据及其元数据，并且直接关联到 WebRTC 的 JavaScript API，使得开发者可以在 JavaScript 中对接收到的或待发送的编码视频帧进行操作和处理。理解这个文件的功能对于深入理解 WebRTC 的媒体处理流程至关重要。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_encoded_video_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame.h"

#include <utility>

#include "base/unguessable_token.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_codec_specifics_vp_8.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_decode_target_indication.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_video_frame_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_video_frame_options.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame_delegate.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/webrtc/api/frame_transformer_interface.h"

namespace blink {

// Allow all fields to be set when calling RTCEncodedVideoFrame.setMetadata.
BASE_FEATURE(kAllowRTCEncodedVideoFrameSetMetadataAllFields,
             "AllowRTCEncodedVideoFrameSetMetadataAllFields",
             base::FEATURE_DISABLED_BY_DEFAULT);

namespace {
static constexpr size_t kMaxNumDependencies = 8;

bool IsAllowedSetMetadataChange(
    const RTCEncodedVideoFrameMetadata* original_metadata,
    const RTCEncodedVideoFrameMetadata* metadata) {
  if (metadata->width() != original_metadata->width() ||
      metadata->height() != original_metadata->height() ||
      metadata->spatialIndex() != original_metadata->spatialIndex() ||
      metadata->temporalIndex() != original_metadata->temporalIndex()) {
    return false;
  }

  // It is possible to not have the RTP metadata values set. This condition
  // checks if the value exists and if it does, it should be the same.
  if ((metadata->hasSynchronizationSource() !=
           original_metadata->hasSynchronizationSource() ||
       (metadata->hasSynchronizationSource()
            ? metadata->synchronizationSource() !=
                  original_metadata->synchronizationSource()
            : false)) ||
      (metadata->hasContributingSources() !=
           original_metadata->hasContributingSources() ||
       (metadata->hasContributingSources()
            ? metadata->contributingSources() !=
                  original_metadata->contributingSources()
            : false))) {
    return false;
  }
  return true;
}

base::expected<void, String> ValidateMetadata(
    const RTCEncodedVideoFrameMetadata* metadata) {
  if (!metadata->hasWidth() || !metadata->hasHeight() ||
      !metadata->hasSpatialIndex() || !metadata->hasTemporalIndex() ||
      !metadata->hasRtpTimestamp()) {
    return base::unexpected("new metadata has member(s) missing.");
  }

  // This might happen if the dependency descriptor is not set.
  if (!metadata->hasFrameId() && metadata->hasDependencies()) {
    return base::unexpected(
        "new metadata has frameID missing, but has dependencies");
  }
  if (!metadata->hasDependencies()) {
    return base::ok();
  }

  // Ensure there are at most 8 deps. Enforced in WebRTC's
  // RtpGenericFrameDescriptor::AddFrameDependencyDiff().
  if (metadata->dependencies().size() > kMaxNumDependencies) {
    return base::unexpected("new metadata has too many dependencies.");
  }
  // Require deps to all be before frame_id, but within 2^14 of it. Enforced in
  // WebRTC by a DCHECK in RtpGenericFrameDescriptor::AddFrameDependencyDiff().
  for (const int64_t dep : metadata->dependencies()) {
    if ((dep >= metadata->frameId()) ||
        ((metadata->frameId() - dep) >= (1 << 14))) {
      return base::unexpected("new metadata has invalid frame dependencies.");
    }
  }

  return base::ok();
}

}  // namespace

RTCEncodedVideoFrame* RTCEncodedVideoFrame::Create(
    RTCEncodedVideoFrame* original_frame,
    ExceptionState& exception_state) {
  return RTCEncodedVideoFrame::Create(original_frame, nullptr, exception_state);
}

RTCEncodedVideoFrame* RTCEncodedVideoFrame::Create(
    RTCEncodedVideoFrame* original_frame,
    const RTCEncodedVideoFrameOptions* options_dict,
    ExceptionState& exception_state) {
  RTCEncodedVideoFrame* new_frame;
  if (original_frame) {
    new_frame = MakeGarbageCollected<RTCEncodedVideoFrame>(
        original_frame->Delegate()->CloneWebRtcFrame());
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "Cannot create a new VideoFrame from an empty VideoFrame");
    return nullptr;
  }
  if (options_dict && options_dict->hasMetadata()) {
    base::expected<void, String> set_metadata =
        new_frame->SetMetadata(options_dict->metadata());
    if (!set_metadata.has_value()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidModificationError,
          "Cannot create a new VideoFrame: " + set_metadata.error());
      return nullptr;
    }
  }
  return new_frame;
}

RTCEncodedVideoFrame::RTCEncodedVideoFrame(
    std::unique_ptr<webrtc::TransformableVideoFrameInterface> webrtc_frame)
    : RTCEncodedVideoFrame(std::move(webrtc_frame),
                           base::UnguessableToken::Null(),
                           0) {}

RTCEncodedVideoFrame::RTCEncodedVideoFrame(
    std::unique_ptr<webrtc::TransformableVideoFrameInterface> webrtc_frame,
    base::UnguessableToken owner_id,
    int64_t counter)
    : delegate_(base::MakeRefCounted<RTCEncodedVideoFrameDelegate>(
          std::move(webrtc_frame))),
      owner_id_(owner_id),
      counter_(counter) {}

RTCEncodedVideoFrame::RTCEncodedVideoFrame(
    scoped_refptr<RTCEncodedVideoFrameDelegate> delegate)
    : RTCEncodedVideoFrame(delegate->CloneWebRtcFrame()) {}

V8RTCEncodedVideoFrameType RTCEncodedVideoFrame::type() const {
  return V8RTCEncodedVideoFrameType(delegate_->Type());
}

uint32_t RTCEncodedVideoFrame::timestamp() const {
  return delegate_->RtpTimestamp();
}

DOMArrayBuffer* RTCEncodedVideoFrame::data(ExecutionContext* context) const {
  if (!frame_data_) {
    frame_data_ = delegate_->CreateDataBuffer(context->GetIsolate());
  }
  return frame_data_.Get();
}

RTCEncodedVideoFrameMetadata* RTCEncodedVideoFrame::getMetadata() const {
  RTCEncodedVideoFrameMetadata* metadata =
      RTCEncodedVideoFrameMetadata::Create();
  if (delegate_->PayloadType()) {
    metadata->setPayloadType(*delegate_->PayloadType());
  }
  if (delegate_->MimeType()) {
    metadata->setMimeType(WTF::String::FromUTF8(*delegate_->MimeType()));
  }

  if (RuntimeEnabledFeatures::RTCEncodedVideoFrameAdditionalMetadataEnabled()) {
    if (delegate_->PresentationTimestamp()) {
      metadata->setTimestamp(delegate_->PresentationTimestamp()->us());
    }
  }

  const std::optional<webrtc::VideoFrameMetadata> webrtc_metadata =
      delegate_->GetMetadata();
  if (!webrtc_metadata) {
    return metadata;
  }

  metadata->setSynchronizationSource(webrtc_metadata->GetSsrc());
  Vector<uint32_t> csrcs;
  for (uint32_t csrc : webrtc_metadata->GetCsrcs()) {
    csrcs.push_back(csrc);
  }
  metadata->setContributingSources(csrcs);

  if (webrtc_metadata->GetFrameId()) {
    metadata->setFrameId(*webrtc_metadata->GetFrameId());
  }

  Vector<int64_t> dependencies;
  for (const auto& dependency : webrtc_metadata->GetFrameDependencies()) {
    dependencies.push_back(dependency);
  }
  metadata->setDependencies(dependencies);
  metadata->setWidth(webrtc_metadata->GetWidth());
  metadata->setHeight(webrtc_metadata->GetHeight());
  metadata->setSpatialIndex(webrtc_metadata->GetSpatialIndex());
  metadata->setTemporalIndex(webrtc_metadata->GetTemporalIndex());
  metadata->setRtpTimestamp(delegate_->RtpTimestamp());

  return metadata;
}

base::UnguessableToken RTCEncodedVideoFrame::OwnerId() {
  return owner_id_;
}
int64_t RTCEncodedVideoFrame::Counter() {
  return counter_;
}

base::expected<void, String> RTCEncodedVideoFrame::SetMetadata(
    const RTCEncodedVideoFrameMetadata* metadata) {
  const std::optional<webrtc::VideoFrameMetadata> original_webrtc_metadata =
      delegate_->GetMetadata();
  if (!original_webrtc_metadata) {
    return base::unexpected("underlying webrtc frame is an empty frame.");
  }

  base::expected<void, String> validate_metadata = ValidateMetadata(metadata);
  if (!validate_metadata.has_value()) {
    return validate_metadata;
  }

  RTCEncodedVideoFrameMetadata* original_metadata = getMetadata();
  if (!original_metadata) {
    return base::unexpected("internal error when calling getMetadata().");
  }
  if (!IsAllowedSetMetadataChange(original_metadata, metadata) &&
      !base::FeatureList::IsEnabled(
          kAllowRTCEncodedVideoFrameSetMetadataAllFields)) {
    return base::unexpected(
        "invalid modification of RTCEncodedVideoFrameMetadata.");
  }

  if ((metadata->hasPayloadType() != original_metadata->hasPayloadType()) ||
      (metadata->hasPayloadType() &&
       metadata->payloadType() != original_metadata->payloadType())) {
    return base::unexpected(
        "invalid modification of payloadType in RTCEncodedVideoFrameMetadata.");
  }

  // Initialize the new metadata from original_metadata to account for fields
  // not part of RTCEncodedVideoFrameMetadata.
  webrtc::VideoFrameMetadata webrtc_metadata = *original_webrtc_metadata;
  if (metadata->hasFrameId()) {
    webrtc_metadata.SetFrameId(metadata->frameId());
  }
  if (metadata->hasDependencies()) {
    webrtc_metadata.SetFrameDependencies(metadata->dependencies());
  }
  webrtc_metadata.SetWidth(metadata->width());
  webrtc_metadata.SetHeight(metadata->height());
  webrtc_metadata.SetSpatialIndex(metadata->spatialIndex());
  webrtc_metadata.SetTemporalIndex(metadata->temporalIndex());
  webrtc_metadata.SetSsrc(metadata->synchronizationSource());

  if (metadata->hasContributingSources()) {
    std::vector<uint32_t> csrcs;
    for (uint32_t csrc : metadata->contributingSources()) {
      csrcs.push_back(csrc);
    }
    webrtc_metadata.SetCsrcs(csrcs);
  }

  return delegate_->SetMetadata(webrtc_metadata, metadata->rtpTimestamp());
}

void RTCEncodedVideoFrame::setMetadata(RTCEncodedVideoFrameMetadata* metadata,
                                       ExceptionState& exception_state) {
  base::expected<void, String> set_metadata = SetMetadata(metadata);
  if (!set_metadata.has_value()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError,
        "Cannot setMetadata: " + set_metadata.error());
  }
}

void RTCEncodedVideoFrame::setData(ExecutionContext*, DOMArrayBuffer* data) {
  frame_data_ = data;
}

String RTCEncodedVideoFrame::toString(ExecutionContext* context) const {
  if (!delegate_) {
    return "empty";
  }

  StringBuilder sb;
  sb.Append("RTCEncodedVideoFrame{rtpTimestamp: ");
  sb.AppendNumber(timestamp());
  sb.Append(", size: ");
  sb.AppendNumber(data(context)->ByteLength());
  sb.Append(" bytes, type: ");
  sb.Append(type().AsCStr());
  sb.Append("}");
  return sb.ToString();
}

void RTCEncodedVideoFrame::SyncDelegate() const {
  delegate_->SetData(frame_data_);
}

scoped_refptr<RTCEncodedVideoFrameDelegate> RTCEncodedVideoFrame::Delegate()
    const {
  SyncDelegate();
  return delegate_;
}

std::unique_ptr<webrtc::TransformableVideoFrameInterface>
RTCEncodedVideoFrame::PassWebRtcFrame(v8::Isolate* isolate,
                                      bool detach_frame_data) {
  SyncDelegate();
  auto transformable_video_frame = delegate_->PassWebRtcFrame();
  // Detach the `frame_data_` ArrayBuffer if it's been created, as described in
  // the transfer on step 5 of the encoded transform spec write steps
  // (https://www.w3.org/TR/webrtc-encoded-transform/#stream-processing)
  if (detach_frame_data && frame_data_ && !frame_data_->IsDetached()) {
    CHECK(isolate);
    ArrayBufferContents contents_to_drop;
    NonThrowableExceptionState exception_state;
    CHECK(frame_data_->Transfer(isolate, v8::Local<v8::Value>(),
                                contents_to_drop, exception_state));
  }
  return transformable_video_frame;
}

void RTCEncodedVideoFrame::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  visitor->Trace(frame_data_);
}

}  // namespace blink
```
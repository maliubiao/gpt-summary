Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `html_media_element_capture.cc` file within the Blink rendering engine. It also wants connections to JavaScript/HTML/CSS, logical reasoning examples, common usage errors, and debugging steps.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the file for important keywords like `captureStream`, `MediaStream`, `HTMLMediaElement`, `VideoCapturerSource`, `AudioCapturerSource`, `addEventListener`, and event names (`loadedmetadata`, `ended`). Notice the inclusion of headers related to media streams, HTML elements, and platform functionalities. The namespace `blink` and the copyright notice confirm this is Blink code.

3. **Identify the Core Functionality:** The function `captureStream` is a strong indicator of the file's main purpose. It takes an `HTMLMediaElement` as input and returns a `MediaStream`. This immediately suggests that the code is responsible for creating a media stream from an existing HTML `<video>` or `<audio>` element.

4. **Analyze `captureStream`:**
    * **Error Handling:** Notice the checks for EME (Encrypted Media Extensions) and cross-origin data. This reveals security considerations and limitations.
    * **MediaStream Creation:**  The code creates a `MediaStreamDescriptor` and then a `MediaStream`. This confirms the fundamental action of creating a stream.
    * **Event Listeners:** The code adds event listeners (`loadedmetadata`, `ended`) to the `HTMLMediaElement`. This is a crucial part of how the capture mechanism works: it reacts to changes in the media element's state.
    * **Handling MediaStream Sources:**  The code checks if the element's source is already a `MediaStream`. If so, it clones it. This is an optimization or a specific handling case.
    * **Creating Capturers:**  The calls to `CreateHTMLVideoElementCapturer` and `CreateHTMLAudioElementCapturer` based on whether the element has video or audio are key. These functions are responsible for the actual capture logic.

5. **Delve into Helper Functions:**  Now, examine the helper functions called within `captureStream`:
    * **`CreateHTMLVideoElementCapturer` and `CreateHTMLAudioElementCapturer`:** These functions take the `HTMLMediaElement` and create `VideoCapturerSource` and `AudioCapturerSource` respectively. This signifies the actual mechanism of getting data from the media element. They also involve `WebMediaPlayer`, which is the underlying media playback engine in Chromium.
    * **`AddVideoTrackToMediaStream`:** This function takes the `VideoCapturerSource` and adds a video track to the `MediaStreamDescriptor`. It creates the necessary `MediaStreamVideoSource` and `MediaStreamVideoTrack` objects.
    * **`MediaElementEventListener`:** This class is crucial for handling events on the `HTMLMediaElement`. Its `Invoke` method handles `loadedmetadata` and `ended` events. The `UpdateSources` method appears to manage muting/stopping sources in cross-origin scenarios.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `captureStream()` method would be exposed to JavaScript, allowing developers to call it on an HTML media element. The returned `MediaStream` object can then be used with other Web APIs like `MediaRecorder` or set as the source for another media element.
    * **HTML:**  The input is an `HTMLMediaElement` (`<video>` or `<audio>`). The functionality directly relates to these HTML tags.
    * **CSS:** While this C++ code doesn't directly interact with CSS, CSS styling of the `<video>` or `<audio>` element will affect the *visual representation* of the element being captured. The captured stream will reflect the current visual content (though it's primarily about the media data, not the styling).

7. **Logical Reasoning and Examples:**
    * **Assumption:** A user has a `<video>` element playing a local video file.
    * **Input:**  JavaScript calls `videoElement.captureStream()`.
    * **Output:** A `MediaStream` object is returned, containing a video track that streams the content of the `<video>` element.

8. **Common Usage Errors:**
    * **Cross-Origin:** Trying to capture a video from a different domain without proper CORS headers will result in a security error.
    * **EME:** Attempting to capture a video that's protected by Digital Rights Management (DRM) through EME will fail.
    * **Context Invalidity:** Calling `captureStream` after the document or window has been closed or unloaded will lead to errors.

9. **Debugging Steps:** Think about the user's journey and the code's execution flow:
    * **User Action:** The user interacts with the webpage, triggering a JavaScript call to `captureStream()` on a `<video>` or `<audio>` element.
    * **JavaScript Execution:** The JavaScript engine calls the native C++ implementation of `captureStream`.
    * **Blink Processing:** The C++ code in this file executes:
        * Checks for errors (EME, cross-origin).
        * Creates a `MediaStream`.
        * Attaches event listeners.
        * If the element is already a `MediaStream`, it clones it.
        * Otherwise, it creates capturer objects based on the media type.
        * The event listeners (especially `loadedmetadata`) trigger the actual capture process.
    * **Debugging Points:**  Setting breakpoints in `captureStream`, `CreateHTMLVideoElementCapturer`, `CreateHTMLAudioElementCapturer`, and the `MediaElementEventListener::Invoke` method would be useful. Inspecting the `MediaStream` object and its tracks in the debugger would also be helpful.

10. **Refine and Organize:** Finally, organize the information into clear sections as requested by the prompt: functionality, relationship to web technologies, logical reasoning, common errors, and debugging. Ensure the language is clear and provides specific examples. Review the code comments for additional insights. For example, the comment about `ended` event handling and `MediaRecorder` is a good point to include.

This systematic approach, starting with high-level understanding and gradually diving into the details, is effective for analyzing and explaining complex code like this.
好的，让我们来分析一下 `blink/renderer/modules/mediacapturefromelement/html_media_element_capture.cc` 这个文件。

**功能概述**

这个 C++ 源代码文件实现了将 HTML `<video>` 或 `<audio>` 元素的内容捕获为 `MediaStream` 的功能。换句话说，它允许网页通过 JavaScript API（具体来说是 `captureStream()` 方法）获取一个可以被当作摄像头或麦克风输入的媒体流，这个流的内容就是 HTML 媒体元素当前正在播放的内容。

**与 JavaScript, HTML, CSS 的关系及举例**

这个文件直接关联了 JavaScript 和 HTML，但与 CSS 的关系较间接。

* **JavaScript:**
    * **API 暴露:**  该文件实现了 `HTMLMediaElementCapture::captureStream` 这个静态方法，这个方法在 Blink 中会被绑定到 JavaScript 的 `HTMLMediaElement.prototype.captureStream()` API 上。这意味着 JavaScript 代码可以直接调用 HTML 媒体元素上的 `captureStream()` 方法来触发这里的功能。
    * **事件处理:**  代码中创建了 `MediaElementEventListener` 类来监听 HTML 媒体元素的 `loadedmetadata` 和 `ended` 事件。这些事件是在 JavaScript 中定义的，并且可以通过 JavaScript 代码触发。
    * **MediaStream 对象:**  该文件创建并返回 `MediaStream` 对象，这是一个 JavaScript API，用于表示媒体数据的流。JavaScript 代码可以获取这个 `MediaStream` 对象，并将其用于其他 Web API，例如 `MediaRecorder` (用于录制媒体流) 或将其设置为另一个 `<video>` 元素的 `srcObject`。

    **举例:**

    ```javascript
    const videoElement = document.getElementById('myVideo');
    const mediaStream = videoElement.captureStream();

    // 将捕获到的流设置为另一个 video 元素的源
    const anotherVideoElement = document.getElementById('anotherVideo');
    anotherVideoElement.srcObject = mediaStream;
    anotherVideoElement.play();

    // 使用 MediaRecorder 录制捕获到的流
    const mediaRecorder = new MediaRecorder(mediaStream);
    mediaRecorder.start();

    // ... 停止录制等
    ```

* **HTML:**
    * **目标元素:**  该功能的核心是操作 `HTMLMediaElement`，这对应于 HTML 中的 `<video>` 和 `<audio>` 标签。`captureStream()` 方法必须在这些 HTML 元素上调用。
    * **媒体内容:** 被捕获的 `MediaStream` 的内容来源于 HTML 媒体元素正在播放的媒体资源。

    **举例:**

    ```html
    <video id="myVideo" src="my-video.mp4" controls></video>
    <video id="anotherVideo" controls></video>

    <script>
      // ... 上面的 JavaScript 代码 ...
    </script>
    ```

* **CSS:**
    * **间接影响:** CSS 可以控制 `<video>` 或 `<audio>` 元素的外观和布局。虽然 CSS 不会直接影响 `captureStream()` 捕获到的媒体数据本身（例如，CSS 滤镜不会直接应用到捕获的流），但 CSS 影响的元素尺寸和可见性可能会间接影响某些浏览器的捕获行为（例如，某些浏览器可能只捕获可见区域）。

**逻辑推理及假设输入与输出**

假设我们有一个正在播放视频的 `<video>` 元素：

**假设输入:**

1. 一个 HTML 文档包含一个 `<video>` 元素，其 `id` 为 `myVideo`，并且 `src` 属性指向一个有效的视频文件。
2. JavaScript 代码获取了这个 `video` 元素：`const videoElement = document.getElementById('myVideo');`
3. JavaScript 代码调用了 `captureStream()` 方法：`const mediaStream = videoElement.captureStream();`

**逻辑推理过程 (基于代码分析):**

1. `captureStream()` 方法被调用。
2. 代码首先检查是否存在 EME (加密媒体扩展)，如果存在则抛出异常，因为不支持捕获受 DRM 保护的内容。
3. 代码检查是否为跨域资源，如果是，则抛出安全错误。
4. 创建一个新的 `MediaStreamDescriptor` 对象。
5. 创建一个新的 `MediaStream` 对象，基于上面的描述符。
6. 创建一个 `MediaElementEventListener` 对象来监听 `videoElement` 的 `loadedmetadata` 和 `ended` 事件。
7. 如果 `videoElement` 当前正在播放一个 `MediaStream` (即它的 `srcObject` 是一个 `MediaStream`)，则直接克隆该 `MediaStream` 并返回。
8. 否则，根据 `videoElement` 是否有视频和音频轨道，分别调用 `CreateHTMLVideoElementCapturer` 和 `CreateHTMLAudioElementCapturer` 来创建相应的捕获源。
9. `CreateHTMLVideoElementCapturer` (或 `CreateHTMLAudioElementCapturer`) 会创建一个 `HtmlVideoElementCapturerSource` (或 `HtmlAudioElementCapturerSource`)，它负责从底层的 `WebMediaPlayer` 获取视频帧（或音频数据）。
10. 新的视频或音频轨道会被添加到 `MediaStreamDescriptor` 中。
11. `MediaElementEventListener` 的 `UpdateSources` 方法可能会根据跨域情况停止某些媒体源。
12. 最终，创建的 `MediaStream` 对象被返回。

**假设输出:**

返回一个 `MediaStream` 对象，该对象包含一个视频轨道（如果 `<video>` 元素有视频），这个视频轨道的数据来源于 `myVideo` 元素当前正在播放的视频内容。JavaScript 代码可以将这个 `MediaStream` 对象用于其他媒体相关的 API。

**用户或编程常见的使用错误**

1. **尝试捕获跨域媒体:**  如果 `<video>` 或 `<audio>` 元素的 `src` 指向的资源位于不同的域，并且没有设置正确的 CORS 头信息，调用 `captureStream()` 将会抛出一个安全错误。

    **举例:**

    ```html
    <video id="myVideo" src="https://another-domain.com/video.mp4"></video>
    <script>
      const videoElement = document.getElementById('myVideo');
      try {
        const stream = videoElement.captureStream(); // 可能抛出 SecurityError
      } catch (e) {
        console.error(e);
      }
    </script>
    ```

2. **尝试捕获加密媒体 (EME):**  如果 `<video>` 元素的内容受到 DRM 保护并且使用了加密媒体扩展 (EME)，调用 `captureStream()` 将会抛出一个 `NotSupportedError`。

    **举例:**  （假设 `myVideo` 元素正在播放需要解密的视频）

    ```javascript
    const videoElement = document.getElementById('myVideo');
    try {
      const stream = videoElement.captureStream(); // 抛出 NotSupportedError
    } catch (e) {
      console.error(e);
    }
    ```

3. **在元素没有加载元数据之前调用 `captureStream()`:**  虽然代码中添加了 `loadedmetadata` 事件监听器，但如果在元素开始播放或加载元数据之前就调用 `captureStream()`，可能导致捕获到的流不包含任何轨道，或者在后续的 `loadedmetadata` 事件触发后才添加轨道。最佳实践是在确保媒体元素已准备好播放后再调用。

4. **忘记处理 `ended` 事件:**  `MediaElementEventListener` 会监听 `ended` 事件并停止 `MediaStream` 中的所有轨道。如果 JavaScript 代码没有妥善处理 `MediaStream` 的 `ended` 事件，可能会导致一些预期之外的行为。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户在浏览器中加载包含 `<video>` 或 `<audio>` 元素的网页。**
2. **网页的 JavaScript 代码获取到这个 HTML 媒体元素 (例如通过 `document.getElementById`)。**
3. **在某个时机 (例如，用户点击按钮，或者媒体元素开始播放后)，JavaScript 代码调用了该媒体元素的 `captureStream()` 方法。**  这是进入 `html_media_element_capture.cc` 中 `HTMLMediaElementCapture::captureStream` 函数的入口点。
4. **浏览器的渲染引擎 (Blink) 执行 JavaScript 代码，当遇到 `captureStream()` 调用时，会调用相应的 C++ 方法。**
5. **在 C++ 代码中，会进行各种检查 (EME, 跨域)，并创建 `MediaStream` 对象和相关的捕获器对象。**
6. **`MediaElementEventListener` 被添加到媒体元素上，开始监听 `loadedmetadata` 和 `ended` 事件。** 这意味着当媒体元素的元数据加载完成或者播放结束时，会触发 `MediaElementEventListener::Invoke` 方法。
7. **如果媒体元素当前没有加载任何源或者正在加载中，`captureStream()` 返回的 `MediaStream` 可能暂时是空的。**  当媒体元素的元数据加载完成后，`loadedmetadata` 事件触发，`MediaElementEventListener::Invoke` 方法会被调用，这时会创建或更新 `MediaStream` 中的轨道。
8. **如果媒体元素播放结束，`ended` 事件触发，`MediaElementEventListener::Invoke` 方法会停止并移除 `MediaStream` 中的所有轨道。**

**调试线索:**

* **在 JavaScript 代码中设置断点:**  在调用 `captureStream()` 的地方设置断点，查看调用时的元素状态。
* **在 Blink 源代码中设置断点:**  在 `html_media_element_capture.cc` 文件的 `HTMLMediaElementCapture::captureStream` 函数的开头设置断点，可以追踪代码的执行流程。
* **检查控制台错误信息:**  如果捕获失败，浏览器控制台通常会显示相关的错误信息 (例如 `SecurityError`, `NotSupportedError`)，这些信息可以帮助定位问题。
* **使用 `chrome://webrtc-internals`:**  这个 Chrome 提供的内部页面可以查看 WebRTC 相关的状态，包括 `MediaStream` 的信息，可以帮助确认 `captureStream()` 是否成功创建了 `MediaStream` 以及其包含的轨道。
* **查看网络请求:**  如果怀疑是跨域问题，可以查看浏览器的开发者工具中的网络请求，确认媒体资源的 CORS 头信息是否正确。
* **检查媒体元素的 `readyState`:**  在调用 `captureStream()` 之前，检查媒体元素的 `readyState` 属性，确保其状态为 `HAVE_METADATA` 或更高。

总而言之，`html_media_element_capture.cc` 文件是 Blink 引擎中实现 HTML 媒体元素捕获为 `MediaStream` 功能的关键部分，它连接了 JavaScript API 和底层的媒体处理逻辑，并涉及到一些安全和事件处理机制。理解这个文件的功能有助于开发者更好地使用 `captureStream()` API，并排查相关问题。

### 提示词
```
这是目录为blink/renderer/modules/mediacapturefromelement/html_media_element_capture.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediacapturefromelement/html_media_element_capture.h"

#include "base/memory/ptr_util.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/modules/encryptedmedia/html_media_element_encrypted_media.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_keys.h"
#include "third_party/blink/renderer/modules/mediacapturefromelement/html_audio_element_capturer_source.h"
#include "third_party/blink/renderer/modules/mediacapturefromelement/html_video_element_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_utils.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"

namespace blink {

namespace {

// This method creates a MediaStreamSource with the provided video
// capturer source. A new MediaStreamComponent + MediaStreamTrack pair is
// created, connected to the source and is plugged into the
// MediaStreamDescriptor (|descriptor|).
// |is_remote| should be true if the source of the data is not a local device.
// |is_readonly| should be true if the format of the data cannot be changed by
// MediaTrackConstraints.
bool AddVideoTrackToMediaStream(
    LocalFrame* frame,
    std::unique_ptr<VideoCapturerSource> video_source,
    bool is_remote,
    MediaStreamDescriptor* descriptor) {
  DCHECK(video_source.get());
  if (!descriptor) {
    DLOG(ERROR) << "MediaStreamDescriptor is null";
    return false;
  }

  media::VideoCaptureFormats preferred_formats =
      video_source->GetPreferredFormats();
  auto media_stream_video_source =
      std::make_unique<MediaStreamVideoCapturerSource>(
          frame->GetTaskRunner(TaskType::kInternalMediaRealTime), frame,
          WebPlatformMediaStreamSource::SourceStoppedCallback(),
          std::move(video_source));
  auto* media_stream_video_source_ptr = media_stream_video_source.get();
  const String track_id(WTF::CreateCanonicalUUIDString());
  auto* media_stream_source = MakeGarbageCollected<MediaStreamSource>(
      track_id, MediaStreamSource::kTypeVideo, track_id, is_remote,
      std::move(media_stream_video_source));
  media_stream_source->SetCapabilities(ComputeCapabilitiesForVideoSource(
      track_id, preferred_formats, mojom::blink::FacingMode::kNone,
      false /* is_device_capture */));
  descriptor->AddRemoteTrack(MediaStreamVideoTrack::CreateVideoTrack(
      media_stream_video_source_ptr,
      MediaStreamVideoSource::ConstraintsOnceCallback(), true));
  return true;
}

// Fills in the MediaStreamDescriptor to capture from the WebMediaPlayer
// identified by the second parameter.
void CreateHTMLVideoElementCapturer(
    LocalFrame* frame,
    MediaStreamDescriptor* descriptor,
    WebMediaPlayer* web_media_player,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(descriptor);
  DCHECK(web_media_player);
  AddVideoTrackToMediaStream(
      frame,
      HtmlVideoElementCapturerSource::CreateFromWebMediaPlayerImpl(
          web_media_player, Platform::Current()->GetIOTaskRunner(),
          std::move(task_runner)),
      false,  // is_remote
      descriptor);
}

// Fills in the MediaStreamDescriptor to capture from the WebMediaPlayer
// identified by the second parameter.
void CreateHTMLAudioElementCapturer(
    LocalFrame*,
    MediaStreamDescriptor* descriptor,
    WebMediaPlayer* web_media_player,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(descriptor);
  DCHECK(web_media_player);

  const String track_id = WTF::CreateCanonicalUUIDString();

  MediaStreamAudioSource* const media_stream_audio_source =
      HtmlAudioElementCapturerSource::CreateFromWebMediaPlayerImpl(
          web_media_player, std::move(task_runner));

  // |media_stream_source| takes ownership of |media_stream_audio_source|.
  auto* media_stream_source = MakeGarbageCollected<MediaStreamSource>(
      track_id, MediaStreamSource::StreamType::kTypeAudio, track_id,
      false /* is_remote */, base::WrapUnique(media_stream_audio_source));
  auto* media_stream_component = MakeGarbageCollected<MediaStreamComponentImpl>(
      media_stream_source,
      std::make_unique<MediaStreamAudioTrack>(/*is_local_track=*/true));

  MediaStreamSource::Capabilities capabilities;
  capabilities.device_id = track_id;
  capabilities.echo_cancellation.emplace_back(false);
  capabilities.auto_gain_control.emplace_back(false);
  capabilities.noise_suppression.emplace_back(false);
  capabilities.voice_isolation.emplace_back(false);
  capabilities.sample_size = {
      media::SampleFormatToBitsPerChannel(media::kSampleFormatS16),  // min
      media::SampleFormatToBitsPerChannel(media::kSampleFormatS16)   // max
  };
  media_stream_source->SetCapabilities(capabilities);

  media_stream_audio_source->ConnectToInitializedTrack(media_stream_component);
  descriptor->AddRemoteTrack(media_stream_component);
}

// Class to register to the events of |m_mediaElement|, acting accordingly on
// the tracks of |m_mediaStream|.
class MediaElementEventListener final : public NativeEventListener {
 public:
  MediaElementEventListener(HTMLMediaElement*, MediaStream*);
  void UpdateSources(ExecutionContext*);

  void Trace(Visitor*) const override;

  // EventListener implementation.
  void Invoke(ExecutionContext*, Event*) override;

 private:
  Member<HTMLMediaElement> media_element_;
  Member<MediaStream> media_stream_;
  HeapHashSet<WeakMember<MediaStreamSource>> sources_;
};

MediaElementEventListener::MediaElementEventListener(HTMLMediaElement* element,
                                                     MediaStream* stream)
    : NativeEventListener(), media_element_(element), media_stream_(stream) {
  UpdateSources(element->GetExecutionContext());
}

void MediaElementEventListener::Invoke(ExecutionContext* context,
                                       Event* event) {
  DVLOG(2) << __func__ << " " << event->type();
  DCHECK(media_stream_);

  if (event->type() == event_type_names::kEnded) {
    const MediaStreamTrackVector tracks = media_stream_->getTracks();
    // Stop all tracks before removing them. This ensures multi-track stream
    // consumers like the MediaRecorder sees all tracks ended before they're
    // removed from the stream, which is interpreted as an error if happening
    // earlier, see for example
    // https://www.w3.org/TR/mediastream-recording/#dom-mediarecorder-start
    // step 14.4.
    for (const auto& track : tracks) {
      track->stopTrack(context);
    }
    for (const auto& track : tracks) {
      media_stream_->RemoveTrackByComponentAndFireEvents(
          track->Component(),
          MediaStreamDescriptorClient::DispatchEventTiming::kScheduled);
    }

    media_stream_->StreamEnded();
    return;
  }
  if (event->type() != event_type_names::kLoadedmetadata)
    return;

  // If |media_element_| is a MediaStream, clone the new tracks.
  if (media_element_->GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream) {
    const MediaStreamTrackVector tracks = media_stream_->getTracks();
    for (const auto& track : tracks) {
      track->stopTrack(context);
      media_stream_->RemoveTrackByComponentAndFireEvents(
          track->Component(),
          MediaStreamDescriptorClient::DispatchEventTiming::kScheduled);
    }
    auto variant = media_element_->GetSrcObjectVariant();
    // The load type check above, should prevent this from failing:
    DCHECK(absl::holds_alternative<MediaStreamDescriptor*>(variant));
    MediaStreamDescriptor* const descriptor =
        absl::get<MediaStreamDescriptor*>(variant);
    DCHECK(descriptor);
    for (unsigned i = 0; i < descriptor->NumberOfAudioComponents(); i++) {
      media_stream_->AddTrackByComponentAndFireEvents(
          descriptor->AudioComponent(i),
          MediaStreamDescriptorClient::DispatchEventTiming::kScheduled);
    }
    for (unsigned i = 0; i < descriptor->NumberOfVideoComponents(); i++) {
      media_stream_->AddTrackByComponentAndFireEvents(
          descriptor->VideoComponent(i),
          MediaStreamDescriptorClient::DispatchEventTiming::kScheduled);
    }
    UpdateSources(context);
    return;
  }

  auto* descriptor = MakeGarbageCollected<MediaStreamDescriptor>(
      WTF::CreateCanonicalUUIDString(), MediaStreamComponentVector(),
      MediaStreamComponentVector());

  if (media_element_->HasVideo()) {
    CreateHTMLVideoElementCapturer(
        To<LocalDOMWindow>(context)->GetFrame(), descriptor,
        media_element_->GetWebMediaPlayer(),
        media_element_->GetExecutionContext()->GetTaskRunner(
            TaskType::kInternalMediaRealTime));
  }
  if (media_element_->HasAudio()) {
    CreateHTMLAudioElementCapturer(
        To<LocalDOMWindow>(context)->GetFrame(), descriptor,
        media_element_->GetWebMediaPlayer(),
        media_element_->GetExecutionContext()->GetTaskRunner(
            TaskType::kInternalMediaRealTime));
  }

  MediaStreamComponentVector video_components = descriptor->VideoComponents();
  for (auto component : video_components) {
    media_stream_->AddTrackByComponentAndFireEvents(
        component,
        MediaStreamDescriptorClient::DispatchEventTiming::kScheduled);
  }

  MediaStreamComponentVector audio_components = descriptor->AudioComponents();
  for (auto component : audio_components) {
    media_stream_->AddTrackByComponentAndFireEvents(
        component,
        MediaStreamDescriptorClient::DispatchEventTiming::kScheduled);
  }

  DVLOG(2) << "#videotracks: " << video_components.size()
           << " #audiotracks: " << audio_components.size();

  UpdateSources(context);
}

void DidStopMediaStreamSource(MediaStreamSource* source) {
  if (!source)
    return;
  WebPlatformMediaStreamSource* const platform_source =
      source->GetPlatformSource();
  DCHECK(platform_source);
  platform_source->SetSourceMuted(true);
  platform_source->StopSource();
}

void MediaElementEventListener::UpdateSources(ExecutionContext* context) {
  for (auto track : media_stream_->getTracks())
    sources_.insert(track->Component()->Source());

  // Handling of the ended event in JS triggered by DidStopMediaStreamSource()
  // may cause a reentrant call to this function, which can modify |sources_|.
  // Iterate over a copy of |sources_| to avoid invalidation of the iterator
  // when a reentrant call occurs.
  auto sources_copy = sources_;
  if (!media_element_->currentSrc().IsEmpty() &&
      !media_element_->IsMediaDataCorsSameOrigin()) {
    for (auto source : sources_copy)
      DidStopMediaStreamSource(source.Get());
  }
}

void MediaElementEventListener::Trace(Visitor* visitor) const {
  visitor->Trace(media_element_);
  visitor->Trace(media_stream_);
  visitor->Trace(sources_);
  EventListener::Trace(visitor);
}

}  // anonymous namespace

// static
MediaStream* HTMLMediaElementCapture::captureStream(
    ScriptState* script_state,
    HTMLMediaElement& element,
    ExceptionState& exception_state) {
  // Avoid capturing from EME-protected Media Elements.
  if (HTMLMediaElementEncryptedMedia::mediaKeys(element)) {
    // This exception is not defined in the spec, see
    // https://github.com/w3c/mediacapture-fromelement/issues/20.
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Stream capture not supported with EME");
    return nullptr;
  }

  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "The context has been destroyed");
    return nullptr;
  }

  ExecutionContext* context = ExecutionContext::From(script_state);
  if (!element.currentSrc().IsEmpty() && !element.IsMediaDataCorsSameOrigin()) {
    exception_state.ThrowSecurityError(
        "Cannot capture from element with cross-origin data");
    return nullptr;
  }

  auto* descriptor = MakeGarbageCollected<MediaStreamDescriptor>(
      WTF::CreateCanonicalUUIDString(), MediaStreamComponentVector(),
      MediaStreamComponentVector());

  // Create() duplicates the MediaStreamTracks inside |descriptor|.
  MediaStream* stream = MediaStream::Create(context, descriptor);

  MediaElementEventListener* listener =
      MakeGarbageCollected<MediaElementEventListener>(&element, stream);
  element.addEventListener(event_type_names::kLoadedmetadata, listener, false);
  element.addEventListener(event_type_names::kEnded, listener, false);

  // If |element| is actually playing a MediaStream, just clone it.
  if (element.GetLoadType() == WebMediaPlayer::kLoadTypeMediaStream) {
    auto variant = element.GetSrcObjectVariant();
    // The load type check above, should prevent this from failing:
    DCHECK(absl::holds_alternative<MediaStreamDescriptor*>(variant));
    MediaStreamDescriptor* const element_descriptor =
        absl::get<MediaStreamDescriptor*>(variant);
    DCHECK(element_descriptor);
    return MediaStream::Create(context, element_descriptor);
  }

  LocalFrame* frame = ToLocalFrameIfNotDetached(script_state->GetContext());
  DCHECK(frame);
  if (element.HasVideo()) {
    CreateHTMLVideoElementCapturer(frame, descriptor,
                                   element.GetWebMediaPlayer(),
                                   element.GetExecutionContext()->GetTaskRunner(
                                       TaskType::kInternalMediaRealTime));
  }
  if (element.HasAudio()) {
    CreateHTMLAudioElementCapturer(frame, descriptor,
                                   element.GetWebMediaPlayer(),
                                   element.GetExecutionContext()->GetTaskRunner(
                                       TaskType::kInternalMediaRealTime));
  }
  listener->UpdateSources(context);

  // If element.currentSrc().isNull() then |stream| will have no tracks, those
  // will be added eventually afterwards via MediaElementEventListener.
  return stream;
}

}  // namespace blink
```
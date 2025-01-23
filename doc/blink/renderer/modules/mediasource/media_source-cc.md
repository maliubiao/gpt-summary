Response:
The user wants a summary of the functionality of the provided C++ code file, `media_source.cc`, which is part of the Chromium Blink rendering engine.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The file is named `media_source.cc` and resides in the `mediasource` directory. This immediately suggests that it implements the core logic for the Media Source Extensions (MSE) API in the browser.

2. **Analyze key classes and methods:**  Look for the main class defined in the file. In this case, it's `MediaSource`. Then, identify its public methods, especially those related to the MSE API: `addSourceBuffer`, `removeSourceBuffer`, `isTypeSupported`, `endOfStream`, and `setLiveSeekableRange`. These methods directly correspond to the JavaScript API.

3. **Connect to web technologies (JavaScript, HTML, CSS):**  Consider how the `MediaSource` class interacts with the web platform. It's evident that `MediaSource` is a JavaScript API available to web developers. Its primary use is in conjunction with the `<video>` or `<audio>` HTML elements. CSS, in this context, is less directly related to the core *functionality* but might be used for styling the media elements.

4. **Look for data structures and internal state:** Identify important member variables like `ready_state_`, `source_buffers_`, and `active_source_buffers_`. These indicate the internal state and data management within the `MediaSource` object.

5. **Consider threading and synchronization:** Notice the use of `base::AutoLock` and references to "main thread" and "worker thread". This suggests that `MediaSource` needs to handle concurrent access and operations, especially in the context of web workers.

6. **Examine dependencies and includes:**  The included headers provide clues about the responsibilities of `MediaSource`. For example, including `<media/base/...>` indicates interaction with the Chromium media pipeline. Includes like  `"third_party/blink/public/platform/web_media_source.h"` show the relationship to the platform-specific abstraction layer.

7. **Infer logic and potential issues:** Based on the method names and code snippets, deduce the logical flow. For example, `addSourceBuffer` creates a `SourceBuffer` object, and `removeSourceBuffer` destroys it. Consider potential user errors, such as calling methods in the wrong state (e.g., adding a source buffer when the `readyState` is not "open").

8. **Address the specific requests in the prompt:**
    * **Functionality listing:** Explicitly list the main functions performed by the class.
    * **Relationship to web technologies:**  Provide concrete examples of how JavaScript interacts with `MediaSource` and how it's used with HTML media elements.
    * **Logic reasoning (input/output):** Although the provided snippet doesn't show complex logic *with clear input/output*, the act of adding a `SourceBuffer` can be considered as an input (type, config) leading to the output of a `SourceBuffer` object.
    * **User errors:**  Specifically address common mistakes developers might make when using the MSE API.
    * **Debugging clues (user steps):** Describe how a user might trigger the code by interacting with a media player on a website.
    * **Summary:**  Provide a concise overview of the class's purpose.

9. **Structure the answer:** Organize the findings into logical sections to improve readability. Use clear headings and bullet points.

10. **Refine and review:**  Read through the generated summary to ensure accuracy, completeness, and clarity. Check that all parts of the prompt have been addressed.

By following these steps, we can effectively analyze the provided code snippet and generate a comprehensive and informative summary of its functionality. The key is to combine code analysis with an understanding of the underlying web technologies and the purpose of the Media Source Extensions API.
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediasource/media_source.h"

// ... (includes) ...

namespace blink {

namespace {

// ... (internal helper functions) ...

}  // namespace

// ... (static helper functions for converting enum to string and error checking) ...

MediaSource* MediaSource::Create(ExecutionContext* context) {
  return MakeGarbageCollected<MediaSource>(context);
}

MediaSource::MediaSource(ExecutionContext* context)
    : ActiveScriptWrappable<MediaSource>({}),
      ExecutionContextLifecycleObserver(context),
      ready_state_(ReadyState::kClosed),
      async_event_queue_(
          MakeGarbageCollected<EventQueue>(GetExecutionContext(),
                                           TaskType::kMediaElementEvent)),
      context_already_destroyed_(false),
      source_buffers_(
          MakeGarbageCollected<SourceBufferList>(GetExecutionContext(),
                                                 async_event_queue_.Get())),
      active_source_buffers_(
          MakeGarbageCollected<SourceBufferList>(GetExecutionContext(),
                                                 async_event_queue_.Get())),
      has_live_seekable_range_(false),
      live_seekable_range_start_(0.0),
      live_seekable_range_end_(0.0) {
  DVLOG(1) << __func__ << " this=" << this;
  if (!IsMainThread()) {
    DCHECK(GetExecutionContext()->IsDedicatedWorkerGlobalScope());
  }
}

MediaSource::~MediaSource() {
  DVLOG(1) << __func__ << " this=" << this;
}

void MediaSource::LogAndThrowDOMException(ExceptionState& exception_state,
                                          DOMExceptionCode error,
                                          const String& message) {
  DVLOG(1) << __func__ << " (error=" << ToExceptionCode(error)
           << ", message=" << message << ")";
  exception_state.ThrowDOMException(error, message);
}

void MediaSource::LogAndThrowTypeError(ExceptionState& exception_state,
                                       const String& message) {
  DVLOG(1) << __func__ << " (message=" << message << ")";
  exception_state.ThrowTypeError(message);
}

SourceBuffer* MediaSource::addSourceBuffer(const String& type,
                                           ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " type=" << type;

  // 2.2
  // https://www.w3.org/TR/media-source/#dom-mediasource-addsourcebuffer
  // 1. If type is an empty string then throw a TypeError exception
  //    and abort these steps.
  if (type.empty()) {
    LogAndThrowTypeError(exception_state, "The type provided is empty");
    return nullptr;
  }

  // 2. If type contains a MIME type that is not supported ..., then throw a
  // NotSupportedError exception and abort these steps.
  // TODO(crbug.com/535738): Actually relax codec-specificity.
  if (!IsTypeSupportedInternal(
          GetExecutionContext(), type,
          false /* Allow underspecified codecs in |type| */)) {
    LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotSupportedError,
        "The type provided ('" + type + "') is unsupported.");
    return nullptr;
  }

  // 4. If the readyState attribute is not in the "open" state then throw an
  // InvalidStateError exception and abort these steps.
  if (!IsOpen()) {
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "The MediaSource's readyState is not 'open'.");
    return nullptr;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case).
  SourceBuffer* source_buffer = nullptr;

  // Note, here we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &MediaSource::AddSourceBuffer_Locked, WrapPersistent(this), type,
          nullptr /* audio_config */, nullptr /* video_config */,
          WTF::Unretained(&exception_state),
          WTF::Unretained(&source_buffer)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }

  return source_buffer;
}

SourceBuffer* MediaSource::AddSourceBufferUsingConfig(
    ExecutionContext* execution_context,
    const SourceBufferConfig* config,
    ExceptionState& exception_state) {
  // ... (implementation for adding SourceBuffer using config) ...
}

void MediaSource::AddSourceBuffer_Locked(
    const String& type,
    std::unique_ptr<media::AudioDecoderConfig> audio_config,
    std::unique_ptr<media::VideoDecoderConfig> video_config,
    ExceptionState* exception_state,
    SourceBuffer** created_buffer,
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  // ... (implementation for the locked part of addSourceBuffer) ...
}

void MediaSource::removeSourceBuffer(SourceBuffer* buffer,
                                     ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " buffer=" << buffer;

  // 2.2
  // https://dvcs.w3.org/hg/html-media/raw-file/default/media-source/media-source.html#widl-MediaSource-removeSourceBuffer-void-SourceBuffer-sourceBuffer

  // 1. If sourceBuffer specifies an object that is not in sourceBuffers then
  //    throw a NotFoundError exception and abort these steps.
  if (!source_buffers_->length() || !source_buffers_->Contains(buffer)) {
    LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotFoundError,
        "The SourceBuffer provided is not contained in this MediaSource.");
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must not be closed (since closing clears our SourceBuffer
  // collections), therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&MediaSource::RemoveSourceBuffer_Locked,
                        WrapPersistent(this), WrapPersistent(buffer)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }
}

void MediaSource::RemoveSourceBuffer_Locked(
    SourceBuffer* buffer,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  // ... (implementation for the locked part of removeSourceBuffer) ...
}

void MediaSource::OnReadyStateChange(const ReadyState old_state,
                                     const ReadyState new_state) {
  // ... (implementation for handling ready state changes) ...
}

bool MediaSource::IsUpdating() const {
  // ... (implementation to check if any source buffer is updating) ...
}

// static
bool MediaSource::isTypeSupported(ExecutionContext* context,
                                  const String& type) {
  // ... (implementation for checking if a type is supported) ...
}

// static
bool MediaSource::IsTypeSupportedInternal(ExecutionContext* context,
                                          const String& type,
                                          bool enforce_codec_specificity) {
  // ... (internal implementation for checking if a type is supported) ...
}

// static
bool MediaSource::canConstructInDedicatedWorker(ExecutionContext* context) {
  return true;
}

void MediaSource::RecordIdentifiabilityMetric(ExecutionContext* context,
                                              const String& type,
                                              bool result) {
  // ... (implementation for recording identifiability metrics) ...
}

const AtomicString& MediaSource::InterfaceName() const {
  return event_target_names::kMediaSource;
}

ExecutionContext* MediaSource::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

// TODO(https://crbug.com/878133): Consider using macros or virtual methods to
// skip the Bind+Run of |cb| when on same-thread, and to instead just run the
// method directly.
bool MediaSource::RunUnlessElementGoneOrClosingUs(
    MediaSourceAttachmentSupplement::RunExclusivelyCB cb) {
  // ... (implementation to run a callback if the element is not gone or closing) ...
}

void MediaSource::AssertAttachmentsMutexHeldIfCrossThreadForDebugging() const {
  // ... (implementation for debugging assertions related to attachments) ...
}

void MediaSource::SendUpdatedInfoToMainThreadCache() {
  // ... (implementation for sending updated info to the main thread cache) ...
}

void MediaSource::Trace(Visitor* visitor) const {
  // ... (implementation for tracing) ...
}

void MediaSource::CompleteAttachingToMediaElement(
    std::unique_ptr<WebMediaSource> web_media_source) {
  // ... (implementation for completing the attachment to a media element) ...
}

double MediaSource::GetDuration_Locked(
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) const {
  // ... (implementation for getting the duration in a locked state) ...
}

WebTimeRanges MediaSource::BufferedInternal(
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) const {
  // ... (implementation for getting buffered ranges) ...
}
```

## blink/renderer/modules/mediasource/media_source.cc 的功能归纳 (第 1 部分)

这个文件的主要功能是实现了 **Media Source API** 的核心逻辑。Media Source API 允许 JavaScript 将媒体数据块 (chunks) 动态地添加到 HTML `<audio>` 或 `<video>` 元素中，从而实现更灵活的媒体播放控制，例如自适应码率流 (ABR) 和拼接不同的媒体片段。

**具体来说，这部分代码主要负责：**

1. **`MediaSource` 对象的创建和生命周期管理:**
   - 定义了 `MediaSource` 类，它是 Media Source API 的入口点。
   - 提供了 `Create()` 静态方法用于创建 `MediaSource` 对象。
   - 管理 `MediaSource` 的 `readyState` 属性，表示 MediaSource 的当前状态 (open, closed, ended)。
   - 实现了析构函数 `~MediaSource()` 来清理资源。

2. **管理 `SourceBuffer` 对象:**
   - 提供了 `addSourceBuffer()` 方法，用于创建和添加新的 `SourceBuffer` 对象到 `MediaSource` 中。`SourceBuffer` 负责接收和缓冲特定类型的媒体数据。
   - 实现了 `AddSourceBufferUsingConfig()` 方法，允许使用更细粒度的配置 (例如 `AudioDecoderConfig` 或 `VideoDecoderConfig`) 来创建 `SourceBuffer`，这与 WebCodecs API 相关联。
   - 包含了 `AddSourceBuffer_Locked()` 方法，这是 `addSourceBuffer()` 的内部实现，在需要线程同步的情况下执行。
   - 提供了 `removeSourceBuffer()` 方法，用于从 `MediaSource` 中移除并销毁 `SourceBuffer` 对象。
   - 实现了 `RemoveSourceBuffer_Locked()` 方法，这是 `removeSourceBuffer()` 的内部实现。
   - 维护了两个 `SourceBufferList` 对象：
     - `source_buffers_`: 包含所有添加到 `MediaSource` 的 `SourceBuffer` 对象。
     - `active_source_buffers_`:  包含当前被 HTMLMediaElement 视为活动的 `SourceBuffer` 对象。

3. **支持的媒体类型检查:**
   - 提供了 `isTypeSupported()` 静态方法，用于检查指定的 MIME 类型和编解码器是否受当前环境支持。
   - 实现了 `IsTypeSupportedInternal()` 方法，是 `isTypeSupported()` 的内部实现，可以控制是否强制要求完整的编解码器信息。

4. **处理 `readyState` 状态变化:**
   - 实现了 `OnReadyStateChange()` 方法，用于处理 `readyState` 的变化，并在状态改变时触发相应的事件 (如 `sourceopen`, `sourceended`, `sourceclose`)。

5. **跟踪更新状态:**
   - 提供了 `IsUpdating()` 方法，用于检查当前是否有任何关联的 `SourceBuffer` 正在进行更新操作 (例如，正在添加媒体数据)。

6. **线程安全和同步:**
   - 使用 `base::AutoLock` 来保护对内部状态的并发访问，特别是在处理跨线程操作时。
   - 提供了 `RunUnlessElementGoneOrClosingUs()` 方法，用于确保在执行某些操作时，`MediaSource` 仍然有效且未被销毁。
   - 包含了 `AssertAttachmentsMutexHeldIfCrossThreadForDebugging()` 方法，用于在调试模式下断言是否持有所需的锁。
   - 实现了 `SendUpdatedInfoToMainThreadCache()` 方法，用于将更新后的信息发送到主线程缓存。

7. **与底层媒体管道的交互:**
   - 该文件包含了与 Chromium 的媒体基础设施 (`media/base/...`) 相关的头文件，表明 `MediaSource` 需要与底层的媒体解码和渲染管道进行交互。

8. **事件处理:**
   - 使用 `async_event_queue_` 来管理异步事件的派发。

9. **与其他 Blink 组件的集成:**
   - 包含了与 HTMLMediaElement (`html_media_element.h`) 和 WebCodecs API (`webcodecs/...`) 相关的头文件，表明 `MediaSource` 与这些组件密切相关。

10. **性能监控和调试:**
    - 使用 `DVLOG` 进行日志输出，用于调试和性能分析。
    - 包含 `TRACE_EVENT` 用于性能跟踪。
    - 实现了 `Trace()` 方法，用于在垃圾回收期间跟踪对象。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    ```javascript
    const video = document.querySelector('video');
    const mediaSource = new MediaSource();
    video.src = URL.createObjectURL(mediaSource);

    mediaSource.addEventListener('sourceopen', () => {
      const sourceBuffer = mediaSource.addSourceBuffer('video/mp4; codecs="avc1.42E01E, mp4a.40.2"');
      // ... 向 sourceBuffer 添加媒体数据 ...
    });

    mediaSource.addEventListener('sourceended', () => {
      console.log('MediaSource ended');
    });

    mediaSource.addEventListener('sourceclose', () => {
      console.log('MediaSource closed');
    });
    ```
    这段 JavaScript 代码创建了一个 `MediaSource` 对象，并将其 URL 设置为 `<video>` 元素的 `src` 属性。然后，它监听 `sourceopen` 事件，并在事件触发后调用 `mediaSource.addSourceBuffer()` 来创建一个 `SourceBuffer`。

* **HTML:**
    ```html
    <video controls></video>
    ```
    HTML 的 `<video>` 元素是 Media Source API 的宿主，媒体数据最终会通过 `MediaSource` 提供给它进行播放。

* **CSS:** CSS 主要用于控制 HTML 元素的外观和布局，与 `media_source.cc` 的核心功能没有直接关系。但是，可以使用 CSS 来样式化 `<video>` 元素。

**逻辑推理的假设输入与输出 (以 `addSourceBuffer` 为例):**

**假设输入:**

* `type`: 字符串 "video/mp4; codecs=\"avc1.42E01E, mp4a.40.2\""
* `readyState`: `MediaSource::ReadyState::kOpen`

**预期输出:**

* 返回一个新的 `SourceBuffer` 对象。
* 将该 `SourceBuffer` 对象添加到 `source_buffers_` 列表中。
* 可能会触发 `sourcebuffers` 上的 `addsourcebuffer` 事件 (虽然这部分逻辑可能在其他地方实现)。

**用户或编程常见的使用错误举例说明:**

* **在 `readyState` 不是 "open" 的状态下调用 `addSourceBuffer()`:**
   ```javascript
   const mediaSource = new MediaSource();
   mediaSource.addSourceBuffer('video/mp4'); // 错误：readyState 此时是 "closed"
   ```
   这会导致抛出一个 `InvalidStateError` 异常。

* **提供不支持的 MIME 类型或编解码器给 `addSourceBuffer()`:**
   ```javascript
   const mediaSource = new MediaSource();
   mediaSource.addEventListener('sourceopen', () => {
     mediaSource.addSourceBuffer('unsupported/type'); // 错误：类型不支持
   });
   ```
   这会导致抛出一个 `NotSupportedError` 异常。

* **尝试在 `SourceBuffer` 正在更新时移除它:** 虽然这段代码没有直接展示移除 `SourceBuffer` 的逻辑，但可以推断出在 `SourceBuffer` 处于更新状态时进行移除可能会导致问题，尽管具体的错误处理可能在 `SourceBuffer` 相关的代码中。

**用户操作如何一步步到达这里 (作为调试线索):**

1. 用户访问一个包含 `<video>` 元素的网页。
2. 网页的 JavaScript 代码创建了一个 `MediaSource` 对象。
3. JavaScript 代码将 `MediaSource` 对象的 URL 设置为 `<video>` 元素的 `src` 属性。这会触发浏览器内部将 `MediaSource` 对象与 `<video>` 元素关联起来。
4. 当 `MediaSource` 的 `readyState` 变为 "open" 时，会触发 `sourceopen` 事件。
5. JavaScript 代码监听 `sourceopen` 事件，并在事件处理程序中调用 `mediaSource.addSourceBuffer()` 来创建一个或多个 `SourceBuffer` 对象。
6. 用户与网页交互，例如点击播放按钮，可能会触发媒体数据的请求和添加到 `SourceBuffer` 的过程。如果在这个过程中出现问题，例如添加了不支持的媒体格式，相关的错误处理逻辑会在 `media_source.cc` 中执行，并可能抛出异常。
7. 如果需要移除某个 `SourceBuffer`，JavaScript 代码会调用 `mediaSource.removeSourceBuffer()`，最终会执行 `media_source.cc` 中的 `removeSourceBuffer` 相关逻辑。

总而言之，`media_source.cc` 的这部分代码是 Media Source API 的核心实现，负责管理 `MediaSource` 对象和其关联的 `SourceBuffer` 对象，处理状态变化，并与底层的媒体管道进行交互。它为 JavaScript 提供了操作媒体流的能力，是实现复杂媒体播放场景的关键组件。

### 提示词
```
这是目录为blink/renderer/modules/mediasource/media_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediasource/media_source.h"

#include <memory>
#include <tuple>

#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "build/chromeos_buildflags.h"
#include "media/base/audio_decoder_config.h"
#include "media/base/logging_override_if_enabled.h"
#include "media/base/media_switches.h"
#include "media/base/media_types.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/video_decoder_config.h"
#include "media/media_buildflags.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/platform/web_media_source.h"
#include "third_party/blink/public/platform/web_source_buffer.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_end_of_stream_error.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_source_buffer_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/modules/mediasource/attachment_creation_pass_key_provider.h"
#include "third_party/blink/renderer/modules/mediasource/cross_thread_media_source_attachment.h"
#include "third_party/blink/renderer/modules/mediasource/handle_attachment_provider.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_handle_impl.h"
#include "third_party/blink/renderer/modules/mediasource/same_thread_media_source_attachment.h"
#include "third_party/blink/renderer/modules/mediasource/same_thread_media_source_tracer.h"
#include "third_party/blink/renderer/modules/mediasource/source_buffer_track_base_supplement.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_decoder.h"
#include "third_party/blink/renderer/modules/webcodecs/video_decoder.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

using blink::WebMediaSource;
using blink::WebSourceBuffer;

namespace blink {

namespace {

#if BUILDFLAG(ENABLE_MSE_MPEG2TS_STREAM_PARSER)

bool IsMp2tCodecSupported(std::string_view codec_id) {
  if (auto result =
          media::ParseVideoCodecString("", codec_id,
                                       /*allow_ambiguous_matches=*/false)) {
    if (result->codec != media::VideoCodec::kH264) {
      return false;
    }
    return true;
  }

  auto audio_codec = media::AudioCodec::kUnknown;
  bool is_codec_ambiguous = false;
  if (media::ParseAudioCodecString("", codec_id, &is_codec_ambiguous,
                                   &audio_codec)) {
    if (is_codec_ambiguous) {
      return false;
    }

    if (audio_codec != media::AudioCodec::kAAC &&
        audio_codec != media::AudioCodec::kMP3) {
      return false;
    }
    return true;
  }

  return false;
}

#endif  // BUILDFLAG(ENABLE_MSE_MPEG2TS_STREAM_PARSER)

}  // namespace

static AtomicString ReadyStateToString(MediaSource::ReadyState state) {
  AtomicString result;
  switch (state) {
    case MediaSource::ReadyState::kOpen:
      result = AtomicString("open");
      break;
    case MediaSource::ReadyState::kClosed:
      result = AtomicString("closed");
      break;
    case MediaSource::ReadyState::kEnded:
      result = AtomicString("ended");
      break;
  }

  return result;
}

static bool ThrowExceptionIfClosed(bool is_open,
                                   ExceptionState& exception_state) {
  if (!is_open) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "The MediaSource's readyState is not 'open'.");
    return true;
  }

  return false;
}

static bool ThrowExceptionIfClosedOrUpdating(bool is_open,
                                             bool is_updating,
                                             ExceptionState& exception_state) {
  if (ThrowExceptionIfClosed(is_open, exception_state))
    return true;

  if (is_updating) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "The 'updating' attribute is true on one or more of this MediaSource's "
        "SourceBuffers.");
    return true;
  }

  return false;
}

MediaSource* MediaSource::Create(ExecutionContext* context) {
  return MakeGarbageCollected<MediaSource>(context);
}

MediaSource::MediaSource(ExecutionContext* context)
    : ActiveScriptWrappable<MediaSource>({}),
      ExecutionContextLifecycleObserver(context),
      ready_state_(ReadyState::kClosed),
      async_event_queue_(
          MakeGarbageCollected<EventQueue>(GetExecutionContext(),
                                           TaskType::kMediaElementEvent)),
      context_already_destroyed_(false),
      source_buffers_(
          MakeGarbageCollected<SourceBufferList>(GetExecutionContext(),
                                                 async_event_queue_.Get())),
      active_source_buffers_(
          MakeGarbageCollected<SourceBufferList>(GetExecutionContext(),
                                                 async_event_queue_.Get())),
      has_live_seekable_range_(false),
      live_seekable_range_start_(0.0),
      live_seekable_range_end_(0.0) {
  DVLOG(1) << __func__ << " this=" << this;
  if (!IsMainThread()) {
    DCHECK(GetExecutionContext()->IsDedicatedWorkerGlobalScope());
  }
}

MediaSource::~MediaSource() {
  DVLOG(1) << __func__ << " this=" << this;
}

void MediaSource::LogAndThrowDOMException(ExceptionState& exception_state,
                                          DOMExceptionCode error,
                                          const String& message) {
  DVLOG(1) << __func__ << " (error=" << ToExceptionCode(error)
           << ", message=" << message << ")";
  exception_state.ThrowDOMException(error, message);
}

void MediaSource::LogAndThrowTypeError(ExceptionState& exception_state,
                                       const String& message) {
  DVLOG(1) << __func__ << " (message=" << message << ")";
  exception_state.ThrowTypeError(message);
}

SourceBuffer* MediaSource::addSourceBuffer(const String& type,
                                           ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " type=" << type;

  // 2.2
  // https://www.w3.org/TR/media-source/#dom-mediasource-addsourcebuffer
  // 1. If type is an empty string then throw a TypeError exception
  //    and abort these steps.
  if (type.empty()) {
    LogAndThrowTypeError(exception_state, "The type provided is empty");
    return nullptr;
  }

  // 2. If type contains a MIME type that is not supported ..., then throw a
  // NotSupportedError exception and abort these steps.
  // TODO(crbug.com/535738): Actually relax codec-specificity.
  if (!IsTypeSupportedInternal(
          GetExecutionContext(), type,
          false /* Allow underspecified codecs in |type| */)) {
    LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotSupportedError,
        "The type provided ('" + type + "') is unsupported.");
    return nullptr;
  }

  // 4. If the readyState attribute is not in the "open" state then throw an
  // InvalidStateError exception and abort these steps.
  if (!IsOpen()) {
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "The MediaSource's readyState is not 'open'.");
    return nullptr;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case).
  SourceBuffer* source_buffer = nullptr;

  // Note, here we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &MediaSource::AddSourceBuffer_Locked, WrapPersistent(this), type,
          nullptr /* audio_config */, nullptr /* video_config */,
          WTF::Unretained(&exception_state),
          WTF::Unretained(&source_buffer)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }

  return source_buffer;
}

SourceBuffer* MediaSource::AddSourceBufferUsingConfig(
    ExecutionContext* execution_context,
    const SourceBufferConfig* config,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this;

  UseCounter::Count(execution_context,
                    WebFeature::kMediaSourceExtensionsForWebCodecs);

  DCHECK(config);

  // Precisely one of the multiple keys in SourceBufferConfig must be set.
  int num_set = 0;
  if (config->hasAudioConfig())
    num_set++;
  if (config->hasVideoConfig())
    num_set++;
  if (num_set != 1) {
    LogAndThrowTypeError(
        exception_state,
        "SourceBufferConfig must have precisely one media type");
    return nullptr;
  }

  // Determine if the config is valid and supported by creating the necessary
  // media decoder configs using WebCodecs converters. This implies that codecs
  // supported by WebCodecs are also supported by MSE, though MSE may require
  // more precise information in the encoded chunks (such as video chunk
  // duration).
  // TODO(crbug.com/1144908): WebCodecs' determination of decoder configuration
  // support may be changed to be async and thus might also motivate making this
  // method async.
  std::unique_ptr<media::AudioDecoderConfig> audio_config;
  std::unique_ptr<media::VideoDecoderConfig> video_config;
  String console_message;

  if (config->hasAudioConfig()) {
    if (!AudioDecoder::IsValidAudioDecoderConfig(*(config->audioConfig()),
                                                 &console_message /* out */)) {
      LogAndThrowTypeError(exception_state, console_message);
      return nullptr;
    }

    std::optional<media::AudioDecoderConfig> out_audio_config =
        AudioDecoder::MakeMediaAudioDecoderConfig(*(config->audioConfig()),
                                                  &console_message /* out */);

    if (out_audio_config) {
      audio_config =
          std::make_unique<media::AudioDecoderConfig>(*out_audio_config);
    } else {
      LogAndThrowDOMException(exception_state,
                              DOMExceptionCode::kNotSupportedError,
                              console_message);
      return nullptr;
    }
  } else {
    DCHECK(config->hasVideoConfig());
    if (!VideoDecoder::IsValidVideoDecoderConfig(*(config->videoConfig()),
                                                 &console_message /* out */)) {
      LogAndThrowTypeError(exception_state, console_message);
      return nullptr;
    }

    bool converter_needed = false;
    std::optional<media::VideoDecoderConfig> out_video_config =
        VideoDecoder::MakeMediaVideoDecoderConfig(*(config->videoConfig()),
                                                  &console_message /* out */,
                                                  &converter_needed /* out */);
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    // TODO(crbug.com/1144908): Initial prototype does not support h264
    // buffering. See above.
    if (out_video_config && converter_needed) {
      out_video_config = std::nullopt;
      console_message =
          "H.264/H.265 EncodedVideoChunk buffering is not yet supported in "
          "MSE.See https://crbug.com/1144908.";
    }
#endif  // BUILDFLAG(USE_PROPRIETARY_CODECS)

    if (out_video_config) {
      video_config =
          std::make_unique<media::VideoDecoderConfig>(*out_video_config);
    } else {
      LogAndThrowDOMException(exception_state,
                              DOMExceptionCode::kNotSupportedError,
                              console_message);
      return nullptr;
    }
  }

  // If the readyState attribute is not in the "open" state then throw an
  // InvalidStateError exception and abort these steps.
  if (!IsOpen()) {
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "The MediaSource's readyState is not 'open'.");
    return nullptr;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case).
  SourceBuffer* source_buffer = nullptr;
  String null_type;

  // Note, here we must be open, therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &MediaSource::AddSourceBuffer_Locked, WrapPersistent(this), null_type,
          std::move(audio_config), std::move(video_config),
          WTF::Unretained(&exception_state),
          WTF::Unretained(&source_buffer)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }

  return source_buffer;
}

void MediaSource::AddSourceBuffer_Locked(
    const String& type,
    std::unique_ptr<media::AudioDecoderConfig> audio_config,
    std::unique_ptr<media::VideoDecoderConfig> video_config,
    ExceptionState* exception_state,
    SourceBuffer** created_buffer,
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 5. Create a new SourceBuffer object and associated resources.
  // TODO(crbug.com/1144908): Plumb the configs through into a new logic in
  // WebSourceBuffer and SourceBufferState such that configs and encoded chunks
  // can be buffered, with appropriate invocations of the
  // InitializationSegmentReceived and AppendError methods.
  ContentType content_type(type);
  String codecs = content_type.Parameter("codecs");
  std::unique_ptr<WebSourceBuffer> web_source_buffer = CreateWebSourceBuffer(
      content_type.GetType(), codecs, std::move(audio_config),
      std::move(video_config), *exception_state);

  if (!web_source_buffer) {
    // 2. If type contains a MIME type that is not supported ..., then throw a
    //    NotSupportedError exception and abort these steps.
    // 3. If the user agent can't handle any more SourceBuffer objects then
    //    throw a QuotaExceededError exception and abort these steps
    *created_buffer = nullptr;
    return;
  }

  bool generate_timestamps_flag =
      web_source_buffer->GetGenerateTimestampsFlag();

  auto* buffer = MakeGarbageCollected<SourceBuffer>(
      std::move(web_source_buffer), this, async_event_queue_.Get());
  // 8. Add the new object to sourceBuffers and queue a simple task to fire a
  //    simple event named addsourcebuffer at sourceBuffers.
  source_buffers_->Add(buffer);

  // Steps 6 and 7 (Set the SourceBuffer's mode attribute based on the byte
  // stream format's generate timestamps flag). We do this after adding to
  // sourceBuffers (step 8) to enable direct reuse of the SetMode_Locked() logic
  // here, which depends on |buffer| being in |source_buffers_| in our
  // implementation.
  if (generate_timestamps_flag) {
    buffer->SetMode_Locked(V8AppendMode::Enum::kSequence, exception_state,
                           pass_key);
  } else {
    buffer->SetMode_Locked(V8AppendMode::Enum::kSegments, exception_state,
                           pass_key);
  }

  // 9. Return the new object to the caller.
  DVLOG(3) << __func__ << " this=" << this << " type=" << type << " -> "
           << buffer;
  *created_buffer = buffer;
  return;
}

void MediaSource::removeSourceBuffer(SourceBuffer* buffer,
                                     ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " buffer=" << buffer;

  // 2.2
  // https://dvcs.w3.org/hg/html-media/raw-file/default/media-source/media-source.html#widl-MediaSource-removeSourceBuffer-void-SourceBuffer-sourceBuffer

  // 1. If sourceBuffer specifies an object that is not in sourceBuffers then
  //    throw a NotFoundError exception and abort these steps.
  if (!source_buffers_->length() || !source_buffers_->Contains(buffer)) {
    LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kNotFoundError,
        "The SourceBuffer provided is not contained in this MediaSource.");
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must not be closed (since closing clears our SourceBuffer
  // collections), therefore we must have an attachment.
  if (!RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&MediaSource::RemoveSourceBuffer_Locked,
                        WrapPersistent(this), WrapPersistent(buffer)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    LogAndThrowDOMException(exception_state,
                            DOMExceptionCode::kInvalidStateError,
                            "Worker MediaSource attachment is closing");
  }
}

void MediaSource::RemoveSourceBuffer_Locked(
    SourceBuffer* buffer,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // Steps 2-8 are implemented by SourceBuffer::removedFromMediaSource.
  buffer->RemovedFromMediaSource();

  // 9. If sourceBuffer is in activeSourceBuffers, then remove sourceBuffer from
  //    activeSourceBuffers ...
  active_source_buffers_->Remove(buffer);

  // 10. Remove sourceBuffer from sourceBuffers and fire a removesourcebuffer
  //     event on that object.
  source_buffers_->Remove(buffer);

  // 11. Destroy all resources for sourceBuffer.
  //     This should have been done already by
  //     SourceBuffer::removedFromMediaSource (steps 2-8) above.

  SendUpdatedInfoToMainThreadCache();
}

void MediaSource::OnReadyStateChange(const ReadyState old_state,
                                     const ReadyState new_state) {
  if (IsOpen()) {
    ScheduleEvent(event_type_names::kSourceopen);
    return;
  }

  if (old_state == ReadyState::kOpen && new_state == ReadyState::kEnded) {
    ScheduleEvent(event_type_names::kSourceended);
    return;
  }

  DCHECK(IsClosed());

  active_source_buffers_->Clear();

  // Clear SourceBuffer references to this object.
  for (unsigned i = 0; i < source_buffers_->length(); ++i)
    source_buffers_->item(i)->RemovedFromMediaSource();
  source_buffers_->Clear();

  {
    base::AutoLock lock(attachment_link_lock_);
    media_source_attachment_.reset();
    attachment_tracer_ = nullptr;
  }

  ScheduleEvent(event_type_names::kSourceclose);
}

bool MediaSource::IsUpdating() const {
  // Return true if any member of |m_sourceBuffers| is updating.
  for (unsigned i = 0; i < source_buffers_->length(); ++i) {
    if (source_buffers_->item(i)->updating())
      return true;
  }

  return false;
}

// static
bool MediaSource::isTypeSupported(ExecutionContext* context,
                                  const String& type) {
  bool result = IsTypeSupportedInternal(
      context, type, true /* Require fully specified mime and codecs */);
  DVLOG(2) << __func__ << "(" << type << ") -> " << (result ? "true" : "false");
  return result;
}

// static
bool MediaSource::IsTypeSupportedInternal(ExecutionContext* context,
                                          const String& type,
                                          bool enforce_codec_specificity) {
  // Even after ExecutionContext teardown notification, bindings may still call
  // code-behinds for a short while. If |context| is null, this is likely
  // happening. To prevent possible null deref of |context| in this path, claim
  // lack of support immediately without proceeding.
  if (!context) {
    DVLOG(1) << __func__ << "(" << type << ", "
             << (enforce_codec_specificity ? "true" : "false")
             << ") -> false (context is null)";
    return false;
  }

  // Section 2.2 isTypeSupported() method steps.
  // https://dvcs.w3.org/hg/html-media/raw-file/tip/media-source/media-source.html#widl-MediaSource-isTypeSupported-boolean-DOMString-type
  // 1. If type is an empty string, then return false.
  if (type.empty()) {
    DVLOG(1) << __func__ << "(" << type << ", "
             << (enforce_codec_specificity ? "true" : "false")
             << ") -> false (empty input)";
    return false;
  }

  // 2. If type does not contain a valid MIME type string, then return false.
  ContentType content_type(type);
  String mime_type = content_type.GetType();
  if (mime_type.empty()) {
    DVLOG(1) << __func__ << "(" << type << ", "
             << (enforce_codec_specificity ? "true" : "false")
             << ") -> false (invalid mime type)";
    return false;
  }

  String codecs = content_type.Parameter("codecs");
  ContentType filtered_content_type = content_type;

#if BUILDFLAG(ENABLE_MSE_MPEG2TS_STREAM_PARSER)
  // Mime util doesn't include the mp2t container in order to prevent codec
  // support leaking into HtmlMediaElement.canPlayType. If the stream parser
  // is enabled, we should check that the codecs are valid using the mp4
  // container, since it can support any of the codecs we support for mp2t.
  if (mime_type == "video/mp2t") {
    std::vector<std::string> parsed_codec_ids;
    media::SplitCodecs(codecs.Ascii(), &parsed_codec_ids);
    for (const auto& codec_id : parsed_codec_ids) {
      if (!IsMp2tCodecSupported(codec_id)) {
        return false;
      }
    }
    return true;
  }
#endif

#if BUILDFLAG(ENABLE_PLATFORM_ENCRYPTED_DOLBY_VISION)
  // When build flag ENABLE_PLATFORM_ENCRYPTED_DOLBY_VISION and feature
  // kPlatformEncryptedDolbyVision are both enabled, encrypted Dolby Vision is
  // allowed in Media Source while clear Dolby Vision is not allowed.
  // In this case:
  // - isTypeSupported(fully qualified type with DV codec) should say false on
  // such platform, but addSourceBuffer(same) and changeType(same) shouldn't
  // fail just due to having DV codec.
  // - We use `enforce_codec_specificity` to understand if we are servicing
  // isTypeSupported (if true) vs addSourceBuffer or changeType (if false). When
  // `enforce_codec_specificity` is false, we'll remove any detected DV codec
  // from the codecs in the `filtered_content_type`.
  // - When `kAllowClearDolbyVisionInMseWhenPlatformEncryptedDvEnabled` is
  // specified, allow DV regardless of `enforce_codec_specificity`.
  if (base::FeatureList::IsEnabled(media::kPlatformEncryptedDolbyVision) &&
      (base::FeatureList::IsEnabled(
           media::kAllowClearDolbyVisionInMseWhenPlatformEncryptedDvEnabled) ||
       !enforce_codec_specificity)) {
    // Remove any detected DolbyVision codec from the query to GetSupportsType.
    std::string filtered_codecs;
    std::vector<std::string> parsed_codec_ids;
    media::SplitCodecs(codecs.Ascii(), &parsed_codec_ids);
    bool first = true;
    for (const auto& codec_id : parsed_codec_ids) {
      if (auto result =
              media::ParseVideoCodecString(mime_type.Ascii(), codec_id,
                                           /*allow_ambiguous_matches=*/false)) {
        if (result->codec == media::VideoCodec::kDolbyVision) {
          continue;
        }
      }
      if (first)
        first = false;
      else
        filtered_codecs += ",";
      filtered_codecs += codec_id;
    }

    std::string filtered_type =
        mime_type.Ascii() + "; codecs=\"" + filtered_codecs + "\"";
    DVLOG(1) << __func__ << " filtered_type=" << filtered_type;
    filtered_content_type =
        ContentType(String::FromUTF8(filtered_type.c_str()));
  }
#endif  // BUILDFLAG(ENABLE_PLATFORM_ENCRYPTED_DOLBY_VISION)

  // Note: MediaSource.isTypeSupported() returning true implies that
  // HTMLMediaElement.canPlayType() will return "maybe" or "probably" since it
  // does not make sense for a MediaSource to support a type the
  // HTMLMediaElement knows it cannot play.
  auto get_supports_type_result =
      HTMLMediaElement::GetSupportsType(filtered_content_type);
  if (get_supports_type_result == MIMETypeRegistry::kNotSupported) {
    DVLOG(1) << __func__ << "(" << type << ", "
             << (enforce_codec_specificity ? "true" : "false")
             << ") -> false (not supported by HTMLMediaElement)";
    RecordIdentifiabilityMetric(context, type, false);
    return false;
  }

  // 3. If type contains a media type or media subtype that the MediaSource does
  //    not support, then return false.
  // 4. If type contains at a codec that the MediaSource does not support, then
  //    return false.
  // 5. If the MediaSource does not support the specified combination of media
  //    type, media subtype, and codecs then return false.
  // 6. Return true.
  // For incompletely specified mime-type and codec combinations, we also return
  // false if |enforce_codec_specificity| is true, complying with the
  // non-normative guidance being incubated for the MSE v2 codec switching
  // feature at https://github.com/WICG/media-source/tree/codec-switching.
  // Relaxed codec specificity following similar non-normative guidance is
  // allowed for addSourceBuffer and changeType methods, but this strict codec
  // specificity is and will be retained for isTypeSupported.
  // TODO(crbug.com/535738): Actually relax the codec-specifity for aSB() and
  // cT() (which is when |enforce_codec_specificity| is false).
  MIMETypeRegistry::SupportsType supported =
      MIMETypeRegistry::SupportsMediaSourceMIMEType(mime_type, codecs);

  bool result = supported == MIMETypeRegistry::kSupported;

  DVLOG(2) << __func__ << "(" << type << ", "
           << (enforce_codec_specificity ? "true" : "false") << ") -> "
           << (result ? "true" : "false");
  RecordIdentifiabilityMetric(context, type, result);
  return result;
}

// static
bool MediaSource::canConstructInDedicatedWorker(ExecutionContext* context) {
  return true;
}

void MediaSource::RecordIdentifiabilityMetric(ExecutionContext* context,
                                              const String& type,
                                              bool result) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kMediaSource_IsTypeSupported)) {
    return;
  }
  blink::IdentifiabilityMetricBuilder(context->UkmSourceID())
      .Add(blink::IdentifiableSurface::FromTypeAndToken(
               blink::IdentifiableSurface::Type::kMediaSource_IsTypeSupported,
               IdentifiabilityBenignStringToken(type)),
           result)
      .Record(context->UkmRecorder());
}

const AtomicString& MediaSource::InterfaceName() const {
  return event_target_names::kMediaSource;
}

ExecutionContext* MediaSource::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

// TODO(https://crbug.com/878133): Consider using macros or virtual methods to
// skip the Bind+Run of |cb| when on same-thread, and to instead just run the
// method directly.
bool MediaSource::RunUnlessElementGoneOrClosingUs(
    MediaSourceAttachmentSupplement::RunExclusivelyCB cb) {
  auto [attachment, tracer] = AttachmentAndTracer();
  DCHECK(IsMainThread() ||
         !tracer);  // Cross-thread attachments do not use a tracer.

  if (!attachment) {
    // Element's context destruction may be in flight.
    return false;
  }

  if (!attachment->RunExclusively(true /* abort if not fully attached */,
                                  std::move(cb))) {
    DVLOG(1) << __func__ << ": element is gone or is closing us.";
    // Only in cross-thread case might we not be attached fully.
    DCHECK(!IsMainThread());
    return false;
  }

  return true;
}

void MediaSource::AssertAttachmentsMutexHeldIfCrossThreadForDebugging() const {
#if DCHECK_IS_ON()
  base::AutoLock lock(attachment_link_lock_);
  DCHECK(media_source_attachment_);
  if (!IsMainThread()) {
    DCHECK(!attachment_tracer_);  // Cross-thread attachments use no tracer;
    media_source_attachment_->AssertCrossThreadMutexIsAcquiredForDebugging();
  }
#endif  // DCHECK_IS_ON()
}

void MediaSource::SendUpdatedInfoToMainThreadCache() {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();
  scoped_refptr<MediaSourceAttachmentSupplement> attachment;
  std::tie(attachment, std::ignore) = AttachmentAndTracer();
  attachment->SendUpdatedInfoToMainThreadCache();
}

void MediaSource::Trace(Visitor* visitor) const {
  visitor->Trace(async_event_queue_);

  // |attachment_tracer_| is only set when this object is owned by the main
  // thread and is possibly involved in a SameThreadMediaSourceAttachment.
  // Therefore, it is thread-safe to access it here without taking the
  // |attachment_link_lock_|.
  visitor->Trace(TS_UNCHECKED_READ(attachment_tracer_));

  visitor->Trace(worker_media_source_handle_);
  visitor->Trace(source_buffers_);
  visitor->Trace(active_source_buffers_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void MediaSource::CompleteAttachingToMediaElement(
    std::unique_ptr<WebMediaSource> web_media_source) {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  {
    base::AutoLock lock(attachment_link_lock_);

    DCHECK_EQ(!attachment_tracer_, !IsMainThread());

    if (attachment_tracer_) {
      // Use of a tracer means we must be using same-thread attachment.
      TRACE_EVENT_NESTABLE_ASYNC_END0(
          "media", "MediaSource::StartAttachingToMediaElement",
          TRACE_ID_LOCAL(this));
    } else {
      // Otherwise, we must be using a cross-thread MSE-in-Workers attachment.
      TRACE_EVENT_NESTABLE_ASYNC_END0(
          "media", "MediaSource::StartWorkerAttachingToMainThreadMediaElement",
          TRACE_ID_LOCAL(this));
    }
    DCHECK(web_media_source);
    DCHECK(!web_media_source_);
    DCHECK(media_source_attachment_);

    web_media_source_ = std::move(web_media_source);
  }

  SetReadyState(ReadyState::kOpen);
}

double MediaSource::GetDuration_Locked(
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) const {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  if (IsClosed()) {
    return std::numeric_limits<float>::quiet_NaN();
  }

  return web_media_source_->Duration();
}

WebTimeRanges MediaSource::BufferedInternal(
    MediaSourceAttachmentSupplement::ExclusiveKey pass_key) const {
  AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // Implements MediaSource algorithm for HTMLMediaElement.buffered.
  // https://dvcs.w3.org/hg/html-media/raw-file/default/media-source/media-source.html#htmlmediaelement-extensions
  Vector<WebTimeRanges> ranges(active_source_buffers_->length());

  for (unsigned i = 0; i < active_source_buffers_->length(); ++i) {
    active_source_buffers_->item(i)->GetBuffered_Locked(&ranges[i],
```
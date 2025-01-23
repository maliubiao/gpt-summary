Response:
The user wants to understand the functionality of the `source_buffer.cc` file in the Chromium Blink engine. I need to extract the core responsibilities of this file and explain its interactions with web technologies like JavaScript, HTML, and CSS. I should also provide examples of logical reasoning within the code, common user errors, and how a user's actions can lead to the execution of this code. Finally, I need to summarize the file's purpose.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The file name "source_buffer.cc" immediately suggests it's related to the `SourceBuffer` interface in the Media Source Extensions (MSE) API. Reading the initial comments and includes confirms this. The primary purpose seems to be managing the buffering of media data.

2. **Relate to Web Technologies:**
    * **JavaScript:** The `SourceBuffer` API is directly accessible and manipulated via JavaScript. Methods like `appendBuffer`, `remove`, `changeType`, and properties like `mode`, `timestampOffset`, `buffered`, etc., are JavaScript interfaces. The code includes V8 bindings (`third_party/blink/renderer/bindings/core/v8/...`) which facilitate this interaction.
    * **HTML:** The `SourceBuffer` is associated with a `<video>` or `<audio>` element through the `MediaSource` API. The buffered data is eventually rendered by these HTML elements. The code includes references to `HTMLMediaElement`.
    * **CSS:** While CSS doesn't directly interact with `SourceBuffer`'s core logic, CSS styles the media elements that display the buffered content. It's a less direct relationship than JavaScript and HTML.

3. **Identify Logical Reasoning (Assumptions, Inputs, and Outputs):**
    * **Input:**  The `appendBuffer` methods take `ArrayBuffer` or `ArrayBufferView` as input, representing media data. The `remove` method takes start and end times. The setters for properties like `timestampOffset` and `appendWindowStart` take numerical values. The `appendEncodedChunks` method takes `EncodedAudioChunk` and `EncodedVideoChunk` objects.
    * **Assumptions/Logic:** The code checks for valid states (e.g., not removed, not currently updating) before performing actions. It validates input parameters (e.g., ranges for `remove`, values for `appendWindowStart`). It handles different append modes (`segments`, `sequence`). It interacts with the underlying media pipeline to actually buffer the data.
    * **Output:** The `buffered` property returns a `TimeRanges` object. Operations like `appendBuffer` and `remove` can trigger events (like 'updateend', 'error'). Setting properties can change the internal state of the `SourceBuffer`. `appendEncodedChunks` returns a Promise.

4. **Identify Common User Errors:**
    * Appending data while the `SourceBuffer` is already updating.
    * Calling methods on a `SourceBuffer` that has been removed from the `MediaSource`.
    * Providing invalid values for properties like `appendWindowStart` or `appendWindowEnd`.
    * Appending data of an incorrect type or format.
    * Incorrectly using `appendEncodedChunks` without the required duration for video chunks.

5. **Describe User Actions Leading to Code Execution:**
    * A user interacts with a web page that uses the MSE API.
    * JavaScript code creates a `MediaSource` object and adds `SourceBuffer` objects to it.
    * The JavaScript code fetches media data (e.g., from a network request).
    * The JavaScript code calls `sourceBuffer.appendBuffer(data)` or `sourceBuffer.appendEncodedChunks(chunks)` to feed the media data to the buffer.
    * The JavaScript code might call `sourceBuffer.remove(startTime, endTime)` to remove buffered data.
    * The JavaScript code might set properties like `sourceBuffer.mode = 'sequence'` or `sourceBuffer.timestampOffset = 10`.

6. **Summarize the Functionality:** Combine the identified core functionality, interactions, and key methods into a concise summary.

7. **Structure the Response:** Organize the information into clear sections with headings for better readability. Use code snippets and examples where appropriate.

**(Self-Correction/Refinement):** Initially, I might have focused too much on the low-level details of the C++ code. I need to keep the focus on the *functionality* from a user's perspective and how it relates to the web APIs. Also, explicitly stating the assumptions and logic within the code makes the explanation clearer. Emphasizing the connection between JavaScript API calls and the C++ implementation is crucial. The distinction between `appendBuffer` and `appendEncodedChunks` needs to be clarified, highlighting the WebCodecs integration.
这是 `blink/renderer/modules/mediasource/source_buffer.cc` 文件的第一部分，它主要负责实现 **SourceBuffer** 接口的功能。`SourceBuffer` 是 Media Source Extensions (MSE) API 的核心组件，允许 JavaScript 将媒体数据块添加到 HTML `<video>` 或 `<audio>` 元素中进行播放。

**主要功能归纳 (基于提供的第一部分代码):**

1. **管理媒体数据的缓冲:** `SourceBuffer` 负责接收、存储和管理即将被媒体元素播放的媒体数据。它内部使用 `WebSourceBuffer` (一个平台相关的接口) 来实际处理底层的缓冲操作。

2. **处理 `appendBuffer` 操作:**  实现了 `appendBuffer` 方法，该方法允许 JavaScript 代码将 `ArrayBuffer` 或 `ArrayBufferView` 形式的媒体数据添加到缓冲区中。这是最基本的向 `SourceBuffer` 提供数据的方式。

3. **处理 `appendEncodedChunks` 操作 (WebCodecs 集成):**  引入了 `appendEncodedChunks` 方法，允许 JavaScript 代码添加 `EncodedAudioChunk` 和 `EncodedVideoChunk` 对象（来自 WebCodecs API）到缓冲区。这标志着 MSE 与 WebCodecs 的集成，使得直接处理编码后的媒体数据成为可能。

4. **管理 `mode` 属性:**  实现了 `mode` 属性的设置，该属性控制着向 `SourceBuffer` 添加数据的模式，可以是 "segments" (默认) 或 "sequence"。 "sequence" 模式会影响时间戳的处理。

5. **管理 `timestampOffset` 属性:** 允许 JavaScript 代码设置 `timestampOffset` 属性，用于调整添加到缓冲区的媒体数据的时间戳。

6. **管理 `appendWindowStart` 和 `appendWindowEnd` 属性:**  实现了这两个属性的设置，用于定义添加到缓冲区的媒体数据的有效时间范围。任何超出此范围的数据都将被忽略。

7. **提供 `buffered` 属性:**  实现了 `buffered` 属性，该属性返回一个 `TimeRanges` 对象，表示当前 `SourceBuffer` 中已缓冲的媒体时间范围。

8. **管理 `audioTracks` 和 `videoTracks` 属性:** 提供了对 `AudioTrackList` 和 `VideoTrackList` 的访问，用于检查和操作媒体流中的音轨和视频轨。

9. **状态管理和错误处理:**  代码中包含了一些状态检查，例如检查 `SourceBuffer` 是否已被移除或正在进行更新操作 (`updating_`)，并在这些情况下抛出异常。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** `SourceBuffer` 是一个 JavaScript 可交互的对象。所有与数据添加、删除、状态查询相关的操作都通过 JavaScript API 完成。
    * **举例:**
        ```javascript
        const mediaSource = new MediaSource();
        const video = document.querySelector('video');
        video.src = URL.createObjectURL(mediaSource);

        mediaSource.addEventListener('sourceopen', () => {
          const sourceBuffer = mediaSource.addSourceBuffer('video/mp4; codecs="avc1.42E01E"');
          fetch('segment.mp4')
            .then(response => response.arrayBuffer())
            .then(data => sourceBuffer.appendBuffer(data)); // JavaScript 调用 appendBuffer
        });

        // 使用 appendEncodedChunks (需要 WebCodecs API)
        const decoder = new VideoDecoder({...});
        decoder.decode(new EncodedVideoChunk({...}));
        ```

* **HTML:** `SourceBuffer` 最终关联到 HTML 的 `<video>` 或 `<audio>` 元素。添加到 `SourceBuffer` 的媒体数据会被这些元素渲染和播放。
    * **举例:** 上面的 JavaScript 代码中，`document.querySelector('video')` 获取了 HTML 中的 `<video>` 元素，并将 `MediaSource` 对象与之关联。

* **CSS:** CSS 主要负责控制 HTML 媒体元素的外观和布局，与 `SourceBuffer` 的核心功能没有直接的逻辑关系。但是，用户可以通过 CSS 来控制视频播放器的大小、样式等。

**逻辑推理的假设输入与输出:**

* **假设输入 (设置 `appendWindowStart`):** JavaScript 代码调用 `sourceBuffer.appendWindowStart = 10;`
* **逻辑推理:** 代码会检查 `SourceBuffer` 的状态（是否被移除，是否正在更新）。然后检查新值 `10` 是否在有效范围内 (>= 0 且 < `appendWindowEnd`)。
* **输出:** 如果输入有效，`appendWindowStart_` 内部变量会被更新，并且底层 `web_source_buffer_` 的 `AppendWindowStart` 会被调用。如果输入无效，会抛出一个 `TypeError` 异常。

* **假设输入 (调用 `buffered`):** JavaScript 代码访问 `sourceBuffer.buffered`.
* **逻辑推理:** 代码会检查 `SourceBuffer` 是否已被移除。
* **输出:** 如果未被移除，代码会调用底层 `web_source_buffer_->Buffered()` 获取当前缓冲的时间范围，并将其封装成一个 `TimeRanges` 对象返回给 JavaScript。

**涉及用户或编程常见的使用错误:**

1. **在 `SourceBuffer` 正在更新时调用方法:**
   * **错误示例:**
     ```javascript
     sourceBuffer.appendBuffer(data1);
     sourceBuffer.appendBuffer(data2); // 如果 data1 的 append 操作还未完成，会抛出异常
     ```
   * **说明:** 用户或程序员需要在 `updateend` 事件触发后才能进行下一次操作。

2. **在 `SourceBuffer` 被移除后调用方法:**
   * **错误示例:**
     ```javascript
     mediaSource.removeSourceBuffer(sourceBuffer);
     sourceBuffer.appendBuffer(data); // 此时 sourceBuffer 已经无效，会抛出异常
     ```
   * **说明:**  一旦 `SourceBuffer` 从 `MediaSource` 中移除，就不能再对其进行操作。

3. **提供无效的 `appendWindowStart` 或 `appendWindowEnd` 值:**
   * **错误示例:**
     ```javascript
     sourceBuffer.appendWindowStart = -1; // 小于 0
     sourceBuffer.appendWindowStart = sourceBuffer.appendWindowEnd; // 大于等于 appendWindowEnd
     ```
   * **说明:**  这些属性的值必须满足一定的范围限制。

4. **`appendEncodedChunks` 缺少必要的 duration:**
   * **错误示例 (对于视频):**
     ```javascript
     const videoChunk = new EncodedVideoChunk({
       type: 'key',
       timestamp: 0,
       data: new Uint8Array(...)
       // 缺少 duration 属性
     });
     sourceBuffer.appendEncodedChunks(videoChunk); // 会抛出 TypeError
     ```
   * **说明:**  使用 `appendEncodedChunks` 时，特别是对于视频块，`duration` 属性是必需的。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户访问一个包含 `<video>` 或 `<audio>` 元素的网页，并且该网页使用了 Media Source Extensions API。**
2. **JavaScript 代码创建了一个 `MediaSource` 对象。**
3. **JavaScript 代码调用 `mediaSource.addSourceBuffer(mimeType)` 创建了一个 `SourceBuffer` 对象。**  这会实例化 `SourceBuffer` 类。
4. **JavaScript 代码发起网络请求或其他方式获取媒体数据。**
5. **JavaScript 代码将获取到的媒体数据（`ArrayBuffer` 或 `ArrayBufferView`）传递给 `sourceBuffer.appendBuffer(data)`。**  这将触发 `SourceBuffer::appendBuffer` 方法的执行。
6. **或者，如果网页使用了 WebCodecs API，JavaScript 代码可能会创建 `EncodedAudioChunk` 或 `EncodedVideoChunk` 对象，并调用 `sourceBuffer.appendEncodedChunks(chunks)`。** 这将触发 `SourceBuffer::appendEncodedChunks` 方法的执行。
7. **用户可能与播放器交互，导致 JavaScript 代码需要调整 `timestampOffset`、`appendWindowStart` 或 `appendWindowEnd` 等属性。** 这些操作会调用相应的 setter 方法。
8. **当需要知道当前缓冲的范围时，JavaScript 代码会访问 `sourceBuffer.buffered` 属性。** 这会调用 `SourceBuffer::buffered` 方法。

通过跟踪这些步骤，开发者可以理解用户操作如何触发 `source_buffer.cc` 中的代码执行，从而进行调试。例如，如果在添加数据时出现问题，可以检查 `appendBuffer` 方法的执行流程和相关状态。如果缓冲范围不正确，可以查看 `buffered` 方法的实现。

### 提示词
```
这是目录为blink/renderer/modules/mediasource/source_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/mediasource/source_buffer.h"

#include <limits>
#include <memory>
#include <sstream>
#include <tuple>
#include <utility>

#include "base/numerics/checked_math.h"
#include "media/base/logging_override_if_enabled.h"
#include "media/base/stream_parser_buffer.h"
#include "partition_alloc/partition_alloc.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_source_buffer.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_source_buffer_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_encodedaudiochunk_encodedaudiochunkorencodedvideochunksequence_encodedvideochunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_encodedaudiochunk_encodedvideochunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_queue.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/time_ranges.h"
#include "third_party/blink/renderer/core/html/track/audio_track.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/mediasource/media_source.h"
#include "third_party/blink/renderer/modules/mediasource/source_buffer_track_base_supplement.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_audio_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/network/mime/content_type.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partition_allocator.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

using blink::WebSourceBuffer;

namespace blink {

namespace {

static bool ThrowExceptionIfRemovedOrUpdating(bool is_removed,
                                              bool is_updating,
                                              ExceptionState& exception_state) {
  if (is_removed) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "This SourceBuffer has been removed from the parent media source.");
    return true;
  }
  if (is_updating) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "This SourceBuffer is still processing an 'appendBuffer' or "
        "'remove' operation.");
    return true;
  }

  return false;
}

WTF::String WebTimeRangesToString(const WebTimeRanges& ranges) {
  StringBuilder string_builder;
  string_builder.Append('{');
  for (auto& r : ranges) {
    string_builder.Append(" [");
    string_builder.AppendNumber(r.start);
    string_builder.Append(';');
    string_builder.AppendNumber(r.end);
    string_builder.Append(']');
  }
  string_builder.Append(" }");
  return string_builder.ToString();
}

// These track IDs are used as to differentiate tracks within a SourceBuffer.
// They can be duplicated across SourceBuffers, since these are not the
// TrackList identifiers exposed to the web app; these are instead equivalents
// of bytestream format's in-band track identifiers.
// TODO(crbug.com/1144908): Consider standardizing these especially if
// TrackDefaults makes a return to MSE spec, so that apps can provide
// name/label/kind/etc metadata for tracks originating from appended WebCodecs
// chunks.
// TODO(crbug.com/1144908): Since these must be identical to those generated
// in the underlying WebCodecsEncodedChunkStreamParser, consider moving these
// to possibly stream_parser.h. Meanwhile, must be kept in sync with similar
// constexpr in that parser manually.
constexpr media::StreamParser::TrackId kWebCodecsAudioTrackId = 1;
constexpr media::StreamParser::TrackId kWebCodecsVideoTrackId = 2;

// TODO(crbug.com/1144908): Move these converters into a WebCodecs decoder
// helper abstraction. Beyond reuse (instead of copying the various
// MakeDecoderBuffer methods), that will also help enable buffering h264 where
// bitstream conversion might be necessary during conversion.
// Note, caller updates results further as necessary (e.g. duration, DTS, etc).
scoped_refptr<media::StreamParserBuffer> MakeAudioStreamParserBuffer(
    const EncodedAudioChunk& audio_chunk) {
  // TODO(crbug.com/1144908): DecoderBuffer takes size_t size, but
  // StreamParserBuffer takes int. Fix this. For now, checked_cast is used.
  // TODO(crbug.com/1144908): Add a way for StreamParserBuffer to share the
  // same underlying DecoderBuffer.
  auto stream_parser_buffer = media::StreamParserBuffer::CopyFrom(
      audio_chunk.buffer()->data(),
      base::checked_cast<int>(audio_chunk.buffer()->size()),
      audio_chunk.buffer()->is_key_frame(), media::DemuxerStream::AUDIO,
      kWebCodecsAudioTrackId);

  // Currently, we do not populate any side_data in these converters.
  DCHECK(!stream_parser_buffer->has_side_data());

  stream_parser_buffer->set_timestamp(audio_chunk.buffer()->timestamp());
  // TODO(crbug.com/1144908): Get EncodedAudioChunk to have an optional duration
  // attribute, and require it to be populated for use by MSE-for-WebCodecs,
  // here. For initial prototype, hard-coded 22ms is used as estimated duration.
  stream_parser_buffer->set_duration(base::Milliseconds(22));
  stream_parser_buffer->set_is_duration_estimated(true);
  return stream_parser_buffer;
}

// Caller must verify that video_chunk.duration().has_value().
scoped_refptr<media::StreamParserBuffer> MakeVideoStreamParserBuffer(
    const EncodedVideoChunk& video_chunk) {
  // TODO(crbug.com/1144908): DecoderBuffer takes size_t size, but
  // StreamParserBuffer takes int. Fix this. For now, checked_cast is used.
  // TODO(crbug.com/1144908): Add a way for StreamParserBuffer to share the
  // same underlying DecoderBuffer.
  auto stream_parser_buffer = media::StreamParserBuffer::CopyFrom(
      video_chunk.buffer()->data(),
      base::checked_cast<int>(video_chunk.buffer()->size()),
      video_chunk.buffer()->is_key_frame(), media::DemuxerStream::VIDEO,
      kWebCodecsVideoTrackId);

  // Currently, we do not populate any side_data in these converters.
  DCHECK(!stream_parser_buffer->has_side_data());

  stream_parser_buffer->set_timestamp(video_chunk.buffer()->timestamp());
  // TODO(crbug.com/1144908): Get EncodedVideoChunk to have an optional decode
  // timestamp attribute. If it is populated, use it for the DTS of the
  // StreamParserBuffer, here. For initial prototype, only in-order PTS==DTS
  // chunks are supported. Out-of-order chunks may result in buffered range gaps
  // or decode errors.
  DCHECK(video_chunk.duration().has_value());
  stream_parser_buffer->set_duration(video_chunk.buffer()->duration());

  if (video_chunk.buffer()->decrypt_config()) {
    stream_parser_buffer->set_decrypt_config(
        video_chunk.buffer()->decrypt_config()->Clone());
  }
  return stream_parser_buffer;
}

}  // namespace

SourceBuffer::SourceBuffer(std::unique_ptr<WebSourceBuffer> web_source_buffer,
                           MediaSource* source,
                           EventQueue* async_event_queue)
    : ActiveScriptWrappable<SourceBuffer>({}),
      ExecutionContextLifecycleObserver(source->GetExecutionContext()),
      web_source_buffer_(std::move(web_source_buffer)),
      source_(source),
      track_defaults_(MakeGarbageCollected<TrackDefaultList>()),
      async_event_queue_(async_event_queue),
      updating_(false),
      timestamp_offset_(0),
      append_window_start_(0),
      append_window_end_(std::numeric_limits<double>::infinity()),
      first_initialization_segment_received_(false),
      pending_remove_start_(-1),
      pending_remove_end_(-1) {
  DVLOG(1) << __func__ << " this=" << this;

  DCHECK(web_source_buffer_);
  DCHECK(source_);

  auto [attachment, tracer] = source_->AttachmentAndTracer();
  DCHECK(attachment);

  if (GetExecutionContext()->IsWindow()) {
    DCHECK(IsMainThread());
    DCHECK(tracer);  // Same-thread attachments must use a tracer.

    // Have the attachment construct our audio and video tracklist members for
    // us, since it knows how to do this with knowledge of the attached media
    // element.
    audio_tracks_ = attachment->CreateAudioTrackList(tracer);
    DCHECK(audio_tracks_);
    video_tracks_ = attachment->CreateVideoTrackList(tracer);
    DCHECK(video_tracks_);
  } else {
    DCHECK(GetExecutionContext()->IsDedicatedWorkerGlobalScope());
    DCHECK(!IsMainThread());

    // TODO(https://crbug.com/878133): Enable construction of media tracks that
    // don't reference the media element if, for instance, they are owned by a
    // different execution context. For now, AudioVideoTracks experimental
    // feature implementation is not complete when MediaSource is in worker.
    DCHECK(!audio_tracks_);
    DCHECK(!video_tracks_);
  }

  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();
  web_source_buffer_->SetClient(this);
}

SourceBuffer::~SourceBuffer() {
  DVLOG(1) << __func__ << " this=" << this;
}

void SourceBuffer::Dispose() {
  // Promptly clears a raw reference from content/ to an on-heap object
  // so that content/ doesn't access it in a lazy sweeping phase.
  web_source_buffer_.reset();
}

void SourceBuffer::setMode(const V8AppendMode& new_mode,
                           ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " new_mode=" << new_mode.AsCStr();

  // Section 3.1 On setting mode attribute steps.
  // https://www.w3.org/TR/media-source/#dom-sourcebuffer-mode
  // 1. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source, then throw an INVALID_STATE_ERR exception and abort
  //    these steps.
  // 2. If the updating attribute equals true, then throw an INVALID_STATE_ERR
  //    exception and abort these steps.
  // 3. Let new mode equal the new value being assigned to this attribute.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must have |source_| and |source_| must have an attachment
  // because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &SourceBuffer::SetMode_Locked, WrapPersistent(this),
          new_mode.AsEnum(), WTF::Unretained(&exception_state)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::SetMode_Locked(
    V8AppendMode::Enum new_mode,
    ExceptionState* exception_state,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 4. If generate timestamps flag equals true and new mode equals "segments",
  //    then throw a TypeError exception and abort these steps.
  if (web_source_buffer_->GetGenerateTimestampsFlag() &&
      new_mode == V8AppendMode::Enum::kSegments) {
    MediaSource::LogAndThrowTypeError(
        *exception_state,
        "The mode value provided (segments) is invalid for a byte stream "
        "format that uses generated timestamps.");
    return;
  }

  // 5. If the readyState attribute of the parent media source is in the "ended"
  //    state then run the following steps:
  // 5.1 Set the readyState attribute of the parent media source to "open"
  // 5.2 Queue a task to fire a simple event named sourceopen at the parent
  //     media source.
  source_->OpenIfInEndedState();

  // 6. If the append state equals PARSING_MEDIA_SEGMENT, then throw an
  //    INVALID_STATE_ERR and abort these steps.
  // 7. If the new mode equals "sequence", then set the group start timestamp to
  //    the highest presentation end timestamp.
  WebSourceBuffer::AppendMode append_mode =
      WebSourceBuffer::kAppendModeSegments;
  if (new_mode == V8AppendMode::Enum::kSequence) {
    append_mode = WebSourceBuffer::kAppendModeSequence;
  }
  if (!web_source_buffer_->SetMode(append_mode)) {
    MediaSource::LogAndThrowDOMException(
        *exception_state, DOMExceptionCode::kInvalidStateError,
        "The mode may not be set while the SourceBuffer's append state is "
        "'PARSING_MEDIA_SEGMENT'.");
    return;
  }

  // 8. Update the attribute to new mode.
  mode_ = new_mode;
}

TimeRanges* SourceBuffer::buffered(ExceptionState& exception_state) const {
  // Section 3.1 buffered attribute steps.
  // 1. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source then throw an InvalidStateError exception and abort
  //    these steps.
  if (IsRemoved()) {
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "This SourceBuffer has been removed from the parent media source.");
    return nullptr;
  }

  // Obtain the current buffered ranges only if attachment is usable and
  // underlying demuxer is protected from destruction (applicable especially for
  // MSE-in-Worker case). Note, we must have |source_| and |source_| must have
  // an attachment because !IsRemoved().
  WebTimeRanges ranges;
  if (!source_->RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&SourceBuffer::GetBuffered_Locked, WrapPersistent(this),
                        WTF::Unretained(&ranges)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
    return nullptr;
  }

  // 2. Return a new static normalized TimeRanges object for the media segments
  //    buffered.
  return MakeGarbageCollected<TimeRanges>(ranges);
}

void SourceBuffer::GetBuffered_Locked(
    WebTimeRanges* ranges /* out parameter */,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) const {
  DCHECK(!IsRemoved());
  DCHECK(ranges);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  *ranges = web_source_buffer_->Buffered();
}

double SourceBuffer::timestampOffset() const {
  return timestamp_offset_;
}

void SourceBuffer::setTimestampOffset(double offset,
                                      ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " offset=" << offset;
  // Section 3.1 timestampOffset attribute setter steps.
  // https://dvcs.w3.org/hg/html-media/raw-file/tip/media-source/media-source.html#widl-SourceBuffer-timestampOffset
  // 1. Let new timestamp offset equal the new value being assigned to this
  //    attribute.
  // 2. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source, then throw an InvalidStateError exception and abort
  //    these steps.
  // 3. If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // Do the remainder of steps only if attachment is usable and underlying
  // demuxer is protected from destruction (applicable especially for
  // MSE-in-Worker case). Note, we must have |source_| and |source_| must have
  // an attachment because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &SourceBuffer::SetTimestampOffset_Locked, WrapPersistent(this),
          offset, WTF::Unretained(&exception_state)))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::SetTimestampOffset_Locked(
    double offset,
    ExceptionState* exception_state,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 4. If the readyState attribute of the parent media source is in the "ended"
  //    state then run the following steps:
  // 4.1 Set the readyState attribute of the parent media source to "open"
  // 4.2 Queue a task to fire a simple event named sourceopen at the parent
  //     media source.
  source_->OpenIfInEndedState();

  // 5. If the append state equals PARSING_MEDIA_SEGMENT, then throw an
  //    INVALID_STATE_ERR and abort these steps.
  // 6. If the mode attribute equals "sequence", then set the group start
  //    timestamp to new timestamp offset.
  if (!web_source_buffer_->SetTimestampOffset(offset)) {
    MediaSource::LogAndThrowDOMException(
        *exception_state, DOMExceptionCode::kInvalidStateError,
        "The timestamp offset may not be set while the SourceBuffer's append "
        "state is 'PARSING_MEDIA_SEGMENT'.");
    return;
  }

  // 7. Update the attribute to new timestamp offset.
  timestamp_offset_ = offset;
}

AudioTrackList& SourceBuffer::audioTracks() {
  // TODO(https://crbug.com/878133): Complete the AudioVideoTracks function
  // necessary to enable successful experimental usage of it when MSE is in
  // worker. Note that if this is consulted as part of parent |source_|'s
  // context destruction, then we cannot consult GetExecutionContext() here.
  CHECK(IsMainThread());

  return *audio_tracks_;
}

VideoTrackList& SourceBuffer::videoTracks() {
  // TODO(https://crbug.com/878133): Complete the AudioVideoTracks function
  // necessary to enable successful experimental usage of it when MSE is in
  // worker. Note that if this is consulted as part of parent |source_|'s
  // context destruction, then we cannot consult GetExecutionContext() here.
  CHECK(IsMainThread());

  return *video_tracks_;
}

double SourceBuffer::appendWindowStart() const {
  return append_window_start_;
}

void SourceBuffer::setAppendWindowStart(double start,
                                        ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " start=" << start;
  // Section 3.1 appendWindowStart attribute setter steps.
  // https://www.w3.org/TR/media-source/#widl-SourceBuffer-appendWindowStart
  // 1. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source then throw an InvalidStateError exception and abort
  //    these steps.
  // 2. If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // 3. If the new value is less than 0 or greater than or equal to
  //    appendWindowEnd then throw a TypeError exception and abort these steps.
  if (start < 0 || start >= append_window_end_) {
    MediaSource::LogAndThrowTypeError(
        exception_state,
        ExceptionMessages::IndexOutsideRange(
            "value", start, 0.0, ExceptionMessages::kExclusiveBound,
            append_window_end_, ExceptionMessages::kInclusiveBound));
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must have |source_| and |source_| must have an attachment
  // because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&SourceBuffer::SetAppendWindowStart_Locked,
                        WrapPersistent(this), start))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::SetAppendWindowStart_Locked(
    double start,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 4. Update the attribute to the new value.
  web_source_buffer_->SetAppendWindowStart(start);
  append_window_start_ = start;
}

double SourceBuffer::appendWindowEnd() const {
  return append_window_end_;
}

void SourceBuffer::setAppendWindowEnd(double end,
                                      ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " end=" << end;
  // Section 3.1 appendWindowEnd attribute setter steps.
  // https://www.w3.org/TR/media-source/#widl-SourceBuffer-appendWindowEnd
  // 1. If this object has been removed from the sourceBuffers attribute of the
  //    parent media source then throw an InvalidStateError exception and abort
  //    these steps.
  // 2. If the updating attribute equals true, then throw an InvalidStateError
  //    exception and abort these steps.
  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    return;
  }

  // 3. If the new value equals NaN, then throw a TypeError and abort these
  //    steps.
  if (std::isnan(end)) {
    MediaSource::LogAndThrowTypeError(exception_state,
                                      ExceptionMessages::NotAFiniteNumber(end));
    return;
  }
  // 4. If the new value is less than or equal to appendWindowStart then throw a
  //    TypeError exception and abort these steps.
  if (end <= append_window_start_) {
    MediaSource::LogAndThrowTypeError(
        exception_state, ExceptionMessages::IndexExceedsMinimumBound(
                             "value", end, append_window_start_));
    return;
  }

  // Do remainder of steps only if attachment is usable and underlying demuxer
  // is protected from destruction (applicable especially for MSE-in-Worker
  // case). Note, we must have |source_| and |source_| must have an attachment
  // because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(
          WTF::BindOnce(&SourceBuffer::SetAppendWindowEnd_Locked,
                        WrapPersistent(this), end))) {
    // TODO(https://crbug.com/878133): Determine in specification what the
    // specific, app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
  }
}

void SourceBuffer::SetAppendWindowEnd_Locked(
    double end,
    MediaSourceAttachmentSupplement::ExclusiveKey /* passkey */) {
  DCHECK(source_);
  DCHECK(!updating_);
  source_->AssertAttachmentsMutexHeldIfCrossThreadForDebugging();

  // 5. Update the attribute to the new value.
  web_source_buffer_->SetAppendWindowEnd(end);
  append_window_end_ = end;
}

void SourceBuffer::appendBuffer(DOMArrayBuffer* data,
                                ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this << " size=" << data->ByteLength();
  // Section 3.2 appendBuffer()
  // https://dvcs.w3.org/hg/html-media/raw-file/default/media-source/media-source.html#widl-SourceBuffer-appendBuffer-void-ArrayBufferView-data
  AppendBufferInternal(data->ByteSpan(), exception_state);
}

void SourceBuffer::appendBuffer(NotShared<DOMArrayBufferView> data,
                                ExceptionState& exception_state) {
  DVLOG(3) << __func__ << " this=" << this << " size=" << data->byteLength();
  // Section 3.2 appendBuffer()
  // https://dvcs.w3.org/hg/html-media/raw-file/default/media-source/media-source.html#widl-SourceBuffer-appendBuffer-void-ArrayBufferView-data
  AppendBufferInternal(data->ByteSpan(), exception_state);
}

// Note that |chunks| may be a sequence of mixed audio and video encoded chunks
// (which should cause underlying buffering validation to emit error akin to
// appending video to an audio track or vice-versa). It was impossible to get
// the bindings generator to disambiguate sequence<audio> vs sequence<video>,
// hence we could not use simple overloading in the IDL for these two. Neither
// could the IDL union attempt similar. We must enforce that semantic in
// implementation. Further note, |chunks| may instead be a single audio or a
// single video chunk as a helpful additional overload for one-chunk-at-a-time
// append use-cases.
ScriptPromise<IDLUndefined> SourceBuffer::appendEncodedChunks(
    ScriptState* script_state,
    const V8EncodedChunks* chunks,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__ << " this=" << this;

  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kMediaSourceExtensionsForWebCodecs);

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(
      "media", "SourceBuffer::appendEncodedChunks", TRACE_ID_LOCAL(this));

  if (ThrowExceptionIfRemovedOrUpdating(IsRemoved(), updating_,
                                        exception_state)) {
    TRACE_EVENT_NESTABLE_ASYNC_END0(
        "media", "SourceBuffer::appendEncodedChunks", TRACE_ID_LOCAL(this));
    return EmptyPromise();
  }

  // Convert |chunks| to a StreamParser::BufferQueue.
  // TODO(crbug.com/1144908): Support out-of-order DTS vs PTS sequences. For
  // now, PTS is assumed to be DTS (as is common in some formats like WebM).
  // TODO(crbug.com/1144908): Add optional EncodedAudioChunk duration attribute
  // and require it to be populated for use with MSE. For now, all audio chunks
  // are estimated.
  DCHECK(!pending_chunks_to_buffer_);
  auto buffer_queue = std::make_unique<media::StreamParser::BufferQueue>();
  size_t size = 0;

  switch (chunks->GetContentType()) {
    case V8EncodedChunks::ContentType::kEncodedAudioChunk:
      buffer_queue->emplace_back(
          MakeAudioStreamParserBuffer(*(chunks->GetAsEncodedAudioChunk())));
      size += buffer_queue->back()->size();
      break;
    case V8EncodedChunks::ContentType::kEncodedVideoChunk: {
      const auto& video_chunk = *(chunks->GetAsEncodedVideoChunk());
      if (!video_chunk.duration().has_value()) {
        MediaSource::LogAndThrowTypeError(
            exception_state,
            "EncodedVideoChunk is missing duration, required for use with "
            "SourceBuffer.");
        return EmptyPromise();
      }
      buffer_queue->emplace_back(MakeVideoStreamParserBuffer(video_chunk));
      size += buffer_queue->back()->size();
      break;
    }
    case V8EncodedChunks::ContentType::
        kEncodedAudioChunkOrEncodedVideoChunkSequence:
      for (const auto& av_chunk :
           chunks->GetAsEncodedAudioChunkOrEncodedVideoChunkSequence()) {
        DCHECK(av_chunk);
        switch (av_chunk->GetContentType()) {
          case V8UnionEncodedAudioChunkOrEncodedVideoChunk::ContentType::
              kEncodedAudioChunk:
            buffer_queue->emplace_back(MakeAudioStreamParserBuffer(
                *(av_chunk->GetAsEncodedAudioChunk())));
            size += buffer_queue->back()->size();
            break;
          case V8UnionEncodedAudioChunkOrEncodedVideoChunk::ContentType::
              kEncodedVideoChunk: {
            const auto& video_chunk = *(av_chunk->GetAsEncodedVideoChunk());
            if (!video_chunk.duration().has_value()) {
              MediaSource::LogAndThrowTypeError(
                  exception_state,
                  "EncodedVideoChunk is missing duration, required for use "
                  "with SourceBuffer.");
              return EmptyPromise();
            }
            buffer_queue->emplace_back(
                MakeVideoStreamParserBuffer(video_chunk));
            size += buffer_queue->back()->size();
            break;
          }
        }
      }
      break;
  }

  DCHECK(!append_encoded_chunks_resolver_);
  append_encoded_chunks_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  auto promise = append_encoded_chunks_resolver_->Promise();

  // Do remainder of steps of analogue of prepare append algorithm and sending
  // the |buffer_queue| to be buffered by |web_source_buffer_| asynchronously
  // only if attachment is usable and underlying demuxer is protected from
  // destruction (applicable especially for MSE-in-Worker case). Note, we must
  // have |source_| and |source_| must have an attachment because !IsRemoved().
  if (!source_->RunUnlessElementGoneOrClosingUs(WTF::BindOnce(
          &SourceBuffer::AppendEncodedChunks_Locked, WrapPersistent(this),
          std::move(buffer_queue), size, WTF::Unretained(&exception_state)))) {
    // TODO(crbug.com/878133): Determine in specification what the specific,
    // app-visible, exception should be for this case.
    MediaSource::LogAndThrowDOMException(
        exception_state, DOMExceptionCode::kInvalidStateError,
        "Worker MediaSource attachment is closing");
    append_encoded_chunks_resolver_ = nullptr;
    return EmptyPromise();
  }

  re
```
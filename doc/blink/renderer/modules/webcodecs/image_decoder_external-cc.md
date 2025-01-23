Response:
Let's break down the thought process for analyzing this Chromium source code file.

1. **Understanding the Goal:** The request asks for a functional description of `image_decoder_external.cc`, its relationship to web technologies, logical reasoning examples, common user errors, and debugging context.

2. **Initial Skim and Keywords:**  A quick read highlights keywords like "ImageDecoder", "WebCodecs", "JavaScript", "HTML", "CSS", "decode", "tracks", "promise", "stream", "ArrayBuffer". This immediately suggests the file is related to decoding images within a web browser, likely through a JavaScript API (WebCodecs).

3. **Core Functionality - Identifying the `ImageDecoderExternal` Class:** The class `ImageDecoderExternal` is central. The `Create` method indicates this is likely the entry point for creating instances. The constructor takes `ImageDecoderInit`, hinting at initialization options.

4. **Dissecting the Constructor:** The constructor's logic is crucial. It handles:
    * **Context Validation:** Checks if the execution context is valid.
    * **Feature Counting:**  `UseCounter::Count` indicates tracking usage.
    * **Data Handling:**  Crucially, it accepts image data as either a `ReadableStream` or an `ArrayBuffer/ArrayBufferView`. This is a major functional aspect.
    * **Type Support:** `IsTypeSupportedInternal` checks if the provided MIME type is valid. The exclusion of ICO/CUR is a specific detail.
    * **Decoder Core:**  The `ImageDecoderCore` is instantiated (via `SequenceBound` for thread safety). This suggests the actual decoding logic resides elsewhere.
    * **Asynchronous Operations:**  The use of `ThreadPool::CreateSequencedTaskRunner` and `SequenceBound` strongly implies asynchronous operations. Promises are used for signaling completion.

5. **Analyzing Key Methods:**
    * **`isTypeSupported`:** A static method directly exposing the type checking functionality to JavaScript.
    * **`decode`:** This is the core decoding method, taking `ImageDecodeOptions` and returning a `Promise` of `ImageDecodeResult`. This ties directly to the JavaScript API.
    * **`tracks`:** Provides access to an `ImageTrackList`, implying support for multi-frame images (like GIFs or animated WebP) and potentially selecting specific "tracks" or layers within them.
    * **`completed`:** Returns a `Promise` that resolves when all image data has been processed.
    * **`reset`:** Handles aborting ongoing decoding operations.
    * **`close`:**  Releases resources and cancels ongoing operations.
    * **`OnStateChange`:** Specifically for handling `ReadableStream` data. It reads chunks of data and feeds them to the `ImageDecoderCore`.
    * **`MaybeSatisfyPendingDecodes`:**  A complex but crucial method that checks if pending decode requests can be fulfilled based on available data and decoding status.
    * **`OnDecodeReady`:**  Handles the results coming back from `ImageDecoderCore` after a decode operation.
    * **`DecodeMetadata` and `OnMetadata`:**  Deals with retrieving metadata about the image (size, frame count, etc.).

6. **Identifying Relationships with Web Technologies:**
    * **JavaScript:**  The presence of `ScriptState`, `ScriptPromise`, `V8...` types, and the structure of methods like `isTypeSupported` and `decode` clearly indicates a JavaScript API. The `ImageDecoder` interface is exposed to JavaScript.
    * **HTML:**  The decoded `VideoFrame` is likely used to update the content of an `<image>` element, a `<video>` element (if the source is animation), or a `<canvas>` element.
    * **CSS:**  While less direct, the decoded image could be used as a `background-image` in CSS. The `desiredWidth` and `desiredHeight` options in `ImageDecoderInit` could relate to how an image is scaled in CSS.

7. **Logical Reasoning Examples:** Focus on the `decode` method and its interaction with `MaybeSatisfyPendingDecodes`. Consider different scenarios:
    * **Single-frame image:**  Input data, decode called, immediate output.
    * **Multi-frame image (incomplete data):** Decode called, data arrives in chunks, decoding proceeds as data becomes available.
    * **Specific frame request:** Decode called with `frameIndex`, decoder targets that frame.
    * **Error scenarios:** Invalid MIME type, corrupted data.

8. **Common User Errors:** Think about how a developer using this API in JavaScript might make mistakes:
    * Providing an unsupported MIME type.
    * Providing a locked or disturbed `ReadableStream`.
    * Trying to decode after closing the decoder.
    * Providing no image data.
    * Incorrectly using `frameIndex` in `ImageDecodeOptions`.

9. **Debugging Context:** Trace the user's actions that would lead to this code being executed. Start from the JavaScript side:
    * Creating an `ImageDecoder` object.
    * Passing data (either a `ReadableStream` or `ArrayBuffer`) and type.
    * Calling the `decode()` method.

10. **Structuring the Answer:** Organize the findings into the requested sections: functionality, JavaScript/HTML/CSS relationship, logical reasoning, user errors, and debugging. Provide concrete examples in each section. Use clear and concise language.

11. **Refinement and Review:** After drafting the initial answer, reread the code and the request to ensure accuracy and completeness. Are there any nuances missed? Are the examples clear? Is the language precise?  For instance, initially, I might have only considered `<image>` elements, but realizing the output is a `VideoFrame` broadens the possibilities to `<video>` and `<canvas>`. Also, explicitly mentioning the asynchronous nature and the use of Promises is important.
This C++ source code file, `image_decoder_external.cc`, within the Chromium Blink rendering engine, implements the **JavaScript API for `ImageDecoder`**. This API, part of the WebCodecs suite, allows web developers to decode image data programmatically, offering more control and flexibility than traditional image loading via HTML `<img>` tags.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Exposes the `ImageDecoder` JavaScript Interface:** This file provides the underlying C++ implementation for the `ImageDecoder` class that is accessible to JavaScript.

2. **Asynchronous Image Decoding:**  It handles the asynchronous decoding of image data provided as either `ArrayBuffer`, `ArrayBufferView`, or `ReadableStream`. This ensures that decoding doesn't block the main browser thread.

3. **MIME Type Support:** It checks for supported image MIME types using `IsSupportedImageMimeType`. It explicitly disables decoding of ICO and CUR files due to their unique nature.

4. **Data Handling:**
   - **ArrayBuffer/ArrayBufferView:**  It efficiently copies or transfers data from these JavaScript data structures to the decoding thread.
   - **ReadableStream:** It consumes data from a `ReadableStream` in chunks, feeding it to the decoder incrementally.

5. **Delegates Decoding to `ImageDecoderCore`:**  The actual decoding work is delegated to the `ImageDecoderCore` class (likely residing in a different file). This separation of concerns keeps the API logic separate from the low-level decoding implementation.

6. **Manages Decoding Requests:** It queues and manages multiple decode requests, allowing developers to request specific frames or subsets of frames.

7. **Provides Image Tracks:** For multi-frame images (like GIFs or animated WebP), it exposes the concept of "tracks" via the `ImageTrackList` and `ImageTrack` classes. This allows selecting specific animated or still versions of the image.

8. **Returns Decoding Results as `VideoFrame`:** The decoded image data is returned as a `VideoFrame` object, which can then be further processed or displayed.

9. **Handles Errors:** It manages and reports errors during decoding, such as unsupported image types, invalid data, or decoding failures, using `DOMException`.

10. **Supports `completed` Promise:** It provides a `completed` promise that resolves when all image data has been processed.

11. **Supports `isTypeSupported` Static Method:** Exposes a static JavaScript method to check if a given MIME type is supported for decoding.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This file directly implements the JavaScript `ImageDecoder` API. JavaScript code interacts with `ImageDecoder` to:
    - Create an `ImageDecoder` object, providing the image data and MIME type.
    - Call the `decode()` method to initiate the decoding process.
    - Access the `tracks` property to manage animation tracks.
    - Use the `completed()` promise to know when all data is processed.
    - Handle the `Promise` returned by `decode()` to get the decoded `VideoFrame`.

    **Example:**
    ```javascript
    const imageData = await fetch('image.png').then(res => res.arrayBuffer());
    const decoder = new ImageDecoder({ type: 'image/png', data: imageData });

    decoder.decode().then(result => {
      // 'result' is an ImageDecodeResult containing the decoded VideoFrame
      console.log('Image decoded!', result.image);
    });
    ```

* **HTML:** While `ImageDecoder` doesn't directly manipulate HTML elements, the decoded `VideoFrame` obtained through this API can be used to:
    - Draw the image onto a `<canvas>` element using the `drawImage()` method.
    - Potentially be used as a source for a `<video>` element if the decoded image represents a single frame of a video. (Though this isn't the primary use case for `ImageDecoder` focusing on still/animated images).

    **Example:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    const imageData = await fetch('image.png').then(res => res.arrayBuffer());
    const decoder = new ImageDecoder({ type: 'image/png', data: imageData });

    decoder.decode().then(result => {
      const bitmap = await createImageBitmap(result.image); // Convert VideoFrame to Bitmap
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      ctx.drawImage(bitmap, 0, 0);
    });
    ```

* **CSS:**  Indirectly, the decoded image could be used as a `background-image` in CSS by first drawing it onto a canvas and then using `canvas.toDataURL()` to get a data URL. However, this is less efficient than directly using the `<img>` tag for simple image display. `ImageDecoder` is more focused on programmatic manipulation and decoding.

**Logical Reasoning Examples:**

**Scenario 1: Decoding a single PNG image.**

* **Hypothetical Input:** JavaScript code creates an `ImageDecoder` with `type: 'image/png'` and an `ArrayBuffer` containing PNG data. `decode()` is called.
* **Internal Logic:**
    1. `IsTypeSupportedInternal('image/png')` returns `true`.
    2. Data is transferred to the decoding thread.
    3. `ImageDecoderCore::DecodeMetadata` is called to get basic image information.
    4. `ImageDecoderCore::Decode` is called to decode the image data.
    5. The decoded image is wrapped in a `VideoFrame`.
    6. The `Promise` returned by `decode()` resolves with an `ImageDecodeResult` containing the `VideoFrame`.
* **Output:** The JavaScript `Promise` resolves with the decoded image data.

**Scenario 2: Decoding an animated GIF with incomplete data.**

* **Hypothetical Input:** JavaScript code creates an `ImageDecoder` with `type: 'image/gif'` and a `ReadableStream` providing GIF data in chunks. `decode()` is called before all data arrives.
* **Internal Logic:**
    1. `IsTypeSupportedInternal('image/gif')` returns `true`.
    2. `OnStateChange()` is called as data chunks arrive from the `ReadableStream`.
    3. Each chunk is appended to `ImageDecoderCore` via `AppendData()`.
    4. `DecodeMetadata()` might be called multiple times as more data becomes available, populating the `ImageTrackList`.
    5. When `decode()` is called, if not enough data for the requested frame is present, the promise might not resolve immediately.
    6. `MaybeSatisfyPendingDecodes()` will check if the pending decode request can be fulfilled with the available data.
    7. Once enough data is available for the requested frame, `ImageDecoderCore::Decode` is called.
    8. The `Promise` resolves with the decoded frame.
* **Output:** The JavaScript `Promise` resolves only when enough data is available to decode the requested frame.

**User or Programming Common Usage Errors:**

1. **Providing an unsupported MIME type:**
   - **Error:** `DOMException: The provided image type (image/webp2) is not supported`
   - **JavaScript Code:** `new ImageDecoder({ type: 'image/webp2', data: arrayBuffer });` (assuming 'image/webp2' is not supported).

2. **Providing a locked or disturbed `ReadableStream`:**
   - **Error:** `TypeError: ImageDecoder can only accept readable streams that are not yet locked to a reader`
   - **JavaScript Code:**
     ```javascript
     const stream = await fetch('image.png').then(res => res.body);
     const reader = stream.getReader();
     reader.read(); // Locking the stream
     const decoder = new ImageDecoder({ type: 'image/png', data: stream });
     ```

3. **Trying to decode after closing the decoder:**
   - **Error:** `DOMException: The decoder has been closed.`
   - **JavaScript Code:**
     ```javascript
     const decoder = new ImageDecoder({ type: 'image/png', data: arrayBuffer });
     decoder.close();
     decoder.decode().catch(e => console.error(e));
     ```

4. **Providing no image data:**
   - **Error:** `TypeError: No image data provided`
   - **JavaScript Code:** `new ImageDecoder({ type: 'image/png' });` or `new ImageDecoder({ type: 'image/png', data: null });`

5. **Accessing tracks before they are ready (for multi-frame images):**
   - **Issue:** May lead to unexpected behavior or errors if the track information hasn't been fully parsed yet. The `tracks().ready` promise should be used.
   - **JavaScript Code (incorrect):**
     ```javascript
     const decoder = new ImageDecoder({ type: 'image/gif', data: arrayBuffer });
     console.log(decoder.tracks().length); // Might be 0 initially
     ```
   - **JavaScript Code (correct):**
     ```javascript
     const decoder = new ImageDecoder({ type: 'image/gif', data: arrayBuffer });
     decoder.tracks().ready.then(() => {
       console.log(decoder.tracks().length);
     });
     ```

**User Operation Steps Leading to This Code (Debugging Clues):**

1. **User navigates to a webpage:** The user opens a webpage in the Chromium browser.
2. **JavaScript code on the page executes:** The webpage's JavaScript code uses the `ImageDecoder` API.
3. **`new ImageDecoder(...)` is called:**  The JavaScript code creates a new `ImageDecoder` object, providing the image data (as `ArrayBuffer`, `ArrayBufferView`, or a `ReadableStream`) and the image's MIME type. This call will eventually lead to the `ImageDecoderExternal::Create` method in this C++ file.
4. **`decoder.decode(...)` is called:** The JavaScript code calls the `decode()` method on the `ImageDecoder` instance, potentially with `ImageDecodeOptions` to specify a frame index or whether to decode only complete frames. This call will trigger the `ImageDecoderExternal::decode` method.
5. **Data is processed:**
   - If the data is an `ArrayBuffer` or `ArrayBufferView`, it's transferred to the decoding thread.
   - If the data is a `ReadableStream`, the `OnStateChange()` method in this file will be invoked as chunks of data are read from the stream.
6. **Decoding happens on a separate thread:** The `ImageDecoderCore` (on a background thread) performs the actual image decoding.
7. **Results are returned:** When decoding is complete (or an error occurs), the results are passed back to the main thread, and the `Promise` returned by `decode()` resolves or rejects.

**Debugging Scenario:**

If a developer encounters an issue with image decoding using the `ImageDecoder` API, they might set breakpoints in this `image_decoder_external.cc` file, particularly in:

- The `Create` method to inspect the initial setup and input parameters.
- The `decode` method to understand how decode requests are being handled.
- The `OnStateChange` method (if a `ReadableStream` is involved) to see how data is being consumed.
- The `OnDecodeReady` method to examine the results coming back from the decoder core.
- Error handling paths to understand why a decoding operation might be failing.

By stepping through the code, inspecting variables, and observing the flow of execution, developers can pinpoint the source of the problem, whether it's an issue with the provided data, the image type, or the decoding process itself. The logging statements within this file (`DVLOG`) can also provide valuable insights during debugging.

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/image_decoder_external.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/webcodecs/image_decoder_external.h"

#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/thread_pool.h"
#include "third_party/blink/public/common/mime_util/mime_util.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybufferallowshared_arraybufferviewallowshared_readablestream.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_decode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_decode_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_decoder_init.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/fetch/readable_stream_bytes_consumer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/modules/webcodecs/image_track.h"
#include "third_party/blink/renderer/modules/webcodecs/image_track_list.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_skia.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"

namespace blink {

namespace {

bool IsTypeSupportedInternal(String type) {
  if (!type.ContainsOnlyASCIIOrEmpty())
    return false;

  // Disable ICO/CUR decoding since the underlying decoder does not operate like
  // the rest of our blink::ImageDecoders. Each frame is a different sized
  // version of a single image in a BMP or PNG format. CUR files additionally
  // use the mouse position to determine which image to use.
  //
  // While we could expose each frame as a different track or use the desired
  // size provided at construction to choose a frame, the mouse position signal
  // would need further JS exposed API considerations. As such, given the
  // ancient nature of the format, it is not worth implementing at this time.
  //
  // Additionally, since the ICO/CUR formats are simple, it seems fine to allow
  // the parsing to happen in JS while decoding for the individual BMP or PNG
  // files can be done using this API.
  const auto type_lower = type.LowerASCII();
  if (type_lower == "image/x-icon" || type_lower == "image/vnd.microsoft.icon")
    return false;

  return IsSupportedImageMimeType(type.Ascii());
}

ImageDecoder::AnimationOption AnimationOptionFromIsAnimated(bool is_animated) {
  return is_animated ? ImageDecoder::AnimationOption::kPreferAnimation
                     : ImageDecoder::AnimationOption::kPreferStillImage;
}

DOMException* CreateUnsupportedImageTypeException(String type) {
  return MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotSupportedError,
      String::Format("The provided image type (%s) is not supported",
                     type.Ascii().c_str()));
}

// Helper class for ensuring memory safe usage of ArrayBufferContents by the
// ImageDecoderCore on the decoding thread.
class ArrayBufferContentsSegmentReader : public SegmentReader {
 public:
  explicit ArrayBufferContentsSegmentReader(ArrayBufferContents contents)
      : contents_(std::move(contents)),
        segment_reader_(SegmentReader::CreateFromSkData(
            SkData::MakeWithoutCopy(contents_.Data(),
                                    contents_.DataLength()))) {}

  size_t size() const override { return segment_reader_->size(); }
  base::span<const uint8_t> GetSomeData(size_t position) const override {
    return segment_reader_->GetSomeData(position);
  }
  sk_sp<SkData> GetAsSkData() const override {
    return segment_reader_->GetAsSkData();
  }

 private:
  ArrayBufferContents contents_;  // Must outlive `segment_reader_`.
  scoped_refptr<SegmentReader> segment_reader_;
};

}  // namespace

// static
ImageDecoderExternal* ImageDecoderExternal::Create(
    ScriptState* script_state,
    const ImageDecoderInit* init,
    ExceptionState& exception_state) {
  auto* result = MakeGarbageCollected<ImageDecoderExternal>(script_state, init,
                                                            exception_state);
  return exception_state.HadException() ? nullptr : result;
}

ImageDecoderExternal::DecodeRequest::DecodeRequest(
    ScriptPromiseResolver<ImageDecodeResult>* resolver,
    uint32_t frame_index,
    bool complete_frames_only)
    : resolver(resolver),
      frame_index(frame_index),
      complete_frames_only(complete_frames_only),
      abort_flag(std::make_unique<base::AtomicFlag>()) {}

ImageDecoderExternal::DecodeRequest::~DecodeRequest() {
  // This must have already been released to the decoder thread manually.
  DCHECK(!abort_flag);
}

void ImageDecoderExternal::DecodeRequest::Trace(Visitor* visitor) const {
  visitor->Trace(resolver);
  visitor->Trace(result);
  visitor->Trace(exception);
}

bool ImageDecoderExternal::DecodeRequest::IsFinal() const {
  return result || exception || range_error_message;
}

// static
ScriptPromise<IDLBoolean> ImageDecoderExternal::isTypeSupported(
    ScriptState* script_state,
    String type) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(script_state);
  auto promise = resolver->Promise();
  resolver->Resolve(IsTypeSupportedInternal(type));
  return promise;
}

ImageDecoderExternal::ImageDecoderExternal(ScriptState* script_state,
                                           const ImageDecoderInit* init,
                                           ExceptionState& exception_state)
    : ActiveScriptWrappable<ImageDecoderExternal>({}),
      ExecutionContextLifecycleObserver(ExecutionContext::From(script_state)),
      script_state_(script_state),
      tracks_(MakeGarbageCollected<ImageTrackList>(this)),
      completed_property_(
          MakeGarbageCollected<CompletedProperty>(GetExecutionContext())) {
  // ImageDecoder requires an active context to operate correctly.
  if (GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Invalid context.");
    return;
  }

  UseCounter::Count(GetExecutionContext(), WebFeature::kWebCodecs);

  // |data| is a required field.
  DCHECK(init->hasData());
  DCHECK(init->data());

  constexpr char kNoneOption[] = "none";
  auto color_behavior = ColorBehavior::kTag;
  if (init->colorSpaceConversion() == kNoneOption)
    color_behavior = ColorBehavior::kIgnore;

  auto desired_size = SkISize::MakeEmpty();
  if (init->hasDesiredWidth() && init->hasDesiredHeight())
    desired_size = SkISize::Make(init->desiredWidth(), init->desiredHeight());

  mime_type_ = init->type().LowerASCII();
  if (!IsTypeSupportedInternal(mime_type_)) {
    tracks_->OnTracksReady(CreateUnsupportedImageTypeException(mime_type_));
    return;
  }

  if (init->hasPreferAnimation()) {
    prefer_animation_ = init->preferAnimation();
    animation_option_ = AnimationOptionFromIsAnimated(*prefer_animation_);
  }

  decode_task_runner_ = base::ThreadPool::CreateSequencedTaskRunner(
      {base::TaskPriority::USER_VISIBLE,
       base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN});

  if (init->data()->IsReadableStream()) {
    if (init->data()->GetAsReadableStream()->IsLocked() ||
        init->data()->GetAsReadableStream()->IsDisturbed()) {
      exception_state.ThrowTypeError(
          "ImageDecoder can only accept readable streams that are not yet "
          "locked to a reader");
      return;
    }

    decoder_ = std::make_unique<WTF::SequenceBound<ImageDecoderCore>>(
        decode_task_runner_, mime_type_, /*data=*/nullptr,
        /*data_complete=*/false, color_behavior, desired_size,
        animation_option_);

    consumer_ = MakeGarbageCollected<ReadableStreamBytesConsumer>(
        script_state, init->data()->GetAsReadableStream());

    construction_succeeded_ = true;

    // We need one initial call to OnStateChange() to start reading, but
    // thereafter calls will be driven by the ReadableStreamBytesConsumer.
    consumer_->SetClient(this);
    OnStateChange();
    return;
  }

  base::span<const uint8_t> array_span;
  switch (init->data()->GetContentType()) {
    case V8ImageBufferSource::ContentType::kArrayBufferAllowShared:
      if (auto* buffer = init->data()->GetAsArrayBufferAllowShared()) {
        if (!buffer->IsDetached()) {
          array_span = buffer->ByteSpanMaybeShared();
        }
      }
      break;
    case V8ImageBufferSource::ContentType::kArrayBufferViewAllowShared:
      if (auto* view = init->data()->GetAsArrayBufferViewAllowShared().Get()) {
        if (!view->IsDetached()) {
          array_span = view->ByteSpanMaybeShared();
        }
      }
      break;
    case V8ImageBufferSource::ContentType::kReadableStream:
      NOTREACHED();
  }

  auto buffer_contents =
      TransferArrayBufferForSpan(init->transfer(), array_span, exception_state,
                                 script_state_->GetIsolate());
  if (exception_state.HadException()) {
    return;
  }

  if (array_span.empty()) {
    exception_state.ThrowTypeError("No image data provided");
    return;
  }

  scoped_refptr<SegmentReader> segment_reader;
  if (buffer_contents.IsValid()) {
    segment_reader = base::MakeRefCounted<ArrayBufferContentsSegmentReader>(
        std::move(buffer_contents));
  } else {
    segment_reader = SegmentReader::CreateFromSkData(
        SkData::MakeWithCopy(array_span.data(), array_span.size()));
  }

  if (!segment_reader) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Failed to read image data");
    return;
  }

  construction_succeeded_ = true;
  data_complete_ = true;
  completed_property_->ResolveWithUndefined();
  decoder_ = std::make_unique<WTF::SequenceBound<ImageDecoderCore>>(
      decode_task_runner_, mime_type_, std::move(segment_reader),
      data_complete_, color_behavior, desired_size, animation_option_);

  DecodeMetadata();
}

ImageDecoderExternal::~ImageDecoderExternal() {
  DVLOG(1) << __func__;

  if (construction_succeeded_)
    base::UmaHistogramBoolean("Blink.WebCodecs.ImageDecoder.Success", !failed_);

  DCHECK_EQ(pending_metadata_requests_, 0);
}

ScriptPromise<ImageDecodeResult> ImageDecoderExternal::decode(
    const ImageDecodeOptions* options) {
  DVLOG(1) << __func__;
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<ImageDecodeResult>>(
          script_state_);
  auto promise = resolver->Promise();

  if (closed_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "The decoder has been closed."));
    return promise;
  }

  if (!decoder_) {
    resolver->Reject(CreateUnsupportedImageTypeException(mime_type_));
    return promise;
  }

  if (!tracks_->IsEmpty() && !tracks_->selectedTrack()) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "No selected track."));
    return promise;
  }

  pending_decodes_.push_back(MakeGarbageCollected<DecodeRequest>(
      resolver, options ? options->frameIndex() : 0,
      options ? options->completeFramesOnly() : true));

  MaybeSatisfyPendingDecodes();
  return promise;
}

void ImageDecoderExternal::UpdateSelectedTrack() {
  DCHECK(!closed_);

  reset(MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError,
                                           "Aborted by track change"));

  // Track changes recreate a new decoder under the hood, so don't let stale
  // metadata updates come in for the newly selected (or no selected) track.
  weak_factory_.Invalidate();

  // TODO(crbug.com/1073995): We eventually need a formal track selection
  // mechanism. For now we can only select between the still and animated images
  // and must destruct the decoder for changes.
  if (!tracks_->selectedTrack()) {
    decoder_->AsyncCall(&ImageDecoderCore::Clear);
    return;
  }

  animation_option_ =
      AnimationOptionFromIsAnimated(tracks_->selectedTrack()->animated());

  decoder_->AsyncCall(&ImageDecoderCore::Reinitialize)
      .WithArgs(animation_option_);

  DecodeMetadata();
  MaybeSatisfyPendingDecodes();
}

String ImageDecoderExternal::type() const {
  return mime_type_;
}

bool ImageDecoderExternal::complete() const {
  return data_complete_;
}

ScriptPromise<IDLUndefined> ImageDecoderExternal::completed(
    ScriptState* script_state) {
  return completed_property_->Promise(script_state->World());
}

ImageTrackList& ImageDecoderExternal::tracks() const {
  return *tracks_;
}

void ImageDecoderExternal::reset(DOMException* exception) {
  if (!exception) {
    exception = MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kAbortError, "Aborted by reset.");
  }

  num_submitted_decodes_ = 0u;
  decode_weak_factory_.Invalidate();

  // Move all state to local variables since promise resolution is re-entrant.
  HeapVector<Member<DecodeRequest>> local_pending_decodes;
  local_pending_decodes.swap(pending_decodes_);

  for (auto& request : local_pending_decodes) {
    request->resolver->Reject(exception);
    request->abort_flag->Set();

    // Since the AtomicFlag may still be referenced by the decoder sequence, we
    // need to delete it on that sequence.
    decode_task_runner_->DeleteSoon(FROM_HERE, std::move(request->abort_flag));
  }
}

void ImageDecoderExternal::close() {
  if (closed_)
    return;

  auto* exception = MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError,
      failed_ ? "Aborted by close." : "Aborted by failure.");

  // Failure cases should have already rejected the tracks ready promise.
  if (!failed_ && decoder_ && tracks_->IsEmpty())
    tracks_->OnTracksReady(exception);

  if (!data_complete_)
    completed_property_->Reject(exception);

  CloseInternal(exception);
}

void ImageDecoderExternal::CloseInternal(DOMException* exception) {
  reset(exception);
  if (consumer_)
    consumer_->Cancel();
  weak_factory_.Invalidate();
  pending_metadata_requests_ = 0;
  consumer_ = nullptr;
  decoder_.reset();
  tracks_->Disconnect();
  mime_type_ = "";
  closed_ = true;
}

void ImageDecoderExternal::OnStateChange() {
  DCHECK(!closed_);
  DCHECK(consumer_);

  while (!internal_data_complete_) {
    base::span<const char> buffer;
    auto result = consumer_->BeginRead(buffer);
    if (result == BytesConsumer::Result::kShouldWait)
      return;

    Vector<uint8_t> data;
    if (result == BytesConsumer::Result::kOk) {
      if (!buffer.empty()) {
        data.ReserveInitialCapacity(static_cast<wtf_size_t>(buffer.size()));
        data.AppendSpan(buffer);
        bytes_read_ += buffer.size();
      }
      result = consumer_->EndRead(buffer.size());
    }

    const bool data_complete = result == BytesConsumer::Result::kDone ||
                               result == BytesConsumer::Result::kError;
    if (!buffer.empty() || data_complete != internal_data_complete_) {
      decoder_->AsyncCall(&ImageDecoderCore::AppendData)
          .WithArgs(std::move(data), data_complete);
      // Note: Requiring a selected track to DecodeMetadata() means we won't
      // resolve completed if all data comes in while there's no selected
      // track. This is intentional since if we resolve completed while there's
      // no underlying decoder, we may signal completed while the tracks have
      // out of date metadata in them.
      if (tracks_->IsEmpty() || tracks_->selectedTrack()) {
        DecodeMetadata();
        MaybeSatisfyPendingDecodes();
      }
    }
    internal_data_complete_ = data_complete;
  }
}

String ImageDecoderExternal::DebugName() const {
  return "ImageDecoderExternal";
}

void ImageDecoderExternal::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(consumer_);
  visitor->Trace(tracks_);
  visitor->Trace(pending_decodes_);
  visitor->Trace(completed_property_);
  visitor->Trace(decode_weak_factory_);
  visitor->Trace(weak_factory_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void ImageDecoderExternal::ContextDestroyed() {
  auto* exception = MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "Aborted by close.");
  CloseInternal(exception);
}

bool ImageDecoderExternal::HasPendingActivity() const {
  const bool has_pending_activity =
      !pending_decodes_.empty() || pending_metadata_requests_ > 0;
  return has_pending_activity;
}

void ImageDecoderExternal::MaybeSatisfyPendingDecodes() {
  DCHECK(!closed_);
  DCHECK(decoder_);
  DCHECK(failed_ || tracks_->IsEmpty() || tracks_->selectedTrack());

  for (auto& request : pending_decodes_) {
    if (failed_) {
      request->exception = MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kEncodingError,
          String::Format("Failed to decode frame at index %d",
                         request->frame_index));
      continue;
    }

    // Ignore already submitted requests and those already satisfied.
    if (request->pending || request->IsFinal())
      continue;

    if (!data_complete_) {
      // When data is incomplete, we must process requests one at a time since
      // we don't know if a given request can be satisfied yet and don't want to
      // fulfill requests out of order.
      if (num_submitted_decodes_ > 0u)
        break;

      // If no data has arrived since we last tried submitting this decode
      // request, do nothing until more data arrives.
      if (request->bytes_read_index && request->bytes_read_index == bytes_read_)
        break;
    }

    request->pending = true;
    request->bytes_read_index = bytes_read_;

    ++num_submitted_decodes_;
    decoder_->AsyncCall(&ImageDecoderCore::Decode)
        .WithArgs(request->frame_index, request->complete_frames_only,
                  WTF::CrossThreadUnretained(request->abort_flag.get()))
        .Then(CrossThreadBindOnce(&ImageDecoderExternal::OnDecodeReady,
                                  MakeUnwrappingCrossThreadHandle(
                                      decode_weak_factory_.GetWeakCell())));
  }

  auto new_end = std::stable_partition(
      pending_decodes_.begin(), pending_decodes_.end(),
      [](const auto& request) { return !request->IsFinal(); });

  // Copy completed requests to a new local vector to avoid reentrancy issues
  // when resolving and rejecting the promises.
  HeapVector<Member<DecodeRequest>> completed_decodes;
  completed_decodes.AppendRange(new_end, pending_decodes_.end());
  pending_decodes_.Shrink(
      static_cast<wtf_size_t>(new_end - pending_decodes_.begin()));

  // Note: Promise resolution may invoke calls into this class.
  for (auto& request : completed_decodes) {
    DCHECK(!request->abort_flag->IsSet());
    if (request->exception) {
      request->resolver->Reject(request->exception);
    } else if (request->range_error_message) {
      ScriptState::Scope scope(script_state_);
      request->resolver->Reject(V8ThrowException::CreateRangeError(
          script_state_->GetIsolate(), *request->range_error_message));
    } else {
      request->resolver->Resolve(request->result);
    }

    // Since the AtomicFlag may still be referenced by the decoder sequence, we
    // need to delete it on that sequence.
    decode_task_runner_->DeleteSoon(FROM_HERE, std::move(request->abort_flag));
  }
}

void ImageDecoderExternal::OnDecodeReady(
    std::unique_ptr<ImageDecoderCore::ImageDecodeResult> result) {
  DCHECK(decoder_);
  DCHECK(!closed_);
  DCHECK(result);
  DCHECK(!pending_decodes_.empty());

  auto& request = pending_decodes_.front();
  DCHECK_EQ(request->frame_index, result->frame_index);
  --num_submitted_decodes_;

  if (result->status == ImageDecoderCore::Status::kDecodeError || failed_) {
    SetFailed();
    return;
  }

  request->pending = false;

  // Abort always invalidates WeakCells, so OnDecodeReady() should never receive
  // the kAborted status.
  DCHECK_NE(result->status, ImageDecoderCore::Status::kAborted);

  if (result->status == ImageDecoderCore::Status::kIndexError) {
    request->range_error_message =
        ExceptionMessages::IndexOutsideRange<uint32_t>(
            "frame index", request->frame_index, 0,
            ExceptionMessages::kInclusiveBound,
            tracks_->selectedTrack()->frameCount(),
            ExceptionMessages::kExclusiveBound);
    MaybeSatisfyPendingDecodes();
    return;
  }

  // If there was nothing to decode yet or no new image, try again; this will do
  // nothing if no new data has been received since the last submitted request.
  if (result->status == ImageDecoderCore::Status::kNoImage) {
    // Once we're data complete, if no further image can be decoded, we should
    // reject the decode() since it can't be satisfied.
    if (data_complete_) {
      request->range_error_message = String::Format(
          "Unexpected end of image. Request for frame index %d "
          "can't be satisfied.",
          request->frame_index);
    }

    MaybeSatisfyPendingDecodes();
    return;
  }

  request->result = ImageDecodeResult::Create();
  request->result->setImage(
      MakeGarbageCollected<VideoFrame>(base::MakeRefCounted<VideoFrameHandle>(
          std::move(result->frame), std::move(result->sk_image))));
  request->result->setComplete(result->complete);
  MaybeSatisfyPendingDecodes();
}

void ImageDecoderExternal::DecodeMetadata() {
  DCHECK(decoder_);
  DCHECK(tracks_->IsEmpty() || tracks_->selectedTrack());

  ++pending_metadata_requests_;
  DCHECK_GE(pending_metadata_requests_, 1);

  decoder_->AsyncCall(&ImageDecoderCore::DecodeMetadata)
      .Then(CrossThreadBindOnce(
          &ImageDecoderExternal::OnMetadata,
          MakeUnwrappingCrossThreadHandle(weak_factory_.GetWeakCell())));
}

void ImageDecoderExternal::OnMetadata(
    ImageDecoderCore::ImageMetadata metadata) {
  DCHECK(decoder_);
  DCHECK(!closed_);

  --pending_metadata_requests_;
  DCHECK_GE(pending_metadata_requests_, 0);

  const bool did_complete = !data_complete_ && metadata.data_complete;

  // Set public value before resolving.
  data_complete_ = metadata.data_complete;
  if (did_complete)
    completed_property_->ResolveWithUndefined();

  if (metadata.failed || failed_) {
    SetFailed();
    return;
  }

  // If we don't have size metadata yet, don't attempt to setup the tracks since
  // we also won't have a reliable frame count. A later call to DecodeMetadata()
  // will be made as bytes come in.
  if (!metadata.has_size) {
    DCHECK(!data_complete_);
    return;
  }

  if (!tracks_->IsEmpty()) {
    tracks_->selectedTrack()->UpdateTrack(metadata.frame_count,
                                          metadata.repetition_count);
    if (did_complete)
      MaybeSatisfyPendingDecodes();
    return;
  }

  // TODO(crbug.com/1073995): None of the underlying ImageDecoders actually
  // expose tracks yet. So for now just assume a still and animated track for
  // images which declare to be multi-image and have animations.

  if (metadata.image_has_both_still_and_animated_sub_images) {
    int selected_track_id = 1;  // Currently animation is always default.
    if (prefer_animation_.has_value()) {
      selected_track_id = prefer_animation_.value() ? 1 : 0;

      // Sadly there's currently no way to get the frame count information for
      // unselected tracks, so for now just leave frame count as unknown but
      // force repetition count to be animated.
      if (!prefer_animation_.value()) {
        metadata.frame_count = 0;
        metadata.repetition_count = kAnimationLoopOnce;
      }
    }

    // All multi-track images have a still image track. Even if it's just the
    // first frame of the animation.
    tracks_->AddTrack(1, kAnimationNone, selected_track_id == 0);
    tracks_->AddTrack(metadata.frame_count, metadata.repetition_count,
                      selected_track_id == 1);
  } else {
    tracks_->AddTrack(metadata.frame_count, metadata.repetition_count, true);
  }

  tracks_->OnTracksReady();
  if (did_complete)
    MaybeSatisfyPendingDecodes();
}

void ImageDecoderExternal::SetFailed() {
  DVLOG(1) << __func__;
  if (failed_) {
    DCHECK(pending_decodes_.empty());
    return;
  }

  failed_ = true;
  decode_weak_factory_.Invalidate();
  if (tracks_->IsEmpty()) {
    tracks_->OnTracksReady(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "Failed to retrieve track metadata."));
  }
  MaybeSatisfyPendingDecodes();
  close();
}

}  // namespace blink
```
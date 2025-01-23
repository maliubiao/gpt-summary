Response:
Let's break down the thought process for analyzing this C++ code:

1. **Identify the Core Purpose:**  The filename `decoder_template.cc` and the class name `DecoderTemplate` immediately suggest this is a template class designed to implement the core logic for *decoders*. The presence of `#include "third_party/blink/renderer/modules/webcodecs/decoder_template.h"` reinforces this. The `webcodecs` namespace points to the WebCodecs API.

2. **Understand the Template Parameter:** The `<typename Traits>` indicates that the template is designed to be used with different types of decoders (likely audio and video, based on the included headers). The `Traits` class will provide specific details for each decoder type.

3. **Analyze Included Headers:** This is crucial for understanding the dependencies and functionalities involved. I would categorize the headers:
    * **General C++:** `<limits>`, `<utility>`, `<vector>`
    * **Chromium Base:** `base/...` (atomic sequence numbers, logging, memory management, metrics, tracing)
    * **Chromium Media:** `media/...` (decoder status, media utilities, build flags, GPU video acceleration)
    * **Blink Platform:** `platform/...` (platform abstraction, task runners, bindings)
    * **Blink Bindings (V8):** `bindings/core/v8/...`, `bindings/modules/v8/...` (JavaScript integration, specifically related to WebCodecs types like `AudioDataOutputCallback`, `AudioDecoderConfig`, `EncodedAudioChunk`, etc.)
    * **Blink Core DOM:** `core/dom/...` (DOM exceptions, events)
    * **Blink Core Execution Context:** `core/execution_context/...` (agent, execution context)
    * **Blink Core Probe:** `core/probe/...` (probing/instrumentation)
    * **Blink WebCodecs:** `modules/webcodecs/...` (specific WebCodecs classes like `AudioData`, `AudioDecoder`, `VideoDecoder`, `VideoFrame`).

4. **Examine the Class Structure:**
    * **Constructor:** Takes `ScriptState` and the decoder initialization information. Initializes members, sets up logging, and associates with the execution context.
    * **Destructor:** Logs final status.
    * **`decodeQueueSize()`:** Returns the size of the pending decode queue.
    * **`IsClosed()`:** Checks if the decoder is closed.
    * **`GetHardwarePreference()`/`SetHardwarePreference()`/`GetLowDelayPreference()`:**  Deals with decoder preferences (hardware acceleration, low latency).
    * **`configure()`:**  Handles the configuration of the decoder. Crucially, it validates the configuration, creates a `MediaConfig`, and initiates the actual configuration process.
    * **`decode()`:**  Processes an input chunk (audio or video). Validates state, creates a `DecoderBuffer`, and adds the request to the queue.
    * **`flush()`:**  Signals the end of input and waits for the decoder to process remaining data. Returns a `Promise`.
    * **`reset()`:** Resets the decoder to an unconfigured state.
    * **`close()`:**  Closes the decoder, releasing resources.
    * **`ProcessRequests()`:** The central logic for processing queued requests (configure, decode, flush, reset). This function ensures that requests are processed in order and handles asynchronous operations.
    * **`ProcessConfigureRequest()`, `ProcessDecodeRequest()`, `ProcessFlushRequest()`, `ProcessResetRequest()`:** Implement the specific logic for each request type.
    * **`Shutdown()`:** Handles the cleanup and error handling when the decoder is closed.
    * **`ResetAlgorithm()`:** Resets the decoder state.
    * **`OnFlushDone()`, `OnInitializeDone()`, `OnDecodeDone()`, `OnResetDone()`:** Callbacks from the underlying media decoder, handling completion and errors.
    * **`OnOutput()`:**  Called when the decoder produces output (decoded audio or video frame). Passes the output to the JavaScript callback.
    * **`TraceQueueSizes()`, `DispatchDequeueEvent()`, `ScheduleDequeueEvent()`:** Implement logic for tracing and signaling when the decode queue changes.
    * **`GetExecutionContext()`, `ContextDestroyed()`, `Trace()`:**  Standard Blink lifecycle and debugging methods.
    * **`OnCodecReclaimed()`:** Handles the case where the system reclaims the decoder due to memory pressure.
    * **`HasPendingActivity()`, `MaybeAbortRequest()`:**  Methods for checking pending work and aborting requests.
    * **`Request` Inner Class:** Represents a request in the processing queue.

5. **Identify Relationships with JavaScript/HTML/CSS:**
    * **JavaScript:** The presence of V8 bindings (`V8AudioDecoderConfig`, `V8EncodedVideoChunk`, `ScriptPromise`, callbacks) clearly indicates a strong integration with JavaScript. The `output` and `error` callbacks are how the decoded data and any errors are communicated back to the JavaScript code using the WebCodecs API. The `configure`, `decode`, `flush`, `reset`, and `close` methods directly correspond to methods in the JavaScript WebCodecs API.
    * **HTML:** While this specific file doesn't directly manipulate the HTML DOM, the WebCodecs API is used in JavaScript to process media, which might be fetched via `<video>` or `<audio>` elements or other means initiated by HTML.
    * **CSS:**  Indirectly related. CSS might style the video or audio elements displaying the decoded content, but this C++ code is not directly involved in CSS processing.

6. **Infer Logic and Assumptions:**
    * **Asynchronous Operations:** The code heavily relies on callbacks and a request queue, indicating asynchronous processing. Decoding is likely done on a separate thread.
    * **State Management:** The `state_` variable and the checks in each method are crucial for managing the decoder's lifecycle (unconfigured, configured, closed).
    * **Error Handling:** The `logger_` and the `error_cb_` are used for logging and reporting errors back to JavaScript.
    * **Resource Management:** The `ReclaimableCodec` base class suggests mechanisms for managing resources and potentially releasing them under memory pressure.
    * **GPU Acceleration:** The inclusion of `media/video/gpu_video_accelerator_factories.h` and the `gpu_factories_` member indicate support for hardware-accelerated decoding.

7. **Consider User/Programming Errors:** Look for places where incorrect usage could lead to errors:
    * Calling methods in the wrong state (e.g., `decode` before `configure`).
    * Providing invalid configuration data.
    * Providing non-keyframe data when a keyframe is required.
    * Not handling errors reported through the `error` callback in JavaScript.

8. **Trace User Operations:**  Think about the sequence of JavaScript calls that would lead to this C++ code being executed:
    * A JavaScript application creates an `AudioDecoder` or `VideoDecoder` instance.
    * The `configure()` method is called with configuration parameters.
    * The `decode()` method is called one or more times with `EncodedAudioChunk` or `EncodedVideoChunk` objects.
    * Optionally, `flush()` is called.
    * Optionally, `reset()` is called.
    * Finally, `close()` is called.

9. **Debugging Clues:** The logging (`DVLOG`), tracing (`TRACE_EVENT`), and the structure of the request queue provide valuable debugging information. If something goes wrong, examining the logs and the state of the request queue can help pinpoint the issue. The `reset_generation_` is crucial for handling out-of-order or stale requests after a reset.

By systematically going through these steps, you can build a comprehensive understanding of the functionality, relationships, and potential issues within this C++ source file.
This C++ source file, `decoder_template.cc`, within the Chromium Blink rendering engine, implements a **template class for WebCodecs decoders**. This means it provides a common framework and logic that can be specialized for different types of decoders, such as audio and video decoders.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **State Management:**
   - Manages the lifecycle of a decoder, transitioning through states like `unconfigured`, `configured`, and `closed`.
   - Ensures methods are called in the correct state (e.g., you can't `decode` before `configure`).

2. **Request Queuing:**
   - Implements a queue (`requests_`) to handle asynchronous operations like configuration, decoding, flushing, and resetting.
   - This is necessary because decoding can be a time-consuming operation, and the browser needs to remain responsive.

3. **Asynchronous Processing:**
   - Utilizes task runners (`main_thread_task_runner_`) to offload potentially heavy decoding tasks to background threads.
   - Relies on callbacks (e.g., `OnInitializeDone`, `OnDecodeDone`, `OnOutput`) to handle the results of these asynchronous operations.

4. **Configuration Handling:**
   - Takes decoder configuration information (e.g., codec, sample rate, bit rate for audio; codec, width, height for video).
   - Validates the configuration.
   - Converts the JavaScript configuration into a format understandable by the underlying media decoder.
   - Handles hardware preference settings for potentially leveraging GPU acceleration.

5. **Decoding Logic:**
   - Accepts encoded audio or video chunks as input.
   - Prepares the input for the underlying media decoder.
   - Tracks pending decode operations.

6. **Flushing and Resetting:**
   - Implements `flush()` to signal the end of input and wait for any remaining data to be decoded.
   - Implements `reset()` to stop the current decoding process and return the decoder to an unconfigured state.

7. **Output Handling:**
   - Receives decoded audio or video frames from the underlying media decoder.
   - Converts the decoded data into WebCodecs-specific output types (`AudioData` or `VideoFrame`).
   - Dispatches the decoded data to the JavaScript `output` callback.

8. **Error Handling:**
   - Implements an error callback mechanism to report errors that occur during the decoding process back to JavaScript.
   - Uses a `CodecLogger` to record detailed information about decoder status and errors.

9. **Resource Management:**
   - Manages the lifetime of the underlying media decoder instance.
   - Includes logic for potentially reclaiming resources under memory pressure (`OnCodecReclaimed`).

10. **Tracing and Metrics:**
    - Includes instrumentation for tracing decoder activity and collecting performance metrics (using `TRACE_EVENT` and `base::UmaHistogramSparse`).

**Relationship with JavaScript, HTML, and CSS:**

This C++ file is a crucial part of the implementation of the **WebCodecs API**, which is exposed to JavaScript.

* **JavaScript:**
    - **Interaction:** JavaScript code uses the `AudioDecoder` and `VideoDecoder` classes (defined in JavaScript) to interact with this C++ template.
    - **Configuration:** JavaScript provides the configuration objects (e.g., `AudioDecoderConfig`, `VideoDecoderConfig`) that are passed to the `configure()` method in C++.
    - **Input:** JavaScript provides the encoded data in the form of `EncodedAudioChunk` and `EncodedVideoChunk` objects, which are passed to the `decode()` method.
    - **Output:** The decoded data is returned to JavaScript via the `output` callback function provided during decoder initialization.
    - **Error Handling:** JavaScript provides the `error` callback function to receive error notifications from the C++ decoder.
    - **Example:**
      ```javascript
      const decoder = new VideoDecoder({
        output(frame) {
          // Handle decoded video frame
          console.log("Decoded frame:", frame);
          frame.close();
        },
        error(e) {
          console.error("Decoding error:", e);
        }
      });

      decoder.configure({
        codec: 'vp8',
        width: 640,
        height: 480
      });

      fetch('encoded_video.ivf')
        .then(response => response.arrayBuffer())
        .then(data => {
          const chunk = new EncodedVideoChunk({
            type: 'key',
            timestamp: 0,
            data: data
          });
          decoder.decode(chunk);
        });
      ```

* **HTML:**
    - **Indirect Relationship:**  The decoded audio or video data is typically used to update `<audio>` or `<video>` elements in the HTML DOM for playback. The WebCodecs API allows for more fine-grained control over the decoding process compared to directly using the media elements.
    - **Example:**  The decoded `VideoFrame` might be drawn onto a `<canvas>` element or used with a media stream track that feeds into a `<video>` element.

* **CSS:**
    - **No Direct Relationship:** This C++ code is responsible for the core decoding logic and doesn't directly interact with CSS. However, CSS can be used to style the `<audio>` or `<video>` elements that display the decoded output.

**Logic Inference (Hypothetical Input and Output):**

**Scenario:** Decoding a single video frame.

**Hypothetical Input (JavaScript):**

```javascript
const decoder = new VideoDecoder({ /* ... output and error callbacks ... */ });
decoder.configure({ codec: 'avc1.42E01E', width: 320, height: 240 });
const encodedData = new Uint8Array([...encoded video frame data...]);
const chunk = new EncodedVideoChunk({
  type: 'key',
  timestamp: 0,
  data: encodedData.buffer
});
decoder.decode(chunk);
```

**Hypothetical Processing (C++):**

1. The `decode()` method in `DecoderTemplate` receives the `EncodedVideoChunk`.
2. It creates a `media::DecoderBuffer` from the `encodedData`.
3. It adds a decode request to the `requests_` queue.
4. The `ProcessRequests()` method eventually picks up the decode request.
5. It calls the underlying video decoder's `Decode()` method with the `DecoderBuffer`.
6. The underlying decoder processes the encoded data.
7. Upon successful decoding, the underlying decoder calls a callback (e.g., `OnOutput` in `DecoderTemplate`).

**Hypothetical Output (JavaScript):**

The `output` callback function in the JavaScript will be invoked with a `VideoFrame` object containing the decoded pixel data of the video frame.

```javascript
output(frame) {
  console.log("Decoded frame with timestamp:", frame.timestamp);
  // Access frame.codedWidth, frame.codedHeight, frame.format, etc.
  frame.close();
}
```

**User or Programming Common Usage Errors:**

1. **Calling `decode()` before `configure()`:** This will result in an error because the decoder needs to be initialized with the correct configuration before it can process any data. The C++ code checks for this state and throws an exception.

   ```javascript
   const decoder = new VideoDecoder({...});
   const chunk = new EncodedVideoChunk({...});
   decoder.decode(chunk); // Error: Decoder is not configured.
   decoder.configure({...});
   ```

2. **Providing an invalid configuration:** If the configuration parameters are not supported by the browser or the underlying codec, the `configure()` method might throw an error, or the decoder might fail to initialize.

   ```javascript
   decoder.configure({ codec: 'some-unsupported-codec' }); // Might throw an error
   ```

3. **Feeding non-keyframe data when a keyframe is required:**  Some video codecs require a keyframe (a self-contained frame) to start decoding. If the first chunk provided is not a keyframe, the decoder will likely throw an error.

   ```javascript
   const chunk = new EncodedVideoChunk({ type: 'delta', ... }); // Assuming this is the first chunk
   decoder.decode(chunk); // Error: Keyframe required.
   ```

4. **Not handling the `error` callback:** If errors occur during decoding and the JavaScript application doesn't handle the `error` callback, the user might experience unexpected behavior or silent failures.

   ```javascript
   const decoder = new VideoDecoder({
     output(frame) { /* ... */ },
     // Missing error callback!
   });
   // ... decoding process that might encounter errors ...
   ```

5. **Closing the `VideoFrame` after using it:** `VideoFrame` objects hold resources. It's crucial to call `frame.close()` after you're done using the frame to release those resources and prevent memory leaks.

**User Operation Steps to Reach Here (Debugging Clues):**

Let's trace a typical user interaction leading to the execution of code in `decoder_template.cc`:

1. **User opens a web page** that uses the WebCodecs API for video or audio processing.
2. **JavaScript code in the web page creates an `AudioDecoder` or `VideoDecoder` instance.** This triggers the creation of the corresponding C++ `DecoderTemplate` object.
3. **The JavaScript calls the `configure()` method** on the decoder instance, providing configuration parameters. This call is routed to the C++ `configure()` method in `decoder_template.cc`.
4. **The JavaScript fetches encoded media data** (e.g., from a network source or a file).
5. **The JavaScript creates `EncodedAudioChunk` or `EncodedVideoChunk` objects** from the fetched data.
6. **The JavaScript calls the `decode()` method** on the decoder instance, passing the encoded chunk. This call is routed to the C++ `decode()` method in `decoder_template.cc`.
7. **(Asynchronous Execution):** The C++ code within `decoder_template.cc` manages the decoding process, potentially involving interaction with platform-specific media decoders.
8. **Upon successful decoding, the `OnOutput()` method in C++ is called.**
9. **The `OnOutput()` method creates a `VideoFrame` or `AudioData` object and invokes the JavaScript `output` callback.**
10. **If an error occurs during any of these steps, the `Shutdown()` method might be called,** and the JavaScript `error` callback will be invoked.
11. **The JavaScript might call `flush()` or `reset()`** to control the decoding process.
12. **Finally, the JavaScript might call `close()`** to release the decoder resources.

**Debugging Clues:**

- **Breakpoints:** Setting breakpoints in the `configure()`, `decode()`, `OnOutput()`, and `Shutdown()` methods in `decoder_template.cc` can help understand the flow of execution and the state of the decoder.
- **Console Logging:** Adding `console.log()` statements in the JavaScript `output` and `error` callbacks can reveal the decoded data or any errors.
- **WebCodecs Inspector (Chrome DevTools):** Chrome DevTools has a WebCodecs inspector that can provide insights into the configuration, state, and performance of WebCodecs decoders.
- **Tracing (about:tracing):**  The `TRACE_EVENT` calls in the C++ code can be captured using Chrome's tracing mechanism (`about:tracing`) to provide a detailed timeline of decoder activity.
- **Logging (`DVLOG`):** The `DVLOG` statements in the C++ code can be enabled in debug builds to get more detailed logs about the internal operations of the decoder.
- **Checking the `decodeQueueSize()`:**  Observing the size of the decode queue can help identify if decoding requests are being processed or are backing up.

In summary, `decoder_template.cc` provides the foundational C++ implementation for WebCodecs decoders in the Blink rendering engine, handling the complex asynchronous operations involved in decoding audio and video data and bridging the gap between JavaScript API calls and the underlying media processing capabilities.

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/decoder_template.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/decoder_template.h"

#include <limits>
#include <utility>
#include <vector>

#include "base/atomic_sequence_num.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/trace_event/trace_event.h"
#include "media/base/decoder_status.h"
#include "media/base/media_util.h"
#include "media/media_buildflags.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_output_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_init.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_decoder.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_state_helper.h"
#include "third_party/blink/renderer/modules/webcodecs/gpu_factories_retriever.h"
#include "third_party/blink/renderer/modules/webcodecs/video_decoder.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {
constexpr const char kCategory[] = "media";

base::AtomicSequenceNumber g_sequence_num_for_counters;
}  // namespace

// static
template <typename Traits>
const CodecTraceNames* DecoderTemplate<Traits>::GetTraceNames() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(CodecTraceNames, trace_names,
                                  (Traits::GetName()));
  return &trace_names;
}

template <typename Traits>
DecoderTemplate<Traits>::DecoderTemplate(ScriptState* script_state,
                                         const InitType* init,
                                         ExceptionState& exception_state)
    : ActiveScriptWrappable<DecoderTemplate<Traits>>({}),
      ReclaimableCodec(ReclaimableCodec::CodecType::kDecoder,
                       ExecutionContext::From(script_state)),
      script_state_(script_state),
      state_(V8CodecState::Enum::kUnconfigured),
      trace_counter_id_(g_sequence_num_for_counters.GetNext()) {
  DVLOG(1) << __func__;
  DCHECK(init->hasOutput());
  DCHECK(init->hasError());

  ExecutionContext* context = GetExecutionContext();
  DCHECK(context);

  main_thread_task_runner_ =
      context->GetTaskRunner(TaskType::kInternalMediaRealTime);

  logger_ = std::make_unique<CodecLogger<media::DecoderStatus>>(
      context, main_thread_task_runner_);

  logger_->log()->SetProperty<media::MediaLogProperty::kFrameUrl>(
      context->Url().GetString().Ascii());

  output_cb_ = init->output();
  error_cb_ = init->error();
}

template <typename Traits>
DecoderTemplate<Traits>::~DecoderTemplate() {
  DVLOG(1) << __func__;
  base::UmaHistogramSparse(
      String::Format("Blink.WebCodecs.%s.FinalStatus", Traits::GetName())
          .Ascii()
          .c_str(),
      static_cast<int>(logger_->status_code()));
}

template <typename Traits>
uint32_t DecoderTemplate<Traits>::decodeQueueSize() {
  return num_pending_decodes_;
}

template <typename Traits>
bool DecoderTemplate<Traits>::IsClosed() {
  return state_ == V8CodecState::Enum::kClosed;
}

template <typename Traits>
HardwarePreference DecoderTemplate<Traits>::GetHardwarePreference(
    const ConfigType&) {
  return HardwarePreference::kNoPreference;
}

template <typename Traits>
bool DecoderTemplate<Traits>::GetLowDelayPreference(const ConfigType&) {
  return false;
}

template <typename Traits>
void DecoderTemplate<Traits>::SetHardwarePreference(HardwarePreference) {}

template <typename Traits>
void DecoderTemplate<Traits>::configure(const ConfigType* config,
                                        ExceptionState& exception_state) {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "decode", exception_state))
    return;

  String js_error_message;
  if (!IsValidConfig(*config, &js_error_message)) {
    exception_state.ThrowTypeError(js_error_message);
    return;
  }

  std::optional<MediaConfigType> media_config =
      MakeMediaConfig(*config, &js_error_message);

  // Audio/VideoDecoder don't yet support encryption.
  if (media_config && media_config->is_encrypted()) {
    js_error_message = "Encrypted content is not supported";
    media_config = std::nullopt;
  }

  MarkCodecActive();

  state_ = V8CodecState(V8CodecState::Enum::kConfigured);
  require_key_frame_ = true;

  Request* request = MakeGarbageCollected<Request>();
  request->type = Request::Type::kConfigure;
  if (media_config.has_value()) {
    request->media_config = std::make_unique<MediaConfigType>(*media_config);
  } else {
    request->js_error_message = js_error_message;
  }
  request->reset_generation = reset_generation_;
  request->hw_pref = GetHardwarePreference(*config);
  request->low_delay = GetLowDelayPreference(*config);
  requests_.push_back(request);
  ProcessRequests();
}

template <typename Traits>
void DecoderTemplate<Traits>::decode(const InputType* chunk,
                                     ExceptionState& exception_state) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "decode", exception_state))
    return;

  if (ThrowIfCodecStateUnconfigured(state_, "decode", exception_state))
    return;

  Request* request = MakeGarbageCollected<Request>();
  request->type = Request::Type::kDecode;
  request->reset_generation = reset_generation_;

  auto status_or_buffer = MakeInput(*chunk, require_key_frame_);
  if (status_or_buffer.has_value()) {
    request->decoder_buffer = std::move(status_or_buffer).value();
    require_key_frame_ = false;
  } else {
    request->status = std::move(status_or_buffer).error();
    if (request->status == media::DecoderStatus::Codes::kKeyFrameRequired) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataError,
                                        request->status.message().c_str());
      return;
    }
  }
  MarkCodecActive();

  requests_.push_back(request);
  ++num_pending_decodes_;
  ProcessRequests();
}

template <typename Traits>
ScriptPromise<IDLUndefined> DecoderTemplate<Traits>::flush(
    ExceptionState& exception_state) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "flush", exception_state))
    return EmptyPromise();

  if (ThrowIfCodecStateUnconfigured(state_, "flush", exception_state))
    return EmptyPromise();

  MarkCodecActive();

  require_key_frame_ = true;

  Request* request = MakeGarbageCollected<Request>();
  request->type = Request::Type::kFlush;
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state_);
  request->resolver = resolver;
  request->reset_generation = reset_generation_;
  requests_.push_back(request);
  ProcessRequests();
  return resolver->Promise();
}

template <typename Traits>
void DecoderTemplate<Traits>::reset(ExceptionState& exception_state) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "reset", exception_state))
    return;

  MarkCodecActive();

  ResetAlgorithm();
}

template <typename Traits>
void DecoderTemplate<Traits>::close(ExceptionState& exception_state) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "close", exception_state))
    return;

  Shutdown();
}

template <typename Traits>
void DecoderTemplate<Traits>::ProcessRequests() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!IsClosed());
  while (!pending_request_ && !requests_.empty()) {
    Request* request = requests_.front();

    // Skip processing for requests that are canceled by a recent reset().
    if (MaybeAbortRequest(request)) {
      requests_.pop_front();
      continue;
    }

    TraceQueueSizes();

    DCHECK_EQ(request->reset_generation, reset_generation_);
    switch (request->type) {
      case Request::Type::kConfigure:
        if (!ProcessConfigureRequest(request))
          return;
        break;
      case Request::Type::kDecode:
        if (!ProcessDecodeRequest(request))
          return;
        break;
      case Request::Type::kFlush:
        if (!ProcessFlushRequest(request))
          return;
        break;
      case Request::Type::kReset:
        if (!ProcessResetRequest(request))
          return;
        break;
    }
    requests_.pop_front();
  }

  TraceQueueSizes();
}

template <typename Traits>
bool DecoderTemplate<Traits>::ProcessConfigureRequest(Request* request) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!IsClosed());
  DCHECK(!pending_request_);
  DCHECK_EQ(request->type, Request::Type::kConfigure);

  if (decoder() &&
      pending_decodes_.size() + 1 >
          static_cast<size_t>(Traits::GetMaxDecodeRequests(*decoder()))) {
    // Try again after OnDecodeDone().
    return false;
  }

  // TODO(sandersd): Record this configuration as pending but don't apply it
  // until there is a decode request.
  pending_request_ = request;
  pending_request_->StartTracing();

  if (!request->media_config) {
    main_thread_task_runner_->PostTask(
        FROM_HERE,
        WTF::BindOnce(&DecoderTemplate<Traits>::Shutdown,
                      WrapWeakPersistent(this),
                      WrapPersistent(MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kNotSupportedError,
                          request->js_error_message))));
    return false;
  }

  if (gpu_factories_.has_value()) {
    ContinueConfigureWithGpuFactories(request, gpu_factories_.value());
  } else if (Traits::kNeedsGpuFactories) {
    RetrieveGpuFactoriesWithKnownDecoderSupport(CrossThreadBindOnce(
        &DecoderTemplate<Traits>::ContinueConfigureWithGpuFactories,
        MakeUnwrappingCrossThreadHandle(this),
        MakeUnwrappingCrossThreadHandle(request)));
  } else {
    ContinueConfigureWithGpuFactories(request, nullptr);
  }
  return true;
}

template <typename Traits>
void DecoderTemplate<Traits>::ContinueConfigureWithGpuFactories(
    Request* request,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(request);
  DCHECK_EQ(request->type, Request::Type::kConfigure);

  if (IsClosed()) {
    return;
  }

  gpu_factories_ = gpu_factories;

  if (MaybeAbortRequest(request)) {
    DCHECK_EQ(request, pending_request_);
    pending_request_.Release()->EndTracing();
    return;
  }

  if (!decoder()) {
    decoder_ = Traits::CreateDecoder(*ExecutionContext::From(script_state_),
                                     gpu_factories_.value(), logger_->log());
    if (!decoder()) {
      Shutdown(MakeOperationError(
          "Internal error: Could not create decoder.",
          media::DecoderStatus::Codes::kFailedToCreateDecoder));
      return;
    }

    SetHardwarePreference(request->hw_pref.value());
    // Processing continues in OnInitializeDone().
    // Note: OnInitializeDone() must not call ProcessRequests() reentrantly,
    // which can happen if InitializeDecoder() calls it synchronously.
    initializing_sync_ = true;
    Traits::InitializeDecoder(
        *decoder(), request->low_delay.value(), *request->media_config,
        WTF::BindOnce(&DecoderTemplate::OnInitializeDone,
                      WrapWeakPersistent(this)),
        WTF::BindRepeating(&DecoderTemplate::OnOutput, WrapWeakPersistent(this),
                           reset_generation_));
    initializing_sync_ = false;
    return;
  }

  // Processing continues in OnFlushDone().
  decoder()->Decode(
      media::DecoderBuffer::CreateEOSBuffer(),
      WTF::BindOnce(&DecoderTemplate::OnFlushDone, WrapWeakPersistent(this)));
}

template <typename Traits>
bool DecoderTemplate<Traits>::ProcessDecodeRequest(Request* request) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(state_, V8CodecState::Enum::kConfigured);
  DCHECK(!pending_request_);
  DCHECK_EQ(request->type, Request::Type::kDecode);
  DCHECK_GT(num_pending_decodes_, 0u);

  if (!decoder()) {
    Shutdown(MakeEncodingError("Decoding error: no decoder found.",
                               media::DecoderStatus::Codes::kNotInitialized));
    return false;
  }

  if (pending_decodes_.size() + 1 >
      static_cast<size_t>(Traits::GetMaxDecodeRequests(*decoder()))) {
    // Try again after OnDecodeDone().
    return false;
  }

  // The request may be invalid, if so report that now.
  if (!request->decoder_buffer || request->decoder_buffer->empty()) {
    if (request->status.is_ok()) {
      Shutdown(MakeEncodingError("Null or empty decoder buffer.",
                                 media::DecoderStatus::Codes::kFailed));
    } else {
      Shutdown(MakeEncodingError("Decoder error.", request->status));
    }

    return false;
  }

  // Submit for decoding.
  //
  // |pending_decode_id_| must not be 0 nor max because it HashMap reserves
  // these values for "emtpy" and "deleted".
  while (++pending_decode_id_ == 0 ||
         pending_decode_id_ == std::numeric_limits<uint32_t>::max() ||
         pending_decodes_.Contains(pending_decode_id_))
    ;
  pending_decodes_.Set(pending_decode_id_, request);
  --num_pending_decodes_;
  ScheduleDequeueEvent();

  if (media::MediaTraceIsEnabled()) {
    request->decode_trace = std::make_unique<media::ScopedDecodeTrace>(
        GetTraceNames()->decode.c_str(), *request->decoder_buffer);
  }

  decoder()->Decode(
      std::move(request->decoder_buffer),
      WTF::BindOnce(&DecoderTemplate::OnDecodeDone, WrapWeakPersistent(this),
                    pending_decode_id_));
  return true;
}

template <typename Traits>
bool DecoderTemplate<Traits>::ProcessFlushRequest(Request* request) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!IsClosed());
  DCHECK(!pending_request_);
  DCHECK_EQ(request->type, Request::Type::kFlush);
  DCHECK_EQ(state_, V8CodecState::Enum::kConfigured);

  // flush() can only be called when state = "configured", in which case we
  // should always have a decoder.
  DCHECK(decoder());

  if (pending_decodes_.size() + 1 >
      static_cast<size_t>(Traits::GetMaxDecodeRequests(*decoder()))) {
    // Try again after OnDecodeDone().
    return false;
  }

  // Processing continues in OnFlushDone().
  pending_request_ = request;
  pending_request_->StartTracing();

  decoder()->Decode(
      media::DecoderBuffer::CreateEOSBuffer(),
      WTF::BindOnce(&DecoderTemplate::OnFlushDone, WrapWeakPersistent(this)));
  return true;
}

template <typename Traits>
bool DecoderTemplate<Traits>::ProcessResetRequest(Request* request) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!IsClosed());
  DCHECK(!pending_request_);
  DCHECK_EQ(request->type, Request::Type::kReset);
  DCHECK_GT(reset_generation_, 0u);

  // Signal [[codec implementation]] to cease producing output for the previous
  // configuration.
  if (decoder()) {
    pending_request_ = request;
    pending_request_->StartTracing();

    // Processing continues in OnResetDone().
    decoder()->Reset(
        WTF::BindOnce(&DecoderTemplate::OnResetDone, WrapWeakPersistent(this)));
  }

  return true;
}

template <typename Traits>
void DecoderTemplate<Traits>::Shutdown(DOMException* exception) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (IsClosed())
    return;

  TRACE_EVENT1(kCategory, GetTraceNames()->shutdown.c_str(), "has_exception",
               !!exception);

  shutting_down_ = true;
  shutting_down_due_to_error_ = exception;

  // Abort pending work (otherwise it will never complete)
  if (pending_request_) {
    if (pending_request_->resolver) {
      pending_request_->resolver.Release()->Reject(
          exception
              ? exception
              : MakeGarbageCollected<DOMException>(
                    DOMExceptionCode::kAbortError, "Aborted due to close()"));
    }

    pending_request_.Release()->EndTracing(/*shutting_down=*/true);
  }

  // Abort all upcoming work.
  ResetAlgorithm();
  ReleaseCodecPressure();

  // Store the error callback so that we can use it after clearing state.
  V8WebCodecsErrorCallback* error_cb = error_cb_.Get();

  // Prevent any new public API calls during teardown.
  // This should make it safe to call into JS synchronously.
  state_ = V8CodecState(V8CodecState::Enum::kClosed);

  // Prevent any late callbacks running.
  output_cb_.Release();
  error_cb_.Release();

  // Prevent any further logging from being reported.
  logger_->Neuter();

  // Clear decoding and JS-visible queue state. Use DeleteSoon() to avoid
  // deleting decoder_ when its callback (e.g. OnDecodeDone()) may be below us
  // in the stack.
  main_thread_task_runner_->DeleteSoon(FROM_HERE, std::move(decoder_));

  if (pending_request_) {
    // This request was added as part of calling ResetAlgorithm above. However,
    // OnResetDone() will never execute, since we are now in a kClosed state,
    // and |decoder_| has been reset.
    DCHECK_EQ(pending_request_->type, Request::Type::kReset);
    pending_request_.Release()->EndTracing(/*shutting_down=*/true);
  }

  bool trace_enabled = false;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(kCategory, &trace_enabled);
  if (trace_enabled) {
    for (auto& pending_decode : pending_decodes_)
      pending_decode.value->decode_trace.reset();
  }

  pending_decodes_.clear();
  num_pending_decodes_ = 0;
  ScheduleDequeueEvent();

  if (exception) {
    error_cb->InvokeAndReportException(nullptr, exception);
  }
}

template <typename Traits>
void DecoderTemplate<Traits>::ResetAlgorithm() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (state_ == V8CodecState::Enum::kUnconfigured)
    return;

  state_ = V8CodecState(V8CodecState::Enum::kUnconfigured);

  // Increment reset counter to cause older pending requests to be rejected. See
  // ProcessRequests().
  reset_generation_++;

  // Any previous pending decode will be filtered by ProcessRequests(). Reset
  // the count immediately to report the correct value in decodeQueueSize().
  num_pending_decodes_ = 0;
  ScheduleDequeueEvent();

  // Since configure is always required after reset we can drop any cached
  // configuration.
  active_config_.reset();

  Request* request = MakeGarbageCollected<Request>();
  request->type = Request::Type::kReset;
  request->reset_generation = reset_generation_;
  requests_.push_back(request);
  ProcessRequests();
}

template <typename Traits>
void DecoderTemplate<Traits>::OnFlushDone(media::DecoderStatus status) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (IsClosed())
    return;

  DCHECK(pending_request_);
  DCHECK(pending_request_->type == Request::Type::kConfigure ||
         pending_request_->type == Request::Type::kFlush);

  if (!status.is_ok()) {
    Shutdown(MakeEncodingError("Error during flush.", status));
    return;
  }

  // If reset() has been called during the Flush(), we can skip reinitialization
  // since the client is required to do so manually.
  const bool is_flush = pending_request_->type == Request::Type::kFlush;
  if (is_flush && MaybeAbortRequest(pending_request_)) {
    pending_request_.Release()->EndTracing();
    ProcessRequests();
    return;
  }

  if (!is_flush)
    SetHardwarePreference(pending_request_->hw_pref.value());

  // Processing continues in OnInitializeDone().
  Traits::InitializeDecoder(
      *decoder(), is_flush ? low_delay_ : pending_request_->low_delay.value(),
      is_flush ? *active_config_ : *pending_request_->media_config,
      WTF::BindOnce(&DecoderTemplate::OnInitializeDone,
                    WrapWeakPersistent(this)),
      WTF::BindRepeating(&DecoderTemplate::OnOutput, WrapWeakPersistent(this),
                         reset_generation_));
}

template <typename Traits>
void DecoderTemplate<Traits>::OnInitializeDone(media::DecoderStatus status) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (IsClosed())
    return;

  DCHECK(pending_request_);
  DCHECK(pending_request_->type == Request::Type::kConfigure ||
         pending_request_->type == Request::Type::kFlush);

  const bool is_flush = pending_request_->type == Request::Type::kFlush;
  if (!status.is_ok()) {
    std::string error_message;
    if (is_flush) {
      error_message = "Error during initialize after flush.";
    } else if (status.code() ==
               media::DecoderStatus::Codes::kUnsupportedConfig) {
      error_message =
          "Unsupported configuration. Check isConfigSupported() prior to "
          "calling configure().";
    } else {
      error_message = "Decoder initialization error.";
    }
    Shutdown(MakeOperationError(error_message, status));
    return;
  }

  if (is_flush) {
    pending_request_->resolver.Release()->Resolve();
  } else {
    Traits::UpdateDecoderLog(*decoder(), *pending_request_->media_config,
                             logger_->log());

    if (decoder()->IsPlatformDecoder())
      ApplyCodecPressure();
    else
      ReleaseCodecPressure();

    low_delay_ = pending_request_->low_delay.value();
    active_config_ = std::move(pending_request_->media_config);
  }

  pending_request_.Release()->EndTracing();

  if (!initializing_sync_)
    ProcessRequests();
  else
    DCHECK(!is_flush);
}

template <typename Traits>
void DecoderTemplate<Traits>::OnDecodeDone(uint32_t id,
                                           media::DecoderStatus status) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (IsClosed())
    return;

  auto it = pending_decodes_.find(id);
  if (it != pending_decodes_.end()) {
    if (it->value->decode_trace)
      it->value->decode_trace->EndTrace(status);
    pending_decodes_.erase(it);
  }

  if (!status.is_ok() &&
      status.code() != media::DecoderStatus::Codes::kAborted) {
    Shutdown(MakeEncodingError("Decoding error.", std::move(status)));
    return;
  }

  ProcessRequests();
}

template <typename Traits>
void DecoderTemplate<Traits>::OnResetDone() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (IsClosed())
    return;

  DCHECK(pending_request_);
  DCHECK_EQ(pending_request_->type, Request::Type::kReset);

  pending_request_.Release()->EndTracing();
  ProcessRequests();
}

template <typename Traits>
void DecoderTemplate<Traits>::OnOutput(uint32_t reset_generation,
                                       scoped_refptr<MediaOutputType> output) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Suppress outputs belonging to an earlier reset_generation.
  if (reset_generation != reset_generation_)
    return;

  if (state_.AsEnum() != V8CodecState::Enum::kConfigured)
    return;

  auto* context = GetExecutionContext();
  if (!context)
    return;

  auto output_or_error = MakeOutput(std::move(output), context);

  if (!output_or_error.has_value()) {
    Shutdown(MakeEncodingError("Error creating output from decoded data",
                               std::move(output_or_error).error()));
    return;
  }

  OutputType* blink_output = std::move(output_or_error).value();

  TRACE_EVENT_BEGIN1(kCategory, GetTraceNames()->output.c_str(), "timestamp",
                     blink_output->timestamp());

  output_cb_->InvokeAndReportException(nullptr, blink_output);

  TRACE_EVENT_END0(kCategory, GetTraceNames()->output.c_str());

  MarkCodecActive();
}

template <typename Traits>
void DecoderTemplate<Traits>::TraceQueueSizes() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  TRACE_COUNTER_ID2(kCategory, GetTraceNames()->requests_counter.c_str(),
                    trace_counter_id_, "decodes", num_pending_decodes_, "other",
                    requests_.size() - num_pending_decodes_);
}

template <typename Traits>
void DecoderTemplate<Traits>::DispatchDequeueEvent(Event* event) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  probe::AsyncTask async_task(GetExecutionContext(),
                              event->async_task_context());
  dequeue_event_pending_ = false;
  DispatchEvent(*event);
}

template <typename Traits>
void DecoderTemplate<Traits>::ScheduleDequeueEvent() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (dequeue_event_pending_)
    return;
  dequeue_event_pending_ = true;

  Event* event = Event::Create(event_type_names::kDequeue);
  event->SetTarget(this);
  event->async_task_context()->Schedule(GetExecutionContext(), event->type());

  main_thread_task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&DecoderTemplate<Traits>::DispatchDequeueEvent,
                    WrapWeakPersistent(this), WrapPersistent(event)));
}

template <typename Traits>
ExecutionContext* DecoderTemplate<Traits>::GetExecutionContext() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

template <typename Traits>
void DecoderTemplate<Traits>::ContextDestroyed() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Deallocate resources and suppress late callbacks from media thread.
  Shutdown();
}

template <typename Traits>
void DecoderTemplate<Traits>::Trace(Visitor* visitor) const {
  visitor->Trace(script_state_);
  visitor->Trace(output_cb_);
  visitor->Trace(error_cb_);
  visitor->Trace(requests_);
  visitor->Trace(pending_request_);
  visitor->Trace(pending_decodes_);
  visitor->Trace(shutting_down_due_to_error_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  ReclaimableCodec::Trace(visitor);
}

template <typename Traits>
void DecoderTemplate<Traits>::OnCodecReclaimed(DOMException* exception) {
  TRACE_EVENT0(kCategory, GetTraceNames()->reclaimed.c_str());
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(is_applying_codec_pressure());

  if (state_.AsEnum() == V8CodecState::Enum::kUnconfigured) {
    decoder_.reset();

    // This codec isn't holding on to any resources, and doesn't need to be
    // reclaimed.
    ReleaseCodecPressure();
    return;
  }

  DCHECK_EQ(state_.AsEnum(), V8CodecState::Enum::kConfigured);
  Shutdown(exception);
}

template <typename Traits>
bool DecoderTemplate<Traits>::HasPendingActivity() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return pending_request_ || !requests_.empty();
}

template <typename Traits>
bool DecoderTemplate<Traits>::MaybeAbortRequest(Request* request) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (request->reset_generation == reset_generation_) {
    return false;
  }

  if (request->resolver) {
    request->resolver.Release()->Reject(
        shutting_down_due_to_error_
            ? shutting_down_due_to_error_.Get()
            : MakeGarbageCollected<DOMException>(
                  DOMExceptionCode::kAbortError,
                  shutting_down_ ? "Aborted due to close()"
                                 : "Aborted due to reset()"));
  }
  return true;
}

template <typename Traits>
void DecoderTemplate<Traits>::Request::Trace(Visitor* visitor) const {
  visitor->Trace(resolver);
}

template <typename Traits>
const char* DecoderTemplate<Traits>::Request::TraceNameFromType() {
  using RequestType = typename DecoderTemplate<Traits>::Request::Type;

  const CodecTraceNames* trace_names = DecoderTemplate<Traits>::GetTraceNames();

  switch (type) {
    case RequestType::kConfigure:
      return trace_names->configure.c_str();
    case RequestType::kDecode:
      return trace_names->decode.c_str();
    case RequestType::kFlush:
      return trace_names->flush.c_str();
    case RequestType::kReset:
      return trace_names->reset.c_str();
  }
  return "InvalidCodecTraceName";
}

template <typename Traits>
void DecoderTemplate<Traits>::Request::StartTracing() {
#if DCHECK_IS_ON()
  DCHECK(!is_tracing);
  is_tracing = true;
#endif
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(kCategory, TraceNameFromType(), this);
}

template <typename Traits>
void DecoderTemplate<Traits>::Request::EndTracing(bool shutting_down) {
#if DCHECK_IS_ON()
  DCHECK(is_tracing);
  is_tracing = false;
#endif
  TRACE_EVENT_NESTABLE_ASYNC_END1(kCategory, TraceNameFromType(), this,
                                  "completed", !shutting_down);
}

template <typename Traits>
DOMException* DecoderTemplate<Traits>::MakeOperationError(
    std::string error_msg,
    media::DecoderStatus status) {
  if (!decoder_ || decoder_->IsPlatformDecoder()) {
    return logger_->MakeOperationError(std::move(error_msg), std::move(status));
  }
  return logger_->MakeSoftwareCodecOperationError(std::move(error_msg),
                                                  std::move(status));
}

template <typename Traits>
DOMException* DecoderTemplate<Traits>::MakeEncodingError(
    std::string error_msg,
    media::DecoderStatus status) {
  if (!decoder_ || decoder_->IsPlatformDecoder()) {
    return logger_->MakeEncodingError(std::move(error_msg), std::move(status));
  }
  return logger_->MakeSoftwareCodecEncodingError(std::move(error_msg),
                                                 std::move(status));
}

template class DecoderTemplate<AudioDecoderTraits>;
template class DecoderTemplate<VideoDecoderTraits>;

}  // namespace blink
```
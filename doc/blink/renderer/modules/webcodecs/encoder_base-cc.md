Response:
Let's break down the thought process for analyzing the `encoder_base.cc` file.

1. **Understand the Goal:** The request is to analyze a specific Chromium Blink engine source file (`encoder_base.cc`) and explain its functionality, relationships to web technologies, internal logic, potential errors, and how a user might trigger its execution.

2. **Initial Scan for Key Information:** The first step is to quickly read through the code, identifying key elements:
    * **Includes:**  These provide clues about dependencies and functionalities. Notice includes like `webcodecs/`, `bindings/`, `core/dom/`, `platform/`. This immediately suggests involvement in the WebCodecs API, JavaScript bindings, DOM interaction, and platform-level abstractions.
    * **Namespaces:**  The code is within the `blink` namespace, which is expected for Blink engine code.
    * **Templates:** The use of templates (`template <typename Traits>`) indicates this is a base class or a generic implementation that will be specialized for different encoder types (likely audio and video). The `Traits` template parameter is a strong hint.
    * **Class Definition:** The central class is `EncoderBase`.
    * **Methods:** Look at the public methods like `configure`, `encode`, `close`, `flush`, `reset`. These are the primary entry points for interacting with the encoder.
    * **Callbacks:**  The presence of `output_callback_` and `error_callback_` suggests asynchronous operations and event handling.
    * **State Management:** The `state_` variable and related `ThrowIfCodecState...` functions point to a state machine managing the encoder's lifecycle.
    * **Request Queue:** The `requests_` queue and `ProcessRequests` method suggest asynchronous handling of encoder operations.
    * **Media Encoder:** The `media_encoder_` member variable strongly indicates interaction with a lower-level media encoding implementation.
    * **Tracing and Logging:** Includes for `trace_event` and the `CodecLogger` suggest debugging and performance analysis capabilities.
    * **Error Handling:**  The `HandleError` method and the use of `DOMException` indicate how errors are managed and reported to the JavaScript side.

3. **Deduce Functionality Based on Key Elements:**
    * **WebCodecs Foundation:** The file's location and the included headers clearly place it as a core component of the WebCodecs API implementation within Blink.
    * **Abstraction:**  The template nature implies it provides a common framework for different encoder types, handling shared logic like state management, request queuing, and error handling.
    * **Asynchronous Operations:** The callbacks, request queue, and `flush` method returning a `ScriptPromise` strongly indicate asynchronous processing. Encoding is likely an I/O-bound or computationally intensive task that shouldn't block the main thread.
    * **Lifecycle Management:**  Methods like `configure`, `close`, and `reset` clearly manage the encoder's lifecycle.
    * **Error Handling and Reporting:** The error callback and `DOMException` usage show how errors are propagated back to JavaScript.
    * **Integration with Lower Layers:** The `media_encoder_` suggests an interaction with a platform-specific or more fundamental media encoding library.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The most direct relationship. The `EncoderBase` class is the underlying implementation for JavaScript APIs like `VideoEncoder` and `AudioEncoder`. JavaScript code calls methods like `configure`, `encode`, `flush`, etc., which then invoke the corresponding C++ methods in this file. The callbacks defined in JavaScript are triggered by the C++ code.
    * **HTML:**  HTML provides the context for using these APIs. A `<video>` or `<audio>` element might be the source of data to be encoded, or the destination for the results (though encoding is more about *creating* media). More directly, JavaScript running within an HTML page would instantiate and use the `VideoEncoder` or `AudioEncoder`.
    * **CSS:**  CSS has a less direct relationship. It primarily deals with the presentation of web content. However, CSS might indirectly influence encoding scenarios. For example, if JavaScript is capturing frames from a `<canvas>` element styled with CSS, the rendered content (affected by CSS) would be encoded.

5. **Illustrate with Examples:**
    * **JavaScript:** Provide a simple code snippet showing how to create and use a `VideoEncoder`, calling methods that directly correspond to the C++ methods.
    * **HTML:** Show a basic HTML structure where the JavaScript code might reside.
    * **CSS (Indirect):** Give an example of how CSS might style a canvas that's being encoded.

6. **Reason about Internal Logic (Hypothetical Inputs and Outputs):**
    * **Configuration:**  Explain the flow of the `configure` method, highlighting the state changes and the queuing of the configuration request.
    * **Encoding:** Describe how the `encode` method takes input, clones it, creates a request, and enqueues it. Explain that the *actual* encoding likely happens asynchronously in a lower-level component.
    * **Flushing:** Detail the process of the `flush` method, especially the use of promises to signal completion.

7. **Identify Common User/Programming Errors:**
    * **Incorrect Configuration:**  Point out common mistakes in the configuration parameters.
    * **Encoding Before Configuration:** Explain the state dependency and the error that occurs if `encode` is called prematurely.
    * **Using a Closed Encoder:** Highlight the consequences of trying to use an encoder after it has been closed.

8. **Explain User Actions Leading to This Code:**  Trace the user's steps:
    * Open a webpage using WebCodecs.
    * JavaScript code creates an encoder instance.
    * JavaScript calls `configure`, `encode`, etc.
    * These JavaScript calls trigger the C++ methods in `encoder_base.cc`.

9. **Consider Debugging:**  How would a developer use this information for debugging?
    * Understanding the asynchronous nature of the encoding process.
    * Recognizing the state transitions.
    * Knowing that errors are reported via the error callback.
    * Being aware of the request queue and how it serializes operations.

10. **Structure and Refine:** Organize the information logically using headings and bullet points for clarity. Ensure the language is clear and avoids excessive jargon. Review and refine the explanation for accuracy and completeness. For instance, explicitly mentioning the threading model (main thread vs. media thread) adds valuable context. Also, be precise about what the code *does* vs. what it *orchestrates*. `encoder_base.cc` doesn't perform the low-level encoding itself, but manages the process.
这个文件 `blink/renderer/modules/webcodecs/encoder_base.cc` 是 Chromium Blink 引擎中 WebCodecs API 的基础编码器类。 它为音频编码器 (`AudioEncoder`) 和视频编码器 (`VideoEncoder`) 提供了共享的通用功能。

以下是该文件的主要功能：

**1. 编码器生命周期管理:**

* **状态管理:** 维护编码器的状态 (`state_`)，包括 `unconfigured`（未配置）、`configured`（已配置）和 `closed`（已关闭）。
* **配置:**  提供 `configure()` 方法，用于接收编码配置信息（例如，视频编码的宽度、高度、编解码器；音频编码的采样率、通道数等）。
* **编码:** 提供 `encode()` 方法，用于接收待编码的媒体数据（例如，视频帧、音频缓冲区）。
* **关闭:** 提供 `close()` 方法，用于终止编码器并释放资源。
* **刷新:** 提供 `flush()` 方法，用于确保所有已排队的编码操作都已完成。这通常返回一个 Promise，当刷新完成时 resolve。
* **重置:** 提供 `reset()` 方法，将编码器重置为未配置状态，并取消所有待处理的编码操作。

**2. 异步操作管理:**

* **请求队列:** 使用 `requests_` 队列来管理待处理的编码、配置和刷新请求。这是因为编码操作通常是异步的。
* **处理请求:** `ProcessRequests()` 方法负责从队列中取出请求并执行。
* **阻塞请求:** 使用 `blocking_request_in_progress_` 跟踪当前正在处理的需要等待完成的请求（例如，刷新操作）。
* **回调:** 使用回调函数 (`output_callback_` 和 `error_callback_`) 将编码后的数据和错误信息异步传递给 JavaScript。

**3. 错误处理:**

* **错误回调:** 允许 JavaScript 提供一个错误处理回调函数，当编码过程中发生错误时被调用。
* **内部错误处理:**  `HandleError()` 方法处理内部错误，更新编码器状态，并调用 JavaScript 的错误回调。
* **DOMException:** 使用 `DOMException` 对象来表示错误情况，并传递给 JavaScript。

**4. 资源管理:**

* **ReclaimableCodec:** 继承自 `ReclaimableCodec`，表明该类参与 Chromium 的资源回收机制，当系统内存压力较大时，可以释放编码器占用的资源。

**5. 性能监控和调试:**

* **Trace Event:** 使用 Chromium 的 tracing 机制 (`TRACE_EVENT`) 来记录编码器的操作，方便性能分析和调试。
* **Use Counter:** 使用 `UseCounter` 记录 WebCodecs 功能的使用情况。
* **CodecLogger:** 使用 `CodecLogger` 记录编码器的状态和事件。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件是 WebCodecs API 在 Blink 渲染引擎中的核心实现部分。它直接对应于 JavaScript 中 `VideoEncoder` 和 `AudioEncoder` 接口的功能。

* **JavaScript:**
    * **创建编码器:**  JavaScript 代码会创建 `VideoEncoder` 或 `AudioEncoder` 的实例。这些操作最终会创建 `EncoderBase` 或其子类的 C++ 对象。
    ```javascript
    const encoder = new VideoEncoder({
      output: (chunk) => {
        // 处理编码后的数据
        console.log('Encoded chunk:', chunk);
      },
      error: (e) => {
        // 处理编码错误
        console.error('Encoding error:', e);
      }
    });
    ```
    这里的 `output` 和 `error` 回调函数会保存在 C++ 对象的 `output_callback_` 和 `error_callback_` 成员中。
    * **配置编码器:** JavaScript 调用 `encoder.configure(config)` 会调用 C++ 的 `configure()` 方法。
    ```javascript
    encoder.configure({
      codec: 'vp8',
      width: 640,
      height: 480,
      // ...其他配置
    });
    ```
    * **编码数据:** JavaScript 调用 `encoder.encode(videoFrame)` 会调用 C++ 的 `encode()` 方法。
    ```javascript
    encoder.encode(videoFrame);
    ```
    * **关闭和刷新:** JavaScript 调用 `encoder.close()` 和 `encoder.flush()` 会调用对应的 C++ 方法。
    ```javascript
    encoder.flush().then(() => {
      encoder.close();
    });
    ```
* **HTML:**
    * HTML 提供运行 JavaScript 代码的环境。WebCodecs API 通常用于处理从 `<canvas>` 元素获取的视频帧，或者从用户麦克风获取的音频流。
    ```html
    <video id="inputVideo" autoplay muted></video>
    <script>
      const video = document.getElementById('inputVideo');
      // ... 获取视频流
      const encoder = new VideoEncoder({...});
      encoder.configure({...});
      // ... 从视频流中获取帧并编码
    </script>
    ```
* **CSS:**
    * CSS 对 `encoder_base.cc` 的功能没有直接影响。然而，CSS 可能会影响通过 `<canvas>` 元素捕获的视频帧的内容，从而间接地影响编码结果。例如，CSS 可以改变 canvas 元素的样式、绘制内容等。

**逻辑推理（假设输入与输出）:**

假设 JavaScript 代码创建了一个 `VideoEncoder` 并进行了如下操作：

**假设输入:**

1. **配置 (configure):**
   ```javascript
   encoder.configure({
     codec: 'vp9',
     width: 1280,
     height: 720,
     bitrate: 2000000,
     framerate: 30,
     output: (chunk) => { /* ... */ },
     error: (e) => { /* ... */ }
   });
   ```
   **C++ 处理:** `EncoderBase::configure()` 会接收配置信息，解析配置，并创建一个配置请求加入到 `requests_` 队列。如果编码器当前未配置，则状态会变为 `kConfigured`。

2. **编码 (encode):**
   假设我们有一个 `VideoFrame` 对象 `frame`。
   ```javascript
   encoder.encode(frame);
   ```
   **C++ 处理:** `EncoderBase::encode()` 会接收 `VideoFrame`，克隆它，创建一个编码请求，并将请求添加到 `requests_` 队列。

3. **刷新 (flush):**
   ```javascript
   encoder.flush().then(() => { console.log('Flush completed'); });
   ```
   **C++ 处理:** `EncoderBase::flush()` 会创建一个刷新请求，其中包含一个 Promise resolver，并将请求添加到 `requests_` 队列。当所有之前的编码请求都处理完毕，并且底层编码器也刷新完成后，Promise 会 resolve。

**假设输出:**

* **编码后的数据:**  当 `encode()` 请求被处理后，底层的视频编码器会生成编码后的数据。这些数据会被封装成 `EncodedVideoChunk` 对象，并通过 JavaScript 提供的 `output` 回调函数传递回去。
* **刷新完成信号:** 当 `flush()` 请求被处理后，与该请求关联的 Promise 会 resolve，表示刷新操作已完成。
* **错误:** 如果在配置或编码过程中发生错误（例如，不支持的编解码器），C++ 的 `HandleError()` 会被调用，并通过 JavaScript 提供的 `error` 回调函数报告错误。

**用户或编程常见的使用错误:**

1. **在未配置前调用 `encode()`:**
   * **错误:** `ThrowIfCodecStateUnconfigured` 检查会抛出一个 `TypeError` 异常。
   * **示例 JavaScript:**
     ```javascript
     const encoder = new VideoEncoder({...});
     encoder.encode(videoFrame); // 错误：编码器尚未配置
     ```

2. **多次调用 `configure()` 而没有先 `reset()` 或 `close()`:**
   * **行为:**  `EncoderBase` 允许在某些条件下重新配置，但如果配置变化较大，可能会导致错误或性能问题。代码中会判断 `CanReconfigure`，如果可以重配置，则执行重配置流程，否则会作为新的配置处理。
   * **潜在问题:**  不必要的重新配置可能会导致资源浪费或意外行为。

3. **在编码器已关闭后调用方法:**
   * **错误:** `ThrowIfCodecStateClosed` 检查会抛出一个 `InvalidStateError` 异常。
   * **示例 JavaScript:**
     ```javascript
     const encoder = new VideoEncoder({...});
     encoder.close();
     encoder.encode(videoFrame); // 错误：编码器已关闭
     ```

4. **忘记处理 `error` 回调:**
   * **问题:** 如果编码过程中发生错误，但 JavaScript 没有提供 `error` 回调函数，错误信息可能不会被捕获和处理，导致程序行为异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个使用 WebCodecs 的网页:** 用户在浏览器中访问一个包含使用 WebCodecs API 的 JavaScript 代码的网页。
2. **JavaScript 代码创建 `VideoEncoder` 或 `AudioEncoder` 实例:** 网页上的 JavaScript 代码会创建编码器对象。这会在 Blink 渲染引擎中创建对应的 `EncoderBase` 或其子类的 C++ 对象。
3. **JavaScript 代码调用 `encoder.configure(config)`:**  这会导致 `encoder_base.cc` 中的 `configure()` 方法被调用，配置信息从 JavaScript 传递到 C++。
4. **JavaScript 代码从媒体源获取数据:**  例如，通过 `<canvas>.captureStream()` 或 `getUserMedia()` 获取视频帧或音频数据。
5. **JavaScript 代码调用 `encoder.encode(mediaData)`:** 这会导致 `encoder_base.cc` 中的 `encode()` 方法被调用，待编码的数据被传递到 C++。
6. **Blink 引擎将编码请求添加到队列并处理:** `encoder_base.cc` 管理编码请求队列，并将其传递给底层的媒体编码器。
7. **底层媒体编码器执行编码:**  例如，VideoToolbox (macOS/iOS), MediaCodec (Android), libvpx, FFmpeg 等。
8. **编码完成，数据通过 `output` 回调返回 JavaScript:** 编码后的数据会被封装成 `EncodedVideoChunk` 或类似的对象，并通过之前在 JavaScript 中提供的 `output` 回调函数传递回 JavaScript。
9. **如果发生错误，`error` 回调被调用:**  如果在任何阶段发生错误，`encoder_base.cc` 中的 `HandleError()` 方法会被调用，并通过 JavaScript 提供的 `error` 回调函数报告错误。
10. **JavaScript 代码调用 `encoder.close()` 或 `encoder.reset()`:** 这些操作会调用 `encoder_base.cc` 中相应的 C++ 方法，用于清理资源和重置状态。

**调试线索:**

* **断点:** 可以在 `encoder_base.cc` 中的关键方法（如 `configure`, `encode`, `ProcessRequests`, `HandleError`）设置断点，以跟踪代码执行流程，查看变量的值，例如配置信息、编码状态、请求队列等。
* **日志:**  `LOG()` 宏可以用于在关键路径上输出日志信息，帮助理解代码执行过程。
* **Trace Event:** 使用 Chromium 的 tracing 工具 (chrome://tracing) 可以查看编码器的操作，例如配置、编码、刷新等，以及它们的时间戳，帮助分析性能问题。
* **检查 JavaScript 调用栈:**  当在 C++ 代码中设置断点时，可以查看 JavaScript 的调用栈，了解是从哪个 JavaScript 代码触发了 C++ 代码的执行。
* **检查 WebCodecs API 的使用方式:**  确认 JavaScript 代码正确地使用了 WebCodecs API，例如，在调用 `encode()` 之前是否已经调用了 `configure()`，以及是否正确处理了 `output` 和 `error` 回调。

总而言之，`blink/renderer/modules/webcodecs/encoder_base.cc` 是 WebCodecs API 在 Chromium 中的一个核心组件，负责管理编码器的生命周期、处理异步编码请求、处理错误，并与底层的媒体编码器和 JavaScript 代码进行交互。理解这个文件的功能对于调试 WebCodecs 相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/encoder_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/encoder_base.h"

#include <string>

#include "base/atomic_sequence_num.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_encoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_init.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_encoder.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_state_helper.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/video_encoder.h"
#include "third_party/blink/renderer/platform/bindings/enumeration_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

namespace {
constexpr const char kCategory[] = "media";

base::AtomicSequenceNumber g_sequence_num_for_counters;
}  // namespace

// static
template <typename Traits>
const CodecTraceNames* EncoderBase<Traits>::GetTraceNames() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(CodecTraceNames, trace_names,
                                  (Traits::GetName()));
  return &trace_names;
}

template <typename Traits>
EncoderBase<Traits>::EncoderBase(ScriptState* script_state,
                                 const InitType* init,
                                 ExceptionState& exception_state)
    : ActiveScriptWrappable<EncoderBase<Traits>>({}),
      ReclaimableCodec(ReclaimableCodec::CodecType::kEncoder,
                       ExecutionContext::From(script_state)),
      state_(V8CodecState::Enum::kUnconfigured),
      script_state_(script_state),
      trace_counter_id_(g_sequence_num_for_counters.GetNext()) {
  auto* context = ExecutionContext::From(script_state);
  callback_runner_ = context->GetTaskRunner(TaskType::kInternalMediaRealTime);

  logger_ = std::make_unique<CodecLogger<media::EncoderStatus>>(
      GetExecutionContext(), callback_runner_);

  media::MediaLog* log = logger_->log();
  logger_->SendPlayerNameInformation(*context, Traits::GetName());
  log->SetProperty<media::MediaLogProperty::kFrameUrl>(
      GetExecutionContext()->Url().GetString().Ascii());

  output_callback_ = init->output();
  if (init->hasError())
    error_callback_ = init->error();
}

template <typename Traits>
EncoderBase<Traits>::~EncoderBase() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  base::UmaHistogramSparse(
      String::Format("Blink.WebCodecs.%s.FinalStatus", Traits::GetName())
          .Ascii()
          .c_str(),
      static_cast<int>(logger_->status_code()));
}

template <typename Traits>
void EncoderBase<Traits>::configure(const ConfigType* config,
                                    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (ThrowIfCodecStateClosed(state_, "configure", exception_state))
    return;

  InternalConfigType* parsed_config = ParseConfig(config, exception_state);
  if (!parsed_config) {
    DCHECK(exception_state.HadException());
    return;
  }

  MarkCodecActive();

  Request* request = MakeGarbageCollected<Request>();
  request->reset_count = reset_count_;
  if (active_config_ && state_.AsEnum() == V8CodecState::Enum::kConfigured &&
      CanReconfigure(*active_config_, *parsed_config)) {
    request->type = Request::Type::kReconfigure;
  } else {
    state_ = V8CodecState(V8CodecState::Enum::kConfigured);
    request->type = Request::Type::kConfigure;
  }
  request->config = parsed_config;
  EnqueueRequest(request);
}

template <typename Traits>
void EncoderBase<Traits>::encode(InputType* input,
                                 const EncodeOptionsType* opts,
                                 ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (ThrowIfCodecStateClosed(state_, "encode", exception_state))
    return;

  if (ThrowIfCodecStateUnconfigured(state_, "encode", exception_state))
    return;

  DCHECK(active_config_);

  // This will fail if |input| is already closed.
  // Remove exceptions relating to cloning closed input.
  auto* internal_input = input->clone(IGNORE_EXCEPTION);

  if (!internal_input) {
    exception_state.ThrowTypeError("Cannot encode closed input.");
    return;
  }

  MarkCodecActive();

  Request* request = MakeGarbageCollected<Request>();
  request->reset_count = reset_count_;
  request->type = Request::Type::kEncode;
  request->input = internal_input;
  request->encodeOpts = opts;
  ++requested_encodes_;
  EnqueueRequest(request);
}

template <typename Traits>
void EncoderBase<Traits>::close(ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (ThrowIfCodecStateClosed(state_, "close", exception_state))
    return;

  state_ = V8CodecState(V8CodecState::Enum::kClosed);

  ResetInternal(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "Aborted due to close()"));
  output_callback_.Clear();
  error_callback_.Clear();
}

template <typename Traits>
ScriptPromise<IDLUndefined> EncoderBase<Traits>::flush(
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "flush", exception_state))
    return EmptyPromise();

  if (ThrowIfCodecStateUnconfigured(state_, "flush", exception_state))
    return EmptyPromise();

  MarkCodecActive();

  Request* request = MakeGarbageCollected<Request>();
  request->resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state_);
  request->reset_count = reset_count_;
  request->type = Request::Type::kFlush;
  EnqueueRequest(request);
  return request->resolver->Promise();
}

template <typename Traits>
void EncoderBase<Traits>::reset(ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ThrowIfCodecStateClosed(state_, "reset", exception_state))
    return;

  TRACE_EVENT0(kCategory, GetTraceNames()->reset.c_str());

  state_ = V8CodecState(V8CodecState::Enum::kUnconfigured);
  ResetInternal(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "Aborted due to reset()"));
}

template <typename Traits>
void EncoderBase<Traits>::ResetInternal(DOMException* ex) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  reset_count_++;

  if (blocking_request_in_progress_ &&
      blocking_request_in_progress_->resolver) {
    blocking_request_in_progress_->resolver.Release()->Reject(ex);
  }

  while (!requests_.empty()) {
    Request* pending_req = requests_.TakeFirst();
    DCHECK(pending_req);
    if (pending_req->resolver) {
      pending_req->resolver.Release()->Reject(ex);
    }
    if (pending_req->input) {
      pending_req->input.Release()->close();
    }
  }
  if (requested_encodes_ > 0) {
    requested_encodes_ = 0;
    ScheduleDequeueEvent();
  }

  blocking_request_in_progress_ = nullptr;

  // Schedule deletion of |media_encoder_| for later.
  // ResetInternal() might be called by an error reporting callback called by
  // |media_encoder_|. If we delete it now, this thread might come back up
  // the call stack and continue executing code belonging to deleted
  // |media_encoder_|.
  callback_runner_->DeleteSoon(FROM_HERE, std::move(media_encoder_));

  // This codec isn't holding on to any resources, and doesn't need to be
  // reclaimed.
  ReleaseCodecPressure();
}

template <typename Traits>
void EncoderBase<Traits>::QueueHandleError(DOMException* ex) {
  callback_runner_->PostTask(
      FROM_HERE, WTF::BindOnce(&EncoderBase<Traits>::HandleError,
                               WrapWeakPersistent(this), WrapPersistent(ex)));
}

template <typename Traits>
void EncoderBase<Traits>::HandleError(DOMException* ex) {
  if (state_.AsEnum() == V8CodecState::Enum::kClosed)
    return;

  TRACE_EVENT0(kCategory, GetTraceNames()->handle_error.c_str());

  // Save a temp before we clear the callback.
  V8WebCodecsErrorCallback* error_callback = error_callback_.Get();

  state_ = V8CodecState(V8CodecState::Enum::kClosed);

  ResetInternal(ex);

  // Errors are permanent. Shut everything down.
  error_callback_.Clear();
  output_callback_.Clear();

  // Prevent further logging.
  logger_->Neuter();

  if (!script_state_->ContextIsValid() || !error_callback)
    return;

  ScriptState::Scope scope(script_state_);

  error_callback->InvokeAndReportException(nullptr, ex);
}

template <typename Traits>
void EncoderBase<Traits>::EnqueueRequest(Request* request) {
  requests_.push_back(request);
  ProcessRequests();
}

template <typename Traits>
void EncoderBase<Traits>::ProcessRequests() {
  while (!requests_.empty() && ReadyToProcessNextRequest()) {
    TraceQueueSizes();

    Request* request = requests_.TakeFirst();
    DCHECK(request);
    switch (request->type) {
      case Request::Type::kConfigure:
        ProcessConfigure(request);
        break;
      case Request::Type::kReconfigure:
        ProcessReconfigure(request);
        break;
      case Request::Type::kEncode:
        ProcessEncode(request);
        break;
      case Request::Type::kFlush:
        ProcessFlush(request);
        break;
      default:
        NOTREACHED();
    }
  }

  TraceQueueSizes();
}

template <typename Traits>
bool EncoderBase<Traits>::ReadyToProcessNextRequest() {
  return !blocking_request_in_progress_;
}

template <typename Traits>
void EncoderBase<Traits>::ProcessFlush(Request* request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(state_, V8CodecState::Enum::kConfigured);
  DCHECK(media_encoder_);
  DCHECK_EQ(request->type, Request::Type::kFlush);

  auto done_callback = [](EncoderBase<Traits>* self, Request* req,
                          media::EncoderStatus status) {
    DCHECK(req);

    if (!req->resolver) {
      // Some error occurred and this was resolved earlier.
      return;
    }

    if (!self) {
      req->resolver.Release()->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kAbortError, "Aborted due to close()"));
      req->EndTracing(/*aborted=*/true);
      return;
    }

    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    if (self->reset_count_ != req->reset_count) {
      req->resolver.Release()->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kAbortError, "Aborted due to reset()"));
      req->EndTracing(/*aborted=*/true);
      return;
    }
    if (status.is_ok()) {
      req->resolver.Release()->Resolve();
    } else {
      self->HandleError(self->logger_->MakeEncodingError("Flushing error.",
                                                         std::move(status)));
      DCHECK(!req->resolver);
    }
    req->EndTracing();

    self->blocking_request_in_progress_ = nullptr;
    self->ProcessRequests();
  };

  request->StartTracing();

  blocking_request_in_progress_ = request;
  media_encoder_->Flush(ConvertToBaseOnceCallback(CrossThreadBindOnce(
      done_callback, MakeUnwrappingCrossThreadWeakHandle(this),
      MakeUnwrappingCrossThreadHandle(request))));
}

template <typename Traits>
void EncoderBase<Traits>::OnCodecReclaimed(DOMException* exception) {
  TRACE_EVENT0(kCategory, GetTraceNames()->reclaimed.c_str());
  DCHECK_EQ(state_.AsEnum(), V8CodecState::Enum::kConfigured);
  HandleError(exception);
}

template <typename Traits>
void EncoderBase<Traits>::ContextDestroyed() {
  state_ = V8CodecState(V8CodecState::Enum::kClosed);
  ResetInternal(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kAbortError, "Aborted due to close()"));
  logger_->Neuter();
}

template <typename Traits>
bool EncoderBase<Traits>::HasPendingActivity() const {
  return blocking_request_in_progress_ || !requests_.empty();
}

template <typename Traits>
void EncoderBase<Traits>::TraceQueueSizes() const {
  TRACE_COUNTER_ID2(kCategory, GetTraceNames()->requests_counter.c_str(),
                    trace_counter_id_, "encodes", requested_encodes_, "other",
                    requests_.size() - requested_encodes_);
}

template <typename Traits>
void EncoderBase<Traits>::DispatchDequeueEvent(Event* event) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  probe::AsyncTask async_task(GetExecutionContext(),
                              event->async_task_context());
  dequeue_event_pending_ = false;
  DispatchEvent(*event);
}

template <typename Traits>
void EncoderBase<Traits>::ScheduleDequeueEvent() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (dequeue_event_pending_)
    return;
  dequeue_event_pending_ = true;

  Event* event = Event::Create(event_type_names::kDequeue);
  event->SetTarget(this);
  event->async_task_context()->Schedule(GetExecutionContext(), event->type());

  callback_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&EncoderBase<Traits>::DispatchDequeueEvent,
                    WrapWeakPersistent(this), WrapPersistent(event)));
}

template <typename Traits>
ExecutionContext* EncoderBase<Traits>::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

template <typename Traits>
void EncoderBase<Traits>::Trace(Visitor* visitor) const {
  visitor->Trace(active_config_);
  visitor->Trace(script_state_);
  visitor->Trace(output_callback_);
  visitor->Trace(error_callback_);
  visitor->Trace(requests_);
  visitor->Trace(blocking_request_in_progress_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  ReclaimableCodec::Trace(visitor);
}

template <typename Traits>
void EncoderBase<Traits>::Request::Trace(Visitor* visitor) const {
  visitor->Trace(input);
  visitor->Trace(encodeOpts);
  visitor->Trace(resolver);
  visitor->Trace(config);
}

template <typename Traits>
const char* EncoderBase<Traits>::Request::TraceNameFromType() {
  using RequestType = typename EncoderBase<Traits>::Request::Type;

  const CodecTraceNames* trace_names = EncoderBase<Traits>::GetTraceNames();

  switch (type) {
    case RequestType::kConfigure:
      return trace_names->configure.c_str();
    case RequestType::kEncode:
      return trace_names->encode.c_str();
    case RequestType::kFlush:
      return trace_names->flush.c_str();
    case RequestType::kReconfigure:
      return trace_names->reconfigure.c_str();
  }
  return "InvalidCodecTraceName";
}

template <typename Traits>
void EncoderBase<Traits>::Request::StartTracingVideoEncode(
    bool is_keyframe,
    base::TimeDelta timestamp) {
#if DCHECK_IS_ON()
  DCHECK(!is_tracing);
  is_tracing = true;
#endif
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN2(kCategory, TraceNameFromType(), this,
                                    "key_frame", is_keyframe, "timestamp",
                                    timestamp);
}

template <typename Traits>
void EncoderBase<Traits>::Request::StartTracing() {
#if DCHECK_IS_ON()
  DCHECK(!is_tracing);
  is_tracing = true;
#endif
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(kCategory, TraceNameFromType(), this);
}

template <typename Traits>
void EncoderBase<Traits>::Request::EndTracing(bool aborted) {
#if DCHECK_IS_ON()
  DCHECK(is_tracing);
  is_tracing = false;
#endif
  TRACE_EVENT_NESTABLE_ASYNC_END1(kCategory, TraceNameFromType(), this,
                                  "aborted", aborted);
}

template class EncoderBase<VideoEncoderTraits>;
template class EncoderBase<AudioEncoderTraits>;

}  // namespace blink

"""

```
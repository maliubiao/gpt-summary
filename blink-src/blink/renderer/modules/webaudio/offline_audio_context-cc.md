Response:
Let's break down the thought process for analyzing the `OfflineAudioContext.cc` file. The goal is to extract its functionality, relate it to web technologies, identify logic, pinpoint potential errors, and understand how a user might trigger its execution.

**1. Initial Scan and Keyword Identification:**

The first step is a quick read-through, looking for prominent keywords and structural elements. Things that jump out:

* `OfflineAudioContext`:  The central class, clearly related to audio processing.
* `Create`: Multiple creation methods suggest different ways to instantiate.
* `startOfflineRendering`:  A key function suggesting the core purpose.
* `suspendContext`, `resumeContext`:  Control over the processing lifecycle.
* `FireCompletionEvent`: Signals the end of processing.
* `AudioBuffer`:  A data structure for audio.
* `ScriptPromise`: Indicates asynchronous operations and JavaScript interaction.
* `ExceptionState`:  Error handling mechanism.
* `ExecutionContext`, `LocalDOMWindow`:  Contextual information, linking to the browser environment.
* `V8AudioContextState`:  Internal state management.
* `DeferredTaskHandler`:  Suggests asynchronous or scheduled tasks.
* `OfflineAudioDestinationNode`:  The output point of the audio graph.

**2. Deconstructing Functionality (Method by Method):**

Now, go through each public method and understand its purpose:

* **`Create` methods:**
    * One takes individual parameters (channels, frames, rate). This is a more fundamental creation.
    * The other takes an `OfflineAudioContextOptions` object, providing a structured way to pass parameters from JavaScript. This highlights the connection to JavaScript.
    *  Note the error handling (`ExceptionState`) for invalid parameters.

* **Constructor (`OfflineAudioContext`)**:  Initializes the object, crucially creating the `OfflineAudioDestinationNode`. This signifies the setup of the output.

* **Destructor (`~OfflineAudioContext`)**: Basic cleanup.

* **`Trace`**:  Related to garbage collection, not directly user-facing functionality but important for memory management.

* **`startOfflineRendering`**:
    * This is the *trigger* for the offline processing.
    * It returns a `ScriptPromise`, indicating an asynchronous result (the rendered `AudioBuffer`).
    * It performs several checks: context state, whether rendering has already started. These are crucial for preventing errors.
    * It allocates the `AudioBuffer` that will hold the rendered audio.
    * It initializes and starts the rendering process within the `DestinationHandler`.

* **`suspendContext`**:
    * Allows pausing the rendering at a specific time.
    * Takes a `when` parameter (time in seconds).
    * Performs validation on the `when` parameter (non-negative, not in the past, not beyond the total rendering time).
    *  Uses the `DeferredTaskHandler` to schedule the suspension, implying the processing is not strictly sequential.
    * Returns a `ScriptPromise` that resolves when the suspension occurs.

* **`resumeContext`**:
    * Restarts the rendering after a suspension.
    * Checks if rendering has started and if the context is in a suspendable state.
    * Returns a resolved `ScriptPromise` immediately.

* **`FireCompletionEvent`**:
    * Called when the rendering is finished.
    * Sets the context state to `closed`.
    * Creates an `OfflineAudioCompletionEvent` and dispatches it, making the result available to JavaScript event listeners.
    * Resolves the promise returned by `startOfflineRendering`.

* **`HandlePreRenderTasks`**:
    * Called on the audio thread *before* each rendering quantum.
    * Updates the audio listener and handles deferred tasks.
    * Determines if the context should be suspended based on scheduled suspensions.

* **`HandlePostRenderTasks`**:
    * Called on the audio thread *after* each rendering quantum.
    * Performs cleanup tasks, including breaking connections and deleting handlers.

* **`DestinationHandler`**: A helper function to access the `OfflineAudioDestinationHandler`.

* **`ResolveSuspendOnMainThread`**:
    * Called on the main thread to finalize a suspension.
    * Updates the context state and resolves the corresponding suspension promise.

* **`RejectPendingResolvers`**:
    * Called when the context is being destroyed to reject any pending promises (suspensions, decodes).

* **`IsPullingAudioGraph`**:  Indicates whether the audio graph is actively being processed. It's different from `AudioContext` because `OfflineAudioContext` is driven by `startOfflineRendering`.

* **`ShouldSuspend`**:  Checks if a suspension is scheduled for the current frame (on the audio thread).

* **`HasPendingActivity`**: Indicates if rendering is in progress.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The primary interface. The `Create` methods, `startOfflineRendering`, `suspendContext`, and `resumeContext` are all directly callable from JavaScript. The promises returned by these methods are fundamental to JavaScript's asynchronous programming model. The `OfflineAudioCompletionEvent` is dispatched and can be listened to using JavaScript event listeners.
* **HTML:**  Indirectly related. The `<audio>` and `<video>` elements, along with JavaScript, could provide the source material for offline audio processing.
* **CSS:** No direct relationship. CSS is for styling, while this code deals with audio processing logic.

**4. Logic Inference and Examples:**

* **Suspension Logic:**  The interaction between `suspendContext`, `HandlePreRenderTasks`, `ShouldSuspend`, and `ResolveSuspendOnMainThread` shows a clear sequence for scheduling and executing suspensions.
    * **Input (JavaScript):** `offlineCtx.suspendContext(2.5)`
    * **Internal Processing:** Calculates the target frame, schedules the suspension, and `ShouldSuspend` returns `true` at the calculated frame.
    * **Output (JavaScript):** The promise returned by `suspendContext` resolves.

* **Rendering Process:** `startOfflineRendering` triggers the core processing loop, which continues until the specified length or a suspension point. `FireCompletionEvent` signals the end.

**5. Identifying User/Programming Errors:**

* **Invalid Parameters:**  The `Create` methods have extensive checks for invalid sample rates, number of channels, and number of frames. Example: `new OfflineAudioContext(2, 0, 44100)` would throw an error because `numberOfFrames` is zero.
* **Calling `startOfflineRendering` multiple times:** The code explicitly prevents this and throws an error.
* **Suspending in the past or beyond the rendering time:** The `suspendContext` method includes checks and throws errors for these scenarios.
* **Resuming before starting:**  `resumeContext` checks if rendering has begun.
* **Operating on a closed context:**  Many methods check if the context is closed and throw errors if it is.

**6. Tracing User Actions (Debugging Clues):**

Imagine a user wants to process an audio file offline:

1. **User Interaction (JavaScript):**
   ```javascript
   const audioCtx = new OfflineAudioContext(2, 44100 * 10, 44100); // Creates the context
   fetch('my-audio.mp3')
     .then(response => response.arrayBuffer())
     .then(arrayBuffer => audioCtx.decodeAudioData(arrayBuffer)) // Decodes the audio
     .then(audioBuffer => {
       const source = audioCtx.createBufferSource();
       source.buffer = audioBuffer;
       source.connect(audioCtx.destination);
       source.start();
       return audioCtx.startOfflineRendering(); // Starts the rendering
     })
     .then(renderedBuffer => {
       // Process the renderedBuffer
       console.log('Rendering complete!');
     });
   ```

2. **Blink Engine Processing (C++ - `OfflineAudioContext.cc`):**
   * The `OfflineAudioContext::Create` method is called.
   * `audioCtx.decodeAudioData` (not in this file, but related) processes the audio data.
   * `source.connect(audioCtx.destination)` establishes a connection in the audio graph.
   * `audioCtx.startOfflineRendering()` is called:
     * Checks the context state.
     * Allocates the output buffer.
     * Initializes and starts the rendering thread.
   * The audio thread (not shown in this file directly) processes the audio data.
   * Eventually, `OfflineAudioContext::FireCompletionEvent` is called:
     * The `OfflineAudioCompletionEvent` is dispatched.
     * The promise in the JavaScript code resolves.

**Debugging:**  If something goes wrong (e.g., no output), a developer would:

* **Set breakpoints** in `startOfflineRendering`, `HandlePreRenderTasks`, `HandlePostRenderTasks`, and `FireCompletionEvent` to trace the execution flow.
* **Inspect variables** like `ContextState`, `is_rendering_started_`, and the contents of the `render_target` `AudioBuffer`.
* **Check error logs** for exceptions thrown by `ExceptionState`.
* **Examine the audio graph** to ensure connections are correct.

By following these steps, you can gain a comprehensive understanding of the functionality and context of the `OfflineAudioContext.cc` file.
好的，让我们来详细分析一下 `blink/renderer/modules/webaudio/offline_audio_context.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述**

`OfflineAudioContext.cc` 文件定义了 `OfflineAudioContext` 类，它是 Web Audio API 的一部分，用于在**后台（非实时）**处理音频。与 `AudioContext` 不同，`OfflineAudioContext` 不连接到实际的音频输出设备。它主要用于：

1. **音频渲染和处理：**  在后台模拟音频上下文的运行，执行音频节点的连接、处理，并将最终的音频结果渲染到一个 `AudioBuffer` 对象中。
2. **预处理和生成音频：**  例如，用于音频效果的离线渲染、音频文件的生成或转换。
3. **测试：**  在没有实际音频硬件的情况下测试 Web Audio API 的功能。

**与 JavaScript, HTML, CSS 的关系**

`OfflineAudioContext` 是通过 JavaScript API 暴露给 Web 开发者的。

* **JavaScript:**
    * **创建 `OfflineAudioContext`：**  开发者使用 JavaScript 的 `new OfflineAudioContext(options)` 或 `new OfflineAudioContext(numberOfChannels, length, sampleRate)` 来创建一个离线音频上下文实例。
    * **构建音频图：**  与 `AudioContext` 类似，开发者可以使用 `OfflineAudioContext` 的方法创建各种音频节点（如 `OscillatorNode`, `GainNode`, `BiquadFilterNode` 等），并将它们连接起来形成一个音频处理图。
    * **启动渲染：**  调用 `offlineAudioContext.startRendering()` 方法启动离线渲染过程。这个方法返回一个 `Promise`，当渲染完成后会 resolve，并将渲染结果的 `AudioBuffer` 对象作为参数传递给 resolve 的回调函数。
    * **暂停和恢复渲染：** 提供了 `suspendContext()` 和 `resumeContext()` 方法来控制渲染的生命周期。
    * **完成事件：**  当渲染完成时，会触发 `oncomplete` 事件。

    **示例 (JavaScript):**
    ```javascript
    const offlineCtx = new OfflineAudioContext(2, 44100 * 10, 44100); // 双声道，10秒，采样率 44100Hz
    const oscillator = offlineCtx.createOscillator();
    const gainNode = offlineCtx.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(offlineCtx.destination);

    oscillator.start();

    offlineCtx.startRendering().then(function(renderedBuffer) {
      console.log('Rendering complete!');
      // 可以使用 renderedBuffer 进行后续处理，例如下载或播放
    });
    ```

* **HTML:**  HTML 本身不直接与 `OfflineAudioContext` 交互。但是，JavaScript 代码通常嵌入在 HTML 文件中，并且可以从 HTML 元素（例如 `<audio>` 或 `<video>`) 中获取音频数据用于离线处理。

* **CSS:**  CSS 与 `OfflineAudioContext` 没有直接关系，因为它主要负责页面样式和布局，而 `OfflineAudioContext` 专注于音频处理逻辑。

**逻辑推理 (假设输入与输出)**

假设有以下 JavaScript 代码：

```javascript
const offlineCtx = new OfflineAudioContext(1, 44100, 44100); // 单声道，1秒，采样率 44100Hz
const oscillator = offlineCtx.createOscillator();
oscillator.frequency.setValueAtTime(440, offlineCtx.currentTime); // 设置频率为 440Hz
oscillator.connect(offlineCtx.destination);
oscillator.start();

offlineCtx.startRendering().then(function(renderedBuffer) {
  // renderedBuffer 是一个 AudioBuffer 对象
  console.log('渲染完成，AudioBuffer 长度:', renderedBuffer.length); // 输出应该接近 44100
  console.log('AudioBuffer 采样率:', renderedBuffer.sampleRate); // 输出应该为 44100
  console.log('AudioBuffer 通道数:', renderedBuffer.numberOfChannels); // 输出应该为 1
  // 可以进一步分析 renderedBuffer.getChannelData(0) 获取音频数据
});
```

**假设输入:**

* 创建一个 `OfflineAudioContext`，单声道，长度为 44100 帧（对应 1 秒），采样率为 44100 Hz。
* 创建一个振荡器，频率设置为 440Hz。
* 将振荡器连接到 `OfflineAudioContext` 的 destination。
* 启动振荡器。
* 调用 `startRendering()`。

**预期输出:**

* `startRendering()` 返回的 Promise 会 resolve。
* `renderedBuffer` 是一个 `AudioBuffer` 对象。
* `renderedBuffer.length` 的值接近 44100。
* `renderedBuffer.sampleRate` 的值为 44100。
* `renderedBuffer.numberOfChannels` 的值为 1。
* `renderedBuffer.getChannelData(0)` 将返回一个 Float32Array，其中包含一个 440Hz 正弦波的音频数据。

**用户或编程常见的使用错误**

1. **在 `startRendering()` 之前没有正确构建音频图:** 如果没有将任何音频源连接到 `destination` 节点，`startRendering()` 后得到的 `AudioBuffer` 将是静音的。
   ```javascript
   const offlineCtx = new OfflineAudioContext(1, 44100, 44100);
   offlineCtx.startRendering().then(buffer => {
       console.log("渲染完成，但是缓冲区是静音的");
   });
   ```

2. **多次调用 `startRendering()`:**  `OfflineAudioContext` 只能渲染一次。如果尝试多次调用 `startRendering()`，会抛出一个 `InvalidStateError` 异常。
   ```javascript
   const offlineCtx = new OfflineAudioContext(1, 44100, 44100);
   const oscillator = offlineCtx.createOscillator();
   oscillator.connect(offlineCtx.destination);
   oscillator.start();

   offlineCtx.startRendering();
   offlineCtx.startRendering(); // 错误：InvalidStateError
   ```

3. **在错误的上下文中调用方法:** 例如，在 `OfflineAudioContext` 已经 `closed` 的情况下调用 `startRendering()` 或其他方法。
   ```javascript
   const offlineCtx = new OfflineAudioContext(1, 44100, 44100);
   // ... 渲染过程 ...
   offlineCtx.startRendering().then(() => {
       // ...
       offlineCtx.startRendering(); // 错误：InvalidStateError，因为上下文已经完成
   });
   ```

4. **传递无效的参数给构造函数:** 例如，`numberOfChannels` 或 `length` 为 0 或负数，或者 `sampleRate` 不在允许的范围内。
   ```javascript
   try {
       const offlineCtx = new OfflineAudioContext(0, 44100, 44100); // 错误：通道数不能为 0
   } catch (e) {
       console.error(e);
   }
   ```

5. **在 Worker 线程中使用不当:**  虽然代码注释中提到了 "FIXME: add support for workers"，但在编写时，直接在 Worker 线程中创建和操作 `OfflineAudioContext` 可能存在问题。通常需要在主线程创建，然后传递必要的信息到 Worker 进行处理。

**用户操作是如何一步步的到达这里，作为调试线索**

当 Web 开发者使用 Web Audio API 的 `OfflineAudioContext` 功能时，他们的 JavaScript 代码会最终调用到 Blink 引擎中对应的 C++ 代码。以下是一个典型的用户操作路径：

1. **用户编写 JavaScript 代码:** 开发者在他们的网页或 Web 应用中编写 JavaScript 代码，使用 `new OfflineAudioContext()` 创建一个离线音频上下文实例。
2. **配置音频图:**  开发者使用 `createXXX` 方法创建各种音频节点，并使用 `connect()` 方法将它们连接起来，定义音频处理流程。
3. **启动离线渲染:** 开发者调用 `offlineCtx.startRendering()` 方法。
4. **JavaScript 引擎调用 Blink 绑定代码:**  当 JavaScript 引擎执行到 `startRendering()` 时，它会调用到 Blink 中对应的 JavaScript 绑定代码 (通常在 `v8_offline_audio_context.cc` 中)。
5. **Blink 绑定代码调用 C++ 实现:**  绑定代码会将 JavaScript 的调用转换为对 `OfflineAudioContext.cc` 中 `OfflineAudioContext::startOfflineRendering()` 方法的调用。
6. **C++ 代码执行音频处理:** `startOfflineRendering()` 方法会初始化渲染过程，并在内部驱动音频图的处理，最终将渲染结果写入到一个 `AudioBuffer` 中。
7. **完成事件和 Promise 回调:**  当渲染完成后，`OfflineAudioContext::FireCompletionEvent()` 方法会被调用，它会触发 JavaScript 的 `oncomplete` 事件，并 resolve `startRendering()` 返回的 Promise，将渲染结果传递回 JavaScript 代码。

**调试线索:**

如果开发者在使用 `OfflineAudioContext` 时遇到问题，可以通过以下方式进行调试：

* **在 JavaScript 代码中设置断点:**  查看变量的值，确认音频图是否正确构建，以及 `startRendering()` 是否被正确调用。
* **查看浏览器的开发者工具的控制台:**  检查是否有 JavaScript 错误或异常抛出。
* **使用 `console.log()` 打印中间结果:**  例如，打印音频节点的参数、连接状态等。
* **在 Blink 引擎的 C++ 代码中设置断点:**  如果问题比较底层，可能需要在 `OfflineAudioContext.cc` 或相关的 C++ 文件中设置断点，例如在 `startOfflineRendering()`、`HandlePreRenderTasks()`、`HandlePostRenderTasks()` 和 `FireCompletionEvent()` 等关键方法中，以跟踪代码的执行流程和状态。
* **查看 Chromium 的日志:**  Blink 引擎可能会输出一些调试信息到 Chromium 的日志中。

总而言之，`OfflineAudioContext.cc` 文件是 Web Audio API 离线渲染功能的核心实现，它处理了音频图的构建、渲染过程的控制以及结果的输出，并通过 JavaScript API 暴露给 Web 开发者使用。理解其功能和工作原理对于开发和调试涉及离线音频处理的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webaudio/offline_audio_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2012, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/modules/webaudio/offline_audio_context.h"

#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "media/base/audio_glitch_info.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_offline_audio_context_options.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/webaudio/audio_listener.h"
#include "third_party/blink/renderer/modules/webaudio/deferred_task_handler.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_completion_event.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_destination_node.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

OfflineAudioContext* OfflineAudioContext::Create(
    ExecutionContext* context,
    unsigned number_of_channels,
    unsigned number_of_frames,
    float sample_rate,
    ExceptionState& exception_state) {
  // FIXME: add support for workers.
  auto* window = DynamicTo<LocalDOMWindow>(context);
  if (!window) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Workers are not supported.");
    return nullptr;
  }

  if (context->IsContextDestroyed()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Cannot create OfflineAudioContext on a detached context.");
    return nullptr;
  }

  if (!number_of_frames) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        ExceptionMessages::IndexExceedsMinimumBound<unsigned>(
            "number of frames", number_of_frames, 1));
    return nullptr;
  }

  if (number_of_channels == 0 ||
      number_of_channels > BaseAudioContext::MaxNumberOfChannels()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        ExceptionMessages::IndexOutsideRange<unsigned>(
            "number of channels", number_of_channels, 1,
            ExceptionMessages::kInclusiveBound,
            BaseAudioContext::MaxNumberOfChannels(),
            ExceptionMessages::kInclusiveBound));
    return nullptr;
  }

  if (!audio_utilities::IsValidAudioBufferSampleRate(sample_rate)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        ExceptionMessages::IndexOutsideRange(
            "sampleRate", sample_rate,
            audio_utilities::MinAudioBufferSampleRate(),
            ExceptionMessages::kInclusiveBound,
            audio_utilities::MaxAudioBufferSampleRate(),
            ExceptionMessages::kInclusiveBound));
    return nullptr;
  }

  SCOPED_UMA_HISTOGRAM_TIMER("WebAudio.OfflineAudioContext.CreateTime");
  OfflineAudioContext* audio_context =
      MakeGarbageCollected<OfflineAudioContext>(window, number_of_channels,
                                                number_of_frames, sample_rate,
                                                exception_state);
  audio_context->UpdateStateIfNeeded();

#if DEBUG_AUDIONODE_REFERENCES
  fprintf(stderr, "[%16p]: OfflineAudioContext::OfflineAudioContext()\n",
          audio_context);
#endif
  return audio_context;
}

OfflineAudioContext* OfflineAudioContext::Create(
    ExecutionContext* context,
    const OfflineAudioContextOptions* options,
    ExceptionState& exception_state) {
  OfflineAudioContext* offline_context =
      Create(context, options->numberOfChannels(), options->length(),
             options->sampleRate(), exception_state);

  return offline_context;
}

OfflineAudioContext::OfflineAudioContext(LocalDOMWindow* window,
                                         unsigned number_of_channels,
                                         uint32_t number_of_frames,
                                         float sample_rate,
                                         ExceptionState& exception_state)
    : BaseAudioContext(window, kOfflineContext),
      total_render_frames_(number_of_frames) {
  destination_node_ = OfflineAudioDestinationNode::Create(
      this, number_of_channels, number_of_frames, sample_rate);
  Initialize();
}

OfflineAudioContext::~OfflineAudioContext() {
#if DEBUG_AUDIONODE_REFERENCES
  fprintf(stderr, "[%16p]: OfflineAudioContext::~OfflineAudioContext()\n",
          this);
#endif
}

void OfflineAudioContext::Trace(Visitor* visitor) const {
  visitor->Trace(complete_resolver_);
  visitor->Trace(scheduled_suspends_);
  BaseAudioContext::Trace(visitor);
}

ScriptPromise<AudioBuffer> OfflineAudioContext::startOfflineRendering(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  // Calling close() on an OfflineAudioContext is not supported/allowed,
  // but it might well have been stopped by its execution context.
  // See: crbug.com/435867
  if (IsContextCleared() ||
      ContextState() == V8AudioContextState::Enum::kClosed) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "cannot call startRendering on an OfflineAudioContext in a stopped "
        "state.");
    return EmptyPromise();
  }

  // If the context is not in the suspended state (i.e. running), reject the
  // promise.
  if (ContextState() != V8AudioContextState::Enum::kSuspended) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "cannot startRendering when an OfflineAudioContext is " +
            state().AsString());
    return EmptyPromise();
  }

  // Can't call startRendering more than once.  Return a rejected promise now.
  if (is_rendering_started_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "cannot call startRendering more than once");
    return EmptyPromise();
  }

  DCHECK(!is_rendering_started_);

  complete_resolver_ = MakeGarbageCollected<ScriptPromiseResolver<AudioBuffer>>(
      script_state, exception_state.GetContext());

  // Allocate the AudioBuffer to hold the rendered result.
  float sample_rate = DestinationHandler().SampleRate();
  unsigned number_of_channels = DestinationHandler().NumberOfChannels();

  AudioBuffer* render_target = AudioBuffer::CreateUninitialized(
      number_of_channels, total_render_frames_, sample_rate);

  if (!render_target) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "startRendering failed to create AudioBuffer(" +
            String::Number(number_of_channels) + ", " +
            String::Number(total_render_frames_) + ", " +
            String::Number(sample_rate) + ")");
    return EmptyPromise();
  }

  // Start rendering and return the promise.
  is_rendering_started_ = true;
  SetContextState(V8AudioContextState::Enum::kRunning);
  static_cast<OfflineAudioDestinationNode*>(destination())
      ->SetDestinationBuffer(render_target);
  DestinationHandler().InitializeOfflineRenderThread(render_target);
  DestinationHandler().StartRendering();

  return complete_resolver_->Promise();
}

ScriptPromise<IDLUndefined> OfflineAudioContext::suspendContext(
    ScriptState* script_state,
    double when,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  // If the rendering is finished, reject the promise.
  if (ContextState() == V8AudioContextState::Enum::kClosed) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "the rendering is already finished");
    return EmptyPromise();
  }

  // The specified suspend time is negative; reject the promise.
  if (when < 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "negative suspend time (" + String::Number(when) + ") is not allowed");
    return EmptyPromise();
  }

  // The suspend time should be earlier than the total render frame. If the
  // requested suspension time is equal to the total render frame, the promise
  // will be rejected.
  double total_render_duration = total_render_frames_ / sampleRate();
  if (total_render_duration <= when) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "cannot schedule a suspend at " +
            String::NumberToStringECMAScript(when) +
            " seconds because it is greater than "
            "or equal to the total "
            "render duration of " +
            String::Number(total_render_frames_) + " frames (" +
            String::NumberToStringECMAScript(total_render_duration) +
            " seconds)");
    return EmptyPromise();
  }

  // Find the sample frame and round up to the nearest render quantum
  // boundary.  This assumes the render quantum is a power of two.
  size_t frame = when * sampleRate();
  frame = GetDeferredTaskHandler().RenderQuantumFrames() *
          ((frame + GetDeferredTaskHandler().RenderQuantumFrames() - 1) /
           GetDeferredTaskHandler().RenderQuantumFrames());

  // The specified suspend time is in the past; reject the promise.
  if (frame < CurrentSampleFrame()) {
    size_t current_frame_clamped =
        std::min(CurrentSampleFrame(), static_cast<size_t>(length()));
    double current_time_clamped =
        std::min(currentTime(), length() / static_cast<double>(sampleRate()));
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "suspend(" + String::Number(when) + ") failed to suspend at frame " +
            String::Number(frame) + " because it is earlier than the current " +
            "frame of " + String::Number(current_frame_clamped) + " (" +
            String::Number(current_time_clamped) + " seconds)");
    return EmptyPromise();
  }

  ScriptPromise<IDLUndefined> promise;

  {
    // Wait until the suspend map is available for the insertion. Here we should
    // use GraphAutoLocker because it locks the graph from the main thread.
    DeferredTaskHandler::GraphAutoLocker locker(this);

    // If there is a duplicate suspension at the same quantized frame,
    // reject the promise.
    if (scheduled_suspends_.Contains(frame)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "cannot schedule more than one suspend at frame " +
              String::Number(frame) + " (" + String::Number(when) +
              " seconds)");
      return EmptyPromise();
    }

    auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
        script_state, exception_state.GetContext());
    promise = resolver->Promise();

    scheduled_suspends_.insert(frame, resolver);
  }

  {
    base::AutoLock suspend_frames_locker(suspend_frames_lock_);
    scheduled_suspend_frames_.insert(frame);
  }

  return promise;
}

ScriptPromise<IDLUndefined> OfflineAudioContext::resumeContext(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  // If the rendering has not started, reject the promise.
  if (!is_rendering_started_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "cannot resume an offline context that has not started");
    return EmptyPromise();
  }

  // If the context is in a closed state or it really is closed (cleared),
  // reject the promise.
  if (IsContextCleared() ||
      ContextState() == V8AudioContextState::Enum::kClosed) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "cannot resume a closed offline context");
    return EmptyPromise();
  }

  // If the context is already running, resolve the promise without altering
  // the current state or starting the rendering loop.
  if (ContextState() == V8AudioContextState::Enum::kRunning) {
    return ToResolvedUndefinedPromise(script_state);
  }

  DCHECK_EQ(ContextState(), V8AudioContextState::Enum::kSuspended);

  // If the context is suspended, resume rendering by setting the state to
  // "Running". and calling startRendering(). Note that resuming is possible
  // only after the rendering started.
  SetContextState(V8AudioContextState::Enum::kRunning);
  DestinationHandler().StartRendering();

  // Resolve the promise immediately.
  return ToResolvedUndefinedPromise(script_state);
}

void OfflineAudioContext::FireCompletionEvent() {
  DCHECK(IsMainThread());

  // Context is finished, so remove any tail processing nodes; there's nowhere
  // for the output to go.
  GetDeferredTaskHandler().FinishTailProcessing();

  // We set the state to closed here so that the oncomplete event handler sees
  // that the context has been closed.
  SetContextState(V8AudioContextState::Enum::kClosed);

  // Avoid firing the event if the document has already gone away.
  if (GetExecutionContext()) {
    AudioBuffer* rendered_buffer =
        static_cast<OfflineAudioDestinationNode*>(destination())
            ->DestinationBuffer();
    DCHECK(rendered_buffer);
    if (!rendered_buffer) {
      return;
    }

    // Call the offline rendering completion event listener and resolve the
    // promise too.
    DispatchEvent(*OfflineAudioCompletionEvent::Create(rendered_buffer));
    complete_resolver_->Resolve(rendered_buffer);
  } else {
    // The resolver should be rejected when the execution context is gone.
    complete_resolver_->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError,
        "the execution context does not exist"));
  }

  is_rendering_started_ = false;

  PerformCleanupOnMainThread();
}

bool OfflineAudioContext::HandlePreRenderTasks(
    uint32_t frames_to_process,
    const AudioIOPosition* output_position,
    const AudioCallbackMetric* metric,
    base::TimeDelta playout_delay,
    const media::AudioGlitchInfo& glitch_info) {
  // TODO(hongchan): passing `nullptr` as an argument is not a good
  // pattern. Consider rewriting this method/interface.
  DCHECK_EQ(output_position, nullptr);
  DCHECK_EQ(metric, nullptr);
  DCHECK_EQ(playout_delay, base::TimeDelta());
  DCHECK_EQ(glitch_info, media::AudioGlitchInfo());

  DCHECK(IsAudioThread());

  {
    // OfflineGraphAutoLocker here locks the audio graph for this scope.
    DeferredTaskHandler::OfflineGraphAutoLocker locker(this);
    listener()->Handler().UpdateState();
    GetDeferredTaskHandler().HandleDeferredTasks();
    HandleStoppableSourceNodes();
  }

  return ShouldSuspend();
}

void OfflineAudioContext::HandlePostRenderTasks() {
  DCHECK(IsAudioThread());

  // OfflineGraphAutoLocker here locks the audio graph for the same reason
  // above in `HandlePreRenderTasks()`.
  {
    DeferredTaskHandler::OfflineGraphAutoLocker locker(this);

    GetDeferredTaskHandler().BreakConnections();
    GetDeferredTaskHandler().HandleDeferredTasks();
    GetDeferredTaskHandler().RequestToDeleteHandlersOnMainThread();
  }
}

OfflineAudioDestinationHandler& OfflineAudioContext::DestinationHandler() {
  return static_cast<OfflineAudioDestinationHandler&>(
      destination()->GetAudioDestinationHandler());
}

void OfflineAudioContext::ResolveSuspendOnMainThread(size_t frame) {
  DCHECK(IsMainThread());

  // Suspend the context first. This will fire onstatechange event.
  SetContextState(V8AudioContextState::Enum::kSuspended);

  {
    base::AutoLock locker(suspend_frames_lock_);
    DCHECK(scheduled_suspend_frames_.Contains(frame));
    scheduled_suspend_frames_.erase(frame);
  }

  {
    // Wait until the suspend map is available for the removal.
    DeferredTaskHandler::GraphAutoLocker locker(this);

    // If the context is going away, m_scheduledSuspends could have had all its
    // entries removed.  Check for that here.
    if (scheduled_suspends_.size()) {
      // `frame` must exist in the map.
      DCHECK(scheduled_suspends_.Contains(frame));

      SuspendMap::iterator it = scheduled_suspends_.find(frame);
      it->value->Resolve();

      scheduled_suspends_.erase(it);
    }
  }
}

void OfflineAudioContext::RejectPendingResolvers() {
  DCHECK(IsMainThread());

  {
    base::AutoLock locker(suspend_frames_lock_);
    scheduled_suspend_frames_.clear();
  }

  {
    // Wait until the suspend map is available for removal.
    DeferredTaskHandler::GraphAutoLocker locker(this);

    // Offline context is going away so reject any promises that are still
    // pending.

    for (auto& pending_suspend_resolver : scheduled_suspends_) {
      pending_suspend_resolver.value->Reject(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kInvalidStateError, "Audio context is going away"));
    }

    scheduled_suspends_.clear();
    DCHECK_EQ(pending_promises_resolvers_.size(), 0u);
  }

  RejectPendingDecodeAudioDataResolvers();
}

bool OfflineAudioContext::IsPullingAudioGraph() const {
  DCHECK(IsMainThread());

  // For an offline context, we're rendering only while the context is running.
  // Unlike an AudioContext, there's no audio device that keeps pulling on graph
  // after the context has finished rendering.
  return ContextState() == V8AudioContextState::Enum::kRunning;
}

bool OfflineAudioContext::ShouldSuspend() {
  DCHECK(IsAudioThread());

  base::AutoLock locker(suspend_frames_lock_);
  return scheduled_suspend_frames_.Contains(CurrentSampleFrame());
}

bool OfflineAudioContext::HasPendingActivity() const {
  return is_rendering_started_;
}

}  // namespace blink

"""

```
Response:
My goal is to analyze the provided C++ code snippet from `base_audio_context.cc` and summarize its functionality, relating it to web technologies like JavaScript, HTML, and CSS where applicable. I need to also consider debugging aspects, potential errors, and logical flow. Since this is part 1 of 2, I should focus on summarizing the functions present in this snippet.

Here's a breakdown of the thinking process:

1. **Identify the Core Functionality:** The file is `base_audio_context.cc`, suggesting it's a fundamental class for Web Audio API contexts in Blink. The `#include` directives at the top reveal the dependencies and thus hint at the class's responsibilities. Key includes are `webaudio/*.h`, platform audio, bindings, core DOM, and some utility/base classes. This points to managing the lifecycle, resources, and core operations of an audio context.

2. **Analyze the Constructor and Destructor:**
    * The constructor initializes various members, including `destination_node_`, `task_runner_`, `deferred_task_handler_`, and pre-defined `PeriodicWave` objects. The parameters indicate it's associated with a `LocalDOMWindow`.
    * The destructor ensures proper cleanup, especially the `destination_handler_`, under a graph lock. It also calls `GetDeferredTaskHandler().ContextWillBeDestroyed()`.

3. **Examine Initialization and Uninitialization:**
    * `Initialize()` sets up the `AudioWorklet`, initializes the destination node handler, creates the `AudioListener`, initializes `FFTFrame`, and reports context creation to the inspector. The dependency on `destination_node_` is clear.
    * `Clear()` simply sets a flag `is_cleared_`.
    * `Uninitialize()` reverses the initialization, stopping the audio thread, releasing source nodes, rejecting pending promises, and waiting for HRTF database loading. The order of operations here is important for cleanup.
    * `Dispose()` removes the context from orphan handlers.

4. **Consider Lifecycle Management:**  `ContextLifecycleStateChanged()` handles pausing and resuming the audio context based on the frame's lifecycle state. `ContextDestroyed()` calls the destination handler's equivalent and then uninitializes. `HasPendingActivity()` checks for ongoing tasks from the `AudioWorklet` and the `is_cleared_` flag.

5. **Analyze Audio Buffer Creation and Decoding:**
    * `createBuffer()` creates `AudioBuffer` objects and logs usage statistics.
    * `decodeAudioData()` handles the asynchronous decoding of audio data. It involves detaching the `ArrayBuffer`, creating a promise, and using an `AudioDecoder`. Error handling for detached buffers and transfer failures is present. The `HandleDecodeAudioData` method is called upon completion of the decoding process, resolving or rejecting the promise and invoking callbacks.

6. **Identify Audio Node Creation Methods:**  A large part of the code consists of methods like `createBufferSource`, `createConstantSource`, `createScriptProcessor`, `createStereoPanner`, `createBiquadFilter`, etc. These methods are factories for creating various Web Audio API nodes. They all operate on the main thread.

7. **Examine `createPeriodicWave` and `GetPeriodicWave`:**  These methods deal with creating and retrieving predefined and custom periodic waves for oscillators. The `GetPeriodicWave` method lazily initializes the default waveforms.

8. **Analyze Context State Management:** `state()` returns the current context state, and `SetContextState()` allows changing it, with validation of valid transitions. `NotifyStateChange()` dispatches a `statechange` event.

9. **Investigate Source Node Management:**  `NotifySourceNodeFinishedProcessing()` and `NotifySourceNodeStartedProcessing()` handle the lifecycle of audio source nodes. `ReleaseActiveSourceNodes()` breaks connections. `HandleStoppableSourceNodes()` checks if sources can be stopped.

10. **Consider Main Thread Cleanup:** `PerformCleanupOnMainThread()` handles resolving or rejecting pending resume promises. `ScheduleMainThreadCleanup()` posts a task to the main thread for cleanup.

11. **Analyze Promise Rejection:** `RejectPendingDecodeAudioDataResolvers()` and `RejectPendingResolvers()` handle rejecting pending promises when the context is being closed.

12. **Relate to Web Technologies:**
    * **JavaScript:** The methods in this C++ file are the backend implementation of the Web Audio API's JavaScript interface. JavaScript code uses methods like `createBuffer`, `decodeAudioData`, `createGain`, etc.
    * **HTML:**  The audio context is often created within the context of an HTML document. The interaction with `LocalDOMWindow` highlights this. `<audio>` elements can be connected to the Web Audio API.
    * **CSS:**  CSS has no direct functional relationship with this code, which is about audio processing.

13. **Consider Debugging Aspects:** The code includes logging and inspector integration (`ReportDidCreate`, `ReportWillBeDestroyed`). The state management and promise handling are crucial for understanding asynchronous operations.

14. **Identify Potential Errors:**  The code handles cases like detached `ArrayBuffer`s, failed transfers, and the context being closed. The `ExceptionState` parameter in many methods indicates where errors can be reported.

15. **Infer User Operations:** User actions like creating an audio context in JavaScript, loading audio files, creating and connecting nodes, and suspending/resuming the context will trigger the execution of this C++ code.

16. **Synthesize the Summary:** Based on the above analysis, I can now formulate a concise summary of the file's functionality. I should emphasize its role as the core implementation of the Web Audio API context, managing its lifecycle, resources, and the creation of audio nodes, along with handling asynchronous operations like audio decoding.

This systematic approach ensures that I cover the key aspects of the code and can generate a comprehensive and accurate summary, fulfilling the prompt's requirements.
好的，根据提供的 blink 引擎源代码文件 `blink/renderer/modules/webaudio/base_audio_context.cc` 的内容，我可以归纳一下它的主要功能：

**`BaseAudioContext` 类的核心功能：**

`BaseAudioContext` 类是 Web Audio API 中 `AudioContext` 和 `OfflineAudioContext` 的基类，它负责管理音频处理的生命周期和核心资源。其主要功能可以概括为：

1. **音频上下文生命周期管理:**
   - 初始化（`Initialize`）：创建 `AudioWorklet`，初始化音频输出目标节点（`destination_node_`），创建 `AudioListener`，初始化 FFT。
   - 清理（`Clear`）：标记上下文为已清理状态。
   - 反初始化（`Uninitialize`）：停止音频线程，释放资源，拒绝未完成的 Promise。
   - 销毁（`Dispose`）：清除与孤立处理器的关联。
   - 跟踪帧生命周期（`ContextLifecycleStateChanged`）：根据文档的生命周期状态暂停或恢复音频处理。
   - 判断是否有未完成的活动（`HasPendingActivity`）：检查是否有待处理的任务，例如 `AudioWorklet` 的脚本加载。

2. **音频节点创建工厂:**
   - 提供创建各种音频节点的方法，例如：
     - `createBufferSource()`: 创建音频缓冲区数据源节点。
     - `createConstantSource()`: 创建常量源节点。
     - `createScriptProcessor()`: 创建脚本处理器节点。
     - `createStereoPanner()`: 创建立体声声像器节点。
     - `createBiquadFilter()`: 创建双二阶滤波器节点。
     - `createWaveShaper()`: 创建波形整形器节点。
     - `createPanner()`: 创建空间定位器节点。
     - `createConvolver()`: 创建卷积器节点。
     - `createDynamicsCompressor()`: 创建动态压缩器节点。
     - `createAnalyser()`: 创建分析器节点。
     - `createGain()`: 创建增益节点。
     - `createDelay()`: 创建延迟节点。
     - `createChannelSplitter()`: 创建声道分离器节点。
     - `createChannelMerger()`: 创建声道合并器节点。
     - `createOscillator()`: 创建振荡器节点。
     - `createPeriodicWave()`: 创建周期波形。
     - `createIIRFilter()`: 创建 IIR 滤波器节点。
   - 这些方法负责创建特定类型的音频节点，并将其与当前音频上下文关联。

3. **音频数据处理:**
   - `createBuffer()`: 创建一个空的 `AudioBuffer` 对象。
   - `decodeAudioData()`: 异步解码音频数据，返回一个 `Promise<AudioBuffer>`。涉及到音频数据的传输和错误处理。
   - `HandleDecodeAudioData()`:  处理音频解码完成后的回调，根据解码结果 resolve 或 reject Promise，并执行成功或失败的回调函数。

4. **音频上下文状态管理:**
   - `state()`: 获取当前音频上下文的状态（例如：running, suspended, closed）。
   - `SetContextState()`: 设置音频上下文的状态，并触发状态改变事件。
   - `NotifyStateChange()`:  分发 `statechange` 事件，通知 JavaScript 音频上下文状态已改变。

5. **音频源节点管理:**
   - `NotifySourceNodeFinishedProcessing()`: 通知上下文某个源节点已完成处理。
   - `NotifySourceNodeStartedProcessing()`: 通知上下文某个源节点开始处理。
   - `ReleaseActiveSourceNodes()`: 释放所有激活的源节点。
   - `HandleStoppableSourceNodes()`: 检查可以停止的源节点。

6. **周期波形缓存:**
   - `GetPeriodicWave()`:  缓存并返回预定义的周期波形（正弦波、方波、锯齿波、三角波），避免重复创建。

7. **与渲染线程的交互:**
   - 使用 `DeferredTaskHandler` 处理需要在音频线程和主线程之间同步的任务。
   - `ScheduleMainThreadCleanup()` 和 `PerformCleanupOnMainThread()`：安排并在主线程执行清理操作，例如处理 Promise 的 resolve 和 reject。

8. **错误处理和警告:**
   - `WarnIfContextClosed()`: 如果上下文已关闭，则发出警告。
   - `WarnForConnectionIfContextClosed()`: 如果上下文已关闭后尝试连接节点，则发出警告。
   - 处理 `decodeAudioData` 过程中可能出现的 `DataCloneError` 和 `EncodingError`。

9. **性能监控:**
   - 使用 UMA 记录 `AudioBuffer` 的声道数、长度和采样率等信息，用于性能分析。

**与 JavaScript, HTML, CSS 的关系:**

- **JavaScript:** `BaseAudioContext` 提供的功能是 Web Audio API 的核心组成部分，JavaScript 代码通过创建 `AudioContext` 或 `OfflineAudioContext` 的实例来使用这些功能。例如，JavaScript 调用 `audioCtx.createGain()` 会最终调用到 C++ 层的 `BaseAudioContext::createGain()` 方法。`decodeAudioData` 方法在 JavaScript 中被调用来解码音频文件。
- **HTML:**  HTML 中的 `<audio>` 或 `<video>` 元素可以通过 `HTMLMediaElement.captureStream()` 或 `HTMLMediaElement.createMediaElementSource()` 方法连接到 Web Audio API，这意味着 `BaseAudioContext` 需要能够与这些 HTML 元素进行交互。
- **CSS:**  CSS 与 `BaseAudioContext` 的功能没有直接关系，CSS 主要负责样式和布局，而 `BaseAudioContext` 专注于音频处理。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行以下操作：

```javascript
const audioCtx = new AudioContext();
const buffer = audioCtx.createBuffer(2, 44100, audioCtx.sampleRate);
const source = audioCtx.createBufferSource();
source.buffer = buffer;
const gainNode = audioCtx.createGain();
source.connect(gainNode);
gainNode.connect(audioCtx.destination);
source.start();
```

- **输入:** JavaScript 调用 `audioCtx.createBuffer(2, 44100, audioCtx.sampleRate)`。
- **输出:** `BaseAudioContext::createBuffer()` 方法会被调用，创建一个声道数为 2，帧数为 44100，采样率为 `audioCtx.sampleRate` 的 `AudioBuffer` 对象。

- **输入:** JavaScript 调用 `audioCtx.createGain()`。
- **输出:** `BaseAudioContext::createGain()` 方法会被调用，创建一个 `GainNode` 对象。

- **输入:** JavaScript 调用 `source.connect(gainNode)`。
- **输出:**  虽然这个文件没有直接展示 `connect` 的实现，但可以推断会涉及到在内部的音频图结构中建立连接。

**用户或编程常见的使用错误:**

- **在上下文关闭后创建节点或连接:** 用户可能会在调用 `audioCtx.close()` 后尝试创建新的音频节点或连接现有节点。`BaseAudioContext` 中的 `WarnIfContextClosed()` 和 `WarnForConnectionIfContextClosed()` 方法会发出警告。
- **尝试解码已分离的 ArrayBuffer:** 用户可能会尝试使用已经传递给 `decodeAudioData` 并被分离的 `ArrayBuffer` 进行其他操作，导致错误。`decodeAudioData` 方法会检查 `ArrayBuffer` 的状态并抛出 `DataCloneError`。
- **忘记处理 `decodeAudioData` 的 Promise 失败情况:** 开发者可能没有正确处理 `decodeAudioData` 返回的 Promise 的 `reject` 状态，导致音频解码失败时程序没有相应的处理。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个包含 Web Audio API 使用的网页。**
2. **网页的 JavaScript 代码创建了一个 `AudioContext` 或 `OfflineAudioContext` 对象。** 这会实例化 `BaseAudioContext` (或其子类) 的 C++ 对象。
3. **JavaScript 代码调用 `audioCtx.createBuffer()` 来创建音频缓冲区。** 这会调用 `BaseAudioContext::createBuffer()`。
4. **JavaScript 代码调用 `audioCtx.decodeAudioData()` 来解码音频文件。**  这会调用 `BaseAudioContext::decodeAudioData()`，并可能触发异步解码操作和后续的 `HandleDecodeAudioData()` 调用。
5. **JavaScript 代码创建各种音频节点 (例如 `createGain()`, `createOscillator()`) 并连接它们。** 这些操作会调用 `BaseAudioContext` 中相应的创建节点的方法。
6. **JavaScript 代码控制音频上下文的状态 (例如 `audioCtx.suspend()`, `audioCtx.resume()`, `audioCtx.close()`)。** 这些操作会调用 `BaseAudioContext::SetContextState()` 等方法。

通过查看调用栈，你可以追踪到 JavaScript 代码的哪一部分触发了 `BaseAudioContext` 中的特定方法调用，从而进行调试。例如，如果你在 `BaseAudioContext::createGain()` 中设置断点，当 JavaScript 代码执行 `audioCtx.createGain()` 时，断点会被命中。

**总结 (第1部分功能归纳):**

`blink/renderer/modules/webaudio/base_audio_context.cc` 文件定义了 `BaseAudioContext` 类，它是 Blink 引擎中 Web Audio API 功能的核心实现。它负责音频上下文的生命周期管理、各种音频节点的创建、音频数据的解码和处理、音频上下文状态的管理以及与渲染线程的交互。它为 JavaScript 提供了底层的音频处理能力，是构建复杂 Web Audio 应用的基础。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/base_audio_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/webaudio/base_audio_context.h"

#include <algorithm>

#include "base/metrics/histogram_functions.h"
#include "build/build_config.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_periodic_wave_constraints.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/webaudio/analyser_node.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer_source_node.h"
#include "third_party/blink/renderer/modules/webaudio/audio_context.h"
#include "third_party/blink/renderer/modules/webaudio/audio_graph_tracer.h"
#include "third_party/blink/renderer/modules/webaudio/audio_listener.h"
#include "third_party/blink/renderer/modules/webaudio/audio_node_input.h"
#include "third_party/blink/renderer/modules/webaudio/audio_node_output.h"
#include "third_party/blink/renderer/modules/webaudio/audio_worklet.h"
#include "third_party/blink/renderer/modules/webaudio/audio_worklet_global_scope.h"
#include "third_party/blink/renderer/modules/webaudio/audio_worklet_messaging_proxy.h"
#include "third_party/blink/renderer/modules/webaudio/biquad_filter_node.h"
#include "third_party/blink/renderer/modules/webaudio/channel_merger_node.h"
#include "third_party/blink/renderer/modules/webaudio/channel_splitter_node.h"
#include "third_party/blink/renderer/modules/webaudio/constant_source_node.h"
#include "third_party/blink/renderer/modules/webaudio/convolver_node.h"
#include "third_party/blink/renderer/modules/webaudio/cross_thread_audio_worklet_processor_info.h"
#include "third_party/blink/renderer/modules/webaudio/delay_node.h"
#include "third_party/blink/renderer/modules/webaudio/dynamics_compressor_node.h"
#include "third_party/blink/renderer/modules/webaudio/gain_node.h"
#include "third_party/blink/renderer/modules/webaudio/iir_filter_node.h"
#include "third_party/blink/renderer/modules/webaudio/inspector_web_audio_agent.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_completion_event.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_context.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_destination_node.h"
#include "third_party/blink/renderer/modules/webaudio/oscillator_node.h"
#include "third_party/blink/renderer/modules/webaudio/panner_node.h"
#include "third_party/blink/renderer/modules/webaudio/periodic_wave.h"
#include "third_party/blink/renderer/modules/webaudio/realtime_audio_destination_node.h"
#include "third_party/blink/renderer/modules/webaudio/script_processor_node.h"
#include "third_party/blink/renderer/modules/webaudio/stereo_panner_node.h"
#include "third_party/blink/renderer/modules/webaudio/wave_shaper_node.h"
#include "third_party/blink/renderer/platform/audio/fft_frame.h"
#include "third_party/blink/renderer/platform/audio/hrtf_database_loader.h"
#include "third_party/blink/renderer/platform/audio/iir_filter.h"
#include "third_party/blink/renderer/platform/audio/vector_math.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/uuid.h"

namespace blink {

// Constructor for rendering to the audio hardware.
BaseAudioContext::BaseAudioContext(LocalDOMWindow* window,
                                   enum ContextType context_type)
    : ActiveScriptWrappable<BaseAudioContext>({}),
      ExecutionContextLifecycleStateObserver(window),
      InspectorHelperMixin(*AudioGraphTracer::FromWindow(*window), String()),
      destination_node_(nullptr),
      task_runner_(window->GetTaskRunner(TaskType::kInternalMedia)),
      deferred_task_handler_(DeferredTaskHandler::Create(
          window->GetTaskRunner(TaskType::kInternalMedia))),
      periodic_wave_sine_(nullptr),
      periodic_wave_square_(nullptr),
      periodic_wave_sawtooth_(nullptr),
      periodic_wave_triangle_(nullptr) {}

BaseAudioContext::~BaseAudioContext() {
  {
    // We may need to destroy summing junctions, which must happen while this
    // object is still valid and with the graph lock held.
    DeferredTaskHandler::GraphAutoLocker locker(this);
    destination_handler_ = nullptr;
  }

  GetDeferredTaskHandler().ContextWillBeDestroyed();
}

void BaseAudioContext::Initialize() {
  if (IsDestinationInitialized()) {
    return;
  }

  audio_worklet_ = MakeGarbageCollected<AudioWorklet>(this);

  if (destination_node_) {
    destination_node_->Handler().Initialize();
    // TODO(crbug.com/863951).  The audio thread needs some things from the
    // destination handler like the currentTime.  But the audio thread
    // shouldn't access the `destination_node_` since it's an Oilpan object.
    // Thus, get the destination handler, a non-oilpan object, so we can get
    // the items directly from the handler instead of through the destination
    // node.
    destination_handler_ = &destination_node_->GetAudioDestinationHandler();

    // The AudioParams in the listener need access to the destination node, so
    // only create the listener if the destination node exists.
    listener_ = MakeGarbageCollected<AudioListener>(*this);

    FFTFrame::Initialize(sampleRate());

    // Report the context construction to the inspector.
    ReportDidCreate();
  }
}

void BaseAudioContext::Clear() {
  // Make a note that we've cleared out the context so that there's no pending
  // activity.
  is_cleared_ = true;
}

void BaseAudioContext::Uninitialize() {
  DCHECK(IsMainThread());

  if (!IsDestinationInitialized()) {
    return;
  }

  // Report the inspector that the context will be destroyed.
  ReportWillBeDestroyed();

  // This stops the audio thread and all audio rendering.
  if (destination_node_) {
    destination_node_->Handler().Uninitialize();
  }

  // Remove tail nodes since the context is done.
  GetDeferredTaskHandler().FinishTailProcessing();

  // Get rid of the sources which may still be playing.
  ReleaseActiveSourceNodes();

  // Reject any pending resolvers before we go away.
  RejectPendingResolvers();

  DCHECK(listener_);
  listener_->Handler().WaitForHRTFDatabaseLoaderThreadCompletion();

  Clear();

  DCHECK(!is_resolving_resume_promises_);
  DCHECK_EQ(pending_promises_resolvers_.size(), 0u);
}

void BaseAudioContext::Dispose() {
  // BaseAudioContext is going away, so remove the context from the orphan
  // handlers.
  GetDeferredTaskHandler().ClearContextFromOrphanHandlers();
}

void BaseAudioContext::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  // Don't need to do anything for an offline context.
  if (!HasRealtimeConstraint()) {
    return;
  }

  if (state == mojom::FrameLifecycleState::kRunning) {
    destination()->GetAudioDestinationHandler().Resume();
  } else if (state == mojom::FrameLifecycleState::kFrozen ||
             state == mojom::FrameLifecycleState::kFrozenAutoResumeMedia) {
    destination()->GetAudioDestinationHandler().Pause();
  }
}

void BaseAudioContext::ContextDestroyed() {
  destination()->GetAudioDestinationHandler().ContextDestroyed();
  Uninitialize();
}

bool BaseAudioContext::HasPendingActivity() const {
  // As long as AudioWorklet has a pending task from worklet script loading,
  // the BaseAudioContext needs to stay.
  if (audioWorklet() && audioWorklet()->HasPendingTasks()) {
    return true;
  }

  // There's no pending activity if the audio context has been cleared.
  return !is_cleared_;
}

AudioDestinationNode* BaseAudioContext::destination() const {
  // Cannot be called from the audio thread because this method touches objects
  // managed by Oilpan, and the audio thread is not managed by Oilpan.
  DCHECK(!IsAudioThread());
  return destination_node_.Get();
}

void BaseAudioContext::WarnIfContextClosed(const AudioHandler* handler) const {
  DCHECK(handler);

  if (IsContextCleared() && GetExecutionContext()) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kOther,
            mojom::ConsoleMessageLevel::kWarning,
            "Construction of " + handler->NodeTypeName() +
                " is not useful when context is closed."));
  }
}

void BaseAudioContext::WarnForConnectionIfContextClosed() const {
  if (IsContextCleared() && GetExecutionContext()) {
    GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<
                                             ConsoleMessage>(
        mojom::ConsoleMessageSource::kOther,
        mojom::ConsoleMessageLevel::kWarning,
        "Connecting nodes after the context has been closed is not useful."));
  }
}

AudioBuffer* BaseAudioContext::createBuffer(uint32_t number_of_channels,
                                            uint32_t number_of_frames,
                                            float sample_rate,
                                            ExceptionState& exception_state) {
  // It's ok to call createBuffer, even if the context is closed because the
  // AudioBuffer doesn't really "belong" to any particular context.

  AudioBuffer* buffer = AudioBuffer::Create(
      number_of_channels, number_of_frames, sample_rate, exception_state);

  // Only record the data if the creation succeeded.
  if (buffer) {
    base::UmaHistogramSparse("WebAudio.AudioBuffer.NumberOfChannels",
                             number_of_channels);

    // Arbitrarly limit the maximum length to 1 million frames (about 20 sec
    // at 48kHz).  The number of buckets is fairly arbitrary.
    base::UmaHistogramCounts1M("WebAudio.AudioBuffer.Length", number_of_frames);

    // The limits are the min and max AudioBuffer sample rates currently
    // supported.  We use explicit values here instead of
    // audio_utilities::minAudioBufferSampleRate() and
    // audio_utilities::maxAudioBufferSampleRate().  The number of buckets is
    // fairly arbitrary.
    base::UmaHistogramCustomCounts("WebAudio.AudioBuffer.SampleRate384kHz",
                                   sample_rate, 3000, 384000, 60);

    // Compute the ratio of the buffer rate and the context rate so we know
    // how often the buffer needs to be resampled to match the context.  For
    // the histogram, we multiply the ratio by 100 and round to the nearest
    // integer.  If the context is closed, don't record this because we
    // don't have a sample rate for closed context.
    if (!IsContextCleared()) {
      // The limits are choosen from 100*(3000/384000) = 0.78125 and
      // 100*(384000/3000) = 12800, where 3000 and 384000 are the current
      // min and max sample rates possible for an AudioBuffer.  The number
      // of buckets is fairly arbitrary.
      float ratio = 100 * sample_rate / sampleRate();
      base::UmaHistogramCustomCounts(
          "WebAudio.AudioBuffer.SampleRateRatio384kHz",
          static_cast<int>(0.5 + ratio), 1, 12800, 50);
    }
  }

  return buffer;
}

ScriptPromise<AudioBuffer> BaseAudioContext::decodeAudioData(
    ScriptState* script_state,
    DOMArrayBuffer* audio_data,
    ExceptionState& exception_state) {
  return decodeAudioData(script_state, audio_data, nullptr, nullptr,
                         exception_state);
}

ScriptPromise<AudioBuffer> BaseAudioContext::decodeAudioData(
    ScriptState* script_state,
    DOMArrayBuffer* audio_data,
    V8DecodeSuccessCallback* success_callback,
    ExceptionState& exception_state) {
  return decodeAudioData(script_state, audio_data, success_callback, nullptr,
                         exception_state);
}

ScriptPromise<AudioBuffer> BaseAudioContext::decodeAudioData(
    ScriptState* script_state,
    DOMArrayBuffer* audio_data,
    V8DecodeSuccessCallback* success_callback,
    V8DecodeErrorCallback* error_callback,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());
  DCHECK(audio_data);

  if (!GetExecutionContext()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot decode audio data: The document is no longer active.");
    return EmptyPromise();
  }

  v8::Isolate* isolate = script_state->GetIsolate();
  ArrayBufferContents buffer_contents;
  DOMException* dom_exception = nullptr;
  // Detach the audio array buffer from the main thread and start
  // async decoding of the data.
  if (!audio_data->IsDetachable(isolate) || audio_data->IsDetached()) {
    // If audioData is already detached (neutered) we need to reject the
    // promise with an error.
    dom_exception = MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kDataCloneError,
        "Cannot decode detached ArrayBuffer");
    // Fall through in order to invoke the error_callback.
  } else if (!audio_data->Transfer(isolate, buffer_contents,
                                   IGNORE_EXCEPTION)) {
    // Transfer may throw a TypeError, which is not a DOMException. However, the
    // spec requires throwing a DOMException with kDataCloneError. Hence ignore
    // that exception and throw a DOMException instead.
    // https://webaudio.github.io/web-audio-api/#dom-baseaudiocontext-decodeaudiodata
    dom_exception = MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kDataCloneError, "Cannot transfer the ArrayBuffer");
    // Fall through in order to invoke the error_callback.
  } else {  // audio_data->Transfer succeeded.
    DOMArrayBuffer* audio = DOMArrayBuffer::Create(buffer_contents);

    auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<AudioBuffer>>(
        script_state, exception_state.GetContext());
    auto promise = resolver->Promise();
    decode_audio_resolvers_.insert(resolver);

    audio_decoder_.DecodeAsync(audio, sampleRate(), success_callback,
                               error_callback, resolver, this, exception_state);
    return promise;
  }

  // Forward the exception to the callback.
  DCHECK(dom_exception);
  if (error_callback) {
    error_callback->InvokeAndReportException(this, dom_exception);
  }

  return ScriptPromise<AudioBuffer>::RejectWithDOMException(script_state,
                                                            dom_exception);
}

void BaseAudioContext::HandleDecodeAudioData(
    AudioBuffer* audio_buffer,
    ScriptPromiseResolver<AudioBuffer>* resolver,
    V8DecodeSuccessCallback* success_callback,
    V8DecodeErrorCallback* error_callback,
    ExceptionContext exception_context) {
  DCHECK(IsMainThread());
  DCHECK(resolver);

  ScriptState* resolver_script_state = resolver->GetScriptState();
  if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                     resolver_script_state)) {
    return;
  }
  ScriptState::Scope script_state_scope(resolver_script_state);

  if (audio_buffer) {
    // Resolve promise successfully and run the success callback
    resolver->Resolve(audio_buffer);
    if (success_callback) {
      success_callback->InvokeAndReportException(this, audio_buffer);
    }
  } else {
    // Reject the promise and run the error callback
    auto* dom_exception = MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kEncodingError, "Unable to decode audio data");
    resolver->Reject(dom_exception);
    if (error_callback) {
      error_callback->InvokeAndReportException(this, dom_exception);
    }
  }

  // Resolving a promise above can result in uninitializing/clearing of the
  // context. (e.g. dropping an iframe. See crbug.com/1350086)
  if (is_cleared_) {
    return;
  }

  // Otherwise the resolver should exist in the set. Check and remove it.
  DCHECK(decode_audio_resolvers_.Contains(resolver));
  decode_audio_resolvers_.erase(resolver);
}

AudioBufferSourceNode* BaseAudioContext::createBufferSource(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  AudioBufferSourceNode* node =
      AudioBufferSourceNode::Create(*this, exception_state);

  // Do not add a reference to this source node now. The reference will be added
  // when start() is called.

  return node;
}

ConstantSourceNode* BaseAudioContext::createConstantSource(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ConstantSourceNode::Create(*this, exception_state);
}

ScriptProcessorNode* BaseAudioContext::createScriptProcessor(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ScriptProcessorNode::Create(*this, exception_state);
}

ScriptProcessorNode* BaseAudioContext::createScriptProcessor(
    uint32_t buffer_size,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ScriptProcessorNode::Create(*this, buffer_size, exception_state);
}

ScriptProcessorNode* BaseAudioContext::createScriptProcessor(
    uint32_t buffer_size,
    uint32_t number_of_input_channels,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ScriptProcessorNode::Create(*this, buffer_size,
                                     number_of_input_channels, exception_state);
}

ScriptProcessorNode* BaseAudioContext::createScriptProcessor(
    uint32_t buffer_size,
    uint32_t number_of_input_channels,
    uint32_t number_of_output_channels,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ScriptProcessorNode::Create(
      *this, buffer_size, number_of_input_channels, number_of_output_channels,
      exception_state);
}

StereoPannerNode* BaseAudioContext::createStereoPanner(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return StereoPannerNode::Create(*this, exception_state);
}

BiquadFilterNode* BaseAudioContext::createBiquadFilter(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return BiquadFilterNode::Create(*this, exception_state);
}

WaveShaperNode* BaseAudioContext::createWaveShaper(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return WaveShaperNode::Create(*this, exception_state);
}

PannerNode* BaseAudioContext::createPanner(ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return PannerNode::Create(*this, exception_state);
}

ConvolverNode* BaseAudioContext::createConvolver(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ConvolverNode::Create(*this, exception_state);
}

DynamicsCompressorNode* BaseAudioContext::createDynamicsCompressor(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return DynamicsCompressorNode::Create(*this, exception_state);
}

AnalyserNode* BaseAudioContext::createAnalyser(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return AnalyserNode::Create(*this, exception_state);
}

GainNode* BaseAudioContext::createGain(ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return GainNode::Create(*this, exception_state);
}

DelayNode* BaseAudioContext::createDelay(ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return DelayNode::Create(*this, exception_state);
}

DelayNode* BaseAudioContext::createDelay(double max_delay_time,
                                         ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return DelayNode::Create(*this, max_delay_time, exception_state);
}

ChannelSplitterNode* BaseAudioContext::createChannelSplitter(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ChannelSplitterNode::Create(*this, exception_state);
}

ChannelSplitterNode* BaseAudioContext::createChannelSplitter(
    uint32_t number_of_outputs,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ChannelSplitterNode::Create(*this, number_of_outputs, exception_state);
}

ChannelMergerNode* BaseAudioContext::createChannelMerger(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ChannelMergerNode::Create(*this, exception_state);
}

ChannelMergerNode* BaseAudioContext::createChannelMerger(
    uint32_t number_of_inputs,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return ChannelMergerNode::Create(*this, number_of_inputs, exception_state);
}

OscillatorNode* BaseAudioContext::createOscillator(
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return OscillatorNode::Create(*this, "sine", nullptr, exception_state);
}

PeriodicWave* BaseAudioContext::createPeriodicWave(
    const Vector<float>& real,
    const Vector<float>& imag,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return PeriodicWave::Create(*this, real, imag, false, exception_state);
}

PeriodicWave* BaseAudioContext::createPeriodicWave(
    const Vector<float>& real,
    const Vector<float>& imag,
    const PeriodicWaveConstraints* options,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  bool disable = options->disableNormalization();

  return PeriodicWave::Create(*this, real, imag, disable, exception_state);
}

IIRFilterNode* BaseAudioContext::createIIRFilter(
    Vector<double> feedforward_coef,
    Vector<double> feedback_coef,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  return IIRFilterNode::Create(*this, feedforward_coef, feedback_coef,
                               exception_state);
}

PeriodicWave* BaseAudioContext::GetPeriodicWave(int type) {
  switch (type) {
    case OscillatorHandler::SINE:
      // Initialize the table if necessary
      if (!periodic_wave_sine_) {
        periodic_wave_sine_ = PeriodicWave::CreateSine(sampleRate());
      }
      return periodic_wave_sine_.Get();
    case OscillatorHandler::SQUARE:
      // Initialize the table if necessary
      if (!periodic_wave_square_) {
        periodic_wave_square_ = PeriodicWave::CreateSquare(sampleRate());
      }
      return periodic_wave_square_.Get();
    case OscillatorHandler::SAWTOOTH:
      // Initialize the table if necessary
      if (!periodic_wave_sawtooth_) {
        periodic_wave_sawtooth_ = PeriodicWave::CreateSawtooth(sampleRate());
      }
      return periodic_wave_sawtooth_.Get();
    case OscillatorHandler::TRIANGLE:
      // Initialize the table if necessary
      if (!periodic_wave_triangle_) {
        periodic_wave_triangle_ = PeriodicWave::CreateTriangle(sampleRate());
      }
      return periodic_wave_triangle_.Get();
    default:
      NOTREACHED();
  }
}

V8AudioContextState BaseAudioContext::state() const {
  return V8AudioContextState(control_thread_state_);
}

void BaseAudioContext::SetContextState(V8AudioContextState::Enum new_state) {
  DCHECK(IsMainThread());
  if (!RuntimeEnabledFeatures::AudioContextInterruptedStateEnabled() &&
      new_state == V8AudioContextState::Enum::kInterrupted) {
    return;
  }

  // If there's no change in the current state, there's nothing that needs to be
  // done.
  if (new_state == control_thread_state_) {
    return;
  }

  // Validate the transitions.  The valid transitions are:
  // Suspended ---> Running or Interrupted,
  // Running -----> Suspended or Interrupted,
  // Interrupted -> Running or Suspended,
  // anything ----> Closed.
  switch (new_state) {
    case V8AudioContextState::Enum::kSuspended:
      DCHECK(control_thread_state_ == V8AudioContextState::Enum::kRunning ||
             control_thread_state_ == V8AudioContextState::Enum::kInterrupted);
      break;
    case V8AudioContextState::Enum::kRunning:
      DCHECK(control_thread_state_ == V8AudioContextState::Enum::kSuspended ||
             control_thread_state_ == V8AudioContextState::Enum::kInterrupted);
      break;
    case V8AudioContextState::Enum::kClosed:
      DCHECK_NE(control_thread_state_, V8AudioContextState::Enum::kClosed);
      break;
    case V8AudioContextState::Enum::kInterrupted:
      DCHECK(control_thread_state_ == V8AudioContextState::Enum::kSuspended ||
             control_thread_state_ == V8AudioContextState::Enum::kRunning);
      break;
  }

  control_thread_state_ = new_state;

  if (new_state == V8AudioContextState::Enum::kClosed) {
    GetDeferredTaskHandler().StopAcceptingTailProcessing();
  }

  // Notify context that state changed
  if (GetExecutionContext()) {
    GetExecutionContext()
        ->GetTaskRunner(TaskType::kMediaElementEvent)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&BaseAudioContext::NotifyStateChange,
                                 WrapPersistent(this)));

    GraphTracer().DidChangeBaseAudioContext(this);
  }
}

void BaseAudioContext::NotifyStateChange() {
  DispatchEvent(*Event::Create(event_type_names::kStatechange));
}

void BaseAudioContext::NotifySourceNodeFinishedProcessing(
    AudioHandler* handler) {
  DCHECK(IsAudioThread());

  GetDeferredTaskHandler().GetFinishedSourceHandlers()->push_back(handler);
}

LocalDOMWindow* BaseAudioContext::GetWindow() const {
  return To<LocalDOMWindow>(GetExecutionContext());
}

void BaseAudioContext::NotifySourceNodeStartedProcessing(AudioNode* node) {
  DCHECK(IsMainThread());
  DeferredTaskHandler::GraphAutoLocker locker(this);

  GetDeferredTaskHandler().GetActiveSourceHandlers()->insert(&node->Handler());
  node->Handler().MakeConnection();
}

void BaseAudioContext::ReleaseActiveSourceNodes() {
  DCHECK(IsMainThread());

  DeferredTaskHandler::GraphAutoLocker locker(this);

  for (auto source_handler :
       *GetDeferredTaskHandler().GetActiveSourceHandlers()) {
    source_handler->BreakConnectionWithLock();
  }
}

void BaseAudioContext::HandleStoppableSourceNodes() {
  DCHECK(IsAudioThread());
  AssertGraphOwner();

  HashSet<scoped_refptr<AudioHandler>>* active_source_handlers =
      GetDeferredTaskHandler().GetActiveSourceHandlers();

  if (active_source_handlers->size()) {
    // Find source handlers to see if we can stop playing them.  Note: this
    // check doesn't have to be done every render quantum, if this checking
    // becomes to expensive.  It's ok to do this on a less frequency basis as
    // long as the active nodes eventually get stopped if they're done.
    for (auto handler : *active_source_handlers) {
      switch (handler->GetNodeType()) {
        case AudioHandler::kNodeTypeAudioBufferSource:
        case AudioHandler::kNodeTypeOscillator:
        case AudioHandler::kNodeTypeConstantSource: {
          AudioScheduledSourceHandler* source_handler =
              static_cast<AudioScheduledSourceHandler*>(handler.get());
          source_handler->HandleStoppableSourceNode();
          break;
        }
        default:
          break;
      }
    }
  }
}

void BaseAudioContext::PerformCleanupOnMainThread() {
  DCHECK(IsMainThread());

  // When a posted task is performed, the execution context might be gone.
  if (!GetExecutionContext()) {
    return;
  }

  DeferredTaskHandler::GraphAutoLocker locker(this);

  if (is_resolving_resume_promises_) {
    for (auto& resolver : pending_promises_resolvers_) {
      if (control_thread_state_ == V8AudioContextState::Enum::kClosed) {
        resolver->Reject(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kInvalidStateError,
            "Cannot resume a context that has been closed"));
      } else {
        SetContextState(V8AudioContextState::Enum::kRunning);
        resolver->Resolve();
      }
    }
    pending_promises_resolvers_.clear();
    is_resolving_resume_promises_ = false;
  }

  has_posted_cleanup_task_ = false;
}

void BaseAudioContext::ScheduleMainThreadCleanup() {
  DCHECK(IsAudioThread());

  if (has_posted_cleanup_task_) {
    return;
  }
  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&BaseAudioContext::PerformCleanupOnMainThread,
                          WrapCrossThreadPersistent(this)));
  has_posted_cleanup_task_ = true;
}

void BaseAudioContext::RejectPendingDecodeAudioDataResolvers() {
  // Now reject any pending decodeAudioData resolvers
  for (auto& resolver : decode_audio_resolvers_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "Audio context is going away"));
  }
  decode_audio_resolvers_.clear();
}

void BaseAudioContext::RejectPendingResolvers() {
  DCHECK(IsMainThread());

  // Audio context is closing down so reject any resume promises that are still
  // pending.

  for (auto& resolver : pending_promises_resolvers_) {
    resolver->Reject(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, "Audio context is going away"));
  }
  pending_promises_resolvers_.clear();
  is_resolving_resume_promises_ = false;

  RejectPendingDecodeAudioDataResolvers();
}

const AtomicString& BaseAudioContext::InterfaceName() const {
  return event_target_names::kAudioContext;
}

ExecutionContext* BaseAudioContext::GetExecutionContext() const {
  return ExecutionContextLifecycleStateObserver::GetExecutionContext();
}

void BaseAudioContext::StartRendering() {
  // This is called for both online and offline contexts.  The caller
  // must set the context state appropriately. In particular, resuming
  // a context should wait until the context has actually resumed to
  // set the state.
  DCHECK(IsMainThread());
  DCHECK(destination_node_);

  if (control_thread_state_ == V8AudioContextState::Enum::kSuspended) {
    destination()->GetAudioDestinationHandler().StartRendering();
  }
}

void BaseAudioContext::Trace(Visitor* visitor) const {
  visitor->Trace(destination_node_);
  visitor->Trace(listener_);
  visitor->Trace(pending_promises_resolvers_);
  visitor->Trace(decode_audio_resolvers_);
  visitor->Trace(periodic_wave_sine_);
  visitor->Trace(periodic_wave_square_);
  visitor->Trace(periodic_wave_sawtooth_);
  visitor->Trace(periodic_wave_triangle_);
  visitor->Trace(audio_worklet_);
  InspectorHelperMixin::Trace(visitor);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
}

const SecurityOrigin* BaseAudioContext::GetSecurityOrigin() const {
  if (GetExecutionContext()) {
    return GetExecutionContext()->GetSecurityOrigin();
  }

  return nullptr;
}

AudioWorklet* BaseAudioContext::audioWorklet() const {
  return audio_worklet_.Get();
}

void BaseAudioContext::NotifyWorkletIsReady() {
  DCHECK(IsMainThread());
  DCHECK(audioWorklet()->IsReady());

  {
    // `audio_worklet_thread_` is constantly peeked by the rendering thread,
    // So we protect it with the graph lock.
    DeferredTaskHandler::GraphAutoLocker locker(this);

    // At this point, the WorkletGlobalScope must be ready so it is safe to keep
    // the reference to the AudioWorkletThread for the future worklet operation.
    audio_worklet_thread_ =
        audioWorklet()->GetMessagingProxy()->Get
```
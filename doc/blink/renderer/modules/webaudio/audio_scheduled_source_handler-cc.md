Response:
My thinking process to analyze the C++ code and answer the user's request goes like this:

1. **Understand the Core Functionality:** The filename `audio_scheduled_source_handler.cc` and the class name `AudioScheduledSourceHandler` strongly suggest this code manages the scheduling and playback of audio sources within the Web Audio API. The presence of `Start` and `Stop` methods confirms this.

2. **Identify Key Data Members:** I scanned the class definition for important member variables:
    * `end_time_`:  Likely stores the scheduled stop time. The initial value `kUnknownTime` is also important.
    * `playback_state_`: Manages the current state of the audio source (UNSCHEDULED, SCHEDULED, PLAYING, FINISHED).
    * `start_time_`:  Stores the scheduled start time.
    * `task_runner_`:  Handles asynchronous tasks, likely for the `ended` event.
    * `process_lock_`: Protects shared state accessed during audio processing.

3. **Analyze Key Methods:**  I focused on the most important methods and what they do:
    * **Constructor:** Initializes the object, sets the initial `playback_state_`, and gets a `task_runner_`.
    * **`UpdateSchedulingInfo`:** This is the heart of the scheduling logic. It determines when and how much audio to process based on the current time, start time, and end time. It also handles silencing before and after playback. This method is crucial for understanding how the scheduling works in each audio processing quantum.
    * **`Start`:**  Sets the `start_time_`, changes the `playback_state_` to `SCHEDULED`, and performs error checking. It also handles the case where the start time is in the past.
    * **`Stop`:** Sets the `end_time_`, performs error checking. It allows calling `stop` multiple times.
    * **`FinishWithoutOnEnded`:**  Transitions the source to the `FINISHED_STATE`.
    * **`Finish`:** Calls `FinishWithoutOnEnded` and then posts a task to notify the `ended` event.
    * **`NotifyEnded`:** Dispatches the `ended` event.

4. **Connect to Web Audio API Concepts:** I linked the code to higher-level Web Audio API concepts that developers interact with:
    * **`AudioBufferSourceNode`:** This is the most obvious connection. The code manages the scheduling of its playback.
    * **`start()` and `stop()` methods:**  The C++ `Start` and `Stop` methods directly implement the functionality of the JavaScript methods on `AudioBufferSourceNode` (and other scheduled source nodes).
    * **`ended` event:** The `NotifyEnded` method handles dispatching this event.
    * **`currentTime`:** The `Context()->currentTime()` call connects to the `BaseAudioContext.currentTime` property in JavaScript.

5. **Identify Relationships with HTML, CSS, and JavaScript:**
    * **JavaScript:**  The most direct relationship is with JavaScript. The C++ code *implements* the underlying functionality that JavaScript exposes. I provided concrete examples of how JavaScript calls would translate to actions in this C++ code.
    * **HTML:**  HTML provides the `<audio>` and `<video>` elements, which can be the source of audio data used with the Web Audio API. I included this connection.
    * **CSS:** CSS has no direct functional relationship with this specific C++ file, which deals with audio processing logic.

6. **Reasoning and Examples:**
    * **Logical Reasoning (Assumptions and Outputs):**  I focused on the `UpdateSchedulingInfo` method, as it involves the most logic. I created a scenario with hypothetical start and end times, along with the current time, to illustrate how the method would calculate the offsets and the number of frames to process.
    * **User/Programming Errors:** I considered common mistakes developers make when using the Web Audio API, such as calling `start()` multiple times or calling `stop()` before `start()`. I linked these errors to the exception throwing in the C++ code.

7. **Debugging Clues (User Operations):**  I traced a possible user interaction that could lead to this code being executed. This involved a user triggering the start of an audio source through JavaScript.

8. **Structure and Clarity:** I organized the information into logical sections based on the user's requests (functionality, relationships, reasoning, errors, debugging). I used clear and concise language, avoiding overly technical jargon where possible. I also used code snippets (even if hypothetical in the "reasoning" section) to illustrate the concepts.

9. **Review and Refinement:** I reread my answer to ensure accuracy and completeness, checking for any logical inconsistencies or missing information. I also made sure the examples were relevant and easy to understand.

Essentially, I approached this by dissecting the code, understanding its purpose within the broader Web Audio API context, and then relating it to the developer-facing JavaScript API and common usage patterns. The key was to bridge the gap between the low-level C++ implementation and the high-level concepts that web developers work with.
好的，让我们来详细分析一下 `blink/renderer/modules/webaudio/audio_scheduled_source_handler.cc` 这个文件。

**功能概要:**

`AudioScheduledSourceHandler` 类是 Chromium Blink 引擎中 Web Audio API 的核心组件之一，它主要负责管理可调度音频源节点的生命周期和播放状态。 它的核心功能包括：

1. **管理音频源的调度:**  负责处理音频源的启动 (`start()`) 和停止 (`stop()`) 时间。它会记录并管理音频源计划开始和结束的时间。
2. **控制播放状态:**  维护音频源的当前播放状态 (例如：未调度、已调度、播放中、已结束)。
3. **同步音频处理:**  在音频处理线程中，根据设定的开始和结束时间，决定何时开始和停止产生音频数据。
4. **处理静音:**  在音频源开始播放前或结束后，负责输出静音数据。
5. **触发 "ended" 事件:**  当音频源播放结束后，负责触发 JavaScript 中的 `ended` 事件。
6. **资源管理:**  在音频源开始和结束时，通知 `BaseAudioContext` 进行资源管理（例如，增加/减少活跃源节点的计数）。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件是 Web Audio API 在 Blink 渲染引擎中的实现细节，它直接响应 JavaScript 中对音频源节点的操作。

* **与 JavaScript 的关系:**
    * **`AudioBufferSourceNode.start(when)` 和 `AudioBufferSourceNode.stop(when)`:**  当 JavaScript 代码调用 `AudioBufferSourceNode` (或其他可调度音频源节点，如 `OscillatorNode`) 的 `start()` 和 `stop()` 方法时，最终会调用到 `AudioScheduledSourceHandler` 的 `Start()` 和 `Stop()` 方法。
        ```javascript
        const audioContext = new AudioContext();
        const bufferSource = audioContext.createBufferSource();
        // ... 加载音频 buffer 到 bufferSource.buffer ...
        bufferSource.connect(audioContext.destination);

        // 在特定时间开始播放
        bufferSource.start(audioContext.currentTime + 1); // 1秒后开始
        // 在另一个特定时间停止播放
        bufferSource.stop(audioContext.currentTime + 3); // 3秒后停止
        ```
        在这个例子中，JavaScript 调用 `start()` 和 `stop()` 方法，Blink 引擎内部会将这些调用路由到 `AudioScheduledSourceHandler` 对象的相应方法，设置 `start_time_` 和 `end_time_`。

    * **`ended` 事件:** 当音频源自然播放结束或者被 `stop()` 方法停止后，`AudioScheduledSourceHandler` 会调用 `NotifyEnded()` 方法，该方法会触发 JavaScript 中注册在音频源节点上的 `ended` 事件监听器。
        ```javascript
        bufferSource.onended = function() {
          console.log('音频播放结束');
        };
        ```

* **与 HTML 的关系:**
    * **`<audio>` 标签作为音频源:**  虽然 `AudioScheduledSourceHandler` 不直接处理 HTML 标签，但 Web Audio API 可以将 HTML `<audio>` 元素的音频流作为输入源 (`MediaElementAudioSourceNode`)。  当控制 `<audio>` 元素的播放 (例如通过 JavaScript 调用 `audioElement.play()` 或设置 `currentTime`) 时，可能会间接地影响到与该元素关联的 Web Audio 节点的调度。

* **与 CSS 的关系:**
    * **无直接关系:** CSS 主要负责样式和布局，与音频处理的逻辑没有直接的功能性关联。

**逻辑推理 (假设输入与输出):**

假设我们有一个 `AudioBufferSourceNode`，并且在 JavaScript 中设置了它的开始和结束时间：

**假设输入:**

* `start()` 方法在 `currentTime = 1.0` 秒时被调用，并且 `when` 参数设置为 `1.5` 秒。
* `stop()` 方法在 `currentTime = 2.5` 秒时被调用，并且 `when` 参数设置为 `3.0` 秒。
* 音频上下文的采样率为 48000 Hz。
* 当前音频处理的时间片（quantum）开始于 `currentTime = 1.2` 秒。

**逻辑推理过程:**

1. **`Start()` 方法调用:** 当 `start(1.5)` 被调用时，`AudioScheduledSourceHandler::Start()` 会被执行。`start_time_` 会被设置为 `max(1.5, context.currentTime())`，假设 `context.currentTime()` 大于等于 1.0，则 `start_time_` 为 `1.5` 秒。 `playback_state_` 会被设置为 `SCHEDULED_STATE`。
2. **音频处理 (`UpdateSchedulingInfo()`):** 在音频处理线程中，`UpdateSchedulingInfo()` 会被周期性调用。当 `context.CurrentSampleFrame()` 对应的时间到达 `1.5` 秒时，并且当前处理的音频帧落在 `start_time_` 和 `end_time_` 之间，该音频源的数据才会被处理并输出。
3. **`Stop()` 方法调用:** 当 `stop(3.0)` 被调用时，`AudioScheduledSourceHandler::Stop()` 会被执行。`end_time_` 会被设置为 `3.0` 秒。
4. **音频处理 (继续):**  `UpdateSchedulingInfo()` 会继续检查 `end_time_`。当处理的音频帧对应的时间超过 `3.0` 秒时，`UpdateSchedulingInfo()` 会输出静音数据，并且 `Finish()` 方法会被调用。
5. **`Finish()` 方法调用:** `Finish()` 方法会将 `playback_state_` 设置为 `FINISHED_STATE`，并异步地调用 `NotifyEnded()`。
6. **`NotifyEnded()` 方法调用:** `NotifyEnded()` 方法会在主线程中触发该音频源节点的 `ended` 事件。

**假设输出:**

* 音频源会在时间 `1.5` 秒开始播放。
* 音频源会在时间 `3.0` 秒停止播放。
* 在 JavaScript 中注册的 `ended` 事件监听器会在 `3.0` 秒之后被触发。

**用户或编程常见的使用错误及举例说明:**

1. **多次调用 `start()`:**  如果在一个已经启动过的音频源节点上再次调用 `start()`，`AudioScheduledSourceHandler::Start()` 会抛出一个 `InvalidStateError` 异常。
    ```javascript
    bufferSource.start();
    // 错误：不能在已经启动的节点上再次调用 start()
    bufferSource.start(); // 这会抛出异常
    ```
    C++ 代码中的检查：
    ```c++
    if (GetPlaybackState() != UNSCHEDULED_STATE) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "cannot call start more than once.");
      return;
    }
    ```

2. **在 `start()` 之前调用 `stop()`:** 如果在没有调用 `start()` 的情况下调用 `stop()`，`AudioScheduledSourceHandler::Stop()` 会抛出一个 `InvalidStateError` 异常。
    ```javascript
    const bufferSource = audioContext.createBufferSource();
    // 错误：在没有调用 start() 的情况下调用 stop()
    bufferSource.stop(); // 这会抛出异常
    ```
    C++ 代码中的检查：
    ```c++
    if (GetPlaybackState() == UNSCHEDULED_STATE) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "cannot call stop without calling start first.");
      return;
    }
    ```

3. **传递负数的开始或停止时间:** 如果 `start()` 或 `stop()` 方法传递了负数的 `when` 参数，会抛出一个 `RangeError` 异常。
    ```javascript
    // 错误：开始时间不能为负数
    bufferSource.start(-1); // 这会抛出异常
    ```
    C++ 代码中的检查 (在 `Start()` 和 `Stop()` 方法中都有类似的检查):
    ```c++
    if (when < 0) {
      exception_state.ThrowRangeError(
          ExceptionMessages::IndexExceedsMinimumBound("start time", when, 0.0));
      return;
    }
    ```

**用户操作是如何一步步到达这里的 (作为调试线索):**

假设用户在浏览器中播放一个网页，该网页使用了 Web Audio API 来播放一段音频：

1. **用户加载网页:** 浏览器加载包含 Web Audio API 代码的 HTML、CSS 和 JavaScript 文件。
2. **JavaScript 代码执行:** JavaScript 代码创建 `AudioContext` 对象，并创建一个或多个可调度的音频源节点 (例如 `AudioBufferSourceNode`)。
3. **加载音频数据 (可选):** 如果使用的是 `AudioBufferSourceNode`，JavaScript 代码会加载音频数据到 `AudioBuffer` 对象中，并将该 buffer 赋值给 `bufferSource.buffer`。
4. **设置播放参数:** JavaScript 代码可能会设置音频源节点的其他参数，例如播放速率 (`playbackRate`)、是否循环 (`loop`) 等。
5. **调用 `start()` 方法:**  当需要开始播放音频时，JavaScript 代码调用音频源节点的 `start(when)` 方法，指定开始播放的时间。
    * **调试线索:**  在浏览器开发者工具的 "Sources" 或 "Debugger" 面板中，可以设置断点在 `start()` 方法的调用处，查看 `when` 参数的值以及当时的调用栈。
6. **Blink 引擎处理 `start()` 调用:**  浏览器引擎 (Blink) 接收到 `start()` 调用，并将其路由到对应的 C++ 代码，即 `AudioScheduledSourceHandler::Start()`。
    * **调试线索:** 如果有 Chromium 的调试版本，可以在 `AudioScheduledSourceHandler::Start()` 方法入口处设置断点，查看 `when` 参数的值，以及调用该方法的 JavaScript 代码的位置。
7. **音频处理线程执行:**  随着时间的推移，音频上下文的音频处理线程会周期性地执行。`AudioScheduledSourceHandler::UpdateSchedulingInfo()` 方法会被调用，根据 `start_time_` 和当前的音频处理时间，决定是否开始产生音频数据。
    * **调试线索:**  可以尝试在 `UpdateSchedulingInfo()` 中设置断点，观察 `start_time_`，`end_time_`，以及当前的音频帧信息，来理解音频源的调度逻辑。
8. **调用 `stop()` 方法 (可选):** 如果音频需要在特定时间停止，JavaScript 代码会调用音频源节点的 `stop(when)` 方法。
    * **调试线索:** 类似于 `start()` 方法，可以在 `stop()` 方法的调用处设置断点进行调试。
9. **Blink 引擎处理 `stop()` 调用:**  浏览器引擎将 `stop()` 调用路由到 `AudioScheduledSourceHandler::Stop()`。
10. **触发 `ended` 事件:** 当音频播放结束 (自然结束或被 `stop()` 停止)，`AudioScheduledSourceHandler::Finish()` 和 `NotifyEnded()` 会被调用，最终在 JavaScript 中触发 `ended` 事件。
    * **调试线索:** 可以在 `NotifyEnded()` 方法中设置断点，查看 `ended` 事件是否被正确触发，以及相关的事件监听器是否被执行。

总而言之，`audio_scheduled_source_handler.cc` 文件是 Web Audio API 中负责音频源时间调度的关键 C++ 组件，它响应 JavaScript 的操作，并在音频处理线程中控制音频的播放生命周期和状态，最终驱动音频的产生和 `ended` 事件的触发。理解这个文件有助于深入了解 Web Audio API 的内部工作原理。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_scheduled_source_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webaudio/audio_scheduled_source_handler.h"

#include <algorithm>

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/modules/webaudio/base_audio_context.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

AudioScheduledSourceHandler::AudioScheduledSourceHandler(NodeType node_type,
                                                         AudioNode& node,
                                                         float sample_rate)
    : AudioHandler(node_type, node, sample_rate),
      end_time_(kUnknownTime),
      playback_state_(UNSCHEDULED_STATE) {
  if (Context()->GetExecutionContext()) {
    task_runner_ = Context()->GetExecutionContext()->GetTaskRunner(
        TaskType::kMediaElementEvent);
  }
}

std::tuple<size_t, size_t, double>
AudioScheduledSourceHandler::UpdateSchedulingInfo(size_t quantum_frame_size,
                                                  AudioBus* output_bus) {
  // Set up default values for the three return values.
  size_t quantum_frame_offset = 0;
  size_t non_silent_frames_to_process = 0;
  double start_frame_offset = 0;

  DCHECK(output_bus);
  DCHECK_EQ(
      quantum_frame_size,
      static_cast<size_t>(GetDeferredTaskHandler().RenderQuantumFrames()));

  double sample_rate = Context()->sampleRate();

  // quantumStartFrame     : Start frame of the current time quantum.
  // quantumEndFrame       : End frame of the current time quantum.
  // startFrame            : Start frame for this source.
  // endFrame              : End frame for this source.
  size_t quantum_start_frame = Context()->CurrentSampleFrame();
  size_t quantum_end_frame = quantum_start_frame + quantum_frame_size;

  // Round up if the start_time isn't on a frame boundary so we don't start too
  // early.
  size_t start_frame = audio_utilities::TimeToSampleFrame(
      start_time_, sample_rate, audio_utilities::kRoundUp);
  size_t end_frame = 0;

  if (end_time_ == kUnknownTime) {
    end_frame = 0;
  } else {
    // The end frame is the end time rounded up because it is an exclusive upper
    // bound of the end time.  We also need to take care to handle huge end
    // times and clamp the corresponding frame to the largest size_t value.
    end_frame = audio_utilities::TimeToSampleFrame(end_time_, sample_rate,
                                                   audio_utilities::kRoundUp);
  }

  // If we know the end time and it's already passed, then don't bother doing
  // any more rendering this cycle.
  if (end_time_ != kUnknownTime && end_frame <= quantum_start_frame) {
    Finish();
  }

  PlaybackState state = GetPlaybackState();

  if (state == UNSCHEDULED_STATE || state == FINISHED_STATE ||
      start_frame >= quantum_end_frame) {
    // Output silence.
    output_bus->Zero();
    non_silent_frames_to_process = 0;
    return std::make_tuple(quantum_frame_offset, non_silent_frames_to_process,
                           start_frame_offset);
  }

  // Check if it's time to start playing.
  if (state == SCHEDULED_STATE) {
    // Increment the active source count only if we're transitioning from
    // SCHEDULED_STATE to PLAYING_STATE.
    SetPlaybackState(PLAYING_STATE);
    // Determine the offset of the true start time from the starting frame.
    // NOTE: start_frame_offset is usually negative, but may not be because of
    // the rounding that may happen in computing `start_frame` above.
    start_frame_offset = start_time_ * sample_rate - start_frame;
  } else {
    start_frame_offset = 0;
  }

  quantum_frame_offset =
      start_frame > quantum_start_frame ? start_frame - quantum_start_frame : 0;
  quantum_frame_offset = std::min(quantum_frame_offset,
                                  quantum_frame_size);  // clamp to valid range
  non_silent_frames_to_process = quantum_frame_size - quantum_frame_offset;

  if (!non_silent_frames_to_process) {
    // Output silence.
    output_bus->Zero();
    return std::make_tuple(quantum_frame_offset, non_silent_frames_to_process,
                           start_frame_offset);
  }

  // Handle silence before we start playing.
  // Zero any initial frames representing silence leading up to a rendering
  // start time in the middle of the quantum.
  if (quantum_frame_offset) {
    for (unsigned i = 0; i < output_bus->NumberOfChannels(); ++i) {
      memset(output_bus->Channel(i)->MutableData(), 0,
             sizeof(float) * quantum_frame_offset);
    }
  }

  // Handle silence after we're done playing.
  // If the end time is somewhere in the middle of this time quantum, then zero
  // out the frames from the end time to the very end of the quantum.
  if (end_time_ != kUnknownTime && end_frame >= quantum_start_frame &&
      end_frame < quantum_end_frame) {
    size_t zero_start_frame = end_frame - quantum_start_frame;
    size_t frames_to_zero = quantum_frame_size - zero_start_frame;

    DCHECK_LT(zero_start_frame, quantum_frame_size);
    DCHECK_LE(frames_to_zero, quantum_frame_size);
    DCHECK_LE(zero_start_frame + frames_to_zero, quantum_frame_size);

    bool is_safe = zero_start_frame < quantum_frame_size &&
                   frames_to_zero <= quantum_frame_size &&
                   zero_start_frame + frames_to_zero <= quantum_frame_size;
    if (is_safe) {
      if (frames_to_zero > non_silent_frames_to_process) {
        non_silent_frames_to_process = 0;
      } else {
        non_silent_frames_to_process -= frames_to_zero;
      }

      for (unsigned i = 0; i < output_bus->NumberOfChannels(); ++i) {
        memset(output_bus->Channel(i)->MutableData() + zero_start_frame, 0,
               sizeof(float) * frames_to_zero);
      }
    }

    Finish();
  }

  return std::make_tuple(quantum_frame_offset, non_silent_frames_to_process,
                         start_frame_offset);
}

void AudioScheduledSourceHandler::Start(double when,
                                        ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  Context()->NotifySourceNodeStart();

  if (GetPlaybackState() != UNSCHEDULED_STATE) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "cannot call start more than once.");
    return;
  }

  if (when < 0) {
    exception_state.ThrowRangeError(
        ExceptionMessages::IndexExceedsMinimumBound("start time", when, 0.0));
    return;
  }

  // The node is started. Add a reference to keep us alive so that audio will
  // eventually get played even if Javascript should drop all references to this
  // node. The reference will get dropped when the source has finished playing.
  Context()->NotifySourceNodeStartedProcessing(GetNode());

  SetOnEndedNotificationPending();

  // This synchronizes with process(). updateSchedulingInfo will read some of
  // the variables being set here.
  base::AutoLock process_locker(process_lock_);

  // If `when` < `currentTime()`, the source must start now according to the
  // spec. So just set `start_time_` to `currentTime()` in this case to start
  // the source now.
  start_time_ = std::max(when, Context()->currentTime());

  SetPlaybackState(SCHEDULED_STATE);
}

void AudioScheduledSourceHandler::Stop(double when,
                                       ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (GetPlaybackState() == UNSCHEDULED_STATE) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "cannot call stop without calling start first.");
    return;
  }

  if (when < 0) {
    exception_state.ThrowRangeError(
        ExceptionMessages::IndexExceedsMinimumBound("stop time", when, 0.0));
    return;
  }

  // This synchronizes with process()
  base::AutoLock process_locker(process_lock_);

  // stop() can be called more than once, with the last call to stop taking
  // effect, unless the source has already stopped due to earlier calls to stop.
  // No exceptions are thrown in any case.
  when = std::max(0.0, when);
  end_time_ = when;
}

void AudioScheduledSourceHandler::FinishWithoutOnEnded() {
  if (GetPlaybackState() != FINISHED_STATE) {
    // Let the context dereference this AudioNode.
    Context()->NotifySourceNodeFinishedProcessing(this);
    SetPlaybackState(FINISHED_STATE);
  }
}

void AudioScheduledSourceHandler::Finish() {
  FinishWithoutOnEnded();

  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&AudioScheduledSourceHandler::NotifyEnded,
                          AsWeakPtr()));
}

void AudioScheduledSourceHandler::NotifyEnded() {
  // NotifyEnded is always called when the node is finished, even if
  // there are no event listeners.  We always dispatch the event and
  // let DispatchEvent take are of sending the event to the right
  // place,
  DCHECK(IsMainThread());

  if (GetNode()) {
    DispatchEventResult result =
        GetNode()->DispatchEvent(*Event::Create(event_type_names::kEnded));
    if (result == DispatchEventResult::kCanceledBeforeDispatch) {
      return;
    }
  }
  on_ended_notification_pending_ = false;
}

}  // namespace blink
```
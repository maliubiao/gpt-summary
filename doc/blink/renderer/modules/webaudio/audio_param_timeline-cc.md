Response:
My thinking process for summarizing the provided C++ code snippet goes through several stages:

1. **Identify the Core Purpose:** I immediately recognize keywords like `AudioParamTimeline`, `ParamEvent`, `SetValueAtTime`, `LinearRampToValueAtTime`, etc. These terms strongly suggest this code manages the scheduling and processing of changes to audio parameters over time. The file path `blink/renderer/modules/webaudio/` confirms this is part of the Web Audio API implementation in Chromium's Blink rendering engine.

2. **Break Down Functionality by Examining Key Classes and Methods:**

   * **`AudioParamTimeline` Class:** This is clearly the central class. I look for its key methods and data structures:
      * **`events_`:**  A container (likely a vector or list) storing `ParamEvent` objects. This is the core of the timeline. The `events_lock_` suggests thread safety considerations for accessing this data.
      * **`InsertEvent()`:**  A crucial method for adding new events to the timeline, with logic to handle overlapping or conflicting events. The error checking (`exception_state`) points to API usage validation.
      * **Methods like `SetValueAtTime()`, `LinearRampToValueAtTime()`, etc.:** These correspond directly to JavaScript methods in the Web Audio API for scheduling parameter changes.
      * **`HasValues()`:**  Determines if there are active parameter changes within a given rendering frame.
      * **`CancelScheduledValues()` and `CancelAndHoldAtTime()`:** Methods for modifying the timeline by removing future events.

   * **`ParamEvent` Class:** This class represents a single scheduled change. I look at its members:
      * **`type_`:**  An enum indicating the type of event (e.g., `SetValue`, `LinearRamp`, `SetTarget`).
      * **`value_`, `time_`, `initial_value_`, `time_constant_`, `duration_`:**  Data members storing the parameters of the event.
      * **Static factory methods (`CreateSetValueEvent`, `CreateLinearRampEvent`, etc.):**  A common pattern for creating instances of the class.

3. **Analyze Interactions with JavaScript, HTML, and CSS:**

   * **JavaScript:**  The method names in `AudioParamTimeline` directly mirror the JavaScript methods of `AudioParam` objects in the Web Audio API. This establishes a clear connection. I consider how a JavaScript call like `audioParam.setValueAtTime(1.0, audioContext.currentTime + 2)` would lead to a call to `AudioParamTimeline::SetValueAtTime()`.
   * **HTML:**  While not directly interacting with HTML elements, the Web Audio API is used within the context of a web page loaded by the browser (which is represented by HTML). Audio elements (`<audio>`, `<video>`) can be sources for the Web Audio API.
   * **CSS:**  No direct interaction with CSS is apparent in this code snippet. The Web Audio API primarily deals with audio processing, not visual presentation.

4. **Consider Logical Reasoning and Examples:**

   * **Assumptions:** The code assumes valid input from the JavaScript API. Error handling (`exception_state`) suggests validation checks are in place.
   * **Input/Output:** For `InsertEvent()`, the input is a `ParamEvent` object and the current state of the `events_` list. The output is the modified `events_` list, potentially throwing an exception if there's a conflict.
   * **`HasValues()`:** Input: current frame, sample rate, render quantum size. Output: a boolean indicating if parameter changes need to be applied during that frame.

5. **Identify Potential User/Programming Errors:**

   * **Time Ordering:** Scheduling events with times in the past or out of order can lead to unexpected behavior or errors.
   * **Overlapping Events:**  The code explicitly checks for and throws errors on certain overlapping event types, particularly `SetValueCurve`.
   * **Invalid Parameter Values:**  Providing non-positive durations or time constants (where not allowed) can cause errors.
   * **Incorrect Use of Ramps:** Using ramp functions without a prior `setValueAtTime` can be problematic.

6. **Trace User Operations for Debugging:**

   I imagine a user interacting with a web page that uses the Web Audio API:
   1. **User Action:** Clicks a button or interacts with a control that triggers audio manipulation.
   2. **JavaScript Execution:** JavaScript code uses Web Audio API methods like `audioParam.setValueAtTime()`, `audioParam.linearRampToValueAtTime()`, etc.
   3. **Blink Engine Processing:** These JavaScript calls are translated into calls to the corresponding C++ methods in `AudioParamTimeline`.
   4. **Event Insertion:** The `InsertEvent()` method in `AudioParamTimeline` is called to schedule the parameter change.
   5. **Audio Rendering:** During audio processing, the `HasValues()` method is likely called to determine if there are pending parameter changes. If so, the timeline is consulted to calculate the parameter value at a specific time.

7. **Synthesize a Concise Summary:**  Based on the above analysis, I group the functionality into logical categories:

   * **Core Functionality:** Managing a timeline of audio parameter changes.
   * **Event Handling:** Inserting, storing, and managing different types of parameter change events.
   * **Value Calculation:** Computing parameter values at specific times based on the scheduled events.
   * **Error Handling:** Validating input and preventing conflicting events.
   * **Connection to JavaScript:** Directly implements the behavior exposed by the Web Audio API.

By following this systematic approach, I can effectively analyze and summarize the functionality of the C++ code snippet, including its relationships to web technologies, potential issues, and debugging context. The iterative process of looking at code, identifying purpose, analyzing components, and synthesizing a summary allows for a comprehensive understanding.
## 功能归纳：blink/renderer/modules/webaudio/audio_param_timeline.cc (第1部分)

这个C++源代码文件 (`audio_param_timeline.cc`) 实现了 **Web Audio API 中 `AudioParam` 接口的时间线管理功能**。  简单来说，它的核心职责是 **存储、排序和管理针对音频参数（如音量、频率等）随时间变化的计划事件**。

更具体地说，这个文件中的 `AudioParamTimeline` 类负责：

1. **存储音频参数的计划事件:** 使用一个有序的容器 (`events_`) 来存储不同类型的 `ParamEvent` 对象。每个 `ParamEvent` 代表一个对音频参数值的改变，并包含改变发生的时间、目标值以及其他相关参数（如斜坡的结束值和时间、时间常数等）。

2. **插入新的计划事件:** 提供了各种方法（例如 `SetValueAtTime`, `LinearRampToValueAtTime`, `SetTargetAtTime` 等）来插入不同类型的参数变化事件。  在插入时会进行 **冲突检测**，例如不允许新的事件与现有的 `setValueCurve` 事件重叠，以确保时间线的逻辑一致性。

3. **查询指定时间的参数值:**  虽然这部分代码没有直接展示查询功能，但从其管理时间线事件的方式可以看出，它的目标是能够根据存储的事件，在给定的时间点计算出音频参数的正确值。  后续的部分很可能会实现这个功能。

4. **取消计划事件:** 提供了 `CancelScheduledValues` 和 `CancelAndHoldAtTime` 方法，允许取消未来计划的参数变化。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Chromium 浏览器 Blink 渲染引擎的一部分，它直接服务于 Web Audio API，这是一个可以通过 **JavaScript** 访问的 API。

* **JavaScript:**  Web 开发者使用 JavaScript 调用 `AudioParam` 对象的方法 (例如 `audioParam.setValueAtTime()`, `audioParam.linearRampToValueAtTime()`) 来安排音频参数的变化。 这些 JavaScript 调用最终会映射到 `AudioParamTimeline` 类的相应 C++ 方法上，将事件添加到时间线中。

   **举例:**  JavaScript 代码 `gainNode.gain.setValueAtTime(0.5, audioContext.currentTime + 1);`  会最终导致 `AudioParamTimeline::SetValueAtTime(0.5, audioContext.currentTime + 1, ...)` 在 C++ 代码中被调用，创建一个 `ParamEvent::kSetValue` 事件并插入到时间线中。

* **HTML:**  HTML 提供了 `<audio>` 和 `<video>` 标签，它们可以作为 Web Audio API 的音频源。虽然这个文件本身不直接操作 HTML 元素，但它所管理的时间线是控制这些音频源播放效果的关键部分。

   **举例:**  HTML 中有一个 `<audio>` 元素，JavaScript 代码可以通过 Web Audio API 创建一个音频图，将这个音频元素的输出连接到一个增益节点（GainNode），并使用 `AudioParamTimeline` 来控制增益节点 `gain` 参数随时间的变化，实现音量淡入淡出的效果。

* **CSS:**  **这个文件与 CSS 没有直接关系。** Web Audio API 主要负责音频处理和合成，而 CSS 主要负责页面的样式和布局。

**逻辑推理 (假设输入与输出):**

假设 `events_` 当前为空，并且我们调用了以下 JavaScript 代码：

```javascript
const audioCtx = new AudioContext();
const oscillator = audioCtx.createOscillator();
const gainNode = audioCtx.createGain();
oscillator.connect(gainNode);
gainNode.connect(audioCtx.destination);
oscillator.start();

gainNode.gain.setValueAtTime(0, audioCtx.currentTime);
gainNode.gain.linearRampToValueAtTime(1, audioCtx.currentTime + 2);
```

**假设输入:**  `AudioParamTimeline` 实例为空， `audioCtx.currentTime` 为 0。

**逻辑推理过程:**

1. 调用 `gainNode.gain.setValueAtTime(0, 0)` 会导致 `AudioParamTimeline::SetValueAtTime(0, 0, ...)` 被调用。
2. `InsertEvent` 方法会创建一个 `ParamEvent::kSetValue` 事件，时间为 0，值为 0，并将其插入到 `events_` 列表中。
3. 调用 `gainNode.gain.linearRampToValueAtTime(1, 2)` 会导致 `AudioParamTimeline::LinearRampToValueAtTime(1, 2, 0, 0, ...)` 被调用（这里假设 `initial_value` 和 `call_time` 为 0）。
4. `InsertEvent` 方法会创建一个 `ParamEvent::kLinearRampToValue` 事件，时间为 2，值为 1，并将其插入到 `events_` 列表中。 由于 `events_` 中已经有一个时间为 0 的事件，新的事件会被插入到其后，保持时间线的有序性。

**假设输出 (events_ 的状态):**

`events_` 列表中包含两个 `ParamEvent` 对象：

1. `ParamEvent::kSetValue`， `time_ = 0`, `value_ = 0`
2. `ParamEvent::kLinearRampToValue`， `time_ = 2`, `value_ = 1`, `initial_value_ = 0`, `call_time_ = 0`

**用户或编程常见的使用错误：**

1. **时间参数错误:**  例如，将一个事件的时间设置为负数，或者后一个事件的时间早于前一个事件的时间。  代码中可以看到 `IsNonNegativeAudioParamTime` 函数用于检查时间参数是否有效，并在出现错误时抛出异常。

   **举例:**  `gainNode.gain.setValueAtTime(0.5, -1);`  会导致 `IsNonNegativeAudioParamTime` 抛出 `RangeError` 异常。

2. **`exponentialRampToValueAtTime` 的目标值为 0:**  代码中明确指出 `exponentialRampToValueAtTime` 的目标值不应为 0，否则会抛出 `RangeError`。这是因为指数斜坡在目标值为 0 时行为不明确。

   **举例:**  `gainNode.gain.exponentialRampToValueAtTime(0, audioContext.currentTime + 1);` 会抛出 `RangeError`。

3. **`setValueCurveAtTime` 的曲线长度小于 2:**  `setValueCurveAtTime` 需要至少两个点来定义曲线，否则会抛出 `InvalidStateError`。

   **举例:** `gainNode.gain.setValueCurveAtTime([0.5], audioContext.currentTime, 1);` 会抛出 `InvalidStateError`。

4. **事件重叠:**  某些类型的事件（特别是 `setValueCurve`）不允许重叠。  如果尝试安排一个与现有 `setValueCurve` 重叠的事件，将会抛出 `NotSupportedError`。

   **举例:**  先执行 `gainNode.gain.setValueCurveAtTime([0, 1], audioContext.currentTime, 2);`，然后再执行 `gainNode.gain.setValueAtTime(0.5, audioContext.currentTime + 1);` 会导致错误，因为 `setValueAtTime` 事件发生在 `setValueCurveAtTime` 事件的中间。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码使用了 Web Audio API。**
3. **JavaScript 代码创建了一个 `AudioContext` 对象。**
4. **JavaScript 代码获取了一个 `AudioParam` 对象，例如通过 `gainNode.gain` 获取增益节点的 gain 参数。**
5. **JavaScript 代码调用了 `AudioParam` 对象上的时间线控制方法，例如 `setValueAtTime()`, `linearRampToValueAtTime()` 等。**
6. **浏览器引擎（Blink）接收到这些 JavaScript 调用。**
7. **Blink 将这些 JavaScript 调用映射到 `AudioParamTimeline` 类的相应 C++ 方法。**
8. **`AudioParamTimeline` 类的方法被执行，例如 `InsertEvent()` 被调用，将新的 `ParamEvent` 添加到 `events_` 列表中。**

**作为调试线索：**  如果开发者在使用 Web Audio API 时遇到了音频参数行为异常的问题，例如音量变化不符合预期，可以：

* **检查 JavaScript 代码中对 `AudioParam` 方法的调用，确认时间参数和目标值是否正确。**
* **使用浏览器的开发者工具查看 Web Audio API 的状态，例如是否有报错信息。**
* **如果需要深入调试 Blink 引擎本身，可以设置断点在 `AudioParamTimeline` 类的相关方法上，例如 `InsertEvent()`，来观察事件是如何被添加和管理的，以及是否存在冲突或错误。**
* **查看 `ParamEvent` 的类型和参数，确认事件是否被正确创建和存储。**

**第1部分功能归纳:**

总而言之，`blink/renderer/modules/webaudio/audio_param_timeline.cc` 的第 1 部分主要负责 **构建和维护 `AudioParam` 的事件时间线**，包括存储、插入和初步的冲突检测，为后续的音频渲染过程提供参数变化的计划信息。它直接响应 JavaScript 中对 Web Audio API 的调用，并将这些调用转换为内部的事件表示。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_param_timeline.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webaudio/audio_param_timeline.h"

#include <algorithm>
#include <limits>
#include <memory>

#include "base/memory/ptr_util.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/audio/vector_math.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/fdlibm/ieee754.h"

#if defined(ARCH_CPU_X86_FAMILY)
#include <emmintrin.h>
#endif

namespace blink {

namespace {

// For a SetTarget event, we want the event to terminate eventually so that we
// can stop using the timeline to compute the values.  See
// `HasSetTargetConverged()` for the algorithm.  `kSetTargetThreshold` is
// exp(-`kTimeConstantsToConverge`).
constexpr float kTimeConstantsToConverge = 10.0f;
constexpr float kSetTargetThreshold = 4.539992976248485e-05f;

bool IsNonNegativeAudioParamTime(double time,
                                 ExceptionState& exception_state,
                                 String message = "Time") {
  if (time >= 0) {
    return true;
  }

  exception_state.ThrowRangeError(
      message +
      " must be a finite non-negative number: " + String::Number(time));
  return false;
}

bool IsPositiveAudioParamTime(double time,
                              ExceptionState& exception_state,
                              String message) {
  if (time > 0) {
    return true;
  }

  exception_state.ThrowRangeError(
      message + " must be a finite positive number: " + String::Number(time));
  return false;
}

// Test that for a SetTarget event, the current value is close enough
// to the target value that we can consider the event to have
// converged to the target.
bool HasSetTargetConverged(float value,
                           float target,
                           double current_time,
                           double start_time,
                           double time_constant) {
  // Converged if enough time constants (`kTimeConstantsToConverge`) have passed
  // since the start of the event.
  if (current_time > start_time + kTimeConstantsToConverge * time_constant) {
    return true;
  }

  // If `target` is 0, converged if |`value`| is less than
  // `kSetTargetThreshold`.
  if (target == 0 && fabs(value) < kSetTargetThreshold) {
    return true;
  }

  // If `target` is not zero, converged if relative difference between `value`
  // and `target` is small.  That is |`target`-`value`|/|`value`| <
  // `kSetTargetThreshold`.
  if (target != 0 && fabs(target - value) < kSetTargetThreshold * fabs(value)) {
    return true;
  }

  return false;
}

}  // namespace

String AudioParamTimeline::EventToString(const ParamEvent& event) const {
  // The default arguments for most automation methods is the value and the
  // time.
  String args =
      String::Number(event.Value()) + ", " + String::Number(event.Time(), 16);

  // Get a nice printable name for the event and update the args if necessary.
  String s;
  switch (event.GetType()) {
    case ParamEvent::kSetValue:
      s = "setValueAtTime";
      break;
    case ParamEvent::kLinearRampToValue:
      s = "linearRampToValueAtTime";
      break;
    case ParamEvent::kExponentialRampToValue:
      s = "exponentialRampToValue";
      break;
    case ParamEvent::kSetTarget:
      s = "setTargetAtTime";
      // This has an extra time constant arg
      args = args + ", " + String::Number(event.TimeConstant(), 16);
      break;
    case ParamEvent::kSetValueCurve:
      s = "setValueCurveAtTime";
      // Replace the default arg, using "..." to denote the curve argument.
      args = "..., " + String::Number(event.Time(), 16) + ", " +
             String::Number(event.Duration(), 16);
      break;
    case ParamEvent::kCancelValues:
    case ParamEvent::kSetValueCurveEnd:
    // Fall through; we should never have to print out the internal
    // `kCancelValues` or `kSetValueCurveEnd` event.
    case ParamEvent::kLastType:
      NOTREACHED();
  };

  return s + "(" + args + ")";
}

// Computes the value of a linear ramp event at time t with the given event
// parameters.
float AudioParamTimeline::LinearRampAtTime(double t,
                                           float value1,
                                           double time1,
                                           float value2,
                                           double time2) {
  return value1 + (value2 - value1) * (t - time1) / (time2 - time1);
}

// Computes the value of an exponential ramp event at time t with the given
// event parameters.
float AudioParamTimeline::ExponentialRampAtTime(double t,
                                                float value1,
                                                double time1,
                                                float value2,
                                                double time2) {
  DCHECK(!std::isnan(value1) && std::isfinite(value1));
  DCHECK(!std::isnan(value2) && std::isfinite(value2));

  return (value1 == 0.0f || std::signbit(value1) != std::signbit(value2))
      ? value1
      : value1 * fdlibm::pow(value2 / value1, (t - time1) / (time2 - time1));
}

// Compute the value of a set target event at time t with the given event
// parameters.
float AudioParamTimeline::TargetValueAtTime(double t,
                                            float value1,
                                            double time1,
                                            float value2,
                                            float time_constant) {
  return value2 + (value1 - value2) * fdlibm::exp(-(t - time1) / time_constant);
}

// Compute the value of a set curve event at time t with the given event
// parameters.
float AudioParamTimeline::ValueCurveAtTime(double t,
                                           double time1,
                                           double duration,
                                           const float* curve_data,
                                           unsigned curve_length) {
  double curve_index = (curve_length - 1) / duration * (t - time1);
  unsigned k = std::min(static_cast<unsigned>(curve_index), curve_length - 1);
  unsigned k1 = std::min(k + 1, curve_length - 1);
  float c0 = curve_data[k];
  float c1 = curve_data[k1];
  float delta = std::min(curve_index - k, 1.0);

  return c0 + (c1 - c0) * delta;
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateSetValueEvent(float value, double time) {
  return base::WrapUnique(new ParamEvent(ParamEvent::kSetValue, value, time));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateLinearRampEvent(float value,
                                                      double time,
                                                      float initial_value,
                                                      double call_time) {
  return base::WrapUnique(new ParamEvent(ParamEvent::kLinearRampToValue, value,
                                         time, initial_value, call_time));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateExponentialRampEvent(float value,
                                                           double time,
                                                           float initial_value,
                                                           double call_time) {
  return base::WrapUnique(new ParamEvent(ParamEvent::kExponentialRampToValue,
                                         value, time, initial_value,
                                         call_time));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateSetTargetEvent(float value,
                                                     double time,
                                                     double time_constant) {
  // The time line code does not expect a timeConstant of 0. (IT
  // returns NaN or Infinity due to division by zero.  The caller
  // should have converted this to a SetValueEvent.
  DCHECK_NE(time_constant, 0);
  return base::WrapUnique(
      new ParamEvent(ParamEvent::kSetTarget, value, time, time_constant));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateSetValueCurveEvent(
    const Vector<float>& curve,
    double time,
    double duration) {
  double curve_points = (curve.size() - 1) / duration;
  float end_value = curve.data()[curve.size() - 1];

  return base::WrapUnique(new ParamEvent(ParamEvent::kSetValueCurve, time,
                                         duration, curve, curve_points,
                                         end_value));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateSetValueCurveEndEvent(float value,
                                                            double time) {
  return base::WrapUnique(
      new ParamEvent(ParamEvent::kSetValueCurveEnd, value, time));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateCancelValuesEvent(
    double time,
    std::unique_ptr<ParamEvent> saved_event) {
  if (saved_event) {
    // The savedEvent can only have certain event types.  Verify that.
    ParamEvent::Type saved_type = saved_event->GetType();

    DCHECK_NE(saved_type, ParamEvent::kLastType);
    DCHECK(saved_type == ParamEvent::kLinearRampToValue ||
           saved_type == ParamEvent::kExponentialRampToValue ||
           saved_type == ParamEvent::kSetValueCurve);
  }

  return base::WrapUnique(
      new ParamEvent(ParamEvent::kCancelValues, time, std::move(saved_event)));
}

std::unique_ptr<AudioParamTimeline::ParamEvent>
AudioParamTimeline::ParamEvent::CreateGeneralEvent(
    Type type,
    float value,
    double time,
    float initial_value,
    double call_time,
    double time_constant,
    double duration,
    Vector<float>& curve,
    double curve_points_per_second,
    float curve_end_value,
    std::unique_ptr<ParamEvent> saved_event) {
  return base::WrapUnique(new ParamEvent(
      type, value, time, initial_value, call_time, time_constant, duration,
      curve, curve_points_per_second, curve_end_value, std::move(saved_event)));
}

AudioParamTimeline::ParamEvent* AudioParamTimeline::ParamEvent::SavedEvent()
    const {
  DCHECK_EQ(GetType(), ParamEvent::kCancelValues);
  return saved_event_.get();
}

bool AudioParamTimeline::ParamEvent::HasDefaultCancelledValue() const {
  DCHECK_EQ(GetType(), ParamEvent::kCancelValues);
  return has_default_cancelled_value_;
}

void AudioParamTimeline::ParamEvent::SetCancelledValue(float value) {
  DCHECK_EQ(GetType(), ParamEvent::kCancelValues);
  value_ = value;
  has_default_cancelled_value_ = true;
}

// General event
AudioParamTimeline::ParamEvent::ParamEvent(
    ParamEvent::Type type,
    float value,
    double time,
    float initial_value,
    double call_time,
    double time_constant,
    double duration,
    Vector<float>& curve,
    double curve_points_per_second,
    float curve_end_value,
    std::unique_ptr<ParamEvent> saved_event)
    : type_(type),
      value_(value),
      time_(time),
      initial_value_(initial_value),
      call_time_(call_time),
      time_constant_(time_constant),
      duration_(duration),
      curve_points_per_second_(curve_points_per_second),
      curve_end_value_(curve_end_value),
      saved_event_(std::move(saved_event)),
      has_default_cancelled_value_(false) {
  curve_ = curve;
}

// Create simplest event needing just a value and time, like setValueAtTime
AudioParamTimeline::ParamEvent::ParamEvent(ParamEvent::Type type,
                                           float value,
                                           double time)
    : type_(type),
      value_(value),
      time_(time),
      initial_value_(0),
      call_time_(0),
      time_constant_(0),
      duration_(0),
      curve_points_per_second_(0),
      curve_end_value_(0),
      saved_event_(nullptr),
      has_default_cancelled_value_(false) {
  DCHECK(type == ParamEvent::kSetValue ||
         type == ParamEvent::kSetValueCurveEnd);
}

// Create a linear or exponential ramp that requires an initial value and
// time in case
// there is no actual event that preceeds this event.
AudioParamTimeline::ParamEvent::ParamEvent(ParamEvent::Type type,
                                           float value,
                                           double time,
                                           float initial_value,
                                           double call_time)
    : type_(type),
      value_(value),
      time_(time),
      initial_value_(initial_value),
      call_time_(call_time),
      time_constant_(0),
      duration_(0),
      curve_points_per_second_(0),
      curve_end_value_(0),
      saved_event_(nullptr),
      has_default_cancelled_value_(false) {
  DCHECK(type == ParamEvent::kLinearRampToValue ||
         type == ParamEvent::kExponentialRampToValue);
}

// Create an event needing a time constant (setTargetAtTime)
AudioParamTimeline::ParamEvent::ParamEvent(ParamEvent::Type type,
                                           float value,
                                           double time,
                                           double time_constant)
    : type_(type),
      value_(value),
      time_(time),
      initial_value_(0),
      call_time_(0),
      time_constant_(time_constant),
      duration_(0),
      curve_points_per_second_(0),
      curve_end_value_(0),
      saved_event_(nullptr),
      has_default_cancelled_value_(false) {
  DCHECK_EQ(type, ParamEvent::kSetTarget);
}

// Create a setValueCurve event
AudioParamTimeline::ParamEvent::ParamEvent(ParamEvent::Type type,
                                           double time,
                                           double duration,
                                           const Vector<float>& curve,
                                           double curve_points_per_second,
                                           float curve_end_value)
    : type_(type),
      value_(0),
      time_(time),
      initial_value_(0),
      call_time_(0),
      time_constant_(0),
      duration_(duration),
      curve_points_per_second_(curve_points_per_second),
      curve_end_value_(curve_end_value),
      saved_event_(nullptr),
      has_default_cancelled_value_(false) {
  DCHECK_EQ(type, ParamEvent::kSetValueCurve);
  unsigned curve_length = curve.size();
  curve_.resize(curve_length);
  memcpy(curve_.data(), curve.data(), curve_length * sizeof(float));
}

// Create CancelValues event
AudioParamTimeline::ParamEvent::ParamEvent(
    ParamEvent::Type type,
    double time,
    std::unique_ptr<ParamEvent> saved_event)
    : type_(type),
      value_(0),
      time_(time),
      initial_value_(0),
      call_time_(0),
      time_constant_(0),
      duration_(0),
      curve_points_per_second_(0),
      curve_end_value_(0),
      saved_event_(std::move(saved_event)),
      has_default_cancelled_value_(false) {
  DCHECK_EQ(type, ParamEvent::kCancelValues);
}

void AudioParamTimeline::SetValueAtTime(float value,
                                        double time,
                                        ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(time, exception_state)) {
    return;
  }

  base::AutoLock locker(events_lock_);
  InsertEvent(ParamEvent::CreateSetValueEvent(value, time), exception_state);
}

void AudioParamTimeline::LinearRampToValueAtTime(
    float value,
    double time,
    float initial_value,
    double call_time,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(time, exception_state)) {
    return;
  }

  base::AutoLock locker(events_lock_);
  InsertEvent(
      ParamEvent::CreateLinearRampEvent(value, time, initial_value, call_time),
      exception_state);
}

void AudioParamTimeline::ExponentialRampToValueAtTime(
    float value,
    double time,
    float initial_value,
    double call_time,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(time, exception_state)) {
    return;
  }

  if (!value) {
    exception_state.ThrowRangeError(
        "The float target value provided (" + String::Number(value) +
        ") should not be in the range (" +
        String::Number(-std::numeric_limits<float>::denorm_min()) + ", " +
        String::Number(std::numeric_limits<float>::denorm_min()) + ").");
    return;
  }

  base::AutoLock locker(events_lock_);
  InsertEvent(ParamEvent::CreateExponentialRampEvent(value, time, initial_value,
                                                     call_time),
              exception_state);
}

void AudioParamTimeline::SetTargetAtTime(float target,
                                         double time,
                                         double time_constant,
                                         ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(time, exception_state) ||
      !IsNonNegativeAudioParamTime(time_constant, exception_state,
                                   "Time constant")) {
    return;
  }

  base::AutoLock locker(events_lock_);

  // If timeConstant = 0, we instantly jump to the target value, so
  // insert a SetValueEvent instead of SetTargetEvent.
  if (time_constant == 0) {
    InsertEvent(ParamEvent::CreateSetValueEvent(target, time), exception_state);
  } else {
    InsertEvent(ParamEvent::CreateSetTargetEvent(target, time, time_constant),
                exception_state);
  }
}

void AudioParamTimeline::SetValueCurveAtTime(const Vector<float>& curve,
                                             double time,
                                             double duration,
                                             ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(time, exception_state) ||
      !IsPositiveAudioParamTime(duration, exception_state, "Duration")) {
    return;
  }

  if (curve.size() < 2) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        ExceptionMessages::IndexExceedsMinimumBound("curve length",
                                                    curve.size(), 2u));
    return;
  }

  base::AutoLock locker(events_lock_);
  InsertEvent(ParamEvent::CreateSetValueCurveEvent(curve, time, duration),
              exception_state);

  // Insert a setValueAtTime event too to establish an event so that all
  // following events will process from the end of the curve instead of the
  // beginning.
  InsertEvent(ParamEvent::CreateSetValueCurveEndEvent(
                  curve.data()[curve.size() - 1], time + duration),
              exception_state);
}

void AudioParamTimeline::InsertEvent(std::unique_ptr<ParamEvent> event,
                                     ExceptionState& exception_state) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("webaudio.audionode"),
               "AudioParamTimeline::InsertEvent");

  DCHECK(IsMainThread());

  // Sanity check the event. Be super careful we're not getting infected with
  // NaN or Inf. These should have been handled by the caller.
  DCHECK_LT(event->GetType(), ParamEvent::kLastType);
  DCHECK(std::isfinite(event->Value()));
  DCHECK(std::isfinite(event->Time()));
  DCHECK(std::isfinite(event->TimeConstant()));
  DCHECK(std::isfinite(event->Duration()));
  DCHECK_GE(event->Duration(), 0);

  double insert_time = event->Time();

  if (!events_.size() &&
      (event->GetType() == ParamEvent::kLinearRampToValue ||
       event->GetType() == ParamEvent::kExponentialRampToValue)) {
    // There are no events preceding these ramps.  Insert a new
    // setValueAtTime event to set the starting point for these
    // events.  Use a time of 0 to make sure it preceeds all other
    // events.  This will get fixed when when handle new events.
    events_.insert(0, AudioParamTimeline::ParamEvent::CreateSetValueEvent(
                          event->InitialValue(), 0));
    new_events_.insert(events_[0].get());
  }

  if (events_.empty()) {
    events_.insert(0, std::move(event));
    new_events_.insert(events_[0].get());
    return;
  }

  // Most of the time, we must insert after the last event. If the time of the
  // last event is greater than the insert_time, use binary search to find the
  // insertion point.
  wtf_size_t insertion_idx = events_.size();
  DCHECK_GT(insertion_idx, wtf_size_t{0});
  wtf_size_t ub = insertion_idx - 1;  // upper bound of events that can overlap.
  if (events_.back()->Time() > insert_time) {
    auto it = std::upper_bound(
        events_.begin(), events_.end(), insert_time,
        [](const double value, const std::unique_ptr<ParamEvent>& entry) {
          return value < entry->Time();
        });
    insertion_idx = static_cast<wtf_size_t>(std::distance(events_.begin(), it));
    DCHECK_LT(insertion_idx, events_.size());
    ub = insertion_idx;
  }
  DCHECK_LT(ub, static_cast<wtf_size_t>(std::numeric_limits<int>::max()));

  if (event->GetType() == ParamEvent::kSetValueCurve) {
    double end_time = event->Time() + event->Duration();
    for (int i = ub; i >= 0; i--) {
      ParamEvent::Type test_type = events_[i]->GetType();
      // Events of type `kSetValueCurveEnd` or `kCancelValues` never conflict.
      if (test_type == ParamEvent::kSetValueCurveEnd ||
          test_type == ParamEvent::kCancelValues) {
        continue;
      }
      if (test_type == ParamEvent::kSetValueCurve) {
        // A SetValueCurve overlapping an existing SetValueCurve requires
        // special care.
        double test_end_time = events_[i]->Time() + events_[i]->Duration();
        // Events are overlapped if the new event starts before the old event
        // ends and the old event starts before the new event ends.
        bool overlap =
            event->Time() < test_end_time && events_[i]->Time() < end_time;
        if (overlap) {
          // If the start time of the event overlaps the start/end of an
          // existing event or if the existing event end overlaps the
          // start/end of the event, it's an error.
          exception_state.ThrowDOMException(
              DOMExceptionCode::kNotSupportedError,
              EventToString(*event) + " overlaps " +
                  EventToString(*events_[i]));
          return;
        }
      } else {
        // Here we handle existing events of types other than
        // `kSetValueCurveEnd`, `kCancelValues` and `kSetValueCurve`.
        // Throw an error if an existing event starts in the middle of this
        // SetValueCurve event.
        if (events_[i]->Time() > event->Time() &&
            events_[i]->Time() < end_time) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kNotSupportedError,
              EventToString(*event) + " overlaps " +
                  EventToString(*events_[i]));
          return;
        }
      }
      if (events_[i]->Time() < insert_time) {
        // We found an existing event, E, of type other than `kSetValueCurveEnd`
        // or `kCancelValues` that starts before the new event of type
        // `kSetValueCurve` that we want to insert. No earlier existing event
        // can overlap with the new event. An overlapping `kSetValueCurve` would
        // have ovelapped with E too, so one of them would not be inserted.
        // Other event types overlap with the new `kSetValueCurve` event only if
        // they start in the middle of the new event, which is not the case.
        break;
      }
    }
  } else {
    // Not a `SetValueCurve` new event. Make sure this new event doesn't overlap
    // any existing `SetValueCurve` event.
    for (int i = ub; i >= 0; i--) {
      ParamEvent::Type test_type = events_[i]->GetType();
      // Events of type `kSetValueCurveEnd` or `kCancelValues` never conflict.
      if (test_type == ParamEvent::kSetValueCurveEnd ||
          test_type == ParamEvent::kCancelValues) {
        continue;
      }
      if (test_type == ParamEvent::kSetValueCurve) {
        double end_time = events_[i]->Time() + events_[i]->Duration();
        if (event->GetType() != ParamEvent::kSetValueCurveEnd &&
            event->Time() >= events_[i]->Time() && event->Time() < end_time) {
          exception_state.ThrowDOMException(
              DOMExceptionCode::kNotSupportedError,
              EventToString(*event) + " overlaps " +
                  EventToString(*events_[i]));
          return;
        }
      }
      if (events_[i]->Time() < insert_time) {
        // We found an existing event, E, of type other than `kSetValueCurveEnd`
        // or `kCancelValues` that starts before the new event that we want to
        // insert. No earlier event of type `kSetValueCurve` can overlap with
        // the new event, because it would have overlapped with E too.
        break;
      }
    }
  }

  events_.insert(insertion_idx, std::move(event));
  new_events_.insert(events_[insertion_idx].get());
}

bool AudioParamTimeline::HasValues(size_t current_frame,
                                   double sample_rate,
                                   unsigned render_quantum_frames) const {
  base::AutoTryLock try_locker(events_lock_);

  if (try_locker.is_acquired()) {
    unsigned n_events = events_.size();

    // Clearly, if there are no scheduled events, we have no timeline values.
    if (n_events == 0) {
      return false;
    }

    // Handle the case where the first event (of certain types) is in the
    // future.  Then, no sample-accurate processing is needed because the event
    // hasn't started.
    if (events_[0]->Time() >
        (current_frame + render_quantum_frames) / sample_rate) {
      switch (events_[0]->GetType()) {
        case ParamEvent::kSetTarget:
        case ParamEvent::kSetValue:
        case ParamEvent::kSetValueCurve:
          // If the first event is one of these types, and the event starts
          // after the end of the current render quantum, we don't need to do
          // the slow sample-accurate path.
          return false;
        default:
          // Handle other event types below.
          break;
      }
    }

    // If there are at least 2 events in the timeline, assume there are timeline
    // values.  This could be optimized to be more careful, but checking is
    // complicated and keeping this consistent with `ValuesForFrameRangeImpl()`
    // will be hard, so it's probably best to let the general timeline handle
    // this until the events are in the past.
    if (n_events >= 2) {
      return true;
    }

    // We have exactly one event in the timeline.
    switch (events_[0]->GetType()) {
      case ParamEvent::kSetTarget:
        // Need automation if the event starts somewhere before the
        // end of the current render quantum.
        return events_[0]->Time() <=
               (current_frame + render_quantum_frames) / sample_rate;
      case ParamEvent::kSetValue:
      case ParamEvent::kLinearRampToValue:
      case ParamEvent::kExponentialRampToValue:
      case ParamEvent::kCancelValues:
      case ParamEvent::kSetValueCurveEnd:
        // If these events are in the past, we don't need any automation; the
        // value is a constant.
        return !(events_[0]->Time() < current_frame / sample_rate);
      case ParamEvent::kSetValueCurve: {
        double curve_end_time = events_[0]->Time() + events_[0]->Duration();
        double current_time = current_frame / sample_rate;

        return (events_[0]->Time() <= current_time) &&
               (current_time < curve_end_time);
      }
      case ParamEvent::kLastType:
        NOTREACHED();
    }
  }

  // Can't get the lock so that means the main thread is trying to insert an
  // event.  Just return true then.  If the main thread releases the lock before
  // valueForContextTime or valuesForFrameRange runs, then the there will be an
  // event on the timeline, so everything is fine.  If the lock is held so that
  // neither valueForContextTime nor valuesForFrameRange can run, this is ok
  // too, because they have tryLocks to produce a default value.  The event will
  // then get processed in the next rendering quantum.
  //
  // Don't want to return false here because that would confuse the processing
  // of the timeline if previously we returned true and now suddenly return
  // false, only to return true on the next rendering quantum.  Currently, once
  // a timeline has been introduced it is always true forever because m_events
  // never shrinks.
  return true;
}

void AudioParamTimeline::CancelScheduledValues(
    double cancel_time,
    ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(cancel_time, exception_state)) {
    return;
  }

  base::AutoLock locker(events_lock_);

  // Remove all events starting at startTime.
  for (wtf_size_t i = 0; i < events_.size(); ++i) {
    // Removal all events whose event time (start) is greater than or
    // equal to the cancel time.  And also handle the special case
    // where the cancel time lies in the middle of a setValueCurve
    // event.
    //
    // This critically depends on the fact that no event can be
    // scheduled in the middle of the curve or at the same start time.
    // Then removing the setValueCurve doesn't remove any events that
    // shouldn't have been.
    double start_time = events_[i]->Time();

    if (start_time >= cancel_time ||
        ((events_[i]->GetType() == ParamEvent::kSetValueCurve) &&
         start_time <= cancel_time &&
         (start_time + events_[i]->Duration() > cancel_time))) {
      RemoveCancelledEvents(i);
      break;
    }
  }
}

void AudioParamTimeline::CancelAndHoldAtTime(double cancel_time,
                                             ExceptionState& exception_state) {
  DCHECK(IsMainThread());

  if (!IsNonNegativeAudioParamTime(cancel_time, exception_state)) {
    return;
  }

  base::AutoLock locker(events_lock_);

  wtf_size_t i;
  // Find the first event at or just past `cancel_time`.
  for (i = 0; i < events_.size(); ++i) {
    if (events_[i]->Time() > cancel_time) {
      break;
    }
  }

  // The event that is being cancelled.  This is the event just past
  // `cancel_time`, if any.
  wtf_size_t cancelled_event_index = i;

  // If the event just before `cancel_time` is a SetTarget or SetValueCurve
  // event, we need to handle that event specially instead of the event after.
  if (i > 0 && ((events_[i - 1]->GetType() == ParamEvent::kSetTarget) ||
                (events_[i - 1]->GetType() == ParamEvent::kSetValueCurve))) {
    cancelled_event_index = i - 1;
  } else if (i >= events_.size()) {
    // If there were no events occurring after `cancel_time` (and the
    // previous event is not SetTarget o
```
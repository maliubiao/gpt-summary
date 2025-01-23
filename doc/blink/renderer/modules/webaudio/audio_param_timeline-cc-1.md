Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/modules/webaudio/audio_param_timeline.cc`. This is part 2 of 3. The focus should be on the operations performed within this specific snippet.

**Plan:**

1. **Identify the main functions within the snippet:** `CancelScheduledValues`, `ValueForContextTime`, `ValuesForFrameRange`, `ValuesForFrameRangeImpl`, `HandleFirstEvent`, `IsEventCurrent`, `ClampNewEventsToCurrentTime`, `HandleAllEventsInThePast`, `ProcessSetTargetFollowedByRamp`, `HandleCancelValues`, `ProcessLinearRamp`, `ProcessExponentialRamp`, `ProcessSetTarget`.
2. **Summarize the purpose of each function:**  Focus on what each function does to the audio parameter timeline and its events.
3. **Explain the relationship to JavaScript/HTML/CSS:**  Consider how the operations in these functions might be triggered by Web Audio API calls in JavaScript.
4. **Identify logical reasoning and provide examples:** Look for conditional logic and how it affects the processing of audio events. Create hypothetical inputs and outputs.
5. **Point out potential user/programming errors:** Think about how incorrect usage of the Web Audio API could lead to issues handled by this code.
6. **Describe user actions leading to this code:** Explain the sequence of Web Audio API calls that could result in the execution of these functions.
7. **Synthesize a concise overall summary of the snippet's functionality.**
```
功能归纳：

这段代码实现了 `AudioParamTimeline` 类中处理音频参数值取消和计算的核心逻辑。它主要负责在指定时间取消已计划的参数变化，并根据时间线上的事件计算音频参数在特定时间范围内的取值。

**主要功能点:**

1. **`CancelScheduledValues(double cancel_time, ExceptionState& exception_state)`:**  此函数负责取消在 `cancel_time` 之后发生的音频参数事件。
    - 它会根据要取消的事件类型进行不同的处理，例如：
        - **线性/指数斜坡 (kLinearRampToValue, kExponentialRampToValue):**  创建一个 `kCancelValues` 事件，保存被取消事件的参数，以便正确保持取消时的值。
        - **设置目标值 (kSetTarget):** 如果 `kSetTarget` 事件在取消时间之前开始，则插入一个 `kCancelValues` 事件来停止自动化。
        - **设置值曲线 (kSetValueCurve):** 如果取消时间在曲线中间，则创建一个新的 `kSetValueCurve` 事件，调整其持续时间和结束值，并插入一个 `kSetValue` 事件以设置取消时的值。
        - **设置值 (kSetValue), 曲线结束 (kSetValueCurveEnd), 取消值 (kCancelValues):** 这些类型的事件不需要特殊处理。
    - 函数会移除取消时间之后的所有事件，并插入新创建的取消事件。

2. **`ValueForContextTime(...)`:**  用于获取音频参数在特定上下文中（由 `audio_destination` 表示）的单个值。
    - 它尝试获取事件锁，如果无法获取或没有事件，则返回默认值。
    - 实际值计算委托给 `ValuesForFrameRange` 函数。

3. **`ValuesForFrameRange(...)`:**  计算音频参数在指定帧范围内的多个值。
    - 它也尝试获取事件锁，如果无法获取，则填充默认值。
    - 核心计算逻辑在 `ValuesForFrameRangeImpl` 中。
    - 计算出的值会被限制在 `min_value` 和 `max_value` 之间。

4. **`ValuesForFrameRangeImpl(...)`:**  `ValuesForFrameRange` 的实际实现。
    - 如果没有匹配时间范围的事件，则填充默认值。
    - 如果有新的事件尚未完全合并到 `events_` 中，会调用 `ClampNewEventsToCurrentTime` 来处理。
    - 调用 `HandleAllEventsInThePast` 处理所有事件都在过去的情况。
    - 遍历事件列表，根据事件类型计算参数值并填充 `values` 数组。
    - 针对不同类型的事件（`kSetValue`, `kCancelValues`, `kLinearRampToValue`, `kExponentialRampToValue`, `kSetTarget`, `kSetValueCurve`）执行相应的计算逻辑。
    - 对于 `kLinearRampToValue` 和 `kExponentialRampToValue`，会预先查看下一个事件以确定斜坡的终点。
    - 在处理完事件后，如果存在被跳过的旧事件，则会调用 `RemoveOldEvents` 清理。
    - 最后，将最后一个计算出的值填充到 `values` 数组的剩余部分。

5. **辅助函数:**
    - **`HandleFirstEvent(...)`:** 处理第一个事件，如果在第一个事件发生前有时间，则用默认值填充。
    - **`IsEventCurrent(...)`:** 判断当前事件是否在当前处理的时间点。
    - **`ClampNewEventsToCurrentTime(...)`:**  调整新添加的事件的时间，防止时间倒流，并重新排序事件列表。
    - **`HandleAllEventsInThePast(...)`:**  优化处理所有事件都已过去的情况。
    - **`ProcessSetTargetFollowedByRamp(...)`:**  处理 `kSetTarget` 事件后紧跟着斜坡事件的情况。
    - **`HandleCancelValues(...)`:**  处理 `kCancelValues` 事件，确定取消后的参数值和下一个事件类型。
    - **`ProcessLinearRamp(...)`:**  计算线性斜坡过程中的参数值。
    - **`ProcessExponentialRamp(...)`:** 计算指数斜坡过程中的参数值。
    - **`ProcessSetTarget(...)`:** 计算 `kSetTarget` 事件影响下的参数值。

**与 JavaScript, HTML, CSS 的关系举例:**

- **JavaScript:**
    - 当 JavaScript 代码调用 Web Audio API 的 `AudioParam` 接口上的方法，如 `setValueAtTime()`, `linearRampToValueAtTime()`, `exponentialRampToValueAtTime()`, `setTargetAtTime()`, `setValueCurveAtTime()`, `cancelScheduledValues()` 时，这些调用最终会影响到 `AudioParamTimeline` 中的事件列表。
    - 例如，JavaScript 调用 `audioParam.cancelScheduledValues(5)` 会导致 `AudioParamTimeline::CancelScheduledValues(5, ...)` 被执行。
    - JavaScript 代码在音频处理过程中，可能需要获取当前音频参数的值。这时，`audioParam.value` 的读取可能会触发 `AudioParamTimeline::ValueForContextTime()` 或 `AudioParamTimeline::ValuesForFrameRange()` 的调用。

- **HTML:**
    - HTML 结构定义了包含 `<audio>` 或 `<video>` 元素的网页，这些元素可以通过 JavaScript 与 Web Audio API 集成。
    - HTML 中的用户交互（如播放、暂停）可能通过 JavaScript 代码间接触发对 Web Audio API 的调用，进而影响 `AudioParamTimeline` 的状态。

- **CSS:**
    - CSS 本身与 `AudioParamTimeline` 的功能没有直接关系。然而，CSS 动画或过渡可能会影响到 JavaScript 代码中与 Web Audio API 相关的逻辑，从而间接地影响 `AudioParamTimeline` 的行为。例如，CSS 动画驱动 JavaScript 代码动态调整音频参数。

**逻辑推理示例:**

**假设输入:**

- `events_` 中已存在一个 `kLinearRampToValue` 事件，起始时间为 2 秒，起始值为 0.5，结束时间为 4 秒，结束值为 1.0。
- 调用 `CancelScheduledValues(3, ...)`。

**输出:**

- 原有的 `kLinearRampToValue` 事件被替换为一个新的 `kLinearRampToValue` 事件，起始时间为 2 秒，起始值为 0.5，结束时间为 3 秒，结束值为 0.75（线性插值）。
- 插入一个新的 `kSetValue` 事件，时间为 3 秒，值为 0.75。
- 原来 3 秒之后的所有事件都被移除。

**用户或编程常见的使用错误举例:**

- **错误的时间顺序:**  用户在 JavaScript 中调用 Web Audio API 的方法时，可能错误地设置了时间参数，导致事件顺序混乱。例如，先调用 `linearRampToValueAtTime(1.0, 5)`，然后调用 `setValueAtTime(0.5, 3)`。`AudioParamTimeline` 会尽力处理这些情况，但可能不是用户期望的结果。
- **在 `setValueCurve` 期间插入事件:** Web Audio API 规范通常不允许在 `setValueCurve` 正在进行时插入其他事件。如果用户尝试这样做，`AudioParamTimeline` 的逻辑需要正确处理，例如通过创建新的 `SetValueCurve` 事件来取消之前的曲线。
- **取消时间早于事件开始时间:** 用户调用 `cancelScheduledValues()` 时指定的时间早于某个事件的开始时间，这将不会影响该事件。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页上进行操作:** 例如点击一个按钮，触发一段 JavaScript 代码。
2. **JavaScript 代码使用 Web Audio API:**  代码中创建了一个 `AudioContext`，获取了一个 `GainNode` 的 `gain` 参数 (这是一个 `AudioParam`)。
3. **JavaScript 代码调度音频参数变化:**  例如，调用 `gain.gain.linearRampToValueAtTime(1.0, audioContext.currentTime + 2)`. 这会在 `AudioParamTimeline` 中添加一个 `kLinearRampToValue` 事件。
4. **JavaScript 代码取消部分调度:** 用户再次操作，触发代码调用 `gain.gain.cancelScheduledValues(audioContext.currentTime + 1)`.
5. **执行 `AudioParamTimeline::CancelScheduledValues()`:**  因为取消时间在之前调度的斜坡事件中间，所以会执行相应的取消逻辑，例如创建新的事件。
6. **音频渲染过程:** 当音频上下文进行渲染时，需要计算每个音频帧的参数值。这会触发 `AudioParamTimeline::ValuesForFrameRange()` (或 `ValueForContextTime()` )，根据事件时间线计算出该帧的 `gain` 值。

总而言之，这段代码负责管理和计算音频参数随时间变化的值，并处理取消操作，是 Web Audio API 中动态控制音频效果的关键组成部分。
```
### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_param_timeline.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
r SetValueCurve, we're done.
    return;
  }

  // cancelledEvent is the event that is being cancelled.
  ParamEvent* cancelled_event = events_[cancelled_event_index].get();
  ParamEvent::Type event_type = cancelled_event->GetType();

  // New event to be inserted, if any, and a SetValueEvent if needed.
  std::unique_ptr<ParamEvent> new_event;
  std::unique_ptr<ParamEvent> new_set_value_event;

  switch (event_type) {
    case ParamEvent::kLinearRampToValue:
    case ParamEvent::kExponentialRampToValue: {
      // For these events we need to remember the parameters of the event
      // for a CancelValues event so that we can properly cancel the event
      // and hold the value.
      std::unique_ptr<ParamEvent> saved_event = ParamEvent::CreateGeneralEvent(
          event_type, cancelled_event->Value(), cancelled_event->Time(),
          cancelled_event->InitialValue(), cancelled_event->CallTime(),
          cancelled_event->TimeConstant(), cancelled_event->Duration(),
          cancelled_event->Curve(), cancelled_event->CurvePointsPerSecond(),
          cancelled_event->CurveEndValue(), nullptr);

      new_event = ParamEvent::CreateCancelValuesEvent(cancel_time,
                                                      std::move(saved_event));
    } break;
    case ParamEvent::kSetTarget: {
      if (cancelled_event->Time() < cancel_time) {
        // Don't want to remove the SetTarget event if it started before the
        // cancel time, so bump the index.  But we do want to insert a
        // cancelEvent so that we stop this automation and hold the value when
        // we get there.
        ++cancelled_event_index;

        new_event = ParamEvent::CreateCancelValuesEvent(cancel_time, nullptr);
      }
    } break;
    case ParamEvent::kSetValueCurve: {
      // If the setValueCurve event started strictly before the cancel time,
      // there might be something to do....
      if (cancelled_event->Time() < cancel_time) {
        if (cancel_time >
            cancelled_event->Time() + cancelled_event->Duration()) {
          // If the cancellation time is past the end of the curve there's
          // nothing to do except remove the following events.
          ++cancelled_event_index;
        } else {
          // Cancellation time is in the middle of the curve.  Therefore,
          // create a new SetValueCurve event with the appropriate new
          // parameters to cancel this event properly.  Since it's illegal
          // to insert any event within a SetValueCurve event, we can
          // compute the new end value now instead of doing when running
          // the timeline.
          double new_duration = cancel_time - cancelled_event->Time();
          float end_value = ValueCurveAtTime(
              cancel_time, cancelled_event->Time(), cancelled_event->Duration(),
              cancelled_event->Curve().data(), cancelled_event->Curve().size());

          // Replace the existing SetValueCurve with this new one that is
          // identical except for the duration.
          new_event = ParamEvent::CreateGeneralEvent(
              event_type, cancelled_event->Value(), cancelled_event->Time(),
              cancelled_event->InitialValue(), cancelled_event->CallTime(),
              cancelled_event->TimeConstant(), new_duration,
              cancelled_event->Curve(), cancelled_event->CurvePointsPerSecond(),
              end_value, nullptr);

          new_set_value_event = ParamEvent::CreateSetValueEvent(
              end_value, cancelled_event->Time() + new_duration);
        }
      }
    } break;
    case ParamEvent::kSetValue:
    case ParamEvent::kSetValueCurveEnd:
    case ParamEvent::kCancelValues:
      // Nothing needs to be done for a SetValue or CancelValues event.
      break;
    case ParamEvent::kLastType:
      NOTREACHED();
  }

  // Now remove all the following events from the timeline.
  if (cancelled_event_index < events_.size()) {
    RemoveCancelledEvents(cancelled_event_index);
  }

  // Insert the new event, if any.
  if (new_event) {
    InsertEvent(std::move(new_event), exception_state);
    if (new_set_value_event) {
      InsertEvent(std::move(new_set_value_event), exception_state);
    }
  }
}

std::tuple<bool, float> AudioParamTimeline::ValueForContextTime(
    AudioDestinationHandler& audio_destination,
    float default_value,
    float min_value,
    float max_value,
    unsigned render_quantum_frames) {
  {
    base::AutoTryLock try_locker(events_lock_);
    if (!try_locker.is_acquired() || !events_.size() ||
        audio_destination.CurrentTime() < events_[0]->Time()) {
      return std::make_tuple(false, default_value);
    }
  }

  // Ask for just a single value.
  float value;
  double sample_rate = audio_destination.SampleRate();
  size_t start_frame = audio_destination.CurrentSampleFrame();
  // One parameter change per render quantum.
  double control_rate = sample_rate / render_quantum_frames;
  value = ValuesForFrameRange(start_frame, start_frame + 1, default_value,
                              &value, 1, sample_rate, control_rate, min_value,
                              max_value, render_quantum_frames);

  return std::make_tuple(true, value);
}

float AudioParamTimeline::ValuesForFrameRange(size_t start_frame,
                                              size_t end_frame,
                                              float default_value,
                                              float* values,
                                              unsigned number_of_values,
                                              double sample_rate,
                                              double control_rate,
                                              float min_value,
                                              float max_value,
                                              unsigned render_quantum_frames) {
  // We can't contend the lock in the realtime audio thread.
  base::AutoTryLock try_locker(events_lock_);
  if (!try_locker.is_acquired()) {
    if (values) {
      for (unsigned i = 0; i < number_of_values; ++i) {
        values[i] = default_value;
      }
    }
    return default_value;
  }

  float last_value = ValuesForFrameRangeImpl(
      start_frame, end_frame, default_value, values, number_of_values,
      sample_rate, control_rate, render_quantum_frames);

  // Clamp the values now to the nominal range
  vector_math::Vclip(values, 1, &min_value, &max_value, values, 1,
                     number_of_values);

  return last_value;
}

float AudioParamTimeline::ValuesForFrameRangeImpl(
    size_t start_frame,
    size_t end_frame,
    float default_value,
    float* values,
    unsigned number_of_values,
    double sample_rate,
    double control_rate,
    unsigned render_quantum_frames) {
  DCHECK(values);
  DCHECK_GE(number_of_values, 1u);

  // Return default value if there are no events matching the desired time
  // range.
  if (!events_.size() || (end_frame / sample_rate <= events_[0]->Time())) {
    FillWithDefault(values, default_value, number_of_values, 0);

    return default_value;
  }

  int number_of_events = events_.size();

  // MUST clamp event before `events_` is possibly mutated because
  // `new_events_` has raw pointers to objects in `events_`.  Clamping
  // will clear out all of these pointers before `events_` is
  // potentially modified.
  //
  // TODO(rtoy): Consider making `events_` be scoped_refptr instead of
  // unique_ptr.
  if (new_events_.size() > 0) {
    ClampNewEventsToCurrentTime(start_frame / sample_rate);
  }

  if (number_of_events > 0) {
    double current_time = start_frame / sample_rate;

    if (HandleAllEventsInThePast(current_time, sample_rate, default_value,
                                 number_of_values, values,
                                 render_quantum_frames)) {
      return default_value;
    }
  }

  // Maintain a running time (frame) and index for writing the values buffer.
  // If first event is after startFrame then fill initial part of values buffer
  // with defaultValue until we reach the first event time.
  auto [current_frame, write_index] =
      HandleFirstEvent(values, default_value, number_of_values, start_frame,
                       end_frame, sample_rate, start_frame, 0);

  float value = default_value;

  // Go through each event and render the value buffer where the times overlap,
  // stopping when we've rendered all the requested values.
  int last_skipped_event_index = 0;
  for (int i = 0; i < number_of_events && write_index < number_of_values; ++i) {
    ParamEvent* event = events_[i].get();
    ParamEvent* next_event =
        i < number_of_events - 1 ? events_[i + 1].get() : nullptr;

    // Wait until we get a more recent event.
    if (!IsEventCurrent(event, next_event, current_frame, sample_rate)) {
      // This is not the special SetValue event case, and nextEvent is
      // in the past. We can skip processing of this event since it's
      // in past. We keep track of this event in lastSkippedEventIndex
      // to note what events we've skipped.
      last_skipped_event_index = i;
      continue;
    }

    // If there's no next event, set nextEventType to LastType to indicate that.
    ProcessSetTargetFollowedByRamp(
        i, event,
        next_event ? static_cast<ParamEvent::Type>(next_event->GetType())
                   : ParamEvent::kLastType,
        current_frame, sample_rate, control_rate, value);

    float value1 = event->Value();
    double time1 = event->Time();

    // Check to see if an event was cancelled.
    auto [value2, time2, next_event_type] = HandleCancelValues(
        event, next_event, next_event ? next_event->Value() : value1,
        next_event ? next_event->Time() : end_frame / sample_rate + 1);

    DCHECK(!std::isnan(value1));
    DCHECK(!std::isnan(value2));
    DCHECK_GE(time2, time1);

    // `fill_to_end_frame` is the exclusive upper bound of the last frame to be
    // computed for this event.  It's either the last desired frame
    // (`end_frame`) or derived from the end time of the next event
    // (`time2`). We compute ceil(`time2`*`sample_rate`) because
    // `fill_to_end_frame` is the exclusive upper bound.  Consider the case
    // where `start_frame` = 128 and `time2` = 128.1 (assuming `sample_rate` =
    // 1).  Since `time2` is greater than 128, we want to output a value for
    // frame 128.  This requires that `fill_to_end_frame` be at least 129.  This
    // is achieved by ceil(`time2`).
    //
    // However, `time2` can be very large, so compute this carefully in the case
    // where `time2` exceeds the size of a size_t.

    size_t fill_to_end_frame = end_frame;
    if (end_frame > time2 * sample_rate) {
      fill_to_end_frame = static_cast<size_t>(ceil(time2 * sample_rate));
    }

    DCHECK_GE(fill_to_end_frame, start_frame);
    unsigned fill_to_frame =
        static_cast<unsigned>(fill_to_end_frame - start_frame);
    fill_to_frame = std::min(fill_to_frame, number_of_values);

    const AutomationState current_state = {
        number_of_values,
        start_frame,
        end_frame,
        sample_rate,
        control_rate,
        fill_to_frame,
        fill_to_end_frame,
        value1,
        time1,
        value2,
        time2,
        event,
        i,
    };

    // First handle linear and exponential ramps which require looking ahead to
    // the next event.
    if (next_event_type == ParamEvent::kLinearRampToValue) {
      std::tie(current_frame, value, write_index) = ProcessLinearRamp(
          current_state, values, current_frame, value, write_index);
    } else if (next_event_type == ParamEvent::kExponentialRampToValue) {
      std::tie(current_frame, value, write_index) = ProcessExponentialRamp(
          current_state, values, current_frame, value, write_index);
    } else {
      // Handle event types not requiring looking ahead to the next event.
      switch (event->GetType()) {
        case ParamEvent::kSetValue:
        case ParamEvent::kSetValueCurveEnd:
        case ParamEvent::kLinearRampToValue: {
          current_frame = fill_to_end_frame;

          // Simply stay at a constant value.
          value = event->Value();
          write_index =
              FillWithDefault(values, value, fill_to_frame, write_index);
          break;
        }

        case ParamEvent::kCancelValues: {
          std::tie(current_frame, value, write_index) = ProcessCancelValues(
              current_state, values, current_frame, value, write_index);
          break;
        }

        case ParamEvent::kExponentialRampToValue: {
          current_frame = fill_to_end_frame;

          // If we're here, we've reached the end of the ramp.  For
          // the values after the end of the ramp, we just want to
          // continue with the ramp end value.
          value = event->Value();
          write_index =
              FillWithDefault(values, value, fill_to_frame, write_index);

          break;
        }

        case ParamEvent::kSetTarget: {
          std::tie(current_frame, value, write_index) = ProcessSetTarget(
              current_state, values, current_frame, value, write_index);
          break;
        }

        case ParamEvent::kSetValueCurve: {
          std::tie(current_frame, value, write_index) = ProcessSetValueCurve(
              current_state, values, current_frame, value, write_index);
          break;
        }
        case ParamEvent::kLastType:
          NOTREACHED();
      }
    }
  }

  // If we skipped over any events (because they are in the past), we can
  // remove them so we don't have to check them ever again.  (This MUST be
  // running with the m_events lock so we can safely modify the m_events
  // array.)
  if (last_skipped_event_index > 0) {
    // `new_events_` should be empty here so we don't have to
    // do any updates due to this mutation of `events_`.
    DCHECK_EQ(new_events_.size(), 0u);
    RemoveOldEvents(last_skipped_event_index - 1);
  }

  // If there's any time left after processing the last event then just
  // propagate the last value to the end of the values buffer.
  write_index = FillWithDefault(values, value, number_of_values, write_index);

  // This value is used to set the `.value` attribute of the AudioParam.  it
  // should be the last computed value.
  return values[number_of_values - 1];
}

std::tuple<size_t, unsigned> AudioParamTimeline::HandleFirstEvent(
    float* values,
    float default_value,
    unsigned number_of_values,
    size_t start_frame,
    size_t end_frame,
    double sample_rate,
    size_t current_frame,
    unsigned write_index) {
  double first_event_time = events_[0]->Time();
  if (first_event_time > start_frame / sample_rate) {
    // `fill_to_frame` is an exclusive upper bound, so use ceil() to compute the
    // bound from the `first_event_time`.
    size_t fill_to_end_frame = end_frame;
    double first_event_frame = ceil(first_event_time * sample_rate);
    if (end_frame > first_event_frame) {
      fill_to_end_frame = first_event_frame;
    }
    DCHECK_GE(fill_to_end_frame, start_frame);

    unsigned fill_to_frame =
        static_cast<unsigned>(fill_to_end_frame - start_frame);
    fill_to_frame = std::min(fill_to_frame, number_of_values);
    write_index =
        FillWithDefault(values, default_value, fill_to_frame, write_index);

    current_frame += fill_to_frame;
  }

  return std::make_tuple(current_frame, write_index);
}

bool AudioParamTimeline::IsEventCurrent(const ParamEvent* event,
                                        const ParamEvent* next_event,
                                        size_t current_frame,
                                        double sample_rate) const {
  // WARNING: due to round-off it might happen that `next_event->Time()` is just
  // larger than `current_frame`/`sample_rate`.  This means that we will end up
  // running the `event` again.  The code below had better be prepared for this
  // case!  What should happen is the fillToFrame should be 0 so that while the
  // event is actually run again, nothing actually gets computed, and we move on
  // to the next event.
  //
  // An example of this case is `SetValueCurveAtTime()`.  The time at which
  // `SetValueCurveAtTime()` ends (and the `SetValueAtTime()` begins) might be
  // just past `current_time`/`sample_rate`.  Then `SetValueCurveAtTime()` will
  // be processed again before advancing to `SetValueAtTime()`.  The number of
  // frames to be processed should be zero in this case.
  if (next_event && next_event->Time() < current_frame / sample_rate) {
    // But if the current event is a SetValue event and the event time is
    // between currentFrame - 1 and currentFrame (in time). we don't want to
    // skip it.  If we do skip it, the SetValue event is completely skipped
    // and not applied, which is wrong.  Other events don't have this problem.
    // (Because currentFrame is unsigned, we do the time check in this funny,
    // but equivalent way.)
    double event_frame = event->Time() * sample_rate;

    // Condition is currentFrame - 1 < eventFrame <= currentFrame, but
    // currentFrame is unsigned and could be 0, so use
    // currentFrame < eventFrame + 1 instead.
    if (!(((event->GetType() == ParamEvent::kSetValue ||
            event->GetType() == ParamEvent::kSetValueCurveEnd) &&
           (event_frame <= current_frame) &&
           (current_frame < event_frame + 1)))) {
      // This is not the special SetValue event case, and nextEvent is
      // in the past. We can skip processing of this event since it's
      // in past.
      return false;
    }
  }
  return true;
}

void AudioParamTimeline::ClampNewEventsToCurrentTime(double current_time) {
  bool clamped_some_event_time = false;

  for (auto* event : new_events_) {
    if (event->Time() < current_time) {
      event->SetTime(current_time);
      clamped_some_event_time = true;
    }
  }

  if (clamped_some_event_time) {
    // If we clamped some event time to current time, we need to sort
    // the event list in time order again, but it must be stable!
    std::stable_sort(events_.begin(), events_.end(), ParamEvent::EventPreceeds);
  }

  new_events_.clear();
}

bool AudioParamTimeline::HandleAllEventsInThePast(
    double current_time,
    double sample_rate,
    float& default_value,
    unsigned number_of_values,
    float* values,
    unsigned render_quantum_frames) {
  // Optimize the case where the last event is in the past.
  ParamEvent* last_event = events_[events_.size() - 1].get();
  ParamEvent::Type last_event_type = last_event->GetType();
  double last_event_time = last_event->Time();

  // If the last event is in the past and the event has ended, then we can
  // just propagate the same value.  Except for SetTarget which lasts
  // "forever".  SetValueCurve also has an explicit SetValue at the end of
  // the curve, so we don't need to worry that SetValueCurve time is a
  // start time, not an end time.
  if (last_event_time + 1.5 * render_quantum_frames / sample_rate <
      current_time) {
    // If the last event is SetTarget, make sure we've converged and, that
    // we're at least 5 time constants past the start of the event.  If not, we
    // have to continue processing it.
    if (last_event_type == ParamEvent::kSetTarget) {
      if (HasSetTargetConverged(default_value, last_event->Value(),
                                current_time, last_event_time,
                                last_event->TimeConstant())) {
        // We've converged. Slam the default value with the target value.
        default_value = last_event->Value();
      } else {
        // Not converged, so give up; we can't remove this event yet.
        return false;
      }
    }

    // `events_` is being mutated.  `new_events_` better be empty because there
    // are raw pointers there.
    DCHECK_EQ(new_events_.size(), 0U);
    // The event has finished, so just copy the default value out.
    // Since all events are now also in the past, we can just remove all
    // timeline events too because `default_value` has the expected
    // value.
    FillWithDefault(values, default_value, number_of_values, 0);
    RemoveOldEvents(events_.size());

    return true;
  }

  return false;
}

void AudioParamTimeline::ProcessSetTargetFollowedByRamp(
    int event_index,
    ParamEvent*& event,
    ParamEvent::Type next_event_type,
    size_t current_frame,
    double sample_rate,
    double control_rate,
    float& value) {
  // If the current event is SetTarget and the next event is a
  // LinearRampToValue or ExponentialRampToValue, special handling is needed.
  // In this case, the linear and exponential ramp should start at wherever
  // the SetTarget processing has reached.
  if (event->GetType() == ParamEvent::kSetTarget &&
      (next_event_type == ParamEvent::kLinearRampToValue ||
       next_event_type == ParamEvent::kExponentialRampToValue)) {
    // Replace the SetTarget with a SetValue to set the starting time and
    // value for the ramp using the current frame.  We need to update `value`
    // appropriately depending on whether the ramp has started or not.
    //
    // If SetTarget starts somewhere between currentFrame - 1 and
    // currentFrame, we directly compute the value it would have at
    // currentFrame.  If not, we update the value from the value from
    // currentFrame - 1.
    //
    // Can't use the condition currentFrame - 1 <= t0 * sampleRate <=
    // currentFrame because currentFrame is unsigned and could be 0.  Instead,
    // compute the condition this way,
    // where f = currentFrame and Fs = sampleRate:
    //
    //    f - 1 <= t0 * Fs <= f
    //    2 * f - 2 <= 2 * Fs * t0 <= 2 * f
    //    -2 <= 2 * Fs * t0 - 2 * f <= 0
    //    -1 <= 2 * Fs * t0 - 2 * f + 1 <= 1
    //     abs(2 * Fs * t0 - 2 * f + 1) <= 1
    if (fabs(2 * sample_rate * event->Time() - 2 * current_frame + 1) <= 1) {
      // SetTarget is starting somewhere between currentFrame - 1 and
      // currentFrame. Compute the value the SetTarget would have at the
      // currentFrame.
      value = event->Value() +
              (value - event->Value()) *
                  fdlibm::exp(-(current_frame / sample_rate - event->Time()) /
                              event->TimeConstant());
    } else {
      // SetTarget has already started.  Update `value` one frame because it's
      // the value from the previous frame.
      float discrete_time_constant =
          static_cast<float>(audio_utilities::DiscreteTimeConstantForSampleRate(
              event->TimeConstant(), control_rate));
      value += (event->Value() - value) * discrete_time_constant;
    }

    // Insert a SetValueEvent to mark the starting value and time.
    // Clear the clamp check because this doesn't need it.
    events_[event_index] =
        ParamEvent::CreateSetValueEvent(value, current_frame / sample_rate);

    // Update our pointer to the current event because we just changed it.
    event = events_[event_index].get();
  }
}

std::tuple<float, double, AudioParamTimeline::ParamEvent::Type>
AudioParamTimeline::HandleCancelValues(const ParamEvent* current_event,
                                       ParamEvent* next_event,
                                       float value2,
                                       double time2) {
  DCHECK(current_event);

  ParamEvent::Type next_event_type =
      next_event ? next_event->GetType() : ParamEvent::kLastType;

  if (next_event && next_event->GetType() == ParamEvent::kCancelValues &&
      next_event->SavedEvent()) {
    float value1 = current_event->Value();
    double time1 = current_event->Time();

    switch (current_event->GetType()) {
      case ParamEvent::kCancelValues:
      case ParamEvent::kLinearRampToValue:
      case ParamEvent::kExponentialRampToValue:
      case ParamEvent::kSetValueCurveEnd:
      case ParamEvent::kSetValue: {
        // These three events potentially establish a starting value for
        // the following event, so we need to examine the cancelled
        // event to see what to do.
        const ParamEvent* saved_event = next_event->SavedEvent();

        // Update the end time and type to pretend that we're running
        // this saved event type.
        time2 = next_event->Time();
        next_event_type = saved_event->GetType();

        if (next_event->HasDefaultCancelledValue()) {
          // We've already established a value for the cancelled
          // event, so just return it.
          value2 = next_event->Value();
        } else {
          // If the next event would have been a LinearRamp or
          // ExponentialRamp, we need to compute a new end value for
          // the event so that the curve works continues as if it were
          // not cancelled.
          switch (saved_event->GetType()) {
            case ParamEvent::kLinearRampToValue:
              value2 =
                  LinearRampAtTime(next_event->Time(), value1, time1,
                                   saved_event->Value(), saved_event->Time());
              break;
            case ParamEvent::kExponentialRampToValue:
              value2 = ExponentialRampAtTime(next_event->Time(), value1, time1,
                                             saved_event->Value(),
                                             saved_event->Time());
              DCHECK(!std::isnan(value1));
              break;
            case ParamEvent::kSetValueCurve:
            case ParamEvent::kSetValueCurveEnd:
            case ParamEvent::kSetValue:
            case ParamEvent::kSetTarget:
            case ParamEvent::kCancelValues:
              // These cannot be possible types for the saved event
              // because they can't be created.
              // createCancelValuesEvent doesn't allow them (SetValue,
              // SetTarget, CancelValues) or cancelScheduledValues()
              // doesn't create such an event (SetValueCurve).
              NOTREACHED();
            case ParamEvent::kLastType:
              // Illegal event type.
              NOTREACHED();
          }

          // Cache the new value so we don't keep computing it over and over.
          next_event->SetCancelledValue(value2);
        }
      } break;
      case ParamEvent::kSetValueCurve:
        // Everything needed for this was handled when cancelling was
        // done.
        break;
      case ParamEvent::kSetTarget:
        // Nothing special needs to be done for SetTarget
        // followed by CancelValues.
        break;
      case ParamEvent::kLastType:
        NOTREACHED();
    }
  }

  return std::make_tuple(value2, time2, next_event_type);
}

std::tuple<size_t, float, unsigned> AudioParamTimeline::ProcessLinearRamp(
    const AutomationState& current_state,
    float* values,
    size_t current_frame,
    float value,
    unsigned write_index) {
#if defined(ARCH_CPU_X86_FAMILY)
  auto number_of_values = current_state.number_of_values;
#endif
  auto fill_to_frame = current_state.fill_to_frame;
  auto time1 = current_state.time1;
  auto time2 = current_state.time2;
  auto value1 = current_state.value1;
  auto value2 = current_state.value2;
  auto sample_rate = current_state.sample_rate;

  double delta_time = time2 - time1;
  DCHECK_GE(delta_time, 0);
  // Since delta_time is a double, 1/delta_time can easily overflow a float.
  // Thus, if delta_time is close enough to zero (less than float min), treat it
  // as zero.
  float k =
      delta_time <= std::numeric_limits<float>::min() ? 0 : 1 / delta_time;
  const float value_delta = value2 - value1;
#if defined(ARCH_CPU_X86_FAMILY)
  if (fill_to_frame > write_index) {
    // Minimize in-loop operations. Calculate starting value and increment.
    // Next step: value += inc.
    //  value = value1 +
    //      (currentFrame/sampleRate - time1) * k * (value2 - value1);
    //  inc = 4 / sampleRate * k * (value2 - value1);
    // Resolve recursion by expanding constants to achieve a 4-step loop
    // unrolling.
    //  value = value1 +
    //    ((currentFrame/sampleRate - time1) + i * sampleFrameTimeIncr) * k
    //    * (value2 -value1), i in 0..3
    __m128 v_value =
        _mm_mul_ps(_mm_set_ps1(1 / sample_rate), _mm_set_ps(3, 2, 1, 0));
    v_value =
        _mm_add_ps(v_value, _mm_set_ps1(current_frame / sample_rate - time1));
    v_value = _mm_mul_ps(v_value, _mm_set_ps1(k * value_delta));
    v_value = _mm_add_ps(v_value, _mm_set_ps1(value1));
    __m128 v_inc = _mm_set_ps1(4 / sample_rate * k * value_delta);

    // Truncate loop steps to multiple of 4.
    unsigned fill_to_frame_trunc =
        write_index + ((fill_to_frame - write_index) / 4) * 4;
    // Compute final time.
    DCHECK_LE(fill_to_frame_trunc, number_of_values);
    current_frame += fill_to_frame_trunc - write_index;

    // Process 4 loop steps.
    for (; write_index < fill_to_frame_trunc; write_index += 4) {
      _mm_storeu_ps(values + write_index, v_value);
      v_value = _mm_add_ps(v_value, v_inc);
    }
  }
  // Update `value` with the last value computed so that the
  // `.value` attribute of the AudioParam gets the correct linear
  // ramp value, in case the following loop doesn't execute.
  if (write_index >= 1) {
    value = values[write_index - 1];
  }
#endif
  // Serially process remaining values.
  for (; write_index < fill_to_frame; ++write_index) {
    float x = (current_frame / sample_rate - time1) * k;
    // value = (1 - x) * value1 + x * value2;
    value = value1 + x * value_delta;
    values[write_index] = value;
    ++current_frame;
  }

  return std::make_tuple(current_frame, value, write_index);
}

std::tuple<size_t, float, unsigned> AudioParamTimeline::ProcessExponentialRamp(
    const AutomationState& current_state,
    float* values,
    size_t current_frame,
    float value,
    unsigned write_index) {
  auto fill_to_frame = current_state.fill_to_frame;
  auto time1 = current_state.time1;
  auto time2 = current_state.time2;
  auto value1 = current_state.value1;
  auto value2 = current_state.value2;
  auto sample_rate = current_state.sample_rate;

  if (value1 * value2 <= 0 || time1 >= time2) {
    // It's an error 1) if `value1` and `value2` have opposite signs or if one
    // of them is zero, or 2) if `time1` is greater than or equal to `time2`.
    // Handle this by propagating the previous value.
    value = value1;

    for (; write_index < fill_to_frame; ++write_index) {
      values[write_index] = value;
    }
  } else {
    double delta_time = time2 - time1;
    double num_sample_frames = delta_time * sample_rate;
    // The value goes exponentially from value1 to value2 in a duration of
    // deltaTime seconds according to
    //
    //  v(t) = v1*(v2/v1)^((t-t1)/(t2-t1))
    //
    // Let c be currentFrame and F be the sampleRate.  Then we want to
    // sample v(t) at times t = (c + k)/F for k = 0, 1, ...:
    //
    //   v((c+k)/F) = v1*(v2/v1)^(((c/F+k/F)-t1)/(t2-t1))
    //              = v1*(v2/v1)^((c/F-t1)/(t2-t1))
    //                  *(v2/v1)^((k/F)/(t2-t1))
    //              = v1*(v2/v1)^((c/F-t1)/(t2-t1))
    //                  *[(v2/v1)^(1/(F*(t2-t1)))]^k
    //
    // Thus, this can be written as
    //
    //   v((c+k)/F) = V*m^k
    //
    // where
    //   V = v1*(v2/v1)^((c/F-t1)/(t2-t1))
    //   m = (v2/v1)^(1/(F*(t2-t1)))

    // Compute the per-sample multiplier.
    double multiplier = fdlibm::pow(value2 / value1, 1.0 / num_sample_frames);
    // Set the starting value of the exponential ramp.  Do not attempt
    // to optimize pow to powf.  See crbug.com/771306.
    value = value1 *
            fdlibm::pow(value2 / static_cast<double>(value1),
                        (current_frame / sample_rate - time1) / delta_time);
    for (double accumulator = value; write_index < fill_to_frame;
         ++write_index) {
      value = accumulator;
      values[write_index] = value;
      accumulator *= multiplier;
      ++current_frame;
    }

    // Due to roundoff it's possible that value exceeds value2.  Clip value
    // to value2 if we are within 1/2 frame of time2.
    if (current_frame > time2 * sample_rate - 0.5) {
      value = value2;
    }
  }

  return std::make_tuple(current_frame, value, write_index);
}

std::tuple<size_t, float, unsigned> AudioParamTimeline::ProcessSetTarget(
    const AutomationState& current_state,
    float* values,
    size_t current_frame,
    float value,
    unsigned write_index) {
#if defined(ARCH_CPU_X86_FAMILY)
  auto number_of_values = current_state.number_of_values;
#endif
  auto fill_to_frame = current_state.fill_to_frame;
  auto time1 = current_state.time1;
  auto value1 = current_state.value1;
  auto sample_rate = current_state.sample_rate;
  auto control_rate = current_state.control_ra
```
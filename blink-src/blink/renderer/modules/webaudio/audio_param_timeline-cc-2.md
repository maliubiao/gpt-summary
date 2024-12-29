Response:
The user wants to understand the functionality of the provided C++ code snippet from `blink/renderer/modules/webaudio/audio_param_timeline.cc`. Specifically, they are interested in:

1. A summary of the file's purpose.
2. Connections to web technologies (JavaScript, HTML, CSS).
3. Logical reasoning with example inputs and outputs.
4. Common usage errors.
5. How a user's actions lead to this code being executed (debugging clues).
6. A final concise summary of the file's function.

Let's break down the code and address each point.

**1. Summary of the file's purpose:**

The code defines the `AudioParamTimeline` class, which is responsible for managing and processing automation events for `AudioParam` objects in the Web Audio API. This involves calculating the parameter's value over time based on a series of scheduled events like setting a value, linearly ramping to a value, exponentially approaching a target, or following a curve.

**2. Connections to web technologies:**

*   **JavaScript:** This is the primary interface for interacting with the Web Audio API. JavaScript code uses methods like `setValueAtTime()`, `linearRampToValueAtTime()`, `exponentialRampToValueAtTime()`, `setTargetAtTime()`, and `setValueCurveAtTime()` on `AudioParam` objects to schedule automation events. The `AudioParamTimeline` processes these events.
*   **HTML:**  While not directly involved, the `<audio>` and `<video>` elements in HTML can be the source of audio streams manipulated by the Web Audio API, which in turn use `AudioParam`s.
*   **CSS:**  CSS is generally not directly involved with the core audio processing logic handled by this file. However, CSS animations or transitions *could* indirectly influence audio parameters if JavaScript code links those animations to Web Audio API calls.

**3. Logical reasoning with example inputs and outputs:**

Let's consider the `ProcessSetTarget` function as an example.

*   **Hypothetical Input:**
    *   `current_state.event->TimeConstant()` (time constant for the exponential approach): `0.1` seconds
    *   `current_state.event->Value()` (target value): `0.8`
    *   `current_state.time1` (start time of the event): `1.0` seconds
    *   `current_frame` (current frame being processed): `100`
    *   `sample_rate`: `44100` Hz
    *   `control_rate`: `4410` Hz
    *   `value` (current parameter value): `0.5`
    *   `write_index`: `0`
    *   `fill_to_frame`: `100` (processing the first frame of the quantum)

*   **Logical Steps:**
    1. Calculate `discrete_time_constant` using the provided helper function.
    2. Check if the current frame is close to the start frame of the event. If so, apply the exact exponential formula; otherwise, use the discretized version.
    3. Since `ramp_start_frame` (44100) is much greater than `current_frame` (100), the `else` branch is taken, and `value` is updated using the discretized formula: `value += (target - value) * discrete_time_constant;`
    4. Check if the value has converged to the target. If not, proceed with the loop to calculate the remaining values in the quantum.
    5. The SIMD optimization for x86 is attempted, calculating 4 values at a time.
    6. Finally, the remaining values are calculated serially.

*   **Hypothetical Output (for the first frame):**
    *   `values[0]` will be a value between `0.5` and `0.8`, closer to `0.5`. The exact value depends on the calculated `discrete_time_constant`.
    *   `current_frame` will be updated to `fill_to_end_frame`.
    *   `value` will be the calculated value for the last processed frame in the quantum.
    *   `write_index` will be equal to `fill_to_frame`.

**4. Common usage errors:**

*   **Setting automation events with times in the past:**  If a JavaScript developer schedules an automation event with a time that has already passed, the behavior might be unpredictable or the event might be missed. The timeline likely handles this, but it's a common conceptual error.
    *   **Example:** `audioParam.setValueAtTime(1.0, audioContext.currentTime - 0.5);`
*   **Conflicting automation events:**  Scheduling multiple events that try to control the same parameter at the same time can lead to unexpected results. The order of events matters.
    *   **Example:**
        ```javascript
        audioParam.setValueAtTime(0.0, 1.0);
        audioParam.linearRampToValueAtTime(1.0, 1.0);
        ```
*   **Incorrectly calculating time constants:** For `setTargetAtTime`, choosing a time constant that is too large or too small can lead to the parameter reaching the target value too slowly or too abruptly.
*   **Providing invalid curve data for `setValueCurveAtTime`:** The curve data should be a `Float32Array`. Providing incorrect data types or malformed arrays will cause errors.

**5. User operation leading to this code (debugging clues):**

1. **User interaction (or script execution):** A web page with JavaScript code is loaded in a Chromium-based browser.
2. **Web Audio API usage:** The JavaScript code uses the Web Audio API to create audio nodes and manipulate their parameters. For instance, setting the gain of a `GainNode`.
    ```javascript
    const audioContext = new AudioContext();
    const gainNode = audioContext.createGain();
    gainNode.gain.setValueAtTime(0.5, audioContext.currentTime);
    gainNode.gain.linearRampToValueAtTime(1.0, audioContext.currentTime + 1);
    ```
3. **Scheduling automation events:** Methods like `setValueAtTime`, `linearRampToValueAtTime`, etc., are called on an `AudioParam` object (e.g., `gainNode.gain`).
4. **Audio processing:** When the audio context processes a new audio buffer, it needs to determine the current value of the `AudioParam`.
5. **`AudioParamTimeline` interaction:** The `AudioParam` object uses its associated `AudioParamTimeline` to retrieve the correct parameter value for each sample frame within the current processing block (quantum).
6. **Execution of functions in `audio_param_timeline.cc`:**  The `Process` method of `AudioParamTimeline` is called, which iterates through the scheduled automation events and calls the appropriate processing function (e.g., `ProcessSetValue`, `ProcessLinearRamp`, `ProcessSetTarget`, `ProcessSetValueCurve`).

**Debugging Clues:**

*   **Breakpoints:** Setting breakpoints in the `Process` method and the individual processing functions within `audio_param_timeline.cc` allows developers to inspect the state of the timeline and the parameter values at each step.
*   **Logging:** Adding `DLOG` statements within the processing functions can help track the flow of execution and the values of important variables.
*   **Web Inspector:** Chromium's DevTools provide tools to inspect the state of Web Audio API objects, although direct inspection of the `AudioParamTimeline` might be limited. However, observing the behavior of audio parameters can indirectly point to issues within the timeline.
*   **Audio Worklet debugging:** If custom audio processing is involved through Audio Worklets, debugging the worklet code might reveal issues related to parameter automation.

**6. Concise summary of the file's function:**

`audio_param_timeline.cc` implements the `AudioParamTimeline` class, which is the core component responsible for calculating the value of an audio parameter over time based on a series of scheduled automation events defined in the Web Audio API. It handles various types of automation, including immediate value changes, linear and exponential ramps, and value curves, ensuring smooth and accurate parameter transitions during audio processing.

这是 `blink/renderer/modules/webaudio/audio_param_timeline.cc` 文件的第 3 部分，总共 3 部分。 根据提供的代码片段，我们可以归纳一下它的功能：

**主要功能归纳： 音频参数时间线的处理**

这个代码片段主要负责 `AudioParamTimeline` 类中处理不同类型音频参数自动化事件的逻辑。  它实现了在给定的时间范围内，根据预定的事件（例如，设置值、线性渐变、指数渐变、设置目标值、设置值曲线）计算出音频参数的取值。

**具体功能点：**

1. **`ProcessSetTarget` 函数:**  实现了指数逼近目标值的自动化过程。它根据给定的时间常数，平滑地将参数值从当前值过渡到目标值。该函数还包含针对 x86 架构的 SIMD 优化，以提高处理效率。
2. **`ProcessSetValueCurve` 函数:** 实现了根据预定义的曲线来改变参数值的自动化过程。它通过线性插值的方式，根据曲线数据计算出每一帧的参数值。同样，也包含针对 x86 架构的 SIMD 优化。
3. **`ProcessCancelValues` 函数:**  处理取消之前设置的自动化事件的情况。它会将参数值设置为取消事件发生时的值，并保持该值不变。
4. **`FillWithDefault` 函数:**  用默认值填充音频参数的缓冲区。
5. **`RemoveCancelledEvents` 函数:**  从事件列表中移除已取消的自动化事件。
6. **`RemoveOldEvents` 函数:**  移除时间线上过期的事件，保持事件列表的精简。

**与其他技术的关系：**

*   **JavaScript:**  这些函数处理的自动化事件通常是由 JavaScript 代码通过 Web Audio API 的 `AudioParam` 接口进行调度的。 例如：
    ```javascript
    const audioContext = new AudioContext();
    const gainNode = audioContext.createGain();
    const gainParam = gainNode.gain;

    // 设置目标值，在 1 秒后以 0.1 秒的时间常数逼近 0.5
    gainParam.setTargetAtTime(0.5, audioContext.currentTime + 1, 0.1);

    // 设置值曲线，在 2 秒后开始，持续 1 秒
    const curve = new Float32Array([0, 0.2, 0.8, 1]);
    gainParam.setValueCurveAtTime(curve, audioContext.currentTime + 2, 1);
    ```
    在这些 JavaScript 代码执行后，Blink 引擎会创建相应的 `ParamEvent` 对象，并将其添加到 `AudioParamTimeline` 中。当音频引擎需要计算参数值时，就会调用 `ProcessSetTarget` 或 `ProcessSetValueCurve` 等函数。

*   **HTML:** HTML 中的 `<audio>` 或 `<video>` 元素是音频数据的来源之一。Web Audio API 可以处理这些元素产生的音频流，并利用 `AudioParam` 节点来控制音频处理过程中的各种参数（例如音量、滤波器频率等）。`AudioParamTimeline` 负责管理这些参数的自动化。

*   **CSS:**  CSS 动画和过渡效果虽然不能直接控制 Web Audio API 的参数，但 JavaScript 可以监听 CSS 动画和过渡的事件，并根据这些事件来驱动 Web Audio API 参数的变化，从而间接地与 `AudioParamTimeline` 产生关联。

**逻辑推理的假设输入与输出 (以 `ProcessSetTarget` 为例):**

**假设输入：**

*   `current_state.event->TimeConstant()` (时间常数): `0.1` 秒
*   `current_state.event->Value()` (目标值): `1.0`
*   `value` (当前值): `0.0`
*   `current_frame`: `100`
*   `time1`: `0.0` 秒 (事件开始时间)
*   `sample_rate`: `44100` Hz
*   `control_rate`: `4410` Hz
*   `fill_to_frame`: `200`

**逻辑推理:**

1. 计算 `discrete_time_constant`。
2. 由于 `ramp_start_frame` (0) 小于等于 `current_frame` (100)，并且 `current_frame` 小于 `ramp_start_frame + 1` (1)，条件不成立。
3. 执行 `else` 分支，使用离散时间常数更新 `value`。
4. 循环从 `write_index` 到 `fill_to_frame`，根据指数逼近公式计算每一帧的参数值。由于代码中包含 SIMD 优化，会尝试一次计算 4 个值。
5. 如果循环结束后，参数值尚未完全收敛到目标值，则继续下一帧的计算。

**假设输出：**

*   `values` 数组中索引 0 到 199 的元素将包含从 `0.0` 指数逼近 `1.0` 的一系列值。
*   `current_frame` 将更新为 `fill_to_end_frame` 的值。
*   `value` 将是计算到最后一帧时的参数值，接近 `1.0`。
*   `write_index` 将等于 `fill_to_frame` (200)。

**用户或编程常见的使用错误：**

*   **在过去的时间设置自动化事件:** 用户可能会尝试设置一个发生在当前时间之前的自动化事件，例如：
    ```javascript
    gainParam.setValueAtTime(1.0, audioContext.currentTime - 1);
    ```
    在这种情况下，`AudioParamTimeline` 可能会立即应用该值，或者忽略该事件，具体取决于实现细节。这可能导致意外的音频行为。

*   **设置冲突的自动化事件:** 用户可能会在同一时间点设置多个互相冲突的自动化事件，例如：
    ```javascript
    gainParam.setValueAtTime(0.5, audioContext.currentTime);
    gainParam.linearRampToValueAtTime(1.0, audioContext.currentTime);
    ```
    在这种情况下，最终的参数值将取决于事件添加的顺序和处理逻辑，可能不是用户期望的结果。

*   **为 `setTargetAtTime` 设置不合适的 `timeConstant`:**  如果 `timeConstant` 设置得过小，参数值会非常快速地跳到目标值，听起来像是阶跃变化，而不是平滑过渡。如果设置得过大，参数值可能永远无法到达目标值或需要很长时间才能到达。

*   **为 `setValueCurveAtTime` 提供错误的曲线数据:**  如果提供的曲线数据不是 `Float32Array`，或者曲线数据的长度为 0 或负数，`ProcessSetValueCurve` 函数会进入错误处理分支，简单地传播之前的值。

**用户操作如何一步步地到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个包含 Web Audio API 代码的网页。**
2. **JavaScript 代码创建了一个 `AudioContext` 对象。**
3. **JavaScript 代码创建了一个或多个 `AudioNode` 对象（例如 `GainNode`）。**
4. **JavaScript 代码获取了 `AudioNode` 的 `AudioParam` 属性（例如 `gainNode.gain`）。**
5. **JavaScript 代码调用 `AudioParam` 的自动化方法（例如 `setValueAtTime`、`linearRampToValueAtTime` 等）来设置参数的随时间变化。**  这些调用会创建 `ParamEvent` 对象并添加到 `AudioParamTimeline` 中。
6. **音频渲染进程开始处理音频数据。**
7. **当需要计算某个 `AudioParam` 在特定时间点的取值时，`AudioParamTimeline::Process` 方法会被调用。**
8. **`Process` 方法会遍历时间线上的事件，并根据事件类型调用相应的处理函数，例如 `ProcessSetTarget`、`ProcessSetValueCurve` 或 `ProcessCancelValues`。**

**调试线索：**

*   在 JavaScript 代码中，检查 `AudioParam` 的自动化方法调用是否正确，包括时间和参数值的设置。
*   使用浏览器的开发者工具，查看 Web Audio API 的状态，例如 `AudioNode` 的参数值。
*   在 `blink/renderer/modules/webaudio/audio_param_timeline.cc` 中设置断点，例如在 `ProcessSetTarget` 或 `ProcessSetValueCurve` 函数的入口处，可以跟踪参数值的计算过程。
*   使用 `DLOG` 宏在关键代码路径上打印变量值，帮助理解代码的执行流程和参数变化。
*   检查 `ParamEvent` 对象的创建和添加过程，确保事件被正确地添加到 `AudioParamTimeline` 中。

总而言之，这个代码片段是 Web Audio API 中音频参数自动化功能的核心实现部分，它负责根据用户在 JavaScript 中设置的自动化事件，在音频渲染过程中精确地计算出参数的取值，从而实现各种动态的音频效果。

Prompt: 
```
这是目录为blink/renderer/modules/webaudio/audio_param_timeline.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
te;
  auto fill_to_end_frame = current_state.fill_to_end_frame;
  auto* event = current_state.event.get();

  // Exponential approach to target value with given time constant.
  //
  //   v(t) = v2 + (v1 - v2)*exp(-(t-t1/tau))
  //
  float target = value1;
  float time_constant = event->TimeConstant();
  float discrete_time_constant =
      static_cast<float>(audio_utilities::DiscreteTimeConstantForSampleRate(
          time_constant, control_rate));

  // Set the starting value correctly.  This is only needed when the
  // current time is "equal" to the start time of this event.  This is
  // to get the sampling correct if the start time of this automation
  // isn't on a frame boundary.  Otherwise, we can just continue from
  // where we left off from the previous rendering quantum.
  {
    double ramp_start_frame = time1 * sample_rate;
    // Condition is c - 1 < r <= c where c = currentFrame and r =
    // rampStartFrame.  Compute it this way because currentFrame is
    // unsigned and could be 0.
    if (ramp_start_frame <= current_frame &&
        current_frame < ramp_start_frame + 1) {
      value = target + (value - target) *
                           fdlibm::exp(-(current_frame / sample_rate - time1) /
                                       time_constant);
    } else {
      // Otherwise, need to compute a new value because `value` is the
      // last computed value of SetTarget.  Time has progressed by one
      // frame, so we need to update the value for the new frame.
      value += (target - value) * discrete_time_constant;
    }
  }

  // If the value is close enough to the target, just fill in the data
  // with the target value.
  if (HasSetTargetConverged(value, target, current_frame / sample_rate, time1,
                            time_constant)) {
    current_frame += fill_to_frame - write_index;
    for (; write_index < fill_to_frame; ++write_index) {
      values[write_index] = target;
    }
  } else {
#if defined(ARCH_CPU_X86_FAMILY)
    if (fill_to_frame > write_index) {
      // Resolve recursion by expanding constants to achieve a 4-step
      // loop unrolling.
      //
      // v1 = v0 + (t - v0) * c
      // v2 = v1 + (t - v1) * c
      // v2 = v0 + (t - v0) * c + (t - (v0 + (t - v0) * c)) * c
      // v2 = v0 + (t - v0) * c + (t - v0) * c - (t - v0) * c * c
      // v2 = v0 + (t - v0) * c * (2 - c)
      // Thus c0 = c, c1 = c*(2-c). The same logic applies to c2 and c3.
      const float c0 = discrete_time_constant;
      const float c1 = c0 * (2 - c0);
      const float c2 = c0 * ((c0 - 3) * c0 + 3);
      const float c3 = c0 * (c0 * ((4 - c0) * c0 - 6) + 4);

      float delta;
      __m128 v_c = _mm_set_ps(c2, c1, c0, 0);
      __m128 v_delta, v_value, v_result;

      // Process 4 loop steps.
      unsigned fill_to_frame_trunc =
          write_index + ((fill_to_frame - write_index) / 4) * 4;
      DCHECK_LE(fill_to_frame_trunc, number_of_values);

      for (; write_index < fill_to_frame_trunc; write_index += 4) {
        delta = target - value;
        v_delta = _mm_set_ps1(delta);
        v_value = _mm_set_ps1(value);

        v_result = _mm_add_ps(v_value, _mm_mul_ps(v_delta, v_c));
        _mm_storeu_ps(values + write_index, v_result);

        // Update value for next iteration.
        value += delta * c3;
      }
    }
#endif
    // Serially process remaining values
    for (; write_index < fill_to_frame; ++write_index) {
      values[write_index] = value;
      value += (target - value) * discrete_time_constant;
    }
    // The previous loops may have updated `value` one extra time.
    // Reset it to the last computed value.
    if (write_index >= 1) {
      value = values[write_index - 1];
    }
    current_frame = fill_to_end_frame;
  }

  return std::make_tuple(current_frame, value, write_index);
}

std::tuple<size_t, float, unsigned> AudioParamTimeline::ProcessSetValueCurve(
    const AutomationState& current_state,
    float* values,
    size_t current_frame,
    float value,
    unsigned write_index) {
  auto number_of_values = current_state.number_of_values;
  auto fill_to_frame = current_state.fill_to_frame;
  auto time1 = current_state.time1;
  auto sample_rate = current_state.sample_rate;
  auto start_frame = current_state.start_frame;
  auto end_frame = current_state.end_frame;
  auto fill_to_end_frame = current_state.fill_to_end_frame;
  auto* event = current_state.event.get();

  const Vector<float> curve = event->Curve();
  const float* curve_data = curve.data();
  unsigned number_of_curve_points = curve.size();

  float curve_end_value = event->CurveEndValue();

  // Curve events have duration, so don't just use next event time.
  double duration = event->Duration();
  // How much to step the curve index for each frame.  This is basically
  // the term (N - 1)/Td in the specification.
  double curve_points_per_frame = event->CurvePointsPerSecond() / sample_rate;

  if (!number_of_curve_points || duration <= 0 || sample_rate <= 0) {
    // Error condition - simply propagate previous value.
    current_frame = fill_to_end_frame;
    for (; write_index < fill_to_frame; ++write_index) {
      values[write_index] = value;
    }
    return std::make_tuple(current_frame, value, write_index);
  }

  // Save old values and recalculate information based on the curve's
  // duration instead of the next event time.
  size_t next_event_fill_to_frame = fill_to_frame;

  // fillToEndFrame = min(endFrame,
  //                      ceil(sampleRate * (time1 + duration))),
  // but compute this carefully in case sampleRate*(time1 + duration) is
  // huge.  fillToEndFrame is an exclusive upper bound of the last frame
  // to be computed, so ceil is used.
  {
    double curve_end_frame = ceil(sample_rate * (time1 + duration));
    if (end_frame > curve_end_frame) {
      fill_to_end_frame = static_cast<size_t>(curve_end_frame);
    } else {
      fill_to_end_frame = end_frame;
    }
  }

  // `fill_to_frame` can be less than `start_frame` when the end of the
  // setValueCurve automation has been reached, but the next automation
  // has not yet started. In this case, `fill_to_frame` is clipped to
  // `time1`+`duration` above, but `start_frame` will keep increasing
  // (because the current time is increasing).
  fill_to_frame = (fill_to_end_frame < start_frame)
                      ? 0
                      : static_cast<unsigned>(fill_to_end_frame - start_frame);
  fill_to_frame = std::min(fill_to_frame, number_of_values);

  // Index into the curve data using a floating-point value.
  // We're scaling the number of curve points by the duration (see
  // curvePointsPerFrame).
  double curve_virtual_index = 0;
  if (time1 < current_frame / sample_rate) {
    // Index somewhere in the middle of the curve data.
    // Don't use timeToSampleFrame() since we want the exact
    // floating-point frame.
    double frame_offset = current_frame - time1 * sample_rate;
    curve_virtual_index = curve_points_per_frame * frame_offset;
  }

  // Set the default value in case fillToFrame is 0.
  value = curve_end_value;

  // Render the stretched curve data using linear interpolation.
  // Oversampled curve data can be provided if sharp discontinuities are
  // desired.
  unsigned k = 0;
#if defined(ARCH_CPU_X86_FAMILY)
  if (fill_to_frame > write_index) {
    const __m128 v_curve_virtual_index = _mm_set_ps1(curve_virtual_index);
    const __m128 v_curve_points_per_frame = _mm_set_ps1(curve_points_per_frame);
    const __m128 v_number_of_curve_points_m1 =
        _mm_set_ps1(number_of_curve_points - 1);
    const __m128 v_n1 = _mm_set_ps1(1.0f);
    const __m128 v_n4 = _mm_set_ps1(4.0f);

    __m128 v_k = _mm_set_ps(3, 2, 1, 0);
    int a_curve_index0[4];
    int a_curve_index1[4];

    // Truncate loop steps to multiple of 4
    unsigned truncated_steps = ((fill_to_frame - write_index) / 4) * 4;
    unsigned fill_to_frame_trunc = write_index + truncated_steps;
    DCHECK_LE(fill_to_frame_trunc, number_of_values);

    for (; write_index < fill_to_frame_trunc; write_index += 4) {
      // Compute current index this way to minimize round-off that would
      // have occurred by incrementing the index by curvePointsPerFrame.
      __m128 v_current_virtual_index = _mm_add_ps(
          v_curve_virtual_index, _mm_mul_ps(v_k, v_curve_points_per_frame));
      v_k = _mm_add_ps(v_k, v_n4);

      // Clamp index to the last element of the array.
      __m128i v_curve_index0 = _mm_cvttps_epi32(
          _mm_min_ps(v_current_virtual_index, v_number_of_curve_points_m1));
      __m128i v_curve_index1 =
          _mm_cvttps_epi32(_mm_min_ps(_mm_add_ps(v_current_virtual_index, v_n1),
                                      v_number_of_curve_points_m1));

      // Linearly interpolate between the two nearest curve points.
      // `delta` is clamped to 1 because `current_virtual_index` can exceed
      // `curve_index0` by more than one.  This can happen when we reached
      // the end of the curve but still need values to fill out the
      // current rendering quantum.
      _mm_storeu_si128(reinterpret_cast<__m128i*>(a_curve_index0),
                       v_curve_index0);
      _mm_storeu_si128(reinterpret_cast<__m128i*>(a_curve_index1),
                       v_curve_index1);
      __m128 v_c0 = _mm_set_ps(
          curve_data[a_curve_index0[3]], curve_data[a_curve_index0[2]],
          curve_data[a_curve_index0[1]], curve_data[a_curve_index0[0]]);
      __m128 v_c1 = _mm_set_ps(
          curve_data[a_curve_index1[3]], curve_data[a_curve_index1[2]],
          curve_data[a_curve_index1[1]], curve_data[a_curve_index1[0]]);
      __m128 v_delta = _mm_min_ps(
          _mm_sub_ps(v_current_virtual_index, _mm_cvtepi32_ps(v_curve_index0)),
          v_n1);

      __m128 v_value =
          _mm_add_ps(v_c0, _mm_mul_ps(_mm_sub_ps(v_c1, v_c0), v_delta));

      _mm_storeu_ps(values + write_index, v_value);
    }
    // Pass along k to the serial loop.
    k = truncated_steps;
  }
  if (write_index >= 1) {
    value = values[write_index - 1];
  }
#endif
  for (; write_index < fill_to_frame; ++write_index, ++k) {
    // Compute current index this way to minimize round-off that would
    // have occurred by incrementing the index by curvePointsPerFrame.
    double current_virtual_index =
        curve_virtual_index + k * curve_points_per_frame;
    unsigned curve_index0;

    // Clamp index to the last element of the array.
    if (current_virtual_index < number_of_curve_points) {
      curve_index0 = static_cast<unsigned>(current_virtual_index);
    } else {
      curve_index0 = number_of_curve_points - 1;
    }

    unsigned curve_index1 =
        std::min(curve_index0 + 1, number_of_curve_points - 1);

    // Linearly interpolate between the two nearest curve points.  `delta` is
    // clamped to 1 because `current_virtual_index` can exceed `curve_index0` by
    // more than one.  This can happen when we reached the end of the curve but
    // still need values to fill out the current rendering quantum.
    DCHECK_LT(curve_index0, number_of_curve_points);
    DCHECK_LT(curve_index1, number_of_curve_points);
    float c0 = curve_data[curve_index0];
    float c1 = curve_data[curve_index1];
    double delta = std::min(current_virtual_index - curve_index0, 1.0);

    value = c0 + (c1 - c0) * delta;

    values[write_index] = value;
  }

  // If there's any time left after the duration of this event and the
  // start of the next, then just propagate the last value of the
  // `curve_data`. Don't modify `value` unless there is time left.
  if (write_index < next_event_fill_to_frame) {
    value = curve_end_value;
    for (; write_index < next_event_fill_to_frame; ++write_index) {
      values[write_index] = value;
    }
  }

  // Re-adjust current time
  current_frame += next_event_fill_to_frame;

  return std::make_tuple(current_frame, value, write_index);
}

std::tuple<size_t, float, unsigned> AudioParamTimeline::ProcessCancelValues(
    const AutomationState& current_state,
    float* values,
    size_t current_frame,
    float value,
    unsigned write_index) {
  auto fill_to_frame = current_state.fill_to_frame;
  auto time1 = current_state.time1;
  auto sample_rate = current_state.sample_rate;
  auto control_rate = current_state.control_rate;
  auto fill_to_end_frame = current_state.fill_to_end_frame;
  auto* event = current_state.event.get();
  auto event_index = current_state.event_index;

  // If the previous event was a SetTarget or ExponentialRamp
  // event, the current value is one sample behind.  Update
  // the sample value by one sample, but only at the start of
  // this CancelValues event.
  if (event->HasDefaultCancelledValue()) {
    value = event->Value();
  } else {
    double cancel_frame = time1 * sample_rate;
    if (event_index >= 1 && cancel_frame <= current_frame &&
        current_frame < cancel_frame + 1) {
      ParamEvent::Type last_event_type = events_[event_index - 1]->GetType();
      if (last_event_type == ParamEvent::kSetTarget) {
        float target = events_[event_index - 1]->Value();
        float time_constant = events_[event_index - 1]->TimeConstant();
        float discrete_time_constant = static_cast<float>(
            audio_utilities::DiscreteTimeConstantForSampleRate(time_constant,
                                                               control_rate));
        value += (target - value) * discrete_time_constant;
      }
    }
  }

  // Simply stay at the current value.
  for (; write_index < fill_to_frame; ++write_index) {
    values[write_index] = value;
  }

  current_frame = fill_to_end_frame;

  return std::make_tuple(current_frame, value, write_index);
}

uint32_t AudioParamTimeline::FillWithDefault(float* values,
                                             float default_value,
                                             uint32_t end_frame,
                                             uint32_t write_index) {
  uint32_t index = write_index;

  for (; index < end_frame; ++index) {
    values[index] = default_value;
  }

  return index;
}

void AudioParamTimeline::RemoveCancelledEvents(
    wtf_size_t first_event_to_remove) {
  // For all the events that are being removed, also remove that event
  // from `new_events_`.
  if (new_events_.size() > 0) {
    for (wtf_size_t k = first_event_to_remove; k < events_.size(); ++k) {
      new_events_.erase(events_[k].get());
    }
  }

  // Now we can remove the cancelled events from the list.
  events_.EraseAt(first_event_to_remove,
                  events_.size() - first_event_to_remove);
}

void AudioParamTimeline::RemoveOldEvents(wtf_size_t event_count) {
  wtf_size_t n_events = events_.size();
  DCHECK(event_count <= n_events);

  // Always leave at least one event in the event list!
  if (n_events > 1) {
    events_.EraseAt(0, std::min(event_count, n_events - 1));
  }
}

}  // namespace blink

"""


```
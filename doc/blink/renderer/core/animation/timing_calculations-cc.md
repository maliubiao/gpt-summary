Response:
Let's break down the thought process for analyzing this `timing_calculations.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to web technologies, examples of logical reasoning, and potential user/programming errors.

2. **Initial Scan for Keywords and Structure:**  I'd start by quickly reading through the code, looking for:
    * **Includes:** `third_party/blink/renderer/core/animation/timing_calculations.h`, `base/metrics/histogram_macros.h`. This immediately tells me it's part of Blink's animation system and involves some metric reporting.
    * **Namespaces:** `blink`, anonymous namespace. Confirms it's Blink-specific.
    * **Class Name:** `TimingCalculations`. This suggests a collection of functions related to timing calculations.
    * **Function Names:**  A large number of functions with names like `CalculatePhase`, `CalculateActiveTime`, `CalculateOverallProgress`, `IsWithinAnimationTimeTolerance`, etc. This strongly indicates the file is about computing different aspects of animation timing.
    * **Comments:**  Comments like `// https://w3.org/TR/web-animations-1/...` are crucial. They directly link the code to the Web Animations specification.
    * **Data Types:** `AnimationTimeDelta`, `Timing::Phase`, `Timing::NormalizedTiming`, `Timing::FillMode`, `Timing::PlaybackDirection`. These suggest the file works with specific animation-related data structures defined elsewhere.
    * **Mathematical Operations:** `std::abs`, `fmod`, `floor`, comparisons with epsilon. Points to numerical calculations and considerations for floating-point precision.
    * **Conditional Logic:** `if`, `switch` statements. Highlights the decision-making processes within the timing calculations.
    * **`DCHECK` statements:** Indicate internal consistency checks and assumptions the code makes.
    * **`UMA_HISTOGRAM_EXACT_LINEAR`:**  Confirms metric recording.

3. **Identify Core Functionality:** Based on the function names and the Web Animations spec links, the core functionality is clearly about calculating various time-related properties of animations. This includes:
    * Determining the current phase of an animation (before, active, after).
    * Calculating the active time within an animation.
    * Calculating progress through iterations (overall and simple).
    * Determining the current iteration number.
    * Handling playback direction (normal, reverse, alternate).
    * Applying timing functions (easing).

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **CSS Animations and Transitions:** The timing calculations directly implement the logic behind CSS animations and transitions. CSS properties like `animation-duration`, `animation-delay`, `animation-iteration-count`, `animation-direction`, `animation-fill-mode`, and `animation-timing-function` all map to concepts handled by this code.
    * **JavaScript Web Animations API:**  The file supports the JavaScript Web Animations API, which provides more fine-grained control over animations. The API's methods and properties correspond to the calculations performed here.
    * **HTML (Implicitly):**  Animations are applied to HTML elements, so this code is fundamental to how visual changes happen on web pages.

5. **Logical Reasoning and Examples:**  Focus on a few key functions to illustrate the logic:
    * **`CalculatePhase`:**  This is a good starting point. I'd analyze the conditions for being in `kPhaseBefore`, `kPhaseActive`, and `kPhaseAfter`, noting the importance of `normalized.start_delay`, `normalized.active_duration`, `normalized.end_time`, and the animation direction. A simple example with a specific `local_time` and `normalized` values would be helpful.
    * **`CalculateOverallProgress`:**  Demonstrate how `active_time` and `iteration_duration` contribute to the overall progress, considering the edge case of zero duration.
    * **`CalculateSimpleIterationProgress`:**  Explain the modulo operation and the special case when the progress reaches the end of an iteration.
    * **`IsCurrentDirectionForwards`:** Illustrate how the `current_iteration` and `PlaybackDirection` determine the playback direction within an iteration.

6. **User/Programming Errors:** Think about common mistakes developers make when working with animations:
    * **Floating-Point Precision Issues:** The code itself handles this with `TimingCalculationEpsilon`, so explain *why* this is necessary and how small discrepancies can cause unexpected behavior.
    * **Incorrect Timing Values:**  Provide examples of how setting conflicting or nonsensical values for animation properties (e.g., negative duration) can lead to unexpected results.
    * **Misunderstanding Fill Modes:** Explain how `fill-mode` affects the animation state before and after the active duration.
    * **Infinite Animations:** Discuss the implications of `iteration-count: infinite`.

7. **Refine and Structure:** Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the key functionalities, grouping related functions.
    * Provide clear examples for the logical reasoning sections, with explicit inputs and outputs.
    * Make the user/programming error examples practical and easy to understand.
    * Use clear headings and formatting to improve readability.

8. **Review and Verify:**  Read through the entire explanation to ensure accuracy and completeness. Check that the examples make sense and that the explanations are clear and concise. Ensure the terminology is correct and consistent with web animation standards. For example, double-check the meaning of `fill-mode: both`.

By following these steps, combining a high-level understanding with a closer examination of key code segments, and relating it back to the user-facing web technologies, I can construct a comprehensive and informative answer like the example provided.
这个 `timing_calculations.cc` 文件是 Chromium Blink 引擎中负责动画时间计算的核心组件。它定义了一系列静态方法，用于根据 Web Animations 规范计算动画在不同阶段和属性下的各种时间值和进度。

**主要功能列举:**

1. **定义时间相关的常量和阈值:**
   - `TimingCalculationEpsilon()`: 定义了一个用于比较浮点数是否接近相等的很小的阈值（epsilon）。这是为了处理浮点数运算的精度问题。
   - `TimeTolerance()`: 定义了一个动画时间差的容差值，用于判断两个 `AnimationTimeDelta` 是否在允许的误差范围内相等。

2. **提供用于比较动画时间的实用函数:**
   - `IsWithinAnimationTimeEpsilon(double a, double b)`: 判断两个 `double` 类型的动画时间是否在 epsilon 范围内相等。
   - `IsWithinAnimationTimeTolerance(AnimationTimeDelta a, AnimationTimeDelta b)`: 判断两个 `AnimationTimeDelta` 类型的动画时间是否在容差范围内相等。
   - `LessThanOrEqualToWithinEpsilon`, `LessThanOrEqualToWithinTimeTolerance`, `GreaterThanOrEqualToWithinEpsilon`, `GreaterThanOrEqualToWithinTimeTolerance`, `GreaterThanWithinTimeTolerance`: 提供带有容差的比较运算符。

3. **处理乘法操作，确保在其中一个操作数为零时结果为零:**
   - `MultiplyZeroAlwaysGivesZero(double x, double y)`
   - `MultiplyZeroAlwaysGivesZero(AnimationTimeDelta x, double y)`:  这在动画计算中处理零持续时间或零比例的情况时很有用。

4. **计算动画的阶段 (Phase):**
   - `CalculatePhase(const Timing::NormalizedTiming& normalized, std::optional<AnimationTimeDelta>& local_time, Timing::AnimationDirection direction)`:  根据动画的标准化时间属性、当前本地时间和播放方向，确定动画所处的阶段（`kPhaseBefore`, `kPhaseActive`, `kPhaseAfter`, `kPhaseNone`）。

5. **计算动画的激活时间 (Active Time):**
   - `CalculateActiveTime(const Timing::NormalizedTiming& normalized, Timing::FillMode fill_mode, std::optional<AnimationTimeDelta> local_time, Timing::Phase phase)`:  根据动画的标准化时间属性、填充模式、本地时间和当前阶段，计算动画的激活时间。

6. **计算动画的总体进度 (Overall Progress):**
   - `CalculateOverallProgress(Timing::Phase phase, std::optional<AnimationTimeDelta> active_time, AnimationTimeDelta iteration_duration, double iteration_count, double iteration_start)`:  根据动画阶段、激活时间、迭代持续时间、迭代次数和起始迭代，计算动画的总体进度（包括小数迭代）。

7. **计算动画的简单迭代进度 (Simple Iteration Progress):**
   - `CalculateSimpleIterationProgress(Timing::Phase phase, std::optional<double> overall_progress, double iteration_start, std::optional<AnimationTimeDelta> active_time, AnimationTimeDelta active_duration, double iteration_count)`: 计算当前迭代的进度，忽略播放方向和缓动函数的影响。

8. **计算动画的当前迭代次数 (Current Iteration):**
   - `CalculateCurrentIteration(Timing::Phase phase, std::optional<AnimationTimeDelta> active_time, double iteration_count, std::optional<double> overall_progress, std::optional<double> simple_iteration_progress)`:  计算动画当前正在进行的迭代次数。

9. **确定当前迭代是否为正向播放:**
   - `IsCurrentDirectionForwards(std::optional<double> current_iteration, Timing::PlaybackDirection direction)`:  根据当前迭代次数和播放方向（`normal`, `reverse`, `alternate-normal`, `alternate-reverse`），判断当前迭代是否为正向播放。

10. **计算动画的定向进度 (Directed Progress):**
    - `CalculateDirectedProgress(std::optional<double> simple_iteration_progress, std::optional<double> current_iteration, Timing::PlaybackDirection direction)`:  根据简单迭代进度、当前迭代次数和播放方向，计算考虑了播放方向的进度。

11. **计算动画的转换后进度 (Transformed Progress):**
    - `CalculateTransformedProgress(Timing::Phase phase, std::optional<double> directed_progress, bool is_current_direction_forward, scoped_refptr<TimingFunction> timing_function)`:  应用缓动函数（`TimingFunction`）到定向进度，得到最终的动画进度。

12. **计算偏移后的激活时间 (Offset Active Time) 和迭代时间 (Iteration Time):**
    - `CalculateOffsetActiveTime(...)`:  用于优化调度，计算从动画开始到当前位置的偏移时间。
    - `CalculateIterationTime(...)`:  计算当前迭代内的偏移时间。

13. **记录边界未对齐的指标:**
    - `RecordBoundaryMisalignment(AnimationTimeDelta misalignment)`:  当动画在迭代边界附近出现时间未对齐时，记录相关指标，用于性能分析和调试。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

这个文件中的函数直接对应了 Web Animations API 和 CSS Animations/Transitions 的底层实现。

* **CSS `animation-duration` 和 `transition-duration`:** `iteration_duration` 参数对应动画或过渡的持续时间。
* **CSS `animation-delay` 和 `transition-delay`:** `normalized.start_delay` 参数对应动画或过渡的延迟。
* **CSS `animation-iteration-count`:** `iteration_count` 参数对应动画的迭代次数，可以是数字或 `infinite`。
* **CSS `animation-direction`:** `direction` 参数对应动画的播放方向，如 `normal`, `reverse`, `alternate`, `alternate-reverse`。
* **CSS `animation-timing-function` 和 `transition-timing-function`:** `TimingFunction` 类及其子类对应各种缓动函数，如 `ease`, `linear`, `ease-in`, `ease-out`, `cubic-bezier()`, `steps()`。 `CalculateTransformedProgress` 函数就负责应用这些缓动函数。
* **CSS `animation-fill-mode`:** `fill_mode` 参数对应 `forwards`, `backwards`, `both`, `none` 这些值，影响动画在延迟或结束后应用样式的方式。`CalculateActiveTime` 函数会根据 `fill_mode` 来确定激活时间。
* **JavaScript Web Animations API 的 `currentTime` 属性:**  `local_time` 参数可以看作是通过 JavaScript 设置或获取的动画当前时间。
* **JavaScript Web Animations API 的 `playState` 属性:**  动画的阶段（`kPhaseBefore`, `kPhaseActive`, `kPhaseAfter`) 可以影响 JavaScript 中获取的 `playState`。
* **JavaScript Web Animations API 的 `playbackRate` 属性 (间接影响):** 虽然这个文件没有直接处理 `playbackRate`，但 `playbackRate` 的改变会影响动画的 `local_time`，从而影响这里计算出的其他时间值。

**举例说明:**

假设有以下 CSS 动画：

```css
.element {
  animation-name: slide;
  animation-duration: 2s;
  animation-delay: 1s;
  animation-iteration-count: 3;
  animation-direction: alternate;
  animation-timing-function: ease-in-out;
  animation-fill-mode: forwards;
}
```

对应到 `timing_calculations.cc` 中的计算：

* 当动画开始时（`local_time` 小于 `normalized.start_delay`），`CalculatePhase` 会返回 `kPhaseBefore`。
* 在延迟结束后，动画进入激活阶段 (`kPhaseActive`)。`CalculateActiveTime` 会根据当前 `local_time` 减去 `normalized.start_delay` 计算出激活时间。
* `CalculateOverallProgress` 会根据激活时间、迭代持续时间 (2s) 和迭代次数 (3) 计算出动画的总体进度。
* `IsCurrentDirectionForwards` 会根据当前的迭代次数是奇数还是偶数来确定播放方向（因为 `animation-direction: alternate`）。
* `CalculateDirectedProgress` 会根据 `IsCurrentDirectionForwards` 的结果来调整简单迭代进度。
* `CalculateTransformedProgress` 会使用 `ease-in-out` 对应的 `TimingFunction` 对象，将定向进度转换为最终的动画进度，影响元素的属性值。
* 当动画结束后（`local_time` 大于动画的总持续时间），并且 `animation-fill-mode` 为 `forwards`，动画会停留在最后一帧。`CalculatePhase` 会返回 `kPhaseAfter`，`CalculateActiveTime` 会返回 `normalized.active_duration`。

**逻辑推理的假设输入与输出:**

假设我们有一个简单的线性动画，持续 1 秒，没有延迟，迭代 1 次。

**假设输入:**

* `normalized.start_delay` = 0 秒
* `normalized.active_duration` = 1 秒
* `iteration_duration` = 1 秒
* `iteration_count` = 1
* `iteration_start` = 0
* `direction` = `Timing::PlaybackDirection::kNormal`
* `fill_mode` = `Timing::FillMode::NONE`
* `timing_function` 是线性缓动函数

**推理与输出示例:**

1. **`CalculatePhase`:**
   - 输入: `local_time` = 0.5 秒
   - 输出: `Timing::kPhaseActive` (因为 0 <= 0.5 < 1)

2. **`CalculateActiveTime`:**
   - 输入: `local_time` = 0.5 秒, `phase` = `Timing::kPhaseActive`
   - 输出: 0.5 秒 (0.5 - 0)

3. **`CalculateOverallProgress`:**
   - 输入: `active_time` = 0.5 秒
   - 输出: 0.5 (0.5 / 1 + 0)

4. **`CalculateSimpleIterationProgress`:**
   - 输入: `overall_progress` = 0.5
   - 输出: 0.5 (fmod(0.5, 1))

5. **`CalculateDirectedProgress`:**
   - 输入: `simple_iteration_progress` = 0.5, `current_iteration` = 0
   - 输出: 0.5 (因为是正向播放)

6. **`CalculateTransformedProgress`:**
   - 输入: `directed_progress` = 0.5, `timing_function` 是线性的
   - 输出: 0.5 (线性缓动函数直接返回输入值)

**用户或编程常见的使用错误举例说明:**

1. **浮点数精度问题:**  直接使用 `==` 比较动画时间可能会因为浮点数精度问题而失败。例如：
   ```c++
   AnimationTimeDelta t1 = ANIMATION_TIME_DELTA_FROM_MILLISECONDS(100);
   AnimationTimeDelta t2 = ANIMATION_TIME_DELTA_FROM_SECONDS(0.1);
   // t1 和 t2 在逻辑上相等，但直接比较可能返回 false
   if (t1 == t2) { // 错误的做法
       // ...
   }
   if (TimingCalculations::IsWithinAnimationTimeTolerance(t1, t2)) { // 正确的做法
       // ...
   }
   ```

2. **对 `fmod` 的误用:** 在计算迭代进度时，如果直接使用 `fmod` 而不考虑精度问题，可能会在迭代边界产生细微的误差。`TimingCalculations` 中使用了 `IsWithinAnimationTimeEpsilon` 来处理这些情况。

3. **不理解 `fill-mode` 的作用:**  开发者可能错误地认为动画结束后元素会恢复到初始状态，而忽略了 `fill-mode: forwards` 或 `both` 会保持动画结束时的状态。这会导致视觉效果上的困惑。

4. **设置不合理的动画属性值:** 例如，设置负的 `animation-duration` 或 `transition-duration` 可能会导致未定义的行为。虽然浏览器通常会处理这些错误，但理解这些属性的含义至关重要。

5. **在 JavaScript 中进行不精确的时间比较:**  与 C++ 类似，在 JavaScript 中比较动画时间时也需要注意精度问题。应该使用适当的容差值进行比较，而不是直接使用 `===`。

总而言之，`timing_calculations.cc` 文件是 Blink 动画系统的核心，它精确地实现了 Web Animations 规范中关于时间计算的部分，确保了各种动画效果的正确执行。理解这个文件中的功能可以帮助开发者更好地理解和使用 CSS Animations、CSS Transitions 和 JavaScript Web Animations API。

### 提示词
```
这是目录为blink/renderer/core/animation/timing_calculations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/timing_calculations.h"

#include "base/metrics/histogram_macros.h"

namespace blink {

namespace {

inline bool EndsOnIterationBoundary(double iteration_count,
                                    double iteration_start) {
  DCHECK(std::isfinite(iteration_count));
  return !fmod(iteration_count + iteration_start, 1);
}

void RecordBoundaryMisalignment(AnimationTimeDelta misalignment) {
  // Animations require 1 microsecond precision. For a scroll-based animation,
  // percentages are internally converted to time. The animation duration in
  // microseconds is 16 * (range in pixels).
  // Refer to cc/animations/scroll_timeline.h for details.
  //
  // It is not particularly meaningful to report the misalignment as a time
  // since there is no dependency on having a high resolution timer. Instead,
  // we convert back to 16ths of a pixel by scaling accordingly.
  int sample = std::round<int>(misalignment.InMicrosecondsF());
  UMA_HISTOGRAM_EXACT_LINEAR("Blink.Animation.SDA.BoundaryMisalignment", sample,
                             64);
}

}  // namespace

double TimingCalculations::TimingCalculationEpsilon() {
  // Permit 2-bits of quantization error. Threshold based on experimentation
  // with accuracy of fmod.
  return 2.0 * std::numeric_limits<double>::epsilon();
}

AnimationTimeDelta TimingCalculations::TimeTolerance() {
  return ANIMATION_TIME_DELTA_FROM_SECONDS(0.000001 /*one microsecond*/);
}

bool TimingCalculations::IsWithinAnimationTimeEpsilon(double a, double b) {
  return std::abs(a - b) <= TimingCalculationEpsilon();
}

bool TimingCalculations::IsWithinAnimationTimeTolerance(AnimationTimeDelta a,
                                                        AnimationTimeDelta b) {
  if (a.is_inf() || b.is_inf()) {
    return a == b;
  }
  AnimationTimeDelta difference = a >= b ? a - b : b - a;
  return difference <= TimeTolerance();
}

bool TimingCalculations::LessThanOrEqualToWithinEpsilon(double a, double b) {
  return a <= b + TimingCalculationEpsilon();
}

bool TimingCalculations::LessThanOrEqualToWithinTimeTolerance(
    AnimationTimeDelta a,
    AnimationTimeDelta b) {
  return a <= b + TimeTolerance();
}

bool TimingCalculations::GreaterThanOrEqualToWithinEpsilon(double a, double b) {
  return a >= b - TimingCalculationEpsilon();
}

bool TimingCalculations::GreaterThanOrEqualToWithinTimeTolerance(
    AnimationTimeDelta a,
    AnimationTimeDelta b) {
  return a >= b - TimeTolerance();
}

bool TimingCalculations::GreaterThanWithinTimeTolerance(AnimationTimeDelta a,
                                                        AnimationTimeDelta b) {
  return a > b - TimeTolerance();
}

double TimingCalculations::MultiplyZeroAlwaysGivesZero(double x, double y) {
  DCHECK(!std::isnan(x));
  DCHECK(!std::isnan(y));
  return x && y ? x * y : 0;
}

AnimationTimeDelta TimingCalculations::MultiplyZeroAlwaysGivesZero(
    AnimationTimeDelta x,
    double y) {
  DCHECK(!std::isnan(y));
  return x.is_zero() || y == 0 ? AnimationTimeDelta() : (x * y);
}

// https://w3.org/TR/web-animations-1/#animation-effect-phases-and-states
Timing::Phase TimingCalculations::CalculatePhase(
    const Timing::NormalizedTiming& normalized,
    std::optional<AnimationTimeDelta>& local_time,
    Timing::AnimationDirection direction) {
  DCHECK(GreaterThanOrEqualToWithinTimeTolerance(normalized.active_duration,
                                                 AnimationTimeDelta()));
  if (!local_time) {
    return Timing::kPhaseNone;
  }

  AnimationTimeDelta before_active_boundary_time =
      std::max(std::min(normalized.start_delay, normalized.end_time),
               AnimationTimeDelta());
  if (IsWithinAnimationTimeTolerance(local_time.value(),
                                     before_active_boundary_time)) {
    local_time = before_active_boundary_time;
  }

  if (local_time.value() < before_active_boundary_time) {
    if (normalized.is_start_boundary_aligned) {
      RecordBoundaryMisalignment(before_active_boundary_time -
                                 local_time.value());
    }
    return Timing::kPhaseBefore;
  }
  if ((direction == Timing::AnimationDirection::kBackwards &&
       local_time.value() == before_active_boundary_time &&
       !normalized.is_start_boundary_aligned)) {
    return Timing::kPhaseBefore;
  }

  AnimationTimeDelta active_after_boundary_time =
      std::max(std::min(normalized.start_delay + normalized.active_duration,
                        normalized.end_time),
               AnimationTimeDelta());
  if (IsWithinAnimationTimeTolerance(local_time.value(),
                                     active_after_boundary_time)) {
    local_time = active_after_boundary_time;
  }
  if (local_time.value() > active_after_boundary_time) {
    if (normalized.is_end_boundary_aligned) {
      RecordBoundaryMisalignment(local_time.value() -
                                 active_after_boundary_time);
    }
    return Timing::kPhaseAfter;
  }
  if ((direction == Timing::AnimationDirection::kForwards &&
       local_time.value() == active_after_boundary_time &&
       !normalized.is_end_boundary_aligned)) {
    return Timing::kPhaseAfter;
  }
  return Timing::kPhaseActive;
}

// https://w3.org/TR/web-animations-1/#calculating-the-active-time
std::optional<AnimationTimeDelta> TimingCalculations::CalculateActiveTime(
    const Timing::NormalizedTiming& normalized,
    Timing::FillMode fill_mode,
    std::optional<AnimationTimeDelta> local_time,
    Timing::Phase phase) {
  DCHECK(GreaterThanOrEqualToWithinTimeTolerance(normalized.active_duration,
                                                 AnimationTimeDelta()));
  switch (phase) {
    case Timing::kPhaseBefore:
      if (fill_mode == Timing::FillMode::BACKWARDS ||
          fill_mode == Timing::FillMode::BOTH) {
        DCHECK(local_time.has_value());
        return std::max(local_time.value() - normalized.start_delay,
                        AnimationTimeDelta());
      }
      return std::nullopt;
    case Timing::kPhaseActive:
      DCHECK(local_time.has_value());
      return local_time.value() - normalized.start_delay;
    case Timing::kPhaseAfter:
      if (fill_mode == Timing::FillMode::FORWARDS ||
          fill_mode == Timing::FillMode::BOTH) {
        DCHECK(local_time.has_value());
        return std::max(AnimationTimeDelta(),
                        std::min(normalized.active_duration,
                                 local_time.value() - normalized.start_delay));
      }
      return std::nullopt;
    case Timing::kPhaseNone:
      DCHECK(!local_time.has_value());
      return std::nullopt;
    default:
      NOTREACHED();
  }
}

// Calculates the overall progress, which describes the number of iterations
// that have completed (including partial iterations).
// https://w3.org/TR/web-animations-1/#calculating-the-overall-progress
std::optional<double> TimingCalculations::CalculateOverallProgress(
    Timing::Phase phase,
    std::optional<AnimationTimeDelta> active_time,
    AnimationTimeDelta iteration_duration,
    double iteration_count,
    double iteration_start) {
  // 1. If the active time is unresolved, return unresolved.
  if (!active_time) {
    return std::nullopt;
  }

  // 2. Calculate an initial value for overall progress.
  double overall_progress = 0;
  if (IsWithinAnimationTimeTolerance(iteration_duration,
                                     AnimationTimeDelta())) {
    if (phase != Timing::kPhaseBefore) {
      overall_progress = iteration_count;
    }
  } else {
    overall_progress = (active_time.value() / iteration_duration);
  }

  return overall_progress + iteration_start;
}

// Calculates the simple iteration progress, which is a fraction of the progress
// through the current iteration that ignores transformations to the time
// introduced by the playback direction or timing functions applied to the
// effect.
// https://w3.org/TR/web-animations-1/#calculating-the-simple-iteration-progress
std::optional<double> TimingCalculations::CalculateSimpleIterationProgress(
    Timing::Phase phase,
    std::optional<double> overall_progress,
    double iteration_start,
    std::optional<AnimationTimeDelta> active_time,
    AnimationTimeDelta active_duration,
    double iteration_count) {
  // 1. If the overall progress is unresolved, return unresolved.
  if (!overall_progress) {
    return std::nullopt;
  }

  // 2. If overall progress is infinity, let the simple iteration progress be
  // iteration start % 1.0, otherwise, let the simple iteration progress be
  // overall progress % 1.0.
  double simple_iteration_progress = std::isinf(overall_progress.value())
                                         ? fmod(iteration_start, 1.0)
                                         : fmod(overall_progress.value(), 1.0);

  // active_time is not null is because overall_progress != null and
  // CalculateOverallProgress() only returns null when active_time is null.
  DCHECK(active_time);

  // 3. If all of the following conditions are true,
  //   * the simple iteration progress calculated above is zero, and
  //   * the animation effect is in the active phase or the after phase, and
  //   * the active time is equal to the active duration, and
  //   * the iteration count is not equal to zero.
  // let the simple iteration progress be 1.0.
  if (IsWithinAnimationTimeEpsilon(simple_iteration_progress, 0.0) &&
      (phase == Timing::kPhaseActive || phase == Timing::kPhaseAfter) &&
      IsWithinAnimationTimeTolerance(active_time.value(), active_duration) &&
      !IsWithinAnimationTimeEpsilon(iteration_count, 0.0)) {
    simple_iteration_progress = 1.0;
  }

  // 4. Return simple iteration progress.
  return simple_iteration_progress;
}

// https://w3.org/TR/web-animations-1/#calculating-the-current-iteration
std::optional<double> TimingCalculations::CalculateCurrentIteration(
    Timing::Phase phase,
    std::optional<AnimationTimeDelta> active_time,
    double iteration_count,
    std::optional<double> overall_progress,
    std::optional<double> simple_iteration_progress) {
  // 1. If the active time is unresolved, return unresolved.
  if (!active_time) {
    return std::nullopt;
  }

  // 2. If the animation effect is in the after phase and the iteration count
  // is infinity, return infinity.
  if (phase == Timing::kPhaseAfter && std::isinf(iteration_count)) {
    return std::numeric_limits<double>::infinity();
  }

  if (!overall_progress) {
    return std::nullopt;
  }

  // simple iteration progress can only be null if overall progress is null.
  DCHECK(simple_iteration_progress);

  // 3. If the simple iteration progress is 1.0, return floor(overall progress)
  // - 1.
  if (simple_iteration_progress.value() == 1.0) {
    // Safeguard for zero duration animation (crbug.com/954558).
    return fmax(0, floor(overall_progress.value()) - 1);
  }

  // 4. Otherwise, return floor(overall progress).
  return floor(overall_progress.value());
}

// https://w3.org/TR/web-animations-1/#calculating-the-directed-progress
bool TimingCalculations::IsCurrentDirectionForwards(
    std::optional<double> current_iteration,
    Timing::PlaybackDirection direction) {
  const bool current_iteration_is_even =
      !current_iteration ? false
                         : (std::isinf(current_iteration.value())
                                ? true
                                : IsWithinAnimationTimeEpsilon(
                                      fmod(current_iteration.value(), 2), 0));

  switch (direction) {
    case Timing::PlaybackDirection::NORMAL:
      return true;

    case Timing::PlaybackDirection::REVERSE:
      return false;

    case Timing::PlaybackDirection::ALTERNATE_NORMAL:
      return current_iteration_is_even;

    case Timing::PlaybackDirection::ALTERNATE_REVERSE:
      return !current_iteration_is_even;
  }
}

// https://w3.org/TR/web-animations-1/#calculating-the-directed-progress
std::optional<double> TimingCalculations::CalculateDirectedProgress(
    std::optional<double> simple_iteration_progress,
    std::optional<double> current_iteration,
    Timing::PlaybackDirection direction) {
  // 1. If the simple progress is unresolved, return unresolved.
  if (!simple_iteration_progress) {
    return std::nullopt;
  }

  // 2. Calculate the current direction.
  bool current_direction_is_forwards =
      IsCurrentDirectionForwards(current_iteration, direction);

  // 3. If the current direction is forwards then return the simple iteration
  // progress. Otherwise return 1 - simple iteration progress.
  return current_direction_is_forwards ? simple_iteration_progress.value()
                                       : 1 - simple_iteration_progress.value();
}

// https://w3.org/TR/web-animations-1/#calculating-the-transformed-progress
std::optional<double> TimingCalculations::CalculateTransformedProgress(
    Timing::Phase phase,
    std::optional<double> directed_progress,
    bool is_current_direction_forward,
    scoped_refptr<TimingFunction> timing_function) {
  if (!directed_progress) {
    return std::nullopt;
  }

  // Set the before flag to indicate if at the leading edge of an iteration.
  // This is used to determine if the left or right limit should be used if at a
  // discontinuity in the timing function.
  bool before = is_current_direction_forward ? phase == Timing::kPhaseBefore
                                             : phase == Timing::kPhaseAfter;
  TimingFunction::LimitDirection limit_direction =
      before ? TimingFunction::LimitDirection::LEFT
             : TimingFunction::LimitDirection::RIGHT;

  // Snap boundaries to correctly render step timing functions at 0 and 1.
  // (crbug.com/949373)
  if (phase == Timing::kPhaseAfter) {
    if (is_current_direction_forward &&
        IsWithinAnimationTimeEpsilon(directed_progress.value(), 1)) {
      directed_progress = 1;
    } else if (!is_current_direction_forward &&
               IsWithinAnimationTimeEpsilon(directed_progress.value(), 0)) {
      directed_progress = 0;
    }
  }

  // Return the result of evaluating the animation effect’s timing function
  // passing directed progress as the input progress value.
  return timing_function->Evaluate(directed_progress.value(), limit_direction);
}

// Offsets the active time by how far into the animation we start (i.e. the
// product of the iteration start and iteration duration). This is not part of
// the Web Animations spec; it is used for calculating the time until the next
// iteration to optimize scheduling.
std::optional<AnimationTimeDelta> TimingCalculations::CalculateOffsetActiveTime(
    AnimationTimeDelta active_duration,
    std::optional<AnimationTimeDelta> active_time,
    AnimationTimeDelta start_offset) {
  DCHECK(GreaterThanOrEqualToWithinTimeTolerance(active_duration,
                                                 AnimationTimeDelta()));
  DCHECK(GreaterThanOrEqualToWithinTimeTolerance(start_offset,
                                                 AnimationTimeDelta()));

  if (!active_time) {
    return std::nullopt;
  }

  DCHECK(GreaterThanOrEqualToWithinTimeTolerance(active_time.value(),
                                                 AnimationTimeDelta()) &&
         LessThanOrEqualToWithinTimeTolerance(active_time.value(),
                                              active_duration));

  if (active_time->is_max()) {
    return AnimationTimeDelta::Max();
  }

  return active_time.value() + start_offset;
}

// Maps the offset active time into 'iteration time space'[0], aka the offset
// into the current iteration. This is not part of the Web Animations spec (note
// that the section linked below is non-normative); it is used for calculating
// the time until the next iteration to optimize scheduling.
//
// [0] https://w3.org/TR/web-animations-1/#iteration-time-space
std::optional<AnimationTimeDelta> TimingCalculations::CalculateIterationTime(
    AnimationTimeDelta iteration_duration,
    AnimationTimeDelta active_duration,
    std::optional<AnimationTimeDelta> offset_active_time,
    AnimationTimeDelta start_offset,
    Timing::Phase phase,
    const Timing& specified) {
  DCHECK(
      GreaterThanWithinTimeTolerance(iteration_duration, AnimationTimeDelta()));
  DCHECK(IsWithinAnimationTimeTolerance(
      active_duration, MultiplyZeroAlwaysGivesZero(iteration_duration,
                                                   specified.iteration_count)));

  if (!offset_active_time) {
    return std::nullopt;
  }

  DCHECK(GreaterThanWithinTimeTolerance(offset_active_time.value(),
                                        AnimationTimeDelta()));
  DCHECK(LessThanOrEqualToWithinTimeTolerance(
      offset_active_time.value(), (active_duration + start_offset)));

  if (offset_active_time->is_max() ||
      (IsWithinAnimationTimeTolerance(offset_active_time.value() - start_offset,
                                      active_duration) &&
       specified.iteration_count &&
       EndsOnIterationBoundary(specified.iteration_count,
                               specified.iteration_start))) {
    return std::make_optional(iteration_duration);
  }

  DCHECK(!offset_active_time->is_max());
  AnimationTimeDelta iteration_time = ANIMATION_TIME_DELTA_FROM_SECONDS(
      fmod(offset_active_time->InSecondsF(), iteration_duration.InSecondsF()));

  // This implements step 3 of
  // https://w3.org/TR/web-animations-1/#calculating-the-simple-iteration-progress
  if (iteration_time.is_zero() && phase == Timing::kPhaseAfter &&
      !active_duration.is_zero() && !offset_active_time.value().is_zero()) {
    return std::make_optional(iteration_duration);
  }

  return iteration_time;
}

}  // namespace blink
```
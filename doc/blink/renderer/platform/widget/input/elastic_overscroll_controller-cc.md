Response:
My thought process for analyzing the `elastic_overscroll_controller.cc` file and generating the summary involved the following steps:

1. **Understand the Core Functionality:**  The file name itself, "elastic_overscroll_controller," strongly suggests its primary purpose: managing the "elastic" or "rubber-band" effect when scrolling beyond the content boundaries. The comments at the beginning, including the copyright notice and the note about Apple's contribution, reinforce this idea.

2. **Identify Key Data Structures and Members:** I looked for the main class definition (`ElasticOverscrollController`) and its member variables. Key members I noted early on were:
    * `helper_`: A pointer to `cc::ScrollElasticityHelper`, indicating interaction with the Compositor thread and its scrolling mechanisms.
    * `state_`: An enum (`kStateInactive`, `kStateActiveScroll`, `kStateMomentumScroll`, `kStateMomentumAnimated`) representing the current state of the overscroll interaction.
    * `scroll_velocity_`, `last_scroll_event_timestamp_`:  Variables related to tracking scroll velocity, crucial for momentum-based effects.
    * `pending_overscroll_delta_`:  Used to accumulate small overscroll deltas before the elastic effect kicks in.
    * `stretch_scroll_force_`, `momentum_animation_...`: Variables specifically for managing the elastic "stretch" and its animation.

3. **Analyze Key Methods and Their Purpose:** I went through the methods of the `ElasticOverscrollController` class, paying attention to their names and what they do:
    * `Create()`:  A static factory method, important for understanding how different platform implementations are handled (Windows uses `ElasticOverscrollControllerBezier`, others use `ElasticOverscrollControllerExponential`).
    * `ObserveRealScrollBegin()`, `ObserveScrollUpdate()`, `ObserveRealScrollEnd()`: Methods that react to the beginning, updates, and end of real scrolling actions. These are central to the controller's logic.
    * `ObserveGestureEventAndResult()`:  Handles `WebGestureEvent`s, translating them into the controller's internal actions. This is where the interaction with browser input events happens.
    * `UpdateVelocity()`:  Calculates scroll velocity, important for momentum.
    * `Overscroll()`: The core method that applies the elastic overscroll logic, including the rubber-band effect and checks for scroll limits.
    * `EnterStateInactive()`, `EnterStateMomentumAnimated()`: Methods for managing the state transitions.
    * `Animate()`:  Handles the animation of the elastic effect returning to normal.
    * `PinnedHorizontally()`, `PinnedVertically()`, `CanScrollHorizontally()`, `CanScrollVertically()`: Utility methods for determining scroll boundaries and capabilities.
    * `ReconcileStretchAndScroll()`:  A method to ensure consistency between the elastic stretch and the actual scroll offset.

4. **Identify Interactions with Other Components:** The presence of `#include` statements and the types used in method parameters hinted at interactions with other parts of the Chromium architecture:
    * `cc::ScrollElasticityHelper`:  Strong dependency on the Compositor for applying visual effects.
    * `WebGestureEvent`:  Interaction with the input event handling system.
    * `cc::OverscrollBehavior`:  Reading overscroll behavior settings.
    * `ui::ScrollGranularity`:  Checking the granularity of scroll events.

5. **Connect Functionality to User Experience (and Web Technologies):** I considered how the code's behavior translates to what a user sees and experiences in a web browser. This led to connecting the overscroll effect to:
    * **JavaScript:**  JavaScript can trigger scrolling, and thus indirectly interact with this controller. Events like `scroll` could potentially trigger overscroll.
    * **HTML/CSS:** CSS properties like `overflow`, `-webkit-overflow-scrolling`, and potentially scroll anchoring affect the behavior of scrollable elements, which directly influences when and how the elastic overscroll controller comes into play. The `overscroll-behavior` CSS property is directly related.

6. **Formulate Examples and Scenarios:** Based on the understanding of the code, I devised examples to illustrate:
    * The effect of overscrolling.
    * How different states are entered and exited.
    * How the momentum animation works.
    * Potential user/programming errors.

7. **Structure the Output:** I organized the information into logical sections: Functionality, Relationship with Web Technologies, Logic Inference (with assumptions and input/output), and Common Errors. This structure makes the information easier to understand.

8. **Refine and Elaborate:** I reviewed my initial analysis and added more detail where needed. For example, I clarified the platform-specific behavior (Windows vs. other platforms) and elaborated on the role of `cc::ScrollElasticityHelper`. I also made sure the examples were concrete and easy to grasp.

Essentially, I followed a process of understanding the code's purpose, dissecting its components, tracing the flow of execution, and connecting it back to the user experience and relevant web technologies. The comments in the code were very helpful in understanding the intent behind certain sections. The variable names, while sometimes long, were generally descriptive, aiding in the analysis.

这个文件 `elastic_overscroll_controller.cc` 是 Chromium Blink 引擎中负责实现**弹性（或橡皮筋）滚动效果**的核心组件。 当用户滚动到可滚动内容的边缘并继续拖动时，会产生这种视觉效果，模拟物理上的弹性拉伸和回弹。

以下是它的主要功能：

**1. 管理弹性过滚动状态：**

*   维护当前弹性过滚动的状态，例如 `kStateInactive` (未激活), `kStateActiveScroll` (主动滚动), `kStateMomentumScroll` (动量滚动), `kStateMomentumAnimated` (动量动画)。
*   根据用户的滚动交互（例如，手势事件）在这些状态之间切换。

**2. 处理滚动事件和计算过滚动量:**

*   监听来自 Chromium 合成器线程（Compositor Thread）的滚动事件。
*   计算超出滚动边界的过滚动量 (`unused_scroll_delta`)。

**3. 应用弹性过滚动效果:**

*   使用不同的算法（例如，Bezier 曲线或指数衰减）来模拟弹性效果。 具体使用哪种算法取决于平台（Windows 使用 Bezier，其他平台使用指数衰减）。
*   通过 `cc::ScrollElasticityHelper` 与合成器通信，来实际应用视觉上的拉伸效果。这通常涉及到在渲染层面上调整内容的位置或形变。

**4. 处理动量滚动:**

*   跟踪滚动速度，并在滚动结束后模拟动量效果，使得过滚动能够平滑地回弹。
*   使用动画来平滑地将过滚动量恢复到零。

**5. 考虑滚动边界和 `overscroll-behavior` CSS 属性:**

*   检查内容是否可滚动以及当前是否到达滚动边界。
*   尊重 CSS 的 `overscroll-behavior` 属性，该属性允许开发者控制元素的滚动链接行为，例如禁止弹性过滚动。

**6. 避免意外触发:**

*   设定最小的过滚动阈值 (`kRubberbandMinimumRequiredDeltaBeforeStretch`)，避免微小的滚动偏移触发弹性效果。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:** JavaScript 可以触发滚动操作，例如通过 `scrollTo()` 或修改 `scrollLeft`/`scrollTop` 属性。 这些操作最终会触发底层的滚动事件，并被 `ElasticOverscrollController` 处理。
    *   **例子：** JavaScript 代码 `element.scrollBy({top: 1000, behavior: 'smooth'});`  如果 `element` 已经滚动到最底部，继续滚动可能会触发弹性过滚动效果，而 `ElasticOverscrollController` 负责实现这个效果的视觉呈现。
*   **HTML:** HTML 结构定义了可滚动的内容区域。  只有当 HTML 元素具有滚动能力（例如，设置了 `overflow: auto` 或 `overflow: scroll`）时，弹性过滚动才有可能发生。
*   **CSS:**
    *   **`overflow` 属性:**  决定了内容溢出时是否显示滚动条以及如何滚动。  `auto` 和 `scroll` 值会使元素可滚动。
    *   **`-webkit-overflow-scrolling: touch;` (WebKit 特有):**  在 iOS 和一些 Android 浏览器上启用硬件加速的滚动，这通常与弹性过滚动效果关联。
    *   **`overscroll-behavior` 属性:**  这个 CSS 属性直接影响 `ElasticOverscrollController` 的行为。
        *   `overscroll-behavior: auto;` (默认):  启用默认的弹性过滚动效果。
        *   `overscroll-behavior: contain;`:  阻止滚动冒泡到父元素，并且禁用当前元素的弹性过滚动效果。
        *   `overscroll-behavior: none;`:  完全禁用当前元素的弹性过滚动效果。
        *   `overscroll-behavior-x`, `overscroll-behavior-y`:  分别控制水平和垂直方向的弹性过滚动。
    *   **例子：**
        ```html
        <div style="width: 200px; height: 100px; overflow: auto; overscroll-behavior: contain;">
          <p>一些很长的内容...</p>
        </div>
        ```
        在这个例子中，`overscroll-behavior: contain;` 会阻止 `div` 元素的弹性过滚动效果。 当用户滚动到内容的边缘时，不会看到橡皮筋效果。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. **用户手势:** 用户在垂直方向向上滑动，超过可滚动内容的顶部边界。
2. **当前状态:**  滚动容器处于非动量滚动状态 (`kStateActiveScroll`)。
3. **过滚动增量 (`unused_scroll_delta`):**  例如，`gfx::Vector2dF(0, -20)`，表示向上过滚动了 20 个像素。
4. **滚动行为 (`overscroll_behavior`):**  `cc::OverscrollBehavior()`，假设 `overscroll-behavior` 设置为默认的 `auto`。

**输出：**

1. **状态改变:**  如果过滚动量超过阈值，并且没有禁用弹性过滚动，状态可能保持在 `kStateActiveScroll`，或者如果滚动结束且有动量，则进入 `kStateMomentumAnimated`。
2. **拉伸量 (`helper_->StretchAmount()`):**  `ElasticOverscrollController` 会计算出一个非零的拉伸量，例如 `gfx::Vector2dF(0, -some_value)`，表示内容被向上拉伸了一定的距离。 这个值会被传递给 `cc::ScrollElasticityHelper` 来进行渲染。
3. **动画启动 (如果进入 `kStateMomentumAnimated`):**  如果滚动结束，并且存在过滚动，控制器会启动一个动画，将拉伸量逐渐恢复到零。

**常见的使用错误：**

1. **误用 `overscroll-behavior: none;`:** 开发者可能意外地设置了 `overscroll-behavior: none;`，导致用户无法体验到预期的弹性过滚动效果，可能会让用户感到滚动体验很生硬。
    *   **例子：**  全局设置 `* { overscroll-behavior: none; }`  会禁用页面上所有元素的弹性过滚动，这通常不是期望的行为。
2. **与自定义滚动逻辑冲突:**  如果开发者使用 JavaScript 实现了自定义的滚动逻辑，并且没有考虑到浏览器的默认弹性过滚动行为，可能会导致冲突或不一致的体验。
    *   **例子：**  自定义滚动库可能会在滚动到边缘时阻止默认事件，从而阻止 `ElasticOverscrollController` 的执行。
3. **过度依赖 `-webkit-overflow-scrolling: touch;`:**  虽然这个属性在某些情况下能提升滚动性能，但它的一些行为（包括弹性过滚动）可能与标准行为略有不同。过度依赖它可能会导致跨浏览器兼容性问题。
4. **不理解 `overscroll-behavior: contain;` 的作用:**  开发者可能不清楚 `contain` 值不仅禁用了当前元素的弹性过滚动，还阻止了滚动链的传播，这可能会影响父元素的滚动行为。
5. **在不需要弹性过滚动的元素上启用:**  在一些不需要滚动或内容很少的元素上，默认的弹性过滚动效果可能显得不必要或突兀。  开发者应该根据具体情况考虑是否需要调整 `overscroll-behavior`。

总而言之，`elastic_overscroll_controller.cc` 是 Blink 引擎中一个关键的组件，它负责实现用户在滚动到边缘时看到的平滑且自然的弹性效果，并且与 Web 技术中的滚动机制和样式属性紧密相关。 理解其功能有助于开发者更好地控制网页的滚动体验。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/elastic_overscroll_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller.h"

#include <math.h>

#include <algorithm>

#include "base/functional/bind.h"
#include "build/build_config.h"
#include "cc/input/input_handler.h"
#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier.h"
#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller_exponential.h"
#include "ui/base/ui_base_features.h"
#include "ui/events/types/scroll_types.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

/*
 * Copyright (C) 2011 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace blink {

namespace {
constexpr double kScrollVelocityZeroingTimeout = 0.10f;
constexpr double kRubberbandMinimumRequiredDeltaBeforeStretch = 10;

#if BUILDFLAG(IS_ANDROID)
// On android, overscroll should not occur if the scroller is not scrollable in
// the overscrolled direction.
constexpr bool kOverscrollNonScrollableDirection = false;
#else   // BUILDFLAG(IS_ANDROID)
// On other platforms, overscroll can occur even if the scroller is not
// scrollable.
constexpr bool kOverscrollNonScrollableDirection = true;
#endif  // BUILDFLAG(IS_ANDROID)

}  // namespace

ElasticOverscrollController::ElasticOverscrollController(
    cc::ScrollElasticityHelper* helper)
    : helper_(helper),
      state_(kStateInactive),
      received_overscroll_update_(false) {}

std::unique_ptr<ElasticOverscrollController>
ElasticOverscrollController::Create(cc::ScrollElasticityHelper* helper) {
#if BUILDFLAG(IS_WIN)
  return base::FeatureList::IsEnabled(features::kElasticOverscroll)
             ? std::make_unique<ElasticOverscrollControllerBezier>(helper)
             : nullptr;
#else
  return std::make_unique<ElasticOverscrollControllerExponential>(helper);
#endif
}

void ElasticOverscrollController::ObserveRealScrollBegin(bool enter_momentum,
                                                         bool leave_momentum) {
  if (enter_momentum) {
    if (state_ == kStateInactive)
      state_ = kStateMomentumScroll;
  } else if (leave_momentum) {
    scroll_velocity_ = gfx::Vector2dF();
    last_scroll_event_timestamp_ = base::TimeTicks();
    state_ = kStateActiveScroll;
    pending_overscroll_delta_ = gfx::Vector2dF();
  }
}

void ElasticOverscrollController::ObserveScrollUpdate(
    const gfx::Vector2dF& event_delta,
    const gfx::Vector2dF& unused_scroll_delta,
    const base::TimeTicks& event_timestamp,
    const cc::OverscrollBehavior overscroll_behavior,
    bool has_momentum) {
  if (state_ == kStateMomentumAnimated || state_ == kStateInactive)
    return;

  if (!received_overscroll_update_ && !unused_scroll_delta.IsZero()) {
    overscroll_behavior_ = overscroll_behavior;
    received_overscroll_update_ = true;
  }

  UpdateVelocity(event_delta, event_timestamp);
  Overscroll(unused_scroll_delta);
  if (has_momentum && !helper_->StretchAmount().IsZero())
    EnterStateMomentumAnimated(event_timestamp);
}

void ElasticOverscrollController::ObserveRealScrollEnd(
    const base::TimeTicks event_timestamp) {
  if (state_ == kStateMomentumAnimated || state_ == kStateInactive)
    return;

  if (helper_->StretchAmount().IsZero()) {
    EnterStateInactive();
  } else {
    EnterStateMomentumAnimated(event_timestamp);
  }
}

void ElasticOverscrollController::ObserveGestureEventAndResult(
    const WebGestureEvent& gesture_event,
    const cc::InputHandlerScrollResult& scroll_result) {
  base::TimeTicks event_timestamp = gesture_event.TimeStamp();

  switch (gesture_event.GetType()) {
    case WebInputEvent::Type::kGestureScrollBegin: {
      received_overscroll_update_ = false;
      overscroll_behavior_ = cc::OverscrollBehavior();
      if (gesture_event.data.scroll_begin.synthetic)
        return;

      bool enter_momentum = gesture_event.data.scroll_begin.inertial_phase ==
                            WebGestureEvent::InertialPhaseState::kMomentum;
      bool leave_momentum =
          gesture_event.data.scroll_begin.inertial_phase ==
              WebGestureEvent::InertialPhaseState::kNonMomentum &&
          gesture_event.data.scroll_begin.delta_hint_units ==
              ui::ScrollGranularity::kScrollByPrecisePixel;
      ObserveRealScrollBegin(enter_momentum, leave_momentum);
      break;
    }
    case WebInputEvent::Type::kGestureScrollUpdate: {
      gfx::Vector2dF event_delta(-gesture_event.data.scroll_update.delta_x,
                                 -gesture_event.data.scroll_update.delta_y);
      bool has_momentum = gesture_event.data.scroll_update.inertial_phase ==
                          WebGestureEvent::InertialPhaseState::kMomentum;
      ObserveScrollUpdate(event_delta, scroll_result.unused_scroll_delta,
                          event_timestamp, scroll_result.overscroll_behavior,
                          has_momentum);
      break;
    }
    case WebInputEvent::Type::kGestureScrollEnd: {
      if (gesture_event.data.scroll_end.synthetic)
        return;
      ObserveRealScrollEnd(event_timestamp);
      break;
    }
    default:
      break;
  }
}

void ElasticOverscrollController::UpdateVelocity(
    const gfx::Vector2dF& event_delta,
    const base::TimeTicks& event_timestamp) {
  float time_delta =
      (event_timestamp - last_scroll_event_timestamp_).InSecondsF();
  if (time_delta < kScrollVelocityZeroingTimeout && time_delta > 0) {
    scroll_velocity_ = gfx::Vector2dF(event_delta.x() / time_delta,
                                      event_delta.y() / time_delta);
  } else {
    scroll_velocity_ = gfx::Vector2dF();
  }
  last_scroll_event_timestamp_ = event_timestamp;
}

void ElasticOverscrollController::Overscroll(
    const gfx::Vector2dF& overscroll_delta) {
  gfx::Vector2dF adjusted_overscroll_delta = overscroll_delta;

  // The effect can be dynamically disabled by setting styles to disallow user
  // scrolling. When disabled, disallow active or momentum overscrolling, but
  // allow any current overscroll to animate back.
  if (!helper_->IsUserScrollableHorizontal())
    adjusted_overscroll_delta.set_x(0);
  if (!helper_->IsUserScrollableVertical())
    adjusted_overscroll_delta.set_y(0);

  if (adjusted_overscroll_delta.IsZero())
    return;

  adjusted_overscroll_delta += pending_overscroll_delta_;
  pending_overscroll_delta_ = gfx::Vector2dF();

  // TODO (arakeri): Make this prefer the writing mode direction instead.
  // Only allow one direction to overscroll at a time, and slightly prefer
  // scrolling vertically by applying the equal case to delta_y.
  if (fabsf(overscroll_delta.y()) >= fabsf(overscroll_delta.x()))
    adjusted_overscroll_delta.set_x(0);
  else
    adjusted_overscroll_delta.set_y(0);

  if (!kOverscrollNonScrollableDirection) {
    // Check whether each direction is scrollable and 0 out the overscroll if it
    // is not.
    if (!CanScrollHorizontally())
      adjusted_overscroll_delta.set_x(0);
    if (!CanScrollVertically())
      adjusted_overscroll_delta.set_y(0);
  }

  // Don't allow overscrolling in a direction where scrolling is possible.
  if (!PinnedHorizontally(adjusted_overscroll_delta.x()))
    adjusted_overscroll_delta.set_x(0);
  if (!PinnedVertically(adjusted_overscroll_delta.y()))
    adjusted_overscroll_delta.set_y(0);

  // Don't allow overscrolling in a direction that has
  // OverscrollBehaviorTypeNone.
  if (overscroll_behavior_.x == cc::OverscrollBehavior::Type::kNone)
    adjusted_overscroll_delta.set_x(0);
  if (overscroll_behavior_.y == cc::OverscrollBehavior::Type::kNone)
    adjusted_overscroll_delta.set_y(0);

  // Require a minimum of 10 units of overscroll before starting the rubber-band
  // stretch effect, so that small stray motions don't trigger it. If that
  // minimum isn't met, save what remains in |pending_overscroll_delta_| for
  // the next event.
  gfx::Vector2dF old_stretch_amount = helper_->StretchAmount();
  gfx::Vector2dF stretch_scroll_force_delta;
  if (old_stretch_amount.x() != 0 ||
      fabsf(adjusted_overscroll_delta.x()) >=
          kRubberbandMinimumRequiredDeltaBeforeStretch) {
    stretch_scroll_force_delta.set_x(adjusted_overscroll_delta.x());
  } else {
    pending_overscroll_delta_.set_x(adjusted_overscroll_delta.x());
  }
  if (old_stretch_amount.y() != 0 ||
      fabsf(adjusted_overscroll_delta.y()) >=
          kRubberbandMinimumRequiredDeltaBeforeStretch) {
    stretch_scroll_force_delta.set_y(adjusted_overscroll_delta.y());
  } else {
    pending_overscroll_delta_.set_y(adjusted_overscroll_delta.y());
  }

  // Update the stretch amount according to the spring equations.
  if (stretch_scroll_force_delta.IsZero())
    return;
  stretch_scroll_force_ += stretch_scroll_force_delta;
  gfx::Vector2dF new_stretch_amount =
      StretchAmountForAccumulatedOverscroll(stretch_scroll_force_);
  helper_->SetStretchAmount(new_stretch_amount);
}

void ElasticOverscrollController::EnterStateInactive() {
  DCHECK_NE(kStateInactive, state_);
  DCHECK(helper_->StretchAmount().IsZero());
  state_ = kStateInactive;
  stretch_scroll_force_ = gfx::Vector2dF();
}

void ElasticOverscrollController::EnterStateMomentumAnimated(
    const base::TimeTicks& triggering_event_timestamp) {
  DCHECK_NE(kStateMomentumAnimated, state_);
  state_ = kStateMomentumAnimated;

  // If the scroller isn't stretched, there's nothing to animate.
  if (helper_->StretchAmount().IsZero())
    return;

  momentum_animation_start_time_ = triggering_event_timestamp;
  momentum_animation_initial_stretch_ = helper_->StretchAmount();
  momentum_animation_initial_velocity_ = scroll_velocity_;

  // Similarly to the logic in Overscroll, prefer vertical scrolling to
  // horizontal scrolling.
  if (fabsf(momentum_animation_initial_velocity_.y()) >=
      fabsf(momentum_animation_initial_velocity_.x()))
    momentum_animation_initial_velocity_.set_x(0);

  if (!CanScrollHorizontally())
    momentum_animation_initial_velocity_.set_x(0);

  if (!CanScrollVertically())
    momentum_animation_initial_velocity_.set_y(0);

  DidEnterMomentumAnimatedState();

  // TODO(crbug.com/394562): This can go away once input is batched to the front
  // of the frame? Then Animate() would always happen after this, so it would
  // have a chance to tick the animation there and would return if any
  // animations were active.
  helper_->RequestOneBeginFrame();
}

void ElasticOverscrollController::Animate(base::TimeTicks time) {
  if (state_ != kStateMomentumAnimated)
    return;

  // If the new stretch amount is near zero, set it directly to zero and enter
  // the inactive state.
  const gfx::Vector2dF new_stretch_amount = StretchAmountForTimeDelta(
      std::max(time - momentum_animation_start_time_, base::TimeDelta()));
  if (fabs(new_stretch_amount.x()) < 1 && fabs(new_stretch_amount.y()) < 1) {
    helper_->SetStretchAmount(gfx::Vector2dF());
    EnterStateInactive();
    return;
  }

  stretch_scroll_force_ =
      AccumulatedOverscrollForStretchAmount(new_stretch_amount);
  helper_->SetStretchAmount(new_stretch_amount);
  // TODO(danakj): Make this a return value back to the compositor to have it
  // schedule another frame and/or a draw. (Also, crbug.com/551138.)
  helper_->RequestOneBeginFrame();
}

bool ElasticOverscrollController::PinnedHorizontally(float direction) const {
  gfx::PointF scroll_offset = helper_->ScrollOffset();
  gfx::PointF max_scroll_offset = helper_->MaxScrollOffset();
  if (direction < 0)
    return scroll_offset.x() <= 0;
  if (direction > 0)
    return scroll_offset.x() >= max_scroll_offset.x();
  return false;
}

bool ElasticOverscrollController::PinnedVertically(float direction) const {
  gfx::PointF scroll_offset = helper_->ScrollOffset();
  gfx::PointF max_scroll_offset = helper_->MaxScrollOffset();
  if (direction < 0)
    return scroll_offset.y() <= 0;
  if (direction > 0)
    return scroll_offset.y() >= max_scroll_offset.y();
  return false;
}

bool ElasticOverscrollController::CanScrollHorizontally() const {
  return helper_->MaxScrollOffset().x() > 0;
}

bool ElasticOverscrollController::CanScrollVertically() const {
  return helper_->MaxScrollOffset().y() > 0;
}

void ElasticOverscrollController::ReconcileStretchAndScroll() {
  gfx::Vector2dF stretch = helper_->StretchAmount();
  if (stretch.IsZero())
    return;

  gfx::PointF scroll_offset = helper_->ScrollOffset();
  gfx::PointF max_scroll_offset = helper_->MaxScrollOffset();

  // Compute stretch_adjustment which will be added to |stretch| and subtracted
  // from the |scroll_offset|.
  gfx::Vector2dF stretch_adjustment;
  if (stretch.x() < 0 && scroll_offset.x() > 0) {
    stretch_adjustment.set_x(
        std::min(-stretch.x(), static_cast<float>(scroll_offset.x())));
  }
  if (stretch.x() > 0 && scroll_offset.x() < max_scroll_offset.x()) {
    stretch_adjustment.set_x(std::max(
        -stretch.x(),
        static_cast<float>(scroll_offset.x() - max_scroll_offset.x())));
  }
  if (stretch.y() < 0 && scroll_offset.y() > 0) {
    stretch_adjustment.set_y(
        std::min(-stretch.y(), static_cast<float>(scroll_offset.y())));
  }
  if (stretch.y() > 0 && scroll_offset.y() < max_scroll_offset.y()) {
    stretch_adjustment.set_y(std::max(
        -stretch.y(),
        static_cast<float>(scroll_offset.y() - max_scroll_offset.y())));
  }

  if (stretch_adjustment.IsZero())
    return;

  gfx::Vector2dF new_stretch_amount = stretch + stretch_adjustment;
  helper_->ScrollBy(-stretch_adjustment);
  helper_->SetStretchAmount(new_stretch_amount);

  // Update the internal state for the active scroll to avoid discontinuities.
  if (state_ == kStateActiveScroll) {
    stretch_scroll_force_ =
        AccumulatedOverscrollForStretchAmount(new_stretch_amount);
  }
}

}  // namespace blink
```
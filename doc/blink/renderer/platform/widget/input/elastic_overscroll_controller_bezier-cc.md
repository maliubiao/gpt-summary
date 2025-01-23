Response:
Let's break down the thought process for analyzing this Chromium source code.

1. **Understanding the Request:** The core request is to explain the functionality of the `elastic_overscroll_controller_bezier.cc` file and its relation to web technologies, along with examples of logic and potential errors.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for key terms and patterns. Words like "overscroll," "elastic," "bezier," "animation," "velocity," "duration," "stretch," and mathematical functions like `tanh` and `atanh` immediately stand out. The presence of `gfx::CubicBezier` is a strong indicator of animation control. The `#include` directives also tell us this is part of the Blink rendering engine.

3. **Identifying the Core Functionality:** Based on the keywords, it becomes clear that this code is responsible for implementing the "elastic overscroll" behavior. This is the effect seen when you scroll past the content boundaries on a webpage and get a "bounce back" or "stretch" effect. The "Bezier" part suggests the use of Bezier curves to control the timing and feel of these animations.

4. **Dissecting Key Methods:** Focus on the main functions and their purpose:

    * `OverscrollBoundary()`:  This clearly defines how far the content can be stretched beyond the boundaries. The `kOverscrollBoundaryMultiplier` constant hints at a percentage-based calculation.
    * `DidEnterMomentumAnimatedState()`: This seems to be triggered when a momentum scroll ends and the elastic overscroll animation begins. It calculates initial velocities, distances for the "bounce forward," and durations for both forward and backward animations.
    * `StretchAmountForForwardBounce()` and `StretchAmountForBackwardBounce()`: These methods calculate the actual amount of "stretch" at a given point in time during the respective animations, using Bezier curves. The logic within these functions involves interpolation based on time and the Bezier curve's shape.
    * `StretchAmountForTimeDelta()`: This acts as a central dispatcher, determining whether a "bounce forward" or "bounce back" animation is currently active and calling the appropriate calculation method.
    * `StretchAmountForAccumulatedOverscroll()`:  This function takes the total amount the user has tried to scroll past the boundary and maps it to the actual visible "stretch." The use of the `tanh` function suggests a dampening effect, limiting the stretch as the overscroll increases.
    * `AccumulatedOverscrollForStretchAmount()`: The inverse of the previous function.

5. **Connecting to Web Technologies (JavaScript, HTML, CSS):**

    * **Direct Connection:**  While this C++ code *doesn't* directly manipulate JavaScript, HTML, or CSS strings, it directly *implements a visual behavior* that users experience in web browsers. The elastic overscroll effect is triggered by user interactions (scrolling) and visually modifies the rendering of the webpage.
    * **Indirect Connection (How it's used):** Think about how this C++ code interacts with the browser's rendering pipeline. When a user scrolls, JavaScript event listeners might detect the scroll and potentially trigger actions. However, the *visual effect* of the elastic overscroll is handled at a lower level by code like this. The final rendering (what the user sees in HTML and CSS) is influenced by the calculations performed here.
    * **CSS `overscroll-behavior`:**  This CSS property is a key link. It allows developers to control the overscroll behavior. This C++ code is likely part of the implementation that respects the settings of `overscroll-behavior`.

6. **Logical Reasoning and Examples:**

    * **Assumptions:**  Identify the inputs and outputs of key functions. For example, `StretchAmountForTimeDelta()` takes a `base::TimeDelta` and outputs a `gfx::Vector2d` representing the stretch amount.
    * **Scenarios:**  Imagine different user interactions: a quick flick, a slow drag past the boundary, etc. How would the code react?  The constants and the Bezier curves control these animations.
    * **Edge Cases:**  Consider scenarios like very small scrollable areas or extremely fast scrolls. The code includes checks (like dividing by `scroll_bounds().width()` only if it's greater than 0) to handle potential issues.

7. **Identifying Potential Errors:**

    * **Incorrect Constant Values:** The code mentions that constants are "determined experimentally."  Incorrectly tuned constants could lead to a jarring or unnatural overscroll experience.
    * **Logic Errors in Bezier Curve Implementation:** While the `gfx::CubicBezier` class is likely well-tested, errors in how the control points are chosen or how the interpolation is done could lead to unexpected animation behavior.
    * **Race Conditions/Concurrency Issues (Less Likely in This Specific File):** Although not immediately apparent in this single file, in a complex rendering engine, there's always a potential for issues if different parts of the code are trying to modify the scroll state simultaneously.

8. **Structuring the Explanation:** Organize the findings into logical sections: Functionality, Relationship to Web Tech, Logic Examples, and Common Errors. Use clear and concise language.

9. **Refinement:** Review the explanation for clarity and accuracy. Ensure that the examples are helpful and illustrate the points effectively. For instance, initially, I might just say it handles "animations," but it's more precise to specify "bounce forward" and "bounce back" animations.

This systematic approach of scanning, identifying key components, understanding the data flow, and connecting it to the broader context of web technologies allows for a comprehensive analysis of the provided source code.
这个C++源代码文件 `elastic_overscroll_controller_bezier.cc` 属于 Chromium Blink 引擎，它实现了**弹性拉伸（Elastic Overscroll）效果的控制器**，并且使用了**贝塞尔曲线（Bezier Curve）**来定义动画的缓动效果。

以下是它的主要功能：

**1. 控制滚动容器超出边界时的弹性动画：**

* 当用户在可滚动容器（例如网页的主体或一个 `div` 元素）中滚动到内容的边缘并继续拖动时，这个控制器会负责产生一个“拉伸”的效果，模拟物理上的弹性。
* 当用户释放拖动时，控制器会产生一个“回弹”的动画，使内容平滑地回到边界。

**2. 使用贝塞尔曲线定义动画的缓动：**

* 文件中定义了多个贝塞尔曲线的控制点 (`kBounceForwardsX1`, `kBounceForwardsY1`, `kBounceBackwardsX1`, `kBounceBackwardsY1` 等)。
* 这些控制点定义了“向前拉伸”和“向后回弹”动画的速度变化规律。例如，回弹动画通常会先加速再减速，以产生更自然的效果。
* `InitialVelocityBasedBezierCurve` 函数根据滚动的初始速度调整贝塞尔曲线的控制点，使得动画效果能更好地匹配用户的操作。

**3. 计算拉伸的距离和动画的持续时间：**

* `OverscrollBoundary` 函数定义了滚动容器可以被拉伸的最大距离，这个距离通常是滚动容器尺寸的一个比例 (`kOverscrollBoundaryMultiplier`)。
* `CalculateBounceForwardsDuration` 和 `CalculateBounceBackDuration` 函数根据拉伸的距离计算动画的持续时间，避免动画过快或过慢。

**4. 处理动量滚动结束后的弹性动画：**

* `DidEnterMomentumAnimatedState` 函数在动量滚动结束后被调用。
* 它根据滚动的速度计算出需要进行的“向前拉伸”的距离和持续时间，以及后续“向后回弹”的持续时间。

**5. 在动画过程中计算当前的拉伸量：**

* `StretchAmountForTimeDelta` 函数根据当前动画已经进行的时间，使用对应的贝塞尔曲线计算出当前的拉伸量。
* 它会先处理“向前拉伸”的动画，然后再处理“向后回弹”的动画。

**6. 将用户滚动的距离映射到实际的拉伸量：**

* `StretchAmountForAccumulatedOverscroll` 函数使用双曲正切函数 (`tanh`) 将用户超出边界的滚动距离映射到实际的拉伸量。这样做可以模拟弹簧的效果，即超出边界越多，拉伸的阻力越大。

**7. 执行反向映射：**

* `AccumulatedOverscrollForStretchAmount` 函数执行 `StretchAmountForAccumulatedOverscroll` 的逆操作，将当前的拉伸量反向映射回用户实际滚动的距离。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Blink 渲染引擎的一部分，负责实现底层的渲染和动画逻辑。它与 JavaScript、HTML 和 CSS 的关系是 **间接的，但至关重要**。

* **HTML：** HTML 定义了网页的结构和内容，包括可滚动的元素。这个控制器作用于这些可滚动的 HTML 元素。
* **CSS：** CSS 可以影响滚动行为，例如通过 `overflow: auto` 或 `overflow: scroll` 属性使元素可滚动。  一些 CSS 属性，如 `overscroll-behavior`，可以直接影响浏览器是否启用或如何执行弹性拉伸效果。这个 C++ 代码会根据 `overscroll-behavior` 的设置来决定是否应用弹性拉伸。
* **JavaScript：** JavaScript 可以监听滚动事件 (`scroll` event) 并操作滚动位置。当 JavaScript 触发滚动或修改滚动位置导致超出边界时，这个 C++ 控制器会被调用来产生弹性动画。此外，一些 JavaScript 库或框架可能会模拟或自定义滚动行为，间接地与这个控制器交互。

**举例说明：**

假设用户在一个 `div` 元素中滚动内容，并且该 `div` 元素的 CSS 设置了 `overflow: auto`，允许内容溢出时出现滚动条。

**场景 1：用户快速滑动到内容底部并继续拖动 (动量滚动):**

* **假设输入：** 用户在 Y 轴方向以 500 像素/秒的速度滑动到内容底部，并继续拖动了 50 像素。
* **逻辑推理：** `DidEnterMomentumAnimatedState` 会被调用。根据速度 (500px/s)，计算出 `bounce_forwards_distance_y_` (例如 20 像素) 和 `bounce_forwards_duration_y_` (例如 50 毫秒)。然后，计算出 `bounce_backwards_duration_y_` (例如 100 毫秒)。
* **输出：**  首先，内容会继续“向前拉伸” 20 像素（模拟超出边界），持续 50 毫秒。然后，会启动“向后回弹”的动画，在 100 毫秒内平滑地将内容滚动回边界。贝塞尔曲线会控制这两个阶段的速度变化。

**场景 2：用户缓慢拖动到内容顶部并继续拖动：**

* **假设输入：** 用户在 Y 轴方向缓慢拖动到内容顶部，并继续拖动了 10 像素。
* **逻辑推理：**  `StretchAmountForAccumulatedOverscroll` 会被调用。根据拖动的距离 (10 像素) 和滚动容器的尺寸，使用 `tanh` 函数计算出实际的拉伸量（可能会小于 10 像素，因为 `tanh` 会产生阻尼效果）。
* **输出：** 滚动容器的顶部会显示出被拉伸的 8 像素（假设经过 `tanh` 计算）。当用户释放拖动时，会启动一个回弹动画，将内容平滑地滚回顶部边界。

**用户或编程常见的使用错误：**

1. **不正确的 CSS `overscroll-behavior` 设置：**
   * **错误：** 用户可能设置了 `overscroll-behavior: contain` 或 `overscroll-behavior: none`，这将阻止默认的弹性拉伸效果生效。
   * **举例：**
     ```css
     body {
       overscroll-behavior: none; /* 禁用了 body 元素的弹性拉伸 */
     }
     ```
   * **结果：** 即使 `elastic_overscroll_controller_bezier.cc` 正常工作，用户也不会看到弹性拉伸的效果。

2. **JavaScript 代码过度干预滚动行为：**
   * **错误：** JavaScript 代码可能会监听 `scroll` 事件并立即重置滚动位置，或者使用 `preventDefault()` 阻止默认的滚动行为。
   * **举例：**
     ```javascript
     const scrollableDiv = document.getElementById('myDiv');
     scrollableDiv.addEventListener('scroll', (event) => {
       scrollableDiv.scrollTop = 0; // 强制将滚动位置重置到顶部
     });
     ```
   * **结果：** 弹性拉伸动画可能无法正常完成，或者会被 JavaScript 代码的干预打断，导致不流畅的用户体验。

3. **假设弹性拉伸在所有浏览器和平台上行为一致：**
   * **错误：** 开发者可能会假设所有浏览器都以完全相同的方式实现弹性拉伸。
   * **结果：** 不同浏览器或平台（例如 Android 和 iOS）的弹性拉伸效果可能存在细微差异，依赖于特定平台行为的代码可能无法在所有环境中正常工作。

4. **没有考虑到嵌套滚动容器的交互：**
   * **错误：** 当存在嵌套的可滚动容器时，可能会出现弹性拉伸效果的冲突或不一致。
   * **举例：** 一个内部 `div` 和外部 `body` 元素都可滚动。用户在内部 `div` 滚动到边界后继续拖动，可能会触发外部 `body` 的弹性拉伸，这可能是非预期的行为。

总而言之，`elastic_overscroll_controller_bezier.cc` 是 Chromium 引擎中负责实现平滑自然的弹性拉伸效果的关键组件。它通过精细的数学计算和贝塞尔曲线的应用，为用户提供了更佳的滚动体验。理解其功能有助于开发者更好地理解浏览器的工作原理，并避免在使用 Web 技术时出现相关的错误。

### 提示词
```
这是目录为blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

namespace {
// The following constants are determined experimentally.

// Used to determine how far the scroller is allowed to stretch.
constexpr double kOverscrollBoundaryMultiplier = 0.1f;

// Maximum duration for the bounce back animation.
constexpr double kBounceBackMaxDurationMilliseconds = 300.0;

// Time taken by the bounce back animation (in milliseconds) to scroll 1 px.
constexpr double kBounceBackMillisecondsPerPixel = 15.0;

// Threshold above which a forward animation should be played. Stray finger
// movements can cause velocities to be non-zero. This in-turn may lead to minor
// jerks when the bounce back animation is being played. Expressed in pixels per
// second.
constexpr double kIgnoreForwardBounceVelocityThreshold = 200;

constexpr double kOverbounceMaxDurationMilliseconds = 150.0;
constexpr double kOverbounceMillisecondsPerPixel = 2.5;
constexpr double kOverbounceDistanceMultiplier = 35.f;

// Control points for the bounce forward Cubic Bezier curve.
constexpr double kBounceForwardsX1 = 0.25;
constexpr double kBounceForwardsY1 = 1.0;
constexpr double kBounceForwardsX2 = 0.99;
constexpr double kBounceForwardsY2 = 1.0;

// Control points for the bounce back Cubic Bezier curve.
constexpr double kBounceBackwardsX1 = 0.05;
constexpr double kBounceBackwardsY1 = 0.7;
constexpr double kBounceBackwardsX2 = 0.25;
constexpr double kBounceBackwardsY2 = 1.0;

base::TimeDelta CalculateBounceForwardsDuration(
    double bounce_forwards_distance) {
  return base::Milliseconds(
      std::min(kOverbounceMaxDurationMilliseconds,
               kOverbounceMillisecondsPerPixel * bounce_forwards_distance));
}

base::TimeDelta CalculateBounceBackDuration(double bounce_back_distance) {
  return base::Milliseconds(std::min(
      kBounceBackMaxDurationMilliseconds,
      kBounceBackMillisecondsPerPixel * std::abs(bounce_back_distance)));
}
}  // namespace

// Scale one of the control points of the Cubic Bezier curve based on the
// initial_velocity (which is expressed in terms of pixels / ms).
gfx::CubicBezier InitialVelocityBasedBezierCurve(const double initial_velocity,
                                                 const double x1,
                                                 const double y1,
                                                 const double x2,
                                                 const double y2) {
  const double velocity = std::abs(initial_velocity);
  double x = x1, y = y1;
  if (x1 * velocity < y1) {
    y = x1 * velocity;
  } else {
    x = y1 / velocity;
  }

  return gfx::CubicBezier(x, y, x2, y2);
}

ElasticOverscrollControllerBezier::ElasticOverscrollControllerBezier(
    cc::ScrollElasticityHelper* helper)
    : ElasticOverscrollController(helper) {}

// Returns the maximum amount to be overscrolled.
gfx::Vector2dF ElasticOverscrollControllerBezier::OverscrollBoundary(
    const gfx::Size& scroller_bounds) const {
  return gfx::Vector2dF(
      scroller_bounds.width() * kOverscrollBoundaryMultiplier,
      scroller_bounds.height() * kOverscrollBoundaryMultiplier);
}

void ElasticOverscrollControllerBezier::DidEnterMomentumAnimatedState() {
  // Express velocity in terms of milliseconds.
  const gfx::Vector2dF velocity(
      fabs(scroll_velocity().x()) > kIgnoreForwardBounceVelocityThreshold
          ? scroll_velocity().x() / 1000.f
          : 0.f,
      fabs(scroll_velocity().y()) > kIgnoreForwardBounceVelocityThreshold
          ? scroll_velocity().y() / 1000.f
          : 0.f);

  residual_velocity_ = velocity;

  gfx::Vector2dF bounce_forwards_delta(gfx::Vector2dF(
      sqrt(std::abs(velocity.x())), sqrt(std::abs(velocity.y()))));
  bounce_forwards_delta.Scale(kOverbounceDistanceMultiplier);

  const gfx::Vector2dF max_stretch_amount = OverscrollBoundary(scroll_bounds());
  bounce_forwards_distance_.set_x(
      std::min(max_stretch_amount.x(),
               std::abs(momentum_animation_initial_stretch_.x()) +
                   bounce_forwards_delta.x()));
  bounce_forwards_distance_.set_y(
      std::min(max_stretch_amount.y(),
               std::abs(momentum_animation_initial_stretch_.y()) +
                   bounce_forwards_delta.y()));

  // If we're flinging towards the edge, the sign of the distance will match
  // that of the velocity. Otherwise, it will match that of the current
  // stretch amount.
  bounce_forwards_distance_.set_x(
      (momentum_animation_initial_stretch_.x() == 0)
          ? std::copysign(bounce_forwards_distance_.x(), velocity.x())
          : std::copysign(bounce_forwards_distance_.x(),
                          momentum_animation_initial_stretch_.x()));
  bounce_forwards_distance_.set_y(
      (momentum_animation_initial_stretch_.y() == 0)
          ? std::copysign(bounce_forwards_distance_.y(), velocity.y())
          : std::copysign(bounce_forwards_distance_.y(),
                          momentum_animation_initial_stretch_.y()));
  bounce_forwards_duration_x_ =
      CalculateBounceForwardsDuration(bounce_forwards_delta.x());
  bounce_forwards_duration_y_ =
      CalculateBounceForwardsDuration(bounce_forwards_delta.y());

  bounce_backwards_duration_x_ =
      CalculateBounceBackDuration(bounce_forwards_distance_.x());
  bounce_backwards_duration_y_ =
      CalculateBounceBackDuration(bounce_forwards_distance_.y());
}

double ElasticOverscrollControllerBezier::StretchAmountForForwardBounce(
    const gfx::CubicBezier bounce_forwards_curve,
    const base::TimeDelta& delta,
    const base::TimeDelta& bounce_forwards_duration,
    const double initial_stretch,
    const double bounce_forwards_distance) const {
  if (delta < bounce_forwards_duration) {
    double curve_progress =
        delta.InMillisecondsF() / bounce_forwards_duration.InMillisecondsF();
    double progress = bounce_forwards_curve.Solve(curve_progress);
    return initial_stretch * (1 - progress) +
           bounce_forwards_distance * progress;
  } else if (delta < std::max(bounce_forwards_duration_x_,
                              bounce_forwards_duration_y_)) {
    // If the overscroll animation has been fully progressed on this axis but
    // the forward bounce is still ongoing on the other axis, stretch the
    // overscroll to its maximum position.
    double progress = bounce_forwards_curve.Solve(1.f);
    return initial_stretch * (1 - progress) +
           bounce_forwards_distance * progress;
  }
  return 0.f;
}

double ElasticOverscrollControllerBezier::StretchAmountForBackwardBounce(
    const gfx::CubicBezier bounce_backwards_curve,
    const base::TimeDelta& delta,
    const base::TimeDelta& bounce_backwards_duration,
    const double bounce_forwards_distance) const {
  if (delta < bounce_backwards_duration) {
    double curve_progress =
        delta.InMillisecondsF() / bounce_backwards_duration.InMillisecondsF();
    double progress = bounce_backwards_curve.Solve(curve_progress);
    return bounce_forwards_distance * (1 - progress);
  }
  return 0.f;
}

gfx::Vector2d ElasticOverscrollControllerBezier::StretchAmountForTimeDelta(
    const base::TimeDelta& delta) const {
  // Check if a bounce forward animation needs to be created. This is needed
  // when user "flings" a scroller. By the time the scroller reaches its bounds,
  // if the velocity isn't 0, a bounce forwards animation will need to be
  // played.
  base::TimeDelta time_delta = delta;
  const gfx::CubicBezier bounce_forwards_curve_x =
      InitialVelocityBasedBezierCurve(residual_velocity_.x(), kBounceForwardsX1,
                                      kBounceForwardsY1, kBounceForwardsX2,
                                      kBounceForwardsY2);
  const gfx::CubicBezier bounce_forwards_curve_y =
      InitialVelocityBasedBezierCurve(residual_velocity_.y(), kBounceForwardsX1,
                                      kBounceForwardsY1, kBounceForwardsX2,
                                      kBounceForwardsY2);
  const gfx::Vector2d forward_animation(gfx::ToRoundedVector2d(gfx::Vector2dF(
      StretchAmountForForwardBounce(bounce_forwards_curve_x, time_delta,
                                    bounce_forwards_duration_x_,
                                    momentum_animation_initial_stretch_.x(),
                                    bounce_forwards_distance_.x()),
      StretchAmountForForwardBounce(bounce_forwards_curve_y, time_delta,
                                    bounce_forwards_duration_y_,
                                    momentum_animation_initial_stretch_.y(),
                                    bounce_forwards_distance_.y()))));

  if (!forward_animation.IsZero()) {
    return forward_animation;
  }

  // Handle the case where the animation is in the bounce-back stage.
  time_delta -=
      std::max(bounce_forwards_duration_x_, bounce_forwards_duration_y_);

  const gfx::CubicBezier bounce_backwards_curve_x =
      InitialVelocityBasedBezierCurve(residual_velocity_.x(),
                                      kBounceBackwardsX1, kBounceBackwardsY1,
                                      kBounceBackwardsX2, kBounceBackwardsY2);
  const gfx::CubicBezier bounce_backwards_curve_y =
      InitialVelocityBasedBezierCurve(residual_velocity_.y(),
                                      kBounceBackwardsX1, kBounceBackwardsY1,
                                      kBounceBackwardsX2, kBounceBackwardsY2);
  return gfx::ToRoundedVector2d(gfx::Vector2dF(
      StretchAmountForBackwardBounce(bounce_backwards_curve_x, time_delta,
                                     bounce_backwards_duration_x_,
                                     bounce_forwards_distance_.x()),
      StretchAmountForBackwardBounce(bounce_backwards_curve_y, time_delta,
                                     bounce_backwards_duration_y_,
                                     bounce_forwards_distance_.y())));
}

// The goal of this calculation is to map the distance the user has scrolled
// past the boundary into the distance to actually scroll the elastic scroller.
gfx::Vector2d
ElasticOverscrollControllerBezier::StretchAmountForAccumulatedOverscroll(
    const gfx::Vector2dF& accumulated_overscroll) const {
  // TODO(arakeri): This should change as you pinch zoom in.
  const gfx::Vector2dF overscroll_boundary =
      OverscrollBoundary(scroll_bounds());

  // We use the tanh function in addition to the mapping, which gives it more of
  // a spring effect. However, we want to use tanh's range from [0, 2], so we
  // multiply the value we provide to tanh by 2.

  // Also, it may happen that the scroll_bounds are 0 if the viewport scroll
  // nodes are null (see: ScrollElasticityHelper::ScrollBounds). We therefore
  // have to check in order to avoid a divide by 0.
  gfx::Vector2d overbounce_distance;
  if (scroll_bounds().width() > 0.f) {
    overbounce_distance.set_x(
        tanh(2 * accumulated_overscroll.x() / scroll_bounds().width()) *
        overscroll_boundary.x());
  }

  if (scroll_bounds().height() > 0.f) {
    overbounce_distance.set_y(
        tanh(2 * accumulated_overscroll.y() / scroll_bounds().height()) *
        overscroll_boundary.y());
  }

  return overbounce_distance;
}

// This function does the inverse of StretchAmountForAccumulatedOverscroll. As
// in, instead of taking in the amount of distance overscrolled to get the
// bounce distance, it takes in the bounce distance and calculates how much is
// actually overscrolled.
gfx::Vector2d
ElasticOverscrollControllerBezier::AccumulatedOverscrollForStretchAmount(
    const gfx::Vector2dF& stretch_amount) const {
  const gfx::Vector2dF overscroll_boundary =
      OverscrollBoundary(scroll_bounds());

  // It may happen that the scroll_bounds are 0 if the viewport scroll
  // nodes are null (see: ScrollElasticityHelper::ScrollBounds). We therefore
  // have to check in order to avoid a divide by 0.
  gfx::Vector2d overscrolled_amount;
  if (overscroll_boundary.x() > 0.f) {
    float atanh_value = atanh(stretch_amount.x() / overscroll_boundary.x());
    overscrolled_amount.set_x((atanh_value / 2) * scroll_bounds().width());
  }

  if (overscroll_boundary.y() > 0.f) {
    float atanh_value = atanh(stretch_amount.y() / overscroll_boundary.y());
    overscrolled_amount.set_y((atanh_value / 2) * scroll_bounds().height());
  }

  return overscrolled_amount;
}
}  // namespace blink
```
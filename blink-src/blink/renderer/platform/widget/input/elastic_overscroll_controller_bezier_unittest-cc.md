Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding - What is it?**

The first lines immediately tell us this is a C++ file (`.cc`) within the Chromium/Blink project, specifically a *unittest*. The path `blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier_unittest.cc` provides key context:

* **`blink/renderer`**: This points to the rendering engine part of Chromium.
* **`platform/widget/input`**:  This narrows it down to input handling within the widget system.
* **`elastic_overscroll_controller_bezier_unittest.cc`**: This is a unittest file for a class named `ElasticOverscrollControllerBezier`. The "bezier" likely refers to the use of Bézier curves in the overscroll effect.

Therefore, the core function is to **test the behavior of the `ElasticOverscrollControllerBezier` class.**

**2. Core Functionality of the Tested Class (Inferred from Tests):**

By quickly scanning the test names and the actions within each test, we can infer the responsibilities of the `ElasticOverscrollControllerBezier`:

* **Overscroll Handling:** Tests like `OverscrollStretch`, `ReconcileStretchAndScroll` clearly indicate it manages how content "stretches" or reacts when scrolling beyond the normal boundaries.
* **Momentum/Inertia:** Tests involving `PhaseState::kNonMomentum` and mentions of "fling" suggest it handles the continuation of scrolling after the user stops interacting.
* **Animation:** Tests like `VerifyBackwardAnimationTick`, `VerifyForwardAnimationTick` confirm it uses animations (likely based on Bézier curves) to create the elastic overscroll effect.
* **Synthetic Event Handling:** The `NoSyntheticEventsOverscroll` test highlights its ability to distinguish between user-initiated and programmatically generated scroll events.
* **Velocity and Thresholds:**  `VerifyForwardAnimationIsNotPlayed` suggests velocity-based decisions regarding whether to trigger certain animations.
* **Interaction During Animation:** `VerifyScrollDuringBounceBack` shows it manages new scroll inputs even while an existing animation is running.

**3. Relationship to Web Technologies (JavaScript, HTML, CSS):**

Now, the crucial connection to web technologies. The elastic overscroll effect is a *visual* and *interactive* behavior. This immediately brings HTML, CSS, and JavaScript into play:

* **HTML (Structure):** The effect is applied to scrollable *elements* within the HTML structure. The `MockScrollElasticityHelper` in the tests even mocks things like `ScrollBounds()`, `IsUserScrollableHorizontal()`, etc., which correspond directly to properties of HTML elements and their scrolling behavior.
* **CSS (Styling and Layout):** While this C++ code *implements* the logic, CSS properties like `overflow: auto;`, `overflow-x`, `overflow-y` *enable* scrolling and thus make the overscroll effect relevant. Furthermore, CSS might influence the visual appearance of the effect (though the core logic is in C++).
* **JavaScript (Interaction and Control):** JavaScript can trigger scrolling (e.g., `element.scrollTo()`). It also receives events related to scrolling (e.g., `scroll` event). While the *core* overscroll logic is in C++, JavaScript interacts with it by initiating scrolls and observing the visual outcome.

**4. Logical Reasoning and Assumptions (Input/Output):**

For the logical reasoning part, we need to think like a tester: what are the key inputs and expected outputs?

* **Input:**
    * **Scroll Events (GestureScrollBegin, GestureScrollUpdate, GestureScrollEnd):**  Crucial inputs that drive the controller's state changes.
    * **Scroll Deltas (Vector2dF):** The amount of movement during a scroll.
    * **Inertial Phase:**  Whether the scroll is part of a momentum sequence.
    * **Time:** Important for animation timing.
    * **Scroll Boundaries/Offsets:** Simulated through the `MockScrollElasticityHelper`.
    * **Velocity:**  Used to determine if a forward "bounce" animation should occur.
* **Output:**
    * **Stretch Amount (Vector2dF):** The core visual feedback of the elastic overscroll.
    * **Controller State:**  Reflects the current phase of the overscroll (inactive, active scroll, momentum animated).
    * **Animation State:** Whether animations are running and their progress.

**Example Assumption and Input/Output:**

* **Assumption:** When the user scrolls beyond the scroll boundaries, the content should "stretch" visually.
* **Input:** `GestureScrollUpdate` with a delta that would cause overscrolling.
* **Expected Output:** The `StretchAmount()` returned by the helper should be non-zero.

**5. Common User/Programming Errors:**

This section requires thinking about how the overscroll effect might go wrong from a user's perspective or how a developer might misuse the underlying mechanisms.

* **User Errors (Perceived):**
    * **Unexpected "stickiness":** If the animation curves are poorly designed, the overscroll might feel unresponsive or jarring.
    * **Inconsistent behavior:**  If the overscroll behaves differently on different platforms or in different scrolling contexts, it can be confusing.
    * **Overscroll interfering with other interactions:**  If the overscroll animation is too long, it might prevent the user from performing other actions quickly.
* **Programming Errors:**
    * **Incorrectly setting scroll boundaries:** If the scroll boundaries are not accurately calculated, the overscroll might not trigger correctly or might trigger prematurely.
    * **Interfering with the controller's state:**  External code trying to manually manipulate the `StretchAmount` or the controller's state could lead to unexpected behavior.
    * **Not handling synthetic events correctly:**  If the controller doesn't properly distinguish synthetic events, it could lead to unwanted overscroll effects triggered by programmatic scrolling.

**Self-Correction/Refinement during the thought process:**

Initially, I might just focus on the individual tests. However, to understand the *overall* functionality, I need to synthesize the information from all the tests and the class name. Realizing that the `MockScrollElasticityHelper` is a stand-in for actual scrollable elements is a key step in connecting the C++ code to the web context. Also, understanding the different `PhaseState` values is important for grasping the nuances of momentum scrolling. Finally, thinking about the *user experience* helps in identifying potential errors from a user's perspective.
好的，让我们来分析一下 `blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier_unittest.cc` 这个文件。

**功能概述:**

这个文件是一个 C++ 单元测试文件，用于测试 `ElasticOverscrollControllerBezier` 类的功能。`ElasticOverscrollControllerBezier` 类的主要职责是控制在网页内容滚动到边界时产生的“弹性拉伸”（elastic overscroll）效果。 具体来说，它使用贝塞尔曲线来模拟这种弹性效果，使得滚动到头或尾时，内容会像被拉伸一样，然后弹回。

**与 JavaScript, HTML, CSS 的关系:**

虽然这个文件本身是 C++ 代码，但它直接关系到用户在浏览器中与网页交互时的视觉效果，而这些效果最终是由 JavaScript, HTML 和 CSS 共同构建的。

* **HTML:** HTML 定义了网页的结构，包括哪些元素是可滚动的。`ElasticOverscrollControllerBezier`  作用于这些可滚动的 HTML 元素上。 例如，一个设置了 `overflow: auto` 或 `overflow: scroll` 的 `<div>` 元素就可能触发这种弹性滚动效果。
* **CSS:** CSS 负责网页的样式和布局。虽然 CSS 本身不直接控制弹性滚动的逻辑，但 `overflow` 属性的设置会决定一个元素是否可以滚动，从而间接影响 `ElasticOverscrollControllerBezier` 的行为。此外，一些 CSS 属性，如 `scroll-behavior: smooth;` 可能会影响滚动的平滑度，与弹性滚动效果协同工作。
* **JavaScript:** JavaScript 可以用来操作 DOM 元素，包括滚动。例如，JavaScript 代码可以使用 `element.scrollTo()` 方法来滚动元素。`ElasticOverscrollControllerBezier` 会响应这些由 JavaScript 触发的滚动行为，并在滚动超出边界时应用弹性效果。当用户通过触摸或鼠标滚轮进行滚动操作时，浏览器也会生成相应的事件，`ElasticOverscrollControllerBezier` 同样会处理这些事件。

**举例说明:**

假设我们有以下简单的 HTML 结构：

```html
<!DOCTYPE html>
<html>
<head>
<style>
  .scrollable-container {
    width: 200px;
    height: 100px;
    overflow: auto;
    border: 1px solid black;
  }
  .long-content {
    height: 300px;
  }
</style>
</head>
<body>
  <div class="scrollable-container">
    <div class="long-content">
      This is long content that can be scrolled.
    </div>
  </div>
</body>
</html>
```

在这个例子中，`.scrollable-container` 是一个可滚动的容器。当用户滚动这个容器，并且滚动到顶部或底部时，`ElasticOverscrollControllerBezier` 就会发挥作用，产生弹性拉伸的效果。

* **用户滚动到顶部或底部（Input）：** 用户使用鼠标滚轮、触摸手势或者键盘来滚动 `.scrollable-container`。
* **`ElasticOverscrollControllerBezier` 检测到超出边界（Logic）：**  `ElasticOverscrollControllerBezier` 监听滚动事件，并判断当前的滚动偏移是否超出了内容的边界。
* **应用贝塞尔曲线计算的拉伸效果（Logic）：** 当超出边界时，它会使用贝塞尔曲线来计算应该产生的拉伸量，并更新内容的位置。
* **视觉上看到内容被拉伸，然后弹回（Output）：** 用户会看到 `.long-content` 在滚动到头或尾时，会有一个被拉伸然后弹回的动画效果。

**逻辑推理、假设输入与输出:**

让我们看一个具体的测试用例 `OverscrollStretch`:

**假设输入:**

1. 用户在不支持惯性滚动的状态下（`PhaseState::kNonMomentum`）开始一个手势滚动。
2. 用户尝试向上滚动超出顶部边界 `100` 个单位 (`Vector2dF(0, -100)` 或 `Vector2dF(-100, 0)` 用于水平方向）。

**逻辑推理:**

`ElasticOverscrollControllerBezier` 会根据超出边界的量，使用预定义的公式（基于贝塞尔曲线）计算出一个拉伸量。这个拉伸量会反映在 `MockScrollElasticityHelper` 的 `StretchAmount()` 方法的返回值中。不同的平台可能有不同的拉伸系数，因此测试中会有针对 Android 和其他平台的条件编译 (`#if BUILDFLAG(IS_ANDROID) ... #else ... #endif`)。

**预期输出:**

*   **非 Android 平台:**  向上滚动超出顶部边界 100 个单位，预计 `helper_.StretchAmount()` 返回 `Vector2dF(0, -19)`。向左滚动超出左侧边界 100 个单位，预计返回 `Vector2dF(-19, 0)`。  这个 `-19` 是经过计算得出的拉伸量。
*   **Android 平台:** 在这个特定的测试中，预期在非惯性滚动时，Android 平台不产生拉伸效果，因此 `helper_.StretchAmount()` 预计返回 `Vector2dF(0, 0)`。

**涉及用户或者编程常见的使用错误:**

1. **用户错误（感知层面）：**
    *   **过度拉伸导致内容不可读:** 如果贝塞尔曲线的参数设置不当，可能导致过度拉伸，使得用户难以理解当前的内容位置。
    *   **与其他动画效果冲突:**  如果网页本身使用了复杂的滚动动画或变换效果，弹性滚动可能与之冲突，产生不流畅或奇怪的视觉效果。
    *   **在不应该出现弹性滚动的区域出现:**  如果滚动容器的边界计算有误，可能会在不应该出现弹性滚动的区域出现这种效果，造成用户困惑。

2. **编程错误:**
    *   **错误配置滚动容器的 `overflow` 属性:**  如果没有正确设置 `overflow: auto` 或 `overflow: scroll`，弹性滚动控制器可能不会被激活。
    *   **手动修改滚动位置时没有考虑弹性效果:**  如果 JavaScript 代码直接修改元素的 `scrollTop` 或 `scrollLeft` 属性，可能会绕过弹性滚动控制器的逻辑，导致不一致的行为。
    *   **在不支持弹性滚动的平台上错误地假设其存在:**  某些浏览器或平台可能不支持原生的弹性滚动效果，开发者需要进行兼容性处理或提供替代方案。
    *   **与事件监听冲突:**  如果开发者在滚动容器上添加了自定义的滚动事件监听器，并且没有正确处理事件的传播或阻止默认行为，可能会干扰弹性滚动控制器的正常工作。

**总结:**

`elastic_overscroll_controller_bezier_unittest.cc` 这个文件通过一系列的单元测试，确保了 `ElasticOverscrollControllerBezier` 类能够正确地实现网页的弹性滚动效果。这个功能直接影响用户在浏览器中与可滚动内容交互的体验，并且与 HTML 结构、CSS 样式以及 JavaScript 的滚动操作紧密相关。理解这个文件的功能有助于我们更好地理解浏览器如何实现平滑自然的滚动交互。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller_bezier.h"

#include "build/build_config.h"
#include "cc/input/input_handler.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

using gfx::Size;
using gfx::Vector2dF;
using PhaseState = WebGestureEvent::InertialPhaseState;

class MockScrollElasticityHelper : public cc::ScrollElasticityHelper {
 public:
  MockScrollElasticityHelper() = default;
  ~MockScrollElasticityHelper() override = default;

  // cc::ScrollElasticityHelper implementation:
  Size ScrollBounds() const override { return Size(1000, 1000); }
  bool IsUserScrollableHorizontal() const override { return true; }
  bool IsUserScrollableVertical() const override { return true; }
  Vector2dF StretchAmount() const override { return stretch_amount_; }
  void SetStretchAmount(const Vector2dF& stretch_amount) override {
    stretch_amount_ = stretch_amount;
  }
  void ScrollBy(const Vector2dF& delta) override { scroll_offset_ += delta; }
  void RequestOneBeginFrame() override {}
  gfx::PointF ScrollOffset() const override { return scroll_offset_; }
  gfx::PointF MaxScrollOffset() const override { return max_scroll_offset_; }

  void SetScrollOffsetAndMaxScrollOffset(const gfx::PointF& scroll_offset,
                                         const gfx::PointF& max_scroll_offset) {
    scroll_offset_ = scroll_offset;
    max_scroll_offset_ = max_scroll_offset;
  }

 private:
  Vector2dF stretch_amount_;
  gfx::PointF scroll_offset_, max_scroll_offset_;
};

class ElasticOverscrollControllerBezierTest : public testing::Test {
 public:
  ElasticOverscrollControllerBezierTest() : controller_(&helper_) {}
  ~ElasticOverscrollControllerBezierTest() override = default;

  void SetUp() override {}

  void SendGestureScrollBegin(PhaseState inertialPhase) {
    WebGestureEvent event(WebInputEvent::Type::kGestureScrollBegin,
                          WebInputEvent::kNoModifiers, base::TimeTicks(),
                          WebGestureDevice::kTouchpad);
    event.data.scroll_begin.inertial_phase = inertialPhase;

    controller_.ObserveGestureEventAndResult(event,
                                             cc::InputHandlerScrollResult());
  }

  void SendGestureScrollUpdate(PhaseState inertialPhase,
                               const Vector2dF& unused_scroll_delta) {
    blink::WebGestureEvent event(WebInputEvent::Type::kGestureScrollUpdate,
                                 WebInputEvent::kNoModifiers, base::TimeTicks(),
                                 blink::WebGestureDevice::kTouchpad);
    event.data.scroll_update.inertial_phase = inertialPhase;
    cc::InputHandlerScrollResult scroll_result;
    scroll_result.did_overscroll_root = !unused_scroll_delta.IsZero();
    scroll_result.unused_scroll_delta = unused_scroll_delta;

    controller_.ObserveGestureEventAndResult(event, scroll_result);
  }
  void SendGestureScrollEnd(base::TimeTicks time = base::TimeTicks::Now()) {
    WebGestureEvent event(WebInputEvent::Type::kGestureScrollEnd,
                          WebInputEvent::kNoModifiers, time,
                          WebGestureDevice::kTouchpad);

    controller_.ObserveGestureEventAndResult(event,
                                             cc::InputHandlerScrollResult());
  }

  MockScrollElasticityHelper helper_;
  ElasticOverscrollControllerBezier controller_;
};

// Tests that the scroller "stretches" as expected when an overscroll occurs
// on a non-scrollable area. See ReconcileStretchAndScroll for an overscroll
// stretch on scrollable areas.
TEST_F(ElasticOverscrollControllerBezierTest, OverscrollStretch) {
  // Test vertical overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, -100));
#if BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
#else
  EXPECT_EQ(Vector2dF(0, -19), helper_.StretchAmount());
#endif
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, 100));
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollEnd();

  // Test horizontal overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-100, 0));
#if BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
#else
  EXPECT_EQ(Vector2dF(-19, 0), helper_.StretchAmount());
#endif
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(100, 0));
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollEnd();
}

// Verify that synthetic gesture events do not trigger an overscroll.
TEST_F(ElasticOverscrollControllerBezierTest, NoSyntheticEventsOverscroll) {
  // Test vertical overscroll.
  WebGestureEvent event(WebInputEvent::Type::kGestureScrollBegin,
                        WebInputEvent::kNoModifiers, base::TimeTicks(),
                        WebGestureDevice::kScrollbar);
  event.data.scroll_begin.inertial_phase = PhaseState::kNonMomentum;
  event.data.scroll_begin.synthetic = true;
  controller_.ObserveGestureEventAndResult(event,
                                           cc::InputHandlerScrollResult());
  EXPECT_EQ(controller_.state_,
            ElasticOverscrollController::State::kStateInactive);
}

// Verify that ReconcileStretchAndScroll reduces the overscrolled delta.
TEST_F(ElasticOverscrollControllerBezierTest, ReconcileStretchAndScroll) {
  // Test vertical overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, -100));
  EXPECT_EQ(Vector2dF(0, -19), helper_.StretchAmount());
  helper_.ScrollBy(Vector2dF(0, 1));
  controller_.ReconcileStretchAndScroll();
  EXPECT_EQ(Vector2dF(0, -18), helper_.StretchAmount());

  // Reset vertical overscroll.
  helper_.SetStretchAmount(Vector2dF(0, 0));
  SendGestureScrollEnd(base::TimeTicks::Now());

  // Test horizontal overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-100, 0));
  EXPECT_EQ(Vector2dF(-19, 0), helper_.StretchAmount());
  helper_.ScrollBy(Vector2dF(1, 0));
  controller_.ReconcileStretchAndScroll();
  EXPECT_EQ(Vector2dF(-18, 0), helper_.StretchAmount());
}

// Tests that momentum_animation_start_time_ doesn't get reset when the
// overscroll animation is ticking and the scroller is diagonally overscrolled.
TEST_F(ElasticOverscrollControllerBezierTest, VerifyInitialStretchDelta) {
  // Set up the state to be in kStateMomentumAnimated with some amount of
  // diagonal stretch.
  controller_.state_ =
      ElasticOverscrollController::State::kStateMomentumAnimated;
  helper_.SetStretchAmount(Vector2dF(5, 10));
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 20),
                                            gfx::PointF(100, 100));
  controller_.ReconcileStretchAndScroll();
  controller_.bounce_forwards_duration_x_ = base::Milliseconds(1000);
  controller_.bounce_forwards_duration_y_ = base::Milliseconds(1000);
  controller_.momentum_animation_initial_stretch_ = gfx::Vector2dF(10.f, 10.f);

  // Verify that the momentum_animation_start_time_ doesn't get reset when the
  // animation ticks.
  const base::TimeTicks animation_start_time =
      base::TimeTicks() + base::Milliseconds(32);

  // After 2 frames.
  controller_.Animate(animation_start_time);
  helper_.ScrollBy(Vector2dF(0, 2));
  EXPECT_NE(controller_.momentum_animation_start_time_, animation_start_time);
  EXPECT_EQ(controller_.state_,
            ElasticOverscrollController::State::kStateMomentumAnimated);

  // After 8 frames.
  controller_.Animate(animation_start_time + base::Milliseconds(128));
  helper_.ScrollBy(Vector2dF(0, 8));
  EXPECT_NE(controller_.momentum_animation_start_time_, animation_start_time);
  EXPECT_EQ(controller_.state_,
            ElasticOverscrollController::State::kStateMomentumAnimated);

  // After 64 frames the forward animation should no longer be active.
  controller_.Animate(animation_start_time + base::Milliseconds(1024));
  helper_.ScrollBy(Vector2dF(0, 64));
  EXPECT_NE(controller_.momentum_animation_start_time_, animation_start_time);
  EXPECT_EQ(controller_.state_,
            ElasticOverscrollController::State::kStateInactive);
  EXPECT_EQ(Vector2dF(), helper_.StretchAmount());
}

// Tests if the overscrolled delta maps correctly to the actual amount that the
// scroller gets stretched.
TEST_F(ElasticOverscrollControllerBezierTest, VerifyOverscrollBounceDistance) {
  Vector2dF overscroll_bounce_distance(
      controller_.StretchAmountForAccumulatedOverscroll(Vector2dF(0, -100)));
  EXPECT_EQ(overscroll_bounce_distance.y(), -19);

  overscroll_bounce_distance =
      controller_.StretchAmountForAccumulatedOverscroll(Vector2dF(-100, 0));
  EXPECT_EQ(overscroll_bounce_distance.x(), -19);
}

// Tests that the bounce back animation ticks as expected. If the animation was
// successfully created, the call to OverscrollBounceController::Animate should
// tick the animation as expected. When the stretch amount is near 0, the
// scroller should treat the bounce as "completed".
TEST_F(ElasticOverscrollControllerBezierTest, VerifyBackwardAnimationTick) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));

  // Test vertical overscroll.
  EXPECT_EQ(controller_.state_, ElasticOverscrollController::kStateInactive);
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, -100));

  // This signals that the finger has lifted off which triggers the bounce back
  // animation.
  const base::TimeTicks now = base::TimeTicks::Now();
  SendGestureScrollEnd(now);

  // Frame 2.
  controller_.Animate(now + base::Milliseconds(32));
  EXPECT_EQ(controller_.state_,
            ElasticOverscrollController::kStateMomentumAnimated);
  ASSERT_FLOAT_EQ(helper_.StretchAmount().y(), -14);

  // Frame 5. The stretch amount moving closer to 0 proves that we're animating.
  controller_.Animate(now + base::Milliseconds(80));
  ASSERT_FLOAT_EQ(helper_.StretchAmount().y(), -8);

  // Frame 15. StretchAmount < abs(1), so snap to 0. state_ is kStateInactive.
  controller_.Animate(now + base::Milliseconds(240));
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());

  EXPECT_EQ(controller_.state_, ElasticOverscrollController::kStateInactive);

  // Test horizontal overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-80, 0));
  SendGestureScrollEnd(now);

  // Frame 2.
  controller_.Animate(now + base::Milliseconds(32));
  ASSERT_FLOAT_EQ(helper_.StretchAmount().x(), -10);

  // Frame 5. The stretch amount moving closer to 0 proves that we're animating.
  controller_.Animate(now + base::Milliseconds(80));
  EXPECT_EQ(controller_.state_,
            ElasticOverscrollController::kStateMomentumAnimated);
  ASSERT_FLOAT_EQ(helper_.StretchAmount().x(), -5);

  // Frame 15. StretchAmount < abs(1), so snap to 0. state_ is kStateInactive.
  controller_.Animate(now + base::Milliseconds(240));
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  EXPECT_EQ(controller_.state_, ElasticOverscrollController::kStateInactive);
}

// Tests that the bounce forward animation ticks as expected.
TEST_F(ElasticOverscrollControllerBezierTest, VerifyForwardAnimationTick) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));

  // Test vertical forward bounce animations.
  EXPECT_EQ(controller_.state_, ElasticOverscrollController::kStateInactive);
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, -100));
  controller_.scroll_velocity_ = gfx::Vector2dF(0.f, -4000.f);

  // This signals that the finger has lifted off which triggers a fling.
  const base::TimeTicks now = base::TimeTicks::Now();
  SendGestureScrollEnd(now);

  const int TOTAL_FRAMES = 28;
  const int stretch_amount_y[TOTAL_FRAMES] = {
      -19, -41, -55, -65, -72, -78, -82, -85, -88, -89, -78, -64, -53, -44,
      -37, -30, -25, -20, -16, -13, -10, -7,  -5,  -4,  -2,  -1,  -1,  0};

  for (int i = 0; i < TOTAL_FRAMES; i++) {
    controller_.Animate(now + base::Milliseconds(i * 16));
    EXPECT_EQ(controller_.state_,
              (stretch_amount_y[i] == 0
                   ? ElasticOverscrollController::kStateInactive
                   : ElasticOverscrollController::kStateMomentumAnimated));
    ASSERT_FLOAT_EQ(helper_.StretchAmount().y(), stretch_amount_y[i]);
  }

  // Test horizontal forward bounce animations.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-50, 0));
  controller_.scroll_velocity_ = gfx::Vector2dF(-3000.f, 0.f);
  SendGestureScrollEnd(now);

  const int stretch_amount_x[TOTAL_FRAMES] = {
      -9,  -24, -34, -42, -48, -54, -58, -62, -66, -69, -62, -52, -43, -36,
      -30, -25, -20, -17, -13, -10, -8,  -6,  -4,  -3,  -2,  -1,  0,   0};

  for (int i = 0; i < TOTAL_FRAMES; i++) {
    controller_.Animate(now + base::Milliseconds(i * 16));
    EXPECT_EQ(controller_.state_,
              (stretch_amount_x[i] == 0
                   ? ElasticOverscrollController::kStateInactive
                   : ElasticOverscrollController::kStateMomentumAnimated));
    ASSERT_FLOAT_EQ(helper_.StretchAmount().x(), stretch_amount_x[i]);
  }
}

// Tests that the bounce forward animation is *not* played when the velocity is
// less than kIgnoreForwardBounceVelocityThreshold. This can be verified by
// checking bounce_forwards_distance_ (since it is a function of velocity)
TEST_F(ElasticOverscrollControllerBezierTest,
       VerifyForwardAnimationIsNotPlayed) {
  EXPECT_EQ(Vector2dF(), helper_.StretchAmount());
  controller_.scroll_velocity_ = gfx::Vector2dF(0.f, -199.f);
  controller_.DidEnterMomentumAnimatedState();
  EXPECT_TRUE(controller_.bounce_forwards_distance_.IsZero());

  controller_.scroll_velocity_ = gfx::Vector2dF(-199.f, 0.f);
  controller_.DidEnterMomentumAnimatedState();
  EXPECT_TRUE(controller_.bounce_forwards_distance_.IsZero());

  // When velocity > 200, forward animation is expected to be played.
  controller_.scroll_velocity_ = gfx::Vector2dF(0.f, -201.f);
  controller_.DidEnterMomentumAnimatedState();
  EXPECT_EQ(gfx::Vector2dF(0, -16),
            gfx::ToRoundedVector2d(controller_.bounce_forwards_distance_));

  controller_.scroll_velocity_ = gfx::Vector2dF(-201.f, 0.f);
  controller_.DidEnterMomentumAnimatedState();
  EXPECT_EQ(gfx::Vector2dF(-16, 0),
            gfx::ToRoundedVector2d(controller_.bounce_forwards_distance_));
}

// Tests initiating a scroll when a bounce back animation is in progress works
// as expected.
TEST_F(ElasticOverscrollControllerBezierTest, VerifyScrollDuringBounceBack) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));

  // Test vertical overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, -100));

  // This signals that the finger has lifted off which triggers the bounce back
  // animation.
  const base::TimeTicks now = base::TimeTicks::Now();
  SendGestureScrollEnd(now);
  EXPECT_EQ(Vector2dF(0, -19), helper_.StretchAmount());

  // Frame 2.
  controller_.Animate(now + base::Milliseconds(32));
  ASSERT_FLOAT_EQ(helper_.StretchAmount().y(), -14);

  // Frame 5. The stretch amount moving closer to 0 proves that we're animating.
  controller_.Animate(now + base::Milliseconds(80));
  ASSERT_FLOAT_EQ(helper_.StretchAmount().y(), -8);

  // While the animation is still ticking, initiate a scroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, -50));
  ASSERT_FLOAT_EQ(helper_.StretchAmount().y(), -17);
}

// Tests that animation doesn't get created when unused_delta is 0.
TEST_F(ElasticOverscrollControllerBezierTest, VerifyAnimationNotCreated) {
  // Test vertical and horizontal overscroll.
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());

  // state_ is kStateActiveScroll. unused_delta is 0 so overscroll should not
  // take place.
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(0, 0));

  // This signals that the finger has lifted off which triggers the bounce back
  // animation.
  const base::TimeTicks now = base::TimeTicks::Now();
  SendGestureScrollEnd(now);

  // Frame 2.
  controller_.Animate(now + base::Milliseconds(32));
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
}

// Tests that the forward bounce animation handles different animations in two
// axis with different durations gracefully.
TEST_F(ElasticOverscrollControllerBezierTest,
       VerifyDifferentDurationForwardAnimations) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));

  // Test vertical forward bounce animations.
  EXPECT_EQ(controller_.state_, ElasticOverscrollController::kStateInactive);
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  // The gesture will be much greater vertically than horizontally. This should
  // cause the animation to be longer on the Y axis than on the X axis.
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-50, -100));
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-50, 0));
  // Verify that both axis are stretched before the fling gesture.
  EXPECT_GT(fabsf(helper_.StretchAmount().x()), 0);
  EXPECT_GT(fabsf(helper_.StretchAmount().y()), 0);

  controller_.scroll_velocity_ = gfx::Vector2dF(-1000.f, -4000.f);

  // This signals that the finger has lifted off which triggers a fling.
  const base::TimeTicks now = base::TimeTicks::Now();
  SendGestureScrollEnd(now);

  constexpr int kMaxFrames = 100;
  controller_.Animate(now);
  float x_stretch_amount = fabsf(helper_.StretchAmount().x());
  float y_stretch_amount = fabsf(helper_.StretchAmount().y());
  enum AnimationState {
    kBouncingForwardBoth,
    kBouncingForwardY,
    kBouncingBackwards
  };
  AnimationState state(kBouncingForwardBoth);
  for (int i = 1;
       i < kMaxFrames && (x_stretch_amount > 0 || y_stretch_amount > 0); i++) {
    controller_.Animate(now + base::Milliseconds(i * 16));
    const float new_x_stretch_amount = fabs(helper_.StretchAmount().x());
    const float new_y_stretch_amount = fabs(helper_.StretchAmount().y());
    if (state == kBouncingForwardBoth &&
        new_x_stretch_amount == x_stretch_amount) {
      EXPECT_NE(new_x_stretch_amount, 0);
      state = kBouncingForwardY;
    }
    if (state == kBouncingForwardY &&
        new_y_stretch_amount <= y_stretch_amount) {
      state = kBouncingBackwards;
    }
    switch (state) {
      case kBouncingForwardBoth:
        // While both axis are bouncing forward, the stretch amount should
        // increase on each tick of the animation.
        EXPECT_GT(new_x_stretch_amount, x_stretch_amount);
        EXPECT_GT(new_y_stretch_amount, y_stretch_amount);
        break;
      case kBouncingForwardY:
        // While one axis has completed it's animation and the other one hasn't,
        // only the one still animating should increase in value.
        EXPECT_EQ(new_x_stretch_amount, x_stretch_amount);
        EXPECT_GT(new_y_stretch_amount, y_stretch_amount);
        break;
      case kBouncingBackwards:
        // Once the bounce backwards animation has kicked in, both stretches
        // should monotonically decrease until they become zero.
        EXPECT_LE(new_x_stretch_amount, x_stretch_amount);
        EXPECT_LE(new_y_stretch_amount, y_stretch_amount);
        break;
    }
    y_stretch_amount = new_y_stretch_amount;
    x_stretch_amount = new_x_stretch_amount;
  }
  // Verify that the loop ended because the animation did and not because we hit
  // the max amount of frames.
  EXPECT_FLOAT_EQ(x_stretch_amount, 0.f);
  EXPECT_FLOAT_EQ(y_stretch_amount, 0.f);
}

// Tests that the forward bounce animation handles single axis animations
// gracefully.
TEST_F(ElasticOverscrollControllerBezierTest, VerifyOneAxisForwardAnimation) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(100, 100));

  // Test vertical forward bounce animations.
  EXPECT_EQ(controller_.state_, ElasticOverscrollController::kStateInactive);
  SendGestureScrollBegin(PhaseState::kNonMomentum);
  EXPECT_EQ(Vector2dF(0, 0), helper_.StretchAmount());
  // The gesture will be much greater vertically than horizontally. This should
  // cause the animation to be longer on the Y axis than on the X axis.
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-50, -100));
  SendGestureScrollUpdate(PhaseState::kNonMomentum, Vector2dF(-50, 0));
  // The X axis should be stretched out to verify that the animation doesn't
  // reset its value.
  EXPECT_GT(fabsf(helper_.StretchAmount().x()), 0);

  controller_.scroll_velocity_ = gfx::Vector2dF(0, -4000.f);

  // This signals that the finger has lifted off which triggers a fling.
  const base::TimeTicks now = base::TimeTicks::Now();
  SendGestureScrollEnd(now);

  constexpr int kMaxFrames = 100;
  controller_.Animate(now);
  float x_stretch_amount = fabsf(helper_.StretchAmount().x());
  float y_stretch_amount = fabsf(helper_.StretchAmount().y());
  // Animate the entire forward animation verifying that the x-axis doesn't get
  // moved.
  for (int i = 1; i < kMaxFrames && x_stretch_amount > 0; i++) {
    controller_.Animate(now + base::Milliseconds(i * 16));
    const float new_x_stretch_amount = fabs(helper_.StretchAmount().x());
    const float new_y_stretch_amount = fabs(helper_.StretchAmount().y());
    // Exit the loop when the forward animation ends.
    if (new_y_stretch_amount <= y_stretch_amount) {
      break;
    }

    EXPECT_FLOAT_EQ(new_x_stretch_amount, x_stretch_amount);
    y_stretch_amount = new_y_stretch_amount;
    x_stretch_amount = new_x_stretch_amount;
  }
}
}  // namespace blink

"""

```
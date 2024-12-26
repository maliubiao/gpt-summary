Response:
The user wants to understand the functionality of the provided C++ unit test file for `ElasticOverscrollControllerExponential` in the Chromium Blink engine. I need to analyze the test cases to identify the features being tested and explain them in a user-friendly way.

Here's a plan:

1. **Identify the core class being tested:**  `ElasticOverscrollControllerExponential`.
2. **Understand the purpose of the class:** Based on the name, it likely handles the "elastic overscroll" effect with an exponential behavior. This is the visual effect when you scroll past the boundaries of a scrollable area.
3. **Analyze the test cases:** Go through each `TEST_F` function to determine what specific aspects of the `ElasticOverscrollControllerExponential` are being validated.
4. **Relate to web technologies (JavaScript, HTML, CSS):** Consider how this overscroll behavior manifests in web pages and how it relates to user interactions.
5. **Identify logic and assumptions:** For each test, infer the expected input, processing, and output.
6. **Point out potential user/programming errors:** Think about how developers might misuse or misunderstand the overscroll functionality.
这个文件 `elastic_overscroll_controller_exponential_unittest.cc` 是 Chromium Blink 引擎中 `ElasticOverscrollControllerExponential` 类的单元测试文件。它的主要功能是**测试弹性过度滚动控制器的指数行为**。

更具体地说，这个文件中的测试用例旨在验证以下 `ElasticOverscrollControllerExponential` 类的行为和逻辑：

1. **单轴拉伸 (Axis):**
   - **功能:** 验证弹性拉伸效果一次只发生在一个轴上（水平或垂直），并且默认情况下偏向于垂直轴。
   - **假设输入与输出:**
     - **假设输入 1:**  同时在 X 和 Y 方向施加相等的过度滚动。
     - **预期输出 1:**  主要的拉伸效果应该发生在 Y 轴上。
     - **假设输入 2:** 在 X 方向施加比 Y 方向更大的过度滚动。
     - **预期输出 2:** 主要的拉伸效果应该发生在 X 轴上。
   - **与 Web 技术的关系:** 当用户使用鼠标滚轮或触摸手势滚动网页内容超出边界时，会触发这种弹性拉伸效果。这与用户在 HTML 元素上通过 CSS 设置的滚动行为有关。

2. **拉伸前的最小偏移量 (MinimumDeltaBeforeStretch):**
   - **功能:** 验证在开始弹性拉伸之前，在被“钉住”的方向上需要一个最小的过度滚动偏移量（至少 10 个单位）。
   - **假设输入与输出:**
     - **假设输入:**  在“钉住”的方向上提供小于 10 个单位的过度滚动偏移量，然后提供一个超过 10 个单位的偏移量。
     - **预期输出:**  在第一次偏移量小于阈值时，不应该发生拉伸。只有当总偏移量超过阈值后才开始拉伸。
   - **与 Web 技术的关系:** 这可以防止在轻微的过度滚动时出现不必要的弹性效果，提供更流畅的用户体验。

3. **动量动画 (MomentumAnimate):**
   - **功能:** 验证由动量滚动引起的拉伸会切换到动画模式，在这种模式下，输入事件被忽略，并在动画过程中更新拉伸量。
   - **假设输入与输出:**
     - **假设输入:**  首先进行主动滚动，然后切换到动量阶段并继续滚动，直到超出边界。
     - **预期输出:**  当超过边界并达到拉伸阈值时，会开始动画，并且在动画期间会持续更新拉伸量。新的滚动事件会被忽略，直到动画结束或被用户中断。
   - **与 Web 技术的关系:** 当用户快速滑动页面并释放触摸屏或鼠标滚轮后，页面会继续滚动（动量滚动），超出边界时会显示弹性拉伸动画。

4. **协调拉伸和滚动 (ReconcileStretchAndScroll):**
   - **功能:** 验证当弹性拉伸存在时，如何正确地与正常的滚动操作协调，以消除或减少拉伸效果。
   - **假设输入与输出:**
     - **假设输入:**  设置一个非零的弹性拉伸量，然后尝试在相反方向滚动。
     - **预期输出:**  滚动操作会减少或消除拉伸量，并相应地调整滚动偏移。
   - **与 Web 技术的关系:**  当用户在弹性拉伸状态下开始向回滚动时，这个机制确保了平滑的过渡，避免了突兀的跳跃。

5. **需要用户可滚动才能拉伸 (UserScrollableRequiredForStretch):**
   - **功能:** 验证只有当区域是用户可滚动时才会发生弹性拉伸。
   - **假设输入与输出:**
     - **假设输入 1:**  在不可滚动的区域尝试过度滚动。
     - **预期输出 1:** 不应该发生弹性拉伸。
     - **假设输入 2:**  在可滚动的区域尝试过度滚动。
     - **预期输出 2:** 应该发生弹性拉伸。
     - **假设输入 3:**  在发生拉伸后，将区域设置为不可滚动。
     - **预期输出 3:**  拉伸效果会逐渐消失。
   - **与 Web 技术的关系:**  这确保了只有在用户可以实际滚动的元素上才会出现弹性效果，避免了在静态内容上出现不必要的效果。这与 HTML 元素的 `overflow` CSS 属性有关。

6. **单轴用户可滚动 (UserScrollableSingleAxis):**
   - **功能:** 验证在只允许单轴滚动的区域，弹性拉伸只会在允许滚动的轴上发生。
   - **假设输入与输出:**
     - **假设输入 1:**  在只允许水平滚动的区域尝试垂直方向的过度滚动。
     - **预期输出 1:** 不会发生垂直方向的拉伸。
     - **假设输入 2:**  在只允许垂直滚动的区域尝试水平方向的过度滚动。
     - **预期输出 2:** 不会发生水平方向的拉伸。
     - **假设输入 3:**  在只允许垂直滚动的区域尝试垂直方向的过度滚动。
     - **预期输出 3:** 会发生垂直方向的拉伸。
     - **假设输入 4:**  在只允许水平滚动的区域尝试水平方向的过度滚动。
     - **预期输出 4:** 会发生水平方向的拉伸。
   - **与 Web 技术的关系:**  这与 CSS 的 `overflow-x` 和 `overflow-y` 属性有关，允许开发者控制特定轴的滚动行为。

7. **OverscrollBehavior (过度滚动行为):**
   - **功能:** 验证 `OverscrollBehavior` CSS 属性如何禁用特定轴上的弹性拉伸。
   - **假设输入与输出:**
     - **假设输入 1:**  设置 `overscroll-behavior-x: none`，并尝试在 X 轴上过度滚动。
     - **预期输出 1:** 不会发生 X 轴上的拉伸。
     - **假设输入 2:**  设置 `overscroll-behavior-x: none`，并尝试在 Y 轴上过度滚动。
     - **预期输出 2:** 会发生 Y 轴上的拉伸。
     - **假设输入 3:**  设置 `overscroll-behavior-y: none`，并尝试在 Y 轴上过度滚动。
     - **预期输出 3:** 不会发生 Y 轴上的拉伸。
     - **假设输入 4:**  设置 `overscroll-behavior-y: none`，并尝试在 X 轴上过度滚动。
     - **预期输出 4:** 会发生 X 轴上的拉伸。
   - **与 Web 技术的关系:**  直接关联到 CSS 的 `overscroll-behavior` 属性，允许开发者控制浏览器的默认过度滚动行为。

8. **不可滚动方向的过度滚动 (OverscrollBehaviorNonScrollable):**
   - **功能:** 测试在不可滚动方向上的过度滚动行为。
   - **假设输入与输出:**
     - **假设输入:** 在一个垂直可滚动且已滚动到底部的元素上，尝试水平方向的过度滚动。
     - **预期输出 (取决于平台):** 在某些平台上（例如 Android），即使该方向不可滚动，也可能不会产生拉伸效果。在其他平台上可能会产生拉伸。尝试在可滚动方向上过度滚动应该始终产生拉伸。
   - **与 Web 技术的关系:**  涉及到浏览器处理超出内容边界的滚动事件的方式，以及不同平台对过度滚动行为的默认实现。

**与 JavaScript, HTML, CSS 的功能关系举例说明:**

- **HTML:**  HTML 结构定义了可滚动的内容区域，例如使用了 `overflow: auto` 或 `overflow: scroll` 的 `<div>` 元素。
- **CSS:**
    - `overflow`:  决定了当内容超出元素边界时如何显示，影响是否可以滚动。
    - `overflow-x`, `overflow-y`: 更精细地控制水平和垂直方向的滚动。
    - `overscroll-behavior`:  控制浏览器的过度滚动行为，例如禁用弹性效果。
- **JavaScript:**  JavaScript 可以监听滚动事件 (`scroll` event) 并执行自定义逻辑。虽然这个单元测试主要关注底层的 C++ 实现，但 JavaScript 的滚动事件与这里测试的弹性过度滚动效果是紧密相关的。例如，开发者可以使用 JavaScript 来实现自定义的过度滚动动画，或者阻止浏览器的默认行为。

**用户或编程常见的使用错误举例说明:**

1. **错误地认为可以通过 CSS 完全禁用所有平台的弹性过度滚动效果：**  虽然可以使用 `overscroll-behavior: none;` 来禁用大部分平台的弹性效果，但某些平台（尤其是移动端）可能有其特定的默认行为，可能需要额外的处理。
2. **在不可滚动的元素上期望出现弹性效果：** 开发者可能会忘记设置 `overflow` 属性，或者将其设置为 `hidden`，然后期望在内容超出时看到弹性效果，但这不会发生。
3. **没有考虑到不同平台的默认过度滚动行为：**  不同的操作系统和浏览器可能对过度滚动的处理方式略有不同，开发者需要在开发跨平台应用时考虑到这些差异。
4. **过度依赖 JavaScript 实现过度滚动效果，而忽略了浏览器提供的原生功能：**  浏览器原生的弹性过度滚动通常性能更好，并且能提供更自然的用户体验。除非有非常特殊的需求，否则应该尽量利用浏览器提供的功能。

总而言之，`elastic_overscroll_controller_exponential_unittest.cc` 这个文件通过各种测试用例，深入地验证了 Blink 引擎中弹性过度滚动控制器的核心逻辑和行为，确保了在不同的滚动场景下，弹性效果能够正确、平滑地工作，并与相关的 Web 技术（HTML, CSS）协同工作。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/elastic_overscroll_controller_exponential_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/elastic_overscroll_controller_exponential.h"

#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/input/input_handler.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"

namespace blink {

using gfx::Size;
using gfx::Vector2dF;

namespace {

enum Phase {
  PhaseNone = WebMouseWheelEvent::kPhaseNone,
  PhaseBegan = WebMouseWheelEvent::kPhaseBegan,
  PhaseStationary = WebMouseWheelEvent::kPhaseStationary,
  PhaseChanged = WebMouseWheelEvent::kPhaseChanged,
  PhaseEnded = WebMouseWheelEvent::kPhaseEnded,
  PhaseCancelled = WebMouseWheelEvent::kPhaseCancelled,
  PhaseMayBegin = WebMouseWheelEvent::kPhaseMayBegin,
};

enum InertialPhaseState {
  UnknownMomentumPhase =
      static_cast<int>(WebGestureEvent::InertialPhaseState::kUnknownMomentum),
  NonMomentumPhase =
      static_cast<int>(WebGestureEvent::InertialPhaseState::kNonMomentum),
  MomentumPhase =
      static_cast<int>(WebGestureEvent::InertialPhaseState::kMomentum),
};

class MockScrollElasticityHelper : public cc::ScrollElasticityHelper {
 public:
  MockScrollElasticityHelper() = default;
  ~MockScrollElasticityHelper() override = default;

  // cc::ScrollElasticityHelper implementation:
  bool IsUserScrollableHorizontal() const override {
    return is_user_scrollable_horizontal_;
  }
  bool IsUserScrollableVertical() const override {
    return is_user_scrollable_vertical_;
  }
  Vector2dF StretchAmount() const override { return stretch_amount_; }
  void SetStretchAmount(const Vector2dF& stretch_amount) override {
    set_stretch_amount_count_ += 1;
    stretch_amount_ = stretch_amount;
  }

  Size ScrollBounds() const override { return Size(800, 600); }
  gfx::PointF ScrollOffset() const override { return scroll_offset_; }
  gfx::PointF MaxScrollOffset() const override { return max_scroll_offset_; }
  void ScrollBy(const Vector2dF& delta) override { scroll_offset_ += delta; }
  void RequestOneBeginFrame() override { request_begin_frame_count_ += 1; }

  // Counters for number of times functions were called.
  int request_begin_frame_count() const { return request_begin_frame_count_; }
  int set_stretch_amount_count() const { return set_stretch_amount_count_; }

  void SetScrollOffsetAndMaxScrollOffset(const gfx::PointF& scroll_offset,
                                         const gfx::PointF& max_scroll_offset) {
    scroll_offset_ = scroll_offset;
    max_scroll_offset_ = max_scroll_offset;
  }
  void SetUserScrollable(bool horizontal, bool vertical) {
    is_user_scrollable_horizontal_ = horizontal;
    is_user_scrollable_vertical_ = vertical;
  }

 private:
  bool is_user_scrollable_horizontal_ = true;
  bool is_user_scrollable_vertical_ = true;
  Vector2dF stretch_amount_;
  int set_stretch_amount_count_ = 0;
  int request_begin_frame_count_ = 0;

  gfx::PointF scroll_offset_;
  gfx::PointF max_scroll_offset_;
};

class ElasticOverscrollControllerExponentialTest : public testing::Test {
 public:
  ElasticOverscrollControllerExponentialTest()
      : controller_(&helper_),
        current_time_(base::TimeTicks() +
                      base::Microseconds(INT64_C(100000000))) {}
  ~ElasticOverscrollControllerExponentialTest() override {}

  void SendGestureScrollBegin(InertialPhaseState inertialPhase) {
    TickCurrentTime();
    WebGestureEvent event(WebInputEvent::Type::kGestureScrollBegin,
                          WebInputEvent::kNoModifiers, current_time_,
                          WebGestureDevice::kTouchpad);
    event.data.scroll_begin.inertial_phase =
        static_cast<WebGestureEvent::InertialPhaseState>(inertialPhase);

    controller_.ObserveGestureEventAndResult(event,
                                             cc::InputHandlerScrollResult());
  }

  void SendGestureScrollUpdate(
      InertialPhaseState inertialPhase,
      const Vector2dF& event_delta = Vector2dF(),
      const Vector2dF& overscroll_delta = Vector2dF(),
      const cc::OverscrollBehavior& overscroll_behavior =
          cc::OverscrollBehavior()) {
    TickCurrentTime();
    WebGestureEvent event(WebInputEvent::Type::kGestureScrollUpdate,
                          WebInputEvent::kNoModifiers, current_time_,
                          WebGestureDevice::kTouchpad);
    event.data.scroll_update.inertial_phase =
        static_cast<WebGestureEvent::InertialPhaseState>(inertialPhase);
    event.data.scroll_update.delta_x = -event_delta.x();
    event.data.scroll_update.delta_y = -event_delta.y();

    cc::InputHandlerScrollResult scroll_result;
    scroll_result.did_overscroll_root = !overscroll_delta.IsZero();
    scroll_result.unused_scroll_delta = overscroll_delta;
    scroll_result.overscroll_behavior = overscroll_behavior;

    controller_.ObserveGestureEventAndResult(event, scroll_result);
  }

  void SendGestureScrollEnd() {
    TickCurrentTime();
    WebGestureEvent event(WebInputEvent::Type::kGestureScrollEnd,
                          WebInputEvent::kNoModifiers, current_time_,
                          WebGestureDevice::kTouchpad);

    controller_.ObserveGestureEventAndResult(event,
                                             cc::InputHandlerScrollResult());
  }

  const base::TimeTicks& TickCurrentTime() {
    current_time_ += base::Seconds(1 / 60.f);
    return current_time_;
  }
  void TickCurrentTimeAndAnimate() {
    TickCurrentTime();
    controller_.Animate(current_time_);
  }

  MockScrollElasticityHelper helper_;
  ElasticOverscrollControllerExponential controller_;
  base::TimeTicks current_time_;
};

// Verify that stretching  occurs in one axis at a time, and that it
// is biased to the Y axis.
TEST_F(ElasticOverscrollControllerExponentialTest, Axis) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(10, 10),
                                            gfx::PointF(10, 10));

  // If we push equally in the X and Y directions, we should see a stretch
  // in the Y direction.
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(10, 10),
                          Vector2dF(10, 10));
  EXPECT_EQ(1, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
  EXPECT_LT(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  EXPECT_EQ(2, helper_.set_stretch_amount_count());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());

  // If we push more in the X direction than the Y direction, we should see a
  // stretch  in the X direction. This decision should be based on the actual
  // overscroll delta.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 10),
                                            gfx::PointF(10, 10));
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(-25, 10),
                          Vector2dF(-25, 10));
  EXPECT_EQ(3, helper_.set_stretch_amount_count());
  EXPECT_GT(0.f, helper_.StretchAmount().x());
  EXPECT_EQ(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  EXPECT_EQ(4, helper_.set_stretch_amount_count());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());
}

// Verify that we need a total overscroll delta of at least 10 in a pinned
// direction before we start stretching.
TEST_F(ElasticOverscrollControllerExponentialTest, MinimumDeltaBeforeStretch) {
  // We should not start stretching while we are not pinned in the direction
  // of the scroll (even if there is an overscroll delta). We have to wait for
  // the regular scroll to eat all of the events.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(5, 5),
                                            gfx::PointF(10, 10));
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 10));
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 10));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Now pin the -X and +Y direction. The first event will not generate a
  // stretch
  // because it is below the delta threshold of 10.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 10),
                                            gfx::PointF(10, 10));
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 8));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Make the next scroll be in the -X direction more than the +Y direction,
  // which will erase the memory of the previous unused delta of 8.
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(-10, 5),
                          Vector2dF(-8, 5));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Now push against the pinned +Y direction again by 8. We reset the
  // previous delta, so this will not generate a stretch.
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 8));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Push against +Y by another 8. This gets us above the delta threshold of
  // 10, so we should now have had the stretch set, and it should be in the
  // +Y direction. The scroll in the -X direction should have been forgotten.
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 8));
  EXPECT_EQ(1, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
  EXPECT_LT(0.f, helper_.StretchAmount().y());

  // End the gesture. Because there is a non-zero stretch, we should be in the
  // animated state, and should have had a frame requested.
  EXPECT_EQ(0, helper_.request_begin_frame_count());
  SendGestureScrollEnd();
  EXPECT_EQ(1, helper_.request_begin_frame_count());
}

// Verify that a stretch caused by a momentum scroll will switch to the
// animating mode, where input events are ignored, and the stretch is updated
// while animating.
TEST_F(ElasticOverscrollControllerExponentialTest, MomentumAnimate) {
  // Do an active scroll, then switch to the momentum phase and scroll for a
  // bit.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(5, 5),
                                            gfx::PointF(10, 10));
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, -80), Vector2dF(0, 0));
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, -80), Vector2dF(0, 0));
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, -80), Vector2dF(0, 0));
  SendGestureScrollEnd();
  SendGestureScrollBegin(MomentumPhase);
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, 0));
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, 0));
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, 0));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Hit the -Y edge and overscroll slightly, but not enough to go over the
  // threshold to cause a stretch.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(5, 0),
                                            gfx::PointF(10, 10));
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, -8));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());
  EXPECT_EQ(0, helper_.request_begin_frame_count());

  // Take another step, this time going over the threshold. This should update
  // the stretch amount, and then switch to the animating mode.
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, -80));
  EXPECT_EQ(1, helper_.set_stretch_amount_count());
  EXPECT_EQ(1, helper_.request_begin_frame_count());
  EXPECT_GT(-1.f, helper_.StretchAmount().y());

  // Subsequent momentum events should do nothing.
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, -80));
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, -80));
  SendGestureScrollUpdate(MomentumPhase, Vector2dF(0, -80), Vector2dF(0, -80));
  SendGestureScrollEnd();
  EXPECT_EQ(1, helper_.set_stretch_amount_count());
  EXPECT_EQ(1, helper_.request_begin_frame_count());

  // Subsequent animate events should update the stretch amount and request
  // another frame.
  TickCurrentTimeAndAnimate();
  EXPECT_EQ(2, helper_.set_stretch_amount_count());
  EXPECT_EQ(2, helper_.request_begin_frame_count());
  EXPECT_GT(-1.f, helper_.StretchAmount().y());

  // Touching the trackpad (a PhaseMayBegin event) should disable animation.
  SendGestureScrollBegin(NonMomentumPhase);
  TickCurrentTimeAndAnimate();
  EXPECT_EQ(2, helper_.set_stretch_amount_count());
  EXPECT_EQ(2, helper_.request_begin_frame_count());

  // Releasing the trackpad should re-enable animation.
  SendGestureScrollEnd();
  EXPECT_EQ(2, helper_.set_stretch_amount_count());
  EXPECT_EQ(3, helper_.request_begin_frame_count());
  TickCurrentTimeAndAnimate();
  EXPECT_EQ(3, helper_.set_stretch_amount_count());
  EXPECT_EQ(4, helper_.request_begin_frame_count());

  // Keep animating frames until the stretch returns to rest.
  int stretch_count = 3;
  int begin_frame_count = 4;
  while (true) {
    TickCurrentTimeAndAnimate();
    if (helper_.StretchAmount().IsZero()) {
      stretch_count += 1;
      EXPECT_EQ(stretch_count, helper_.set_stretch_amount_count());
      EXPECT_EQ(begin_frame_count, helper_.request_begin_frame_count());
      break;
    }
    stretch_count += 1;
    begin_frame_count += 1;
    EXPECT_EQ(stretch_count, helper_.set_stretch_amount_count());
    EXPECT_EQ(begin_frame_count, helper_.request_begin_frame_count());
  }

  // After coming to rest, no subsequent animate calls change anything.
  TickCurrentTimeAndAnimate();
  EXPECT_EQ(stretch_count, helper_.set_stretch_amount_count());
  EXPECT_EQ(begin_frame_count, helper_.request_begin_frame_count());
}

// Verify that a stretch opposing a scroll is correctly resolved.
TEST_F(ElasticOverscrollControllerExponentialTest, ReconcileStretchAndScroll) {
  SendGestureScrollBegin(NonMomentumPhase);

  // Verify completely knocking out the scroll in the -Y direction.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(5, 5),
                                            gfx::PointF(10, 10));
  helper_.SetStretchAmount(Vector2dF(0, -10));
  controller_.ReconcileStretchAndScroll();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, -5));
  EXPECT_EQ(helper_.ScrollOffset(), gfx::PointF(5, 0));

  // Verify partially knocking out the scroll in the -Y direction.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(5, 8),
                                            gfx::PointF(10, 10));
  helper_.SetStretchAmount(Vector2dF(0, -5));
  controller_.ReconcileStretchAndScroll();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_EQ(helper_.ScrollOffset(), gfx::PointF(5, 3));

  // Verify completely knocking out the scroll in the +X direction.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(5, 5),
                                            gfx::PointF(10, 10));
  helper_.SetStretchAmount(Vector2dF(10, 0));
  controller_.ReconcileStretchAndScroll();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(5, 0));
  EXPECT_EQ(helper_.ScrollOffset(), gfx::PointF(10, 5));

  // Verify partially knocking out the scroll in the +X and +Y directions.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(2, 3),
                                            gfx::PointF(10, 10));
  helper_.SetStretchAmount(Vector2dF(5, 5));
  controller_.ReconcileStretchAndScroll();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_EQ(helper_.ScrollOffset(), gfx::PointF(7, 8));
}

// Verify that stretching  happens when the area is user scrollable.
TEST_F(ElasticOverscrollControllerExponentialTest,
       UserScrollableRequiredForStretch) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(10, 10));
  Vector2dF delta(0, -15);

  // Do an active scroll, and ensure that the stretch amount doesn't change.
  helper_.SetUserScrollable(false, false);
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, delta, delta);
  SendGestureScrollUpdate(NonMomentumPhase, delta, delta);
  SendGestureScrollEnd();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());
  SendGestureScrollBegin(MomentumPhase);
  SendGestureScrollUpdate(MomentumPhase, delta, delta);
  SendGestureScrollUpdate(MomentumPhase, delta, delta);
  SendGestureScrollEnd();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Re-enable user scrolling and ensure that stretching is re-enabled.
  helper_.SetUserScrollable(true, true);
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, delta, delta);
  SendGestureScrollUpdate(NonMomentumPhase, delta, delta);
  SendGestureScrollEnd();
  EXPECT_NE(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_GT(helper_.set_stretch_amount_count(), 0);
  SendGestureScrollBegin(MomentumPhase);
  SendGestureScrollUpdate(MomentumPhase, delta, delta);
  SendGestureScrollUpdate(MomentumPhase, delta, delta);
  SendGestureScrollEnd();
  EXPECT_NE(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_GT(helper_.set_stretch_amount_count(), 0);

  // Disable user scrolling and tick the timer until the stretch goes back
  // to zero. Ensure that the return to zero doesn't happen immediately.
  helper_.SetUserScrollable(false, false);
  int ticks_to_zero = 0;
  while (true) {
    TickCurrentTimeAndAnimate();
    if (helper_.StretchAmount().IsZero())
      break;
    ticks_to_zero += 1;
  }
  EXPECT_GT(ticks_to_zero, 3);
}

TEST_F(ElasticOverscrollControllerExponentialTest, UserScrollableSingleAxis) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 0),
                                            gfx::PointF(10, 10));
  Vector2dF vertical_delta(0, -15);
  Vector2dF horizontal_delta(-15, 0);

  // Attempt vertical scroll when only horizontal allowed.
  helper_.SetUserScrollable(true, false);
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, vertical_delta, vertical_delta);
  SendGestureScrollEnd();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Attempt horizontal scroll when only vertical allowed.
  helper_.SetUserScrollable(false, true);
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, horizontal_delta, horizontal_delta);
  SendGestureScrollEnd();
  EXPECT_EQ(helper_.StretchAmount(), Vector2dF(0, 0));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());

  // Vertical scroll, only vertical allowed.
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, vertical_delta, vertical_delta);
  SendGestureScrollEnd();
  EXPECT_LT(helper_.StretchAmount().y(), 0);

  // Horizontal scroll, only horizontal allowed.
  helper_.SetUserScrollable(true, false);
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, horizontal_delta, horizontal_delta);
  SendGestureScrollEnd();
  EXPECT_LT(helper_.StretchAmount().x(), 0);
}

// Verify that OverscrollBehaviorTypeNone disables the stretching on the
// specified axis.
TEST_F(ElasticOverscrollControllerExponentialTest, OverscrollBehavior) {
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(10, 10),
                                            gfx::PointF(10, 10));

  // If we set OverscrollBehaviorTypeNone on x, we should not see a stretch
  // in the X direction.
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(
      NonMomentumPhase, Vector2dF(10, 0), Vector2dF(10, 0),
      cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kNone,
                             cc::OverscrollBehavior::Type::kAuto));
  EXPECT_EQ(0, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
  EXPECT_EQ(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  EXPECT_EQ(1, helper_.set_stretch_amount_count());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());

  // If we set OverscrollBehaviorTypeNone on x, we could still see a stretch
  // in the Y direction
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(
      NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 10),
      cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kNone,
                             cc::OverscrollBehavior::Type::kAuto));
  EXPECT_EQ(2, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
  EXPECT_LT(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  EXPECT_EQ(3, helper_.set_stretch_amount_count());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());

  // If we set OverscrollBehaviorTypeNone on y, we should not see a stretch
  // in the Y direction.
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(
      NonMomentumPhase, Vector2dF(0, 10), Vector2dF(0, 10),
      cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kAuto,
                             cc::OverscrollBehavior::Type::kNone));
  EXPECT_EQ(3, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
  EXPECT_EQ(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  EXPECT_EQ(4, helper_.set_stretch_amount_count());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());

  // If we set OverscrollBehaviorTypeNone on y, we could still see a stretch
  // in the X direction.
  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(
      NonMomentumPhase, Vector2dF(10, 0), Vector2dF(10, 0),
      cc::OverscrollBehavior(cc::OverscrollBehavior::Type::kAuto,
                             cc::OverscrollBehavior::Type::kNone));
  EXPECT_EQ(5, helper_.set_stretch_amount_count());
  EXPECT_LT(0.f, helper_.StretchAmount().x());
  EXPECT_EQ(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  EXPECT_EQ(6, helper_.set_stretch_amount_count());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());
}

// Test overscroll in non-scrollable direction.
TEST_F(ElasticOverscrollControllerExponentialTest,
       OverscrollBehaviorNonScrollable) {
  int expected_stretch_count = 0;
  // Set up a scroller which is vertically scrollable scrolled to the bottom.
  helper_.SetScrollOffsetAndMaxScrollOffset(gfx::PointF(0, 10),
                                            gfx::PointF(0, 10));

  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(25, 0), Vector2dF(25, 0));
#if BUILDFLAG(IS_ANDROID)
  // Scrolling in x axis which has no scroll range should produce no stretch
  // on android.
  EXPECT_EQ(expected_stretch_count, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
#else
  EXPECT_EQ(++expected_stretch_count, helper_.set_stretch_amount_count());
  EXPECT_LT(0.f, helper_.StretchAmount().x());
#endif
  EXPECT_EQ(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());
  EXPECT_EQ(++expected_stretch_count, helper_.set_stretch_amount_count());

  SendGestureScrollBegin(NonMomentumPhase);
  SendGestureScrollUpdate(NonMomentumPhase, Vector2dF(0, 25), Vector2dF(0, 25));
  // Scrolling in y axis which has scroll range should produce overscroll
  // on all platforms.
  EXPECT_EQ(++expected_stretch_count, helper_.set_stretch_amount_count());
  EXPECT_EQ(0.f, helper_.StretchAmount().x());
  EXPECT_LT(0.f, helper_.StretchAmount().y());
  helper_.SetStretchAmount(Vector2dF());
  SendGestureScrollEnd();
  EXPECT_EQ(0, helper_.request_begin_frame_count());
}

}  // namespace
}  // namespace blink

"""

```
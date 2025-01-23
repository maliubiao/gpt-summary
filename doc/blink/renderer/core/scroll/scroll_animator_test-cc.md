Response:
My thinking process to analyze the provided C++ test file goes like this:

1. **Understand the Core Purpose:** The file name `scroll_animator_test.cc` immediately suggests this file contains unit tests for the `ScrollAnimator` class. The `#include` directives confirm this, especially the inclusion of `scroll_animator.h`.

2. **Identify Key Classes and Concepts:**  Scanning the includes reveals important related classes:
    * `ScrollAnimator`: The central class being tested.
    * `ScrollableArea`:  The class that `ScrollAnimator` interacts with. The tests mock this class to control its behavior.
    * `ScrollOffset`: Represents the scroll position.
    * `ScrollType`:  Indicates the type of scroll (user, programmatically, etc.).
    * `ScrollBehavior`:  Indicates if the scroll should be smooth or instant.
    * `ScrollbarOrientation`:  Specifies horizontal or vertical scrollbars.
    * `ui::ScrollGranularity`:  Defines the scroll increment (line, page, pixel).
    * `base::TestMockTimeTaskRunner`: Used to control the passage of time in tests, essential for testing animations.
    * `testing::gmock` and `testing::gtest`:  The testing frameworks used.

3. **Analyze the Test Structure:**  The file uses Google Test (`TEST` macro). Each `TEST` case focuses on a specific aspect of `ScrollAnimator`'s functionality. Looking at the test names provides a good overview of the tested features.

4. **Examine Individual Test Cases:** For each test, I try to understand:
    * **Setup:** What mock objects are created? What expectations are set on the mock objects (using `EXPECT_CALL`)?  What initial conditions are established?
    * **Action:** What methods of `ScrollAnimator` are being called? What are the inputs to these methods?
    * **Assertions:** What are the expected outcomes (using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_FLOAT_EQ`)? These assertions verify the correctness of `ScrollAnimator`'s behavior under specific conditions.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  This is where understanding the *purpose* of `ScrollAnimator` comes in. Scroll animation is directly related to how scrolling behaves in web browsers. I look for connections like:
    * **User Interaction:**  `UserScroll` directly maps to user actions like using the mouse wheel, trackpad gestures, or scrollbar interactions.
    * **Smooth Scrolling:**  The tests involving `ScrollBehavior::kSmooth` and the use of `base::TestMockTimeTaskRunner` demonstrate testing the implementation of CSS's `scroll-behavior: smooth;` property or JavaScript's `scrollTo({ behavior: 'smooth' })`.
    * **Programmatic Scrolling:** While not explicitly tested with a "programmatic" flag, the underlying mechanism handles both user-initiated and script-initiated smooth scrolling.
    * **Compositor Involvement:**  Tests with names like "AnimatedScrollTakeover" and those involving `SendAnimationToCompositor` relate to how the browser's compositor process can handle scroll animations for better performance.

6. **Identify Logic and Assumptions:**  The tests make assumptions about how `ScrollAnimator` *should* behave. For instance, the test "AnimatedScrollAborted" assumes that an instant scroll will interrupt a smooth scroll. The use of mocks allows isolating `ScrollAnimator` and controlling the behavior of its dependencies.

7. **Recognize Potential User/Programming Errors:** The tests often implicitly reveal potential errors. For example, failing to handle interruptions correctly, not respecting minimum/maximum scroll boundaries, or issues with coordination between the main thread and the compositor.

8. **Trace User Steps (Debugging Clues):**  I consider how a user action might trigger the code being tested. For example, a user scrolling quickly might trigger a smooth animation. If the animation doesn't behave as expected, these tests provide clues about where to look for problems in the `ScrollAnimator` implementation.

9. **Synthesize a Summary:**  Based on the above analysis, I form a concise summary of the file's purpose and key functionalities.

**Applying this to the given code snippet:**

* The initial comment block describes the licensing.
* The `#include` statements highlight the dependencies and the core class being tested.
* The `MockScrollableAreaForAnimatorTest` class is crucial. It allows simulating the environment in which `ScrollAnimator` operates, with controllable responses to `ScrollAnimator`'s actions.
* The various `TEST` cases cover different scenarios: main thread states, enabling/disabling animations, interrupting animations, compositor involvement, and handling callbacks.
* The use of `base::TestMockTimeTaskRunner` is essential for testing time-based behavior (animations).
* The assertions within each test case define the expected behavior.

By systematically going through these steps, I can understand the purpose and functionality of the `scroll_animator_test.cc` file and how it relates to the broader context of the Blink rendering engine.
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials made available with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Tests for the ScrollAnimator class.

#include "third_party/blink/renderer/core/scroll/scroll_animator.h"

#include "base/task/single_thread_task_runner.h"
#include "base/test/test_mock_time_task_runner.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

using testing::AtLeast;
using testing::Return;
using testing::_;

namespace {

base::TimeTicks NowTicksInSeconds(
    const base::TestMockTimeTaskRunner* task_runner) {
  return task_runner->NowTicks();
}

}  // namespace

class MockScrollableAreaForAnimatorTest
    : public GarbageCollected<MockScrollableAreaForAnimatorTest>,
      public ScrollableArea {
 public:
  explicit MockScrollableAreaForAnimatorTest(bool scroll_animator_enabled,
                                             const ScrollOffset& min_offset,
                                             const ScrollOffset& max_offset)
      : ScrollableArea(blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        scroll_animator_enabled_(scroll_animator_enabled),
        min_offset_(min_offset),
        max_offset_(max_offset) {}

  MOCK_CONST_METHOD0(IsActive, bool());
  MOCK_CONST_METHOD0(IsThrottled, bool());
  MOCK_CONST_METHOD1(ScrollSize, int(ScrollbarOrientation));
  MOCK_CONST_METHOD0(IsScrollCornerVisible, bool());
  MOCK_CONST_METHOD0(ScrollCornerRect, gfx::Rect());
  MOCK_METHOD2(UpdateScrollOffset,
               void(const ScrollOffset&, mojom::blink::ScrollType));
  MOCK_METHOD0(ScrollControlWasSetNeedsPaintInvalidation, void());
  MOCK_CONST_METHOD0(EnclosingScrollableArea, ScrollableArea*());
  MOCK_CONST_METHOD1(VisibleContentRect, gfx::Rect(IncludeScrollbarsInRect));
  MOCK_CONST_METHOD0(ContentsSize, gfx::Size());
  MOCK_CONST_METHOD0(ScrollbarsCanBeActive, bool());
  MOCK_METHOD0(RegisterForAnimation, void());
  MOCK_METHOD0(ScheduleAnimation, bool());
  MOCK_CONST_METHOD0(UsedColorSchemeScrollbars, mojom::blink::ColorScheme());

  bool UsesCompositedScrolling() const override { NOTREACHED(); }
  PhysicalOffset LocalToScrollOriginOffset() const override { return {}; }
  bool UserInputScrollable(ScrollbarOrientation) const override { return true; }
  bool ShouldPlaceVerticalScrollbarOnLeft() const override { return false; }
  gfx::Vector2d ScrollOffsetInt() const override { return gfx::Vector2d(); }
  int VisibleHeight() const override { return 768; }
  int VisibleWidth() const override { return 1024; }
  CompositorElementId GetScrollElementId() const override {
    return CompositorElementId();
  }
  bool ScrollAnimatorEnabled() const override {
    return scroll_animator_enabled_;
  }
  int PageStep(ScrollbarOrientation) const override { return 0; }
  gfx::Vector2d MinimumScrollOffsetInt() const override {
    return gfx::ToFlooredVector2d(min_offset_);
  }
  gfx::Vector2d MaximumScrollOffsetInt() const override {
    return gfx::ToFlooredVector2d(max_offset_);
  }

  void SetScrollAnimator(ScrollAnimator* scroll_animator) {
    animator = scroll_animator;
  }

  ScrollOffset GetScrollOffset() const override {
    if (animator)
      return animator->CurrentOffset();
    return ScrollOffsetInt();
  }

  bool SetScrollOffset(const ScrollOffset& offset,
                       mojom::blink::ScrollType type,
                       mojom::blink::ScrollBehavior behavior =
                           mojom::blink::ScrollBehavior::kInstant,
                       ScrollCallback on_finish = ScrollCallback()) override {
    if (animator)
      animator->SetCurrentOffset(offset);
    return ScrollableArea::SetScrollOffset(offset, type, behavior,
                                           std::move(on_finish));
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTimerTaskRunner() const final {
    if (!timer_task_runner_) {
      timer_task_runner_ =
          blink::scheduler::GetSingleThreadTaskRunnerForTesting();
    }
    return timer_task_runner_;
  }

  ScrollbarTheme& GetPageScrollbarTheme() const override {
    return ScrollbarTheme::GetTheme();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(animator);
    ScrollableArea::Trace(visitor);
  }

  void DisposeImpl() override { timer_task_runner_.reset(); }

 private:
  bool scroll_animator_enabled_;
  ScrollOffset min_offset_;
  ScrollOffset max_offset_;
  Member<ScrollAnimator> animator;
  mutable scoped_refptr<base::SingleThreadTaskRunner> timer_task_runner_;
};

class TestScrollAnimator : public ScrollAnimator {
 public:
  TestScrollAnimator(ScrollableArea* scrollable_area,
                     const base::TickClock* tick_clock)
      : ScrollAnimator(scrollable_area, tick_clock) {}
  ~TestScrollAnimator() override = default;

  void SetShouldSendToCompositor(bool send) {
    should_send_to_compositor_ = send;
  }

  bool SendAnimationToCompositor() override {
    if (should_send_to_compositor_) {
      run_state_ =
          ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor;
      compositor_animation_id_ = 1;
      return true;
    }
    return false;
  }

 protected:
  void AbortAnimation() override {}

 private:
  bool should_send_to_compositor_ = false;
};

static void Reset(ScrollAnimator& scroll_animator) {
  scroll_animator.ScrollToOffsetWithoutAnimation(ScrollOffset());
}

// TODO(skobes): Add unit tests for composited scrolling paths.

TEST(ScrollAnimatorTest, MainThreadStates) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(2);
  // Once from userScroll, once from updateCompositorAnimations.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(2);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  // Idle
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::kIdle);

  // WaitingToSendToCompositor
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // RunningOnMainThread
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);

  // PostAnimationCleanup
  scroll_animator->CancelAnimation();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  // Idle
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::kIdle);

  Reset(*scroll_animator);

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

TEST(ScrollAnimatorTest, MainThreadEnabled) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(9);
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(6);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(-100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_FALSE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(-100.0f, result.unused_scroll_delta_x);

  result = scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                                       ScrollOffset(100, 0),
                                       ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPage,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPixel,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  task_runner->FastForwardBy(base::Seconds(1.0));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());

  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

// Test that a smooth scroll offset animation is aborted when followed by a
// non-smooth scroll offset animation.
TEST(ScrollAnimatorTest, AnimatedScrollAborted) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(3);
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(2);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  // Smooth scroll.
  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);
  EXPECT_TRUE(scroll_animator->HasRunningAnimation());

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  float x = scroll_animator->CurrentOffset().x();

  // Instant scroll.
  result = scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                       ScrollOffset(100, 0),
                                       ScrollableArea::ScrollCallback());
  EXPECT_TRUE(result.did_scroll_x);
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_FALSE(scroll_animator->HasRunningAnimation());
  EXPECT_EQ(x + 100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  Reset(*scroll_animator);
}

// Test that a smooth scroll offset animation running on the compositor is
// completed on the main thread.
TEST(ScrollAnimatorTest, AnimatedScrollTakeover) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  TestScrollAnimator* scroll_animator =
      MakeGarbageCollected<TestScrollAnimator>(scrollable_area,
                                               task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(2);
  // Called from userScroll, updateCompositorAnimations, then
  // takeOverCompositorAnimation (to re-register after RunningOnCompositor).
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(3);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  // Smooth scroll.
  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);
  EXPECT_TRUE(scroll_animator->HasRunningAnimation());

  // Update compositor animation.
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->SetShouldSendToCompositor(true);
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor);

  // Takeover.
  scroll_animator->TakeOverCompositorAnimation();
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kRunningOnCompositorButNeedsTakeover);

  // Animation should now be running on the main thread.
  scroll_animator->SetShouldSendToCompositor(false);
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

TEST(ScrollAnimatorTest, Disabled) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          false, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(8);
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(0);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPage,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByDocument,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPixel,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

// Test that cancelling an animation resets the animation state.
// See crbug.com/598548.
TEST(ScrollAnimatorTest, CancellingAnimationResetsState) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  // Called from first userScroll, setCurrentOffset, and second userScroll.
  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(3);
  // Called from userScroll, updateCompositorAnimations.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(4);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_EQ(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  // WaitingToSendToCompositor
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // RunningOnMainThread
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);

  // Amount scrolled so far.
  float offset_x = scroll_animator->CurrentOffset().x();

  // Interrupt user scroll.
  scroll_animator->CancelAnimation();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  // Another userScroll after modified scroll offset.
  scroll_animator->SetCurrentOffset(ScrollOffset(offset_x + 15, 0));
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // Finish scroll animation.
  task_runner->FastForwardBy(base::Seconds(1));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  EXPECT_EQ(offset_x + 15 + 10, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

// Test that the callback passed to UserScroll function will be run when the
// animation is canceled or finished when the scroll is sent to main thread.
TEST(ScrollAnimatorTest, UserScrollCallBackAtAnimationFinishOnMainThread) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  // Called from first userScroll, setCurrentOffset, and second userScroll.
  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(3);
  // Called from userScroll, updateCompositorAnimations.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(4);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_EQ(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  // WaitingToSendToCompositor
  bool finished = false;
  scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(10, 0),
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  EXPECT_FALSE(finished);
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendTo
### 提示词
```
这是目录为blink/renderer/core/scroll/scroll_animator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

// Tests for the ScrollAnimator class.

#include "third_party/blink/renderer/core/scroll/scroll_animator.h"

#include "base/task/single_thread_task_runner.h"
#include "base/test/test_mock_time_task_runner.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

using testing::AtLeast;
using testing::Return;
using testing::_;

namespace {

base::TimeTicks NowTicksInSeconds(
    const base::TestMockTimeTaskRunner* task_runner) {
  return task_runner->NowTicks();
}

}  // namespace

class MockScrollableAreaForAnimatorTest
    : public GarbageCollected<MockScrollableAreaForAnimatorTest>,
      public ScrollableArea {
 public:
  explicit MockScrollableAreaForAnimatorTest(bool scroll_animator_enabled,
                                             const ScrollOffset& min_offset,
                                             const ScrollOffset& max_offset)
      : ScrollableArea(blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        scroll_animator_enabled_(scroll_animator_enabled),
        min_offset_(min_offset),
        max_offset_(max_offset) {}

  MOCK_CONST_METHOD0(IsActive, bool());
  MOCK_CONST_METHOD0(IsThrottled, bool());
  MOCK_CONST_METHOD1(ScrollSize, int(ScrollbarOrientation));
  MOCK_CONST_METHOD0(IsScrollCornerVisible, bool());
  MOCK_CONST_METHOD0(ScrollCornerRect, gfx::Rect());
  MOCK_METHOD2(UpdateScrollOffset,
               void(const ScrollOffset&, mojom::blink::ScrollType));
  MOCK_METHOD0(ScrollControlWasSetNeedsPaintInvalidation, void());
  MOCK_CONST_METHOD0(EnclosingScrollableArea, ScrollableArea*());
  MOCK_CONST_METHOD1(VisibleContentRect, gfx::Rect(IncludeScrollbarsInRect));
  MOCK_CONST_METHOD0(ContentsSize, gfx::Size());
  MOCK_CONST_METHOD0(ScrollbarsCanBeActive, bool());
  MOCK_METHOD0(RegisterForAnimation, void());
  MOCK_METHOD0(ScheduleAnimation, bool());
  MOCK_CONST_METHOD0(UsedColorSchemeScrollbars, mojom::blink::ColorScheme());

  bool UsesCompositedScrolling() const override { NOTREACHED(); }
  PhysicalOffset LocalToScrollOriginOffset() const override { return {}; }
  bool UserInputScrollable(ScrollbarOrientation) const override { return true; }
  bool ShouldPlaceVerticalScrollbarOnLeft() const override { return false; }
  gfx::Vector2d ScrollOffsetInt() const override { return gfx::Vector2d(); }
  int VisibleHeight() const override { return 768; }
  int VisibleWidth() const override { return 1024; }
  CompositorElementId GetScrollElementId() const override {
    return CompositorElementId();
  }
  bool ScrollAnimatorEnabled() const override {
    return scroll_animator_enabled_;
  }
  int PageStep(ScrollbarOrientation) const override { return 0; }
  gfx::Vector2d MinimumScrollOffsetInt() const override {
    return gfx::ToFlooredVector2d(min_offset_);
  }
  gfx::Vector2d MaximumScrollOffsetInt() const override {
    return gfx::ToFlooredVector2d(max_offset_);
  }

  void SetScrollAnimator(ScrollAnimator* scroll_animator) {
    animator = scroll_animator;
  }

  ScrollOffset GetScrollOffset() const override {
    if (animator)
      return animator->CurrentOffset();
    return ScrollOffsetInt();
  }

  bool SetScrollOffset(const ScrollOffset& offset,
                       mojom::blink::ScrollType type,
                       mojom::blink::ScrollBehavior behavior =
                           mojom::blink::ScrollBehavior::kInstant,
                       ScrollCallback on_finish = ScrollCallback()) override {
    if (animator)
      animator->SetCurrentOffset(offset);
    return ScrollableArea::SetScrollOffset(offset, type, behavior,
                                           std::move(on_finish));
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTimerTaskRunner() const final {
    if (!timer_task_runner_) {
      timer_task_runner_ =
          blink::scheduler::GetSingleThreadTaskRunnerForTesting();
    }
    return timer_task_runner_;
  }

  ScrollbarTheme& GetPageScrollbarTheme() const override {
    return ScrollbarTheme::GetTheme();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(animator);
    ScrollableArea::Trace(visitor);
  }

  void DisposeImpl() override { timer_task_runner_.reset(); }

 private:
  bool scroll_animator_enabled_;
  ScrollOffset min_offset_;
  ScrollOffset max_offset_;
  Member<ScrollAnimator> animator;
  mutable scoped_refptr<base::SingleThreadTaskRunner> timer_task_runner_;
};

class TestScrollAnimator : public ScrollAnimator {
 public:
  TestScrollAnimator(ScrollableArea* scrollable_area,
                     const base::TickClock* tick_clock)
      : ScrollAnimator(scrollable_area, tick_clock) {}
  ~TestScrollAnimator() override = default;

  void SetShouldSendToCompositor(bool send) {
    should_send_to_compositor_ = send;
  }

  bool SendAnimationToCompositor() override {
    if (should_send_to_compositor_) {
      run_state_ =
          ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor;
      compositor_animation_id_ = 1;
      return true;
    }
    return false;
  }

 protected:
  void AbortAnimation() override {}

 private:
  bool should_send_to_compositor_ = false;
};

static void Reset(ScrollAnimator& scroll_animator) {
  scroll_animator.ScrollToOffsetWithoutAnimation(ScrollOffset());
}

// TODO(skobes): Add unit tests for composited scrolling paths.

TEST(ScrollAnimatorTest, MainThreadStates) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(2);
  // Once from userScroll, once from updateCompositorAnimations.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(2);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  // Idle
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::kIdle);

  // WaitingToSendToCompositor
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // RunningOnMainThread
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);

  // PostAnimationCleanup
  scroll_animator->CancelAnimation();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  // Idle
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::kIdle);

  Reset(*scroll_animator);

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

TEST(ScrollAnimatorTest, MainThreadEnabled) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(9);
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(6);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(-100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_FALSE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(-100.0f, result.unused_scroll_delta_x);

  result = scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                                       ScrollOffset(100, 0),
                                       ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPage,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPixel,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  task_runner->FastForwardBy(base::Seconds(1.0));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());

  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

// Test that a smooth scroll offset animation is aborted when followed by a
// non-smooth scroll offset animation.
TEST(ScrollAnimatorTest, AnimatedScrollAborted) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(3);
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(2);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  // Smooth scroll.
  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);
  EXPECT_TRUE(scroll_animator->HasRunningAnimation());

  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  float x = scroll_animator->CurrentOffset().x();

  // Instant scroll.
  result = scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPrecisePixel,
                                       ScrollOffset(100, 0),
                                       ScrollableArea::ScrollCallback());
  EXPECT_TRUE(result.did_scroll_x);
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_FALSE(scroll_animator->HasRunningAnimation());
  EXPECT_EQ(x + 100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  Reset(*scroll_animator);
}

// Test that a smooth scroll offset animation running on the compositor is
// completed on the main thread.
TEST(ScrollAnimatorTest, AnimatedScrollTakeover) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  TestScrollAnimator* scroll_animator =
      MakeGarbageCollected<TestScrollAnimator>(scrollable_area,
                                               task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(2);
  // Called from userScroll, updateCompositorAnimations, then
  // takeOverCompositorAnimation (to re-register after RunningOnCompositor).
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(3);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  // Smooth scroll.
  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);
  EXPECT_TRUE(scroll_animator->HasRunningAnimation());

  // Update compositor animation.
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->SetShouldSendToCompositor(true);
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor);

  // Takeover.
  scroll_animator->TakeOverCompositorAnimation();
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kRunningOnCompositorButNeedsTakeover);

  // Animation should now be running on the main thread.
  scroll_animator->SetShouldSendToCompositor(false);
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_NE(100, scroll_animator->CurrentOffset().x());
  EXPECT_NE(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

TEST(ScrollAnimatorTest, Disabled) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          false, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(8);
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(0);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPage,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByDocument,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByPixel,
                              ScrollOffset(100, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(100, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

// Test that cancelling an animation resets the animation state.
// See crbug.com/598548.
TEST(ScrollAnimatorTest, CancellingAnimationResetsState) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  // Called from first userScroll, setCurrentOffset, and second userScroll.
  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(3);
  // Called from userScroll, updateCompositorAnimations.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(4);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_EQ(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  // WaitingToSendToCompositor
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // RunningOnMainThread
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);

  // Amount scrolled so far.
  float offset_x = scroll_animator->CurrentOffset().x();

  // Interrupt user scroll.
  scroll_animator->CancelAnimation();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  // Another userScroll after modified scroll offset.
  scroll_animator->SetCurrentOffset(ScrollOffset(offset_x + 15, 0));
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // Finish scroll animation.
  task_runner->FastForwardBy(base::Seconds(1));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  EXPECT_EQ(offset_x + 15 + 10, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);
}

// Test that the callback passed to UserScroll function will be run when the
// animation is canceled or finished when the scroll is sent to main thread.
TEST(ScrollAnimatorTest, UserScrollCallBackAtAnimationFinishOnMainThread) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  ScrollAnimator* scroll_animator = MakeGarbageCollected<ScrollAnimator>(
      scrollable_area, task_runner->GetMockTickClock());

  // Called from first userScroll, setCurrentOffset, and second userScroll.
  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(3);
  // Called from userScroll, updateCompositorAnimations.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(4);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_EQ(0, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());

  // WaitingToSendToCompositor
  bool finished = false;
  scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(10, 0),
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  EXPECT_FALSE(finished);
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // RunningOnMainThread
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_FALSE(finished);
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnMainThread);
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));

  // Amount scrolled so far.
  float offset_x = scroll_animator->CurrentOffset().x();

  // Interrupt user scroll.
  scroll_animator->CancelAnimation();
  EXPECT_TRUE(finished);
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);

  // Another userScroll after modified scroll offset.
  scroll_animator->SetCurrentOffset(ScrollOffset(offset_x + 15, 0));
  scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                              ScrollOffset(10, 0),
                              ScrollableArea::ScrollCallback());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // Finish scroll animation.
  task_runner->FastForwardBy(base::Seconds(1.0));
  scroll_animator->UpdateCompositorAnimations();
  scroll_animator->TickAnimation(NowTicksInSeconds(task_runner.get()));
  EXPECT_TRUE(finished);
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kPostAnimationCleanup);
  EXPECT_EQ(offset_x + 15 + 10, scroll_animator->CurrentOffset().x());
  EXPECT_EQ(0, scroll_animator->CurrentOffset().y());
  Reset(*scroll_animator);

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

// Test that the callback passed to UserScroll function will be run when the
// animation is canceled or finished when the scroll is sent to compositor.
TEST(ScrollAnimatorTest, UserScrollCallBackAtAnimationFinishOnCompositor) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  TestScrollAnimator* scroll_animator =
      MakeGarbageCollected<TestScrollAnimator>(scrollable_area,
                                               task_runner->GetMockTickClock());

  // Called from userScroll, and first update.
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  // First user scroll.
  bool finished = false;
  scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 0),
      ScrollableArea::ScrollCallback(WTF::BindOnce(
          [](bool* finished, ScrollableArea::ScrollCompletionMode) {
            *finished = true;
          },
          WTF::Unretained(&finished))));
  EXPECT_FALSE(finished);
  EXPECT_TRUE(scroll_animator->HasRunningAnimation());
  EXPECT_EQ(100, scroll_animator->DesiredTargetOffset().x());
  EXPECT_EQ(0, scroll_animator->DesiredTargetOffset().y());
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToSendToCompositor);

  // Update compositor animation.
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->SetShouldSendToCompositor(true);
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_FALSE(finished);
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor);

  // Cancel
  scroll_animator->CancelAnimation();
  EXPECT_TRUE(finished);
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToCancelOnCompositor);

  // Forced GC in order to finalize objects depending on the mock object.
  ThreadState::Current()->CollectAllGarbageForTesting();
}

// Test the behavior when in WaitingToCancelOnCompositor and a new user scroll
// happens.
TEST(ScrollAnimatorTest, CancellingCompositorAnimation) {
  test::TaskEnvironment task_environment;
  auto* scrollable_area =
      MakeGarbageCollected<MockScrollableAreaForAnimatorTest>(
          true, ScrollOffset(), ScrollOffset(1000, 1000));
  scoped_refptr<base::TestMockTimeTaskRunner> task_runner =
      base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  TestScrollAnimator* scroll_animator =
      MakeGarbageCollected<TestScrollAnimator>(scrollable_area,
                                               task_runner->GetMockTickClock());

  // Called when reset, not setting anywhere else.
  EXPECT_CALL(*scrollable_area, UpdateScrollOffset(_, _)).Times(1);
  // Called from userScroll, and first update.
  EXPECT_CALL(*scrollable_area, RegisterForAnimation()).Times(4);
  EXPECT_CALL(*scrollable_area, ScheduleAnimation())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(scroll_animator->HasAnimationThatRequiresService());

  // First user scroll.
  ScrollResult result = scroll_animator->UserScroll(
      ui::ScrollGranularity::kScrollByLine, ScrollOffset(100, 0),
      ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);
  EXPECT_TRUE(scroll_animator->HasRunningAnimation());
  EXPECT_EQ(100, scroll_animator->DesiredTargetOffset().x());
  EXPECT_EQ(0, scroll_animator->DesiredTargetOffset().y());

  // Update compositor animation.
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->SetShouldSendToCompositor(true);
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor);

  // Cancel
  scroll_animator->CancelAnimation();
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToCancelOnCompositor);

  // Unrelated scroll offset update.
  scroll_animator->SetCurrentOffset(ScrollOffset(50, 0));

  // Desired target offset should be that of the second scroll.
  result = scroll_animator->UserScroll(ui::ScrollGranularity::kScrollByLine,
                                       ScrollOffset(100, 0),
                                       ScrollableArea::ScrollCallback());
  EXPECT_TRUE(scroll_animator->HasAnimationThatRequiresService());
  EXPECT_TRUE(result.did_scroll_x);
  EXPECT_FLOAT_EQ(0.0, result.unused_scroll_delta_x);
  EXPECT_EQ(scroll_animator->run_state_,
            ScrollAnimatorCompositorCoordinator::RunState::
                kWaitingToCancelOnCompositorButNewScroll);
  EXPECT_EQ(150, scroll_animator->DesiredTargetOffset().x());
  EXPECT_EQ(0, scroll_animator->DesiredTargetOffset().y());

  // Update compositor animation.
  task_runner->FastForwardBy(base::Milliseconds(50));
  scroll_animator->UpdateCompositorAnimations();
  EXPECT_EQ(
      scroll_animator->run_state_,
      ScrollAnimatorCompositorCoordinator::RunState::kRunningOnCompositor);

  // Third user scroll after compositor update updates the target.
  result = sc
```
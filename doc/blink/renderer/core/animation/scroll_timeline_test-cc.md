Response:
The user wants to understand the functionality of the `scroll_timeline_test.cc` file in the Chromium Blink engine. This file is a C++ test suite for the `ScrollTimeline` feature. To answer the user's request, I need to:

1. **Identify the core purpose:** The file tests the behavior of `ScrollTimeline` and related classes.
2. **Explain its relationship to web technologies:**  `ScrollTimeline` is a Web Animations API feature that allows synchronizing animations with the scroll position of an element. This directly relates to JavaScript, HTML, and CSS.
3. **Provide illustrative examples:**  Show how the tests connect to real-world web development scenarios.
4. **Infer test logic (if possible):** While I don't have the full test implementation yet, I can analyze the test names and code snippets provided to understand the tested scenarios.
5. **Highlight potential user/developer errors:** Based on the tested functionalities, I can infer common mistakes.
6. **Summarize the file's functionality based on the first part.**
这是 Blink 渲染引擎中 `blink/renderer/core/animation/scroll_timeline_test.cc` 文件的第一部分。它是一个 C++ 单元测试文件，专门用于测试 `ScrollTimeline` 和相关类的功能。

**主要功能归纳：**

这个文件的主要功能是验证 `ScrollTimeline` 及其相关组件在 Blink 引擎中的正确性和预期行为。  `ScrollTimeline` 允许开发者创建与特定元素滚动位置同步的动画。  因此，这个测试文件涵盖了与 `ScrollTimeline` 创建、激活、更新、销毁以及与普通 `Animation` 对象交互相关的各种场景。

**与 JavaScript, HTML, CSS 的关系以及举例说明：**

`ScrollTimeline` 是 Web Animations API 的一部分，因此它与 JavaScript, HTML, 和 CSS 都有着密切的联系：

* **JavaScript:**  开发者主要通过 JavaScript 来创建和控制 `ScrollTimeline` 对象，并将其关联到 `Animation` 对象上。
    * **例子：**  在 JavaScript 中，你可以创建一个 `ScrollTimeline` 对象，指定一个 HTML 元素作为滚动源，然后将这个时间线赋给一个动画的 `timeline` 属性。这样，动画的播放进度就会和滚动元素的滚动位置关联起来。

* **HTML:**  `ScrollTimeline` 需要关联到一个具体的 HTML 元素作为滚动源。测试文件中可以看到，经常会通过 `SetBodyInnerHTML` 来创建包含特定 HTML 结构的测试环境，例如带有 `overflow: scroll` 属性的 `div` 元素，使其成为可滚动的容器。
    * **例子：** HTML 中一个 `div` 元素可能被赋予 `overflow: scroll` 样式，使其内容溢出时可以滚动。这个 `div` 可以作为 `ScrollTimeline` 的 `source`。

* **CSS:**  虽然 `ScrollTimeline` 本身不是 CSS 属性，但它影响着动画的播放，而动画经常用于改变元素的 CSS 属性。
    * **例子：**  你可以创建一个 CSS 动画，让一个元素的透明度从 0 变化到 1。然后，通过 JavaScript 将这个动画的时间线设置为一个 `ScrollTimeline`，关联到一个滚动容器。这样，当滚动容器滚动时，元素的透明度会相应地变化。

**逻辑推理的假设输入与输出：**

虽然我们只看到了文件的前半部分，但可以根据测试用例的命名和代码片段推断一些测试逻辑：

* **假设输入：**  创建一个 `ScrollTimeline` 对象，指定不同的 HTML 元素作为滚动源（例如，可滚动的 div，文档的滚动元素）。
* **预期输出：**
    * 当滚动源不可滚动时，`ScrollTimeline` 的 `currentTime` 应该为 null。
    * 当滚动源是文档的滚动元素时，`ResolvedSource()` 应该正确返回 `Document` 对象。
    * 当滚动源被移除时，关联的动画应该被垃圾回收。
    * 当滚动容器滚动时，关联的动画的当前时间应该根据滚动位置正确更新。
    * 当滚动容器的 `overflow` 属性改变导致其不再可滚动时，`ScrollTimeline` 的 `currentTime` 应该变为未定义。

* **假设输入：**  创建一个 `Animation` 对象，将其关联到一个 `ScrollTimeline`，然后操作滚动容器的滚动位置。
* **预期输出：**
    * 动画的播放状态（例如 `running`, `finished`）应该根据滚动位置和动画的定义正确变化。
    * 当动画完成时，即使滚动位置反向，动画对象仍然应该存在，并且在再次滚动到完成状态时可以触发 `finish` 事件。

**涉及用户或者编程常见的使用错误以及举例说明：**

根据测试用例和 `ScrollTimeline` 的工作原理，可以推测一些常见的用户或编程错误：

* **错误地将不可滚动的元素作为 `ScrollTimeline` 的 `source`：**  如果指定的 HTML 元素没有设置 `overflow: scroll` 或 `overflow: auto` 等属性，它将不是一个可滚动的容器。此时，`ScrollTimeline` 将不会正常工作，`currentTime` 会是未定义的。
    * **例子：**  在 JavaScript 中创建 `ScrollTimeline` 时，错误地将一个普通的 `div` 元素（没有设置滚动）作为 `source`。

* **在滚动源被移除后，没有清理对 `ScrollTimeline` 或 `Animation` 的引用：**  虽然 Blink 有垃圾回收机制，但在某些复杂的场景下，如果开发者没有正确管理对象的生命周期，可能会导致内存泄漏。
    * **例子：**  在 JavaScript 中创建了一个关联到某个滚动容器的 `ScrollTimeline` 和 `Animation`，然后在 JavaScript 中移除了该滚动容器的 DOM 节点，但仍然持有对 `ScrollTimeline` 或 `Animation` 的引用。

* **期望 `ScrollTimeline` 在非预期的时机更新：**  `ScrollTimeline` 的更新通常发生在动画帧 (animation frame) 的开始或者当关联的滚动源的滚动位置发生变化时。开发者可能会错误地期望 `currentTime` 在每次滚动偏移量改变后立即同步更新。
    * **例子：**  在 JavaScript 中设置了滚动偏移量后，立即读取 `ScrollTimeline` 的 `currentTime`，期望得到最新的值，但实际上可能需要在下一个动画帧才能反映出来。

总体来说，`scroll_timeline_test.cc` 文件的这部分着重测试了 `ScrollTimeline` 的基本功能、生命周期管理、与滚动行为的联动，以及在不同场景下的正确性。这对于确保 Web Animations API 中 `ScrollTimeline` 功能的稳定性和可靠性至关重要。

### 提示词
```
这是目录为blink/renderer/core/animation/scroll_timeline_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/scroll_timeline.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_animation_play_state.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_timeline_options.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/animation_test_helpers.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/timing_calculations.h"
#include "third_party/blink/renderer/core/animation/view_timeline.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

namespace blink {

namespace {

static constexpr double percent_precision = 0.01;

#define EXPECT_CURRENT_TIME_AS_PERCENT_NEAR(expected, animation)          \
  EXPECT_NEAR(expected,                                                   \
              (animation->CurrentTimeInternal()->InMillisecondsF() /      \
               animation->timeline()->GetDuration()->InMillisecondsF()) * \
                  100,                                                    \
              percent_precision);

Animation* CreateTestAnimation(AnimationTimeline* timeline) {
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(0.1);
  return Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                               nullptr,
                               MakeGarbageCollected<StringKeyframeEffectModel>(
                                   StringKeyframeVector()),
                               timing),
                           timeline, ASSERT_NO_EXCEPTION);
}

Animation* CreateCompositableTestAnimation(Element* target,
                                           AnimationTimeline* timeline) {
  KeyframeEffect* effect =
      animation_test_helpers::CreateSimpleKeyframeEffectForTest(
          target, CSSPropertyID::kTranslate, "50px", "100px");
  effect->Model()->SnapshotAllCompositorKeyframesIfNecessary(
      *target, target->GetDocument().GetStyleResolver().InitialStyle(),
      /* parent_style */ nullptr);
  return MakeGarbageCollected<Animation>(
      timeline->GetDocument()->GetExecutionContext(), timeline, effect);
}

}  // namespace

class ScrollTimelineTest : public RenderingTest {
  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
  }

 public:
  void SimulateFrame() {
    // Advance time by 100 ms.
    auto new_time = GetAnimationClock().CurrentTime() + base::Milliseconds(100);
    GetPage().Animator().ServiceScriptedAnimations(new_time);
  }

  wtf_size_t TimelinesCount() const {
    return GetDocument()
        .GetDocumentAnimations()
        .GetTimelinesForTesting()
        .size();
  }

  wtf_size_t AnimationsCount() const {
    wtf_size_t count = 0;
    for (auto timeline :
         GetDocument().GetDocumentAnimations().GetTimelinesForTesting()) {
      count += timeline->GetAnimations().size();
    }
    return count;
  }
};

class TestScrollTimeline : public ScrollTimeline {
 public:
  TestScrollTimeline(Document* document, Element* source, bool snapshot = true)
      : ScrollTimeline(document,
                       ScrollTimeline::ReferenceType::kSource,
                       source,
                       ScrollAxis::kY) {
    if (snapshot) {
      UpdateSnapshot();
    }
  }

  void Trace(Visitor* visitor) const override {
    ScrollTimeline::Trace(visitor);
  }

  // UpdateSnapshot has 'protected' visibility.
  void UpdateSnapshotForTesting() { UpdateSnapshot(); }

  AnimationTimeDelta CalculateIntrinsicIterationDurationForTest(
      const std::optional<TimelineOffset>& range_start,
      const std::optional<TimelineOffset>& range_end) {
    Timing timing;
    timing.iteration_count = 1;
    TimelineRange timeline_range = GetTimelineRange();
    return CalculateIntrinsicIterationDuration(timeline_range, range_start,
                                               range_end, timing);
  }
};

class TestViewTimeline : public ViewTimeline {
 public:
  TestViewTimeline(Document* document, Element* subject, bool snapshot = true)
      : ViewTimeline(document, subject, ScrollAxis::kY, TimelineInset()) {
    if (snapshot) {
      UpdateSnapshot();
    }
  }

  void UpdateSnapshotForTesting() { UpdateSnapshot(); }
};

class TestDeferredTimeline : public DeferredTimeline {
 public:
  explicit TestDeferredTimeline(Document* document, bool snapshot = true)
      : DeferredTimeline(document) {
    if (snapshot) {
      UpdateSnapshot();
    }
  }
};

TEST_F(ScrollTimelineTest, CurrentTimeIsNullIfSourceIsNotScrollable) {
  SetBodyInnerHTML(R"HTML(
    <style>#scroller { width: 100px; height: 100px; }</style>
    <div id='scroller'></div>
  )HTML");

  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  ASSERT_TRUE(scroller);

  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  EXPECT_FALSE(scroll_timeline->CurrentTimeSeconds().has_value());
  EXPECT_FALSE(scroll_timeline->IsActive());
}

TEST_F(ScrollTimelineTest,
       UsingDocumentScrollingElementShouldCorrectlyResolveToDocument) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #content { width: 10000px; height: 10000px; }
    </style>
    <div id='content'></div>
  )HTML");

  EXPECT_EQ(GetDocument().documentElement(), GetDocument().scrollingElement());
  // Create the ScrollTimeline with Document.scrollingElement() as source. The
  // resolved scroll source should be the Document.
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetDocument().scrollingElement());
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);
  EXPECT_EQ(&GetDocument(), scroll_timeline->ResolvedSource());
}

TEST_F(ScrollTimelineTest,
       ChangingDocumentScrollingElementShouldNotImpactScrollTimeline) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #body { overflow: scroll; width: 100px; height: 100px; }
      #content { width: 10000px; height: 10000px; }
    </style>
    <div id='content'></div>
  )HTML");

  // In QuirksMode, the body is the scrolling element
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  EXPECT_EQ(GetDocument().body(), GetDocument().scrollingElement());

  // Create the ScrollTimeline with Document.scrollingElement() as source. The
  // resolved scroll source should be the Document.
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetDocument().scrollingElement());
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);
  EXPECT_EQ(&GetDocument(), scroll_timeline->ResolvedSource());

  // Now change the Document.scrollingElement(). In NoQuirksMode, the
  // documentElement is the scrolling element and not the body.
  GetDocument().SetCompatibilityMode(Document::kNoQuirksMode);
  EXPECT_NE(GetDocument().documentElement(), GetDocument().body());
  EXPECT_EQ(GetDocument().documentElement(), GetDocument().scrollingElement());

  // Changing the scrollingElement should not impact the previously resolved
  // scroll source. Note that at this point the scroll timeline's scroll source
  // is still body element which is no longer the scrolling element. So if we
  // were to re-resolve the scroll source, it would not map to Document.
  EXPECT_EQ(&GetDocument(), scroll_timeline->ResolvedSource());
}

TEST_F(ScrollTimelineTest, AttachOrDetachAnimationWithNullSource) {
  // Directly call the constructor to make it easier to pass a null
  // source. The alternative approach would require us to remove the
  // documentElement from the document.
  Element* scroll_source = nullptr;
  Persistent<ScrollTimeline> scroll_timeline = ScrollTimeline::Create(
      &GetDocument(), scroll_source, ScrollTimeline::ScrollAxis::kBlock);

  // Sanity checks.
  ASSERT_EQ(scroll_timeline->source(), nullptr);
  ASSERT_EQ(scroll_timeline->ResolvedSource(), nullptr);

  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);
  Animation* animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  EXPECT_EQ(1u, scroll_timeline->GetAnimations().size());
  EXPECT_TRUE(scroll_timeline->GetAnimations().Contains(animation));

  animation = nullptr;
  scroll_timeline = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, AnimationsCount());
}

TEST_F(ScrollTimelineTest, AnimationIsGarbageCollectedWhenScrollerIsRemoved) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");

  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               GetElementById("scroller"));
  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);
  Animation* animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  animation->play();
  UpdateAllLifecyclePhasesForTest();

  animation->finish();
  animation = nullptr;
  scroll_timeline = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  // Scroller is alive, animation is not GC'ed.
  EXPECT_EQ(1u, AnimationsCount());

  GetElementById("scroller")->remove();
  UpdateAllLifecyclePhasesForTest();
  ThreadState::Current()->CollectAllGarbageForTesting();
  // Scroller is removed and unreachable, animation is GC'ed.
  EXPECT_EQ(0u, AnimationsCount());
}

TEST_F(ScrollTimelineTest, AnimationPersistsWhenFinished) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");

  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  Persistent<TestScrollTimeline> scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               GetElementById("scroller"));
  Animation* animation = CreateTestAnimation(scroll_timeline);
  animation->play();
  animation->SetDeferredStartTimeForTesting();
  SimulateFrame();

  // Scroll to finished:
  scrollable_area->SetScrollOffset(ScrollOffset(0, 100),
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());

  // Animation should still persist after GC.
  animation = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  ASSERT_EQ(1u, scroll_timeline->GetAnimations().size());
  animation = *scroll_timeline->GetAnimations().begin();

  // Scroll back to 50%. The animation should update, even though it was
  // previously in a finished state.
  ScrollOffset offset(0, 50);  // 10 + (90 - 10) * 0.5 = 50
  scrollable_area->SetScrollOffset(offset,
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_CURRENT_TIME_AS_PERCENT_NEAR(50.0, animation);
}

TEST_F(ScrollTimelineTest, AnimationPersistsWhenSourceBecomesNonScrollable) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
      .scroll { overflow: scroll; }
    </style>
    <div id='scroller' class='scroll'>
      <div id ='spacer'></div>
    </div>
  )HTML");

  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  Persistent<TestScrollTimeline> scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               GetElementById("scroller"));
  Animation* animation = CreateTestAnimation(scroll_timeline);
  animation->play();
  animation->SetDeferredStartTimeForTesting();
  SimulateFrame();

  // Scroll to 50%:
  ASSERT_TRUE(scroller->GetScrollableArea());
  ScrollOffset offset_50(0, 50);
  scroller->GetScrollableArea()->SetScrollOffset(
      offset_50, mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  EXPECT_CURRENT_TIME_AS_PERCENT_NEAR(50.0, animation);

  // Make #scroller non-scrollable.
  GetElementById("scroller")->classList().Remove(AtomicString("scroll"));
  UpdateAllLifecyclePhasesForTest();
  scroller = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  ASSERT_TRUE(scroller);
  EXPECT_FALSE(scroller->GetScrollableArea());

  // ScrollTimeline should now have an unresolved current time.
  SimulateFrame();
  EXPECT_FALSE(scroll_timeline->CurrentTimeSeconds().has_value());

  // Animation should still persist after GC.
  animation = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  ASSERT_EQ(1u, scroll_timeline->GetAnimations().size());
  animation = *scroll_timeline->GetAnimations().begin();

  // Make #scroller scrollable again.
  GetElementById("scroller")->classList().Add(AtomicString("scroll"));
  UpdateAllLifecyclePhasesForTest();
  scroller = To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  ASSERT_TRUE(scroller);
  ASSERT_TRUE(scroller->GetScrollableArea());

  // Scroll to 40%:
  ScrollOffset offset_40(0, 40);
  scroller->GetScrollableArea()->SetScrollOffset(
      offset_40, mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  EXPECT_CURRENT_TIME_AS_PERCENT_NEAR(40.0, animation);
}

TEST_F(ScrollTimelineTest, ScheduleFrameOnlyWhenScrollOffsetChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");

  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->SetScrollOffset(ScrollOffset(0, 20),
                                   mojom::blink::ScrollType::kProgrammatic);

  Element* scroller_element = GetElementById("scroller");
  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               scroller_element);

  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);
  Animation* scroll_animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  scroll_animation->play();
  UpdateAllLifecyclePhasesForTest();

  // Validate that no frame is scheduled when there is no scroll change.
  GetChromeClient().UnsetAnimationScheduled();
  GetFrame().ScheduleNextServiceForScrollSnapshotClients();
  EXPECT_FALSE(GetChromeClient().AnimationScheduled());

  // Validate that frame is scheduled when scroll changes.
  GetChromeClient().UnsetAnimationScheduled();
  scrollable_area->SetScrollOffset(ScrollOffset(0, 30),
                                   mojom::blink::ScrollType::kProgrammatic);
  GetFrame().ScheduleNextServiceForScrollSnapshotClients();
  EXPECT_TRUE(GetChromeClient().AnimationScheduled());
}

// This test verifies scenario when scroll timeline is updated as a result of
// layout run. In this case the expectation is that at the end of paint
// lifecycle phase scroll timeline schedules a new frame that runs animations
// update.
TEST_F(ScrollTimelineTest, ScheduleFrameWhenScrollerLayoutChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");
  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->SetScrollOffset(ScrollOffset(0, 20),
                                   mojom::blink::ScrollType::kProgrammatic);
  Element* scroller_element = GetElementById("scroller");

  // Use empty offsets as 'auto'.
  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               scroller_element);
  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);
  Animation* scroll_animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  scroll_animation->play();
  UpdateAllLifecyclePhasesForTest();
  // Validate that frame is scheduled when scroller layout changes that causes
  // current time to change. Here we change the scroller max offset which
  // affects current time because endScrollOffset is 'auto'.
  Element* spacer_element = GetElementById("spacer");
  spacer_element->setAttribute(html_names::kStyleAttr,
                               AtomicString("height:1000px;"));
  GetChromeClient().UnsetAnimationScheduled();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetChromeClient().AnimationScheduled());

  // Also test changing the scroller height, which also affect the max offset.
  GetElementById("scroller")
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  GetChromeClient().UnsetAnimationScheduled();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetChromeClient().AnimationScheduled());
}

TEST_F(ScrollTimelineTest,
       TimelineInvalidationWhenScrollerDisplayPropertyChanges) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");
  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->SetScrollOffset(ScrollOffset(0, 20),
                                   mojom::blink::ScrollType::kProgrammatic);
  Element* scroller_element = GetElementById("scroller");

  // Use empty offsets as 'auto'.
  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               scroller_element);
  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);
  Animation* scroll_animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  scroll_animation->play();
  UpdateAllLifecyclePhasesForTest();

  scroller_element->setAttribute(html_names::kStyleAttr,
                                 AtomicString("display:table-cell;"));
  GetChromeClient().UnsetAnimationScheduled();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(GetChromeClient().AnimationScheduled());
}

// Verify that scroll timeline current time is updated once upon construction
// and at the top of every animation frame.
TEST_F(ScrollTimelineTest, CurrentTimeUpdateAfterNewAnimationFrame) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { height: 1000px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");

  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  ASSERT_TRUE(scroller);
  ASSERT_TRUE(scroller->IsScrollContainer());
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  ASSERT_TRUE(scrollable_area);
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));

  scrollable_area->SetScrollOffset(ScrollOffset(0, 5),
                                   mojom::blink::ScrollType::kProgrammatic);

  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  double time_before = scroll_timeline->CurrentTimeSeconds().value();

  scrollable_area->SetScrollOffset(ScrollOffset(0, 10),
                                   mojom::blink::ScrollType::kProgrammatic);
  // Verify that the current time didn't change before there is a new animation
  // frame.
  EXPECT_EQ(time_before, scroll_timeline->CurrentTimeSeconds().value());

  // Simulate a new animation frame  which allows the timeline to compute a new
  // current time.
  SimulateFrame();

  // Verify that current time did change in the new animation frame.
  EXPECT_NE(time_before, scroll_timeline->CurrentTimeSeconds().value());
}

TEST_F(ScrollTimelineTest, FinishedAnimationPlaysOnReversedScrolling) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");
  Element* scroller_element = GetElementById("scroller");
  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               scroller_element);
  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(0.1);
  Animation* scroll_animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  scroll_animation->play();
  UpdateAllLifecyclePhasesForTest();

  // Scroll to finished state.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 100),
                                   mojom::blink::ScrollType::kProgrammatic);
  // Simulate a new animation frame  which allows the timeline to compute a new
  // current time.
  SimulateFrame();
  ASSERT_EQ(V8AnimationPlayState::Enum::kFinished,
            scroll_animation->playState());
  // Verify that the animation was not removed from animations needing update
  // list.
  EXPECT_EQ(1u, scroll_timeline->AnimationsNeedingUpdateCount());

  // Scroll back.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 50),
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  // Verify that the animation as back to running.
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning,
            scroll_animation->playState());
}

TEST_F(ScrollTimelineTest, CancelledAnimationDetachedFromTimeline) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");
  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               GetElementById("scroller"));
  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(0.1);
  Animation* scroll_animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  scroll_animation->play();
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(1u, scroll_timeline->AnimationsNeedingUpdateCount());

  scroll_animation->cancel();
  // Simulate a new animation frame  which allows the timeline to compute a new
  // current time.
  SimulateFrame();
  ASSERT_EQ(V8AnimationPlayState::Enum::kIdle, scroll_animation->playState());
  // Verify that the animation is removed from animations needing update
  // list.
  EXPECT_EQ(0u, scroll_timeline->AnimationsNeedingUpdateCount());
}

class AnimationEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event* event) override {
    event_received_ = true;
  }
  bool EventReceived() const { return event_received_; }
  void ResetEventReceived() { event_received_ = false; }

 private:
  bool event_received_ = false;
};

TEST_F(ScrollTimelineTest,
       FiringAnimationEventsByFinishedAnimationOnReversedScrolling) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");
  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  TestScrollTimeline* scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               GetElementById("scroller"));
  NonThrowableExceptionState exception_state;
  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(0.1);
  Animation* scroll_animation =
      Animation::Create(MakeGarbageCollected<KeyframeEffect>(
                            nullptr,
                            MakeGarbageCollected<StringKeyframeEffectModel>(
                                StringKeyframeVector()),
                            timing),
                        scroll_timeline, exception_state);
  auto* event_listener = MakeGarbageCollected<AnimationEventListener>();
  scroll_animation->addEventListener(event_type_names::kFinish, event_listener);

  scroll_animation->play();
  UpdateAllLifecyclePhasesForTest();
  // Scroll to finished state.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 100),
                                   mojom::blink::ScrollType::kProgrammatic);
  // Simulate a new animation frame  which allows the timeline to compute a new
  // current time.
  SimulateFrame();
  ASSERT_TRUE(event_listener->EventReceived());
  event_listener->ResetEventReceived();

  // Verify finished event does not re-fire.
  SimulateFrame();
  EXPECT_FALSE(event_listener->EventReceived());

  // Scroll back.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 80),
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  // Verify finished event is not fired on reverse scroll from finished state.
  EXPECT_FALSE(event_listener->EventReceived());

  // Scroll forward to finished state.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 100),
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  // Verify animation finished event is fired.
  EXPECT_TRUE(event_listener->EventReceived());
  event_listener->ResetEventReceived();

  scrollable_area->SetScrollOffset(ScrollOffset(0, 95),
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrame();
  // Verify animation finished event is fired only once in finished state.
  EXPECT_FALSE(event_listener->EventReceived());
}

TEST_F(ScrollTimelineTest, WeakReferences) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      #spacer { width: 200px; height: 200px; }
    </style>
    <div id='scroller'>
      <div id ='spacer'></div>
    </div>
  )HTML");

  Persistent<TestScrollTimeline> scroll_timeline =
      MakeGarbageCollected<TestScrollTimeline>(&GetDocument(),
                                               GetElementById("scroller"));

  EXPECT_EQ(0u, scroll_timeline->GetAnimations().size());

  // Attaching an animation to a ScrollTimeline, and never playing it:
  Animation* animation = CreateTestAnimation(scroll_timeline);
  DCHECK(animation);
  animation = nullptr;
  EXPECT_EQ(1u, scroll_timeline->GetAnimations().size());

  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, scroll_timeline->GetAnimations().size());

  // Playing, then canceling an animation:
  animation = CreateTestAnimation(scroll_timeline);
  EXPECT_EQ(1u, scroll_timeline->GetAnimations().size());

  animation->play();
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, scroll_timeline->GetAnimations().size());

  animation->cancel();
  // UpdateAllLifecyclePhasesForTest does not call Animation::Update with
  // reason=kTimingUpdateForAnimationFrame, which is required in order to lose
  // all strong references to the animation. Hence the explicit call to
  // SimulateFrame().
  SimulateFrame();
  UpdateAllLifecyclePhasesForTest();
  animation = nullptr;

  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_EQ(0u, scroll_timeline->GetAnimations().size());
}

TEST_F(ScrollTimelineTest, WeakViewTimelines) {
  SetBodyInnerHTML(R"HTML(
    <div id='scroller'>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
      <div></div>
    </div>
  )HTML");

  wtf_size_t base_count = TimelinesCount();

  StaticElementList* list =
      GetDocument().QuerySelectorAll(AtomicString("#scroller > div"));
  ASSERT_TRUE(list);
  EXPECT_EQ(10u, list->length());

  HeapVector<Member<Animation>> animations;

  for (wtf_size_t i = 0; i < list->length(); ++i) {
    Element* element = list->item(i);
    Animation* animation = CreateTestAnimation(
        MakeGarbageCollected<TestViewTimeline>(&GetDocument(), element));
    ani
```
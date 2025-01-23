Response:
The user wants me to analyze the provided C++ code snippet from the Chromium Blink engine, specifically the `animation_test.cc` file. I need to identify its functionality and relate it to web technologies like JavaScript, HTML, and CSS. If the code demonstrates logical reasoning, I should provide examples with inputs and outputs. I also need to point out potential user or programming errors. Finally, for this first part of the file, I need to summarize its main purpose.

Here's a breakdown of the tasks:

1. **Functionality Listing:** Describe what the code does. This involves looking at the included headers and the test cases within the provided snippet.
2. **Relationship to Web Technologies:** Explain how the code relates to JavaScript, HTML, and CSS. This likely involves how animations are defined and controlled in these technologies and how the C++ code implements the underlying logic.
3. **Logical Reasoning Examples:** If the code demonstrates conditional logic or calculations, I need to create hypothetical scenarios with inputs and expected outputs.
4. **Common Errors:** Identify potential mistakes users or developers might make when working with animations, as suggested by the test cases.
5. **Part 1 Summary:**  Provide a concise overview of the functionality covered in this initial part of the file.
这是 Chromium Blink 引擎中 `blink/renderer/core/animation/animation_test.cc` 文件的一部分，它主要的功能是 **测试 `blink::Animation` 类的各种功能和状态转换**。

更具体地说，从提供的代码片段来看，它测试了以下方面的功能：

**1. 动画的基本生命周期和状态管理：**

*   **初始化状态：** 测试动画创建时的初始状态，例如当前时间、播放状态、播放速率、是否挂起等。
*   **当前时间 (currentTime)：**  测试设置和获取动画的当前时间，包括正值、负值和超出动画持续时间范围的值，以及对动画状态的影响。
*   **开始时间 (startTime)：** 测试设置和获取动画的开始时间，以及它如何影响动画的播放。
*   **播放状态 (playState)：** 测试动画的不同播放状态，如 "running"（运行中）、"paused"（暂停）、"finished"（已完成）和 "pending"（挂起），以及状态之间的转换。
*   **播放速率 (playbackRate)：** 测试设置动画的播放速率，包括正向、反向和零速率，以及对动画播放的影响。
*   **暂停 (pause)：** 测试暂停动画的功能。
*   **播放 (play)：** 测试播放动画的功能，包括从头开始、从中间开始、以及反向播放的情况。
*   **反向 (reverse)：** 测试反转动画播放方向的功能。
*   **完成 (finish)：** 测试立即将动画跳转到结束或开始的功能，取决于当前的播放方向。

**2. 与 JavaScript, HTML, CSS 的关系：**

*   **CSS 属性动画：** 代码中使用了 `CSSPropertyID::kOpacity` 和 `StringKeyframe` 等，这表明测试与通过 CSS 属性进行动画的场景相关。例如，测试了如何创建一个从不透明度 1.0 变化到 0.0 的动画 (`MakeCompositedAnimation` 函数)。
    *   **举例说明：** 在 HTML 中，我们可以使用 CSS 定义一个元素的 `opacity` 属性的动画，例如：
        ```css
        #target {
            opacity: 1;
            animation: fadeOut 30s;
        }
        @keyframes fadeOut {
            from { opacity: 1; }
            to { opacity: 0; }
        }
        ```
        这段 C++ 测试代码验证了 Blink 引擎在处理这种 CSS 动画时的行为。
*   **JavaScript 动画控制：**  测试代码模拟了 JavaScript 中控制动画的方法，例如 `animation.currentTime = ...`, `animation.play()`, `animation.pause()`, `animation.reverse()`, `animation.finish()` 等。
    *   **举例说明：**  在 JavaScript 中，我们可以通过 `Animation` 接口来控制 CSS 动画或 Web Animations API 创建的动画：
        ```javascript
        const element = document.getElementById('target');
        const animation = element.animate(
            [{ opacity: 1 }, { opacity: 0 }],
            { duration: 30000 }
        );
        animation.currentTime = 10000; // 设置当前时间为 10 秒
        animation.pause();
        ```
        这段 C++ 代码测试了 Blink 引擎中 `Animation` 对象对这些 JavaScript 操作的响应。
*   **HTML 元素关联：** 代码中创建了 HTML 元素 (`GetElementById("target")`) 并将其与动画效果关联，这模拟了动画应用于特定 HTML 元素的场景。

**3. 逻辑推理 (假设输入与输出)：**

*   **假设输入：** 一个持续时间为 30 秒的动画，当前时间设置为 10 秒，播放速率为 1。
*   **输出：**  如果调用 `animation.pause()`，则动画的 `playState` 将变为 "paused"，`currentTime` 保持为 10 秒。后续调用 `animation.play()` 后，如果模拟时间前进 10 秒，则 `currentTime` 将变为 20 秒。
*   **假设输入：** 一个动画的 `currentTime` 设置为 -10 秒，播放速率为 1。
*   **输出：** 动画的 `playState` 可能变为 "finished"，并且 `currentTime` 保持为 -10 秒。

**4. 涉及用户或者编程常见的使用错误：**

*   **设置超出范围的 `currentTime`：**  测试代码演示了设置负值的 `currentTime` 或超出动画持续时间的值。虽然 Blink 引擎允许这样做，但用户可能会期望动画会自动裁剪到 0 或最大持续时间。例如，用户可能错误地认为将 `currentTime` 设置为 50 秒（对于 30 秒的动画）会使动画停留在最后一帧，但实际上 `playState` 会变为 "finished"。
*   **在动画未准备好时操作：**  测试代码中使用了 `pending()` 状态来检查动画是否准备好。用户如果未等待动画准备好就进行操作，可能会导致意外的行为。例如，在动画 `pending` 状态时设置 `startTime` 或 `currentTime`，其效果可能不会立即生效。
*   **混淆 `startTime` 和 `currentTime`：** 用户可能不清楚 `startTime` 是指动画开始播放的时间点，而 `currentTime` 是指动画在其持续时间内的进度。错误地设置 `startTime` 可能导致动画从意外的时间点开始播放。

**5. 第一部分的功能归纳：**

这部分代码主要集中在 **测试 `blink::Animation` 对象的基本属性（如 `currentTime`, `startTime`, `playbackRate`) 和控制方法（如 `play`, `pause`, `reverse`, `finish`) 的正确性**。它验证了在不同操作下，动画的状态转换是否符合预期，并且模拟了 JavaScript 中对动画的各种操作，确保 Blink 引擎的动画实现与 Web 标准一致。此外，它还初步涉及了 composited animation 的测试。

总结来说，这部分测试代码是确保 Blink 引擎中动画核心功能正确性和稳定性的基础。

### 提示词
```
这是目录为blink/renderer/core/animation/animation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/animation/animation.h"

#include <bit>
#include <memory>
#include <tuple>

#include "base/test/metrics/histogram_tester.h"
#include "build/build_config.h"
#include "cc/trees/target_property.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_animation_play_state.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_optional_effect_timing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_timeline_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_double.h"
#include "third_party/blink/renderer/core/animation/css_number_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/animation/timing.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_values.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/animation/compositor_animation.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

void ExpectRelativeErrorWithinEpsilon(double expected, double observed) {
  EXPECT_NEAR(1.0, observed / expected, std::numeric_limits<double>::epsilon());
}

class AnimationAnimationTestNoCompositing : public PaintTestConfigurations,
                                            public RenderingTest {
 public:
  AnimationAnimationTestNoCompositing()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void SetUp() override {
    last_frame_time = 0;
    RenderingTest::SetUp();
    SetUpWithoutStartingTimeline();
    StartTimeline();
  }

  void SetUpWithoutStartingTimeline() {
    GetDocument().GetAnimationClock().ResetTimeForTesting();
    timeline = GetDocument().Timeline();
    timeline->ResetForTesting();
    animation = timeline->Play(nullptr);
    animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                            ASSERT_NO_EXCEPTION);
    animation->setEffect(MakeAnimation());
  }

  void StartTimeline() { SimulateFrame(0); }

  KeyframeEffectModelBase* MakeSimpleEffectModel() {
    PropertyHandle PropertyHandleOpacity(GetCSSPropertyOpacity());
    static CSSNumberInterpolationType opacity_type(PropertyHandleOpacity);
    TransitionKeyframe* start_keyframe =
        MakeGarbageCollected<TransitionKeyframe>(PropertyHandleOpacity);
    start_keyframe->SetValue(MakeGarbageCollected<TypedInterpolationValue>(
        opacity_type, MakeGarbageCollected<InterpolableNumber>(1.0)));
    start_keyframe->SetOffset(0.0);
    // Egregious hack: Sideload the compositor value.
    // This is usually set in a part of the rendering process SimulateFrame
    // doesn't call.
    start_keyframe->SetCompositorValue(
        MakeGarbageCollected<CompositorKeyframeDouble>(1.0));
    TransitionKeyframe* end_keyframe =
        MakeGarbageCollected<TransitionKeyframe>(PropertyHandleOpacity);
    end_keyframe->SetValue(MakeGarbageCollected<TypedInterpolationValue>(
        opacity_type, MakeGarbageCollected<InterpolableNumber>(0.0)));
    end_keyframe->SetOffset(1.0);
    // Egregious hack: Sideload the compositor value.
    end_keyframe->SetCompositorValue(
        MakeGarbageCollected<CompositorKeyframeDouble>(0.0));

    TransitionKeyframeVector keyframes;
    keyframes.push_back(start_keyframe);
    keyframes.push_back(end_keyframe);

    return MakeGarbageCollected<TransitionKeyframeEffectModel>(keyframes);
  }

  void ResetWithCompositedAnimation() {
    // Get rid of the default animation.
    animation->cancel();

    RunDocumentLifecycle();

    SetBodyInnerHTML(R"HTML(
      <div id='target' style='width: 1px; height: 1px; background: green'></div>
    )HTML");

    MakeCompositedAnimation();
  }

  void MakeCompositedAnimation() {
    // Create a compositable animation; in this case opacity from 1 to 0.
    Timing timing;
    timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);

    StringKeyframe* start_keyframe = MakeGarbageCollected<StringKeyframe>();
    start_keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "1.0",
                                        SecureContextMode::kInsecureContext,
                                        nullptr);
    StringKeyframe* end_keyframe = MakeGarbageCollected<StringKeyframe>();
    end_keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "0.0",
                                      SecureContextMode::kInsecureContext,
                                      nullptr);

    StringKeyframeVector keyframes;
    keyframes.push_back(start_keyframe);
    keyframes.push_back(end_keyframe);

    Element* element = GetElementById("target");
    auto* model = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
    animation = timeline->Play(
        MakeGarbageCollected<KeyframeEffect>(element, model, timing));

    // After creating the animation we need to clean the lifecycle so that the
    // animation can be pushed to the compositor.
    UpdateAllLifecyclePhasesForTest();

    GetDocument().GetAnimationClock().UpdateTime(base::TimeTicks());
    GetDocument().GetPendingAnimations().Update(nullptr, true);
  }

  KeyframeEffectModelBase* MakeEmptyEffectModel() {
    return MakeGarbageCollected<StringKeyframeEffectModel>(
        StringKeyframeVector());
  }

  KeyframeEffect* MakeAnimation(
      double duration = 30,
      Timing::FillMode fill_mode = Timing::FillMode::AUTO) {
    Timing timing;
    timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(duration);
    timing.fill_mode = fill_mode;
    return MakeGarbageCollected<KeyframeEffect>(nullptr, MakeEmptyEffectModel(),
                                                timing);
  }

  void SimulateFrame(double time_ms) {
    if (animation->pending()) {
      animation->NotifyReady(
          ANIMATION_TIME_DELTA_FROM_MILLISECONDS(last_frame_time));
    }
    SimulateMicrotask();

    last_frame_time = time_ms;
    const auto* paint_artifact_compositor =
        GetDocument().GetFrame()->View()->GetPaintArtifactCompositor();
    GetDocument().GetAnimationClock().UpdateTime(base::TimeTicks() +
                                                 base::Milliseconds(time_ms));

    // The timeline does not know about our animation, so we have to explicitly
    // call update().
    animation->Update(kTimingUpdateForAnimationFrame);
    GetDocument().GetPendingAnimations().Update(paint_artifact_compositor,
                                                false);
  }

  void SimulateAwaitReady() { SimulateFrame(last_frame_time); }

  void SimulateMicrotask() {
    GetDocument().GetAgent().event_loop()->PerformMicrotaskCheckpoint();
  }

  void SimulateFrameForScrollAnimations() {
    // Advance time by 100 ms.
    auto new_time = GetAnimationClock().CurrentTime() + base::Milliseconds(100);
    GetPage().Animator().ServiceScriptedAnimations(new_time);
  }

  bool StartTimeIsSet(Animation* for_animation) {
    return for_animation->startTime();
  }

  bool CurrentTimeIsSet(Animation* for_animation) {
    return for_animation->currentTime();
  }

  double GetStartTimeMs(Animation* for_animation) {
    return for_animation->startTime()->GetAsDouble();
  }

  double GetCurrentTimeMs(Animation* for_animation) {
    return for_animation->currentTime()->GetAsDouble();
  }

  double GetStartTimePercent(Animation* for_animation) {
    return for_animation->startTime()
        ->GetAsCSSNumericValue()
        ->to(CSSPrimitiveValue::UnitType::kPercentage)
        ->value();
  }

  double GetCurrentTimePercent(Animation* for_animation) {
    return for_animation->currentTime()
        ->GetAsCSSNumericValue()
        ->to(CSSPrimitiveValue::UnitType::kPercentage)
        ->value();
  }

  bool UsesCompositedScrolling(const LayoutBox& box) const {
    auto* pac = GetDocument().GetFrame()->View()->GetPaintArtifactCompositor();
    auto* property_trees =
        pac->RootLayer()->layer_tree_host()->property_trees();
    const auto* cc_scroll = property_trees->scroll_tree().Node(
        box.FirstFragment().PaintProperties()->Scroll()->CcNodeId(
            property_trees->sequence_number()));
    return cc_scroll && cc_scroll->is_composited;
  }

#define EXPECT_TIME(expected, observed) \
  EXPECT_NEAR(expected, observed, Animation::kTimeToleranceMs)

  Persistent<DocumentTimeline> timeline;
  Persistent<Animation> animation;

 private:
  double last_frame_time;
};

class AnimationAnimationTestCompositing
    : public AnimationAnimationTestNoCompositing {
 public:
  Animation* CreateAnimation(CSSPropertyID property_id,
                             String from,
                             String to) {
    Timing timing;
    timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(30);

    StringKeyframe* start_keyframe = MakeGarbageCollected<StringKeyframe>();
    start_keyframe->SetCSSPropertyValue(
        property_id, from, SecureContextMode::kInsecureContext, nullptr);
    StringKeyframe* end_keyframe = MakeGarbageCollected<StringKeyframe>();
    end_keyframe->SetCSSPropertyValue(
        property_id, to, SecureContextMode::kInsecureContext, nullptr);

    StringKeyframeVector keyframes;
    keyframes.push_back(start_keyframe);
    keyframes.push_back(end_keyframe);

    Element* element = GetElementById("target");
    auto* model = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);

    NonThrowableExceptionState exception_state;
    DocumentTimeline* timeline =
        MakeGarbageCollected<DocumentTimeline>(&GetDocument());
    return Animation::Create(
        MakeGarbageCollected<KeyframeEffect>(element, model, timing), timeline,
        exception_state);
  }

 private:
  void SetUp() override {
    EnableCompositing();
    AnimationAnimationTestNoCompositing::SetUp();
  }
};

INSTANTIATE_PAINT_TEST_SUITE_P(AnimationAnimationTestNoCompositing);
INSTANTIATE_PAINT_TEST_SUITE_P(AnimationAnimationTestCompositing);

TEST_P(AnimationAnimationTestNoCompositing, InitialState) {
  SetUpWithoutStartingTimeline();
  animation = timeline->Play(nullptr);
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->pending());
  EXPECT_FALSE(animation->Paused());
  EXPECT_EQ(1, animation->playbackRate());
  EXPECT_FALSE(StartTimeIsSet(animation));

  StartTimeline();
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(0, timeline->CurrentTimeMilliseconds().value());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_FALSE(animation->Paused());
  EXPECT_FALSE(animation->pending());
  EXPECT_EQ(1, animation->playbackRate());
  EXPECT_TIME(0, GetStartTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, CurrentTimeDoesNotSetOutdated) {
  EXPECT_FALSE(animation->Outdated());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_FALSE(animation->Outdated());
  // FIXME: We should split simulateFrame into a version that doesn't update
  // the animation and one that does, as most of the tests don't require
  // update() to be called.
  GetDocument().GetAnimationClock().UpdateTime(base::TimeTicks() +
                                               base::Milliseconds(10000));
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  EXPECT_FALSE(animation->Outdated());
}

TEST_P(AnimationAnimationTestNoCompositing, SetCurrentTime) {
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(10000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));

  SimulateFrame(10000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetCurrentTimeNegative) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(-10000, GetCurrentTimeMs(animation));

  SimulateFrame(20000);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  animation->setPlaybackRate(-2);
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  // A seek can set current time outside the range [0, EffectEnd()].
  EXPECT_TIME(-10000, GetCurrentTimeMs(animation));

  SimulateFrame(40000);
  // Hold current time even though outside normal range for the animation.
  EXPECT_FALSE(animation->pending());
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(-10000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing,
       SetCurrentTimeNegativeWithoutSimultaneousPlaybackRateChange) {
  SimulateFrame(20000);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());

  // Reversing the direction preserves current time.
  animation->setPlaybackRate(-1);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  SimulateAwaitReady();

  SimulateFrame(30000);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());

  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
}

TEST_P(AnimationAnimationTestNoCompositing, SetCurrentTimePastContentEnd) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(50000, GetCurrentTimeMs(animation));

  SimulateFrame(20000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(50000, GetCurrentTimeMs(animation));
  // Reversing the play direction changes the play state from finished to
  // running.
  animation->setPlaybackRate(-2);
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(50000, GetCurrentTimeMs(animation));
  SimulateAwaitReady();

  SimulateFrame(40000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestCompositing, SetCurrentTimeMax) {
  ResetWithCompositedAnimation();
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(nullptr));
  double limit = std::numeric_limits<double>::max();
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(limit),
                            ASSERT_NO_EXCEPTION);
  V8CSSNumberish* current_time = animation->currentTime();
  ExpectRelativeErrorWithinEpsilon(limit, current_time->GetAsDouble());
  EXPECT_TRUE(animation->CheckCanStartAnimationOnCompositor(nullptr) &
              CompositorAnimations::kEffectHasUnsupportedTimingParameters);
  SimulateFrame(100000);
  current_time = animation->currentTime();
  ExpectRelativeErrorWithinEpsilon(limit, current_time->GetAsDouble());
}

TEST_P(AnimationAnimationTestCompositing, SetCurrentTimeAboveMaxTimeDelta) {
  // Similar to the SetCurrentTimeMax test. The limit is much less, but still
  // too large to be expressed as a 64-bit int and thus not able to run on the
  // compositor.
  ResetWithCompositedAnimation();
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(nullptr));
  double limit = 1e30;
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(limit),
                            ASSERT_NO_EXCEPTION);
  std::ignore = animation->currentTime();
  EXPECT_TRUE(animation->CheckCanStartAnimationOnCompositor(nullptr) &
              CompositorAnimations::kEffectHasUnsupportedTimingParameters);
}

TEST_P(AnimationAnimationTestNoCompositing, SetCurrentTimeSetsStartTime) {
  EXPECT_TIME(0, GetStartTimeMs(animation));
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(1000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_TIME(-1000, GetStartTimeMs(animation));

  SimulateFrame(1000);
  EXPECT_TIME(-1000, GetStartTimeMs(animation));
  EXPECT_TIME(2000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, SetStartTime) {
  SimulateFrame(20000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(0, GetStartTimeMs(animation));
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(10000),
                          ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(10000, GetStartTimeMs(animation));
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));

  SimulateFrame(30000);
  EXPECT_TIME(10000, GetStartTimeMs(animation));
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(-20000),
                          ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
}

TEST_P(AnimationAnimationTestNoCompositing, SetStartTimeLimitsAnimation) {
  // Setting the start time is a seek operation, which is not constrained by the
  // normal limits on the animation.
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(-50000),
                          ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TRUE(animation->Limited());
  EXPECT_TIME(50000, GetCurrentTimeMs(animation));
  animation->setPlaybackRate(-1);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(-100000),
                          ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(-100000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->Limited());
}

TEST_P(AnimationAnimationTestNoCompositing, SetStartTimeOnLimitedAnimation) {
  // The setStartTime method is a seek and thus not constrained by the normal
  // limits on the animation.
  SimulateFrame(30000);
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                          ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TIME(40000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->Limited());

  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_TIME(50000, GetCurrentTimeMs(animation));
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(-40000),
                          ASSERT_NO_EXCEPTION);
  EXPECT_TIME(70000, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_TRUE(animation->Limited());
}

TEST_P(AnimationAnimationTestNoCompositing, StartTimePauseFinish) {
  NonThrowableExceptionState exception_state;
  animation->pause();
  EXPECT_EQ("paused", animation->playState());
  EXPECT_TRUE(animation->pending());
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_FALSE(StartTimeIsSet(animation));
  animation->finish(exception_state);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_FALSE(animation->pending());
  EXPECT_TIME(-30000, GetStartTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, FinishWhenPaused) {
  NonThrowableExceptionState exception_state;
  animation->pause();
  EXPECT_EQ("paused", animation->playState());
  EXPECT_TRUE(animation->pending());

  SimulateFrame(10000);
  EXPECT_EQ("paused", animation->playState());
  EXPECT_FALSE(animation->pending());
  animation->finish(exception_state);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
}

TEST_P(AnimationAnimationTestNoCompositing, StartTimeFinishPause) {
  NonThrowableExceptionState exception_state;
  animation->finish(exception_state);
  EXPECT_TIME(-30000, GetStartTimeMs(animation));
  animation->pause();
  EXPECT_EQ("paused", animation->playState());
  EXPECT_TRUE(animation->pending());
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_FALSE(StartTimeIsSet(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, StartTimeWithZeroPlaybackRate) {
  animation->setPlaybackRate(0);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  SimulateAwaitReady();
  EXPECT_TRUE(StartTimeIsSet(animation));

  SimulateFrame(10000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, PausePlay) {
  // Pause the animation at the 10s mark.
  SimulateFrame(10000);
  animation->pause();
  EXPECT_EQ("paused", animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));

  // Resume playing the animation at the 20s mark.
  SimulateFrame(20000);
  EXPECT_EQ("paused", animation->playState());
  EXPECT_FALSE(animation->pending());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());

  // Advance another 10s.
  SimulateFrame(30000);
  EXPECT_TIME(20000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, PlayRewindsToStart) {
  // Auto-replay when starting from limit.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(30000),
                            ASSERT_NO_EXCEPTION);
  animation->play();
  EXPECT_TIME(0, GetCurrentTimeMs(animation));

  // Auto-replay when starting past the upper bound.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  animation->play();
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());

  // Snap to start of the animation if playing in forward direction starting
  // from a negative value of current time.
  SimulateFrame(10000);
  EXPECT_FALSE(animation->pending());
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_FALSE(animation->pending());
  animation->play();
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  SimulateAwaitReady();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_FALSE(animation->pending());
}

TEST_P(AnimationAnimationTestNoCompositing, PlayRewindsToEnd) {
  // Snap to end when playing a reversed animation from the start.
  animation->setPlaybackRate(-1);
  animation->play();
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));

  // Snap to end if playing a reversed animation starting past the upper limit.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  animation->play();
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_TRUE(animation->pending());

  SimulateFrame(10000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_FALSE(animation->pending());

  // Snap to the end if playing a reversed animation starting with a negative
  // value for current time.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  animation->play();
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());

  SimulateFrame(20000);
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_FALSE(animation->pending());
}

TEST_P(AnimationAnimationTestNoCompositing,
       PlayWithPlaybackRateZeroDoesNotSeek) {
  // When playback rate is zero, any value set for the current time effectively
  // becomes the hold time.
  animation->setPlaybackRate(0);
  animation->play();
  EXPECT_TIME(0, GetCurrentTimeMs(animation));

  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  animation->play();
  EXPECT_TIME(40000, GetCurrentTimeMs(animation));

  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  animation->play();
  EXPECT_TIME(-10000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing,
       PlayAfterPauseWithPlaybackRateZeroUpdatesPlayState) {
  animation->pause();
  animation->setPlaybackRate(0);

  SimulateFrame(1000);
  EXPECT_EQ("paused", animation->playState());
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
}

TEST_P(AnimationAnimationTestNoCompositing, Reverse) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(10000),
                            ASSERT_NO_EXCEPTION);
  animation->pause();
  animation->reverse();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  // Effective playback rate does not kick in until the animation is ready.
  EXPECT_EQ(1, animation->playbackRate());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
  SimulateAwaitReady();
  EXPECT_FALSE(animation->pending());
  EXPECT_EQ(-1, animation->playbackRate());
  // Updating the playback rate does not change current time.
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing,
       ReverseHoldsCurrentTimeWithPlaybackRateZero) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(10000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(0);
  animation->pause();
  animation->reverse();
  SimulateAwaitReady();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_EQ(0, animation->playbackRate());
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));

  SimulateFrame(20000);
  EXPECT_TIME(10000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, ReverseSeeksToStart) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(-1);
  animation->reverse();
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, ReverseSeeksToEnd) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  animation->reverse();
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, ReverseBeyondLimit) {
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(40000),
                            ASSERT_NO_EXCEPTION);
  animation->setPlaybackRate(-1);
  animation->reverse();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(0, GetCurrentTimeMs(animation));

  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(-10000),
                            ASSERT_NO_EXCEPTION);
  animation->reverse();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->pending());
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
}

TEST_P(AnimationAnimationTestNoCompositing, Finish) {
  NonThrowableExceptionState exception_state;
  animation->finish(exception_state);
  // Finished snaps to the end of the animation.
  EXPECT_TIME(30000, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  // Finished is a synchronous operation.
  EXPECT_FALSE(animation->pending());

  animation->setPlaybackRate(-1);
  animation->finish(exception_state);
  EXPECT_TIME(0, GetCurrentTimeMs(animation));
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_FALSE(animation->pending());
}

TEST_P(AnimationAnimationTestNoCompositing, FinishAfterEffectEnd) {
  NonThrowableExceptionState exception_state;
  // OK to set current time out of bounds.
  animation->setCurrentTim
```
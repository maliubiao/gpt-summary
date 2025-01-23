Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `animation_test.cc` file in the Chromium Blink engine. I need to identify the core purpose of the code, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with hypothetical inputs and outputs, and point out potential user or programming errors.

Based on the code, the file seems to focus on testing the behavior of animations, specifically how they interact with compositing, scrolling, and the document lifecycle.

Here's a breakdown of the tasks:

1. **Identify Core Functionality:** The tests seem to cover scenarios like restarting composited animations on size changes, handling scroll-linked animations, managing animation states (running, finished, canceled), and synchronizing animation starts.

2. **Relate to Web Technologies:**
    *   **JavaScript:** The code interacts with JavaScript objects like `V8CSSNumberish` and relates to animation APIs that are exposed to JavaScript.
    *   **HTML:** The tests use HTML to create elements and structures that are animated.
    *   **CSS:** The tests utilize CSS properties (e.g., `transform`, `opacity`) and keyframes to define animations.

3. **Provide Logical Reasoning Examples:**  I'll pick a test case and explain the expected behavior with sample input (e.g., initial size, animation properties) and output (e.g., whether the animation restarts).

4. **Illustrate User/Programming Errors:** I'll think about common mistakes developers might make when working with web animations that these tests might be catching.

5. **Summarize the Functionality:**  I'll provide a concise summary of the code's purpose.
这是 `blink/renderer/core/animation/animation_test.cc` 文件的第三部分，主要功能是 **测试动画在不同场景下的行为，特别是与 CSS 动画、滚动动画以及 compositing (合成) 的交互**。

**功能归纳：**

这部分代码主要集中在以下几个方面的测试：

*   **Composited 动画的重启机制:**  测试在元素尺寸变化时，composited 动画是否会正确重启。这包括了变换属性 (`transform`) 依赖于宽度、高度或两者的情况。
*   **Scroll-linked 动画的 compositing 能力:** 验证当动画与滚动条关联时，即使滚动容器本身没有启用 compositing，动画是否仍然可以被 composited。
*   **Scroll-linked 动画的启动时间处理:** 测试当 scroll-linked 动画设置了起始时间时，compositor 是否能正确地应用这个起始时间。
*   **Scroll-linked 动画的状态管理:**  测试 scroll-linked 动画在不同状态 (Idle, Pending, Playing) 下的起始时间和当前时间的正确性。
*   **已完成的 Scroll-linked 动画的重启:**  验证当 composited 的 scroll-linked 动画完成后，如果用户反向滚动，动画是否会在 compositor 上重新启动。
*   **动画从活动集合中移除:**  测试被取消或完成的动画是否会从活动的动画集合中正确移除。
*   **动画的 pending activity (待处理活动):**  测试动画在有 `finished` promise 或 `finish` 事件监听器时，是否会正确地报告 pending activity。
*   **无效的执行上下文处理:**  测试代码是否能正确处理动画关联的执行上下文被销毁的情况。
*   **Pending 动画的同步启动:** 测试 composited 动画和 non-composited 动画在启动时的同步行为，以及取消 composited 动画后 non-composited 动画是否能正常启动。
*   **Content-visibility 属性的影响:** 测试 `content-visibility` 属性对动画的影响，特别是当元素处于 "hidden" 状态时，动画是否会被暂停。
*   **隐藏的动画是否 tick:**  测试当动画元素被隐藏时，动画是否仍然会执行。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **JavaScript:**
    *   代码中使用了 `V8CSSNumberish`，这是一个代表 CSS 数值类型的 V8 对象，说明动画的某些属性值可以由 JavaScript 提供。例如，可以使用 JavaScript 设置动画的 `startTime`。
        ```javascript
        animation.startTime = new CSSUnitValue(0, 'second');
        ```
    *   测试涉及到动画的 `play()`, `cancel()`, `finish()`, `setCurrentTime()` 等方法，这些都是 JavaScript 中 `Animation` 接口暴露的方法。
    *   测试还涉及到事件监听，例如 "finish" 事件，这在 JavaScript 中是常见的动画事件处理方式。

*   **HTML:**
    *   测试中使用了 `SetBodyInnerHTML()` 来动态创建 HTML 结构，这些结构包含了被动画的元素。例如：
        ```html
        <div id="target" style="width: 100px; height: 200px; background: blue; will-change: transform"></div>
        ```
    *   `GetElementById()` 等方法用于获取 HTML 元素，以便将动画应用到这些元素上。

*   **CSS:**
    *   测试中使用了 `CSSPropertyID` 来指定动画的 CSS 属性，例如 `kTransform` (变换) 和 `kOpacity` (不透明度)。
    *   测试创建了 `StringKeyframe` 对象，并设置了 CSS 属性值，这模拟了 CSS 关键帧动画的行为。例如：
        ```css
        @keyframes my-animation {
          from { opacity: 1; }
          to { opacity: 0; }
        }
        ```
    *   测试中使用了 `will-change` CSS 属性来提示浏览器哪些属性将会被动画，这对于触发 compositing 非常重要。

**逻辑推理举例 (假设输入与输出):**

以 `RestartCompositedAnimationOnWidthChange` 测试为例：

*   **假设输入:**
    *   HTML 结构中有一个 `div` 元素，初始宽度 100px，高度 200px，设置了 `will-change: transform`。
    *   应用了一个 `transform: translateX(100%)` 到 `translateX(0%)` 的 composited 动画。
    *   初始状态下，动画已播放。
    *   之后，元素的宽度变为 200px，高度不变。
*   **逻辑推理:** 因为动画的 `translateX` 值依赖于元素的宽度 (使用百分比单位)，宽度变化会影响动画的最终效果，因此 composited 动画需要重启。
*   **预期输出:**
    *   在宽度变化后，`animation->CompositorPendingCancel()` 应该返回 `true`，表示 compositor 上的动画取消操作正在等待执行。
    *   在 `GetDocument().GetPendingAnimations().Update()` 后，`animation->CompositorPendingCancel()` 应该返回 `false`，表示取消操作已处理，新的动画可以开始。

**用户或编程常见的使用错误举例:**

*   **忘记设置 `will-change`:** 如果开发者忘记为需要 compositing 的动画元素设置 `will-change` 属性，浏览器可能不会将动画放到 compositor 上执行，导致性能问题。例如，在上述 `RestartCompositedAnimationOnWidthChange` 测试中，如果移除 `will-change: transform`，动画可能不会被 composited，尺寸变化时也不一定会触发重启 compositor 动画的逻辑。
*   **对 composited 动画的理解不足:** 开发者可能不清楚哪些操作会触发 composited 动画的重启。例如，他们可能认为只有动画属性发生变化才会重启，而忽略了元素尺寸变化对某些 `transform` 函数 (如使用百分比单位) 的影响。
*   **Scroll-linked 动画的错误配置:**  开发者可能错误地配置 `ScrollTimeline` 的 `source` 属性，导致动画无法正确地与滚动容器关联。或者，他们可能不理解 scroll-linked 动画的起始时间是如何相对于滚动位置计算的。

总而言之，这部分测试代码深入验证了 Blink 引擎中动画模块的复杂逻辑，确保了在各种场景下动画行为的正确性和性能，特别是与 compositing 和滚动相关的动画。

### 提示词
```
这是目录为blink/renderer/core/animation/animation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
on out of the play-pending state.
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                          ASSERT_NO_EXCEPTION);

  // No size change and animation does not require a restart.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(100, 200));
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation->CompositorPendingCancel());

  // Restart animation on a width change.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(200, 200));
  // Cancel is deferred to PreCommit.
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_TRUE(animation->CompositorPendingCancel());

  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation->CompositorPendingCancel());

  // Restart animation on a height change.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(200, 300));
  EXPECT_TRUE(animation->CompositorPendingCancel());
  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_FALSE(animation->CompositorPendingCancel());
}

// crbug.com/1149012
// Regression test to ensure proper restart logic for composited animations on
// relative transforms after a size change. In this test, the transform only
// depends on width and a change to the height does not trigger a restart.
TEST_P(AnimationAnimationTestCompositing,
       RestartCompositedAnimationOnWidthChange) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 100px; height: 200px; background: blue;
                            will-change: transform">
    </div>
  )HTML");

  animation = CreateAnimation(CSSPropertyID::kTransform, "translateX(100%)",
                              "translateX(0%)");

  UpdateAllLifecyclePhasesForTest();
  animation->play();
  KeyframeEffect* keyframe_effect =
      DynamicTo<KeyframeEffect>(animation->effect());
  ASSERT_TRUE(keyframe_effect);

  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(100, 200));
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                          ASSERT_NO_EXCEPTION);

  // Transform is not height dependent and a change to the height does not force
  // an animation restart.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(100, 300));
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation->CompositorPendingCancel());

  // Width change forces a restart.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(200, 300));
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_TRUE(animation->CompositorPendingCancel());

  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation->CompositorPendingCancel());
}

// crbug.com/1149012
// Regression test to ensure proper restart logic for composited animations on
// relative transforms after a size change.  In this test, the transition only
// affects height and a change to the width does not trigger a restart.
TEST_P(AnimationAnimationTestCompositing,
       RestartCompositedAnimationOnHeightChange) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" style="width: 100px; height: 200px; background: blue;
                            will-change: transform">
    </div>
  )HTML");

  animation = CreateAnimation(CSSPropertyID::kTransform, "translateY(100%)",
                              "translateY(0%)");

  UpdateAllLifecyclePhasesForTest();
  animation->play();
  KeyframeEffect* keyframe_effect =
      DynamicTo<KeyframeEffect>(animation->effect());
  ASSERT_TRUE(keyframe_effect);

  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(100, 200));
  animation->setStartTime(MakeGarbageCollected<V8CSSNumberish>(0),
                          ASSERT_NO_EXCEPTION);

  // Transform is not width dependent and a change to the width does not force
  // an animation restart.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(300, 200));
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());

  // Height change forces a restart.
  keyframe_effect->UpdateBoxSizeAndCheckTransformAxisAlignment(
      gfx::SizeF(300, 400));
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_TRUE(animation->CompositorPending());
  EXPECT_TRUE(animation->CompositorPendingCancel());

  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation->CompositorPending());
  EXPECT_FALSE(animation->CompositorPendingCancel());
}

TEST_P(AnimationAnimationTestCompositing,
       ScrollLinkedAnimationCanBeComposited) {
  ResetWithCompositedAnimation();
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        will-change: transform; overflow: scroll; width: 100px; height: 100px;
      }
      #target {
        width: 100px; height: 200px; background: blue; will-change: opacity;
      }
      #spacer { width: 200px; height: 2000px; }
    </style>
    <div id ='scroller'>
      <div id ='target'></div>
      <div id ='spacer'></div>
    </div>
  )HTML");

  // Create ScrollTimeline
  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->SetScrollOffset(ScrollOffset(0, 20),
                                   mojom::blink::ScrollType::kProgrammatic);
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  // Create KeyframeEffect
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

  // Create scroll-linked animation
  NonThrowableExceptionState exception_state;
  Animation* scroll_animation = Animation::Create(
      MakeGarbageCollected<KeyframeEffect>(element, model, timing),
      scroll_timeline, exception_state);

  model->SnapshotAllCompositorKeyframesIfNecessary(
      *element, GetDocument().GetStyleResolver().InitialStyle(), nullptr);

  UpdateAllLifecyclePhasesForTest();
  scroll_animation->play();
  scroll_animation->SetDeferredStartTimeForTesting();
  EXPECT_EQ(scroll_animation->CheckCanStartAnimationOnCompositor(nullptr),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationAnimationTestCompositing,
       StartScrollLinkedAnimationWithStartTimeIfApplicable) {
  ResetWithCompositedAnimation();
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller {
        will-change: transform; overflow: scroll; width: 100px; height: 100px; background: blue;
      }
      #target {
        width: 100px; height: 200px; background: blue; will-change: opacity;
      }
      #spacer { width: 200px; height: 700px; }
    </style>
    <div id ='scroller'>
      <div id ='target'></div>
      <div id ='spacer'></div>
    </div>
  )HTML");

  // Create ScrollTimeline
  auto* scroller =
      To<LayoutBoxModelObject>(GetLayoutObjectByElementId("scroller"));
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  scrollable_area->SetScrollOffset(ScrollOffset(0, 100),
                                   mojom::blink::ScrollType::kProgrammatic);
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  // Create KeyframeEffect
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

  KeyframeEffect* keyframe_effect =
      MakeGarbageCollected<KeyframeEffect>(element, model, timing);

  // Create scroll-linked animation
  NonThrowableExceptionState exception_state;
  Animation* scroll_animation =
      Animation::Create(keyframe_effect, scroll_timeline, exception_state);

  model->SnapshotAllCompositorKeyframesIfNecessary(
      *element, GetDocument().GetStyleResolver().InitialStyle(), nullptr);

  UpdateAllLifecyclePhasesForTest();
  const double TEST_START_PERCENT = 10;
  scroll_animation->play();
  scroll_animation->setStartTime(
      MakeGarbageCollected<V8CSSNumberish>(
          CSSUnitValues::percent(TEST_START_PERCENT)),
      ASSERT_NO_EXCEPTION);
  EXPECT_EQ(scroll_animation->CheckCanStartAnimationOnCompositor(nullptr),
            CompositorAnimations::kNoFailure);
  UpdateAllLifecyclePhasesForTest();
  // Start the animation on compositor. The time offset of the compositor
  // keyframe should be unset if we start the animation with its start time.
  scroll_animation->PreCommit(1, nullptr, true);
  cc::KeyframeModel* keyframe_model =
      keyframe_effect->GetAnimationForTesting()
          ->GetCompositorAnimation()
          ->CcAnimation()
          ->GetKeyframeModel(cc::TargetProperty::OPACITY);

  double timeline_duration_ms =
      scroll_timeline->GetDuration()->InMillisecondsF();
  double start_time_ms =
      (keyframe_model->start_time() - base::TimeTicks()).InMillisecondsF();
  double progress_percent = (start_time_ms / timeline_duration_ms) * 100;
  EXPECT_NEAR(progress_percent, TEST_START_PERCENT, 1e-3);
  EXPECT_EQ(keyframe_model->time_offset(), base::TimeDelta());
}

// Verifies correctness of scroll linked animation current and start times in
// various animation states.
TEST_P(AnimationAnimationTestNoCompositing, ScrollLinkedAnimationCreation) {
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
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  NonThrowableExceptionState exception_state;
  Animation* scroll_animation =
      Animation::Create(MakeAnimation(), scroll_timeline, exception_state);

  // Verify start and current times in Idle state.
  EXPECT_FALSE(StartTimeIsSet(scroll_animation));
  EXPECT_FALSE(CurrentTimeIsSet(scroll_animation));

  scroll_animation->play();

  // Verify start and current times in Pending state.
  EXPECT_FALSE(StartTimeIsSet(scroll_animation));
  EXPECT_FALSE(CurrentTimeIsSet(scroll_animation));

  UpdateAllLifecyclePhasesForTest();
  // Verify start and current times in Playing state.
  EXPECT_TIME(0, GetStartTimePercent(scroll_animation));
  EXPECT_TIME(20, GetCurrentTimePercent(scroll_animation));

  // Verify current time after scroll.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 40),
                                   mojom::blink::ScrollType::kProgrammatic);
  SimulateFrameForScrollAnimations();
  EXPECT_TIME(40, GetCurrentTimePercent(scroll_animation));
}

// Verifies that finished composited scroll-linked animations restart on
// compositor upon reverse scrolling.
TEST_P(AnimationAnimationTestCompositing,
       FinishedScrollLinkedAnimationRestartsOnReverseScrolling) {
  ResetWithCompositedAnimation();
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { will-change: transform; overflow: scroll; width: 100px; height: 100px; }
      #target { width: 100px; height: 200px; will-change: opacity; background: green;}
      #spacer { width: 200px; height: 700px; }
    </style>
    <div id ='scroller'>
      <div id ='target'></div>
      <div id ='spacer'></div>
    </div>
  )HTML");

  auto* scroller = GetLayoutBoxByElementId("scroller");
  ASSERT_TRUE(UsesCompositedScrolling(*scroller));

  // Create ScrollTimeline
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  // Create KeyframeEffect
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

  KeyframeEffect* keyframe_effect =
      MakeGarbageCollected<KeyframeEffect>(element, model, timing);

  // Create scroll-linked animation
  NonThrowableExceptionState exception_state;
  Animation* scroll_animation =
      Animation::Create(keyframe_effect, scroll_timeline, exception_state);
  model->SnapshotAllCompositorKeyframesIfNecessary(
      *element, GetDocument().GetStyleResolver().InitialStyle(), nullptr);
  UpdateAllLifecyclePhasesForTest();

  scroll_animation->play();
  EXPECT_EQ(scroll_animation->playState(),
            V8AnimationPlayState::Enum::kRunning);
  UpdateAllLifecyclePhasesForTest();
  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(scroll_animation->HasActiveAnimationsOnCompositor());

  // Advances the animation to V8AnimationPlayState::Enum::kFinished state. The
  // composited animation will be destroyed accordingly.
  scroll_animation->setCurrentTime(
      MakeGarbageCollected<V8CSSNumberish>(CSSUnitValues::percent(100)),
      ASSERT_NO_EXCEPTION);
  EXPECT_EQ(scroll_animation->playState(),
            V8AnimationPlayState::Enum::kFinished);
  scroll_animation->Update(kTimingUpdateForAnimationFrame);
  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_FALSE(scroll_animation->HasActiveAnimationsOnCompositor());

  // Restarting the animation should create a new compositor animation.
  scroll_animation->setCurrentTime(
      MakeGarbageCollected<V8CSSNumberish>(CSSUnitValues::percent(50)),
      ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(scroll_animation->playState(),
            V8AnimationPlayState::Enum::kRunning);
  scroll_animation->Update(kTimingUpdateForAnimationFrame);
  GetDocument().GetPendingAnimations().Update(nullptr, true);
  EXPECT_TRUE(scroll_animation->HasActiveAnimationsOnCompositor());
}

TEST_P(AnimationAnimationTestNoCompositing,
       RemoveCanceledAnimationFromActiveSet) {
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->Update(kTimingUpdateForAnimationFrame));
  SimulateFrame(1000);
  EXPECT_TRUE(animation->Update(kTimingUpdateForAnimationFrame));
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));
}

TEST_P(AnimationAnimationTestNoCompositing,
       RemoveFinishedAnimationFromActiveSet) {
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->Update(kTimingUpdateForAnimationFrame));
  SimulateFrame(1000);
  EXPECT_TRUE(animation->Update(kTimingUpdateForAnimationFrame));

  // Synchronous completion.
  animation->finish();
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));

  // Play creates a new pending finished promise.
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_TRUE(animation->Update(kTimingUpdateForAnimationFrame));

  // Asynchronous completion.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));
}

TEST_P(AnimationAnimationTestNoCompositing,
       PendingActivityWithFinishedPromise) {
  // No pending activity even when running if there is no finished promise
  // or event listener.
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  SimulateFrame(1000);
  EXPECT_FALSE(animation->HasPendingActivity());

  // An unresolved finished promise indicates pending activity.
  ScriptState* script_state =
      ToScriptStateForMainWorld(GetDocument().GetFrame());
  animation->finished(script_state);
  EXPECT_TRUE(animation->HasPendingActivity());

  // Resolving the finished promise clears the pending activity.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  SimulateMicrotask();
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));
  EXPECT_FALSE(animation->HasPendingActivity());

  // Playing an already finished animation creates a new pending finished
  // promise.
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  SimulateFrame(2000);
  EXPECT_TRUE(animation->HasPendingActivity());
  // Cancel rejects the finished promise and creates a new pending finished
  // promise.
  // TODO(crbug.com/960944): Investigate if this should return false to prevent
  // holding onto the animation indefinitely.
  animation->cancel();
  EXPECT_TRUE(animation->HasPendingActivity());
}

class MockEventListener final : public NativeEventListener {
 public:
  MOCK_METHOD2(Invoke, void(ExecutionContext*, Event*));
};

TEST_P(AnimationAnimationTestNoCompositing,
       PendingActivityWithFinishedEventListener) {
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  EXPECT_FALSE(animation->HasPendingActivity());

  // Attaching a listener for the finished event indicates pending activity.
  MockEventListener* event_listener = MakeGarbageCollected<MockEventListener>();
  animation->addEventListener(event_type_names::kFinish, event_listener);
  EXPECT_TRUE(animation->HasPendingActivity());

  // Synchronous finish clears pending activity.
  animation->finish();
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));
  EXPECT_TRUE(animation->HasPendingActivity());
  animation->pending_finished_event_ = nullptr;
  EXPECT_FALSE(animation->HasPendingActivity());

  // Playing an already finished animation resets the finished state.
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  SimulateFrame(2000);
  EXPECT_TRUE(animation->HasPendingActivity());

  // Finishing the animation asynchronously clears the pending activity.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50000),
                            ASSERT_NO_EXCEPTION);
  EXPECT_EQ(V8AnimationPlayState::Enum::kFinished, animation->playState());
  SimulateMicrotask();
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));
  EXPECT_TRUE(animation->HasPendingActivity());
  animation->pending_finished_event_ = nullptr;
  EXPECT_FALSE(animation->HasPendingActivity());

  // Canceling an animation clears the pending activity.
  animation->play();
  EXPECT_EQ(V8AnimationPlayState::Enum::kRunning, animation->playState());
  SimulateFrame(2000);
  animation->cancel();
  EXPECT_EQ("idle", animation->playState());
  EXPECT_FALSE(animation->Update(kTimingUpdateForAnimationFrame));
  EXPECT_FALSE(animation->HasPendingActivity());
}

TEST_P(AnimationAnimationTestCompositing, InvalidExecutionContext) {
  // Test for crbug.com/1254444. Guard against setting an invalid execution
  // context.
  EXPECT_TRUE(animation->GetExecutionContext());
  GetDocument().GetExecutionContext()->NotifyContextDestroyed();
  EXPECT_FALSE(animation->GetExecutionContext());
  Animation* original_animation = animation;
  ResetWithCompositedAnimation();
  EXPECT_TRUE(animation);
  EXPECT_NE(animation, original_animation);
  EXPECT_FALSE(animation->GetExecutionContext());
  // Cancel queues an event if there is a valid execution context.
  animation->cancel();
  EXPECT_FALSE(animation->HasPendingActivity());
}

class AnimationPendingAnimationsTest : public PaintTestConfigurations,
                                       public RenderingTest {
 public:
  AnimationPendingAnimationsTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  enum CompositingMode { kComposited, kNonComposited };

  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
    GetDocument().GetAnimationClock().ResetTimeForTesting();
    timeline = GetDocument().Timeline();
    timeline->ResetForTesting();
  }

  Animation* MakeAnimation(const char* target, CompositingMode mode) {
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

    Element* element = GetElementById(target);
    auto* model = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);

    Animation* animation = timeline->Play(
        MakeGarbageCollected<KeyframeEffect>(element, model, timing));

    if (mode == kNonComposited) {
      // Having a playback rate of zero is one of several ways to force an
      // animation to be non-composited.
      animation->updatePlaybackRate(0);
    }

    return animation;
  }

  bool Update() {
    UpdateAllLifecyclePhasesForTest();
    GetDocument().GetAnimationClock().UpdateTime(base::TimeTicks());
    return GetDocument().GetPendingAnimations().Update(nullptr, true);
  }

  void NotifyAnimationStarted(Animation* animation) {
    animation->GetDocument()
        ->GetPendingAnimations()
        .NotifyCompositorAnimationStarted(0, animation->CompositorGroup());
  }

  void restartAnimation(Animation* animation) {
    animation->cancel();
    animation->play();
  }

  Persistent<DocumentTimeline> timeline;
};

INSTANTIATE_PAINT_TEST_SUITE_P(AnimationPendingAnimationsTest);

TEST_P(AnimationPendingAnimationsTest, PendingAnimationStartSynchronization) {
  RunDocumentLifecycle();
  SetBodyInnerHTML("<div id='foo'>f</div><div id='bar'>b</div>");

  Animation* animA = MakeAnimation("foo", kComposited);
  Animation* animB = MakeAnimation("bar", kNonComposited);

  // B's start time synchronized with A's start time.
  EXPECT_TRUE(Update());
  EXPECT_TRUE(animA->pending());
  EXPECT_TRUE(animB->pending());
  EXPECT_TRUE(animA->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animB->HasActiveAnimationsOnCompositor());
  NotifyAnimationStarted(animA);
  EXPECT_FALSE(animA->pending());
  EXPECT_FALSE(animB->pending());
}

TEST_P(AnimationPendingAnimationsTest,
       PendingAnimationCancelUnblocksSynchronizedStart) {
  RunDocumentLifecycle();
  SetBodyInnerHTML("<div id='foo'>f</div><div id='bar'>b</div>");

  Animation* animA = MakeAnimation("foo", kComposited);
  Animation* animB = MakeAnimation("bar", kNonComposited);

  EXPECT_TRUE(Update());
  EXPECT_TRUE(animA->pending());
  EXPECT_TRUE(animB->pending());
  animA->cancel();

  // Animation A no longer blocks B from starting.
  EXPECT_FALSE(Update());
  EXPECT_FALSE(animB->pending());
}

TEST_P(AnimationPendingAnimationsTest,
       PendingAnimationOnlySynchronizeStartsOfNewlyPendingAnimations) {
  RunDocumentLifecycle();
  SetBodyInnerHTML(
      "<div id='foo'>f</div><div id='bar'>b</div><div id='baz'>z</div>");

  Animation* animA = MakeAnimation("foo", kComposited);
  Animation* animB = MakeAnimation("bar", kNonComposited);

  // This test simulates the conditions in crbug.com/666710. The start of a
  // non-composited animation is deferred in order to synchronize with a
  // composited animation, which is canceled before it starts. Subsequent frames
  // produce new composited animations which prevented the non-composited
  // animation from ever starting. Non-composited animations should not be
  // synchronize with new composited animations if queued up in a prior call to
  // PendingAnimations::Update.
  EXPECT_TRUE(Update());
  EXPECT_TRUE(animA->pending());
  EXPECT_TRUE(animB->pending());
  animA->cancel();

  Animation* animC = MakeAnimation("baz", kComposited);
  Animation* animD = MakeAnimation("bar", kNonComposited);

  EXPECT_TRUE(Update());
  // B's is unblocked despite newly created composited animation.
  EXPECT_FALSE(animB->pending());
  EXPECT_TRUE(animC->pending());
  // D's start time is synchronized with C's start.
  EXPECT_TRUE(animD->pending());
  NotifyAnimationStarted(animC);
  EXPECT_FALSE(animC->pending());
  EXPECT_FALSE(animD->pending());
}

TEST_P(AnimationAnimationTestCompositing,
       ScrollLinkedAnimationCompositedEvenIfSourceIsNotComposited) {
  SetPreferCompositingToLCDText(false);
  SetBodyInnerHTML(R"HTML(
    <style>
      #scroller { overflow: scroll; width: 100px; height: 100px; }
      /* to prevent the mock overlay scrollbar from affecting compositing. */
      #scroller::-webkit-scrollbar { display: none; }
      #target { width: 100px; height: 200px; will-change: transform; }
      #spacer { width: 200px; height: 2000px; }
    </style>
    <div id ='scroller'>
      <div id ='target'></div>
      <div id ='spacer'></div>
    </div>
  )HTML");

  // Create ScrollTimeline
  auto* scroller = GetLayoutBoxByElementId("scroller");
  PaintLayerScrollableArea* scrollable_area = scroller->GetScrollableArea();
  ASSERT_FALSE(UsesCompositedScrolling(*scroller));
  scrollable_area->SetScrollOffset(ScrollOffset(0, 20),
                                   mojom::blink::ScrollType::kProgrammatic);
  ScrollTimelineOptions* options = ScrollTimelineOptions::Create();
  options->setSource(GetElementById("scroller"));
  ScrollTimeline* scroll_timeline =
      ScrollTimeline::Create(GetDocument(), options, ASSERT_NO_EXCEPTION);

  // Create KeyframeEffect
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

  // Create scroll-linked animation
  NonThrowableExceptionState exception_state;
  Animation* scroll_animation = Animation::Create(
      MakeGarbageCollected<KeyframeEffect>(element, model, timing),
      scroll_timeline, exception_state);

  model->SnapshotAllCompositorKeyframesIfNecessary(
      *element, GetDocument().GetStyleResolver().InitialStyle(), nullptr);

  UpdateAllLifecyclePhasesForTest();
  scroll_animation->play();
  scroll_animation->SetDeferredStartTimeForTesting();
  EXPECT_EQ(scroll_animation->CheckCanStartAnimationOnCompositor(nullptr),
            CompositorAnimations::kNoFailure);
}

#if BUILDFLAG(IS_MAC) && defined(ARCH_CPU_ARM64)
// https://crbug.com/1222646
#define MAYBE_ContentVisibleDisplayLockTest \
  DISABLED_ContentVisibleDisplayLockTest
#else
#define MAYBE_ContentVisibleDisplayLockTest ContentVisibleDisplayLockTest
#endif
TEST_P(AnimationAnimationTestCompositing, MAYBE_ContentVisibleDisplayLockTest) {
  animation->cancel();
  RunDocumentLifecycle();

  SetBodyInnerHTML(R"HTML(
    <style>
      .container {
        content-visibility: auto;
      }
      @keyframes anim {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      #target {
        background-color: blue;
        width: 50px;
        height: 50px;
        animation: anim 1s linear alternate infinite;
      }
    </style>
    <div id="outer" class="container">
      <div id="inner" class="container">
        <div id ="target">
        </div>
      </div>
    </div>
  )HTML");

  RunDocumentLifecycle();

  Element* outer = GetElementById("outer");
  Element* inner = GetElementById("inner");
  Element* target = GetElementById("target");

  ElementAnimations* element_animations = target->GetElementAnimations();
  EXPECT_EQ(1u, element_animations->Animations().size());

  Animation* animation = element_animations->Animations().begin()->key;
  ASSERT_TRUE(!!animation);
  EXPECT_FALSE(animation->IsInDisplayLockedSubtree());

  inner->setAttribute(html_names::kStyleAttr,
                      AtomicString("content-visibility: hidden"));
  RunDocumentLifecycle();
  EXPECT_TRUE(animation->IsInDisplayLockedSubtree());

  inner->setAttribute(html_names::kStyleAttr,
                      AtomicString("content-visibility: visible"));
  RunDocumentLifecycle();
  EXPECT_FALSE(animation->IsInDisplayLockedSubtree());

  outer->setAttribute(html_names::kStyleAttr,
                      AtomicString("content-visibility: hidden"));
  RunDocumentLifecycle();
  EXPECT_TRUE(animation->IsInDisplayLockedSubtree());

  // Ensure that the animation has not been canceled even though display locked.
  EXPECT_EQ(1u, target->GetElementAnimations()->Animations().size());
  EXPECT_EQ(animation->playState(), V8AnimationPlayState::Enum::kRunning);
}

TEST_P(AnimationAnimationTestCompositing, HiddenAnimationsDoNotTick) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes anim {
        from { opacity:
```
Response:
Let's break down the thought process for analyzing the `effect_stack_test.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this test file and its relation to web technologies (JavaScript, HTML, CSS). We also need to identify any logic, assumptions, and potential usage errors it reveals.

2. **Identify the Tested Class:** The filename itself, `effect_stack_test.cc`, strongly suggests that the class under test is `EffectStack`. A quick scan of the `#include` directives confirms this, specifically `#include "third_party/blink/renderer/core/animation/effect_stack.h"`.

3. **Recognize the Test Framework:** The inclusion of `#include "testing/gtest/include/gtest/gtest.h"` immediately tells us this is using the Google Test framework. This means we'll be looking for `TEST_F` macros defining individual test cases.

4. **Examine `SetUp()`:** The `SetUp()` method is crucial for understanding the test environment. It initializes:
    * `PageTestBase`:  This implies the tests run within a simulated browser page environment.
    * `DocumentTimeline`: This is the core object managing animations within a document.
    * `Element`:  A basic HTML element (`<foo>`) is created. This tells us the tests are likely focused on how animations affect elements.

5. **Analyze Helper Functions:**  The test fixture has several helper functions. Understanding these is key to grasping the test logic:
    * `Play()`:  This function creates and starts an animation on the `timeline`. It takes a `KeyframeEffect` and a `start_time` as input. The important part is how it sets the start time using `V8CSSNumberish`, hinting at JavaScript interaction.
    * `UpdateTimeline()`: This advances the animation timeline, allowing tests to simulate animation progression.
    * `SampledEffectCount()`:  This function checks the number of "sampled effects" on the element. This likely relates to how animations are being processed and stored.
    * `MakeEffectModel()`:  This creates a `KeyframeEffectModel` which defines the animation's properties (e.g., `font-size: 1px`). It takes a CSS property ID and a value as input, indicating a direct link to CSS properties.
    * `MakeInertEffect()`: Creates an `InertEffect`, which appears to represent an animation effect that might not be actively playing.
    * `MakeKeyframeEffect()`: Creates a `KeyframeEffect`, the core object defining an animation on an element. It links an effect model to an element and has timing properties.
    * `GetFontSizeValue()` and `GetZIndexValue()`: These extract the animated values of `font-size` and `z-index` from the `ActiveInterpolationsMap`. They demonstrate how animated values are retrieved and are crucial for verifying animation results. The use of `InterpolableLength` and `InterpolableNumber` provides deeper technical detail.

6. **Study Individual Test Cases (`TEST_F`):**  Each `TEST_F` focuses on a specific aspect of `EffectStack` functionality:
    * `ElementAnimationsSorted`: Checks if animations are applied in the correct order based on their start times (highest priority animation wins). This relates to CSS animation precedence.
    * `NewAnimations`: Tests how newly added animations affect the element's styles.
    * `CancelledAnimations`: Examines the impact of canceling animations.
    * `ClearedEffectsRemoved`: Verifies that removing an animation effect properly updates the applied styles.
    * `ForwardsFillDiscarding`:  Focuses on the `fill: forwards` behavior of CSS animations, particularly how older animations are discarded as newer ones take effect and persist. The use of `ThreadState::Current()->CollectAllGarbageForTesting()` is a detail about memory management during testing.
    * `AffectsPropertiesCSSBitsetDefaultPriority` and `AffectsPropertiesCSSBitsetTransitionPriority`: These tests examine the `AffectsProperties` method, which determines if the `EffectStack` has animations affecting specific CSS properties at a given priority. This relates to how the browser optimizes style calculations.
    * `AffectedPropertiesDefaultPriority` and `AffectedPropertiesTransitionPriority`: These tests check the `AffectedProperties` method, which returns the set of CSS properties currently animated at a specific priority.

7. **Connect to Web Technologies:**  As each test case is analyzed, explicitly connect its functionality to JavaScript, HTML, and CSS:
    * **CSS:** The tests heavily use CSS property IDs and values (`font-size`, `z-index`, `color`, `top`, `left`). The concepts of animation duration, fill modes (`both`, implying `forwards`), and transitions are directly related to CSS animation and transition properties.
    * **JavaScript:** The `Play()` function uses `V8CSSNumberish`, which bridges the gap between JavaScript numbers and Blink's internal representation of CSS values. The overall animation control (starting, canceling) is often done via JavaScript's Web Animations API.
    * **HTML:** The tests create and manipulate an `Element`, the fundamental building block of HTML documents. Animations are applied *to* these HTML elements.

8. **Identify Logic and Assumptions:**  For each test:
    * **Input:** What initial state is set up (e.g., playing specific animations with certain start times)?
    * **Action:** What method of `EffectStack` is being called (e.g., `ActiveInterpolations`)?
    * **Output:** What is the expected result (e.g., the `font-size` should be a specific value)?
    * **Assumptions:** What underlying assumptions are being made about the behavior of the animation system (e.g., later animations with the same property override earlier ones)?

9. **Consider Usage Errors:** Think about common mistakes developers might make when working with web animations that these tests might implicitly or explicitly guard against:
    * Conflicting animations on the same property.
    * Incorrect start times or durations.
    * Misunderstanding `fill` modes.
    * Expecting animations to apply when they haven't been properly started or are outside their active time range.

10. **Structure the Output:** Organize the findings into clear categories as requested by the prompt: functionality, relationship to web technologies, logical reasoning (input/output), and common usage errors. Use concrete examples from the code to illustrate each point.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the tests are *only* about the ordering of animations. **Correction:**  Looking at tests like `NewAnimations` and `CancelledAnimations` reveals that the tests also cover adding and removing animations.
* **Initial thought:**  The `V8CSSNumberish` might be some internal Blink type. **Correction:** Recognizing the `V8` prefix connects it to the V8 JavaScript engine, clarifying the interaction with JavaScript.
* **Realization:** The `ForwardsFillDiscarding` test is more complex than just basic `fill: forwards`. It involves how Blink manages memory and discards older, no-longer-relevant animation effects. This requires understanding the interaction between animation behavior and garbage collection.

By following this detailed breakdown and constantly referring back to the code, we can systematically extract the necessary information and provide a comprehensive answer to the prompt.
This C++ source code file, `effect_stack_test.cc`, is a **unit test file** for the `EffectStack` class within the Chromium Blink rendering engine. The `EffectStack` class is responsible for managing and resolving the active animation effects that apply to a particular HTML element at a given point in time.

Here's a breakdown of its functionalities:

**Core Functionality Being Tested:**

1. **Animation Ordering and Resolution:** The tests verify that when multiple animations affect the same CSS property, the `EffectStack` correctly determines the winning animation based on factors like start time and priority. This ensures that CSS animation rules for precedence are correctly implemented.
2. **Adding and Removing Animations:**  Tests cover scenarios where new animations are added and existing animations are cancelled or have their effects removed, ensuring the `EffectStack` updates its state accordingly.
3. **`fill: forwards` Behavior:**  Specific tests examine how animations with `fill-mode: forwards` behave. This means that the final state of the animation persists after the animation has finished. The tests check if older, finished animations are correctly discarded when newer, also finished, animations with `fill: forwards` are present.
4. **Identifying Affected Properties:** The tests verify the `AffectsProperties` method of the `EffectStack`. This method determines whether the stack contains animations that affect a given set of CSS properties at a specific priority level (e.g., default animation priority vs. CSS transition priority).
5. **Retrieving Affected Properties:**  The tests check the `AffectedProperties` method, which returns a set of all CSS properties currently being animated by the `EffectStack` at a given priority.

**Relationship to JavaScript, HTML, and CSS:**

This test file is deeply intertwined with the functionality of JavaScript, HTML, and CSS animations:

* **CSS Animations:** The tests directly manipulate CSS properties (e.g., `font-size`, `z-index`, `color`, `top`, `left`) through animation effects. The concept of animation priority, fill modes (`fill: both`, which often implies `forwards` for the purposes of these tests), and the timing of animations are all core to CSS animations.
    * **Example:** The test `ElementAnimationsSorted` verifies that if multiple animations target the `font-size` property with different start times, the animation that starts later (and is thus considered to have higher precedence in this case) will be the one whose value is reflected. This aligns with CSS animation cascading rules.
* **JavaScript and the Web Animations API:**  While this test file is in C++, it tests the underlying implementation of the Web Animations API, which is heavily used by JavaScript. The `timeline->Play(effect)` call in the `Play` helper function simulates starting an animation, which is a common operation performed via JavaScript. The setting of the `startTime` using `V8CSSNumberish` hints at the interaction with JavaScript's numeric representation of time.
    * **Example:**  A JavaScript developer might use the `Element.animate()` method to create and start animations. The `EffectStack` is the underlying mechanism that Blink uses to manage these animations.
* **HTML Elements:** The tests create an HTML element (`<foo>`) and apply animations to it. The `EffectStack` is associated with a specific HTML element's animation state.
    * **Example:** The `element = GetDocument().CreateElementForBinding(AtomicString("foo"));` line creates a basic HTML element. The subsequent animations are applied to *this* element, demonstrating how animations affect specific elements in the DOM.

**Logical Reasoning (Assumptions, Inputs, and Outputs):**

Let's take the `ElementAnimationsSorted` test as an example of logical reasoning:

* **Assumption:** Animations started later with the same priority affecting the same property will override earlier animations.
* **Input:**
    * Three `KeyframeEffect` objects are created, all targeting the `font-size` property with different values ("1px", "2px", "3px").
    * These effects are played on the same element at different start times (10, 15, and 5 respectively).
* **Action:** The `ActiveInterpolations` method of the `EffectStack` is called to retrieve the currently active interpolated values.
* **Output:** The test asserts that the `font-size` value is "3px". This is because the animation with the latest effective start time (after considering any delays or negative start times) should win.

**Common Usage Errors (Implied by Tests):**

While this is a test file and not directly demonstrating user errors, it implicitly highlights potential issues developers might face:

1. **Conflicting Animations:** Developers might unintentionally create multiple animations that target the same CSS property. Understanding the order and priority of animations is crucial to avoid unexpected results. The `ElementAnimationsSorted` test directly addresses this.
    * **Example Error:** A developer might have a CSS animation for `opacity` and then, through JavaScript, add another animation for `opacity` without realizing the potential conflict.
2. **Misunderstanding `fill-mode`:**  The `ForwardsFillDiscarding` test emphasizes the importance of `fill-mode: forwards`. Developers might incorrectly assume that older animations will continue to influence the element's style even after they've finished, without explicitly setting `fill-mode: forwards`.
    * **Example Error:** A developer expects an animation with `fill-mode: none` to leave the element in its final animated state, but that's not the default behavior.
3. **Incorrect Animation Timing:** Developers might have issues with the start times and durations of their animations, leading to unexpected behavior. While not directly tested here, the setup with `Play` and setting `startTime` is a fundamental aspect of animation control.
4. **Forgetting to Update the Timeline:** In a manual testing context (or even within complex animation logic), forgetting to advance the animation timeline can lead to confusion about why animations aren't progressing as expected. The `UpdateTimeline` helper function in the test fixture mimics this progression.

In summary, `effect_stack_test.cc` is a crucial component of the Blink rendering engine's testing infrastructure. It ensures the correct behavior of the `EffectStack`, which is fundamental to how CSS animations are managed and applied in the browser. The tests cover various scenarios related to animation ordering, lifecycle, and property application, providing confidence in the reliability of the animation implementation.

Prompt: 
```
这是目录为blink/renderer/core/animation/effect_stack_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/effect_stack.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/animation_test_helpers.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/interpolable_length.h"
#include "third_party/blink/renderer/core/animation/invalidatable_interpolation.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

namespace blink {

using animation_test_helpers::EnsureInterpolatedValueCached;

class AnimationEffectStackTest : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    GetDocument().GetAnimationClock().ResetTimeForTesting();
    timeline = GetDocument().Timeline();
    element = GetDocument().CreateElementForBinding(AtomicString("foo"));
  }

  Animation* Play(KeyframeEffect* effect, double start_time) {
    Animation* animation = timeline->Play(effect);
    animation->setStartTime(
        MakeGarbageCollected<V8CSSNumberish>(start_time * 1000),
        ASSERT_NO_EXCEPTION);
    animation->Update(kTimingUpdateOnDemand);
    return animation;
  }

  void UpdateTimeline(base::TimeDelta time) {
    GetDocument().GetAnimationClock().UpdateTime(
        GetDocument().Timeline().CalculateZeroTime() + time);
    timeline->ServiceAnimations(kTimingUpdateForAnimationFrame);
  }

  size_t SampledEffectCount() {
    return element->EnsureElementAnimations()
        .GetEffectStack()
        .sampled_effects_.size();
  }

  KeyframeEffectModelBase* MakeEffectModel(CSSPropertyID id,
                                           const String& value) {
    StringKeyframeVector keyframes(2);
    keyframes[0] = MakeGarbageCollected<StringKeyframe>();
    keyframes[0]->SetOffset(0.0);
    keyframes[0]->SetCSSPropertyValue(
        id, value, SecureContextMode::kInsecureContext, nullptr);
    keyframes[1] = MakeGarbageCollected<StringKeyframe>();
    keyframes[1]->SetOffset(1.0);
    keyframes[1]->SetCSSPropertyValue(
        id, value, SecureContextMode::kInsecureContext, nullptr);
    return MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  }

  InertEffect* MakeInertEffect(KeyframeEffectModelBase* effect) {
    Timing timing;
    timing.fill_mode = Timing::FillMode::BOTH;
    return MakeGarbageCollected<InertEffect>(
        effect, timing, animation_test_helpers::TestAnimationProxy());
  }

  KeyframeEffect* MakeKeyframeEffect(KeyframeEffectModelBase* effect,
                                     double duration = 10) {
    Timing timing;
    timing.fill_mode = Timing::FillMode::BOTH;
    timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(duration);
    return MakeGarbageCollected<KeyframeEffect>(element.Get(), effect, timing);
  }

  double GetFontSizeValue(
      const ActiveInterpolationsMap& active_interpolations) {
    ActiveInterpolations* interpolations =
        active_interpolations.at(PropertyHandle(GetCSSPropertyFontSize()));
    EnsureInterpolatedValueCached(interpolations, GetDocument(), element);

    const auto* typed_value =
        To<InvalidatableInterpolation>(*interpolations->at(0))
            .GetCachedValueForTesting();
    // font-size is stored as an |InterpolableLength|; here we assume pixels.
    EXPECT_TRUE(typed_value->GetInterpolableValue().IsLength());
    const InterpolableLength& length =
        To<InterpolableLength>(typed_value->GetInterpolableValue());
    return length.CreateCSSValue(Length::ValueRange::kAll)->GetDoubleValue();
  }

  double GetZIndexValue(const ActiveInterpolationsMap& active_interpolations) {
    ActiveInterpolations* interpolations =
        active_interpolations.at(PropertyHandle(GetCSSPropertyZIndex()));
    EnsureInterpolatedValueCached(interpolations, GetDocument(), element);

    const auto* typed_value =
        To<InvalidatableInterpolation>(*interpolations->at(0))
            .GetCachedValueForTesting();
    // z-index is stored as a straight number value.
    EXPECT_TRUE(typed_value->GetInterpolableValue().IsNumber());
    return To<InterpolableNumber>(&typed_value->GetInterpolableValue())
        ->Value(CSSToLengthConversionData(/*element=*/nullptr));
  }

  Persistent<DocumentTimeline> timeline;
  Persistent<Element> element;
};

TEST_F(AnimationEffectStackTest, ElementAnimationsSorted) {
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "1px")),
       10);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "2px")),
       15);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "3px")), 5);
  ActiveInterpolationsMap result = EffectStack::ActiveInterpolations(
      &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
      KeyframeEffect::kDefaultPriority);
  EXPECT_EQ(1u, result.size());
  EXPECT_EQ(GetFontSizeValue(result), 3);
}

TEST_F(AnimationEffectStackTest, NewAnimations) {
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "1px")),
       15);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kZIndex, "2")), 10);
  HeapVector<Member<const InertEffect>> new_animations;
  InertEffect* inert1 =
      MakeInertEffect(MakeEffectModel(CSSPropertyID::kFontSize, "3px"));
  InertEffect* inert2 =
      MakeInertEffect(MakeEffectModel(CSSPropertyID::kZIndex, "4"));
  new_animations.push_back(inert1);
  new_animations.push_back(inert2);
  ActiveInterpolationsMap result = EffectStack::ActiveInterpolations(
      &element->GetElementAnimations()->GetEffectStack(), &new_animations,
      nullptr, KeyframeEffect::kDefaultPriority);
  EXPECT_EQ(2u, result.size());
  EXPECT_EQ(GetFontSizeValue(result), 3);
  EXPECT_EQ(GetZIndexValue(result), 4);
}

TEST_F(AnimationEffectStackTest, CancelledAnimations) {
  HeapHashSet<Member<const Animation>> cancelled_animations;
  Animation* animation = Play(
      MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "1px")), 0);
  cancelled_animations.insert(animation);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kZIndex, "2")), 0);
  ActiveInterpolationsMap result = EffectStack::ActiveInterpolations(
      &element->GetElementAnimations()->GetEffectStack(), nullptr,
      &cancelled_animations, KeyframeEffect::kDefaultPriority);
  EXPECT_EQ(1u, result.size());
  EXPECT_EQ(GetZIndexValue(result), 2);
}

TEST_F(AnimationEffectStackTest, ClearedEffectsRemoved) {
  Animation* animation = Play(
      MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "1px")), 10);
  ActiveInterpolationsMap result = EffectStack::ActiveInterpolations(
      &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
      KeyframeEffect::kDefaultPriority);
  EXPECT_EQ(1u, result.size());
  EXPECT_EQ(GetFontSizeValue(result), 1);

  animation->setEffect(nullptr);
  result = EffectStack::ActiveInterpolations(
      &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
      KeyframeEffect::kDefaultPriority);
  EXPECT_EQ(0u, result.size());
}

TEST_F(AnimationEffectStackTest, ForwardsFillDiscarding) {
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "1px")), 2);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "2px")), 6);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kFontSize, "3px")), 4);
  GetDocument().GetPendingAnimations().Update(nullptr);

  // Because we will be forcing a naive GC that assumes there are no Oilpan
  // objects on the stack (e.g. passes BlinkGC::kNoHeapPointersOnStack), we have
  // to keep the ActiveInterpolationsMap in a Persistent.
  Persistent<ActiveInterpolationsMap> interpolations;

  UpdateTimeline(base::Seconds(11));
  ThreadState::Current()->CollectAllGarbageForTesting();
  interpolations = MakeGarbageCollected<ActiveInterpolationsMap>(
      EffectStack::ActiveInterpolations(
          &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
          KeyframeEffect::kDefaultPriority));
  EXPECT_EQ(1u, interpolations->size());
  EXPECT_EQ(GetFontSizeValue(*interpolations), 3);
  EXPECT_EQ(3u, SampledEffectCount());

  UpdateTimeline(base::Seconds(13));
  ThreadState::Current()->CollectAllGarbageForTesting();
  interpolations = MakeGarbageCollected<ActiveInterpolationsMap>(
      EffectStack::ActiveInterpolations(
          &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
          KeyframeEffect::kDefaultPriority));
  EXPECT_EQ(1u, interpolations->size());
  EXPECT_EQ(GetFontSizeValue(*interpolations), 3);
  EXPECT_EQ(3u, SampledEffectCount());

  UpdateTimeline(base::Seconds(15));
  ThreadState::Current()->CollectAllGarbageForTesting();
  interpolations = MakeGarbageCollected<ActiveInterpolationsMap>(
      EffectStack::ActiveInterpolations(
          &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
          KeyframeEffect::kDefaultPriority));
  EXPECT_EQ(1u, interpolations->size());
  EXPECT_EQ(GetFontSizeValue(*interpolations), 3);
  EXPECT_EQ(2u, SampledEffectCount());

  UpdateTimeline(base::Seconds(17));
  ThreadState::Current()->CollectAllGarbageForTesting();
  interpolations = MakeGarbageCollected<ActiveInterpolationsMap>(
      EffectStack::ActiveInterpolations(
          &element->GetElementAnimations()->GetEffectStack(), nullptr, nullptr,
          KeyframeEffect::kDefaultPriority));
  EXPECT_EQ(1u, interpolations->size());
  EXPECT_EQ(GetFontSizeValue(*interpolations), 3);
  EXPECT_EQ(1u, SampledEffectCount());
}

TEST_F(AnimationEffectStackTest, AffectsPropertiesCSSBitsetDefaultPriority) {
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kColor, "red")), 10);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kTop, "1px")), 10);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kLeft, "1px")), 10);

  ASSERT_TRUE(element->GetElementAnimations());
  const EffectStack& effect_stack =
      element->GetElementAnimations()->GetEffectStack();

  EXPECT_FALSE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kBackgroundColor}),
      KeyframeEffect::kDefaultPriority));
  EXPECT_FALSE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kBackgroundColor, CSSPropertyID::kFontSize}),
      KeyframeEffect::kDefaultPriority));
  EXPECT_FALSE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kColor}), KeyframeEffect::kTransitionPriority));

  EXPECT_TRUE(effect_stack.AffectsProperties(CSSBitset({CSSPropertyID::kColor}),
                                             KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(effect_stack.AffectsProperties(CSSBitset({CSSPropertyID::kTop}),
                                             KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(effect_stack.AffectsProperties(CSSBitset({CSSPropertyID::kLeft}),
                                             KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kColor, CSSPropertyID::kRight}),
      KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kColor, CSSPropertyID::kTop}),
      KeyframeEffect::kDefaultPriority));
  EXPECT_FALSE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kColor}), KeyframeEffect::kTransitionPriority));
}

TEST_F(AnimationEffectStackTest, AffectsPropertiesCSSBitsetTransitionPriority) {
  Element* body = GetDocument().body();
  body->SetInlineStyleProperty(CSSPropertyID::kTransition, "color 10s");
  body->SetInlineStyleProperty(CSSPropertyID::kColor, "red");
  UpdateAllLifecyclePhasesForTest();

  body->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");
  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(body->GetElementAnimations());
  const EffectStack& effect_stack =
      body->GetElementAnimations()->GetEffectStack();

  EXPECT_FALSE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kColor}), KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kColor}), KeyframeEffect::kTransitionPriority));
  EXPECT_FALSE(effect_stack.AffectsProperties(
      CSSBitset({CSSPropertyID::kBackgroundColor}),
      KeyframeEffect::kTransitionPriority));
}

TEST_F(AnimationEffectStackTest, AffectedPropertiesDefaultPriority) {
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kColor, "red")), 10);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kTop, "1px")), 10);
  Play(MakeKeyframeEffect(MakeEffectModel(CSSPropertyID::kLeft, "1px")), 10);

  ASSERT_TRUE(element->GetElementAnimations());
  const EffectStack& effect_stack =
      element->GetElementAnimations()->GetEffectStack();

  EXPECT_TRUE(
      effect_stack.AffectedProperties(KeyframeEffect::kTransitionPriority)
          .empty());

  auto set = effect_stack.AffectedProperties(KeyframeEffect::kDefaultPriority);
  ASSERT_EQ(3u, set.size());
  EXPECT_TRUE(set.Contains(PropertyHandle(GetCSSPropertyColor())));
  EXPECT_TRUE(set.Contains(PropertyHandle(GetCSSPropertyTop())));
  EXPECT_TRUE(set.Contains(PropertyHandle(GetCSSPropertyLeft())));
}

TEST_F(AnimationEffectStackTest, AffectedPropertiesTransitionPriority) {
  Element* body = GetDocument().body();
  body->SetInlineStyleProperty(CSSPropertyID::kTransition, "color 10s");
  body->SetInlineStyleProperty(CSSPropertyID::kColor, "red");
  UpdateAllLifecyclePhasesForTest();

  body->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");
  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(body->GetElementAnimations());
  const EffectStack& effect_stack =
      body->GetElementAnimations()->GetEffectStack();

  EXPECT_TRUE(effect_stack.AffectedProperties(KeyframeEffect::kDefaultPriority)
                  .empty());

  auto set =
      effect_stack.AffectedProperties(KeyframeEffect::kTransitionPriority);
  ASSERT_EQ(1u, set.size());
  EXPECT_TRUE(set.Contains(PropertyHandle(GetCSSPropertyColor())));
}

}  // namespace blink

"""

```
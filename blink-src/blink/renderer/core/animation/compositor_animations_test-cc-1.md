Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is a part of a test file for the Blink rendering engine, specifically focusing on compositor animations.

Here's a breakdown of the code's functionality:

1. **Testing Compositing of CSS Paint API Animations:** The first test case `TestCSSPaintAPI` verifies if animations applied to custom properties used in the CSS Paint API can be offloaded to the compositor. It checks various scenarios like supported and unsupported property types, side effects, and implicit initial values.

2. **Testing Conversion of Animation Timings for Compositor:** Several test cases (`ConvertTimingForCompositorStartDelay`, `ConvertTimingForCompositorIterationStart`, etc.) focus on the `ConvertTimingForCompositor` function. This function likely translates the animation timing parameters from the CSSOM representation to the compositor's representation. These tests cover different aspects of timing like start delay, iteration start, iteration count, and direction.

3. **Testing if Effects Can Start on the Compositor Based on Timing Functions:**  The `CanStartEffectOnCompositorTimingFunction...` test cases examine whether an animation effect can be run on the compositor based on the timing function used (linear, cubic, steps).

4. **Testing if Effects Can Start on the Compositor for Specific CSS Properties:** The `CanStartElementOnCompositorEffect...` tests check if animations of specific CSS properties (like opacity, filter, transform) can be composited. They consider factors like the property itself, the target element's compositing state, and potential side effects.

5. **Testing Force Reduced Motion:** The `ForceReduceMotion...` test cases verify the behavior of animations when the "prefers-reduced-motion" setting is enabled, potentially forcing animations to snap to keyframes instead of smoothly transitioning. It also considers the `<meta name='supports-reduced-motion'>` tag.

6. **Testing the `CheckCanStartEffectOnCompositor` Function:**  Several tests use the `CheckCanStartEffectOnCompositor` function to determine if an animation can be run on the compositor. These tests cover scenarios with valid and invalid (non-animatable or non-compositable) CSS properties.

7. **Testing Reporting of Unsupported CSS Properties:** The `CheckCanStartEffectOnCompositorUnsupportedCSSProperties` test verifies that the system correctly identifies and reports CSS properties that cannot be composited.

**Relationship to Javascript, HTML, and CSS:**

* **CSS:** The tests directly deal with CSS properties (opacity, transform, filter, custom properties) and animation timing functions. They check how these CSS features interact with the compositor.
* **Javascript:**  While the test is in C++, it simulates scenarios that would be initiated or controlled by Javascript. For example, setting animation properties via Javascript would lead to the kind of internal processing being tested here. The `V8CSSNumberish` type suggests interaction with the V8 Javascript engine.
* **HTML:** The tests manipulate HTML elements and their styles. They create elements, apply animations, and check their composited behavior. The use of `SetBodyInnerHTML` demonstrates HTML manipulation.

**Logical Reasoning (Assumptions and Potential Input/Output):**

* **Assumption:** The `CreateReplaceOpKeyframe` function creates keyframes for animation.
* **Assumption:** The `CreateKeyframeListAndTestIsCandidateOnResult` and `CheckKeyframeVector` functions determine if a set of keyframes is suitable for compositing.
* **Input (for `CreateKeyframeListAndTestIsCandidateOnResult`):** Two `StringKeyframe` objects representing the start and end states of an animation for a specific CSS property.
* **Output (for `CreateKeyframeListAndTestIsCandidateOnResult`):**  A value indicating whether the animation can be composited (e.g., `CompositorAnimations::kNoFailure` or flags indicating reasons for failure like `CompositorAnimations::kUnsupportedCSSProperty`).

**Common User/Programming Errors:**

* **Animating non-animatable CSS properties:** Users might try to animate properties like `display` or `position: static`, which cannot be smoothly transitioned. The tests check for this.
* **Animating properties with side effects in Paint Worklets incorrectly:** As shown in the `TestCSSPaintAPI` case, animating a custom property in a paint worklet that affects another unrelated property can prevent compositing.
* **Incorrect timing parameter values:**  Setting very large or invalid values for animation delays or durations could cause issues. The tests for `ConvertTimingForCompositorStartDelay` explore edge cases.
* **Assuming all transforms are compositable on all elements:**  Transforms on inline elements might not be compositable, as demonstrated in the `CanStartElementOnCompositorEffectInvalid` test.
* **Not understanding the limitations of `prefers-reduced-motion`:** Developers might not realize how this setting affects animation behavior, leading to unexpected snapping instead of smooth transitions. The `ForceReduceMotion` tests highlight this.
这是对 `blink/renderer/core/animation/compositor_animations_test.cc` 文件中第二部分代码的功能归纳。

**总体功能归纳:**

这部分代码主要专注于测试 Blink 渲染引擎中将 CSS 动画效果转移到合成器线程执行的能力，即“合成动画”。它涵盖了以下几个方面的测试：

1. **CSS Paint API 的动画合成：**  测试了当 CSS 动画应用于 CSS Paint API 中使用的自定义属性时，是否能够正确地在合成器线程上运行。这包括测试支持的属性类型（如颜色），不支持的属性类型（如长度），以及由于副作用导致无法合成的情况。

2. **动画时间信息的转换：** 测试了 `ConvertTimingForCompositor` 函数，该函数负责将 CSS 动画的时间参数（如延迟、迭代次数、方向等）转换为合成器线程可以理解的格式。这部分测试了各种时间参数组合以及边界情况。

3. **基于时间函数的动画效果启动：**  测试了 `CanStartEffectOnCompositor` 函数，该函数判断是否可以将动画效果转移到合成器线程执行，重点关注了不同的时间函数（如线性、缓动、步进）对合成的影响。

4. **特定 CSS 属性的动画效果启动：**  测试了不同 CSS 属性（如 `opacity`、`filter`、`transform` 等）的动画是否能在合成器线程启动。这包括检查属性本身是否支持合成，以及目标元素是否满足合成的条件。

5. **强制降低动画效果（Force Reduce Motion）：**  测试了当用户设置了“降低动画效果”时，动画的执行行为。这部分测试验证了动画是否会跳过中间帧直接到达关键帧，以及 `<meta name='supports-reduced-motion'>` 标签对这种行为的影响。

6. **`CheckCanStartEffectOnCompositor` 函数的测试：**  进一步测试了 `CheckCanStartEffectOnCompositor` 函数，验证其在不同场景下（例如，动画属性不可动画或不可合成）的判断逻辑。

7. **不支持的 CSS 属性的报告：**  测试了当动画包含无法在合成器线程执行的 CSS 属性时，系统是否能正确地识别并报告这些属性。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:** 代码直接测试了 CSS 动画的特性，例如 `@keyframes` 规则中定义的属性变化和时间函数。测试了不同 CSS 属性是否可以被合成。
    * **举例:** 测试了自定义属性 `--foo` 的动画，以及 `opacity`、`filter`、`transform` 等标准 CSS 属性的动画合成能力。
* **JavaScript:** 虽然测试代码是 C++，但它模拟了 JavaScript 通过 CSSOM 操作动画的场景。例如，测试中创建了 `StringKeyframe` 对象，这类似于 JavaScript 中通过 `element.animate()` 或 CSSStyleSheet API 创建动画效果。`V8CSSNumberish` 的使用也暗示了与 V8 引擎的交互。
    * **举例:**  通过 `animation->setCurrentTime()` 方法设置动画的当前时间，这类似于在 JavaScript 中操作动画的 `currentTime` 属性。
* **HTML:**  测试代码创建和操作 HTML 元素，并对这些元素应用动画。
    * **举例:** 使用 `SetBodyInnerHTML` 创建带有 `animation` 样式的 `div` 元素。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一组 `StringKeyframe` 对象，代表动画的关键帧，以及一个 `Timing` 对象，描述动画的播放时间参数。
* **输出:** `CreateKeyframeListAndTestIsCandidateOnResult` 函数会返回一个枚举值，指示该动画是否适合在合成器线程执行，以及失败的原因（例如 `CompositorAnimations::kNoFailure` 表示可以合成，`CompositorAnimations::kUnsupportedCSSProperty` 表示包含不支持的 CSS 属性）。

**用户或编程常见的使用错误举例说明:**

* **尝试动画无法合成的 CSS 属性:**  用户可能会尝试动画类似 `width` 或 `height` 这样的属性，但这些属性的动画可能无法直接在合成器线程执行，导致性能问题或动画不流畅。测试中就包含了对这些属性的测试。
* **在 Paint Worklet 中使用有副作用的自定义属性动画:**  如果一个 Paint Worklet 的自定义属性动画影响了其他元素的渲染，可能导致无法进行合成优化。测试中用 `--foo` 影响 `opacity` 的例子说明了这一点。
* **不理解 `prefers-reduced-motion` 的影响:**  开发者可能没有考虑到用户开启了“降低动画效果”的设置，导致动画行为与预期不符（例如，本应平滑过渡的动画直接跳到关键帧）。

**功能归纳:**

这部分测试代码的主要功能是 **验证 Blink 渲染引擎是否能够正确地判断和执行可以转移到合成器线程的 CSS 动画，并针对各种 CSS 属性、时间参数、以及特殊场景（如 CSS Paint API 和强制降低动画效果）进行细致的测试，确保动画性能和用户体验。**

Prompt: 
```
这是目录为blink/renderer/core/animation/compositor_animations_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ator::CSSPaintImageGeneratorCreateFunction>
      scoped_create_function(
          CSSPaintImageGenerator::GetCreateFunctionForTesting(),
          ProvideOverrideGenerator);

  mock_generator->AddCustomProperty(AtomicString("--foo"));
  mock_generator->AddCustomProperty(AtomicString("--bar"));
  mock_generator->AddCustomProperty(AtomicString("--loo"));
  mock_generator->AddCustomProperty(AtomicString("--y"));
  mock_generator->AddCustomProperty(AtomicString("--z"));
  auto* ident =
      MakeGarbageCollected<CSSCustomIdentValue>(AtomicString("foopainter"));
  CSSPaintValue* paint_value = MakeGarbageCollected<CSSPaintValue>(ident);
  paint_value->CreateGeneratorForTesting(GetDocument());
  StyleGeneratedImage* style_image = MakeGarbageCollected<StyleGeneratedImage>(
      *paint_value, StyleGeneratedImage::ContainerSizes());

  ComputedStyleBuilder builder(*style);
  builder.AddPaintImage(style_image);
  element_->GetLayoutObject()->SetStyle(builder.TakeStyle());

  // The image is added for testing off-thread paint worklet supporting
  // custom property animation case. The style doesn't have a real
  // PaintImage, so we cannot call UpdateAllLifecyclePhasesForTest. But the
  // PaintArtifactCompositor requires NeedsUpdate to be false.
  // In the real world when a PaintImage does exist in the style, the life
  // cycle will be updated automatically and we don't have to worry about
  // this.
  auto* paint_artifact_compositor =
      GetDocument().View()->GetPaintArtifactCompositor();
  paint_artifact_compositor->ClearNeedsUpdateForTesting();

  ON_CALL(*mock_generator, IsImageGeneratorReady()).WillByDefault(Return(true));
  StringKeyframe* keyframe1 = CreateReplaceOpKeyframe("--foo", "10", 0);
  StringKeyframe* keyframe2 = CreateReplaceOpKeyframe("--foo", "20", 1);
  EXPECT_EQ(CreateKeyframeListAndTestIsCandidateOnResult(keyframe1, keyframe2),
            CompositorAnimations::kNoFailure);

  // Color-valued properties are supported
  StringKeyframe* color_keyframe1 =
      CreateReplaceOpKeyframe("--loo", "rgb(0, 255, 0)", 0);
  StringKeyframe* color_keyframe2 =
      CreateReplaceOpKeyframe("--loo", "rgb(0, 0, 255)", 1);
  EXPECT_EQ(CreateKeyframeListAndTestIsCandidateOnResult(color_keyframe1,
                                                         color_keyframe2),
            CompositorAnimations::kNoFailure);

  // Length-valued properties are not compositable.
  StringKeyframe* non_animatable_keyframe1 =
      CreateReplaceOpKeyframe("--bar", "10px", 0);
  StringKeyframe* non_animatable_keyframe2 =
      CreateReplaceOpKeyframe("--bar", "20px", 1);
  EXPECT_TRUE(CreateKeyframeListAndTestIsCandidateOnResult(
                  non_animatable_keyframe1, non_animatable_keyframe2) &
              CompositorAnimations::kUnsupportedCSSProperty);

  // Cannot composite due to side effect.
  SetCustomProperty("opacity", "var(--foo)");
  EXPECT_TRUE(
      CreateKeyframeListAndTestIsCandidateOnResult(keyframe1, keyframe2) &
      CompositorAnimations::kUnsupportedCSSProperty);

  // Cannot composite because "--x" is not used by the paint worklet.
  StringKeyframe* non_used_keyframe1 = CreateReplaceOpKeyframe("--x", "5", 0);
  StringKeyframe* non_used_keyframe2 = CreateReplaceOpKeyframe("--x", "15", 1);

  EXPECT_EQ(CreateKeyframeListAndTestIsCandidateOnResult(non_used_keyframe1,
                                                         non_used_keyframe2),
            CompositorAnimations::kUnsupportedCSSProperty);

  // Implicitly initial values are supported.
  StringKeyframe* y_keyframe = CreateReplaceOpKeyframe("--y", "1000", 1);
  StringKeyframeVector keyframe_vector;
  keyframe_vector.push_back(y_keyframe);
  EXPECT_EQ(CheckKeyframeVector(keyframe_vector),
            CompositorAnimations::kNoFailure);

  // Implicitly initial values are not supported when the property
  // has been referenced.
  SetCustomProperty("opacity", "var(--z)");
  StringKeyframe* z_keyframe = CreateReplaceOpKeyframe("--z", "1000", 1);
  StringKeyframeVector keyframe_vector2;
  keyframe_vector2.push_back(z_keyframe);
  EXPECT_EQ(CheckKeyframeVector(keyframe_vector2),
            CompositorAnimations::kUnsupportedCSSProperty);
}

TEST_P(AnimationCompositorAnimationsTest,
       ConvertTimingForCompositorStartDelay) {
  const double play_forward = 1;
  const double play_reverse = -1;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(20);

  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(2.0));
  EXPECT_TRUE(
      ConvertTimingForCompositor(timing_, compositor_timing_, play_forward));
  EXPECT_DOUBLE_EQ(-2.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_TRUE(
      ConvertTimingForCompositor(timing_, compositor_timing_, play_reverse));
  EXPECT_DOUBLE_EQ(0.0, compositor_timing_.scaled_time_offset.InSecondsF());

  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-2.0));
  EXPECT_TRUE(
      ConvertTimingForCompositor(timing_, compositor_timing_, play_forward));
  EXPECT_DOUBLE_EQ(2.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_TRUE(
      ConvertTimingForCompositor(timing_, compositor_timing_, play_reverse));
  EXPECT_DOUBLE_EQ(0.0, compositor_timing_.scaled_time_offset.InSecondsF());

  // Stress test with an effectively infinite start delay.
  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1e19));
  EXPECT_FALSE(
      ConvertTimingForCompositor(timing_, compositor_timing_, play_forward));
}

TEST_P(AnimationCompositorAnimationsTest,
       ConvertTimingForCompositorIterationStart) {
  timing_.iteration_start = 2.2;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
}

TEST_P(AnimationCompositorAnimationsTest,
       ConvertTimingForCompositorIterationCount) {
  timing_.iteration_count = 5.0;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(5, compositor_timing_.adjusted_iteration_count);

  timing_.iteration_count = 5.5;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(5.5, compositor_timing_.adjusted_iteration_count);

  timing_.iteration_count = std::numeric_limits<double>::infinity();
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(std::numeric_limits<double>::infinity(),
            compositor_timing_.adjusted_iteration_count);

  timing_.iteration_count = std::numeric_limits<double>::infinity();
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(5);
  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-6.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(6.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_EQ(std::numeric_limits<double>::infinity(),
            compositor_timing_.adjusted_iteration_count);
}

TEST_P(AnimationCompositorAnimationsTest,
       ConvertTimingForCompositorIterationsAndStartDelay) {
  timing_.iteration_count = 4.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(5);

  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(6.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(-6.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_DOUBLE_EQ(4.0, compositor_timing_.adjusted_iteration_count);

  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-6.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(6.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_DOUBLE_EQ(4.0, compositor_timing_.adjusted_iteration_count);

  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(21.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
}

TEST_P(AnimationCompositorAnimationsTest, ConvertTimingForCompositorDirection) {
  timing_.direction = Timing::PlaybackDirection::NORMAL;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(compositor_timing_.direction, Timing::PlaybackDirection::NORMAL);

  timing_.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(compositor_timing_.direction,
            Timing::PlaybackDirection::ALTERNATE_NORMAL);

  timing_.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(compositor_timing_.direction,
            Timing::PlaybackDirection::ALTERNATE_REVERSE);

  timing_.direction = Timing::PlaybackDirection::REVERSE;
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_EQ(compositor_timing_.direction, Timing::PlaybackDirection::REVERSE);
}

TEST_P(AnimationCompositorAnimationsTest,
       ConvertTimingForCompositorDirectionIterationsAndStartDelay) {
  timing_.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;
  timing_.iteration_count = 4.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(5);
  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-6.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(6.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_EQ(4, compositor_timing_.adjusted_iteration_count);
  EXPECT_EQ(compositor_timing_.direction,
            Timing::PlaybackDirection::ALTERNATE_NORMAL);

  timing_.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;
  timing_.iteration_count = 4.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(5);
  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-11.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(11.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_EQ(4, compositor_timing_.adjusted_iteration_count);
  EXPECT_EQ(compositor_timing_.direction,
            Timing::PlaybackDirection::ALTERNATE_NORMAL);

  timing_.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;
  timing_.iteration_count = 4.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(5);
  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-6.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(6.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_EQ(4, compositor_timing_.adjusted_iteration_count);
  EXPECT_EQ(compositor_timing_.direction,
            Timing::PlaybackDirection::ALTERNATE_REVERSE);

  timing_.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;
  timing_.iteration_count = 4.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(5);
  timing_.start_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(-11.0));
  EXPECT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));
  EXPECT_DOUBLE_EQ(11.0, compositor_timing_.scaled_time_offset.InSecondsF());
  EXPECT_EQ(4, compositor_timing_.adjusted_iteration_count);
  EXPECT_EQ(compositor_timing_.direction,
            Timing::PlaybackDirection::ALTERNATE_REVERSE);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionLinear) {
  timing_.timing_function = linear_timing_function_;
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionCubic) {
  timing_.timing_function = cubic_ease_timing_function_;
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);

  timing_.timing_function = cubic_custom_timing_function_;
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionSteps) {
  timing_.timing_function = step_timing_function_;
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionChainedLinear) {
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorNonLinearTimingFunctionOnFirstOrLastFrame) {
  keyframe_vector2_->at(0)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_animation_effect2_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector2_);

  keyframe_vector5_->at(3)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_animation_effect5_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);

  timing_.timing_function = cubic_ease_timing_function_;
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);

  timing_.timing_function = cubic_custom_timing_function_;
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartElementOnCompositorEffectOpacity) {
  // Check that we got something effectively different.
  StringKeyframeVector key_frames = CreateDefaultKeyframeVector(
      CSSPropertyID::kOpacity, EffectModel::kCompositeReplace);
  KeyframeEffectModelBase* animation_effect =
      MakeGarbageCollected<StringKeyframeEffectModel>(key_frames);

  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);

  // The first animation for opacity is ok to run on compositor.
  auto* keyframe_effect1 =
      MakeGarbageCollected<KeyframeEffect>(element_, animation_effect, timing);
  Animation* animation = timeline_->Play(keyframe_effect1);
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();
  animation_effect->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(),
                                                              style, nullptr);

  // Now we can check that we are set up correctly.
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing, *element_.Get(), animation,
                                            *animation_effect),
            CompositorAnimations::kNoFailure);

  // Timings have to be convertible for compositor.
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing, *element_.Get(), animation,
                                            *animation_effect),
            CompositorAnimations::kNoFailure);
  timing.end_delay = Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(1.0));
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing, *element_.Get(),
                                              animation, *animation_effect) &
              CompositorAnimations::kEffectHasUnsupportedTimingParameters);
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing, *element_.Get(),
                                              animation, *animation_effect) &
              (CompositorAnimations::kTargetHasInvalidCompositingState |
               CompositorAnimations::kEffectHasUnsupportedTimingParameters));
}

TEST_P(AnimationCompositorAnimationsTest, ForceReduceMotion) {
  ScopedForceReduceMotionForTest force_reduce_motion(true);
  GetDocument().GetSettings()->SetPrefersReducedMotion(true);
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes slide {
        0% { transform: translateX(100px); }
        50% { transform: translateX(200px); }
        100% { transform: translateX(300px); }
      }
      html, body {
        margin: 0;
      }
    </style>
    <div id='test' style='animation: slide 2s linear'></div>
  )HTML");
  element_ = GetDocument().getElementById(AtomicString("test"));
  Animation* animation = element_->getAnimations()[0];

  // The effect should snap between keyframes at the halfway points.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(450),
                            ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(element_->GetBoundingClientRect()->x(), 100.0, 0.001);
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(550),
                            ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(element_->GetBoundingClientRect()->x(), 200.0, 0.001);
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(1450),
                            ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(element_->GetBoundingClientRect()->x(), 200.0, 0.001);
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(1550),
                            ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(element_->GetBoundingClientRect()->x(), 300.0, 0.001);
}

TEST_P(AnimationCompositorAnimationsTest,
       ForceReduceMotionDocumentSupportsReduce) {
  ScopedForceReduceMotionForTest force_reduce_motion(true);
  GetDocument().GetSettings()->SetPrefersReducedMotion(true);
  SetBodyInnerHTML(R"HTML(
    <meta name='supports-reduced-motion' content='reduce'>
    <style>
      @keyframes slide {
        0% { transform: translateX(100px); }
        100% { transform: translateX(200px); }
      }
      html, body {
        margin: 0;
      }
    </style>
    <div id='test' style='animation: slide 1s linear'></div>
  )HTML");
  element_ = GetDocument().getElementById(AtomicString("test"));
  Animation* animation = element_->getAnimations()[0];

  // As the page has indicated support for reduce motion, the effect should not
  // jump to the nearest keyframe.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(500),
                            ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(element_->GetBoundingClientRect()->x(), 150.0, 0.001);
}

TEST_P(AnimationCompositorAnimationsTest,
       ForceReduceMotionChildDocumentSupportsReduce) {
  ScopedForceReduceMotionForTest force_reduce_motion(true);
  GetDocument().GetSettings()->SetPrefersReducedMotion(true);
  SetBodyInnerHTML(R"HTML(
    <iframe></iframe>
    <style>
      @keyframes slide {
        0% { transform: translateX(100px); }
        100% { transform: translateX(200px); }
      }
      html, body {
        margin: 0;
      }
    </style>
    <div id='parent-anim' style='animation: slide 1s linear'></div>
    )HTML");
  SetChildFrameHTML(R"HTML(
    <meta name='supports-reduced-motion' content='reduce'>
    <style>
      @keyframes slide {
        0% { transform: translateX(100px); }
        100% { transform: translateX(200px); }
      }
      html, body {
        margin: 0;
      }
    </style>
    <div id='child-anim' style='animation: slide 1s linear'></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  element_ = GetDocument().getElementById(AtomicString("parent-anim"));
  Animation* animation = element_->getAnimations()[0];

  // As the parent document does not support reduce motion, the effect will jump
  // to the nearest keyframe.
  animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(400),
                            ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(element_->GetBoundingClientRect()->x(), 100.0, 0.001);

  // As the child document does support reduce motion, its animation will not be
  // snapped.
  Element* child_element =
      ChildDocument().getElementById(AtomicString("child-anim"));
  Animation* child_animation = child_element->getAnimations()[0];
  child_animation->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(400),
                                  ASSERT_NO_EXCEPTION);
  EXPECT_NEAR(child_element->GetBoundingClientRect()->x(), 140.0, 0.001);
}

TEST_P(AnimationCompositorAnimationsTest, CheckCanStartForceReduceMotion) {
  ScopedForceReduceMotionForTest force_reduce_motion(true);
  GetDocument().GetSettings()->SetPrefersReducedMotion(true);
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "translateX(100px)"),
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "translateX(200px)",
                              1));

  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(2);
  auto* keyframe_effect =
      MakeGarbageCollected<KeyframeEffect>(element_, effect, timing);
  Animation* animation = timeline_->Play(keyframe_effect);
  // The animation should not run on the compositor since we are forcing reduced
  // motion.
  EXPECT_NE(CheckCanStartEffectOnCompositor(timing_, *element_.Get(), animation,
                                            *effect),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartElementOnCompositorEffectInvalid) {
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();

  // Check that we notice the value is not animatable correctly.
  const CSSProperty& target_property1(GetCSSPropertyOutlineStyle());
  PropertyHandle target_property1h(target_property1);
  StringKeyframeEffectModel* effect1 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(target_property1.PropertyID(), "dotted", 0),
      CreateReplaceOpKeyframe(target_property1.PropertyID(), "dashed", 1.0));

  auto* keyframe_effect1 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect1, timing_);

  Animation* animation1 = timeline_->Play(keyframe_effect1);
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  const auto& keyframes1 =
      *effect1->GetPropertySpecificKeyframes(target_property1h);
  EXPECT_EQ(2u, keyframes1.size());
  EXPECT_FALSE(keyframes1[0]->GetCompositorKeyframeValue());
  EXPECT_EQ(1u, effect1->Properties().size());
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                              animation1, *effect1) &
              CompositorAnimations::kUnsupportedCSSProperty);

  // Check that we notice transform is not animatable correctly on an inline.
  const CSSProperty& target_property2(GetCSSPropertyScale());
  PropertyHandle target_property2h(target_property2);
  StringKeyframeEffectModel* effect2 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(target_property2.PropertyID(), "1", 0),
      CreateReplaceOpKeyframe(target_property2.PropertyID(), "3", 1.0));

  auto* keyframe_effect2 =
      MakeGarbageCollected<KeyframeEffect>(inline_.Get(), effect2, timing_);

  Animation* animation2 = timeline_->Play(keyframe_effect2);
  effect2->SnapshotAllCompositorKeyframesIfNecessary(*inline_.Get(), style,
                                                     nullptr);

  const auto& keyframes2 =
      *effect2->GetPropertySpecificKeyframes(target_property2h);
  EXPECT_EQ(2u, keyframes2.size());
  EXPECT_TRUE(keyframes2[0]->GetCompositorKeyframeValue());
  EXPECT_EQ(1u, effect2->Properties().size());
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *inline_.Get(),
                                              animation2, *effect2) &
              CompositorAnimations::
                  kTransformRelatedPropertyCannotBeAcceleratedOnTarget);

  // Check that we notice the Property is not animatable correctly.
  // These ones claim to have animatable values, but we can't composite
  // the property. We also don't know the ID domain.
  const CSSProperty& target_property3(GetCSSPropertyWidth());
  PropertyHandle target_property3h(target_property3);
  StringKeyframeEffectModel* effect3 = CreateKeyframeEffectModel(
      CreateMockReplaceKeyframe(target_property3.PropertyID(), "10px", 0.0),
      CreateMockReplaceKeyframe(target_property3.PropertyID(), "20px", 1.0));

  auto* keyframe_effect3 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect3, timing_);

  Animation* animation3 = timeline_->Play(keyframe_effect3);
  effect3->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  const auto& keyframes3 =
      *effect3->GetPropertySpecificKeyframes(target_property3h);
  EXPECT_EQ(2u, keyframes3.size());
  EXPECT_TRUE(keyframes3[0]->GetCompositorKeyframeValue());
  EXPECT_EQ(1u, effect3->Properties().size());
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                              animation3, *effect3) &
              CompositorAnimations::kUnsupportedCSSProperty);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartElementOnCompositorEffectFilter) {
  // Filter Properties use a different ID namespace
  StringKeyframeEffectModel* effect1 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kFilter, "none", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kFilter, "sepia(50%)", 1.0));

  auto* keyframe_effect1 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect1, timing_);

  Animation* animation1 = timeline_->Play(keyframe_effect1);
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  // Now we can check that we are set up correctly.
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                            animation1, *effect1),
            CompositorAnimations::kNoFailure);

  // Filters that affect neighboring pixels can't be composited.
  StringKeyframeEffectModel* effect2 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kFilter, "none", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kFilter, "blur(10px)", 1.0));

  auto* keyframe_effect2 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect2, timing_);

  Animation* animation2 = timeline_->Play(keyframe_effect2);
  effect2->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                              animation2, *effect2) &
              CompositorAnimations::kFilterRelatedPropertyMayMovePixels);

  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                              animation2, *effect2) &
              (CompositorAnimations::kFilterRelatedPropertyMayMovePixels |
               CompositorAnimations::kTargetHasInvalidCompositingState));
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartElementOnCompositorEffectTransform) {
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();

  StringKeyframeEffectModel* effect1 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "none", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "rotate(45deg)", 1.0));

  auto* keyframe_effect1 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect1, timing_);

  Animation* animation1 = timeline_->Play(keyframe_effect1);
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  // Check if our layout object is not TransformApplicable
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *inline_.Get(),
                                              animation1, *effect1) &
              CompositorAnimations::
                  kTransformRelatedPropertyCannotBeAcceleratedOnTarget);
}

TEST_P(AnimationCompositorAnimationsTest,
       CheckCanStartEffectOnCompositorUnsupportedCSSProperties) {
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();

  StringKeyframeEffectModel* effect1 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "1", 1));

  auto* keyframe_effect1 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect1, timing_);

  Animation* animation1 = timeline_->Play(keyframe_effect1);
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  // Make sure supported properties do not register a failure
  PropertyHandleSet unsupported_properties1;
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing_, *inline_.Get(), animation1,
                                            *effect1, &unsupported_properties1),
            CompositorAnimations::kNoFailure);
  EXPECT_TRUE(unsupported_properties1.empty());

  StringKeyframeEffectModel* effect2 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kHeight, "100px", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kHeight, "200px", 1));

  auto* keyframe_effect2 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect2, timing_);

  Animation* animation2 = timeline_->Play(keyframe_effect2);
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  // Make sure unsupported properties are reported
  PropertyHandleSet unsupported_properties2;
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *inline_.Get(),
                                              animation2, *effect2,
                                              &unsupported_properties2) &
              CompositorAnimations::kUnsupportedCSSProperty);
  EXPECT_EQ(unsupported_properties2.size(), 1U);
  EXPECT_EQ(
      unsupported_properties2.begin()->GetCSSPropertyName().ToAtomicString(),
      "height");

  StringKeyframeEffectModel* effect3 =
      MakeGarbageCollected<StringKeyframeEffectModel>(StringKeyframeVector({
          CreateReplaceOpKeyframe(CSSPropertyID::kHeight, "100px", 0),
          CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0", 0),
          CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "translateY(0)",
                                  0),
          CreateReplaceOpKeyframe(CSSPropertyID::kFilter, "grayscale(50%)", 0),
          CreateReplaceOpKeyframe(CSSPropertyID::kHeight, "200px", 1),
          CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "1", 1),
          CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "translateY(50px)",
                                  1),
          CreateReplaceOpKeyframe(CSSPropertyID::kFilter, "grayscale(100%)", 1),
      }));

  auto* keyframe_effect3 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect3, timing_);

  Animation* animation3 = timeline_->Play(keyframe_effect3);
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);

  // Make sure only the unsupported properties are reported
  PropertyHandleSet unsupported_properties3;
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing_, *inline_.Get(),
                                              animation3, *effect3,
                                              &unsupported_properties3) &
              CompositorAnimations::kUnsupportedCSSProperty);
  EXPECT_EQ(unsupported_properties3.size(), 1U);
  EXPECT_EQ(
      unsupported_properties3.begin()->GetCSSPropertyName().ToAtomicString(),
      "height");
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionChainedCubicMatchingOffsets) {
  keyframe_vector2_->at(0)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_animation_effect2_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector2_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);

  keyframe_vector2_->at(0)->SetEasing(cubic_custom_timing_function_.get());
  keyframe_animation_effect2_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector2_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effec
"""


```
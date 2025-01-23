Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code is a part of the Chromium Blink engine and seems to be testing the `CompositorAnimations` functionality.

Here's a breakdown of the code and its functionality:

1. **Test Setup and Keyframe Creation:** The code uses the `TEST_P` macro, suggesting it's a parameterized test. It sets up various keyframe vectors (`keyframe_vector2_`, `keyframe_vector5_`, etc.) with different easing functions and CSS properties. These keyframes define animation steps.

2. **`CanStartEffectOnCompositor` Tests:** Several tests use `CanStartEffectOnCompositor` to determine if an animation effect can be run on the compositor thread. This is crucial for performance as compositor animations can run independently of the main thread, leading to smoother animations.

3. **Timing Function Tests:** The code tests different timing functions (linear, ease, custom cubic bezier, step) and their combinations to see if they can be handled by the compositor.

4. **Basic vs. Non-basic Animations:** The code distinguishes between "basic" and "non-basic" animations, likely referring to whether the animation can be directly handled by the compositor without main thread involvement. It tests scenarios with composite modes like `kCompositeReplace` and `kCompositeAdd`.

5. **Non-CSS Property Animations:** There's a test involving SVG attributes, which are non-CSS properties, to see how `CanStartEffectOnCompositor` handles them.

6. **`ConvertToCompositorAnimation` Tests:**  These tests convert Blink's animation data structures (`KeyframeEffectModel`) into Chromium's compositor animation structures (`cc::KeyframeModel`). It checks various aspects of the converted animation, such as:
    - Target property (e.g., opacity).
    - Iteration count.
    - Time offset (start delay).
    - Playback direction (normal, alternate).
    - Playback rate.
    - Keyframe times and values.
    - Timing functions applied to keyframes.
    - Fill mode.

7. **Custom Property Animations:** The code includes tests for CSS custom properties (variables), including number and color types. It also tests cases where a custom property might have mixed types in its animation.

8. **`CancelIncompatibleCompositorAnimations` Test:** This test simulates a scenario where two animations target the same property, but the second animation cannot be run on the compositor. It verifies that the compositor animation for the first animation is canceled when the second incompatible animation starts.

9. **Compositing Reasons and Paint Properties:** The final test checks if an animation can start on the compositor based on the element's paint properties and the reasons for compositing (e.g., active transform animation).

**Overall Function of the Code Snippet:**

This code snippet is part of the unit tests for the `CompositorAnimations` feature in the Chromium Blink engine. Its primary function is to verify the correctness and capabilities of the logic that determines:

- Whether a given CSS animation can be offloaded to the compositor thread for better performance.
- How Blink's animation data structures are converted into the compositor's animation data structures.
- How the system handles conflicting or incompatible animations targeting the same properties.
- How compositing reasons influence the decision of running animations on the compositor.
这是 `blink/renderer/core/animation/compositor_animations_test.cc` 文件的第三部分，主要功能是**测试 Blink 引擎中将 CSS 动画转换为可以在渲染器合成器线程上运行的动画的功能。**  这部分测试主要关注以下几个方面：

**1. 测试 `CanStartEffectOnCompositor` 函数对于不同动画场景的判断：**

* **Timing Function 的组合：**  测试了当动画的关键帧使用不同的 timing function 时，`CanStartEffectOnCompositor` 是否能正确判断动画是否能在合成器上运行。
    * **假设输入：**  一个包含多个关键帧的动画效果，这些关键帧分别设置了 `linear`, `ease`, 自定义的 `cubic-bezier` 等 timing function。
    * **预期输出：**  `CompositorAnimations::kNoFailure`，表示动画可以在合成器上启动。
* **包含 `step` 或 `frames()` timing function：** 测试了包含 `step` 或 `frames()` timing function 的动画是否可以运行在合成器上。
    * **假设输入：**  一个或多个关键帧设置了 `step` timing function，或者与其他 timing function 混合使用。
    * **预期输出：** `CompositorAnimations::kNoFailure`。
* **基本动画与非基本动画：**  区分了“基本”动画（例如只包含 `opacity` 属性的动画，且使用 `replace` 合成模式）和“非基本”动画。
    * **假设输入 (基本动画)：**  一个 `opacity` 属性的动画，使用 `EffectModel::kCompositeReplace` 合成模式，timing function 使用 `linear` 或 `ease`。
    * **预期输出 (基本动画)：** `CompositorAnimations::kNoFailure`。
    * **假设输入 (非基本动画)：**  一个 `opacity` 属性的动画，但 timing function 在不同关键帧之间不同。
    * **预期输出 (非基本动画)：** `CompositorAnimations::kNoFailure`。
    * **假设输入 (非兼容合成模式)：** 一个 `opacity` 属性的动画，使用 `EffectModel::kCompositeAdd` 合成模式。
    * **预期输出 (非兼容合成模式)：**  结果包含 `CompositorAnimations::kEffectHasNonReplaceCompositeMode`，表示由于使用了非 `replace` 的合成模式，动画无法完全在合成器上运行。
* **影响非 CSS 属性的动画：**  测试了动画影响 SVG 属性等非 CSS 属性时，`CanStartEffectOnCompositor` 的判断。
    * **假设输入：** 一个动画效果作用于 SVG 属性。
    * **预期输出：** 结果包含 `CompositorAnimations::kAnimationAffectsNonCSSProperties`，表示动画影响了非 CSS 属性。

**2. 测试 `ConvertToCompositorAnimation` 函数将 Blink 动画模型转换为合成器动画模型的功能：**

* **简单 `opacity` 动画：**  测试将一个简单的 `opacity` 动画转换为合成器动画模型，并验证转换后的模型的属性，如目标属性、迭代次数、时间偏移、播放方向、播放速率等。同时验证了关键帧的时间、值和 timing function 是否正确转换。
    * **假设输入：**  一个 `opacity` 属性的动画，包含两个关键帧，时间分别为 0 和 1，值分别为 "0.2" 和 "0.5"。
    * **预期输出：**  合成器动画模型的目标属性为 `cc::TargetProperty::OPACITY`，迭代次数为 1，时间偏移为 0，方向为 `cc::KeyframeModel::Direction::NORMAL`，播放速率为 1。关键帧的时间和值被正确转换，timing function 为 `LINEAR`。
* **带持续时间的 `opacity` 动画：** 测试了设置动画持续时间后，关键帧的时间是否被正确计算。
    * **假设输入：**  一个 `opacity` 属性的动画，持续时间为 10 秒。
    * **预期输出：**  合成器动画模型中第二个关键帧的时间为 10 秒。
* **多关键帧 `opacity` 动画：** 测试了包含多个关键帧的 `opacity` 动画的转换，并验证关键帧的数量、时间和值是否正确转换。
    * **假设输入：** 一个包含 4 个关键帧的 `opacity` 动画，时间分别为 0, 0.25, 0.5, 1，值分别为 "0.2", "0.0", "0.25", "0.5"。
    * **预期输出：** 合成器动画模型包含 4 个关键帧，其时间和值被正确转换。
* **带 `start-delay` 的 `opacity` 动画：** 测试了设置 `start-delay` 后，合成器动画模型的时间偏移是否正确。
    * **假设输入：**  一个 `opacity` 属性的动画，`start-delay` 为 3.25 秒。
    * **预期输出：**  合成器动画模型的时间偏移为 -3.25 秒。
* **带有不同关键帧 timing function 的 `opacity` 动画：**  测试了当动画的关键帧设置了不同的 timing function 时，这些 timing function 是否被正确转换到合成器动画模型的关键帧中。
    * **假设输入：**  一个 `opacity` 属性的动画，包含多个关键帧，分别设置了 `ease`, `linear`, 自定义 `cubic-bezier` 等 timing function。
    * **预期输出：**  合成器动画模型中对应的关键帧的 timing function 类型被正确设置。
* **反向播放的 `opacity` 动画：** 测试了 `direction` 属性设置为 `alternate-reverse` 时，合成器动画模型的播放方向是否正确，并且关键帧的 timing function 是否仍然被正确应用。
    * **假设输入：**  一个 `opacity` 属性的动画，`direction` 为 `alternate-reverse`。
    * **预期输出：** 合成器动画模型的方向为 `cc::KeyframeModel::Direction::ALTERNATE_REVERSE`。
* **负 `start-delay` 的反向播放动画：**  测试了当 `start-delay` 为负值且 `direction` 为 `alternate-reverse` 时，合成器动画模型的属性是否正确设置。
    * **假设输入：**  一个 `opacity` 属性的动画，`start-delay` 为 -3 秒，`direction` 为 `alternate-reverse`。
    * **预期输出：** 合成器动画模型的时间偏移为 3 秒，方向为 `cc::KeyframeModel::Direction::ALTERNATE_REVERSE`。
* **`fill-mode` 属性：** 测试了 `fill-mode` 属性对合成器动画模型的影响。
    * **假设输入 (`fill-mode: none` 或 `fill-mode: auto`)：**  一个 `opacity` 属性的动画，`fill-mode` 分别设置为 `none` 和 `auto`。
    * **预期输出：** 合成器动画模型的 `fill_mode` 为 `cc::KeyframeModel::FillMode::FORWARDS`（由于是基于时间的动画，会隐式填充）。
* **全局 timing function：** 测试了当动画本身设置了 timing function 时，合成器动画模型是否使用了这个全局 timing function。
    * **假设输入：**  一个 `opacity` 属性的动画，设置了自定义的 `cubic-bezier` timing function。
    * **预期输出：** 合成器动画模型的曲线 timing function 类型为 `CUBIC_BEZIER`，并且参数与自定义的 timing function 一致。
* **自定义属性动画：** 测试了自定义 CSS 属性（CSS variables）的动画转换，包括非 ASCII 字符的属性名，以及数值和颜色类型的自定义属性。
    * **假设输入 (数值类型)：**  一个自定义属性 `--foo` 的动画，从 "10" 变化到 "20"。
    * **预期输出 (数值类型)：**  合成器动画模型的目标属性为 `cc::TargetProperty::CSS_CUSTOM_PROPERTY`，关键帧的值被转换为浮点数。
    * **假设输入 (颜色类型)：**  一个自定义属性 `--foo` 的动画，从 "rgb(0, 0, 0)" 变化到 "rgb(0, 255, 0)"。
    * **预期输出 (颜色类型)：** 合成器动画模型的目标属性为 `cc::TargetProperty::CSS_CUSTOM_PROPERTY`，关键帧的值被转换为颜色值。
* **混合类型自定义属性动画：** 测试了当自定义属性的动画关键帧包含不同类型的值时的情况。
    * **假设输入：**  一个自定义属性 `--foo` 的动画，关键帧的值分别为数值 "20" 和颜色 "rgb(0, 255, 0)"。
    * **预期输出：**  `CanStartEffectOnCompositor` 的结果包含 `CompositorAnimations::kMixedKeyframeValueTypes`，表示存在混合的关键帧值类型。

**3. 测试 `CancelIncompatibleCompositorAnimations` 函数：**

* **取消不兼容的合成器动画：** 测试了当一个元素上存在一个可以在合成器上运行的动画，然后又添加了一个不能在合成器上运行的动画时，系统会取消之前在合成器上运行的动画，以便回退到 Blink 的实现。
    * **假设输入：**  一个元素上先应用了一个可以合成的 `opacity` 动画，然后又应用了一个无法合成的 `opacity` 动画。
    * **预期输出：**  第二个动画启动时，会取消第一个动画的合成器版本，两个动画都不会在合成器上运行。

**4. 测试基于 Paint Properties 判断是否可以在合成器上启动动画：**

* **基于 Transform 的合成原因：** 测试了当一个元素因为 Transform 属性的动画而进行合成时，可以启动针对该元素的合成器动画。
    * **假设输入：**  一个元素的 Paint Properties 中因为 `CompositingReason::kActiveTransformAnimation` 而存在 Transform 节点。
    * **预期输出：**  `CheckCanStartElementOnCompositor` 返回 `CompositorAnimations::kNoFailure`。
* **移除合成原因：** 测试了当元素的合成原因被移除后，无法启动合成器动画。
    * **假设输入：**  一个元素的 Paint Properties 中 Transform 节点的合成原因被设置为 `CompositingReason::kNone`。
    * **预期输出：** `CheckCanStartElementOnCompositor` 的结果包含 `CompositorAnimations::kTargetHasInvalidCompositingState`。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关系到 CSS 动画在浏览器中的实现方式。

* **CSS：** 测试涵盖了各种 CSS 动画属性，如 `opacity`、`timing-function`、`start-delay`、`direction`、`fill-mode` 以及 CSS 自定义属性。测试确保了 Blink 引擎能够正确解析和处理这些 CSS 属性，并将它们转换为可以在合成器上运行的动画。
    * **举例：**  `TEST_P(AnimationCompositorAnimationsTest, CreateSimpleOpacityAnimation)` 测试了 `opacity: 0.2 to 0.5` 这样的 CSS 动画是否能被正确转换为合成器动画。
* **JavaScript：** 虽然代码本身是 C++，但它测试的功能与通过 JavaScript 操作 CSS 动画密切相关。例如，通过 JavaScript 的 `element.animate()` API 或 CSSOM 操作创建的动画最终会经过 Blink 引擎的处理，而这里的测试就验证了这部分处理的正确性。
    * **举例：** 当 JavaScript 代码创建了一个带有特定 `easing` 函数的动画时，`TEST_P(AnimationCompositorAnimationsTest, CanStartEffectOnCompositorTimingFunctionMixedGood)` 就验证了 Blink 是否能识别并允许这样的动画在合成器上运行。
* **HTML：**  HTML 元素是动画的目标。测试中创建了 `Element` 对象，模拟了 HTML 元素应用动画的场景。

**逻辑推理的假设输入与输出：**

在 `CanStartEffectOnCompositor` 的测试中，逻辑推理主要基于动画的属性（如目标属性、合成模式、timing function）来判断是否满足在合成器上运行的条件。

* **假设输入：** 一个 `transform` 属性的动画，使用了 `cubic-bezier` timing function 和 `replace` 合成模式。
* **逻辑推理：**  `transform` 属性通常可以在合成器上运行，`cubic-bezier` 也是支持的 timing function，`replace` 合成模式也是允许的。
* **预期输出：** `CanStartEffectOnCompositor` 返回 `CompositorAnimations::kNoFailure`。

**用户或编程常见的使用错误举例：**

* **尝试合成不支持的属性动画：** 用户可能会尝试对一些性能敏感或复杂的属性（例如 `filter` 的某些子属性）进行动画，而这些属性可能无法完全在合成器上运行。测试会覆盖这些情况，确保 Blink 引擎能正确处理回退逻辑。
* **混合使用不支持的 timing function：**  虽然测试中展示了混合使用 timing function 的场景，但用户可能会无意中使用了 Blink 合成器不支持的 timing function 组合，导致动画无法在合成器上运行，性能下降。
* **错误地使用合成模式：**  如果用户为一个可以合成的属性设置了 `add` 或其他非 `replace` 的合成模式，可能会阻止动画在合成器上运行。`TEST_P(AnimationCompositorAnimationsTest, CanStartEffectOnCompositorBasic)` 中就测试了这种情况。

**总结一下它的功能（作为第 3 部分）：**

这部分测试代码的核心功能是**验证 Blink 引擎在将 CSS 动画转换为合成器动画方面的能力和正确性**。它涵盖了各种动画场景，包括不同类型的 timing function、合成模式、目标属性以及自定义属性，并测试了转换过程中关键属性的映射和处理。此外，还测试了在存在不兼容动画时，Blink 引擎的取消和回退机制，以及基于元素合成原因来判断是否可以启动合成器动画的逻辑。  这部分测试是确保浏览器动画性能和流畅度的重要组成部分。

### 提示词
```
这是目录为blink/renderer/core/animation/compositor_animations_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
t2_),
            CompositorAnimations::kNoFailure);

  keyframe_vector5_->at(0)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_vector5_->at(1)->SetEasing(cubic_custom_timing_function_.get());
  keyframe_vector5_->at(2)->SetEasing(cubic_custom_timing_function_.get());
  keyframe_vector5_->at(3)->SetEasing(cubic_custom_timing_function_.get());
  keyframe_animation_effect5_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionMixedGood) {
  keyframe_vector5_->at(0)->SetEasing(linear_timing_function_.get());
  keyframe_vector5_->at(1)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_vector5_->at(2)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_vector5_->at(3)->SetEasing(linear_timing_function_.get());
  keyframe_animation_effect5_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorTimingFunctionWithStepOrFrameOkay) {
  keyframe_vector2_->at(0)->SetEasing(step_timing_function_.get());
  keyframe_animation_effect2_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector2_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect2_),
            CompositorAnimations::kNoFailure);

  keyframe_vector5_->at(0)->SetEasing(step_timing_function_.get());
  keyframe_vector5_->at(1)->SetEasing(linear_timing_function_.get());
  keyframe_vector5_->at(2)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_animation_effect5_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);

  keyframe_vector5_->at(1)->SetEasing(step_timing_function_.get());
  keyframe_vector5_->at(2)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_vector5_->at(3)->SetEasing(linear_timing_function_.get());
  keyframe_animation_effect5_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);

  keyframe_vector5_->at(0)->SetEasing(linear_timing_function_.get());
  keyframe_vector5_->at(2)->SetEasing(cubic_ease_timing_function_.get());
  keyframe_vector5_->at(3)->SetEasing(step_timing_function_.get());
  keyframe_animation_effect5_ =
      MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *keyframe_animation_effect5_),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest, CanStartEffectOnCompositorBasic) {
  StringKeyframeVector basic_frames_vector = CreateDefaultKeyframeVector(
      CSSPropertyID::kOpacity, EffectModel::kCompositeReplace);

  StringKeyframeVector non_basic_frames_vector;
  non_basic_frames_vector.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0", 0));
  non_basic_frames_vector.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 0.5));
  non_basic_frames_vector.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "1", 1));

  basic_frames_vector[0]->SetEasing(linear_timing_function_.get());
  auto* basic_frames =
      MakeGarbageCollected<StringKeyframeEffectModel>(basic_frames_vector);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *basic_frames),
            CompositorAnimations::kNoFailure);

  basic_frames_vector[0]->SetEasing(CubicBezierTimingFunction::Preset(
      CubicBezierTimingFunction::EaseType::EASE_IN));
  basic_frames =
      MakeGarbageCollected<StringKeyframeEffectModel>(basic_frames_vector);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *basic_frames),
            CompositorAnimations::kNoFailure);

  non_basic_frames_vector[0]->SetEasing(linear_timing_function_.get());
  non_basic_frames_vector[1]->SetEasing(CubicBezierTimingFunction::Preset(
      CubicBezierTimingFunction::EaseType::EASE_IN));
  auto* non_basic_frames =
      MakeGarbageCollected<StringKeyframeEffectModel>(non_basic_frames_vector);
  EXPECT_EQ(CanStartEffectOnCompositor(timing_, *non_basic_frames),
            CompositorAnimations::kNoFailure);

  StringKeyframeVector non_allowed_frames_vector = CreateDefaultKeyframeVector(
      CSSPropertyID::kOpacity, EffectModel::kCompositeAdd);
  auto* non_allowed_frames = MakeGarbageCollected<StringKeyframeEffectModel>(
      non_allowed_frames_vector);
  EXPECT_TRUE(CanStartEffectOnCompositor(timing_, *non_allowed_frames) &
              CompositorAnimations::kEffectHasNonReplaceCompositeMode);

  // Set SVGAttribute keeps a pointer to this thing for the lifespan of
  // the Keyframe.  This is ugly but sufficient to work around it.
  QualifiedName fake_name(AtomicString("prefix"), AtomicString("local"),
                          AtomicString("uri"));

  StringKeyframeVector non_css_frames_vector;
  non_css_frames_vector.push_back(CreateSVGKeyframe(fake_name, "cargo", 0.0));
  non_css_frames_vector.push_back(CreateSVGKeyframe(fake_name, "Fargo", 1.0));
  auto* non_css_frames =
      MakeGarbageCollected<StringKeyframeEffectModel>(non_css_frames_vector);
  EXPECT_TRUE(CanStartEffectOnCompositor(timing_, *non_css_frames) &
              CompositorAnimations::kAnimationAffectsNonCSSProperties);
  EXPECT_TRUE(non_css_frames->RequiresPropertyNode());
  // NB: Important that non_css_frames_vector goes away and cleans up
  // before fake_name.
}

// -----------------------------------------------------------------------
// -----------------------------------------------------------------------

TEST_P(AnimationCompositorAnimationsTest, CreateSimpleOpacityAnimation) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(1.0, keyframe_model->iterations());
  EXPECT_EQ(0, keyframe_model->time_offset().InSecondsF());
  EXPECT_EQ(cc::KeyframeModel::Direction::NORMAL, keyframe_model->direction());
  EXPECT_EQ(1.0, keyframe_model->playback_rate());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF());
  EXPECT_EQ(0.2f, keyframes[0]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[0]->timing_function())
                                              ->GetType());

  EXPECT_EQ(1.0, keyframes[1]->Time().InSecondsF());
  EXPECT_EQ(0.5f, keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleOpacityAnimationDuration) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  const AnimationTimeDelta kDuration = ANIMATION_TIME_DELTA_FROM_SECONDS(10);
  timing_.iteration_duration = kDuration;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());

  EXPECT_EQ(kDuration, keyframes[1]->Time().InSecondsF() * kDuration);
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateMultipleKeyframeOpacityAnimationLinear) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.0", 0.25),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.25", 0.5),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  timing_.iteration_count = 5;
  timing_.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect, 2.0);
  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(5.0, keyframe_model->iterations());
  EXPECT_EQ(0, keyframe_model->time_offset().InSecondsF());
  EXPECT_EQ(cc::KeyframeModel::Direction::ALTERNATE_NORMAL,
            keyframe_model->direction());
  EXPECT_EQ(2.0, keyframe_model->playback_rate());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(4UL, keyframes.size());

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF());
  EXPECT_EQ(0.2f, keyframes[0]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[0]->timing_function())
                                              ->GetType());

  EXPECT_EQ(0.25, keyframes[1]->Time().InSecondsF());
  EXPECT_EQ(0, keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());

  EXPECT_EQ(0.5, keyframes[2]->Time().InSecondsF());
  EXPECT_EQ(0.25f, keyframes[2]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[2]->timing_function())
                                              ->GetType());

  EXPECT_EQ(1.0, keyframes[3]->Time().InSecondsF());
  EXPECT_EQ(0.5f, keyframes[3]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[3]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleOpacityAnimationStartDelay) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  const double kStartDelay = 3.25;

  timing_.iteration_count = 5.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1.75);
  timing_.start_delay =
      Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(kStartDelay));

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);

  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(5.0, keyframe_model->iterations());
  EXPECT_EQ(-kStartDelay, keyframe_model->time_offset().InSecondsF());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());

  EXPECT_EQ(1.75, keyframes[1]->Time().InSecondsF() *
                      timing_.iteration_duration->InSecondsF());
  EXPECT_EQ(0.5f, keyframes[1]->Value());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateMultipleKeyframeOpacityAnimationChained) {
  // KeyframeEffect to convert
  StringKeyframeVector frames;
  frames.push_back(CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0));
  frames.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.0", 0.25));
  frames.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.35", 0.5));
  frames.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));
  frames[0]->SetEasing(cubic_ease_timing_function_.get());
  frames[1]->SetEasing(linear_timing_function_.get());
  frames[2]->SetEasing(cubic_custom_timing_function_.get());
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(frames);

  timing_.timing_function = linear_timing_function_.get();
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(2);
  timing_.iteration_count = 10;
  timing_.direction = Timing::PlaybackDirection::ALTERNATE_NORMAL;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(10.0, keyframe_model->iterations());
  EXPECT_EQ(0, keyframe_model->time_offset().InSecondsF());
  EXPECT_EQ(cc::KeyframeModel::Direction::ALTERNATE_NORMAL,
            keyframe_model->direction());
  EXPECT_EQ(1.0, keyframe_model->playback_rate());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(4UL, keyframes.size());

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF() *
                   timing_.iteration_duration->InSecondsF());
  EXPECT_EQ(0.2f, keyframes[0]->Value());
  ExpectKeyframeTimingFunctionCubic(*keyframes[0],
                                    CubicBezierTimingFunction::EaseType::EASE);

  EXPECT_EQ(0.5, keyframes[1]->Time().InSecondsF() *
                     timing_.iteration_duration->InSecondsF());
  EXPECT_EQ(0, keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());

  EXPECT_EQ(1.0, keyframes[2]->Time().InSecondsF() *
                     timing_.iteration_duration->InSecondsF());
  EXPECT_EQ(0.35f, keyframes[2]->Value());
  ExpectKeyframeTimingFunctionCubic(
      *keyframes[2], CubicBezierTimingFunction::EaseType::CUSTOM);

  EXPECT_EQ(2.0, keyframes[3]->Time().InSecondsF() *
                     timing_.iteration_duration->InSecondsF());
  EXPECT_EQ(0.5f, keyframes[3]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[3]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest, CreateReversedOpacityAnimation) {
  scoped_refptr<TimingFunction> cubic_easy_flip_timing_function =
      CubicBezierTimingFunction::Create(0.0, 0.0, 0.0, 1.0);

  // KeyframeEffect to convert
  StringKeyframeVector frames;
  frames.push_back(CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0));
  frames.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.0", 0.25));
  frames.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.25", 0.5));
  frames.push_back(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));
  frames[0]->SetEasing(CubicBezierTimingFunction::Preset(
      CubicBezierTimingFunction::EaseType::EASE_IN));
  frames[1]->SetEasing(linear_timing_function_.get());
  frames[2]->SetEasing(cubic_easy_flip_timing_function.get());
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(frames);

  timing_.timing_function = linear_timing_function_.get();
  timing_.iteration_count = 10;
  timing_.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(10.0, keyframe_model->iterations());
  EXPECT_EQ(0, keyframe_model->time_offset().InSecondsF());
  EXPECT_EQ(cc::KeyframeModel::Direction::ALTERNATE_REVERSE,
            keyframe_model->direction());
  EXPECT_EQ(1.0, keyframe_model->playback_rate());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(4UL, keyframes.size());

  EXPECT_EQ(CreateCompositorTimingFunctionFromCC(
                keyframed_float_curve->timing_function_for_testing())
                ->GetType(),
            TimingFunction::Type::LINEAR);

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF());
  EXPECT_EQ(0.2f, keyframes[0]->Value());
  ExpectKeyframeTimingFunctionCubic(
      *keyframes[0], CubicBezierTimingFunction::EaseType::EASE_IN);

  EXPECT_EQ(0.25, keyframes[1]->Time().InSecondsF());
  EXPECT_EQ(0, keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());

  EXPECT_EQ(0.5, keyframes[2]->Time().InSecondsF());
  EXPECT_EQ(0.25f, keyframes[2]->Value());
  ExpectKeyframeTimingFunctionCubic(
      *keyframes[2], CubicBezierTimingFunction::EaseType::CUSTOM);

  EXPECT_EQ(1.0, keyframes[3]->Time().InSecondsF());
  EXPECT_EQ(0.5f, keyframes[3]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[3]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateReversedOpacityAnimationNegativeStartDelay) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  const double kNegativeStartDelay = -3;

  timing_.iteration_count = 5.0;
  timing_.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1.5);
  timing_.start_delay =
      Timing::Delay(ANIMATION_TIME_DELTA_FROM_SECONDS(kNegativeStartDelay));
  timing_.direction = Timing::PlaybackDirection::ALTERNATE_REVERSE;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(5.0, keyframe_model->iterations());
  EXPECT_EQ(-kNegativeStartDelay, keyframe_model->time_offset().InSecondsF());
  EXPECT_EQ(cc::KeyframeModel::Direction::ALTERNATE_REVERSE,
            keyframe_model->direction());
  EXPECT_EQ(1.0, keyframe_model->playback_rate());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleOpacityAnimationFillModeNone) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  timing_.fill_mode = Timing::FillMode::NONE;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  // Time based animations implicitly fill forwards to remain active until
  // the subsequent commit.
  EXPECT_EQ(cc::KeyframeModel::FillMode::FORWARDS, keyframe_model->fill_mode());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleOpacityAnimationFillModeAuto) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  timing_.fill_mode = Timing::FillMode::AUTO;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::OPACITY, keyframe_model->TargetProperty());
  EXPECT_EQ(1.0, keyframe_model->iterations());
  EXPECT_EQ(0, keyframe_model->time_offset().InSecondsF());
  EXPECT_EQ(cc::KeyframeModel::Direction::NORMAL, keyframe_model->direction());
  EXPECT_EQ(1.0, keyframe_model->playback_rate());
  // Time based animations implicitly fill forwards to remain active until
  // the subsequent commit.
  EXPECT_EQ(cc::KeyframeModel::FillMode::FORWARDS, keyframe_model->fill_mode());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleOpacityAnimationWithTimingFunction) {
  // KeyframeEffect to convert
  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.2", 0),
      CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, "0.5", 1.0));

  timing_.timing_function = cubic_custom_timing_function_;

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  auto curve_timing_function = CreateCompositorTimingFunctionFromCC(
      keyframed_float_curve->timing_function_for_testing());
  EXPECT_EQ(curve_timing_function->GetType(),
            TimingFunction::Type::CUBIC_BEZIER);
  const auto& cubic_timing_function =
      To<CubicBezierTimingFunction>(*curve_timing_function);
  EXPECT_EQ(cubic_timing_function.GetEaseType(),
            CubicBezierTimingFunction::EaseType::CUSTOM);
  EXPECT_EQ(cubic_timing_function.X1(), 1.0);
  EXPECT_EQ(cubic_timing_function.Y1(), 2.0);
  EXPECT_EQ(cubic_timing_function.X2(), 3.0);
  EXPECT_EQ(cubic_timing_function.Y2(), 4.0);

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF());
  EXPECT_EQ(0.2f, keyframes[0]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[0]->timing_function())
                                              ->GetType());

  EXPECT_EQ(1.0, keyframes[1]->Time().InSecondsF());
  EXPECT_EQ(0.5f, keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateCustomFloatPropertyAnimationWithNonAsciiName) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);

  String property_name = "--東京都";
  RegisterProperty(GetDocument(), property_name, "<number>", "0", false);
  SetCustomProperty(property_name, "10");

  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(property_name, "10", 0),
      CreateReplaceOpKeyframe(property_name, "20", 1.0));

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::CSS_CUSTOM_PROPERTY,
            keyframe_model->TargetProperty());
  EXPECT_EQ(keyframe_model->custom_property_name(),
            property_name.Utf8().data());
  EXPECT_FALSE(effect->RequiresPropertyNode());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleCustomFloatPropertyAnimation) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);

  RegisterProperty(GetDocument(), "--foo", "<number>", "0", false);
  SetCustomProperty("--foo", "10");

  StringKeyframeEffectModel* effect =
      CreateKeyframeEffectModel(CreateReplaceOpKeyframe("--foo", "10", 0),
                                CreateReplaceOpKeyframe("--foo", "20", 1.0));

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::CSS_CUSTOM_PROPERTY,
            keyframe_model->TargetProperty());

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve> keyframed_float_curve =
      CreateKeyframedFloatAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::FloatKeyframe>>& keyframes =
      keyframed_float_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF());
  EXPECT_EQ(10, keyframes[0]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[0]->timing_function())
                                              ->GetType());

  EXPECT_EQ(1.0, keyframes[1]->Time().InSecondsF());
  EXPECT_EQ(20, keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest,
       CreateSimpleCustomColorPropertyAnimation) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);

  RegisterProperty(GetDocument(), "--foo", "<color>", "rgb(0, 0, 0)", false);
  SetCustomProperty("--foo", "rgb(0, 0, 0)");

  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe("--foo", "rgb(0, 0, 0)", 0),
      CreateReplaceOpKeyframe("--foo", "rgb(0, 255, 0)", 1.0));

  std::unique_ptr<cc::KeyframeModel> keyframe_model =
      ConvertToCompositorAnimation(*effect);
  EXPECT_EQ(cc::TargetProperty::CSS_CUSTOM_PROPERTY,
            keyframe_model->TargetProperty());

  std::unique_ptr<gfx::KeyframedColorAnimationCurve> keyframed_color_curve =
      CreateKeyframedColorAnimationCurve(keyframe_model.get());

  const std::vector<std::unique_ptr<gfx::ColorKeyframe>>& keyframes =
      keyframed_color_curve->keyframes_for_testing();
  ASSERT_EQ(2UL, keyframes.size());

  EXPECT_EQ(0, keyframes[0]->Time().InSecondsF());
  EXPECT_EQ(SkColorSetRGB(0, 0, 0), keyframes[0]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[0]->timing_function())
                                              ->GetType());

  EXPECT_EQ(1.0, keyframes[1]->Time().InSecondsF());
  EXPECT_EQ(SkColorSetRGB(0, 0xFF, 0), keyframes[1]->Value());
  EXPECT_EQ(TimingFunction::Type::LINEAR, CreateCompositorTimingFunctionFromCC(
                                              keyframes[1]->timing_function())
                                              ->GetType());
}

TEST_P(AnimationCompositorAnimationsTest, MixedCustomPropertyAnimation) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);

  RegisterProperty(GetDocument(), "--foo", "<number> | <color>", "0", false);
  SetCustomProperty("--foo", "0");

  StringKeyframeEffectModel* effect = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe("--foo", "20", 0),
      CreateReplaceOpKeyframe("--foo", "rgb(0, 255, 0)", 1.0));

  EXPECT_TRUE(CanStartEffectOnCompositor(timing_, *effect) &
              CompositorAnimations::kMixedKeyframeValueTypes);
}

TEST_P(AnimationCompositorAnimationsTest,
       CancelIncompatibleCompositorAnimations) {
  Persistent<HeapVector<Member<StringKeyframe>>> key_frames =
      MakeGarbageCollected<HeapVector<Member<StringKeyframe>>>(
          CreateDefaultKeyframeVector(CSSPropertyID::kOpacity,
                                      EffectModel::kCompositeReplace));
  KeyframeEffectModelBase* animation_effect1 =
      MakeGarbageCollected<StringKeyframeEffectModel>(*key_frames);
  KeyframeEffectModelBase* animation_effect2 =
      MakeGarbageCollected<StringKeyframeEffectModel>(*key_frames);

  Timing timing;
  timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);

  // The first animation for opacity is ok to run on compositor.
  auto* keyframe_effect1 = MakeGarbageCollected<KeyframeEffect>(
      element_.Get(), animation_effect1, timing);
  Animation* animation1 = timeline_->Play(keyframe_effect1);
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();
  animation_effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(),
                                                               style, nullptr);
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing, *element_.Get(), animation1,
                                            *animation_effect1),
            CompositorAnimations::kNoFailure);

  // The second animation for opacity is not ok to run on compositor.
  auto* keyframe_effect2 = MakeGarbageCollected<KeyframeEffect>(
      element_.Get(), animation_effect2, timing);
  Animation* animation2 = timeline_->Play(keyframe_effect2);
  animation_effect2->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(),
                                                               style, nullptr);
  EXPECT_TRUE(CheckCanStartEffectOnCompositor(timing, *element_.Get(),
                                              animation2, *animation_effect2) &
              CompositorAnimations::kTargetHasIncompatibleAnimations);
  EXPECT_FALSE(animation2->HasActiveAnimationsOnCompositor());

  // A fallback to blink implementation needed, so cancel all compositor-side
  // opacity animations for this element.
  animation2->CancelIncompatibleAnimationsOnCompositor();

  EXPECT_FALSE(animation1->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation2->HasActiveAnimationsOnCompositor());

  SimulateFrame(0);
  EXPECT_EQ(2U, element_->GetElementAnimations()->Animations().size());

  // After finishing and collecting garbage there should be no
  // ElementAnimations on the element.
  SimulateFrame(1.);
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_TRUE(element_->GetElementAnimations()->Animations().empty());
}

namespace {

void UpdateDummyTransformNode(ObjectPaintProperties& properties,
                              CompositingReasons reasons) {
  TransformPaintPropertyNode::State state;
  state.direct_compositing_reasons = reasons;
  properties.UpdateTransform(TransformPaintPropertyNode::Root(),
                             std::move(state));
}

void UpdateDummyEffectNode(ObjectPaintProperties& properties,
                           CompositingReasons reasons) {
  EffectPaintPropertyNode::State state;
  state.direct_compositing_reasons = reasons;
  properties.UpdateEffect(EffectPaintPropertyNode::Root(), std::move(state));
}

}  // namespace

TEST_P(AnimationCompositorAnimationsTest,
       CanStartElementOnCompositorTransformBasedOnPaintProperties) {
  Persistent<Element> element =
      GetDocument().CreateElementForBinding(AtomicString("shared"));
  LayoutObjectProxy* layout_object = LayoutObjectProxy::Create(element.Get());
  layout_object->EnsureIdForTestingProxy();
  element->SetLayoutObject(layout_object);

  auto& properties = layout_object->GetMutableForPainting()
                         .FirstFragment()
                         .EnsurePaintProperties();

  // Add a transform with a compositing reason, which should allow starting
  // animation.
  UpdateDummyTransformNode(properties,
                           CompositingReason::kActiveTransformAnimation);
  EXPECT_EQ(
      CheckCanStartElementOnCompositor(*element, *keyframe_animation_effect2_),
      CompositorAnimations::kNoFailure);

  // Setting to CompositingReasonNone should produce false.
  UpdateDummyTransformNode(properties, CompositingReason::kNone);
  EXPECT_TRUE(
      CheckCanStartElementOnCompositor(*element, *keyframe_animation_effect2_) &
      CompositorAnimations::kTargetHasInvalidCompositingState);

  // Clearing
```
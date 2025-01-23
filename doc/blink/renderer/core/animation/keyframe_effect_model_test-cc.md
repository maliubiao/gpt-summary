Response:
The user wants me to analyze a C++ source code file (`keyframe_effect_model_test.cc`) from the Chromium Blink engine. Specifically, they want me to:

1. **Describe its functionality.**
2. **Explain its relation to JavaScript, HTML, and CSS**, providing examples.
3. **Illustrate logical reasoning** with input/output examples.
4. **Highlight common usage errors** with examples.
5. **Summarize its function** based on the provided first part of the file.

My plan is to:

1. **Skim the code** to understand the main components being tested. I see `KeyframeEffectModel`, `StringKeyframe`, various `CompositorKeyframe` types, and usage of `gtest`. This strongly suggests it's a unit test file for the `KeyframeEffectModel`.
2. **Focus on the test names** (e.g., `BasicOperation`, `CompositeReplace`, `ExtrapolateReplace`) to infer the specific functionalities being tested.
3. **Identify key classes and methods** being used (e.g., `Sample`, `SetCSSPropertyValue`, `SetComposite`, `SetEasing`).
4. **Relate these tests to web technologies:**
    * **CSS:** Keyframe animations are a core CSS feature. The tests likely verify how different CSS properties and their values are handled during animation.
    * **JavaScript:** JavaScript can manipulate CSS animations, so I'll consider how these tests might relate to JavaScript's animation APIs.
    * **HTML:** Animations are applied to HTML elements, so the tests will likely involve elements.
5. **Construct illustrative examples** of how the tested functionalities manifest in a web context.
6. **Devise hypothetical input/output scenarios** based on the test logic. For example, given keyframes for `left` property, what's the interpolated value at a specific time?
7. **Consider common mistakes:** How might developers misuse CSS animations, and how do these tests relate to preventing those errors?
8. **Synthesize a summary** of the file's purpose based on my analysis of the first part.
这是 Chromium Blink 引擎中 `blink/renderer/core/animation/keyframe_effect_model_test.cc` 文件的第一部分，其主要功能是**测试 `KeyframeEffectModel` 类的功能和行为**。`KeyframeEffectModel` 是 Blink 引擎中负责管理和计算基于关键帧的动画效果的核心组件。

具体来说，从这部分代码中可以看出，该测试文件主要关注以下功能：

**1. 基本的动画插值 (Basic Interpolation):**

* **功能:** 测试在给定时间和关键帧的情况下，`KeyframeEffectModel` 如何计算属性的插值。
* **与 CSS 关系:**  CSS 动画使用 `@keyframes` 规则定义不同时间点的属性值。 `KeyframeEffectModel` 模拟了这个过程，根据时间点在定义的关键帧之间进行插值。
* **举例:**
    * **CSS:**
      ```css
      @keyframes my-animation {
        0% { font-family: serif; }
        100% { font-family: cursive; }
      }
      .element {
        animation: my-animation 1s;
      }
      ```
    * **测试用例 (推断):**  `TEST_F(AnimationKeyframeEffectModel, BasicOperation)` 测试了当动画进行到 60% 时，`font-family` 属性应该被插值为 `cursive` (因为它是结束状态的值，非可插值属性通常直接使用目标值)。
    * **假设输入与输出:**  假设输入时间偏移为 0.6，关键帧定义了 `font-family` 从 `serif` 到 `cursive` 的变化。输出应该是 `cursive`。

**2. 合成操作 (Composite Operations):**

* **功能:** 测试 `KeyframeEffectModel` 如何处理关键帧的合成模式 (`composite`)，例如 `replace` (替换) 和 `add` (添加)。
* **与 CSS 关系:**  CSS 合成操作决定了动画效果如何与元素的原有样式以及其他动画效果进行组合。
* **举例:**
    * **CSS:**
      ```css
      @keyframes move-left {
        0% { left: 3px; }
        100% { left: 5px; }
      }
      .element {
        animation: move-left 1s, another-animation 1s; /* 多个动画可能互相影响 */
      }
      ```
    * **测试用例:**
        * `TEST_F(AnimationKeyframeEffectModel, CompositeReplaceNonInterpolable)` 测试了当合成模式为 `replace` 且属性值不可插值时，如何处理。
        * `TEST_F(AnimationKeyframeEffectModel, CompositeReplace)` 测试了 `replace` 模式下可插值属性的插值计算。
        * `TEST_F(AnimationKeyframeEffectModel, DISABLED_CompositeAdd)` (目前被禁用)  原本应该是测试 `add` 模式下的插值计算，这通常涉及到基于初始值进行增量计算。
    * **假设输入与输出 (CompositeReplace):** 假设关键帧定义了 `left` 从 `3px` 到 `5px` 的变化，合成模式为 `replace`，时间偏移为 0.6。输出应该是 `3px * 0.4 + 5px * 0.6 = 4.2px`。

**3. 缓动函数 (Easing Functions):**

* **功能:** 测试 `KeyframeEffectModel` 如何应用缓动函数来控制动画的速率。
* **与 CSS 关系:** CSS 动画允许指定不同的缓动函数 (例如 `ease-in`, `cubic-bezier`) 来实现不同的动画效果。
* **举例:**
    * **CSS:**
      ```css
      @keyframes my-animation {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      .element {
        animation: my-animation 1s ease-in;
      }
      ```
    * **测试用例:**
        * `TEST_F(AnimationKeyframeEffectModel, CompositeEaseIn)` 测试了 `ease-in` 缓动函数的应用。
        * `TEST_F(AnimationKeyframeEffectModel, CompositeCubicBezier)` 测试了自定义 `cubic-bezier` 缓动函数的应用。
    * **假设输入与输出 (CompositeEaseIn):** 假设关键帧定义了 `left` 从 `3px` 到 `5px` 的变化，缓动函数为 `ease-in`，时间偏移为 0.6。输出应该是基于 `ease-in` 函数计算出的介于 3px 和 5px 之间的值，例如 `3.85824px`。

**4. 动画的超出范围 (Extrapolation):**

* **功能:** 测试当动画时间超出 0 到 1 的范围时，`KeyframeEffectModel` 的行为。
* **与 CSS 关系:** CSS 动画可以通过 `animation-fill-mode` 属性来控制动画在开始之前和结束之后的状态。
* **举例:**
    * **CSS:**
      ```css
      .element {
        animation: my-animation 1s forwards; /* 动画结束后保持结束状态 */
      }
      ```
    * **测试用例:**
        * `TEST_F(AnimationKeyframeEffectModel, ExtrapolateReplaceNonInterpolable)` 测试了超出范围时，不可插值属性在 `replace` 模式下的行为。
        * `TEST_F(AnimationKeyframeEffectModel, ExtrapolateReplace)` 测试了超出范围时，可插值属性在 `replace` 模式下的插值计算。
    * **假设输入与输出 (ExtrapolateReplace):** 假设关键帧定义了 `left` 从 `3px` 到 `5px` 的变化，时间偏移为 1.6。输出应该是基于线性插值的超出范围的值，例如 `3px * -0.6 + 5px * 1.6 = 6.2px`。

**5. 关键帧的数量和位置 (Number and Position of Keyframes):**

* **功能:** 测试不同数量和偏移的关键帧对动画效果的影响。
* **与 CSS 关系:**  CSS 动画允许定义任意数量的关键帧，每个关键帧可以设置不同的偏移量。
* **测试用例:**
    * `TEST_F(AnimationKeyframeEffectModel, ZeroKeyframes)` 测试了没有关键帧的情况。
    * `TEST_F(AnimationKeyframeEffectModel, DISABLED_SingleKeyframeAtOffsetZero)` 和 `TEST_F(AnimationKeyframeEffectModel, DISABLED_SingleKeyframeAtOffsetOne)` (目前被禁用) 测试了只有一个关键帧的情况。
    * `TEST_F(AnimationKeyframeEffectModel, MoreThanTwoKeyframes)` 测试了超过两个关键帧的情况。
    * `TEST_F(AnimationKeyframeEffectModel, EndKeyframeOffsetsUnspecified)` 测试了未指定偏移量的关键帧。
    * `TEST_F(AnimationKeyframeEffectModel, SampleOnKeyframe)` 测试了在关键帧时间点采样时的结果。
    * `TEST_F(AnimationKeyframeEffectModel, MultipleKeyframesWithSameOffset)` 测试了具有相同偏移量的多个关键帧。

**6. 每关键帧的合成 (Per-Keyframe Composite):**

* **功能:** 测试在单个关键帧上设置合成模式的效果。
* **与 CSS 关系:** CSS 允许在关键帧级别设置合成模式，虽然这不如在整个动画上设置常见。
* **测试用例:** `TEST_F(AnimationKeyframeEffectModel, DISABLED_PerKeyframeComposite)` (目前被禁用)  原本应该是测试在第二个关键帧上设置 `composite: add` 的效果。

**7. 多个属性动画 (Multiple Properties):**

* **功能:** 测试 `KeyframeEffectModel` 如何处理同时动画多个 CSS 属性的情况。
* **与 CSS 关系:** CSS 动画可以同时改变多个属性。
* **举例:**
    * **CSS:**
      ```css
      @keyframes multi-prop {
        0% { opacity: 0; transform: translateX(0); }
        100% { opacity: 1; transform: translateX(100px); }
      }
      .element {
        animation: multi-prop 1s;
      }
      ```
    * **测试用例:** `TEST_F(AnimationKeyframeEffectModel, MultipleProperties)` 测试了同时动画 `font-family` 和 `font-synthesis-weight` 属性。

**8. 多次迭代 (Multiple Iterations):**

* **功能:** 测试动画循环播放时的行为。
* **与 CSS 关系:** CSS 动画可以使用 `animation-iteration-count` 属性设置循环次数。
* **测试用例:** `TEST_F(AnimationKeyframeEffectModel, MultipleIterations)` 测试了在不同迭代次数下的动画状态。

**9. 依赖于底层值 (Depends On Underlying Value):**

* **功能:**  测试当动画的合成模式为 `add` 且关键帧值相同时，`KeyframeEffectModel` 是否正确地依赖于元素的初始值。
* **与 CSS 关系:** `composite: add` 意味着动画值是相对于元素的当前值的增量。
* **测试用例:** `TEST_F(AnimationKeyframeEffectModel, DISABLED_DependsOnUnderlyingValue)` (目前被禁用)  原本应该是测试当关键帧的 `left` 值都为 `1px` 且合成模式为 `add` 时，在不同时间点的行为。

**10. 添加合成关键帧 (Add Synthetic Keyframes):**

* **功能:** 测试 `KeyframeEffectModel` 是否会在必要时自动添加起始和结束的关键帧，以确保动画的完整性。
* **与 CSS 关系:**  当 CSS 动画只定义了中间的关键帧时，浏览器会自动推断起始和结束状态。
* **测试用例:** `TEST_F(AnimationKeyframeEffectModel, AddSyntheticKeyframes)` 测试了当只定义了一个偏移量为 0.5 的关键帧时，是否会生成偏移量为 0 和 1 的合成关键帧。

**11. 类型转换 (ToKeyframeEffectModel):**

* **功能:**  测试 `KeyframeEffectModel` 对象是否可以安全地转换为其基类 `EffectModel`。这通常用于多态场景。

**用户或编程常见的使用错误示例 (推断):**

* **未定义关键帧:** 如果 CSS 动画的 `@keyframes` 规则为空，`KeyframeEffectModel` 可能会返回默认值或不进行任何动画。 `TEST_F(AnimationKeyframeEffectModel, ZeroKeyframes)` 就是在测试这种情况。
* **关键帧偏移量错误:**  如果关键帧的偏移量未排序或超出 0-1 的范围，可能会导致意外的动画效果。虽然这段代码没有直接测试这种情况，但 `KeyframeEffectModel` 需要能够处理这些错误。
* **合成模式理解错误:**  错误地使用 `composite: add` 而不考虑元素的初始值，可能导致动画效果不符合预期。 `TEST_F(AnimationKeyframeEffectModel, DISABLED_DependsOnUnderlyingValue)` 的存在暗示了这种潜在的错误。
* **缓动函数使用不当:**  使用复杂的缓动函数可能导致性能问题或难以理解的动画效果。测试用例中对不同缓动函数的测试有助于确保 `KeyframeEffectModel` 对这些情况的处理是正确的。

**总结一下它的功能 (基于第一部分):**

该文件的主要功能是为 Blink 引擎中的 `KeyframeEffectModel` 类提供全面的单元测试。它测试了该模型在各种场景下的行为，包括基本的插值、不同的合成模式、缓动函数的应用、超出动画范围的情况、不同数量和位置的关键帧，以及处理多个属性动画的能力。这些测试旨在确保 `KeyframeEffectModel` 能够准确地模拟和计算 CSS 关键帧动画的效果。

### 提示词
```
这是目录为blink/renderer/core/animation/keyframe_effect_model_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/animation/animation_test_helpers.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_color.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_double.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_transform.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_value_factory.h"
#include "third_party/blink/renderer/core/animation/css_default_interpolation_type.h"
#include "third_party/blink/renderer/core/animation/interpolable_length.h"
#include "third_party/blink/renderer/core/animation/invalidatable_interpolation.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/skia/include/core/SkColor.h"

namespace blink {

using animation_test_helpers::EnsureInterpolatedValueCached;

class AnimationKeyframeEffectModel : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    GetDocument().UpdateStyleAndLayoutTree();
    element = GetDocument().CreateElementForBinding(AtomicString("foo"));
    GetDocument().body()->appendChild(element);
  }

  void ExpectLengthValue(double expected_value,
                         Interpolation* interpolation_value) {
    ActiveInterpolations* interpolations =
        MakeGarbageCollected<ActiveInterpolations>();
    interpolations->push_back(interpolation_value);
    EnsureInterpolatedValueCached(interpolations, GetDocument(), element);

    const auto* typed_value =
        To<InvalidatableInterpolation>(interpolation_value)
            ->GetCachedValueForTesting();
    // Length values are stored as an |InterpolableLength|; here we assume
    // pixels.
    ASSERT_TRUE(typed_value->GetInterpolableValue().IsLength());
    const InterpolableLength& length =
        To<InterpolableLength>(typed_value->GetInterpolableValue());
    // Lengths are computed in logical units, which are quantized to 64ths of
    // a pixel.
    EXPECT_NEAR(
        expected_value,
        length.CreateCSSValue(Length::ValueRange::kAll)->GetDoubleValue(),
        /*abs_error=*/0.02);
  }

  void ExpectNonInterpolableValue(const String& expected_value,
                                  Interpolation* interpolation_value) {
    ActiveInterpolations* interpolations =
        MakeGarbageCollected<ActiveInterpolations>();
    interpolations->push_back(interpolation_value);
    EnsureInterpolatedValueCached(interpolations, GetDocument(), element);

    const auto* typed_value =
        To<InvalidatableInterpolation>(interpolation_value)
            ->GetCachedValueForTesting();
    const NonInterpolableValue* non_interpolable_value =
        typed_value->GetNonInterpolableValue();
    ASSERT_TRUE(IsA<CSSDefaultNonInterpolableValue>(non_interpolable_value));

    const CSSValue* css_value =
        To<CSSDefaultNonInterpolableValue>(non_interpolable_value)->CssValue();
    EXPECT_EQ(expected_value, css_value->CssText());
  }

  Persistent<Element> element;
};

const AnimationTimeDelta kDuration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);

StringKeyframeVector KeyframesAtZeroAndOne(CSSPropertyID property,
                                           const String& zero_value,
                                           const String& one_value) {
  StringKeyframeVector keyframes(2);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(
      property, zero_value, SecureContextMode::kInsecureContext, nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(1.0);
  keyframes[1]->SetCSSPropertyValue(
      property, one_value, SecureContextMode::kInsecureContext, nullptr);
  return keyframes;
}

StringKeyframeVector KeyframesAtZeroAndOne(AtomicString property_name,
                                           const String& zero_value,
                                           const String& one_value) {
  StringKeyframeVector keyframes(2);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(
      property_name, zero_value, SecureContextMode::kInsecureContext, nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(1.0);
  keyframes[1]->SetCSSPropertyValue(
      property_name, one_value, SecureContextMode::kInsecureContext, nullptr);
  return keyframes;
}

const PropertySpecificKeyframeVector& ConstructEffectAndGetKeyframes(
    const char* property_name,
    const char* type,
    Document* document,
    Element* element,
    const String& zero_value,
    const String& one_value,
    ExceptionState& exception_state) {
  AtomicString property_name_string(property_name);
  css_test_helpers::RegisterProperty(*document, property_name_string,
                                     AtomicString(type), zero_value, false);

  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(property_name_string, zero_value, one_value);

  element->style()->setProperty(document->GetExecutionContext(),
                                property_name_string, zero_value,
                                g_empty_string, exception_state);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);

  const auto* style =
      document->GetStyleResolver().ResolveStyle(element, StyleRecalcContext());

  // Snapshot should update first time after construction
  EXPECT_TRUE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *element, *style, nullptr));

  return *effect->GetPropertySpecificKeyframes(
      PropertyHandle(property_name_string));
}

void ExpectProperty(CSSPropertyID property,
                    Interpolation* interpolation_value) {
  auto* interpolation = To<InvalidatableInterpolation>(interpolation_value);
  const PropertyHandle& property_handle = interpolation->GetProperty();
  ASSERT_TRUE(property_handle.IsCSSProperty());
  ASSERT_EQ(property, property_handle.GetCSSProperty().PropertyID());
}

Interpolation* FindValue(HeapVector<Member<Interpolation>>& values,
                         CSSPropertyID id) {
  for (auto& value : values) {
    const auto& property =
        To<InvalidatableInterpolation>(value.Get())->GetProperty();
    if (property.IsCSSProperty() &&
        property.GetCSSProperty().PropertyID() == id)
      return value.Get();
  }
  return nullptr;
}

TEST_F(AnimationKeyframeEffectModel, BasicOperation) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kFontFamily, "serif", "cursive");
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ASSERT_EQ(1UL, values.size());
  ExpectProperty(CSSPropertyID::kFontFamily, values.at(0));
  ExpectNonInterpolableValue("cursive", values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, CompositeReplaceNonInterpolable) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kFontFamily, "serif", "cursive");
  keyframes[0]->SetComposite(EffectModel::kCompositeReplace);
  keyframes[1]->SetComposite(EffectModel::kCompositeReplace);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("cursive", values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, CompositeReplace) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  keyframes[0]->SetComposite(EffectModel::kCompositeReplace);
  keyframes[1]->SetComposite(EffectModel::kCompositeReplace);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(3.0 * 0.4 + 5.0 * 0.6, values.at(0));
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_CompositeAdd) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  keyframes[0]->SetComposite(EffectModel::kCompositeAdd);
  keyframes[1]->SetComposite(EffectModel::kCompositeAdd);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue((7.0 + 3.0) * 0.4 + (7.0 + 5.0) * 0.6, values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, CompositeEaseIn) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  keyframes[0]->SetComposite(EffectModel::kCompositeReplace);
  keyframes[0]->SetEasing(CubicBezierTimingFunction::Preset(
      CubicBezierTimingFunction::EaseType::EASE_IN));
  keyframes[1]->SetComposite(EffectModel::kCompositeReplace);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  // CubicBezier(0.42, 0, 1, 1)(0.6) = 0.4291197695757142.
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(3.85824, values.at(0));
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration * 100,
                 values);
  ExpectLengthValue(3.85824, values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, CompositeCubicBezier) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  keyframes[0]->SetComposite(EffectModel::kCompositeReplace);
  keyframes[0]->SetEasing(CubicBezierTimingFunction::Create(0.42, 0, 0.58, 1));
  keyframes[1]->SetComposite(EffectModel::kCompositeReplace);
  // CubicBezier(0.42, 0, 0.58, 1)(0.6) = 0.6681161300485039.
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(4.336232, values.at(0));
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT,
                 kDuration * 1000, values);
  ExpectLengthValue(4.336232, values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, ExtrapolateReplaceNonInterpolable) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kFontFamily, "serif", "cursive");
  keyframes[0]->SetComposite(EffectModel::kCompositeReplace);
  keyframes[1]->SetComposite(EffectModel::kCompositeReplace);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 1.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("cursive", values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, ExtrapolateReplace) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  keyframes[0]->SetComposite(EffectModel::kCompositeReplace);
  keyframes[1]->SetComposite(EffectModel::kCompositeReplace);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 1.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(3.0 * -0.6 + 5.0 * 1.6, values.at(0));
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_ExtrapolateAdd) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  keyframes[0]->SetComposite(EffectModel::kCompositeAdd);
  keyframes[1]->SetComposite(EffectModel::kCompositeAdd);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 1.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue((7.0 + 3.0) * -0.6 + (7.0 + 5.0) * 1.6, values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, ZeroKeyframes) {
  auto* effect =
      MakeGarbageCollected<StringKeyframeEffectModel>(StringKeyframeVector());
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_TRUE(values.empty());
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_SingleKeyframeAtOffsetZero) {
  StringKeyframeVector keyframes(1);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_SingleKeyframeAtOffsetOne) {
  StringKeyframeVector keyframes(1);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(1.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kLeft, "5px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(7.0 * 0.4 + 5.0 * 0.6, values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, MoreThanTwoKeyframes) {
  StringKeyframeVector keyframes(3);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(0.5);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "sans-serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2]->SetOffset(1.0);
  keyframes[2]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "cursive",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.3, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("sans-serif", values.at(0));
  effect->Sample(0, 0.8, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("cursive", values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, EndKeyframeOffsetsUnspecified) {
  StringKeyframeVector keyframes(3);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(0.5);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "cursive",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.1, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("cursive", values.at(0));
  effect->Sample(0, 0.9, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, SampleOnKeyframe) {
  StringKeyframeVector keyframes(3);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(0.5);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "cursive",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2]->SetOffset(1.0);
  keyframes[2]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.0, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
  effect->Sample(0, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("cursive", values.at(0));
  effect->Sample(0, 1.0, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, MultipleKeyframesWithSameOffset) {
  StringKeyframeVector keyframes(9);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(0.1);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "sans-serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2]->SetOffset(0.1);
  keyframes[2]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "monospace",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[3] = MakeGarbageCollected<StringKeyframe>();
  keyframes[3]->SetOffset(0.5);
  keyframes[3]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "cursive",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[4] = MakeGarbageCollected<StringKeyframe>();
  keyframes[4]->SetOffset(0.5);
  keyframes[4]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "fantasy",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[5] = MakeGarbageCollected<StringKeyframe>();
  keyframes[5]->SetOffset(0.5);
  keyframes[5]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "system-ui",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[6] = MakeGarbageCollected<StringKeyframe>();
  keyframes[6]->SetOffset(0.9);
  keyframes[6]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[7] = MakeGarbageCollected<StringKeyframe>();
  keyframes[7]->SetOffset(0.9);
  keyframes[7]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "sans-serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[8] = MakeGarbageCollected<StringKeyframe>();
  keyframes[8]->SetOffset(1.0);
  keyframes[8]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "monospace",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.0, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
  effect->Sample(0, 0.2, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("monospace", values.at(0));
  effect->Sample(0, 0.4, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("cursive", values.at(0));
  effect->Sample(0, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("system-ui", values.at(0));
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("system-ui", values.at(0));
  effect->Sample(0, 0.8, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("serif", values.at(0));
  effect->Sample(0, 1.0, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectNonInterpolableValue("monospace", values.at(0));
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_PerKeyframeComposite) {
  StringKeyframeVector keyframes(2);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kLeft, "3px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(1.0);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kLeft, "5px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1]->SetComposite(EffectModel::kCompositeAdd);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(3.0 * 0.4 + (7.0 + 5.0) * 0.6, values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, MultipleProperties) {
  StringKeyframeVector keyframes(2);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "serif",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kFontSynthesisWeight, "auto",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(1.0);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kFontFamily, "cursive",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kFontSynthesisWeight, "none",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_EQ(2UL, values.size());
  Interpolation* left_value = FindValue(values, CSSPropertyID::kFontFamily);
  ASSERT_TRUE(left_value);
  ExpectNonInterpolableValue("cursive", left_value);
  Interpolation* right_value =
      FindValue(values, CSSPropertyID::kFontSynthesisWeight);
  ASSERT_TRUE(right_value);
  ExpectNonInterpolableValue("none", right_value);
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_RecompositeCompositableValue) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  keyframes[0]->SetComposite(EffectModel::kCompositeAdd);
  keyframes[1]->SetComposite(EffectModel::kCompositeAdd);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue((7.0 + 3.0) * 0.4 + (7.0 + 5.0) * 0.6, values.at(0));
  ExpectLengthValue((9.0 + 3.0) * 0.4 + (9.0 + 5.0) * 0.6, values.at(1));
}

TEST_F(AnimationKeyframeEffectModel, MultipleIterations) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "1px", "3px");
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(2.0, values.at(0));
  effect->Sample(1, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(2.0, values.at(0));
  effect->Sample(2, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  ExpectLengthValue(2.0, values.at(0));
}

// FIXME: Re-enable this test once compositing of CompositeAdd is supported.
TEST_F(AnimationKeyframeEffectModel, DISABLED_DependsOnUnderlyingValue) {
  StringKeyframeVector keyframes(3);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.0);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kLeft, "1px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[0]->SetComposite(EffectModel::kCompositeAdd);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1]->SetOffset(0.5);
  keyframes[1]->SetCSSPropertyValue(CSSPropertyID::kLeft, "1px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2]->SetOffset(1.0);
  keyframes[2]->SetCSSPropertyValue(CSSPropertyID::kLeft, "1px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  HeapVector<Member<Interpolation>> values;
  effect->Sample(0, 0, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_TRUE(values.at(0));
  effect->Sample(0, 0.1, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_TRUE(values.at(0));
  effect->Sample(0, 0.25, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_TRUE(values.at(0));
  effect->Sample(0, 0.4, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_TRUE(values.at(0));
  effect->Sample(0, 0.5, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_FALSE(values.at(0));
  effect->Sample(0, 0.6, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_FALSE(values.at(0));
  effect->Sample(0, 0.75, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_FALSE(values.at(0));
  effect->Sample(0, 0.8, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_FALSE(values.at(0));
  effect->Sample(0, 1, TimingFunction::LimitDirection::RIGHT, kDuration,
                 values);
  EXPECT_FALSE(values.at(0));
}

TEST_F(AnimationKeyframeEffectModel, AddSyntheticKeyframes) {
  StringKeyframeVector keyframes(1);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.5);
  keyframes[0]->SetCSSPropertyValue(CSSPropertyID::kLeft, "4px",
                                    SecureContextMode::kInsecureContext,
                                    nullptr);

  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  const StringPropertySpecificKeyframeVector& property_specific_keyframes =
      *effect->GetPropertySpecificKeyframes(
          PropertyHandle(GetCSSPropertyLeft()));
  EXPECT_EQ(3U, property_specific_keyframes.size());
  EXPECT_DOUBLE_EQ(0.0, property_specific_keyframes[0]->Offset());
  EXPECT_DOUBLE_EQ(0.5, property_specific_keyframes[1]->Offset());
  EXPECT_DOUBLE_EQ(1.0, property_specific_keyframes[2]->Offset());
}

TEST_F(AnimationKeyframeEffectModel, ToKeyframeEffectModel) {
  StringKeyframeVector keyframes(0);
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);

  EffectModel* base_effect = effect;
  EXPECT_TRUE(ToStringKeyframeEffectModel(base_effect));
}

TEST_F(AnimationKeyframeEffectModel, CompositorSn
```
Response:
The user wants a summary of the functionality of the provided C++ code, which is a test file for the `KeyframeEffectModel` in the Chromium Blink engine.

Here's a breakdown of the thought process:

1. **Identify the Core Subject:** The filename `keyframe_effect_model_test.cc` and the class names like `AnimationKeyframeEffectModel` clearly indicate that the code is testing the functionality of the `KeyframeEffectModel`. This model is related to animations driven by keyframes.

2. **Analyze the Test Cases:** Each `TEST_F` block represents a specific test case. Reviewing the name and code within each test case provides insights into what aspect of the `KeyframeEffectModel` is being tested.

3. **Group Related Test Cases:**  Several test cases revolve around the concept of "Compositor Snapshot". This suggests a key feature being tested: how the model prepares data for the compositor, which is responsible for the actual rendering.

4. **Look for Specific Property Tests:** Tests like `CompositorUpdateColorProperty` and `CompositorSnapshotContainerRelative` indicate testing the model's behavior with different CSS properties (color, transforms involving container queries).

5. **Examine Non-Compositor Tests:** Tests like `EvenlyDistributed1/2/3` and `RejectInvalidPropertyValue` seem to focus on internal logic like calculating keyframe offsets and handling invalid CSS values, which aren't directly tied to the compositor.

6. **Consider the Purpose of Testing:**  Test code is designed to verify the correct behavior of the unit under test. This means the tests aim to ensure the `KeyframeEffectModel` functions as expected in various scenarios.

7. **Relate to Web Technologies:**  Since it's part of the Blink engine, the functionality will likely be tied to CSS animations and transitions. Look for keywords like "opacity", "filter", "transform", "color", and container queries, as these are all CSS features that can be animated using keyframes.

8. **Infer Relationships with JavaScript, HTML, and CSS:**  Animations are triggered and controlled via JavaScript, applied to HTML elements, and defined using CSS keyframes. The `KeyframeEffectModel` sits in the middle, processing this information.

9. **Identify Potential User/Programming Errors:**  Test cases that deal with invalid input (`RejectInvalidPropertyValue`) or the timing of snapshot updates point to potential pitfalls for developers using these APIs.

10. **Structure the Summary:** Organize the findings into logical categories: core functionality, relationships to web technologies (with examples), logical reasoning (with hypothetical inputs/outputs), and potential errors.

11. **Address the "Part 2" Request:**  Acknowledge that this is the second part and summarize the overall function of the file, considering the information gleaned from both parts. The previous part likely focused on the fundamental creation and manipulation of keyframe effects, while this part seems more focused on the interaction with the compositor and specific CSS property handling.

**(Self-Correction/Refinement during the process):**

* Initially, I might focus too much on the "Compositor" aspect. It's important to also capture the tests related to keyframe distribution and invalid properties, as these are also crucial functionalities.
* I need to ensure the examples provided for JavaScript, HTML, and CSS are clear and directly related to the tested features. For example, show a CSS `@keyframes` rule that would use the tested properties.
* The "logical reasoning" section needs concrete examples of input and expected output based on the test cases. Instead of just saying "it updates snapshots," show what triggers an update and what the expected state change is.

By following these steps and continuously refining the understanding based on the code, a comprehensive and accurate summary can be generated.
这是对 `blink/renderer/core/animation/keyframe_effect_model_test.cc` 文件第二部分的分析总结。结合第一部分的分析，我们可以归纳出这个测试文件的主要功能是：

**总体功能：**

这个测试文件主要用于测试 `KeyframeEffectModel` 及其相关类的功能，这是 Blink 渲染引擎中处理 CSS 动画和过渡效果的核心组件。`KeyframeEffectModel` 负责管理动画的关键帧数据，并将这些数据转换为可以在渲染流水线中使用的形式。测试用例涵盖了 `KeyframeEffectModel` 的各种操作和场景，确保其在不同情况下都能正确工作。

**第二部分具体功能总结：**

这部分主要关注 `KeyframeEffectModel` 如何与合成器（Compositor）交互，以及如何处理不同类型的 CSS 属性。具体来说，测试了以下几个方面：

1. **合成器快照的更新机制：**
   - **首次更新：**  验证在 `KeyframeEffectModel` 创建后首次调用 `SnapshotAllCompositorKeyframesIfNecessary` 方法时，会生成合成器关键帧快照。
   - **重复调用：** 验证在没有发生改变的情况下，重复调用 `SnapshotAllCompositorKeyframesIfNecessary` 不会重复生成快照。
   - **显式失效：** 验证调用 `InvalidateCompositorKeyframesSnapshot` 后，再次调用 `SnapshotAllCompositorKeyframesIfNecessary` 会重新生成快照。
   - **关键帧改变后更新：** 验证在修改了 `KeyframeEffectModel` 的关键帧数据后，调用 `SnapshotAllCompositorKeyframesIfNecessary` 会更新合成器快照。

2. **处理不同类型的 CSS 属性：**
   - **自定义属性：** 测试了对于 CSS 自定义属性，`KeyframeEffectModel` 能正确生成合成器关键帧值，并能识别出数值类型。
   - **颜色属性：**  详细测试了 `KeyframeEffectModel` 如何处理各种颜色格式（rgb, hsl, named color, hex）的动画，以及 `currentcolor` 关键字。验证了能够正确解析和转换为合成器可以使用的颜色值。
   - **容器相对单位：** 测试了 `KeyframeEffectModel` 如何处理使用容器查询单位（例如 `cqw`, `cqh`）的 `transform` 属性，验证了能够根据容器尺寸计算出正确的像素值。

3. **计算关键帧偏移量：** 测试了 `KeyframeEffectModelBase::GetComputedOffsets` 方法，用于计算在部分关键帧没有显式指定偏移量的情况下，如何均匀分布剩余的关键帧。

4. **处理无效的属性值：** 测试了当关键帧中设置了无效的 CSS 属性值时，该属性会被静默拒绝，不会导致程序崩溃。

5. **静态属性和动态属性的区分：** 测试了当动画的关键帧值相同时，该属性被认为是静态属性；当关键帧值不同时，该属性被认为是动态属性。这对于优化动画性能很重要。

6. **处理 background 简写属性：** 测试了当使用 `background` 简写属性进行动画时，`KeyframeEffectModel` 能正确识别出其中可以独立动画的子属性，并区分静态和动态属性。

**与 JavaScript, HTML, CSS 的关系举例说明：**

- **CSS @keyframes 规则：**  测试模拟了 CSS `@keyframes` 规则定义的动画效果。例如，`KeyframesAtZeroAndOne(CSSPropertyID::kOpacity, "0", "1")` 就模拟了一个从 `opacity: 0` 到 `opacity: 1` 的动画关键帧。
  ```css
  @keyframes fade {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  ```
- **HTML 元素：** 测试中创建了一个虚拟的 HTML 元素 (`element`) 来模拟动画应用的目标。`GetDocument().getElementById(AtomicString("target"))`  类似在 JavaScript 中使用 `document.getElementById()` 获取元素。
  ```html
  <div id="target" style="animation: fade 1s;">Content</div>
  ```
- **CSS 属性：** 测试针对不同的 CSS 属性，如 `opacity`, `filter`, `transform`, `color`, `background` 等进行。例如，测试 `CompositorSnapshotUpdateAfterKeyframeChange` 就测试了改变 `opacity` 和 `filter` 属性的关键帧后，合成器快照的更新。
- **JavaScript 操作动画：** 虽然测试代码是用 C++ 编写的，但它模拟了 JavaScript 通过 CSS 或 Web Animations API 操作动画的行为。 例如，`effect->SetFrames(filter_keyframes);`  可以类比 JavaScript 中修改动画的关键帧。

**逻辑推理的假设输入与输出：**

**假设输入 (Compositor 快照更新):**

1. **初始状态：**  创建一个 `StringKeyframeEffectModel`，包含 `opacity` 属性从 "0" 到 "1" 的关键帧。
2. **操作 1：** 首次调用 `SnapshotAllCompositorKeyframesIfNecessary`。
3. **操作 2：** 再次调用 `SnapshotAllCompositorKeyframesIfNecessary`。
4. **操作 3：** 调用 `InvalidateCompositorKeyframesSnapshot`。
5. **操作 4：** 再次调用 `SnapshotAllCompositorKeyframesIfNecessary`。

**预期输出 (Compositor 快照更新):**

1. 首次调用后，合成器关键帧快照被创建，`GetCompositorKeyframeValue()` 返回一个非空值。
2. 第二次调用后，快照不会重新生成，`SnapshotAllCompositorKeyframesIfNecessary` 返回 `false`。
3. 调用 `InvalidateCompositorKeyframesSnapshot` 后，内部状态被标记为需要更新。
4. 第四次调用后，快照会被重新生成，`SnapshotAllCompositorKeyframesIfNecessary` 返回 `true`，并且 `GetCompositorKeyframeValue()` 返回一个新的非空值。

**假设输入 (容器相对单位):**

1. **HTML 结构：** 包含一个设置了 `container-type: size` 的父元素和一个子元素。
2. **CSS 动画：**  子元素的动画 `transform` 属性使用容器相对单位 `cqw` 和 `cqh`。父元素宽度 100px，高度 200px。
3. **操作：** 调用 `SnapshotAllCompositorKeyframesIfNecessary`。

**预期输出 (容器相对单位):**

合成器关键帧中 `transform` 属性的 `translateX` 值会被计算为正确的像素值：
- `translateX(10cqw)` 会被转换为 `translateX(10px)` (因为容器宽度是 100px)。
- `translateX(10cqh)` 会被转换为 `translateX(20px)` (因为容器高度是 200px)。

**用户或编程常见的使用错误举例说明：**

- **忘记调用 `SnapshotAllCompositorKeyframesIfNecessary`：**  如果开发者创建了一个 `KeyframeEffectModel` 后，没有调用 `SnapshotAllCompositorKeyframesIfNecessary`，那么在合成线程中就无法获取到动画的关键帧数据，导致动画无法正常执行。这就像在 JavaScript 中定义了一个动画，但没有将其应用到任何元素上。
- **在不必要的时候重复调用 `SnapshotAllCompositorKeyframesIfNecessary`：**  虽然重复调用不会出错，但会造成不必要的性能开销。开发者应该只在必要的时候调用，例如在关键帧数据改变后。
- **设置无效的 CSS 属性值：**  虽然测试表明 Blink 会静默拒绝无效值，但开发者应该避免设置无效的 CSS 属性值，这可能会导致意想不到的渲染问题或者与其他动画属性冲突。例如，将 `opacity` 的值设置为 "abc" 而不是 "0" 或 "1"。
- **假设合成器关键帧值总是立即可用：**  合成器关键帧的生成可能需要一些时间，开发者不应该假设在 `KeyframeEffectModel` 创建后立即就能获取到合成器关键帧值。应该依赖于快照机制来确保数据准备就绪。

总而言之，这个测试文件的第二部分专注于验证 `KeyframeEffectModel` 与合成器的交互，以及对各种 CSS 属性的处理能力，确保动画数据能正确地传递到渲染流水线中，并能处理各种可能出现的场景和用户错误。

### 提示词
```
这是目录为blink/renderer/core/animation/keyframe_effect_model_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
apshotUpdateBasic) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kOpacity, "0", "1");
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);

  const auto* style = GetDocument().GetStyleResolver().ResolveStyle(
      element, StyleRecalcContext());

  const CompositorKeyframeValue* value;

  // Compositor keyframe value should be empty before snapshot
  const auto& empty_keyframes = *effect->GetPropertySpecificKeyframes(
      PropertyHandle(GetCSSPropertyOpacity()));
  value = empty_keyframes[0]->GetCompositorKeyframeValue();
  EXPECT_FALSE(value);

  // Snapshot should update first time after construction
  EXPECT_TRUE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *element, *style, nullptr));
  // Snapshot should not update on second call
  EXPECT_FALSE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *element, *style, nullptr));
  // Snapshot should update after an explicit invalidation
  effect->InvalidateCompositorKeyframesSnapshot();
  EXPECT_TRUE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *element, *style, nullptr));

  // Compositor keyframe value should be available after snapshot
  const auto& available_keyframes = *effect->GetPropertySpecificKeyframes(
      PropertyHandle(GetCSSPropertyOpacity()));
  value = available_keyframes[0]->GetCompositorKeyframeValue();
  EXPECT_TRUE(value);
  EXPECT_TRUE(value->IsDouble());
}

TEST_F(AnimationKeyframeEffectModel,
       CompositorSnapshotUpdateAfterKeyframeChange) {
  StringKeyframeVector opacity_keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kOpacity, "0", "1");
  auto* effect =
      MakeGarbageCollected<StringKeyframeEffectModel>(opacity_keyframes);

  const auto* style = GetDocument().GetStyleResolver().ResolveStyle(
      element, StyleRecalcContext());

  EXPECT_TRUE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *element, *style, nullptr));

  const CompositorKeyframeValue* value;
  const auto& keyframes = *effect->GetPropertySpecificKeyframes(
      PropertyHandle(GetCSSPropertyOpacity()));
  value = keyframes[0]->GetCompositorKeyframeValue();
  EXPECT_TRUE(value);
  EXPECT_TRUE(value->IsDouble());

  StringKeyframeVector filter_keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kFilter, "blur(1px)", "blur(10px)");
  effect->SetFrames(filter_keyframes);

  // Snapshot should update after changing keyframes
  EXPECT_TRUE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *element, *style, nullptr));
  const auto& updated_keyframes = *effect->GetPropertySpecificKeyframes(
      PropertyHandle(GetCSSPropertyFilter()));
  value = updated_keyframes[0]->GetCompositorKeyframeValue();
  EXPECT_TRUE(value);
  EXPECT_TRUE(value->IsFilterOperations());
}

TEST_F(AnimationKeyframeEffectModel, CompositorSnapshotUpdateCustomProperty) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  DummyExceptionStateForTesting exception_state;

  // Compositor keyframe value available after snapshot
  const CompositorKeyframeValue* value =
      ConstructEffectAndGetKeyframes("--foo", "<number>", &GetDocument(),
                                     element, "0", "100", exception_state)[1]
          ->GetCompositorKeyframeValue();
  ASSERT_FALSE(exception_state.HadException());

  // Test value holds the correct number type
  EXPECT_TRUE(value);
  EXPECT_TRUE(value->IsDouble());
  EXPECT_EQ(To<CompositorKeyframeDouble>(value)->ToDouble(), 100);
}

TEST_F(AnimationKeyframeEffectModel, CompositorUpdateColorProperty) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  DummyExceptionStateForTesting exception_state;

  element->style()->setProperty(GetDocument().GetExecutionContext(), "color",
                                "rgb(0, 255, 0)", g_empty_string,
                                exception_state);

  // Compositor keyframe value available after snapshot
  const CompositorKeyframeValue* value_rgb =
      ConstructEffectAndGetKeyframes("--rgb", "<color>", &GetDocument(),
                                     element, "rgb(0, 0, 0)", "rgb(0, 255, 0)",
                                     exception_state)[1]
          ->GetCompositorKeyframeValue();
  const CompositorKeyframeValue* value_hsl =
      ConstructEffectAndGetKeyframes("--hsl", "<color>", &GetDocument(),
                                     element, "hsl(0, 0%, 0%)",
                                     "hsl(120, 100%, 50%)", exception_state)[1]
          ->GetCompositorKeyframeValue();
  const CompositorKeyframeValue* value_name =
      ConstructEffectAndGetKeyframes("--named", "<color>", &GetDocument(),
                                     element, "black", "lime",
                                     exception_state)[1]
          ->GetCompositorKeyframeValue();
  const CompositorKeyframeValue* value_hex =
      ConstructEffectAndGetKeyframes("--hex", "<color>", &GetDocument(),
                                     element, "#000000", "#00FF00",
                                     exception_state)[1]
          ->GetCompositorKeyframeValue();
  const CompositorKeyframeValue* value_curr =
      ConstructEffectAndGetKeyframes("--curr", "<color>", &GetDocument(),
                                     element, "#000000", "currentcolor",
                                     exception_state)[1]
          ->GetCompositorKeyframeValue();
  const PropertySpecificKeyframeVector& values_mixed =
      ConstructEffectAndGetKeyframes("--mixed", "<color>", &GetDocument(),
                                     element, "#000000", "lime",
                                     exception_state);
  ASSERT_FALSE(exception_state.HadException());

  // Test rgb color input
  EXPECT_TRUE(value_rgb);
  EXPECT_TRUE(value_rgb->IsColor());
  EXPECT_EQ(To<CompositorKeyframeColor>(value_rgb)->ToColor(), SK_ColorGREEN);

  // Test hsl color input
  EXPECT_TRUE(value_hsl);
  EXPECT_TRUE(value_hsl->IsColor());
  EXPECT_EQ(To<CompositorKeyframeColor>(value_hsl)->ToColor(), SK_ColorGREEN);

  // Test named color input
  EXPECT_TRUE(value_name);
  EXPECT_TRUE(value_name->IsColor());
  EXPECT_EQ(To<CompositorKeyframeColor>(value_name)->ToColor(), SK_ColorGREEN);

  // Test hex color input
  EXPECT_TRUE(value_hex);
  EXPECT_TRUE(value_hex->IsColor());
  EXPECT_EQ(To<CompositorKeyframeColor>(value_hex)->ToColor(), SK_ColorGREEN);

  // currentcolor is a CSSIdentifierValue not a color
  EXPECT_FALSE(value_curr);

  // Ensure both frames are consistent when values are mixed
  const CompositorKeyframeValue* value_mixed0 =
      values_mixed[0]->GetCompositorKeyframeValue();
  const CompositorKeyframeValue* value_mixed1 =
      values_mixed[1]->GetCompositorKeyframeValue();

  EXPECT_TRUE(value_mixed0);
  EXPECT_TRUE(value_mixed0->IsColor());
  EXPECT_EQ(To<CompositorKeyframeColor>(value_mixed0)->ToColor(),
            SK_ColorBLACK);

  EXPECT_TRUE(value_mixed1);
  EXPECT_TRUE(value_mixed1->IsColor());
  EXPECT_EQ(To<CompositorKeyframeColor>(value_mixed1)->ToColor(),
            SK_ColorGREEN);
}

TEST_F(AnimationKeyframeEffectModel, CompositorSnapshotContainerRelative) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        container-type: size;
        width: 100px;
        height: 200px;
      }
    </style>
    <div id=container>
      <div id="target">
        Test
      </div>
    </div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  StringKeyframeVector keyframes = KeyframesAtZeroAndOne(
      CSSPropertyID::kTransform, "translateX(10cqw)", "translateX(10cqh)");
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);

  EXPECT_TRUE(effect->SnapshotAllCompositorKeyframesIfNecessary(
      *target, target->ComputedStyleRef(), nullptr));

  const auto& property_specific_keyframes =
      *effect->GetPropertySpecificKeyframes(
          PropertyHandle(GetCSSPropertyTransform()));
  ASSERT_EQ(2u, property_specific_keyframes.size());
  const auto* value0 = DynamicTo<CompositorKeyframeTransform>(
      property_specific_keyframes[0]->GetCompositorKeyframeValue());
  const auto* value1 = DynamicTo<CompositorKeyframeTransform>(
      property_specific_keyframes[1]->GetCompositorKeyframeValue());
  ASSERT_TRUE(value0);
  ASSERT_TRUE(value1);
  const TransformOperations& ops0 = value0->GetTransformOperations();
  const TransformOperations& ops1 = value1->GetTransformOperations();
  ASSERT_EQ(1u, ops0.size());
  ASSERT_EQ(1u, ops1.size());
  const auto* op0 = DynamicTo<TranslateTransformOperation>(ops0.at(0));
  const auto* op1 = DynamicTo<TranslateTransformOperation>(ops1.at(0));
  ASSERT_TRUE(op0);
  ASSERT_TRUE(op1);
  EXPECT_FLOAT_EQ(10.0f, op0->X().Pixels());
  EXPECT_FLOAT_EQ(20.0f, op1->X().Pixels());
}

}  // namespace blink

namespace blink {

class KeyframeEffectModelTest : public testing::Test {
 public:
  static Vector<double> GetComputedOffsets(const KeyframeVector& keyframes) {
    return KeyframeEffectModelBase::GetComputedOffsets(keyframes);
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(KeyframeEffectModelTest, EvenlyDistributed1) {
  KeyframeVector keyframes(5);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0.125);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[3] = MakeGarbageCollected<StringKeyframe>();
  keyframes[4] = MakeGarbageCollected<StringKeyframe>();
  keyframes[4]->SetOffset(0.625);

  const Vector<double> result = GetComputedOffsets(keyframes);
  EXPECT_EQ(5U, result.size());
  EXPECT_DOUBLE_EQ(0.125, result[0]);
  EXPECT_DOUBLE_EQ(0.25, result[1]);
  EXPECT_DOUBLE_EQ(0.375, result[2]);
  EXPECT_DOUBLE_EQ(0.5, result[3]);
  EXPECT_DOUBLE_EQ(0.625, result[4]);
}

TEST_F(KeyframeEffectModelTest, EvenlyDistributed2) {
  KeyframeVector keyframes(6);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[3] = MakeGarbageCollected<StringKeyframe>();
  keyframes[3]->SetOffset(0.75);
  keyframes[4] = MakeGarbageCollected<StringKeyframe>();
  keyframes[5] = MakeGarbageCollected<StringKeyframe>();

  const Vector<double> result = GetComputedOffsets(keyframes);
  EXPECT_EQ(6U, result.size());
  EXPECT_DOUBLE_EQ(0.0, result[0]);
  EXPECT_DOUBLE_EQ(0.25, result[1]);
  EXPECT_DOUBLE_EQ(0.5, result[2]);
  EXPECT_DOUBLE_EQ(0.75, result[3]);
  EXPECT_DOUBLE_EQ(0.875, result[4]);
  EXPECT_DOUBLE_EQ(1.0, result[5]);
}

TEST_F(KeyframeEffectModelTest, EvenlyDistributed3) {
  KeyframeVector keyframes(12);
  keyframes[0] = MakeGarbageCollected<StringKeyframe>();
  keyframes[0]->SetOffset(0);
  keyframes[1] = MakeGarbageCollected<StringKeyframe>();
  keyframes[2] = MakeGarbageCollected<StringKeyframe>();
  keyframes[3] = MakeGarbageCollected<StringKeyframe>();
  keyframes[4] = MakeGarbageCollected<StringKeyframe>();
  keyframes[4]->SetOffset(0.5);
  keyframes[5] = MakeGarbageCollected<StringKeyframe>();
  keyframes[6] = MakeGarbageCollected<StringKeyframe>();
  keyframes[7] = MakeGarbageCollected<StringKeyframe>();
  keyframes[7]->SetOffset(0.8);
  keyframes[8] = MakeGarbageCollected<StringKeyframe>();
  keyframes[9] = MakeGarbageCollected<StringKeyframe>();
  keyframes[10] = MakeGarbageCollected<StringKeyframe>();
  keyframes[11] = MakeGarbageCollected<StringKeyframe>();

  const Vector<double> result = GetComputedOffsets(keyframes);
  EXPECT_EQ(12U, result.size());
  EXPECT_DOUBLE_EQ(0.0, result[0]);
  EXPECT_DOUBLE_EQ(0.125, result[1]);
  EXPECT_DOUBLE_EQ(0.25, result[2]);
  EXPECT_DOUBLE_EQ(0.375, result[3]);
  EXPECT_DOUBLE_EQ(0.5, result[4]);
  EXPECT_DOUBLE_EQ(0.6, result[5]);
  EXPECT_DOUBLE_EQ(0.7, result[6]);
  EXPECT_DOUBLE_EQ(0.8, result[7]);
  EXPECT_DOUBLE_EQ(0.85, result[8]);
  EXPECT_DOUBLE_EQ(0.9, result[9]);
  EXPECT_DOUBLE_EQ(0.95, result[10]);
  EXPECT_DOUBLE_EQ(1.0, result[11]);
}

TEST_F(KeyframeEffectModelTest, RejectInvalidPropertyValue) {
  StringKeyframe* keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetCSSPropertyValue(CSSPropertyID::kBackgroundColor,
                                "not a valid color",
                                SecureContextMode::kInsecureContext, nullptr);
  // Verifty that property is quietly rejected.
  EXPECT_EQ(0U, keyframe->Properties().size());

  // Verify that a valid property value is accepted.
  keyframe->SetCSSPropertyValue(CSSPropertyID::kBackgroundColor, "blue",
                                SecureContextMode::kInsecureContext, nullptr);
  EXPECT_EQ(1U, keyframe->Properties().size());
}

TEST_F(KeyframeEffectModelTest, StaticProperty) {
  StringKeyframeVector keyframes =
      KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "3px");
  auto* effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  EXPECT_EQ(1U, effect->Properties().size());
  EXPECT_EQ(0U, effect->EnsureDynamicProperties().size());

  keyframes = KeyframesAtZeroAndOne(CSSPropertyID::kLeft, "3px", "5px");
  effect = MakeGarbageCollected<StringKeyframeEffectModel>(keyframes);
  EXPECT_EQ(1U, effect->Properties().size());
  EXPECT_EQ(1U, effect->EnsureDynamicProperties().size());
}

TEST_F(AnimationKeyframeEffectModel, BackgroundShorthandStaticProperties) {
  // Following background properties can be animated:
  //    background-attachment, background-clip, background-color,
  //    background-image, background-origin, background-position-x,
  //    background-position-y, background-repeat, background-size
  const wtf_size_t kBackgroundProperties = 9U;
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes colorize {
        from { background: red; }
        to { background: green; }
      }
      #block {
        container-type: size;
        animation: colorize 1s linear paused;
        width: 100px;
        height: 100px;
      }
    </style>
    <div id=block>
    </div>
  )HTML");
  const auto& animations = GetDocument().getAnimations();
  EXPECT_EQ(1U, animations.size());
  auto* effect = animations[0]->effect();
  auto* model = To<KeyframeEffect>(effect)->Model();
  EXPECT_EQ(kBackgroundProperties, model->Properties().size());
  // Background-color is the only property that is changing between keyframes.
  EXPECT_EQ(1U, model->EnsureDynamicProperties().size());
}

}  // namespace blink
```
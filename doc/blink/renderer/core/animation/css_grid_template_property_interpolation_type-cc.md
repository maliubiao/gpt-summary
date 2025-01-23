Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding - What is this file about?**

The filename `css_grid_template_property_interpolation_type.cc` immediately suggests this file deals with how the `grid-template-columns` and `grid-template-rows` CSS properties are animated (interpolated) in the Blink rendering engine. The `interpolation_type` suffix is a strong indicator of animation handling.

**2. High-Level Structure Scan - Identifying Key Components:**

I'd quickly scan the code for major blocks and keywords:

* **Includes:**  These tell us the dependencies. `InterpolableGridTrackList`, `ComputedGridTrackList`, `StyleResolverState`, `CSSPropertyID` are all related to CSS grid layout and styling. The presence of `animation` in some include paths confirms the animation focus.
* **Namespaces:** `blink` tells us this is Blink-specific code.
* **Classes:**  `CSSGridTrackListNonInterpolableValue`, `UnderlyingGridTrackListChecker`, `InheritedGridTrackListChecker`, and `CSSGridTemplatePropertyInterpolationType`. These are the core actors.
* **Methods in `CSSGridTemplatePropertyInterpolationType`:** `CreateInterpolableGridTrackList`, `MaybeMergeSingles`, `MaybeConvertNeutral`, `MaybeConvertInitial`, `MaybeConvertInherit`, `MaybeConvertStandardPropertyUnderlyingValue`, `MaybeConvertValue`, `ApplyStandardPropertyValue`, `Composite`. These clearly map to the different stages of the CSS animation process.
* **Templates and Structs:**  `DowncastTraits` suggests type safety and downcasting utilities.

**3. Deep Dive into Key Classes:**

* **`CSSGridTrackListNonInterpolableValue`:** The name suggests this class holds information that *doesn't* directly get interpolated numerically. It seems to store the "from" and "to" states of named grid lines during an animation. The `GetCurrentNamedGridLines` and `GetCurrentOrderedNamedGridLines` methods using `progress < 0.5` are a key detail, indicating a discrete switch midway through the animation. This hints at how named grid lines are handled during transitions – not smoothly interpolated.

* **`UnderlyingGridTrackListChecker` and `InheritedGridTrackListChecker`:** These are "checkers" used during the conversion process. `UnderlyingGridTrackListChecker` likely verifies if the underlying (previous) state is compatible with the current one for interpolation. `InheritedGridTrackListChecker` checks for compatibility during inheritance, specifically focusing on the structure of the grid tracks (repeats, etc.). This suggests that certain structural changes in inherited grid definitions might prevent smooth animation.

* **`CSSGridTemplatePropertyInterpolationType`:** This is the main class. Its methods mirror the standard CSS animation lifecycle:
    * `CreateInterpolableGridTrackList`: Creates the interpolatable representation of the grid tracks (likely numerical values like sizes).
    * `MaybeMergeSingles`: Checks if two single-value states can be merged for interpolation.
    * `MaybeConvertNeutral`, `MaybeConvertInitial`, `MaybeConvertInherit`, `MaybeConvertValue`: Handle the conversion from different starting points (neutral, initial, inherited, specific values) to an interpolatable representation.
    * `ApplyStandardPropertyValue`: Applies the interpolated values to the `ComputedStyle`.
    * `Composite`:  Handles combining the underlying value with the current value during animation.

**4. Connecting to Web Technologies:**

* **CSS:** The entire file revolves around the `grid-template-columns` and `grid-template-rows` CSS properties. The code directly manipulates the internal representation of these properties.
* **HTML:** While not directly manipulated here, this code affects how CSS grid layouts defined in HTML are animated.
* **JavaScript:** JavaScript triggers CSS animations via setting styles or using the Web Animations API. This code is part of the engine that *executes* those animations.

**5. Logical Reasoning and Examples:**

At this point, I start thinking about how the code would behave in specific scenarios.

* **Named Grid Lines:** The discrete switching in `CSSGridTrackListNonInterpolableValue` is crucial. I'd imagine a scenario where the named lines change completely between the start and end states of an animation. The animation wouldn't "morph" the names; it would jump from one set to the other halfway through.
* **Grid Track Compatibility:** The checkers highlight the importance of compatibility. Changing the number of repeating tracks or their basic structure during an animation would likely break smooth transitions.
* **`none` Keyword:** The `MaybeConvertInitial` method returning `nullptr` for `'none'` indicates that animating *to* or *from* `grid-template-columns: none` (or `rows`) isn't directly supported through interpolation.

**6. Common Errors:**

Based on the code, I'd anticipate the following common errors:

* **Trying to animate incompatible grid layouts:** Changing the number of columns/rows significantly or altering repeating patterns in the middle of a transition would likely result in jumps or the animation not working as expected.
* **Assuming named grid lines interpolate smoothly:** Developers might expect the positions associated with named lines to transition. The code shows a discrete switch, which could lead to unexpected visual results.

**7. Refinement and Structure of the Answer:**

Finally, I'd organize the findings into a structured answer, covering the main functionalities, relationships to web technologies, logical reasoning with examples, and potential user errors. I'd try to use clear and concise language, avoiding overly technical jargon where possible. I'd use bullet points and code formatting to improve readability.

This iterative process of understanding the code's purpose, dissecting its components, connecting it to broader web technologies, and then reasoning about its behavior in specific cases leads to a comprehensive analysis like the example provided in the prompt.
这个文件 `css_grid_template_property_interpolation_type.cc` 是 Chromium Blink 渲染引擎的一部分，专门负责处理 CSS Grid 布局中 `grid-template-columns` 和 `grid-template-rows` 属性的动画插值（interpolation）。

**核心功能：**

1. **定义了如何对 `grid-template-columns` 和 `grid-template-rows` 属性的值进行平滑过渡动画。**  当这两个属性的值发生变化时，浏览器需要一种方式来在起始值和结束值之间创建一个平滑的动画效果，而不是直接跳变。这个文件定义了这种插值的逻辑。

2. **处理可插值和不可插值的部分。** CSS Grid 的 `grid-template-columns` 和 `grid-template-rows` 属性值包含两部分信息：
    * **可插值的部分：** 主要是指轨道列表的长度值（如 `px`, `fr`, `%` 等）。这些值可以进行数值上的插值计算。
    * **不可插值的部分：** 指的是命名的网格线（named grid lines）。这些名字本身不能直接进行数值插值。

3. **创建 `InterpolableValue` 和 `NonInterpolableValue`。**  Blink 的动画系统使用 `InterpolableValue` 来存储可以进行插值计算的值，使用 `NonInterpolableValue` 存储不能直接插值，但需要在动画过程中传递和使用的信息。

4. **实现不同状态之间的转换和合并。**  例如，从 `initial` 值、`inherit` 值或者具体的 CSS 值转换为可用于插值的中间表示。

5. **处理 `none` 值。**  当 `grid-template-columns` 或 `grid-template-rows` 的值为 `none` 时，不能进行插值。这个文件会处理这种情况。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  这个文件直接对应于 CSS 的 `grid-template-columns` 和 `grid-template-rows` 属性。它定义了当这些属性发生动画过渡时，浏览器内部如何计算中间值，从而实现平滑的动画效果。
    * **例子：**  假设一个元素的 CSS 初始状态是 `grid-template-columns: 100px 1fr;`，动画结束状态是 `grid-template-columns: 200px 2fr;`。这个文件中的代码会负责计算动画过程中间时刻的 `grid-template-columns` 值，例如在动画进行到一半时，可能计算出类似 `grid-template-columns: 150px 1.5fr;` 的值。

* **HTML:**  HTML 定义了文档的结构，CSS 样式应用于 HTML 元素。当 HTML 元素的样式（包括 `grid-template-columns` 和 `grid-template-rows`）发生变化并触发 CSS 动画或过渡时，这个文件中的代码会被调用。

* **JavaScript:**  JavaScript 可以通过操作元素的 style 属性或使用 Web Animations API 来触发 CSS 动画和过渡。当 JavaScript 导致 `grid-template-columns` 或 `grid-template-rows` 的值发生变化并需要进行动画时，最终会涉及到这个文件中的插值逻辑。
    * **例子：** JavaScript 代码可以这样写：
      ```javascript
      const element = document.getElementById('myGrid');
      element.style.transition = 'grid-template-columns 1s';
      element.style.gridTemplateColumns = '200px 2fr';
      ```
      当这段代码执行时，浏览器会使用 `css_grid_template_property_interpolation_type.cc` 中的逻辑来平滑地改变网格列的宽度。

**逻辑推理与假设输入/输出：**

**假设输入：**

* **起始状态的 `grid-template-columns` 值：**  `1fr 1fr`
* **结束状态的 `grid-template-columns` 值：**  `2fr 3fr`
* **动画进度 (progress)：** 0.5 (动画进行到一半)

**逻辑推理：**

文件中的 `InterpolableGridTrackList` 类会处理可插值的部分。它会计算每个轨道长度值在起始和结束状态之间的线性插值。

* 对于第一个轨道，从 `1fr` 到 `2fr`，进度为 0.5 时，插值结果为 `1fr + (2fr - 1fr) * 0.5 = 1.5fr`。
* 对于第二个轨道，从 `1fr` 到 `3fr`，进度为 0.5 时，插值结果为 `1fr + (3fr - 1fr) * 0.5 = 2fr`。

**假设输出：**

* **动画进行到一半时的 `grid-template-columns` 值：** `1.5fr 2fr`

**关于命名网格线 (Named Grid Lines)：**

这个文件对命名网格线的处理方式比较特殊。从代码中可以看到，`CSSGridTrackListNonInterpolableValue` 类存储了起始和结束状态的命名网格线，并且在动画过程中，会根据进度选择使用起始状态的命名网格线还是结束状态的命名网格线，而不是进行平滑的“融合”。

* **假设输入：**
    * **起始状态的命名网格线：**  `[start-line] 1fr [middle-line] 1fr [end-line]`
    * **结束状态的命名网格线：**  `[begin] 2fr [center] 3fr [finish]`
    * **动画进度：** 0.3

* **输出：**  由于进度小于 0.5，会使用起始状态的命名网格线：`[start-line]`, `[middle-line]`, `[end-line]`。

* **如果动画进度为 0.7，则会使用结束状态的命名网格线：** `[begin]`, `[center]`, `[finish]`。

**用户或编程常见的使用错误：**

1. **尝试在结构差异很大的网格布局之间进行动画。** 例如，从一个只有两列的网格动画到一个有五列的网格。虽然浏览器会尽力插值，但结果可能不是预期的平滑过渡，尤其是在没有明确指定轨道大小时。

2. **错误地假设命名网格线会进行“融合”动画。**  用户可能会期望命名网格线的位置或数量在动画过程中平滑变化。但实际上，根据代码逻辑，命名网格线会在动画进行到一半时突然切换到结束状态的命名。

    * **例子：**  如果一个元素最初定义了 `grid-template-columns: [col1] 1fr [col2] 1fr;`，然后动画到 `grid-template-columns: [start] 1fr [end] 1fr [final] 1fr;`，在动画过程中，依赖于 `col1` 和 `col2` 的网格项可能会在动画中期突然改变其布局，因为命名网格线发生了切换。

3. **忘记考虑 `fr` 单位的动态性。**  `fr` 单位代表可用空间的一部分。在动画过程中，如果容器的大小发生变化，或者其他网格项的大小发生变化，`fr` 单位所代表的实际像素值也会变化，这可能会导致动画效果与预期不符。

4. **对 `auto` 关键字进行动画可能产生不确定的结果。**  如果网格轨道的大小使用了 `auto` 关键字，其大小取决于内容。在动画过程中，内容的变化可能会影响 `auto` 轨道的大小，使得动画效果难以预测。

总之，`css_grid_template_property_interpolation_type.cc` 文件在 Chromium Blink 引擎中扮演着关键角色，它确保了 CSS Grid 布局的 `grid-template-columns` 和 `grid-template-rows` 属性在动画过程中能够平滑过渡，但同时也需要开发者理解其内部的插值逻辑，特别是对于命名网格线的处理方式，以避免产生不符合预期的动画效果。

### 提示词
```
这是目录为blink/renderer/core/animation/css_grid_template_property_interpolation_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/css_grid_template_property_interpolation_type.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/animation/interpolable_grid_track_list.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/style/computed_grid_track_list.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

class CSSGridTrackListNonInterpolableValue final : public NonInterpolableValue {
 public:
  ~CSSGridTrackListNonInterpolableValue() final = default;

  static scoped_refptr<CSSGridTrackListNonInterpolableValue> Create(
      NamedGridLinesMap named_grid_lines,
      OrderedNamedGridLines ordered_named_grid_lines) {
    return base::AdoptRef(new CSSGridTrackListNonInterpolableValue(
        std::move(named_grid_lines), std::move(ordered_named_grid_lines),
        NamedGridLinesMap(), OrderedNamedGridLines()));
  }

  static scoped_refptr<CSSGridTrackListNonInterpolableValue> Create(
      const CSSGridTrackListNonInterpolableValue& start,
      const CSSGridTrackListNonInterpolableValue& end) {
    return base::AdoptRef(new CSSGridTrackListNonInterpolableValue(
        start.GetNamedGridLines(), start.GetOrderedNamedGridLines(),
        end.GetNamedGridLines(), end.GetOrderedNamedGridLines()));
  }

  bool Equals(const CSSGridTrackListNonInterpolableValue& other) const {
    return named_grid_lines_from_ == other.named_grid_lines_from_ &&
           ordered_named_grid_lines_from_ ==
               other.ordered_named_grid_lines_from_ &&
           named_grid_lines_to_ == other.named_grid_lines_to_ &&
           ordered_named_grid_lines_to_ == other.ordered_named_grid_lines_to_;
  }

  const NamedGridLinesMap& GetNamedGridLines() const {
    return named_grid_lines_from_;
  }
  const OrderedNamedGridLines& GetOrderedNamedGridLines() const {
    return ordered_named_grid_lines_from_;
  }

  const NamedGridLinesMap& GetCurrentNamedGridLines(double progress) const {
    return (progress < 0.5) ? named_grid_lines_from_ : named_grid_lines_to_;
  }
  const OrderedNamedGridLines& GetCurrentOrderedNamedGridLines(
      double progress) const {
    return (progress < 0.5) ? ordered_named_grid_lines_from_
                            : ordered_named_grid_lines_to_;
  }

  DECLARE_NON_INTERPOLABLE_VALUE_TYPE();

 private:
  explicit CSSGridTrackListNonInterpolableValue(
      NamedGridLinesMap named_grid_lines_from,
      OrderedNamedGridLines ordered_named_grid_lines_from,
      NamedGridLinesMap named_grid_lines_to,
      OrderedNamedGridLines ordered_named_grid_lines_to)
      : named_grid_lines_from_(std::move(named_grid_lines_from)),
        ordered_named_grid_lines_from_(
            std::move(ordered_named_grid_lines_from)),
        named_grid_lines_to_(std::move(named_grid_lines_to)),
        ordered_named_grid_lines_to_(std::move(ordered_named_grid_lines_to)) {}

  // For the first half of the interpolation, we return the 'from' values for
  // named grid lines. For the second half, we return the 'to' values. As the
  // named grid lines 'from' and 'to' values and its size may be different, we
  // have to cache both and return the appropriate value given the
  // interpolation's progress.
  NamedGridLinesMap named_grid_lines_from_;
  OrderedNamedGridLines ordered_named_grid_lines_from_;
  NamedGridLinesMap named_grid_lines_to_;
  OrderedNamedGridLines ordered_named_grid_lines_to_;
};

DEFINE_NON_INTERPOLABLE_VALUE_TYPE(CSSGridTrackListNonInterpolableValue);

template <>
struct DowncastTraits<CSSGridTrackListNonInterpolableValue> {
  static bool AllowFrom(const NonInterpolableValue* value) {
    return value && AllowFrom(*value);
  }
  static bool AllowFrom(const NonInterpolableValue& value) {
    return value.GetType() ==
           CSSGridTrackListNonInterpolableValue::static_type_;
  }
};

class UnderlyingGridTrackListChecker final
    : public CSSInterpolationType::CSSConversionChecker {
 public:
  explicit UnderlyingGridTrackListChecker(const InterpolationValue& underlying)
      : underlying_(MakeGarbageCollected<InterpolationValueGCed>(underlying)) {}
  ~UnderlyingGridTrackListChecker() final = default;

  void Trace(Visitor* visitor) const final {
    InterpolationType::ConversionChecker::Trace(visitor);
    visitor->Trace(underlying_);
  }

 private:
  bool IsValid(const StyleResolverState&,
               const InterpolationValue& underlying) const final {
    return To<InterpolableGridTrackList>(
               *underlying_->underlying().interpolable_value)
               .Equals(To<InterpolableGridTrackList>(
                   *underlying.interpolable_value)) &&
           To<CSSGridTrackListNonInterpolableValue>(
               *underlying_->underlying().non_interpolable_value)
               .Equals(To<CSSGridTrackListNonInterpolableValue>(
                   *underlying.non_interpolable_value));
  }

  const Member<const InterpolationValueGCed> underlying_;
};

class InheritedGridTrackListChecker
    : public CSSInterpolationType::CSSConversionChecker {
 public:
  explicit InheritedGridTrackListChecker(const NGGridTrackList& track_list,
                                         const CSSPropertyID& property_id)
      : track_list_(track_list), property_id_(property_id) {}

 private:
  bool IsValid(const StyleResolverState& state,
               const InterpolationValue&) const final {
    const ComputedStyle& style = *state.ParentStyle();
    const NGGridTrackList& state_track_list =
        (property_id_ == CSSPropertyID::kGridTemplateColumns)
            ? style.GridTemplateColumns().track_list
            : style.GridTemplateRows().track_list;

    if (track_list_.HasAutoRepeater() || state_track_list.HasAutoRepeater() ||
        track_list_.RepeaterCount() != state_track_list.RepeaterCount() ||
        track_list_.TrackCountWithoutAutoRepeat() !=
            state_track_list.TrackCountWithoutAutoRepeat()) {
      return false;
    }

    for (wtf_size_t i = 0; i < track_list_.RepeaterCount(); ++i) {
      if (!(track_list_.RepeatType(i) == state_track_list.RepeatType(i) &&
            track_list_.RepeatCount(i, 0) ==
                state_track_list.RepeatCount(i, 0) &&
            track_list_.RepeatSize(i) == state_track_list.RepeatSize(i))) {
        return false;
      }
    }
    return true;
  }

  const NGGridTrackList track_list_;
  const CSSPropertyID property_id_;
};

// static
InterpolableValue*
CSSGridTemplatePropertyInterpolationType::CreateInterpolableGridTrackList(
    const NGGridTrackList& track_list,
    const CSSProperty& property,
    float zoom) {
  return InterpolableGridTrackList::MaybeCreate(track_list, property, zoom);
}

PairwiseInterpolationValue
CSSGridTemplatePropertyInterpolationType::MaybeMergeSingles(
    InterpolationValue&& start,
    InterpolationValue&& end) const {
  if (!To<InterpolableGridTrackList>(*start.interpolable_value)
           .IsCompatibleWith(
               To<InterpolableGridTrackList>(*end.interpolable_value))) {
    return nullptr;
  }
  return PairwiseInterpolationValue(
      std::move(start.interpolable_value), std::move(end.interpolable_value),
      CSSGridTrackListNonInterpolableValue::Create(
          To<CSSGridTrackListNonInterpolableValue>(
              *start.non_interpolable_value),
          To<CSSGridTrackListNonInterpolableValue>(
              *end.non_interpolable_value)));
}

InterpolationValue
CSSGridTemplatePropertyInterpolationType::MaybeConvertNeutral(
    const InterpolationValue& underlying,
    ConversionCheckers& conversion_checkers) const {
  conversion_checkers.push_back(
      MakeGarbageCollected<UnderlyingGridTrackListChecker>(underlying));
  return InterpolationValue(underlying.interpolable_value->CloneAndZero(),
                            underlying.non_interpolable_value);
}

InterpolationValue
CSSGridTemplatePropertyInterpolationType::MaybeConvertInitial(
    const StyleResolverState& state,
    ConversionCheckers&) const {
  // 'none' cannot be interpolated.
  return nullptr;
}

InterpolationValue
CSSGridTemplatePropertyInterpolationType::MaybeConvertInherit(
    const StyleResolverState& state,
    ConversionCheckers& conversion_checkers) const {
  const ComputedStyle* parent_style = state.ParentStyle();
  if (!parent_style)
    return nullptr;

  const ComputedGridTrackList& parent_computed_grid_track_list =
      (property_id_ == CSSPropertyID::kGridTemplateColumns)
          ? parent_style->GridTemplateColumns()
          : parent_style->GridTemplateRows();
  const NGGridTrackList& parent_track_list =
      parent_computed_grid_track_list.track_list;

  conversion_checkers.push_back(
      MakeGarbageCollected<InheritedGridTrackListChecker>(parent_track_list,
                                                          property_id_));
  return InterpolationValue(
      CreateInterpolableGridTrackList(parent_track_list, CssProperty(),
                                      parent_style->EffectiveZoom()),
      CSSGridTrackListNonInterpolableValue::Create(
          parent_computed_grid_track_list.named_grid_lines,
          parent_computed_grid_track_list.ordered_named_grid_lines));
}

InterpolationValue CSSGridTemplatePropertyInterpolationType::
    MaybeConvertStandardPropertyUnderlyingValue(
        const ComputedStyle& style) const {
  const ComputedGridTrackList& computed_grid_track_list =
      (property_id_ == CSSPropertyID::kGridTemplateColumns)
          ? style.GridTemplateColumns()
          : style.GridTemplateRows();
  return InterpolationValue(
      CreateInterpolableGridTrackList(computed_grid_track_list.track_list,
                                      CssProperty(), style.EffectiveZoom()),
      CSSGridTrackListNonInterpolableValue::Create(
          computed_grid_track_list.named_grid_lines,
          computed_grid_track_list.ordered_named_grid_lines));
}

InterpolationValue CSSGridTemplatePropertyInterpolationType::MaybeConvertValue(
    const CSSValue& value,
    const StyleResolverState* state,
    ConversionCheckers&) const {
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(identifier_value->GetValueID(), CSSValueID::kNone);
    return InterpolationValue(nullptr);
  }

  ComputedGridTrackList computed_grid_track_list;
  StyleBuilderConverter::ConvertGridTrackList(
      value, computed_grid_track_list, *const_cast<StyleResolverState*>(state));
  return InterpolationValue(
      CreateInterpolableGridTrackList(computed_grid_track_list.track_list,
                                      CssProperty(),
                                      state->StyleBuilder().EffectiveZoom()),
      CSSGridTrackListNonInterpolableValue::Create(
          computed_grid_track_list.named_grid_lines,
          computed_grid_track_list.ordered_named_grid_lines));
}

void CSSGridTemplatePropertyInterpolationType::ApplyStandardPropertyValue(
    const InterpolableValue& interpolable_value,
    const NonInterpolableValue* non_interpolable_value,
    StyleResolverState& state) const {
  const InterpolableGridTrackList& interpolable_grid_track_list =
      To<InterpolableGridTrackList>(interpolable_value);
  const CSSGridTrackListNonInterpolableValue* non_interoplable_grid_track_list =
      To<CSSGridTrackListNonInterpolableValue>(non_interpolable_value);

  double progress = interpolable_grid_track_list.GetProgress();
  bool is_for_columns = property_id_ == CSSPropertyID::kGridTemplateColumns;
  ComputedStyleBuilder& builder = state.StyleBuilder();
  CSSToLengthConversionData conversion_data = state.CssToLengthConversionData();
  ComputedGridTrackList computed_grid_track_list(
      is_for_columns ? builder.GridTemplateColumns()
                     : builder.GridTemplateRows());

  computed_grid_track_list.track_list =
      interpolable_grid_track_list.CreateNGGridTrackList(conversion_data);
  computed_grid_track_list.named_grid_lines =
      non_interoplable_grid_track_list->GetCurrentNamedGridLines(progress);
  computed_grid_track_list.ordered_named_grid_lines =
      non_interoplable_grid_track_list->GetCurrentOrderedNamedGridLines(
          progress);

  if (is_for_columns)
    builder.SetGridTemplateColumns(computed_grid_track_list);
  else
    builder.SetGridTemplateRows(computed_grid_track_list);
}

void CSSGridTemplatePropertyInterpolationType::Composite(
    UnderlyingValueOwner& underlying_value_owner,
    double underlying_fraction,
    const InterpolationValue& value,
    double interpolation_fraction) const {
  if (!To<InterpolableGridTrackList>(
           *underlying_value_owner.Value().interpolable_value)
           .IsCompatibleWith(
               To<InterpolableGridTrackList>(*value.interpolable_value))) {
    underlying_value_owner.Set(*this, value);
    return;
  }
  underlying_value_owner.SetNonInterpolableValue(value.non_interpolable_value);
  underlying_value_owner.MutableValue().interpolable_value->ScaleAndAdd(
      underlying_fraction, *value.interpolable_value);
}

}  // namespace blink
```
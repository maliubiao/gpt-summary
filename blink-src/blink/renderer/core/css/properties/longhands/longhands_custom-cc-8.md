Response:
The user wants a summary of the functionality of the provided C++ code file. I need to analyze the code, identify its purpose, and explain its relationship to web technologies like JavaScript, HTML, and CSS. I should also provide examples, potential user errors, and how a user might trigger this code.

**Plan:**

1. **Overall Function:** Determine the main goal of the `longhands_custom.cc` file based on the class names and functions defined.
2. **CSS Property Handling:** Identify which CSS properties are handled in this file.
3. **Parsing:** Analyze the `ParseSingleValue` functions to understand how CSS property values are parsed from text.
4. **Computed Style:** Examine the `CSSValueFromComputedStyleInternal` functions to see how CSS property values are retrieved from the computed style.
5. **Relationship to Web Tech:** Explain how the parsing and computed style retrieval relate to CSS, and potentially HTML and JavaScript interactions.
6. **Examples:** Provide concrete examples of CSS syntax that would be processed by this code.
7. **Logic and I/O:**  Describe the input (CSS text) and output (internal representation of CSS values) of the parsing functions.
8. **User Errors:** Identify common mistakes users might make in their CSS that would lead to parsing errors.
9. **User Actions:** Explain the sequence of user actions that would cause the browser to parse CSS and potentially execute this code.
10. **File Purpose (Part 9 of 13):** Summarize the specific role of this file within the larger CSS parsing and style computation process.
目录 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 是 Chromium Blink 引擎中处理 **CSS 长属性** 的一个源代码文件。这个文件主要负责定义和实现一些**非标准或较新的 CSS 属性**的 **解析 (parsing)** 和 **计算样式 (computed style) 获取** 的逻辑。

**功能归纳 (作为第 9 部分):**

这个文件作为处理 CSS 长属性的一部分，专门负责定义一些特定的、通常是较新的或实验性的 CSS 属性的解析和计算样式获取逻辑。它确保了当浏览器遇到这些 CSS 属性时，能够正确地理解它们的值，并在渲染页面时应用它们的效果。这个文件中的代码连接了 CSS 文本表示和 Blink 引擎内部的样式表示，是 CSS 引擎工作流程中的关键环节。

**具体功能列举:**

这个文件主要定义了以下 CSS 属性的处理逻辑：

* **`view-transition-name`**:  用于指定一个元素的视图转换名称，配合视图转换 API 使用。
* **`view-transition-class`**: 用于指定一个元素参与的视图转换的类名，同样是视图转换 API 的一部分。
* **`view-transition-group`**: 用于控制视图转换中元素的组合方式。
* **`view-transition-capture-mode`**:  控制视图转换中元素的捕获模式（例如，分层或扁平）。
* **`paint-order`**:  定义 SVG 元素绘制顺序。
* **`perspective`**:  定义 3D 变换的透视效果。
* **`perspective-origin`**: 定义 3D 透视效果的原点。
* **`pointer-events`**:  指定在什么情况下一个元素可以成为鼠标事件的目标。
* **`position`**:  指定元素的定位方式（`static`, `relative`, `absolute`, `fixed`, `sticky`）。
* **`position-try-fallbacks`**: 定义在定位元素时尝试的备用位置。
* **`position-try-order`**:  定义定位元素时尝试位置的顺序。
* **`quotes`**:  指定用于 `open-quote` 和 `close-quote` 伪元素的引号类型。
* **`r`**:  用于 `border-radius` 属性，定义椭圆角的水平半径。
* **`reading-flow`**:  定义元素内容阅读的流动方向。
* **`resize`**:  指定元素是否可以被用户调整大小以及调整的方向。
* **`right`**:  指定定位元素的右外边距边界与其包含块右边缘之间的偏移量。
* **`rotate`**:  定义元素的 2D 或 3D 旋转变换。
* **`row-gap`**:  在网格布局或弹性盒布局中，定义行之间的间距。
* **`rx`**:  用于 `border-radius` 属性，定义椭圆角的水平半径。
* **`ry`**:  用于 `border-radius` 属性，定义椭圆角的垂直半径。
* **`scale`**:  定义元素的 2D 或 3D 缩放变换。
* **`scroll-marker-group`**:  用于关联滚动标记和滚动容器。
* **`scrollbar-color`**:  设置元素的滚动条颜色。
* **`scrollbar-gutter`**:  为滚动条预留空间。
* **`scrollbar-width`**:  设置元素的滚动条宽度。
* **`scroll-behavior`**:  指定滚动框的滚动行为是平滑滚动还是立即滚动。
* **`scroll-margin-block-end`**, **`scroll-margin-block-start`**, **`scroll-margin-bottom`**, **`scroll-margin-inline-end`**, **`scroll-margin-inline-start`**, **`scroll-margin-left`**, **`scroll-margin-right`**, **`scroll-margin-top`**:  定义元素的滚动边距，影响滚动捕捉点的计算。
* **`scroll-padding-block-end`** (代码片段未完整包含，但可以推测)：定义元素的滚动内边距，影响滚动捕捉点的计算。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

1. **CSS 解析:**
   - **功能:** `ParseSingleValue` 函数负责解析 CSS 文本中这些属性的值。例如，对于 `perspective: 300px;`，`Perspective::ParseSingleValue` 会将字符串 `"300px"` 解析为一个表示长度的 CSS 值对象。
   - **关系:** 这是 CSS 引擎理解和应用样式的第一步。
   - **例子:**
     ```css
     .element {
       view-transition-name: image-slide;
       perspective: 500px;
       rotate: 45deg;
     }
     ```

2. **CSS 计算样式:**
   - **功能:** `CSSValueFromComputedStyleInternal` 函数负责从元素的计算样式对象中获取这些属性的值，并将其转换为 CSS 值对象。计算样式是经过层叠、继承等规则计算后的最终样式。
   - **关系:** JavaScript 可以通过 `getComputedStyle` 方法访问元素的计算样式，从而获取这些 CSS 属性的最终值。
   - **例子:**
     ```javascript
     const element = document.querySelector('.element');
     const computedStyle = getComputedStyle(element);
     const perspectiveValue = computedStyle.perspective; // 获取计算后的 perspective 值 (例如 "500px")
     const rotateValue = computedStyle.rotate; // 获取计算后的 rotate 值 (例如 "45deg")
     ```

3. **HTML 元素应用:**
   - **功能:** 这些 CSS 属性最终会应用到 HTML 元素上，影响元素的渲染效果和行为。
   - **关系:**  CSS 规则通过选择器与 HTML 元素关联，这些属性定义了这些元素的视觉呈现和交互方式。
   - **例子:**
     ```html
     <!DOCTYPE html>
     <html>
     <head>
       <style>
         .element {
           width: 200px;
           height: 100px;
           background-color: lightblue;
           transform: rotate(30deg); /* 使用 rotate 的效果 */
         }
       </style>
     </head>
     <body>
       <div class="element">This is a rotated element.</div>
     </body>
     </html>
     ```

**逻辑推理 (假设输入与输出):**

假设输入以下 CSS 规则：

```css
.box {
  perspective: none;
  rotate: 30deg;
  rotate: 30deg 1 0 0;
  rotate: 30deg x;
  rotate: x 30deg;
  rotate: 30deg 0 1 0;
  rotate: 30deg y;
  rotate: y 30deg;
  rotate: 30deg 0 0 1;
  rotate: 30deg z;
  rotate: z 30deg;
  paint-order: normal fill stroke;
  paint-order: stroke fill markers;
}
```

**`Perspective::ParseSingleValue` 的假设输入与输出:**

* **输入:**  `"none"` (来自 `perspective: none;`)
* **输出:**  一个表示 `CSSValueID::kNone` 的 `CSSIdentifierValue` 对象。

**`Rotate::ParseSingleValue` 的假设输入与输出:**

* **输入:** `"30deg"` (来自 `rotate: 30deg;`)
* **输出:** 一个包含一个角度值的 `CSSValueList` 对象。
* **输入:** `"30deg 1 0 0"` (来自 `rotate: 30deg 1 0 0;`)
* **输出:** 一个包含一个轴向量（x 轴）和一个角度值的 `CSSValueList` 对象。
* **输入:** `"30deg x"` (来自 `rotate: 30deg x;`)
* **输出:** 一个包含一个轴向量（x 轴）和一个角度值的 `CSSValueList` 对象。
* **输入:** `"x 30deg"` (来自 `rotate: x 30deg;`)
* **输出:** 一个包含一个轴向量（x 轴）和一个角度值的 `CSSValueList` 对象。
* **输入:** `"30deg 0 1 0"` (来自 `rotate: 30deg 0 1 0;`)
* **输出:** 一个包含一个轴向量（y 轴）和一个角度值的 `CSSValueList` 对象。
* **输入:** `"30deg y"` (来自 `rotate: 30deg y;`)
* **输出:** 一个包含一个轴向量（y 轴）和一个角度值的 `CSSValueList` 对象。
* **输入:** `"y 30deg"` (来自 `rotate: y 30deg;`)
* **输出:** 一个包含一个轴向量（y 轴）和一个角度值的 `CSSValueList` 对象。
* **输入:** `"30deg 0 0 1"` (来自 `rotate: 30deg 0 0 1;`)
* **输出:** 一个包含一个角度值的 `CSSValueList` 对象 (z 轴被标准化)。
* **输入:** `"30deg z"` (来自 `rotate: 30deg z;`)
* **输出:** 一个包含一个角度值的 `CSSValueList` 对象 (z 轴被标准化)。
* **输入:** `"z 30deg"` (来自 `rotate: z 30deg;`)
* **输出:** 一个包含一个角度值的 `CSSValueList` 对象 (z 轴被标准化)。

**`PaintOrder::ParseSingleValue` 的假设输入与输出:**

* **输入:** `"normal fill stroke"` (来自 `paint-order: normal fill stroke;`)
* **输出:** `CSSIdentifierValue::Create(CSSValueID::kNormal)` (因为以 normal 开头，后续会被忽略)
* **输入:** `"fill stroke markers"` (来自 `paint-order: stroke fill markers;`)
* **输出:** 一个包含 `fill`, `stroke` 和 `markers` 标识符的 `CSSValueList` 对象，顺序为 `fill`, `stroke`, `markers`。

**用户或编程常见的使用错误举例说明:**

1. **`perspective` 属性值错误:**
   - **错误 CSS:** `perspective: -100px;` (负值无效)
   - **说明:** `Perspective::ParseSingleValue` 会返回 `nullptr`，因为期望非负值。

2. **`rotate` 属性值错误:**
   - **错误 CSS:** `rotate: abc;` (无效的角度值)
   - **说明:** `Rotate::ParseSingleValue` 无法解析 `"abc"` 为有效的角度，会返回 `nullptr`。
   - **错误 CSS:** `rotate: 30deg 1;` (缺少轴向量的足够分量)
   - **说明:** `Rotate::ParseSingleValue` 会返回 `nullptr`。

3. **`paint-order` 属性值错误:**
   - **错误 CSS:** `paint-order: fill fill;` (重复的关键字)
   - **说明:** `PaintOrder::ParseSingleValue` 在遇到重复的关键字时会停止解析，可能不会得到预期的结果。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编辑 HTML 或 CSS 文件:** 开发者在文本编辑器中修改了 HTML 或 CSS 文件，引入了上述提到的 CSS 属性和值。
2. **浏览器加载网页:** 用户打开包含这些修改的 HTML 文件的网页，或者浏览器重新加载页面。
3. **HTML 解析和 DOM 构建:** 浏览器解析 HTML 文件，构建 DOM 树。
4. **CSS 解析:** 浏览器解析 `<style>` 标签或外部 CSS 文件中的 CSS 规则。当解析器遇到例如 `perspective: 300px;` 这样的规则时，会调用与 `perspective` 属性关联的解析函数 `Perspective::ParseSingleValue`。
5. **样式计算:**  解析后的 CSS 值会被用于计算元素的最终样式。在计算样式时，`CSSValueFromComputedStyleInternal` 函数会被调用，将内部的样式表示转换为 CSS 值对象，供 JavaScript 或渲染引擎使用。
6. **渲染:**  最终计算出的样式会被用于渲染网页，包括应用透视变换、旋转等效果。

**作为调试线索:**  如果开发者发现某个元素的 `perspective` 或 `rotate` 效果没有生效，或者 JavaScript 通过 `getComputedStyle` 获取到的值不正确，那么就可以怀疑是在 CSS 解析或样式计算阶段出现了问题。`longhands_custom.cc` 文件中的代码就是这些阶段的关键执行部分。通过查看这个文件中的代码，可以了解特定属性是如何被解析和处理的，从而帮助定位问题。例如，如果解析逻辑有误，或者计算样式获取逻辑不正确，都会导致最终的渲染结果与预期不符。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共13部分，请归纳一下它的功能

"""
:kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return RuntimeEnabledFeatures::CSSViewTransitionAutoNameEnabled()
               ? css_parsing_utils::ConsumeIdent(stream)
               : nullptr;
  }
  return css_parsing_utils::ConsumeCustomIdent(stream, context);
}

const CSSValue* ViewTransitionName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.ViewTransitionName()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  if (style.ViewTransitionName()->IsAuto()) {
    CHECK(RuntimeEnabledFeatures::CSSViewTransitionAutoNameEnabled());
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  CHECK(style.ViewTransitionName()->IsCustom());
  return MakeGarbageCollected<CSSCustomIdentValue>(
      style.ViewTransitionName()->CustomName());
}

const CSSValue* ViewTransitionClass::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // The valid syntax is `none | <<custom-ident>>*` where the list of custom
  // idents can't include `none`. So handle `none` separately, and then consume
  // a list without `none`s.
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeSpaceSeparatedList(
      ConsumeCustomIdentExcludingNone, stream, context);
}

const CSSValue* ViewTransitionClass::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const auto& view_transition_class = style.ViewTransitionClass();
  if (!view_transition_class || view_transition_class->GetNames().empty()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  CSSValueList* ident_list = CSSValueList::CreateSpaceSeparated();
  for (const auto& class_name : view_transition_class->GetNames()) {
    auto* value =
        MakeGarbageCollected<CSSCustomIdentValue>(class_name->GetName());
    value->EnsureScopedValue(class_name->GetTreeScope());
    ident_list->Append(*value);
  }
  return ident_list;
}

const CSSValue* ViewTransitionGroup::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  auto id = stream.Peek().Id();
  if (id == CSSValueID::kNormal || id == CSSValueID::kNearest ||
      id == CSSValueID::kContain) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeCustomIdent(stream, context);
}

const CSSValue* ViewTransitionCaptureMode::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  auto id = stream.Peek().Id();
  if (id == CSSValueID::kLayered || id == CSSValueID::kFlat) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return nullptr;
}

const CSSValue* ViewTransitionGroup::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.ViewTransitionGroup().IsNormal()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  } else if (style.ViewTransitionGroup().IsNearest()) {
    return CSSIdentifierValue::Create(CSSValueID::kNearest);
  } else if (style.ViewTransitionGroup().IsContain()) {
    return CSSIdentifierValue::Create(CSSValueID::kContain);
  }
  return MakeGarbageCollected<CSSCustomIdentValue>(
      style.ViewTransitionGroup().CustomName());
}

const CSSValue* ViewTransitionCaptureMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  switch (style.ViewTransitionCaptureMode()) {
    case blink::StyleViewTransitionCaptureMode::kFlat:
      return CSSIdentifierValue::Create(CSSValueID::kFlat);
    case blink::StyleViewTransitionCaptureMode::kLayered:
      return CSSIdentifierValue::Create(CSSValueID::kLayered);
  }
}

const CSSValue* PaintOrder::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNormal) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  Vector<CSSValueID, 3> paint_type_list;
  CSSIdentifierValue* fill = nullptr;
  CSSIdentifierValue* stroke = nullptr;
  CSSIdentifierValue* markers = nullptr;
  do {
    CSSValueID id = stream.Peek().Id();
    if (id == CSSValueID::kFill && !fill) {
      fill = css_parsing_utils::ConsumeIdent(stream);
    } else if (id == CSSValueID::kStroke && !stroke) {
      stroke = css_parsing_utils::ConsumeIdent(stream);
    } else if (id == CSSValueID::kMarkers && !markers) {
      markers = css_parsing_utils::ConsumeIdent(stream);
    } else {
      break;
    }
    paint_type_list.push_back(id);
  } while (!stream.AtEnd());

  if (paint_type_list.empty()) {
    return nullptr;
  }

  // After parsing we serialize the paint-order list. Since it is not possible
  // to pop a last list items from CSSValueList without bigger cost, we create
  // the list after parsing.
  CSSValueID first_paint_order_type = paint_type_list.at(0);
  CSSValueList* paint_order_list = CSSValueList::CreateSpaceSeparated();
  switch (first_paint_order_type) {
    case CSSValueID::kFill:
    case CSSValueID::kStroke:
      paint_order_list->Append(
          first_paint_order_type == CSSValueID::kFill ? *fill : *stroke);
      if (paint_type_list.size() > 1) {
        if (paint_type_list.at(1) == CSSValueID::kMarkers) {
          paint_order_list->Append(*markers);
        }
      }
      break;
    case CSSValueID::kMarkers:
      paint_order_list->Append(*markers);
      if (paint_type_list.size() > 1) {
        if (paint_type_list.at(1) == CSSValueID::kStroke) {
          paint_order_list->Append(*stroke);
        }
      }
      break;
    default:
      NOTREACHED();
  }

  return paint_order_list;
}

const CSSValue* PaintOrder::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const EPaintOrder paint_order = style.PaintOrder();
  if (paint_order == kPaintOrderNormal) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  const unsigned canonical_length =
      PaintOrderArray::CanonicalLength(paint_order);
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  const PaintOrderArray paint_order_array(paint_order);
  for (unsigned i = 0; i < canonical_length; ++i) {
    list->Append(*CSSIdentifierValue::Create(paint_order_array[i]));
  }
  return list;
}

const CSSValue* Perspective::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& localContext) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  CSSPrimitiveValue* parsed_value = css_parsing_utils::ConsumeLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
  bool use_legacy_parsing = localContext.UseAliasParsing();
  if (!parsed_value && use_legacy_parsing) {
    double perspective;
    if (!css_parsing_utils::ConsumeNumberRaw(stream, context, perspective) ||
        perspective < 0.0) {
      return nullptr;
    }
    context.Count(WebFeature::kUnitlessPerspectiveInPerspectiveProperty);
    parsed_value = CSSNumericLiteralValue::Create(
        perspective, CSSPrimitiveValue::UnitType::kPixels);
  }
  return parsed_value;
}

const CSSValue* Perspective::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.HasPerspective()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return ZoomAdjustedPixelValue(style.Perspective(), style);
}

const CSSValue* PerspectiveOrigin::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumePosition(stream, context,
                         css_parsing_utils::UnitlessQuirk::kForbid,
                         std::optional<WebFeature>());
}

bool PerspectiveOrigin::IsLayoutDependent(const ComputedStyle* style,
                                          LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* PerspectiveOrigin::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (layout_object) {
    PhysicalRect box;
    if (layout_object->IsBox()) {
      box = To<LayoutBox>(layout_object)->PhysicalBorderBoxRect();
    }

    return MakeGarbageCollected<CSSValuePair>(
        ZoomAdjustedPixelValue(
            MinimumValueForLength(style.PerspectiveOrigin().X(), box.Width()),
            style),
        ZoomAdjustedPixelValue(
            MinimumValueForLength(style.PerspectiveOrigin().Y(), box.Height()),
            style),
        CSSValuePair::kKeepIdenticalValues);
  } else {
    return MakeGarbageCollected<CSSValuePair>(
        ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
            style.PerspectiveOrigin().X(), style),
        ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
            style.PerspectiveOrigin().Y(), style),
        CSSValuePair::kKeepIdenticalValues);
  }
}

const CSSValue* PointerEvents::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.PointerEvents());
}

const CSSValue* Position::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.PositionInternal());
}

const CSSValue* PositionTryFallbacks::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePositionTryFallbacks(stream, context);
}

const CSSValue* PositionTryFallbacks::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const blink::PositionTryFallbacks* fallbacks =
          style.GetPositionTryFallbacks()) {
    return ComputedStyleUtils::ValueForPositionTryFallbacks(*fallbacks);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

void PositionTryFallbacks::ApplyValue(StyleResolverState& state,
                                      const CSSValue& value,
                                      ValueMode) const {
  if (value.IsIdentifierValue()) {
    DCHECK(To<CSSIdentifierValue>(value).GetValueID() == CSSValueID::kNone);
    // Just represent as nullptr.
    return;
  }
  HeapVector<PositionTryFallback> fallbacks;
  for (const auto& fallback : To<CSSValueList>(value)) {
    // position-area( <position-area> )
    if (const auto* function = DynamicTo<CSSFunctionValue>(fallback.Get())) {
      CHECK(!RuntimeEnabledFeatures::CSSPositionAreaValueEnabled());
      CHECK_EQ(1u, function->length());
      blink::PositionArea position_area =
          StyleBuilderConverter::ConvertPositionArea(state, function->First());
      fallbacks.push_back(PositionTryFallback(position_area));
      continue;
    }
    // <'position-area'>
    if (IsA<CSSValuePair>(fallback.Get()) ||
        IsA<CSSIdentifierValue>(fallback.Get())) {
      blink::PositionArea position_area =
          StyleBuilderConverter::ConvertPositionArea(state, *fallback.Get());
      fallbacks.push_back(PositionTryFallback(position_area));
      continue;
    }
    // [<dashed-ident> || <try-tactic>]
    const ScopedCSSName* scoped_name = nullptr;
    TryTacticList tactic_list = {TryTactic::kNone};
    wtf_size_t tactic_index = 0;
    for (const auto& name_or_tactic : To<CSSValueList>(*fallback)) {
      if (const auto* name = DynamicTo<CSSCustomIdentValue>(*name_or_tactic)) {
        scoped_name = StyleBuilderConverter::ConvertCustomIdent(state, *name);
        continue;
      }
      CHECK_LT(tactic_index, tactic_list.size());
      tactic_list[tactic_index++] =
          To<CSSIdentifierValue>(*name_or_tactic).ConvertTo<TryTactic>();
    }
    fallbacks.push_back(PositionTryFallback(scoped_name, tactic_list));
  }
  DCHECK(!fallbacks.empty());
  state.StyleBuilder().SetPositionTryFallbacks(
      MakeGarbageCollected<blink::PositionTryFallbacks>(fallbacks));
}

const CSSValue* PositionTryOrder::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNormal);
}

const CSSValue* PositionTryOrder::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.PositionTryOrder());
}

const CSSValue* Quotes::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  if (auto* value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kAuto, CSSValueID::kNone>(
              stream)) {
    return value;
  }
  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  while (!stream.AtEnd()) {
    CSSStringValue* parsed_value = css_parsing_utils::ConsumeString(stream);
    if (!parsed_value) {
      // NOTE: Technically, if we consumed an odd number of strings,
      // we should have returned success here but un-consumed
      // the last string (since we should allow any arbitrary junk).
      // However, in practice, the only thing we need to care about
      // is !important, since we're not part of a shorthand,
      // so we let it slip.
      break;
    }
    values->Append(*parsed_value);
  }
  if (values->length() && values->length() % 2 == 0) {
    return values;
  }
  return nullptr;
}

const CSSValue* Quotes::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.Quotes()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (style.Quotes()->size()) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    for (int i = 0; i < style.Quotes()->size(); i++) {
      list->Append(*MakeGarbageCollected<CSSStringValue>(
          style.Quotes()->GetOpenQuote(i)));
      list->Append(*MakeGarbageCollected<CSSStringValue>(
          style.Quotes()->GetCloseQuote(i)));
    }
    return list;
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* R::ParseSingleValue(CSSParserTokenStream& stream,
                                    const CSSParserContext& context,
                                    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* R::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.R(), style);
}

const CSSValue* ReadingFlow::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool,
    CSSValuePhase) const {
  return CSSIdentifierValue::Create(style.ReadingFlow());
}

const CSSValue* Resize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Resize());
}

void Resize::ApplyValue(StyleResolverState& state,
                        const CSSValue& value,
                        ValueMode) const {
  const CSSIdentifierValue& identifier_value = To<CSSIdentifierValue>(value);

  EResize r = EResize::kNone;
  if (identifier_value.GetValueID() == CSSValueID::kAuto ||
      identifier_value.GetValueID() == CSSValueID::kInternalTextareaAuto) {
    if (Settings* settings = state.GetDocument().GetSettings()) {
      r = settings->GetTextAreasAreResizable() ? EResize::kBoth
                                               : EResize::kNone;
    }
    if (identifier_value.GetValueID() == CSSValueID::kAuto) {
      UseCounter::Count(state.GetDocument(), WebFeature::kCSSResizeAuto);
    }
  } else {
    r = identifier_value.ConvertTo<EResize>();
  }
  state.StyleBuilder().SetResize(r);
}

const CSSValue* Right::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context,
      css_parsing_utils::UnitlessUnlessShorthand(local_context), anchor_types);
}

bool Right::IsLayoutDependent(const ComputedStyle* style,
                              LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* Right::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPositionOffset(style, *this,
                                                    layout_object);
}

const CSSValue* Rotate::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();

  CSSValue* rotation = css_parsing_utils::ConsumeAngle(
      stream, context, std::optional<WebFeature>());

  CSSValue* axis = css_parsing_utils::ConsumeAxis(stream, context);
  if (axis) {
    if (To<cssvalue::CSSAxisValue>(axis)->AxisName() != CSSValueID::kZ) {
      // The z axis should be normalized away and stored as a 2D rotate.
      list->Append(*axis);
    }
  } else if (!rotation) {
    return nullptr;
  }

  if (!rotation) {
    rotation = css_parsing_utils::ConsumeAngle(stream, context,
                                               std::optional<WebFeature>());
    if (!rotation) {
      return nullptr;
    }
  }
  list->Append(*rotation);

  return list;
}

const CSSValue* Rotate::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.Rotate()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (style.Rotate()->X() != 0 || style.Rotate()->Y() != 0 ||
      style.Rotate()->Z() != 1) {
    const cssvalue::CSSAxisValue* axis =
        MakeGarbageCollected<cssvalue::CSSAxisValue>(
            MakeGarbageCollected<CSSNumericLiteralValue>(
                style.Rotate()->X(), CSSPrimitiveValue::UnitType::kNumber),
            MakeGarbageCollected<CSSNumericLiteralValue>(
                style.Rotate()->Y(), CSSPrimitiveValue::UnitType::kNumber),
            MakeGarbageCollected<CSSNumericLiteralValue>(
                style.Rotate()->Z(), CSSPrimitiveValue::UnitType::kNumber));
    list->Append(*axis);
  }
  list->Append(*CSSNumericLiteralValue::Create(
      style.Rotate()->Angle(), CSSPrimitiveValue::UnitType::kDegrees));
  return list;
}

const CSSValue* RowGap::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGapLength(stream, context);
}

const CSSValue* RowGap::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGapLength(style.RowGap(), style);
}

const CSSValue* Rx::ParseSingleValue(CSSParserTokenStream& stream,
                                     const CSSParserContext& context,
                                     const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* Rx::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Rx(), style);
}

const CSSValue* Ry::ParseSingleValue(CSSParserTokenStream& stream,
                                     const CSSParserContext& context,
                                     const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* Ry::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Ry(), style);
}

const CSSValue* Scale::ParseSingleValue(CSSParserTokenStream& stream,
                                        const CSSParserContext& context,
                                        const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSPrimitiveValue* x_scale = css_parsing_utils::ConsumeNumberOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (!x_scale) {
    return nullptr;
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*x_scale);

  CSSPrimitiveValue* y_scale = css_parsing_utils::ConsumeNumberOrPercent(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
  if (y_scale) {
    CSSPrimitiveValue* z_scale = css_parsing_utils::ConsumeNumberOrPercent(
        stream, context, CSSPrimitiveValue::ValueRange::kAll);
    if (z_scale &&
        (!z_scale->IsNumericLiteralValue() ||
         To<CSSNumericLiteralValue>(z_scale)->DoubleValue() != 1.0)) {
      list->Append(*y_scale);
      list->Append(*z_scale);
    } else if (!x_scale->IsNumericLiteralValue() ||
               !y_scale->IsNumericLiteralValue() ||
               To<CSSNumericLiteralValue>(x_scale)->DoubleValue() !=
                   To<CSSNumericLiteralValue>(y_scale)->DoubleValue()) {
      list->Append(*y_scale);
    }
  }

  return list;
}

const CSSValue* Scale::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  ScaleTransformOperation* scale = style.Scale();
  if (!scale) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSNumericLiteralValue::Create(
      scale->X(), CSSPrimitiveValue::UnitType::kNumber));

  if (scale->Z() == 1) {
    if (scale->X() != scale->Y()) {
      list->Append(*CSSNumericLiteralValue::Create(
          scale->Y(), CSSPrimitiveValue::UnitType::kNumber));
    }
  } else {
    list->Append(*CSSNumericLiteralValue::Create(
        scale->Y(), CSSPrimitiveValue::UnitType::kNumber));
    list->Append(*CSSNumericLiteralValue::Create(
        scale->Z(), CSSNumericLiteralValue::UnitType::kNumber));
  }
  return list;
}

const CSSValue* ScrollMarkerGroup::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ScrollMarkerGroup());
}

// https://www.w3.org/TR/css-scrollbars/
// auto | <color>{2}
const CSSValue* ScrollbarColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  DCHECK(RuntimeEnabledFeatures::ScrollbarColorEnabled());

  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValue* thumb_color = css_parsing_utils::ConsumeColor(stream, context);
  if (!thumb_color) {
    return nullptr;
  }

  CSSValue* track_color = css_parsing_utils::ConsumeColor(stream, context);
  if (!track_color) {
    return nullptr;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*thumb_color);
  list->Append(*track_color);
  return list;
}

const CSSValue* ScrollbarColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleScrollbarColor* scrollbar_color = style.UsedScrollbarColor();
  if (!scrollbar_color) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*ComputedStyleUtils::CurrentColorOrValidColor(
      style, scrollbar_color->GetThumbColor(), value_phase));
  list->Append(*ComputedStyleUtils::CurrentColorOrValidColor(
      style, scrollbar_color->GetTrackColor(), value_phase));
  return list;
}

// https://www.w3.org/TR/css-overflow-4
// auto | stable && both-edges?
const CSSValue* ScrollbarGutter::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (auto* value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kAuto>(stream)) {
    return value;
  }

  CSSIdentifierValue* stable = nullptr;
  CSSIdentifierValue* both_edges = nullptr;

  while (!stream.AtEnd()) {
    if (!stable) {
      if ((stable =
               css_parsing_utils::ConsumeIdent<CSSValueID::kStable>(stream))) {
        continue;
      }
    }
    CSSValueID id = stream.Peek().Id();
    if (id == CSSValueID::kBothEdges && !both_edges) {
      both_edges = css_parsing_utils::ConsumeIdent(stream);
    } else {
      // Something that didn't parse, or end-of-stream, or duplicate both-edges.
      // End-of-stream is success; the caller will clean up for us in the
      // failure case (since we didn't consume the erroneous token).
      break;
    }
  }
  if (!stable) {
    return nullptr;
  }
  if (both_edges) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    list->Append(*stable);
    list->Append(*both_edges);
    return list;
  }
  return stable;
}

const CSSValue* ScrollbarGutter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  auto scrollbar_gutter = style.ScrollbarGutter();
  if (scrollbar_gutter == kScrollbarGutterAuto) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  DCHECK(scrollbar_gutter & kScrollbarGutterStable);

  CSSValue* stable = nullptr;
  if (scrollbar_gutter & kScrollbarGutterStable) {
    stable = CSSIdentifierValue::Create(CSSValueID::kStable);
  }

  if (!(scrollbar_gutter & kScrollbarGutterBothEdges)) {
    return stable;
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*stable);
  if (scrollbar_gutter & kScrollbarGutterBothEdges) {
    list->Append(*CSSIdentifierValue::Create(kScrollbarGutterBothEdges));
  }
  return list;
}

const CSSValue* ScrollbarWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.UsedScrollbarWidth());
}

const CSSValue* ScrollBehavior::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetScrollBehavior());
}

const CSSValue* ScrollMarginBlockEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginBlockStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginBottom::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginBottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.ScrollMarginBottom(), style);
}

const CSSValue* ScrollMarginInlineEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginInlineStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginLeft::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginLeft::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.ScrollMarginLeft(), style);
}

const CSSValue* ScrollMarginRight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginRight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.ScrollMarginRight(), style);
}

const CSSValue* ScrollMarginTop::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return ConsumeLength(stream, context, CSSPrimitiveValue::ValueRange::kAll,
                       css_parsing_utils::UnitlessQuirk::kForbid);
}

const CSSValue* ScrollMarginTop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ZoomAdjustedPixelValue(style.ScrollMarginTop(), style);
}

const CSSValue* ScrollPaddingBlockEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeScrollPadding(stream, context);
}

const CSSValu
"""


```
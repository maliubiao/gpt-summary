Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Initial Understanding of the Request:**

The request asks for the functionality of a specific Chromium Blink engine source code file (`longhands_custom.cc`), its relation to web technologies (HTML, CSS, JavaScript), and to provide examples, logic inferences, common user errors, debugging tips, and a summary. It's the 6th part of 13, implying a larger context (likely defining various CSS properties).

**2. Core Function Identification - The "What":**

The first step is to read through the code and identify the primary actors: classes like `GridTemplateAreas`, `GridTemplateColumns`, `Height`, `PopoverShowDelay`, `HyphenateLimitChars`, etc. Each of these class names strongly suggests they represent individual CSS properties.

* **Key Observation:** The naming convention (`GridTemplateAreas::`, `Height::`, etc.) and the functions within each class (`ParseSingleValue`, `CSSValueFromComputedStyleInternal`, `InitialValue`, `IsLayoutDependent`) are characteristic of how CSS properties are defined and handled within a browser engine.

* **Further Inspection:** The function names provide clues about their roles:
    * `ParseSingleValue`: Deals with taking the string representation of the CSS property value and converting it into an internal representation. This links directly to CSS syntax.
    * `CSSValueFromComputedStyleInternal`:  Handles getting the final, computed value of the property after all cascading and inheritance have been applied. This connects to the browser's rendering engine and how it determines the final styling.
    * `InitialValue`: Specifies the default value of the property.
    * `IsLayoutDependent`:  Indicates whether changes to this property require recalculating the layout of the page. This is a performance-critical aspect of rendering.

* **Internal Visited Properties:** A significant section deals with properties prefixed with `InternalVisited`. This immediately flags them as related to how visited links are styled, which is a special case due to privacy concerns.

**3. Relationship to Web Technologies - The "How":**

Once the core functionality (representing CSS properties) is established, the connection to HTML, CSS, and JavaScript becomes clearer:

* **CSS:** The code directly implements how CSS properties are parsed, computed, and their initial values are defined. The code interacts with CSS syntax elements like keywords (`none`, `auto`, `drop`, `raise`), units (pixels, seconds), and complex values (like grid template definitions).

* **HTML:** These CSS properties are applied to HTML elements. The `LayoutObject*` parameters in some functions indicate interaction with the browser's internal representation of the HTML document structure. The effect of these properties is to style the visual presentation of HTML elements.

* **JavaScript:** While this specific file doesn't directly execute JavaScript, JavaScript can manipulate CSS properties, leading to these code paths being executed. For instance, `element.style.height = '100px'` or accessing computed styles via `getComputedStyle`.

**4. Examples, Inferences, and Common Errors - The "Show Me":**

With the understanding of *what* the code does and *how* it relates to web technologies, we can generate specific examples:

* **CSS Examples:**  Simple CSS rules demonstrating the properties.
* **JavaScript Examples:**  JavaScript code interacting with the properties.
* **Logic Inferences:**  Hypothetical CSS inputs and how the parsing logic might interpret them (e.g., invalid grid area names).
* **Common Errors:**  Typical mistakes developers make when using these CSS properties (e.g., incorrect syntax for grid areas, missing units for lengths).

**5. Debugging Clues - The "Where Did This Go Wrong":**

Thinking about how developers might end up in this code during debugging helps in understanding the context:

* **CSS Styling Issues:**  If a grid layout isn't working as expected, a developer might step into the parsing logic for `grid-template-areas`, `grid-template-columns`, etc.
* **Computed Style Inspection:**  If the final style of an element is unexpected, debugging might involve tracing how the computed style values are determined (`CSSValueFromComputedStyleInternal`).
* **Visited Link Styling:** Issues with visited link colors would likely lead to debugging the `InternalVisited*` properties.

**6. Summarization - The "In a Nutshell":**

The final step is to concisely summarize the findings, focusing on the key responsibilities of the file.

**Self-Correction/Refinement during the process:**

* **Initial Over-generalization:**  Initially, one might just say "this file handles CSS properties." The request asks for *specific* functionalities. Therefore, the analysis needs to go deeper into the role of `ParseSingleValue`, `CSSValueFromComputedStyleInternal`, etc.
* **Specificity of Examples:**  Vague examples aren't helpful. Concrete CSS and JavaScript snippets are necessary.
* **Connecting to User Actions:**  Thinking about the user's perspective (the developer writing CSS/JS) makes the explanation of common errors and debugging more relevant.
* **Understanding the "Visited" Context:** Recognizing the significance of the `InternalVisited*` properties and their privacy implications is crucial.

By following this systematic approach of identification, connection, exemplification, and summarization, we can generate a comprehensive and accurate response to the given request. The iterative process of reading, interpreting, and refining the understanding is key to success.
这是 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件的第 6 部分，共 13 部分。根据提供的代码片段，我们可以归纳出这个文件的功能是：

**核心功能：定义和实现各种 CSS 属性的“长手”属性的解析、计算和初始值逻辑。**

这个文件中的代码主要负责以下方面：

1. **解析 CSS 值 (`ParseSingleValue`)**: 将 CSS 样式表中的文本值解析成 Blink 引擎内部可以理解的数据结构。例如，将字符串 "100px" 解析成表示 100 像素的数值。
2. **获取计算后的 CSS 值 (`CSSValueFromComputedStyleInternal`)**:  根据元素的计算样式（ComputedStyle）生成对应的 CSSValue 对象。计算样式是经过层叠、继承等规则计算后最终应用于元素的样式。
3. **定义初始值 (`InitialValue`)**:  为每个 CSS 属性定义其默认的初始值。
4. **判断属性是否影响布局 (`IsLayoutDependent`)**:  确定修改该属性是否需要重新计算元素的布局。
5. **应用 CSS 值 (`ApplyValue`, `ApplyInherit`, `ApplyInitial`)**:  在样式解析和应用过程中，将解析得到的 CSS 值应用到元素的样式构建器（StyleBuilder）中。
6. **处理特定类型的 CSS 值**:  例如，处理颜色值 (`ColorIncludingFallback`)，Grid 布局相关的值，以及时间值等。

**与 Javascript, HTML, CSS 的关系：**

这个文件直接与 CSS 功能紧密相关，因为它定义了如何处理各种 CSS 属性。它间接与 JavaScript 和 HTML 相关，因为：

* **HTML**:  CSS 属性最终应用于 HTML 元素。`LayoutObject* layout_object` 参数在许多函数中出现，表示这些操作与具体的 HTML 元素实例相关。
* **CSS**: 这是直接相关的。这个文件实现了 CSS 属性的解析和计算逻辑，是浏览器引擎处理 CSS 的核心部分。
* **JavaScript**: JavaScript 可以通过 DOM API 修改元素的样式，这些修改会触发 Blink 引擎的 CSS 处理流程，最终会调用到这里定义的解析和计算逻辑。例如，通过 `element.style.height = '100px'` 或 `element.style.gridTemplateAreas = '"a a" "b c"'` 来设置样式。

**举例说明：**

以下列举一些代码片段与 CSS 功能的关系：

* **`GridTemplateAreas`**:  处理 CSS 属性 `grid-template-areas`，用于定义 Grid 布局中网格项所在的区域。
    * **CSS 示例**:
      ```css
      .container {
        display: grid;
        grid-template-areas: "header header"
                             "sidebar content"
                             "footer footer";
      }
      ```
    * **`ParseSingleValue`**:  负责解析像 `"header header" "sidebar content" "footer footer"` 这样的字符串，并构建 `CSSGridTemplateAreasValue` 对象。
    * **`CSSValueFromComputedStyleInternal`**:  从 `ComputedStyle` 中获取已经计算好的 `grid-template-areas` 值。
    * **假设输入与输出**:
        * **假设输入 (CSS 字符串)**: `"a b c" "d e f"`
        * **假设输出 (`CSSGridTemplateAreasValue` 对象)**: 一个表示两行三列的网格，第一行区域名称为 "a", "b", "c"，第二行区域名称为 "d", "e", "f"。

* **`Height`**: 处理 CSS 属性 `height`，用于设置元素的高度。
    * **CSS 示例**:
      ```css
      .box {
        height: 200px;
      }
      ```
    * **`ParseSingleValue`**:  负责解析像 `"200px"` 或 `"auto"` 这样的字符串，并构建相应的 CSSValue 对象。
    * **`CSSValueFromComputedStyleInternal`**:  根据元素的 `ComputedStyle` 和 `LayoutObject` 计算出最终的高度值。
    * **假设输入 (CSS 字符串)**: `"50vh"`
    * **假设输出 (`CSSPrimitiveValue` 对象)**:  一个表示视口高度 50% 的数值对象。

* **`PopoverShowDelay`**: 处理 CSS 属性 `popover-show-delay`，用于设置 popover 显示的延迟时间。
    * **CSS 示例**:
      ```css
      #myPopover {
        popover-show-delay: 0.5s;
      }
      ```
    * **`ParseSingleValue`**: 解析像 `"0.5s"` 这样的时间字符串。
    * **`CSSValueFromComputedStyleInternal`**: 从 `ComputedStyle` 中获取计算后的延迟时间。

* **`InternalVisitedBackgroundColor`**:  处理 visited 链接的背景颜色。这是一个特殊的内部属性，用于在用户访问过的链接上应用不同的样式，出于隐私考虑，其行为受到限制。
    * **CSS 示例**:
      ```css
      a:visited {
        background-color: purple; /* 浏览器可能不会完全按照这里的颜色显示 */
      }
      ```
    * **`ColorIncludingFallback`**:  这个方法负责在 visited 状态下确定背景颜色，并考虑到 forced colors 等因素。

**用户或编程常见的使用错误：**

* **`GridTemplateAreas`**:
    * **错误**:  提供的字符串不是一个矩形，例如 `"a b" "c"`。
    * **后果**:  解析会失败或者产生意想不到的布局。
    * **假设输入**: `"a b" "c"`
    * **可能输出**:  `nullptr` 或者抛出错误。
* **`Height`**:
    * **错误**:  忘记添加单位，例如 `height: 100;` 而不是 `height: 100px;`。
    * **后果**:  样式可能不会生效，或者被浏览器解释为默认单位（通常是像素）。
* **`PopoverShowDelay`**:
    * **错误**:  提供负数时间，例如 `popover-show-delay: -0.2s;`。
    * **后果**:  解析可能失败或者被浏览器忽略。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户编写 HTML 和 CSS 代码**:  开发者编写包含特定 CSS 属性的 HTML 和 CSS 文件。
2. **浏览器加载网页**:  当用户在浏览器中打开或刷新网页时，浏览器会开始解析 HTML 和 CSS。
3. **CSS 解析**:  浏览器解析 CSS 样式表，遇到像 `grid-template-areas`, `height` 等属性时，会调用到 `longhands_custom.cc` 中对应的 `ParseSingleValue` 函数。
4. **样式计算**:  解析后的 CSS 值会参与到样式计算过程中，生成元素的 `ComputedStyle`。 当需要获取某个属性的计算值时，会调用 `CSSValueFromComputedStyleInternal`。
5. **布局和渲染**:  计算后的样式会用于布局和渲染页面。如果属性是布局相关的，例如 `height` 或 Grid 布局属性，修改这些属性的值可能会触发重新布局。

**调试线索**:

* 如果开发者发现某个 CSS 属性没有按照预期工作，他们可能会使用浏览器的开发者工具查看元素的计算样式。
* 如果计算样式的值不正确，他们可能会怀疑是 CSS 解析或计算阶段出了问题。
* 这时，浏览器引擎的开发者可能会设置断点在 `longhands_custom.cc` 文件的相关函数中，例如 `GridTemplateAreas::ParseSingleValue` 或 `Height::CSSValueFromComputedStyleInternal`，来检查解析和计算过程中的数据。

**总结 `longhands_custom.cc` 的功能 (针对提供的代码片段):**

这个代码片段主要负责定义和实现以下 CSS 长手属性的解析、计算和初始值逻辑：

* `grid-template-areas`
* `grid-template-columns`
* `grid-template-rows`
* `height`
* `popover-show-delay`
* `popover-hide-delay`
* `hyphenate-limit-chars`
* `hyphens`
* `image-orientation`
* `image-rendering`
* `initial-letter`
* `inline-size`
* `position-area`
* `inset-block-end`
* `inset-block-start`
* `inset-inline-end`
* `inset-inline-start`
* 以及一系列以 `InternalVisited` 和 `InternalForced` 开头的内部属性，主要涉及 visited 链接的样式和 forced colors 功能。

总而言之，`longhands_custom.cc` 是 Blink 引擎中处理各种 CSS 属性的核心部分，它连接了 CSS 语法和浏览器内部的样式表示，并负责将 CSS 规则转化为实际的渲染效果。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共13部分，请归纳一下它的功能

"""
tr;
    }
    ++row_count;
  }

  if (row_count == 0) {
    return nullptr;
  }
  DCHECK(column_count);
  return MakeGarbageCollected<cssvalue::CSSGridTemplateAreasValue>(
      grid_area_map, row_count, column_count);
}

const CSSValue* GridTemplateAreas::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const auto& grid_template_areas = style.GridTemplateAreas()) {
    return MakeGarbageCollected<cssvalue::CSSGridTemplateAreasValue>(
        grid_template_areas->named_areas, grid_template_areas->row_count,
        grid_template_areas->column_count);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* GridTemplateAreas::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* GridTemplateColumns::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream, context);
}

bool GridTemplateColumns::IsLayoutDependent(const ComputedStyle* style,
                                            LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutGrid();
}

const CSSValue* GridTemplateColumns::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridTrackList(kForColumns, layout_object,
                                                   style);
}

const CSSValue* GridTemplateColumns::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* GridTemplateRows::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream, context);
}

bool GridTemplateRows::IsLayoutDependent(const ComputedStyle* style,
                                         LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutGrid();
}

const CSSValue* GridTemplateRows::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridTrackList(kForRows, layout_object,
                                                   style);
}

const CSSValue* GridTemplateRows::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* Height::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

bool Height::IsLayoutDependent(const ComputedStyle* style,
                               LayoutObject* layout_object) const {
  return layout_object && (layout_object->IsBox() || layout_object->IsSVG());
}

const CSSValue* Height::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (value_phase == CSSValuePhase::kResolvedValue &&
      ComputedStyleUtils::WidthOrHeightShouldReturnUsedValue(layout_object)) {
    return ZoomAdjustedPixelValue(
        ComputedStyleUtils::UsedBoxSize(*layout_object).height(), style);
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Height(),
                                                             style);
}

const CSSValue* PopoverShowDelay::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeTime(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* PopoverShowDelay::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.PopoverShowDelay(),
                                        CSSPrimitiveValue::UnitType::kSeconds);
}

const CSSValue* PopoverHideDelay::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeTime(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

const CSSValue* PopoverHideDelay::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.PopoverHideDelay(),
                                        CSSPrimitiveValue::UnitType::kSeconds);
}

const CSSValue* HyphenateLimitChars::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleHyphenateLimitChars& value = style.HyphenateLimitChars();
  if (value.IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  AppendIntegerOrAutoIfZero(value.MinWordChars(), list);
  if (value.MinBeforeChars() || value.MinAfterChars()) {
    AppendIntegerOrAutoIfZero(value.MinBeforeChars(), list);
    if (value.MinAfterChars()) {
      list->Append(*CSSNumericLiteralValue::Create(
          value.MinAfterChars(), CSSPrimitiveValue::UnitType::kInteger));
    }
  }
  return list;
}

const CSSValue* HyphenateLimitChars::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeHyphenateLimitChars(stream, context);
}

const CSSValue* Hyphens::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetHyphens());
}

const CSSValue* ImageOrientation::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeIdent<CSSValueID::kFromImage,
                                         CSSValueID::kNone>(stream);
}

const CSSValue* ImageOrientation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSValueID value = style.ImageOrientation() == kRespectImageOrientation
                               ? CSSValueID::kFromImage
                               : CSSValueID::kNone;
  return CSSIdentifierValue::Create(value);
}

const CSSValue* ImageRendering::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ImageRendering());
}

const CSSValue* InitialLetter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleInitialLetter initial_letter = style.InitialLetter();
  if (initial_letter.IsNormal()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSNumericLiteralValue::Create(
      initial_letter.Size(), CSSPrimitiveValue::UnitType::kNumber));
  if (initial_letter.IsIntegerSink()) {
    list->Append(*CSSNumericLiteralValue::Create(
        initial_letter.Sink(), CSSPrimitiveValue::UnitType::kInteger));
  } else if (initial_letter.IsDrop()) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kDrop));
  } else if (initial_letter.IsRaise()) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kRaise));
  }
  return list;
}

const CSSValue* InitialLetter::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeInitialLetter(stream, context);
}

const CSSValue* InlineSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeWidthOrHeight(stream, context);
}

bool InlineSize::IsLayoutDependent(const ComputedStyle* style,
                                   LayoutObject* layout_object) const {
  return layout_object && (layout_object->IsBox() || layout_object->IsSVG());
}

const CSSValue* PositionArea::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumePositionArea(stream);
}

const CSSValue* PositionArea::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPositionArea(style.GetPositionArea());
}

namespace {

void ComputeAnchorEdgeOffsetsForPositionArea(
    StyleResolverState& state,
    blink::PositionArea position_area) {
  if (AnchorEvaluator* evaluator =
          state.CssToLengthConversionData().GetAnchorEvaluator()) {
    state.SetPositionAreaOffsets(evaluator->ComputePositionAreaOffsetsForLayout(
        state.StyleBuilder().PositionAnchor(), position_area));
  }
  state.StyleBuilder().SetHasAnchorFunctions();
}

}  // namespace

void PositionArea::ApplyValue(StyleResolverState& state,
                              const CSSValue& value,
                              ValueMode) const {
  blink::PositionArea position_area =
      StyleBuilderConverter::ConvertPositionArea(state, value);
  state.StyleBuilder().SetPositionArea(position_area);
  if (!position_area.IsNone()) {
    ComputeAnchorEdgeOffsetsForPositionArea(state, position_area);
  }
}

void PositionArea::ApplyInherit(StyleResolverState& state) const {
  blink::PositionArea position_area = state.ParentStyle()->GetPositionArea();
  state.StyleBuilder().SetPositionArea(position_area);
  if (!position_area.IsNone()) {
    ComputeAnchorEdgeOffsetsForPositionArea(state, position_area);
  }
}

const CSSValue* InsetBlockEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

bool InsetBlockEnd::IsLayoutDependent(const ComputedStyle* style,
                                      LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* InsetBlockStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

bool InsetBlockStart::IsLayoutDependent(const ComputedStyle* style,
                                        LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* InsetInlineEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

bool InsetInlineEnd::IsLayoutDependent(const ComputedStyle* style,
                                       LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* InsetInlineStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

bool InsetInlineStart::IsLayoutDependent(const ComputedStyle* style,
                                         LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const blink::Color InternalVisitedBackgroundColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);

  const StyleColor& visited_background_color =
      style.InternalVisitedBackgroundColor();
  if (style.ShouldForceColor(visited_background_color)) {
    return GetCSSPropertyInternalForcedBackgroundColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  blink::Color color = visited_background_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);

  // TODO: Technically someone could explicitly specify the color
  // transparent, but for now we'll just assume that if the background color
  // is transparent that it wasn't set. Note that it's weird that we're
  // returning unvisited info for a visited link, but given our restriction
  // that the alpha values have to match, it makes more sense to return the
  // unvisited background color if specified than it does to return black.
  // This behavior matches what Firefox 4 does as well.
  if (color == blink::Color::kTransparent) {
    // Overwrite is_current_color based on the unvisited background color.
    return style.BackgroundColor().Resolve(
        style.GetCurrentColor(), style.UsedColorScheme(), is_current_color);
  }

  return color;
}

const CSSValue* InternalVisitedBackgroundColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const blink::Color InternalVisitedBorderLeftColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_border_left_color =
      style.InternalVisitedBorderLeftColor();
  if (style.ShouldForceColor(visited_border_left_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  return visited_border_left_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedBorderLeftColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color InternalVisitedBorderTopColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_border_top_color =
      style.InternalVisitedBorderTopColor();
  if (style.ShouldForceColor(visited_border_top_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  return visited_border_top_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedBorderTopColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color InternalVisitedCaretColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleAutoColor& auto_color = style.InternalVisitedCaretColor();
  const StyleColor result = auto_color.IsAutoColor()
                                ? StyleColor::CurrentColor()
                                : auto_color.ToStyleColor();
  if (style.ShouldForceColor(result)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return result.Resolve(style.GetInternalVisitedCurrentColor(),
                        style.UsedColorScheme(), is_current_color);
}

const CSSValue* InternalVisitedCaretColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return GetCSSPropertyCaretColor().ParseSingleValue(stream, context,
                                                     local_context);
}

const blink::Color InternalVisitedBorderRightColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_border_right_color =
      style.InternalVisitedBorderRightColor();
  if (style.ShouldForceColor(visited_border_right_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  return visited_border_right_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedBorderRightColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const blink::Color InternalVisitedBorderBottomColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_border_bottom_color =
      style.InternalVisitedBorderBottomColor();
  if (style.ShouldForceColor(visited_border_bottom_color)) {
    return GetCSSPropertyInternalForcedBorderColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  return visited_border_bottom_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedBorderBottomColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const CSSValue* InternalVisitedBorderInlineStartColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const CSSValue* InternalVisitedBorderInlineEndColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const CSSValue* InternalVisitedBorderBlockStartColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const CSSValue* InternalVisitedBorderBlockEndColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeBorderColorSide(stream, context,
                                                   local_context);
}

const CSSValue* InternalVisitedFill::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeSVGPaint(stream, context);
}

const blink::Color InternalVisitedFill::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const SVGPaint& paint = style.InternalVisitedFillPaint();

  // FIXME: This code doesn't support the uri component of the visited link
  // paint, https://bugs.webkit.org/show_bug.cgi?id=70006
  if (!paint.HasColor()) {
    return GetCSSPropertyFill().ColorIncludingFallback(false, style,
                                                       is_current_color);
  }
  const StyleColor& visited_fill_color = paint.GetColor();
  if (style.ShouldForceColor(visited_fill_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_fill_color.Resolve(style.GetInternalVisitedCurrentColor(),
                                    style.UsedColorScheme(), is_current_color);
}

const blink::Color InternalVisitedColumnRuleColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_column_rule_color =
      style.InternalVisitedColumnRuleColor().GetLegacyValue();
  if (style.ShouldForceColor(visited_column_rule_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_column_rule_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedColumnRuleColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color InternalVisitedOutlineColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_outline_color = style.InternalVisitedOutlineColor();
  if (style.ShouldForceColor(visited_outline_color)) {
    return GetCSSPropertyInternalForcedOutlineColor().ColorIncludingFallback(
        true, style, is_current_color);
  }
  return visited_outline_color.Resolve(style.GetInternalVisitedCurrentColor(),
                                       style.UsedColorScheme(),
                                       is_current_color);
}

const CSSValue* InternalVisitedOutlineColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return GetCSSPropertyOutlineColor().ParseSingleValue(stream, context,
                                                       local_context);
}

const CSSValue* InternalVisitedStroke::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeSVGPaint(stream, context);
}

const blink::Color InternalVisitedStroke::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const SVGPaint& paint = style.InternalVisitedStrokePaint();

  // FIXME: This code doesn't support the uri component of the visited link
  // paint, https://bugs.webkit.org/show_bug.cgi?id=70006
  if (!paint.HasColor()) {
    return GetCSSPropertyStroke().ColorIncludingFallback(false, style,
                                                         is_current_color);
  }
  const StyleColor& visited_stroke_color = paint.GetColor();
  if (style.ShouldForceColor(visited_stroke_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_stroke_color.Resolve(style.GetInternalVisitedCurrentColor(),
                                      style.UsedColorScheme(),
                                      is_current_color);
}

const blink::Color InternalVisitedTextDecorationColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_decoration_color =
      style.DecorationColorIncludingFallback(visited_link);
  if (style.ShouldForceColor(visited_decoration_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_decoration_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedTextDecorationColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color InternalVisitedTextEmphasisColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_text_emphasis_color =
      style.InternalVisitedTextEmphasisColor();
  if (style.ShouldForceColor(visited_text_emphasis_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_text_emphasis_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedTextEmphasisColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color InternalVisitedTextFillColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_text_fill_color =
      style.InternalVisitedTextFillColor();
  if (style.ShouldForceColor(visited_text_fill_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_text_fill_color.Resolve(style.GetInternalVisitedCurrentColor(),
                                         style.UsedColorScheme(),
                                         is_current_color);
}

const CSSValue* InternalVisitedTextFillColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color InternalVisitedTextStrokeColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  const StyleColor& visited_text_stroke_color =
      style.InternalVisitedTextStrokeColor();
  if (style.ShouldForceColor(visited_text_stroke_color)) {
    return style.GetInternalForcedVisitedCurrentColor(is_current_color);
  }
  return visited_text_stroke_color.Resolve(
      style.GetInternalVisitedCurrentColor(), style.UsedColorScheme(),
      is_current_color);
}

const CSSValue* InternalVisitedTextStrokeColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color InternalForcedBackgroundColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  blink::Color forced_current_color;
  int alpha;
  bool alpha_is_current_color;
  if (visited_link) {
    forced_current_color = style.GetInternalForcedVisitedCurrentColor(
        /* No is_current_color because we might not be forced_current_color */);
    alpha = style.InternalVisitedBackgroundColor()
                .Resolve(style.GetInternalVisitedCurrentColor(),
                         style.UsedColorScheme(), &alpha_is_current_color)
                .AlphaAsInteger();
  } else {
    forced_current_color = style.GetInternalForcedCurrentColor(
        /* No is_current_color because we might not be forced_current_color */);
    alpha = style.BackgroundColor()
                .Resolve(style.GetCurrentColor(), style.UsedColorScheme(),
                         &alpha_is_current_color)
                .AlphaAsInteger();
  }

  bool result_is_current_color;
  blink::Color result = style.InternalForcedBackgroundColor().ResolveWithAlpha(
      forced_current_color, style.UsedColorScheme(), alpha,
      &result_is_current_color);

  if (is_current_color) {
    *is_current_color = alpha_is_current_color || result_is_current_color;
  }
  return result;
}

const CSSValue*
InternalForcedBackgroundColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  bool visited_link = allow_visited_style &&
                      style.InsideLink() == EInsideLink::kInsideVisitedLink;
  return cssvalue::CSSColor::Create(
      ColorIncludingFallback(visited_link, style));
}

const CSSValue* InternalForcedBackgroundColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const blink::Color InternalForcedBorderColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  // Don’t pass is_current_color here because we might not be current_color
  blink::Color current_color =
      visited_link ? style.GetInternalForcedVisitedCurrentColor()
                   : style.GetInternalForcedCurrentColor();

  return style.InternalForcedBorderColor().Resolve(
      current_color, style.UsedColorScheme(), is_current_color);
}

const CSSValue* InternalForcedBorderColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  bool visited_link = allow_visited_style &&
                      style.InsideLink() == EInsideLink::kInsideVisitedLink;
  return cssvalue::CSSColor::Create(
      ColorIncludingFallback(visited_link, style));
}

const CSSValue* InternalForcedBorderColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

void InternalForcedColor::ApplyInitial(StyleResolverState& state) const {
  state.StyleBuilder().SetInternalForcedColor(
      ComputedStyleInitialValues::InitialInternalForcedColor());
}

void InternalForcedColor::ApplyInherit(StyleResolverState& state) const {
  state.StyleBuilder().SetInternalForcedColor(
      state.ParentStyle()->InternalForcedColor());
}

void InternalForcedColor::ApplyValue(StyleResolverState& state,
                                     const CSSValue& value,
                                     ValueMode) const {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_valu
"""


```
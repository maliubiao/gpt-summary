Response:
My goal is to analyze the provided C++ code snippet and summarize its functionality, relating it to web technologies like JavaScript, HTML, and CSS where applicable. Here's a breakdown of the thought process:

1. **Identify the Core Class:** The code snippet is part of the `StyleCascade` class within the Blink rendering engine. This immediately suggests a connection to CSS styling and how it's applied to HTML elements.

2. **Analyze Includes:** The included headers provide clues about the class's responsibilities. Keywords like "css," "resolver," "animation," "parser," "style," and "computed_style" are highly indicative of CSS processing. Specifically, "resolver" points to the process of determining the final style values for an element.

3. **Deconstruct the `Apply` Method:** This method seems central to the `StyleCascade`'s purpose. The comments and the calls to other `Apply*` methods strongly suggest a step-by-step process for applying styles. The `CascadeResolver` parameter further reinforces the idea of resolving style conflicts.

4. **Focus on `MatchResult` and `Interpolations`:** The code interacts with `MatchResult` and `Interpolations`. `MatchResult` likely holds the results of CSS selector matching. `Interpolations` clearly deals with CSS animations and transitions.

5. **Connect to CSS Concepts:**  As I go through the code, I actively look for connections to fundamental CSS concepts:
    * **Specificity/Cascade:** The `CascadePriority` class and the different `Apply*` methods strongly suggest the implementation of the CSS cascade.
    * **Inheritance:** The mention of parent styles and the handling of inherited properties confirms this.
    * **Important Rules:** The `IsImportant()` method in `CascadePriority` confirms support for `!important`.
    * **Animations and Transitions:** The `Interpolations` and related code clearly link to CSS animations and transitions.
    * **Custom Properties (CSS Variables):**  The mentions of `CSSVariableData`, `CSSCyclicVariableValue`, and handling of variable resolution are key.
    * **`revert` keyword:**  The `TargetOriginForRevert` function directly addresses the CSS `revert` keyword.

6. **Relate to HTML and JavaScript:**
    * **HTML:** The code operates on the results of CSS matching against HTML elements. The inclusion of `<html_element.h>` confirms this direct interaction.
    * **JavaScript:** While this specific code is C++, it's part of the rendering engine that JavaScript interacts with when manipulating the DOM and styles. Changes made via JavaScript's `style` property or by manipulating CSS classes ultimately flow through this system.

7. **Identify Potential User Errors:**  Consider common mistakes developers make with CSS:
    * **Specificity Issues:**  Misunderstanding the cascade and specificity leading to unexpected styles.
    * **Animation/Transition Conflicts:**  Conflicting animations or transitions.
    * **Incorrect Use of `!important`:** Overusing or misusing `!important`.
    * **CSS Variable Errors:**  Cyclic dependencies or invalid variable values.

8. **Infer Debugging Steps:**  Think about how a developer might end up examining this code during debugging:
    * **Unexpected Styling:** When an element doesn't look as expected.
    * **Animation Problems:** When animations or transitions don't behave correctly.
    * **Performance Issues:** While not immediately obvious, inefficient style resolution could be a performance bottleneck.

9. **Structure the Summary:** Organize the findings into clear categories:
    * Core Functionality
    * Relationship to JavaScript, HTML, CSS (with examples)
    * Logical Inference (with hypothetical inputs/outputs)
    * Common User Errors
    * Debugging Context

10. **Refine and Iterate:** Read through the generated summary to ensure clarity, accuracy, and completeness. For example, initially, I might have focused too much on low-level details. I'd then refine it to focus on the high-level functions and their relation to web standards. I also need to ensure I directly address the prompt's request to "歸納一下它的功能" (summarize its functionality).

By following this thought process, I can effectively analyze the C++ code snippet and generate a comprehensive and informative summary as requested. The key is to bridge the gap between the low-level implementation details and the high-level concepts of web development.
好的，让我们来分析一下 `blink/renderer/core/css/resolver/style_cascade.cc` 文件的功能。

**核心功能归纳:**

`style_cascade.cc` 文件的核心功能是 **实现 CSS 级联 (Cascade) 算法**，这是浏览器渲染引擎 Blink 中至关重要的一个步骤。 它的主要职责是：

1. **收集和排序适用于特定 HTML 元素的 CSS 声明:**  它从各种来源（例如，样式表、内联样式、用户代理样式）收集匹配当前元素的 CSS 规则和声明。

2. **处理 CSS 优先级和层叠规则:**  根据 CSS 规范定义的优先级规则（例如，!important 规则，来源顺序，选择器特异性等），以及层叠规则（例如，后声明覆盖先声明），来决定最终哪些 CSS 声明会生效。

3. **处理 CSS 继承:** 对于可继承的 CSS 属性，如果当前元素没有显式声明，则会从父元素继承相应的值。

4. **处理 CSS 动画和过渡:**  集成 CSS 动画和过渡的效果，确保它们在级联过程中得到正确的应用。

5. **解析和处理 CSS 值:**  将 CSS 声明中的值解析成内部表示，并进行必要的转换和计算。

6. **为元素的最终样式计算提供基础:**  `StyleCascade` 的结果将作为 `ComputedStyle` 的输入，`ComputedStyle` 存储了元素最终的、可用于渲染的样式属性值。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS (直接关系):**  `StyleCascade` 直接实现了 CSS 的核心机制。
    * **举例:** 当你在 CSS 文件中定义了 `.my-class { color: red; }`，并在 HTML 中应用了这个类 `<div class="my-class">`，`StyleCascade` 的工作就是找到这个规则，并确定 `color: red;` 应该应用到这个 `div` 元素上。如果还有其他 CSS 规则也影响了这个 `color` 属性，`StyleCascade` 会根据优先级规则来决定哪个规则生效。

* **HTML (间接关系):**  `StyleCascade` 处理的是应用于 HTML 元素的 CSS 规则。
    * **举例:** HTML 结构定义了元素的父子关系，这影响了 CSS 继承。例如，如果父元素设置了 `font-family: Arial;`，并且子元素没有设置自己的 `font-family`，`StyleCascade` 会使得子元素继承父元素的字体。

* **JavaScript (间接关系):**  JavaScript 可以动态地修改 HTML 元素的样式，这些修改最终也会通过 `StyleCascade` 来处理。
    * **举例:** 当 JavaScript 代码执行 `element.style.backgroundColor = 'blue';` 时，这个内联样式会被添加到元素的样式信息中。`StyleCascade` 在进行级联计算时，会考虑到这个内联样式，并且由于内联样式的优先级通常较高，它可能会覆盖其他来源的 `background-color` 声明。

**逻辑推理 (假设输入与输出):**

假设我们有以下 HTML 和 CSS:

**HTML:**

```html
<div id="container" style="font-size: 16px;">
  <p class="text">Hello</p>
</div>
```

**CSS:**

```css
#container {
  color: black;
}

.text {
  color: red !important;
  font-weight: bold;
}
```

**假设输入 (到 `StyleCascade`):**  对于 `<p class="text">` 元素，`StyleCascade` 会接收到来自以下来源的 CSS 声明：

1. **用户代理样式表 (User-Agent Stylesheet):**  浏览器默认的样式。
2. **外部样式表 (假设存在):**  链接到 HTML 的 CSS 文件中的规则。
3. **内联样式 (Inline Style):**  父元素 `<div id="container">` 的 `font-size: 16px;`。
4. **作者样式表 (Author Stylesheet):**  CSS 代码块中的 `#container { color: black; }` 和 `.text { color: red !important; font-weight: bold; }`。

**逻辑推理过程 (简化):**

* **颜色 (color):**
    * `#container` 设置 `color: black;` (较低优先级)。
    * `.text` 设置 `color: red !important;` (最高优先级，因为有 `!important`)。
    * **输出:** `<p>` 元素的最终颜色将是 `red`。

* **字体大小 (font-size):**
    * 父元素内联样式设置 `font-size: 16px;` (较高优先级)。
    * `.text` 没有显式设置 `font-size`，会继承父元素的。
    * **输出:** `<p>` 元素的字体大小将是 `16px`。

* **字体粗细 (font-weight):**
    * `.text` 设置 `font-weight: bold;`。
    * **输出:** `<p>` 元素的字体粗细将是 `bold`。

**假设输出 (来自 `StyleCascade`):**  `StyleCascade` 会输出一个包含以下信息的结构，表明最终应用于 `<p class="text">` 元素的样式：

* `color`: `red` (来自 `.text`，因为 `!important`)
* `font-size`: `16px` (继承自父元素)
* `font-weight`: `bold` (来自 `.text`)
* 其他未被覆盖的属性会从用户代理样式表或其他来源继承/获取。

**用户或编程常见的使用错误举例说明:**

1. **特异性冲突导致样式未生效:**  用户可能期望某个 CSS 规则生效，但由于另一个具有更高特异性的规则存在，导致期望的样式没有应用上。
    * **例子:**
    ```css
    .container div { color: blue; } /* 较低特异性 */
    #main-content { color: green; } /* 较高特异性 */
    ```
    如果 HTML 中有 `<div id="main-content"><div>...</div></div>`，开发者可能期望 `div` 元素是蓝色，但实际上是绿色。

2. **滥用 `!important` 导致样式难以维护:**  过度使用 `!important` 会打破正常的层叠规则，使得样式难以覆盖和调试。
    * **例子:**  如果在多个地方都使用了 `!important`，当需要修改样式时，可能需要使用更强的 `!important` 或者修改原始的 `!important` 声明，这会使 CSS 代码变得混乱。

3. **忘记考虑继承:**  用户可能忘记某些 CSS 属性是可继承的，当父元素的样式发生变化时，子元素的样式也会随之改变，这可能不是期望的行为。
    * **例子:**  如果父元素设置了 `font-family`，子元素如果没有显式设置，则会继承父元素的字体。如果开发者期望子元素使用不同的字体，就需要显式地在子元素上设置 `font-family`。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在调试一个网页的样式问题，发现某个元素的样式没有按照预期显示。以下是可能的步骤，最终可能会涉及到查看 `style_cascade.cc` 的代码：

1. **检查元素的 CSS 规则:**  开发者会使用浏览器的开发者工具（例如 Chrome DevTools）查看该元素应用的 CSS 规则。
2. **查看 Computed 标签:**  开发者会查看 "Computed" 标签，了解最终生效的样式属性值以及它们的来源。
3. **识别优先级冲突:**  如果发现某个样式被其他样式覆盖，开发者可能会注意到优先级更高的规则。
4. **检查样式来源:**  开发者会检查样式的来源 (样式表文件，内联样式等)。
5. **定位到具体的 CSS 规则:**  开发者可能会找到导致问题的具体 CSS 规则。
6. **如果问题复杂，例如涉及动画或复杂的选择器:**  开发者可能需要更深入地理解 Blink 渲染引擎是如何处理 CSS 级联的。这时，如果开发者正在参与 Blink 的开发或者有访问 Blink 源代码的权限，他们可能会查看 `style_cascade.cc` 这样的文件，以了解 CSS 级联算法的具体实现细节，例如：
    *  `ApplyCascadeAffecting`: 查看影响级联的属性（如 `direction`, `writing-mode`）的处理。
    *  `ApplyHighPriority`: 查看 `!important` 规则的处理。
    *  `ApplyMatchResult`:  查看普通 CSS 声明的应用顺序。
    *  `ApplyInterpolations`: 查看动画和过渡效果的应用。

**总结 (根据你的要求):**

这是 `blink/renderer/core/css/resolver/style_cascade.cc` 文件的第一部分，它的主要功能是 **开始实现 CSS 级联算法的核心逻辑**。 这部分代码定义了 `StyleCascade` 类，并包含了初始化、添加匹配的 CSS 规则和声明、以及初步处理级联影响属性（如 `direction` 和 `writing-mode`）的逻辑。  它为后续更高优先级的样式应用和最终的样式计算奠定了基础。 这部分代码的关键在于 `ApplyCascadeAffecting` 方法，它处理了可能需要重新分析级联的属性。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_cascade.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/resolver/style_cascade.h"

#include <bit>
#include <optional>

#include "base/not_fatal_until.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/css_interpolation_environment.h"
#include "third_party/blink/renderer/core/animation/css_interpolation_types_map.h"
#include "third_party/blink/renderer/core/animation/invalidatable_interpolation.h"
#include "third_party/blink/renderer/core/animation/property_handle.h"
#include "third_party/blink/renderer/core/animation/transition_interpolation.h"
#include "third_party/blink/renderer/core/css/css_attr_type.h"
#include "third_party/blink/renderer/core/css/css_attr_value_tainting.h"
#include "third_party/blink/renderer/core/css/css_cyclic_variable_value.h"
#include "third_party/blink/renderer/core/css/css_flip_revert_value.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_invalid_variable_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_pending_substitution_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_syntax_string_parser.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/css_unset_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/document_style_environment_variables.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/property_bitsets.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_expansion-inl.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_expansion.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_interpolations.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/try_value_flips.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

AtomicString ConsumeVariableName(CSSParserTokenStream& stream) {
  stream.ConsumeWhitespace();
  CSSParserToken ident_token = stream.ConsumeIncludingWhitespaceRaw();
  DCHECK_EQ(ident_token.GetType(), kIdentToken);
  return ident_token.Value().ToAtomicString();
}

bool ConsumeComma(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() == kCommaToken) {
    stream.ConsumeRaw();
    return true;
  }
  return false;
}

const CSSValue* Parse(const CSSProperty& property,
                      CSSParserTokenStream& stream,
                      const CSSParserContext* context) {
  return CSSPropertyParser::ParseSingleValue(property.PropertyID(), stream,
                                             context);
}

const CSSValue* ValueAt(const MatchResult& result, uint32_t position) {
  wtf_size_t matched_properties_index = DecodeMatchedPropertiesIndex(position);
  wtf_size_t declaration_index = DecodeDeclarationIndex(position);
  const MatchedPropertiesVector& vector = result.GetMatchedProperties();
  const CSSPropertyValueSet* set = vector[matched_properties_index].properties;
  return &set->PropertyAt(declaration_index).Value();
}

const TreeScope& TreeScopeAt(const MatchResult& result, uint32_t position) {
  wtf_size_t matched_properties_index = DecodeMatchedPropertiesIndex(position);
  const MatchedProperties& properties =
      result.GetMatchedProperties()[matched_properties_index];
  DCHECK_EQ(properties.data_.origin, CascadeOrigin::kAuthor);
  return result.ScopeFromTreeOrder(properties.data_.tree_order);
}

const CSSValue* EnsureScopedValue(const Document& document,
                                  const MatchResult& match_result,
                                  CascadePriority priority,
                                  const CSSValue* value) {
  CascadeOrigin origin = priority.GetOrigin();
  const TreeScope* tree_scope{nullptr};
  if (origin == CascadeOrigin::kAuthor) {
    tree_scope = &TreeScopeAt(match_result, priority.GetPosition());
  } else if (origin == CascadeOrigin::kAuthorPresentationalHint) {
    tree_scope = &document;
  }
  return &value->EnsureScopedValue(tree_scope);
}

PropertyHandle ToPropertyHandle(const CSSProperty& property,
                                CascadePriority priority) {
  uint32_t position = priority.GetPosition();
  CSSPropertyID id = DecodeInterpolationPropertyID(position);
  if (id == CSSPropertyID::kVariable) {
    DCHECK(IsA<CustomProperty>(property));
    return PropertyHandle(property.GetPropertyNameAtomicString());
  }
  return PropertyHandle(CSSProperty::Get(id),
                        DecodeIsPresentationAttribute(position));
}

// https://drafts.csswg.org/css-cascade-4/#default
CascadeOrigin TargetOriginForRevert(CascadeOrigin origin) {
  switch (origin) {
    case CascadeOrigin::kNone:
    case CascadeOrigin::kTransition:
      NOTREACHED();
    case CascadeOrigin::kUserAgent:
      return CascadeOrigin::kNone;
    case CascadeOrigin::kUser:
      return CascadeOrigin::kUserAgent;
    case CascadeOrigin::kAuthorPresentationalHint:
    case CascadeOrigin::kAuthor:
    case CascadeOrigin::kAnimation:
      return CascadeOrigin::kUser;
  }
}

CSSPropertyID UnvisitedID(CSSPropertyID id) {
  if (id == CSSPropertyID::kVariable) {
    return id;
  }
  const CSSProperty& property = CSSProperty::Get(id);
  if (!property.IsVisited()) {
    return id;
  }
  return property.GetUnvisitedProperty()->PropertyID();
}

bool IsInterpolation(CascadePriority priority) {
  switch (priority.GetOrigin()) {
    case CascadeOrigin::kAnimation:
    case CascadeOrigin::kTransition:
      return true;
    case CascadeOrigin::kNone:
    case CascadeOrigin::kUserAgent:
    case CascadeOrigin::kUser:
    case CascadeOrigin::kAuthorPresentationalHint:
    case CascadeOrigin::kAuthor:
      return false;
  }
}

}  // namespace

MatchResult& StyleCascade::MutableMatchResult() {
  DCHECK(!generation_) << "Apply has already been called";
  needs_match_result_analyze_ = true;
  return match_result_;
}

void StyleCascade::AddInterpolations(const ActiveInterpolationsMap* map,
                                     CascadeOrigin origin) {
  DCHECK(map);
  needs_interpolations_analyze_ = true;
  interpolations_.Add(map, origin);
}

void StyleCascade::Apply(CascadeFilter filter) {
  AnalyzeIfNeeded();
  state_.UpdateLengthConversionData();

  CascadeResolver resolver(filter, ++generation_);

  ApplyCascadeAffecting(resolver);

  ApplyHighPriority(resolver);
  state_.UpdateFont();

  if (map_.NativeBitset().Has(CSSPropertyID::kLineHeight)) {
    LookupAndApply(GetCSSPropertyLineHeight(), resolver);
  }
  state_.UpdateLineHeight();

  ApplyWideOverlapping(resolver);

  ApplyMatchResult(resolver);
  ApplyInterpolations(resolver);

  // These three flags are only used if HasAppearance() is set
  // (they are used for knowing whether appearance: auto is to be overridden),
  // but we compute them nevertheless, to avoid suddenly having to compute them
  // after-the-fact if inline style is updated incrementally.
  if (resolver.AuthorFlags() & CSSProperty::kBackground) {
    state_.StyleBuilder().SetHasAuthorBackground();
  }
  if (resolver.AuthorFlags() & CSSProperty::kBorder) {
    state_.StyleBuilder().SetHasAuthorBorder();
  }
  if (resolver.AuthorFlags() & CSSProperty::kBorderRadius) {
    state_.StyleBuilder().SetHasAuthorBorderRadius();
  }

  if ((state_.InsideLink() != EInsideLink::kInsideVisitedLink &&
       (resolver.AuthorFlags() & CSSProperty::kHighlightColors)) ||
      (state_.InsideLink() == EInsideLink::kInsideVisitedLink &&
       (resolver.AuthorFlags() & CSSProperty::kVisitedHighlightColors))) {
    state_.StyleBuilder().SetHasAuthorHighlightColors();
  }

  if (resolver.Flags() & CSSProperty::kAnimation) {
    state_.StyleBuilder().SetCanAffectAnimations();
  }
  if (resolver.RejectedFlags() & CSSProperty::kLegacyOverlapping) {
    state_.SetRejectedLegacyOverlapping();
  }

  // TOOD(crbug.com/1334570):
  //
  // Count applied H1 font-size from html.css UA stylesheet where H1 is inside
  // a sectioning element matching selectors like:
  //
  // :-webkit-any(article,aside,nav,section) h1 { ... }
  //
  if (!state_.GetElement().HasTagName(html_names::kH1Tag)) {
    return;
  }
  if (CascadePriority* priority =
          map_.Find(GetCSSPropertyFontSize().GetCSSPropertyName())) {
    if (priority->GetOrigin() != CascadeOrigin::kUserAgent) {
      return;
    }
    const CSSValue* value = ValueAt(match_result_, priority->GetPosition());
    if (const auto* numeric = DynamicTo<CSSNumericLiteralValue>(value)) {
      DCHECK(numeric->GetType() == CSSNumericLiteralValue::UnitType::kEms);
      if (numeric->DoubleValue() != 2.0) {
        CountUse(WebFeature::kH1UserAgentFontSizeInSectionApplied);
      }
    }
  }
}

std::unique_ptr<CSSBitset> StyleCascade::GetImportantSet() {
  AnalyzeIfNeeded();
  if (!map_.HasImportant()) {
    return nullptr;
  }
  auto set = std::make_unique<CSSBitset>();
  for (CSSPropertyID id : map_.NativeBitset()) {
    // We use the unvisited ID because visited/unvisited colors are currently
    // interpolated together.
    // TODO(crbug.com/1062217): Interpolate visited colors separately
    set->Or(UnvisitedID(id), map_.At(CSSPropertyName(id)).IsImportant());
  }
  return set;
}

void StyleCascade::Reset() {
  map_.Reset();
  match_result_.Reset();
  interpolations_.Reset();
  generation_ = 0;
  depends_on_cascade_affecting_property_ = false;
}

const CSSValue* StyleCascade::Resolve(const CSSPropertyName& name,
                                      const CSSValue& value,
                                      CascadeOrigin origin,
                                      CascadeResolver& resolver) {
  CSSPropertyRef ref(name, state_.GetDocument());

  const CSSValue* resolved = Resolve(ResolveSurrogate(ref.GetProperty()), value,
                                     CascadePriority(origin), origin, resolver);

  DCHECK(resolved);

  // TODO(crbug.com/1185745): Cycles in animations get special handling by our
  // implementation. This is not per spec, but the correct behavior is not
  // defined at the moment.
  if (resolved->IsCyclicVariableValue()) {
    return nullptr;
  }

  // TODO(crbug.com/1185745): We should probably not return 'unset' for
  // properties where CustomProperty::SupportsGuaranteedInvalid return true.
  if (resolved->IsInvalidVariableValue()) {
    return cssvalue::CSSUnsetValue::Create();
  }

  return resolved;
}

HeapHashMap<CSSPropertyName, Member<const CSSValue>>
StyleCascade::GetCascadedValues() const {
  DCHECK(!needs_match_result_analyze_);
  DCHECK(!needs_interpolations_analyze_);
  DCHECK_GE(generation_, 0);

  HeapHashMap<CSSPropertyName, Member<const CSSValue>> result;

  for (CSSPropertyID id : map_.NativeBitset()) {
    CSSPropertyName name(id);
    CascadePriority priority = map_.At(name);
    if (IsInterpolation(priority)) {
      continue;
    }
    if (!priority.HasOrigin()) {
      // Declarations added for explicit defaults (AddExplicitDefaults)
      // should not be observable.
      continue;
    }
    const CSSValue* cascaded = ValueAt(match_result_, priority.GetPosition());
    DCHECK(cascaded);
    result.Set(name, cascaded);
  }

  for (const auto& name : map_.GetCustomMap().Keys()) {
    CascadePriority priority = map_.At(CSSPropertyName(name));
    DCHECK(priority.HasOrigin());
    if (IsInterpolation(priority)) {
      continue;
    }
    const CSSValue* cascaded = ValueAt(match_result_, priority.GetPosition());
    DCHECK(cascaded);
    result.Set(CSSPropertyName(name), cascaded);
  }

  return result;
}

const CSSValue* StyleCascade::Resolve(StyleResolverState& state,
                                      const CSSPropertyName& name,
                                      const CSSValue& value) {
  STACK_UNINITIALIZED StyleCascade cascade(state);

  // Since the cascade map is empty, the CascadeResolver isn't important,
  // as there can be no cycles in an empty map. We just instantiate it to
  // satisfy the API.
  CascadeResolver resolver(CascadeFilter(), /* generation */ 0);

  // The origin is relevant for 'revert', but since the cascade map
  // is empty, there will be nothing to revert to regardless of the origin
  // We use kNone, because kAuthor (etc) imply that the `value` originates
  // from a location on the `MatchResult`, which is not the case.
  CascadeOrigin origin = CascadeOrigin::kNone;

  return cascade.Resolve(name, value, origin, resolver);
}

void StyleCascade::AnalyzeIfNeeded() {
  if (needs_match_result_analyze_) {
    AnalyzeMatchResult();
    needs_match_result_analyze_ = false;
  }
  if (needs_interpolations_analyze_) {
    AnalyzeInterpolations();
    needs_interpolations_analyze_ = false;
  }
}

void StyleCascade::AnalyzeMatchResult() {
  AddExplicitDefaults();

  int index = 0;
  for (const MatchedProperties& properties :
       match_result_.GetMatchedProperties()) {
    ExpandCascade(
        properties, GetDocument(), index++,
        [this](CascadePriority cascade_priority,
               const AtomicString& custom_property_name) {
          map_.Add(custom_property_name, cascade_priority);
        },
        [this](CascadePriority cascade_priority, CSSPropertyID property_id) {
          if (kSurrogateProperties.Has(property_id)) {
            const CSSProperty& property =
                ResolveSurrogate(CSSProperty::Get(property_id));
            map_.Add(property.PropertyID(), cascade_priority);
          } else {
            map_.Add(property_id, cascade_priority);
          }
        });
  }
}

void StyleCascade::AnalyzeInterpolations() {
  const auto& entries = interpolations_.GetEntries();
  for (wtf_size_t i = 0; i < entries.size(); ++i) {
    for (const auto& active_interpolation : *entries[i].map) {
      auto name = active_interpolation.key.GetCSSPropertyName();
      uint32_t position = EncodeInterpolationPosition(
          name.Id(), i, active_interpolation.key.IsPresentationAttribute());
      CascadePriority priority(entries[i].origin,
                               /* important */ false,
                               /* tree_order */ 0,
                               /* is_inline_style */ false,
                               /* is_try_style */ false,
                               /* is_try_tactics_style */ false,
                               /* layer_order */ 0, position);

      CSSPropertyRef ref(name, GetDocument());
      DCHECK(ref.IsValid());

      if (name.IsCustomProperty()) {
        map_.Add(name.ToAtomicString(), priority);
      } else {
        const CSSProperty& property = ResolveSurrogate(ref.GetProperty());
        map_.Add(property.PropertyID(), priority);

        // Since an interpolation for an unvisited property also causes an
        // interpolation of the visited property, add the visited property to
        // the map as well.
        // TODO(crbug.com/1062217): Interpolate visited colors separately
        if (const CSSProperty* visited = property.GetVisitedProperty()) {
          map_.Add(visited->PropertyID(), priority);
        }
      }
    }
  }
}

// The implicit defaulting behavior of inherited properties is to take
// the value of the parent style [1]. However, we never reach
// Longhand::ApplyInherit for implicit defaults, which is needed to adjust
// Lengths with premultiplied zoom. Therefore, all inherited properties
// are instead explicitly defaulted [2] when the effective zoom has changed
// versus the parent zoom.
//
// [1] https://drafts.csswg.org/css-cascade/#defaulting
// [2] https://drafts.csswg.org/css-cascade/#defaulting-keywords
void StyleCascade::AddExplicitDefaults() {
  if (state_.GetDocument().StandardizedBrowserZoomEnabled() &&
      effective_zoom_changed_) {
    // These inherited properties can contain lengths:
    //
    //   -webkit-border-horizontal-spacing
    //   -webkit-border-vertical-spacing
    //   -webkit-text-stroke-width
    //   letter-spacing
    //   line-height
    //   list-style-image *
    //   stroke-dasharray
    //   stroke-dashoffset
    //   stroke-width **
    //   text-indent
    //   text-shadow
    //   text-underline-offset
    //   word-spacing
    //
    // * list-style-image need not be recomputed on zoom change because list
    // image marker is sized to 1em and font-size is already correctly zoomed.
    //
    // ** stroke-width gets special handling elsewhere.
    map_.Add(CSSPropertyID::kLetterSpacing,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kLineHeight, CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kStrokeDasharray,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kStrokeDashoffset,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kTextIndent, CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kTextShadow, CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kTextUnderlineOffset,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kWebkitTextStrokeWidth,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kWebkitBorderHorizontalSpacing,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kWebkitBorderVerticalSpacing,
             CascadePriority(CascadeOrigin::kNone));
    map_.Add(CSSPropertyID::kWordSpacing,
             CascadePriority(CascadeOrigin::kNone));
  }
}

void StyleCascade::Reanalyze() {
  map_.Reset();
  generation_ = 0;
  depends_on_cascade_affecting_property_ = false;

  needs_match_result_analyze_ = true;
  needs_interpolations_analyze_ = true;
  AnalyzeIfNeeded();
}

void StyleCascade::ApplyCascadeAffecting(CascadeResolver& resolver) {
  // During the initial call to Analyze, we speculatively assume that the
  // direction/writing-mode inherited from the parent will be the final
  // direction/writing-mode. If either property ends up with another value,
  // our assumption was incorrect, and we have to Reanalyze with the correct
  // values on ComputedStyle.
  auto direction = state_.StyleBuilder().Direction();
  auto writing_mode = state_.StyleBuilder().GetWritingMode();
  // Similarly, we assume that the effective zoom of this element
  // is the same as the parent's effective zoom. If it isn't,
  // we re-cascade with explicit defaults inserted at CascadeOrigin::kNone.
  //
  // See also StyleCascade::AddExplicitDefaults.
  float effective_zoom = state_.StyleBuilder().EffectiveZoom();

  if (map_.NativeBitset().Has(CSSPropertyID::kDirection)) {
    LookupAndApply(GetCSSPropertyDirection(), resolver);
  }
  if (map_.NativeBitset().Has(CSSPropertyID::kWritingMode)) {
    LookupAndApply(GetCSSPropertyWritingMode(), resolver);
  }
  if (map_.NativeBitset().Has(CSSPropertyID::kZoom)) {
    LookupAndApply(GetCSSPropertyZoom(), resolver);
  }

  bool reanalyze = false;

  if (depends_on_cascade_affecting_property_) {
    if (direction != state_.StyleBuilder().Direction() ||
        writing_mode != state_.StyleBuilder().GetWritingMode()) {
      reanalyze = true;
    }
  }
  if (effective_zoom != state_.StyleBuilder().EffectiveZoom()) {
    effective_zoom_changed_ = true;
    reanalyze = true;
  }

  if (reanalyze) {
    Reanalyze();
  }
}

void StyleCascade::ApplyHighPriority(CascadeResolver& resolver) {
  uint64_t bits = map_.HighPriorityBits();

  while (bits) {
    int i = std::countr_zero(bits);
    bits &= bits - 1;  // Clear the lowest bit.
    LookupAndApply(CSSProperty::Get(ConvertToCSSPropertyID(i)), resolver);
  }
}

void StyleCascade::ApplyWideOverlapping(CascadeResolver& resolver) {
  // Overlapping properties are handled as follows:
  //
  // 1. Apply the "wide" longhand which represents the entire computed value
  //    first. This is not always the non-legacy property,
  //    e.g.-webkit-border-image is one such longhand.
  // 2. For the other overlapping longhands (each of which represent a *part*
  //    of that computed value), *skip* applying that longhand if the wide
  //    longhand has a higher priority.
  //
  // This allows us to always apply the "wide" longhand in a fixed order versus
  // the other overlapping longhands, but still produce the same result as if
  // everything was applied in the order the properties were specified.

  // Skip `property` if its priority is lower than the incoming priority.
  // Skipping basically means pretending it's already applied by setting the
  // generation.
  auto maybe_skip = [this, &resolver](const CSSProperty& property,
                                      CascadePriority priority) {
    if (CascadePriority* p = map_.Find(property.GetCSSPropertyName())) {
      if (*p < priority) {
        *p = CascadePriority(*p, resolver.generation_);
      }
    }
  };

  const CSSProperty& webkit_border_image = GetCSSPropertyWebkitBorderImage();
  if (!resolver.filter_.Rejects(webkit_border_image)) {
    if (const CascadePriority* priority =
            map_.Find(webkit_border_image.GetCSSPropertyName())) {
      LookupAndApply(webkit_border_image, resolver);

      const auto& shorthand = borderImageShorthand();
      for (const CSSProperty* const longhand : shorthand.properties()) {
        maybe_skip(*longhand, *priority);
      }
    }
  }

  const CSSProperty& perspective_origin = GetCSSPropertyPerspectiveOrigin();
  if (!resolver.filter_.Rejects(perspective_origin)) {
    if (const CascadePriority* priority =
            map_.Find(perspective_origin.GetCSSPropertyName())) {
      LookupAndApply(perspective_origin, resolver);
      maybe_skip(GetCSSPropertyWebkitPerspectiveOriginX(), *priority);
      maybe_skip(GetCSSPropertyWebkitPerspectiveOriginY(), *priority);
    }
  }

  const CSSProperty& transform_origin = GetCSSPropertyTransformOrigin();
  if (!resolver.filter_.Rejects(transform_origin)) {
    if (const CascadePriority* priority =
            map_.Find(transform_origin.GetCSSPropertyName())) {
      LookupAndApply(transform_origin, resolver);
      maybe_skip(GetCSSPropertyWebkitTransformOriginX(), *priority);
      maybe_skip(GetCSSPropertyWebkitTransformOriginY(), *priority);
      maybe_skip(GetCSSPropertyWebkitTransformOriginZ(), *priority);
    }
  }

  // vertical-align will become a shorthand in the future - in order to
  // mitigate the forward compat risk, skip the baseline-source longhand.
  const CSSProperty& vertical_align = GetCSSPropertyVerticalAlign();
  if (!resolver.filter_.Rejects(vertical_align)) {
    if (const CascadePriority* priority =
            map_.Find(vertical_align.GetCSSPropertyName())) {
      LookupAndApply(vertical_align, resolver);
      maybe_skip(GetCSSPropertyBaselineSource(), *priority);
    }
  }

  // Note that -webkit-box-decoration-break isn't really more (or less)
  // "wide" than the non-prefixed counterpart, but they still share
  // a ComputedStyle location, and therefore need to be handled here.
  const CSSProperty& webkit_box_decoration_break =
      GetCSSPropertyWebkitBoxDecorationBreak();
  if (!resolver.filter_.Rejects(webkit_box_decoration_break)) {
    if (const CascadePriority* priority =
            map_.Find(webkit_box_decoration_break.GetCSSPropertyName())) {
      LookupAndApply(webkit_box_decoration_break, resolver);
      maybe_skip(GetCSSPropertyBoxDecorationBreak(), *priority);
    }
  }
}

// Go through all properties that were found during the analyze phase
// (e.g. in AnalyzeMatchResult()) and actually apply them. We need to do this
// in a second phase so that we know which ones actually won the cascade
// before we start applying, as some properties can affect others.
void StyleCascade::ApplyMatchResult(CascadeResolver& resolver) {
  // All the high-priority properties were dealt with in ApplyHighPriority(),
  // so we don't need to look at them again. (That would be a no-op due to
  // the generation check below, but it's cheaper just to mask them out
  // entirely.)
  for (auto it = map_.NativeBitset().BeginAfterHighPriority();
       it != map_.NativeBitset().end(); ++it) {
    CSSPropertyID id = *it;
    CascadePriority* p = map_.FindKnownToExist(id);
    const CascadePriority priority = *p;
    if (priority.GetGeneration() >= resolver.generation_) {
      // Already applied this generation.
      // Also checked in LookupAndApplyDeclaration,
      // but done here to get a fast exit.
      continue;
    }
    if (IsInterpolation(priority)) {
      continue;
    }

    const CSSProperty& property = CSSProperty::Get(id);
    if (resolver.Rejects(property)) {
      continue;
    }
    LookupAndApplyDeclaration(property, p, resolver);
  }

  for (auto& [name, priority_list] : map_.GetCustomMap()) {
    CascadePriority* p = &map_.Top(priority_list);
    CascadePriority priority = *p;
    if (priority.GetGeneration() >= resolver.generation_) {
      continue;
    }
    if (IsInterpolation(priority)) {
      continue;
    }

    CustomProperty property(name, GetDocument());
    if (resolver.Rejects(property)) {
      continue;
    }
    LookupAndApplyDeclaration(property, p, resolver);
  }
}

void StyleCascade::ApplyInterpolations(CascadeResolver& resolver) {
  const auto& entries = interpolations_.GetEntries();
  for (wtf_size_t i = 0; i < entries.size(); ++i) {
    const auto& entry = entries[i];
    ApplyInterpolationMap(*entry.map, entry.origin, i, resolver);
  }
}

void StyleCascade::ApplyInterpolationMap(const ActiveInterpolationsMap& map,
                                         CascadeOrigin origin,
                                         size_t index,
                                         CascadeResolver& resolver) {
  for (const auto& entry : map) {
    auto name = entry.key.GetCSSPropertyName();
    uint32_t position = EncodeInterpolationPosition(
        name.Id(), index, entry.key.IsPresentationAttribute());
    CascadePriority priority(origin,
                             /* important */ false,
                             /* tree_order */ 0,
                             /* is_inline_style */ false,
                             /* is_try_style */ false,
                             /* is_try_tactics_style */ false,
                             /* layer_order */ 0, position);
    priority = CascadePriority(priority, resolver.generation_);

    CSSPropertyRef ref(name, GetDocument());
    if (resolver.Rejects(ref.GetProperty())) {
      continue;
    }

    const CSSProperty& property = ResolveSurrogate(ref.GetProperty());

    CascadePriority* p = map_.Find(property.GetCSSPropertyName());
    if (!p || *p >= priority) {
      continue;
    }
    *p = priority;

    ApplyInterpolation(property, priority, *entry.value, resolver);
  }
}

void StyleCascade::ApplyInterpolation(
    const CSSProperty& property,
    CascadePriority priority,
    const ActiveInterpolations& interpolations,
    CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());

  CSSInterpolationTypesMap map(state_.GetDocument().GetPropertyRegistry(),
                               state_.GetDocument());
  CSSInterpolationEnvironment environment(map, state_, this, &resolver);

  const Interpolation& interpolation = *interpolations.front();
  if (IsA<InvalidatableInterpolation>(interpolation)) {
    InvalidatableInterpolation::ApplyStack(interpolations, environment);
  } else {
    To<TransitionInterpolation>(interpolation).Apply(environment);
  }

  // Applying a color property interpolation will also unconditionally apply
  // the -internal-visited- counterpart (see CSSColorInterpolationType::
  // ApplyStandardPropertyValue). To make sure !important rules in :visited
  // selectors win over animations, we re-apply the -internal-visited property
  // if its priority is higher.
  //
  // TODO(crbug.com/1062217): Interpolate visited colors separately
  if (const CSSProperty* visited = property.GetVisitedProperty()) {
    CascadePriority* visited_priority =
        map_.Find(visited->GetCSSPropertyName());
    if (visited_priority && priority < *visited_priority) {
      DCHECK(visited_priority->IsImportant());
      // Resetting generation to zero makes it possible to apply the
      // visited property again.
      *visited_priority = CascadePriority(*visited_priority, 0);
      LookupAndApply(*visited, resolver);
    }
  }
}

void StyleCascade::LookupAndApply(const CSSPropertyName& name,
                                  CascadeResolver& resolver) {
  CSSPropertyRef ref(name, state_.GetDocument());
  DCHECK(ref.IsValid());
  LookupAndApply(ref.GetProperty(), resolver);
}

void StyleCascade::LookupAndApply(const CSSProperty& property,
                                  CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());

  CSSPropertyName name = property.GetCSSPropertyName();
  DCHECK(!resolver.IsLocked(property));

  CascadePriority* priority = map_.Find(name);
  if (!priority) {
    return;
  }

  if (resolver.Rejects(property)) {
    return;
  }

  LookupAndApplyValue(property, priority, resolver);
}

void StyleCascade::LookupAndApplyValue(const CSSProperty& property,
                                       CascadePriority* priority,
                                       CascadeResolver& resolver) {
  DCHECK(!property.IsSurrogate());

  if (priority->GetOrigin() < CascadeOrigin::kAnimation) {
    LookupAndApplyDeclaration(property, priority, resolver);
  } else if (priority->GetOrigin() >= CascadeOrigin::kAnimation) {
    LookupAndApplyInterpolation(property, priority, resolver);
  }
}

void StyleCascade::LookupAndApplyDeclaration(const CSSProperty& property,
                                             CascadePriority* priority,
                                             CascadeResolver& resolver) {
  if (priority->GetGeneration() >= resolver.generation_) {
    // Already applied this generation.
    return;
  }
  *priority = CascadePriority(*priority, resolver.generation_);
  DCHECK(!property.IsSurrogate());
  DCHECK(priority->GetOrigin() < CascadeOrigin::kAnimation);
  CascadeOrigin origin = priority->GetOrigin();
  // Values at CascadeOrigin::kNone
```
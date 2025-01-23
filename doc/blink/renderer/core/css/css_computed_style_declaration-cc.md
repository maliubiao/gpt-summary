Response:
Let's break down the thought process for analyzing the `CSSComputedStyleDeclaration.cc` file.

1. **Understand the Goal:** The request asks for the file's functionalities, its relationship with web technologies (JavaScript, HTML, CSS), examples, logical reasoning, common errors, and debugging clues.

2. **Initial Scan for Key Information:**  The first step is to quickly scan the file for obvious clues.

    * **File Path:** `blink/renderer/core/css/css_computed_style_declaration.cc`  immediately tells us this is about *computed styles* within the Blink rendering engine, specifically related to CSS. The `.cc` extension indicates C++ code.
    * **Copyright Notice:**  Lists contributors and licensing information, generally not directly relevant to functionality but provides context.
    * **Includes:**  The `#include` directives are crucial. They reveal dependencies and hint at the functionalities. We see includes for:
        * Core CSS concepts (`css_computed_style_declaration.h`, `css_identifier_value.h`, `css_primitive_value.h`, `css_property_names.h`, `css_selector.h`, etc.)
        * Animation (`css_animation_data.h`)
        * DOM elements (`document.h`, `element.h`, `pseudo_element.h`)
        * Layout (`layout_object.h`)
        * Styling (`computed_style.h`)
        * JavaScript bindings (`platform/bindings/exception_state.h`)
        * Utility and platform features (`base/memory/values_equivalent.h`, `platform/instrumentation/use_counter.h`, `platform/runtime_enabled_features.h`, etc.)

3. **Identify the Core Class:** The file name itself points to `CSSComputedStyleDeclaration`. This is the central class we need to analyze.

4. **Analyze Key Methods:**  Now, we delve into the class members (methods). We should focus on the public and most significant methods:

    * **Constructor (`CSSComputedStyleDeclaration`) and Destructor (`~CSSComputedStyleDeclaration`):**  Initialization and cleanup. The constructor takes an `Element`, a boolean for visited styles, and a pseudo-element name.
    * **`cssText()` and `setCSSText()`:**  These are standard methods for CSS style declarations. The implementation here tells us computed styles are read-only.
    * **`GetFontSizeCSSValuePreferringKeyword()`:**  Specific to font size, handling both keyword and pixel values.
    * **`IsMonospaceFont()`:**  Checks if the font is monospace.
    * **`ComputeComputedStyle()`:**  A core method that retrieves the `ComputedStyle` object. This is crucial for understanding how computed styles are accessed.
    * **`GetVariableNames()` and `GetVariableNamesCount()`:** Deal with CSS custom properties (variables).
    * **`StyledElement()` and `StyledLayoutObject()`:** These methods are essential for connecting the computed style to the actual DOM element and its layout representation. The handling of pseudo-elements here is important.
    * **`GetPropertyCSSValue(CSSPropertyID)` and `GetPropertyCSSValue(AtomicString)`:** The primary methods for getting computed style values. Note the distinction between standard properties and custom properties.
    * **`GetVariables()`:** Returns all custom properties.
    * **`UpdateStyleAndLayoutTreeIfNeeded()` and `UpdateStyleAndLayoutIfNeeded()`:** Critical for understanding when and how style and layout calculations are triggered. Pay attention to the conditions and the reasons for updates.
    * **`GetPropertyValue(CSSPropertyID)`:** Returns the string representation of a computed style value.
    * **`length()` and `item(unsigned i)`:**  Implement the indexed access to computed style properties. Note the handling of custom properties.
    * **`CssPropertyMatches()`:**  Used for comparing computed style values, primarily in editing scenarios.
    * **`CopyProperties()` and `CopyPropertiesInSet()`:** Methods for creating copies of the computed style.
    * **`parentRule()`:**  Computed styles don't have a parent rule.
    * **`getPropertyValue(const String&)`:**  The JavaScript-facing method to get property values.
    * **`getPropertyPriority()`:** Computed styles have no priority.
    * **`setProperty()`, `removeProperty()`:**  These are disabled for computed styles.
    * **`ScopedCleanStyleForAllProperties`:** This is a helper class for ensuring style and layout are up-to-date, used in specific scenarios.

5. **Map Functionalities to Web Technologies:**  Based on the methods and included headers:

    * **CSS:** The core purpose is to provide computed CSS style values. It deals with CSS properties, values, selectors (for pseudo-elements), and the concept of computed styles.
    * **HTML:**  It operates on `Element` objects, which are the building blocks of HTML. It retrieves styles for specific elements, including pseudo-elements.
    * **JavaScript:** The class is accessible from JavaScript via methods like `getPropertyValue()`, `length()`, and `item()`. The `ExceptionState` parameter indicates interactions with the JavaScript environment.

6. **Construct Examples:** Think of common scenarios where computed styles are used:

    * **JavaScript accessing styles:** `element.style.width` (though this gets inline styles, `getComputedStyle` is the relevant API).
    * **CSS affecting layout:**  Changes to computed `width`, `height`, `display`, etc.
    * **CSS animations and transitions:**  The code explicitly mentions animation durations.
    * **CSS custom properties:** The presence of `GetVariables()` and related methods highlights this.

7. **Logical Reasoning (Assumptions and Outputs):**  Consider specific methods and what they would return given certain inputs. For instance:

    * **Input:** An `Element` with `font-size: 16px;`. **Output of `GetPropertyValue("font-size")`:** `"16px"`.
    * **Input:** An `Element` with `font-size: large;`. **Output of `GetPropertyValue("font-size")`:**  The corresponding pixel value (e.g., `"18px"`). This demonstrates the *computation* aspect.
    * **Input:**  Accessing a non-existent property. **Output:** An empty string.

8. **Common Usage Errors:** Focus on mistakes developers might make when working with computed styles:

    * **Trying to set computed styles:**  This will fail as they are read-only.
    * **Forgetting about pseudo-elements:**  Computed styles can be obtained for pseudo-elements (`::before`, `::after`, etc.).
    * **Performance implications:**  Repeatedly calling `getComputedStyle` can be expensive, as it might trigger style and layout recalculations.

9. **Debugging Clues:**  Think about how someone would end up in this code during debugging:

    * **Using browser developer tools:** Inspecting computed styles.
    * **JavaScript code:**  Calling `window.getComputedStyle()`.
    * **Following the call stack:**  Tracing the execution from the JavaScript API down into the Blink rendering engine.

10. **Structure the Answer:** Organize the information logically into the categories requested by the prompt: functionalities, relationship with web technologies, examples, logical reasoning, common errors, and debugging clues. Use clear and concise language.

11. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have missed the nuance of `UpdateStyleAndLayoutTreeIfNeeded` and `UpdateStyleAndLayoutIfNeeded` and needed to revisit those sections for a more precise explanation. Also, ensure the examples are practical and illustrative.
这个文件 `blink/renderer/core/css/css_computed_style_declaration.cc` 是 Chromium Blink 引擎中负责实现 **计算样式声明 (Computed Style Declaration)** 的核心代码。它主要的功能是提供一个接口，允许 JavaScript 代码获取元素在应用所有 CSS 规则后最终生效的样式值。

以下是它的详细功能以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **提供元素计算后的样式信息:**  这是最核心的功能。它根据元素的匹配 CSS 规则、继承、层叠等机制，计算出最终应用于该元素的样式值。
2. **实现 `window.getComputedStyle()`:**  这个文件中的代码是浏览器提供给 JavaScript 的 `window.getComputedStyle()` API 的底层实现。当 JavaScript 调用此方法时，Blink 引擎会使用 `CSSComputedStyleDeclaration` 对象来返回元素的计算样式。
3. **处理伪元素样式:** 它能够处理元素的伪元素 (例如 `::before`, `::after`) 的计算样式。
4. **处理 CSS 变量:** 支持获取和解析 CSS 自定义属性（变量）的值。
5. **懒加载和缓存:** 为了性能考虑，计算样式通常是按需计算的，并且可能会被缓存起来。这个文件中的逻辑会处理何时需要重新计算样式。
6. **与布局引擎交互:** 计算样式会影响元素的布局。这个文件中的代码会与布局引擎进行交互，确保在获取某些依赖布局的属性时，布局是最新状态。
7. **处理 `!important` 规则:** 计算样式会考虑 CSS 规则的优先级，包括 `!important` 声明。
8. **处理动画和过渡:**  能够反映动画和过渡效果应用后的样式值。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

* **与 JavaScript 的关系:**
    * **API 提供者:** `CSSComputedStyleDeclaration` 是 `window.getComputedStyle()` API 的实现基础。
    * **数据提供者:**  JavaScript 通过 `window.getComputedStyle()` 获取到的对象就是 `CSSComputedStyleDeclaration` 的实例，它包含了元素的计算样式信息。
    * **举例:**
        ```javascript
        const element = document.getElementById('myElement');
        const computedStyle = window.getComputedStyle(element);
        const backgroundColor = computedStyle.backgroundColor; // 获取计算后的背景颜色
        console.log(backgroundColor);
        ```
        在这个例子中，JavaScript 调用 `window.getComputedStyle(element)`，Blink 引擎会创建或获取与 `element` 关联的 `CSSComputedStyleDeclaration` 对象，并从中提取 `backgroundColor` 属性的值。

* **与 HTML 的关系:**
    * **作用于 HTML 元素:** 计算样式的目标是 HTML 文档中的元素。
    * **基于 DOM 结构:** 计算样式的过程依赖于 HTML 的 DOM 树结构，因为样式继承和选择器的匹配都与 DOM 结构有关。
    * **举例:**
        ```html
        <div id="parent" style="color: blue;">
          <p id="child">This is a paragraph.</p>
        </div>
        ```
        ```javascript
        const child = document.getElementById('child');
        const computedStyle = window.getComputedStyle(child);
        const color = computedStyle.color; // 获取计算后的字体颜色，会继承父元素的蓝色
        console.log(color); // 输出 "rgb(0, 0, 255)" (或类似的 RGB 值)
        ```
        在这个例子中，`CSSComputedStyleDeclaration` 会考虑 `p` 元素从其父元素 `div` 继承的 `color` 样式。

* **与 CSS 的关系:**
    * **CSS 规则的应用结果:** 计算样式是所有匹配元素的 CSS 规则最终应用后的结果。
    * **考虑 CSS 层叠和优先级:**  `CSSComputedStyleDeclaration` 的实现需要严格遵循 CSS 的层叠规则和优先级机制，例如行内样式、ID 选择器、类选择器、类型选择器、通用选择器以及 `!important` 声明等。
    * **举例:**
        ```html
        <style>
          #myElement { color: red !important; }
          .my-class { color: green; }
          div { color: blue; }
        </style>
        <div id="myElement" class="my-class">Hello</div>
        ```
        ```javascript
        const element = document.getElementById('myElement');
        const computedStyle = window.getComputedStyle(element);
        const color = computedStyle.color;
        console.log(color); // 输出 "rgb(255, 0, 0)" (红色)，因为 ID 选择器的 !important 优先级最高
        ```
        在这个例子中，`CSSComputedStyleDeclaration` 会根据 CSS 规则的优先级，最终计算出 `color` 属性的值为红色。

**逻辑推理的假设输入与输出:**

假设我们有以下 HTML 和 CSS:

```html
<!DOCTYPE html>
<html>
<head>
<style>
  .container {
    font-size: 16px;
  }
  #special {
    font-size: 20px;
  }
</style>
</head>
<body>
  <div class="container" id="special">Text</div>
</body>
</html>
```

**假设输入:**  JavaScript 代码调用 `window.getComputedStyle(document.getElementById('special')).fontSize;`

**逻辑推理:**

1. Blink 引擎会找到 ID 为 `special` 的元素。
2. 它会查找匹配该元素的所有 CSS 规则。
3. `.container` 规则设置了 `font-size: 16px;`。
4. `#special` 规则设置了 `font-size: 20px;`。
5. 由于 ID 选择器比类选择器具有更高的优先级，`#special` 规则中的 `font-size: 20px;` 将会覆盖 `.container` 规则中的值。
6. `CSSComputedStyleDeclaration` 对象会存储计算后的 `fontSize` 为 `"20px"`。

**输出:** JavaScript 代码会得到字符串 `"20px"`。

**用户或编程常见的使用错误举例:**

1. **尝试修改计算样式:**  计算样式是只读的，尝试通过 `computedStyle.property = value` 来修改是无效的，并且不会报错（在某些浏览器中会警告）。
   ```javascript
   const element = document.getElementById('myElement');
   const computedStyle = window.getComputedStyle(element);
   computedStyle.backgroundColor = 'red'; // 无效，不会改变元素背景色
   element.style.backgroundColor = 'red'; // 正确的方式，修改行内样式
   ```
2. **混淆 `element.style` 和 `window.getComputedStyle()`:**
   * `element.style` 只能访问和修改元素的 **行内样式**。
   * `window.getComputedStyle()` 返回的是元素 **最终生效的样式**，包括行内样式、内部样式表和外部样式表中的规则。
3. **在样式尚未计算完成时访问:** 在某些情况下（例如，在文档加载完成之前），尝试获取计算样式可能会得到不完整或不准确的结果。应该确保在 DOMContentLoaded 或 load 事件之后访问。
4. **过度依赖计算样式进行性能敏感的操作:**  频繁地调用 `window.getComputedStyle()` 可能会导致浏览器的性能问题，因为它可能触发样式的重新计算和布局。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器中加载一个包含 CSS 样式的 HTML 页面。**
2. **JavaScript 代码执行，并且调用了 `window.getComputedStyle(element)`。**  这可能是直接调用，也可能是某个库或框架内部调用。
3. **浏览器内核接收到这个 JavaScript 调用。**
4. **Blink 引擎开始工作:**
   * **查找目标元素 (element)。**
   * **确定需要计算的伪元素 (如果有)。**
   * **遍历所有相关的样式表 (包括用户代理样式表、作者样式表和用户样式表)。**
   * **根据 CSS 选择器匹配规则，找到适用于该元素的所有 CSS 规则。**
   * **根据 CSS 的层叠和继承规则，计算出每个 CSS 属性的最终值。**  这个过程中会涉及到 `CSSComputedStyleDeclaration` 对象的创建和填充。
   * **将计算后的样式信息存储在 `CSSComputedStyleDeclaration` 对象中。**
5. **`window.getComputedStyle()` 方法返回 `CSSComputedStyleDeclaration` 对象给 JavaScript 代码。**
6. **JavaScript 代码可以访问该对象的属性 (例如 `computedStyle.backgroundColor`) 来获取具体的样式值。**

**作为调试线索:**

* 如果你在调试过程中发现 `window.getComputedStyle()` 返回的样式值与预期不符，可以考虑以下几点：
    * **CSS 优先级问题:** 检查是否有更高优先级的 CSS 规则覆盖了你期望的样式。
    * **样式继承问题:**  检查父元素的样式是否影响了子元素的样式。
    * **伪元素样式:**  确认你是否正确地获取了伪元素的计算样式。
    * **动态 CSS:**  如果样式是通过 JavaScript 动态修改的，确保修改已经生效。
    * **浏览器兼容性:**  某些 CSS 属性在不同浏览器中的计算方式可能略有差异。
    * **动画和过渡:**  动画和过渡效果会动态改变元素的样式，需要考虑这些因素。

通过理解 `CSSComputedStyleDeclaration` 的功能和工作原理，可以更好地理解浏览器如何处理 CSS 样式，以及如何有效地使用 JavaScript 获取和操作元素的样式信息。这个文件是 Blink 引擎中 CSS 模块的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/css/css_computed_style_declaration.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004 Zack Rusin <zack@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007 Nicholas Shanks <webkit@nickshanks.com>
 * Copyright (C) 2011 Sencha, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 */

#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"

#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/animation/css/css_animation_data.h"
#include "third_party/blink/renderer/core/css/computed_style_css_value_mapping.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_variable_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/zoom_adjusted_pixel_value.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

CSSValueID CssIdentifierForFontSizeKeyword(int keyword_size) {
  DCHECK_NE(keyword_size, 0);
  DCHECK_LE(keyword_size, 8);
  return static_cast<CSSValueID>(static_cast<int>(CSSValueID::kXxSmall) +
                                 keyword_size - 1);
}

void LogUnimplementedPropertyID(const CSSProperty& property) {
  if (!DCHECK_IS_ON() || !VLOG_IS_ON(1) ||
      property.PropertyID() == CSSPropertyID::kVariable) {
    return;
  }
  DEFINE_STATIC_LOCAL(HashSet<CSSPropertyID>, property_id_set, ());
  if (!property_id_set.insert(property.PropertyID()).is_new_entry) {
    return;
  }

  DVLOG(1) << "Blink does not yet implement getComputedStyle for '"
           << property.GetPropertyName() << "'.";
}

// Tally counts of animation duration being zero when querying a property on
// an element that has at least one active animation. We are interested in
// direct queries of the duration property as well as coincidental queries in
// order to gauge the impact of changing the default duration from 0 to auto.
void UseCountIfAnimationDurationZero(Document& document,
                                     const ComputedStyle& style,
                                     mojom::blink::WebFeature feature) {
  if (const CSSAnimationData* animation_data = style.Animations()) {
    for (std::optional<double> duration : animation_data->DurationList()) {
      if (duration == 0.0) {
        UseCounter::Count(document, feature);
        return;
      }
    }
  }
}

}  // namespace

const Vector<const CSSProperty*>&
CSSComputedStyleDeclaration::ComputableProperties(
    const ExecutionContext* execution_context) {
  DEFINE_STATIC_LOCAL(Vector<const CSSProperty*>, properties, ());
  if (properties.empty()) {
    CSSProperty::FilterWebExposedCSSPropertiesIntoVector(
        execution_context, kCSSComputableProperties,
        std::size(kCSSComputableProperties), properties);
  }
  return properties;
}

CSSComputedStyleDeclaration::CSSComputedStyleDeclaration(
    Element* element,
    bool allow_visited_style,
    const String& pseudo_element_name)
    : CSSStyleDeclaration(element ? element->GetExecutionContext() : nullptr),
      element_(element),
      allow_visited_style_(allow_visited_style),
      guaranteed_style_clean_(false) {
  pseudo_element_specifier_ = CSSSelectorParser::ParsePseudoElement(
      pseudo_element_name, element, pseudo_argument_);
}
CSSComputedStyleDeclaration::~CSSComputedStyleDeclaration() = default;

String CSSComputedStyleDeclaration::cssText() const {
  // CSSStyleDeclaration.cssText should return empty string for computed style.
  return String();
}

void CSSComputedStyleDeclaration::setCSSText(const ExecutionContext*,
                                             const String&,
                                             ExceptionState& exception_state) {
  exception_state.ThrowDOMException(
      DOMExceptionCode::kNoModificationAllowedError,
      "These styles are computed, and therefore read-only.");
}

const CSSValue*
CSSComputedStyleDeclaration::GetFontSizeCSSValuePreferringKeyword() const {
  if (!element_) {
    return nullptr;
  }

  element_->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  const ComputedStyle* style =
      element_->EnsureComputedStyle(pseudo_element_specifier_);
  if (!style) {
    return nullptr;
  }

  if (int keyword_size = style->GetFontDescription().KeywordSize()) {
    return CSSIdentifierValue::Create(
        CssIdentifierForFontSizeKeyword(keyword_size));
  }

  return ZoomAdjustedPixelValue(style->GetFontDescription().ComputedPixelSize(),
                                *style);
}

bool CSSComputedStyleDeclaration::IsMonospaceFont() const {
  if (!element_) {
    return false;
  }

  const ComputedStyle* style =
      element_->EnsureComputedStyle(pseudo_element_specifier_);
  if (!style) {
    return false;
  }

  return style->GetFontDescription().IsMonospace();
}
const ComputedStyle* CSSComputedStyleDeclaration::ComputeComputedStyle() const {
  Element* styled_element = StyledElement();
  DCHECK(styled_element);
  const ComputedStyle* style = styled_element->EnsureComputedStyle(
      (styled_element == element_) ? pseudo_element_specifier_ : kPseudoIdNone,
      pseudo_argument_);
  if (style && style->IsEnsuredOutsideFlatTree()) {
    UseCounter::Count(element_->GetDocument(),
                      WebFeature::kGetComputedStyleOutsideFlatTree);
  }
  return style;
}

const Vector<AtomicString>* CSSComputedStyleDeclaration::GetVariableNames()
    const {
  if (auto* style = ComputeComputedStyle()) {
    return &style->GetVariableNames();
  }
  return nullptr;
}

wtf_size_t CSSComputedStyleDeclaration::GetVariableNamesCount() const {
  if (auto* style = ComputeComputedStyle()) {
    return style->GetVariableNamesCount();
  }
  return 0;
}

Element* CSSComputedStyleDeclaration::StyledElement() const {
  if (!element_) {
    return nullptr;
  }

  if (pseudo_element_specifier_ == kPseudoIdInvalid) {
    CHECK(RuntimeEnabledFeatures::
              CSSComputedStyleFullPseudoElementParserEnabled());
    return nullptr;
  }

  if (Element* pseudo_element = element_->GetStyledPseudoElement(
          pseudo_element_specifier_, pseudo_argument_)) {
    return pseudo_element;
  }
  return element_.Get();
}

LayoutObject* CSSComputedStyleDeclaration::StyledLayoutObject() const {
  auto* node = StyledElement();
  if (!node) {
    return nullptr;
  }

  if (pseudo_element_specifier_ != kPseudoIdNone && node == element_.Get()) {
    return nullptr;
  }

  return node->GetLayoutObject();
}

const CSSValue* CSSComputedStyleDeclaration::GetPropertyCSSValue(
    CSSPropertyID property_id) const {
  if (property_id == CSSPropertyID::kVariable) {
    // TODO(https://crbug.com/980160): Disallow calling this function with
    // kVariable.
    return nullptr;
  }
  return GetPropertyCSSValue(CSSPropertyName(property_id));
}

const CSSValue* CSSComputedStyleDeclaration::GetPropertyCSSValue(
    const AtomicString& custom_property_name) const {
  return GetPropertyCSSValue(CSSPropertyName(custom_property_name));
}

HeapHashMap<AtomicString, Member<const CSSValue>>
CSSComputedStyleDeclaration::GetVariables() const {
  const ComputedStyle* style = ComputeComputedStyle();
  if (!style) {
    return {};
  }
  DCHECK(StyledElement());
  return ComputedStyleCSSValueMapping::GetVariables(
      *style, StyledElement()->GetDocument().GetPropertyRegistry(),
      CSSValuePhase::kResolvedValue);
}

void CSSComputedStyleDeclaration::UpdateStyleAndLayoutTreeIfNeeded(
    const CSSPropertyName* property_name,
    bool for_all_properties) const {
  if (guaranteed_style_clean_) {
    return;
  }

  Element* styled_element = StyledElement();
  if (!styled_element) {
    return;
  }

  Document& document = styled_element->GetDocument();

  if (HTMLFrameOwnerElement* owner = document.LocalOwner()) {
    // We are inside an iframe. If any of our ancestor iframes needs a style
    // and/or layout update, we need to make that up-to-date to resolve viewport
    // media queries and generate boxes as we might be moving to/from
    // display:none in some element in the chain of ancestors.
    //
    // TODO(futhark@chromium.org): There is an open question what the computed
    // style should be in a display:none iframe. If the property we are querying
    // is not layout dependent, we will not update the iframe layout box here.
    bool is_for_layout_dependent_property =
        for_all_properties ||
        (property_name && !property_name->IsCustomProperty() &&
         CSSProperty::Get(property_name->Id()).IsLayoutDependentProperty());
    if (is_for_layout_dependent_property) {
      owner->GetDocument().UpdateStyleAndLayout(
          DocumentUpdateReason::kComputedStyle);
      // The style recalc could have caused the styled node to be discarded or
      // replaced if it was a PseudoElement so we need to update it.
      styled_element = StyledElement();
    }
  }

  // Transition pseudo-elements require data computed in pre-paint to generate
  // the UA stylesheet for these pseudo-elements.
  // TODO(khushalsagar): We can probably optimize this to run only when a
  // property set by the UA stylesheet is queried.
  if (IsTransitionPseudoElement(styled_element->GetPseudoId())) {
    if (auto* view = document.View()) {
      view->UpdateAllLifecyclePhasesExceptPaint(
          DocumentUpdateReason::kComputedStyle);
    }
    return;
  }

  document.UpdateStyleAndLayoutTreeForElement(
      styled_element, DocumentUpdateReason::kComputedStyle);
}

void CSSComputedStyleDeclaration::UpdateStyleAndLayoutIfNeeded(
    const CSSProperty* property,
    bool for_all_properties) const {
  if (guaranteed_style_clean_) {
    return;
  }

  Element* styled_element = StyledElement();
  if (!styled_element) {
    return;
  }

  bool is_for_layout_dependent_property =
      for_all_properties || (property && property->IsLayoutDependent(
                                             styled_element->GetComputedStyle(),
                                             StyledLayoutObject()));

  if (is_for_layout_dependent_property) {
    auto& doc = styled_element->GetDocument();
    doc.UpdateStyleAndLayoutForNode(styled_element,
                                    DocumentUpdateReason::kJavaScript);
  }
}

const CSSValue* CSSComputedStyleDeclaration::GetPropertyCSSValue(
    const CSSPropertyName& property_name) const {
  Element* styled_element = StyledElement();
  if (!styled_element) {
    return nullptr;
  }

  UpdateStyleAndLayoutTreeIfNeeded(&property_name,
                                   /*for_all_properties=*/false);

  CSSPropertyRef ref(property_name, styled_element->GetDocument());
  if (!ref.IsValid()) {
    return nullptr;
  }
  const CSSProperty& property_class = ref.GetProperty();

  UpdateStyleAndLayoutIfNeeded(&property_class, /*for_all_properties=*/false);

  const ComputedStyle* style = ComputeComputedStyle();

  if (!style) {
    return nullptr;
  }

  // Tally property value fetches when there is a running animation with zero
  // duration.
  //   1. duration shorthand
  //   2. obscure webkit property for baseline.
  if (property_class.PropertyID() == CSSPropertyID::kAnimationDuration) {
    UseCountIfAnimationDurationZero(
        styled_element->GetDocument(), *style,
        WebFeature::kCSSGetComputedAnimationDurationZero);
  }

  // For a baseline comparison, we use a property unrelated to animations (and
  // likely to be obscure). If reading this property and duration happens to
  // be zero, then it is by shear coincidence and the reader is probably not
  // interested in the distinction between 0 and 'auto' for the duration value.
  if (property_class.PropertyID() == CSSPropertyID::kWebkitFontSmoothing) {
    UseCountIfAnimationDurationZero(
        styled_element->GetDocument(), *style,
        WebFeature::kCSSGetComputedWebkitFontSmoothingAnimationDurationZero);
  }

  const CSSValue* value = property_class.CSSValueFromComputedStyle(
      *style, StyledLayoutObject(), allow_visited_style_,
      CSSValuePhase::kResolvedValue);
  if (value) {
    return value;
  }

  LogUnimplementedPropertyID(property_class);
  return nullptr;
}

String CSSComputedStyleDeclaration::GetPropertyValue(
    CSSPropertyID property_id) const {
  const CSSValue* value = GetPropertyCSSValue(property_id);
  if (value) {
    return value->CssText();
  }
  return "";
}

unsigned CSSComputedStyleDeclaration::length() const {
  if (!element_ || !element_->InActiveDocument() ||
      (pseudo_element_specifier_ == kPseudoIdInvalid)) {
    return 0;
  }

  wtf_size_t variable_count = 0;

  if (RuntimeEnabledFeatures::CSSEnumeratedCustomPropertiesEnabled()) {
    UpdateStyleAndLayoutTreeIfNeeded(nullptr /* property_name */,
                                     /*for_all_properties=*/false);
    UpdateStyleAndLayoutIfNeeded(nullptr /* property */,
                                 /*for_all_properties=*/false);
    variable_count = GetVariableNamesCount();
  }

  return ComputableProperties(GetExecutionContext()).size() + variable_count;
}

String CSSComputedStyleDeclaration::item(unsigned i) const {
  if (i >= length()) {
    return "";
  }

  const auto& standard_names = ComputableProperties(GetExecutionContext());

  if (i < standard_names.size()) {
    return standard_names[i]->GetPropertyNameString();
  }

  DCHECK(RuntimeEnabledFeatures::CSSEnumeratedCustomPropertiesEnabled());
  DCHECK(GetVariableNames());
  const auto& variable_names = *GetVariableNames();
  CHECK_LT(i - standard_names.size(), variable_names.size());

  return variable_names[i - standard_names.size()];
}

bool CSSComputedStyleDeclaration::CssPropertyMatches(
    CSSPropertyID property_id,
    const CSSValue& property_value) const {
  if (property_id == CSSPropertyID::kFontSize &&
      (property_value.IsPrimitiveValue() ||
       property_value.IsIdentifierValue()) &&
      element_) {
    // This is only used by editing code.
    element_->GetDocument().UpdateStyleAndLayout(
        DocumentUpdateReason::kEditing);
    const ComputedStyle* style =
        element_->EnsureComputedStyle(pseudo_element_specifier_);
    if (style && style->GetFontDescription().KeywordSize()) {
      CSSValueID size_value = CssIdentifierForFontSizeKeyword(
          style->GetFontDescription().KeywordSize());
      auto* identifier_value = DynamicTo<CSSIdentifierValue>(property_value);
      if (identifier_value && identifier_value->GetValueID() == size_value) {
        return true;
      }
    }
  }
  const CSSValue* value = GetPropertyCSSValue(property_id);
  return base::ValuesEquivalent(value, &property_value);
}

MutableCSSPropertyValueSet* CSSComputedStyleDeclaration::CopyProperties()
    const {
  return CopyPropertiesInSet(ComputableProperties(GetExecutionContext()));
}

MutableCSSPropertyValueSet* CSSComputedStyleDeclaration::CopyPropertiesInSet(
    const Vector<const CSSProperty*>& properties) const {
  HeapVector<CSSPropertyValue, 64> list;
  list.ReserveInitialCapacity(properties.size());
  for (unsigned i = 0; i < properties.size(); ++i) {
    CSSPropertyName name = properties[i]->GetCSSPropertyName();
    const CSSValue* value = GetPropertyCSSValue(name);
    if (value) {
      list.push_back(CSSPropertyValue(name, *value, false));
    }
  }
  return MakeGarbageCollected<MutableCSSPropertyValueSet>(list);
}

CSSRule* CSSComputedStyleDeclaration::parentRule() const {
  return nullptr;
}

String CSSComputedStyleDeclaration::getPropertyValue(
    const String& property_name) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);
  if (!IsValidCSSPropertyID(property_id)) {
    return String();
  }
  if (property_id == CSSPropertyID::kVariable) {
    const CSSValue* value = GetPropertyCSSValue(AtomicString(property_name));
    if (value) {
      return value->CssText();
    }
    return String();
  }
#if DCHECK_IS_ON
  DCHECK(CSSProperty::Get(property_id).IsEnabled());
#endif
  return GetPropertyValue(property_id);
}

String CSSComputedStyleDeclaration::getPropertyPriority(const String&) {
  // All computed styles have a priority of not "important".
  return "";
}

String CSSComputedStyleDeclaration::GetPropertyShorthand(const String&) {
  return "";
}

bool CSSComputedStyleDeclaration::IsPropertyImplicit(const String&) {
  return false;
}

void CSSComputedStyleDeclaration::setProperty(const ExecutionContext*,
                                              const String& name,
                                              const String&,
                                              const String&,
                                              ExceptionState& exception_state) {
  exception_state.ThrowDOMException(
      DOMExceptionCode::kNoModificationAllowedError,
      "These styles are computed, and therefore the '" + name +
          "' property is read-only.");
}

String CSSComputedStyleDeclaration::removeProperty(
    const String& name,
    ExceptionState& exception_state) {
  exception_state.ThrowDOMException(
      DOMExceptionCode::kNoModificationAllowedError,
      "These styles are computed, and therefore the '" + name +
          "' property is read-only.");
  return String();
}

const CSSValue* CSSComputedStyleDeclaration::GetPropertyCSSValueInternal(
    CSSPropertyID property_id) {
  return GetPropertyCSSValue(property_id);
}

const CSSValue* CSSComputedStyleDeclaration::GetPropertyCSSValueInternal(
    const AtomicString& custom_property_name) {
  DCHECK_EQ(CSSPropertyID::kVariable,
            CssPropertyID(GetExecutionContext(), custom_property_name));
  return GetPropertyCSSValue(custom_property_name);
}

String CSSComputedStyleDeclaration::GetPropertyValueInternal(
    CSSPropertyID property_id) {
  return GetPropertyValue(property_id);
}

String CSSComputedStyleDeclaration::GetPropertyValueWithHint(
    const String& property_name,
    unsigned index) {
  NOTREACHED();
}

String CSSComputedStyleDeclaration::GetPropertyPriorityWithHint(
    const String& property_name,
    unsigned index) {
  NOTREACHED();
}

void CSSComputedStyleDeclaration::SetPropertyInternal(
    CSSPropertyID id,
    const String&,
    StringView,
    bool,
    SecureContextMode,
    ExceptionState& exception_state) {
  exception_state.ThrowDOMException(
      DOMExceptionCode::kNoModificationAllowedError,
      "These styles are computed, and therefore the '" +
          CSSUnresolvedProperty::Get(id).GetPropertyNameString() +
          "' property is read-only.");
}

void CSSComputedStyleDeclaration::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  CSSStyleDeclaration::Trace(visitor);
}

CSSComputedStyleDeclaration::ScopedCleanStyleForAllProperties::
    ScopedCleanStyleForAllProperties(CSSComputedStyleDeclaration* declaration)
    : declaration_(declaration) {
  declaration_->UpdateStyleAndLayoutTreeIfNeeded(nullptr,
                                                 /*for_all_properties=*/true);
  declaration_->UpdateStyleAndLayoutIfNeeded(nullptr,
                                             /*for_all_properties=*/true);
  disallow_scope_.emplace(
      declaration_->StyledElement()->GetDocument().Lifecycle());
  declaration_->guaranteed_style_clean_ = true;
}

CSSComputedStyleDeclaration::ScopedCleanStyleForAllProperties::
    ~ScopedCleanStyleForAllProperties() {
  declaration_->guaranteed_style_clean_ = false;
}

}  // namespace blink
```
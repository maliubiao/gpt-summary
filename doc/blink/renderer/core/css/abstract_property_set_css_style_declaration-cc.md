Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided C++ file (`abstract_property_set_css_style_declaration.cc`). They're particularly interested in its relationship to web technologies (JavaScript, HTML, CSS), examples of usage and errors, and how a user might trigger its execution.

**2. Initial Code Scan and Identification of Key Classes/Concepts:**

The first step is to quickly scan the code for keywords and class names that provide clues about its purpose. I see:

* `AbstractPropertySetCSSStyleDeclaration`: This is the central class. The name suggests it's an abstract base class related to CSS style declarations.
* `#include` directives point to other relevant files, like `css_numeric_literal_value.h`, `css_property_value_set.h`, `css_style_sheet.h`, `css_property_parser.h`, etc. These confirm the file's focus on CSS.
* Methods like `length()`, `item()`, `cssText()`, `setCSSText()`, `getPropertyValue()`, `setProperty()`, `removeProperty()`, `getPropertyPriority()` directly map to the CSSOM (CSS Object Model) APIs that JavaScript interacts with.
* The namespace `blink` indicates this is part of the Chromium rendering engine.

**3. Inferring Functionality Based on Method Names:**

The method names are very descriptive. I can infer the following functionalities:

* **Getting/Setting CSS Properties:** `getPropertyValue`, `setProperty`, `removeProperty`, `getPropertyPriority`. These directly manipulate CSS properties.
* **Accessing Multiple Properties:** `length`, `item`, `cssText`. These provide ways to iterate and retrieve the collection of styles.
* **Parsing CSS:** `setCSSText`, and the internal use of `PropertySet().ParseDeclarationList` point to parsing CSS text into a structured representation.
* **Handling Priorities:** The `priority` parameter in `setProperty` and `getPropertyPriority` suggests support for `!important`.
* **Custom Properties:**  The special handling of `CSSPropertyID::kVariable` indicates support for CSS custom properties (variables).
* **Shorthand Properties:** `GetPropertyShorthand` deals with mapping longhand properties to their shorthand equivalents.
* **Implicit Properties:** `IsPropertyImplicit` helps determine if a property's value is implicitly set.

**4. Connecting to JavaScript, HTML, and CSS:**

The method names strongly suggest a connection to the CSSOM. JavaScript uses the CSSOM to:

* **Read styles:**  `element.style.getPropertyValue('color')`
* **Set styles:** `element.style.setProperty('background-color', 'red')`
* **Remove styles:** `element.style.removeProperty('margin')`
* **Access all styles:** `element.style.length`, `element.style[0]`, `element.style.cssText`

HTML elements have a `style` attribute that corresponds to inline styles. JavaScript can access and modify these inline styles, and this C++ code is responsible for the underlying implementation of those operations. CSS rules defined in `<style>` tags or external stylesheets are also eventually represented using similar internal structures.

**5. Developing Examples and Scenarios:**

Based on the identified functionality, I can create examples demonstrating the interaction with JavaScript, HTML, and CSS:

* **JavaScript Interaction:**  Show how `element.style.setProperty` would call the corresponding C++ `setProperty` method.
* **HTML Interaction:** Illustrate how inline styles in HTML are parsed and stored using the mechanisms implemented in this file.
* **CSS Interaction:** Briefly explain how CSS rules from stylesheets are processed, although this file primarily deals with *individual* style declarations.

**6. Considering Logical Reasoning (Input/Output):**

For methods like `getPropertyValue`, `setProperty`, and `removeProperty`, I can define hypothetical inputs and expected outputs to illustrate their behavior. This helps to clarify the function's purpose.

**7. Identifying Common User Errors:**

Thinking about how developers typically work with CSS and the CSSOM, I can identify common errors:

* **Incorrect Property Names:** Typos in property names.
* **Invalid Values:** Providing values that are not valid for a given property.
* **Incorrect Priority Usage:** Misunderstanding or misusing `!important`.

**8. Tracing User Actions (Debugging Clues):**

To understand how a user's actions lead to this code, I need to consider the rendering pipeline:

* **Loading HTML:** The browser parses HTML.
* **Parsing CSS:**  The browser parses CSS from `<style>` tags and external stylesheets.
* **Applying Styles:** The browser calculates the final styles for each element, taking into account CSS specificity and inheritance.
* **JavaScript Manipulation:**  JavaScript code can directly modify an element's `style` object.

A user action like setting an inline style via JavaScript (`element.style.color = 'blue'`) or defining a CSS rule would eventually trigger the code in this file to store and manage those styles.

**9. Structuring the Answer:**

Finally, I need to organize the information logically, addressing each part of the user's request. This involves:

* **Listing Functions:**  Summarize the purpose of each public method.
* **Relating to Web Technologies:** Provide clear examples of how this code interacts with JavaScript, HTML, and CSS.
* **Illustrating Logical Reasoning:** Present input/output examples for key methods.
* **Highlighting User Errors:** Explain common mistakes and their consequences.
* **Describing User Actions (Debugging):** Outline the steps leading to the execution of this code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus solely on the individual methods.
* **Correction:** Realize the need to explain the bigger picture – how this file fits into the overall rendering process and the CSSOM.
* **Initial thought:** Provide highly technical explanations.
* **Correction:**  Simplify the language and provide concrete examples that are easier for someone less familiar with the Blink internals to understand.
* **Initial thought:** Only consider direct JavaScript manipulation.
* **Correction:**  Include the parsing of inline styles from HTML and the processing of CSS rules from stylesheets, even if this file doesn't handle *all* aspects of those processes.

By following this structured approach, I can provide a comprehensive and informative answer to the user's request.
这个 C++ 文件的主要功能是实现了 `AbstractPropertySetCSSStyleDeclaration` 类，该类是 Blink 渲染引擎中用于表示和操作 CSS 样式声明的一个抽象基类。  更具体地说，它提供了对一组 CSS 属性的底层访问和修改机制，这些属性可以来自于内联样式 (`style` 属性)、CSS 规则或者通过 JavaScript 动态设置。

以下是该文件的详细功能分解：

**核心功能：**

1. **存储和管理 CSS 属性:**  该类内部使用了 `PropertySet` 对象来实际存储 CSS 属性和它们的值。`PropertySet` 是一个更底层的类，用于高效地存储和查找 CSS 属性。

2. **实现 CSSOM 接口:**  `AbstractPropertySetCSSStyleDeclaration` 实现了部分 Web 标准中定义的 CSSOM (CSS Object Model) 接口，允许 JavaScript 代码通过 `element.style` 对象来访问和修改元素的样式。  这包括：
   * `length()`:  返回样式声明中属性的数量。
   * `item(unsigned i)`:  返回索引为 `i` 的属性名称。
   * `cssText()`:  返回包含所有样式声明的 CSS 文本字符串。
   * `setCSSText(ExecutionContext*, const String&, ExceptionState&)`:  解析给定的 CSS 文本并设置样式声明。
   * `getPropertyValue(const String&)`:  返回给定属性名称的属性值。
   * `setProperty(ExecutionContext*, const String&, const String&, const String&, ExceptionState&)`: 设置给定属性名称和值的属性。
   * `removeProperty(const String&, ExceptionState&)`:  移除给定属性名称的属性。
   * `getPropertyPriority(const String&)`:  返回给定属性的优先级（例如 "important"）。

3. **处理 CSS 优先级 (`!important`)**:  该类能够处理 CSS 属性的优先级，允许设置和获取带有 `!important` 标记的属性。

4. **处理 CSS 自定义属性 (变量)**:  特殊处理了 `CSSPropertyID::kVariable`，允许获取和设置 CSS 自定义属性（例如 `--my-color: blue;`）。

5. **获取属性的简写形式**:  `GetPropertyShorthand(const String&)` 方法可以返回给定长属性的简写形式（例如，对于 `margin-top`，可能返回 `margin`）。

6. **判断属性是否是隐式的**: `IsPropertyImplicit(const String&)` 方法用于判断属性是否是通过级联规则隐式设置的，而不是显式设置的。

7. **高性能路径优化**:  `FastPathSetProperty` 提供了一种针对某些数值类型的 CSS 属性进行快速设置的优化路径。

8. **与 CSS 解析器交互**:  `setCSSText` 和 `SetPropertyInternal` 方法会调用 CSS 解析器 (`PropertySet().ParseDeclarationList` 和 `PropertySet().ParseAndSetProperty`) 来将字符串形式的 CSS 值转换为内部表示。

9. **Mutation 观察**: 使用 `StyleAttributeMutationScope` 来在修改样式时生成 MutationRecord，以便 JavaScript 的 Mutation Observer API 可以观察到这些变化。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 该文件是实现 JavaScript 中 `element.style` API 的关键部分。当 JavaScript 代码通过 `element.style.color = 'red'` 或 `element.style.setProperty('font-size', '16px')` 修改元素样式时，最终会调用到这个文件中的方法，例如 `setProperty`。

   ```javascript
   // HTML: <div id="myDiv">Hello</div>
   const myDiv = document.getElementById('myDiv');

   // JavaScript 设置样式
   myDiv.style.color = 'blue';
   myDiv.style.setProperty('background-color', 'yellow', 'important');

   // JavaScript 获取样式
   console.log(myDiv.style.color); // 输出 "blue"
   console.log(myDiv.style.getPropertyValue('background-color')); // 输出 "yellow"
   console.log(myDiv.style.getPropertyPriority('background-color')); // 输出 "important"
   console.log(myDiv.style.cssText); // 输出 "color: blue; background-color: yellow !important;"
   ```

* **HTML:** 当浏览器解析 HTML 遇到元素的 `style` 属性时，例如 `<div style="color: green; font-weight: bold;">Text</div>`，这个文件中的 `setCSSText` 方法会被调用来解析 `style` 属性中的 CSS 文本，并将属性存储到 `AbstractPropertySetCSSStyleDeclaration` 对象中。

* **CSS:**  虽然这个文件主要处理的是单个元素的样式声明，但它与 CSS 规则也有联系。当 CSS 规则应用于元素时，计算出的样式值最终也会存储在与元素关联的 `AbstractPropertySetCSSStyleDeclaration` 对象中。 例如，如果 CSS 文件中有 `.my-class { border: 1px solid black; }`，当一个元素拥有 `my-class` 时，计算出的 `border-width`, `border-style`, `border-color` 等属性值会被存储。

**逻辑推理 (假设输入与输出):**

假设有一个 `AbstractPropertySetCSSStyleDeclaration` 对象 `styleDeclaration`，并且它当前没有任何属性。

* **输入:** `styleDeclaration->setCSSText(executionContext, "width: 100px; height: 50px !important;", exceptionState)`
* **输出:**
    * `styleDeclaration->length()` 将返回 `2`。
    * `styleDeclaration->getPropertyValue("width")` 将返回 `"100px"`。
    * `styleDeclaration->getPropertyValue("height")` 将返回 `"50px"`。
    * `styleDeclaration->getPropertyPriority("height")` 将返回 `"important"`。
    * `styleDeclaration->item(0)` 可能返回 `"width"`，`styleDeclaration->item(1)` 可能返回 `"height"` (顺序不保证)。
    * `styleDeclaration->cssText()` 可能返回 `"width: 100px; height: 50px !important;"` (顺序可能不同)。

* **输入:** `styleDeclaration->setProperty(executionContext, "color", "red", "", exceptionState)`
* **输出:**
    * `styleDeclaration->length()` 将变为 `3`。
    * `styleDeclaration->getPropertyValue("color")` 将返回 `"red"`。
    * `styleDeclaration->cssText()` 将包含 `"color: red;"`。

* **输入:** `styleDeclaration->removeProperty("width", exceptionState)`
* **输出:**
    * `styleDeclaration->length()` 将变为 `2`。
    * `styleDeclaration->getPropertyValue("width")` 将返回空字符串 `""`。
    * `styleDeclaration->cssText()` 将不再包含 `"width: 100px;"`。

**用户或编程常见的使用错误举例说明:**

1. **拼写错误的属性名:**

   ```javascript
   element.style.colr = 'blue'; // 拼写错误，不会生效
   ```
   在这个例子中，`colr` 不是一个有效的 CSS 属性名，Blink 会忽略这个设置，`setProperty` 方法可能直接返回或不进行任何操作。

2. **提供无效的属性值:**

   ```javascript
   element.style.width = 'abc'; // 'abc' 不是一个有效的 width 值
   ```
   Blink 的 CSS 解析器会尝试解析这个值，如果解析失败，该属性可能不会被设置，或者会被设置为默认值。在 C++ 代码中，`ParseAndSetProperty` 方法会返回一个指示解析结果的状态。

3. **在 `setProperty` 中使用错误的优先级字符串:**

   ```javascript
   element.style.setProperty('font-size', '20px', 'important!'); // 错误的优先级字符串
   ```
   `setProperty` 方法只接受 `"important"` 作为有效的优先级字符串。如果提供了其他字符串，该优先级会被忽略，相当于没有设置优先级。在 C++ 代码中，`setProperty` 方法会检查优先级字符串是否等于 `"important"`。

4. **尝试设置不存在的自定义属性但语法错误:**

   ```javascript
   element.style.setProperty('--my-var', 'value;'); // 注意末尾的分号，这可能导致解析错误
   ```
   虽然设置自定义属性是允许的，但如果值包含语法错误，Blink 的 CSS 解析器可能会报错，导致属性设置失败。

**用户操作是如何一步步到达这里的（调试线索）：**

1. **用户加载包含 CSS 的 HTML 页面:** 当浏览器加载 HTML 页面时，解析器会遇到 `<style>` 标签或链接的 CSS 文件。
2. **CSS 解析和规则创建:** Blink 的 CSS 解析器会解析 CSS 规则，并创建内部表示，包括选择器和属性值。
3. **样式计算:** 当渲染引擎需要确定元素的最终样式时，会进行样式计算。这涉及匹配 CSS 规则到 HTML 元素，并考虑优先级、继承等因素。
4. **`element.style` 访问:**
   * **用户通过 JavaScript 直接操作 `element.style`:** 例如，在浏览器的开发者工具的控制台中输入 `document.getElementById('myElement').style.backgroundColor = 'red'`。
   * **JavaScript 代码执行:** 网页上的 JavaScript 代码执行了类似 `element.style.setProperty(...)` 的操作。
5. **Blink 调用 C++ 代码:** 当 JavaScript 代码修改 `element.style` 时，Blink 的 JavaScript 绑定层会将这些操作转换为对 C++ 对象的调用。  对于 `element.style.backgroundColor = 'red'`，最终会调用到 `AbstractPropertySetCSSStyleDeclaration` 对象的 `setProperty` 方法。
6. **`setProperty` 内部处理:** `setProperty` 方法会：
   * 确定要设置的属性 ID。
   * 调用 CSS 解析器来解析属性值字符串。
   * 更新内部的 `PropertySet` 对象，存储新的属性值。
   * 如果需要，触发样式重新计算和页面重绘。

**调试线索:**

如果开发者在调试与 CSS 样式相关的问题，并且怀疑问题出在样式设置或获取的环节，他们可能会：

* **在 JavaScript 代码中设置断点:** 在修改 `element.style` 的代码行设置断点，查看传入的值是否正确。
* **使用浏览器的开发者工具:**
    * 查看元素的 "Styles" 面板，检查计算出的样式是否与预期一致。
    * 使用 "Computed" 面板查看最终应用的样式，以及哪些 CSS 规则影响了该样式。
    * 使用 "Performance" 面板或 "Timeline" 面板来分析样式计算的性能。
* **在 Blink 源代码中设置断点:**  如果需要深入了解 Blink 的内部行为，开发者可以在 `abstract_property_set_css_style_declaration.cc` 文件的相关方法（如 `setProperty`、`getPropertyValue`）中设置断点，查看参数和执行流程。这需要编译 Chromium 源码。

总而言之，`abstract_property_set_css_style_declaration.cc` 文件是 Blink 渲染引擎中处理元素样式声明的核心组件，它连接了 JavaScript 的 CSSOM 操作和底层的 CSS 属性存储和管理机制。理解它的功能对于理解浏览器如何处理 CSS 样式至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/abstract_property_set_css_style_declaration.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2011 Research In Motion Limited. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/css/abstract_property_set_css_style_declaration.h"

#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/style_attribute_mutation_scope.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"

namespace blink {

unsigned AbstractPropertySetCSSStyleDeclaration::length() const {
  return PropertySet().PropertyCount();
}

String AbstractPropertySetCSSStyleDeclaration::item(unsigned i) const {
  if (i >= PropertySet().PropertyCount()) {
    return "";
  }
  return PropertySet().PropertyAt(i).Name().ToAtomicString();
}

String AbstractPropertySetCSSStyleDeclaration::cssText() const {
  return PropertySet().AsText();
}

void AbstractPropertySetCSSStyleDeclaration::setCSSText(
    const ExecutionContext* execution_context,
    const String& text,
    ExceptionState&) {
  StyleAttributeMutationScope mutation_scope(this);
  WillMutate();

  const SecureContextMode mode = execution_context
                                     ? execution_context->GetSecureContextMode()
                                     : SecureContextMode::kInsecureContext;
  PropertySet().ParseDeclarationList(text, mode, ContextStyleSheet());

  DidMutate(kPropertyChanged);

  mutation_scope.EnqueueMutationRecord();
}

String AbstractPropertySetCSSStyleDeclaration::getPropertyValue(
    const String& property_name) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);
  if (!IsValidCSSPropertyID(property_id)) {
    return String();
  }
  if (property_id == CSSPropertyID::kVariable) {
    return PropertySet().GetPropertyValue(AtomicString(property_name));
  }
  return PropertySet().GetPropertyValue(property_id);
}

String AbstractPropertySetCSSStyleDeclaration::getPropertyPriority(
    const String& property_name) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);
  if (!IsValidCSSPropertyID(property_id)) {
    return String();
  }

  bool important = false;
  if (property_id == CSSPropertyID::kVariable) {
    important = PropertySet().PropertyIsImportant(AtomicString(property_name));
  } else {
    important = PropertySet().PropertyIsImportant(property_id);
  }
  return important ? "important" : "";
}

String AbstractPropertySetCSSStyleDeclaration::GetPropertyShorthand(
    const String& property_name) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);

  // Custom properties don't have shorthands, so we can ignore them here.
  if (!IsValidCSSPropertyID(property_id) ||
      !CSSProperty::Get(property_id).IsLonghand()) {
    return String();
  }
  CSSPropertyID shorthand_id = PropertySet().GetPropertyShorthand(property_id);
  if (!IsValidCSSPropertyID(shorthand_id)) {
    return String();
  }
  return CSSProperty::Get(shorthand_id).GetPropertyNameString();
}

bool AbstractPropertySetCSSStyleDeclaration::IsPropertyImplicit(
    const String& property_name) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);

  // Custom properties don't have shorthands, so we can ignore them here.
  if (property_id < kFirstCSSProperty) {
    return false;
  }
  return PropertySet().IsPropertyImplicit(property_id);
}

void AbstractPropertySetCSSStyleDeclaration::setProperty(
    const ExecutionContext* execution_context,
    const String& property_name,
    const String& value,
    const String& priority,
    ExceptionState& exception_state) {
  CSSPropertyID property_id =
      UnresolvedCSSPropertyID(execution_context, property_name);
  if (!IsValidCSSPropertyID(property_id) || !IsPropertyValid(property_id)) {
    return;
  }

  bool important = EqualIgnoringASCIICase(priority, "important");
  if (!important && !priority.empty()) {
    return;
  }

  const SecureContextMode mode = execution_context
                                     ? execution_context->GetSecureContextMode()
                                     : SecureContextMode::kInsecureContext;
  SetPropertyInternal(property_id, property_name, value, important, mode,
                      exception_state);
}

String AbstractPropertySetCSSStyleDeclaration::removeProperty(
    const String& property_name,
    ExceptionState& exception_state) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);
  if (!IsValidCSSPropertyID(property_id)) {
    return String();
  }

  StyleAttributeMutationScope mutation_scope(this);
  WillMutate();

  String result;
  bool changed = false;
  if (property_id == CSSPropertyID::kVariable) {
    changed =
        PropertySet().RemoveProperty(AtomicString(property_name), &result);
  } else {
    changed = PropertySet().RemoveProperty(property_id, &result);
  }

  DidMutate(changed ? kPropertyChanged : kNoChanges);

  if (changed) {
    mutation_scope.EnqueueMutationRecord();
  }
  return result;
}

const CSSValue*
AbstractPropertySetCSSStyleDeclaration::GetPropertyCSSValueInternal(
    CSSPropertyID property_id) {
  return PropertySet().GetPropertyCSSValue(property_id);
}

const CSSValue*
AbstractPropertySetCSSStyleDeclaration::GetPropertyCSSValueInternal(
    const AtomicString& custom_property_name) {
  DCHECK_EQ(CSSPropertyID::kVariable,
            CssPropertyID(GetExecutionContext(), custom_property_name));
  return PropertySet().GetPropertyCSSValue(custom_property_name);
}

String AbstractPropertySetCSSStyleDeclaration::GetPropertyValueInternal(
    CSSPropertyID property_id) {
  return PropertySet().GetPropertyValue(property_id);
}

String AbstractPropertySetCSSStyleDeclaration::GetPropertyValueWithHint(
    const String& property_name,
    unsigned index) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);
  if (!IsValidCSSPropertyID(property_id)) {
    return String();
  }
  if (property_id == CSSPropertyID::kVariable) {
    return PropertySet().GetPropertyValueWithHint(AtomicString(property_name),
                                                  index);
  }
  return PropertySet().GetPropertyValue(property_id);
}

String AbstractPropertySetCSSStyleDeclaration::GetPropertyPriorityWithHint(
    const String& property_name,
    unsigned index) {
  CSSPropertyID property_id =
      CssPropertyID(GetExecutionContext(), property_name);
  if (!IsValidCSSPropertyID(property_id)) {
    return String();
  }
  bool important = false;
  if (property_id == CSSPropertyID::kVariable) {
    important = PropertySet().PropertyIsImportantWithHint(
        AtomicString(property_name), index);
  } else {
    important = PropertySet().PropertyIsImportant(property_id);
  }
  return important ? "important" : "";
}

DISABLE_CFI_PERF
void AbstractPropertySetCSSStyleDeclaration::SetPropertyInternal(
    CSSPropertyID unresolved_property,
    const String& custom_property_name,
    StringView value,
    bool important,
    SecureContextMode secure_context_mode,
    ExceptionState&) {
  StyleAttributeMutationScope mutation_scope(this);
  WillMutate();

  MutableCSSPropertyValueSet::SetResult result;
  if (unresolved_property == CSSPropertyID::kVariable) {
    AtomicString atomic_name(custom_property_name);

    bool is_animation_tainted = IsKeyframeStyle();
    result = PropertySet().ParseAndSetCustomProperty(
        atomic_name, value, important, secure_context_mode, ContextStyleSheet(),
        is_animation_tainted);
  } else {
    result = PropertySet().ParseAndSetProperty(unresolved_property, value,
                                               important, secure_context_mode,
                                               ContextStyleSheet());
  }

  if (result == MutableCSSPropertyValueSet::kParseError ||
      result == MutableCSSPropertyValueSet::kUnchanged) {
    DidMutate(kNoChanges);
    return;
  }

  CSSPropertyID property_id = ResolveCSSPropertyID(unresolved_property);

  if (result == MutableCSSPropertyValueSet::kModifiedExisting &&
      CSSProperty::Get(property_id).SupportsIncrementalStyle()) {
    DidMutate(kIndependentPropertyChanged);
  } else {
    DidMutate(kPropertyChanged);
  }

  mutation_scope.EnqueueMutationRecord();
}

bool AbstractPropertySetCSSStyleDeclaration::FastPathSetProperty(
    CSSPropertyID unresolved_property,
    double value) {
  if (unresolved_property == CSSPropertyID::kVariable) {
    // We don't bother with the fast path for custom properties,
    // even though we could.
    return false;
  }
  if (!std::isfinite(value)) {
    // Just to be on the safe side.
    return false;
  }
  CSSPropertyID property_id = ResolveCSSPropertyID(unresolved_property);
  const CSSProperty& property = CSSProperty::Get(property_id);
  if (!property.AcceptsNumericLiteral()) {
    // Not all properties are prepared to accept numeric literals;
    // e.g. widths could accept doubles but want to convert them
    // to lengths, and shorthand properties may want to do their
    // own things. We don't support either yet, only specifically
    // allowlisted properties.
    return false;
  }

  StyleAttributeMutationScope mutation_scope(this);
  WillMutate();

  const CSSValue* css_value = CSSNumericLiteralValue::Create(
      value, CSSPrimitiveValue::UnitType::kNumber);
  MutableCSSPropertyValueSet::SetResult result =
      PropertySet().SetLonghandProperty(
          CSSPropertyValue(CSSPropertyName(property_id), *css_value,
                           /*important=*/false));

  if (result == MutableCSSPropertyValueSet::kParseError ||
      result == MutableCSSPropertyValueSet::kUnchanged) {
    DidMutate(kNoChanges);
    return true;
  }

  if (result == MutableCSSPropertyValueSet::kModifiedExisting &&
      property.SupportsIncrementalStyle()) {
    DidMutate(kIndependentPropertyChanged);
  } else {
    DidMutate(kPropertyChanged);
  }

  mutation_scope.EnqueueMutationRecord();
  return true;
}

DISABLE_CFI_PERF
StyleSheetContents* AbstractPropertySetCSSStyleDeclaration::ContextStyleSheet()
    const {
  CSSStyleSheet* css_style_sheet = ParentStyleSheet();
  return css_style_sheet ? css_style_sheet->Contents() : nullptr;
}

bool AbstractPropertySetCSSStyleDeclaration::CssPropertyMatches(
    CSSPropertyID property_id,
    const CSSValue& property_value) const {
  return PropertySet().PropertyMatches(property_id, property_value);
}

void AbstractPropertySetCSSStyleDeclaration::Trace(Visitor* visitor) const {
  CSSStyleDeclaration::Trace(visitor);
}

}  // namespace blink
```
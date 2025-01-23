Response:
Let's break down the thought process for analyzing this `StylePropertyMap.cc` file.

**1. Initial Understanding - What is the Goal?**

The prompt asks for the *functionality* of this file. The file path `blink/renderer/core/css/cssom/style_property_map.cc` immediately gives a strong hint. It's part of the CSS Object Model (CSSOM) within the Blink rendering engine. "Style property map" suggests a mechanism for managing and manipulating CSS properties.

**2. Core Functionality Identification - Key Methods:**

The next step is to scan the file for the main functions defined within the `StylePropertyMap` class. The provided code snippet makes this relatively easy. We can see the following public methods:

* `set()`
* `append()`
* `remove()`
* `clear()`

These method names are highly indicative of their purpose. `set` likely sets a property, `append` adds to a property (especially if it's a list), `remove` deletes a property, and `clear` removes all properties.

**3. Connecting to Web Technologies - JavaScript, HTML, CSS:**

The prompt specifically asks about relationships to JavaScript, HTML, and CSS. Knowing that this is part of the CSSOM is key. The CSSOM is the JavaScript API that allows manipulation of CSS styles. Therefore, this file is likely *the implementation* of the JavaScript `style` property and the newer CSS Typed OM interfaces like `element.computedStyleMap()` and `element.attributeStyleMap()`.

* **JavaScript:**  The methods directly correspond to actions a JavaScript developer would take to modify CSS styles. `element.style.propertyName = value` maps to `set()`. `element.style.propertyName += value` or using the Typed OM `element.attributeStyleMap().append()` maps to `append()`. `element.style.propertyName = ''` or `element.attributeStyleMap().delete()` maps to `remove()`.
* **HTML:**  HTML elements have inline `style` attributes. This code handles how those inline styles are parsed and represented in the CSSOM.
* **CSS:** This file is at the heart of how CSS properties are managed programmatically. It deals with CSS property names, values, keywords, and the different ways CSS values can be represented (single values, lists, etc.).

**4. Delving into the Implementation Details - Helper Functions:**

The file contains several private helper functions:

* `CssValueListForPropertyID()`: This clearly creates different types of CSS value lists (space-separated, comma-separated, slash-separated), suggesting handling of multi-value CSS properties.
* `StyleValueToCSSValue()`:  This is a critical function for converting a `CSSStyleValue` (a more structured representation in the CSSOM) into a raw `CSSValue` (the fundamental representation of a CSS value). It handles special cases and type coercion.
* `CoerceStyleValueOrString()` and `CoerceStyleValuesOrStrings()`: These are crucial for handling the input from JavaScript, which can be either a `CSSStyleValue` object or a raw CSS string. They parse the string and convert it into the internal `CSSValue` representation.

**5. Identifying Logic and Assumptions - Type Coercion, Shorthands, Custom Properties:**

Reading through the code reveals specific logic:

* **Type Coercion:** The `Coerce...` functions demonstrate the need to convert JavaScript values (strings or `CSSStyleValue` objects) into the internal Blink representation.
* **Shorthand Properties:** The `set()` method has special handling for shorthand properties (like `margin`, `border`). It parses the string value and potentially breaks it down into individual longhand properties.
* **Custom Properties (CSS Variables):** The code explicitly handles CSS variables (properties starting with `--`).
* **Repeated Properties (Lists):** The `append()` method and the `CssValueListForPropertyID()` function show how multi-value properties are handled.

**6. Considering Errors and Usage Mistakes:**

Based on the function signatures and logic, potential errors become apparent:

* **Invalid Property Names:**  The code checks for `CSSPropertyID::kInvalid` and throws a `TypeError`.
* **Incorrect Value Types:** The `Coerce...` functions can return `nullptr` if the provided value doesn't match the expected type for the property, leading to a `TypeError`.
* **Appending to Non-List Properties:** The `append()` method explicitly checks if a property is repeated and throws an error if it's not.
* **Appending to Custom Properties:** The `append()` method doesn't support appending to custom properties.
* **Invalid Shorthand Values:** If the provided string for a shorthand property is invalid, the parsing will fail, leading to an error.

**7. Debugging Scenario - How to Reach This Code:**

To illustrate a debugging scenario, consider a simple example:

1. **User Action:** A user interacts with a web page, triggering a JavaScript function.
2. **JavaScript Code:** The JavaScript function modifies the style of an HTML element using the `style` property or the Typed OM. For example: `element.style.backgroundColor = 'red';` or `element.attributeStyleMap().set('background-color', CSS.keyword('red'))`.
3. **Blink Engine:** The browser's JavaScript engine executes this code. The call to modify the style is routed to the Blink rendering engine.
4. **`StylePropertyMap`:**  The `set()` method in `StylePropertyMap.cc` (or a related method depending on the API used) is invoked.
5. **Processing:** The code in `set()` parses the property name (`background-color`), the value (`red`), and updates the internal representation of the element's style.

**8. Refinement and Organization:**

Finally, organize the gathered information into a clear and structured answer, addressing each point in the prompt. Use bullet points, code examples (even hypothetical ones for input/output), and clear explanations to make the information easily digestible. Emphasize the connections to the web technologies and highlight potential error scenarios.

This detailed thought process, moving from a high-level understanding to the implementation details and potential error scenarios, is crucial for effectively analyzing and explaining the functionality of a code file like `StylePropertyMap.cc`.
这个文件 `blink/renderer/core/css/cssom/style_property_map.cc` 是 Chromium Blink 引擎中负责实现 CSS Typed OM (CSS Typed Object Model) 中 `StylePropertyMap` 接口的核心代码。 `StylePropertyMap` 允许 JavaScript 以类型安全的方式访问和修改元素的 CSS 样式。

以下是它的主要功能：

**1. 提供 JavaScript 访问和操作 CSS 样式的接口:**

*   **`set(executionContext, propertyName, values, exceptionState)`:**  允许 JavaScript 设置指定 CSS 属性的值。可以设置单个值或多个值 (对于支持多值的属性)。
*   **`append(executionContext, propertyName, values, exceptionState)`:**  允许 JavaScript 向支持多值的 CSS 属性追加值。
*   **`remove(executionContext, propertyName, exceptionState)`:** 允许 JavaScript 移除指定的 CSS 属性。
*   **`clear()`:** 允许 JavaScript 清除所有 CSS 属性。

**2. 类型安全地处理 CSS 值:**

*   该文件负责将 JavaScript 传递的 `CSSStyleValue` 对象或字符串转换为 Blink 内部使用的 `CSSValue` 对象。
*   它会根据 CSS 属性的定义进行类型检查和转换，例如确保长度单位正确、颜色格式正确等。
*   这有助于防止由于类型错误导致的样式问题。

**3. 处理 CSS 属性的各种特性:**

*   **处理长属性和简写属性:**  `set()` 方法可以处理简写属性，例如 `margin`，它会将简写值分解为对应的长属性值（`margin-top`, `margin-right` 等）。
*   **处理自定义属性 (CSS Variables):**  文件中有专门的代码来处理 CSS 变量的设置、追加和移除。
*   **处理重复属性 (例如 `background-image`):**  `append()` 方法专门用于向可以拥有多个值的属性添加新的值。
*   **处理特殊情况和语法:**  代码中包含针对特定 CSS 属性的特殊处理逻辑，例如 `border-radius`，它期望两个值 (水平和垂直半径)。

**4. 与 CSS 解析器集成:**

*   当 JavaScript 传递的是字符串类型的 CSS 值时，该文件会使用 Blink 的 CSS 解析器 (`CSSParser`) 将字符串转换为 `CSSValue` 对象。

**5. 错误处理:**

*   当 JavaScript 尝试设置无效的属性名或提供与属性类型不匹配的值时，该文件会抛出 `TypeError` 异常。

**它与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**  `StylePropertyMap` 是 CSS Typed OM 的一部分，直接被 JavaScript 代码调用。开发者可以使用它来更精细、类型安全地操作元素的样式。
    *   **举例:**  在 JavaScript 中，可以使用 `element.attributeStyleMap.set('opacity', CSS.number(0.5))` 来设置元素的不透明度。这里的 `attributeStyleMap` 对象就包含了 `StylePropertyMap` 的功能。
*   **HTML:**  `StylePropertyMap` 操作的是 HTML 元素的样式。无论是内联样式 (`style` 属性) 还是通过 CSS 规则应用的样式，都可以通过 `StylePropertyMap` 进行访问和修改。
*   **CSS:**  `StylePropertyMap` 的核心是处理 CSS 属性和值。它理解 CSS 的语法和规则，并确保 JavaScript 的操作符合 CSS 规范。
    *   **举例:**  当 JavaScript 调用 `set('margin', '10px 20px')` 时，`StylePropertyMap` 会理解这是设置 `margin-top` 和 `margin-bottom` 为 `10px`，`margin-left` 和 `margin-right` 为 `20px`。

**逻辑推理示例：**

**假设输入：**

*   **JavaScript 代码:** `element.attributeStyleMap.set('border-radius', '10px');`
*   **`propertyName`:** "border-radius"
*   **`values`:** 包含一个字符串 "10px" 的 `HeapVector<Member<V8UnionCSSStyleValueOrString>>`

**逻辑推理和输出：**

1. `set()` 方法被调用，接收到 `propertyName` 和 `values`。
2. 识别出 `border-radius` 是一个简写属性，期望两个值（水平半径和垂直半径）。
3. `CoerceStyleValueOrString()` 被调用，将字符串 "10px" 解析为 `CSSPrimitiveValue` 对象，表示长度 `10px`。
4. 由于 `border-radius` 期望两个值，代码会创建一个 `CSSValuePair` 对象，其中水平和垂直半径都设置为解析出的 `CSSPrimitiveValue` (即 `10px 10px`)。
5. 最终，元素的 `border-radius` 样式会被设置为 `10px 10px`。

**常见的使用错误举例：**

*   **设置了无效的属性名:**
    *   **用户操作:** 在 JavaScript 中调用 `element.attributeStyleMap.set('invalid-property', 'red');`
    *   **结果:** `CssPropertyID()` 函数会返回 `CSSPropertyID::kInvalid`，`set()` 方法会抛出一个 `TypeError`，提示 "Invalid propertyName: invalid-property"。
*   **为不支持多值的属性调用 `append()`:**
    *   **用户操作:** 在 JavaScript 中调用 `element.attributeStyleMap.append('opacity', CSS.number(0.8));`
    *   **结果:** `append()` 方法会检查 `opacity` 是否是重复属性，由于不是，会抛出一个 `TypeError`，提示 "Property does not support multiple values"。
*   **为简写属性设置了错误数量的值:**
    *   **用户操作:** 在 JavaScript 中调用 `element.attributeStyleMap.set('margin', '10px');`  (只提供了一个值，`margin` 期望 1 到 4 个值)
    *   **结果:** `SetShorthandProperty()` 函数可能会解析失败，`set()` 方法会抛出一个 `TypeError`，提示 "Invalid type for property"。
*   **为属性设置了错误类型的值:**
    *   **用户操作:** 在 JavaScript 中调用 `element.attributeStyleMap.set('width', 'red');` (`width` 期望长度或百分比值，而不是颜色值)
    *   **结果:** `CoerceStyleValueOrString()` 或 `StyleValueToCSSValue()` 会尝试将 "red" 解析为长度值，失败后返回 `nullptr`，`set()` 方法会抛出一个 `TypeError`，提示 "Invalid type for property"。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中与网页进行交互。** 例如，点击一个按钮，或者鼠标悬停在一个元素上。
2. **该交互触发了 JavaScript 代码的执行。**  例如，一个事件监听器被触发。
3. **JavaScript 代码尝试修改元素的样式。**  这可以通过以下方式实现：
    *   直接修改元素的 `style` 属性： `element.style.backgroundColor = 'blue';`  (虽然 `style` 属性本身不是 `StylePropertyMap`，但其背后的机制最终会涉及到类似的处理)
    *   使用 CSS Typed OM API： `element.attributeStyleMap.set('color', CSS.keyword('green'));`
    *   修改 CSS 类名，并通过 CSS 规则应用样式。
4. **如果 JavaScript 代码使用了 CSS Typed OM API (例如 `attributeStyleMap.set`, `append`, `remove`)，那么代码执行流程会进入 `blink/renderer/core/css/cssom/style_property_map.cc` 文件中的相应方法。**
5. **调试时，可以在 `StylePropertyMap.cc` 中的关键方法 (`set`, `append`, `remove`) 设置断点。** 当 JavaScript 代码执行到相关的 CSS Typed OM 操作时，断点会被命中，可以观察到传入的 `propertyName` 和 `values`，以及代码的执行流程。
6. **查看调用堆栈 (Call Stack) 可以追溯到触发样式修改的 JavaScript 代码。** 这有助于理解用户操作是如何导致特定的样式修改操作的。

总而言之，`blink/renderer/core/css/cssom/style_property_map.cc` 是 Blink 引擎中至关重要的一个文件，它实现了 CSS Typed OM 的核心功能，负责以类型安全的方式管理和操作元素的 CSS 样式，并连接了 JavaScript、HTML 和 CSS 三种 web 技术。理解它的功能有助于深入理解浏览器如何处理和应用样式。

### 提示词
```
这是目录为blink/renderer/core/css/cssom/style_property_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/cssom/style_property_map.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssstylevalue_string.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_property_name.h"
#include "third_party/blink/renderer/core/css/css_scoped_keyword_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/cssom/css_style_value.h"
#include "third_party/blink/renderer/core/css/cssom/cssom_types.h"
#include "third_party/blink/renderer/core/css/cssom/style_value_factory.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

CSSValueList* CssValueListForPropertyID(CSSPropertyID property_id) {
  DCHECK(CSSProperty::Get(property_id).IsRepeated());
  char separator = CSSProperty::Get(property_id).RepetitionSeparator();
  switch (separator) {
    case ' ':
      return CSSValueList::CreateSpaceSeparated();
    case ',':
      return CSSValueList::CreateCommaSeparated();
    case '/':
      return CSSValueList::CreateSlashSeparated();
    default:
      NOTREACHED();
  }
}

const CSSValue* StyleValueToCSSValue(
    const CSSProperty& property,
    const AtomicString& custom_property_name,
    const CSSStyleValue& style_value,
    const ExecutionContext& execution_context) {
  DCHECK_EQ(property.IDEquals(CSSPropertyID::kVariable),
            !custom_property_name.IsNull());

  const CSSPropertyID property_id = property.PropertyID();
  if (!CSSOMTypes::PropertyCanTake(property_id, custom_property_name,
                                   style_value)) {
    return nullptr;
  }

  if (style_value.GetType() == CSSStyleValue::kUnknownType) {
    return CSSParser::ParseSingleValue(
        property.PropertyID(), style_value.toString(),
        MakeGarbageCollected<CSSParserContext>(execution_context));
  }

  // Handle properties that use ad-hoc structures for their CSSValues:
  // TODO(https://crbug.com/545324): Move this into a method on
  // CSSProperty when there are more of these cases.
  switch (property_id) {
    case CSSPropertyID::kAnchorScope: {
      // The 'all' keyword is tree-scoped.
      if (const auto* ident =
              DynamicTo<CSSIdentifierValue>(style_value.ToCSSValue());
          ident && ident->GetValueID() == CSSValueID::kAll) {
        return MakeGarbageCollected<cssvalue::CSSScopedKeywordValue>(
            ident->GetValueID());
      }
      break;
    }
    case CSSPropertyID::kBorderBottomLeftRadius:
    case CSSPropertyID::kBorderBottomRightRadius:
    case CSSPropertyID::kBorderTopLeftRadius:
    case CSSPropertyID::kBorderTopRightRadius:
    case CSSPropertyID::kBorderEndEndRadius:
    case CSSPropertyID::kBorderEndStartRadius:
    case CSSPropertyID::kBorderStartEndRadius:
    case CSSPropertyID::kBorderStartStartRadius: {
      // level 1 only accept single <length-percentages>, but border-radius-*
      // expects pairs.
      const auto* value = style_value.ToCSSValue();
      if (value->IsPrimitiveValue()) {
        return MakeGarbageCollected<CSSValuePair>(
            value, value, CSSValuePair::kDropIdenticalValues);
      }
      break;
    }
    case CSSPropertyID::kClipPath: {
      // level 1 only accepts single keywords
      const auto* value = style_value.ToCSSValue();
      // only 'none' is stored as an identifier, the other keywords are
      // wrapped in a list.
      auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
      if (identifier_value && !value->IsCSSWideKeyword() &&
          identifier_value->GetValueID() != CSSValueID::kNone) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kContain:
    case CSSPropertyID::kContainerType: {
      // level 1 only accepts single values, which are stored internally
      // as a single element list.
      const auto* value = style_value.ToCSSValue();
      if ((value->IsIdentifierValue() && !value->IsCSSWideKeyword()) ||
          value->IsPrimitiveValue()) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kFontVariantEastAsian:
    case CSSPropertyID::kFontVariantLigatures:
    case CSSPropertyID::kFontVariantNumeric: {
      // level 1 only accept single keywords, but font-variant-* store
      // them as a list
      if (const auto* value =
              DynamicTo<CSSIdentifierValue>(style_value.ToCSSValue())) {
        // 'none' and 'normal' are stored as a single value
        if (value->GetValueID() == CSSValueID::kNone ||
            value->GetValueID() == CSSValueID::kNormal) {
          break;
        }

        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kGridAutoFlow: {
      // level 1 only accepts single keywords
      const auto* value = style_value.ToCSSValue();
      // single keywords are wrapped in a list.
      if (value->IsIdentifierValue() && !value->IsCSSWideKeyword()) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kOffsetRotate: {
      // level 1 only accepts single values, which are stored internally
      // as a single element list.
      const auto* value = style_value.ToCSSValue();
      if ((value->IsIdentifierValue() && !value->IsCSSWideKeyword()) ||
          value->IsPrimitiveValue()) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kPaintOrder: {
      // level 1 only accepts single keywords
      const auto* value = style_value.ToCSSValue();
      // only 'normal' is stored as an identifier, the other keywords are
      // wrapped in a list.
      auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
      if (identifier_value && !value->IsCSSWideKeyword() &&
          identifier_value->GetValueID() != CSSValueID::kNormal) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kTextDecorationLine: {
      // level 1 only accepts single keywords
      const auto* value = style_value.ToCSSValue();
      // only 'none' is stored as an identifier, the other keywords are
      // wrapped in a list.
      auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
      if (identifier_value && !value->IsCSSWideKeyword() &&
          identifier_value->GetValueID() != CSSValueID::kNone) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    case CSSPropertyID::kTextIndent: {
      // level 1 only accepts single values, which are stored internally
      // as a single element list.
      const auto* value = style_value.ToCSSValue();
      if (value->IsPrimitiveValue()) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*value);
        return list;
      }
      break;
    }
    case CSSPropertyID::kTransitionProperty:
    case CSSPropertyID::kTouchAction: {
      // level 1 only accepts single keywords, which are stored internally
      // as a single element list
      const auto* value = style_value.ToCSSValue();
      if (value->IsIdentifierValue() && !value->IsCSSWideKeyword()) {
        CSSValueList* list = CSSValueList::CreateSpaceSeparated();
        list->Append(*style_value.ToCSSValue());
        return list;
      }
      break;
    }
    default:
      break;
  }

  return style_value.ToCSSValueWithProperty(property_id);
}

const CSSValue* CoerceStyleValueOrString(
    const CSSProperty& property,
    const AtomicString& custom_property_name,
    const V8UnionCSSStyleValueOrString* value,
    const ExecutionContext& execution_context) {
  DCHECK(!property.IsRepeated());
  DCHECK_EQ(property.IDEquals(CSSPropertyID::kVariable),
            !custom_property_name.IsNull());
  DCHECK(value);

  switch (value->GetContentType()) {
    case V8UnionCSSStyleValueOrString::ContentType::kCSSStyleValue:
      return StyleValueToCSSValue(property, custom_property_name,
                                  *value->GetAsCSSStyleValue(),
                                  execution_context);
    case V8UnionCSSStyleValueOrString::ContentType::kString: {
      const auto& values = StyleValueFactory::FromString(
          property.PropertyID(), custom_property_name, value->GetAsString(),
          MakeGarbageCollected<CSSParserContext>(execution_context));
      if (values.size() != 1U) {
        return nullptr;
      }
      return StyleValueToCSSValue(property, custom_property_name, *values[0],
                                  execution_context);
    }
  }

  NOTREACHED();
}

const CSSValue* CoerceStyleValuesOrStrings(
    const CSSProperty& property,
    const AtomicString& custom_property_name,
    const HeapVector<Member<V8UnionCSSStyleValueOrString>>& values,
    const ExecutionContext& execution_context) {
  DCHECK(property.IsRepeated());
  DCHECK_EQ(property.IDEquals(CSSPropertyID::kVariable),
            !custom_property_name.IsNull());
  if (values.empty()) {
    return nullptr;
  }

  CSSStyleValueVector style_values =
      StyleValueFactory::CoerceStyleValuesOrStrings(
          property, custom_property_name, values, execution_context);

  if (style_values.empty()) {
    return nullptr;
  }

  CSSValueList* result = CssValueListForPropertyID(property.PropertyID());
  for (const auto& style_value : style_values) {
    const CSSValue* css_value = StyleValueToCSSValue(
        property, custom_property_name, *style_value, execution_context);
    if (!css_value) {
      return nullptr;
    }
    if (css_value->IsCSSWideKeyword() || css_value->IsUnparsedDeclaration()) {
      return style_values.size() == 1U ? css_value : nullptr;
    }
    result->Append(*css_value);
  }

  return result;
}

}  // namespace

void StylePropertyMap::set(
    const ExecutionContext* execution_context,
    const String& property_name,
    const HeapVector<Member<V8UnionCSSStyleValueOrString>>& values,
    ExceptionState& exception_state) {
  const CSSPropertyID property_id =
      CssPropertyID(execution_context, property_name);
  if (property_id == CSSPropertyID::kInvalid) {
    exception_state.ThrowTypeError("Invalid propertyName: " + property_name);
    return;
  }

  DCHECK(IsValidCSSPropertyID(property_id));
  const CSSProperty& property = CSSProperty::Get(property_id);

  // Descriptors (like 'src') have CSSProperty instances, but are not
  // valid properties in this context.
  if (!property.IsProperty()) {
    exception_state.ThrowTypeError("Invalid propertyName: " + property_name);
    return;
  }

  if (property.IsShorthand()) {
    if (values.size() != 1) {
      exception_state.ThrowTypeError("Invalid type for property");
      return;
    }

    String css_text;
    switch (values[0]->GetContentType()) {
      case V8UnionCSSStyleValueOrString::ContentType::kCSSStyleValue: {
        CSSStyleValue* style_value = values[0]->GetAsCSSStyleValue();
        if (CSSOMTypes::PropertyCanTake(property_id, g_null_atom,
                                        *style_value)) {
          css_text = style_value->toString();
        }
        break;
      }
      case V8UnionCSSStyleValueOrString::ContentType::kString:
        css_text = values[0]->GetAsString();
        break;
    }

    if (css_text.empty() ||
        !SetShorthandProperty(property.PropertyID(), css_text,
                              execution_context->GetSecureContextMode())) {
      exception_state.ThrowTypeError("Invalid type for property");
    }

    return;
  }

  const AtomicString& custom_property_name =
      (property_id == CSSPropertyID::kVariable) ? AtomicString(property_name)
                                                : g_null_atom;

  const CSSValue* result = nullptr;
  if (property.IsRepeated()) {
    result = CoerceStyleValuesOrStrings(property, custom_property_name, values,
                                        *execution_context);
  } else if (values.size() == 1U) {
    result = CoerceStyleValueOrString(property, custom_property_name, values[0],
                                      *execution_context);
  }

  if (!result) {
    exception_state.ThrowTypeError("Invalid type for property");
    return;
  }

  if (property_id == CSSPropertyID::kVariable) {
    SetCustomProperty(custom_property_name, *result);
  } else {
    SetProperty(property_id, *result);
  }
}

void StylePropertyMap::append(
    const ExecutionContext* execution_context,
    const String& property_name,
    const HeapVector<Member<V8UnionCSSStyleValueOrString>>& values,
    ExceptionState& exception_state) {
  if (values.empty()) {
    return;
  }

  const CSSPropertyID property_id =
      CssPropertyID(execution_context, property_name);

  if (property_id == CSSPropertyID::kInvalid) {
    exception_state.ThrowTypeError("Invalid propertyName: " + property_name);
    return;
  }

  const CSSProperty& property = CSSProperty::Get(property_id);

  if (property_id == CSSPropertyID::kVariable) {
    exception_state.ThrowTypeError(
        "Appending to custom properties is not supported");
    return;
  }

  if (!property.IsRepeated()) {
    exception_state.ThrowTypeError("Property does not support multiple values");
    return;
  }

  CSSValueList* current_value = nullptr;
  if (const CSSValue* css_value = GetProperty(property_id)) {
    if (css_value->IsUnparsedDeclaration() ||
        css_value->IsPendingSubstitutionValue()) {
      // https://drafts.css-houdini.org/css-typed-om/#dom-stylepropertymap-append
      // 8. If props[property] contains a var() reference, throw a TypeError.
      exception_state.ThrowTypeError(
          "Cannot append to a list containing a variable reference");
      return;
    }
    if (!css_value->IsValueList()) {
      // The standard doesn't seem to cover this explicitly
      // (https://github.com/w3c/css-houdini-drafts/issues/823),
      // but the only really reasonable solution seems to be
      // to throw a TypeError.
      //
      // This covers e.g. system-wide CSS keywords, like inherit.
      exception_state.ThrowTypeError(
          "Cannot append to something that is not a list");
      return;
    }
    current_value = To<CSSValueList>(css_value)->Copy();
  } else {
    current_value = CssValueListForPropertyID(property_id);
  }

  const CSSValue* result = CoerceStyleValuesOrStrings(
      property, g_null_atom, values, *execution_context);
  const auto* result_value_list = DynamicTo<CSSValueList>(result);
  if (!result_value_list) {
    exception_state.ThrowTypeError("Invalid type for property");
    return;
  }

  for (const auto& value : *result_value_list) {
    current_value->Append(*value);
  }

  SetProperty(property_id, *current_value);
}

void StylePropertyMap::remove(const ExecutionContext* execution_context,
                              const String& property_name,
                              ExceptionState& exception_state) {
  CSSPropertyID property_id = CssPropertyID(execution_context, property_name);
  if (property_id == CSSPropertyID::kInvalid) {
    exception_state.ThrowTypeError("Invalid property name: " + property_name);
    return;
  }

  if (property_id == CSSPropertyID::kVariable) {
    RemoveCustomProperty(AtomicString(property_name));
  } else {
    RemoveProperty(property_id);
  }
}

void StylePropertyMap::clear() {
  RemoveAllProperties();
}

}  // namespace blink
```
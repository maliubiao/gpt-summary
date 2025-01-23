Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine. This file seems to handle the parsing and application of various CSS properties related to rendering.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the File's Purpose:** The file name `longhands_custom.cc` within the `blink/renderer/core/css/properties/longhands/` directory suggests that it defines the parsing and application logic for certain CSS longhand properties. The `_custom` suffix might indicate properties that don't have a simple one-to-one mapping with their underlying representation.

2. **Analyze Individual Property Handlers:** The code is structured as a series of classes, each named after a CSS property (e.g., `Content`, `CounterIncrement`, `Cursor`, `Display`). Each class contains methods like `ParseSingleValue`, `CSSValueFromComputedStyleInternal`, `ApplyInitial`, `ApplyInherit`, and `ApplyValue`. These methods are characteristic of how Blink handles CSS properties.

3. **Focus on Key Methods:**
    * `ParseSingleValue`:  This method is responsible for taking a stream of CSS tokens and parsing them into a `CSSValue` object. It defines the syntax allowed for each property.
    * `CSSValueFromComputedStyleInternal`: This method takes the computed style of an element and converts the internal representation of the property into a `CSSValue`. This is used when getting the computed style via JavaScript.
    * `ApplyInitial`: Sets the property to its initial (default) value.
    * `ApplyInherit`: Sets the property to the inherited value from the parent element.
    * `ApplyValue`: Takes a parsed `CSSValue` and updates the internal representation of the style for the element.

4. **Relate to CSS, HTML, and JavaScript:**
    * **CSS:** The primary function is to handle CSS properties. Examples will involve demonstrating how CSS syntax is parsed and how the parsed values are used.
    * **HTML:**  CSS styles are applied to HTML elements. Examples should show how the CSS properties affect the rendering of HTML.
    * **JavaScript:** JavaScript can be used to get and set CSS property values. Examples should illustrate how JavaScript interacts with the parsing and computed style retrieval mechanisms.

5. **Provide Concrete Examples:** For each property, try to create simple, illustrative examples that demonstrate the connection to CSS, HTML, and JavaScript.

6. **Consider Logic and Assumptions:** Some properties involve more complex logic (like the `content` property with `attr()` and `counter()`). For these, provide hypothetical inputs and outputs to illustrate the parsing process.

7. **Identify Potential User Errors:** Think about common mistakes developers make when using these CSS properties. For instance, incorrect syntax for `content`, providing invalid values for `cursor`, or misunderstanding how `counter-increment` and `counter-reset` work.

8. **Explain the User Journey (Debugging Context):** Imagine a developer encountering an issue with one of these properties. Describe the steps they might take that would lead them to investigate this part of the Blink source code. This usually involves inspecting styles, debugging rendering problems, or examining the computed style in the browser's developer tools.

9. **Summarize the Functionality:**  Concisely reiterate the main purpose of the file based on the analysis of the individual property handlers.

10. **Address the "Part 4 of 13" Instruction:** Acknowledge this and ensure the summary reflects the scope of this specific file within the larger context. It primarily deals with parsing and applying the listed longhand CSS properties.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  Simply list the properties and their basic CSS function.
* **Refinement:**  Provide more detailed explanations of the parsing and application logic within Blink. Emphasize the role of the different methods.
* **Initial thought:**  Give general examples of CSS, HTML, and JavaScript.
* **Refinement:**  Create specific examples tied to the functionality of the code being analyzed. Focus on how the parsing influences the final rendering.
* **Initial thought:** Briefly mention common errors.
* **Refinement:** Provide concrete examples of user errors that would be relevant to the specific properties handled in this file.

By following these steps and iteratively refining the explanation, we arrive at a comprehensive answer that addresses all aspects of the user's request.
这是 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件的第 4 部分，共 13 部分。根据提供的代码片段，我们可以归纳出这个文件主要负责以下功能：

**核心功能： 解析和应用特定的 CSS 长属性 (Longhand Properties)**

这个文件定义了多个 C++ 类，每个类对应一个 CSS 长属性，并负责处理该属性的解析（从 CSS 字符串到内部数据结构）和应用（将解析后的值应用到元素的样式中）。

**涉及的 CSS 属性（根据提供的代码片段）：**

* **`content`**:  定义元素生成的内容。
* **`counter-increment`**: 增加计数器的值。
* **`counter-reset`**: 重置计数器的值。
* **`counter-set`**: 设置计数器的值。
* **`cursor`**: 定义鼠标光标的样式。
* **`cx`**: 用于 SVG 变换中心点的 X 坐标。
* **`cy`**: 用于 SVG 变换中心点的 Y 坐标。
* **`d`**: 用于定义 SVG `path` 元素的路径数据。
* **`direction`**: 定义文本的书写方向。
* **`display`**: 定义元素的显示类型。
* **`dominant-baseline`**: 定义行内元素的基线对齐方式。
* **`dynamic-range-limit`**: 控制图像的动态范围。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **CSS 解析 (Parsing):**
   - **功能:** `ParseSingleValue` 方法负责将 CSS 属性值（以字符串形式）解析成 Blink 内部使用的 `CSSValue` 对象。
   - **例子:**  当浏览器遇到 CSS 规则 `content: "Hello";` 时，`Content::ParseSingleValue` 会被调用，将字符串 `"Hello"` 解析成 `CSSStringValue` 对象。
   - **假设输入与输出:**
     - **输入 (CSS):** `content: url(image.png) "Alt Text";`
     - **输出 (内部 `CSSValue` 结构，简化表示):**  一个包含两个元素的 `CSSValueList`: 一个 `CSSImageValue` 指向 `image.png`，另一个 `CSSStringValue` 包含 `"Alt Text"`。

2. **CSS 值到计算样式 (Computed Style):**
   - **功能:** `CSSValueFromComputedStyleInternal` 方法负责将元素计算后的样式值（Blink 内部表示）转换为 `CSSValue` 对象，通常用于 JavaScript 获取元素的计算样式。
   - **例子:**  如果一个元素的 `content` 属性计算后的值为一个计数器，`Content::CSSValueFromComputedStyleInternal` 会生成一个 `CSSCounterValue` 对象。
   - **假设输入与输出:**
     - **输入 (ComputedStyle 中的 `content` 数据):**  一个表示计数器 `mycounter`，列表样式为 `decimal`，分隔符为 `.` 的内部结构。
     - **输出 (CSSValue):**  一个 `CSSCounterValue` 对象，可以通过 JavaScript 的 `getComputedStyle` 获取，并可能被格式化为类似 `"1. "`.

3. **应用 CSS 值 (Applying CSS Values):**
   - **功能:** `ApplyValue` 方法负责将解析后的 `CSSValue` 应用到元素的样式中，最终影响元素的渲染。
   - **例子:** 当 `Content::ApplyValue` 接收到一个包含字符串的 `CSSValue` 时，它会创建一个 `TextContentData` 对象并设置到元素的样式中，这样浏览器就知道要渲染该字符串。
   - **假设输入与输出:**
     - **输入 (CSSValue，来自 `content: 'example';`):**  一个 `CSSStringValue` 对象，包含字符串 `"example"`。
     - **输出 (元素样式):** 元素的样式数据中 `content` 属性被设置为一个 `TextContentData` 对象，其文本内容为 `"example"`。

4. **初始值和继承 (Initial and Inherited Values):**
   - **功能:** `ApplyInitial` 设置属性的初始值，`ApplyInherit` 设置属性从父元素继承的值。
   - **例子:**  `Content::ApplyInitial` 会将 `content` 属性设置为 `nullptr`，表示没有内容。 `Cursor::ApplyInherit` 会将元素的 `cursor` 样式设置为其父元素的 `cursor` 样式。

5. **与 HTML 的关系:**
   - 这些 CSS 属性直接影响 HTML 元素的渲染方式。例如，`content` 可以在元素前后插入内容，`cursor` 改变鼠标悬停时的样式，`display` 控制元素的布局行为。

6. **与 JavaScript 的关系:**
   - JavaScript 可以通过 DOM API 获取和设置这些 CSS 属性的值。浏览器内部会调用这里定义的方法进行解析和应用。例如，使用 `element.style.content = 'New Content';` 会触发 `Content::ParseSingleValue` 和 `Content::ApplyValue`。
   - `getComputedStyle(element).content` 会触发 `Content::CSSValueFromComputedStyleInternal` 来获取计算后的 `content` 值。

**用户或编程常见的使用错误举例说明:**

1. **`content` 属性:**
   - **错误:** `content: image.png;`  // 缺少 `url()`
   - **说明:** 用户忘记使用 `url()` 函数来引用图像。Blink 的解析器会返回 `nullptr`，导致该条 CSS 规则无效。
   - **用户操作:** 在 CSS 中错误地编写了 `content` 属性的值。
   - **调试线索:** 检查开发者工具的 "Styles" 面板，该规则可能被标记为无效，或者在 "Computed" 面板中 `content` 属性可能显示为初始值。

2. **`cursor` 属性:**
   - **错误:** `cursor: my-custom-cursor;` // 未定义 `my-custom-cursor`
   - **说明:** 用户尝试使用一个未定义的自定义光标名称。Blink 会将光标设置为默认值。
   - **用户操作:** 在 CSS 中使用了未知的光标名称。
   - **调试线索:**  检查 "Computed" 面板，`cursor` 属性可能显示为 `auto` 或其他默认值。

3. **`counter-increment` 和 `counter-reset` 属性:**
   - **错误:**  忘记在伪元素（如 `::before` 或 `::after`）的 `content` 属性中使用 `counter()` 或 `counters()` 函数来显示计数器的值。
   - **说明:**  即使 `counter-increment` 或 `counter-reset` 被设置，如果 `content` 中没有引用计数器，用户也看不到效果。
   - **用户操作:**  在 CSS 中设置了计数器的增量或重置，但没有在 `content` 中使用。
   - **调试线索:**  检查元素的样式，确认 `counter-increment` 或 `counter-reset` 已生效，但检查伪元素的 "Computed" 样式，看 `content` 是否正确使用了 `counter()` 函数。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在 HTML 文件中引入了 CSS 样式:** 这可以是内联样式、`<style>` 标签内的样式，或者通过 `<link>` 标签引入的外部 CSS 文件。
2. **CSS 解析器开始解析这些 CSS 规则:** 当浏览器加载页面并遇到 CSS 规则时，Blink 的 CSS 解析器会读取这些规则。
3. **遇到特定的 CSS 属性:**  当解析器遇到例如 `content: "text";` 这样的规则时，它会识别出 `content` 属性。
4. **查找对应的处理函数:**  解析器会查找负责处理 `content` 属性的逻辑，这就会定位到 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件中的 `Content` 类及其 `ParseSingleValue` 方法。
5. **执行解析逻辑:** `Content::ParseSingleValue` 方法会读取 CSS 属性的值（例如 `"text"`），并将其转换为 Blink 内部的 `CSSValue` 对象。
6. **应用样式:**  随后，`Content::ApplyValue` 方法会被调用，将解析后的 `CSSValue` 应用到对应的 HTML 元素上，最终影响元素的渲染。

**总结其功能:**

`blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件（的这一部分）的主要功能是：

* **定义和实现了多个特定 CSS 长属性的解析逻辑。** 它负责将 CSS 字符串表示的属性值转换为 Blink 内部使用的数据结构。
* **定义了如何将这些解析后的值应用到元素的样式中。** 这直接影响了最终的页面渲染效果。
* **提供了获取这些属性计算值的接口。**  用于 JavaScript 获取元素的最终样式。
* **处理了这些属性的初始值和继承逻辑。**

简单来说，这个文件是 Blink 引擎处理特定 CSS 样式属性的核心组成部分，连接了 CSS 规则的文本表示和浏览器内部的样式表示及应用。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
kOpenQuote, CSSValueID::kCloseQuote,
          CSSValueID::kNoOpenQuote, CSSValueID::kNoCloseQuote>(stream);
    }
    if (!parsed_value) {
      parsed_value = css_parsing_utils::ConsumeString(stream);
    }
    if (!parsed_value) {
      if (stream.Peek().FunctionId() == CSSValueID::kAttr &&
          !RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled()) {
        parsed_value = ConsumeAttr(stream, context);
      } else if (stream.Peek().FunctionId() == CSSValueID::kCounter) {
        parsed_value = ConsumeCounterContent(stream, context, false);
      } else if (stream.Peek().FunctionId() == CSSValueID::kCounters) {
        parsed_value = ConsumeCounterContent(stream, context, true);
      }
    }
    if (!parsed_value) {
      if (css_parsing_utils::ConsumeSlashIncludingWhitespace(stream)) {
        // No values were parsed before the slash, so nothing to apply the
        // alternative text to.
        if (!values->length()) {
          return nullptr;
        }
        alt_text_present = true;
      } else {
        break;
      }
    } else {
      values->Append(*parsed_value);
    }
    savepoint.Release();
  } while (!stream.AtEnd() && !alt_text_present);
  if (!values->length()) {
    return nullptr;
  }
  outer_list->Append(*values);
  if (alt_text_present) {
    CSSValueList* alt_text_values = CSSValueList::CreateSpaceSeparated();
    do {
      CSSParserSavePoint savepoint(stream);
      CSSValue* alt_text = nullptr;
      if (stream.Peek().FunctionId() == CSSValueID::kAttr &&
          !RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled()) {
        alt_text = ConsumeAttr(stream, context);
      } else {
        alt_text = css_parsing_utils::ConsumeString(stream);
      }
      if (!alt_text) {
        break;
      }
      alt_text_values->Append(*alt_text);
      savepoint.Release();
    } while (!stream.AtEnd());
    if (!alt_text_values->length()) {
      return nullptr;
    }

    outer_list->Append(*alt_text_values);
  }
  return outer_list;
}

}  // namespace

const CSSValue* Content::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  return ParseContentValue(stream, context);
}

const CSSValue* Content::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForContentData(style, allow_visited_style,
                                                 value_phase);
}

void Content::ApplyInitial(StyleResolverState& state) const {
  state.StyleBuilder().SetContent(nullptr);
}

void Content::ApplyInherit(StyleResolverState& state) const {
  // FIXME: In CSS3, it will be possible to inherit content. In CSS2 it is
  // not. This note is a reminder that eventually "inherit" needs to be
  // supported.
}

namespace {

String GetStringFromAttributeOrStringValue(const CSSValue& value,
                                           StyleResolverState& state,
                                           ComputedStyleBuilder& builder) {
  String string = g_empty_string;
  if (const auto* function_value = DynamicTo<CSSFunctionValue>(value)) {
    DCHECK(!RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled());
    DCHECK_EQ(function_value->FunctionType(), CSSValueID::kAttr);
    builder.SetHasAttrFunction();
    // TODO: Can a namespace be specified for an attr(foo)?
    QualifiedName attr(
        To<CSSCustomIdentValue>(function_value->Item(0)).Value());
    const AtomicString& attr_value =
        state.GetUltimateOriginatingElementOrSelf().getAttribute(attr);
    string = attr_value.IsNull() ? g_empty_string : attr_value.GetString();
  } else {
    // We should be able to assume at this point that `value` is a
    // CSSStringValue, since all other types of CSSValues produced in
    // Content::ParseSingleValue should have been handled by Content::ApplyValue
    // before reaching this point. However, as observed in crbug.com/348304397
    // there is some unexpected type that is not getting handled. The following
    // two DCHECKs are intended to help investigate this. The first DCHECK tests
    // the theory that the unexpected type is coming from ConsumeImage, where a
    // light-dark() function in a UA shadow DOM could cause a
    // CSSLightDarkValuePair to be created. The second DCHECK will hit if this
    // first theory is wrong and `value` has some other unexpected type.
    DCHECK(!IsA<CSSLightDarkValuePair>(value));
    DCHECK(IsA<CSSStringValue>(value));
    if (const auto* string_value = DynamicTo<CSSStringValue>(value)) {
      string = string_value->Value();
    }
  }
  return string;
}

}  // namespace

void Content::ApplyValue(StyleResolverState& state,
                         const CSSValue& value,
                         ValueMode) const {
  DCHECK(value.IsScopedValue());
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK(identifier_value->GetValueID() == CSSValueID::kNormal ||
           identifier_value->GetValueID() == CSSValueID::kNone);
    if (identifier_value->GetValueID() == CSSValueID::kNone) {
      builder.SetContent(MakeGarbageCollected<NoneContentData>());
    } else {
      builder.SetContent(nullptr);
    }
    return;
  }
  const CSSValueList& outer_list = To<CSSValueList>(value);
  ContentData* first_content = nullptr;
  ContentData* prev_content = nullptr;
  for (auto& item : To<CSSValueList>(outer_list.Item(0))) {
    ContentData* next_content = nullptr;
    if (item->IsImageGeneratorValue() || item->IsImageSetValue() ||
        item->IsImageValue()) {
      next_content = MakeGarbageCollected<ImageContentData>(
          state.GetStyleImage(CSSPropertyID::kContent, *item));
    } else if (const auto* counter_value =
                   DynamicTo<cssvalue::CSSCounterValue>(item.Get())) {
      next_content = MakeGarbageCollected<CounterContentData>(
          AtomicString(counter_value->Identifier()), counter_value->ListStyle(),
          AtomicString(counter_value->Separator()),
          counter_value->GetTreeScope());
    } else if (auto* item_identifier_value =
                   DynamicTo<CSSIdentifierValue>(item.Get())) {
      QuoteType quote_type;
      switch (item_identifier_value->GetValueID()) {
        default:
          NOTREACHED();
        case CSSValueID::kOpenQuote:
          quote_type = QuoteType::kOpen;
          break;
        case CSSValueID::kCloseQuote:
          quote_type = QuoteType::kClose;
          break;
        case CSSValueID::kNoOpenQuote:
          quote_type = QuoteType::kNoOpen;
          break;
        case CSSValueID::kNoCloseQuote:
          quote_type = QuoteType::kNoClose;
          break;
      }
      next_content = MakeGarbageCollected<QuoteContentData>(quote_type);
    } else {
      String string =
          GetStringFromAttributeOrStringValue(*item, state, builder);
      if (prev_content && prev_content->IsText()) {
        TextContentData* text_content = To<TextContentData>(prev_content);
        text_content->SetText(text_content->GetText() + string);
        continue;
      }
      next_content = MakeGarbageCollected<TextContentData>(string);
    }

    if (!first_content) {
      first_content = next_content;
    } else {
      prev_content->SetNext(next_content);
    }

    prev_content = next_content;
  }
  // If alt text was provided, it will be present as the final element of the
  // outer list.
  if (outer_list.length() > 1) {
    CHECK_EQ(outer_list.length(), 2U);
    for (auto& item : To<CSSValueList>(outer_list.Item(1))) {
      auto* alt_content = MakeGarbageCollected<AltTextContentData>(
          GetStringFromAttributeOrStringValue(*item, state, builder));
      prev_content->SetNext(alt_content);
      prev_content = alt_content;
    }
  }
  DCHECK(first_content);
  builder.SetContent(first_content);
}

const int kCounterIncrementDefaultValue = 1;

const CSSValue* CounterIncrement::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCounter(stream, context,
                                           kCounterIncrementDefaultValue);
}

const CSSValue* CounterIncrement::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForCounterDirectives(
      style, CountersAttachmentContext::Type::kIncrementType);
}

const int kCounterResetDefaultValue = 0;

const CSSValue* CounterReset::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCounter(stream, context,
                                           kCounterResetDefaultValue);
}

const CSSValue* CounterReset::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForCounterDirectives(
      style, CountersAttachmentContext::Type::kResetType);
}

const int kCounterSetDefaultValue = 0;

const CSSValue* CounterSet::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCounter(stream, context,
                                           kCounterSetDefaultValue);
}

const CSSValue* CounterSet::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForCounterDirectives(
      style, CountersAttachmentContext::Type::kSetType);
}

const CSSValue* Cursor::ParseSingleValue(CSSParserTokenStream& stream,
                                         const CSSParserContext& context,
                                         const CSSParserLocalContext&) const {
  bool in_quirks_mode = IsQuirksModeBehavior(context.Mode());
  CSSValueList* list = nullptr;
  while (CSSValue* image = css_parsing_utils::ConsumeImage(
             stream, context,
             css_parsing_utils::ConsumeGeneratedImagePolicy::kForbid)) {
    double num;
    gfx::Point hot_spot(-1, -1);
    bool hot_spot_specified = false;
    if (css_parsing_utils::ConsumeNumberRaw(stream, context, num)) {
      hot_spot.set_x(ClampTo<int>(num));
      if (!css_parsing_utils::ConsumeNumberRaw(stream, context, num)) {
        return nullptr;
      }
      hot_spot.set_y(ClampTo<int>(num));
      hot_spot_specified = true;
    }

    if (!list) {
      list = CSSValueList::CreateCommaSeparated();
    }

    list->Append(*MakeGarbageCollected<cssvalue::CSSCursorImageValue>(
        *image, hot_spot_specified, hot_spot));
    if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
      return nullptr;
    }
  }

  CSSValueID id = stream.Peek().Id();
  if (id == CSSValueID::kWebkitZoomIn) {
    context.Count(WebFeature::kPrefixedCursorZoomIn);
  } else if (id == CSSValueID::kWebkitZoomOut) {
    context.Count(WebFeature::kPrefixedCursorZoomOut);
  } else if (id == CSSValueID::kWebkitGrab) {
    context.Count(WebFeature::kPrefixedCursorGrab);
  } else if (id == CSSValueID::kWebkitGrabbing) {
    context.Count(WebFeature::kPrefixedCursorGrabbing);
  }
  CSSIdentifierValue* cursor_type = nullptr;
  if (id == CSSValueID::kHand) {
    if (!in_quirks_mode) {  // Non-standard behavior
      return nullptr;
    }
    cursor_type = MakeGarbageCollected<CSSIdentifierValue>(
        CSSValueID::kPointer,
        /*was_quirky=*/true);  // Cannot use the identifier value pool due to
                               // was_quirky.
    stream.ConsumeIncludingWhitespace();
  } else if ((id >= CSSValueID::kAuto && id <= CSSValueID::kWebkitZoomOut) ||
             id == CSSValueID::kCopy || id == CSSValueID::kNone) {
    cursor_type = css_parsing_utils::ConsumeIdent(stream);
  } else {
    return nullptr;
  }

  if (!list) {
    return cursor_type;
  }
  list->Append(*cursor_type);
  return list;
}

const CSSValue* Cursor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = nullptr;
  CursorList* cursors = style.Cursors();
  if (cursors && cursors->size() > 0) {
    list = CSSValueList::CreateCommaSeparated();
    for (const CursorData& cursor : *cursors) {
      if (StyleImage* image = cursor.GetImage()) {
        list->Append(*MakeGarbageCollected<cssvalue::CSSCursorImageValue>(
            *image->ComputedCSSValue(style, allow_visited_style, value_phase),
            cursor.HotSpotSpecified(), cursor.HotSpot()));
      }
    }
  }
  CSSValue* value = CSSIdentifierValue::Create(style.Cursor());
  if (list) {
    list->Append(*value);
    return list;
  }
  return value;
}

void Cursor::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.ClearCursorList();
  builder.SetCursor(ComputedStyleInitialValues::InitialCursor());
}

void Cursor::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetCursor(state.ParentStyle()->Cursor());
  builder.SetCursorList(state.ParentStyle()->Cursors());
}

void Cursor::ApplyValue(StyleResolverState& state,
                        const CSSValue& value,
                        ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.ClearCursorList();
  if (auto* value_list = DynamicTo<CSSValueList>(value)) {
    builder.SetCursor(ECursor::kAuto);
    for (const auto& item : *value_list) {
      if (const auto* cursor =
              DynamicTo<cssvalue::CSSCursorImageValue>(*item)) {
        const CSSValue& image = cursor->ImageValue();
        builder.AddCursor(state.GetStyleImage(CSSPropertyID::kCursor, image),
                          cursor->HotSpotSpecified(), cursor->HotSpot());
      } else {
        builder.SetCursor(To<CSSIdentifierValue>(*item).ConvertTo<ECursor>());
      }
    }
  } else {
    builder.SetCursor(To<CSSIdentifierValue>(value).ConvertTo<ECursor>());
  }
}

const CSSValue* Cx::ParseSingleValue(CSSParserTokenStream& stream,
                                     const CSSParserContext& context,
                                     const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* Cx::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Cx(), style);
}

const CSSValue* Cy::ParseSingleValue(CSSParserTokenStream& stream,
                                     const CSSParserContext& context,
                                     const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSVGGeometryPropertyLength(
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* Cy::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.Cy(), style);
}

const CSSValue* D::ParseSingleValue(CSSParserTokenStream& stream,
                                    const CSSParserContext&,
                                    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumePathOrNone(stream);
}

const CSSValue* D::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const StylePath* style_path = style.D()) {
    return style_path->ComputedCSSValue();
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* Direction::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Direction());
}

void Direction::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  state.StyleBuilder().SetDirection(
      To<CSSIdentifierValue>(value).ConvertTo<TextDirection>());
}

namespace {

static bool IsDisplayOutside(CSSValueID id) {
  return id >= CSSValueID::kInline && id <= CSSValueID::kBlock;
}

static bool IsDisplayInside(CSSValueID id) {
  if (id == CSSValueID::kMasonry) {
    return RuntimeEnabledFeatures::CSSMasonryLayoutEnabled();
  }
  return (id >= CSSValueID::kFlowRoot && id <= CSSValueID::kMasonry) ||
         id == CSSValueID::kMath || id == CSSValueID::kRuby;
}

static bool IsDisplayBox(CSSValueID id) {
  return css_parsing_utils::IdentMatches<CSSValueID::kNone,
                                         CSSValueID::kContents>(id);
}

static bool IsDisplayInternal(CSSValueID id) {
  return id >= CSSValueID::kTableRowGroup && id <= CSSValueID::kRubyText;
}

static bool IsDisplayLegacy(CSSValueID id) {
  if (id == CSSValueID::kInlineMasonry) {
    return RuntimeEnabledFeatures::CSSMasonryLayoutEnabled();
  }
  return id >= CSSValueID::kInlineBlock && id <= CSSValueID::kWebkitInlineFlex;
}

bool IsDisplayListItem(CSSValueID id) {
  return id == CSSValueID::kListItem;
}

struct DisplayValidationResult {
  STACK_ALLOCATED();

 public:
  const CSSIdentifierValue* outside;
  const CSSIdentifierValue* inside;
  const CSSIdentifierValue* list_item;
};

// Find <display-outside>, <display-inside>, and `list-item` in the unordered
// keyword list `values`.  Returns nullopt if `values` contains an invalid
// combination of keywords.
std::optional<DisplayValidationResult> ValidateDisplayKeywords(
    const CSSValueList& values) {
  const CSSIdentifierValue* outside = nullptr;
  const CSSIdentifierValue* inside = nullptr;
  const CSSIdentifierValue* list_item = nullptr;
  for (const auto& item : values) {
    const CSSIdentifierValue* value = To<CSSIdentifierValue>(item.Get());
    CSSValueID value_id = value->GetValueID();
    if (!outside && IsDisplayOutside(value_id)) {
      outside = value;
    } else if (!inside && IsDisplayInside(value_id)) {
      inside = value;
    } else if (!list_item && IsDisplayListItem(value_id)) {
      list_item = value;
    } else {
      return std::nullopt;
    }
  }
  DisplayValidationResult result{outside, inside, list_item};
  return result;
}

// Drop redundant keywords, and update to backward-compatible keywords.
// e.g. {outside:"block", inside:"flow"} ==> {outside:"block", inside:null}
//      {outside:"inline", inside:"flow-root"} ==>
//          {outside:null, inside:"inline-block"}
void AdjustDisplayKeywords(DisplayValidationResult& result) {
  CSSValueID outside =
      result.outside ? result.outside->GetValueID() : CSSValueID::kInvalid;
  CSSValueID inside =
      result.inside ? result.inside->GetValueID() : CSSValueID::kInvalid;
  switch (inside) {
    case CSSValueID::kFlow:
      if (result.outside) {
        result.inside = nullptr;
      }
      break;
    case CSSValueID::kFlex:
    case CSSValueID::kFlowRoot:
    case CSSValueID::kGrid:
    case CSSValueID::kTable:
      if (outside == CSSValueID::kBlock) {
        result.outside = nullptr;
      } else if (outside == CSSValueID::kInline && !result.list_item) {
        CSSValueID new_id = CSSValueID::kInvalid;
        if (inside == CSSValueID::kFlex) {
          new_id = CSSValueID::kInlineFlex;
        } else if (inside == CSSValueID::kFlowRoot) {
          new_id = CSSValueID::kInlineBlock;
        } else if (inside == CSSValueID::kGrid) {
          new_id = CSSValueID::kInlineGrid;
        } else if (inside == CSSValueID::kTable) {
          new_id = CSSValueID::kInlineTable;
        }
        CHECK_NE(new_id, CSSValueID::kInvalid);
        result.outside = nullptr;
        result.inside = CSSIdentifierValue::Create(new_id);
      }
      break;
    case CSSValueID::kMath:
    case CSSValueID::kRuby:
      if (outside == CSSValueID::kInline) {
        result.outside = nullptr;
      }
      break;
    default:
      break;
  }

  if (result.list_item) {
    if (outside == CSSValueID::kBlock) {
      result.outside = nullptr;
    }
    if (inside == CSSValueID::kFlow) {
      result.inside = nullptr;
    }
  }
}

const CSSValue* ParseDisplayMultipleKeywords(
    CSSParserTokenStream& stream,
    const CSSIdentifierValue* first_value) {
  CSSValueList* values = CSSValueList::CreateSpaceSeparated();
  values->Append(*first_value);
  values->Append(*css_parsing_utils::ConsumeIdent(stream));
  if (stream.Peek().Id() != CSSValueID::kInvalid) {
    values->Append(*css_parsing_utils::ConsumeIdent(stream));
  }
  // `values` now has two or three CSSIdentifierValue pointers.

  auto result = ValidateDisplayKeywords(*values);
  if (!result) {
    return nullptr;
  }

  if (result->list_item && result->inside) {
    CSSValueID inside = result->inside->GetValueID();
    if (inside != CSSValueID::kFlow && inside != CSSValueID::kFlowRoot) {
      return nullptr;
    }
  }

  AdjustDisplayKeywords(*result);
  CSSValueList* result_list = CSSValueList::CreateSpaceSeparated();
  if (result->outside) {
    result_list->Append(*result->outside);
  }
  if (result->inside) {
    result_list->Append(*result->inside);
  }
  if (result->list_item) {
    result_list->Append(*result->list_item);
  }
  return result_list->length() == 1u ? &result_list->Item(0) : result_list;
}

}  // namespace

// https://drafts.csswg.org/css-display/#the-display-properties
//   [<display-outside> || <display-inside>] |
//   [<display-outside>? && [ flow | flow-root ]? && list-item] |
//   <display-internal> | <display-box> | <display-legacy>
const CSSValue* Display::ParseSingleValue(CSSParserTokenStream& stream,
                                          const CSSParserContext& context,
                                          const CSSParserLocalContext&) const {
  CSSValueID id = stream.Peek().Id();
  if (id != CSSValueID::kInvalid) {
    const CSSIdentifierValue* value = css_parsing_utils::ConsumeIdent(stream);
    if (stream.Peek().Id() != CSSValueID::kInvalid) {
      context.Count(WebFeature::kCssDisplayPropertyMultipleValues);
      return ParseDisplayMultipleKeywords(stream, value);
    }

    // The property has only one keyword (or one keyword and then junk,
    // in which case the caller will abort for us).
    if (id == CSSValueID::kFlow) {
      return CSSIdentifierValue::Create(CSSValueID::kBlock);
    } else if (id == CSSValueID::kListItem || IsDisplayBox(id) ||
               IsDisplayInternal(id) || IsDisplayLegacy(id) ||
               IsDisplayInside(id) || IsDisplayOutside(id)) {
      return value;
    } else {
      return nullptr;
    }
  }

  if (!RuntimeEnabledFeatures::CSSLayoutAPIEnabled()) {
    return nullptr;
  }

  if (!context.IsSecureContext()) {
    return nullptr;
  }

  CSSValueID function = stream.Peek().FunctionId();
  if (function != CSSValueID::kLayout &&
      function != CSSValueID::kInlineLayout) {
    return nullptr;
  }

  CSSCustomIdentValue* name;
  {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    name = css_parsing_utils::ConsumeCustomIdent(stream, context);

    // If we didn't get a custom-ident or didn't exhaust the function arguments
    // return nothing.
    // NOTE: This AtEnd() is fine, because we are inside a RestoringBlockGuard
    // (i.e., we are testing the end of the argument list).
    if (!name || !stream.AtEnd()) {
      return nullptr;
    }

    guard.Release();
  }
  stream.ConsumeWhitespace();
  return MakeGarbageCollected<cssvalue::CSSLayoutFunctionValue>(
      name, /* is_inline */ function == CSSValueID::kInlineLayout);
}

const CSSValue* Display::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.IsDisplayLayoutCustomBox()) {
    return MakeGarbageCollected<cssvalue::CSSLayoutFunctionValue>(
        MakeGarbageCollected<CSSCustomIdentValue>(
            style.DisplayLayoutCustomName()),
        style.IsDisplayInlineType());
  }

  if (style.Display() == EDisplay::kBlockMath) {
    CSSValueList* values = CSSValueList::CreateSpaceSeparated();
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kBlock));
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kMath));
    return values;
  }
  if (style.Display() == EDisplay::kBlockRuby) {
    CSSValueList* values = CSSValueList::CreateSpaceSeparated();
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kBlock));
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kRuby));
    return values;
  }
  if (style.Display() == EDisplay::kInlineListItem) {
    CSSValueList* values = CSSValueList::CreateSpaceSeparated();
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kInline));
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kListItem));
    return values;
  }
  if (style.Display() == EDisplay::kFlowRootListItem) {
    CSSValueList* values = CSSValueList::CreateSpaceSeparated();
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kFlowRoot));
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kListItem));
    return values;
  }
  if (style.Display() == EDisplay::kInlineFlowRootListItem) {
    CSSValueList* values = CSSValueList::CreateSpaceSeparated();
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kInline));
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kFlowRoot));
    values->Append(*CSSIdentifierValue::Create(CSSValueID::kListItem));
    return values;
  }

  return CSSIdentifierValue::Create(style.Display());
}

void Display::ApplyInitial(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetDisplay(ComputedStyleInitialValues::InitialDisplay());
  builder.SetDisplayLayoutCustomName(
      ComputedStyleInitialValues::InitialDisplayLayoutCustomName());
}

void Display::ApplyInherit(StyleResolverState& state) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  builder.SetDisplay(state.ParentStyle()->Display());
  builder.SetDisplayLayoutCustomName(
      state.ParentStyle()->DisplayLayoutCustomName());
}

void Display::ApplyValue(StyleResolverState& state,
                         const CSSValue& value,
                         ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    builder.SetDisplay(identifier_value->ConvertTo<EDisplay>());
    builder.SetDisplayLayoutCustomName(
        ComputedStyleInitialValues::InitialDisplayLayoutCustomName());
    return;
  }

  if (value.IsValueList()) {
    builder.SetDisplayLayoutCustomName(
        ComputedStyleInitialValues::InitialDisplayLayoutCustomName());
    const CSSValueList& list = To<CSSValueList>(value);
    DCHECK(list.length() == 2u ||
           (list.length() == 3u && list.Item(2).IsIdentifierValue()));
    DCHECK(list.Item(0).IsIdentifierValue());
    DCHECK(list.Item(1).IsIdentifierValue());
    auto result = ValidateDisplayKeywords(list);
    DCHECK(result);
    CSSValueID outside =
        result->outside ? result->outside->GetValueID() : CSSValueID::kInvalid;
    CSSValueID inside =
        result->inside ? result->inside->GetValueID() : CSSValueID::kInvalid;

    if (result->list_item) {
      const bool is_block =
          outside == CSSValueID::kBlock || !IsValidCSSValueID(outside);
      if (inside != CSSValueID::kFlowRoot) {
        builder.SetDisplay(is_block ? EDisplay::kListItem
                                    : EDisplay::kInlineListItem);
      } else {
        builder.SetDisplay(is_block ? EDisplay::kFlowRootListItem
                                    : EDisplay::kInlineFlowRootListItem);
      }
      return;
    }

    DCHECK(IsDisplayOutside(outside));
    DCHECK(IsDisplayInside(inside));
    const bool is_block = outside == CSSValueID::kBlock;
    if (inside == CSSValueID::kFlowRoot) {
      builder.SetDisplay(is_block ? EDisplay::kFlowRoot
                                  : EDisplay::kInlineBlock);
    } else if (inside == CSSValueID::kFlow) {
      builder.SetDisplay(is_block ? EDisplay::kBlock : EDisplay::kInline);
    } else if (inside == CSSValueID::kTable) {
      builder.SetDisplay(is_block ? EDisplay::kTable : EDisplay::kInlineTable);
    } else if (inside == CSSValueID::kFlex) {
      builder.SetDisplay(is_block ? EDisplay::kFlex : EDisplay::kInlineFlex);
    } else if (inside == CSSValueID::kGrid) {
      builder.SetDisplay(is_block ? EDisplay::kGrid : EDisplay::kInlineGrid);
    } else if (inside == CSSValueID::kMath) {
      builder.SetDisplay(is_block ? EDisplay::kBlockMath : EDisplay::kMath);
    } else if (inside == CSSValueID::kRuby) {
      builder.SetDisplay(is_block ? EDisplay::kBlockRuby : EDisplay::kRuby);
    }
    return;
  }

  const auto& layout_function_value =
      To<cssvalue::CSSLayoutFunctionValue>(value);

  EDisplay display = layout_function_value.IsInline()
                         ? EDisplay::kInlineLayoutCustom
                         : EDisplay::kLayoutCustom;
  builder.SetDisplay(display);
  builder.SetDisplayLayoutCustomName(layout_function_value.GetName());
}

const CSSValue* DominantBaseline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.DominantBaseline());
}

const CSSValue* DynamicRangeLimit::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  if (const CSSValue* const keyword_value = css_parsing_utils::ConsumeIdent<
          CSSValueID::kStandard, CSSValueID::kHigh,
          CSSValueID::kConstrainedHigh>(stream)) {
    return keyword_value;
  }

  if (stream.Peek().FunctionId() != CSSValueID::kDynamicRangeLimitMix) {
    return nullptr;
  }

  HeapVector<Member<const CSSValue>> limits;
  HeapVector<Member<const CSSPrimitiveValue>> percentages;
  bool all_percentages_zero = true;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    while (true) {
      stream.ConsumeWhitespace();

      const CSSValue* limit =
          DynamicRangeLimit::ParseSingleValue(stream, context, local_context);
      if (limit == nullptr) {
        return nullptr;
      }
      limits.push_back(limit);
      stream.ConsumeWhitespace();

      const CSSPrimitiveValue* percentage = css_parsing_utils::ConsumePercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      if (!percentage) {
        return nullptr;
      }
      percentages.push_back(percentage);
      stream.ConsumeWhitespace();

      // Reject literal negative values and values > 100%, and track if all
      // percentage values are zero.
      if (auto* numeric = DynamicTo<CSSNumericLiteralValue>(percentage)) {
        float numeric_percentage = numeric->ComputePercentage();
        if (numeric_percentage < 0.f || numeric_percentage > 100.f) {
          return nullptr;
        }
        all_percentages_zero &= numeric_percentage == 0.0f;
      } else {
        all_percentages_zero = false;
      }

      // If there is no comma then require that we be at the end of the
      // functional.
      if (!css_parsing_utils::ConsumeCommaIncludingWhitespace(stream)) {
        if (!stream.AtEnd()) {
          return nullptr;
        }
        break;
      }
    }
  }

  // If all values are literally zero, reject at parse time.
  if (all_percentages_zero) {
    return nullptr;
  }

  return MakeGarbageCollected<cssvalue::CSSDynamicRangeLimitMixValue>(
      std::move(limits), std::move(percentages));
}

const CSSValue* DynamicRangeLimit::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const auto& limit = style.GetDynamicRangeLimit();
  if (limit.standard_mix == 1.f) {
    return CSSIdentifierValue::Create(CSSValueID::kStandard);
  }
  if (limit.constrained_high_mix == 1.f) {
    return CSSIdentifierValu
```
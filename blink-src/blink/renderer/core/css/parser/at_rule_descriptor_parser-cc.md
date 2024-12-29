Response:
Let's break down the thought process for analyzing the `at_rule_descriptor_parser.cc` file.

1. **Understand the Goal:** The core request is to understand the *functionality* of this specific Chromium Blink file. This involves identifying its purpose, how it relates to web technologies (CSS, HTML, JavaScript), potential errors, and how a user's actions might lead to its execution.

2. **Initial Scan and Keywords:**  Start by quickly scanning the code for prominent keywords and structures. Things that jump out:
    * `#include`: Immediately tells us about dependencies. Look at the included headers: `css_font_face_src_value.h`, `css_string_value.h`, `css_syntax_string_parser.h`, `css_unicode_range_value.h`, `css_unparsed_declaration_value.h`, `css_value.h`, `css_value_pair.h`, `css_parser_context.h`, `css_parser_mode.h`, `css_tokenizer.h`, `css_variable_parser.h`, `css_parsing_utils.h`, `css_property.h`. These heavily indicate the file is involved in *parsing* CSS, specifically within the context of `@` rules.
    * `namespace blink`: Confirms this is part of the Blink rendering engine.
    * Function names like `ConsumeFontVariantList`, `ConsumeFontDisplay`, `ConsumeFontFaceUnicodeRange`, `ConsumeFontFaceSrcURI`, `ConsumeFontFaceSrcLocal`, `ConsumeDescriptor`, `ParseFontFaceDescriptor`, `ParseAtPropertyDescriptor`, `ParseAtViewTransitionDescriptor`. The "Consume" prefix suggests reading and processing input, while "Parse" suggests a more structured analysis. The specific names point to handling CSS descriptors within `@font-face`, `@property`, and `@view-transition` rules.
    * `AtRuleDescriptorID`: This strongly suggests the file handles the specific properties within `@` rules.
    * `CSSParserTokenStream`: Indicates the input is a stream of CSS tokens, a common structure in parsers.
    * `CSSParserContext`:  Hints at a context object holding parsing state.

3. **Identify Core Functionality:** Based on the keywords and function names, the core functionality is clearly: **Parsing the descriptors within CSS at-rules.**  This means taking a stream of CSS tokens and turning them into structured `CSSValue` objects.

4. **Relationship to Web Technologies:**
    * **CSS:** This is the primary focus. The file directly parses CSS syntax related to `@font-face`, `@property`, and `@view-transition` rules. Give concrete examples of these rules and the descriptors they contain (e.g., `@font-face { font-family: ...; src: ...; }`).
    * **HTML:**  CSS is applied to HTML elements. Explain that this parser comes into play when the browser encounters CSS, either in `<style>` tags or linked stylesheets.
    * **JavaScript:** While this file doesn't directly execute JavaScript, JavaScript can *manipulate* CSS. Mention how JavaScript could dynamically add or modify stylesheets containing these at-rules, triggering the parser.

5. **Logic and Assumptions (Input/Output):**  Consider how the parser works. It takes a stream of tokens and attempts to match them against expected syntax for each descriptor. For example, for `font-family`, it expects a valid family name.

    * **Hypothetical Input:**  Provide example CSS snippets for each supported at-rule and descriptor (e.g., `@font-face { font-family: "MyFont"; }`).
    * **Expected Output:** Describe the `CSSValue` object that would be created (e.g., a `CSSIdentifierValue` for the font family name).

6. **Common User/Programming Errors:** Think about what mistakes developers might make when writing CSS that would involve this parser.
    * **Syntax Errors:**  Misspelled keywords, incorrect punctuation, missing values (e.g., `@font-face { src: ; }`).
    * **Invalid Values:** Providing values that are not valid for the specific descriptor (e.g., `@font-face { font-weight: lighter-than-thin; }`).
    * **Incorrect Order:** While less common for descriptors, sometimes the order matters in CSS syntax. This parser enforces the expected order of tokens within a descriptor's value.

7. **Debugging and User Actions:**  Imagine how a developer might end up looking at this code while debugging.

    * **Steps to Reach the Code:** Outline the steps a user takes that lead the browser to parse CSS (opening a web page, the browser requesting CSS files).
    * **Debugging Scenario:** Describe a situation where a developer notices a font isn't loading or a registered property isn't working. They might then inspect the browser's developer tools, see errors related to CSS parsing, and potentially even delve into the browser's source code (like this file) to understand the parsing process. Mention specific developer tools (Elements tab, Network tab, Console).

8. **Structure and Refine:**  Organize the findings logically. Start with the main function, then detail the relationships, examples, errors, and debugging aspects. Use clear headings and bullet points for readability. Ensure the language is accessible but still technically accurate. Avoid jargon where possible, or explain it briefly.

9. **Review and Iterate:** Read through the explanation to make sure it's clear, comprehensive, and accurate. Check for any inconsistencies or missing information. For example, initially, I might focus too much on just `@font-face`. A review would remind me to cover `@property` and `@view-transition` as well.

This systematic approach, combining code scanning, keyword analysis, understanding of web technologies, and thinking through user scenarios, allows for a thorough analysis of the functionality of the `at_rule_descriptor_parser.cc` file.
这个文件 `blink/renderer/core/css/parser/at_rule_descriptor_parser.cc` 是 Chromium Blink 渲染引擎中负责**解析 CSS at-rule 中的描述符 (descriptors)** 的源代码文件。

**功能概览:**

1. **解析 `@font-face` 规则的描述符:** 例如 `font-family`, `src`, `unicode-range`, `font-display` 等。它负责将这些描述符的值从 CSS 语法转换为 Blink 内部的 `CSSValue` 对象。

2. **解析 `@property` 规则的描述符:** 例如 `syntax`, `inherits`, `initial-value`。它负责解析自定义属性的语法约束、继承行为和初始值。

3. **解析 `@view-transition` 规则的描述符:** 例如 `navigation`, `types`。它负责解析视图过渡规则的导航类型和过渡类型。

4. **提供通用的描述符解析框架:**  尽管目前主要处理上述三种 at-rule，但其架构设计允许扩展以支持其他 at-rule 的描述符解析。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这是该文件最直接相关的领域。它直接解析 CSS 语法中 at-rule 的描述符部分。
    * **例子 (针对 `@font-face`):**
        ```css
        @font-face {
          font-family: "Open Sans"; /* 描述符 */
          src: url("/fonts/OpenSans-Regular.woff2") format("woff2"); /* 描述符 */
          font-weight: 400; /* 描述符 */
        }
        ```
        `at_rule_descriptor_parser.cc` 会解析 `font-family` 的值为字符串 "Open Sans"，`src` 的值为一个包含 URL 和 format 的 `CSSValue` 对象，`font-weight` 的值为数字 400 的 `CSSValue` 对象。

    * **例子 (针对 `@property`):**
        ```css
        @property --my-color {
          syntax: '<color>'; /* 描述符 */
          inherits: false; /* 描述符 */
          initial-value: red; /* 描述符 */
        }
        ```
        `at_rule_descriptor_parser.cc` 会解析 `syntax` 的值为字符串 '<color>'，`inherits` 的值为布尔值 false，`initial-value` 的值为颜色 red 的 `CSSValue` 对象。

    * **例子 (针对 `@view-transition`):**
        ```css
        @view-transition {
          navigation: auto; /* 描述符 */
          types: replace; /* 描述符 */
        }
        ```
        `at_rule_descriptor_parser.cc` 会解析 `navigation` 的值为关键字 `auto`，`types` 的值为关键字 `replace`。

* **HTML:**  HTML 负责组织网页结构，CSS 负责样式。当浏览器解析 HTML 文档并遇到 `<style>` 标签或链接的 CSS 文件时，会调用 CSS 解析器，其中就包括这个文件来处理 at-rule 中的描述符。

* **JavaScript:** JavaScript 可以动态地修改 CSS 样式，包括添加或修改包含 at-rule 的样式表。当 JavaScript 更改样式后，渲染引擎会重新解析 CSS，`at_rule_descriptor_parser.cc` 可能会被再次调用。
    * **例子:**
        ```javascript
        const styleSheet = document.createElement('style');
        styleSheet.textContent = `
          @font-face {
            font-family: "CustomFont";
            src: url("/my-custom-font.woff");
          }
        `;
        document.head.appendChild(styleSheet);
        ```
        当这段 JavaScript 代码执行时，浏览器会解析新添加的 `@font-face` 规则，`at_rule_descriptor_parser.cc` 将负责解析 `font-family` 和 `src` 描述符。

**逻辑推理及假设输入与输出:**

假设输入一段 CSS 代码片段：

```css
@font-face {
  font-family: "My Special Font";
  src: url('localFont.woff') format('woff');
}
```

`AtRuleDescriptorParser::ParseFontFaceDescriptor` 函数会被调用，并且 `id` 参数会对应到 `AtRuleDescriptorID::FontFamily` 和 `AtRuleDescriptorID::Src`。

* **假设输入 (针对 `font-family` 描述符):**  Token 流包含标识符 "font-family"，冒号，以及字符串 "My Special Font"。
    * **输出:** 返回一个 `CSSIdentifierValue` 对象，其值为 "My Special Font"。

* **假设输入 (针对 `src` 描述符):** Token 流包含标识符 "src"，冒号，`url()` 函数，`format()` 函数。
    * **输出:** 返回一个 `CSSValueList` 对象，其中包含一个 `CSSFontFaceSrcValue` 对象，该对象包含 URL "localFont.woff" 和 format "woff"。

**用户或编程常见的使用错误:**

1. **拼写错误:** 错误地拼写描述符名称，例如将 `font-family` 写成 `font-fammily`。这会导致解析器无法识别该描述符。
    * **例子:**
        ```css
        @font-face {
          font-fammily: "Invalid Font"; /* 拼写错误 */
          src: url("/invalid.woff");
        }
        ```
        `at_rule_descriptor_parser.cc` 将无法找到匹配的解析逻辑，可能返回 `nullptr`。

2. **语法错误:**  在描述符的值中使用了错误的语法。
    * **例子 (针对 `@font-face`):**
        ```css
        @font-face {
          font-family: "MyFont" extra words; /* 语法错误 */
          src: url("/myfont.woff");
        }
        ```
        解析 `font-family` 描述符时，`css_parsing_utils::ConsumeFamilyName` 会尝试解析，但遇到额外的词语会失败。

    * **例子 (针对 `@property`):**
        ```css
        @property --my-size {
          syntax: <length>; /* 缺少引号 */
          inherits: true;
        }
        ```
        解析 `syntax` 描述符时，`css_parsing_utils::ConsumeString` 会期望一个带引号的字符串，但这里没有，导致解析失败。

3. **提供无效的值:**  为描述符提供了不符合其类型或规范的值。
    * **例子 (针对 `@font-face`):**
        ```css
        @font-face {
          font-weight: very-very-bold; /* 无效的 font-weight 值 */
          src: url("/bold.woff");
        }
        ```
        `css_parsing_utils::ConsumeFontWeight` 会尝试将 "very-very-bold" 解析为有效的 `font-weight` 值，但会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **浏览器遇到 `<style>` 标签或链接的 CSS 文件。**
4. **浏览器启动 CSS 解析器。**
5. **CSS 解析器逐个解析 CSS 规则。**
6. **当解析器遇到 `@font-face`, `@property`, 或 `@view-transition` 规则时，会识别出这是一个 at-rule。**
7. **解析器会查找与该 at-rule 相关的描述符解析逻辑，即 `AtRuleDescriptorParser` 类中的相应函数 (例如 `ParseFontFaceDescriptor`, `ParseAtPropertyDescriptor`, `ParseAtViewTransitionDescriptor`)。**
8. **这些函数会进一步调用辅助函数 (例如 `ConsumeFontVariantList`, `ConsumeFontFaceSrc`, `ConsumeDescriptor` 等) 来解析具体的描述符及其值。**
9. **如果解析过程中遇到错误 (例如上述的拼写错误、语法错误、无效值)，解析器会报告错误或忽略该规则/描述符，这可能会影响页面的渲染效果。**

**调试线索:**

当开发者遇到与 CSS at-rule 相关的渲染问题时，可以按照以下步骤进行调试，并可能最终查看此文件：

1. **检查浏览器的开发者工具 (Elements 面板 -> Styles 标签):** 查看样式是否被正确应用，是否有 CSS 解析错误或警告。
2. **检查 Network 面板:** 确认字体文件或其他资源是否加载成功。
3. **使用 "Sources" 或 "Debugger" 面板:**  如果怀疑是 JavaScript 动态修改样式导致的问题，可以在 JavaScript 代码中设置断点，观察样式变化的过程。
4. **如果错误信息指向 CSS 解析问题:** 开发者可能会想了解 Blink 引擎是如何解析 CSS 的，这时就可能需要查看相关的源代码文件，例如 `at_rule_descriptor_parser.cc`，来理解具体的解析逻辑和错误处理机制。
5. **阅读 `at_rule_descriptor_parser.cc` 的代码:** 开发者可以了解各种描述符的解析方式，以及可能导致解析失败的条件，从而帮助定位 CSS 代码中的问题。
6. **在 Chromium 源码中搜索相关的错误信息或函数名:**  开发者可以搜索例如 `ConsumeFontFaceSrcSkipToComma` 等函数，来追踪解析过程中的具体步骤。

总而言之，`at_rule_descriptor_parser.cc` 在 Chromium Blink 引擎中扮演着关键的角色，它负责将 CSS at-rule 中描述符的文本表示转换为内部数据结构，是浏览器正确理解和应用 CSS 样式的基石。理解它的功能有助于开发者更好地编写和调试 CSS 代码。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/at_rule_descriptor_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/at_rule_descriptor_parser.h"

#include "third_party/blink/renderer/core/css/css_font_face_src_value.h"
#include "third_party/blink/renderer/core/css/css_string_value.h"
#include "third_party/blink/renderer/core/css/css_syntax_string_parser.h"
#include "third_party/blink/renderer/core/css/css_unicode_range_value.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/css_unset_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_mode.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"

namespace blink {

namespace {

CSSValue* ConsumeFontVariantList(CSSParserTokenStream& stream) {
  CSSValueList* values = CSSValueList::CreateCommaSeparated();
  do {
    if (stream.Peek().Id() == CSSValueID::kAll) {
      // FIXME: CSSPropertyParser::ParseFontVariant() implements
      // the old css3 draft:
      // http://www.w3.org/TR/2002/WD-css3-webfonts-20020802/#font-variant
      // 'all' is only allowed in @font-face and with no other values.
      if (values->length()) {
        return nullptr;
      }
      return css_parsing_utils::ConsumeIdent(stream);
    }
    CSSIdentifierValue* font_variant =
        css_parsing_utils::ConsumeFontVariantCSS21(stream);
    if (font_variant) {
      values->Append(*font_variant);
    }
  } while (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream));

  if (values->length()) {
    return values;
  }

  return nullptr;
}

CSSIdentifierValue* ConsumeFontDisplay(CSSParserTokenStream& stream) {
  return css_parsing_utils::ConsumeIdent<
      CSSValueID::kAuto, CSSValueID::kBlock, CSSValueID::kSwap,
      CSSValueID::kFallback, CSSValueID::kOptional>(stream);
}

CSSValueList* ConsumeFontFaceUnicodeRange(CSSParserTokenStream& stream) {
  CSSValueList* values = CSSValueList::CreateCommaSeparated();

  do {
    CSSParserToken token = stream.Peek();
    if (token.GetType() != kUnicodeRangeToken) {
      return nullptr;
    }
    stream.ConsumeIncludingWhitespace();  // kUnicodeRangeToken

    UChar32 start = token.UnicodeRangeStart();
    UChar32 end = token.UnicodeRangeEnd();
    if (start > end || end > 0x10FFFF) {
      return nullptr;
    }
    values->Append(
        *MakeGarbageCollected<cssvalue::CSSUnicodeRangeValue>(start, end));
  } while (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream));

  return values;
}

bool IsSupportedFontFormat(String font_format) {
  return css_parsing_utils::IsSupportedKeywordFormat(
             css_parsing_utils::FontFormatToId(font_format)) ||
         EqualIgnoringASCIICase(font_format, "woff-variations") ||
         EqualIgnoringASCIICase(font_format, "truetype-variations") ||
         EqualIgnoringASCIICase(font_format, "opentype-variations") ||
         EqualIgnoringASCIICase(font_format, "woff2-variations");
}

CSSFontFaceSrcValue::FontTechnology ValueIDToTechnology(CSSValueID valueID) {
  switch (valueID) {
    case CSSValueID::kFeaturesAat:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyFeaturesAAT;
    case CSSValueID::kFeaturesOpentype:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyFeaturesOT;
    case CSSValueID::kVariations:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyVariations;
    case CSSValueID::kPalettes:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyPalettes;
    case CSSValueID::kColorCOLRv0:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyCOLRv0;
    case CSSValueID::kColorCOLRv1:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyCOLRv1;
    case CSSValueID::kColorCBDT:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologyCDBT;
    case CSSValueID::kColorSbix:
      return CSSFontFaceSrcValue::FontTechnology::kTechnologySBIX;
    default:
      NOTREACHED();
  }
}

CSSValue* ConsumeFontFaceSrcURI(CSSParserTokenStream& stream,
                                const CSSParserContext& context) {
  cssvalue::CSSURIValue* src_value =
      css_parsing_utils::ConsumeUrl(stream, context);
  if (!src_value) {
    return nullptr;
  }
  auto* uri_value =
      CSSFontFaceSrcValue::Create(src_value, context.JavascriptWorld());

  // After the url() it's either the end of the src: line, or a comma
  // for the next url() or format().
  if (!stream.AtEnd() &&
      stream.Peek().GetType() != CSSParserTokenType::kCommaToken &&
      (stream.Peek().GetType() != CSSParserTokenType::kFunctionToken ||
       (stream.Peek().FunctionId() != CSSValueID::kFormat &&
        stream.Peek().FunctionId() != CSSValueID::kTech))) {
    return nullptr;
  }

  if (stream.Peek().FunctionId() == CSSValueID::kFormat) {
    {
      CSSParserTokenStream::BlockGuard guard(stream);
      stream.ConsumeWhitespace();
      CSSParserTokenType peek_type = stream.Peek().GetType();
      if (peek_type != kIdentToken && peek_type != kStringToken) {
        return nullptr;
      }

      String sanitized_format;

      if (peek_type == kIdentToken) {
        CSSIdentifierValue* font_format =
            css_parsing_utils::ConsumeFontFormatIdent(stream);
        if (!font_format) {
          return nullptr;
        }
        sanitized_format = font_format->CssText();
      }

      if (peek_type == kStringToken) {
        sanitized_format = css_parsing_utils::ConsumeString(stream)->Value();
      }

      if (IsSupportedFontFormat(sanitized_format)) {
        uri_value->SetFormat(sanitized_format);
      } else {
        return nullptr;
      }

      stream.ConsumeWhitespace();

      // After one argument to the format function, there shouldn't be anything
      // else, for example not a comma.
      if (!stream.AtEnd()) {
        return nullptr;
      }
    }
    stream.ConsumeWhitespace();
  }

  if (stream.Peek().FunctionId() == CSSValueID::kTech) {
    {
      CSSParserTokenStream::BlockGuard guard(stream);
      stream.ConsumeWhitespace();

      // One or more tech args expected.
      if (stream.AtEnd()) {
        return nullptr;
      }

      do {
        CSSIdentifierValue* technology_value =
            css_parsing_utils::ConsumeFontTechIdent(stream);
        if (!technology_value) {
          return nullptr;
        }
        if (!stream.AtEnd() &&
            stream.Peek().GetType() != CSSParserTokenType::kCommaToken) {
          return nullptr;
        }
        if (css_parsing_utils::IsSupportedKeywordTech(
                technology_value->GetValueID())) {
          uri_value->AppendTechnology(
              ValueIDToTechnology(technology_value->GetValueID()));
        } else {
          return nullptr;
        }
      } while (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream));
    }
    stream.ConsumeWhitespace();
  }

  return uri_value;
}

CSSValue* ConsumeFontFaceSrcLocal(CSSParserTokenStream& stream,
                                  const CSSParserContext& context) {
  CSSParserTokenStream::BlockGuard guard(stream);
  stream.ConsumeWhitespace();
  if (stream.Peek().GetType() == kStringToken) {
    const CSSParserToken& arg = stream.ConsumeIncludingWhitespace();
    if (!stream.AtEnd()) {
      return nullptr;
    }
    return CSSFontFaceSrcValue::CreateLocal(arg.Value().ToString());
  }
  if (stream.Peek().GetType() == kIdentToken) {
    String family_name = css_parsing_utils::ConcatenateFamilyName(stream);
    if (!stream.AtEnd()) {
      return nullptr;
    }
    if (family_name.empty()) {
      return nullptr;
    }
    return CSSFontFaceSrcValue::CreateLocal(family_name);
  }
  return nullptr;
}

CSSValue* ConsumeFontFaceSrcSkipToComma(
    CSSValue* parse_function(CSSParserTokenStream&, const CSSParserContext&),
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSValue* parse_result = parse_function(stream, context);
  stream.ConsumeWhitespace();
  if (parse_result && (stream.AtEnd() || stream.Peek().GetType() ==
                                             CSSParserTokenType::kCommaToken)) {
    return parse_result;
  }

  stream.SkipUntilPeekedTypeIs<CSSParserTokenType::kCommaToken>();
  return nullptr;
}

CSSValueList* ConsumeFontFaceSrc(CSSParserTokenStream& stream,
                                 const CSSParserContext& context) {
  CSSValueList* values = CSSValueList::CreateCommaSeparated();

  stream.ConsumeWhitespace();
  do {
    const CSSParserToken& token = stream.Peek();
    CSSValue* parsed_value = nullptr;
    if (token.FunctionId() == CSSValueID::kLocal) {
      parsed_value = ConsumeFontFaceSrcSkipToComma(ConsumeFontFaceSrcLocal,
                                                   stream, context);
    } else {
      parsed_value =
          ConsumeFontFaceSrcSkipToComma(ConsumeFontFaceSrcURI, stream, context);
    }
    if (parsed_value) {
      values->Append(*parsed_value);
    }
  } while (css_parsing_utils::ConsumeCommaIncludingWhitespace(stream));

  return values->length() ? values : nullptr;
}

CSSValue* ConsumeDescriptor(StyleRule::RuleType rule_type,
                            AtRuleDescriptorID id,
                            CSSParserTokenStream& stream,
                            const CSSParserContext& context) {
  using Parser = AtRuleDescriptorParser;

  switch (rule_type) {
    case StyleRule::kFontFace:
      return Parser::ParseFontFaceDescriptor(id, stream, context);
    case StyleRule::kFontPaletteValues:
      return Parser::ParseAtFontPaletteValuesDescriptor(id, stream, context);
    case StyleRule::kProperty:
      return Parser::ParseAtPropertyDescriptor(id, stream, context);
    case StyleRule::kCounterStyle:
      return Parser::ParseAtCounterStyleDescriptor(id, stream, context);
    case StyleRule::kViewTransition:
      return Parser::ParseAtViewTransitionDescriptor(id, stream, context);
    case StyleRule::kCharset:
    case StyleRule::kContainer:
    case StyleRule::kStyle:
    case StyleRule::kImport:
    case StyleRule::kMedia:
    case StyleRule::kPage:
    case StyleRule::kPageMargin:
    case StyleRule::kKeyframes:
    case StyleRule::kKeyframe:
    case StyleRule::kFontFeatureValues:
    case StyleRule::kFontFeature:
    case StyleRule::kLayerBlock:
    case StyleRule::kLayerStatement:
    case StyleRule::kNestedDeclarations:
    case StyleRule::kNamespace:
    case StyleRule::kScope:
    case StyleRule::kSupports:
    case StyleRule::kStartingStyle:
    case StyleRule::kFunction:
    case StyleRule::kMixin:
    case StyleRule::kApplyMixin:
    case StyleRule::kPositionTry:
      // TODO(andruud): Handle other descriptor types here.
      // Note that we can reach this path through @supports at-rule(...).
      return nullptr;
  }
}

CSSValue* ConsumeFontMetricOverride(CSSParserTokenStream& stream,
                                    const CSSParserContext& context) {
  if (CSSIdentifierValue* normal =
          css_parsing_utils::ConsumeIdent<CSSValueID::kNormal>(stream)) {
    return normal;
  }
  return css_parsing_utils::ConsumePercent(
      stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
}

}  // namespace

CSSValue* AtRuleDescriptorParser::ParseFontFaceDescriptor(
    AtRuleDescriptorID id,
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSValue* parsed_value = nullptr;
  stream.ConsumeWhitespace();
  switch (id) {
    case AtRuleDescriptorID::FontFamily:
      // In order to avoid confusion, <family-name> does not accept unquoted
      // <generic-family> keywords and general CSS keywords.
      // ConsumeGenericFamily will take care of excluding the former while the
      // ConsumeFamilyName will take care of excluding the latter.
      // See https://drafts.csswg.org/css-fonts/#family-name-syntax,
      if (css_parsing_utils::ConsumeGenericFamily(stream)) {
        return nullptr;
      }
      parsed_value = css_parsing_utils::ConsumeFamilyName(stream);
      break;
    case AtRuleDescriptorID::Src:  // This is a list of urls or local
                                   // references.
      parsed_value = ConsumeFontFaceSrc(stream, context);
      break;
    case AtRuleDescriptorID::UnicodeRange: {
      CSSParserTokenStream::EnableUnicodeRanges enable(stream, true);
      parsed_value = ConsumeFontFaceUnicodeRange(stream);
      break;
    }
    case AtRuleDescriptorID::FontDisplay:
      parsed_value = ConsumeFontDisplay(stream);
      break;
    case AtRuleDescriptorID::FontStretch: {
      CSSParserContext::ParserModeOverridingScope scope(context,
                                                        kCSSFontFaceRuleMode);
      parsed_value = css_parsing_utils::ConsumeFontStretch(stream, context);
      break;
    }
    case AtRuleDescriptorID::FontStyle: {
      CSSParserContext::ParserModeOverridingScope scope(context,
                                                        kCSSFontFaceRuleMode);
      parsed_value = css_parsing_utils::ConsumeFontStyle(stream, context);
      break;
    }
    case AtRuleDescriptorID::FontVariant:
      parsed_value = ConsumeFontVariantList(stream);
      break;
    case AtRuleDescriptorID::FontWeight: {
      CSSParserContext::ParserModeOverridingScope scope(context,
                                                        kCSSFontFaceRuleMode);
      parsed_value = css_parsing_utils::ConsumeFontWeight(stream, context);
      break;
    }
    case AtRuleDescriptorID::FontFeatureSettings:
      parsed_value =
          css_parsing_utils::ConsumeFontFeatureSettings(stream, context);
      break;
    case AtRuleDescriptorID::AscentOverride:
    case AtRuleDescriptorID::DescentOverride:
    case AtRuleDescriptorID::LineGapOverride:
      parsed_value = ConsumeFontMetricOverride(stream, context);
      break;
    case AtRuleDescriptorID::SizeAdjust:
      parsed_value = css_parsing_utils::ConsumePercent(
          stream, context, CSSPrimitiveValue::ValueRange::kNonNegative);
      break;
    default:
      break;
  }

  if (!parsed_value || !stream.AtEnd()) {
    return nullptr;
  }

  return parsed_value;
}

CSSValue* AtRuleDescriptorParser::ParseFontFaceDescriptor(
    AtRuleDescriptorID id,
    StringView string,
    const CSSParserContext& context) {
  CSSParserTokenStream stream(string);
  return ParseFontFaceDescriptor(id, stream, context);
}

CSSValue* AtRuleDescriptorParser::ParseFontFaceDeclaration(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  DCHECK_EQ(stream.Peek().GetType(), kIdentToken);
  const CSSParserToken& token = stream.ConsumeIncludingWhitespace();
  AtRuleDescriptorID id = token.ParseAsAtRuleDescriptorID();

  if (stream.Consume().GetType() != kColonToken) {
    return nullptr;  // Parse error
  }

  return ParseFontFaceDescriptor(id, stream, context);
}

CSSValue* AtRuleDescriptorParser::ParseAtPropertyDescriptor(
    AtRuleDescriptorID id,
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSValue* parsed_value = nullptr;
  switch (id) {
    case AtRuleDescriptorID::Syntax:
      stream.ConsumeWhitespace();
      parsed_value = css_parsing_utils::ConsumeString(stream);
      if (parsed_value) {
        CSSSyntaxStringParser parser(To<CSSStringValue>(parsed_value)->Value());
        if (!parser.Parse().has_value()) {
          // Treat an invalid syntax string as a parse error.
          // In particular, this means @supports at-rule() will reject
          // descriptors we do not support.
          parsed_value = nullptr;
        }
      }
      break;
    case AtRuleDescriptorID::InitialValue: {
      bool important_ignored;
      CSSVariableData* variable_data =
          CSSVariableParser::ConsumeUnparsedDeclaration(
              stream, /*allow_important_annotation=*/false,
              /*is_animation_tainted=*/false,
              /*must_contain_variable_reference=*/false,
              /*restricted_value=*/false, /*comma_ends_declaration=*/false,
              important_ignored, context);
      if (variable_data) {
        return MakeGarbageCollected<CSSUnparsedDeclarationValue>(variable_data,
                                                                 &context);
      } else {
        return nullptr;
      }
    }
    case AtRuleDescriptorID::Inherits:
      stream.ConsumeWhitespace();
      parsed_value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kTrue,
                                          CSSValueID::kFalse>(stream);
      break;
    default:
      break;
  }

  if (!parsed_value || !stream.AtEnd()) {
    stream.SkipUntilPeekedTypeIs();  // For the inspector.
    return nullptr;
  }

  return parsed_value;
}

CSSValue* AtRuleDescriptorParser::ParseAtViewTransitionDescriptor(
    AtRuleDescriptorID id,
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  CSSValue* parsed_value = nullptr;
  switch (id) {
    case AtRuleDescriptorID::Navigation:
      stream.ConsumeWhitespace();
      parsed_value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kAuto, CSSValueID::kNone>(
              stream);
      break;
    case AtRuleDescriptorID::Types: {
      CSSValueList* types = CSSValueList::CreateSpaceSeparated();
      parsed_value = types;
      while (!stream.AtEnd()) {
        stream.ConsumeWhitespace();
        if (stream.Peek().Id() == CSSValueID::kNone) {
          return nullptr;
        }
        CSSCustomIdentValue* ident =
            css_parsing_utils::ConsumeCustomIdent(stream, context);
        if (!ident || ident->Value().StartsWith("-ua-")) {
          return nullptr;
        }
        types->Append(*ident);
      }
      break;
    }
    default:
      break;
  }

  if (!parsed_value || !stream.AtEnd()) {
    return nullptr;
  }

  return parsed_value;
}

bool AtRuleDescriptorParser::ParseDescriptorValue(
    StyleRule::RuleType rule_type,
    AtRuleDescriptorID id,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    HeapVector<CSSPropertyValue, 64>& parsed_descriptors) {
  CSSValue* result = ConsumeDescriptor(rule_type, id, stream, context);

  if (!result) {
    return false;
  }
  // Convert to CSSPropertyID for legacy compatibility,
  // TODO(crbug.com/752745): Refactor CSSParserImpl to avoid using
  // the CSSPropertyID.
  CSSPropertyID equivalent_property_id = AtRuleDescriptorIDAsCSSPropertyID(id);
  parsed_descriptors.push_back(
      CSSPropertyValue(CSSPropertyName(equivalent_property_id), *result));
  context.Count(context.Mode(), equivalent_property_id);
  return true;
}

}  // namespace blink

"""

```
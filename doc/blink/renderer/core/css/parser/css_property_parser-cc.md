Response:
Let's break down the thought process to analyze the `css_property_parser.cc` file.

1. **Understand the Core Purpose:** The filename itself, `css_property_parser.cc`, strongly suggests this file is responsible for parsing CSS properties and their values. The location within the Blink rendering engine (`blink/renderer/core/css/parser`) reinforces this.

2. **Identify Key Data Structures:** Look for the main classes and data structures used within the file. The constructor `CSSPropertyParser` takes a `CSSParserTokenStream`, `CSSParserContext`, and `HeapVector<CSSPropertyValue>`. This immediately tells us:
    * **Input:**  A stream of CSS tokens (`CSSParserTokenStream`).
    * **Context:**  Information about the parsing environment (`CSSParserContext`).
    * **Output:**  A vector of parsed CSS properties and their values (`HeapVector<CSSPropertyValue>`).

3. **Analyze Key Functions:**  Examine the public and important-looking functions:
    * `ParseValue`:  This seems like the primary entry point for parsing a property value. It takes an `unresolved_property` ID, suggesting there's a resolution step. The `allow_important_annotation` parameter hints at handling `!important`.
    * `ParseSingleValue`:  Similar to `ParseValue`, but seems to handle a single value without the `!important` annotation. It's likely used in scenarios like CSSOM manipulation.
    * `ParseValueStart`:  Called by `ParseValue`, suggesting it handles the core parsing logic once initial setup is done. It deals with shorthands and longhands.
    * `ConsumeCSSWideKeyword`:  Handles keywords like `inherit`, `initial`, and `unset`.
    * `ParseCSSWideKeyword`:  Uses `ConsumeCSSWideKeyword` and adds the parsed value to the properties list.
    * `ParseFontFaceDescriptor`:  Specifically handles parsing descriptors within `@font-face` rules.
    * `UnresolvedCSSPropertyID`:  Takes a string and tries to find the corresponding `CSSPropertyID`. The "Unresolved" part suggests it might handle vendor prefixes or flags.
    * `CssValueKeywordID`:  Similar to `UnresolvedCSSPropertyID`, but for CSS value keywords.

4. **Trace the Flow (Conceptual):** Imagine the journey of a CSS property through this parser:
    * A CSS rule is tokenized (likely elsewhere).
    * `ParseValue` is called with the property name.
    * `ResolveCSSPropertyID` (mentioned but not defined in the snippet) maps the name to an internal ID.
    * `ParseValueStart` checks if it's a shorthand or longhand property.
    * If it's a shorthand, `ParseShorthand` (from the `Shorthand` class) handles it.
    * If it's a longhand, `ParseLonghand` (from `css_parsing_utils`) parses the value.
    * `ConsumeCSSWideKeyword` handles global keywords.
    * The parsed value and associated information are added to `parsed_properties_`.
    * `!important` is handled appropriately.

5. **Identify Relationships with Web Technologies:**
    * **CSS:**  The entire purpose is to parse CSS. Examples are obvious – any CSS property and value.
    * **HTML:** CSS rules are applied to HTML elements. The parsing happens when the browser processes the `<style>` tag or linked stylesheets. User interaction causing style changes (hover, focus) can trigger re-parsing in certain scenarios.
    * **JavaScript:** JavaScript can interact with CSS through the CSSOM. Methods like `element.style.setProperty()` or modifying CSS rules in a stylesheet will likely involve this parser to interpret the new values.

6. **Look for Logic and Assumptions:**
    * **Shorthand Expansion:** The code handles the expansion of shorthand properties (e.g., `margin: 10px 20px`) into individual longhand properties.
    * **`!important` Handling:** Explicit logic is present for processing the `!important` flag.
    * **CSS-Wide Keywords:** Specific handling for keywords like `inherit`, `initial`, etc.
    * **Vendor Prefixes/Flags:** The `UnresolvedCSSPropertyID` function and the concept of "ExposedProperty" hint at managing properties that might be experimental or require flags.
    * **Error Handling (Implicit):** While not explicit exception handling, the parser returns `false` or `nullptr` on failure, indicating an inability to parse.

7. **Consider User/Developer Errors:**
    * **Invalid Syntax:**  Typographical errors in CSS property names or values.
    * **Incorrect Shorthand Usage:**  Providing the wrong number or order of values for a shorthand property.
    * **Using Properties in Invalid Contexts:**  Trying to use properties that aren't allowed in specific at-rules (e.g., `animation-name` in a `@page` rule).

8. **Think About Debugging:**  How would a developer end up here during debugging?
    * **Setting Breakpoints:** A developer might set a breakpoint in `ParseValue` or `ParseValueStart` to see how a specific CSS property is being processed.
    * **Inspecting the Token Stream:**  They might want to examine the `stream_` to see the raw tokens being parsed.
    * **Tracing the Call Stack:** If a style isn't being applied as expected, they might trace the call stack back to this parser.
    * **Using DevTools:** The browser's developer tools provide insights into applied styles. When styles are not applied correctly, understanding the parsing stage can be crucial.

9. **Refine and Organize:** Structure the findings logically, grouping related points together. Use clear language and examples. Ensure all instructions in the prompt are addressed.

By following these steps, we can effectively analyze the provided code snippet and extract meaningful information about its functionality, relationships with other technologies, potential issues, and debugging scenarios.
这个 `css_property_parser.cc` 文件是 Chromium Blink 渲染引擎中负责解析 CSS 属性的关键部分。它的主要功能是将 CSS 属性名称和值从 token 流转换为内部的 CSS 对象表示。

下面是它的详细功能列表以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能：**

1. **解析 CSS 属性和值:** 这是其核心功能。它接收一个 CSS 属性名称（可能是简写属性）和一系列表示值的 token，然后尝试将其解析成对应的 `CSSValue` 对象。

2. **处理简写属性 (Shorthand Properties):**  对于像 `margin` 或 `background` 这样的简写属性，它负责将它们分解成对应的长属性（例如 `margin-top`, `margin-right` 等）。

3. **处理 `!important` 标记:**  它会识别并处理 CSS 声明中的 `!important` 标记，并将其标记在生成的 `CSSPropertyValue` 对象上。

4. **处理 CSS 变量 (Custom Properties):** 它能够解析包含 CSS 变量引用的属性值，并将它们表示为 `CSSUnparsedDeclarationValue` 或 `CSSPendingSubstitutionValue` 对象。

5. **处理 CSS 宽泛关键字 (CSS-wide keywords):**  例如 `inherit`, `initial`, `unset`, `revert` 等。

6. **处理 `@font-face` 描述符:**  专门处理 `@font-face` 规则中的描述符，例如 `font-family`, `src` 等。

7. **处理不同类型的 CSS 规则:**  根据 CSS 规则的类型（例如 `style`, `page`, `keyframe`），决定哪些属性是允许的。

8. **与 `CSSParserTokenStream` 交互:**  它从 `CSSParserTokenStream` 中读取 token，并根据 token 的类型和值进行解析。

9. **与 `CSSParserContext` 交互:**  它使用 `CSSParserContext` 提供的信息，例如当前解析模式、是否允许某些特性等。

10. **生成 `CSSPropertyValue` 对象:**  解析成功后，会将解析出的属性 ID、值、重要性等信息封装到 `CSSPropertyValue` 对象中，并添加到 `parsed_properties_` 列表中。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  `css_property_parser.cc` 直接处理 CSS 语法。它理解各种 CSS 属性和值的语法规则，例如长度单位、颜色格式、URL 等。
    * **举例:** 当解析 `color: red;` 时，它会识别 `color` 属性和 `red` 值，并将 `red` 解析为对应的颜色对象。解析 `margin: 10px 20px;` 时，它会将 `margin` 分解为 `margin-top: 10px;` 和 `margin-left: 20px;` (以及 `margin-right` 和 `margin-bottom` 默认值)。

* **HTML:**  HTML 文档中的 `<style>` 标签和 `<link>` 标签引用的 CSS 文件最终会被解析。`css_property_parser.cc` 就是解析这些 CSS 规则的一部分。
    * **举例:** 当浏览器解析以下 HTML 代码时：
      ```html
      <div style="font-size: 16px;">Hello</div>
      ```
      `css_property_parser.cc` 会负责解析 `font-size: 16px;` 这个内联样式声明。

* **JavaScript:** JavaScript 可以通过 CSSOM (CSS Object Model) 与 CSS 交互。当 JavaScript 代码修改元素的样式时，Blink 引擎可能会调用 `css_property_parser.cc` 中的函数来解析新的样式值。
    * **举例:** 当 JavaScript 代码执行 `element.style.backgroundColor = 'blue';` 时，Blink 引擎会使用 CSS 解析器（包括 `css_property_parser.cc`）来解析 `'blue'` 这个颜色值。

**逻辑推理的举例说明：**

**假设输入：**  `stream_` 中包含以下 token 流（代表 `border: 1px solid red !important;`）：
```
IDENT("border")
COLON
LENGTH_UNIT(1, "px")
IDENT("solid")
IDENT("red")
IMPORTANT_SYM
EOF
```

**输出：**  `parsed_properties_` 列表中会添加以下 `CSSPropertyValue` 对象：

* `property_id`: `CSSPropertyID::kBorderWidth`， `value`:  表示 `1px` 的 `CSSPrimitiveValue` 对象， `important`: `true`
* `property_id`: `CSSPropertyID::kBorderStyle`， `value`:  表示 `solid` 的 `CSSIdentifierValue` 对象， `important`: `true`
* `property_id`: `CSSPropertyID::kBorderColor`， `value`:  表示 `red` 的 `CSSPrimitiveValue` 对象， `important`: `true`

**用户或编程常见的使用错误举例：**

1. **拼写错误的属性名或值：**
   * **错误代码:**  `p { colr: blue; }` (属性名 `color` 拼写错误)
   * **结果:** 解析器可能无法识别 `colr` 属性，导致该样式规则被忽略或作为自定义属性处理。

2. **使用了不合法的属性值：**
   * **错误代码:** `p { font-size: abc; }` (`abc` 不是合法的字体大小值)
   * **结果:** 解析器会尝试解析，但最终可能会生成一个无效的 `CSSValue` 对象，或者使用默认值。

3. **在不允许的上下文中使用了属性：**
   * **错误代码:**  在 `@page` 规则中使用 `animation-name` 属性。
   * **结果:**  `IsPropertyAllowedInRule` 函数会阻止解析，因为 `animation-name` 不适用于 `@page` 规则。

4. **简写属性值格式错误：**
   * **错误代码:** `margin: 10px;` (缺少其他三个方向的值)
   * **结果:** 解析器会根据 CSS 规范处理，可能会为缺失的值设置默认值，但如果格式完全错误，可能导致解析失败。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户编辑 CSS 代码：** 用户在 HTML 文件中的 `<style>` 标签内，或者在外部 CSS 文件中，编写 CSS 样式规则。

2. **浏览器加载 HTML 页面或 CSS 文件：** 当浏览器加载页面或 CSS 文件时，会触发 HTML 和 CSS 解析过程。

3. **HTML 解析器识别 `<style>` 标签或 `<link>` 标签：**  HTML 解析器遇到这些标签时，会启动 CSS 解析流程。

4. **CSS 预处理器 (如果存在) 处理 CSS 代码：**  如果使用了 Sass、Less 等 CSS 预处理器，会先进行预处理，生成标准的 CSS 代码。

5. **CSS 词法分析器 (Lexer) 将 CSS 代码转换为 token 流：**  例如 `CSSParserTokenStream` 负责将 CSS 文本分解成一个个的 token，例如 `IDENT("color")`, `COLON`, `IDENT("red")` 等。

6. **CSS 语法分析器 (Parser) 使用 `css_property_parser.cc` 解析属性和值：**  语法分析器会遍历 token 流，当遇到属性名时，会调用 `CSSPropertyParser::ParseValue` 或相关函数，将后续的 token 解析为属性值。

7. **Blink 渲染引擎使用解析后的 CSS 信息进行布局和绘制：** 解析后的 `CSSPropertyValue` 对象会被用于构建渲染树，并最终影响页面的显示效果。

**调试线索:**

当开发者遇到 CSS 样式不生效或出现异常时，可能会通过以下方式追踪到 `css_property_parser.cc`：

* **使用浏览器开发者工具：**  查看 "Elements" 面板中的 "Styles" 标签，可以查看浏览器解析后的样式。如果某个样式没有生效，可能是解析阶段就出现了问题。
* **设置断点：**  在 Blink 引擎的源码中（例如 `css_property_parser.cc` 的 `ParseValue` 函数）设置断点，可以观察 CSS 属性是如何被解析的。
* **查看控制台错误信息：**  如果 CSS 语法有严重错误，浏览器控制台可能会输出相关的警告或错误信息。
* **抓取网络请求：**  查看浏览器加载的 CSS 文件内容，确保 CSS 代码本身没有问题。
* **使用 Blink 内部的调试工具：** Blink 提供了一些内部的工具和标志，可以帮助开发者更深入地了解渲染过程，包括 CSS 解析。

总而言之，`css_property_parser.cc` 是 Blink 渲染引擎中负责理解和解释 CSS 样式规则的关键组件，它连接了 CSS 文本和浏览器内部的样式表示，对网页的最终呈现至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_property_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"

#include "third_party/blink/renderer/core/css/css_pending_substitution_value.h"
#include "third_party/blink/renderer/core/css/css_unicode_range_value.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/hash_tools.h"
#include "third_party/blink/renderer/core/css/parser/at_rule_descriptor_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_mode.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/shorthand.h"
#include "third_party/blink/renderer/core/css/property_bitsets.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"

namespace blink {

using css_parsing_utils::ConsumeIdent;
using css_parsing_utils::IsImplicitProperty;
using css_parsing_utils::ParseLonghand;

class CSSIdentifierValue;

namespace {

bool IsPropertyAllowedInRule(const CSSProperty& property,
                             StyleRule::RuleType rule_type) {
  // This function should be called only when parsing a property. Shouldn't
  // reach here with a descriptor.
  DCHECK(property.IsProperty());
  switch (rule_type) {
    case StyleRule::kStyle:
    case StyleRule::kScope:
      return true;
    case StyleRule::kPage:
    case StyleRule::kPageMargin:
      // TODO(sesse): Limit the allowed properties here.
      // https://www.w3.org/TR/css-page-3/#page-property-list
      // https://www.w3.org/TR/css-page-3/#margin-property-list
      return true;
    case StyleRule::kKeyframe:
      return property.IsValidForKeyframe();
    case StyleRule::kPositionTry:
      return property.IsValidForPositionTry();
    default:
      NOTREACHED();
  }
}

}  // namespace

CSSPropertyParser::CSSPropertyParser(
    CSSParserTokenStream& stream,
    const CSSParserContext* context,
    HeapVector<CSSPropertyValue, 64>* parsed_properties)
    : stream_(stream),
      context_(context),
      parsed_properties_(parsed_properties) {
  // Strip initial whitespace/comments from stream_.
  stream_.ConsumeWhitespace();
}

bool CSSPropertyParser::ParseValue(
    CSSPropertyID unresolved_property,
    bool allow_important_annotation,
    CSSParserTokenStream& stream,
    const CSSParserContext* context,
    HeapVector<CSSPropertyValue, 64>& parsed_properties,
    StyleRule::RuleType rule_type) {
  CSSPropertyParser parser(stream, context, &parsed_properties);
  CSSPropertyID resolved_property = ResolveCSSPropertyID(unresolved_property);
  bool parse_success;
  if (rule_type == StyleRule::kFontFace) {
    parse_success = parser.ParseFontFaceDescriptor(resolved_property);
  } else {
    parse_success = parser.ParseValueStart(
        unresolved_property, allow_important_annotation, rule_type);
  }

  // This doesn't count UA style sheets
  if (parse_success) {
    context->Count(context->Mode(), unresolved_property);
  }

  return parse_success;
}

// NOTE: “stream” cannot include !important; this is for setting properties
// from CSSOM or similar.
const CSSValue* CSSPropertyParser::ParseSingleValue(
    CSSPropertyID property,
    CSSParserTokenStream& stream,
    const CSSParserContext* context) {
  DCHECK(context);
  stream.ConsumeWhitespace();

  const CSSValue* value = css_parsing_utils::ConsumeCSSWideKeyword(stream);
  if (!value) {
    value = ParseLonghand(property, CSSPropertyID::kInvalid, *context, stream);
  }
  if (!value || !stream.AtEnd()) {
    return nullptr;
  }
  return value;
}

StringView StripInitialWhitespace(StringView value) {
  wtf_size_t initial_whitespace_len = 0;
  while (initial_whitespace_len < value.length() &&
         IsHTMLSpace(value[initial_whitespace_len])) {
    ++initial_whitespace_len;
  }
  return StringView(value, initial_whitespace_len);
}

bool CSSPropertyParser::ParseValueStart(CSSPropertyID unresolved_property,
                                        bool allow_important_annotation,
                                        StyleRule::RuleType rule_type) {
  if (ParseCSSWideKeyword(unresolved_property, rule_type)) {
    return true;
  }

  CSSParserTokenStream::State savepoint = stream_.Save();

  CSSPropertyID property_id = ResolveCSSPropertyID(unresolved_property);
  const CSSProperty& property = CSSProperty::Get(property_id);
  // If a CSSPropertyID is only a known descriptor (@fontface, @property), not a
  // style property, it will not be a valid declaration.
  if (!property.IsProperty()) {
    return false;
  }
  if (!IsPropertyAllowedInRule(property, rule_type)) {
    return false;
  }
  int parsed_properties_size = parsed_properties_->size();

  bool is_shorthand = property.IsShorthand();
  DCHECK(context_);

  // NOTE: The first branch of the if here uses the tokenized form,
  // and the second uses the streaming parser. This is only allowed
  // since they start from the same place and we reset both below,
  // so they cannot go out of sync.
  if (is_shorthand) {
    const auto local_context =
        CSSParserLocalContext()
            .WithAliasParsing(IsPropertyAlias(unresolved_property))
            .WithCurrentShorthand(property_id);
    // Variable references will fail to parse here and will fall out to the
    // variable ref parser below.
    //
    // NOTE: We call ParseShorthand() with important=false, since we don't know
    // yet whether we have !important or not. We'll change the flag for all
    // added properties below (ParseShorthand() makes its own calls to
    // AddProperty(), since there may be more than one of them).
    if (To<Shorthand>(property).ParseShorthand(
            /*important=*/false, stream_, *context_, local_context,
            *parsed_properties_)) {
      bool important = css_parsing_utils::MaybeConsumeImportant(
          stream_, allow_important_annotation);
      if (stream_.AtEnd()) {
        if (important) {
          for (wtf_size_t property_idx = parsed_properties_size;
               property_idx < parsed_properties_->size(); ++property_idx) {
            (*parsed_properties_)[property_idx].SetImportant();
          }
        }
        return true;
      }
    }

    // Remove any properties that may have been added by ParseShorthand()
    // during a failing parse earlier.
    parsed_properties_->Shrink(parsed_properties_size);
  } else {
    if (const CSSValue* parsed_value = ParseLonghand(
            unresolved_property, CSSPropertyID::kInvalid, *context_, stream_)) {
      bool important = css_parsing_utils::MaybeConsumeImportant(
          stream_, allow_important_annotation);
      if (stream_.AtEnd()) {
        AddProperty(property_id, CSSPropertyID::kInvalid, *parsed_value,
                    important, IsImplicitProperty::kNotImplicit,
                    *parsed_properties_);
        return true;
      }
    }
  }

  // We did not parse properly without variable substitution,
  // so rewind the stream, and see if parsing it as something
  // containing variables will help.
  //
  // Note that if so, this needs the original text, so we need to take
  // note of the original offsets so that we can see what we tokenized.
  stream_.EnsureLookAhead();
  stream_.Restore(savepoint);

  bool important = false;
  CSSVariableData* variable_data =
      CSSVariableParser::ConsumeUnparsedDeclaration(
          stream_,
          /*allow_important_annotation=*/true,
          /*is_animation_tainted=*/false,
          /*must_contain_variable_reference=*/true,
          /*restricted_value=*/true, /*comma_ends_declaration=*/false,
          important, *context_);
  if (!variable_data) {
    return false;
  }

  auto* variable = MakeGarbageCollected<CSSUnparsedDeclarationValue>(
      variable_data, context_);
  if (is_shorthand) {
    const cssvalue::CSSPendingSubstitutionValue& pending_value =
        *MakeGarbageCollected<cssvalue::CSSPendingSubstitutionValue>(
            property_id, variable);
    css_parsing_utils::AddExpandedPropertyForValue(
        property_id, pending_value, important, *parsed_properties_);
  } else {
    AddProperty(property_id, CSSPropertyID::kInvalid, *variable, important,
                IsImplicitProperty::kNotImplicit, *parsed_properties_);
  }
  return true;
}

static inline bool IsExposedInMode(const ExecutionContext* execution_context,
                                   const CSSUnresolvedProperty& property,
                                   CSSParserMode mode) {
  return mode == kUASheetMode ? property.IsUAExposed(execution_context)
                              : property.IsWebExposed(execution_context);
}

// Take the given string, lowercase it (with possible caveats;
// see comments on the LChar version), convert it to ASCII and store it into
// the buffer together with a zero terminator. The string and zero terminator
// is assumed to fit.
//
// Returns false if the string is outside the allowed range of ASCII, so that
// it could never match any CSS properties or values.
static inline bool QuasiLowercaseIntoBuffer(const UChar* src,
                                            unsigned length,
                                            char* dst) {
  for (unsigned i = 0; i < length; ++i) {
    UChar c = src[i];
    if (c == 0 || c >= 0x7F) {  // illegal character
      return false;
    }
    dst[i] = ToASCIILower(c);
  }
  dst[length] = '\0';
  return true;
}

// Fast-path version for LChar strings. This uses the fact that all
// CSS properties and values are restricted to [a-zA-Z0-9-]. Crucially,
// this means we can do whatever we want to the six characters @[\]^_,
// because they cannot match any known values anyway. We use this to
// get a faster lowercasing than ToASCIILower() (which uses a table)
// can give us; we take anything in the range [0x40, 0x7f] and just
// set the 0x20 bit. This converts A-Z to a-z and messes up @[\]^_
// (so that they become `{|}~<DEL>, respectively). Things outside this
// range, such as 0-9 and -, are unchanged.
//
// This version never returns false, since the [0x80, 0xff] range
// won't match anything anyway (it is really only needed for UChar,
// since otherwise we could have e.g. U+0161 be downcasted to 0x61).
static inline bool QuasiLowercaseIntoBuffer(const LChar* src,
                                            unsigned length,
                                            char* dst) {
  unsigned i;
  for (i = 0; i < (length & ~3); i += 4) {
    uint32_t x;
    memcpy(&x, src + i, sizeof(x));
    x |= (x & 0x40404040) >> 1;
    memcpy(dst + i, &x, sizeof(x));
  }
  for (; i < length; ++i) {
    LChar c = src[i];
    dst[i] = c | ((c & 0x40) >> 1);
  }
  dst[length] = '\0';
  return true;
}

// The "exposed" property is different from the incoming property in the
// following cases:
//
//  - The property has an alternative property [1] which is enabled. Note that
//    alternative properties also can have alternative properties.
//  - The property is not enabled. This is represented by
//    CSSPropertyID::kInvalid.
//
// [1] See documentation near "alternative_of" in css_properties.json5.
static CSSPropertyID ExposedProperty(CSSPropertyID property_id,
                                     const ExecutionContext* execution_context,
                                     CSSParserMode mode) {
  const CSSUnresolvedProperty& property =
      CSSUnresolvedProperty::Get(property_id);
  CSSPropertyID alternative_id = property.GetAlternative();
  if (alternative_id != CSSPropertyID::kInvalid) {
    if (CSSPropertyID exposed_id =
            ExposedProperty(alternative_id, execution_context, mode);
        exposed_id != CSSPropertyID::kInvalid) {
      return exposed_id;
    }
  }
  return IsExposedInMode(execution_context, property, mode)
             ? property_id
             : CSSPropertyID::kInvalid;
}

template <typename CharacterType>
static CSSPropertyID UnresolvedCSSPropertyID(
    const ExecutionContext* execution_context,
    const CharacterType* property_name,
    unsigned length,
    CSSParserMode mode) {
  if (length == 0) {
    return CSSPropertyID::kInvalid;
  }
  if (length >= 3 && property_name[0] == '-' && property_name[1] == '-') {
    return CSSPropertyID::kVariable;
  }
  if (length > kMaxCSSPropertyNameLength) {
    return CSSPropertyID::kInvalid;
  }

  char buffer[kMaxCSSPropertyNameLength + 1];  // 1 for null character
  if (!QuasiLowercaseIntoBuffer(property_name, length, buffer)) {
    return CSSPropertyID::kInvalid;
  }

  const char* name = buffer;
  const Property* hash_table_entry = FindProperty(name, length);
#if DCHECK_IS_ON()
  // Verify that we get the same answer with standard lowercasing.
  for (unsigned i = 0; i < length; ++i) {
    buffer[i] = ToASCIILower(property_name[i]);
  }
  DCHECK_EQ(hash_table_entry, FindProperty(buffer, length));
#endif
  if (!hash_table_entry) {
    return CSSPropertyID::kInvalid;
  }

  CSSPropertyID property_id = static_cast<CSSPropertyID>(hash_table_entry->id);
  if (kKnownExposedProperties.Has(property_id)) {
    DCHECK_EQ(property_id,
              ExposedProperty(property_id, execution_context, mode));
    return property_id;
  }

  // The property is behind a runtime flag, so we need to go ahead
  // and actually do the resolution to see if that flag is on or not.
  // This should happen only occasionally.
  return ExposedProperty(property_id, execution_context, mode);
}

CSSPropertyID UnresolvedCSSPropertyID(const ExecutionContext* execution_context,
                                      StringView string,
                                      CSSParserMode mode) {
  return WTF::VisitCharacters(string, [&](auto chars) {
    return UnresolvedCSSPropertyID(execution_context, chars.data(),
                                   chars.size(), mode);
  });
}

template <typename CharacterType>
static CSSValueID CssValueKeywordID(const CharacterType* value_keyword,
                                    unsigned length) {
  char buffer[kMaxCSSValueKeywordLength + 1];  // 1 for null character
  if (!QuasiLowercaseIntoBuffer(value_keyword, length, buffer)) {
    return CSSValueID::kInvalid;
  }

  const Value* hash_table_entry = FindValue(buffer, length);
#if DCHECK_IS_ON()
  // Verify that we get the same answer with standard lowercasing.
  for (unsigned i = 0; i < length; ++i) {
    buffer[i] = ToASCIILower(value_keyword[i]);
  }
  DCHECK_EQ(hash_table_entry, FindValue(buffer, length));
#endif
  return hash_table_entry ? static_cast<CSSValueID>(hash_table_entry->id)
                          : CSSValueID::kInvalid;
}

CSSValueID CssValueKeywordID(StringView string) {
  unsigned length = string.length();
  if (!length) {
    return CSSValueID::kInvalid;
  }
  if (length > kMaxCSSValueKeywordLength) {
    return CSSValueID::kInvalid;
  }

  return string.Is8Bit() ? CssValueKeywordID(string.Characters8(), length)
                         : CssValueKeywordID(string.Characters16(), length);
}

const CSSValue* CSSPropertyParser::ConsumeCSSWideKeyword(
    CSSParserTokenStream& stream,
    bool allow_important_annotation,
    bool& important) {
  CSSParserTokenStream::State savepoint = stream.Save();

  const CSSValue* value = css_parsing_utils::ConsumeCSSWideKeyword(stream);
  if (!value) {
    // No need to Restore(), we are at the right spot anyway.
    // (We do this instead of relying on CSSParserTokenStream's
    // Restore() optimization, as this path is so hot.)
    return nullptr;
  }

  important = css_parsing_utils::MaybeConsumeImportant(
      stream, allow_important_annotation);
  if (!stream.AtEnd()) {
    stream.Restore(savepoint);
    return nullptr;
  }

  return value;
}

bool CSSPropertyParser::ParseCSSWideKeyword(CSSPropertyID unresolved_property,
                                            bool allow_important_annotation) {
  bool important;
  const CSSValue* value =
      ConsumeCSSWideKeyword(stream_, allow_important_annotation, important);
  if (!value) {
    return false;
  }

  CSSPropertyID property = ResolveCSSPropertyID(unresolved_property);
  const StylePropertyShorthand& shorthand = shorthandForProperty(property);
  if (!shorthand.length()) {
    if (!CSSProperty::Get(property).IsProperty()) {
      return false;
    }
    AddProperty(property, CSSPropertyID::kInvalid, *value, important,
                IsImplicitProperty::kNotImplicit, *parsed_properties_);
  } else {
    css_parsing_utils::AddExpandedPropertyForValue(property, *value, important,
                                                   *parsed_properties_);
  }
  return true;
}

bool CSSPropertyParser::ParseFontFaceDescriptor(
    CSSPropertyID resolved_property) {
  // TODO(meade): This function should eventually take an AtRuleDescriptorID.
  const AtRuleDescriptorID id =
      CSSPropertyIDAsAtRuleDescriptor(resolved_property);
  if (id == AtRuleDescriptorID::Invalid) {
    return false;
  }

  CSSValue* parsed_value =
      AtRuleDescriptorParser::ParseFontFaceDescriptor(id, stream_, *context_);
  if (!parsed_value) {
    return false;
  }

  AddProperty(resolved_property,
              CSSPropertyID::kInvalid /* current_shorthand */, *parsed_value,
              false /* important */, IsImplicitProperty::kNotImplicit,
              *parsed_properties_);
  return true;
}

}  // namespace blink
```
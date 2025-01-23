Response:
My thought process for summarizing the provided code snippet went something like this:

1. **Understand the Goal:** The request asks for a summary of the `CSSParserImpl.cc` file's functionality, specifically highlighting its relationship to HTML, CSS, and JavaScript, its logic, potential user errors, and debugging information. Crucially, it states this is *part 1 of 4*, implying a need for a high-level overview rather than delving into intricate details of every function.

2. **Initial Scan for Keywords and Core Concepts:** I quickly scanned the included headers and the code itself for recurring themes. Keywords like `parser`, `CSS`, `rule`, `token`, `stream`, `declaration`, `selector`, `stylesheet`, and the various `@` rules (e.g., `@keyframes`, `@media`) immediately stood out. This suggests the file is central to the process of understanding and interpreting CSS.

3. **Identify the Central Class:** The name of the file, `CSSParserImpl`, and the frequent use of this class throughout the code strongly indicate it's the core component. The constructor and various methods associated with this class are where the main logic resides.

4. **Map High-Level Functionality to Code Sections:** I then tried to mentally map the core concepts to the different parts of the code. For example:
    * **Parsing values:**  The `ParseValue` and `ParseVariableValue` functions clearly handle the interpretation of individual CSS property values.
    * **Parsing declarations:** Functions like `ParseInlineStyleDeclaration` and `ParseDeclarationList` deal with collections of property-value pairs.
    * **Parsing rules:** `ParseRule` and `ConsumeAtRule` handle the interpretation of complete CSS rules (selectors and declarations).
    * **Parsing stylesheets:** `ParseStyleSheet` is the entry point for processing entire CSS files or blocks of CSS.
    * **Tokenization:**  While not directly implemented in this file, the inclusion of `css_tokenizer.h` and the use of `CSSParserTokenStream` indicate a dependency on a separate tokenization process.

5. **Focus on the "Why":**  I didn't just want to list function names. I aimed to understand the *purpose* of these functions within the larger context of a browser rendering engine. Why does Blink need to parse CSS?  To style HTML elements, to understand animations, to handle different media queries, etc.

6. **Address the Specific Request Points:** I reviewed the initial request and made sure to touch upon each point:
    * **Functionality:**  Described the core purpose of parsing CSS and related tasks.
    * **Relationship to HTML, CSS, JavaScript:** Explained how this file is directly involved in applying CSS styles to HTML elements. While not directly interacting with JavaScript *in this file*, I noted that the parsed styles are used by JavaScript for animations and other dynamic effects.
    * **Logic and Examples:**  Used the examples provided in the code (like parsing inline styles) to illustrate the parsing process.
    * **User/Programming Errors:**  Mentioned common CSS syntax errors and how the parser might handle them (or where errors could lead to unexpected behavior).
    * **Debugging Clues:** Highlighted how the parsing process is triggered by loading stylesheets or encountering inline styles, and that this file would be a key point for investigating styling issues.

7. **Structure and Clarity:** I organized the summary into logical sections with clear headings. I used concise language and avoided overly technical jargon where possible.

8. **Address the "Part 1" Constraint:** Because this is stated to be "Part 1," I intentionally kept the summary at a high level. I avoided getting bogged down in the implementation details of specific parsing functions, knowing that later parts might delve into those areas. The goal was to establish the fundamental role of this file.

9. **Refinement:** I reviewed the summary to ensure accuracy and completeness, making minor adjustments for clarity and flow. For example, I explicitly mentioned the role of the `CSSParserContext`.

Essentially, I adopted a top-down approach, starting with the overall goal of the file and then gradually zooming in on key functionalities while keeping the specific constraints of the request in mind. The goal was to provide a comprehensive yet concise overview suitable for the first part of a multi-part analysis.
```
这是目录为blink/renderer/core/css/parser/css_parser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

根据提供的代码片段（第一部分），我们可以归纳出 `blink/renderer/core/css/parser/css_parser_impl.cc` 文件的主要功能是：**实现 CSS 语法解析的核心逻辑。**  它负责将 CSS 字符串解析成 Blink 引擎能够理解和使用的内部数据结构，例如 `CSSStyleSheet`、`StyleRule` 和 `CSSPropertyValueSet` 等。

更具体地说，从第一部分的代码中可以提取出以下更细致的功能点：

**核心解析功能:**

* **解析 CSS 值 (ParseValue, ParseVariableValue):**  将 CSS 属性的值字符串解析成 `CSSPropertyValue` 对象。这包括处理各种 CSS 数据类型，如数字、颜色、字符串、URL 等。
* **解析内联样式 (ParseInlineStyleDeclaration):**  解析 HTML 元素的 `style` 属性中的 CSS 声明。
* **解析声明列表 (ParseDeclarationList):**  解析一组 CSS 属性和值的声明，通常在一个规则块 `{}` 内部。
* **解析嵌套声明规则 (ParseNestedDeclarationsRule):** 处理 CSS 嵌套规则中的声明块。
* **解析完整的 CSS 规则 (ParseRule):**  解析包括选择器和声明块的完整 CSS 规则。
* **解析 CSS 样式表 (ParseStyleSheet):**  解析完整的 CSS 样式表字符串，包括 `@import`、 `@media` 等各种 at-rule 和普通的样式规则。
* **解析 `@page` 选择器 (ParsePageSelector):**  解析 `@page` at-rule 中使用的选择器。
* **解析 `@keyframes` 关键帧列表 (ParseKeyframeKeyList):**  解析 `@keyframes` 规则中的关键帧偏移量列表。
* **解析自定义属性名 (ParseCustomPropertyName):**  验证并提取 CSS 自定义属性（CSS 变量）的名称。
* **解析 `@supports` 声明 (ConsumeSupportsDeclaration):**  解析 `@supports` at-rule 中的声明，用于条件判断。
* **为开发者工具提供解析能力 (ParseDeclarationListForInspector, ParseStyleSheetForInspector):**  为 Chrome 开发者工具提供解析 CSS 的接口，以便进行调试和检查。
* **为延迟样式解析声明列表 (ParseDeclarationListForLazyStyle):**  支持延迟解析 CSS 属性，提高初始加载性能。
* **管理规则列表 (ConsumeRuleList):**  处理各种类型的 CSS 规则列表，例如顶级规则列表、普通规则列表、关键帧规则列表等。
* **处理 At-Rules (ConsumeAtRule, ConsumeEndOfPreludeForAtRuleWithBlock, ConsumeEndOfPreludeForAtRuleWithoutBlock, ConsumeErroneousAtRule):**  解析各种 CSS At-Rules，例如 `@media`、`@keyframes`、`@import` 等，并处理它们的语法结构和错误情况。

**与 HTML、CSS、JavaScript 的关系举例:**

* **HTML:** 当浏览器加载 HTML 页面时，遇到 `<style>` 标签或外部 CSS 文件链接 (`<link rel="stylesheet">`)，或者解析 HTML 元素的 `style` 属性时，会调用 `CSSParserImpl` 来解析 CSS 代码。
    * **例子:**  HTML 中有 `<div style="color: red; font-size: 16px;">Hello</div>`，`CSSParserImpl::ParseInlineStyleDeclaration` 会被调用来解析 `"color: red; font-size: 16px;"` 这个字符串。
* **CSS:**  `CSSParserImpl` 的核心功能就是解析 CSS 语法。它负责理解 CSS 的各种语法结构，例如选择器、属性、值、规则、At-Rules 等。
    * **例子:**  CSS 文件中有规则 `.container { width: 100%; }`，`CSSParserImpl::ParseStyleSheet` 会解析这个字符串，创建对应的 `StyleRule` 对象，其中包含选择器 `.container` 和属性 `width` 的值 `100%`。
* **JavaScript:** 虽然这个文件本身不直接包含 JavaScript 代码，但 JavaScript 可以通过 DOM API 操作 CSS 样式，例如修改元素的 `style` 属性，或者动态创建和修改 `<style>` 标签。当 JavaScript 修改 CSS 时，Blink 引擎可能会再次调用 `CSSParserImpl` 来解析新的 CSS 字符串。  此外，JavaScript 可以通过 CSSOM (CSS Object Model) 访问和操作已经解析的 CSS 对象，这些对象是 `CSSParserImpl` 创建的。
    * **例子:**  JavaScript 代码 `document.getElementById('myDiv').style.backgroundColor = 'blue';`  可能会导致引擎内部重新解析 `style` 属性，并可能涉及到 `CSSParserImpl`。

**逻辑推理的假设输入与输出:**

假设输入一个简单的 CSS 规则字符串：

```css
.my-class { color: blue; }
```

`CSSParserImpl::ParseRule` 函数（或其内部调用的其他函数）会接收这个字符串作为输入。

**可能的内部处理步骤 (简化):**

1. **词法分析 (Tokenization):**  将字符串分解成一个个 Token，例如 `.my-class` (IdentToken), `{` (DelimToken), `color` (IdentToken), `:` (DelimToken), `blue` (IdentToken), `;` (DelimToken), `}` (DelimToken)。
2. **语法分析:** 根据 CSS 的语法规则，将这些 Token 组织成有意义的结构。
3. **对象创建:**  创建对应的 Blink 内部对象，例如：
    * `CSSSelector` 对象表示 `.my-class` 选择器。
    * `CSSPropertyValue` 对象表示 `color: blue;` 这个声明。
    * `StyleRule` 对象将选择器和声明关联起来。

**可能的输出:**

一个 `StyleRule` 对象的指针，该对象包含：

* 一个 `CSSSelectorList`，其中包含一个 `CSSSelector` 对象，其值为 `.my-class`。
* 一个 `CSSPropertyValueSet`，其中包含一个 `CSSPropertyValue` 对象，表示 `color` 属性的值为 `blue`。

**用户或编程常见的使用错误举例:**

* **拼写错误:** 用户在 CSS 中将 `color` 拼写成 `colr`，`CSSParserImpl` 会尝试解析，但可能无法识别该属性，导致样式不生效或被忽略。
    * **调试线索:**  开发者工具的 Elements 面板可能会显示该属性为无效属性。
* **语法错误:**  用户忘记在 CSS 声明末尾添加分号 `;`，例如 `.my-class { color: blue }`。`CSSParserImpl` 在解析时可能会遇到错误，导致该规则或后续规则无法正确解析。
    * **调试线索:** 开发者工具的 Console 面板可能会显示 CSS 解析错误。
* **使用了浏览器不支持的 CSS 特性:** 用户使用了最新的 CSS 特性，但浏览器版本过低不支持，`CSSParserImpl` 可能无法正确解析该特性。
    * **调试线索:** 开发者工具可能会警告使用了未知属性或值。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **当解析器遇到 `<style>` 标签或 `<link>` 标签指向的 CSS 文件时。**
4. **或者当解析器遇到带有 `style` 属性的 HTML 元素时。**
5. **Blink 引擎会获取 CSS 代码字符串。**
6. **Blink 引擎创建 `CSSParserImpl` 的实例。**
7. **根据 CSS 代码的来源（内联、外部文件），调用 `CSSParserImpl` 相应的解析方法，例如 `ParseStyleSheet` 或 `ParseInlineStyleDeclaration`。**
8. **`CSSParserImpl` 内部进行词法分析和语法分析，将 CSS 字符串转换为内部数据结构。**

**归纳一下它的功能 (针对第 1 部分):**

`blink/renderer/core/css/parser/css_parser_impl.cc` 的第一部分主要定义了 `CSSParserImpl` 类及其一些核心方法，这些方法负责将 CSS 字符串片段（值、声明、规则等）解析成 Blink 引擎可以理解的内部表示。 它涵盖了基本的 CSS 语法解析功能，并提供了与 HTML 和 JavaScript 交互的基础。 这一部分为后续更复杂的 CSS 特性解析奠定了基础。  它还包含了一些辅助函数，例如用于过滤和创建 `ImmutableCSSPropertyValueSet` 的函数，以及用于处理特定 At-Rules 的初步逻辑。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"

#include <bitset>
#include <limits>
#include <memory>
#include <utility>

#include "base/cpu.h"
#include "third_party/blink/renderer/core/animation/timeline_offset.h"
#include "third_party/blink/renderer/core/core_probes_inl.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_position_try_rule.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_syntax_string_parser.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/parser/at_rule_descriptor_parser.h"
#include "third_party/blink/renderer/core/css/parser/container_query_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_at_rule_id.h"
#include "third_party/blink/renderer/core/css/parser/css_lazy_parsing_state.h"
#include "third_party/blink/renderer/core/css/parser/css_lazy_property_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_observer.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_supports_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/parser/find_length_of_declaration_list-inl.h"
#include "third_party/blink/renderer/core/css/parser/media_query_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/style_rule_counter_style.h"
#include "third_party/blink/renderer/core/css/style_rule_font_feature_values.h"
#include "third_party/blink/renderer/core/css/style_rule_font_palette_values.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_rule_keyframe.h"
#include "third_party/blink/renderer/core/css/style_rule_namespace.h"
#include "third_party/blink/renderer/core/css/style_rule_nested_declarations.h"
#include "third_party/blink/renderer/core/css/style_scope.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"

using std::swap;

namespace blink {

namespace {

// This may still consume tokens if it fails
AtomicString ConsumeStringOrURI(CSSParserTokenStream& stream) {
  const CSSParserToken& token = stream.Peek();

  if (token.GetType() == kStringToken || token.GetType() == kUrlToken) {
    return stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
  }

  if (token.GetType() != kFunctionToken ||
      !EqualIgnoringASCIICase(token.Value(), "url")) {
    return AtomicString();
  }

  AtomicString result;
  {
    CSSParserTokenStream::BlockGuard guard(stream);
    stream.ConsumeWhitespace();
    // If the block doesn't start with a quote, then the tokenizer
    // would return a kUrlToken or kBadUrlToken instead of a
    // kFunctionToken. Note also that this Peek() placates the
    // DCHECK that we Peek() before Consume().
    DCHECK(stream.Peek().GetType() == kStringToken ||
           stream.Peek().GetType() == kBadStringToken)
        << "Got unexpected token " << stream.Peek();
    const CSSParserToken& uri = stream.ConsumeIncludingWhitespace();
    if (uri.GetType() != kBadStringToken && stream.UncheckedAtEnd()) {
      DCHECK_EQ(uri.GetType(), kStringToken);
      result = uri.Value().ToAtomicString();
    }
  }
  stream.ConsumeWhitespace();
  return result;
}

// Finds the longest prefix of |stream| that matches a <layer-name> and parses
// it. Returns an empty result with |stream| unmodified if parsing fails.
StyleRuleBase::LayerName ConsumeCascadeLayerName(CSSParserTokenStream& stream) {
  CSSParserTokenStream::State savepoint = stream.Save();
  StyleRuleBase::LayerName name;
  while (!stream.AtEnd() && stream.Peek().GetType() == kIdentToken) {
    const CSSParserToken& name_part = stream.Consume();
    name.emplace_back(name_part.Value().ToString());

    // Check if we have a next part.
    if (stream.Peek().GetType() != kDelimiterToken ||
        stream.Peek().Delimiter() != '.') {
      break;
    }
    CSSParserTokenStream::State inner_savepoint = stream.Save();
    stream.Consume();
    if (stream.Peek().GetType() != kIdentToken) {
      stream.Restore(inner_savepoint);
      break;
    }
  }

  if (!name.size()) {
    stream.Restore(savepoint);
  } else {
    stream.ConsumeWhitespace();
  }

  return name;
}

StyleRule::RuleType RuleTypeForMutableDeclaration(
    MutableCSSPropertyValueSet* declaration) {
  switch (declaration->CssParserMode()) {
    case kCSSFontFaceRuleMode:
      return StyleRule::kFontFace;
    case kCSSKeyframeRuleMode:
      return StyleRule::kKeyframe;
    case kCSSPropertyRuleMode:
      return StyleRule::kProperty;
    case kCSSFontPaletteValuesRuleMode:
      return StyleRule::kFontPaletteValues;
    case kCSSPositionTryRuleMode:
      return StyleRule::kPositionTry;
    default:
      return StyleRule::kStyle;
  }
}

std::optional<StyleRuleFontFeature::FeatureType> ToStyleRuleFontFeatureType(
    CSSAtRuleID rule_id) {
  switch (rule_id) {
    case CSSAtRuleID::kCSSAtRuleStylistic:
      return StyleRuleFontFeature::FeatureType::kStylistic;
    case CSSAtRuleID::kCSSAtRuleStyleset:
      return StyleRuleFontFeature::FeatureType::kStyleset;
    case CSSAtRuleID::kCSSAtRuleCharacterVariant:
      return StyleRuleFontFeature::FeatureType::kCharacterVariant;
    case CSSAtRuleID::kCSSAtRuleSwash:
      return StyleRuleFontFeature::FeatureType::kSwash;
    case CSSAtRuleID::kCSSAtRuleOrnaments:
      return StyleRuleFontFeature::FeatureType::kOrnaments;
    case CSSAtRuleID::kCSSAtRuleAnnotation:
      return StyleRuleFontFeature::FeatureType::kAnnotation;
    default:
      NOTREACHED();
  }
}

}  // namespace

CSSParserImpl::CSSParserImpl(const CSSParserContext* context,
                             StyleSheetContents* style_sheet)
    : context_(context),
      style_sheet_(style_sheet),
      observer_(nullptr),
      lazy_state_(nullptr) {}

MutableCSSPropertyValueSet::SetResult CSSParserImpl::ParseValue(
    MutableCSSPropertyValueSet* declaration,
    CSSPropertyID unresolved_property,
    StringView string,
    bool important,
    const CSSParserContext* context) {
  STACK_UNINITIALIZED CSSParserImpl parser(context);
  StyleRule::RuleType rule_type = RuleTypeForMutableDeclaration(declaration);
  CSSParserTokenStream stream(string);
  parser.ConsumeDeclarationValue(stream, unresolved_property,
                                 /*is_in_declaration_list=*/false, rule_type);
  if (parser.parsed_properties_.empty()) {
    return MutableCSSPropertyValueSet::kParseError;
  }
  if (important) {
    for (CSSPropertyValue& property : parser.parsed_properties_) {
      property.SetImportant();
    }
  }
  return declaration->AddParsedProperties(parser.parsed_properties_);
}

MutableCSSPropertyValueSet::SetResult CSSParserImpl::ParseVariableValue(
    MutableCSSPropertyValueSet* declaration,
    const AtomicString& property_name,
    StringView value,
    bool important,
    const CSSParserContext* context,
    bool is_animation_tainted) {
  STACK_UNINITIALIZED CSSParserImpl parser(context);
  CSSParserTokenStream stream(value);
  if (!parser.ConsumeVariableValue(stream, property_name,
                                   /*allow_important_annotation=*/false,
                                   is_animation_tainted)) {
    return MutableCSSPropertyValueSet::kParseError;
  }
  if (important) {
    parser.parsed_properties_.back().SetImportant();
  }
  return declaration->AddParsedProperties(parser.parsed_properties_);
}

static inline void FilterProperties(
    bool important,
    const HeapVector<CSSPropertyValue, 64>& input,
    HeapVector<CSSPropertyValue, 64>& output,
    wtf_size_t& unused_entries,
    std::bitset<kNumCSSProperties>& seen_properties,
    HashSet<AtomicString>& seen_custom_properties) {
  // Add properties in reverse order so that highest priority definitions are
  // reached first. Duplicate definitions can then be ignored when found.
  for (wtf_size_t i = input.size(); i--;) {
    const CSSPropertyValue& property = input[i];
    if (property.IsImportant() != important) {
      continue;
    }
    if (property.Id() == CSSPropertyID::kVariable) {
      const AtomicString& name = property.CustomPropertyName();
      if (seen_custom_properties.Contains(name)) {
        continue;
      }
      seen_custom_properties.insert(name);
    } else {
      const unsigned property_id_index = GetCSSPropertyIDIndex(property.Id());
      if (seen_properties.test(property_id_index)) {
        continue;
      }
      seen_properties.set(property_id_index);
    }
    output[--unused_entries] = property;
  }
}

static ImmutableCSSPropertyValueSet* CreateCSSPropertyValueSet(
    HeapVector<CSSPropertyValue, 64>& parsed_properties,
    CSSParserMode mode,
    const Document* document) {
  if (mode != kHTMLQuirksMode &&
      (parsed_properties.size() < 2 ||
       (parsed_properties.size() == 2 &&
        parsed_properties[0].Id() != parsed_properties[1].Id()))) {
    // Fast path for the situations where we can trivially detect that there can
    // be no collision between properties, and don't need to reorder, make
    // bitsets, or similar.
    ImmutableCSSPropertyValueSet* result =
        ImmutableCSSPropertyValueSet::Create(parsed_properties, mode);
    parsed_properties.clear();
    return result;
  }

  std::bitset<kNumCSSProperties> seen_properties;
  wtf_size_t unused_entries = parsed_properties.size();
  HeapVector<CSSPropertyValue, 64> results(unused_entries);
  HashSet<AtomicString> seen_custom_properties;

  FilterProperties(true, parsed_properties, results, unused_entries,
                   seen_properties, seen_custom_properties);
  FilterProperties(false, parsed_properties, results, unused_entries,
                   seen_properties, seen_custom_properties);

  bool count_cursor_hand = false;
  if (document && mode == kHTMLQuirksMode &&
      seen_properties.test(GetCSSPropertyIDIndex(CSSPropertyID::kCursor))) {
    // See if the properties contain “cursor: hand” without also containing
    // “cursor: pointer”. This is a reasonable approximation for whether
    // removing support for the former would actually matter. (Of course,
    // we don't check whether “cursor: hand” could lose in the cascade
    // due to properties coming from other declarations, but that would be
    // much more complicated)
    bool contains_cursor_hand = false;
    bool contains_cursor_pointer = false;
    for (const CSSPropertyValue& property : parsed_properties) {
      const CSSIdentifierValue* value =
          DynamicTo<CSSIdentifierValue>(property.Value());
      if (value) {
        if (value->WasQuirky()) {
          contains_cursor_hand = true;
        } else if (value->GetValueID() == CSSValueID::kPointer) {
          contains_cursor_pointer = true;
        }
      }
    }
    if (contains_cursor_hand && !contains_cursor_pointer) {
      document->CountUse(WebFeature::kQuirksModeCursorHand);
      count_cursor_hand = true;
    }
  }

  ImmutableCSSPropertyValueSet* result = ImmutableCSSPropertyValueSet::Create(
      base::span(results).subspan(unused_entries), mode, count_cursor_hand);
  parsed_properties.clear();
  return result;
}

ImmutableCSSPropertyValueSet* CSSParserImpl::ParseInlineStyleDeclaration(
    const String& string,
    Element* element) {
  Document& document = element->GetDocument();
  auto* context = MakeGarbageCollected<CSSParserContext>(
      document.ElementSheet().Contents()->ParserContext(), &document);
  CSSParserMode mode = element->IsHTMLElement() && !document.InQuirksMode()
                           ? kHTMLStandardMode
                           : kHTMLQuirksMode;
  context->SetMode(mode);
  CSSParserImpl parser(context, document.ElementSheet().Contents());
  CSSParserTokenStream stream(string);
  parser.ConsumeBlockContents(stream, StyleRule::kStyle, CSSNestingType::kNone,
                              /*parent_rule_for_nesting=*/nullptr,
                              /*is_within_scope=*/false,
                              /*nested_declarations_start_index=*/kNotFound,
                              /*child_rules=*/nullptr);
  return CreateCSSPropertyValueSet(parser.parsed_properties_, mode, &document);
}

ImmutableCSSPropertyValueSet* CSSParserImpl::ParseInlineStyleDeclaration(
    const String& string,
    CSSParserMode parser_mode,
    SecureContextMode secure_context_mode,
    const Document* document) {
  auto* context =
      MakeGarbageCollected<CSSParserContext>(parser_mode, secure_context_mode);
  CSSParserImpl parser(context);
  CSSParserTokenStream stream(string);
  parser.ConsumeBlockContents(stream, StyleRule::kStyle, CSSNestingType::kNone,
                              /*parent_rule_for_nesting=*/nullptr,
                              /*is_within_scope=*/false,
                              /*nested_declarations_start_index=*/kNotFound,
                              /*child_rules=*/nullptr);
  return CreateCSSPropertyValueSet(parser.parsed_properties_, parser_mode,
                                   document);
}

bool CSSParserImpl::ParseDeclarationList(
    MutableCSSPropertyValueSet* declaration,
    const String& string,
    const CSSParserContext* context) {
  CSSParserImpl parser(context);
  StyleRule::RuleType rule_type = RuleTypeForMutableDeclaration(declaration);
  CSSParserTokenStream stream(string);
  // See function declaration comment for why parent_rule_for_nesting ==
  // nullptr.
  parser.ConsumeBlockContents(stream, rule_type, CSSNestingType::kNone,
                              /*parent_rule_for_nesting=*/nullptr,
                              /*is_within_scope=*/false,
                              /*nested_declarations_start_index=*/kNotFound,
                              /*child_rules=*/nullptr);
  if (parser.parsed_properties_.empty()) {
    return false;
  }

  std::bitset<kNumCSSProperties> seen_properties;
  wtf_size_t unused_entries = parser.parsed_properties_.size();
  HeapVector<CSSPropertyValue, 64> results(unused_entries);
  HashSet<AtomicString> seen_custom_properties;
  FilterProperties(true, parser.parsed_properties_, results, unused_entries,
                   seen_properties, seen_custom_properties);
  FilterProperties(false, parser.parsed_properties_, results, unused_entries,
                   seen_properties, seen_custom_properties);
  if (unused_entries) {
    results.EraseAt(0, unused_entries);
  }
  return declaration->AddParsedProperties(results);
}

StyleRuleBase* CSSParserImpl::ParseNestedDeclarationsRule(
    const CSSParserContext* context,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    StringView text) {
  CSSParserImpl parser(context);
  CSSParserTokenStream stream(text);

  HeapVector<Member<StyleRuleBase>, 4> child_rules;

  // Using nested_declarations_start_index=0u causes the leading block
  // of declarations (the only block) to be wrapped in a CSSNestedDeclarations
  // rule.
  //
  // See comment above CSSParserImpl::ConsumeBlockContents (definition)
  // for more on nested_declarations_start_index.
  parser.ConsumeBlockContents(stream, StyleRule::RuleType::kStyle, nesting_type,
                              parent_rule_for_nesting, is_within_scope,
                              /*nested_declarations_start_index=*/0u,
                              &child_rules);

  return child_rules.size() == 1u ? child_rules.back().Get() : nullptr;
}

StyleRuleBase* CSSParserImpl::ParseRule(const String& string,
                                        const CSSParserContext* context,
                                        CSSNestingType nesting_type,
                                        StyleRule* parent_rule_for_nesting,
                                        bool is_within_scope,
                                        StyleSheetContents* style_sheet,
                                        AllowedRulesType allowed_rules) {
  CSSParserImpl parser(context, style_sheet);
  CSSParserTokenStream stream(string);
  stream.ConsumeWhitespace();
  if (stream.UncheckedAtEnd()) {
    return nullptr;  // Parse error, empty rule
  }
  StyleRuleBase* rule;
  if (stream.UncheckedPeek().GetType() == kAtKeywordToken) {
    // TODO(andruud): Why does this ignore the nesting context?
    rule = parser.ConsumeAtRule(stream, allowed_rules, CSSNestingType::kNone,
                                /*parent_rule_for_nesting=*/nullptr,
                                /* is_within_scope */ false);
  } else if (allowed_rules == kPageMarginRules) {
    // Style rules are not allowed inside @page.
    rule = nullptr;
  } else {
    rule =
        parser.ConsumeQualifiedRule(stream, allowed_rules, nesting_type,
                                    parent_rule_for_nesting, is_within_scope);
  }
  if (!rule) {
    return nullptr;  // Parse error, failed to consume rule
  }
  stream.ConsumeWhitespace();
  if (!rule || !stream.UncheckedAtEnd()) {
    return nullptr;  // Parse error, trailing garbage
  }
  return rule;
}

ParseSheetResult CSSParserImpl::ParseStyleSheet(
    const String& string,
    const CSSParserContext* context,
    StyleSheetContents* style_sheet,
    CSSDeferPropertyParsing defer_property_parsing,
    bool allow_import_rules) {
  std::optional<LocalFrameUkmAggregator::ScopedUkmHierarchicalTimer> timer;
  if (context->GetDocument() && context->GetDocument()->View()) {
    if (auto* metrics_aggregator =
            context->GetDocument()->View()->GetUkmAggregator()) {
      timer.emplace(metrics_aggregator->GetScopedTimer(
          static_cast<size_t>(LocalFrameUkmAggregator::kParseStyleSheet)));
    }
  }
  TRACE_EVENT_BEGIN2("blink,blink_style", "CSSParserImpl::parseStyleSheet",
                     "baseUrl", context->BaseURL().GetString().Utf8(), "mode",
                     context->Mode());

  TRACE_EVENT_BEGIN0("blink,blink_style",
                     "CSSParserImpl::parseStyleSheet.parse");
  CSSParserTokenStream stream(string);
  CSSParserImpl parser(context, style_sheet);
  if (defer_property_parsing == CSSDeferPropertyParsing::kYes) {
    parser.lazy_state_ = MakeGarbageCollected<CSSLazyParsingState>(
        context, string, parser.style_sheet_);
  }
  ParseSheetResult result = ParseSheetResult::kSucceeded;
  bool first_rule_valid = parser.ConsumeRuleList(
      stream, kTopLevelRuleList, CSSNestingType::kNone,
      /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false,
      [&style_sheet, &result, &string, allow_import_rules, context](
          StyleRuleBase* rule, wtf_size_t offset) {
        if (rule->IsCharsetRule()) {
          return;
        }
        if (rule->IsImportRule()) {
          if (!allow_import_rules || context->IsForMarkupSanitization()) {
            result = ParseSheetResult::kHasUnallowedImportRule;
            return;
          }

          Document* document = style_sheet->AnyOwnerDocument();
          if (document) {
            TextPosition position = TextPosition::MinimumPosition();
            probe::GetTextPosition(document, offset, &string, &position);
            To<StyleRuleImport>(rule)->SetPositionHint(position);
          }
        }

        style_sheet->ParserAppendRule(rule);
      });
  style_sheet->SetHasSyntacticallyValidCSSHeader(first_rule_valid);
  TRACE_EVENT_END0("blink,blink_style", "CSSParserImpl::parseStyleSheet.parse");

  TRACE_EVENT_END2("blink,blink_style", "CSSParserImpl::parseStyleSheet",
                   "tokenCount", stream.TokenCount(), "length",
                   string.length());
  return result;
}

// static
CSSSelectorList* CSSParserImpl::ParsePageSelector(
    CSSParserTokenStream& stream,
    StyleSheetContents* style_sheet,
    const CSSParserContext& context) {
  // We only support a small subset of the css-page spec.
  stream.ConsumeWhitespace();
  AtomicString type_selector;
  if (stream.Peek().GetType() == kIdentToken) {
    type_selector = stream.Consume().Value().ToAtomicString();
  }

  AtomicString pseudo;
  if (stream.Peek().GetType() == kColonToken) {
    stream.Consume();
    if (stream.Peek().GetType() != kIdentToken) {
      return nullptr;
    }
    pseudo = stream.Consume().Value().ToAtomicString();
  }

  stream.ConsumeWhitespace();

  HeapVector<CSSSelector> selectors;
  if (!type_selector.IsNull()) {
    selectors.push_back(
        CSSSelector(QualifiedName(g_null_atom, type_selector, g_star_atom)));
  }
  if (!pseudo.IsNull()) {
    CSSSelector selector;
    selector.SetMatch(CSSSelector::kPagePseudoClass);
    selector.UpdatePseudoPage(pseudo.LowerASCII(), context.GetDocument());
    if (selector.GetPseudoType() == CSSSelector::kPseudoUnknown) {
      return nullptr;
    }
    if (selectors.size() != 0) {
      selectors[0].SetLastInComplexSelector(false);
    }
    selectors.push_back(selector);
  }
  if (selectors.empty()) {
    selectors.push_back(CSSSelector());
  }
  selectors[0].SetForPage();
  selectors.back().SetLastInComplexSelector(true);
  return CSSSelectorList::AdoptSelectorVector(
      base::span<CSSSelector>(selectors));
}

std::unique_ptr<Vector<KeyframeOffset>> CSSParserImpl::ParseKeyframeKeyList(
    const CSSParserContext* context,
    const String& key_list) {
  CSSParserTokenStream stream(key_list);
  std::unique_ptr<Vector<KeyframeOffset>> result =
      ConsumeKeyframeKeyList(context, stream);
  if (stream.AtEnd()) {
    return result;
  } else {
    return nullptr;
  }
}

String CSSParserImpl::ParseCustomPropertyName(StringView name_text) {
  CSSParserTokenStream stream(name_text);
  const CSSParserToken name_token = stream.Peek();
  if (!CSSVariableParser::IsValidVariableName(name_token)) {
    return {};
  }
  stream.ConsumeIncludingWhitespace();
  if (!stream.AtEnd()) {
    return {};
  }
  return name_token.Value().ToString();
}

bool CSSParserImpl::ConsumeSupportsDeclaration(CSSParserTokenStream& stream) {
  DCHECK(parsed_properties_.empty());
  // Even though we might use an observer here, this is just to test if we
  // successfully parse the stream, so we can temporarily remove the observer.
  CSSParserObserver* observer_copy = observer_;
  observer_ = nullptr;
  ConsumeDeclaration(stream, StyleRule::kStyle);
  observer_ = observer_copy;

  bool result = !parsed_properties_.empty();
  parsed_properties_.clear();
  return result;
}

void CSSParserImpl::ParseDeclarationListForInspector(
    const String& declaration,
    const CSSParserContext* context,
    CSSParserObserver& observer) {
  CSSParserImpl parser(context);
  parser.observer_ = &observer;
  observer.StartRuleHeader(StyleRule::kStyle, 0);
  observer.EndRuleHeader(1);
  CSSParserTokenStream stream(declaration);
  observer.StartRuleBody(stream.Offset());
  parser.ConsumeBlockContents(stream, StyleRule::kStyle, CSSNestingType::kNone,
                              /*parent_rule_for_nesting=*/nullptr,
                              /*is_within_scope=*/false,
                              /*nested_declarations_start_index=*/kNotFound,
                              /*child_rules=*/nullptr);
  observer.EndRuleBody(stream.LookAheadOffset());
}

void CSSParserImpl::ParseStyleSheetForInspector(const String& string,
                                                const CSSParserContext* context,
                                                StyleSheetContents* style_sheet,
                                                CSSParserObserver& observer) {
  CSSParserImpl parser(context, style_sheet);
  parser.observer_ = &observer;
  CSSParserTokenStream stream(string);
  bool first_rule_valid =
      parser.ConsumeRuleList(stream, kTopLevelRuleList, CSSNestingType::kNone,
                             /*parent_rule_for_nesting=*/nullptr,
                             /*is_within_scope=*/false,
                             [&style_sheet](StyleRuleBase* rule, wtf_size_t) {
                               if (rule->IsCharsetRule()) {
                                 return;
                               }
                               style_sheet->ParserAppendRule(rule);
                             });
  style_sheet->SetHasSyntacticallyValidCSSHeader(first_rule_valid);
}

CSSPropertyValueSet* CSSParserImpl::ParseDeclarationListForLazyStyle(
    const String& string,
    wtf_size_t offset,
    const CSSParserContext* context) {
  // NOTE: Lazy parsing does not support nested rules (it happens
  // only after matching, which means that we cannot insert child rules
  // we encounter during parsing -- we never match against them),
  // so parent_rule_for_nesting is always nullptr here. The parser
  // explicitly makes sure we do not invoke lazy parsing for rules
  // with child rules in them.
  CSSParserTokenStream stream(string, offset);
  CSSParserTokenStream::BlockGuard guard(stream);
  CSSParserImpl parser(context);
  parser.ConsumeBlockContents(stream, StyleRule::kStyle, CSSNestingType::kNone,
                              /*parent_rule_for_nesting=*/nullptr,
                              /*is_within_scope=*/false,
                              /*nested_declarations_start_index=*/kNotFound,
                              /*child_rules=*/nullptr);
  return CreateCSSPropertyValueSet(parser.parsed_properties_, context->Mode(),
                                   context->GetDocument());
}

static CSSParserImpl::AllowedRulesType ComputeNewAllowedRules(
    CSSParserImpl::AllowedRulesType allowed_rules,
    StyleRuleBase* rule) {
  if (!rule || allowed_rules == CSSParserImpl::kKeyframeRules ||
      allowed_rules == CSSParserImpl::kFontFeatureRules ||
      allowed_rules == CSSParserImpl::kNoRules) {
    return allowed_rules;
  }
  DCHECK_LE(allowed_rules, CSSParserImpl::kRegularRules);
  if (rule->IsCharsetRule()) {
    return CSSParserImpl::kAllowLayerStatementRules;
  }
  if (rule->IsLayerStatementRule()) {
    if (allowed_rules <= CSSParserImpl::kAllowLayerStatementRules) {
      return CSSParserImpl::kAllowLayerStatementRules;
    }
    return CSSParserImpl::kRegularRules;
  }
  if (rule->IsImportRule()) {
    return CSSParserImpl::kAllowImportRules;
  }
  if (rule->IsNamespaceRule()) {
    return CSSParserImpl::kAllowNamespaceRules;
  }
  return CSSParserImpl::kRegularRules;
}

template <typename T>
bool CSSParserImpl::ConsumeRuleList(CSSParserTokenStream& stream,
                                    RuleListType rule_list_type,
                                    CSSNestingType nesting_type,
                                    StyleRule* parent_rule_for_nesting,
                                    bool is_within_scope,
                                    const T callback) {
  AllowedRulesType allowed_rules = kRegularRules;
  switch (rule_list_type) {
    case kTopLevelRuleList:
      allowed_rules = kAllowCharsetRules;
      break;
    case kRegularRuleList:
      allowed_rules = kRegularRules;
      break;
    case kKeyframesRuleList:
      allowed_rules = kKeyframeRules;
      break;
    case kFontFeatureRuleList:
      allowed_rules = kFontFeatureRules;
      break;
    default:
      NOTREACHED();
  }

  bool seen_rule = false;
  bool first_rule_valid = false;
  while (!stream.AtEnd()) {
    wtf_size_t offset = stream.Offset();
    StyleRuleBase* rule = nullptr;
    switch (stream.UncheckedPeek().GetType()) {
      case kWhitespaceToken:
        stream.UncheckedConsume();
        continue;
      case kAtKeywordToken:
        rule = ConsumeAtRule(stream, allowed_rules, nesting_type,
                             parent_rule_for_nesting, is_within_scope);
        break;
      case kCDOToken:
      case kCDCToken:
        if (rule_list_type == kTopLevelRuleList) {
          stream.UncheckedConsume();
          continue;
        }
        [[fallthrough]];
      default:
        rule = ConsumeQualifiedRule(stream, allowed_rules, nesting_type,
                                    parent_rule_for_nesting, is_within_scope);
        break;
    }
    if (!seen_rule) {
      seen_rule = true;
      first_rule_valid = rule;
    }
    if (rule) {
      allowed_rules = ComputeNewAllowedRules(allowed_rules, rule);
      callback(rule, offset);
    }
    DCHECK_GT(stream.Offset(), offset);
  }

  return first_rule_valid;
}

// Same as ConsumeEndOfPreludeForAtRuleWithBlock() below, but for at-rules
// that don't have a block and are terminated only by semicolon.
bool CSSParserImpl::ConsumeEndOfPreludeForAtRuleWithoutBlock(
    CSSParserTokenStream& stream,
    CSSAtRuleID id) {
  stream.ConsumeWhitespace();
  if (stream.AtEnd()) {
    return true;
  }
  if (stream.UncheckedPeek().GetType() == kSemicolonToken) {
    stream.UncheckedConsume();  // kSemicolonToken
    return true;
  }

  if (observer_) {
    observer_->ObserveErroneousAtRule(stream.Offset(), id);
  }

  // Consume the erroneous block.
  ConsumeErroneousAtRule(stream, id);
  return false;  // Parse error, we expected no block.
}

// Call this after parsing the prelude of an at-rule that takes a block
// (i.e. @foo-rule <prelude> /* call here */ { ... }). It will check
// that there is no junk after the prelude, and that there is indeed
// a block starting. If either of these are false, then it will consume
// until the end of the declaration (any junk after the prelude,
// and the block if one exists), notify the observer, and return false.
bool CSSParserImpl::ConsumeEndOfPreludeForAtRuleWithBlock(
    CSSParserTokenStream& stream,
    CSSAtRuleID id) {
  stream.ConsumeWhitespace();

  if (stream.AtEnd()) {
    // Parse error, we expected a block.
    if (observer_) {
      observer_->ObserveErroneousAtRule(stream.Offset(), id);
    }
    return false;
  }
  if (stream.UncheckedPeek().GetType() == kLeftBraceToken) {
    return true;
  }

  // We have a parse error, so we need to return an error, but before that,
  // we need to consume until the end of the declaration.
  ConsumeErroneousAtRule(stream, id);
  return false;
}

void CSSParserImpl::ConsumeErroneousAtRule(CSSParserTokenStream& stream,
                                           CSSAtRuleID id) {
  if (observer_) {
    observer_->ObserveErroneousAtRule(stream.Offset(), id);
  }
  // Consume the prelude and block if present.
  stream.SkipUntilPeekedTypeIs<kLeftBraceToken, kSemicolonToken>();
  if (!stream.AtEnd()) {
    if (stream.UncheckedPeek().GetType() == kLeftBraceToken) {
      CSSParserTokenStream::BlockGuard guard(stream);
    } else {
      stream.UncheckedConsume();  // kSemicolonToken
    }
  }
}

StyleRuleBase* CSSParserImpl::ConsumeAtRule(CSSParserTokenStream& stream,
                                            AllowedRulesType allowed_rules,
                                            CSSNestingType nesting_type,
                                            StyleRule* parent_rule_for_nesting,
                                            bool is_within_scope) {
  DCHECK_EQ(stream.Peek().GetType(), kAtKeywordToken);
  CSSParserToken name_token =
      stream.ConsumeIncludingWhitespace();  // Must live until CssAtRuleID().
  const StringView name = name_token.Value();
  const CSSAtRuleID id = CssAtRule
```
Response:
Let's break down the thought process for analyzing the `css_supports_parser.cc` file.

1. **Understand the Goal:** The core task is to explain the functionality of this file within the Chromium Blink rendering engine, particularly how it relates to CSS, HTML, and JavaScript. We also need to cover logical reasoning, potential errors, and debugging.

2. **Initial Scan and Keywords:**  Read through the code, looking for prominent keywords and patterns. Immediately, `@supports`, `not`, `and`, `or`, `selector`, `font-format`, `font-tech`, `at-rule`, `declaration`, `general-enclosed` stand out. These point towards the file's role in parsing CSS `@supports` at-rules.

3. **Identify the Main Functionality:** The function names like `ConsumeSupportsCondition`, `ConsumeSupportsInParens`, `ConsumeSupportsFeature`, etc., clearly indicate a parsing process. The file's name itself, `css_supports_parser.cc`, confirms this. The goal is to parse the conditions within a `@supports` rule.

4. **Deconstruct the Grammar:** The comments in the code directly present the grammar for `<supports-condition>`, `<supports-in-parens>`, and `<supports-feature>`. This is a crucial piece of information. We can use this to understand the structure the parser is expecting.

5. **Relate to CSS:**  The `@supports` rule is a CSS feature that allows conditional application of styles based on browser support for certain CSS features. This is the fundamental connection to CSS. The different types of features being checked (selectors, font formats, font technologies, at-rules, declarations) solidify this connection.

6. **Consider HTML and JavaScript:**
    * **HTML:**  The `@supports` rule is used *within* CSS stylesheets. These stylesheets are linked to or embedded in HTML documents. The browser parses the HTML, finds the CSS, and then uses this parser to interpret the `@supports` rules. This establishes the HTML connection.
    * **JavaScript:** While this file is C++, it's part of the rendering engine that JavaScript interacts with. JavaScript can dynamically modify styles, and the browser needs to re-evaluate `@supports` conditions when this happens. Also, the results of `@supports` can influence JavaScript behavior (though this file itself doesn't directly execute JS).

7. **Logical Reasoning and Examples:** For each part of the grammar, think of concrete examples.
    * `not (display: grid)`: Tests if grid layout is *not* supported.
    * `(display: flex) and (pointer: fine)`: Tests for support of both flexbox and fine pointers.
    * `selector(.my-element:hover)`: Checks if the `:hover` pseudo-class works on the `.my-element` selector.
    * `@supports (display: grid)`: A common usage in CSS.

8. **User/Programming Errors:**  Think about common mistakes when writing `@supports` rules:
    * Incorrect syntax (`suppoorts`, missing parentheses).
    * Logical errors (using `and` when `or` is intended).
    * Referring to non-existent features (though the parser might not catch *all* of these).

9. **Debugging Walkthrough:**  Imagine how a developer might end up looking at this code:
    * They encounter a problem with `@supports` not working as expected.
    * They might use browser developer tools to inspect the computed styles and see that a rule within `@supports` isn't being applied.
    * This leads them to suspect an issue with the parsing of the `@supports` condition.
    * They might search the Chromium source code for "supports parser" or "CSSSupportsParser" and land on this file.

10. **Structure the Explanation:**  Organize the information logically:
    * Start with the main function.
    * Explain the core concepts (parsing `@supports`).
    * Detail the relationships with HTML, CSS, and JavaScript.
    * Provide concrete examples.
    * Discuss potential errors.
    * Outline a debugging scenario.

11. **Refine and Elaborate:** Go back through the explanation and add details and clarity. For instance, explicitly mentioning the role of `CSSParserTokenStream` and `CSSParserImpl`. Explain the `Result` enum (`kSupported`, `kUnsupported`, `kParseFailure`).

12. **Review and Self-Critique:** Read the explanation as if you were someone else trying to understand the file. Is anything unclear? Are there any missing pieces?  For example, initially, I might have focused too much on the individual parsing functions and not enough on the overall purpose of `@supports`. I'd then go back and add more context. Also, ensuring the examples are diverse and cover different aspects of the functionality.

By following these steps, you can systematically analyze a source code file and produce a comprehensive explanation like the example provided in the prompt. The key is to move from a high-level understanding to the specific details, always connecting back to the bigger picture of how the code fits within the browser engine.
这个文件 `blink/renderer/core/css/parser/css_supports_parser.cc` 的主要功能是**解析 CSS `@supports` at-规则中的条件表达式**。它负责判断浏览器是否支持特定的 CSS 特性，从而决定是否应用 `@supports` 块内的 CSS 规则。

更具体地说，这个文件实现了以下功能：

1. **解析 `@supports` 条件语法:**  该文件实现了 CSS Conditional Rules Module Level 4 规范中定义的 `<supports-condition>` 语法，包括：
    * 使用 `not` 关键字否定条件。
    * 使用 `and` 关键字组合多个条件，要求所有条件都成立。
    * 使用 `or` 关键字组合多个条件，要求至少一个条件成立。
    * 使用括号 `()` 来组织和嵌套条件。

2. **解析不同的支持特性 (supports-feature):** `@supports` 可以检查多种类型的特性支持情况，该文件实现了对以下几种特性的解析：
    * **`<supports-decl>` (声明支持):** 检查浏览器是否支持特定的 CSS 属性及其值，例如 `(display: flex)`。
    * **`<supports-selector-fn>` (选择器支持):** 使用 `selector()` 函数检查浏览器是否支持特定的 CSS 选择器，例如 `selector(.my-element:hover)`。
    * **`<supports-font-tech-fn>` (字体技术支持):** 使用 `font-tech()` 函数检查浏览器是否支持特定的字体技术，例如 `font-tech(color-font-v1)`。
    * **`<supports-font-format-fn>` (字体格式支持):** 使用 `font-format()` 函数检查浏览器是否支持特定的字体格式，例如 `font-format(woff2)`。
    * **`<supports-at-rule-fn>` (at-规则支持):** 使用 `at-rule()` 函数检查浏览器是否支持特定的 at-规则，例如 `@supports at-rule(@container)`。
    * **`<general-enclosed>` (通用包含):** 允许包含任意的 token 序列，但总是评估为不支持 (unsupported)。
    * **`<blink-feature-fn>` (Blink 特性支持):** 这是一个 Chromium Blink 特有的扩展，允许检查特定的 Blink 运行时特性是否启用。

3. **与 CSS 解析器集成:** 该文件与 `CSSParserImpl` 类紧密集成，后者是 Blink 中主要的 CSS 解析器。`CSSSupportsParser` 接收来自 `CSSParserImpl` 的 token 流，并根据 `@supports` 语法进行解析。

4. **返回解析结果:** 解析器返回一个 `Result` 枚举值，表示条件是否被支持 (`kSupported`)、不支持 (`kUnsupported`) 或解析失败 (`kParseFailure`)。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  `css_supports_parser.cc` 直接处理 CSS 语法中的 `@supports` 规则。它的目的是确定浏览器是否理解并支持 `@supports` 中指定的 CSS 特性。
    * **举例:**
        ```css
        @supports (display: grid) {
          .container {
            display: grid;
          }
        }
        ```
        在这个例子中，`css_supports_parser.cc` 会解析 `(display: grid)` 这个条件，判断浏览器是否支持 `display: grid` 属性。如果支持，则应用 `.container` 的 `display: grid` 样式。

* **HTML:** `@supports` 规则被包含在 CSS 样式表中，而 CSS 样式表会被嵌入到 HTML 文档中（通过 `<style>` 标签）或通过 `<link>` 标签链接到 HTML 文档。浏览器在解析 HTML 时会加载和解析 CSS，`css_supports_parser.cc` 在这个过程中发挥作用。
    * **用户操作到达这里:** 用户在浏览器中打开一个包含使用 `@supports` 规则的 CSS 的 HTML 页面时，Blink 渲染引擎会解析 CSS，并调用 `css_supports_parser.cc` 来评估 `@supports` 的条件。

* **JavaScript:**  虽然这个文件本身是 C++ 代码，但 JavaScript 可以通过 DOM API 操作 CSS 样式。当 JavaScript 修改样式时，浏览器可能需要重新评估 `@supports` 规则，以确保样式的正确应用。此外，JavaScript 可以使用 `CSS.supports()` 方法来查询浏览器对特定 CSS 特性的支持情况，这个方法的实现背后也可能涉及到类似的解析逻辑。
    * **举例:**
        ```javascript
        if (CSS.supports('display', 'grid')) {
          console.log('浏览器支持 Grid Layout');
        } else {
          console.log('浏览器不支持 Grid Layout');
        }
        ```
        `CSS.supports()` 方法的实现会间接地涉及到对 CSS 特性的判断，这与 `css_supports_parser.cc` 的功能相关。

**逻辑推理、假设输入与输出：**

假设输入是一个 CSS token 流，代表 `@supports` 规则中的条件表达式。

* **假设输入 1:**  token 流表示 `(display: flex)`
    * **输出:** `Result::kSupported` (如果浏览器支持 `display: flex`) 或 `Result::kUnsupported` (如果不支持)。

* **假设输入 2:** token 流表示 `not (transform: rotate(45deg))`
    * **输出:** `Result::kSupported` (如果浏览器 *不* 支持 `transform: rotate(45deg)`) 或 `Result::kUnsupported` (如果支持)。

* **假设输入 3:** token 流表示 `(display: grid) and (pointer: fine)`
    * **输出:** `Result::kSupported` (如果浏览器同时支持 `display: grid` 和 `pointer: fine` 媒体查询特性) 或 `Result::kUnsupported` (如果至少有一个不支持)。

* **假设输入 4:** token 流表示 `selector(.my-element:hover)`
    * **输出:** `Result::kSupported` (如果浏览器支持 `:hover` 伪类用于 `.my-element` 选择器) 或 `Result::kUnsupported`。

* **假设输入 5:** token 流表示 `(invalid property)`
    * **输出:** `Result::kParseFailure` (因为 "invalid property" 不是一个有效的 CSS 声明)。

**用户或编程常见的使用错误：**

1. **拼写错误或语法错误:** 用户在编写 `@supports` 规则时可能会出现拼写错误（例如 `suppoorts` 而不是 `supports`）或语法错误（例如缺少括号）。这些错误会导致解析失败。
    * **举例:**
        ```css
        @suppoorts (display: grid) { /* 拼写错误 */
          /* ... */
        }

        @supports display: grid { /* 缺少括号 */
          /* ... */
        }
        ```
        `css_supports_parser.cc` 会尝试解析这些输入，但由于语法不正确，最终会返回 `kParseFailure`。

2. **逻辑错误:** 用户可能会错误地使用 `and` 和 `or` 组合条件，导致与预期不符的结果。
    * **举例:**  假设用户想在支持 Grid 或 Flexbox 的浏览器上应用样式，但错误地使用了 `and`：
        ```css
        @supports (display: grid) and (display: flex) { /* 逻辑错误，不可能同时支持两种 display 模式 */
          /* ... */
        }
        ```
        `css_supports_parser.cc` 会分别评估 `(display: grid)` 和 `(display: flex)`，然后根据 `and` 的逻辑返回结果，可能导致样式没有按预期应用。

3. **检查不存在或不兼容的特性:** 用户可能会尝试检查实际上不存在或浏览器不支持的 CSS 特性。
    * **举例:**
        ```css
        @supports (non-existent-property: value) {
          /* ... */
        }
        ```
        `css_supports_parser.cc` 会评估该声明，并由于属性无效而返回 `kUnsupported`。

**用户操作如何一步步到达这里，作为调试线索：**

假设开发者发现某个使用了 `@supports` 规则的样式没有在特定的浏览器上生效。以下是可能的调试步骤，最终可能会引导他们查看 `css_supports_parser.cc`：

1. **开发者编写 HTML 和 CSS:**  开发者创建了一个包含 `@supports` 规则的 CSS 文件，并将其链接到 HTML 文件。
2. **用户在浏览器中打开页面:** 用户使用浏览器访问该 HTML 页面。
3. **浏览器加载和解析 HTML:** 浏览器开始解析 HTML 文档。
4. **浏览器发现 CSS 链接或 `<style>` 标签:** 浏览器找到需要加载的 CSS 文件或嵌入的 CSS 代码。
5. **浏览器开始解析 CSS:** Blink 渲染引擎的 CSS 解析器 (`CSSParserImpl`) 开始解析 CSS 代码。
6. **CSS 解析器遇到 `@supports` 规则:** 当解析器遇到 `@supports` 关键字时，它会识别这是一个条件规则。
7. **调用 `CSSSupportsParser::ConsumeSupportsCondition`:**  `CSSParserImpl` 会调用 `css_supports_parser.cc` 中的 `ConsumeSupportsCondition` 函数，并将 `@supports` 规则中的条件表达式的 token 流传递给它。
8. **`CSSSupportsParser` 解析条件:** `css_supports_parser.cc` 中的代码会根据定义的语法规则，逐个 token 地解析条件表达式，例如检查 `not`、`and`、`or` 关键字，以及括号。
9. **评估特性支持:** 对于 `<supports-decl>`、`<supports-selector-fn>` 等，`CSSSupportsParser` 会调用相应的子函数来检查浏览器是否支持指定的特性。这可能涉及到查询浏览器内部的特性支持信息。
10. **返回解析结果:** `CSSSupportsParser` 返回 `Result::kSupported` 或 `Result::kUnsupported` 或 `Result::kParseFailure` 给 `CSSParserImpl`。
11. **根据结果应用或忽略样式:** `CSSParserImpl` 根据 `css_supports_parser.cc` 返回的结果，决定是否应用 `@supports` 块内的样式规则。
12. **开发者检查样式:** 如果样式没有按预期生效，开发者可能会使用浏览器开发者工具检查元素的计算样式，发现 `@supports` 块内的样式没有被应用。
13. **怀疑 `@supports` 规则解析问题:** 开发者可能会怀疑是 `@supports` 规则的解析出现了问题。
14. **查看浏览器控制台或日志:**  浏览器可能会在控制台中输出 CSS 解析错误或警告信息。
15. **搜索浏览器引擎源码:** 如果开发者需要深入了解，可能会搜索 Chromium 的源代码，查找与 `@supports` 解析相关的代码，从而找到 `blink/renderer/core/css/parser/css_supports_parser.cc` 文件。
16. **阅读和调试代码:** 开发者可以阅读 `css_supports_parser.cc` 的代码，理解其解析逻辑，并尝试通过添加日志或断点来调试解析过程，找出问题所在。例如，他们可能会检查 token 流的内容，或者查看 `ConsumeSupportsDecl` 等函数的返回值，以确定哪个环节出了问题。

总而言之，`css_supports_parser.cc` 在浏览器解析 CSS 样式表时扮演着关键角色，它负责理解 `@supports` 规则中的条件，并告知浏览器是否应该应用相应的样式，从而实现了 CSS 的条件加载特性。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_supports_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_supports_parser.h"

#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/parser/at_rule_descriptor_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

using css_parsing_utils::AtIdent;
using css_parsing_utils::ConsumeAnyValue;
using css_parsing_utils::ConsumeIfIdent;

CSSSupportsParser::Result CSSSupportsParser::ConsumeSupportsCondition(
    CSSParserTokenStream& stream,
    CSSParserImpl& parser) {
  stream.ConsumeWhitespace();
  CSSSupportsParser supports_parser(parser);
  return supports_parser.ConsumeSupportsCondition(stream);
}

//
// Every non-static Consume function should:
//
//  1. Assume that the calling function already consumed whitespace.
//  2. Clean up trailing whitespace if a supported condition was consumed.
//  3. Otherwise, leave the stream untouched.
//

// <supports-condition> = not <supports-in-parens>
//                   | <supports-in-parens> [ and <supports-in-parens> ]*
//                   | <supports-in-parens> [ or <supports-in-parens> ]*
CSSSupportsParser::Result CSSSupportsParser::ConsumeSupportsCondition(
    CSSParserTokenStream& stream) {
  // not <supports-in-parens>
  if (ConsumeIfIdent(stream, "not")) {
    return !ConsumeSupportsInParens(stream);
  }

  // <supports-in-parens> [ and <supports-in-parens> ]*
  // | <supports-in-parens> [ or <supports-in-parens> ]*
  Result result = ConsumeSupportsInParens(stream);

  if (AtIdent(stream.Peek(), "and")) {
    while (ConsumeIfIdent(stream, "and")) {
      result = result & ConsumeSupportsInParens(stream);
    }
  } else if (AtIdent(stream.Peek(), "or")) {
    while (ConsumeIfIdent(stream, "or")) {
      result = result | ConsumeSupportsInParens(stream);
    }
  }

  return result;
}

// <supports-in-parens> = ( <supports-condition> )
//                    | <supports-feature>
//                    | <general-enclosed>
CSSSupportsParser::Result CSSSupportsParser::ConsumeSupportsInParens(
    CSSParserTokenStream& stream) {
  // ( <supports-condition> )
  if (stream.Peek().GetType() == kLeftParenthesisToken) {
    CSSParserTokenStream::RestoringBlockGuard guard(stream);
    stream.ConsumeWhitespace();
    Result result = ConsumeSupportsCondition(stream);
    if (result == Result::kSupported && guard.Release()) {
      stream.ConsumeWhitespace();
      return result;
    }
    // Otherwise, fall through.
    //
    // Note that even when the result is kParseFailure, we still want to fall
    // through here, in case it's valid as <general-enclosed>. If it's not,
    // we'll gain back the kParseFailure at the end of this function.
  }

  // <supports-feature>
  if (ConsumeSupportsFeature(stream)) {
    return Result::kSupported;
  }

  // <general-enclosed>
  if (ConsumeGeneralEnclosed(stream)) {
    // <general-enclosed> evaluates to kUnsupported, even when parsed
    // successfully.
    return Result::kUnsupported;
  }

  return Result::kParseFailure;
}

// https://drafts.csswg.org/css-conditional-4/#at-supports-ext
// <supports-feature> = <supports-selector-fn> | <supports-font-tech-fn>
//                    | <supports-font-format-fn> | <supports-at-rule-fn>
//                    | <supports-decl>
//
// <supports-at-rule-fn> is currently only documented here:
// https://github.com/w3c/csswg-drafts/issues/2463#issuecomment-1016720310
bool CSSSupportsParser::ConsumeSupportsFeature(CSSParserTokenStream& stream) {
  // <supports-selector-fn>
  if (ConsumeSupportsSelectorFn(stream)) {
    return true;
  }
  // <supports-font-tech-fn>
  if (ConsumeFontTechFn(stream)) {
    return true;
  }
  // <supports-font-format-fn>
  if (ConsumeFontFormatFn(stream)) {
    return true;
  }
  // <supports-at-rule-fn>
  if (ConsumeAtRuleFn(stream)) {
    return true;
  }
  if (parser_.GetMode() == CSSParserMode::kUASheetMode) {
    if (ConsumeBlinkFeatureFn(stream)) {
      return true;
    }
  }
  // <supports-decl>
  return ConsumeSupportsDecl(stream);
}

// <supports-selector-fn> = selector( <complex-selector> )
bool CSSSupportsParser::ConsumeSupportsSelectorFn(
    CSSParserTokenStream& stream) {
  if (stream.Peek().FunctionId() != CSSValueID::kSelector) {
    return false;
  }
  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();

  if (CSSSelectorParser::SupportsComplexSelector(stream,
                                                 parser_.GetContext()) &&
      guard.Release()) {
    stream.ConsumeWhitespace();
    return true;
  }
  return false;
}

bool CSSSupportsParser::ConsumeFontFormatFn(CSSParserTokenStream& stream) {
  if (stream.Peek().FunctionId() != CSSValueID::kFontFormat) {
    return false;
  }
  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();

  CSSIdentifierValue* consumed_value =
      css_parsing_utils::ConsumeFontFormatIdent(stream);

  if (consumed_value &&
      css_parsing_utils::IsSupportedKeywordFormat(
          consumed_value->GetValueID()) &&
      guard.Release()) {
    stream.ConsumeWhitespace();
    return true;
  }

  return false;
}

bool CSSSupportsParser::ConsumeFontTechFn(CSSParserTokenStream& stream) {
  if (stream.Peek().FunctionId() != CSSValueID::kFontTech) {
    return false;
  }
  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();

  CSSIdentifierValue* consumed_value =
      css_parsing_utils::ConsumeFontTechIdent(stream);

  if (consumed_value &&
      css_parsing_utils::IsSupportedKeywordTech(consumed_value->GetValueID()) &&
      guard.Release()) {
    stream.ConsumeWhitespace();
    return true;
  }

  return false;
}

// <supports-at-rule-fn> = at-rule( <at-rule> [ ; <descriptor> : <value> ]? )
bool CSSSupportsParser::ConsumeAtRuleFn(CSSParserTokenStream& stream) {
  if (!RuntimeEnabledFeatures::CSSSupportsAtRuleFunctionEnabled()) {
    return false;
  }

  if (stream.Peek().FunctionId() != CSSValueID::kAtRule) {
    return false;
  }
  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();

  if (stream.Peek().GetType() != kAtKeywordToken) {
    return false;
  }
  CSSParserToken name_token = stream.ConsumeIncludingWhitespace();
  const StringView name = name_token.Value();
  const CSSAtRuleID at_rule_id = CssAtRuleID(name);
  if (at_rule_id == CSSAtRuleID::kCSSAtRuleInvalid) {
    return false;
  }

  if (stream.AtEnd()) {
    return guard.Release();
  }

  StyleRule::RuleType rule_type;
  switch (at_rule_id) {
    case CSSAtRuleID::kCSSAtRuleInvalid:
      NOTREACHED();
    case CSSAtRuleID::kCSSAtRuleViewTransition:
      rule_type = StyleRule::kViewTransition;
      break;
    case CSSAtRuleID::kCSSAtRuleContainer:
      rule_type = StyleRule::kContainer;
      break;
    case CSSAtRuleID::kCSSAtRuleMedia:
      rule_type = StyleRule::kMedia;
      break;
    case CSSAtRuleID::kCSSAtRuleSupports:
      rule_type = StyleRule::kSupports;
      break;
    case CSSAtRuleID::kCSSAtRuleStartingStyle:
      rule_type = StyleRule::kStartingStyle;
      break;
    case CSSAtRuleID::kCSSAtRuleFontFace:
      rule_type = StyleRule::kFontFace;
      break;
    case CSSAtRuleID::kCSSAtRuleFontPaletteValues:
      rule_type = StyleRule::kFontPaletteValues;
      break;
    case CSSAtRuleID::kCSSAtRuleFontFeatureValues:
      rule_type = StyleRule::kFontFeatureValues;
      break;
    case CSSAtRuleID::kCSSAtRuleWebkitKeyframes:
    case CSSAtRuleID::kCSSAtRuleKeyframes:
      rule_type = StyleRule::kKeyframes;
      break;
    case CSSAtRuleID::kCSSAtRuleLayer:
      rule_type = StyleRule::kLayerBlock;
      break;
    case CSSAtRuleID::kCSSAtRulePage:
      rule_type = StyleRule::kPage;
      break;
    case CSSAtRuleID::kCSSAtRuleProperty:
      rule_type = StyleRule::kProperty;
      break;
    case CSSAtRuleID::kCSSAtRuleScope:
      rule_type = StyleRule::kScope;
      break;
    case CSSAtRuleID::kCSSAtRuleCounterStyle:
      rule_type = StyleRule::kCounterStyle;
      break;
    case CSSAtRuleID::kCSSAtRuleFunction:
      rule_type = StyleRule::kFunction;
      break;
    case CSSAtRuleID::kCSSAtRuleMixin:
      rule_type = StyleRule::kMixin;
      break;
    case CSSAtRuleID::kCSSAtRuleApplyMixin:
      rule_type = StyleRule::kApplyMixin;
      break;
    case CSSAtRuleID::kCSSAtRulePositionTry:
      rule_type = StyleRule::kPositionTry;
      break;
    case CSSAtRuleID::kCSSAtRuleCharset:
      rule_type = StyleRule::kCharset;
      break;
    case CSSAtRuleID::kCSSAtRuleImport:
      rule_type = StyleRule::kImport;
      break;
    case CSSAtRuleID::kCSSAtRuleNamespace:
      rule_type = StyleRule::kNamespace;
      break;
    case CSSAtRuleID::kCSSAtRuleStylistic:
    case CSSAtRuleID::kCSSAtRuleStyleset:
    case CSSAtRuleID::kCSSAtRuleCharacterVariant:
    case CSSAtRuleID::kCSSAtRuleSwash:
    case CSSAtRuleID::kCSSAtRuleOrnaments:
    case CSSAtRuleID::kCSSAtRuleAnnotation:
      rule_type = StyleRule::kFontFeature;
      break;
    case CSSAtRuleID::kCSSAtRuleTopLeftCorner:
    case CSSAtRuleID::kCSSAtRuleTopLeft:
    case CSSAtRuleID::kCSSAtRuleTopCenter:
    case CSSAtRuleID::kCSSAtRuleTopRight:
    case CSSAtRuleID::kCSSAtRuleTopRightCorner:
    case CSSAtRuleID::kCSSAtRuleBottomLeftCorner:
    case CSSAtRuleID::kCSSAtRuleBottomLeft:
    case CSSAtRuleID::kCSSAtRuleBottomCenter:
    case CSSAtRuleID::kCSSAtRuleBottomRight:
    case CSSAtRuleID::kCSSAtRuleBottomRightCorner:
    case CSSAtRuleID::kCSSAtRuleLeftTop:
    case CSSAtRuleID::kCSSAtRuleLeftMiddle:
    case CSSAtRuleID::kCSSAtRuleLeftBottom:
    case CSSAtRuleID::kCSSAtRuleRightTop:
    case CSSAtRuleID::kCSSAtRuleRightMiddle:
    case CSSAtRuleID::kCSSAtRuleRightBottom:
      rule_type = StyleRule::kPageMargin;
      break;
  };

  // Parse an optional descriptor.
  if (stream.Peek().GetType() != kSemicolonToken) {
    return false;
  }
  stream.ConsumeIncludingWhitespace();

  // The descriptor ID.
  if (stream.Peek().GetType() != kIdentToken) {
    return false;
  }
  AtRuleDescriptorID descriptor_id = stream.Peek().ParseAsAtRuleDescriptorID();
  if (descriptor_id == AtRuleDescriptorID::Invalid) {
    return false;
  }
  stream.ConsumeIncludingWhitespace();

  // Colon.
  if (stream.Peek().GetType() != kColonToken) {
    return false;
  }
  stream.ConsumeIncludingWhitespace();

  // The descriptor value.
  HeapVector<CSSPropertyValue, 64> parsed_descriptors;
  bool ok = AtRuleDescriptorParser::ParseDescriptorValue(
      rule_type, descriptor_id, stream, *parser_.GetContext(),
      parsed_descriptors);

  return ok && guard.Release();
}

// <supports-decl> = ( <declaration> )
bool CSSSupportsParser::ConsumeSupportsDecl(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kLeftParenthesisToken) {
    return false;
  }
  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();

  if (stream.Peek().GetType() == kIdentToken &&
      parser_.ConsumeSupportsDeclaration(stream) && guard.Release()) {
    stream.ConsumeWhitespace();
    return true;
  }
  return false;
}

// <general-enclosed> = [ <function-token> <any-value>? ) ]
//                  | ( <any-value>? )
bool CSSSupportsParser::ConsumeGeneralEnclosed(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kLeftParenthesisToken &&
      stream.Peek().GetType() != kFunctionToken) {
    return false;
  }

  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  ConsumeAnyValue(stream);
  if (guard.Release()) {
    stream.ConsumeWhitespace();
    return true;
  }
  return false;
}

bool CSSSupportsParser::ConsumeBlinkFeatureFn(CSSParserTokenStream& stream) {
  if (stream.Peek().FunctionId() != CSSValueID::kBlinkFeature) {
    return false;
  }
  CSSParserTokenStream::RestoringBlockGuard guard(stream);
  stream.ConsumeWhitespace();

  if (stream.Peek().GetType() == kIdentToken) {
    const CSSParserToken& feature_name = stream.ConsumeIncludingWhitespace();
    if (RuntimeEnabledFeatures::IsFeatureEnabledFromString(
            feature_name.Value().Utf8()) &&
        guard.Release()) {
      stream.ConsumeWhitespace();
      return true;
    }
  }
  return false;
}

}  // namespace blink

"""

```
Response:
Let's break down the thought process for analyzing the `media_query_parser.cc` file.

1. **Understand the Core Purpose:** The file name and the initial `#include` statements strongly suggest this file is responsible for parsing CSS media queries. Keywords like "parser," "media query," "CSS," and specific media feature names reinforce this.

2. **Identify Key Data Structures:** Look for class definitions and prominent data structures. The presence of `MediaQuerySet`, `MediaQuery`, `MediaQueryExpNode`, and `MediaQueryParser` itself are crucial. These hint at how the parser organizes and represents the parsed media query information. The `FeatureSet` abstract class suggests a mechanism for defining allowed media features.

3. **Trace the Parsing Process (High-Level):**  Start with the public entry points. `ParseMediaQuerySet` and `ParseMediaCondition` are likely how external code triggers the parsing. Notice they create a `MediaQueryParser` instance. The `ParseImpl` method seems to be the core logic.

4. **Examine the Parsing Logic (Mid-Level):**  Within `ParseImpl`, observe the flow. It seems to handle comma-separated media queries in a `MediaQuerySet`. The `ConsumeQuery` function appears to parse a single media query. The branching logic within `ConsumeQuery` (trying type-based and condition-based parsing) is important.

5. **Dive into Specific Parsing Components (Low-Level):** Focus on functions that parse specific parts of a media query, such as:
    * `ConsumeRestrictor`: Parses `not`, `only`.
    * `ConsumeType`: Parses the media type (e.g., `screen`, `print`).
    * `ConsumeCondition`: Parses the logical conditions (using `and`, `or`, `not`).
    * `ConsumeInParens`: Handles expressions within parentheses.
    * `ConsumeFeature`: Parses individual media features and their values (this is complex!).

6. **Analyze `ConsumeFeature` in Detail:** This is a complex function, indicating it handles the diverse syntax of media features. Notice the multiple attempts to parse different forms (`<mf-boolean>`, `<mf-plain>`, `<mf-range>`). The use of `stream.Save()` and `stream.Restore()` indicates backtracking during parsing, which is common in handling ambiguous grammars. Pay attention to how it handles range comparisons (`<`, `>`, `<=`, `>=`).

7. **Understand the `FeatureSet` Role:**  The `MediaQueryFeatureSet` class and the `IsAllowed` and `IsAllowedWithoutValue` methods are essential for enforcing the allowed set of media features and their syntax. This is critical for correctness and security.

8. **Connect to Web Technologies:** Consider how the parsed media queries relate to HTML, CSS, and JavaScript.
    * **HTML:** The `<link>` tag with `media` attribute is the most direct link.
    * **CSS:** `@media` rules are the primary way media queries are used in stylesheets.
    * **JavaScript:**  `window.matchMedia()` allows JavaScript to evaluate media queries.

9. **Identify Potential Errors:** Think about what could go wrong during parsing or what mistakes developers might make. Invalid feature names, incorrect syntax, missing values, or using unsupported features are common issues.

10. **Construct Examples:**  Create concrete examples to illustrate the functionality and potential errors. This helps solidify understanding and provides test cases.

11. **Consider the Debugging Perspective:** How does this parser fit into the larger browser debugging process? When a media query doesn't work as expected, the parser is one of the first places to investigate. Knowing the parsing steps can help pinpoint where the issue lies.

12. **Refine and Organize:** Structure the analysis logically, starting with the overall purpose and drilling down into details. Use clear language and provide specific code references where relevant.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Maybe this parser directly manipulates the DOM.
* **Correction:**  Closer inspection reveals it primarily focuses on *parsing* the string representation of media queries. The *evaluation* of these queries against the current environment is likely handled elsewhere in the Blink engine.

* **Initial thought:** The `FeatureSet` might be dynamically loaded.
* **Correction:** The current code shows a concrete `MediaQueryFeatureSet` class, implying a fixed set of allowed features (although this could be extended in other parts of the codebase).

* **Realization:** The complexity of `ConsumeFeature` highlights the flexibility (and potential ambiguity) of the media query syntax.

By following these steps and continually refining the understanding based on the code, one can arrive at a comprehensive analysis of the `media_query_parser.cc` file.
这个文件 `blink/renderer/core/css/parser/media_query_parser.cc` 是 Chromium Blink 渲染引擎中的一个关键组件，专门负责**解析 CSS 媒体查询 (Media Queries)**。它的主要功能是将表示媒体查询的字符串转换为 Blink 内部可以理解和使用的结构化数据。

以下是该文件的详细功能列表：

**核心功能：解析 CSS 媒体查询字符串**

* **将字符串转换为结构化数据:**  它接收一个表示媒体查询的字符串作为输入，并将其解析成一个 `MediaQuerySet` 对象。`MediaQuerySet` 包含一个或多个 `MediaQuery` 对象，每个 `MediaQuery` 对象代表一个独立的媒体查询。
* **处理不同的媒体查询语法:**  该解析器能够理解并处理 CSS 媒体查询的各种语法，包括：
    * **媒体类型 (Media Types):** 例如 `screen`, `print`, `all`。
    * **媒体特性 (Media Features):** 例如 `width`, `height`, `orientation`, `color`,  以及带 `min-` 或 `max-` 前缀的特性 (如 `min-width`)。
    * **逻辑运算符 (Logical Operators):**  `and`, `or`, `not`, `only`.
    * **比较运算符 (Comparison Operators):** `<`, `>`, `=`, `<=`, `>=`。
    * **范围上下文 (Range Context):**  支持像 `(100px < width < 200px)` 这样的范围表示。
    * **通用封闭 (General Enclosed):** 处理括号内的任意值，用于扩展媒体查询的灵活性，尽管其语义可能不在标准媒体查询中。
* **处理逗号分隔的多个媒体查询:**  能够解析包含多个以逗号分隔的媒体查询的字符串。
* **处理 `not` 和 `only` 限制符:**  正确解析 `not` 和 `only` 关键字对媒体查询结果的影响。

**辅助功能：**

* **定义允许的媒体特性:**  通过 `MediaQueryFeatureSet` 类定义了哪些媒体特性是允许的，以及哪些特性不需要值。这有助于进行语法校验。
* **处理 CSS 变量:**  初步支持媒体查询中的 CSS 变量，尽管在提供的代码片段中，明确排除了某些变量名。
* **使用 UseCounter 统计特性使用情况:**  使用 `UseCounter` 记录媒体查询中特定语法 (如范围语法) 的使用情况，用于 Chromium 的遥测数据收集。
* **区分不同的解析模式:**  通过 `ParserType` 枚举区分解析整个 `MediaQuerySet` 还是仅仅解析一个 `MediaCondition`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  `media_query_parser.cc` 最直接地服务于 **CSS**。它解析的是 CSS 规范中定义的媒体查询语法。
    * **示例:** 当浏览器解析 CSS 样式表中的 `@media` 规则时，会调用这个解析器来理解媒体查询的条件。
        ```css
        @media screen and (min-width: 768px) {
          /* 在屏幕上且宽度大于等于 768px 时应用的样式 */
          body {
            font-size: 16px;
          }
        }
        ```
        在这个例子中，`screen and (min-width: 768px)` 这个字符串会交给 `media_query_parser.cc` 进行解析。

* **HTML:**  媒体查询也可以在 **HTML** 中使用，特别是 `<link>` 标签的 `media` 属性。
    * **示例:**
        ```html
        <link rel="stylesheet" href="style.css" media="screen and (orientation: portrait)">
        ```
        当浏览器加载这个 `<link>` 标签时，`screen and (orientation: portrait)` 这个媒体查询字符串会被 `media_query_parser.cc` 解析，以确定是否应该应用 `style.css` 这个样式表。

* **JavaScript:** **JavaScript** 可以通过 `window.matchMedia()` 方法来动态评估媒体查询。
    * **示例:**
        ```javascript
        if (window.matchMedia('(max-width: 600px)').matches) {
          console.log('屏幕宽度小于等于 600px');
        }
        ```
        虽然 JavaScript 代码本身不直接调用 `media_query_parser.cc`，但当 JavaScript 引擎执行 `window.matchMedia()` 时，它会创建一个内部的媒体查询对象，这个过程可能涉及到使用 `media_query_parser.cc` 来解析提供的媒体查询字符串 `'(max-width: 600px)'`。

**逻辑推理的假设输入与输出:**

**假设输入 1:**  `"screen and (width > 100px)"`

* **输出:** 一个 `MediaQuerySet` 对象，包含一个 `MediaQuery` 对象。该 `MediaQuery` 对象表示针对 `screen` 媒体类型，并且有一个媒体特性条件：`width` 大于 `100px`。内部的表示形式会是一个 `MediaQueryExpNode` 树，可能类似于 `AndNode(MediaTypeNode("screen"), FeatureNode("width", GreaterThan, "100px"))` (这只是一个简化的概念表示)。

**假设输入 2:**  `"print, (color)"`

* **输出:** 一个 `MediaQuerySet` 对象，包含两个 `MediaQuery` 对象。
    * 第一个 `MediaQuery` 对象表示 `print` 媒体类型，没有额外的特性条件。
    * 第二个 `MediaQuery` 对象针对 `all` 媒体类型（当没有指定媒体类型时默认为 `all`），并且有一个媒体特性条件：`color` (表示设备支持彩色)。

**假设输入 3 (包含错误):** `"screen and (min-width: )"`

* **输出:**  根据代码，如果解析失败，可能会创建一个表示 `not all` 的 `MediaQuery` 对象。具体错误处理逻辑可能在调用此解析器的上层代码中。  理想情况下，解析器应该能够标记出语法错误。

**用户或编程常见的使用错误:**

* **拼写错误的媒体特性名称:** 例如，写成 `widht` 而不是 `width`。解析器会将其识别为未知特性。
* **错误的语法结构:** 例如，忘记括号或使用错误的运算符顺序，如 `"screen and min-width: 100px"` (缺少括号)。
* **缺少媒体特性的值:** 例如，`"screen and (min-width)"`，对于需要值的特性，会导致解析错误。
* **使用了不支持的媒体特性:** 虽然 `MediaQueryFeatureSet` 有助于限制，但用户仍然可能尝试使用非标准的或过时的特性。
* **在不允许使用逻辑运算符的地方使用:**  例如，在 `<link media="...">` 属性中过度复杂的使用 `or` 可能会导致兼容性问题，尽管解析器可能能够处理。
* **CSS 变量使用不当:**  虽然支持 CSS 变量，但在媒体查询中的使用受到限制，某些上下文可能不允许使用。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 HTML 或 CSS 代码:** 用户在 HTML 文件中使用了 `<link media="...">` 标签，或者在 CSS 文件中编写了 `@media` 规则，其中包含了媒体查询字符串。

2. **浏览器加载和解析 HTML/CSS:** 当浏览器加载 HTML 文件或解析 CSS 文件时，会遇到这些包含媒体查询的声明。

3. **Blink 引擎的 CSS 解析器被调用:**  Blink 引擎的 CSS 解析器 (例如 `CSSParser`) 会负责处理 CSS 样式规则。当遇到 `@media` 规则或 `<link>` 标签的 `media` 属性时，它会识别出需要解析媒体查询。

4. **`media_query_parser.cc` 中的函数被调用:**  CSS 解析器会调用 `media_query_parser.cc` 中提供的解析函数，例如 `ParseMediaQuerySet`，并将媒体查询字符串作为参数传递给它。

5. **解析过程:** `media_query_parser.cc` 中的代码会逐步读取和分析输入的媒体查询字符串，根据 CSS 媒体查询的语法规则，将其分解成 token，并构建出内部的 `MediaQuerySet` 和 `MediaQuery` 对象。

6. **结果用于样式应用或条件判断:** 解析后的 `MediaQuery` 对象会被 Blink 引擎用于：
    * **条件化应用 CSS 样式:** 判断当前环境是否满足媒体查询的条件，从而决定是否应用相应的 CSS 规则。
    * **`window.matchMedia()` 的评估:** 当 JavaScript 调用 `window.matchMedia()` 时，会使用解析器来理解提供的查询字符串，并根据当前环境进行匹配。

**调试线索:**

如果用户报告媒体查询没有按预期工作，作为调试线索，可以考虑以下步骤：

* **检查媒体查询字符串的语法:**  仔细检查 HTML 或 CSS 代码中媒体查询字符串的拼写、语法结构是否正确。
* **使用开发者工具检查解析结果:**  现代浏览器开发者工具 (如 Chrome DevTools) 允许查看解析后的 CSS 规则和媒体查询，可以帮助确认解析器是否正确理解了媒体查询。
* **断点调试 Blink 引擎代码:**  对于更深入的调试，开发人员可以在 Blink 引擎的 `media_query_parser.cc` 文件中设置断点，跟踪解析过程，查看每个步骤的输入和输出，以定位解析错误的原因。例如，可以在 `ConsumeType`, `ConsumeFeature`, `ConsumeCondition` 等函数入口设置断点。
* **查看 UseCounter 统计信息:**  可以间接了解某些媒体查询特性是否被识别和使用。
* **对比不同浏览器的行为:**  如果特定媒体查询在一个浏览器中工作正常，但在另一个浏览器中不正常，可能暗示了浏览器实现上的差异或 bug。

总而言之，`media_query_parser.cc` 是 Blink 引擎中负责理解和处理 CSS 媒体查询的关键部分，它连接了前端开发者编写的 CSS 代码和浏览器内部的样式计算与应用机制。理解其功能和工作原理对于调试与媒体查询相关的问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/parser/media_query_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/media_query_parser.h"

#include "third_party/blink/renderer/core/css/media_feature_names.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/media_type_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

using css_parsing_utils::AtIdent;
using css_parsing_utils::ConsumeAnyValue;
using css_parsing_utils::ConsumeIfDelimiter;
using css_parsing_utils::ConsumeIfIdent;

namespace {

class MediaQueryFeatureSet : public MediaQueryParser::FeatureSet {
  STACK_ALLOCATED();

 public:
  MediaQueryFeatureSet() = default;

  bool IsAllowed(const AtomicString& feature) const override {
    if (feature == media_feature_names::kInlineSizeMediaFeature ||
        feature == media_feature_names::kMinInlineSizeMediaFeature ||
        feature == media_feature_names::kMaxInlineSizeMediaFeature ||
        feature == media_feature_names::kBlockSizeMediaFeature ||
        feature == media_feature_names::kMinBlockSizeMediaFeature ||
        feature == media_feature_names::kMaxBlockSizeMediaFeature ||
        feature == media_feature_names::kStuckMediaFeature ||
        feature == media_feature_names::kSnappedMediaFeature ||
        feature == media_feature_names::kOverflowingMediaFeature ||
        CSSVariableParser::IsValidVariableName(feature)) {
      return false;
    }
    return true;
  }
  bool IsAllowedWithoutValue(
      const AtomicString& feature,
      const ExecutionContext* execution_context) const override {
    // Media features that are prefixed by min/max cannot be used without a
    // value.
    return feature == media_feature_names::kMonochromeMediaFeature ||
           feature == media_feature_names::kColorMediaFeature ||
           feature == media_feature_names::kColorIndexMediaFeature ||
           feature == media_feature_names::kGridMediaFeature ||
           feature == media_feature_names::kHeightMediaFeature ||
           feature == media_feature_names::kWidthMediaFeature ||
           feature == media_feature_names::kBlockSizeMediaFeature ||
           feature == media_feature_names::kInlineSizeMediaFeature ||
           feature == media_feature_names::kDeviceHeightMediaFeature ||
           feature == media_feature_names::kDeviceWidthMediaFeature ||
           feature == media_feature_names::kOrientationMediaFeature ||
           feature == media_feature_names::kAspectRatioMediaFeature ||
           feature == media_feature_names::kDeviceAspectRatioMediaFeature ||
           feature == media_feature_names::kHoverMediaFeature ||
           feature == media_feature_names::kAnyHoverMediaFeature ||
           feature == media_feature_names::kTransform3dMediaFeature ||
           feature == media_feature_names::kPointerMediaFeature ||
           feature == media_feature_names::kAnyPointerMediaFeature ||
           feature == media_feature_names::kDevicePixelRatioMediaFeature ||
           feature == media_feature_names::kResolutionMediaFeature ||
           feature == media_feature_names::kDisplayModeMediaFeature ||
           feature == media_feature_names::kScanMediaFeature ||
           feature == media_feature_names::kColorGamutMediaFeature ||
           feature == media_feature_names::kPrefersColorSchemeMediaFeature ||
           feature == media_feature_names::kPrefersContrastMediaFeature ||
           feature == media_feature_names::kPrefersReducedMotionMediaFeature ||
           feature == media_feature_names::kOverflowInlineMediaFeature ||
           feature == media_feature_names::kOverflowBlockMediaFeature ||
           feature == media_feature_names::kUpdateMediaFeature ||
           (feature == media_feature_names::kPrefersReducedDataMediaFeature &&
            RuntimeEnabledFeatures::PrefersReducedDataEnabled()) ||
           feature ==
               media_feature_names::kPrefersReducedTransparencyMediaFeature ||
           (feature == media_feature_names::kForcedColorsMediaFeature &&
            RuntimeEnabledFeatures::ForcedColorsEnabled()) ||
           (feature == media_feature_names::kNavigationControlsMediaFeature &&
            RuntimeEnabledFeatures::MediaQueryNavigationControlsEnabled()) ||
           (feature == media_feature_names::kOriginTrialTestMediaFeature &&
            RuntimeEnabledFeatures::OriginTrialsSampleAPIEnabled(
                execution_context)) ||
           (feature ==
                media_feature_names::kHorizontalViewportSegmentsMediaFeature &&
            RuntimeEnabledFeatures::ViewportSegmentsEnabled(
                execution_context)) ||
           (feature ==
                media_feature_names::kVerticalViewportSegmentsMediaFeature &&
            RuntimeEnabledFeatures::ViewportSegmentsEnabled(
                execution_context)) ||
           (feature == media_feature_names::kDevicePostureMediaFeature &&
            RuntimeEnabledFeatures::DevicePostureEnabled(execution_context)) ||
           (feature == media_feature_names::kInvertedColorsMediaFeature &&
            RuntimeEnabledFeatures::InvertedColorsEnabled()) ||
           CSSVariableParser::IsValidVariableName(feature) ||
           feature == media_feature_names::kScriptingMediaFeature ||
           (RuntimeEnabledFeatures::
                DesktopPWAsAdditionalWindowingControlsEnabled() &&
            feature == media_feature_names::kDisplayStateMediaFeature) ||
           (RuntimeEnabledFeatures::
                DesktopPWAsAdditionalWindowingControlsEnabled() &&
            feature == media_feature_names::kResizableMediaFeature);
  }

  bool IsCaseSensitive(const AtomicString& feature) const override {
    return false;
  }
  bool SupportsRange() const override { return true; }
};

}  // namespace

MediaQuerySet* MediaQueryParser::ParseMediaQuerySet(
    StringView query_string,
    ExecutionContext* execution_context) {
  CSSParserTokenStream stream(query_string);
  return ParseMediaQuerySet(stream, execution_context);
}

MediaQuerySet* MediaQueryParser::ParseMediaQuerySet(
    CSSParserTokenStream& stream,
    ExecutionContext* execution_context) {
  return MediaQueryParser(kMediaQuerySetParser, kHTMLStandardMode,
                          execution_context)
      .ParseImpl(stream);
}

MediaQuerySet* MediaQueryParser::ParseMediaQuerySetInMode(
    CSSParserTokenStream& stream,
    CSSParserMode mode,
    ExecutionContext* execution_context) {
  return MediaQueryParser(kMediaQuerySetParser, mode, execution_context)
      .ParseImpl(stream);
}

MediaQuerySet* MediaQueryParser::ParseMediaCondition(
    CSSParserTokenStream& stream,
    ExecutionContext* execution_context) {
  return MediaQueryParser(kMediaConditionParser, kHTMLStandardMode,
                          execution_context)
      .ParseImpl(stream);
}

MediaQueryParser::MediaQueryParser(ParserType parser_type,
                                   CSSParserMode mode,
                                   ExecutionContext* execution_context,
                                   SyntaxLevel syntax_level)
    : parser_type_(parser_type),
      mode_(mode),
      execution_context_(execution_context),
      syntax_level_(syntax_level),
      fake_context_(*MakeGarbageCollected<CSSParserContext>(
          kHTMLStandardMode,
          SecureContextMode::kInsecureContext,
          DynamicTo<LocalDOMWindow>(execution_context)
              ? DynamicTo<LocalDOMWindow>(execution_context)->document()
              : nullptr)) {}

namespace {

bool IsRestrictorOrLogicalOperator(const CSSParserToken& token) {
  // FIXME: it would be more efficient to use lower-case always for tokenValue.
  return EqualIgnoringASCIICase(token.Value(), "not") ||
         EqualIgnoringASCIICase(token.Value(), "and") ||
         EqualIgnoringASCIICase(token.Value(), "or") ||
         EqualIgnoringASCIICase(token.Value(), "only") ||
         EqualIgnoringASCIICase(token.Value(), "layer");
}

bool ConsumeUntilCommaInclusive(CSSParserTokenStream& stream) {
  stream.SkipUntilPeekedTypeIs<kCommaToken>();
  if (stream.Peek().GetType() == kCommaToken) {
    stream.ConsumeIncludingWhitespace();
    return true;
  } else {
    return false;
  }
}

bool IsComparisonDelimiter(UChar c) {
  return c == '<' || c == '>' || c == '=';
}

void SkipUntilComparisonOrColon(CSSParserTokenStream& stream) {
  while (!stream.AtEnd()) {
    stream.SkipUntilPeekedTypeIs<kDelimiterToken, kColonToken>();
    if (stream.AtEnd()) {
      return;
    }
    const CSSParserToken& token = stream.Peek();
    if (token.GetType() == kDelimiterToken) {
      if (IsComparisonDelimiter(token.Delimiter())) {
        return;
      } else {
        stream.Consume();
      }
    } else {
      DCHECK_EQ(token.GetType(), kColonToken);
      return;
    }
  }
}

bool IsLtLe(MediaQueryOperator op) {
  return op == MediaQueryOperator::kLt || op == MediaQueryOperator::kLe;
}

bool IsGtGe(MediaQueryOperator op) {
  return op == MediaQueryOperator::kGt || op == MediaQueryOperator::kGe;
}

}  // namespace

MediaQuery::RestrictorType MediaQueryParser::ConsumeRestrictor(
    CSSParserTokenStream& stream) {
  if (ConsumeIfIdent(stream, "not")) {
    return MediaQuery::RestrictorType::kNot;
  }
  if (ConsumeIfIdent(stream, "only")) {
    return MediaQuery::RestrictorType::kOnly;
  }
  return MediaQuery::RestrictorType::kNone;
}

AtomicString MediaQueryParser::ConsumeType(CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kIdentToken) {
    return g_null_atom;
  }
  if (IsRestrictorOrLogicalOperator(stream.Peek())) {
    return g_null_atom;
  }
  return stream.ConsumeIncludingWhitespace().Value().ToAtomicString();
}

MediaQueryOperator MediaQueryParser::ConsumeComparison(
    CSSParserTokenStream& stream) {
  const CSSParserToken& first = stream.Peek();
  if (first.GetType() != kDelimiterToken ||
      !IsComparisonDelimiter(first.Delimiter())) {
    return MediaQueryOperator::kNone;
  }
  switch (first.Delimiter()) {
    case '=':
      stream.ConsumeIncludingWhitespace();
      return MediaQueryOperator::kEq;
    case '<':
      stream.Consume();
      if (ConsumeIfDelimiter(stream, '=')) {
        return MediaQueryOperator::kLe;
      }
      stream.ConsumeWhitespace();
      return MediaQueryOperator::kLt;
    case '>':
      stream.Consume();
      if (ConsumeIfDelimiter(stream, '=')) {
        return MediaQueryOperator::kGe;
      }
      stream.ConsumeWhitespace();
      return MediaQueryOperator::kGt;
  }

  NOTREACHED();
}

AtomicString MediaQueryParser::ConsumeAllowedName(
    CSSParserTokenStream& stream,
    const FeatureSet& feature_set) {
  if (stream.Peek().GetType() != kIdentToken) {
    return g_null_atom;
  }
  AtomicString name = stream.Peek().Value().ToAtomicString();
  if (!feature_set.IsCaseSensitive(name)) {
    name = name.LowerASCII();
  }
  if (!feature_set.IsAllowed(name)) {
    return g_null_atom;
  }
  stream.ConsumeIncludingWhitespace();
  return name;
}

AtomicString MediaQueryParser::ConsumeUnprefixedName(
    CSSParserTokenStream& stream,
    const FeatureSet& feature_set) {
  AtomicString name = ConsumeAllowedName(stream, feature_set);
  if (name.IsNull()) {
    return name;
  }
  if (name.StartsWith("min-") || name.StartsWith("max-")) {
    return g_null_atom;
  }
  return name;
}

const MediaQueryExpNode* MediaQueryParser::ConsumeFeature(
    CSSParserTokenStream& stream,
    const FeatureSet& feature_set) {
  // There are several possible grammars for media queries, and we don't
  // know where <mf-name> appears. Thus, our only strategy is to just try them
  // one by one and restart if we got it wrong.
  //

  CSSParserTokenStream::State start = stream.Save();

  {
    AtomicString feature_name = ConsumeAllowedName(stream, feature_set);

    // <mf-boolean> = <mf-name>
    if (!feature_name.IsNull() && stream.AtEnd() &&
        feature_set.IsAllowedWithoutValue(feature_name, execution_context_)) {
      return MakeGarbageCollected<MediaQueryFeatureExpNode>(
          MediaQueryExp::Create(feature_name, MediaQueryExpBounds()));
    }

    // <mf-plain> = <mf-name> : <mf-value>
    if (!feature_name.IsNull() && stream.Peek().GetType() == kColonToken) {
      stream.ConsumeIncludingWhitespace();

      // NOTE: We do not check for stream.AtEnd() here, as an empty mf-value is
      // legal.
      auto exp = MediaQueryExp::Create(feature_name, stream, fake_context_);
      if (exp.IsValid() && stream.AtEnd()) {
        return MakeGarbageCollected<MediaQueryFeatureExpNode>(exp);
      }
    }

    stream.Restore(start);
  }

  if (!feature_set.SupportsRange()) {
    return nullptr;
  }

  // Otherwise <mf-range>:
  //
  // <mf-range> = <mf-name> <mf-comparison> <mf-value>
  //            | <mf-value> <mf-comparison> <mf-name>
  //            | <mf-value> <mf-lt> <mf-name> <mf-lt> <mf-value>
  //            | <mf-value> <mf-gt> <mf-name> <mf-gt> <mf-value>

  {
    // Try: <mf-name> <mf-comparison> <mf-value> (e.g., “width <= 10px”)
    AtomicString feature_name = ConsumeUnprefixedName(stream, feature_set);
    if (!feature_name.IsNull() && !stream.AtEnd()) {
      MediaQueryOperator op = ConsumeComparison(stream);
      if (op != MediaQueryOperator::kNone) {
        auto value =
            MediaQueryExpValue::Consume(feature_name, stream, fake_context_);
        if (value && stream.AtEnd()) {
          auto left = MediaQueryExpComparison();
          auto right = MediaQueryExpComparison(*value, op);

          UseCountRangeSyntax();
          return MakeGarbageCollected<MediaQueryFeatureExpNode>(
              MediaQueryExp::Create(feature_name,
                                    MediaQueryExpBounds(left, right)));
        }
      }
    }
    stream.Restore(start);
  }

  // It must be one of these three:
  //
  // <mf-value> <mf-comparison> <mf-name>  (e.g., “10px = width”)
  // <mf-value> <mf-lt> <mf-name> <mf-lt> <mf-value>
  // <mf-value> <mf-gt> <mf-name> <mf-gt> <mf-value>
  //
  // We don't know how to parse <mf-value> yet, so we need to skip it
  // and parse <mf-name> first, then return to (the first) <mf-value>
  // afterwards.
  //
  // Local variables names from here on are chosen with the expectation
  // that we are heading towards the most complicated form of <mf-range>
  // (the latter in the list), which corresponds to the local variables:
  //
  //  <value1> <op1> <feature_name> <op2> <value2>
  SkipUntilComparisonOrColon(stream);
  if (stream.AtEnd()) {
    return nullptr;
  }
  wtf_size_t offset_after_value1 = stream.LookAheadOffset();

  MediaQueryOperator op1 = ConsumeComparison(stream);
  if (op1 == MediaQueryOperator::kNone) {
    return nullptr;
  }

  AtomicString feature_name = ConsumeUnprefixedName(stream, feature_set);
  if (feature_name.IsNull()) {
    return nullptr;
  }

  stream.ConsumeWhitespace();
  CSSParserTokenStream::State after_feature_name = stream.Save();

  stream.Restore(start);
  auto value1 =
      MediaQueryExpValue::Consume(feature_name, stream, fake_context_);
  if (!value1) {
    return nullptr;
  }

  if (stream.LookAheadOffset() != offset_after_value1) {
    // There was junk between <value1> and <op1>.
    return nullptr;
  }

  // Skip over the comparison and name again.
  stream.Restore(after_feature_name);

  if (stream.AtEnd()) {
    // Must be: <mf-value> <mf-comparison> <mf-name>
    auto left = MediaQueryExpComparison(*value1, op1);
    auto right = MediaQueryExpComparison();

    UseCountRangeSyntax();
    return MakeGarbageCollected<MediaQueryFeatureExpNode>(
        MediaQueryExp::Create(feature_name, MediaQueryExpBounds(left, right)));
  }

  // Parse the last <mf-value>.
  MediaQueryOperator op2 = ConsumeComparison(stream);
  if (op2 == MediaQueryOperator::kNone) {
    return nullptr;
  }

  // Mixing [lt, le] and [gt, ge] is not allowed by the grammar.
  const bool both_lt_le = IsLtLe(op1) && IsLtLe(op2);
  const bool both_gt_ge = IsGtGe(op1) && IsGtGe(op2);
  if (!(both_lt_le || both_gt_ge)) {
    return nullptr;
  }

  auto value2 =
      MediaQueryExpValue::Consume(feature_name, stream, fake_context_);
  if (!value2) {
    return nullptr;
  }

  UseCountRangeSyntax();
  return MakeGarbageCollected<MediaQueryFeatureExpNode>(MediaQueryExp::Create(
      feature_name,
      MediaQueryExpBounds(MediaQueryExpComparison(*value1, op1),
                          MediaQueryExpComparison(*value2, op2))));
}

const MediaQueryExpNode* MediaQueryParser::ConsumeCondition(
    CSSParserTokenStream& stream,
    ConditionMode mode) {
  // <media-not>
  if (ConsumeIfIdent(stream, "not")) {
    return MediaQueryExpNode::Not(ConsumeInParens(stream));
  }

  // Otherwise:
  // <media-in-parens> [ <media-and>* | <media-or>* ]

  const MediaQueryExpNode* result = ConsumeInParens(stream);

  if (AtIdent(stream.Peek(), "and")) {
    while (result && ConsumeIfIdent(stream, "and")) {
      result = MediaQueryExpNode::And(result, ConsumeInParens(stream));
    }
  } else if (result && AtIdent(stream.Peek(), "or") &&
             mode == ConditionMode::kNormal) {
    while (result && ConsumeIfIdent(stream, "or")) {
      result = MediaQueryExpNode::Or(result, ConsumeInParens(stream));
    }
  }

  return result;
}

const MediaQueryExpNode* MediaQueryParser::ConsumeInParens(
    CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() == kLeftParenthesisToken) {
    {
      CSSParserTokenStream::RestoringBlockGuard guard(stream);
      stream.ConsumeWhitespace();

      // ( <media-condition> )
      const MediaQueryExpNode* condition = ConsumeCondition(stream);
      if (condition && guard.Release()) {
        stream.ConsumeWhitespace();
        return MediaQueryExpNode::Nested(condition);
      }
    }

    {
      CSSParserTokenStream::RestoringBlockGuard guard(stream);
      stream.ConsumeWhitespace();
      // ( <media-feature> )
      const MediaQueryExpNode* feature =
          ConsumeFeature(stream, MediaQueryFeatureSet());
      if (feature && guard.Release()) {
        stream.ConsumeWhitespace();
        return MediaQueryExpNode::Nested(feature);
      }
    }
  }

  // <general-enclosed>
  return ConsumeGeneralEnclosed(stream);
}

const MediaQueryExpNode* MediaQueryParser::ConsumeGeneralEnclosed(
    CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kLeftParenthesisToken &&
      stream.Peek().GetType() != kFunctionToken) {
    return nullptr;
  }

  wtf_size_t start_offset = stream.Offset();
  StringView general_enclosed;
  {
    CSSParserTokenStream::BlockGuard guard(stream);

    stream.ConsumeWhitespace();

    // Note that <any-value> is optional in <general-enclosed>, so having an
    // empty block is fine.
    ConsumeAnyValue(stream);
    if (!stream.AtEnd()) {
      return nullptr;
    }
  }

  wtf_size_t end_offset = stream.Offset();

  // TODO(crbug.com/962417): This is not well specified.
  general_enclosed =
      stream.StringRangeAt(start_offset, end_offset - start_offset);

  stream.ConsumeWhitespace();
  return MakeGarbageCollected<MediaQueryUnknownExpNode>(
      general_enclosed.ToString());
}

MediaQuerySet* MediaQueryParser::ConsumeSingleCondition(
    CSSParserTokenStream& stream) {
  DCHECK_EQ(parser_type_, kMediaConditionParser);
  DCHECK(!stream.AtEnd());

  HeapVector<Member<const MediaQuery>> queries;
  const MediaQueryExpNode* node = ConsumeCondition(stream);
  if (!node) {
    queries.push_back(MediaQuery::CreateNotAll());
  } else {
    queries.push_back(MakeGarbageCollected<MediaQuery>(
        MediaQuery::RestrictorType::kNone, media_type_names::kAll, node));
  }
  return MakeGarbageCollected<MediaQuerySet>(std::move(queries));
}

MediaQuery* MediaQueryParser::ConsumeQuery(CSSParserTokenStream& stream) {
  DCHECK_EQ(parser_type_, kMediaQuerySetParser);
  CSSParserTokenStream::State savepoint = stream.Save();

  // First try to parse following grammar:
  //
  // [ not | only ]? <media-type> [ and <media-condition-without-or> ]?
  MediaQuery::RestrictorType restrictor = ConsumeRestrictor(stream);
  AtomicString type = ConsumeType(stream);

  if (!type.IsNull()) {
    if (!ConsumeIfIdent(stream, "and")) {
      return MakeGarbageCollected<MediaQuery>(restrictor, type, nullptr);
    }
    if (const MediaQueryExpNode* node =
            ConsumeCondition(stream, ConditionMode::kWithoutOr)) {
      return MakeGarbageCollected<MediaQuery>(restrictor, type, node);
    }
    return nullptr;
  }
  stream.Restore(savepoint);

  // Otherwise, <media-condition>
  if (const MediaQueryExpNode* node = ConsumeCondition(stream)) {
    return MakeGarbageCollected<MediaQuery>(MediaQuery::RestrictorType::kNone,
                                            media_type_names::kAll, node);
  }
  return nullptr;
}

MediaQuerySet* MediaQueryParser::ParseImpl(CSSParserTokenStream& stream) {
  stream.ConsumeWhitespace();

  // Note that we currently expect an empty input to evaluate to an empty
  // MediaQuerySet, rather than "not all".
  if (stream.AtEnd()) {
    return MakeGarbageCollected<MediaQuerySet>();
  }

  if (parser_type_ == kMediaConditionParser) {
    return ConsumeSingleCondition(stream);
  }

  DCHECK_EQ(parser_type_, kMediaQuerySetParser);

  HeapVector<Member<const MediaQuery>> queries;

  do {
    MediaQuery* query = ConsumeQuery(stream);
    bool ok =
        query && (stream.AtEnd() || stream.Peek().GetType() == kCommaToken);
    queries.push_back(ok ? query : MediaQuery::CreateNotAll());
  } while (!stream.AtEnd() && ConsumeUntilCommaInclusive(stream));

  return MakeGarbageCollected<MediaQuerySet>(std::move(queries));
}

void MediaQueryParser::UseCountRangeSyntax() {
  UseCounter::Count(execution_context_, WebFeature::kMediaQueryRangeSyntax);
}

}  // namespace blink
```
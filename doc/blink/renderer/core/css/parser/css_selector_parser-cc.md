Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This is part 1 of 3, so the summary should focus on the aspects covered in this section.
The code is from `css_selector_parser.cc` within the Blink rendering engine.
It's responsible for parsing CSS selectors.

Here's a breakdown of what this part seems to handle:

1. **Core Parsing Logic:** The code contains functions to parse different levels of CSS selectors (complex, compound, relative, nested).
2. **Handling Combinators:** It identifies and processes CSS combinators like descendant, child, adjacent sibling, and general sibling.
3. **Nesting Support:**  It deals with CSS nesting features, including the `&` and `:scope` selectors.
4. **Pseudo-classes and Pseudo-elements:** The code likely contains logic to identify and handle different types of pseudo-classes and pseudo-elements.
5. **Error Handling/Forgiving Parsing:** There are mentions of "forgiving" parsing, suggesting it can handle some invalid CSS.
6. **Internal Structure:** The code uses `CSSSelector` objects to represent parsed selectors and stores them in a `HeapVector`.
7. **Context and Options:** The `CSSSelectorParser` constructor takes a `CSSParserContext`, indicating it's aware of the parsing context (e.g., UA stylesheet, author stylesheet).

**Plan:**

1. Identify the primary goal of the file.
2. List the key functionalities implemented in this part of the code.
3. Mention any specific features like nesting or forgiving parsing.
这是 `blink/renderer/core/css/parser/css_selector_parser.cc` 文件的第一部分，其主要功能是**解析 CSS 选择器**。

**具体功能归纳：**

1. **核心解析功能:** 提供了 `ParseSelector` 和 `ConsumeSelector` 等静态方法，作为解析 CSS 选择器的入口点。这些方法接收 `CSSParserTokenStream` （CSS 词法单元流）和 `CSSParserContext` （解析上下文）等参数，并返回解析后的 `CSSSelector` 对象。
2. **支持不同类型的选择器:** 能够解析复杂选择器列表 (`ConsumeComplexSelectorList`)、复合选择器列表 (`ConsumeCompoundSelectorList`)、嵌套选择器列表 (`ConsumeNestedSelectorList`) 以及相对选择器 (`ConsumeRelativeSelector`)。
3. **处理 CSS 组合器 (Combinators):** 能够识别和处理 CSS 组合器，如后代选择器（空格）、子选择器（`>`）、相邻兄弟选择器（`+`）和后续兄弟选择器（`~`），并通过 `ConsumeCombinator` 函数实现。
4. **支持 CSS 嵌套 (Nesting):**  实现了对 CSS 嵌套语法的解析，包括对父选择器引用符 `&` 和 `:scope` 伪类的处理。`ConsumeNestedRelativeSelector` 函数专门用于解析以组合器开头的嵌套选择器。
5. **处理伪类和伪元素:** 具备解析伪类（如 `:hover`, `:active`）和伪元素（如 `::before`, `::after`）的能力，并通过 `ParsePseudoType` 函数来识别伪元素的类型。
6. **支持 `:is()` 等伪类:**  虽然代码中没有直接列出所有支持的伪类，但其结构支持解析带有参数的伪类，如 `:is()`。
7. **“容错”解析 (Forgiving Parsing):** 提供了 `ConsumeForgivingComplexSelectorList` 等方法，可以在解析过程中遇到错误时尝试恢复，而不是立即失败，这对于处理不完全或有错误的 CSS 代码很有用。
8. **判断选择器是否支持:** 提供了 `SupportsComplexSelector` 方法，用于判断给定的词法单元流是否能解析为一个有效的复杂选择器。
9. **内部数据结构管理:** 使用 `HeapVector<CSSSelector>` 作为 arena 来存储解析过程中创建的 `CSSSelector` 对象，以进行内存管理。
10. **记录使用情况和弃用警告:**  `RecordUsageAndDeprecations` 函数用于记录已使用的 CSS 特性以及可能存在的弃用警告。

**与其他功能的关系举例说明：**

*   **JavaScript:**  JavaScript 可以通过 DOM API 获取或修改元素的样式。当浏览器需要应用样式时，会使用 CSS 选择器来匹配元素。例如，`document.querySelector('.my-class')` 会使用 CSS 选择器 `.my-class` 来查找元素，而 `css_selector_parser.cc` 的功能正是将这样的字符串选择器解析成内部数据结构，供匹配引擎使用。
*   **HTML:** HTML 结构定义了文档的元素和它们的层级关系。CSS 选择器正是基于 HTML 结构来选取元素的。例如，CSS 规则 `div p` 会选择 `div` 元素内部的所有 `p` 元素，而 `css_selector_parser.cc` 负责解析这个选择器，以便样式系统能够正确地将样式应用到这些 `p` 元素上。
*   **CSS:** `css_selector_parser.cc` 的核心功能就是解析 CSS。任何 CSS 规则都包含选择器，例如：

    ```css
    .container > .item:hover {
      color: red;
    }
    ```

    在这个例子中，`.container > .item:hover` 就是一个 CSS 选择器。`css_selector_parser.cc` 会将其解析成表示“类名为 `container` 的元素的直接子元素中类名为 `item` 的，并且鼠标悬停在其上”的内部结构。

**逻辑推理举例：**

假设输入的 CSS 词法单元流表示选择器 `.foo .bar > span`。

*   **假设输入:**  词法单元流包含表示 `.foo`、空格、`.bar`、空格、`>`、空格、`span` 的 token。
*   **输出:**  `css_selector_parser.cc` 会解析出三个 `CSSSelector` 对象，分别对应 `.foo`、`.bar` 和 `span`。它们之间的关系会被记录下来：`.foo` 和 `.bar` 之间是后代关系，`.bar` 和 `span` 之间是子元素关系。最终会构建一个表示该复杂选择器的内部结构。

**用户或编程常见的使用错误举例：**

*   **CSS 语法错误:** 用户在编写 CSS 时可能会犯语法错误，例如选择器中缺少空格或者使用了错误的组合符。例如，写成 `.foobar` 而不是 `.foo .bar`。`css_selector_parser.cc` 在解析时会检测这些错误，并可能产生错误信息或回退到“容错”解析模式。
*   **使用了浏览器不支持的 CSS 特性:** 如果 CSS 中使用了当前浏览器版本不支持的伪类或伪元素，`css_selector_parser.cc` 可能会忽略这些部分或者产生警告。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在 HTML 文件中添加 `<style>` 标签或通过 `<link>` 标签引入 CSS 文件。**
2. **浏览器加载 HTML 文件并开始解析。**
3. **当解析器遇到 `<style>` 标签或 CSS 文件时，会启动 CSS 解析流程。**
4. **CSS 解析器会将 CSS 文本分解成词法单元 (tokens)。**
5. **`css_selector_parser.cc` 中的代码会被调用，负责解析这些词法单元，特别是识别和构建 CSS 选择器的内部表示。**
6. **如果 CSS 中存在语法错误或不支持的特性，`css_selector_parser.cc` 在解析过程中可能会记录错误信息，这些信息可能会出现在浏览器的开发者工具的控制台中，作为调试线索。**
7. **开发者可以通过浏览器开发者工具查看元素的样式，以及匹配到该元素的 CSS 规则，这可以帮助理解 CSS 选择器是如何被解析和应用的。**

总而言之，`css_selector_parser.cc` 的第一部分主要负责将 CSS 选择器的文本形式转换为 Blink 引擎内部可以理解和使用的结构化表示，这是浏览器渲染页面和应用样式的核心步骤之一。它涵盖了多种选择器类型和 CSS 嵌套特性，并具备一定的容错能力。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_selector_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
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

#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"

#include <algorithm>
#include <memory>

#include "base/auto_reset.h"
#include "base/containers/span.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/parser/css_nesting_type.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_observer.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

static void RecordUsageAndDeprecationsOneSelector(
    const CSSSelector* selector,
    const CSSParserContext* context,
    bool* has_visited_pseudo);

namespace {

bool AtEndIgnoringWhitespace(CSSParserTokenStream& stream) {
  stream.EnsureLookAhead();
  CSSParserSavePoint savepoint(stream);
  stream.ConsumeWhitespace();
  return stream.AtEnd();
}

bool IsHostPseudoSelector(const CSSSelector& selector) {
  return selector.GetPseudoType() == CSSSelector::kPseudoHost ||
         selector.GetPseudoType() == CSSSelector::kPseudoHostContext;
}

// Some pseudo elements behave as if they have an implicit combinator to their
// left even though they are written without one. This method returns the
// correct implicit combinator. If no new combinator should be used,
// it returns RelationType::kSubSelector.
CSSSelector::RelationType GetImplicitShadowCombinatorForMatching(
    CSSSelector::PseudoType pseudo_type) {
  switch (pseudo_type) {
    case CSSSelector::PseudoType::kPseudoSlotted:
      return CSSSelector::RelationType::kShadowSlot;
    case CSSSelector::PseudoType::kPseudoWebKitCustomElement:
    case CSSSelector::PseudoType::kPseudoBlinkInternalElement:
    case CSSSelector::PseudoType::kPseudoCue:
    case CSSSelector::PseudoType::kPseudoDetailsContent:
    case CSSSelector::PseudoType::kPseudoPlaceholder:
    case CSSSelector::PseudoType::kPseudoFileSelectorButton:
    case CSSSelector::PseudoType::kPseudoPicker:
      return CSSSelector::RelationType::kUAShadow;
    case CSSSelector::PseudoType::kPseudoPart:
      return CSSSelector::RelationType::kShadowPart;
    default:
      return CSSSelector::RelationType::kSubSelector;
  }
}

bool NeedsImplicitShadowCombinatorForMatching(const CSSSelector& selector) {
  return GetImplicitShadowCombinatorForMatching(selector.GetPseudoType()) !=
         CSSSelector::RelationType::kSubSelector;
}

// Marks the end of parsing a complex selector. (In many cases, there may
// be more complex selectors after this, since we are often dealing with
// lists of complex selectors. Those are marked using SetLastInSelectorList(),
// which happens in CSSSelectorList::AdoptSelectorVector.)
void MarkAsEntireComplexSelector(base::span<CSSSelector> selectors) {
#if DCHECK_IS_ON()
  for (CSSSelector& selector : selectors.first(selectors.size() - 1)) {
    DCHECK(!selector.IsLastInComplexSelector());
  }
#endif
  selectors.back().SetLastInComplexSelector(true);
}

}  // namespace

// static
base::span<CSSSelector> CSSSelectorParser::ParseSelector(
    CSSParserTokenStream& stream,
    const CSSParserContext* context,
    CSSNestingType nesting_type,
    const StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    bool semicolon_aborts_nested_selector,
    StyleSheetContents* style_sheet,
    HeapVector<CSSSelector>& arena) {
  CSSSelectorParser parser(context, parent_rule_for_nesting, is_within_scope,
                           semicolon_aborts_nested_selector, style_sheet,
                           arena);
  stream.ConsumeWhitespace();
  ResultFlags result_flags = 0;
  base::span<CSSSelector> result =
      parser.ConsumeComplexSelectorList(stream, nesting_type, result_flags);
  if (!stream.AtEnd()) {
    return {};
  }

  parser.RecordUsageAndDeprecations(result);
  return result;
}

// static
base::span<CSSSelector> CSSSelectorParser::ConsumeSelector(
    CSSParserTokenStream& stream,
    const CSSParserContext* context,
    CSSNestingType nesting_type,
    const StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    bool semicolon_aborts_nested_selector,
    StyleSheetContents* style_sheet,
    CSSParserObserver* observer,
    HeapVector<CSSSelector>& arena,
    bool* has_visited_style) {
  CSSSelectorParser parser(context, parent_rule_for_nesting, is_within_scope,
                           semicolon_aborts_nested_selector, style_sheet,
                           arena);
  stream.ConsumeWhitespace();
  ResultFlags result_flags = 0;
  base::span<CSSSelector> result = parser.ConsumeComplexSelectorList(
      stream, observer, nesting_type, result_flags);
  parser.RecordUsageAndDeprecations(result, has_visited_style);
  return result;
}

// static
base::span<CSSSelector> CSSSelectorParser::ParseScopeBoundary(
    CSSParserTokenStream& stream,
    const CSSParserContext* context,
    CSSNestingType nesting_type,
    const StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    StyleSheetContents* style_sheet,
    HeapVector<CSSSelector>& arena) {
  CSSSelectorParser parser(context, parent_rule_for_nesting, is_within_scope,
                           /*semicolon_aborts_nested_selector=*/false,
                           style_sheet, arena);
  DisallowPseudoElementsScope disallow_pseudo_elements(&parser);

  stream.ConsumeWhitespace();
  ResultFlags result_flags = 0;
  base::span<CSSSelector> result =
      parser.ConsumeComplexSelectorList(stream, nesting_type, result_flags);
  if (result.empty() || !stream.AtEnd()) {
    return {};
  }
  parser.RecordUsageAndDeprecations(result);
  return result;
}

// static
bool CSSSelectorParser::SupportsComplexSelector(
    CSSParserTokenStream& stream,
    const CSSParserContext* context) {
  stream.ConsumeWhitespace();
  HeapVector<CSSSelector> arena;
  CSSSelectorParser parser(
      context, /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
      /*semicolon_aborts_nested_selector=*/false, nullptr, arena);
  parser.SetInSupportsParsing();
  ResultFlags result_flags = 0;
  base::span<CSSSelector> selectors = parser.ConsumeComplexSelector(
      stream, CSSNestingType::kNone,
      /*first_in_complex_selector_list=*/true, result_flags);
  if (parser.failed_parsing_ || !stream.AtEnd() || selectors.empty()) {
    return false;
  }
  if (ContainsUnknownWebkitPseudoElements(selectors)) {
    return false;
  }
  return true;
}

CSSSelectorParser::CSSSelectorParser(const CSSParserContext* context,
                                     const StyleRule* parent_rule_for_nesting,
                                     bool is_within_scope,
                                     bool semicolon_aborts_nested_selector,
                                     StyleSheetContents* style_sheet,
                                     HeapVector<CSSSelector>& output)
    : context_(context),
      parent_rule_for_nesting_(parent_rule_for_nesting),
      is_within_scope_(is_within_scope),
      semicolon_aborts_nested_selector_(semicolon_aborts_nested_selector),
      style_sheet_(style_sheet),
      output_(output) {}

base::span<CSSSelector> CSSSelectorParser::ConsumeComplexSelectorList(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    ResultFlags& result_flags) {
  ResetVectorAfterScope reset_vector(output_);
  if (ConsumeComplexSelector(stream, nesting_type,
                             /*first_in_complex_selector_list=*/true,
                             result_flags)
          .empty()) {
    return {};
  }
  while (!stream.AtEnd() && stream.Peek().GetType() == kCommaToken) {
    stream.ConsumeIncludingWhitespace();
    if (ConsumeComplexSelector(stream, nesting_type,
                               /*first_in_complex_selector_list=*/false,
                               result_flags)
            .empty()) {
      return {};
    }
  }

  if (failed_parsing_) {
    return {};
  }

  return reset_vector.CommitAddedElements();
}

static bool AtEndOfComplexSelector(CSSParserTokenStream& stream) {
  const CSSParserToken& token = stream.Peek();
  return stream.AtEnd() || token.GetType() == kLeftBraceToken ||
         token.GetType() == kCommaToken;
}

base::span<CSSSelector> CSSSelectorParser::ConsumeComplexSelectorList(
    CSSParserTokenStream& stream,
    CSSParserObserver* observer,
    CSSNestingType nesting_type,
    ResultFlags& result_flags) {
  ResetVectorAfterScope reset_vector(output_);

  bool first_in_complex_selector_list = true;
  while (true) {
    const wtf_size_t selector_offset_start = stream.LookAheadOffset();

    if (ConsumeComplexSelector(stream, nesting_type,
                               first_in_complex_selector_list, result_flags)
            .empty() ||
        failed_parsing_ || !AtEndOfComplexSelector(stream)) {
      if (AbortsNestedSelectorParsing(kSemicolonToken,
                                      semicolon_aborts_nested_selector_,
                                      nesting_type)) {
        stream.SkipUntilPeekedTypeIs<kLeftBraceToken, kCommaToken,
                                     kSemicolonToken>();
      } else {
        stream.SkipUntilPeekedTypeIs<kLeftBraceToken, kCommaToken>();
      }
      return {};
    }
    const wtf_size_t selector_offset_end = stream.LookAheadOffset();
    first_in_complex_selector_list = false;

    if (observer) {
      observer->ObserveSelector(selector_offset_start, selector_offset_end);
    }

    if (stream.UncheckedAtEnd()) {
      break;
    }

    if (stream.Peek().GetType() == kLeftBraceToken ||
        AbortsNestedSelectorParsing(stream.Peek().GetType(),
                                    semicolon_aborts_nested_selector_,
                                    nesting_type)) {
      break;
    }

    DCHECK_EQ(stream.Peek().GetType(), kCommaToken);
    stream.ConsumeIncludingWhitespace();
  }

  return reset_vector.CommitAddedElements();
}

CSSSelectorList* CSSSelectorParser::ConsumeCompoundSelectorList(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  ResetVectorAfterScope reset_vector(output_);

  base::span<CSSSelector> selector =
      ConsumeCompoundSelector(stream, CSSNestingType::kNone, result_flags);
  stream.ConsumeWhitespace();
  if (selector.empty()) {
    return nullptr;
  }
  MarkAsEntireComplexSelector(selector);
  while (!stream.AtEnd() && stream.Peek().GetType() == kCommaToken) {
    stream.ConsumeIncludingWhitespace();
    selector =
        ConsumeCompoundSelector(stream, CSSNestingType::kNone, result_flags);
    stream.ConsumeWhitespace();
    if (selector.empty()) {
      return nullptr;
    }
    MarkAsEntireComplexSelector(selector);
  }

  if (failed_parsing_) {
    return nullptr;
  }

  return CSSSelectorList::AdoptSelectorVector(reset_vector.AddedElements());
}

CSSSelectorList* CSSSelectorParser::ConsumeNestedSelectorList(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  if (inside_compound_pseudo_) {
    return ConsumeCompoundSelectorList(stream, result_flags);
  }

  ResetVectorAfterScope reset_vector(output_);
  base::span<CSSSelector> result =
      ConsumeComplexSelectorList(stream, CSSNestingType::kNone, result_flags);
  if (result.empty()) {
    return {};
  } else {
    CSSSelectorList* selector_list =
        CSSSelectorList::AdoptSelectorVector(result);
    return selector_list;
  }
}

CSSSelectorList* CSSSelectorParser::ConsumeForgivingNestedSelectorList(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  if (inside_compound_pseudo_) {
    return ConsumeForgivingCompoundSelectorList(stream, result_flags);
  }
  ResetVectorAfterScope reset_vector(output_);
  std::optional<base::span<CSSSelector>> forgiving_list =
      ConsumeForgivingComplexSelectorList(stream, CSSNestingType::kNone,
                                          result_flags);
  if (!forgiving_list.has_value()) {
    return nullptr;
  }
  return CSSSelectorList::AdoptSelectorVector(forgiving_list.value());
}

std::optional<base::span<CSSSelector>>
CSSSelectorParser::ConsumeForgivingComplexSelectorList(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    ResultFlags& result_flags) {
  if (in_supports_parsing_) {
    base::span<CSSSelector> selectors =
        ConsumeComplexSelectorList(stream, nesting_type, result_flags);
    if (selectors.empty()) {
      return std::nullopt;
    } else {
      return selectors;
    }
  }

  ResetVectorAfterScope reset_vector(output_);

  bool first_in_complex_selector_list = true;
  while (!stream.AtEnd()) {
    base::AutoReset<bool> reset_failure(&failed_parsing_, false);
    CSSParserTokenStream::State state = stream.Save();
    wtf_size_t subpos = output_.size();
    base::span<CSSSelector> selector = ConsumeComplexSelector(
        stream, nesting_type, first_in_complex_selector_list, result_flags);
    if (selector.empty() || failed_parsing_ ||
        !AtEndOfComplexSelector(stream)) {
      output_.resize(subpos);  // Drop what we parsed so far.
      stream.Restore(state);
      AddPlaceholderSelectorIfNeeded(
          stream);  // Forwards until the end of the argument (i.e. to comma or
                    // EOB).
    }
    if (stream.Peek().GetType() != kCommaToken) {
      break;
    }
    stream.ConsumeIncludingWhitespace();
    first_in_complex_selector_list = false;
  }

  if (reset_vector.AddedElements().empty()) {
    //  Parsed nothing that was supported.
    return base::span<CSSSelector>();
  }

  return reset_vector.CommitAddedElements();
}

static CSSNestingType ConsumeUntilCommaAndFindNestingType(
    CSSParserTokenStream& stream) {
  CSSNestingType nesting_type = CSSNestingType::kNone;
  CSSParserToken previous_token(kIdentToken);

  while (!stream.AtEnd()) {
    const CSSParserToken& token = stream.Peek();
    if (token.GetBlockType() == CSSParserToken::kBlockStart) {
      CSSParserTokenStream::BlockGuard block(stream);
      while (!stream.AtEnd()) {
        nesting_type =
            std::max(nesting_type, ConsumeUntilCommaAndFindNestingType(stream));
        if (!stream.AtEnd()) {
          DCHECK_EQ(stream.Peek().GetType(), kCommaToken);
          stream.Consume();
        }
      }
      continue;
    }
    if (token.GetType() == kCommaToken) {
      // End of this argument.
      break;
    }
    if (token.GetType() == kDelimiterToken && token.Delimiter() == '&') {
      nesting_type = std::max(nesting_type, CSSNestingType::kNesting);
    }
    if (previous_token.GetType() == kColonToken &&
        token.GetType() == kIdentToken &&
        EqualIgnoringASCIICase(token.Value(), "scope")) {
      nesting_type = CSSNestingType::kScope;
    }

    previous_token = token;
    stream.Consume();
  }
  return nesting_type;
}

// If the argument was unparsable but contained a parent-referencing selector
// (& or :scope), we need to keep it so that we still consider the :is()
// as containing that selector; furthermore, we need to keep it on serialization
// so that a round-trip doesn't lose this information.
// We do not preserve comments fully.
//
// Note that this forwards the stream to the end of the argument (either to the
// next comma on the same nesting level, or the end of block).
void CSSSelectorParser::AddPlaceholderSelectorIfNeeded(
    CSSParserTokenStream& stream) {
  wtf_size_t start = stream.LookAheadOffset();
  CSSNestingType nesting_type = ConsumeUntilCommaAndFindNestingType(stream);
  stream.EnsureLookAhead();
  wtf_size_t end = stream.LookAheadOffset();

  if (nesting_type != CSSNestingType::kNone) {
    CSSSelector placeholder_selector;
    placeholder_selector.SetMatch(CSSSelector::kPseudoClass);
    placeholder_selector.SetUnparsedPlaceholder(
        nesting_type,
        stream.StringRangeAt(start, end - start).ToAtomicString());
    placeholder_selector.SetLastInComplexSelector(true);
    output_.push_back(placeholder_selector);
  }
}

CSSSelectorList* CSSSelectorParser::ConsumeForgivingCompoundSelectorList(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  if (in_supports_parsing_) {
    CSSSelectorList* selector_list =
        ConsumeCompoundSelectorList(stream, result_flags);
    if (!selector_list || !selector_list->IsValid()) {
      return nullptr;
    }
    return selector_list;
  }

  ResetVectorAfterScope reset_vector(output_);
  while (!stream.AtEnd()) {
    base::AutoReset<bool> reset_failure(&failed_parsing_, false);
    wtf_size_t subpos = output_.size();
    base::span<CSSSelector> selector =
        ConsumeCompoundSelector(stream, CSSNestingType::kNone, result_flags);
    stream.ConsumeWhitespace();
    if (selector.empty() || failed_parsing_ ||
        (!stream.AtEnd() && stream.Peek().GetType() != kCommaToken)) {
      output_.resize(subpos);  // Drop what we parsed so far.
      stream.SkipUntilPeekedTypeIs<kCommaToken>();
    } else {
      MarkAsEntireComplexSelector(selector);
    }
    if (!stream.AtEnd()) {
      stream.ConsumeIncludingWhitespace();
    }
  }

  if (reset_vector.AddedElements().empty()) {
    return CSSSelectorList::Empty();
  }

  return CSSSelectorList::AdoptSelectorVector(reset_vector.AddedElements());
}

CSSSelectorList* CSSSelectorParser::ConsumeForgivingRelativeSelectorList(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  if (in_supports_parsing_) {
    CSSSelectorList* selector_list =
        ConsumeRelativeSelectorList(stream, result_flags);
    if (!selector_list || !selector_list->IsValid()) {
      return nullptr;
    }
    return selector_list;
  }

  ResetVectorAfterScope reset_vector(output_);
  while (!stream.AtEnd()) {
    base::AutoReset<bool> reset_failure(&failed_parsing_, false);
    CSSParserTokenStream::BlockGuard guard(stream);
    wtf_size_t subpos = output_.size();
    base::span<CSSSelector> selector =
        ConsumeRelativeSelector(stream, result_flags);

    if (selector.empty() || failed_parsing_ ||
        (!stream.AtEnd() && stream.Peek().GetType() != kCommaToken)) {
      output_.resize(subpos);  // Drop what we parsed so far.
      stream.SkipUntilPeekedTypeIs<kCommaToken>();
    }
    if (!stream.AtEnd()) {
      stream.ConsumeIncludingWhitespace();
    }
  }

  // :has() is not allowed in the pseudos accepting only compound selectors, or
  // not allowed after pseudo elements.
  // (e.g. '::slotted(:has(.a))', '::part(foo):has(:hover)')
  if (inside_compound_pseudo_ ||
      restricting_pseudo_element_ != CSSSelector::kPseudoUnknown ||
      reset_vector.AddedElements().empty()) {
    // TODO(blee@igalia.com) Workaround to make :has() unforgiving to avoid
    // JQuery :has() issue: https://github.com/w3c/csswg-drafts/issues/7676
    // Should return empty CSSSelectorList. (return CSSSelectorList::Empty())
    return nullptr;
  }

  return CSSSelectorList::AdoptSelectorVector(reset_vector.AddedElements());
}

CSSSelectorList* CSSSelectorParser::ConsumeRelativeSelectorList(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  ResetVectorAfterScope reset_vector(output_);
  if (ConsumeRelativeSelector(stream, result_flags).empty()) {
    return nullptr;
  }
  while (!stream.AtEnd() && stream.Peek().GetType() == kCommaToken) {
    stream.ConsumeIncludingWhitespace();
    if (ConsumeRelativeSelector(stream, result_flags).empty()) {
      return nullptr;
    }
  }

  if (failed_parsing_) {
    return nullptr;
  }

  // :has() is not allowed in the pseudos accepting only compound selectors, or
  // not allowed after pseudo elements.
  // (e.g. '::slotted(:has(.a))', '::part(foo):has(:hover)')
  if (inside_compound_pseudo_ ||
      restricting_pseudo_element_ != CSSSelector::kPseudoUnknown ||
      reset_vector.AddedElements().empty()) {
    return nullptr;
  }

  return CSSSelectorList::AdoptSelectorVector(reset_vector.AddedElements());
}

namespace {

enum CompoundSelectorFlags {
  kHasPseudoElementForRightmostCompound = 1 << 0,
};

unsigned ExtractCompoundFlags(const CSSSelector& simple_selector,
                              CSSParserMode parser_mode) {
  if (simple_selector.Match() != CSSSelector::kPseudoElement) {
    return 0;
  }
  // We don't restrict what follows custom ::-webkit-* pseudo elements in UA
  // sheets. We currently use selectors in mediaControls.css like this:
  //
  // video::-webkit-media-text-track-region-container.scrolling
  if (parser_mode == kUASheetMode &&
      simple_selector.GetPseudoType() ==
          CSSSelector::kPseudoWebKitCustomElement) {
    return 0;
  }
  return kHasPseudoElementForRightmostCompound;
}

unsigned ExtractCompoundFlags(const base::span<CSSSelector> compound_selector,
                              CSSParserMode parser_mode) {
  unsigned compound_flags = 0;
  for (const CSSSelector& simple : compound_selector) {
    if (compound_flags) {
      break;
    }
    compound_flags |= ExtractCompoundFlags(simple, parser_mode);
  }
  return compound_flags;
}

}  // namespace

base::span<CSSSelector> CSSSelectorParser::ConsumeRelativeSelector(
    CSSParserTokenStream& stream,
    ResultFlags& result_flags) {
  ResetVectorAfterScope reset_vector(output_);

  CSSSelector selector;
  selector.SetMatch(CSSSelector::kPseudoClass);
  selector.UpdatePseudoType(AtomicString("-internal-relative-anchor"),
                            *context_, false /*has_arguments*/,
                            context_->Mode());
  DCHECK_EQ(selector.GetPseudoType(), CSSSelector::kPseudoRelativeAnchor);
  output_.push_back(selector);

  CSSSelector::RelationType combinator =
      ConvertRelationToRelative(ConsumeCombinator(stream));
  unsigned previous_compound_flags = 0;

  if (!ConsumePartialComplexSelector(stream, combinator,
                                     previous_compound_flags,
                                     CSSNestingType::kNone, result_flags)) {
    return {};
  }

  // See ConsumeComplexSelector().
  std::reverse(reset_vector.AddedElements().begin(),
               reset_vector.AddedElements().end());

  MarkAsEntireComplexSelector(reset_vector.AddedElements());
  return reset_vector.CommitAddedElements();
}

// This acts like CSSSelector::GetNestingType, except across a whole
// selector list.
//
// A return value of CSSNestingType::kNesting means that the list
// "contains the nesting selector".
// https://drafts.csswg.org/css-nesting-1/#contain-the-nesting-selector
//
// A return value of CSSNestingType::kScope means that the list
// contains the :scope selector.
static CSSNestingType GetNestingTypeForSelectorList(
    const CSSSelector* selector) {
  if (selector == nullptr) {
    return CSSNestingType::kNone;
  }
  CSSNestingType nesting_type = CSSNestingType::kNone;
  for (;;) {  // Termination condition within loop.
    nesting_type = std::max(nesting_type, selector->GetNestingType());
    if (selector->SelectorList() != nullptr) {
      nesting_type = std::max(
          nesting_type,
          GetNestingTypeForSelectorList(selector->SelectorList()->First()));
    }
    if (selector->IsLastInSelectorList() ||
        nesting_type == CSSNestingType::kNesting) {
      break;
    }
    ++selector;
  }
  return nesting_type;
}

// https://drafts.csswg.org/selectors/#relative-selector-anchor-elements
static CSSSelector CreateImplicitAnchor(
    CSSNestingType nesting_type,
    const StyleRule* parent_rule_for_nesting) {
  DCHECK(nesting_type == CSSNestingType::kNesting ||
         nesting_type == CSSNestingType::kScope);
  CSSSelector selector =
      (nesting_type == CSSNestingType::kNesting)
          ? CSSSelector(parent_rule_for_nesting, /*is_implicit=*/true)
          : CSSSelector(AtomicString("scope"), /*is_implicit=*/true);
  selector.SetScopeContaining(true);
  return selector;
}

static std::optional<CSSSelector> MaybeCreateImplicitDescendantAnchor(
    CSSNestingType nesting_type,
    const StyleRule* parent_rule_for_nesting,
    const CSSSelector* selector) {
  switch (nesting_type) {
    case CSSNestingType::kNone:
      break;
    case CSSNestingType::kScope:
    case CSSNestingType::kNesting:
      static_assert(CSSNestingType::kNone < CSSNestingType::kScope);
      static_assert(CSSNestingType::kScope < CSSNestingType::kNesting);
      // For kNesting, we should only produce an implied descendant combinator
      // if the selector list is not nest-containing.
      //
      // For kScope, we should should only produce an implied descendant
      // combinator if the selector list is not :scope-containing. Note however
      // that selectors which are nest-containing are also treated as
      // :scope-containing.
      if (GetNestingTypeForSelectorList(selector) < nesting_type) {
        return CreateImplicitAnchor(nesting_type, parent_rule_for_nesting);
      }
      break;
  }
  return std::nullopt;
}

// A nested rule that starts with a combinator; very similar to
// ConsumeRelativeSelector() (but we don't use the kRelative* relations,
// as they have different matching semantics). There's an implicit anchor
// compound in front, which for CSSNestingType::kNesting is the nesting
// selector (&) and for CSSNestingType::kScope is the :scope pseudo class.
// E.g. given CSSNestingType::kNesting, “> .a” is parsed as “& > .a” ().
base::span<CSSSelector> CSSSelectorParser::ConsumeNestedRelativeSelector(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    ResultFlags& result_flags) {
  DCHECK_NE(nesting_type, CSSNestingType::kNone);

  ResetVectorAfterScope reset_vector(output_);
  output_.push_back(
      CreateImplicitAnchor(nesting_type, parent_rule_for_nesting_));
  result_flags |= kContainsScopeOrParent;
  CSSSelector::RelationType combinator = ConsumeCombinator(stream);
  unsigned previous_compound_flags = 0;
  if (!ConsumePartialComplexSelector(stream, combinator,
                                     previous_compound_flags, nesting_type,
                                     result_flags)) {
    return {};
  }

  std::reverse(reset_vector.AddedElements().begin(),
               reset_vector.AddedElements().end());

  MarkAsEntireComplexSelector(reset_vector.AddedElements());
  return reset_vector.CommitAddedElements();
}

base::span<CSSSelector> CSSSelectorParser::ConsumeComplexSelector(
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    bool first_in_complex_selector_list,
    ResultFlags& result_flags) {
  if (nesting_type != CSSNestingType::kNone && PeekIsCombinator(stream)) {
    // Nested selectors that start with a combinator are to be
    // interpreted as relative selectors (with the anchor being
    // the parent selector, i.e., &).
    return ConsumeNestedRelativeSelector(stream, nesting_type, result_flags);
  }

  ResetVectorAfterScope reset_vector(output_);
  base::span<CSSSelector> compound_selector =
      ConsumeCompoundSelector(stream, nesting_type, result_flags);
  if (compound_selector.empty()) {
    return {};
  }

  // Reverse the compound selector, so that it comes out properly
  // after we reverse everything below.
  std::reverse(compound_selector.begin(), compound_selector.end());

  if (CSSSelector::RelationType combinator = ConsumeCombinator(stream)) {
    result_flags |= kContainsComplexSelector;
    unsigned previous_compound_flags =
        ExtractCompoundFlags(compound_selector, context_->Mode());
    if (!ConsumePartialComplexSelector(stream, combinator,
                                       previous_compound_flags, nesting_type,
                                       result_flags)) {
      return {};
    }
  }

  // Complex selectors (i.e., groups of compound selectors) are stored
  // right-to-left, ie., the opposite direction of what we parse them. However,
  // within each compound selector, the simple selectors are stored
  // left-to-right. The simplest way of doing this in-place is to reverse each
  // compound selector after we've parsed it (which we do above), and then
  // reverse the entire list in the end. So if the CSS text says:
  //
  //   .a.b.c .d.e.f .g.h
  //
  // we first parse and reverse each compound selector:
  //
  //   .c.b.a .f.e.d .h.g
  //
  // and then reverse the entire list, giving the desired in-memory layout:
  //
  //   .g.h .d.e.f .a.b.c
  //
  // The boundaries between the compound selectors are implicit; they are given
  // by having a Relation() not equal to kSubSelector, so they follow
  // automatically when we do the reversal.
  std::reverse(reset_vector.AddedElements().begin(),
               reset_vector.AddedElements().end());

  if (nesting_type != CSSNestingType::kNone) {
    // In nested top-level rules, if we do not have a & anywhere in the list,
    // we are a relative selector (with & as the anchor), and we must prepend
    // (or append, since we're storing reversed) an implicit & using
    // a descendant combinator.
    //
    // We need to temporarily mark the end of the selector list, for the benefit
    // of GetNestingTypeForSelectorList().
    wtf_size_t last_index = output_.size() - 1;
    output_[last_index].SetLastInSelectorList(true);
    if (std::optional<CSSSelector> anchor = MaybeCreateImplicitDescendantAnchor(
            nesting_type, parent_rule_for_nesting_,
            reset_vector.AddedElements().data())) {
      output_.back().SetRelation(CSSSelector::kDescendant);
      output_.push_back(anchor.value());
      result_flags |= kContainsScopeOrParent;
    }

    output_[last_index].SetLastInSelectorList(false);
  }

  MarkAsEntireComplexSelector(reset_vector.AddedElements());

  return reset_vector.CommitAddedElements();
}

bool CSSSelectorParser::ConsumePartialComplexSelector(
    CSSParserTokenStream& stream,
    CSSSelector::RelationType& combinator,
    unsigned previous_compound_flags,
    CSSNestingType nesting_type,
    ResultFlags& result_flags) {
  do {
    base::span<CSSSelector> compound_selector =
        ConsumeCompoundSelector(stream, nesting_type, result_flags);
    if (compound_selector.empty()) {
      // No more selectors. If we ended with some explicit combinator
      // (e.g. “a >” and then nothing), that's a parse error.
      // But if not, we're simply done and return everything
      // we've parsed so far.
      return combinator == CSSSelector::kDescendant;
    }
    compound_selector.back().SetRelation(combinator);

    // See ConsumeComplexSelector().
    std::reverse(compound_selector.begin(), compound_selector.end());

    if (previous_compound_flags & kHasPseudoElementForRightmostCompound) {
      // If we've already seen a compound that needs to be rightmost, and still
      // get more, that's a parse error.
      return false;
    }
    previous_compound_flags =
        ExtractCompoundFlags(compound_selector, context_->Mode());
  } while ((combinator = ConsumeCombinator(stream)));

  return true;
}

// static
CSSSelector::PseudoType CSSSelectorParser::ParsePseudoType(
    const AtomicString& name,
    bool has_arguments,
    const Document* document) {
  CSSSelector::PseudoType pseudo_type =
      CSSSelector::NameToPseudoType(name, has_arguments, document);

  if (pseudo_type != CSSSelector::PseudoType::kPseudoUnknown) {
    return pseudo_type;
  }

  if (name.StartsWith("-webkit-")) {
    return CSSSelector::PseudoType::kPseudoWebKitCustomElement;
  }
  if (name.StartsWith("-internal-")) {
    return CSSSelector::PseudoType::kPseudoBlinkInternalElement;
  }
  if (name.StartsWith("--")) {
    String custom_name = name.GetString().Substring(2);
    if (ExecutionContext* context =
            document ? document->GetExecutionContext() : nullptr) {
      Deprecation::CountDeprecation(
          context, WebFeature::kCSSCustomSt
```
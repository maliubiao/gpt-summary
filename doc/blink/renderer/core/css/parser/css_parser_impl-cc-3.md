Response:
My thinking process to analyze the provided code snippet and generate the description goes through these steps:

1. **Understand the Goal:** The request asks for a functional summary of `css_parser_impl.cc`, focusing on its role in parsing CSS, its relationship with HTML and JavaScript, error handling, debugging context, and a final overall summary. The fact that this is part 4 of 4 indicates a need to summarize the specific functionality within *this* snippet, not the entire file.

2. **Initial Code Scan and High-Level Identification:** I quickly skim the code for recognizable keywords and function names related to CSS parsing. Terms like `ConsumeStyleRule`, `ConsumeDeclaration`, `ConsumeAtRuleContents`, `CSSParserTokenStream`, `CSSSelectorParser`, `CSSPropertyValueSet`, and `StyleRule` immediately jump out. These strongly suggest this code is responsible for taking a stream of CSS tokens and building an internal representation of CSS rules.

3. **Focus on Key Functions:** I identify the major functions within the snippet and try to understand their purpose:
    * `ConsumeStyleRule`:  This appears to be the core function for parsing style rules (selectors and declarations).
    * `ConsumeStyleRuleContents`:  Likely handles the content within the curly braces of a style rule (declarations and nested rules).
    * `ConsumeBlockContents`:  A more general function for parsing the content of blocks, used for both style rules and at-rules.
    * `ConsumeDeclaration`:  Parses individual CSS property-value pairs.
    * `ConsumeNestedRule`: Handles parsing of rules nested within other rules (like media queries or other style rules).
    * `ConsumeRuleListOrNestedDeclarationList`: Deals with parsing a list of rules or, in the context of nested group rules, a list of declarations.
    * `ConsumeKeyframeKeyList`:  Specifically parses the keyframe offsets in animation keyframes.

4. **Trace the Flow of Execution:** I mentally trace how these functions might call each other. For instance, `ConsumeStyleRule` likely calls `ConsumeBlockContents` to parse the content within the braces. `ConsumeBlockContents` might then call `ConsumeDeclaration` or `ConsumeNestedRule` based on the encountered tokens. This helps understand the overall parsing process.

5. **Identify Relationships with HTML, CSS, and JavaScript:**
    * **CSS:** The code directly manipulates CSS structures (`StyleRule`, `CSSPropertyValue`). It parses CSS syntax (selectors, properties, values, at-rules). This is its primary function.
    * **HTML:** While this code doesn't directly manipulate the HTML DOM, it's crucial for *styling* the HTML. The parsed CSS rules will eventually be used to determine how HTML elements are rendered. The example of a selector like `.foo` targeting an HTML element is a good illustration.
    * **JavaScript:**  JavaScript can interact with CSS in several ways. It can dynamically modify styles (e.g., `element.style.color = 'red'`), access computed styles, and potentially trigger style recalculations. This code is part of the engine that *interprets* the CSS that JavaScript might interact with.

6. **Look for Logic and Edge Cases:** I examine the conditional statements (`if`, `switch`) and loops (`while`) to understand the decision-making processes within the parser. I look for special handling of things like:
    * `@` rules (at-rules like `@media`).
    * Nested rules.
    * Important flags (`!important`).
    * Custom properties (`--variable`).
    * Potential parsing errors and error recovery (`SkipUntilPeekedTypeIs`).
    * Lazy parsing (`CSSLazyPropertyParserImpl`).

7. **Consider User/Programming Errors:** Based on the parsing logic, I think about common mistakes developers might make that would lead the parser to execute this code path:
    * Syntax errors in CSS (e.g., missing semicolons, invalid property names).
    * Incorrectly nesting rules.
    * Using custom properties in invalid contexts.

8. **Imagine the Debugging Scenario:** I try to envision how a developer might end up debugging this specific code. This often involves inspecting the call stack when a style is not being applied as expected or when the browser reports a CSS parsing error. Setting breakpoints within these `Consume...` functions would be a natural step.

9. **Synthesize and Organize the Information:** Finally, I structure the gathered information into the requested categories:
    * **Functionality:**  Provide a concise overview of the code's core purpose.
    * **Relationship to HTML, CSS, and JavaScript:** Explain how this code interacts with or enables these technologies. Use concrete examples.
    * **Logic and Reasoning (Hypothetical Input/Output):**  Create simplified scenarios to illustrate the behavior of key functions.
    * **User/Programming Errors:** Give practical examples of mistakes that would involve this code.
    * **User Operation as Debugging Clue:** Describe the steps a user takes that eventually lead to this code being executed during rendering, highlighting the debugging relevance.
    * **Overall Functionality (Part 4 Summary):**  Specifically summarize the functionality present within *this* code snippet, recognizing it as a part of a larger parsing process.

10. **Refine and Review:** I reread my explanation to ensure clarity, accuracy, and completeness, checking against the code to confirm my interpretations. I make sure to address all aspects of the original request. For example, noting the lazy parsing optimization or the handling of comments observed by the `observer_`.

By following these steps, I can generate a comprehensive and informative description of the provided code snippet, addressing all the key points in the prompt. The iterative nature of this process (scanning, focusing, tracing, considering errors, etc.) helps ensure that I don't miss important details and that the final explanation is well-structured and easy to understand.
这是 `blink/renderer/core/css/parser/css_parser_impl.cc` 文件的第四部分，主要涵盖了 CSS 解析器实现中处理样式规则（style rules）、块内容（block contents）、声明（declarations）以及关键帧（keyframes）相关的逻辑。

**功能归纳:**

这部分代码的核心功能是：

1. **解析样式规则 (Style Rules):**  `ConsumeStyleRule` 函数负责解析 CSS 样式规则，包括选择器（selectors）和声明块（declaration block）。它会利用 `CSSSelectorParser` 来解析选择器，并处理嵌套规则的情况。
2. **处理块内容 (Block Contents):** `ConsumeBlockContents` 函数负责解析样式规则或 at-rule 的声明块内的内容。它可以处理声明（属性-值对）和嵌套的规则。
3. **解析声明 (Declarations):** `ConsumeDeclaration` 函数负责解析单个 CSS 声明，即属性名和属性值。它会识别属性名，调用相应的解析器来解析属性值，并处理 `!important` 标志。
4. **解析变量值 (Variable Values):** `ConsumeVariableValue` 函数专门用于解析 CSS 自定义属性（变量）的值。
5. **解析声明值 (Declaration Values):** `ConsumeDeclarationValue` 函数调用 `CSSPropertyParser` 来解析各种 CSS 属性的特定值。
6. **解析关键帧列表 (Keyframe Key List):** `ConsumeKeyframeKeyList` 函数用于解析 `@keyframes` 规则中关键帧的偏移量列表 (`from`, `to`, 或百分比)。
7. **处理嵌套规则 (Nested Rules):** `ConsumeNestedRule` 函数用于递归地解析嵌套在其他规则内的规则，例如 media query 内的样式规则。
8. **处理规则列表或嵌套声明列表:** `ConsumeRuleListOrNestedDeclarationList` 用于解析一系列的规则，或者在嵌套的组规则中，直接解析一系列的声明。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这部分代码是 CSS 解析器的核心，直接负责理解 CSS 语法。它将 CSS 文本转换为浏览器可以理解和使用的内部数据结构。
    * **例子:**  当解析到 `.foo { color: red; }` 时，`ConsumeStyleRule` 会识别出选择器 `.foo`，然后 `ConsumeBlockContents` 会调用 `ConsumeDeclaration` 来解析 `color: red;` 这个声明。
* **HTML:**  解析后的 CSS 规则会被应用到 HTML 元素上，从而控制页面的样式。
    * **例子:**  如果 HTML 中存在 `<div class="foo"></div>`，并且 CSS 中有 `.foo { color: red; }`，那么解析器会解析这个 CSS 规则，最终使得这个 `div` 元素的文字颜色变为红色。
* **Javascript:**  JavaScript 可以通过 DOM API (例如 `element.style.color = 'blue'`)  动态修改元素的样式。浏览器内部也需要解析这些通过 JavaScript 设置的样式。此外，CSSOM (CSS Object Model) 允许 JavaScript 访问和操作 CSS 规则。这部分代码生成的内部 CSS 结构会被 JavaScript 使用。
    * **例子:**  当 JavaScript 执行 `document.querySelector('.foo').style.fontSize = '16px'` 时，浏览器内部的 CSS 解析器（可能包含 `CSSParserImpl`）需要解析 `'16px'` 这个值并应用到对应的元素上。

**逻辑推理的假设输入与输出:**

假设输入一段简单的 CSS 样式规则：

```css
.bar {
  font-size: 14px;
}
```

**`ConsumeStyleRule` 函数的推断过程:**

1. **输入:**  一个指向 CSS token 流的迭代器，当前指向 `.bar`。
2. **假设:**  `CSSSelectorParser::ConsumeSelector` 被调用来解析选择器 `.bar`。
3. **中间状态:**  `selector_vector` 包含了表示选择器 `.bar` 的数据结构。
4. **假设:**  遇到左大括号 `{`，表明开始解析声明块。
5. **调用:** `ConsumeBlockContents` 函数被调用来处理声明块的内容。
6. **`ConsumeBlockContents` 函数的推断过程:**
   * **输入:**  指向 `font-size` token 的迭代器。
   * **调用:** `ConsumeDeclaration` 函数被调用来解析 `font-size: 14px;`。
   * **`ConsumeDeclaration` 函数的推断过程:**
     * **输入:** 指向 `font-size` token 的迭代器。
     * **识别:** 识别出属性名 `font-size`。
     * **假设:** 遇到冒号 `:`。
     * **调用:** `ConsumeDeclarationValue` 函数被调用来解析 `14px`。
     * **`ConsumeDeclarationValue` 函数的推断过程:**
       * **输入:** 指向 `14px` token 的迭代器。
       * **调用:** `CSSPropertyParser::ParseValue` (针对 `font-size` 属性) 被调用，解析出数值 `14` 和单位 `px`。
   * **中间状态:** `parsed_properties_` 包含了表示 `font-size: 14px` 的 `CSSPropertyValue` 对象。
   * **假设:** 遇到右大括号 `}`，声明块解析完成。
7. **输出:**  返回一个 `StyleRule` 对象，其中包含了选择器 `.bar` 和一个包含 `font-size: 14px` 属性的 `CSSPropertyValueSet`。

**用户或编程常见的使用错误举例说明:**

1. **CSS 语法错误:** 用户在编写 CSS 时可能犯语法错误，例如忘记分号、冒号，或者使用了无效的属性名或值。
   * **例子:** `.baz { color red }` (缺少冒号)。当解析到这里时，`ConsumeDeclaration` 可能会因为找不到冒号而返回 `false`。
2. **嵌套规则错误:**  在不允许嵌套规则的地方使用了嵌套规则。
   * **例子:**  在普通的样式规则中直接写另一个样式规则，而不是在 `@media` 等容器内。这会导致 `ConsumeBlockContents` 在遇到非声明的 token 时，尝试调用 `ConsumeNestedRule`，但如果上下文不允许，可能会导致解析错误。
3. **自定义属性使用错误:** 在不支持自定义属性的上下文中使用了自定义属性。
   * **例子:** 在 `keyframes` 规则中直接使用自定义属性作为普通属性。 `ConsumeDeclaration` 在遇到自定义属性时，会调用 `ConsumeVariableValue`，但如果 `rule_type` 不允许，可能不会正确处理。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址并访问网页，或打开本地 HTML 文件。**
2. **浏览器开始解析 HTML 文档。**
3. **在解析 HTML 的过程中，浏览器遇到 `<style>` 标签或 `<link>` 标签引用的 CSS 文件。**
4. **浏览器加载 CSS 文本。**
5. **CSS 解析器开始工作，将 CSS 文本转换为内部表示。**
6. **`CSSParserImpl` 类的实例被创建，并开始逐个解析 CSS token。**
7. **当解析到样式规则时，例如 `.my-class { ... }`，控制流会进入 `ConsumeStyleRule` 函数。**
8. **在 `ConsumeStyleRule` 中，选择器部分会由 `CSSSelectorParser` 处理。**
9. **当遇到声明块的开始 `{` 时，会调用 `ConsumeBlockContents`。**
10. **在 `ConsumeBlockContents` 中，对于每个声明，会调用 `ConsumeDeclaration`。**
11. **如果声明的值需要进一步解析，例如 `font-size: 14px;`，则会调用 `ConsumeDeclarationValue`。**

**作为调试线索：**  如果开发者发现页面的样式没有按预期显示，或者浏览器报错提示 CSS 语法错误，那么他们可能会：

* **检查浏览器的开发者工具 (Elements 面板 和 Console 面板)。**
* **在 Elements 面板中查看元素的 Computed 样式，看是否有样式被覆盖或者没有生效。**
* **在 Console 面板中查看是否有 CSS 解析错误的信息。**
* **如果怀疑是某个特定的 CSS 规则导致问题，他们可能会尝试修改 CSS 代码并刷新页面。**
* **更高级的调试可能涉及到在 Chromium 的源代码中设置断点，例如在 `ConsumeStyleRule` 或 `ConsumeDeclaration` 等函数中，来跟踪 CSS 解析的具体过程，查看解析器是如何处理特定的 CSS 代码，以及在哪里发生了错误。**

总而言之，这部分代码是 Chromium Blink 引擎中 CSS 解析器的核心组成部分，负责将 CSS 文本转化为浏览器可以理解和应用的内部结构，是实现网页样式渲染的关键环节。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_parser_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
 sizeof(LChar) : sizeof(UChar);
  auto text_bytes = base::as_chars(
      text.RawByteSpan().subspan(offset * char_size, length * char_size));
  return memchr(text_bytes.data(), '{', text_bytes.size()) != nullptr;
}

StyleRule* CSSParserImpl::ConsumeStyleRule(CSSParserTokenStream& stream,
                                           CSSNestingType nesting_type,
                                           StyleRule* parent_rule_for_nesting,
                                           bool is_within_scope,
                                           bool nested,
                                           bool& invalid_rule_error) {
  if (!in_nested_style_rule_) {
    DCHECK_EQ(0u, arena_.size());
  }
  auto func_clear_arena = [&](HeapVector<CSSSelector>* arena) {
    if (!in_nested_style_rule_) {
      arena->resize(0);  // See class comment on CSSSelectorParser.
    }
  };
  std::unique_ptr<HeapVector<CSSSelector>, decltype(func_clear_arena)>
      scope_guard(&arena_, std::move(func_clear_arena));

  if (observer_) {
    observer_->StartRuleHeader(StyleRule::kStyle, stream.LookAheadOffset());
  }

  // Style rules that look like custom property declarations
  // are not allowed by css-syntax.
  //
  // https://drafts.csswg.org/css-syntax/#consume-qualified-rule
  bool custom_property_ambiguity = false;
  if (CSSVariableParser::IsValidVariableName(stream.Peek())) {
    CSSParserTokenStream::State state = stream.Save();
    stream.ConsumeIncludingWhitespace();  // <ident>
    custom_property_ambiguity = stream.Peek().GetType() == kColonToken;
    stream.Restore(state);
  }

  bool has_visited_pseudo = false;
  // Parse the prelude of the style rule
  base::span<CSSSelector> selector_vector = CSSSelectorParser::ConsumeSelector(
      stream, context_, nesting_type, parent_rule_for_nesting, is_within_scope,
      /* semicolon_aborts_nested_selector*/ nested, style_sheet_, observer_,
      arena_, &has_visited_pseudo);

  if (selector_vector.empty()) {
    // Read the rest of the prelude if there was an error
    stream.EnsureLookAhead();
    if (nested) {
      stream.SkipUntilPeekedTypeIs<kLeftBraceToken, kSemicolonToken>();
    } else {
      stream.SkipUntilPeekedTypeIs<kLeftBraceToken>();
    }
  }

  if (observer_) {
    observer_->EndRuleHeader(stream.LookAheadOffset());
  }

  if (stream.Peek().GetType() != kLeftBraceToken) {
    // Parse error, EOF instead of qualified rule block
    // (or we went into error recovery above).
    // NOTE: If we aborted due to a semicolon, don't consume it here;
    // the caller will do that for us.
    return nullptr;
  }

  if (custom_property_ambiguity) {
    if (nested) {
      // https://drafts.csswg.org/css-syntax/#consume-the-remnants-of-a-bad-declaration
      // Note that the caller consumes the bad declaration remnants
      // (see ConsumeBlockContents).
      return nullptr;
    }
    // "If nested is false, consume a block from input, and return nothing."
    // https://drafts.csswg.org/css-syntax/#consume-qualified-rule
    CSSParserTokenStream::BlockGuard guard(stream);
    return nullptr;
  }
  // Check if rule is "valid in current context".
  // https://drafts.csswg.org/css-syntax/#consume-qualified-rule
  //
  // This means checking if the selector parsed successfully.
  if (selector_vector.empty()) {
    CSSParserTokenStream::BlockGuard guard(stream);
    invalid_rule_error = true;
    return nullptr;
  }

  if (RuntimeEnabledFeatures::CSSLazyParsingFastPathEnabled()) {
    // TODO(csharrison): How should we lazily parse css that needs the observer?
    if (!observer_ && lazy_state_) {
      DCHECK(style_sheet_);

      StringView text(stream.RemainingText(), 1);
#ifdef ARCH_CPU_X86_FAMILY
      wtf_size_t len;
      if (base::CPU::GetInstanceNoAllocation().has_avx2()) {
        len = static_cast<wtf_size_t>(FindLengthOfDeclarationListAVX2(text));
      } else {
        len = static_cast<wtf_size_t>(FindLengthOfDeclarationList(text));
      }
#else
      wtf_size_t len =
          static_cast<wtf_size_t>(FindLengthOfDeclarationList(text));
#endif
      if (len != 0) {
        wtf_size_t block_start_offset = stream.Offset();
        stream.SkipToEndOfBlock(len + 2);  // +2 for { and }.
        return StyleRule::Create(
            selector_vector, MakeGarbageCollected<CSSLazyPropertyParserImpl>(
                                 block_start_offset, lazy_state_));
      }
    }
    CSSParserTokenStream::BlockGuard guard(stream);
    return ConsumeStyleRuleContents(selector_vector, stream, is_within_scope,
                                    has_visited_pseudo);
  } else {
    CSSParserTokenStream::BlockGuard guard(stream);

    // TODO(csharrison): How should we lazily parse css that needs the observer?
    if (!observer_ && lazy_state_) {
      DCHECK(style_sheet_);

      wtf_size_t block_start_offset = stream.Offset() - 1;  // - 1 for the {.
      guard.SkipToEndOfBlock();
      wtf_size_t block_length = stream.Offset() - block_start_offset;

      // Lazy parsing cannot deal with nested rules. We make a very quick check
      // to see if there could possibly be any in there; if so, we need to go
      // back to normal (non-lazy) parsing. If that happens, we've wasted some
      // work; specifically, the SkipToEndOfBlock(), and potentially that we
      // cannot use the CachedCSSTokenizer if that would otherwise be in use.
      if (MayContainNestedRules(lazy_state_->SheetText(), block_start_offset,
                                block_length)) {
        CSSParserTokenStream block_stream(lazy_state_->SheetText(),
                                          block_start_offset);
        CSSParserTokenStream::BlockGuard sub_guard(
            block_stream);  // Consume the {, and open the block stack.
        return ConsumeStyleRuleContents(selector_vector, block_stream,
                                        is_within_scope, has_visited_pseudo);
      }

      return StyleRule::Create(selector_vector,
                               MakeGarbageCollected<CSSLazyPropertyParserImpl>(
                                   block_start_offset, lazy_state_));
    }
    return ConsumeStyleRuleContents(selector_vector, stream, is_within_scope,
                                    has_visited_pseudo);
  }
}

StyleRule* CSSParserImpl::ConsumeStyleRuleContents(
    base::span<CSSSelector> selector_vector,
    CSSParserTokenStream& stream,
    bool is_within_scope,
    bool has_visited_pseudo) {
  StyleRule* style_rule = StyleRule::Create(selector_vector);
  HeapVector<Member<StyleRuleBase>, 4> child_rules;
  if (observer_) {
    observer_->StartRuleBody(stream.Offset());
  }
  ConsumeBlockContents(stream, StyleRule::kStyle, CSSNestingType::kNesting,
                       /*parent_rule_for_nesting=*/style_rule, is_within_scope,
                       /*nested_declarations_start_index=*/kNotFound,
                       &child_rules, has_visited_pseudo);
  if (observer_) {
    observer_->EndRuleBody(stream.LookAheadOffset());
  }
  for (StyleRuleBase* child_rule : child_rules) {
    style_rule->AddChildRule(child_rule);
  }
  style_rule->SetProperties(CreateCSSPropertyValueSet(
      parsed_properties_, context_->Mode(), context_->GetDocument()));
  return style_rule;
}

// https://drafts.csswg.org/css-syntax/#consume-block-contents
//
// Consumes declarations and/or child rules from the block of a style rule
// or an at-rule (e.g. @media).
//
// The `nested_declarations_start_index` parameter controls how this function
// emits "nested declaration" rules for the leading block of declarations.
// For regular style rules (which can hold declarations directly), this should
// be kNotFound, which will prevent a wrapper rule for the leading block.
// (Subsequent declarations "interleaved" with child rules will still be
// wrapped). For nested group rules, or generally rules that cannot hold
// declarations directly (e.g. @media), the parameter value should be 0u,
// causing the leading declarations to get wrapped as well.
void CSSParserImpl::ConsumeBlockContents(
    CSSParserTokenStream& stream,
    StyleRule::RuleType rule_type,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    wtf_size_t nested_declarations_start_index,
    HeapVector<Member<StyleRuleBase>, 4>* child_rules,
    bool has_visited_pseudo) {
  DCHECK(parsed_properties_.empty());

  while (true) {
    // Having a lookahead may skip comments, which are used by the observer.
    DCHECK(!stream.HasLookAhead() || stream.AtEnd());

    if (observer_ && !stream.HasLookAhead()) {
      while (true) {
        wtf_size_t start_offset = stream.Offset();
        if (!stream.ConsumeCommentOrNothing()) {
          break;
        }
        observer_->ObserveComment(start_offset, stream.Offset());
      }
    }

    if (stream.AtEnd()) {
      break;
    }

    switch (stream.UncheckedPeek().GetType()) {
      case kWhitespaceToken:
      case kSemicolonToken:
        stream.UncheckedConsume();
        break;
      case kAtKeywordToken: {
        CSSParserToken name_token = stream.ConsumeIncludingWhitespace();
        const StringView name = name_token.Value();
        const CSSAtRuleID id = CssAtRuleID(name);
        bool invalid_rule_error_ignored = false;
        StyleRuleBase* child = ConsumeNestedRule(
            id, rule_type, stream, nesting_type, parent_rule_for_nesting,
            is_within_scope, invalid_rule_error_ignored);
        // "Consume an at-rule" can't return invalid-rule-error.
        // https://drafts.csswg.org/css-syntax/#consume-at-rule
        DCHECK(!invalid_rule_error_ignored);
        if (child && child_rules) {
          EmitNestedDeclarationsRuleIfNeeded(
              nesting_type, parent_rule_for_nesting,
              nested_declarations_start_index, *child_rules);
          nested_declarations_start_index = parsed_properties_.size();
          child_rules->push_back(child);
        }
        break;
      }
      case kIdentToken: {
        CSSParserTokenStream::State state = stream.Save();
        bool consumed_declaration = false;
        {
          CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
          consumed_declaration =
              ConsumeDeclaration(stream, rule_type, has_visited_pseudo);
        }
        if (consumed_declaration) {
          if (!stream.AtEnd()) {
            DCHECK_EQ(stream.UncheckedPeek().GetType(), kSemicolonToken);
            stream.UncheckedConsume();  // kSemicolonToken
          }
          break;
        } else if (stream.Peek().GetType() == kSemicolonToken) {
          // As an optimization, we avoid the restart below (retrying as a
          // nested style rule) if we ended on a kSemicolonToken, as this
          // situation can't produce a valid rule.
          stream.UncheckedConsume();  // kSemicolonToken
          break;
        }
        // Retry as nested rule.
        stream.Restore(state);
        [[fallthrough]];
      }
      default:
        if (nesting_type != CSSNestingType::kNone) {
          bool invalid_rule_error = false;
          StyleRuleBase* child = ConsumeNestedRule(
              std::nullopt, rule_type, stream, nesting_type,
              parent_rule_for_nesting, is_within_scope, invalid_rule_error);
          if (child) {
            if (child_rules) {
              EmitNestedDeclarationsRuleIfNeeded(
                  nesting_type, parent_rule_for_nesting,
                  nested_declarations_start_index, *child_rules);
              nested_declarations_start_index = parsed_properties_.size();
              child_rules->push_back(child);
            }
            break;
          } else if (invalid_rule_error) {
            // https://drafts.csswg.org/css-syntax/#invalid-rule-error
            //
            // This means the rule was valid per the "core" grammar of
            // css-syntax, but the prelude (i.e. selector list) didn't parse.
            // We should not fall through to error recovery in this case,
            // because we should continue parsing immediately after
            // the {}-block.
            break;
          }
          // Fall through to error recovery.
          stream.EnsureLookAhead();
        }

        [[fallthrough]];
        // Function tokens should start parsing a declaration
        // (which then immediately goes into error recovery mode).
      case CSSParserTokenType::kFunctionToken:
        stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
        if (!stream.UncheckedAtEnd()) {
          stream.UncheckedConsume();  // kSemicolonToken
        }

        break;
    }
  }

  // We need a final call to EmitNestedDeclarationsRuleIfNeeded in case there
  // are trailing bare declarations. If no child rule has been observed,
  // nested_declarations_start_index is still kNotFound (UINT_MAX),
  // which causes EmitNestedDeclarationsRuleIfNeeded to have no effect.
  if (child_rules) {
    EmitNestedDeclarationsRuleIfNeeded(nesting_type, parent_rule_for_nesting,
                                       nested_declarations_start_index,
                                       *child_rules);
  }
}

// Consumes a list of style rules and stores the result in `child_rules`,
// or (if `is_nested_group_rule` is true) consumes the interior of a nested
// group rule [1]. Nested group rules allow a list of declarations to appear
// directly in place of where a list of rules would normally go.
//
// [1] https://drafts.csswg.org/css-nesting-1/#nested-group-rules
void CSSParserImpl::ConsumeRuleListOrNestedDeclarationList(
    CSSParserTokenStream& stream,
    bool is_nested_group_rule,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    HeapVector<Member<StyleRuleBase>, 4>* child_rules) {
  DCHECK(child_rules);

  if (is_nested_group_rule) {
    // This is a nested group rule, which (in addition to rules) allows
    // *declarations* to appear directly within the body of the rule, e.g.:
    //
    // .foo {
    //    @media (width > 800px) {
    //      color: green;
    //    }
    //  }
    //
    if (RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled()) {
      // Using nested_declarations_start_index=0u here means that the leading
      // declarations will be wrapped in a CSSNestedDeclarations rule.
      // Unlike regular style rules, the leading declarations must be wrapped
      // in something that can hold them, because group rules (e.g. @media)
      // can not hold properties directly.
      ConsumeBlockContents(stream, StyleRule::kStyle, nesting_type,
                           parent_rule_for_nesting, is_within_scope,
                           /* nested_declarations_start_index */ 0u,
                           child_rules);
    } else {
      if (observer_) {
        // Observe an empty rule header to ensure the observer has a new rule
        // data on the stack for the following ConsumeBlockContents.
        observer_->StartRuleHeader(StyleRule::kStyle, stream.Offset());
        observer_->EndRuleHeader(stream.Offset());
        observer_->StartRuleBody(stream.Offset());
      }
      ConsumeBlockContents(stream, StyleRule::kStyle, nesting_type,
                           parent_rule_for_nesting, is_within_scope,
                           /* nested_declarations_start_index */ kNotFound,
                           child_rules);
      if (observer_) {
        observer_->EndRuleBody(stream.LookAheadOffset());
      }
      if (!parsed_properties_.empty()) {
        child_rules->push_front(
            CreateImplicitNestedRule(nesting_type, parent_rule_for_nesting));
      }
    }
  } else {
    ConsumeRuleList(stream, kRegularRuleList, nesting_type,
                    parent_rule_for_nesting, is_within_scope,
                    [child_rules](StyleRuleBase* rule, wtf_size_t) {
                      child_rules->push_back(rule);
                    });
  }
}

namespace {

CSSParserImpl::AllowedRulesType AllowedNestedRuleTypes(
    StyleRule::RuleType parent_rule_type,
    bool in_nested_style_rule) {
  switch (parent_rule_type) {
    case StyleRule::kScope:
      if (!in_nested_style_rule) {
        return CSSParserImpl::kRegularRules;
      }
      [[fallthrough]];
    case StyleRule::kStyle:
      return CSSParserImpl::kNestedGroupRules;
    case StyleRule::kPage:
      return CSSParserImpl::kPageMarginRules;
    default:
      return CSSParserImpl::kNoRules;
  }
}

}  // namespace

StyleRuleBase* CSSParserImpl::ConsumeNestedRule(
    std::optional<CSSAtRuleID> id,
    StyleRule::RuleType parent_rule_type,
    CSSParserTokenStream& stream,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    bool& invalid_rule_error) {
  // A nested style rule. Recurse into the parser; we need to move the parsed
  // properties out of the way while we're parsing the child rule, though.
  // TODO(sesse): The spec says that any properties after a nested rule
  // should be ignored. We don't support this yet.
  // See https://github.com/w3c/csswg-drafts/issues/7501.
  HeapVector<CSSPropertyValue, 64> outer_parsed_properties;
  swap(parsed_properties_, outer_parsed_properties);
  StyleRuleBase* child;
  base::AutoReset<bool> reset_in_nested_style_rule(
      &in_nested_style_rule_,
      in_nested_style_rule_ || parent_rule_type == StyleRule::kStyle);
  if (!id.has_value()) {
    child = ConsumeStyleRule(stream, nesting_type, parent_rule_for_nesting,
                             is_within_scope,
                             /* nested */ true, invalid_rule_error);
  } else {
    child = ConsumeAtRuleContents(
        *id, stream,
        AllowedNestedRuleTypes(parent_rule_type, in_nested_style_rule_),
        nesting_type, parent_rule_for_nesting, is_within_scope);
  }
  parsed_properties_ = std::move(outer_parsed_properties);
  if (child && parent_rule_type != StyleRule::kPage &&
      parent_rule_type != StyleRule::kScope) {
    context_->Count(WebFeature::kCSSNesting);
  }
  return child;
}

// This function can leave the stream in one of the following states:
//
//  1) If the ident token is not immediately followed by kColonToken,
//     then the stream is left at the token where kColonToken was expected.
//  2) If the ident token is not a recognized property/descriptor,
//     then the stream is left at the token immediately after kColonToken.
//  3) Otherwise the stream is is left AtEnd(), regardless of whether or
//     not the value was valid.
//
// Leaving the stream in an awkward states is normally not desirable for
// Consume functions, but declarations are sometimes parsed speculatively,
// which may cause a restart at the call site (see ConsumeBlockContents,
// kIdentToken branch). If we are anyway going to restart, any work we do
// to leave the stream in a more consistent state is just wasted.
bool CSSParserImpl::ConsumeDeclaration(CSSParserTokenStream& stream,
                                       StyleRule::RuleType rule_type,
                                       bool has_visited_pseudo) {
  const wtf_size_t decl_offset_start = stream.Offset();

  DCHECK_EQ(stream.Peek().GetType(), kIdentToken);
  const CSSParserToken& lhs = stream.ConsumeIncludingWhitespace();
  if (stream.Peek().GetType() != kColonToken) {
    return false;  // Parse error.
  }

  stream.UncheckedConsume();  // kColonToken
  stream.EnsureLookAhead();

  size_t properties_count = parsed_properties_.size();

  bool parsing_descriptor = rule_type == StyleRule::kFontFace ||
                            rule_type == StyleRule::kFontPaletteValues ||
                            rule_type == StyleRule::kProperty ||
                            rule_type == StyleRule::kCounterStyle ||
                            rule_type == StyleRule::kViewTransition;

  uint64_t id = parsing_descriptor
                    ? static_cast<uint64_t>(lhs.ParseAsAtRuleDescriptorID())
                    : static_cast<uint64_t>(lhs.ParseAsUnresolvedCSSPropertyID(
                          context_->GetExecutionContext(), context_->Mode()));

  bool important = false;

  static_assert(static_cast<uint64_t>(AtRuleDescriptorID::Invalid) == 0u);
  static_assert(static_cast<uint64_t>(CSSPropertyID::kInvalid) == 0u);

  stream.ConsumeWhitespace();

  if (id) {
    if (parsing_descriptor) {
      const AtRuleDescriptorID atrule_id = static_cast<AtRuleDescriptorID>(id);
      AtRuleDescriptorParser::ParseDescriptorValue(
          rule_type, atrule_id, stream, *context_, parsed_properties_);
    } else {
      const CSSPropertyID unresolved_property = static_cast<CSSPropertyID>(id);
      if (unresolved_property == CSSPropertyID::kVariable) {
        if (rule_type != StyleRule::kStyle && rule_type != StyleRule::kScope &&
            rule_type != StyleRule::kKeyframe) {
          return false;
        }
        AtomicString variable_name = lhs.Value().ToAtomicString();
        bool allow_important_annotation = (rule_type != StyleRule::kKeyframe);
        bool is_animation_tainted = rule_type == StyleRule::kKeyframe;
        if (!ConsumeVariableValue(stream, variable_name,
                                  allow_important_annotation,
                                  is_animation_tainted)) {
          return false;
        }
      } else if (unresolved_property != CSSPropertyID::kInvalid) {
        if (observer_) {
          CSSParserTokenStream::State savepoint = stream.Save();
          ConsumeDeclarationValue(stream, unresolved_property,
                                  /*is_in_declaration_list=*/true, rule_type);

          // The observer would like to know (below) whether this declaration
          // was !important or not. If our parse succeeded, we can just pick it
          // out from the list of properties. If not, we'll need to look at the
          // tokens ourselves.
          if (parsed_properties_.size() != properties_count) {
            important = parsed_properties_.back().IsImportant();
          } else {
            stream.Restore(savepoint);
            // NOTE: This call is solely to update “important”.
            CSSVariableParser::ConsumeUnparsedDeclaration(
                stream, /*allow_important_annotation=*/true,
                /*is_animation_tainted=*/false,
                /*must_contain_variable_reference=*/false,
                /*restricted_value=*/true, /*comma_ends_declaration=*/false,
                important, *context_);
          }
        } else {
          if (context_->IsUseCounterRecordingEnabled() && has_visited_pseudo &&
              unresolved_property == CSSPropertyID::kColumnRuleColor) {
            context_->Count(WebFeature::kVisitedColumnRuleColor);
          }
          ConsumeDeclarationValue(stream, unresolved_property,
                                  /*is_in_declaration_list=*/true, rule_type);
        }
      }
    }
  }
  if (observer_ &&
      (rule_type == StyleRule::kStyle || rule_type == StyleRule::kScope ||
       rule_type == StyleRule::kKeyframe || rule_type == StyleRule::kProperty ||
       rule_type == StyleRule::kPositionTry ||
       rule_type == StyleRule::kFontPaletteValues)) {
    if (!id) {
      // If we skipped the relevant Consume*() calls above due to an invalid
      // property/descriptor, the inspector still needs to know the offset
      // where the would-be declaration ends.
      CSSVariableParser::ConsumeUnparsedDeclaration(
          stream, /*allow_important_annotation=*/true,
          /*is_animation_tainted=*/false,
          /*must_contain_variable_reference=*/false,
          /*restricted_value=*/true, /*comma_ends_declaration=*/false,
          important, *context_);
    }
    // The end offset is the offset of the terminating token, which is peeked
    // but not yet consumed.
    observer_->ObserveProperty(decl_offset_start, stream.LookAheadOffset(),
                               important,
                               parsed_properties_.size() != properties_count);
  }

  return parsed_properties_.size() != properties_count;
}

bool CSSParserImpl::ConsumeVariableValue(CSSParserTokenStream& stream,
                                         const AtomicString& variable_name,
                                         bool allow_important_annotation,
                                         bool is_animation_tainted) {
  stream.EnsureLookAhead();

  // First, see if this is (only) a CSS-wide keyword.
  bool important;
  const CSSValue* value = CSSPropertyParser::ConsumeCSSWideKeyword(
      stream, allow_important_annotation, important);
  if (!value) {
    // It was not, so try to parse it as an unparsed declaration value
    // (which is pretty free-form).
    CSSVariableData* variable_data =
        CSSVariableParser::ConsumeUnparsedDeclaration(
            stream, allow_important_annotation, is_animation_tainted,
            /*must_contain_variable_reference=*/false,
            /*restricted_value=*/false, /*comma_ends_declaration=*/false,
            important, *context_);
    if (!variable_data) {
      return false;
    }

    value = MakeGarbageCollected<CSSUnparsedDeclarationValue>(variable_data,
                                                              context_);
  }
  parsed_properties_.push_back(
      CSSPropertyValue(CSSPropertyName(variable_name), *value, important));
  context_->Count(context_->Mode(), CSSPropertyID::kVariable);
  return true;
}

// NOTE: Leading whitespace must be stripped from the stream, since
// ParseValue() has the same requirement.
void CSSParserImpl::ConsumeDeclarationValue(CSSParserTokenStream& stream,
                                            CSSPropertyID unresolved_property,
                                            bool is_in_declaration_list,
                                            StyleRule::RuleType rule_type) {
  const bool allow_important_annotation = is_in_declaration_list &&
                                          rule_type != StyleRule::kKeyframe &&
                                          rule_type != StyleRule::kPositionTry;
  CSSPropertyParser::ParseValue(unresolved_property, allow_important_annotation,
                                stream, context_, parsed_properties_,
                                rule_type);
}

std::unique_ptr<Vector<KeyframeOffset>> CSSParserImpl::ConsumeKeyframeKeyList(
    const CSSParserContext* context,
    CSSParserTokenStream& stream) {
  std::unique_ptr<Vector<KeyframeOffset>> result =
      std::make_unique<Vector<KeyframeOffset>>();
  while (true) {
    stream.ConsumeWhitespace();
    const CSSParserToken& token = stream.Peek();
    if (token.GetType() == kPercentageToken && token.NumericValue() >= 0 &&
        token.NumericValue() <= 100) {
      result->push_back(KeyframeOffset(TimelineOffset::NamedRange::kNone,
                                       token.NumericValue() / 100));
      stream.ConsumeIncludingWhitespace();
    } else if (token.GetType() == kIdentToken) {
      if (EqualIgnoringASCIICase(token.Value(), "from")) {
        result->push_back(KeyframeOffset(TimelineOffset::NamedRange::kNone, 0));
        stream.ConsumeIncludingWhitespace();
      } else if (EqualIgnoringASCIICase(token.Value(), "to")) {
        result->push_back(KeyframeOffset(TimelineOffset::NamedRange::kNone, 1));
        stream.ConsumeIncludingWhitespace();
      } else {
        auto* stream_name_percent = To<CSSValueList>(
            css_parsing_utils::ConsumeTimelineRangeNameAndPercent(stream,
                                                                  *context));
        if (!stream_name_percent) {
          return nullptr;
        }

        auto stream_name = To<CSSIdentifierValue>(stream_name_percent->Item(0))
                               .ConvertTo<TimelineOffset::NamedRange>();
        auto percent =
            To<CSSPrimitiveValue>(stream_name_percent->Item(1)).GetFloatValue();

        if (!RuntimeEnabledFeatures::ScrollTimelineEnabled() &&
            stream_name != TimelineOffset::NamedRange::kNone) {
          return nullptr;
        }

        result->push_back(KeyframeOffset(stream_name, percent / 100.0));
      }
    } else {
      return nullptr;
    }

    if (stream.Peek().GetType() != kCommaToken) {
      return result;
    }
    stream.Consume();
  }
}

CSSParserMode CSSParserImpl::GetMode() const {
  return context_->Mode();
}

}  // namespace blink

"""


```
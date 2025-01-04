Response:
My thinking process to answer the request about `css_selector_parser.cc` involved several steps:

1. **Understanding the Core Request:** The initial request asks for a summary of the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), illustrative examples, potential user errors, debugging tips, and a final overall summary as part 3 of a series.

2. **Initial Skim and Keyword Identification:** I first skimmed the provided code, looking for keywords and patterns that reveal the file's purpose. Keywords like "parser," "selector," "consume," "token," "CSSSelector," "pseudo," "attribute," "namespace," "combinator," and "nesting" immediately stood out. This suggested the file is responsible for taking CSS selector strings and breaking them down into a structured representation.

3. **Inferring Primary Functionality:** Based on the keywords, I inferred that the primary function of `css_selector_parser.cc` is to parse CSS selector syntax. This involves:
    * **Tokenization:** Breaking down the CSS selector string into individual meaningful units (tokens).
    * **Structure Recognition:** Identifying the different components of a CSS selector (type selectors, class selectors, ID selectors, attribute selectors, pseudo-classes, pseudo-elements, combinators).
    * **Building a Data Structure:** Creating an internal representation of the parsed selector, likely a tree-like structure or a linked list of `CSSSelector` objects.

4. **Identifying Relationships with Web Technologies:**
    * **CSS:** The most direct relationship. The file *parses* CSS selectors. I needed to illustrate this with examples of different selector types and how they might be represented internally.
    * **HTML:** CSS selectors target HTML elements. I considered how the parsed selectors would be used to match elements in the HTML DOM. Examples of HTML structures and corresponding CSS selectors became important.
    * **JavaScript:** JavaScript can interact with CSS through the DOM API (e.g., `querySelector`, `querySelectorAll`). I recognized that the parsing done by this file is crucial for JavaScript's ability to select elements based on CSS selectors. I considered an example of JavaScript using a CSS selector.

5. **Crafting Examples:**  For each relationship, I tried to create simple but illustrative examples. I focused on common CSS selector patterns:
    * Type selector (`div`)
    * Class selector (`.my-class`)
    * ID selector (`#my-id`)
    * Attribute selector (`[data-type="value"]`)
    * Pseudo-class (`:hover`)
    * Pseudo-element (`::before`)
    * Combinators (` `, `>`, `+`, `~`)

6. **Considering Logic and Assumptions:** The code contained conditional logic (e.g., `if` statements checking token types). I thought about hypothetical input and the expected output of the parser. For example, if the input is a simple type selector like "div", the output should be a `CSSSelector` object representing that. If the input is invalid, the parser should indicate an error. This led to the "Hypothetical Input and Output" section.

7. **Identifying User Errors:** I thought about common mistakes developers make when writing CSS selectors:
    * Typos in selectors.
    * Incorrect syntax for pseudo-classes or pseudo-elements.
    * Misunderstanding combinator behavior.
    * Incorrect namespace usage.

8. **Developing Debugging Clues:**  I considered how a developer might end up needing to debug this code. This usually involves a styling issue or a JavaScript selector not working as expected. Tracing how the browser processes CSS rules, starting from loading the stylesheet to applying styles to elements, provided the "User Operations and Debugging" sequence.

9. **Focusing on Part 3 and Summarization:**  Since this was part 3, I needed to synthesize the information from the provided code snippet. The key here was to notice the code dealing with more complex selectors, pseudo-classes (especially those with arguments or involving `:nth-child` and `of`), combinators, and namespace handling. The presence of `RuntimeEnabledFeatures` suggested handling of experimental or browser-specific features. The code also explicitly deals with nesting selectors.

10. **Structuring the Answer:** I organized the information into logical sections based on the request's components: Functionality, Relationship to Web Technologies, Examples, Logic and Assumptions, User Errors, Debugging, and Final Summary. I used clear headings and bullet points for readability.

11. **Refinement and Language:** I reviewed my answer for clarity, accuracy, and completeness. I made sure to use appropriate technical terms and explain concepts in a way that would be understandable to someone familiar with web development concepts. I also paid attention to the specific phrasing requested (e.g., "list its functions").

By following this structured approach, combining code analysis with my understanding of web technologies, I was able to generate a comprehensive and informative answer that addressed all aspects of the user's request. The process involved both low-level code inspection and high-level conceptual understanding.
好的，让我们来分析一下 `blink/renderer/core/css/parser/css_selector_parser.cc` 文件的功能，并根据您的要求进行详细说明。

**文件功能归纳 (Part 3 Summary):**

从提供的代码片段来看，`css_selector_parser.cc` 文件的主要功能是 **解析 CSS 选择器中更复杂的结构和特性**。 这部分代码主要关注以下方面：

* **解析伪类和伪元素:**  处理各种伪类 (如 `:nth-child`, `:lang`, `:slotted`, `:hover`, `:focus` 等) 和伪元素 (如 `::cue`, `::-webkit-clear-button` 等)。
* **解析 `:nth-child` 等结构性伪类:**  特别处理了带有 `an+b` 语法的结构性伪类，例如 `:nth-child(2n+1)` 或 `:nth-of-type(odd)`，以及带有 `of <selector-list>` 的变体。
* **处理嵌套选择器 (`&`):**  解析 CSS 嵌套语法中使用的父选择器引用符 `&`。
* **解析组合符 (Combinators):**  识别并处理 CSS 选择器中的组合符，如后代选择器 (空格), 子选择器 (`>`), 相邻兄弟选择器 (`+`), 通用兄弟选择器 (`~`)。
* **解析属性选择器:**  识别和处理属性选择器，包括不同的匹配方式 (精确匹配 `=`, 包含 `~=`,  以...开头 `^=`, 以...结尾 `$=`, 包含子串 `*=`, 连字符分隔 `|=`) 和属性标志（如 `i` 表示忽略大小写）。
* **处理命名空间:** 确定元素或属性的命名空间，包括默认命名空间和带有前缀的命名空间。
* **处理 Shadow DOM 相关伪类:**  解析与 Shadow DOM 相关的伪类，如 `::slotted`。
* **记录 CSS 特性使用情况:**  记录 CSS 选择器中使用的各种特性，用于统计和废弃跟踪。
* **处理 WebKit 特定的伪元素:**  识别并处理以 `-webkit-` 开头的浏览器特定伪元素。
* **处理 `:part()` 伪元素 (可能涉及，虽然代码片段中没有直接体现):**  虽然提供的代码片段没有直接处理 `:part()`, 但作为处理伪元素的一部分，这个文件也需要支持它。
* **处理 View Transitions API 相关的特性:**  支持与 View Transitions API 相关的类名选择器 (`.view-transition-class-name`).

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`css_selector_parser.cc` 是 Blink 渲染引擎解析 CSS 的关键部分，它直接关联到 JavaScript, HTML 和 CSS 的功能：

* **CSS:**  这是最直接的关系。`css_selector_parser.cc` 的核心功能就是 **解析 CSS 选择器的语法**，将文本形式的 CSS 选择器转换为引擎可以理解和使用的内部结构。
    * **例子:** 当 CSS 规则 `div.container > p:first-child { color: blue; }` 被解析时，这个文件会负责识别 `div` (类型选择器), `.container` (类选择器), `>` (子选择器组合符), `p` (类型选择器), `:first-child` (伪类)。

* **HTML:** CSS 选择器的目的是 **选择 HTML 元素**。解析后的选择器将被用于匹配 DOM 树中的元素，从而应用相应的 CSS 样式。
    * **例子:**  如果 `css_selector_parser.cc` 解析了选择器 `#myElement`, 那么渲染引擎会使用这个解析结果在 HTML DOM 中找到 `id` 为 `myElement` 的元素。

* **JavaScript:** JavaScript 可以通过 DOM API (如 `document.querySelector()` 和 `document.querySelectorAll()`) 使用 CSS 选择器来查询 HTML 元素。  `css_selector_parser.cc` **间接地支持了 JavaScript 的这些功能**，因为它负责解析 JavaScript 传递给这些 API 的 CSS 选择器字符串。
    * **例子:**  当 JavaScript 代码执行 `document.querySelector('.active')` 时，浏览器内部会调用 CSS 解析器（包括 `css_selector_parser.cc`）来理解选择器 `.active`，然后在当前 HTML 文档中找到第一个带有 `active` 类名的元素。

**逻辑推理的假设输入与输出:**

假设输入是一个 CSS 选择器字符串，`css_selector_parser.cc` 的相关函数会尝试解析它。

* **假设输入:** `input[type="text"]:focus`
* **预期输出:**  一个内部数据结构，表示一个由两个简单选择器组成的复合选择器：
    * 类型选择器: `input`
    * 属性选择器: `[type="text"]` (属性名: `type`, 匹配类型: `kAttributeExact`, 值: `"text"`)
    * 伪类: `:focus`
    * 这些选择器组合在一起，没有显式的组合符，意味着它们是同一元素上的条件。

* **假设输入:** `body > div p + span`
* **预期输出:** 一个表示复杂选择器的数据结构，包含以下部分：
    * 第一个复合选择器: `body`
    * 组合符: `kChild` (子选择器 `>`)
    * 第二个复合选择器: `div`
    * 组合符: `kDescendant` (后代选择器 空格)
    * 第三个复合选择器: `p`
    * 组合符: `kDirectAdjacent` (相邻兄弟选择器 `+`)
    * 第四个复合选择器: `span`

* **假设输入:** `::webkit-scrollbar-thumb:hover`
* **预期输出:** 一个内部数据结构，表示一个由伪元素和伪类组成的复合选择器：
    * 伪元素: `::-webkit-scrollbar-thumb`
    * 伪类: `:hover`

**用户或编程常见的错误及举例说明:**

用户或开发者在编写 CSS 或使用 JavaScript 的选择器 API 时，可能会犯以下错误，这些错误可能会导致 `css_selector_parser.cc` 解析失败或产生意外的结果：

1. **拼写错误:**  错误的拼写选择器名称、属性名或属性值。
    * **例子:**  写成 `div.continer` 而不是 `div.container`。
    * **后果:** 解析器无法识别 `.continer` 类选择器。

2. **错误的伪类/伪元素语法:**  遗漏冒号、使用错误的参数等。
    * **例子:**  写成 `:firstchild` 而不是 `:first-child`，或者 `:nth-child(odd)` 没有参数。
    * **后果:** 解析器无法正确识别或解析伪类/伪元素。

3. **组合符使用错误:**  误解不同组合符的作用。
    * **例子:**  希望选择 `div` 元素的直接子元素 `p`，却错误地使用了空格 `div p` (后代选择器)。
    * **后果:**  选择器会匹配到更深层次的 `p` 元素，而不是仅仅直接子元素。

4. **属性选择器语法错误:**  属性值缺少引号、匹配符使用错误等。
    * **例子:**  写成 `[type=text]` 而不是 `[type="text"]`。
    * **后果:**  解析器可能无法正确解析属性选择器。

5. **命名空间前缀错误:**  在使用命名空间时，前缀未正确声明或使用。
    * **例子:**  使用 `svg|rect` 选择器，但 CSS 中没有定义 `svg` 命名空间。
    * **后果:** 解析器无法找到对应的命名空间 URI。

6. **使用了浏览器不支持的特性:**  使用了实验性的或特定浏览器才支持的伪类/伪元素，而目标浏览器不支持。
    * **例子:**  使用了某个新的 CSS 规范中定义的伪类，但当前的浏览器版本尚未实现。
    * **后果:** 解析器可能无法识别该伪类。

**用户操作如何一步步到达这里 (调试线索):**

当网页开发者遇到 CSS 样式不生效或 JavaScript 选择器无法正确选中元素的问题时，他们可能会进行以下操作，这些操作最终会涉及到 `css_selector_parser.cc` 的代码执行：

1. **编写 HTML 结构:**  开发者创建 HTML 文件，包含需要应用样式的元素。
2. **编写 CSS 样式规则:** 开发者在 CSS 文件或 `<style>` 标签中编写 CSS 规则，其中包含选择器。
3. **浏览器加载网页:**  当用户在浏览器中打开该网页时，浏览器开始解析 HTML 和 CSS。
4. **CSS 解析:**  浏览器 CSS 解析器开始工作，读取 CSS 样式规则。
5. **选择器解析:**  当解析到 CSS 规则的选择器部分时，`css_selector_parser.cc` 中的代码会被调用，负责将选择器字符串转换为内部表示。
6. **样式匹配:**  解析后的选择器将被用于在 DOM 树中查找匹配的元素。
7. **样式应用:**  匹配到的元素会应用相应的 CSS 样式。

**调试线索:**

* **样式不生效:** 如果开发者发现某些 CSS 规则没有应用到预期的元素上，可能是因为选择器写错了，导致 `css_selector_parser.cc` 解析出的选择器无法正确匹配到目标元素。
* **JavaScript 选择器错误:**  如果开发者使用 `document.querySelector()` 或 `querySelectorAll()` 无法选中预期的元素，同样可能是因为传递给这些方法的选择器字符串有误，导致解析器无法正确理解。
* **开发者工具检查:** 开发者可以使用浏览器开发者工具的 "Elements" 面板查看元素的样式，以及 "Console" 面板查看 JavaScript 错误。 如果选择器有语法错误，开发者工具可能会给出相关的警告或错误信息，这通常意味着 `css_selector_parser.cc` 在解析时遇到了问题。
* **断点调试:**  对于更复杂的情况，开发者可能会在浏览器开发者工具中设置断点，逐步执行 JavaScript 代码，查看选择器 API 的调用，以及浏览器内部的 CSS 解析过程。 虽然不太可能直接调试到 Blink 引擎的 C++ 代码，但理解 CSS 解析的流程有助于定位问题。

希望这些详细的解释能够帮助您理解 `blink/renderer/core/css/parser/css_selector_parser.cc` 文件的功能以及它在 Web 技术栈中的作用。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_selector_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
SViewTransitionClassEnabled()) {
        if (stream.Peek().GetType() == kDelimiterToken &&
            stream.Peek().Delimiter() == '.') {
          name_and_classes->push_back(CSSSelector::UniversalSelectorAtom());
        }
      }

      if (name_and_classes->empty()) {
        const CSSParserToken& ident = stream.Peek();
        if (ident.GetType() == kIdentToken) {
          name_and_classes->push_back(ident.Value().ToAtomicString());
          stream.Consume();
        } else if (ident.GetType() == kDelimiterToken &&
                   ident.Delimiter() == '*') {
          name_and_classes->push_back(CSSSelector::UniversalSelectorAtom());
          stream.Consume();
        } else {
          return false;
        }
      }

      CHECK_EQ(name_and_classes->size(), 1ull);

      if (RuntimeEnabledFeatures::CSSViewTransitionClassEnabled()) {
        while (!stream.AtEnd() && stream.Peek().GetType() != kWhitespaceToken) {
          if (stream.Peek().GetType() != kDelimiterToken ||
              stream.Consume().Delimiter() != '.') {
            return false;
          }

          if (stream.Peek().GetType() != kIdentToken) {
            return false;
          }
          name_and_classes->push_back(
              stream.Consume().Value().ToAtomicString());
        }
      }

      stream.ConsumeWhitespace();

      if (!stream.AtEnd()) {
        return false;
      }

      selector.SetIdentList(std::move(name_and_classes));
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoSlotted: {
      DisallowPseudoElementsScope scope(this);
      base::AutoReset<bool> inside_compound(&inside_compound_pseudo_, true);

      {
        ResetVectorAfterScope reset_vector(output_);
        base::span<CSSSelector> inner_selector = ConsumeCompoundSelector(
            stream, CSSNestingType::kNone, result_flags);
        stream.ConsumeWhitespace();
        if (inner_selector.empty() || !stream.AtEnd()) {
          return false;
        }
        MarkAsEntireComplexSelector(reset_vector.AddedElements());
        selector.SetSelectorList(
            CSSSelectorList::AdoptSelectorVector(reset_vector.AddedElements()));
      }
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoLang: {
      // FIXME: CSS Selectors Level 4 allows :lang(*-foo)
      const CSSParserToken& ident = stream.Peek();
      if (ident.GetType() != kIdentToken) {
        return false;
      }
      selector.SetArgument(ident.Value().ToAtomicString());
      stream.ConsumeIncludingWhitespace();
      if (!stream.AtEnd()) {
        return false;
      }
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoNthChild:
    case CSSSelector::kPseudoNthLastChild:
    case CSSSelector::kPseudoNthOfType:
    case CSSSelector::kPseudoNthLastOfType: {
      std::pair<int, int> ab;
      if (!ConsumeANPlusB(stream, ab)) {
        return false;
      }
      stream.ConsumeWhitespace();
      if (stream.AtEnd()) {
        selector.SetNth(ab.first, ab.second, nullptr);
        output_.push_back(std::move(selector));
        return true;
      }

      // See if there's an “of ...” part.
      if (selector.GetPseudoType() != CSSSelector::kPseudoNthChild &&
          selector.GetPseudoType() != CSSSelector::kPseudoNthLastChild) {
        return false;
      }

      CSSSelectorList* sub_selectors = ConsumeNthChildOfSelectors(stream);
      if (sub_selectors == nullptr) {
        return false;
      }
      stream.ConsumeWhitespace();
      if (!stream.AtEnd()) {
        return false;
      }

      selector.SetNth(ab.first, ab.second, sub_selectors);
      output_.push_back(std::move(selector));
      return true;
    }
    case CSSSelector::kPseudoHighlight: {
      const CSSParserToken& ident = stream.Peek();
      if (ident.GetType() != kIdentToken) {
        return false;
      }
      selector.SetArgument(ident.Value().ToAtomicString());
      stream.ConsumeIncludingWhitespace();
      if (!stream.AtEnd()) {
        return false;
      }
      output_.push_back(std::move(selector));
      return true;
    }
    default:
      break;
  }

  return false;
}

bool CSSSelectorParser::ConsumeNestingParent(CSSParserTokenStream& stream,
                                             ResultFlags& result_flags) {
  DCHECK_EQ(stream.Peek().GetType(), kDelimiterToken);
  DCHECK_EQ(stream.Peek().Delimiter(), '&');
  stream.Consume();

  output_.push_back(
      CSSSelector(parent_rule_for_nesting_, /*is_implicit=*/false));

  result_flags |= kContainsScopeOrParent;
  // In case that a nesting parent selector is inside a :has() pseudo class,
  // mark the :has() containing a pseudo selector and a complex selector
  // so that the StyleEngine can invalidate the anchor element of the :has()
  // for a pseudo state change (crbug.com/1517866) or a complex selector
  // state change (crbug.com/350946979) in the parent selector.
  // These ignore whether the nesting parent actually contains a pseudo or
  // complex selector to avoid nesting parent lookup overhead and the
  // complexity caused by reparenting style rules.
  result_flags |= kContainsPseudo;
  result_flags |= kContainsComplexSelector;

  return true;
}

bool CSSSelectorParser::PeekIsCombinator(CSSParserTokenStream& stream) {
  stream.ConsumeWhitespace();

  if (stream.Peek().GetType() != kDelimiterToken) {
    return false;
  }

  switch (stream.Peek().Delimiter()) {
    case '+':
    case '~':
    case '>':
      return true;
    default:
      return false;
  }
}

CSSSelector::RelationType CSSSelectorParser::ConsumeCombinator(
    CSSParserTokenStream& stream) {
  CSSSelector::RelationType fallback_result = CSSSelector::kSubSelector;
  while (stream.Peek().GetType() == kWhitespaceToken) {
    stream.Consume();
    fallback_result = CSSSelector::kDescendant;
  }

  if (stream.Peek().GetType() != kDelimiterToken) {
    return fallback_result;
  }

  switch (stream.Peek().Delimiter()) {
    case '+':
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kDirectAdjacent;

    case '~':
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kIndirectAdjacent;

    case '>':
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kChild;

    default:
      break;
  }
  return fallback_result;
}

CSSSelector::MatchType CSSSelectorParser::ConsumeAttributeMatch(
    CSSParserTokenStream& stream) {
  const CSSParserToken& token = stream.Peek();
  switch (token.GetType()) {
    case kIncludeMatchToken:
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kAttributeList;
    case kDashMatchToken:
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kAttributeHyphen;
    case kPrefixMatchToken:
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kAttributeBegin;
    case kSuffixMatchToken:
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kAttributeEnd;
    case kSubstringMatchToken:
      stream.ConsumeIncludingWhitespace();
      return CSSSelector::kAttributeContain;
    case kDelimiterToken:
      if (token.Delimiter() == '=') {
        stream.ConsumeIncludingWhitespace();
        return CSSSelector::kAttributeExact;
      }
      [[fallthrough]];
    default:
      failed_parsing_ = true;
      return CSSSelector::kAttributeExact;
  }
}

CSSSelector::AttributeMatchType CSSSelectorParser::ConsumeAttributeFlags(
    CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kIdentToken) {
    return CSSSelector::AttributeMatchType::kCaseSensitive;
  }
  const CSSParserToken& flag = stream.ConsumeIncludingWhitespace();
  if (EqualIgnoringASCIICase(flag.Value(), "i")) {
    return CSSSelector::AttributeMatchType::kCaseInsensitive;
  } else if (EqualIgnoringASCIICase(flag.Value(), "s") &&
             RuntimeEnabledFeatures::CSSCaseSensitiveSelectorEnabled()) {
    return CSSSelector::AttributeMatchType::kCaseSensitiveAlways;
  }
  failed_parsing_ = true;
  return CSSSelector::AttributeMatchType::kCaseSensitive;
}

bool CSSSelectorParser::ConsumeANPlusB(CSSParserTokenStream& stream,
                                       std::pair<int, int>& result) {
  if (stream.AtEnd()) {
    return false;
  }

  if (stream.Peek().GetBlockType() != CSSParserToken::kNotBlock) {
    return false;
  }

  const CSSParserToken& token = stream.Consume();
  if (token.GetType() == kNumberToken &&
      token.GetNumericValueType() == kIntegerValueType) {
    result = std::make_pair(0, ClampTo<int>(token.NumericValue()));
    return true;
  }
  if (token.GetType() == kIdentToken) {
    if (EqualIgnoringASCIICase(token.Value(), "odd")) {
      result = std::make_pair(2, 1);
      return true;
    }
    if (EqualIgnoringASCIICase(token.Value(), "even")) {
      result = std::make_pair(2, 0);
      return true;
    }
  }

  // The 'n' will end up as part of an ident or dimension. For a valid <an+b>,
  // this will store a string of the form 'n', 'n-', or 'n-123'.
  String n_string;

  if (token.GetType() == kDelimiterToken && token.Delimiter() == '+' &&
      stream.Peek().GetType() == kIdentToken) {
    result.first = 1;
    n_string = stream.Consume().Value().ToString();
  } else if (token.GetType() == kDimensionToken &&
             token.GetNumericValueType() == kIntegerValueType) {
    result.first = ClampTo<int>(token.NumericValue());
    n_string = token.Value().ToString();
  } else if (token.GetType() == kIdentToken) {
    if (token.Value()[0] == '-') {
      result.first = -1;
      n_string = token.Value().ToString().Substring(1);
    } else {
      result.first = 1;
      n_string = token.Value().ToString();
    }
  }

  stream.ConsumeWhitespace();

  if (n_string.empty() || !IsASCIIAlphaCaselessEqual(n_string[0], 'n')) {
    return false;
  }
  if (n_string.length() > 1 && n_string[1] != '-') {
    return false;
  }

  if (n_string.length() > 2) {
    bool valid;
    result.second = n_string.Substring(1).ToIntStrict(&valid);
    return valid;
  }

  NumericSign sign = n_string.length() == 1 ? kNoSign : kMinusSign;
  if (sign == kNoSign && stream.Peek().GetType() == kDelimiterToken) {
    char delimiter_sign = stream.ConsumeIncludingWhitespace().Delimiter();
    if (delimiter_sign == '+') {
      sign = kPlusSign;
    } else if (delimiter_sign == '-') {
      sign = kMinusSign;
    } else {
      return false;
    }
  }

  if (sign == kNoSign && stream.Peek().GetType() != kNumberToken) {
    result.second = 0;
    return true;
  }

  const CSSParserToken& b = stream.Consume();
  if (b.GetType() != kNumberToken ||
      b.GetNumericValueType() != kIntegerValueType) {
    return false;
  }
  if ((b.GetNumericSign() == kNoSign) == (sign == kNoSign)) {
    return false;
  }
  result.second = ClampTo<int>(b.NumericValue());
  if (sign == kMinusSign) {
    // Negating minimum integer returns itself, instead return max integer.
    if (result.second == std::numeric_limits<int>::min()) [[unlikely]] {
      result.second = std::numeric_limits<int>::max();
    } else {
      result.second = -result.second;
    }
  }
  return true;
}

// Consumes the “of ...” part of :nth_child(An+B of ...).
// Returns nullptr on failure.
CSSSelectorList* CSSSelectorParser::ConsumeNthChildOfSelectors(
    CSSParserTokenStream& stream) {
  if (stream.Peek().GetType() != kIdentToken ||
      stream.Consume().Value() != "of") {
    return nullptr;
  }
  stream.ConsumeWhitespace();

  ResetVectorAfterScope reset_vector(output_);
  ResultFlags result_flags = 0;
  base::span<CSSSelector> selectors =
      ConsumeComplexSelectorList(stream, CSSNestingType::kNone, result_flags);
  if (selectors.empty()) {
    return nullptr;
  }
  return CSSSelectorList::AdoptSelectorVector(selectors);
}

const AtomicString& CSSSelectorParser::DefaultNamespace() const {
  if (!style_sheet_ || ignore_default_namespace_) {
    return g_star_atom;
  }
  return style_sheet_->DefaultNamespace();
}

const AtomicString& CSSSelectorParser::DetermineNamespace(
    const AtomicString& prefix) {
  if (prefix.IsNull()) {
    return DefaultNamespace();
  }
  if (prefix.empty()) {
    return g_empty_atom;  // No namespace. If an element/attribute has a
                          // namespace, we won't match it.
  }
  if (prefix == g_star_atom) {
    return g_star_atom;  // We'll match any namespace.
  }
  if (!style_sheet_) {
    return g_null_atom;  // Cannot resolve prefix to namespace without a
                         // stylesheet, syntax error.
  }
  return style_sheet_->NamespaceURIFromPrefix(prefix);
}

void CSSSelectorParser::PrependTypeSelectorIfNeeded(
    const AtomicString& namespace_prefix,
    bool has_q_name,
    const AtomicString& element_name,
    wtf_size_t start_index_of_compound_selector) {
  const CSSSelector& compound_selector =
      output_[start_index_of_compound_selector];

  if (!has_q_name && DefaultNamespace() == g_star_atom &&
      !NeedsImplicitShadowCombinatorForMatching(compound_selector)) {
    return;
  }

  AtomicString determined_element_name =
      !has_q_name ? CSSSelector::UniversalSelectorAtom() : element_name;
  AtomicString namespace_uri = DetermineNamespace(namespace_prefix);
  if (namespace_uri.IsNull()) {
    failed_parsing_ = true;
    return;
  }
  AtomicString determined_prefix = namespace_prefix;
  if (namespace_uri == DefaultNamespace()) {
    determined_prefix = g_null_atom;
  }
  QualifiedName tag =
      QualifiedName(determined_prefix, determined_element_name, namespace_uri);

  // *:host/*:host-context never matches, so we can't discard the *,
  // otherwise we can't tell the difference between *:host and just :host.
  //
  // Also, selectors where we use a ShadowPseudo combinator between the
  // element and the pseudo element for matching (custom pseudo elements,
  // ::cue, ::shadow), we need a universal selector to set the combinator
  // (relation) on in the cases where there are no simple selectors preceding
  // the pseudo element.
  bool is_host_pseudo = IsHostPseudoSelector(compound_selector);
  if (is_host_pseudo && !has_q_name && namespace_prefix.IsNull()) {
    return;
  }
  if (tag != AnyQName() || is_host_pseudo ||
      NeedsImplicitShadowCombinatorForMatching(compound_selector)) {
    const bool is_implicit =
        determined_prefix == g_null_atom &&
        determined_element_name == CSSSelector::UniversalSelectorAtom() &&
        !is_host_pseudo;

    output_.insert(start_index_of_compound_selector,
                   CSSSelector(tag, is_implicit));
  }
}

// If we have a compound that implicitly crosses a shadow root, rewrite it to
// have a shadow-crossing combinator (kUAShadow, which has no symbol, but let's
// call it >> for the same of the argument) instead of kSubSelector. E.g.:
//
//   video::-webkit-video-controls => video >> ::webkit-video-controls
//
// This is required because the element matching ::-webkit-video-controls is
// not the video element itself, but an element somewhere down in <video>'s
// shadow DOM tree. Note that since we store compounds right-to-left, this may
// require rearranging elements in memory (see the comment below).
void CSSSelectorParser::SplitCompoundAtImplicitShadowCrossingCombinator(
    base::span<CSSSelector> selectors) {
  // The simple selectors are stored in an array that stores
  // combinator-separated compound selectors from right-to-left. Yet, within a
  // single compound selector, stores the simple selectors from left-to-right.
  //
  // ".a.b > div#id" is stored as [div, #id, .a, .b], each element in the list
  // stored with an associated relation (combinator or SubSelector).
  //
  // ::cue, ::shadow, and custom pseudo elements have an implicit ShadowPseudo
  // combinator to their left, which really makes for a new compound selector,
  // yet it's consumed by the selector parser as a single compound selector.
  //
  // Example:
  //
  // input#x::-webkit-clear-button -> [ ::-webkit-clear-button, input, #x ]
  //
  // Likewise, ::slotted() pseudo element has an implicit ShadowSlot combinator
  // to its left for finding matching slot element in other TreeScope.
  //
  // ::part has a implicit ShadowPart combinator to its left finding the host
  // element in the scope of the style rule.
  //
  // Example:
  //
  // slot[name=foo]::slotted(div) -> [ ::slotted(div), slot, [name=foo] ]
  for (size_t i = 1; i < selectors.size(); ++i) {
    if (NeedsImplicitShadowCombinatorForMatching(selectors[i])) {
      CSSSelector::RelationType relation =
          GetImplicitShadowCombinatorForMatching(selectors[i].GetPseudoType());
      std::rotate(selectors.begin(), selectors.begin() + i, selectors.end());

      base::span<CSSSelector> remaining = selectors.first(selectors.size() - i);
      // We might need to split the compound multiple times, since a number of
      // the relevant pseudo-elements can be combined, and they all need an
      // implicit combinator for matching.
      SplitCompoundAtImplicitShadowCrossingCombinator(remaining);
      remaining.back().SetRelation(relation);
      break;
    }
  }
}

namespace {

struct PseudoElementFeatureMapEntry {
  template <unsigned key_length>
  PseudoElementFeatureMapEntry(const char (&key)[key_length],
                               WebFeature feature)
      : key(key),
        key_length(base::checked_cast<uint16_t>(key_length - 1)),
        feature(base::checked_cast<uint16_t>(feature)) {}
  const char* const key;
  const uint16_t key_length;
  const uint16_t feature;
};

WebFeature FeatureForWebKitCustomPseudoElement(const AtomicString& name) {
  static const PseudoElementFeatureMapEntry feature_table[] = {
      {"cue", WebFeature::kCSSSelectorCue},
      {"-internal-media-controls-overlay-cast-button",
       WebFeature::kCSSSelectorInternalMediaControlsOverlayCastButton},
      {"-webkit-calendar-picker-indicator",
       WebFeature::kCSSSelectorWebkitCalendarPickerIndicator},
      {"-webkit-clear-button", WebFeature::kCSSSelectorWebkitClearButton},
      {"-webkit-color-swatch", WebFeature::kCSSSelectorWebkitColorSwatch},
      {"-webkit-color-swatch-wrapper",
       WebFeature::kCSSSelectorWebkitColorSwatchWrapper},
      {"-webkit-date-and-time-value",
       WebFeature::kCSSSelectorWebkitDateAndTimeValue},
      {"-webkit-datetime-edit", WebFeature::kCSSSelectorWebkitDatetimeEdit},
      {"-webkit-datetime-edit-ampm-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditAmpmField},
      {"-webkit-datetime-edit-day-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditDayField},
      {"-webkit-datetime-edit-fields-wrapper",
       WebFeature::kCSSSelectorWebkitDatetimeEditFieldsWrapper},
      {"-webkit-datetime-edit-hour-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditHourField},
      {"-webkit-datetime-edit-millisecond-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditMillisecondField},
      {"-webkit-datetime-edit-minute-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditMinuteField},
      {"-webkit-datetime-edit-month-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditMonthField},
      {"-webkit-datetime-edit-second-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditSecondField},
      {"-webkit-datetime-edit-text",
       WebFeature::kCSSSelectorWebkitDatetimeEditText},
      {"-webkit-datetime-edit-week-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditWeekField},
      {"-webkit-datetime-edit-year-field",
       WebFeature::kCSSSelectorWebkitDatetimeEditYearField},
      {"-webkit-file-upload-button",
       WebFeature::kCSSSelectorWebkitFileUploadButton},
      {"-webkit-inner-spin-button",
       WebFeature::kCSSSelectorWebkitInnerSpinButton},
      {"-webkit-input-placeholder",
       WebFeature::kCSSSelectorWebkitInputPlaceholder},
      {"-webkit-media-controls", WebFeature::kCSSSelectorWebkitMediaControls},
      {"-webkit-media-controls-current-time-display",
       WebFeature::kCSSSelectorWebkitMediaControlsCurrentTimeDisplay},
      {"-webkit-media-controls-enclosure",
       WebFeature::kCSSSelectorWebkitMediaControlsEnclosure},
      {"-webkit-media-controls-fullscreen-button",
       WebFeature::kCSSSelectorWebkitMediaControlsFullscreenButton},
      {"-webkit-media-controls-mute-button",
       WebFeature::kCSSSelectorWebkitMediaControlsMuteButton},
      {"-webkit-media-controls-overlay-enclosure",
       WebFeature::kCSSSelectorWebkitMediaControlsOverlayEnclosure},
      {"-webkit-media-controls-overlay-play-button",
       WebFeature::kCSSSelectorWebkitMediaControlsOverlayPlayButton},
      {"-webkit-media-controls-panel",
       WebFeature::kCSSSelectorWebkitMediaControlsPanel},
      {"-webkit-media-controls-play-button",
       WebFeature::kCSSSelectorWebkitMediaControlsPlayButton},
      {"-webkit-media-controls-timeline",
       WebFeature::kCSSSelectorWebkitMediaControlsTimeline},
      // Note: This feature is no longer implemented in Blink.
      {"-webkit-media-controls-timeline-container",
       WebFeature::kCSSSelectorWebkitMediaControlsTimelineContainer},
      {"-webkit-media-controls-time-remaining-display",
       WebFeature::kCSSSelectorWebkitMediaControlsTimeRemainingDisplay},
      {"-webkit-media-controls-toggle-closed-captions-button",
       WebFeature::kCSSSelectorWebkitMediaControlsToggleClosedCaptionsButton},
      {"-webkit-media-controls-volume-slider",
       WebFeature::kCSSSelectorWebkitMediaControlsVolumeSlider},
      {"-webkit-media-slider-container",
       WebFeature::kCSSSelectorWebkitMediaSliderContainer},
      {"-webkit-media-slider-thumb",
       WebFeature::kCSSSelectorWebkitMediaSliderThumb},
      {"-webkit-media-text-track-container",
       WebFeature::kCSSSelectorWebkitMediaTextTrackContainer},
      {"-webkit-media-text-track-display",
       WebFeature::kCSSSelectorWebkitMediaTextTrackDisplay},
      {"-webkit-media-text-track-region",
       WebFeature::kCSSSelectorWebkitMediaTextTrackRegion},
      {"-webkit-media-text-track-region-container",
       WebFeature::kCSSSelectorWebkitMediaTextTrackRegionContainer},
      {"-webkit-meter-bar", WebFeature::kCSSSelectorWebkitMeterBar},
      {"-webkit-meter-even-less-good-value",
       WebFeature::kCSSSelectorWebkitMeterEvenLessGoodValue},
      {"-webkit-meter-inner-element",
       WebFeature::kCSSSelectorWebkitMeterInnerElement},
      {"-webkit-meter-optimum-value",
       WebFeature::kCSSSelectorWebkitMeterOptimumValue},
      {"-webkit-meter-suboptimum-value",
       WebFeature::kCSSSelectorWebkitMeterSuboptimumValue},
      {"-webkit-progress-bar", WebFeature::kCSSSelectorWebkitProgressBar},
      {"-webkit-progress-inner-element",
       WebFeature::kCSSSelectorWebkitProgressInnerElement},
      {"-webkit-progress-value", WebFeature::kCSSSelectorWebkitProgressValue},
      {"-webkit-search-cancel-button",
       WebFeature::kCSSSelectorWebkitSearchCancelButton},
      {"-webkit-slider-container",
       WebFeature::kCSSSelectorWebkitSliderContainer},
      {"-webkit-slider-runnable-track",
       WebFeature::kCSSSelectorWebkitSliderRunnableTrack},
      {"-webkit-slider-thumb", WebFeature::kCSSSelectorWebkitSliderThumb},
      {"-webkit-textfield-decoration-container",
       WebFeature::kCSSSelectorWebkitTextfieldDecorationContainer},
  };
  // TODO(fs): Could use binary search once there's a less finicky way to
  // compare (order) String and StringView/non-String.
  for (const auto& entry : feature_table) {
    if (name == StringView(entry.key, entry.key_length)) {
      return static_cast<WebFeature>(entry.feature);
    }
  }
  return WebFeature::kCSSSelectorWebkitUnknownPseudo;
}

}  // namespace

static void RecordUsageAndDeprecationsOneSelector(
    const CSSSelector* selector,
    const CSSParserContext* context,
    bool* has_visited_pseudo) {
  std::optional<WebFeature> feature;
  switch (selector->GetPseudoType()) {
    case CSSSelector::kPseudoAny:
      feature = WebFeature::kCSSSelectorPseudoAny;
      break;
    case CSSSelector::kPseudoIs:
      feature = WebFeature::kCSSSelectorPseudoIs;
      break;
    case CSSSelector::kPseudoFocusVisible:
      feature = WebFeature::kCSSSelectorPseudoFocusVisible;
      break;
    case CSSSelector::kPseudoFocus:
      feature = WebFeature::kCSSSelectorPseudoFocus;
      break;
    case CSSSelector::kPseudoAnyLink:
      feature = WebFeature::kCSSSelectorPseudoAnyLink;
      break;
    case CSSSelector::kPseudoWebkitAnyLink:
      feature = WebFeature::kCSSSelectorPseudoWebkitAnyLink;
      break;
    case CSSSelector::kPseudoWhere:
      feature = WebFeature::kCSSSelectorPseudoWhere;
      break;
    case CSSSelector::kPseudoDefined:
      feature = WebFeature::kCSSSelectorPseudoDefined;
      break;
    case CSSSelector::kPseudoSlotted:
      feature = WebFeature::kCSSSelectorPseudoSlotted;
      break;
    case CSSSelector::kPseudoHost:
      feature = WebFeature::kCSSSelectorPseudoHost;
      break;
    case CSSSelector::kPseudoHostContext:
      feature = WebFeature::kCSSSelectorPseudoHostContext;
      break;
    case CSSSelector::kPseudoFullScreenAncestor:
      feature = WebFeature::kCSSSelectorPseudoFullScreenAncestor;
      break;
    case CSSSelector::kPseudoFullScreen:
      feature = WebFeature::kCSSSelectorPseudoFullScreen;
      break;
    case CSSSelector::kPseudoListBox:
      feature = WebFeature::kCSSSelectorInternalPseudoListBox;
      break;
    case CSSSelector::kPseudoWebKitCustomElement:
      feature = FeatureForWebKitCustomPseudoElement(selector->Value());
      break;
    case CSSSelector::kPseudoSpatialNavigationFocus:
      feature = WebFeature::kCSSSelectorInternalPseudoSpatialNavigationFocus;
      break;
    case CSSSelector::kPseudoReadOnly:
      feature = WebFeature::kCSSSelectorPseudoReadOnly;
      break;
    case CSSSelector::kPseudoReadWrite:
      feature = WebFeature::kCSSSelectorPseudoReadWrite;
      break;
    case CSSSelector::kPseudoDir:
      feature = WebFeature::kCSSSelectorPseudoDir;
      break;
    case CSSSelector::kPseudoHas:
      feature = WebFeature::kCSSSelectorPseudoHas;
      break;
    case CSSSelector::kPseudoState:
      feature = WebFeature::kCSSSelectorPseudoState;
      break;
    case CSSSelector::kPseudoUserValid:
      feature = WebFeature::kCSSSelectorUserValid;
      break;
    case CSSSelector::kPseudoUserInvalid:
      feature = WebFeature::kCSSSelectorUserInvalid;
      break;
    case CSSSelector::kPseudoNthChild:
      if (selector->SelectorList()) {
        feature = WebFeature::kCSSSelectorNthChildOfSelector;
      }
      break;
    case CSSSelector::kPseudoModal:
      feature = WebFeature::kCSSSelectorPseudoModal;
      break;
    case CSSSelector::kPseudoFileSelectorButton:
      feature = WebFeature::kCSSSelectorPseudoFileSelectorButton;
      break;
    case CSSSelector::kPseudoVisited:
      if (has_visited_pseudo) {
        *has_visited_pseudo = true;
      }
      break;
    case CSSSelector::kPseudoActiveViewTransition:
      feature = WebFeature::kActiveViewTransitionPseudo;
      break;
    default:
      break;
  }
  if (feature.has_value()) {
    if (Deprecation::IsDeprecated(*feature)) {
      context->CountDeprecation(*feature);
    } else {
      context->Count(*feature);
    }
  }
  if (selector->Relation() == CSSSelector::kIndirectAdjacent) {
    context->Count(WebFeature::kCSSSelectorIndirectAdjacent);
  }
  if (selector->SelectorList()) {
    for (const CSSSelector* current = selector->SelectorList()->First();
         current; current = current->NextSimpleSelector()) {
      RecordUsageAndDeprecationsOneSelector(current, context,
                                            has_visited_pseudo);
    }
  }
}

void CSSSelectorParser::RecordUsageAndDeprecations(
    const base::span<CSSSelector> selector_vector,
    bool* has_visited_pseudo) {
  if (!context_->IsUseCounterRecordingEnabled()) {
    return;
  }
  if (context_->Mode() == kUASheetMode) {
    return;
  }

  for (const CSSSelector& current : selector_vector) {
    RecordUsageAndDeprecationsOneSelector(&current, context_,
                                          has_visited_pseudo);
  }
}

bool CSSSelectorParser::ContainsUnknownWebkitPseudoElements(
    base::span<CSSSelector> selectors) {
  for (const CSSSelector& current : selectors) {
    if (current.GetPseudoType() != CSSSelector::kPseudoWebKitCustomElement) {
      continue;
    }
    WebFeature feature = FeatureForWebKitCustomPseudoElement(current.Value());
    if (feature == WebFeature::kCSSSelectorWebkitUnknownPseudo) {
      return true;
    }
  }
  return false;
}

}  // namespace blink

"""


```
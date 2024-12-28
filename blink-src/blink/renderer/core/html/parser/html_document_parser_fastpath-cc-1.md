Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the Blink rendering engine and is specifically for the fast path of the HTML document parser.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename and comments clearly indicate this is about a "fast path" for HTML parsing. This implies it's an optimization for common, simple HTML structures.

2. **Analyze key code sections:** Focus on the main methods and data structures:
    - `HTMLFastPathParser` class: This is the main driver.
    - `Scan...` methods: These are responsible for tokenizing the HTML.
    - `Parse...` methods: These build the DOM structure.
    - `Fail` method: Handles error conditions.
    - `ProcessAttribute`:  Deals with HTML attributes.
    - `CanUseFastPath`:  Determines if the fast path can be used.
    - `UnsupportedTagTypeValueForNode`:  Identifies unsupported HTML tags.

3. **Relate to HTML, CSS, and JavaScript:**  Think about how these parsing steps connect to the web platform:
    - HTML structure is being built.
    - Attributes can affect styling (CSS) and behavior (JavaScript).
    - Character references are relevant to content display.

4. **Look for logic and assumptions:**  Pay attention to conditional statements, loops, and error handling. Identify the assumptions made for the fast path.

5. **Identify potential errors:**  Consider what could go wrong during parsing and how the fast path handles it. Think about common mistakes in HTML.

6. **Formulate the summary:** Combine the findings into a concise description of the code's purpose and key functionalities.

**Pre-computation/Analysis of the code:**

- **Tokenization (Scanning):** The code scans for tag names, attribute names, and attribute values. It handles both quoted and unquoted attribute values and has a vectorized optimization for some cases. It also deals with character references.
- **DOM Construction (Parsing):** It builds a simplified DOM tree, focusing on a limited set of common HTML elements. It handles nesting of elements.
- **Attributes:** It parses attributes and stores them in the DOM. It specifically checks for `on` attributes (event handlers) and the `is` attribute, which trigger a fallback to the full parser. It also checks for duplicate attributes.
- **Error Handling:** The `Fail` method is used to indicate parsing failures and record the reason. There are various `HtmlFastPathResult` enum values indicating different failure scenarios.
- **Fast Path Eligibility:** The `CanUseFastPath` function determines if the fast path is applicable based on factors like content policy, presence of shadow DOM, and whether it's inside a form.
- **Unsupported Tags:** The code explicitly lists many HTML tags that are *not* handled by the fast path. It uses a bitmask approach to track and log these unsupported tags.
- **Optimization:** The code uses techniques like vectorized scanning (`VECTORIZE_SCANNING`) to speed up parsing.
- **Assumptions:** The fast path makes assumptions about the structure of the HTML to avoid the complexity of the full HTML parsing algorithm. This includes assumptions about nesting rules and the absence of certain features.

**Output Structure:**

The summary should cover:
- Core function
- Relationship to HTML, CSS, and JavaScript (with examples)
- Logic and assumptions (with input/output examples if applicable)
- Common errors (with examples)
这是对 `blink/renderer/core/html/parser/html_document_parser_fastpath.cc` 文件代码片段的功能归纳，该代码片段主要负责 HTML 文档解析的**快速通道**部分。

**功能归纳:**

这段代码实现了 HTML 文档解析器的一个优化路径，旨在**快速解析结构简单、常用的 HTML 片段，避免使用完整的、更复杂的解析流程**。  它的主要功能可以归纳为以下几点：

1. **快速扫描和识别 HTML 结构:**
   - 提供了 `ScanTagname`、`ScanAttrName`、`ScanAttrValue` 等函数，用于快速扫描和识别 HTML 标签名、属性名和属性值。
   - 针对常见的属性值，提供了向量化扫描的优化 (`VECTORIZE_SCANNING`)，利用 SIMD 指令加速扫描过程。
   - 能识别带引号和不带引号的属性值。

2. **构建简化的 DOM 树:**
   - 提供了 `ParseElement`、`ParseSpecificElements`、`ParseContainerElement`、`ParseVoidElement` 等函数，用于根据扫描到的标签信息创建和连接 DOM 节点。
   - 支持解析一部分常用的 HTML 元素，这些元素在 `ParseSpecificElements` 和 `ParseElement` 函数中被明确列出（例如 `div`, `span`, `p`, `a`, `button`, `input` 等）。
   -  对于不支持的标签，会触发回退到完整的解析器。
   -  能够处理元素的属性。

3. **处理 HTML 实体引用:**
   - 提供了 `ScanHTMLCharacterReference` 函数，用于解析 HTML 实体引用（例如 `&amp;`, `&lt;`）。
   - 支持数字和命名的实体引用。

4. **错误处理和回退机制:**
   - 提供了 `Fail` 函数，用于在解析过程中遇到无法处理的情况时设置错误状态 (`failed_ = true`) 并记录错误原因 (`parse_result_`)。
   - 一旦遇到错误，快速通道解析会停止，并回退到完整的 HTML 解析器进行处理。

5. **判断是否可以使用快速通道:**
   - 提供了 `CanUseFastPath` 函数，用于判断当前解析场景是否适合使用快速通道。判断依据包括：
     - 是否启用了 Shadow DOM (`kIncludeShadowRoots`)
     - 是否启用了 tracing
     - 内容策略 (`ParserContentPolicy`)
     - 是否在 `<form>` 元素内
     - 是否使用了 declarative DOM Parts (`kParsepartsAttr` on `<template>`)

6. **性能监控和日志记录:**
   - 提供了 `LogFastPathResult` 函数，用于记录快速通道解析的结果（成功或失败），用于性能分析。
   - 提供了 `UnsupportedTagTypeValueForNode` 和相关的日志函数，用于统计快速通道不支持的 HTML 标签类型。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 这是核心，快速通道解析器直接处理 HTML 文本，并构建 HTML 元素节点。
    * **例子:**  输入 `<div><span>Hello</span></div>`，快速通道可以识别 `div` 和 `span` 标签，创建对应的 DOM 元素并建立父子关系。
* **CSS:**  快速通道解析器会解析 HTML 元素的属性，这些属性可能包含 CSS 相关的属性，例如 `class` 和 `style`。
    * **例子:** 输入 `<div class="container" style="color: blue;">Text</div>`，快速通道可以识别 `class` 和 `style` 属性及其值，虽然它不会立即应用样式，但这些信息会被存储在 DOM 元素中，供后续 CSS 处理。
* **JavaScript:** 快速通道解析器会特别检查 `on` 开头的事件处理属性，如果发现，则会放弃使用快速通道，因为它不处理 JavaScript 的执行。
    * **例子:** 输入 `<button onclick="alert('clicked')">Click me</button>`，由于存在 `onclick` 属性，快速通道会判断无法处理并回退。

**逻辑推理及假设输入与输出:**

假设输入一个简单的 HTML 片段：`"<p id='my-paragraph'>This is text.</p>"`

* **扫描阶段:**
    * `ScanTagname` 识别出 `p`。
    * `ScanAttrName` 识别出 `id`。
    * `ScanAttrValue` 识别出 `'my-paragraph'`。
* **解析阶段:**
    * `ParseSpecificElements<TagInfo::P>` 或 `ParseElementAfterTagname<TagInfo::P>` 创建一个 `<p>` 元素。
    * `ProcessAttribute` 将 `id='my-paragraph'`  添加到 `<p>` 元素的属性中。
    * `ParseChildren<TagInfo::P>` 处理子节点，这里会扫描到文本节点 "This is text."。
* **输出:**  会创建一个 `<p>` 元素节点，其 `id` 属性值为 "my-paragraph"，并包含一个文本子节点 "This is text."。

**涉及用户或者编程常见的使用错误及举例说明:**

* **使用了快速通道不支持的 HTML 标签或属性:**  例如使用了 `<article>`, `<table>`, `<svg>` 标签，或者 `data-*` 以外的自定义属性，会导致快速通道解析失败并回退。
    * **例子:** 输入 `"<article>Content</article>"`，快速通道会因为不支持 `article` 标签而失败。
* **HTML 结构不符合快速通道的预期:**  例如标签没有正确闭合，或者存在复杂的嵌套结构，可能导致解析错误。
    * **例子:** 输入 `"<div><span>Text"` (缺少 `</span>` 和 `</div>`)，快速通道可能会在扫描或解析过程中遇到意外的结尾而失败。
* **在表单元素内部插入内容:**  如果在 `<form>` 元素内部使用 `innerHTML` 等方法插入 HTML，快速通道会因为无法处理表单元素的关联而回退。

**总结这段代码的功能:**

这段代码是 Blink 引擎中 HTML 解析器的一个**性能优化模块**，它通过实现一个**轻量级的快速解析通道**，处理常见的、简单的 HTML 结构，从而加速 HTML 文档的解析过程。当遇到快速通道无法处理的情况时，它会优雅地回退到完整的、更健壮的 HTML 解析器，保证解析的正确性。 它的核心在于**快速扫描 HTML 结构、构建简化的 DOM 树、处理基本的 HTML 实体**，并具备**错误检测和回退机制**，同时会**判断是否适合使用快速通道**以实现性能优化。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_document_parser_fastpath.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
 This path could handle other valid attribute name chars, but they
    // are not as common, so it only looks for lowercase.
    const Char* start = pos_;
    while (pos_ != end_ && ((*pos_ >= 'a' && *pos_ <= 'z') || *pos_ == '-')) {
      ++pos_;
    }
    if (pos_ == end_) [[unlikely]] {
      return Fail(HtmlFastPathResult::kFailedEndOfInputReached, Span());
    }
    if (!IsValidAttributeNameChar(*pos_)) {
      return Span(start, static_cast<size_t>(pos_ - start));
    }

    // At this point name does not contain lowercase. It may contain upper-case,
    // which requires mapping. Assume it does.
    pos_ = start;
    attribute_name_buffer_.clear();
    Char c;
    // IsValidAttributeNameChar() returns false if end of input is reached.
    while (c = GetNext(), IsValidAttributeNameChar(c)) {
      if ('A' <= c && c <= 'Z') {
        c = c - ('A' - 'a');
      }
      attribute_name_buffer_.AddChar(c);
      ++pos_;
    }
    return Span(attribute_name_buffer_.data(),
                static_cast<size_t>(attribute_name_buffer_.size()));
  }

#if VECTORIZE_SCANNING
  ALWAYS_INLINE uint8_t
  ScanAttrValueVectorizedWithSingleQuote(const Char* initial_start) {
    namespace hw = hwy::HWY_NAMESPACE;
    DCHECK_GE(static_cast<size_t>(end_ - pos_), kVectorizationThreshold);
    hw::FixedTag<uint8_t, 16> tag;
    // ASCII representation of interesting symbols:
    //   ': 0010 0111
    //  \r: 0000 1101
    //  \0: 0000 0000
    //   &: 0010 0110
    // The lower nibbles represent offsets into the |low_nibble_table|. The
    // values in the table are the corresponding characters.
    const auto low_nibble_table = hw::Dup128VecFromValues(
        tag, '\0', 0, 0, 0, 0, 0, '&', '\'', 0, 0, 0, 0, 0, '\r', 0, 0);
    return SimdAdvanceAndLookup(pos_, end_, low_nibble_table);
  }

  ALWAYS_INLINE uint8_t
  ScanAttrValueVectorizedWithDoubleQuote(const Char* initial_start) {
    namespace hw = hwy::HWY_NAMESPACE;
    DCHECK_GE(static_cast<size_t>(end_ - pos_), kVectorizationThreshold);
    hw::FixedTag<uint8_t, 16> tag;
    // ASCII representation of interesting symbols:
    //   ": 0010 0010
    //  \r: 0000 1101
    //  \0: 0000 0000
    //   &: 0010 0110
    // The lower nibbles represent offsets into the |low_nibble_table|. The
    // values in the table are the corresponding characters.
    const auto low_nibble_table = hw::Dup128VecFromValues(
        tag, '\0', 0, '"', 0, 0, 0, '&', 0, 0, 0, 0, 0, 0, '\r', 0, 0);
    return SimdAdvanceAndLookup(pos_, end_, low_nibble_table);
  }

  ALWAYS_INLINE std::pair<Span, USpan> ScanAttrValueVectorized(
      Char quote_symbol,
      const Char* initial_start) {
    DCHECK(quote_symbol == '\'' || quote_symbol == '\"');
    const uint8_t found_character =
        quote_symbol == '\''
            ? ScanAttrValueVectorizedWithSingleQuote(initial_start)
            : ScanAttrValueVectorizedWithDoubleQuote(initial_start);

    switch (found_character) {
      case kNeverMatchedChar:
        DCHECK_EQ(pos_, end_);
        return Fail(HtmlFastPathResult::kFailedParsingQuotedAttributeValue,
                    std::pair{Span{}, USpan{}});
      case '\0':
        DCHECK_EQ(*pos_, '\0');
        // \0 is generally mapped to \uFFFD (but there are exceptions).
        // Fallback to normal path as this generally does not happen often.
        return Fail(HtmlFastPathResult::kFailedParsingQuotedAttributeValue,
                    std::pair{Span{}, USpan{}});
      case '\'':
      case '"': {
        DCHECK(*pos_ == '\'' || *pos_ == '\"');
        Span result =
            Span{initial_start, static_cast<size_t>(pos_ - initial_start)};
        // Consume quote.
        ConsumeNext();
        return {result, USpan{}};
      }
      case '&':
      case '\r':
        DCHECK(*pos_ == '&' || *pos_ == '\r');
        pos_ = initial_start - 1;
        return {Span{}, ScanEscapedAttrValue()};
    };

    NOTREACHED();
  }
#endif  // VECTORIZE_SCANNING

  std::pair<Span, USpan> ScanAttrValue() {
    Span result;
    SkipWhitespace();
    const Char* start = pos_;
    // clang-format off
    if (Char quote_char = GetNext();
        quote_char == '"' || quote_char == '\'') {
      // clang-format on
      start = ++pos_;
#if VECTORIZE_SCANNING
      if (static_cast<size_t>(end_ - pos_) >= kVectorizationThreshold) {
        return ScanAttrValueVectorized(quote_char, start);
      }
#endif  // VECTORIZE_SCANNING
      while (pos_ != end_) {
        uint16_t c = GetNext();
        static_assert('\'' > '\"');
        // The c is mostly like to be a~z or A~Z, the ASCII code value of a~z
        // and A~Z is greater than kSingleQuote, so we just need to compare
        // kSingleQuote here.
        if (c > '\'') [[likely]] {
          ++pos_;
        } else if (c == '&' || c == '\r') {
          pos_ = start - 1;
          return {Span{}, ScanEscapedAttrValue()};
        } else if (c == '\'' || c == '\"') {
          break;
        } else if (c == '\0') [[unlikely]] {
          // \0 is generally mapped to \uFFFD (but there are exceptions).
          // Fallback to normal path as this generally does not happen often.
          return Fail(HtmlFastPathResult::kFailedParsingQuotedAttributeValue,
                      std::pair{Span{}, USpan{}});
        } else {
          ++pos_;
        }
      }
      if (pos_ == end_) {
        return Fail(HtmlFastPathResult::kFailedParsingQuotedAttributeValue,
                    std::pair{Span{}, USpan{}});
      }
      result = Span{start, static_cast<size_t>(pos_ - start)};
      if (ConsumeNext() != quote_char) {
        return Fail(HtmlFastPathResult::kFailedParsingQuotedAttributeValue,
                    std::pair{Span{}, USpan{}});
      }
    } else {
      while (IsValidUnquotedAttributeValueChar(GetNext())) {
        ++pos_;
      }
      result = Span{start, static_cast<size_t>(pos_ - start)};
      if (!IsCharAfterUnquotedAttribute(GetNext())) {
        return Fail(HtmlFastPathResult::kFailedParsingUnquotedAttributeValue,
                    std::pair{Span{}, USpan{}});
      }
    }
    return {result, USpan{}};
  }

  // Slow path for scanning an attribute value. Used for special cases such
  // as '&' and '\r'.
  USpan ScanEscapedAttrValue() {
    Span result;
    SkipWhitespace();
    uchar_buffer_.clear();
    const Char* start = pos_;
    if (Char quote_char = GetNext(); quote_char == '"' || quote_char == '\'') {
      start = ++pos_;
      while (pos_ != end_ && GetNext() != quote_char) {
        if (failed_) {
          return USpan{};
        }
        if (GetNext() == '&') {
          ScanHTMLCharacterReference(&uchar_buffer_);
        } else if (GetNext() == '\r') {
          // Normalize "\r\n" to "\n" according to
          // https://infra.spec.whatwg.org/#normalize-newlines.
          if (pos_ + 1 != end_ && pos_[1] == '\n') {
            ++pos_;
          }
          uchar_buffer_.AddChar('\n');
          ++pos_;
        } else {
          uchar_buffer_.AddChar(*pos_);
          ++pos_;
        }
      }
      if (pos_ == end_) {
        return Fail(
            HtmlFastPathResult::kFailedParsingQuotedEscapedAttributeValue,
            USpan());
      }
      result = Span{start, static_cast<size_t>(pos_ - start)};
      if (ConsumeNext() != quote_char) {
        return Fail(
            HtmlFastPathResult::kFailedParsingQuotedEscapedAttributeValue,
            USpan{});
      }
    } else {
      return Fail(
          HtmlFastPathResult::kFailedParsingUnquotedEscapedAttributeValue,
          USpan{});
    }
    return USpan{uchar_buffer_.data(), uchar_buffer_.size()};
  }

  void ScanHTMLCharacterReference(UCharLiteralBufferType* out) {
    DCHECK_EQ(*pos_, '&');
    ++pos_;
    const Char* start = pos_;
    while (true) {
      // A rather arbitrary constant to prevent unbounded lookahead in the case
      // of ill-formed input.
      constexpr int kMaxLength = 20;
      if (pos_ == end_ || pos_ - start > kMaxLength) {
        return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
      }
      if (*pos_ == '\0') [[unlikely]] {
        return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
      }
      // Note: the fast path will only parse `;`-terminated character
      // references, and will fail (above) on others, e.g. `A&ampB`.
      if (ConsumeNext() == ';') {
        break;
      }
    }
    Span reference = Span{start, static_cast<size_t>(pos_ - start) - 1};
    // There are no valid character references shorter than that. The check
    // protects the indexed accesses below.
    constexpr size_t kMinLength = 2;
    if (reference.size() < kMinLength) {
      return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
    }
    if (reference[0] == '#') {
      UChar32 res = 0;
      if (reference[1] == 'x' || reference[1] == 'X') {
        for (size_t i = 2; i < reference.size(); ++i) {
          Char c = reference[i];
          res *= 16;
          if (c >= '0' && c <= '9') {
            res += c - '0';
          } else if (c >= 'a' && c <= 'f') {
            res += c - 'a' + 10;
          } else if (c >= 'A' && c <= 'F') {
            res += c - 'A' + 10;
          } else {
            return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
          }
          if (res > UCHAR_MAX_VALUE) {
            return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
          }
        }
      } else {
        for (size_t i = 1; i < reference.size(); ++i) {
          Char c = reference[i];
          res *= 10;
          if (c >= '0' && c <= '9') {
            res += c - '0';
          } else {
            return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
          }
          if (res > UCHAR_MAX_VALUE) {
            return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
          }
        }
      }
      DecodedHTMLEntity entity;
      AppendLegalEntityFor(res, entity);
      for (size_t i = 0; i < entity.length; ++i) {
        out->AddChar(entity.data[i]);
      }
      // Handle the most common named references.
    } else if (reference == "amp") {
      out->AddChar('&');
    } else if (reference == "lt") {
      out->AddChar('<');
    } else if (reference == "gt") {
      out->AddChar('>');
    } else if (reference == "nbsp") {
      out->AddChar(0xa0);
    } else {
      // This handles uncommon named references.
      // This does not use `reference` as `reference` does not contain the `;`,
      // which impacts behavior of ConsumeHTMLEntity().
      String input_string{base::span(start, pos_)};
      SegmentedString input_segmented{input_string};
      DecodedHTMLEntity entity;
      bool not_enough_characters = false;
      if (!ConsumeHTMLEntity(input_segmented, entity, not_enough_characters) ||
          not_enough_characters) {
        return Fail(HtmlFastPathResult::kFailedParsingCharacterReference);
      }
      for (size_t i = 0; i < entity.length; ++i) {
        out->AddChar(entity.data[i]);
      }
      // ConsumeHTMLEntity() may not have consumed all the input.
      const unsigned remaining_length = input_segmented.length();
      if (remaining_length) {
        pos_ -= remaining_length;
      }
    }
  }

  void Fail(HtmlFastPathResult result) {
    // This function may be called multiple times. Only record the result the
    // first time it's called.
    if (failed_) {
      return;
    }
    parse_result_ = result;
    failed_ = true;
  }

  template <class R>
  R Fail(HtmlFastPathResult result, R res) {
    Fail(result);
    return res;
  }

  Char GetNext() {
    DCHECK_LE(pos_, end_);
    if (pos_ == end_) {
      Fail(HtmlFastPathResult::kFailedEndOfInputReached);
      return '\0';
    }
    return *pos_;
  }

  Char ConsumeNext() {
    if (pos_ == end_) {
      return Fail(HtmlFastPathResult::kFailedEndOfInputReached, '\0');
    }
    return *(pos_++);
  }

  template <class ParentTag>
  void ParseChildren(ContainerNode* parent) {
    while (true) {
      ScanTextResult<Char> scanned_text = ScanText();
      if (failed_) {
        return;
      }
      DCHECK(scanned_text.text.empty() || !scanned_text.escaped_text);
      if (!scanned_text.text.empty()) {
        const auto text = scanned_text.text;
        if (text.size() >= Text::kDefaultLengthLimit) {
          return Fail(HtmlFastPathResult::kFailedBigText);
        }
        parent->ParserAppendChildInDocumentFragment(
            Text::Create(document_, scanned_text.TryCanonicalizeString()));
      } else if (scanned_text.escaped_text) {
        if (scanned_text.escaped_text->size() >= Text::kDefaultLengthLimit) {
          return Fail(HtmlFastPathResult::kFailedBigText);
        }
        parent->ParserAppendChildInDocumentFragment(
            Text::Create(document_, scanned_text.escaped_text->AsString()));
      }
      if (pos_ == end_) {
        return;
      }
      DCHECK_EQ(*pos_, '<');
      ++pos_;
      if (GetNext() == '/') {
        // We assume that we found the closing tag. The tagname will be checked
        // by the caller `ParseContainerElement()`.
        return;
      } else {
        if (++element_depth_ ==
            HTMLConstructionSite::kMaximumHTMLParserDOMTreeDepth) {
          return Fail(HtmlFastPathResult::kFailedMaxDepth);
        }
        Element* child = ParentTag::ParseChild(*this);
        --element_depth_;
        if (failed_) {
          return;
        }
        parent->ParserAppendChildInDocumentFragment(child);
      }
    }
  }

  Attribute ProcessAttribute(Span name_span,
                             std::pair<Span, USpan> value_span) {
    QualifiedName name = LookupHTMLAttributeName(
        name_span.data(), static_cast<unsigned>(name_span.size()));
    if (name == g_null_name) {
      name = QualifiedName(AtomicString(name_span));
    }

    // The string pointer in |value| is null for attributes with no values, but
    // the null atom is used to represent absence of attributes; attributes with
    // no values have the value set to an empty atom instead.
    AtomicString value;
    if (value_span.second.empty()) {
      value = AtomicString(value_span.first);
    } else {
      value = AtomicString(value_span.second);
    }
    if (value.IsNull()) {
      value = g_empty_atom;
    }
    return Attribute(std::move(name), std::move(value));
  }

  void ParseAttributes(Element* parent) {
    DCHECK(attribute_buffer_.empty());
    DCHECK(attribute_names_.empty());
    while (true) {
      Span attr_name = ScanAttrName();
      if (attr_name.empty()) {
        if (GetNext() == '>') {
          ++pos_;
          break;
        } else if (GetNext() == '/') {
          ++pos_;
          SkipWhitespace();
          if (ConsumeNext() != '>') {
            return Fail(HtmlFastPathResult::kFailedParsingAttributes);
          }
          break;
        } else {
          return Fail(HtmlFastPathResult::kFailedParsingAttributes);
        }
      }
      if (attr_name.size() > 2 && attr_name[0] == 'o' && attr_name[1] == 'n') {
        // These attributes likely contain script that may be executed at random
        // points, which could cause problems if parsing via the fast path
        // fails. For example, an image's onload event.
        return Fail(HtmlFastPathResult::kFailedOnAttribute);
      }
      if (attr_name.size() == 2 && attr_name[0] == 'i' && attr_name[1] == 's') {
        // This is for the "is" attribute case.
        return Fail(HtmlFastPathResult::kFailedParsingAttributes);
      }
      if (GetNext() != '=') {
        SkipWhitespace();
      }
      std::pair<Span, USpan> attr_value = {};
      if (GetNext() == '=') {
        ++pos_;
        attr_value = ScanAttrValue();
        SkipWhitespace();
      }
      Attribute attribute = ProcessAttribute(attr_name, attr_value);
      attribute_names_.push_back(attribute.LocalName().Impl());
      attribute_buffer_.push_back(std::move(attribute));
    }
    std::sort(attribute_names_.begin(), attribute_names_.end());
    if (std::adjacent_find(attribute_names_.begin(), attribute_names_.end()) !=
        attribute_names_.end()) {
      // Found duplicate attributes. We would have to ignore repeated
      // attributes, but leave this to the general parser instead.
      return Fail(HtmlFastPathResult::kFailedParsingAttributes);
    }
    parent->ParserSetAttributes(attribute_buffer_);
    attribute_buffer_.clear();
    attribute_names_.resize(0);
  }

  template <class... Tags>
  Element* ParseSpecificElements() {
    Span tagname = ScanTagname();
    return ParseSpecificElements<Tags...>(tagname);
  }

  template <void* = nullptr>
  Element* ParseSpecificElements(Span tagname) {
    return Fail(HtmlFastPathResult::kFailedParsingSpecificElements, nullptr);
  }

  template <class Tag, class... OtherTags>
  Element* ParseSpecificElements(Span tagname) {
    if (tagname == Tag::tagname) {
      return ParseElementAfterTagname<Tag>();
    }
    return ParseSpecificElements<OtherTags...>(tagname);
  }

  template <bool non_phrasing_content>
  Element* ParseElement() {
    Span tagname = ScanTagname();
    if (tagname.empty()) {
      return Fail(HtmlFastPathResult::kFailedParsingElement, nullptr);
    }
    // HTML has complicated rules around auto-closing tags and re-parenting
    // DOM nodes. We avoid complications with auto-closing rules by disallowing
    // certain nesting. In particular, we bail out if non-phrasing-content
    // elements are nested into elements that require phrasing content.
    // Similarly, we disallow nesting <a> tags. But tables for example have
    // complex re-parenting rules that cannot be captured in this way, so we
    // cannot support them.
    //
    // If this switch has duplicate cases, then `TagnameHash()` needs to be
    // updated.
    // Clang has a hard time formatting this, disable clang format.
    // clang-format off
#define TAG_CASE(Tagname)                                                      \
    case TagnameHash(TagInfo::Tagname::tagname):                               \
      if constexpr (non_phrasing_content                                       \
                      ? TagInfo::Tagname::AllowedInFlowContent()               \
                      : TagInfo::Tagname::AllowedInPhrasingOrFlowContent()) {  \
        /* See comment in Run() for details on why equality is checked */      \
        /* here. */                                                            \
        if (tagname == TagInfo::Tagname::tagname) {                            \
          return ParseElementAfterTagname<typename TagInfo::Tagname>();        \
        }                                                                      \
      }                                                                        \
      break;

    switch (TagnameHash(tagname)) {
      case TagnameHash(TagInfo::A::tagname):
        // <a> tags must not be nested, because HTML parsing would auto-close
        // the outer one when encountering a nested one.
        if (tagname == TagInfo::A::tagname && !inside_of_tag_a_) {
          return non_phrasing_content
                     ? ParseElementAfterTagname<typename TagInfo::A>()
                     : ParseElementAfterTagname<
                           typename TagInfo::AWithPhrasingContent>();
        }
        break;
      TAG_CASE(B)
      TAG_CASE(Br)
      TAG_CASE(Button)
      TAG_CASE(Div)
      TAG_CASE(Footer)
      TAG_CASE(I)
      TAG_CASE(Input)
      case TagnameHash(TagInfo::Li::tagname):
        if constexpr (non_phrasing_content
                          ? TagInfo::Li::AllowedInFlowContent()
                          : TagInfo::Li::AllowedInPhrasingOrFlowContent()) {
          // See comment in Run() for details on why equality is checked here.
          // <li>s autoclose when multiple are encountered. For example,
          // <li><li></li></li> results in sibling <li>s, not nested <li>s. Fail
          // in such a case.
          if (tagname == TagInfo::Li::tagname && !inside_of_tag_li_) {
            inside_of_tag_li_ = true;
            Element* result = ParseElementAfterTagname<typename TagInfo::Li>();
            inside_of_tag_li_ = false;
            return result;
          }
        }
        break;
      TAG_CASE(Label)
      TAG_CASE(Option)
      TAG_CASE(Ol)
      TAG_CASE(P)
      TAG_CASE(Select)
      TAG_CASE(Span)
      TAG_CASE(Strong)
      TAG_CASE(Ul)
#undef TAG_CASE
      default:
        break;
    }
    // clang-format on
    return Fail(HtmlFastPathResult::kFailedUnsupportedTag, nullptr);
  }

  template <class Tag>
  Element* ParseElementAfterTagname() {
    if constexpr (Tag::is_void) {
      return ParseVoidElement(Tag::Create(document_));
    } else {
      return ParseContainerElement<Tag>(Tag::Create(document_));
    }
  }

  template <class Tag>
  Element* ParseContainerElement(Element* element) {
    ParseAttributes(element);
    if (failed_) {
      return element;
    }
    element->BeginParsingChildren();
    ParseChildren<Tag>(element);
    if (failed_ || pos_ == end_) {
      return Fail(HtmlFastPathResult::kFailedEndOfInputReachedForContainer,
                  element);
    }
    // ParseChildren<Tag>(element) stops after the (hopefully) closing tag's `<`
    // and fails if the the current char is not '/'.
    DCHECK_EQ(*pos_, '/');
    ++pos_;
    // -1 as the name includes \0.
    const size_t tag_length = std::size(Tag::tagname) - 1;
    DCHECK_LE(pos_, end_);
    // <= as there needs to be a '>'.
    if (static_cast<size_t>(end_ - pos_) <= tag_length) {
      return Fail(HtmlFastPathResult::kFailedUnexpectedTagNameCloseState,
                  element);
    }
    Span tag_name_span(pos_, tag_length);
    pos_ += tag_length;
    if (tag_name_span == Tag::tagname ||
        SpanMatchesLowercase(tag_name_span, Tag::tagname)) {
      SkipWhitespace();
      if (ConsumeNext() != '>') {
        return Fail(HtmlFastPathResult::kFailedUnexpectedTagNameCloseState,
                    element);
      }
    } else {
      return Fail(HtmlFastPathResult::kFailedEndTagNameMismatch, element);
    }
    element->FinishParsingChildren();
    return element;
  }

  Element* ParseVoidElement(Element* element) {
    ParseAttributes(element);
    if (failed_) {
      return element;
    }
    element->BeginParsingChildren();
    element->FinishParsingChildren();
    return element;
  }
};

void LogFastPathResult(HtmlFastPathResult result) {
  UMA_HISTOGRAM_ENUMERATION("Blink.HTMLFastPathParser.ParseResult", result);
  if (result != HtmlFastPathResult::kSucceeded) {
    VLOG(2) << "innerHTML fast-path parser failed, "
            << static_cast<int>(result);
  }
}

bool CanUseFastPath(Document& document,
                    Element& context_element,
                    ParserContentPolicy policy,
                    HTMLFragmentParsingBehaviorSet behavior) {
  if (behavior.Has(HTMLFragmentParsingBehavior::kIncludeShadowRoots)) {
    LogFastPathResult(HtmlFastPathResult::kFailedShadowRoots);
    return false;
  }

  // Disable when tracing is enabled to preserve trace behavior.
  bool tracing_enabled = false;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("devtools.timeline", &tracing_enabled);
  if (tracing_enabled) {
    LogFastPathResult(HtmlFastPathResult::kFailedTracingEnabled);
    return false;
  }

  // We could probably allow other content policies too, as we do not support
  // scripts or plugins anyway.
  if (policy != ParserContentPolicy::kAllowScriptingContent) {
    LogFastPathResult(HtmlFastPathResult::kFailedParserContentPolicy);
    return false;
  }
  // If we are within a form element, we would need to create associations,
  // which we do not. Therefore, we do not support this case.
  // See HTMLConstructionSite::InitFragmentParsing() and
  // HTMLConstructionSite::CreateElement() for the corresponding code on the
  // slow-path.
  auto* template_element = DynamicTo<HTMLTemplateElement>(context_element);
  if (!template_element && Traversal<HTMLFormElement>::FirstAncestorOrSelf(
                               context_element) != nullptr) {
    LogFastPathResult(HtmlFastPathResult::kFailedInForm);
    return false;
  }

  // TODO(crbug.com/1453291) For now, declarative DOM Parts are not supported by
  // the fast path parser.
  if (RuntimeEnabledFeatures::DOMPartsAPIEnabled() && template_element &&
      template_element->hasAttribute(html_names::kParsepartsAttr)) {
    LogFastPathResult(HtmlFastPathResult::kFailedUnsupportedContextTag);
    return false;
  }
  return true;
}

// A hand picked enumeration of the most frequently used tags on web pages with
// some amount of grouping. Ranking comes from
// (https://discuss.httparchive.org/t/use-of-html-elements/1438).
//
// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused (unless the histogram name is
// updated).
enum class UnsupportedTagType : uint32_t {
  // The tag is supported.
  kSupported = 0,
  kImg = 1 << 0,
  kAside = 1 << 1,
  kU = 1 << 2,
  kHr = 1 << 3,
  // This is h1-h6.
  kH = 1 << 4,
  kEm = 1 << 5,
  // The tag is not html.
  kNotHtml = 1 << 6,
  // The tag is a known html tag, but not one covered by this enum.
  kOtherHtml = 1 << 7,
  kForm = 1 << 8,
  // This includes header, footer, and section.
  kArticleLike = 1 << 9,
  kNav = 1 << 10,
  kIFrame = 1 << 11,
  // This includes tr, td, tbody, th.
  kTableLike = 1 << 12,
  // This includes dl, dt, dd.
  kDescriptionList = 1 << 13,
  kIns = 1 << 14,
  kBlockquote = 1 << 15,
  kCenter = 1 << 16,
  kSmall = 1 << 17,
  kFont = 1 << 18,
  kFieldset = 1 << 19,
  kTextarea = 1 << 20,
  kTime = 1 << 21,
  kSvg = 1 << 22,
  kBody = 1 << 23,
  kMaxValue = kBody,
};

constexpr uint32_t kAllUnsupportedTags =
    (static_cast<uint32_t>(UnsupportedTagType::kMaxValue) << 1) - 1;
// If UnsupportedTagType is > 24, then need to add a fourth chunk to the
// overall histogram.
static_assert(kAllUnsupportedTags < (1 << 24));

#define CHECK_TAG_TYPE(t)                       \
  if (node.HasTagName(html_names::k##t##Tag)) { \
    return UnsupportedTagType::k##t;            \
  }

#define NODE_HAS_TAG_NAME(t) node.HasTagName(html_names::k##t##Tag) ||

// Returns the UnsupportedTagType for node. Returns 0 if `node` is one of the
// supported tags.
UnsupportedTagType UnsupportedTagTypeValueForNode(const Node& node) {
  // "false" is needed as NODE_HAS_TAG_NAME has a trailing '||'. Without it,
  // would get compile errors.
  const bool hack_for_macro_to_work_in_conditional = false;
  if (SUPPORTED_TAGS(NODE_HAS_TAG_NAME) hack_for_macro_to_work_in_conditional) {
    // Known tag.
    return UnsupportedTagType::kSupported;
  }
  if (node.HasTagName(html_names::kH1Tag) ||
      node.HasTagName(html_names::kH2Tag) ||
      node.HasTagName(html_names::kH3Tag) ||
      node.HasTagName(html_names::kH4Tag) ||
      node.HasTagName(html_names::kH5Tag) ||
      node.HasTagName(html_names::kH6Tag)) {
    return UnsupportedTagType::kH;
  }
  if (node.HasTagName(html_names::kArticleTag) ||
      node.HasTagName(html_names::kHeaderTag) ||
      node.HasTagName(html_names::kFooterTag) ||
      node.HasTagName(html_names::kSectionTag)) {
    return UnsupportedTagType::kArticleLike;
  }
  if (node.HasTagName(html_names::kTableTag) ||
      node.HasTagName(html_names::kTrTag) ||
      node.HasTagName(html_names::kTdTag) ||
      node.HasTagName(html_names::kTbodyTag) ||
      node.HasTagName(html_names::kThTag)) {
    return UnsupportedTagType::kTableLike;
  }
  if (node.HasTagName(html_names::kDlTag) ||
      node.HasTagName(html_names::kDtTag) ||
      node.HasTagName(html_names::kDdTag)) {
    return UnsupportedTagType::kDescriptionList;
  }
  if (node.HasTagName(svg_names::kSVGTag)) {
    return UnsupportedTagType::kSvg;
  }
  CHECK_TAG_TYPE(Aside)
  CHECK_TAG_TYPE(U)
  CHECK_TAG_TYPE(Hr)
  CHECK_TAG_TYPE(Em)
  CHECK_TAG_TYPE(Form)
  CHECK_TAG_TYPE(Nav)
  CHECK_TAG_TYPE(IFrame)
  CHECK_TAG_TYPE(Ins)
  CHECK_TAG_TYPE(Blockquote)
  CHECK_TAG_TYPE(Center)
  CHECK_TAG_TYPE(Small)
  CHECK_TAG_TYPE(Font)
  CHECK_TAG_TYPE(Fieldset)
  CHECK_TAG_TYPE(Textarea)
  CHECK_TAG_TYPE(Time)
  CHECK_TAG_TYPE(Body)
  if (node.IsHTMLElement() && To<Element>(node).TagQName().IsDefinedName()) {
    return UnsupportedTagType::kOtherHtml;
  }
  return UnsupportedTagType::kNotHtml;
}

// Histogram names used when logging unsupported tag type.
const char* kUnsupportedTagTypeCompositeName =
    "Blink.HTMLFastPathParser.UnsupportedTag.CompositeMaskV2";
const char* kUnsupportedTagTypeMaskNames[] = {
    "Blink.HTMLFastPathParser.UnsupportedTag.Mask0V2",
    "Blink.HTMLFastPathParser.UnsupportedTag.Mask1V2",
    "Blink.HTMLFastPathParser.UnsupportedTag.Mask2V2",
};

// Histogram names used when logging unsupported context tag type.
const char* kUnsupportedContextTagTypeCompositeName =
    "Blink.HTMLFastPathParser.UnsupportedContextTag.CompositeMaskV2";
const char* kUnsupportedContextTagTypeMaskNames[] = {
    "Blink.HTMLFastPathParser.UnsupportedContextTag.Mask0V2",
    "Blink.HTMLFastPathParser.UnsupportedContextTag.Mask1V2",
    "Blink.HTMLFastPathParser.UnsupportedContextTag.Mask2V2",
};

// Logs histograms for either an unsupported tag or unsupported context tag.
// `type_mask` is a bitmask of the unsupported tags that were encountered. As
// the uma frontend doesn't handle large bitmasks well, there are 4 separate
// histograms logged:
// . histogram for bits 1-8, 9-16, 17-24. The names used for these histograms
//   is specified in `mask_histogram_names`.
// . A histogram identifying which bit ranges of `type_mask` have at least one
//   bit set. More specifically:
//   . bit 1 set if `type_mask` has at least one bit set in bits 1-8.
//   . bit 2 set if `type_mask` has at least one bit set in bits 9-16.
//   . bit 3 set if `type_mask` has at least one bit set in bits 17-24.
void LogFastPathUnsupportedTagTypeDetails(uint32_t type_mask,
                                          const char* composite_histogram_name,
                                          const char* mask_histogram_names[]) {
  // This should only be called once an unsupported tag is encountered.
  DCHECK_NE(static_cast<uint32_t>(0), type_mask);
  uint32_t chunk_mask = 0;
  if ((type_mask & 0xFF) != 0) {
    chunk_mask |= 1;
    base::UmaHistogramExactLinear(mask_histogram_names[0], type_mask & 0xFF,
                                  256);
  }
  if (((type_mask >> 8) & 0xFF) != 0) {
    chunk_mask |= 2;
    base::UmaHistogramExactLinear(mask_histogram_names[1],
                                  (type_mask >> 8) & 0xFF, 256);
  }
  if (((type_mask >> 16) & 0xFF) != 0) {
    chunk_mask |= 4;
    base::UmaHistogramExactLinear(mask_histogram_names[2],
                                  (type_mask >> 16) & 0xFF, 256);
  }
  base::UmaHistogramExactLinear(composite_histogram_name, chunk_mask, 8);
}

template <class Char>
bool TryParsingHTMLFragmentImpl(const base::span<const Char>& source,
                                Document& document,
                                ContainerNode& root_node,
                                Element& context_element,
                                HTMLFragmentParsingBehaviorSet behavior,
                                bool* failed_because_unsupported_tag) {
  base::ElapsedTimer parse_timer;
  int number_of_bytes_parsed;
  HTMLFastPathParser<Char> parser{source, document, root_node};
  const bool success = parser.Run(context_element, behavior);
  LogFastPathResult(parser.parse_result());
  number_of_bytes_parsed = parser.NumberOfBytesParsed();
  // The time needed to parse is typically < 1ms (even at the 99%).
  if (success) {
    root_node.ParserFinishedBuildingDocumentFragment();
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "Blink.HTMLFastPathParser.SuccessfulParseTime2", parse_timer.Elapsed(),
        base::Microseconds(1), base::Milliseconds(10), 100);
  } else {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "Blink.HTMLFastPathParser.AbortedParseTime2", parse_timer.Elapsed(),
        base::Microseconds(1), base::Milliseconds(10), 100);
  }
  if (failed_because_unsupported_tag) {
    *failed_because_unsupported_tag =
        parser.parse_result() == HtmlFastPathResult::kFailedUnsupportedTag;
  }
  if (parser.parse_result() ==
          HtmlFastPathResult::kFailedUnsupportedContextTag &&
      RuntimeEnabledFeatures::InnerHTMLParserFastpathLogFailureEnabled()) {
    const UnsupportedTagType context_tag_type =
        UnsupportedTagTypeValueForNode(context_element);
    // If the context element isn't a valid container but is supported
    // UnsupportedTagTypeValueForNode() will return kSupported. For now this is
    // really only <br>. I suspect this is extremely rare, so don't log for now.
    if (context_tag_type != UnsupportedTagType::kSupport
"""


```
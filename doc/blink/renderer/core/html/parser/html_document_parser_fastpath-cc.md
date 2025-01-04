Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is a part of the Chromium Blink rendering engine and located in the `html_document_parser_fastpath.cc` file.

The task is to:
1. **List the functionalities** of the code.
2. **Explain its relation to JavaScript, HTML, and CSS** with examples.
3. **Provide examples of logical reasoning** with hypothetical input and output.
4. **Illustrate common user/programming errors** related to the code.
5. **Summarize the functions** of the code in this first part.

**Plan:**

1. **Analyze the included headers:** Identify the core functionalities based on the imported modules.
2. **Examine the defined macros and namespaces:** Understand the context and potential conditional compilation.
3. **Deconstruct the `HTMLFastPathParser` class:**
    - Identify the purpose of the class.
    - Analyze the `Run` method and its role in parsing.
    - Examine the helper methods for scanning and processing HTML content (e.g., `ScanText`, `ScanTagname`, `ScanAttrName`).
    - Pay attention to the error handling mechanisms (`Fail` method).
4. **Focus on the first part of the code:** Since this is part 1 of 3, concentrate on the initialization and the early stages of parsing.
5. **Relate the functionality to web technologies:** Connect the HTML parsing to how it interprets HTML structure, how it might interact with JavaScript (e.g., event attributes), and how it doesn't directly handle CSS but influences the DOM for styling.
```
这是目录为blink/renderer/core/html/parser/html_document_parser_fastpath.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

**功能列举:**

1. **快速解析HTML:** 该文件实现了 Chromium Blink 引擎中用于快速解析 HTML 代码的 `HTMLFastPathParser` 类。这个快速解析器旨在比通用的 HTML 解析器更快地处理某些常见的 HTML 结构。

2. **支持部分HTML特性:**  `HTMLFastPathParser` 并非支持所有 HTML 语法，它专注于处理一个预定义的、常见的 HTML 子集。从引入的头文件和 `SUPPORTED_TAGS` 宏可以看出，它支持解析 `<a>`, `<b>`, `<br>`, `<button>`, `<div>`, `<footer>`, `<i>`, `<input>`, `<li>`, `<label>`, `<option>`, `<ol>`, `<p>`, `<select>`, `<span>`, `<strong>`, `<ul>` 等标签。

3. **优化性能:** 该文件通过使用递归下降解析、合并词法分析和语法分析、以及尽可能使用原始输入的子序列来避免内存分配等方式来提高解析性能。代码中还包含了使用 SIMD (Single Instruction, Multiple Data) 指令进行字符扫描的尝试 (通过 `#if VECTORIZE_SCANNING`)，这进一步体现了对性能的关注。

4. **错误处理和回退机制:**  当遇到不支持的 HTML 特性或解析错误时，快速解析器会选择“bailout”（退出），并回退到使用通用的、更健壮但可能更慢的 HTML 解析器。`Fail` 方法就体现了这种错误处理机制。

5. **处理文本内容:** 文件中定义了 `ScanTextResult` 结构体和 `ScanText`、`ScanEscapedText` 方法，用于扫描和处理 HTML 文本内容，包括处理 HTML 实体转义。

6. **处理标签和属性:**  代码中包含 `ScanTagname` 和 `ScanAttrName` 方法，用于从 HTML 代码中提取标签名和属性名。

7. **限制:** 注释中明确列出了快速解析器的限制，例如不支持自动闭合标签、严格的嵌套规则、不支持自定义元素、不支持重复属性、对未加引号的属性名有严格限制、仅支持少量字符实体引用等。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:** 该文件的核心功能就是解析 HTML 代码。它将 HTML 字符串转换为 Blink 引擎可以理解的 DOM 结构。例如，当解析到 `<div>` 标签时，会创建 `HTMLDivElement` 对象。

* **JavaScript:** 虽然此文件本身不包含 JavaScript 代码，但其解析的 HTML 结构会影响 JavaScript 的执行。例如，如果 HTML 中包含 `<button>` 元素，JavaScript 可以通过 DOM API 获取到这个元素并添加事件监听器。此外，`innerHTML` 的设置操作会触发此快速路径解析器（如果条件允许）。

   * **举例:** 假设 JavaScript 代码执行了 `element.innerHTML = '<div><span>Hello</span></div>';`，Blink 引擎会尝试使用 `HTMLFastPathParser` 来快速解析这段 HTML 字符串，创建 `HTMLDivElement` 和 `HTMLSpanElement` 节点，并将它们添加到 `element` 的子节点中。

* **CSS:**  该文件不直接处理 CSS。它的职责是将 HTML 结构化。然而，解析出的 DOM 结构是 CSS 样式应用的基础。CSS 选择器会根据 DOM 树的结构来匹配元素并应用样式。

   * **举例:** 如果 HTML 中解析出 `<div class="container"><span>Text</span></div>`，那么 CSS 规则 `.container { ... }` 就能匹配到这个 `<div>` 元素。

**逻辑推理示例:**

**假设输入:**  `const char* html = "<span>test</span>";`， 并且调用 `HTMLFastPathParser` 解析这段字符串。

**输出:**  快速解析器会成功识别出 `<span>` 标签和文本内容 `test`，并创建一个 `HTMLSpanElement` 节点，其文本子节点包含 "test"。

**假设输入 (错误情况):** `const char* html = "<p>nested <p>paragraph</p></p>";`

**输出:**  由于快速解析器不支持嵌套的 `<p>` 标签，它会检测到这个错误并 "bailout"，返回失败状态，并可能记录 `HtmlFastPathResult::kFailed...` 相关的错误码。

**用户或编程常见的使用错误示例:**

1. **设置了包含不支持的 HTML 特性的 `innerHTML`:**  如果 JavaScript 代码尝试设置包含 `<script>` 标签或自定义元素的 `innerHTML`，快速解析器会因为不支持这些特性而失败。

   * **示例:** `element.innerHTML = '<my-custom-element></my-custom-element>';`  或  `element.innerHTML = '<script>alert("hello");</script>';`

2. **假设快速解析器总是成功:**  开发者可能会错误地假设 `innerHTML` 的设置会始终使用快速解析器，并且不会处理所有可能的 HTML 结构。在实际开发中，应该意识到快速解析器有其局限性，并为更复杂的情况做好准备。

3. **在期望严格 HTML 结构的地方使用了可能导致快速解析器失败的 HTML:** 例如，在需要保证正确嵌套的场景下，使用了可能导致快速解析器退出的不规范 HTML。

**第1部分的归纳总结:**

这部分代码定义了 `HTMLFastPathParser` 类的框架和部分核心功能，用于实现一个针对特定 HTML 子集的快速解析器。它包含了基本的结构定义、构造函数、`Run` 方法的初步逻辑，以及用于跳过空白符、扫描文本、标签名和属性名的辅助方法。代码中还包含了对性能优化的考虑（SIMD 指令），以及错误处理和回退到通用解析器的机制。这部分主要关注于解析器的初始化和开始解析 HTML 代码的流程。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_document_parser_fastpath.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/parser/html_document_parser_fastpath.h"

#include <algorithm>
#include <iostream>
#include <type_traits>

#include "base/metrics/histogram_functions.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_paragraph_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/parser/atomic_html_token.h"
#include "third_party/blink/renderer/core/html/parser/html_construction_site.h"
#include "third_party/blink/renderer/core/html/parser/html_entity_parser.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/segmented_string.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string_encoding.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_uchar.h"

#if defined(BLINK_ENABLE_VECTORIZED_HTML_SCANNING)
#include "third_party/highway/src/hwy/highway.h"
#define VECTORIZE_SCANNING 1
#else
#define VECTORIZE_SCANNING 0
#endif

namespace blink {

namespace {

#if VECTORIZE_SCANNING
// We use the vectorized classification trick to scan and classify characters.
// Instead of checking the string byte-by-byte (or vector-by-vector), the
// algorithm takes the lower nibbles (4-bits) of the passed string and uses them
// as offsets into the table, represented as a vector. The values corresponding
// to those offsets are actual interesting symbols. The algorithm then simply
// compares the looked up values with the input vector. The true lanes in the
// resulting vector correspond to the interesting symbols.
//
// A big shout out to Daniel Lemire for suggesting the idea. See more on
// vectorized classification in the Daniel's paper:
// https://arxiv.org/pdf/1902.08318.
//
// For relatively short incoming strings (less than 64 characters) it's assumed
// that byte-by-byte comparison is faster. TODO(340582182): According to
// microbenchmarks on M1, string larger than 16 bytes are already scanned faster
// with SIMD.
constexpr size_t kVectorizationThreshold = 64;
// The byte that shall never match any symbol. Using 0xff for it is okay since
// we only want to match ASCII chars (<=128).
constexpr uint8_t kNeverMatchedChar = 0xff;

// The result of the TryMatch function (see below). Contains the index inside
// the vector (the lane) and the found character.
struct MatchedCharacter {
  bool Matched() const { return found_character != kNeverMatchedChar; }

  size_t index_in_vector = 0;
  uint8_t found_character = kNeverMatchedChar;
};

// Tries to match the characters for the single vector. If matched, returns the
// first matched character in the vector.
template <typename D, typename VectorT>
  requires(sizeof(hwy::HWY_NAMESPACE::TFromD<D>) == 1)
HWY_ATTR ALWAYS_INLINE MatchedCharacter TryMatch(D tag,
                                                 VectorT input,
                                                 VectorT low_nibble_table,
                                                 VectorT low_nib_and_mask) {
  namespace hw = hwy::HWY_NAMESPACE;

  // Get the low nibbles.
  const auto nib_lo = input & low_nib_and_mask;
  // Lookup the values in the table using the nibbles as offsets into the table.
  const auto shuf_lo = hw::TableLookupBytes(low_nibble_table, nib_lo);
  // The values in the tables correspond to the interesting symbols. Just
  // compare them with the input vector.
  const auto result = shuf_lo == input;
  // Find the interesting symbol.
  if (const intptr_t index = hw::FindFirstTrue(tag, result); index != -1) {
    return {static_cast<size_t>(index), hw::ExtractLane(input, index)};
  }

  return {};
}

// Scans the 1-byte string and returns the first matched character (1-byte) or
// kNeverMatchedChar otherwise.
template <typename T, typename VectorT>
  requires(sizeof(T) == 1)
HWY_ATTR ALWAYS_INLINE uint8_t SimdAdvanceAndLookup(const T*& start,
                                                    const T* end,
                                                    VectorT low_nibble_table) {
  namespace hw = hwy::HWY_NAMESPACE;
  DCHECK_GE(static_cast<size_t>(end - start), kVectorizationThreshold);

  hw::FixedTag<uint8_t, 16> tag;
  static constexpr auto stride = hw::MaxLanes(tag);

  const auto low_nib_and_mask = hw::Set(tag, 0xf);

  // The main scanning loop.
  for (; start + (stride - 1) < end; start += stride) {
    const auto input = hw::LoadU(tag, reinterpret_cast<const uint8_t*>(start));
    if (const auto result =
            TryMatch(tag, input, low_nibble_table, low_nib_and_mask);
        result.Matched()) {
      start = reinterpret_cast<const T*>(start + result.index_in_vector);
      return result.found_character;
    };
  }

  // Scan the last stride.
  if (start < end) {
    const auto input =
        hw::LoadU(tag, reinterpret_cast<const uint8_t*>(end - stride));
    if (const auto result =
            TryMatch(tag, input, low_nibble_table, low_nib_and_mask);
        result.Matched()) {
      start = end - stride + result.index_in_vector;
      return result.found_character;
    }
    start = end;
  }

  return kNeverMatchedChar;
}

// This overload for 2-bytes strings uses the interleaved load to check the
// lower bytes of the string. We don't use the gather instruction, since it's
// not available on NEON (as opposed to SVE) and is emulated in Highway.
template <typename T, typename VectorT>
  requires(sizeof(T) == 2)
HWY_ATTR ALWAYS_INLINE uint8_t SimdAdvanceAndLookup(const T*& start,
                                                    const T* end,
                                                    VectorT low_nibble_table) {
  namespace hw = hwy::HWY_NAMESPACE;
  DCHECK_GE(static_cast<size_t>(end - start), kVectorizationThreshold);

  hw::FixedTag<uint8_t, 16> tag;
  static constexpr auto stride = hw::MaxLanes(tag);

  const auto low_nib_and_mask = hw::Set(tag, 0xf);

  // The main scanning loop.
  while (start + (stride - 1) < end) {
    VectorT dummy_upper;
    VectorT input;
    hw::LoadInterleaved2(tag, reinterpret_cast<const uint8_t*>(start), input,
                         dummy_upper);
    if (const auto result =
            TryMatch(tag, input, low_nibble_table, low_nib_and_mask);
        result.Matched()) {
      const auto index = result.index_in_vector;
      // Check if the upper byte is zero.
      if (*(start + index) >> 8 == 0) {
        start = reinterpret_cast<const T*>(start + index);
        return result.found_character;
      }

      start += index + 1;
      continue;
    }

    // Otherwise, continue scanning.
    start += stride;
  }

  // Scan the last stride.
  if (start < end) {
    VectorT dummy_upper;
    VectorT input;
    hw::LoadInterleaved2(tag, reinterpret_cast<const uint8_t*>(end - stride),
                         input, dummy_upper);
    for (auto result = TryMatch(tag, input, low_nibble_table, low_nib_and_mask);
         result.Matched();
         result = TryMatch(tag, input, low_nibble_table, low_nib_and_mask)) {
      const auto index = result.index_in_vector;
      // Check if the upper byte is zero.
      if (*(end - stride + index) >> 8 == 0) {
        start = reinterpret_cast<const T*>(end - stride + index);
        return result.found_character;
      }

      // Otherwise, set the corresponding lane to kNeverMatchedChar to never
      // match it again and continue.
      input = hw::InsertLane(input, index, kNeverMatchedChar);
    }
    start = end;
  }

  return kNeverMatchedChar;
}
#endif  // VECTORIZE_SCANNING

template <class Char, size_t n>
bool operator==(base::span<const Char> span, const char (&s)[n]) {
  if (span.size() != n - 1) {
    return false;
  }
  for (size_t i = 0; i < n - 1; ++i) {
    if (span[i] != s[i]) {
      return false;
    }
  }
  return true;
}

template <int n>
constexpr bool OnlyContainsLowercaseASCIILetters(const char (&s)[n]) {
  for (int i = 0; i < n - 1; ++i) {
    if (!('a' <= s[i] && s[i] <= 'z')) {
      return false;
    }
  }
  return true;
}

template <class Char, size_t n>
bool SpanMatchesLowercase(base::span<const Char> span, const char (&s)[n]) {
  DCHECK_EQ(span.size(), n - 1);
  for (size_t i = 0; i < n - 1; ++i) {
    Char lower =
        (span[i] >= 'A' && span[i] <= 'Z') ? span[i] - 'A' + 'a' : span[i];
    if (lower != s[i]) {
      return false;
    }
  }
  return true;
}

// A hash function that is just good enough to distinguish the supported
// tagnames. It needs to be adapted as soon as we have colliding tagnames.
// The implementation was chosen to map to a dense integer range to allow for
// compact switch jump-tables. If adding support for a new tag results in a
// collision, then pick a new function that minimizes the number of operations
// and results in a dense integer range. This will require some finesse, feel
// free to reach out to owners of bug 1407201 for help.
template <uint32_t n>
constexpr uint32_t TagnameHash(const char (&s)[n]) {
  // The fast-path parser only scans for letters in tagnames.
  DCHECK(OnlyContainsLowercaseASCIILetters<n>(s));
  DCHECK_EQ('\0', s[n - 1]);
  // This function is called with null-termined string, which should be used in
  // the hash implementation, hence the -2.
  return (s[0] + 17 * s[n - 2]) & 63;
}
template <class Char>
uint32_t TagnameHash(base::span<const Char> s) {
  return (s[0] + 17 * s[s.size() - 1]) & 63;
}
uint32_t TagnameHash(const String& s) {
  uint32_t l = s.length();
  return (s[0] + 17 * s[l - 1]) & 63;
}

#define SUPPORTED_TAGS(V) \
  V(A)                    \
  V(B)                    \
  V(Br)                   \
  V(Button)               \
  V(Div)                  \
  V(Footer)               \
  V(I)                    \
  V(Input)                \
  V(Li)                   \
  V(Label)                \
  V(Option)               \
  V(Ol)                   \
  V(P)                    \
  V(Select)               \
  V(Span)                 \
  V(Strong)               \
  V(Ul)

using UCharLiteralBufferType = UCharLiteralBuffer<32>;

template <class Char>
struct ScanTextResult {
  // Converts `text` to a String. This handles converting UChar to LChar if
  // possible.
  String TextToString() const;

  // HTML strings of the form '\n<space>*' are widespread on the web. Caching
  // them saves us allocations, which improves the runtime.
  String TryCanonicalizeString() const {
    DCHECK(!text.empty());
    if (is_newline_then_whitespace_string &&
        text.size() < WTF::NewlineThenWhitespaceStringsTable::kTableSize) {
      DCHECK(WTF::NewlineThenWhitespaceStringsTable::IsNewlineThenWhitespaces(
          String(text)));
      return WTF::NewlineThenWhitespaceStringsTable::GetStringForLength(
          text.size());
    }
    return TextToString();
  }

  base::span<const Char> text;
  UCharLiteralBufferType* escaped_text = nullptr;
  bool is_newline_then_whitespace_string = false;
};

template <>
String ScanTextResult<LChar>::TextToString() const {
  return String(text);
}

template <>
String ScanTextResult<UChar>::TextToString() const {
  return String(StringImpl::Create8BitIfPossible(text));
}

// This HTML parser is used as a fast-path for setting innerHTML.
// It is faster than the general parser by only supporting a subset of valid
// HTML. This way, it can be spec-compliant without following the algorithm
// described in the spec. Unsupported features or parse errors lead to bailout,
// falling back to the general HTML parser.
// It differs from the general HTML parser in the following ways.
//
// Implementation:
// - It uses recursive descent for better CPU branch prediction.
// - It merges tokenization with parsing.
// - Whenever possible, tokens are represented as subsequences of the original
//   input, avoiding allocating memory for them.
//
// Restrictions (these may evolve based on uma data, https://crbug.com/1407201):
// - No auto-closing of tags.
// - Wrong nesting of HTML elements (for example nested <p>) leads to bailout
//   instead of fix-up.
// - No custom elements, no "is"-attribute.
// - No duplicate attributes. This restriction could be lifted easily.
// - Unquoted attribute names are very restricted.
// - Many tags are unsupported, but we could support more. For example, <table>
//   because of the complex re-parenting rules
// - Only a few named "&" character references are supported.
// - No '\0'. The handling of '\0' varies depending upon where it is found
//   and in general the correct handling complicates things.
// - Fails if an attribute name starts with 'on'. Such attributes are generally
//   events that may be fired. Allowing this could be problematic if the fast
//   path fails. For example, the 'onload' event of an <img> would be called
//   multiple times if parsing fails.
// - Fails if a text is encountered larger than Text::kDefaultLengthLimit. This
//   requires special processing.
// - Fails if a deep hierarchy is encountered. This is both to avoid a crash,
//   but also at a certain depth elements get added as siblings vs children (see
//   use of HTMLConstructionSite::kMaximumHTMLParserDOMTreeDepth).
// - Fails if an <img> is encountered. Image elements request the image early
//   on, resulting in network connections. Additionally, loading the image
//   may consume preloaded resources.
template <class Char>
class HTMLFastPathParser {
  STACK_ALLOCATED();
  using Span = base::span<const Char>;
  using USpan = base::span<const UChar>;
  // 32 matches that used by HTMLToken::Attribute.
  typedef std::conditional<std::is_same_v<Char, UChar>,
                           UCharLiteralBuffer<32>,
                           LCharLiteralBuffer<32>>::type LiteralBufferType;
  static_assert(std::is_same_v<Char, UChar> || std::is_same_v<Char, LChar>);

 public:
  HTMLFastPathParser(Span source, Document& document, ContainerNode& root_node)
      : source_(source), document_(document), root_node_(root_node) {}

  bool Run(Element& context_element, HTMLFragmentParsingBehaviorSet behavior) {
    QualifiedName context_tag = context_element.TagQName();
    DCHECK(!context_tag.LocalName().empty());

    // This switch checks that the context element is supported and applies the
    // same restrictions regarding content as the fast-path parser does for a
    // corresponding nested tag.
    // This is to ensure that we preserve correct HTML structure with respect
    // to the context tag.
    //
    // If this switch has duplicate cases, then `TagnameHash()` needs to be
    // updated.
    switch (TagnameHash(context_tag.LocalName())) {
      case TagnameHash(TagInfo::Body::tagname):
        if (context_tag == html_names::kBodyTag) {
          if (behavior.Has(HTMLFragmentParsingBehavior::
                               kStripInitialWhitespaceForBody)) {
            SkipWhitespace();
          }
          ParseCompleteInput<typename TagInfo::Body>();
          return !failed_;
        }
        break;
#define TAG_CASE(Tagname)                                     \
  case TagnameHash(TagInfo::Tagname::tagname):                \
    DCHECK(html_names::k##Tagname##Tag.LocalName().Ascii() == \
           TagInfo::Tagname::tagname);                        \
    if constexpr (!TagInfo::Tagname::is_void) {               \
      /* The hash function won't return collisions for the */ \
      /* supported tags, but this function takes */           \
      /* potentially unsupported tags, which may collide. */  \
      /* Protect against that by checking equality.  */       \
      if (context_tag == html_names::k##Tagname##Tag) {       \
        ParseCompleteInput<typename TagInfo::Tagname>();      \
        return !failed_;                                      \
      }                                                       \
    }                                                         \
    break;
      SUPPORTED_TAGS(TAG_CASE)
      default:
        break;
#undef TAG_CASE
    }

    Fail(HtmlFastPathResult::kFailedUnsupportedContextTag);
    return false;
  }

  int NumberOfBytesParsed() const {
    return sizeof(Char) * static_cast<int>(pos_ - source_.data());
  }

  HtmlFastPathResult parse_result() const { return parse_result_; }

 private:
  Span source_;
  Document& document_;
  ContainerNode& root_node_;

  const Char* const end_ = source_.data() + source_.size();
  const Char* pos_ = source_.data();

  bool failed_ = false;
  bool inside_of_tag_a_ = false;
  bool inside_of_tag_li_ = false;
  // Used to limit how deep a hierarchy can be created. Also note that
  // HTMLConstructionSite ends up flattening when this depth is reached.
  unsigned element_depth_ = 0;
  LiteralBufferType char_buffer_;
  UCharLiteralBufferType uchar_buffer_;
  // Used if the attribute name contains upper case ascii (which must be
  // mapped to lower case).
  LiteralBufferType attribute_name_buffer_;
  Vector<Attribute, kAttributePrealloc> attribute_buffer_;
  Vector<StringImpl*> attribute_names_;
  HtmlFastPathResult parse_result_ = HtmlFastPathResult::kSucceeded;

  enum class PermittedParents {
    kPhrasingOrFlowContent,  // allowed in phrasing content or flow content
    kFlowContent,  // only allowed in flow content, not in phrasing content
    kSpecial,      // only allowed for special parents
  };

  struct TagInfo {
    template <class T, PermittedParents parents>
    struct Tag {
      using ElemClass = T;
      static constexpr PermittedParents kPermittedParents = parents;
      static ElemClass* Create(Document& document) {
        return MakeGarbageCollected<ElemClass>(document);
      }
      static constexpr bool AllowedInPhrasingOrFlowContent() {
        return kPermittedParents == PermittedParents::kPhrasingOrFlowContent;
      }
      static constexpr bool AllowedInFlowContent() {
        return kPermittedParents == PermittedParents::kPhrasingOrFlowContent ||
               kPermittedParents == PermittedParents::kFlowContent;
      }
    };

    template <class T, PermittedParents parents>
    struct VoidTag : Tag<T, parents> {
      static constexpr bool is_void = true;
    };

    template <class T, PermittedParents parents>
    struct ContainerTag : Tag<T, parents> {
      static constexpr bool is_void = false;

      static Element* ParseChild(HTMLFastPathParser& self) {
        return self.ParseElement</*non_phrasing_content*/ true>();
      }
    };

    // A tag that can only contain phrasing content.
    // If a tag is considered phrasing content itself is decided by
    // `allowed_in_phrasing_content`.
    template <class T, PermittedParents parents>
    struct ContainsPhrasingContentTag : ContainerTag<T, parents> {
      static constexpr bool is_void = false;

      static Element* ParseChild(HTMLFastPathParser& self) {
        return self.ParseElement</*non_phrasing_content*/ false>();
      }
    };

    struct A : ContainerTag<HTMLAnchorElement, PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "a";

      static Element* ParseChild(HTMLFastPathParser& self) {
        DCHECK(!self.inside_of_tag_a_);
        self.inside_of_tag_a_ = true;
        Element* res =
            ContainerTag<HTMLAnchorElement,
                         PermittedParents::kFlowContent>::ParseChild(self);
        self.inside_of_tag_a_ = false;
        return res;
      }
    };

    struct AWithPhrasingContent
        : ContainsPhrasingContentTag<HTMLAnchorElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "a";

      static Element* ParseChild(HTMLFastPathParser& self) {
        DCHECK(!self.inside_of_tag_a_);
        self.inside_of_tag_a_ = true;
        Element* res = ContainsPhrasingContentTag<
            HTMLAnchorElement,
            PermittedParents::kPhrasingOrFlowContent>::ParseChild(self);
        self.inside_of_tag_a_ = false;
        return res;
      }
    };

    struct B
        : ContainsPhrasingContentTag<HTMLElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "b";
      static HTMLElement* Create(Document& document) {
        return MakeGarbageCollected<HTMLElement>(html_names::kBTag, document);
      }
    };

    struct Body : ContainerTag<HTMLBodyElement, PermittedParents::kSpecial> {
      static constexpr const char tagname[] = "body";
      static HTMLElement* Create(Document& document) {
        // Body is only supported as an element for adding children, and not
        // a node that is created by this code.
        CHECK(false);
        return nullptr;
      }
    };

    struct Br
        : VoidTag<HTMLBRElement, PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "br";
    };

    struct Button
        : ContainsPhrasingContentTag<HTMLButtonElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "button";
    };

    struct Div : ContainerTag<HTMLDivElement, PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "div";
    };

    struct Footer : ContainerTag<HTMLElement, PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "footer";
      static HTMLElement* Create(Document& document) {
        return MakeGarbageCollected<HTMLElement>(html_names::kFooterTag,
                                                 document);
      }
    };

    struct I
        : ContainsPhrasingContentTag<HTMLElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "i";
      static HTMLElement* Create(Document& document) {
        return MakeGarbageCollected<HTMLElement>(html_names::kITag, document);
      }
    };

    struct Input
        : VoidTag<HTMLInputElement, PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "input";
      static HTMLInputElement* Create(Document& document) {
        return MakeGarbageCollected<HTMLInputElement>(
            document, CreateElementFlags::ByFragmentParser(&document));
      }
    };

    struct Li : ContainerTag<HTMLLIElement, PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "li";
    };

    struct Label
        : ContainsPhrasingContentTag<HTMLLabelElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "label";
    };

    struct Option
        : ContainerTag<HTMLOptionElement, PermittedParents::kSpecial> {
      static constexpr const char tagname[] = "option";
      static Element* ParseChild(HTMLFastPathParser& self) {
        // <option> can only contain a text content.
        return self.Fail(HtmlFastPathResult::kFailedOptionWithChild, nullptr);
      }
    };

    struct Ol : ContainerTag<HTMLOListElement, PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "ol";

      static Element* ParseChild(HTMLFastPathParser& self) {
        return self.ParseSpecificElements<Li>();
      }
    };

    struct P : ContainsPhrasingContentTag<HTMLParagraphElement,
                                          PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "p";
    };

    struct Select : ContainerTag<HTMLSelectElement,
                                 PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "select";
      static Element* ParseChild(HTMLFastPathParser& self) {
        return self.ParseSpecificElements<Option>();
      }
    };

    struct Span
        : ContainsPhrasingContentTag<HTMLSpanElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "span";
    };

    struct Strong
        : ContainsPhrasingContentTag<HTMLElement,
                                     PermittedParents::kPhrasingOrFlowContent> {
      static constexpr const char tagname[] = "strong";
      static HTMLElement* Create(Document& document) {
        return MakeGarbageCollected<HTMLElement>(html_names::kStrongTag,
                                                 document);
      }
    };

    struct Ul : ContainerTag<HTMLUListElement, PermittedParents::kFlowContent> {
      static constexpr const char tagname[] = "ul";

      static Element* ParseChild(HTMLFastPathParser& self) {
        return self.ParseSpecificElements<Li>();
      }
    };
  };

  template <class ParentTag>
  void ParseCompleteInput() {
    ParseChildren<ParentTag>(&root_node_);
    if (pos_ != end_) {
      Fail(HtmlFastPathResult::kFailedDidntReachEndOfInput);
    }
  }

  // Match ASCII Whitespace according to
  // https://infra.spec.whatwg.org/#ascii-whitespace
  bool IsWhitespace(Char c) {
    switch (c) {
      case ' ':
      case '\t':
      case '\n':
      case '\r':
      case '\f':
        return true;
      default:
        return false;
    }
  }

  bool IsValidUnquotedAttributeValueChar(Char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
           ('0' <= c && c <= '9') || c == '_' || c == '-';
  }

  // https://html.spec.whatwg.org/#syntax-attribute-name
  bool IsValidAttributeNameChar(Char c) {
    if (c == '=') {
      // Early exit for the most common way to end an attribute.
      return false;
    }
    return ('a' <= c && c <= 'z') || c == '-' || ('A' <= c && c <= 'Z') ||
           ('0' <= c && c <= '9');
  }

  bool IsCharAfterTagnameOrAttribute(Char c) {
    return c == ' ' || c == '>' || IsWhitespace(c) || c == '/';
  }

  bool IsCharAfterUnquotedAttribute(Char c) {
    return c == ' ' || c == '>' || IsWhitespace(c);
  }

  void SkipWhitespace() {
    while (pos_ != end_ && IsWhitespace(*pos_)) {
      ++pos_;
    }
  }

#if VECTORIZE_SCANNING
  ALWAYS_INLINE HWY_ATTR ScanTextResult<Char> ScanTextVectorized(
      const Char* initial_start) {
    namespace hw = hwy::HWY_NAMESPACE;
    DCHECK_GE(static_cast<size_t>(end_ - pos_), kVectorizationThreshold);
    hw::FixedTag<uint8_t, 16> tag;
    // ASCII representation of interesting symbols:
    //   <: 0011 1100
    //  \r: 0000 1101
    //  \0: 0000 0000
    //   &: 0010 0110
    // The lower nibbles represent offsets into the |low_nibble_table|. The
    // values in the table are the corresponding characters.
    const auto low_nibble_table = hw::Dup128VecFromValues(
        tag, '\0', 0, 0, 0, 0, 0, '&', 0, 0, 0, 0, 0, '<', '\r', 0, 0);
    switch (SimdAdvanceAndLookup(pos_, end_, low_nibble_table)) {
      case kNeverMatchedChar:
        DCHECK_EQ(pos_, end_);
        return {{initial_start, static_cast<size_t>(pos_ - initial_start)},
                nullptr};
      case '\0':
        DCHECK_EQ(*pos_, '\0');
        return Fail(HtmlFastPathResult::kFailedContainsNull,
                    ScanTextResult<Char>{Span{}, nullptr});
      case '<':
        DCHECK_EQ(*pos_, '<');
        return {{initial_start, static_cast<size_t>(pos_ - initial_start)},
                nullptr};
      case '&':
      case '\r':
        DCHECK(*pos_ == '&' || *pos_ == '\r');
        pos_ = initial_start;
        return {Span{}, ScanEscapedText()};
    };

    NOTREACHED();
    return {};
  }
#endif  // VECTORIZE_SCANNING

  // We first try to scan text as an unmodified subsequence of the input.
  // However, if there are escape sequences, we have to copy the text to a
  // separate buffer and we might go outside of `Char` range if we are in an
  // `LChar` parser. Therefore, this function returns either a `Span` or a
  // `USpan`. Callers distinguish the two cases by checking if the `Span` is
  // empty, as only one of them can be non-empty.
  ScanTextResult<Char> ScanText() {
    const Char* start = pos_;

    // First, try to check if the test is a canonical whitespace string.
    if (pos_ != end_ && *pos_ == '\n') {
      while (++pos_ != end_ && *pos_ == ' ')
        ;
      if (pos_ == end_ || *pos_ == '<') {
        return {{start, static_cast<size_t>(pos_ - start)},
                nullptr,
                /*is_newline_then_whitespace_string=*/true};
      }
    }

#if VECTORIZE_SCANNING
    if (static_cast<size_t>(end_ - pos_) >= kVectorizationThreshold) {
      return ScanTextVectorized(start);
    }
#endif  // VECTORIZE_SCANNING

    while (pos_ != end_ && *pos_ != '<') {
      // '&' indicates escape sequences, '\r' might require
      // https://infra.spec.whatwg.org/#normalize-newlines
      if (*pos_ == '&' || *pos_ == '\r') {
        pos_ = start;
        return {Span{}, ScanEscapedText()};
      } else if (*pos_ == '\0') [[unlikely]] {
        return Fail(HtmlFastPathResult::kFailedContainsNull,
                    ScanTextResult<Char>{Span{}, nullptr});
      }
      ++pos_;
    }

    return {{start, static_cast<size_t>(pos_ - start)}, nullptr};
  }

  // Slow-path of `ScanText()`, which supports escape sequences by copying to a
  // separate buffer.
  UCharLiteralBufferType* ScanEscapedText() {
    uchar_buffer_.clear();
    while (pos_ != end_ && *pos_ != '<') {
      if (*pos_ == '&') {
        ScanHTMLCharacterReference(&uchar_buffer_);
        if (failed_) {
          return nullptr;
        }
      } else if (*pos_ == '\r') {
        // Normalize "\r\n" to "\n" according to
        // https://infra.spec.whatwg.org/#normalize-newlines.
        if (pos_ + 1 != end_ && pos_[1] == '\n') {
          ++pos_;
        }
        uchar_buffer_.AddChar('\n');
        ++pos_;
      } else if (*pos_ == '\0') [[unlikely]] {
        return Fail(HtmlFastPathResult::kFailedContainsNull, nullptr);
      } else {
        uchar_buffer_.AddChar(*pos_);
        ++pos_;
      }
    }
    return &uchar_buffer_;
  }

  // Scan a tagname and convert to lowercase if necessary.
  Span ScanTagname() {
    const Char* start = pos_;
    while (pos_ != end_ && 'a' <= *pos_ && *pos_ <= 'z') {
      ++pos_;
    }
    if (pos_ == end_ || !IsCharAfterTagnameOrAttribute(*pos_)) {
      // Try parsing a case-insensitive tagname.
      char_buffer_.clear();
      pos_ = start;
      while (pos_ != end_) {
        Char c = *pos_;
        if ('A' <= c && c <= 'Z') {
          c = c - ('A' - 'a');
        } else if (!('a' <= c && c <= 'z')) {
          break;
        }
        ++pos_;
        char_buffer_.AddChar(c);
      }
      if (pos_ == end_ || !IsCharAfterTagnameOrAttribute(*pos_)) {
        return Fail(HtmlFastPathResult::kFailedParsingTagName, Span{});
      }
      SkipWhitespace();
      return Span{char_buffer_.data(), char_buffer_.size()};
    }
    Span res = Span{start, static_cast<size_t>(pos_ - start)};
    SkipWhitespace();
    return res;
  }

  Span ScanAttrName() {
    // First look for all lower case. This path doesn't require any mapping of
    // input.
"""


```
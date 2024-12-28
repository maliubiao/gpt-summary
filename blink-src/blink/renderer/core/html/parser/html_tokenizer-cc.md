Response:
My thought process for summarizing the provided code snippet goes like this:

1. **Identify the Core Function:** The file name `html_tokenizer.cc` immediately tells me this code is responsible for tokenizing HTML. The copyright notices reinforce that this is foundational HTML parsing code.

2. **Scan for Key Classes and Data Structures:** I quickly look for class definitions. The obvious one is `HTMLTokenizer`. I also notice mentions of `HTMLToken`, `HTMLParserOptions`, `SegmentedString`, and various helper classes like `HTMLEntityParser`, `HTMLTreeBuilder`, etc. These names provide clues about the responsibilities of `HTMLTokenizer`. It seems to:
    * Take input (`SegmentedString`).
    * Produce tokens (`HTMLToken`).
    * Be configurable (`HTMLParserOptions`).
    * Potentially interact with entity parsing and tree building.

3. **Look for Key Methods:** The `NextToken` method stands out. This is likely the main entry point for getting the next token. The `Reset` method suggests the tokenizer can be reused. Internal methods with names like `ProcessEntity`, `FlushBufferedEndTag`, and methods starting with `Emit` suggest specific actions during tokenization.

4. **Examine State Machines:** The abundance of `HTML_BEGIN_STATE`, `HTML_ADVANCE_TO`, `HTML_SWITCH_TO`, etc., strongly indicates a state machine implementation. The various state names (e.g., `kDataState`, `kTagOpenState`, `kAttributeNameState`) give insights into the different stages of HTML parsing.

5. **Analyze Relationships to HTML, CSS, and JavaScript:**
    * **HTML:** The primary function is to parse HTML. The state names (tags, attributes, comments, etc.) directly relate to HTML syntax.
    * **CSS:**  While not directly parsing CSS, the tokenizer needs to handle `<style>` tags and their content, which can contain CSS. The handling of different data states (like RCDATA for `<textarea>` and `<title>`) and RAWTEXT/ScriptData for `<script>` is relevant.
    * **JavaScript:** Similar to CSS, the tokenizer needs to process the content of `<script>` tags. The various `ScriptData` states are specific to this. The handling of escape sequences is important within script blocks.

6. **Identify Potential User Errors:**  The "ParseError()" calls within the state machine indicate handling of malformed HTML. I consider common HTML mistakes:
    * Unclosed tags (`<p>`).
    * Mismatched tags (`<p></i>`).
    * Incorrect attribute syntax (`<div class=error>`).
    * Invalid characters in tags or attributes.

7. **Infer Logic and Examples:** Based on the state names and actions, I can infer some basic logic. For example, encountering `<` in the `kDataState` transitions to `kTagOpenState`. I can then construct simple input/output examples to illustrate this:
    * Input: `<div`
    * Output: Starts a start tag token with name "div".

8. **Focus on the "Part 1" Aspect:** The prompt mentions this is part 1 of 3. This likely means this section focuses on the initial stages of tokenization, getting the basic structure. Later parts might handle more complex aspects or error recovery. Therefore, the summary should reflect this initial focus.

9. **Structure the Summary:** I organize the summary into clear points, addressing each part of the prompt: core function, relationship to web technologies, logic examples, user errors, and the overall function of this part.

10. **Refine and Elaborate:**  I review the initial draft and add more detail where needed. For instance, I emphasize the state machine aspect and the specific roles of the different states. I also make sure the examples are clear and concise. I clarify that the tokenizer *prepares* the data for the parser, rather than doing the full parsing itself.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate summary of its functionality.
这是对 `blink/renderer/core/html/parser/html_tokenizer.cc` 文件（第一部分）的功能归纳：

**核心功能：HTML 词法分析 (Tokenization)**

`html_tokenizer.cc` 文件的核心功能是实现 HTML 词法分析器 (tokenizer)。它的主要任务是将输入的 HTML 字符串流分解成一系列有意义的词法单元（tokens）。这些 tokens 是后续 HTML 解析器（通常是 `HTMLTreeBuilder`）构建 DOM 树的基础。

**具体功能点：**

1. **状态机驱动：** 代码使用状态机模式来实现词法分析。不同的状态代表了解析器当前所处的上下文，例如在处理标签名、属性名、属性值或纯文本内容等。

2. **逐字符处理：**  词法分析器逐个字符地读取输入的 HTML 字符串。

3. **识别和生成 Tokens：**  根据当前状态和读取的字符，词法分析器识别出不同的 HTML 语法结构，并生成对应的 tokens。常见的 token 类型包括：
    * **StartTag:**  表示一个开始标签，例如 `<div`。
    * **EndTag:**  表示一个结束标签，例如 `</div>`。
    * **Character:** 表示文本内容，例如 `Hello`。
    * **Comment:** 表示 HTML 注释，例如 `<!-- comment -->`。
    * **DOCTYPE:** 表示文档类型声明，例如 `<!DOCTYPE html>`。
    * **DOMPart:**  处理 Blink 特有的 DOM Parts 特性（例如，用于 Shadow DOM）。

4. **处理实体引用：**  代码中提到了 `HTMLTokenizer::ProcessEntity`，表明词法分析器负责处理 HTML 实体引用（例如 `&nbsp;`），将其转换为对应的字符。

5. **处理不同内容类型：**  HTML 中有不同的内容类型，例如纯文本、RCDATA (Raw Character Data，例如 `<textarea>` 和 `<title>`)、RAWTEXT (`<script>` 和 `<style>`)、ScriptData 等。词法分析器需要根据当前所处的标签来切换状态，并以不同的方式处理这些内容。

6. **错误处理：**  代码中包含 `ParseError()` 的调用，表明词法分析器会检测并报告 HTML 语法错误。

7. **缓冲机制：**  `FlushBufferedEndTag` 等方法暗示了词法分析器可能存在缓冲机制，用于暂存部分解析结果，以便在合适的时机一次性输出。

8. **支持 DOM Parts API：** 代码中出现了 `kChildNodePartStartMarker`、`kChildNodePartEndMarker` 等常量，以及相关的状态 `kChildNodePartStartState` 和 `kChildNodePartEndState`，表明此词法分析器支持 Blink 特有的 DOM Parts API。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:**  `HTMLTokenizer` 的主要功能就是解析 HTML。它识别 HTML 标签、属性、文本内容等基本构成元素。例如，当遇到 `<p>` 时，它会生成一个 `StartTag` token，名称为 "p"。

* **JavaScript:** 当词法分析器遇到 `<script>` 标签时，它会进入 `kScriptDataState` 等相关状态，以特殊的方式处理标签内的内容，因为它被视为 JavaScript 代码而非普通的 HTML 内容。例如，在 `kScriptDataState` 中，除了 `<` 会触发状态切换，大部分字符都会被当作字符数据处理。

* **CSS:** 类似地，当遇到 `<style>` 标签时，词法分析器会进入相应的状态（虽然这段代码中没有直接展示 `style` 标签的处理，但可以推断存在类似的处理逻辑），将标签内的内容视为 CSS 代码。例如，在 `<style>` 标签内的字符通常不会被当作 HTML 标签来解析，而是直接作为字符数据。

**逻辑推理示例（假设输入与输出）：**

* **假设输入:**  `"<div class='container'>Hello</div>"`
* **输出的 Tokens (简化):**
    * `StartTag(name: "div", attributes: ["class='container'"])`
    * `Character("Hello")`
    * `EndTag(name: "div")`

* **假设输入:**  `"<script>console.log('hi');</script>"`
* **输出的 Tokens (简化):**
    * `StartTag(name: "script")`
    * `Character("console.log('hi');")` (在 `ScriptData` 状态下，大部分内容会被当作字符数据)
    * `EndTag(name: "script")`

**用户或编程常见的使用错误举例：**

虽然 `HTMLTokenizer` 是浏览器引擎内部的组件，开发者不会直接使用它，但它的行为直接影响了浏览器如何解析有错误的 HTML。

* **未闭合的标签:**  例如 `<p>This is a paragraph.`  `HTMLTokenizer` 会尝试恢复，可能会隐式地关闭 `p` 标签，但这可能导致意外的 DOM 结构。

* **错误的标签嵌套:** 例如 `<p><b></p></b>`。 `HTMLTokenizer` 会按照一定的规则来处理，例如当遇到 `</b>` 时，如果当前没有打开的 `b` 标签，可能会忽略该结束标签或者尝试修复 DOM 结构。

* **属性值没有引号:** 例如 `<div class=error>`。 `HTMLTokenizer` 会尽可能地解析，但可能会将空格后的内容截断，导致属性值不完整。

**本部分功能归纳：**

作为 `html_tokenizer.cc` 的第一部分，此代码主要负责 HTML 词法分析的核心逻辑，包括：

* **状态机的定义和状态转换规则。**
* **识别和生成基本的 HTML tokens (如开始标签、文本内容等)。**
* **处理简单的实体引用。**
* **初步处理不同类型的内容 (Data, RCDATA, RAWTEXT, ScriptData)。**

可以预期后续部分会继续完善词法分析器的功能，例如处理更复杂的实体引用、CDATA 部分、DOCTYPE 声明、以及更精细的错误处理和恢复机制。这部分代码奠定了 HTML 解析的第一步，将原始的 HTML 文本转化为结构化的 tokens 序列，为后续的 DOM 树构建做好准备。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_tokenizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 * Copyright (C) 2009 Torch Mobile, Inc. http://www.torchmobile.com/
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/parser/html_tokenizer.h"

#include "third_party/blink/renderer/core/html/parser/html_entity_parser.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/html_tree_builder.h"
#include "third_party/blink/renderer/core/html/parser/markup_tokenizer_inlines.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/html_tokenizer_names.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

// clang-format off
#define INT_0_TO_127_LIST(V)                                                    \
V(0),   V(1),   V(2),   V(3),   V(4),   V(5),   V(6),   V(7),   V(8),   V(9),   \
V(10),  V(11),  V(12),  V(13),  V(14),  V(15),  V(16),  V(17),  V(18),  V(19),  \
V(20),  V(21),  V(22),  V(23),  V(24),  V(25),  V(26),  V(27),  V(28),  V(29),  \
V(30),  V(31),  V(32),  V(33),  V(34),  V(35),  V(36),  V(37),  V(38),  V(39),  \
V(40),  V(41),  V(42),  V(43),  V(44),  V(45),  V(46),  V(47),  V(48),  V(49),  \
V(50),  V(51),  V(52),  V(53),  V(54),  V(55),  V(56),  V(57),  V(58),  V(59),  \
V(60),  V(61),  V(62),  V(63),  V(64),  V(65),  V(66),  V(67),  V(68),  V(69),  \
V(70),  V(71),  V(72),  V(73),  V(74),  V(75),  V(76),  V(77),  V(78),  V(79),  \
V(80),  V(81),  V(82),  V(83),  V(84),  V(85),  V(86),  V(87),  V(88),  V(89),  \
V(90),  V(91),  V(92),  V(93),  V(94),  V(95),  V(96),  V(97),  V(98),  V(99),  \
V(100), V(101), V(102), V(103), V(104), V(105), V(106), V(107), V(108), V(109), \
V(110), V(111), V(112), V(113), V(114), V(115), V(116), V(117), V(118), V(119), \
V(120), V(121), V(122), V(123), V(124), V(125), V(126), V(127),
// clang-format on

// Character flags for fast paths.
enum class ScanFlags : uint16_t {
  // Base flags
  kNullCharacter = 1 << 0,
  kNewlineOrCarriageReturn = 1 << 1,
  kWhitespaceNotNewline = 1 << 2,
  kAmpersand = 1 << 3,
  kOpenTag = 1 << 4,
  kSlashAndCloseTag = 1 << 5,
  kEqual = 1 << 6,
  kQuotes = 1 << 7,
  kOpenBrace = 1 << 8,
  // Compound flags
  kWhitespace = kWhitespaceNotNewline | kNewlineOrCarriageReturn,
  kCharacterTokenSpecial = kNullCharacter | kNewlineOrCarriageReturn |
                           kAmpersand | kOpenTag | kOpenBrace,
  kNullOrNewline = kNullCharacter | kNewlineOrCarriageReturn,
  kRCDATASpecial = kNullCharacter | kAmpersand | kOpenTag,
  kTagNameSpecial = kWhitespace | kSlashAndCloseTag | kNullCharacter,
  kAttributeNameSpecial = kWhitespace | kSlashAndCloseTag | kNullCharacter |
                          kEqual | kOpenTag | kQuotes,
};

static constexpr uint16_t CreateScanFlags(UChar cc) {
#define SCAN_FLAG(flag) static_cast<uint16_t>(ScanFlags::flag)
  DCHECK(!(cc & ~0x7F));  // IsASCII
  uint16_t scan_flag = 0;
  if (cc == '\0') {
    scan_flag = SCAN_FLAG(kNullCharacter);
  } else if (cc == '\n' || cc == '\r') {
    scan_flag = SCAN_FLAG(kNewlineOrCarriageReturn);
  } else if (cc == ' ' || cc == '\x09' || cc == '\x0C') {
    scan_flag = SCAN_FLAG(kWhitespaceNotNewline);
  } else if (cc == '&') {
    scan_flag = SCAN_FLAG(kAmpersand);
  } else if (cc == '<') {
    scan_flag = SCAN_FLAG(kOpenTag);
  } else if (cc == '/' || cc == '>') {
    scan_flag = SCAN_FLAG(kSlashAndCloseTag);
  } else if (cc == '=') {
    scan_flag = SCAN_FLAG(kEqual);
  } else if (cc == '"' || cc == '\'') {
    scan_flag = SCAN_FLAG(kQuotes);
  } else if (cc == '{') {
    scan_flag = SCAN_FLAG(kOpenBrace);
  }
  return scan_flag;
#undef SCAN_FLAG
}

// DOM Part marker strings. Eventually move these to html_tokenizer_names.
#define kChildNodePartStartMarker "{{#}}"
#define kChildNodePartEndMarker "{{/}}"
#define kNodePartMarker "{{}}"
#define kAttributePartMarker "{{}}"

// Table of precomputed scan flags for the first 128 ASCII characters.
static constexpr const uint16_t character_scan_flags_[128] = {
    INT_0_TO_127_LIST(CreateScanFlags)};

static inline UChar ToLowerCase(UChar cc) {
  DCHECK(IsASCIIAlpha(cc));
  return cc | 0x20;
}

static inline bool CheckScanFlag(UChar cc, ScanFlags flag) {
  return IsASCII(cc) &&
         (character_scan_flags_[cc] & static_cast<uint16_t>(flag));
}

static inline UChar ToLowerCaseIfAlpha(UChar cc) {
  return cc | (IsASCIIUpper(cc) ? 0x20 : 0);
}

static inline bool VectorEqualsString(const LCharLiteralBuffer<32>& vector,
                                      const String& string) {
  if (vector.size() != string.length())
    return false;

  if (!string.length())
    return true;

  return Equal(string.Impl(), vector);
}

#define HTML_BEGIN_STATE(stateName) BEGIN_STATE(HTMLTokenizer, stateName)
#define HTML_BEGIN_STATE_NOLABEL(stateName) \
  BEGIN_STATE_NOLABEL(HTMLTokenizer, stateName)
#define HTML_RECONSUME_IN(stateName) RECONSUME_IN(HTMLTokenizer, stateName)
#define HTML_ADVANCE_TO(stateName) ADVANCE_TO(HTMLTokenizer, stateName)
#define HTML_ADVANCE_PAST_NON_NEWLINE_TO(stateName) \
  ADVANCE_PAST_NON_NEWLINE_TO(HTMLTokenizer, stateName)
#define HTML_CONSUME(stateName) CONSUME(HTMLTokenizer, stateName)
#define HTML_CONSUME_NON_NEWLINE(stateName) \
  CONSUME_NON_NEWLINE(HTMLTokenizer, stateName)
#define HTML_SWITCH_TO(stateName) SWITCH_TO(HTMLTokenizer, stateName)

HTMLTokenizer::HTMLTokenizer(const HTMLParserOptions& options)
    : track_attributes_ranges_(options.track_attributes_ranges),
      input_stream_preprocessor_(this),
      options_(options) {
  Reset();
}

HTMLTokenizer::~HTMLTokenizer() = default;

void HTMLTokenizer::Reset() {
  token_.Clear();
  state_ = HTMLTokenizer::kDataState;
  force_null_character_replacement_ = false;
  should_allow_cdata_ = false;
  additional_allowed_character_ = '\0';
}

inline bool HTMLTokenizer::ProcessEntity(SegmentedString& source) {
  bool not_enough_characters = false;
  DecodedHTMLEntity decoded_entity;
  bool success =
      ConsumeHTMLEntity(source, decoded_entity, not_enough_characters);
  if (not_enough_characters)
    return false;
  if (!success) {
    DCHECK(decoded_entity.IsEmpty());
    BufferCharacter('&');
  } else {
    for (unsigned i = 0; i < decoded_entity.length; ++i)
      BufferCharacter(decoded_entity.data[i]);
  }
  return true;
}

bool HTMLTokenizer::FlushBufferedEndTag(SegmentedString& source,
                                        bool current_char_may_be_newline) {
  DCHECK(token_.GetType() == HTMLToken::kCharacter ||
         token_.GetType() == HTMLToken::kUninitialized);
  if (current_char_may_be_newline)
    source.AdvanceAndUpdateLineNumber();
  else
    source.AdvancePastNonNewline();
  if (token_.GetType() == HTMLToken::kCharacter)
    return true;
  token_.BeginEndTag(buffered_end_tag_name_);
  buffered_end_tag_name_.clear();
  appropriate_end_tag_name_.clear();
  temporary_buffer_.clear();
  return false;
}

#define FLUSH_AND_ADVANCE_TO(stateName, current_char_may_be_newline)      \
  do {                                                                    \
    state_ = HTMLTokenizer::stateName;                                    \
    if (FlushBufferedEndTag(source, current_char_may_be_newline))         \
      return true;                                                        \
    if (source.IsEmpty() || !input_stream_preprocessor_.Peek(source, cc)) \
      return HaveBufferedCharacterToken();                                \
    goto stateName;                                                       \
  } while (false)

#define FLUSH_AND_ADVANCE_TO_NO_NEWLINE(stateName) \
  FLUSH_AND_ADVANCE_TO(stateName, /* current_char_may_be_newline */ false)

#define FLUSH_AND_ADVANCE_TO_MAY_CONTAIN_NEWLINE(stateName) \
  FLUSH_AND_ADVANCE_TO(stateName, /* current_char_may_be_newline */ true)

#define ADVANCE_PAST_MULTIPLE_NO_NEWLINE(len, newState)                 \
  {                                                                     \
    DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());               \
    for (unsigned i = 1; i < (len); ++i) {                              \
      bool success =                                                    \
          input_stream_preprocessor_.AdvancePastNonNewline(source, cc); \
      DCHECK(success);                                                  \
    }                                                                   \
    if (state_ == HTMLTokenizer::newState) {                            \
      HTML_CONSUME(newState);                                           \
    } else {                                                            \
      HTML_SWITCH_TO(newState);                                         \
    }                                                                   \
  }

bool HTMLTokenizer::FlushEmitAndResumeInDataState(SegmentedString& source) {
  state_ = HTMLTokenizer::kDataState;
  FlushBufferedEndTag(source, /* current_char_may_be_newline */ false);
  return true;
}

HTMLToken* HTMLTokenizer::NextToken(SegmentedString& source) {
#if DCHECK_IS_ON()
  DCHECK(!token_should_be_in_uninitialized_state_ || token_.IsUninitialized());
  DCHECK(!token_should_be_in_uninitialized_state_ ||
         attributes_ranges_.attributes().empty());
#endif
  const bool completed_token = NextTokenImpl(source);
#if DCHECK_IS_ON()
  // If the token was completed, then the caller is expected to clear it
  // (putting it into the uninitialized state) before NextToken() gets called
  // again.
  token_should_be_in_uninitialized_state_ = completed_token;
#endif
  return completed_token ? &token_ : nullptr;
}

bool HTMLTokenizer::NextTokenImpl(SegmentedString& source) {
  if (!buffered_end_tag_name_.IsEmpty() && !IsEndTagBufferingState(state_)) {
    // FIXME: This should call flushBufferedEndTag().
    // We started an end tag during our last iteration.
    token_.BeginEndTag(buffered_end_tag_name_);
    buffered_end_tag_name_.clear();
    appropriate_end_tag_name_.clear();
    temporary_buffer_.clear();
    if (state_ == HTMLTokenizer::kDataState) {
      // We're back in the data state, so we must be done with the tag.
      return true;
    }
  }

  UChar cc;
  if (source.IsEmpty() || !input_stream_preprocessor_.Peek(source, cc))
    return HaveBufferedCharacterToken();

  // Source: http://www.whatwg.org/specs/web-apps/current-work/#tokenisation0
  switch (state_) {
    HTML_BEGIN_STATE(kDataState) {
      if (cc == '&')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCharacterReferenceInDataState);
      else if (cc == '<') {
        if (HaveBufferedCharacterToken()) {
          // We have a bunch of character tokens queued up that we
          // are emitting lazily here.
          return true;
        }
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kTagOpenState);
      } else if (cc == kEndOfFileMarker)
        return EmitEndOfFile(source);
      else {
        return EmitData(source, cc);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE_NOLABEL(kChildNodePartStartState) {
      DCHECK_EQ(source.LookAhead(kChildNodePartStartMarker),
                SegmentedString::kDidMatch);
      AdvanceStringAndASSERT(source, kChildNodePartStartMarker);
      token_.BeginDOMPart(DOMPartTokenType::kChildNodePartStart);
      // Emit the DOM Part token and then return to the DATA state.
      state_ = kDataState;
      return true;
    }
    END_STATE()

    HTML_BEGIN_STATE_NOLABEL(kChildNodePartEndState) {
      DCHECK_EQ(source.LookAhead(kChildNodePartEndMarker),
                SegmentedString::kDidMatch);
      AdvanceStringAndASSERT(source, kChildNodePartEndMarker);
      token_.BeginDOMPart(DOMPartTokenType::kChildNodePartEnd);
      // Emit the DOM Part token and then return to the DATA state.
      state_ = kDataState;
      return true;
    }
    END_STATE()

    HTML_BEGIN_STATE(kCharacterReferenceInDataState) {
      if (!ProcessEntity(source))
        return HaveBufferedCharacterToken();
      HTML_SWITCH_TO(kDataState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kRCDATAState) {
      while (!CheckScanFlag(cc, ScanFlags::kRCDATASpecial)) {
        BufferCharacter(cc);
        if (!input_stream_preprocessor_.Advance(source, cc))
          return HaveBufferedCharacterToken();
      }
      if (cc == '&') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kCharacterReferenceInRCDATAState);
      } else if (cc == '<') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kRCDATALessThanSignState);
      } else if (cc == kEndOfFileMarker) {
        return EmitEndOfFile(source);
      } else {
        NOTREACHED();
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kCharacterReferenceInRCDATAState) {
      if (!ProcessEntity(source))
        return HaveBufferedCharacterToken();
      HTML_SWITCH_TO(kRCDATAState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kRAWTEXTState) {
      if (cc == '<')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kRAWTEXTLessThanSignState);
      else if (cc == kEndOfFileMarker)
        return EmitEndOfFile(source);
      else {
        BufferCharacter(cc);
        HTML_CONSUME(kRAWTEXTState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataState) {
      if (cc == '<')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataLessThanSignState);
      else if (cc == kEndOfFileMarker)
        return EmitEndOfFile(source);
      else {
        BufferCharacter(cc);
        HTML_CONSUME(kScriptDataState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE_NOLABEL(kPLAINTEXTState) {
      if (cc == kEndOfFileMarker)
        return EmitEndOfFile(source);
      return EmitPLAINTEXT(source, cc);
    }
    END_STATE()

    HTML_BEGIN_STATE(kTagOpenState) {
      if (IsASCIIAlpha(cc)) {
        token_.BeginStartTag(ToLowerCase(cc));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kTagNameState);
      } else if (cc == '!') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kMarkupDeclarationOpenState);
      } else if (cc == '/') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kEndTagOpenState);
      } else if (cc == '?') {
        ParseError();
        // The spec consumes the current character before switching
        // to the bogus comment state, but it's easier to implement
        // if we reconsume the current character.
        HTML_RECONSUME_IN(kBogusCommentState);
      } else {
        ParseError();
        BufferCharacter('<');
        HTML_RECONSUME_IN(kDataState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kEndTagOpenState) {
      if (IsASCIIAlpha(cc)) {
        token_.BeginEndTag(static_cast<LChar>(ToLowerCase(cc)));
        appropriate_end_tag_name_.clear();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kTagNameState);
      } else if (cc == '>') {
        ParseError();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kDataState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        BufferCharacter('<');
        BufferCharacter('/');
        HTML_RECONSUME_IN(kDataState);
      } else {
        ParseError();
        HTML_RECONSUME_IN(kBogusCommentState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kTagNameState) {
      while (!CheckScanFlag(cc, ScanFlags::kTagNameSpecial)) {
        token_.AppendToName(ToLowerCaseIfAlpha(cc));
        if (!input_stream_preprocessor_.AdvancePastNonNewline(source, cc))
          return HaveBufferedCharacterToken();
      }
      if (cc == '/') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kSelfClosingStartTagState);
      } else if (cc == '>') {
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        DCHECK(IsTokenizerWhitespace(cc));
        HTML_ADVANCE_TO(kBeforeAttributeNameState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kRCDATALessThanSignState) {
      if (cc == '/') {
        temporary_buffer_.clear();
        DCHECK(buffered_end_tag_name_.IsEmpty());
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kRCDATAEndTagOpenState);
      } else {
        BufferCharacter('<');
        HTML_RECONSUME_IN(kRCDATAState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kRCDATAEndTagOpenState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kRCDATAEndTagNameState);
      } else {
        BufferCharacter('<');
        BufferCharacter('/');
        HTML_RECONSUME_IN(kRCDATAState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kRCDATAEndTagNameState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_CONSUME_NON_NEWLINE(kRCDATAEndTagNameState);
      } else {
        if (IsTokenizerWhitespace(cc)) {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_MAY_CONTAIN_NEWLINE(kBeforeAttributeNameState);
          }
        } else if (cc == '/') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_NO_NEWLINE(kSelfClosingStartTagState);
          }
        } else if (cc == '>') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            return FlushEmitAndResumeInDataState(source);
          }
        }
        BufferCharacter('<');
        BufferCharacter('/');
        token_.AppendToCharacter(temporary_buffer_);
        buffered_end_tag_name_.clear();
        temporary_buffer_.clear();
        HTML_RECONSUME_IN(kRCDATAState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kRAWTEXTLessThanSignState) {
      if (cc == '/') {
        temporary_buffer_.clear();
        DCHECK(buffered_end_tag_name_.IsEmpty());
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kRAWTEXTEndTagOpenState);
      } else {
        BufferCharacter('<');
        HTML_RECONSUME_IN(kRAWTEXTState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kRAWTEXTEndTagOpenState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kRAWTEXTEndTagNameState);
      } else {
        BufferCharacter('<');
        BufferCharacter('/');
        HTML_RECONSUME_IN(kRAWTEXTState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kRAWTEXTEndTagNameState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_CONSUME_NON_NEWLINE(kRAWTEXTEndTagNameState);
      } else {
        if (IsTokenizerWhitespace(cc)) {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_MAY_CONTAIN_NEWLINE(kBeforeAttributeNameState);
          }
        } else if (cc == '/') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_NO_NEWLINE(kSelfClosingStartTagState);
          }
        } else if (cc == '>') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            return FlushEmitAndResumeInDataState(source);
          }
        }
        BufferCharacter('<');
        BufferCharacter('/');
        token_.AppendToCharacter(temporary_buffer_);
        buffered_end_tag_name_.clear();
        temporary_buffer_.clear();
        HTML_RECONSUME_IN(kRAWTEXTState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataLessThanSignState) {
      if (cc == '/') {
        temporary_buffer_.clear();
        DCHECK(buffered_end_tag_name_.IsEmpty());
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEndTagOpenState);
      } else if (cc == '!') {
        BufferCharacter('<');
        BufferCharacter('!');
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapeStartState);
      } else {
        BufferCharacter('<');
        HTML_RECONSUME_IN(kScriptDataState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEndTagOpenState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEndTagNameState);
      } else {
        BufferCharacter('<');
        BufferCharacter('/');
        HTML_RECONSUME_IN(kScriptDataState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEndTagNameState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_CONSUME_NON_NEWLINE(kScriptDataEndTagNameState);
      } else {
        if (IsTokenizerWhitespace(cc)) {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_MAY_CONTAIN_NEWLINE(kBeforeAttributeNameState);
          }
        } else if (cc == '/') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_NO_NEWLINE(kSelfClosingStartTagState);
          }
        } else if (cc == '>') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            return FlushEmitAndResumeInDataState(source);
          }
        }
        BufferCharacter('<');
        BufferCharacter('/');
        token_.AppendToCharacter(temporary_buffer_);
        buffered_end_tag_name_.clear();
        temporary_buffer_.clear();
        HTML_RECONSUME_IN(kScriptDataState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapeStartState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapeStartDashState);
      } else
        HTML_RECONSUME_IN(kScriptDataState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapeStartDashState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedDashDashState);
      } else
        HTML_RECONSUME_IN(kScriptDataState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapedState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedDashState);
      } else if (cc == '<')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedLessThanSignState);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        BufferCharacter(cc);
        HTML_CONSUME(kScriptDataEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapedDashState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedDashDashState);
      } else if (cc == '<')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedLessThanSignState);
      else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        BufferCharacter(cc);
        HTML_ADVANCE_TO(kScriptDataEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapedDashDashState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_CONSUME_NON_NEWLINE(kScriptDataEscapedDashDashState);
      } else if (cc == '<')
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedLessThanSignState);
      else if (cc == '>') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        BufferCharacter(cc);
        HTML_ADVANCE_TO(kScriptDataEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapedLessThanSignState) {
      if (cc == '/') {
        temporary_buffer_.clear();
        DCHECK(buffered_end_tag_name_.IsEmpty());
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedEndTagOpenState);
      } else if (IsASCIIAlpha(cc)) {
        BufferCharacter('<');
        BufferCharacter(cc);
        temporary_buffer_.clear();
        temporary_buffer_.AddChar(static_cast<LChar>(ToLowerCase(cc)));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataDoubleEscapeStartState);
      } else {
        BufferCharacter('<');
        HTML_RECONSUME_IN(kScriptDataEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapedEndTagOpenState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataEscapedEndTagNameState);
      } else {
        BufferCharacter('<');
        BufferCharacter('/');
        HTML_RECONSUME_IN(kScriptDataEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataEscapedEndTagNameState) {
      if (IsASCIIAlpha(cc)) {
        temporary_buffer_.AddChar(static_cast<LChar>(cc));
        AddToPossibleEndTag(static_cast<LChar>(ToLowerCase(cc)));
        HTML_CONSUME_NON_NEWLINE(kScriptDataEscapedEndTagNameState);
      } else {
        if (IsTokenizerWhitespace(cc)) {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_MAY_CONTAIN_NEWLINE(kBeforeAttributeNameState);
          }
        } else if (cc == '/') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            FLUSH_AND_ADVANCE_TO_NO_NEWLINE(kSelfClosingStartTagState);
          }
        } else if (cc == '>') {
          if (IsAppropriateEndTag()) {
            temporary_buffer_.AddChar(static_cast<LChar>(cc));
            return FlushEmitAndResumeInDataState(source);
          }
        }
        BufferCharacter('<');
        BufferCharacter('/');
        token_.AppendToCharacter(temporary_buffer_);
        buffered_end_tag_name_.clear();
        temporary_buffer_.clear();
        HTML_RECONSUME_IN(kScriptDataEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataDoubleEscapeStartState) {
      if (IsTokenizerWhitespace(cc) || cc == '/' || cc == '>') {
        BufferCharacter(cc);
        if (TemporaryBufferIs(html_names::kScriptTag.LocalName()))
          HTML_ADVANCE_TO(kScriptDataDoubleEscapedState);
        else
          HTML_ADVANCE_TO(kScriptDataEscapedState);
      } else if (IsASCIIAlpha(cc)) {
        BufferCharacter(cc);
        temporary_buffer_.AddChar(static_cast<LChar>(ToLowerCase(cc)));
        HTML_CONSUME_NON_NEWLINE(kScriptDataDoubleEscapeStartState);
      } else
        HTML_RECONSUME_IN(kScriptDataEscapedState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataDoubleEscapedState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataDoubleEscapedDashState);
      } else if (cc == '<') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kScriptDataDoubleEscapedLessThanSignState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        BufferCharacter(cc);
        HTML_CONSUME(kScriptDataDoubleEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataDoubleEscapedDashState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataDoubleEscapedDashDashState);
      } else if (cc == '<') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kScriptDataDoubleEscapedLessThanSignState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        BufferCharacter(cc);
        HTML_ADVANCE_TO(kScriptDataDoubleEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataDoubleEscapedDashDashState) {
      if (cc == '-') {
        BufferCharacter(cc);
        HTML_CONSUME_NON_NEWLINE(kScriptDataDoubleEscapedDashDashState);
      } else if (cc == '<') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(
            kScriptDataDoubleEscapedLessThanSignState);
      } else if (cc == '>') {
        BufferCharacter(cc);
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataState);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else {
        BufferCharacter(cc);
        HTML_ADVANCE_TO(kScriptDataDoubleEscapedState);
      }
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataDoubleEscapedLessThanSignState) {
      if (cc == '/') {
        BufferCharacter(cc);
        temporary_buffer_.clear();
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kScriptDataDoubleEscapeEndState);
      } else
        HTML_RECONSUME_IN(kScriptDataDoubleEscapedState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kScriptDataDoubleEscapeEndState) {
      if (IsTokenizerWhitespace(cc) || cc == '/' || cc == '>') {
        BufferCharacter(cc);
        if (TemporaryBufferIs(html_names::kScriptTag.LocalName()))
          HTML_ADVANCE_TO(kScriptDataEscapedState);
        else
          HTML_ADVANCE_TO(kScriptDataDoubleEscapedState);
      } else if (IsASCIIAlpha(cc)) {
        BufferCharacter(cc);
        temporary_buffer_.AddChar(static_cast<LChar>(ToLowerCase(cc)));
        HTML_CONSUME_NON_NEWLINE(kScriptDataDoubleEscapeEndState);
      } else
        HTML_RECONSUME_IN(kScriptDataDoubleEscapedState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kBeforeAttributeNameState) {
      if (!SkipWhitespaces(source, cc))
        return HaveBufferedCharacterToken();
      if (cc == '/') {
        HTML_ADVANCE_PAST_NON_NEWLINE_TO(kSelfClosingStartTagState);
      } else if (cc == '>') {
        return EmitAndResumeInDataState(source);
      } else if (cc == kEndOfFileMarker) {
        ParseError();
        HTML_RECONSUME_IN(kDataState);
      } else if (cc == '{' && ShouldAllowDOMParts() &&
                 source.LookAhead(kNodePartMarker) ==
                     SegmentedString::kDidMatch) {
        static_assert(kNodePartMarker[0] == '{');
        token_.SetNeedsNodePart();
        // Need to skip ahead here so we don't get {{}} as an attribute.
        ADVANCE_PAST_MULTIPLE_NO_NEWLINE(sizeof(kNodePartMarker) - 1,
                                         kBeforeAttributeNameState);
      } else if (cc == '"' || cc == '\'' || cc == '<' || cc == '=') {
        ParseError();
      }
      token_.AddNewAttribute(ToLowerCaseIfAlpha(cc));
      if (track_attributes_ranges_) {
        attributes_ranges_.AddAttribute(source.NumberOfCharactersConsumed());
      }
      HTML_ADVANCE_PAST_NON_NEWLINE_TO(kAttributeNameState);
    }
    END_STATE()

    HTML_BEGIN_STATE(kAttributeNameState) {
      while (!CheckScanFlag(cc, ScanFlags::kAttributeNameSpecial)) {
        token_.AppendToAttributeName(ToLowerCaseIfAlpha(cc));
        if (!input_stream_preprocessor_.AdvancePastNonNewline(source, cc))
          return HaveBuf
"""


```
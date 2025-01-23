Response:
The user wants me to analyze the provided C++ source code file, which is part of the Blink rendering engine in Chromium. Specifically, they are asking about the functionality of `HTMLTreeBuilder.cc`.

Here's a breakdown of how to address the user's request:

1. **Identify the core function:** The file name `html_tree_builder.cc` strongly suggests that this code is responsible for building the DOM tree from HTML input.

2. **Analyze included headers:** The `#include` statements provide valuable clues about the classes and functionalities the `HTMLTreeBuilder` interacts with. Look for relevant DOM classes (e.g., `Document`, `Element`, `DocumentFragment`), parser-related classes (e.g., `HTMLDocumentParser`, `HTMLTokenizer`, `HTMLToken`), and other utility classes.

3. **Examine class definition and methods:** Focus on the `HTMLTreeBuilder` class itself. Look at its constructor, destructor, and key methods like `ConstructTree`, `ProcessToken`, `ProcessStartTag`, `ProcessEndTag`, etc. These methods indicate the steps involved in the tree building process.

4. **Look for relationships to HTML, CSS, and JavaScript:**
    * **HTML:** The core function of the class is to parse HTML, so direct relationships are expected. The processing of tags, attributes, and text nodes are key indicators.
    * **CSS:**  While this specific file might not directly *apply* CSS, it's responsible for creating the DOM structure that CSS selectors target. Look for mentions of style or elements where CSS is typically applied.
    * **JavaScript:** The interaction with JavaScript is often through script elements. Look for how `<script>` tags are handled and the pausing/resuming of parsing during script execution.

5. **Infer logical reasoning and assumptions:** The code likely follows the HTML parsing specification. Think about how the parser handles different types of tokens and maintains state (insertion modes, open element stack, etc.). Consider common scenarios like nested elements, malformed HTML, and how the parser attempts to recover.

6. **Consider user/programming errors:** Think about common mistakes developers make in writing HTML that the parser has to handle. Examples include missing closing tags, incorrect nesting, and invalid attribute values.

7. **Focus on the provided code snippet:** The user has provided the *first part* of the file. Therefore, the analysis should be limited to the functionality visible in this segment. Avoid making assumptions about code that might appear later in the file.

8. **Structure the response:** Organize the findings into clear categories as requested by the user:
    * Overall functionality.
    * Relationships to HTML, CSS, and JavaScript with examples.
    * Logical reasoning with hypothetical inputs and outputs.
    * Common user errors.
    * Summary of the current part.

**Pre-computation/Pre-analysis (Mental Walkthrough):**

* **Core Function:** Confirmed, the primary role is building the DOM tree from HTML tokens.
* **Insertion Modes:**  The code mentions `insertion_mode_`, hinting at the state machine nature of HTML parsing.
* **Open Element Stack:** The `tree_.OpenElements()` member suggests a stack-based approach to managing open tags.
* **Token Processing:** Methods like `ProcessStartTag` and `ProcessEndTag` are central to how the parser handles different HTML elements.
* **Error Handling:**  The presence of `ParseError(token)` indicates mechanisms for dealing with malformed HTML.
* **Script Handling:** The `script_to_process_` member and related methods point to how script execution is managed during parsing.

By following these steps and focusing on the provided code, I can generate a comprehensive and accurate response to the user's request.
这个文件 `blink/renderer/core/html/parser/html_tree_builder.cc` 是 Chromium Blink 引擎中负责 **构建 DOM 树** 的核心组件。它的主要功能是接收来自 HTML 解析器（`HTMLDocumentParser` 和 `HTMLTokenizer`）的标记（tokens），并根据 HTML 规范将这些标记转换成一个表示网页结构的 DOM 树。

以下是根据提供的代码片段归纳出的主要功能点：

**1. DOM 树的构建与维护:**

* **接收 HTML 标记 (Tokens):** `HTMLTreeBuilder` 从 `HTMLDocumentParser` 接收解析后的 HTML 标记，包括起始标签、结束标签、文本内容、注释、DOCTYPE 等。
* **维护开放元素栈 (Open Elements Stack):**  它使用一个栈结构来跟踪当前正在处理的 HTML 元素，确保标签的正确嵌套和闭合。
* **执行插入操作:**  根据当前的插入模式和接收到的标记类型，调用 `HTMLConstructionSite` (通过 `tree_` 成员) 的方法来创建和插入 DOM 节点 (例如，`InsertHTMLElement`, `InsertTextNode`, `InsertComment`) 到 DOM 树中。
* **处理嵌套关系:**  根据 HTML 规范处理各种标签的嵌套规则，例如，某些标签不能嵌套在另一些标签中。
* **处理自闭合标签:**  正确处理像 `<br>`、`<hr>`、`<img>` 这样的自闭合标签。

**2. 实现 HTML 解析算法:**

* **管理插入模式 (Insertion Modes):**  `insertion_mode_` 变量跟踪当前的解析状态，不同的插入模式下，对相同的标记会有不同的处理方式。例如，在 `kInitialMode` 下遇到 `<html>` 标签和在 `kInBodyMode` 下遇到 `<html>` 标签的处理是不同的。
* **实现不同的插入模式逻辑:**  文件中可以看到针对不同插入模式（例如 `kInitialMode`, `kBeforeHTMLMode`, `kInBodyMode`, `kInTableMode` 等）的具体处理函数，例如 `ProcessDoctypeToken`, `ProcessStartTag`, `ProcessEndTag` 等。
* **处理特定标签的特殊规则:**  代码中针对一些特殊的 HTML 标签实现了特殊的处理逻辑，例如 `<script>`, `<style>`, `<iframe>`, `<form>`, `<table>` 等，这些标签的解析会影响后续的解析状态和行为。
* **处理错误和异常情况:**  通过 `ParseError(token)` 函数来处理解析过程中遇到的错误，并尝试从错误中恢复，保证解析过程的鲁棒性。

**3. 与 JavaScript, HTML, CSS 的关系 (基于代码片段推断):**

* **HTML:**  `HTMLTreeBuilder` 的核心功能就是解析 HTML 并构建 DOM 树，这是它与 HTML 最直接的关系。它根据 HTML 标签的类型、属性以及它们之间的关系来构建 DOM 结构。  例如，遇到 `<p>` 标签会创建一个 `HTMLParagraphElement` 节点，遇到 `<div>` 会创建一个 `HTMLDivElement` 节点。
* **JavaScript:**
    * **`<script>` 标签的处理:**  代码中可以看到对 `<script>` 标签的处理 (`ProcessStartTagForInBody` 中有 `HTMLTag::kScript` 的 case)。当遇到 `<script>` 标签时，`HTMLTreeBuilder` 会暂停解析，将脚本交给 JavaScript 引擎执行。执行完毕后，解析会继续。 `TakeScriptToProcess` 方法用于取出待处理的脚本。
    * **事件处理:**  虽然这段代码没有直接展示事件处理，但 DOM 树是 JavaScript 操作的基础。构建正确的 DOM 树是 JavaScript 代码能够正确访问和操作网页元素的前提。
* **CSS:**
    * **`<style>` 标签的处理:**  类似 `<script>` 标签，`HTMLTreeBuilder` 会处理 `<style>` 标签 (`ProcessStartTagForInHead` 中有 `HTMLTag::kStyle` 的 case)。当遇到 `<style>` 标签时，会将 CSS 样式信息提取出来，后续会由 CSS 解析器进行解析，并应用到 DOM 树上。
    * **DOM 结构作为 CSS 选择器的目标:**  `HTMLTreeBuilder` 构建的 DOM 树是 CSS 选择器匹配的目标。CSS 规则会根据 DOM 树的结构来确定哪些元素应用哪些样式。

**4. 逻辑推理 (假设输入与输出):**

假设输入一个简单的 HTML 片段：

```html
<div>
  <p>Hello, world!</p>
</div>
```

**假设输入 (Tokens):**

1. `StartTag: <div>`
2. `Character: '\n  '` (空白字符)
3. `StartTag: <p>`
4. `Character: Hello, world!`
5. `EndTag: </p>`
6. `Character: '\n'` (空白字符)
7. `EndTag: </div>`

**可能的输出 (DOM 树片段):**

```
HTMLDivElement
  |
  +-- HTMLParagraphElement
        |
        +-- Text: "Hello, world!"
```

**逻辑推理过程:**

* 遇到 `StartTag: <div>`，创建一个 `HTMLDivElement` 并压入开放元素栈。
* 遇到 `Character: '\n  '`，根据当前的插入模式，可能会插入一个空白文本节点，也可能忽略（取决于具体的插入模式和上下文）。
* 遇到 `StartTag: <p>`，创建一个 `HTMLParagraphElement` 并作为 `HTMLDivElement` 的子节点，压入开放元素栈。
* 遇到 `Character: Hello, world!`，创建一个文本节点 "Hello, world!" 并作为 `HTMLParagraphElement` 的子节点。
* 遇到 `EndTag: </p>`，从开放元素栈中弹出 `HTMLParagraphElement`。
* 遇到 `Character: '\n'`，处理方式同第二个字符 token。
* 遇到 `EndTag: </div>`，从开放元素栈中弹出 `HTMLDivElement`。

**5. 用户或编程常见的使用错误 (基于代码片段推断):**

* **未闭合的标签:**  如果输入的 HTML 是 `<div><p>Hello</div>`，`HTMLTreeBuilder` 会检测到 `p` 标签未闭合，可能会产生一个 `ParseError`，并根据规则尝试闭合 `p` 标签，最终构建出类似 `<div><p>Hello</p></div>` 的 DOM 树，但这可能不是用户的预期。
* **错误的标签嵌套:**  例如 `<p><div>Hello</p></div>`，`HTMLTreeBuilder` 会检测到 `div` 不应该嵌套在 `p` 中，可能会进行调整，例如提前闭合 `p` 标签，生成类似 `<p></p><div>Hello</div>` 的结构。
* **在不允许的地方使用某些标签:** 例如在 `<head>` 中使用 `<body>` 标签，`HTMLTreeBuilder` 会报错并忽略或进行调整。
* **属性值缺失引号:**  虽然 `HTMLTreeBuilder` 通常能处理一些简单的属性值不带引号的情况，但在某些情况下可能会导致解析错误或属性值被错误解析。

**总结 (基于提供的第 1 部分代码):**

`HTMLTreeBuilder.cc` 的这一部分代码展示了其作为 Blink 引擎中构建 DOM 树核心组件的基本功能。它负责接收 HTML 标记，维护解析状态（插入模式和开放元素栈），并根据 HTML 规范将这些标记转换成 DOM 树。代码中已经展现了处理不同类型的 HTML 标记（DOCTYPE, 起始标签, 结束标签, 文本, 注释）的基本逻辑，以及与 JavaScript (通过 `<script>` 标签) 的初步交互。此外，代码中也包含了错误处理的机制。 总之，这一部分是 `HTMLTreeBuilder` 初始化和处理基本 HTML 结构的关键部分。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google, Inc. All Rights Reserved.
 * Copyright (C) 2011, 2014 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GOOGLE INC. OR
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

#include "third_party/blink/renderer/core/html/parser/html_tree_builder.h"

#include <memory>

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/parser/atomic_html_token.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/html_stack_item.h"
#include "third_party/blink/renderer/core/html/parser/html_token.h"
#include "third_party/blink/renderer/core/html/parser/html_tokenizer.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/xlink_names.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/core/xmlns_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"

namespace blink {

using HTMLTag = html_names::HTMLTag;

namespace {

inline bool IsHTMLSpaceOrReplacementCharacter(UChar character) {
  return IsHTMLSpace<UChar>(character) || character == kReplacementCharacter;
}
}  // namespace

static TextPosition UninitializedPositionValue1() {
  return TextPosition(OrdinalNumber::FromOneBasedInt(-1),
                      OrdinalNumber::First());
}

static inline bool IsAllWhitespace(const StringView& string_view) {
  return string_view.IsAllSpecialCharacters<IsHTMLSpace<UChar>>();
}

static inline bool IsAllWhitespaceOrReplacementCharacters(
    const StringView& string_view) {
  return string_view
      .IsAllSpecialCharacters<IsHTMLSpaceOrReplacementCharacter>();
}

// The following macros are used in switch statements for some common types.
// They are defined so that they can look like a normal case statement, e.g.:
//   case FOO_CASES:

// Disable formatting as it mangles these macros.
// clang-format off

#define CAPTION_COL_OR_COLGROUP_CASES \
  HTMLTag::kCaption: \
  case HTMLTag::kCol: \
  case HTMLTag::kColgroup

#define NUMBERED_HEADER_CASES \
  HTMLTag::kH1: \
  case HTMLTag::kH2: \
  case HTMLTag::kH3: \
  case HTMLTag::kH4: \
  case HTMLTag::kH5: \
  case HTMLTag::kH6

#define TABLE_BODY_CONTEXT_CASES \
  HTMLTag::kTbody: \
  case HTMLTag::kTfoot: \
  case HTMLTag::kThead

#define TABLE_CELL_CONTEXT_CASES \
  HTMLTag::kTh: \
  case HTMLTag::kTd

// clang-format on

static bool IsTableBodyContextTag(HTMLTag tag) {
  switch (tag) {
    case TABLE_BODY_CONTEXT_CASES:
      return true;
    default:
      return false;
  }
}

// http://www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html#formatting
class HTMLTreeBuilder::CharacterTokenBuffer {
 public:
  explicit CharacterTokenBuffer(AtomicHTMLToken* token)
      : characters_(token->Characters()),
        current_(0),
        end_(token->Characters().length()) {
    DCHECK(!IsEmpty());
  }

  CharacterTokenBuffer(const CharacterTokenBuffer&) = delete;
  CharacterTokenBuffer& operator=(const CharacterTokenBuffer&) = delete;

  ~CharacterTokenBuffer() { DCHECK(IsEmpty()); }

  bool IsEmpty() const { return current_ == end_; }

  void SkipAtMostOneLeadingNewline() {
    DCHECK(!IsEmpty());
    if (characters_[current_] == '\n') {
      ++current_;
    }
  }

  void SkipLeadingWhitespace() { SkipLeading<IsHTMLSpace<UChar>>(); }

  struct TakeLeadingWhitespaceResult {
    StringView string;
    WhitespaceMode whitespace_mode;
  };

  TakeLeadingWhitespaceResult TakeLeadingWhitespace() {
    DCHECK(!IsEmpty());
    const unsigned start = current_;
    WhitespaceMode whitespace_mode = WhitespaceMode::kNewlineThenWhitespace;

    // First, check the first character to identify whether the string looks
    // common (i.e. "\n<space>*").
    const UChar first = characters_[current_];
    if (!IsHTMLSpace(first)) {
      return {StringView(characters_, start, 0),
              WhitespaceMode::kNotAllWhitespace};
    }
    if (first != '\n') {
      whitespace_mode = WhitespaceMode::kAllWhitespace;
    }

    // Then, check the rest.
    ++current_;
    for (; current_ != end_; ++current_) {
      const UChar ch = characters_[current_];
      if (ch == ' ') [[likely]] {
        continue;
      } else if (IsHTMLSpecialWhitespace(ch)) {
        whitespace_mode = WhitespaceMode::kAllWhitespace;
      } else {
        break;
      }
    }

    return {StringView(characters_, start, current_ - start), whitespace_mode};
  }

  void SkipLeadingNonWhitespace() { SkipLeading<IsNotHTMLSpace<UChar>>(); }

  void SkipRemaining() { current_ = end_; }

  StringView TakeRemaining() {
    DCHECK(!IsEmpty());
    unsigned start = current_;
    current_ = end_;
    return StringView(characters_, start, end_ - start);
  }

  void GiveRemainingTo(StringBuilder& recipient) {
    WTF::VisitCharacters(characters_, [&](auto chars) {
      recipient.Append(chars.subspan(current_, end_ - current_));
    });
    current_ = end_;
  }

  struct TakeRemainingWhitespaceResult {
    String string;
    WhitespaceMode whitespace_mode;
  };

  TakeRemainingWhitespaceResult TakeRemainingWhitespace() {
    DCHECK(!IsEmpty());
    const unsigned start = current_;
    current_ = end_;  // One way or another, we're taking everything!

    WhitespaceMode whitespace_mode = WhitespaceMode::kNewlineThenWhitespace;
    unsigned length = 0;
    for (unsigned i = start; i < end_; ++i) {
      const UChar ch = characters_[i];
      if (length == 0) {
        if (ch == '\n') {
          ++length;
          continue;
        }
        // Otherwise, it's a random whitespace string. Drop the mode.
        whitespace_mode = WhitespaceMode::kAllWhitespace;
      }

      if (ch == ' ') {
        ++length;
      } else if (IsHTMLSpecialWhitespace<UChar>(ch)) {
        whitespace_mode = WhitespaceMode::kAllWhitespace;
        ++length;
      }
    }
    // Returning the null string when there aren't any whitespace
    // characters is slightly cleaner semantically because we don't want
    // to insert a text node (as opposed to inserting an empty text node).
    if (!length) {
      return {String(), WhitespaceMode::kNotAllWhitespace};
    }
    if (length == start - end_) {  // It's all whitespace.
      return {String(characters_.Substring(start, start - end_)),
              whitespace_mode};
    }

    // All HTML spaces are ASCII.
    StringBuffer<LChar> result(length);
    unsigned j = 0;
    for (unsigned i = start; i < end_; ++i) {
      UChar c = characters_[i];
      if (c == ' ' || IsHTMLSpecialWhitespace(c)) {
        result[j++] = static_cast<LChar>(c);
      }
    }
    DCHECK_EQ(j, length);
    return {String::Adopt(result), whitespace_mode};
  }

 private:
  template <bool characterPredicate(UChar)>
  void SkipLeading() {
    DCHECK(!IsEmpty());
    while (characterPredicate(characters_[current_])) {
      if (++current_ == end_)
        return;
    }
  }

  String characters_;
  unsigned current_;
  unsigned end_;
};

HTMLTreeBuilder::HTMLTreeBuilder(HTMLDocumentParser* parser,
                                 Document& document,
                                 ParserContentPolicy parser_content_policy,
                                 const HTMLParserOptions& options,
                                 bool include_shadow_roots,
                                 DocumentFragment* for_fragment,
                                 Element* fragment_context_element)
    : tree_(parser->ReentryPermit(),
            document,
            parser_content_policy,
            for_fragment,
            fragment_context_element),
      insertion_mode_(kInitialMode),
      original_insertion_mode_(kInitialMode),
      should_skip_leading_newline_(false),
      include_shadow_roots_(include_shadow_roots),
      frameset_ok_(true),
      parser_(parser),
      script_to_process_start_position_(UninitializedPositionValue1()),
      options_(options) {}
HTMLTreeBuilder::HTMLTreeBuilder(HTMLDocumentParser* parser,
                                 Document& document,
                                 ParserContentPolicy parser_content_policy,
                                 const HTMLParserOptions& options,
                                 bool include_shadow_roots)
    : HTMLTreeBuilder(parser,
                      document,
                      parser_content_policy,
                      options,
                      include_shadow_roots,
                      nullptr,
                      nullptr) {}
HTMLTreeBuilder::HTMLTreeBuilder(HTMLDocumentParser* parser,
                                 DocumentFragment* fragment,
                                 Element* context_element,
                                 ParserContentPolicy parser_content_policy,
                                 const HTMLParserOptions& options,
                                 bool include_shadow_roots)
    : HTMLTreeBuilder(parser,
                      fragment->GetDocument(),
                      parser_content_policy,
                      options,
                      include_shadow_roots,
                      fragment,
                      context_element) {
  DCHECK(IsMainThread());
  fragment_context_.Init(fragment, context_element);

  // Steps 4.2-4.6 of the HTML5 Fragment Case parsing algorithm:
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/the-end.html#fragment-case
  // For efficiency, we skip step 4.2 ("Let root be a new html element with no
  // attributes") and instead use the DocumentFragment as a root node.
  tree_.OpenElements()->PushRootNode(MakeGarbageCollected<HTMLStackItem>(
      fragment, HTMLStackItem::kItemForDocumentFragmentNode));

  if (IsA<HTMLTemplateElement>(*context_element))
    template_insertion_modes_.push_back(kTemplateContentsMode);

  ResetInsertionModeAppropriately();
}

HTMLTreeBuilder::~HTMLTreeBuilder() = default;

void HTMLTreeBuilder::FragmentParsingContext::Init(DocumentFragment* fragment,
                                                   Element* context_element) {
  DCHECK(fragment);
  DCHECK(!fragment->HasChildren());
  fragment_ = fragment;
  context_element_stack_item_ = MakeGarbageCollected<HTMLStackItem>(
      context_element, HTMLStackItem::kItemForContextElement);
}

void HTMLTreeBuilder::FragmentParsingContext::Trace(Visitor* visitor) const {
  visitor->Trace(fragment_);
  visitor->Trace(context_element_stack_item_);
}

void HTMLTreeBuilder::Trace(Visitor* visitor) const {
  visitor->Trace(fragment_context_);
  visitor->Trace(tree_);
  visitor->Trace(parser_);
  visitor->Trace(script_to_process_);
}

void HTMLTreeBuilder::Detach() {
#if DCHECK_IS_ON()
  // This call makes little sense in fragment mode, but for consistency
  // DocumentParser expects Detach() to always be called before it's destroyed.
  is_attached_ = false;
#endif
  // HTMLConstructionSite might be on the callstack when Detach() is called
  // otherwise we'd just call tree_.Clear() here instead.
  tree_.Detach();
}

Element* HTMLTreeBuilder::TakeScriptToProcess(
    TextPosition& script_start_position) {
  DCHECK(script_to_process_);
  DCHECK(!tree_.HasPendingTasks());
  // Unpause ourselves, callers may pause us again when processing the script.
  // The HTML5 spec is written as though scripts are executed inside the tree
  // builder.  We pause the parser to exit the tree builder, and then resume
  // before running scripts.
  script_start_position = script_to_process_start_position_;
  script_to_process_start_position_ = UninitializedPositionValue1();
  return script_to_process_.Release();
}

void HTMLTreeBuilder::ConstructTree(AtomicHTMLToken* token) {
  RUNTIME_CALL_TIMER_SCOPE(parser_->GetDocument()->GetAgent().isolate(),
                           RuntimeCallStats::CounterId::kConstructTree);
  if (ShouldProcessTokenInForeignContent(token))
    ProcessTokenInForeignContent(token);
  else
    ProcessToken(token);

  if (parser_->IsDetached())
    return;

  bool in_foreign_content = false;
  if (!tree_.IsEmpty()) {
    HTMLStackItem* adjusted_current_node = AdjustedCurrentStackItem();
    in_foreign_content =
        !adjusted_current_node->IsInHTMLNamespace() &&
        !HTMLElementStack::IsHTMLIntegrationPoint(adjusted_current_node) &&
        !HTMLElementStack::IsMathMLTextIntegrationPoint(adjusted_current_node);
  }

  parser_->tokenizer().SetForceNullCharacterReplacement(
      GetInsertionMode() == kTextMode || in_foreign_content);
  parser_->tokenizer().SetShouldAllowCDATA(in_foreign_content);
  if (RuntimeEnabledFeatures::DOMPartsAPIEnabled()) {
    parser_->tokenizer().SetShouldAllowDOMParts(tree_.InParsePartsScope());
  }

  tree_.ExecuteQueuedTasks();
  // We might be detached now.
}

void HTMLTreeBuilder::ProcessToken(AtomicHTMLToken* token) {
  if (token->GetType() == HTMLToken::kCharacter) {
    ProcessCharacter(token);
    return;
  }

  // Any non-character token needs to cause us to flush any pending text
  // immediately. NOTE: flush() can cause any queued tasks to execute, possibly
  // re-entering the parser.
  tree_.Flush();
  should_skip_leading_newline_ = false;

  switch (token->GetType()) {
    case HTMLToken::kUninitialized:
    case HTMLToken::kCharacter:
      NOTREACHED();
    case HTMLToken::DOCTYPE:
      ProcessDoctypeToken(token);
      break;
    case HTMLToken::kStartTag:
      ProcessStartTag(token);
      break;
    case HTMLToken::kEndTag:
      ProcessEndTag(token);
      break;
    case HTMLToken::kComment:
      ProcessComment(token);
      break;
    case HTMLToken::kEndOfFile:
      ProcessEndOfFile(token);
      break;
    case HTMLToken::kDOMPart:
      ProcessDOMPart(token);
      break;
  }
}

void HTMLTreeBuilder::ProcessDoctypeToken(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::DOCTYPE);
  if (GetInsertionMode() == kInitialMode) {
    tree_.InsertDoctype(token);
    SetInsertionMode(kBeforeHTMLMode);
    return;
  }
  if (GetInsertionMode() == kInTableTextMode) {
    DefaultForInTableText();
    ProcessDoctypeToken(token);
    return;
  }
  ParseError(token);
}

void HTMLTreeBuilder::ProcessFakeStartTag(HTMLTag tag,
                                          const Vector<Attribute>& attributes) {
  // FIXME: We'll need a fancier conversion than just "localName" for SVG/MathML
  // tags.
  AtomicHTMLToken fake_token(HTMLToken::kStartTag, tag, attributes);
  ProcessStartTag(&fake_token);
}

void HTMLTreeBuilder::ProcessFakeEndTag(HTMLTag tag) {
  AtomicHTMLToken fake_token(HTMLToken::kEndTag, tag);
  ProcessEndTag(&fake_token);
}

void HTMLTreeBuilder::ProcessFakeEndTag(const HTMLStackItem& stack_item) {
  AtomicHTMLToken fake_token(HTMLToken::kEndTag, stack_item.GetTokenName());
  ProcessEndTag(&fake_token);
}

void HTMLTreeBuilder::ProcessFakePEndTagIfPInButtonScope() {
  if (!tree_.OpenElements()->InButtonScope(HTMLTag::kP))
    return;
  AtomicHTMLToken end_p(HTMLToken::kEndTag, HTMLTag::kP);
  ProcessEndTag(&end_p);
}

namespace {

bool IsLi(const HTMLStackItem* item) {
  return item->MatchesHTMLTag(HTMLTag::kLi);
}

bool IsDdOrDt(const HTMLStackItem* item) {
  return item->MatchesHTMLTag(HTMLTag::kDd) ||
         item->MatchesHTMLTag(HTMLTag::kDt);
}

}  // namespace

template <bool shouldClose(const HTMLStackItem*)>
void HTMLTreeBuilder::ProcessCloseWhenNestedTag(AtomicHTMLToken* token) {
  frameset_ok_ = false;
  HTMLStackItem* item = tree_.OpenElements()->TopStackItem();
  while (true) {
    if (shouldClose(item)) {
      DCHECK(item->IsElementNode());
      ProcessFakeEndTag(*item);
      break;
    }
    if (item->IsSpecialNode() && !item->MatchesHTMLTag(HTMLTag::kAddress) &&
        !item->MatchesHTMLTag(HTMLTag::kDiv) &&
        !item->MatchesHTMLTag(HTMLTag::kP))
      break;
    item = item->NextItemInStack();
  }
  ProcessFakePEndTagIfPInButtonScope();
  tree_.InsertHTMLElement(token);
}

namespace {
typedef HashMap<AtomicString, QualifiedName> PrefixedNameToQualifiedNameMap;

template <typename TableQualifiedName>
void MapLoweredLocalNameToName(PrefixedNameToQualifiedNameMap* map,
                               const TableQualifiedName* const* names,
                               size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const QualifiedName& name = *names[i];
    const AtomicString& local_name = name.LocalName();
    AtomicString lowered_local_name = local_name.LowerASCII();
    if (lowered_local_name != local_name)
      map->insert(lowered_local_name, name);
  }
}

void AddManualLocalName(PrefixedNameToQualifiedNameMap* map, const char* name) {
  const QualifiedName item{AtomicString(name)};
  const blink::QualifiedName* const names = &item;
  MapLoweredLocalNameToName<QualifiedName>(map, &names, 1);
}

// "Any other start tag" bullet in
// https://html.spec.whatwg.org/C/#parsing-main-inforeign
void AdjustSVGTagNameCase(AtomicHTMLToken* token) {
  static PrefixedNameToQualifiedNameMap* case_map = nullptr;
  if (!case_map) {
    case_map = new PrefixedNameToQualifiedNameMap;
    std::unique_ptr<const SVGQualifiedName*[]> svg_tags = svg_names::GetTags();
    MapLoweredLocalNameToName(case_map, svg_tags.get(), svg_names::kTagsCount);
    // These tags aren't implemented by Chromium, so they don't exist in
    // svg_tag_names.json5.
    AddManualLocalName(case_map, "altGlyph");
    AddManualLocalName(case_map, "altGlyphDef");
    AddManualLocalName(case_map, "altGlyphItem");
    AddManualLocalName(case_map, "glyphRef");
  }

  const auto it = case_map->find(token->GetName());
  if (it != case_map->end()) {
    DCHECK(!it->value.LocalName().IsNull());
    token->SetTokenName(HTMLTokenName::FromLocalName(it->value.LocalName()));
  }
}

template <std::unique_ptr<const QualifiedName* []> getAttrs(),
          unsigned length,
          bool forSVG>
void AdjustAttributes(AtomicHTMLToken* token) {
  static PrefixedNameToQualifiedNameMap* case_map = nullptr;
  if (!case_map) {
    case_map = new PrefixedNameToQualifiedNameMap;
    std::unique_ptr<const QualifiedName*[]> attrs = getAttrs();
    MapLoweredLocalNameToName(case_map, attrs.get(), length);
    if (forSVG) {
      // This attribute isn't implemented by Chromium, so it doesn't exist in
      // svg_attribute_names.json5.
      AddManualLocalName(case_map, "viewTarget");
    }
  }

  for (auto& token_attribute : token->Attributes()) {
    const auto it = case_map->find(token_attribute.LocalName());
    if (it != case_map->end()) {
      DCHECK(!it->value.LocalName().IsNull());
      token_attribute.ParserSetName(it->value);
    }
  }
}

// https://html.spec.whatwg.org/C/#adjust-svg-attributes
void AdjustSVGAttributes(AtomicHTMLToken* token) {
  AdjustAttributes<svg_names::GetAttrs, svg_names::kAttrsCount,
                   /*forSVG*/ true>(token);
}

// https://html.spec.whatwg.org/C/#adjust-mathml-attributes
void AdjustMathMLAttributes(AtomicHTMLToken* token) {
  AdjustAttributes<mathml_names::GetAttrs, mathml_names::kAttrsCount,
                   /*forSVG*/ false>(token);
}

void AddNamesWithPrefix(PrefixedNameToQualifiedNameMap* map,
                        const AtomicString& prefix,
                        const QualifiedName* const* names,
                        size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const QualifiedName* name = names[i];
    const AtomicString& local_name = name->LocalName();
    AtomicString prefix_colon_local_name = prefix + ':' + local_name;
    QualifiedName name_with_prefix(prefix, local_name, name->NamespaceURI());
    map->insert(prefix_colon_local_name, name_with_prefix);
  }
}

void AdjustForeignAttributes(AtomicHTMLToken* token) {
  static PrefixedNameToQualifiedNameMap* map = nullptr;
  if (!map) {
    map = new PrefixedNameToQualifiedNameMap;

    std::unique_ptr<const QualifiedName*[]> attrs = xlink_names::GetAttrs();
    AddNamesWithPrefix(map, g_xlink_atom, attrs.get(),
                       xlink_names::kAttrsCount);

    std::unique_ptr<const QualifiedName*[]> xml_attrs = xml_names::GetAttrs();
    AddNamesWithPrefix(map, g_xml_atom, xml_attrs.get(),
                       xml_names::kAttrsCount);

    map->insert(WTF::g_xmlns_atom, xmlns_names::kXmlnsAttr);
    map->insert(
        AtomicString("xmlns:xlink"),
        QualifiedName(g_xmlns_atom, g_xlink_atom, xmlns_names::kNamespaceURI));
  }

  for (unsigned i = 0; i < token->Attributes().size(); ++i) {
    Attribute& token_attribute = token->Attributes().at(i);
    const auto it = map->find(token_attribute.LocalName());
    if (it != map->end()) {
      DCHECK(!it->value.LocalName().IsNull());
      token_attribute.ParserSetName(it->value);
    }
  }
}

}  // namespace

void HTMLTreeBuilder::ProcessStartTagForInBody(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kStartTag);
  switch (token->GetHTMLTag()) {
    case HTMLTag::kHTML:
      ProcessHtmlStartTagForInBody(token);
      break;
    case HTMLTag::kBase:
    case HTMLTag::kBasefont:
    case HTMLTag::kBgsound:
    case HTMLTag::kCommand:
    case HTMLTag::kLink:
    case HTMLTag::kMeta:
    case HTMLTag::kNoframes:
    case HTMLTag::kScript:
    case HTMLTag::kStyle:
    case HTMLTag::kTitle:
    case HTMLTag::kTemplate: {
      bool did_process = ProcessStartTagForInHead(token);
      DCHECK(did_process);
      break;
    }
    case HTMLTag::kBody:
      ParseError(token);
      if (!tree_.OpenElements()->SecondElementIsHTMLBodyElement() ||
          tree_.OpenElements()->HasOnlyOneElement() ||
          tree_.OpenElements()->HasTemplateInHTMLScope()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        break;
      }
      frameset_ok_ = false;
      tree_.InsertHTMLBodyStartTagInBody(token);
      break;
    case HTMLTag::kFrameset:
      ParseError(token);
      if (!tree_.OpenElements()->SecondElementIsHTMLBodyElement() ||
          tree_.OpenElements()->HasOnlyOneElement()) {
        DCHECK(IsParsingFragmentOrTemplateContents());
        break;
      }
      if (!frameset_ok_)
        break;
      tree_.OpenElements()->BodyElement()->remove(ASSERT_NO_EXCEPTION);
      tree_.OpenElements()->PopUntil(tree_.OpenElements()->BodyElement());
      tree_.OpenElements()->PopHTMLBodyElement();

      // Note: in the fragment case the root is a DocumentFragment instead of
      // a proper html element which is a quirk in Blink's implementation.
      DCHECK(!IsParsingTemplateContents());
      DCHECK(!IsParsingFragment() ||
             To<DocumentFragment>(tree_.OpenElements()->TopNode()));
      DCHECK(IsParsingFragment() || tree_.OpenElements()->Top() ==
                                        tree_.OpenElements()->HtmlElement());
      tree_.InsertHTMLElement(token);
      SetInsertionMode(kInFramesetMode);
      break;
    case HTMLTag::kAddress:
    case HTMLTag::kArticle:
    case HTMLTag::kAside:
    case HTMLTag::kBlockquote:
    case HTMLTag::kCenter:
    case HTMLTag::kDetails:
    case HTMLTag::kDialog:
    case HTMLTag::kDir:
    case HTMLTag::kDiv:
    case HTMLTag::kDl:
    case HTMLTag::kFieldset:
    case HTMLTag::kFigcaption:
    case HTMLTag::kFigure:
    case HTMLTag::kFooter:
    case HTMLTag::kHeader:
    case HTMLTag::kHgroup:
    case HTMLTag::kMain:
    case HTMLTag::kMenu:
    case HTMLTag::kNav:
    case HTMLTag::kOl:
    case HTMLTag::kP:
    case HTMLTag::kSearch:
    case HTMLTag::kSection:
    case HTMLTag::kSummary:
    case HTMLTag::kUl:
      // https://html.spec.whatwg.org/multipage/parsing.html#:~:text=A%20start%20tag%20whose%20tag%20name%20is%20one%20of%3A%20%22address%22%2C
      ProcessFakePEndTagIfPInButtonScope();
      tree_.InsertHTMLElement(token);
      break;
    case HTMLTag::kLi:
      ProcessCloseWhenNestedTag<IsLi>(token);
      break;
    case HTMLTag::kInput: {
      if (RuntimeEnabledFeatures::InputClosesSelectEnabled()) {
        if (tree_.OpenElements()->InScope(HTMLTag::kSelect)) {
          ProcessFakeEndTag(HTMLTag::kSelect);
        }
      }
      // Per spec https://html.spec.whatwg.org/C/#parsing-main-inbody,
      // section "A start tag whose tag name is "input""

      Attribute* type_attribute =
          token->GetAttributeItem(html_names::kTypeAttr);
      bool disable_frameset =
          !type_attribute ||
          !EqualIgnoringASCIICase(type_attribute->Value(), "hidden");

      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertSelfClosingHTMLElementDestroyingToken(token);

      if (disable_frameset)
        frameset_ok_ = false;
      break;
    }
    case HTMLTag::kButton:
      if (tree_.OpenElements()->InScope(HTMLTag::kButton)) {
        ParseError(token);
        ProcessFakeEndTag(HTMLTag::kButton);
        ProcessStartTag(token);  // FIXME: Could we just fall through here?
        break;
      }
      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertHTMLElement(token);
      frameset_ok_ = false;
      break;
    case NUMBERED_HEADER_CASES:
      ProcessFakePEndTagIfPInButtonScope();
      if (tree_.CurrentStackItem()->IsNumberedHeaderElement()) {
        ParseError(token);
        tree_.OpenElements()->Pop();
      }
      tree_.InsertHTMLElement(token);
      break;
    case HTMLTag::kListing:
    case HTMLTag::kPre:
      ProcessFakePEndTagIfPInButtonScope();
      tree_.InsertHTMLElement(token);
      should_skip_leading_newline_ = true;
      frameset_ok_ = false;
      break;
    case HTMLTag::kForm:
      if (tree_.IsFormElementPointerNonNull() && !IsParsingTemplateContents()) {
        ParseError(token);
        UseCounter::Count(tree_.CurrentNode()->GetDocument(),
                          WebFeature::kHTMLParseErrorNestedForm);
        break;
      }
      ProcessFakePEndTagIfPInButtonScope();
      tree_.InsertHTMLFormElement(token);
      break;
    case HTMLTag::kDd:
    case HTMLTag::kDt:
      ProcessCloseWhenNestedTag<IsDdOrDt>(token);
      break;
    case HTMLTag::kPlaintext:
      ProcessFakePEndTagIfPInButtonScope();
      tree_.InsertHTMLElement(token);
      parser_->tokenizer().SetState(HTMLTokenizer::kPLAINTEXTState);
      break;
    case HTMLTag::kA: {
      Element* active_a_tag =
          tree_.ActiveFormattingElements()->ClosestElementInScopeWithName(
              token->GetName());
      if (active_a_tag) {
        ParseError(token);
        ProcessFakeEndTag(HTMLTag::kA);
        tree_.ActiveFormattingElements()->Remove(active_a_tag);
        if (tree_.OpenElements()->Contains(active_a_tag))
          tree_.OpenElements()->Remove(active_a_tag);
      }
      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertFormattingElement(token);
      break;
    }
    case HTMLTag::kB:
    case HTMLTag::kBig:
    case HTMLTag::kCode:
    case HTMLTag::kEm:
    case HTMLTag::kFont:
    case HTMLTag::kI:
    case HTMLTag::kS:
    case HTMLTag::kSmall:
    case HTMLTag::kStrike:
    case HTMLTag::kStrong:
    case HTMLTag::kTt:
    case HTMLTag::kU:
      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertFormattingElement(token);
      break;
    case HTMLTag::kNobr:
      tree_.ReconstructTheActiveFormattingElements();
      if (tree_.OpenElements()->InScope(HTMLTag::kNobr)) {
        ParseError(token);
        ProcessFakeEndTag(HTMLTag::kNobr);
        tree_.ReconstructTheActiveFormattingElements();
      }
      tree_.InsertFormattingElement(token);
      break;
    case HTMLTag::kApplet:
    case HTMLTag::kObject:
      if (!PluginContentIsAllowed(tree_.GetParserContentPolicy()))
        break;
      [[fallthrough]];
    case HTMLTag::kMarquee:
      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertHTMLElement(token);
      tree_.ActiveFormattingElements()->AppendMarker();
      frameset_ok_ = false;
      break;
    case HTMLTag::kTable:
      if (!tree_.InQuirksMode() &&
          tree_.OpenElements()->InButtonScope(HTMLTag::kP))
        ProcessFakeEndTag(HTMLTag::kP);
      tree_.InsertHTMLElement(token);
      frameset_ok_ = false;
      SetInsertionMode(kInTableMode);
      break;
    case HTMLTag::kImage:
      ParseError(token);
      // Apparently we're not supposed to ask.
      token->SetTokenName(HTMLTokenName(HTMLTag::kImg));
      [[fallthrough]];
    case HTMLTag::kArea:  // Includes kImgTag, thus the
    case HTMLTag::kBr:    // fallthrough.
    case HTMLTag::kEmbed:
    case HTMLTag::kImg:
    case HTMLTag::kKeygen:
    case HTMLTag::kWbr:
      if (token->GetHTMLTag() == HTMLTag::kEmbed &&
          !PluginContentIsAllowed(tree_.GetParserContentPolicy())) {
        break;
      }
      tree_.ReconstructTheActiveFormattingElements();
      tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
      frameset_ok_ = false;
      break;
    case HTMLTag::kParam:
    case HTMLTag::kSource:
    case HTMLTag::kTrack:
      tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
      break;
    case HTMLTag::kHr:
      ProcessFakePEndTagIfPInButtonScope();
      if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
        if (tree_.OpenElements()->InScope(HTMLTag::kSelect)) {
          tree_.GenerateImpliedEndTagsWithExclusion(
              HTMLTokenName(HTMLTag::kOptgroup));
        }
      }
      tree_.InsertSelfClosingHTMLElementDestroyingToken(token);
      frameset_ok_ = false;
      break;
    case HTMLTag::kTextarea:
      tree_.InsertHTMLElement(token);
      should_skip_leading_newline_ = true;
      parser_->tokenizer().SetState(HTMLTokenizer::kRCDATAState);
      original_insertion_mode_ = insertion_mode_;
      frameset_ok_ = false;
      SetInsertionMode(kTextMode);
      break;
    case HTMLTag::kXmp:
      ProcessFakePEndTagIfPInButtonScope();
      tree_.ReconstructTheActiveFormattingElements();
      frameset_ok_ = false;
      ProcessGenericRawTextStartTag(token);
      break;
    case HTMLTag::kIFrame:
      frameset_ok_ = false;
      ProcessGen
```
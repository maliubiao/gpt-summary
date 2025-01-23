Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for the functionality of the `TextFragmentSelectorGenerator` class in Chromium's Blink engine, its relation to web technologies (HTML, CSS, JavaScript), examples, logical reasoning (input/output), and common usage errors.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for important keywords and structural elements. Look for:
    * Class name: `TextFragmentSelectorGenerator`
    * Included headers: These give hints about dependencies and related functionality (e.g., `text_fragment_selector.h`, `editing/range.h`, `platform/text/text_boundaries.h`).
    * Member variables: These hold the state of the object (e.g., `range_`, `selector_`, `state_`, `error_`).
    * Member functions: These define the actions the object can perform (e.g., `Generate`, `Reset`, `DidFindMatch`, `NoMatchFound`).
    * Enums/Structs: `LinkGenerationError`, `LinkGenerationStatus`, `ForwardDirection`, `BackwardDirection`. These define specific states or organizational structures.
    * Logging/Metrics:  Mentions of `base::UmaHistogram...` and `ukm::UkmRecorder`. Indicates this class tracks performance and errors.

3. **Core Functionality Identification (The `Generate` method is key):** The `Generate` method appears to be the entry point. It takes a `RangeInFlatTree` as input and a callback. This suggests the core purpose is to create a `TextFragmentSelector` based on a given text range.

4. **Deconstructing the Generation Process (Following the state machine):** The code uses a state machine (`state_`) to manage the generation process. Follow the transitions:
    * `kNotStarted` -> `kNeedsNewCandidate` -> (`kExact` or `kRange` or `kContext`) -> `kTestCandidate` -> (`kSuccess` or `kNeedsNewCandidate` or `kFailure`).
    * This suggests a step-by-step refinement of the selector.

5. **Understanding Each Step:**
    * **`kExact`:**  Tries to create a selector based on the exact text. Limitations: length, single block.
    * **`kRange`:** If `kExact` fails or is unsuitable, tries to define the selection with a "start" and "end" text snippet. This is important for selections spanning multiple elements or longer text.
    * **`kContext`:**  If `kRange` still isn't unique or more context is needed, adds a "prefix" and "suffix" to the selector. This is crucial for disambiguation.
    * **`kTestCandidate`:**  Uses a `TextFragmentFinder` to check if the generated selector uniquely identifies the original text.

6. **Identifying Key Classes and Their Roles:**
    * **`RangeInFlatTree`:** Represents the user's selected text.
    * **`TextFragmentSelector`:**  The output of the process, containing the selected text and optional context.
    * **`TextFragmentFinder`:**  A separate class (likely in another file) responsible for searching the document for matches based on a `TextFragmentSelector`.
    * **Iterators (`ForwardSameBlockWordIterator`, `BackwardSameBlockWordIterator`):** Used for efficiently extracting words around the selected text.

7. **Connecting to Web Technologies:**
    * **HTML:**  The entire process operates on the DOM, which is the representation of an HTML document. The selection is made within HTML content.
    * **CSS:** While not directly manipulated, CSS affects the layout and visibility of text, which is implicitly considered (e.g., "visible text node").
    * **JavaScript:** JavaScript would be the typical way to trigger this functionality in a web page. A user selecting text and then using a "share" or "copy link to selection" feature would likely invoke this code.

8. **Developing Examples:** Based on the understanding of the steps, create illustrative examples. Think about:
    * Simple, single-word selections.
    * Multi-word selections within the same paragraph.
    * Selections spanning paragraphs or elements.
    * Cases where the exact text is short or long.
    * Situations requiring context for uniqueness.

9. **Logical Reasoning (Input/Output):** Define a clear input (the `RangeInFlatTree`) and the possible outputs (a `TextFragmentSelector` or an error). Show how the different steps in the generation process lead to different types of selectors.

10. **Common Usage Errors:**  Consider how developers or users might interact with this functionality and what could go wrong. This involves understanding the constraints and error conditions built into the code. Examples include:
    * Empty selections.
    * Selections spanning non-contiguous text.
    * The limits on the length of exact matches and context.

11. **Review and Refine:**  Go back through the code and the generated explanation. Ensure accuracy, clarity, and completeness. Are there any edge cases missed?  Is the explanation easy to understand for someone familiar with web development concepts?  For instance, initially, I might not have fully appreciated the role of the iterators, but closer inspection reveals their importance in efficiently finding word boundaries.

By following these steps, systematically analyzing the code, and connecting it to the broader context of web technologies, a comprehensive and accurate explanation can be generated. The key is to move from a high-level understanding to the specific details of the implementation, and then back up to explain the overall purpose and implications.
这个C++源代码文件 `text_fragment_selector_generator.cc` 位于 Chromium Blink 引擎中，其主要功能是 **生成 Text Fragment Selector (文本片段选择器)**。Text Fragment Selector 是一种 URL 特性，允许直接链接到网页中特定的文本片段。

以下是该文件的详细功能列表：

**核心功能：生成文本片段选择器**

* **输入：**  接收一个 `RangeInFlatTree` 对象作为输入，该对象表示用户在网页中选中的一段文本范围。
* **输出：**  生成一个 `TextFragmentSelector` 对象，该对象包含了用于唯一标识该文本片段的信息。
* **生成策略：**  采用多步骤策略来生成最佳的文本片段选择器，以确保链接的准确性和唯一性。主要包含以下步骤：
    * **精确匹配 (Exact Match):** 尝试使用选中文本的精确内容作为选择器。
    * **范围匹配 (Range Match):** 如果精确匹配不够唯一或选中文本过长，则尝试使用选中文本的开头和结尾的几个词作为选择器。
    * **上下文匹配 (Context Match):** 如果范围匹配仍然不够唯一，则在范围匹配的基础上添加选中文本前后的上下文（前缀和后缀）。
* **唯一性验证：**  使用 `TextFragmentFinder` 类在当前页面中查找生成的选择器，以验证其是否能唯一标识目标文本片段。
* **回退机制：** 如果生成的选择器不是唯一的，或者达到预设的尝试次数或长度限制，则会回退到更简单的选择器或标记生成失败。

**与 JavaScript, HTML, CSS 的关系：**

该文件主要在浏览器内核层面工作，负责生成文本片段选择器的逻辑。它与 JavaScript、HTML 和 CSS 的关系如下：

* **JavaScript：**
    * JavaScript 可以通过浏览器提供的 API (如 `getSelection()`) 获取用户选中的文本范围。
    * JavaScript 可以调用浏览器提供的接口来触发文本片段选择器的生成（虽然在这个文件中没有直接体现，但这是其使用场景）。
    * 生成的文本片段选择器最终会编码到 URL 中，JavaScript 可以使用这些 URL 进行导航或分享。
    * **示例：** 用户在网页上选中一段文字后，一个 JavaScript 脚本可以调用浏览器的 API 生成包含该文本片段选择器的 URL，并显示给用户进行复制或分享。
* **HTML：**
    * `TextFragmentSelectorGenerator` 分析的是 HTML 文档的结构和内容，以确定选中文本的位置和上下文。
    * 选中文本的 HTML 结构（例如，是否跨越多个标签，是否在同一个块级元素内）会影响选择器的生成策略。
    * **示例：** 如果选中的文本完全在一个 `<p>` 标签内，且内容较短，生成器可能会优先尝试精确匹配。如果选中文本跨越了多个 `<div>` 标签，生成器可能会采用范围匹配或上下文匹配。
* **CSS：**
    * CSS 的样式可能会影响文本的布局和渲染，但 `TextFragmentSelectorGenerator` 主要关注文本内容本身及其在 DOM 树中的位置。
    * 隐藏的文本（通过 `display: none` 或 `visibility: hidden`）通常不会被选中，因此也不会被用于生成选择器。
    * **示例：** 即使一段文本被 CSS 设置为不同的字体、颜色或大小，`TextFragmentSelectorGenerator` 仍然可以基于其文本内容生成选择器。

**逻辑推理、假设输入与输出：**

**假设输入：** 用户在以下 HTML 片段中选中了 "example text" 这段文字。

```html
<div>This is some example text on the page.</div>
```

**情景 1：精确匹配**

* **假设：** "example text" 在页面上是唯一的。
* **生成过程：**
    1. `Generate()` 方法接收包含 "example text" 的 `RangeInFlatTree` 对象。
    2. `GenerateExactSelector()` 被调用。
    3. 因为 "example text" 长度较短且假设唯一，生成器创建了一个类型为 `kExact` 的 `TextFragmentSelector`。
* **输出：** `TextFragmentSelector` 对象，其 `target_text` 成员为 "example text"。

**情景 2：范围匹配**

* **假设：** 页面上还有其他包含 "text" 的文字。
* **生成过程：**
    1. `Generate()` 方法接收包含 "example text" 的 `RangeInFlatTree` 对象。
    2. `GenerateExactSelector()` 被调用，但发现 "example text" 不是唯一的。
    3. `ExtendRangeSelector()` 被调用，尝试使用选中文本的开头和结尾的几个词。
* **输出：** `TextFragmentSelector` 对象，其 `start` 成员可能为 "example"，`end` 成员可能为 "text"。

**情景 3：上下文匹配**

* **假设：** 页面上还有其他以 "example" 开头，以 "text" 结尾的文字。
* **生成过程：**
    1. 前两步的匹配都不够唯一。
    2. `ExtendContext()` 被调用，尝试添加前缀和后缀。
* **输出：** `TextFragmentSelector` 对象，其 `prefix` 可能为 "some"，`target_text` 为 "example text"，`suffix` 可能为 "on"。

**用户或编程常见的使用错误：**

* **选择空文本：** 用户没有选中任何文本就尝试生成选择器。这会导致生成器返回一个无效的选择器。
    * **示例：**  用户点击了一个按钮，但没有先选中任何文本。`PlainText(ephemeral_range).LengthWithStrippedWhiteSpace() == 0` 条件会成立，导致 `error_` 被设置为 `LinkGenerationError::kEmptySelection`。
* **选择的文本片段在页面上不唯一，且没有足够的上下文进行区分：** 生成器可能会生成一个不精确的选择器，导致链接跳转到错误的文本片段。
    * **示例：**  页面上多次出现 "the quick brown fox"。如果用户只选中其中一个，而生成器只使用了 "the quick brown fox" 作为精确匹配，那么链接可能会跳转到页面上第一次出现的这个短语。
* **选择的文本片段过长，导致无法生成有效的选择器：**  生成器对选择器的长度有限制，过长的文本片段可能无法生成简洁且有效的选择器。
    * **示例：** 用户选中了整篇文章的内容。`selected_text.length() > GetExactTextMaxChars()` 条件可能会成立，导致生成器尝试范围匹配或上下文匹配。如果即使添加上下文后选择器仍然过长，可能会导致生成失败。
* **在动态加载内容的页面上生成选择器，之后页面内容发生变化：**  先前生成的选择器可能不再有效，因为目标文本片段的位置或内容已经改变。
    * **示例：** 用户在一个新闻网站上选中了一段新闻标题并生成了链接。几分钟后，该新闻被更新或移除，之前生成的链接可能就无法正确定位到目标文本。

总而言之，`text_fragment_selector_generator.cc` 负责将用户在网页上选择的文本转化为一种可以在 URL 中使用的、指向该特定文本片段的机制。它通过一系列策略来提高选择器的准确性和唯一性，并考虑了各种边界情况和潜在的错误。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_selector_generator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector_generator.h"

#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/default_tick_clock.h"
#include "components/shared_highlighting/core/common/shared_highlighting_features.h"
#include "third_party/abseil-cpp/absl/base/macros.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_buffer.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/range_in_flat_tree.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_anchor_metrics.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_finder.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_selector.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/platform/text/text_boundaries.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

using LinkGenerationError = shared_highlighting::LinkGenerationError;
using LinkGenerationStatus = shared_highlighting::LinkGenerationStatus;

namespace blink {

namespace {

// Returns true if text from beginning of |node| until |pos_offset| can be
// considered empty. Otherwise, return false.
bool IsFirstVisiblePosition(Node* node, unsigned pos_offset) {
  auto range_start = PositionInFlatTree::FirstPositionInNode(*node);
  auto range_end = PositionInFlatTree(node, pos_offset);
  return node->getNodeType() == Node::kElementNode || pos_offset == 0 ||
         PlainText(EphemeralRangeInFlatTree(range_start, range_end))
                 .LengthWithStrippedWhiteSpace() == 0;
}

// Returns true if text from |pos_offset| until end of |node| can be considered
// empty. Otherwise, return false.
bool IsLastVisiblePosition(Node* node, unsigned pos_offset) {
  auto range_start = PositionInFlatTree(node, pos_offset);
  auto range_end = PositionInFlatTree::LastPositionInNode(*node);
  return node->getNodeType() == Node::kElementNode ||
         pos_offset == node->textContent().length() ||
         PlainText(EphemeralRangeInFlatTree(range_start, range_end))
                 .LengthWithStrippedWhiteSpace() == 0;
}

struct ForwardDirection {
  static Node* Next(const Node& node) { return FlatTreeTraversal::Next(node); }
  static Node* Next(const Node& node, const Node* stay_within) {
    return FlatTreeTraversal::Next(node, stay_within);
  }
  static Node* GetVisibleTextNode(Node& start_node) {
    return FindBuffer::ForwardVisibleTextNode(start_node);
  }
};

struct BackwardDirection {
  static Node* Next(const Node& node) {
    return FlatTreeTraversal::Previous(node);
  }
  static Node* GetVisibleTextNode(Node& start_node) {
    return FindBuffer::BackwardVisibleTextNode(start_node);
  }
};

template <class Direction>
Node* NextNonEmptyVisibleTextNode(Node* start_node) {
  if (!start_node)
    return nullptr;

  // Move forward/backward until non empty visible text node is found.
  for (Node* node = start_node; node; node = Direction::Next(*node)) {
    Node* next_node = Direction::GetVisibleTextNode(*node);
    if (!next_node)
      return nullptr;
    // Filter out nodes without layout object.
    if (next_node->GetLayoutObject() &&
        PlainText(EphemeralRange::RangeOfContents(*next_node))
                .LengthWithStrippedWhiteSpace() > 0) {
      return next_node;
    }
    node = next_node;
  }
  return nullptr;
}

// Returns the next/previous visible node to |start_node|.
Node* FirstNonEmptyVisibleTextNode(Node* start_node) {
  return NextNonEmptyVisibleTextNode<ForwardDirection>(start_node);
}

Node* BackwardNonEmptyVisibleTextNode(Node* start_node) {
  return NextNonEmptyVisibleTextNode<BackwardDirection>(start_node);
}

// For Element-based Position returns the node that its pointing to, otherwise
// returns the container node.
Node* ResolvePositionToNode(const PositionInFlatTree& position) {
  Node* node = position.ComputeContainerNode();
  int offset = position.ComputeOffsetInContainerNode();

  if (node->getNodeType() == Node::kElementNode && node->hasChildren() &&
      node->childNodes()->item(offset)) {
    return node->childNodes()->item(offset);
  }
  return node;
}

}  // namespace

constexpr int kExactTextMaxChars = 300;
constexpr int kNoContextMinChars = 20;
constexpr int kMaxContextWords = 10;
constexpr int kMaxRangeWords = 10;
constexpr int kMaxIterationCountToRecord = 10;
constexpr int kMinWordCount = 3;

std::optional<int> g_exactTextMaxCharsOverride;

TextFragmentSelectorGenerator::TextFragmentSelectorGenerator(
    LocalFrame* main_frame)
    : frame_(main_frame) {}

void TextFragmentSelectorGenerator::Generate(const RangeInFlatTree& range,
                                             GenerateCallback callback) {
  DCHECK(callback);
  Reset();
  range_ = MakeGarbageCollected<RangeInFlatTree>(range.StartPosition(),
                                                 range.EndPosition());
  pending_generate_selector_callback_ = std::move(callback);

  StartGeneration();
}

void TextFragmentSelectorGenerator::Reset() {
  if (finder_) {
    finder_->Cancel();
    finder_.Clear();
  }

  generation_start_time_ = base::DefaultTickClock::GetInstance()->NowTicks();
  state_ = kNotStarted;
  error_ = LinkGenerationError::kNone;
  step_ = kExact;
  prefix_iterator_ = nullptr;
  suffix_iterator_ = nullptr;
  range_start_iterator_ = nullptr;
  range_end_iterator_ = nullptr;
  num_context_words_ = 0;
  num_range_words_ = 0;
  iteration_ = 0;
  selector_ = nullptr;
  range_ = nullptr;
  pending_generate_selector_callback_.Reset();
}

void TextFragmentSelectorGenerator::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(range_);
  visitor->Trace(finder_);
  visitor->Trace(prefix_iterator_);
  visitor->Trace(suffix_iterator_);
  visitor->Trace(range_start_iterator_);
  visitor->Trace(range_end_iterator_);
}

void TextFragmentSelectorGenerator::RecordSelectorStateUma() const {
  base::UmaHistogramEnumeration("SharedHighlights.LinkGenerated.StateAtRequest",
                                state_);
}

String TextFragmentSelectorGenerator::GetSelectorTargetText() const {
  if (!range_)
    return g_empty_string;

  return PlainText(range_->ToEphemeralRange()).StripWhiteSpace();
}

void TextFragmentSelectorGenerator::DidFindMatch(const RangeInFlatTree& match,
                                                 bool is_unique) {
  finder_.Clear();

  if (did_find_match_callback_for_testing_)
    std::move(did_find_match_callback_for_testing_).Run(is_unique);

  if (is_unique &&
      PlainText(match.ToEphemeralRange()).LengthWithStrippedWhiteSpace() ==
          PlainText(range_->ToEphemeralRange())
              .LengthWithStrippedWhiteSpace()) {
    state_ = kSuccess;
    ResolveSelectorState();
  } else {
    state_ = kNeedsNewCandidate;

    // If already tried exact selector then should continue by adding context.
    if (step_ == kExact)
      step_ = kContext;
    GenerateSelectorCandidate();
  }
}

void TextFragmentSelectorGenerator::NoMatchFound() {
  finder_.Clear();

  state_ = kFailure;
  error_ = LinkGenerationError::kIncorrectSelector;
  ResolveSelectorState();
}

void TextFragmentSelectorGenerator::AdjustSelection() {
  if (!range_)
    return;

  EphemeralRangeInFlatTree ephemeral_range = range_->ToEphemeralRange();
  Node* start_container =
      ephemeral_range.StartPosition().ComputeContainerNode();
  Node* end_container = ephemeral_range.EndPosition().ComputeContainerNode();
  Node* corrected_start =
      ResolvePositionToNode(ephemeral_range.StartPosition());
  int corrected_start_offset =
      (corrected_start->isSameNode(start_container))
          ? ephemeral_range.StartPosition().ComputeOffsetInContainerNode()
          : 0;

  Node* corrected_end = ResolvePositionToNode(ephemeral_range.EndPosition());
  int corrected_end_offset =
      (corrected_end->isSameNode(end_container))
          ? ephemeral_range.EndPosition().ComputeOffsetInContainerNode()
          : 0;

  // If start node has no text or given start position point to the last visible
  // text in its containiner node, use the following visible node for selection
  // start. This has to happen before generation, so that selection is correctly
  // classified as same block or not.
  if (IsLastVisiblePosition(corrected_start, corrected_start_offset)) {
    corrected_start = FirstNonEmptyVisibleTextNode(
        FlatTreeTraversal::NextSkippingChildren(*corrected_start));
    corrected_start_offset = 0;
  } else {
    // if node change was not necessary move start and end positions to
    // contain full words. This is not necessary when node change happened
    // because block limits are also word limits.
    String start_text = corrected_start->textContent();
    start_text.Ensure16Bit();
    corrected_start_offset =
        FindWordStartBoundary(start_text.Span16(), corrected_start_offset);
  }

  // If end node has no text or given end position point to the first visible
  // text in its containiner node, use the previous visible node for selection
  // end. This has to happen before generation, so that selection is correctly
  // classified as same block or not.
  if (IsFirstVisiblePosition(corrected_end, corrected_end_offset)) {
    // Here, |Previous()| already skips the children of the given node,
    // because we're doing pre-order traversal.
    corrected_end = BackwardNonEmptyVisibleTextNode(
        FlatTreeTraversal::Previous(*corrected_end));
    if (corrected_end)
      corrected_end_offset = corrected_end->textContent().length();
  } else {
    // if node change was not necessary move start and end positions to
    // contain full words. This is not necessary when node change happened
    // because block limits are also word limits.
    String end_text = corrected_end->textContent();
    end_text.Ensure16Bit();

    // If |selection_end_pos| is at the beginning of a new word then don't
    // search for the word end as it will be the end of the next word, which was
    // not included in the selection.
    if (corrected_end_offset !=
        FindWordStartBoundary(end_text.Span16(), corrected_end_offset)) {
      corrected_end_offset =
          FindWordEndBoundary(end_text.Span16(), corrected_end_offset);
    }
  }

  if (corrected_start != start_container ||
      static_cast<int>(corrected_start_offset) !=
          ephemeral_range.StartPosition().ComputeOffsetInContainerNode() ||
      corrected_end != end_container ||
      static_cast<int>(corrected_end_offset) !=
          ephemeral_range.EndPosition().ComputeOffsetInContainerNode()) {
    PositionInFlatTree start(corrected_start, corrected_start_offset);
    PositionInFlatTree end(corrected_end, corrected_end_offset);

    // TODO(bokan): This can sometimes occur from a selection. Avoid crashing
    // from this case but this can come from a seemingly correct range so we
    // should investigate the source of the bug.  https://crbug.com/1216357
    if (start >= end) {
      range_ = nullptr;
      return;
    }

    range_ = MakeGarbageCollected<RangeInFlatTree>(start, end);
  }
}

void TextFragmentSelectorGenerator::StartGeneration() {
  DCHECK(range_);

  range_->StartPosition().GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kFindInPage);

  // TODO(bokan): This can sometimes occur from a selection. Avoid crashing from
  // this case but this can come from a seemingly correct range so we should
  // investigate the source of the bug.
  // https://crbug.com/1216357
  EphemeralRangeInFlatTree ephemeral_range = range_->ToEphemeralRange();
  if (ephemeral_range.StartPosition() >= ephemeral_range.EndPosition()) {
    state_ = kFailure;
    error_ = LinkGenerationError::kEmptySelection;
    ResolveSelectorState();
    return;
  }

  // Shouldn't continue if selection is empty.
  if (PlainText(ephemeral_range).LengthWithStrippedWhiteSpace() == 0) {
    state_ = kFailure;
    error_ = LinkGenerationError::kEmptySelection;
    ResolveSelectorState();
    return;
  }

  AdjustSelection();

  // TODO(bokan): This can sometimes occur from a selection. Avoid crashing from
  // this case but this can come from a seemingly correct range so we should
  // investigate the source of the bug.
  // https://crbug.com/1216357
  if (!range_) {
    state_ = kFailure;
    error_ = LinkGenerationError::kEmptySelection;
    ResolveSelectorState();
    return;
  }

  state_ = kNeedsNewCandidate;
  GenerateSelectorCandidate();
}

void TextFragmentSelectorGenerator::GenerateSelectorCandidate() {
  DCHECK_EQ(kNeedsNewCandidate, state_);

  if (step_ == kExact)
    GenerateExactSelector();

  if (step_ == kRange)
    ExtendRangeSelector();

  if (step_ == kContext)
    ExtendContext();
  ResolveSelectorState();
}

void TextFragmentSelectorGenerator::ResolveSelectorState() {
  switch (state_) {
    case kTestCandidate:
      RunTextFinder();
      break;
    case kNotStarted:
    case kNeedsNewCandidate:
      NOTREACHED();
    case kFailure:
      OnSelectorReady(
          TextFragmentSelector(TextFragmentSelector::SelectorType::kInvalid));
      break;
    case kSuccess:
      OnSelectorReady(*selector_);
      break;
  }
}

void TextFragmentSelectorGenerator::RunTextFinder() {
  DCHECK(selector_);
  iteration_++;
  // |FindMatch| will call |DidFindMatch| indicating if the match was unique.
  finder_ = MakeGarbageCollected<TextFragmentFinder>(
      *this, *selector_, frame_->GetDocument(),
      TextFragmentFinder::FindBufferRunnerType::kAsynchronous);
  finder_->FindMatch();
}

PositionInFlatTree TextFragmentSelectorGenerator::GetPreviousTextEndPosition(
    const PositionInFlatTree& position) {
  PositionInFlatTree search_end_position =
      PositionInFlatTree::FirstPositionInNode(
          *frame_->GetDocument()->documentElement()->firstChild());
  PositionInFlatTree previous_text_position =
      TextFragmentFinder::PreviousTextPosition(position, search_end_position);
  if (previous_text_position == search_end_position) {
    return PositionInFlatTree();
  }
  return previous_text_position;
}

PositionInFlatTree TextFragmentSelectorGenerator::GetNextTextStartPosition(
    const PositionInFlatTree& position) {
  PositionInFlatTree search_end_position =
      PositionInFlatTree::LastPositionInNode(
          *frame_->GetDocument()->documentElement()->lastChild());
  PositionInFlatTree next_text_position =
      TextFragmentFinder::NextTextPosition(position, search_end_position);

  if (next_text_position == search_end_position) {
    return PositionInFlatTree();
  }
  return next_text_position;
}

void TextFragmentSelectorGenerator::GenerateExactSelector() {
  DCHECK_EQ(kExact, step_);
  DCHECK_EQ(kNeedsNewCandidate, state_);
  EphemeralRangeInFlatTree ephemeral_range = range_->ToEphemeralRange();

  // TODO(bokan): Another case where the range appears to not have valid nodes.
  // Not sure how this happens. https://crbug.com/1216773.
  if (!ephemeral_range.StartPosition().ComputeContainerNode() ||
      !ephemeral_range.EndPosition().ComputeContainerNode()) {
    state_ = kFailure;
    error_ = LinkGenerationError::kEmptySelection;
    return;
  }

  // If not in same block, should use ranges.
  if (!TextFragmentFinder::IsInSameUninterruptedBlock(
          ephemeral_range.StartPosition(), ephemeral_range.EndPosition())) {
    step_ = kRange;
    return;
  }
  String selected_text = PlainText(ephemeral_range).StripWhiteSpace();
  // If too long should use ranges.
  if (selected_text.length() > GetExactTextMaxChars()) {
    step_ = kRange;
    return;
  }

  selector_ = std::make_unique<TextFragmentSelector>(
      TextFragmentSelector::SelectorType::kExact, selected_text, "", "", "");

  // If too short should use exact selector, but should add context.
  if (selected_text.length() < kNoContextMinChars) {
    step_ = kContext;
    return;
  }

  state_ = kTestCandidate;
}

void TextFragmentSelectorGenerator::ExtendRangeSelector() {
  DCHECK_EQ(kRange, step_);
  DCHECK_EQ(kNeedsNewCandidate, state_);
  // Give up if range is already too long.
  if (num_range_words_ > kMaxRangeWords) {
    step_ = kContext;
    return;
  }

  int num_words_to_add = 1;

  // Determine length of target string for verifictaion.
  unsigned target_length = PlainText(range_->ToEphemeralRange()).length();

  // Initialize range start/end and word min count, if needed.
  if (!range_start_iterator_ && !range_end_iterator_) {
    PositionInFlatTree range_start_position =
        GetNextTextStartPosition(range_->StartPosition());
    PositionInFlatTree range_end_position =
        GetPreviousTextEndPosition(range_->EndPosition());

    if (range_start_position.IsNull() || range_end_position.IsNull()) {
      state_ = kFailure;
      error_ = LinkGenerationError::kNoRange;
      return;
    }

    range_start_iterator_ = MakeGarbageCollected<ForwardSameBlockWordIterator>(
        range_start_position);
    range_end_iterator_ =
        MakeGarbageCollected<BackwardSameBlockWordIterator>(range_end_position);

    // Use at least 3 words from both sides for more robust link to text unless
    // the selected text is shorter than 6 words.
    if (TextFragmentFinder::IsInSameUninterruptedBlock(range_start_position,
                                                       range_end_position)) {
      num_words_to_add = 0;
      auto* range_start_counter =
          MakeGarbageCollected<ForwardSameBlockWordIterator>(
              range_start_position);
      // TODO(crbug.com/1302719) ForwardSameBlockWordIterator Should be made to
      // return the current posision in a form that is comparable against
      // range_end_position directly.

      while (num_words_to_add < kMinWordCount * 2 &&
             range_start_counter->AdvanceNextWord() &&
             range_start_counter->TextFromStart().length() <= target_length) {
        num_words_to_add++;
      }
      num_words_to_add = num_words_to_add / 2;
      if (num_words_to_add == 0) {
        // If there is only one word found in the range selection explicitly set
        // exact selector to avoid round tripping.
        EphemeralRangeInFlatTree ephemeral_range = range_->ToEphemeralRange();
        String selected_text = PlainText(ephemeral_range).StripWhiteSpace();
        step_ = kExact;
        state_ = kTestCandidate;
        selector_ = std::make_unique<TextFragmentSelector>(
            TextFragmentSelector::SelectorType::kExact, selected_text, "", "",
            "");
        return;
      }
    } else {
      // If the the start and end are in different blocks overlaps dont need to
      // be prevented as the number of words will limited by the block
      // boundaries.
      num_words_to_add = kMinWordCount;
    }
  }

  if (!range_start_iterator_ || !range_end_iterator_) {
    state_ = kFailure;
    error_ = LinkGenerationError::kNoRange;
    return;
  }

  for (int i = 0; i < num_words_to_add; i++) {
    if (range_start_iterator_)
      range_start_iterator_->AdvanceNextWord();

    if (range_end_iterator_)
      range_end_iterator_->AdvanceNextWord();

    num_range_words_++;
  }

  String start =
      range_start_iterator_ ? range_start_iterator_->TextFromStart() : "";
  String end = range_end_iterator_ ? range_end_iterator_->TextFromStart() : "";

  if (start.length() + end.length() > target_length) {
    if (!selector_) {
      state_ = kFailure;
      error_ = LinkGenerationError::kNoRange;
      return;
    }

    // If start and end overlap but its not the first attempt, then proceed with
    // adding context.
    step_ = kContext;
    return;
  }

  if (selector_ && start == selector_->Start() && end == selector_->End()) {
    // If the start and end didn't change, it means we
    // exhausted the selected text and should try adding context.
    step_ = kContext;
    return;
  }

  selector_ = std::make_unique<TextFragmentSelector>(
      TextFragmentSelector::SelectorType::kRange, start, end, "", "");
  state_ = kTestCandidate;
}

void TextFragmentSelectorGenerator::ExtendContext() {
  DCHECK_EQ(kContext, step_);
  DCHECK_EQ(kNeedsNewCandidate, state_);
  DCHECK(selector_);

  // Give up if context is already too long.
  if (num_context_words_ >= kMaxContextWords) {
    state_ = kFailure;
    error_ = LinkGenerationError::kContextLimitReached;
    return;
  }

  int num_words_to_add = 1;
  // Try initiating properties necessary for calculating prefix and suffix.
  if (!suffix_iterator_ && !prefix_iterator_) {
    PositionInFlatTree suffix_start_position =
        GetNextTextStartPosition(range_->EndPosition());
    PositionInFlatTree prefix_end_position =
        GetPreviousTextEndPosition(range_->StartPosition());

    if (suffix_start_position.IsNotNull()) {
      suffix_iterator_ = MakeGarbageCollected<ForwardSameBlockWordIterator>(
          suffix_start_position);
    }

    if (prefix_end_position.IsNotNull()) {
      prefix_iterator_ = MakeGarbageCollected<BackwardSameBlockWordIterator>(
          prefix_end_position);
    }

    // Use at least 3 words from both sides for more robust link to text.
    num_words_to_add = kMinWordCount;
  }

  if (!suffix_iterator_ && !prefix_iterator_) {
    state_ = kFailure;
    error_ = LinkGenerationError::kNoContext;
    return;
  }

  for (int i = 0; i < num_words_to_add; i++) {
    if (suffix_iterator_)
      suffix_iterator_->AdvanceNextWord();

    if (prefix_iterator_)
      prefix_iterator_->AdvanceNextWord();

    num_context_words_++;
  }

  String prefix = prefix_iterator_ ? prefix_iterator_->TextFromStart() : "";
  String suffix = suffix_iterator_ ? suffix_iterator_->TextFromStart() : "";

  // Give up if we were unable to get new prefix and suffix.
  if (prefix == selector_->Prefix() && suffix == selector_->Suffix()) {
    state_ = kFailure;
    error_ = LinkGenerationError::kContextExhausted;
    return;
  }
  selector_ = std::make_unique<TextFragmentSelector>(
      selector_->Type(), selector_->Start(), selector_->End(), prefix, suffix);

  state_ = kTestCandidate;
}

void TextFragmentSelectorGenerator::RecordAllMetrics(
    const TextFragmentSelector& selector) {
  LinkGenerationStatus status =
      selector.Type() == TextFragmentSelector::SelectorType::kInvalid
          ? LinkGenerationStatus::kFailure
          : LinkGenerationStatus::kSuccess;
  shared_highlighting::LogLinkGenerationStatus(status);

  ukm::UkmRecorder* recorder = frame_->GetDocument()->UkmRecorder();
  ukm::SourceId source_id = frame_->GetDocument()->UkmSourceID();

  if (selector.Type() != TextFragmentSelector::SelectorType::kInvalid) {
    UMA_HISTOGRAM_TIMES("SharedHighlights.LinkGenerated.TimeToGenerate",
                        base::DefaultTickClock::GetInstance()->NowTicks() -
                            generation_start_time_);

    shared_highlighting::LogLinkGeneratedSuccessUkmEvent(recorder, source_id);
  } else {
    UMA_HISTOGRAM_EXACT_LINEAR(
        "SharedHighlights.LinkGenerated.Error.Iterations", iteration_,
        kMaxIterationCountToRecord);
    UMA_HISTOGRAM_TIMES("SharedHighlights.LinkGenerated.Error.TimeToGenerate",
                        base::DefaultTickClock::GetInstance()->NowTicks() -
                            generation_start_time_);
    if (error_ == LinkGenerationError::kNone)
      error_ = LinkGenerationError::kUnknown;
    shared_highlighting::LogLinkGenerationErrorReason(error_);
    shared_highlighting::LogLinkGeneratedErrorUkmEvent(recorder, source_id,
                                                       error_);
  }
}

void TextFragmentSelectorGenerator::OnSelectorReady(
    const TextFragmentSelector& selector) {
  // Check that frame is not deattched and generator is still valid.
  DCHECK(frame_);

  RecordAllMetrics(selector);
  if (pending_generate_selector_callback_) {
    std::move(pending_generate_selector_callback_).Run(selector, error_);
  }
}

// static
void TextFragmentSelectorGenerator::OverrideExactTextMaxCharsForTesting(
    int value) {
  if (value < 0)
    g_exactTextMaxCharsOverride.reset();
  else
    g_exactTextMaxCharsOverride = value;
}

unsigned TextFragmentSelectorGenerator::GetExactTextMaxChars() {
  if (g_exactTextMaxCharsOverride)
    return g_exactTextMaxCharsOverride.value();
  else
    return kExactTextMaxChars;
}

}  // namespace blink
```
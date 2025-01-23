Response:
Let's break down the request and the provided code to formulate a comprehensive response.

**1. Understanding the Core Request:**

The request asks for a functional explanation of the `offset_mapping.cc` file within the Chromium Blink engine. Key aspects to address include:

* **Functionality:** What does this code do?
* **Relationships:** How does it interact with JavaScript, HTML, and CSS?
* **Logic & Examples:**  Provide examples of input and output based on its logic.
* **Common Errors:**  Highlight potential mistakes users or developers might make.

**2. Initial Code Scan & Keyword Identification:**

Skimming the code reveals several important keywords and concepts:

* `OffsetMapping`, `OffsetMappingUnit`: These are the central data structures.
* `Position`, `EphemeralRange`:  Relate to text selection and cursor placement.
* `LayoutObject`, `LayoutText`, `LayoutBlockFlow`, `InlineNode`:  Indicate interaction with the layout engine.
* `DOMOffset`, `TextContentOffset`: Key terms suggesting a mapping between DOM structure and rendered text.
* `text-transform`:  A CSS property mentioned as a potential complication.
* `text_content_`: A string member, implying the storage of rendered text.
* `GetMappingUnitForPosition`, `GetMappingUnitsForDOMRange`, `GetTextContentOffset`, etc.:  Methods that perform the core mapping operations.
* `Concatenate`: Suggests merging adjacent mapping units.

**3. Formulating a High-Level Functional Description:**

Based on the keywords and the overall structure, the primary function seems to be:

* **Mapping between DOM positions and rendered text offsets.** This is crucial for tasks like:
    * Identifying which part of the rendered text corresponds to a given DOM node/offset.
    * Finding the DOM position corresponding to a point within the rendered text.
    * Handling text transformations and other layout effects that change the relationship between DOM structure and rendered output.

**4. Connecting to JavaScript, HTML, and CSS:**

* **JavaScript:** JavaScript often interacts with the DOM and text selection. The offset mapping provides the underlying mechanism to translate JavaScript selections (based on DOM positions) to the actual rendered text.
* **HTML:** The structure of the HTML document defines the DOM tree that the offset mapping works with. Different HTML elements (especially text nodes and inline elements) will have corresponding mapping units.
* **CSS:**  CSS properties, especially those affecting text layout and rendering (like `text-transform`, `::before`, `::after`, line breaks), directly influence the offset mapping.

**5. Developing Illustrative Examples:**

* **Simple Text:** A basic example helps to establish the fundamental mapping.
* **Text Transformation:**  Demonstrates how CSS can alter the mapping.
* **Inline Elements:** Shows how the mapping handles elements within the text flow.
* **Generated Content:** Highlights the interaction with CSS `content`.

**6. Identifying Logical Inferences and Assumptions:**

The code makes several logical connections:

* A `Position` can be converted to a `Node` and an offset.
* `LayoutObject`s are associated with DOM nodes.
* The mapping is built within an inline formatting context (a `LayoutBlockFlow`).

**7. Pinpointing Potential User/Developer Errors:**

Common mistakes could arise from:

* **Incorrect DOM offsets:**  Providing offsets that are out of bounds for a given node.
* **Assuming a direct 1:1 mapping:** Not considering the impact of CSS transformations.
* **Ignoring collapsed units:**  Failing to account for elements that don't contribute to rendered text.

**8. Structuring the Response:**

Organize the information logically:

* Start with a clear and concise summary of the file's purpose.
* Explain the core concepts (`OffsetMapping`, `OffsetMappingUnit`).
* Detail the relationships with JavaScript, HTML, and CSS with examples.
* Provide concrete input/output examples to illustrate the logic.
* Highlight common usage errors.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  Maybe it's just about text nodes.
* **Correction:**  The code also handles inline elements (`IsAtomicInlineLevel`) and deals with positions before/after elements. The examples need to reflect this.
* **Initial thought:** The mapping is always straightforward.
* **Correction:** The mention of `text-transform` and the handling of collapsed units indicates that the mapping can be complex and requires careful consideration of CSS. The examples should include these scenarios.
* **Initial thought:**  Focus on the code's internal workings.
* **Correction:** The request specifically asks about relationships with web technologies and common errors, so shift the focus to the external impact and potential pitfalls.

By following this structured approach, considering the key elements of the code, and refining the understanding through self-correction, we can generate a comprehensive and accurate explanation of the `offset_mapping.cc` file.
这个文件 `blink/renderer/core/layout/inline/offset_mapping.cc` 的主要功能是**在 Blink 渲染引擎中，用于将 DOM 树中的位置（Position）和范围（Range）映射到渲染后的内联文本内容中的偏移量（offset）**。

更具体地说，它创建并管理一个 `OffsetMapping` 对象，该对象存储了关于如何将 DOM 结构（特别是文本节点和内联元素）映射到最终渲染出的文本字符串的信息。这种映射关系考虑了各种因素，例如：

* **文本转换（text-transform）:** CSS 的 `text-transform` 属性可能会改变文本的长度和内容。
* **CSS 生成内容（content）:** `::before` 和 `::after` 伪元素可以插入文本内容。
* **内联元素:**  非文本的内联元素（如 `<img>`）在 DOM 中占据位置，但在文本内容中可能不直接对应字符。
* **换行符和空白符处理:** 渲染引擎对换行符和空白符的处理可能会与 DOM 结构不同。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `OffsetMapping` 的输入是基于 HTML 结构构建的 DOM 树。它遍历和分析 DOM 树中的文本节点和内联元素。
    * **例子:**  考虑以下 HTML 片段：
    ```html
    <p>Hello <span>world</span>!</p>
    ```
    `OffsetMapping` 会分析 `<p>` 元素及其子节点（文本节点 "Hello ", `<span>` 元素, 文本节点 "!"）。

* **CSS:** CSS 样式会影响文本的渲染，从而影响 `OffsetMapping` 的构建。
    * **例子 (text-transform):**
        ```html
        <style>
          .uppercase { text-transform: uppercase; }
        </style>
        <p class="uppercase">hello</p>
        ```
        原始 DOM 文本是 "hello"，但渲染后的文本是 "HELLO"。`OffsetMapping` 需要记录这种转换，以便将 DOM 中的 "h" 映射到渲染后的 "H" 的偏移量。

    * **例子 (content):**
        ```html
        <style>
          p::before { content: "Start: "; }
        </style>
        <p>Text</p>
        ```
        实际渲染的文本是 "Start: Text"。`OffsetMapping` 需要知道 "Start: " 这部分内容不是直接来自 DOM，而是由 CSS 生成的。

* **JavaScript:** JavaScript 可以操作 DOM，并需要知道 DOM 结构与渲染文本之间的对应关系，例如在处理用户选择文本或光标位置时。`OffsetMapping` 提供了这种映射能力，JavaScript 可以通过 Blink 提供的 API 来访问它。
    * **例子 (获取渲染文本偏移量):**  假设 JavaScript 需要知道 "world" 这个词在渲染后的文本中的起始位置。它可以先找到 "world" 对应的 DOM 范围，然后利用 `OffsetMapping` 将这个 DOM 范围转换为渲染文本的偏移量。

**逻辑推理、假设输入与输出:**

`OffsetMapping` 的核心逻辑是构建一个 `OffsetMappingUnit` 的列表，每个 `OffsetMappingUnit` 代表 DOM 结构中的一部分（通常是文本节点的一部分或一个内联元素），并记录其对应的渲染文本的偏移范围。

**假设输入:**  一个简单的 HTML 结构：

```html
<p>ab<span>c</span>de</p>
```

**假设 `OffsetMappingUnit` 的输出 (简化表示):**

| 类型        | 关联的 LayoutObject | DOM 起始偏移 | DOM 结束偏移 | 文本内容起始偏移 | 文本内容结束偏移 | 渲染文本片段 |
|-------------|----------------------|--------------|--------------|--------------------|--------------------|--------------|
| Identity    | LayoutText("ab")     | 0            | 2            | 0                  | 2                  | "ab"         |
| Identity    | LayoutInline(span)   | 0            | 1            | 2                  | 3                  | "c"          |
| Identity    | LayoutText("de")     | 0            | 2            | 3                  | 5                  | "de"         |

**逻辑推理:**

1. **遍历 DOM 树:** `OffsetMapping` 会从需要进行偏移量映射的布局对象（通常是块级容器）开始，遍历其包含的内联布局对象。
2. **创建 `OffsetMappingUnit`:** 对于每个文本节点或内联元素，创建一个 `OffsetMappingUnit`。
3. **确定偏移量范围:**
    * **DOM 偏移量:** 对于文本节点，通常就是文本节点内的字符索引。对于非文本内联元素，可以认为占据一个 DOM 偏移位置 (0 到 1)。
    * **文本内容偏移量:** 这需要考虑 CSS 的影响。例如，如果 `<span>` 的 `display` 是 `none`，那么对应的 `OffsetMappingUnit` 的文本内容偏移范围可能为空。
4. **合并相邻单元:**  为了优化，相邻且映射关系简单的 `OffsetMappingUnit` 可以被合并。

**用户或编程常见的使用错误:**

* **假设 DOM 偏移量直接等于渲染文本偏移量:**  这是最常见的错误。没有考虑到 `text-transform`，CSS 生成内容，以及内联元素的处理。
    * **例子:** 用户可能会错误地认为对于 `<p>abc</p>`，DOM 偏移量 1 对应渲染文本的第二个字符 'b'。但在更复杂的情况下，这种假设可能不成立。

* **在多线程或异步操作中缓存过期的 `OffsetMapping` 对象:** `OffsetMapping` 对象是基于特定的渲染状态创建的。如果 DOM 结构或 CSS 样式发生变化，旧的 `OffsetMapping` 对象可能会失效，导致映射错误。

* **不正确地使用 `Position` 对象:** `Position` 对象定义了 DOM 树中的一个位置。如果创建了错误的 `Position` 对象，那么使用 `OffsetMapping` 进行映射也会得到错误的结果。
    * **例子:**  创建一个指向错误节点或错误偏移量的 `Position` 对象。

* **没有考虑到折叠的 `OffsetMappingUnit`:**  某些元素或文本片段可能不会产生任何渲染的文本内容（例如，空的 `<span>` 元素或者被 `visibility: hidden` 的文本）。在处理偏移量时需要注意这些折叠的单元。

总而言之，`offset_mapping.cc` 是 Blink 渲染引擎中一个关键的组件，它弥合了 DOM 抽象结构和最终渲染出的文本之间的鸿沟，为诸如文本选择、光标定位等功能提供了底层的映射支持，并且需要考虑到 CSS 样式带来的复杂性。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/offset_mapping.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"

#include <algorithm>

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/platform/text/character.h"

namespace blink {

namespace {

// Note: LayoutFlowThread, used for multicol, can't provide offset mapping.
bool CanUseOffsetMapping(const LayoutObject& object) {
  return object.IsLayoutBlockFlow() && !object.IsLayoutFlowThread();
}

Position CreatePositionForOffsetMapping(const Node& node, unsigned dom_offset) {
  if (auto* text_node = DynamicTo<Text>(node)) {
    // 'text-transform' may make the rendered text length longer than the
    // original text node, in which case we clamp the offset to avoid crashing.
    // TODO(crbug.com/750990): Support 'text-transform' to remove this hack.
#if DCHECK_IS_ON()
    // Ensures that the clamping hack kicks in only with text-transform.
    if (node.GetLayoutObject()->StyleRef().TextTransform() ==
        ETextTransform::kNone) {
      DCHECK_LE(dom_offset, text_node->length());
    }
#endif
    const unsigned clamped_offset = std::min(dom_offset, text_node->length());
    return Position(&node, clamped_offset);
  }
  // For non-text-anchored position, the offset must be either 0 or 1.
  DCHECK_LE(dom_offset, 1u);
  return dom_offset ? Position::AfterNode(node) : Position::BeforeNode(node);
}

std::pair<const Node&, unsigned> ToNodeOffsetPair(const Position& position) {
  DCHECK(OffsetMapping::AcceptsPosition(position)) << position;
  if (auto* text_node = DynamicTo<Text>(position.AnchorNode())) {
    if (position.IsOffsetInAnchor())
      return {*position.AnchorNode(), position.OffsetInContainerNode()};
    if (position.IsBeforeAnchor())
      return {*position.AnchorNode(), 0};
    DCHECK(position.IsAfterAnchor());
    return {*position.AnchorNode(), text_node->length()};
  }
  if (position.IsBeforeAnchor())
    return {*position.AnchorNode(), 0};
  return {*position.AnchorNode(), 1};
}

// TODO(xiaochengh): Introduce predicates for comparing Position and
// OffsetMappingUnit, to reduce position-offset conversion and ad-hoc
// predicates below.

}  // namespace

LayoutBlockFlow* NGInlineFormattingContextOf(const Position& position) {
  LayoutBlockFlow* block_flow =
      OffsetMapping::GetInlineFormattingContextOf(position);
  if (!block_flow || !block_flow->IsLayoutNGObject())
    return nullptr;
  return block_flow;
}

// static
LayoutBlockFlow* OffsetMapping::GetInlineFormattingContextOf(
    const Position& position) {
  if (!AcceptsPosition(position))
    return nullptr;
  const auto node_offset_pair = ToNodeOffsetPair(position);
  const LayoutObject* layout_object =
      AssociatedLayoutObjectOf(node_offset_pair.first, node_offset_pair.second);
  if (!layout_object)
    return nullptr;
  return GetInlineFormattingContextOf(*layout_object);
}

OffsetMappingUnit::OffsetMappingUnit(OffsetMappingUnitType type,
                                     const LayoutObject& layout_object,
                                     unsigned dom_start,
                                     unsigned dom_end,
                                     unsigned text_content_start,
                                     unsigned text_content_end)
    : type_(type),
      // Use atomic construction to allow for concurrently marking
      // OffsetMappingUnit.
      layout_object_(&layout_object,
                     Member<const LayoutObject>::AtomicInitializerTag{}),
      dom_start_(dom_start),
      dom_end_(dom_end),
      text_content_start_(text_content_start),
      text_content_end_(text_content_end) {
  AssertValid();
}

void OffsetMappingUnit::AssertValid() const {
#if ENABLE_SECURITY_ASSERT
  SECURITY_DCHECK(dom_start_ <= dom_end_) << dom_start_ << " vs. " << dom_end_;
  SECURITY_DCHECK(text_content_start_ <= text_content_end_)
      << text_content_start_ << " vs. " << text_content_end_;
  if (layout_object_->IsText() &&
      !To<LayoutText>(*layout_object_).IsWordBreak()) {
    const auto& layout_text = To<LayoutText>(*layout_object_);
    const unsigned text_start =
        AssociatedNode() ? layout_text.TextStartOffset() : 0;
    SECURITY_DCHECK(dom_end_ >= text_start)
        << dom_end_ << " vs. " << text_start;
  } else {
    SECURITY_DCHECK(dom_start_ == 0) << dom_start_;
    SECURITY_DCHECK(dom_end_ == 1) << dom_end_;
  }
#endif
}

const Node* OffsetMappingUnit::AssociatedNode() const {
  if (const auto* text_fragment =
          DynamicTo<LayoutTextFragment>(layout_object_.Get()))
    return text_fragment->AssociatedTextNode();
  return layout_object_->GetNode();
}

const Node& OffsetMappingUnit::GetOwner() const {
  const Node* const node = AssociatedNode();
  DCHECK(node) << layout_object_;
  return *node;
}

bool OffsetMappingUnit::Concatenate(const OffsetMappingUnit& other) {
  if (layout_object_ != other.layout_object_)
    return false;
  if (type_ != other.type_)
    return false;
  if (dom_end_ != other.dom_start_)
    return false;
  if (text_content_end_ != other.text_content_start_)
    return false;
  // Don't merge first letter and remaining text
  if (const auto* text_fragment =
          DynamicTo<LayoutTextFragment>(layout_object_.Get())) {
    // TODO(layout-dev): Fix offset calculation for text-transform
    if (text_fragment->IsRemainingTextLayoutObject() &&
        other.dom_start_ == text_fragment->TextStartOffset())
      return false;
  }
  dom_end_ = other.dom_end_;
  text_content_end_ = other.text_content_end_;
  return true;
}

unsigned OffsetMappingUnit::ConvertDOMOffsetToTextContent(
    unsigned offset) const {
  DCHECK_GE(offset, dom_start_);
  DCHECK_LE(offset, dom_end_);
  // DOM start is always mapped to text content start.
  if (offset == dom_start_)
    return text_content_start_;
  // DOM end is always mapped to text content end.
  if (offset == dom_end_)
    return text_content_end_;
  // Handle collapsed mapping.
  if (text_content_start_ == text_content_end_)
    return text_content_start_;
  // Handle has identity mapping.
  return offset - dom_start_ + text_content_start_;
}

unsigned OffsetMappingUnit::ConvertTextContentToFirstDOMOffset(
    unsigned offset) const {
  DCHECK_GE(offset, text_content_start_);
  DCHECK_LE(offset, text_content_end_);
  // Always return DOM start for collapsed units.
  if (text_content_start_ == text_content_end_)
    return dom_start_;
  // Handle identity mapping.
  if (type_ == OffsetMappingUnitType::kIdentity) {
    return dom_start_ + offset - text_content_start_;
  }
  // Handle expanded mapping.
  return offset < text_content_end_ ? dom_start_ : dom_end_;
}

unsigned OffsetMappingUnit::ConvertTextContentToLastDOMOffset(
    unsigned offset) const {
  DCHECK_GE(offset, text_content_start_);
  DCHECK_LE(offset, text_content_end_);
  // Always return DOM end for collapsed units.
  if (text_content_start_ == text_content_end_)
    return dom_end_;
  // In a non-collapsed unit, mapping between DOM and text content offsets is
  // one-to-one. Reuse existing code.
  return ConvertTextContentToFirstDOMOffset(offset);
}

// static
bool OffsetMapping::AcceptsPosition(const Position& position) {
  if (position.IsNull())
    return false;
  if (position.AnchorNode()->IsTextNode()) {
    // Position constructor should have rejected other anchor types.
    DCHECK(position.IsOffsetInAnchor() || position.IsBeforeAnchor() ||
           position.IsAfterAnchor());
    return true;
  }
  if (!position.IsBeforeAnchor() && !position.IsAfterAnchor())
    return false;
  const LayoutObject* layout_object = position.AnchorNode()->GetLayoutObject();
  if (!layout_object || !layout_object->IsInline())
    return false;
  return layout_object->IsText() || layout_object->IsAtomicInlineLevel();
}

// static
const OffsetMapping* OffsetMapping::GetFor(const Position& position) {
  return ForceGetFor(position);
}

const OffsetMapping* OffsetMapping::ForceGetFor(const Position& position) {
  if (!OffsetMapping::AcceptsPosition(position)) {
    return nullptr;
  }
  LayoutBlockFlow* context =
      OffsetMapping::GetInlineFormattingContextOf(position);
  if (!context)
    return nullptr;
  return InlineNode::GetOffsetMapping(context);
}

// static
const OffsetMapping* OffsetMapping::GetFor(const LayoutObject* layout_object) {
  if (!layout_object)
    return nullptr;
  LayoutBlockFlow* context = layout_object->FragmentItemsContainer();
  if (!context)
    return nullptr;
  return InlineNode::GetOffsetMapping(context);
}

// static
LayoutBlockFlow* OffsetMapping::GetInlineFormattingContextOf(
    const LayoutObject& object) {
  for (LayoutObject* runner = object.Parent(); runner;
       runner = runner->Parent()) {
    if (!CanUseOffsetMapping(*runner)) {
      continue;
    }
    return To<LayoutBlockFlow>(runner);
  }
  return nullptr;
}

OffsetMapping::OffsetMapping(UnitVector&& units, RangeMap&& ranges, String text)
    : units_(std::move(units)), ranges_(std::move(ranges)), text_(text) {
#if ENABLE_SECURITY_ASSERT
  for (const auto& unit : units_) {
    SECURITY_DCHECK(unit.TextContentStart() <= text.length())
        << unit.TextContentStart() << "<=" << text.length();
    SECURITY_DCHECK(unit.TextContentEnd() <= text.length())
        << unit.TextContentEnd() << "<=" << text.length();
    unit.AssertValid();
  }
  for (const auto& pair : ranges_) {
    SECURITY_DCHECK(pair.value.first < units_.size())
        << pair.value.first << "<" << units_.size();
    SECURITY_DCHECK(pair.value.second <= units_.size())
        << pair.value.second << "<=" << units_.size();
  }
#endif
}

OffsetMapping::~OffsetMapping() = default;

const OffsetMappingUnit* OffsetMapping::GetMappingUnitForPosition(
    const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position));
  const auto node_and_offset = ToNodeOffsetPair(position);
  const Node& node = node_and_offset.first;
  const unsigned offset = node_and_offset.second;
  unsigned range_start;
  unsigned range_end;
  auto it = ranges_.find(&node);
  std::tie(range_start, range_end) =
      it != ranges_.end() ? it->value : std::pair<unsigned, unsigned>(0, 0);
  if (range_start == range_end || units_[range_start].DOMStart() > offset)
    return nullptr;
  // Find the last unit where unit.dom_start <= offset
  auto unit = std::prev(std::upper_bound(
      units_.begin() + range_start, units_.begin() + range_end, offset,
      [](unsigned offset, const OffsetMappingUnit& unit) {
        return offset < unit.DOMStart();
      }));
  if (unit->DOMEnd() < offset)
    return nullptr;
  return &*unit;
}

OffsetMapping::UnitVector OffsetMapping::GetMappingUnitsForDOMRange(
    const EphemeralRange& range) const {
  DCHECK(OffsetMapping::AcceptsPosition(range.StartPosition()));
  DCHECK(OffsetMapping::AcceptsPosition(range.EndPosition()));
  DCHECK_EQ(range.StartPosition().AnchorNode(),
            range.EndPosition().AnchorNode());
  const Node& node = *range.StartPosition().AnchorNode();
  const unsigned start_offset = ToNodeOffsetPair(range.StartPosition()).second;
  const unsigned end_offset = ToNodeOffsetPair(range.EndPosition()).second;
  unsigned range_start;
  unsigned range_end;
  auto it = ranges_.find(&node);
  std::tie(range_start, range_end) =
      it != ranges_.end() ? it->value : std::pair<unsigned, unsigned>(0, 0);

  if (range_start == range_end || units_[range_start].DOMStart() > end_offset ||
      units_[range_end - 1].DOMEnd() < start_offset)
    return UnitVector();

  // Find the first unit where unit.dom_end >= start_offset
  auto result_begin = std::lower_bound(
      units_.begin() + range_start, units_.begin() + range_end, start_offset,
      [](const OffsetMappingUnit& unit, unsigned offset) {
        return unit.DOMEnd() < offset;
      });

  // Find the next of the last unit where unit.dom_start <= end_offset
  auto result_end =
      std::upper_bound(result_begin, units_.begin() + range_end, end_offset,
                       [](unsigned offset, const OffsetMappingUnit& unit) {
                         return offset < unit.DOMStart();
                       });

  UnitVector result;
  result.reserve(base::checked_cast<wtf_size_t>(result_end - result_begin));
  for (const auto& unit : base::make_span(result_begin, result_end)) {
    // If the unit isn't fully within the range, create a new unit that's
    // within the range.
    const unsigned clamped_start = std::max(unit.DOMStart(), start_offset);
    const unsigned clamped_end = std::min(unit.DOMEnd(), end_offset);
    DCHECK_LE(clamped_start, clamped_end);
    const unsigned clamped_text_content_start =
        unit.ConvertDOMOffsetToTextContent(clamped_start);
    const unsigned clamped_text_content_end =
        unit.ConvertDOMOffsetToTextContent(clamped_end);
    result.emplace_back(unit.GetType(), unit.GetLayoutObject(), clamped_start,
                        clamped_end, clamped_text_content_start,
                        clamped_text_content_end);
  }
  return result;
}

base::span<const OffsetMappingUnit> OffsetMapping::GetMappingUnitsForNode(
    const Node& node) const {
  const auto it = ranges_.find(&node);
  if (it == ranges_.end()) {
    return {};
  }
  return base::make_span(units_.begin() + it->value.first,
                         units_.begin() + it->value.second);
}

base::span<const OffsetMappingUnit>
OffsetMapping::GetMappingUnitsForLayoutObject(
    const LayoutObject& layout_object) const {
  const auto begin = base::ranges::find(units_, layout_object,
                                        &OffsetMappingUnit::GetLayoutObject);
  CHECK_NE(begin, units_.end());
  const auto end =
      std::find_if(std::next(begin), units_.end(),
                   [&layout_object](const OffsetMappingUnit& unit) {
                     return unit.GetLayoutObject() != layout_object;
                   });
  DCHECK_LT(begin, end);
  return base::make_span(begin, end);
}

base::span<const OffsetMappingUnit>
OffsetMapping::GetMappingUnitsForTextContentOffsetRange(unsigned start,
                                                        unsigned end) const {
  DCHECK_LE(start, end);
  if (units_.front().TextContentStart() >= end ||
      units_.back().TextContentEnd() <= start)
    return {};

  // Find the first unit where unit.text_content_end > start
  auto result_begin =
      std::lower_bound(units_.begin(), units_.end(), start,
                       [](const OffsetMappingUnit& unit, unsigned offset) {
                         return unit.TextContentEnd() <= offset;
                       });
  if (result_begin == units_.end() || result_begin->TextContentStart() >= end)
    return {};

  // Find the next of the last unit where unit.text_content_start < end
  auto result_end =
      std::upper_bound(units_.begin(), units_.end(), end,
                       [](unsigned offset, const OffsetMappingUnit& unit) {
                         return offset <= unit.TextContentStart();
                       });
  return base::make_span(result_begin, result_end);
}

std::optional<unsigned> OffsetMapping::GetTextContentOffset(
    const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position)) << position;
  const OffsetMappingUnit* unit = GetMappingUnitForPosition(position);
  if (!unit)
    return std::nullopt;
  return unit->ConvertDOMOffsetToTextContent(ToNodeOffsetPair(position).second);
}

Position OffsetMapping::StartOfNextNonCollapsedContent(
    const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position)) << position;
  const OffsetMappingUnit* unit = GetMappingUnitForPosition(position);
  if (!unit)
    return Position();

  const auto node_and_offset = ToNodeOffsetPair(position);
  const Node& node = node_and_offset.first;
  const unsigned offset = node_and_offset.second;
  while (unit != units_.data() + units_.size() &&
         unit->AssociatedNode() == node) {
    if (unit->DOMEnd() > offset &&
        unit->GetType() != OffsetMappingUnitType::kCollapsed) {
      const unsigned result = std::max(offset, unit->DOMStart());
      return CreatePositionForOffsetMapping(node, result);
    }
    ++unit;
  }
  return Position();
}

Position OffsetMapping::EndOfLastNonCollapsedContent(
    const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position)) << position;
  const OffsetMappingUnit* unit = GetMappingUnitForPosition(position);
  if (!unit)
    return Position();

  const auto node_and_offset = ToNodeOffsetPair(position);
  const Node& node = node_and_offset.first;
  const unsigned offset = node_and_offset.second;
  while (unit->AssociatedNode() == node) {
    if (unit->DOMStart() < offset &&
        unit->GetType() != OffsetMappingUnitType::kCollapsed) {
      const unsigned result = std::min(offset, unit->DOMEnd());
      return CreatePositionForOffsetMapping(node, result);
    }
    if (unit == units_.data()) {
      break;
    }
    --unit;
  }
  return Position();
}

bool OffsetMapping::IsBeforeNonCollapsedContent(
    const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position));
  const OffsetMappingUnit* unit = GetMappingUnitForPosition(position);
  const unsigned offset = ToNodeOffsetPair(position).second;
  return unit && offset < unit->DOMEnd() &&
         unit->GetType() != OffsetMappingUnitType::kCollapsed;
}

bool OffsetMapping::IsAfterNonCollapsedContent(const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position));
  const auto node_and_offset = ToNodeOffsetPair(position);
  const Node& node = node_and_offset.first;
  const unsigned offset = node_and_offset.second;
  if (!offset)
    return false;
  // In case we have one unit ending at |offset| and another starting at
  // |offset|, we need to find the former. Hence, search with |offset - 1|.
  const OffsetMappingUnit* unit = GetMappingUnitForPosition(
      CreatePositionForOffsetMapping(node, offset - 1));
  return unit && offset > unit->DOMStart() &&
         unit->GetType() != OffsetMappingUnitType::kCollapsed;
}

std::optional<UChar> OffsetMapping::GetCharacterBefore(
    const Position& position) const {
  DCHECK(OffsetMapping::AcceptsPosition(position));
  std::optional<unsigned> text_content_offset = GetTextContentOffset(position);
  if (!text_content_offset || !*text_content_offset)
    return std::nullopt;
  return text_[*text_content_offset - 1];
}

Position OffsetMapping::GetFirstPosition(unsigned offset) const {
  // Find the first unit where |unit.TextContentEnd() >= offset|
  if (units_.empty() || units_.back().TextContentEnd() < offset)
    return {};
  auto result =
      std::lower_bound(units_.begin(), units_.end(), offset,
                       [](const OffsetMappingUnit& unit, unsigned offset) {
                         return unit.TextContentEnd() < offset;
                       });
  CHECK_NE(result, units_.end());
  // Skip CSS generated content, e.g. "content" property in ::before/::after.
  while (!result->AssociatedNode()) {
    result = std::next(result);
    if (result == units_.end() || result->TextContentStart() > offset)
      return {};
  }
  const Node& node = result->GetOwner();
  const unsigned dom_offset =
      result->ConvertTextContentToFirstDOMOffset(offset);
  return CreatePositionForOffsetMapping(node, dom_offset);
}

const OffsetMappingUnit* OffsetMapping::GetFirstMappingUnit(
    unsigned offset) const {
  // Find the first unit where |unit.TextContentEnd() <= offset|
  if (units_.empty() || units_.front().TextContentStart() > offset)
    return nullptr;
  auto result =
      std::lower_bound(units_.begin(), units_.end(), offset,
                       [](const OffsetMappingUnit& unit, unsigned offset) {
                         return unit.TextContentEnd() < offset;
                       });
  if (result == units_.end())
    return nullptr;
  auto next_unit = std::next(result);
  if (next_unit != units_.end() && next_unit->TextContentStart() == offset) {
    // For offset=2, returns [1] instead of [0].
    // For offset=3, returns [3] instead of [2],
    // in below example:
    //  text_content = "ab\ncd"
    //  offset mapping unit:
    //   [0] I DOM:0-2 TC:0-2 "ab"
    //   [1] C DOM:2-3 TC:2-2
    //   [2] I DOM:3-4 TC:2-3 "\n"
    //   [3] C DOM:4-5 TC:3-3
    //   [4] I DOM:5-7 TC:3-5 "cd"
    return &*next_unit;
  }
  return &*result;
}

const OffsetMappingUnit* OffsetMapping::GetLastMappingUnit(
    unsigned offset) const {
  // Find the last unit where |unit.TextContentStart() <= offset|
  if (units_.empty() || units_.front().TextContentStart() > offset)
    return nullptr;
  auto result =
      std::upper_bound(units_.begin(), units_.end(), offset,
                       [](unsigned offset, const OffsetMappingUnit& unit) {
                         return offset < unit.TextContentStart();
                       });
  CHECK_NE(result, units_.begin());
  result = std::prev(result);
  if (result->TextContentEnd() < offset)
    return nullptr;
  return &*result;
}

Position OffsetMapping::GetLastPosition(unsigned offset) const {
  const OffsetMappingUnit* result = GetLastMappingUnit(offset);
  if (!result)
    return {};
  // Skip CSS generated content, e.g. "content" property in ::before/::after.
  while (!result->AssociatedNode()) {
    if (result == units_.data()) {
      return {};
    }
    result = std::prev(result);
    if (result->TextContentEnd() < offset)
      return {};
  }
  const Node& node = result->GetOwner();
  const unsigned dom_offset = result->ConvertTextContentToLastDOMOffset(offset);
  return CreatePositionForOffsetMapping(node, dom_offset);
}

bool OffsetMapping::HasBidiControlCharactersOnly(unsigned start,
                                                 unsigned end) const {
  DCHECK_LE(start, end);
  DCHECK_LE(end, text_.length());
  for (unsigned i = start; i < end; ++i) {
    if (!Character::IsBidiControl(text_[i]))
      return false;
  }
  return true;
}

unsigned OffsetMapping::LayoutObjectConverter::TextContentOffset(
    unsigned offset) const {
  auto iter = offset >= last_offset_ ? last_unit_ : units_.begin();
  if (offset >= iter->DOMEnd()) {
    iter = base::ranges::find_if(
        iter, units_.end(), [offset](const OffsetMappingUnit& unit) {
          return unit.DOMStart() <= offset && offset < unit.DOMEnd();
        });
  }
  CHECK(iter != units_.end());
  last_unit_ = iter;
  last_offset_ = offset;
  return iter->ConvertDOMOffsetToTextContent(offset);
}

void OffsetMappingUnit::Trace(Visitor* visitor) const {
  visitor->Trace(layout_object_);
}

}  // namespace blink
```
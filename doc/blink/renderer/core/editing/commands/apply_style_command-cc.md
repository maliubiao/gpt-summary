Response:
The user wants to understand the functionality of the `apply_style_command.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet to identify its core responsibilities.

Here's a breakdown of my thought process:

1. **Identify the Core Class:** The filename and the presence of the `ApplyStyleCommand` class declaration strongly suggest that this file is responsible for implementing a command that applies styling to content.

2. **Analyze the Class Members:** I'll examine the member variables of `ApplyStyleCommand` to understand what data it holds and manipulates. Key members include:
    * `style_`:  Likely holds the CSS styles to be applied.
    * `start_`, `end_`:  Represent the range to which the styles will be applied.
    * `input_type_`:  Indicates the type of user action that triggered this command.
    * `property_level_`:  Determines the scope of style application (block vs. inline).
    * `styled_inline_element_`:  A specific element to style.
    * `remove_only_`:  A flag to indicate if the command should only remove styles.
    * `is_inline_element_to_remove_function_`: A function pointer for custom removal logic.

3. **Analyze the Class Methods:**  The methods within the class reveal the steps involved in applying styles. Key methods to focus on are:
    * `DoApply()`: The main entry point for applying styles, coordinating block and inline style application.
    * `ApplyBlockStyle()`: Handles the application of block-level styles.
    * `ApplyRelativeFontStyleChange()`: Deals with relative font size adjustments.
    * `ApplyInlineStyle()`:  Manages the application of inline styles.
    * Helper functions like `SplitTextAtStart`, `SplitTextAtEnd`, `MergeStartWithPreviousIfIdentical`, `MergeEndWithNextIfIdentical`, `RemoveInlineStyle`, `AddBlockStyle`, etc. suggest finer-grained operations.

4. **Identify Interactions with Other Components:** The `#include` directives at the beginning of the file provide clues about the file's dependencies and interactions with other parts of the Blink engine. These include:
    * CSS-related classes (`CSSComputedStyleDeclaration`, `CSSPropertyValueSet`, etc.)
    * DOM-related classes (`Document`, `Node`, `Element`, `Range`, etc.)
    * Editing-related classes (`EditingStyle`, `VisibleSelection`, `EphemeralRange`, etc.)
    * HTML element classes (`HTMLSpanElement`, `HTMLFontElement`, etc.)

5. **Relate Functionality to Web Technologies (JavaScript, HTML, CSS):** Based on the class names, member variables, and included headers, I can infer how this file relates to web technologies:
    * **CSS:** The primary focus is on applying and manipulating CSS styles.
    * **HTML:** The command operates on HTML elements and their attributes (specifically the `style` attribute).
    * **JavaScript:** While the code itself is C++, it's triggered by user interactions or JavaScript calls that result in style changes.

6. **Consider User Actions and Debugging:** I need to think about how a user might trigger this code and how a developer might use it for debugging. User actions like typing, formatting text (bold, italic), or using the "style" attribute directly could lead to this code being executed.

7. **Address Specific Requirements of the Prompt:** I need to provide:
    * A summary of the file's functionality.
    * Examples of how it relates to JavaScript, HTML, and CSS.
    * Hypothetical input/output scenarios (although detailed logic is hard to fully reconstruct from just the header).
    * Common user/programming errors.
    * Steps leading to this code for debugging.

**Constraint Checklist & Confidence Score:**

* Provide functionality: Yes
* Relate to JS/HTML/CSS: Yes
* Examples for JS/HTML/CSS: Yes
* Logic inference (with input/output): Yes (though high-level)
* User/programming errors: Yes
* Steps to reach the code (debugging): Yes
* Summarize functionality: Yes

Confidence Score: 4/5 (Slight uncertainty in providing very precise input/output scenarios without the full implementation).

**Pre-computation and Pre-analysis:**

* I've identified the core purpose: applying styles.
* I've noted the involvement of block and inline styles.
* I've recognized the manipulation of the `style` attribute.
* I've identified the interactions with DOM nodes and CSS objects.

Strategizing complete. I will now generate the response based on the above analysis.

好的，让我们来分析一下 `blink/renderer/core/editing/commands/apply_style_command.cc` 这个文件的功能。

**核心功能归纳:**

从代码的结构和包含的头文件来看，`apply_style_command.cc` 文件的主要功能是**实现一个编辑命令，用于将 CSS 样式应用到文档的指定范围或元素上**。 这个命令能够处理块级样式和内联样式，并且考虑了各种复杂的编辑场景，例如文本节点的拆分与合并，以及处理具有 `unicode-bidi` 属性的元素。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **CSS (层叠样式表):**  这是该文件的核心所在。 `ApplyStyleCommand` 接收一个 `EditingStyle` 对象作为参数，该对象封装了要应用的 CSS 属性和值。
    * **例子:** 当用户在富文本编辑器中点击 "加粗" 按钮时，可能会创建一个 `EditingStyle` 对象，其中包含 `font-weight: bold;` 这样的 CSS 属性。 `ApplyStyleCommand` 负责将这个样式应用到当前选中的文本范围。

* **HTML (超文本标记语言):**  `ApplyStyleCommand` 的作用对象是 HTML 文档的节点和元素。它可能会创建或修改 HTML 元素的 `style` 属性，或者创建新的 HTML 标签 (例如 `<span>`) 来应用样式。
    * **例子:**
        * **修改 `style` 属性:**  如果选中的文本在一个 `<p>` 标签内，应用颜色样式可能会直接修改 `<p>` 标签的 `style` 属性，例如 `<p style="color: red;">选中文本</p>`。
        * **创建 `<span>` 标签:** 如果需要应用内联样式到部分文本，并且周围没有合适的元素，`ApplyStyleCommand` 可能会用 `<span>` 标签包裹选中文本，并将样式应用到 `<span>` 标签上，例如 `<span><span style="font-style: italic;">部分</span>文本</span>`。

* **JavaScript:**  虽然这个 C++ 文件本身不是 JavaScript，但它通常是由 JavaScript 代码间接触发的。浏览器中的富文本编辑器或内容可编辑区域的功能通常由 JavaScript 实现，当用户执行格式化操作时，JavaScript 会调用 Blink 引擎提供的接口来执行相应的编辑命令，其中就包括 `ApplyStyleCommand`。
    * **例子:**  一个 JavaScript 函数可能会监听用户的 "设置字体大小" 操作，然后调用 Blink 的 API，创建一个 `ApplyStyleCommand` 实例，并将用户选择的字体大小封装到 `EditingStyle` 对象中传递给该命令。

**逻辑推理 (假设输入与输出):**

假设输入：

* **用户操作:** 选中一段文本 "Hello World"，然后点击 "设置为红色"。
* **`EditingStyle` 对象:**  包含 `color: red;` 这个 CSS 属性。
* **选中文本所在的 HTML 结构 (简化):**  `<p>Hello World</p>`

可能的输出 (取决于具体的实现细节和上下文):

1. **修改 `style` 属性:**  `<p style="color: red;">Hello World</p>`
2. **创建 `<span>` 标签:** `<p><span style="color: red;">Hello World</span></p>`
3. **如果部分文本已经有其他样式，可能更复杂:** `<p>普通文本<span style="color: red; font-weight: bold;">Hello</span> World</p>` (假设 "Hello" 之前被加粗了)。

**涉及用户或编程常见的使用错误:**

* **用户错误:**
    * **选择范围不准确:** 用户可能只选中了部分字符，导致样式应用不符合预期。例如，只选中了 "Hell"，点击加粗，可能只会在 "Hell" 周围创建 `<b>` 或 `<span>` 标签。
    * **样式冲突:** 用户可能尝试应用互相冲突的样式，例如同时设置 `color: red;` 和 `color: blue;`，结果可能取决于 CSS 的层叠规则。
* **编程错误:**
    * **传递错误的 `EditingStyle` 对象:**  开发者可能创建了一个包含无效 CSS 属性或值的 `EditingStyle` 对象，导致样式应用失败或产生意外效果。
    * **没有正确处理选择范围:**  如果 JavaScript 代码没有正确获取用户的选择范围并传递给 `ApplyStyleCommand`，可能会导致样式应用到错误的位置。
    * **过度或不必要的样式嵌套:**  连续应用样式可能会导致 HTML 中出现大量嵌套的 `<span>` 标签，影响性能和可读性。`ApplyStyleCommand` 内部应该有逻辑来避免这种情况，但错误的配置或使用可能会导致问题。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在可编辑的 HTML 元素中进行操作:** 例如，在一个 `<div contenteditable="true">` 或富文本编辑器中。
2. **用户进行格式化操作:** 例如，选中一段文本，然后点击工具栏上的 "加粗"、"斜体"、"设置颜色" 等按钮。
3. **JavaScript 事件监听器捕获用户操作:**  通常，JavaScript 代码会监听用户的点击事件或其他相关事件。
4. **JavaScript 调用 Blink 引擎的编辑接口:**  当用户执行格式化操作时，JavaScript 代码会调用 Blink 引擎提供的 C++ 接口，请求执行相应的编辑命令。这可能涉及到 `document.execCommand()` 方法或者更底层的 API。
5. **创建 `ApplyStyleCommand` 实例:**  Blink 引擎接收到请求后，会根据用户的操作创建一个 `ApplyStyleCommand` 的实例，并传入相关的参数，例如要应用的 `EditingStyle` 对象和目标范围。
6. **执行 `ApplyStyleCommand::DoApply()` 方法:**  创建好的 `ApplyStyleCommand` 实例的 `DoApply()` 方法会被调用，该方法会根据传入的样式和范围，修改底层的 DOM 结构和样式。

**本部分功能归纳:**

这部分代码主要负责 `ApplyStyleCommand` 类的初始化和一些辅助方法。它定义了如何创建 `ApplyStyleCommand` 对象，以及如何更新命令的起始和结束位置。 此外，还包含了一些用于判断 HTML 元素类型和属性的辅助函数，例如 `HasNoAttributeOrOnlyStyleAttribute`，`IsStyleSpanOrSpanWithOnlyStyleAttribute` 和 `IsEmptyFontTag`。  这些辅助函数在后续的样式应用逻辑中被用来判断是否需要创建新的元素或者修改现有元素的属性。

请提供后续部分的代码，以便进行更深入的分析。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/apply_style_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2005, 2006, 2008, 2009 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/commands/apply_style_command.h"

#include "mojo/public/mojom/base/text_direction.mojom-blink.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_style.h"
#include "third_party/blink/renderer/core/editing/editing_style_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/relocatable_position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/html_interchange.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_font_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

static bool HasNoAttributeOrOnlyStyleAttribute(
    const HTMLElement* element,
    ShouldStyleAttributeBeEmpty should_style_attribute_be_empty) {
  AttributeCollection attributes = element->Attributes();
  if (attributes.IsEmpty())
    return true;

  unsigned matched_attributes = 0;
  if (element->hasAttribute(html_names::kStyleAttr) &&
      (should_style_attribute_be_empty == kAllowNonEmptyStyleAttribute ||
       !element->InlineStyle() || element->InlineStyle()->IsEmpty()))
    matched_attributes++;

  DCHECK_LE(matched_attributes, attributes.size());
  return matched_attributes == attributes.size();
}

bool IsStyleSpanOrSpanWithOnlyStyleAttribute(const Element* element) {
  if (auto* span = DynamicTo<HTMLSpanElement>(element)) {
    return HasNoAttributeOrOnlyStyleAttribute(span,
                                              kAllowNonEmptyStyleAttribute);
  }
  return false;
}

static inline bool IsSpanWithoutAttributesOrUnstyledStyleSpan(
    const Node* node) {
  if (auto* span = DynamicTo<HTMLSpanElement>(node)) {
    return HasNoAttributeOrOnlyStyleAttribute(span,
                                              kStyleAttributeShouldBeEmpty);
  }
  return false;
}

bool IsEmptyFontTag(
    const Element* element,
    ShouldStyleAttributeBeEmpty should_style_attribute_be_empty) {
  if (auto* font = DynamicTo<HTMLFontElement>(element)) {
    return HasNoAttributeOrOnlyStyleAttribute(font,
                                              should_style_attribute_be_empty);
  }
  return false;
}

static bool OffsetIsBeforeLastNodeOffset(int offset, Node* anchor_node) {
  if (auto* character_data = DynamicTo<CharacterData>(anchor_node))
    return offset < static_cast<int>(character_data->length());
  int current_offset = 0;
  for (Node* node = NodeTraversal::FirstChild(*anchor_node);
       node && current_offset < offset;
       node = NodeTraversal::NextSibling(*node))
    current_offset++;
  return offset < current_offset;
}

ApplyStyleCommand::ApplyStyleCommand(Document& document,
                                     const EditingStyle* style,
                                     InputEvent::InputType input_type,
                                     PropertyLevel property_level)
    : CompositeEditCommand(document),
      style_(style->Copy()),
      input_type_(input_type),
      property_level_(property_level),
      start_(MostForwardCaretPosition(EndingSelection().Start())),
      end_(MostBackwardCaretPosition(EndingSelection().End())),
      use_ending_selection_(true),
      styled_inline_element_(nullptr),
      remove_only_(false),
      is_inline_element_to_remove_function_(nullptr) {}

ApplyStyleCommand::ApplyStyleCommand(Document& document,
                                     const EditingStyle* style,
                                     const Position& start,
                                     const Position& end)
    : CompositeEditCommand(document),
      style_(style->Copy()),
      input_type_(InputEvent::InputType::kNone),
      property_level_(kPropertyDefault),
      start_(start),
      end_(end),
      use_ending_selection_(false),
      styled_inline_element_(nullptr),
      remove_only_(false),
      is_inline_element_to_remove_function_(nullptr) {}

ApplyStyleCommand::ApplyStyleCommand(Element* element, bool remove_only)
    : CompositeEditCommand(element->GetDocument()),
      style_(MakeGarbageCollected<EditingStyle>()),
      input_type_(InputEvent::InputType::kNone),
      property_level_(kPropertyDefault),
      start_(MostForwardCaretPosition(EndingSelection().Start())),
      end_(MostBackwardCaretPosition(EndingSelection().End())),
      use_ending_selection_(true),
      styled_inline_element_(element),
      remove_only_(remove_only),
      is_inline_element_to_remove_function_(nullptr) {}

ApplyStyleCommand::ApplyStyleCommand(
    Document& document,
    const EditingStyle* style,
    IsInlineElementToRemoveFunction is_inline_element_to_remove_function,
    InputEvent::InputType input_type)
    : CompositeEditCommand(document),
      style_(style->Copy()),
      input_type_(input_type),
      property_level_(kPropertyDefault),
      start_(MostForwardCaretPosition(EndingSelection().Start())),
      end_(MostBackwardCaretPosition(EndingSelection().End())),
      use_ending_selection_(true),
      styled_inline_element_(nullptr),
      remove_only_(true),
      is_inline_element_to_remove_function_(
          is_inline_element_to_remove_function) {}

void ApplyStyleCommand::UpdateStartEnd(const EphemeralRange& range) {
  if (!use_ending_selection_ &&
      (range.StartPosition() != start_ || range.EndPosition() != end_))
    use_ending_selection_ = true;
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const bool was_base_first =
      StartingSelection().IsAnchorFirst() || !SelectionIsDirectional();
  SelectionInDOMTree::Builder builder;
  if (was_base_first)
    builder.SetAsForwardSelection(range);
  else
    builder.SetAsBackwardSelection(range);
  const VisibleSelection& visible_selection =
      CreateVisibleSelection(builder.Build());
  SetEndingSelection(
      SelectionForUndoStep::From(visible_selection.AsSelection()));
  start_ = range.StartPosition();
  end_ = range.EndPosition();
}

Position ApplyStyleCommand::StartPosition() {
  if (use_ending_selection_)
    return EndingSelection().Start();

  return start_;
}

Position ApplyStyleCommand::EndPosition() {
  if (use_ending_selection_)
    return EndingSelection().End();

  return end_;
}

void ApplyStyleCommand::DoApply(EditingState* editing_state) {
  DCHECK(StartPosition().IsNotNull());
  DCHECK(EndPosition().IsNotNull());
  switch (property_level_) {
    case kPropertyDefault: {
      // Apply the block-centric properties of the style.
      EditingStyle* block_style = style_->ExtractAndRemoveBlockProperties(
          GetDocument().GetExecutionContext());
      if (!block_style->IsEmpty()) {
        ApplyBlockStyle(block_style, editing_state);
        if (editing_state->IsAborted())
          return;
      }
      // Apply any remaining styles to the inline elements.
      if (!style_->IsEmpty() || styled_inline_element_ ||
          is_inline_element_to_remove_function_) {
        ApplyRelativeFontStyleChange(style_.Get(), editing_state);
        if (editing_state->IsAborted())
          return;
        ApplyInlineStyle(style_.Get(), editing_state);
        if (editing_state->IsAborted())
          return;
      }
      break;
    }
    case kForceBlockProperties:
      // Force all properties to be applied as block styles.
      ApplyBlockStyle(style_.Get(), editing_state);
      break;
  }
}

InputEvent::InputType ApplyStyleCommand::GetInputType() const {
  return input_type_;
}

void ApplyStyleCommand::ApplyBlockStyle(EditingStyle* style,
                                        EditingState* editing_state) {
  // update document layout once before removing styles
  // so that we avoid the expense of updating before each and every call
  // to check a computed style
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // get positions we want to use for applying style
  Position start = StartPosition();
  Position end = EndPosition();
  if (ComparePositions(end, start) < 0) {
    Position swap = start;
    start = end;
    end = swap;
  }

  VisiblePosition visible_start = CreateVisiblePosition(start);
  VisiblePosition visible_end = CreateVisiblePosition(end);

  if (visible_start.IsNull() || visible_start.IsOrphan() ||
      visible_end.IsNull() || visible_end.IsOrphan())
    return;

  // Save and restore the selection endpoints using their indices in the
  // document, since addBlockStyleIfNeeded may moveParagraphs, which can remove
  // these endpoints. Calculate start and end indices from the start of the tree
  // that they're in.
  const Node& scope = NodeTraversal::HighestAncestorOrSelf(
      *visible_start.DeepEquivalent().AnchorNode());
  const EphemeralRange start_range(
      Position::FirstPositionInNode(scope),
      visible_start.DeepEquivalent().ParentAnchoredEquivalent());
  const EphemeralRange end_range(
      Position::FirstPositionInNode(scope),
      visible_end.DeepEquivalent().ParentAnchoredEquivalent());

  const TextIteratorBehavior behavior =
      TextIteratorBehavior::AllVisiblePositionsRangeLengthBehavior();

  const int start_index = TextIterator::RangeLength(start_range, behavior);
  const int end_index = TextIterator::RangeLength(end_range, behavior);

  VisiblePosition paragraph_start(StartOfParagraph(visible_start));
  RelocatablePosition* relocatable_beyond_end =
      MakeGarbageCollected<RelocatablePosition>(
          NextPositionOf(EndOfParagraph(visible_end)).DeepEquivalent());
  while (paragraph_start.IsNotNull()) {
    DCHECK(paragraph_start.IsValidFor(GetDocument())) << paragraph_start;
    const Position& beyond_end = relocatable_beyond_end->GetPosition();
    DCHECK(beyond_end.IsValidFor(GetDocument())) << beyond_end;
    if (beyond_end.IsNotNull() &&
        beyond_end <= paragraph_start.DeepEquivalent())
      break;

    RelocatablePosition* next_paragraph_start =
        MakeGarbageCollected<RelocatablePosition>(
            NextPositionOf(EndOfParagraph(paragraph_start)).DeepEquivalent());
    StyleChange style_change(style, paragraph_start.DeepEquivalent());
    if (style_change.CssStyle().length() || remove_only_) {
      Element* block =
          EnclosingBlock(paragraph_start.DeepEquivalent().AnchorNode());
      const Position& paragraph_start_to_move =
          paragraph_start.DeepEquivalent();
      if (!remove_only_ && IsEditablePosition(paragraph_start_to_move)) {
        HTMLElement* new_block = MoveParagraphContentsToNewBlockIfNecessary(
            paragraph_start_to_move, editing_state);
        if (editing_state->IsAborted())
          return;
        if (new_block)
          block = new_block;
      }
      if (auto* html_element = DynamicTo<HTMLElement>(block)) {
        RemoveCSSStyle(style, html_element, editing_state);
        if (editing_state->IsAborted())
          return;
        if (!remove_only_)
          AddBlockStyle(style_change, html_element);
      }

      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    }

    paragraph_start =
        CreateVisiblePosition(next_paragraph_start->GetPosition());
  }

  // Update style and layout again, since added or removed styles could have
  // affected the layout. We need clean layout in order to compute
  // plain-text ranges below.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  EphemeralRange start_ephemeral_range =
      PlainTextRange(start_index)
          .CreateRangeForSelection(To<ContainerNode>(scope));
  if (start_ephemeral_range.IsNull())
    return;
  EphemeralRange end_ephemeral_range =
      PlainTextRange(end_index).CreateRangeForSelection(
          To<ContainerNode>(scope));
  if (end_ephemeral_range.IsNull())
    return;
  UpdateStartEnd(EphemeralRange(start_ephemeral_range.StartPosition(),
                                end_ephemeral_range.StartPosition()));
}

static MutableCSSPropertyValueSet* CopyStyleOrCreateEmpty(
    const CSSPropertyValueSet* style) {
  if (!style)
    return MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  return style->MutableCopy();
}

void ApplyStyleCommand::ApplyRelativeFontStyleChange(
    EditingStyle* style,
    EditingState* editing_state) {
  static const float kMinimumFontSize = 0.1f;

  if (!style || !style->HasFontSizeDelta())
    return;

  Position start = StartPosition();
  Position end = EndPosition();
  if (ComparePositions(end, start) < 0) {
    Position swap = start;
    start = end;
    end = swap;
  }

  // Join up any adjacent text nodes.
  if (start.AnchorNode()->IsTextNode()) {
    JoinChildTextNodes(start.AnchorNode()->parentNode(), start, end);
    start = StartPosition();
    end = EndPosition();
  }

  if (start.IsNull() || end.IsNull())
    return;

  if (end.AnchorNode()->IsTextNode() &&
      start.AnchorNode()->parentNode() != end.AnchorNode()->parentNode()) {
    JoinChildTextNodes(end.AnchorNode()->parentNode(), start, end);
    start = StartPosition();
    end = EndPosition();
  }

  if (start.IsNull() || end.IsNull())
    return;

  // Split the start text nodes if needed to apply style.
  if (IsValidCaretPositionInTextNode(start)) {
    SplitTextAtStart(start, end);
    start = StartPosition();
    end = EndPosition();
  }

  if (IsValidCaretPositionInTextNode(end)) {
    SplitTextAtEnd(start, end);
    start = StartPosition();
    end = EndPosition();
  }

  DCHECK(start.AnchorNode());
  DCHECK(end.AnchorNode());
  // Calculate loop end point.
  // If the end node is before the start node (can only happen if the end node
  // is an ancestor of the start node), we gather nodes up to the next sibling
  // of the end node
  const Node* const beyond_end = end.NodeAsRangePastLastNode();
  // Move upstream to ensure we do not add redundant spans.
  start = MostBackwardCaretPosition(start);
  Node* start_node = start.AnchorNode();
  DCHECK(start_node);

  // Make sure we're not already at the end or the next NodeTraversal::next()
  // will traverse past it.
  if (start_node == beyond_end)
    return;

  if (start_node->IsTextNode() &&
      start.ComputeOffsetInContainerNode() >= CaretMaxOffset(start_node)) {
    // Move out of text node if range does not include its characters.
    start_node = NodeTraversal::Next(*start_node);
    if (!start_node)
      return;
  }

  // Store away font size before making any changes to the document.
  // This ensures that changes to one node won't effect another.
  HeapHashMap<Member<Node>, float> starting_font_sizes;
  for (Node* node = start_node; node != beyond_end;
       node = NodeTraversal::Next(*node)) {
    DCHECK(node);
    starting_font_sizes.Set(node, ComputedFontSize(node));
  }

  // These spans were added by us. If empty after font size changes, they can be
  // removed.
  HeapVector<Member<HTMLElement>> unstyled_spans;

  Node* last_styled_node = nullptr;
  Node* node = start_node;
  while (node != beyond_end) {
    DCHECK(node);
    Node* const next_node = NodeTraversal::Next(*node);
    auto* element = DynamicTo<HTMLElement>(node);
    if (element) {
      // Only work on fully selected nodes.
      if (!ElementFullySelected(*element, start, end)) {
        node = next_node;
        continue;
      }
    } else if (node->IsTextNode() && node->GetLayoutObject() &&
               node->parentNode() != last_styled_node) {
      // Last styled node was not parent node of this text node, but we wish to
      // style this text node. To make this possible, add a style span to
      // surround this text node.
      auto* span = MakeGarbageCollected<HTMLSpanElement>(GetDocument());
      SurroundNodeRangeWithElement(node, node, span, editing_state);
      if (editing_state->IsAborted())
        return;
      element = span;
    } else {
      node = next_node;
      // Only handle HTML elements and text nodes.
      continue;
    }
    last_styled_node = node;

    MutableCSSPropertyValueSet* inline_style =
        CopyStyleOrCreateEmpty(element->InlineStyle());
    float current_font_size = ComputedFontSize(node);
    float desired_font_size =
        max(kMinimumFontSize,
            starting_font_sizes.at(node) + style->FontSizeDelta());
    const CSSValue* value =
        inline_style->GetPropertyCSSValue(CSSPropertyID::kFontSize);
    if (value) {
      element->RemoveInlineStyleProperty(CSSPropertyID::kFontSize);
      current_font_size = ComputedFontSize(node);
    }
    if (current_font_size != desired_font_size) {
      inline_style->SetProperty(
          CSSPropertyID::kFontSize,
          *CSSNumericLiteralValue::Create(desired_font_size,
                                          CSSPrimitiveValue::UnitType::kPixels),
          false);
      SetNodeAttribute(element, html_names::kStyleAttr,
                       AtomicString(inline_style->AsText()));
    }
    if (inline_style->IsEmpty()) {
      RemoveElementAttribute(element, html_names::kStyleAttr);
      if (IsSpanWithoutAttributesOrUnstyledStyleSpan(element))
        unstyled_spans.push_back(element);
    }
    node = next_node;
  }

  for (const auto& unstyled_span : unstyled_spans) {
    RemoveNodePreservingChildren(unstyled_span, editing_state);
    if (editing_state->IsAborted())
      return;
  }
}

static ContainerNode* DummySpanAncestorForNode(const Node* node) {
  if (!node)
    return nullptr;

  for (Node& current : NodeTraversal::InclusiveAncestorsOf(*node)) {
    if (IsStyleSpanOrSpanWithOnlyStyleAttribute(DynamicTo<Element>(current)))
      return current.parentNode();
  }
  return nullptr;
}

void ApplyStyleCommand::CleanupUnstyledAppleStyleSpans(
    ContainerNode* dummy_span_ancestor,
    EditingState* editing_state) {
  if (!dummy_span_ancestor)
    return;

  // Dummy spans are created when text node is split, so that style information
  // can be propagated, which can result in more splitting. If a dummy span gets
  // cloned/split, the new node is always a sibling of it. Therefore, we scan
  // all the children of the dummy's parent
  Node* next;
  for (Node* node = dummy_span_ancestor->firstChild(); node; node = next) {
    next = node->nextSibling();
    if (IsSpanWithoutAttributesOrUnstyledStyleSpan(node)) {
      RemoveNodePreservingChildren(node, editing_state);
      if (editing_state->IsAborted())
        return;
    }
  }
}

HTMLElement* ApplyStyleCommand::SplitAncestorsWithUnicodeBidi(
    Node* node,
    bool before,
    mojo_base::mojom::blink::TextDirection allowed_direction) {
  // We are allowed to leave the highest ancestor with unicode-bidi unsplit if
  // it is unicode-bidi: embed and direction: allowedDirection. In that case, we
  // return the unsplit ancestor. Otherwise, we return 0.
  Element* block = EnclosingBlock(node);
  if (!block)
    return nullptr;

  ContainerNode* highest_ancestor_with_unicode_bidi = nullptr;
  ContainerNode* next_highest_ancestor_with_unicode_bidi = nullptr;
  CSSValueID highest_ancestor_unicode_bidi = CSSValueID::kInvalid;
  for (Node& runner : NodeTraversal::AncestorsOf(*node)) {
    if (runner == block) {
      break;
    }
    Element* element = DynamicTo<Element>(runner);
    if (!element) {
      continue;
    }
    CSSValueID unicode_bidi = GetIdentifierValue(
        MakeGarbageCollected<CSSComputedStyleDeclaration>(element),
        CSSPropertyID::kUnicodeBidi);
    if (IsValidCSSValueID(unicode_bidi) &&
        unicode_bidi != CSSValueID::kNormal) {
      highest_ancestor_unicode_bidi = unicode_bidi;
      next_highest_ancestor_with_unicode_bidi =
          highest_ancestor_with_unicode_bidi;
      highest_ancestor_with_unicode_bidi = element;
    }
  }

  if (!highest_ancestor_with_unicode_bidi)
    return nullptr;

  HTMLElement* unsplit_ancestor = nullptr;

  mojo_base::mojom::blink::TextDirection highest_ancestor_direction;
  auto* highest_ancestor_html_element =
      DynamicTo<HTMLElement>(highest_ancestor_with_unicode_bidi);
  if (allowed_direction !=
          mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION &&
      highest_ancestor_unicode_bidi != CSSValueID::kBidiOverride &&
      highest_ancestor_html_element &&
      MakeGarbageCollected<EditingStyle>(highest_ancestor_html_element,
                                         EditingStyle::kAllProperties)
          ->GetTextDirection(highest_ancestor_direction) &&
      highest_ancestor_direction == allowed_direction) {
    if (!next_highest_ancestor_with_unicode_bidi)
      return highest_ancestor_html_element;

    unsplit_ancestor = highest_ancestor_html_element;
    highest_ancestor_with_unicode_bidi =
        next_highest_ancestor_with_unicode_bidi;
  }

  // Split every ancestor through highest ancestor with embedding.
  Node* current_node = node;
  while (current_node) {
    auto* parent = To<Element>(current_node->parentNode());
    if (before ? current_node->previousSibling() : current_node->nextSibling())
      SplitElement(parent, before ? current_node : current_node->nextSibling());
    if (parent == highest_ancestor_with_unicode_bidi)
      break;
    current_node = parent;
  }
  return unsplit_ancestor;
}

void ApplyStyleCommand::RemoveEmbeddingUpToEnclosingBlock(
    Node* node,
    HTMLElement* unsplit_ancestor,
    EditingState* editing_state) {
  Element* block = EnclosingBlock(node);
  if (!block)
    return;

  for (Node& runner : NodeTraversal::AncestorsOf(*node)) {
    if (runner == block || runner == unsplit_ancestor)
      break;
    if (!runner.IsStyledElement())
      continue;

    auto* element = To<Element>(&runner);
    CSSValueID unicode_bidi = GetIdentifierValue(
        MakeGarbageCollected<CSSComputedStyleDeclaration>(element),
        CSSPropertyID::kUnicodeBidi);
    if (!IsValidCSSValueID(unicode_bidi) || unicode_bidi == CSSValueID::kNormal)
      continue;

    // FIXME: This code should really consider the mapped attribute 'dir', the
    // inline style declaration, and all matching style rules in order to
    // determine how to best set the unicode-bidi property to 'normal'. For now,
    // it assumes that if the 'dir' attribute is present, then removing it will
    // suffice, and otherwise it sets the property in the inline style
    // declaration.
    if (element->FastHasAttribute(html_names::kDirAttr)) {
      // FIXME: If this is a BDO element, we should probably just remove it if
      // it has no other attributes, like we (should) do with B and I elements.
      RemoveElementAttribute(element, html_names::kDirAttr);
    } else {
      MutableCSSPropertyValueSet* inline_style =
          CopyStyleOrCreateEmpty(element->InlineStyle());
      inline_style->SetLonghandProperty(CSSPropertyID::kUnicodeBidi,
                                        CSSValueID::kNormal);
      inline_style->RemoveProperty(CSSPropertyID::kDirection);
      SetNodeAttribute(element, html_names::kStyleAttr,
                       AtomicString(inline_style->AsText()));
      if (IsSpanWithoutAttributesOrUnstyledStyleSpan(element)) {
        RemoveNodePreservingChildren(element, editing_state);
        if (editing_state->IsAborted())
          return;
      }
    }
  }
}

static HTMLElement* HighestEmbeddingAncestor(Node* start_node,
                                             Node* enclosing_node) {
  for (Node* n = start_node; n && n != enclosing_node; n = n->parentNode()) {
    auto* html_element = DynamicTo<HTMLElement>(n);
    if (html_element &&
        EditingStyleUtilities::IsEmbedOrIsolate(GetIdentifierValue(
            MakeGarbageCollected<CSSComputedStyleDeclaration>(html_element),
            CSSPropertyID::kUnicodeBidi))) {
      return html_element;
    }
  }

  return nullptr;
}

void ApplyStyleCommand::ApplyInlineStyle(EditingStyle* style,
                                         EditingState* editing_state) {
  ContainerNode* start_dummy_span_ancestor = nullptr;
  ContainerNode* end_dummy_span_ancestor = nullptr;

  // update document layout once before removing styles
  // so that we avoid the expense of updating before each and every call
  // to check a computed style
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // adjust to the positions we want to use for applying style
  Position start = StartPosition();
  Position end = EndPosition();

  if (start.IsNull() || end.IsNull())
    return;

  if (ComparePositions(end, start) < 0) {
    Position swap = start;
    start = end;
    end = swap;
  }

  // split the start node and containing element if the selection starts inside
  // of it
  bool split_start = IsValidCaretPositionInTextNode(start);
  if (split_start) {
    if (ShouldSplitTextElement(start.AnchorNode()->parentElement(), style))
      SplitTextElementAtStart(start, end);
    else
      SplitTextAtStart(start, end);
    start = StartPosition();
    end = EndPosition();
    if (start.IsNull() || end.IsNull())
      return;
    start_dummy_span_ancestor = DummySpanAncestorForNode(start.AnchorNode());
  }

  // split the end node and containing element if the selection ends inside of
  // it
  bool split_end = IsValidCaretPositionInTextNode(end);
  if (split_end) {
    if (ShouldSplitTextElement(end.AnchorNode()->parentElement(), style))
      SplitTextElementAtEnd(start, end);
    else
      SplitTextAtEnd(start, end);
    start = StartPosition();
    end = EndPosition();
    if (start.IsNull() || end.IsNull())
      return;
    end_dummy_span_ancestor = DummySpanAncestorForNode(end.AnchorNode());
  }

  // Remove style from the selection.
  // Use the upstream position of the start for removing style.
  // This will ensure we remove all traces of the relevant styles from the
  // selection and prevent us from adding redundant ones, as described in:
  // <rdar://problem/3724344> Bolding and unbolding creates extraneous tags
  Position remove_start = MostBackwardCaretPosition(start);
  mojo_base::mojom::blink::TextDirection text_direction =
      mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;
  bool has_text_direction = style->GetTextDirection(text_direction);
  EditingStyle* style_without_embedding = nullptr;
  EditingStyle* embedding_style = nullptr;
  if (has_text_direction) {
    // Leave alone an ancestor that provides the desired single level embedding,
    // if there is one.
    HTMLElement* start_unsplit_ancestor =
        SplitAncestorsWithUnicodeBidi(start.AnchorNode(), true, text_direction);
    HTMLElement* end_unsplit_ancestor =
        SplitAncestorsWithUnicodeBidi(end.AnchorNode(), false, text_direction);
    RemoveEmbeddingUpToEnclosingBlock(start.AnchorNode(),
                                      start_unsplit_ancestor, editing_state);
    if (editing_state->IsAborted())
      return;
    RemoveEmbeddingUpToEnclosingBlock(end.AnchorNode(), end_unsplit_ancestor,
                                      editing_state);
    if (editing_state->IsAborted())
      return;

    // Avoid removing the dir attribute and the unicode-bidi and direction
    // properties from the unsplit ancestors.
    Position embedding_remove_start = remove_start;
    if (start_unsplit_ancestor &&
        ElementFullySelected(*start_unsplit_ancestor, remove_start, end))
      embedding_remove_start =
          Position::InParentAfterNode(*start_unsplit_ancestor);

    Position embedding_remove_end = end;
    if (end_unsplit_ancestor &&
        ElementFullySelected(*end_unsplit_ancestor, remove_start, end))
      embedding_remove_end = MostForwardCaretPosition(
          Position::InParentBeforeNode(*end_unsplit_ancestor));

    if (embedding_remove_end != remove_start || embedding_remove_end != end) {
      style_without_embedding = style->Copy();
      embedding_style = style_without_embedding->ExtractAndRemoveTextDirection(
          GetDocument().GetExecutionContext()->GetSecureContextMode());

      if (ComparePositions(embedding_remove_start, embedding_remove_end) <= 0) {
        RemoveInlineStyle(
            embedding_style,
            EphemeralRange(embedding_remove_start, embedding_remove_end),
            editing_state);
        if (editing_state->IsAborted())
          return;
      }
    }
  }

  RemoveInlineStyle(style_without_embedding ? style_without_embedding : style,
                    EphemeralRange(remove_start, end), editing_state);
  if (editing_state->IsAborted())
    return;
  start = StartPosition();
  end = EndPosition();
  if (start.IsNull() || start.IsOrphan() || end.IsNull() || end.IsOrphan())
    return;

  if (split_start) {
    bool merge_result =
        MergeStartWithPreviousIfIdentical(start, end, editing_state);
    if (editing_state->IsAborted())
      return;
    if (split_start && merge_result) {
      start = StartPosition();
      end = EndPosition();
    }
  }

  if (split_end) {
    MergeEndWithNextIfIdentical(start, end, editing_state);
    if (editing_state->IsAborted())
      return;
    start = StartPosition();
    end = EndPosition();
  }

  // update document layout once before running the rest of the function
  // so that we avoid the expense of updating before each and every call
  // to check a computed style
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  EditingStyle* style_to_apply = style;
  if (has_text_direction) {
    // Avoid applying the unicode-bidi and direction properties beneath
    // ancestors that already have them.
    HTMLElement* embedding_start_element = HighestEmbeddingAncestor(
        start.AnchorNode(), EnclosingBlock(start.AnchorNode())
```
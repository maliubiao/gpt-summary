Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Request:** The request asks for the *functionality* of the given C++ code, its relation to web technologies (JavaScript, HTML, CSS), examples, logical reasoning with input/output, common user/programming errors, debugging tips, and finally, a summary of its functionality. The "part 1 of 3" indicates this is an ongoing analysis.

2. **Initial Scan and Identify Key Classes:** The first step is to quickly scan the `#include` directives and the namespace declaration (`namespace blink`). This immediately reveals the core class being examined: `ReplaceSelectionCommand`. Other important classes and concepts emerge from the includes:
    * **DOM manipulation:** `Document`, `DocumentFragment`, `Element`, `Text`, etc.
    * **CSS:** `CSSStyleDeclaration`, `CSSPropertyValueSet`.
    * **Editing:**  `EditingStyle`, `VisibleSelection`, `EphemeralRange`, various `...Command` classes (like `ApplyStyleCommand`, `DeleteSelectionOptions`).
    * **Events:** `BeforeTextInsertedEvent`.
    * **HTML elements:**  Numerous specific HTML element classes (`HTMLInputElement`, `HTMLBodyElement`, etc.).

3. **Focus on the Main Class (`ReplaceSelectionCommand`):** The core task seems to be related to replacing a selection within a document. The constructor and member variables provide clues:
    * `document_fragment_`: Stores the content to be inserted.
    * `options`:  Flags like `kSelectReplacement`, `kSmartReplace`, `kMatchStyle`, etc., suggest different modes of operation.
    * `input_type_`:  Indicates the type of input (paste, drop, etc.).

4. **Analyze Helper Classes and Functions:**
    * **`ReplacementFragment`:**  This appears to be a crucial helper class for preparing the replacement content. Its constructor takes a `DocumentFragment` and a `VisibleSelection`, suggesting it handles the input. Methods like `RemoveInterchangeNodes`, `InsertFragmentForTestRendering`, and `RemoveUnrenderedNodes` indicate preprocessing and cleaning of the fragment. The "interchange newline" concept is important here, suggesting handling of content copied from other applications.
    * **`IsInterchangeHTMLBRElement`:**  A utility function to identify special `<br>` tags used for inter-application content transfer.
    * **`PositionAvoidingPrecedingNodes`:**  A function to adjust a `Position` object, likely for edge cases related to line breaks and block elements.
    * **`InsertedNodes`:** A simple struct to keep track of the first and last inserted nodes, useful for subsequent processing.
    * Several `ShouldMerge...` functions: These suggest logic for intelligently merging content at the boundaries of the insertion.

5. **Infer Functionality Based on Method Names and Logic:**  Go through the methods of `ReplaceSelectionCommand` and `ReplacementFragment`, trying to understand their purpose:
    * `TextDataForInputEvent()`:  Related to providing data for input events, particularly for paste/drop.
    * `ShouldMergeStart/End()`:  Determine if the inserted content should be merged with the surrounding content.
    * `RemoveRedundantStylesAndKeepStyleSpanInline()`:  Clean up styles after insertion.
    * `MakeInsertedContentRoundTrippableWithHTMLTreeBuilder()`:  Adjust the inserted content to ensure it can be correctly parsed if it were to be serialized and re-parsed.
    * `MoveElementOutOfAncestor()`:  A helper for `MakeInsertedContentRoundTrippableWithHTMLTreeBuilder()`, likely dealing with nesting issues.
    * `RemoveUnrenderedTextNodesAtEnds()`: Removes empty or whitespace-only text nodes.

6. **Connect to Web Technologies:**
    * **JavaScript:** The command is likely triggered by JavaScript events related to user actions like typing, pasting, or dragging and dropping. The `BeforeTextInsertedEvent` is a clear link to JavaScript event handling.
    * **HTML:** The code directly manipulates the HTML DOM, creating and modifying elements. The inclusion of specific HTML tag names is a strong indicator.
    * **CSS:** The code interacts with CSS styles, both inline styles and stylesheets, through classes like `CSSStyleDeclaration` and functions like `RemoveRedundantStylesAndKeepStyleSpanInline`.

7. **Formulate Examples:** Based on the identified functionality, create concrete examples illustrating the code's behavior. Focus on the interactions between JavaScript, HTML, and CSS.

8. **Logical Reasoning (Input/Output):**  Choose a specific scenario (e.g., pasting text) and describe the expected input (the selected content, the pasted content) and the output (the modified DOM).

9. **Identify Potential Errors:** Think about common mistakes users or programmers might make that would lead to issues with this code. Pasting malformed HTML or relying on specific browser behavior are good examples.

10. **Debugging Clues:** Consider how a developer would trace the execution to reach this code. User actions and the corresponding JavaScript events are key here.

11. **Summarize Functionality for Part 1:** Based on the analysis of the first part of the code, provide a concise summary of its main purpose. Emphasize the preparation and initial processing of the replacement fragment.

12. **Iterative Refinement:**  After the initial analysis, review the code and the generated explanation. Are there any ambiguities?  Can the explanations be clearer?  Are the examples relevant?  This iterative process helps to improve the accuracy and clarity of the analysis. For instance, the initial thought might be simply "replaces the selection," but further analysis reveals the nuances of handling different input types, style matching, and content sanitization. The "interchange newline" handling is a specific detail worth highlighting.
好的，让我们来分析一下 `blink/renderer/core/editing/commands/replace_selection_command.cc` 文件的功能。

从提供的代码片段来看，这个文件定义了一个名为 `ReplaceSelectionCommand` 的类，它继承自 `CompositeEditCommand`。这个命令的主要作用是**替换当前选中的内容**。

以下是根据代码内容推断出的更具体的功能点：

**主要功能:**

1. **替换选区内容:** 这是该命令的核心功能。它接收一个 `DocumentFragment` 作为要插入的内容，并将其替换掉当前文档中的选区。
2. **处理不同类型的替换:** 通过 `CommandOptions` 参数，该命令支持多种替换模式，例如：
    *   `kSelectReplacement`:  替换后选中新插入的内容。
    *   `kSmartReplace`:  进行智能替换，可能涉及保留周围的空格或标点符号。
    *   `kMatchStyle`:  尝试使插入的内容样式与周围内容匹配。
    *   `kPreventNesting`: 防止在某些情况下进行嵌套插入。
    *   `kMovingParagraph`:  指示正在移动段落。
    *   `kSanitizeFragment`:  对要插入的 `DocumentFragment` 进行清理。
3. **处理剪贴板内容:**  代码中涉及到 `AppleInterchangeNewline` 的处理，这表明该命令可能用于处理从其他应用程序（特别是 Apple 的应用程序）复制粘贴过来的内容，需要识别并处理特殊的换行符。
4. **文本预处理:**  在插入内容之前，可能会触发 `webkitBeforeTextInserted` 事件，允许 JavaScript 代码修改要插入的文本内容。
5. **样式处理:**  代码中有 `RemoveRedundantStylesAndKeepStyleSpanInline` 函数，说明该命令会处理插入内容的样式，去除冗余样式，并可能将某些样式属性保留在 `<span>` 标签上。
6. **处理富文本和纯文本:**  代码区分了富文本编辑和纯文本编辑的情况，对于纯文本编辑，插入的内容会进行特殊处理。
7. **处理不可渲染的节点:**  代码中包含 `RemoveUnrenderedNodes` 函数，表明该命令会移除插入内容中不可渲染的节点。
8. **处理插入位置的合并:**  `ShouldMergeStart` 和 `ShouldMergeEnd` 函数表明，该命令会判断插入的内容是否应该与插入位置的前后内容进行合并，例如合并相邻的段落或列表项。
9. **确保插入内容的HTML结构合法:**  `MakeInsertedContentRoundTrippableWithHTMLTreeBuilder` 函数表明，该命令会调整插入的内容，以确保它能被 HTML 解析器正确解析，避免出现嵌套错误等问题。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**
    *   `webkitBeforeTextInserted` 事件：JavaScript 可以监听这个事件，并在内容插入之前修改文本内容。
    *   该命令通常由 JavaScript 代码触发，例如响应用户的输入、粘贴操作或拖放操作。
    *   例如，用户在一个可编辑的 `<div>` 中选中一段文字，然后按下键盘上的某个字符，JavaScript 可能会调用这个命令来替换选中的内容。

*   **HTML:**
    *   该命令直接操作 HTML 结构，创建、删除、修改 HTML 元素和文本节点。
    *   例如，插入一段包含 `<b>` 和 `<i>` 标签的文本，或者插入一个 `<div>` 元素。
    *   代码中大量引用了 HTML 元素的类名，例如 `HTMLBRElement`, `HTMLInputElement`, `HTMLSpanElement` 等。

*   **CSS:**
    *   该命令会处理插入内容的 CSS 样式。
    *   `kMatchStyle` 选项指示命令尝试匹配周围内容的样式。
    *   `RemoveRedundantStylesAndKeepStyleSpanInline` 函数涉及到对 CSS 属性的处理。
    *   例如，用户在一个设置了特定字体颜色的段落中粘贴一段文本，`kMatchStyle` 可能会让粘贴的文本也继承该颜色。

**逻辑推理 (假设输入与输出):**

**假设输入:**

*   **当前选区:**  文档中一段包含文本 "old text" 的 `<span>` 元素。
*   **要替换的内容 (fragment):**  一个包含文本 "new text" 的 `DocumentFragment`。
*   **CommandOptions:**  设置为 `kSelectReplacement`。

**输出:**

*   文档中的 "old text" `<span>` 元素被移除。
*   在原来选区的位置插入了一个包含 "new text" 的文本节点（或者可能是一个包含 "new text" 的 `<span>` 元素，取决于具体的实现细节）。
*   插入的 "new text" 被选中。

**用户或编程常见的使用错误:**

1. **尝试在非可编辑区域执行替换:**  如果用户的选择位于一个 `contenteditable="false"` 的元素内，该命令可能不会执行或产生意外结果。
2. **传递不合法的 `DocumentFragment`:**  如果传递的 `DocumentFragment` 结构不正确或包含不允许的元素，可能会导致渲染错误或命令执行失败。
3. **过度依赖 `kMatchStyle`:**  `kMatchStyle` 可能会尝试应用复杂的样式匹配逻辑，在某些情况下可能无法得到预期的结果，或者可能导致性能问题。
4. **没有正确处理 `webkitBeforeTextInserted` 事件:**  如果 JavaScript 代码错误地修改了要插入的文本，可能会导致插入的内容与预期不符。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户进行文本选择:** 用户在浏览器中通过鼠标拖拽或键盘操作选中了一段文本。
2. **用户触发替换操作:** 用户可能进行了以下操作之一：
    *   **输入文本:** 用户在选区存在的情况下直接开始输入字符。
    *   **粘贴内容:** 用户按下 `Ctrl+V` (或 `Cmd+V`) 粘贴了剪贴板中的内容。
    *   **拖放内容:** 用户将一段文本或 HTML 内容拖放到选区上。
    *   **使用 JavaScript API:**  JavaScript 代码调用了与内容编辑相关的 API，例如 `document.execCommand('insertText', ...)` 或 `document.execCommand('paste', ...)`。
3. **浏览器引擎处理用户操作:** 浏览器引擎识别到用户的编辑操作。
4. **触发相应的编辑命令:**  浏览器引擎根据用户操作和当前上下文，决定执行 `ReplaceSelectionCommand`。
5. **创建 `ReplaceSelectionCommand` 实例:**  引擎会创建一个 `ReplaceSelectionCommand` 对象，并将相关的参数（例如要插入的 `DocumentFragment`、`CommandOptions` 等）传递给它。
6. **执行 `ReplaceSelectionCommand`:**  `ReplaceSelectionCommand` 的 `DoApply` 或相关方法会被调用，开始执行替换选区内容的操作。

**归纳一下它的功能 (第1部分):**

这份代码是 Chromium Blink 引擎中用于实现**替换选区内容**功能的关键部分。它定义了 `ReplaceSelectionCommand` 类，该类负责接收要插入的内容，并根据不同的选项和上下文，智能地替换掉当前用户选中的内容。 这个部分的代码主要关注于 **`ReplacementFragment` 辅助类的定义和 `ReplaceSelectionCommand` 的基本构造和一些预处理逻辑**，例如处理剪贴板的特殊换行符，以及判断是否需要合并插入位置的开头部分。它为后续的实际插入和样式处理奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/replace_selection_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2005, 2006, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2009, 2010, 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/commands/replace_selection_command.h"

#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/apply_style_command.h"
#include "third_party/blink/renderer/core/editing/commands/break_blockquote_command.h"
#include "third_party/blink/renderer/core/editing/commands/delete_selection_options.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/commands/simplify_markup_command.h"
#include "third_party/blink/renderer/core/editing/commands/smart_replace.h"
#include "third_party/blink/renderer/core/editing/editing_style.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/html_interchange.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/events/before_text_inserted_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_base_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_quote_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_title_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

using mojom::blink::FormControlType;

// --- ReplacementFragment helper class

class ReplacementFragment final {
  STACK_ALLOCATED();

 public:
  ReplacementFragment(Document*, DocumentFragment*, const VisibleSelection&);
  ReplacementFragment(const ReplacementFragment&) = delete;
  ReplacementFragment& operator=(const ReplacementFragment&) = delete;

  Node* FirstChild() const;
  Node* LastChild() const;

  bool IsEmpty() const;

  bool HasInterchangeNewlineAtStart() const {
    return has_interchange_newline_at_start_;
  }
  bool HasInterchangeNewlineAtEnd() const {
    return has_interchange_newline_at_end_;
  }

  void RemoveNode(Node*);
  void RemoveNodePreservingChildren(ContainerNode*);

 private:
  HTMLElement* InsertFragmentForTestRendering(Element* root_editable_element);
  void RemoveUnrenderedNodes(ContainerNode*);
  void RestoreAndRemoveTestRenderingNodesToFragment(Element*);
  void RemoveInterchangeNodes(ContainerNode*);

  void InsertNodeBefore(Node*, Node* ref_node);

  Document* document_;
  DocumentFragment* fragment_;
  bool has_interchange_newline_at_start_;
  bool has_interchange_newline_at_end_;
};

static bool IsInterchangeHTMLBRElement(const Node* node) {
  DEFINE_STATIC_LOCAL(String, interchange_newline_class_string,
                      (AppleInterchangeNewline));
  auto* html_br_element = DynamicTo<HTMLBRElement>(node);
  if (!html_br_element ||
      html_br_element->getAttribute(html_names::kClassAttr) !=
          interchange_newline_class_string)
    return false;
  UseCounter::Count(node->GetDocument(),
                    WebFeature::kEditingAppleInterchangeNewline);
  return true;
}

static Position PositionAvoidingPrecedingNodes(Position pos) {
  // If we're already on a break, it's probably a placeholder and we shouldn't
  // change our position.
  if (EditingIgnoresContent(*pos.AnchorNode()))
    return pos;

  // We also stop when changing block flow elements because even though the
  // visual position is the same.  E.g.,
  //   <div>foo^</div>^
  // The two positions above are the same visual position, but we want to stay
  // in the same block.
  Element* enclosing_block_element = EnclosingBlock(pos.ComputeContainerNode());
  for (Position next_position = pos;
       next_position.ComputeContainerNode() != enclosing_block_element;
       pos = next_position) {
    if (LineBreakExistsAtPosition(pos))
      break;

    if (pos.ComputeContainerNode()->NonShadowBoundaryParentNode())
      next_position = Position::InParentAfterNode(*pos.ComputeContainerNode());

    if (next_position == pos ||
        EnclosingBlock(next_position.ComputeContainerNode()) !=
            enclosing_block_element ||
        CreateVisiblePosition(pos).DeepEquivalent() !=
            CreateVisiblePosition(next_position).DeepEquivalent())
      break;
  }
  return pos;
}

ReplacementFragment::ReplacementFragment(Document* document,
                                         DocumentFragment* fragment,
                                         const VisibleSelection& selection)
    : document_(document),
      fragment_(fragment),
      has_interchange_newline_at_start_(false),
      has_interchange_newline_at_end_(false) {
  if (!document_)
    return;
  if (!fragment_ || !fragment_->HasChildren())
    return;

  TRACE_EVENT0("blink", "ReplacementFragment constructor");
  Element* editable_root = selection.RootEditableElement();
  DCHECK(editable_root);
  if (!editable_root)
    return;

  document_->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  Element* shadow_ancestor_element;
  if (editable_root->IsInShadowTree())
    shadow_ancestor_element = editable_root->OwnerShadowHost();
  else
    shadow_ancestor_element = editable_root;

  if (!editable_root->GetAttributeEventListener(
          event_type_names::kWebkitBeforeTextInserted)
      // FIXME: Remove these checks once textareas and textfields actually
      // register an event handler.
      &&
      !(shadow_ancestor_element && shadow_ancestor_element->GetLayoutObject() &&
        shadow_ancestor_element->GetLayoutObject()->IsTextControl()) &&
      IsRichlyEditable(*editable_root)) {
    RemoveInterchangeNodes(fragment_);
    return;
  }

  if (!IsRichlyEditable(*editable_root)) {
    bool is_plain_text = true;
    for (Node& node : NodeTraversal::ChildrenOf(*fragment_)) {
      if (IsInterchangeHTMLBRElement(&node) && &node == fragment_->lastChild())
        continue;
      if (!node.IsTextNode()) {
        is_plain_text = false;
        break;
      }
    }
    // We don't need TestRendering for plain-text editing + plain-text
    // insertion.
    if (is_plain_text) {
      RemoveInterchangeNodes(fragment_);
      String original_text = fragment_->textContent();
      auto* event =
          MakeGarbageCollected<BeforeTextInsertedEvent>(original_text);
      editable_root->DefaultEventHandler(*event);
      if (original_text != event->GetText()) {
        fragment_ = CreateFragmentFromText(
            selection.ToNormalizedEphemeralRange(), event->GetText());
        RemoveInterchangeNodes(fragment_);
      }
      return;
    }
  }

  HTMLElement* holder = InsertFragmentForTestRendering(editable_root);
  if (!holder) {
    RemoveInterchangeNodes(fragment_);
    return;
  }

  const EphemeralRange range =
      CreateVisibleSelection(
          SelectionInDOMTree::Builder().SelectAllChildren(*holder).Build())
          .ToNormalizedEphemeralRange();
  const TextIteratorBehavior& behavior = TextIteratorBehavior::Builder()
                                             .SetEmitsOriginalText(true)
                                             .SetIgnoresStyleVisibility(true)
                                             .Build();
  const String& text = PlainText(range, behavior);

  RemoveInterchangeNodes(holder);
  RemoveUnrenderedNodes(holder);
  RestoreAndRemoveTestRenderingNodesToFragment(holder);

  // Give the root a chance to change the text.
  auto* evt = MakeGarbageCollected<BeforeTextInsertedEvent>(text);
  editable_root->DefaultEventHandler(*evt);
  if (text != evt->GetText() || !IsRichlyEditable(*editable_root)) {
    RestoreAndRemoveTestRenderingNodesToFragment(holder);

    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited.  See http://crbug.com/590369 for more details.
    document->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    fragment_ = CreateFragmentFromText(selection.ToNormalizedEphemeralRange(),
                                       evt->GetText());
    if (!fragment_->HasChildren())
      return;

    holder = InsertFragmentForTestRendering(editable_root);
    RemoveInterchangeNodes(holder);
    RemoveUnrenderedNodes(holder);
    RestoreAndRemoveTestRenderingNodesToFragment(holder);
  }
}

bool ReplacementFragment::IsEmpty() const {
  return (!fragment_ || !fragment_->HasChildren()) &&
         !has_interchange_newline_at_start_ && !has_interchange_newline_at_end_;
}

Node* ReplacementFragment::FirstChild() const {
  return fragment_ ? fragment_->firstChild() : nullptr;
}

Node* ReplacementFragment::LastChild() const {
  return fragment_ ? fragment_->lastChild() : nullptr;
}

void ReplacementFragment::RemoveNodePreservingChildren(ContainerNode* node) {
  if (!node)
    return;

  while (Node* n = node->firstChild()) {
    RemoveNode(n);
    InsertNodeBefore(n, node);
  }
  RemoveNode(node);
}

void ReplacementFragment::RemoveNode(Node* node) {
  if (!node)
    return;

  ContainerNode* parent = node->NonShadowBoundaryParentNode();
  if (!parent)
    return;

  parent->RemoveChild(node);
}

void ReplacementFragment::InsertNodeBefore(Node* node, Node* ref_node) {
  if (!node || !ref_node)
    return;

  ContainerNode* parent = ref_node->NonShadowBoundaryParentNode();
  if (!parent)
    return;

  parent->InsertBefore(node, ref_node);
}

HTMLElement* ReplacementFragment::InsertFragmentForTestRendering(
    Element* root_editable_element) {
  TRACE_EVENT0("blink", "ReplacementFragment::insertFragmentForTestRendering");
  DCHECK(document_);
  HTMLElement* holder = CreateDefaultParagraphElement(*document_);

  holder->AppendChild(fragment_);
  root_editable_element->AppendChild(holder);

  // TODO(editing-dev): Hoist this call to the call sites.
  document_->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  return holder;
}

void ReplacementFragment::RestoreAndRemoveTestRenderingNodesToFragment(
    Element* holder) {
  if (!holder)
    return;

  while (Node* node = holder->firstChild()) {
    holder->RemoveChild(node);
    fragment_->AppendChild(node);
  }

  RemoveNode(holder);
}

void ReplacementFragment::RemoveUnrenderedNodes(ContainerNode* holder) {
  HeapVector<Member<Node>> unrendered;

  for (Node& node : NodeTraversal::DescendantsOf(*holder)) {
    if (!IsNodeRendered(node) && !IsTableStructureNode(&node))
      unrendered.push_back(&node);
  }

  for (auto& node : unrendered)
    RemoveNode(node);
}

void ReplacementFragment::RemoveInterchangeNodes(ContainerNode* container) {
  has_interchange_newline_at_start_ = false;
  has_interchange_newline_at_end_ = false;

  // Interchange newlines at the "start" of the incoming fragment must be
  // either the first node in the fragment or the first leaf in the fragment.
  Node* node = container->firstChild();
  while (node) {
    if (IsInterchangeHTMLBRElement(node)) {
      has_interchange_newline_at_start_ = true;
      RemoveNode(node);
      break;
    }
    node = node->firstChild();
  }
  if (!container->HasChildren())
    return;
  // Interchange newlines at the "end" of the incoming fragment must be
  // either the last node in the fragment or the last leaf in the fragment.
  node = container->lastChild();
  while (node) {
    if (IsInterchangeHTMLBRElement(node)) {
      has_interchange_newline_at_end_ = true;
      RemoveNode(node);
      break;
    }
    node = node->lastChild();
  }
}

inline void ReplaceSelectionCommand::InsertedNodes::RespondToNodeInsertion(
    Node& node) {
  if (!first_node_inserted_)
    first_node_inserted_ = &node;

  last_node_inserted_ = &node;
}

inline void
ReplaceSelectionCommand::InsertedNodes::WillRemoveNodePreservingChildren(
    Node& node) {
  if (first_node_inserted_ == node)
    first_node_inserted_ = NodeTraversal::Next(node);
  if (last_node_inserted_ == node)
    last_node_inserted_ = node.lastChild()
                              ? node.lastChild()
                              : NodeTraversal::NextSkippingChildren(node);
  if (ref_node_ == node)
    ref_node_ = NodeTraversal::Next(node);
}

inline void ReplaceSelectionCommand::InsertedNodes::WillRemoveNode(Node& node) {
  if (first_node_inserted_ == node && last_node_inserted_ == node) {
    first_node_inserted_ = nullptr;
    last_node_inserted_ = nullptr;
  } else if (first_node_inserted_ == node) {
    first_node_inserted_ =
        NodeTraversal::NextSkippingChildren(*first_node_inserted_);
  } else if (last_node_inserted_ == node) {
    last_node_inserted_ =
        NodeTraversal::PreviousAbsoluteSibling(*last_node_inserted_);
  }
  if (node.contains(ref_node_))
    ref_node_ = NodeTraversal::NextSkippingChildren(node);
}

inline void ReplaceSelectionCommand::InsertedNodes::DidReplaceNode(
    Node& node,
    Node& new_node) {
  if (first_node_inserted_ == node)
    first_node_inserted_ = &new_node;
  if (last_node_inserted_ == node)
    last_node_inserted_ = &new_node;
  if (ref_node_ == node)
    ref_node_ = &new_node;
}

ReplaceSelectionCommand::ReplaceSelectionCommand(
    Document& document,
    DocumentFragment* fragment,
    CommandOptions options,
    InputEvent::InputType input_type)
    : CompositeEditCommand(document),
      select_replacement_(options & kSelectReplacement),
      smart_replace_(options & kSmartReplace),
      match_style_(options & kMatchStyle),
      document_fragment_(fragment),
      prevent_nesting_(options & kPreventNesting),
      moving_paragraph_(options & kMovingParagraph),
      input_type_(input_type),
      sanitize_fragment_(options & kSanitizeFragment),
      should_merge_end_(false) {}

String ReplaceSelectionCommand::TextDataForInputEvent() const {
  // As per spec https://www.w3.org/TR/input-events-1/#overview
  // input event data should be set for certain input types.
  if (RuntimeEnabledFeatures::NonNullInputEventDataForTextAreaEnabled() &&
      (input_type_ == InputEvent::InputType::kInsertFromDrop ||
       input_type_ == InputEvent::InputType::kInsertFromPaste ||
       input_type_ == InputEvent::InputType::kInsertReplacementText)) {
    return input_event_data_;
  }
  return g_null_atom;
}
static bool HasMatchingQuoteLevel(VisiblePosition end_of_existing_content,
                                  VisiblePosition end_of_inserted_content) {
  Position existing = end_of_existing_content.DeepEquivalent();
  Position inserted = end_of_inserted_content.DeepEquivalent();
  bool is_inside_mail_blockquote = EnclosingNodeOfType(
      inserted, IsMailHTMLBlockquoteElement, kCanCrossEditingBoundary);
  return is_inside_mail_blockquote && (NumEnclosingMailBlockquotes(existing) ==
                                       NumEnclosingMailBlockquotes(inserted));
}

bool ReplaceSelectionCommand::ShouldMergeStart(
    bool selection_start_was_start_of_paragraph,
    bool fragment_has_interchange_newline_at_start,
    bool selection_start_was_inside_mail_blockquote) {
  if (moving_paragraph_)
    return false;

  VisiblePosition start_of_inserted_content =
      PositionAtStartOfInsertedContent();
  VisiblePosition prev = PreviousPositionOf(start_of_inserted_content,
                                            kCannotCrossEditingBoundary);
  if (prev.IsNull())
    return false;

  // When we have matching quote levels, its ok to merge more frequently.
  // For a successful merge, we still need to make sure that the inserted
  // content starts with the beginning of a paragraph. And we should only merge
  // here if the selection start was inside a mail blockquote. This prevents
  // against removing a blockquote from newly pasted quoted content that was
  // pasted into an unquoted position. If that unquoted position happens to be
  // right after another blockquote, we don't want to merge and risk stripping a
  // valid block (and newline) from the pasted content.
  if (IsStartOfParagraph(start_of_inserted_content) &&
      selection_start_was_inside_mail_blockquote &&
      HasMatchingQuoteLevel(prev, PositionAtEndOfInsertedContent()))
    return true;

  return !selection_start_was_start_of_paragraph &&
         !fragment_has_interchange_newline_at_start &&
         IsStartOfParagraph(start_of_inserted_content) &&
         !IsA<HTMLBRElement>(
             *start_of_inserted_content.DeepEquivalent().AnchorNode()) &&
         ShouldMerge(start_of_inserted_content, prev);
}

bool ReplaceSelectionCommand::ShouldMergeEnd(
    bool selection_end_was_end_of_paragraph) {
  VisiblePosition end_of_inserted_content(PositionAtEndOfInsertedContent());
  VisiblePosition next =
      NextPositionOf(end_of_inserted_content, kCannotCrossEditingBoundary);
  if (next.IsNull())
    return false;

  return !selection_end_was_end_of_paragraph &&
         IsEndOfParagraph(end_of_inserted_content) &&
         !IsA<HTMLBRElement>(
             *end_of_inserted_content.DeepEquivalent().AnchorNode()) &&
         ShouldMerge(end_of_inserted_content, next);
}

static bool IsHTMLHeaderElement(const Node* a) {
  const auto* element = DynamicTo<HTMLElement>(a);
  if (!element)
    return false;

  return element->HasTagName(html_names::kH1Tag) ||
         element->HasTagName(html_names::kH2Tag) ||
         element->HasTagName(html_names::kH3Tag) ||
         element->HasTagName(html_names::kH4Tag) ||
         element->HasTagName(html_names::kH5Tag) ||
         element->HasTagName(html_names::kH6Tag);
}

static bool HaveSameTagName(Element* a, Element* b) {
  return a && b && a->tagName() == b->tagName();
}

bool ReplaceSelectionCommand::ShouldMerge(const VisiblePosition& source,
                                          const VisiblePosition& destination) {
  if (source.IsNull() || destination.IsNull())
    return false;

  Node* source_node = source.DeepEquivalent().AnchorNode();
  Node* destination_node = destination.DeepEquivalent().AnchorNode();
  Element* source_block = EnclosingBlock(source_node);
  Element* destination_block = EnclosingBlock(destination_node);
  return source_block &&
         (!source_block->HasTagName(html_names::kBlockquoteTag) ||
          IsMailHTMLBlockquoteElement(source_block)) &&
         EnclosingListChild(source_block) ==
             EnclosingListChild(destination_node) &&
         EnclosingTableCell(source.DeepEquivalent()) ==
             EnclosingTableCell(destination.DeepEquivalent()) &&
         (!IsHTMLHeaderElement(source_block) ||
          HaveSameTagName(source_block, destination_block))
         // Don't merge to or from a position before or after a block because it
         // would be a no-op and cause infinite recursion.
         && !IsEnclosingBlock(source_node) &&
         !IsEnclosingBlock(destination_node);
}

// Style rules that match just inserted elements could change their appearance,
// like a div inserted into a document with div { display:inline; }.
void ReplaceSelectionCommand::RemoveRedundantStylesAndKeepStyleSpanInline(
    InsertedNodes& inserted_nodes,
    EditingState* editing_state) {
  Node* past_end_node = inserted_nodes.PastLastLeaf();
  Node* next = nullptr;
  for (Node* node = inserted_nodes.FirstNodeInserted();
       node && node != past_end_node; node = next) {
    // FIXME: <rdar://problem/5371536> Style rules that match pasted content can
    // change it's appearance

    next = NodeTraversal::Next(*node);
    if (!node->IsStyledElement())
      continue;

    auto* element = To<Element>(node);

    const CSSPropertyValueSet* inline_style = element->InlineStyle();
    EditingStyle* new_inline_style =
        MakeGarbageCollected<EditingStyle>(inline_style);
    if (inline_style) {
      auto* html_element = DynamicTo<HTMLElement>(element);
      if (html_element) {
        Vector<QualifiedName> attributes;
        DCHECK(html_element);

        if (new_inline_style->ConflictsWithImplicitStyleOfElement(
                html_element)) {
          // e.g. <b style="font-weight: normal;"> is converted to <span
          // style="font-weight: normal;">
          element = ReplaceElementWithSpanPreservingChildrenAndAttributes(
              html_element);
          inline_style = element->InlineStyle();
          inserted_nodes.DidReplaceNode(*html_element, *element);
        } else if (new_inline_style
                       ->ExtractConflictingImplicitStyleOfAttributes(
                           html_element,
                           EditingStyle::kPreserveWritingDirection, nullptr,
                           attributes,
                           EditingStyle::kDoNotExtractMatchingStyle)) {
          // e.g. <font size="3" style="font-size: 20px;"> is converted to <font
          // style="font-size: 20px;">
          for (wtf_size_t i = 0; i < attributes.size(); i++)
            RemoveElementAttribute(html_element, attributes[i]);
        }
      }

      Element* context = element->parentElement();

      // If Mail wraps the fragment with a Paste as Quotation blockquote, or if
      // you're pasting into a quoted region, styles from blockquoteNode are
      // allowed to override those from the source document, see
      // <rdar://problem/4930986> and <rdar://problem/5089327>.
      auto* blockquote_element =
          !context
              ? To<HTMLQuoteElement>(context)
              : To<HTMLQuoteElement>(EnclosingNodeOfType(
                    Position::FirstPositionInNode(*context),
                    IsMailHTMLBlockquoteElement, kCanCrossEditingBoundary));

      // EditingStyle::removeStyleFromRulesAndContext() uses StyleResolver,
      // which requires clean style.
      // TODO(editing-dev): There is currently no way to update style without
      // updating layout. We might want to have updateLifcycleToStyleClean()
      // similar to FrameView::updateLifecylceToLayoutClean() in Document.
      GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

      if (blockquote_element)
        new_inline_style->RemoveStyleFromRulesAndContext(
            element, GetDocument().documentElement());

      new_inline_style->RemoveStyleFromRulesAndContext(element, context);
    }

    if (!inline_style || new_inline_style->IsEmpty()) {
      if (IsStyleSpanOrSpanWithOnlyStyleAttribute(element) ||
          IsEmptyFontTag(element, kAllowNonEmptyStyleAttribute)) {
        inserted_nodes.WillRemoveNodePreservingChildren(*element);
        RemoveNodePreservingChildren(element, editing_state);
        if (editing_state->IsAborted())
          return;
        continue;
      }
      RemoveElementAttribute(element, html_names::kStyleAttr);
    } else if (new_inline_style->Style()->PropertyCount() !=
               inline_style->PropertyCount()) {
      SetNodeAttribute(element, html_names::kStyleAttr,
                       AtomicString(new_inline_style->Style()->AsText()));
    }

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

    // FIXME: Tolerate differences in id, class, and style attributes.
    if (element->parentNode() && IsNonTableCellHTMLBlockElement(element) &&
        AreIdenticalElements(*element, *element->parentNode()) &&
        VisiblePosition::FirstPositionInNode(*element->parentNode())
                .DeepEquivalent() ==
            VisiblePosition::FirstPositionInNode(*element).DeepEquivalent() &&
        VisiblePosition::LastPositionInNode(*element->parentNode())
                .DeepEquivalent() ==
            VisiblePosition::LastPositionInNode(*element).DeepEquivalent()) {
      inserted_nodes.WillRemoveNodePreservingChildren(*element);
      RemoveNodePreservingChildren(element, editing_state);
      if (editing_state->IsAborted())
        return;
      continue;
    }

    if (element->parentNode() && IsRichlyEditable(*element->parentNode()) &&
        IsRichlyEditable(*element)) {
      RemoveElementAttribute(element, html_names::kContenteditableAttr);
    }
  }
}

static bool IsProhibitedParagraphChild(const AtomicString& name) {
  // https://dvcs.w3.org/hg/editing/raw-file/57abe6d3cb60/editing.html#prohibited-paragraph-child
  DEFINE_STATIC_LOCAL(
      HashSet<AtomicString>, elements,
      ({
          html_names::kAddressTag.LocalName(),
          html_names::kArticleTag.LocalName(),
          html_names::kAsideTag.LocalName(),
          html_names::kBlockquoteTag.LocalName(),
          html_names::kCaptionTag.LocalName(),
          html_names::kCenterTag.LocalName(),
          html_names::kColTag.LocalName(),
          html_names::kColgroupTag.LocalName(),
          html_names::kDdTag.LocalName(),
          html_names::kDetailsTag.LocalName(),
          html_names::kDirTag.LocalName(),
          html_names::kDivTag.LocalName(),
          html_names::kDlTag.LocalName(),
          html_names::kDtTag.LocalName(),
          html_names::kFieldsetTag.LocalName(),
          html_names::kFigcaptionTag.LocalName(),
          html_names::kFigureTag.LocalName(),
          html_names::kFooterTag.LocalName(),
          html_names::kFormTag.LocalName(),
          html_names::kH1Tag.LocalName(),
          html_names::kH2Tag.LocalName(),
          html_names::kH3Tag.LocalName(),
          html_names::kH4Tag.LocalName(),
          html_names::kH5Tag.LocalName(),
          html_names::kH6Tag.LocalName(),
          html_names::kHeaderTag.LocalName(),
          html_names::kHgroupTag.LocalName(),
          html_names::kHrTag.LocalName(),
          html_names::kLiTag.LocalName(),
          html_names::kListingTag.LocalName(),
          html_names::kMainTag.LocalName(),  // Missing in the specification.
          html_names::kMenuTag.LocalName(),
          html_names::kNavTag.LocalName(),
          html_names::kOlTag.LocalName(),
          html_names::kPTag.LocalName(),
          html_names::kPlaintextTag.LocalName(),
          html_names::kPreTag.LocalName(),
          html_names::kSectionTag.LocalName(),
          html_names::kSummaryTag.LocalName(),
          html_names::kTableTag.LocalName(),
          html_names::kTbodyTag.LocalName(),
          html_names::kTdTag.LocalName(),
          html_names::kTfootTag.LocalName(),
          html_names::kThTag.LocalName(),
          html_names::kTheadTag.LocalName(),
          html_names::kTrTag.LocalName(),
          html_names::kUlTag.LocalName(),
          html_names::kXmpTag.LocalName(),
      }));
  return elements.Contains(name);
}

void ReplaceSelectionCommand::
    MakeInsertedContentRoundTrippableWithHTMLTreeBuilder(
        const InsertedNodes& inserted_nodes,
        EditingState* editing_state) {
  Node* past_end_node = inserted_nodes.PastLastLeaf();
  Node* next = nullptr;
  for (Node* node = inserted_nodes.FirstNodeInserted();
       node && node != past_end_node; node = next) {
    next = NodeTraversal::Next(*node);

    auto* element = DynamicTo<HTMLElement>(node);
    if (!element)
      continue;
    // moveElementOutOfAncestor() in a previous iteration might have failed,
    // and |node| might have been detached from the document tree.
    if (!node->isConnected())
      continue;

    if (IsProhibitedParagraphChild(element->localName())) {
      if (HTMLElement* paragraph_element =
              To<HTMLElement>(EnclosingElementWithTag(
                  Position::InParentBeforeNode(*element), html_names::kPTag))) {
        MoveElementOutOfAncestor(element, paragraph_element, editing_state);
        if (editing_state->IsAborted())
          return;
      }
    }

    if (IsHTMLHeaderElement(element)) {
      if (auto* header_element = To<HTMLElement>(HighestEnclosingNodeOfType(
              Position::InParentBeforeNode(*element), IsHTMLHeaderElement))) {
        MoveElementOutOfAncestor(element, header_element, editing_state);
        if (editing_state->IsAborted())
          return;
      }
    }
  }
}

void ReplaceSelectionCommand::MoveElementOutOfAncestor(
    Element* element,
    Element* ancestor,
    EditingState* editing_state) {
  DCHECK(element);
  if (!IsEditable(*ancestor->parentNode()))
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  VisiblePosition position_at_end_of_node =
      CreateVisiblePosition(LastPositionInOrAfterNode(*element));
  VisiblePosition last_position_in_paragraph =
      VisiblePosition::LastPositionInNode(*ancestor);
  if (position_at_end_of_node.DeepEquivalent() ==
      last_position_in_paragraph.DeepEquivalent()) {
    RemoveNode(element, editing_state);
    if (editing_state->IsAborted())
      return;
    if (ancestor->nextSibling())
      InsertNodeBefore(element, ancestor->nextSibling(), editing_state);
    else
      AppendNode(element, ancestor->parentNode(), editing_state);
    if (editing_state->IsAborted())
      return;
  } else {
    Node* node_to_split_to = SplitTreeToNode(element, ancestor, true);
    RemoveNode(element, editing_state);
    if (editing_state->IsAborted())
      return;
    InsertNodeBefore(element, node_to_split_to, editing_state);
    if (editing_state->IsAborted())
      return;
  }
  if (!ancestor->HasChildren())
    RemoveNode(ancestor, editing_state);
}

static inline bool NodeHasVisibleLayoutText(Text& text) {
  return text.GetLayoutObject() &&
         text.GetLayoutObject()->ResolvedTextLength() > 0;
}

void ReplaceSelectionCommand::RemoveUnrenderedTextNodesAtEnds(
    InsertedNodes& insert
```
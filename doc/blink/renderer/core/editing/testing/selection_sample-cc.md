Response:
Let's break down the thought process for analyzing the `selection_sample.cc` file.

1. **Understand the Goal:** The core purpose of this file is evident from its name and location: it's a testing utility for selections within the Blink rendering engine. It aims to provide a way to represent and manipulate selections in a simplified string format for testing purposes.

2. **Identify Key Components:** Scan the file for prominent classes and functions. The presence of `Parser` and `Serializer` immediately suggests two core functionalities: converting a string representation *to* a selection object and converting a selection object *to* a string representation. The `SelectionSample` class acts as a facade providing the public interface.

3. **Analyze the `Parser`:**
    * **Input:**  A string like `"abc^def|ghi"` embedded within an HTML element's innerHTML.
    * **Output:** A `SelectionInDOMTree` object, which represents the start (anchor) and end (focus) points of the selection within the DOM.
    * **Mechanism:** The parser iterates through the text, looking for '^' (anchor) and '|' (focus) markers. It records the node and offset where these markers are found. It removes the markers from the text before setting it as innerHTML. It handles the case where a marker is the *only* content of a text node, removing the node entirely.
    * **Edge Cases/Assumptions:**
        * Only one '^' and one '|' are allowed.
        * The input string is well-formed according to the defined marker syntax.
        * The input is eventually placed within an HTML element for the parser to operate on.
        * Shadow DOM is handled through the `ConvertTemplatesToShadowRoots` function.

4. **Analyze the `Serializer`:**
    * **Input:** A DOM tree (or flat tree) and a `SelectionTemplate` object.
    * **Output:** A string representation of the DOM tree, including '^' and '|' markers indicating the selection.
    * **Mechanism:** The serializer recursively traverses the DOM tree. For each text node, it checks if the selection's anchor or focus points fall within that node. If so, it inserts the corresponding markers at the appropriate offsets. It also handles attributes and different node types (elements, comments, processing instructions).
    * **Edge Cases/Assumptions:**
        * The `SelectionTemplate` object accurately reflects the selection within the provided DOM tree.
        * Correctly handles different types of nodes and their serialization.
        * Attributes are sorted alphabetically in the output.

5. **Analyze `ConvertTemplatesToShadowRoots`:**  This function specifically deals with converting `<template data-mode="open">` elements into open shadow roots. This is important because shadow DOM affects how selections are calculated and represented.

6. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The input to the parser is HTML (inner HTML). The output of the serializer is a string representation of HTML structure with selection markers. The shadow DOM conversion directly manipulates the HTML DOM.
    * **CSS:** While CSS isn't directly manipulated by this code, the *effects* of CSS (layout, rendering) are relevant because selection behavior can be influenced by how elements are rendered. This code operates on the DOM structure *after* CSS has been applied.
    * **JavaScript:** JavaScript would be the typical way to interact with selections in a web page. This C++ code provides a low-level mechanism to *test* the selection logic that JavaScript APIs (like `window.getSelection()`) rely on.

7. **Identify Potential Errors:**  Consider how users or developers might misuse these utilities.
    * Incorrect marker usage in the input string (multiple '^' or '|').
    * Providing a selection object that doesn't actually correspond to the given DOM tree.
    * Misunderstanding the purpose and limitations of this testing utility.

8. **Trace User Operations (Debugging Clues):** Think about how a user's actions in a browser could lead to the execution of code that relies on these selection utilities (although the `selection_sample.cc` itself isn't directly executed during normal browsing).
    * Selecting text with the mouse or keyboard.
    * Using JavaScript to manipulate selections.
    * Performing operations that involve the selection, like copying, pasting, or applying formatting. The Blink engine would need to determine the exact boundaries of the selection for these operations.

9. **Structure the Answer:**  Organize the findings into logical sections based on the prompt's questions:
    * Functionality of the file.
    * Relationship to web technologies with examples.
    * Logical reasoning with input/output examples.
    * Common usage errors.
    * User operations leading to this code.

10. **Refine and Clarify:** Review the answer for clarity, accuracy, and completeness. Ensure that the explanations are easy to understand and provide sufficient detail without being overly technical. For instance, instead of just saying "DOM manipulation," explain *what kind* of DOM manipulation is happening (setting innerHTML, attaching shadow roots).

This systematic approach helps to dissect the code, understand its purpose, and connect it to broader concepts within the Blink rendering engine and web development. It involves understanding the data flow, the algorithms involved, and the context in which this code operates.
这个文件 `selection_sample.cc` 是 Chromium Blink 引擎中的一个测试辅助工具，专门用于处理和表示文本选择（selection）。它提供了一种便捷的方式来用文本字符串描述 DOM 结构以及其中的选择状态，并在 C++ 代码中将这种文本表示转换为实际的 `Selection` 对象，以及反过来将 `Selection` 对象转换为文本表示。

以下是它的主要功能：

**1. 将文本表示转换为 `Selection` 对象 (`SetSelectionText`)**

   - **功能：** 接收一个 HTML 元素的指针和一个包含特殊标记的字符串（例如，`^` 表示选择的起始位置，`|` 表示选择的结束位置或光标位置），将该字符串设置为元素的 `innerHTML`，并根据标记解析出 `Selection` 对象。
   - **与 JavaScript, HTML 的关系：**
     - **HTML:** 输入的字符串会被设置为 HTML 元素的 `innerHTML`，这意味着它直接操作了 DOM 结构。文件中的代码会解析这个 HTML 结构来定位选择的起始和结束节点。
     - **JavaScript:** 虽然这个 C++ 文件本身不直接与 JavaScript 交互，但它所创建和操作的 `Selection` 对象是 JavaScript 中 `window.getSelection()` API 的底层表示。这个工具使得在 C++ 测试中更容易模拟和验证 JavaScript 选择的行为。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**
       - `element`: 一个指向 `<div>` 元素的指针。
       - `selection_text`: `"abc^def|ghi"`
     - **处理过程:**
       1. `element` 的 `innerHTML` 被设置为 `"abc^def|ghi"`。
       2. 解析器找到 `^`，记录选择的起始位置在 "abc" 之后。
       3. 解析器找到 `|`，记录选择的结束位置在 "def" 之后。
     - **预期输出:** 一个 `SelectionInDOMTree` 对象，其锚点（anchor）位于 `element` 的第一个子文本节点（包含 "abcdefghi"）偏移量为 3 的位置，焦点（focus）位于同一个文本节点偏移量为 6 的位置。
   - **用户或编程常见的使用错误：**
     - **错误使用标记：** 例如，在字符串中使用了多个 `^` 或 `|`，导致解析器无法确定唯一的选择起始和结束位置。
     - **标记位置超出文本范围：** 例如，`"abc|"` 会将光标放在 "abc" 之后，这是合法的，但如果文本内容只有 "abc"，而标记在其他位置可能会导致错误或不期望的结果。

**2. 将 `Selection` 对象转换为文本表示 (`GetSelectionText`, `GetSelectionTextInFlatTree`)**

   - **功能：** 接收一个 DOM 树的根节点和一个 `Selection` 对象，生成一个包含特殊标记的字符串，表示该 DOM 树以及其中的选择状态。`GetSelectionText` 用于基于 DOM 树的 `SelectionInDOMTree`，`GetSelectionTextInFlatTree` 用于基于扁平树的 `SelectionInFlatTree`。
   - **与 JavaScript, HTML, CSS 的关系：**
     - **HTML:** 输出的字符串是对 HTML 结构的文本表示，包括元素标签和文本内容。选择的起始和结束位置用 `^` 和 `|` 标记出来。
     - **JavaScript:** 这个功能可以用于验证 JavaScript 代码操作 `Selection` 对象后的结果。例如，在 JavaScript 中设置了一个选择后，可以使用这个 C++ 工具将其转换为文本表示，方便进行断言和比较。
     - **CSS:** 虽然 CSS 不直接参与文本表示的生成，但 CSS 的样式会影响元素的布局和渲染，进而影响选择的范围。这个工具操作的是 DOM 结构，其呈现效果受 CSS 影响。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**
       - `root`: 一个指向 `<div>` 元素的指针，其 `innerHTML` 为 `"<div>abc</div><div>def</div>"`。
       - `selection`: 一个 `SelectionInDOMTree` 对象，锚点位于第一个 `<div>` 的文本节点 "abc" 的偏移量 1，焦点位于第二个 `<div>` 的文本节点 "def" 的偏移量 2。
     - **预期输出:** `"<div>a^bc</div><div>de|f</div>"`
   - **用户或编程常见的使用错误：**
     - **传入的 `Selection` 对象与 DOM 树不一致：** 如果 `Selection` 对象指向的节点或偏移量在 `root` 表示的 DOM 树中不存在，会导致错误或不期望的结果。

**3. 将 `<template data-mode="open">` 转换为 Shadow DOM (`ConvertTemplatesToShadowRootsForTesring`)**

   - **功能：** 遍历给定的 HTML 元素及其子元素，查找带有 `data-mode="open"` 属性的 `<template>` 元素，并将其内容转换为开放的 Shadow DOM。
   - **与 JavaScript, HTML 的关系：**
     - **HTML:** 该功能直接操作 HTML 结构，将 `<template>` 元素的内容移动到其父元素的 Shadow Root 中。
     - **JavaScript:** Shadow DOM 是 Web Components 的一部分，JavaScript 可以访问和操作 Shadow DOM。这个功能是为了在测试环境中模拟 Shadow DOM 的创建。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 一个指向 `<div>` 元素的指针，其 `innerHTML` 为 `"<div><template data-mode="open"><span>shadow content</span></template></div>"`。
     - **处理过程:** 找到 `<template>` 元素，创建一个开放的 Shadow Root，并将 `<span>shadow content</span>` 移动到该 Shadow Root 中。
     - **预期输出:**  该 `<div>` 元素拥有一个开放的 Shadow Root，其内容为 `<span>shadow content</span>`。在后续的选择操作中，Shadow DOM 的边界会被考虑。
   - **用户或编程常见的使用错误：**
     - **`data-mode` 属性缺失或值不为 "open"：** 如果 `<template>` 元素没有 `data-mode="open"` 属性，则不会被转换为 Shadow DOM。

**用户操作是如何一步步的到达这里，作为调试线索：**

这个文件主要用于 Blink 引擎的 **单元测试** 和 **集成测试**。它不是在用户日常浏览网页时直接执行的代码。然而，理解它的功能有助于调试与文本选择相关的 Bug。

以下是可能导致开发人员查看或使用这个文件的场景：

1. **用户在网页上进行文本选择：** 当用户使用鼠标或键盘在网页上选择文本时，浏览器底层的渲染引擎（Blink）会维护一个 `Selection` 对象来记录选择的范围。如果选择行为出现异常（例如，选择范围错误、光标位置不正确），开发人员可能会尝试使用类似 `GetSelectionText` 的工具来查看当前的选择状态，以便调试问题。

2. **JavaScript 代码操作文本选择：** 网页上的 JavaScript 代码可以使用 `window.getSelection()` API 来获取和修改文本选择。如果 JavaScript 代码操作选择后出现问题，开发人员可能会编写 C++ 测试用例，使用 `SetSelectionText` 来模拟特定的 DOM 结构和选择状态，然后验证 JavaScript 代码的行为是否符合预期。

3. **开发新的编辑功能：** 当 Blink 引擎的开发人员实现新的编辑功能（例如，富文本编辑器、内容可编辑区域）时，他们需要确保文本选择在各种情况下都能正常工作。`selection_sample.cc` 提供的工具可以帮助他们编写测试用例，覆盖不同的选择场景，包括跨元素、跨 Shadow DOM 等复杂情况。

4. **修复与文本选择相关的 Bug：** 当报告了与文本选择相关的 Bug 时，开发人员可能会使用这个文件来重现 Bug 的场景，并编写测试用例来验证修复是否有效。他们可能会分析导致 Bug 的 DOM 结构和选择状态，并使用 `SetSelectionText` 创建类似的测试环境。

**总结：**

`selection_sample.cc` 是一个用于测试和调试文本选择功能的内部工具。它通过文本字符串来表示 DOM 结构和选择状态，方便在 C++ 测试代码中创建和操作 `Selection` 对象。虽然普通用户不会直接接触到这个文件，但理解它的功能有助于理解浏览器底层是如何处理文本选择的，并为调试相关问题提供了有力的手段。

Prompt: 
```
这是目录为blink/renderer/core/editing/testing/selection_sample.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"

#include <algorithm>

#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"

namespace blink {

namespace {

void ConvertTemplatesToShadowRoots(HTMLElement& element) {
  // |element| and descendant elements can have TEMPLATE element with
  // |data-mode="open"|, which is required. Each elemnt can have only one
  // TEMPLATE element.
  HTMLCollection* const templates =
      element.getElementsByTagName(AtomicString("template"));
  HeapVector<Member<Element>> template_vector;
  for (Element* template_element : *templates)
    template_vector.push_back(template_element);
  for (Element* template_element : template_vector) {
    const AtomicString& data_mode =
        template_element->getAttribute(AtomicString("data-mode"));
    DCHECK_EQ(data_mode, "open");

    Element* const parent = template_element->parentElement();
    parent->removeChild(template_element);

    Document* const document = element.ownerDocument();
    ShadowRoot& shadow_root =
        parent->AttachShadowRootForTesting(ShadowRootMode::kOpen);
    Node* const fragment = document->importNode(
        To<HTMLTemplateElement>(template_element)->content(), true,
        ASSERT_NO_EXCEPTION);
    shadow_root.AppendChild(fragment);
  }
}

// Parse selection text notation into Selection object.
class Parser final {
  STACK_ALLOCATED();

 public:
  Parser() = default;
  ~Parser() = default;

  // Set |selection_text| as inner HTML of |element| and returns
  // |SelectionInDOMTree| marked up within |selection_text|.
  SelectionInDOMTree SetSelectionText(HTMLElement* element,
                                      const std::string& selection_text) {
    element->setInnerHTML(String::FromUTF8(selection_text.c_str()));
    element->GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    ConvertTemplatesToShadowRoots(*element);
    Traverse(element);
    if (anchor_node_ && focus_node_) {
      return typename SelectionInDOMTree::Builder()
          .Collapse(Position(anchor_node_, anchor_offset_))
          .Extend(Position(focus_node_, focus_offset_))
          .Build();
    }
    DCHECK(focus_node_) << "Need just '|', or '^' and '|'";
    return typename SelectionInDOMTree::Builder()
        .Collapse(Position(focus_node_, focus_offset_))
        .Build();
  }

 private:
  // Removes selection markers from |node| and records selection markers as
  // |Node| and |offset|. The |node| is removed from container when |node|
  // contains only selection markers.
  void HandleCharacterData(CharacterData* node) {
    int anchor_offset = -1;
    int focus_offset = -1;
    StringBuilder builder;
    for (unsigned i = 0; i < node->length(); ++i) {
      const UChar char_code = node->data()[i];
      if (char_code == '^') {
        DCHECK_EQ(anchor_offset, -1) << node->data();
        anchor_offset = static_cast<int>(builder.length());
        continue;
      }
      if (char_code == '|') {
        DCHECK_EQ(focus_offset, -1) << node->data();
        focus_offset = static_cast<int>(builder.length());
        continue;
      }
      builder.Append(char_code);
    }
    if (anchor_offset == -1 && focus_offset == -1)
      return;
    node->setData(builder.ToString());
    if (node->length() == 0) {
      // Remove |node| if it contains only selection markers.
      ContainerNode* const parent_node = node->parentNode();
      DCHECK(parent_node) << node;
      const int offset_in_parent = node->NodeIndex();
      if (anchor_offset >= 0)
        RecordSelectionAnchor(parent_node, offset_in_parent);
      if (focus_offset >= 0)
        RecordSelectionFocus(parent_node, offset_in_parent);
      parent_node->removeChild(node);
      return;
    }
    if (anchor_offset >= 0)
      RecordSelectionAnchor(node, anchor_offset);
    if (focus_offset >= 0)
      RecordSelectionFocus(node, focus_offset);
  }

  void HandleElementNode(Element* element) {
    if (ShadowRoot* shadow_root = element->GetShadowRoot())
      HandleChildren(shadow_root);
    HandleChildren(element);
  }

  void HandleChildren(ContainerNode* node) {
    Node* runner = node->firstChild();
    while (runner) {
      Node* const next_sibling = runner->nextSibling();
      // |Traverse()| may remove |runner|.
      Traverse(runner);
      runner = next_sibling;
    }
  }

  void RecordSelectionAnchor(Node* node, int offset) {
    DCHECK(!anchor_node_) << "Found more than one '^' in " << *anchor_node_
                          << " and " << *node;
    anchor_node_ = node;
    anchor_offset_ = offset;
  }

  void RecordSelectionFocus(Node* node, int offset) {
    DCHECK(!focus_node_) << "Found more than one '|' in " << *focus_node_
                         << " and " << *node;
    focus_node_ = node;
    focus_offset_ = offset;
  }

  // Traverses descendants of |node|. The |node| may be removed when it is
  // |CharacterData| node contains only selection markers.
  void Traverse(Node* node) {
    if (auto* element = DynamicTo<Element>(node)) {
      HandleElementNode(element);
      return;
    }
    if (auto* data = DynamicTo<CharacterData>(node)) {
      HandleCharacterData(data);
      return;
    }
    NOTREACHED() << node;
  }

  Node* anchor_node_ = nullptr;
  Node* focus_node_ = nullptr;
  int anchor_offset_ = 0;
  int focus_offset_ = 0;
};

// Serialize DOM/Flat tree to selection text.
template <typename Strategy>
class Serializer final {
  STACK_ALLOCATED();

 public:
  explicit Serializer(const SelectionTemplate<Strategy>& selection)
      : selection_(selection) {}

  std::string Serialize(const ContainerNode& root) {
    SerializeChildren(root);
    return builder_.ToString().Utf8();
  }

 private:
  void HandleCharacterData(const CharacterData& node) {
    const String text = node.data();
    if (selection_.IsNone()) {
      builder_.Append(text);
      return;
    }
    const Node& anchor_node = *selection_.Anchor().ComputeContainerNode();
    const Node& focus_node = *selection_.Focus().ComputeContainerNode();
    const int anchor_offset =
        selection_.Anchor().ComputeOffsetInContainerNode();
    const int focus_offset = selection_.Focus().ComputeOffsetInContainerNode();
    if (anchor_node == node && focus_node == node) {
      if (anchor_offset == focus_offset) {
        builder_.Append(text.Left(anchor_offset));
        builder_.Append('|');
        builder_.Append(text.Substring(anchor_offset));
        return;
      }
      if (anchor_offset < focus_offset) {
        builder_.Append(text.Left(anchor_offset));
        builder_.Append('^');
        builder_.Append(
            text.Substring(anchor_offset, focus_offset - anchor_offset));
        builder_.Append('|');
        builder_.Append(text.Substring(focus_offset));
        return;
      }
      builder_.Append(text.Left(focus_offset));
      builder_.Append('|');
      builder_.Append(
          text.Substring(focus_offset, anchor_offset - focus_offset));
      builder_.Append('^');
      builder_.Append(text.Substring(anchor_offset));
      return;
    }
    if (anchor_node == node) {
      builder_.Append(text.Left(anchor_offset));
      builder_.Append('^');
      builder_.Append(text.Substring(anchor_offset));
      return;
    }
    if (focus_node == node) {
      builder_.Append(text.Left(focus_offset));
      builder_.Append('|');
      builder_.Append(text.Substring(focus_offset));
      return;
    }
    builder_.Append(text);
  }

  void HandleAttribute(const Attribute& attribute) {
    builder_.Append(attribute.GetName().ToString());
    if (attribute.Value().empty())
      return;
    builder_.Append("=\"");
    for (wtf_size_t i = 0; i < attribute.Value().length(); ++i) {
      const UChar char_code = attribute.Value()[i];
      if (char_code == '"') {
        builder_.Append("&quot;");
        continue;
      }
      if (char_code == '&') {
        builder_.Append("&amp;");
        continue;
      }
      builder_.Append(char_code);
    }
    builder_.Append('"');
  }

  void HandleAttributes(const Element& element) {
    Vector<const Attribute*> attributes;
    for (const Attribute& attribute : element.Attributes())
      attributes.push_back(&attribute);
    std::sort(attributes.begin(), attributes.end(),
              [](const Attribute* attribute1, const Attribute* attribute2) {
                return CodeUnitCompareLessThan(
                    attribute1->GetName().ToString(),
                    attribute2->GetName().ToString());
              });
    for (const Attribute* attribute : attributes) {
      builder_.Append(' ');
      HandleAttribute(*attribute);
    }
  }

  void HandleElementNode(const Element& element) {
    builder_.Append('<');
    builder_.Append(element.TagQName().ToString());
    HandleAttributes(element);
    builder_.Append('>');
    if (IsVoidElement(element))
      return;
    SerializeChildren(element);
    builder_.Append("</");
    builder_.Append(element.TagQName().ToString());
    builder_.Append('>');
  }

  void HandleNode(const Node& node) {
    if (auto* element = DynamicTo<Element>(node)) {
      HandleElementNode(*element);
      return;
    }
    if (node.IsTextNode()) {
      HandleCharacterData(To<CharacterData>(node));
      return;
    }
    if (node.getNodeType() == Node::kCommentNode) {
      builder_.Append("<!--");
      HandleCharacterData(To<CharacterData>(node));
      builder_.Append("-->");
      return;
    }
    if (auto* processing_instruction_node =
            DynamicTo<ProcessingInstruction>(node)) {
      builder_.Append("<?");
      builder_.Append(processing_instruction_node->target());
      builder_.Append(' ');
      HandleCharacterData(To<CharacterData>(node));
      builder_.Append("?>");
      return;
    }
    NOTREACHED() << node;
  }

  void HandleSelection(const ContainerNode& node, int offset) {
    if (selection_.IsNone())
      return;
    const PositionTemplate<Strategy> position(node, offset);
    if (selection_.Focus().ToOffsetInAnchor() == position) {
      builder_.Append('|');
      return;
    }
    if (selection_.Anchor().ToOffsetInAnchor() != position) {
      return;
    }
    builder_.Append('^');
  }

  static bool IsVoidElement(const Element& element) {
    if (Strategy::HasChildren(element))
      return false;
    return ElementCannotHaveEndTag(element);
  }

  void SerializeChildren(const ContainerNode& container) {
    int offset_in_container = 0;
    for (const Node& child : Strategy::ChildrenOf(container)) {
      HandleSelection(container, offset_in_container);
      HandleNode(child);
      ++offset_in_container;
    }
    HandleSelection(container, offset_in_container);
  }

  StringBuilder builder_;
  SelectionTemplate<Strategy> selection_;
};

}  // namespace

void SelectionSample::ConvertTemplatesToShadowRootsForTesring(
    HTMLElement& element) {
  ConvertTemplatesToShadowRoots(element);
}

SelectionInDOMTree SelectionSample::SetSelectionText(
    HTMLElement* element,
    const std::string& selection_text) {
  SelectionInDOMTree selection =
      Parser().SetSelectionText(element, selection_text);
  DCHECK(!selection.IsNone()) << "|selection_text| should container caret "
                                 "marker '|' or selection marker '^' and "
                                 "'|'.";
  return selection;
}

std::string SelectionSample::GetSelectionText(
    const ContainerNode& root,
    const SelectionInDOMTree& selection) {
  return Serializer<EditingStrategy>(selection).Serialize(root);
}

std::string SelectionSample::GetSelectionTextInFlatTree(
    const ContainerNode& root,
    const SelectionInFlatTree& selection) {
  return Serializer<EditingInFlatTreeStrategy>(selection).Serialize(root);
}

}  // namespace blink

"""

```
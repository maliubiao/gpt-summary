Response:
Let's break down the thought process for analyzing the `blink/renderer/core/dom/text.cc` file.

**1. Initial Understanding and Goal:**

The primary goal is to understand the functionality of this C++ file within the Chromium Blink rendering engine. We need to identify its core responsibilities, how it interacts with other parts of the engine (especially JavaScript, HTML, and CSS), potential usage errors, and how a user's actions can lead to the execution of code within this file.

**2. High-Level Overview (Skimming the Code):**

The first step is to quickly scan the code and identify key elements:

* **Copyright and License:**  This tells us who owns the code and under what terms it can be used.
* **Includes:**  These `#include` directives are crucial. They reveal the dependencies and hint at the file's interactions with other Blink components. Looking at these immediately brings to mind concepts like:
    * CSS styling (`StyleResolver`, `ComputedStyle`)
    * DOM events (`ScopedEventQueue`)
    * Layout (`LayoutText`, `LayoutTreeBuilder`)
    * Node manipulation (`NodeTraversal`, `NodeCloningData`)
    * Shadow DOM (`ShadowRoot`)
    * Text manipulation (`TextDiffRange`)
    * JavaScript interaction (`DOMDataStore`, `ExceptionState`)
* **Namespace `blink`:** This indicates the code belongs to the Blink engine.
* **Class `Text`:**  The core of the file. We need to analyze its methods.
* **`Create` methods:** These are factory methods for creating `Text` objects. The different variations (with and without moving data, and for editing) suggest different usage scenarios.
* **Methods related to text manipulation:** `MergeNextSiblingNodesIfPossible`, `splitText`, `wholeText`, `ReplaceWholeText`. These directly relate to the core functionality of a text node.
* **Layout-related methods:** `TextLayoutObjectIsNeeded`, `CreateTextLayoutObject`, `AttachLayoutTree`, `ReattachLayoutTreeIfNeeded`, `RecalcTextStyle`, `RebuildTextLayoutTree`, `UpdateTextLayoutObject`. These methods strongly suggest the file's involvement in the rendering process.
* **Other methods:** `nodeName`, `CloneWithData`, `Trace`. These are standard DOM node methods.

**3. Deeper Dive into Key Methods:**

Now, let's examine some of the more complex and interesting methods in detail:

* **`MergeNextSiblingNodesIfPossible`:**  The logic of merging adjacent text nodes is interesting and hints at optimization. The handling of empty text nodes and the use of `TextDiffRange` for layout updates are noteworthy.
* **`splitText`:**  This directly corresponds to the DOM `splitText()` method. The error handling (`IndexSizeError`), event queuing, and layout updates are important aspects.
* **`wholeText` and `ReplaceWholeText`:** These methods deal with the concept of contiguous text nodes and how to manipulate them as a single unit.
* **The layout-related methods (especially `TextLayoutObjectIsNeeded`, `AttachLayoutTree`, `ReattachLayoutTreeIfNeeded`):** These are crucial for understanding how text nodes are rendered. The logic within `TextLayoutObjectIsNeeded` involving whitespace, CSS `white-space` property, and adjacent nodes is significant. The distinction between `AttachLayoutTree` and `ReattachLayoutTreeIfNeeded` points to optimization strategies. `UpdateTextLayoutObject` and the use of `TextDiffRange` show how incremental updates are handled.

**4. Connecting to JavaScript, HTML, and CSS:**

Based on the method analysis, we can now establish the connections:

* **JavaScript:** The methods like `splitText`, `wholeText`, and `replaceWholeText` directly correspond to JavaScript DOM API methods. The `Create` methods are used internally but indirectly influenced by JavaScript actions that create or modify the DOM. `ExceptionState` is used for reporting errors back to JavaScript.
* **HTML:**  Text nodes are fundamental to HTML structure. This file handles the underlying representation of the text content within HTML elements. The interaction with elements (parent nodes, siblings) is evident in many methods.
* **CSS:**  The inclusion of `StyleResolver` and the logic within `TextLayoutObjectIsNeeded` and `RecalcTextStyle` clearly demonstrate the connection to CSS styling. The `white-space` property is a key factor in how text nodes are handled.

**5. Logical Reasoning (Hypothetical Inputs and Outputs):**

Consider specific scenarios:

* **Input:** JavaScript calls `textNode.splitText(5)`.
* **Output:** A new `Text` node is created with the latter part of the original text, inserted into the DOM, and layout is updated.

* **Input:**  Adjacent text nodes are present in the DOM.
* **Output:** `MergeNextSiblingNodesIfPossible` combines them into a single text node.

**6. Common User/Programming Errors:**

Think about how developers might misuse the functionality related to text nodes:

* Incorrect offset in `splitText`.
* Assuming direct manipulation of layout objects instead of going through the DOM API.
* Not understanding the implications of whitespace and the `white-space` CSS property.

**7. Debugging Clues (User Actions Leading Here):**

Trace the path of execution from user interaction:

* User types text in an input field.
* JavaScript manipulates the text content of an element.
* The browser parses HTML and creates text nodes.
* CSS styles are applied, influencing the layout of text nodes.

**8. Structuring the Answer:**

Finally, organize the findings into a clear and comprehensive answer, addressing each part of the prompt:

* **Functions:** List and explain the key functionalities.
* **Relationships with JavaScript, HTML, and CSS:** Provide concrete examples.
* **Logical Reasoning:**  Offer input/output scenarios.
* **Common Errors:** Illustrate potential mistakes.
* **Debugging Clues:** Explain the user interaction flow leading to the file.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file just stores text data.
* **Correction:** The presence of layout-related code indicates a deeper involvement in the rendering process.

* **Initial thought:**  The connection to CSS is only through applying styles.
* **Correction:** The `TextLayoutObjectIsNeeded` function shows that CSS properties like `white-space` directly influence whether a layout object is even created for a text node.

By following these steps, we can systematically analyze the code and provide a detailed and accurate explanation of its functionality within the broader context of the Blink rendering engine.
这个 `blink/renderer/core/dom/text.cc` 文件是 Chromium Blink 引擎中负责处理 DOM 树中 `Text` 节点的关键代码。`Text` 节点代表 HTML 或 XML 文档中的文本内容。

以下是该文件的主要功能：

**1. `Text` 节点的创建与管理:**

* **创建 `Text` 对象:** 提供了多种静态 `Create` 方法来创建不同类型的 `Text` 节点，例如普通文本节点和用于编辑的文本节点。
* **合并相邻文本节点 (`MergeNextSiblingNodesIfPossible`):**  当相邻的兄弟节点都是文本节点时，此方法会将它们合并成一个。这有助于优化 DOM 结构和渲染性能。
    * **假设输入:**  DOM 树中存在两个相邻的 `Text` 节点，例如 `<p>Hello</p><p>World</p>` 经过修改变成 `<p>HelloWorld</p>`，或者  `<div>Text1</div><div>Text2</div>`，经过 JavaScript 操作，使得两个 `div` 的内容被合并成一个文本节点。
    * **输出:** 如果两个相邻节点都是 `Text` 节点，且可以合并（例如，中间没有其他类型的节点），则后一个 `Text` 节点的内容会被追加到前一个，并且后一个 `Text` 节点会被移除。
* **分割文本节点 (`splitText`):**  允许将一个 `Text` 节点在指定的偏移量处分割成两个新的 `Text` 节点。
    * **与 JavaScript 的关系:**  对应 JavaScript 中 `Text` 节点的 `splitText()` 方法。
    * **HTML 举例:**  如果一个 `Text` 节点包含 "Hello World"，调用 `splitText(5)` 将会产生两个新的 `Text` 节点，分别包含 "Hello" 和 " World"。
    * **假设输入:**  一个 `Text` 节点包含字符串 "abcdefg"，调用 `splitText(3)`。
    * **输出:**  原始 `Text` 节点的内容变为 "abc"，并且在其后插入一个新的 `Text` 节点，内容为 "defg"。
    * **常见错误:**  指定的 `offset` 超出文本节点的长度，会导致抛出 `IndexSizeError` 异常。
* **获取完整的文本内容 (`wholeText`):**  返回与当前 `Text` 节点逻辑上相邻的所有文本节点的完整文本内容。
    * **HTML 举例:**  对于 `<div>Part 1<br>Part 2</div>`，如果对 "Part 1" 的 `Text` 节点调用 `wholeText()`，将返回 "Part 1Part 2"。
* **替换所有相邻文本节点的内容 (`ReplaceWholeText`):**  移除所有逻辑上相邻的文本节点，并将当前节点的文本内容替换为新的字符串。
    * **与 JavaScript 的关系:**  对应 JavaScript 中 `Text` 节点的 `replaceWholeText()` 方法。

**2. 与布局 (Layout) 的交互:**

* **判断是否需要布局对象 (`TextLayoutObjectIsNeeded`):**  根据父元素的样式、自身内容等因素，判断该 `Text` 节点是否需要创建对应的 `LayoutText` 对象进行渲染。例如，只有空格的文本节点在某些情况下可能不需要布局对象。
    * **CSS 举例:**  如果父元素的 `display` 属性为 `none`，则文本节点不需要布局对象。如果文本节点只包含空格，且父元素的 `white-space` 属性为 `normal`，则可能不需要布局对象。
    * **假设输入:**  一个只包含空格的 `Text` 节点，其父元素的 CSS `white-space` 属性为 `normal`。
    * **输出:**  `TextLayoutObjectIsNeeded` 返回 `false`。
* **创建布局对象 (`CreateTextLayoutObject`):**  为 `Text` 节点创建对应的 `LayoutText` 或 `LayoutSVGInlineText` 对象，用于渲染文本。
* **附加布局树 (`AttachLayoutTree`):**  将 `Text` 节点对应的布局对象添加到布局树中。
* **根据需要重新附加布局树 (`ReattachLayoutTreeIfNeeded`):**  当 `Text` 节点的属性或样式发生变化，需要更新布局时，会调用此方法。
* **重新计算文本样式 (`RecalcTextStyle`):**  当应用的 CSS 样式发生变化时，重新计算 `Text` 节点的样式，并根据需要触发布局更新。
* **重建文本布局树 (`RebuildTextLayoutTree`):**  当需要彻底重建 `Text` 节点的布局时调用。
* **更新文本布局对象 (`UpdateTextLayoutObject`):**  当 `Text` 节点的内容发生变化时，更新其对应的 `LayoutText` 对象，并尽可能进行增量更新，例如使用 `TextDiffRange` 来描述文本的变化范围。
    * **假设输入:**  一个 `Text` 节点的内容从 "abc" 变为 "abde"。
    * **输出:** `UpdateTextLayoutObject` 会使用 `TextDiffRange` 来表示 "c" 被删除，"de" 被插入。

**3. 其他功能:**

* **克隆节点 (`CloneWithData`):**  创建 `Text` 节点的副本。
* **获取节点名称 (`nodeName`):**  返回 "#text"。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * 当 JavaScript 代码调用 `document.createTextNode("Hello")` 时，最终会调用到 `Text::Create` 来创建一个新的 `Text` 节点。
    * 当 JavaScript 代码修改 `textNode.data = "World"` 时，会触发 `Text::setData`，进而可能导致 `UpdateTextLayoutObject` 被调用以更新渲染。
    * `textNode.splitText(5)` 直接对应 `Text::splitText` 的实现。
* **HTML:**
    * HTML 文档中的文本内容会被解析器创建为 `Text` 节点。例如，对于 `<div>Some text</div>`，"Some text" 部分会被创建为一个 `Text` 节点。
* **CSS:**
    * CSS 样式会影响 `Text` 节点的渲染方式。例如，`color` 属性会影响文本颜色，`font-size` 会影响文本大小，`white-space` 属性会影响空格和换行的处理。`TextLayoutObjectIsNeeded` 和 `RecalcTextStyle` 等方法负责根据 CSS 样式来决定如何渲染文本。
    * 例如，CSS `white-space: pre;` 会强制保留文本中的空格和换行符，这会影响 `TextLayoutObjectIsNeeded` 的判断，确保即使只有空格也需要布局对象。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载或浏览网页:**  浏览器会解析 HTML 结构，创建 DOM 树，其中包括 `Text` 节点来表示文本内容.
2. **用户与网页交互:**
   * **输入文本:** 当用户在 `<input>` 或 `<textarea>` 等元素中输入文本时，浏览器会更新对应的 `Text` 节点的内容。
   * **点击链接或按钮:**  这可能导致 JavaScript 代码执行，例如通过 `innerHTML` 或 `textContent` 修改 DOM 结构，包括 `Text` 节点的内容。
   * **CSS 样式变化:**  用户的操作（例如，鼠标悬停）或 JavaScript 代码可能会动态修改元素的 CSS 样式，这会触发样式的重新计算，进而影响 `Text` 节点的渲染。
3. **Blink 引擎处理:**
   * 当创建新的 `Text` 节点或修改现有 `Text` 节点的内容时，会调用 `Text::Create` 或 `Text::setData` 等方法。
   * 如果 DOM 结构发生变化，可能会调用 `MergeNextSiblingNodesIfPossible` 或 `splitText` 等方法来维护 DOM 树的结构。
   * 当需要渲染或重新渲染 `Text` 节点时，会涉及到 `TextLayoutObjectIsNeeded`、`CreateTextLayoutObject`、`AttachLayoutTree`、`ReattachLayoutTreeIfNeeded`、`UpdateTextLayoutObject` 等方法。
   * CSS 样式的变化会触发 `RecalcTextStyle`，进而可能导致布局的更新。

**调试线索:**

如果你在调试过程中遇到了与文本显示或 DOM 操作相关的问题，并且断点命中了 `blink/renderer/core/dom/text.cc` 中的代码，那么可能的线索包括：

* **文本内容错误:**  检查 `Text` 节点的数据是否正确。
* **布局问题:**  检查 `TextLayoutObjectIsNeeded` 的返回值以及相关的 CSS 样式，确定是否正确创建了布局对象，以及布局对象的位置和尺寸是否正确。
* **DOM 结构问题:**  检查是否存在不必要的文本节点合并或分割，或者 `Text` 节点是否被错误地插入或删除。
* **事件处理问题:**  某些事件处理可能会导致 JavaScript 代码修改 `Text` 节点的内容，从而触发这里的代码执行。

总而言之，`blink/renderer/core/dom/text.cc` 文件是 Blink 引擎中处理文本内容的核心部分，它负责 `Text` 节点的创建、管理以及与渲染引擎的交互，是理解浏览器如何显示和操作网页文本的关键。

### 提示词
```
这是目录为blink/renderer/core/dom/text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/dom/text.h"

#include <utility>

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text_diff_range.h"
#include "third_party/blink/renderer/core/dom/whitespace_attacher.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/svg/svg_foreign_object_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

Text* Text::Create(Document& document, const String& data) {
  return MakeGarbageCollected<Text>(document, data, kCreateText);
}

Text* Text::Create(Document& document, String&& data) {
  return MakeGarbageCollected<Text>(document, std::move(data), kCreateText);
}

Text* Text::CreateEditingText(Document& document, const String& data) {
  return MakeGarbageCollected<Text>(document, data, kCreateEditingText);
}

Node* Text::MergeNextSiblingNodesIfPossible() {
  // Remove empty text nodes.
  if (!length()) {
    // Care must be taken to get the next node before removing the current node.
    Node* next_node = NodeTraversal::NextPostOrder(*this);
    remove(IGNORE_EXCEPTION_FOR_TESTING);
    return next_node;
  }

  // Merge text nodes.
  while (Node* next_sibling = nextSibling()) {
    if (next_sibling->getNodeType() != kTextNode)
      break;

    auto* next_text = To<Text>(next_sibling);

    // Remove empty text nodes.
    if (!next_text->length()) {
      next_text->remove(IGNORE_EXCEPTION_FOR_TESTING);
      continue;
    }

    // Both non-empty text nodes. Merge them.
    unsigned offset = length();
    String next_text_data = next_text->data();
    String old_text_data = data();
    SetDataWithoutUpdate(data() + next_text_data);
    UpdateTextLayoutObject(
        TextDiffRange::Insert(old_text_data.length(), next_text_data.length()));

    GetDocument().DidMergeTextNodes(*this, *next_text, offset);

    // Empty nextText for layout update.
    next_text->SetDataWithoutUpdate(g_empty_string);
    next_text->UpdateTextLayoutObject(
        TextDiffRange::Delete(0, next_text_data.length()));

    // Restore nextText for mutation event.
    next_text->SetDataWithoutUpdate(next_text_data);
    next_text->UpdateTextLayoutObject(
        TextDiffRange::Insert(0, next_text_data.length()));

    GetDocument().IncDOMTreeVersion();
    DidModifyData(old_text_data, CharacterData::kUpdateFromNonParser);
    next_text->remove(IGNORE_EXCEPTION_FOR_TESTING);
  }

  return NodeTraversal::NextPostOrder(*this);
}

Text* Text::splitText(unsigned offset, ExceptionState& exception_state) {
  // IndexSizeError: Raised if the specified offset is negative or greater than
  // the number of 16-bit units in data.
  if (offset > length()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The offset " + String::Number(offset) +
            " is larger than the Text node's length.");
    return nullptr;
  }

  EventQueueScope scope;
  String old_str = data();
  Text* new_text =
      To<Text>(CloneWithData(GetDocument(), old_str.Substring(offset)));
  SetDataWithoutUpdate(old_str.Substring(0, offset));

  DidModifyData(old_str, CharacterData::kUpdateFromNonParser);

  if (parentNode())
    parentNode()->InsertBefore(new_text, nextSibling(), exception_state);
  if (exception_state.HadException())
    return nullptr;

  if (LayoutText* layout_text = GetLayoutObject()) {
    if (RuntimeEnabledFeatures::TextDiffSplitFixEnabled()) {
      // To avoid |LayoutText| has empty text, we rebuild layout tree.
      if (ContainsOnlyWhitespaceOrEmpty()) {
        SetForceReattachLayoutTree();
      } else {
        layout_text->SetTextWithOffset(
            data(), TextDiffRange::Delete(offset, old_str.length() - offset));
      }
    } else {
      layout_text->SetTextWithOffset(
          data(), TextDiffRange::Delete(0, old_str.length()));
      if (ContainsOnlyWhitespaceOrEmpty()) {
        // To avoid |LayoutText| has empty text, we rebuild layout tree.
        SetForceReattachLayoutTree();
      }
    }
  }

  if (parentNode())
    GetDocument().DidSplitTextNode(*this);
  else
    GetDocument().DidRemoveText(*this, offset, old_str.length() - offset);

  // [NewObject] must always create a new wrapper.  Check that a wrapper
  // does not exist yet.
  DCHECK(DOMDataStore::GetWrapper(GetDocument().GetAgent().isolate(), new_text)
             .IsEmpty());

  return new_text;
}

static const Text* EarliestLogicallyAdjacentTextNode(const Text* t) {
  for (const Node* n = t->previousSibling(); n; n = n->previousSibling()) {
    if (auto* text_node = DynamicTo<Text>(n)) {
      t = text_node;
      continue;
    }

    break;
  }
  return t;
}

static const Text* LatestLogicallyAdjacentTextNode(const Text* t) {
  for (const Node* n = t->nextSibling(); n; n = n->nextSibling()) {
    if (auto* text_node = DynamicTo<Text>(n)) {
      t = text_node;
      continue;
    }

    break;
  }
  return t;
}

String Text::wholeText() const {
  const Text* start_text = EarliestLogicallyAdjacentTextNode(this);
  const Text* end_text = LatestLogicallyAdjacentTextNode(this);

  Node* one_past_end_text = end_text->nextSibling();
  unsigned result_length = 0;
  for (const Node* n = start_text; n != one_past_end_text;
       n = n->nextSibling()) {
    auto* text_node = DynamicTo<Text>(n);
    if (!text_node)
      continue;
    const String& data = text_node->data();
    CHECK_GE(std::numeric_limits<unsigned>::max() - data.length(),
             result_length);
    result_length += data.length();
  }
  StringBuilder result;
  result.ReserveCapacity(result_length);
  for (const Node* n = start_text; n != one_past_end_text;
       n = n->nextSibling()) {
    auto* text_node = DynamicTo<Text>(n);
    if (!text_node)
      continue;
    result.Append(text_node->data());
  }
  DCHECK_EQ(result.length(), result_length);

  return result.ReleaseString();
}

Text* Text::ReplaceWholeText(const String& new_text) {
  // Remove all adjacent text nodes, and replace the contents of this one.

  // Protect startText and endText against mutation event handlers removing the
  // last ref
  Text* start_text = const_cast<Text*>(EarliestLogicallyAdjacentTextNode(this));
  Text* end_text = const_cast<Text*>(LatestLogicallyAdjacentTextNode(this));

  ContainerNode* parent = parentNode();  // Protect against mutation handlers
                                         // moving this node during traversal
  for (Node* n = start_text;
       n && n != this && n->IsTextNode() && n->parentNode() == parent;) {
    Node* node_to_remove = n;
    n = node_to_remove->nextSibling();
    parent->RemoveChild(node_to_remove, IGNORE_EXCEPTION_FOR_TESTING);
  }

  if (this != end_text) {
    Node* one_past_end_text = end_text->nextSibling();
    for (Node* n = nextSibling(); n && n != one_past_end_text &&
                                  n->IsTextNode() &&
                                  n->parentNode() == parent;) {
      Node* node_to_remove = n;
      n = node_to_remove->nextSibling();
      parent->RemoveChild(node_to_remove, IGNORE_EXCEPTION_FOR_TESTING);
    }
  }

  if (new_text.empty()) {
    if (parent && parentNode() == parent)
      parent->RemoveChild(this, IGNORE_EXCEPTION_FOR_TESTING);
    return nullptr;
  }

  setData(new_text);
  return this;
}

String Text::nodeName() const {
  return "#text";
}

static inline bool EndsWithWhitespace(const String& text) {
  return text.length() && IsASCIISpace(text[text.length() - 1]);
}

static inline bool CanHaveWhitespaceChildren(
    const ComputedStyle& style,
    const Text::AttachContext& context) {
  const LayoutObject& parent = *context.parent;
  if (parent.IsTable() || parent.IsTableRow() || parent.IsTableSection() ||
      parent.IsLayoutTableCol() || parent.IsFrameSet() ||
      parent.IsFlexibleBox() || parent.IsLayoutGrid() || parent.IsSVGRoot() ||
      parent.IsSVGContainer() || parent.IsSVGImage() || parent.IsSVGShape()) {
    if (!context.use_previous_in_flow || !context.previous_in_flow ||
        !context.previous_in_flow->IsText())
      return false;

    return style.ShouldPreserveBreaks() ||
           !EndsWithWhitespace(
               To<LayoutText>(context.previous_in_flow)->TransformedText());
  }
  return true;
}

bool Text::TextLayoutObjectIsNeeded(const AttachContext& context,
                                    const ComputedStyle& style) const {
  const LayoutObject& parent = *context.parent;
  if (!parent.CanHaveChildren())
    return false;

  if (IsEditingText())
    return true;

  if (!length())
    return false;

  if (style.Display() == EDisplay::kNone)
    return false;

  if (!ContainsOnlyWhitespaceOrEmpty())
    return true;

  if (!CanHaveWhitespaceChildren(style, context))
    return false;

  // pre-wrap in SVG never makes layoutObject.
  if (style.ShouldPreserveWhiteSpaces() && style.ShouldWrapLine() &&
      parent.IsSVG()) {
    return false;
  }

  // pre/pre-wrap/pre-line always make layoutObjects.
  if (style.ShouldPreserveBreaks()) {
    return true;
  }

  if (!context.use_previous_in_flow)
    return false;

  if (!context.previous_in_flow)
    return parent.IsLayoutInline();

  if (context.previous_in_flow->IsText()) {
    return !EndsWithWhitespace(
        To<LayoutText>(context.previous_in_flow)->TransformedText());
  }

  return context.previous_in_flow->IsInline() &&
         !context.previous_in_flow->IsBR();
}

static bool IsSVGText(Text* text) {
  Node* parent_or_shadow_host_node = text->ParentOrShadowHostNode();
  DCHECK(parent_or_shadow_host_node);
  return parent_or_shadow_host_node->IsSVGElement() &&
         !IsA<SVGForeignObjectElement>(*parent_or_shadow_host_node);
}

LayoutText* Text::CreateTextLayoutObject() {
  if (IsSVGText(this))
    return MakeGarbageCollected<LayoutSVGInlineText>(this, data());
  return MakeGarbageCollected<LayoutText>(this, data());
}

void Text::AttachLayoutTree(AttachContext& context) {
  if (context.parent) {
    if (Element* style_parent =
            LayoutTreeBuilderTraversal::ParentElement(*this)) {
      const ComputedStyle* const style =
          IsA<HTMLHtmlElement>(style_parent) && style_parent->GetLayoutObject()
              ? style_parent->GetLayoutObject()->Style()
              : style_parent->GetComputedStyle();
      CHECK(style);
      if (TextLayoutObjectIsNeeded(context, *style)) {
        LayoutTreeBuilderForText(*this, context, style).CreateLayoutObject();
        context.previous_in_flow = GetLayoutObject();
      }
    }
  }
  CharacterData::AttachLayoutTree(context);
}

void Text::ReattachLayoutTreeIfNeeded(AttachContext& context) {
  bool layout_object_is_needed = false;
  Element* style_parent = LayoutTreeBuilderTraversal::ParentElement(*this);
  if (style_parent && context.parent) {
    const ComputedStyle* style = style_parent->GetComputedStyle();
    CHECK(style);
    layout_object_is_needed = TextLayoutObjectIsNeeded(context, *style);
  }

  if (layout_object_is_needed == !!GetLayoutObject())
    return;

  AttachContext reattach_context(context);
  reattach_context.performing_reattach = true;

  if (layout_object_is_needed) {
    DCHECK(!GetLayoutObject());
    LayoutTreeBuilderForText(*this, context, style_parent->GetComputedStyle())
        .CreateLayoutObject();
  } else {
    DetachLayoutTree(/*performing_reattach=*/true);
  }
  CharacterData::AttachLayoutTree(reattach_context);
}

namespace {

bool NeedsWhitespaceLayoutObject(const ComputedStyle& style) {
  return style.ShouldPreserveBreaks();
}

}  // namespace

void Text::RecalcTextStyle(const StyleRecalcChange change) {
  const ComputedStyle* new_style =
      GetDocument().GetStyleResolver().StyleForText(this);
  if (LayoutText* layout_text = GetLayoutObject()) {
    const ComputedStyle* layout_parent_style =
        GetLayoutObject()->Parent()->Style();
    if (!new_style || GetForceReattachLayoutTree() ||
        (new_style != layout_parent_style &&
         !new_style->InheritedEqual(*layout_parent_style))) {
      // The computed style or the need for an anonymous inline wrapper for a
      // display:contents text child changed.
      SetNeedsReattachLayoutTree();
    } else {
      layout_text->SetStyle(new_style);
      if (NeedsStyleRecalc())
        layout_text->SetTextIfNeeded(data());
    }
  } else if (new_style && (NeedsStyleRecalc() || change.ReattachLayoutTree() ||
                           GetForceReattachLayoutTree() ||
                           NeedsWhitespaceLayoutObject(*new_style))) {
    SetNeedsReattachLayoutTree();
  }
  ClearNeedsStyleRecalc();
}

void Text::RebuildTextLayoutTree(WhitespaceAttacher& whitespace_attacher) {
  DCHECK(!ChildNeedsStyleRecalc());
  DCHECK(NeedsReattachLayoutTree());
  DCHECK(parentNode());

  AttachContext context;
  context.parent = LayoutTreeBuilderTraversal::ParentLayoutObject(*this);
  ReattachLayoutTree(context);
  whitespace_attacher.DidReattachText(this);
  ClearNeedsReattachLayoutTree();
}

// Passing both |text_node| and its layout object because repeated calls to
// |Node::GetLayoutObject()| are discouraged.
static bool ShouldUpdateLayoutByReattaching(const Text& text_node,
                                            LayoutText* text_layout_object) {
  DCHECK_EQ(text_node.GetLayoutObject(), text_layout_object);
  if (!text_layout_object)
    return true;
  Node::AttachContext context;
  context.parent = text_layout_object->Parent();
  if (!text_node.TextLayoutObjectIsNeeded(context,
                                          *text_layout_object->Style())) {
    return true;
  }
  if (text_layout_object->IsTextFragment()) {
    // Changes of |text_node| may change first letter part, so we should
    // reattach. Note: When |text_node| is empty or holds collapsed whitespaces
    // |text_fragment_layout_object| represents first-letter part but it isn't
    // inside first-letter-pseudo element. See http://crbug.com/978947
    const auto& text_fragment_layout_object =
        *To<LayoutTextFragment>(text_layout_object);
    return text_fragment_layout_object.GetFirstLetterPseudoElement() ||
           !text_fragment_layout_object.IsRemainingTextLayoutObject();
  }
  // If we force a re-attach for password inputs and other elements hiding text
  // input via -webkit-text-security, the last character input will be hidden
  // immediately, even if the passwordEchoEnabled setting is enabled.
  // ::first-letter do not seem to apply to text inputs, so for those skipping
  // the re-attachment should be safe.
  // We can possibly still cause DCHECKs for mismatch of first letter text in
  // editing with the combination of -webkit-text-security in author styles on
  // other elements in combination with ::first-letter.
  // See crbug.com/1240988
  if (text_layout_object->IsSecure()) {
    return false;
  }
  FirstLetterPseudoElement::Punctuation punctuation1 =
      FirstLetterPseudoElement::Punctuation::kNotSeen;
  FirstLetterPseudoElement::Punctuation punctuation2 =
      FirstLetterPseudoElement::Punctuation::kNotSeen;
  bool preserve_breaks = ShouldPreserveBreaks(
      text_layout_object->StyleRef().GetWhiteSpaceCollapse());
  if (!FirstLetterPseudoElement::FirstLetterLength(
          text_layout_object->TransformedText(), preserve_breaks,
          punctuation1) &&
      FirstLetterPseudoElement::FirstLetterLength(
          text_node.data(), preserve_breaks, punctuation2)) {
    // We did not previously apply ::first-letter styles to this |text_node|,
    // and if there was no first formatted letter, but now is, we may need to
    // reattach.
    return true;
  }
  return false;
}

void Text::UpdateTextLayoutObject(const TextDiffRange& diff) {
  if (!InActiveDocument())
    return;
  LayoutText* text_layout_object = GetLayoutObject();
  if (ShouldUpdateLayoutByReattaching(*this, text_layout_object)) {
    SetForceReattachLayoutTree();
  } else {
    text_layout_object->SetTextWithOffset(data(), diff);
  }
}

CharacterData* Text::CloneWithData(Document& factory,
                                   const String& data) const {
  return Create(factory, data);
}

void Text::Trace(Visitor* visitor) const {
  CharacterData::Trace(visitor);
}

}  // namespace blink
```
Response:
My thinking process for analyzing the `text_iterator.cc` code snippet went through these stages:

1. **Understand the Goal:** The request asks for the functions of this specific file, its relation to web technologies (HTML, CSS, JavaScript), potential usage errors, debugging clues, and a summary of its purpose (for this first part of the file).

2. **Initial Scan for Key Terms:** I quickly scanned the code for prominent terms and patterns:
    * `#include`:  This tells me about dependencies. I saw includes related to DOM, editing, layout, and platform features. This immediately suggested the file is involved in text processing within the rendering engine.
    * `TextIteratorAlgorithm`: This is the central class, and its template nature (`<Strategy>`) suggests different strategies for iteration.
    * `Advance()`, `HandleTextNode()`, `HandleReplacedElement()`, `RepresentNodeOffsetZero()`: These look like core functions defining the iteration process.
    * `behavior_`, `text_state_`:  These likely control how the iteration behaves and maintains state.
    * Namespaces like `blink` and `mojom::blink`:  This confirms it's part of the Chromium Blink engine.
    * Comments mentioning copyright and redistribution: Standard boilerplate but indicates a substantial piece of code.

3. **Infer Core Functionality from Includes and Class Members:** Based on the includes and the names of the class members, I started forming a hypothesis about the file's purpose: It's responsible for iterating through the text content of a DOM tree, potentially with different strategies for handling different scenarios (like shadow DOM or plain DOM).

4. **Analyze Key Functions:** I then looked more closely at the major functions:
    * `TextIteratorAlgorithm` (constructor): It takes start and end positions and a `TextIteratorBehavior` object, indicating it defines an iteration range and behavior.
    * `Advance()`: This is the core iteration logic. The `while` loop, the checks for `should_stop_`, and the calls to various `Handle...` methods suggest a state machine driving the iteration. The handling of shadow DOM with `shadow_depth_` is apparent.
    * `HandleTextNode()`: Deals with text nodes, considering start and end offsets.
    * `HandleReplacedElement()`: Handles elements like images or form controls.
    * `RepresentNodeOffsetZero()`:  Seems responsible for emitting characters (like newlines or tabs) to represent the positioning of elements.
    * Functions like `ShouldEmitNewlineForNode()`, `ShouldEmitTabBeforeNode()`: These help determine when to insert special characters.

5. **Connect to Web Technologies:**  Based on my understanding of the functions and the included headers, I started drawing connections to web technologies:
    * **HTML:** The code interacts heavily with HTML elements (e.g., `HTMLInputElement`, `HTMLImageElement`, `<div>`, `<p>`). The processing of block and inline elements, handling of `<br>` tags, and the emission of newlines are all related to how HTML is rendered.
    * **CSS:**  The code checks `layout_object` properties like `IsInline()`, `IsBlock()`, and `Style()->Visibility()`, indicating it considers CSS styling during iteration. The handling of `display: contents` is explicitly mentioned.
    * **JavaScript:** While this C++ file doesn't directly execute JavaScript, its functionality is crucial for features that JavaScript interacts with, like `window.find()`, selection APIs, and getting text content of elements.

6. **Identify Potential Usage Errors:** I thought about scenarios where incorrect input could lead to problems. Providing an invalid start or end position (where the end is before the start) is a clear error. The code even has a `CHECK_LE` to try and catch this.

7. **Consider Debugging Clues:**  The code's structure and the information it processes provide hints for debugging:
    * The start and end positions are key.
    * The `shadow_depth_` helps track the traversal of shadow DOM.
    * The `iteration_progress_` variable indicates where the iterator is in processing a node.
    * Understanding the logic in `Advance()` is crucial for stepping through the iteration process.

8. **Summarize the Functionality for Part 1:**  Based on my analysis up to the provided code snippet, I summarized the core function as providing a way to iterate over the text content of a DOM range, handling different node types, considering CSS layout, and supporting various iteration behaviors (like handling shadow DOM).

9. **Refine and Structure the Answer:**  I then organized my findings into the categories requested by the prompt: functionality, relation to web technologies, logical reasoning (input/output examples), common errors, debugging clues, and the summary. I tried to provide specific examples to illustrate each point. For logical reasoning, I created simple HTML snippets and described how the iterator would process them.

Essentially, I started with a high-level understanding, drilled down into the code's details, connected it to my knowledge of web technologies, and then synthesized the information into a structured answer. The process involved both deductive reasoning (from the code to its purpose) and inductive reasoning (from the code's behavior to potential use cases and errors).
好的，让我们来分析一下 `blink/renderer/core/editing/iterators/text_iterator.cc` 文件的功能。

**文件功能归纳 (第 1 部分):**

这个 C++ 源代码文件 `text_iterator.cc` 定义了一个名为 `TextIteratorAlgorithm` 的模板类，以及相关的辅助函数和结构体。该类的主要功能是**遍历 DOM 树结构，并以文本形式提取指定范围内的内容**。  它能够处理各种类型的 DOM 节点，包括文本节点和元素节点，并根据预设的行为标志 (`TextIteratorBehavior`) 来控制遍历的方式和输出的内容格式。

更具体地说，这个文件的代码实现了以下关键功能：

* **DOM 树的迭代:** 提供了一种深度优先的遍历算法，可以从指定的起始节点和偏移量迭代到指定的结束节点和偏移量。
* **文本内容的提取:**  能够从文本节点中提取文本内容。
* **特殊字符的处理:**  根据不同的 `TextIteratorBehavior` 选项，决定是否以及如何插入换行符、制表符、空格等特殊字符来表示元素的边界和布局。
* **替换元素 (Replaced Elements) 的处理:**  能够处理像 `<img>` 这样的替换元素，可以提取它们的 `alt` 属性文本，或者用特定的替代字符表示它们。
* **Shadow DOM 的处理:**  支持遍历 Shadow DOM 树，可以配置是否进入 Open Shadow Roots 和 User-Agent Shadow Roots。
* **表单控件的处理:**  能够识别和处理表单控件元素，并根据行为标志决定是否进入其内部结构。
* **`display: contents` 元素的处理:**  能够跳过 `display: contents` 元素本身的渲染盒子，但继续遍历其子节点。
* **选择 (Selection) 相关的功能:**  提供了一些专门用于处理文本选择的功能，例如排除自动填充的值。
* **性能优化:**  避免在不必要的时刻进行布局计算，并使用一些技巧来提高遍历效率。

**与 Javascript, HTML, CSS 的关系举例说明:**

这个 `TextIteratorAlgorithm` 类是 Blink 渲染引擎的核心组成部分，它为浏览器处理网页内容提供了基础能力。它与 JavaScript、HTML 和 CSS 的功能有密切关系：

* **HTML:**  `TextIteratorAlgorithm` 直接操作 HTML DOM 树。它需要理解各种 HTML 元素的结构和语义，例如：
    * **`<p>`, `<div>`, `<h1>` 等块级元素:** 在遍历到这些元素的边界时，会根据配置插入换行符，模拟块级元素的布局。
    * **`<img>` 元素:** 可以提取其 `alt` 属性的文本，这对于屏幕阅读器等辅助功能非常重要。
    * **`<br>` 元素:** 识别并处理换行符。
    * **`<table>`, `<tr>`, `<td>` 元素:**  在遍历表格时，可以插入制表符来分隔单元格内容。
    * **表单控件 (例如 `<input>`, `<textarea>`)**:  能够提取用户输入的值。

    **举例:**  当 JavaScript 代码使用 `document.getElementById('myDiv').textContent` 获取一个 `<div>` 元素的文本内容时，Blink 内部很可能使用类似 `TextIteratorAlgorithm` 的机制来遍历 `<div>` 元素及其子节点，并将提取到的文本拼接起来。

* **CSS:** `TextIteratorAlgorithm` 需要考虑 CSS 的渲染效果，例如：
    * **`display: none` 或 `visibility: hidden`:**  默认情况下，会跳过不可见的元素。
    * **`display: contents`:**  会跳过该元素的渲染盒子，但会遍历其子节点。
    * **Inline 和 Block 元素的布局:**  通过插入换行符、制表符等来模拟元素的布局结构。
    * **Shadow DOM:**  根据 CSS Shadow DOM 的规则进行遍历。

    **举例:** 如果一个 `<span>` 元素设置了 `display: none;`，那么 `TextIteratorAlgorithm` 在默认情况下遍历到该元素时不会提取其包含的文本。

* **JavaScript:** `TextIteratorAlgorithm` 的功能为浏览器提供了一些 JavaScript API 的底层实现，例如：
    * **`Selection API` (例如 `window.getSelection().toString()`):**  当用户选中一段文本并调用 `toString()` 方法时，Blink 内部会使用 `TextIteratorAlgorithm` 来遍历选区范围内的 DOM 节点并提取文本。
    * **`Range API`:** `TextIteratorAlgorithm` 可以基于 `Range` 对象进行迭代。
    * **`Node.textContent` 和 `Element.innerText`:** 这些属性的实现也依赖于类似的文本提取机制。
    * **`window.find()`:** 浏览器的查找功能需要遍历页面内容，`TextIteratorAlgorithm` 可以用于实现这一功能。

    **举例:**  假设 JavaScript 代码如下：

    ```javascript
    const range = document.createRange();
    range.selectNodeContents(document.body);
    const iterator = new TextIterator(range); // 实际上 JavaScript 中没有直接暴露 TextIterator，这里只是为了说明概念
    let text = '';
    while (!iterator.isDone()) {
      text += iterator.getText();
      iterator.next();
    }
    console.log(text);
    ```

    虽然 JavaScript 中没有直接暴露 `TextIterator` 类，但上述逻辑说明了 `TextIteratorAlgorithm` 背后的思想：遍历 DOM 树并提取文本。

**逻辑推理、假设输入与输出:**

假设我们有以下简单的 HTML 结构：

```html
<div>
  <p>Hello, <span>world</span>!</p>
  <img src="image.png" alt="An image">
</div>
```

如果我们创建一个 `TextIteratorAlgorithm` 实例来遍历 `<div>` 元素的内容，并且启用了默认的行为标志，那么：

* **假设输入 (起始和结束范围):**  起始位置为 `<div>` 元素的开始，结束位置为 `<div>` 元素的结尾。
* **逻辑推理:**
    1. 遍历到 `<p>` 元素，由于是块级元素，可能会在其前后添加换行符。
    2. 遍历到文本节点 "Hello, "，提取该文本。
    3. 遍历到 `<span>` 元素。
    4. 遍历到 `<span>` 内部的文本节点 "world"，提取该文本。
    5. 遍历到 `<span>` 元素的结束标签。
    6. 遍历到文本节点 "!"，提取该文本。
    7. 遍历到 `<p>` 元素的结束标签，可能会添加换行符。
    8. 遍历到 `<img>` 元素，如果行为标志允许，可能会提取其 `alt` 属性值 "An image"。
* **假设输出 (提取到的文本):**

    ```
    Hello, world!
    An image
    ```

    (实际输出可能因具体的 `TextIteratorBehavior` 设置而略有不同，例如换行符的数量)

**用户或编程常见的使用错误:**

* **创建范围错误:**  如果创建 `TextIteratorAlgorithm` 时提供的起始位置在结束位置之后，会导致未定义的行为或者断言失败。
* **不理解 `TextIteratorBehavior` 的影响:**  错误地配置 `TextIteratorBehavior` 可能导致输出的文本格式不符合预期，例如没有包含 Shadow DOM 的内容，或者没有正确处理替换元素。
* **在 DOM 结构发生变化时继续使用迭代器:**  如果在迭代过程中 DOM 结构发生了修改，迭代器的行为可能是不可预测的，可能会导致崩溃或提取到错误的内容。
* **忘记检查迭代器的结束状态:**  没有正确判断迭代器是否已经遍历到结尾，可能导致无限循环。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **用户在网页上进行文本选择 (例如，用鼠标拖拽)。**
3. **浏览器内核 (Blink) 接收到用户的选择操作。**
4. **Blink 需要获取用户选中的文本内容。**
5. **Blink 内部会创建一个表示选区的 `Range` 对象。**
6. **为了获取选区内的文本，Blink 可能会使用 `TextIteratorAlgorithm` (或者类似机制) 来遍历 `Range` 对象所包含的 DOM 节点。**
7. **在 `TextIteratorAlgorithm` 的实现过程中，代码会执行到 `text_iterator.cc` 文件中的相关逻辑，例如 `Advance()` 函数来移动到下一个节点，`HandleTextNode()` 来处理文本节点，等等。**

或者：

1. **用户在浏览器地址栏输入内容并按下回车键。**
2. **浏览器开始加载新的网页。**
3. **Blink 解析 HTML 内容并构建 DOM 树。**
4. **如果网页包含需要渲染的文本内容，Blink 的布局引擎会计算文本的布局。**
5. **在某些情况下 (例如，为了支持复制粘贴功能)，Blink 可能需要将渲染后的文本内容转换为纯文本格式。**
6. **此时，`TextIteratorAlgorithm` 就可能被用来遍历相关的 DOM 节点，并提取用于复制的文本。**

**总结 (第 1 部分功能):**

总而言之，`blink/renderer/core/editing/iterators/text_iterator.cc` 文件的主要功能是提供一个灵活且可配置的 DOM 树文本内容迭代器。它在 Blink 渲染引擎中扮演着核心角色，为诸如文本选择、复制粘贴、查找等功能提供了基础的文本提取能力。它需要深入理解 HTML 结构和 CSS 渲染规则，并能够处理各种复杂的 DOM 场景，包括 Shadow DOM 和表单控件。

### 提示词
```
这是目录为blink/renderer/core/editing/iterators/text_iterator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2005 Alexey Proskuryakov.
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

#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"

#include <unicode/utf16.h>

#include "build/build_config.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_meter_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

template <typename Strategy>
TextIteratorBehavior AdjustBehaviorFlags(const TextIteratorBehavior&);

template <>
TextIteratorBehavior AdjustBehaviorFlags<EditingStrategy>(
    const TextIteratorBehavior& behavior) {
  if (!behavior.ForSelectionToString())
    return behavior;
  return TextIteratorBehavior::Builder(behavior)
      .SetExcludeAutofilledValue(true)
      .Build();
}

template <>
TextIteratorBehavior AdjustBehaviorFlags<EditingInFlatTreeStrategy>(
    const TextIteratorBehavior& behavior) {
  return TextIteratorBehavior::Builder(behavior)
      .SetExcludeAutofilledValue(behavior.ForSelectionToString() ||
                                 behavior.ExcludeAutofilledValue())
      .SetEntersOpenShadowRoots(false)
      .Build();
}

static inline bool HasDisplayContents(const Node& node) {
  auto* element = DynamicTo<Element>(node);
  return element && element->HasDisplayContentsStyle();
}

// Checks if |advance()| skips the descendants of |node|, which is the case if
// |node| is neither a shadow root nor the owner of a layout object.
static bool NotSkipping(const Node& node) {
  return node.GetLayoutObject() || HasDisplayContents(node) ||
         (IsA<ShadowRoot>(node) && node.OwnerShadowHost()->GetLayoutObject());
}

template <typename Strategy>
const Node* StartNode(const Node* start_container, unsigned start_offset) {
  if (start_container->IsCharacterDataNode())
    return start_container;
  if (Node* child = Strategy::ChildAt(*start_container, start_offset))
    return child;
  if (!start_offset)
    return start_container;
  return Strategy::NextSkippingChildren(*start_container);
}

template <typename Strategy>
const Node* EndNode(const Node& end_container, unsigned end_offset) {
  if (!end_container.IsCharacterDataNode() && end_offset)
    return Strategy::ChildAt(end_container, end_offset - 1);
  return nullptr;
}

// This function is like Range::PastLastNode, except for the fact that it can
// climb up out of shadow trees and ignores all nodes that will be skipped in
// |advance()|.
template <typename Strategy>
const Node* PastLastNode(const Node& range_end_container,
                         unsigned range_end_offset) {
  if (!range_end_container.IsCharacterDataNode() &&
      NotSkipping(range_end_container)) {
    for (Node* next = Strategy::ChildAt(range_end_container, range_end_offset);
         next; next = Strategy::NextSibling(*next)) {
      if (NotSkipping(*next))
        return next;
    }
  }
  for (const Node* node = &range_end_container; node;) {
    const Node* parent = ParentCrossingShadowBoundaries<Strategy>(*node);
    if (parent && NotSkipping(*parent)) {
      if (Node* next = Strategy::NextSibling(*node))
        return next;
    }
    node = parent;
  }
  return nullptr;
}

// Figure out the initial value of shadow_depth_: the depth of start_container's
// tree scope from the common ancestor tree scope.
template <typename Strategy>
unsigned ShadowDepthOf(const Node& start_container, const Node& end_container);

template <>
unsigned ShadowDepthOf<EditingStrategy>(const Node& start_container,
                                        const Node& end_container) {
  const TreeScope* common_ancestor_tree_scope =
      start_container.GetTreeScope().CommonAncestorTreeScope(
          end_container.GetTreeScope());
  DCHECK(common_ancestor_tree_scope);
  unsigned shadow_depth = 0;
  for (const TreeScope* tree_scope = &start_container.GetTreeScope();
       tree_scope != common_ancestor_tree_scope;
       tree_scope = tree_scope->ParentTreeScope())
    ++shadow_depth;
  return shadow_depth;
}

template <>
unsigned ShadowDepthOf<EditingInFlatTreeStrategy>(const Node& start_container,
                                                  const Node& end_container) {
  return 0;
}

bool IsRenderedAsTable(const Node* node) {
  if (!node || !node->IsElementNode())
    return false;
  LayoutObject* layout_object = node->GetLayoutObject();
  return layout_object && layout_object->IsTable();
}

bool ShouldHandleChildren(const Node& node,
                          const TextIteratorBehavior& behavior) {
  // To support |TextIteratorEmitsImageAltText|, we don't traversal child
  // nodes, in flat tree.
  if (IsA<HTMLImageElement>(node))
    return false;
  // Traverse internals of text control elements in flat tree only when
  // |EntersTextControls| flag is set.
  if (!behavior.EntersTextControls() && IsTextControl(node))
    return false;

  if (!behavior.IgnoresDisplayLock()) {
    if (auto* element = DynamicTo<Element>(node)) {
      if (auto* context = element->GetDisplayLockContext()) {
        return !context->IsLocked() ||
               context->IsActivatable(DisplayLockActivationReason::kSelection);
      }
    }
  }
  return true;
}

}  // namespace

template <typename Strategy>
TextIteratorAlgorithm<Strategy>::TextIteratorAlgorithm(
    const EphemeralRangeTemplate<Strategy>& range,
    const TextIteratorBehavior& behavior)
    : TextIteratorAlgorithm(range.StartPosition(),
                            range.EndPosition(),
                            behavior) {}

template <typename Strategy>
TextIteratorAlgorithm<Strategy>::TextIteratorAlgorithm(
    const PositionTemplate<Strategy>& start,
    const PositionTemplate<Strategy>& end,
    const TextIteratorBehavior& behavior)
    : start_container_(start.ComputeContainerNode()),
      start_offset_(start.ComputeOffsetInContainerNode()),
      end_container_(end.ComputeContainerNode()),
      end_offset_(end.ComputeOffsetInContainerNode()),
      end_node_(EndNode<Strategy>(*end_container_, end_offset_)),
      past_end_node_(PastLastNode<Strategy>(*end_container_, end_offset_)),
      node_(StartNode<Strategy>(start_container_, start_offset_)),
      iteration_progress_(kHandledNone),
      shadow_depth_(
          ShadowDepthOf<Strategy>(*start_container_, *end_container_)),
      behavior_(AdjustBehaviorFlags<Strategy>(behavior)),
      text_state_(behavior_),
      text_node_handler_(behavior_, &text_state_) {
  DCHECK(start_container_);
  DCHECK(end_container_);

  // TODO(dglazkov): TextIterator should not be created for documents that don't
  // have a frame, but it currently still happens in some cases. See
  // http://crbug.com/591877 for details.
  DCHECK(!start.GetDocument()->View() ||
         !start.GetDocument()->View()->NeedsLayout());
  DCHECK(!start.GetDocument()->NeedsLayoutTreeUpdate());
  // To avoid renderer hang, we use |CHECK_LE()| to catch the bad callers
  // in release build.
  CHECK_LE(start, end);

  if (!node_)
    return;

  fully_clipped_stack_.SetUpFullyClippedStack(node_);

  // Identify the first run.
  Advance();
}

template <typename Strategy>
TextIteratorAlgorithm<Strategy>::~TextIteratorAlgorithm() {
  if (!handle_shadow_root_)
    return;
  const Document& document = OwnerDocument();
  if (behavior_.ForSelectionToString())
    document.CountUse(WebFeature::kSelectionToStringWithShadowTree);
  if (behavior_.ForWindowFind())
    document.CountUse(WebFeature::kWindowFindWithShadowTree);
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::IsInsideAtomicInlineElement() const {
  if (AtEnd() || length() != 1 || !node_)
    return false;

  LayoutObject* layout_object = node_->GetLayoutObject();
  return layout_object && layout_object->IsAtomicInlineLevel();
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::HandleRememberedProgress() {
  // Handle remembered node that needed a newline after the text node's newline
  if (needs_another_newline_) {
    // Emit the extra newline, and position it *inside* node_, after node_'s
    // contents, in case it's a block, in the same way that we position the
    // first newline. The range for the emitted newline should start where the
    // line break begins.
    // FIXME: It would be cleaner if we emitted two newlines during the last
    // iteration, instead of using needs_another_newline_.
    Node* last_child = Strategy::LastChild(*node_);
    const Node* base_node = last_child ? last_child : node_;
    EmitChar16AfterNode('\n', *base_node);
    needs_another_newline_ = false;
    return true;
  }

  if (needs_handle_replaced_element_) {
    HandleReplacedElement();
    if (text_state_.PositionNode())
      return true;
  }

  // Try to emit more text runs if we are handling a text node.
  return text_node_handler_.HandleRemainingTextRuns();
}

template <typename Strategy>
void TextIteratorAlgorithm<Strategy>::Advance() {
  if (should_stop_)
    return;

  if (node_)
    DCHECK(!node_->GetDocument().NeedsLayoutTreeUpdate()) << node_;

  text_state_.ResetRunInformation();

  if (HandleRememberedProgress())
    return;

  while (node_ && (node_ != past_end_node_ || shadow_depth_)) {
    // TODO(crbug.com/1296290): Disable this DCHECK as it's troubling CrOS engs.
#if DCHECK_IS_ON() && !BUILDFLAG(IS_CHROMEOS)
    // |node_| shouldn't be after |past_end_node_|.
    if (past_end_node_) {
      DCHECK_LE(PositionTemplate<Strategy>(node_, 0),
                PositionTemplate<Strategy>(past_end_node_, 0));
    }
#endif

    if (!should_stop_ && StopsOnFormControls() &&
        HTMLFormControlElement::EnclosingFormControlElement(node_))
      should_stop_ = true;

    // if the range ends at offset 0 of an element, represent the
    // position, but not the content, of that element e.g. if the
    // node is a blockflow element, emit a newline that
    // precedes the element
    if (node_ == end_container_ && !end_offset_) {
      RepresentNodeOffsetZero();
      node_ = nullptr;
      return;
    }

    // If an element is locked, we shouldn't recurse down into its children
    // since they might not have up-to-date layout. In particular, they might
    // not have the NG offset mapping which is required. The display lock can
    // still be bypassed by marking the iterator behavior to ignore display
    // lock.
    const bool locked =
        !behavior_.IgnoresDisplayLock() &&
        DisplayLockUtilities::LockedInclusiveAncestorPreventingLayout(*node_);

    LayoutObject* layout_object = node_->GetLayoutObject();
    if (!layout_object || locked) {
      if (!locked && (IsA<ShadowRoot>(node_) || HasDisplayContents(*node_))) {
        // Shadow roots or display: contents elements don't have LayoutObjects,
        // but we want to visit children anyway.
        iteration_progress_ = iteration_progress_ < kHandledNode
                                  ? kHandledNode
                                  : iteration_progress_;
        handle_shadow_root_ = IsA<ShadowRoot>(node_);
      } else {
        iteration_progress_ = kHandledChildren;
      }
    } else {
      // Enter author shadow roots, from youngest, if any and if necessary.
      if (iteration_progress_ < kHandledOpenShadowRoots) {
        auto* element = DynamicTo<Element>(node_);
        if (std::is_same<Strategy, EditingStrategy>::value &&
            EntersOpenShadowRoots() && element && element->OpenShadowRoot()) {
          ShadowRoot* youngest_shadow_root = element->OpenShadowRoot();
          DCHECK(youngest_shadow_root->IsOpen());
          node_ = youngest_shadow_root;
          iteration_progress_ = kHandledNone;
          ++shadow_depth_;
          fully_clipped_stack_.PushFullyClippedState(node_);
          continue;
        }

        iteration_progress_ = kHandledOpenShadowRoots;
      }

      // Enter user-agent shadow root, if necessary.
      if (iteration_progress_ < kHandledUserAgentShadowRoot) {
        if (std::is_same<Strategy, EditingStrategy>::value &&
            EntersTextControls() && layout_object->IsTextControl()) {
          ShadowRoot* user_agent_shadow_root =
              To<Element>(node_)->UserAgentShadowRoot();
          DCHECK(user_agent_shadow_root->IsUserAgent());
          node_ = user_agent_shadow_root;
          iteration_progress_ = kHandledNone;
          ++shadow_depth_;
          fully_clipped_stack_.PushFullyClippedState(node_);
          continue;
        }
        iteration_progress_ = kHandledUserAgentShadowRoot;
      }

      // Handle the current node according to its type.
      if (iteration_progress_ < kHandledNode) {
        if (!SkipsUnselectableContent() || layout_object->IsSelectable()) {
          auto* html_element = DynamicTo<HTMLElement>(*node_);
          if (layout_object->IsText() &&
              node_->getNodeType() ==
                  Node::kTextNode) {  // FIXME: What about kCdataSectionNode?
            if (!fully_clipped_stack_.Top() || IgnoresStyleVisibility())
              HandleTextNode();
          } else if (layout_object &&
                     (layout_object->IsImage() ||
                      layout_object->IsLayoutEmbeddedContent() ||
                      (html_element &&
                       (IsA<HTMLFormControlElement>(html_element) ||
                        IsA<HTMLLegendElement>(html_element) ||
                        IsA<HTMLImageElement>(html_element) ||
                        IsA<HTMLMeterElement>(html_element) ||
                        IsA<HTMLProgressElement>(html_element))))) {
            HandleReplacedElement();
          } else {
            HandleNonTextNode();
          }
        }
        iteration_progress_ = kHandledNode;
        if (text_state_.PositionNode())
          return;
      }
    }

    // Find a new current node to handle in depth-first manner,
    // calling exitNode() as we come back thru a parent node.
    //
    // 1. Iterate over child nodes, if we haven't done yet.
    Node* next = iteration_progress_ < kHandledChildren &&
                         ShouldHandleChildren(*node_, behavior_)
                     ? Strategy::FirstChild(*node_)
                     : nullptr;
    if (!next) {
      // We are skipping children, check that |past_end_node_| is not a
      // descendant, since we shouldn't iterate past it.
      if (past_end_node_ && Strategy::IsDescendantOf(*past_end_node_, *node_)) {
        node_ = past_end_node_;
        iteration_progress_ = kHandledNone;
        fully_clipped_stack_.Pop();
        DCHECK(AtEnd());
        return;
      }

      // 2. If we've already iterated children or they are not available, go
      // to the next sibling node.
      next = Strategy::NextSibling(*node_);
      if (!next) {
        // 3. If we are at the last child, go up the node tree until we find a
        // next sibling.
        ContainerNode* parent_node = Strategy::Parent(*node_);
        while (!next && parent_node) {
          if (node_ == end_node_ ||
              Strategy::IsDescendantOf(*end_container_, *parent_node)) {
            return;
          }
          // We should call the ExitNode() always if |node_| has a layout
          // object or not and it's the last child under |parent_node|.
          bool have_layout_object = node_->GetLayoutObject();
          node_ = parent_node;
          fully_clipped_stack_.Pop();
          parent_node = Strategy::Parent(*node_);
          if (RuntimeEnabledFeatures::
                  CallExitNodeWithoutLayoutObjectEnabled() ||
              have_layout_object) {
            ExitNode();
          }
          if (text_state_.PositionNode()) {
            iteration_progress_ = kHandledChildren;
            return;
          }
          next = Strategy::NextSibling(*node_);
        }

        if (!next && !parent_node && shadow_depth_) {
          // 4. Reached the top of a shadow root. If it's created by author,
          // then try to visit the next
          // sibling shadow root, if any.
          const auto* shadow_root = DynamicTo<ShadowRoot>(node_);
          if (!shadow_root) {
            NOTREACHED();
          }
          if (shadow_root->IsOpen()) {
            // We are the shadow root; exit from here and go back to
            // where we were.
            node_ = &shadow_root->host();
            iteration_progress_ = kHandledOpenShadowRoots;
            --shadow_depth_;
            fully_clipped_stack_.Pop();
          } else {
            // If we are in a closed or user-agent shadow root, then go back
            // to the host.
            // TODO(kochi): Make sure we treat closed shadow as user agent
            // shadow here.
            DCHECK(shadow_root->GetMode() == ShadowRootMode::kClosed ||
                   shadow_root->IsUserAgent());
            node_ = &shadow_root->host();
            iteration_progress_ = kHandledUserAgentShadowRoot;
            --shadow_depth_;
            fully_clipped_stack_.Pop();
          }
          continue;
        }
      }
      fully_clipped_stack_.Pop();
    }

    // set the new current node
    node_ = next;
    if (node_)
      fully_clipped_stack_.PushFullyClippedState(node_);
    iteration_progress_ = kHandledNone;

    // how would this ever be?
    if (text_state_.PositionNode())
      return;
  }
}

template <typename Strategy>
void TextIteratorAlgorithm<Strategy>::HandleTextNode() {
  if (ExcludesAutofilledValue()) {
    TextControlElement* control = EnclosingTextControl(node_);
    // For security reason, we don't expose suggested value if it is
    // auto-filled.
    // TODO(crbug.com/1472209): Only hide suggested value of previews.
    if (control && (control->IsAutofilled() || control->IsPreviewed())) {
      return;
    }
  }

  DCHECK_NE(last_text_node_, node_)
      << "We should never call HandleTextNode on the same node twice";
  const auto* text = To<Text>(node_);
  last_text_node_ = text;

  // TODO(editing-dev): Introduce a |DOMOffsetRange| class so that we can pass
  // an offset range with unbounded endpoint(s) in an easy but still clear way.
  if (node_ != start_container_) {
    if (node_ != end_container_)
      text_node_handler_.HandleTextNodeWhole(text);
    else
      text_node_handler_.HandleTextNodeEndAt(text, end_offset_);
    return;
  }
  if (node_ != end_container_) {
    text_node_handler_.HandleTextNodeStartFrom(text, start_offset_);
    return;
  }
  text_node_handler_.HandleTextNodeInRange(text, start_offset_, end_offset_);
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::SupportsAltText(const Node& node) {
  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;

  // FIXME: Add isSVGImageElement.
  if (IsA<HTMLImageElement>(*element))
    return true;

  auto* html_input_element = DynamicTo<HTMLInputElement>(element);
  if (html_input_element &&
      html_input_element->FormControlType() == FormControlType::kInputImage) {
    return true;
  }
  return false;
}

template <typename Strategy>
void TextIteratorAlgorithm<Strategy>::HandleReplacedElement() {
  needs_handle_replaced_element_ = false;

  if (fully_clipped_stack_.Top())
    return;

  LayoutObject* layout_object = node_->GetLayoutObject();
  if (layout_object->Style()->Visibility() != EVisibility::kVisible &&
      !IgnoresStyleVisibility()) {
    return;
  }

  if (EmitsObjectReplacementCharacter()) {
    EmitChar16AsNode(kObjectReplacementCharacter, *node_);
    return;
  }

  DCHECK_EQ(last_text_node_, text_node_handler_.GetNode());

  if (EntersTextControls() && layout_object->IsTextControl()) {
    // The shadow tree should be already visited.
    return;
  }

  if (EmitsCharactersBetweenAllVisiblePositions()) {
    // We want replaced elements to behave like punctuation for boundary
    // finding, and to simply take up space for the selection preservation
    // code in moveParagraphs, so we use a comma.
    EmitChar16AsNode(',', *node_);
    return;
  }

  if (EmitsImageAltText() && TextIterator::SupportsAltText(*node_)) {
    text_state_.EmitAltText(To<HTMLElement>(*node_));
    return;
  }
  // TODO(editing-dev): We can remove |UpdateForReplacedElement()| call when
  // we address web test failures (text diff by newlines only) and unit
  // tests, e.g. TextIteratorTest.IgnoreAltTextInTextControls.
  text_state_.UpdateForReplacedElement(*node_);
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::ShouldEmitTabBeforeNode(
    const Node& node) {
  LayoutObject* r = node.GetLayoutObject();

  // Table cells are delimited by tabs.
  if (!r || !IsTableCell(&node))
    return false;

  // Want a tab before every cell other than the first one
  const auto* rc = To<LayoutTableCell>(r);
  const LayoutTable* t = rc->Table();
  return t && !t->IsFirstCell(*rc);
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::ShouldEmitNewlineForNode(
    const Node& node,
    bool emits_original_text) {
  LayoutObject* layout_object = node.GetLayoutObject();

  if (layout_object ? !layout_object->IsBR() : !IsA<HTMLBRElement>(node))
    return false;
  return emits_original_text ||
         !(node.IsInShadowTree() &&
           IsA<HTMLInputElement>(*node.OwnerShadowHost()));
}

static bool ShouldEmitNewlinesBeforeAndAfterNode(const Node& node) {
  // Block flow (versus inline flow) is represented by having
  // a newline both before and after the element.
  LayoutObject* r = node.GetLayoutObject();
  if (!r) {
    if (HasDisplayContents(node))
      return false;
    return (node.HasTagName(html_names::kBlockquoteTag) ||
            node.HasTagName(html_names::kDdTag) ||
            node.HasTagName(html_names::kDivTag) ||
            node.HasTagName(html_names::kDlTag) ||
            node.HasTagName(html_names::kDtTag) ||
            node.HasTagName(html_names::kH1Tag) ||
            node.HasTagName(html_names::kH2Tag) ||
            node.HasTagName(html_names::kH3Tag) ||
            node.HasTagName(html_names::kH4Tag) ||
            node.HasTagName(html_names::kH5Tag) ||
            node.HasTagName(html_names::kH6Tag) ||
            node.HasTagName(html_names::kHrTag) ||
            node.HasTagName(html_names::kLiTag) ||
            node.HasTagName(html_names::kListingTag) ||
            node.HasTagName(html_names::kOlTag) ||
            node.HasTagName(html_names::kPTag) ||
            node.HasTagName(html_names::kPreTag) ||
            node.HasTagName(html_names::kTrTag) ||
            node.HasTagName(html_names::kUlTag));
  }

  // Need to make an exception for option and optgroup, because we want to
  // keep the legacy behavior before we added layoutObjects to them.
  if (IsA<HTMLOptionElement>(node) || IsA<HTMLOptGroupElement>(node))
    return false;

  // Need to make an exception for table cells, because they are blocks, but we
  // want them tab-delimited rather than having newlines before and after.
  if (IsTableCell(&node))
    return false;

  // Need to make an exception for table row elements, because they are neither
  // "inline" or "LayoutBlock", but we want newlines for them.
  if (r->IsTableRow()) {
    const LayoutTable* t = To<LayoutTableRow>(r)->Table();
    if (t && !t->IsInline()) {
      return true;
    }
  }

  return !r->IsInline() && r->IsLayoutBlock() &&
         !r->IsFloatingOrOutOfFlowPositioned() && !r->IsBody();
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::ShouldEmitNewlineAfterNode(
    const Node& node) {
  // FIXME: It should be better but slower to create a VisiblePosition here.
  if (!ShouldEmitNewlinesBeforeAndAfterNode(node))
    return false;
  // Check if this is the very last layoutObject in the document.
  // If so, then we should not emit a newline.
  const Node* next = &node;
  do {
    next = Strategy::NextSkippingChildren(*next);
    if (next && next->GetLayoutObject())
      return true;
  } while (next);
  return false;
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::ShouldEmitNewlineBeforeNode(
    const Node& node) {
  return ShouldEmitNewlinesBeforeAndAfterNode(node);
}

static bool ShouldEmitExtraNewlineForNode(const Node* node) {
  // https://html.spec.whatwg.org/C/#the-innertext-idl-attribute
  // Append two required linebreaks after a P element.
  LayoutObject* r = node->GetLayoutObject();
  if (!r || !r->IsBox())
    return false;

  return node->HasTagName(html_names::kPTag);
}

// Whether or not we should emit a character as we enter node_ (if it's a
// container) or as we hit it (if it's atomic).
template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::ShouldRepresentNodeOffsetZero() {
  if (EmitsCharactersBetweenAllVisiblePositions() && IsRenderedAsTable(node_))
    return true;

  // Leave element positioned flush with start of a paragraph
  // (e.g. do not insert tab before a table cell at the start of a paragraph)
  if (text_state_.LastCharacter() == '\n')
    return false;

  // Otherwise, show the position if we have emitted any characters
  if (text_state_.HasEmitted())
    return true;

  // We've not emitted anything yet. Generally, there is no need for any
  // positioning then. The only exception is when the element is visually not in
  // the same line as the start of the range (e.g. the range starts at the end
  // of the previous paragraph).
  // NOTE: Creating VisiblePositions and comparing them is relatively expensive,
  // so we make quicker checks to possibly avoid that. Another check that we
  // could make is is whether the inline vs block flow changed since the
  // previous visible element. I think we're already in a special enough case
  // that that won't be needed, tho.

  // No character needed if this is the first node in the range.
  if (node_ == start_container_)
    return false;

  // If we are outside the start container's subtree, assume we need to emit.
  // FIXME: start_container_ could be an inline block
  if (!Strategy::IsDescendantOf(*node_, *start_container_))
    return true;

  // If we started as start_container_ offset 0 and the current node is a
  // descendant of the start container, we already had enough context to
  // correctly decide whether to emit after a preceding block. We chose not to
  // emit (has_emitted_ is false), so don't second guess that now.
  // NOTE: Is this really correct when node_ is not a leftmost descendant?
  // Probably immaterial since we likely would have already emitted something by
  // now.
  if (!start_offset_)
    return false;

  // If this node is unrendered or invisible the VisiblePosition checks below
  // won't have much meaning.
  // Additionally, if the range we are iterating over contains huge sections of
  // unrendered content, we would create VisiblePositions on every call to this
  // function without this check.
  if (!node_->GetLayoutObject() ||
      node_->GetLayoutObject()->Style()->Visibility() !=
          EVisibility::kVisible ||
      (node_->GetLayoutObject()->IsLayoutBlockFlow() &&
       !To<LayoutBlock>(node_->GetLayoutObject())->Size().height &&
       !IsA<HTMLBodyElement>(*node_))) {
    return false;
  }

  // The startPos.isNotNull() check is needed because the start could be before
  // the body, and in that case we'll get null. We don't want to put in newlines
  // at the start in that case.
  // The currPos.isNotNull() check is needed because positions in non-HTML
  // content (like SVG) do not have visible positions, and we don't want to emit
  // for them either.
  const VisiblePositionTemplate<Strategy> start_pos = CreateVisiblePosition(
      PositionTemplate<Strategy>(start_container_, start_offset_));
  const VisiblePositionTemplate<Strategy> curr_pos =
      VisiblePositionTemplate<Strategy>::BeforeNode(*node_);
  return start_pos.IsNotNull() && curr_pos.IsNotNull() &&
         !InSameLine(start_pos, curr_pos);
}

template <typename Strategy>
bool TextIteratorAlgorithm<Strategy>::ShouldEmitSpaceBeforeAndAfterNode(
    const Node& node) {
  return IsRenderedAsTable(&node) &&
         (node.GetLayoutObject()->IsInline() ||
          EmitsCharactersBetweenAllVisiblePositions());
}

template <typename Strategy>
void TextIteratorAlgorithm<Strategy>::RepresentNodeOffsetZero() {
  // Emit a character to show the positioning of node_.

  // TODO(editing-dev): We should rewrite this below code fragment to utilize
  // early-return style.
  // When we haven't been emitting any characters,
  // ShouldRepresentNodeOffsetZero() can create VisiblePositions, which is
  // expensive. So, we perform the inexpensive checks on |node_| to see if it
  // necessitates emitting a character first and will early return before
  // encountering ShouldRepresentNodeOffsetZero()s worse case behavior.
  if (ShouldEmitTabBeforeNode(*node_)) {
    if (ShouldRepresentNodeOffsetZero())
      EmitChar16BeforeNode('\t', *node_);
  } else if (ShouldEmitNewlineBeforeNode(*node_)) {
    if (ShouldRepresentNodeOffsetZero())
      EmitChar16BeforeNode('\n', *node_);
  } else if (ShouldEmitSpaceBeforeAndAfterNode(*node_)) {
    if (ShouldRepresentNodeOffsetZero())
      EmitChar16BeforeNode(kSpaceCharacter, *node_);
  }
}

template <typename Strategy>
void TextIteratorAlgorithm<Strategy>::HandleNonTextNode() {
  if (ShouldEmitNewlineForNode(*node_, EmitsOriginalText()))
    EmitChar16AsNode('\n', *node_);
  else if (EmitsCharactersBetweenAllVisiblePositions() &&
           node_->GetLayoutObject() && node_->GetLayoutObject()->IsHR())
    EmitChar16AsNode(kSpaceCharacter, *node_);
  else
    RepresentNodeOffsetZero();
}

templ
```
Response:
Let's break down the thought process for analyzing this C++ code snippet. The goal is to understand its function and how it relates to web technologies.

**1. Initial Scan and Keywords:**

* I first scanned the file path: `blink/renderer/core/editing/element_inner_text.cc`. The `editing` directory suggests this code is involved in text manipulation within the browser's rendering engine (Blink). `element_inner_text` clearly points to handling the `innerText` property of HTML elements.
* I then looked for key terms and data structures within the code itself: `Element`, `Text`, `LayoutObject`, `ComputedStyle`, `TextVisitor`, `StringBuilder`, `HTMLSelectElement`, `HTMLOptionElement`, `display`, `visibility`. These terms provide clues about the code's purpose and the web technologies it interacts with.

**2. Identifying the Core Class:**

* The code defines a class named `ElementInnerTextCollector`. The comment preceding its definition explicitly states: "// The implementation of Element#innerText algorithm[1]." This is a crucial piece of information. It confirms the class's primary responsibility: implementing the `innerText` behavior.

**3. Understanding the Algorithm's Goal:**

* The comment points to the HTML specification for `innerText`. This directs us to the official definition of how `innerText` should work. The core idea is to get the rendered text content of an element, taking into account CSS styling, including `display` and `visibility`.

**4. Analyzing Key Methods:**

* **`RunOn(const Element& element)`:** This is likely the entry point of the algorithm. It takes an `Element` as input. The checks for `DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint` and `!IsBeingRendered(element)` are important. They indicate the algorithm considers whether the element is visible and rendered.
* **`ProcessChildren(const Node& node)`:** This suggests a recursive or iterative approach to traverse the element's children.
* **`ProcessTextNode(const Text& node)`:** This function specifically handles `Text` nodes, which contain the actual textual content.
* **`ProcessLayoutText(const LayoutText& layout_text, const Text& text_node)`:** This indicates the algorithm interacts with the layout tree (`LayoutText`) to understand how the text is rendered.
* **`ProcessOptionElement(const HTMLOptionElement& element)` and `ProcessSelectElement(const HTMLSelectElement& element)`:** These methods show special handling for `<select>` and `<option>` elements, which have unique rendering behaviors and often involve shadow DOM.
* **`IsBeingRendered(const Node& node)` and `IsDisplayBlockLevel(const Node&)`:** These helper functions clarify how the algorithm determines if an element is rendered and its display type, both crucial for `innerText`'s behavior.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The very existence of this code is to implement the `innerText` JavaScript property. This immediately establishes a strong connection. I looked for how the output is generated (`StringBuilder`) and how it relates to the string returned by the JavaScript property.
* **HTML:** The code explicitly handles various HTML elements like `<br>`, `<p>`, `<select>`, `<option>`, `<table>`, `<tr>`, `<td>`, etc. The logic for inserting newlines and tabs is directly related to how these elements are rendered and how their content should be presented when accessed via `innerText`.
* **CSS:** The code checks for CSS properties like `display` and `visibility`. The behavior of `innerText` is heavily influenced by these styles. The comments mentioning "block-level," "table-cell," and "table-row" directly link to CSS display values.

**6. Logical Reasoning and Assumptions:**

* **Input/Output:** I considered simple HTML structures and how `innerText` would behave. For example, a `<p>` tag causing double newlines or `<br>` causing a single newline. This helps formulate example inputs and expected outputs.
* **Assumptions:**  I assumed the code correctly implements the HTML specification. I also assumed the included header files (`.h`) provide necessary interfaces and data structures.

**7. Identifying Potential Errors:**

* I looked for cases where the code might deviate from the specification or where user actions could lead to unexpected behavior. The handling of `display: contents` and the comments about potential issues with `OffsetMapping` were good starting points. The "user setting `display: none`" scenario is a common pitfall.

**8. Tracing User Actions:**

* I thought about how a user's interaction could trigger this code. Simply accessing the `innerText` property via JavaScript is the most direct way. I considered the steps involved in the browser's rendering process that lead to the execution of this C++ code.

**9. Structuring the Explanation:**

* I organized my findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Potential Errors, and Debugging Clues. This makes the explanation clear and easy to understand.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the low-level implementation details. However, the prompt specifically asked about the *functionality* and *relationship* to web technologies. So, I shifted my focus to the higher-level purpose and how it connects to JavaScript, HTML, and CSS.
* The comments in the code were very helpful in guiding my understanding. I paid close attention to them, especially the references to the HTML specification and bug trackers.
* I made sure to provide concrete examples for each relationship with web technologies, which is more helpful than just stating a general connection.

By following this structured analysis, I was able to effectively understand and explain the functionality of the provided C++ code snippet in the context of web development.
这个C++源代码文件 `element_inner_text.cc` 位于 Chromium Blink 引擎中，负责实现 HTML 元素的 `innerText` 属性的获取逻辑。

**功能列举:**

1. **获取元素的渲染文本内容:**  `innerText` 的核心功能是返回元素及其后代的**渲染后**的文本内容。这与 `textContent` 不同，`textContent` 会返回所有文本内容，包括被 CSS 隐藏的或不可见的。
2. **遵循 HTML 规范:** 该文件中的代码严格遵循 WHATWG HTML 规范中定义的 `innerText` 算法。
3. **处理不同类型的节点:**  能够处理各种类型的 DOM 节点，包括：
    * **文本节点 (`Text`)**: 直接提取文本内容。
    * **换行符元素 (`<br>`)**: 插入换行符 (`\n`)。
    * **块级元素 (如 `<p>`, `div`)**: 在其内容前后插入换行符。
    * **表格相关元素 (`<table>`, `<tr>`, `<td>`)**:  根据表格结构插入换行符和制表符 (`\t`)。
    * **`select` 和 `option` 元素**: 特殊处理，只包含可见的选项文本。
4. **考虑 CSS 样式:**  `innerText` 的行为受 CSS 样式的影响，例如：
    * **`display: none` 或 `visibility: hidden`**: 这些元素的内容不会被包含在 `innerText` 中。
    * **`display: contents`**: 按照规范进行特殊处理。
5. **处理 Display Lock:** 如果元素或其祖先被 Display Lock 锁定，则返回空字符串。
6. **使用 `TextVisitor` (可选):** 允许通过 `TextVisitor` 接口在遍历过程中收集额外的信息，例如文本的位置。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  该文件是 JavaScript 中 `element.innerText` 属性的底层实现。当 JavaScript 代码访问一个元素的 `innerText` 属性时，Blink 引擎会调用此文件中的 C++ 代码来计算返回值。
    * **举例:**
      ```javascript
      const myDiv = document.getElementById('myDiv');
      const text = myDiv.innerText; // JavaScript 代码触发了 element_inner_text.cc 中的逻辑
      console.log(text);
      ```

* **HTML:**  `innerText` 操作的是 HTML 元素。该文件需要理解不同 HTML 元素的渲染特性，例如 `<br>` 会产生换行，`<p>` 会产生段落间距等。
    * **举例:**
      ```html
      <div id="myDiv">
        <p>This is a paragraph.</p>
        <span>This is inline text.<br>With a line break.</span>
        <table>
          <tr><td>Cell 1</td><td>Cell 2</td></tr>
          <tr><td>Cell 3</td><td>Cell 4</td></tr>
        </table>
      </div>
      ```
      如果 JavaScript 获取 `myDiv.innerText`，`element_inner_text.cc` 会处理 `<p>`, `<br>`, `<table>`, `<tr>`, `<td>` 等元素，并根据它们的渲染方式生成文本内容，例如：
      ```
      This is a paragraph.

      This is inline text.
      With a line break.
      Cell 1	Cell 2
      Cell 3	Cell 4
      ```

* **CSS:**  元素的 CSS 样式直接影响 `innerText` 的结果。
    * **举例:**
      ```html
      <div id="hiddenDiv" style="display: none;">This text is hidden.</div>
      <div id="visibleDiv">This text is visible.</div>
      ```
      ```javascript
      const hiddenText = document.getElementById('hiddenDiv').innerText; // hiddenText 将为空字符串
      const visibleText = document.getElementById('visibleDiv').innerText; // visibleText 将为 "This text is visible."
      ```
      `element_inner_text.cc` 中的代码会检查元素的 `display` 和 `visibility` 属性，从而决定是否包含其内容。

**逻辑推理与假设输入/输出:**

假设我们有以下 HTML 结构：

```html
<div id="container">
  <span>Hello</span>
  <br>
  World
  <p>Another paragraph</p>
</div>
```

**假设输入:**  `Element` 对象对应于 ID 为 "container" 的 `div` 元素。

**逻辑推理过程 (简化):**

1. **遍历子节点:**  遍历 `div` 的子节点：`span`，`br`，文本节点 "World"，`p`。
2. **处理 `span`:**  提取 `span` 的文本内容 "Hello"。
3. **处理 `br`:**  插入换行符 `\n`。
4. **处理文本节点:**  提取文本内容 "World"。
5. **处理 `p`:**  由于 `p` 是块级元素，在其内容前后插入换行符。提取 `p` 的文本内容 "Another paragraph"。

**预期输出:**

```
Hello
World
Another paragraph
```

**用户或编程常见的使用错误举例说明:**

1. **混淆 `innerText` 和 `textContent`:** 开发者可能会错误地认为 `innerText` 会返回所有文本内容，而忽略了 CSS 样式的影响。
    * **错误示例:**
      ```html
      <div style="display: none;">Hidden Text</div>
      <script>
        const div = document.querySelector('div');
        console.log(div.innerText);   // 输出空字符串
        console.log(div.textContent); // 输出 "Hidden Text"
      </script>
      ```
2. **期望获取隐藏元素的文本:**  尝试使用 `innerText` 获取 `display: none` 或 `visibility: hidden` 元素的文本内容将会失败。
3. **不理解表格元素的 `innerText` 行为:**  表格元素的 `innerText` 会使用制表符分隔单元格内容，换行符分隔行，这可能与开发者直接拼接字符串的预期不同。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户与网页交互:** 用户在浏览器中加载网页并进行操作，例如点击按钮、提交表单等。
2. **JavaScript 代码执行:**  用户的操作可能触发 JavaScript 代码的执行。
3. **访问 `innerText` 属性:**  JavaScript 代码中可能存在访问某个 DOM 元素的 `innerText` 属性的操作，例如：
   ```javascript
   document.getElementById('myElement').innerText;
   ```
4. **Blink 引擎处理:** 浏览器引擎 (Blink) 接收到获取 `innerText` 的请求。
5. **样式和布局计算:**  Blink 引擎需要确保元素的样式和布局信息是最新的，因为 `innerText` 的结果依赖于渲染后的状态。这可能涉及到样式计算 (style recalc) 和布局 (layout)。
6. **调用 `element_inner_text.cc` 代码:**  Blink 引擎内部会调用 `blink/renderer/core/editing/element_inner_text.cc` 文件中的相关代码来执行 `innerText` 的算法。
7. **DOM 树遍历和处理:**  `ElementInnerTextCollector` 类会遍历目标元素的子节点，并根据节点类型和样式进行处理。
8. **构建结果字符串:**  `Result` 类负责构建最终的文本字符串。
9. **返回结果给 JavaScript:**  计算出的文本字符串会返回给 JavaScript 代码。

**作为调试线索:**

* **断点设置:**  在 `element_inner_text.cc` 的关键函数中设置断点，例如 `ElementInnerTextCollector::RunOn`，`ProcessNode`，`ProcessTextNode` 等，可以跟踪 `innerText` 的计算过程。
* **查看调用堆栈:**  当程序执行到 `element_inner_text.cc` 中的代码时，查看调用堆栈可以了解是哪个 JavaScript 代码触发了 `innerText` 的访问。
* **检查元素样式和布局:**  使用浏览器的开发者工具检查目标元素的 CSS 样式和布局信息，确认 `display` 和 `visibility` 等属性是否符合预期。
* **分析 DOM 树结构:**  使用开发者工具查看元素的 DOM 树结构，了解其子节点的类型和内容，有助于理解 `innerText` 的计算逻辑。
* **使用 `TextVisitor` 进行更细粒度的跟踪:** 如果需要更详细的文本处理过程信息，可以自定义 `TextVisitor` 并传递给 `innerText` 方法进行跟踪。

总而言之，`element_inner_text.cc` 是 Blink 引擎中一个关键的组成部分，它负责实现 `innerText` 这一常用的 JavaScript 属性，并且其行为与 HTML 结构和 CSS 样式紧密相关。理解其功能和实现原理有助于开发者更好地理解和使用 `innerText`，并在出现问题时进行调试。

Prompt: 
```
这是目录为blink/renderer/core/editing/element_inner_text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/element.h"

#include <algorithm>

#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/text_visitor.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_paragraph_element.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

// The implementation of Element#innerText algorithm[1].
// [1]
// https://html.spec.whatwg.org/C/#the-innertext-idl-attribute
class ElementInnerTextCollector final {
  STACK_ALLOCATED();

 public:
  explicit ElementInnerTextCollector(TextVisitor* visitor)
      : visitor_(visitor) {}
  ElementInnerTextCollector(const ElementInnerTextCollector&) = delete;
  ElementInnerTextCollector& operator=(const ElementInnerTextCollector&) =
      delete;

  String RunOn(const Element& element);

 private:
  // Result characters of innerText collection steps.
  class Result final {
   public:
    Result() = default;
    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;

    void EmitNewline();
    void EmitRequiredLineBreak(wtf_size_t count);
    void EmitTab();
    void EmitText(const StringView& text);
    String Finish();

    unsigned length() const { return builder_.length(); }

   private:
    void FlushRequiredLineBreak();

    StringBuilder builder_;
    wtf_size_t required_line_break_count_ = 0;
  };

  static bool HasDisplayContentsStyle(const Node& node);
  static bool IsBeingRendered(const Node& node);
  // Returns true if used value of "display" is block-level.
  static bool IsDisplayBlockLevel(const Node&);
  static bool ShouldEmitNewlineForTableRow(const LayoutTableRow& table_row);

  const OffsetMapping* GetOffsetMapping(const LayoutText& layout_text);
  void ProcessChildren(const Node& node);
  void ProcessChildrenWithRequiredLineBreaks(
      const Node& node,
      wtf_size_t required_line_break_count);
  void ProcessLayoutText(const LayoutText& layout_text, const Text& text_node);
  void ProcessNode(const Node& node);
  void ProcessOptionElement(const HTMLOptionElement& element);
  void ProcessSelectElement(const HTMLSelectElement& element);
  void ProcessTextNode(const Text& node);

  // Result character buffer.
  Result result_;
  TextVisitor* visitor_;
};

String ElementInnerTextCollector::RunOn(const Element& element) {
  DCHECK(!element.InActiveDocument() || !NeedsLayoutTreeUpdate(element));

  if (visitor_) {
    visitor_->WillVisit(element, result_.length());
  }

  // 1. If this element is locked or a part of a locked subtree, then it is
  // hidden from view (and also possibly not laid out) and innerText should be
  // empty.
  if (DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(element))
    return {};

  // 2. If this element is not being rendered, or if the user agent is a non-CSS
  // user agent, then return the same value as the textContent IDL attribute on
  // this element.
  // Note: To pass WPT test, case we don't use |textContent| for
  // "display:content". See [1] for discussion about "display:contents" and
  // "being rendered".
  // [1] https://github.com/whatwg/html/issues/1837
  if (!IsBeingRendered(element) && !HasDisplayContentsStyle(element)) {
    const bool convert_brs_to_newlines = false;
    return element.textContent(convert_brs_to_newlines, visitor_);
  }

  // 3. Let results be a new empty list.
  // 4. For each child node node of this element:
  //   1. Let current be the list resulting in running the inner text collection
  //      steps with node. Each item in results will either be a JavaScript
  //      string or a positive integer (a required line break count).
  //   2. For each item item in current, append item to results.
  // Note: Handles <select> and <option> here since they are implemented as
  // UA shadow DOM, e.g. Text nodes in <option> don't have layout object.
  // See also: https://github.com/whatwg/html/issues/3797
  if (auto* html_select_element = DynamicTo<HTMLSelectElement>(element))
    ProcessSelectElement(*html_select_element);
  else if (auto* option_element = DynamicTo<HTMLOptionElement>(element))
    ProcessOptionElement(*option_element);
  else
    ProcessChildren(element);
  return result_.Finish();
}

// static
bool ElementInnerTextCollector::HasDisplayContentsStyle(const Node& node) {
  auto* element = DynamicTo<Element>(node);
  return element && element->HasDisplayContentsStyle();
}

// An element is *being rendered* if it has any associated CSS layout boxes,
// SVG layout boxes, or some equivalent in other styling languages.
// Note: Just being off-screen does not mean the element is not being rendered.
// The presence of the "hidden" attribute normally means the element is not
// being rendered, though this might be overridden by the style sheets.
// From https://html.spec.whatwg.org/C/#being-rendered
// static
bool ElementInnerTextCollector::IsBeingRendered(const Node& node) {
  return node.GetLayoutObject();
}

// static
bool ElementInnerTextCollector::IsDisplayBlockLevel(const Node& node) {
  const LayoutObject* const layout_object = node.GetLayoutObject();
  if (!layout_object)
    return false;
  if (layout_object->IsTableSection()) {
    // Note: |LayoutTableSection::IsInline()| returns false, but it is not
    // block-level.
    return false;
  }
  if (!layout_object->IsLayoutBlock()) {
    // Note: Block-level replaced elements, e.g. <img style=display:block>,
    // reach here. Unlike |LayoutBlockFlow::AddChild()|, innerText considers
    // floats and absolutely-positioned elements as block-level node.
    return !layout_object->IsInline();
  }
  // TODO(crbug.com/567964): Due by the issue, |IsAtomicInlineLevel()| is always
  // true for replaced elements event if it has display:block, once it is fixed
  // we should check at first.
  if (layout_object->IsAtomicInlineLevel())
    return false;
  // Note: CAPTION is associated to |LayoutTableCaption| in LayoutNG or
  // |LayoutBlockFlow| in legacy layout.
  return true;
}

// static
bool ElementInnerTextCollector::ShouldEmitNewlineForTableRow(
    const LayoutTableRow& table_row) {
  const LayoutTable* const table = table_row.Table();
  if (!table)
    return false;
  if (table_row.NextRow()) {
    return true;
  }
  // For TABLE contains TBODY, TFOOTER, THEAD.
  const LayoutTableSection* table_section = table_row.Section();
  if (!table_section)
    return false;
  // See |LayoutTable::NextSection()| and
  // |PreviousSection()| for traversing |LayoutTableSection|.
  for (const LayoutObject* runner = table_section->NextSibling(); runner;
       runner = runner->NextSibling()) {
    const auto* section = DynamicTo<LayoutTableSection>(runner);
    if (section && section->NumRows() > 0) {
      return true;
    }
  }
  // No table row after |node|.
  return false;
}

const OffsetMapping* ElementInnerTextCollector::GetOffsetMapping(
    const LayoutText& layout_text) {
  // TODO(editing-dev): We should handle "text-transform" in "::first-line".
  // In legacy layout, |InlineTextBox| holds original text and text box
  // paint does text transform.
  LayoutBlockFlow* const block_flow =
      OffsetMapping::GetInlineFormattingContextOf(layout_text);
  DCHECK(block_flow) << layout_text;
  return InlineNode::GetOffsetMapping(block_flow);
}

void ElementInnerTextCollector::ProcessChildren(const Node& container) {
  for (const Node& node : NodeTraversal::ChildrenOf(container)) {
    if (visitor_) {
      visitor_->WillVisit(node, result_.length());
    }
    ProcessNode(node);
  }
}

void ElementInnerTextCollector::ProcessChildrenWithRequiredLineBreaks(
    const Node& node,
    wtf_size_t required_line_break_count) {
  DCHECK_GE(required_line_break_count, 1u);
  DCHECK_LE(required_line_break_count, 2u);
  result_.EmitRequiredLineBreak(required_line_break_count);
  ProcessChildren(node);
  result_.EmitRequiredLineBreak(required_line_break_count);
}

void ElementInnerTextCollector::ProcessLayoutText(const LayoutText& layout_text,
                                                  const Text& text_node) {
  if (layout_text.HasEmptyText()) {
    return;
  }
  if (layout_text.Style()->Visibility() != EVisibility::kVisible) {
    // TODO(editing-dev): Once we make ::first-letter don't apply "visibility",
    // we should get rid of this if-statement. http://crbug.com/866744
    return;
  }

  const OffsetMapping* const mapping = GetOffsetMapping(layout_text);
  if (!mapping) {
    // TODO(crbug.com/967995): There are certain cases where we fail to compute
    // |OffsetMapping| due to failures in layout. As the root cause is hard to
    // fix at the moment, we work around it here so that the production build
    // doesn't crash.
    DUMP_WILL_BE_NOTREACHED() << layout_text;
    return;
  }

  for (const OffsetMappingUnit& unit :
       mapping->GetMappingUnitsForNode(text_node)) {
    result_.EmitText(
        StringView(mapping->GetText(), unit.TextContentStart(),
                   unit.TextContentEnd() - unit.TextContentStart()));
  }
}

// The "inner text collection steps".
void ElementInnerTextCollector::ProcessNode(const Node& node) {
  // 1. Let items be the result of running the inner text collection steps with
  // each child node of node in tree order, and then concatenating the results
  // to a single list.

  // 2. If the node is display locked, then we should not process it or its
  // children, since they are not visible or accessible via innerText.
  if (DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(node))
    return;

  // 3. If node's computed value of 'visibility' is not 'visible', then return
  // items.
  const ComputedStyle* style = node.GetComputedStyleForElementOrLayoutObject();
  if (style && style->Visibility() != EVisibility::kVisible) {
    return ProcessChildren(node);
  }

  // 4. If node is not being rendered, then return items. For the purpose of
  // this step, the following elements must act as described if the computed
  // value of the 'display' property is not 'none':
  // Note: items can be non-empty due to 'display:contents'.
  if (!IsBeingRendered(node)) {
    // "display:contents" also reaches here since it doesn't have a CSS box.
    return ProcessChildren(node);
  }
  // * select elements have an associated non-replaced inline CSS box whose
  //   child boxes include only those of optgroup and option element child
  //   nodes;
  // * optgroup elements have an associated non-replaced block-level CSS box
  //   whose child boxes include only those of option element child nodes; and
  // * option element have an associated non-replaced block-level CSS box whose
  //   child boxes are as normal for non-replaced block-level CSS boxes.
  if (auto* html_select_element = DynamicTo<HTMLSelectElement>(node))
    return ProcessSelectElement(*html_select_element);
  if (auto* option_element = DynamicTo<HTMLOptionElement>(node)) {
    // Since child nodes of OPTION are not rendered, we use dedicated function.
    // e.g. <div>ab<option>12</div>cd</div>innerText == "ab\n12\ncd"
    // Note: "label" attribute doesn't affect value of innerText.
    return ProcessOptionElement(*option_element);
  }

  // 5. If node is a Text node, then for each CSS text box produced by node.
  auto* text_node = DynamicTo<Text>(node);
  if (text_node)
    return ProcessTextNode(*text_node);

  // 6. If node is a br element, then append a string containing a single U+000A
  // LINE FEED (LF) character to items.
  if (IsA<HTMLBRElement>(node)) {
    ProcessChildren(node);
    result_.EmitNewline();
    return;
  }

  // 7. If node's computed value of 'display' is 'table-cell', and node's CSS
  // box is not the last 'table-cell' box of its enclosing 'table-row' box, then
  // append a string containing a single U+0009 CHARACTER TABULATION (tab)
  // character to items.
  const LayoutObject& layout_object = *node.GetLayoutObject();
  if (style->Display() == EDisplay::kTableCell) {
    ProcessChildren(node);
    if (layout_object.IsTableCell() && layout_object.NextSibling()) {
      result_.EmitTab();
    }
    return;
  }

  // 8. If node's computed value of 'display' is 'table-row', and node's CSS box
  // is not the last 'table-row' box of the nearest ancestor 'table' box, then
  // append a string containing a single U+000A LINE FEED (LF) character to
  // items.
  if (style->Display() == EDisplay::kTableRow) {
    ProcessChildren(node);
    if (layout_object.IsTableRow() &&
        ShouldEmitNewlineForTableRow(To<LayoutTableRow>(layout_object))) {
      result_.EmitNewline();
    }
    return;
  }

  // 9. If node is a p element, then append 2 (a required line break count) at
  // the beginning and end of items.
  if (IsA<HTMLParagraphElement>(node)) {
    // Note: <p style="display:contents>foo</p> doesn't generate layout object
    // for P.
    ProcessChildrenWithRequiredLineBreaks(node, 2u);
    return;
  }

  // 10. If node's used value of 'display' is block-level or 'table-caption',
  // then append 1 (a required line break count) at the beginning and end of
  // items.
  if (IsDisplayBlockLevel(node))
    return ProcessChildrenWithRequiredLineBreaks(node, 1u);

  ProcessChildren(node);
}

void ElementInnerTextCollector::ProcessOptionElement(
    const HTMLOptionElement& option_element) {
  result_.EmitRequiredLineBreak(1);
  result_.EmitText(option_element.text());
  result_.EmitRequiredLineBreak(1);
}

void ElementInnerTextCollector::ProcessSelectElement(
    const HTMLSelectElement& select_element) {
  for (const Node& child : NodeTraversal::ChildrenOf(select_element)) {
    if (visitor_) {
      visitor_->WillVisit(child, result_.length());
    }
    if (auto* option_element = DynamicTo<HTMLOptionElement>(child)) {
      ProcessOptionElement(*option_element);
      continue;
    }
    if (!IsA<HTMLOptGroupElement>(child)) {
      continue;
    }
    // Note: We should emit newline for OPTGROUP even if it has no OPTION.
    // e.g. <div>a<select><optgroup></select>b</div>.innerText == "a\nb"
    result_.EmitRequiredLineBreak(1);
    for (const Node& maybe_option : NodeTraversal::ChildrenOf(child)) {
      if (visitor_) {
        visitor_->WillVisit(maybe_option, result_.length());
      }
      if (auto* option_element = DynamicTo<HTMLOptionElement>(maybe_option)) {
        ProcessOptionElement(*option_element);
      }
    }
    result_.EmitRequiredLineBreak(1);
  }
}

void ElementInnerTextCollector::ProcessTextNode(const Text& node) {
  if (!node.GetLayoutObject())
    return;
  const LayoutText& layout_text = *node.GetLayoutObject();
  if (LayoutText* first_letter_part = layout_text.GetFirstLetterPart()) {
    if (layout_text.HasEmptyText() ||
        OffsetMapping::GetInlineFormattingContextOf(layout_text) !=
            OffsetMapping::GetInlineFormattingContextOf(*first_letter_part)) {
      // "::first-letter" with "float" reach here.
      ProcessLayoutText(*first_letter_part, node);
    }
  }
  ProcessLayoutText(layout_text, node);
}

// ----

void ElementInnerTextCollector::Result::EmitNewline() {
  FlushRequiredLineBreak();
  builder_.Append(kNewlineCharacter);
}

void ElementInnerTextCollector::Result::EmitRequiredLineBreak(
    wtf_size_t count) {
  DCHECK_LE(count, 2u);
  if (count == 0)
    return;
  // 4. Remove any runs of consecutive required line break count items at the
  // start or end of results.
  if (builder_.empty()) {
    DCHECK_EQ(required_line_break_count_, 0u);
    return;
  }
  // 5. Replace each remaining run of consecutive required line break count
  // items with a string consisting of as many U+000A LINE FEED (LF) characters
  // as the maximum of the values in the required line break count items.
  required_line_break_count_ = std::max(required_line_break_count_, count);
}

void ElementInnerTextCollector::Result::EmitTab() {
  FlushRequiredLineBreak();
  builder_.Append(kTabulationCharacter);
}

void ElementInnerTextCollector::Result::EmitText(const StringView& text) {
  if (text.empty())
    return;
  FlushRequiredLineBreak();
  DCHECK_EQ(required_line_break_count_, 0u);
  builder_.Append(text);
}

String ElementInnerTextCollector::Result::Finish() {
  return builder_.ToString();
}

void ElementInnerTextCollector::Result::FlushRequiredLineBreak() {
  DCHECK_LE(required_line_break_count_, 2u);
  builder_.Append(
      base::byte_span_from_cstring("\n\n").first(required_line_break_count_));
  required_line_break_count_ = 0;
}

}  // anonymous namespace

String Element::innerText(TextVisitor* visitor) {
  // We need to update layout, since |ElementInnerTextCollector()| uses line
  // boxes in the layout tree.
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  return GetInnerTextWithoutUpdate(visitor);
}

// Used for callers that must ensure no document lifecycle rewind.
String Element::GetInnerTextWithoutUpdate(TextVisitor* visitor) {
  // TODO(https:://crbug.com/1165850 https:://crbug.com/1166296) Layout should
  // always be clean here, but the lifecycle does not report the correctly
  // updated value unless servicing animations. Fix the UpdateStyleAndLayout()
  // to correctly advance the lifecycle, and then update the following DCHECK to
  // always require clean layout in active documents.
  // DCHECK(!GetDocument().IsActive() || !GetDocument().GetPage() ||
  //        GetDocument().Lifecycle().GetState() >=
  //            DocumentLifecycle::kLayoutClean)
  //     << "Layout must be clean when GetInnerTextWithoutUpdate() is called.";
  return ElementInnerTextCollector(visitor).RunOn(*this);
}

}  // namespace blink

"""

```
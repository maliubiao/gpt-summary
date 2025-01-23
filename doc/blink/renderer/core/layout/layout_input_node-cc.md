Response:
Let's break down the thought process for analyzing the `layout_input_node.cc` file and generating the comprehensive response.

1. **Understand the Goal:** The core request is to understand the functionality of this specific Chromium Blink file. The prompt also asks to connect it to web technologies (JavaScript, HTML, CSS), provide input/output examples for logical inferences, and highlight potential user/developer errors.

2. **Identify the Core Class:** The filename `layout_input_node.cc` strongly suggests the existence of a `LayoutInputNode` class. The `#include` directives confirm this. This class is the central focus.

3. **Analyze the `#include` Directives:** These are the first clues about the class's responsibilities and the types of objects it interacts with. Key inclusions are:
    * `html/forms/html_input_element.h`: Indicates a relationship with HTML `<input>` elements.
    * `html/shadow/shadow_element_utils.h`: Suggests involvement with Shadow DOM.
    * `input_type_names.h`:  Implies handling different types of input elements (text, range, etc.).
    * `layout/*.h`:  This is a goldmine. It shows the class is part of the layout system and interacts with various layout primitives like `BlockNode`, `InlineNode`, `LayoutReplaced`, `LayoutView`, and table-related layout objects.
    * `platform/wtf/text/string_builder.h`:  Indicates string manipulation, likely for debugging or representation.

4. **Examine the Class Members and Methods:**  This is where the real understanding happens. Go through each method and its implementation:

    * **Constructors/Destructors (Implicit):** The file doesn't show explicit constructors, suggesting it might be a wrapper around an existing `LayoutBox`. The `box_` member confirms this.
    * **`IsSlider()`, `IsSliderThumb()`, `IsSvgText()`, `IsEmptyTableSection()`, `IsTextControlPlaceholder()`, `IsPaginatedRoot()`:** These are predicate methods. They check specific properties of the underlying `LayoutBox` or its associated DOM node. This reveals the class's role in identifying the *type* or *state* of a layout object.
    * **`TableColumnSpan()`, `TableCellColspan()`, `TableCellRowspan()`:**  These methods are specific to table layout and access span information from table-related `LayoutBox` objects.
    * **`ListMarkerBlockNodeIfListItem()`:**  Deals with the special layout of list item markers.
    * **`IntrinsicSize()`:** A crucial method related to layout calculations. It calculates the default or intrinsic size of a replaced element (like `<img>` or `<video>`). The logic involving `IntrinsicSizingInfo` and handling horizontal/vertical writing modes is important.
    * **`NextSibling()`:**  Provides a way to navigate the layout tree, respecting the difference between block and inline nodes.
    * **`InitialContainingBlockSize()`:**  Retrieves the size of the viewport.
    * **`ToString()`:**  Provides a string representation of the node, useful for debugging.
    * **`DumpNodeTree()`, `DumpNodeTreeFromRoot()`, `ShowNodeTree()`, `ShowNodeTreeFromRoot()`:** These are debugging utilities to visualize the layout tree structure. The `DCHECK_IS_ON()` conditional compilation highlights their debugging purpose.
    * **`GetOverrideIntrinsicSize()`:**  This is called by `IntrinsicSize()` and further refines how intrinsic sizes are determined, considering potential overrides and default values. The mention of "size containment" is a key concept related to CSS.

5. **Connect to Web Technologies (HTML, CSS, JavaScript):**  Now, relate the discovered functionalities to how these technologies manifest in the browser:

    * **HTML:** The file directly deals with HTML elements (`HTMLInputElement`). The various `Is...()` methods relate to specific HTML elements or their states (e.g., `<input type="range">`, table cells).
    * **CSS:** The layout properties are heavily influenced by CSS. The `IntrinsicSize()` method is directly affected by CSS properties that control the size of replaced elements. "Size containment" is a CSS feature. The way the layout tree is structured and rendered is governed by CSS rules.
    * **JavaScript:** While the C++ code doesn't directly *execute* JavaScript, it provides the underlying structure and information that JavaScript can interact with. JavaScript can query the layout (e.g., using `getBoundingClientRect()`) and manipulate the DOM, which in turn triggers layout recalculations involving `LayoutInputNode`.

6. **Logical Inferences and Examples:**  For methods that perform logical checks or calculations (like `IntrinsicSize`), think about the inputs and expected outputs. Consider different scenarios, such as different `type` attributes for `<input>` elements or varying CSS properties.

7. **Identify Potential Errors:** Think about how developers might misuse the underlying layout system or encounter unexpected behavior. For example, assuming synchronous layout updates or incorrectly manipulating the DOM can lead to performance issues or layout thrashing.

8. **Structure the Response:** Organize the findings logically. Start with a high-level summary of the file's purpose. Then, detail the key functionalities. Separately address the connections to HTML, CSS, and JavaScript. Provide clear input/output examples and error scenarios. Use code snippets where appropriate to illustrate points.

9. **Refine and Review:** Read through the generated response to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have just said "deals with input elements."  Refining it to mention specific input types and their layout implications makes it more informative. Similarly, explicitly mentioning "layout thrashing" adds practical value.

By following this structured approach, combining code analysis with knowledge of web technologies and common development practices, it's possible to generate a comprehensive and informative explanation of a complex source code file like `layout_input_node.cc`.
好的，让我们详细分析一下 `blink/renderer/core/layout/layout_input_node.cc` 这个文件。

**文件功能总览**

`layout_input_node.cc` 文件定义了 `LayoutInputNode` 类，这个类在 Blink 渲染引擎的布局（Layout）阶段扮演着重要的角色。它的主要功能是作为 **布局树（Layout Tree）中节点的轻量级包装器**，特别针对那些可能包含交互元素的布局对象，例如 HTML `<input>` 元素。

**核心功能和职责**

1. **提供布局对象（LayoutObject）的便捷访问:** `LayoutInputNode` 内部持有一个指向 `LayoutBox` 的智能指针 `box_`。 `LayoutBox` 是 Blink 布局系统的核心类，代表了渲染树中的一个盒子（box），负责计算盒子的尺寸和位置。`LayoutInputNode` 提供了访问和操作这个底层 `LayoutBox` 的接口。

2. **提供特定类型布局对象的判断方法:**  文件中定义了一系列 `Is...()` 方法，用于判断 `LayoutInputNode` 所包装的 `LayoutBox` 是否属于特定的类型或具有特定的属性。例如：
    * `IsSlider()`:  判断是否是 `<input type="range">` 这样的滑块输入框。
    * `IsSliderThumb()`: 判断是否是滑块的滑块部分（thumb）。
    * `IsSvgText()`: 判断是否是 SVG 文本元素。
    * `IsEmptyTableSection()`: 判断是否是空的表格 section（`<tbody>`, `<thead>`, `<tfoot>`）。
    * `IsTextControlPlaceholder()`: 判断是否是文本输入框的占位符。
    * `IsPaginatedRoot()`: 判断是否是分页的根元素。

3. **提供特定布局属性的访问方法:**  针对特定的布局类型，`LayoutInputNode` 提供了访问相关属性的方法，例如：
    * `TableColumnSpan()`: 获取表格列的 `colspan` 值。
    * `TableCellColspan()`: 获取表格单元格的 `colspan` 值。
    * `TableCellRowspan()`: 获取表格单元格的 `rowspan` 值。

4. **处理 intrinsic size (固有尺寸):** `IntrinsicSize()` 方法用于计算替换元素（Replaced Element，如 `<img>`, `<video>`, `<input>` 等）的固有尺寸。这对于在没有显式指定尺寸时，浏览器如何确定元素的大小至关重要。

5. **提供遍历布局树的能力:** `NextSibling()` 方法用于获取当前 `LayoutInputNode` 的下一个兄弟节点。这对于遍历布局树结构很有用。

6. **提供调试和输出布局树信息的功能:**  在 `DCHECK_IS_ON()` 宏开启的情况下，`DumpNodeTree()`, `DumpNodeTreeFromRoot()`, `ShowNodeTree()`, `ShowNodeTreeFromRoot()` 等方法可以用于打印和显示布局树的结构，方便开发人员调试和理解布局过程。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`LayoutInputNode` 位于渲染引擎的布局阶段，因此与 HTML 结构、CSS 样式和 JavaScript 都有密切关系。

* **HTML:**
    * **关系:** `LayoutInputNode` 包装的 `LayoutBox` 对象对应于 HTML 元素。文件中的很多 `Is...()` 方法直接关联到特定的 HTML 元素类型，例如 `HTMLInputElement`。
    * **举例:**  当浏览器解析到 `<input type="range">` 元素时，会创建一个对应的 `LayoutBox` 对象，然后 `LayoutInputNode::IsSlider()` 方法就可以判断出这是一个滑块。

* **CSS:**
    * **关系:** CSS 样式会影响布局对象的属性，进而影响 `LayoutInputNode` 的行为和判断。例如，CSS 的 `display` 属性会影响一个元素是否是 block 或 inline，这会影响 `NextSibling()` 的实现。CSS 的 `colspan` 和 `rowspan` 属性会被 `TableCellColspan()` 和 `TableCellRowspan()` 方法读取。
    * **举例:** 如果一个 `<div>` 元素设置了 `display: none;`，那么它可能不会在布局树中生成对应的 `LayoutBox`，也就不会有对应的 `LayoutInputNode`。 另外，CSS 作用于 `<input>` 元素的 `width` 和 `height` 属性会影响 `IntrinsicSize()` 方法计算的默认尺寸。

* **JavaScript:**
    * **关系:** JavaScript 可以操作 DOM 结构和 CSS 样式，这些操作会触发浏览器的重新布局（reflow 或 relayout）。当发生重新布局时，会创建或更新布局树，`LayoutInputNode` 会参与到这个过程中。
    * **举例:** JavaScript 代码可以通过 `element.style.display = 'none'` 隐藏一个元素，这将导致该元素的 `LayoutBox`（以及对应的 `LayoutInputNode`）从布局树中移除。或者，JavaScript 可以通过 `element.setAttribute('type', 'range')` 将一个普通的 `<input>` 元素变成滑块，这会使得对应的 `LayoutInputNode::IsSlider()` 返回 true。JavaScript 使用 `getBoundingClientRect()` 等方法获取元素的尺寸和位置信息时，这些信息是布局阶段计算出来的，而 `LayoutInputNode` 参与了这些计算。

**逻辑推理及假设输入与输出**

考虑 `IsSlider()` 方法：

* **假设输入:** 一个 `LayoutInputNode` 对象，其内部的 `LayoutBox` 对应于一个 `HTMLInputElement`。
* **逻辑推理:** `IsSlider()` 方法首先判断内部的 `LayoutBox` 是否对应一个 `HTMLInputElement`。如果是，它会进一步检查该 `HTMLInputElement` 的 `FormControlType()` 是否为 `FormControlType::kInputRange`。
* **预期输出:**
    * 如果输入的 `LayoutInputNode` 对应于 `<input type="range">`，则 `IsSlider()` 返回 `true`。
    * 如果输入的 `LayoutInputNode` 对应于 `<input type="text">` 或其他类型的 input，则 `IsSlider()` 返回 `false`。
    * 如果输入的 `LayoutInputNode` 对应的不是 `HTMLInputElement`，则 `IsSlider()` 返回 `false`。

考虑 `IntrinsicSize()` 方法：

* **假设输入:** 一个 `LayoutInputNode` 对象，其内部的 `LayoutBox` 对应于一个 `<img>` 元素（这是一个替换元素）。假设该 `<img>` 元素没有设置 `width` 和 `height` 属性，但图片本身有一个固有的尺寸（例如 100x50）。
* **逻辑推理:** `IntrinsicSize()` 方法会尝试获取重写的固有尺寸（`GetOverrideIntrinsicSize`），如果没有，则会调用 `ComputeIntrinsicSizingInfo` 来计算。对于 `<img>` 元素，这通常会涉及到读取图片文件的元数据来获取其原始尺寸。
* **预期输出:** `computed_inline_size` 将被设置为 100px（或相应的布局单位）， `computed_block_size` 将被设置为 50px（或相应的布局单位），假设是水平书写模式。如果是非水平书写模式，则 inline 和 block 尺寸会交换。

**用户或编程常见的使用错误**

虽然用户和程序员不会直接操作 `LayoutInputNode` 对象，但他们在编写 HTML, CSS 和 JavaScript 时的错误会间接地影响到与 `LayoutInputNode` 相关的布局行为。

1. **HTML 结构错误导致布局异常:** 例如，表格结构不完整，缺少 `<table>`, `<tr>`, `<td>` 等元素，可能会导致 `IsEmptyTableSection()`, `TableCellColspan()` 等方法返回不符合预期的结果，最终导致页面布局错乱。

2. **CSS 样式冲突或错误导致尺寸计算错误:** 例如，对替换元素设置了不合理的 `width` 和 `height`，可能会干扰 `IntrinsicSize()` 的计算，导致元素显示不正确。 开发者过度依赖 CSS 来控制尺寸，而忽略了替换元素的固有尺寸，可能导致在某些情况下显示异常。

3. **JavaScript 操作 DOM 导致频繁的重排（Reflow）:**  频繁地修改影响布局的 DOM 属性或 CSS 样式，可能会导致浏览器进行大量的布局计算，其中涉及到 `LayoutInputNode` 的创建和更新，从而影响页面性能。例如，在一个循环中连续修改多个元素的样式，可能会触发多次重排。

4. **错误地假设布局是同步的:**  开发者可能会错误地认为在修改 DOM 或 CSS 之后，布局会立即更新。实际上，浏览器会对布局进行优化，可能会延迟更新。因此，在某些情况下，直接读取布局信息（例如使用 `getBoundingClientRect()`）可能得到旧的值。

5. **在 Shadow DOM 中不理解布局的上下文:** `LayoutInputNode` 也涉及到 Shadow DOM。开发者如果没有正确理解 Shadow DOM 的边界和样式隔离，可能会导致内部元素的布局样式受到外部样式的意外影响，或者反之。`blink::IsSliderThumb(GetDOMNode())` 的实现可能需要考虑 Shadow DOM 的结构。

**总结**

`layout_input_node.cc` 中的 `LayoutInputNode` 类是 Blink 渲染引擎布局阶段的关键组件，它为操作和查询布局树中的特定节点提供了便利的接口。它与 HTML 的结构、CSS 的样式以及 JavaScript 的 DOM 操作都息息相关，共同决定了网页的最终呈现效果。理解 `LayoutInputNode` 的功能有助于更深入地理解浏览器的布局过程。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_input_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_input_node.h"

#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_utils.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/intrinsic_sizing_info.h"
#include "third_party/blink/renderer/core/layout/layout_replaced.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/layout/min_max_sizes.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

#if DCHECK_IS_ON()
void AppendSubtreeToString(const BlockNode&,
                           const LayoutInputNode* target,
                           StringBuilder*,
                           unsigned indent);

void IndentForDump(const LayoutInputNode& node,
                   const LayoutInputNode* target,
                   StringBuilder* string_builder,
                   unsigned indent) {
  unsigned start_col = 0;
  if (node && target && node == *target) {
    string_builder->Append("*");
    start_col = 1;
  }
  for (unsigned i = start_col; i < indent; i++) {
    string_builder->Append(" ");
  }
}

void AppendNodeToString(const LayoutInputNode& node,
                        const LayoutInputNode* target,
                        StringBuilder* string_builder,
                        unsigned indent = 2) {
  if (!node)
    return;
  DCHECK(string_builder);

  IndentForDump(node, target, string_builder, indent);
  string_builder->Append(node.ToString());
  string_builder->Append("\n");

  if (auto* block_node = DynamicTo<BlockNode>(node)) {
    AppendSubtreeToString(*block_node, target, string_builder, indent + 2);
  } else if (auto* inline_node = DynamicTo<InlineNode>(node)) {
    const auto& items = inline_node->ItemsData(false).items;
    indent += 2;
    for (const InlineItem& inline_item : items) {
      BlockNode child_node(nullptr);
      if (auto* box = DynamicTo<LayoutBox>(inline_item.GetLayoutObject())) {
        child_node = BlockNode(box);
      }
      IndentForDump(child_node, target, string_builder, indent);
      string_builder->Append(inline_item.ToString());
      string_builder->Append("\n");
      if (child_node) {
        // Dump the subtree of an atomic inline, float, block-in-inline, etc.
        AppendSubtreeToString(child_node, target, string_builder, indent + 2);
      }
    }
    DCHECK(!inline_node->NextSibling());
  }
}

void AppendSubtreeToString(const BlockNode& node,
                           const LayoutInputNode* target,
                           StringBuilder* string_builder,
                           unsigned indent) {
  LayoutInputNode first_child = node.FirstChild();
  for (LayoutInputNode node_runner = first_child; node_runner;
       node_runner = node_runner.NextSibling()) {
    AppendNodeToString(node_runner, target, string_builder, indent);
  }
}
#endif

}  // namespace

bool LayoutInputNode::IsSlider() const {
  if (const auto* input = DynamicTo<HTMLInputElement>(box_->GetNode()))
    return input->FormControlType() == FormControlType::kInputRange;
  return false;
}

bool LayoutInputNode::IsSliderThumb() const {
  return IsBlock() && blink::IsSliderThumb(GetDOMNode());
}

bool LayoutInputNode::IsSvgText() const {
  return box_ && box_->IsSVGText();
}

bool LayoutInputNode::IsEmptyTableSection() const {
  return box_->IsTableSection() &&
         To<LayoutTableSection>(box_.Get())->IsEmpty();
}

wtf_size_t LayoutInputNode::TableColumnSpan() const {
  DCHECK(IsTableCol() || IsTableColgroup());
  return To<LayoutTableColumn>(box_.Get())->Span();
}

wtf_size_t LayoutInputNode::TableCellColspan() const {
  DCHECK(box_->IsTableCell());
  return To<LayoutTableCell>(box_.Get())->ColSpan();
}

wtf_size_t LayoutInputNode::TableCellRowspan() const {
  DCHECK(box_->IsTableCell());
  return To<LayoutTableCell>(box_.Get())->ComputedRowSpan();
}

bool LayoutInputNode::IsTextControlPlaceholder() const {
  return IsBlock() && blink::IsTextControlPlaceholder(GetDOMNode());
}

bool LayoutInputNode::IsPaginatedRoot() const {
  if (!IsBlock())
    return false;
  const auto* view = DynamicTo<LayoutView>(box_.Get());
  return view && view->IsFragmentationContextRoot();
}

BlockNode LayoutInputNode::ListMarkerBlockNodeIfListItem() const {
  if (auto* list_item = DynamicTo<LayoutListItem>(box_.Get())) {
    return BlockNode(DynamicTo<LayoutBox>(list_item->Marker()));
  }
  return BlockNode(nullptr);
}

void LayoutInputNode::IntrinsicSize(
    std::optional<LayoutUnit>* computed_inline_size,
    std::optional<LayoutUnit>* computed_block_size) const {
  DCHECK(IsReplaced());

  GetOverrideIntrinsicSize(computed_inline_size, computed_block_size);
  if (*computed_inline_size && *computed_block_size)
    return;

  IntrinsicSizingInfo legacy_sizing_info;
  To<LayoutReplaced>(box_.Get())
      ->ComputeIntrinsicSizingInfo(legacy_sizing_info);

  std::optional<LayoutUnit> intrinsic_inline_size =
      legacy_sizing_info.has_width
          ? std::make_optional(
                LayoutUnit::FromFloatRound(legacy_sizing_info.size.width()))
          : std::nullopt;
  std::optional<LayoutUnit> intrinsic_block_size =
      legacy_sizing_info.has_height
          ? std::make_optional(
                LayoutUnit::FromFloatRound(legacy_sizing_info.size.height()))
          : std::nullopt;
  if (!IsHorizontalWritingMode()) {
    std::swap(intrinsic_inline_size, intrinsic_block_size);
  }

  if (!*computed_inline_size) {
    *computed_inline_size = intrinsic_inline_size;
  }
  if (!*computed_block_size) {
    *computed_block_size = intrinsic_block_size;
  }
}

LayoutInputNode LayoutInputNode::NextSibling() const {
  auto* inline_node = DynamicTo<InlineNode>(this);
  return inline_node ? nullptr : To<BlockNode>(*this).NextSibling();
}

PhysicalSize LayoutInputNode::InitialContainingBlockSize() const {
  gfx::Size icb_size =
      GetDocument().GetLayoutView()->GetLayoutSize(kIncludeScrollbars);
  return PhysicalSize(icb_size);
}

String LayoutInputNode::ToString() const {
  auto* inline_node = DynamicTo<InlineNode>(this);
  return inline_node ? inline_node->ToString()
                     : To<BlockNode>(*this).ToString();
}

#if DCHECK_IS_ON()
String LayoutInputNode::DumpNodeTree(const LayoutInputNode* target) const {
  StringBuilder string_builder;
  string_builder.Append(".:: Layout input node tree ::.\n");
  AppendNodeToString(*this, target, &string_builder);
  return string_builder.ToString();
}

String LayoutInputNode::DumpNodeTreeFromRoot() const {
  return BlockNode(box_->View()).DumpNodeTree(this);
}

void LayoutInputNode::ShowNodeTree(const LayoutInputNode* target) const {
  if (getenv("RUNNING_UNDER_RR")) {
    // Printing timestamps requires an IPC to get the local time, which
    // does not work in an rr replay session. Just disable timestamp printing
    // globally, since we don't need them. Affecting global state isn't a
    // problem because invoking this from a rr session creates a temporary
    // program environment that will be destroyed as soon as the invocation
    // completes.
    logging::SetLogItems(true, true, false, false);
  }

  DLOG(INFO) << "\n" << DumpNodeTree(target).Utf8();
}

void LayoutInputNode::ShowNodeTreeFromRoot() const {
  BlockNode(box_->View()).ShowNodeTree(this);
}
#endif

void LayoutInputNode::GetOverrideIntrinsicSize(
    std::optional<LayoutUnit>* computed_inline_size,
    std::optional<LayoutUnit>* computed_block_size) const {
  DCHECK(IsReplaced());

  LayoutUnit override_inline_size = OverrideIntrinsicContentInlineSize();
  if (override_inline_size != kIndefiniteSize) {
    *computed_inline_size = override_inline_size;
  } else {
    LayoutUnit default_inline_size = DefaultIntrinsicContentInlineSize();
    if (default_inline_size != kIndefiniteSize)
      *computed_inline_size = default_inline_size;
  }

  LayoutUnit override_block_size = OverrideIntrinsicContentBlockSize();
  if (override_block_size != kIndefiniteSize) {
    *computed_block_size = override_block_size;
  } else {
    LayoutUnit default_block_size = DefaultIntrinsicContentBlockSize();
    if (default_block_size != kIndefiniteSize)
      *computed_block_size = default_block_size;
  }

  if (ShouldApplyInlineSizeContainment() && !*computed_inline_size)
    *computed_inline_size = LayoutUnit();
  if (ShouldApplyBlockSizeContainment() && !*computed_block_size)
    *computed_block_size = LayoutUnit();
}

}  // namespace blink

#if DCHECK_IS_ON()

CORE_EXPORT void ShowLayoutTree(const blink::LayoutInputNode& node) {
  ShowLayoutTree(node.GetLayoutBox());
}

#endif  // DCHECK_IS_ON()
```
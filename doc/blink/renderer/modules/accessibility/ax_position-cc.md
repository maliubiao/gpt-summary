Response:
Let's break down the thought process for analyzing this `ax_position.cc` file.

**1. Initial Understanding of the Goal:**

The core request is to understand the functionality of the `ax_position.cc` file within the Chromium Blink rendering engine. The request specifically asks about relationships to JavaScript, HTML, and CSS, logical reasoning, common errors, debugging, and a summary.

**2. High-Level Overview and Keywords:**

The filename `ax_position.cc` immediately suggests it's related to accessibility (`ax`) and the concept of a position. The initial lines of the code confirm this with the inclusion of headers like `ax_object_cache.h`, `dom/node.h`, and `modules/accessibility/ax_object.h`. Keywords like "accessibility tree," "AXObject," "position," "text offset," and "child index" start to emerge as important concepts.

**3. Core Functionality Identification (Reading the Code):**

The next step involves carefully reading through the code, function by function, and understanding their purpose. Key observations:

* **`CreatePositionBeforeObject`, `CreatePositionAfterObject`, `CreateFirstPositionInObject`, `CreateLastPositionInObject`:** These functions are clearly factory methods for creating `AXPosition` objects at specific locations relative to other `AXObject`s. The differentiation based on `IsTextObject` is an important detail.

* **`CreatePositionInTextObject`:** This function specifically deals with creating positions *within* text objects, taking an offset and affinity as arguments.

* **`FromPosition(const Position& ...)` and `FromPosition(const PositionWithAffinity& ...)`:**  These are crucial for bridging the gap between the DOM's `Position` concept and the accessibility tree's `AXPosition`. They handle the conversion from DOM positions to their accessibility tree equivalents. The logic here is more complex, dealing with ignored nodes and layout contexts.

* **Constructor (`AXPosition(...)`)**:  The constructors initialize the core members: `container_object_`, `text_offset_or_child_index_`, and `affinity_`. The inclusion of `DCHECK` for versioning hints at tracking changes in the DOM and style.

* **Getter Methods (`ChildAfterTreePosition`, `ChildIndex`, `TextOffset`, `MaxTextOffset`, `Affinity`):**  These provide access to the internal state of the `AXPosition` object. `MaxTextOffset` has interesting logic for handling different types of text containers.

* **`IsValid`:**  This is a validation function to ensure the `AXPosition` is in a consistent state. It checks for detached objects, document state, and offset bounds.

* **`IsTextPosition`:** A simple helper to determine if the position is within a text object.

* **Navigation Methods (`CreateNextPosition`, `CreatePreviousPosition`):** These are fundamental for traversing the accessibility tree by moving to the next or previous logical position.

* **Adjustment Methods (`AsUnignoredPosition`, `AsValidDOMPosition`):** These are more advanced, handling cases where the initial position might be on an ignored node or a virtual object, requiring adjustments to find a valid, relevant position in the accessibility or DOM tree.

* **`ToPositionWithAffinity`:**  The reverse of the `FromPosition` functions, converting an `AXPosition` back to a DOM `PositionWithAffinity`.

**4. Relating to JavaScript, HTML, and CSS:**

As the code is analyzed, connections to the web platform become apparent:

* **HTML:** The accessibility tree is built upon the HTML structure. The existence of `AXObject`s and their parent-child relationships directly mirrors the DOM. Examples like text within `<p>` tags or the structure of lists (`<ul>`, `<li>`) come to mind.

* **CSS:** CSS properties (like `display: none` or `aria-hidden="true"`) can cause elements to be excluded from the accessibility tree. The `IsIncludedInTree()` checks and the `AsUnignoredPosition()` function directly relate to this. CSS pseudo-elements (`::before`, `::after`) also have corresponding `AXObject`s.

* **JavaScript:**  JavaScript interacts with accessibility through APIs like the Accessibility Object Model (AOM). JavaScript can query the accessibility tree to understand the structure and content of a web page for assistive technologies. The `AXPosition` is a fundamental concept for identifying specific locations within that tree.

**5. Logical Reasoning, Assumptions, and Outputs:**

Consider the logic within functions like `FromPosition`. Think about different scenarios:

* **Input:** A DOM `Position` inside a `<span>` element containing the text "Hello".
* **Output:** An `AXPosition` object pointing to the corresponding location within the `AXObject` representing the `<span>`'s text.

* **Input:** A DOM `Position` on a node that is ignored due to `aria-hidden="true"`.
* **Output:** The `FromPosition` function, with `adjustment_behavior`, will try to find the nearest *unignored* `AXObject` and create a position relative to it.

**6. Common Errors and User Actions:**

Think about situations where things might go wrong:

* **Error:** Trying to create a position in a detached `AXObject`. The `IsValid()` checks would catch this.
* **User Action:**  A user might interact with a dynamic web page where elements are added or removed rapidly. This could lead to detached `AXObject`s if the accessibility tree isn't updated correctly.

* **Error:** Providing an offset that's out of bounds for a text object. The `IsValid()` function and the `MaxTextOffset()` calculation prevent this.
* **User Action:** A screen reader user navigating through text might encounter issues if the offsets are incorrect.

**7. Debugging Clues and User Operations:**

Imagine debugging an accessibility issue:

* **Scenario:** A screen reader isn't reading text in the correct order.
* **Debugging:** You might set breakpoints in functions like `CreateNextPosition` or `CreatePreviousPosition` to see how the `AXPosition` is being moved through the tree. You'd also inspect the `container_object_` and `text_offset_or_child_index_`.
* **User Operation:** The user navigating with the Tab key or arrow keys is implicitly triggering the movement through the accessibility tree, relying on the correctness of `AXPosition`.

**8. Structuring the Output:**

Finally, organize the information clearly, addressing each part of the original request:

* **Functionality:** List the primary roles of the `ax_position.cc` file.
* **Relationships:** Explain how it connects to JavaScript, HTML, and CSS with concrete examples.
* **Logical Reasoning:** Provide examples of input and output for key functions.
* **Common Errors:** Illustrate potential mistakes and how the code handles them.
* **User Operations/Debugging:** Describe how user interactions lead to this code being executed and how it can be used for debugging.
* **Summary (Part 1):** Briefly recap the core purpose of the file based on the analysis so far.

This iterative process of reading, analyzing, connecting to web platform concepts, considering scenarios, and organizing the information helps to generate a comprehensive understanding of the `ax_position.cc` file.
```
好的，这是对 blink/renderer/modules/accessibility/ax_position.cc 文件功能的分析，作为第一部分：

**blink/renderer/modules/accessibility/ax_position.cc 的功能归纳 (第 1 部分):**

该文件定义了 `AXPosition` 类，这是 Blink 渲染引擎中用于表示可访问性树（Accessibility Tree）中特定位置的关键概念。它的核心功能可以归纳为：

1. **表示可访问性树中的位置:** `AXPosition` 对象能够精确地指向可访问性树中的一个特定点。这个位置可以是：
    * 在某个可访问性对象（`AXObject`）之前。
    * 在某个可访问性对象之后。
    * 在某个可访问性对象内部（对于文本对象，可以指向文本的某个字符偏移量）。

2. **创建和管理可访问性位置:**  文件中包含了多个静态工厂方法（例如 `CreatePositionBeforeObject`, `CreateFirstPositionInObject` 等）用于创建不同类型的 `AXPosition` 对象。这些方法考虑了各种边界情况，例如对象是否被分离、是否包含在可访问性树中，以及处理文本对象和非文本对象的不同方式。

3. **DOM 位置与可访问性位置的转换:**  `FromPosition` 方法负责将 DOM 树中的 `Position` 对象（表示文档中的一个点）转换为相应的 `AXPosition` 对象。这对于将用户的 DOM 操作（例如光标位置）映射到可访问性树中的位置至关重要。

4. **可访问性位置的导航:**  `CreateNextPosition` 和 `CreatePreviousPosition` 方法允许在可访问性树中移动 `AXPosition`。这对于实现屏幕阅读器等辅助技术的导航功能至关重要。

5. **处理被忽略的可访问性对象:** `AsUnignoredPosition` 方法用于查找与当前 `AXPosition` 等效的、但位于可访问性树中未被忽略的对象上的位置。这对于处理由于 `aria-hidden` 或其他原因而被排除在可访问性树之外的 DOM 元素至关重要。

6. **转换为有效的 DOM 位置:** `AsValidDOMPosition` 方法尝试将 `AXPosition` 转换为 DOM 树中有效的 `Position` 对象。这涉及到处理虚拟对象（例如 CSS 生成的内容）和确保位置指向实际存在的 DOM 节点。

7. **可访问性位置的验证:** `IsValid` 方法用于检查 `AXPosition` 对象是否处于有效状态。它会检查容器对象是否仍然存在，是否已分离，以及偏移量是否在有效范围内。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能关系:** `AXPosition` 的概念直接基于 HTML 结构构建的可访问性树。HTML 元素会被映射为 `AXObject`，而 `AXPosition` 则用于定位这些对象之间的边界或内部。
    * **举例说明:** 考虑以下 HTML 代码：
      ```html
      <div>
        <p>Hello <span>world</span></p>
      </div>
      ```
      `AXPosition::CreatePositionBeforeObject` 可以创建一个指向 "Hello " 文本节点之前的位置。`AXPosition::CreatePositionAfterObject` 可以创建一个指向 `<span>` 元素之后的位置。

* **CSS:**
    * **功能关系:** CSS 属性可以影响可访问性树的结构。例如，`display: none` 或 `visibility: hidden` 可能会导致元素不被包含在可访问性树中。`AXPosition` 的创建和调整需要考虑这些因素。`AsUnignoredPosition` 方法就处理了这种情况。
    * **举例说明:** 如果 `<span>` 元素设置了 `aria-hidden="true"`，那么 `FromPosition` 将会尝试找到其父节点或其他可见的兄弟节点来创建 `AXPosition`。

* **JavaScript:**
    * **功能关系:** JavaScript 可以通过 Accessibility Object Model (AOM) API 与可访问性树进行交互。`AXPosition` 是 AOM 中表示位置的关键类型。JavaScript 可以使用 AOM API 获取或设置可访问性树中的焦点，这通常会涉及到 `AXPosition` 的操作。
    * **举例说明:**  JavaScript 可以调用浏览器提供的 API 来获取当前可访问性焦点的 `AXPosition`。或者，当 JavaScript 需要模拟用户在可访问性树中的导航时，可以创建和移动 `AXPosition` 对象。

**逻辑推理的假设输入与输出:**

**假设输入:** 一个 DOM `Position` 对象，指向以下 HTML 中的 `w` 字符之前：

```html
<p>Hello <span>world</span></p>
```

**调用函数:** `AXPosition::FromPosition(dom_position, TextAffinity::kDownstream, AXPositionAdjustmentBehavior::kMoveDown)`

**逻辑推理:**

1. `FromPosition` 获取与 DOM `Position` 相关的 `AXObject`，即包含 "world" 文本的 `AXObject`。
2. 由于 `TextAffinity` 是 `kDownstream`，并且指向 'w' 之前，因此 `text_offset_or_child_index_` 将被设置为该文本对象中的偏移量 0。
3. 创建一个 `AXPosition` 对象，其容器是 "world" 的文本 `AXObject`，`text_offset_or_child_index_` 为 0。

**假设输出:** 一个 `AXPosition` 对象，其状态为：
* `container_object_`: 指向 "world" 文本的 `AXObject`。
* `text_offset_or_child_index_`: 0
* `affinity_`: `TextAffinity::kDownstream`

**用户或编程常见的使用错误举例说明:**

1. **使用已分离的 `AXObject` 创建 `AXPosition`:**
   * **错误:**  尝试使用一个已经被从可访问性树中移除的 `AXObject` 来调用 `CreatePositionBeforeObject` 等方法。
   * **现象:** `IsValid()` 方法会返回 `false`，可能导致后续操作失败或崩溃。
   * **用户操作如何到达:** 用户可能与一个动态更新的网页进行交互，导致某个元素被移除，但程序仍然持有该元素对应的 `AXObject` 的引用。

2. **在非文本对象上创建文本位置:**
   * **错误:**  尝试使用 `CreatePositionInTextObject` 方法，但提供的 `AXObject` 并非文本对象。
   * **现象:**  该方法会直接返回一个空的 `AXPosition` 对象。
   * **用户操作如何到达:**  程序逻辑可能错误地判断了 `AXObject` 的类型。

3. **提供超出文本范围的偏移量:**
   * **错误:**  在 `CreatePositionInTextObject` 中提供了一个大于文本长度的 `offset` 值。
   * **现象:** `IsValid()` 方法会返回 `false`。
   * **用户操作如何到达:**  程序在处理用户输入或计算偏移量时可能出现错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一些可能导致 `ax_position.cc` 中的代码被执行的用户操作场景，可以作为调试线索：

1. **页面加载和渲染:** 当浏览器加载 HTML、解析 CSS 并构建渲染树时，辅助功能模块会同步构建可访问性树。在这个过程中，会创建各种 `AXObject`，而 `AXPosition` 可能被用来标记初始位置或边界。

2. **用户与表单控件交互:** 当用户聚焦到一个文本输入框（`<input>` 或 `<textarea>`）时，浏览器需要确定可访问性焦点的位置。这可能会涉及到将 DOM 焦点的 `Position` 转换为 `AXPosition`。

3. **用户使用屏幕阅读器导航:** 屏幕阅读器依赖于可访问性树来理解页面结构和内容。当用户使用键盘快捷键（例如 Tab 键、方向键）进行导航时，屏幕阅读器会请求下一个或上一个可访问对象或文本位置，这会触发 `CreateNextPosition` 和 `CreatePreviousPosition` 的调用。

4. **用户使用鼠标选择文本:** 当用户在页面上拖动鼠标选择文本时，浏览器需要将鼠标位置映射到 DOM 树中的 `Position`，然后将其转换为 `AXPosition`，以便辅助功能 API 可以获取选中文本的范围。

5. **JavaScript 通过 AOM API 操作:**  如果网页上的 JavaScript 代码使用了 AOM API 来获取或设置可访问性信息（例如焦点、选中内容），那么这些 API 的底层实现很可能会使用到 `AXPosition` 类。

**调试线索:** 如果在调试可访问性相关的问题时，例如屏幕阅读器无法正确读取内容或焦点移动不正确，可以考虑以下调试步骤，可能会涉及到 `ax_position.cc`：

1. **在 `AXPosition` 的构造函数和关键方法（如 `FromPosition`, `CreateNextPosition`, `CreatePreviousPosition`）中设置断点。**
2. **检查 `AXPosition` 对象的成员变量，例如 `container_object_` 和 `text_offset_or_child_index_`，以确定位置是否正确。**
3. **追踪 `AXObject` 的创建和销毁，以排除由于 `AXObject` 分离导致的问题。**
4. **查看与当前 `AXPosition` 相关的 DOM 节点和布局信息，以确保可访问性树与 DOM 树和渲染树保持一致。**

总而言之，`ax_position.cc` 定义的 `AXPosition` 类是 Blink 渲染引擎中可访问性功能的核心组件，它用于表示和操作可访问性树中的位置，并与 DOM 树和用户交互密切相关。理解其功能对于理解和调试浏览器如何为辅助技术提供网页信息至关重要。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_position.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_position.h"

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/list/list_marker.h"
#include "third_party/blink/renderer/modules/accessibility/ax_node_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

// static
const AXPosition AXPosition::CreatePositionBeforeObject(
    const AXObject& child,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  if (child.IsDetached() || !child.IsIncludedInTree())
    return {};

  // If |child| is a text object, but not a text control, make behavior the same
  // as |CreateFirstPositionInObject| so that equality would hold. Text controls
  // behave differently because you should be able to set a position before the
  // text control in case you want to e.g. select it as a whole.
  if (child.IsTextObject())
    return CreateFirstPositionInObject(child, adjustment_behavior);

  const AXObject* parent = child.ParentObjectIncludedInTree();

  if (!parent || parent->IsDetached())
    return {};

  DCHECK(parent);
  AXPosition position(*parent);
  position.text_offset_or_child_index_ = child.IndexInParent();
#if DCHECK_IS_ON()
  String failure_reason;
  DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
  return position.AsUnignoredPosition(adjustment_behavior);
}

// static
const AXPosition AXPosition::CreatePositionAfterObject(
    const AXObject& child,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  if (child.IsDetached() || !child.IsIncludedInTree())
    return {};

  // If |child| is a text object, but not a text control, make behavior the same
  // as |CreateLastPositionInObject| so that equality would hold. Text controls
  // behave differently because you should be able to set a position after the
  // text control in case you want to e.g. select it as a whole.
  if (child.IsTextObject())
    return CreateLastPositionInObject(child, adjustment_behavior);

  const AXObject* parent = child.ParentObjectIncludedInTree();

  if (!parent || parent->IsDetached())
    return {};

  DCHECK(parent);
  AXPosition position(*parent);
  position.text_offset_or_child_index_ = child.IndexInParent() + 1;
#if DCHECK_IS_ON()
  String failure_reason;
  DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
  return position.AsUnignoredPosition(adjustment_behavior);
}

// static
const AXPosition AXPosition::CreateFirstPositionInObject(
    const AXObject& container,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  if (container.IsDetached())
    return {};

  if (container.IsTextObject() || container.IsAtomicTextField()) {
    AXPosition position(container);
    position.text_offset_or_child_index_ = 0;
#if DCHECK_IS_ON()
    String failure_reason;
    DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
    return position.AsUnignoredPosition(adjustment_behavior);
  }

  // If the container is not a text object, creating a position inside an
  // object that is excluded from the accessibility tree will result in an
  // invalid position, because child count is not always accurate for such
  // objects.
  const AXObject* unignored_container =
      !container.IsIncludedInTree()
          ? container.ParentObjectIncludedInTree()
          : &container;
  DCHECK(unignored_container);
  AXPosition position(*unignored_container);
  position.text_offset_or_child_index_ = 0;
#if DCHECK_IS_ON()
  String failure_reason;
  DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
  return position.AsUnignoredPosition(adjustment_behavior);
}

// static
const AXPosition AXPosition::CreateLastPositionInObject(
    const AXObject& container,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  if (container.IsDetached())
    return {};

  if (container.IsTextObject() || container.IsAtomicTextField()) {
    AXPosition position(container);
    position.text_offset_or_child_index_ = position.MaxTextOffset();
#if DCHECK_IS_ON()
    String failure_reason;
    DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
    return position.AsUnignoredPosition(adjustment_behavior);
  }

  // If the container is not a text object, creating a position inside an
  // object that is excluded from the accessibility tree will result in an
  // invalid position, because child count is not always accurate for such
  // objects.
  const AXObject* unignored_container =
      !container.IsIncludedInTree()
          ? container.ParentObjectIncludedInTree()
          : &container;
  DCHECK(unignored_container);
  AXPosition position(*unignored_container);
  position.text_offset_or_child_index_ =
      unignored_container->ChildCountIncludingIgnored();
#if DCHECK_IS_ON()
  String failure_reason;
  DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
  return position.AsUnignoredPosition(adjustment_behavior);
}

// static
const AXPosition AXPosition::CreatePositionInTextObject(
    const AXObject& container,
    const int offset,
    const TextAffinity affinity,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  if (container.IsDetached() ||
      !(container.IsTextObject() || container.IsTextField())) {
    return {};
  }

  AXPosition position(container);
  position.text_offset_or_child_index_ = offset;
  position.affinity_ = affinity;
#if DCHECK_IS_ON()
  String failure_reason;
  DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
  return position.AsUnignoredPosition(adjustment_behavior);
}

// static
const AXPosition AXPosition::FromPosition(
    const Position& position,
    const TextAffinity affinity,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  if (position.IsNull() || position.IsOrphan())
    return {};

  const Document* document = position.GetDocument();
  // Non orphan positions always have a document.
  DCHECK(document);

  AXObjectCache* ax_object_cache = document->ExistingAXObjectCache();
  if (!ax_object_cache)
    return {};

  auto* ax_object_cache_impl = static_cast<AXObjectCacheImpl*>(ax_object_cache);
  const Position& parent_anchored_position = position.ToOffsetInAnchor();
  const Node* container_node = parent_anchored_position.AnchorNode();
  DCHECK(container_node);
  const AXObject* container = ax_object_cache_impl->Get(container_node);
  if (!container)
    return {};

  if (container_node->IsTextNode()) {
    if (!container->IsIncludedInTree()) {
      // Find the closest DOM sibling that is unignored in the accessibility
      // tree.
      switch (adjustment_behavior) {
        case AXPositionAdjustmentBehavior::kMoveRight: {
          const AXObject* next_container = FindNeighboringUnignoredObject(
              *document, *container_node, container_node->parentNode(),
              adjustment_behavior);
          if (next_container) {
            return CreatePositionBeforeObject(*next_container,
                                              adjustment_behavior);
          }

          // Do the next best thing by moving up to the unignored parent if it
          // exists.
          if (!container || !container->ParentObjectIncludedInTree())
            return {};
          return CreateLastPositionInObject(
              *container->ParentObjectIncludedInTree(), adjustment_behavior);
        }

        case AXPositionAdjustmentBehavior::kMoveLeft: {
          const AXObject* previous_container = FindNeighboringUnignoredObject(
              *document, *container_node, container_node->parentNode(),
              adjustment_behavior);
          if (previous_container) {
            return CreatePositionAfterObject(*previous_container,
                                             adjustment_behavior);
          }

          // Do the next best thing by moving up to the unignored parent if it
          // exists.
          if (!container || !container->ParentObjectIncludedInTree())
            return {};
          return CreateFirstPositionInObject(
              *container->ParentObjectIncludedInTree(), adjustment_behavior);
        }
      }
    }

    AXPosition ax_position(*container);
    // Convert from a DOM offset that may have uncompressed white space to a
    // character offset.
    //
    // Note that OffsetMapping::GetInlineFormattingContextOf will reject DOM
    // positions that it does not support, so we don't need to explicitly check
    // this before calling the method.)
    LayoutBlockFlow* formatting_context =
        OffsetMapping::GetInlineFormattingContextOf(parent_anchored_position);
    const OffsetMapping* container_offset_mapping =
        formatting_context ? InlineNode::GetOffsetMapping(formatting_context)
                           : nullptr;
    if (!container_offset_mapping) {
      // We are unable to compute the text offset in the accessibility tree that
      // corresponds to the DOM offset. We do the next best thing by returning
      // either the first or the last AX position in |container| based on the
      // |adjustment_behavior|.
      switch (adjustment_behavior) {
        case AXPositionAdjustmentBehavior::kMoveRight:
          return CreateLastPositionInObject(*container, adjustment_behavior);
        case AXPositionAdjustmentBehavior::kMoveLeft:
          return CreateFirstPositionInObject(*container, adjustment_behavior);
      }
    }

    // We can now compute the text offset that corresponds to the given DOM
    // position from the beginning of our formatting context. We also need to
    // subtract the text offset of our |container| from the beginning of the
    // same formatting context.
    int container_offset = container->TextOffsetInFormattingContext(0);
    std::optional<unsigned> content_offset =
        container_offset_mapping->GetTextContentOffset(
            parent_anchored_position);
    int text_offset = 0;
    if (content_offset.has_value()) {
      text_offset = content_offset.value() - container_offset;
      // Adjust the offset for characters that are not in the accessible text.
      // These can include zero-width breaking opportunities inserted after
      // preserved preliminary whitespace and isolate characters inserted when
      // positioning SVG text at a specific x coordinate.
      int adjustment = ax_position.GetLeadingIgnoredCharacterCount(
          container_offset_mapping, container->GetClosestNode(),
          container_offset, content_offset.value());
      text_offset -= adjustment;
    }
    DCHECK_GE(text_offset, 0);
    ax_position.text_offset_or_child_index_ = text_offset;
    ax_position.affinity_ = affinity;
#if DCHECK_IS_ON()
    String failure_reason;
    DCHECK(ax_position.IsValid(&failure_reason)) << failure_reason;
#endif
    return ax_position;
  }

  DCHECK(container_node->IsContainerNode());
  if (!container->IsIncludedInTree()) {
    container = container->ParentObjectIncludedInTree();
    if (!container)
      return {};

    // |container_node| could potentially become nullptr if the unignored
    // parent is an anonymous layout block.
    container_node = container->GetClosestNode();
  }

  AXPosition ax_position(*container);
  // |ComputeNodeAfterPosition| returns nullptr for "after children"
  // positions.
  const Node* node_after_position = position.ComputeNodeAfterPosition();
  if (!node_after_position) {
    ax_position.text_offset_or_child_index_ =
        container->ChildCountIncludingIgnored();

    } else {
      const AXObject* ax_child = ax_object_cache_impl->Get(node_after_position);
      // |ax_child| might be nullptr because not all DOM nodes can have AX
      // objects. For example, the "head" element has no corresponding AX
      // object.
      if (!ax_child || !ax_child->IsIncludedInTree()) {
        // Find the closest DOM sibling that is present and unignored in the
        // accessibility tree.
        switch (adjustment_behavior) {
          case AXPositionAdjustmentBehavior::kMoveRight: {
            const AXObject* next_child = FindNeighboringUnignoredObject(
                *document, *node_after_position,
                DynamicTo<ContainerNode>(container_node), adjustment_behavior);
            if (next_child) {
              return CreatePositionBeforeObject(*next_child,
                                                adjustment_behavior);
            }

            return CreateLastPositionInObject(*container, adjustment_behavior);
          }

          case AXPositionAdjustmentBehavior::kMoveLeft: {
            const AXObject* previous_child = FindNeighboringUnignoredObject(
                *document, *node_after_position,
                DynamicTo<ContainerNode>(container_node), adjustment_behavior);
            if (previous_child) {
              // |CreatePositionAfterObject| cannot be used here because it will
              // try to create a position before the object that comes after
              // |previous_child|, which in this case is the ignored object
              // itself.
              return CreateLastPositionInObject(*previous_child,
                                                adjustment_behavior);
            }

            return CreateFirstPositionInObject(*container, adjustment_behavior);
          }
        }
      }

      if (!container->ChildrenIncludingIgnored().Contains(ax_child)) {
        // The |ax_child| is aria-owned by another object.
        return CreatePositionBeforeObject(*ax_child, adjustment_behavior);
      }

      if (ax_child->IsTextObject()) {
        // The |ax_child| is a text object. In order that equality between
        // seemingly identical positions would hold, i.e. a "before object"
        // position before the text object and a "text position" before the
        // first character of the text object, we would need to convert to the
        // deep equivalent position.
        return CreateFirstPositionInObject(*ax_child, adjustment_behavior);
      }

      ax_position.text_offset_or_child_index_ = ax_child->IndexInParent();
    }

    return ax_position;
}

// static
const AXPosition AXPosition::FromPosition(
    const PositionWithAffinity& position_with_affinity,
    const AXPositionAdjustmentBehavior adjustment_behavior) {
  return FromPosition(position_with_affinity.GetPosition(),
                      position_with_affinity.Affinity(), adjustment_behavior);
}

AXPosition::AXPosition()
    : container_object_(nullptr),
      text_offset_or_child_index_(0),
      affinity_(TextAffinity::kDownstream) {
#if DCHECK_IS_ON()
  dom_tree_version_ = 0;
  style_version_ = 0;
#endif
}

AXPosition::AXPosition(const AXObject& container)
    : container_object_(&container),
      text_offset_or_child_index_(0),
      affinity_(TextAffinity::kDownstream) {
  const Document* document = container_object_->GetDocument();
  DCHECK(document);
#if DCHECK_IS_ON()
  dom_tree_version_ = document->DomTreeVersion();
  style_version_ = document->StyleVersion();
#endif
}

const AXObject* AXPosition::ChildAfterTreePosition() const {
  if (!IsValid() || IsTextPosition())
    return nullptr;
  if (ChildIndex() == container_object_->ChildCountIncludingIgnored())
    return nullptr;
  DCHECK_LT(ChildIndex(), container_object_->ChildCountIncludingIgnored());
  return container_object_->ChildAtIncludingIgnored(ChildIndex());
}

int AXPosition::ChildIndex() const {
  if (!IsTextPosition())
    return text_offset_or_child_index_;
  DUMP_WILL_BE_NOTREACHED() << *this << " should be a tree position.";
  return 0;
}

int AXPosition::TextOffset() const {
  if (IsTextPosition())
    return text_offset_or_child_index_;
  NOTREACHED() << *this << " should be a text position.";
}

int AXPosition::MaxTextOffset() const {
  if (!IsTextPosition()) {
    NOTREACHED() << *this << " should be a text position.";
  }

  // TODO(nektar): Make AXObject::TextLength() public and use throughout this
  // method.
  if (container_object_->IsAtomicTextField())
    return container_object_->GetValueForControl().length();

  if (!container_object_->GetNode()) {
    // 1. The |Node| associated with an inline text box contains all the text in
    // the static text object parent, whilst the inline text box might contain
    // only part of it.
    // 2. Some accessibility objects, such as those used for CSS "::before" and
    // "::after" content, don't have an associated text node. We retrieve the
    // text from the inline text box or layout object itself.
    return container_object_->ComputedName().length();
  }

  const LayoutObject* layout_object = container_object_->GetLayoutObject();
  if (!layout_object)
    return container_object_->ComputedName().length();
  // TODO(nektar): Remove all this logic once we switch to
  // AXObject::TextLength().
  const bool is_atomic_inline_level =
      layout_object->IsInline() && layout_object->IsAtomicInlineLevel();
  if (!is_atomic_inline_level && !layout_object->IsText())
    return container_object_->ComputedName().length();

  // TODO(crbug.com/1149171): OffsetMappingBuilder does not properly
  // compute offset mappings for empty LayoutText objects. Other text objects
  // (such as some list markers) are not affected.
  if (const LayoutText* layout_text = DynamicTo<LayoutText>(layout_object)) {
    if (layout_text->HasEmptyText()) {
      return container_object_->ComputedName().length();
    }
  }

  LayoutBlockFlow* formatting_context =
      OffsetMapping::GetInlineFormattingContextOf(*layout_object);
  const OffsetMapping* container_offset_mapping =
      formatting_context ? InlineNode::GetOffsetMapping(formatting_context)
                         : nullptr;
  if (!container_offset_mapping)
    return container_object_->ComputedName().length();
  const base::span<const OffsetMappingUnit> mapping_units =
      container_offset_mapping->GetMappingUnitsForNode(
          *container_object_->GetClosestNode());
  if (mapping_units.empty())
    return container_object_->ComputedName().length();
  return static_cast<int>(mapping_units.back().TextContentEnd() -
                          mapping_units.front().TextContentStart());
}

TextAffinity AXPosition::Affinity() const {
  if (!IsTextPosition()) {
    NOTREACHED() << *this << " should be a text position.";
  }

  return affinity_;
}

bool AXPosition::IsValid(String* failure_reason) const {
  if (!container_object_) {
    if (failure_reason)
      *failure_reason = "\nPosition invalid: no container object.";
    return false;
  }
  if (container_object_->IsDetached()) {
    if (failure_reason)
      *failure_reason = "\nPosition invalid: detached container object.";
    return false;
  }
  if (!container_object_->GetDocument()) {
    if (failure_reason) {
      *failure_reason = "\nPosition invalid: no document for container object.";
    }
    return false;
  }

  // Some container objects, such as those for CSS "::before" and "::after"
  // text, don't have associated DOM nodes.
  if (container_object_->GetClosestNode() &&
      !container_object_->GetClosestNode()->isConnected()) {
    if (failure_reason) {
      *failure_reason =
          "\nPosition invalid: container object node is disconnected.";
    }
    return false;
  }

  const Document* document = container_object_->GetDocument();
  DCHECK(document->IsActive());
  DCHECK(!document->NeedsLayoutTreeUpdate());
  if (!document->IsActive() || document->NeedsLayoutTreeUpdate()) {
    if (failure_reason) {
      *failure_reason =
          "\nPosition invalid: document is either not active or it needs "
          "layout tree update.";
    }
    return false;
  }

  if (IsTextPosition()) {
    if (text_offset_or_child_index_ > MaxTextOffset()) {
      if (failure_reason) {
        *failure_reason = String::Format(
            "\nPosition invalid: text offset too large.\n%d vs. %d.",
            text_offset_or_child_index_, MaxTextOffset());
      }
      return false;
    }
  } else {
    if (text_offset_or_child_index_ >
        container_object_->ChildCountIncludingIgnored()) {
      if (failure_reason) {
        *failure_reason = String::Format(
            "\nPosition invalid: child index too large.\n%d vs. %d.",
            text_offset_or_child_index_,
            container_object_->ChildCountIncludingIgnored());
      }
      return false;
    }
  }

#if DCHECK_IS_ON()
  DCHECK_EQ(container_object_->GetDocument()->DomTreeVersion(),
            dom_tree_version_);
  DCHECK_EQ(container_object_->GetDocument()->StyleVersion(), style_version_);
#endif  // DCHECK_IS_ON()
  return true;
}

bool AXPosition::IsTextPosition() const {
  // We don't call |IsValid| from here because |IsValid| uses this method.
  if (!container_object_)
    return false;
  return container_object_->IsTextObject() ||
         container_object_->IsAtomicTextField();
}

const AXPosition AXPosition::CreateNextPosition() const {
  if (!IsValid())
    return {};

  if (IsTextPosition() && TextOffset() < MaxTextOffset()) {
    return CreatePositionInTextObject(*container_object_, (TextOffset() + 1),
                                      TextAffinity::kDownstream,
                                      AXPositionAdjustmentBehavior::kMoveRight);
  }

  // Handles both an "after children" position, or a text position that is right
  // after the last character.
  const AXObject* child = ChildAfterTreePosition();
  if (!child) {
    // If this is a static text object, we should not descend into its inline
    // text boxes when present, because we'll just be creating a text position
    // in the same piece of text.
    const AXObject* next_in_order =
        container_object_->ChildCountIncludingIgnored()
            ? container_object_->DeepestLastChildIncludingIgnored()
                  ->NextInPreOrderIncludingIgnored()
            : container_object_->NextInPreOrderIncludingIgnored();
    if (!next_in_order || !next_in_order->ParentObjectIncludedInTree())
      return {};

    return CreatePositionBeforeObject(*next_in_order,
                                      AXPositionAdjustmentBehavior::kMoveRight);
  }

  if (!child->ParentObjectIncludedInTree())
    return {};

  return CreatePositionAfterObject(*child,
                                   AXPositionAdjustmentBehavior::kMoveRight);
}

const AXPosition AXPosition::CreatePreviousPosition() const {
  if (!IsValid())
    return {};

  if (IsTextPosition() && TextOffset() > 0) {
    return CreatePositionInTextObject(*container_object_, (TextOffset() - 1),
                                      TextAffinity::kDownstream,
                                      AXPositionAdjustmentBehavior::kMoveLeft);
  }

  const AXObject* child = ChildAfterTreePosition();
  const AXObject* object_before_position = nullptr;
  // Handles both an "after children" position, or a text position that is
  // before the first character.
  if (!child) {
    // If this is a static text object, we should not descend into its inline
    // text boxes when present, because we'll just be creating a text position
    // in the same piece of text.
    if (!container_object_->IsTextObject() &&
        container_object_->ChildCountIncludingIgnored()) {
      const AXObject* last_child =
          container_object_->LastChildIncludingIgnored();
      // Dont skip over any intervening text.
      if (last_child->IsTextObject() || last_child->IsAtomicTextField()) {
        return CreatePositionAfterObject(
            *last_child, AXPositionAdjustmentBehavior::kMoveLeft);
      }

      return CreatePositionBeforeObject(
          *last_child, AXPositionAdjustmentBehavior::kMoveLeft);
    }

    object_before_position =
        container_object_->PreviousInPreOrderIncludingIgnored();
  } else {
    object_before_position = child->PreviousInPreOrderIncludingIgnored();
  }

  if (!object_before_position ||
      !object_before_position->ParentObjectIncludedInTree()) {
    return {};
  }

  // Dont skip over any intervening text.
  if (object_before_position->IsTextObject() ||
      object_before_position->IsAtomicTextField()) {
    return CreatePositionAfterObject(*object_before_position,
                                     AXPositionAdjustmentBehavior::kMoveLeft);
  }

  return CreatePositionBeforeObject(*object_before_position,
                                    AXPositionAdjustmentBehavior::kMoveLeft);
}

const AXPosition AXPosition::AsUnignoredPosition(
    const AXPositionAdjustmentBehavior adjustment_behavior) const {
  if (!IsValid())
    return {};

  // There are five possibilities:
  //
  // 1. The container object is ignored and this is not a text position or an
  // "after children" position. Try to find the equivalent position in the
  // unignored parent.
  //
  // 2. The position is a text position and the container object is ignored.
  // Return a "before children" or an "after children" position anchored at the
  // container's unignored parent.
  //
  // 3. The container object is ignored and this is an "after children"
  // position. Find the previous or the next object in the tree and recurse.
  //
  // 4. The child after a tree position is ignored, but the container object is
  // not. Return a "before children" or an "after children" position.
  //
  // 5. We arbitrarily decided to ignore positions that are anchored to before a
  // text object. We move such positions to before the first character of the
  // text object. This is in an effort to ensure that two positions, one a
  // "before object" position anchored to a text object, and one a "text
  // position" anchored to before the first character of the same text object,
  // compare as equivalent.

  const AXObject* container = container_object_;
  const AXObject* child = ChildAfterTreePosition();

  // Case 1.
  // Neither text positions nor "after children" positions have a |child|
  // object.
  if (!container->IsIncludedInTree() && child) {
    // |CreatePositionBeforeObject| already finds the unignored parent before
    // creating the new position, so we don't need to replicate the logic here.
    return CreatePositionBeforeObject(*child, adjustment_behavior);
  }

  // Cases 2 and 3.
  if (!container->IsIncludedInTree()) {
    // Case 2.
    if (IsTextPosition()) {
      if (!container->ParentObjectIncludedInTree())
        return {};

      // Calling |CreateNextPosition| or |CreatePreviousPosition| is not
      // appropriate here because they will go through the text position
      // character by character which is unnecessary, in addition to skipping
      // any unignored siblings.
      switch (adjustment_behavior) {
        case AXPositionAdjustmentBehavior::kMoveRight:
          return CreateLastPositionInObject(
              *container->ParentObjectIncludedInTree(), adjustment_behavior);
        case AXPositionAdjustmentBehavior::kMoveLeft:
          return CreateFirstPositionInObject(
              *container->ParentObjectIncludedInTree(), adjustment_behavior);
      }
    }

    // Case 3.
    switch (adjustment_behavior) {
      case AXPositionAdjustmentBehavior::kMoveRight:
        return CreateNextPosition().AsUnignoredPosition(adjustment_behavior);
      case AXPositionAdjustmentBehavior::kMoveLeft:
        return CreatePreviousPosition().AsUnignoredPosition(
            adjustment_behavior);
    }
  }

  // Case 4.
  if (child && !child->IsIncludedInTree()) {
    switch (adjustment_behavior) {
      case AXPositionAdjustmentBehavior::kMoveRight:
        return CreateLastPositionInObject(*container);
      case AXPositionAdjustmentBehavior::kMoveLeft:
        return CreateFirstPositionInObject(*container);
    }
  }

  // Case 5.
  if (child && child->IsTextObject())
    return CreateFirstPositionInObject(*child);

  // The position is not ignored.
  return *this;
}

const AXPosition AXPosition::AsValidDOMPosition(
    const AXPositionAdjustmentBehavior adjustment_behavior) const {
  if (!IsValid())
    return {};

  // We adjust to the next or previous position if the container or the child
  // object after a tree position are mock or virtual objects, since mock or
  // virtual objects will not be present in the DOM tree. Alternatively, in the
  // case of an "after children" position, we need to check if the last child of
  // the container object is mock or virtual and adjust accordingly. Abstract
  // inline text boxes and static text nodes for CSS "::before" and "::after"
  // positions are also considered to be virtual since they don't have an
  // associated DOM node.

  // In more detail:
  // If the child after a tree position doesn't have an associated node in the
  // DOM tree, we adjust to the next or previous position because a
  // corresponding child node will not be found in the DOM tree. We need a
  // corresponding child node in the DOM tree so that we can anchor the DOM
  // position before it. We can't ask the layout tree for the child's container
  // block node, because this might change the placement of the AX position
  // drastically. However, if the container doesn't have a corresponding DOM
  // node, we need to use the layout tree to find its corresponding container
  // block node, because no AX positions inside an anonymous layout block could
  // be represented in the DOM tree anyway.

  const AXObject* container = container_object_;
  DCHECK(container);
  const AXObject* child = ChildAfterTreePosition();
  const AXObject* last_child = container->LastChildIncludingIgnored();
  if ((IsTextPosition() &&
       (!container->GetClosestNode() ||
        container->GetClosestNode()->IsMarkerPseudoElement())) ||
      (!child && last_child &&
       (!last_child->GetClosestNode() ||
        last_child->GetClosestNode()->IsMarkerPseudoElement())) ||
      (child && (!child->GetClosestNode() ||
                 child->GetClosestNode()->IsMarkerPseudoElement()))) {
    AXPosition result;
    if (adjustment_behavior == AXPositionAdjustmentBehavior::kMoveRight)
      result = CreateNextPosition();
    else
      result = CreatePreviousPosition();

    if (result && result != *this)
      return result.AsValidDOMPosition(adjustment_behavior);
    return {};
  }

  // At this point, if a non-pseudo element DOM node is associated with our
  // container, then the corresponding DOM position should be valid.
  const Node* container_node = container->GetClosestNode();
  if (container_node->IsPseudoElement()) {
    container_node = LayoutTreeBuilderTraversal::Parent(*container_node);
  } else {
    return *this;
  }
  DCHECK(container_node) << "All anonymous layout objects and list markers "
                            "should have a containing block element.";
  DCHECK(!container->IsDetached());
  if (!container_node || container->IsDetached())
    return {};

  auto& ax_object_cache_impl = container->AXObjectCache();
  const AXObject* new_container = ax_object_cache_impl.Get(container_node);
  DCHECK(new_container);
  if (!new_container)
    return {};

  AXPosition position(*new_container);
  if (new_container == container->ParentObjectIncludedInTree()) {
    position.text_offset_or_child_index_ = container->IndexInParent();
  } else {
    switch (adjustment_behavior) {
      case AXPositionAdjustmentBehavior::kMoveRight:
        position.text_offset_or_child_index_ =
            new_container->ChildCountIncludingIgnored();
        break;
      case AXPositionAdjustmentBehavior::kMoveLeft:
        position.text_offset_or_child_index_ = 0;
        break;
    }
  }
#if DCHECK_IS_ON()
  String failure_reason;
  DCHECK(position.IsValid(&failure_reason)) << failure_reason;
#endif
  return position.AsValidDOMPosition(adjustment_behavior);
}

const PositionWithAffinity AXPosition::ToPositionWithAffinity(
    const AXPositionAdjustmentBehavior adjustment_behavior) const {
  const AXPosition adjusted_position = AsValidDOMPosition(adjustment_behavior);
  if (!adjusted_position.IsValid())
    return {};

  const Node* container_node =
      adjusted_positio
```
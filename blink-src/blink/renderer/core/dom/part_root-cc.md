Response:
Let's break down the thought process for analyzing the `part_root.cc` file.

1. **Initial Understanding - What is `PartRoot`?**  The file name and the `#include` directives immediately suggest that `PartRoot` is a core class within the Blink rendering engine. The presence of `Part`, `Node`, `Document`, and `Element` in the includes points to it being related to the Document Object Model (DOM). The `DOMPartsAPIEnabled` flags hint at a specific feature or set of features being managed by this class.

2. **Core Functionality - Skimming the Code:**  A quick read-through reveals several key methods:
    * `AddPart`, `RemovePart`:  Suggests managing a collection of `Part` objects.
    * `CloneParts`:  Indicates involvement in node cloning, specifically related to `Part` objects.
    * `SwapPartsList`:  Points to the ability to exchange the internal list of parts with another `PartRoot`.
    * `RebuildPartsList`:  Suggests a mechanism to dynamically construct the list of parts based on the DOM.
    * `getParts`:  Provides access to the managed list of `Part` objects.
    * Methods involving `DOMPartsAPIMinimalEnabled`: Indicates two different implementations or modes of operation depending on a flag.

3. **Relating to Web Technologies (HTML, CSS, JavaScript):** Now, the crucial step is to connect these internal functionalities to the user-facing web technologies.

    * **HTML:** The very concept of "parts" strongly suggests a way to delineate sections or components within the HTML structure. The mentions of `ChildNodePart` and the logic involving start and end comments further solidify this idea. *Hypothesis:*  `PartRoot` helps represent and manage logical groupings of nodes within the HTML tree.

    * **CSS:**  While not explicitly mentioned in the code's core logic, the ability to define "parts" could potentially be linked to CSS styling. Perhaps CSS selectors could target these "parts" for specific styling. This is a more speculative connection, but worth noting. The initial code doesn't show direct CSS interaction.

    * **JavaScript:**  This is where the most significant interaction likely occurs. The ability to get a list of "parts" (`getParts`) strongly implies that JavaScript APIs would allow developers to access and manipulate these logical groupings. This is where the real power of the `DOMPartsAPI` would lie. The cloning functionality also suggests that JavaScript could trigger or interact with these cloning operations.

4. **Logical Reasoning and Examples:**  Based on the understanding so far, let's construct some illustrative examples:

    * **Hypothesis:** `ChildNodePart` likely represents a range of child nodes.
    * **Input (HTML):**
        ```html
        <div>
          <!-- part-start -->
          <p>Paragraph 1</p>
          <span>Span 1</span>
          <!-- part-end -->
        </div>
        ```
    * **Output (Conceptual):** The `ChildNodePart` would encapsulate the `<p>` and `<span>` elements.

    * **Hypothesis:** `NodePart` represents a single node.
    * **Input (HTML):** `<div data-part="my-div"></div>`
    * **Output (Conceptual):** The `NodePart` would encapsulate the `<div>` element.

5. **User and Programming Errors:**  Thinking about how developers might misuse the API or how the browser could encounter inconsistencies is important.

    * **Mismatched start/end comments:**  A common error when manually creating these "parts."
    * **Overlapping parts:** Defining parts that intersect, leading to ambiguity. The code has comments about this.
    * **Modifying the DOM in ways that invalidate parts:**  Deleting or moving nodes that are part of a defined "part."

6. **Debugging and User Actions:**  How does a user action lead to this code being executed?

    * **Initial Page Load:**  The browser parses HTML and may identify and create `Part` objects based on specific markers or attributes.
    * **JavaScript DOM Manipulation:** JavaScript code using a hypothetical `DOMParts` API could trigger the creation, modification, or deletion of parts.
    * **Node Cloning:**  As the code explicitly handles cloning, actions that involve cloning nodes (e.g., `cloneNode` in JavaScript) could invoke the `CloneParts` logic.
    * **Developer Tools Inspection:**  Developers inspecting the DOM might indirectly trigger the retrieval of parts information for display.

7. **Refining the Explanation:**  Finally, organize the information logically, using clear headings and bullet points. Emphasize the core functionalities, the relationships to web technologies, provide concrete examples, and address potential errors and debugging scenarios. It's important to acknowledge areas of uncertainty or speculation (e.g., the exact nature of the JavaScript API, the direct interaction with CSS).

By following this thought process – starting with the basics, analyzing the code structure, connecting to web technologies, creating examples, considering errors, and thinking about debugging – we can arrive at a comprehensive understanding of the `part_root.cc` file's role within the Chromium rendering engine.
好的，我们来详细分析一下 `blink/renderer/core/dom/part_root.cc` 文件的功能。

**文件功能概述**

`PartRoot` 类是 Blink 渲染引擎中用于管理 "Part" 对象的根类。 "Part" 是一个抽象概念，代表 DOM 树中的一部分节点或节点范围。`PartRoot` 负责维护这些 `Part` 对象的集合，并提供操作这些集合的方法。

更具体地说，`PartRoot` 的主要功能包括：

* **存储和管理 Part 对象:**  它维护一个列表 (`cached_ordered_parts_`) 来存储属于该 `PartRoot` 的 `Part` 对象。
* **跟踪 Part 列表的有效性:** 使用 `cached_parts_list_dirty_` 标志来标记缓存的 Part 列表是否需要重建。
* **添加和移除 Part 对象:** 提供 `AddPart` 和 `RemovePart` 方法来动态更新 Part 列表。
* **克隆 Part 对象:**  提供 `CloneParts` 静态方法，在克隆 DOM 节点时处理相关的 Part 对象。
* **交换 Part 列表:**  提供 `SwapPartsList` 方法，允许两个 `PartRoot` 对象交换它们的 Part 列表。
* **重建 Part 列表:**  提供 `RebuildPartsList` 方法，根据 DOM 树的结构重新构建 Part 列表。这通常在 Part 列表被标记为脏时发生。
* **获取 Part 列表:** 提供 `getParts` 方法来获取当前有效的 Part 列表。
* **支持不同的 PartRoot 类型:** 通过 `GetPartRootFromUnion` 和 `GetUnionFromPartRoot` 静态方法，处理 `DocumentPartRoot` 和 `ChildNodePart` 这两种不同的 `PartRoot` 类型。
* **支持 Minimal API 模式:**  通过 `RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()` 标志，支持一种简化的 `DOMParts` API 模式，在这种模式下，Part 列表不会被缓存，而是每次都重新构建。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`PartRoot` 类是 Blink 内部实现的一部分，它本身并不直接暴露给 JavaScript, HTML 或 CSS。 然而，它的功能是为可能由这些技术驱动的更高级别的 API 或功能提供基础。

**推测的关联性 (基于代码和命名):**

* **HTML:**
    * **可能的应用场景:**  `Part` 对象可能用于表示 HTML 结构中的特定逻辑片段，例如，模板的一部分、自定义元素的内部结构，或者使用特定属性标记的区域。
    * **举例说明:** 假设 HTML 中有如下结构：
        ```html
        <template id="my-template">
          <!-- part-start: header -->
          <h1>Template Header</h1>
          <!-- part-end: header -->
          <p>Template content.</p>
        </template>
        ```
        这里的 `<!-- part-start: header -->` 和 `<!-- part-end: header -->` 注释可能被解析器识别，并在内部创建一个表示 "header" 部分的 `Part` 对象，并由某个 `PartRoot` 管理。

* **JavaScript:**
    * **可能的应用场景:**  JavaScript API 可能会允许开发者访问和操作这些 `Part` 对象。例如，可能存在一个 API 来获取特定元素的 `Part` 列表，或者创建一个新的 `Part` 来标记 DOM 树的一部分。
    * **举例说明:**  假设存在一个 JavaScript API 如下：
        ```javascript
        const template = document.getElementById('my-template');
        const parts = template.getDOMParts(); // 假设有这样一个 API
        parts.forEach(part => {
          console.log(part.name); // 可能输出 "header"
          console.log(part.nodes); // 可能输出包含 <h1> 元素的节点列表
        });
        ```
        这个 API 可能会依赖 `PartRoot` 来获取和管理 `Part` 对象。

* **CSS:**
    * **可能的应用场景 (推测性):**  虽然代码中没有直接体现，但未来可能会有 CSS 选择器能够针对 `Part` 对象进行样式设置。
    * **举例说明 (推测性):** 可能会有类似这样的 CSS 选择器：
        ```css
        ::part(header) { /* 选择名为 "header" 的 part */
          font-weight: bold;
        }
        ```
        这需要浏览器内部将 CSS 选择器与 `Part` 对象关联起来，而 `PartRoot` 负责维护这些 `Part` 对象。

**逻辑推理、假设输入与输出**

假设我们正在处理一个包含以下 HTML 片段的 `Document`：

```html
<div>
  <!-- part-start: section1 -->
  <p id="p1">Paragraph 1</p>
  <span>Span 1</span>
  <!-- part-end: section1 -->
  <p id="p2">Paragraph 2</p>
</div>
```

**假设输入:**  当浏览器解析到这个 HTML 时，可能会创建一个 `DocumentPartRoot` 对象来管理与这个文档相关的 `Part` 对象。 解析器会识别 `<!-- part-start: section1 -->` 和 `<!-- part-end: section1 -->` 注释，并创建一个表示 "section1" 的 `ChildNodePart` 对象。

**逻辑推理 (基于 `RebuildPartsList` 方法):**

当 `cached_parts_list_dirty_` 为 true 时，`RebuildPartsList` 方法会被调用。它会遍历 DOM 树：

1. 从 `FirstIncludedChildNode` 开始遍历（在这个例子中是 `<div>`）。
2. 遇到注释 `<!-- part-start: section1 -->`，这可能标志着一个 `ChildNodePart` 的开始。
3. 继续遍历，直到遇到 `<!-- part-end: section1 -->`。
4. 创建一个新的 `ChildNodePart` 对象，它引用 `<!-- part-start: section1 -->` 和 `<!-- part-end: section1 -->` 之间的节点（`<p id="p1">` 和 `<span>`）。
5. 将这个新的 `ChildNodePart` 添加到 `cached_ordered_parts_` 列表中。

**假设输出:**  `cached_ordered_parts_` 列表将包含一个 `ChildNodePart` 对象，该对象：

* 标记为 "section1" (虽然代码中没有直接体现名称，但这是可能的推断)。
* 包含对 `<p id="p1">` 和 `<span>` 元素的引用。

**用户或编程常见的使用错误**

尽管开发者通常不直接操作 `PartRoot`，但在更高级别的 API 或功能层面，可能会出现以下错误：

1. **不匹配的 Part 起始和结束标记:**  例如，忘记添加结束注释 `<!-- part-end: ... -->`，或者起始和结束标记的名称不一致。这可能导致 `RebuildPartsList` 无法正确识别和创建 `Part` 对象。

   **示例:**
   ```html
   <div>
     <!-- part-start: section1 -->
     <p>Content</p>
   </div>
   ```
   或者
   ```html
   <div>
     <!-- part-start: section1 -->
     <p>Content</p>
     <!-- part-end: section2 -->
   </div>
   ```

2. **嵌套但未正确处理的 Part:**  如果 `Part` 对象可以嵌套，但实现没有正确处理嵌套逻辑，可能会导致意外的结果。 `RebuildPartsList` 中的相关注释 `// TODO(crbug.com/1453291)` 也提到了重叠的 `ChildNodePart` 可能会导致的问题。

   **示例:**
   ```html
   <div>
     <!-- part-start: outer -->
       <!-- part-start: inner -->
       <p>Inner content</p>
       <!-- part-end: inner -->
     <!-- part-end: outer -->
   </div>
   ```
   如果处理不当，可能会创建错误的 `Part` 结构。

3. **在 Minimal API 模式下的误用:**  如果启用了 `DOMPartsAPIMinimalEnabled()`，开发者可能会期望 Part 列表会被缓存，但实际上每次都会重新构建。这可能会导致性能问题，如果开发者在性能敏感的代码中频繁获取 Part 列表。

**用户操作如何一步步到达这里 (作为调试线索)**

作为开发者，我们通常不会直接调试到 `part_root.cc` 这样的底层代码。但是，当涉及到与 "Part" 相关的 Bug 或性能问题时，可能会需要深入到这里进行分析。以下是一些可能导致执行到 `part_root.cc` 代码的用户操作和调试步骤：

1. **页面加载和渲染:**
   * **用户操作:** 用户在浏览器中打开一个包含使用 "Part" 相关特性的网页。
   * **调试线索:**  在 Blink 的渲染流水线中，当解析 HTML 并构建 DOM 树时，可能会调用 `PartRoot` 的相关方法来创建和管理 `Part` 对象。可以在 DOM 构建相关的代码中设置断点，追踪 `Part` 对象的创建过程。

2. **JavaScript 操作 DOM:**
   * **用户操作:** 网页上的 JavaScript 代码动态地修改 DOM 结构，例如添加、删除或移动节点。
   * **调试线索:** 如果这些修改涉及到被 "Part" 对象包含的节点，可能会触发 `PartRoot` 的 `AddPart`、`RemovePart` 或 `RebuildPartsList` 方法。可以在相关的 DOM 操作 JavaScript 代码附近设置断点，并逐步跟踪到 Blink 内部的 `PartRoot` 方法调用。

3. **克隆 DOM 节点:**
   * **用户操作:** JavaScript 代码使用 `cloneNode` 方法复制 DOM 树的一部分。
   * **调试线索:** `CloneParts` 静态方法会在节点克隆过程中被调用，以处理相关的 `Part` 对象。可以在 `cloneNode` 的调用处设置断点，并观察 `CloneParts` 的执行流程。

4. **访问与 "Part" 相关的 JavaScript API:**
   * **用户操作:** 网页上的 JavaScript 代码调用了浏览器提供的、与 "Part" 相关的 API（如果存在）。
   * **调试线索:** 这些 API 的实现很可能会调用 `PartRoot` 的 `getParts` 方法或其他相关方法。可以在这些 API 的实现代码中设置断点。

5. **开发者工具检查:**
   * **用户操作:** 开发者使用浏览器的开发者工具检查 DOM 树。
   * **调试线索:**  开发者工具可能会尝试展示与节点相关的 "Part" 信息，这可能会触发 `PartRoot` 的 `getParts` 方法。

**总结**

`blink/renderer/core/dom/part_root.cc` 文件定义了 `PartRoot` 类，它是 Blink 渲染引擎中用于管理和维护 "Part" 对象的关键组件。虽然它本身不直接与 JavaScript, HTML, CSS 交互，但它为可能构建在其之上的更高级别的 API 和功能提供了基础。理解 `PartRoot` 的功能有助于理解 Blink 内部如何处理 DOM 树的逻辑分段和结构化表示。

Prompt: 
```
这是目录为blink/renderer/core/dom/part_root.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/part_root.h"

#include "base/containers/contains.h"
#include "third_party/blink/renderer/core/dom/child_node_list.h"
#include "third_party/blink/renderer/core/dom/child_node_part.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_part_root.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/part.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

void PartRoot::Trace(Visitor* visitor) const {
  visitor->Trace(cached_ordered_parts_);
}

void PartRoot::AddPart(Part& new_part) {
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  if (cached_parts_list_dirty_) {
    return;
  }
  DCHECK(!base::Contains(cached_ordered_parts_, &new_part));
  cached_ordered_parts_.push_back(&new_part);
}

// If we're removing the first Part in the cached part list, then just remove
// that Part and keep the parts list clean. Otherwise mark it dirty and clear
// the cached list.
// TODO(crbug.com/1453291) The above case happens when we're moving the entire
// tree that contains Parts, or the *first* part of the tree that contains
// Parts. If we're moving the *last* part of the tree, it would be possible
// to detect that situation and remove parts from the end of the parts list.
// The tricky bit there is that we need to know that we're
// doing that, and we only know it's true when we get to the last removal
// and we've removed the entire end of the list of parts.
// TODO(crbug.com/1453291) The comment for this function should get updated
// if we get rid of part tracking.
void PartRoot::RemovePart(Part& part) {
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  if (cached_parts_list_dirty_) {
    return;
  }
  // TODO(crbug.com/1453291) If we go back to tracking parts, we can pop_front
  // this part if it's in the front.
  cached_parts_list_dirty_ = true;
}

// static
void PartRoot::CloneParts(const Node& source_node,
                          Node& destination_node,
                          NodeCloningData& data) {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  DCHECK(data.Has(CloneOption::kPreserveDOMParts));
  DCHECK(!data.Has(CloneOption::kPreserveDOMPartsMinimalAPI));
  if (auto* parts = source_node.GetDOMParts()) {
    for (Part* part : *parts) {
      if (!part->IsValid()) {
        // Only valid parts get cloned. This avoids issues with nesting
        // of invalid parts affecting the part root stack.
        continue;
      }
      if (part->NodeToSortBy() == source_node) {
        // This can be a NodePart or the previousSibling of a ChildNodePart.
        // If this is a ChildNodePart, this will push the new part onto the
        // part root stack.
        part->ClonePart(data, destination_node);
        continue;
      }
      // This should *only* be the nextSibling of a ChildNodePart.
      CHECK(part->GetAsPartRoot()) << "Should be a ChildNodePart";
      DCHECK_EQ(static_cast<ChildNodePart*>(part)->nextSibling(), source_node)
          << "This should be the next sibling node";
      if (data.PartRootStackHasOnlyDocumentRoot()) {
        // If there have been mis-nested parts, abort.
        continue;
      }
      // The top of the part root stack should be the appropriate part.
      ChildNodePart& child_node_part =
          static_cast<ChildNodePart&>(data.CurrentPartRoot());
      child_node_part.setNextSibling(destination_node);
      data.PopPartRoot(child_node_part);
    }
  }
}

void PartRoot::SwapPartsList(PartRoot& other) {
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  cached_ordered_parts_.swap(other.cached_ordered_parts_);
  std::swap(cached_parts_list_dirty_, other.cached_parts_list_dirty_);
}

// |getParts| must always return the contained parts list subject to these
// rules:
//  1. parts are returned in DOM tree order. If more than one part refers to the
//     same Node, parts are returned in the order they were constructed.
//  2. parts referring to nodes that aren't in a document, not in the same
//     document as the owning DocumentPartRoot, or not contained by the root
//     Element of the DocumentPartRoot are not returned.
//  3. parts referring to invalid parts are not returned. For example, a
//     ChildNodePart whose previous_node comes after its next_node.
// To rebuild the parts list, we simply traverse the entire tree under the
// PartRoot (from FirstIncludedChildNode to LastIncludedChildNode), and collect
// any Parts we find. If we find a ChildNodePart (or other PartRoot), we ignore
// Parts until we exit the Partroot.
void PartRoot::RebuildPartsList() {
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  DCHECK(cached_parts_list_dirty_);
  cached_ordered_parts_.clear();
  // Then traverse the tree under the root container and add parts in the order
  // they're found in the tree, and for the same Node, in the order they were
  // constructed.
  Node* node = FirstIncludedChildNode();
  if (!node || !LastIncludedChildNode()) {
    return;  // Empty list
  }
  Node* end_node = LastIncludedChildNode()->nextSibling();
  enum class NestedPartRoot {
    kNone,
    kAtStart,
    kAtEnd
  } nested_part_root = NestedPartRoot::kNone;
  while (node != end_node) {
    Node* next_node = NodeTraversal::Next(*node);
    if (auto* parts = node->GetDOMParts()) {
      // If we were previously at the start of a nested root, we're now at the
      // end.
      nested_part_root = nested_part_root == NestedPartRoot::kAtStart
                             ? NestedPartRoot::kAtEnd
                             : NestedPartRoot::kNone;
      for (Part* part : *parts) {
        if (!part->IsValid()) {
          continue;
        }
        if (PartRoot* part_root = part->GetAsPartRoot()) {
          // Skip the PartRoot itself.
          if (part_root == this) {
            continue;
          }
          // TODO(crbug.com/1453291) It's still possible to construct two
          // overlapping ChildNodeParts, e.g. both with the same endpoints,
          // overlapping endpoints, or adjoining endpoings (previous==next).
          // Eventually that should not be legal. Until then, ignore the second
          // and subsequent nested part roots we find. When such parts are no
          // longer legal, |nested_part_root| can be removed.
          if (nested_part_root != NestedPartRoot::kNone) {
            continue;
          }
          // We just entered a contained PartRoot; we should be at the
          // FirstIncludedChildNode. Skip all descendants of this PartRoot and
          // move to the last included child. Make sure to process any other
          // Parts that are on the endpoint Nodes.
          DCHECK_EQ(part_root->FirstIncludedChildNode(), node);
          DCHECK_EQ(part_root->LastIncludedChildNode()->parentNode(),
                    node->parentNode());
          next_node = part_root->LastIncludedChildNode();
          nested_part_root = NestedPartRoot::kAtStart;
        }
        if (part->NodeToSortBy() != node) {
          continue;
        }
        DCHECK(!base::Contains(cached_ordered_parts_, part));
        cached_ordered_parts_.push_back(part);
      }
    }
    node = next_node;
  }
}

namespace {

// This is used only in the case of DOMPartsAPIMinimal enabled, and it just
// fresh-builds the parts list, and/or just the node lists, every time with no
// caching.
void BuildPartsList(PartRoot& part_root,
                    PartRoot::PartList* part_list,
                    PartRoot::PartNodeList* node_part_nodes,
                    PartRoot::PartNodeList* child_node_part_nodes) {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  Node* node = part_root.FirstIncludedChildNode();
  Node* end_node = part_root.LastIncludedChildNode();
  if (!node || !end_node) {
    return;  // Empty lists
  }
  if (!part_root.IsDocumentPartRoot()) {
    // This is a ChildNodePart, so we need to skip the first start node, or
    // we'll just re-detect this ChildNodePart. If `node` doesn't have a
    // nextSibling (i.e. this ChildNodePart is mal-formed), then `node` will be
    // set to nullptr, and the entire while loop below will be properly skipped.
    node = node->nextSibling();
  } else {
    end_node = end_node->nextSibling();
  }
  while (node != end_node) {
    if (node->HasNodePart()) {
      if (Comment* start_comment = DynamicTo<Comment>(node);
          start_comment &&
          start_comment->data() == kChildNodePartStartCommentData) {
        // We've found the starting node of a child node range - scan to find
        // the ending node, skipping contents and nested ChildNodeParts.
        unsigned nested_child_node_part_count = 0;
        while (node->HasNextSibling() &&
               ((node = node->nextSibling()) != end_node)) {
          if (!IsA<Comment>(node)) [[likely]] {
            continue;
          }
          Comment& end_comment = *To<Comment>(node);
          if (!end_comment.HasNodePart()) {
            continue;  // Plain comment, not ChildNodePart marker.
          }
          if (end_comment.data() == kChildNodePartEndCommentData) [[likely]] {
            if (!nested_child_node_part_count) [[likely]] {
              // Found the end of the child node part.
              if (part_list) {
                part_list->push_back(MakeGarbageCollected<ChildNodePart>(
                    part_root, *start_comment, end_comment, Vector<String>()));
              }
              if (child_node_part_nodes) {
                child_node_part_nodes->push_back(start_comment);
                child_node_part_nodes->push_back(&end_comment);
              }
              break;
            }
            --nested_child_node_part_count;
          } else if (end_comment.data() == kChildNodePartStartCommentData) {
            ++nested_child_node_part_count;
          }
        }
      } else {
        // This is just a NodePart.
        if (part_list) {
          part_list->push_back(MakeGarbageCollected<NodePart>(
              part_root, *node, Vector<String>()));
        }
        if (node_part_nodes) {
          node_part_nodes->push_back(node);
        }
      }
    }
    node = NodeTraversal::Next(*node);
  }
}

}  // namespace

const PartRoot::PartNodeList& PartRoot::getNodePartNodes() {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  auto* nodes = MakeGarbageCollected<PartRoot::PartNodeList>();
  BuildPartsList(*this, nullptr, nodes, nullptr);
  return *nodes;
}

const PartRoot::PartNodeList& PartRoot::getChildNodePartNodes() {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  auto* nodes = MakeGarbageCollected<PartRoot::PartNodeList>();
  BuildPartsList(*this, nullptr, nullptr, nodes);
  return *nodes;
}

const PartRoot::PartList& PartRoot::getParts() {
  if (RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
    DCHECK(cached_ordered_parts_.empty());
    DCHECK(!cached_parts_list_dirty_);
    auto* parts = MakeGarbageCollected<PartRoot::PartList>();
    BuildPartsList(*this, parts, nullptr, nullptr);
    return *parts;
  } else if (cached_parts_list_dirty_) {
    RebuildPartsList();
    cached_parts_list_dirty_ = false;
  } else {
    // Remove invalid cached parts.
    bool remove_invalid = false;
    for (auto& part : cached_ordered_parts_) {
      if (!part->IsValid()) {
        remove_invalid = true;
        break;
      }
    }
    if (remove_invalid) {
      PartRoot::PartList new_list;
      for (auto& part : cached_ordered_parts_) {
        if (part->IsValid()) {
          new_list.push_back(part);
        }
      }
      cached_ordered_parts_.swap(new_list);
    }
  }
  return cached_ordered_parts_;
}

// static
PartRoot* PartRoot::GetPartRootFromUnion(PartRootUnion* root_union) {
  if (root_union->IsChildNodePart()) {
    return root_union->GetAsChildNodePart();
  }
  CHECK(root_union->IsDocumentPartRoot());
  return root_union->GetAsDocumentPartRoot();
}

// static
PartRootUnion* PartRoot::GetUnionFromPartRoot(PartRoot* root) {
  if (!root) {
    return nullptr;
  }
  if (root->IsDocumentPartRoot()) {
    return MakeGarbageCollected<PartRootUnion>(
        static_cast<DocumentPartRoot*>(root));
  }
  return MakeGarbageCollected<PartRootUnion>(static_cast<ChildNodePart*>(root));
}

}  // namespace blink

"""

```
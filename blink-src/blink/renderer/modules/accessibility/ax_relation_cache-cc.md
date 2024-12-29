Response:
My thought process to analyze the provided code snippet and answer the prompt goes like this:

1. **Understand the Goal:** The request is to analyze the `AXRelationCache.cc` file, explain its purpose, identify connections to web technologies (JS/HTML/CSS), highlight logical reasoning, point out potential errors, trace user actions, and summarize its functionality (for part 1 of 2).

2. **Initial Code Scan (High-Level):** I first quickly read through the code, looking for keywords and overall structure. I noticed:
    * Includes for various Blink/Chromium components (DOM, HTML elements, layout, accessibility).
    * Data structures like `HashMap`, `HashSet`, `Vector`.
    * Methods related to "cache," "relations," "update," "owns," "labelledby," "describedby," "activedescendant," etc.
    * Use of ARIA attributes (e.g., `aria-owns`, `aria-labelledby`).
    * Checks for cycles and validity.

3. **Identify Core Functionality (The "What"):** Based on the keywords and structure, it became clear that `AXRelationCache` is responsible for managing accessibility relationships between elements. It caches these relationships to avoid recalculating them repeatedly. The relationships are primarily defined by ARIA attributes and the `<label for>` attribute.

4. **Connect to Web Technologies (The "How"):**  This is where the connection to JS/HTML/CSS comes in:
    * **HTML:** The code directly deals with HTML elements (`<label>`, `<div>`, etc.) and their attributes (`for`, `aria-*`). The relationships are defined *in* the HTML structure and attributes.
    * **JavaScript:** While the C++ code itself isn't JavaScript, the relationships it manages are often manipulated by JavaScript. For example, JavaScript can dynamically add or change ARIA attributes, and this cache needs to reflect those changes. The code mentions `ElementInternals`, which can be involved when custom elements and their shadow DOM are manipulated with JavaScript.
    * **CSS:**  Indirectly, CSS can influence accessibility, especially through `display: none` or `visibility: hidden`. While this file doesn't directly deal with CSS *properties*, it needs to be aware of the *effects* of CSS, as hidden elements might impact the validity or inclusion of accessibility relationships. The code mentions `LayoutObject`, hinting at this connection.

5. **Analyze Logical Reasoning (The "Why"):** The code includes checks and validation steps. This involves logical reasoning:
    * **Cycle Detection:** The `ContainsCycle` function implements logic to prevent circular ownership, which would break accessibility trees.
    * **Validity Checks:** `IsValidOwnsRelation`, `IsValidOwner`, `IsValidOwnedChild` enforce rules about what constitutes a valid ARIA relationship. These are based on accessibility best practices and specifications.

6. **Consider Potential Errors (The "What Could Go Wrong"):** Based on the validation logic, I could identify potential authoring errors:
    * Creating cycles in ARIA relationships (e.g., element A owns element B, and element B owns element A).
    * Using `aria-owns` on elements that are not allowed to own other elements (e.g., `<br>`, `input`).
    * Attempting to own elements that are not valid children (e.g., `<area>` outside of a `<map>`, `<option>` outside of a `<select>`).

7. **Trace User Actions (The "How Did We Get Here"):**  To debug issues related to this code, understanding how user actions lead to its execution is crucial. I thought about the typical browser rendering pipeline:
    * **Page Load/Navigation:** When a page loads, the browser parses the HTML, and this cache is initialized to capture existing relationships.
    * **DOM Manipulation (JS):**  JavaScript changes to the DOM (adding/removing elements, modifying attributes) trigger updates to the cache.
    * **User Interaction:** Certain user interactions (like focusing on an element or expanding a menu) might trigger accessibility updates that rely on the cached relationships.

8. **Synthesize Functionality (The Summary):** Finally, I distilled the analysis into a concise summary of the `AXRelationCache`'s purpose.

9. **Structure the Answer:** I organized the answer into the requested sections (functionality, relations to web tech, logical reasoning, usage errors, user actions, and summary) for clarity and completeness. I used examples to illustrate the connections to web technologies and potential errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this is just about ARIA.
* **Correction:** Realized the `<label for>` attribute is also a key part of accessibility relationships and is handled by this code.
* **Initial thought:**  Focus solely on the `aria-owns` attribute.
* **Correction:** Noticed the code handles other ARIA attributes (`labelledby`, `describedby`, etc.) and that's a significant part of its function.
* **Initial thought:**  The "logical reasoning" is just simple checks.
* **Correction:** Recognized the cycle detection logic as a more involved form of reasoning.
* **Initial thought:** The user action is just "the page loads."
* **Correction:**  Considered more dynamic scenarios involving JavaScript and user interactions.

By following this thought process, breaking down the code into smaller parts, connecting it to broader concepts, and iterating on my understanding, I was able to generate a comprehensive and accurate answer to the prompt.
这是 `blink/renderer/modules/accessibility/ax_relation_cache.cc` 文件的第一部分，它主要负责 **缓存和管理 DOM 节点之间的可访问性关系**。这些关系通常由 ARIA 属性（如 `aria-owns`, `aria-labelledby`, `aria-describedby` 等）以及 HTML 属性（如 `<label for>`）定义。

以下是其功能的详细归纳：

**主要功能：**

1. **关系缓存:**
   -  存储和管理 DOM 元素之间的可访问性关系，以便在需要时快速查找，避免重复计算。
   -  使用多种哈希表 (`HashMap`, `HashSet`) 来存储不同类型的关系，例如：
      - `aria_owns_id_map_`: 存储 `aria-owns` 关系，键是目标元素的 ID，值是拥有该元素的元素的 ID 集合。
      - `aria_owns_node_map_`: 存储 `aria-owns` 关系，键是目标元素的 DOM 节点 ID，值是拥有该元素的元素的 DOM 节点 ID 集合。
      - `aria_text_relations_id_map_`: 存储文本关系（如 `aria-labelledby`, `aria-describedby`），键是目标元素的 ID，值是引用该 ID 的元素的 ID 集合。
      - `aria_text_relations_node_map_`: 存储文本关系，键是目标元素的 DOM 节点 ID，值是引用该节点的元素的 DOM 节点 ID 集合。
      - 其他类似的映射用于存储 `aria-activedescendant`, `aria-controls`, `aria-details` 等关系。
      - `aria_owned_child_to_owner_mapping_`: 存储被 `aria-owns` 的子元素到其所有者元素的映射。

2. **关系初始化:**
   - 在 `Init()` 方法中，当 `AXRelationCache` 初始化时，会扫描整个文档（包括 Shadow DOM），查找并缓存已存在的可访问性关系。
   - `DoInitialDocumentScan()` 负责遍历文档并调用 `CacheRelations()` 来缓存每个元素的关系。

3. **关系缓存更新:**
   - `CacheRelations()` 方法负责解析给定元素的 ARIA 属性和 HTML 属性，并将它们对应的关系添加到缓存中。
   - 它会更新不同类型的关系映射，例如 `UpdateReverseOwnsRelations`, `UpdateReverseTextRelations`, `UpdateReverseActiveDescendantRelations`, `UpdateReverseOtherRelations`。
   - 对于 `aria-owns` 关系，它还会将拥有者元素的 ID 添加到 `owner_axids_to_update_` 集合中，以便在布局完成后进行进一步处理。

4. **反向关系管理:**
   - 代码使用 "反向关系" 的概念，即不仅存储从拥有者到目标的映射，也存储从目标到拥有者的映射。这使得查找哪些元素引用了特定目标元素变得高效。
   - 例如，对于 `aria-labelledby`，如果一个元素使用了 `aria-labelledby="id1 id2"`，则 `aria_text_relations_id_map_` 会存储 `id1` 和 `id2` 到该元素 ID 的映射。

5. **关系有效性检查:**
   - 提供了一些方法来验证 ARIA 关系的有效性，例如 `IsValidOwnsRelation`, `IsValidOwner`, `IsValidOwnedChild`。
   - 这些检查可以防止创建无效的或循环的 ARIA 关系，确保可访问性树的正确性。
   - `ContainsCycle()` 函数用于检测 `aria-owns` 关系中是否存在循环。

6. **脏标记和更新:**
   -  使用 `owner_axids_to_update_` 集合来跟踪需要更新 `aria-owns` 关系的元素。
   -  `ProcessUpdatesWithCleanLayout()` 方法会在布局完成后处理这些更新。
   -  `IsDirty()` 方法用于检查是否有需要更新的关系。

**与 JavaScript, HTML, CSS 的关系及举例：**

1. **HTML:** `AXRelationCache` 直接处理 HTML 元素和属性。
   - **例子:** 当 HTML 中有 `<div aria-labelledby="label1">Content</div>` 时，`CacheRelations()` 会解析 `aria-labelledby` 属性，并将 "label1" 和该 `div` 元素的 ID 存储到 `aria_text_relations_id_map_` 中。
   - **例子:** 当 HTML 中有 `<label for="input1">Label</label> <input type="text" id="input1">` 时，`CacheRelations()` 会解析 `<label>` 的 `for` 属性，并将 "input1" 记录在 `all_previously_seen_label_target_ids_` 中。

2. **JavaScript:** JavaScript 可以动态地修改 HTML 结构和属性，这会影响 `AXRelationCache` 的缓存。
   - **例子:**  如果 JavaScript 使用 `element.setAttribute('aria-owns', 'element2')`，那么当 Blink 的渲染引擎处理这个更改时，`AXRelationCache` 会更新其 `aria_owns_id_map_` 和 `aria_owns_node_map_` 以反映这个新的关系。
   - **例子:**  如果 JavaScript 动态创建了一个带有 `aria-describedby` 属性的元素并将其添加到 DOM 中，`AXRelationCache` 会在元素连接到文档后缓存这个关系。

3. **CSS:** CSS 主要影响元素的视觉呈现，但间接地，通过控制元素的显示与隐藏，也可能影响可访问性关系。
   - **例子:**  如果一个被 `aria-labelledby` 引用的元素通过 `display: none` 隐藏，虽然关系仍然存在于 `AXRelationCache` 中，但辅助技术可能会以不同的方式处理这种情况。`AXRelationCache` 本身不直接处理 CSS 属性，但它依赖于 DOM 结构，而 CSS 会影响 DOM 的渲染和可访问性树的构建。

**逻辑推理及假设输入输出：**

**假设输入:**

```html
<div id="owner">
  <button id="owned1" aria-label="Owned Button 1"></button>
  <span id="owned2">Owned Text 2</span>
</div>
<p aria-owns="owned1 owned2" id="paragraph"></p>
```

**逻辑推理:**

当 `CacheRelations()` 处理 `<p id="paragraph" aria-owns="owned1 owned2">` 时：

1. `IdsFromAttribute()` 会将 `aria-owns` 属性的值 "owned1 owned2" 分割成 `["owned1", "owned2"]`。
2. `UpdateReverseOwnsRelations()` 会被调用。
3. 对于 "owned1"，`aria_owns_id_map_["owned1"]` 将会包含 "paragraph" 的 DOM 节点 ID。
4. 对于 "owned2"，`aria_owns_id_map_["owned2"]` 将会包含 "paragraph" 的 DOM 节点 ID。
5. 同时，`owner_axids_to_update_` 集合将会包含 "paragraph" 的 DOM 节点 ID，以便后续处理 `aria-owns` 关系。

**假设输出 (部分 `aria_owns_id_map_`):**

```
{
  "owned1": { "paragraph 的 DOM 节点 ID" },
  "owned2": { "paragraph 的 DOM 节点 ID" }
}
```

**用户或编程常见的使用错误及举例：**

1. **循环的 `aria-owns` 关系:**
   - **错误例子:**
     ```html
     <div id="a" aria-owns="b"></div>
     <div id="b" aria-owns="a"></div>
     ```
   - `ContainsCycle()` 函数会检测到这种循环，并且 `IsValidOwnsRelation()` 会返回 `false`，阻止建立这个无效的关系。

2. **将自身作为 `aria-owns` 的目标:**
   - **错误例子:**
     ```html
     <div id="self" aria-owns="self"></div>
     ```
   - `ContainsCycle()` 也会检测到这种情况。

3. **`aria-owns` 指向不存在的 ID:**
   - **错误例子:**
     ```html
     <div aria-owns="nonexistent"></div>
     ```
   - `AXRelationCache` 会尝试查找该 ID 的元素，但如果找不到，则不会建立关系。这可能导致辅助技术无法正确理解页面的结构。

4. **在不允许拥有子元素的元素上使用 `aria-owns`:**
   - **错误例子:**
     ```html
     <br aria-owns="someElement">
     ```
   - `IsValidOwner()` 会返回 `false`，阻止在这种元素上使用 `aria-owns`。

5. **尝试拥有不允许被拥有的元素:**
   - **错误例子:**
     ```html
     <div aria-owns="areaElement"></div>
     <map><area id="areaElement"></area></map>
     ```
   - `IsValidOwnedChild()` 会返回 `false`，因为 `<area>` 元素通常只能被 `<map>` 元素拥有。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户加载包含 ARIA 属性或 `<label for>` 的 HTML 页面:**  当浏览器解析 HTML 时，Blink 引擎会创建 DOM 树，并初始化 `AXRelationCache`。
2. **JavaScript 动态修改 DOM 结构或 ARIA 属性:** 用户与页面交互或页面上的 JavaScript 代码执行可能会修改 DOM。例如，通过点击按钮或提交表单，JavaScript 可能会添加、删除或修改元素的 ARIA 属性。
3. **Blink 引擎处理 DOM 变化:** 当 DOM 发生变化时，Blink 引擎会收到通知，并更新其内部数据结构，包括 `AXRelationCache`。
4. **辅助技术请求可访问性信息:** 屏幕阅读器等辅助技术会通过 Chromium 的 Accessibility 接口请求页面的可访问性信息。
5. **`AXRelationCache` 提供缓存的关系数据:** 当需要确定元素之间的可访问性关系时，Blink 引擎会查询 `AXRelationCache` 以获取缓存的信息。

**调试线索:**

- 如果辅助技术无法正确识别页面元素之间的关系，例如，屏幕阅读器没有将 `<label>` 与其关联的 `<input>` 正确关联起来，或者元素的 `aria-owns` 关系没有生效，那么可能需要检查 `AXRelationCache` 是否正确缓存了这些关系。
- 可以通过在 `AXRelationCache` 的关键方法（如 `CacheRelations`, `UpdateReverseOwnsRelations` 等）中添加日志输出来跟踪关系的建立过程。
- 使用 Chromium 的开发者工具中的 Accessibility 面板可以查看页面的可访问性树，以及元素的属性和关系。这有助于确定问题是否出在关系的缓存上。

**总结其功能:**

总而言之，`AXRelationCache` 的主要功能是 **高效地缓存和管理 Chromium Blink 引擎中 DOM 元素之间的可访问性关系**。它通过监听 DOM 变化并解析 ARIA 属性和 HTML 属性来维护这些关系，并提供机制来验证关系的有效性，从而确保辅助技术能够正确理解和呈现网页内容。 这是实现 Web 内容可访问性的一个关键组件。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_relation_cache.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_relation_cache.h"

#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/shadow_including_tree_order_traversal.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/modules/accessibility/ax_node_object.h"
#include "ui/accessibility/ax_common.h"

namespace blink {

namespace {
void IdsFromAttribute(const Element& element,
                      Vector<AtomicString>& ids,
                      const QualifiedName& attr_name) {
  SpaceSplitString split_ids(AXObject::AriaAttribute(element, attr_name));
  ids.AppendRange(split_ids.begin(), split_ids.end());
}
}  // namespace

AXRelationCache::AXRelationCache(AXObjectCacheImpl* object_cache)
    : object_cache_(object_cache) {}

AXRelationCache::~AXRelationCache() = default;

void AXRelationCache::Init() {
  // Init the relation cache with elements already present.
  // Normally, these relations would be cached when the node is first attached,
  // via AXObjectCacheImpl::NodeIsConnected().
  // The initial scan must include both flat traversal and node traversal,
  // othrwise some connected elements can be missed.
  DoInitialDocumentScan(object_cache_->GetDocument());
  if (Document* popup_doc = object_cache_->GetPopupDocumentIfShowing()) {
    DoInitialDocumentScan(*popup_doc);
  }

#if DCHECK_IS_ON()
  is_initialized_ = true;
#endif
}

void AXRelationCache::DoInitialDocumentScan(Document& document) {
#if DCHECK_IS_ON()
  DCHECK(document.Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle " << document.Lifecycle().ToString();
#endif

  // TODO(crbug.com/1473733) Address flaw that all DOM ids are being cached
  // together regardless of their TreeScope, which can lead to conflicts.
  // Traverse all connected nodes in the document, via both DOM and shadow DOM.
  for (Node& node :
       ShadowIncludingTreeOrderTraversal::DescendantsOf(document)) {
    if (Element* element = DynamicTo<Element>(node)) {
      // Cache relations that do not require an AXObject.
      CacheRelations(*element);

      // Caching aria-owns requires creating target AXObjects.
      // TODO(crbug.com/41469336): Support aria-owns relations set via
      // explicitly set attr-elements on element or element internals.
      if (AXObject::HasAriaAttribute(*element, html_names::kAriaOwnsAttr)) {
        owner_axids_to_update_.insert(element->GetDomNodeId());
      }
    }
  }
}

void AXRelationCache::CacheRelations(Element& element) {
  DOMNodeId node_id = element.GetDomNodeId();

#if DCHECK_IS_ON()
  // Register that the relations for this element have been cached, to
  // help enforce that relations are never missed.
  DCHECK(node_id);
  processed_elements_.insert(node_id);
#endif

  UpdateRegisteredIdAttribute(element, node_id);

  // Register aria-owns.
  UpdateReverseOwnsRelations(element);

  // Register <label for>.
  // TODO(crbug.com/41469336): Track reverse relations set via explicitly set
  // attr-elements for htmlFor, when/if this is supported.
  const auto& for_id = element.FastGetAttribute(html_names::kForAttr);
  if (!for_id.empty()) {
    all_previously_seen_label_target_ids_.insert(for_id);
  }

  // Register aria-labelledby, aria-describedby relations.
  UpdateReverseTextRelations(element);

  // Register aria-activedescendant.
  UpdateReverseActiveDescendantRelations(element);

  // Register aria-controls, aria-details, aria-errormessage, aria-flowto, and
  // aria-actions.
  UpdateReverseOtherRelations(element);
}

#if DCHECK_IS_ON()
void AXRelationCache::CheckRelationsCached(Element& element) {
  if (!is_initialized_) {
    return;
  }
  CheckElementWasProcessed(element);

  // Check aria-owns.
  Vector<AtomicString> owns_ids;
  HeapVector<Member<Element>> owns_elements;
  GetRelationTargets(element, html_names::kAriaOwnsAttr, owns_ids,
                     owns_elements);
  for (const auto& owns_id : owns_ids) {
    DCHECK(aria_owns_id_map_.Contains(owns_id))
        << element << " with aria-owns=" << owns_id
        << " and DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
        << " should already be in cache.";
  }
  for (const Member<Element>& owns_element : owns_elements) {
    DOMNodeId owns_dom_node_id =
        DOMNodeIds::ExistingIdForNode(owns_element.Get());
    DCHECK(owns_dom_node_id && aria_owns_node_map_.Contains(owns_dom_node_id))
        << element << " with ariaOwnsElements including " << owns_element
        << " and DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
        << " should already be in cache.";
  }

  // Check <label for>.
  // TODO(crbug.com/41469336): Track reverse relations set via explicitly set
  // attr-elements for htmlFor, when/if this is supported.
  if (IsA<HTMLLabelElement>(element)) {
    const auto& for_id = element.FastGetAttribute(html_names::kForAttr);
    if (!for_id.empty()) {
      DCHECK(all_previously_seen_label_target_ids_.Contains(for_id))
          << element << " <label for=" << for_id
          << " with DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
          << " should already be in cache.";
    }
  }

  // Check aria-labelledby, aria-describedby.
  for (const QualifiedName& attribute : GetTextRelationAttributes()) {
    Vector<AtomicString> text_relation_ids;
    HeapVector<Member<Element>> text_relation_elements;
    GetRelationTargets(element, attribute, text_relation_ids,
                       text_relation_elements);

    for (const auto& text_relation_id : text_relation_ids) {
      DCHECK(aria_text_relations_id_map_.Contains(text_relation_id))
          << element << " with " << attribute << "=" << text_relation_id
          << " and DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
          << " should already be in cache.";
    }
    for (const Member<Element>& text_relation_element :
         text_relation_elements) {
      DOMNodeId text_relation_dom_node_id =
          DOMNodeIds::ExistingIdForNode(text_relation_element.Get());
      DCHECK(text_relation_dom_node_id &&
             aria_text_relations_node_map_.Contains(text_relation_dom_node_id))
          << element << " with " << attribute
          << "-associated elements including " << text_relation_element
          << " and DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
          << " should already be in cache.";
    }
  }

  // Check aria-activedescendant.
  const AtomicString& activedescendant_id =
      AXObject::AriaAttribute(element, html_names::kAriaActivedescendantAttr);

  if (!activedescendant_id.empty()) {
    DCHECK(aria_activedescendant_id_map_.Contains(activedescendant_id))
        << element << " with aria-activedescendant=" << activedescendant_id
        << " and DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
        << " should already be in cache.";
  } else {
    HeapVector<Member<Element>> activedescendant_elements;
    GetExplicitlySetElementsForAttr(element,
                                    html_names::kAriaActivedescendantAttr,
                                    activedescendant_elements);
    if (!activedescendant_elements.empty()) {
      Member<Element>& active_descendant_element = activedescendant_elements[0];
      DOMNodeId active_descendant_dom_node_id =
          DOMNodeIds::ExistingIdForNode(active_descendant_element);
      DCHECK(active_descendant_dom_node_id &&
             aria_activedescendant_node_map_.Contains(
                 active_descendant_dom_node_id))
          << element << " with ariaActiveDescendantElement "
          << active_descendant_element
          << " and DOMNodeId=" << DOMNodeIds::ExistingIdForNode(&element)
          << " should already be in cache.";
    }
  }
}

void AXRelationCache::CheckElementWasProcessed(Element& element) {
  DOMNodeId node_id = DOMNodeIds::ExistingIdForNode(&element);
  if (node_id && processed_elements_.Contains(node_id)) {
    return;
  }

  // Find first ancestor that was not processed.
  Node* ancestor = &element;
  if (element.GetDocument().IsFlatTreeTraversalForbidden()) {
    DVLOG(1) << "Note: flat tree traversal forbidden.";
  } else {
    while (true) {
      Node* next_ancestor = FlatTreeTraversal::Parent(*ancestor);
      if (!next_ancestor) {
        break;
      }
      if (!IsA<Element>(next_ancestor)) {
        break;
      }

      node_id = DOMNodeIds::ExistingIdForNode(next_ancestor);
      if (node_id && processed_elements_.Contains(node_id)) {
        // next_ancestor was not processed, therefore ancestor is the
        // top unprocessed node.
        break;
      }
      ancestor = next_ancestor;
    }
  }

  AXObject* obj = Get(ancestor);
  NOTREACHED()
      << "The following element was attached to the document, but "
         "UpdateCacheAfterNodeIsAttached() was never called with it, and it "
         "did not exist when the cache was first initialized:"
      << "\n* Element: " << ancestor
      << "\n* LayoutObject: " << ancestor->GetLayoutObject()
      << "\n* AXObject: " << obj << "\n"
      << (obj && obj->ParentObjectIncludedInTree()
              ? obj->ParentObjectIncludedInTree()->GetAXTreeForThis()
              : "");
}
#endif

void AXRelationCache::ProcessUpdatesWithCleanLayout() {
  HashSet<DOMNodeId> old_owner_axids_to_update;
  old_owner_axids_to_update.swap(owner_axids_to_update_);

  for (DOMNodeId aria_owner_axid : old_owner_axids_to_update) {
    AXObject* obj = ObjectFromAXID(aria_owner_axid);
    if (obj) {
      UpdateAriaOwnsWithCleanLayout(obj);
    }
  }

  owner_axids_to_update_.clear();
}

bool AXRelationCache::IsDirty() const {
  return !owner_axids_to_update_.empty();
}

bool AXRelationCache::IsAriaOwned(const AXObject* child, bool check) const {
  if (!child)
    return false;
  DCHECK(!child->IsDetached()) << "Child was detached: " << child;
  bool is_owned =
      aria_owned_child_to_owner_mapping_.Contains(child->AXObjectID());
  if (is_owned) {
    return true;
  }

  if (!check) {
    return false;
  }

  // Ensure that unowned objects have the expected parent.
  AXObject* parent = child->ParentObjectIfPresent();
  if (parent && parent->GetElement() && child->GetElement() &&
      !child->GetElement()->IsPseudoElement()) {
    Node* natural_parent = AXObject::GetParentNodeForComputeParent(
        *object_cache_, child->GetElement());
    if (parent->GetNode() != natural_parent) {
      std::ostringstream msg;
      msg << "Unowned child should have natural parent:" << "\n* Child: "
          << child << "\n* Actual parent: " << parent
          << "\n* Natural ax parent: " << object_cache_->Get(natural_parent)
          << "\n* Natural dom parent: " << natural_parent << " #"
          << natural_parent->GetDomNodeId() << "\n* Owners to update:";
      for (AXID id : owner_axids_to_update_) {
        msg << " " << id;
      }
      DUMP_WILL_BE_CHECK(false) << msg.str();
    }
  }

  return false;
}

AXObject* AXRelationCache::GetAriaOwnedParent(const AXObject* child) const {
  // Child IDs may still be present in owning parents whose list of children
  // have been marked as requiring an update, but have not been updated yet.
  HashMap<AXID, AXID>::const_iterator iter =
      aria_owned_child_to_owner_mapping_.find(child->AXObjectID());
  if (iter == aria_owned_child_to_owner_mapping_.end())
    return nullptr;
  return ObjectFromAXID(iter->value);
}

AXObject* AXRelationCache::ValidatedAriaOwner(const AXObject* child) {
  if (!child->GetNode()) {
    return nullptr;
  }
  AXObject* owner = GetAriaOwnedParent(child);
  if (!owner || IsValidOwnsRelation(owner, *child->GetNode())) {
    return owner;
  }
  RemoveOwnedRelation(child->AXObjectID());
  return nullptr;
}

void AXRelationCache::GetExplicitlySetElementsForAttr(
    const Element& source,
    const QualifiedName& attr_name,
    HeapVector<Member<Element>>& target_elements) {
  if (source.HasExplicitlySetAttrAssociatedElements(attr_name)) {
    HeapLinkedHashSet<WeakMember<Element>>* explicitly_set_elements =
        source.GetExplicitlySetElementsForAttr(attr_name);
    for (const WeakMember<Element>& element : *explicitly_set_elements) {
      target_elements.push_back(element);
    }
    return;
  }

  const ElementInternals* element_internals = source.GetElementInternals();
  if (!element_internals) {
    return;
  }

  const FrozenArray<Element>* element_internals_attr_elements =
      element_internals->GetElementArrayAttribute(attr_name);

  if (!element_internals_attr_elements) {
    return;
  }

  target_elements = element_internals_attr_elements->AsVector();
}

void AXRelationCache::GetRelationTargets(
    const Element& source,
    const QualifiedName& attr_name,
    Vector<AtomicString>& target_ids,
    HeapVector<Member<Element>>& target_elements) {
  const AtomicString& ids = AXObject::AriaAttribute(source, attr_name);
  if (!ids.empty()) {
    // If the attribute is set to an ID list string, the IDs are the primary key
    // for the relation.
    IdsFromAttribute(source, target_ids, attr_name);
    return;
  }

  GetExplicitlySetElementsForAttr(source, attr_name, target_elements);
}

void AXRelationCache::UpdateReverseRelations(
    Element& source,
    const QualifiedName& attr_name,
    TargetIdToSourceNodeMap& id_map,
    TargetNodeToSourceNodeMap& node_map) {
  Vector<AtomicString> target_ids;
  HeapVector<Member<Element>> target_elements;
  GetRelationTargets(source, attr_name, target_ids, target_elements);
  UpdateReverseIdAttributeRelations(id_map, &source, target_ids);
  Vector<DOMNodeId> target_nodes;
  for (const Member<Element>& element : target_elements) {
    target_nodes.push_back(element->GetDomNodeId());
  }
  UpdateReverseElementAttributeRelations(node_map, &source, target_nodes);
}

// Update reverse relation map, where source is related to target_ids.
void AXRelationCache::UpdateReverseIdAttributeRelations(
    TargetIdToSourceNodeMap& id_map,
    Node* source,
    const Vector<AtomicString>& target_ids) {
  // Add entries to reverse map.
  for (const AtomicString& target_id : target_ids) {
    auto result = id_map.insert(target_id, HashSet<DOMNodeId>());
    result.stored_value->value.insert(source->GetDomNodeId());
  }
}

// Update reverse relation map, where source is related to
// target_elements.
void AXRelationCache::UpdateReverseElementAttributeRelations(
    TargetNodeToSourceNodeMap& node_map,
    Node* source,
    const Vector<DOMNodeId>& target_nodes) {
  // Add entries to reverse map.
  for (const DOMNodeId& target_node : target_nodes) {
    auto result = node_map.insert(target_node, HashSet<DOMNodeId>());
    result.stored_value->value.insert(source->GetDomNodeId());
  }
}

Vector<QualifiedName>& AXRelationCache::GetTextRelationAttributes() {
  DEFINE_STATIC_LOCAL(
      Vector<QualifiedName>, text_attributes,
      ({html_names::kAriaLabelledbyAttr, html_names::kAriaLabeledbyAttr,
        html_names::kAriaDescribedbyAttr}));
  return text_attributes;
}

void AXRelationCache::UpdateReverseTextRelations(Element& source) {
  Vector<QualifiedName> text_attributes = GetTextRelationAttributes();
  for (const QualifiedName& attribute : text_attributes) {
    UpdateReverseTextRelations(source, attribute);
  }
}

void AXRelationCache::UpdateReverseTextRelations(
    Element& source,
    const QualifiedName& attr_name) {
  Vector<AtomicString> id_vector;
  HeapVector<Member<Element>> target_elements;
  GetRelationTargets(source, attr_name, id_vector, target_elements);
  UpdateReverseIdAttributeTextRelations(source, id_vector);
  UpdateReverseElementAttributeTextRelations(source, target_elements);
}

void AXRelationCache::UpdateReverseIdAttributeTextRelations(
    Element& source,
    const Vector<AtomicString>& target_ids) {
  if (target_ids.empty()) {
    return;
  }

  Vector<AtomicString> new_target_ids;
  for (const AtomicString& id : target_ids) {
    if (aria_text_relations_id_map_.Contains(id)) {
      continue;
    }
    new_target_ids.push_back(id);
  }

  // Update the target ids so that the point back to the relation source node.
  UpdateReverseIdAttributeRelations(aria_text_relations_id_map_, &source,
                                    target_ids);

  // Mark all of the new text relation targets dirty.
  TreeScope& scope = source.GetTreeScope();
  for (const AtomicString& id : new_target_ids) {
    MarkNewRelationTargetDirty(scope.getElementById(id));
  }
}

void AXRelationCache::UpdateReverseElementAttributeTextRelations(
    Element& source,
    const HeapVector<Member<Element>>& target_elements) {
  if (target_elements.empty()) {
    return;
  }

  Vector<DOMNodeId> target_nodes;
  HeapVector<Member<Element>> new_target_elements;
  for (const Member<Element>& element : target_elements) {
    DOMNodeId dom_node_id = element->GetDomNodeId();
    target_nodes.push_back(dom_node_id);

    if (!aria_text_relations_node_map_.Contains(element->GetDomNodeId())) {
      new_target_elements.push_back(element);
    }
  }

  // Update the target nodes so that they point back to the relation source
  // node.
  UpdateReverseElementAttributeRelations(aria_text_relations_node_map_, &source,
                                         target_nodes);

  // Mark all of the new text relation targets dirty.
  for (const Member<Element>& element : new_target_elements) {
    MarkNewRelationTargetDirty(element.Get());
  }
}

void AXRelationCache::UpdateReverseActiveDescendantRelations(Element& source) {
  UpdateReverseRelations(source, html_names::kAriaActivedescendantAttr,
                         aria_activedescendant_id_map_,
                         aria_activedescendant_node_map_);
}

void AXRelationCache::UpdateReverseOwnsRelations(Element& source) {
  UpdateReverseRelations(source, html_names::kAriaOwnsAttr, aria_owns_id_map_,
                         aria_owns_node_map_);
}

Vector<QualifiedName>& AXRelationCache::GetOtherRelationAttributes() {
  DEFINE_STATIC_LOCAL(
      Vector<QualifiedName>, attributes,
      ({html_names::kAriaControlsAttr, html_names::kAriaDetailsAttr,
        html_names::kAriaErrormessageAttr, html_names::kAriaFlowtoAttr,
        html_names::kAriaActionsAttr}));
  return attributes;
}

void AXRelationCache::UpdateReverseOtherRelations(Element& source) {
  Vector<QualifiedName>& attributes = GetOtherRelationAttributes();
  for (const QualifiedName& attribute : attributes) {
    UpdateReverseRelations(source, attribute, aria_other_relations_id_map_,
                           aria_other_relations_node_map_);
  }
}

void AXRelationCache::MarkNewRelationTargetDirty(Node* target) {
  // Mark root of label dirty so that we can change inclusion states as
  // necessary (label subtrees are included in the tree even if hidden).
  if (object_cache_->lifecycle().StateAllowsImmediateTreeUpdates()) {
    // WHen the relation cache is first initialized, we are already in
    // processing deferred events, and must manually invalidate the
    // cached values (is_used_for_label_or_description may have changed).
    if (AXObject* ax_target = Get(target)) {
      ax_target->InvalidateCachedValues();
    }
    // Must use clean layout method.
    object_cache_->MarkElementDirtyWithCleanLayout(target);
  } else {
    // This will automatically invalidate the cached values of the target.
    object_cache_->MarkElementDirty(target);
  }
}

// ContainsCycle() should:
// * Return true when a cycle is an authoring error, but not an error in Blink.
// * CHECK(false) when Blink should have caught this error earlier ... we should
// have never gotten into this state.
//
// For example, if a web page specifies that grandchild owns it's grandparent,
// what should happen is the ContainsCycle will start at the grandchild and go
// up, finding that it's grandparent is already in the ancestor chain, and
// return false, thus disallowing the relation. However, if on the way to the
// root, it discovers that any other two objects are repeated in the ancestor
// chain, this is unexpected, and results in the CHECK(false) condition.
static bool ContainsCycle(AXObject* owner, Node& child_node) {
  if (FlatTreeTraversal::IsDescendantOf(*owner->GetNode(), child_node)) {
    // A DOM descendant cannot own its ancestor.
    return true;
  }
  HashSet<AXID> visited;
  // Walk up the parents of the owner object, make sure that this child
  // doesn't appear there, as that would create a cycle.
  for (AXObject* ancestor = owner; ancestor;
       ancestor = ancestor->ParentObject()) {
    if (ancestor->GetNode() == &child_node) {
      return true;
    }
    CHECK(visited.insert(ancestor->AXObjectID()).is_new_entry)
        << "Cycle in unexpected place:\n"
        << "* Owner = " << owner << "* Child = " << child_node;
  }
  return false;
}

bool AXRelationCache::IsValidOwnsRelation(AXObject* owner,
                                          Node& child_node) const {
  if (!IsValidOwner(owner)) {
    return false;
  }

  if (!IsValidOwnedChild(child_node)) {
    return false;
  }

  // If this child is already aria-owned by a different owner, continue.
  // It's an author error if this happens and we don't worry about which of
  // the two owners wins ownership, as long as only one of them does.
  if (AXObject* child = object_cache_->Get(&child_node)) {
    if (IsAriaOwned(child) && GetAriaOwnedParent(child) != owner) {
      return false;
    }
  }

  // You can't own yourself or an ancestor!
  if (ContainsCycle(owner, child_node)) {
    return false;
  }

  return true;
}

// static
bool AXRelationCache::IsValidOwner(AXObject* owner) {
  if (!owner->GetNode()) {
    NOTREACHED() << "Cannot use aria-owns without a node on both ends";
  }

  // Can't have element children.
  // <br> is special in that it is allowed to have inline textbox children,
  // but no element children.
  if (!owner->CanHaveChildren() || IsA<HTMLBRElement>(owner->GetNode())) {
    return false;
  }

  // An aria-owns is disallowed on editable roots and atomic text fields, such
  // as <input>, <textarea> and content editables, otherwise the result would be
  // unworkable and totally unexpected on the browser side.
  if (owner->IsTextField())
    return false;

  // A frame/iframe/fencedframe can only parent a document.
  if (AXObject::IsFrame(owner->GetNode()))
    return false;

  // Images can only use <img usemap> to "own" <area> children.
  // This requires special parenting logic, and aria-owns is prevented here in
  // order to keep things from getting too complex.
  if (owner->RoleValue() == ax::mojom::blink::Role::kImage)
    return false;

  // Many types of nodes cannot be used as parent in normal situations.
  // These rules also apply to allowing aria-owns.
  if (!AXObject::CanComputeAsNaturalParent(owner->GetNode()))
    return false;

  // Problematic for cycles, and does not solve a known use case.
  // Easiest to omit the possibility.
  if (owner->IsAriaHidden())
    return false;

  return true;
}

// static
bool AXRelationCache::IsValidOwnedChild(Node& child_node) {
  Element* child_element = DynamicTo<Element>(child_node);
  if (!child_element) {
    return false;
  }

  // Require a layout object, in order to avoid strange situations where
  // a node tries to parent an AXObject that cannot exist because its node
  // cannot partake in layout tree building (e.g. unused fallback content of a
  // media element). This is the simplest way to avoid many types of abnormal
  // situations, and there's no known use case for pairing aria-owns with
  // invisible content.
  if (!child_node.GetLayoutObject()) {
    return false;
  }

  // An area can't be owned, only parented by <img usemap>.
  if (IsA<HTMLAreaElement>(child_node)) {
    return false;
  }

  // <select> options can only be children of AXMenuListPopup or AXListBox.
  if (IsA<HTMLOptionElement>(child_node) ||
      IsA<HTMLOptGroupElement>(child_node)) {
    return false;
  }

  // aria-hidden is problematic for cycles, and does not solve a known use case.
  // Easiest to omit the possibility.
  if (AXObject::IsAriaAttributeTrue(*child_element,
                                    html_names::kAriaHiddenAttr)) {
    return false;
  }

  return true;
}

void AXRelationCache::UnmapOwnedChildrenWithCleanLayout(
    const AXObject* owner,
    const Vector<AXID>& removed_child_ids,
    Vector<AXID>& unparented_child_ids) {
  DCHECK(owner);
  DCHECK(!owner->IsDetached());
  for (AXID removed_child_id : removed_child_ids) {
    // Find the AXObject for the child that this owner no longer owns.
    AXObject* removed_child = ObjectFromAXID(removed_child_id);

    // It's possible that this child has already been owned by some other
    // owner, in which case we don't need to do anything other than marking
    // the original parent dirty.
    if (removed_child && GetAriaOwnedParent(removed_child) != owner) {
      ChildrenChangedWithCleanLayout(removed_child->ParentObjectIfPresent());
      continue;
    }

    // Remove it from the child -> owner mapping so it's not owned by this
    // owner anymore.
    aria_owned_child_to_owner_mapping_.erase(removed_child_id);

    if (removed_child) {
      // Return the unparented children so their parent can be restored after
      // all aria-owns changes are complete.
      unparented_child_ids.push_back(removed_child_id);
    }
  }
}

void AXRelationCache::MapOwnedChildrenWithCleanLayout(
    const AXObject* owner,
    const Vector<AXID>& child_ids) {
  DCHECK(owner);
  DCHECK(!owner->IsDetached());
  for (AXID added_child_id : child_ids) {
    AXObject* added_child = ObjectFromAXID(added_child_id);
    DCHECK(added_child);
    DCHECK(!added_child->IsDetached());

    // Invalidating ensures that cached "included in tree" state is recomputed
    // on objects with changed ownership -- owned children must always be
    // included in the tree.
    added_child->InvalidateCachedValues();

    // Add this child to the mapping from child to owner.
    aria_owned_child_to_owner_mapping_.Set(added_child_id, owner->AXObjectID());

    // Now detach the object from its original parent and call childrenChanged
    // on the original parent so that it can recompute its list of children.
    AXObject* original_parent = added_child->ParentObjectIfPresent();
    if (original_parent != owner) {
      if (original_parent) {
        added_child->DetachFromParent();
      }
      added_child->SetParent(const_cast<AXObject*>(owner));
      if (original_parent) {
        ChildrenChangedWithCleanLayout(original_parent);
        // Reparenting detection requires the parent of the original parent to
        // be reserialized.
        // This change prevents several DumpAccessibilityEventsTest failures:
        // - AccessibilityEventsSubtreeReparentedViaAriaOwns/linux
        // - AccessibilityEventsSubtreeReparentedViaAriaOwns2/linux
        // TODO(crbug.com/1299031) Find out why this is necessary.
        object_cache_->MarkAXObjectDirtyWithCleanLayout(
            original_parent->ParentObject());
      }
    }
    // Now that the child is owned, it's "included in tree" state must be
    // recomputed because owned children are always included in the tree.
    added_child->UpdateCachedAttributeValuesIfNeeded(false);

    // If the added child had a change in an inherited state because of the new
    // owner, that state needs to propagate into the subtree. Remove its
    // descendants so they are re-added with the correct cached states.
    // The new states would also be propagted in FinalizeTree(), but this is
    // safer for certain situations such as the aria-owns + aria-hidden state,
    // where the aria-hidden state could be invalidated late in the cycle due
    // to focus changes.
    if (added_child->ChildrenNeedToUpdateCachedValues()) {
      object_cache_->RemoveSubtree(added_child->GetNode(),
                                   /*remove_root*/ false);
    }
  }
}

void AXRelationCache::UpdateAriaOwnsFromAttrAssociatedElementsWithCleanLayout(
    AXObject* owner,
    const HeapVector<Member<Element>>& attr_associated_elements,
    HeapVector<Member<AXObject>>& validated_owned_children_result,
    bool force) {
  CHECK(!object_cache_->IsFrozen());

  // attr-associated elements have already had their scope validated, but they
  // need to be further validated to determine if they introduce a cycle or are
  // already owned by another element.

  Vector<DOMNodeId> owned_dom_node_ids;
  for (const auto& element : attr_associated_elements) {
    CHECK(element);
    if (!IsValidOwnsRelation(const_cast<AXObject*>(owner), *element)) {
      continue;
    }
    AXObject* child = GetOrCreate(element, owner);
    if (!child) {
      return;
    }
    owned_dom_node_ids.push_back(element->GetDomNodeId());
    validated_owned_children_result.push_back(child);
  }

  // Track reverse relations for future tree updates.
  UpdateReverseElementAttributeRelations(aria_owns_node_map_, owner->GetNode(),
                                         owned_dom_node_ids);

  // Update the internal mappings of owned children.
  UpdateAriaOwnerToChildrenMappingWithCleanLayout(
      owner, validated_owned_children_result, force);
}

void AXRelationCache::ValidatedAriaOwnedChildren(
    const AXObject* owner,
    HeapVector<Member<AXObject>>& validated_owned_children_result) {
  if (!aria_owner_to_children_mapping_.Contains(owner->AXObjectID()))
    return;
  Vector<AXID> current_child_axids =
      aria_owner_to_children_mapping_.at(owner->AXObjectID());
  for (AXID child_id : current_child_axids) {
    AXObject* child = ObjectFromAXID(child_id);
    if (!child) {
      RemoveOwnedRelation(child_id);
    } else if (ValidatedAriaOwner(child) == owner) {
      validated_owned_children_result.push_back(child);
      DCHECK(IsAriaOwned(child))
          << "Owned child not in owned child map:" << "\n* Owner = " << owner
          << "\n* Child = " << child;
    }
  }
}

void AXRelationCache::UpdateAriaOwnsWithCleanLayout(AXObject* owner,
                                                    bool force) {
  CHECK(!object_cache_->IsFrozen());
  DCHECK(owner);
  Element* element = owner->GetElement();
  if (!element)
    return;

  DCHECK(!element->GetDocument().NeedsLayoutTreeUpdateForNode(*element));

  // A refresh can occur even if not a valid owner, because the old object
  // that |owner| is replacing may have previously been a valid owner. In this
  // case, the old owned child mappings will need to be removed.
  bool is_valid_owner = IsValidOwner(owner);
  if (!force && !is_valid_owner)
    return;

  HeapVector<Member<AXObject>> owned_children;

  // We first check if the element has an explicitly set aria-owns association.
  // Explicitly set elements are validated when they are read (that they are in
  // a valid scope etc). The content attribute can contain ids that are not
  // legally ownable.
  if (!is_valid_owner) {
    DCHECK(force) << "Should not reach here except when an AXObject was "
                     "invalidated and is being refreshed: "
                  << owner;
  } else if (element && element->HasExplicitlySetAttrAssociatedElements(
                            html_names::kAriaOwnsAttr)) {
    // TODO (crbug.com/41469336): Also check ElementInternals here.
    UpdateAriaOwnsFromAttrAssociatedElementsWithCleanLayout(
        owner,
        // TODO (crbug.com/353750122): Set resolve_reference_target to false.
        *element->GetAttrAssociatedElements(html_names::kAriaOwnsAttr,
                                            /*resolve_reference_target*/ true),
        owned_children, force);
  } else {
    // Figure out the ids that actually correspond to children that exist
    // and that we can legally own (not cyclical, not already owned, etc.) and
    // update the maps and |validated_owned_children_result| based on that.
    //
    // Figure out the children that are owned by this object and are in the
    // tree.
    TreeScope& scope = element->GetTreeScope();
    SpaceSplitString owned_id_vector(
        AXObject::AriaAttribute(*element, ht
"""


```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ax_node_object.cc`. They also want to understand its relation to web technologies (JavaScript, HTML, CSS), see examples of logical reasoning with inputs and outputs, common usage errors, and debugging steps to reach this code. Finally, they want the summary to cover the specific code provided, as it's part 7 of a 10-part series.

Here's a breakdown of the code's functionality and how to address each point:

1. **Inline Offset Mapping:** The first function `TextOffsetInFormattingContext` deals with mapping a text offset within a layout object's formatting context, specifically for inline nodes.
2. **Inline Text Boxes:**  The code then focuses on managing inline text boxes for accessibility. This includes:
    - Determining if inline text boxes should be loaded (`ShouldLoadInlineTextBoxes`).
    - Loading and creating these boxes (`LoadInlineTextBoxes`, `LoadInlineTextBoxesHelper`, `AddInlineTextBoxChildren`).
    - The logic for loading inline text boxes can differ across platforms (e.g., Android vs. others).
3. **Adding Children:** The rest of the code deals with adding different types of children to the accessibility tree:
    - Validation messages.
    - Image map areas.
    - Popup elements (like select dropdowns).
    - Pseudo-element children.
    - Regular DOM node children, considering reading flow order.
    - Children for menu lists and their popups.
    - Children owned via ARIA attributes.
    - The main `AddChildren` method orchestrates these additions, ensuring proper attachment and handling of dirty states.
    - Helper functions like `AddNodeChild`, `AddChild`, `InsertChild` handle the actual insertion and checks.
4. **Can Have Children:**  A function to determine if an object can have children in the accessibility tree.
5. **Document and Page Properties:**  A function to get the estimated loading progress of the document.
6. **DOM and Render Tree Access:** Functions to retrieve associated DOM elements (`ActionElement`, `AnchorElement`, `GetNode`), layout objects (`GetLayoutObject`), and the document itself (`GetDocument`).
7. **Native Actions:** Functions to perform native browser actions like blur, focus, increment, decrement, and setting the sequential focus navigation starting point.
8. **Selected Options:** A function stub related to selecting options.

**Relating to JavaScript, HTML, CSS:**

* **HTML:** The code directly interacts with HTML elements (e.g., `HTMLImageElement`, `HTMLSelectElement`, `HTMLMapElement`, pseudo-elements) and their attributes (e.g., `usemap`). ARIA attributes (like `aria-owns`) are also considered.
* **CSS:**  The code checks for `display: contents` and reading flow containers, indicating a dependency on CSS layout concepts. The management of inline text boxes is tied to how text is rendered based on CSS.
* **JavaScript:** While this C++ code doesn't directly execute JavaScript, it provides the accessibility representation of the DOM that JavaScript accessibility APIs (like the Accessibility Object Model) would interact with. User actions triggered by JavaScript might lead to changes reflected in this accessibility tree.

**Logical Reasoning Examples:**

* **Assumption:** An `HTMLImageElement` has a `usemap` attribute.
* **Input:** An `AXNodeObject` representing this image element.
* **Output:** The `AddImageMapChildren` function will find the associated `HTMLMapElement` and create `AXNodeObject`s for its `<area>` children.

* **Assumption:**  A `<div>` element has `display: contents` and contains other elements.
* **Input:** The `AXNodeObject` for the `<div>`.
* **Output:**  `AddNodeChildren` will traverse the DOM children, respecting the reading flow order if the closest layout parent is a reading flow container.

**Common Usage Errors:**

* **Detached Objects:**  The code has many checks for detached objects (`IsDetached()`). A common error would be trying to add or manipulate an `AXObject` that is no longer part of the accessibility tree. This could happen due to DOM mutations.
* **Incorrect Parent-Child Relationships:**  The checks in `AddChild` and related functions aim to prevent invalid parent-child relationships in the accessibility tree, particularly concerning ARIA ownership. Manually trying to construct or manipulate the accessibility tree without going through the proper Blink mechanisms could lead to such errors.

**User Operations and Debugging:**

1. **Page Load:**  The process often starts with a user loading a web page.
2. **Layout:** The Blink rendering engine performs layout, creating `LayoutObject`s.
3. **Accessibility Tree Construction:** The accessibility system in Blink builds the accessibility tree, using `AXNodeObject` and other classes.
4. **Specific Actions:**
    * **Text Selection:** Selecting text within an element might trigger the need to understand text offsets, leading to the `TextOffsetInFormattingContext` function.
    * **Focus Navigation (Tab Key):**  Tabbing through elements could trigger calls to `OnNativeFocusAction`.
    * **Using a Screen Reader:** A screen reader interacting with the page would heavily rely on the information provided by the accessibility tree, which is populated by these functions.
    * **Interacting with Form Controls:** Using a `<select>` element or a slider would involve the code related to adding popup children or handling increment/decrement actions.
5. **Debugging:** A developer might set breakpoints within these functions in the Chromium source code to understand how the accessibility tree is being built for a specific page or to diagnose issues reported by users of assistive technologies.

**Part 7 Summary:**

This section of `ax_node_object.cc` focuses on two core aspects of the accessibility tree: **accurate text offset mapping within inline content** and the **mechanisms for adding various types of children to an `AXNodeObject`**. It handles the specific logic for inline text boxes, image maps, popups, pseudo-elements, and regular DOM nodes, including consideration for ARIA ownership and reading flow order. The code ensures that the accessibility tree reflects the underlying DOM and rendering structure, providing essential information for assistive technologies.
这是 `blink/renderer/modules/accessibility/ax_node_object.cc` 文件的第 7 部分，主要功能是负责管理和构建可访问性树中 `AXNodeObject` 的子节点。它涉及到不同类型的子节点添加逻辑，包括内联文本框、图像地图、弹出窗口、伪元素以及常规的 DOM 节点，并且考虑了 ARIA 属性的影响。

**主要功能归纳：**

1. **内联文本框处理:**
   - `TextOffsetInFormattingContext`: 计算内联节点在格式化上下文中的文本偏移量。它首先尝试获取内联节点的偏移映射，如果存在则使用该映射计算，否则回退到父类的默认方法。
   - `ShouldLoadInlineTextBoxes`: 判断是否应该为当前对象加载内联文本框子节点。这取决于是否满足拥有内联文本框子节点的条件、可访问性模式是否启用了内联文本框，以及平台特定的配置（例如 Android）。
   - `LoadInlineTextBoxes`: 负责加载所有需要内联文本框的对象的内联文本框子节点。它使用一个工作队列来遍历可访问性树，并为每个满足条件的对象调用 `LoadInlineTextBoxesHelper`。
   - `LoadInlineTextBoxesHelper`:  实际执行加载内联文本框的辅助方法。它会根据当前生命周期状态决定是立即添加子节点还是延迟到稍后处理。
   - `AddInlineTextBoxChildren`:  为当前对象添加内联文本框子节点。它遍历 `LayoutText` 对象的内联文本框，为每个框创建或获取对应的 `AXObject`，并将其添加到子节点列表中。

2. **其他类型子节点添加:**
   - `AddValidationMessageChild`: 为 WebArea 类型的根节点添加验证消息子节点。
   - `AddImageMapChildren`: 为带有 `usemap` 属性的图像元素添加图像地图的 `<area>` 子节点。它会找到对应的 `HTMLMapElement` 并为其子节点创建 `AXObject`。
   - `AddPopupChildren`: 为具有弹出行为的元素（例如 `<select>` 和 `<input>`）添加弹出窗口的 `AXObject` 子节点。
   - `AddPseudoElementChildrenFromLayoutTree`:  为伪元素添加基于布局树的子节点。
   - `AddNodeChildren`: 添加常规的 DOM 节点子节点。它会遍历当前节点的 DOM 子节点，并为每个子节点创建或获取对应的 `AXObject`。它还考虑了 `display: contents` 和 reading-flow 的情况，以正确的顺序添加子节点。
   - `AddMenuListChildren`: 特殊处理 `role="combobox"` 的 `<select>` 元素，为其添加菜单列表的子节点。
   - `AddMenuListPopupChildren`:  特殊处理菜单列表弹出窗口，为其添加子节点。
   - `AddOwnedChildren`:  添加通过 `aria-owns` 属性关联的子节点。

3. **子节点管理通用方法:**
   - `AddChildrenImpl`:  实际执行添加子节点的逻辑，根据不同的条件调用不同的添加子节点的方法。
   - `AddChildren`:  入口函数，用于触发子节点的添加过程。它会检查是否需要更新子节点，并在添加子节点前后进行断言检查。
   - `AddNodeChild`:  添加一个由 DOM 节点支持的非拥有子节点。
   - `AddChild`:  添加一个子节点到子节点列表中。
   - `AddChildAndCheckIncluded`: 添加一个已知包含在可访问性树中的子节点。
   - `InsertChild`:  在指定索引位置插入一个子节点。

4. **判断是否可以拥有子节点:**
   - `CanHaveChildren`:  判断当前 `AXNodeObject` 是否可以拥有子节点。这取决于元素的类型、ARIA 角色以及一些内置角色的特定规则。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  代码直接与 HTML 元素交互，例如 `HTMLImageElement`, `HTMLSelectElement`, `HTMLMapElement` 等。它会检查 HTML 属性，例如 `usemap`，并根据 HTML 结构构建可访问性树。例如，`AddImageMapChildren` 功能就是根据 HTML 的 `<image>` 和 `<map>` 标签及其关联来创建可访问性树的结构。
* **CSS:**  代码中涉及到布局概念，例如格式化上下文 (`formatting_context`) 和内联文本框的布局。`ShouldLoadInlineTextBoxes` 的决策可能受到 CSS 影响的布局结果。`AddNodeChildren` 中处理 `display: contents` 和 reading-flow 也体现了对 CSS 布局的理解。
* **JavaScript:** 虽然这段 C++ 代码本身不执行 JavaScript，但它构建的可访问性树会被 JavaScript 可访问性 API (如 ARIA) 使用。JavaScript 可以修改 DOM 结构和元素的属性，这些修改最终会反映到由这段 C++ 代码构建的可访问性树中。例如，JavaScript 动态添加的 DOM 元素会被 `AddNodeChildren` 处理，并添加到可访问性树中。

**逻辑推理举例：**

假设输入是一个 `HTMLImageElement` 节点，该节点具有 `usemap="#imagemap"` 属性，并且页面中存在一个 ID 为 `imagemap` 的 `HTMLMapElement`，其中包含一些 `<area>` 子节点。

* **假设输入：** 一个代表带有 `usemap` 属性的 `HTMLImageElement` 的 `AXNodeObject`。
* **处理过程：** 当调用该 `AXNodeObject` 的 `AddChildren` 方法时，会进入 `AddImageMapChildren` 函数。
* **输出：** `AddImageMapChildren` 会找到对应的 `HTMLMapElement`，并为该 `HTMLMapElement` 的每个 `<area>` 子节点创建新的 `AXNodeObject`，并将这些新的 `AXNodeObject` 添加到原始 `HTMLImageElement` 的 `AXNodeObject` 的子节点列表中。

**用户或编程常见的使用错误举例：**

* **在不应该调用 `AddChildren` 的时候调用:**  开发者可能错误地在 `AXNodeObject` 的生命周期中多次调用 `AddChildren`，导致子节点被重复添加或状态不一致。代码中的 `CHECK(children_.empty())` 断言可以帮助检测这种错误。
* **手动修改子节点列表:** 开发者不应该直接操作 `AXNodeObject` 的 `children_` 列表，而应该通过 Blink 提供的接口来添加或删除子节点。直接修改可能导致内部状态不一致。
* **在对象被 detached 后尝试添加子节点:** 代码中有多处 `CHECK(!IsDetached())` 的检查。尝试向一个已经从可访问性树中移除的对象添加子节点会导致错误。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户加载包含特定 HTML 结构的网页：** 例如，一个包含带有 `usemap` 属性的 `<img>` 标签，或者一个复杂的表单元素。
2. **Blink 渲染引擎解析 HTML 和 CSS，构建 DOM 树和渲染树。**
3. **可访问性系统开始构建可访问性树。** 当需要为某个 `HTMLImageElement` 创建 `AXNodeObject` 并添加子节点时，会调用 `AXNodeObject::AddChildren()`。
4. **根据元素类型和属性，执行相应的子节点添加逻辑。** 对于带有 `usemap` 的 `<img>` 标签，会执行 `AddImageMapChildren()`。
5. **调试时，开发者可以在 `AddImageMapChildren()` 函数中设置断点，** 查看 `GetNode()` 获取到的 `HTMLImageElement`，检查其 `usemap` 属性，并跟踪如何找到对应的 `HTMLMapElement` 以及创建其子节点的 `AXObject` 的过程。

**总结 `ax_node_object.cc` 第 7 部分的功能：**

本部分代码的核心职责是构建 `AXNodeObject` 的子节点列表，确保可访问性树能够准确地反映页面的结构和内容。它针对不同类型的 HTML 元素和 ARIA 属性提供了特定的子节点添加逻辑，包括对内联文本的精细处理。理解这部分代码对于调试可访问性问题，例如屏幕阅读器无法正确识别页面元素或元素之间的关系至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共10部分，请归纳一下它的功能

"""
t OffsetMapping* inline_offset_mapping =
      InlineNode::GetOffsetMapping(formatting_context);
  if (!inline_offset_mapping)
    return AXObject::TextOffsetInFormattingContext(offset);

  const base::span<const OffsetMappingUnit> mapping_units =
      inline_offset_mapping->GetMappingUnitsForLayoutObject(*layout_obj);
  if (mapping_units.empty())
    return AXObject::TextOffsetInFormattingContext(offset);
  return static_cast<int>(mapping_units.front().TextContentStart()) + offset;
}

//
// Inline text boxes.
//

bool AXNodeObject::ShouldLoadInlineTextBoxes() const {
  CHECK(!IsDetached());

  if (!CanHaveInlineTextBoxChildren(this)) {
    return false;
  }

  if (!AXObjectCache().GetAXMode().has_mode(ui::AXMode::kInlineTextBoxes)) {
    return false;
  }

#if defined(REDUCE_AX_INLINE_TEXTBOXES)
  // On Android, once an object has loaded inline text boxes, it will keep
  // them refreshed.
  return always_load_inline_text_boxes_;
#else
  // Other platforms keep all inline text boxes in the tree and refreshed,
  // depending on the AXMode.
  return true;
#endif
}

void AXNodeObject::LoadInlineTextBoxes() {
#if DCHECK_IS_ON()
  DCHECK(GetDocument()->Lifecycle().GetState() >=
         DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle "
      << GetDocument()->Lifecycle().ToString();
#endif

  std::queue<AXID> work_queue;
  work_queue.push(AXObjectID());

  while (!work_queue.empty()) {
    AXObject* work_obj = AXObjectCache().ObjectFromAXID(work_queue.front());
    work_queue.pop();
    if (!work_obj || !work_obj->IsIncludedInTree()) {
      continue;
    }

    if (CanHaveInlineTextBoxChildren(work_obj)) {
      if (work_obj->CachedChildrenIncludingIgnored().empty()) {
        // We only need to add inline textbox children if they aren't present.
        // Although some platforms (e.g. Android), load inline text boxes
        // on subtrees that may later be stale, once they are stale, the old
        // inline text boxes are cleared because SetNeedsToUpdateChildren()
        // calls ClearChildren().
        work_obj->LoadInlineTextBoxesHelper();
      }
    } else {
      for (const auto& child : work_obj->ChildrenIncludingIgnored())
        work_queue.push(child->AXObjectID());
    }
  }

  // If the work was deferred via ChildrenChanged(), update accessibility
  // to force that work to be performed now.
  if (!AXObjectCache().lifecycle().StateAllowsImmediateTreeUpdates()) {
    AXObjectCache().UpdateAXForAllDocuments();
  }
}

void AXNodeObject::LoadInlineTextBoxesHelper() {
  // The inline textbox children start empty.
  DCHECK(CachedChildrenIncludingIgnored().empty());

#if defined(REDUCE_AX_INLINE_TEXTBOXES)
  // Keep inline text box children up-to-date for this object in the future.
  // This is only necessary on Android, which tries to skip inline text boxes
  // for most objects.
  always_load_inline_text_boxes_ = true;
#endif

  if (AXObjectCache().lifecycle().StateAllowsImmediateTreeUpdates()) {
    // Can only add new objects while processing deferred events.
    AddInlineTextBoxChildren();
    // Avoid adding these children twice.
    SetNeedsToUpdateChildren(false);
    // If inline text box children were added, mark the node dirty so that the
    // results are serialized.
    if (!CachedChildrenIncludingIgnored().empty()) {
      AXObjectCache().AddDirtyObjectToSerializationQueue(
          this, ax::mojom::blink::EventFrom::kNone,
          ax::mojom::blink::Action::kNone, {});
    }
  } else {
    // Wait until processing deferred events.
    AXObjectCache().ChildrenChanged(this);
  }
}

void AXNodeObject::AddInlineTextBoxChildren() {
  CHECK(GetDocument());
  CHECK(ShouldLoadInlineTextBoxes());
  CHECK(GetLayoutObject());
  GetLayoutObject()->CheckIsNotDestroyed();
  CHECK(GetLayoutObject()->IsText()) << GetLayoutObject() << " " << this;
  CHECK(!GetLayoutObject()->NeedsLayout());
  CHECK(AXObjectCache().GetAXMode().has_mode(ui::AXMode::kInlineTextBoxes));
  CHECK(!AXObjectCache().GetAXMode().HasExperimentalFlags(
      ui::AXMode::kExperimentalFormControls))
      << "Form controls mode should not have inline text boxes turned on.";
  CHECK(AXObjectCache().lifecycle().StateAllowsImmediateTreeUpdates())
      << AXObjectCache();

#if EXPENSIVE_DCHECKS_ARE_ON()
  AXBlockFlowIterator it;
  if (::features::IsAccessibilityBlockFlowIteratorEnabled()) {
    it = AXBlockFlowIterator(this);
  }
#endif

  auto* layout_text = To<LayoutText>(GetLayoutObject());
  for (auto* box = layout_text->FirstAbstractInlineTextBox(); box;
       box = box->NextInlineTextBox()) {
    AXObject* ax_box = AXObjectCache().GetOrCreate(box, this);
    if (!ax_box) {
      continue;
    }

    children_.push_back(ax_box);

#if EXPENSIVE_DCHECKS_ARE_ON()
    if (::features::IsAccessibilityBlockFlowIteratorEnabled()) {
      DCHECK(it.Next());
      WTF::String fragment_text = it.GetText();
      WTF::String abstract_inline_text = box->GetText();

      if (!layout_text->GetFirstLetterPart()) {
        // Explicitly skip the check if the layout text has a first letter
        // pseudo-element part. Currently, this is prefixed to the text, but
        // this is problematic since:
        //   * not accounted for in the glyph vector
        //   * can have a different style including flow direction
        //   * can be multiple characters due to punctuation
        DCHECK_EQ(fragment_text, abstract_inline_text)
            << "Mismatch in extracted text fragment: " << abstract_inline_text
            << " vs " << fragment_text;
      }
      AbstractInlineTextBox* next_on_line_box = box->NextOnLine();
      AbstractInlineTextBox* previous_on_line_box = box->PreviousOnLine();

      std::optional<AXBlockFlowIterator::MapKey> next_fragment_key =
          it.NextOnLine();
      std::optional<AXBlockFlowIterator::MapKey> previous_fragment_key =
          it.PreviousOnLine();

      if (next_on_line_box) {
        DCHECK(next_fragment_key) << "Failed to find next on line fragment";
        InlineCursor cursor = next_on_line_box->GetCursor();
        DCHECK_EQ(&cursor.Items(), next_fragment_key->first);
        wtf_size_t item_index = static_cast<wtf_size_t>(
            cursor.CurrentItem() - &cursor.Items().front());
        DCHECK_EQ(item_index, next_fragment_key->second)
            << "Mismatched fragment indices";
      } else {
        // TODO: Update once AXBlockFlowIterator::NextOnLine navigates into
        // box fragments. Currently, we fall back to the parent when
        // AbstractInlineTextBox::NextOnLine is null. This fallback should no
        // longer be necessary.
        DCHECK(!next_fragment_key)
            << "Expected not to find a next on line fragment";
      }

      if (previous_on_line_box) {
        DCHECK(previous_fragment_key)
            << "Failed to find previous on line fragment";
        InlineCursor cursor = previous_on_line_box->GetCursor();
        DCHECK_EQ(&cursor.Items(), previous_fragment_key->first);
        wtf_size_t item_index = static_cast<wtf_size_t>(
            cursor.CurrentItem() - &cursor.Items().front());
        DCHECK_EQ(item_index, previous_fragment_key->second)
            << "Mismatched fragment indices";
      } else {
        // TODO: Update once AXBlockFlowIterator::NextOnLine navigates into
        // box fragments. Currently, we fall back to the parent when
        // AbstractInlineTextBox::NextOnLine is null. This fallback should no
        // longer be necessary.
        DCHECK(!previous_fragment_key)
            << "Expected not to find a previous on line fragment";
      }
    }
#endif
  }
}

void AXNodeObject::AddValidationMessageChild() {
  DCHECK(IsWebArea()) << "Validation message must be child of root";
  // First child requirement enables easy checking to see if a children changed
  // event is needed in AXObjectCacheImpl::ValidationMessageObjectIfInvalid().
  DCHECK_EQ(children_.size(), 0U)
      << "Validation message must be the first child";
  AddChildAndCheckIncluded(AXObjectCache().ValidationMessageObjectIfInvalid());
}

void AXNodeObject::AddImageMapChildren() {
  HTMLMapElement* map = GetMapForImage(GetNode());
  if (!map)
    return;

  HTMLImageElement* curr_image_element = DynamicTo<HTMLImageElement>(GetNode());
  DCHECK(curr_image_element);
  DCHECK(curr_image_element->IsLink());
  DCHECK(
      !curr_image_element->FastGetAttribute(html_names::kUsemapAttr).empty());

  // Even though several images can point to the same map via usemap, only
  // use one reported via HTMLImageMapElement::ImageElement(), which is always
  // the first image in the DOM that matches the #usemap, even if there are
  // changes to the DOM. Only allow map children for the primary image.
  // This avoids two problems:
  // 1. Focusing the same area but in a different image scrolls the page to
  //    the first image that uses that map. Safari does the same thing, and
  //    Firefox does something similar (but seems to prefer the last image).
  // 2. When an object has multiple parents, serialization errors occur.
  // While allowed in the spec, using multiple images with the same map is not
  // handled well in browsers (problem #1), and serializer support for multiple
  // parents of the same area children is messy.

  // Get the primary image, which is the first image using this map.
  HTMLImageElement* primary_image_element = map->ImageElement();

  // Is this the primary image for this map?
  if (primary_image_element != curr_image_element) {
    return;
  }

  // Yes, this is the primary image.

  // Add the children to |this|.
  Node* child = LayoutTreeBuilderTraversal::FirstChild(*map);
  while (child) {
    AddChildAndCheckIncluded(AXObjectCache().GetOrCreate(child, this));
    child = LayoutTreeBuilderTraversal::NextSibling(*child);
  }
}

void AXNodeObject::AddPopupChildren() {
  auto* html_select_element = DynamicTo<HTMLSelectElement>(GetNode());
  if (html_select_element) {
    if (html_select_element->UsesMenuList()) {
      AddChildAndCheckIncluded(html_select_element->PopupRootAXObject());
    }
    return;
  }

  auto* html_input_element = DynamicTo<HTMLInputElement>(GetNode());
  if (html_input_element) {
    AddChildAndCheckIncluded(html_input_element->PopupRootAXObject());
  }
}

void AXNodeObject::AddPseudoElementChildrenFromLayoutTree() {
  // Children are added this way only for pseudo-element subtrees.
  // See AXObject::ShouldUseLayoutObjectTraversalForChildren().
  if (!IsVisible() || !GetLayoutObject()) {
    DCHECK(GetNode());
    DCHECK(GetNode()->IsPseudoElement());
    return;  // Can't add children for hidden or display-locked pseudo elements.
  }
  LayoutObject* child = GetLayoutObject()->SlowFirstChild();
  while (child) {
    // All added pseudo element descendants are included in the tree.
    if (AXObject* ax_child = AXObjectCache().GetOrCreate(child, this)) {
      DCHECK(AXObjectCacheImpl::IsRelevantPseudoElementDescendant(*child));
      AddChildAndCheckIncluded(ax_child);
    }
    child = child->NextSibling();
  }
}

void AXNodeObject::AddNodeChildren() {
  if (!node_)
    return;

  // Ignore DOM children of frame/iframe: they do not act as fallbacks and
  // are never part of layout.
  if (IsA<HTMLFrameElementBase>(GetNode()))
    return;

  // If node is a ReadingFlowContainer or if its closest layout parent is
  // ReadingFlowContainer (i.e. node has display: contents), then we should
  // follow reading-flow order. The same children will be added as in the simple
  // case using only LayoutTreeBuilderTraversal children, with no additions or
  // removals, but in the order defined in CSS.
  // Note that this is only used for the case where the element is a
  // reading-flow container, and not for the case where the element is a
  // reading-flow item.
  Element* element = GetElement();
  Element* closest_layout_parent =
      element && element->HasDisplayContentsStyle()
          ? LayoutTreeBuilderTraversal::LayoutParentElement(*element)
          : element;
  if (closest_layout_parent &&
      closest_layout_parent->IsReadingFlowContainer()) {
    HeapHashSet<Member<Node>> ax_children_added;
    // Add all reading flow items first, in the reading flow order.
    for (Element* reading_flow_item :
         closest_layout_parent->GetLayoutBox()->ReadingFlowElements()) {
      // reading_flow_item or its parent (for example, display: contents) might
      // be a child of element. Loop the parents and only add the node if its
      // LayoutTreeBuilderTraversal::Parent is this element.
      do {
        auto* parent = LayoutTreeBuilderTraversal::Parent(*reading_flow_item);
        if (parent == element) {
          if (ax_children_added.insert(reading_flow_item).is_new_entry) {
            AddNodeChild(reading_flow_item);
          }
          break;
        }
        reading_flow_item = DynamicTo<Element>(parent);
        // If parent is the reading flow container, then we have traversed all
        // potential parents and there is no reading flow item to add.
      } while (reading_flow_item && reading_flow_item != closest_layout_parent);
    }
    // Add all non-reading flow items at the end of the reading flow.
    for (Node* child = LayoutTreeBuilderTraversal::FirstChild(*node_); child;
         child = LayoutTreeBuilderTraversal::NextSibling(*child)) {
      if (ax_children_added.insert(child).is_new_entry) {
        AddNodeChild(child);
      }
    }
#if DCHECK_IS_ON()
    // At this point, the number of AXObject children added should equal the
    // number of LayoutTreeBuilderTraversal children.
    size_t num_layout_tree_children = 0;
    for (Node* child = LayoutTreeBuilderTraversal::FirstChild(*node_); child;
         child = LayoutTreeBuilderTraversal::NextSibling(*child)) {
      DCHECK(ax_children_added.Contains(child));
      ++num_layout_tree_children;
    }
    DCHECK_EQ(ax_children_added.size(), num_layout_tree_children);
#endif
  } else {
    for (Node* child = LayoutTreeBuilderTraversal::FirstChild(*node_); child;
         child = LayoutTreeBuilderTraversal::NextSibling(*child)) {
      AddNodeChild(child);
    }
  }
}

void AXNodeObject::AddMenuListChildren() {
  auto* select = To<HTMLSelectElement>(GetNode());

  if (select->IsAppearanceBasePicker()) {
    // In appearance: base-select (customizable select), the children of the
    // combobox is the displayed data list.
    AddNodeChild(select->PopoverForAppearanceBase());
    return;
  }

  AddNodeChildren();
}

void AXNodeObject::AddMenuListPopupChildren() {
  auto* select = To<HTMLSelectElement>(ParentObject()->GetNode());

  if (select->IsAppearanceBasePicker()) {
    // In appearance: base-select (customizable select), the children of the
    // popup are all of the natural dom children of the <select>.
    for (Node* child = NodeTraversal::FirstChild(*select); child;
         child = NodeTraversal::NextSibling(*child)) {
      if (child == select->SlottedButton()) {
        // The displayed button does not need to be part of the a11y tree. It
        // is not in the popup, and for accessibility purposes it is redundant
        // with the <select>.
        continue;
      }
      AddNodeChild(child);
    }
    return;
  }

  // In appearance: auto/none, the children of the popup are the flat tree
  // children of the slot associated with the popup.
  AddNodeChildren();
}

void AXNodeObject::AddOwnedChildren() {
  AXObjectVector owned_children;
  AXObjectCache().ValidatedAriaOwnedChildren(this, owned_children);

  DCHECK(owned_children.size() == 0 || AXRelationCache::IsValidOwner(this))
      << "This object is not allowed to use aria-owns, but it is.\n"
      << this;

  // Always include owned children.
  for (const auto& owned_child : owned_children) {
    DCHECK(owned_child->GetNode());
    DCHECK(AXRelationCache::IsValidOwnedChild(*owned_child->GetNode()))
        << "This object is not allowed to be owned, but it is.\n"
        << owned_child;
    AddChildAndCheckIncluded(owned_child, true);
  }
}

void AXNodeObject::AddChildrenImpl() {
#define CHECK_ATTACHED()                                  \
  if (IsDetached()) {                                     \
    NOTREACHED() << "Detached adding children: " << this; \
  }

  CHECK(NeedsToUpdateChildren());
  CHECK(CanHaveChildren());

  if (ShouldLoadInlineTextBoxes() && HasLayoutText(this)) {
    AddInlineTextBoxChildren();
    CHECK_ATTACHED();
    return;
  }

  if (IsA<HTMLImageElement>(GetNode())) {
    AddImageMapChildren();
    CHECK_ATTACHED();
    return;
  }

  // If validation message exists, always make it the first child of the root,
  // to enable easy checking of whether it's a known child of the root.
  if (IsWebArea())
    AddValidationMessageChild();
  CHECK_ATTACHED();

  if (RoleValue() == ax::mojom::blink::Role::kComboBoxSelect) {
    AddMenuListChildren();
  } else if (RoleValue() == ax::mojom::blink::Role::kMenuListPopup) {
    AddMenuListPopupChildren();
  } else if (HasValidHTMLTableStructureAndLayout()) {
    AddTableChildren();
  } else if (ShouldUseLayoutObjectTraversalForChildren()) {
    AddPseudoElementChildrenFromLayoutTree();
  } else {
    AddNodeChildren();
  }
  CHECK_ATTACHED();

  AddPopupChildren();
  CHECK_ATTACHED();

  AddOwnedChildren();
  CHECK_ATTACHED();
}

void AXNodeObject::AddChildren() {
#if DCHECK_IS_ON()
  DCHECK(!IsDetached());
  // If the need to add more children in addition to existing children arises,
  // childrenChanged should have been called, which leads to children_dirty_
  // being true, then UpdateChildrenIfNecessary() clears the children before
  // calling AddChildren().
  DCHECK(children_.empty()) << "\nParent still has " << children_.size()
                            << " children before adding:" << "\nParent is "
                            << this << "\nFirst child is " << children_[0];
#endif

#if defined(AX_FAIL_FAST_BUILD)
  SANITIZER_CHECK(!is_computing_text_from_descendants_)
      << "Should not attempt to simultaneously compute text from descendants "
         "and add children on: "
      << this;
  SANITIZER_CHECK(!is_adding_children_) << " Reentering method on " << this;
  base::AutoReset<bool> reentrancy_protector(&is_adding_children_, true);
#endif

  AddChildrenImpl();
  SetNeedsToUpdateChildren(false);

#if DCHECK_IS_ON()
  // All added children must be attached.
  for (const auto& child : children_) {
    DCHECK(!child->IsDetached()) << "A brand new child was detached.\n"
                                 << child << "\n ... of parent " << this;
  }
#endif
}

// Add non-owned children that are backed with a DOM node.
void AXNodeObject::AddNodeChild(Node* node) {
  if (!node)
    return;

  AXObject* ax_child = AXObjectCache().Get(node);
  CHECK(!ax_child || !ax_child->IsDetached());
  // Should not have another parent unless owned.
  if (AXObjectCache().IsAriaOwned(ax_child))
    return;  // Do not add owned children to their natural parent.

  AXObject* ax_cached_parent =
      ax_child ? ax_child->ParentObjectIfPresent() : nullptr;

  if (!ax_child) {
    ax_child =
        AXObjectCache().CreateAndInit(node, node->GetLayoutObject(), this);
    if (!ax_child) {
      return;
    }
    CHECK(!ax_child->IsDetached());
  }

  AddChild(ax_child);

  // If we are adding an included child, check to see that it didn't have a
  // different previous parent, because that indicates something strange is
  // happening -- we shouldn't be stealing AXObjects from other parents here.
  bool did_add_child_as_included =
      children_.size() && children_[children_.size() - 1] == ax_child;
  if (did_add_child_as_included && ax_cached_parent) {
    CHECK(ax_child->IsIncludedInTree());
    DUMP_WILL_BE_CHECK(ax_cached_parent->AXObjectID() == AXObjectID())
        << "Newly added child shouldn't have a different preexisting parent:"
        << "\nChild = " << ax_child << "\nNew parent = " << this
        << "\nPreexisting parent = " << ax_cached_parent;
  }
}

#if DCHECK_IS_ON()
void AXNodeObject::CheckValidChild(AXObject* child) {
  DCHECK(!child->IsDetached()) << "Cannot add a detached child.\n" << child;

  Node* child_node = child->GetNode();

  // <area> children should only be added via AddImageMapChildren(), as the
  // descendants of an <image usemap> -- never alone or as children of a <map>.
  if (IsA<HTMLAreaElement>(child_node)) {
    AXObject* ancestor = this;
    while (ancestor && !IsA<HTMLImageElement>(ancestor->GetNode()))
      ancestor = ancestor->ParentObject();
    DCHECK(ancestor && IsA<HTMLImageElement>(ancestor->GetNode()))
        << "Area elements can only be added by image parents: " << child
        << " had a parent of " << this;
  }

  DCHECK(!IsA<HTMLFrameElementBase>(GetNode()) ||
         IsA<Document>(child->GetNode()))
      << "Cannot have a non-document child of a frame or iframe."
      << "\nChild: " << child << "\nParent: " << child->ParentObject();
}
#endif

void AXNodeObject::AddChild(AXObject* child, bool is_from_aria_owns) {
  if (!child)
    return;

#if DCHECK_IS_ON()
  CheckValidChild(child);
#endif

  unsigned int index = children_.size();
  InsertChild(child, index, is_from_aria_owns);
}

void AXNodeObject::AddChildAndCheckIncluded(AXObject* child,
                                            bool is_from_aria_owns) {
  if (!child)
    return;
  DCHECK(child->CachedIsIncludedInTree());
  AddChild(child, is_from_aria_owns);
}

void AXNodeObject::InsertChild(AXObject* child,
                               unsigned index,
                               bool is_from_aria_owns) {
  if (!child)
    return;

  DCHECK(CanHaveChildren());
  DCHECK(!child->IsDetached()) << "Cannot add a detached child: " << child;
  // Enforce expected aria-owns status:
  // - Don't add a non-aria-owned child when called from AddOwnedChildren().
  // - Don't add an aria-owned child to its natural parent, because it will
  //   already be the child of the element with aria-owns.
  DCHECK_EQ(AXObjectCache().IsAriaOwned(child), is_from_aria_owns);

  // Set the parent:
  // - For a new object it will have already been set.
  // - For a reused, older object, it may need to be changed to a new parent.
  child->SetParent(this);

  if (ChildrenNeedToUpdateCachedValues()) {
    child->InvalidateCachedValues();
  }
  // Update cached values preemptively, but don't allow children changed to be
  // called on the parent if the ignored state changes, as we are already
  // recomputing children and don't want to recurse.
  child->UpdateCachedAttributeValuesIfNeeded(
      /*notify_parent_of_ignored_changes*/ false);

  if (!child->IsIncludedInTree()) {
    DCHECK(!is_from_aria_owns)
        << "Owned elements must be in tree: " << child
        << "\nRecompute included in tree: "
        << child->ComputeIsIgnoredButIncludedInTree();

    // Get the ignored child's children and add to children of ancestor
    // included in tree. This will recurse if necessary, skipping levels of
    // unignored descendants as it goes.
    const auto& children = child->ChildrenIncludingIgnored();
    wtf_size_t length = children.size();
    int new_index = index;
    for (wtf_size_t i = 0; i < length; ++i) {
      if (children[i]->IsDetached()) {
        // TODO(accessibility) Restore to CHECK().
#if defined(AX_FAIL_FAST_BUILD)
        SANITIZER_NOTREACHED()
            << "Cannot add a detached child: " << "\n* Child: " << children[i]
            << "\n* Parent: " << child << "\n* Grandparent: " << this;
#endif
        continue;
      }
      // If the child was owned, it will be added elsewhere as a direct
      // child of the object owning it.
      if (!AXObjectCache().IsAriaOwned(children[i]))
        children_.insert(new_index++, children[i]);
    }
  } else {
    children_.insert(index, child);
  }
}

bool AXNodeObject::CanHaveChildren() const {
  DCHECK(!IsDetached());

  // A child tree has been stitched onto this node, hiding its usual subtree.
  if (child_tree_id()) {
    return false;
  }

  // Notes:
  // * Native text fields expose any children they might have, complying
  // with browser-side expectations that editable controls have children
  // containing the actual text content.
  // * ARIA roles with childrenPresentational:true in the ARIA spec expose
  // their contents to the browser side, allowing platforms to decide whether
  // to make them a leaf, ensuring that focusable content cannot be hidden,
  // and improving stability in Blink.
  bool result = !GetElement() || AXObject::CanHaveChildren(*GetElement());
  switch (native_role_) {
    case ax::mojom::blink::Role::kCheckBox:
    case ax::mojom::blink::Role::kListBoxOption:
    case ax::mojom::blink::Role::kMenuItem:
    case ax::mojom::blink::Role::kMenuItemCheckBox:
    case ax::mojom::blink::Role::kMenuItemRadio:
    case ax::mojom::blink::Role::kProgressIndicator:
    case ax::mojom::blink::Role::kRadioButton:
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kSlider:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kSwitch:
    case ax::mojom::blink::Role::kTab:
      DCHECK(!result) << "Expected to disallow children for:" << "\n* Node: "
                      << GetNode() << "\n* Layout Object: " << GetLayoutObject()
                      << "\n* Native role: " << native_role_
                      << "\n* Aria role: " << RawAriaRole();
      break;
    case ax::mojom::blink::Role::kComboBoxSelect:
    case ax::mojom::blink::Role::kPopUpButton:
    case ax::mojom::blink::Role::kStaticText:
      // Note: these can have AXInlineTextBox children, but when adding them, we
      // also check AXObjectCache().InlineTextBoxAccessibilityEnabled().
      DCHECK(result) << "Expected to allow children for " << GetElement()
                     << " on role " << native_role_;
      break;
    default:
      break;
  }
  return result;
}

//
// Properties of the object's owning document or page.
//

double AXNodeObject::EstimatedLoadingProgress() const {
  if (!GetDocument())
    return 0;

  if (IsLoaded())
    return 1.0;

  if (LocalFrame* frame = GetDocument()->GetFrame())
    return frame->Loader().Progress().EstimatedProgress();
  return 0;
}

//
// DOM and Render tree access.
//

Element* AXNodeObject::ActionElement() const {
  const AXObject* current = this;

  if (blink::IsA<blink::Document>(current->GetNode()))
    return nullptr;  // Do not expose action element for document.

  // In general, we look an action element up only for AXObjects that have a
  // backing Element. We make an exception for text nodes and pseudo elements
  // because we also want these to expose a default action when any of their
  // ancestors is clickable. We have found Windows ATs relying on this behavior
  // (see https://crbug.com/1382034).
  DCHECK(current->GetElement() || current->IsTextObject() ||
         current->ShouldUseLayoutObjectTraversalForChildren());

  while (current) {
    // Handles clicks or is a textfield and is not a disabled form control.
    if (current->IsClickable()) {
      Element* click_element = current->GetElement();
      DCHECK(click_element) << "Only elements are clickable";
      // Only return if the click element is a DOM ancestor as well, because
      // the click handler won't propagate down via aria-owns.
      if (!GetNode() || click_element->contains(GetNode()))
        return click_element;
      return nullptr;
    }
    current = current->ParentObject();
  }

  return nullptr;
}

Element* AXNodeObject::AnchorElement() const {
  // Search up the DOM tree for an anchor. This can be anything that has the
  // linked state, such as an HTMLAnchorElement or role=link/doc-backlink.
  const AXObject* current = this;
  while (current) {
    if (current->IsLink()) {
      if (!current->GetElement()) {
        // TODO(crbug.com/1524124): Investigate and fix why this gets hit.
        DUMP_WILL_BE_NOTREACHED()
            << "An AXObject* that is a link should always have an element.\n"
            << this << "\n"
            << current;
      }
      return current->GetElement();
    }
    current = current->ParentObject();
  }

  return nullptr;
}

Document* AXNodeObject::GetDocument() const {
  if (GetNode()) {
    return &GetNode()->GetDocument();
  }
  if (GetLayoutObject()) {
    return &GetLayoutObject()->GetDocument();
  }
  return nullptr;
}

Node* AXNodeObject::GetNode() const {
  if (IsDetached()) {
    DCHECK(!node_);
    return nullptr;
  }

  DCHECK(!GetLayoutObject() || GetLayoutObject()->GetNode() == node_)
      << "If there is an associated layout object, its node should match the "
         "associated node of this accessibility object.\n"
      << this;
  return node_.Get();
}

LayoutObject* AXNodeObject::GetLayoutObject() const {
  return layout_object_;
}

bool AXNodeObject::OnNativeBlurAction() {
  Document* document = GetDocument();
  Node* node = GetNode();
  if (!document || !node) {
    return false;
  }

  // An AXObject's node will always be of type `Element`, `Document` or
  // `Text`. If the object we're currently on is associated with the currently
  // focused element or the document object, we want to clear the focus.
  // Otherwise, no modification is needed.
  Element* element = GetElement();
  if (element) {
    element->blur();
    return true;
  }

  if (IsA<Document>(GetNode())) {
    document->ClearFocusedElement();
    return true;
  }

  return false;
}

bool AXNodeObject::OnNativeFocusAction() {
  Document* document = GetDocument();
  Node* node = GetNode();
  if (!document || !node)
    return false;

  if (!CanSetFocusAttribute())
    return false;

  if (IsWebArea()) {
    // If another Frame has focused content (e.g. nested iframe), then we
    // need to clear focus for the other Document Frame.
    // Here we set the focused element via the FocusController so that the
    // other Frame loses focus, and the target Document Element gains focus.
    // This fixes a scenario with Narrator Item Navigation when the user
    // navigates from the outer UI to the document when the last focused
    // element was within a nested iframe before leaving the document frame.
    if (Page* page = document->GetPage()) {
      page->GetFocusController().SetFocusedElement(document->documentElement(),
                                                   document->GetFrame());
    } else {
      document->ClearFocusedElement();
    }
    return true;
  }

  Element* element = GetElement();
  if (!element) {
    document->ClearFocusedElement();
    return true;
  }

  // Forward the focus in an appearance:base-select <select> to the button,
  // which actually handles the focus.
  // TODO(accessibility) Try to remove after crrev.com/c/5800883 lands.
  if (auto* select = DynamicTo<HTMLSelectElement>(element)) {
    if (auto* button = select->SlottedButton()) {
      element = button;
    }
  }

#if BUILDFLAG(IS_ANDROID)
  // If this node is already the currently focused node, then calling
  // focus() won't do anything.  That is a problem when focus is removed
  // from the webpage to chrome, and then returns.  In these cases, we need
  // to do what keyboard and mouse focus do, which is reset focus first.
  if (document->FocusedElement() == element) {
    document->ClearFocusedElement();

    // Calling ClearFocusedElement could result in changes to the document,
    // like this AXObject becoming detached.
    if (IsDetached()) {
      return false;
    }
  }
#endif

  element->Focus(FocusParams(FocusTrigger::kUserGesture));

  // Calling NotifyUserActivation here allows the browser to activate features
  // that need user activation, such as showing an autofill suggestion.
  LocalFrame::NotifyUserActivation(
      document->GetFrame(),
      mojom::blink::UserActivationNotificationType::kInteraction);

  return true;
}

bool AXNodeObject::OnNativeIncrementAction() {
  LocalFrame* frame = GetDocument() ? GetDocument()->GetFrame() : nullptr;
  LocalFrame::NotifyUserActivation(
      frame, mojom::blink::UserActivationNotificationType::kInteraction);
  AlterSliderOrSpinButtonValue(true);
  return true;
}

bool AXNodeObject::OnNativeDecrementAction() {
  LocalFrame* frame = GetDocument() ? GetDocument()->GetFrame() : nullptr;
  LocalFrame::NotifyUserActivation(
      frame, mojom::blink::UserActivationNotificationType::kInteraction);
  AlterSliderOrSpinButtonValue(false);
  return true;
}

bool AXNodeObject::OnNativeSetSequentialFocusNavigationStartingPointAction() {
  if (!GetNode())
    return false;

  Document* document = GetDocument();
  document->ClearFocusedElement();
  document->SetSequentialFocusNavigationStartingPoint(GetNode());
  return true;
}

void AXNodeObject::SelectedOptions(AXObjectVector& options) const {
  if (auto* select = DynamicT
"""


```
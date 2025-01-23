Response:
My thinking process for analyzing the code and generating the response involved several steps:

1. **Understanding the Request:** I first parsed the request to identify the key requirements:
    * Analyze the provided C++ code snippet from `layout_object.cc`.
    * List the functions and their purposes.
    * Identify connections to JavaScript, HTML, and CSS, providing examples.
    * Provide examples of logical reasoning with hypothetical inputs/outputs.
    * Identify common usage errors.
    * Summarize the overall functionality of this part of the file.
    * Note that this is part 2 of a 6-part series.

2. **Code Examination (Iterative):** I then went through the code snippet function by function. For each function, I asked myself:
    * **What does this function do?** I focused on understanding the core logic and the purpose of the code within the function.
    * **What are the inputs and outputs?**  While the code doesn't explicitly take arguments in many cases, I considered what information the function relies on (e.g., member variables, parent/child relationships) and what it returns.
    * **How does this relate to the layout process?**  This was crucial for connecting the code to the larger context of a browser engine.
    * **Does it involve DOM elements, CSS properties, or JavaScript interactions?**  This is where the connections to web technologies emerge.

3. **Categorization and Grouping:** As I analyzed each function, I started to group them based on their related functionalities. I noticed patterns related to:
    * **Tree Traversal:** Functions like `NextInPreOrder`, `PreviousInPostOrder`, `CommonAncestor`, `IsBeforeInPreOrder`, `LastLeafChild`.
    * **Layer Management:** Functions like `AddLayers`, `RemoveLayers`, `MoveLayers`, `FindNextLayer`, `EnclosingLayer`, `PaintingLayer`.
    * **Containing Blocks and Formatting Contexts:** Functions like `EnclosingBox`, `FragmentItemsContainer`, `ContainingNGBox`, `ContainingFragmentationContextRoot`, `LocateFlowThreadContainingBlock`, `ContainerForAbsolutePosition`, `ContainerForFixedPosition`.
    * **Layout Invalidation and Dirty Flags:** Functions like `SetNeedsCollectInlines`, `SetChildNeedsCollectInlines`, `MarkContainerChainForLayout`, `MarkParentForSpannerOrOutOfFlowPositionedChange`, `SetIntrinsicLogicalWidthsDirty`, `ClearIntrinsicLogicalWidthsDirty`, `InvalidateSubtreeLayoutForFontUpdates`, `InvalidateContainerIntrinsicLogicalWidths`.
    * **Specific Element Types:** Functions like `IsRenderedLegendInternal`, `IsScrollMarker`, `IsListMarkerForSummary`, `IsInListMarker`.
    * **Clipping:** `HasClipRelatedProperty`.
    * **Relayout Boundaries:** `ObjectIsRelayoutBoundary`.

4. **Identifying Connections to Web Technologies:** With a good understanding of the functions, I focused on the connections to JavaScript, HTML, and CSS. This involved:
    * **HTML:** Recognizing functions that directly deal with specific HTML elements (e.g., `HTMLFieldSetElement` in `IsRenderedLegendInternal`, `HTMLSummaryElement` in `IsListMarkerForSummary`). Understanding how layout objects are created for HTML elements.
    * **CSS:** Identifying functions that check or are influenced by CSS properties (e.g., `HasClip` and `ShouldClipOverflowAlongEitherAxis` in `HasClipRelatedProperty`, `contain` property in `HasClipRelatedProperty` and `ObjectIsRelayoutBoundary`,  `position: absolute/fixed` in `ContainerForAbsolutePosition/FixedPosition`, various grid and flexbox properties in `ObjectIsRelayoutBoundary`).
    * **JavaScript:** Recognizing that while this C++ code doesn't directly *execute* JavaScript, it provides the underlying mechanisms for how layout changes (often triggered by JavaScript manipulation of the DOM or CSS) are handled. The concept of invalidating layout is key here.

5. **Logical Reasoning Examples:** I selected a few functions with clear logic (`NextInPreOrder`, `CommonAncestor`) and constructed simple hypothetical scenarios to illustrate their behavior with specific input and output. The goal was to demonstrate how these functions traverse the layout tree.

6. **Identifying Common Usage Errors:**  I considered what mistakes developers might make that would relate to this code. This often involves misunderstandings about how layout works, especially around:
    * **Incorrect assumptions about parent/child relationships:**  This ties into the tree traversal functions.
    * **Not understanding when layout invalidation is needed:**  This relates to the "dirty flag" functions.
    * **Misusing CSS properties that affect layout:**  This links to the CSS connections.

7. **Summarization:**  Finally, I synthesized the information gathered to provide a concise summary of the overall functionality of this code snippet. I focused on the key themes and the purpose of these functions within the Blink rendering engine. I also made sure to acknowledge that this was part 2 of a larger file.

8. **Review and Refinement:** I reread my entire response to ensure clarity, accuracy, and completeness. I checked that I addressed all aspects of the original request and that my examples were appropriate and easy to understand. I also considered the "part 2 of 6" context, understanding that this snippet likely focuses on a subset of the `LayoutObject`'s responsibilities.这是 `blink/renderer/core/layout/layout_object.cc` 文件的第二部分，主要包含 `LayoutObject` 类中用于**遍历布局树、判断属性、查找相关对象、管理渲染层以及处理布局失效**等功能的成员函数。

以下是该部分代码的功能归纳：

**1. 布局树遍历 (Tree Traversal):**

* **`NextInPreOrder()` 和 `NextInPreOrderAfterChildren()`:**  以先序遍历的方式查找下一个布局对象。`NextInPreOrder()` 首先尝试返回第一个子节点，如果没有子节点则调用 `NextInPreOrderAfterChildren()`。
* **`PreviousInPostOrder()` 和 `PreviousInPostOrderBeforeChildren()`:** 以后序遍历的方式查找前一个布局对象。
* **`NextInPreOrder(const LayoutObject* stay_within)` 和 `PreviousInPostOrder(const LayoutObject* stay_within)`:**  带有限制的先序和后序遍历，确保不会超出指定的布局对象范围。
* **`NextInPreOrderAfterChildren(const LayoutObject* stay_within)` 和 `PreviousInPostOrderBeforeChildren(const LayoutObject* stay_within)`:** 带有限制的先序和后序遍历辅助函数。
* **`PreviousInPreOrder()` 和 `PreviousInPreOrder(const LayoutObject* stay_within)`:** 以先序遍历方式查找前一个布局对象。
* **`Depth()`:** 计算当前布局对象在布局树中的深度。
* **`CommonAncestor()`:**  查找两个布局对象的最近公共祖先。
* **`IsBeforeInPreOrder()`:** 判断一个布局对象是否在另一个布局对象的前面（基于先序遍历）。
* **`LastLeafChild()`:** 查找最后一个叶子子节点。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:** 这些遍历方法用于访问和操作与 HTML 结构对应的布局对象树。例如，JavaScript 可以通过 DOM API 获取元素，Blink 引擎内部会使用这些遍历方法来找到对应的 `LayoutObject`。
* **CSS:** CSS 样式会影响布局树的结构。例如，`display: none` 会导致元素及其子元素的 `LayoutObject` 不会出现在渲染树中，遍历时会跳过。
* **JavaScript:** JavaScript 可以通过 DOM 操作（如 `appendChild`, `removeChild`）修改 HTML 结构，Blink 引擎会更新布局树，这些遍历方法会反映这些变化。

**逻辑推理举例：**

**假设输入：**
一个布局树如下：
```
A
├── B
│   ├── D
└── C
```
调用 `D->NextInPreOrder()`

**输出：** C

**推理过程：**
1. `D` 没有子节点，调用 `D->NextInPreOrderAfterChildren()`。
2. `D` 的下一个兄弟节点不存在。
3. 向上找到父节点 `B`，`B` 的下一个兄弟节点是 `C`。
4. 返回 `C`。

**2. 属性判断和相关对象查找:**

* **`HasClipRelatedProperty()`:**  检测是否存在可能影响裁剪继承链的 CSS 属性（如 `clip`, `overflow`, `contain: paint` 等）。
* **`IsRenderedLegendInternal()`:** 判断是否是 fieldset 元素的内部渲染的 legend。
* **`IsScrollMarker()` 和相关函数:** 判断是否是滚动条标记相关的伪元素。
* **`GetScrollMarkerGroup()`:** 获取滚动条标记组的布局对象。
* **`IsListMarkerForSummary()`:** 判断是否是 summary 元素的列表标记（用于展开/折叠指示）。
* **`IsInListMarker()`:** 判断是否在列表标记内部。
* **`EnclosingBox()`:** 查找最近的 `LayoutBox` 祖先。
* **`FragmentItemsContainer()`:** 查找片段项的容器（通常用于 inline 元素）。
* **`ContainingNGBox()`:** 查找最近的 LayoutNG 容器。
* **`ContainingFragmentationContextRoot()`:** 查找最近的分裂上下文根。
* **`LocateFlowThreadContainingBlock()`:**  在流线程中查找包含块。
* **`ContainerForAbsolutePosition()` 和 `ContainerForFixedPosition()`:** 查找绝对定位和固定定位的包含块。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:** `IsRenderedLegendInternal()` 直接与 `<fieldset>` 和 `<legend>` 元素相关。 `IsListMarkerForSummary()` 与 `<summary>` 元素相关。
* **CSS:** `HasClipRelatedProperty()` 检查 CSS 裁剪相关的属性。 `IsScrollMarker()` 涉及到浏览器默认或自定义滚动条样式。
* **JavaScript:** JavaScript 可以获取元素的样式信息，这些函数内部会根据元素的样式（通过 `Style()` 获取）进行判断。

**逻辑推理举例：**

**假设输入：**
一个 `<div>` 元素设置了 `overflow: auto;` 样式。
调用该 `<div>` 元素的 `LayoutObject` 的 `HasClipRelatedProperty()`。

**输出：** `true`

**推理过程：**
1. 函数内部检查 `ShouldClipOverflowAlongEitherAxis()`，该函数会根据元素的 `overflow` 属性判断是否需要裁剪溢出内容。
2. 由于 `overflow: auto` 会在内容溢出时显示滚动条，需要裁剪溢出内容。
3. 因此 `ShouldClipOverflowAlongEitherAxis()` 返回 `true`。
4. `HasClipRelatedProperty()` 返回 `true`。

**3. 渲染层管理 (Layer Management):**

* **`AddLayers()`:** 将当前布局对象及其子对象的渲染层添加到指定的父渲染层。
* **`RemoveLayers()`:** 从父渲染层移除当前布局对象及其子对象的渲染层。
* **`MoveLayers()`:** 将当前布局对象及其子对象的渲染层从一个父渲染层移动到另一个父渲染层。
* **`FindNextLayer()`:**  查找指定父渲染层下的下一个渲染层。
* **`EnclosingLayer()`:** 查找最近的拥有渲染层的祖先的渲染层。
* **`PaintingLayer()`:**  查找用于绘制当前布局对象的渲染层。

**与 JavaScript, HTML, CSS 的关系举例：**

* **CSS:** CSS 属性如 `z-index`, `opacity`, `transform` 等会触发创建新的渲染层。这些函数负责在布局阶段管理这些渲染层的添加、移除和移动。
* **JavaScript:** JavaScript 可以修改 CSS 属性，间接影响渲染层的创建和管理。例如，通过 JavaScript 修改元素的 `z-index` 可能会导致新的渲染层被创建。

**4. 布局失效处理 (Layout Invalidation):**

* **`SetNeedsCollectInlines()` 和 `SetChildNeedsCollectInlines()`:**  标记需要重新收集 inline 元素。
* **`MarkContainerChainForLayout()`:** 标记容器链需要重新布局。
* **`MarkParentForSpannerOrOutOfFlowPositionedChange()`:** 标记父元素需要处理 column spanner 或 out-of-flow 定位元素的变化。
* **`SetIntrinsicLogicalWidthsDirty()` 和 `ClearIntrinsicLogicalWidthsDirty()`:** 标记和清除 intrinsic 逻辑宽度失效。
* **`InvalidateSubtreeLayoutForFontUpdates()`:** 因字体更新使子树布局失效。
* **`InvalidateContainerIntrinsicLogicalWidths()`:** 使容器的 intrinsic 逻辑宽度失效。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:**  DOM 结构的修改（添加、删除节点）会导致布局失效。
* **CSS:** 任何影响元素大小、位置、可见性的 CSS 属性变化都会导致布局失效。
* **JavaScript:** JavaScript 通过 DOM 操作和修改样式触发布局失效。例如，使用 JavaScript 改变元素的 `width` 或 `display` 属性会导致 Blink 引擎标记相关 `LayoutObject` 需要重新布局。

**常见的使用错误（开发者角度）：**

虽然开发者通常不直接操作 `LayoutObject`，但理解这些概念有助于避免性能问题。

* **过度修改样式导致频繁的布局（Layout Thrashing）：**  JavaScript 代码中连续修改多个元素的样式，如果没有合理的批处理，会导致浏览器频繁地进行布局计算，影响性能。
* **不理解 CSS 属性对布局的影响：** 错误地使用某些 CSS 属性可能会导致意想不到的布局行为或性能问题。例如，过度使用 `position: absolute` 可能会使布局计算变得复杂。
* **在动画中使用会导致布局的属性：**  动画应该尽量使用不会触发布局的属性，例如 `transform` 和 `opacity`。

**总结:**

这部分 `LayoutObject.cc` 的代码主要负责：

* **提供布局树的遍历机制，** 允许 Blink 引擎在布局过程中访问和操作布局对象。
* **提供判断布局对象属性和查找相关对象的能力，** 例如判断是否需要裁剪、查找包含块等，这些判断是布局计算的基础。
* **管理渲染层的生命周期，** 包括添加、移除和移动渲染层，确保渲染的正确性。
* **处理布局失效，**  当 HTML 结构或 CSS 样式发生变化时，标记需要重新布局的布局对象，以保证渲染结果与最新的 DOM 和样式一致。

总的来说，这部分代码是 Blink 渲染引擎核心布局功能的重要组成部分，它为布局计算、渲染层管理和布局更新提供了必要的底层支持。理解这些功能有助于理解浏览器是如何将 HTML、CSS 和 JavaScript 代码转化为用户可见的页面的。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
utObject::NextInPreOrder() const {
  NOT_DESTROYED();
  if (LayoutObject* o = SlowFirstChild())
    return o;

  return NextInPreOrderAfterChildren();
}

bool LayoutObject::HasClipRelatedProperty() const {
  NOT_DESTROYED();
  // This function detects a bunch of properties that can potentially affect
  // clip inheritance chain. However such generalization is practically useless
  // because these properties change clip inheritance in different way that
  // needs to be handled explicitly.
  // CSS clip applies clip to the current element and all descendants.
  // CSS overflow clip applies only to containing-block descendants.
  // CSS contain:paint applies to all descendants by making itself a containing
  // block for all descendants.
  // CSS clip-path/mask/filter induces a stacking context and applies inherited
  // clip to that stacking context, while resetting clip for descendants. This
  // special behavior is already handled elsewhere.
  if (HasClip() || ShouldClipOverflowAlongEitherAxis())
    return true;
  // Paint containment establishes isolation which creates clip isolation nodes.
  // Style & Layout containment also establish isolation (see
  // |NeedsIsolationNodes| in PaintPropertyTreeBuilder).
  if (ShouldApplyPaintContainment() ||
      (ShouldApplyStyleContainment() && ShouldApplyLayoutContainment())) {
    return true;
  }
  if (IsBox() && To<LayoutBox>(this)->HasControlClip())
    return true;
  return false;
}

bool LayoutObject::IsRenderedLegendInternal() const {
  NOT_DESTROYED();
  DCHECK(IsBox());
  DCHECK(IsRenderedLegendCandidate());

  const auto* parent = Parent();
  // We may not be inserted into the tree yet.
  if (!parent)
    return false;

  const auto* parent_layout_block = DynamicTo<LayoutBlock>(parent);
  return parent_layout_block && IsA<HTMLFieldSetElement>(parent->GetNode()) &&
         LayoutFieldset::FindInFlowLegend(*parent_layout_block) == this;
}

bool LayoutObject::IsScrollMarker() const {
  NOT_DESTROYED();
  return GetNode() && GetNode()->IsScrollMarkerPseudoElement();
}

bool LayoutObject::IsScrollMarkerGroup() const {
  NOT_DESTROYED();
  return GetNode() && GetNode()->IsScrollMarkerGroupPseudoElement();
}

bool LayoutObject::IsScrollMarkerGroupBefore() const {
  NOT_DESTROYED();
  return GetNode() && GetNode()->IsScrollMarkerGroupBeforePseudoElement();
}

LayoutObject* LayoutObject::GetScrollMarkerGroup() const {
  NOT_DESTROYED();
  if (Style()->ScrollMarkerGroup() == EScrollMarkerGroup::kNone) {
    return nullptr;
  }
  if (IsFieldset()) {
    const LayoutBlock* fieldset_content =
        To<LayoutFieldset>(this)->FindAnonymousFieldsetContentBox();
    if (!fieldset_content || !fieldset_content->IsScrollContainer()) {
      return nullptr;
    }
  } else if (!IsScrollContainer()) {
    return nullptr;
  }
  if (auto* element = DynamicTo<Element>(GetNode())) {
    if (PseudoElement* pseudo =
            element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
      return pseudo->GetLayoutObject();
    }
    if (PseudoElement* pseudo =
            element->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
      return pseudo->GetLayoutObject();
    }
  }
  return nullptr;
}

bool LayoutObject::IsListMarkerForSummary() const {
  if (!IsListMarker()) {
    return false;
  }
  if (const auto* summary =
          DynamicTo<HTMLSummaryElement>(Parent()->GetNode())) {
    if (!summary->IsMainSummary())
      return false;
    if (ListMarker::GetListStyleCategory(GetDocument(), StyleRef()) !=
        ListMarker::ListStyleCategory::kSymbol)
      return false;
    const AtomicString& name =
        StyleRef().ListStyleType()->GetCounterStyleName();
    return name == keywords::kDisclosureOpen ||
           name == keywords::kDisclosureClosed;
  }
  return false;
}

bool LayoutObject::IsInListMarker() const {
  // List markers are either leaf nodes (legacy LayoutListMarker), or have
  // exactly one leaf child. So there's no need to traverse ancestors.
  return Parent() && Parent()->IsListMarker();
}

LayoutObject* LayoutObject::NextInPreOrderAfterChildren() const {
  NOT_DESTROYED();
  LayoutObject* o = NextSibling();
  if (!o) {
    o = Parent();
    while (o && !o->NextSibling())
      o = o->Parent();
    if (o)
      o = o->NextSibling();
  }

  return o;
}

LayoutObject* LayoutObject::NextInPreOrder(
    const LayoutObject* stay_within) const {
  NOT_DESTROYED();
  if (LayoutObject* o = SlowFirstChild())
    return o;

  return NextInPreOrderAfterChildren(stay_within);
}

LayoutObject* LayoutObject::PreviousInPostOrder(
    const LayoutObject* stay_within) const {
  NOT_DESTROYED();
  if (LayoutObject* o = SlowLastChild())
    return o;

  return PreviousInPostOrderBeforeChildren(stay_within);
}

LayoutObject* LayoutObject::NextInPreOrderAfterChildren(
    const LayoutObject* stay_within) const {
  NOT_DESTROYED();
  if (this == stay_within)
    return nullptr;

  const LayoutObject* current = this;
  LayoutObject* next = current->NextSibling();
  for (; !next; next = current->NextSibling()) {
    current = current->Parent();
    if (!current || current == stay_within)
      return nullptr;
  }
  return next;
}

LayoutObject* LayoutObject::PreviousInPostOrderBeforeChildren(
    const LayoutObject* stay_within) const {
  NOT_DESTROYED();
  if (this == stay_within)
    return nullptr;

  const LayoutObject* current = this;
  LayoutObject* previous = current->PreviousSibling();
  for (; !previous; previous = current->PreviousSibling()) {
    current = current->Parent();
    if (!current || current == stay_within)
      return nullptr;
  }
  return previous;
}

LayoutObject* LayoutObject::PreviousInPreOrder() const {
  NOT_DESTROYED();
  if (LayoutObject* o = PreviousSibling()) {
    while (LayoutObject* last_child = o->SlowLastChild())
      o = last_child;
    return o;
  }

  return Parent();
}

LayoutObject* LayoutObject::PreviousInPreOrder(
    const LayoutObject* stay_within) const {
  NOT_DESTROYED();
  if (this == stay_within)
    return nullptr;

  return PreviousInPreOrder();
}

wtf_size_t LayoutObject::Depth() const {
  wtf_size_t depth = 0;
  for (const LayoutObject* object = this; object; object = object->Parent())
    ++depth;
  return depth;
}

LayoutObject* LayoutObject::CommonAncestor(const LayoutObject& other,
                                           CommonAncestorData* data) const {
  if (this == &other)
    return const_cast<LayoutObject*>(this);

  const wtf_size_t depth = Depth();
  const wtf_size_t other_depth = other.Depth();
  const LayoutObject* iterator = this;
  const LayoutObject* other_iterator = &other;
  const LayoutObject* last = nullptr;
  const LayoutObject* other_last = nullptr;
  if (depth > other_depth) {
    for (wtf_size_t i = depth - other_depth; i; --i) {
      last = iterator;
      iterator = iterator->Parent();
    }
  } else if (other_depth > depth) {
    for (wtf_size_t i = other_depth - depth; i; --i) {
      other_last = other_iterator;
      other_iterator = other_iterator->Parent();
    }
  }
  while (iterator) {
    DCHECK(other_iterator);
    if (iterator == other_iterator) {
      if (data) {
        data->last = const_cast<LayoutObject*>(last);
        data->other_last = const_cast<LayoutObject*>(other_last);
      }
      return const_cast<LayoutObject*>(iterator);
    }
    last = iterator;
    iterator = iterator->Parent();
    other_last = other_iterator;
    other_iterator = other_iterator->Parent();
  }
  DCHECK(!other_iterator);
  return nullptr;
}

bool LayoutObject::IsBeforeInPreOrder(const LayoutObject& other) const {
  DCHECK_NE(this, &other);
  CommonAncestorData data;
  const LayoutObject* common_ancestor = CommonAncestor(other, &data);
  DCHECK(common_ancestor);
  DCHECK(data.last || data.other_last);
  if (!data.last)
    return true;  // |this| is the ancestor of |other|.
  if (!data.other_last)
    return false;  // |other| is the ancestor of |this|.
  for (const LayoutObject* child = common_ancestor->SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (child == data.last)
      return true;
    if (child == data.other_last)
      return false;
  }
  NOTREACHED();
}

LayoutObject* LayoutObject::LastLeafChild() const {
  NOT_DESTROYED();
  LayoutObject* r = SlowLastChild();
  while (r) {
    LayoutObject* n = nullptr;
    n = r->SlowLastChild();
    if (!n)
      break;
    r = n;
  }
  return r;
}

static void AddLayers(LayoutObject* obj,
                      PaintLayer* parent_layer,
                      LayoutObject*& new_object,
                      PaintLayer*& before_child) {
  if (obj->HasLayer()) {
    if (!before_child && new_object) {
      // We need to figure out the layer that follows newObject. We only do
      // this the first time we find a child layer, and then we update the
      // pointer values for newObject and beforeChild used by everyone else.
      before_child =
          new_object->Parent()->FindNextLayer(parent_layer, new_object);
      new_object = nullptr;
    }
    parent_layer->AddChild(To<LayoutBoxModelObject>(obj)->Layer(),
                           before_child);
    return;
  }

  for (LayoutObject* curr = obj->SlowFirstChild(); curr;
       curr = curr->NextSibling())
    AddLayers(curr, parent_layer, new_object, before_child);
}

void LayoutObject::AddLayers(PaintLayer* parent_layer) {
  NOT_DESTROYED();
  if (!parent_layer)
    return;

  LayoutObject* object = this;
  PaintLayer* before_child = nullptr;
  blink::AddLayers(this, parent_layer, object, before_child);
}

void LayoutObject::RemoveLayers(PaintLayer* parent_layer) {
  NOT_DESTROYED();
  if (!parent_layer)
    return;

  if (HasLayer()) {
    parent_layer->RemoveChild(To<LayoutBoxModelObject>(this)->Layer());
    return;
  }

  for (LayoutObject* curr = SlowFirstChild(); curr; curr = curr->NextSibling())
    curr->RemoveLayers(parent_layer);
}

void LayoutObject::MoveLayers(PaintLayer* old_parent, PaintLayer* new_parent) {
  NOT_DESTROYED();
  if (!new_parent)
    return;

  if (HasLayer()) {
    PaintLayer* layer = To<LayoutBoxModelObject>(this)->Layer();
    DCHECK_EQ(old_parent, layer->Parent());
    if (old_parent)
      old_parent->RemoveChild(layer);
    new_parent->AddChild(layer);
    return;
  }

  for (LayoutObject* curr = SlowFirstChild(); curr; curr = curr->NextSibling())
    curr->MoveLayers(old_parent, new_parent);
}

PaintLayer* LayoutObject::FindNextLayer(PaintLayer* parent_layer,
                                        LayoutObject* start_point,
                                        bool check_parent) {
  NOT_DESTROYED();
  // Error check the parent layer passed in. If it's null, we can't find
  // anything.
  if (!parent_layer)
    return nullptr;

  // Step 1: If our layer is a child of the desired parent, then return our
  // layer.
  PaintLayer* our_layer =
      HasLayer() ? To<LayoutBoxModelObject>(this)->Layer() : nullptr;
  if (our_layer && our_layer->Parent() == parent_layer)
    return our_layer;

  // Step 2: If we don't have a layer, or our layer is the desired parent, then
  // descend into our siblings trying to find the next layer whose parent is the
  // desired parent.
  if (!our_layer || our_layer == parent_layer) {
    for (LayoutObject* curr = start_point ? start_point->NextSibling()
                                          : SlowFirstChild();
         curr; curr = curr->NextSibling()) {
      PaintLayer* next_layer =
          curr->FindNextLayer(parent_layer, nullptr, false);
      if (next_layer)
        return next_layer;
    }
  }

  // Step 3: If our layer is the desired parent layer, then we're finished. We
  // didn't find anything.
  if (parent_layer == our_layer)
    return nullptr;

  // Step 4: If |checkParent| is set, climb up to our parent and check its
  // siblings that follow us to see if we can locate a layer.
  if (check_parent && Parent())
    return Parent()->FindNextLayer(parent_layer, this, true);

  return nullptr;
}

PaintLayer* LayoutObject::EnclosingLayer() const {
  NOT_DESTROYED();
  for (const LayoutObject* current = this; current;
       current = current->Parent()) {
    if (current->HasLayer())
      return To<LayoutBoxModelObject>(current)->Layer();
  }
  // TODO(crbug.com/365897): we should get rid of detached layout subtrees, at
  // which point this code should not be reached.
  return nullptr;
}

PaintLayer* LayoutObject::PaintingLayer(int max_depth) const {
  NOT_DESTROYED();
  auto FindContainer = [](const LayoutObject& object) -> const LayoutObject* {
    // Column spanners paint through their multicolumn containers which can
    // be accessed through the associated out-of-flow placeholder's parent.
    if (object.IsColumnSpanAll())
      return object.SpannerPlaceholder();
    // Use ContainingBlock() instead of Parent() for floating objects to omit
    // any self-painting layers of inline objects that don't paint the floating
    // object. This is only needed for inline-level floats not managed by
    // LayoutNG. LayoutNG floats are painted by the correct painting layer.
    if (object.IsFloating() && !object.IsInLayoutNGInlineFormattingContext())
      return object.ContainingBlock();
    // Physical fragments and fragment items for ruby-text boxes are not
    // managed by inline parents, and stored in a separated line of the IFC.
    if (object.IsInlineRubyText()) {
      return object.ContainingBlock();
    }
    if (IsA<LayoutView>(object))
      return object.GetFrame()->OwnerLayoutObject();
    return object.Parent();
  };
  int depth = 0;
  const LayoutObject* outermost = nullptr;
  for (const LayoutObject* current = this; current;
       outermost = current, current = FindContainer(*current)) {
    if (max_depth != -1 && ++depth > max_depth) {
      return nullptr;
    }
    if (current->HasLayer() &&
        To<LayoutBoxModelObject>(current)->Layer()->IsSelfPaintingLayer())
      return To<LayoutBoxModelObject>(current)->Layer();
  }

  if (const auto* box = DynamicTo<LayoutBox>(outermost)) {
    if (box->PhysicalFragmentCount()) {
      // Only actual page content is attached to the layout tree. Page boxes and
      // margin boxes are not, since they are not part of the DOM. Return the
      // LayoutView paint layer for such objects.
      const PhysicalBoxFragment& fragment = *box->GetPhysicalFragment(0);
      if (fragment.GetBoxType() == PhysicalFragment::kPageContainer ||
          fragment.GetBoxType() == PhysicalFragment::kPageBorderBox ||
          fragment.GetBoxType() == PhysicalFragment::kPageMargin) {
        return box->View()->Layer();
      }
    }
  }

  // TODO(crbug.com/365897): we should get rid of detached layout subtrees, at
  // which point this code should not be reached.
  return nullptr;
}

LayoutBox* LayoutObject::EnclosingBox() const {
  NOT_DESTROYED();
  LayoutObject* curr = const_cast<LayoutObject*>(this);
  while (curr) {
    if (curr->IsBox())
      return To<LayoutBox>(curr);
    curr = curr->Parent();
  }

  DUMP_WILL_BE_NOTREACHED();
  return nullptr;
}

LayoutBlockFlow* LayoutObject::FragmentItemsContainer() const {
  NOT_DESTROYED();
  DCHECK(!IsOutOfFlowPositioned());
  auto* block_flow = DynamicTo<LayoutBlockFlow>(ContainingNGBox());
  if (!block_flow || !block_flow->IsLayoutNGObject())
    return nullptr;
#if EXPENSIVE_DCHECKS_ARE_ON()
  // Make sure that we don't skip blocks in the ancestry chain (which might
  // happen if there are out-of-flow positioned objects, for instance). In this
  // method we don't want to escape the enclosing inline formatting context.
  for (const LayoutObject* walker = Parent(); walker != block_flow;
       walker = walker->Parent())
    DCHECK(!walker->IsLayoutBlock());
#endif
  return block_flow;
}

LayoutBox* LayoutObject::ContainingNGBox() const {
  NOT_DESTROYED();
  if (Parent() && Parent()->IsMedia()) {
    return To<LayoutBox>(Parent());
  }
  LayoutBlock* containing_block = ContainingBlock();
  if (!containing_block)
    return nullptr;
  // Flow threads should be invisible to LayoutNG, so skip to the multicol
  // container.
  if (containing_block->IsLayoutFlowThread()) [[unlikely]] {
    containing_block = To<LayoutBlockFlow>(containing_block->Parent());
  }
  if (!containing_block->IsLayoutNGObject())
    return nullptr;
  return containing_block;
}

LayoutBlock* LayoutObject::ContainingFragmentationContextRoot() const {
  NOT_DESTROYED();
  if (!MightBeInsideFragmentationContext())
    return nullptr;
  bool found_column_spanner = IsColumnSpanAll();
  for (LayoutBlock* ancestor = ContainingBlock(); ancestor;
       ancestor = ancestor->ContainingBlock()) {
    if (ancestor->IsFragmentationContextRoot()) {
      // Column spanners do not participate in the fragmentation context
      // of their nearest fragmentation context, but rather the next above,
      // if there is one.
      if (found_column_spanner)
        return ancestor->ContainingFragmentationContextRoot();
      return ancestor;
    }
    if (ancestor->IsColumnSpanAll())
      found_column_spanner = true;
  }
  return nullptr;
}

bool LayoutObject::IsFirstInlineFragmentSafe() const {
  NOT_DESTROYED();
  DCHECK(IsInline());
  LayoutBlockFlow* block_flow = FragmentItemsContainer();
  return block_flow && !block_flow->NeedsLayout();
}

LayoutFlowThread* LayoutObject::LocateFlowThreadContainingBlock() const {
  NOT_DESTROYED();
  DCHECK(IsInsideFlowThread());
  return LayoutFlowThread::LocateFlowThreadContainingBlockOf(
      *this, LayoutFlowThread::kAnyAncestor);
}

static inline bool ObjectIsRelayoutBoundary(const LayoutObject* object) {
  // Only LayoutBox (and subclasses) are allowed to be relayout roots.
  const auto* box = DynamicTo<LayoutBox>(object);
  if (!box) {
    return false;
  }

  // We need a previous layout result to begin layout at a subtree root.
  const LayoutResult* layout_result = box->GetCachedLayoutResult(nullptr);
  if (!layout_result) {
    return false;
  }

  // Positioned objects always have self-painting layers and are safe to use as
  // relayout boundaries.
  bool is_svg_root = box->IsSVGRoot();
  bool has_self_painting_layer = box->HasLayer() && box->HasSelfPaintingLayer();
  if (!has_self_painting_layer && !is_svg_root)
    return false;

  // Table parts can't be relayout roots since the table is responsible for
  // layouting all the parts.
  if (box->IsTablePart()) {
    return false;
  }

  // OOF-positioned objects which rely on their static-position for placement
  // cannot be relayout boundaries (their final position would be incorrect).
  // TODO(crbug.com/40280256): Ignoring position-area means we may not allow
  // using the object as a relayout boundary even if position-area causes the
  // object to not rely on static position.
  const ComputedStyle* style = box->Style();
  if (box->IsOutOfFlowPositioned() &&
      (style->HasAutoLeftAndRightIgnoringPositionArea() ||
       style->HasAutoTopAndBottomIgnoringPositionArea())) {
    return false;
  }

  // In general we can't relayout a flex item independently of its container;
  // not only is the result incorrect due to the override size that's set, it
  // also messes with the cached main size on the flexbox.
  if (box->IsFlexItem()) {
    return false;
  }

  // Similarly to flex items, we can't relayout a grid item independently of
  // its container. This also applies to out of flow items of the grid, as we
  // need the cached information of the grid to recompute the out of flow
  // item's containing block rect.
  if (box->ContainingBlock()->IsLayoutGrid()) {
    return false;
  }

  // Make sure our fragment is safe to use.
  const auto& fragment = layout_result->GetPhysicalFragment();
  if (fragment.IsLayoutObjectDestroyedOrMoved()) {
    return false;
  }

  // Fragmented nodes cannot be relayout roots.
  if (fragment.GetBreakToken()) {
    return false;
  }

  // Any propagated layout-objects will affect the our container chain.
  if (fragment.HasPropagatedLayoutObjects()) {
    return false;
  }

  // If a box has any OOF descendants, they are propagated up the tree to
  // accumulate their static-position.
  if (fragment.HasOutOfFlowPositionedDescendants()) {
    return false;
  }

  // Anchor queries should be propagated across the layout boundaries, even
  // when `contain: strict` is explicitly set.
  if (fragment.HasAnchorQuery()) {
    return false;
  }

  // A box which doesn't establish a new formating context can pass a whole
  // bunch of state (floats, margins) to an arbitrary sibling, causing that
  // sibling to position/size differently.
  if (!fragment.IsFormattingContextRoot()) {
    return false;
  }

  // MathML subtrees can't be relayout roots because of the embellished operator
  // and space-like logic.
  if (box->IsMathML() && !box->IsMathMLRoot()) {
    return false;
  }

  if (box->ShouldApplyLayoutContainment() &&
      box->ShouldApplySizeContainment()) {
    return true;
  }

  // SVG roots are sufficiently self-contained to be a relayout boundary, even
  // if their size is non-fixed.
  if (is_svg_root)
    return true;

  // If either dimension is percent-based, intrinsic, or anything but fixed,
  // this object cannot form a re-layout boundary. A non-fixed computed logical
  // height will allow the object to grow and shrink based on the content
  // inside. The same goes for for logical width, if this objects is inside a
  // shrink-to-fit container, for instance.
  if (!style->Width().IsFixed() || !style->Height().IsFixed()) {
    return false;
  }

  if (box->IsTextControl()) {
    return true;
  }

  if (!box->ShouldClipOverflowAlongBothAxis()) {
    return false;
  }

  // Scrollbar parts can be removed during layout. Avoid the complexity of
  // having to deal with that.
  if (box->IsLayoutCustomScrollbarPart()) {
    return false;
  }

  // Inside block fragmentation it's generally problematic to allow relayout
  // roots. A multicol container ancestor may be scheduled for relayout as well
  // (due to other changes that may have happened since the previous layout
  // pass), which might affect the column heights, which may affect how this
  // object breaks across columns). Column spanners may also have been added or
  // removed since the previous layout pass, which is just another way of
  // affecting the column heights (and the number of rows). Another problematic
  // case is out-of-flow positioned objects, since they are being laid out by
  // the fragmentation context root (to become direct fragmentainer children),
  // rather than being laid out by their actual CSS containing block.
  //
  // Instead of identifying cases where it's safe to allow relayout roots, just
  // disallow them inside block fragmentation.
  if (box->MightBeInsideFragmentationContext()) {
    return false;
  }

  return true;
}

// Mark this object needing to re-run |CollectInlines()|.
//
// The flag is propagated to its container so that InlineNode that contains
// |this| is marked too. When |this| is a container, the propagation stops at
// |this|. When invalidating on inline blocks, floats, or OOF, caller need to
// pay attention whether it should mark its inner context or outer.
void LayoutObject::SetNeedsCollectInlines() {
  NOT_DESTROYED();
  if (NeedsCollectInlines())
    return;

  if (IsSVGChild() && !IsSVGText() && !IsSVGInline() && !IsSVGInlineText() &&
      !IsSVGForeignObject()) [[unlikely]] {
    return;
  }

  // Don't mark |LayoutFlowThread| because |CollectInlines()| skips them.
  if (!IsLayoutFlowThread())
    SetNeedsCollectInlines(true);

  if (LayoutObject* parent = Parent())
    parent->SetChildNeedsCollectInlines();
}

void LayoutObject::SetChildNeedsCollectInlines() {
  NOT_DESTROYED();
  LayoutObject* object = this;
  do {
    // Should not stop at |LayoutFlowThread| as |CollectInlines()| skips them.
    if (object->IsLayoutFlowThread()) [[unlikely]] {
      object = object->Parent();
      continue;
    }
    if (object->NeedsCollectInlines())
      break;
    object->SetNeedsCollectInlines(true);

    // Stop marking at the inline formatting context root. This is usually a
    // |LayoutBlockFlow|, but some other classes can have children; e.g.,
    // |LayoutButton| or |LayoutSVGRoot|. |LayoutInline| is the only class we
    // collect recursively (see |CollectInlines|). Use the same condition here.
    if (!object->IsLayoutInline())
      break;

    object = object->Parent();
  } while (object);
}

namespace {

bool HasPropagatedLayoutObjects(const LayoutObject* object) {
  if (auto* box = DynamicTo<LayoutBox>(object)) {
    for (const auto& fragment : box->PhysicalFragments()) {
      if (fragment.IsLayoutObjectDestroyedOrMoved()) {
        return true;
      }
      if (fragment.HasPropagatedLayoutObjects()) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

void LayoutObject::MarkContainerChainForLayout(bool schedule_relayout) {
  NOT_DESTROYED();
#if DCHECK_IS_ON()
  DCHECK(!IsSetNeedsLayoutForbidden());
  DCHECK(!GetDocument().InvalidationDisallowed());
#endif
  // When we're in layout, we're marking a descendant as needing layout with
  // the intention of visiting it during this layout. We shouldn't be
  // scheduling it to be laid out later. Also, scheduleRelayout() must not be
  // called while iterating LocalFrameView::layout_subtree_root_list_.
  schedule_relayout &= !GetFrameView()->IsInPerformLayout();

  LayoutObject* object = Container();
  LayoutObject* last = this;

  bool simplified_normal_flow_layout = NeedsSimplifiedLayoutOnly();
  while (object) {
    if (object->SelfNeedsFullLayout()) {
      return;
    }

    // Note that if the last element we processed was blocked by a display lock,
    // and the reason we're propagating a change is that a subtree needed layout
    // (ie |last| doesn't need either self layout or positioned movement
    // layout), then we can return and stop the dirty bit propagation. Note that
    // it's not enough to check |object|, since the element that is actually
    // locked needs its child bits set properly, we need to go one more
    // iteration after that.
    if (!last->SelfNeedsFullLayout() &&
        last->ChildLayoutBlockedByDisplayLock() &&
        !HasPropagatedLayoutObjects(last)) {
      return;
    }

    // Don't mark the outermost object of an unrooted subtree. That object will
    // be marked when the subtree is added to the document.
    LayoutObject* container = object->Container();
    if (!container && !IsA<LayoutView>(object))
      return;

    if (!last->IsTextOrSVGChild() && last->StyleRef().HasOutOfFlowPosition()) {
      object = last->ContainingBlock();
      container = object->Container();
      simplified_normal_flow_layout = true;
    }

    if (simplified_normal_flow_layout) {
      if (object->NeedsSimplifiedLayout()) {
        return;
      }
      object->SetNeedsSimplifiedLayout(true);
    } else {
      if (object->ChildNeedsFullLayout()) {
        return;
      }
      object->SetChildNeedsFullLayout(true);
    }
#if DCHECK_IS_ON()
    DCHECK(!object->IsSetNeedsLayoutForbidden());
#endif

    object->MarkSelfPaintingLayerForVisualOverflowRecalc();

    last = object;
    if (schedule_relayout && ObjectIsRelayoutBoundary(last))
      break;
    object = container;
  }

  if (schedule_relayout)
    last->ScheduleRelayout();
}

// LayoutNG has different OOF-positioned handling compared to the existing
// layout system. To correctly determine the static-position of the object,
// LayoutNG "bubbles" up the static-position inside the LayoutResult.
// See: |LayoutResult::OutOfFlowPositionedDescendants()|.
//
// Column spanners also have a bubbling mechanism, and therefore also need to
// mark ancestors between the element itself and the containing block (the
// multicol container).
//
// Whenever an OOF-positioned object is added/removed we need to invalidate
// layout for all the layout objects which may have stored a LayoutResult
// with this object contained in that list.
//
// In the future it may be possible to optimize this, e.g.
//  - For the removal case, add a pass which modifies the layout result to
//    remove the OOF-positioned descendant.
//  - For the adding case, if the OOF-positioned doesn't require a
//    static-position, simply insert the object up the LayoutResult chain with
//    an invalid static-position.
void LayoutObject::MarkParentForSpannerOrOutOfFlowPositionedChange() {
  NOT_DESTROYED();
#if DCHECK_IS_ON()
  DCHECK(!IsSetNeedsLayoutForbidden());
  DCHECK(!GetDocument().InvalidationDisallowed());
#endif

  LayoutObject* object = Parent();
  if (!object)
    return;

  // As OOF-positioned objects are represented as an object replacement
  // character in the inline items list. We need to ensure we collect the
  // inline items again to either collect or drop the OOF-positioned object.
  //
  // Note that this isn't necessary if we're dealing with a column spanner here,
  // but in order to keep things simple, we'll make no difference.
  object->SetNeedsCollectInlines();

  const LayoutBlock* containing_block = ContainingBlock();
  while (object != containing_block) {
    object->SetChildNeedsLayout(kMarkOnlyThis);
    object = object->Parent();
  }
  // Finally mark the parent block for layout. This will mark everything which
  // has an OOF-positioned object or column spanner in a LayoutResult as
  // needing layout.
  if (object)
    object->SetChildNeedsLayout();
}

void LayoutObject::SetIntrinsicLogicalWidthsDirty(
    MarkingBehavior mark_parents) {
  NOT_DESTROYED();
  bitfields_.SetIntrinsicLogicalWidthsDirty(true);
  bitfields_.SetIntrinsicLogicalWidthsDependsOnBlockConstraints(true);
  bitfields_.SetIndefiniteIntrinsicLogicalWidthsDirty(true);
  bitfields_.SetDefiniteIntrinsicLogicalWidthsDirty(true);
  if (mark_parents == kMarkContainerChain &&
      (IsText() || !StyleRef().HasOutOfFlowPosition()))
    InvalidateContainerIntrinsicLogicalWidths();
}

void LayoutObject::ClearIntrinsicLogicalWidthsDirty() {
  NOT_DESTROYED();
  bitfields_.SetIntrinsicLogicalWidthsDirty(false);
}

bool LayoutObject::IsFontFallbackValid() const {
  NOT_DESTROYED();
  return StyleRef().GetFont().IsFallbackValid() &&
         FirstLineStyle()->GetFont().IsFallbackValid();
}

void LayoutObject::InvalidateSubtreeLayoutForFontUpdates() {
  NOT_DESTROYED();
  if (!IsFontFallbackValid()) {
    SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
        layout_invalidation_reason::kFontsChanged);
  }
  for (LayoutObject* child = SlowFirstChild(); child;
       child = child->NextSibling()) {
    child->InvalidateSubtreeLayoutForFontUpdates();
  }
}

static inline bool ShouldInvalidateBeyond(LayoutObject* o) {
  // We don't work on individual inline objects, instead at an IFC level. We
  // never clear these bits on inline elements so invalidate past them.
  if (o->IsLayoutInline() || o->IsText()) {
    return true;
  }

  // Similarly for tables we don't compute min/max sizes on rows/sections.
  // Invalidate past them.
  if (o->IsTableRow() || o->IsTableSection()) {
    return true;
  }

  // Flow threads also don't have min/max sizes computed.
  if (o->IsLayoutFlowThread()) {
    return true;
  }

  // Invalidate past any subgrids. NOTE: we do this in both axes as we don't
  // know what writing-mode the root grid is in.
  if (o->IsLayoutGrid()) {
    const auto& style = o->StyleRef();
    if (style.GridTemplateColumns().IsSubgriddedAxis() ||
        style.GridTemplateRows().IsSubgriddedAxis()) {
      return true;
    }
  }

  return false;
}

inline void LayoutObject::InvalidateContainerIntrinsicLogicalWidths() {
  NOT_DESTROYED();

  LayoutObject* o = Container();
  while (o &&
         (!o->IntrinsicLogicalWidthsDirty() || ShouldInvalidateBeyond(o))) {
    LayoutObject* container = o->Container();

    // Don't invalidate the outermost object of an unrooted subtree. That object
    // will be invalidated when the subtree is added to the document.
    if (!container && !IsA<LayoutView>(o))
      break;

    o->bitfields_.SetIntrinsicLogicalWidthsDirty(true);
    // A positioned object has no effect on the min/max width of its containing
    // block ever. We can optimize this case and not go up any further.
    if (o->StyleRef().HasOutOfFlowPosition())
      break;
    o = container;
  }
}

LayoutObject* LayoutObject::ContainerForAbsolutePosition(
    AncestorSkipInfo* skip_info) const {
  NOT_DESTROYED();
  return FindAncestorByPredicate(this, skip_info, [](LayoutObject* candidate) {
    return candidate->CanContainAbsolutePositionObjects();
  });
}

LayoutObject* LayoutObject::ContainerForFixedPosition(
    AncestorSkipInfo* skip_info) const {
  NOT_DESTROYED();
  DCHECK(!IsText());
  return FindAncestorByPredicate(this, skip_info, [](LayoutObjec
```
Response:
The user wants to understand the functionality of the provided C++ code snippet from `ax_object.cc`. This involves:

1. **Identifying the core functions:** Analyze the methods defined in the code.
2. **Explaining their purpose:** Describe what each function does within the accessibility context.
3. **Relating to web technologies:** Connect the C++ code to JavaScript, HTML, and CSS concepts.
4. **Illustrating with examples:** Provide concrete scenarios for function behavior and potential errors.
5. **Tracing user interaction:** Explain how user actions can lead to the execution of this code.
6. **Summarizing the overall function:** Condense the findings into a concise description.

Let's break down the code snippet function by function and address each of the user's requirements.
这是 `blink/renderer/modules/accessibility/ax_object.cc` 文件中关于缓存可访问性属性值更新和判断的代码片段。它的主要功能是管理和更新 `AXObject` 中缓存的各种可访问性相关的属性值，这些属性决定了对象是否被辅助技术（例如屏幕阅读器）所感知和如何感知。

以下是对代码片段功能的详细列举和说明：

**核心功能：管理和更新 `AXObject` 的缓存可访问性属性值**

* **`CheckCanAccessCachedValues()`:**
    * **功能:**  在开发模式下（DCHECK_IS_ON），检查是否能在 `AXObjectCache` 冻结时访问缓存的值。如果 `AXObject` 未分离 ( `!IsDetached()` ) 并且 `AXObjectCache` 处于冻结状态 ( `AXObjectCache().IsFrozen()` )，则断言 `NeedsToUpdateCachedValues()` 返回 `false`。
    * **目的:**  用于调试，确保在 `AXObjectCache` 冻结（通常发生在序列化时）后访问的缓存值是最新的。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** `AXObject` 实例 `obj`，`obj.IsDetached()` 返回 `false`，`AXObjectCache().IsFrozen()` 返回 `true`。
        * **输出:** 如果 `obj.NeedsToUpdateCachedValues()` 返回 `true`，则触发断言，输出错误信息 "Stale values: [obj的地址]"。
* **`InvalidateCachedValues()`:**
    * **功能:**  将 `cached_values_need_update_` 标志设置为 `true`，表示缓存的值需要更新。
    * **前提条件:**  必须在 `AXObjectCache` 的生命周期允许 `AXObject` 被标记为脏 ( `AXObjectCache().lifecycle().StateAllowsAXObjectsToBeDirtied()` ) 的状态下调用。
    * **目的:**  当影响可访问性属性的因素发生变化时，需要调用此方法来标记缓存失效。
    * **常见使用错误:** 在更新缓存值的过程中调用此方法，可能导致数据不一致。代码中使用了 `DCHECK(!is_updating_cached_values_)` 进行检查。
* **`UpdateCachedAttributeValuesIfNeeded(bool notify_parent_of_ignored_changes)`:**
    * **功能:**  检查是否需要更新缓存的可访问性属性值，如果需要则进行更新。
    * **参数:** `notify_parent_of_ignored_changes`：一个布尔值，指示当子元素的忽略状态发生变化时，是否通知父元素。
    * **核心步骤:**
        1. **检查是否分离:** 如果 `AXObject` 已分离，则将其标记为忽略，并返回。
        2. **检查是否需要更新:** 如果 `NeedsToUpdateCachedValues()` 返回 `false`，则直接返回，无需更新。
        3. **设置更新标志:** 将 `cached_values_need_update_` 设置为 `false`，表示正在进行更新。
        4. **断言检查:**  进行一系列断言检查，例如是否在计算角色时更新缓存、是否在同一个节点上重复调用此方法、文档生命周期是否正常等。
        5. **计算各种属性:**  计算并缓存各种可访问性相关的属性值，例如 `cached_is_hidden_via_style_`、`cached_is_inert_`、`cached_is_aria_hidden_`、`cached_can_set_focus_attribute_`、`cached_is_ignored_`、`cached_is_used_for_label_or_description_` 等。这些属性的计算依赖于 DOM 结构、CSS 样式以及 ARIA 属性。
        6. **处理继承属性变化:** 如果某些继承的属性值发生变化，则调用 `OnInheritedCachedValuesChanged()` 通知子元素也需要更新。
        7. **处理包含在树中的状态变化:**  当元素的 "包含在树中" 的状态发生变化时，会通知父元素，以便父元素重新计算其子元素。
        8. **计算 Live Region Root:**  确定当前元素的 Live Region Root。
        9. **更新局部边界框:** 如果元素是文本节点，则更新其局部边界框。
    * **与 JavaScript, HTML, CSS 的关系:**
        * **HTML:**  该方法会检查与 ARIA 属性相关的 HTML 属性，例如 `aria-hidden`、`aria-modal`、`aria-disabled`。例如，`ComputeIsAriaHidden()` 函数会检查 `aria-hidden` 属性的值。
        * **CSS:** 该方法会获取元素的计算样式 ( `GetComputedStyle()` )，并根据样式属性（例如 `display: none`、`visibility: hidden`、`inert`）来计算可访问性属性，例如 `ComputeIsHiddenViaStyle()` 和 `ComputeIsInertViaStyle()`。
        * **JavaScript:** JavaScript 可以通过 DOM API 修改 HTML 结构、CSS 样式和 ARIA 属性，这些修改会触发 `InvalidateCachedValues()` 的调用，最终导致 `UpdateCachedAttributeValuesIfNeeded()` 被执行，更新缓存的可访问性属性值。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 一个 `AXObject` 实例对应一个设置了 `style="display: none;"` 的 HTML 元素。
        * **输出:**  `ComputeIsHiddenViaStyle()` 将返回 `true`，`cached_is_hidden_via_style_` 将被设置为 `true`，最终导致 `ComputeIsIgnored()` 返回 `true`，表明该元素被辅助技术忽略。
        * **假设输入:** 一个 `AXObject` 实例对应一个设置了 `aria-hidden="true"` 的 HTML 元素。
        * **输出:** `ComputeIsAriaHidden()` 将返回 `true`，`cached_is_aria_hidden_` 将被设置为 `true`，最终导致 `ComputeIsIgnored()` 返回 `true`。
    * **用户操作如何一步步的到达这里 (调试线索):**
        1. 用户在网页上进行某些操作，例如加载页面、滚动、与元素交互（点击、输入等）。
        2. 这些操作可能导致 DOM 结构、CSS 样式或 ARIA 属性发生变化。
        3. Blink 渲染引擎会检测到这些变化，并通知 `AXObjectCache`。
        4. `AXObjectCache` 会调用 `InvalidateCachedValues()` 来标记相关的 `AXObject` 实例的缓存失效。
        5. 在下次需要访问这些 `AXObject` 的可访问性信息时（例如，辅助技术请求），会调用 `UpdateCachedAttributeValuesIfNeeded()` 来更新缓存值。
* **`OnInheritedCachedValuesChanged()`:**
    * **功能:** 当一个可能继承的缓存值发生变化时调用。它标记当前对象的子元素也需要更新其缓存值。
    * **核心步骤:**
        1. 检查当前对象是否可以拥有子元素 (`CanHaveChildren()`)。
        2. 设置 `child_cached_values_need_update_` 标志为 `true`。
        3. 如果 `children_dirty_` 已经为 `true`，则直接返回，避免重复处理。
        4. 如果 `AXObjectCache` 正在更新树，则设置 `children_dirty_` 为 `true`，并通知父元素其有脏的子元素。
        5. 否则，调用 `SetNeedsToUpdateChildren()` 来确保子元素在下次树更新时被更新，并且如果当前元素未包含在树中，则通知其祖先需要更新子元素。
* **`ComputeIsIgnored(IgnoredReasons* ignored_reasons)`:**
    * **功能:** 计算当前 `AXObject` 是否应该被辅助技术忽略。
    * **参数:** `ignored_reasons`：一个可选的指针，用于记录被忽略的原因。
    * **核心逻辑:** 调用 `ShouldIgnoreForHiddenOrInert()` 来判断是否因为隐藏或惰性而被忽略。
* **`ShouldIgnoreForHiddenOrInert(IgnoredReasons* ignored_reasons)`:**
    * **功能:** 判断 `AXObject` 是否因为 CSS 隐藏、ARIA 隐藏或 `inert` 属性而被忽略。
    * **核心步骤:**
        1. **断言检查:** 确保在计算忽略状态之前缓存值是最新的。
        2. **Document 节点:**  如果当前节点是 Document 节点，则不忽略。
        3. **检查 `aria-hidden`:** 如果 `cached_is_aria_hidden_` 为 `true`，则忽略。
        4. **检查 `inert`:** 如果 `cached_is_inert_` 为 `true`，则忽略。
        5. **检查 CSS 隐藏:** 如果 `cached_is_hidden_via_style_` 为 `true`，则忽略。
        6. **检查渲染状态:** 如果元素没有布局对象 ( `GetLayoutObject()` )，并且不是特定类型的元素（例如 `HTMLAreaElement`），并且没有被 `display: contents` 样式影响，也不是 `HTMLOptionElement`，则可能被忽略（例如，空白文本节点）。
* **`IsInert()`:**
    * **功能:**  返回当前 `AXObject` 是否是惰性的 (inert)。
    * **核心步骤:**  先检查是否可以访问缓存的值，然后根据需要更新缓存，最后返回 `cached_is_inert_` 的值。
* **`ComputeIsInertViaStyle(const ComputedStyle* style, IgnoredReasons* ignored_reasons)`:**
    * **功能:** 根据元素的计算样式来判断其是否是惰性的。
    * **核心逻辑:**
        1. **Inline Text Box:** 如果是内联文本框，则继承其父元素的惰性状态。
        2. **检查 `inert` 样式:** 如果元素的样式设置了 `inert`，则它是惰性的。
        3. **检查 `aria-modal` 阻止:** 如果被 `aria-modal` 对话框阻止，则认为是惰性的。
        4. **检查 `frame` 的 `inert` 状态:** 如果元素所在的 frame 是惰性的，则认为是惰性的。
        5. **递归检查父元素:** 如果以上条件都不满足，则递归检查父元素的惰性状态。
* **`ComputeIsInert(IgnoredReasons* ignored_reasons)`:**
    * **功能:** 计算当前 `AXObject` 是否是惰性的。
    * **核心逻辑:** 调用 `ComputeIsInertViaStyle()` 并传入元素的计算样式。
* **`IsAriaHiddenRoot()`:**
    * **功能:** 判断当前 `AXObject` 是否是 `aria-hidden` 属性为 `true` 的根元素。
    * **核心逻辑:**
        1. 检查是否有错误的 `aria-hidden` 属性使用 (`AXObjectCache().HasBadAriaHidden(*this)`)。
        2. 检查 `aria-hidden` 属性是否为 `true`。
        3. 排除不适用 `aria-hidden` 属性的元素，例如 `html`、`body` 和 `option` 元素。
* **`IsAriaHidden()`:**
    * **功能:** 返回当前 `AXObject` 是否被 `aria-hidden` 属性隐藏。
    * **核心步骤:** 先检查是否可以访问缓存的值，然后根据需要更新缓存，最后返回 `cached_is_aria_hidden_` 的值。
* **`ComputeIsAriaHidden(IgnoredReasons* ignored_reasons)`:**
    * **功能:** 计算当前 `AXObject` 是否被 `aria-hidden` 属性隐藏。
    * **核心逻辑:**
        1. **Document 节点:** Document 节点不能被 `aria-hidden` 隐藏。
        2. **检查自身是否是 `aria-hidden` 根元素:** 调用 `IsAriaHiddenRoot()`。
        3. **递归检查父元素:** 如果父元素被 `aria-hidden` 隐藏，则当前元素也被隐藏。
* **`IsModal()`:**
    * **功能:** 判断当前 `AXObject` 是否是模态对话框。
    * **核心逻辑:**
        1. 检查元素的 role 是否是 `dialog` 或 `alertdialog`。
        2. 检查 `aria-modal` 属性是否为 `true`。
        3. 对于 `<dialog>` 元素，检查是否处于顶层 (top layer)。
* **`IsBlockedByAriaModalDialog(IgnoredReasons* ignored_reasons)`:**
    * **功能:** 判断当前 `AXObject` 是否被活动的 `aria-modal` 对话框所阻止。
    * **核心逻辑:**
        1. 如果 `AXObject` 已分离，则不被阻止。
        2. 获取活动的 `aria-modal` 对话框。
        3. 在不需要手动修剪可访问性树的平台上，模态对话框没有影响。
        4. 如果当前元素是活动模态对话框的子元素，则不被阻止。
        5. 否则，认为被模态对话框阻止。
* **`IsVisible()`:**
    * **功能:** 判断当前 `AXObject` 是否对用户可见（在可访问性的上下文中）。
    * **核心逻辑:**  只有当元素未分离、未被 `aria-hidden` 隐藏、不是惰性的且未被 CSS 隐藏时，才被认为是可见的。
* **`AriaHiddenRoot()`:**
    * **功能:**  返回当前元素所在 `aria-hidden` 子树的根元素。
    * **核心逻辑:** 如果当前元素被 `aria-hidden` 隐藏，则向上查找最近的设置了 `aria-hidden="true"` 的祖先元素。
* **`InertRoot()`:**
    * **功能:** 返回当前元素所在 `inert` 子树的根元素。
    * **核心逻辑:** 向上查找最近的设置了 `inert` 属性的祖先元素。
* **`IsDescendantOfDisabledNode()`:**
    * **功能:** 返回当前 `AXObject` 是否是禁用节点的后代。
    * **核心步骤:** 先检查是否可以访问缓存的值，然后根据需要更新缓存，最后返回 `cached_is_descendant_of_disabled_node_` 的值。
* **`ComputeIsDescendantOfDisabledNode()`:**
    * **功能:** 计算当前 `AXObject` 是否是禁用节点的后代。
    * **核心逻辑:**
        1. Document 节点不可能是禁用节点的后代。
        2. 检查 `aria-disabled` 属性是否为 `true`。
        3. 递归检查父元素是否被禁用或是否是禁用节点的后代。
* **`IsExcludedByFormControlsFilter()`:**
    * **功能:**  判断当前 `AXObject` 是否被表单控件过滤器排除。这个过滤器用于实验性的表单控件可访问性功能。
    * **核心逻辑:**  根据实验性标志、元素是否因样式隐藏、是否是控件元素、是否是表单控件的上下文标签、是否是富文本编辑元素等条件来判断是否应该被排除。
* **`ComputeIsIgnoredButIncludedInTree()`:**
    * **功能:** 计算当前 `AXObject` 是否被辅助技术忽略，但仍然包含在可访问性树中。
    * **核心逻辑:**  某些被忽略的元素仍然需要保留在可访问性树中，以便进行名称计算、关系建立等。例如，`aria-owns` 属性引用的元素、`<label>` 元素、 `<map>` 元素的子元素、伪元素的父元素、用于 label 或 description 的元素等。同时，也考虑了表单控件过滤器的影响。

**总结 `AXObject.cc` (本部分) 的功能:**

这段代码主要负责管理 `AXObject` 中缓存的可访问性相关属性值，并提供方法来判断元素是否被辅助技术忽略，以及是否包含在可访问性树中。它涉及了对 HTML 结构、CSS 样式和 ARIA 属性的解析和处理，以确保辅助技术能够正确理解和呈现网页内容。核心目标是维护可访问性信息的准确性和及时性，以便辅助技术能够提供最佳的用户体验。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共10部分，请归纳一下它的功能

"""


void AXObject::CheckCanAccessCachedValues() const {
  if (!IsDetached() && AXObjectCache().IsFrozen()) {
    DUMP_WILL_BE_CHECK(!NeedsToUpdateCachedValues())
        << "Stale values: " << this;
  }
}

void AXObject::InvalidateCachedValues() {
  CHECK(AXObjectCache().lifecycle().StateAllowsAXObjectsToBeDirtied())
      << AXObjectCache();
#if DCHECK_IS_ON()
  DCHECK(!is_updating_cached_values_)
      << "Should not invalidate cached values while updating them.";
#endif

  cached_values_need_update_ = true;
}

void AXObject::UpdateCachedAttributeValuesIfNeeded(
    bool notify_parent_of_ignored_changes) {
  if (IsDetached()) {
    cached_is_ignored_ = true;
    cached_is_ignored_but_included_in_tree_ = false;
    return;
  }

  if (!NeedsToUpdateCachedValues()) {
    return;
  }

  cached_values_need_update_ = false;

  CHECK(AXObjectCache().lifecycle().StateAllowsImmediateTreeUpdates())
      << AXObjectCache();

#if DCHECK_IS_ON()  // Required in order to get Lifecycle().ToString()
  DCHECK(!is_computing_role_)
      << "Updating cached values while computing a role is dangerous as it "
         "can lead to code that uses the AXObject before it is ready.";
  DCHECK(!is_updating_cached_values_)
      << "Reentering UpdateCachedAttributeValuesIfNeeded() on same node: "
      << GetNode();

  base::AutoReset<bool> reentrancy_protector(&is_updating_cached_values_, true);

  DCHECK(!GetDocument() || GetDocument()->Lifecycle().GetState() >=
                               DocumentLifecycle::kAfterPerformLayout)
      << "Unclean document at lifecycle "
      << GetDocument()->Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  DUMP_WILL_BE_CHECK(!IsMissingParent()) << "Missing parent: " << this;

  const ComputedStyle* style = GetComputedStyle();

  cached_is_hidden_via_style_ = ComputeIsHiddenViaStyle(style);

  // Decisions in what subtree descendants are included (each descendant's
  // cached children_) depends on the ARIA hidden state. When it changes,
  // the entire subtree needs to recompute descendants.
  // In addition, the below computations for is_ignored_but_included_in_tree is
  // dependent on having the correct new cached value.
  bool is_inert = ComputeIsInertViaStyle(style);
  bool is_aria_hidden = ComputeIsAriaHidden();
  bool is_in_menu_list_subtree = ComputeIsInMenuListSubtree();
  bool is_descendant_of_disabled_node = ComputeIsDescendantOfDisabledNode();
  bool is_changing_inherited_values = false;
  if (cached_is_inert_ != is_inert ||
      cached_is_aria_hidden_ != is_aria_hidden ||
      cached_is_in_menu_list_subtree_ != is_in_menu_list_subtree ||
      cached_is_descendant_of_disabled_node_ !=
          is_descendant_of_disabled_node) {
    is_changing_inherited_values = true;
    cached_is_inert_ = is_inert;
    cached_is_aria_hidden_ = is_aria_hidden;
    cached_is_in_menu_list_subtree_ = is_in_menu_list_subtree;
    cached_is_descendant_of_disabled_node_ = is_descendant_of_disabled_node;
  }

  // Must be after inert computation, because focusability depends on that, but
  // before the included in tree computation, which depends on focusability.
  CHECK(!IsDetached());
  cached_can_set_focus_attribute_ = ComputeCanSetFocusAttribute();
  CHECK(!IsDetached());

  // Must be computed before is_used_for_label_or_description computation.
  bool was_included_in_tree = IsIncludedInTree();
  bool is_ignored = ComputeIsIgnored();
  if (is_ignored != IsIgnored()) {
    // Presence of inline text children depends on ignored state.
    if (ui::CanHaveInlineTextBoxChildren(RoleValue())) {
      is_changing_inherited_values = true;
    }
    cached_is_ignored_ = is_ignored;
  }

  // This depends on cached_is_ignored_ and cached_can_set_focus_attribute_.
  bool is_used_for_label_or_description = ComputeIsUsedForLabelOrDescription();
  if (is_used_for_label_or_description !=
      cached_is_used_for_label_or_description_) {
    is_changing_inherited_values = true;
    cached_is_used_for_label_or_description_ = is_used_for_label_or_description;
  }

  // This depends on cached_is_used_for_label_or_description_.
  bool is_ignored_but_included_in_tree =
      is_ignored && ComputeIsIgnoredButIncludedInTree();
  bool is_included_in_tree = !is_ignored || is_ignored_but_included_in_tree;
#if DCHECK_IS_ON()
  if (!is_included_in_tree && GetNode()) {
    Node* dom_parent = NodeTraversal::Parent(*GetNode());
    DCHECK(dom_parent)
        << "A node with no DOM parent must be included in the tree, so that it "
           "can be found while traversing descendants.";
    Node* flat_tree_parent = LayoutTreeBuilderTraversal::Parent(*GetNode());
    DCHECK_EQ(dom_parent, flat_tree_parent)
        << "\nA node with a different flat tree parent must be included in the "
           "tree, so that it can be found while traversing descendants.";
  }
#endif
  bool included_in_tree_changed = is_included_in_tree != was_included_in_tree;
  bool notify_included_in_tree_changed = false;
  if (included_in_tree_changed) {
    // If the inclusion bit is changing, we need to repair the
    // has_dirty_descendants, because it is only set on included nodes.
    if (is_included_in_tree) {
      // This is being inserted in the hierarchy as an included node: if the
      // parent has dirty descendants copy that bit to this as well, so as not
      // to interrupt the chain of descendant updates.
      if (AXObject* unignored_parent = ParentObjectUnignored()) {
        if (unignored_parent->HasDirtyDescendants()) {
          has_dirty_descendants_ = true;
        }
      }
    } else {
      // The has dirty descendant bits will only be cleared on included
      // nodes, so it should not be set on nodes that becomes unincluded.
      has_dirty_descendants_ = false;
    }
    // If the child's "included in tree" state changes, we will be notifying the
    // parent to recompute its children.
    // Exceptions:
    // - Caller passes in |notify_parent_of_ignored_changes = false| -- this
    //   occurs when this is a new child, or when a parent is in the middle of
    //   adding this child, and doing this would be redundant.
    // - Inline text boxes: their "included in tree" state is entirely dependent
    //   on their static text parent.
    if (notify_parent_of_ignored_changes) {
      notify_included_in_tree_changed = true;
    }
  }

  // If the child's "included in tree" state changes, we will be notifying the
  // parent to recompute it's children.
  // Exceptions:
  // - Caller passes in |notify_parent_of_ignored_changes = false| -- this
  //   occurs when this is a new child, or when a parent is in the middle of
  //   adding this child, and doing this would be redundant.
  // - Inline text boxes: their "included in tree" state is entirely dependent
  //   on their static text parent.
  // This must be called before cached_is_ignored_* are updated, otherwise a
  // performance optimization depending on IsIncludedInTree()
  // may misfire.
  if (RoleValue() != ax::mojom::blink::Role::kInlineTextBox) {
    if (notify_included_in_tree_changed) {
      if (AXObject* parent = ParentObject()) {
        SANITIZER_CHECK(!AXObjectCache().IsFrozen())
            << "Objects cannot change their inclusion state during "
               "serialization:\n"
            << "* Object: " << this << "\n* Ignored will become " << is_ignored
            << "\n* Included in tree will become "
            << (!is_ignored || is_ignored_but_included_in_tree)
            << "\n* Parent: " << parent;
        // Defers a ChildrenChanged() on the first included ancestor.
        // Must defer it, otherwise it can cause reentry into
        // UpdateCachedAttributeValuesIfNeeded() on |this|.
        // ParentObjectUnignored()->SetNeedsToUpdateChildren();
        AXObjectCache().ChildrenChangedOnAncestorOf(this);
      }
    } else if (included_in_tree_changed && AXObjectCache().IsUpdatingTree()) {
      // In some cases changes to inherited properties can cause an object
      // inclusion change in the tree updating phase, where it's too late to use
      // the usual dirty object mechanisms, but we can still queue the dirty
      // object for the serializer. The dirty object is the parent.
      // TODO(accessibility) Do we need to de-dupe these?
      AXObject* unignored_parent = ParentObjectUnignored();
      CHECK(unignored_parent);
      AXObjectCache().AddDirtyObjectToSerializationQueue(unignored_parent);
    }
  }

  cached_is_ignored_ = is_ignored;
  cached_is_ignored_but_included_in_tree_ = is_ignored_but_included_in_tree;

  // Compute live region root, which can be from any ARIA live value, including
  // "off", or from an automatic ARIA live value, e.g. from role="status".
  AXObject* previous_live_region_root = cached_live_region_root_;
  if (RoleValue() == ax::mojom::blink::Role::kInlineTextBox) {
    // Inline text boxes do not need live region properties.
    cached_live_region_root_ = nullptr;
  } else if (IsA<Document>(GetNode())) {
    // The document root is never a live region root.
    cached_live_region_root_ = nullptr;
  } else {
    DCHECK(parent_);
    // Is a live region root if this or an ancestor is a live region.
    cached_live_region_root_ =
        IsLiveRegionRoot() ? this : parent_->LiveRegionRoot();
  }
  if (cached_live_region_root_ != previous_live_region_root) {
    is_changing_inherited_values = true;
  }

  if (GetLayoutObject() && GetLayoutObject()->IsText()) {
    cached_local_bounding_box_ =
        GetLayoutObject()->LocalBoundingBoxRectForAccessibility();
  }

  if (is_changing_inherited_values) {
    // Update children if not already dirty.
    OnInheritedCachedValuesChanged();
  }

#if DCHECK_IS_ON()
  DCHECK(!NeedsToUpdateCachedValues())
      << "While recomputing cached values, they were invalidated again.";
  if (included_in_tree_changed) {
    AXObjectCache().UpdateIncludedNodeCount(this);
  }
#endif
}

void AXObject::OnInheritedCachedValuesChanged() {
  // When a cached value that can inherit its value changes, it means that
  // all descendants need to recompute its value. We do this by ensuring
  // that FinalizeTree() will visit all descendants and recompute
  // cached values.
  if (!CanHaveChildren()) {
    return;  // Nothing to do.
  }

  // This flag is checked and cleared when children are added.
  child_cached_values_need_update_ = true;

  if (children_dirty_) {
    return;
  }

  if (AXObjectCache().IsUpdatingTree()) {
    // When already in the middle of updating the tree, we know we are building
    // from the top down, and that its ok to mark things below (descendants) as
    // dirty and alter/rebuild them, but at this point we must not alter
    // ancestors. Mark the current children and their cached values dirty, and
    // set a flag so that
    children_dirty_ = true;
    if (AXObject* parent = ParentObjectIncludedInTree()) {
      // Make sure the loop in FinalizeTree() recursively will continue
      // and rebuild children whenever cached values of children have changed.
      // The loop continues if |has_dirty_descendants_| is set on the parent
      // that added this child.
      parent->SetHasDirtyDescendants(true);
    }
  } else {
    // Ensure that all children of this node will be updated during the next
    // tree update in AXObjectCacheImpl::FinalizeTree().
    SetNeedsToUpdateChildren();
    if (!IsIncludedInTree()) {
      // Make sure that, starting at an included node, children will
      // recursively be updated until we reach |this|.
      AXObjectCache().ChildrenChangedOnAncestorOf(this);
    }
  }
}

bool AXObject::ComputeIsIgnored(
    IgnoredReasons* ignored_reasons) const {
  return ShouldIgnoreForHiddenOrInert(ignored_reasons);
}

bool AXObject::ShouldIgnoreForHiddenOrInert(
    IgnoredReasons* ignored_reasons) const {
  DUMP_WILL_BE_CHECK(!cached_values_need_update_)
      << "Tried to compute ignored value without up-to-date hidden/inert "
         "values on "
      << this;

  // All nodes must have an unignored parent within their tree under
  // the root node of the web area, so force that node to always be unignored.
  if (IsA<Document>(GetNode())) {
    return false;
  }

  if (cached_is_aria_hidden_) {
    if (ignored_reasons) {
      ComputeIsAriaHidden(ignored_reasons);
    }
    return true;
  }

  if (cached_is_inert_) {
    if (ignored_reasons) {
      ComputeIsInert(ignored_reasons);
    }
    return true;
  }

  if (cached_is_hidden_via_style_) {
    if (ignored_reasons) {
      ignored_reasons->push_back(
          IgnoredReason(GetLayoutObject() ? kAXNotVisible : kAXNotRendered));
    }
    return true;
  }

  // Hide nodes that are whitespace or are occluded by CSS alt text.
  if (!GetLayoutObject() && GetNode() && !IsA<HTMLAreaElement>(GetNode()) &&
      !DisplayLockUtilities::IsDisplayLockedPreventingPaint(GetNode()) &&
      (!GetElement() || !GetElement()->HasDisplayContentsStyle()) &&
      !IsA<HTMLOptionElement>(GetNode())) {
    if (ignored_reasons) {
      ignored_reasons->push_back(IgnoredReason(kAXNotRendered));
    }
    return true;
  }

  return false;
}

// Note: do not rely on the value of this inside of display:none.
// In practice, it does not matter because nodes in display:none subtrees are
// marked ignored either way.
bool AXObject::IsInert() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_inert_;
}

bool AXObject::ComputeIsInertViaStyle(const ComputedStyle* style,
                                      IgnoredReasons* ignored_reasons) const {
  if (IsAXInlineTextBox()) {
    return ParentObject()->IsInert()
               ? ParentObject()->ComputeIsInertViaStyle(style, ignored_reasons)
               : false;
  }
  // TODO(szager): This method is n^2 -- it recurses into itself via
  // ComputeIsInert(), and InertRoot() does as well.
  if (style) {
    if (style->IsInert()) {
      if (ignored_reasons) {
        const AXObject* ax_inert_root = InertRoot();
        if (ax_inert_root == this) {
          ignored_reasons->push_back(IgnoredReason(kAXInertElement));
          return true;
        }
        if (ax_inert_root) {
          ignored_reasons->push_back(
              IgnoredReason(kAXInertSubtree, ax_inert_root));
          return true;
        }
        // If there is no inert root, inertness must have been set by a modal
        // dialog or a fullscreen element (see AdjustStyleForInert).
        Document& document = GetNode()->GetDocument();
        if (HTMLDialogElement* dialog = document.ActiveModalDialog()) {
          if (AXObject* dialog_object = AXObjectCache().Get(dialog)) {
            ignored_reasons->push_back(
                IgnoredReason(kAXActiveModalDialog, dialog_object));
            return true;
          }
        } else if (Element* fullscreen =
                       Fullscreen::FullscreenElementFrom(document)) {
          if (AXObject* fullscreen_object = AXObjectCache().Get(fullscreen)) {
            ignored_reasons->push_back(
                IgnoredReason(kAXActiveFullscreenElement, fullscreen_object));
            return true;
          }
        }
        ignored_reasons->push_back(IgnoredReason(kAXInertElement));
      }
      return true;
    } else if (IsBlockedByAriaModalDialog(ignored_reasons)) {
      if (ignored_reasons)
        ignored_reasons->push_back(IgnoredReason(kAXAriaModalDialog));
      return true;
    } else if (const LocalFrame* frame = GetNode()->GetDocument().GetFrame()) {
      // Inert frames don't expose the inertness to the style of their contents,
      // but accessibility should consider them inert anyways.
      if (frame->IsInert()) {
        if (ignored_reasons)
          ignored_reasons->push_back(IgnoredReason(kAXInertSubtree));
        return true;
      }
    }
    return false;
  }

  // Either GetNode() is null, or it's locked by content-visibility, or we
  // failed to obtain a ComputedStyle. Make a guess iterating the ancestors.
  if (const AXObject* ax_inert_root = InertRoot()) {
    if (ignored_reasons) {
      if (ax_inert_root == this) {
        ignored_reasons->push_back(IgnoredReason(kAXInertElement));
      } else {
        ignored_reasons->push_back(
            IgnoredReason(kAXInertSubtree, ax_inert_root));
      }
    }
    return true;
  } else if (IsBlockedByAriaModalDialog(ignored_reasons)) {
    if (ignored_reasons)
      ignored_reasons->push_back(IgnoredReason(kAXAriaModalDialog));
    return true;
  } else if (GetNode()) {
    if (const LocalFrame* frame = GetNode()->GetDocument().GetFrame()) {
      // Inert frames don't expose the inertness to the style of their contents,
      // but accessibility should consider them inert anyways.
      if (frame->IsInert()) {
        if (ignored_reasons)
          ignored_reasons->push_back(IgnoredReason(kAXInertSubtree));
        return true;
      }
    }
  }

  AXObject* parent = ParentObject();
  if (parent && parent->IsInert()) {
    if (ignored_reasons)
      parent->ComputeIsInert(ignored_reasons);
    return true;
  }

  return false;
}

bool AXObject::ComputeIsInert(IgnoredReasons* ignored_reasons) const {
  return ComputeIsInertViaStyle(GetComputedStyle(), ignored_reasons);
}

bool AXObject::IsAriaHiddenRoot() const {
  if (AXObjectCache().HasBadAriaHidden(*this)) {
    return false;
  }

  // aria-hidden:true works a bit like display:none.
  // * aria-hidden=true affects entire subtree.
  // * aria-hidden=false is a noop.
  if (!IsAriaAttributeTrue(html_names::kAriaHiddenAttr)) {
    return false;
  }

  auto* node = GetNode();

  // The aria-hidden attribute is not valid for the main html and body elements:
  // See more at https://github.com/w3c/aria/pull/1880.
  // Also ignored for <option> because it would unnecessarily complicate the
  // logic in the case where the option is selected, and aria-hidden does not
  // prevent selection of the option (it cannot because ARIA does not affect
  // behavior outside of assistive tech driven by a11y API).
  if (IsA<HTMLBodyElement>(node) || node == GetDocument()->documentElement() ||
      IsA<HTMLOptionElement>(node)) {
    AXObjectCache().DiscardBadAriaHiddenBecauseOfElement(*this);
    return false;
  }

  return true;
}

bool AXObject::IsAriaHidden() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_aria_hidden_;
}

bool AXObject::ComputeIsAriaHidden(IgnoredReasons* ignored_reasons) const {
  // The root node of a document or popup document cannot be aria-hidden:
  // - The root node of the main document cannot be hidden because there
  // is no element to place aria-hidden markup on.
  // - The root node of the popup document cannot be aria-hidden because it
  // seems like a bad idea to not allow access to it if it's actually there and
  // visible.
  if (IsA<Document>(GetNode())) {
    return false;
  }

  if (IsAriaHiddenRoot()) {
    if (ignored_reasons)
      ignored_reasons->push_back(IgnoredReason(kAXAriaHiddenElement));
    return true;
  }

  if (AXObject* parent = ParentObject()) {
    if (parent->IsAriaHidden()) {
      if (ignored_reasons) {
        ignored_reasons->push_back(
            IgnoredReason(kAXAriaHiddenSubtree, AriaHiddenRoot()));
      }
      return true;
    }
  }

  return false;
}

bool AXObject::IsModal() const {
  if (RoleValue() != ax::mojom::blink::Role::kDialog &&
      RoleValue() != ax::mojom::blink::Role::kAlertDialog)
    return false;

  bool modal = false;
  if (AriaBooleanAttribute(html_names::kAriaModalAttr, &modal)) {
    return modal;
  }

  if (GetNode() && IsA<HTMLDialogElement>(*GetNode()))
    return To<Element>(GetNode())->IsInTopLayer();

  return false;
}

bool AXObject::IsBlockedByAriaModalDialog(
    IgnoredReasons* ignored_reasons) const {
  if (IsDetached()) {
    return false;
  }

  Element* active_aria_modal_dialog =
      AXObjectCache().GetActiveAriaModalDialog();

  // On platforms that don't require manual pruning of the accessibility tree,
  // the active aria modal dialog should never be set, so has no effect.
  if (!active_aria_modal_dialog) {
    return false;
  }

  if ((!GetNode() || GetNode()->IsPseudoElement()) && ParentObject()) {
    return ParentObject()->IsBlockedByAriaModalDialog();
  }

  if (FlatTreeTraversal::Contains(*active_aria_modal_dialog, *GetNode())) {
    return false;
  }

  if (ignored_reasons) {
    ignored_reasons->push_back(IgnoredReason(
        kAXAriaModalDialog, AXObjectCache().Get(active_aria_modal_dialog)));
  }
  return true;
}

bool AXObject::IsVisible() const {
  // TODO(accessibility) Consider exposing inert objects as visible, since they
  // are visible. It should be fine, since the objexcts are ignored.
  return !IsDetached() && !IsAriaHidden() && !IsInert() && !IsHiddenViaStyle();
}

const AXObject* AXObject::AriaHiddenRoot() const {
  return IsAriaHidden() ? FindAncestorWithAriaHidden(this) : nullptr;
}

const AXObject* AXObject::InertRoot() const {
  const AXObject* object = this;
  while (object && !object->IsAXNodeObject())
    object = object->ParentObject();

  DCHECK(object);

  Node* node = object->GetNode();
  if (!node)
    return nullptr;
  auto* element = DynamicTo<Element>(node);
  if (!element)
    element = FlatTreeTraversal::ParentElement(*node);

  while (element) {
    if (element->IsInertRoot())
      return AXObjectCache().Get(element);
    element = FlatTreeTraversal::ParentElement(*element);
  }

  return nullptr;
}

bool AXObject::IsDescendantOfDisabledNode() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_descendant_of_disabled_node_;
}

bool AXObject::ComputeIsDescendantOfDisabledNode() {
  if (IsA<Document>(GetNode()))
    return false;

  bool disabled = false;
  if (AriaBooleanAttribute(html_names::kAriaDisabledAttr, &disabled)) {
    return disabled;
  }

  if (AXObject* parent = ParentObject()) {
    return parent->IsDescendantOfDisabledNode() || parent->IsDisabled();
  }

  return false;
}

bool AXObject::IsExcludedByFormControlsFilter() const {
  AXObjectCacheImpl& cache = AXObjectCache();
  const ui::AXMode& mode = cache.GetAXMode();

  bool filter_to_form_controls =
      mode.HasExperimentalFlags(ui::AXMode::kExperimentalFormControls);

  if (!filter_to_form_controls) {
    return false;
  }

  // Nodes at which another tree has been stitched should always remain in the
  // tree so that browser code can traverse through them to the child tree.
  if (child_tree_id_) {
    return false;
  }

  // Filter out elements hidden via style.
  if (IsHiddenViaStyle()) {
    return true;
  }

  // Keep control elements.
  if (IsControl()) {
    return false;
  }

  // Keep any relevant contextual labels on form controls.
  // TODO (aldietz): this check could have further nuance to filter out
  // irrelevant text. Potential future adjustments include: Trim out text nodes
  // with length > 40 (or some threshold), as these are likely to be prose. Trim
  // out text nodes that would end up as siblings of other text in the reduced
  // tree.
  if (RoleValue() == ax::mojom::blink::Role::kStaticText) {
    return false;
  }

  // Keep generic container shadow DOM nodes inside text controls like input
  // elements.
  if (RoleValue() == ax::mojom::blink::Role::kGenericContainer &&
      EnclosingTextControl(GetNode())) {
    return false;
  }

  // Keep focusable elements to avoid breaking focus events.
  if (CanSetFocusAttribute()) {
    return false;
  }

  // Keep elements with rich text editing.
  // This is an O(1) check that will return true for matching elements and
  // avoid the O(n) IsEditable() check below.
  // It is unlikely that password managers will need elements within
  // the content editable, but if we do then consider adding a check
  // for IsEditable(). IsEditable() is O(n) where n is the number of
  // ancestors so it should only be added if necessary.
  // We may also consider caching IsEditable value so that the
  // HasContentEditableAttributeSet call can potentially be folded into a single
  // IsEditable call. See crbug/1420757.
  if (HasContentEditableAttributeSet()) {
    return false;
  }

  return true;
}

bool AXObject::ComputeIsIgnoredButIncludedInTree() {
  CHECK(!IsDetached());

  // If an inline text box is ignored, it is never included in the tree.
  if (IsAXInlineTextBox()) {
    return false;
  }

  if (AXObjectCache().IsAriaOwned(this) || HasARIAOwns(GetElement())) {
    // Always include an aria-owned object. It must be a child of the
    // element with aria-owns.
    return true;
  }

  const Node* node = GetNode();

  if (!node) {
    if (GetLayoutObject()) {
      // All AXObjects created for anonymous layout objects are included.
      // See IsLayoutObjectRelevantForAccessibility() in
      // ax_object_cache_impl.cc.
      // - Visible content, such as text, images and quotes (can't have
      // children).
      // - Any containers inside of pseudo-elements.
      DCHECK(GetLayoutObject()->IsAnonymous())
          << "Object has layout object but no node and is not anonymous: "
          << GetLayoutObject();
    } else {
      NOTREACHED();
    }
    // By including all of these objects in the tree, it is ensured that
    // ClearChildren() will be able to find these children and detach them
    // from their parent.
    return true;
  }

  // Labels are sometimes marked ignored, to prevent duplication when the AT
  // reads the label and the control it labels (see
  // AXNodeObject::IsRedundantLabel), but we will need them to calculate the
  // name of the control.
  if (IsA<HTMLLabelElement>(node)) {
    return true;
  }

  Node* dom_parent = NodeTraversal::Parent(*node);
  if (!dom_parent) {
    // No DOM parent, so will not be able to reach this node when cleaning uo
    // subtrees.
    return true;
  }

  if (dom_parent != LayoutTreeBuilderTraversal::Parent(*node)) {
    // If the flat tree parent from LayoutTreeBuilderTraversal is different than
    // the DOM parent, we must include this object in the tree so that we can
    // find it using cached children_. Otherwise, the object could be missed --
    // LayoutTreeBuilderTraversal and its cousin FlatTreeTraversal cannot
    // always be safely used, e.g. when slot assignments are pending.
    return true;
  }

  // Include children of <label> elements, for accname calculation purposes.
  // <span>s are ignored because they are considered uninteresting. Do not add
  // them back inside labels.
  if (IsA<HTMLLabelElement>(dom_parent) && !IsA<HTMLSpanElement>(node)) {
    return true;
  }

  // Always include the children of a map.
  if (IsA<HTMLMapElement>(dom_parent)) {
    return true;
  }

  // Necessary to calculate the accessible description of a ruby node.
  if (dom_parent->HasTagName(html_names::kRtTag)) {
    return true;
  }

  if (const Element* owner = node->OwnerShadowHost()) {
    // The ignored state of media controls can change without a layout update.
    // Keep them in the tree at all times so that the serializer isn't
    // accidentally working with unincluded nodes, which is not allowed.
    if (IsA<HTMLMediaElement>(owner)) {
      return true;
    }

    // Do not include ignored descendants of an <input type="search"> or
    // <input type="number"> because they interfere with AXPosition code that
    // assumes a plain input field structure. Specifically, due to the ignored
    // node at the end of textfield, end of editable text position will get
    // adjusted to past text field or caret moved events will not be emitted for
    // the final offset because the associated tree position. In some cases
    // platform accessibility code will instead incorrectly emit a caret moved
    // event for the AXPosition which follows the input.
    if (IsA<HTMLInputElement>(owner) &&
        (DynamicTo<HTMLInputElement>(owner)->FormControlType() ==
             FormControlType::kInputSearch ||
         DynamicTo<HTMLInputElement>(owner)->FormControlType() ==
             FormControlType::kInputNumber)) {
      return false;
    }
  }

  Element* element = GetElement();

  // Include all pseudo element content. Any anonymous subtree is included
  // from above, in the condition where there is no node.
  if (element && element->IsPseudoElement()) {
    return true;
  }

  // Include all parents of ::before/::after/::marker/::scroll-marker-group
  // pseudo elements to help ClearChildren() find all children, and assist
  // naming computation. It is unnecessary to include a rule for other types of
  // pseudo elements: Specifically, ::first-letter/::backdrop are not visited by
  // LayoutTreeBuilderTraversal, and cannot be in the tree, therefore do not add
  // a special rule to include their parents.
  if (element && (element->GetPseudoElement(kPseudoIdBefore) ||
                  element->GetPseudoElement(kPseudoIdAfter) ||
                  element->GetPseudoElement(kPseudoIdMarker) ||
                  element->GetPseudoElement(kPseudoIdScrollNextButton) ||
                  element->GetPseudoElement(kPseudoIdScrollPrevButton) ||
                  element->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore) ||
                  element->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter) ||
                  element->GetPseudoElement(kPseudoIdScrollMarker))) {
    return true;
  }

  if (IsUsedForLabelOrDescription()) {
    // We identify nodes in display none subtrees, or nodes that are display
    // locked, because they lack a layout object.
    if (!GetLayoutObject()) {
      // Datalists and options inside them will never a layout object. They
      // match the condition above, but we don't need them for accessible
      // naming nor have any other use in the accessibility tree, so we exclude
      // them specifically. What's more, including them breaks the browser test
      // SelectToSpeakKeystrokeSelectionTest.textFieldWithComboBoxSimple.
      // Selection and position code takes into account ignored nodes, and it
      // looks like including ignored nodes for datalists and options is totally
      // unexpected, making selections misbehave.
      if (!IsA<HTMLDataListElement>(node) && !IsA<HTMLOptionElement>(node)) {
        return true;
      }
    } else {  // GetLayoutObject() != nullptr.
      // We identify hidden or collapsed nodes by their associated style values.
      if (IsHiddenViaStyle()) {
        return true;
      }

      // Allow the browser side ax tree to access "aria-hidden" nodes.
      // This is useful for APIs that return the node referenced by
      // aria-labeledby and aria-describedby.
      // Exception: iframes. Do not expose aria-hidden iframes, where
      // there is no possibility for the content within to know it's
      // aria-hidden, and therefore the entire iframe must be hidden from the
      // outer document.
      if (IsAriaHidden()) {
        return !IsEmbeddingElement();
      }
    }
  }

  if (IsExcludedByFormControlsFilter()) {
    return false;
  }

  if (!element)
    return false;

  // Include the <html> element in the accessibility tree, which will be
  // "ignored".
  if (IsA<HTMLHtmlElement>(element))
    return true;

  // Keep the internal accessibility tree consistent for videos which lack
  // a player and also inner text.
  if (RoleValue() == ax::mojom::blink::Role::kVideo ||
      RoleValue() == ax::mojom::blink::Role::kAudio) {
    return true;
  }

  // Expose menus even if hidden, enabling event generation as they open.
  if (RoleValue() == ax::mojom::blink::Role::kMenu) {
    return true;
  }

  // Always pass through Line Breaking objects, this is necessary to
  // detect paragraph edges, which are defined as hard-line breaks.
  if (IsLineBreakingObject() && IsVisible()) {
    return true;
  }

  // Ruby annotations (i.e. <rt> elements) need to be included because they are
  // used for calculating an accessible description for the ruby. We explicitly
  // exclude from the tree any <rp> elements, even though they also have the
  // kRubyAnnotation role, because such elements provide fallback content for
  // browsers that do not support ruby. Hence, their contents should not be
  // included in the accessible description, unless another condition in this
  // method decides to keep them in the tree for some reason.
  if (element->HasTagName(html_names::kRtTag)) {
    return true;
  }

  // Keep table-related elements in the tree, because it's too easy for them
  // to in and out of being ignored based on their ancestry, as their role
  // can depend on several levels up in the hierarchy.
  if (IsA<HTMLTableElement>(element) ||
      element->HasTagName(html_names::kTbodyTag) ||
      IsA<HTMLTableRowElement>(element) || IsA<HTMLTableCellElement>(element)) {
    return tru
"""


```
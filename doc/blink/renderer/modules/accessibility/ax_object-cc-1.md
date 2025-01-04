Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `ax_object.cc`. I need to identify the key actions and responsibilities of this code, focusing on how it relates to accessibility, and highlight any connections to JavaScript, HTML, or CSS. I also need to look for examples of logical reasoning, potential user errors, and how a user action might lead to this code being executed. Finally, I need to remember that this is part 2 of a 10-part explanation and keep the summary concise.

Here's a plan:
1. **Identify Core Functionalities:**  Focus on the methods and data members being manipulated. The code seems to handle object attachment, detachment, parent management, and some property updates.
2. **Relate to Web Technologies:** Analyze how these functionalities connect to HTML elements, CSS styles, and potentially JavaScript interactions that modify the DOM.
3. **Look for Logic and Assumptions:** Examine the `DCHECK` statements and conditional logic for implicit assumptions about the state of the AXObject and its relationships.
4. **Identify Potential Errors:** Consider scenarios where the assumptions might be violated, leading to crashes or incorrect behavior.
5. **Trace User Actions:**  Think about common user interactions (like page navigation, content manipulation) that could trigger the code.
6. **Summarize Key Functions:**  Condense the findings into a concise summary for part 2.
Based on the provided code snippet from `blink/renderer/modules/accessibility/ax_object.cc`, here's a summary of its functionality:

**Core Functionalities:**

This part of `AXObject` class primarily deals with the **lifecycle and structural relationships** of accessibility objects within the Blink rendering engine. It focuses on:

* **Attachment and Detachment:**  The `Attach()` method establishes the parent-child relationship between AXObjects, ensuring consistency and triggering updates to cached values. The `Detach()` method breaks these relationships, cleaning up references and preventing dangling pointers when an object is no longer needed in the accessibility tree.
* **Parent Management:** The code includes methods like `SetParent()`, `ComputeParent()`, and `ComputeParentOrNull()` responsible for determining and setting the parent of an AXObject. This involves logic to handle various DOM structures, including shadow DOM, image maps, and customizable select elements.
* **Tree Integrity:**  Several `DCHECK` statements enforce invariants and assumptions about the accessibility tree structure, such as ensuring a parent exists (except for the root), that parents can have children when children are added, and that objects aren't detached during cached value updates.
* **ARIA Attribute Handling:**  The code includes functions like `HasAriaAttribute()`, `IsAriaAttributeTrue()`, `AriaBooleanAttribute()`, `AriaIntAttribute()`, `AriaFloatAttribute()`, and `AriaTokenAttribute()` to retrieve and interpret ARIA attributes defined on HTML elements.
* **Serialization (Partial):** The `Serialize()` method, along with its helper functions like `SerializeBoundingBoxAttributes()`, `SerializeColorAttributes()`, and `SerializeChildTreeID()`, begins the process of converting the internal state of an `AXObject` into a representation suitable for communication with assistive technologies or other parts of the system. This includes properties like role, ID, bounding box, colors, and child tree identifiers.

**Relationships with JavaScript, HTML, and CSS:**

* **HTML:**
    * **Attachment and Parentage:** When a new HTML element is added to the DOM (through JavaScript or initial page load), a corresponding `AXObject` might be created and attached to its parent `AXObject`. The `ComputeParent()` logic relies heavily on traversing the HTML DOM structure to determine the correct accessibility parent. For example, the code explicitly handles the parentage of elements within `<map>` elements and customizable `<select>` elements, which have specific HTML structures.
    * **ARIA Attributes:**  The functions for handling ARIA attributes directly interact with attributes defined in the HTML. For example, `IsAriaAttributeTrue(*GetElement(), attribute)` checks if a specific ARIA attribute like `aria-hidden` is set to "true" (or any value other than "false" or "undefined") on the corresponding HTML element.
    * **Serialization:** The `Serialize()` method extracts information directly related to HTML, such as the HTML ID (`SerializeHTMLId()`) and potentially other HTML attributes for specific assistive technologies (`SerializeHTMLNonStandardAttributesForJAWS()`).
* **CSS:**
    * **Visibility:** The `IsVisible()` check, used in `Serialize()` and other methods, indirectly relies on CSS `display` and `visibility` properties. An element hidden via CSS will likely result in its corresponding `AXObject` being marked as invisible.
    * **Bounding Box:**  `SerializeBoundingBoxAttributes()` calculates the position and size of the `AXObject` based on the rendered layout of the corresponding HTML element, which is heavily influenced by CSS.
    * **Colors:** `SerializeColorAttributes()` retrieves the computed background and text colors, which are derived from CSS styles.
* **JavaScript:**
    * **DOM Manipulation:** JavaScript code that adds, removes, or modifies HTML elements can trigger the creation, destruction, or restructuring of the accessibility tree, leading to calls to `Attach()`, `Detach()`, and `SetParent()`.
    * **ARIA Attribute Updates:** JavaScript can dynamically change ARIA attributes on HTML elements. The `AXObject` will need to update its cached values based on these changes, which is handled by mechanisms triggered when the underlying HTML changes.

**Examples of Logical Reasoning (Assumptions and Invariants):**

* **Assumption:**  All `AXObject` instances, once created and attached, should belong to a document. This is enforced by `DCHECK(GetDocument()) << "All AXObjects must have a document: " << this;` in `Attach()`.
    * **Hypothetical Input:** An `AXObject` is created without being associated with a `Document`.
    * **Output:** The `DCHECK` would fail, likely causing a program termination in debug builds.
* **Invariant:**  A parent `AXObject` must be able to have children before a child is attached to it. This is checked by `DCHECK(!parent_ || parent_->CanHaveChildren())` in `Attach()`.
    * **Hypothetical Input:** An attempt is made to attach an `AXObject` as a child to a parent whose role inherently doesn't allow children (e.g., a `kImage`).
    * **Output:** The `DCHECK` would fail.

**Examples of User or Programming Common Usage Errors:**

* **Attaching to a Detached Parent:**  A common programming error could be attempting to set the parent of an `AXObject` to another `AXObject` that has already been detached from the tree.
    * **Code Example:**
      ```c++
      AXObject* child = ...;
      AXObject* parent = ...;
      parent->Detach();
      child->SetParent(parent); // Error: parent is detached
      ```
    * **Consequence:** The `DCHECK(!new_parent->IsDetached())` in `SetParent()` would trigger, indicating an error.
* **Incorrectly Computing Parentage:** If the logic in `ComputeParent()` is flawed or doesn't account for a specific edge case in the DOM structure, it might assign the wrong parent to an `AXObject`. This can lead to an incorrect accessibility tree representation.
    * **Scenario:** A complex custom component with a non-standard DOM structure might confuse the parent computation logic.
    * **Debugging:** Examining the output of `ToString()` for the incorrectly parented object and its computed parent, as well as stepping through the `ComputeParent()` logic, can help identify the issue.

**User Operation Steps Leading Here (Debugging Clues):**

1. **Page Load:** When a web page is loaded, the rendering engine parses the HTML and CSS, creates the DOM tree, and then builds the accessibility tree. This involves creating `AXObject` instances and attaching them, leading to calls to `Attach()`.
2. **Dynamic Content Updates:**  User interactions or JavaScript code can dynamically modify the DOM (e.g., adding a new element, removing an element, changing attributes).
    * **Adding an Element:** If JavaScript appends a new `<div>` to the DOM, a corresponding `AXObject` will be created, and `Attach()` will be called to link it to its parent's `AXObject`.
    * **Removing an Element:** If JavaScript removes an element, the `Detach()` method will be called on its corresponding `AXObject` and its descendants to clean up the accessibility tree.
3. **ARIA Attribute Changes:** If a user interacts with a widget, or JavaScript updates ARIA attributes in response to user actions, the `AXObject` will need to update its internal state. This might trigger updates to cached ARIA values.
4. **Inspecting Accessibility Tree:** Developers using browser accessibility tools to inspect the accessibility tree will trigger the serialization process (`Serialize()`) to display the properties of `AXObject` instances.

**Summary of Functionality (Part 2):**

This portion of the `AXObject` code is fundamentally responsible for managing the **creation, destruction, and hierarchical relationships** of accessibility objects within the Blink rendering engine. It ensures the **integrity of the accessibility tree**, correctly determines **parent-child relationships** based on the underlying DOM structure, and provides mechanisms to **access and interpret ARIA attributes**. It also initiates the process of **serializing `AXObject` data** for external consumption, encompassing basic properties like bounding boxes and color information. This functionality is crucial for accurately representing the structure and semantics of a web page to assistive technologies.

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共10部分，请归纳一下它的功能

"""
                   << GetNode() << '\n'
                             << GetLayoutObject();
  // The parent cannot have children. This object must be destroyed.
  DCHECK(!parent_ || parent_->CanHaveChildren())
      << "Tried to set a parent that cannot have children:" << "\n* Parent = "
      << parent_ << "\n* Child = " << this;
#endif

  children_dirty_ = true;

  UpdateCachedAttributeValuesIfNeeded(false);

  DCHECK(GetDocument()) << "All AXObjects must have a document: " << this;

  // Set the parent again, this time via SetParent(), so that all related checks
  // and calls occur now that we have the role and updated cached values.
  SetParent(parent_);
}

void AXObject::Detach() {
#if DCHECK_IS_ON()
  DCHECK(!is_updating_cached_values_)
      << "Don't detach in the middle of updating cached values: " << this;
  DCHECK(!IsDetached());
#endif
  // Prevents LastKnown*() methods from returning the wrong values.
  cached_is_ignored_ = true;
  cached_is_ignored_but_included_in_tree_ = false;

#if defined(AX_FAIL_FAST_BUILD)
  SANITIZER_CHECK(ax_object_cache_);
  SANITIZER_CHECK(!ax_object_cache_->IsFrozen())
      << "Do not detach children while the tree is frozen, in order to avoid "
         "an object detaching itself in the middle of computing its own "
         "accessibility properties.";
  SANITIZER_CHECK(!is_adding_children_) << this;
#endif

#if !defined(NDEBUG)
  // Facilitates debugging of detached objects by providing info on what it was.
  if (!ax_object_cache_->HasBeenDisposed()) {
    detached_object_debug_info_ = ToString();
  }
#endif

  if (AXObjectCache().HasBeenDisposed()) {
    // Shutting down a11y, just clear the children.
    children_.clear();
  } else {
    // Clear children and call DetachFromParent() on them so that
    // no children are left with dangling pointers to their parent.
    ClearChildren();
  }

  parent_ = nullptr;
  ax_object_cache_ = nullptr;
  children_dirty_ = false;
  child_cached_values_need_update_ = false;
  cached_values_need_update_ = false;
  has_dirty_descendants_ = false;
  id_ = 0;
}

bool AXObject::IsDetached() const {
  return !ax_object_cache_;
}

bool AXObject::IsRoot() const {
  return GetNode() && GetNode() == &AXObjectCache().GetDocument();
}

void AXObject::SetParent(AXObject* new_parent) {
  CHECK(!AXObjectCache().IsFrozen());
#if DCHECK_IS_ON()
  if (!new_parent && !IsRoot()) {
    std::ostringstream message;
    message << "Parent cannot be null, except at the root."
            << "\nThis: " << this
            << "\nDOM parent chain , starting at |this->GetNode()|:";
    int count = 0;
    for (Node* node = GetNode(); node;
         node = GetParentNodeForComputeParent(AXObjectCache(), node)) {
      message << "\n"
              << (++count) << ". " << node
              << "\n  LayoutObject=" << node->GetLayoutObject();
      if (AXObject* obj = AXObjectCache().Get(node))
        message << "\n  " << obj;
      if (!node->isConnected()) {
        break;
      }
    }
    NOTREACHED() << message.str();
  }

  if (new_parent) {
    DCHECK(!new_parent->IsDetached())
        << "Cannot set parent to a detached object:" << "\n* Child: " << this
        << "\n* New parent: " << new_parent;

    DCHECK(!IsAXInlineTextBox() ||
           ui::CanHaveInlineTextBoxChildren(new_parent->RoleValue()))
        << "Unexpected parent of inline text box: " << new_parent->RoleValue();
  }

  // Check to ensure that if the parent is changing from a previous parent,
  // that |this| is not still a child of that one.
  // This is similar to the IsParentUnignoredOf() check in
  // BlinkAXTreeSource, but closer to where the problem would occur.
  if (parent_ && new_parent != parent_ && !parent_->NeedsToUpdateChildren() &&
      !parent_->IsDetached()) {
    for (const auto& child : parent_->ChildrenIncludingIgnored()) {
      DUMP_WILL_BE_CHECK(child != this)
          << "Previous parent still has |this| child:\n"
          << this << " should be a child of " << new_parent << " not of "
          << parent_;
    }
    // TODO(accessibility) This should not be reached unless this method is
    // called on an AXObject of role kRootWebArea or when the parent's
    // children are dirty, aka parent_->NeedsToUpdateChildren());
    // Ideally we will also ensure |this| is in the parent's children now, so
    // that ClearChildren() can later find the child to detach from the parent.
  }

#endif
  parent_ = new_parent;
  if (AXObjectCache().IsUpdatingTree()) {
    // If updating tree, tell the newly included parent to iterate through
    // all of its children to look for the has dirty descendants flag.
    // However, we do not set the flag on higher ancestors since
    // they have already been walked by the tree update loop.
    if (AXObject* ax_included_parent = ParentObjectIncludedInTree()) {
      ax_included_parent->SetHasDirtyDescendants(true);
    }
  } else {
    SetAncestorsHaveDirtyDescendants();
  }
}

bool AXObject::IsMissingParent() const {
  // This method should not be called on a detached object.
  if (IsDetached()) {
    // TODO(a11y): Upgrade to NOTREACHED once all hits of
    // crbug.com/337178753 have been addressed.
    DUMP_WILL_BE_NOTREACHED()
        << "Checking for parent on detached object: " << this;
    return false;
  }

  if (!parent_) {
    // Do not attempt to repair the ParentObject() of a validation message
    // object, because hidden ones are purposely kept around without being in
    // the tree, and without a parent, for potential later reuse.
    bool is_missing = !IsRoot();
    DUMP_WILL_BE_CHECK(!is_missing || !AXObjectCache().IsFrozen())
        << "Should not have missing parent in frozen tree: " << this;
    return is_missing;
  }

  if (parent_->IsDetached()) {
    DUMP_WILL_BE_CHECK(!AXObjectCache().IsFrozen())
        << "Should not have detached parent in frozen tree: " << this;
    return true;
  }

  return false;
}

// In many cases, ComputeParent() is not called, because the parent adding
// the parent adding the child will pass itself into AXObjectCacheImpl.
// ComputeParent() is still necessary because some parts of the code,
// especially web tests, result in AXObjects being created in the middle of
// the tree before their parents are created.
// TODO(accessibility) Consider forcing all ax objects to be created from
// the top down, eliminating the need for ComputeParent().
AXObject* AXObject::ComputeParent() const {
  AXObject* ax_parent = ComputeParentOrNull();

  CHECK(!ax_parent || !ax_parent->IsDetached())
      << "Computed parent should never be detached:" << "\n* Child: " << this
      << "\n* Parent: " << ax_parent;

  return ax_parent;
}

// Same as ComputeParent, but without the extra check for valid parent in the
// end. This is for use in RestoreParentOrPrune.
AXObject* AXObject::ComputeParentOrNull() const {
  CHECK(!IsDetached());

  CHECK(GetNode() || GetLayoutObject())
      << "Can't compute parent on AXObjects without a backing Node or "
         "LayoutObject. Objects without those must set the "
         "parent in Init(), |this| = "
      << RoleValue();

  AXObject* ax_parent = nullptr;
  if (IsAXInlineTextBox()) {
    NOTREACHED()
        << "AXInlineTextBox box tried to compute a new parent, but they are "
           "not allowed to exist even temporarily without a parent, as their "
           "existence depends on the parent text object. Parent text = "
        << AXObjectCache().Get(GetNode());
  } else if (AXObjectCache().IsAriaOwned(this)) {
    ax_parent = AXObjectCache().ValidatedAriaOwner(this);
  }
  if (!ax_parent) {
    ax_parent = ComputeNonARIAParent(AXObjectCache(), GetNode());
  }

  return ax_parent;
}

// static
Node* AXObject::GetParentNodeForComputeParent(AXObjectCacheImpl& cache,
                                              Node* node) {
  if (!node || !node->isConnected()) {
    return nullptr;
  }

  // A document's parent should be the page popup owner, if any, otherwise null.
  if (auto* document = DynamicTo<Document>(node)) {
    LocalFrame* frame = document->GetFrame();
    DCHECK(frame);
    return frame->PagePopupOwner();
  }

  // Avoid a CHECK that disallows calling LayoutTreeBuilderTraversal::Parent() with a shadow root node.
  if (node->IsShadowRoot()) {
    return node->OwnerShadowHost();
  }

  // Use LayoutTreeBuilderTraversal::Parent(), which handles pseudo content.
  // This can return nullptr for a node that is never visited by
  // LayoutTreeBuilderTraversal's child traversal. For example, while an element
  // can be appended as a <textarea>'s child, it is never visited by
  // LayoutTreeBuilderTraversal's child traversal. Therefore, returning null in
  // this case is appropriate, because that child content is not attached to any
  // parent as far as rendering or accessibility are concerned.
  // Whenever null is returned from this function, then a parent cannot be
  // computed, and when a parent is not provided or computed, the accessible
  // object will not be created.
  Node* parent = LayoutTreeBuilderTraversal::Parent(*node);

  // The parent of a customizable select's popup is the select.
  if (IsA<HTMLDataListElement>(node)) {
    if (auto* select = DynamicTo<HTMLSelectElement>(node->OwnerShadowHost())) {
      if (node == select->PopoverForAppearanceBase()) {
        return select;
      }
    }
  }

  // For the content of a customizable select, the parent must be the element
  // assigned the role of kMenuListPopup. To accomplish this, it is necessary to
  // adapt to unusual DOM structure. If no parent, or the parent has a <select>
  // shadow host, then the actual parent should be the <select>.
  // TODO(aleventhal, jarhar): try to simplify this code. @jarhar wrote in code
  // review: "I don't think that a UA <slot> will ever get returned by
  // LayoutTreeBuilderTraversal::Parent. In this case, I think
  // LayoutTreeBuilderTraversal::Parent should just return the <select>."

  HTMLSelectElement* owner_select = nullptr;
  if (IsA<HTMLSlotElement>(parent) && parent->IsInUserAgentShadowRoot()) {
    owner_select = DynamicTo<HTMLSelectElement>(parent->OwnerShadowHost());
  } else if (!parent) {
    owner_select = DynamicTo<HTMLSelectElement>(NodeTraversal::Parent(*node));
  }
  if (owner_select && owner_select->IsAppearanceBasePicker()) {
    // Return the popup's <datalist> element.
    return owner_select->PopoverForAppearanceBase();
  }

  // No parent: this can occur when elements are not assigned a slot.
  if (!parent) {
    return nullptr;
  }

  // Descendants of pseudo elements must only be created by walking the tree via
  // AXNodeObject::AddChildren(), which already knows the parent. Therefore, the
  // parent must not be computed. This helps avoid situations with certain
  // elements where there is asymmetry between what considers this a child vs
  // what the this considers its parent. An example of this kind of situation is
  // a ::first-letter within a ::before.
  if (node->GetLayoutObject() && node->GetLayoutObject()->Parent() &&
      node->GetLayoutObject()->Parent()->IsPseudoElement()) {
    return nullptr;
  }

  HTMLMapElement* map_element = DynamicTo<HTMLMapElement>(parent);
  if (map_element) {
    // For a <map>, return the <img> associated with it. This is necessary
    // because the AX tree is flat, adding image map children as children of the
    // <img>, whereas in the DOM they are actually children of the <map>.
    // Therefore, if a node is a DOM child of a map, its AX parent is the image.
    // This code double checks that the image actually uses the map.
    HTMLImageElement* image_element = map_element->ImageElement();
    return AXObject::GetMapForImage(image_element) == map_element
               ? image_element
               : nullptr;
  }

  return CanComputeAsNaturalParent(parent) ? parent : nullptr;
}

// static
bool AXObject::CanComputeAsNaturalParent(Node* node) {
  if (IsA<Document>(node)) {
    return true;
  }

  DCHECK(IsA<Element>(node)) << "Expected element: " << node;

  // An image cannot be the natural DOM parent of another AXObject, it can only
  // have <area> children, which are from another part of the DOM tree.
  if (IsA<HTMLImageElement>(node)) {
    return false;
  }

  return CanHaveChildren(*To<Element>(node));
}

// static
bool AXObject::CanHaveChildren(Element& element) {
  // Image map parent-child relationships work as follows:
  // - The image is the parent
  // - The DOM children of the associated <map> are the children
  // This is accomplished by having GetParentNodeForComputeParent() return the
  // <img> instead of the <map> for the map's children.
  if (IsA<HTMLMapElement>(element)) {
    return false;
  }

  if (IsA<HTMLImageElement>(element)) {
    return GetMapForImage(&element);
  }

  // Placeholder gets exposed as an attribute on the input accessibility node,
  // so there's no need to add its text children. Placeholder text is a separate
  // node that gets removed when it disappears, so this will only be present if
  // the placeholder is visible.
  if (Element* host = element.OwnerShadowHost()) {
    if (auto* ancestor_input = DynamicTo<TextControlElement>(host)) {
      if (ancestor_input->PlaceholderElement() == &element) {
        // |element| is a placeholder.
        return false;
      }
    }
  }

  if (IsA<HTMLBRElement>(element)) {
    // Normally, a <br> is allowed to have a single inline text box child.
    // However, a <br> element that has DOM children can occur only if a script
    // adds the children, and Blink will not render those children. This is an
    // obscure edge case that should only occur during fuzzing, but to maintain
    // tree consistency and prevent DCHECKs, AXObjects for <br> elements are not
    // allowed to have children if there are any DOM children at all.
    return !element.hasChildren();
  }

  if (IsA<HTMLHRElement>(element)) {
    return false;
  }

  if (auto* input = DynamicTo<HTMLInputElement>(&element)) {
    // False for checkbox, radio and range.
    return !input->IsCheckable() &&
           input->FormControlType() != FormControlType::kInputRange;
  }

  // For consistency with the past, options with a single text child are leaves.
  // However, options can now sometimes have interesting children, for
  // a <select> menulist that uses appearance:base-select.
  if (auto* option = DynamicTo<HTMLOptionElement>(element)) {
    return option->OwnerSelectElement() &&
           option->OwnerSelectElement()->IsAppearanceBasePicker() &&
           !option->HasOneTextChild();
  }

  if (IsA<HTMLProgressElement>(element)) {
    return false;
  }

  return true;
}

// static
HTMLMapElement* AXObject::GetMapForImage(Node* image) {
  if (!IsA<HTMLImageElement>(image))
    return nullptr;

  LayoutImage* layout_image = DynamicTo<LayoutImage>(image->GetLayoutObject());
  if (!layout_image)
    return nullptr;

  HTMLMapElement* map_element = layout_image->ImageMap();
  if (!map_element)
    return nullptr;

  // Don't allow images that are actually children of a map, as this could lead
  // to an infinite loop, where the descendant image points to the ancestor map,
  // yet the descendant image is being returned here as an ancestor.
  if (Traversal<HTMLMapElement>::FirstAncestor(*image))
    return nullptr;

  // The image has an associated <map> and does not have a <map> ancestor.
  return map_element;
}

// static
AXObject* AXObject::ComputeNonARIAParent(AXObjectCacheImpl& cache,
                                         Node* current_node) {
  if (!current_node) {
    return nullptr;
  }
  Node* parent_node = GetParentNodeForComputeParent(cache, current_node);
  return cache.Get(parent_node);
}

#if DCHECK_IS_ON()
std::string AXObject::GetAXTreeForThis() const {
  return TreeToStringWithMarkedObjectHelper(AXObjectCache().Root(), this);
}

void AXObject::ShowAXTreeForThis() const {
  DLOG(INFO) << "\n" << GetAXTreeForThis();
}

#endif

// static
bool AXObject::HasAriaAttribute(const Element& element,
                                const QualifiedName& attribute) {
  if (element.FastHasAttribute(attribute)) {
    return true;
  }

  const ElementInternals* internals = element.GetElementInternals();
  return internals && internals->HasAttribute(attribute);
}

bool AXObject::HasAriaAttribute(const QualifiedName& attribute) const {
  Element* element = GetElement();
  if (!element) {
    return false;
  }
  return HasAriaAttribute(*element, attribute);
}

// static
const AtomicString& AXObject::AriaAttribute(const Element& element,
                                            const QualifiedName& attribute) {
  const AtomicString& value = element.FastGetAttribute(attribute);
  if (!value.IsNull()) {
    return value;
  }
  return GetInternalsAttribute(element, attribute);
}

const AtomicString& AXObject::AriaAttribute(
    const QualifiedName& attribute) const {
  return GetElement() ? AriaAttribute(*GetElement(), attribute) : g_null_atom;
}

// static
bool AXObject::IsAriaAttributeTrue(const Element& element,
                                   const QualifiedName& attribute) {
  const AtomicString& value = AriaAttribute(element, attribute);
  return !value.empty() && !EqualIgnoringASCIICase(value, "undefined") &&
         !EqualIgnoringASCIICase(value, "false");
}

// ARIA attributes are true if they are not empty, "false" or "undefined".
bool AXObject::IsAriaAttributeTrue(const QualifiedName& attribute) const {
  return GetElement() ? IsAriaAttributeTrue(*GetElement(), attribute) : false;
}

bool AXObject::AriaBooleanAttribute(const QualifiedName& attribute,
                                    bool* out_value) const {
  const AtomicString& value = AriaAttribute(attribute);
  if (value == g_null_atom || value.empty() ||
      EqualIgnoringASCIICase(value, "undefined")) {
    if (out_value) {
      *out_value = false;
    }
    return false;
  }
  if (out_value) {
    *out_value = !EqualIgnoringASCIICase(value, "false");
  }
  return true;
}

bool AXObject::AriaIntAttribute(const QualifiedName& attribute,
                                int32_t* out_value) const {
  const AtomicString& value = AriaAttribute(attribute);
  if (value == g_null_atom || value.empty()) {
    if (out_value) {
      *out_value = 0;
    }
    return false;
  }

  int int_value = value.ToInt();
  int value_if_less_than_1 = 1;

  if (attribute == html_names::kAriaSetsizeAttr) {
    // -1 is a special "indeterminate" value for aria-setsize.
    // However, any value that's not a positive number should be given the
    // intederminate treatment.
    value_if_less_than_1 = -1;
  } else if (attribute == html_names::kAriaPosinsetAttr ||
             attribute == html_names::kAriaLevelAttr) {
    value_if_less_than_1 = 1;
  } else {
    // For now, try to get the illegal attribute, but catch the error.
    NOTREACHED(base::NotFatalUntil::M133) << "Not an int attribute.";
  }

  if (out_value) {
    *out_value = int_value < 1 ? value_if_less_than_1 : int_value;
  }

  return true;
}

bool AXObject::AriaFloatAttribute(const QualifiedName& attribute,
                                  float* out_value) const {
  const AtomicString& value = AriaAttribute(attribute);
  if (value == g_null_atom) {
    if (out_value) {
      *out_value = 0.0;
    }
    return false;
  }

  if (out_value) {
    *out_value = value.ToFloat();
  }
  return true;
}

const AtomicString& AXObject::AriaTokenAttribute(
    const QualifiedName& attribute) const {
  DEFINE_STATIC_LOCAL(const AtomicString, undefined_value, ("undefined"));
  const AtomicString& value = AriaAttribute(attribute);
  if (attribute == html_names::kAriaAutocompleteAttr ||
      attribute == html_names::kAriaCheckedAttr ||
      attribute == html_names::kAriaCurrentAttr ||
      attribute == html_names::kAriaHaspopupAttr ||
      attribute == html_names::kAriaInvalidAttr ||
      attribute == html_names::kAriaLiveAttr ||
      attribute == html_names::kAriaOrientationAttr ||
      attribute == html_names::kAriaPressedAttr ||
      attribute == html_names::kAriaRelevantAttr ||
      attribute == html_names::kAriaSortAttr) {
    // These properties support a list of tokens, and "undefined"/"" is
    // equivalent to not setting the attribute.
    return value.empty() || value == undefined_value ? g_null_atom : value;
  }
  DCHECK(false) << "Not a token attribute. Use AriaFloatAttribute(), "
                   "AriaIntAttribute(), AriaStringAttribute(), etc. instead.";
  return value;
}

// static
const AtomicString& AXObject::GetInternalsAttribute(
    const Element& element,
    const QualifiedName& attribute) {
  const ElementInternals* internals = element.GetElementInternals();
  if (!internals) {
    return g_null_atom;
  }
  return internals->FastGetAttribute(attribute);
}

namespace {

void SerializeAriaNotificationAttributes(const AriaNotifications& notifications,
                                         ui::AXNodeData* node_data) {
  DCHECK(node_data);

  const auto size = notifications.Size();
  if (!size) {
    // Avoid serializing empty attribute lists if there are no notifications.
    return;
  }

  std::vector<std::string> announcements;
  std::vector<std::string> notification_ids;
  std::vector<int32_t> interrupt_properties;
  std::vector<int32_t> priority_properties;

  announcements.reserve(size);
  notification_ids.reserve(size);
  interrupt_properties.reserve(size);
  priority_properties.reserve(size);

  for (const auto& notification : notifications) {
    announcements.emplace_back(TruncateString(notification.Announcement()));
    notification_ids.emplace_back(
        TruncateString(notification.NotificationId()));
    interrupt_properties.emplace_back(
        static_cast<int32_t>(notification.Interrupt()));
    priority_properties.emplace_back(
        static_cast<int32_t>(notification.Priority()));
  }

  node_data->AddStringListAttribute(
      ax::mojom::blink::StringListAttribute::kAriaNotificationAnnouncements,
      announcements);
  node_data->AddStringListAttribute(
      ax::mojom::blink::StringListAttribute::kAriaNotificationIds,
      notification_ids);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kAriaNotificationInterruptProperties,
      interrupt_properties);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kAriaNotificationPriorityProperties,
      priority_properties);
}

}  // namespace

void AXObject::Serialize(ui::AXNodeData* node_data,
                         ui::AXMode accessibility_mode,
                         bool is_snapshot) const {
  // Reduce redundant ancestor chain walking for display lock computations.
  auto memoization_scope =
      DisplayLockUtilities::CreateLockCheckMemoizationScope();

  node_data->role = ComputeFinalRoleForSerialization();
  node_data->id = AXObjectID();

  PreSerializationConsistencyCheck();

  if (node_data->role == ax::mojom::blink::Role::kInlineTextBox) {
    SerializeInlineTextBox(node_data);
    return;
  }

  // Serialize a few things that we need even for ignored nodes.
  if (CanSetFocusAttribute()) {
    node_data->AddState(ax::mojom::blink::State::kFocusable);
  }

  bool is_visible = IsVisible();
  if (!is_visible)
    node_data->AddState(ax::mojom::blink::State::kInvisible);

  if (is_visible || CanSetFocusAttribute()) {
    // If the author applied the ARIA "textbox" role on something that is not
    // (currently) editable, this may be a read-only rich-text object. Or it
    // might just be bad authoring. Either way, we want to expose its
    // descendants, especially the interactive ones which might gain focus.
    bool is_non_atomic_textfield_root = IsARIATextField();

    // Preserve continuity in subtrees of richly editable content by including
    // richlyEditable state even if ignored.
    if (IsEditable()) {
      node_data->AddState(ax::mojom::blink::State::kEditable);
      if (!is_non_atomic_textfield_root)
        is_non_atomic_textfield_root = IsEditableRoot();

      if (IsRichlyEditable())
        node_data->AddState(ax::mojom::blink::State::kRichlyEditable);
    }
    if (is_non_atomic_textfield_root) {
      node_data->AddBoolAttribute(
          ax::mojom::blink::BoolAttribute::kNonAtomicTextFieldRoot, true);
    }
  }

  if (!accessibility_mode.has_mode(ui::AXMode::kPDFPrinting)) {
    SerializeBoundingBoxAttributes(*node_data);
  }

  if (accessibility_mode.has_mode(ui::AXMode::kScreenReader)) {
    // TODO(accessibility) We serialize these even on ignored nodes, in order
    // for the browser side to compute inherited colors for descendants, but we
    // do not ensure that elements that change foreground/background color are
    // included in the tree. Could this lead to errors?
    // See All/DumpAccess*.AccessibilityCSSBackgroundColorTransparent/blink.
    SerializeColorAttributes(node_data);  // Blends using all nodes' values.
  }

  if (accessibility_mode.has_mode(ui::AXMode::kScreenReader) ||
      accessibility_mode.has_mode(ui::AXMode::kPDFPrinting)) {
    SerializeLangAttribute(node_data);  // Propagates using all nodes' values.
  }

  // Always try to serialize child tree ids.
  SerializeChildTreeID(node_data);

  // Return early. The following attributes are unnecessary for ignored nodes.
  // Exception: focusable ignored nodes are fully serialized, so that reasonable
  // verbalizations can be made if they actually receive focus.
  if (IsIgnored()) {
    node_data->AddState(ax::mojom::blink::State::kIgnored);
    if (!CanSetFocusAttribute()) {
      return;
    }
  }

  if (RoleValue() != ax::mojom::blink::Role::kStaticText) {
    // Needed on Android for testing frameworks.
    SerializeHTMLId(node_data);
  }

  SerializeUnignoredAttributes(node_data, accessibility_mode, is_snapshot);

  if (!accessibility_mode.has_mode(ui::AXMode::kScreenReader)) {
    // Return early. None of the following attributes are needed outside of
    // screen reader mode.
    return;
  }

  SerializeScreenReaderAttributes(node_data);

  if (accessibility_mode.has_mode(ui::AXMode::kPDFPrinting)) {
    // Return early. None of the following attributes are needed for PDFs.
    return;
  }

  if (LiveRegionRoot())
    SerializeLiveRegionAttributes(node_data);

  if (GetElement() && accessibility_mode.has_mode(ui::AXMode::kHTML)) {
    if (is_snapshot) {
      SerializeHTMLAttributesForSnapshot(node_data);
    } else {
      SerializeHTMLNonStandardAttributesForJAWS(node_data);
      // Serialize <input name> for use by password managers.
      if (auto* input = DynamicTo<HTMLInputElement>(GetNode())) {
        if (const AtomicString& input_name = input->GetName()) {
          TruncateAndAddStringAttribute(
              node_data, ax::mojom::blink::StringAttribute::kHtmlInputName,
              input_name);
        }
      }
    }
  }
  SerializeOtherScreenReaderAttributes(node_data);
  SerializeMathContent(node_data);
  SerializeAriaNotificationAttributes(
      AXObjectCache().RetrieveAriaNotifications(this), node_data);
}

void AXObject::SerializeBoundingBoxAttributes(ui::AXNodeData& dst) const {
  bool clips_children = false;
  PopulateAXRelativeBounds(dst.relative_bounds, &clips_children);
  if (clips_children) {
    dst.AddBoolAttribute(ax::mojom::blink::BoolAttribute::kClipsChildren, true);
  }

  if (IsLineBreakingObject()) {
    dst.AddBoolAttribute(ax::mojom::blink::BoolAttribute::kIsLineBreakingObject,
                         true);
  }
  gfx::Point scroll_offset = GetScrollOffset();
  AXObjectCache().SetCachedBoundingBox(AXObjectID(), dst.relative_bounds,
                                       scroll_offset.x(), scroll_offset.y());
}

static bool AXShouldIncludePageScaleFactorInRoot() {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_MAC)
  return true;
#else
  return false;
#endif
}

void AXObject::PopulateAXRelativeBounds(ui::AXRelativeBounds& bounds,
                                        bool* clips_children) const {
  AXObject* offset_container;
  gfx::RectF bounds_in_container;
  gfx::Transform container_transform;
  GetRelativeBounds(&offset_container, bounds_in_container, container_transform,
                    clips_children);
  bounds.bounds = bounds_in_container;
  if (offset_container && !offset_container->IsDetached())
    bounds.offset_container_id = offset_container->AXObjectID();

  if (AXShouldIncludePageScaleFactorInRoot() && IsRoot()) {
    const Page* page = GetDocument()->GetPage();
    container_transform.Scale(page->PageScaleFactor(), page->PageScaleFactor());
    container_transform.Translate(
        -page->GetVisualViewport().VisibleRect().origin().OffsetFromOrigin());
  }

  if (!container_transform.IsIdentity())
    bounds.transform = std::make_unique<gfx::Transform>(container_transform);
}

void AXObject::SerializeActionAttributes(ui::AXNodeData* node_data) const {
  if (CanSetValueAttribute())
    node_data->AddAction(ax::mojom::blink::Action::kSetValue);
  if (IsSlider()) {
    node_data->AddAction(ax::mojom::blink::Action::kDecrement);
    node_data->AddAction(ax::mojom::blink::Action::kIncrement);
  }
  if (IsUserScrollable()) {
    node_data->AddAction(ax::mojom::blink::Action::kScrollUp);
    node_data->AddAction(ax::mojom::blink::Action::kScrollDown);
    node_data->AddAction(ax::mojom::blink::Action::kScrollLeft);
    node_data->AddAction(ax::mojom::blink::Action::kScrollRight);
    node_data->AddAction(ax::mojom::blink::Action::kScrollForward);
    node_data->AddAction(ax::mojom::blink::Action::kScrollBackward);
  }
}

void AXObject::SerializeChildTreeID(ui::AXNodeData* node_data) const {
  // If a child tree has explicitly been stitched at this object via the
  // `ax::mojom::blink::Action::kStitchChildTree`, then override any child trees
  // coming from HTML.
  if (child_tree_id_) {
    node_data->AddChildTreeId(*child_tree_id_);
    return;
  }

  // If this is an HTMLFrameOwnerElement (such as an iframe), we may need to
  // embed the ID of the child frame.
  if (!IsEmbeddingElement()) {
    // TODO(crbug.com/1342603) Determine why these are firing in the wild and,
    // once fixed, turn into a DCHECK.
    SANITIZER_CHECK(!IsFrame(GetNode()))
        << "If this is an iframe, it should also be a child tree owner: "
        << this;
    return;
  }

  // Do not attach hidden child trees.
  if (!IsVisible()) {
    return;
  }

  auto* html_frame_owner_element = To<HTMLFrameOwnerElement>(GetElement());

  Frame* child_frame = html_frame_owner_element->ContentFrame();
  if (!child_frame) {
    // TODO(crbug.com/1342603) Determine why these are firing in the wild and,
    // once fixed, turn into a DCHECK.
    SANITIZER_CHECK(IsDisabled()) << this;
    return;
  }

  std::optional<base::UnguessableToken> child_token =
      child_frame->GetEmbeddingToken();
  if (!child_token)
    return;  // No child token means that the connection isn't ready yet.

  DCHECK_EQ(ChildCountIncludingIgnored(), 0)
      << "Children won't exist until the trees are stitched together in the "
         "browser process. A failure means that a child node was incorrectly "
         "considered relevant by AXObjectCacheImpl."
      << "\n* Parent: " << this
      << "\n* Frame owner: " << IsA<HTMLFrameOwnerElement>(GetNode())
      << "\n* Element src: "
      << GetElement()->FastGetAttribute(html_names::kSrcAttr)
      << "\n* First child: " << FirstChildIncludingIgnored();

  ui::AXTreeID child_tree_id = ui::AXTreeID::FromToken(child_token.value());
  node_data->AddChildTreeId(child_tree_id);
}

void AXObject::SerializeChooserPopupAttributes(ui::AXNodeData* node_data) const {
  AXObject* chooser_popup = ChooserPopup();
  if (!chooser_popup)
    return;

  int32_t chooser_popup_id = chooser_popup->AXObjectID();
  auto controls_ids = node_data->GetIntListAttribute(
      ax::mojom::blink::IntListAttribute::kControlsIds);
  controls_ids.push_back(chooser_popup_id);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kControlsIds, controls_ids);
}

void AXObject::SerializeColorAttributes(ui::AXNodeData* node_data) const {
  // Text attributes.
  if (RGBA32 bg_color = BackgroundColor()) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kBackgroundColor,
                               bg_color);
  }

  if (RGBA32 color = GetColor())
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kColor, color);
}

void AXObject::SerializeElementAttributes(ui::AXNodeData* node_data) const {
  Element* element = GetElement();
  if (!element)
    return;

  if (const AtomicString& class_name = element->GetClassAttribute()) {
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kClassName, class_name);
  }

  // Expose StringAttribute::kRole, which is used for the xml-rol
"""


```
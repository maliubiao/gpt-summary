Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ax_object_cache_impl.cc`. The summary should specifically address:

1. **Core Functions:** What does this code do?
2. **Relation to Web Technologies:** How does it interact with Javascript, HTML, and CSS?
3. **Logical Reasoning:**  Any examples of input and output based on the code's logic.
4. **Common Errors:**  What mistakes might users or programmers make related to this code?
5. **Debugging:** How would a user end up interacting with this code during debugging?
6. **Overall Purpose:** A concise summary of the code's role.

Let's break down the code section by section to identify key functionalities and connections to web technologies.

*   The code primarily handles attribute changes on DOM elements (`HandleAttributeChanged`).
*   It uses specific HTML attribute names (e.g., `aria-label`, `role`, `alt`, `href`).
*   It triggers actions based on these attribute changes, such as updating the accessibility tree, posting notifications, and marking elements as dirty.
*   It manages the lifecycle of a validation message object.
*   It deals with event listeners and their impact on accessibility.
*   It manages a serialization queue for accessibility updates.
*   It tracks dirty objects and schedules updates.

Now, let's consider each of the user's requirements in detail:

**1. Core Functions:** The code is responsible for updating the accessibility tree in response to changes in the DOM, particularly attribute modifications. It also handles validation messages and manages the serialization of accessibility information.

**2. Relation to Web Technologies:**

*   **HTML:** The code directly interacts with HTML attributes. Changes to these attributes trigger the logic within `HandleAttributeChanged`.
*   **CSS:** While not explicitly manipulating CSS properties, the code can be indirectly affected by CSS. For example, `aria-hidden` can visually hide elements, which impacts accessibility. The code also has a `CSSAnchorChangedWithCleanLayout` function, suggesting a relationship with CSS positioning.
*   **JavaScript:** JavaScript code that modifies HTML attributes will indirectly trigger the logic in this C++ code.

**3. Logical Reasoning (Hypothetical Input/Output):**

*   **Input:**  JavaScript sets the `aria-label` attribute of a `<div>` element to "Close".
*   **Processing:** The `HandleAttributeChanged` function detects the change to `aria-label`. It updates the reverse text relations and defers a tree update.
*   **Output:** The accessibility tree is updated, and the accessible name of the `<div>` element is now "Close". Assistive technologies will report this name.

**4. Common Errors:**

*   **User Error:**  Incorrectly using ARIA attributes (e.g., misspelling them or applying them to inappropriate elements). This will still trigger the `HandleAttributeChanged` function but might not result in the intended accessibility behavior.
*   **Programming Error:**  JavaScript code that modifies attributes frequently without considering the performance implications of accessibility tree updates. This could lead to excessive processing.

**5. Debugging:**

*   A developer might set a breakpoint in `HandleAttributeChanged` to understand why an accessibility property is being updated unexpectedly after a JavaScript modification.
*   They might trace the execution flow when an ARIA attribute is changed to see how it affects the accessibility tree.

**6. Overall Purpose:** This code snippet is a crucial part of the Blink rendering engine responsible for keeping the accessibility tree synchronized with the state of the DOM. It reacts to attribute changes, ensuring that assistive technologies receive accurate information about the web page's structure and content.

Now, let's construct the final answer based on these considerations.
```cpp
el, element);
    } else if (attr_name == html_names::kAriaLabeledbyAttr ||
               attr_name == html_names::kAriaLabelledbyAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseTextRelations(*element, attr_name);
      }
      DeferTreeUpdate(
          TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLabelledBy,
          element);
      TextChanged(element);
    } else if (attr_name == html_names::kAriaDescriptionAttr) {
      TextChanged(element);
    } else if (attr_name == html_names::kAriaDescribedbyAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseTextRelations(*element, attr_name);
      }
      TextChanged(element);
    } else if (attr_name == html_names::kAriaCheckedAttr) {
      PostNotification(element, ax::mojom::blink::Event::kCheckedStateChanged);
      DeferTreeUpdate(TreeUpdateReason::kMaybeDisallowImplicitSelection,
                      element);
    } else if (attr_name == html_names::kAriaPressedAttr) {
      DeferTreeUpdate(TreeUpdateReason::kAriaPressedChanged, element);
    } else if (attr_name == html_names::kAriaSelectedAttr) {
      DeferTreeUpdate(TreeUpdateReason::kAriaSelectedChanged, element);
      DeferTreeUpdate(TreeUpdateReason::kMaybeDisallowImplicitSelection,
                      element);
    } else if (attr_name == html_names::kAriaMultiselectableAttr) {
      if (element == FocusedNode()) {
        // Even though active descendant didn't necessarily change, we want
        // to mark it dirty, because it could lose an implicit selected state.
        DeferTreeUpdate(TreeUpdateReason::kActiveDescendantChanged, element);
      } else {
        MarkElementDirty(FocusedNode());
      }
      MarkElementDirty(element);
    } else if (attr_name == html_names::kAriaExpandedAttr) {
      DeferTreeUpdate(TreeUpdateReason::kAriaExpandedChanged, element);
      DeferTreeUpdate(TreeUpdateReason::kMaybeDisallowImplicitSelection,
                      element);
    } else if (attr_name == html_names::kAriaHiddenAttr) {
      // Removing the subtree will also notify its parent that children changed,
      // causing the subtree to recursively be rebuilt with correct cached
      // values. In addition, changes to aria-hidden can affect with aria-owns
      // within the subtree are considered valid. Removing the subtree forces
      // any stale assumptions regarding aria-owns to be tossed, and the
      // resulting tree structure changes to occur as the subtree is rebuilt,
      // including restoring the natural parent of previously owned children
      // if the owner becomes aria-hidden.
      RemoveSubtree(element);
    } else if (attr_name == html_names::kAriaOwnsAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseOwnsRelations(*element);
      }
      DeferTreeUpdate(TreeUpdateReason::kAriaOwnsChanged, element);
    } else if (attr_name == html_names::kAriaHaspopupAttr) {
      if (AXObject* obj = Get(element)) {
        if (obj->RoleValue() == ax::mojom::blink::Role::kButton ||
            obj->RoleValue() == ax::mojom::blink::Role::kPopUpButton) {
          // The aria-haspopup attribute can switch the role between kButton and
          // kPopupButton.
          DeferTreeUpdate(TreeUpdateReason::kRoleChangeFromAriaHasPopup,
                          element);
        } else {
          MarkElementDirty(element);
        }
      }
    } else if (attr_name == html_names::kAriaActionsAttr ||
               attr_name == html_names::kAriaControlsAttr ||
               attr_name == html_names::kAriaDetailsAttr ||
               attr_name == html_names::kAriaErrormessageAttr ||
               attr_name == html_names::kAriaFlowtoAttr) {
      MarkElementDirty(element);
      if (relation_cache_) {
        relation_cache_->UpdateReverseOtherRelations(*element);
      }
    } else {
      MarkElementDirty(element);
    }
    return;
  }

  if (attr_name == html_names::kRoleAttr ||
      attr_name == html_names::kTypeAttr) {
    DeferTreeUpdate(TreeUpdateReason::kRoleChangeFromRoleOrType, element);
  } else if (attr_name == html_names::kSizeAttr ||
             attr_name == html_names::kMultipleAttr) {
    if (IsA<HTMLSelectElement>(element)) {
      DeferTreeUpdate(TreeUpdateReason::kRoleMaybeChangedOnSelect, element);
    }
  } else if (attr_name == html_names::kAltAttr) {
    TextChanged(element);
  } else if (attr_name == html_names::kTitleAttr) {
    DeferTreeUpdate(TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromTitle,
                    element);
  } else if (attr_name == html_names::kForAttr) {
    if (relation_cache_) {
      if (HTMLLabelElement* label = DynamicTo<HTMLLabelElement>(element)) {
        if (Node* label_target = relation_cache_->LabelChanged(*label)) {
          // If label_target's subtree was ignored because it was hidden, it
          // will no longer be, because labels must be unignored to partake
          // in name calculations.
          MarkElementDirty(label_target);
        }
      }
    }
  } else if (attr_name == html_names::kIdAttr) {
    DeferTreeUpdate(TreeUpdateReason::kIdChanged, element);
  } else if (attr_name == html_names::kClassAttr) {
    MarkElementDirty(element);  // Reserialize the class.
  } else if (attr_name == html_names::kTabindexAttr) {
    MarkElementDirty(element);
  } else if (attr_name == html_names::kValueAttr) {
    HandleValueChanged(element);
  } else if (attr_name == html_names::kDisabledAttr ||
             attr_name == html_names::kReadonlyAttr ||
             attr_name == html_names::kMinAttr ||
             attr_name == html_names::kMaxAttr ||
             attr_name == html_names::kStepAttr) {
    MarkElementDirty(element);
  } else if (attr_name == html_names::kUsemapAttr) {
    DeferTreeUpdate(TreeUpdateReason::kUseMapAttributeChanged, element);
  } else if (attr_name == html_names::kNameAttr) {
    HandleNameAttributeChanged(element);
  } else if (attr_name == html_names::kControlsAttr) {
    ChildrenChanged(element);
  } else if (attr_name == html_names::kHrefAttr) {
    DeferTreeUpdate(TreeUpdateReason::kRoleMaybeChangedFromHref, element);
  } else if (attr_name == html_names::kLangAttr) {
    MarkElementDirty(element);
    // ATs may look at the language of the document as a whole on the root web
    // area. Since the root's language can come from the <html> element's
    // language, if the language changes on <html>, we need to update the root.
    if (element == document_->documentElement()) {
      MarkElementDirty(document_);
    }
  }
}
```

**功能归纳**

这段代码的主要功能是 **响应 HTML 元素属性的更改，并根据这些更改更新浏览器的可访问性树（Accessibility Tree）**。 可访问性树是浏览器为辅助技术（如屏幕阅读器）提供的页面结构表示，以便残疾用户能够理解和操作网页内容。

**与 JavaScript, HTML, CSS 的关系及举例说明**

*   **HTML:**  这段代码直接监听和处理 HTML 元素的各种属性变化。例如：
    *   当 `aria-label` 属性的值改变时，代码会更新元素的无障碍名称。
    *   当 `role` 属性的值改变时，代码会重新评估元素的语义角色。
    *   当 `alt` 属性（用于图像）改变时，代码会更新图像的无障碍替代文本。
    *   当 `href` 属性（用于链接）改变时，代码可能会重新评估链接的角色。

    **举例：** 如果 HTML 中有 `<button id="myButton">Click Me</button>`，然后 JavaScript 执行 `document.getElementById('myButton').setAttribute('aria-label', 'Press to activate');`，这段 C++ 代码的 `HandleAttributeChanged` 函数会被调用，检测到 `aria-label` 的变化，并更新可访问性树中该按钮的无障碍名称为 "Press to activate"。

*   **JavaScript:** JavaScript 代码通常会动态修改 HTML 元素的属性，这些修改会触发这段 C++ 代码中的逻辑。

    **举例：** 一个 JavaScript 框架可能会根据用户的交互动态添加或删除 `aria-expanded` 属性来表示一个折叠/展开的区域。  这段 C++ 代码会捕获 `aria-expanded` 属性的更改，并更新可访问性树中对应元素的状态。

*   **CSS:** CSS 主要负责视觉呈现，但某些 CSS 属性（如 `display: none;` 或 `visibility: hidden;`）会影响元素是否在可访问性树中显示。 虽然这段代码本身不直接处理 CSS 属性变化，但 CSS 的渲染结果会影响可访问性树的构建，进而影响这里代码的某些行为。 例如，一个 `aria-hidden="true"` 的元素即使在 CSS 中可见，也会被从可访问性树中移除（在后续代码中会看到 `RemoveSubtree(element);`）。

**逻辑推理及假设输入与输出**

假设输入：一个 `<div>` 元素，初始状态没有 `aria-labelledby` 属性。
操作：JavaScript 代码执行 `element.setAttribute('aria-labelledby', 'label1 label2');`。

逻辑推理：

1. `HandleAttributeChanged` 函数被调用，`attr_name` 为 `aria-labelledby`。
2. `relation_cache_` 存在，则调用 `relation_cache_->UpdateReverseTextRelations(*element, attr_name);`。 这会建立或更新元素与 ID 为 "label1" 和 "label2" 的元素的反向引用关系，表示该 `div` 由这两个元素进行标签说明。
3. 调用 `DeferTreeUpdate`，原因是 `kSectionOrRegionRoleMaybeChangedFromLabelledBy`，表示可能需要重新评估该 `div` 的角色，因为它现在被标签说明了。
4. 调用 `TextChanged(element);`，因为标签说明的改变可能影响元素的无障碍名称计算。

假设输出：可访问性树被更新，该 `div` 元素的 `AXObject` 会包含指向 ID 为 "label1" 和 "label2" 的 `AXObject` 的引用，用于计算其无障碍名称。 辅助技术在读取该 `div` 时，可能会先读取 "label1" 和 "label2" 的内容。

**用户或编程常见的使用错误及举例说明**

*   **用户错误（内容作者）：** 错误地使用 ARIA 属性。例如，将 `aria-labelledby` 指向不存在的 ID。

    **举例：**  HTML 中有 `<div aria-labelledby="nonExistentID">Content</div>`。  这段 C++ 代码会尝试查找 ID 为 "nonExistentID" 的元素，但找不到，这会导致辅助技术无法正确地获取该 `div` 的标签，可能导致用户理解困难。虽然代码会执行，但不会产生预期的可访问性效果。

*   **编程错误（开发者）：**  频繁地、不必要地修改元素的属性，导致可访问性树频繁更新，影响性能。

    **举例：**  一个动画效果通过 JavaScript 快速地改变一个元素的 `aria-valuenow` 属性。 每次属性变化都会触发这段 C++ 代码的执行和可访问性树的更新，如果更新频率过高，可能会导致浏览器卡顿或辅助技术响应缓慢。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户在网页上进行操作**，例如：
    *   点击一个按钮，导致 JavaScript 代码修改了该按钮的 `aria-pressed` 属性。
    *   在一个文本框中输入内容，导致 JavaScript 代码动态更新某个提示元素的 `aria-live` 属性。
    *   页面加载完成，浏览器解析 HTML 并构建 DOM 树。
2. **JavaScript 代码执行**，修改了 DOM 元素的属性（例如使用 `setAttribute` 方法）。
3. **Blink 渲染引擎捕获到属性变化**。
4. **`AXObjectCacheImpl::HandleAttributeChanged` 函数被调用**，传入发生变化的元素和属性名称。
5. **该函数根据属性名称执行相应的逻辑**，例如更新关系缓存、标记元素为 dirty、触发可访问性事件等。

调试线索：如果在调试可访问性问题时，发现某个元素的无障碍属性值不正确，可以设置断点在 `AXObjectCacheImpl::HandleAttributeChanged` 函数中，观察当该元素的属性发生变化时，代码是如何执行的，以及是否按照预期更新了可访问性树。 可以检查 `attr_name` 的值，以及在不同 `if` 分支中执行的逻辑，从而定位问题所在。

**第 6 部分功能归纳**

作为第 6 部分，这段代码着重于 **处理 HTML 元素属性的变更，并同步更新可访问性树的状态**。  它定义了针对不同 HTML 和 ARIA 属性变化的具体处理逻辑，包括更新元素名称、角色、状态以及维护元素之间的关系。 这是可访问性功能的核心部分，确保动态网页内容的变化能够及时反映给辅助技术。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
el, element);
    } else if (attr_name == html_names::kAriaLabeledbyAttr ||
               attr_name == html_names::kAriaLabelledbyAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseTextRelations(*element, attr_name);
      }
      DeferTreeUpdate(
          TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLabelledBy,
          element);
      TextChanged(element);
    } else if (attr_name == html_names::kAriaDescriptionAttr) {
      TextChanged(element);
    } else if (attr_name == html_names::kAriaDescribedbyAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseTextRelations(*element, attr_name);
      }
      TextChanged(element);
    } else if (attr_name == html_names::kAriaCheckedAttr) {
      PostNotification(element, ax::mojom::blink::Event::kCheckedStateChanged);
      DeferTreeUpdate(TreeUpdateReason::kMaybeDisallowImplicitSelection,
                      element);
    } else if (attr_name == html_names::kAriaPressedAttr) {
      DeferTreeUpdate(TreeUpdateReason::kAriaPressedChanged, element);
    } else if (attr_name == html_names::kAriaSelectedAttr) {
      DeferTreeUpdate(TreeUpdateReason::kAriaSelectedChanged, element);
      DeferTreeUpdate(TreeUpdateReason::kMaybeDisallowImplicitSelection,
                      element);
    } else if (attr_name == html_names::kAriaMultiselectableAttr) {
      if (element == FocusedNode()) {
        // Even though active descendant didn't necessarily change, we want
        // to mark it dirty, because it could lose an implicit selected state.
        DeferTreeUpdate(TreeUpdateReason::kActiveDescendantChanged, element);
      } else {
        MarkElementDirty(FocusedNode());
      }
      MarkElementDirty(element);
    } else if (attr_name == html_names::kAriaExpandedAttr) {
      DeferTreeUpdate(TreeUpdateReason::kAriaExpandedChanged, element);
      DeferTreeUpdate(TreeUpdateReason::kMaybeDisallowImplicitSelection,
                      element);
    } else if (attr_name == html_names::kAriaHiddenAttr) {
      // Removing the subtree will also notify its parent that children changed,
      // causing the subtree to recursively be rebuilt with correct cached
      // values. In addition, changes to aria-hidden can affect with aria-owns
      // within the subtree are considered valid. Removing the subtree forces
      // any stale assumptions regarding aria-owns to be tossed, and the
      // resulting tree structure changes to occur as the subtree is rebuilt,
      // including restoring the natural parent of previously owned children
      // if the owner becomes aria-hidden.
      RemoveSubtree(element);
    } else if (attr_name == html_names::kAriaOwnsAttr) {
      if (relation_cache_) {
        relation_cache_->UpdateReverseOwnsRelations(*element);
      }
      DeferTreeUpdate(TreeUpdateReason::kAriaOwnsChanged, element);
    } else if (attr_name == html_names::kAriaHaspopupAttr) {
      if (AXObject* obj = Get(element)) {
        if (obj->RoleValue() == ax::mojom::blink::Role::kButton ||
            obj->RoleValue() == ax::mojom::blink::Role::kPopUpButton) {
          // The aria-haspopup attribute can switch the role between kButton and
          // kPopupButton.
          DeferTreeUpdate(TreeUpdateReason::kRoleChangeFromAriaHasPopup,
                          element);
        } else {
          MarkElementDirty(element);
        }
      }
    } else if (attr_name == html_names::kAriaActionsAttr ||
               attr_name == html_names::kAriaControlsAttr ||
               attr_name == html_names::kAriaDetailsAttr ||
               attr_name == html_names::kAriaErrormessageAttr ||
               attr_name == html_names::kAriaFlowtoAttr) {
      MarkElementDirty(element);
      if (relation_cache_) {
        relation_cache_->UpdateReverseOtherRelations(*element);
      }
    } else {
      MarkElementDirty(element);
    }
    return;
  }

  if (attr_name == html_names::kRoleAttr ||
      attr_name == html_names::kTypeAttr) {
    DeferTreeUpdate(TreeUpdateReason::kRoleChangeFromRoleOrType, element);
  } else if (attr_name == html_names::kSizeAttr ||
             attr_name == html_names::kMultipleAttr) {
    if (IsA<HTMLSelectElement>(element)) {
      DeferTreeUpdate(TreeUpdateReason::kRoleMaybeChangedOnSelect, element);
    }
  } else if (attr_name == html_names::kAltAttr) {
    TextChanged(element);
  } else if (attr_name == html_names::kTitleAttr) {
    DeferTreeUpdate(TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromTitle,
                    element);
  } else if (attr_name == html_names::kForAttr) {
    if (relation_cache_) {
      if (HTMLLabelElement* label = DynamicTo<HTMLLabelElement>(element)) {
        if (Node* label_target = relation_cache_->LabelChanged(*label)) {
          // If label_target's subtree was ignored because it was hidden, it
          // will no longer be, because labels must be unignored to partake
          // in name calculations.
          MarkElementDirty(label_target);
        }
      }
    }
  } else if (attr_name == html_names::kIdAttr) {
    DeferTreeUpdate(TreeUpdateReason::kIdChanged, element);
  } else if (attr_name == html_names::kClassAttr) {
    MarkElementDirty(element);  // Reserialize the class.
  } else if (attr_name == html_names::kTabindexAttr) {
    MarkElementDirty(element);
  } else if (attr_name == html_names::kValueAttr) {
    HandleValueChanged(element);
  } else if (attr_name == html_names::kDisabledAttr ||
             attr_name == html_names::kReadonlyAttr ||
             attr_name == html_names::kMinAttr ||
             attr_name == html_names::kMaxAttr ||
             attr_name == html_names::kStepAttr) {
    MarkElementDirty(element);
  } else if (attr_name == html_names::kUsemapAttr) {
    DeferTreeUpdate(TreeUpdateReason::kUseMapAttributeChanged, element);
  } else if (attr_name == html_names::kNameAttr) {
    HandleNameAttributeChanged(element);
  } else if (attr_name == html_names::kControlsAttr) {
    ChildrenChanged(element);
  } else if (attr_name == html_names::kHrefAttr) {
    DeferTreeUpdate(TreeUpdateReason::kRoleMaybeChangedFromHref, element);
  } else if (attr_name == html_names::kLangAttr) {
    MarkElementDirty(element);
    // ATs may look at the language of the document as a whole on the root web
    // area. Since the root's language can come from the <html> element's
    // language, if the language changes on <html>, we need to update the root.
    if (element == document_->documentElement()) {
      MarkElementDirty(document_);
    }
  }
}

void AXObjectCacheImpl::HandleUseMapAttributeChangedWithCleanLayout(
    Node* node) {
  if (!IsA<HTMLImageElement>(node)) {
    return;
  }
  // Get an area (aka image link) from the previous usemap.
  AXObject* ax_image = Get(node);
  AXObject* ax_image_link =
      ax_image ? ax_image->FirstChildIncludingIgnored() : nullptr;
  HTMLMapElement* previous_map =
      ax_image_link && ax_image_link->GetNode()
          ? Traversal<HTMLMapElement>::FirstAncestor(*ax_image_link->GetNode())
          : nullptr;
  // Both the old and new image may change image <--> image map.
  HandleRoleChangeWithCleanLayout(node);
  if (previous_map)
    HandleRoleChangeWithCleanLayout(previous_map->ImageElement());
}

void AXObjectCacheImpl::HandleNameAttributeChanged(Node* node) {
  HTMLMapElement* map = DynamicTo<HTMLMapElement>(node);
  if (!map) {
    return;
  }

  // Changing a map name can alter an image's role and children.
  // First update any image that may have used the old map name.
  if (AXObject* ax_previous_image = GetAXImageForMap(*map)) {
    DeferTreeUpdate(TreeUpdateReason::kRoleChangeFromImageMapName,
                    ax_previous_image->GetElement());
  }

  // Then, update any image which may use the new map name.
  HTMLImageElement* new_image = map->ImageElement();
  if (new_image) {
    if (AXObject* obj = Get(new_image)) {
      DeferTreeUpdate(TreeUpdateReason::kRoleChangeFromImageMapName,
                      obj->GetElement());
    }
  }
}

AXObject* AXObjectCacheImpl::GetOrCreateValidationMessageObject() {
  // New AXObjects cannot be created when the tree is frozen.
  AXObject* message_ax_object = nullptr;
  // Create only if it does not already exist.
  if (validation_message_axid_) {
    message_ax_object = ObjectFromAXID(validation_message_axid_);
  }
  if (message_ax_object) {
    DCHECK(!message_ax_object->IsDetached());
    if (message_ax_object->IsMissingParent()) {
      message_ax_object->SetParent(Root());  // Reattach to parent (root).
    } else {
      DCHECK(message_ax_object->ParentObject() == Root());
    }
  } else {
    if (IsFrozen()) {
      return nullptr;
    }
    message_ax_object = MakeGarbageCollected<AXValidationMessage>(*this);
    CHECK(message_ax_object);
    CHECK(!message_ax_object->IsDetached());
    // Cache the validation message container for reuse.
    validation_message_axid_ = AssociateAXID(message_ax_object);
    // Validation message alert object is a child of the document, as not all
    // form controls can have a child. Also, there are form controls such as
    // listbox that technically can have children, but they are probably not
    // expected to have alerts within AT client code.
    message_ax_object->Init(Root());
  }
  CHECK(!message_ax_object->IsDetached());
  return message_ax_object;
}

AXObject* AXObjectCacheImpl::ValidationMessageObjectIfInvalid() {
  Element* focused_element = document_->FocusedElement();
  if (focused_element) {
    ListedElement* form_control = ListedElement::From(*focused_element);
    if (form_control && !form_control->IsNotCandidateOrValid()) {
      // These must both be true:
      // * Focused control is currently invalid.
      // * Validation message was previously created but hidden
      // from timeout or currently visible.
      bool was_validation_message_already_created = validation_message_axid_;
      if (was_validation_message_already_created ||
          form_control->IsValidationMessageVisible()) {
        // Create the validation message unless the focused form control is
        // overriding it with a different message via aria-errormessage.
        if (!AXObject::ElementsFromAttributeOrInternals(
                focused_element, html_names::kAriaErrormessageAttr)) {
          AXObject* message = GetOrCreateValidationMessageObject();
          CHECK(message);
          CHECK(!message->IsDetached());
          CHECK_EQ(message->ParentObject(), Root());
          return message;
        }
      }
    }
  }

  // No focused, invalid form control.
  if (validation_message_axid_) {
    RemoveValidationMessageObjectWithCleanLayout(document_);
  }
  return nullptr;
}

void AXObjectCacheImpl::RemoveValidationMessageObjectWithCleanLayout(
    Node* document) {
  DCHECK_EQ(document, document_);
  if (validation_message_axid_) {
    // Remove when it becomes hidden, so that a new object is created the next
    // time the message becomes visible. It's not possible to reuse the same
    // alert, because the event generator will not generate an alert event if
    // the same object is hidden and made visible quickly, which occurs if the
    // user submits the form when an alert is already visible.
    Remove(validation_message_axid_, /* notify_parent */ false);
    validation_message_axid_ = 0;
  }
  ChildrenChangedWithCleanLayout(document_);
}

// Native validation error popup for focused form control in current document.
void AXObjectCacheImpl::HandleValidationMessageVisibilityChanged(
    Node* form_control) {
  DCHECK(form_control);
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  DeferTreeUpdate(TreeUpdateReason::kValidationMessageVisibilityChanged,
                  form_control);
}

void AXObjectCacheImpl::HandleValidationMessageVisibilityChangedWithCleanLayout(
    const Node* form_control) {
#if DCHECK_IS_ON()
  DCHECK(form_control);
  Document* document = &form_control->GetDocument();
  DCHECK(document);
  DCHECK(document->Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle " << document->Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  if (AXObject* message_ax_object = ValidationMessageObjectIfInvalid()) {
    MarkAXObjectDirtyWithCleanLayout(message_ax_object);
  }

  ChildrenChangedWithCleanLayout(Root());

  // If the form control is invalid, it will now have an error message relation
  // to the message container.
  MarkElementDirtyWithCleanLayout(form_control);
}

void AXObjectCacheImpl::HandleEventListenerAdded(
    Node& node,
    const AtomicString& event_type) {
  // If this is the first |event_type| listener for |node|, handle the
  // subscription change.
  if (node.NumberOfEventListeners(event_type) == 1)
    HandleEventSubscriptionChanged(node, event_type);
}

void AXObjectCacheImpl::HandleEventListenerRemoved(
    Node& node,
    const AtomicString& event_type) {
  // If there are no more |event_type| listeners for |node|, handle the
  // subscription change.
  if (node.NumberOfEventListeners(event_type) == 0)
    HandleEventSubscriptionChanged(node, event_type);
}

void AXObjectCacheImpl::HandleReferenceTargetChanged(Element& element) {
  DeferTreeUpdate(TreeUpdateReason::kReferenceTargetChanged, &element);
}

bool AXObjectCacheImpl::DoesEventListenerImpactIgnoredState(
    const AtomicString& event_type,
    const Node& node) const {
  // An SVG graphics element with a focus event listener is focusable, which
  // causes it to be unignored.
  if (auto* svg_graphics_element = DynamicTo<SVGGraphicsElement>(node)) {
    if (svg_graphics_element->HasFocusEventListeners()) {
      return true;
    }
  }
  // A mouse event listener causes a node to be unignored.
  return event_util::IsMouseButtonEventType(event_type);
}

void AXObjectCacheImpl::HandleEventSubscriptionChanged(
    Node& node,
    const AtomicString& event_type) {
  // Adding or Removing an event listener for certain events may affect whether
  // a node or its descendants should be accessibility ignored.
  if (!DoesEventListenerImpactIgnoredState(event_type, node)) {
    return;
  }

  MarkElementDirty(&node);
  // If the ignored state changes, the parent's children may have changed.
  if (AXObject* obj = Get(&node)) {
    if (!obj->IsDetached()) {
      if (obj->ParentObject()) {
        ChildrenChanged(obj->ParentObject());
        // ChildrenChanged() can cause the obj to be detached.
        if (obj->IsDetached()) {
          return;
        }
      }

      DeferTreeUpdate(TreeUpdateReason::kRoleMaybeChangedFromEventListener,
                      &node);
    }
  }
}

void AXObjectCacheImpl::CSSAnchorChangedWithCleanLayout(Node* positioned_node) {
  relation_cache_->UpdateCSSAnchorFor(positioned_node);
}

void AXObjectCacheImpl::AriaOwnsChangedWithCleanLayout(Node* node) {
  CHECK(relation_cache_);
  if (AXObject* obj = Get(node)) {
    relation_cache_->UpdateAriaOwnsWithCleanLayout(obj);
  }
}

void AXObjectCacheImpl::InlineTextBoxesUpdated(LayoutObject* layout_object) {
  if (AXObject* obj = Get(layout_object)) {
    // Only update if the accessibility object already exists and it's
    // not already marked as dirty.
    CHECK(!obj->IsDetached());
    if (obj->ShouldLoadInlineTextBoxes()) {
      obj->SetNeedsToUpdateChildren();
      obj->ClearChildren();
      MarkAXObjectDirty(obj);
    }
  }
}

Settings* AXObjectCacheImpl::GetSettings() {
  return document_->GetSettings();
}

const Element* AXObjectCacheImpl::RootAXEditableElement(const Node* node) {
  const Element* result = RootEditableElement(*node);
  const auto* element = DynamicTo<Element>(node);
  if (!element)
    element = node->parentElement();

  for (; element; element = element->parentElement()) {
    if (NodeIsTextControl(element))
      result = element;
  }

  return result;
}

bool AXObjectCacheImpl::NodeIsTextControl(const Node* node) {
  if (!node)
    return false;

  const AXObject* ax_object = Get(const_cast<Node*>(node));
  return ax_object && ax_object->IsTextField();
}

WebLocalFrameClient* AXObjectCacheImpl::GetWebLocalFrameClient() const {
  DCHECK(document_);
  WebLocalFrameImpl* web_frame =
      WebLocalFrameImpl::FromFrame(document_->AXObjectCacheOwner().GetFrame());
  if (!web_frame)
    return nullptr;
  WebLocalFrameClient* client = web_frame->Client();
  DCHECK(client);
  return client;
}

bool AXObjectCacheImpl::IsImmediateProcessingRequiredForEvent(
    ax::mojom::blink::EventFrom& event_from,
    AXObject* target,
    ax::mojom::blink::Event& event_type) const {
  // Already scheduled for immediate mode.
  if (serialize_immediately_) {
    return true;
  }

  // Actions should result in an immediate response.
  if (event_from == ax::mojom::blink::EventFrom::kAction) {
    return true;
  }

  // It's important for the user to have access to any changes to the
  // currently focused object, so schedule serializations immediately if that
  // object changes. The root is an exception because it often has focus while
  // the page is loading.
  if (target->GetNode() != document_ && target->IsFocused()) {
    return true;
  }

  switch (event_type) {
    case ax::mojom::blink::Event::kActiveDescendantChanged:
    case ax::mojom::blink::Event::kBlur:
    case ax::mojom::blink::Event::kCheckedStateChanged:
    case ax::mojom::blink::Event::kClicked:
    case ax::mojom::blink::Event::kDocumentSelectionChanged:
    case ax::mojom::blink::Event::kExpandedChanged:
    case ax::mojom::blink::Event::kFocus:
    case ax::mojom::blink::Event::kHover:
    case ax::mojom::blink::Event::kLoadComplete:
    case ax::mojom::blink::Event::kLoadStart:
    case ax::mojom::blink::Event::kRowExpanded:
    case ax::mojom::blink::Event::kScrolledToAnchor:
    case ax::mojom::blink::Event::kSelectedChildrenChanged:
    case ax::mojom::blink::Event::kValueChanged:
      return true;

    case ax::mojom::blink::Event::kDocumentTitleChanged:
    case ax::mojom::blink::Event::kLayoutComplete:
    case ax::mojom::blink::Event::kLocationChanged:
    case ax::mojom::blink::Event::kRowCollapsed:
    case ax::mojom::blink::Event::kRowCountChanged:
    case ax::mojom::blink::Event::kScrollPositionChanged:
    case ax::mojom::blink::Event::kTextChanged:
      return false;

    // These events are not fired from Blink.
    // This list is duplicated in WebFrameTestProxy::PostAccessibilityEvent().
    case ax::mojom::blink::Event::kAlert:
    case ax::mojom::blink::Event::kAriaAttributeChangedDeprecated:
    case ax::mojom::blink::Event::kAutocorrectionOccured:
    case ax::mojom::blink::Event::kChildrenChanged:
    case ax::mojom::blink::Event::kControlsChanged:
    case ax::mojom::blink::Event::kEndOfTest:
    case ax::mojom::blink::Event::kFocusAfterMenuClose:
    case ax::mojom::blink::Event::kFocusContext:
    case ax::mojom::blink::Event::kHide:
    case ax::mojom::blink::Event::kHitTestResult:
    case ax::mojom::blink::Event::kImageFrameUpdated:
    case ax::mojom::blink::Event::kLiveRegionCreated:
    case ax::mojom::blink::Event::kLiveRegionChanged:
    case ax::mojom::blink::Event::kMediaStartedPlaying:
    case ax::mojom::blink::Event::kMediaStoppedPlaying:
    case ax::mojom::blink::Event::kMenuEnd:
    case ax::mojom::blink::Event::kMenuListValueChangedDeprecated:
    case ax::mojom::blink::Event::kMenuPopupEnd:
    case ax::mojom::blink::Event::kMenuPopupStart:
    case ax::mojom::blink::Event::kMenuStart:
    case ax::mojom::blink::Event::kMouseCanceled:
    case ax::mojom::blink::Event::kMouseDragged:
    case ax::mojom::blink::Event::kMouseMoved:
    case ax::mojom::blink::Event::kMousePressed:
    case ax::mojom::blink::Event::kMouseReleased:
    case ax::mojom::blink::Event::kNone:
    case ax::mojom::blink::Event::kSelection:
    case ax::mojom::blink::Event::kSelectionAdd:
    case ax::mojom::blink::Event::kSelectionRemove:
    case ax::mojom::blink::Event::kShow:
    case ax::mojom::blink::Event::kStateChanged:
    case ax::mojom::blink::Event::kTextSelectionChanged:
    case ax::mojom::blink::Event::kTooltipClosed:
    case ax::mojom::blink::Event::kTooltipOpened:
    case ax::mojom::blink::Event::kTreeChanged:
    case ax::mojom::blink::Event::kWindowActivated:
    case ax::mojom::blink::Event::kWindowDeactivated:
    case ax::mojom::blink::Event::kWindowVisibilityChanged:
      // Never fired from Blink.
      NOTREACHED() << "Event not expected from Blink: " << event_type;
  }
}

bool AXObjectCacheImpl::IsImmediateProcessingRequired(
    TreeUpdateParams* tree_update) const {
  // For now, immediate processing is never required for deferred AXObject
  // updates, and this method doesn't need to be called for that case.
  CHECK(!tree_update->axid);

  // Already scheduled for immediate mode.
  if (serialize_immediately_) {
    return true;
  }

  // Get some initial content as soon as possible.
  if (objects_.size() <= 1) {
    return true;
  }

  // Actions should result in an immediate response.
  if (tree_update->event_from_action != ax::mojom::blink::Action::kNone) {
    return true;
  }

  // It's important for the user to have access to any changes to the
  // currently focused object, so schedule serializations immediately if that
  // object changes. The root is an exception because it often has focus while
  // the page is loading.
  if (tree_update->node != document_ &&
      tree_update->node == document_->FocusedElement()) {
    return true;
  }

  switch (tree_update->update_reason) {
    // These updates are associated with a Node:
    case TreeUpdateReason::kActiveDescendantChanged:
    case TreeUpdateReason::kAriaExpandedChanged:
    case TreeUpdateReason::kAriaPressedChanged:
    case TreeUpdateReason::kAriaSelectedChanged:
    case TreeUpdateReason::kDidShowMenuListPopup:
    case TreeUpdateReason::kEditableTextContentChanged:
    case TreeUpdateReason::kNodeGainedFocus:
    case TreeUpdateReason::kNodeLostFocus:
    case TreeUpdateReason::kPostNotificationFromHandleLoadComplete:
    case TreeUpdateReason::kUpdateActiveMenuOption:
    case TreeUpdateReason::kValidationMessageVisibilityChanged:
      return true;

    case TreeUpdateReason::kAriaOwnsChanged:
    case TreeUpdateReason::kCSSAnchorChanged:
    case TreeUpdateReason::kDelayEventFromPostNotification:
    case TreeUpdateReason::kFocusableChanged:
    case TreeUpdateReason::kIdChanged:
    case TreeUpdateReason::kMaybeDisallowImplicitSelection:
    case TreeUpdateReason::kNodeIsAttached:
    case TreeUpdateReason::kPostNotificationFromHandleLoadStart:
    case TreeUpdateReason::kPostNotificationFromHandleScrolledToAnchor:
    case TreeUpdateReason::kReferenceTargetChanged:
    case TreeUpdateReason::kRemoveValidationMessageObjectFromFocusedUIElement:
    case TreeUpdateReason::
        kRemoveValidationMessageObjectFromValidationMessageObject:
    case TreeUpdateReason::kRestoreParentOrPrune:
    case TreeUpdateReason::kRoleChangeFromAriaHasPopup:
    case TreeUpdateReason::kRoleChangeFromImageMapName:
    case TreeUpdateReason::kRoleChangeFromRoleOrType:
    case TreeUpdateReason::kRoleMaybeChangedFromEventListener:
    case TreeUpdateReason::kRoleMaybeChangedFromHref:
    case TreeUpdateReason::kRoleMaybeChangedOnSelect:
    case TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLabel:
    case TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromLabelledBy:
    case TreeUpdateReason::kSectionOrRegionRoleMaybeChangedFromTitle:
    case TreeUpdateReason::kTextChangedOnNode:
    case TreeUpdateReason::kTextChangedOnClosestNodeForLayoutObject:
    case TreeUpdateReason::kTextMarkerDataAdded:
    case TreeUpdateReason::kUpdateAriaOwns:
    case TreeUpdateReason::kUpdateTableRole:
    case TreeUpdateReason::kUseMapAttributeChanged:
      return false;

    // These updates are associated with an AXID:
    case TreeUpdateReason::kChildrenChanged:
    case TreeUpdateReason::kMarkAXObjectDirty:
    case TreeUpdateReason::kMarkAXSubtreeDirty:
    case TreeUpdateReason::kTextChangedOnLayoutObject:
      return false;
  }
}

// The lifecycle serialization works as follows:
// 1) Dirty objects and events are fired through
// AXObjectCacheImpl::PostPlatformNotification which in turn makes a call to
// AXObjectCacheImpl::AddEventToSerializationQueue to queue it.
//
// 2) When the lifecycle is ready to be serialized,
// AXObjectCacheImpl::CommitAXUpdates is called which first
// checks if it's time to make a new serialization, and if not, it will early
// return in order to add a delay between serializations.
//
// 3) AXObjectCacheImpl::CommitAXUpdates then calls
// RenderAccessibilityImpl:AXReadyCallback to start serialization process.
//
// Check the below CL for more information:
// https://chromium-review.googlesource.com/c/chromium/src/+/4994320
void AXObjectCacheImpl::AddEventToSerializationQueue(
    const ui::AXEvent& event,
    bool immediate_serialization) {
  CHECK(lifecycle_.StateAllowsQueueingEventsForSerialization()) << *this;

  AXObject* obj = ObjectFromAXID(event.id);
  DCHECK(!obj->IsDetached());

  pending_events_to_serialize_.push_back(event);

  AddDirtyObjectToSerializationQueue(
      obj, event.event_from, event.event_from_action, event.event_intents);

  if (immediate_serialization) {
    ScheduleImmediateSerialization();
  }
}

void AXObjectCacheImpl::OnSerializationCancelled() {
  serialization_in_flight_ = false;
}

void AXObjectCacheImpl::OnSerializationStartSend() {
  serialization_in_flight_ = true;
}

bool AXObjectCacheImpl::IsSerializationInFlight() const {
  return serialization_in_flight_;
}

void AXObjectCacheImpl::OnSerializationReceived() {
  serialization_in_flight_ = false;
  last_serialization_timestamp_ = base::Time::Now();

  // Another serialization may be needed, in the case where the AXObjectCache is
  // dirty. In that case, make sure a visual update is scheduled so that
  // AXReadyCallback() will be called. ScheduleAXUpdate() will only schedule a
  // visual update if the AXObjectCache is dirty.
  if (serialize_immediately_after_current_serialization_) {
    serialize_immediately_after_current_serialization_ = false;
    ScheduleImmediateSerialization();
  } else {
    ScheduleAXUpdate();
  }
}

void AXObjectCacheImpl::ScheduleImmediateSerialization() {
  if (IsSerializationInFlight()) {
    // Wait until current serialization message has been received.
    serialize_immediately_after_current_serialization_ = true;
    return;
  }

  serialize_immediately_ = true;

  // Call ScheduleAXUpdate() to ensure lifecycle does not get stalled.
  // Will call AXReadyCallback() at the next available opportunity.
  ScheduleAXUpdate();
}

void AXObjectCacheImpl::PostPlatformNotification(
    AXObject* obj,
    ax::mojom::blink::Event event_type,
    ax::mojom::blink::EventFrom event_from,
    ax::mojom::blink::Action event_from_action,
    const BlinkAXEventIntentsSet& event_intents) {
  CHECK(lifecycle_.StateAllowsQueueingEventsForSerialization()) << *this;

  obj = GetSerializationTarget(obj);
  if (!obj)
    return;

  ui::AXEvent event;
  event.id = obj->AXObjectID();
  event.event_type = event_type;
  event.event_from = event_from;
  event.event_from_action = event_from_action;
  event.event_intents.resize(event_intents.size());
  // We need to filter out the counts from every intent.
  base::ranges::transform(
      event_intents, event.event_intents.begin(),
      [](const auto& intent) { return intent.key.intent(); });
  for (auto agent : agents_)
    agent->AXEventFired(obj, event_type);

  // Since we're in the middle of processing deferred events anyways, we know
  // this will be immediately serialized.
  AddEventToSerializationQueue(event, /* immediate_serialization */ false);

  // TODO(aleventhal) This is for web tests only, in order to record MarkDirty
  // events. Is there a way to avoid these calls for normal browsing?
  // Maybe we should use dependency injection from AccessibilityController.
  if (auto* client = GetWebLocalFrameClient()) {
    client->HandleWebAccessibilityEventForTest(event);
  }
}

void AXObjectCacheImpl::MarkAXObjectDirtyWithCleanLayoutHelper(
    AXObject* obj,
    ax::mojom::blink::EventFrom event_from,
    ax::mojom::blink::Action event_from_action) {
  CHECK(!IsFrozen());
  obj = GetSerializationTarget(obj);
  if (!obj)
    return;

  obj->SetAncestorsHaveDirtyDescendants();

  // If the content is inside the popup, mark the owning element dirty.
  // TODO(aleventhal): not sure why this works, but now that we run a11y in
  // PostRunLifecycleTasks(), we need this, otherwise the pending updates in
  // the popup aren't processed.
  if (IsPopup(*obj->GetDocument())) {
    MarkElementDirtyWithCleanLayout(GetDocument().FocusedElement());
  }

  // TODO(aleventhal) This is for web tests only, in order to record MarkDirty
  // events. Is there a way to avoid these calls for normal browsing?
  // Maybe we should use dependency injection from AccessibilityController.
  if (auto* client = GetWebLocalFrameClient()) {
    client->HandleWebAccessibilityEventForTest(
        WebAXObject(obj), "MarkDirty", std::vector<ui::AXEventIntent>());
  }

  std::vector<ui::AXEventIntent> event_intents;
  AddDirtyObjectToSerializationQueue(obj, event_from, event_from_action,
                                     event_intents);

  obj->UpdateCachedAttributeValuesIfNeeded(true);
}

void AXObjectCacheImpl::MarkAXObjectDirtyWithCleanLayout(AXObject* obj) {
  if (!obj) {
    return;
  }
  MarkAXObjectDirtyWithCleanLayoutHelper(obj, active_event_from_,
                                         active_event_from_action_);
  if (!obj->IsIncludedInTree()) {
    obj = obj->ParentObjectIncludedInTree();
  }
  for (auto agent : agents_) {
    agent->AXObjectModified(obj, /*subtree*/ false);
  }
}

void AXObjectCacheImpl::MarkAXObjectDirty(AXObject* obj) {
  if (!obj)
    return;

  // TODO(accessibility) Consider catching all redundant dirty object work,
  // perhaps by setting a flag on the AXObject, or by adding the id to a set of
  // already-dirtied objects.
  DeferTreeUpdate(TreeUpdateReason::kMarkAXObjectDirty, obj);
}

void AXObjectCacheImpl::NotifySubtreeDirty(AXObject* obj) {
  DUMP_WILL_BE_CHECK(obj->IsIncludedInTree());

  // Note: if there is no serializer yet, then there is nothing to mark dirty
  // for serialization purposes yet -- effectively everything starts out dirty
  // in a new serializer.
  if (ax_tree_serializer_) {
    ax_tree_serializer_->MarkSubtreeDirty(obj->AXObjectID());
  }
  for (auto agent : agents_) {
    agent->AXObjectModified(obj, /*subtree*/ true);
  }
}

void AXObjectCacheImpl::MarkAXSubtreeDirtyWithCleanLayout(AXObject* obj) {
  if (!obj) {
    return;
  }
  if (!obj->IsIncludedInTree()) {
    for (const auto& included_child : obj->ChildrenIncludingIgnored()) {
      MarkAXSubtreeDirtyWithCleanLayout(included_child);
    }
    return;
  }

  MarkAXObjectDirtyWithCleanLayoutHelper(obj, active_event_from_,
                                         active_event_from_action_);
  NotifySubtreeDirty(obj);
}

void AXObjectCacheImpl::MarkAXSubtreeDirty(AXObject* obj) {
  if (!obj)
    return;

  DeferTreeUpdate(TreeUpdateReason::kMarkAXSubtreeDirty, obj);
}

void AXObjectCacheImpl::MarkSubtreeDirty(Node* node) {
  if (AXObject* obj = Get(node)) {
    MarkAXSubtreeDirty(obj);
  } else if (node) {
    // There is no AXObject, so there is no subtree to mark dirty.
    MarkElementDirty(node);
  }
}

void AXObjectCacheImpl::MarkDocumentDirty() {
  CHECK(!IsFrozen());

  mark_all_dirty_ = true;

  ScheduleAXUpdate();
}

void AXObjectCacheImpl::MarkDocumentDirtyWithCleanLayout() {
  // This function will cause everything to be reserialized from the root down,
  // but will not create new AXObjects, which avoids resetting the user's
  // position in the content.
  DCHECK(mark_all_dirty_);

  // Assume all nodes in the tree need to recompute their properties.
  // Note that objects can remain in the tree without being re-created.
  // However, they will be dropped if they are no longer needed as the tree
  // structure is rebuilt from the top down.
  for (auto& entry : objects_) {
    AXObject* object = entry.value;
    DCHECK(!object->IsDetached());
    object->InvalidateCachedValues();
  }

  // Don't keep previous parent-child relationships.
  // This loop operates on a copy of values in the objects_ map, because some
  // entries may be removed from objects_ while iterating.
  HeapVector<Member<AXObject>> objects;
  CopyValuesToVector(objects_, objects);
  for (auto& object : objects) {
    if (!object->IsDetached()) {
      object->SetNeedsToUpdateChildren();
    }
  }

  // Clear anything about to be serialized, because everything will be
  // reserialized anyway.
  pending_events_to_serialize_.clear();
  pending_objects_to_serialize_.clear();
  ch
```
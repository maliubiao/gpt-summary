Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ax_object.cc`. This involves understanding what the code does, its relation to web technologies, identifying potential errors, outlining how user actions lead to this code, and finally, summarizing the code's purpose.

Here's a breakdown of the thought process to achieve that:

1. **Identify the Core Function:** The code is within the `AXObject` class and heavily uses `ui::AXNodeData`. This strongly suggests it's involved in serializing accessibility information about a web element into a structured data format. The function name `SerializeAccessibilityProperties` reinforces this.

2. **Analyze the Serialized Properties:**  Go through each section of the code, noting what attributes are being added to `node_data`. Look for patterns and connections to web technologies:
    * **Basic Attributes:** `kName`, `kDescription`, `kRole`, `kUrl` - These are fundamental accessibility properties.
    * **ARIA Attributes:** `kAriaBrailleLabel`, `kAriaBrailleRoleDescription`, `kRoleDescription`, `kKeyShortcuts`, `kVirtualContent`, `kAriaBusyAttr` - This section directly interacts with ARIA attributes in HTML.
    * **Form Control Values:** `kValue`, `kInputType`, `kTextSelStart`, `kTextSelEnd`, `kMaxLength` -  This indicates handling of form elements like `<input>` and `<textarea>`.
    * **Relationships:**  `kControlsIds`,  the logic around `GetControlsListboxForTextfieldCombobox`, and the sections dealing with `aria-details`, `popover`, and `interestTarget` point to how accessible relationships are established and serialized.
    * **State:** `kHasActions` -  Indicates serialization of states.
    * **Scrolling:** `SerializeScrollAttributes` -  Handles properties related to scrolling containers.
    * **Image Data:** `kImageDataUrl` -  Deals with image data.
    * **Text Edits:** `kTextOperationStartOffsets`, etc. -  Serializes information about text insertions and deletions.
    * **Datetime:** Handles the `datetime` attribute on specific elements.

3. **Connect to Web Technologies:**  For each identified property or logic block, relate it to the corresponding HTML, CSS, or JavaScript concepts:
    * **HTML:**  Recognize the direct mapping of attributes like `aria-*`, `type`, `maxlength`, `datetime`. Identify elements like `<input>`, `<textarea>`, `<img>`, `<time>`, `<ins>`, `<del>`, and the semantic roles they represent.
    * **CSS:**  Acknowledge the influence of CSS on properties like visibility, which affects the serialization of details relationships.
    * **JavaScript:** Understand that JavaScript can dynamically manipulate ARIA attributes and form control values, which will eventually be reflected in the serialized accessibility tree. Also consider how JavaScript events might trigger changes that lead to this serialization.

4. **Identify Potential Errors:** Think about common mistakes developers make when implementing accessibility:
    * **Incorrect ARIA usage:**  Using `aria-roledescription` on a `generic` role.
    * **Missing ARIA attributes:** Not providing alternative text for images.
    * **Incorrect relationships:**  Using `aria-owns` on a text field when `aria-controls` would be more appropriate for a combobox.
    * **Performance issues:**  Sending the `value` attribute for every keystroke in large text fields.

5. **Trace User Interaction:**  Consider how a user interacting with a web page would trigger this code:
    * **Page load:** The initial accessibility tree is built when the page loads.
    * **User input:** Typing in a text field, selecting from a dropdown, checking a checkbox.
    * **Navigation:** Moving focus between elements.
    * **Dynamic updates:** JavaScript changing the DOM structure or attributes.
    * **Hovering/Activating elements:**  Potentially triggering popovers or tooltips.

6. **Infer Assumptions and Outputs:**  Think about the expected input and output of specific code sections:
    * **Input:**  An `AXObject` representing a text field with the text "Hello".
    * **Output:** `node_data` will have `kValue` set to "Hello", `kInputType` set to "text" (if it's a text input), and potentially selection attributes if the text is selected.
    * **Input:** An `AXObject` representing an element with `aria-details="someId"`.
    * **Output:** `node_data` will have `kDetailsIds` containing the AXObjectID of the element with `id="someId"`, and `DetailsFrom` will be `kAriaDetails`.

7. **Structure the Summary:** Organize the findings into logical categories:
    * **Core Functionality:**  A concise statement of the main purpose.
    * **Relationship to Web Technologies:**  Specific examples linking the code to HTML, CSS, and JavaScript.
    * **Logical Inferences:**  Present the assumed inputs and outputs.
    * **Common User/Programming Errors:** Highlight potential pitfalls.
    * **User Interaction as Debugging Clues:** Describe how user actions lead to this code.
    * **Overall Function Summary (as requested):** A brief recap of the main function.

8. **Refine and Elaborate:** Review the generated summary for clarity and completeness. Add more details and examples where necessary. Ensure the language is precise and easy to understand. For instance, explicitly mention the serialization process and the purpose of the serialized data (for assistive technologies).

By following these steps, we can systematically analyze the code snippet and provide a comprehensive and informative summary as requested by the user.
好的，让我们来归纳一下这段代码的功能。

**这段代码的主要功能是负责将 `AXObject` 对象的特定属性序列化（转换为可以传输或存储的格式）到 `ui::AXNodeData` 对象中。`ui::AXNodeData` 是 Chromium 中用于表示可访问性树节点数据的结构。**

更具体地说，这段代码片段（作为 `SerializeAccessibilityProperties` 函数的一部分）专注于序列化与以下方面相关的属性：

**1. 基本属性和 ARIA 属性:**

* **`node_data->SetName(ComputeName())`**:  获取并设置可访问对象的名称。
    * **与 HTML 关系:** 例如，对于一个 `<h1>` 标签，`ComputeName()` 可能会返回标签内的文本内容。对于一个带有 `alt` 属性的 `<img>` 标签，会返回 `alt` 属性的值。对于使用了 `aria-label` 或 `aria-labelledby` 的元素，会使用这些属性提供名称。
    * **与 JavaScript 关系:** JavaScript 可以动态修改元素的文本内容或 ARIA 属性，从而影响 `ComputeName()` 的结果。
* **`node_data->SetDescription(ComputeDescription())`**: 获取并设置可访问对象的描述。
    * **与 HTML 关系:**  例如，对于使用了 `aria-describedby` 的元素，会使用该属性指向的元素的文本内容作为描述。
    * **与 JavaScript 关系:**  JavaScript 可以动态修改元素的 ARIA 属性，从而影响 `ComputeDescription()` 的结果。
* **`GetRoleStringForSerialization(node_data)`**:  获取并设置可访问对象的角色 (role)。
    * **与 HTML 关系:**  元素的原生 HTML 标签（例如 `button`, `input`, `div`）会对应一个默认的角色。`role` 属性可以显式指定 ARIA 角色。
    * **与 JavaScript 关系:** JavaScript 可以动态设置元素的 `role` 属性。
* **`node_data->AddStringAttribute(ax::mojom::blink::StringAttribute::kUrl, Url().GetString())`**:  如果对象有相关的 URL，则添加到 `node_data` 中。
    * **与 HTML 关系:** 例如，对于 `<a>` 标签，会添加 `href` 属性的值。对于 `<img>` 标签，会添加 `src` 属性的值。
* **序列化各种 ARIA 属性:**  例如 `aria-braillelabel`, `aria-roledescription`, `aria-keyshortcuts`, `aria-virtualcontent`, `aria-busy` 等。
    * **与 HTML 关系:** 这些属性直接对应 HTML 中的 ARIA 属性。
    * **与 JavaScript 关系:** JavaScript 可以动态修改这些 ARIA 属性。

**2. 表单控件相关属性:**

* **`GetValueForControl()`**: 获取表单控件的值，并设置到 `node_data` 的 `kValue` 属性中。
    * **与 HTML 关系:**  对于 `<input type="text">`，会获取输入框中的文本。对于 `<select>`，会获取选中的选项的值。
    * **与 JavaScript 关系:** JavaScript 可以通过修改表单控件的 `value` 属性来改变其值。
    * **假设输入与输出:**
        * **假设输入:** 一个 `<input type="text" value="Example Text">` 元素对应的 `AXObject`。
        * **输出:**  `node_data` 中 `ax::mojom::blink::StringAttribute::kValue` 的值为 "Example Text"。
* **`kInputType`**: 对于 `<input>` 元素，获取其 `type` 属性。
    * **与 HTML 关系:** 直接对应 `<input>` 标签的 `type` 属性。
* **`kTextSelStart`, `kTextSelEnd`**:  对于可编辑的文本字段，获取当前选中文本的起始和结束位置。
    * **与 HTML 关系:**  适用于 `<input type="text">` 和 `<textarea>` 等元素。
    * **用户操作示例:** 用户在文本框中选中一段文字。
    * **调试线索:**  如果用户报告在屏幕阅读器中选中文本的范围不正确，可以检查这两个属性的值。
* **`kMaxLength`**:  获取 `<input>` 或 `<textarea>` 元素的 `maxlength` 属性。
    * **与 HTML 关系:** 直接对应 HTML 属性。

**3. 关系属性:**

* **`SerializeRelationAttributes(node_data)`**:  处理诸如 `aria-labelledby`, `aria-describedby`, `aria-owns` 等关系属性。
    * **与 HTML 关系:** 这些属性用于建立可访问对象之间的语义关系。
* **处理 `aria-controls`**:  特别是针对 `role="combobox"` 的 `<input>` 元素，尝试找到关联的 `listbox`。
    * **与 HTML 关系:** 用于将文本框与下拉列表关联起来，方便辅助技术理解交互。
    * **用户操作示例:** 用户与一个 `combobox` 交互，展开或收起下拉列表。
    * **调试线索:**  如果辅助技术无法正确识别 `combobox` 的下拉列表，可能需要检查 `kControlsIds` 属性。
* **`SerializeComputedDetailsRelation(node_data)`**:  处理 `aria-details` 属性以及与 `popover` 和 `interestTarget` 相关的细节关系。
    * **与 HTML 关系:** `aria-details` 用于指向提供额外信息的元素。`popover` 和 `interestTarget` 是新的 HTML 属性，用于创建弹出内容。
    * **用户操作示例:** 用户点击一个按钮，触发一个 `popover` 或 `interestTarget` 显示。

**4. 状态属性:**

* **`kHasActions`**:  如果元素有 `aria-actions` 属性，则添加此状态。
    * **与 HTML 关系:**  对应于 `aria-actions` 属性，表示元素可能具有自定义操作。

**5. 其他属性:**

* **`SerializeScrollAttributes(node_data)`**:  处理与滚动相关的属性。
* **`SerializeChooserPopupAttributes(node_data)`**:  处理选择器弹出窗口相关的属性。
* **`SerializeElementAttributes(node_data)`**:  序列化其他元素特定的属性。
* **`SerializeImageDataAttributes(node_data)`**:  处理图像数据相关的属性，例如 `kImageDataUrl`。
* **`SerializeTextInsertionDeletionOffsetAttributes(node_data)`**:  记录文本插入和删除操作的偏移量，用于辅助技术理解文本编辑。
* **`kDateTime`**:  对于 `<time>`, `<ins>`, `<del>` 元素，获取并设置 `datetime` 属性。
    * **与 HTML 关系:** 直接对应 HTML 属性。

**用户或编程常见的使用错误示例:**

* **错误地在 `role="generic"` 的元素上使用 `aria-roledescription`**: 代码中有一个 `if` 判断来避免这种情况。
* **对于非原子文本字段，仍然尝试发送 `value` 属性**: 代码中有注释说明了为什么要避免这种情况以提高性能。
* **`aria-owns` 的错误使用**:  代码中尝试将某些情况下的 `aria-owns` 映射到 `aria-controls`，说明开发者可能会错误地使用 `aria-owns` 来关联 `combobox` 的文本框和列表框。

**用户操作如何一步步到达这里（作为调试线索）:**

1. **用户加载包含可访问元素的网页:**  当浏览器解析 HTML 并构建 DOM 树时，渲染引擎会创建相应的 `AXObject`。
2. **辅助技术请求可访问性信息:** 屏幕阅读器等辅助技术会请求页面的可访问性树。
3. **Blink 渲染引擎构建可访问性树:**  Blink 会遍历 DOM 树并创建 `AXObject` 的层次结构。
4. **序列化 `AXObject` 的属性:** 对于每个 `AXObject`，`SerializeAccessibilityProperties` 函数会被调用，将对象的属性序列化到 `ui::AXNodeData` 中。
5. **传输可访问性数据:** `ui::AXNodeData` 被传递到浏览器进程，最终提供给辅助技术。

**例如，假设用户正在填写一个带有 `role="combobox"` 的输入框:**

1. 用户在输入框中输入文本。
2. 屏幕阅读器可能会请求输入框的可访问性信息。
3. `SerializeAccessibilityProperties` 被调用处理输入框的 `AXObject`。
4. 代码会获取输入框的 `value` 属性（用户输入的文本），并设置到 `node_data` 的 `kValue`。
5. 代码还会尝试找到关联的列表框（通过 `GetControlsListboxForTextfieldCombobox`），并将列表框的 ID 添加到 `node_data` 的 `kControlsIds` 中。

**总结一下这段代码的功能：**

这段代码是 Chromium Blink 引擎可访问性实现的关键部分，它负责将 `AXObject` 对象的状态和属性（包括基本的名称、描述、角色，以及 ARIA 属性和特定于 HTML 元素的属性）转换为 `ui::AXNodeData` 结构，以便将这些信息传递给辅助技术，从而使网页内容对残障人士更易访问。它特别关注表单控件、ARIA 属性以及对象之间的可访问性关系。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共10部分，请归纳一下它的功能

"""
node_data, ax::mojom::blink::StringAttribute::kUrl, Url().GetString());

  if (Element* element = GetElement()) {
    SerializeRelationAttributes(node_data);

    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kAriaBrailleLabel,
        AriaAttribute(html_names::kAriaBraillelabelAttr));
    if (RoleValue() != ax::mojom::blink::Role::kGenericContainer) {
      // ARIA 1.2 prohibits aria-roledescription on the "generic" role.
      TruncateAndAddStringAttribute(
          node_data,
          ax::mojom::blink::StringAttribute::kAriaBrailleRoleDescription,
          AriaAttribute(html_names::kAriaBrailleroledescriptionAttr));
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kRoleDescription,
          AriaAttribute(html_names::kAriaRoledescriptionAttr));
    }
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kKeyShortcuts,
        AriaAttribute(html_names::kAriaKeyshortcutsAttr));
    if (RuntimeEnabledFeatures::AccessibilityAriaVirtualContentEnabled()) {
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kVirtualContent,
          AriaAttribute(html_names::kAriaVirtualcontentAttr));
    }

    if (IsAriaAttributeTrue(html_names::kAriaBusyAttr)) {
      node_data->AddBoolAttribute(ax::mojom::blink::BoolAttribute::kBusy, true);
    }

    // Do not send the value attribute for non-atomic text fields in order to
    // improve the performance of the cross-process communication with the
    // browser process, and since it can be easily computed in that process.
    TruncateAndAddStringAttribute(node_data,
                                  ax::mojom::blink::StringAttribute::kValue,
                                  GetValueForControl());

    if (IsA<HTMLInputElement>(element)) {
      String type = element->getAttribute(html_names::kTypeAttr);
      if (type.empty()) {
        type = "text";
      }
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kInputType, type);
    }

    if (IsAtomicTextField()) {
      // Selection offsets are only used for plain text controls, (input of a
      // text field type, and textarea). Rich editable areas, such as
      // contenteditables, use AXTreeData.
      //
      // TODO(nektar): Remove kTextSelStart and kTextSelEnd from the renderer.
      const auto ax_selection =
          AXSelection::FromCurrentSelection(ToTextControl(*element));
      int start = ax_selection.Anchor().IsTextPosition()
                      ? ax_selection.Anchor().TextOffset()
                      : ax_selection.Anchor().ChildIndex();
      int end = ax_selection.Focus().IsTextPosition()
                    ? ax_selection.Focus().TextOffset()
                    : ax_selection.Focus().ChildIndex();
      node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kTextSelStart,
                                 start);
      node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kTextSelEnd,
                                 end);
    }

    // Serialize maxlength property.
    // TODO(https://github.com/w3c/aria/issues/1119): consider aria-maxlength.
    int max_length = 0;
    if (auto* input = DynamicTo<HTMLInputElement>(GetElement())) {
      max_length = input->maxLength();
    } else if (auto* textarea = DynamicTo<HTMLTextAreaElement>(GetElement())) {
      max_length = textarea->maxLength();
    }
    if (max_length > 0) {
      node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kMaxLength,
                                 max_length);
    }
  }

  SerializeComputedDetailsRelation(node_data);
  // Try to get an aria-controls listbox for an <input role="combobox">.
  if (!node_data->HasIntListAttribute(
          ax::mojom::blink::IntListAttribute::kControlsIds)) {
    if (AXObject* listbox = GetControlsListboxForTextfieldCombobox()) {
      node_data->AddIntListAttribute(
          ax::mojom::blink::IntListAttribute::kControlsIds,
          {static_cast<int32_t>(listbox->AXObjectID())});
    }
  }

  // Check for presence of aria-actions. Even if the value is empty or the
  // targets are hidden, we still want to expose that there could be actions.
  if (RuntimeEnabledFeatures::AriaActionsEnabled() &&
      HasAriaAttribute(html_names::kAriaActionsAttr)) {
    node_data->AddState(ax::mojom::blink::State::kHasActions);
  }

  if (IsScrollableContainer())
    SerializeScrollAttributes(node_data);

  SerializeChooserPopupAttributes(node_data);

  if (GetElement()) {
    SerializeElementAttributes(node_data);
  }

  SerializeImageDataAttributes(node_data);
  SerializeTextInsertionDeletionOffsetAttributes(node_data);

  // Serialize datetime attribute on <time>, <ins> and <del>.
  if (NativeRoleIgnoringAria() == ax::mojom::blink::Role::kTime ||
      NativeRoleIgnoringAria() == ax::mojom::blink::Role::kContentInsertion ||
      NativeRoleIgnoringAria() == ax::mojom::blink::Role::kContentDeletion) {
    if (const AtomicString& datetime =
            GetElement()->FastGetAttribute(html_names::kDatetimeAttr)) {
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kDateTime, datetime);
    }
  }
}

void AXObject::SerializeComputedDetailsRelation(
    ui::AXNodeData* node_data) const {
  // aria-details was used -- it may have set a relation, unless the attribute
  // value did not point to valid elements (e.g aria-details=""). Whether it
  // actually set the relation or not, the author's intent in using the
  // aria-details attribute is understood to mean that no automatic relation
  // should be set.
  if (HasAriaAttribute(html_names::kAriaDetailsAttr)) {
    if (!node_data
             ->GetIntListAttribute(ax::mojom::IntListAttribute::kDetailsIds)
             .empty()) {
      node_data->SetDetailsFrom(ax::mojom::blink::DetailsFrom::kAriaDetails);
    }
    return;
  }

  // Add aria-details for a interest target.
  if (AXObject* interest_popover = GetInterestTargetForInvoker()) {
    // Add state even if the target is hidden.
    node_data->AddState(ax::mojom::blink::State::kHasInterestTarget);
    if (interest_popover->IsVisible()) {
      node_data->AddIntListAttribute(
          ax::mojom::blink::IntListAttribute::kDetailsIds,
          {static_cast<int32_t>(interest_popover->AXObjectID())});
      node_data->SetDetailsFrom(ax::mojom::blink::DetailsFrom::kInterestTarget);
      return;
    }
  }

  // Add aria-details for a popover invoker.
  if (AXObject* popover = GetPopoverTargetForInvoker()) {
    node_data->AddIntListAttribute(
        ax::mojom::blink::IntListAttribute::kDetailsIds,
        {static_cast<int32_t>(popover->AXObjectID())});
    node_data->SetDetailsFrom(ax::mojom::blink::DetailsFrom::kPopoverTarget);
    return;
  }

  // Add aria-details for the element anchored to this object.
  if (AXObject* positioned_obj = GetPositionedObjectForAnchor(node_data)) {
    node_data->AddIntListAttribute(
        ax::mojom::blink::IntListAttribute::kDetailsIds,
        {static_cast<int32_t>(positioned_obj->AXObjectID())});
    node_data->SetDetailsFrom(ax::mojom::blink::DetailsFrom::kCssAnchor);
  }
}

bool AXObject::IsPlainContent() const {
  if (!ui::IsPlainContentElement(role_)) {
    return false;
  }
  for (const auto& child : ChildrenIncludingIgnored()) {
    if (!child->IsPlainContent()) {
      return false;
    }
  }
  return true;
}

// Popover invoking elements should have details relationships with their
// target popover, when that popover is:
// a) open, and
// b) not the next element in the DOM (depth first search order), and
// c) either not a hint or a rich hint.
AXObject* AXObject::GetPopoverTargetForInvoker() const {
  auto* form_element = DynamicTo<HTMLFormControlElement>(GetElement());
  if (!form_element) {
    return nullptr;
  }
  HTMLElement* popover = form_element->popoverTargetElement().popover;
  if (!popover || !popover->popoverOpen()) {
    return nullptr;
  }
  if (ElementTraversal::NextSkippingChildren(*form_element) == popover) {
    // The next element is already the popover.
    return nullptr;
  }

  AXObject* ax_popover = AXObjectCache().Get(popover);
  if (popover->PopoverType() == PopoverValueType::kHint &&
      ax_popover->IsPlainContent()) {
    return nullptr;
  }

  // Only expose a details relationship if the trigger isn't
  // contained within the popover itself (shadow-including). E.g. a close
  // button within the popover should not get a details relationship back
  // to the containing popover.
  if (GetElement()->IsDescendantOrShadowDescendantOf(popover)) {
    return nullptr;
  }

  return ax_popover;
}

// Interest target invoking elements should have details relationships with
// their interest target, when that interest target is a) visible, b) is rich,
// and c) not the next element in the DOM (depth first search order).
AXObject* AXObject::GetInterestTargetForInvoker() const {
  if (!RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled()) {
    return nullptr;
  }

  if (!GetElement()) {
    return nullptr;
  }

  Element* popover = GetElement()->interestTargetElement();
  if (ElementTraversal::NextSkippingChildren(*GetElement()) == popover) {
    // The next element is already the popover.
    return nullptr;
  }

  AXObject* ax_popover = AXObjectCache().Get(popover);
  if (!ax_popover) {
    return nullptr;
  }

  // Only expose a details relationship if the trigger isn't
  // contained within the popover itself (shadow-including).
  if (GetElement()->IsDescendantOrShadowDescendantOf(popover)) {
    return nullptr;
  }

  if (ax_popover->IsPlainContent()) {
    return nullptr;
  }

  return ax_popover;
}

AXObject* AXObject::GetPositionedObjectForAnchor(ui::AXNodeData* data) const {
  AXObject* positioned_obj = AXObjectCache().GetPositionedObjectForAnchor(this);
  if (!positioned_obj) {
    return nullptr;
  }

  // Check for cases where adding an aria-details relationship between the
  // anchor and the positioned elements would add extra noise.
  // https://github.com/w3c/html-aam/issues/545
  if (positioned_obj->RoleValue() == ax::mojom::blink::Role::kTooltip) {
    return nullptr;
  }

  // Elements are direct DOM siblings.
  if (ElementTraversal::NextSkippingChildren(*GetNode()) ==
      positioned_obj->GetElement()) {
    return nullptr;
  }

  // Check for existing labelledby/describedby/controls relationships.
  for (auto attr : {ax::mojom::blink::IntListAttribute::kLabelledbyIds,
                    ax::mojom::blink::IntListAttribute::kDescribedbyIds,
                    ax::mojom::blink::IntListAttribute::kControlsIds}) {
    auto attr_ids = data->GetIntListAttribute(attr);
    if (std::find(attr_ids.begin(), attr_ids.end(),
                  positioned_obj->AXObjectID()) != attr_ids.end()) {
      return nullptr;
    }
  }

  // Check for existing parent/child relationship (includes case where the
  // anchor has an aria-owns relationship with the positioned element).
  if (positioned_obj->ParentObject() == this) {
    return nullptr;
  }

  return positioned_obj;
}

// Try to get an aria-controls for an <input role="combobox">, because it
// helps identify focusable options in the listbox using activedescendant
// detection, even though the focus is on the textbox and not on the listbox
// ancestor.
AXObject* AXObject::GetControlsListboxForTextfieldCombobox() const {
  // Only perform work for textfields.
  if (!ui::IsTextField(RoleValue()))
    return nullptr;

  // Object is ignored for some reason, most likely hidden.
  if (IsIgnored()) {
    return nullptr;
  }

  // Authors used to be told to use aria-owns to point from the textfield to the
  // listbox. However, the aria-owns  on a textfield must be ignored for its
  // normal purpose because a textfield cannot have children. This code allows
  // the textfield's invalid aria-owns to be remapped to aria-controls.
  DCHECK(GetElement());
  const HeapVector<Member<Element>>* owned_elements =
      ElementsFromAttributeOrInternals(GetElement(), html_names::kAriaOwnsAttr);
  AXObject* listbox_candidate = nullptr;
  if (owned_elements && owned_elements->size() > 0) {
    DCHECK(owned_elements->at(0));
    listbox_candidate = AXObjectCache().Get(owned_elements->at(0));
  }

  // Combobox grouping <div role="combobox"><input><div role="listbox"></div>.
  if (!listbox_candidate && RoleValue() == ax::mojom::blink::Role::kTextField &&
      ParentObject()->RoleValue() ==
          ax::mojom::blink::Role::kComboBoxGrouping) {
    listbox_candidate = UnignoredNextSibling();
  }

  // Heuristic: try the next sibling, but we are very strict about this in
  // order to avoid false positives such as an <input> followed by a
  // <select>.
  if (!listbox_candidate &&
      RoleValue() == ax::mojom::blink::Role::kTextFieldWithComboBox) {
    // Require an aria-activedescendant on the <input>.
    if (!ElementFromAttributeOrInternals(
            GetElement(), html_names::kAriaActivedescendantAttr)) {
      return nullptr;
    }
    listbox_candidate = UnignoredNextSibling();
    if (!listbox_candidate)
      return nullptr;
    // Require that the next sibling is not a <select>.
    if (IsA<HTMLSelectElement>(listbox_candidate->GetNode()))
      return nullptr;
    // Require an ARIA role on the next sibling.
    if (!ui::IsComboBoxContainer(listbox_candidate->RawAriaRole())) {
      return nullptr;
    }
    // Naming a listbox within a composite combobox widget is not part of a
    // known/used pattern. If it has a name, it's an indicator that it's
    // probably a separate listbox widget.
    if (!listbox_candidate->ComputedName().empty())
      return nullptr;
  }

  if (!listbox_candidate ||
      !ui::IsComboBoxContainer(listbox_candidate->RoleValue())) {
    return nullptr;
  }

  return listbox_candidate;
}

const AtomicString& AXObject::GetRoleStringForSerialization(
    ui::AXNodeData* node_data) const {
  // All ARIA roles are exposed in xml-roles.
  if (const AtomicString& role_str = AriaAttribute(html_names::kRoleAttr)) {
    return role_str;
  }

  ax::mojom::blink::Role landmark_role = node_data->role;
  if (landmark_role == ax::mojom::blink::Role::kFooter) {
    // - Treat <footer> as "contentinfo" in xml-roles object attribute.
    landmark_role = ax::mojom::blink::Role::kContentInfo;
  } else if (landmark_role == ax::mojom::blink::Role::kHeader) {
    // - Treat <header> as "banner" in xml-roles object attribute.
    landmark_role = ax::mojom::blink::Role::kBanner;
  } else if (!ui::IsLandmark(node_data->role)) {
    // Landmarks are the only roles exposed in xml-roles, matching Firefox.
    return g_null_atom;
  }
  return AriaRoleName(landmark_role);
}

void AXObject::SerializeMarkerAttributes(ui::AXNodeData* node_data) const {
  // Implemented in subclasses.
}

void AXObject::SerializeImageDataAttributes(ui::AXNodeData* node_data) const {
  if (AXObjectID() != AXObjectCache().image_data_node_id()) {
    return;
  }

  // In general, string attributes should be truncated using
  // TruncateAndAddStringAttribute, but ImageDataUrl contains a data url
  // representing an image, so add it directly using AddStringAttribute.
  node_data->AddStringAttribute(
      ax::mojom::blink::StringAttribute::kImageDataUrl,
      ImageDataUrl(AXObjectCache().max_image_data_size()).Utf8());
}

void AXObject::SerializeTextInsertionDeletionOffsetAttributes(
    ui::AXNodeData* node_data) const {
  if (!IsEditable()) {
    return;
  }

  WTF::Vector<TextChangedOperation>* offsets =
      AXObjectCache().GetFromTextOperationInNodeIdMap(AXObjectID());
  if (!offsets) {
    return;
  }

  std::vector<int> start_offsets;
  std::vector<int> end_offsets;
  std::vector<int> start_anchor_ids;
  std::vector<int> end_anchor_ids;
  std::vector<int> operations_ints;

  start_offsets.reserve(offsets->size());
  end_offsets.reserve(offsets->size());
  start_anchor_ids.reserve(offsets->size());
  end_anchor_ids.reserve(offsets->size());
  operations_ints.reserve(offsets->size());

  for (auto operation : *offsets) {
    start_offsets.push_back(operation.start);
    end_offsets.push_back(operation.end);
    start_anchor_ids.push_back(operation.start_anchor_id);
    end_anchor_ids.push_back(operation.end_anchor_id);
    operations_ints.push_back(static_cast<int>(operation.op));
  }

  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kTextOperationStartOffsets,
      start_offsets);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kTextOperationEndOffsets,
      end_offsets);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kTextOperationStartAnchorIds,
      start_anchor_ids);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kTextOperationEndAnchorIds,
      end_anchor_ids);
  node_data->AddIntListAttribute(
      ax::mojom::blink::IntListAttribute::kTextOperations, operations_ints);
  AXObjectCache().ClearTextOperationInNodeIdMap();
}

bool AXObject::IsAXNodeObject() const {
  return false;
}

bool AXObject::IsAXInlineTextBox() const {
  return false;
}

bool AXObject::IsList() const {
  return ui::IsList(RoleValue());
}

bool AXObject::IsProgressIndicator() const {
  return false;
}

bool AXObject::IsAXRadioInput() const {
  return false;
}

bool AXObject::IsSlider() const {
  return false;
}

bool AXObject::IsValidationMessage() const {
  return false;
}

ax::mojom::blink::Role AXObject::ComputeFinalRoleForSerialization() const {
  // An SVG with no accessible children should be exposed as an image rather
  // than a document. See https://github.com/w3c/svg-aam/issues/12.
  // We do this check here for performance purposes: When
  // AXNodeObject::RoleFromLayoutObjectOrNode is called, that node's
  // accessible children have not been calculated. Rather than force calculation
  // there, wait until we have the full tree.
  if (role_ == ax::mojom::blink::Role::kSvgRoot &&
      IsIncludedInTree() && !UnignoredChildCount()) {
    return ax::mojom::blink::Role::kImage;
  }

  // DPUB ARIA 1.1 deprecated doc-biblioentry and doc-endnote, but it's still
  // possible to create these internal roles / platform mappings with a listitem
  // (native or ARIA) inside of a doc-bibliography or doc-endnotes section.
  if (role_ == ax::mojom::blink::Role::kListItem) {
    AXObject* ancestor = ParentObject();
    if (ancestor && ancestor->RoleValue() == ax::mojom::blink::Role::kList) {
      // Go up to the root, or next list, checking to see if the list item is
      // inside an endnote or bibliography section. If it is, remap the role.
      // The remapping does not occur for list items multiple levels deep.
      while (true) {
        ancestor = ancestor->ParentObject();
        if (!ancestor)
          break;
        ax::mojom::blink::Role ancestor_role = ancestor->RoleValue();
        if (ancestor_role == ax::mojom::blink::Role::kList)
          break;
        if (ancestor_role == ax::mojom::blink::Role::kDocBibliography)
          return ax::mojom::blink::Role::kDocBiblioEntry;
        if (ancestor_role == ax::mojom::blink::Role::kDocEndnotes)
          return ax::mojom::blink::Role::kDocEndnote;
      }
    }
  }

  if (role_ == ax::mojom::blink::Role::kHeader) {
    if (IsDescendantOfLandmarkDisallowedElement()) {
      return ax::mojom::blink::Role::kSectionHeader;
    }
  }

  if (role_ == ax::mojom::blink::Role::kFooter) {
    if (IsDescendantOfLandmarkDisallowedElement()) {
      return ax::mojom::blink::Role::kSectionFooter;
    }
  }

  // An <aside> element should not be considered a landmark region
  // if it is a child of a landmark disallowed element, UNLESS it has
  // an accessible name.
  if (role_ == ax::mojom::blink::Role::kComplementary &&
      RawAriaRole() != ax::mojom::blink::Role::kComplementary) {
    if (IsDescendantOfLandmarkDisallowedElement() &&
        !IsNameFromAuthorAttribute()) {
      return ax::mojom::blink::Role::kGenericContainer;
    }
  }

  // Treat a named <section> as role="region".
  if (role_ == ax::mojom::blink::Role::kSection) {
    return IsNameFromAuthorAttribute()
               ? ax::mojom::blink::Role::kRegion
               : ax::mojom::blink::Role::kSectionWithoutName;
  }

  if (role_ == ax::mojom::blink::Role::kCell) {
    AncestorsIterator ancestor = base::ranges::find_if(
        UnignoredAncestorsBegin(), UnignoredAncestorsEnd(),
        &AXObject::IsTableLikeRole);
    if (ancestor.current_ &&
        (ancestor.current_->RoleValue() == ax::mojom::blink::Role::kGrid ||
         ancestor.current_->RoleValue() == ax::mojom::blink::Role::kTreeGrid)) {
      return ax::mojom::blink::Role::kGridCell;
    }
  }

  if (RuntimeEnabledFeatures::AccessibilityMinRoleTabbableEnabled()) {
    // Expose focused generic containers as a group.
    // Focused generics also get a repaired name from contents.
    // Therefore, the event generator will also fire role and name change events
    // as they receive focus.
    if (role_ == ax::mojom::blink::Role::kGenericContainer && IsFocused() &&
        !HasAriaAttribute(html_names::kRoleAttr)) {
      return ax::mojom::blink::Role::kGroup;
    }
  }

  // TODO(accessibility): Consider moving the image vs. image map role logic
  // here. Currently it is implemented in AXPlatformNode subclasses and thus
  // not available to the InspectorAccessibilityAgent.
  return role_;
}

ax::mojom::blink::Role AXObject::RoleValue() const {
  return role_;
}

bool AXObject::IsARIATextField() const {
  if (IsAtomicTextField())
    return false;  // Native role supercedes the ARIA one.
  return RawAriaRole() == ax::mojom::blink::Role::kTextField ||
         RawAriaRole() == ax::mojom::blink::Role::kSearchBox ||
         RawAriaRole() == ax::mojom::blink::Role::kTextFieldWithComboBox;
}

bool AXObject::IsButton() const {
  return ui::IsButton(RoleValue());
}

bool AXObject::ShouldUseComboboxMenuButtonRole() const {
  DCHECK(GetElement());
  if (GetElement()->SupportsFocus(
          Element::UpdateBehavior::kNoneForAccessibility) !=
      FocusableState::kNotFocusable) {
    return true;
  }
  if (IsA<HTMLButtonElement>(GetNode())) {
    return true;
  }
  if (auto* input = DynamicTo<HTMLInputElement>(GetNode())) {
    if (input && input->IsButton()) {
      return true;
    }
  }
  return false;
}

bool AXObject::IsCanvas() const {
  return RoleValue() == ax::mojom::blink::Role::kCanvas;
}

bool AXObject::IsColorWell() const {
  return RoleValue() == ax::mojom::blink::Role::kColorWell;
}

bool AXObject::IsControl() const {
  return ui::IsControl(RoleValue());
}

bool AXObject::IsDefault() const {
  return false;
}

bool AXObject::IsFieldset() const {
  return false;
}

bool AXObject::IsHeading() const {
  return ui::IsHeading(RoleValue());
}

bool AXObject::IsImage() const {
  // Canvas is not currently included so that it is not exposed unless there is
  // a label, fallback content or something to make it accessible. This decision
  // may be revisited at a later date.
  return ui::IsImage(RoleValue()) &&
         RoleValue() != ax::mojom::blink::Role::kCanvas;
}

bool AXObject::IsInputImage() const {
  return false;
}

bool AXObject::IsLink() const {
  return ui::IsLink(RoleValue());
}

bool AXObject::IsImageMapLink() const {
  return false;
}

bool AXObject::IsMenu() const {
  return RoleValue() == ax::mojom::blink::Role::kMenu;
}

bool AXObject::IsCheckable() const {
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kCheckBox:
    case ax::mojom::blink::Role::kMenuItemCheckBox:
    case ax::mojom::blink::Role::kMenuItemRadio:
    case ax::mojom::blink::Role::kRadioButton:
    case ax::mojom::blink::Role::kSwitch:
    case ax::mojom::blink::Role::kToggleButton:
      return true;
    case ax::mojom::blink::Role::kTreeItem:
    case ax::mojom::blink::Role::kListBoxOption:
    case ax::mojom::blink::Role::kMenuListOption:
      return AriaTokenAttribute(html_names::kAriaCheckedAttr) != g_null_atom;
    default:
      return false;
  }
}

ax::mojom::blink::CheckedState AXObject::CheckedState() const {
  const Node* node = GetNode();
  if (!IsCheckable() || !node) {
    return ax::mojom::blink::CheckedState::kNone;
  }

  // First test for native checked state
  if (IsA<HTMLInputElement>(*node)) {
    const auto* input = DynamicTo<HTMLInputElement>(node);
    if (!input) {
      return ax::mojom::blink::CheckedState::kNone;
    }

    const auto inputType = input->type();
    // The native checked state is processed exlusively. Aria is ignored because
    // the native checked value takes precedence for input elements with type
    // `checkbox` or `radio` according to the HTML-AAM specification.
    if (inputType == input_type_names::kCheckbox ||
        inputType == input_type_names::kRadio) {
      // Expose native checkbox mixed state as accessibility mixed state (unless
      // the role is switch). However, do not expose native radio mixed state as
      // accessibility mixed state. This would confuse the JAWS screen reader,
      // which reports a mixed radio as both checked and partially checked, but
      // a native mixed native radio button simply means no radio buttons have
      // been checked in the group yet.
      if (IsNativeCheckboxInMixedState(node)) {
        return ax::mojom::blink::CheckedState::kMixed;
      }

      return input->ShouldAppearChecked()
                 ? ax::mojom::blink::CheckedState::kTrue
                 : ax::mojom::blink::CheckedState::kFalse;
    }
  }

  // Try ARIA checked/pressed state
  const ax::mojom::blink::Role role = RoleValue();
  const QualifiedName& prop = role == ax::mojom::blink::Role::kToggleButton
                                  ? html_names::kAriaPressedAttr
                                  : html_names::kAriaCheckedAttr;
  const AtomicString& checked_attribute = AriaTokenAttribute(prop);
  if (checked_attribute) {
    if (EqualIgnoringASCIICase(checked_attribute, "mixed")) {
      if (role == ax::mojom::blink::Role::kCheckBox ||
          role == ax::mojom::blink::Role::kMenuItemCheckBox ||
          role == ax::mojom::blink::Role::kListBoxOption ||
          role == ax::mojom::blink::Role::kToggleButton ||
          role == ax::mojom::blink::Role::kTreeItem) {
        // Mixed value is supported in these roles: checkbox, menuitemcheckbox,
        // option, togglebutton, and treeitem.
        return ax::mojom::blink::CheckedState::kMixed;
      } else {
        // Mixed value is not supported in these roles: radio, menuitemradio,
        // and switch.
        return ax::mojom::blink::CheckedState::kFalse;
      }
    }

    // Anything other than "false" should be treated as "true".
    return EqualIgnoringASCIICase(checked_attribute, "false")
               ? ax::mojom::blink::CheckedState::kFalse
               : ax::mojom::blink::CheckedState::kTrue;
  }

  return ax::mojom::blink::CheckedState::kFalse;
}

String AXObject::GetValueForControl() const {
  return String();
}

String AXObject::GetValueForControl(AXObjectSet& visited) const {
  return String();
}

String AXObject::SlowGetValueForControlIncludingContentEditable() const {
  return String();
}

String AXObject::SlowGetValueForControlIncludingContentEditable(
    AXObjectSet& visited) const {
  return String();
}

bool AXObject::IsNativeCheckboxInMixedState(const Node* node) {
  const auto* input = DynamicTo<HTMLInputElement>(node);
  if (!input)
    return false;

  const auto inputType = input->type();
  if (inputType != input_type_names::kCheckbox)
    return false;
  return input->ShouldAppearIndeterminate();
}

bool AXObject::IsMenuRelated() const {
  return ui::IsMenuRelated(RoleValue());
}

bool AXObject::IsMeter() const {
  return RoleValue() == ax::mojom::blink::Role::kMeter;
}

bool AXObject::IsNativeImage() const {
  return false;
}

bool AXObject::IsNativeSpinButton() const {
  return false;
}

bool AXObject::IsAtomicTextField() const {
  return blink::IsTextControl(GetNode());
}

bool AXObject::IsNonAtomicTextField() const {
  // Consivably, an <input type=text> or a <textarea> might also have the
  // contenteditable attribute applied. In such cases, the <input> or <textarea>
  // tags should supercede.
  if (IsAtomicTextField())
    return false;
  return HasContentEditableAttributeSet() || IsARIATextField();
}

AXObject* AXObject::GetTextFieldAncestor() {
  AXObject* ancestor = this;
  while (ancestor && !ancestor->IsTextField()) {
    ancestor = ancestor->ParentObject();
  }
  return ancestor;
}

bool AXObject::IsPasswordField() const {
  auto* input_element = DynamicTo<HTMLInputElement>(GetNode());
  return input_element &&
         input_element->FormControlType() == FormControlType::kInputPassword;
}

bool AXObject::IsPasswordFieldAndShouldHideValue() const {
  if (!IsPasswordField())
    return false;
  const Settings* settings = GetDocument()->GetSettings();
  return settings && !settings->GetAccessibilityPasswordValuesEnabled();
}

bool AXObject::IsPresentational() const {
  return ui::IsPresentational(RoleValue());
}

bool AXObject::IsTextObject() const {
  // Objects with |ax::mojom::blink::Role::kLineBreak| are HTML <br> elements
  // and are not backed by DOM text nodes. We can't mark them as text objects
  // for that reason.
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kInlineTextBox:
    case ax::mojom::blink::Role::kStaticText:
      return true;
    default:
      return false;
  }
}

bool AXObject::IsRangeValueSupported() const {
  if (RoleValue() == ax::mojom::blink::Role::kSplitter) {
    // According to the ARIA spec, role="separator" acts as a splitter only
    // when focusable, and supports a range only in that case.
    return CanSetFocusAttribute();
  }
  return ui::IsRangeValueSupported(RoleValue());
}

bool AXObject::IsScrollbar() const {
  return RoleValue() == ax::mojom::blink::Role::kScrollBar;
}

bool AXObject::IsNativeSlider() const {
  return false;
}

bool AXObject::IsSpinButton() const {
  return RoleValue() == ax::mojom::blink::Role::kSpinButton;
}

bool AXObject::IsTabItem() const {
  return RoleValue() == ax::mojom::blink::Role::kTab;
}

bool AXObject::IsTextField() const {
  if (IsDetached())
    return false;
  return IsAtomicTextField() || IsNonAtomicTextField();
}

bool AXObject::IsAutofillAvailable() const {
  return false;
}

bool AXObject::IsClickable() const {
  return ui::IsClickable(RoleValue());
}

AccessibilityExpanded AXObject::IsExpanded() const {
  return kExpandedUndefined;
}

bool AXObject::IsFocused() const {
  return false;
}

bool AXObject::IsHovered() const {
  return false;
}

bool AXObject::IsLineBreakingObject() const {
  // We assume that most images on the Web are inline.
  return !IsImage() && ui::IsStructure(RoleValue()) &&
         !IsA<SVGElement>(GetNode());
}

bool AXObject::IsLinked() const {
  return false;
}

bool AXObject::IsLoaded() const {
  return false;
}

bool AXObject::IsMultiSelectable() const {
  return false;
}

bool AXObject::IsRequired() const {
  return false;
}

AccessibilitySelectedState AXObject::IsSelected() const {
  return kSelectedStateUndefined;
}

bool AXObject::IsSelectedFromFocusSupported() const {
  return false;
}

bool AXObject::IsSelectedFromFocus() const {
  return false;
}

bool AXObject::IsNotUserSelectable() const {
  return false;
}

bool AXObject::IsVisited() const {
  return false;
}

bool AXObject::IsIgnored() const {
  DCHECK(cached_is_ignored_ || !IsDetached())
      << "A detached object should always indicate that it is ignored so that "
         "it won't ever accidentally be included in the tree.";
  return cached_is_ignored_;
}

bool AXObject::IsIgnored() {
  CheckCanAccessCachedValues();
  UpdateCachedAttributeValuesIfNeeded();
#if defined(AX_FAIL_FAST_BUILD)
  if (!cached_is_ignored_ && IsDetached()) {
    NOTREACHED()
        << "A detached node cannot be ignored: " << this
        << "\nThe Detach() method sets cached_is_ignored_ to true, but "
           "something has recomputed it.";
  }
#endif
  return cached_is_ignored_;
}

bool AXObject::IsIgnoredButIncludedInTree() const {
  return cached_is_ignored_but_included_in_tree_;
}

bool AXObject::IsIgnoredButIncludedInTree() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_ignored_but_included_in_tree_;
}

// IsIncludedInTree should be true for all nodes that should be
// included in the tree, even if they are ignored
bool AXObject::CachedIsIncludedInTree() const {
  return !cached_is_ignored_ || cached_is_ignored_but_included_in_tree_;
}

bool AXObject::IsIncludedInTree() const {
  return CachedIsIncludedInTree();
}

bool AXObject::IsIncludedInTree() {
  return !IsIgnored() || IsIgnoredButIncludedInTree();
}
"""


```
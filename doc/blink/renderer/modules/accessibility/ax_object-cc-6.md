Response:
My thinking process to analyze the provided C++ code snippet for `AXObject::cc` in Chromium's Blink engine went like this:

1. **Understand the Goal:** The request asks for a functional summary of the code, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user/programming errors, debugging hints, and a high-level summary considering it's part 7 of 10.

2. **Identify the Core Class:** The file is `ax_object.cc`, and the code revolves around the `AXObject` class. This immediately tells me it's related to Accessibility (AX).

3. **Scan for Key Functionality:** I read through the code, looking for methods and their apparent purpose. I paid attention to:
    * **Static methods:** These often provide utility or factory-like functions related to `AXObject` but don't operate on a specific instance. I noticed `ElementsFromAttributeOrInternals`, `ElementFromAttributeOrInternals`, `HasAriaLabelledbyElements`, and `IsNameFromAriaAttribute`. These clearly deal with fetching elements based on ARIA attributes.
    * **Instance methods related to ARIA:**  Methods like `IsNameFromAuthorAttribute`, `Orientation`, `SupportsARIAExpanded`, `LiveRegionStatus`, `LiveRegionRelevant`, `IsDisabled`, `Restriction`, `RawAriaRole`, `DetermineRawAriaRole`, `DetermineAriaRole`, `HasPopup`, `IsPopup`, `IsEditable`, `IsMultiline`, `IsRichlyEditable`, `LiveRegionAtomic`, `ContainerLiveRegionStatus`, `ContainerLiveRegionRelevant`, `ContainerLiveRegionAtomic`, and `ContainerLiveRegionBusy`. These are central to how the accessibility tree reflects ARIA attributes.
    * **Methods related to the object hierarchy:**  `IndexInParent`, `IsOnlyChild`, `IsInMenuListSubtree`, `AncestorMenuListOption`, `AncestorMenuList`, `FirstChildIncludingIgnored`, `LastChildIncludingIgnored`, `NextSiblingIncludingIgnored`, `PreviousSiblingIncludingIgnored`, `NextInPreOrderIncludingIgnored`, `PreviousInPreOrderIncludingIgnored`, `PreviousInPostOrderIncludingIgnored`, `FirstObjectWithRole`, `UnignoredChildCount`, `UnignoredChildAt`, `UnignoredNextSibling`, `UnignoredPreviousSibling`. These are about traversing and understanding the structure of the accessibility tree.
    * **Methods related to text content:** `TextLength`, `TextOffsetInFormattingContext`, `TextOffsetInContainer`, `TextCharacterOffsets`, `GetWordBoundaries`.
    * **Methods related to actions:** `Action`.
    * **Methods related to hit testing:** `ElementAccessibilityHitTest`.
    * **Helper methods and iterators:** `UnignoredAncestorsBegin`, `UnignoredAncestorsEnd`.
    * **Caching related methods:** `ComputeIsInMenuListSubtree`.

4. **Categorize Functionality:**  Based on the scanned methods, I grouped the functionalities into logical categories:
    * **ARIA Attribute Handling:** Getting elements by ARIA attributes, checking for ARIA attributes, determining the accessible name based on ARIA, handling `aria-expanded`, `aria-live`, `aria-disabled`, `aria-readonly`, and `role`.
    * **Accessibility Tree Traversal:** Getting parent, children, siblings (including and excluding ignored nodes), and traversing the tree in different orders.
    * **Object Properties:**  Checking if an object is editable, multiline, part of a menu list, a live region root, disabled, etc.
    * **Actions:** Determining the default action associated with an object.
    * **Text Information:**  Getting the length and boundaries of text within an accessible object.
    * **Hit Testing:** Determining which accessible object is at a given point.

5. **Connect to Web Technologies:** I considered how each category relates to HTML, CSS, and JavaScript:
    * **HTML:** ARIA attributes are directly embedded in HTML elements. The structure of the HTML document influences the accessibility tree. Semantic HTML elements have default roles.
    * **CSS:** CSS `display: none` and `visibility: hidden` can affect whether an element is included in the accessibility tree (ignored). CSS properties don't directly map to ARIA attributes but influence the visual representation.
    * **JavaScript:** JavaScript can dynamically modify HTML attributes, including ARIA attributes. This can trigger updates to the accessibility tree. JavaScript is often used to implement interactive elements that require ARIA to convey their behavior.

6. **Develop Examples (Input/Output, Usage Errors):** For each category, I brainstormed simple examples to illustrate the functionality and potential errors:
    * **Input/Output:** Focused on what a function would return given specific HTML structures and ARIA attributes.
    * **Usage Errors:** Considered common mistakes developers make when using ARIA, such as incorrect attribute usage, missing required attributes, or conflicting ARIA and native HTML semantics.

7. **Consider User Interaction and Debugging:** I thought about how a user interacting with a webpage triggers the code and how developers could debug issues:
    * **User Interaction:**  Mouse clicks, keyboard navigation, screen reader interaction all rely on the accessibility tree.
    * **Debugging:**  Using accessibility developer tools in browsers to inspect the accessibility tree and ARIA attributes.

8. **Address the "Part 7 of 10" Aspect:**  Since this is part of a larger series, I inferred that the file likely covers a significant portion of the `AXObject`'s core functionality. Earlier parts might have dealt with object creation or basic properties, while later parts might cover more specialized aspects.

9. **Structure the Response:** I organized my findings according to the prompt's requirements: functionality, relationships to web technologies, logical reasoning examples, usage errors, debugging, and the overall summary. I used clear headings and bullet points to improve readability.

10. **Refine and Review:** I reread my analysis to ensure accuracy, clarity, and completeness, making sure I addressed all parts of the original request. I double-checked my examples for correctness. For instance, I initially might have just said "gets ARIA attributes," but refined it to be more specific, like "gets elements referenced by `aria-labelledby`."

By following these steps, I could systematically analyze the code snippet and generate a comprehensive and informative response. The key was to understand the role of `AXObject` in the accessibility pipeline and how it interacts with web content.
这是第7部分，我们将归纳一下 `blink/renderer/modules/accessibility/ax_object.cc` 文件的功能。

**功能归纳：**

总的来说，`ax_object.cc` 文件是 Chromium Blink 引擎中负责 **可访问性对象 (`AXObject`)** 核心逻辑实现的关键部分。它定义了 `AXObject` 类的各种方法，用于表示和操作网页元素在可访问性树中的信息。

**主要功能可以概括为以下几点：**

1. **获取与 ARIA 属性相关的元素:**  提供静态方法来根据 ARIA 属性（如 `aria-labelledby`, `aria-activedescendant`）或元素内部属性（ElementInternals）查找关联的 HTML 元素。

2. **判断元素名称的来源:** 检查元素的名称是否来源于 ARIA 属性（`aria-label`, `aria-labelledby`）或 HTML 属性（`title`）。

3. **获取/判断对象属性:** 提供方法来获取和判断 `AXObject` 的各种属性，例如：
    * `Orientation()`:  获取对象的方向（水平、垂直等）。
    * `IsDisabled()`: 判断对象是否被禁用。
    * `Restriction()`: 获取对象的限制状态（禁用、只读）。
    * `LiveRegionStatus()`: 获取对象的 Live Region 状态（off, polite, assertive）。
    * `LiveRegionRelevant()`: 获取 Live Region 的相关性设置。
    * `LiveRegionAtomic()`: 判断 Live Region 的更新是否是原子性的。
    * `IsEditable()`: 判断对象是否可编辑。
    * `IsMultiline()`: 判断文本框是否是多行的。
    * `IsRichlyEditable()`: 判断对象是否是富文本可编辑区域。
    * `HasPopup()`:  指示元素是否拥有弹出窗口。
    * `IsPopup()`: 指示元素本身是否是弹出窗口。

4. **处理 ARIA Role:**  提供方法来确定 `AXObject` 的 ARIA 角色，包括原始角色 (`RawAriaRole`) 和最终确定的角色 (`DetermineAriaRole`)，并考虑了 role="presentation" 的特殊情况。

5. **确定默认操作:**  `Action()` 方法根据 `AXObject` 的角色和状态，确定其默认操作动词（例如，"Press" for button, "Select" for list box option）。

6. **处理对象层级关系:**  提供方法来获取 `AXObject` 在可访问性树中的父节点、子节点和兄弟节点，包括忽略和不忽略被忽略节点的情况。
    * `IndexInParent()`: 获取对象在其父节点中的索引。
    * `IsOnlyChild()`: 判断对象是否是其父节点的唯一子节点。
    * `FirstChildIncludingIgnored()`, `LastChildIncludingIgnored()`, `NextSiblingIncludingIgnored()`, `PreviousSiblingIncludingIgnored()`:  用于遍历包括被忽略节点在内的子节点和兄弟节点。
    * `UnignoredChildren()`, `UnignoredNextSibling()`, `UnignoredPreviousSibling()`: 用于遍历不包括被忽略节点的子节点和兄弟节点。

7. **处理文本内容:** 提供方法来获取和操作 `AXObject` 中的文本内容，例如：
    * `TextLength()`: 获取文本长度。
    * `TextOffsetInFormattingContext()`, `TextOffsetInContainer()`: 获取文本偏移量。
    * `TextCharacterOffsets()`, `GetWordBoundaries()`: 获取字符和单词的边界。

8. **处理 Live Region:**  识别 Live Region 根节点，并获取相关的属性。

9. **命中测试:** `ElementAccessibilityHitTest()` 方法用于判断给定坐标点命中了哪个可访问性对象。

10. **菜单列表支持:** 提供方法来判断对象是否在菜单列表的子树中，以及获取祖先菜单列表和菜单列表选项。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**  `AXObject` 的很多功能都直接对应于 HTML 元素及其属性。例如：
    * `IsDisabled()`:  与 HTML 元素的 `disabled` 属性相关。如果一个 HTML 元素（如 `<button>`）设置了 `disabled` 属性，那么对应的 `AXObject` 的 `IsDisabled()` 将返回 `true`。
    * `IsNameFromAuthorAttribute()`:  会检查 HTML 元素的 `title` 属性。例如，`<img title="描述">` 会使 `IsNameFromAuthorAttribute()` 返回 `true`。
    * ARIA 属性的处理 (例如 `aria-label`, `aria-labelledby`, `aria-live` 等) 直接对应于 HTML 元素上设置的 ARIA 属性。
    * `RoleValue()`:  会考虑 HTML 元素的默认语义 (例如 `<button>` 默认的角色是 `button`) 以及 `role` 属性的设置。

* **CSS:**  CSS 的某些属性会影响 `AXObject` 的某些行为，特别是 `display: none` 和 `visibility: hidden` 会导致元素被从可访问性树中忽略。虽然这个文件本身不直接处理 CSS，但它所代表的 `AXObject` 会受到 CSS 的影响。

* **JavaScript:** JavaScript 可以动态修改 HTML 结构和属性，包括 ARIA 属性。这些修改会触发可访问性树的更新，从而影响 `AXObject` 的状态和属性。
    * **假设输入:** JavaScript 代码使用 `element.setAttribute('aria-label', '新的标签');` 修改了一个按钮的 `aria-label` 属性。
    * **输出:**  与该按钮对应的 `AXObject` 实例，其 `IsNameFromAriaAttribute()` 将返回 `true`，并且其 accessible name 将会更新为 "新的标签"。

**逻辑推理的假设输入与输出：**

* **假设输入:**  一个 `<div>` 元素设置了 `role="combobox"`，并且包含一个 `<input>` 子元素。
* **输出:**  `DetermineAriaRole()` 方法会判断该 `AXObject` 的最终角色为 `ax::mojom::blink::Role::kTextFieldWithComboBox`，因为它是一个 `combobox` 并且包含一个可输入的文本字段。

* **假设输入:** 一个 `<a>` 元素设置了 `aria-expanded="true"`。
* **输出:** `SupportsARIAExpanded()` 方法将返回 `true`，表示该 `AXObject` 支持 `aria-expanded` 属性。

**用户或编程常见的使用错误举例说明：**

* **错误使用 ARIA 属性:**
    * **错误:**  在一个不应该支持 `aria-expanded` 的元素上（例如 `<span>`）设置了 `aria-expanded` 属性。
    * **后果:** 尽管 `AXObject` 可能会识别到该属性，但屏幕阅读器等辅助技术可能不会正确解释或呈现。`SupportsARIAExpanded()` 方法可能返回 `false`，或者根据元素的原生语义进行处理。

* **Live Region 设置不当:**
    * **错误:**  将一个频繁更新但并不重要的区域设置为 `aria-live="assertive"`。
    * **后果:** 屏幕阅读器可能会不断打断用户的操作，影响用户体验。

* **忽略语义化 HTML:**
    * **错误:**  使用 `<div>` 模拟按钮，并添加 `role="button"`，而不是使用原生的 `<button>` 元素。
    * **后果:**  可能会遗漏一些原生的可访问性特性，并且需要手动处理更多的 ARIA 属性。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户与网页交互:** 用户通过鼠标点击、键盘操作（例如 Tab 键导航）或者使用辅助技术（例如屏幕阅读器）与网页上的元素进行交互。

2. **浏览器事件触发:** 用户的操作会触发浏览器事件（例如 `click`, `focus`, `mouseover`）。

3. **Blink 渲染引擎处理事件:** Blink 渲染引擎接收到这些事件，并根据事件类型和目标元素进行处理。

4. **可访问性树的构建和更新:**  当网页内容发生变化时（例如 DOM 结构改变、属性更新），Blink 的可访问性模块会构建或更新可访问性树。`AXObject` 就是可访问性树中的节点。

5. **`AXObject` 方法的调用:** 当需要获取某个元素的可访问性信息时（例如，屏幕阅读器需要知道当前焦点的元素的名称、角色、状态），或者当元素的状态发生变化时，就会调用 `ax_object.cc` 中 `AXObject` 的各种方法。

6. **例如，当用户 Tab 键到一个链接时:**
    * 浏览器会触发 `focus` 事件。
    * Blink 的可访问性模块会检查该链接对应的 `AXObject`。
    * 屏幕阅读器可能会请求该 `AXObject` 的 accessible name (`IsNameFromAuthorAttribute`, ARIA attributes 等会被调用) 和 role (`DetermineAriaRole` 会被调用)。
    * 屏幕阅读器可能会询问该链接的默认操作 (`Action` 方法会被调用，返回 `ax::mojom::blink::DefaultActionVerb::kJump`)。

**作为调试线索:**  当你在调试可访问性问题时，例如屏幕阅读器没有正确朗读元素的信息，或者键盘导航行为不符合预期，你可以：

* **使用浏览器的可访问性开发者工具:**  查看可访问性树，检查元素的 role、name、state 等属性是否正确。
* **设置断点:** 在 `ax_object.cc` 中与问题相关的 `AXObject` 方法上设置断点，例如 `DetermineAriaRole` 或 `IsDisabled`，来跟踪代码的执行流程，查看哪些因素影响了 `AXObject` 的属性计算。
* **检查 HTML 和 ARIA 属性:** 确保 HTML 结构正确，并且 ARIA 属性的使用符合规范。

总而言之，`ax_object.cc` 文件是 Blink 引擎中可访问性功能的核心组成部分，它定义了 `AXObject` 类的行为，使得浏览器能够将网页元素的语义信息以结构化的方式暴露给辅助技术，从而提升用户的可访问性体验。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
e);
  if (attr_associated_elements) {
    if (attr_associated_elements->empty()) {
      return nullptr;
    }
    return attr_associated_elements;
  }

  const ElementInternals* element_internals = from->GetElementInternals();
  if (!element_internals) {
    return nullptr;
  }

  const FrozenArray<Element>* element_internals_attr_elements =
      element_internals->GetElementArrayAttribute(attribute);

  if (!element_internals_attr_elements ||
      element_internals_attr_elements->empty()) {
    return nullptr;
  }

  return MakeGarbageCollected<HeapVector<Member<Element>>>(
      element_internals_attr_elements->AsVector());
}

// static
Element* AXObject::ElementFromAttributeOrInternals(
    const Element* from,
    const QualifiedName& attribute) {
  // This method only makes sense for aria-activedescendant, so make sure nobody
  // has made a typo trying to use ElementsFromAttributeOrInternals.
  DCHECK(attribute == html_names::kAriaActivedescendantAttr);

  if (!from) {
    return nullptr;
  }

  const HeapVector<Member<Element>>* vector =
      ElementsFromAttributeOrInternals(from, attribute);
  if (!vector) {
    return nullptr;
  }

  DCHECK_EQ(vector->size(), 1u);
  return vector->at(0).Get();
}

// static
bool AXObject::HasAriaLabelledbyElements(Element* from) {
  // Try both spellings, but prefer aria-labelledby, which is the official spec.
  const HeapVector<Member<Element>>* aria_labelledby_elements =
      ElementsFromAttributeOrInternals(from, html_names::kAriaLabelledbyAttr);
  if (aria_labelledby_elements && aria_labelledby_elements->size() > 0) {
    return true;
  }

  const HeapVector<Member<Element>>* aria_labeledby_elements =
      ElementsFromAttributeOrInternals(from, html_names::kAriaLabeledbyAttr);
  return aria_labeledby_elements && aria_labeledby_elements->size() > 0;
}

// static
bool AXObject::IsNameFromAriaAttribute(Element* element) {
  if (!element)
    return false;

  if (HasAriaLabelledbyElements(element)) {
    return true;
  }

  const AtomicString& aria_label =
      AriaAttribute(*element, html_names::kAriaLabelAttr);
  if (!aria_label.GetString().ContainsOnlyWhitespaceOrEmpty()) {
    return true;
  }

  return false;
}

bool AXObject::IsNameFromAuthorAttribute() const {
  return GetElement() &&
         (IsNameFromAriaAttribute(GetElement()) ||
          GetElement()->FastHasAttribute(html_names::kTitleAttr));
}

AXObject* AXObject::InPageLinkTarget() const {
  return nullptr;
}

const AtomicString& AXObject::EffectiveTarget() const {
  return g_null_atom;
}

AccessibilityOrientation AXObject::Orientation() const {
  // In ARIA 1.1, the default value for aria-orientation changed from
  // horizontal to undefined.
  return kAccessibilityOrientationUndefined;
}

AXObject* AXObject::GetChildFigcaption() const { return nullptr; }

bool AXObject::IsDescendantOfLandmarkDisallowedElement() const {
  return false;
}

void AXObject::LoadInlineTextBoxes() {}

void AXObject::LoadInlineTextBoxesHelper() {}

AXObject* AXObject::NextOnLine() const {
  return nullptr;
}

AXObject* AXObject::PreviousOnLine() const {
  return nullptr;
}

std::optional<const DocumentMarker::MarkerType>
AXObject::GetAriaSpellingOrGrammarMarker() const {
  // TODO(accessibility) It looks like we are walking ancestors when we
  // shouldn't need to do that. At the most we should need get this via
  // GetClosestElement().
  AtomicString aria_invalid_value;
  const AncestorsIterator iter = std::find_if(
      UnignoredAncestorsBegin(), UnignoredAncestorsEnd(),
      [&aria_invalid_value](const AXObject& ancestor) {
        aria_invalid_value =
            ancestor.AriaTokenAttribute(html_names::kAriaInvalidAttr);
        return aria_invalid_value || ancestor.IsLineBreakingObject();
      });

  if (iter == UnignoredAncestorsEnd())
    return std::nullopt;
  if (EqualIgnoringASCIICase(aria_invalid_value, "spelling"))
    return DocumentMarker::kSpelling;
  if (EqualIgnoringASCIICase(aria_invalid_value, "grammar"))
    return DocumentMarker::kGrammar;
  return std::nullopt;
}

void AXObject::TextCharacterOffsets(Vector<int>&) const {}

void AXObject::GetWordBoundaries(Vector<int>& word_starts,
                                 Vector<int>& word_ends) const {}

int AXObject::TextLength() const {
  if (IsAtomicTextField())
    return GetValueForControl().length();
  return 0;
}

int AXObject::TextOffsetInFormattingContext(int offset) const {
  DCHECK_GE(offset, 0);
  return offset;
}

int AXObject::TextOffsetInContainer(int offset) const {
  DCHECK_GE(offset, 0);
  return offset;
}

ax::mojom::blink::DefaultActionVerb AXObject::Action() const {
  Element* action_element = ActionElement();

  if (!action_element)
    return ax::mojom::blink::DefaultActionVerb::kNone;

  // TODO(dmazzoni): Ensure that combo box text field is handled here.
  if (IsTextField())
    return ax::mojom::blink::DefaultActionVerb::kActivate;

  if (IsCheckable()) {
    return CheckedState() != ax::mojom::blink::CheckedState::kTrue
               ? ax::mojom::blink::DefaultActionVerb::kCheck
               : ax::mojom::blink::DefaultActionVerb::kUncheck;
  }

  switch (RoleValue()) {
    case ax::mojom::blink::Role::kButton:
    case ax::mojom::blink::Role::kDisclosureTriangle:
    case ax::mojom::blink::Role::kDisclosureTriangleGrouped:
    case ax::mojom::blink::Role::kToggleButton:
      return ax::mojom::blink::DefaultActionVerb::kPress;
    case ax::mojom::blink::Role::kListBoxOption:
    case ax::mojom::blink::Role::kMenuItemRadio:
    case ax::mojom::blink::Role::kMenuItem:
    case ax::mojom::blink::Role::kMenuListOption:
      return ax::mojom::blink::DefaultActionVerb::kSelect;
    case ax::mojom::blink::Role::kLink:
      return ax::mojom::blink::DefaultActionVerb::kJump;
    case ax::mojom::blink::Role::kComboBoxMenuButton:
    case ax::mojom::blink::Role::kComboBoxSelect:
    case ax::mojom::blink::Role::kPopUpButton:
      return ax::mojom::blink::DefaultActionVerb::kOpen;
    default:
      if (action_element == GetNode())
        return ax::mojom::blink::DefaultActionVerb::kClick;
      return ax::mojom::blink::DefaultActionVerb::kClickAncestor;
  }
}

bool AXObject::SupportsARIAExpanded() const {
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kApplication:
    case ax::mojom::blink::Role::kButton:
    case ax::mojom::blink::Role::kCheckBox:
    case ax::mojom::blink::Role::kColumnHeader:
    case ax::mojom::blink::Role::kComboBoxGrouping:
    case ax::mojom::blink::Role::kComboBoxMenuButton:
    case ax::mojom::blink::Role::kComboBoxSelect:
    case ax::mojom::blink::Role::kDisclosureTriangle:
    case ax::mojom::blink::Role::kDisclosureTriangleGrouped:
    case ax::mojom::blink::Role::kGridCell:
    case ax::mojom::blink::Role::kLink:
    case ax::mojom::blink::Role::kPopUpButton:
    case ax::mojom::blink::Role::kMenuItem:
    case ax::mojom::blink::Role::kMenuItemCheckBox:
    case ax::mojom::blink::Role::kMenuItemRadio:
    case ax::mojom::blink::Role::kRow:
    case ax::mojom::blink::Role::kRowHeader:
    case ax::mojom::blink::Role::kSwitch:
    case ax::mojom::blink::Role::kTab:
    case ax::mojom::blink::Role::kTextFieldWithComboBox:
    case ax::mojom::blink::Role::kToggleButton:
    case ax::mojom::blink::Role::kTreeItem:
      return true;
    // Nonstandard. For Read Anything's Gmail thread support, likely temporary:
    // TODO(accessibility): remove once Gmail uses standards-compliant markup.
    // Alternatively, consider adding aria-expanded support to listitem.
    case ax::mojom::blink::Role::kListItem:
      return true;
    default:
      return false;
  }
}

bool DoesUndoRolePresentation(const AtomicString& name) {
  // This is the list of global ARIA properties that force
  // role="presentation"/"none" to be exposed, and does not contain ARIA
  // properties who's global status is being deprecated.
  // clang-format off
  DEFINE_STATIC_LOCAL(
      HashSet<AtomicString>, aria_global_properties,
      ({
        AtomicString("ARIA-ATOMIC"),
        AtomicString("ARIA-BRAILLEROLEDESCRIPTION"),
        AtomicString("ARIA-BUSY"),
        AtomicString("ARIA-CONTROLS"),
        AtomicString("ARIA-CURRENT"),
        AtomicString("ARIA-DESCRIBEDBY"),
        AtomicString("ARIA-DESCRIPTION"),
        AtomicString("ARIA-DETAILS"),
        AtomicString("ARIA-FLOWTO"),
        AtomicString("ARIA-GRABBED"),
        AtomicString("ARIA-KEYSHORTCUTS"),
        AtomicString("ARIA-LABEL"),
        AtomicString("ARIA-LABELEDBY"),
        AtomicString("ARIA-LABELLEDBY"),
        AtomicString("ARIA-LIVE"),
        AtomicString("ARIA-OWNS"),
        AtomicString("ARIA-RELEVANT"),
        AtomicString("ARIA-ROLEDESCRIPTION")
      }));
  // clang-format on

  return aria_global_properties.Contains(name);
}

bool AXObject::ElementHasAnyAriaAttribute(
    bool does_undo_role_presentation) const {
  auto* element = GetElement();
  if (!element)
    return false;

  // A role is considered an ARIA attribute.
  if (!does_undo_role_presentation &&
      RawAriaRole() != ax::mojom::blink::Role::kUnknown) {
    return true;
  }

  // Check for any attribute that begins with "aria-".
  AttributeCollection attributes = element->AttributesWithoutUpdate();
  for (const Attribute& attr : attributes) {
    // Attributes cache their uppercase names.
    auto name = attr.GetName().LocalNameUpper();
    if (name.StartsWith("ARIA-")) {
      if (!does_undo_role_presentation || DoesUndoRolePresentation(name))
        return true;
    }
  }

  return false;
}

int AXObject::IndexInParent() const {
  DCHECK(IsIncludedInTree())
      << "IndexInParent is only valid when a node is included in the tree";
  AXObject* ax_parent_included = ParentObjectIncludedInTree();
  if (!ax_parent_included)
    return 0;

  const AXObjectVector& siblings =
      ax_parent_included->ChildrenIncludingIgnored();

  wtf_size_t index = siblings.Find(this);

  DCHECK_NE(index, kNotFound)
      << "Could not find child in parent:" << "\nChild: " << this
      << "\nParent: " << ax_parent_included
      << "  #children=" << siblings.size();
  return (index == kNotFound) ? 0 : static_cast<int>(index);
}

bool AXObject::IsOnlyChild() const {
  DCHECK(IsIncludedInTree())
      << "IsOnlyChild is only valid when a node is included in the tree";
  AXObject* ax_parent_included = ParentObjectIncludedInTree();
  if (!ax_parent_included) {
    return false;
  }

  return ax_parent_included->ChildrenIncludingIgnored().size() == 1;
}

bool AXObject::IsInMenuListSubtree() {
  CheckCanAccessCachedValues();
  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_in_menu_list_subtree_;
}

bool AXObject::ComputeIsInMenuListSubtree() {
  if (IsRoot()) {
    return false;
  }
  return IsMenuList() || ParentObject()->IsInMenuListSubtree();
}

bool AXObject::IsMenuList() const {
  return RoleValue() == ax::mojom::blink::Role::kComboBoxSelect;
}

const AXObject* AXObject::AncestorMenuListOption() const {
  if (!IsInMenuListSubtree()) {
    return nullptr;
  }
  for (const AXObject* ax_option = this; ax_option;
       ax_option = ax_option->ParentObject()) {
    if (ax_option->RoleValue() == ax::mojom::blink::Role::kMenuListOption &&
        IsA<HTMLOptionElement>(ax_option->GetNode())) {
      return ax_option;
    }
  }

  return nullptr;
}

const AXObject* AXObject::AncestorMenuList() const {
  if (!IsInMenuListSubtree()) {
    return nullptr;
  }
  for (const AXObject* ax_menu_list = this; ax_menu_list;
       ax_menu_list = ax_menu_list->ParentObject()) {
    if (ax_menu_list->IsMenuList()) {
      DCHECK(IsA<HTMLSelectElement>(ax_menu_list->GetNode()));
      DCHECK(To<HTMLSelectElement>(ax_menu_list->GetNode())->UsesMenuList());
      DCHECK(!To<HTMLSelectElement>(ax_menu_list->GetNode())->IsMultiple());
      return ax_menu_list;
    }
  }
#if DCHECK_IS_ON()
  NOTREACHED() << "No menu list found:\n" << ParentChainToStringHelper(this);
#else
  NOTREACHED();
#endif
}

bool AXObject::IsLiveRegionRoot() const {
  const AtomicString& live_region = LiveRegionStatus();
  return !live_region.empty();
}

bool AXObject::IsActiveLiveRegionRoot() const {
  const AtomicString& live_region = LiveRegionStatus();
  return !live_region.empty() && !EqualIgnoringASCIICase(live_region, "off");
}

const AtomicString& AXObject::LiveRegionStatus() const {
  DEFINE_STATIC_LOCAL(const AtomicString, live_region_status_assertive,
                      ("assertive"));
  DEFINE_STATIC_LOCAL(const AtomicString, live_region_status_polite,
                      ("polite"));
  DEFINE_STATIC_LOCAL(const AtomicString, live_region_status_off, ("off"));

  const AtomicString& live_region_status =
      AriaTokenAttribute(html_names::kAriaLiveAttr);
  // These roles have implicit live region status.
  if (live_region_status.empty()) {
    switch (RoleValue()) {
      case ax::mojom::blink::Role::kAlert:
        return live_region_status_assertive;
      case ax::mojom::blink::Role::kLog:
      case ax::mojom::blink::Role::kStatus:
        return live_region_status_polite;
      case ax::mojom::blink::Role::kTimer:
      case ax::mojom::blink::Role::kMarquee:
        return live_region_status_off;
      default:
        break;
    }
  }

  return live_region_status;
}

const AtomicString& AXObject::LiveRegionRelevant() const {
  DEFINE_STATIC_LOCAL(const AtomicString, default_live_region_relevant,
                      ("additions text"));
  const AtomicString& relevant =
      AriaTokenAttribute(html_names::kAriaRelevantAttr);

  // Default aria-relevant = "additions text".
  if (relevant.empty())
    return default_live_region_relevant;

  return relevant;
}

bool AXObject::IsDisabled() const {
  // <embed> or <object> with unsupported plugin, or more iframes than allowed.
  if (IsEmbeddingElement()) {
    if (IsAriaHidden()) {
      return true;
    }
    auto* html_frame_owner_element = To<HTMLFrameOwnerElement>(GetElement());
    return !html_frame_owner_element->ContentFrame();
  }

  Node* node = GetNode();
  if (node) {
    // Check for HTML form control with the disabled attribute.
    if (GetElement() && GetElement()->IsDisabledFormControl()) {
      return true;
    }
    // This is for complex pickers, such as a date picker.
    if (AXObject::IsControl()) {
      Element* owner_shadow_host = node->OwnerShadowHost();
      if (owner_shadow_host &&
          owner_shadow_host->FastHasAttribute(html_names::kDisabledAttr)) {
        return true;
      }
    }
  }
  // Check aria-disabled. According to ARIA in HTML section 3.1, aria-disabled
  // attribute does NOT override the native HTML disabled attribute.
  // https://www.w3.org/TR/html-aria/
  if (IsAriaAttributeTrue(html_names::kAriaDisabledAttr)) {
    return true;
  }

  // A focusable object with a disabled container.
  return cached_is_descendant_of_disabled_node_ && CanSetFocusAttribute();
}

AXRestriction AXObject::Restriction() const {
  // According to ARIA, all elements of the base markup can be disabled.
  // According to CORE-AAM, any focusable descendant of aria-disabled
  // ancestor is also disabled.
  if (IsDisabled())
    return kRestrictionDisabled;

  // Check aria-readonly if supported by current role.
  bool is_read_only;
  if (SupportsARIAReadOnly() &&
      AriaBooleanAttribute(html_names::kAriaReadonlyAttr, &is_read_only)) {
    // ARIA overrides other readonly state markup.
    return is_read_only ? kRestrictionReadOnly : kRestrictionNone;
  }

  // This is a node that is not readonly and not disabled.
  return kRestrictionNone;
}

ax::mojom::blink::Role AXObject::RawAriaRole() const {
  return ax::mojom::blink::Role::kUnknown;
}

ax::mojom::blink::Role AXObject::DetermineRawAriaRole() const {
  const AtomicString& aria_role = AriaAttribute(html_names::kRoleAttr);
  if (aria_role.empty()) {
    return ax::mojom::blink::Role::kUnknown;
  }
  return FirstValidRoleInRoleString(aria_role);
}

ax::mojom::blink::Role AXObject::DetermineAriaRole() const {
  ax::mojom::blink::Role role = DetermineRawAriaRole();

  if ((role == ax::mojom::blink::Role::kForm ||
       role == ax::mojom::blink::Role::kRegion) &&
      !IsNameFromAuthorAttribute() &&
      !HasAriaAttribute(html_names::kAriaRoledescriptionAttr)) {
    // If form or region is nameless, use a valid fallback role (if present
    // in the role attribute) or the native element's role (by returning
    // kUnknown). We only check aria-label/aria-labelledby because those are the
    // only allowed ways to name an ARIA role.
    // TODO(accessibility) The aria-roledescription logic is required, otherwise
    // ChromeVox will ignore the aria-roledescription. It only speaks the role
    // description on certain roles, and ignores it on the generic role.
    // See also https://github.com/w3c/aria/issues/1463.
    if (const AtomicString& role_str = AriaAttribute(html_names::kRoleAttr)) {
      return FirstValidRoleInRoleString(role_str,
                                        /*ignore_form_and_region*/ true);
    }
    return ax::mojom::blink::Role::kUnknown;
  }

  // ARIA states if an item can get focus, it should not be presentational.
  // It also states user agents should ignore the presentational role if
  // the element has global ARIA states and properties.
  if (ui::IsPresentational(role)) {
    if (IsFrame(GetNode()))
      return ax::mojom::blink::Role::kIframePresentational;
    if ((GetElement() && GetElement()->SupportsFocus(
                             Element::UpdateBehavior::kNoneForAccessibility) !=
                             FocusableState::kNotFocusable) ||
        ElementHasAnyAriaAttribute(true /* does_undo_role_presentation */)) {
      // Must be exposed with a role if focusable or has a global ARIA property
      // that is allowed in this context. See
      // https://w3c.github.io/aria/#presentation for more information about the
      // conditions upon which elements with role="none"/"presentation" must be
      // included in the tree. Return Role::kUnknown, so that the native HTML
      // role is used instead.
      return ax::mojom::blink::Role::kUnknown;
    }
  }

  if (role == ax::mojom::blink::Role::kButton)
    role = ButtonRoleType();

  // Distinguish between different uses of the "combobox" role:
  //
  // ax::mojom::blink::Role::kComboBoxGrouping:
  //   <div role="combobox"><input></div>
  // ax::mojom::blink::Role::kTextFieldWithComboBox:
  //   <input role="combobox">
  // ax::mojom::blink::Role::kComboBoxMenuButton:
  //   <div tabindex=0 role="combobox">Select</div>
  // Note: make sure to exclude this aria role if the element is a <select>,
  // where this role would be redundant and may cause problems for screen
  // readers.
  if (role == ax::mojom::blink::Role::kComboBoxGrouping) {
    if (IsAtomicTextField()) {
      role = ax::mojom::blink::Role::kTextFieldWithComboBox;
    } else if (auto* select_element =
                   DynamicTo<HTMLSelectElement>(*GetNode())) {
      if (select_element->UsesMenuList() && !select_element->IsMultiple()) {
        // This is a select element. Don't set the aria role for it.
        role = ax::mojom::blink::Role::kUnknown;
      }
    } else if (ShouldUseComboboxMenuButtonRole()) {
      role = ax::mojom::blink::Role::kComboBoxMenuButton;
    }
  }

  return role;
}

ax::mojom::blink::HasPopup AXObject::HasPopup() const {
  return ax::mojom::blink::HasPopup::kFalse;
}

ax::mojom::blink::IsPopup AXObject::IsPopup() const {
  return ax::mojom::blink::IsPopup::kNone;
}

bool AXObject::IsEditable() const {
  const Node* node = GetClosestNode();
  if (IsDetached() || !node)
    return false;
#if DCHECK_IS_ON()  // Required in order to get Lifecycle().ToString()
  DCHECK(GetDocument());
  DCHECK_GE(GetDocument()->Lifecycle().GetState(),
            DocumentLifecycle::kStyleClean)
      << "Unclean document style at lifecycle state "
      << GetDocument()->Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  if (blink::IsEditable(*node))
    return true;

  // For the purposes of accessibility, atomic text fields  i.e. input and
  // textarea are editable because the user can potentially enter text in them.
  if (IsAtomicTextField())
    return true;

  return false;
}

bool AXObject::IsEditableRoot() const {
  return false;
}

bool AXObject::HasContentEditableAttributeSet() const {
  return false;
}

bool AXObject::IsMultiline() const {
  if (IsDetached() || !GetNode() || !IsTextField())
    return false;

  // While the specs don't specify that we can't do <input aria-multiline=true>,
  // it is in direct contradiction to the `HTMLInputElement` which is always
  // single line. Ensure that we can't make an input report that it's multiline
  // by returning early.
  if (IsA<HTMLInputElement>(*GetNode()))
    return false;

  bool is_multiline = false;
  if (AriaBooleanAttribute(html_names::kAriaMultilineAttr, &is_multiline)) {
    return is_multiline;
  }

  return IsA<HTMLTextAreaElement>(*GetNode()) ||
         HasContentEditableAttributeSet();
}

bool AXObject::IsRichlyEditable() const {
  const Node* node = GetClosestNode();
  if (IsDetached() || !node)
    return false;

  return node->IsRichlyEditableForAccessibility();
}

AXObject* AXObject::LiveRegionRoot() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_live_region_root_;
}

bool AXObject::LiveRegionAtomic() const {
  bool atomic = false;
  if (AriaBooleanAttribute(html_names::kAriaAtomicAttr, &atomic)) {
    return atomic;
  }

  // ARIA roles "alert" and "status" should have an implicit aria-atomic value
  // of true.
  return RoleValue() == ax::mojom::blink::Role::kAlert ||
         RoleValue() == ax::mojom::blink::Role::kStatus;
}

const AtomicString& AXObject::ContainerLiveRegionStatus() const {
  return cached_live_region_root_ ? cached_live_region_root_->LiveRegionStatus()
                                  : g_null_atom;
}

const AtomicString& AXObject::ContainerLiveRegionRelevant() const {
  return cached_live_region_root_
             ? cached_live_region_root_->LiveRegionRelevant()
             : g_null_atom;
}

bool AXObject::ContainerLiveRegionAtomic() const {
  return cached_live_region_root_ &&
         cached_live_region_root_->LiveRegionAtomic();
}

bool AXObject::ContainerLiveRegionBusy() const {
  return cached_live_region_root_ &&
         cached_live_region_root_->IsAriaAttributeTrue(
             html_names::kAriaBusyAttr);
}

AXObject* AXObject::ElementAccessibilityHitTest(const gfx::Point& point) const {
  PhysicalOffset physical_point(point);
  if (child_tree_id_ &&
      GetBoundsInFrameCoordinates().Contains(physical_point)) {
    // The children of this object are hidden by a stitched child tree, so
    // return early.
    return const_cast<AXObject*>(this);
  }
  for (const auto& child : ChildrenIncludingIgnored()) {
    if (child->IsValidationMessage() &&
        child->GetBoundsInFrameCoordinates().Contains(physical_point)) {
      return child->ElementAccessibilityHitTest(point);
    }
  }
  return const_cast<AXObject*>(this);
}

AXObject::AncestorsIterator AXObject::UnignoredAncestorsBegin() const {
  AXObject* parent = ParentObjectUnignored();
  if (parent)
    return AXObject::AncestorsIterator(*parent);
  return UnignoredAncestorsEnd();
}

AXObject::AncestorsIterator AXObject::UnignoredAncestorsEnd() const {
  return AXObject::AncestorsIterator();
}

int AXObject::ChildCountIncludingIgnored() const {
  return static_cast<int>(ChildrenIncludingIgnored().size());
}

AXObject* AXObject::ChildAtIncludingIgnored(int index) const {
  DCHECK_GE(index, 0);
  DCHECK_LE(index, ChildCountIncludingIgnored());
  if (index >= ChildCountIncludingIgnored())
    return nullptr;
  return ChildrenIncludingIgnored()[index].Get();
}

const AXObject::AXObjectVector& AXObject::ChildrenIncludingIgnored() const {
  DCHECK(!IsDetached());
  return children_;
}

const AXObject::AXObjectVector& AXObject::ChildrenIncludingIgnored() {
  UpdateChildrenIfNecessary();
  return children_;
}

const AXObject::AXObjectVector AXObject::UnignoredChildren() const {
  return const_cast<AXObject*>(this)->UnignoredChildren();
}

const AXObject::AXObjectVector AXObject::UnignoredChildren() {
  UpdateChildrenIfNecessary();

  if (!IsIncludedInTree()) {
    NOTREACHED() << "We don't support finding the unignored children of "
                    "objects excluded from the accessibility tree: "
                 << this;
  }

  // Capture only descendants that are not accessibility ignored, and that are
  // one level deeper than the current object after flattening any accessibility
  // ignored descendants.
  //
  // For example :
  // ++A
  // ++++B
  // ++++C IGNORED
  // ++++++F
  // ++++D
  // ++++++G
  // ++++E IGNORED
  // ++++++H IGNORED
  // ++++++++J
  // ++++++I
  //
  // Objects [B, F, D, I, J] will be returned, since after flattening all
  // ignored objects ,those are the ones that are one level deep.

  AXObjectVector unignored_children;
  AXObject* child = FirstChildIncludingIgnored();
  while (child && child != this) {
    if (child->IsIgnored()) {
      child = child->NextInPreOrderIncludingIgnored(this);
      continue;
    }

    unignored_children.push_back(child);
    for (; child != this; child = child->ParentObjectIncludedInTree()) {
      if (AXObject* sibling = child->NextSiblingIncludingIgnored()) {
        child = sibling;
        break;
      }
    }
  }

  return unignored_children;
}

AXObject* AXObject::FirstChildIncludingIgnored() const {
  return ChildCountIncludingIgnored() ? ChildrenIncludingIgnored().front()
                                      : nullptr;
}

AXObject* AXObject::LastChildIncludingIgnored() const {
  DCHECK(!IsDetached());
  return ChildCountIncludingIgnored() ? ChildrenIncludingIgnored().back()
                                      : nullptr;
}

AXObject* AXObject::DeepestFirstChildIncludingIgnored() const {
  if (IsDetached()) {
    NOTREACHED();
  }
  if (!ChildCountIncludingIgnored())
    return nullptr;

  AXObject* deepest_child = FirstChildIncludingIgnored();
  while (deepest_child->ChildCountIncludingIgnored())
    deepest_child = deepest_child->FirstChildIncludingIgnored();

  return deepest_child;
}

AXObject* AXObject::DeepestLastChildIncludingIgnored() const {
  if (IsDetached()) {
    NOTREACHED();
  }
  if (!ChildCountIncludingIgnored())
    return nullptr;

  AXObject* deepest_child = LastChildIncludingIgnored();
  while (deepest_child->ChildCountIncludingIgnored())
    deepest_child = deepest_child->LastChildIncludingIgnored();

  return deepest_child;
}

AXObject* AXObject::NextSiblingIncludingIgnored() const {
  if (!IsIncludedInTree()) {
    NOTREACHED() << "We don't support iterating children of objects excluded "
                    "from the accessibility tree: "
                 << this;
  }

  const AXObject* parent_in_tree = ParentObjectIncludedInTree();
  if (!parent_in_tree)
    return nullptr;

  const int index_in_parent = IndexInParent();
  if (index_in_parent < parent_in_tree->ChildCountIncludingIgnored() - 1)
    return parent_in_tree->ChildAtIncludingIgnored(index_in_parent + 1);
  return nullptr;
}

AXObject* AXObject::PreviousSiblingIncludingIgnored() const {
  if (!IsIncludedInTree()) {
    NOTREACHED() << "We don't support iterating children of objects excluded "
                    "from the accessibility tree: "
                 << this;
  }

  const AXObject* parent_in_tree = ParentObjectIncludedInTree();
  if (!parent_in_tree)
    return nullptr;

  const int index_in_parent = IndexInParent();
  if (index_in_parent > 0)
    return parent_in_tree->ChildAtIncludingIgnored(index_in_parent - 1);
  return nullptr;
}

AXObject* AXObject::CachedPreviousSiblingIncludingIgnored() const {
  if (!IsIncludedInTree()) {
    NOTREACHED() << "We don't support iterating children of objects excluded "
                    "from the accessibility tree: "
                 << this;
  }

  const AXObject* included_parent = ParentObjectIncludedInTree();
  if (!included_parent) {
    return nullptr;
  }

  const AXObjectVector& siblings =
      included_parent->CachedChildrenIncludingIgnored();

  for (wtf_size_t count = 0; count < siblings.size(); count++) {
    if (siblings[count] == this) {
      return count > 0 ? siblings[count - 1] : nullptr;
    }
  }
  return nullptr;
}

AXObject* AXObject::NextInPreOrderIncludingIgnored(
    const AXObject* within) const {
  if (!IsIncludedInTree()) {
    // TODO(crbug.com/1421052): Make sure this no longer fires then turn the
    // above into CHECK(IsIncludedInTree());
    DUMP_WILL_BE_NOTREACHED()
        << "We don't support iterating children of objects excluded "
           "from the accessibility tree: "
        << this;
    return nullptr;
  }

  if (ChildCountIncludingIgnored())
    return FirstChildIncludingIgnored();

  if (within == this)
    return nullptr;

  const AXObject* current = this;
  AXObject* next = current->NextSiblingIncludingIgnored();
  for (; !next; next = current->NextSiblingIncludingIgnored()) {
    current = current->ParentObjectIncludedInTree();
    if (!current || within == current)
      return nullptr;
  }
  return next;
}

AXObject* AXObject::PreviousInPreOrderIncludingIgnored(
    const AXObject* within) const {
  if (!IsIncludedInTree()) {
    NOTREACHED() << "We don't support iterating children of objects excluded "
                    "from the accessibility tree: "
                 << this;
  }
  if (within == this)
    return nullptr;

  if (AXObject* sibling = PreviousSiblingIncludingIgnored()) {
    if (sibling->ChildCountIncludingIgnored())
      return sibling->DeepestLastChildIncludingIgnored();
    return sibling;
  }

  return ParentObjectIncludedInTree();
}

AXObject* AXObject::PreviousInPostOrderIncludingIgnored(
    const AXObject* within) const {
  if (!IsIncludedInTree()) {
    NOTREACHED() << "We don't support iterating children of objects excluded "
                    "from the accessibility tree: "
                 << this;
  }

  if (ChildCountIncludingIgnored())
    return LastChildIncludingIgnored();

  if (within == this)
    return nullptr;

  const AXObject* current = this;
  AXObject* previous = current->PreviousSiblingIncludingIgnored();
  for (; !previous; previous = current->PreviousSiblingIncludingIgnored()) {
    current = current->ParentObjectIncludedInTree();
    if (!current || within == current)
      return nullptr;
  }
  return previous;
}

AXObject* AXObject::FirstObjectWithRole(ax::mojom::blink::Role role) const {
  AXObject* object = const_cast<AXObject*>(this);
  for (; object && object->RoleValue() != role;
       object = object->NextInPreOrderIncludingIgnored()) {
  }
  return object;
}

int AXObject::UnignoredChildCount() const {
  return static_cast<int>(UnignoredChildren().size());
}

AXObject* AXObject::UnignoredChildAt(int index) const {
  const AXObjectVector unignored_children = UnignoredChildren();
  if (index < 0 || index >= static_cast<int>(unignored_children.size()))
    return nullptr;
  return unignored_children[index].Get();
}

AXObject* AXObject::UnignoredNextSibling() const {
  if (IsIgnored()) {
    // TODO(crbug.com/1407397): Make sure this no longer fires then turn this
    // block into CHECK(!IsIgnored());
    DUMP_WILL_BE_NOTREACHED()
        << "We don't support finding unignored siblings for ignored "
           "objects because it is not clear whether to search for the "
           "sibling in the unignored tree or in the whole tree: "
        << this;
    return nullptr;
  }

  // Find the next sibling for the same unignored parent object,
  // flattening accessibility ignored objects.
  //
  // For example :
  // ++A
  // ++++B
  // ++++C IGNORED
  // ++++++E
  // ++++D
  // Objects [B, E, D] will be siblings since C is ignored.

  const AXObject* unignored_parent = ParentObjectUnignored();
  const AXObject* current_obj = this;
  while (current_obj) {
    AXObject* sibling = current_obj->NextSiblingIncludingIgnored();
    if (sibling) {
      // If we found an ignored sibling, walk in next pre-order
      // until an unignored object is found, flattening the ignored object.
      while (sibling && sibling->IsIgnored()) {
        sibling = sibling->NextInPreOrderIncludingIgnored(unignored_parent);
      }
      return sibling;
    }

    // If a sibling has not been found, try again with the parent object,
    // until the unignored parent is reached.
    current_obj = current_obj->ParentObjectIncludedInTree();
    if (!current_obj || !current_obj->IsIgnored())
      return nullptr;
  }
  return nullptr;
}

AXObject* AXObject::UnignoredPreviousSibling() const {
  if (IsIgnored()) {
    NOTREACHED() << "We don't support finding unignored siblings for ignored "
                    "objects beca
```
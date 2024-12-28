Response:
Let's break down the thought process for analyzing the `HTMLOptGroupElement.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this specific Chromium Blink engine source file. The analysis should include its relationship to web technologies (HTML, CSS, JavaScript), logical inferences with examples, and common usage errors.

2. **Identify the Core Entity:** The file name `html_opt_group_element.cc` immediately tells us this file is about the implementation of the `<optgroup>` HTML element within the Blink rendering engine.

3. **Scan for Key Concepts and Function Names:**  A quick skim of the code reveals several important terms and functions:
    * `HTMLOptGroupElement` (the class being implemented)
    * `Document` (web page context)
    * `HTMLElement` (its base class, indicating it's a DOM element)
    * `HTMLSelectElement` (its parent element, crucial for understanding its purpose)
    * `HTMLOptionElement` (its children, the actual selectable options)
    * `HTMLSlotElement` (related to shadow DOM and content distribution)
    * `HTMLLegendElement` (used as an alternative way to label the group)
    * `kDisabledAttr`, `kLabelAttr` (key HTML attributes)
    * `IsDisabledFormControl()`, `ParseAttribute()`, `SupportsFocus()` (methods reflecting its behavior)
    * `ChildrenChanged()` (handling dynamic updates to its content)
    * `InsertedInto()`, `RemovedFrom()` (lifecycle methods when added/removed from the DOM)
    * `GroupLabelText()`, `LabelAttributeText()` (methods for retrieving the group label)
    * `OwnerSelectElement()` (finding its parent `<select>` element)
    * `DefaultToolTip()`
    * `AccessKeyAction()` (keyboard accessibility)
    * `DidAddUserAgentShadowRoot()` (setting up the internal structure)
    * `ManuallyAssignSlots()` (managing content within the shadow DOM)
    * `UpdateGroupLabel()` (updating the visual label)

4. **Infer Functionality Based on Keywords:**

    * **`HTMLOptGroupElement` and its methods:** This class represents the `<optgroup>` element in the browser's internal representation. Its methods control how it behaves, how it responds to attribute changes, how it interacts with its children and parent, and how it's rendered.
    * **`HTMLSelectElement`:** The frequent interaction with `HTMLSelectElement` clearly indicates the core purpose of `<optgroup>` is to organize options within a `<select>` dropdown.
    * **`HTMLOptionElement`:** The mention of inserting and removing `HTMLOptionElement` confirms `<optgroup>` is a container for these options.
    * **`kDisabledAttr`:** The handling of the `disabled` attribute suggests the `<optgroup>` can be disabled, affecting all its child options.
    * **`kLabelAttr`:** The handling of the `label` attribute signifies it's the primary way to provide a visual label for the option group.
    * **`HTMLSlotElement` and Shadow DOM:**  The presence of `HTMLSlotElement` and `DidAddUserAgentShadowRoot` indicates the use of Shadow DOM for encapsulating the internal structure and styling of the `<optgroup>`. This is a key optimization and implementation detail.
    * **`HTMLLegendElement`:** The handling of `<legend>` within the `<optgroup>` suggests an alternative way to label the group, specific to certain rendering modes.

5. **Connect to Web Technologies:**

    * **HTML:** The file directly implements the `<optgroup>` HTML tag, controlling its structure and attributes.
    * **CSS:** The methods like `PseudoStateChanged` and setting inline styles (e.g., `kDisplay`, `kPadding`) show how the `<optgroup>`'s appearance is affected by CSS, including pseudo-classes like `:disabled`.
    * **JavaScript:** While this C++ code isn't JavaScript, it *enables* JavaScript functionality. JavaScript can interact with `<optgroup>` elements (e.g., setting the `disabled` attribute, accessing the `label`, dynamically adding/removing options) because this C++ code provides the underlying DOM representation and behavior that JavaScript manipulates.

6. **Formulate Logical Inferences and Examples:**

    * **Disabled State:** If the `disabled` attribute is present, the `IsDisabledFormControl()` method will return true, and the element (and likely its options) will be visually disabled and not interactable.
    * **Labeling:** The `label` attribute is the standard way to label the group. The code handles both the `label` attribute and the `<legend>` element as alternative labeling mechanisms, demonstrating flexibility.
    * **Option Management:** When options are added or removed within an `<optgroup>`, the `ChildrenChanged()` method updates the associated `<select>` element.

7. **Identify Common Usage Errors:**

    * **Incorrect Nesting:**  The `OwnerSelectElement()` method checks for invalid nesting (e.g., `<optgroup>` inside another `<optgroup>` or `<option>`).
    * **Misunderstanding `disabled`:** Forgetting that disabling an `<optgroup>` disables all its options.
    * **Labeling Issues:**  Not providing a label (either via `label` attribute or `<legend>`), leading to an unlabeled group.

8. **Structure the Answer:** Organize the findings into logical sections (Functionality, Relationship to Web Technologies, Logical Inferences, Common Usage Errors). Use clear language and provide concrete examples.

9. **Refine and Review:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check for any jargon that needs explanation. For example, initially, I might just say "Shadow DOM," but it's better to briefly explain *why* it's used (encapsulation, internal structure).

This methodical approach, combining code scanning, keyword identification, inferential reasoning, and connection to web technologies, allows for a comprehensive analysis of the provided source code. The focus is on understanding not just *what* the code does, but *why* and how it fits into the larger web development ecosystem.
这个文件 `blink/renderer/core/html/forms/html_opt_group_element.cc` 是 Chromium Blink 引擎中负责实现 HTML `<optgroup>` 元素功能的 C++ 代码。 `<optgroup>` 元素用于在 HTML `<select>` 元素中对相关的 `<option>` 元素进行分组，从而提供更好的用户体验和表单结构。

以下是该文件的主要功能：

**1. 表示和管理 `<optgroup>` 元素：**

*   该文件定义了 `HTMLOptGroupElement` 类，该类继承自 `HTMLElement`，用于在 Blink 渲染引擎中表示一个 `<optgroup>` 元素。
*   它处理 `<optgroup>` 元素的属性解析，例如 `disabled` 和 `label` 属性。
*   它维护了 `<optgroup>` 元素的状态，例如是否被禁用。

**2. 处理禁用状态：**

*   `IsDisabledFormControl()` 方法用于判断 `<optgroup>` 元素是否被禁用（通过 `disabled` 属性）。
*   当 `disabled` 属性发生变化时，`ParseAttribute()` 方法会更新元素的状态，并触发相应的伪类状态变化 (`:disabled`, `:enabled`)，这会影响 CSS 样式。

**3. 处理标签（Label）：**

*   `ParseAttribute()` 方法会监测 `label` 属性的变化。
*   `GroupLabelText()` 和 `LabelAttributeText()` 方法用于获取 `<optgroup>` 元素的标签文本。
*   当启用可定制的 `<select>` 渲染时，它还支持使用 `<legend>` 元素作为 `<optgroup>` 的标签。
*   `UpdateGroupLabel()` 方法负责更新用户代理阴影根中用于显示标签的元素的文本内容和 `aria-label` 属性。

**4. 与 `<select>` 元素的交互：**

*   `OwnerSelectElement()` 方法用于获取拥有该 `<optgroup>` 元素的 `<select>` 元素。
*   `InsertedInto()` 和 `RemovedFrom()` 方法在 `<optgroup>` 元素被插入或移除到 DOM 树时被调用，并通知其父 `<select>` 元素。
*   `ChildrenChanged()` 方法在 `<optgroup>` 的子节点发生变化时被调用，例如添加或移除 `<option>` 元素，并通知父 `<select>` 元素进行相应的更新。这确保了 `<select>` 元素能够正确地维护其选项列表。

**5. 焦点管理：**

*   `SupportsFocus()` 方法决定 `<optgroup>` 元素是否可以获得焦点。通常，`<optgroup>` 自身不能获得焦点，焦点会落在其包含的 `<option>` 元素上。但在某些情况下（例如使用菜单列表渲染 `<select>`），`<optgroup>` 也可能不获得焦点。
*   `AccessKeyAction()` 方法处理访问键（accesskey）事件，它会将焦点传递给父 `<select>` 元素。

**6. 用户代理阴影根（User-Agent Shadow Root）：**

*   `DidAddUserAgentShadowRoot()` 方法在创建用户代理阴影根时被调用。它会在阴影根中创建用于显示 `<optgroup>` 标签的 `<div>` 元素和一个 `<slot>` 元素。
*   `<slot>` 元素用于投影 `<optgroup>` 的子节点（`<option>` 元素）。
*   `ManuallyAssignSlots()` 方法负责将 `<option>` 和 `<hr>` 元素手动分配到阴影根的 `<slot>` 中。

**与 Javascript, HTML, CSS 的关系：**

*   **HTML:**  该文件是 `<optgroup>` HTML 元素的底层实现。它处理了 HTML 结构中 `<optgroup>` 标签的解析和渲染。例如，当 HTML 解析器遇到 `<optgroup label="Group 1">` 时，Blink 引擎会创建 `HTMLOptGroupElement` 的实例，并调用 `ParseAttribute()` 方法来处理 `label` 属性。
*   **Javascript:** Javascript 可以通过 DOM API 操作 `<optgroup>` 元素，例如：
    *   获取和设置 `disabled` 和 `label` 属性： `element.disabled = true;` 或 `element.label = "New Group";`  这些操作最终会触发 `HTMLOptGroupElement` 中的相应逻辑。
    *   动态添加和删除 `<option>` 元素： 当使用 Javascript 向 `<optgroup>` 中添加或删除 `<option>` 元素时，会触发 `ChildrenChanged()` 方法，从而更新 `<select>` 元素的状态。
    *   访问 `<optgroup>` 元素的属性和方法。
*   **CSS:** CSS 可以用来样式化 `<optgroup>` 元素，尽管样式选项相对有限。
    *   可以使用选择器如 `optgroup` 或 `optgroup:disabled` 来应用样式。例如，可以设置禁用状态下 `<optgroup>` 的文本颜色：
        ```css
        optgroup:disabled {
          color: gray;
        }
        ```
    *   用户代理阴影根内部的元素也可以通过 CSS 进行样式化，但通常需要使用特殊的选择器或主题。  该文件中的 `DidAddUserAgentShadowRoot()` 方法设置了一些内联样式，例如 `padding` 和 `min-height`。

**逻辑推理与示例：**

**假设输入：**

```html
<select>
  <optgroup label="Fruits">
    <option value="apple">Apple</option>
    <option value="banana">Banana</option>
  </optgroup>
  <optgroup label="Vegetables" disabled>
    <option value="carrot">Carrot</option>
    <option value="broccoli">Broccoli</option>
  </optgroup>
</select>
```

**逻辑推理：**

1. 当浏览器解析到这段 HTML 时，会为每个 `<optgroup>` 标签创建一个 `HTMLOptGroupElement` 对象。
2. 对于第一个 `<optgroup>`，`ParseAttribute()` 会解析 `label` 属性并将其值设置为 "Fruits"。
3. 对于第二个 `<optgroup>`，`ParseAttribute()` 会解析 `label` 属性并将其值设置为 "Vegetables"，同时解析 `disabled` 属性，调用 `PseudoStateChanged(CSSSelector::kPseudoDisabled)` 和 `PseudoStateChanged(CSSSelector::kPseudoEnabled)` 来更新其 CSS 伪类状态。
4. 当 `<option>` 元素被插入到 `<optgroup>` 中时，`ChildrenChanged()` 方法会被调用，并通知父 `<select>` 元素。
5. 由于第二个 `<optgroup>` 设置了 `disabled` 属性，`IsDisabledFormControl()` 方法会返回 `true`。 这会导致其包含的 "Carrot" 和 "Broccoli" 选项在用户界面上显示为禁用状态，用户无法选择它们。

**输出：**

*   一个下拉选择框，其中 "Fruits" 和 "Vegetables" 作为分组标题显示。
*   "Apple" 和 "Banana" 选项在 "Fruits" 分组下，可以被选择。
*   "Carrot" 和 "Broccoli" 选项在 "Vegetables" 分组下，并且显示为禁用状态，无法被选择。

**用户或编程常见的使用错误：**

1. **嵌套 `<optgroup>` 元素：** HTML 规范不允许 `<optgroup>` 元素嵌套在另一个 `<optgroup>` 元素中。 虽然浏览器可能不会抛出错误，但其行为可能不符合预期。
    ```html
    <select>
      <optgroup label="Group A">
        <optgroup label="Subgroup">  <!-- 错误的使用方式 -->
          <option value="1">Option 1</option>
        </optgroup>
      </optgroup>
    </select>
    ```
    Blink 引擎的 `OwnerSelectElement()` 方法中会检查这种嵌套情况，如果发现 `<optgroup>` 或 `<option>` 作为祖先，则返回 `nullptr`。

2. **忘记设置 `label` 属性：**  `<optgroup>` 元素如果没有 `label` 属性，将不会显示分组标题，这会降低用户体验。
    ```html
    <select>
      <optgroup>  <!-- 缺少 label 属性 -->
        <option value="a">Option A</option>
        <option value="b">Option B</option>
      </optgroup>
    </select>
    ```
    虽然代码中也考虑了使用 `<legend>` 作为标签的替代方案（在启用可定制的 `<select>` 渲染时），但通常还是应该使用 `label` 属性。

3. **错误地认为可以单独禁用 `<option>` 组：** 虽然可以禁用整个 `<optgroup>`，但无法直接禁用一个“选项组”而不使用 `<optgroup>` 标签。 `<optgroup>` 是实现分组和批量禁用的机制。

4. **过度依赖 CSS 样式化 `<optgroup>`：**  `<optgroup>` 元素提供的 CSS 样式化选项相对有限，不同浏览器的渲染可能存在差异。应该更多地关注其结构作用，而不是样式。

5. **在 Javascript 中不正确地操作子节点：**  直接操作 `<optgroup>` 的子节点（例如使用 `appendChild` 添加非 `<option>` 元素）可能会导致意外的行为。应该始终确保 `<optgroup>` 的直接子元素是 `<option>` 元素或 `<hr>` 元素（在某些情况下）。

总而言之，`html_opt_group_element.cc` 文件是 Blink 引擎中 `<optgroup>` 元素的核心实现，负责处理其属性、状态、与父 `<select>` 元素的交互以及在用户界面上的呈现。它与 HTML 结构、Javascript 的 DOM 操作和 CSS 样式都有着密切的联系。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/html_opt_group_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2010 Apple Inc. All rights
 * reserved.
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"

#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace {

bool CanAssignToOptGroupSlot(const Node& node) {
  return node.HasTagName(html_names::kOptionTag) ||
         node.HasTagName(html_names::kHrTag);
}

}  // namespace

HTMLOptGroupElement::HTMLOptGroupElement(Document& document)
    : HTMLElement(html_names::kOptgroupTag, document) {
  EnsureUserAgentShadowRoot(SlotAssignmentMode::kManual);
}

// An explicit empty destructor should be in html_opt_group_element.cc, because
// if an implicit destructor is used or an empty destructor is defined in
// html_opt_group_element.h, when including html_opt_group_element.h,
// msvc tries to expand the destructor and causes
// a compile error because of lack of ComputedStyle definition.
HTMLOptGroupElement::~HTMLOptGroupElement() = default;

bool HTMLOptGroupElement::IsDisabledFormControl() const {
  return FastHasAttribute(html_names::kDisabledAttr);
}

void HTMLOptGroupElement::ParseAttribute(
    const AttributeModificationParams& params) {
  HTMLElement::ParseAttribute(params);

  if (params.name == html_names::kDisabledAttr) {
    PseudoStateChanged(CSSSelector::kPseudoDisabled);
    PseudoStateChanged(CSSSelector::kPseudoEnabled);
  } else if (params.name == html_names::kLabelAttr) {
    UpdateGroupLabel();
  }
}

FocusableState HTMLOptGroupElement::SupportsFocus(
    UpdateBehavior update_behavior) const {
  HTMLSelectElement* select = OwnerSelectElement();
  if (select && select->UsesMenuList())
    return FocusableState::kNotFocusable;
  return HTMLElement::SupportsFocus(update_behavior);
}

bool HTMLOptGroupElement::MatchesEnabledPseudoClass() const {
  return !IsDisabledFormControl();
}

void HTMLOptGroupElement::ChildrenChanged(const ChildrenChange& change) {
  HTMLElement::ChildrenChanged(change);
  auto* select = OwnerSelectElement();
  if (!select)
    return;
  // Code path used for kFinishedBuildingDocumentFragmentTree should not be
  // hit for optgroups as fast-path parser does not handle optgroups.
  DCHECK_NE(change.type,
            ChildrenChangeType::kFinishedBuildingDocumentFragmentTree);
  if (change.type == ChildrenChangeType::kElementInserted) {
    if (auto* option = DynamicTo<HTMLOptionElement>(change.sibling_changed))
      select->OptionInserted(*option, option->Selected());
  } else if (change.type == ChildrenChangeType::kElementRemoved) {
    if (auto* option = DynamicTo<HTMLOptionElement>(change.sibling_changed))
      select->OptionRemoved(*option);
  } else if (change.type == ChildrenChangeType::kAllChildrenRemoved) {
    for (Node* node : change.removed_nodes) {
      if (auto* option = DynamicTo<HTMLOptionElement>(node))
        select->OptionRemoved(*option);
    }
  }
}

bool HTMLOptGroupElement::ChildrenChangedAllChildrenRemovedNeedsList() const {
  return true;
}

Node::InsertionNotificationRequest HTMLOptGroupElement::InsertedInto(
    ContainerNode& insertion_point) {
  customizable_select_rendering_ = false;
  HTMLElement::InsertedInto(insertion_point);
  if (HTMLSelectElement* select = OwnerSelectElement()) {
    if (&insertion_point == select)
      select->OptGroupInsertedOrRemoved(*this);
    // TODO(crbug.com/1511354): This UsesMenuList check doesn't account for
    // the case when the select's rendering is changed after insertion.
    customizable_select_rendering_ =
        RuntimeEnabledFeatures::CustomizableSelectEnabled() &&
        select->UsesMenuList();
  }
  if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    UpdateGroupLabel();
  }
  return kInsertionDone;
}

void HTMLOptGroupElement::RemovedFrom(ContainerNode& insertion_point) {
  if (auto* select = DynamicTo<HTMLSelectElement>(insertion_point)) {
    if (!parentNode())
      select->OptGroupInsertedOrRemoved(*this);
  }
  HTMLElement::RemovedFrom(insertion_point);
}

String HTMLOptGroupElement::GroupLabelText() const {
  String label_attribute_text = LabelAttributeText();
  if (RuntimeEnabledFeatures::CustomizableSelectEnabled() &&
      label_attribute_text.ContainsOnlyWhitespaceOrEmpty()) {
    for (auto& node : NodeTraversal::DescendantsOf(*this)) {
      if (auto* legend = DynamicTo<HTMLLegendElement>(node)) {
        return legend->textContent();
      }
    }
  }
  return label_attribute_text;
}

String HTMLOptGroupElement::LabelAttributeText() const {
  String item_text = FastGetAttribute(html_names::kLabelAttr);

  // In WinIE, leading and trailing whitespace is ignored in options and
  // optgroups. We match this behavior.
  item_text = item_text.StripWhiteSpace();
  // We want to collapse our whitespace too.  This will match other browsers.
  item_text = item_text.SimplifyWhiteSpace();

  return item_text;
}

HTMLSelectElement* HTMLOptGroupElement::OwnerSelectElement() const {
  if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
    // TODO(crbug.com/351990825): Cache the owner select ancestor on insertion
    // rather than doing a tree traversal here every time OwnerSelectElement is
    // called, which may be a lot.
    for (Node& ancestor : NodeTraversal::AncestorsOf(*this)) {
      if (IsA<HTMLOptGroupElement>(ancestor) ||
          IsA<HTMLOptionElement>(ancestor)) {
        return nullptr;
      }
      if (auto* select = DynamicTo<HTMLSelectElement>(ancestor)) {
        return select;
      }
    }
    return nullptr;
  } else {
    return DynamicTo<HTMLSelectElement>(parentNode());
  }
}

String HTMLOptGroupElement::DefaultToolTip() const {
  if (HTMLSelectElement* select = OwnerSelectElement())
    return select->DefaultToolTip();
  return String();
}

void HTMLOptGroupElement::AccessKeyAction(
    SimulatedClickCreationScope creation_scope) {
  HTMLSelectElement* select = OwnerSelectElement();
  // Send to the parent to bring focus to the list box.
  // TODO(crbug.com/1176745): investigate why we don't care
  // about creation scope.
  if (select && !select->IsFocused())
    select->AccessKeyAction(SimulatedClickCreationScope::kFromUserAgent);
}

void HTMLOptGroupElement::DidAddUserAgentShadowRoot(ShadowRoot& root) {
  DEFINE_STATIC_LOCAL(AtomicString, label_padding, ("0 2px 1px 2px"));
  DEFINE_STATIC_LOCAL(AtomicString, label_min_height, ("1.2em"));
  auto* label = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  label->setAttribute(html_names::kAriaHiddenAttr, AtomicString("true"));
  label->SetInlineStyleProperty(CSSPropertyID::kPadding, label_padding);
  label->SetInlineStyleProperty(CSSPropertyID::kMinHeight, label_min_height);
  label->SetIdAttribute(shadow_element_names::kIdOptGroupLabel);
  root.AppendChild(label);
  opt_group_slot_ = MakeGarbageCollected<HTMLSlotElement>(GetDocument());
  root.AppendChild(opt_group_slot_);
}

void HTMLOptGroupElement::ManuallyAssignSlots() {
  HeapVector<Member<Node>> opt_group_nodes;
  for (Node& child : NodeTraversal::ChildrenOf(*this)) {
    if (!child.IsSlotable())
      continue;
    if (customizable_select_rendering_ || CanAssignToOptGroupSlot(child)) {
      opt_group_nodes.push_back(child);
    }
  }
  opt_group_slot_->Assign(opt_group_nodes);
}

void HTMLOptGroupElement::UpdateGroupLabel() {
  const String& label_text = LabelAttributeText();
  HTMLDivElement& label = OptGroupLabelElement();
  label.setTextContent(label_text);
  label.setAttribute(html_names::kAriaLabelAttr, AtomicString(label_text));
  if (label_text.ContainsOnlyWhitespaceOrEmpty()) {
    if (customizable_select_rendering_) {
      // If the author uses <legend> to label the <optgroup> instead of the
      // label attribute, then we don't want extra space being taken up for the
      // unused label attribute.
      label.SetInlineStyleProperty(CSSPropertyID::kDisplay, "none");
    }
  } else {
    label.RemoveInlineStyleProperty(CSSPropertyID::kDisplay);
  }
}

HTMLDivElement& HTMLOptGroupElement::OptGroupLabelElement() const {
  auto* element = UserAgentShadowRoot()->getElementById(
      shadow_element_names::kIdOptGroupLabel);
  CHECK(!element || IsA<HTMLDivElement>(element));
  return *To<HTMLDivElement>(element);
}

void HTMLOptGroupElement::Trace(Visitor* visitor) const {
  visitor->Trace(opt_group_slot_);
  HTMLElement::Trace(visitor);
}

}  // namespace blink

"""

```
Response:
My thought process for analyzing the provided code snippet and generating the comprehensive explanation goes through these stages:

1. **Initial Reading and Keyword Spotting:** I first read through the code to get a general sense of its purpose. I look for keywords and patterns like `setAttribute`, `removeAttribute`, `focus`, `blur`, `styleRecalc`, `ShadowRoot`, `Document`, `ExceptionState`, etc. These keywords immediately hint at the core functionalities being handled.

2. **Section-wise Breakdown and Function Identification:**  I mentally (or physically, if it's a larger file) divide the code into logical blocks based on function definitions. For each function, I try to understand its primary goal. For example:
    * `ChildrenChanged`:  Deals with modifications to the element's children.
    * `FinishParsingChildren`:  Handles actions after parsing children.
    * `GetAttrNodeList`, `RemoveAttrNodeList`:  Manage the attribute node list.
    * `setAttributeNodeNS`, `removeAttributeNode`:  Add and remove attribute nodes.
    * `LangAttributeChanged`, `ParseAttribute`: Handle changes to the `lang` attribute.
    * `ParseAttributeName`:  Validates attribute names.
    * `setAttributeNS`: Sets attributes with namespaces.
    * `RemoveAttributeInternal`, `AppendAttributeInternal`: Core logic for adding and removing attributes.
    * `removeAttributeNS`: Removes namespaced attributes.
    * `getAttributeNode`, `getAttributeNodeNS`: Gets attribute nodes.
    * `hasAttribute`, `hasAttributeNS`: Checks for attribute existence.
    * `IsShadowHostWithDelegatesFocus`: Checks for focus delegation in shadow DOM.
    * `GetFocusableArea`, `GetFocusDelegate`:  Finds the actual focusable element.
    * `focusForBindings`, `Focus` (multiple overloads):  Sets focus on the element.
    * `SetFocused`:  Updates the internal focused state.
    * `SetDragged`: Handles drag state changes.
    * `UpdateSelectionOnFocus`:  Manages selection when an element receives focus.
    * `blur`: Removes focus.
    * `SupportsSpatialNavigationFocus`:  Checks if the element supports spatial navigation.
    * `CanBeKeyboardFocusableScroller`, `IsKeyboardFocusableScroller`: Determines if the element is a keyboard-focusable scroller.
    * `IsKeyboardFocusable`, `IsMouseFocusable`, `IsFocusable`, `IsFocusableState`, `SupportsFocus`:  Various checks for focusability.
    * `IsAutofocusable`: Checks for the `autofocus` attribute.
    * `FocusStateChanged`, `FocusVisibleStateChanged`: Handles changes in focus-related pseudo-classes.

3. **Identifying Relationships with Web Technologies:** Once I understand the individual functions, I consider how they relate to JavaScript, HTML, and CSS. This involves thinking about the browser's rendering process and how these technologies interact:
    * **HTML:**  Attributes are directly manipulated (`setAttribute`, `removeAttribute`). The concept of child nodes and the DOM tree (`ChildrenChanged`). Focus and blur events are tied to HTML elements.
    * **JavaScript:** The functions often take `ExceptionState` as an argument, indicating they can be called from JavaScript and may throw errors. The manipulation of attributes and focus directly impacts what JavaScript can observe and control. Event listeners are checked (`HasJSBasedEventListeners`).
    * **CSS:**  The `SetNeedsStyleRecalc` calls are crucial. Changes to attributes, focus, and the DOM structure can trigger style recalculations, impacting how the element is rendered based on CSS rules. Pseudo-classes like `:focus`, `:hover`, `:lang`, and `:drag` are explicitly mentioned. Shadow DOM is a key concept in controlling CSS scope.

4. **Inferring Logic and Creating Examples:** For functions with more involved logic, I try to deduce the input and output. For instance, in `ChildrenChanged`, I consider what happens when an element is added or removed. I then construct hypothetical scenarios to illustrate the function's behavior. For example, adding a new element might trigger a style recalculation for the parent if a CSS rule like `> *` is present.

5. **Considering User and Programming Errors:** I think about common mistakes developers might make when interacting with these functionalities. For example, trying to remove an attribute node from the wrong element will throw an error. Incorrectly managing focus can lead to unexpected behavior.

6. **Tracing User Actions (Debugging Context):** I imagine a user interacting with a web page and how those actions might lead to the execution of the code within `element.cc`. Clicking on an element, typing in a form field, or using the Tab key can all trigger focus-related code. Modifying the DOM through JavaScript will call the `ChildrenChanged` functions.

7. **Summarizing Functionality (Part 8 of 13):**  Given that this is part 8 of a larger file, I try to synthesize the main themes covered in this specific section. The focus here is clearly on:
    * **Attribute manipulation:** Getting, setting, removing attributes.
    * **Focus management:**  Gaining and losing focus, finding focusable elements.
    * **DOM manipulation and change notifications:** Handling changes to the element's children.
    * **Interaction with the styling system:** Triggering style recalculations based on changes.

8. **Refinement and Organization:**  Finally, I organize my thoughts into a clear and structured explanation, using headings, bullet points, and code examples to make the information easy to understand. I try to use precise terminology and avoid jargon where possible. I review the explanation to ensure it accurately reflects the code's functionality and addresses all aspects of the prompt.

By following these steps, I can effectively analyze the Chromium source code snippet and generate a comprehensive explanation of its functionalities, its relationships with web technologies, and its implications for developers and users.
好的，这是`blink/renderer/core/dom/element.cc`文件的第8部分，主要关注元素属性操作、焦点管理以及与样式系统交互的部分。

**核心功能归纳 (第8部分):**

* **子节点变更处理 (Continuation from previous parts):**  `ChildrenChanged` 函数继续处理子节点变更后的逻辑，包括触发样式重算、处理 `dir` 属性等。
* **完成子节点解析:** `FinishParsingChildren` 函数在元素子节点解析完成后执行，用于触发样式更新，并处理 `expect-link` 资源加载。
* **属性节点列表管理:** 提供了获取和移除属性节点列表的方法 (`GetAttrNodeList`, `RemoveAttrNodeList`)。
* **属性节点操作:**  `setAttributeNodeNS` (实际调用 `setAttributeNode`) 和 `removeAttributeNode` 用于添加和移除 `Attr` 节点，并处理相关的错误情况。
* **`lang` 属性变更处理:** `LangAttributeChanged` 函数在 `lang` 属性改变时触发样式重算，影响 `:lang` CSS 伪类的应用。 `ParseAttribute` 函数用于解析属性变更，并调用 `LangAttributeChanged` 如果是 `lang` 属性。
* **属性名称解析:** `ParseAttributeName` 函数用于解析属性的命名空间和名称，并进行合法性校验。
* **命名空间属性操作:** `setAttributeNS` 和 `removeAttributeNS` 用于添加和移除带有命名空间的属性。
* **内部属性操作:** `RemoveAttributeInternal` 和 `AppendAttributeInternal` 是内部用于添加和移除属性的核心函数，会触发 `WillModifyAttribute` 和 `DidAddAttribute`/`DidRemoveAttribute` 等钩子。
* **获取属性节点:** `getAttributeNode` 和 `getAttributeNodeNS` 用于根据名称（带或不带命名空间）获取对应的 `Attr` 节点。
* **检查属性是否存在:** `hasAttribute` 和 `hasAttributeNS` 用于检查元素是否包含指定名称（带或不带命名空间）的属性。
* **焦点委托判断:** `IsShadowHostWithDelegatesFocus` 判断元素是否是委托焦点的 Shadow Host。
* **获取可聚焦区域:** `GetFocusableArea` 用于获取元素内部可获得焦点的区域，考虑到 Shadow DOM 的焦点委托。
* **获取焦点委托:** `GetFocusDelegate` 用于查找实际应该获得焦点的元素，包括考虑 `autofocus` 属性。
* **焦点设置:** 提供了多个 `Focus` 重载函数，用于设置元素的焦点，并考虑不同的焦点来源和选项。
* **设置焦点状态:** `SetFocused` 函数用于更新元素的内部焦点状态，并触发相关的样式重算和伪类更新 (`:focus`, `:focus-visible`, `:focus-within`)。
* **拖拽状态设置:** `SetDragged` 函数用于设置元素的拖拽状态，并触发 `:drag` 伪类的样式更新。
* **焦点时的选择处理:** `UpdateSelectionOnFocus` 函数在元素获得焦点时，根据 `selection_behavior` 参数处理文本选择。
* **失去焦点:** `blur` 函数用于移除元素的焦点。
* **支持空间导航焦点:** `SupportsSpatialNavigationFocus` 函数判断元素是否支持空间导航焦点。
* **键盘可聚焦滚动容器判断:** `CanBeKeyboardFocusableScroller` 和 `IsKeyboardFocusableScroller` 用于判断元素是否是键盘可聚焦的滚动容器。
* **可聚焦性判断:**  `IsKeyboardFocusable`, `IsMouseFocusable`, `IsFocusable`, `IsFocusableState`, `SupportsFocus` 等函数用于判断元素在不同场景下的可聚焦性。
* **自动聚焦判断:** `IsAutofocusable` 判断元素是否设置了 `autofocus` 属性。
* **焦点状态变更通知:** `FocusStateChanged` 和 `FocusVisibleStateChanged` 函数在焦点状态发生变化时触发样式更新。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **获取/设置属性:**  JavaScript 可以通过 `element.setAttribute('id', 'myElement')` 调用到 `setAttribute` 系列的 C++ 代码，最终可能触及 `setAttributeNS` 或内部的 `AppendAttributeInternal`。  `element.getAttribute('id')` 会触发属性值的同步。
    * **移除属性:** `element.removeAttribute('id')` 会调用到 `removeAttribute` 系列的 C++ 代码，最终可能触及 `removeAttributeNS` 或内部的 `RemoveAttributeInternal`。
    * **获取/设置属性节点:**  `element.getAttributeNode('id')`, `element.setAttributeNode(attr)` 分别对应 `getAttributeNode` 和 `setAttributeNode`。
    * **焦点操作:** `element.focus()` 会调用 `Focus` 函数。 `element.blur()` 会调用 `blur` 函数。
    * **事件监听:**  虽然代码中没有直接处理事件，但焦点状态的改变会触发 `focus` 和 `blur` 事件，这些事件是在 JavaScript 中处理的。
    * **`lang` 属性:**  JavaScript 设置 `element.lang = 'en'` 会触发 `LangAttributeChanged`，可能影响依赖于 `:lang` 伪类的样式。

    ```javascript
    // JavaScript 示例
    const div = document.createElement('div');
    div.setAttribute('class', 'my-div'); // 触发 setAttribute 相关 C++ 代码
    div.id = 'unique-id'; // 也会触发 setAttribute 相关 C++ 代码
    console.log(div.getAttribute('class')); // 触发 getAttribute 相关 C++ 代码
    div.focus(); // 触发 Focus C++ 代码
    setTimeout(() => {
      div.blur(); // 触发 blur C++ 代码
    }, 1000);
    ```

* **HTML:**
    * **属性定义:** HTML 标签中的属性（例如 `<div id="myDiv">`）在解析时会触发属性相关的 C++ 代码进行处理。
    * **`lang` 属性:**  HTML 中使用 `<html lang="zh-CN">` 或 `<div lang="en">` 会设置元素的 `lang` 属性，触发 `LangAttributeChanged`。
    * **`tabindex` 属性:** HTML 中使用 `<button tabindex="0">` 会影响元素的可聚焦性，`Element::IsKeyboardFocusable` 等函数会检查这个属性。
    * **`autofocus` 属性:** HTML 中使用 `<input autofocus>` 会使元素在页面加载时自动获得焦点，`Element::IsAutofocusable` 会检查这个属性。
    * **Shadow DOM:**  HTML 中使用 `<template><slot></slot></template><script>customElements.define('my-shadow', class extends HTMLElement { constructor() { super(); this.attachShadow({mode: 'open', delegatesFocus: true}).innerHTML = this.querySelector('template').content.cloneNode(true).innerHTML; } });</script><my-shadow><div><template><span>Focusable content</span></template></div></my-shadow>`  `delegatesFocus` 属性会影响 `IsShadowHostWithDelegatesFocus` 和焦点查找逻辑。

* **CSS:**
    * **属性选择器:** CSS 可以使用属性选择器（例如 `[id="myDiv"]`, `[lang|="en"]`）来匹配元素，这些选择器的匹配依赖于元素属性的值，而这些值是由 C++ 代码管理的。
    * **`:focus` 伪类:** 当元素获得焦点时，`SetFocused` 函数会触发样式重算，导致 `:focus` 伪类对应的样式生效。
    * **`:hover`, `:active` 等伪类:**  虽然这里主要关注焦点，但类似的机制也适用于其他伪类。
    * **`:lang` 伪类:** `LangAttributeChanged` 会影响 `:lang(en)` 等伪类的应用。
    * **`:drag` 伪类:** `SetDragged` 会影响 `:-webkit-drag` 或标准的 `:drag` 伪类的应用。
    * **`display: none` 和焦点:**  代码中多次提到如果 `:focus` 等伪类导致 `display: none`，会触发额外的样式重算。

    ```css
    /* CSS 示例 */
    .my-div { color: blue; }
    [id="unique-id"] { font-weight: bold; }
    button:focus { outline: 2px solid red; }
    :lang(en) { quotes: "“" "”"; }
    ```

**逻辑推理与假设输入输出:**

假设输入一个 `div` 元素，并且通过 JavaScript 设置其 `lang` 属性为 `"fr"`:

* **假设输入:**
    * `Element`: 一个 `HTMLDivElement` 对象。
    * JavaScript 操作: `divElement.lang = 'fr';`

* **逻辑推理:**
    1. JavaScript 设置 `lang` 属性会调用到 C++ 层的属性设置代码。
    2. C++ 代码检测到 `lang` 属性发生变化。
    3. `LangAttributeChanged` 函数被调用。
    4. `LangAttributeChanged` 函数会调用 `SetNeedsStyleRecalc`，标记需要进行样式重算，并指定原因是伪类变化 (`CSSSelector::kPseudoLang`)。

* **预期输出:**
    * 浏览器的渲染引擎会将该 `div` 元素标记为需要重新计算样式。
    * 如果有 CSS 规则使用了 `:lang(fr)` 伪类，这些规则会被应用到该 `div` 元素。

**用户或编程常见的使用错误举例说明:**

* **尝试移除不属于该元素的属性节点:**

    ```javascript
    const div1 = document.createElement('div');
    const div2 = document.createElement('div');
    const attr = document.createAttribute('data-test');
    div2.setAttributeNode(attr); // attr 属于 div2
    div1.removeAttributeNode(attr); // 错误：尝试移除不属于 div1 的属性节点
    ```
    这会触发 `removeAttributeNode` 中的错误检查，抛出 `NotFoundError` 异常。

* **在不恰当的时机调用焦点方法:**

    ```javascript
    const button = document.createElement('button');
    document.body.appendChild(button);
    button.focus(); // 正常，按钮可以获得焦点

    const div = document.createElement('div');
    document.body.appendChild(div);
    div.focus(); // 如果 div 没有设置 tabindex 或其他使其可聚焦的属性，则可能不会生效，或者会聚焦到其内部的可聚焦元素。
    ```
    开发者可能期望所有元素都能通过 `focus()` 方法获得焦点，但实际上只有可聚焦元素才能真正获得焦点。

* **忘记处理焦点变化时的样式:**

    开发者可能没有为 `:focus` 伪类定义样式，导致用户在使用键盘导航时，无法清晰地看到哪个元素获得了焦点，影响可访问性。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户点击或使用 Tab 键:**  用户在网页上点击一个可聚焦的元素，或者使用 Tab 键进行导航，会导致浏览器尝试将焦点设置到该元素。 这会触发 JavaScript 的 `focus()` 方法（可能是浏览器内部调用），最终到达 `Element::Focus` 和 `Element::SetFocused`。

2. **JavaScript 调用 `focus()`:** 网页上的 JavaScript 代码显式调用了某个元素的 `focus()` 方法。

3. **修改元素属性:** 用户通过浏览器开发者工具修改了元素的属性，或者网页上的 JavaScript 代码调用了 `setAttribute` 或 `removeAttribute` 等方法，这些操作会触发 C++ 层的属性管理代码。

4. **`lang` 属性变化:**  用户的浏览器语言设置发生变化，或者网页上的 JavaScript 代码动态修改了 `document.documentElement.lang` 或某个元素的 `lang` 属性，会触发 `LangAttributeChanged`。

5. **Shadow DOM 交互:** 用户与使用了 Shadow DOM 的组件进行交互，例如点击了一个 Shadow Host，浏览器需要确定哪个元素应该获得焦点，这会涉及到 `IsShadowHostWithDelegatesFocus` 和 `GetFocusableArea` 等函数的调用。

通过理解这些用户操作如何触发底层的 C++ 代码，开发者可以更好地进行调试和问题排查。 例如，如果一个元素的焦点行为不符合预期，可以检查是否正确设置了 `tabindex` 属性，或者是否存在 Shadow DOM 导致的焦点委托问题。

总而言之，`blink/renderer/core/dom/element.cc` 文件的这一部分是 Chromium Blink 引擎中处理元素属性和焦点管理的核心逻辑，它连接了 HTML 结构、CSS 样式以及 JavaScript 行为，确保网页能够正确地响应用户的交互和动态变化。

Prompt: 
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共13部分，请归纳一下它的功能

"""
, then they won't get to see an up to date version of the
  // flat tree.
  if (ShadowRoot* shadow_root = GetShadowRoot()) {
    shadow_root->SetNeedsAssignmentRecalc();
  }

  ContainerNode::ChildrenChanged(change);

  CheckForEmptyStyleChange(change.sibling_before_change,
                           change.sibling_after_change);

  if (!change.ByParser()) {
    if (change.IsChildElementChange()) {
      Element* changed_element = To<Element>(change.sibling_changed);
      bool removed = change.type == ChildrenChangeType::kElementRemoved;
      CheckForSiblingStyleChanges(
          removed ? kSiblingElementRemoved : kSiblingElementInserted,
          changed_element, change.sibling_before_change,
          change.sibling_after_change);
      GetDocument()
          .GetStyleEngine()
          .ScheduleInvalidationsForHasPseudoAffectedByInsertionOrRemoval(
              this, change.sibling_before_change, *changed_element, removed);
    } else if (change.type == ChildrenChangeType::kAllChildrenRemoved) {
      GetDocument()
          .GetStyleEngine()
          .ScheduleInvalidationsForHasPseudoWhenAllChildrenRemoved(*this);
    }
  }

  if (GetDocument().HasDirAttribute()) {
    AdjustDirectionalityIfNeededAfterChildrenChanged(change);
  }
}

void Element::FinishParsingChildren() {
  SetIsFinishedParsingChildren(true);
  CheckForEmptyStyleChange(this, this);
  CheckForSiblingStyleChanges(kFinishedParsingChildren, nullptr, lastChild(),
                              nullptr);

  if (GetDocument().HasRenderBlockingExpectLinkElements()) {
    DCHECK(GetDocument().GetRenderBlockingResourceManager());
    GetDocument()
        .GetRenderBlockingResourceManager()
        ->RemovePendingParsingElement(GetIdAttribute(), this);
  }
  GetDocument()
      .GetStyleEngine()
      .ScheduleInvalidationsForHasPseudoAffectedByInsertionOrRemoval(
          parentElement(), previousSibling(), *this, /* removal */ false);
}

AttrNodeList* Element::GetAttrNodeList() {
  if (ElementRareDataVector* data = GetElementRareData()) {
    return data->GetAttrNodeList();
  }
  return nullptr;
}

void Element::RemoveAttrNodeList() {
  DCHECK(GetAttrNodeList());
  if (ElementRareDataVector* data = GetElementRareData()) {
    data->RemoveAttrNodeList();
  }
}

Attr* Element::setAttributeNodeNS(Attr* attr, ExceptionState& exception_state) {
  return setAttributeNode(attr, exception_state);
}

Attr* Element::removeAttributeNode(Attr* attr,
                                   ExceptionState& exception_state) {
  if (attr->ownerElement() != this) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The node provided is owned by another element.");
    return nullptr;
  }

  DCHECK_EQ(GetDocument(), attr->GetDocument());

  SynchronizeAttribute(attr->GetQualifiedName());

  wtf_size_t index =
      GetElementData()->Attributes().FindIndex(attr->GetQualifiedName());
  if (index == kNotFound) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The attribute was not found on this element.");
    return nullptr;
  }

  DetachAttrNodeAtIndex(attr, index);
  return attr;
}

void Element::LangAttributeChanged() {
  SetNeedsStyleRecalc(
      kSubtreeStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kPseudoClass));
  PseudoStateChanged(CSSSelector::kPseudoLang);
}

void Element::ParseAttribute(const AttributeModificationParams& params) {
  if (params.name.Matches(xml_names::kLangAttr)) {
    LangAttributeChanged();
  }
}

// static
std::optional<QualifiedName> Element::ParseAttributeName(
    const AtomicString& namespace_uri,
    const AtomicString& qualified_name,
    ExceptionState& exception_state) {
  AtomicString prefix, local_name;
  if (!Document::ParseQualifiedName(qualified_name, prefix, local_name,
                                    exception_state)) {
    return std::nullopt;
  }
  DCHECK(!exception_state.HadException());

  QualifiedName q_name(prefix, local_name, namespace_uri);

  if (!Document::HasValidNamespaceForAttributes(q_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNamespaceError,
        "'" + namespace_uri + "' is an invalid namespace for attributes.");
    return std::nullopt;
  }
  return q_name;
}

void Element::setAttributeNS(const AtomicString& namespace_uri,
                             const AtomicString& qualified_name,
                             String value,
                             ExceptionState& exception_state) {
  std::optional<QualifiedName> parsed_name =
      ParseAttributeName(namespace_uri, qualified_name, exception_state);
  if (!parsed_name) {
    return;
  }

  AtomicString trusted_value(TrustedTypesCheckFor(
      ExpectedTrustedTypeForAttribute(*parsed_name), std::move(value),
      GetExecutionContext(), "Element", "setAttributeNS", exception_state));
  if (exception_state.HadException()) {
    return;
  }

  setAttribute(*parsed_name, trusted_value);
}

void Element::setAttributeNS(const AtomicString& namespace_uri,
                             const AtomicString& qualified_name,
                             const V8TrustedType* trusted_string,
                             ExceptionState& exception_state) {
  std::optional<QualifiedName> parsed_name =
      ParseAttributeName(namespace_uri, qualified_name, exception_state);
  if (!parsed_name) {
    return;
  }

  AtomicString value(TrustedTypesCheckFor(
      ExpectedTrustedTypeForAttribute(*parsed_name), trusted_string,
      GetExecutionContext(), "Element", "setAttributeNS", exception_state));
  if (exception_state.HadException()) {
    return;
  }

  setAttribute(*parsed_name, value);
}

void Element::RemoveAttributeInternal(wtf_size_t index,
                                      AttributeModificationReason reason) {
  MutableAttributeCollection attributes =
      EnsureUniqueElementData().Attributes();
  SECURITY_DCHECK(index < attributes.size());

  QualifiedName name = attributes[index].GetName();
  AtomicString value_being_removed = attributes[index].Value();

  if (reason !=
      AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
    if (!value_being_removed.IsNull()) {
      WillModifyAttribute(name, value_being_removed, g_null_atom);
    } else if (GetCustomElementState() == CustomElementState::kCustom) {
      // This would otherwise be enqueued by willModifyAttribute.
      CustomElement::EnqueueAttributeChangedCallback(
          *this, name, value_being_removed, g_null_atom);
    }
  }

  if (Attr* attr_node = AttrIfExists(name)) {
    DetachAttrNodeFromElementWithValue(attr_node, attributes[index].Value());
  }

  attributes.Remove(index);

  if (reason !=
      AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
    DidRemoveAttribute(name, value_being_removed);
  }
}

void Element::AppendAttributeInternal(const QualifiedName& name,
                                      const AtomicString& value,
                                      AttributeModificationReason reason) {
  if (reason !=
      AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
    WillModifyAttribute(name, g_null_atom, value);
  }
  EnsureUniqueElementData().Attributes().Append(name, value);
  if (reason !=
      AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
    DidAddAttribute(name, value);
  }
}

void Element::removeAttributeNS(const AtomicString& namespace_uri,
                                const AtomicString& local_name) {
  removeAttribute(QualifiedName(g_null_atom, local_name, namespace_uri));
}

Attr* Element::getAttributeNode(const AtomicString& local_name) {
  if (!HasElementData()) {
    return nullptr;
  }
  WTF::AtomicStringTable::WeakResult hint =
      WeakLowercaseIfNecessary(local_name);
  SynchronizeAttributeHinted(local_name, hint);
  const Attribute* attribute =
      GetElementData()->Attributes().FindHinted(local_name, hint);
  if (!attribute) {
    return nullptr;
  }
  return EnsureAttr(attribute->GetName());
}

Attr* Element::getAttributeNodeNS(const AtomicString& namespace_uri,
                                  const AtomicString& local_name) {
  if (!HasElementData()) {
    return nullptr;
  }
  QualifiedName q_name(g_null_atom, local_name, namespace_uri);
  SynchronizeAttribute(q_name);
  const Attribute* attribute = GetElementData()->Attributes().Find(q_name);
  if (!attribute) {
    return nullptr;
  }
  return EnsureAttr(attribute->GetName());
}

bool Element::hasAttribute(const AtomicString& local_name) const {
  if (!HasElementData()) {
    return false;
  }
  WTF::AtomicStringTable::WeakResult hint =
      WeakLowercaseIfNecessary(local_name);
  SynchronizeAttributeHinted(local_name, hint);
  return GetElementData()->Attributes().FindHinted(local_name, hint);
}

bool Element::hasAttributeNS(const AtomicString& namespace_uri,
                             const AtomicString& local_name) const {
  if (!HasElementData()) {
    return false;
  }
  QualifiedName q_name(g_null_atom, local_name, namespace_uri);
  SynchronizeAttribute(q_name);
  return GetElementData()->Attributes().Find(q_name);
}

bool Element::IsShadowHostWithDelegatesFocus() const {
  return GetShadowRoot() && GetShadowRoot()->delegatesFocus();
}

// https://html.spec.whatwg.org/C/#get-the-focusable-area
Element* Element::GetFocusableArea(bool in_descendant_traversal) const {
  // GetFocusableArea should only be called as a fallback on elements which
  // aren't mouse and keyboard focusable, unless we are looking for an initial
  // focus candidate for a dialog element in which case we are looking for a
  // keyboard focusable element and will be calling this for mouse focusable
  // elements.
  DCHECK(!IsKeyboardFocusable() ||
         FocusController::AdjustedTabIndex(*this) < 0);

  // TODO(crbug.com/1018619): Support AREA -> IMG delegation.
  if (!IsShadowHostWithDelegatesFocus()) {
    return nullptr;
  }
  Document& doc = GetDocument();
  if (AuthorShadowRoot()) {
    UseCounter::Count(doc, WebFeature::kDelegateFocus);
  }

  Element* focused_element = doc.FocusedElement();
  if (focused_element &&
      IsShadowIncludingInclusiveAncestorOf(*focused_element)) {
    return focused_element;
  }

  DCHECK(GetShadowRoot());
  if (RuntimeEnabledFeatures::NewGetFocusableAreaBehaviorEnabled()) {
    return GetFocusDelegate(in_descendant_traversal);
  } else {
    return FocusController::FindFocusableElementInShadowHost(*this);
  }
}

Element* Element::GetFocusDelegate(bool in_descendant_traversal) const {
  ShadowRoot* shadowroot = GetShadowRoot();
  if (shadowroot && !shadowroot->IsUserAgent() &&
      !shadowroot->delegatesFocus()) {
    return nullptr;
  }

  const ContainerNode* where_to_look = this;
  if (IsShadowHostWithDelegatesFocus()) {
    where_to_look = shadowroot;
  }

  if (Element* autofocus_delegate = where_to_look->GetAutofocusDelegate()) {
    return autofocus_delegate;
  }

  for (Element& descendant : ElementTraversal::DescendantsOf(*where_to_look)) {
    // Dialog elements should only initially focus keyboard focusable elements,
    // not mouse focusable elements.
    if (descendant.IsFocusable() &&
        (!IsA<HTMLDialogElement>(this) ||
         FocusController::AdjustedTabIndex(descendant) >= 0)) {
      return &descendant;
    }
    if (Element* focusable_area =
            descendant.GetFocusableArea(/*in_descendant_traversal=*/true)) {
      return focusable_area;
    }
  }
  return nullptr;
}

void Element::focusForBindings(const FocusOptions* options) {
  Focus(FocusParams(SelectionBehaviorOnFocus::kRestore,
                    mojom::blink::FocusType::kScript,
                    /*capabilities=*/nullptr, options));
}

void Element::Focus() {
  Focus(FocusParams());
}

void Element::Focus(const FocusOptions* options) {
  Focus(FocusParams(SelectionBehaviorOnFocus::kRestore,
                    mojom::blink::FocusType::kNone, /*capabilities=*/nullptr,
                    options));
}

void Element::Focus(const FocusParams& params) {
  if (!isConnected()) {
    return;
  }

  if (!GetDocument().IsFocusAllowed()) {
    return;
  }

  if (GetDocument().FocusedElement() == this) {
    return;
  }

  if (!GetDocument().IsActive()) {
    return;
  }

  auto* frame_owner_element = DynamicTo<HTMLFrameOwnerElement>(this);
  if (frame_owner_element && frame_owner_element->contentDocument() &&
      frame_owner_element->contentDocument()->UnloadStarted()) {
    return;
  }

  FocusOptions* focus_options = nullptr;
  bool should_consume_user_activation = false;
  if (params.focus_trigger == FocusTrigger::kScript) {
    LocalFrame& frame = *GetDocument().GetFrame();
    if (!frame.AllowFocusWithoutUserActivation() &&
        !LocalFrame::HasTransientUserActivation(&frame)) {
      return;
    }

    // Fenced frame focusing should not auto-scroll, since that behavior can
    // be observed by an embedder.
    if (frame.IsInFencedFrameTree()) {
      focus_options = FocusOptions::Create();
      focus_options->setPreventScroll(true);
    }

    // Wait to consume user activation until after the focus takes place.
    if (!frame.AllowFocusWithoutUserActivation()) {
      should_consume_user_activation = true;
    }
  }

  FocusParams params_to_use = FocusParams(
      params.selection_behavior, params.type, params.source_capabilities,
      focus_options ? focus_options : params.options, params.focus_trigger);

  // Ensure we have clean style (including forced display locks).
  GetDocument().UpdateStyleAndLayoutTreeForElement(
      this, DocumentUpdateReason::kFocus);

  // https://html.spec.whatwg.org/C/#focusing-steps
  //
  // 1. If new focus target is not a focusable area, ...
  if (!IsFocusable()) {
    if (Element* new_focus_target = GetFocusableArea()) {
      // Unlike the specification, we re-run focus() for new_focus_target
      // because we can't change |this| in a member function.
      new_focus_target->Focus(FocusParams(
          SelectionBehaviorOnFocus::kReset, mojom::blink::FocusType::kForward,
          /*capabilities=*/nullptr, params_to_use.options));
    }
    // 2. If new focus target is null, then:
    //  2.1. If no fallback target was specified, then return.
    return;
  }
  // If a script called focus(), then the type would be kScript. This means
  // we are activating because of a script action (kScriptFocus). Otherwise,
  // this is a user activation (kUserFocus).
  ActivateDisplayLockIfNeeded(params_to_use.type ==
                                      mojom::blink::FocusType::kScript
                                  ? DisplayLockActivationReason::kScriptFocus
                                  : DisplayLockActivationReason::kUserFocus);

  if (!GetDocument().GetPage()->GetFocusController().SetFocusedElement(
          this, GetDocument().GetFrame(), params_to_use)) {
    return;
  }

  if (GetDocument().FocusedElement() == this) {
    ChromeClient& chrome_client = GetDocument().GetPage()->GetChromeClient();
    if (GetDocument().GetFrame()->HasStickyUserActivation()) {
      // Bring up the keyboard in the context of anything triggered by a user
      // gesture. Since tracking that across arbitrary boundaries (eg.
      // animations) is difficult, for now we match IE's heuristic and bring
      // up the keyboard if there's been any gesture since load.
      chrome_client.ShowVirtualKeyboardOnElementFocus(
          *GetDocument().GetFrame());
    }

    // TODO(bebeaudr): We might want to move the following code into the
    // HasStickyUserActivation condition above once https://crbug.com/1208874 is
    // fixed.
    //
    // Trigger a tooltip to show for the newly focused element only when the
    // focus was set resulting from a keyboard action.
    //
    // TODO(bebeaudr): To also trigger a tooltip when the |params_to_use.type|
    // is kSpatialNavigation, we'll first have to ensure that the fake mouse
    // move event fired by `SpatialNavigationController::DispatchMouseMoveEvent`
    // does not lead to a cursor triggered tooltip update. The only tooltip
    // update that there should be in that case is the one triggered from the
    // spatial navigation keypress. This issue is tracked in
    // https://crbug.com/1206446.
    bool is_focused_from_keypress = false;
    switch (params_to_use.type) {
      case mojom::blink::FocusType::kScript:
        if (GetDocument()
                .GetFrame()
                ->LocalFrameRoot()
                .GetEventHandler()
                .IsHandlingKeyEvent()) {
          is_focused_from_keypress = true;
        }
        break;
      case mojom::blink::FocusType::kForward:
      case mojom::blink::FocusType::kBackward:
      case mojom::blink::FocusType::kAccessKey:
        is_focused_from_keypress = true;
        break;
      default:
        break;
    }

    if (is_focused_from_keypress) {
      chrome_client.ElementFocusedFromKeypress(*GetDocument().GetFrame(), this);
    } else {
      chrome_client.ClearKeyboardTriggeredTooltip(*GetDocument().GetFrame());
    }
  }

  if (should_consume_user_activation) {
    // Fenced frames should consume user activation when attempting to pull
    // focus across a fenced boundary into itself.
    // TODO(crbug.com/848778) Right now the browser can't verify that the
    // renderer properly consumed user activation. When user activation code is
    // migrated to the browser, move this logic to the browser as well.
    LocalFrame::ConsumeTransientUserActivation(GetDocument().GetFrame());
  }
}

void Element::SetFocused(bool received, mojom::blink::FocusType focus_type) {
  // Recurse up author shadow trees to mark shadow hosts if it matches :focus.
  // TODO(kochi): Handle UA shadows which marks multiple nodes as focused such
  // as <input type="date"> the same way as author shadow.
  if (ShadowRoot* root = ContainingShadowRoot()) {
    if (!root->IsUserAgent()) {
      OwnerShadowHost()->SetFocused(received, focus_type);
    }
  }

  // We'd like to invalidate :focus style for kPage even if element's focus
  // state has not been changed, because the element might have been focused
  // while the page was inactive.
  if (IsFocused() == received && focus_type != mojom::blink::FocusType::kPage) {
    return;
  }

  if (focus_type == mojom::blink::FocusType::kMouse) {
    GetDocument().SetHadKeyboardEvent(false);
  }
  GetDocument().UserActionElements().SetFocused(this, received);

  FocusStateChanged();

  if (received &&
      RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled()) {
    InterestGained();
  }

  if (GetLayoutObject() || received) {
    return;
  }

  // If :focus sets display: none, we lose focus but still need to recalc our
  // style.
  if (!ChildrenOrSiblingsAffectedByFocus()) {
    SetNeedsStyleRecalc(kLocalStyleChange,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_focus));
  }
  PseudoStateChanged(CSSSelector::kPseudoFocus);

  if (!ChildrenOrSiblingsAffectedByFocusVisible()) {
    SetNeedsStyleRecalc(kLocalStyleChange,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_focus_visible));
  }
  PseudoStateChanged(CSSSelector::kPseudoFocusVisible);

  if (!ChildrenOrSiblingsAffectedByFocusWithin()) {
    SetNeedsStyleRecalc(kLocalStyleChange,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_focus_within));
  }
  PseudoStateChanged(CSSSelector::kPseudoFocusWithin);
}

void Element::SetDragged(bool new_value) {
  if (new_value == IsDragged()) {
    return;
  }

  Node::SetDragged(new_value);

  // If :-webkit-drag sets display: none we lose our dragging but still need
  // to recalc our style.
  if (!GetLayoutObject()) {
    if (new_value) {
      return;
    }
    if (ChildrenOrSiblingsAffectedByDrag()) {
      PseudoStateChanged(CSSSelector::kPseudoDrag);
    } else {
      SetNeedsStyleRecalc(kLocalStyleChange,
                          StyleChangeReasonForTracing::CreateWithExtraData(
                              style_change_reason::kPseudoClass,
                              style_change_extra_data::g_drag));
    }
    return;
  }

  if (GetComputedStyle()->AffectedByDrag()) {
    StyleChangeType change_type =
        GetComputedStyle()->HasPseudoElementStyle(kPseudoIdFirstLetter)
            ? kSubtreeStyleChange
            : kLocalStyleChange;
    SetNeedsStyleRecalc(change_type,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_drag));
  }
  if (ChildrenOrSiblingsAffectedByDrag()) {
    PseudoStateChanged(CSSSelector::kPseudoDrag);
  }
}

void Element::UpdateSelectionOnFocus(
    SelectionBehaviorOnFocus selection_behavior) {
  UpdateSelectionOnFocus(selection_behavior, FocusOptions::Create());
}

void Element::UpdateSelectionOnFocus(
    SelectionBehaviorOnFocus selection_behavior,
    const FocusOptions* options) {
  if (selection_behavior == SelectionBehaviorOnFocus::kNone) {
    return;
  }
  if (IsRootEditableElement(*this)) {
    LocalFrame* frame = GetDocument().GetFrame();
    if (!frame) {
      return;
    }

    // When focusing an editable element in an iframe, don't reset the selection
    // if it already contains a selection.
    if (this == frame->Selection()
                    .ComputeVisibleSelectionInDOMTreeDeprecated()
                    .RootEditableElement()) {
      return;
    }

    // FIXME: We should restore the previous selection if there is one.
    // Passing DoNotSetFocus as this function is called after
    // FocusController::setFocusedElement() and we don't want to change the
    // focus to a new Element.
    frame->Selection().SetSelection(
        RuntimeEnabledFeatures::RemoveVisibleSelectionInDOMSelectionEnabled()
            ? CreateVisibleSelection(
                  SelectionInDOMTree::Builder()
                      .Collapse(FirstPositionInOrBeforeNode(*this))
                      .Build())
                  .AsSelection()
            : SelectionInDOMTree::Builder()
                  .Collapse(FirstPositionInOrBeforeNode(*this))
                  .Build(),
        SetSelectionOptions::Builder()
            .SetShouldCloseTyping(true)
            .SetShouldClearTypingStyle(true)
            .SetDoNotSetFocus(true)
            .Build());
    if (!options->preventScroll()) {
      frame->Selection().RevealSelection();
    }
  } else if (GetLayoutObject() &&
             !GetLayoutObject()->IsLayoutEmbeddedContent()) {
    if (!options->preventScroll()) {
      auto params = scroll_into_view_util::CreateScrollIntoViewParams();

      // It's common to have menus and list controls that have items slightly
      // overflowing horizontally but the control isn't horizontally
      // scrollable. Navigating through such a list should make sure items are
      // vertically fully visible but avoid horizontal changes. This mostly
      // matches behavior in WebKit and Gecko (though, the latter has the
      // same behavior vertically) and there's some UA-defined wiggle room in
      // the spec for the scrollIntoViewOptions from focus:
      // https://html.spec.whatwg.org/#dom-focus.
      params->align_x->rect_partial =
          mojom::blink::ScrollAlignment::Behavior::kNoScroll;

      scroll_into_view_util::ScrollRectToVisible(*GetLayoutObject(),
                                                 BoundingBoxForScrollIntoView(),
                                                 std::move(params));
    }
  }
}

void Element::blur() {
  CancelSelectionAfterLayout();
  if (AdjustedFocusedElementInTreeScope() == this) {
    Document& doc = GetDocument();
    if (doc.GetPage()) {
      doc.GetPage()->GetFocusController().SetFocusedElement(nullptr,
                                                            doc.GetFrame());
      if (doc.GetFrame()) {
        doc.GetPage()->GetChromeClient().ClearKeyboardTriggeredTooltip(
            *doc.GetFrame());
      }
    } else {
      doc.ClearFocusedElement();
    }
  }
}

bool Element::SupportsSpatialNavigationFocus() const {
  // This function checks whether the element satisfies the extended criteria
  // for the element to be focusable, introduced by spatial navigation feature,
  // i.e. checks if click or keyboard event handler is specified.
  // This is the way to make it possible to navigate to (focus) elements
  // which web designer meant for being active (made them respond to click
  // events).
  if (!IsSpatialNavigationEnabled(GetDocument().GetFrame())) {
    return false;
  }

  if (!GetLayoutObject()) {
    return false;
  }

  if (HasJSBasedEventListeners(event_type_names::kClick) ||
      HasJSBasedEventListeners(event_type_names::kKeydown) ||
      HasJSBasedEventListeners(event_type_names::kKeypress) ||
      HasJSBasedEventListeners(event_type_names::kKeyup) ||
      HasJSBasedEventListeners(event_type_names::kMouseover) ||
      HasJSBasedEventListeners(event_type_names::kMouseenter)) {
    return true;
  }

  // Some web apps use click-handlers to react on clicks within rects that are
  // styled with {cursor: pointer}. Such rects *look* clickable so they probably
  // are. Here we make Hand-trees' tip, the first (biggest) node with {cursor:
  // pointer}, navigable because users shouldn't need to navigate through every
  // sub element that inherit this CSS.
  if (GetComputedStyle()->Cursor() == ECursor::kPointer &&
      (!ParentComputedStyle() ||
       (ParentComputedStyle()->Cursor() != ECursor::kPointer))) {
    return true;
  }

  if (!IsSVGElement()) {
    return false;
  }
  return (HasEventListeners(event_type_names::kFocus) ||
          HasEventListeners(event_type_names::kBlur) ||
          HasEventListeners(event_type_names::kFocusin) ||
          HasEventListeners(event_type_names::kFocusout));
}

bool Element::CanBeKeyboardFocusableScroller(
    UpdateBehavior update_behavior) const {
  if (!GetDocument().KeyboardFocusableScrollersEnabled()) {
    return false;
  }
  // A node is scrollable depending on its layout size. As such, it is important
  // to have up to date style and layout before calling IsScrollableNode.
  // However, some lifecycle stages don't allow update here so we use
  // UpdateBehavior to guard this behavior.
  switch (update_behavior) {
    case UpdateBehavior::kAssertNoLayoutUpdates:
      CHECK(!GetDocument().NeedsLayoutTreeUpdate());
      [[fallthrough]];
    case UpdateBehavior::kStyleAndLayout:
      GetDocument().UpdateStyleAndLayoutForNode(this,
                                                DocumentUpdateReason::kFocus);
      break;
    case UpdateBehavior::kNoneForAccessibility:
      if (DisplayLockUtilities::IsDisplayLockedPreventingPaint(this, true)) {
        return false;
      }
      break;
    case UpdateBehavior::kNoneForFocusManagement:
      DCHECK(!DisplayLockUtilities::IsDisplayLockedPreventingPaint(this));
      break;
  }
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetDocument().Lifecycle());
  return IsScrollableNode(this);
}

// This can be slow, because it can require a tree walk. It might be
// a good idea to cache this bit on the element to avoid having to
// recompute it. That would require marking that bit dirty whenever
// a node in the subtree was mutated, or when styles for the subtree
// were recomputed.
bool Element::IsKeyboardFocusableScroller(
    UpdateBehavior update_behavior) const {
  DCHECK(
      CanBeKeyboardFocusableScroller(UpdateBehavior::kAssertNoLayoutUpdates));
  // This condition is to avoid clearing the focus in the middle of a
  // keyboard focused scrolling event. If the scroller is currently focused,
  // then let it continue to be focused even if focusable children are added.
  if (GetDocument().FocusedElement() == this) {
    return true;
  }

  for (Node* node = FlatTreeTraversal::FirstChild(*this); node;
       node = FlatTreeTraversal::Next(*node, this)) {
    if (Element* element = DynamicTo<Element>(node)) {
      if (element->IsKeyboardFocusable(update_behavior)) {
        return false;
      }
    }
  }
  return true;
}

bool Element::IsKeyboardFocusable(UpdateBehavior update_behavior) const {
  FocusableState focusable_state = Element::IsFocusableState(update_behavior);
  if (focusable_state == FocusableState::kNotFocusable) {
    return false;
  }
  // If the element has a tabindex, then that determines keyboard
  // focusability.
  if (HasElementFlag(ElementFlags::kTabIndexWasSetExplicitly)) {
    return GetIntegralAttribute(html_names::kTabindexAttr, 0) >= 0;
  }
  // If the element is only potentially focusable because it *might* be a
  // keyboard-focusable scroller, then check whether it actually is.
  if (focusable_state == FocusableState::kKeyboardFocusableScroller) {
    return IsKeyboardFocusableScroller(update_behavior);
  }
  // Otherwise, if the element is focusable, then it should be keyboard-
  // focusable.
  DCHECK_EQ(focusable_state, FocusableState::kFocusable);
  return true;
}

bool Element::IsMouseFocusable(UpdateBehavior update_behavior) const {
  FocusableState focusable_state = Element::IsFocusableState(update_behavior);
  if (focusable_state == FocusableState::kNotFocusable) {
    return false;
  }
  // Any element with tabindex (regardless of its value) is mouse focusable.
  if (HasElementFlag(ElementFlags::kTabIndexWasSetExplicitly)) {
    return true;
  }
  DCHECK_EQ(tabIndex(), DefaultTabIndex());
  // If the element's default tabindex is >=0, it should be click focusable.
  if (DefaultTabIndex() >= 0) {
    return true;
  }
  // If the element is only potentially focusable because it might be a
  // keyboard-focusable scroller, then it should not be mouse focusable.
  if (focusable_state == FocusableState::kKeyboardFocusableScroller) {
    return false;
  }
  DCHECK_EQ(focusable_state, FocusableState::kFocusable);
  return true;
}

bool Element::IsFocusable(UpdateBehavior update_behavior) const {
  return IsFocusableState(update_behavior) != FocusableState::kNotFocusable;
}

FocusableState Element::IsFocusableState(UpdateBehavior update_behavior) const {
  if (!isConnected() || !IsFocusableStyle(update_behavior)) {
    return FocusableState::kNotFocusable;
  }
  return SupportsFocus(update_behavior);
}

FocusableState Element::SupportsFocus(UpdateBehavior update_behavior) const {
  // SupportsFocus must return true when the element is editable, or else
  // it won't be focusable. Furthermore, supportsFocus cannot just return true
  // always or else tabIndex() will change for all HTML elements.
  if (IsShadowHostWithDelegatesFocus()) {
    return FocusableState::kNotFocusable;
  }
  if (HasElementFlag(ElementFlags::kTabIndexWasSetExplicitly) ||
      IsRootEditableElementWithCounting(*this) ||
      IsScrollControlPseudoElement() || SupportsSpatialNavigationFocus()) {
    return FocusableState::kFocusable;
  }
  if (CanBeKeyboardFocusableScroller(update_behavior)) {
    return FocusableState::kKeyboardFocusableScroller;
  }
  return FocusableState::kNotFocusable;
}

bool Element::IsAutofocusable() const {
  // https://html.spec.whatwg.org/C/#global-attributes
  // https://svgwg.org/svg2-draft/struct.html#autofocusattribute
  return (IsHTMLElement() || IsSVGElement()) &&
         FastHasAttribute(html_names::kAutofocusAttr);
}

// This is used by FrameSelection to denote when the active-state of the page
// has changed independent of the focused element changing.
void Element::FocusStateChanged() {
  // If we're just changing the window's active state and the focused node has
  // no layoutObject we can just ignore the state change.
  if (!GetLayoutObject()) {
    return;
  }

  StyleChangeType change_type =
      GetComputedStyle()->HasPseudoElementStyle(kPseudoIdFirstLetter)
          ? kSubtreeStyleChange
          : kLocalStyleChange;
  SetNeedsStyleRecalc(
      change_type,
      StyleChangeReasonForTracing::CreateWithExtraData(
          style_change_reason::kPseudoClass, style_change_extra_data::g_focus));

  PseudoStateChanged(CSSSelector::kPseudoFocus);

  InvalidateIfHasEffectiveAppearance();
  FocusVisibleStateChanged();
  FocusWithinStateChanged();
}

void Element::FocusVisibleStateChanged() {
  StyleChangeType change_type =
      GetComputedStyle()->HasPseudoElementStyle(kPseudoIdFirstLetter)
          ? kSubtreeStyleChange
          : kLocalStyleChange;
  SetNeedsStyleRecalc(ch
"""


```
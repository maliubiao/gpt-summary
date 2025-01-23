Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to identify the key responsibilities of the `AXObject` class based on the methods present in the code. I also need to consider the relationships with web technologies (JavaScript, HTML, CSS), provide examples, reason about the logic, point out potential usage errors, and describe how a user action might lead to this code being executed.

Here's a breakdown of the thought process to address each requirement:

1. **Identify Core Functionality:** Read through the methods and their names. Terms like "Role," "Name," "Focus," "Hidden," "Selected," "TextAlternative" strongly suggest accessibility-related functions. The `AX` prefix reinforces this.

2. **Categorize Functionality:** Group related methods. For example, methods dealing with focus (`CanSetFocusAttribute`, `ComputeCanSetFocusAttribute`), visibility (`IsHiddenViaStyle`, `ComputeIsHiddenViaStyle`), and names (`GetName`, `ComputedName`, `TextAlternative`).

3. **Explain Each Category:**  Describe the purpose of each category in the context of accessibility. For instance, the "Role Determination" category aims to identify the semantic type of a UI element for assistive technologies.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** Many methods interact directly with HTML elements (e.g., `GetElement()`, `DynamicTo<HTMLInputElement>`, checks for specific HTML attributes like `aria-label`, `lang`). Think about how HTML structures the content.
    * **CSS:** Methods like `GetComputedStyle()` and `ComputeIsHiddenViaStyle()` directly relate to how CSS styles and hides elements. Consider how CSS affects the visual presentation and accessibility.
    * **JavaScript:** While not directly apparent in *this* snippet, accessibility information is often exposed to JavaScript through the Accessibility Object Model (AOM). Methods like setting focus or changing ARIA attributes are often triggered or modified by JavaScript. Acknowledge the connection even if it's not explicit here.

5. **Provide Examples:**  For each relationship, give concrete examples. For example, for `DetermineRoleValue`, mention how the role of a `<button>` element would be determined. For `IsHiddenViaStyle`, explain how `display: none` or `visibility: hidden` would affect the result.

6. **Logical Reasoning (Hypothetical Input/Output):** Choose a method with clear logic, like `GetAtomicTextFieldAncestor`. Define a scenario (a text field nested within other elements) and trace the execution to illustrate the input (the starting `AXObject`) and the output (the ancestor text field, or null).

7. **Common Usage Errors:** Think about how developers might misuse accessibility features. Incorrectly applying ARIA attributes (like using `aria-label` on elements where it's prohibited) is a common mistake. Not considering the accessibility implications of hiding elements is another.

8. **User Actions as Debugging Clues:**  Consider how a user interacting with a web page might trigger the execution of this code. Focusing on an element, hovering over it, or the browser needing to present the page to an assistive technology are potential triggers. Describe the steps leading to the code being involved.

9. **Summarize Functionality (for Part 6):**  Based on the identified categories, create a concise summary of the overall purpose of the code. Focus on the core responsibility of providing accessibility information.

10. **Review and Refine:** Read through the generated explanation, ensuring clarity, accuracy, and completeness. Check that all parts of the prompt have been addressed. Make sure the language is easy to understand for someone familiar with web development but perhaps not internal Blink details. Ensure the "part 6 of 10" aspect is addressed by summarizing the specific functionality in this segment.
这是目录为 `blink/renderer/modules/accessibility/ax_object.cc` 的 Chromium Blink 引擎源代码文件的第 6 部分，共 10 部分。根据提供的代码片段，我们可以归纳一下 `AXObject` 类在这一部分的主要功能：

**核心功能归纳:**

这一部分 `AXObject` 类主要负责**确定和管理与可访问性相关的属性和状态**，例如角色、焦点、选中状态、是否隐藏以及辅助技术名称的计算。 它还包含一些用于**在可访问性树中查找特定类型祖先**的实用方法。

**具体功能点:**

* **确定角色 (`DetermineRoleValue`):**  虽然这里只返回 `NativeRoleIgnoringAria()`,  但它标志着角色确定的起点，实际的角色可能会在其他部分的代码中被 ARIA 属性覆盖。
* **判断是否可以设置 `value` 属性 (`CanSetValueAttribute`):**  根据对象的 `RoleValue()` 来判断，例如 `kColorWell`, `kDate`, `kSlider`, `kTextField` 等角色通常可以设置值。
* **判断是否可以设置焦点 (`CanSetFocusAttribute`, `ComputeCanSetFocusAttribute`):**  这是一个复杂的逻辑，考虑了多种因素，包括：
    * 是否是 `WebArea`。
    * 是否有对应的 DOM 节点。
    * 是否被 `inert` 属性标记。
    * 是否是子树所有者 (embedding element)。
    * 是否是禁用的表单控件。
    * 是否是 `<option>` 元素（取决于是否在 `<datalist>` 中）。
    * 是否通过 CSS 隐藏 (`cached_is_hidden_via_style_`)。
    * 元素是否支持焦点 (`elem->SupportsFocus`)。
* **判断是否可以设置选中状态 (`CanSetSelectedAttribute`):**  通常是 `IsSubWidget()` 并且没有被禁用。
* **判断是否是子控件 (`IsSubWidget`):**  例如表格的 `kCell`, 列表框的 `kListBoxOption` 等，并且需要考虑其在可访问性树中的位置（例如，是否在 `kGrid` 或 `kTreeGrid` 中）。
* **判断是否支持 ARIA 的 `setsize` 和 `posinset` 属性 (`SupportsARIASetSizeAndPosInSet`):**  主要针对列表类或条目类的角色，以及 `kRow` 在 `kTreeGrid` 中的情况。
* **处理禁止命名的角色 (`GetProhibitedNameError`, `IsNameProhibited`):**  某些 ARIA 角色（例如 `kCaption`, `kCode`, `kParagraph` 等）不应该直接设置可访问性名称。这段代码会检测这种情况并给出错误提示，并提供修复策略（将名称移到描述字段）。
* **简化名称字符串 (`SimplifyName`):**  去除多余的空格，但保留首尾的单个空格。对于禁止命名的角色，会根据配置将名称置空或移动到描述字段。
* **计算可访问性名称 (`ComputedName`, `GetName`):**  这是获取对象的可访问性名称的核心功能，它会调用 `TextAlternative` 方法。
* **递归计算文本替代 (`RecursiveTextAlternative`):**  用于处理 `aria-labelledby` 和 `aria-describedby` 等属性引用的元素。
* **获取计算后的样式 (`GetComputedStyle`):**  用于判断元素是否被 CSS 隐藏。
* **计算是否通过样式隐藏 (`ComputeIsHiddenViaStyle`):**  考虑了 `display: none`, `visibility: hidden/collapse`, `content-visibility: hidden/auto` 等 CSS 属性。
* **判断是否通过样式隐藏 (`IsHiddenViaStyle`):**  使用缓存的值。
* **判断是否在文本替代计算中被隐藏 (`IsHiddenForTextAlternativeCalculation`):**  综合考虑了 `aria-hidden`, CSS 隐藏，以及是否正在处理 `aria-labelledby` 等情况。
* **判断是否被用于标签或描述 (`IsUsedForLabelOrDescription`, `ComputeIsUsedForLabelOrDescription`):**  判断当前对象或者其祖先是否被用作其他元素的可访问性标签或描述。
* **计算 ARIA 文本替代 (`AriaTextAlternative`):**  处理 `aria-labelledby` 和 `aria-label` 属性，并递归地获取引用的元素的文本内容。
* **从元素集合中获取文本 (`TextFromElements`):**  用于处理 `aria-labelledby` 等属性引用的多个元素，并将它们的文本内容拼接起来。
* **从属性或内部元素获取元素集合 (`ElementsFromAttributeOrInternals`):**  辅助 `aria-labelledby` 等属性查找目标元素。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **`HasAriaAttribute(html_names::kLangAttr)`:**  检查 HTML 元素是否具有 `lang` 属性。这与国际化和辅助技术朗读语言有关。例如，`<p lang="en">Hello</p>` 会返回 true。
    * **`DynamicTo<HTMLInputElement>(&shadow_root->host())`:**  将阴影根的主机转换为 `HTMLInputElement`。这用于处理 input 类型的控件，例如 `<input type="date">`。
    * **`IsDisabledFormControl(elem)`:** 检查 HTML 表单元素是否被 `disabled` 属性禁用。例如，`<button disabled>Submit</button>`。
    * **`IsA<HTMLOptionElement>(elem)`:** 检查是否是 `<option>` 元素，例如 `<select><option>Option 1</option></select>`。
    * **`AriaAttribute(html_names::kAriaLabelAttr)`:**  获取 HTML 元素的 `aria-label` 属性值。例如，`<div aria-label="Close">X</div>` 会返回 "Close"。
    * **`GetElement()->outerHTML()`:**  获取 HTML 元素的外部 HTML 字符串表示。这用于错误信息输出，方便调试。
* **CSS:**
    * **`GetComputedStyle()`:**  获取元素的计算后样式，例如判断 `display: none` 或 `visibility: hidden`。
    * **`style->Visibility() != EVisibility::kVisible`:**  判断 CSS 的 `visibility` 属性是否为 `hidden` 或 `collapse`。例如，`<div style="visibility: hidden;"></div>`。
    * **`style->IsEnsuredInDisplayNone()`:** 判断元素是否由于 `display: none` 而被隐藏。例如，`<div style="display: none;"></div>`。
    * **`DisplayLockUtilities::IsDisplayLockedPreventingPaint(node)`:**  判断元素是否由于 `content-visibility: hidden` 或 `content-visibility: auto` 而被锁定，阻止渲染。例如，`<div style="content-visibility: hidden;"></div>`。
* **JavaScript:**
    * 尽管此代码片段主要是 C++，但 JavaScript 可以通过 DOM API 与这些可访问性属性交互。例如，JavaScript 可以使用 `element.setAttribute('aria-label', 'New Label')` 来修改元素的 ARIA 属性，这会影响 `AriaAttribute` 的返回值。
    * JavaScript 可以通过 `element.focus()` 来触发焦点事件，最终可能导致 `ComputeCanSetFocusAttribute` 被调用。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个 `<div>` 元素，其内部包含一个 `<input type="text">` 元素，并且该 input 元素获得了焦点。

```html
<div>
  <input type="text" id="myInput">
</div>
<script>
  document.getElementById('myInput').focus();
</script>
```

**方法:** `AXObject::GetAtomicTextFieldAncestor(int max_levels_to_check)`

**推理:**

1. 当 `<input type="text">` 元素获得焦点时，会创建一个对应的 `AXObject` 实例。
2. 假设我们对这个 `input` 元素的 `AXObject` 调用 `GetAtomicTextFieldAncestor(2)`。
3. `IsAtomicTextField()` 会返回 true，因为该元素的角色是 `kTextField` (或其他原子文本字段角色)。
4. **输出:** 函数会立即返回 `this` (指向 `input` 元素的 `AXObject`)。

**假设输入:**  一个被 CSS 设置了 `display: none` 的 `<span>` 元素。

```html
<span style="display: none;">This is hidden</span>
```

**方法:** `AXObject::ComputeIsHiddenViaStyle(const ComputedStyle* style)`

**推理:**

1. 当 Blink 引擎渲染或更新这个 `<span>` 元素时，会计算其样式。
2. 传入 `ComputeIsHiddenViaStyle` 的 `ComputedStyle` 指针会反映 `display: none` 的设置。
3. `style->IsEnsuredInDisplayNone()` 会返回 true。
4. **输出:** 函数会返回 true。

**用户或编程常见的使用错误及举例说明:**

* **在禁止命名的角色上使用 ARIA 属性设置名称:**
    * **错误示例 HTML:** `<p aria-label="Paragraph label">This is a paragraph.</p>`
    * **说明:**  `kParagraph` 角色不应该直接设置名称，因为辅助技术通常会读取其内容。开发者应该避免在这种角色上使用 `aria-label` 或 `aria-labelledby`。这段代码中的 `IsNameProhibited()` 会检测到这种情况，并在开发者工具中输出警告。
* **错误地假设所有可见元素都可以获得焦点:**
    * **错误示例 JavaScript:**  尝试对一个 `<div>` 元素调用 `focus()`，但该 `div` 元素没有设置 `tabindex` 属性。
    * **说明:**  并非所有 HTML 元素天生就可获得焦点。开发者需要使用 `tabindex` 属性或使用语义化的可获得焦点的元素（如 `<a>`, `<button>`, `<input>` 等）。`ComputeCanSetFocusAttribute()` 会根据多种条件判断元素是否可以获得焦点，如果缺少必要的条件，则返回 false。
* **过度使用 `aria-hidden` 而不考虑其影响:**
    * **错误示例 HTML:**  使用 `aria-hidden="true"` 隐藏一个包含重要内容的元素，导致辅助技术用户无法访问这些内容。
    * **说明:**  虽然 `aria-hidden` 可以将元素从辅助技术树中移除，但开发者应该谨慎使用，确保不会意外地隐藏用户需要访问的信息。`IsHiddenForTextAlternativeCalculation()` 在计算文本替代时会考虑 `aria-hidden` 属性。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户执行某些操作，例如：
    * **鼠标悬停或点击:** 可能触发事件，导致页面状态变化，进而触发 Blink 引擎的渲染和可访问性树更新。
    * **键盘导航 (Tab 键):**  用户按下 Tab 键在可获得焦点的元素之间切换，这会触发焦点事件，最终会调用到 `AXObject::ComputeCanSetFocusAttribute()` 和相关方法。
    * **使用辅助技术:** 屏幕阅读器等辅助技术尝试获取页面信息时，会调用 Blink 引擎的可访问性 API，从而访问 `AXObject` 及其属性。
    * **页面加载或动态更新:** 当页面加载或通过 JavaScript 动态修改 DOM 结构和样式时，Blink 引擎会重新计算可访问性树，这会涉及到 `AXObject` 的各种方法的调用。

2. **Blink 引擎处理:** 当上述用户操作发生时，Blink 引擎会进行以下处理：
    * **布局计算和样式更新:** 如果操作涉及到元素的大小、位置或可见性变化，Blink 引擎会重新计算布局和样式，这会影响 `GetComputedStyle()` 和 `ComputeIsHiddenViaStyle()` 的结果。
    * **可访问性树构建或更新:** Blink 引擎会根据 DOM 结构和 ARIA 属性构建或更新可访问性树。`AXObject` 是可访问性树的节点，其属性和状态会被计算和更新。
    * **事件触发:**  用户的交互可能触发 JavaScript 事件，JavaScript 代码可能会修改 DOM 结构或 ARIA 属性，从而间接地触发 `AXObject` 的相关方法。

3. **`AXObject` 的方法被调用:**  在可访问性树构建或更新的过程中，以及辅助技术请求信息时，`AXObject` 的各种方法会被调用，例如：
    * 当需要确定一个元素在辅助技术中扮演的角色时，会调用 `DetermineRoleValue()`。
    * 当辅助技术需要获取元素的名称时，会调用 `GetName()` 或 `ComputedName()`。
    * 当用户使用 Tab 键导航时，会调用 `CanSetFocusAttribute()` 和 `ComputeCanSetFocusAttribute()` 来判断哪些元素可以获得焦点。

**作为调试线索:**

当开发者在调试可访问性问题时，理解用户操作如何触发 `AXObject` 的方法调用非常重要。例如：

* **如果屏幕阅读器没有正确朗读某个元素的名称:** 可以检查该元素的 ARIA 属性，并查看 `GetName()` 或 `ComputedName()` 的实现，分析名称是如何被计算出来的，以及 `SimplifyName()` 是否对名称进行了不期望的修改。
* **如果用户无法使用 Tab 键聚焦到某个元素:**  可以检查该元素的 `tabindex` 属性，并分析 `ComputeCanSetFocusAttribute()` 的逻辑，确定是哪个条件导致该元素无法获得焦点。
* **如果某个元素意外地被屏幕阅读器忽略:** 可以检查该元素的 `aria-hidden` 属性以及其 CSS 样式，分析 `IsHiddenViaStyle()` 和 `IsHiddenForTextAlternativeCalculation()` 的结果。

理解用户操作的流程，以及 Blink 引擎如何处理这些操作并调用 `AXObject` 的方法，可以帮助开发者更有效地定位和解决可访问性问题。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
e;
  }

  // Preserve nodes with language attributes.
  if (HasAriaAttribute(html_names::kLangAttr)) {
    return true;
  }

  return false;
}

const AXObject* AXObject::GetAtomicTextFieldAncestor(
    int max_levels_to_check) const {
  if (IsAtomicTextField())
    return this;

  if (max_levels_to_check == 0)
    return nullptr;

  if (AXObject* parent = ParentObject())
    return parent->GetAtomicTextFieldAncestor(max_levels_to_check - 1);

  return nullptr;
}

const AXObject* AXObject::DatetimeAncestor() const {
  ShadowRoot* shadow_root = GetNode()->ContainingShadowRoot();
  if (!shadow_root || shadow_root->GetMode() != ShadowRootMode::kUserAgent) {
    return nullptr;
  }
  auto* input = DynamicTo<HTMLInputElement>(&shadow_root->host());
  if (!input) {
    return nullptr;
  }
  FormControlType type = input->FormControlType();
  if (type != FormControlType::kInputDatetimeLocal &&
      type != FormControlType::kInputDate &&
      type != FormControlType::kInputTime &&
      type != FormControlType::kInputMonth &&
      type != FormControlType::kInputWeek) {
    return nullptr;
  }
  return AXObjectCache().Get(input);
}

ax::mojom::blink::Role AXObject::DetermineRoleValue() {
#if DCHECK_IS_ON()
  base::AutoReset<bool> reentrancy_protector(&is_computing_role_, true);
  DCHECK(!IsDetached());
  // Check parent object to work around circularity issues during AXObject::Init
  // (DetermineRoleValue is called there but before the parent is set).
  if (ParentObject()) {
    DCHECK(GetDocument());
    DCHECK(GetDocument()->Lifecycle().GetState() >=
           DocumentLifecycle::kLayoutClean)
        << "Unclean document at lifecycle "
        << GetDocument()->Lifecycle().ToString();
  }
#endif

  return NativeRoleIgnoringAria();
}

bool AXObject::CanSetValueAttribute() const {
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kColorWell:
    case ax::mojom::blink::Role::kDate:
    case ax::mojom::blink::Role::kDateTime:
    case ax::mojom::blink::Role::kInputTime:
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kSearchBox:
    case ax::mojom::blink::Role::kSlider:
    case ax::mojom::blink::Role::kSpinButton:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kTextField:
    case ax::mojom::blink::Role::kTextFieldWithComboBox:
      return Restriction() == kRestrictionNone;
    default:
      return false;
  }
}

bool AXObject::CanSetFocusAttribute() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_can_set_focus_attribute_;
}

bool AXObject::ComputeCanSetFocusAttribute() {
  DCHECK(!IsDetached());
  DCHECK(GetDocument());

  // Focusable: web area -- this is the only focusable non-element.
  if (IsWebArea()) {
    return true;
  }

  // NOT focusable: objects with no DOM node, e.g. extra layout blocks inserted
  // as filler, or objects where the node is not an element, such as a text
  // node or an HTML comment.
  Element* elem = GetElement();
  if (!elem)
    return false;

  if (cached_is_inert_) {
    return false;
  }

  // NOT focusable: child tree owners (it's the content area that will be marked
  // focusable in the a11y tree).
  if (IsEmbeddingElement()) {
    return false;
  }

  // NOT focusable: disabled form controls.
  if (IsDisabledFormControl(elem))
    return false;

  // Option elements do not receive DOM focus but they do receive a11y focus,
  // unless they are part of a <datalist>, in which case they can be displayed
  // by the browser process, but not the renderer.
  // TODO(crbug.com/1399852) Address gaps in datalist a11y.
  if (auto* option = DynamicTo<HTMLOptionElement>(elem)) {
    return !option->OwnerDataListElement();
  }

  // Invisible nodes are never focusable.
  // We already have these cached, so it's a very quick check.
  // This also prevents implementations of Element::SupportsFocus()
  // from trying to update style on descendants of content-visibility:hidden
  // nodes, or display:none nodes, which are the only nodes that don't have
  // updated style at this point.
  if (cached_is_hidden_via_style_) {
    return false;
  }

  // TODO(crbug.com/1489580) Investigate why this is not yet true, and the
  // early return is necessary, rather than just having a CHECK().
  // At this point, all nodes that are not display:none or
  // content-visibility:hidden should have updated style, which means it is safe
  // to call Element::SupportsFocus(), Element::IsKeyboardFocusable(), and
  // Element::IsFocusableStyle() without causing an update.
  // Updates are problematic when we are expecting the tree to be frozen,
  // or are in the middle of ProcessDeferredAccessibilityEvents(), where an
  // update would cause unwanted recursion.
  // Code that pvoes that this is impossible to reach is at:
  // AXObjectCacheImpl::CheckStyleIsComplete().
  if (elem->NeedsStyleRecalc()) {
    DCHECK(false) << "Avoiding IsFocusableStyle() crash for style update on:"
                  << "\n* Element: " << elem
                  << "\n* LayoutObject: " << elem->GetLayoutObject()
                  << "\n* NeedsStyleRecalc: " << elem->NeedsStyleRecalc()
                  << "\n* IsDisplayLockedPreventingPaint: "
                  << DisplayLockUtilities::IsDisplayLockedPreventingPaint(elem);
    return false;
  }

  // NOT focusable: hidden elements.
  if (!IsA<HTMLAreaElement>(elem) &&
      !elem->IsFocusableStyle(Element::UpdateBehavior::kNoneForAccessibility)) {
    return false;
  }

  // Customizable select: get focusable state from displayed button if present.
  if (auto* select = DynamicTo<HTMLSelectElement>(elem)) {
    if (auto* button = select->SlottedButton()) {
      elem = button;
    }
  }

  // We should not need style updates at this point.
  CHECK(!elem->NeedsStyleRecalc())
      << "\n* Element: " << elem << "\n* Object: " << this
      << "\n* LayoutObject: " << GetLayoutObject();

  // Focusable: element supports focus.
  return elem->SupportsFocus(Element::UpdateBehavior::kNoneForAccessibility) !=
         FocusableState::kNotFocusable;
}

bool AXObject::CanSetSelectedAttribute() const {
  // Sub-widget elements can be selected if not disabled (native or ARIA)
  return IsSubWidget() && Restriction() != kRestrictionDisabled;
}

bool AXObject::IsSubWidget() const {
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kCell:
    case ax::mojom::blink::Role::kColumnHeader:
    case ax::mojom::blink::Role::kRowHeader:
    case ax::mojom::blink::Role::kColumn:
    case ax::mojom::blink::Role::kRow: {
      // It's only a subwidget if it's in a grid or treegrid, not in a table.
      AncestorsIterator ancestor = base::ranges::find_if(
          UnignoredAncestorsBegin(), UnignoredAncestorsEnd(),
          &AXObject::IsTableLikeRole);
      return ancestor.current_ &&
             (ancestor.current_->RoleValue() == ax::mojom::blink::Role::kGrid ||
              ancestor.current_->RoleValue() ==
                  ax::mojom::blink::Role::kTreeGrid);
    }
    case ax::mojom::blink::Role::kGridCell:
    case ax::mojom::blink::Role::kListBoxOption:
    case ax::mojom::blink::Role::kMenuListOption:
    case ax::mojom::blink::Role::kTab:
    case ax::mojom::blink::Role::kTreeItem:
      return true;
    default:
      return false;
  }
}

bool AXObject::SupportsARIASetSizeAndPosInSet() const {
  if (RoleValue() == ax::mojom::blink::Role::kRow) {
    AncestorsIterator ancestor = base::ranges::find_if(
        UnignoredAncestorsBegin(), UnignoredAncestorsEnd(),
        &AXObject::IsTableLikeRole);
    return ancestor.current_ &&
           ancestor.current_->RoleValue() == ax::mojom::blink::Role::kTreeGrid;
  }
  return ui::IsSetLike(RoleValue()) || ui::IsItemLike(RoleValue());
}

std::string AXObject::GetProhibitedNameError(
    const String& prohibited_name,
    ax::mojom::blink::NameFrom& prohibited_name_from) const {
  std::ostringstream error;
  error << "An accessible name was placed on a prohibited role. This "
           "causes inconsistent behavior in screen readers. For example, "
           "<div aria-label=\"foo\"> is invalid as it is not accessible in "
           "every screen reader, because they expect only to read the inner "
           "contents of certain types of containers. Please add a valid role "
           "or put the name on a different object. As a repair technique, "
           "the browser will place the prohibited name in the accessible "
           "description field. To learn more, see the section 'Roles which "
           "cannot be named' in the ARIA specification at "
           "https://w3c.github.io/aria/#namefromprohibited."
        << "\nError details:" << "\n* Element: " << GetElement()
        << "\n* Role: " << InternalRoleName(RoleValue())
        << "\n* Prohibited name: " << prohibited_name
        << "\n* Name from = " << prohibited_name_from << "\n";
  return error.str();
}

// Simplify whitespace, but preserve a single leading and trailing whitespace
// character if it's present.
String AXObject::SimplifyName(const String& str,
                              ax::mojom::blink::NameFrom& name_from) const {
  if (str.empty())
    return "";  // Fast path / early return for many objects in tree.

  // Do not simplify name for text, unless it is pseudo content.
  // TODO(accessibility) There seems to be relatively little value for the
  // special pseudo content rule, and that the null check for node can
  // probably be removed without harm.
  if (GetNode() && ui::IsText(RoleValue()))
    return str;

  String simplified = str.SimplifyWhiteSpace(IsHTMLSpace<UChar>);

  if (GetElement() && !simplified.empty() && IsNameProhibited()) {
    // Enforce that names cannot occur on prohibited roles in Web UI.
    static bool name_on_prohibited_role_error_shown;
    if (!name_on_prohibited_role_error_shown) {
      name_on_prohibited_role_error_shown = true;  // Reduce console spam.
#if DCHECK_IS_ON()
      if (AXObjectCache().IsInternalUICheckerOn(*this)) {
        DCHECK(false)
            << "A prohibited accessible name was used in chromium web UI:\n"
            << GetProhibitedNameError(str, name_from)
            << "* URL: " << GetDocument()->Url()
            << "\n* Outer html: " << GetElement()->outerHTML()
            << "\n* AXObject ancestry:\n"
            << ParentChainToStringHelper(this);
      }
#endif
      if (RuntimeEnabledFeatures::AccessibilityProhibitedNamesEnabled()) {
        // Log error on dev tools console the first time.
        GetElement()->AddConsoleMessage(
            mojom::blink::ConsoleMessageSource::kRendering,
            mojom::blink::ConsoleMessageLevel::kError,
            String(GetProhibitedNameError(str, name_from)));
      }
    }

    if (RuntimeEnabledFeatures::AccessibilityProhibitedNamesEnabled()) {
      // Prohibited names are repaired by moving them to the description field,
      // where they will not override the contents of the element for screen
      // reader users. Exception: if it would be redundant with the inner
      // contents, then the name is stripped out rather than repaired.
      name_from = ax::mojom::blink::NameFrom::kProhibited;
      // If already redundant with inner text, do not repair to description
      if (name_from == ax::mojom::blink::NameFrom::kContents ||
          simplified ==
              GetElement()->GetInnerTextWithoutUpdate().StripWhiteSpace()) {
        name_from = ax::mojom::blink::NameFrom::kProhibitedAndRedundant;
      }
      return "";
    }
  }

  bool has_before_space = IsHTMLSpace<UChar>(str[0]);
  bool has_after_space = IsHTMLSpace<UChar>(str[str.length() - 1]);
  if (!has_before_space && !has_after_space) {
    return simplified;
  }

  // Preserve a trailing and/or leading space.
  StringBuilder result;
  if (has_before_space) {
    result.Append(' ');
  }
  result.Append(simplified);
  if (has_after_space) {
    result.Append(' ');
  }
  return result.ToString();
}

String AXObject::ComputedName(ax::mojom::blink::NameFrom* name_from_out) const {
  ax::mojom::blink::NameFrom name_from;
  AXObjectVector name_objects;
  return GetName(name_from_out ? *name_from_out : name_from, &name_objects);
}

bool AXObject::IsNameProhibited() const {
  if (CanSetFocusAttribute() &&
      !RuntimeEnabledFeatures::AccessibilityMinRoleTabbableEnabled()) {
    // Make an exception for focusable elements. ATs will likely read the name
    // of a focusable element even if it has the wrong role.
    // We do not need to do this if/when AccessibilityMinRoleTabbableEnabled
    // becomes enabled by default, because focusable objects will get a
    // minimum role of group, which can support an accessible name.
    // TODO(crbug.com/350528330): Test to see whether the following content
    // works in all screen readers we support, and if not, we should return true
    // here: <div tabindex="0" aria-label="Some label"></div>. Either way,
    // we should still disallow this pattern in Chromium Web UI.
    return false;
  }

  // Will not be in platform tree.
  if (IsIgnored()) {
    return false;
  }
  // This is temporary in order for web-ui to pass tests.
  // For example, <cr-expand-button> in cr_expand_button.ts expects authors
  // to supply the label by putting aria-label on the <cr-expand-button>
  // element, which it then copies to a second element inside the shadow root,
  // and resulting in two elements with the same aria-label. This could be
  // modified to use data-label instead of aria-label.
  // TODO(crbug.com/350528330):  Fix WebUI and remove this.
  if (GetElement() && GetElement()->IsCustomElement()) {
    return false;
  }

  // The ARIA specification disallows providing accessible names on certain
  // roles because doing so causes problems in screen readers.
  // Roles which probit names: https://w3c.github.io/aria/#namefromprohibited.
  switch (RoleValue()) {
    case ax::mojom::blink::Role::kCaption:
    case ax::mojom::blink::Role::kCode:
    case ax::mojom::blink::Role::kContentDeletion:
    case ax::mojom::blink::Role::kContentInsertion:
    case ax::mojom::blink::Role::kDefinition:
    case ax::mojom::blink::Role::kEmphasis:
    case ax::mojom::blink::Role::kGenericContainer:
    case ax::mojom::blink::Role::kMark:
    case ax::mojom::blink::Role::kNone:
    case ax::mojom::blink::Role::kParagraph:
    case ax::mojom::blink::Role::kStrong:
    case ax::mojom::blink::Role::kSuggestion:
    case ax::mojom::blink::Role::kTerm:
      return true;
    default:
      return false;
  }
}

String AXObject::GetName(ax::mojom::blink::NameFrom& name_from,
                         AXObject::AXObjectVector* name_objects) const {
  HeapHashSet<Member<const AXObject>> visited;
  AXRelatedObjectVector related_objects;

  // Initialize |name_from|, as TextAlternative() might never set it in some
  // cases.
  name_from = ax::mojom::blink::NameFrom::kNone;
  String text = TextAlternative(
      /*recursive=*/false, /*aria_label_or_description_root=*/nullptr, visited,
      name_from, &related_objects, /*name_sources=*/nullptr);

  if (name_objects) {
    name_objects->clear();
    for (NameSourceRelatedObject* related_object : related_objects)
      name_objects->push_back(related_object->object);
  }

  return SimplifyName(text, name_from);
}

String AXObject::GetName(NameSources* name_sources) const {
  AXObjectSet visited;
  ax::mojom::blink::NameFrom name_from;
  AXRelatedObjectVector tmp_related_objects;
  String text = TextAlternative(false, nullptr, visited, name_from,
                                &tmp_related_objects, name_sources);

  return SimplifyName(text, name_from);
}

String AXObject::RecursiveTextAlternative(
    const AXObject& ax_obj,
    const AXObject* aria_label_or_description_root,
    AXObjectSet& visited) {
  ax::mojom::blink::NameFrom tmp_name_from;
  return RecursiveTextAlternative(ax_obj, aria_label_or_description_root,
                                  visited, tmp_name_from);
}

String AXObject::RecursiveTextAlternative(
    const AXObject& ax_obj,
    const AXObject* aria_label_or_description_root,
    AXObjectSet& visited,
    ax::mojom::blink::NameFrom& name_from) {
  if (visited.Contains(&ax_obj) && !aria_label_or_description_root) {
    return String();
  }

  return ax_obj.TextAlternative(true, aria_label_or_description_root, visited,
                                name_from, nullptr, nullptr);
}

const ComputedStyle* AXObject::GetComputedStyle() const {
  if (IsAXInlineTextBox()) {
    return ParentObject()->GetComputedStyle();
  }
  Node* node = GetNode();
  if (!node) {
    return nullptr;
  }

#if DCHECK_IS_ON()
  DCHECK(GetDocument());
  DCHECK(GetDocument()->Lifecycle().GetState() >=
         DocumentLifecycle::kLayoutClean)
      << "Unclean document at lifecycle "
      << GetDocument()->Lifecycle().ToString();
#endif

  // content-visibility:hidden or content-visibility: auto.
  if (DisplayLockUtilities::IsDisplayLockedPreventingPaint(node)) {
    return nullptr;
  }

  // For elements with layout objects we can get their style directly.
  if (GetLayoutObject()) {
    return GetLayoutObject()->Style();
  }
  if (const Element* element = GetElement()) {
    return element->GetComputedStyle();
  }
  return nullptr;
}

// There are 4 ways to use CSS to hide something:
// * "display: none" is "destroy rendering state and don't do anything in the
//   subtree"
// * "visibility: [hidden|collapse]" are "don't visually show things, but still
//   keep all of the rendering up to date"
// * "content-visibility: hidden" is "don't show anything, skip all of the
//   work, but don't destroy the work that was already there"
// * "content-visibility: auto" is "paint when it's scrolled into the viewport,
//   but its layout information is not updated when it isn't"
bool AXObject::ComputeIsHiddenViaStyle(const ComputedStyle* style) {
  // The the parent element of text is hidden, then the text is hidden too.
  // This helps provide more consistent results in edge cases, e.g. text inside
  // of a <canvas> or display:none content.
  if (RoleValue() == ax::mojom::blink::Role::kStaticText) {
    // TODO(accessibility) All text objects should have a parent, and therefore
    // the extra null check should be unnecessary.
    DCHECK(ParentObject());
    if (ParentObject() && ParentObject()->IsHiddenViaStyle()) {
      return true;
    }
  }

  if (style) {
    if (GetLayoutObject()) {
      return style->Visibility() != EVisibility::kVisible;
    }

    // TODO(crbug.com/1286465): It's not consistent to only check
    // IsEnsuredInDisplayNone() on layoutless elements.
    return GetNode() && GetNode()->IsElementNode() &&
           (style->IsEnsuredInDisplayNone() ||
            style->Visibility() != EVisibility::kVisible);
  }

  Node* node = GetNode();
  if (!node)
    return false;

  // content-visibility:hidden or content-visibility: auto.
  if (DisplayLockUtilities::IsDisplayLockedPreventingPaint(node)) {
    // Ensure contents of head, style and script are not exposed when
    // display-locked --the only time they are ever exposed is if author
    // explicitly makes them visible.
    DCHECK(!Traversal<SVGStyleElement>::FirstAncestorOrSelf(*node)) << node;
    DCHECK(!Traversal<HTMLHeadElement>::FirstAncestorOrSelf(*node)) << node;
    DCHECK(!Traversal<HTMLStyleElement>::FirstAncestorOrSelf(*node)) << node;
    DCHECK(!Traversal<HTMLScriptElement>::FirstAncestorOrSelf(*node)) << node;

    // content-visibility: hidden subtrees are always hidden.
    // content-visibility: auto subtrees are treated as visible, as we must
    // make a guess since computed style is not available.
    return DisplayLockUtilities::ShouldIgnoreNodeDueToDisplayLock(
        *node, DisplayLockActivationReason::kAccessibility);
  }

  return node->IsElementNode();
}

bool AXObject::IsHiddenViaStyle() {
  CheckCanAccessCachedValues();

  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_hidden_via_style_;
}

// Return true if this should be removed from accessible name computations.
// We must take into account if we are traversing an aria-labelledby or
// describedby relation, because those can use hidden subtrees. When the target
// node of the aria-labelledby or describedby relation is hidden, we contribute
// all its children, because there is no way to know if they are explicitly
// hidden or they inherited the hidden value. See:
// https://github.com/w3c/accname/issues/57
bool AXObject::IsHiddenForTextAlternativeCalculation(
    const AXObject* aria_label_or_description_root) const {
  auto* node = GetNode();
  if (!node)
    return false;

  // Display-locked elements are available for text/name resolution.
  if (DisplayLockUtilities::IsDisplayLockedPreventingPaint(node))
    return false;

  Document* document = GetDocument();
  if (!document || !document->GetFrame())
    return false;

  // Do not contribute <noscript> to text alternative of an ancestor.
  if (IsA<HTMLNoScriptElement>(node))
    return true;

  // Always contribute SVG <title> despite it having a hidden style by default.
  if (IsA<SVGTitleElement>(node))
    return false;

  // Always contribute SVG <desc> despite it having a hidden style by default.
  if (IsA<SVGDescElement>(node))
    return false;

  // Always contribute text nodes, because they don't have display-related
  // properties of their own, only their parents do. Parents should have been
  // checked for their contribution earlier in the process.
  if (IsA<Text>(node))
    return false;

  // Markers do not contribute to the accessible name.
  // TODO(accessibility): Chrome has never included markers, but that's
  // actually undefined behavior. We will have to revisit after this is
  // settled, see: https://github.com/w3c/accname/issues/76
  if (node->IsMarkerPseudoElement())
    return true;

  // HTML Options build their accessible name even when they are hidden in a
  // collapsed <select>.
  if (!IsAriaHidden() && AncestorMenuListOption()) {
    return false;
  }

  // Step 2A from: http://www.w3.org/TR/accname-aam-1.1
  // When traversing an aria-labelledby relation where the targeted node is
  // hidden, we must contribute its children. There is no way to know if they
  // are explicitly hidden or they inherited the hidden value, so we resort to
  // contributing them all. See also: https://github.com/w3c/accname/issues/57
  if (aria_label_or_description_root &&
      !aria_label_or_description_root->IsVisible()) {
    return false;
  }

  // aria-hidden nodes are generally excluded, with the exception:
  // when computing name/description through an aria-labelledby/describedby
  // relation, if the target of the relation is hidden it will expose the entire
  // subtree, including aria-hidden=true nodes. The exception was accounted in
  // the previous if block, so we are safe to hide any node with a valid
  // aria-hidden=true at this point.
  if (IsAriaHiddenRoot()) {
    return true;
  }

  return IsHiddenViaStyle();
}

bool AXObject::IsUsedForLabelOrDescription() {
  UpdateCachedAttributeValuesIfNeeded();
  return cached_is_used_for_label_or_description_;
}

bool AXObject::ComputeIsUsedForLabelOrDescription() {
  if (GetElement()) {
    // Return true if a <label> or the target of a naming/description
    // relation (<aria-labelledby or aria-describedby).
    if (AXObjectCache().IsLabelOrDescription(*GetElement())) {
      return true;
    }
    // Also return true if a visible, focusable object that gets its name
    // from contents. Requires visibility because a hidden node can only partake
    // in a name or description in the relation case. Note: objects that are
    // visible and focused but aria-hidden can still compute their name from
    // contents as a repair.
    // Note: this must match the SupportsNameFromContents() rule in
    // AXRelationCache::UpdateRelatedText().
    if ((!IsIgnored() || CanSetFocusAttribute()) &&
        SupportsNameFromContents(/*recursive*/ false)) {
      // Descendants of nodes that label themselves via their inner contents
      // and are visible are effectively part of the label for that node.
      return true;
    }
  }

  if (RoleValue() == ax::mojom::blink::Role::kGroup) {
    // Groups do not contribute to ancestor names. There are other roles that
    // don't (listed in SupportsNameFromContents()), but it is not worth
    // the complexity to list each case. Group is relatively common, and
    // also prevents us from considering the popup document (which has kGroup)
    // from returning true.
    return false;
  }

  // Finally, return true if an ancetor is part of a label or description and
  // visibility hasn't changed from visible to hidden
  if (AXObject* parent = ParentObject()) {
    if (parent->IsUsedForLabelOrDescription()) {
      // The parent was part of a label or description. If this object is not
      // hidden, or the parent was also hidden, continue the label/description
      // state into the child.
      bool is_hidden = IsHiddenViaStyle() || IsAriaHidden();
      bool is_parent_hidden =
          parent->IsHiddenViaStyle() || parent->IsAriaHidden();
      if (!is_hidden || is_parent_hidden) {
        return true;
      }
      // Visibility has changed to hidden, where the parent was visible.
      // Iterate through the ancestors that are part of a label/description.
      // If any are part of a label/description relation, consider the hidden
      // node as also part of the label/description, because label and
      // descriptions computed from relations include hidden nodes.
      while (parent && parent->IsUsedForLabelOrDescription()) {
        if (AXObjectCache().IsLabelOrDescription(*parent->GetElement())) {
          return true;
        }
        parent = parent->ParentObject();
      }
    }
  }

  return false;
}

String AXObject::AriaTextAlternative(
    bool recursive,
    const AXObject* aria_label_or_description_root,
    AXObjectSet& visited,
    ax::mojom::blink::NameFrom& name_from,
    AXRelatedObjectVector* related_objects,
    NameSources* name_sources,
    bool* found_text_alternative) const {
  String text_alternative;

  bool already_visited = visited.Contains(this);
  visited.insert(this);

  // Slots are elements that cannot be named.
  if (IsA<HTMLSlotElement>(GetNode())) {
    *found_text_alternative = false;
    return String();
  }

  // Step 2A from: http://www.w3.org/TR/accname-aam-1.1
  if (IsHiddenForTextAlternativeCalculation(aria_label_or_description_root)) {
    *found_text_alternative = true;
    return String();
  }

  // Step 2B from: http://www.w3.org/TR/accname-aam-1.1
  // If you change this logic, update AXObject::IsNameFromAriaAttribute, too.
  if (!aria_label_or_description_root && !already_visited) {
    name_from = ax::mojom::blink::NameFrom::kRelatedElement;
    String text_from_aria_labelledby;

    // Check ARIA attributes.
    const QualifiedName& attr =
        HasAriaAttribute(html_names::kAriaLabeledbyAttr) &&
                !HasAriaAttribute(html_names::kAriaLabelledbyAttr)
            ? html_names::kAriaLabeledbyAttr
            : html_names::kAriaLabelledbyAttr;

    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, attr));
      name_sources->back().type = name_from;
    }

    Element* element = GetElement();
    if (element) {
      const HeapVector<Member<Element>>* elements_from_attribute =
          ElementsFromAttributeOrInternals(element, attr);

      const AtomicString& aria_labelledby = AriaAttribute(attr);

      if (!aria_labelledby.IsNull()) {
        if (name_sources) {
          name_sources->back().attribute_value = aria_labelledby;
        }

        // TODO(crbug/41469336): Show ElementInternals name sources in
        // DevTools
        if (elements_from_attribute) {
          text_from_aria_labelledby = TextFromElements(
              true, visited, *elements_from_attribute, related_objects);
        }
        if (!text_from_aria_labelledby.ContainsOnlyWhitespaceOrEmpty()) {
          if (name_sources) {
            NameSource& source = name_sources->back();
            source.type = name_from;
            source.related_objects = *related_objects;
            source.text = text_alternative = text_from_aria_labelledby;
            *found_text_alternative = true;
          } else {
            *found_text_alternative = true;
            return text_from_aria_labelledby;
          }
        } else if (name_sources) {
          name_sources->back().invalid = true;
        }
      }
    }
  }

  // Step 2C from: http://www.w3.org/TR/accname-aam-1.1
  // If you change this logic, update AXObject::IsNameFromAriaAttribute, too.
  name_from = ax::mojom::blink::NameFrom::kAttribute;
  if (name_sources) {
    name_sources->push_back(
        NameSource(*found_text_alternative, html_names::kAriaLabelAttr));
    name_sources->back().type = name_from;
  }
  const AtomicString& aria_label = AriaAttribute(html_names::kAriaLabelAttr);
  if (!aria_label.GetString().ContainsOnlyWhitespaceOrEmpty()) {
    String text_from_aria_label = aria_label;

    if (name_sources) {
      NameSource& source = name_sources->back();
      source.text = text_alternative = text_from_aria_label;
      source.attribute_value = aria_label;
      *found_text_alternative = true;
    } else {
      *found_text_alternative = true;
      return text_from_aria_label;
    }
  }

  return text_alternative;
}

#if EXPENSIVE_DCHECKS_ARE_ON()
void AXObject::CheckSubtreeIsForLabelOrDescription(const AXObject* obj) const {
  DCHECK(obj->IsUsedForLabelOrDescription())
      << "This object is being used for a label or description, but isn't "
         "flagged as such, which will cause problems for determining whether "
         "invisible nodes should be included in the tree."
      << obj;

  // Set of all children, whether in included or not.
  HeapHashSet<Member<AXObject>> children;

  // If the current object is included, check its children.
  if (obj->IsIncludedInTree()) {
    for (const auto& child : obj->ChildrenIncludingIgnored()) {
      children.insert(child);
    }
  }

  if (obj->GetNode()) {
    // Also check unincluded children.
    for (Node* child_node = NodeTraversal::FirstChild(*obj->GetNode());
         child_node; child_node = NodeTraversal::NextSibling(*child_node)) {
      // Get the child object that should be detached from this parent.
      // Do not invalidate from layout, because it may be unsafe to check layout
      // at this time. However, do allow invalidations if an object changes its
      // display locking (content-visibility: auto) status, as this may be the
      // only chance to do that, and it's safe to do now.
      AXObject* ax_child_from_node = obj->AXObjectCache().Get(child_node);
      if (ax_child_from_node && ax_child_from_node->ParentObject() == this) {
        children.insert(ax_child_from_node);
      }
    }
  }

  for (const auto& ax_child : children) {
    if (ax_child->SupportsNameFromContents(/*recursive*/ false)) {
      CheckSubtreeIsForLabelOrDescription(ax_child);
    }
  }
}
#endif

String AXObject::TextFromElements(
    bool in_aria_labelledby_traversal,
    AXObjectSet& visited,
    const HeapVector<Member<Element>>& elements,
    AXRelatedObjectVector* related_objects) const {
  StringBuilder accumulated_text;
  bool found_valid_element = false;
  AXRelatedObjectVector local_related_objects;

  for (const auto& element : elements) {
    AXObject* ax_element = AXObjectCache().Get(element);
    if (ax_element) {
#if EXPENSIVE_DCHECKS_ARE_ON()
      CheckSubtreeIsForLabelOrDescription(ax_element);
#endif
      found_valid_element = true;
      AXObject* aria_labelled_by_node = nullptr;
      if (in_aria_labelledby_traversal)
        aria_labelled_by_node = ax_element;
      String result =
          RecursiveTextAlternative(*ax_element, aria_labelled_by_node, visited);
      visited.insert(ax_element);
      local_related_objects.push_back(
          MakeGarbageCollected<NameSourceRelatedObject>(ax_element, result));
      if (!result.empty()) {
        if (!accumulated_text.empty())
          accumulated_text.Append(' ');
        accumulated_text.Append(result);
      }
    }
  }
  if (!found_valid_element)
    return String();
  if (related_objects)
    *related_objects = local_related_objects;
  return accumulated_text.ToString();
}

// static
const HeapVector<Member<Element>>* AXObject::ElementsFromAttributeOrInternals(
    const Element* from,
    const QualifiedName& attribute) {
  if (!from)
    return nullptr;

  const HeapVector<Member<Element>>* attr_associated_elements =
      from->GetAttrAssociatedElements(attribute,
                                      /*resolve_reference_target=*/tru
```
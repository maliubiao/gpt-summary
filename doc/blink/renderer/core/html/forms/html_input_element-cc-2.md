Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to identify the key actions and responsibilities of the `HTMLInputElement` class based on the methods and member variables present in the code.

Here's a breakdown of the thought process:

1. **Identify the Core Class:** The code is about the `HTMLInputElement` class. This immediately tells me it's about handling HTML `<input>` elements.

2. **Analyze Key Methods:** I'll go through the provided methods and group them by functionality. This will give me a clear picture of what the class does.

3. **Look for Interactions with Web Technologies:** The prompt specifically asks about relationships with JavaScript, HTML, and CSS. I need to look for methods that suggest these interactions.

4. **Identify Potential Logic and Assumptions:**  Are there conditional statements or specific behaviors that rely on certain inputs or states?  These can be framed as input/output scenarios.

5. **Spot Common User/Programming Errors:** Are there methods or situations where incorrect usage is likely?

6. **Consider the "Part 3" Context:** This implies there are previous parts. The summary should build on the understanding of `HTMLInputElement` established in those parts, though I don't have access to them. I'll focus on summarizing what's explicitly shown here.

**Detailed Analysis of the Code Snippet:**

* **Lifecycle Management:**
    * `InsertedInto`: Handles actions when the `<input>` is added to the DOM (scheduling shadow tree creation, logging).
    * `RemovedFrom`: Handles cleanup when the `<input>` is removed (closing popup, removing from radio group, unscheduling shadow tree).
    * `DidMoveToNewDocument`: Handles actions when the `<input>` moves to a new document (updating image loader, removing from radio group).

* **Validation:**
    * `RecalcWillValidate`: Determines if the input should be validated.
    * `RequiredAttributeChanged`: Handles changes to the `required` attribute.

* **Disabled State:**
    * `DisabledAttributeChanged`: Handles changes to the `disabled` attribute.

* **Color Chooser:**
    * `SelectColorInColorChooser`: Handles color selection.
    * `EndColorChooserForTesting`: Closes the color chooser.

* **Data List (`<datalist>`) Integration:**
    * `DataList`: Retrieves the associated `<datalist>` element.
    * `listForBinding`: Similar to `DataList`, but potentially for binding.
    * `HasValidDataListOptions`: Checks if the `<datalist>` has valid options.
    * `FilteredDataListOptions`: Filters the `<datalist>` options based on input.
    * `SetListAttributeTargetObserver`/`ResetListAttributeTargetObserver`: Manages an observer for changes to the `list` attribute.
    * `ListAttributeTargetChanged`: Handles notifications when the target of the `list` attribute changes.

* **Properties and State:**
    * `IsSteppable`/`IsButton`/`IsTextButton`/`IsEnumeratable`/`IsLabelable`/`MatchesDefaultPseudoClass`:  Query methods about the input's characteristics.
    * `scrollWidth`/`scrollHeight`:  Get the scroll dimensions.
    * `ShouldAppearChecked`: Determines if a checkbox/radio should appear checked.
    * `SetPlaceholderVisibility`: Controls placeholder visibility.
    * `SupportsPlaceholder`: Checks if the input supports placeholders.
    * `GetPlaceholderValue`: Retrieves the placeholder value.
    * `DefaultToolTip`: Gets the default tooltip text.
    * `FileStatusText`: Gets the status text for file inputs.
    * `ShouldApplyMiddleEllipsis`:  Determines if an ellipsis should be used for long file names.
    * `ShouldAppearIndeterminate`: Determines if a checkbox should appear indeterminate.
    * `SupportsPopoverTriggering`: Checks if the input can trigger a popover.
    * `height`/`width`/`setHeight`/`setWidth`: Get and set the `height` and `width` attributes.
    * `SetShouldRevealPassword`: Controls password visibility.

* **Radio Button Group Management:**
    * `GetRadioButtonGroupScope`: Gets the scope for radio button groups.
    * `SizeOfRadioGroup`: Gets the size of the radio button group.
    * `AddToRadioButtonGroup`/`RemoveFromRadioButtonGroup`:  Adds or removes the input from a radio button group.

* **Text Manipulation:**
    * `setRangeText`: Sets text within a range (with and without selection mode).

* **Date/Time Chooser:**
    * `SetupDateTimeChooserParameters`: Prepares parameters for a date/time picker.

* **Input Mode:**
    * `SupportsInputModeAttribute`: Checks if the input supports the `inputmode` attribute.

* **Accessibility:**
    * `PopupRootAXObject`: Gets the root accessibility object for popups.

* **Shadow DOM:**
    * Methods related to creating and managing the shadow DOM (`scheduled_create_shadow_tree_`, `CreateInnerEditorElementIfNecessary`, `UpdatePlaceholderText`, `EnsureFallbackContent`, `EnsurePrimaryContent`, `HasFallbackContent`, `ChildrenChanged`).

* **File Handling:**
    * `SetFilesFromPaths`: Sets files for file inputs.

* **Scrolling:**
    * `GetLayoutBoxForScrolling`: Returns the appropriate layout box for scrolling.

* **Mutability:**
    * `isMutable`: Determines if the input is mutable.

* **Picker Invocation:**
    * `showPicker`: Opens the browser's picker UI.

* **Command Handling:**
    * `IsValidBuiltinCommand`: Checks if a command is valid for this input.
    * `HandleCommandInternal`: Handles specific commands (like showing the picker, stepping up/down for number inputs).

* **Focus Management:**
    * `SetFocused`: Handles focus changes.

* **Styling:**
    * `AdjustStyle`: Allows modification of the input's style.

* **Other:**
    * `CapsLockStateMayHaveChanged`/`ShouldDrawCapsLockIndicator`: Handles Caps Lock state for password fields.
    * `DidNotifySubtreeInsertionsToDocument`: Handles notifications about subtree insertions.
    * `IsDraggedSlider`: Checks if a range input's slider is being dragged.

**Structuring the Summary:** I'll organize the summary by functional area to make it easier to understand.

**Addressing Specific Prompt Requirements:**

* **JavaScript, HTML, CSS Relationships:** I'll provide examples of how the code interacts with these technologies (e.g., attributes in HTML, styling with CSS, event handling potentially triggered by JavaScript).
* **Logic and Assumptions:** I'll create simple input/output scenarios based on the code's logic.
* **Common Errors:** I'll think about typical mistakes developers might make when using `<input>` elements.

By following these steps, I can generate a comprehensive and accurate summary that addresses all aspects of the user's request.
这是 `blink/renderer/core/html/forms/html_input_element.cc` 文件的第三部分，它延续了对 `HTMLInputElement` 类的实现。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能总结 (基于提供的代码片段):**

* **处理 `<datalist>` 关联:**  这部分代码着重处理 `<input>` 元素与 `<datalist>` 元素的关联。它负责查找、过滤和展示 `<datalist>` 中匹配的 `<option>` 元素作为输入建议。
* **管理 `list` 属性观察者:**  它维护一个观察者 (`ListAttributeTargetObserver`)，用于监听 `list` 属性指向的 `<datalist>` 元素的变化，并在变化时更新输入框的行为。
* **提供属性和状态查询:**  提供一系列方法来查询输入元素的状态和特性，例如是否可步进 (`IsSteppable`)，是否为按钮 (`IsButton`)，是否可被标签关联 (`IsLabelable`) 等。
* **处理滚动:**  针对文本类型的输入框，提供自定义的 `scrollWidth` 和 `scrollHeight` 计算，考虑了内联编辑器和可能的预览状态。
* **管理占位符 (Placeholder):**  控制和更新占位符文本的显示。
* **提供默认工具提示:**  为不同类型的输入框提供默认的工具提示文本。
* **处理文件状态文本:**  对于文件选择类型的输入框，提供文件状态相关的文本。
* **判断是否显示省略号:**  决定是否在文件选择类型的输入框中显示中间省略号。
* **处理不确定状态:**  对于某些类型的输入框（如复选框），判断是否应显示为不确定状态。
* **管理单选按钮组:**  当输入类型为 `radio` 时，负责将其添加到所属的单选按钮组或从中移除。
* **获取和设置高度/宽度:**  提供获取和设置 `height` 和 `width` HTML 属性的方法。
* **实现 `setRangeText` 方法:**  允许通过脚本设置输入框中指定范围的文本。
* **配置日期/时间选择器参数:**  为日期和时间类型的输入框准备参数，以便弹出系统或浏览器提供的选择器。
* **支持 `inputmode` 属性:**  指示输入元素是否支持 `inputmode` 属性。
* **处理 Caps Lock 状态:**  在密码输入框中，可能处理 Caps Lock 键的状态提示。
* **实现 `showPicker` 方法:**  允许通过脚本触发浏览器原生的选择器（例如日期、颜色、文件选择等）。
* **处理内置命令:**  响应特定的内置命令，例如 `stepUp`、`stepDown` (对于数字输入框) 和 `showPicker`。
* **管理焦点状态:**  当输入元素获得或失去焦点时执行相应的操作。
* **辅助功能 (Accessibility):**  提供获取弹出窗口根 AX 对象的接口。
* **处理后备内容 (Fallback Content):**  确保为某些输入类型创建或管理后备内容。
* **处理文件路径设置:**  允许通过文件路径设置文件选择输入框的文件。
* **处理子节点变化:**  当输入元素的子节点发生变化时执行相应的操作。
* **判断是否为拖动中的滑块:**  用于范围类型的输入框，判断滑块是否正在被拖动。
* **判断是否可变 (Mutable):**  判断输入元素是否可编辑。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **`list` 属性:**  通过 `DataList()` 方法获取 `list` 属性关联的 `<datalist>` 元素。例如，HTML 中有 `<input type="text" list="suggestions">` 和 `<datalist id="suggestions"><option value="apple"></option></datalist>`，代码会查找 id 为 `suggestions` 的 `<datalist>`。
    * **`height` 和 `width` 属性:**  `setHeight()` 和 `setWidth()` 方法对应于设置 HTML 元素的 `height` 和 `width` 属性。
    * **事件处理:**  尽管代码片段中没有直接展示事件处理，但 `HTMLInputElement` 会响应各种 HTML 事件，例如 `input`, `change`, `focus`, `blur` 等。
    * **表单交互:**  `Form()` 方法用于获取输入框所属的 `<form>` 元素，这与 HTML 表单的提交和验证机制相关。
    * **属性变化:**  `RequiredAttributeChanged()`, `DisabledAttributeChanged()` 等方法响应 HTML 属性的变化。

* **JavaScript:**
    * **DOM 操作:**  JavaScript 可以通过 DOM API 获取 `HTMLInputElement` 对象，并调用其方法，例如 `setRangeText()` 或 `showPicker()`。
    * **事件监听:**  JavaScript 可以监听输入框上的事件，并根据其状态和行为执行操作。
    * **表单控制:**  JavaScript 可以读取和修改输入框的值，以及控制表单的提交。

* **CSS:**
    * **样式应用:**  CSS 样式会影响输入框的外观，例如宽度、高度、颜色等。代码中的 `scrollWidth()` 和 `scrollHeight()` 计算会考虑元素的 CSS 盒模型。
    * **伪类 (Pseudo-classes):**  `MatchesDefaultPseudoClass()` 方法可能与 CSS 伪类（如 `:default`）的匹配有关。
    * **`:user-valid` 和 `:user-invalid` 伪类:** `SetFocused()` 方法中提到在失去焦点且用户编辑过字段后会触发 `:user-valid` 和 `:user-invalid` 的匹配，这与 CSS 的表单验证样式相关。
    * **`-webkit-text-security` 样式:** `SetShouldRevealPassword()` 方法会更新 `-webkit-text-security` 样式，用于控制密码的显示方式。

**逻辑推理与假设输入/输出:**

* **假设输入:** 用户在文本输入框中输入 "ap"。
* **逻辑推理:** `FilteredDataListOptions()` 方法会被调用，它会遍历与该输入框关联的 `<datalist>` 中的 `<option>` 元素，并比较 `<option>` 的 `value` 或 `label` 是否包含 "ap"（忽略大小写和空格）。
* **输出:**  该方法会返回一个包含所有 `value` 或 `label` 包含 "ap" 的 `<option>` 元素的列表，这些元素将作为输入建议展示给用户。

* **假设输入:**  一个 `type="radio"` 的输入框的 `name` 属性与其他单选按钮相同，并且该输入框被插入到 DOM 中。
* **逻辑推理:** `InsertedInto()` 方法会被调用，然后 `AddToRadioButtonGroup()` 方法会将该输入框添加到与其 `name` 属性相同的单选按钮组中。
* **输出:**  该输入框现在成为该单选按钮组的一部分，与组内的其他单选按钮互斥。

**用户或编程常见的使用错误举例说明:**

* **忘记设置 `<datalist>` 的 `id` 属性，或者 `<input>` 的 `list` 属性指向不存在的 `id`:**  这会导致 `DataList()` 方法返回 `nullptr`，输入框无法显示任何建议。
* **在 JavaScript 中错误地调用 `setRangeText()` 方法，提供的 `start` 或 `end` 超出输入框文本的长度:**  这会导致异常抛出。
* **在跨域的 iframe 中调用 `showPicker()` 方法 (非 `file` 或 `color` 类型):**  这会抛出一个 "SecurityError" 类型的 DOMException。
* **在没有用户手势的情况下调用 `showPicker()` 方法:**  这会抛出一个 "NotAllowedError" 类型的 DOMException。
* **尝试对 `disabled` 或 `readonly` 的输入框调用 `showPicker()` 或其他修改值的方法:** 这会导致 "InvalidStateError" 类型的 DOMException。

**总结 `HTMLInputElement.cc` (第三部分) 的功能:**

总而言之，这部分 `HTMLInputElement.cc` 代码主要负责实现 `<input>` 元素的高级功能，包括与 `<datalist>` 的集成、属性和状态管理、滚动处理、占位符管理、工具提示、单选按钮组的管理、文本范围操作、日期/时间选择器的配置、`showPicker()` 方法的实现，以及处理一些内置命令。它提供了丰富的接口和逻辑，使得 `<input>` 元素能够提供更复杂和用户友好的交互体验。这部分代码是 Blink 引擎中处理 HTML 表单元素交互逻辑的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_input_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
hadow_tree_ = true;
      GetDocument().ScheduleShadowTreeCreation(*this);
    }
  }
  ResetListAttributeTargetObserver();
  LogAddElementIfIsolatedWorldAndInDocument("input", html_names::kTypeAttr,
                                            html_names::kFormactionAttr);
  if (!RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled()) {
    EventDispatchForbiddenScope::AllowUserAgentEvents allow_events;
    input_type_view_->CreateShadowSubtreeIfNeeded();
  }
  return kInsertionShouldCallDidNotifySubtreeInsertions;
}

void HTMLInputElement::RemovedFrom(ContainerNode& insertion_point) {
  input_type_view_->ClosePopupView();
  if (insertion_point.isConnected()) {
    if (!Form()) {
      RemoveFromRadioButtonGroup();
    }
    if (scheduled_create_shadow_tree_) {
      scheduled_create_shadow_tree_ = false;
      GetDocument().UnscheduleShadowTreeCreation(*this);
    }
  }
  TextControlElement::RemovedFrom(insertion_point);
  DCHECK(!isConnected());
  ResetListAttributeTargetObserver();
}

void HTMLInputElement::DidMoveToNewDocument(Document& old_document) {
  if (ImageLoader())
    ImageLoader()->ElementDidMoveToNewDocument();

  // FIXME: Remove type check.
  if (FormControlType() == FormControlType::kInputRadio) {
    GetTreeScope().GetRadioButtonGroupScope().RemoveButton(this);
  }

  TextControlElement::DidMoveToNewDocument(old_document);
}

bool HTMLInputElement::RecalcWillValidate() const {
  return input_type_->SupportsValidation() &&
         TextControlElement::RecalcWillValidate();
}

void HTMLInputElement::RequiredAttributeChanged() {
  TextControlElement::RequiredAttributeChanged();
  if (RadioButtonGroupScope* scope = GetRadioButtonGroupScope())
    scope->RequiredAttributeChanged(this);
  input_type_view_->RequiredAttributeChanged();
}

void HTMLInputElement::DisabledAttributeChanged() {
  TextControlElement::DisabledAttributeChanged();
  input_type_view_->DisabledAttributeChanged();
}

void HTMLInputElement::SelectColorInColorChooser(const Color& color) {
  if (ColorChooserClient* client = input_type_->GetColorChooserClient())
    client->DidChooseColor(color);
}

void HTMLInputElement::EndColorChooserForTesting() {
  input_type_view_->ClosePopupView();
}

HTMLDataListElement* HTMLInputElement::DataList() const {
  if (!has_non_empty_list_) {
    return nullptr;
  }

  if (!input_type_->ShouldRespectListAttribute()) {
    return nullptr;
  }

  return DynamicTo<HTMLDataListElement>(
      GetElementAttributeResolvingReferenceTarget(html_names::kListAttr));
}

HTMLElement* HTMLInputElement::listForBinding() const {
  if (!has_non_empty_list_) {
    return nullptr;
  }

  if (!input_type_->ShouldRespectListAttribute()) {
    return nullptr;
  }

  return DynamicTo<HTMLDataListElement>(
      GetElementAttribute(html_names::kListAttr));
}

bool HTMLInputElement::HasValidDataListOptions() const {
  HTMLDataListElement* data_list = DataList();
  if (!data_list)
    return false;
  HTMLDataListOptionsCollection* options = data_list->options();
  for (unsigned i = 0; HTMLOptionElement* option = options->Item(i); ++i) {
    if (!option->value().empty() && !option->IsDisabledFormControl())
      return true;
  }
  return false;
}

HeapVector<Member<HTMLOptionElement>>
HTMLInputElement::FilteredDataListOptions() const {
  HeapVector<Member<HTMLOptionElement>> filtered;
  HTMLDataListElement* data_list = DataList();
  if (!data_list)
    return filtered;

  // Ensure the editor has been created as InnerEditorValue() returns an empty
  // string if the editor wasn't created.
  EnsureInnerEditorElement();

  String editor_value = InnerEditorValue();
  if (Multiple() && FormControlType() == FormControlType::kInputEmail) {
    Vector<String> emails;
    editor_value.Split(',', true, emails);
    if (!emails.empty())
      editor_value = emails.back().StripWhiteSpace();
  }

  HTMLDataListOptionsCollection* options = data_list->options();
  filtered.reserve(options->length());
  editor_value = editor_value.FoldCase();

  TextBreakIterator* iter =
      WordBreakIterator(editor_value, 0, editor_value.length());

  Vector<bool> filtering_flag(options->length(), true);
  if (iter) {
    for (int word_start = iter->current(), word_end = iter->next();
         word_end != kTextBreakDone; word_end = iter->next()) {
      String value = editor_value.Substring(word_start, word_end - word_start);
      word_start = word_end;

      if (!IsWordBreak(value[0]))
        continue;

      for (unsigned i = 0; i < options->length(); ++i) {
        if (!filtering_flag[i])
          continue;
        HTMLOptionElement* option = options->Item(i);
        DCHECK(option);
        if (!value.empty()) {
          // Firefox shows OPTIONs with matched labels, Edge shows OPTIONs
          // with matches values. We show both.
          if (!(option->value()
                        .FoldCase()
                        .RemoveCharacters(IsWhitespace)
                        .Find(value) == kNotFound &&
                option->label()
                        .FoldCase()
                        .RemoveCharacters(IsWhitespace)
                        .Find(value) == kNotFound))
            continue;
        }
        filtering_flag[i] = false;
      }
    }
  }

  for (unsigned i = 0; i < options->length(); ++i) {
    HTMLOptionElement* option = options->Item(i);
    DCHECK(option);
    if (option->value().empty() || option->IsDisabledFormControl())
      continue;
    if (filtering_flag[i])
      filtered.push_back(option);
  }
  return filtered;
}

void HTMLInputElement::SetListAttributeTargetObserver(
    ListAttributeTargetObserver* new_observer) {
  if (list_attribute_target_observer_)
    list_attribute_target_observer_->Unregister();
  list_attribute_target_observer_ = new_observer;
}

void HTMLInputElement::ResetListAttributeTargetObserver() {
  const AtomicString& value = FastGetAttribute(html_names::kListAttr);
  if (!value.IsNull() && isConnected()) {
    SetListAttributeTargetObserver(
        MakeGarbageCollected<ListAttributeTargetObserver>(value, this));
  } else {
    SetListAttributeTargetObserver(nullptr);
  }
}

void HTMLInputElement::ListAttributeTargetChanged() {
  input_type_view_->ListAttributeTargetChanged();
  PseudoStateChanged(CSSSelector::kPseudoHasDatalist);
}

bool HTMLInputElement::IsSteppable() const {
  return input_type_->IsSteppable();
}

bool HTMLInputElement::IsButton() const {
  return input_type_->IsButton();
}

bool HTMLInputElement::IsTextButton() const {
  return input_type_->IsTextButton();
}

bool HTMLInputElement::IsEnumeratable() const {
  return input_type_->IsEnumeratable();
}

bool HTMLInputElement::IsLabelable() const {
  return input_type_->IsInteractiveContent();
}

bool HTMLInputElement::MatchesDefaultPseudoClass() const {
  return input_type_->MatchesDefaultPseudoClass();
}

int HTMLInputElement::scrollWidth() {
  if (!IsTextField())
    return TextControlElement::scrollWidth();
  // If in preview state, fake the scroll width to prevent that any information
  // about the suggested content can be derived from the size.
  if (!SuggestedValue().empty())
    return clientWidth();

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  const auto* editor = InnerEditorElement();
  const auto* editor_box = editor ? editor->GetLayoutBox() : nullptr;
  const auto* box = GetLayoutBox();
  if (!editor_box || !box)
    return TextControlElement::scrollWidth();
  // Adjust scrollWidth to include input element horizontal paddings and
  // decoration width.
  LayoutUnit adjustment = box->ClientWidth() - editor_box->ClientWidth();
  int snapped_scroll_width =
      SnapSizeToPixel(editor_box->ScrollWidth() + adjustment,
                      box->PhysicalLocation().left + box->ClientLeft());
  return AdjustForAbsoluteZoom::AdjustLayoutUnit(
             LayoutUnit(snapped_scroll_width), box->StyleRef())
      .Round();
}

int HTMLInputElement::scrollHeight() {
  if (!IsTextField())
    return TextControlElement::scrollHeight();

  // If in preview state, fake the scroll height to prevent that any information
  // about the suggested content can be derived from the size.
  if (!SuggestedValue().empty())
    return clientHeight();

  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  const auto* editor = InnerEditorElement();
  const auto* editor_box = editor ? editor->GetLayoutBox() : nullptr;
  const auto* box = GetLayoutBox();
  if (!editor_box || !box)
    return TextControlElement::scrollHeight();
  // Adjust scrollHeight to include input element vertical paddings and
  // decoration height.
  LayoutUnit adjustment = box->ClientHeight() - editor_box->ClientHeight();
  return AdjustForAbsoluteZoom::AdjustLayoutUnit(
             editor_box->ScrollHeight() + adjustment, box->StyleRef())
      .Round();
}

bool HTMLInputElement::ShouldAppearChecked() const {
  return Checked() && IsCheckable();
}

void HTMLInputElement::SetPlaceholderVisibility(bool visible) {
  is_placeholder_visible_ = visible;
}

bool HTMLInputElement::SupportsPlaceholder() const {
  return input_type_->SupportsPlaceholder();
}

void HTMLInputElement::CreateInnerEditorElementIfNecessary() const {
  input_type_view_->CreateShadowSubtreeIfNeeded();
}

HTMLElement* HTMLInputElement::UpdatePlaceholderText() {
  return input_type_view_->UpdatePlaceholderText(!SuggestedValue().empty());
}

String HTMLInputElement::GetPlaceholderValue() const {
  return !SuggestedValue().empty() ? SuggestedValue() : StrippedPlaceholder();
}

String HTMLInputElement::DefaultToolTip() const {
  return input_type_->DefaultToolTip(*input_type_view_);
}

String HTMLInputElement::FileStatusText() const {
  return input_type_view_->FileStatusText();
}

bool HTMLInputElement::ShouldApplyMiddleEllipsis() const {
  return files() && files()->length() <= 1;
}

bool HTMLInputElement::ShouldAppearIndeterminate() const {
  return input_type_->ShouldAppearIndeterminate();
}

HTMLFormControlElement::PopoverTriggerSupport
HTMLInputElement::SupportsPopoverTriggering() const {
  return input_type_->SupportsPopoverTriggering();
}

RadioButtonGroupScope* HTMLInputElement::GetRadioButtonGroupScope() const {
  // FIXME: Remove type check.
  if (FormControlType() != FormControlType::kInputRadio) {
    return nullptr;
  }
  if (HTMLFormElement* form_element = Form())
    return &form_element->GetRadioButtonGroupScope();
  if (isConnected())
    return &GetTreeScope().GetRadioButtonGroupScope();
  return nullptr;
}

unsigned HTMLInputElement::SizeOfRadioGroup() const {
  RadioButtonGroupScope* scope = GetRadioButtonGroupScope();
  if (!scope)
    return 0;
  return scope->GroupSizeFor(this);
}

inline void HTMLInputElement::AddToRadioButtonGroup() {
  if (RadioButtonGroupScope* scope = GetRadioButtonGroupScope())
    scope->AddButton(this);
}

inline void HTMLInputElement::RemoveFromRadioButtonGroup() {
  if (RadioButtonGroupScope* scope = GetRadioButtonGroupScope())
    scope->RemoveButton(this);
}

unsigned HTMLInputElement::height() const {
  return input_type_->Height();
}

unsigned HTMLInputElement::width() const {
  return input_type_->Width();
}

void HTMLInputElement::setHeight(unsigned height) {
  SetUnsignedIntegralAttribute(html_names::kHeightAttr, height);
}

void HTMLInputElement::setWidth(unsigned width) {
  SetUnsignedIntegralAttribute(html_names::kWidthAttr, width);
}

ListAttributeTargetObserver::ListAttributeTargetObserver(
    const AtomicString& id,
    HTMLInputElement* element)
    : IdTargetObserver(element->GetTreeScope().EnsureIdTargetObserverRegistry(),
                       id),
      element_(element) {}

void ListAttributeTargetObserver::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  IdTargetObserver::Trace(visitor);
}

void ListAttributeTargetObserver::IdTargetChanged() {
  element_->ListAttributeTargetChanged();
}

void HTMLInputElement::setRangeText(const String& replacement,
                                    ExceptionState& exception_state) {
  if (!input_type_->SupportsSelectionAPI()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The input element's type ('" + input_type_->FormControlTypeAsString() +
            "') does not support selection.");
    return;
  }

  TextControlElement::setRangeText(replacement, exception_state);
}

void HTMLInputElement::setRangeText(const String& replacement,
                                    unsigned start,
                                    unsigned end,
                                    const V8SelectionMode& selection_mode,
                                    ExceptionState& exception_state) {
  if (!input_type_->SupportsSelectionAPI()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The input element's type ('" + input_type_->FormControlTypeAsString() +
            "') does not support selection.");
    return;
  }

  TextControlElement::setRangeText(replacement, start, end, selection_mode,
                                   exception_state);
}

bool HTMLInputElement::SetupDateTimeChooserParameters(
    DateTimeChooserParameters& parameters) {
  if (!GetDocument().View())
    return false;

  parameters.type = input_type_->type();
  parameters.minimum = Minimum();
  parameters.maximum = Maximum();
  parameters.required = IsRequired();
  if (!RuntimeEnabledFeatures::LangAttributeAwareFormControlUIEnabled()) {
    parameters.locale = DefaultLanguage();
  } else {
    AtomicString computed_locale = ComputeInheritedLanguage();
    parameters.locale =
        computed_locale.empty() ? DefaultLanguage() : computed_locale;
  }

  StepRange step_range = CreateStepRange(kRejectAny);
  if (step_range.HasStep()) {
    parameters.step = step_range.Step().ToDouble();
    parameters.step_base = step_range.StepBase().ToDouble();
  } else {
    parameters.step = 1.0;
    parameters.step_base = 0;
  }

  parameters.anchor_rect_in_screen =
      GetDocument().View()->FrameToScreen(PixelSnappedBoundingBox());
  parameters.double_value = input_type_->ValueAsDouble();
  parameters.focused_field_index = input_type_view_->FocusedFieldIndex();
  parameters.is_anchor_element_rtl =
      GetLayoutObject()
          ? input_type_view_->ComputedTextDirection() == TextDirection::kRtl
          : false;
  if (HTMLDataListElement* data_list = DataList()) {
    HTMLDataListOptionsCollection* options = data_list->options();
    for (unsigned i = 0; HTMLOptionElement* option = options->Item(i); ++i) {
      if (option->value().empty() || option->IsDisabledFormControl() ||
          !IsValidValue(option->value()))
        continue;
      auto suggestion = mojom::blink::DateTimeSuggestion::New();
      suggestion->value =
          input_type_->ParseToNumber(option->value(), Decimal::Nan())
              .ToDouble();
      if (std::isnan(suggestion->value))
        continue;
      suggestion->localized_value = LocalizeValue(option->value());
      suggestion->label =
          option->value() == option->label() ? String("") : option->label();
      parameters.suggestions.push_back(std::move(suggestion));
    }
  }
  return true;
}

bool HTMLInputElement::SupportsInputModeAttribute() const {
  return input_type_->SupportsInputModeAttribute();
}

void HTMLInputElement::CapsLockStateMayHaveChanged() {
  input_type_view_->CapsLockStateMayHaveChanged();
}

bool HTMLInputElement::ShouldDrawCapsLockIndicator() const {
  return input_type_view_->ShouldDrawCapsLockIndicator();
}

void HTMLInputElement::SetShouldRevealPassword(bool value) {
  if (!!should_reveal_password_ == value)
    return;
  should_reveal_password_ = value;
  if (HTMLElement* inner_editor = InnerEditorElement()) {
    // Update -webkit-text-security style.
    inner_editor->SetNeedsStyleRecalc(
        kLocalStyleChange,
        StyleChangeReasonForTracing::Create(style_change_reason::kControl));
  }
}

#if BUILDFLAG(IS_ANDROID)
bool HTMLInputElement::IsLastInputElementInForm() {
  DCHECK(GetDocument().GetPage());
  return !GetDocument()
              .GetPage()
              ->GetFocusController()
              .NextFocusableElementForImeAndAutofill(
                  this, mojom::blink::FocusType::kForward);
}

void HTMLInputElement::DispatchSimulatedEnter() {
  DCHECK(GetDocument().GetPage());
  GetDocument().GetPage()->GetFocusController().SetFocusedElement(
      this, GetDocument().GetFrame());

  EventDispatcher::DispatchSimulatedEnterEvent(*this);
}
#endif

bool HTMLInputElement::IsInteractiveContent() const {
  return input_type_->IsInteractiveContent();
}

void HTMLInputElement::AdjustStyle(ComputedStyleBuilder& builder) {
  return input_type_view_->AdjustStyle(builder);
}

void HTMLInputElement::DidNotifySubtreeInsertionsToDocument() {
  ListAttributeTargetChanged();
}

AXObject* HTMLInputElement::PopupRootAXObject() {
  return input_type_view_->PopupRootAXObject();
}

void HTMLInputElement::EnsureFallbackContent() {
  input_type_view_->EnsureFallbackContent();
}

void HTMLInputElement::EnsurePrimaryContent() {
  input_type_view_->EnsurePrimaryContent();
}

bool HTMLInputElement::HasFallbackContent() const {
  return input_type_view_->HasFallbackContent();
}

void HTMLInputElement::SetFilesFromPaths(const Vector<String>& paths) {
  return input_type_->SetFilesFromPaths(paths);
}

void HTMLInputElement::ChildrenChanged(const ChildrenChange& change) {
  // Some input types only need shadow roots to hide any children that may
  // have been appended by script. For such types, shadow roots are lazily
  // created when children are added for the first time. For the case of
  // `kFinishedBuildingDocumentFragmentTree` this function may be called
  // when the HTMLInputElement has no children.
  if (change.type !=
          ChildrenChangeType::kFinishedBuildingDocumentFragmentTree ||
      HasChildren()) {
    EnsureUserAgentShadowRoot();
  }
  ContainerNode::ChildrenChanged(change);
}

LayoutBox* HTMLInputElement::GetLayoutBoxForScrolling() const {
  // If it's LayoutTextControlSingleLine, return InnerEditorElement's LayoutBox.
  if (IsTextField() && InnerEditorElement())
    return InnerEditorElement()->GetLayoutBox();
  return Element::GetLayoutBoxForScrolling();
}

bool HTMLInputElement::IsDraggedSlider() const {
  return input_type_view_->IsDraggedSlider();
}

// https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#concept-fe-mutable
bool HTMLInputElement::isMutable() {
  return !IsDisabledFormControl() &&
         !(input_type_->SupportsReadOnly() && IsReadOnly());
}

// Show a browser picker for this input element.
// https://html.spec.whatwg.org/multipage/input.html#dom-input-showpicker
void HTMLInputElement::showPicker(ExceptionState& exception_state) {
  LocalFrame* frame = GetDocument().GetFrame();
  // In cross-origin iframes it should throw a "SecurityError" DOMException
  // except on file and color. In same-origin iframes it should work fine.
  // https://github.com/whatwg/html/issues/6909#issuecomment-917138991
  if (FormControlType() != FormControlType::kInputFile &&
      FormControlType() != FormControlType::kInputColor && frame) {
    if (!frame->IsSameOrigin()) {
      exception_state.ThrowSecurityError(
          "showPicker() called from cross-origin iframe.");
      return;
    }
  }

  if (!isMutable()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "HTMLInputElement::showPicker() cannot be used on immutable controls.");
    return;
  }

  if (!LocalFrame::HasTransientUserActivation(frame)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "HTMLInputElement::showPicker() requires a user gesture.");
    return;
  }
  LocalFrame::ConsumeTransientUserActivation(frame);

  input_type_view_->OpenPopupView();
}

bool HTMLInputElement::IsValidBuiltinCommand(HTMLElement& invoker,
                                             CommandEventType command) {
  bool parent_is_valid = HTMLElement::IsValidBuiltinCommand(invoker, command);
  if (!RuntimeEnabledFeatures::HTMLInvokeActionsV2Enabled() ||
      parent_is_valid) {
    return parent_is_valid;
  }

  if (input_type_->IsNumberInputType()) {
    if (command == CommandEventType::kStepUp ||
        command == CommandEventType::kStepDown) {
      return true;
    }
  }

  return command == CommandEventType::kShowPicker;
}

bool HTMLInputElement::HandleCommandInternal(HTMLElement& invoker,
                                             CommandEventType command) {
  CHECK(IsValidBuiltinCommand(invoker, command));

  if (HTMLElement::HandleCommandInternal(invoker, command)) {
    return true;
  }

  // Step 1. If this is not mutable, then return.
  if (!isMutable()) {
    return false;
  }

  if (command == CommandEventType::kShowPicker) {
    // Step 2. If this's relevant settings object's origin is not same origin
    // with this's relevant settings object's top-level origin, [...], then
    // return.
    Document& document = GetDocument();
    LocalFrame* frame = document.GetFrame();
    if (frame && !frame->IsSameOrigin()) {
      String message = "Input cannot be invoked from cross-origin iframe.";
      document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kJavaScript,
          mojom::ConsoleMessageLevel::kWarning, message));
      return false;
    }

    // If this's relevant global object does not have transient
    // activation, then return.
    if (!LocalFrame::HasTransientUserActivation(frame)) {
      String message = "Input cannot be invoked without a user gesture.";
      document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kJavaScript,
          mojom::ConsoleMessageLevel::kWarning, message));
      return false;
    }

    // Step 3. ... show the picker, if applicable, for this.
    input_type_view_->OpenPopupView();
    return true;
  }

  if (input_type_->IsNumberInputType()) {
    if (command == CommandEventType::kStepUp) {
      input_type_->StepUp(1.0, ASSERT_NO_EXCEPTION);
      return true;
    }

    if (command == CommandEventType::kStepDown) {
      input_type_->StepUp(-1.0, ASSERT_NO_EXCEPTION);
      return true;
    }
  }

  return false;
}

void HTMLInputElement::SetFocused(bool is_focused,
                                  mojom::blink::FocusType focus_type) {
  TextControlElement::SetFocused(is_focused, focus_type);
  // Multifield inputs will call SetFocused when switching between the
  // individual parts, but we don't want to start matching
  // :user-valid/:user-invalid at that time. However, for other inputs, we want
  // to start matching :user-valid/:user-invalid as soon as possible, especially
  // to support the case where the user types something, then deletes it, then
  // blurs the input.
  if (!is_focused && !input_type_view_->IsMultipleFieldsTemporal() &&
      UserHasEditedTheField()) {
    SetUserHasEditedTheFieldAndBlurred();
  }
}

}  // namespace blink
```
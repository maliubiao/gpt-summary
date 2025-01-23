Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. This code is part of the `HTMLInputElement` class, which represents the `<input>` HTML element in the browser's rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core class:** The code is within the `HTMLInputElement` class. This immediately tells us the code is responsible for the behavior and state of `<input>` elements.

2. **Scan for key methods and keywords:** Look for methods that handle attribute changes (`ParseAttribute`), lifecycle events (`ParserDidSetAttributes`, `FinishParsingChildren`), value manipulation (`SetValue`, `SetValueForUser`, `valueAsDate`, `valueAsNumber`), state management (`SetChecked`, `setIndeterminate`), and event handling (`DefaultEventHandler`, `PreDispatchEventHandler`, `PostDispatchEventHandler`). Also, look for keywords like "shadow", "form", "value", "checked", "attribute", "event", which are strong indicators of the code's purpose.

3. **Group related functionalities:**  As you identify methods and keywords, start grouping them by related functionality. For example:
    * **Attribute Handling:**  `ParseAttribute`, `ParserDidSetAttributes`, methods handling specific attributes like `value`, `checked`, `maxlength`, `minlength`, etc.
    * **Value Management:** `SetValue`, `SetValueForUser`, `SetNonAttributeValue`, `Value`, `DefaultValue`, `valueAsDate`, `valueAsNumber`, sanitization, localization.
    * **Checked State:** `SetChecked`, `Checked`, `setIndeterminate`.
    * **Form Interaction:** `AppendToFormData`, `ResetImpl`, `WillChangeForm`, `DidChangeForm`, `CanBeSuccessfulSubmitButton`.
    * **Event Handling:** `DefaultEventHandler`, `PreDispatchEventHandler`, `PostDispatchEventHandler`, specific handlers for click, keydown, keypress, etc.
    * **Shadow DOM:** `EnsureShadowSubtree`, mentions of `input_type_view_` creating shadow trees.
    * **Layout and Rendering:** Mentions of `GetLayoutObject`, `SetNeedsStyleRecalc`, `AttachLayoutTree`, `DetachLayoutTree`.
    * **Accessibility:** Mentions of `AXObjectCache`.
    * **Autofill:** Mentions of `SetAutofillState`.
    * **File Handling:** Methods related to `files()` and drag-and-drop (`ReceiveDroppedFiles`).

4. **Analyze specific code blocks:**  For each identified functionality, analyze the code within the relevant methods to understand the specific actions being performed. For example, in `ParseAttribute`, observe how different attributes trigger different behaviors like updating the value, setting checked state, or triggering style recalculations.

5. **Infer relationships with HTML, CSS, and JavaScript:**  Based on the functionalities identified, deduce how they relate to web technologies.
    * **HTML:** The code directly manipulates the state and attributes of `<input>` elements, reflecting changes in the HTML structure.
    * **CSS:**  Methods like `SetNeedsStyleRecalc` and `PseudoStateChanged` indicate how changes in the input element can trigger CSS updates and pseudo-class changes.
    * **JavaScript:** Methods with "binding" in their names (`setValueForBinding`, `setCheckedForBinding`) suggest how JavaScript can interact with and control the `<input>` element. Event handlers demonstrate how the element responds to user interactions that JavaScript can listen for.

6. **Look for logic and conditional behavior:** Identify `if` statements and conditional logic that dictate different outcomes based on input values or element state. This helps in understanding the assumptions and potential inputs and outputs of the code.

7. **Identify potential user/programming errors:** Look for validation checks, error handling (like the `ExceptionState`), and constraints on input values that might lead to common mistakes.

8. **Synthesize the summary:** Combine the identified functionalities, relationships, logic, and potential errors into a concise summary. Organize the summary by grouping related points.

9. **Refine and clarify:**  Review the summary for clarity, accuracy, and completeness. Ensure that the language is understandable and avoids overly technical jargon where possible. Make sure to address all aspects of the user's request (functionality, relationships with web technologies, logic, errors).

Applying this process to the provided code snippet leads to the detailed summary provided in the initial good answer. The breakdown into categories like "Attribute Handling", "Value Management", "Checked State", etc., makes the information more digestible. The inclusion of examples for JavaScript, HTML, and CSS interaction directly addresses the user's specific request. The analysis of potential errors and the mention of assumptions also provides valuable context.
这段代码是 `HTMLInputElement.cc` 文件的第二部分，主要负责处理 `HTMLInputElement` 元素的一些核心功能，包括属性解析、值管理、状态更新、事件处理以及与渲染和表单系统的交互。

以下是这段代码的主要功能归纳：

**1. 属性解析与处理 (Attribute Parsing and Handling):**

* **`ParseAttribute(const Attribute& attribute)`:**  这个函数是核心，负责解析 HTML `input` 元素的各种属性。
    * **`type` 属性:**  根据 `type` 属性的值（例如 "text", "checkbox", "radio"），创建或更新对应的 `InputType` 对象 (`input_type_`) 和 `InputTypeView` 对象 (`input_type_view_`)，这两个对象负责处理特定输入类型的行为和渲染。
    * **`value` 属性:**  处理 `value` 属性的变更，包括更新内部值 (`non_attribute_value_`)，触发占位符更新，以及通知视图更新。如果表单正在查看默认值，则会设置 `changed` 状态。
    * **`checked` 属性:**  处理 `checked` 属性的变更，设置 `is_checked_` 标志，并可能更新同一单选按钮组的其他按钮状态。
    * **`maxlength`, `minlength` 属性:**  设置最大和最小长度限制，并触发验证检查。
    * **`size` 属性:**  设置输入框的尺寸，并可能触发布局更新。
    * **`alt`, `src` 属性:**  传递给 `input_type_view_` 处理，可能用于图像类型的输入。
    * **`onsearch` 属性:**  设置搜索事件的监听器。
    * **`min`, `max`, `multiple`, `step`, `pattern` 属性:**  传递给 `input_type_view_` 或 `input_type_` 处理，用于数值或日期时间类型的输入，并触发验证检查。
    * **`readonly` 属性:**  设置只读状态，并传递给 `input_type_view_`。
    * **`list` 属性:**  处理关联的 `<datalist>` 元素。
    * **`webkitdirectory` 属性:**  处理目录选择（webkit 前缀）。
    * 其他属性：调用父类 `TextControlElement::ParseAttribute` 进行处理。
* **`ParserDidSetAttributes()`:** 在解析器设置完所有属性后调用，用于完成类型初始化。
* **`FinishParsingChildren()`:** 在子节点解析完成后调用，处理延迟的 `checked` 属性设置。

**2. 布局和渲染 (Layout and Rendering):**

* **`LayoutObjectIsNeeded(const DisplayStyle& style) const`:**  确定是否需要布局对象。
* **`CreateLayoutObject(const ComputedStyle& style)`:**  创建布局对象，委托给 `input_type_view_`。
* **`AttachLayoutTree(AttachContext& context)`:**  附加到布局树，并通知 `input_type_`。
* **`DetachLayoutTree(bool performing_reattach)`:**  从布局树分离，并通知 `input_type_view_` 关闭弹窗视图。

**3. 值管理 (Value Management):**

* **`AltText() const`:** 获取用于替代文本的值，优先级为 `alt` > `title` > `value` > 本地化字符串。
* **`AppendToFormData(FormData& form_data)`:**  将输入元素的值添加到表单数据中，用于表单提交。
* **`ResultForDialogSubmit()`:**  为表单对话框提交获取结果。
* **`ResetImpl()`:**  重置输入元素的值和 `checked` 状态为默认值。
* **`Value() const`:**  获取输入元素的当前值，根据 `input_type_->GetValueMode()` 返回不同的值来源。
* **`ValueOrDefaultLabel() const`:** 获取当前值，如果为空则返回默认标签。
* **`SetValueForUser(const String& value)`:**  为用户交互设置值，会触发 `change` 事件。
* **`SetSuggestedValue(const String& value)`:** 设置建议值，常用于自动填充。
* **`SetInnerEditorValue(const String& value)`:** 设置内部编辑器的值。
* **`setValueForBinding(const String& value, ExceptionState& exception_state)`:**  通过 JavaScript 设置值，会进行错误检查。
* **`SetValue(const String& value, ...)`:**  设置输入元素的值，可以控制是否触发事件以及选择行为。
* **`SetNonAttributeValue(const String& sanitized_value)`:** 设置非属性值，常用于 `ValueMode::kValue`。
* **`SetNonAttributeValueByUserEdit(const String& sanitized_value)`:**  设置用户编辑后的非属性值。
* **`SetNonDirtyValue(const String& new_value)`:**  设置非脏值。
* **`HasDirtyValue() const`:**  判断值是否被修改过。
* **`UpdateView()`:**  通知 `input_type_view_` 更新视图。
* **`valueAsDate(ScriptState* script_state) const` / `setValueAsDate(...)`:**  以 `Date` 对象的形式获取或设置值（适用于日期/时间类型）。
* **`valueAsNumber() const` / `setValueAsNumber(...)`:**  以数字的形式获取或设置值（适用于数字类型）。
* **`RatioValue() const`:** 获取范围输入 (range) 的比例值。
* **`SetValueFromRenderer(const String& value)`:**  从渲染器接收值更新。

**4. 状态管理 (State Management):**

* **`IsTextField() const`, `IsTelephone() const`, `IsAutoDirectionalityFormAssociated() const`:** 判断输入类型。
* **`HasBeenPasswordField() const`:**  记录是否曾是密码字段。
* **`DispatchChangeEventIfNeeded()`, `DispatchInputAndChangeEventIfNeeded()`:**  根据条件触发 `change` 或 `input` 事件。
* **`IsCheckable() const`:**  判断是否可勾选（checkbox 或 radio）。
* **`Checked() const` / `setCheckedForBinding(bool now_checked)` / `SetChecked(...)`:**  获取或设置 `checked` 状态，并处理相关事件和状态更新。
* **`setIndeterminate(bool new_value)`:**  设置复选框的不确定状态。
* **`size() const` / `setSize(...)`:**  获取或设置 `size` 属性。
* **`CloneNonAttributePropertiesFrom(const Element& source, NodeCloningData& data)`:**  从源元素克隆非属性属性。

**5. 事件处理 (Event Handling):**

* **`PreDispatchEventHandler(Event& event)`:**  在事件分发前进行处理，例如阻止文本输入事件的冒泡。
* **`PostDispatchEventHandler(Event& event, EventDispatchHandlingState* state)`:**  在事件分发后进行处理。
* **`DefaultEventHandler(Event& evt)`:**  默认的事件处理器，处理各种事件，包括 `click`, `keydown`, `keypress`, `keyup`, `DOMActivate` 等。它根据事件类型调用 `input_type_view_` 的相应处理函数，并处理表单的隐式提交。
* **`OnSearch()`:**  触发搜索事件。

**6. 表单交互 (Form Interaction):**

* **`CanBeSuccessfulSubmitButton() const`:**  判断是否是有效的提交按钮。
* **`IsActivatedSubmit() const` / `SetActivatedSubmit(bool flag)`:**  记录提交按钮是否被激活。
* **`WillChangeForm()`, `DidChangeForm()`:**  在元素的表单关联发生变化时进行处理，例如更新单选按钮组。

**7. Shadow DOM (Shadow DOM):**

* **`EnsureShadowSubtree()`:**  确保创建了 Shadow DOM 子树。
* 代码中多次提到 `input_type_view_->CreateShadowSubtreeIfNeeded()`，表明输入元素的某些部分（例如清除按钮、密码显示按钮）是通过 Shadow DOM 实现的。

**8. 其他功能:**

* **`HasActivationBehavior() const`:**  表明该元素具有激活行为。
* **`WillRespondToMouseClickEvents()`:**  判断是否响应鼠标点击事件。
* **`IsURLAttribute(const Attribute& attribute) const`, `HasLegalLinkAttribute(const QualifiedName& name) const`:**  判断属性是否是 URL 属性或合法的链接属性。
* **静态辅助函数 `IsValidMIMEType`, `IsValidFileExtension`, `ParseAcceptAttribute`:**  用于解析 `accept` 属性。
* **`AcceptMIMETypes() const`, `AcceptFileExtensions() const`:**  获取接受的 MIME 类型和文件扩展名。
* **`Alt() const`, `Multiple() const`, `Src() const`:**  获取其他属性值。
* **文件处理相关：`files() const`, `setFiles(FileList* files)`, `ReceiveDroppedFiles(const DragData* drag_data)`, `DroppedFileSystemId()`, `CanReceiveDroppedFiles() const`, `SetCanReceiveDroppedFiles(...)`, `UploadButton() const`:**  处理文件上传类型的输入。
* **`SanitizeValue(const String& proposed_value) const`, `LocalizeValue(const String& proposed_value) const`:**  对输入值进行清理和本地化。
* **验证相关：`IsInRange() const`, `IsOutOfRange() const`, `IsRequiredFormControl() const`, `MatchesReadOnlyPseudoClass() const`, `MatchesReadWritePseudoClass() const`:**  判断输入值是否在有效范围内，是否是必填项，以及是否匹配只读/读写伪类。
* **`AutoAppearance() const`:**  获取自动外观。
* **`UpdateClearButtonVisibility()`:**  更新清除按钮的可见性。
* **`IsInnerEditorValueEmpty() const`:**  判断内部编辑器是否为空。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * **`setValueForBinding()`:**  JavaScript 可以通过 `element.value = 'new value'` 来调用此方法设置输入框的值。
    * **`setCheckedForBinding()`:**  JavaScript 可以通过 `element.checked = true` 来设置复选框或单选按钮的选中状态.
    * **`valueAsDate()`, `valueAsNumber()`:**  JavaScript 可以调用这些方法来获取日期或数值类型输入框的值，例如 `const date = element.valueAsDate;`.
    * **事件处理:**  JavaScript 可以监听 `input`, `change`, `click` 等事件，这些事件的触发与代码中的 `DispatchChangeEventIfNeeded()`, `DefaultEventHandler()` 等函数相关。

* **HTML:**
    * **属性解析:**  `ParseAttribute()` 函数直接对应 HTML 中 `<input>` 标签的各种属性，例如 `<input type="text" value="initial value" maxlength="10">` 会调用 `ParseAttribute()` 处理 `type`, `value`, `maxlength` 等属性。
    * **表单提交:**  `AppendToFormData()` 函数参与了表单数据的构建，当 HTML 表单提交时，输入框的值会被添加到表单数据中。

* **CSS:**
    * **伪类:**  `PseudoStateChanged(CSSSelector::kPseudoChecked)` 会更新元素的 `:checked` 伪类状态，CSS 可以根据此伪类设置样式，例如 `input:checked { ... }`。
    * **布局更新:** 当 `size` 属性改变时，`SetNeedsStyleRecalc()` 和相关的布局函数会被调用，从而影响输入框在页面上的渲染尺寸。
    * **Shadow DOM:**  CSS 可以通过类似 `input::shadow .clear-button { ... }` 的选择器来样式化 Shadow DOM 中的元素（例如清除按钮）。

**逻辑推理的假设输入与输出示例:**

**假设输入:**  一个 `HTMLInputElement` 元素，其 `type` 属性为 "text"，`value` 属性为 "old value"，然后 JavaScript 代码执行 `element.value = 'new value'`.

**代码逻辑推理:**

1. JavaScript 的赋值操作会调用 `setValueForBinding('new value', ...)`.
2. `setValueForBinding()` 内部会调用 `SetValue('new value', ...)`.
3. `SetValue()` 会进行一些检查，然后调用 `input_type_->SetValue('new value', ...)`.
4. `input_type_` 对象（可能是 `TextControlInnerType`）会更新其内部的值表示。
5. `SetValue()` 还会调用 `input_type_view_->DidSetValue('new value', true)`，通知视图更新。
6. 如果需要，会触发 `input` 和 `change` 事件。

**假设输出:**  输入框的内部值被更新为 "new value"，并且可能触发了 `input` 和 `change` 事件，如果绑定了相应的事件监听器，这些监听器会被触发执行。页面上输入框的显示值也会更新。

**用户或编程常见的使用错误举例:**

* **直接修改 `non_attribute_value_` 而不调用 `SetValue()`:**  这样做可能导致状态不一致，例如没有触发 `change` 事件或验证检查。
* **在不应该设置文件列表的输入框上调用 `setFiles()`:**  例如，在一个 `type="text"` 的输入框上调用 `element.files = ...` 会导致错误或无效操作。
* **假设所有输入类型都有相同的属性和方法:**  例如，尝试在 `type="checkbox"` 的输入框上获取 `valueAsNumber` 可能会得到 `NaN` 或错误的结果。
* **忘记处理异步操作:**  例如，在文件上传类型的输入框中，用户选择文件后，文件读取可能是异步的，需要正确处理回调和错误。
* **不理解 `has_dirty_value_` 的含义:**  错误地假设 `has_dirty_value_` 总是表示用户已经修改了值，而忽略了程序设置值的情况。

**总结来说，这段代码是 `HTMLInputElement` 元素的核心逻辑实现，负责处理属性、管理状态、响应事件以及与浏览器的渲染引擎和表单系统进行交互。它定义了 `input` 元素在 HTML 文档中的行为和功能，并且与 JavaScript 和 CSS 紧密联系。**

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_input_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ld_value != value) {
      UpdateType(value);
    }
  } else if (name == html_names::kValueAttr) {
    // We only need to setChanged if the form is looking at the default value
    // right now.
    if (!HasDirtyValue()) {
      if (input_type_->GetValueMode() == ValueMode::kValue)
        non_attribute_value_ = SanitizeValue(value);
      UpdatePlaceholderVisibility();
      SetNeedsStyleRecalc(
          kSubtreeStyleChange,
          StyleChangeReasonForTracing::FromAttribute(html_names::kValueAttr));
      needs_to_update_view_value_ = true;
    }
    SetNeedsValidityCheck();
    input_type_->WarnIfValueIsInvalidAndElementIsVisible(value);
    input_type_->InRangeChanged();
    if (input_type_view_->HasCreatedShadowSubtree() ||
        !RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled() ||
        !input_type_view_->NeedsShadowSubtree()) {
      input_type_view_->ValueAttributeChanged();
    } else {
      input_type_view_->set_needs_update_view_in_create_shadow_subtree(true);
    }
  } else if (name == html_names::kCheckedAttr) {
    // Another radio button in the same group might be checked by state
    // restore. We shouldn't call SetChecked() even if this has the checked
    // attribute. So, delay the SetChecked() call until
    // finishParsingChildren() is called if parsing is in progress.
    if ((!parsing_in_progress_ ||
         !GetDocument().GetFormController().HasControlStates()) &&
        !dirty_checkedness_) {
      SetChecked(!value.IsNull());
      dirty_checkedness_ = false;
    }
    PseudoStateChanged(CSSSelector::kPseudoDefault);
  } else if (name == html_names::kMaxlengthAttr) {
    SetNeedsValidityCheck();
  } else if (name == html_names::kMinlengthAttr) {
    SetNeedsValidityCheck();
  } else if (name == html_names::kSizeAttr) {
    unsigned size = 0;
    if (value.empty() || !ParseHTMLNonNegativeInteger(value, size) ||
        size == 0 || size > 0x7fffffffu)
      size = kDefaultSize;
    if (size_ != size) {
      size_ = size;
      if (GetLayoutObject()) {
        GetLayoutObject()
            ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
                layout_invalidation_reason::kAttributeChanged);
      }
    }
  } else if (name == html_names::kAltAttr) {
    input_type_view_->AltAttributeChanged();
  } else if (name == html_names::kSrcAttr) {
    input_type_view_->SrcAttributeChanged();
  } else if (name == html_names::kUsemapAttr ||
             name == html_names::kAccesskeyAttr) {
    // FIXME: ignore for the moment
  } else if (name == html_names::kOnsearchAttr) {
    // Search field and slider attributes all just cause updateFromElement to be
    // called through style recalcing.
    SetAttributeEventListener(event_type_names::kSearch,
                              JSEventHandlerForContentAttribute::Create(
                                  GetExecutionContext(), name, value));
  } else if (name == html_names::kIncrementalAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kIncrementalAttribute);
  } else if (name == html_names::kMinAttr) {
    input_type_view_->MinOrMaxAttributeChanged();
    input_type_->SanitizeValueInResponseToMinOrMaxAttributeChange();
    input_type_->InRangeChanged();
    SetNeedsValidityCheck();
    UseCounter::Count(GetDocument(), WebFeature::kMinAttribute);
  } else if (name == html_names::kMaxAttr) {
    input_type_view_->MinOrMaxAttributeChanged();
    input_type_->SanitizeValueInResponseToMinOrMaxAttributeChange();
    input_type_->InRangeChanged();
    SetNeedsValidityCheck();
    UseCounter::Count(GetDocument(), WebFeature::kMaxAttribute);
  } else if (name == html_names::kMultipleAttr) {
    input_type_view_->MultipleAttributeChanged();
    SetNeedsValidityCheck();
  } else if (name == html_names::kStepAttr) {
    input_type_view_->StepAttributeChanged();
    SetNeedsValidityCheck();
    UseCounter::Count(GetDocument(), WebFeature::kStepAttribute);
  } else if (name == html_names::kPatternAttr) {
    SetNeedsValidityCheck();
    UseCounter::Count(GetDocument(), WebFeature::kPatternAttribute);
  } else if (name == html_names::kReadonlyAttr) {
    TextControlElement::ParseAttribute(params);
    input_type_view_->ReadonlyAttributeChanged();
  } else if (name == html_names::kListAttr) {
    has_non_empty_list_ = !value.empty();
    ResetListAttributeTargetObserver();
    ListAttributeTargetChanged();
    PseudoStateChanged(CSSSelector::kPseudoHasDatalist);
    UseCounter::Count(GetDocument(), WebFeature::kListAttribute);
  } else if (name == html_names::kWebkitdirectoryAttr) {
    TextControlElement::ParseAttribute(params);
    UseCounter::Count(GetDocument(), WebFeature::kPrefixedDirectoryAttribute);
  } else {
    if (name == html_names::kFormactionAttr)
      LogUpdateAttributeIfIsolatedWorldAndInDocument("input", params);
    TextControlElement::ParseAttribute(params);
  }
}

void HTMLInputElement::ParserDidSetAttributes() {
  DCHECK(parsing_in_progress_);
  InitializeTypeInParsing();
  TextControlElement::ParserDidSetAttributes();
}

void HTMLInputElement::FinishParsingChildren() {
  parsing_in_progress_ = false;
  DCHECK(input_type_);
  DCHECK(input_type_view_);
  TextControlElement::FinishParsingChildren();
  if (!state_restored_) {
    bool checked = FastHasAttribute(html_names::kCheckedAttr);
    if (checked)
      SetChecked(checked);
    dirty_checkedness_ = false;
  }
}

bool HTMLInputElement::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  return input_type_->LayoutObjectIsNeeded() &&
         TextControlElement::LayoutObjectIsNeeded(style);
}

LayoutObject* HTMLInputElement::CreateLayoutObject(const ComputedStyle& style) {
  return input_type_view_->CreateLayoutObject(style);
}

void HTMLInputElement::AttachLayoutTree(AttachContext& context) {
  TextControlElement::AttachLayoutTree(context);
  if (GetLayoutObject())
    input_type_->OnAttachWithLayoutObject();
  input_type_->CountUsage();
}

void HTMLInputElement::DetachLayoutTree(bool performing_reattach) {
  TextControlElement::DetachLayoutTree(performing_reattach);
  needs_to_update_view_value_ = true;
  input_type_view_->ClosePopupView();
}

String HTMLInputElement::AltText() const {
  // http://www.w3.org/TR/1998/REC-html40-19980424/appendix/notes.html#altgen
  // also heavily discussed by Hixie on bugzilla
  // note this is intentionally different to HTMLImageElement::altText()
  String alt = FastGetAttribute(html_names::kAltAttr);
  // fall back to title attribute
  if (alt.IsNull())
    alt = FastGetAttribute(html_names::kTitleAttr);
  if (alt.IsNull())
    alt = FastGetAttribute(html_names::kValueAttr);
  if (alt.IsNull())
    alt = GetLocale().QueryString(IDS_FORM_INPUT_ALT);
  return alt;
}

bool HTMLInputElement::CanBeSuccessfulSubmitButton() const {
  return input_type_->CanBeSuccessfulSubmitButton();
}

bool HTMLInputElement::IsActivatedSubmit() const {
  return is_activated_submit_;
}

void HTMLInputElement::SetActivatedSubmit(bool flag) {
  is_activated_submit_ = flag;
}

void HTMLInputElement::AppendToFormData(FormData& form_data) {
  if (input_type_->IsFormDataAppendable())
    input_type_->AppendToFormData(form_data);
}

String HTMLInputElement::ResultForDialogSubmit() {
  return input_type_->ResultForDialogSubmit();
}

void HTMLInputElement::ResetImpl() {
  if (input_type_->GetValueMode() == ValueMode::kValue) {
    SetNonDirtyValue(DefaultValue());
    SetNeedsValidityCheck();
  } else if (input_type_->GetValueMode() == ValueMode::kFilename) {
    SetNonDirtyValue(String());
    SetNeedsValidityCheck();
  }
  SetChecked(FastHasAttribute(html_names::kCheckedAttr));
  dirty_checkedness_ = false;
  HTMLFormControlElementWithState::ResetImpl();
}

bool HTMLInputElement::IsTextField() const {
  return input_type_->IsTextFieldInputType();
}

bool HTMLInputElement::IsTelephone() const {
  return input_type_->IsTelephoneInputType();
}

bool HTMLInputElement::IsAutoDirectionalityFormAssociated() const {
  return input_type_->IsAutoDirectionalityFormAssociated();
}

bool HTMLInputElement::HasBeenPasswordField() const {
  return has_been_password_field_;
}

void HTMLInputElement::DispatchChangeEventIfNeeded() {
  if (isConnected() && input_type_->ShouldSendChangeEventAfterCheckedChanged())
    DispatchChangeEvent();
}

void HTMLInputElement::DispatchInputAndChangeEventIfNeeded() {
  if (isConnected() &&
      input_type_->ShouldSendChangeEventAfterCheckedChanged()) {
    DispatchInputEvent();
    DispatchChangeEvent();
  }
}

bool HTMLInputElement::IsCheckable() const {
  return input_type_->IsCheckable();
}

bool HTMLInputElement::Checked() const {
  input_type_->ReadingChecked();
  return is_checked_;
}

void HTMLInputElement::setCheckedForBinding(bool now_checked) {
  SetChecked(now_checked, TextFieldEventBehavior::kDispatchNoEvent,
             IsAutofilled() && this->Checked() == now_checked
                 ? WebAutofillState::kAutofilled
                 : WebAutofillState::kNotFilled);
}

void HTMLInputElement::SetChecked(bool now_checked,
                                  TextFieldEventBehavior event_behavior,
                                  WebAutofillState autofill_state) {
  SetAutofillState(autofill_state);

  dirty_checkedness_ = true;
  if (Checked() == now_checked)
    return;

  input_type_->WillUpdateCheckedness(now_checked);
  is_checked_ = now_checked;

  if (RadioButtonGroupScope* scope = GetRadioButtonGroupScope())
    scope->UpdateCheckedState(this);
  InvalidateIfHasEffectiveAppearance();
  SetNeedsValidityCheck();

  // Ideally we'd do this from the layout tree (matching
  // LayoutTextView), but it's not possible to do it at the moment
  // because of the way the code is structured.
  if (GetLayoutObject()) {
    if (AXObjectCache* cache =
            GetLayoutObject()->GetDocument().ExistingAXObjectCache())
      cache->CheckedStateChanged(this);
  }

  if (!RuntimeEnabledFeatures::AllowJavaScriptToResetAutofillStateEnabled()) {
    // Only send a change event for items in the document (avoid firing during
    // parsing) and don't send a change event for a radio button that's getting
    // unchecked to match other browsers. DOM is not a useful standard for this
    // because it says only to fire change events at "lose focus" time, which is
    // definitely wrong in practice for these types of elements.
    if (event_behavior ==
            TextFieldEventBehavior::kDispatchInputAndChangeEvent &&
        isConnected() &&
        input_type_->ShouldSendChangeEventAfterCheckedChanged()) {
      DispatchInputEvent();
    }
  }

  // We set the Autofilled state again because setting the autofill value
  // triggers JavaScript events and the site may override the autofilled value,
  // which resets the autofill state. Even if the website modifies the from
  // control element's content during the autofill operation, we want the state
  // to show as as autofilled.
  SetAutofillState(autofill_state);

  PseudoStateChanged(CSSSelector::kPseudoChecked);
}

void HTMLInputElement::setIndeterminate(bool new_value) {
  if (indeterminate() == new_value)
    return;

  is_indeterminate_ = new_value;

  PseudoStateChanged(CSSSelector::kPseudoIndeterminate);

  InvalidateIfHasEffectiveAppearance();

  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->CheckedStateChanged(this);
}

unsigned HTMLInputElement::size() const {
  return size_;
}

bool HTMLInputElement::SizeShouldIncludeDecoration(int& preferred_size) const {
  return input_type_view_->SizeShouldIncludeDecoration(kDefaultSize,
                                                       preferred_size);
}

void HTMLInputElement::CloneNonAttributePropertiesFrom(const Element& source,
                                                       NodeCloningData& data) {
  const auto& source_element = To<HTMLInputElement>(source);

  non_attribute_value_ = source_element.non_attribute_value_;
  has_dirty_value_ = source_element.has_dirty_value_;
  SetChecked(source_element.is_checked_);
  dirty_checkedness_ = source_element.dirty_checkedness_;
  is_indeterminate_ = source_element.is_indeterminate_;
  input_type_->CopyNonAttributeProperties(source_element);

  TextControlElement::CloneNonAttributePropertiesFrom(source, data);

  needs_to_update_view_value_ = true;
  input_type_view_->UpdateView();
}

String HTMLInputElement::Value() const {
  switch (input_type_->GetValueMode()) {
    case ValueMode::kFilename:
      return input_type_->ValueInFilenameValueMode();
    case ValueMode::kDefault:
      return FastGetAttribute(html_names::kValueAttr);
    case ValueMode::kDefaultOn: {
      AtomicString value_string = FastGetAttribute(html_names::kValueAttr);
      return value_string.IsNull() ? AtomicString("on") : value_string;
    }
    case ValueMode::kValue:
      return non_attribute_value_;
  }
  NOTREACHED();
}

String HTMLInputElement::ValueOrDefaultLabel() const {
  String value = this->Value();
  if (!value.IsNull())
    return value;
  return input_type_->DefaultLabel();
}

void HTMLInputElement::SetValueForUser(const String& value) {
  // Call setValue and make it send a change event.
  SetValue(value, TextFieldEventBehavior::kDispatchChangeEvent);
}

void HTMLInputElement::SetSuggestedValue(const String& value) {
  if (!input_type_->CanSetSuggestedValue()) {
    // Clear the suggested value because it may have been set when
    // `input_type_->CanSetSuggestedValue()` was true.
    SetAutofillState(WebAutofillState::kNotFilled);
    TextControlElement::SetSuggestedValue(String());
    return;
  }
  needs_to_update_view_value_ = true;
  String sanitized_value = SanitizeValue(value);
  SetAutofillState(sanitized_value.empty() ? WebAutofillState::kNotFilled
                                           : WebAutofillState::kPreviewed);
  TextControlElement::SetSuggestedValue(sanitized_value);

  // Update the suggested value revelation.
  if (auto* placeholder = PlaceholderElement()) {
    const AtomicString reveal("reveal-password");
    if (should_reveal_password_) {
      placeholder->classList().Add(reveal);
    } else {
      placeholder->classList().Remove(reveal);
    }
  }

  SetNeedsStyleRecalc(
      kSubtreeStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kControlValue));
  input_type_view_->UpdateView();
}

void HTMLInputElement::SetInnerEditorValue(const String& value) {
  TextControlElement::SetInnerEditorValue(value);
  if (InnerEditorElement()) {
    needs_to_update_view_value_ = false;
  }
}

void HTMLInputElement::setValueForBinding(const String& value,
                                          ExceptionState& exception_state) {
  // FIXME: Remove type check.
  if (FormControlType() == FormControlType::kInputFile && !value.empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "This input element accepts a filename, "
                                      "which may only be programmatically set "
                                      "to the empty string.");
    return;
  }
  String old_value = this->Value();
  bool was_autofilled = IsAutofilled();
  bool value_changed = old_value != value;
  SetValue(value, TextFieldEventBehavior::kDispatchNoEvent,
           TextControlSetValueSelection::kSetSelectionToEnd,
           was_autofilled && !value_changed && !value.empty()
               ? WebAutofillState::kAutofilled
               : WebAutofillState::kNotFilled);
  if (Page* page = GetDocument().GetPage(); page && value_changed) {
    page->GetChromeClient().JavaScriptChangedValue(*this, old_value,
                                                   was_autofilled);
  }
}

void HTMLInputElement::SetValue(const String& value,
                                TextFieldEventBehavior event_behavior,
                                TextControlSetValueSelection selection,
                                WebAutofillState autofill_state) {
  input_type_->WarnIfValueIsInvalidAndElementIsVisible(value);
  if (!input_type_->CanSetValue(value))
    return;

  // Clear the suggested value. Use the base class version to not trigger a view
  // update.
  TextControlElement::SetSuggestedValue(String());

  SetAutofillState(autofill_state);

  // Scope for EventQueueScope so that change events are dispatched and handled
  // before the second SetAutofillState is executed.
  {
    EventQueueScope scope;
    String sanitized_value = SanitizeValue(value);
    bool value_changed = sanitized_value != this->Value();

    SetLastChangeWasNotUserEdit();
    needs_to_update_view_value_ = true;

    input_type_->SetValue(sanitized_value, value_changed, event_behavior,
                          selection);
    input_type_view_->DidSetValue(sanitized_value, value_changed);

    if (value_changed) {
      NotifyFormStateChanged();
      if (sanitized_value.empty() && HasBeenPasswordField() &&
          GetDocument().GetPage()) {
        GetDocument().GetPage()->GetChromeClient().PasswordFieldReset(*this);
      }
    }
  }

  if (!RuntimeEnabledFeatures::AllowJavaScriptToResetAutofillStateEnabled()) {
    // We set the Autofilled state again because setting the autofill value
    // triggers JavaScript events and the site may override the autofilled
    // value, which resets the autofill state. Even if the website modifies the
    // form control element's content during the autofill operation, we want the
    // state to show as autofilled.
    // If AllowJavaScriptToResetAutofillState is enabled, the WebAutofillClient
    // will monitor JavaScript induced changes and take care of resetting the
    // autofill state when appropriate.
    SetAutofillState(autofill_state);
  }
}

void HTMLInputElement::SetNonAttributeValue(const String& sanitized_value) {
  // This is a common code for ValueMode::kValue.
  DCHECK_EQ(input_type_->GetValueMode(), ValueMode::kValue);
  non_attribute_value_ = sanitized_value;
  has_dirty_value_ = true;
  SetNeedsValidityCheck();
  input_type_->InRangeChanged();
}

void HTMLInputElement::SetNonAttributeValueByUserEdit(
    const String& sanitized_value) {
  SetValueBeforeFirstUserEditIfNotSet();
  SetNonAttributeValue(sanitized_value);
  CheckIfValueWasReverted(sanitized_value);
}

void HTMLInputElement::SetNonDirtyValue(const String& new_value) {
  SetValue(new_value);
  has_dirty_value_ = false;
}

bool HTMLInputElement::HasDirtyValue() const {
  return has_dirty_value_;
}

void HTMLInputElement::UpdateView() {
  input_type_view_->UpdateView();
}

ScriptValue HTMLInputElement::valueAsDate(ScriptState* script_state) const {
  UseCounter::Count(GetDocument(), WebFeature::kInputElementValueAsDateGetter);
  // TODO(crbug.com/988343): InputType::ValueAsDate() should return
  // std::optional<base::Time>.
  double date = input_type_->ValueAsDate();
  v8::Isolate* isolate = script_state->GetIsolate();
  if (!std::isfinite(date))
    return ScriptValue::CreateNull(isolate);
  return ScriptValue(
      isolate,
      ToV8Traits<IDLNullable<IDLDate>>::ToV8(
          script_state, base::Time::FromMillisecondsSinceUnixEpoch(date)));
}

void HTMLInputElement::setValueAsDate(ScriptState* script_state,
                                      const ScriptValue& value,
                                      ExceptionState& exception_state) {
  UseCounter::Count(GetDocument(), WebFeature::kInputElementValueAsDateSetter);
  std::optional<base::Time> date =
      NativeValueTraits<IDLNullable<IDLDate>>::NativeValue(
          script_state->GetIsolate(), value.V8Value(), exception_state);
  if (exception_state.HadException())
    return;
  input_type_->SetValueAsDate(date, exception_state);
}

double HTMLInputElement::valueAsNumber() const {
  return input_type_->ValueAsDouble();
}

void HTMLInputElement::setValueAsNumber(double new_value,
                                        ExceptionState& exception_state,
                                        TextFieldEventBehavior event_behavior) {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/common-input-element-attributes.html#dom-input-valueasnumber
  // On setting, if the new value is infinite, then throw a TypeError exception.
  if (std::isinf(new_value)) {
    exception_state.ThrowTypeError(
        ExceptionMessages::NotAFiniteNumber(new_value));
    return;
  }
  input_type_->SetValueAsDouble(new_value, event_behavior, exception_state);
}

Decimal HTMLInputElement::RatioValue() const {
  DCHECK_EQ(FormControlType(), FormControlType::kInputRange);
  const StepRange step_range(CreateStepRange(kRejectAny));
  const Decimal old_value =
      ParseToDecimalForNumberType(Value(), step_range.DefaultValue());
  return step_range.ProportionFromValue(step_range.ClampValue(old_value));
}

void HTMLInputElement::SetValueFromRenderer(const String& value) {
  // File upload controls will never use this.
  DCHECK_NE(FormControlType(), FormControlType::kInputFile);

  // Clear the suggested value. Use the base class version to not trigger a view
  // update.
  TextControlElement::SetSuggestedValue(String());

  // Renderer and our event handler are responsible for sanitizing values.
  DCHECK(value == input_type_->SanitizeUserInputValue(value) ||
         input_type_->SanitizeUserInputValue(value).empty());

  DCHECK(!value.IsNull());
  SetValueBeforeFirstUserEditIfNotSet();
  non_attribute_value_ = value;
  has_dirty_value_ = true;
  if (InnerEditorElement()) {
    needs_to_update_view_value_ = false;
  }
  CheckIfValueWasReverted(value);

  // Input event is fired by the Node::defaultEventHandler for editable
  // controls.
  if (!IsTextField())
    DispatchInputEvent();
  NotifyFormStateChanged();

  SetNeedsValidityCheck();

  // Clear autofill flag (and yellow background) on user edit.
  SetAutofillState(WebAutofillState::kNotFilled);
}

EventDispatchHandlingState* HTMLInputElement::PreDispatchEventHandler(
    Event& event) {
  if (event.type() == event_type_names::kTextInput &&
      input_type_view_->ShouldSubmitImplicitly(event)) {
    event.stopPropagation();
    return nullptr;
  }
  if (event.type() != event_type_names::kClick)
    return nullptr;

  auto* mouse_event = DynamicTo<MouseEvent>(event);
  if (!mouse_event ||
      mouse_event->button() !=
          static_cast<int16_t>(WebPointerProperties::Button::kLeft))
    return nullptr;
  return input_type_view_->WillDispatchClick();
}

void HTMLInputElement::PostDispatchEventHandler(
    Event& event,
    EventDispatchHandlingState* state) {
  if (!state)
    return;
  input_type_view_->DidDispatchClick(event,
                                     *static_cast<ClickHandlingState*>(state));
}

void HTMLInputElement::DefaultEventHandler(Event& evt) {
  auto* mouse_event = DynamicTo<MouseEvent>(evt);
  if (mouse_event && evt.type() == event_type_names::kClick &&
      mouse_event->button() ==
          static_cast<int16_t>(WebPointerProperties::Button::kLeft)) {
    input_type_view_->HandleClickEvent(To<MouseEvent>(evt));
    if (evt.DefaultHandled())
      return;
  }

  auto* keyboad_event = DynamicTo<KeyboardEvent>(evt);
  if (keyboad_event && evt.type() == event_type_names::kKeydown) {
    input_type_view_->HandleKeydownEvent(*keyboad_event);
    if (evt.DefaultHandled())
      return;
  }

  // Call the base event handler before any of our own event handling for almost
  // all events in text fields.  Makes editing keyboard handling take precedence
  // over the keydown and keypress handling in this function.
  bool call_base_class_early =
      IsTextField() && (evt.type() == event_type_names::kKeydown ||
                        evt.type() == event_type_names::kKeypress);
  if (call_base_class_early) {
    TextControlElement::DefaultEventHandler(evt);
    if (evt.DefaultHandled())
      return;
  }

  // DOMActivate events cause the input to be "activated" - in the case of image
  // and submit inputs, this means actually submitting the form. For reset
  // inputs, the form is reset. These events are sent when the user clicks on
  // the element, or presses enter while it is the active element. JavaScript
  // code wishing to activate the element must dispatch a DOMActivate event - a
  // click event will not do the job.
  if (evt.type() == event_type_names::kDOMActivate) {
    input_type_view_->HandleDOMActivateEvent(evt);
    if (evt.DefaultHandled())
      return;
  }

  // Use key press event here since sending simulated mouse events
  // on key down blocks the proper sending of the key press event.
  if (keyboad_event && evt.type() == event_type_names::kKeypress) {
    input_type_view_->HandleKeypressEvent(*keyboad_event);
    if (evt.DefaultHandled())
      return;
  }

  if (keyboad_event && evt.type() == event_type_names::kKeyup) {
    input_type_view_->HandleKeyupEvent(*keyboad_event);
    if (evt.DefaultHandled())
      return;
  }

  if (input_type_view_->ShouldSubmitImplicitly(evt)) {
    // FIXME: Remove type check.
    if (FormControlType() == FormControlType::kInputSearch) {
      GetDocument()
          .GetTaskRunner(TaskType::kUserInteraction)
          ->PostTask(FROM_HERE, WTF::BindOnce(&HTMLInputElement::OnSearch,
                                              WrapPersistent(this)));
    }
    // Form submission finishes editing, just as loss of focus does.
    // If there was a change, send the event now.
    DispatchFormControlChangeEvent();

    HTMLFormElement* form_for_submission =
        input_type_view_->FormForSubmission();
    // Form may never have been present, or may have been destroyed by code
    // responding to the change event.
    if (form_for_submission) {
      form_for_submission->SubmitImplicitly(evt,
                                            CanTriggerImplicitSubmission());
    }
    evt.SetDefaultHandled();
    return;
  }

  if (evt.IsBeforeTextInsertedEvent()) {
    input_type_view_->HandleBeforeTextInsertedEvent(
        static_cast<BeforeTextInsertedEvent&>(evt));
  }

  if (mouse_event && evt.type() == event_type_names::kMousedown) {
    input_type_view_->HandleMouseDownEvent(*mouse_event);
    if (evt.DefaultHandled())
      return;
  }

  input_type_view_->ForwardEvent(evt);

  if (!call_base_class_early && !evt.DefaultHandled())
    TextControlElement::DefaultEventHandler(evt);
}

ShadowRoot* HTMLInputElement::EnsureShadowSubtree() {
  scheduled_create_shadow_tree_ = false;
  input_type_view_->CreateShadowSubtreeIfNeeded();
  return UserAgentShadowRoot();
}

bool HTMLInputElement::HasActivationBehavior() const {
  return true;
}

bool HTMLInputElement::WillRespondToMouseClickEvents() {
  // FIXME: Consider implementing willRespondToMouseClickEvents() in InputType
  // if more accurate results are necessary.
  if (!IsDisabledFormControl())
    return true;

  return TextControlElement::WillRespondToMouseClickEvents();
}

bool HTMLInputElement::IsURLAttribute(const Attribute& attribute) const {
  return attribute.GetName() == html_names::kSrcAttr ||
         attribute.GetName() == html_names::kFormactionAttr ||
         TextControlElement::IsURLAttribute(attribute);
}

bool HTMLInputElement::HasLegalLinkAttribute(const QualifiedName& name) const {
  return input_type_->HasLegalLinkAttribute(name) ||
         TextControlElement::HasLegalLinkAttribute(name);
}

const AtomicString& HTMLInputElement::DefaultValue() const {
  return FastGetAttribute(html_names::kValueAttr);
}

static inline bool IsRFC2616TokenCharacter(UChar ch) {
  return IsASCII(ch) && ch > ' ' && ch != '"' && ch != '(' && ch != ')' &&
         ch != ',' && ch != '/' && (ch < ':' || ch > '@') &&
         (ch < '[' || ch > ']') && ch != '{' && ch != '}' && ch != 0x7f;
}

static bool IsValidMIMEType(const String& type) {
  size_t slash_position = type.find('/');
  if (slash_position == kNotFound || !slash_position ||
      slash_position == type.length() - 1)
    return false;
  for (wtf_size_t i = 0; i < type.length(); ++i) {
    if (!IsRFC2616TokenCharacter(type[i]) && i != slash_position)
      return false;
  }
  return true;
}

static bool IsValidFileExtension(const String& type) {
  if (type.length() < 2)
    return false;
  return type[0] == '.';
}

static Vector<String> ParseAcceptAttribute(const String& accept_string,
                                           bool (*predicate)(const String&)) {
  Vector<String> types;
  if (accept_string.empty())
    return types;

  Vector<String> split_types;
  accept_string.Split(',', false, split_types);
  for (const String& split_type : split_types) {
    String trimmed_type = StripLeadingAndTrailingHTMLSpaces(split_type);
    if (trimmed_type.empty())
      continue;
    if (!predicate(trimmed_type))
      continue;
    types.push_back(trimmed_type.DeprecatedLower());
  }

  return types;
}

Vector<String> HTMLInputElement::AcceptMIMETypes() const {
  return ParseAcceptAttribute(FastGetAttribute(html_names::kAcceptAttr),
                              IsValidMIMEType);
}

Vector<String> HTMLInputElement::AcceptFileExtensions() const {
  return ParseAcceptAttribute(FastGetAttribute(html_names::kAcceptAttr),
                              IsValidFileExtension);
}

const AtomicString& HTMLInputElement::Alt() const {
  return FastGetAttribute(html_names::kAltAttr);
}

bool HTMLInputElement::Multiple() const {
  return FastHasAttribute(html_names::kMultipleAttr);
}

void HTMLInputElement::setSize(unsigned size, ExceptionState& exception_state) {
  if (size == 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The value provided is 0, which is an invalid size.");
  } else {
    SetUnsignedIntegralAttribute(html_names::kSizeAttr,
                                 size ? size : kDefaultSize, kDefaultSize);
  }
}

KURL HTMLInputElement::Src() const {
  return GetDocument().CompleteURL(FastGetAttribute(html_names::kSrcAttr));
}

FileList* HTMLInputElement::files() const {
  return input_type_->Files();
}

void HTMLInputElement::setFiles(FileList* files) {
  input_type_->SetFiles(files);
}

bool HTMLInputElement::ReceiveDroppedFiles(const DragData* drag_data) {
  return input_type_->ReceiveDroppedFiles(drag_data);
}

String HTMLInputElement::DroppedFileSystemId() {
  return input_type_->DroppedFileSystemId();
}

bool HTMLInputElement::CanReceiveDroppedFiles() const {
  return can_receive_dropped_files_;
}

void HTMLInputElement::SetCanReceiveDroppedFiles(
    bool can_receive_dropped_files) {
  if (!!can_receive_dropped_files_ == can_receive_dropped_files)
    return;
  can_receive_dropped_files_ = can_receive_dropped_files;
  if (HTMLInputElement* button = UploadButton())
    button->SetActive(can_receive_dropped_files);
}

HTMLInputElement* HTMLInputElement::UploadButton() const {
  return input_type_view_->UploadButton();
}

String HTMLInputElement::SanitizeValue(const String& proposed_value) const {
  return input_type_->SanitizeValue(proposed_value);
}

String HTMLInputElement::LocalizeValue(const String& proposed_value) const {
  if (proposed_value.IsNull())
    return proposed_value;
  return input_type_->LocalizeValue(proposed_value);
}

bool HTMLInputElement::IsInRange() const {
  return willValidate() && input_type_->IsInRange(Value());
}

bool HTMLInputElement::IsOutOfRange() const {
  return willValidate() && input_type_->IsOutOfRange(Value());
}

bool HTMLInputElement::IsRequiredFormControl() const {
  return input_type_->SupportsRequired() && IsRequired();
}

bool HTMLInputElement::MatchesReadOnlyPseudoClass() const {
  return !input_type_->SupportsReadOnly() || IsDisabledOrReadOnly();
}

bool HTMLInputElement::MatchesReadWritePseudoClass() const {
  return input_type_->SupportsReadOnly() && !IsDisabledOrReadOnly();
}

ControlPart HTMLInputElement::AutoAppearance() const {
  return input_type_view_->AutoAppearance();
}

void HTMLInputElement::OnSearch() {
  input_type_->DispatchSearchEvent();
}

void HTMLInputElement::UpdateClearButtonVisibility() {
  input_type_view_->UpdateClearButtonVisibility();
}

bool HTMLInputElement::IsInnerEditorValueEmpty() const {
  return input_type_view_->IsInnerEditorValueEmpty();
}

void HTMLInputElement::WillChangeForm() {
  if (input_type_)
    RemoveFromRadioButtonGroup();
  TextControlElement::WillChangeForm();
}

void HTMLInputElement::DidChangeForm() {
  TextControlElement::DidChangeForm();
  if (input_type_)
    AddToRadioButtonGroup();
}

Node::InsertionNotificationRequest HTMLInputElement::InsertedInto(
    ContainerNode& insertion_point) {
  TextControlElement::InsertedInto(insertion_point);
  if (insertion_point.isConnected()) {
    if (!Form()) {
      AddToRadioButtonGroup();
    }
    if (RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled() &&
        !input_type_view_->HasCreatedShadowSubtree() &&
        input_type_view_->NeedsShadowSubtree()) {
      scheduled_create_s
```
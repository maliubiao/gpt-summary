Response:
Let's break down the thought process for analyzing this C++ source file.

1. **Understand the Goal:** The primary goal is to understand the functionality of `html_text_area_element.cc`, its relationships with web technologies (HTML, CSS, JavaScript), identify potential errors, and understand its logic through hypothetical examples.

2. **Initial Scan and Header Analysis:** The first step is to quickly scan the file and examine the included headers. This gives a high-level overview of the functionalities the class might touch upon. We see includes related to:
    * **Core Blink:** `Document`, `events`, `DOM`, `HTML`, `CSS`, `layout`, `editing`. This confirms the file is a core component of the rendering engine.
    * **Forms:** `form_controller`, `form_data`, `text_control_inner_elements`. This strongly suggests the file is responsible for handling the `<textarea>` HTML element.
    * **Platform:**  `platform_locale`, `wtf` (WTF is a WebKit/Blink utility library). These indicate platform-specific functionalities and utility functions.
    * **Bindings:** `v8_focus_options`. This hints at interaction with JavaScript.

3. **Class Definition and Inheritance:** Identify the main class being defined: `HTMLTextAreaElement`. Note its inheritance from `TextControlElement`. This tells us it inherits functionalities related to text input controls.

4. **Key Methods - Functional Decomposition:**  Go through the class methods, especially public ones, and infer their purpose from their names and parameters.
    * **Constructor (`HTMLTextAreaElement`)**:  Initialization of the object, setting default values for `rows`, `cols`, `wrap`. Note the pre-warming of the monospace font.
    * **`FormControlType`, `FormControlTypeAsString`**: Indicate the element's role in a form.
    * **`SaveFormControlState`, `RestoreFormControlState`**:  Methods for persisting and restoring the state of the control. This is crucial for form submissions and page navigation.
    * **`scrollWidth`, `scrollHeight`**: Implement scrolling behavior, with a special case for "suggested values" (likely related to autofill).
    * **`ChildrenChanged`**: Handles changes to the content within the `<textarea>`.
    * **`IsPresentationAttribute`, `CollectStyleForPresentationAttribute`**: Deal with HTML attributes that affect styling (`wrap`).
    * **`ParseAttribute`**:  Processes HTML attributes specific to `<textarea>` (`rows`, `cols`, `wrap`, `maxlength`, `minlength`).
    * **`CreateLayoutObject`**: Creates the layout representation of the element. Crucially, it creates a `LayoutTextControlMultiLine`.
    * **`AppendToFormData`**:  Prepares the `<textarea>`'s value for form submission. Handles the `wrap` attribute.
    * **`ResetImpl`**: Implements the reset behavior of the form control.
    * **Focus Related Methods (`HasCustomFocusLogic`, `IsKeyboardFocusable`, `MayTriggerVirtualKeyboard`, `UpdateSelectionOnFocus`)**:  Control how the `<textarea>` gains focus.
    * **`DefaultEventHandler`**: Handles various events. Notice the special handling for `BeforeTextInsertedEvent`.
    * **`HandleBeforeTextInsertedEvent`, `SanitizeUserInputValue`**: Implement the `maxlength` constraint.
    * **`UpdateValue`, `Value`, `setValueForBinding`, `SetValue`, `SetNonDirtyValue`**: Manage the element's text content. Pay attention to the handling of newlines and the `is_dirty_` flag.
    * **`defaultValue`, `setDefaultValue`**:  Handle the initial content of the `<textarea>`.
    * **`SetSuggestedValue`**: Deals with autofill suggestions.
    * **Validation Methods (`validationMessage`, `ValueMissing`, `TooLong`, `TooShort`, `IsValidValue`)**: Implement HTML5 form validation rules.
    * **`AccessKeyAction`**:  Handles access key activation.
    * **`setCols`, `setRows`**: Setter methods for the `cols` and `rows` attributes.
    * **Pseudo-class Matching (`MatchesReadOnlyPseudoClass`, `MatchesReadWritePseudoClass`)**: Determine if the `<textarea>` matches CSS pseudo-classes related to readonly state.
    * **Placeholder Related Methods (`SetPlaceholderVisibility`, `CreateInnerEditorElementIfNecessary`, `IsInnerEditorValueEmpty`, `UpdatePlaceholderText`, `GetPlaceholderValue`)**: Manage the display and content of the placeholder.
    * **`IsInteractiveContent`**:  Indicates the element can be interacted with.
    * **`CloneNonAttributePropertiesFrom`**: Handles copying state when cloning the element.
    * **`DefaultToolTip`**: Provides the default tooltip content (based on validation errors).
    * **`SetFocused`**: Handles focus and blur events.

5. **Identify Relationships with Web Technologies:**
    * **HTML:** The entire file revolves around the `<textarea>` element. Methods like `ParseAttribute` directly handle HTML attributes.
    * **CSS:** Methods like `CollectStyleForPresentationAttribute` and the handling of the `wrap` attribute demonstrate the connection to CSS styling. The placeholder functionality also uses CSS for display.
    * **JavaScript:**  Methods like `setValueForBinding`, the handling of events in `DefaultEventHandler`, and the interaction with the `value` property show the connection to JavaScript. The autofill functionality also involves JavaScript interaction.

6. **Logical Inference and Examples:**  For crucial methods, think about how they work and create hypothetical scenarios:
    * **`ParseAttribute`**:  If `rows="10"` is set, `rows_` becomes 10, and layout is updated. If `wrap="hard"` is set, CSS properties related to `white-space` and `overflow-wrap` are set.
    * **`AppendToFormData`**: If a `<textarea name="comment">Hello\nWorld</textarea>` has `wrap="hard"`, the form data will contain `comment=Hello\r\nWorld`.
    * **`HandleBeforeTextInsertedEvent`**: If `maxlength="10"` and the current value is "12345" and the user types "67890", the event's text will be truncated to "6789".
    * **`SetValue`**:  Setting the `value` property via JavaScript triggers layout updates, potential event dispatch, and validity checks.

7. **Identify Potential Errors:** Look for situations that could lead to incorrect behavior or user errors:
    * Incorrectly setting `rows` or `cols` to non-numeric or negative values.
    * Mismatched or unexpected behavior with the deprecated `wrap="physical"` attribute.
    * Issues with line ending normalization across different platforms.
    * Exceeding `maxlength` and the user experience around that.
    * Incorrect assumptions about the behavior of `defaultValue`.

8. **Structure the Output:** Organize the findings into clear categories as requested: functionality, relationship with web technologies, logical inference with examples, and common usage errors. Use clear and concise language.

9. **Refine and Review:**  Read through the analysis, ensuring accuracy and completeness. Check for any missing aspects or areas that need more explanation. For instance, initially, I might have overlooked the details of the suggested value handling in `scrollWidth` and `scrollHeight`, which requires a closer look at the code. Similarly, understanding the nuances of `is_dirty_` and how it impacts form submission requires careful consideration.
This C++ source file, `html_text_area_element.cc`, within the Chromium Blink rendering engine, is responsible for implementing the behavior and rendering logic of the HTML `<textarea>` element. Let's break down its functionalities:

**Core Functionalities:**

1. **Represents the `<textarea>` Element:** This file defines the `HTMLTextAreaElement` class, which is the C++ representation of the `<textarea>` HTML tag in the Document Object Model (DOM).

2. **Handles Attributes:** It manages the parsing and interpretation of `<textarea>` specific HTML attributes like:
   - `rows`:  Sets the visible height of the text area (in lines).
   - `cols`: Sets the visible width of the text area (in average character widths).
   - `wrap`: Controls how line breaks are handled when submitting the form (`soft`, `hard`, `off`).
   - `maxlength`: Limits the maximum number of characters the user can enter.
   - `minlength`: Specifies the minimum number of characters required.
   - `placeholder`:  Displays hint text when the text area is empty.
   - `dirname`:  Specifies that the directionality of the element should be submitted.
   - `readonly`: Prevents the user from editing the content.
   - `disabled`: Disables the text area, making it non-interactive and un-submittable.
   - `accesskey`:  Specifies a keyboard shortcut to focus the element.

3. **Manages the Text Content:** It stores and manages the text content entered by the user within the `<textarea>`. This includes getting, setting, and manipulating the value.

4. **Implements Form Control Behavior:** As a form control, it interacts with form submission:
   - **Saving and Restoring State:** It can save and restore its state, which is crucial for features like back/forward navigation and form caching.
   - **Appending to FormData:** When a form is submitted, it appends its name and value to the `FormData` object. The `wrap` attribute influences the submitted value.
   - **Resetting:** It implements the reset behavior, setting the value back to its default.

5. **Handles User Interaction:** It manages user interactions like typing, pasting, selecting text, and focusing.

6. **Supports Autofill:**  It participates in the browser's autofill mechanism, allowing users to fill in data automatically.

7. **Implements Validation:** It enforces HTML5 form validation rules:
   - **`required`:** Checks if a value is present.
   - **`maxlength`:**  Checks if the value exceeds the maximum length.
   - **`minlength`:** Checks if the value meets the minimum length.

8. **Manages Placeholder Functionality:**  It controls the display and behavior of the placeholder text.

9. **Handles Focus and Blur Events:** It responds to the element gaining and losing focus.

10. **Integrates with Layout:** It creates a `LayoutTextControlMultiLine` object, which is responsible for the visual layout and rendering of the multi-line text area.

**Relationships with JavaScript, HTML, and CSS:**

* **HTML:**
    - **Direct Representation:** This C++ file is the underlying implementation of the `<textarea>` HTML element. When the browser parses HTML and encounters a `<textarea>` tag, it creates an instance of `HTMLTextAreaElement`.
    - **Attribute Mapping:** The `ParseAttribute` method directly maps HTML attributes to internal properties and behaviors of the `HTMLTextAreaElement`.
    - **Example:** When the HTML contains `<textarea rows="5" cols="30">Initial Text</textarea>`, the `ParseAttribute` method sets `rows_` to 5 and `cols_` to 30. The `defaultValue()` method extracts "Initial Text".

* **JavaScript:**
    - **DOM Interaction:** JavaScript can access and manipulate properties and methods of the `HTMLTextAreaElement` through the DOM API.
    - **`value` Property:** JavaScript can get and set the text content using the `textareaElement.value` property. This interacts with the `Value()` and `setValueForBinding()` methods in the C++ code.
        - **Example:** `document.getElementById('myTextarea').value = 'New text';` in JavaScript will call the `setValueForBinding()` method in `html_text_area_element.cc`.
    - **Event Handling:** JavaScript can attach event listeners to `<textarea>` elements (e.g., `input`, `change`, `focus`, `blur`). These events are triggered by the C++ code when user actions occur.
        - **Example:** When the user types in the `<textarea>`, the C++ code dispatches an `input` event, which can be caught by a JavaScript listener.
    - **Form Submission:** JavaScript can programmatically submit forms containing `<textarea>` elements.
    - **Validation API:** JavaScript can use the Constraint Validation API (e.g., `textareaElement.checkValidity()`, `textareaElement.validationMessage`) which relies on the validation logic implemented in this C++ file.

* **CSS:**
    - **Styling:** CSS rules apply to `<textarea>` elements to control their appearance (e.g., `width`, `height`, `font`, `border`, `padding`).
    - **`wrap` Attribute Styling:** The `CollectStyleForPresentationAttribute` method handles the `wrap` attribute and translates it into corresponding CSS properties like `white-space` and `overflow-wrap`.
        - **Example:** `<textarea wrap="hard"></textarea>` will result in CSS properties being set internally to enforce hard wrapping.
    - **Placeholder Styling:** The placeholder text is styled using the `::placeholder` pseudo-element in CSS.
    - **Pseudo-classes:** The `MatchesReadOnlyPseudoClass()` and `MatchesReadWritePseudoClass()` methods determine if the `<textarea>` matches the `:read-only` and `:read-write` CSS pseudo-classes, enabling conditional styling.

**Logical Inference with Assumptions, Inputs, and Outputs:**

Let's consider the `HandleBeforeTextInsertedEvent` method, which deals with the `maxlength` attribute:

**Assumptions:**

1. The `<textarea>` element has a `maxlength` attribute set to a positive integer.
2. The user is attempting to insert text into the `<textarea>`.

**Input:**

* `event`: A `BeforeTextInsertedEvent` object containing the text the user is trying to insert (`event->GetText()`).
* The current text content of the `<textarea>` (`InnerEditorValue()`).
* The `maxlength` value from the attribute.

**Logic:**

1. Calculate the combined length of the current text and the text to be inserted.
2. If the combined length exceeds `maxlength`, truncate the input text to fit within the limit.
3. If the insertion clears the existing content, notify the Chrome client (for potential UI updates).

**Output:**

* The `event` object's text is potentially modified (`event->SetText()`) to be within the `maxlength` limit.

**Example:**

* **Input:** `<textarea maxlength="10">Hello</textarea>`, user types " world!"
* **Current Value:** "Hello" (length 5)
* **Text to Insert:** " world!" (length 7)
* **`maxlength`:** 10
* **Combined Length:** 5 + 7 = 12
* **Logic:** Since 12 > 10, the input text is truncated to " wo" (10 - 5 = 5 characters allowed).
* **Output:** The `BeforeTextInsertedEvent`'s text is set to " wo". The resulting text in the textarea will be "Hellowo".

**Common Usage Errors and Examples:**

1. **Setting `rows` or `cols` to non-numeric values:**
   - **HTML:** `<textarea rows="abc"></textarea>`
   - **C++ Behavior:** The `ParseAttribute` method will fail to parse "abc" as an integer, and the `rows_` will default to `kDefaultRows` (2). The visual rendering will use the default number of rows.

2. **Misunderstanding the `wrap` attribute:**
   - **HTML:** `<textarea wrap="hard">Line1\nLine2</textarea>`
   - **User Expectation:** Submitting the form will send "Line1\nLine2".
   - **Actual Output (with `wrap="hard"`):** The submitted data will replace line breaks with carriage return + line feed (`\r\n`), so it becomes "Line1\r\nLine2". Developers might forget this conversion happens on form submission with `wrap="hard"`.

3. **Relying on `defaultValue` for dynamic content:**
   - **JavaScript:**
     ```javascript
     const textarea = document.getElementById('myTextarea');
     textarea.innerHTML = 'Dynamically set text';
     console.log(textarea.defaultValue); // Might be an empty string or the initial HTML content
     ```
   - **Error:** `defaultValue` reflects the initial content in the HTML. Setting the content using `innerHTML` or `textContent` after the element is created does *not* change the `defaultValue`. Developers should use the `value` property to get the current content.

4. **Assuming `maxlength` prevents pasting:**
   - **User Action:** Pasting a large amount of text into a `<textarea>` with a `maxlength` limit.
   - **C++ Behavior:** The `HandleBeforeTextInsertedEvent` will truncate the pasted text to fit within the `maxlength`. The user might be surprised that not all pasted content is inserted.

5. **Not handling line break differences:**
   - **Cross-platform issues:** Different operating systems use different line break characters (`\n` on Linux/macOS, `\r\n` on Windows). The `ReplaceCRWithNewLine` function in the C++ code normalizes these to `\n` for internal consistency, but developers working directly with the `value` might need to be aware of these differences when dealing with text from the server or other sources.

In summary, `html_text_area_element.cc` is a crucial component for rendering and managing the behavior of the `<textarea>` element in Blink. It bridges the gap between the HTML markup, CSS styling, and JavaScript interaction, handling user input, form submission, and validation according to web standards. Understanding its functionality is essential for web developers to create robust and predictable web forms.

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_text_area_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2010 Apple Inc. All rights
 * reserved.
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 * Copyright (C) 2007 Samuel Weinig (sam@webkit.org)
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

#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"

#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_focus_options.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/event_interface_names.h"
#include "third_party/blink/renderer/core/events/before_text_inserted_event.h"
#include "third_party/blink/renderer/core/events/drag_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/text_control_inner_elements.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/forms/layout_text_control_multi_line.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using mojom::blink::FormControlType;

static const unsigned kDefaultRows = 2;
static const unsigned kDefaultCols = 20;

static bool is_default_font_prewarmed_ = false;

static inline unsigned ComputeLengthForAPIValue(const String& text) {
  unsigned length = text.length();
  unsigned crlf_count = 0;
  for (unsigned i = 0; i < length; ++i) {
    if (text[i] == '\r' && i + 1 < length && text[i + 1] == '\n')
      crlf_count++;
  }
  return text.length() - crlf_count;
}

static inline void ReplaceCRWithNewLine(String& text) {
  text.Replace("\r\n", "\n");
  text.Replace('\r', '\n');
}

HTMLTextAreaElement::HTMLTextAreaElement(Document& document)
    : TextControlElement(html_names::kTextareaTag, document),
      rows_(kDefaultRows),
      cols_(kDefaultCols),
      wrap_(kSoftWrap),
      is_dirty_(false),
      is_placeholder_visible_(false) {
  EnsureUserAgentShadowRoot();

  if (!is_default_font_prewarmed_) {
    if (Settings* settings = document.GetSettings()) {
      // Prewarm 'monospace', the default font family for `<textarea>`. The
      // default language should be fine for this purpose because most users set
      // the same family for all languages.
      FontCache::PrewarmFamily(settings->GetGenericFontFamilySettings().Fixed(
          LayoutLocale::GetDefault().GetScript()));
      is_default_font_prewarmed_ = true;
    }
  }
}

void HTMLTextAreaElement::DidAddUserAgentShadowRoot(ShadowRoot& root) {
  root.AppendChild(CreateInnerEditorElement());
}

FormControlType HTMLTextAreaElement::FormControlType() const {
  return FormControlType::kTextArea;
}

const AtomicString& HTMLTextAreaElement::FormControlTypeAsString() const {
  DEFINE_STATIC_LOCAL(const AtomicString, textarea, ("textarea"));
  return textarea;
}

FormControlState HTMLTextAreaElement::SaveFormControlState() const {
  return is_dirty_ ? FormControlState(Value()) : FormControlState();
}

void HTMLTextAreaElement::RestoreFormControlState(
    const FormControlState& state) {
  SetValue(state[0]);
}

int HTMLTextAreaElement::scrollWidth() {
  if (SuggestedValue().empty())
    return TextControlElement::scrollWidth();
  // If in preview state, fake the scroll width to prevent that any information
  // about the suggested content can be derived from the size.
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  auto* editor = InnerEditorElement();
  auto* editor_box = editor ? editor->GetLayoutBox() : nullptr;
  auto* box = GetLayoutBox();
  if (!box || !editor_box)
    return TextControlElement::scrollWidth();
  LayoutUnit width =
      editor_box->ClientWidth() + box->PaddingLeft() + box->PaddingRight();
  return AdjustForAbsoluteZoom::AdjustLayoutUnit(width, box->StyleRef())
      .Round();
}

int HTMLTextAreaElement::scrollHeight() {
  if (SuggestedValue().empty())
    return TextControlElement::scrollHeight();
  // If in preview state, fake the scroll height to prevent that any
  // information about the suggested content can be derived from the size.
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  auto* editor = InnerEditorElement();
  auto* editor_box = editor ? editor->GetLayoutBox() : nullptr;
  auto* box = GetLayoutBox();
  if (!box || !editor_box)
    return TextControlElement::scrollHeight();
  LayoutUnit height =
      editor_box->ClientHeight() + box->PaddingTop() + box->PaddingBottom();
  return AdjustForAbsoluteZoom::AdjustLayoutUnit(height, box->StyleRef())
      .Round();
}

void HTMLTextAreaElement::ChildrenChanged(const ChildrenChange& change) {
  HTMLElement::ChildrenChanged(change);
  if (is_dirty_)
    SetInnerEditorValue(Value());
  else
    SetNonDirtyValue(defaultValue(), TextControlSetValueSelection::kClamp);
}

bool HTMLTextAreaElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kAlignAttr) {
    // Don't map 'align' attribute.  This matches what Firefox, Opera and IE do.
    // See http://bugs.webkit.org/show_bug.cgi?id=7075
    return false;
  }

  if (name == html_names::kWrapAttr)
    return true;
  return TextControlElement::IsPresentationAttribute(name);
}

void HTMLTextAreaElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kWrapAttr) {
    if (ShouldWrapText()) {
      // Longhands of `white-space: pre-wrap`.
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWhiteSpaceCollapse, CSSValueID::kPreserve);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kTextWrapMode, CSSValueID::kWrap);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kOverflowWrap, CSSValueID::kBreakWord);
    } else {
      // Longhands of `white-space: pre`.
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWhiteSpaceCollapse, CSSValueID::kPreserve);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kTextWrapMode, CSSValueID::kNowrap);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kOverflowWrap, CSSValueID::kNormal);
    }
  } else {
    TextControlElement::CollectStyleForPresentationAttribute(name, value,
                                                             style);
  }
}

void HTMLTextAreaElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  const AtomicString& value = params.new_value;
  if (name == html_names::kRowsAttr) {
    unsigned rows = 0;
    if (value.empty() || !ParseHTMLNonNegativeInteger(value, rows) ||
        rows <= 0 || rows > 0x7fffffffu)
      rows = kDefaultRows;
    if (rows_ != rows) {
      rows_ = rows;
      if (GetLayoutObject()) {
        GetLayoutObject()
            ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
                layout_invalidation_reason::kAttributeChanged);
      }
    }
  } else if (name == html_names::kColsAttr) {
    unsigned cols = 0;
    if (value.empty() || !ParseHTMLNonNegativeInteger(value, cols) ||
        cols <= 0 || cols > 0x7fffffffu)
      cols = kDefaultCols;
    if (cols_ != cols) {
      cols_ = cols;
      if (LayoutObject* layout_object = GetLayoutObject()) {
        layout_object
            ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
                layout_invalidation_reason::kAttributeChanged);
      }
    }
  } else if (name == html_names::kWrapAttr) {
    // The virtual/physical values were a Netscape extension of HTML 3.0, now
    // deprecated.  The soft/hard /off values are a recommendation for HTML 4
    // extension by IE and NS 4.
    WrapMethod wrap;
    if (EqualIgnoringASCIICase(value, "physical") ||
        EqualIgnoringASCIICase(value, "hard") ||
        EqualIgnoringASCIICase(value, "on"))
      wrap = kHardWrap;
    else if (EqualIgnoringASCIICase(value, "off"))
      wrap = kNoWrap;
    else
      wrap = kSoftWrap;
    if (wrap != wrap_) {
      wrap_ = wrap;
      if (LayoutObject* layout_object = GetLayoutObject()) {
        layout_object
            ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
                layout_invalidation_reason::kAttributeChanged);
      }
    }
  } else if (name == html_names::kAccesskeyAttr) {
    // ignore for the moment
  } else if (name == html_names::kMaxlengthAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kTextAreaMaxLength);
    SetNeedsValidityCheck();
  } else if (name == html_names::kMinlengthAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kTextAreaMinLength);
    SetNeedsValidityCheck();
  } else {
    TextControlElement::ParseAttribute(params);
  }
}

LayoutObject* HTMLTextAreaElement::CreateLayoutObject(const ComputedStyle&) {
  return MakeGarbageCollected<LayoutTextControlMultiLine>(this);
}

void HTMLTextAreaElement::AppendToFormData(FormData& form_data) {
  if (GetName().empty())
    return;

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kForm);

  const String& text =
      (wrap_ == kHardWrap) ? ValueWithHardLineBreaks() : Value();
  form_data.AppendFromElement(GetName(), text);

  const AtomicString& dirname_attr_value =
      FastGetAttribute(html_names::kDirnameAttr);
  if (!dirname_attr_value.IsNull())
    form_data.AppendFromElement(dirname_attr_value, DirectionForFormData());
}

void HTMLTextAreaElement::ResetImpl() {
  SetNonDirtyValue(defaultValue(),
                   TextControlSetValueSelection::kSetSelectionToEnd);
  HTMLFormControlElementWithState::ResetImpl();
}

bool HTMLTextAreaElement::HasCustomFocusLogic() const {
  return true;
}

bool HTMLTextAreaElement::IsKeyboardFocusable(
    UpdateBehavior update_behavior) const {
  // If a given text area can be focused at all, then it will always be keyboard
  // focusable, unless it has a negative tabindex set.
  return IsFocusable(update_behavior) && tabIndex() >= 0;
}

bool HTMLTextAreaElement::MayTriggerVirtualKeyboard() const {
  return true;
}

void HTMLTextAreaElement::UpdateSelectionOnFocus(
    SelectionBehaviorOnFocus selection_behavior,
    const FocusOptions* options) {
  switch (selection_behavior) {
    case SelectionBehaviorOnFocus::kReset:  // Fallthrough.
    case SelectionBehaviorOnFocus::kRestore:
      RestoreCachedSelection();
      break;
    case SelectionBehaviorOnFocus::kNone:
      return;
  }
  if (!options->preventScroll()) {
    if (GetDocument().GetFrame())
      GetDocument().GetFrame()->Selection().RevealSelection();
  }
}

void HTMLTextAreaElement::DefaultEventHandler(Event& event) {
  if (GetLayoutObject() &&
      (IsA<MouseEvent>(event) || IsA<DragEvent>(event) ||
       event.HasInterface(event_interface_names::kWheelEvent) ||
       event.type() == event_type_names::kBlur)) {
    ForwardEvent(event);
  } else if (GetLayoutObject() && event.IsBeforeTextInsertedEvent()) {
    HandleBeforeTextInsertedEvent(
        static_cast<BeforeTextInsertedEvent*>(&event));
  }

  TextControlElement::DefaultEventHandler(event);
}

void HTMLTextAreaElement::SubtreeHasChanged() {
#if DCHECK_IS_ON()
  // The innerEditor should have either Text nodes or a placeholder break
  // element. If we see other nodes, it's a bug in editing code and we should
  // fix it.
  Element* inner_editor = InnerEditorElement();
  for (Node& node : NodeTraversal::DescendantsOf(*inner_editor)) {
    if (node.IsTextNode())
      continue;
    DCHECK(IsA<HTMLBRElement>(node));
    DCHECK_EQ(&node, inner_editor->lastChild());
  }
#endif
  AddPlaceholderBreakElementIfNecessary();
  SetValueBeforeFirstUserEditIfNotSet();
  UpdateValue();
  CheckIfValueWasReverted(Value());
  SetNeedsValidityCheck();
  SetAutofillState(WebAutofillState::kNotFilled);
  UpdatePlaceholderVisibility();

  if (HasDirectionAuto() ||
      !RuntimeEnabledFeatures::TextInputNotAlwaysDirAutoEnabled()) {
    // When typing in a textarea, childrenChanged is not called, so we need to
    // force the directionality check.
    CalculateAndAdjustAutoDirectionality();
  }

  if (!IsFocused())
    return;

  DCHECK(GetDocument().IsActive());
  if (InnerEditorValue().empty()) {
    GetDocument().GetPage()->GetChromeClient().DidClearValueInTextField(*this);
  }
  GetDocument().GetPage()->GetChromeClient().DidChangeValueInTextField(*this);
}

void HTMLTextAreaElement::HandleBeforeTextInsertedEvent(
    BeforeTextInsertedEvent* event) {
  DCHECK(event);
  DCHECK(GetLayoutObject());
  int signed_max_length = maxLength();
  if (signed_max_length < 0)
    return;
  unsigned unsigned_max_length = static_cast<unsigned>(signed_max_length);

  const String& current_value = InnerEditorValue();
  unsigned current_length = ComputeLengthForAPIValue(current_value);
  if (current_length + ComputeLengthForAPIValue(event->GetText()) <
      unsigned_max_length)
    return;

  // selectionLength represents the selection length of this text field to be
  // removed by this insertion.
  // If the text field has no focus, we don't need to take account of the
  // selection length. The selection is the source of text drag-and-drop in
  // that case, and nothing in the text field will be removed.
  unsigned selection_length = 0;
  if (IsFocused()) {
    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited.  See http://crbug.com/590369 for more details.
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kForm);

    selection_length = ComputeLengthForAPIValue(
        GetDocument().GetFrame()->Selection().SelectedText());
  }
  DCHECK_GE(current_length, selection_length);
  unsigned base_length = current_length - selection_length;
  unsigned appendable_length =
      unsigned_max_length > base_length ? unsigned_max_length - base_length : 0;
  event->SetText(SanitizeUserInputValue(event->GetText(), appendable_length));

  if (selection_length == current_length && selection_length != 0 &&
      !event->GetText().empty()) {
    GetDocument().GetPage()->GetChromeClient().DidClearValueInTextField(*this);
  }
}

String HTMLTextAreaElement::SanitizeUserInputValue(const String& proposed_value,
                                                   unsigned max_length) {
  unsigned submission_length = 0;
  unsigned i = 0;
  for (; i < proposed_value.length(); ++i) {
    if (proposed_value[i] == '\r' && i + 1 < proposed_value.length() &&
        proposed_value[i + 1] == '\n')
      continue;
    ++submission_length;
    if (submission_length == max_length) {
      ++i;
      break;
    }
    if (submission_length > max_length)
      break;
  }
  if (i > 0 && U16_IS_LEAD(proposed_value[i - 1]))
    --i;
  return proposed_value.Left(i);
}

void HTMLTextAreaElement::UpdateValue() {
  value_ = InnerEditorValue();
  NotifyFormStateChanged();
  is_dirty_ = true;
  UpdatePlaceholderVisibility();
}

String HTMLTextAreaElement::Value() const {
  return value_;
}

void HTMLTextAreaElement::setValueForBinding(const String& value) {
  String old_value = this->Value();
  bool was_autofilled = IsAutofilled();
  bool value_changed = old_value != value;
  SetValue(value, TextFieldEventBehavior::kDispatchNoEvent,
           TextControlSetValueSelection::kSetSelectionToEnd,
           was_autofilled && !value_changed ? WebAutofillState::kAutofilled
                                            : WebAutofillState::kNotFilled);
  if (Page* page = GetDocument().GetPage(); page && value_changed) {
    page->GetChromeClient().JavaScriptChangedValue(*this, old_value,
                                                   was_autofilled);
  }
}

void HTMLTextAreaElement::SetValue(const String& value,
                                   TextFieldEventBehavior event_behavior,
                                   TextControlSetValueSelection selection,
                                   WebAutofillState autofill_state) {
  SetValueCommon(value, event_behavior, selection, autofill_state);
  is_dirty_ = true;
}

void HTMLTextAreaElement::SetNonDirtyValue(
    const String& value,
    TextControlSetValueSelection selection) {
  SetValueCommon(value, TextFieldEventBehavior::kDispatchNoEvent, selection,
                 WebAutofillState::kNotFilled);
  is_dirty_ = false;
}

void HTMLTextAreaElement::SetValueCommon(const String& new_value,
                                         TextFieldEventBehavior event_behavior,
                                         TextControlSetValueSelection selection,
                                         WebAutofillState autofill_state) {
  // Code elsewhere normalizes line endings added by the user via the keyboard
  // or pasting.  We normalize line endings coming from JavaScript here.
  String normalized_value = new_value;
  ReplaceCRWithNewLine(normalized_value);

  // Clear the suggested value. Use the base class version to not trigger a view
  // update.
  TextControlElement::SetSuggestedValue(String());

  // Return early because we don't want to trigger other side effects when the
  // value isn't changing. This is interoperable.
  if (normalized_value == Value())
    return;

  // selectionStart and selectionEnd values can be changed by
  // SetInnerEditorValue(). We need to get them before SetInnerEditorValue() to
  // clamp them later in a case of kClamp.
  const bool is_clamp = selection == TextControlSetValueSelection::kClamp;
  const unsigned selection_start = is_clamp ? selectionStart() : 0;
  const unsigned selection_end = is_clamp ? selectionEnd() : 0;

  if (event_behavior != TextFieldEventBehavior::kDispatchNoEvent)
    SetValueBeforeFirstUserEditIfNotSet();
  value_ = normalized_value;
  SetInnerEditorValue(value_);
  if (event_behavior == TextFieldEventBehavior::kDispatchNoEvent)
    SetLastChangeWasNotUserEdit();
  else
    CheckIfValueWasReverted(value_);
  UpdatePlaceholderVisibility();
  SetNeedsStyleRecalc(
      kSubtreeStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kControlValue));
  SetNeedsValidityCheck();
  if (selection == TextControlSetValueSelection::kSetSelectionToEnd) {
    // Set the caret to the end of the text value except for initialize.
    unsigned end_of_string = value_.length();
    SetSelectionRange(end_of_string, end_of_string);
  } else if (selection == TextControlSetValueSelection::kSetSelectionToStart) {
    // Set the caret to the start of the text value.
    SetSelectionRange(0, 0);
  } else if (is_clamp) {
    const unsigned end_of_string = value_.length();
    SetSelectionRange(std::min(end_of_string, selection_start),
                      std::min(end_of_string, selection_end));
  }

  SetAutofillState(autofill_state);
  NotifyFormStateChanged();
  switch (event_behavior) {
    case TextFieldEventBehavior::kDispatchChangeEvent:
      DispatchFormControlChangeEvent();
      break;

    case TextFieldEventBehavior::kDispatchInputEvent:
      DispatchInputEvent();
      break;

    case TextFieldEventBehavior::kDispatchInputAndChangeEvent:
      DispatchInputEvent();
      DispatchFormControlChangeEvent();
      break;

    case TextFieldEventBehavior::kDispatchNoEvent:
      break;
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

String HTMLTextAreaElement::defaultValue() const {
  StringBuilder value;

  // Since there may be comments, ignore nodes other than text nodes.
  for (Node* n = firstChild(); n; n = n->nextSibling()) {
    if (auto* text_node = DynamicTo<Text>(n))
      value.Append(text_node->data());
  }

  return value.ToString();
}

void HTMLTextAreaElement::setDefaultValue(const String& default_value) {
  setTextContent(default_value);
}

void HTMLTextAreaElement::SetSuggestedValue(const String& value) {
  SetAutofillState(!value.empty() ? WebAutofillState::kPreviewed
                                  : WebAutofillState::kNotFilled);
  TextControlElement::SetSuggestedValue(value);
  SetNeedsStyleRecalc(
      kSubtreeStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kControlValue));
}

String HTMLTextAreaElement::validationMessage() const {
  if (!willValidate())
    return String();

  if (CustomError())
    return CustomValidationMessage();

  if (ValueMissing())
    return GetLocale().QueryString(IDS_FORM_VALIDATION_VALUE_MISSING);

  if (TooLong()) {
    return GetLocale().ValidationMessageTooLongText(Value().length(),
                                                    maxLength());
  }

  if (TooShort()) {
    return GetLocale().ValidationMessageTooShortText(Value().length(),
                                                     minLength());
  }

  return String();
}

bool HTMLTextAreaElement::ValueMissing() const {
  // We should not call value() for performance.
  return ValueMissing(nullptr);
}

bool HTMLTextAreaElement::ValueMissing(const String* value) const {
  // For textarea elements, the value is missing only if it is mutable.
  // https://html.spec.whatwg.org/multipage/form-elements.html#attr-textarea-required
  return IsRequiredFormControl() && !IsDisabledOrReadOnly() &&
         (value ? *value : this->Value()).empty();
}

bool HTMLTextAreaElement::TooLong() const {
  // We should not call value() for performance.
  return willValidate() && TooLong(nullptr, kCheckDirtyFlag);
}

bool HTMLTextAreaElement::TooShort() const {
  // We should not call value() for performance.
  return willValidate() && TooShort(nullptr, kCheckDirtyFlag);
}

bool HTMLTextAreaElement::TooLong(const String* value,
                                  NeedsToCheckDirtyFlag check) const {
  // Return false for the default value or value set by script even if it is
  // longer than maxLength.
  if (check == kCheckDirtyFlag && !LastChangeWasUserEdit())
    return false;

  int max = maxLength();
  if (max < 0)
    return false;
  unsigned len =
      value ? ComputeLengthForAPIValue(*value) : this->Value().length();
  return len > static_cast<unsigned>(max);
}

bool HTMLTextAreaElement::TooShort(const String* value,
                                   NeedsToCheckDirtyFlag check) const {
  // Return false for the default value or value set by script even if it is
  // shorter than minLength.
  if (check == kCheckDirtyFlag && !LastChangeWasUserEdit())
    return false;

  int min = minLength();
  if (min <= 0)
    return false;
  // An empty string is excluded from minlength check.
  unsigned len =
      value ? ComputeLengthForAPIValue(*value) : this->Value().length();
  return len > 0 && len < static_cast<unsigned>(min);
}

bool HTMLTextAreaElement::IsValidValue(const String& candidate) const {
  return !ValueMissing(&candidate) && !TooLong(&candidate, kIgnoreDirtyFlag) &&
         !TooShort(&candidate, kIgnoreDirtyFlag);
}

void HTMLTextAreaElement::AccessKeyAction(SimulatedClickCreationScope) {
  Focus(FocusParams(FocusTrigger::kUserGesture));
}

void HTMLTextAreaElement::setCols(unsigned cols) {
  SetUnsignedIntegralAttribute(html_names::kColsAttr,
                               cols ? cols : kDefaultCols, kDefaultCols);
}

void HTMLTextAreaElement::setRows(unsigned rows) {
  SetUnsignedIntegralAttribute(html_names::kRowsAttr,
                               rows ? rows : kDefaultRows, kDefaultRows);
}

bool HTMLTextAreaElement::MatchesReadOnlyPseudoClass() const {
  return IsDisabledOrReadOnly();
}

bool HTMLTextAreaElement::MatchesReadWritePseudoClass() const {
  return !IsDisabledOrReadOnly();
}

void HTMLTextAreaElement::SetPlaceholderVisibility(bool visible) {
  is_placeholder_visible_ = visible;
}

void HTMLTextAreaElement::CreateInnerEditorElementIfNecessary() const {
  // HTMLTextArea immediately creates the inner-editor, so this function should
  // never be called.
  NOTREACHED();
}

bool HTMLTextAreaElement::IsInnerEditorValueEmpty() const {
  return InnerEditorValue().empty();
}

HTMLElement* HTMLTextAreaElement::UpdatePlaceholderText() {
  HTMLElement* placeholder = PlaceholderElement();
  const String placeholder_text = GetPlaceholderValue();
  const bool is_suggested_value = !SuggestedValue().empty();
  if (!is_suggested_value && !FastHasAttribute(html_names::kPlaceholderAttr)) {
    if (placeholder)
      UserAgentShadowRoot()->RemoveChild(placeholder);
    return nullptr;
  }
  if (!placeholder) {
    auto* new_element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
    placeholder = new_element;
    placeholder->SetShadowPseudoId(
        shadow_element_names::kPseudoInputPlaceholder);
    placeholder->setAttribute(html_names::kIdAttr,
                              shadow_element_names::kIdPlaceholder);
    placeholder->SetInlineStyleProperty(
        CSSPropertyID::kDisplay,
        IsPlaceholderVisible() ? CSSValueID::kBlock : CSSValueID::kNone, true);
    UserAgentShadowRoot()->InsertBefore(placeholder, InnerEditorElement());
  }
  if (is_suggested_value) {
    placeholder->SetInlineStyleProperty(CSSPropertyID::kUserSelect,
                                        CSSValueID::kNone, true);
  } else {
    placeholder->RemoveInlineStyleProperty(CSSPropertyID::kUserSelect);
  }
  String normalized_value = placeholder_text;
  // https://html.spec.whatwg.org/multipage/form-elements.html#attr-textarea-placeholder
  ReplaceCRWithNewLine(normalized_value);
  placeholder->setTextContent(normalized_value);
  return placeholder;
}

String HTMLTextAreaElement::GetPlaceholderValue() const {
  return !SuggestedValue().empty()
             ? SuggestedValue()
             : FastGetAttribute(html_names::kPlaceholderAttr);
}

bool HTMLTextAreaElement::IsInteractiveContent() const {
  return true;
}

void HTMLTextAreaElement::CloneNonAttributePropertiesFrom(
    const Element& source,
    NodeCloningData& data) {
  const auto& source_element = To<HTMLTextAreaElement>(source);
  SetValueCommon(source_element.Value(),
                 TextFieldEventBehavior::kDispatchNoEvent,
                 TextControlSetValueSelection::kSetSelectionToStart,
                 source_element.GetAutofillState());
  is_dirty_ = source_element.is_dirty_;
  TextControlElement::CloneNonAttributePropertiesFrom(source, data);
}

String HTMLTextAreaElement::DefaultToolTip() const {
  if (FastHasAttribute(html_names::kNovalidateAttr))
    return String();
  return validationMessage();
}

void HTMLTextAreaElement::SetFocused(bool is_focused,
                                     mojom::blink::FocusType focus_type) {
  // See comment in HTMLInputElement::SetFocused.
  if (UserHasEditedTheField()) {
    SetUserHasEditedTheFieldAndBlurred();
  }
  TextControlElement::SetFocused(is_focused, focus_type);
}

}  // namespace blink
```
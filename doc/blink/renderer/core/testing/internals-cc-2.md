Response:
The user wants a summary of the functionalities provided by the C++ code snippet from `blink/renderer/core/testing/internals.cc`. The summary should consider relationships to web technologies (JavaScript, HTML, CSS) and provide examples, including potential usage errors and debugging hints.

Here's a breakdown of how to approach this:

1. **Identify the Class:** The code is within the `Internals` class. This immediately suggests it's for internal testing purposes within the Blink engine.

2. **Analyze Individual Functions:** Go through each function in the provided snippet and determine its primary purpose.

3. **Categorize Functionalities:** Group related functions together. For example, there are several functions dealing with text selection, input elements, and spellchecking.

4. **Identify Web Technology Relationships:** For each function or group of functions, consider how they interact with or expose aspects of JavaScript, HTML, and CSS.

5. **Construct Examples:** For each identified functionality, create simple examples illustrating its use and relationship to web technologies. Think about how a test might use these functions.

6. **Consider User/Programming Errors:**  Analyze the function parameters and logic to identify potential misuse scenarios or common programming errors.

7. **Trace User Operations:** Think about the user actions that might lead to these internal functions being used. This is often related to testing specific browser behaviors.

8. **Formulate a Summary:** Combine the analyzed functionalities and their relationships into a concise summary.

**Constraint Checklist & Confidence Score:**

* Provide functionality list: Yes
* Explain relationship with JS/HTML/CSS: Yes
* Provide examples for JS/HTML/CSS: Yes
* Include logical reasoning with input/output: Yes (will be simple examples)
* Explain common usage errors: Yes
* Explain how user operations lead here: Yes
* This is part 3 of 5: Acknowledge and focus on the provided snippet.
* Summarize functionality: Yes

Confidence Score: 5/5 -  The information is present in the code to fulfill all requirements.

**Mental Sandbox:**

* **Spellchecking functions:**  These are clearly related to text input and could be triggered by a user typing. A test might use these to verify spellchecking. Error: Passing a `nullptr` Document.
* **Viewport functions:** These relate to how the browser renders the page and are connected to CSS layout. A test might check how the viewport adapts.
* **Input/Form functions:**  Directly related to HTML forms. Tests could simulate user input or check auto-completion. Error: Providing a non-form element to `setSuggestedValue`.
* **Hit-testing functions:** These simulate mouse or touch interactions and are crucial for event handling. A test could verify which element receives an event.
* **Selection/Range functions:** Used to programmatically manipulate text selection, often in rich text editors or form fields.
* **Layer Tree functions:**  Related to the internal rendering process and how elements are composited. This is more advanced and used for graphics testing.
* **Event Handler Counts:**  Used for debugging event listener attachment.
* **`nodesFromRect`:** Useful for testing what elements are present within a given area on the screen.
* **General Testing Utilities:** Some functions seem to provide low-level access for test setup and verification (e.g., setting preferred languages).

**Refinement:** The examples should be simple and directly related to the function's purpose. Avoid overly complex scenarios. Focus on clarity and directness. The debugging hints should be tied to the common usage errors.

Strategizing complete. Proceeding with response generation.
这是 `blink/renderer/core/testing/internals.cc` 文件的第 3 部分，它主要提供了一系列 **内部接口**，用于 Blink 渲染引擎的 **测试** 目的。这些接口允许测试代码以编程方式访问和操作 Blink 引擎的内部状态和功能，从而实现更细粒度的控制和断言。

**主要功能归纳：**

这部分代码主要集中在以下几个方面的测试辅助功能：

1. **文本操作和选择：**  提供了获取和设置文本选择范围、文本内容的方法，用于测试文本编辑和操作相关的功能。
2. **输入和表单控件：**  可以控制表单控件的自动完成、建议值和自动填充状态，用于测试表单相关的行为。
3. **视口控制：**  允许获取视口的文本描述，并能临时设置视口大小，用于测试不同视口配置下的页面渲染。
4. **命中测试：**  提供模拟点击或触摸事件进行命中测试的功能，并能根据不同条件（例如可点击区域、上下文菜单区域）调整目标节点。
5. **拼写检查：**  可以获取和控制拼写检查请求的状态和结果，用于测试拼写检查功能。
6. **事件处理：**  能够获取各种事件处理器的数量，用于分析和调试事件监听器的注册情况。
7. **触摸事件目标区域：**  可以获取参与触摸事件处理的图层矩形信息，用于测试触摸事件的目标定位。
8. **命令执行：**  允许执行编辑器命令，用于测试编辑相关的操作。
9. **DOM 元素查找：**  提供根据矩形区域查找 DOM 节点的功能，用于测试元素在页面上的布局和可见性。
10. **拼写和语法标记：**  可以检查是否存在拼写或语法错误标记，用于测试拼写和语法检查功能。
11. **文本排版：**  提供了与文本断行和连字符相关的测试功能。
12. **资源管理：**  可以触发资源回收，用于测试资源管理相关的行为。
13. **计数器：**  可以获取特定对象（如 MediaKeys，MediaKeySession，Node，Document）的实时数量，用于内存泄漏检测等。
14. **图层树信息：**  可以以文本形式输出图层树的结构，用于测试渲染流水线。
15. **滚动原因：**  可以获取主线程滚动的触发原因，用于性能分析和优化。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`Internals` 提供的功能通常是 JavaScript 无法直接访问的底层能力，但它们直接影响着 JavaScript 可以操作的 DOM、CSS 样式以及用户在 HTML 页面上的交互。

* **JavaScript:**  JavaScript 代码可以通过调用 `internals` 全局对象（在测试环境下）来使用这些方法。例如，测试 JavaScript 操作文本选择的效果，可以使用 `internals.rangeFromLocationAndLength()` 创建一个 Range 对象，然后用 JavaScript API 进行操作。

   ```javascript
   // 假设有一个 id 为 "myDiv" 的 div 元素
   let myDiv = document.getElementById('myDiv');
   internals.setSelectionRangeForNode(myDiv, 1, 5); // 设置选择范围
   console.log(window.getSelection().toString()); // 使用 JavaScript 获取选择的文本
   ```

* **HTML:**  许多 `Internals` 的功能都直接作用于 HTML 元素。例如，`internals.setSuggestedValue()` 可以设置 HTML 输入元素的建议值，这会影响浏览器显示的自动完成提示。

   ```javascript
   let inputElement = document.createElement('input');
   inputElement.setAttribute('type', 'text');
   document.body.appendChild(inputElement);
   internals.setSuggestedValue(inputElement, 'example@domain.com');
   // 当用户聚焦输入框时，可能会看到 "example@domain.com" 作为建议值
   ```

* **CSS:**  `internals.viewportAsText()` 可以获取视口的文本描述，这受到 CSS 中 `<meta name="viewport">` 标签的影响。测试可以验证不同的 viewport 设置是否产生了预期的效果。

   ```javascript
   internals.viewportAsText(document, 0, 800, 600); // 获取视口信息，参数可能不同
   // 输出可能包含视口的尺寸和缩放信息，这受到 CSS 布局和 viewport meta 标签的影响
   ```

**逻辑推理、假设输入与输出：**

* **`internals.elementShouldAutoComplete(element)`:**
    * **假设输入:** 一个 `<input type="text" autocomplete="on">` 元素。
    * **预期输出:** `true`。
    * **假设输入:** 一个 `<div>` 元素。
    * **预期输出:** 抛出一个 `DOMException`，因为该元素不是输入元素。

* **`internals.viewportAsText(document, 0, 800, 600)`:**
    * **假设输入:** 一个包含 `<meta name="viewport" content="width=device-width, initial-scale=1.0">` 的文档。
    * **预期输出:**  类似 `"viewport size 800x600 scale 1 with limits [0.25, 5] and userScalable true"` 的字符串 (具体数值可能因浏览器默认值而异)。

**用户或编程常见的使用错误举例说明：**

* **错误使用 `internals.setSuggestedValue()`:**
    * **错误:**  尝试在一个非表单控件元素（例如 `<div>`）上调用 `internals.setSuggestedValue()`。
    * **结果:**  会抛出一个 `DOMException: The element provided is not a form control element.`
    * **调试线索:** 检查传递给 `setSuggestedValue()` 的元素类型是否是 `HTMLInputElement`, `HTMLTextAreaElement` 或 `HTMLSelectElement`。用户操作通常是开发者在编写测试代码时直接调用这个方法，如果参数类型错误就会触发。

* **错误使用需要 `Document` 参数的方法时传递 `null` 或不正确的 `Document` 对象:**
    * **错误:**  调用 `internals.lastSpellCheckRequestSequence(null)`。
    * **结果:**  会抛出一个 `DOMException: The document provided is invalid.` 或类似错误信息。
    * **调试线索:**  确认在调用 `Internals` 的方法时，传递的 `Document` 对象是有效的并且是当前页面的 document 对象。用户操作到达这里通常是通过测试代码直接调用，需要确保测试代码正确获取了 Document 对象。

**用户操作是如何一步步的到达这里，作为调试线索：**

`Internals` 接口主要用于 **自动化测试**，并非用户直接操作到达的代码。用户操作最终会触发 Blink 引擎的各种功能，而测试代码会使用 `Internals` 提供的接口来验证这些功能的正确性。

一个典型的场景是：

1. **开发者编写一个 Web 应用程序，其中包含一个文本输入框。**
2. **开发者希望测试该输入框的拼写检查功能。**
3. **开发者编写一个 JavaScript 测试，该测试会创建一个包含该输入框的 HTML 文档。**
4. **测试代码使用 `internals.runIdleTimeSpellChecker(document)` 强制触发拼写检查。**
5. **测试代码使用 `internals.hasSpellingMarker(document, start, length)` 检查输入框中是否存在拼写错误标记。**

在这种情况下，"用户操作" 是 **开发者编写并执行了测试代码**。调试线索会集中在测试代码的逻辑是否正确，例如：

* **确保测试代码正确地获取了 `document` 对象。**
* **确保测试代码在期望的时间点调用了 `Internals` 的方法。**
* **检查 `Internals` 方法的参数是否符合预期。**
* **查看 `Internals` 方法的返回值是否与预期一致。**

总而言之，`blink/renderer/core/testing/internals.cc` (特别是这部分) 提供了强大的测试工具，允许开发者深入 Blink 引擎内部进行功能验证。 它与 JavaScript, HTML, CSS 的关系在于，它提供的接口能够操作和检查这些 Web 技术最终呈现和运作的状态。

Prompt: 
```
这是目录为blink/renderer/core/testing/internals.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
nge, underline_color_value, thickness_value, underline_style_value,
      text_color_value, background_color_value, exception_state,
      [&document_marker_controller, &suggestions, &suggestion_highlight_color](
          const EphemeralRange& range, Color underline_color,
          ImeTextSpanThickness thickness,
          ImeTextSpanUnderlineStyle underline_style, Color text_color,
          Color background_color) {
        document_marker_controller.AddSuggestionMarker(
            range,
            SuggestionMarkerProperties::Builder()
                .SetType(SuggestionMarker::SuggestionType::kNotMisspelling)
                .SetSuggestions(suggestions)
                .SetHighlightColor(suggestion_highlight_color)
                .SetUnderlineColor(underline_color)
                .SetThickness(thickness)
                .SetUnderlineStyle(underline_style)
                .SetTextColor(text_color)
                .SetBackgroundColor(background_color)
                .Build());
      });
}

void Internals::setTextMatchMarkersActive(Node* node,
                                          unsigned start_offset,
                                          unsigned end_offset,
                                          bool active) {
  DCHECK(node);
  node->GetDocument().Markers().SetTextMatchMarkersActive(
      To<Text>(*node), start_offset, end_offset, active);
}

String Internals::viewportAsText(Document* document,
                                 float,
                                 int available_width,
                                 int available_height,
                                 ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetPage()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return String();
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Page* page = document->GetPage();

  // Update initial viewport size.
  gfx::Size initial_viewport_size(available_width, available_height);
  document->GetPage()->DeprecatedLocalMainFrame()->View()->SetFrameRect(
      gfx::Rect(gfx::Point(), initial_viewport_size));

  ViewportDescription description = page->GetViewportDescription();
  PageScaleConstraints constraints =
      description.Resolve(gfx::SizeF(initial_viewport_size), Length());

  constraints.FitToContentsWidth(constraints.layout_size.width(),
                                 available_width);
  constraints.ResolveAutoInitialScale();

  StringBuilder builder;

  builder.Append("viewport size ");
  builder.Append(String::Number(constraints.layout_size.width()));
  builder.Append('x');
  builder.Append(String::Number(constraints.layout_size.height()));

  builder.Append(" scale ");
  builder.Append(String::Number(constraints.initial_scale));
  builder.Append(" with limits [");
  builder.Append(String::Number(constraints.minimum_scale));
  builder.Append(", ");
  builder.Append(String::Number(constraints.maximum_scale));

  builder.Append("] and userScalable ");
  builder.Append(description.user_zoom ? "true" : "false");

  return builder.ToString();
}

bool Internals::elementShouldAutoComplete(Element* element,
                                          ExceptionState& exception_state) {
  DCHECK(element);
  if (auto* input = DynamicTo<HTMLInputElement>(*element))
    return input->ShouldAutocomplete();

  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidNodeTypeError,
                                    "The element provided is not an INPUT.");
  return false;
}

String Internals::suggestedValue(Element* element,
                                 ExceptionState& exception_state) {
  DCHECK(element);
  if (!element->IsFormControlElement()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidNodeTypeError,
        "The element provided is not a form control element.");
    return String();
  }

  String suggested_value;
  if (auto* input = DynamicTo<HTMLInputElement>(*element))
    return input->SuggestedValue();

  if (auto* textarea = DynamicTo<HTMLTextAreaElement>(*element))
    return textarea->SuggestedValue();

  if (auto* select = DynamicTo<HTMLSelectElement>(*element))
    return select->SuggestedValue();

  return suggested_value;
}

void Internals::setSuggestedValue(Element* element,
                                  const String& value,
                                  ExceptionState& exception_state) {
  DCHECK(element);
  if (!element->IsFormControlElement()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidNodeTypeError,
        "The element provided is not a form control element.");
    return;
  }

  if (auto* input = DynamicTo<HTMLInputElement>(*element))
    input->SetSuggestedValue(value);

  if (auto* textarea = DynamicTo<HTMLTextAreaElement>(*element))
    textarea->SetSuggestedValue(value);

  if (auto* select = DynamicTo<HTMLSelectElement>(*element)) {
    // A Null string resets the suggested value.
    select->SetSuggestedValue(value.empty() ? String() : value);
  }

  To<HTMLFormControlElement>(element)->SetAutofillState(
      value.empty() ? WebAutofillState::kNotFilled
                    : WebAutofillState::kPreviewed);
}

void Internals::setAutofilledValue(Element* element,
                                   const String& value,
                                   ExceptionState& exception_state) {
  DCHECK(element);
  if (!element->IsFormControlElement()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidNodeTypeError,
        "The element provided is not a form control element.");
    return;
  }

  if (auto* input = DynamicTo<HTMLInputElement>(*element)) {
    input->DispatchScopedEvent(
        *Event::CreateBubble(event_type_names::kKeydown));
    input->SetAutofillValue(value);
    input->DispatchScopedEvent(*Event::CreateBubble(event_type_names::kKeyup));
  }

  if (auto* textarea = DynamicTo<HTMLTextAreaElement>(*element)) {
    textarea->DispatchScopedEvent(
        *Event::CreateBubble(event_type_names::kKeydown));
    textarea->SetAutofillValue(value);
    textarea->DispatchScopedEvent(
        *Event::CreateBubble(event_type_names::kKeyup));
  }

  if (auto* select = DynamicTo<HTMLSelectElement>(*element)) {
    select->SetAutofillValue(
        value.empty() ? String()  // Null string resets the autofill state.
                      : value,
        value.empty() ? WebAutofillState::kNotFilled
                      : WebAutofillState::kAutofilled);
  }
}

void Internals::setAutofilled(Element* element,
                              bool enabled,
                              ExceptionState& exception_state) {
  DCHECK(element);
  auto* form_control_element = DynamicTo<HTMLFormControlElement>(element);
  if (!form_control_element) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidNodeTypeError,
        "The element provided is not a form control element.");
    return;
  }
  form_control_element->SetAutofillState(
      enabled ? WebAutofillState::kAutofilled : WebAutofillState::kNotFilled);
}

void Internals::setSelectionRangeForNumberType(
    Element* input_element,
    uint32_t start,
    uint32_t end,
    ExceptionState& exception_state) {
  DCHECK(input_element);
  auto* html_input_element = DynamicTo<HTMLInputElement>(input_element);
  if (!html_input_element) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidNodeTypeError,
        "The element provided is not an input element.");
    return;
  }

  html_input_element->SetSelectionRangeForTesting(start, end, exception_state);
}

Range* Internals::rangeFromLocationAndLength(Element* scope,
                                             int range_location,
                                             int range_length) {
  DCHECK(scope);

  // TextIterator depends on Layout information, make sure layout it up to date.
  scope->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  return CreateRange(
      PlainTextRange(range_location, range_location + range_length)
          .CreateRange(*scope));
}

unsigned Internals::locationFromRange(Element* scope, const Range* range) {
  DCHECK(scope && range);
  // PlainTextRange depends on Layout information, make sure layout it up to
  // date.
  scope->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  return PlainTextRange::Create(*scope, *range).Start();
}

unsigned Internals::lengthFromRange(Element* scope, const Range* range) {
  DCHECK(scope && range);
  // PlainTextRange depends on Layout information, make sure layout it up to
  // date.
  scope->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  return PlainTextRange::Create(*scope, *range).length();
}

String Internals::rangeAsText(const Range* range) {
  DCHECK(range);
  // Clean layout is required by plain text extraction.
  range->OwnerDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  return range->GetText();
}

void Internals::HitTestRect(HitTestLocation& location,
                            HitTestResult& result,
                            int x,
                            int y,
                            int width,
                            int height,
                            Document* document) {
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  EventHandler& event_handler = document->GetFrame()->GetEventHandler();
  PhysicalRect rect{LayoutUnit(x), LayoutUnit(y), LayoutUnit(width),
                    LayoutUnit(height)};
  rect.offset = document->GetFrame()->View()->ConvertFromRootFrame(rect.offset);
  location = HitTestLocation(rect);
  result = event_handler.HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive |
                    HitTestRequest::kListBased);
}

// TODO(mustaq): The next 5 functions are very similar, can we combine them?

DOMPoint* Internals::touchPositionAdjustedToBestClickableNode(
    int x,
    int y,
    int width,
    int height,
    Document* document,
    ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return nullptr;
  }

  HitTestLocation location;
  HitTestResult result;
  HitTestRect(location, result, x, y, width, height, document);
  Node* target_node = nullptr;
  gfx::Point adjusted_point;

  EventHandler& event_handler = document->GetFrame()->GetEventHandler();
  bool found_node = event_handler.BestNodeForHitTestResult(
      TouchAdjustmentCandidateType::kClickable, location, result,
      adjusted_point, target_node);
  if (found_node)
    return DOMPoint::Create(adjusted_point.x(), adjusted_point.y());

  return nullptr;
}

Node* Internals::touchNodeAdjustedToBestClickableNode(
    int x,
    int y,
    int width,
    int height,
    Document* document,
    ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return nullptr;
  }

  HitTestLocation location;
  HitTestResult result;
  HitTestRect(location, result, x, y, width, height, document);
  Node* target_node = nullptr;
  gfx::Point adjusted_point;
  document->GetFrame()->GetEventHandler().BestNodeForHitTestResult(
      TouchAdjustmentCandidateType::kClickable, location, result,
      adjusted_point, target_node);
  return target_node;
}

DOMPoint* Internals::touchPositionAdjustedToBestContextMenuNode(
    int x,
    int y,
    int width,
    int height,
    Document* document,
    ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return nullptr;
  }

  HitTestLocation location;
  HitTestResult result;
  HitTestRect(location, result, x, y, width, height, document);
  Node* target_node = nullptr;
  gfx::Point adjusted_point;

  EventHandler& event_handler = document->GetFrame()->GetEventHandler();
  bool found_node = event_handler.BestNodeForHitTestResult(
      TouchAdjustmentCandidateType::kContextMenu, location, result,
      adjusted_point, target_node);
  if (found_node)
    return DOMPoint::Create(adjusted_point.x(), adjusted_point.y());

  return DOMPoint::Create(x, y);
}

Node* Internals::touchNodeAdjustedToBestContextMenuNode(
    int x,
    int y,
    int width,
    int height,
    Document* document,
    ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return nullptr;
  }

  HitTestLocation location;
  HitTestResult result;
  HitTestRect(location, result, x, y, width, height, document);
  Node* target_node = nullptr;
  gfx::Point adjusted_point;
  document->GetFrame()->GetEventHandler().BestNodeForHitTestResult(
      TouchAdjustmentCandidateType::kContextMenu, location, result,
      adjusted_point, target_node);
  return target_node;
}

Node* Internals::touchNodeAdjustedToBestStylusWritableNode(
    int x,
    int y,
    int width,
    int height,
    Document* document,
    ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return nullptr;
  }

  HitTestLocation location;
  HitTestResult result;
  HitTestRect(location, result, x, y, width, height, document);
  Node* target_node = nullptr;
  gfx::Point adjusted_point;
  document->GetFrame()->GetEventHandler().BestNodeForHitTestResult(
      TouchAdjustmentCandidateType::kStylusWritable, location, result,
      adjusted_point, target_node);
  return target_node;
}

int Internals::lastSpellCheckRequestSequence(Document* document,
                                             ExceptionState& exception_state) {
  SpellCheckRequester* requester = GetSpellCheckRequester(document);

  if (!requester) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No spell check requestor can be obtained for the provided document.");
    return -1;
  }

  return requester->LastRequestSequence();
}

int Internals::lastSpellCheckProcessedSequence(
    Document* document,
    ExceptionState& exception_state) {
  SpellCheckRequester* requester = GetSpellCheckRequester(document);

  if (!requester) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No spell check requestor can be obtained for the provided document.");
    return -1;
  }

  return requester->LastProcessedSequence();
}

int Internals::spellCheckedTextLength(Document* document,
                                      ExceptionState& exception_state) {
  SpellCheckRequester* requester = GetSpellCheckRequester(document);

  if (!requester) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No spell check requestor can be obtained for the provided document.");
    return -1;
  }

  return requester->SpellCheckedTextLength();
}

void Internals::cancelCurrentSpellCheckRequest(
    Document* document,
    ExceptionState& exception_state) {
  SpellCheckRequester* requester = GetSpellCheckRequester(document);

  if (!requester) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No spell check requestor can be obtained for the provided document.");
    return;
  }

  requester->CancelCheck();
}

String Internals::idleTimeSpellCheckerState(Document* document,
                                            ExceptionState& exception_state) {
  if (!document || !document->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No frame can be obtained from the provided document.");
    return String();
  }

  return document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .GetStateAsString();
}

void Internals::runIdleTimeSpellChecker(Document* document,
                                        ExceptionState& exception_state) {
  if (!document || !document->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No frame can be obtained from the provided document.");
    return;
  }

  document->GetFrame()
      ->GetSpellChecker()
      .GetIdleSpellCheckController()
      .ForceInvocationForTesting();
}

bool Internals::hasLastEditCommand(Document* document,
                                   ExceptionState& exception_state) {
  if (!document || !document->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No frame can be obtained from the provided document.");
    return false;
  }

  return document->GetFrame()->GetEditor().LastEditCommand();
}

Vector<AtomicString> Internals::userPreferredLanguages() const {
  return blink::UserPreferredLanguages();
}

// Optimally, the bindings generator would pass a Vector<AtomicString> here but
// this is not supported yet.
void Internals::setUserPreferredLanguages(const Vector<String>& languages) {
  Vector<AtomicString> atomic_languages;
  for (const String& language : languages)
    atomic_languages.push_back(AtomicString(language));
  OverrideUserPreferredLanguagesForTesting(atomic_languages);
}

void Internals::setSystemTimeZone(const String& timezone) {
  blink::TimeZoneController::ChangeTimeZoneForTesting(timezone);
}

unsigned Internals::mediaKeysCount() {
  return InstanceCounters::CounterValue(InstanceCounters::kMediaKeysCounter);
}

unsigned Internals::mediaKeySessionCount() {
  return InstanceCounters::CounterValue(
      InstanceCounters::kMediaKeySessionCounter);
}

static unsigned EventHandlerCount(
    Document& document,
    EventHandlerRegistry::EventHandlerClass handler_class) {
  if (!document.GetPage())
    return 0;
  EventHandlerRegistry* registry =
      &document.GetFrame()->GetEventHandlerRegistry();
  unsigned count = 0;
  const EventTargetSet* targets = registry->EventHandlerTargets(handler_class);
  if (targets) {
    for (const auto& target : *targets)
      count += target.value;
  }
  return count;
}

unsigned Internals::wheelEventHandlerCount(Document* document) const {
  DCHECK(document);
  return EventHandlerCount(*document,
                           EventHandlerRegistry::kWheelEventBlocking) +
         EventHandlerCount(*document, EventHandlerRegistry::kWheelEventPassive);
}

unsigned Internals::scrollEventHandlerCount(Document* document) const {
  DCHECK(document);
  return EventHandlerCount(*document, EventHandlerRegistry::kScrollEvent);
}

unsigned Internals::touchStartOrMoveEventHandlerCount(
    Document* document) const {
  DCHECK(document);
  return EventHandlerCount(*document, EventHandlerRegistry::kTouchAction) +
         EventHandlerCount(
             *document, EventHandlerRegistry::kTouchStartOrMoveEventBlocking) +
         EventHandlerCount(
             *document,
             EventHandlerRegistry::kTouchStartOrMoveEventBlockingLowLatency) +
         EventHandlerCount(*document,
                           EventHandlerRegistry::kTouchStartOrMoveEventPassive);
}

unsigned Internals::touchEndOrCancelEventHandlerCount(
    Document* document) const {
  DCHECK(document);
  return EventHandlerCount(
             *document, EventHandlerRegistry::kTouchEndOrCancelEventBlocking) +
         EventHandlerCount(*document,
                           EventHandlerRegistry::kTouchEndOrCancelEventPassive);
}

unsigned Internals::pointerEventHandlerCount(Document* document) const {
  DCHECK(document);
  return EventHandlerCount(*document, EventHandlerRegistry::kPointerEvent) +
         EventHandlerCount(*document,
                           EventHandlerRegistry::kPointerRawUpdateEvent);
}

// Given a vector of rects, merge those that are adjacent, leaving empty rects
// in the place of no longer used slots. This is intended to simplify the list
// of rects returned by an SkRegion (which have been split apart for sorting
// purposes). No attempt is made to do this efficiently (eg. by relying on the
// sort criteria of SkRegion).
static void MergeRects(Vector<gfx::Rect>& rects) {
  for (wtf_size_t i = 0; i < rects.size(); ++i) {
    if (rects[i].IsEmpty())
      continue;
    bool updated;
    do {
      updated = false;
      for (wtf_size_t j = i + 1; j < rects.size(); ++j) {
        if (rects[j].IsEmpty())
          continue;
        // Try to merge rects[j] into rects[i] along the 4 possible edges.
        if (rects[i].y() == rects[j].y() &&
            rects[i].height() == rects[j].height()) {
          if (rects[i].x() + rects[i].width() == rects[j].x()) {
            rects[i].set_width(rects[i].width() + rects[j].width());
            rects[j] = gfx::Rect();
            updated = true;
          } else if (rects[i].x() == rects[j].x() + rects[j].width()) {
            rects[i].set_x(rects[j].x());
            rects[i].set_width(rects[i].width() + rects[j].width());
            rects[j] = gfx::Rect();
            updated = true;
          }
        } else if (rects[i].x() == rects[j].x() &&
                   rects[i].width() == rects[j].width()) {
          if (rects[i].y() + rects[i].height() == rects[j].y()) {
            rects[i].set_height(rects[i].height() + rects[j].height());
            rects[j] = gfx::Rect();
            updated = true;
          } else if (rects[i].y() == rects[j].y() + rects[j].height()) {
            rects[i].set_y(rects[j].y());
            rects[i].set_height(rects[i].height() + rects[j].height());
            rects[j] = gfx::Rect();
            updated = true;
          }
        }
      }
    } while (updated);
  }
}

HitTestLayerRectList* Internals::touchEventTargetLayerRects(
    Document* document,
    ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->View() || !document->GetPage() || document != document_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return nullptr;
  }

  document->View()->UpdateAllLifecyclePhasesForTest();

  auto* hit_test_rects = MakeGarbageCollected<HitTestLayerRectList>();
  if (!document->View()->RootCcLayer()) {
    return hit_test_rects;
  }
  for (const auto& layer : document->View()->RootCcLayer()->children()) {
    const cc::TouchActionRegion& touch_action_region =
        layer->touch_action_region();
    if (!touch_action_region.GetAllRegions().IsEmpty()) {
      const auto& offset = layer->offset_to_transform_parent();
      gfx::Rect layer_rect(
          gfx::ToRoundedPoint(gfx::PointAtOffsetFromOrigin(offset)),
          layer->bounds());

      Vector<gfx::Rect> layer_hit_test_rects;
      for (auto hit_test_rect : touch_action_region.GetAllRegions())
        layer_hit_test_rects.push_back(hit_test_rect);
      MergeRects(layer_hit_test_rects);

      for (const gfx::Rect& hit_test_rect : layer_hit_test_rects) {
        if (!hit_test_rect.IsEmpty()) {
          hit_test_rects->Append(DOMRectReadOnly::FromRect(layer_rect),
                                 DOMRectReadOnly::FromRect(hit_test_rect));
        }
      }
    }
  }
  return hit_test_rects;
}

bool Internals::executeCommand(Document* document,
                               const String& name,
                               const String& value,
                               ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return false;
  }

  LocalFrame* frame = document->GetFrame();
  return frame->GetEditor().ExecuteCommand(name, value);
}

void Internals::triggerTestInspectorIssue(Document* document) {
  DCHECK(document);
  auto info = mojom::blink::InspectorIssueInfo::New(
      mojom::InspectorIssueCode::kCookieIssue,
      mojom::blink::InspectorIssueDetails::New());
  document->GetFrame()->AddInspectorIssue(
      AuditsIssue(ConvertInspectorIssueToProtocolFormat(
          InspectorIssue::Create(std::move(info)))));
}

AtomicString Internals::htmlNamespace() {
  return html_names::xhtmlNamespaceURI;
}

Vector<AtomicString> Internals::htmlTags() {
  Vector<AtomicString> tags(html_names::kTagsCount);
  std::unique_ptr<const HTMLQualifiedName*[]> qualified_names =
      html_names::GetTags();
  for (wtf_size_t i = 0; i < html_names::kTagsCount; ++i)
    tags[i] = qualified_names[i]->LocalName();
  return tags;
}

AtomicString Internals::svgNamespace() {
  return svg_names::kNamespaceURI;
}

Vector<AtomicString> Internals::svgTags() {
  Vector<AtomicString> tags(svg_names::kTagsCount);
  std::unique_ptr<const SVGQualifiedName*[]> qualified_names =
      svg_names::GetTags();
  for (wtf_size_t i = 0; i < svg_names::kTagsCount; ++i)
    tags[i] = qualified_names[i]->LocalName();
  return tags;
}

StaticNodeList* Internals::nodesFromRect(
    ScriptState* script_state,
    Document* document,
    int x,
    int y,
    int width,
    int height,
    bool ignore_clipping,
    bool allow_child_frame_content,
    ExceptionState& exception_state) const {
  DCHECK(document);
  if (!document->GetFrame() || !document->GetFrame()->View()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No view can be obtained from the provided document.");
    return nullptr;
  }

  HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kReadOnly |
                                                HitTestRequest::kActive |
                                                HitTestRequest::kListBased;
  LocalFrame* frame = document->GetFrame();
  PhysicalRect rect{LayoutUnit(x), LayoutUnit(y), LayoutUnit(width),
                    LayoutUnit(height)};
  if (ignore_clipping) {
    hit_type |= HitTestRequest::kIgnoreClipping;
  } else if (!gfx::Rect(gfx::Point(), frame->View()->Size())
                  .Intersects(ToEnclosingRect(rect))) {
    return nullptr;
  }
  if (allow_child_frame_content)
    hit_type |= HitTestRequest::kAllowChildFrameContent;

  HitTestRequest request(hit_type);
  HitTestLocation location(rect);
  HitTestResult result(request, location);
  frame->ContentLayoutObject()->HitTest(location, result);
  HeapVector<Member<Node>> matches(result.ListBasedTestResult());

  // Ensure WindowProxy instances for child frames. crbug.com/1407555.
  for (auto& node : matches) {
    if (node->IsDocumentNode() && node.Get() != document) {
      node->GetDocument().GetFrame()->GetWindowProxy(script_state->World());
    }
  }

  return StaticNodeList::Adopt(matches);
}

bool Internals::hasSpellingMarker(Document* document,
                                  int from,
                                  int length,
                                  ExceptionState& exception_state) {
  if (!document || !document->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No frame can be obtained from the provided document.");
    return false;
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  return document->GetFrame()->GetSpellChecker().SelectionStartHasMarkerFor(
      DocumentMarker::kSpelling, from, length);
}

void Internals::replaceMisspelled(Document* document,
                                  const String& replacement,
                                  ExceptionState& exception_state) {
  if (!document || !document->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No frame can be obtained from the provided document.");
    return;
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  document->GetFrame()->GetSpellChecker().ReplaceMisspelledRange(replacement);
}

bool Internals::canHyphenate(const AtomicString& locale) {
  return LayoutLocale::ValueOrDefault(LayoutLocale::Get(locale))
      .GetHyphenation();
}

void Internals::setMockHyphenation(const AtomicString& locale) {
  LayoutLocale::SetHyphenationForTesting(locale, MockHyphenation::Create());
}

unsigned Internals::numberOfLiveNodes() const {
  return InstanceCounters::CounterValue(InstanceCounters::kNodeCounter);
}

unsigned Internals::numberOfLiveDocuments() const {
  return InstanceCounters::CounterValue(InstanceCounters::kDocumentCounter);
}

bool Internals::hasGrammarMarker(Document* document,
                                 int from,
                                 int length,
                                 ExceptionState& exception_state) {
  if (!document || !document->GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "No frame can be obtained from the provided document.");
    return false;
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  return document->GetFrame()->GetSpellChecker().SelectionStartHasMarkerFor(
      DocumentMarker::kGrammar, from, length);
}

unsigned Internals::numberOfScrollableAreas(Document* document) {
  DCHECK(document);
  if (!document->GetFrame())
    return 0;

  unsigned count = 0;
  LocalFrame* frame = document->GetFrame();
  for (const auto& scrollable_area :
       frame->View()->ScrollableAreas().Values()) {
    if (scrollable_area->ScrollsOverflow()) {
      count++;
    }
  }

  for (Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    auto* child_local_frame = DynamicTo<LocalFrame>(child);
    if (child_local_frame && child_local_frame->View()) {
      for (const auto& scrollable_area :
           child_local_frame->View()->ScrollableAreas().Values()) {
        if (scrollable_area->ScrollsOverflow())
          count++;
      }
    }
  }

  return count;
}

String Internals::layerTreeAsText(Document* document,
                                  ExceptionState& exception_state) const {
  return layerTreeAsText(document, 0, exception_state);
}

String Internals::layerTreeAsText(Document* document,
                                  unsigned flags,
                                  ExceptionState& exception_state) const {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return String();
  }

  document->View()->UpdateAllLifecyclePhasesForTest();

  return document->GetFrame()->GetLayerTreeAsTextForTesting(flags);
}

String Internals::mainThreadScrollingReasons(
    Document* document,
    ExceptionState& exception_state) const {
  DCHECK(document);
  if (!document->GetFrame()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return String();
  }

  document->GetFrame()->View()->UpdateAllLifecyclePhasesForTest();

  return document->GetFrame()->View()->MainThreadScrollingReasonsAsText();
}

void Internals::evictAllResources() const {
  MemoryCache::Get()->EvictResources();
}

String Internals::counterValue(Element* element) {
  if (!element)
    return String();

  return CounterValueForElement(element);
}

int Internals::pageNumber(Element* element,
                          float page_width,
                          float page_height,
                          ExceptionState& exception_state) {
  if (!element)
    return 0;

  if (page_width <= 0 || page_height <= 0) {
    exception_state.ThrowTypeError(
        "Page width and height must be larger than 0.");
    return 0;
  }

  return PrintContext::PageNumberForElement(
      element, gfx::SizeF(page_width, page_height));
}

Vector<String> Internals::IconURLs(Document* document,
                                   int icon_types_mask) const {
  Vector<IconURL> icon_urls = document->IconURLs(icon_types_mask);
  Vector<String> array;

  for (auto& icon_url : icon_urls)
    array.push_back(icon_url.icon_url_.GetString());

  return array;
}

Vector<String> Internals::shortcutIconURLs(Document* document) const {
  int icon_types_mask =
      1 << static_cast<int>(mojom::blink::FaviconIconType::kFavicon);
  return IconURLs(document, icon_types_mask);
}


"""


```
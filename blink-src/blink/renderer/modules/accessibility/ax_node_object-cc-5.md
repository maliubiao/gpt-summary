Response:
The user wants to understand the functionality of the provided C++ code snippet from `ax_node_object.cc`. I need to break down the code, explain its purpose, identify its relationships with web technologies (JavaScript, HTML, CSS), provide examples of logic flow, discuss potential user/programmer errors, describe how a user's action might lead to this code being executed, and finally, summarize the overall function of the excerpt.

**Plan:**

1. **Functionality Breakdown:** Analyze each function (`GetNearestBlockFlow`, `IsInSameBlockFlow`, `OnNativeSetSelectedAction`, `OnNativeSetValueAction`, `GetName`, `TextAlternative`, `ShouldInsertSpaceBetweenObjectsIfNeeded`, `TextFromDescendants`, `IsNameFromLabelElement`, `IsRedundantLabel`, `GetRelativeBounds`, `HasValidHTMLTableStructureAndLayout`, `AddTableChildren`, `TextOffsetInFormattingContext`).
2. **Web Technology Relationships:** For each function, consider its interaction with HTML elements, CSS styling, and potential JavaScript interactions.
3. **Logic Inference Examples:**  For functions with conditional logic, create hypothetical inputs and expected outputs.
4. **User/Programmer Error Examples:** Identify common mistakes related to the functionality of these methods.
5. **User Operation to Code Execution:** Trace a potential user interaction back to the execution of these code segments.
6. **Summary:** Concisely summarize the core responsibility of this code within the accessibility framework.
这是 `blink/renderer/modules/accessibility/ax_node_object.cc` 文件代码片段的第 6 部分，主要涉及以下功能：

**核心功能归纳:**

* **辅助功能树 (Accessibility Tree) 的节点对象操作:**  这段代码定义了 `AXNodeObject` 类的一些方法，用于处理辅助功能树中节点对象的特定操作，例如设置选中状态、设置值、计算名称、获取文本替代等。
* **与渲染树 (Layout Tree) 的交互:**  代码片段中大量使用了 `LayoutObject` 和 `LayoutBlockFlow` 等类，表明它在辅助功能层与渲染层之间存在紧密的联系，用于确定元素在页面上的布局和渲染信息，并将其用于辅助功能计算。
* **处理 HTML 元素特性:**  代码中检查和操作了各种 HTML 元素的属性和状态，例如 `HTMLOptionElement` 的 `selected` 状态，`HTMLInputElement` 和 `HTMLTextAreaElement` 的 `value` 属性，以及 `contenteditable` 属性等。
* **计算可访问名称 (Accessible Name):**  `GetName` 和 `TextAlternative` 方法的核心职责是根据 W3C 的可访问名称计算规范 (AccName) 来确定元素的辅助功能名称，这涉及到多种来源的考虑，包括元素的文本内容、属性 (例如 `aria-label`, `title`)、以及子元素的内容。
* **处理文本内容和空格:**  `ShouldInsertSpaceBetweenObjectsIfNeeded` 和 `TextFromDescendants` 方法用于处理如何从元素的后代中提取文本内容，并决定在不同的元素之间是否需要插入空格，以生成更易于理解的辅助功能文本。
* **处理表格的辅助功能:** `HasValidHTMLTableStructureAndLayout` 和 `AddTableChildren` 涉及如何判断 HTML 表格的结构是否有效，以及如何按照渲染顺序添加表格的子元素到辅助功能树中。
* **获取元素边界:** `GetRelativeBounds` 用于获取元素相对于其容器的边界信息，这对于辅助技术（例如屏幕阅读器）定位页面元素非常重要。
* **计算文本偏移:** `TextOffsetInFormattingContext` 用于计算文本在其格式化上下文中的偏移量，这在处理文本光标位置和范围时很有用。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **HTML:**
   * **元素属性:** `OnNativeSetSelectedAction` 检查 `HTMLOptionElement`，并获取其所属的 `HTMLSelectElement`，这直接关联到 HTML `<option>` 和 `<select>` 元素及其 `selected` 属性。
     * **示例:** HTML 中 `<select><option value="1">Option 1</option></select>`，JavaScript 可以通过设置 option 元素的 `selected` 属性来改变选项，或者辅助技术可以通过 `OnNativeSetSelectedAction` 来模拟用户的选择操作。
   * **表单元素:** `OnNativeSetValueAction` 处理 `HTMLInputElement` 和 `HTMLTextAreaElement` 的值设置，这直接对应 HTML 的 `<input>` 和 `<textarea>` 元素。
     * **示例:** HTML 中 `<input type="text" id="name">`，JavaScript 可以通过 `document.getElementById('name').value = 'John';` 来设置输入框的值，或者辅助技术可以通过 `OnNativeSetValueAction` 来模拟用户输入。
   * **富文本编辑:** `OnNativeSetValueAction` 也处理带有 `contenteditable` 属性的 HTML 元素。
     * **示例:** HTML 中 `<div contenteditable="true">编辑内容</div>`，用户可以直接编辑 div 中的内容，或者辅助技术可以通过 `OnNativeSetValueAction` 来修改其文本。
   * **标签关联:** `IsNameFromLabelElement` 检查 `<label>` 元素与表单控件的关联 (通过 `for` 属性或嵌套关系)，这直接影响到控件的可访问名称。
     * **示例:** HTML 中 `<label for="email">Email:</label><input type="email" id="email">`，`IsNameFromLabelElement` 会判断 `input` 元素的名称是否来源于关联的 `label`。
   * **表格结构:** `HasValidHTMLTableStructureAndLayout` 检查 `<table>`, `<thead>`, `<tbody>`, `<tfoot>`, `<caption>` 等表格相关元素的结构。
     * **示例:** 如果 HTML 表格结构不符合规范（例如，`<td>` 直接作为 `<table>` 的子元素），`HasValidHTMLTableStructureAndLayout` 将返回 `false`。

2. **CSS:**
   * **可见性:** `IsRedundantLabel` 中检查 `input->GetLayoutObject()->Style()->Visibility() != EVisibility::kVisible`，这意味着 CSS 的 `visibility` 属性会影响标签是否被认为是冗余的。
   * **`display` 属性:** `ShouldInsertSpaceBetweenObjectsIfNeeded` 中考虑了 `display: inline-block`, `display: inline-flex` 等属性对元素间空格的影响。
     * **示例:**  CSS 中设置 `span { display: inline-block; }` 会导致 `ShouldInsertSpaceBetweenObjectsIfNeeded` 在两个相邻的 `span` 元素之间插入空格。
   * **CSS 伪元素和文本渲染:** `TextOffsetInFormattingContext` 提到了 "first-letter CSS style"，这涉及到 CSS 伪元素 `:first-letter` 对文本布局的影响。
   * **`alt` 属性:** `TextAlternative` 方法中提到了 `GetCSSAltText(GetElement())`，这与 `<img>` 元素的 `alt` 属性相关，它作为图像的文本替代。

3. **JavaScript:**
   * **事件触发:** `OnNativeSetSelectedAction` 和 `OnNativeSetValueAction` 的执行可能会触发 JavaScript 事件，例如 `change` 和 `input` 事件。
     * **示例:** 当辅助技术调用 `OnNativeSetValueAction` 修改输入框的值时，会触发输入框的 `input` 和 `change` 事件，JavaScript 可以监听这些事件并执行相应的操作。
   * **DOM 操作:** JavaScript 可以动态地创建、修改和删除 HTML 元素，这些操作会影响到辅助功能树的结构和内容，最终会影响到这里代码的执行。
   * **ARIA 属性:** `TextAlternative` 方法会考虑 ARIA 属性（例如 `aria-label`, `aria-labelledby`），这些属性通常由 JavaScript 动态添加或修改。

**逻辑推理的假设输入与输出:**

**例子 1: `IsInSameBlockFlow`**

* **假设输入 1:** 两个 `LayoutObject` 指针，分别指向同一个 `div` 元素内的两个 `span` 元素。
* **预期输出 1:** `true` (因为它们在同一个 `LayoutBlockFlow` 中)。

* **假设输入 2:** 两个 `LayoutObject` 指针，分别指向两个相邻的 `div` 元素内的 `span` 元素。
* **预期输出 2:** `false` (因为它们在不同的 `LayoutBlockFlow` 中)。

**例子 2: `OnNativeSetSelectedAction`**

* **假设输入:** `selected = true`，`AXNodeObject` 对象对应一个未选中的 `<option>` 元素。
* **预期输出:** `true` (成功设置了选项为选中状态)。

* **假设输入:** `selected = true`，`AXNodeObject` 对象对应一个已经选中的 `<option>` 元素。
* **预期输出:** `false` (因为状态没有改变)。

**例子 3: `ShouldInsertSpaceBetweenObjectsIfNeeded`**

* **假设输入 1:** `previous` 指向一个 `<span>Hello</span>` 的 `AXObject`，`next` 指向一个 `<span>World</span>` 的 `AXObject`，它们在同一个 `div` 中。
* **预期输出 1:** `false` (默认情况下，内联元素之间不需要额外空格)。

* **假设输入 2:** `previous` 指向一个 `<div>Hello</div>` 的 `AXObject`，`next` 指向一个 `<div>World</div>` 的 `AXObject`。
* **预期输出 2:** `true` (块级元素之间需要插入空格)。

**用户或编程常见的使用错误及举例说明:**

1. **错误地设置 ARIA 属性:**  开发者可能错误地使用了 ARIA 属性，导致辅助技术无法正确获取元素的名称或角色。例如，在一个不需要交互的元素上使用了 `aria-pressed="true"`。
2. **忽略 `alt` 属性:**  在 `<img>` 元素中缺少 `alt` 属性或者 `alt` 属性为空但图像并非纯装饰性，这会导致辅助技术用户无法理解图像的内容。
3. **不正确的表格结构:**  HTML 表格结构不符合规范，例如 `<td>` 元素直接作为 `<table>` 的子元素，这会导致辅助技术解析表格时出现问题。
4. **过度使用 `aria-hidden`:**  开发者可能错误地使用 `aria-hidden="true"` 隐藏了重要的内容，导致辅助技术用户无法访问这些内容。
5. **动态更新后未更新辅助功能树:**  JavaScript 动态修改 DOM 结构或内容后，可能没有正确触发辅助功能树的更新，导致辅助技术获取的是过时的信息.

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户使用屏幕阅读器与一个包含 `<select>` 元素的网页进行交互：

1. **用户焦点移动到 `<select>` 元素:** 屏幕阅读器会将焦点移动到该元素，并读取其可访问名称。
2. **用户展开 `<select>` 列表:** 用户可能会按下空格键或回车键来展开下拉列表。
3. **用户导航到某个 `<option>` 元素:** 用户使用上下箭头键在下拉列表中导航。
4. **用户选择某个 `<option>` 元素:** 用户按下回车键或点击鼠标来选择一个选项。
5. **辅助功能 API 调用:** 用户的选择操作会被屏幕阅读器捕获，并可能通过操作系统或浏览器提供的辅助功能 API 传递给浏览器内核。
6. **Blink 接收辅助功能事件:** Blink 的辅助功能模块接收到这个“设置选中状态”的事件。
7. **调用 `OnNativeSetSelectedAction`:**  Blink 的辅助功能代码会找到对应的 `AXNodeObject` (代表被选中的 `<option>` 元素)，并调用其 `OnNativeSetSelectedAction` 方法，传入 `selected = true`。
8. **代码执行:** `OnNativeSetSelectedAction` 方法会执行相应的逻辑，找到 `HTMLOptionElement` 和 `HTMLSelectElement`，并更新选项的选中状态。
9. **触发 DOM 事件和辅助功能事件:**  选项状态的改变可能会触发 `change` 事件，并且 Blink 会更新辅助功能树，通知屏幕阅读器状态已改变。

在调试过程中，如果发现辅助功能行为异常，例如屏幕阅读器没有正确播报选中的选项，开发者可以检查 `OnNativeSetSelectedAction` 方法的执行过程，查看是否正确地找到了对应的 HTML 元素，以及是否正确地更新了选中状态。

总而言之，这段代码是 Chromium Blink 引擎中负责处理辅助功能的核心部分，它将渲染树的信息转化为辅助功能树可以理解的结构和属性，并响应辅助技术的操作请求，从而使网页内容能够被辅助技术用户访问。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共10部分，请归纳一下它的功能

"""
* current = object;
  while (current) {
    if (auto* block_flow = DynamicTo<LayoutBlockFlow>(current)) {
      return block_flow;
    }
    current = current->Parent();
  }

  NOTREACHED();
}

// Returns true if |r1| and |r2| are both non-null, both inline, and are
// contained within the same LayoutBlockFlow.
static bool IsInSameBlockFlow(LayoutObject* r1, LayoutObject* r2) {
  if (!r1 || !r2)
    return false;
  if (!r1->IsInline() || !r2->IsInline())
    return false;
  LayoutBlockFlow* b1 = GetNearestBlockFlow(r1);
  LayoutBlockFlow* b2 = GetNearestBlockFlow(r2);
  return b1 && b2 && b1 == b2;
}

//
// Modify or take an action on an object.
//

bool AXNodeObject::OnNativeSetSelectedAction(bool selected) {
  auto* option = DynamicTo<HTMLOptionElement>(GetNode());
  if (!option) {
    return false;
  }

  HTMLSelectElement* select_element = option->OwnerSelectElement();
  if (!select_element) {
    return false;
  }

  if (!CanSetSelectedAttribute()) {
    return false;
  }

  AccessibilitySelectedState is_option_selected = IsSelected();
  if (is_option_selected == kSelectedStateUndefined) {
    return false;
  }

  bool is_selected = (is_option_selected == kSelectedStateTrue) ? true : false;
  if ((is_selected && selected) || (!is_selected && !selected)) {
    return false;
  }

  select_element->SelectOptionByAccessKey(To<HTMLOptionElement>(GetNode()));
  return true;
}

bool AXNodeObject::OnNativeSetValueAction(const String& string) {
  if (!GetNode() || !GetNode()->IsElementNode())
    return false;
  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object || !layout_object->IsBoxModelObject())
    return false;

  auto* html_input_element = DynamicTo<HTMLInputElement>(*GetNode());
  if (html_input_element && layout_object->IsTextField()) {
    html_input_element->SetValue(
        string, TextFieldEventBehavior::kDispatchInputAndChangeEvent);
    return true;
  }

  if (auto* text_area_element = DynamicTo<HTMLTextAreaElement>(*GetNode())) {
    DCHECK(layout_object->IsTextArea());
    text_area_element->SetValue(
        string, TextFieldEventBehavior::kDispatchInputAndChangeEvent);
    return true;
  }

  if (HasContentEditableAttributeSet()) {
    To<HTMLElement>(GetNode())->setInnerText(string);
    return true;
  }

  return false;
}

//
// New AX name calculation.
//

String AXNodeObject::GetName(ax::mojom::blink::NameFrom& name_from,
                             AXObjectVector* name_objects) const {
  String name = AXObject::GetName(name_from, name_objects);
  if (RoleValue() == ax::mojom::blink::Role::kSpinButton &&
      DatetimeAncestor()) {
    // Fields inside a datetime control need to merge the field name with
    // the name of the <input> element.
    name_objects->clear();
    String input_name = DatetimeAncestor()->GetName(name_from, name_objects);
    if (!input_name.empty())
      return name + " " + input_name;
  }

  return name;
}

String AXNodeObject::TextAlternative(
    bool recursive,
    const AXObject* aria_label_or_description_root,
    AXObjectSet& visited,
    ax::mojom::blink::NameFrom& name_from,
    AXRelatedObjectVector* related_objects,
    NameSources* name_sources) const {
  // If nameSources is non-null, relatedObjects is used in filling it in, so it
  // must be non-null as well.
  DCHECK(!name_sources || related_objects);

  bool found_text_alternative = false;
  Node* node = GetNode();

  name_from = ax::mojom::blink::NameFrom::kNone;
  if (!node && !GetLayoutObject()) {
    return String();
  }

  if (IsA<HTMLSlotElement>(node) && node->IsInUserAgentShadowRoot() &&
      !recursive) {
    // User agent slots do not have their own name, but their subtrees can
    // contribute to ancestor names (where recursive == true).
    return String();
  }

  if (GetLayoutObject()) {
    std::optional<String> text_alternative = GetCSSAltText(GetElement());
    if (text_alternative) {
      name_from = ax::mojom::blink::NameFrom::kCssAltText;
      if (name_sources) {
        name_sources->push_back(NameSource(false));
        name_sources->back().type = name_from;
        name_sources->back().text = text_alternative.value();
      }
      return text_alternative.value();
    }
    if (GetLayoutObject()->IsBR()) {
      text_alternative = String("\n");
      found_text_alternative = true;
    } else if (GetLayoutObject()->IsText() &&
               (!recursive || !GetLayoutObject()->IsCounter())) {
      auto* layout_text = To<LayoutText>(GetLayoutObject());
      String visible_text = layout_text->PlainText();  // Actual rendered text.
      // If no text boxes we assume this is unrendered end-of-line whitespace.
      // TODO find robust way to deterministically detect end-of-line space.
      if (visible_text.empty()) {
        // No visible rendered text -- must be whitespace.
        // Either it is useful whitespace for separating words or not.
        if (layout_text->IsAllCollapsibleWhitespace()) {
          if (IsIgnored()) {
            return "";
          }
          // If no textboxes, this was whitespace at the line's end.
          text_alternative = " ";
        } else {
          text_alternative = layout_text->TransformedText();
        }
      } else {
        text_alternative = visible_text;
      }
      found_text_alternative = true;
    } else if (!recursive) {
      if (ListMarker* marker = ListMarker::Get(GetLayoutObject())) {
        text_alternative = marker->TextAlternative(*GetLayoutObject());
        found_text_alternative = true;
      }
    }

    if (found_text_alternative) {
      name_from = ax::mojom::blink::NameFrom::kContents;
      if (name_sources) {
        name_sources->push_back(NameSource(false));
        name_sources->back().type = name_from;
        name_sources->back().text = text_alternative.value();
      }
      // Ensure that text nodes count toward
      // kMaxDescendantsForTextAlternativeComputation when calculating the name
      // for their direct parent (see AXNodeObject::TextFromDescendants).
      visited.insert(this);
      return text_alternative.value();
    }
  }

  // Step 2E from: http://www.w3.org/TR/accname-aam-1.1 -- value from control.
  // This must occur before 2C, because 2C is not applied if 2E will be:
  // 2C: "If traversal of the current node is due to recursion and the current
  // node is an embedded control as defined in step 2E, ignore aria-label and
  // skip to rule 2E".
  // Note that 2E only applies the label is for "another widget", therefore, the
  // value cannot be used to label the original control, even if aria-labelledby
  // points to itself. The easiest way to check this is by testing whether this
  // node has already been visited.
  if (recursive && !visited.Contains(this)) {
    String value_for_name = GetValueContributionToName(visited);
    // TODO(accessibility): Consider using `empty` check instead of `IsNull`.
    if (!value_for_name.IsNull()) {
      name_from = ax::mojom::blink::NameFrom::kValue;
      if (name_sources) {
        name_sources->push_back(NameSource(false));
        name_sources->back().type = ax::mojom::blink::NameFrom::kValue;
        name_sources->back().text = value_for_name;
      }
      return value_for_name;
    }
  }

  // Step 2C from: http://www.w3.org/TR/accname-aam-1.1 -- aria-label.
  String text_alternative = AriaTextAlternative(
      recursive, aria_label_or_description_root, visited, name_from,
      related_objects, name_sources, &found_text_alternative);
  if (found_text_alternative && !name_sources)
    return MaybeAppendFileDescriptionToName(text_alternative);

  // Step 2D from: http://www.w3.org/TR/accname-aam-1.1  -- native markup.
  text_alternative =
      NativeTextAlternative(visited, name_from, related_objects, name_sources,
                            &found_text_alternative);
  // An explicitly empty native text alternative can still be overridden if a
  // viable text alternative is found later in the search, so remember that it
  // was explicitly empty here but don't terminate the search yet unless we
  // already found something non-empty.
  const bool has_explicitly_empty_native_text_alternative =
      text_alternative.empty() &&
      name_from == ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty;
  if (!text_alternative.empty() && !name_sources) {
    return MaybeAppendFileDescriptionToName(text_alternative);
  }

  // Step 2F / 2G from: http://www.w3.org/TR/accname-aam-1.1 -- from content.
  if (ShouldIncludeContentInTextAlternative(
          recursive, aria_label_or_description_root, visited)) {
    name_from = ax::mojom::blink::NameFrom::kContents;
    if (name_sources) {
      name_sources->push_back(NameSource(found_text_alternative));
      name_sources->back().type = name_from;
    }

    if (auto* text_node = DynamicTo<Text>(node)) {
      text_alternative = text_node->data();
    } else if (IsA<HTMLBRElement>(node)) {
      text_alternative = String("\n");
    } else {
      text_alternative =
          TextFromDescendants(visited, aria_label_or_description_root, false);
    }

    if (!text_alternative.empty()) {
      if (name_sources) {
        found_text_alternative = true;
        name_sources->back().text = text_alternative;
      } else {
        return MaybeAppendFileDescriptionToName(text_alternative);
      }
    }
  }

  // Step 2I from: http://www.w3.org/TR/accname-aam-1.1
  // Use the tooltip text for the name if there was no other accessible name.
  // However, it does not make sense to do this if the object has a role
  // that prohibits name as specified in
  // https://w3c.github.io/aria/#namefromprohibited.
  // Preventing the tooltip for being used in the name causes it to be used for
  // the description instead.
  // This complies with https://w3c.github.io/html-aam/#att-title, which says
  // how to expose a title: "Either the accessible name, or the accessible
  // description, or Not mapped". There's nothing in HTML-AAM that explicitly
  // forbids this, and it seems reasonable for authors to use a tooltip on any
  // visible element without causing an accessibility error or user problem.
  // Note: if this is part of another label or description, it needs to be
  // computed as a name, in order to contribute to that.
  if (aria_label_or_description_root || !IsNameProhibited()) {
    String resulting_text = TextAlternativeFromTooltip(
        name_from, name_sources, &found_text_alternative, &text_alternative,
        related_objects);
    if (!resulting_text.empty()) {
      if (name_sources) {
        text_alternative = resulting_text;
      } else {
        return resulting_text;
      }
    }
  }

  String saved_text_alternative = GetSavedTextAlternativeFromNameSource(
      found_text_alternative, name_from, related_objects, name_sources);
  if (!saved_text_alternative.empty()) {
    return saved_text_alternative;
  }

  if (has_explicitly_empty_native_text_alternative) {
    // If the native text alternative is explicitly empty and we
    // never found another text alternative, then set name_source
    // to reflect the fact that there was an explicitly empty text
    // alternative. This is important because an empty `alt` attribute on an
    // <img> can be used to indicate that the image is presentational and should
    // be ignored by ATs.
    name_from = ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty;
  }

  return String();
}

static bool ShouldInsertSpaceBetweenObjectsIfNeeded(
    AXObject* previous,
    AXObject* next,
    ax::mojom::blink::NameFrom last_used_name_from,
    ax::mojom::blink::NameFrom name_from) {
  LayoutObject* next_layout = next->GetLayoutObject();
  LayoutObject* prev_layout = previous->GetLayoutObject();

  // If we're going between two LayoutObjects that are in separate
  // LayoutBoxes, add whitespace if it wasn't there already. Intuitively if
  // you have <span>Hello</span><span>World</span>, those are part of the same
  // LayoutBox so we should return "HelloWorld", but given
  // <div>Hello</div><div>World</div> the strings are in separate boxes so we
  // should return "Hello World".
  // https://www.w3.org/TR/css-display-3/#the-display-properties
  if (!IsInSameBlockFlow(next_layout, prev_layout)) {
    return true;
  }

  // Even if we are in the same block flow, let's make sure to add whitespace
  // if the layout objects define new formatting contexts for their children,
  // as is the case with the inline-* family of display properties.
  // So we want the following:
  //    <span style="display:inline-block;">Hello</span><span>World</span>
  //    <span style="display:inline-flex;">Hello</span><span>World</span>
  //    <span style="display:inline-grid;">Hello</span><span>World</span>
  //    <span style="display:inline-table;">Hello</span><span>World</span>
  // to return "Hello World". See "inner display type" in the CSS Display 3.0
  // spec: https://www.w3.org/TR/css-display-3/#the-display-properties
  CHECK(next_layout);
  CHECK(prev_layout);
  if (next_layout->IsAtomicInlineLevel() ||
      prev_layout->IsAtomicInlineLevel()) {
    return true;
  }

  // Even if it is in the same inline block flow, if we are using a text
  // alternative such as an ARIA label or HTML title, we should separate
  // the strings. Doing so is consistent with what is stated in the AccName
  // spec and with what is done in other user agents.
  switch (last_used_name_from) {
    case ax::mojom::blink::NameFrom::kNone:
    case ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty:
    case ax::mojom::blink::NameFrom::kContents:
    case ax::mojom::blink::NameFrom::kProhibited:
    case ax::mojom::blink::NameFrom::kProhibitedAndRedundant:
      break;
    case ax::mojom::blink::NameFrom::kAttribute:
    case ax::mojom::blink::NameFrom::kCaption:
    case ax::mojom::blink::NameFrom::kCssAltText:
    case ax::mojom::blink::NameFrom::kInterestTarget:
    case ax::mojom::blink::NameFrom::kPlaceholder:
    case ax::mojom::blink::NameFrom::kRelatedElement:
    case ax::mojom::blink::NameFrom::kTitle:
    case ax::mojom::blink::NameFrom::kValue:
    case ax::mojom::blink::NameFrom::kPopoverTarget:
      return true;
  }
  switch (name_from) {
    case ax::mojom::blink::NameFrom::kNone:
    case ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty:
    case ax::mojom::blink::NameFrom::kContents:
    case ax::mojom::blink::NameFrom::kProhibited:
    case ax::mojom::blink::NameFrom::kProhibitedAndRedundant:
      break;
    case ax::mojom::blink::NameFrom::kAttribute:
    case ax::mojom::blink::NameFrom::kCaption:
    case ax::mojom::blink::NameFrom::kCssAltText:
    case ax::mojom::blink::NameFrom::kInterestTarget:
    case ax::mojom::blink::NameFrom::kPlaceholder:
    case ax::mojom::blink::NameFrom::kRelatedElement:
    case ax::mojom::blink::NameFrom::kTitle:
    case ax::mojom::blink::NameFrom::kValue:
    case ax::mojom::blink::NameFrom::kPopoverTarget:
      return true;
  }

  // According to the AccName spec, we need to separate controls from text nodes
  // using a space.
  if (previous->IsControl() || next->IsControl())
    return true;

  // When |previous| and |next| are in same inline formatting context, we
  // may have block-in-inline between |previous| and |next|.
  // For <div>abc<p aria-hidden=true>...</p>def</div>, we have following
  // layout tree:
  //    LayoutBlockFlow {DIV}, children are inline
  //      LayoutText "abc"  <= previous
  //      LayoutBlockFlow (anonymous) block-in-inline wrapper
  //        LayoutBlockFlow {P}
  //          ...
  //      LayoutText "def" <= next
  // When block-in-inline disabled, layout tree is:
  //    LayoutBlockFlow {DIV}, children are block
  //      LayoutBlockFlow (anonymous)
  //        LayoutText "abc"  <= previous
  //      LayoutBlockFlow (anonymous) block-in-inline wrapper
  //        LayoutBlockFlow {P}
  //          ...
  //      LayoutBlockFlow (anonymous)
  //        LayoutText "def" <= next
  // See accessibility/name-calc-aria-hidden.html
  for (auto* layout_object = previous->GetLayoutObject();
       layout_object && layout_object != next_layout;
       layout_object = layout_object->NextInPreOrder()) {
    if (layout_object->IsBlockInInline())
      return true;
  }
  return false;
}

String AXNodeObject::TextFromDescendants(
    AXObjectSet& visited,
    const AXObject* aria_label_or_description_root,
    bool recursive) const {
  if (!CanHaveChildren()) {
    return recursive || !GetElement()
               ? String()
               : GetElement()->GetInnerTextWithoutUpdate();
  }

  StringBuilder accumulated_text;
  AXObject* previous = nullptr;
  ax::mojom::blink::NameFrom last_used_name_from =
      ax::mojom::blink::NameFrom::kNone;

  CHECK(!NeedsToUpdateCachedValues());

  const AXObjectVector& children = ChildrenIncludingIgnored();
#if defined(AX_FAIL_FAST_BUILD)
  base::AutoReset<bool> auto_reset(&is_computing_text_from_descendants_, true);
#endif
  wtf_size_t num_children = children.size();
  for (wtf_size_t index = 0; index < num_children; index++) {
    DCHECK_EQ(children.size(), num_children);
    if (index >= children.size()) {
      // TODO(accessibility) Remove this condition once we solve all causes of
      // the child list being altered during this loop.
      break;
    }
    AXObject* child = children[index];
    DCHECK(child);
    DCHECK(!child->IsDetached()) << child;
    constexpr size_t kMaxDescendantsForTextAlternativeComputation = 100;
    if (visited.size() > kMaxDescendantsForTextAlternativeComputation)
      break;

    if (child->IsHiddenForTextAlternativeCalculation(
            aria_label_or_description_root)) {
      continue;
    }

    ax::mojom::blink::NameFrom child_name_from =
        ax::mojom::blink::NameFrom::kNone;
    String result;
    if (child->IsPresentational()) {
      result = child->TextFromDescendants(visited,
                                          aria_label_or_description_root, true);
    } else {
      result = RecursiveTextAlternative(*child, aria_label_or_description_root,
                                        visited, child_name_from);
    }

    if (!result.empty() && previous && accumulated_text.length() &&
        !IsHTMLSpace(accumulated_text[accumulated_text.length() - 1]) &&
        !IsHTMLSpace(result[0])) {
      if (ShouldInsertSpaceBetweenObjectsIfNeeded(
              previous, child, last_used_name_from, child_name_from)) {
        accumulated_text.Append(' ');
      }
    }

    accumulated_text.Append(result);

    // We keep track of all non-hidden children, even those whose content is
    // not included, because all rendered children impact whether or not a
    // space should be inserted between objects. Example: A label which has
    // a single, nameless input surrounded by CSS-generated content should
    // have a space separating the before and after content.
    previous = child;

    // We only keep track of the source of children whose content is included.
    // Example: Three spans, the first with an aria-label, the second with no
    // content, and the third whose name comes from content. There should be a
    // space between the first and third because of the aria-label in the first.
    if (!result.empty())
      last_used_name_from = child_name_from;
  }

  return accumulated_text.ToString();
}

// static
bool AXNodeObject::IsNameFromLabelElement(HTMLElement* control) {
  // This duplicates some logic from TextAlternative()/NativeTextAlternative(),
  // but is necessary because IsNameFromLabelElement() needs to be called from
  // ComputeIsIgnored(), which isn't allowed to call
  // AXObjectCache().GetOrCreate() in random places in the tree.

  if (!control)
    return false;

  // aria-label and aria-labelledby take precedence over <label>.
  if (IsNameFromAriaAttribute(control))
    return false;

  // <label> will be used. It contains the control or points via <label for>.
  // Based on https://www.w3.org/TR/html-aam-1.0
  // 5.1/5.5 Text inputs, Other labelable Elements
  auto* labels = control->labels();
  return labels && labels->length();
}

// static
bool AXNodeObject::IsRedundantLabel(HTMLLabelElement* label) {
  // Determine if label is redundant:
  // - Labelling a checkbox or radio.
  // - Text was already used to name the checkbox/radio.
  // - No interesting content in the label (focusable or semantically useful)
  // TODO(accessibility) Consider moving this logic to the browser side.
  // TODO(accessibility) Consider this for more controls, such as textboxes.
  // There isn't a clear history why this is only done for checkboxes, and not
  // other controls such as textboxes. It may be because the checkbox/radio
  // itself is small, so this makes a nicely sized combined click target. Most
  // ATs do not already have features to combine labels and controls, e.g.
  // removing redundant announcements caused by having text and named controls
  // as separate objects.
  HTMLInputElement* input = DynamicTo<HTMLInputElement>(label->Control());
  if (!input)
    return false;

  if (!input->GetLayoutObject() ||
      input->GetLayoutObject()->Style()->Visibility() !=
          EVisibility::kVisible) {
    return false;
  }

  if (!input->IsCheckable()) {
    return false;
  }

  if (!IsNameFromLabelElement(input)) {
    return false;
  }

  DCHECK_NE(input->labels()->length(), 0U);

  // Look for any first child element that is not the input control itself.
  // This could be important semantically.
  Element* first_child = ElementTraversal::FirstChild(*label);
  if (!first_child)
    return true;  // No element children.

  if (first_child != input)
    return false;  // Has an element child that is not the input control.

  // The first child was the input control.
  // If there's another child, then it won't be the input control.
  return ElementTraversal::NextSibling(*first_child) == nullptr;
}

void AXNodeObject::GetRelativeBounds(AXObject** out_container,
                                     gfx::RectF& out_bounds_in_container,
                                     gfx::Transform& out_container_transform,
                                     bool* clips_children) const {
  if (GetLayoutObject()) {
    AXObject::GetRelativeBounds(out_container, out_bounds_in_container,
                                out_container_transform, clips_children);
    return;
  }

#if DCHECK_IS_ON()
  DCHECK(!getting_bounds_) << "GetRelativeBounds reentrant: " << ToString();
  base::AutoReset<bool> reentrancy_protector(&getting_bounds_, true);
#endif

  *out_container = nullptr;
  out_bounds_in_container = gfx::RectF();
  out_container_transform.MakeIdentity();

  if (RoleValue() == ax::mojom::blink::Role::kMenuListOption) {
    // When a <select> is collapsed, the bounds of its options are the same as
    // that of the containing <select>. Falling through will achieve this.
    // TODO(accessibility): Support bounding boxes for <optgroup>. Could
    // union the rect of the first and last option in it.
    auto* select = To<HTMLOptionElement>(GetNode())->OwnerSelectElement();
    if (auto* ax_select = AXObjectCache().Get(select)) {
      if (ax_select->IsExpanded() == kExpandedExpanded) {
        auto* options_bounds = AXObjectCache().GetOptionsBounds(*ax_select);
        if (options_bounds) {
          unsigned int index = static_cast<unsigned int>(
              To<HTMLOptionElement>(GetNode())->index());
          // Some <option> bounding boxes may not be sent, as a performance
          // optimization. For example, only the first 1000 options may have
          // bounding boxes. If no bounding box is available, then we serialize
          // the option with everything except for that information.
          if (index < options_bounds->size()) {
            out_bounds_in_container = gfx::RectF(options_bounds->at(index));
          }
          return;
        }
      }
    }
  }

  // First check if it has explicit bounds, for example if this element is tied
  // to a canvas path. When explicit coordinates are provided, the ID of the
  // explicit container element that the coordinates are relative to must be
  // provided too.
  if (!explicit_element_rect_.IsEmpty()) {
    *out_container = AXObjectCache().ObjectFromAXID(explicit_container_id_);
    if (*out_container) {
      out_bounds_in_container = gfx::RectF(explicit_element_rect_);
      return;
    }
  }

  Element* element = GetElement();
  // If it's in a canvas but doesn't have an explicit rect, or has display:
  // contents set, get the bounding rect of its children.
  if ((GetNode()->parentElement() &&
       GetNode()->parentElement()->IsInCanvasSubtree()) ||
      (element && element->HasDisplayContentsStyle())) {
    Vector<gfx::RectF> rects;
    for (Node& child : NodeTraversal::ChildrenOf(*GetNode())) {
      if (child.IsHTMLElement()) {
        if (AXObject* obj = AXObjectCache().Get(&child)) {
          AXObject* container;
          gfx::RectF bounds;
          obj->GetRelativeBounds(&container, bounds, out_container_transform,
                                 clips_children);
          if (container) {
            *out_container = container;
            rects.push_back(bounds);
          }
        }
      }
    }

    if (*out_container) {
      for (auto& rect : rects)
        out_bounds_in_container.Union(rect);
      return;
    }
  }

  // If this object doesn't have an explicit element rect or computable from its
  // children, for now, let's return the position of the ancestor that does have
  // a position, and make it the width of that parent, and about the height of a
  // line of text, so that it's clear the object is a child of the parent.
  for (AXObject* position_provider = ParentObject(); position_provider;
       position_provider = position_provider->ParentObject()) {
    if (position_provider->GetLayoutObject()) {
      position_provider->GetRelativeBounds(
          out_container, out_bounds_in_container, out_container_transform,
          clips_children);
      if (*out_container) {
        out_bounds_in_container.set_size(
            gfx::SizeF(out_bounds_in_container.width(),
                       std::min(10.0f, out_bounds_in_container.height())));
      }
      break;
    }
  }
}

bool AXNodeObject::HasValidHTMLTableStructureAndLayout() const {
  // Is it a visible <table> with a table-like role and layout?
  if (!IsTableLikeRole() || !GetLayoutObject() ||
      !GetLayoutObject()->IsTable() || !IsA<HTMLTableElement>(GetNode()))
    return false;

  // Check for any invalid children, as far as W3C table validity is concerned.
  // * If no invalid children exist, this will be considered a valid table,
  //   and AddTableChildren() can be used to add the children in rendered order.
  // * If any invalid children exist, this table will be considered invalid.
  //   In that case the children will still be added via AddNodeChildren(),
  //   so that no content is lost.
  // See comments in AddTableChildren() for more information about valid tables.
  auto* table = To<HTMLTableElement>(GetNode());
  auto* thead = table->tHead();
  auto* tfoot = table->tFoot();
  for (Node* node = LayoutTreeBuilderTraversal::FirstChild(*GetElement()); node;
       node = LayoutTreeBuilderTraversal::NextSibling(*node)) {
    if (Element* child = DynamicTo<Element>(node)) {
      if (child == thead || child == tfoot) {
        // Only 1 thead and 1 tfoot are allowed.
        continue;
      }
      if (IsA<HTMLTableSectionElement>(child) &&
          child->HasTagName(html_names::kTbodyTag)) {
        // Multiple <tbody>s are valid, but only 1 thead or tfoot.
        continue;
      }
      if (!child->GetLayoutObject() &&
          child->HasTagName(html_names::kColgroupTag)) {
        continue;
      }
      if (IsA<HTMLTableCaptionElement>(child) && child == table->caption()) {
        continue;  // Only one caption is valid.
      }
    } else if (!node->GetLayoutObject()) {
      continue;
    }
    return false;
  }

  return true;
}

void AXNodeObject::AddTableChildren() {
  // Add the caption (if any) and table sections in the visible order.
  //
  // Implementation notes:
  //
  // * In a valid table, there is always at least one section child DOM node.
  //   For example, if the HTML of the web page includes <tr>s as direct
  //   children of a <table>, Blink will insert a <tbody> as a child of the
  //   table, and parent of the <tr> elements.
  //
  // * Rendered order can differ from DOM order:
  //   The valid DOM order of <table> children is specified here:
  //   https://html.spec.whatwg.org/multipage/tables.html#the-table-element,
  //   "... optionally a caption element, followed by zero or more
  //   colgroup elements, followed optionally by a thead element, followed by
  //   either zero or more tbody elements or one or more tr elements, followed
  //   optionally by a tfoot element"
  //   However, even if the DOM children occur in an incorrect order, Blink
  //   automatically renders them as if they were in the correct order.
  //   The following code ensures that the children are added to the AX tree in
  //   the same order as Blink renders them.

  DCHECK(HasValidHTMLTableStructureAndLayout());
  auto* html_table_element = To<HTMLTableElement>(GetNode());
  AddNodeChild(html_table_element->caption());
  AddNodeChild(html_table_element->tHead());
  for (Node* node : *html_table_element->tBodies())
    AddNodeChild(node);
  AddNodeChild(html_table_element->tFoot());
}

int AXNodeObject::TextOffsetInFormattingContext(int offset) const {
  DCHECK_GE(offset, 0);
  if (IsDetached())
    return 0;

  // When a node has the first-letter CSS style applied to it, it is split into
  // two parts (two branches) in the layout tree. The "first-letter part"
  // contains its first letter and any surrounding Punctuation. The "remaining
  // part" contains the rest of the text.
  //
  // We need to ensure that we retrieve the correct layout object: either the
  // one for the "first-letter part" or the one for the "remaining part",
  // depending of the value of |offset|.
  const LayoutObject* layout_obj =
      GetNode() ? AssociatedLayoutObjectOf(*GetNode(), offset)
                : GetLayoutObject();
  if (!layout_obj)
    return AXObject::TextOffsetInFormattingContext(offset);

  // We support calculating the text offset from the start of the formatting
  // contexts of the following layout objects, provided that they are at
  // inline-level, (display=inline) or "display=inline-block":
  //
  // (Note that in the following examples, the paragraph is the formatting
  // context.
  //
  // Layout replaced, e.g. <p><img></p>.
  // Layout inline with a layout text child, e.g. <p><a href="#">link</a></p>.
  // Layout block flow, e.g. <p><b style="display: inline-block;"></b></p>.
  // Layout text, e.g. <p>Hello</p>.
  // Layout br (subclass of layout text), e.g. <p><br></p>.

  if (layout_obj->IsLayoutInline()) {
    // The OffsetMapping class doesn't map layout inline objects to their text
    // mappings because such an operation could be ambiguous. An inline object
    // may have another inline object inside it. For example,
    // <span><span>Inner</span outer</span>. We need to recursively retrieve the
    // first layout text or layout replaced child so that any potential
    // ambiguity would be removed.
    const AXObject* first_child = FirstChildIncludingIgnored();
    return first_child ? first_child->TextOffsetInFormattingContext(offset)
                       : offset;
  }

  // TODO(crbug.com/567964): LayoutObject::IsAtomicInlineLevel() also includes
  // block-level replaced elements. We need to explicitly exclude them via
  // LayoutObject::IsInline().
  const bool is_atomic_inline_level =
      layout_obj->IsInline() && layout_obj->IsAtomicInlineLevel();
  if (!is_atomic_inline_level && !layout_obj->IsText()) {
    // Not in a formatting context in which text offsets are meaningful.
    return AXObject::TextOffsetInFormattingContext(offset);
  }

  // TODO(crbug.com/1149171): NGInlineOffsetMappingBuilder does not properly
  // compute offset mappings for empty LayoutText objects. Other text objects
  // (such as some list markers) are not affected.
  if (const LayoutText* layout_text = DynamicTo<LayoutText>(layout_obj)) {
    if (layout_text->HasEmptyText()) {
      return AXObject::TextOffsetInFormattingContext(offset);
    }
  }

  LayoutBlockFlow* formatting_context =
      OffsetMapping::GetInlineFormattingContextOf(*layout_obj);
  if (!formatting_context || formatting_context == layout_obj)
    return AXObject::TextOffsetInFormattingContext(offset);

  // If "formatting_context" is not a Layout NG object, the offset mappings will
  // be computed on demand and cached.
  cons
"""


```
Response:
Let's break down the thought process for analyzing this `HTMLDetailsElement.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship with web technologies (HTML, CSS, JavaScript), logical reasoning with examples, and common usage errors.

2. **Identify the Core Element:** The filename `html_details_element.cc` immediately points to the `<details>` HTML element. This is the central focus.

3. **Scan for Key Information:** Quickly read through the code, looking for keywords, function names, and comments that give clues about the element's behavior. I'd look for:
    * Constructor (`HTMLDetailsElement::HTMLDetailsElement`):  Initialization, feature flags.
    * Shadow DOM related functions (`DidAddUserAgentShadowRoot`, `ManuallyAssignSlots`):  Internal structure.
    * Attribute handling (`ParseAttribute`, `AttributeChanged`): How the `open` and `name` attributes are processed.
    * Event handling (`DispatchPendingEvent`): How the `toggle` event is managed.
    * Layout related functions (`CreateLayoutObject`):  How the element renders.
    * `ToggleOpen()`: The core logic for expanding/collapsing.
    * `MaybeCloseForExclusivity()`, `OtherElementsInNameGroup()`:  The accordion behavior.
    * `ExpandDetailsAncestors()`:  Accessibility/navigation related behavior.
    * `HandleCommandInternal()`:  Handling declarative actions.

4. **Group Functionality:** Based on the scanned information, I'd start grouping related functionalities:
    * **Basic Setup:** Constructor, User-Agent Shadow DOM creation.
    * **Opening/Closing:**  `open` attribute handling, `ToggleOpen()`, `DispatchPendingEvent`.
    * **Accordion Behavior:** `name` attribute handling, `MaybeCloseForExclusivity()`, `OtherElementsInNameGroup()`.
    * **Layout:** `CreateLayoutObject`.
    * **Accessibility/Navigation:** `ExpandDetailsAncestors()`.
    * **Declarative Actions:** `HandleCommandInternal()`.

5. **Relate to Web Technologies:**  Now, connect the identified functionalities to HTML, CSS, and JavaScript:
    * **HTML:** The `<details>` and `<summary>` tags, the `open` and `name` attributes. The structure of the light DOM within `<details>`.
    * **CSS:**  The default styling provided by the browser (disclosure triangle), the use of `content-visibility: hidden`, `display: block`, and `:host` selectors in the shadow DOM CSS. The potential for custom styling.
    * **JavaScript:** The `toggle` event, the ability to programmatically control the `open` attribute using JavaScript.

6. **Construct Examples:** For each relationship, create concrete examples:
    * **HTML:** Show basic `<details>` structure with and without `<summary>`. Demonstrate the `open` attribute. Show the `name` attribute for accordion.
    * **CSS:** Mention basic styling and how to style the `<summary>` and the content area.
    * **JavaScript:**  Show how to listen for the `toggle` event and how to set the `open` property.

7. **Logical Reasoning and Input/Output:**  Focus on the core logic, especially the accordion behavior. Think about scenarios:
    * **Input:** Multiple `<details>` elements with the same `name`, one is open.
    * **Output:** Opening another one closes the first.
    * **Input:** A deeply nested element within a closed `<details>`.
    * **Output:**  Using a feature that expands ancestors opens the relevant `<details>` elements.

8. **Identify Common Usage Errors:** Think about how developers might misuse the `<details>` element:
    * **Forgetting `<summary>`:** Leads to default text.
    * **Incorrect `name` usage:**  Unexpected accordion behavior.
    * **Assuming synchronous behavior of `toggle`:** The event is asynchronous.
    * **Over-reliance on default styling:** Not customizing appearance.

9. **Structure the Output:** Organize the information logically with clear headings and bullet points. Start with a high-level overview of the file's purpose and then delve into specifics. Use clear and concise language.

10. **Review and Refine:**  Read through the generated output, checking for accuracy, completeness, and clarity. Ensure the examples are correct and easy to understand. For instance, initially, I might forget to mention the asynchronous nature of the `toggle` event and would add that during the review. I'd also double-check the code snippets for correctness.

This iterative process of scanning, grouping, connecting, exemplifying, reasoning, and refining helps build a comprehensive understanding of the code and generate a detailed and accurate response to the request.
这个文件 `blink/renderer/core/html/html_details_element.cc` 是 Chromium Blink 渲染引擎中负责实现 HTML `<details>` 元素功能的源代码文件。它处理了 `<details>` 元素的行为、样式以及与 JavaScript、HTML 和 CSS 的交互。

**主要功能:**

1. **实现 `<details>` 元素的行为:**
   - **展开/折叠逻辑:**  核心功能是控制 `<details>` 元素的展开和折叠状态。当 `open` 属性存在时，内容区域展开；反之，内容区域折叠。
   - **`toggle` 事件:** 当展开或折叠状态改变时，会触发 `toggle` 事件。
   - **用户代理 Shadow DOM:**  创建并管理 `<details>` 元素的内部结构，包括 `<summary>` 元素的默认样式和内容区域的显示/隐藏。
   - **与 `<summary>` 元素的关联:**  识别并处理作为 `<details>` 子元素的 `<summary>` 元素，作为展开/折叠的触发器。如果没有 `<summary>`，则在 Shadow DOM 中创建一个默认的。
   - **`name` 属性的独占性（Accordion 行为）:**  当多个 `<details>` 元素具有相同的 `name` 属性时，确保一次只有一个元素处于展开状态，实现手风琴效果。

2. **处理 HTML 属性:**
   - **`open` 属性:**  监听 `open` 属性的变化，更新元素的展开/折叠状态，并触发 `toggle` 事件。
   - **`name` 属性:**  监听 `name` 属性的变化，并根据 `name` 属性实现手风琴行为。

3. **与 CSS 的交互:**
   - **默认样式:** 提供用户代理（浏览器）提供的默认样式，例如 `<summary>` 元素的 `list-style: disclosure-closed/open` 样式，显示展开/折叠指示符。
   - **`content-visibility: hidden`:**  在折叠状态下，使用 `content-visibility: hidden` 隐藏内容区域，提高性能。
   - **Shadow DOM 样式:**  定义 Shadow DOM 中元素的默认样式。

4. **与 JavaScript 的交互:**
   - **`toggle` 事件:**  JavaScript 可以监听 `<details>` 元素的 `toggle` 事件，以便在展开或折叠状态改变时执行相应的操作。
   - **`open` 属性的设置:** JavaScript 可以通过设置或移除 `open` 属性来控制 `<details>` 元素的展开/折叠状态。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

**1. 与 HTML 的关系:**

- **元素定义:**  该文件实现了 HTML 的 `<details>` 元素。
- **子元素 `<summary>`:**  代码识别并处理 `<details>` 元素的子元素 `<summary>`。
  ```html
  <details>
    <summary>点击展开/折叠</summary>
    这是要显示或隐藏的内容。
  </details>
  ```
- **`open` 属性:**  HTML 中使用 `open` 属性来初始设置 `<details>` 元素的展开状态。
  ```html
  <details open>
    <summary>默认展开</summary>
    这是默认显示的内容。
  </details>
  ```
- **`name` 属性:**  HTML 中使用 `name` 属性将多个 `<details>` 元素关联起来，形成手风琴效果。
  ```html
  <details name="accordion">
    <summary>第一个面板</summary>
    第一个面板的内容。
  </details>
  <details name="accordion">
    <summary>第二个面板</summary>
    第二个面板的内容。
  </details>
  ```

**2. 与 JavaScript 的关系:**

- **`toggle` 事件:**  JavaScript 可以监听 `toggle` 事件，当用户点击 `<summary>` 或通过其他方式改变展开状态时触发。
  ```javascript
  const detailsElement = document.querySelector('details');
  detailsElement.addEventListener('toggle', () => {
    if (detailsElement.open) {
      console.log('Details 元素已展开');
    } else {
      console.log('Details 元素已折叠');
    }
  });
  ```
- **控制 `open` 属性:**  JavaScript 可以动态地设置或移除 `open` 属性来控制 `<details>` 元素的展开/折叠。
  ```javascript
  const detailsElement = document.querySelector('details');
  const openButton = document.getElementById('openBtn');
  const closeButton = document.getElementById('closeBtn');

  openButton.addEventListener('click', () => {
    detailsElement.open = true;
  });

  closeButton.addEventListener('click', () => {
    detailsElement.open = false;
  });
  ```

**3. 与 CSS 的关系:**

- **默认样式:**  浏览器为 `<details>` 和 `<summary>` 元素提供默认的样式，例如 `<summary>` 元素的展开/折叠指示符。
- **自定义样式:**  开发者可以使用 CSS 来自定义 `<details>` 和 `<summary>` 元素的外观。可以使用伪类 `:open` 来针对展开状态设置样式。
  ```css
  details summary {
    cursor: pointer;
    font-weight: bold;
  }

  details[open] summary::marker { /* 自定义展开状态的指示符 */
    content: "▼ ";
  }

  details summary::marker { /* 自定义折叠状态的指示符 */
    content: "▶ ";
  }

  details div { /* 假设内容被包裹在一个 div 中 */
    padding: 10px;
    border: 1px solid #ccc;
  }

  details:not([open]) div {
    display: none; /*  老方法隐藏内容，现在更多用 content-visibility */
  }
  ```
- **Shadow DOM 样式:**  `HTMLDetailsElement.cc` 中会创建 Shadow DOM，并包含默认的样式规则，例如控制 `<summary>` 的 `list-style`。

**逻辑推理与假设输入/输出:**

**场景 1:  处理 `open` 属性变化**

**假设输入:**

- HTML: `<details id="myDetails"></details>`
- JavaScript: `document.getElementById('myDetails').setAttribute('open', '');`

**逻辑推理:**

1. `setAttribute('open', '')` 会触发 `HTMLDetailsElement::ParseAttribute` 函数。
2. `params.name` 为 `open`，`params.new_value` 不为空。
3. `is_open_` 从 `false` 变为 `true`。
4. 创建一个 `toggle` 事件，`oldState` 为 "closed"，`newState` 为 "open"。
5. 异步调度 `DispatchPendingEvent` 函数来触发 `toggle` 事件。
6. 找到 Shadow DOM 中的内容区域元素。
7. 移除内容区域元素的 `content-visibility: hidden` 样式 (如果 `DetailsStylingEnabled()` 为 true，也会移除 `display: block`)。

**假设输出:**

- `<details>` 元素的状态变为展开。
- 触发一个 `toggle` 事件，可以通过 JavaScript 监听。
- 内容区域在页面上可见。

**场景 2: 处理具有相同 `name` 属性的多个 `<details>` 元素**

**假设输入:**

- HTML:
  ```html
  <details name="accordion" id="details1"><summary>Panel 1</summary>Content 1</details>
  <details name="accordion" id="details2" open><summary>Panel 2</summary>Content 2</details>
  <details name="accordion" id="details3"><summary>Panel 3</summary>Content 3</details>
  ```
- JavaScript: `document.getElementById('details1').setAttribute('open', '');`

**逻辑推理:**

1. `setAttribute('open', '')` 在 `details1` 上触发 `HTMLDetailsElement::ParseAttribute`。
2. `details1` 的 `is_open_` 从 `false` 变为 `true`。
3. 由于 `details1` 有 `name` 属性 "accordion"，且状态变为 open，会调用 `MaybeCloseForExclusivity`。
4. `MaybeCloseForExclusivity` 会查找具有相同 `name` 的其他 `<details>` 元素。
5. 找到 `details2` 并且它是打开的。
6. 调用 `details2->ToggleOpen()`，这会移除 `details2` 的 `open` 属性。
7. 触发 `details1` 的 `toggle` 事件。

**假设输出:**

- `details1` 展开。
- `details2` 折叠。
- 触发 `details1` 的 `toggle` 事件。

**用户或编程常见的使用错误:**

1. **忘记使用 `<summary>` 元素:** 如果 `<details>` 元素没有 `<summary>` 子元素，浏览器会使用 Shadow DOM 提供一个默认的 "Details" 文本作为标题，这可能不是期望的效果。
   ```html
   <details>  <!-- 缺少 <summary> -->
     这是内容。
   </details>
   ```
   **后果:** 显示默认的 "Details" 文本，用户体验可能不佳。

2. **错误地假设 `toggle` 事件是同步的:** `toggle` 事件是异步触发的。如果在设置 `open` 属性后立即访问某些与展开状态相关的属性或执行操作，可能会得到旧的状态。
   ```javascript
   const detailsElement = document.querySelector('details');
   detailsElement.open = true;
   console.log(detailsElement.open); // 此时可能仍然输出 false，因为 toggle 事件尚未完全处理
   ```
   **后果:** 导致竞态条件和不可预测的行为。

3. **在具有相同 `name` 属性的 `<details>` 元素中使用复杂的 JavaScript 控制，而没有理解其默认的独占行为:**  如果手动通过 JavaScript 控制多个具有相同 `name` 的 `<details>` 元素的展开/折叠，可能会与浏览器默认的独占行为冲突，导致意外的结果。

4. **过度依赖默认样式，没有进行自定义:**  `<details>` 和 `<summary>` 的默认样式可能无法满足所有设计需求。开发者需要使用 CSS 来自定义其外观。

5. **在不支持 `<details>` 元素的旧浏览器上没有提供回退方案:**  虽然现代浏览器都支持 `<details>` 元素，但在旧版本的浏览器上可能不被支持，需要考虑提供替代的交互方式或使用 JavaScript polyfill。

总而言之，`html_details_element.cc` 文件是实现 `<details>` 元素核心功能的重要组成部分，它处理了元素的展开/折叠逻辑、属性变化、事件触发以及与 CSS 的交互，并为开发者提供了创建可折叠内容区域的标准方式。

### 提示词
```
这是目录为blink/renderer/core/html/html_details_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2010, 2011 Nokia Corporation and/or its subsidiary(-ies)
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

#include "third_party/blink/renderer/core/html/html_details_element.h"

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/mutation_event_suppression_scope.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_summary_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"

namespace blink {

HTMLDetailsElement::HTMLDetailsElement(Document& document)
    : HTMLElement(html_names::kDetailsTag, document) {
  UseCounter::Count(document, WebFeature::kDetailsElement);
  EnsureUserAgentShadowRoot(SlotAssignmentMode::kManual);
}

HTMLDetailsElement::~HTMLDetailsElement() = default;

void HTMLDetailsElement::DispatchPendingEvent(
    const AttributeModificationReason reason) {
  Event* toggle_event = nullptr;
  CHECK(pending_toggle_event_);
  toggle_event = pending_toggle_event_.Get();
  pending_toggle_event_ = nullptr;

  if (reason == AttributeModificationReason::kByParser)
    GetDocument().SetToggleDuringParsing(true);
  DispatchEvent(*toggle_event);
  if (reason == AttributeModificationReason::kByParser)
    GetDocument().SetToggleDuringParsing(false);
}

LayoutObject* HTMLDetailsElement::CreateLayoutObject(
    const ComputedStyle& style) {
  if (RuntimeEnabledFeatures::DetailsStylingEnabled()) {
    return HTMLElement::CreateLayoutObject(style);
  }

  return LayoutObject::CreateBlockFlowOrListItem(this, style);
}

// Creates shadow DOM:
// #shadowroot
//   <SLOT id="details-summary">
//     <SUMMARY>Details</SUMMARY>
//   </SLOT>
//   <SLOT id="details-content"
//         style="content-visibility: hidden; display:block;"></SLOT>
//   <STYLE>...
void HTMLDetailsElement::DidAddUserAgentShadowRoot(ShadowRoot& root) {
  auto* default_summary =
      MakeGarbageCollected<HTMLSummaryElement>(GetDocument());
  default_summary->AppendChild(
      Text::Create(GetDocument(),
                   GetLocale().QueryString(IDS_DETAILS_WITHOUT_SUMMARY_LABEL)));

  summary_slot_ = MakeGarbageCollected<HTMLSlotElement>(GetDocument());
  summary_slot_->SetIdAttribute(shadow_element_names::kIdDetailsSummary);
  summary_slot_->AppendChild(default_summary);
  root.AppendChild(summary_slot_);

  content_slot_ = MakeGarbageCollected<HTMLSlotElement>(GetDocument());
  content_slot_->SetIdAttribute(shadow_element_names::kIdDetailsContent);
  if (RuntimeEnabledFeatures::DetailsStylingEnabled()) {
    content_slot_->SetShadowPseudoId(shadow_element_names::kIdDetailsContent);
  }
  content_slot_->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                        CSSValueID::kHidden);
  content_slot_->EnsureDisplayLockContext().SetIsDetailsSlotElement(true);
  content_slot_->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                        CSSValueID::kBlock);
  root.AppendChild(content_slot_);

  auto* default_summary_style =
      MakeGarbageCollected<HTMLStyleElement>(GetDocument());
  // This style is required only if this <details> shows the UA-provided
  // <summary>, not a light child <summary>.
  default_summary_style->setTextContent(R"CSS(
:host summary {
  display: list-item;
  counter-increment: list-item 0;
  list-style: disclosure-closed inside;
}
:host([open]) summary {
  list-style-type: disclosure-open;
}
)CSS");
  root.AppendChild(default_summary_style);
}

Element* HTMLDetailsElement::FindMainSummary() const {
  if (HTMLSummaryElement* summary =
          Traversal<HTMLSummaryElement>::FirstChild(*this))
    return summary;
  HTMLSlotElement& slot =
      To<HTMLSlotElement>(*UserAgentShadowRoot()->firstChild());
  CHECK(IsA<HTMLSummaryElement>(*slot.firstChild()));
  return To<Element>(slot.firstChild());
}

void HTMLDetailsElement::ManuallyAssignSlots() {
  HeapVector<Member<Node>> summary_nodes;
  HeapVector<Member<Node>> content_nodes;
  for (Node& child : NodeTraversal::ChildrenOf(*this)) {
    if (!child.IsSlotable()) {
      CHECK(!IsA<HTMLSummaryElement>(child));
      continue;
    }
    bool is_first_summary =
        summary_nodes.empty() && IsA<HTMLSummaryElement>(child);
    if (is_first_summary) {
      summary_nodes.push_back(child);
    } else {
      content_nodes.push_back(child);
    }
  }
  summary_slot_->Assign(summary_nodes);
  content_slot_->Assign(content_nodes);
}

void HTMLDetailsElement::Trace(Visitor* visitor) const {
  visitor->Trace(pending_toggle_event_);
  visitor->Trace(summary_slot_);
  visitor->Trace(content_slot_);
  HTMLElement::Trace(visitor);
}

void HTMLDetailsElement::ParseAttribute(
    const AttributeModificationParams& params) {
  CHECK(params.reason != AttributeModificationReason::kByParser ||
        !parentNode())
      << "This code depends on the parser setting attributes before inserting "
         "into the document; if that were not the case we would need to "
         "handle setting of either open or name by the parser, and "
         "potentially change the open attribute during that handling.";

  if (params.name == html_names::kOpenAttr) {
    bool old_value = is_open_;
    is_open_ = !params.new_value.IsNull();
    if (is_open_ == old_value)
      return;

    // Dispatch toggle event asynchronously.
    String old_state = is_open_ ? "closed" : "open";
    String new_state = is_open_ ? "open" : "closed";
    if (pending_toggle_event_) {
      old_state = pending_toggle_event_->oldState();
    }
    pending_toggle_event_ =
        ToggleEvent::Create(event_type_names::kToggle, Event::Cancelable::kNo,
                            old_state, new_state);
    pending_event_task_ = PostCancellableTask(
        *GetDocument().GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
        WTF::BindOnce(&HTMLDetailsElement::DispatchPendingEvent,
                      WrapPersistent(this), params.reason));

    Element* content =
        EnsureUserAgentShadowRoot(SlotAssignmentMode::kManual)
            .getElementById(shadow_element_names::kIdDetailsContent);
    DCHECK(content);

    if (is_open_) {
      content->RemoveInlineStyleProperty(CSSPropertyID::kContentVisibility);
      if (!RuntimeEnabledFeatures::DetailsStylingEnabled()) {
        content->RemoveInlineStyleProperty(CSSPropertyID::kDisplay);
      }

      // https://html.spec.whatwg.org/multipage/interactive-elements.html#ensure-details-exclusivity-by-closing-other-elements-if-needed
      //
      // The name attribute links multiple details elements into an
      // exclusive accordion.  So if this one has a name, close the
      // other ones with the same name.
      CHECK_NE(params.reason,
               AttributeModificationReason::kBySynchronizationOfLazyAttribute);
      // TODO(https://crbug.com/1444057): Should this be in
      // AttributeChanged instead?
      if (!GetName().empty() &&
          params.reason == AttributeModificationReason::kDirectly) {
        // Don't fire mutation events for any changes to the open attribute
        // that this causes.
        MutationEventSuppressionScope scope(GetDocument());

        HeapVector<Member<HTMLDetailsElement>> details_with_name(
            OtherElementsInNameGroup());
        for (HTMLDetailsElement* other_details : details_with_name) {
          CHECK_NE(other_details, this);
          UseCounter::Count(
              GetDocument(),
              WebFeature::kHTMLDetailsElementNameAttributeClosesOther);
          other_details->setAttribute(html_names::kOpenAttr, g_null_atom);
        }
      }
    } else {
      if (!RuntimeEnabledFeatures::DetailsStylingEnabled()) {
        content->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                        CSSValueID::kBlock);
      }
      content->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                      CSSValueID::kHidden);
      content->EnsureDisplayLockContext().SetIsDetailsSlotElement(true);
    }
  } else {
    HTMLElement::ParseAttribute(params);
  }
}

void HTMLDetailsElement::AttributeChanged(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  if (name == html_names::kNameAttr) {
    if (!params.new_value.empty()) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLDetailsElementNameAttribute);
    }
    MaybeCloseForExclusivity();
  }

  HTMLElement::AttributeChanged(params);
}

Node::InsertionNotificationRequest HTMLDetailsElement::InsertedInto(
    ContainerNode& insertion_point) {
  Node::InsertionNotificationRequest result =
      HTMLElement::InsertedInto(insertion_point);

  MaybeCloseForExclusivity();

  return result;
}

// https://html.spec.whatwg.org/multipage/C#ensure-details-exclusivity-by-closing-the-given-element-if-needed
void HTMLDetailsElement::MaybeCloseForExclusivity() {
  if (GetName().empty() || !is_open_) {
    return;
  }

  // Don't fire mutation events for any changes to the open attribute
  // that this causes.
  MutationEventSuppressionScope scope(GetDocument());

  HeapVector<Member<HTMLDetailsElement>> details_with_name(
      OtherElementsInNameGroup());
  for (HTMLDetailsElement* other_details : details_with_name) {
    CHECK_NE(other_details, this);
    if (other_details->is_open_) {
      // close this details element
      UseCounter::Count(GetDocument(),
                        WebFeature::kHTMLDetailsElementNameAttributeClosesSelf);
      ToggleOpen();
      break;
    }
  }
}

void HTMLDetailsElement::ToggleOpen() {
  setAttribute(html_names::kOpenAttr, is_open_ ? g_null_atom : g_empty_atom);
}

HeapVector<Member<HTMLDetailsElement>>
HTMLDetailsElement::OtherElementsInNameGroup() {
  HeapVector<Member<HTMLDetailsElement>> result;
  const AtomicString& name = GetName();
  if (name.empty()) {
    return result;
  }
  HTMLDetailsElement* details = Traversal<HTMLDetailsElement>::Next(TreeRoot());
  while (details) {
    if (details != this && details->GetName() == name) {
      result.push_back(details);
    }
    details = Traversal<HTMLDetailsElement>::Next(*details);
  }
  return result;
}

bool HTMLDetailsElement::IsInteractiveContent() const {
  return true;
}

// static
bool HTMLDetailsElement::ExpandDetailsAncestors(const Node& node) {
  CHECK(&node);
  // Since setting the open attribute fires mutation events which could mess
  // with the FlatTreeTraversal iterator, we should first iterate details
  // elements to open and then open them all.
  HeapVector<Member<HTMLDetailsElement>> details_to_open;

  for (Node& parent : FlatTreeTraversal::AncestorsOf(node)) {
    if (HTMLDetailsElement* details = DynamicTo<HTMLDetailsElement>(parent)) {
      // If the active match is inside the <summary> of a <details>, then we
      // shouldn't expand the <details> because the active match is already
      // visible.
      bool inside_summary = false;
      Element& summary = *details->FindMainSummary();
      for (Node& ancestor : FlatTreeTraversal::AncestorsOf(node)) {
        if (&ancestor == &summary) {
          inside_summary = true;
          break;
        }
      }

      if (!inside_summary &&
          !details->FastHasAttribute(html_names::kOpenAttr)) {
        details_to_open.push_back(details);
      }
    }
  }

  for (HTMLDetailsElement* details : details_to_open) {
    details->setAttribute(html_names::kOpenAttr, g_empty_atom);
  }

  return details_to_open.size();
}

bool HTMLDetailsElement::IsValidBuiltinCommand(HTMLElement& invoker,
                                               CommandEventType command) {
  bool parent_is_valid = HTMLElement::IsValidBuiltinCommand(invoker, command);
  if (!RuntimeEnabledFeatures::HTMLInvokeActionsV2Enabled()) {
    return parent_is_valid;
  }
  return parent_is_valid || command == CommandEventType::kToggle ||
         command == CommandEventType::kOpen ||
         command == CommandEventType::kClose;
}

bool HTMLDetailsElement::HandleCommandInternal(HTMLElement& invoker,
                                               CommandEventType command) {
  CHECK(IsValidBuiltinCommand(invoker, command));

  if (HTMLElement::HandleCommandInternal(invoker, command)) {
    return true;
  }

  if (command == CommandEventType::kToggle) {
    ToggleOpen();
    return true;
  } else if (command == CommandEventType::kClose) {
    if (is_open_) {
      setAttribute(html_names::kOpenAttr, g_null_atom);
    }
    return true;
  } else if (command == CommandEventType::kOpen) {
    if (!is_open_) {
      setAttribute(html_names::kOpenAttr, g_empty_atom);
    }
    return true;
  }

  return false;
}

}  // namespace blink
```
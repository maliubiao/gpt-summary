Response:
The user wants to understand the functionality of the `html_element.cc` file in the Chromium Blink engine. They specifically want to know:

1. **General Functions:** What does this file do?
2. **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logic and Reasoning:**  Examples of input and output if any logical deductions are present.
4. **Common Errors:**  Potential mistakes made by users or programmers.
5. **Summary:** A concise overview of the file's purpose based on the provided first part of the code.

Let's analyze the provided code snippet to address these points for the first part of the file.

**Code Analysis (Part 1):**

* **Copyright and License:**  Standard open-source licensing information. Not directly related to functionality but indicates the file's nature.
* **Includes:**  A significant number of header files are included. This gives a good indication of the file's dependencies and the areas it touches:
    * **Fundamental Types:** `base/containers/enum_set.h`, `third_party/blink/public/common/features.h`
    * **Blink Core:**  `third_party/blink/renderer/core/...` -  This is the core of the functionality. We see includes for:
        * **Bindings (V8):**  Interaction with JavaScript.
        * **Accessibility:**  Features for assistive technologies.
        * **CSS:** Styling and visual presentation.
        * **DOM:** The Document Object Model, the tree-like structure of HTML.
        * **Events:** Handling user interactions and other events.
        * **Editing:** Functionality for text editing within the browser.
        * **Frame:**  The concept of frames and windows.
        * **HTML:** Specific HTML element implementations and parsing.
        * **Layout:**  How elements are positioned and sized on the page.
        * **MathML & SVG:** Support for mathematical and vector graphics content.
        * **Trusted Types:** Security mechanisms.
    * **Platform:** `third_party/blink/renderer/platform/...` - Lower-level platform abstractions.
* **`UNSAFE_BUFFERS_BUILD`:** A conditional compilation flag suggesting potential memory safety concerns and areas requiring careful handling.
* **Namespaces:** The code is within the `blink` namespace.
* **`AttributeTriggers` struct:**  This is a key structure defining the relationship between HTML attributes and their associated actions (like triggering a JavaScript event handler).
* **Anonymous Namespace:** Contains helper functions:
    * `IsEditableOrEditingHost`: Determines if a node is editable, a core concept for content editing.
    * `PopoverCloseWatcherEventListener`: A specific event listener for handling the closing of popover elements.
    * `NameInHeapSnapshotBuilder`: Used for creating string representations of elements for debugging and memory analysis.
* **`HTMLElement::nodeName()`:** Returns the name of the HTML element.
* **`HTMLElement::NameInHeapSnapshot()`:** Provides a string representation for heap snapshots.
* **`HTMLElement::ShouldSerializeEndTag()`:** Determines if an end tag is required for a specific HTML element (e.g., `<img>` doesn't need one).
* **`HTMLElement::ParseBorderWidthAttribute()`:**  Parses the value of the `border` attribute.
* **`HTMLElement::ApplyBorderAttributeToStyle()`:**  Applies the parsed border width to the element's style.
* **`HTMLElement::IsPresentationAttribute()`:**  Checks if an attribute is considered a "presentation attribute" that affects styling.
* **`HTMLElement::IsValidDirAttribute()`:** Validates the value of the `dir` (direction) attribute.
* **`HTMLElement::CollectStyleForPresentationAttribute()`:**  The central function for translating HTML presentation attributes into CSS styles. This includes handling attributes like `align`, `contenteditable`, `hidden`, `draggable`, `dir`, and `lang`.
* **`HTMLElement::TriggersForAttributeName()`:**  A static method that seems to provide a mapping between attribute names and their corresponding handlers. The initial part of the `attribute_triggers` array is shown, listing attributes like `dir`, `form`, `lang`, `nonce`, `popover`, and various event handler attributes (e.g., `onabort`, `onclick`).

**Functionality Summary (Part 1):**

Based on this initial part of the code, the `html_element.cc` file seems to be responsible for the fundamental behavior of HTML elements in the Blink rendering engine. It handles:

* **Attribute Processing:**  Parsing and interpreting HTML attributes, especially those that directly influence styling (presentation attributes) and trigger JavaScript events.
* **Style Application:** Converting HTML attributes into corresponding CSS style properties.
* **Event Handling Setup:** Connecting HTML attributes like `onclick` to JavaScript event listeners.
* **Core HTML Element Properties:**  Managing basic properties like `nodeName` and determining if an end tag is required.
* **Editing Support:**  Providing mechanisms for determining if an element is editable.
* **Accessibility Considerations:** Though not explicitly detailed in this snippet, the inclusion of accessibility headers suggests this file contributes to making web content accessible.
这是`blink/renderer/core/html/html_element.cc`文件的第一部分，主要负责**HTML元素的基础功能和属性处理**。

以下是根据代码推断的功能归纳和举例说明：

**功能归纳:**

1. **定义了 `HTMLElement` 类:**  这是所有具体HTML元素的基类。它包含了所有HTML元素通用的属性和方法。
2. **处理元素的基本属性:** 例如 `nodeName` (节点名称)，判断是否需要结束标签 (`ShouldSerializeEndTag`)。
3. **处理和应用 "presentation attributes" (呈现属性):**  这些属性可以直接影响元素的样式，例如 `align`, `contenteditable`, `hidden`, `lang`, `dir`, `draggable` 等。
4. **将 HTML 属性转换为 CSS 样式:**  例如，将 `align` 属性的值转换为 `text-align` CSS 属性，将 `hidden` 属性转换为 `display: none` 或 `content-visibility: hidden`。
5. **处理事件处理属性 (event handler attributes):**  例如 `onclick`, `onload`, `onmouseover` 等。代码中定义了一个 `AttributeTriggers` 结构体，用于关联属性名和相应的事件类型。
6. **提供一些辅助方法:** 例如 `ParseBorderWidthAttribute` 解析 `border` 属性的值，`ApplyBorderAttributeToStyle` 将 `border` 属性应用到样式上。
7. **处理 `dir` 属性:**  根据 `dir` 属性的值设置元素的文本方向 (从左到右或从右到左)。
8. **处理 `lang` 属性:**  将 `lang` 属性的值映射到区域设置。
9. **提供对 `contenteditable` 属性的支持:**  使元素可编辑。
10. **提供对 "popover" 属性的支持:**  处理弹出框元素的显示和隐藏。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能:** `HTMLElement` 类是所有 HTML 元素的基类，因此它直接关系到每一个 HTML 元素的功能和属性。
    * **举例:**  代码中处理了大量的 HTML 属性，例如 `hidden` 属性。当 HTML 中设置了 `<div hidden></div>` 时，这段代码会将 `hidden` 属性转换为 CSS 的 `display: none;`，从而隐藏该元素。
* **CSS:**
    * **功能:**  该文件负责将 HTML 的呈现属性转换为 CSS 样式，从而影响元素的视觉呈现。
    * **举例:**
        * 当 HTML 中有 `<p align="center"></p>` 时，`CollectStyleForPresentationAttribute` 函数会将 `align="center"` 转换为 CSS 的 `text-align: center;`。
        * 当 HTML 中有 `<div contenteditable="true"></div>` 时，代码会添加 CSS 属性 `webkit-user-modify: read-write;` 等，使得该 `div` 可以被用户编辑。
* **JavaScript:**
    * **功能:**  通过处理以 "on" 开头的属性 (例如 `onclick`)，该文件建立了 HTML 元素和 JavaScript 事件处理函数之间的联系。
    * **举例:**  当 HTML 中有 `<button onclick="alert('Clicked!')"></button>` 时，`AttributeTriggers` 结构体中定义了 `html_names::kOnclickAttr` 对应的事件类型是 `event_type_names::kClick`。Blink 引擎会利用这些信息将点击事件与相应的 JavaScript 代码关联起来。

**逻辑推理及假设输入与输出:**

* **假设输入:**  一个 HTML 元素带有 `dir="auto"` 属性，并且该元素不是 `<bdo>`, `<textarea>`, 或 `<pre>` 标签。
* **逻辑:** `HTMLElement::CollectStyleForPresentationAttribute` 函数会检查 `dir` 属性的值是否为 "auto"，并且判断元素标签名。
* **输出:**  代码会根据元素类型添加不同的 `unicode-bidi` CSS 属性。对于大部分元素，会添加 `unicode-bidi: isolate;`。但对于某些特定的输入类型 (例如 `search`, `tel`, `url`, `email`)，会添加 `unicode-bidi: plaintext;`。

**用户或编程常见的使用错误举例:**

* **错误使用 `contenteditable` 的值:** 用户可能会将 `contenteditable` 设置为除了 "true", "false", "plaintext-only" 之外的值，这可能导致意外的行为。代码中会检查这些有效值，并根据其设置相应的 CSS 属性。
* **错误使用 `dir` 属性的值:**  用户可能会将 `dir` 属性设置为无效的值，例如 "middle"。代码中 `IsValidDirAttribute` 函数会检查 `dir` 属性的值是否为 "auto", "ltr", 或 "rtl"。如果使用了无效值，对于普通的 HTML 元素，该属性会被忽略（但对于 `<body>` 元素，会默认设置为 "ltr"）。
* **不理解呈现属性的优先级:** 开发者可能会不清楚 HTML 呈现属性和 CSS 样式之间的优先级关系。直接在 HTML 中使用呈现属性会覆盖浏览器默认样式，但会被外部 CSS 样式覆盖。

**总结 (针对第一部分):**

`blink/renderer/core/html/html_element.cc` 的第一部分主要负责定义 `HTMLElement` 基类，并处理 HTML 元素的基础属性，特别是那些直接影响元素呈现的属性（呈现属性）和用于关联 JavaScript 事件处理函数的属性。它扮演着连接 HTML 结构、CSS 样式和 JavaScript 行为的关键角色。该部分的代码逻辑主要集中在属性的解析、验证和将 HTML 属性值转换为相应的 CSS 样式。

### 提示词
```
这是目录为blink/renderer/core/html/html_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 * Copyright (C) 2004-2008, 2013, 2014 Apple Inc. All rights reserved.
 * Copyright (C) 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2011 Motorola Mobility. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/html_element.h"

#include "base/containers/enum_set.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/forms/form_control_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/js_event_handler_for_content_attribute.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_show_popover_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_toggle_popover_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_boolean_togglepopoveroptions.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_stringlegacynulltoemptystring_trustedscript.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_ratio_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element_rare_data_vector.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/popover_data.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_recalc_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/serializers/markup_accumulator.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/events/toggle_event.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/anchor_element_observer.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/labels_node_list.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_bdi_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_dimension.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cancellable_task.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

using AttributeChangedFunction =
    void (HTMLElement::*)(const Element::AttributeModificationParams& params);
using mojom::blink::FormControlType;

struct AttributeTriggers {
  const QualifiedName& attribute;
  WebFeature web_feature;
  const AtomicString& event;
  AttributeChangedFunction function;
};

namespace {

// https://html.spec.whatwg.org/multipage/interaction.html#editing-host
// An editing host is either an HTML element with its contenteditable attribute
// in the true state, or a child HTML element of a Document whose design mode
// enabled is true.
// https://w3c.github.io/editing/execCommand.html#editable
// Something is editable if it is a node; it is not an editing host; it does not
// have a contenteditable attribute set to the false state; its parent is an
// editing host or editable; and either it is an HTML element, or it is an svg
// or math element, or it is not an Element and its parent is an HTML element.
bool IsEditableOrEditingHost(const Node& node) {
  auto* html_element = DynamicTo<HTMLElement>(node);
  if (html_element) {
    ContentEditableType content_editable =
        html_element->contentEditableNormalized();
    if (content_editable == ContentEditableType::kContentEditable ||
        content_editable == ContentEditableType::kPlaintextOnly)
      return true;
    if (html_element->GetDocument().InDesignMode() &&
        html_element->isConnected()) {
      return true;
    }
    if (content_editable == ContentEditableType::kNotContentEditable)
      return false;
  }
  if (!node.parentNode())
    return false;
  if (!IsEditableOrEditingHost(*node.parentNode()))
    return false;
  if (html_element)
    return true;
  if (IsA<SVGSVGElement>(node))
    return true;
  if (auto* mathml_element = DynamicTo<MathMLElement>(node))
    return mathml_element->HasTagName(mathml_names::kMathTag);
  return !IsA<Element>(node) && node.parentNode()->IsHTMLElement();
}

const WebFeature kNoWebFeature = static_cast<WebFeature>(0);

class PopoverCloseWatcherEventListener : public NativeEventListener {
 public:
  explicit PopoverCloseWatcherEventListener(HTMLElement* popover)
      : popover_(popover) {}

  void Invoke(ExecutionContext*, Event* event) override {
    if (!popover_) {
      return;
    }
    // Don't do anything in response to cancel events, as per the HTML spec
    if (event->type() == event_type_names::kClose) {
      popover_->HidePopoverInternal(
          HidePopoverFocusBehavior::kFocusPreviousElement,
          HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
          /*exception_state=*/nullptr);
    }
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(popover_);
    NativeEventListener::Trace(visitor);
  }

 private:
  WeakMember<HTMLElement> popover_;
};

class NameInHeapSnapshotBuilder : public MarkupAccumulator {
 public:
  NameInHeapSnapshotBuilder()
      : MarkupAccumulator(kDoNotResolveURLs,
                          SerializationType::kHTML,
                          ShadowRootInclusion(),
                          MarkupAccumulator::AttributesMode::kUnsynchronized) {}
  String GetStartTag(const Element& element) {
    AppendElement(element);
    return markup_.ToString();
  }
};

}  // anonymous namespace

String HTMLElement::nodeName() const {
  // FIXME: Would be nice to have an atomicstring lookup based off uppercase
  // chars that does not have to copy the string on a hit in the hash.
  // FIXME: We should have a way to detect XHTML elements and replace the
  // hasPrefix() check with it.
  if (IsA<HTMLDocument>(GetDocument())) {
    if (!TagQName().HasPrefix())
      return TagQName().LocalNameUpper();
    return Element::nodeName().UpperASCII();
  }
  return Element::nodeName();
}

const char* HTMLElement::NameInHeapSnapshot() const {
  if (!ThreadState::Current()->IsTakingHeapSnapshot()) {
    // If a heap snapshot is not in progress, we must return a string with
    // static lifetime rather than allocating something.
    return Element::NameInHeapSnapshot();
  }
  NameInHeapSnapshotBuilder builder;
  String start_tag = builder.GetStartTag(*this);
  std::string utf_8 = start_tag.Utf8();
  return ThreadState::Current()->CopyNameForHeapSnapshot(utf_8.c_str());
}

bool HTMLElement::ShouldSerializeEndTag() const {
  // See https://www.w3.org/TR/DOM-Parsing/
  if (HasTagName(html_names::kAreaTag) || HasTagName(html_names::kBaseTag) ||
      HasTagName(html_names::kBasefontTag) ||
      HasTagName(html_names::kBgsoundTag) || HasTagName(html_names::kBrTag) ||
      HasTagName(html_names::kColTag) || HasTagName(html_names::kEmbedTag) ||
      HasTagName(html_names::kFrameTag) || HasTagName(html_names::kHrTag) ||
      HasTagName(html_names::kImgTag) || HasTagName(html_names::kInputTag) ||
      HasTagName(html_names::kKeygenTag) || HasTagName(html_names::kLinkTag) ||
      HasTagName(html_names::kMetaTag) || HasTagName(html_names::kParamTag) ||
      HasTagName(html_names::kSourceTag) || HasTagName(html_names::kTrackTag) ||
      HasTagName(html_names::kWbrTag))
    return false;
  return true;
}

static inline CSSValueID UnicodeBidiAttributeForDirAuto(HTMLElement* element) {
  DCHECK(!element->HasTagName(html_names::kBdoTag));
  DCHECK(!element->HasTagName(html_names::kTextareaTag));
  DCHECK(!element->HasTagName(html_names::kPreTag));
  if (auto* input_element = DynamicTo<HTMLInputElement>(element)) {
    // https://html.spec.whatwg.org/multipage/rendering.html#bidi-rendering has
    // prescribed UA stylesheet rules for type=search|tel|url|email with
    // dir=auto, setting unicode-bidi: plaintext. However, those rules need
    // `:is()`, so this is implemented here, rather than in html.css.
    switch (input_element->FormControlType()) {
      case FormControlType::kInputSearch:
      case FormControlType::kInputTelephone:
      case FormControlType::kInputUrl:
      case FormControlType::kInputEmail:
        return CSSValueID::kPlaintext;
      default:
        return CSSValueID::kIsolate;
    }
  }
  return CSSValueID::kIsolate;
}

unsigned HTMLElement::ParseBorderWidthAttribute(
    const AtomicString& value) const {
  unsigned border_width = 0;
  if (value.empty() || !ParseHTMLNonNegativeInteger(value, border_width)) {
    if (HasTagName(html_names::kTableTag) && !value.IsNull())
      return 1;
  }
  return border_width;
}

void HTMLElement::ApplyBorderAttributeToStyle(
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  unsigned width = ParseBorderWidthAttribute(value);
  for (CSSPropertyID property_id :
       {CSSPropertyID::kBorderTopWidth, CSSPropertyID::kBorderBottomWidth,
        CSSPropertyID::kBorderLeftWidth, CSSPropertyID::kBorderRightWidth}) {
    AddPropertyToPresentationAttributeStyle(
        style, property_id, width, CSSPrimitiveValue::UnitType::kPixels);
  }
  for (CSSPropertyID property_id :
       {CSSPropertyID::kBorderTopStyle, CSSPropertyID::kBorderBottomStyle,
        CSSPropertyID::kBorderLeftStyle, CSSPropertyID::kBorderRightStyle}) {
    AddPropertyToPresentationAttributeStyle(style, property_id,
                                            CSSValueID::kSolid);
  }
}

bool HTMLElement::IsPresentationAttribute(const QualifiedName& name) const {
  if (name == html_names::kAlignAttr ||
      name == html_names::kContenteditableAttr ||
      name == html_names::kHiddenAttr || name == html_names::kLangAttr ||
      name.Matches(xml_names::kLangAttr) ||
      name == html_names::kDraggableAttr || name == html_names::kDirAttr ||
      name == html_names::kInertAttr)
    return true;
  return Element::IsPresentationAttribute(name);
}

bool HTMLElement::IsValidDirAttribute(const AtomicString& value) {
  return EqualIgnoringASCIICase(value, "auto") ||
         EqualIgnoringASCIICase(value, "ltr") ||
         EqualIgnoringASCIICase(value, "rtl");
}

void HTMLElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kAlignAttr) {
    if (EqualIgnoringASCIICase(value, "middle")) {
      AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kTextAlign,
                                              CSSValueID::kCenter);
    } else {
      AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kTextAlign,
                                              value);
    }
  } else if (name == html_names::kContenteditableAttr) {
    AtomicString lower_value = value.LowerASCII();
    if (lower_value.empty() || lower_value == keywords::kTrue) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitUserModify, CSSValueID::kReadWrite);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kOverflowWrap, CSSValueID::kBreakWord);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitLineBreak, CSSValueID::kAfterWhiteSpace);
      UseCounter::Count(GetDocument(), WebFeature::kContentEditableTrue);
      if (HasTagName(html_names::kHTMLTag)) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kContentEditableTrueOnHTML);
      }
    } else if (lower_value == keywords::kPlaintextOnly) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitUserModify,
          CSSValueID::kReadWritePlaintextOnly);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kOverflowWrap, CSSValueID::kBreakWord);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitLineBreak, CSSValueID::kAfterWhiteSpace);
      UseCounter::Count(GetDocument(),
                        WebFeature::kContentEditablePlainTextOnly);
    } else if (lower_value == keywords::kFalse) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitUserModify, CSSValueID::kReadOnly);
    }
  } else if (name == html_names::kHiddenAttr) {
    if (EqualIgnoringASCIICase(value, "until-found")) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kContentVisibility, CSSValueID::kHidden);
      UseCounter::Count(GetDocument(), WebFeature::kHiddenUntilFoundAttribute);
    } else {
      AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kDisplay,
                                              CSSValueID::kNone);
      UseCounter::Count(GetDocument(), WebFeature::kHiddenAttribute);
    }
  } else if (name == html_names::kDraggableAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kDraggableAttribute);
    if (EqualIgnoringASCIICase(value, keywords::kTrue)) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitUserDrag, CSSValueID::kElement);
      AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kUserSelect,
                                              CSSValueID::kNone);
    } else if (EqualIgnoringASCIICase(value, keywords::kFalse)) {
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWebkitUserDrag, CSSValueID::kNone);
    }
  } else if (name == html_names::kDirAttr) {
    // This chunk of code interacts with the html.css stylesheet rule labelled
    // with `rendering.html#bidi-rendering`. Make sure any changes here are
    // congruent with changes made there.
    if (EqualIgnoringASCIICase(value, "auto")) {
      // These three are handled by the UA stylesheet.
      if (!HasTagName(html_names::kBdoTag) &&
          !HasTagName(html_names::kTextareaTag) &&
          !HasTagName(html_names::kPreTag)) {
        AddPropertyToPresentationAttributeStyle(
            style, CSSPropertyID::kUnicodeBidi,
            UnicodeBidiAttributeForDirAuto(this));
      }
    } else {
      if (IsValidDirAttribute(value)) {
        AddPropertyToPresentationAttributeStyle(
            style, CSSPropertyID::kDirection, value);
      } else if (IsA<HTMLBodyElement>(*this)) {
        AddPropertyToPresentationAttributeStyle(
            style, CSSPropertyID::kDirection, "ltr");
      }
    }
  } else if (name.Matches(xml_names::kLangAttr)) {
    MapLanguageAttributeToLocale(value, style);
  } else if (name == html_names::kLangAttr) {
    // xml:lang has a higher priority than lang.
    if (!FastHasAttribute(xml_names::kLangAttr))
      MapLanguageAttributeToLocale(value, style);
  } else {
    Element::CollectStyleForPresentationAttribute(name, value, style);
  }
}

// static
AttributeTriggers* HTMLElement::TriggersForAttributeName(
    const QualifiedName& attr_name) {
  const AtomicString& kNoEvent = g_null_atom;
  static AttributeTriggers attribute_triggers[] = {
      {html_names::kDirAttr, kNoWebFeature, kNoEvent,
       &HTMLElement::OnDirAttrChanged},
      {html_names::kFormAttr, kNoWebFeature, kNoEvent,
       &HTMLElement::OnFormAttrChanged},
      {html_names::kLangAttr, kNoWebFeature, kNoEvent,
       &HTMLElement::OnLangAttrChanged},
      {html_names::kNonceAttr, kNoWebFeature, kNoEvent,
       &HTMLElement::OnNonceAttrChanged},
      {html_names::kPopoverAttr, kNoWebFeature, kNoEvent,
       &HTMLElement::OnPopoverChanged},

      {html_names::kOnabortAttr, kNoWebFeature, event_type_names::kAbort,
       nullptr},
      {html_names::kOnanimationendAttr, kNoWebFeature,
       event_type_names::kAnimationend, nullptr},
      {html_names::kOnanimationiterationAttr, kNoWebFeature,
       event_type_names::kAnimationiteration, nullptr},
      {html_names::kOnanimationstartAttr, kNoWebFeature,
       event_type_names::kAnimationstart, nullptr},
      {html_names::kOnauxclickAttr, kNoWebFeature, event_type_names::kAuxclick,
       nullptr},
      {html_names::kOnbeforecopyAttr, kNoWebFeature,
       event_type_names::kBeforecopy, nullptr},
      {html_names::kOnbeforecutAttr, kNoWebFeature,
       event_type_names::kBeforecut, nullptr},
      {html_names::kOnbeforeinputAttr, kNoWebFeature,
       event_type_names::kBeforeinput, nullptr},
      {html_names::kOnbeforepasteAttr, kNoWebFeature,
       event_type_names::kBeforepaste, nullptr},
      {html_names::kOnbeforetoggleAttr, kNoWebFeature,
       event_type_names::kBeforetoggle, nullptr},
      {html_names::kOnblurAttr, kNoWebFeature, event_type_names::kBlur,
       nullptr},
      {html_names::kOncancelAttr, kNoWebFeature, event_type_names::kCancel,
       nullptr},
      {html_names::kOncanplayAttr, kNoWebFeature, event_type_names::kCanplay,
       nullptr},
      {html_names::kOncanplaythroughAttr, kNoWebFeature,
       event_type_names::kCanplaythrough, nullptr},
      {html_names::kOnchangeAttr, kNoWebFeature, event_type_names::kChange,
       nullptr},
      {html_names::kOnclickAttr, kNoWebFeature, event_type_names::kClick,
       nullptr},
      {html_names::kOncloseAttr, kNoWebFeature, event_type_names::kClose,
       nullptr},
      {html_names::kOncontentvisibilityautostatechangeAttr, kNoWebFeature,
       event_type_names::kContentvisibilityautostatechange, nullptr},
      {html_names::kOncontextlostAttr, kNoWebFeature,
       event_type_names::kContextlost, nullptr},
      {html_names::kOncontextmenuAttr, kNoWebFeature,
       event_type_names::kContextmenu, nullptr},
      {html_names::kOncontextrestoredAttr, kNoWebFeature,
       event_type_names::kContextrestored, nullptr},
      {html_names::kOncopyAttr, kNoWebFeature, event_type_names::kCopy,
       nullptr},
      {html_names::kOncuechangeAttr, kNoWebFeature,
       event_type_names::kCuechange, nullptr},
      {html_names::kOncutAttr, kNoWebFeature, event_type_names::kCut, nullptr},
      {html_names::kOndblclickAttr, kNoWebFeature, event_type_names::kDblclick,
       nullptr},
      {html_names::kOndismissAttr, kNoWebFeature, event_type_names::kDismiss,
       nullptr},
      {html_names::kOndragAttr, kNoWebFeature, event_type_names::kDrag,
       nullptr},
      {html_names::kOndragendAttr, kNoWebFeature, event_type_names::kDragend,
       nullptr},
      {html_names::kOndragenterAttr, kNoWebFeature,
       event_type_names::kDragenter, nullptr},
      {html_names::kOndragleaveAttr, kNoWebFeature,
       event_type_names::kDragleave, nullptr},
      {html_names::kOndragoverAttr, kNoWebFeature, event_type_names::kDragover,
       nullptr},
      {html_names::kOndragstartAttr, kNoWebFeature,
       event_type_names::kDragstart, nullptr},
      {html_names::kOndropAttr, kNoWebFeature, event_type_names::kDrop,
       nullptr},
      {html_names::kOndurationchangeAttr, kNoWebFeature,
       event_type_names::kDurationchange, nullptr},
      {html_names::kOnemptiedAttr, kNoWebFeature, event_type_names::kEmptied,
       nullptr},
      {html_names::kOnendedAttr, kNoWebFeature, event_type_names::kEnded,
       nullptr},
      {html_names::kOnerrorAttr, kNoWebFeature, event_type_names::kError,
       nullptr},
      {html_names::kOnfocusAttr, kNoWebFeature, event_type_names::kFocus,
       nullptr},
      {html_names::kOnfocusinAttr, kNoWebFeature, event_type_names::kFocusin,
       nullptr},
      {html_names::kOnfocusoutAttr, kNoWebFeature, event_type_names::kFocusout,
       nullptr},
      {html_names::kOnformdataAttr, kNoWebFeature, event_type_names::kFormdata,
       nullptr},
      {html_names::kOngotpointercaptureAttr, kNoWebFeature,
       event_type_names::kGotpointercapture, nullptr},
      {html_names::kOninputAttr, kNoWebFeature, event_type_names::kInput,
       nullptr},
      {html_names::kOninvalidAttr, kNoWebFeature, event_type_names::kInvalid,
       nullptr},
      {html_names::kOnkeydownAttr, kNoWebFeature, event_type_names::kKeydown,
       nullptr},
      {html_names::kOnkeypressAttr, kNoWebFeature, event_type_names::kKeypress,
       nullptr},
      {html_names::kOnkeyupAttr, kNoWebFeature, event_type_names::kKeyup,
       nullptr},
      {html_names::kOnloadAttr, kNoWebFeature, event_type_names::kLoad,
       nullptr},
      {html_names::kOnloadeddataAttr, kNoWebFeature,
       event_type_names::kLoadeddata, nullptr},
      {html_names::kOnloadedmetadataAttr, kNoWebFeature,
       event_type_names::kLoadedmetadata, nullptr},
      {html_names::kOnloadstartAttr, kNoWebFeature,
       event_type_names::kLoadstart, nullptr},
      {html_names::kOnlostpointercaptureAttr, kNoWebFeature,
       event_type_names::kLostpointercapture, nullptr},
      {html_names::kOnmousedownAttr, kNoWebFeature,
       event_type_names::kMousedown, nullptr},
      {html_names::kOnmouseenterAttr, kNoWebFeature,
       event_type_names::kMouseenter, nullptr},
      {html_names::kOnmouseleaveAttr, kNoWebFeature,
       event_type_names::kMouseleave, nullptr},
      {html_names::kOnmousemoveAttr, kNoWebFeature,
       event_type_names::kMousemove, nullptr},
      {html_names::kOnmouseoutAttr, kNoWebFeature, event_type_names::kMouseout,
       nullptr},
      {html_names::kOnmouseoverAttr, kNoWebFeature,
       event_type_names::kMouseover, nullptr},
      {html_names::kOnmouseupAttr, kNoWebFeature, event_type_names::kMouseup,
       nullptr},
      {html_names::kOnmousewheelAttr, kNoWebFeature,
       event_type_names::kMousewheel, nullptr},
      {html_names::kOnoverscrollAttr, kNoWebFeature,
       event_type_names::kOverscroll, nullptr},
      {html_names::kOnpasteAttr, kNoWebFeature, event_type_names::kPaste,
       nullptr},
      {html_names::kOnpauseAttr, kNoWebFeature, event_type_names::kPause,
       nullptr},
      {html_names::kOnplayAttr, kNoWebFeature, event_type_names::kPlay,
       nullptr},
      {html_names::kOnplayingAttr, kNoWebFeature, event_type_names::kPlaying,
       nullptr},
      {html_names::kOnpointercancelAttr, kNoWebFeature,
       event_type_names::kPointercancel, nullptr},
      {html_names::kOnpointerdownAttr, kNoWebFeature,
       event_type_names::kPointerdown, nullptr},
      {html_names::kOnpointerenterAttr, kNoWebFeature,
       event_type_names::kPointerenter, nullptr},
      {html_names::kOnpointerleaveAttr, kNoWebFeature,
       event_type_names::kPointerleave, nullptr},
      {html_names::kOnpointermoveAttr, kNoWebFeature,
       event_type_names::kPointermove, nullptr},
      {html_names::kOnpointeroutAttr, kNoWebFeature,
       event_type_names::kPointerout, nullptr},
      {html_names::kOnpointeroverAttr, kNoWebFeature,
       event_type_names::kPointerover, nullptr},
      {html_names::kOnpointerrawupdateAttr, kNoWebFeature,
       event_type_names::kPointerrawupdate, nullptr},
      {html_names::kOnpointerupAttr, kNoWebFeature,
       event_type_names::kPointerup, nullptr},
      {html_names::kOnprogressAttr, kNoWebFeature, event_type_names::kProgress,
       nullptr},
      {html_names::kOnratechangeAttr, kNoWebFeature,
       event_type_names::kRatechange, nullptr},
      {html_names::kOnresetAttr, kNoWebFeature, event_type_names::kReset,
       nullptr},
      {html_names::kOnresizeAttr, kNoWebFeature, event_type_names::kResize,
       nullptr},
      {html_names::kOnresolveAttr, kNoWebFeature, event_type_names::kResolve,
       nullptr},
      {html_names::kOnscrollAttr, kNoWebFeature, event_type_names::kScroll,
       nullptr},
      {html_names::kOnscrollendAttr, kNoWebFeature,
       event_type_names::kScrollend, nullptr},
      {html_names::kOnseekedAttr, kNoWebFeature, event_type_names::kSeeked,
       nullptr},
      {html_names::kOnseekingAttr, kNoWebFeature, event_type_names::kSeeking,
       nullptr},
      {html_names::kOnsecuritypolicyviolationAttr, kNoWebFeature,
       event_type_names::kSecuritypolicyviolation, nullptr},
      {html_names::kOnselectAttr, kNoWebFeature, event_type_names::kSelect,
       nullptr},
      {html_names::kOnselectstartAttr, kNoWebFeature,
       event_type_names::kSelectstart, nullptr},
      {html_names::kOnslotchangeAttr, kNoWebFeature,
       event_type_names::kSlotchange, nullptr},
      {html_names::kOnscrollsnapchangeAttr, kNoWebFeature,
       event_type_names::kScrollsnapchange, nullptr},
      {html_names::kOnscrollsnapchangingAttr, kNoWebFeature,
       event_type_names::kScrollsnapchanging, nullptr},
      {html_names::kOnstalledAttr, kNoWebFeature, event_type_names::kStalled,
       nullptr},
      {html_names::kOnsubmitAttr, kNoWebFeature, event_type_names::kSubmit,
       nullptr},
      {html_names::kOnsuspendAttr, kNoWebFeature, event_type_names::kSuspend,
       nullptr},
      {html_names::kOntimeupdateAttr, kNoWebFeature,
       event_type_names::kTimeupdate, nullptr},
      {html_names::kOntoggleAttr, kNoWebFeature, event_type_names::kToggle,
       nullptr},
      {html_names::kOntouchcancelAttr, kNoWebFeature,
       event_type_names::kTouchcancel, nullptr},
      {html_names::kOntouchendAttr, kNoWebFeature, event_type_names::kTouchend,
       nullptr},
      {html_names::kOntouchmoveAttr, kNoWebFeature,
       event_type_names::kTouchmove, nullptr},
      {html_names::kOntouchstartAttr, kNoWebFeature,
       event_type_names::kTouchstart, nullptr},
      {html_names::kOntransitionendAttr, kNoWebFeature,
       event_type_names::kWebkitTransitionEnd, nullptr},
      {html_names::kOnvalidationstatuschangeAttr, kNoWebFeature,
       event_type_names::kValidationstatuschange, nullptr},
      {html_names::kOnvolumechangeAttr, kNoWebFeature,
       event_type_names::kVolumechange, nullptr},
      {html_names::kOnwaitingAttr, kNoWebFeature, event_type_names::kWaiting,
       nullptr},
      {html_names::kOnwebkitanimationendAttr, kNoWebFeature,
       event_type_names::kWebkitAnimationEnd, nullptr},
      {html_names::kOnwebkitanimationiterationAttr, kNoWebFeature,
       event_type_names::kWebkitAnimationIteration, nullptr},
      {html_names::kOnwebkitanimationstartAttr, kNoWebFeature,
       event_type_names::kWebkitAnimationStart, nullptr},
      {html_names::kOnwebkitfullscreenchangeAttr, kNoWebFeature,
       event_type_names::kWebkitfullscreenchange, nullptr},
      {html_names::kOnwebkitfullscreenerrorAttr, kNoWebFeature,
       event_type_names::kWebkitfullscreenerror, nullptr},
      {html_names::kOnwebkittransitionendAttr, kNoWebFeature,
       event_type_names::kWebkitTransitionEnd, nullptr},
      {html_names::kOnwheelAttr, kNoWebFeature, event_type_names::kWheel,
       nullptr},

      // Begin ARIA attributes.
      {html_names::kAriaActionsAttr, WebFeature::kARIAActionsAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaActivedescendantAttr,
       WebFeature::kARIAActiveDescendantAttribute, kNoEvent, nullptr},
      {html_names::kAriaAtomicAttr, WebFeature::kARIAAtomicAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaAutocompleteAttr,
       WebFeature::kARIAAutocompleteAttribute, kNoEvent, nullptr},
```
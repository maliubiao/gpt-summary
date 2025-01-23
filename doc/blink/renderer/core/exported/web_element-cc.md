Response:
Let's break down the thought process for analyzing the `web_element.cc` file.

**1. Initial Understanding - What is this?**

The first line gives us a crucial clue: `blink/renderer/core/exported/web_element.cc`. The `exported` directory strongly suggests this is a public API intended for use outside the core Blink rendering engine. The name `web_element` hints at a representation of an HTML element in this public API. The copyright notice confirms it's part of the Chromium project.

**2. High-Level Functionality - What does it *do*?**

Skimming the `#include` directives reveals the core purpose. It includes:

* `web/web_element.h`: The header file likely defining the `WebElement` class.
* `bindings/core/v8/v8_element.h`:  Indicates interaction with the V8 JavaScript engine.
* `core/dom/element.h`:  Shows it's a wrapper around the internal Blink `Element` class.
* Various `core/clipboard`, `core/css`, `core/editing`, `core/events`, `core/frame`, `core/html` headers: This tells us `WebElement` provides access to element properties and functionalities related to these areas.

Therefore, the primary function is to provide a **public interface to interact with HTML elements** within the Blink rendering engine, making them accessible from other parts of Chromium, especially those interacting with web content (like the browser UI or DevTools).

**3. Detailed Analysis - Examining the Methods:**

Now, we go through the methods defined in the file. For each method, we ask:

* **What does it do?** (Based on its name and included headers).
* **How does it relate to HTML, CSS, and JavaScript?**
* **Are there any potential user/programmer errors?**
* **How might a user action lead to this code being executed?**

Let's exemplify with a few key methods:

* **`FromV8Value`:**  The name and the inclusion of `v8_element.h` immediately suggest this is used to create a `WebElement` from a JavaScript `Element` object.

* **`IsFormControlElement`:** The name is self-explanatory. This relates to HTML form elements. A user interacting with a form would trigger this.

* **`IsEditable`:** Checks if an element is editable. This involves both HTML attributes (like `contenteditable`) and potentially CSS (although the comment hints at a better way). User interaction: Clicking into an editable area.

* **`TagName`, `GetIdAttribute`, `HasAttribute`, `GetAttribute`, `SetAttribute`:** These are straightforward accessors and mutators for HTML attributes. JavaScript code manipulating the DOM would often use these. User interaction: Inspecting an element in DevTools and modifying its attributes.

* **`TextContent`, `InnerHTML`:**  These provide access to the text content and HTML content of an element, respectively. JavaScript can read and write these properties. User interaction: Viewing the text or structure of a webpage.

* **`SelectedText`, `SelectText`:**  These deal with text selection. JavaScript can programmatically select text. User interaction: Selecting text with the mouse.

* **`PasteText`:** Simulates pasting. This is directly related to the "paste" event and clipboard operations. User interaction: Using Ctrl+V or the context menu to paste.

* **`Labels`:** Gets the associated `<label>` elements for a form control. This relates directly to the HTML `<label>` tag. User interaction: Clicking on a label to focus its associated input.

* **`ShadowRoot`, `OwnerShadowHost`:**  Deal with Shadow DOM, a web component technology. JavaScript interacts heavily with Shadow DOM.

* **`BoundsInWidget`, `ImageContents`, `CopyOfImageData`, `ImageExtension`, `GetImageSize`, `GetClientSize`, `GetScrollSize`:** These relate to the visual representation and properties of the element, including images. CSS styling and layout calculations influence these. User interaction: Inspecting element dimensions in DevTools, viewing images.

* **`GetComputedValue`:** This is critical for understanding how CSS styles are applied. JavaScript uses `getComputedStyle` which maps to this. User interaction: Inspecting the computed styles of an element in DevTools.

**4. Logical Inference and Examples:**

Once the methods are understood, constructing examples becomes easier. For instance, for `SetAttribute`:

* **Hypothesis:** Setting an attribute via this method will change the element's HTML.
* **Input:**  Calling `SetAttribute("class", "new-class")` on an element.
* **Output:** The element in the DOM will now have the class "new-class".

Similarly, for `PasteText`:

* **Hypothesis:** This method will insert text into an editable element as if the user pasted it.
* **Input:** Calling `PasteText("Some text", false)` on a focused text input.
* **Output:** "Some text" will be inserted at the current cursor position in the input.

**5. Identifying User/Programmer Errors:**

By thinking about how each method is used, potential errors become apparent.

* **`SetAttribute`:** Setting an invalid attribute name.
* **`PasteText`:** Calling it on a non-editable element.
* **`GetComputedValue`:**  Using an invalid CSS property name.

**6. Tracing User Actions:**

This involves connecting user interactions with the underlying Blink code. For example:

* **User types in a text field:**  This triggers events that eventually lead to the `PasteText` logic (if the text is being pasted) or other text manipulation within the editable element.
* **User clicks on a button:** This might trigger JavaScript that calls methods like `SetAttribute` or `SelectText`.
* **User opens DevTools and inspects an element:** This will lead to Blink retrieving element properties via methods like `TagName`, `GetAttribute`, `GetComputedValue`, etc.

**7. Structuring the Response:**

Finally, organize the information logically, starting with the overall functionality, then detailing individual methods with their relations to HTML, CSS, JavaScript, examples, errors, and user actions. Use clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial broad strokes might need refinement:**  Instead of just saying "manipulates elements," be specific about *what* manipulations are possible (attributes, text content, selection, etc.).
* **Connect to specific web technologies:**  Don't just say "related to web pages."  Mention HTML, CSS, JavaScript, Shadow DOM, etc.
* **Ensure examples are concrete and easy to understand.**
* **Double-check the `#include` directives:** They provide strong hints about the functionality.
* **Consider the "exported" aspect:** This highlights that the file is part of a public API and therefore needs to be robust and well-defined.

By following these steps, you can systematically analyze a source code file and understand its purpose, functionality, and connections to other technologies. The key is to move from the general to the specific and to constantly ask "why" and "how" for each piece of code.
好的，让我们来分析一下 `blink/renderer/core/exported/web_element.cc` 这个文件。

**文件功能总览:**

`web_element.cc` 文件定义了 `blink::WebElement` 类，这个类是 Blink 渲染引擎中对 HTML 元素的 **公共接口**。它提供了一组方法，允许 Chromium 的其他组件（例如，浏览器 UI，开发者工具等）以及外部代码，以一种类型安全且封装的方式与底层的 Blink 元素对象进行交互。

**与 JavaScript, HTML, CSS 的关系及举例:**

`WebElement` 作为公共接口，其功能与 JavaScript, HTML, CSS 都有着密切的关系。它提供的方法允许外部代码获取和操作元素的各种属性和状态，这些属性和状态最终都反映在渲染出的网页上。

**1. 与 HTML 的关系:**

* **获取/设置 HTML 属性:**
    * `TagName()`: 获取元素的标签名 (例如 "div", "p", "span")。
    * `GetIdAttribute()`: 获取元素的 `id` 属性值。
    * `HasHTMLTagName(const WebString& tag_name)`: 检查元素是否是指定的 HTML 标签。
    * `HasAttribute(const WebString& attr_name)`: 检查元素是否拥有指定的属性。
    * `GetAttribute(const WebString& attr_name)`: 获取元素的指定属性值。
    * `SetAttribute(const WebString& attr_name, const WebString& attr_value)`: 设置元素的指定属性值。

    **例子:**
    * **假设输入 (JavaScript 调用):**  `element.tagName()`
    * **输出:**  如果 `element` 是一个 `<div>` 元素，则输出 "div"。
    * **用户操作:** 用户在开发者工具中选中一个元素，开发者工具会调用 `TagName()` 来显示元素的标签名。

* **获取/设置 HTML 内容:**
    * `TextContent()`: 获取元素的文本内容（包括所有后代元素的文本）。
    * `InnerHTML()`: 获取元素的 HTML 内容（包括所有后代元素的 HTML 标签）。

    **例子:**
    * **假设输入 (JavaScript 调用):** `element.textContent`
    * **HTML 内容:** `<div>Hello <span>World</span></div>`
    * **输出:** "Hello World"
    * **假设输入 (JavaScript 调用):** `element.innerHTML`
    * **输出:** "Hello <span>World</span>"
    * **用户操作:** 用户在开发者工具的 "Elements" 面板中查看元素的文本内容或内部 HTML。

* **访问关联的 `<label>` 元素:**
    * `Labels()`: 获取与表单控件元素关联的 `<label>` 元素列表。

    **例子:**
    * **HTML 内容:** `<label for="name">Name:</label><input type="text" id="name">`
    * **假设输入 (C++ 代码调用 `Labels()`):**  针对 `<input>` 元素调用。
    * **输出:** 包含 `<label>` 元素的 `WebVector<WebLabelElement>`。
    * **用户操作:** 当屏幕阅读器等辅助技术解析网页时，会用到标签的关联信息。

* **判断是否是自定义元素:**
    * `IsAutonomousCustomElement()`: 检查元素是否是自主自定义元素。

    **例子:**
    * **HTML 内容:** `<my-element></my-element>` (如果 `my-element` 已定义为自定义元素)
    * **假设输入 (C++ 代码调用 `IsAutonomousCustomElement()`):** 针对 `<my-element>` 元素调用。
    * **输出:** `true`
    * **用户操作:**  浏览器在解析和渲染自定义元素时会用到此信息。

**2. 与 CSS 的关系:**

* **获取计算后的 CSS 属性值:**
    * `GetComputedValue(const WebString& property_name)`: 获取元素指定 CSS 属性的计算后的值。

    **例子:**
    * **HTML 内容:** `<div style="color: red;"></div>`
    * **CSS 规则 (可能在外部样式表或 `<style>` 标签中):** `div { font-size: 16px; }`
    * **假设输入 (C++ 代码调用 `GetComputedValue()`):** 针对 `<div>` 元素调用 `GetComputedValue("color")` 和 `GetComputedValue("font-size")`。
    * **输出:** 分别为 "rgb(255, 0, 0)" 和 "16px"。
    * **用户操作:** 开发者工具的 "Computed" 面板会调用此方法来显示元素的最终样式。

* **获取元素在窗口中的边界:**
    * `BoundsInWidget()`: 获取元素在渲染窗口中的矩形边界。

    **例子:**
    * **假设 HTML 结构和 CSS 样式使得一个 `<div>` 元素显示在页面的 (10, 20) 位置，宽度 100px，高度 50px。**
    * **假设输入 (C++ 代码调用 `BoundsInWidget()`):** 针对该 `<div>` 元素调用。
    * **输出:**  一个表示矩形的 `gfx::Rect` 对象，其值为 `(10, 20, 100, 50)`。
    * **用户操作:** 开发者工具在绘制元素边界高亮时会用到此信息。

**3. 与 JavaScript 的关系:**

* **从 V8 值创建 `WebElement`:**
    * `FromV8Value(v8::Isolate* isolate, v8::Local<v8::Value> value)`:  将 JavaScript 中表示 DOM 元素的 V8 对象转换为 `WebElement` 对象。这是 Blink 内部 JavaScript 和 C++ 交互的重要桥梁。

    **例子:**
    * **假设输入 (Blink 内部代码接收到 JavaScript 调用):**  一个 V8 `Element` 对象。
    * **输出:**  对应的 `WebElement` 对象。
    * **场景:** 当 JavaScript 代码操作 DOM 元素后，Blink 需要将这些操作同步到 C++ 渲染层时，会用到此方法。

* **模拟粘贴操作:**
    * `PasteText(const WebString& text, bool replace_all)`:  模拟将指定的文本粘贴到元素中。

    **例子:**
    * **假设输入 (JavaScript 调用 `document.execCommand('paste')` 或者某些扩展触发粘贴操作):**  要粘贴的文本 "Hello"。
    * **输出:** 如果目标元素是可编辑的，则会将 "Hello" 插入到该元素中，并可能触发相关的事件 (如 `input` 事件)。
    * **用户操作:** 用户在可编辑区域使用 Ctrl+V 快捷键或右键菜单的 "粘贴" 功能。

* **文本选择操作:**
    * `SelectedText()`: 获取元素中选中的文本。
    * `SelectText(bool select_all)`: 选中元素中的文本。

    **例子:**
    * **假设输入 (JavaScript 调用 `window.getSelection().toString()`):**  获取用户选中的文本。Blink 内部会调用 `SelectedText()`。
    * **输出:** 用户选中的文本字符串。
    * **假设输入 (JavaScript 调用 `element.select()`):**  选中输入框中的所有文本。Blink 内部会调用 `SelectText(true)`。
    * **用户操作:** 用户使用鼠标拖拽选中文本，或者使用快捷键 (如 Ctrl+A) 全选文本。

* **焦点控制:**
    * 涉及到 `Focus()` 方法 (虽然在这个文件中没有直接定义，但 `SelectText` 方法内部使用了 `FocusParams`)，用于将焦点设置到元素上。

    **例子:**
    * **假设输入 (JavaScript 调用 `element.focus()`):**  将焦点移到一个输入框。
    * **输出:** 输入框获得焦点，可以接收键盘输入。
    * **用户操作:** 用户点击一个输入框或者按下 Tab 键切换焦点。

**逻辑推理的假设输入与输出:**

以下是一些基于 `WebElement` 方法的逻辑推理示例：

* **假设输入:**  `WebElement` 对象代表一个 `<input type="checkbox" id="myCheckbox">` 元素。
    * **调用 `TagName()`:** 输出 "input"。
    * **调用 `GetIdAttribute()`:** 输出 "myCheckbox"。
    * **调用 `HasHTMLTagName("input")`:** 输出 `true`。
    * **调用 `GetAttribute("type")`:** 输出 "checkbox"。
    * **调用 `IsFormControlElement()`:** 输出 `true`。

* **假设输入:** `WebElement` 对象代表一个 `<div style="color: blue; font-size: 18px;">Hello</div>` 元素。
    * **调用 `GetComputedValue("color")`:** 输出类似 "rgb(0, 0, 255)"。
    * **调用 `GetComputedValue("font-size")`:** 输出 "18px"。

**用户或编程常见的使用错误:**

* **在非可编辑元素上调用 `PasteText()`:**  这不会产生任何效果，因为目标元素不允许编辑。
* **传递无效的 CSS 属性名给 `GetComputedValue()`:**  该方法会返回一个空的 `WebString`。
* **尝试在 `WebElement` 对象为空时调用方法:**  例如，`WebElement` 是通过 `FromV8Value` 从 JavaScript 传递过来的，如果 JavaScript 传递了一个 `null` 或 `undefined`，则需要在使用前进行检查，否则可能会导致程序崩溃或未定义行为。
* **假设 `Labels()` 方法总是返回非空的 `WebVector`:**  并非所有元素都有关联的 `<label>` 元素，因此需要在使用返回的列表前检查其大小。

**用户操作如何一步步的到达这里 (调试线索):**

以下是一些用户操作可能最终触发 `web_element.cc` 中代码执行的场景，可以作为调试线索：

1. **页面加载和渲染:**
   * 用户在浏览器地址栏输入 URL 并回车。
   * Blink 接收 HTML、CSS 和 JavaScript 代码。
   * Blink 的 HTML 解析器创建 DOM 树，其中包含了各种 `Element` 对象。
   * 当需要将这些底层的 `Element` 对象暴露给 Chromium 的其他组件（例如，渲染树构建、布局计算、绘制等）时，会创建或使用 `WebElement` 对象作为中间接口。

2. **JavaScript DOM 操作:**
   * 网页上的 JavaScript 代码执行，例如：
     * `document.getElementById('myDiv')`:  JavaScript 获取 DOM 元素，Blink 会将底层的 `Element` 对象封装成 V8 对象返回给 JavaScript。
     * 修改元素属性：`element.setAttribute('class', 'newClass')`。Blink 接收到 JavaScript 的调用后，可能会通过 `WebElement::SetAttribute` 来修改底层的 `Element` 对象。
     * 获取元素信息：`element.tagName`，`element.textContent` 等。Blink 内部会调用 `WebElement` 相应的方法来获取信息。

3. **用户交互事件:**
   * 用户点击一个元素，触发 `click` 事件。
   * 用户在一个输入框中输入文本，触发 `input` 或 `change` 事件。
   * 用户选中一段文本。
   * 这些事件的处理可能会涉及到 JavaScript 代码的执行，而 JavaScript 代码又可能调用 DOM API 来获取或修改元素的状态，最终会触及 `WebElement` 提供的方法。

4. **开发者工具的使用:**
   * 用户打开开发者工具的 "Elements" 面板查看页面结构。开发者工具会调用 Blink 提供的接口（很可能就包括 `WebElement` 的方法）来获取元素的标签名、属性、样式等信息并显示出来。
   * 用户在开发者工具中修改元素的属性或样式。开发者工具的操作会调用 Blink 提供的接口来修改底层的元素对象。

5. **浏览器功能:**
   * 浏览器的 "复制" 和 "粘贴" 功能。当用户复制或粘贴文本时，Blink 会使用 `WebElement` 的相关方法来获取选中的文本或将文本粘贴到目标元素中。
   * 浏览器的自动填充功能。当浏览器尝试自动填充表单时，可能会使用 `WebElement` 的方法来设置表单控件的值。
   * 辅助功能（Accessibility）：屏幕阅读器等辅助技术会通过 Blink 提供的 API 获取页面元素的结构和内容信息，`WebElement` 在此过程中扮演重要角色。

**总结:**

`web_element.cc` 中定义的 `WebElement` 类是 Blink 渲染引擎对外提供元素操作能力的关键接口。理解这个文件的功能，有助于理解 Chromium 如何与网页内容进行交互，以及在调试过程中如何追踪与元素相关的行为。

### 提示词
```
这是目录为blink/renderer/core/exported/web_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/public/web/web_element.h"

#include "third_party/blink/public/web/web_label_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/events/clipboard_event.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

WebElement WebElement::FromV8Value(v8::Isolate* isolate,
                                   v8::Local<v8::Value> value) {
  Element* element = V8Element::ToWrappable(isolate, value);
  return WebElement(element);
}

bool WebElement::IsFormControlElement() const {
  return ConstUnwrap<Element>()->IsFormControlElement();
}

// TODO(dglazkov): Remove. Consumers of this code should use
// Node:hasEditableStyle.  http://crbug.com/612560
bool WebElement::IsEditable() const {
  const Element* element = ConstUnwrap<Element>();

  element->GetDocument().UpdateStyleAndLayoutTree();
  if (blink::IsEditable(*element))
    return true;

  if (auto* text_control = ToTextControlOrNull(element)) {
    if (!text_control->IsDisabledOrReadOnly())
      return true;
  }

  return EqualIgnoringASCIICase(
      element->FastGetAttribute(html_names::kRoleAttr), "textbox");
}

WebString WebElement::TagName() const {
  return ConstUnwrap<Element>()->tagName();
}

WebString WebElement::GetIdAttribute() const {
  return ConstUnwrap<Element>()->GetIdAttribute();
}

bool WebElement::HasHTMLTagName(const WebString& tag_name) const {
  const auto* html_element =
      blink::DynamicTo<HTMLElement>(ConstUnwrap<Element>());
  return html_element &&
         html_element->localName() == String(tag_name).LowerASCII();
}

bool WebElement::HasAttribute(const WebString& attr_name) const {
  return ConstUnwrap<Element>()->hasAttribute(attr_name);
}

WebString WebElement::GetAttribute(const WebString& attr_name) const {
  return ConstUnwrap<Element>()->getAttribute(attr_name);
}

void WebElement::SetAttribute(const WebString& attr_name,
                              const WebString& attr_value) {
  Unwrap<Element>()->setAttribute(attr_name, attr_value,
                                  IGNORE_EXCEPTION_FOR_TESTING);
}

WebString WebElement::TextContent() const {
  return ConstUnwrap<Element>()->textContent();
}
WebString WebElement::TextContentAbridged(const unsigned int max_length) const {
  return ConstUnwrap<Element>()->textContent(false, nullptr, max_length);
}

WebString WebElement::InnerHTML() const {
  return ConstUnwrap<Element>()->innerHTML();
}

bool WebElement::WritingSuggestions() const {
  const auto* html_element =
      blink::DynamicTo<HTMLElement>(ConstUnwrap<Element>());
  return html_element &&
         !EqualIgnoringASCIICase(html_element->writingSuggestions(),
                                 keywords::kFalse);
}

bool WebElement::ContainsFrameSelection() const {
  auto& e = *ConstUnwrap<Element>();
  LocalFrame* frame = e.GetDocument().GetFrame();
  if (!frame) {
    return false;
  }
  Element* root = frame->Selection().RootEditableElementOrDocumentElement();
  if (!root) {
    return false;
  }
  // For form controls, the selection's root editable is a contenteditable in
  // a shadow DOM tree.
  return (e.IsFormControlElement() ? root->OwnerShadowHost() : root) == e;
}

WebString WebElement::SelectedText() const {
  if (!ContainsFrameSelection()) {
    return "";
  }
  return ConstUnwrap<Element>()
      ->GetDocument()
      .GetFrame()
      ->Selection()
      .SelectedText(TextIteratorBehavior::Builder()
                        .SetEntersOpenShadowRoots(true)
                        .SetSkipsUnselectableContent(true)
                        .SetEntersTextControls(true)
                        .Build());
}

void WebElement::SelectText(bool select_all) {
  auto* element = Unwrap<Element>();
  LocalFrame* frame = element->GetDocument().GetFrame();
  if (!frame) {
    return;
  }

  // Makes sure the selection is inside `element`: if `select_all`, selects
  // all inside `element`; otherwise, selects an empty range at the end.
  if (auto* text_control_element =
          blink::DynamicTo<TextControlElement>(element)) {
    if (select_all) {
      text_control_element->select();
    } else {
      text_control_element->Focus(FocusParams(SelectionBehaviorOnFocus::kNone,
                                              mojom::blink::FocusType::kScript,
                                              nullptr, FocusOptions::Create()));
      text_control_element->setSelectionStart(std::numeric_limits<int>::max());
    }
  } else {
    Position base = FirstPositionInOrBeforeNode(*element);
    Position extent = LastPositionInOrAfterNode(*element);
    if (!select_all) {
      base = extent;
    }
    frame->Selection().SetSelection(
        SelectionInDOMTree::Builder().SetBaseAndExtent(base, extent).Build(),
        SetSelectionOptions());
  }
}

void WebElement::PasteText(const WebString& text, bool replace_all) {
  if (!IsEditable()) {
    return;
  }
  auto* element = Unwrap<Element>();
  LocalFrame* frame = element->GetDocument().GetFrame();
  if (!frame) {
    return;
  }

  // Returns true if JavaScript handlers destroyed the `frame`.
  auto is_destroyed = [](LocalFrame& frame) {
    return frame.GetDocument()->GetFrame() != frame;
  };

  if (replace_all || !ContainsFrameSelection()) {
    SelectText(replace_all);
    // JavaScript handlers may have destroyed the frame or moved the selection.
    if (is_destroyed(*frame) || !ContainsFrameSelection()) {
      return;
    }
  }

  // Simulates a paste command, except that it does not access the system
  // clipboard but instead pastes `text`. This block is a stripped-down version
  // of ClipboardCommands::Paste() that's limited to pasting plain text.
  Element* target = FindEventTargetFrom(
      *frame, frame->Selection().ComputeVisibleSelectionInDOMTree());
  auto create_data_transfer = [](const WebString& text) {
    return DataTransfer::Create(DataTransfer::kCopyAndPaste,
                                DataTransferAccessPolicy::kReadable,
                                DataObject::CreateFromString(text));
  };
  // Fires "paste" event.
  if (target->DispatchEvent(*ClipboardEvent::Create(
          event_type_names::kPaste, create_data_transfer(text))) !=
      DispatchEventResult::kNotCanceled) {
    return;
  }
  // Fires "beforeinput" event.
  if (DispatchBeforeInputDataTransfer(
          target, InputEvent::InputType::kInsertFromPaste,
          create_data_transfer(text)) != DispatchEventResult::kNotCanceled) {
    return;
  }
  // No DOM mutation if EditContext is active.
  if (frame->GetInputMethodController().GetActiveEditContext()) {
    return;
  }
  // Fires "textInput" and "input".
  target->DispatchEvent(
      *TextEvent::CreateForPlainTextPaste(frame->DomWindow(), text,
                                          /*should_smart_replace=*/true));
}

WebVector<WebLabelElement> WebElement::Labels() const {
  auto* html_element = blink::DynamicTo<HTMLElement>(ConstUnwrap<Element>());
  if (!html_element)
    return {};
  LabelsNodeList* html_labels =
      const_cast<HTMLElement*>(html_element)->labels();
  if (!html_labels)
    return {};
  Vector<WebLabelElement> labels;
  for (unsigned i = 0; i < html_labels->length(); i++) {
    if (auto* label_element =
            blink::DynamicTo<HTMLLabelElement>(html_labels->item(i))) {
      labels.push_back(label_element);
    }
  }
  return labels;
}

bool WebElement::IsAutonomousCustomElement() const {
  auto* element = ConstUnwrap<Element>();
  if (element->GetCustomElementState() == CustomElementState::kCustom)
    return CustomElement::IsValidName(element->localName());
  return false;
}

WebNode WebElement::ShadowRoot() const {
  auto* root = ConstUnwrap<Element>()->GetShadowRoot();
  if (!root || root->IsUserAgent())
    return WebNode();
  return WebNode(root);
}

WebElement WebElement::OwnerShadowHost() const {
  if (auto* host = ConstUnwrap<Element>()->OwnerShadowHost()) {
    return WebElement(host);
  }
  return WebElement();
}

WebNode WebElement::OpenOrClosedShadowRoot() {
  if (IsNull())
    return WebNode();

  auto* root = ConstUnwrap<Element>()->AuthorShadowRoot();
  return WebNode(root);
}

gfx::Rect WebElement::BoundsInWidget() const {
  return ConstUnwrap<Element>()->BoundsInWidget();
}

SkBitmap WebElement::ImageContents() {
  Image* image = GetImage();
  if (!image)
    return {};
  return image->AsSkBitmapForCurrentFrame(kRespectImageOrientation);
}

std::vector<uint8_t> WebElement::CopyOfImageData() {
  Image* image = GetImage();
  if (!image || !image->HasData())
    return std::vector<uint8_t>();
  return image->Data()->CopyAs<std::vector<uint8_t>>();
}

std::string WebElement::ImageExtension() {
  Image* image = GetImage();
  if (!image)
    return std::string();
  return image->FilenameExtension().Utf8();
}

gfx::Size WebElement::GetImageSize() {
  Image* image = GetImage();
  if (!image)
    return gfx::Size();
  return gfx::Size(image->width(), image->height());
}

gfx::Size WebElement::GetClientSize() const {
  Element* element = const_cast<Element*>(ConstUnwrap<Element>());
  return gfx::Size(element->clientWidth(), element->clientHeight());
}

gfx::Size WebElement::GetScrollSize() const {
  Element* element = const_cast<Element*>(ConstUnwrap<Element>());
  return gfx::Size(element->scrollWidth(), element->scrollHeight());
}

WebString WebElement::GetComputedValue(const WebString& property_name) {
  if (IsNull())
    return WebString();

  Element* element = Unwrap<Element>();
  CSSPropertyID property_id = CssPropertyID(
      element->GetDocument().GetExecutionContext(), property_name);
  if (property_id == CSSPropertyID::kInvalid)
    return WebString();

  element->GetDocument().UpdateStyleAndLayoutTree();
  auto* computed_style =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element);
  return computed_style->GetPropertyCSSValue(property_id)->CssText();
}

WebElement::WebElement(Element* elem) : WebNode(elem) {}

DEFINE_WEB_NODE_TYPE_CASTS(WebElement, IsElementNode())

WebElement& WebElement::operator=(Element* elem) {
  private_ = elem;
  return *this;
}

WebElement::operator Element*() const {
  return blink::To<Element>(private_.Get());
}

Image* WebElement::GetImage() {
  if (IsNull())
    return nullptr;
  return Unwrap<Element>()->ImageContents();
}

}  // namespace blink
```
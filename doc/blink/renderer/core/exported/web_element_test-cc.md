Response:
Let's break down the thought process for analyzing this `web_element_test.cc` file.

1. **Identify the Core Purpose:** The file name itself, `web_element_test.cc`, strongly suggests this is a test file. Specifically, it's testing the `WebElement` class. This is the most important initial deduction.

2. **Scan for Key Classes and Functions:**  Look for familiar C++ constructs and Blink-specific classes.
    * Includes:  `Web/WebElement.h`, `Web/WebDocument.h`, `Web/WebLabelElement.h`. These confirm we're dealing with the public Blink API.
    * Namespace: `blink`. This is the main namespace for the Blink rendering engine.
    * Test Framework: `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`. This immediately tells us it's using Google Test and Google Mock for its test structure.
    * Test Class: `WebElementTest` inheriting from `PageTestBase`. This pattern is common in Blink tests and signifies an integration test that sets up a minimal rendering environment.
    * Test Macros: `TEST_F`. This is the standard Google Test macro for defining test cases within a test fixture.

3. **Analyze the Test Fixture (`WebElementTest`):**
    * Protected Members: `InsertHTML`, `AddScript`, `TestElement`. These are helper functions for setting up the test environment.
        * `InsertHTML`:  Likely injects HTML content into the test document.
        * `AddScript`:  Likely adds and executes JavaScript code in the test document.
        * `TestElement`:  Likely retrieves the `WebElement` instance being tested, probably based on an `id`.

4. **Examine Individual Test Cases (`TEST_F` blocks):**  Go through each test case and try to understand what specific functionality of `WebElement` is being tested.
    * `IsEditable`:  Tests the `IsEditable()` method. Looks at various HTML attributes and CSS properties that influence editability.
    * `IsAutonomousCustomElement`: Tests the `IsAutonomousCustomElement()` method. Involves custom elements and JavaScript definition.
    * `SelectedTextOfContentEditable`: Tests `SelectedText()` and `ContainsFrameSelection()` in the context of `contenteditable` elements. This clearly relates to user interaction and text selection.
    * `SelectedTextOfTextArea`: Similar to the above, but focuses on `<textarea>` elements.
    * `SelectedTextEmptyDocument`: Tests edge cases where the document has no root.
    * `SelectTextOfTextArea` and `SelectTextOfContentEditable`: Test the `SelectText()` method, which programmatically selects text.
    * `PasteTextIntoContentEditable` and `PasteTextIntoTextArea`: Test the `PasteText()` method, simulating pasting text.
    * `PasteTextIsNoOpWhenPasteIsCancelled` and `PasteTextIsNoOpWhenBeforeInputIsCancelled`: Test scenarios where JavaScript event handlers prevent default pasting behavior. This shows interaction with the event system.
    * `ShadowRoot`: Tests the `ShadowRoot()` method, which retrieves the shadow root of an element. This is a key feature of Web Components.
    * `ComputedStyleProperties`: Tests the `GetComputedValue()` method, which retrieves computed CSS property values.
    * `Labels`: Tests the `Labels()` method, which retrieves associated `<label>` elements.

5. **Identify Connections to Web Technologies (JavaScript, HTML, CSS):**  As you analyze the test cases, explicitly note how they relate to these technologies:
    * **HTML:**  The tests heavily rely on inserting HTML snippets (`InsertHTML`). They test attributes like `contenteditable`, `readonly`, `disabled`, and the structure of the DOM.
    * **JavaScript:**  The `AddScript` function is used to define custom elements, and some tests check the interaction between JavaScript event handlers and `WebElement` methods (e.g., preventing default paste behavior).
    * **CSS:** The `ComputedStyleProperties` test directly interacts with CSS styles (both inline and in stylesheets) and verifies the `GetComputedValue()` method. The `IsEditable` test also considers CSS properties like `-webkit-user-modify`.

6. **Infer Logic and Assumptions:**  For each test case, try to understand the underlying logic. What is the input (the HTML structure, JavaScript code), and what is the expected output (the return value of the `WebElement` method, the state of the DOM)?  Consider edge cases and different scenarios.

7. **Consider User and Developer Errors:**  Think about how a developer might misuse the `WebElement` API or encounter unexpected behavior. The tests related to event cancellation during pasting are good examples of this.

8. **Trace User Actions (Debugging Clues):**  Imagine a user interacting with a web page and how that interaction might lead to the execution of the code being tested. For example, selecting text, focusing an element, or triggering a paste operation.

9. **Structure the Explanation:** Organize your findings into clear categories (Functionality, Relationship to Web Technologies, Logic/Assumptions, Common Errors, Debugging Clues). Use examples to illustrate your points.

10. **Refine and Elaborate:** Review your initial analysis and add more detail where necessary. For instance, when discussing `ComputedStyleProperties`, specify which CSS properties are being tested. When discussing user actions, provide more concrete steps.

By following these steps, you can systematically analyze the provided source code and produce a comprehensive explanation of its functionality and its relationship to web technologies. The key is to break down the problem into smaller, manageable parts and to connect the code back to its intended purpose and the broader context of web development.
这个文件 `web_element_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `blink::WebElement` 类的功能。`blink::WebElement` 是 Chromium 中对 DOM 元素进行抽象的 C++ 类，它提供了一组方法来访问和操作 DOM 元素的属性、状态以及与用户交互相关的功能。

以下是该文件的功能及其与 JavaScript、HTML、CSS 的关系、逻辑推理、常见错误以及调试线索的详细说明：

**功能列表:**

1. **测试 `IsEditable()` 方法:**  验证 `WebElement` 对象是否可编辑。这包括检查 `contenteditable` 属性、`-webkit-user-modify` CSS 属性以及表单控件的 `readonly` 和 `disabled` 属性。
2. **测试 `IsAutonomousCustomElement()` 方法:** 检查 `WebElement` 对象是否是一个自主定制元素。涉及到 JavaScript 中使用 `customElements.define` 定义的自定义元素。
3. **测试 `SelectedText()` 和 `ContainsFrameSelection()` 方法 (针对 contenteditable 元素):** 验证在可编辑元素中选中文字时的行为，包括获取选中文本和判断选区是否在元素内部。
4. **测试 `SelectedText()` 和 `ContainsFrameSelection()` 方法 (针对 textarea 元素):** 验证在 `<textarea>` 元素中选中文字时的行为。
5. **测试 `SelectedText()` 方法 (针对无根节点的文档):** 测试在没有根节点的文档中，对表单控件元素调用 `SelectedText()` 的行为。
6. **测试 `SelectText()` 方法 (针对 textarea 元素):** 验证使用 `SelectText()` 方法全选或取消全选 `<textarea>` 元素中的文本。
7. **测试 `SelectText()` 方法 (针对 contenteditable 元素):** 验证使用 `SelectText()` 方法全选或取消全选可编辑元素中的文本。
8. **测试 `PasteText()` 方法 (针对 contenteditable 元素):** 验证向可编辑元素粘贴文本的功能，包括替换选区和替换所有内容。
9. **测试 `PasteText()` 方法 (针对 textarea 元素):** 验证向 `<textarea>` 元素粘贴文本的功能。
10. **测试 `PasteText()` 方法在 `paste` 事件被取消时的行为:**  验证当 JavaScript 监听的 `paste` 事件调用 `preventDefault()` 时，`PasteText()` 方法是否会中止操作。
11. **测试 `PasteText()` 方法在 `beforeinput` 事件被取消时的行为:** 验证当 JavaScript 监听的 `beforeinput` 事件调用 `preventDefault()` 时，`PasteText()` 方法是否会中止操作。
12. **测试 `ShadowRoot()` 方法:** 验证获取元素的 Shadow DOM 根节点的功能。
13. **测试 `GetComputedValue()` 方法:** 验证获取元素计算后的 CSS 属性值的功能，包括读取和在修改内联样式后的读取。
14. **测试 `Labels()` 方法:** 验证获取与元素关联的 `<label>` 元素的功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  测试代码通过 `InsertHTML()` 方法插入各种 HTML 结构来测试 `WebElement` 的行为。例如：
    * 测试 `IsEditable()` 时，插入了带有 `contenteditable` 属性的 `<div>` 元素和带有 `readonly` 或 `disabled` 属性的 `<input>` 元素。
    * 测试自定义元素时，插入了 `<x-undefined>` 和通过 JavaScript 定义的自定义元素 `<v1-custom>` 和 `<button is="v1-builtin">`。
    * 测试选中文本时，插入了包含文本内容的 `<div>` 和 `<textarea>` 元素。
    * 测试 Shadow DOM 时，插入了 `<span>` 和 `<p>` 元素来附加 Shadow Root。
    * 测试 `Labels()` 时，插入了 `<label>` 和 `<input>` 元素，并使用 `for` 属性关联它们。

* **JavaScript:** 测试代码通过 `AddScript()` 方法执行 JavaScript 代码，以影响 `WebElement` 的行为或创建特定的测试场景。例如：
    * 测试自定义元素时，使用 JavaScript 的 `customElements.define()` 来定义新的 HTML 标签。
    * 测试 `PasteText()` 方法在事件被取消时的行为时，添加了监听 `paste` 和 `beforeinput` 事件的 JavaScript 代码，并调用 `preventDefault()` 来阻止默认行为。

* **CSS:** 测试代码通过内联样式或插入样式表来影响元素的样式，并使用 `GetComputedValue()` 方法来验证计算后的样式值。例如：
    * 测试 `IsEditable()` 时，使用了 `-webkit-user-modify` CSS 属性。
    * 测试 `ComputedStyleProperties()` 时，插入了包含 `font-size`, `text-decoration`, `font-weight`, `color` 等 CSS 属性的样式表，并使用 `SetAttribute("style", ...)` 方法修改内联样式。

**逻辑推理及假设输入与输出:**

* **`IsEditable()` 测试:**
    * **假设输入:** `<div id=testElement></div>`
    * **预期输出:** `TestElement().IsEditable()` 返回 `false`。
    * **假设输入:** `<div id=testElement contenteditable=true></div>`
    * **预期输出:** `TestElement().IsEditable()` 返回 `true`。
    * **假设输入:** `<input id=testElement readonly>`
    * **预期输出:** `TestElement().IsEditable()` 返回 `false`。

* **`SelectedTextOfContentEditable()` 测试:**
    * **假设输入:** `<div id=testElement contenteditable>Some <b>rich text</b> here.</div>`，并通过 `Selection()` API 选中 "me rich text he"。
    * **预期输出:** `TestElement().SelectedText().Utf8()` 返回 "me rich text he"，`TestElement().ContainsFrameSelection()` 返回 `true`。

* **`PasteTextIntoContentEditable()` 测试:**
    * **假设输入:** `<div id=testElement contenteditable>Some <b>rich text</b> here.</div>`，并选中 "rich text"。
    * **执行:** `TestElement().PasteText("fancy text", /*replace_all=*/false)`
    * **预期输出:** 元素 innerHTML 变为 "Some <b>fancy text</b>&nbsp;here."

**用户或编程常见的使用错误举例:**

* **错误地假设 `ShadowRoot()` 始终返回非空值:**  `ShadowRoot()` 只有在元素附加了 Shadow DOM 时才会返回有效的 `WebElement`，否则返回 null。开发者可能会在没有检查返回值的情况下直接使用，导致程序崩溃或出现未定义行为。
* **没有理解 `IsEditable()` 的判断逻辑:**  开发者可能认为只有 `contenteditable="true"` 的元素才是可编辑的，而忽略了 `-webkit-user-modify` CSS 属性或表单控件的状态。
* **在 `PasteText()` 之后没有更新 UI 或进行必要的处理:**  `PasteText()` 方法会修改 DOM 结构或表单控件的值，开发者需要在粘贴操作后更新相关的 UI 或执行其他逻辑。
* **在 JavaScript 事件处理中错误地取消了粘贴操作:**  如果开发者在 `paste` 或 `beforeinput` 事件处理中意外地调用了 `preventDefault()`，可能会导致 `PasteText()` 操作被阻止，用户粘贴的内容没有生效。

**用户操作是如何一步步的到达这里，作为调试线索:**

这个测试文件本身不会直接被用户的操作触发。它是 Blink 引擎的开发者用来测试 `WebElement` 类的代码。然而，当用户在浏览器中进行各种操作时，底层的 Blink 引擎会使用 `WebElement` 类来操作和管理 DOM 元素。以下是一些用户操作可能间接触发到 `WebElement` 相关代码的场景：

1. **用户点击可编辑区域并输入文本:**
   * 用户操作：点击一个 `contenteditable` 的 `<div>` 或其他元素，开始输入文本。
   * 调试线索：Blink 引擎会创建或修改文本节点，并可能调用 `WebElement` 的相关方法来更新元素的内部结构和状态，例如 `IsEditable()` 可能会被调用来判断元素是否允许编辑。

2. **用户在 `<textarea>` 或 `<input type="text">` 中输入文本:**
   * 用户操作：聚焦一个表单控件并输入文本。
   * 调试线索：`WebElement` 可能会被用来获取或设置表单控件的值，例如在处理 `input` 或 `change` 事件时。 `IsEditable()` 也会被调用来检查控件是否可编辑。

3. **用户选中网页上的文本:**
   * 用户操作：按住鼠标左键并拖动，选中网页上的部分文本。
   * 调试线索：Blink 引擎会使用选择 API 来管理选区，`WebElement` 的 `SelectedText()` 和 `ContainsFrameSelection()` 方法的实现逻辑可能会被间接调用，虽然这个测试文件直接测试的是 `blink::WebElement` 的包装类 `Webkit::WebElement` 的行为。

4. **用户执行粘贴操作 (Ctrl+V 或右键菜单粘贴):**
   * 用户操作：复制一些文本，然后在网页上执行粘贴操作。
   * 调试线索：浏览器会触发 `paste` 事件，Blink 引擎会处理该事件，并可能调用 `WebElement` 的 `PasteText()` 方法来将文本插入到目标元素中。测试文件中关于 `paste` 和 `beforeinput` 事件取消的测试就模拟了这种情况。

5. **网页使用了 Shadow DOM:**
   * 网页开发者创建了使用 Shadow DOM 的 Web Components。
   * 用户操作：与这些 Web Components 进行交互。
   * 调试线索：Blink 引擎会使用 `WebElement` 的 `ShadowRoot()` 方法来访问元素的 Shadow DOM 树，以便进行渲染和事件处理。

6. **网页使用了 JavaScript 操作 DOM:**
   * 网页 JavaScript 代码使用 `document.getElementById()` 等方法获取元素，并进行属性修改、样式修改等操作。
   * 调试线索：这些 JavaScript 操作最终会调用 Blink 引擎提供的接口，其中可能涉及到 `WebElement` 类的方法，例如 `GetComputedValue()` 在 JavaScript 获取元素的计算样式时会被间接使用。

因此，尽管开发者不会直接编写调用 `blink::WebElement` 的代码（通常使用公共的 `Webkit::WebElement`），但用户的各种网页交互操作都会间接地通过 Blink 引擎的内部机制触发到与 `WebElement` 相关的代码执行。这个测试文件就是用来确保这些核心的 DOM 元素操作接口能够正确工作。

### 提示词
```
这是目录为blink/renderer/core/exported/web_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/web/web_element.h"

#include <memory>
#include <vector>
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_label_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"

namespace blink {

class WebElementTest : public PageTestBase {
 protected:
  void InsertHTML(String html);
  void AddScript(String script);
  WebElement TestElement();
};

void WebElementTest::InsertHTML(String html) {
  GetDocument().documentElement()->setInnerHTML(html);
}

void WebElementTest::AddScript(String js) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setInnerHTML(js);
  GetDocument().body()->AppendChild(script);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
}

WebElement WebElementTest::TestElement() {
  Element* element = GetDocument().getElementById(AtomicString("testElement"));
  DCHECK(element);
  return WebElement(element);
}

TEST_F(WebElementTest, IsEditable) {
  InsertHTML("<div id=testElement></div>");
  EXPECT_FALSE(TestElement().IsEditable());

  InsertHTML("<div id=testElement contenteditable=true></div>");
  EXPECT_TRUE(TestElement().IsEditable());

  InsertHTML(R"HTML(
    <div style='-webkit-user-modify: read-write'>
      <div id=testElement></div>
    </div>
  )HTML");
  EXPECT_TRUE(TestElement().IsEditable());

  InsertHTML(R"HTML(
    <div style='-webkit-user-modify: read-write'>
      <div id=testElement style='-webkit-user-modify: read-only'></div>
    </div>
  )HTML");
  EXPECT_FALSE(TestElement().IsEditable());

  InsertHTML("<input id=testElement>");
  EXPECT_TRUE(TestElement().IsEditable());

  InsertHTML("<input id=testElement readonly>");
  EXPECT_FALSE(TestElement().IsEditable());

  InsertHTML("<input id=testElement disabled>");
  EXPECT_FALSE(TestElement().IsEditable());

  InsertHTML("<fieldset disabled><div><input id=testElement></div></fieldset>");
  EXPECT_FALSE(TestElement().IsEditable());
}

TEST_F(WebElementTest, IsAutonomousCustomElement) {
  InsertHTML("<x-undefined id=testElement></x-undefined>");
  EXPECT_FALSE(TestElement().IsAutonomousCustomElement());
  InsertHTML("<div id=testElement></div>");
  EXPECT_FALSE(TestElement().IsAutonomousCustomElement());

  GetDocument().GetSettings()->SetScriptEnabled(true);
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    customElements.define('v1-custom', class extends HTMLElement {});
    document.body.appendChild(document.createElement('v1-custom'));
    customElements.define('v1-builtin',
                          class extends HTMLButtonElement {},
                          { extends:'button' });
    document.body.appendChild(
        document.createElement('button', { is: 'v1-builtin' }));
  )JS");
  GetDocument().body()->appendChild(script);
  auto* v1builtin = GetDocument().body()->lastChild();
  EXPECT_FALSE(WebElement(To<Element>(v1builtin)).IsAutonomousCustomElement());
  auto* v1autonomous = v1builtin->previousSibling();
  EXPECT_TRUE(
      WebElement(To<Element>(v1autonomous)).IsAutonomousCustomElement());
}

// Tests SelectedText() and ContainsFrameSelection() with divs, including a
// contenteditable.
TEST_F(WebElementTest, SelectedTextOfContentEditable) {
  InsertHTML(
      R"(<div>Foo</div>
         <div id=testElement contenteditable>Some <b>rich text</b> here.</div>
         <div>Bar</div>)");
  auto* element = GetDocument().getElementById(AtomicString("testElement"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Selection().SelectSubString(*element, 2, 15);
  ASSERT_EQ(Selection().SelectedText(), String("me rich text he"));
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "me rich text he");

  Selection().SelectSubString(*element, 10, 7);
  ASSERT_EQ(Selection().SelectedText(), String("text he"));
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "text he");

  Selection().SelectSubString(*element->firstElementChild(), 0, 9);
  ASSERT_EQ(Selection().SelectedText(), String("rich text"));
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "rich text");

  Selection().SelectSubString(*element->parentElement(), 0, 8);
  ASSERT_EQ(Selection().SelectedText(), String("Foo\nSome"));
  EXPECT_FALSE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "");

  Selection().SelectSubString(*element->parentElement(), 19, 9);
  ASSERT_EQ(Selection().SelectedText(), String("here.\nBar"));
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  // This is not ideal behavior: it'd be preferable if SelectedText() truncated
  // the selection at the end of `TestElement()`.
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "here.\nBar");
}

// Tests SelectedText() and ContainsFrameSelection() with a textarea.
TEST_F(WebElementTest, SelectedTextOfTextArea) {
  InsertHTML(
      R"(<div>Foo</div>
         <textarea id=testElement>Some plain text here.</textarea>
         <div>Bar</div>)");
  auto* element = blink::To<HTMLTextAreaElement>(
      GetDocument().getElementById(AtomicString("testElement")));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  element->Focus();

  element->SetSelectionRange(2, 18);
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "me plain text he");

  element->SetSelectionRange(11, 18);
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "text he");

  element->SetSelectionRange(5, 15);
  EXPECT_TRUE(TestElement().ContainsFrameSelection());
  EXPECT_EQ(TestElement().SelectedText().Utf8(), "plain text");
}

// Tests SelectedText() and ContainsFrameSelection() with a document
// with no root, on a form control element.
TEST_F(WebElementTest, SelectedTextEmptyDocument) {
  InsertHTML(R"(<input type=text id=testElement></div>)");
  WebElement test_element = TestElement();
  GetDocument().documentElement()->remove();

  EXPECT_FALSE(test_element.ContainsFrameSelection());
  EXPECT_EQ(test_element.SelectedText().Utf8(), "");
}

// Tests SelectText() with a textarea.
TEST_F(WebElementTest, SelectTextOfTextArea) {
  InsertHTML(
      R"(<div>Foo</div>
      <textarea id=testElement>Some plain text here.</textarea>
      <div>Bar</div>)");

  TestElement().SelectText(/*select_all=*/false);
  EXPECT_EQ(Selection().SelectedText(), "");

  TestElement().SelectText(/*select_all=*/true);
  EXPECT_EQ(Selection().SelectedText(), "Some plain text here.");
}

// Tests SelectText() with a contenteditable.
TEST_F(WebElementTest, SelectTextOfContentEditable) {
  InsertHTML(
      R"(<div>Foo</div>
      <div id=testElement contenteditable>Some <b>rich text</b> here.</div>
      <textarea>Some plain text here.</textarea>)");

  TestElement().SelectText(/*select_all=*/false);
  EXPECT_EQ(Selection().SelectedText(), "");

  TestElement().SelectText(/*select_all=*/true);
  EXPECT_EQ(Selection().SelectedText(), "Some rich text here.");
}

TEST_F(WebElementTest, PasteTextIntoContentEditable) {
  InsertHTML(
      "<div id=testElement contenteditable>Some <b>rich text</b> here.</div>"
      "<textarea>Some plain text here.</textarea>");
  auto* element = GetDocument().getElementById(AtomicString("testElement"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().SelectSubString(*element->firstElementChild(), 0, 9);
  ASSERT_EQ(Selection().SelectedText(), String("rich text"));
  // Paste and replace selection.
  TestElement().PasteText("fancy text", /*replace_all=*/false);
  EXPECT_EQ(element->innerHTML(), "Some <b>fancy text</b>&nbsp;here.");
  // Paste and replace all.
  TestElement().PasteText("Hello", /*replace_all=*/true);
  EXPECT_EQ(element->innerHTML(), "Hello");
  // Paste into an unfocused element.
  element->nextElementSibling()->Focus();
  TestElement().PasteText("world", /*replace_all=*/false);
  EXPECT_EQ(element->innerHTML(), "Hello&nbsp;world");
}

TEST_F(WebElementTest, PasteTextIntoTextArea) {
  InsertHTML(
      "<div contenteditable>Some <b>rich text</b> here.</div>"
      "<textarea id=testElement>Some plain text here.</textarea>");
  auto* element = blink::To<HTMLTextAreaElement>(
      GetDocument().getElementById(AtomicString("testElement")));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  element->Focus();
  element->setSelectionStart(5);
  element->setSelectionEnd(15);
  ASSERT_EQ(element->Value().Substring(
                element->selectionStart(),
                element->selectionEnd() - element->selectionStart()),
            String("plain text"));
  // Paste and replace selection.
  TestElement().PasteText("boring text", /*replace_all=*/false);
  EXPECT_EQ(element->Value(), "Some boring text here.");
  // Paste and replace all.
  TestElement().PasteText("Hello", /*replace_all=*/true);
  EXPECT_EQ(element->Value(), "Hello");
  // Paste into an unfocused element.
  element->previousElementSibling()->Focus();
  TestElement().PasteText("world", /*replace_all=*/false);
  EXPECT_EQ(element->Value(), "Hello world");
}

// Tests that PasteText() aborts when the JavaScript handler of the 'paste'
// event prevents the default handling.
TEST_F(WebElementTest, PasteTextIsNoOpWhenPasteIsCancelled) {
  InsertHTML(
      "<div id=testElement contenteditable>Some <b>rich text</b> here.</div>");
  AddScript(R"(
      document.getElementById('testElement').addEventListener('paste', e => {
        e.target.textContent = 'UPPERCASE TEXT';
        e.preventDefault();
      }))");
  auto* element = GetDocument().getElementById(AtomicString("testElement"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().SelectSubString(*element->firstElementChild(), 0, 9);
  ASSERT_EQ(Selection().SelectedText(), String("rich text"));
  // Paste and replace selection.
  TestElement().PasteText("fancy text", /*replace_all=*/false);
  EXPECT_EQ(element->innerHTML(), "Some <b>UPPERCASE TEXT</b> here.");
}

// Tests that PasteText() aborts when the JavaScript handler of the
// 'beforeinput' event prevents the default handling.
TEST_F(WebElementTest, PasteTextIsNoOpWhenBeforeInputIsCancelled) {
  InsertHTML(
      "<div id=testElement contenteditable>Some <b>rich text</b> here.</div>");
  AddScript(R"(
      document.getElementById('testElement').addEventListener('beforeinput',
                                                              e => {
        e.target.textContent = 'UPPERCASE TEXT';
        e.preventDefault();
      }))");
  auto* element = GetDocument().getElementById(AtomicString("testElement"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().SelectSubString(*element->firstElementChild(), 0, 9);
  ASSERT_EQ(Selection().SelectedText(), String("rich text"));
  // Paste and replace selection.
  TestElement().PasteText("fancy text", /*replace_all=*/false);
  EXPECT_EQ(element->innerHTML(), "Some <b>UPPERCASE TEXT</b> here.");
}

TEST_F(WebElementTest, ShadowRoot) {
  InsertHTML("<input id=testElement>");
  EXPECT_TRUE(TestElement().ShadowRoot().IsNull())
      << "ShadowRoot() should not return a UA ShadowRoot.";

  {
    InsertHTML("<span id=testElement></span>");
    EXPECT_TRUE(TestElement().ShadowRoot().IsNull())
        << "No ShadowRoot initially.";
    auto* element = GetDocument().getElementById(AtomicString("testElement"));
    element->AttachShadowRootForTesting(ShadowRootMode::kOpen);
    EXPECT_FALSE(TestElement().ShadowRoot().IsNull())
        << "Should return V1 open ShadowRoot.";
  }

  {
    InsertHTML("<p id=testElement></p>");
    EXPECT_TRUE(TestElement().ShadowRoot().IsNull())
        << "No ShadowRoot initially.";
    auto* element = GetDocument().getElementById(AtomicString("testElement"));
    element->AttachShadowRootForTesting(ShadowRootMode::kClosed);
    EXPECT_FALSE(TestElement().ShadowRoot().IsNull())
        << "Should return V1 closed ShadowRoot.";
  }
}

TEST_F(WebElementTest, ComputedStyleProperties) {
  InsertHTML(R"HTML(
    <body>
      <div id=testElement></div>
    </body>
  )HTML");

  WebElement element = TestElement();
  element.GetDocument().InsertStyleSheet(
      "body { font-size: 16px; text-decoration: underline; color: blue;}");
  // font-size
  {
    EXPECT_EQ(element.GetComputedValue("font-size"), "16px");
    element.SetAttribute("style", "font-size: 3em");
    EXPECT_EQ(element.GetComputedValue("font-size"), "48px");
  }

  // text-decoration
  {
    EXPECT_EQ(element.GetComputedValue("text-decoration"),
              "none solid rgb(0, 0, 255)");
    element.SetAttribute("style", "text-decoration: line-through");
    EXPECT_EQ(element.GetComputedValue("text-decoration-line"), "line-through");
    EXPECT_EQ(element.GetComputedValue("-Webkit-text-decorations-in-effect"),
              "underline line-through");
  }

  // font-weight
  {
    EXPECT_EQ(element.GetComputedValue("font-weight"), "400");
    element.SetAttribute("style", "font-weight: bold");
    EXPECT_EQ(element.GetComputedValue("font-weight"), "700");
  }

  // color
  {
    EXPECT_EQ(element.GetComputedValue("color"), "rgb(0, 0, 255)");
    element.SetAttribute("style", "color: red");
    EXPECT_EQ(element.GetComputedValue("color"), "rgb(255, 0, 0)");
  }
}

TEST_F(WebElementTest, Labels) {
  auto ExpectLabelIdsEqual = [&](const std::vector<WebString>& expected_ids) {
    std::vector<WebString> label_ids;
    for (const WebLabelElement& label : TestElement().Labels())
      label_ids.push_back(label.GetIdAttribute());
    EXPECT_THAT(label_ids, ::testing::UnorderedElementsAreArray(expected_ids));
  };

  // No label.
  InsertHTML("<input id=testElement>");
  ExpectLabelIdsEqual({});

  // A single label.
  InsertHTML(R"HTML(
    <label id=testLabel for=testElement>Label</label>
    <input id=testElement>
  )HTML");
  ExpectLabelIdsEqual({"testLabel"});

  // Multiple labels.
  InsertHTML(R"HTML(
    <label id=testLabel1 for=testElement>Label 1</label>
    <label id=testLabel2 for=testElement>Label 2</label>
    <input id=testElement>
  )HTML");
  ExpectLabelIdsEqual({"testLabel1", "testLabel2"});
}

}  // namespace blink
```
Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Goal:**

The initial request is to analyze the `html_element_test.cc` file and identify its purpose, its relationship to web technologies (HTML, CSS, JavaScript), potential issues, and illustrate with examples.

**2. Initial Scan and Keyword Recognition:**

My first step is to quickly scan the code for familiar keywords and structures:

* `#include`:  Indicates dependencies. I see `html_element.h`, `gtest/gtest.h`, `shadow_root.h`, `text.h`, `local_frame_view.h`, `settings.h`, `html_dialog_element.h`, `page_animator.h`, `computed_style.h`, `core_unit_test_helper.h`, `runtime_enabled_features_test_helpers.h`. These headers hint at the components being tested and the testing framework.
* `namespace blink`: Confirms this is Blink (Chromium's rendering engine) code.
* `class HTMLElementTest : public RenderingTest`:  This is the core of the test suite. It inherits from `RenderingTest`, suggesting it's testing aspects of rendering and DOM manipulation.
* `TEST_F(HTMLElementTest, ...)`: These are individual test cases within the `HTMLElementTest` suite. The names of the tests are very informative.
* `SetBodyContent`, `SetBodyInnerHTML`, `GetDocument`, `getElementById`, `CreateRawElement`, `appendChild`, `remove`, `setAttribute`, `removeAttribute`, `RunDocumentLifecycle`, `ChildDocument`, `setAnchorElementForBinding`, `ShowPopoverInternal`, `HidePopoverInternal`, `showModal`, `close`: These are DOM manipulation and lifecycle-related functions, often used in JavaScript interaction with the DOM.
* `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`: These are assertions from the Google Test framework, indicating that the tests are verifying expected behavior.
* `R"JS(...)JS"`: This raw string literal clearly denotes JavaScript code embedded within the C++ test.
* `style`:  References to `box.style` and `attributeStyleMap` strongly suggest testing CSS manipulation.
* `anchor`, `popover`, `dialog`: These are HTML attributes and elements, indicating tests related to their specific behavior.

**3. Analyzing Individual Test Cases (Pattern Recognition):**

I start going through each `TEST_F` and try to understand its purpose:

* **`AdjustDirectionalityInFlatTree`**: Seems like a basic test to ensure removing a node doesn't crash the rendering engine, likely related to bidirectional text handling (`bdi`).
* **`DirectStyleMutationTriggered`**: The name is very suggestive. It uses JavaScript to modify the `style` of an element and checks `has_inline_style_mutation_for_test`. This clearly links to JavaScript and CSS. The assertions check if a flag is set when inline styles are modified.
* **`DirectStyleMutationNotTriggeredOnFirstFrameInDOM`**: Similar to the previous test, but the element is created and appended within the JavaScript. This is testing a specific scenario where mutation tracking might be different.
* **`DirectStyleMutationNotTriggeredOnFirstPaint`**:  The element is initially hidden, and styles are applied after the first paint. This investigates mutation tracking during initial rendering.
* **`DirectStyleMutationFromString`**: Style is set using a string assignment (`box.style = '...'`). Another CSS/JavaScript interaction test.
* **`DirectStyleMutationCustomPropertyFromString`**:  Similar to the previous, but with a CSS custom property (`--foo`).
* **`DirectStyleMutationByAttributeStyleMap`**:  Uses the `attributeStyleMap` API, a modern JavaScript way to manipulate styles.
* **`DirectStyleMutationCustomPropertyByAttributeStyleMap`**:  Combines `attributeStyleMap` with custom properties.
* **`DirectStyleMutationInFrame`**: Tests style mutation within an iframe, important for ensuring isolation and correct behavior across frames.
* **`DirectStyleMutationNotTriggeredByInsertStyleSheet`**:  Tests that adding a `<style>` tag doesn't trigger the *inline* style mutation flag, as it's a different mechanism.
* **`DirectStyleMutationNotTriggeredByToggleStyleChange`**: Uses `classList.toggle`, which modifies CSS classes, not inline styles directly.
* **`DirectStyleMutationNotTriggeredByPseudoClassStyleChange`**: Tests that activating a pseudo-class (`:focus`) doesn't trigger the inline style mutation flag.
* **`HasImplicitlyAnchoredElement`**: Focuses on the `anchor` attribute and the `anchorElement()` method, relating to linking and scrolling behavior within the page.
* **`HasImplicitlyAnchoredElementViaElementAttr`**: Tests setting the anchor element programmatically using `setAnchorElementForBinding`.
* **`ImplicitAnchorIdChange`**: Checks how the anchoring mechanism handles changes to the `id` of the anchor element.
* **`ImplicitlyAnchoredElementRemoved`**: Tests what happens when the anchored element is removed from the DOM.
* **`ImplicitlyAnchorElementConnected`**:  Verifies the anchoring relationship when elements are dynamically added to the DOM.
* **`PopoverTopLayerRemovalTiming`**: Tests the timing of removing a `<div popover>` from the "top layer" (used for popovers and dialogs) when it's hidden and when the element is removed from the document.
* **`DialogTopLayerRemovalTiming`**: Similar to the popover test, but for the `<dialog>` element.

**4. Categorizing and Summarizing Functionality:**

Based on the individual test analysis, I group the functionalities:

* **DOM Manipulation:** Creating, appending, removing elements, setting attributes.
* **CSS Styling:**  Setting inline styles directly, using `attributeStyleMap`, testing custom properties.
* **JavaScript Interaction:**  Executing JavaScript code within the tests to drive DOM and style changes.
* **Event Handling/Lifecycle:**  `RunDocumentLifecycle` suggests testing how changes affect the rendering pipeline.
* **Anchoring:** Testing the `anchor` attribute and related methods.
* **Popovers and Dialogs:** Testing the behavior of `<div popover>` and `<dialog>` elements, particularly regarding the top layer.
* **Mutation Observation (Implicit):**  The tests involving `has_inline_style_mutation_for_test` indicate a focus on tracking inline style changes.

**5. Connecting to Web Technologies (HTML, CSS, JavaScript):**

This is straightforward now that the individual tests are understood:

* **HTML:** The tests directly manipulate HTML elements and attributes (`<div>`, `<script>`, `<button>`, `<dialog>`, `anchor`, `popover`).
* **CSS:** The tests extensively cover setting inline styles, including custom properties, and indirectly touch on CSS classes and pseudo-classes.
* **JavaScript:**  JavaScript is used as the primary mechanism to trigger DOM and style changes within the test environment. The tests verify how Blink reacts to these JavaScript-driven modifications.

**6. Developing Examples and Scenarios:**

For each area, I construct simple HTML/CSS/JavaScript snippets to illustrate the concepts being tested. This helps to make the technical details more concrete. For example, for the `DirectStyleMutationTriggered` test, I would create a simple HTML div and show how JavaScript can change its style.

**7. Identifying Potential Issues and Common Errors:**

By understanding the tests, I can infer potential developer errors:

* **Incorrectly assuming style changes always trigger immediate repaints/layout.** The tests about mutation tracking highlight that Blink optimizes this.
* **Misunderstanding the difference between inline styles and CSS rules.** The tests make this distinction clear.
* **Not considering the lifecycle implications of DOM manipulation.** The popover/dialog tests about top-layer removal are good examples.
* **Issues with anchoring, especially with dynamic content.** The anchoring tests demonstrate potential pitfalls.

**8. Formulating Assumptions, Inputs, and Outputs (Logical Inference):**

For the more complex tests (like those involving mutation tracking), I try to articulate the assumptions being tested. For example, the `DirectStyleMutationTriggered` test assumes that modifying `element.style` directly *should* trigger a specific mutation flag. The input is the JavaScript code that modifies the style, and the output is the state of the mutation flag.

**Self-Correction/Refinement:**

Throughout this process, I might need to revisit earlier steps. For example, if I encounter a test case I don't fully understand, I'll go back to the code, read the surrounding tests, and look for clues in the test name and assertions. If my initial categorization feels incomplete, I'll refine it as I learn more about the file's contents. I also ensure my examples are clear and directly relate to the functionality being tested.
这个文件 `html_element_test.cc` 是 Chromium Blink 引擎中用于测试 `HTMLElement` 类的单元测试文件。它的主要功能是验证 `HTMLElement` 类的各种行为和属性是否按照预期工作。

**功能列举:**

1. **测试基本的 `HTMLElement` 功能:** 验证 `HTMLElement` 类的核心功能，例如属性的设置和获取、节点的添加和删除等。
2. **测试与样式相关的行为:**  重点测试通过 JavaScript 修改元素的内联样式 (`style` 属性) 是否会触发预期的行为，例如触发样式突变 (style mutation) 的通知。
3. **测试 `anchor` 属性和锚定行为:** 验证 HTML 元素的 `anchor` 属性以及与之相关的锚定功能，例如 `anchorElement()` 方法和 `HasImplicitlyAnchoredElement()` 方法。
4. **测试 `popover` 和 `dialog` 元素的 top-layer 相关行为:** 验证 `popover` 和 `dialog` 元素在显示和隐藏时，以及从 DOM 中移除时，top-layer 的移除时机是否正确。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件与 JavaScript, HTML, CSS 有着密切的关系，因为它测试的是 `HTMLElement` 类的行为，而 `HTMLElement` 是 Web 页面中各种 HTML 元素的基类。JavaScript 可以通过 DOM API 与 `HTMLElement` 实例进行交互，修改其属性和样式，从而影响页面的结构和外观。CSS 则定义了元素的样式规则。

**1. 与 JavaScript 的关系:**

* **修改内联样式:** 许多测试用例使用了 JavaScript 来修改元素的 `style` 属性，例如：
   ```javascript
   box.style.width = '100px';
   box.style.height = '100px';
   ```
   或者通过 `attributeStyleMap` API：
   ```javascript
   box.attributeStyleMap.set('width', '100px');
   ```
   测试文件会验证这些操作是否会触发 `PageAnimator` 中的 `has_inline_style_mutation_for_test()` 标志。这模拟了 JavaScript 动态修改元素样式的情况。
* **获取和设置属性:** 虽然文件中没有直接展示，但 `HTMLElement` 的其他测试可能涉及到使用 JavaScript 获取和设置 HTML 元素的属性，例如 `id`, `class` 等。
* **操作 DOM 结构:**  测试用例中使用 `document.createElement()`, `appendChild()`, `remove()` 等方法来创建、添加和删除元素，模拟 JavaScript 操作 DOM 结构的行为。

**2. 与 HTML 的关系:**

* **测试 HTML 属性:** `HasImplicitlyAnchoredElement` 系列的测试用例直接测试了 HTML 元素的 `anchor` 属性，以及它如何影响元素的行为。例如，设置了 `anchor="anchor1"` 的元素会尝试关联 `id` 为 `anchor1` 的元素。
* **测试特定 HTML 元素:** `PopoverTopLayerRemovalTiming` 和 `DialogTopLayerRemovalTiming` 测试用例分别针对 `<div popover>` 和 `<dialog>` 这两种特定的 HTML 元素，验证它们在 top-layer 相关的行为。
* **设置 HTML 内容:** 测试用例使用 `SetBodyInnerHTML()` 来设置 HTML 文档的内容，为后续的 JavaScript 操作和属性验证提供上下文。

**3. 与 CSS 的关系:**

* **测试内联样式突变:** 文件中的大部分测试用例都围绕着通过 JavaScript 修改元素的内联样式是否会触发样式突变的通知。这与 CSS 的应用方式有关，内联样式具有最高的优先级。
* **间接涉及 CSS 规则:** 尽管测试主要关注内联样式，但 `DirectStyleMutationNotTriggeredByToggleStyleChange` 测试用例通过 `classList.toggle()` 操作 CSS 类，间接地测试了 CSS 规则的影响，并验证了这种方式不会触发内联样式突变的通知。
* **涉及样式计算:** 虽然没有直接测试样式计算的细节，但 `HTMLElement` 的行为与最终应用的样式密切相关。例如，元素的 `anchorElement()` 方法返回的锚点元素会受到页面样式的影响。

**逻辑推理和假设输入/输出:**

**示例 1: `DirectStyleMutationTriggered` 测试**

* **假设输入:**
    * HTML 内容: `<div id='box'></div>`
    * JavaScript 代码:
      ```javascript
      var box = document.getElementById('box');
      box.style.width = '100px';
      box.style.height = '100px';
      ```
* **逻辑推理:** 当 JavaScript 代码执行时，它会直接修改 `id` 为 `box` 的 `div` 元素的内联 `style` 属性。这种直接的样式修改应该被 Blink 的样式系统检测到，并触发一个内联样式突变的通知。
* **预期输出:** `GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test()` 返回 `true`。

**示例 2: `HasImplicitlyAnchoredElement` 测试**

* **假设输入:**
    * HTML 内容:
      ```html
      <div id="anchor1"></div>
      <div id="anchor2"></div>
      <div id="target" anchor="anchor1"></div>
      ```
* **逻辑推理:**  `id` 为 `target` 的 `div` 元素设置了 `anchor="anchor1"` 属性，这意味着它应该与 `id` 为 `anchor1` 的元素关联起来。`anchorElement()` 方法应该返回指向 `anchor1` 元素的指针，并且 `anchor1` 元素的 `HasImplicitlyAnchoredElement()` 方法应该返回 `true`。
* **预期输出:**
    * `target->anchorElement()` 等于指向 `anchor1` 元素的指针。
    * `anchor1->HasImplicitlyAnchoredElement()` 返回 `true`.
    * `anchor2->HasImplicitlyAnchoredElement()` 返回 `false`.

**用户或编程常见的使用错误及举例说明:**

1. **误以为所有样式修改都会立即触发内联样式突变通知:**  开发者可能会认为，通过任何方式修改元素样式，都会导致 `has_inline_style_mutation_for_test()` 返回 `true`。然而，测试用例表明，通过添加 `<style>` 标签或修改 CSS 类等方式修改样式并不会触发这种通知。
   ```javascript
   // 错误假设：以下代码会触发内联样式突变通知
   var sheet = document.createElement('style');
   sheet.innerHTML = 'div { width:100px; }';
   document.body.appendChild(sheet);
   ```
   测试用例 `DirectStyleMutationNotTriggeredByInsertStyleSheet` 验证了这一点。

2. **不理解 `anchor` 属性的工作方式:** 开发者可能错误地认为 `anchor` 属性可以指向任何元素，而实际上它需要指向页面中具有对应 `id` 的元素。如果 `anchor` 属性指向一个不存在的 `id`，则不会建立锚定关系。
   ```html
   <!-- 如果页面中没有 id 为 "nonexistent-anchor" 的元素，则 target 元素不会锚定到任何元素 -->
   <div id="target" anchor="nonexistent-anchor"></div>
   ```
   `HasImplicitlyAnchoredElement` 测试用例通过验证 `anchorElement()` 的返回值来确保锚定关系是否正确建立。

3. **对 `popover` 和 `dialog` 元素的 top-layer 移除时机的误解:** 开发者可能认为在调用 `HidePopoverInternal()` 或 `close()` 后，元素会立即从 top-layer 中移除。然而，测试用例 `PopoverTopLayerRemovalTiming` 和 `DialogTopLayerRemovalTiming` 表明，top-layer 的移除可能会延迟到下一个生命周期阶段。
   ```javascript
   // 错误假设：调用 hidePopover 后，target 会立即不在 top-layer 中
   target.HidePopoverInternal(...);
   console.log(target.IsInTopLayer()); // 可能仍然是 true
   ```
   开发者需要理解 top-layer 的管理和渲染流程，避免出现依赖于立即移除的行为。

总而言之，`html_element_test.cc` 文件通过各种单元测试用例，详细地验证了 `HTMLElement` 类的功能，涵盖了与 JavaScript、HTML 和 CSS 的交互，并揭示了开发者在使用这些 Web 技术时可能遇到的常见误解和错误。这些测试对于确保 Blink 引擎的稳定性和正确性至关重要。

### 提示词
```
这是目录为blink/renderer/core/html/html_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/html_element.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class HTMLElementTest : public RenderingTest {
 public:
  HTMLElementTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
};

TEST_F(HTMLElementTest, AdjustDirectionalityInFlatTree) {
  SetBodyContent("<bdi><summary><i id=target></i></summary></bdi>");
  UpdateAllLifecyclePhasesForTest();
  GetDocument().getElementById(AtomicString("target"))->remove();
  // Pass if not crashed.
}

TEST_F(HTMLElementTest, DirectStyleMutationTriggered) {
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML("<div id='box'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.style.width = '100px';
    box.style.height = '100px';
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationNotTriggeredOnFirstFrameInDOM) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.createElement('box');
    document.body.appendChild(box);
    box.style.width = '100px';
    box.style.height = '100px';
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationNotTriggeredOnFirstPaint) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML("<div id='box' style='display:none'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.style.display = 'block';
    box.style.width = '100px';
    box.style.height = '100px';
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationFromString) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML("<div id='box'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.style = 'width:100px';
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationCustomPropertyFromString) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML("<div id='box'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.style = '--foo:100px';
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationByAttributeStyleMap) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML("<div id='box'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.attributeStyleMap.set('width', '100px');
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationCustomPropertyByAttributeStyleMap) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML("<div id='box'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.attributeStyleMap.set('--foo', '100px');
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationInFrame) {
  SetBodyInnerHTML(R"HTML(
    <iframe id='iframe'></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <div id='box'></div>
  )HTML");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  ChildDocument().GetSettings()->SetScriptEnabled(true);
  EXPECT_FALSE(ChildDocument()
                   .GetPage()
                   ->Animator()
                   .has_inline_style_mutation_for_test());
  RunDocumentLifecycle();
  auto* script = ChildDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.style.width = '100px';
    box.style.height = '100px';
  )JS");
  ChildDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationNotTriggeredByInsertStyleSheet) {
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML("<div id='box'></div>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var sheet = document.createElement('style');
    sheet.innerHTML = 'div { width:100px; }';
    document.body.appendChild(sheet);
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, DirectStyleMutationNotTriggeredByToggleStyleChange) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
    <style>
    .mystyle {
      width: 100px;
    }
    </style>
    <div id='box'></div>
  )HTML");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.classList.toggle('mystyle');
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest,
       DirectStyleMutationNotTriggeredByPseudoClassStyleChange) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
    .button {
      width: 50px;
      height: 50px;
    }
    .button:focus {
      width: 100px;
    }
    <button id='box' class='button'></button>
  )HTML");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var box = document.getElementById('box');
    box.focus();
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_EQ(GetDocument().FocusedElement(),
            GetDocument().getElementById(AtomicString("box")));
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_inline_style_mutation_for_test());
}

TEST_F(HTMLElementTest, HasImplicitlyAnchoredElement) {
  SetBodyInnerHTML(R"HTML(
    <div id="anchor1"></div>
    <div id="anchor2"></div>
    <div id="target" anchor="anchor1"></div>
  )HTML");

  Element* anchor1 = GetDocument().getElementById(AtomicString("anchor1"));
  Element* anchor2 = GetDocument().getElementById(AtomicString("anchor2"));
  HTMLElement* target =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("target")));

  EXPECT_EQ(target->anchorElement(), anchor1);
  EXPECT_TRUE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_FALSE(anchor2->HasImplicitlyAnchoredElement());

  target->setAttribute(html_names::kAnchorAttr, AtomicString("anchor2"));

  EXPECT_EQ(target->anchorElement(), anchor2);
  EXPECT_FALSE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_TRUE(anchor2->HasImplicitlyAnchoredElement());

  target->removeAttribute(html_names::kAnchorAttr);

  EXPECT_FALSE(target->anchorElement());
  EXPECT_FALSE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_FALSE(anchor2->HasImplicitlyAnchoredElement());
}

TEST_F(HTMLElementTest, HasImplicitlyAnchoredElementViaElementAttr) {
  SetBodyInnerHTML(R"HTML(
    <div id="anchor1"></div>
    <div id="anchor2"></div>
    <div id="target" anchor="anchor1"></div>
  )HTML");

  Element* anchor1 = GetDocument().getElementById(AtomicString("anchor1"));
  Element* anchor2 = GetDocument().getElementById(AtomicString("anchor2"));
  HTMLElement* target =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("target")));

  EXPECT_EQ(target->anchorElement(), anchor1);
  EXPECT_TRUE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_FALSE(anchor2->HasImplicitlyAnchoredElement());

  target->setAnchorElementForBinding(anchor2);

  EXPECT_EQ(target->anchorElement(), anchor2);
  EXPECT_FALSE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_TRUE(anchor2->HasImplicitlyAnchoredElement());

  target->setAnchorElementForBinding(nullptr);

  EXPECT_FALSE(target->anchorElement());
  EXPECT_FALSE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_FALSE(anchor2->HasImplicitlyAnchoredElement());

  target->setAttribute(html_names::kAnchorAttr, AtomicString("anchor1"));

  EXPECT_EQ(target->anchorElement(), anchor1);
  EXPECT_TRUE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_FALSE(anchor2->HasImplicitlyAnchoredElement());
}

TEST_F(HTMLElementTest, ImplicitAnchorIdChange) {
  SetBodyInnerHTML(R"HTML(
    <div id="anchor1"></div>
    <div id="anchor2"></div>
    <div id="target" anchor="anchor1"></div>
  )HTML");

  Element* anchor1 = GetDocument().getElementById(AtomicString("anchor1"));
  Element* anchor2 = GetDocument().getElementById(AtomicString("anchor2"));
  HTMLElement* target =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("target")));

  EXPECT_EQ(target->anchorElement(), anchor1);
  EXPECT_TRUE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_FALSE(anchor2->HasImplicitlyAnchoredElement());

  anchor1->setAttribute(html_names::kIdAttr, AtomicString("anchor2"));
  anchor2->setAttribute(html_names::kIdAttr, AtomicString("anchor1"));

  EXPECT_EQ(target->anchorElement(), anchor2);
  EXPECT_FALSE(anchor1->HasImplicitlyAnchoredElement());
  EXPECT_TRUE(anchor2->HasImplicitlyAnchoredElement());
}

TEST_F(HTMLElementTest, ImplicitlyAnchoredElementRemoved) {
  SetBodyInnerHTML(R"HTML(
    <div id="anchor"></div>
    <div id="target1" anchor="anchor"></div>
    <div id="target2"></div>
  )HTML");

  Element* anchor = GetDocument().getElementById(AtomicString("anchor"));
  HTMLElement* target1 =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("target1")));
  HTMLElement* target2 =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("target2")));

  target2->setAnchorElementForBinding(anchor);

  EXPECT_EQ(target1->anchorElement(), anchor);
  EXPECT_EQ(target2->anchorElement(), anchor);
  EXPECT_TRUE(anchor->HasImplicitlyAnchoredElement());

  target1->remove();
  target2->remove();

  EXPECT_FALSE(target1->anchorElement());
  EXPECT_FALSE(target2->anchorElement());
  EXPECT_FALSE(anchor->HasImplicitlyAnchoredElement());
}

TEST_F(HTMLElementTest, ImplicitlyAnchorElementConnected) {
  SetBodyInnerHTML("<div id=anchor></div>");

  Element* anchor = GetDocument().getElementById(AtomicString("anchor"));

  HTMLElement* target1 = To<HTMLElement>(
      GetDocument().CreateElementForBinding(AtomicString("div")));
  target1->setAttribute(html_names::kAnchorAttr, AtomicString("anchor"));

  HTMLElement* target2 = To<HTMLElement>(
      GetDocument().CreateElementForBinding(AtomicString("div")));
  target2->setAnchorElementForBinding(anchor);

  EXPECT_FALSE(target1->anchorElement());
  EXPECT_FALSE(target2->anchorElement());
  EXPECT_FALSE(anchor->HasImplicitlyAnchoredElement());

  GetDocument().body()->appendChild(target1);
  GetDocument().body()->appendChild(target2);

  EXPECT_EQ(target1->anchorElement(), anchor);
  EXPECT_EQ(target2->anchorElement(), anchor);
  EXPECT_TRUE(anchor->HasImplicitlyAnchoredElement());
}

TEST_F(HTMLElementTest, PopoverTopLayerRemovalTiming) {
  SetBodyInnerHTML(R"HTML(
    <div id="target" popover></div>
  )HTML");

  HTMLElement* target =
      To<HTMLElement>(GetDocument().getElementById(AtomicString("target")));

  EXPECT_FALSE(target->popoverOpen());
  EXPECT_FALSE(target->IsInTopLayer());
  target->ShowPopoverInternal(/*invoker*/ nullptr, /*exception_state*/ nullptr);
  EXPECT_TRUE(target->popoverOpen());
  EXPECT_TRUE(target->IsInTopLayer());

  // HidePopoverInternal causes :closed to match immediately, but schedules
  // the removal from the top layer.
  target->HidePopoverInternal(
      HidePopoverFocusBehavior::kFocusPreviousElement,
      HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions, nullptr);
  EXPECT_FALSE(target->popoverOpen());
  EXPECT_TRUE(target->IsInTopLayer());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->IsInTopLayer());

  // Document removal should cause immediate top layer removal.
  target->ShowPopoverInternal(/*invoker*/ nullptr, /*exception_state*/ nullptr);
  EXPECT_TRUE(target->popoverOpen());
  EXPECT_TRUE(target->IsInTopLayer());
  target->remove();
  EXPECT_FALSE(target->popoverOpen());
  EXPECT_FALSE(target->IsInTopLayer());
}

TEST_F(HTMLElementTest, DialogTopLayerRemovalTiming) {
  SetBodyInnerHTML(R"HTML(
    <dialog id="target"></dialog>
  )HTML");

  auto* target = To<HTMLDialogElement>(
      GetDocument().getElementById(AtomicString("target")));

  EXPECT_FALSE(target->IsInTopLayer());
  target->showModal(ASSERT_NO_EXCEPTION);
  EXPECT_TRUE(target->IsInTopLayer());
  target->close();
  EXPECT_TRUE(target->IsInTopLayer());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(target->IsInTopLayer());
}

}  // namespace blink
```
Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly scan the file for prominent keywords and patterns. I'd look for things like:

* `TEST(...)`: This immediately signals that it's a test file using Google Test.
* `UnsafeSVGAttributeSanitizationTest`:  The core subject of the tests.
* `PasteAndVerifySanitization`, `PasteAndVerifyBasicSanitization`:  Helper functions indicating actions being tested.
* `javascript:`, `alert()`:  Suspicious strings suggesting security concerns.
* `<svg>`, `<a>`, `<animate>`, `<set>`:  SVG elements under scrutiny.
* `xlink:href`, `href`, `from`, `to`, `values`:  SVG attributes being tested.
* `contenteditable`:  Indicates interaction with editable content.
* `clipboard`:  Suggests pasting or drag-and-drop scenarios.
* `StripScriptingAttributes`, `IsJavaScriptURLAttribute`, `IsSVGAnimationAttributeSettingJavaScriptURL`: Key functions being tested.

**2. Understanding the Core Functionality:**

Based on the keywords, the central theme emerges: **sanitizing SVG attributes to prevent JavaScript injection, particularly during paste operations.** The file tests how the Blink rendering engine handles potentially malicious JavaScript URLs within SVG content.

**3. Deconstructing the `PasteAndVerifySanitization` Function:**

This function is the workhorse for the integration tests. I'd analyze its steps:

* **Setup:** Creates a dummy page, makes the body editable, and focuses on it. This simulates a user interacting with an editable area.
* **Clipboard Interaction:** It writes HTML to the clipboard (`frame.GetSystemClipboard()->WriteHTML`) and then pastes it (`frame.GetEditor().ExecuteCommand("Paste")`). This directly tests the paste sanitization logic.
* **Verification:** It checks if the resulting HTML in the body contains the `expected_partial_contents` (to ensure something was pasted) and crucially, it verifies the absence of the suspicious `":alert()"` string (indicating successful sanitization).

**4. Analyzing Individual Tests (Integration Tests):**

The `TEST` macros with names like `pasteAnchor_javaScriptHrefIsStripped` are straightforward. They:

* Define `kUnsafeContent`:  An SVG snippet containing a `javascript:` URL in an attribute.
* Call `PasteAndVerifyBasicSanitization`:  This verifies that the dangerous URL is removed.

I'd pay attention to variations: `href` vs. `xlink:href`, different casing and entity encoding of "javascript", and animation elements.

**5. Analyzing Individual Tests (Unit Tests):**

These tests focus on specific functions within the sanitization process:

* `stringsShouldNotSupportAddition`:  A lower-level check related to string handling to ensure vulnerabilities aren't introduced through string manipulation.
* `stripScriptingAttributes_animateElement`: Tests the `StripScriptingAttributes` function directly on an `<animate>` element, confirming it correctly identifies and removes (or doesn't remove, as appropriate) specific attributes.
* `isJavaScriptURLAttribute_*`: Tests the logic for identifying attributes that contain potentially malicious JavaScript URLs. It covers `href` and `xlink:href` on `<a>` elements.
* `isSVGAnimationAttributeSettingJavaScriptURL_*`: Tests the logic for identifying malicious JavaScript URLs within animation attributes like `from`, `to`, and `values` on `<animate>` and `<set>` elements.

**6. Identifying Relationships to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:** The tests directly manipulate HTML structures (`<svg>`, `<a>`, etc.) and attributes. The `contenteditable` attribute is a key HTML feature used to enable pasting.
* **JavaScript:** The core goal is to prevent the execution of embedded JavaScript within SVG attributes. The tests explicitly check for the removal of `javascript:` URLs.
* **CSS:**  While not the primary focus, the visual rendering of SVG (which CSS plays a role in) is implicitly involved. However, these tests primarily focus on the *content* of the SVG, not its styling.

**7. Logical Inference and Hypothetical Scenarios:**

For `PasteAndVerifySanitization`:

* **Input:**  An HTML string containing potentially unsafe SVG.
* **Output:** The sanitized HTML content in the body of the document. The output should *not* contain `":alert()"`.

For functions like `IsJavaScriptURLAttribute`:

* **Input:** An `Attribute` object and the SVG element.
* **Output:** A boolean indicating whether the attribute contains a JavaScript URL.

**8. Identifying User/Programming Errors:**

* **User Error:** A user might copy SVG code from an untrusted source that contains embedded JavaScript and paste it into an editable area.
* **Programming Error:** A developer might incorrectly implement the sanitization logic, allowing malicious scripts to bypass the checks. This test file is designed to *prevent* such errors.

**9. Tracing User Operations (Debugging Clues):**

The `PasteAndVerifySanitization` function provides the steps:

1. **User selects and copies SVG content (potentially malicious).**
2. **User navigates to an editable area in the browser.**
3. **User pastes the content (Ctrl+V, right-click -> Paste, drag-and-drop).**

These tests simulate this exact flow to verify the sanitization at the paste point.

**10. Structuring the Explanation:**

Finally, I would organize the information logically, starting with the high-level purpose and then drilling down into the details of the functions, tests, and relationships to web technologies. Using clear headings and examples makes the explanation easier to understand. Highlighting the security implications is also crucial.
这个C++源代码文件 `unsafe_svg_attribute_sanitization_test.cc` 的主要功能是**测试 Blink 渲染引擎在处理 SVG 属性时，特别是当这些属性可能包含不安全的内容（如 JavaScript 代码）时，是否能够正确地进行清理（sanitization）**。

更具体地说，这个文件包含了一系列单元测试和集成测试，用于验证以下场景下的 SVG 属性清理逻辑：

**主要功能:**

1. **粘贴（Paste）操作时的 SVG 清理:** 测试当用户将包含潜在恶意 JavaScript 的 SVG 内容粘贴到可编辑区域时，Blink 是否能正确地移除这些不安全代码。
2. **检查特定属性是否包含 JavaScript URL:**  测试辅助函数，用于判断 SVG 元素的特定属性（例如 `href` 或 `xlink:href`）的值是否为 JavaScript URL。
3. **检查 SVG 动画属性是否设置了 JavaScript URL:** 测试辅助函数，用于判断 SVG 动画元素（如 `<animate>` 或 `<set>`) 的特定属性（如 `from`, `to`, `values`）是否被设置为 JavaScript URL。
4. **确保字符串对象不支持加法操作:** 这是一个较低层次的测试，确保 Blink 的字符串处理方式不会引入安全漏洞，例如通过字符串拼接绕过清理机制。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  该测试文件与 HTML 密切相关，因为它测试的是在 HTML 文档中嵌入 SVG 时发生的清理行为，特别是当用户与可编辑的 HTML 元素进行交互时（例如粘贴）。
    * **举例:**  测试中使用了 `body->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);` 将 HTML `<body>` 元素设置为可编辑，模拟用户在网页上可编辑区域粘贴内容。
* **JavaScript:** 测试的核心目标是防止执行嵌入在 SVG 属性中的恶意 JavaScript 代码。
    * **举例:**  测试用例中使用了包含 `javascript:alert()` 的 SVG 代码片段，例如 `<a href='javascript:alert()'></a>`，来验证清理机制是否能将其移除。
* **CSS:**  虽然这个测试文件不直接测试 CSS 的功能，但它涉及的 SVG 元素和属性的渲染最终会受到 CSS 的影响。  清理掉不安全的 JavaScript 确保了 CSS 渲染不会被恶意代码干扰。

**逻辑推理与假设输入输出:**

* **假设输入 (针对粘贴测试):**  一个包含 SVG 代码的字符串，其中某个属性（例如 `<a>` 标签的 `href` 或 `xlink:href`）的值是 `javascript:alert()`。
* **预期输出:**  粘贴到可编辑区域后，该 SVG 代码的对应属性中的 `javascript:alert()` 部分被移除或修改，使得其不再是可执行的 JavaScript 代码。 例如，`href='javascript:alert()'` 可能会被清理为空白或移除整个属性。

* **假设输入 (针对 `isJavaScriptURLAttribute` 函数):**
    * **输入 1:** 一个 `Attribute` 对象，其名称为 `href`，值为 `javascript:void(0)`。
    * **预期输出 1:**  该函数返回 `true`。
    * **输入 2:** 一个 `Attribute` 对象，其名称为 `href`，值为 `https://www.example.com`。
    * **预期输出 2:** 该函数返回 `false`。

* **假设输入 (针对 `isSVGAnimationAttributeSettingJavaScriptURL` 函数):**
    * **输入 1:** 一个 `Attribute` 对象，其名称为 `from`，值为 `javascript:evil()`。
    * **预期输出 1:** 该函数返回 `true`。
    * **输入 2:** 一个 `Attribute` 对象，其名称为 `to`，值为 `red`。
    * **预期输出 2:** 该函数返回 `false`。

**用户或编程常见的使用错误:**

* **用户错误:**
    1. **从不可信来源复制粘贴 SVG 代码:** 用户可能会从一些不安全的网站或邮件中复制包含恶意 JavaScript 的 SVG 代码，并粘贴到允许输入 SVG 的应用程序或网页的可编辑区域。
    2. **错误地认为 SVG 是完全安全的:** 用户可能不了解 SVG 中嵌入 JavaScript 的风险，并随意使用未经检查的 SVG 代码。

* **编程错误:**
    1. **未对用户输入的 SVG 进行充分的清理:** 开发者在处理用户提供的 SVG 内容时，如果没有进行适当的清理，可能会导致 XSS (跨站脚本攻击) 漏洞。
    2. **清理逻辑存在缺陷:** 清理算法可能存在漏洞，使得某些形式的恶意 JavaScript 代码可以绕过清理机制。例如，可能只检查了小写 "javascript:"，而忽略了大小写混合或 URL 编码的情况 (如测试用例中 `j&#x41;vascriPT:alert()` 所示)。

**用户操作如何一步步到达这里（作为调试线索）:**

1. **用户在浏览器中打开一个网页。**
2. **网页上存在一个可编辑的区域，例如使用了 `contenteditable` 属性的 `div` 或 `textarea`。**
3. **用户从另一个来源（例如，一个包含恶意 SVG 代码的文本文件、另一个网页或剪贴板）复制了一些文本，其中包含包含 `javascript:` URL 的 SVG 代码。**
4. **用户将复制的内容粘贴到网页的可编辑区域中（通常通过 Ctrl+V 或鼠标右键菜单）。**

当用户执行粘贴操作时，Blink 渲染引擎会接收到粘贴的内容，并尝试将其渲染到页面上。在这个过程中，就会触发 SVG 属性的清理逻辑。`unsafe_svg_attribute_sanitization_test.cc` 中的测试模拟了这一过程，以确保清理逻辑能够有效地阻止恶意脚本的执行。

**总结:**

`unsafe_svg_attribute_sanitization_test.cc` 是 Blink 引擎中至关重要的一个测试文件，它专注于保障用户安全，防止恶意 JavaScript 代码通过 SVG 属性注入到网页中。它通过模拟用户粘贴 SVG 内容的行为，并针对不同的 SVG 元素和属性进行测试，确保了 Blink 的清理机制能够有效地防御潜在的 XSS 攻击。

### 提示词
```
这是目录为blink/renderer/core/svg/unsafe_svg_attribute_sanitization_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// FIXME(dominicc): Poor confused check-webkit-style demands Attribute.h here.
#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/svg/animation/svg_smil_element.h"
#include "third_party/blink/renderer/core/svg/properties/svg_property_info.h"
#include "third_party/blink/renderer/core/svg/svg_a_element.h"
#include "third_party/blink/renderer/core/svg/svg_animate_element.h"
#include "third_party/blink/renderer/core/svg/svg_set_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/mock_clipboard_host.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/xlink_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/size.h"

// Test that SVG content with JavaScript URLs is sanitized by removing
// the URLs. This sanitization happens when the content is pasted or
// drag-dropped into an editable element.
//
// There are two vectors for JavaScript URLs in SVG content:
//
// 1. Attributes, for example xlink:href/href in an <svg:a> element.
// 2. Animations which set those attributes, for example
//    <animate attributeName="xlink:href" values="javascript:...
//
// The following SVG elements, although related to animation, cannot
// set JavaScript URLs:
//
// - 'animateMotion' does not use attribute name and produces floats
// - 'animateTransform' can only animate transform lists

namespace blink {

// Pastes |html_to_paste| into the body of |page_holder|'s document, and
// verifies the new content of the body is safe and sanitized, and contains
// |expected_partial_contents|.
void PasteAndVerifySanitization(const char* html_to_paste,
                                const char* expected_partial_contents) {
  test::TaskEnvironment task_environment;
  auto page_holder = std::make_unique<DummyPageHolder>(gfx::Size(1, 1));
  LocalFrame& frame = page_holder.get()->GetFrame();

  // Setup a mock clipboard host.
  PageTestBase::MockClipboardHostProvider mock_clipboard_host_provider(
      frame.GetBrowserInterfaceBroker());

  HTMLElement* body = page_holder->GetDocument().body();

  // Make the body editable, and put the caret in it.
  body->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);
  body->Focus();
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  frame.Selection().SetSelection(
      SelectionInDOMTree::Builder().SelectAllChildren(*body).Build(),
      SetSelectionOptions());
  EXPECT_TRUE(frame.Selection().ComputeVisibleSelectionInDOMTree().IsCaret());
  EXPECT_TRUE(
      frame.Selection().ComputeVisibleSelectionInDOMTree().IsContentEditable())
      << "We should be pasting into something editable.";

  frame.GetSystemClipboard()->WriteHTML(html_to_paste, BlankURL(),
                                        SystemClipboard::kCannotSmartReplace);
  frame.GetSystemClipboard()->CommitWrite();
  // Run all tasks in a message loop to allow asynchronous clipboard writing
  // to happen before reading from it synchronously.
  test::RunPendingTasks();
  EXPECT_TRUE(frame.GetEditor().ExecuteCommand("Paste"));

  // Verify that sanitization during pasting strips JavaScript, but keeps at
  // least |expected_partial_contents|.
  String sanitized_content = body->innerHTML();
  EXPECT_TRUE(sanitized_content.Contains(expected_partial_contents))
      << "We should have pasted *something*; the document is: "
      << sanitized_content.Utf8();
  EXPECT_FALSE(sanitized_content.Contains(":alert()"))
      << "The JavaScript URL is unsafe and should have been stripped; "
         "instead: "
      << sanitized_content.Utf8();
}

void PasteAndVerifyBasicSanitization(const char* unsafe_content) {
  static const char kMinimalExpectedContents[] = "</a>";
  PasteAndVerifySanitization(unsafe_content, kMinimalExpectedContents);
}

// Integration tests.

TEST(UnsafeSVGAttributeSanitizationTest, pasteAnchor_javaScriptHrefIsStripped) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     width='1cm' height='1cm'>"
      "  <a href='javascript:alert()'></a>"
      "</svg>";
  PasteAndVerifyBasicSanitization(kUnsafeContent);
}

TEST(UnsafeSVGAttributeSanitizationTest,
     pasteAnchor_javaScriptXlinkHrefIsStripped) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     xmlns:xlink='http://www.w3.org/1999/xlink'"
      "     width='1cm' height='1cm'>"
      "  <a xlink:href='javascript:alert()'></a>"
      "</svg>";
  PasteAndVerifyBasicSanitization(kUnsafeContent);
}

TEST(UnsafeSVGAttributeSanitizationTest,
     pasteAnchor_javaScriptHrefIsStripped_caseAndEntityInProtocol) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     width='1cm' height='1cm'>"
      "  <a href='j&#x41;vascriPT:alert()'></a>"
      "</svg>";
  PasteAndVerifyBasicSanitization(kUnsafeContent);
}

TEST(UnsafeSVGAttributeSanitizationTest,
     pasteAnchor_javaScriptXlinkHrefIsStripped_caseAndEntityInProtocol) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     xmlns:xlink='http://www.w3.org/1999/xlink'"
      "     width='1cm' height='1cm'>"
      "  <a xlink:href='j&#x41;vascriPT:alert()'></a>"
      "</svg>";
  PasteAndVerifyBasicSanitization(kUnsafeContent);
}

TEST(UnsafeSVGAttributeSanitizationTest,
     pasteAnchor_javaScriptHrefIsStripped_entityWithoutSemicolonInProtocol) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     width='1cm' height='1cm'>"
      "  <a href='jav&#x61script:alert()'></a>"
      "</svg>";
  PasteAndVerifyBasicSanitization(kUnsafeContent);
}

TEST(
    UnsafeSVGAttributeSanitizationTest,
    pasteAnchor_javaScriptXlinkHrefIsStripped_entityWithoutSemicolonInProtocol) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     xmlns:xlink='http://www.w3.org/1999/xlink'"
      "     width='1cm' height='1cm'>"
      "  <a xlink:href='jav&#x61script:alert()'></a>"
      "</svg>";
  PasteAndVerifyBasicSanitization(kUnsafeContent);
}

// Other sanitization integration tests are web tests that use
// document.execCommand('Copy') to source content that they later
// paste. However SVG animation elements are not serialized when
// copying, which means we can't test sanitizing these attributes in
// web tests: there is nowhere to source the unsafe content from.
TEST(UnsafeSVGAttributeSanitizationTest,
     pasteAnimatedAnchor_javaScriptHrefIsStripped_caseAndEntityInProtocol) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     width='1cm' height='1cm'>"
      "  <a href='https://www.google.com/'>"
      "    <animate attributeName='href' values='evil;J&#x61VaSCRIpT:alert()'>"
      "  </a>"
      "</svg>";
  static const char kExpectedContentAfterSanitization[] =
      "<a href=\"https://www.goo";
  PasteAndVerifySanitization(kUnsafeContent, kExpectedContentAfterSanitization);
}

TEST(
    UnsafeSVGAttributeSanitizationTest,
    pasteAnimatedAnchor_javaScriptXlinkHrefIsStripped_caseAndEntityInProtocol) {
  static const char kUnsafeContent[] =
      "<svg xmlns='http://www.w3.org/2000/svg' "
      "     xmlns:xlink='http://www.w3.org/1999/xlink'"
      "     width='1cm' height='1cm'>"
      "  <a xlink:href='https://www.google.com/'>"
      "    <animate xmlns:ng='http://www.w3.org/1999/xlink' "
      "             attributeName='ng:href' "
      "values='evil;J&#x61VaSCRIpT:alert()'>"
      "  </a>"
      "</svg>";
  static const char kExpectedContentAfterSanitization[] =
      "<a xlink:href=\"https://www.goo";
  PasteAndVerifySanitization(kUnsafeContent, kExpectedContentAfterSanitization);
}

// Unit tests

// stripScriptingAttributes inspects animation attributes for
// javascript: URLs. This check could be defeated if strings supported
// addition. If this test starts failing you must strengthen
// Element::stripScriptingAttributes, perhaps to strip all
// SVG animation attributes.
TEST(UnsafeSVGAttributeSanitizationTest, stringsShouldNotSupportAddition) {
  test::TaskEnvironment task_environment;
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* target = MakeGarbageCollected<SVGAElement>(*document);
  auto* element = MakeGarbageCollected<SVGAnimateElement>(*document);
  element->SetTargetElement(target);
  element->SetAttributeName(xlink_names::kHrefAttr);

  // Sanity check that xlink:href was identified as a "string" attribute
  EXPECT_EQ(kAnimatedString, element->GetAnimatedPropertyTypeForTesting());

  EXPECT_FALSE(element->AnimatedPropertyTypeSupportsAddition());

  element->SetAttributeName(svg_names::kHrefAttr);

  // Sanity check that href was identified as a "string" attribute
  EXPECT_EQ(kAnimatedString, element->GetAnimatedPropertyTypeForTesting());

  EXPECT_FALSE(element->AnimatedPropertyTypeSupportsAddition());
}

TEST(UnsafeSVGAttributeSanitizationTest,
     stripScriptingAttributes_animateElement) {
  test::TaskEnvironment task_environment;
  Vector<Attribute, kAttributePrealloc> attributes;
  attributes.push_back(
      Attribute(xlink_names::kHrefAttr, AtomicString("javascript:alert()")));
  attributes.push_back(
      Attribute(svg_names::kHrefAttr, AtomicString("javascript:alert()")));
  attributes.push_back(Attribute(svg_names::kFromAttr, AtomicString("/home")));
  attributes.push_back(
      Attribute(svg_names::kToAttr, AtomicString("javascript:own3d()")));

  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGAnimateElement>(*document);
  element->StripScriptingAttributes(attributes);

  EXPECT_EQ(3ul, attributes.size())
      << "One of the attributes should have been stripped.";
  EXPECT_EQ(xlink_names::kHrefAttr, attributes[0].GetName())
      << "The 'xlink:href' attribute should not have been stripped from "
         "<animate> because it is not a URL attribute of <animate>.";
  EXPECT_EQ(svg_names::kHrefAttr, attributes[1].GetName())
      << "The 'href' attribute should not have been stripped from "
         "<animate> because it is not a URL attribute of <animate>.";
  EXPECT_EQ(svg_names::kFromAttr, attributes[2].GetName())
      << "The 'from' attribute should not have been strippef from <animate> "
         "because its value is innocuous.";
}

TEST(UnsafeSVGAttributeSanitizationTest,
     isJavaScriptURLAttribute_hrefContainingJavascriptURL) {
  test::TaskEnvironment task_environment;
  Attribute attribute(svg_names::kHrefAttr, AtomicString("javascript:alert()"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGAElement>(*document);
  EXPECT_TRUE(element->IsJavaScriptURLAttribute(attribute))
      << "The 'a' element should identify an 'href' attribute with a "
         "JavaScript URL value as a JavaScript URL attribute";
}

TEST(UnsafeSVGAttributeSanitizationTest,
     isJavaScriptURLAttribute_xlinkHrefContainingJavascriptURL) {
  test::TaskEnvironment task_environment;
  Attribute attribute(xlink_names::kHrefAttr,
                      AtomicString("javascript:alert()"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGAElement>(*document);
  EXPECT_TRUE(element->IsJavaScriptURLAttribute(attribute))
      << "The 'a' element should identify an 'xlink:href' attribute with a "
         "JavaScript URL value as a JavaScript URL attribute";
}

TEST(
    UnsafeSVGAttributeSanitizationTest,
    isJavaScriptURLAttribute_xlinkHrefContainingJavascriptURL_alternatePrefix) {
  test::TaskEnvironment task_environment;
  QualifiedName href_alternate_prefix(AtomicString("foo"), AtomicString("href"),
                                      xlink_names::kNamespaceURI);
  Attribute evil_attribute(href_alternate_prefix,
                           AtomicString("javascript:alert()"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGAElement>(*document);
  EXPECT_TRUE(element->IsJavaScriptURLAttribute(evil_attribute))
      << "The XLink 'href' attribute with a JavaScript URL value should be "
         "identified as a JavaScript URL attribute, even if the attribute "
         "doesn't use the typical 'xlink' prefix.";
}

TEST(UnsafeSVGAttributeSanitizationTest,
     isSVGAnimationAttributeSettingJavaScriptURL_fromContainingJavaScriptURL) {
  test::TaskEnvironment task_environment;
  Attribute evil_attribute(svg_names::kFromAttr,
                           AtomicString("javascript:alert()"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGAnimateElement>(*document);
  EXPECT_TRUE(
      element->IsSVGAnimationAttributeSettingJavaScriptURL(evil_attribute))
      << "The animate element should identify a 'from' attribute with a "
         "JavaScript URL value as setting a JavaScript URL.";
}

TEST(UnsafeSVGAttributeSanitizationTest,
     isSVGAnimationAttributeSettingJavaScriptURL_toContainingJavaScripURL) {
  test::TaskEnvironment task_environment;
  Attribute evil_attribute(svg_names::kToAttr,
                           AtomicString("javascript:window.close()"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGSetElement>(*document);
  EXPECT_TRUE(
      element->IsSVGAnimationAttributeSettingJavaScriptURL(evil_attribute))
      << "The set element should identify a 'to' attribute with a JavaScript "
         "URL value as setting a JavaScript URL.";
}

TEST(
    UnsafeSVGAttributeSanitizationTest,
    isSVGAnimationAttributeSettingJavaScriptURL_valuesContainingJavaScriptURL) {
  test::TaskEnvironment task_environment;
  Attribute evil_attribute(svg_names::kValuesAttr,
                           AtomicString("hi!; javascript:confirm()"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGAnimateElement>(*document);
  EXPECT_TRUE(
      element->IsSVGAnimationAttributeSettingJavaScriptURL(evil_attribute))
      << "The animate element should identify a 'values' attribute with a "
         "JavaScript URL value as setting a JavaScript URL.";
}

TEST(UnsafeSVGAttributeSanitizationTest,
     isSVGAnimationAttributeSettingJavaScriptURL_innocuousAnimationAttribute) {
  test::TaskEnvironment task_environment;
  Attribute fine_attribute(svg_names::kFromAttr, AtomicString("hello, world!"));
  ScopedNullExecutionContext execution_context;
  auto* document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  auto* element = MakeGarbageCollected<SVGSetElement>(*document);
  EXPECT_FALSE(
      element->IsSVGAnimationAttributeSettingJavaScriptURL(fine_attribute))
      << "The animate element should not identify a 'from' attribute with an "
         "innocuous value as setting a JavaScript URL.";
}

}  // namespace blink
```
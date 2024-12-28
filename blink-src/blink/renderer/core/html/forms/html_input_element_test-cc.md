Response:
My thinking process to analyze the `html_input_element_test.cc` file went through these stages:

1. **Understand the Purpose:** The file name itself (`html_input_element_test.cc`) strongly suggests it's a test file for the `HTMLInputElement` class in the Blink rendering engine. The presence of `#include "third_party/blink/renderer/core/html/forms/html_input_element.h"` confirms this. The `_test.cc` suffix is a common convention for test files in C++ projects.

2. **Identify Key Imports:** I scanned the `#include` directives to understand the dependencies and the areas of Blink this test file interacts with. This revealed connections to:
    * **Testing Frameworks:** `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h` indicate the use of Google Mock and Google Test for writing unit tests.
    * **DOM and Events:** Includes for `Document`, `KeyboardEvent`, and `V8KeyboardEventInit` point to tests involving DOM manipulation and event handling.
    * **Forms:**  Imports like `HTMLFormElement`, `HTMLOptionElement`, `FileInputType`, and `DateTimeChooser` clearly show that the tests focus on form-related functionalities of the input element.
    * **Frame and View:** Includes like `LocalFrame`, `LocalFrameView`, and `VisualViewport` suggest tests related to how the input element is rendered and interacts with the viewport.
    * **Layout:** The `LayoutObject` include means there are tests involving the layout and rendering of the input element.
    * **File API:** `FileList` and related includes signify tests for file input elements.
    * **Internal Blink Components:** Includes like `EmptyChromeClient`, `NullExecutionContext`, and `PageTestBase` point to the testing infrastructure within Blink.

3. **Analyze Test Structure:** I looked for the `TEST_F` macros, which define individual test cases within the `HTMLInputElementTest` class. This allowed me to break down the functionality being tested:
    * **`FilteredDataListOptions...`:**  Tests how the `<datalist>` element interacts with the input element, specifically filtering options based on user input.
    * **`create`:** Tests the creation and initialization of `HTMLInputElement` objects.
    * **`NoAssertWhenMovedInNewDocument`:** Tests for potential crashes when moving input elements between documents.
    * **`DefaultToolTip`:** Tests the default tooltip behavior, especially for required fields.
    * **`ImageTypeCrash`:** Tests for crashes specific to `type="image"` inputs.
    * **`RadioKeyDownDCHECKFailure`:** Tests for potential errors when handling keyboard events on radio buttons.
    * **`DateTimeChooserSizeParamRespectsScale`:** Tests how the size of the date/time chooser is affected by page scaling.
    * **`StepDownOverflow` and `StepDownDefaultToMin`:** Test the `stepDown` functionality for numeric and date/time inputs.
    * **Checkbox Shadow Root Tests:** Tests related to the shadow DOM of checkbox input elements.
    * **`RepaintAfterClearingFile`:** Tests for proper repainting after clearing a file input.
    * **`UpdateTypeDcheck`:** Tests for potential errors when changing the input type.
    * **Lazy Shadow Tree Creation Tests:** Tests how and when the shadow DOM is created for input elements.
    * **`PasswordFieldReset`:** Tests the `PasswordFieldReset` functionality, likely related to password management.

4. **Identify Relationships with Web Technologies (HTML, CSS, JavaScript):** Based on the test names and the included headers, I could connect the tests to specific web technologies:
    * **HTML:** The core focus is on the `<input>` element and its attributes (`type`, `value`, `list`, `placeholder`, `required`, `min`, `step`). The tests also involve related elements like `<datalist>`, `<form>`, and `<option>`.
    * **CSS:**  The `DateTimeChooserSizeParamRespectsScale` test explicitly mentions CSS `width` and `height` styles. The lazy shadow DOM creation tests implicitly touch upon the styling applied within the shadow DOM.
    * **JavaScript:** While this is a C++ test file, it implicitly tests the underlying behavior that JavaScript interacts with. For example, JavaScript can read and set the `value` of an input element, trigger events, and manipulate the DOM. The tests indirectly verify the correctness of these interactions.

5. **Infer Logic and Potential Errors:** By understanding the functionality being tested, I could deduce the underlying logic and potential user/developer errors. For instance, the `FilteredDataListOptions` tests are clearly checking the logic for matching input values against datalist options. The `StepDown` tests examine boundary conditions and potential overflow issues. The "crash" tests target specific error scenarios.

6. **Consider User Interaction:** I thought about how a user's actions in a browser could lead to the execution of the code being tested. Typing in an input field, selecting options from a dropdown, submitting a form, changing the input type using JavaScript, and interacting with date/time pickers are all examples of user actions that could trigger the functionalities tested here.

7. **Structure the Explanation:** Finally, I organized my findings into clear categories (Functionality, Relationships with Web Technologies, Logic and Assumptions, User/Programming Errors, User Operations) with specific examples drawn from the code and my understanding of web technologies. I used the test names as hints for the functionality being tested and looked for patterns in the test setup (e.g., setting innerHTML to create input elements).
这个文件 `html_input_element_test.cc` 是 Chromium Blink 引擎中用于测试 `HTMLInputElement` 类功能的单元测试文件。它的主要目的是确保 `HTMLInputElement` 类的各种方法和属性按照预期工作，并且能够正确地与 Blink 引擎的其他部分交互。

以下是它的主要功能以及与 JavaScript, HTML, CSS 的关系，逻辑推理，常见错误和用户操作路径的详细说明：

**文件功能概览:**

1. **测试 `HTMLInputElement` 类的各种属性和方法:**  例如，测试设置和获取 `value` 属性，`type` 属性的更改，以及与表单相关的行为。
2. **测试与 `<datalist>` 元素的交互:**  验证输入框如何根据 `<datalist>` 中的选项进行过滤和显示。
3. **测试事件处理:**  例如，测试键盘事件 (`keydown`) 在特定输入类型（如 radio）上的行为。
4. **测试用户代理阴影根 (User-Agent Shadow Root):** 验证阴影根的创建和管理，这影响了浏览器的默认渲染和行为。
5. **测试特定输入类型的行为:** 例如，`type="radio"`, `type="checkbox"`, `type="file"`, `type="date"`, `type="image"`, `type="password"` 等。
6. **测试日期和时间选择器 (Date/Time Chooser):** 验证日期和时间输入类型的选择器参数和行为。
7. **测试 `stepUp` 和 `stepDown` 方法:**  验证数值或日期/时间输入框的步进操作。
8. **测试与表单验证相关的行为:** 例如，测试 `required` 属性以及 `novalidate` 属性对默认工具提示的影响。
9. **测试错误处理和异常情况:**  例如，测试在特定情况下是否会发生崩溃或 DCheck 失败。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  这个测试文件大量使用了 HTML 字符串来创建和操作 `HTMLInputElement` 元素。例如，可以看到这样的代码：
    ```c++
    GetDocument().documentElement()->setInnerHTML("<input id=test>");
    ```
    这模拟了在 HTML 文档中创建 `<input>` 元素。测试会验证这些元素在 Blink 引擎中的行为是否符合 HTML 规范。不同的输入类型 (`type` 属性) 和其他属性 (例如 `value`, `list`, `required`, `min`, `step`) 都在测试中有所体现。

* **JavaScript:**  尽管这是一个 C++ 测试文件，但它测试的是 JavaScript 可以直接操作的 DOM 元素的行为。JavaScript 可以通过 DOM API 获取和设置 `HTMLInputElement` 的属性，例如 `element.value = 'some text';` 或 `element.type = 'radio';`。这个测试文件验证了 Blink 引擎对这些操作的实现是否正确。例如，测试 `FilteredDataListOptions` 就模拟了用户在输入框中输入内容，触发 JavaScript 可以监听的 `input` 事件，并导致浏览器根据 `<datalist>` 中的选项进行过滤。

* **CSS:** 虽然这个测试文件主要关注逻辑和功能，但某些测试间接涉及 CSS。例如，`DateTimeChooserSizeParamRespectsScale` 测试验证了当页面缩放时，日期选择器的大小是否正确。这涉及到 Blink 引擎的布局和渲染机制，而布局和渲染是与 CSS 密切相关的。此外，用户代理阴影根的存在也意味着默认的输入框样式是由浏览器提供的 CSS 决定的。

**逻辑推理和假设输入与输出:**

例如，在 `FilteredDataListOptionsContain` 测试中：

* **假设输入 (HTML):**
    ```html
    <input id=test value=BC list=dl2>
    <datalist id=dl2>
    <option>AbC DEF</option>
    <option>VAX</option>
    <option value=ghi>abc</option>
    </datalist>
    ```
* **逻辑推理:**  测试代码会获取 `id="test"` 的输入框，并检查其 `FilteredDataListOptions()` 方法的输出。这个方法应该根据输入框的 `value` ("BC") 和关联的 `<datalist>` 的选项进行过滤。过滤逻辑会考虑大小写不敏感的包含匹配。
* **预期输出:**  `FilteredDataListOptions()` 方法应该返回一个包含两个 `HTMLOptionElement` 对象的列表，分别对应 "AbC DEF" 和 "ghi"。注意，虽然 "abc" 的标签与 "BC" 不匹配，但其 `value` 属性 "ghi" 会被包含。

再例如，在 `StepDownDefaultToMin` 测试中：

* **假设输入 (HTML):**
    ```html
    <input type="number" min="7">
    ```
* **逻辑推理:** 测试代码会调用 `stepDown(1, ASSERT_NO_EXCEPTION)` 方法。由于输入框初始没有 `value`，并且设置了 `min` 属性为 "7"，`stepDown` 应该将 `value` 设置为最小值。
* **预期输出:** 调用 `stepDown` 后，输入框的 `Value()` 方法应该返回 "7"。

**用户或编程常见的使用错误:**

* **误解 `<datalist>` 的匹配规则:**  开发者可能认为 `<option>` 的 `value` 属性是用于匹配的，但实际上浏览器会优先匹配 `<option>` 标签内的文本内容（如果有）。`FilteredDataListOptionsContain` 测试中的一个例子就展示了这一点。
* **不了解不同输入类型的行为差异:** 例如，尝试对 `type="checkbox"` 的输入框调用某些只有文本输入框才有的方法可能会导致错误。
* **错误地假设用户代理阴影根的存在和结构:** 开发者不应该直接操作用户代理阴影根，因为它是由浏览器控制的。
* **在 JavaScript 中动态改变输入类型时未考虑潜在的副作用:**  例如，从 `type="text"` 更改为 `type="file"` 会导致输入框的行为和渲染方式发生很大变化。`ChangingInputTypeCausesShadowRootToBeCreated` 测试就关注了这种变化。
* **在处理文件输入时可能存在的安全问题和路径问题:** `RepaintAfterClearingFile` 测试虽然关注的是渲染，但也间接提醒了文件输入的一些特殊性。

**用户操作如何一步步到达这里:**

虽然用户不会直接 "到达" 这个 C++ 测试文件，但用户的操作会触发浏览器执行 `HTMLInputElement` 类的相关代码，而这个测试文件就是用来验证这些代码的正确性的。以下是一些用户操作和它们如何关联到测试的功能：

1. **在网页的输入框中输入文本:**
    * **关联测试:** `FilteredDataListOptions...` 系列的测试。
    * **步骤:** 用户在带有 `list` 属性的 `<input>` 框中输入字符。浏览器会查找关联的 `<datalist>`，并根据用户输入动态过滤选项。

2. **点击 `type="radio"` 的单选按钮:**
    * **关联测试:** `RadioKeyDownDCHECKFailure` (虽然这个测试关注的是键盘事件，但单选按钮的切换也涉及到类似的状态更新)。
    * **步骤:** 用户点击一个未选中的单选按钮，该按钮会被选中，同一 `name` 属性组的其他按钮会被取消选中。

3. **使用 `type="date"` 的日期选择器:**
    * **关联测试:** `DateTimeChooserSizeParamRespectsScale`, `StepDownOverflow`, `StepDownDefaultToMin` (对于日期类型)。
    * **步骤:** 用户点击日期输入框，弹出日期选择器。用户选择日期，或使用选择器上的步进按钮调整日期。

4. **上传文件 (使用 `type="file"`):**
    * **关联测试:** `RepaintAfterClearingFile`.
    * **步骤:** 用户点击文件上传按钮，选择本地文件。浏览器会处理文件信息，并可能在界面上显示文件名。清除文件后，界面需要正确刷新。

5. **与表单元素交互并提交表单:**
    * **关联测试:** `DefaultToolTip`.
    * **步骤:** 用户填写表单，可能会遇到带有 `required` 属性的输入框。如果未填写，浏览器可能会显示默认的验证提示信息。

6. **通过 JavaScript 修改输入框的属性:**
    * **关联测试:** `ChangingInputTypeCausesShadowRootToBeCreated`, `UpdateTypeDcheck`.
    * **步骤:** 网页上的 JavaScript 代码可能会动态修改输入框的 `type` 属性或其他属性，例如：`document.getElementById('myInput').type = 'radio';`。浏览器需要正确处理这些动态变化。

总而言之，`html_input_element_test.cc` 是 Blink 引擎确保其 `<input>` 元素实现符合规范且行为正确的关键组成部分。它通过各种单元测试覆盖了 `HTMLInputElement` 类的核心功能和与其他 Web 技术 (HTML, CSS, JavaScript) 的交互。理解这个测试文件有助于深入了解浏览器如何解析和渲染 HTML 表单，以及如何响应用户的交互。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/html_input_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/forms/html_input_element.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_keyboard_event_init.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/date_time_chooser.h"
#include "third_party/blink/renderer/core/html/forms/file_input_type.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

using ::testing::Truly;

namespace blink {

namespace {

class PasswordResetChromeClient : public EmptyChromeClient {
 public:
  MOCK_METHOD(void,
              PasswordFieldReset,
              (HTMLInputElement & element),
              (override));
};

class HTMLInputElementTestChromeClient : public EmptyChromeClient {
 public:
  gfx::Rect LocalRootToScreenDIPs(const gfx::Rect& local_root_rect,
                                  const LocalFrameView* view) const override {
    return view->GetPage()->GetVisualViewport().RootFrameToViewport(
        local_root_rect);
  }
};

}  // namespace

class HTMLInputElementTest : public PageTestBase {
 protected:
  void SetUp() override {
    auto* chrome_client =
        MakeGarbageCollected<HTMLInputElementTestChromeClient>();
    SetupPageWithClients(chrome_client);
  }

  HTMLInputElement& TestElement() {
    Element* element = GetDocument().getElementById(AtomicString("test"));
    DCHECK(element);
    return To<HTMLInputElement>(*element);
  }
};

TEST_F(HTMLInputElementTest, FilteredDataListOptionsNoList) {
  GetDocument().documentElement()->setInnerHTML("<input id=test>");
  EXPECT_TRUE(TestElement().FilteredDataListOptions().empty());

  GetDocument().documentElement()->setInnerHTML(
      "<input id=test list=dl1><datalist id=dl1></datalist>");
  EXPECT_TRUE(TestElement().FilteredDataListOptions().empty());
}

TEST_F(HTMLInputElementTest, FilteredDataListOptionsContain) {
  GetDocument().documentElement()->setInnerHTML(
      "<input id=test value=BC list=dl2>"
      "<datalist id=dl2>"
      "<option>AbC DEF</option>"
      "<option>VAX</option>"
      "<option value=ghi>abc</option>"  // Match to label, not value.
      "</datalist>");
  auto options = TestElement().FilteredDataListOptions();
  EXPECT_EQ(2u, options.size());
  EXPECT_EQ("AbC DEF", options[0]->value().Utf8());
  EXPECT_EQ("ghi", options[1]->value().Utf8());

  GetDocument().documentElement()->setInnerHTML(
      "<input id=test value=i list=dl2>"
      "<datalist id=dl2>"
      "<option>I</option>"
      "<option>&#x0130;</option>"  // LATIN CAPITAL LETTER I WITH DOT ABOVE
      "<option>&#xFF49;</option>"  // FULLWIDTH LATIN SMALL LETTER I
      "</datalist>");
  options = TestElement().FilteredDataListOptions();
  EXPECT_EQ(2u, options.size());
  EXPECT_EQ("I", options[0]->value().Utf8());
  EXPECT_EQ(0x0130, options[1]->value()[0]);
}

TEST_F(HTMLInputElementTest, FilteredDataListOptionsForMultipleEmail) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <input id=test value='foo@example.com, tkent' list=dl3 type=email
    multiple>
    <datalist id=dl3>
    <option>keishi@chromium.org</option>
    <option>tkent@chromium.org</option>
    </datalist>
  )HTML");
  auto options = TestElement().FilteredDataListOptions();
  EXPECT_EQ(1u, options.size());
  EXPECT_EQ("tkent@chromium.org", options[0]->value().Utf8());
}

TEST_F(HTMLInputElementTest, FilteredDataListOptionsDynamicContain) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <input id=test value='40m auto reel' list=dl4>
    <datalist id=dl4>
    <option>Hozelock 10m Mini Auto Reel - 2485</option>
    <option>Hozelock Auto Reel 20m - 2401</option>
    <option>Hozelock Auto Reel 30m - 2403</option>
    <option>Hozelock Auto Reel 40m - 2595</option>
    </datalist>
  )HTML");
  auto options = TestElement().FilteredDataListOptions();
  EXPECT_EQ(1u, options.size());
  EXPECT_EQ("Hozelock Auto Reel 40m - 2595", options[0]->value().Utf8());

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <input id=test value='autoreel' list=dl4>
    <datalist id=dl4>
    <option>Hozelock 10m Mini Auto Reel - 2485</option>
    <option>Hozelock Auto Reel 20m - 2401</option>
    <option>Hozelock Auto Reel 30m - 2403</option>
    <option>Hozelock Auto Reel 40m - 2595</option>
    </datalist>
  )HTML");
  options = TestElement().FilteredDataListOptions();
  EXPECT_EQ(4u, options.size());
  EXPECT_EQ("Hozelock 10m Mini Auto Reel - 2485", options[0]->value().Utf8());
  EXPECT_EQ("Hozelock Auto Reel 20m - 2401", options[1]->value().Utf8());
  EXPECT_EQ("Hozelock Auto Reel 30m - 2403", options[2]->value().Utf8());
  EXPECT_EQ("Hozelock Auto Reel 40m - 2595", options[3]->value().Utf8());
}

TEST_F(HTMLInputElementTest, create) {
  auto* input = MakeGarbageCollected<HTMLInputElement>(
      GetDocument(), CreateElementFlags::ByCreateElement());
  EXPECT_EQ(nullptr, input->UserAgentShadowRoot());

  input = MakeGarbageCollected<HTMLInputElement>(
      GetDocument(), CreateElementFlags::ByParser(&GetDocument()));
  EXPECT_EQ(nullptr, input->UserAgentShadowRoot());
  input->ParserSetAttributes(Vector<Attribute, kAttributePrealloc>());
  if (RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled()) {
    EXPECT_EQ(nullptr, input->UserAgentShadowRoot());
  } else {
    EXPECT_NE(nullptr, input->UserAgentShadowRoot());
  }
}

TEST_F(HTMLInputElementTest, NoAssertWhenMovedInNewDocument) {
  ScopedNullExecutionContext execution_context;
  auto* document_without_frame =
      Document::CreateForTest(execution_context.GetExecutionContext());
  EXPECT_EQ(nullptr, document_without_frame->GetPage());
  auto* html = MakeGarbageCollected<HTMLHtmlElement>(*document_without_frame);
  html->AppendChild(
      MakeGarbageCollected<HTMLBodyElement>(*document_without_frame));

  // Create an input element with type "range" inside a document without frame.
  To<HTMLBodyElement>(html->firstChild())
      ->setInnerHTML("<input type='range' />");
  document_without_frame->AppendChild(html);

  auto page_holder = std::make_unique<DummyPageHolder>();
  auto& document = page_holder->GetDocument();
  EXPECT_NE(nullptr, document.GetPage());

  // Put the input element inside a document with frame.
  document.body()->AppendChild(document_without_frame->body()->firstChild());

  // Remove the input element and all refs to it so it gets deleted before the
  // document.
  // The assert in |EventHandlerRegistry::updateEventHandlerTargets()| should
  // not be triggered.
  document.body()->RemoveChild(document.body()->firstChild());
}

TEST_F(HTMLInputElementTest, DefaultToolTip) {
  auto* input_without_form =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input_without_form->SetBooleanAttribute(html_names::kRequiredAttr, true);
  GetDocument().body()->AppendChild(input_without_form);
  EXPECT_EQ("<<ValidationValueMissing>>", input_without_form->DefaultToolTip());

  auto* form = MakeGarbageCollected<HTMLFormElement>(GetDocument());
  GetDocument().body()->AppendChild(form);
  auto* input_with_form = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input_with_form->SetBooleanAttribute(html_names::kRequiredAttr, true);
  form->AppendChild(input_with_form);
  EXPECT_EQ("<<ValidationValueMissing>>", input_with_form->DefaultToolTip());

  form->SetBooleanAttribute(html_names::kNovalidateAttr, true);
  EXPECT_EQ(String(), input_with_form->DefaultToolTip());
}

// crbug.com/589838
TEST_F(HTMLInputElementTest, ImageTypeCrash) {
  auto* input = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input->setAttribute(html_names::kTypeAttr, AtomicString("image"));
  input->EnsureFallbackContent();
  // Make sure ensurePrimaryContent() recreates UA shadow tree, and updating
  // |value| doesn't crash.
  input->EnsurePrimaryContent();
  input->setAttribute(html_names::kValueAttr, AtomicString("aaa"));
}

TEST_F(HTMLInputElementTest, RadioKeyDownDCHECKFailure) {
  // crbug.com/697286
  GetDocument().body()->setInnerHTML(
      "<input type=radio name=g><input type=radio name=g>");
  auto& radio1 = To<HTMLInputElement>(*GetDocument().body()->firstChild());
  auto& radio2 = To<HTMLInputElement>(*radio1.nextSibling());
  radio1.Focus();
  // Make layout-dirty.
  radio2.setAttribute(html_names::kStyleAttr, AtomicString("position:fixed"));
  KeyboardEventInit* init = KeyboardEventInit::Create();
  init->setKey(keywords::kArrowRight);
  radio1.DefaultEventHandler(
      *MakeGarbageCollected<KeyboardEvent>(event_type_names::kKeydown, init));
  EXPECT_EQ(GetDocument().ActiveElement(), &radio2);
}

TEST_F(HTMLInputElementTest, DateTimeChooserSizeParamRespectsScale) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  GetDocument().View()->GetFrame().GetPage()->GetVisualViewport().SetScale(2.f);
  GetDocument().body()->setInnerHTML(
      "<input type='date' style='width:200px;height:50px' />");
  UpdateAllLifecyclePhasesForTest();
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());

  DateTimeChooserParameters params;
  bool success = input->SetupDateTimeChooserParameters(params);
  EXPECT_TRUE(success);
  EXPECT_EQ(InputType::Type::kDate, params.type);
  EXPECT_EQ(gfx::Rect(16, 16, 400, 100), params.anchor_rect_in_screen);
}

TEST_F(HTMLInputElementTest, StepDownOverflow) {
  auto* input = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input->setAttribute(html_names::kTypeAttr, AtomicString("date"));
  input->setAttribute(html_names::kMinAttr, AtomicString("2010-02-10"));
  input->setAttribute(html_names::kStepAttr,
                      AtomicString("9223372036854775556"));
  // InputType::applyStep() should not pass an out-of-range value to
  // setValueAsDecimal, and WTF::msToYear() should not cause a DCHECK failure.
  input->stepDown(1, ASSERT_NO_EXCEPTION);
}

TEST_F(HTMLInputElementTest, StepDownDefaultToMin) {
  AtomicString min_attr_value("7");

  auto* input = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input->setAttribute(html_names::kTypeAttr, AtomicString("number"));
  input->setAttribute(html_names::kMinAttr, min_attr_value);

  EXPECT_TRUE(input->Value().empty());

  input->stepDown(1, ASSERT_NO_EXCEPTION);

  // stepDown() should default to min value when the input has no initial value.
  EXPECT_EQ(min_attr_value, input->Value());
}

TEST_F(HTMLInputElementTest, CheckboxHasNoShadowRoot) {
  GetDocument().body()->setInnerHTML("<input type='checkbox' />");
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());
  EXPECT_EQ(nullptr, input->UserAgentShadowRoot());
}

TEST_F(HTMLInputElementTest, ChangingInputTypeCausesShadowRootToBeCreated) {
  GetDocument().body()->setInnerHTML("<input type='checkbox' />");
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());
  EXPECT_EQ(nullptr, input->UserAgentShadowRoot());
  input->setAttribute(html_names::kTypeAttr, AtomicString("text"));
  EXPECT_NE(nullptr, input->UserAgentShadowRoot());
}

TEST_F(HTMLInputElementTest, RepaintAfterClearingFile) {
  GetDocument().body()->setInnerHTML("<input type='file' />");
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());

  FileChooserFileInfoList files;
  files.push_back(CreateFileChooserFileInfoNative("/native/path/native-file",
                                                  "display-name"));
  auto* execution_context = MakeGarbageCollected<NullExecutionContext>();
  FileList* list = FileInputType::CreateFileList(*execution_context, files,
                                                 base::FilePath());
  ASSERT_TRUE(list);
  EXPECT_EQ(1u, list->length());

  input->setFiles(list);
  UpdateAllLifecyclePhasesForTest();

  ASSERT_TRUE(input->GetLayoutObject());
  EXPECT_FALSE(input->GetLayoutObject()->ShouldCheckForPaintInvalidation());

  input->SetValue("");
  GetDocument().UpdateStyleAndLayoutTree();

  ASSERT_TRUE(input->GetLayoutObject());
  EXPECT_TRUE(input->GetLayoutObject()->ShouldCheckForPaintInvalidation());
  execution_context->NotifyContextDestroyed();
}

TEST_F(HTMLInputElementTest, UpdateTypeDcheck) {
  Document& doc = GetDocument();
  // Removing <body> is required to reproduce the issue.
  doc.body()->remove();
  Element* input = doc.CreateRawElement(html_names::kInputTag);
  doc.documentElement()->appendChild(input);
  input->Focus();
  input->setAttribute(html_names::kTypeAttr, AtomicString("radio"));
  // Test succeeds if the above setAttribute() didn't trigger a DCHECK failure
  // in Document::UpdateFocusAppearanceAfterLayout().
}

TEST_F(HTMLInputElementTest, LazilyCreateShadowTree) {
  GetDocument().body()->setInnerHTML("<input/>");
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());
  ASSERT_TRUE(input);
  EXPECT_FALSE(IsShadowHost(*input));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(IsShadowHost(*input));
}

TEST_F(HTMLInputElementTest, LazilyCreateShadowTreeWithPlaceholder) {
  GetDocument().body()->setInnerHTML("<input placeholder='x'/>");
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());
  ASSERT_TRUE(input);
  EXPECT_FALSE(IsShadowHost(*input));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(IsShadowHost(*input));
}

TEST_F(HTMLInputElementTest, LazilyCreateShadowTreeWithValue) {
  GetDocument().body()->setInnerHTML("<input value='x'/>");
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());
  ASSERT_TRUE(input);
  EXPECT_FALSE(IsShadowHost(*input));
}

struct PasswordFieldResetParam {
  const char* new_type;
  const char* temporary_value;
  bool expected_call = true;
};

class HTMLInputElementPasswordFieldResetTest
    : public HTMLInputElementTest,
      public ::testing::WithParamInterface<PasswordFieldResetParam> {
 protected:
  void SetUp() override {
    chrome_client_ = MakeGarbageCollected<PasswordResetChromeClient>();
    SetupPageWithClients(chrome_client_);
  }

  PasswordResetChromeClient& chrome_client() { return *chrome_client_; }

 private:
  Persistent<PasswordResetChromeClient> chrome_client_;
};

// Tests that PasswordFieldReset() is (only) called for empty fields. This is
// particularly relevant for field types where setValue("") does not imply
// value().IsEmpty(), such as <input type="range"> (see crbug.com/1265130).
TEST_P(HTMLInputElementPasswordFieldResetTest, PasswordFieldReset) {
  GetDocument().documentElement()->setInnerHTML(
      "<input id=test type=password>");
  GetDocument().UpdateStyleAndLayoutTree();

  TestElement().setType(AtomicString(GetParam().new_type));
  GetDocument().UpdateStyleAndLayoutTree();

  TestElement().SetValue(GetParam().temporary_value);
  GetDocument().UpdateStyleAndLayoutTree();

  EXPECT_CALL(chrome_client(),
              PasswordFieldReset(Truly([this](const HTMLInputElement& e) {
                return e.isSameNode(&TestElement()) && e.Value().empty();
              })))
      .Times(GetParam().expected_call ? 1 : 0);
  TestElement().SetValue("");
  GetDocument().UpdateStyleAndLayoutTree();
}

INSTANTIATE_TEST_SUITE_P(
    HTMLInputElementTest,
    HTMLInputElementPasswordFieldResetTest,
    ::testing::Values(PasswordFieldResetParam{"password", "some_value", true},
                      PasswordFieldResetParam{"text", "some_value", true},
                      PasswordFieldResetParam{"range", "51", false}));

}  // namespace blink

"""

```
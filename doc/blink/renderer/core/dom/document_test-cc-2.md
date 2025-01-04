Response:
My thinking process to arrive at the summary of `document_test.cc` goes through these stages:

1. **Understand the Context:** The file is `document_test.cc` within the Blink rendering engine. The `_test.cc` suffix immediately signals that this file contains unit tests for the `Document` class. Blink is responsible for rendering web pages, so the `Document` class represents the parsed HTML document.

2. **Identify Key Areas by Examining `TEST_F` Definitions:** The `TEST_F` macro indicates individual test cases within a test fixture. Scanning the names of these tests reveals the primary functionalities being tested:

    * **Trust Tokens (HasRedemptionRecord):**  Several tests focus on `HasRedemptionRecord`, including error conditions (no answerer, invalid argument, disconnection) and security restrictions (non-HTTP/HTTPS).
    * **Viewport Fit:** Tests like `MetaViewportButNoFit`, `ForceExpandIntoCutout`, and `EffectiveViewportFit` indicate testing of how the `<meta name="viewport">` tag and related CSS properties affect the viewport.
    * **Document Metadata (LastModified):** The `LastModified` test checks how the `Last-Modified` HTTP header is parsed and stored.
    * **Document Policy:** The `DuplicatedDocumentPolicyViolationsAreIgnored` test deals with how the browser handles `Document-Policy` HTTP headers.
    * **Listed Elements (Form Controls):** A large section of tests starting with `UnassociatedListedElementTest` is dedicated to testing how the `Document` class tracks form-related elements (buttons, inputs, etc.) that are *not* explicitly associated with a `<form>` element. This includes dynamic addition/removal and association changes.
    * **Top-Level Forms:** The `TopLevelFormsListTest` focuses on how the `Document` tracks forms that are direct children of the `<body>` or within shadow roots.
    * **Viewport Defining Element:** The `DocumentDefiningElementWithMultipleBodies` test examines how the browser chooses the element that defines the viewport, especially when multiple `<body>` elements are present (an unusual but potentially valid scenario).
    * **CSS `overflow: visible` on Replaced Elements:** Tests with names containing "LayoutReplacedUseCounter" verify if the browser correctly tracks the usage of `overflow: visible` on replaced elements (like `<img>`, `<iframe>`).
    * **Header Preload:** The `HeaderPreloadRemoveReaddClient` test checks how the browser handles preloaded resources when the element initiating the preload is removed and then re-added.
    * **Active Modal Dialog:** The `ActiveModalDialog` test checks the functionality related to tracking the currently active modal `<dialog>` element.
    * **Lifecycle State:** `LifecycleState_DirtyStyle_NoBody` tests how style changes affect the document's lifecycle state, particularly when there's no `<body>`.
    * **Payment Link Handling:** The `PaymentLinkHandling` tests (under `#if BUILDFLAG(IS_ANDROID)`) verify the logic for detecting and handling `<link rel="payment">` tags.

3. **Categorize and Group Functionalities:**  Based on the identified test areas, I group them into logical categories:

    * Core Document Functionality (metadata, lifecycle)
    * Security and Privacy Features (Trust Tokens)
    * Rendering and Layout (Viewport Fit, Viewport Defining Element, `overflow: visible`)
    * Form Handling (Listed Elements, Top-Level Forms)
    * Resource Loading (Header Preload)
    * Interactive Elements (Active Modal Dialog)
    * Platform-Specific Features (Payment Link Handling on Android)
    * Error Handling and Robustness (disconnections, invalid arguments)

4. **Relate to Web Technologies (HTML, CSS, JavaScript):** For each category, I consider its relation to the core web technologies:

    * **HTML:**  The tests heavily involve parsing and manipulating HTML elements and attributes (e.g., `<meta>`, `<link>`, `<form>`, `<input>`, `<dialog>`, `<body>`).
    * **CSS:** Tests for viewport fit and `overflow: visible` directly relate to CSS properties.
    * **JavaScript:** The Trust Token tests involve `ScriptState` and promises, indicating interaction with JavaScript. The manipulation of DOM elements in the tests also reflects how JavaScript interacts with the DOM.

5. **Consider Logic, Inputs, and Outputs:** For tests involving specific logic (like Trust Tokens or listed elements), I think about potential inputs and expected outputs:

    * **Trust Tokens:** Input: Issuer URL, success/failure scenarios from the browser process. Output: Promise resolution (success/failure) and specific `DOMException` codes.
    * **Listed Elements:** Input: HTML structure with various form elements, dynamic additions/removals, form attribute changes. Output: The list of unassociated listed elements.

6. **Identify Potential User/Programming Errors:** I consider common mistakes developers might make that these tests implicitly cover:

    * Incorrect viewport meta tag syntax.
    * Relying on `hasRedemptionRecord` in insecure contexts.
    * Not handling promise rejections from asynchronous APIs.
    * Incorrectly associating form controls.
    * Making assumptions about which element defines the viewport.

7. **Trace User Operations (Debugging Clues):** I think about how a user's interaction with a web page might lead to the execution of the code being tested:

    * Opening a webpage with specific meta tags or link headers.
    * Submitting forms.
    * Dynamically adding or removing elements via JavaScript.
    * Using JavaScript APIs like `navigator.trustToken().redeem(...)`.
    * Opening modal dialogs.

8. **Synthesize a Summary:** Finally, I combine the information gathered into a concise summary that covers the key functionalities, their relation to web technologies, error handling, and debugging aspects. I organize the summary for clarity and use bullet points for easier reading. Since it's part 3, I specifically focus on summarizing the functionalities covered in *this* specific code snippet, building upon the understanding gained from the hypothetical previous parts.

This systematic approach ensures I cover the essential aspects of the code and provide a comprehensive and insightful summary.
这是`blink/renderer/core/dom/document_test.cc`文件的第 3 部分，延续了对 `Document` 类的功能测试。基于提供的代码片段，我们可以归纳出以下功能测试点：

**核心功能归纳 (基于提供的代码片段):**

* **Trust Token API 测试 (延续):**  继续测试 `Document` 接口中与 Trust Token API 相关的 `hasRedemptionRecord` 方法。
    * **测试 Mojo 连接断开的情况:**  验证在 `hasRedemptionRecord` 操作执行过程中，如果与浏览器进程的 Mojo 连接断开，Promise 是否会正确地被拒绝，并返回预期的 `OperationError` 类型的 `DOMException`。
    * **测试非 HTTP/HTTPS 文档调用 `hasRedemptionRecord` 的情况:** 验证从非 HTTP 或 HTTPS 的安全上下文（例如 `file://` 协议）调用 `hasRedemptionRecord` 是否会抛出 `NotAllowedError` 异常。

* **视口 (Viewport) 配置测试:** 测试与 `<meta name="viewport">` 标签相关的视口配置功能。
    * **测试不存在 `viewport-fit` 属性的情况:** 验证当 `<meta name="viewport">` 存在但没有 `viewport-fit` 属性时，视口的默认行为（`auto`）。
    * **测试通过 JavaScript 强制覆盖 `viewport-fit` 的情况:** 验证 `Document` 对象是否允许通过 JavaScript 代码 (`SetExpandIntoDisplayCutout`) 强制覆盖 `<meta>` 标签中定义的 `viewport-fit` 值，以及这种覆盖的优先级。
    * **参数化测试 `viewport-fit` 的有效值:**  使用参数化测试验证不同的 `viewport-fit` 属性值（`auto`, `contain`, `cover` 以及无效值）是否能被正确解析和应用。

* **文档元数据测试:** 测试与文档元数据相关的属性。
    * **测试 `lastModified` 属性:** 验证 `Document` 对象是否能正确解析和存储 HTTP 响应头中的 `Last-Modified` 信息。

* **文档策略 (Document Policy) 测试:** 测试浏览器如何处理文档策略。
    * **测试重复的文档策略是否被忽略:** 验证当收到重复的 `Document-Policy` HTTP 头时，浏览器是否会忽略后续的策略声明，并只报告一次违规。

* **未关联的列表元素 (Unassociated Listed Elements) 测试:** 测试 `Document` 对象如何跟踪未显式关联到 `<form>` 元素的表单控件（例如 `<button>`, `<input>`, `<select>` 等）。
    * **测试正确提取未关联的列表元素:** 验证 `Document` 对象是否能正确识别和提取文档中未被 `<form>` 包裹的表单控件。测试了多种类型的表单控件。
    * **测试 Shadow DOM 中的未关联列表元素:** 验证是否能正确提取 Shadow DOM 中的未关联列表元素。
    * **测试动态添加/删除未关联列表元素:** 验证当动态地向文档添加或删除未关联的表单控件时，`Document` 对象是否能实时更新其跟踪的列表。
    * **测试动态修改元素的 `form` 属性:** 验证当动态地为一个未关联的表单控件设置或移除 `form` 属性时，其是否会被正确地从未关联列表中添加或移除。
    * **测试添加到未附加到文档的元素上的未关联列表元素:** 验证添加到尚未插入到文档树中的元素上的表单控件不会被视为未关联的。
    * **测试嵌套的未关联列表元素:** 验证嵌套在其他元素内的未关联表单控件也能被正确提取。

* **顶级表单 (Top-Level Forms) 列表测试:** 测试 `Document` 对象如何跟踪直接位于 `<body>` 或 Shadow Root 下的 `<form>` 元素。
    * **测试提取 Light DOM 中的顶级表单:** 验证能够正确列出 Light DOM 中的 `<form>` 元素。
    * **测试动态插入和删除顶级表单:** 验证当动态添加或删除顶级表单时，`Document` 对象维护的列表会同步更新。
    * **测试 Shadow DOM 中的顶级表单:** 验证能够正确列出 Shadow DOM 中的 `<form>` 元素，并且动态添加/删除也会更新列表。
    * **测试忽略嵌套在其他表单内的表单:** 验证 `Document` 对象只会将直接子元素识别为顶级表单，而忽略嵌套在其他表单内的表单。

* **视口定义元素 (Viewport Defining Element) 测试:** 测试在存在多个 `<body>` 元素的情况下，浏览器如何确定哪个元素是视口的定义元素。

* **布局替换元素 (Layout Replaced Elements) 的 `overflow: visible` 使用计数器测试:** 测试浏览器是否正确跟踪在替换元素（如 `<img>`）上显式设置 `overflow: visible` 的情况，以及是否考虑了 `object-fit` 属性。

* **头部预加载 (Header Preload) 测试:** 测试当预加载的资源对应的客户端（例如 `<link>` 元素）被移除并重新添加时，预加载机制是否能正常工作。

* **活动模态对话框 (Active Modal Dialog) 测试:** 测试 `Document` 对象是否能正确跟踪当前活动的模态 `<dialog>` 元素。

* **生命周期状态 (Lifecycle State) 测试:** 测试在没有 `<body>` 元素的情况下，修改文档的样式属性是否会正确触发布局更新。

* **支付链接处理 (Payment Link Handling) 测试 (Android Only):** 测试在 Android 平台上，浏览器是否能正确识别和处理 `<link rel="payment">` 标签，并触发相应的处理逻辑。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * `hasRedemptionRecord` 方法是 JavaScript 可以调用的 API，用于查询 Trust Token 的状态。测试中使用了 `ScriptState` 和 `ScriptPromiseTester` 来模拟 JavaScript 环境并验证 Promise 的结果。
    * 通过 JavaScript 代码 (`SetExpandIntoDisplayCutout`) 强制覆盖 `viewport-fit` 的测试，直接体现了 JavaScript 与 DOM 的交互。
* **HTML:**
    * 大量测试都围绕 HTML 元素和属性展开，例如 `<meta name="viewport">`, `<link>`, `<form>`, `<input>`, `<dialog>`, `<body>` 等。这些测试验证了 `Document` 对象对 HTML 结构和语义的理解。
    * 未关联的列表元素和顶级表单的测试，直接关系到 HTML 中表单控件的组织方式。
* **CSS:**
    * 视口配置的测试直接关联到 CSS 的 `viewport-fit` 属性。
    * 布局替换元素的 `overflow: visible` 测试，验证了 CSS 属性对布局的影响以及浏览器的使用情况统计。

**逻辑推理、假设输入与输出:**

* **`HandlesDisconnectDuringHasRedemptionRecord`:**
    * **假设输入:**  JavaScript 调用 `document.hasRedemptionRecord('https://issuer.example')`，但在 Promise resolve/reject 之前，模拟与浏览器进程的 TrustTokenQueryAnswerer 的 Mojo 连接断开。
    * **预期输出:**  Promise 被拒绝，并且 `promise_tester.Value()` 是一个 `DOMException` 对象，其 `code` 属性为 `OperationError`。

* **`RejectsHasRedemptionRecordCallFromNonHttpNonHttpsDocument`:**
    * **假设输入:**  当前文档的 URL 是 `file:///trusttoken.txt`，JavaScript 调用 `document.hasRedemptionRecord('https://issuer.example')`。
    * **预期输出:**  `hasRedemptionRecord` 方法返回一个空的 Promise，并且会同步抛出一个 `NotAllowedError` 类型的 `DOMException`。

* **`MetaViewportButNoFit`:**
    * **假设输入:**  HTML 中包含 `<meta name='viewport' content='initial-scale=1'>`。
    * **预期输出:**  `GetViewportFit()` 返回 `mojom::ViewportFit::kAuto`。

**用户或编程常见的使用错误举例:**

* **在非安全上下文中使用 `hasRedemptionRecord`:** 开发者可能在 `file://` 协议的页面中调用 `hasRedemptionRecord`，导致意外的异常。
* **错误的 `viewport-fit` 属性值:** 开发者可能在 `<meta>` 标签中使用了无效的 `viewport-fit` 值，导致浏览器使用默认行为。
* **假设所有的表单控件都必须在 `<form>` 内部:**  开发者可能没有意识到未被 `<form>` 包裹的表单控件仍然会被浏览器处理，只是它们的行为可能略有不同。

**用户操作如何到达这里 (调试线索):**

1. **用户访问网页:** 用户在浏览器中打开一个包含相关 HTML 结构和 JavaScript 代码的网页。
2. **触发 Trust Token API 调用:** 网页上的 JavaScript 代码调用了 `document.hasRedemptionRecord()` 方法。
3. **视口配置:** 浏览器解析网页的 `<meta name="viewport">` 标签，并根据其内容配置视口。
4. **浏览器接收 HTTP 响应头:**  当浏览器加载网页资源时，会接收到包含 `Last-Modified` 和 `Document-Policy` 等信息的 HTTP 响应头。
5. **动态 DOM 操作:** 网页上的 JavaScript 代码可能动态地添加、删除或修改 DOM 元素，包括表单控件。
6. **模态对话框交互:** 网页上的 JavaScript 代码可能显示一个模态 `<dialog>` 元素。
7. **Android 平台支付链接:** 在 Android 平台上，如果网页包含 `<link rel="payment">` 标签，浏览器会尝试处理这些链接。

这些用户操作都会触发 Blink 渲染引擎中的相应代码执行，而 `document_test.cc` 中的测试就是为了验证这些代码路径的正确性。当开发者遇到与这些功能相关的问题时，可以通过查看 `document_test.cc` 中的测试用例，了解 Blink 引擎的预期行为，从而更好地进行调试。

Prompt: 
```
这是目录为blink/renderer/core/dom/document_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
 WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasRedemptionRecord");

  auto promise = document.hasRedemptionRecord(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kOperationError));

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasRedemptionRecordInvalidArgument) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(
      MockTrustTokenQueryAnswerer::kInvalidArgument);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasRedemptionRecord");

  auto promise = document.hasRedemptionRecord(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kOperationError));

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HandlesDisconnectDuringHasRedemptionRecord) {
  // Check that a Mojo handle disconnecting during hasRedemptionRecord
  // operation execution results in the promise getting rejected with
  // the proper exception.
  V8TestingScope scope(KURL("https://trusttoken.example"));

  Document& document = scope.GetDocument();

  auto promise = document.hasRedemptionRecord(scope.GetScriptState(),
                                              "https://issuer.example",
                                              scope.GetExceptionState());
  DocumentTest::SimulateTrustTokenQueryAnswererConnectionError(&document);
  ScriptPromiseTester promise_tester(scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(scope.GetScriptState(), promise_tester.Value(),
                             DOMExceptionCode::kOperationError));
}

TEST_F(DocumentTest,
       RejectsHasRedemptionRecordCallFromNonHttpNonHttpsDocument) {
  // Check that hasRedemptionRecord getting called from a secure, but
  // non-http/non-https, document results in an exception being thrown.
  V8TestingScope scope(KURL("file:///trusttoken.txt"));

  Document& document = scope.GetDocument();
  ScriptState* script_state = scope.GetScriptState();
  DummyExceptionStateForTesting exception_state;

  auto promise = document.hasRedemptionRecord(
      script_state, "https://issuer.example", exception_state);
  EXPECT_TRUE(promise.IsEmpty());
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kNotAllowedError);
}

/**
 * Tests for viewport-fit propagation.
 */

class ViewportFitDocumentTest : public DocumentTest,
                                private ScopedDisplayCutoutAPIForTest {
 public:
  ViewportFitDocumentTest() : ScopedDisplayCutoutAPIForTest(true) {}
  void SetUp() override {
    DocumentTest::SetUp();
    GetDocument().GetSettings()->SetViewportMetaEnabled(true);
  }

  mojom::ViewportFit GetViewportFit() const {
    return GetDocument().GetViewportData().GetCurrentViewportFitForTests();
  }
};

// Test meta viewport present but no viewport-fit.
TEST_F(ViewportFitDocumentTest, MetaViewportButNoFit) {
  SetHtmlInnerHTML("<meta name='viewport' content='initial-scale=1'>");

  EXPECT_EQ(mojom::ViewportFit::kAuto, GetViewportFit());
}

// Test overriding the viewport fit using SetExpandIntoDisplayCutout.
TEST_F(ViewportFitDocumentTest, ForceExpandIntoCutout) {
  SetHtmlInnerHTML("<meta name='viewport' content='viewport-fit=contain'>");
  EXPECT_EQ(mojom::ViewportFit::kContain, GetViewportFit());

  // Now override the viewport fit value and expect it to be kCover.
  GetDocument().GetViewportData().SetExpandIntoDisplayCutout(true);
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, GetViewportFit());

  // Test that even if we change the value we ignore it.
  SetHtmlInnerHTML("<meta name='viewport' content='viewport-fit=auto'>");
  EXPECT_EQ(mojom::ViewportFit::kCoverForcedByUserAgent, GetViewportFit());

  // Now remove the override and check that it went back to the previous value.
  GetDocument().GetViewportData().SetExpandIntoDisplayCutout(false);
  EXPECT_EQ(mojom::ViewportFit::kAuto, GetViewportFit());
}

// This is a test case for testing a combination of viewport-fit meta value,
// viewport CSS value and the expected outcome.
using ViewportTestCase = std::tuple<const char*, mojom::ViewportFit>;

class ParameterizedViewportFitDocumentTest
    : public ViewportFitDocumentTest,
      public testing::WithParamInterface<ViewportTestCase> {
 protected:
  void LoadTestHTML() {
    const char* kMetaValue = std::get<0>(GetParam());
    StringBuilder html;

    if (kMetaValue) {
      html.Append("<meta name='viewport' content='viewport-fit=");
      html.Append(kMetaValue);
      html.Append("'>");
    }

    GetDocument().documentElement()->setInnerHTML(html.ReleaseString());
    UpdateAllLifecyclePhasesForTest();
  }
};

TEST_P(ParameterizedViewportFitDocumentTest, EffectiveViewportFit) {
  LoadTestHTML();
  EXPECT_EQ(std::get<1>(GetParam()), GetViewportFit());
}

INSTANTIATE_TEST_SUITE_P(
    All,
    ParameterizedViewportFitDocumentTest,
    testing::Values(
        // Test the default case.
        ViewportTestCase(nullptr, mojom::ViewportFit::kAuto),
        // Test the different values set through the meta tag.
        ViewportTestCase("auto", mojom::ViewportFit::kAuto),
        ViewportTestCase("contain", mojom::ViewportFit::kContain),
        ViewportTestCase("cover", mojom::ViewportFit::kCover),
        ViewportTestCase("invalid", mojom::ViewportFit::kAuto)));

namespace {
class MockReportingContext final : public ReportingContext {
 public:
  explicit MockReportingContext(ExecutionContext& ec) : ReportingContext(ec) {}

  void QueueReport(Report* report, const Vector<String>& endpoint) override {
    report_count++;
  }

  unsigned report_count = 0;
};

}  // namespace

TEST_F(DocumentSimTest, LastModified) {
  const char kLastModified[] = "Tue, 15 Nov 1994 12:45:26 GMT";
  SimRequest::Params params;
  params.response_http_headers = {{"Last-Modified", kLastModified}};
  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  main_resource.Finish();

  // We test lastModifiedTime() instead of lastModified() because the latter
  // returns a string in the local time zone.
  base::Time time;
  ASSERT_TRUE(base::Time::FromString(kLastModified, &time));
  EXPECT_EQ(time, GetDocument().lastModifiedTime());
}

TEST_F(DocumentSimTest, DuplicatedDocumentPolicyViolationsAreIgnored) {
  SimRequest::Params params;
  params.response_http_headers = {{"Document-Policy", "force-load-at-top=?0"}};
  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  main_resource.Finish();

  ExecutionContext* execution_context = GetDocument().GetExecutionContext();
  MockReportingContext* mock_reporting_context =
      MakeGarbageCollected<MockReportingContext>(*execution_context);
  Supplement<ExecutionContext>::ProvideTo(*execution_context,
                                          mock_reporting_context);

  EXPECT_FALSE(execution_context->IsFeatureEnabled(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop,
      PolicyValue::CreateBool(true), ReportOptions::kReportOnFailure));

  EXPECT_EQ(mock_reporting_context->report_count, 1u);

  EXPECT_FALSE(execution_context->IsFeatureEnabled(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop,
      PolicyValue::CreateBool(true), ReportOptions::kReportOnFailure));

  EXPECT_EQ(mock_reporting_context->report_count, 1u);
}

// Tests getting the unassociated listed elements.
class UnassociatedListedElementTest : public DocumentTest {
 protected:
  ListedElement* GetElement(const char* id) {
    Element* element = GetElementById(id);
    return ListedElement::From(*element);
  }
};

// Check if the unassociated listed elements are properly extracted.
// Listed elements are: button, fieldset, input, textarea, output, select,
// object and form-associated custom elements.
TEST_F(UnassociatedListedElementTest, GetUnassociatedListedElements) {
  SetHtmlInnerHTML(R"HTML(
    <button id='unassociated_button'>Unassociated button</button>
    <fieldset id='unassociated_fieldset'>
      <label>Unassociated fieldset</label>
    </fieldset>
    <input id='unassociated_input'>
    <textarea id='unassociated_textarea'>I am unassociated</textarea>
    <output id='unassociated_output'>Unassociated output</output>
    <select id='unassociated_select'>
      <option value='first'>first</option>
      <option value='second' selected>second</option>
    </select>
    <object id='unassociated_object'></object>

    <form id='form'>
      <button id='form_button'>Form button</button>
      <fieldset id='form_fieldset'>
        <label>Form fieldset</label>
      </fieldset>
      <input id='form_input'>
      <textarea id='form_textarea'>I am in a form</textarea>
      <output id='form_output'>Form output</output>
      <select name='form_select' id='form_select'>
        <option value='june'>june</option>
        <option value='july' selected>july</option>
      </select>
      <object id='form_object'></object>
    </form>
 )HTML");

  // Add unassociated form-associated custom element.
  Element* unassociated_custom_element =
      CreateElement(AtomicString("input")).WithIsValue(AtomicString("a-b"));
  unassociated_custom_element->SetIdAttribute(
      AtomicString("unassociated_custom_element"));
  GetDocument().body()->AppendChild(unassociated_custom_element);
  ASSERT_TRUE(GetDocument().getElementById(
      AtomicString("unassociated_custom_element")));

  // Add associated form-associated custom element.
  Element* associated_custom_element =
      CreateElement(AtomicString("input")).WithIsValue(AtomicString("a-b"));
  associated_custom_element->SetIdAttribute(
      AtomicString("associated_custom_element"));
  GetDocument()
      .getElementById(AtomicString("form"))
      ->AppendChild(associated_custom_element);
  ASSERT_TRUE(
      GetDocument().getElementById(AtomicString("associated_custom_element")));

  auto expected_elements = [&] {
    return ElementsAre(
        GetElement("unassociated_button"), GetElement("unassociated_fieldset"),
        GetElement("unassociated_input"), GetElement("unassociated_textarea"),
        GetElement("unassociated_output"), GetElement("unassociated_select"),
        /*Button inside <object> Shadow DOM*/ _,
        GetElement("unassociated_custom_element"));
  };
  EXPECT_THAT(GetDocument().UnassociatedListedElements(), expected_elements());

  // Try getting the cached unassociated listed elements again (calling
  // UnassociatedListedElements() again will not re-extract them).
  EXPECT_THAT(GetDocument().UnassociatedListedElements(), expected_elements());
}

// We extract unassociated listed element in a shadow DOM.
TEST_F(UnassociatedListedElementTest,
       GetUnassociatedListedElementsFromShadowTree) {
  ShadowRoot& shadow_root =
      GetDocument().body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input->SetIdAttribute(AtomicString("unassociated_input"));
  shadow_root.AppendChild(input);
  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements,
              ElementsAre(ListedElement::From(*shadow_root.getElementById(
                  AtomicString("unassociated_input")))));
}

// Check if the dynamically added unassociated listed element is properly
// extracted.
TEST_F(UnassociatedListedElementTest,
       GetDynamicallyAddedUnassociatedListedElements) {
  SetHtmlInnerHTML(R"HTML(
    <form id="form_id">
      <input id='form_input_1'>
    </form>
  )HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());

  auto* input = MakeGarbageCollected<HTMLInputElement>(GetDocument());
  input->SetIdAttribute(AtomicString("unassociated_input"));
  GetDocument().body()->AppendChild(input);

  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements, ElementsAre(GetElement("unassociated_input")));
}

// Check if the dynamically removed unassociated listed element from the
// Document is no longer extracted.
TEST_F(UnassociatedListedElementTest,
       GetDynamicallyRemovedUnassociatedListedElement) {
  SetHtmlInnerHTML(R"HTML(
    <form id='form_id'></form>
    <input id='input_id'>
  )HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements, ElementsAre(GetElement("input_id")));

  GetDocument().getElementById(AtomicString("input_id"))->remove();
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());
}

// Check if dynamically assigning an unassociated listed element to a form by
// changing its form attribute is no longer extracted as an unassociated listed
// element.
TEST_F(UnassociatedListedElementTest,
       GetUnassociatedListedElementAfterAddingFormAttr) {
  SetHtmlInnerHTML(R"HTML(
    <form id='form_id'></form>
    <input id='input_id'>
  )HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements, ElementsAre(GetElement("input_id")));

  GetDocument()
      .getElementById(AtomicString("input_id"))
      ->setAttribute(html_names::kFormAttr, AtomicString("form_id"));
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());
}

// Check if dynamically removing the form attribute from an associated listed
// element makes it unassociated.
TEST_F(UnassociatedListedElementTest,
       GetUnassociatedListedElementAfterRemovingFormAttr) {
  SetHtmlInnerHTML(R"HTML(
    <form id='form_id'></form>
    <input id='input_id' form='form_id'>
  )HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());

  GetDocument()
      .getElementById(AtomicString("input_id"))
      ->removeAttribute(html_names::kFormAttr);
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements, ElementsAre(GetElement("input_id")));
}

// Check if after dynamically setting an associated listed element's form
// attribute to a non-existent one, the element becomes unassociated even if
// inside a <form> element.
TEST_F(UnassociatedListedElementTest,
       GetUnassociatedListedElementAfterSettingFormAttrToNonexistent) {
  SetHtmlInnerHTML(
      R"HTML(<form id='form_id'><input id='input_id'></form>)HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());

  GetDocument()
      .getElementById(AtomicString("input_id"))
      ->setAttribute(html_names::kFormAttr, AtomicString("nonexistent_id"));
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements, ElementsAre(GetElement("input_id")));
}

// Check if dynamically adding an unassociated listed element to an element
// that is not in the Document won't be extracted.
TEST_F(UnassociatedListedElementTest,
       GeDynamicallyAddedUnassociatedListedElementThatIsNotInTheDocument) {
  SetHtmlInnerHTML(R"HTML(<body></body>)HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());

  HTMLDivElement* div = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  div->AppendChild(input);
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());
}

// Check if an unassociated listed element added as a nested element will be
// extracted.
TEST_F(UnassociatedListedElementTest,
       GetAttachedNestedUnassociatedFormFieldElements) {
  SetHtmlInnerHTML(R"HTML(<body></body>)HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());

  HTMLDivElement* div = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  HTMLInputElement* input =
      MakeGarbageCollected<HTMLInputElement>(GetDocument());
  div->AppendChild(input);
  GetDocument().body()->AppendChild(div);
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_EQ(listed_elements[0]->ToHTMLElement(), input);
}

// Check when removing the ancestor element of an unassociated listed element
// won't make the unassociated element extracted.
TEST_F(UnassociatedListedElementTest,
       GetDetachedNestedUnassociatedFormFieldElements) {
  SetHtmlInnerHTML(R"HTML(<div id='div_id'><input id='input_id'></div>)HTML");

  ListedElement::List listed_elements =
      GetDocument().UnassociatedListedElements();
  EXPECT_THAT(listed_elements, ElementsAre(GetElement("input_id")));

  auto* div = GetDocument().getElementById(AtomicString("div_id"));
  div->remove();
  listed_elements = GetDocument().UnassociatedListedElements();
  EXPECT_EQ(0u, listed_elements.size());
}

class TopLevelFormsListTest : public DocumentTest {
 public:
  HTMLFormElement* GetFormElement(const char* id) {
    return DynamicTo<HTMLFormElement>(GetElementById(id));
  }
  HTMLFormElement* GetFormElement(const char* id, ShadowRoot& shadow_root) {
    return DynamicTo<HTMLFormElement>(
        shadow_root.getElementById(AtomicString(id)));
  }
};

// Tests that `GetTopLevelForms` correctly lists forms in the light DOM.
TEST_F(TopLevelFormsListTest, FormsInLightDom) {
  SetHtmlInnerHTML(R"HTML(
    <form id="f1">
      <input type="text">
    </form>
    <div>
      <form id="f2">
        <input type="text">
      </form>
    </div>
  )HTML");
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), GetFormElement("f2")));
  // A second call has the same result.
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), GetFormElement("f2")));
}

// Tests that `GetTopLevelForms` functions correctly after dynamic form element
// insertion and removal.
TEST_F(TopLevelFormsListTest, FormsInLightDomInsertionAndRemoval) {
  SetHtmlInnerHTML(R"HTML(
    <form id="f1">
      <input type="text">
    </form>
    <div>
      <form id="f2">
        <input type="text">
      </form>
    </div>
  )HTML");
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), GetFormElement("f2")));

  // Adding a new form element invalidates the cache.
  Element* new_form = CreateElement(AtomicString("form"));
  new_form->SetIdAttribute(AtomicString("f3"));
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), GetFormElement("f2")));
  GetDocument().body()->AppendChild(new_form);
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), GetFormElement("f3"),
                          GetFormElement("f2")));

  // Removing a form element invalidates the cache.
  GetFormElement("f2")->remove();
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), GetFormElement("f3")));
}

// Tests that top level forms inside shadow DOM are listed correctly and
// insertion and removal updates the cache.
TEST_F(TopLevelFormsListTest, FormsInShadowDomInsertionAndRemoval) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <form id="f1">
      <input type="text">
    </form>
    <div id="d">
      <template shadowrootmode=open>
        <form id="f2">
          <input type="text">
        </form>
      </template>
    </div>
  )HTML");
  HTMLFormElement* f2 =
      GetFormElement("f2", *GetElementById("d")->GetShadowRoot());
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1"), f2));

  // Removing f1 updates the cache.
  GetFormElement("f1")->remove();
  EXPECT_THAT(GetDocument().GetTopLevelForms(), ElementsAre(f2));

  // Removing f2 also updates the cache.
  f2->remove();
  EXPECT_THAT(GetDocument().GetTopLevelForms(), IsEmpty());
}

// Tests that nested forms across shadow DOM are ignored by `GetTopLevelForms`.
TEST_F(TopLevelFormsListTest, GetTopLevelFormsIgnoresNestedChildren) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <form id="f1">
      <input type="text">
      <div id="d">
        <template shadowrootmode=open>
          <form id="f2">
            <input type="text">
          </form>
        </template>
      </div>
    </form>
  )HTML");
  EXPECT_THAT(GetDocument().GetTopLevelForms(),
              ElementsAre(GetFormElement("f1")));
}

TEST_F(DocumentTest, DocumentDefiningElementWithMultipleBodies) {
  SetHtmlInnerHTML(R"HTML(
    <body style="overflow: auto; height: 100%">
      <div style="height: 10000px"></div>
    </body>
  )HTML");

  Element* body1 = GetDocument().body();
  EXPECT_EQ(body1, GetDocument().ViewportDefiningElement());
  EXPECT_FALSE(body1->GetLayoutBox()->GetScrollableArea());

  Element* body2 = To<Element>(body1->cloneNode(true));
  GetDocument().documentElement()->appendChild(body2);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(body1, GetDocument().ViewportDefiningElement());
  EXPECT_FALSE(body1->GetLayoutBox()->GetScrollableArea());
  EXPECT_TRUE(body2->GetLayoutBox()->GetScrollableArea());

  GetDocument().documentElement()->appendChild(body1);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(body2, GetDocument().ViewportDefiningElement());
  EXPECT_TRUE(body1->GetLayoutBox()->GetScrollableArea());
  EXPECT_FALSE(body2->GetLayoutBox()->GetScrollableArea());
}

TEST_F(DocumentTest, LayoutReplacedUseCounterNoStyles) {
  SetHtmlInnerHTML(R"HTML(
    <img>
  )HTML");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

TEST_F(DocumentTest, LayoutReplacedUseCounterExplicitlyHidden) {
  SetHtmlInnerHTML(R"HTML(
    <style> .tag { overflow: hidden } </style>
    <img class=tag>
  )HTML");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

TEST_F(DocumentTest, LayoutReplacedUseCounterExplicitlyVisible) {
  SetHtmlInnerHTML(R"HTML(
    <style> .tag { overflow: visible } </style>
    <img class=tag>
  )HTML");

  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

TEST_F(DocumentTest, LayoutReplacedUseCounterExplicitlyVisibleWithObjectFit) {
  SetHtmlInnerHTML(R"HTML(
    <style> .tag { overflow: visible; object-fit: cover; } </style>
    <img class=tag>
  )HTML");

  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

TEST_F(DocumentTest, LayoutReplacedUseCounterExplicitlyVisibleLaterHidden) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      img { overflow: visible; }
      .tag { overflow: hidden; }
    </style>
    <img class=tag>
  )HTML");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

TEST_F(DocumentTest, LayoutReplacedUseCounterIframe) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      iframe { overflow: visible; }
    </style>
    <iframe></iframe>
  )HTML");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

TEST_F(DocumentTest, LayoutReplacedUseCounterSvg) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      svg { overflow: visible; }
    </style>
    <svg></svg>
  )HTML");

  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElement));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kExplicitOverflowVisibleOnReplacedElementWithObjectProp));
}

// https://crbug.com/1311370
TEST_F(DocumentSimTest, HeaderPreloadRemoveReaddClient) {
  SimRequest::Params main_params;
  main_params.response_http_headers = {
      {"Link", "<https://example.com/sheet.css>;rel=preload;as=style;"}};

  SimRequest main_resource("https://example.com", "text/html", main_params);
  SimSubresourceRequest css_resource("https://example.com/sheet.css",
                                     "text/css");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <link rel="stylesheet" href="sheet.css">
  )HTML");

  // Remove and garbage-collect the pending stylesheet link element, which will
  // remove it from the list of ResourceClients of the Resource being preloaded.
  GetDocument().QuerySelector(AtomicString("link"))->remove();
  ThreadState::Current()->CollectAllGarbageForTesting();

  // Removing the ResourceClient should not affect the preloading.
  css_resource.Complete(".target { width: 100px; }");

  // After the preload finishes, when a new ResourceClient is added, it should
  // be able to use the Resource immediately.
  main_resource.Complete(R"HTML(
    <link rel="stylesheet" href="sheet.css">
    <div class="target"></div>
  )HTML");

  Element* target = GetDocument().QuerySelector(AtomicString(".target"));
  EXPECT_EQ(100, target->OffsetWidth());
}

TEST_F(DocumentTest, ActiveModalDialog) {
  SetHtmlInnerHTML(R"HTML(
    <dialog id="modal"></dialog>
    <dialog popover id="popover"></dialog>
  )HTML");

  HTMLDialogElement* modal = DynamicTo<HTMLDialogElement>(
      GetDocument().getElementById(AtomicString("modal")));
  HTMLDialogElement* popover = DynamicTo<HTMLDialogElement>(
      GetDocument().getElementById(AtomicString("popover")));

  ASSERT_TRUE(modal);
  ASSERT_TRUE(popover);

  EXPECT_EQ(GetDocument().ActiveModalDialog(), nullptr);

  NonThrowableExceptionState exception_state;
  modal->showModal(exception_state);

  EXPECT_EQ(GetDocument().ActiveModalDialog(), modal);
  ASSERT_FALSE(GetDocument().TopLayerElements().empty());
  EXPECT_EQ(GetDocument().TopLayerElements().back(), modal);

  popover->showPopover(exception_state);

  // The popover is the last of the top layer elements, but it's not modal.
  ASSERT_FALSE(GetDocument().TopLayerElements().empty());
  EXPECT_EQ(GetDocument().TopLayerElements().back(), popover);
  EXPECT_EQ(GetDocument().ActiveModalDialog(), modal);
}

TEST_F(DocumentTest, LifecycleState_DirtyStyle_NoBody) {
  GetDocument().body()->remove();
  UpdateAllLifecyclePhasesForTest();
  GetDocument().documentElement()->setAttribute(html_names::kStyleAttr,
                                                AtomicString("color:pink"));
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_EQ(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kVisualUpdatePending);
}

class TestPaymentLinkHandler
    : public payments::facilitated::mojom::blink::PaymentLinkHandler {
 public:
  void HandlePaymentLink(const KURL& url) override {
    ++payment_link_handled_counter_;
    handled_url_ = url;
    std::move(on_link_handled_callback_).Run();
  }

  int get_payment_link_handled_counter() const {
    return payment_link_handled_counter_;
  }

  const KURL& get_handled_url() const { return handled_url_; }

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(mojo::PendingReceiver<
                   payments::facilitated::mojom::blink::PaymentLinkHandler>(
        std::move(handle)));
  }

  void set_on_link_handled_callback(
      base::OnceClosure on_link_handled_callback) {
    on_link_handled_callback_ = std::move(on_link_handled_callback);
  }

 private:
  int payment_link_handled_counter_ = 0;
  KURL handled_url_;
  mojo::Receiver<payments::facilitated::mojom::blink::PaymentLinkHandler>
      receiver_{this};
  base::OnceClosure on_link_handled_callback_;
};

#if BUILDFLAG(IS_ANDROID)
TEST_F(DocumentTest, PaymentLinkHandling_SinglePaymentLink) {
  TestPaymentLinkHandler test_payment_link_handler;
  base::RunLoop run_loop;
  test_payment_link_handler.set_on_link_handled_callback(
      run_loop.QuitClosure());

  GetDocument().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      payments::facilitated::mojom::blink::PaymentLinkHandler::Name_,
      base::BindRepeating(&TestPaymentLinkHandler::Bind,
                          base::Unretained(&test_payment_link_handler)));

  ScopedPaymentLinkDetectionForTest payment_link_detection(true);

  SetHtmlInnerHTML(R"HTML(
    <head>
      <link rel="payment" href="upi://payment_link_1">
    </head>
  )HTML");

  // Run the message loop to ensure Mojo messages are dispatched.
  run_loop.Run();

  // Check if the correct payment link was handled.
  EXPECT_EQ(test_payment_link_handler.get_payment_link_handled_counter(), 1);
  EXPECT_EQ(test_payment_link_handler.get_handled_url(),
            KURL("upi://payment_link_1"));
}

TEST_F(DocumentTest, PaymentLinkHandling_MultiplePaymentLink) {
  TestPaymentLinkHandler test_payment_link_handler;
  base::RunLoop run_loop;
  test_payment_link_handler.set_on_link_handled_callback(
      run_loop.QuitClosure());

  GetDocument().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      payments::facilitated::mojom::blink::PaymentLinkHandler::Name_,
      base::BindRepeating(&TestPaymentLinkHandler::Bind,
                          base::Unretained(&test_payment_link_handler)));

  ScopedPaymentLinkDetectionForTest payment_link_detection(true);

  SetHtmlInnerHTML(R"HTML(
    <head>
      <link rel="payment" href="upi://payment_link_1">
      <link rel="payment" href="upi://payment_link_2">
    </head>
  )HTML");

  // Run the message loop to ensure Mojo messages are dispatched.
  run_loop.Run();

  // Check if the correct payment link was handled and the payment link handling
  // was invoked only once.
  EXPECT_EQ(test_payment_link_handler.get_payment_link_handled_counter(), 1);
  EXPECT_EQ(test_payment_link_handler.get_handled_url(),
            KURL("upi://payment_link_1"));
}
#endif  // BUILDFLAG(IS_ANDROID)

}  // namespace blink

"""


```
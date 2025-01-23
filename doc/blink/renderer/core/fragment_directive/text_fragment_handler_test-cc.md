Response:
The user wants me to summarize the functionality of the provided C++ test file. The file seems to be testing the `TextFragmentHandler` class in the Chromium Blink engine.

Here's a breakdown of what the tests appear to cover:

1. **Text Fragment Matching and Highlighting:** Tests if the handler correctly identifies and highlights text fragments specified in the URL hash.
2. **Removing Highlights:** Checks if the handler can remove the highlights.
3. **Extracting Matching Text:** Verifies the ability to extract the matched text fragments.
4. **Extracting the Location of the First Match:** Tests the functionality for getting the screen coordinates of the first matched text fragment.
5. **Preemptive Link Generation:**  Examines if the handler generates a link (selector) for selected text when the context menu is opened.
6. **Link Generation Restrictions:**  Checks scenarios where link generation should not occur (e.g., blocklisted sites, editable content).
7. **Mojo Integration:** Tests the interaction of the `TextFragmentHandler` with its Mojo interface (`TextFragmentReceiver`). This includes removing highlights and requesting selectors via Mojo.
8. **IFrames:**  Verifies the handler's behavior within iframes.
9. **Metrics:** Confirms that metrics related to link generation are being recorded correctly.

I need to synthesize these observations into a concise summary for part 1.
这是位于 `blink/renderer/core/fragment_directive/text_fragment_handler_test.cc` 的 Chromium Blink 引擎源代码文件，它主要的功能是**测试 `TextFragmentHandler` 类的各项功能**。`TextFragmentHandler` 负责处理 URL 中文本片段指令（Text Fragment Directive），即 `#:~:text=` 部分，用于在页面加载时自动滚动并高亮显示指定的文本。

以下是根据提供的代码列举的 `TextFragmentHandlerTest` 类及其测试用例所涵盖的功能：

1. **文本片段匹配与高亮显示:**
   - 测试当 URL 中包含文本片段指令时，`TextFragmentHandler` 是否能正确识别并高亮显示页面中的匹配文本。
   - **假设输入:** URL 为 `https://example.com/test.html#:~:text=test%20page`，页面内容包含 `<p>This is a test page</p>`。
   - **预期输出:** 页面加载后，“test page” 这部分文本会被高亮显示。

2. **移除文本片段高亮:**
   - 测试 `TextFragmentHandler` 是否能够移除已经添加的文本片段高亮。
   - **假设输入:** 页面已经因为 URL 中的文本片段指令而高亮显示了部分文本。
   - **预期输出:** 调用 `RemoveFragments()` 后，高亮显示被移除。

3. **提取匹配的文本片段:**
   - 测试 `TextFragmentHandler` 是否能够提取出所有匹配的文本片段。
   - **假设输入:** URL 为 `https://example.com/test.html#:~:text=test%20page&text=more%20text`，页面内容包含 `<p>This is a test page</p>` 和 `<p>With some more text</p>`。
   - **预期输出:** 调用 `ExtractTextFragmentsMatches()` 后，返回包含 "test page" 和 "more text" 的字符串向量。

4. **提取首个匹配文本片段的屏幕坐标:**
   - 测试 `TextFragmentHandler` 是否能够获取第一个匹配到的文本片段在屏幕上的位置和尺寸。这涉及到与渲染引擎的交互。
   - **假设输入:** URL 为 `https://example.com/test.html#:~:text=This,page`，页面内容包含 `<p>This is a test page</p>`。
   - **预期输出:** 调用 `ExtractFirstTextFragmentsRect()` 后，返回一个 `gfx::Rect` 对象，表示 "This is a test page" 这部分文本在视口中的矩形区域。

5. **预先生成文本片段选择器 (Preemptive Generation):**
   - 测试在用户选中一段文本并打开上下文菜单时，`TextFragmentHandler` 是否能够预先生成用于创建指向该文本片段的链接的选择器。
   - **与 JavaScript 的关系:**  虽然测试代码是 C++，但该功能最终会影响到用户与网页的交互，例如，用户可以通过复制生成的链接分享到特定文本位置。
   - **与 HTML 的关系:**  选择器是基于 HTML 结构生成的，用于精确定位选中的文本。
   - **假设输入:** 用户在页面上选中了 "First" 这部分文本并打开了上下文菜单。
   - **预期输出:**  后台会生成一个类似于 "First" 的文本片段选择器。

6. **阻止在特定情况下预先生成选择器:**
   - 测试在某些情况下（如 URL 在黑名单中，选中的是可编辑文本）不会预先生成选择器。
   - **与 JavaScript, HTML 的关系:**  涉及对特定网站或 HTML 元素的判断，以决定是否启用此功能。
   - **假设输入 (黑名单):** 当前页面 URL 为 `https://instagram.com/test.html`，用户选中了文本。
   - **预期输出 (黑名单):** 不会预先生成选择器。
   - **假设输入 (可编辑文本):** 用户在 `<input>` 元素中选中了文本。
   - **预期输出 (可编辑文本):** 不会预先生成选择器。

7. **处理跨域 Iframe 中的文本片段:**
   - 测试 `TextFragmentHandler` 在包含 Iframe 的页面中，能否正确处理 Iframe 中的文本片段指令。
   - **与 HTML 的关系:**  涉及到对 HTML `<iframe>` 元素的处理。
   - **假设输入:** 主页面和 Iframe 的 URL 都包含文本片段指令。
   - **预期输出:** 主页面和 Iframe 中指定的文本都会被高亮显示。

8. **通过 Mojo 接口与渲染进程通信:**
   - 测试 `TextFragmentHandler` 通过 Mojo 接口 (`TextFragmentReceiver`) 与渲染进程进行通信，例如移除高亮和请求选择器。
   - 这部分涉及到 Chromium 的进程间通信机制。

9. **处理没有匹配项的情况:**
   - 测试当 URL 中的文本片段指令在页面中找不到匹配项时，`TextFragmentHandler` 的行为。
   - **假设输入:** URL 为 `https://example.com/test.html#:~:text=non%20existent%20text`，但页面内容不包含 "non existent text"。
   - **预期输出:** 不会高亮显示任何内容，但 `TextFragmentHandler` 仍然会被创建。

**用户或编程常见的使用错误示例 (推断):**

虽然代码本身是测试，但可以推断一些用户或编程中可能出现的错误：

- **URL 编码错误:**  文本片段指令中的特殊字符如果没有正确进行 URL 编码，可能导致匹配失败。例如，空格应该编码为 `%20`。
- **HTML 结构变化:** 如果页面的 HTML 结构与生成选择器时的结构发生变化，之前生成的选择器可能无法正确匹配到目标文本。
- **JavaScript 动态修改内容:**  如果页面加载后，JavaScript 动态修改了文本内容，原本匹配的文本片段可能不再存在。

**总结一下 `TextFragmentHandlerTest` 的功能 (Part 1 归纳):**

该测试文件主要用于验证 Chromium Blink 引擎中 `TextFragmentHandler` 类的核心功能，包括文本片段的解析、匹配、高亮显示、移除，以及预先生成文本片段选择器的能力。它还测试了在特定场景下（如黑名单网站、可编辑内容）阻止选择器生成，并涵盖了与 Iframe 和 Mojo 接口的交互。 总之，这些测试旨在确保文本片段指令功能的正确性和稳定性。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"

#include <gtest/gtest.h>

#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/run_loop.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "components/shared_highlighting/core/common/shared_highlighting_features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mouse_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/core/css/css_font_face.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using test::RunPendingTasks;

class TextFragmentHandlerTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }

  void RunAsyncMatchingTasks() {
    ThreadScheduler::Current()
        ->ToMainThreadScheduler()
        ->StartIdlePeriodForTesting();
    RunPendingTasks();
  }

  void SetSelection(const Position& start, const Position& end) {
    GetDocument().GetFrame()->Selection().SetSelection(
        SelectionInDOMTree::Builder().SetBaseAndExtent(start, end).Build(),
        SetSelectionOptions());
  }

  void SetLocationHash(Document& document, String hash) {
    ScriptState* script_state = ToScriptStateForMainWorld(document.GetFrame());
    ScriptState::Scope entered_context_scope(script_state);
    document.GetFrame()->DomWindow()->location()->setHash(
        script_state->GetIsolate(), hash, ASSERT_NO_EXCEPTION);
  }

  String SelectThenRequestSelector(const Position& start, const Position& end) {
    SetSelection(start, end);
    TextFragmentHandler::OpenedContextMenuOverSelection(
        GetDocument().GetFrame());
    return RequestSelector();
  }

  String RequestSelector() {
    bool callback_called = false;
    String selector;
    auto lambda =
        [](bool& callback_called, String& selector,
           const String& generated_selector,
           shared_highlighting::LinkGenerationError error,
           shared_highlighting::LinkGenerationReadyStatus ready_status) {
          selector = generated_selector;
          callback_called = true;
        };
    auto callback =
        WTF::BindOnce(lambda, std::ref(callback_called), std::ref(selector));
    GetTextFragmentHandler().RequestSelector(std::move(callback));
    base::RunLoop().RunUntilIdle();

    EXPECT_TRUE(callback_called);
    return selector;
  }

  Vector<String> ExtractTextFragmentsMatches() {
    bool callback_called = false;
    Vector<String> target_texts;
    auto lambda = [](bool& callback_called, Vector<String>& target_texts,
                     const Vector<String>& fetched_target_texts) {
      target_texts = fetched_target_texts;
      callback_called = true;
    };
    auto callback = WTF::BindOnce(lambda, std::ref(callback_called),
                                  std::ref(target_texts));

    GetTextFragmentHandler().ExtractTextFragmentsMatches(std::move(callback));

    EXPECT_TRUE(callback_called);
    return target_texts;
  }

  gfx::Rect ExtractFirstTextFragmentsRect() {
    bool callback_called = false;
    gfx::Rect text_fragment_rect;
    auto lambda = [](bool& callback_called, gfx::Rect& text_fragment_rect,
                     const gfx::Rect& fetched_text_fragment_rect) {
      text_fragment_rect = fetched_text_fragment_rect;
      callback_called = true;
    };
    auto callback = WTF::BindOnce(lambda, std::ref(callback_called),
                                  std::ref(text_fragment_rect));

    GetTextFragmentHandler().ExtractFirstFragmentRect(std::move(callback));

    EXPECT_TRUE(callback_called);
    return text_fragment_rect;
  }

  void LoadAhem() {
    std::optional<Vector<char>> data =
        test::ReadFromFile(test::CoreTestDataPath("Ahem.ttf"));
    ASSERT_TRUE(data);
    auto* buffer =
        MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferViewOrString>(
            DOMArrayBuffer::Create(base::as_byte_span(*data)));
    FontFace* ahem = FontFace::Create(GetDocument().GetExecutionContext(),
                                      AtomicString("Ahem"), buffer,
                                      FontFaceDescriptors::Create());

    ScriptState* script_state =
        ToScriptStateForMainWorld(GetDocument().GetFrame());
    DummyExceptionStateForTesting exception_state;
    FontFaceSetDocument::From(GetDocument())
        ->addForBinding(script_state, ahem, exception_state);
  }

  TextFragmentHandler& GetTextFragmentHandler() {
    if (!GetDocument().GetFrame()->GetTextFragmentHandler())
      GetDocument().GetFrame()->CreateTextFragmentHandler();
    return *GetDocument().GetFrame()->GetTextFragmentHandler();
  }

  bool HasTextFragmentHandler(LocalFrame* frame) {
    return frame->GetTextFragmentHandler();
  }

 protected:
  base::HistogramTester histogram_tester_;
  base::test::ScopedFeatureList feature_list_;
};

TEST_F(TextFragmentHandlerTest, RemoveTextFragments) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  // Render two frames to handle the async step added by the beforematch event.
  Compositor().BeginFrame();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  GetTextFragmentHandler().RemoveFragments();

  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  // Ensure the fragment is uninstalled
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());
}

TEST_F(TextFragmentHandlerTest,
       ExtractTextFragmentWithWithMultipleTextFragments) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  Vector<String> target_texts = ExtractTextFragmentsMatches();

  EXPECT_EQ(2u, target_texts.size());
  EXPECT_EQ("test page", target_texts[0]);
  EXPECT_EQ("more text", target_texts[1]);
}

TEST_F(TextFragmentHandlerTest, ExtractTextFragmentWithNoMatch) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=not%20on%20the%20page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=not%20on%20the%20page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p>This is a test page, with some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  Vector<String> target_texts = ExtractTextFragmentsMatches();

  EXPECT_EQ(0u, target_texts.size());
}

TEST_F(TextFragmentHandlerTest, ExtractTextFragmentWithRange) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=This,text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=This,text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p>This is a test page, with some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  Vector<String> target_texts = ExtractTextFragmentsMatches();

  EXPECT_EQ(1u, target_texts.size());
  EXPECT_EQ("This is a test page, with some more text", target_texts[0]);
}

TEST_F(TextFragmentHandlerTest, ExtractTextFragmentWithRangeAndContext) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=this,is&text=a-,test,page&text=with,some,-content&"
      "text=about-,nothing,at,-all",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=this,is&text=a-,test,page&text=with,some,-content&"
      "text=about-,nothing,at,-all");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test for the page</p>
    <p>With some content</p>
    <p>About nothing at all</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(4u, GetDocument().Markers().Markers().size());

  Vector<String> target_texts = ExtractTextFragmentsMatches();

  EXPECT_EQ(4u, target_texts.size());
  EXPECT_EQ("This is", target_texts[0]);
  EXPECT_EQ("test for the page", target_texts[1]);
  EXPECT_EQ("With some", target_texts[2]);
  EXPECT_EQ("nothing at", target_texts[3]);
}

TEST_F(TextFragmentHandlerTest, ExtractFirstTextFragmentRect) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=This,page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=This,page");
  LoadAhem();
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <meta name="viewport" content="width=device-width">
    <style>p { font: 10px/1 Ahem; }</style>
    <p id="first">This is a test page</p>
    <p id="second">with some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(first_paragraph, 19);
  ASSERT_EQ("This is a test page", PlainText(EphemeralRange(start, end)));
  gfx::Rect rect(ComputeTextRect(EphemeralRange(start, end)));
  gfx::Rect expected_rect =
      GetDocument().GetFrame()->View()->FrameToViewport(rect);
  // ExtractFirstTextFragmentsRect should return the first matched viewport
  // relative location.
  ASSERT_EQ(expected_rect.ToString(), "8,10 190x10");

  gfx::Rect text_fragment_rect = ExtractFirstTextFragmentsRect();

  EXPECT_EQ(expected_rect.ToString(), text_fragment_rect.ToString());
}

TEST_F(TextFragmentHandlerTest, ExtractFirstTextFragmentRectScroll) {
  // Android settings to correctly extract the rect when the page is loaded
  // zoomed in
  WebView().GetPage()->GetSettings().SetViewportEnabled(true);
  WebView().GetPage()->GetSettings().SetViewportMetaEnabled(true);
  WebView().GetPage()->GetSettings().SetShrinksViewportContentToFit(true);
  WebView().GetPage()->GetSettings().SetMainFrameResizesAreOrientationChanges(
      true);
  SimRequest request("https://example.com/test.html#:~:text=test,page",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test,page");
  LoadAhem();
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <meta name="viewport" content="initial-scale=4">
    <style>
      body {
        height: 2200px;
      }
      p {
        position: absolute;
        top: 2000px;
        font: 10px/1 Ahem;
      }
    </style>
    <p id="first">This is a test page</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(first_paragraph, 10);
  const auto& end = Position(first_paragraph, 19);
  ASSERT_EQ("test page", PlainText(EphemeralRange(start, end)));
  gfx::Rect rect(ComputeTextRect(EphemeralRange(start, end)));
  gfx::Rect expected_rect =
      GetDocument().GetFrame()->View()->FrameToViewport(rect);
  // ExtractFirstTextFragmentsRect should return the first matched scaled
  // viewport relative location since the page is loaded zoomed in 4X
  ASSERT_EQ(gfx::Rect(432, 300, 360, 40), expected_rect);

  gfx::Rect text_fragment_rect = ExtractFirstTextFragmentsRect();

  EXPECT_EQ(expected_rect, text_fragment_rect);
}

TEST_F(TextFragmentHandlerTest, ExtractFirstTextFragmentRectMultipleHighlight) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  LoadAhem();
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <meta name="viewport" content="width=device-width">
    <style>
      p {
        font: 10px/1 Ahem;
      }
      body {
        height: 1200px;
      }
      #second {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(first_paragraph, 10);
  const auto& end = Position(first_paragraph, 19);
  ASSERT_EQ("test page", PlainText(EphemeralRange(start, end)));
  gfx::Rect rect(ComputeTextRect(EphemeralRange(start, end)));
  gfx::Rect expected_rect =
      GetDocument().GetFrame()->View()->FrameToViewport(rect);
  // ExtractFirstTextFragmentsRect should return the first matched viewport
  // relative location.
  ASSERT_EQ(expected_rect.ToString(), "108,10 90x10");

  gfx::Rect text_fragment_rect = ExtractFirstTextFragmentsRect();

  EXPECT_EQ(expected_rect.ToString(), text_fragment_rect.ToString());
}

TEST_F(TextFragmentHandlerTest,
       ExtractFirstTextFragmentRectMultipleHighlightWithNoFoundText) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=fake&text=test%20page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=fake&text=test%20page");
  LoadAhem();
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <meta name="viewport" content="width=device-width">
    <style>
      p {
        font: 10px/1 Ahem;
      }
      body {
        height: 1200px;
      }
      #second {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="first">This is a test page</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = Position(first_paragraph, 10);
  const auto& end = Position(first_paragraph, 19);
  ASSERT_EQ("test page", PlainText(EphemeralRange(start, end)));
  gfx::Rect rect(ComputeTextRect(EphemeralRange(start, end)));
  gfx::Rect expected_rect =
      GetDocument().GetFrame()->View()->FrameToViewport(rect);
  // ExtractFirstTextFragmentsRect should return the first matched viewport
  // relative location.
  ASSERT_EQ(expected_rect.ToString(), "108,10 90x10");

  gfx::Rect text_fragment_rect = ExtractFirstTextFragmentsRect();

  EXPECT_EQ(expected_rect.ToString(), text_fragment_rect.ToString());
}

TEST_F(TextFragmentHandlerTest, RejectExtractFirstTextFragmentRect) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=not%20on%20the%20page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=not%20on%20the%20page");
  LoadAhem();
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <meta name="viewport" content="width=device-width">
    <style>
      p {
        font: 10px/1 Ahem;
      }
      body {
        height: 1200px;
      }
      #second {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  gfx::Rect text_fragment_rect = ExtractFirstTextFragmentsRect();

  EXPECT_TRUE(text_fragment_rect.IsEmpty());
}

// Checks that the selector is preemptively generated.
TEST_F(TextFragmentHandlerTest, CheckPreemptiveGeneration) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph</p>
    )HTML");

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 5);
  ASSERT_EQ("First", PlainText(EphemeralRange(selected_start, selected_end)));

  SetSelection(selected_start, selected_end);
  TextFragmentHandler::OpenedContextMenuOverSelection(GetDocument().GetFrame());

  base::RunLoop().RunUntilIdle();

  histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated", 1);
  histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated.Error", 0);
}

// When URL is blocklisted, the selector shouldn't be preemptively generated.
TEST_F(TextFragmentHandlerTest, CheckNoPreemptiveGenerationBlocklist) {
  SimRequest request("https://instagram.com/test.html", "text/html");
  LoadURL("https://instagram.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id='first'>First paragraph</p>
    )HTML");

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 5);
  ASSERT_EQ("First", PlainText(EphemeralRange(selected_start, selected_end)));

  SetSelection(selected_start, selected_end);
  TextFragmentHandler::OpenedContextMenuOverSelection(GetDocument().GetFrame());

  base::RunLoop().RunUntilIdle();

  histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated", 0);
  histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated.Error", 0);
}

// Check that selector is not generated for editable text.
TEST_F(TextFragmentHandlerTest, CheckNoPreemptiveGenerationEditable) {
  SimRequest request("https://instagram.com/test.html", "text/html");
  LoadURL("https://instagram.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <input type="text" id="input" value="default text in input">
    )HTML");

  Node* input_text = FlatTreeTraversal::Next(
                         *GetDocument().getElementById(AtomicString("input")))
                         ->firstChild();
  const auto& selected_start = Position(input_text, 0);
  const auto& selected_end = Position(input_text, 12);
  ASSERT_EQ("default text",
            PlainText(EphemeralRange(selected_start, selected_end)));

  SetSelection(selected_start, selected_end);
  TextFragmentHandler::OpenedContextMenuOverSelection(GetDocument().GetFrame());

  base::RunLoop().RunUntilIdle();

  histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated", 0);
  histogram_tester_.ExpectTotalCount("SharedHighlights.LinkGenerated.Error", 0);
}

// TODO(crbug.com/1192047): Update the test to better reflect the real repro
// steps. Test case for crash in crbug.com/1190137. When selector is requested
// after callback is set and unused.
TEST_F(TextFragmentHandlerTest, SecondGenerationCrash) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
  <p id='p'>First paragraph text</p>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  Node* p = GetDocument().getElementById(AtomicString("p"));
  const auto& start = Position(p->lastChild(), 0);
  const auto& end = Position(p->lastChild(), 15);
  ASSERT_EQ("First paragraph", PlainText(EphemeralRange(start, end)));
  SetSelection(start, end);

  auto callback =
      WTF::BindOnce([](const TextFragmentSelector& selector,
                       shared_highlighting::LinkGenerationError error) {});
  MakeGarbageCollected<TextFragmentSelectorGenerator>(GetDocument().GetFrame())
      ->SetCallbackForTesting(std::move(callback));

  // This shouldn't crash.
  TextFragmentHandler::OpenedContextMenuOverSelection(GetDocument().GetFrame());
  base::RunLoop().RunUntilIdle();
}

// Verifies metrics for preemptive generation are correctly recorded when the
// selector is successfully generated.
TEST_F(TextFragmentHandlerTest, CheckMetrics_Success) {
  base::test::ScopedFeatureList feature_list;
  // Basic exact selector case.
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 28);
  ASSERT_EQ("First paragraph text that is",
            PlainText(EphemeralRange(selected_start, selected_end)));

  String selector = SelectThenRequestSelector(selected_start, selected_end);
  EXPECT_EQ(selector, "First%20paragraph%20text%20that%20is");
}

// Verifies metrics for preemptive generation are correctly recorded when the
// selector request fails, in this case, because the context limit is reached.
TEST_F(TextFragmentHandlerTest, CheckMetrics_Failure) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph prefix one two three four five six seven
     eight nine ten to not unique snippet of text followed by suffix</p>
    <p id='second'>Second paragraph prefix one two three four five six seven
     eight nine ten to not unique snippet of text followed by suffix</p>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 80);
  const auto& selected_end = Position(first_paragraph, 106);
  ASSERT_EQ("not unique snippet of text",
            PlainText(EphemeralRange(selected_start, selected_end)));
  String selector = SelectThenRequestSelector(selected_start, selected_end);
  EXPECT_EQ(selector, "");
}

TEST_F(TextFragmentHandlerTest,
       ShouldCreateTextFragmentHandlerAndRemoveHighlightForIframes) {
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
    <iframe id="iframe" src="child.html"></iframe>
  )HTML");

  child_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <p>
      test
    </p>
    <script>
      window.location.hash = ':~:text=test';
    </script>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element* iframe = GetDocument().getElementById(AtomicString("iframe"));
  auto* child_frame =
      To<LocalFrame>(To<HTMLFrameOwnerElement>(iframe)->ContentFrame());

  EXPECT_EQ(1u, child_frame->GetDocument()->Markers().Markers().size());
  EXPECT_TRUE(HasTextFragmentHandler(child_frame));

  TextFragmentHandler::OpenedContextMenuOverSelection(GetDocument().GetFrame());

  mojo::Remote<mojom::blink::TextFragmentReceiver> remote;
  child_frame->BindTextFragmentReceiver(remote.BindNewPipeAndPassReceiver());

  ASSERT_TRUE(remote.is_bound());
  remote.get()->RemoveFragments();

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, child_frame->GetDocument()->Markers().Markers().size());

  // Ensure the fragment is uninstalled
  EXPECT_FALSE(child_frame->GetDocument()->View()->GetFragmentAnchor());
}

TEST_F(TextFragmentHandlerTest, NonMatchingTextDirectiveCreatesHandler) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  Compositor().BeginFrame();

  ASSERT_FALSE(HasTextFragmentHandler(GetDocument().GetFrame()));

  // Navigate to a text directive that doesn't exist on the page.
  SetLocationHash(GetDocument(), ":~:text=non%20existent%20text");

  Compositor().BeginFrame();
  RunAsyncMatchingTasks();

  ASSERT_EQ(0u, GetDocument().Markers().Markers().size());

  // Even though the directive didn't find a match, a handler is created by the
  // attempt.
  EXPECT_TRUE(HasTextFragmentHandler(GetDocument().GetFrame()));
}

TEST_F(TextFragmentHandlerTest, MatchingTextDirectiveCreatesHandler) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p>This is a test page</p>
  )HTML");
  Compositor().BeginFrame();

  ASSERT_FALSE(HasTextFragmentHandler(GetDocument().GetFrame()));

  // Navigate to a text directive that highlights "test page".
  SetLocationHash(GetDocument(), ":~:text=test%20page");

  Compositor().BeginFrame();
  Compositor().BeginFrame();
  RunAsyncMatchingTasks();

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());

  EXPECT_TRUE(HasTextFragmentHandler(GetDocument().GetFrame()));
}

TEST_F(TextFragmentHandlerTest,
       ShouldCreateTextFragmentHandlerAndRemoveHighlight) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  Compositor().BeginFrame();

  ASSERT_EQ(0u, GetDocument().Markers().Markers().size());
  ASSERT_FALSE(HasTextFragmentHandler(GetDocument().GetFrame()));

  // Binding a receiver should create a handler.
  mojo::Remote<mojom::blink::TextFragmentReceiver> remote;
  GetDocument().GetFrame()->BindTextFragmentReceiver(
      remote.BindNewPipeAndPassReceiver());
  EXPECT_TRUE(remote.is_bound());
  EXPECT_TRUE(HasTextFragmentHandler(GetDocument().GetFrame()));

  // Set the fragment to two text directives.
  SetLocationHash(GetDocument(), ":~:text=test%20page&text=more%20text");

  // Render two frames to handle the async step added by the beforematch event.
  Compositor().BeginFrame();
  Compositor().BeginFrame();
  RunAsyncMatchingTasks();

  ASSERT_EQ(2u, GetDocument().Markers().Markers().size());

  // Ensure RemoveFragments called via Mojo removes the document markers.
  remote.get()->RemoveFragments();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  // Ensure the fragment was uninstalled.
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());
}

TEST_F(TextFragmentHandlerTest,
       ShouldCreateTextFragmentHandlerAndRequestSelector) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>Test page</div>
    <p id='first'>First paragraph text that is longer than 20 chars</p>
    <p id='second'>Second paragraph text</p>
  )HTML");

  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& selected_start = Position(first_paragraph, 0);
  const auto& selected_end = Position(first_paragraph, 28);
  ASSERT_EQ("First paragraph text that is",
            PlainText(EphemeralRange(selected_start, selected_end)));

  SetSelection(selected_start, selected_end);

  mojo::Remote<mojom::blink::TextFragmentReceiver> remote;
  EXPECT_FALSE(HasTextFragmentHandler(GetDocument().GetFrame()));
  EXPECT_FALSE(remote.is_bound());

  TextFragmentHandler::OpenedContextMenuOverSelection(GetDocument().GetFrame());
  GetDocument().GetFrame()->BindTextFragmentReceiver(
      remote.BindNewPipeAndPassReceiver());

  EXPECT_TRUE(HasTextFragmentHandler(GetDocument().GetFrame()));
  EXPECT_TRUE(remote.is_bound());

  bool callback_called = false;
  String selector;
  auto lambda =
      [](bool& callback_called, String& selector,
         const String& generated_selector,
         shared_highlighting::LinkGenerationError error,
         shared_highlighting::LinkGenerationReadyStatus ready_status) {
        selector = generated_selector;
        callback_called = true;
      };
  auto callback =
      WTF::BindOnce(lambda, std::ref(callback_called), std::ref(selector));
  remote->RequestSelector(std::move(callback));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(callback_called);

  EXPECT_EQ(selector, "First%20paragraph%20text%20that%20is");
}

// Verify that removing a shared highlight removes document markers and the
// text directive from the URL, for both main frame and subframe.
TEST_F(TextFragmentHandlerTest,
       ShouldRemoveFromMainFrameAndIframeWhenBothHaveHighlights) {
  SimRequest main_request("https://example.com/test.html#:~:text=test",
                          "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id="first">This is a test page</p>
    <iframe id="iframe" src="child.html"></iframe>
  )HTML");

  child_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <p>
      iframe
    </p>
    <script>
      window.location.hash = ':~:text=iframe';
    </script>
  )HTML");
  RunAsyncMatchingTasks();

  // Render two frames to handle the async step added by the beforematch event.
  Compositor().BeginFrame();

  Element* iframe = GetDocument().getElementById(AtomicString("iframe"));
  auto* child_frame =
      To<LocalFrame>(To<HTMLFrameOwnerElement>(iframe)->ContentFrame());
  auto* main_frame = GetDocument().GetFrame();

  ASSERT_EQ(1u, child_frame->GetDocument()->Markers().Markers().size());
  ASSERT_EQ("https://example.com/child.html#:~:text=iframe",
            child_frame->Loader().GetDocumentLoader()->GetHistoryItem()->Url());

  ASSERT_EQ(1u, GetDocument().Markers().Markers().size());
  ASSERT_EQ("https://example.com/test.html#:~:text=test",
            main_frame->Loader().GetDocumentLoader()->GetHistoryItem()->Url());

  // Remove shared hig
```
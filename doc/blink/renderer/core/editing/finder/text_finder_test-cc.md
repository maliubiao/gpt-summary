Response:
The user is asking for a summary of the functionality of the `text_finder_test.cc` file in the Chromium Blink engine. I need to go through the provided code and identify its purpose. The file name strongly suggests it's a test file for the `TextFinder` class. I should look for `TEST_F` macros, which indicate individual test cases. These test cases will reveal the functionalities being tested and, by extension, the functionalities of the `TextFinder` class itself.

Here's a breakdown of the identified test cases and their corresponding functionalities:

*   `FindTextSimple`: Basic text searching functionality, including forward and backward search, and wrapping around the document.
*   `FindTextAutosizing`: Tests how text finding interacts with text autosizing (a feature to adjust text size for better readability on mobile).
*   `FindTextNotFound`: Tests the scenario where the searched text is not found in the document.
*   `FindTextInShadowDOM`: Checks if the text finder can search within Shadow DOM, a feature for encapsulation in web components.
*   `ScopeTextMatchesSimple` (and similar `ScopeTextMatches*` tests): Focuses on the "scoping" functionality, which seems to involve finding all occurrences of a text and highlighting them. These tests also examine how the highlighting rectangles are calculated and updated when the document layout changes.
*   `FindTextJavaScriptUpdatesDOM`: Tests how the text finder behaves when the DOM is modified by JavaScript while a search is in progress.
*   `FindTextJavaScriptUpdatesDOMAfterNoMatches`: Similar to the above, but starts when no matches are initially found.
*   `ScopeWithTimeouts`: Tests if the scoping process respects timeouts, likely to avoid blocking the UI for too long in large documents.
*   `BeforeMatchEvent`: Tests the `beforematch` event, which is triggered when a matching element is about to become visible (especially relevant for `hidden="until-found"`).
*   `BeforeMatchEventRemoveElement`: Checks the behavior when an element triggering `beforematch` is removed within the event handler.
*   `BeforeMatchEventAsyncExpandHighlight`: Tests how the `beforematch` event interacts with the asynchronous highlighting of matches.
*   `BeforeMatchExpandedHiddenMatchableUkm`: Checks if User Key Metrics (UKM) are logged correctly for matches found within elements with `hidden="until-found"`.

Therefore, the main function of this file is to test the `TextFinder` class, verifying its ability to find text in various scenarios, including simple cases, with layout changes, within Shadow DOM, and in dynamic content. It also tests interaction with features like text autosizing and the `beforematch` event.
这是目录为blink/renderer/core/editing/finder/text_finder_test.cc的chromium blink引擎源代码文件，其主要功能是 **测试 `TextFinder` 类**。`TextFinder` 类负责在网页文档中查找指定的文本。

以下是该测试文件所覆盖的 `TextFinder` 类的主要功能归纳：

1. **基本的文本查找功能:**
    *   在文档中向前和向后搜索指定的文本。
    *   支持在搜索到文档末尾或开头时循环查找。
    *   能够找到文本的多个实例。
    *   能够处理大小写敏感和不敏感的查找（虽然在这个文件中没有明确体现，但 `TextFinder` 类通常会支持）。

2. **与文档结构相关的查找:**
    *   能够在包含 Shadow DOM 的文档中查找文本。这意味着可以穿透 Shadow DOM 的边界进行搜索。

3. **与页面布局相关的查找:**
    *   能够在页面缩放 (autosizing) 的情况下正确查找文本。
    *   能够获取匹配文本在页面上的矩形区域 (用于高亮显示等功能)。
    *   能够在文档布局发生变化后，重新计算匹配文本的矩形区域。

4. **异步查找和高亮:**
    *   支持异步地查找所有匹配的文本，并高亮显示它们。
    *   能够在查找过程中动态更新匹配的数量和位置。
    *   能够处理在查找过程中 DOM 被 JavaScript 修改的情况。
    *   支持在查找过程中设置超时，防止长时间阻塞。

5. **`beforematch` 事件测试:**
    *   测试了 `beforematch` 事件的触发，这个事件在找到带有 `hidden="until-found"` 属性的元素时触发。
    *   测试了在 `beforematch` 事件处理函数中移除元素的情况，确保不会导致崩溃。
    *   测试了 `beforematch` 事件触发时页面滚动行为。

**与 javascript, html, css 的功能关系举例说明:**

*   **JavaScript:**  测试文件中使用了 `EvalJs` 函数来执行 JavaScript 代码，用于设置页面内容、创建 Shadow DOM，以及测试 `beforematch` 事件的处理。例如，在 `BeforeMatchEvent` 测试中，JavaScript 代码创建了带有 `hidden="until-found"` 属性的元素，并为其添加了 `beforematch` 事件监听器。

    ```c++
    EvalJs(R"(
        const foo = document.createElement('div');
        foo.textContent = 'foo';
        foo.setAttribute('hidden', 'until-found');
        document.body.appendChild(foo);
        window.beforematchFiredOnFoo = false;
        foo.addEventListener('beforematch', () => {
          window.beforematchFiredOnFoo = true;
        });
    )");
    ```

*   **HTML:** 测试文件中通过设置 `innerHTML` 来创建 HTML 结构，用于测试文本查找在不同 HTML 结构下的表现，例如包含 `<b>`, `<i>`, `<u>` 等标签的情况。在 `FindTextInShadowDOM` 测试中，就使用了 HTML 的 `<slot>` 元素和 Shadow DOM 的相关 API。

    ```c++
    GetDocument().body()->setInnerHTML("<b>FOO</b><i slot='bar'>foo</i>");
    ShadowRoot& shadow_root =
        GetDocument().body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
    shadow_root.setInnerHTML("<slot name='bar'></slot><u>Foo</u><slot></slot>");
    ```

*   **CSS:**  虽然在这个文件中没有直接操作 CSS 样式，但 `TextFinder` 的功能与 CSS 密切相关，因为它需要考虑元素的渲染和布局才能正确找到文本的位置。例如，在 `ScopeTextMatchesSimple` 测试中，通过修改元素的 `style` 属性来模拟页面布局的变化，并测试 `TextFinder` 是否能正确更新匹配矩形的位置。

    ```c++
    GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                       AtomicString("margin: 2000px"));
    ```

**逻辑推理的假设输入与输出举例:**

*   **假设输入:**  HTML 内容为 "Hello World Hello"，搜索文本为 "Hello"，查找方向为向前。
*   **预期输出:**  第一次 `Find` 调用应该选中第一个 "Hello"，第二次 `Find` 调用应该选中第二个 "Hello"，第三次 `Find` 调用（如果开启了循环查找）应该再次选中第一个 "Hello"。

*   **假设输入:**  HTML 内容为 "<a>link text</a>"，搜索文本为 "link text"。
*   **预期输出:** `TextFinder` 能够找到链接文本并返回包含该文本的 Range 对象。

**用户或编程常见的使用错误举例说明:**

*   **用户错误:**  用户可能在输入搜索文本时拼写错误，导致 `TextFinder` 找不到匹配项。例如，用户想搜索 "example"，却输入了 "exmaple"。
*   **编程错误:**  开发者可能在配置 `FindOptions` 时出现错误，例如错误地设置了 `forward` 标志，导致搜索方向不符合预期。或者，开发者可能在 DOM 结构被修改后没有及时更新 `TextFinder` 的状态，导致查找结果不准确。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **用户按下快捷键 (通常是 Ctrl+F 或 Cmd+F) 打开浏览器的“在页面中查找”功能。**
3. **用户在查找框中输入要搜索的文本。**
4. **用户点击“查找下一个”或“查找上一个”按钮，或者按下 Enter 键。**

在这些操作背后，浏览器会调用 Blink 引擎中的相关代码，最终会涉及到 `TextFinder` 类的使用。如果开发者想要调试“在页面中查找”功能，他们可能会在 `text_finder_test.cc` 文件中编写新的测试用例，或者运行现有的测试用例来验证 `TextFinder` 类的行为是否符合预期。如果发现了 bug，开发者可能会通过修改测试用例来重现 bug，并在修复 bug 后确保测试用例能够通过，从而避免 bug 的再次出现。

**这是第1部分，共2部分，请归纳一下它的功能:**

这部分代码主要定义了 `TextFinderTest` 和 `TextFinderSimTest` 两个测试类，并包含了一系列针对 `TextFinder` 类的单元测试。这些测试用例涵盖了 `TextFinder` 类的基本文本查找、在复杂文档结构中查找、与页面布局交互、异步查找和高亮显示以及 `beforematch` 事件处理等核心功能。总而言之，**这部分代码的功能是验证 `TextFinder` 类的核心文本查找逻辑的正确性和健壮性。**

### 提示词
```
这是目录为blink/renderer/core/editing/finder/text_finder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/finder/text_finder.h"

#include "components/ukm/test_ukm_recorder.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/find_in_page.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node_list.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_in_page_coordinates.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class TextFinderTest : public testing::Test {
 protected:
  TextFinderTest() {
    web_view_helper_.Initialize();
    WebLocalFrameImpl& frame_impl = *web_view_helper_.LocalMainFrame();
    frame_impl.ViewImpl()->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
    frame_impl.ViewImpl()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
    document_ = static_cast<Document*>(frame_impl.GetDocument());
    text_finder_ = &frame_impl.EnsureTextFinder();
  }

  Document& GetDocument() const;
  TextFinder& GetTextFinder() const;

  v8::Local<v8::Value> EvalJs(const std::string& script);

  static gfx::RectF FindInPageRect(Node* start_container,
                                   int start_offset,
                                   Node* end_container,
                                   int end_offset);

 private:
  test::TaskEnvironment task_environment_;

  frame_test_helpers::WebViewHelper web_view_helper_;
  Persistent<Document> document_;
  Persistent<TextFinder> text_finder_;
};

class TextFinderSimTest : public SimTest {
 protected:
  TextFinder& GetTextFinder() {
    return WebLocalFrameImpl::FromFrame(GetDocument().GetFrame())
        ->EnsureTextFinder();
  }
};

v8::Local<v8::Value> TextFinderTest::EvalJs(const std::string& script) {
  return ClassicScript::CreateUnspecifiedScript(script.c_str())
      ->RunScriptAndReturnValue(GetDocument().domWindow())
      .GetSuccessValueOrEmpty();
}

Document& TextFinderTest::GetDocument() const {
  return *document_;
}

TextFinder& TextFinderTest::GetTextFinder() const {
  return *text_finder_;
}

gfx::RectF TextFinderTest::FindInPageRect(Node* start_container,
                                          int start_offset,
                                          Node* end_container,
                                          int end_offset) {
  const Position start_position(start_container, start_offset);
  const Position end_position(end_container, end_offset);
  const EphemeralRange range(start_position, end_position);
  return FindInPageRectFromRange(range);
}

TEST_F(TextFinderTest, FindTextSimple) {
  GetDocument().body()->setInnerHTML("XXXXFindMeYYYYfindmeZZZZ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Node* text_node = GetDocument().body()->firstChild();

  int identifier = 0;
  String search_text("FindMe");
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  bool wrap_within_frame = true;

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  Range* active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_node, active_match->startContainer());
  EXPECT_EQ(4u, active_match->startOffset());
  EXPECT_EQ(text_node, active_match->endContainer());
  EXPECT_EQ(10u, active_match->endOffset());

  find_options->new_session = false;
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_node, active_match->startContainer());
  EXPECT_EQ(14u, active_match->startOffset());
  EXPECT_EQ(text_node, active_match->endContainer());
  EXPECT_EQ(20u, active_match->endOffset());

  // Should wrap to the first match.
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_node, active_match->startContainer());
  EXPECT_EQ(4u, active_match->startOffset());
  EXPECT_EQ(text_node, active_match->endContainer());
  EXPECT_EQ(10u, active_match->endOffset());

  // Search in the reverse order.
  identifier = 1;
  find_options = mojom::blink::FindOptions::New();
  find_options->forward = false;

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_node, active_match->startContainer());
  EXPECT_EQ(14u, active_match->startOffset());
  EXPECT_EQ(text_node, active_match->endContainer());
  EXPECT_EQ(20u, active_match->endOffset());

  find_options->new_session = false;
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_node, active_match->startContainer());
  EXPECT_EQ(4u, active_match->startOffset());
  EXPECT_EQ(text_node, active_match->endContainer());
  EXPECT_EQ(10u, active_match->endOffset());

  // Wrap to the first match (last occurence in the document).
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_node, active_match->startContainer());
  EXPECT_EQ(14u, active_match->startOffset());
  EXPECT_EQ(text_node, active_match->endContainer());
  EXPECT_EQ(20u, active_match->endOffset());
}

TEST_F(TextFinderTest, FindTextAutosizing) {
  GetDocument().body()->setInnerHTML("XXXXFindMeYYYYfindmeZZZZ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  WebString search_text(String("FindMe"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;
  bool wrap_within_frame = true;

  // Set viewport scale to 20 in order to simulate zoom-in
  GetDocument().GetPage()->SetDefaultPageScaleLimits(1, 20);
  GetDocument().GetPage()->SetPageScaleFactor(20);
  VisualViewport& visual_viewport =
      GetDocument().GetPage()->GetVisualViewport();

  // Enforce autosizing
  GetDocument().GetSettings()->SetTextAutosizingEnabled(true);
  GetDocument().GetSettings()->SetTextAutosizingWindowSizeOverride(
      gfx::Size(20, 20));
  GetDocument().GetTextAutosizer()->UpdatePageInfo();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // In case of autosizing, scale _should_ change
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  ASSERT_TRUE(GetTextFinder().ActiveMatch());
  ASSERT_EQ(1, visual_viewport.Scale());  // in this case to 1

  // Disable autosizing and reset scale to 20
  visual_viewport.SetScale(20);
  GetDocument().GetSettings()->SetTextAutosizingEnabled(false);
  GetDocument().GetTextAutosizer()->UpdatePageInfo();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  ASSERT_TRUE(GetTextFinder().ActiveMatch());
  ASSERT_EQ(20, visual_viewport.Scale());
}

TEST_F(TextFinderTest, FindTextNotFound) {
  GetDocument().body()->setInnerHTML("XXXXFindMeYYYYfindmeZZZZ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  String search_text("Boo");
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  bool wrap_within_frame = true;

  EXPECT_FALSE(GetTextFinder().Find(identifier, search_text, *find_options,
                                    wrap_within_frame));
  EXPECT_FALSE(GetTextFinder().ActiveMatch());
}

TEST_F(TextFinderTest, FindTextInShadowDOM) {
  GetDocument().body()->setInnerHTML("<b>FOO</b><i slot='bar'>foo</i>");
  ShadowRoot& shadow_root =
      GetDocument().body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<slot name='bar'></slot><u>Foo</u><slot></slot>");
  Node* text_in_b_element = GetDocument().body()->firstChild()->firstChild();
  Node* text_in_i_element = GetDocument().body()->lastChild()->firstChild();
  Node* text_in_u_element = shadow_root.childNodes()->item(1)->firstChild();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  String search_text("foo");
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  bool wrap_within_frame = true;

  // TextIterator currently returns the matches in the flat treeorder, so
  // in this case the matches will be returned in the order of
  // <i> -> <u> -> <b>.
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  Range* active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_i_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_i_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  find_options->new_session = false;
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_u_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_u_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_b_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_b_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  // Should wrap to the first match.
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_i_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_i_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  // Fresh search in the reverse order.
  identifier = 1;
  find_options = mojom::blink::FindOptions::New();
  find_options->forward = false;

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_b_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_b_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  find_options->new_session = false;
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_u_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_u_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_i_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_i_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());

  // And wrap.
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame));
  active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_EQ(text_in_b_element, active_match->startContainer());
  EXPECT_EQ(0u, active_match->startOffset());
  EXPECT_EQ(text_in_b_element, active_match->endContainer());
  EXPECT_EQ(3u, active_match->endOffset());
}

#if BUILDFLAG(IS_ANDROID)
TEST_F(TextFinderTest, ScopeTextMatchesSimple) {
  GetDocument().body()->setInnerHTML("XXXXFindMeYYYYfindmeZZZZ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Node* text_node = GetDocument().body()->firstChild();

  int identifier = 0;
  WebString search_text(String("FindMe"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  EXPECT_EQ(2, GetTextFinder().TotalMatchCount());
  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(2u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_node, 4, text_node, 10), match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_node, 14, text_node, 20), match_rects[1]);

  // Modify the document size and ensure the cached match rects are recomputed
  // to reflect the updated layout.
  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("margin: 2000px"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(2u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_node, 4, text_node, 10), match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_node, 14, text_node, 20), match_rects[1]);
}

TEST_F(TextFinderTest, ScopeTextMatchesRepeated) {
  GetDocument().body()->setInnerHTML("XXXXFindMeYYYYfindmeZZZZ");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Node* text_node = GetDocument().body()->firstChild();

  int identifier = 0;
  WebString search_text1(String("XFindMe"));
  WebString search_text2(String("FindMe"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text1,
                                            *find_options);
  GetTextFinder().StartScopingStringMatches(identifier, search_text2,
                                            *find_options);

  // Only searchText2 should be highlighted.
  EXPECT_EQ(2, GetTextFinder().TotalMatchCount());
  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(2u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_node, 4, text_node, 10), match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_node, 14, text_node, 20), match_rects[1]);
}

TEST_F(TextFinderTest, ScopeTextMatchesWithShadowDOM) {
  GetDocument().body()->setInnerHTML("<b>FOO</b><i slot='bar'>foo</i>");
  ShadowRoot& shadow_root =
      GetDocument().body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<slot name='bar'></slot><u>Foo</u><slot></slot>");
  Node* text_in_b_element = GetDocument().body()->firstChild()->firstChild();
  Node* text_in_i_element = GetDocument().body()->lastChild()->firstChild();
  Node* text_in_u_element = shadow_root.childNodes()->item(1)->firstChild();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  WebString search_text(String("fOO"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  // TextIterator currently returns the matches in the flat tree order,
  // so in this case the matches will be returned in the order of
  // <i> -> <u> -> <b>.
  EXPECT_EQ(3, GetTextFinder().TotalMatchCount());
  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(3u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_in_i_element, 0, text_in_i_element, 3),
            match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_in_u_element, 0, text_in_u_element, 3),
            match_rects[1]);
  EXPECT_EQ(FindInPageRect(text_in_b_element, 0, text_in_b_element, 3),
            match_rects[2]);
}

TEST_F(TextFinderTest, ScopeRepeatPatternTextMatches) {
  GetDocument().body()->setInnerHTML("ab ab ab ab ab");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Node* text_node = GetDocument().body()->firstChild();

  int identifier = 0;
  WebString search_text(String("ab ab"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  EXPECT_EQ(2, GetTextFinder().TotalMatchCount());
  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(2u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_node, 0, text_node, 5), match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_node, 6, text_node, 11), match_rects[1]);
}

TEST_F(TextFinderTest, OverlappingMatches) {
  GetDocument().body()->setInnerHTML("aababaa");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Node* text_node = GetDocument().body()->firstChild();

  int identifier = 0;
  WebString search_text(String("aba"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  // We shouldn't find overlapped matches.
  EXPECT_EQ(1, GetTextFinder().TotalMatchCount());
  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(1u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_node, 1, text_node, 4), match_rects[0]);
}

TEST_F(TextFinderTest, SequentialMatches) {
  GetDocument().body()->setInnerHTML("ababab");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  Node* text_node = GetDocument().body()->firstChild();

  int identifier = 0;
  WebString search_text(String("ab"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  EXPECT_EQ(3, GetTextFinder().TotalMatchCount());
  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(3u, match_rects.size());
  EXPECT_EQ(FindInPageRect(text_node, 0, text_node, 2), match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_node, 2, text_node, 4), match_rects[1]);
  EXPECT_EQ(FindInPageRect(text_node, 4, text_node, 6), match_rects[2]);
}

TEST_F(TextFinderTest, FindTextJavaScriptUpdatesDOM) {
  GetDocument().body()->setInnerHTML("<b>XXXXFindMeYYYY</b><i></i>");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  String search_text("FindMe");
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;
  bool wrap_within_frame = true;
  bool active_now;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  find_options->new_session = false;
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame, &active_now));
  EXPECT_TRUE(active_now);
  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame, &active_now));
  EXPECT_TRUE(active_now);

  // Add new text to DOM and try FindNext.
  auto* i_element = To<Element>(GetDocument().body()->lastChild());
  ASSERT_TRUE(i_element);
  i_element->setInnerHTML("ZZFindMe");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame, &active_now));
  Range* active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_FALSE(active_now);
  EXPECT_EQ(2u, active_match->startOffset());
  EXPECT_EQ(8u, active_match->endOffset());

  // Restart full search and check that added text is found.
  find_options->new_session = true;
  GetTextFinder().ResetMatchCount();
  GetTextFinder().CancelPendingScopingEffort();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  EXPECT_EQ(2, GetTextFinder().TotalMatchCount());

  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(2u, match_rects.size());
  Node* text_in_b_element = GetDocument().body()->firstChild()->firstChild();
  Node* text_in_i_element = GetDocument().body()->lastChild()->firstChild();
  EXPECT_EQ(FindInPageRect(text_in_b_element, 4, text_in_b_element, 10),
            match_rects[0]);
  EXPECT_EQ(FindInPageRect(text_in_i_element, 2, text_in_i_element, 8),
            match_rects[1]);
}

TEST_F(TextFinderTest, FindTextJavaScriptUpdatesDOMAfterNoMatches) {
  GetDocument().body()->setInnerHTML("<b>XXXXYYYY</b><i></i>");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  WebString search_text(String("FindMe"));
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;
  bool wrap_within_frame = true;
  bool active_now = false;

  GetTextFinder().ResetMatchCount();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  find_options->new_session = false;
  ASSERT_FALSE(GetTextFinder().Find(identifier, search_text, *find_options,
                                    wrap_within_frame, &active_now));
  EXPECT_FALSE(active_now);

  // Add new text to DOM and try FindNext.
  auto* i_element = To<Element>(GetDocument().body()->lastChild());
  ASSERT_TRUE(i_element);
  i_element->setInnerHTML("ZZFindMe");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  ASSERT_TRUE(GetTextFinder().Find(identifier, search_text, *find_options,
                                   wrap_within_frame, &active_now));
  Range* active_match = GetTextFinder().ActiveMatch();
  ASSERT_TRUE(active_match);
  EXPECT_FALSE(active_now);
  EXPECT_EQ(2u, active_match->startOffset());
  EXPECT_EQ(8u, active_match->endOffset());

  // Restart full search and check that added text is found.
  find_options->new_session = true;
  GetTextFinder().ResetMatchCount();
  GetTextFinder().CancelPendingScopingEffort();
  GetTextFinder().StartScopingStringMatches(identifier, search_text,
                                            *find_options);

  EXPECT_EQ(1, GetTextFinder().TotalMatchCount());

  WebVector<gfx::RectF> match_rects = GetTextFinder().FindMatchRects();
  ASSERT_EQ(1u, match_rects.size());
  Node* text_in_i_element = GetDocument().body()->lastChild()->firstChild();
  EXPECT_EQ(FindInPageRect(text_in_i_element, 2, text_in_i_element, 8),
            match_rects[0]);
}
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(TextFinderTest, ScopeWithTimeouts) {
  // Make a long string.
  String search_pattern("abc");
  StringBuilder text;
  // Make 4 substrings "abc" in text.
  for (int i = 0; i < 100; ++i) {
    if (i == 1 || i == 10 || i == 50 || i == 90) {
      text.Append(search_pattern);
    } else {
      text.Append('a');
    }
  }

  GetDocument().body()->setInnerHTML(text.ToString());
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  int identifier = 0;
  auto find_options =
      mojom::blink::FindOptions::New();  // Default + add testing flag.
  find_options->run_synchronously_for_testing = true;

  GetTextFinder().ResetMatchCount();

  // There will be only one iteration before timeout, because increment
  // of the TimeProxyPlatform timer is greater than timeout threshold.
  GetTextFinder().StartScopingStringMatches(identifier, search_pattern,
                                            *find_options);

  EXPECT_EQ(4, GetTextFinder().TotalMatchCount());
}

TEST_F(TextFinderTest, BeforeMatchEvent) {
  V8TestingScope v8_testing_scope;

  EvalJs(R"(
      const spacer = document.createElement('div');
      spacer.style.height = '2000px';
      document.body.appendChild(spacer);

      const foo = document.createElement('div');
      foo.textContent = 'foo';
      foo.setAttribute('hidden', 'until-found');
      document.body.appendChild(foo);
      window.beforematchFiredOnFoo = false;
      foo.addEventListener('beforematch', () => {
        window.beforematchFiredOnFoo = true;
      });

      const bar = document.createElement('div');
      bar.textContent = 'bar';
      bar.setAttribute('hidden', 'until-found');
      document.body.appendChild(bar);
      window.beforematchFiredOnBar = false;
      bar.addEventListener('beforematch', () => {
        window.YOffsetOnBeforematch = window.pageYOffset;
        window.beforematchFiredOnBar = true;
      });
      )");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  auto find_options = mojom::blink::FindOptions::New();
  find_options->run_synchronously_for_testing = true;
  GetTextFinder().Find(/*identifier=*/0, "bar", *find_options,
                       /*wrap_within_frame=*/false);

  v8::Local<v8::Value> beforematch_fired_on_foo =
      EvalJs("window.beforematchFiredOnFoo");
  ASSERT_TRUE(beforematch_fired_on_foo->IsBoolean());
  EXPECT_FALSE(
      beforematch_fired_on_foo->ToBoolean(v8_testing_scope.GetIsolate())
          ->Value());

  v8::Local<v8::Value> beforematch_fired_on_bar =
      EvalJs("window.beforematchFiredOnBar");
  ASSERT_TRUE(beforematch_fired_on_bar->IsBoolean());
  EXPECT_TRUE(beforematch_fired_on_bar->ToBoolean(v8_testing_scope.GetIsolate())
                  ->Value());

  // Scrolling should occur after the beforematch event.
  v8::Local<v8::Context> context =
      v8_testing_scope.GetScriptState()->GetContext();
  v8::Local<v8::Value> beforematch_y_offset =
      EvalJs("window.YOffsetOnBeforematch");
  ASSERT_TRUE(beforematch_y_offset->IsNumber());
  EXPECT_TRUE(
      beforematch_y_offset->ToNumber(context).ToLocalChecked()->Value() == 0);
}

TEST_F(TextFinderTest, BeforeMatchEventRemoveElement) {
  V8TestingScope v8_testing_scope;

  EvalJs(R"(
      const spacer = document.createElement('div');
      spacer.style.height = '2000px';
      document.body.appendChild(spacer);

      const foo = document.createElement('div');
      foo.setAttribute('hidden', 'until-found');
      foo.textContent = 'foo';
      document.body.appendChild(foo);
      window.beforematchFiredOnFoo = false;
      foo.addEventListener('beforematch', () => {
        foo.remove();
        window.beforematchFiredOnFoo = true;
      });
      )");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  auto find_options = mojom::blink::FindOptions::New();
  find_options->run_synchronously_for_testing = true;
  GetTextFinder().Find(/*identifier=*/0, "foo", *find_options,
                       /*wrap_within_frame=*/false);

  v8::Local<v8::Value> beforematch_fired_on_foo =
      EvalJs("window.beforematchFiredOnFoo");
  ASSERT_TRUE(beforematch_fired_on_foo->IsBoolean());
  EXPECT_TRUE(beforematch_fired_on_foo->ToBoolean(v8_testing_scope.GetIsolate())
                  ->Value());

  // TODO(jarhar): Update this test to include checks for scrolling behavior
  // once we decide what the behavior should be. Right now it is just here to
  // make sure we avoid a renderer crash due to the detached element.
}

// TODO(jarhar): Write more tests here once we decide on a behavior here:
// https://github.com/WICG/display-locking/issues/150

TEST_F(TextFinderSimTest, BeforeMatchEventAsyncExpandHighlight) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id=hiddenid hidden=until-found>hidden</div>
  )HTML");
  Compositor().BeginFrame();

  GetTextFinder().Find(/*identifier=*/0, "hidden",
                       *mojom::blink::FindOptions::New(),
                       /*wrap_within_frame=*/false);

  Compositor().BeginFrame();

  HeapVector<Member<DocumentMarker>> markers =
      GetDocument().Markers().Markers();
  ASSERT_EQ(markers.size(), 1u);
  DocumentMarker* marker = markers[0];
  EXPECT_TRUE(marker->GetType() == DocumentMarker::kTextMatch);
}

TEST_F(TextFinderSimTest, BeforeMatchExpandedHiddenMatchableUkm) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id=hiddenid hidden=until-found>hidden</div>
  )HTML");
  ukm::TestAutoSetUkmRecorder recorder;
  GetDocument().View()->ResetUkmAggregatorForTesting();

  Compositor().BeginFrame();
  EXPECT_EQ(recorder.entries_count(), 0u);

  GetTextFinder().Find(/*identifier=*/0, "hidden",
                       *mojom::blink::FindOptions::New(),
                       /*wrap_within_frame=*/false);

  Compositor().BeginFrame();

  auto entries = recorder.GetEntriesByName("Blink.FindInPage");
  // There are two entries because
  // DisplayLockUtilities::ActivateFindInPageMatchRangeIfNeeded followed by
  // DisplayLockContext::CommitForActivationWithSignal sets a
  // "HasFindInPageContentVisibilityActiveMatch" UKM.
  ASSERT_EQ(entries.size(), 2u);

  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[0], "BeforematchExpandedHiddenMatchable"));
  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[1], "BeforematchExpandedHiddenMatc
```
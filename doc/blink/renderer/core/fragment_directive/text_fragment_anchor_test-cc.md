Response:
The user wants a summary of the functionality of the provided C++ code. I need to analyze the code and identify its purpose, especially focusing on its interaction with web technologies like JavaScript, HTML, and CSS. I also need to look for logical reasoning within the tests and common user errors that the code might address.

Based on the file name `text_fragment_anchor_test.cc` and the included headers like `text_fragment_finder.h` and `fragment_anchor.h`, the code seems to be testing the functionality of Text Fragment Anchors in Chromium's Blink rendering engine. Text Fragment Anchors allow navigating to specific text content on a webpage using a URL fragment.

Here's a breakdown of the code's components:

* **Includes:** Various headers related to testing, core Blink functionalities like DOM manipulation, CSS styling, frame handling, and text fragment implementation.
* **`TextFragmentAnchorTestController`:** A test fixture that sets up the environment for testing Text Fragment Anchors. It includes methods for loading URLs, simulating user interactions (clicks, taps), and accessing DOM elements.
* **`TextFragmentAnchorTest`:**  Inherits from `TextFragmentAnchorTestController` and sets up the time source for the tests.
* **Test Cases (using `TEST_F`):**  Each test case focuses on a specific aspect of the Text Fragment Anchor functionality.

Now, let's address the specific requirements of the prompt:

1. **Functionality:** The primary function is to test the implementation of Text Fragment Anchors. This includes:
    * Matching text within a page based on the URL fragment.
    * Scrolling the matched text into view.
    * Highlighting the matched text.
    * Handling cases with multiple matches, no matches, and different types of text fragment directives (simple text, text ranges, contextual text).

2. **Relationship with JavaScript, HTML, and CSS:**
    * **HTML:** The tests load HTML content to simulate real web pages. The tests manipulate and inspect HTML elements to verify the behavior of Text Fragment Anchors.
    * **CSS:** The tests use CSS to control the layout and visibility of elements, ensuring that scrolling works correctly even with complex layouts. The highlighting of the matched text is likely implemented using CSS classes or styles.
    * **JavaScript:** While this particular test file is in C++, the Text Fragment Anchor feature is triggered by URL changes, which can be initiated by JavaScript code. The browser also exposes APIs in JavaScript to interact with the URL and potentially observe or customize the behavior of Text Fragment Anchors.

3. **Logical Reasoning (Hypothetical Input/Output):** The test cases themselves represent logical reasoning. For example:
    * **Input:** A URL with a text fragment like `#:~:text=test` and an HTML document containing the word "test".
    * **Output:** The browser should scroll to and highlight the first occurrence of "test" in the document.

4. **User/Programming Errors:**
    * **Incorrect URL Fragment:** Users might type the text fragment incorrectly, leading to no matches. The tests cover scenarios where the specified text doesn't exist.
    * **Unexpected HTML Structure:**  The implementation needs to be robust enough to handle various HTML structures. Tests cover nested elements and different element types.

5. **Summary of Functionality (Part 1):**  The provided code is the first part of a test suite for the Text Fragment Anchor feature in the Chromium browser. It focuses on basic functionality like matching and scrolling to simple text fragments and text ranges within a single page, including cases with no matches and multiple matches. It also starts to explore scenarios involving text ranges that span across multiple elements and introduce the concept of contextual text matching.
这个C++源代码文件 `text_fragment_anchor_test.cc` 是 Chromium Blink 引擎中用于测试 **文本片段锚点 (Text Fragment Anchor)** 功能的单元测试。

**它的主要功能是：**

1. **测试文本片段的匹配和高亮:** 验证浏览器是否能够根据 URL 中指定的文本片段 (例如 `#:~:text=要查找的文本`) 在页面中正确地找到并高亮显示对应的文本。
2. **测试滚动到匹配的文本:** 验证当找到匹配的文本片段时，浏览器是否能够自动滚动页面，使匹配的文本出现在可视区域内。
3. **测试不同类型的文本片段指令:**  测试各种复杂的文本片段指令，例如：
    * 简单的文本匹配 (`#:~:text=test`)
    * 匹配文本范围 (`#:~:text=start,end`)
    * 带上下文的文本匹配 (`#:~:text=prefix-,match,-suffix`)
    * 多个文本片段指令 (`#:~:text=text1&text=text2`)
4. **测试匹配失败的情况:** 验证当 URL 中指定的文本片段在页面中不存在时，浏览器是否能够正确处理，例如不进行滚动，不错误地高亮。
5. **验证与浏览器的其他组件的交互:** 例如，它会涉及到 `DocumentMarkerController` 来标记高亮的文本， `FragmentAnchor` 来管理滚动行为。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:** 测试代码会加载预定义的 HTML 内容 (通过 `R"HTML(...)HTML"`)，模拟真实的网页结构，用于测试文本片段锚点功能在不同 HTML 结构下的表现。例如，测试文本片段是否能在嵌套的 `<div>` 和 `<p>` 元素中正确匹配。
    ```html
    <p id="text">This is a test page</p>
    ```
* **JavaScript:**  虽然这个测试文件是用 C++ 写的，但文本片段锚点功能本身是通过修改 URL 来触发的，这在实际应用中常常发生在 JavaScript 代码中。例如，一个 JavaScript 代码可能会动态地修改 `window.location.hash` 来添加或修改文本片段。这个 C++ 测试验证了当 URL 包含文本片段时，渲染引擎的行为是否符合预期。
* **CSS:**  测试代码会使用 CSS 来控制页面的布局，例如设置 `body` 的高度，以模拟需要滚动的长页面。此外，文本片段的高亮显示通常是通过应用特定的 CSS 样式来实现的，虽然在这个测试代码中没有直接体现 CSS 的编写，但它验证了高亮功能是否正确生效，这意味着底层的 CSS 应用是成功的。

**逻辑推理的假设输入与输出举例：**

**假设输入:**

* **URL:** `https://example.com/test.html#:~:text=test`
* **HTML:**
  ```html
  <!DOCTYPE html>
  <p id="text">This is a test page</p>
  ```

**输出:**

* 页面会滚动到包含 "test" 文本的 `<p>` 元素附近。
* "test" 这四个字符会被高亮显示。
* `GetDocument().CssTarget()` 会返回对应的 DOM 元素 (`<p id="text">`)。
* `GetDocument().Markers().Markers().size()` 会返回 1，表示有一个文本片段标记。

**用户或者编程常见的使用错误举例：**

* **URL 中文本片段拼写错误:** 用户可能在 URL 中错误地输入了要查找的文本，例如 `#:~:text=tesst` 而不是 `#:~:text=test`。在这种情况下，测试会验证没有匹配项，不会发生滚动或高亮。
* **假设输入:** URL 为 `https://example.com/test.html#:~:text=tesst`，而 HTML 中只有 "test"。
* **预期行为:**  `GetDocument().CssTarget()` 应该返回 `nullptr`，`GetDocument().Markers().Markers().size()` 应该返回 0，页面不应该滚动。

**功能归纳 (第 1 部分):**

这个代码文件的第一部分主要集中在测试 **基本的文本片段锚点功能**。它验证了对于简单的文本匹配和文本范围匹配，浏览器能否正确地找到目标文本并滚动到该位置进行高亮显示。  它还包含了对匹配失败情况的测试，确保在找不到指定文本时不会发生错误行为。 这一部分主要关注单个文本片段指令的处理，以及在简单 HTML 结构下的匹配。 此外，它开始涉及跨元素匹配的文本范围场景。

Prompt: 
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/containers/span.h"
#include "base/run_loop.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "components/shared_highlighting/core/common/shared_highlighting_features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_menu_source_type.h"
#include "third_party/blink/public/public_buildflags.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mouse_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_impl.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_finder.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_test_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/location.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

#if BUILDFLAG(ENABLE_UNHANDLED_TAP)
#include "third_party/blink/public/mojom/unhandled_tap_notifier/unhandled_tap_notifier.mojom-blink.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)

namespace blink {

namespace {

using test::RunPendingTasks;

class TextFragmentAnchorTestController : public TextFragmentAnchorTestBase {
 public:
  explicit TextFragmentAnchorTestController(
      base::test::TaskEnvironment::TimeSource time_source)
      : TextFragmentAnchorTestBase(time_source) {}
  TextFragmentAnchorTestController() = default;

  void BeginEmptyFrame() {
    // If a test case doesn't find a match and therefore doesn't schedule the
    // beforematch event, we should still render a second frame as if we did
    // schedule the event to retain test coverage.
    // When the beforematch event is not scheduled, a DCHECK will fail on
    // BeginFrame() because no event was scheduled, so we schedule an empty task
    // here.
    GetDocument().EnqueueAnimationFrameTask(WTF::BindOnce([]() {}));
    Compositor().BeginFrame();
  }

  ScrollableArea* LayoutViewport() {
    return GetDocument().View()->LayoutViewport();
  }

  gfx::Rect ViewportRect() {
    return gfx::Rect(LayoutViewport()->VisibleContentRect().size());
  }

  gfx::Rect BoundingRectInFrame(Node& node) {
    return node.GetLayoutObject()->AbsoluteBoundingBoxRect();
  }

  void SimulateClick(int x, int y) {
    WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(x, y),
                        gfx::PointF(x, y), WebPointerProperties::Button::kLeft,
                        0, WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    WebView().MainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
        WebCoalescedInputEvent(event, ui::LatencyInfo()));
  }

  void SimulateRightClick(int x, int y) {
    WebMouseEvent event(WebInputEvent::Type::kMouseDown, gfx::PointF(x, y),
                        gfx::PointF(x, y), WebPointerProperties::Button::kRight,
                        0, WebInputEvent::Modifiers::kLeftButtonDown,
                        base::TimeTicks::Now());
    event.SetFrameScale(1);
    WebView().MainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
        WebCoalescedInputEvent(event, ui::LatencyInfo()));
  }

  void SimulateTap(int x, int y) {
    InjectEvent(WebInputEvent::Type::kTouchStart, x, y);
    InjectEvent(WebInputEvent::Type::kTouchEnd, x, y);
    InjectEvent(WebInputEvent::Type::kGestureTapDown, x, y);
    InjectEvent(WebInputEvent::Type::kGestureTapUnconfirmed, x, y);
    InjectEvent(WebInputEvent::Type::kGestureShowPress, x, y);
    InjectEvent(WebInputEvent::Type::kGestureTap, x, y);
  }

  void LoadAhem() {
    std::optional<Vector<char>> data =
        test::ReadFromFile(test::CoreTestDataPath("Ahem.ttf"));
    ASSERT_TRUE(data);
    auto* buffer =
        MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferViewOrString>(
            DOMArrayBuffer::Create(base::as_byte_span(*data)));
    FontFace* ahem = FontFace::Create(GetDocument().GetFrame()->DomWindow(),
                                      AtomicString("Ahem"), buffer,
                                      FontFaceDescriptors::Create());

    ScriptState* script_state =
        ToScriptStateForMainWorld(GetDocument().GetFrame());
    DummyExceptionStateForTesting exception_state;
    FontFaceSetDocument::From(GetDocument())
        ->addForBinding(script_state, ahem, exception_state);
  }

 private:
  void InjectEvent(WebInputEvent::Type type, int x, int y) {
    if (WebInputEvent::IsGestureEventType(type)) {
      WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                            base::TimeTicks::Now(),
                            WebGestureDevice::kTouchscreen);
      event.SetPositionInWidget(gfx::PointF(x, y));
      event.SetPositionInScreen(gfx::PointF(x, y));
      event.SetFrameScale(1);

      WebView().MainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
          WebCoalescedInputEvent(event, ui::LatencyInfo()));
    } else if (WebInputEvent::IsTouchEventType(type)) {
      WebTouchEvent event(type, WebInputEvent::kNoModifiers,
                          base::TimeTicks::Now());
      event.SetFrameScale(1);

      WebPointerProperties pointer(0, WebPointerProperties::PointerType::kTouch,
                                   WebPointerProperties::Button::kNoButton,
                                   gfx::PointF(x, y), gfx::PointF(x, y));
      event.touches[0] = pointer;
      if (type == WebInputEvent::Type::kTouchStart)
        event.touches[0].state = WebTouchPoint::State::kStatePressed;
      else if (type == WebInputEvent::Type::kTouchEnd)
        event.touches[0].state = WebTouchPoint::State::kStateReleased;

      WebView().MainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
          WebCoalescedInputEvent(event, ui::LatencyInfo()));
      WebView().MainFrameWidget()->DispatchBufferedTouchEvents();
    } else {
      NOTREACHED() << "Only needed to support Gesture/Touch until now. "
                      "Implement others if new modality is needed.";
    }
  }
};

class TextFragmentAnchorTest : public TextFragmentAnchorTestController {
 public:
  TextFragmentAnchorTest()
      : TextFragmentAnchorTestController(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
};

// Basic test case, ensure we scroll the matching text into view.
TEST_F(TextFragmentAnchorTest, BasicSmokeTest) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Make sure an anchor isn't created (and we don't crash) if text= is empty.
TEST_F(TextFragmentAnchorTest, EmptyText) {
  SimRequest request("https://example.com/test.html#:~:text=", "text/html");
  LoadURL("https://example.com/test.html#:~:text=");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id="text">This is a test page</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// Make sure a non-matching string doesn't cause scroll and the fragment is
// removed when completed.
TEST_F(TextFragmentAnchorTest, NonMatchingString) {
  SimRequest request("https://example.com/test.html#:~:text=unicorn",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=unicorn");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());

  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());

  // Force a layout
  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("height: 1300px"));
  Compositor().BeginFrame();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// Ensure multiple matches will scroll the first into view.
TEST_F(TextFragmentAnchorTest, MultipleMatches) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
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
    <p id="second">This is a test page</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& first = *GetDocument().getElementById(AtomicString("first"));

  EXPECT_EQ(first, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(first)))
      << "First <p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  // Ensure we only report one marker.
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Ensure matching works inside nested blocks.
TEST_F(TextFragmentAnchorTest, NestedBlocks) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #spacer {
        height: 1000px;
      }
    </style>
    <body>
      <div id="spacer">
        Some non-matching text
      </div>
      <div>
        <p id="match">This is a test page</p>
      </div>
    </body>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& match = *GetDocument().getElementById(AtomicString("match"));

  EXPECT_EQ(match, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(match)))
      << "<p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Ensure multiple texts are highlighted and the first is scrolled into
// view.
TEST_F(TextFragmentAnchorTest, MultipleTextFragments) {
  SimRequest request("https://example.com/test.html#:~:text=test&text=more",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test&text=more");
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
    <p id="second">This is some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& first = *GetDocument().getElementById(AtomicString("first"));

  EXPECT_EQ(first, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(first)))
      << "First <p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Ensure we scroll the second text into view if the first isn't found.
TEST_F(TextFragmentAnchorTest, FirstTextFragmentNotFound) {
  SimRequest request("https://example.com/test.html#:~:text=test&text=more",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test&text=more");
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
    <p id="first">This is a page</p>
    <p id="second">This is some more text</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& second = *GetDocument().getElementById(AtomicString("second"));

  EXPECT_EQ(second, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(second)))
      << "Second <p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Ensure we still scroll the first text into view if the second isn't
// found.
TEST_F(TextFragmentAnchorTest, OnlyFirstTextFragmentFound) {
  SimRequest request("https://example.com/test.html#:~:text=test&text=more",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test&text=more");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Make sure multiple non-matching strings doesn't cause scroll and the fragment
// is removed when completed.
TEST_F(TextFragmentAnchorTest, MultipleNonMatchingStrings) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=unicorn&text=cookie&text=cat",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=unicorn&text=cookie&text=cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());

  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());

  // Force a layout
  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("height: 1300px"));
  Compositor().BeginFrame();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// Test matching a text range within the same element
TEST_F(TextFragmentAnchorTest, SameElementTextRange) {
  SimRequest request("https://example.com/test.html#:~:text=This,page",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=This,page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("text")),
            *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on "This is a test page".
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("text"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(19u, markers.at(0)->EndOffset());
}

// Test matching a text range across two neighboring elements
TEST_F(TextFragmentAnchorTest, NeighboringElementTextRange) {
  SimRequest request("https://example.com/test.html#:~:text=test,paragraph",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test,paragraph");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text1">This is a test page</p>
    <p id="text2">with another paragraph of text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().body(), *GetDocument().CssTarget());
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  // Expect marker on "test page"
  auto* text1 = To<Text>(
      GetDocument().getElementById(AtomicString("text1"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text1, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(10u, markers.at(0)->StartOffset());
  EXPECT_EQ(19u, markers.at(0)->EndOffset());

  // Expect marker on "with another paragraph"
  auto* text2 = To<Text>(
      GetDocument().getElementById(AtomicString("text2"))->firstChild());
  markers = GetDocument().Markers().MarkersFor(
      *text2, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(22u, markers.at(0)->EndOffset());
}

// Test matching a text range from an element to a deeper nested element
TEST_F(TextFragmentAnchorTest, DifferentDepthElementTextRange) {
  SimRequest request("https://example.com/test.html#:~:text=test,paragraph",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test,paragraph");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text1">This is a test page</p>
    <div>
      <p id="text2">with another paragraph of text</p>
    </div>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().body(), *GetDocument().CssTarget());
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  // Expect marker on "test page"
  auto* text1 = To<Text>(
      GetDocument().getElementById(AtomicString("text1"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text1, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(10u, markers.at(0)->StartOffset());
  EXPECT_EQ(19u, markers.at(0)->EndOffset());

  // Expect marker on "with another paragraph"
  auto* text2 = To<Text>(
      GetDocument().getElementById(AtomicString("text2"))->firstChild());
  markers = GetDocument().Markers().MarkersFor(
      *text2, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(22u, markers.at(0)->EndOffset());
}

// Ensure that we don't match anything if endText is not found.
TEST_F(TextFragmentAnchorTest, TextRangeEndTextNotFound) {
  SimRequest request("https://example.com/test.html#:~:text=test,cat",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test,cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());
}

// Test matching multiple text ranges
TEST_F(TextFragmentAnchorTest, MultipleTextRanges) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test,with&text=paragraph,text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test,with&text=paragraph,text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <p id="text1">This is a test page</p>
    <div>
      <p id="text2">with another paragraph of text</p>
    </div>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().body(), *GetDocument().CssTarget());
  EXPECT_EQ(3u, GetDocument().Markers().Markers().size());

  // Expect marker on "test page"
  auto* text1 = To<Text>(
      GetDocument().getElementById(AtomicString("text1"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text1, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(10u, markers.at(0)->StartOffset());
  EXPECT_EQ(19u, markers.at(0)->EndOffset());

  // Expect markers on "with" and "paragraph of text"
  auto* text2 = To<Text>(
      GetDocument().getElementById(AtomicString("text2"))->firstChild());
  markers = GetDocument().Markers().MarkersFor(
      *text2, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(2u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(4u, markers.at(0)->EndOffset());
  EXPECT_EQ(13u, markers.at(1)->StartOffset());
  EXPECT_EQ(30u, markers.at(1)->EndOffset());
}

// Ensure we scroll to the beginning of a text range larger than the viewport.
TEST_F(TextFragmentAnchorTest, DistantElementTextRange) {
  SimRequest request("https://example.com/test.html#:~:text=test,paragraph",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test,paragraph");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 3000px;
      }
    </style>
    <p id="text">This is a test page</p>
    <p>with another paragraph of text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Test a text range with both context terms in the same element.
TEST_F(TextFragmentAnchorTest, TextRangeWithContext) {
  SimRequest request(
      "https://example.com/test.html#:~:text=This-,is,test,-page", "text/html");
  LoadURL("https://example.com/test.html#:~:text=This-,is,test,-page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("text")),
            *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on "is a test".
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("text"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(5u, markers.at(0)->StartOffset());
  EXPECT_EQ(14u, markers.at(0)->EndOffset());
}

// Ensure that we do not match a text range if the prefix is not found.
TEST_F(TextFragmentAnchorTest, PrefixNotFound) {
  SimRequest request(
      "https://example.com/test.html#:~:text=prefix-,is,test,-page",
      "text/html");
  LoadURL("https://example.com/test.html#:~:text=prefix-,is,test,-page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

// Ensure that we do not match a text range if the suffix is not found.
TEST_F(TextFragmentAnchorTest, SuffixNotFound) {
  SimRequest request(
      "https://example.com/test.html#:~:text=This-,is,test,-suffix",
      "text/html");
  LoadURL("https://example.com/test.html#:~:text=This-,is,test,-suffix");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
}

// Test a text range with context terms in different elements
TEST_F(TextFragmentAnchorTest, TextRangeWithCrossElementContext) {
  SimRequest request(
      "https://example.com/test.html#:~:text=Header%202-,A,text,-Footer%201",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=Header%202-,A,text,-Footer%201");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <h1>Header 1</h1>
    <p>A string of text</p>
    <p>Footer 1</p>
    <h1>Header 2</h1>
    <p id="expected">A string of text</p>
    <p>Footer 1</p>
    <h1>Header 2</h1>
    <p>A string of text</p>
    <p>Footer 2</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("expected")),
            *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on the expected "A string of text".
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("expected"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(16u, markers.at(0)->EndOffset());
}

// Test context terms separated by elements and whitespace
TEST_F(TextFragmentAnchorTest, CrossElementAndWhitespaceContext) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=List%202-,Cat,-Good%20cat",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=List%202-,Cat,-Good%20cat");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <h1> List 1 </h1>
    <div>
      <p>Cat</p>
      <p>&nbsp;Good cat</p>
    </div>
    <h1> List 2 </h1>
    <div>
      <p id="expected">Cat</p>
      <p>&nbsp;Good cat</p>
    </div>
    <h1> List 2 </h1>
    <div>
      <p>Cat</p>
      <p>&nbsp;Bad cat</p>
    </div>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("expected")),
            *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on the expected "cat".
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("expected"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(3u, markers.at(0)->EndOffset());
}

// Test context terms separated by empty sibling and parent elements
TEST_F(TextFragmentAnchorTest, CrossEmptySiblingAndParentElementContext) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=prefix-,match,-suffix",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=prefix-,match,-suffix");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div>
      <p>prefix</p>
    <div>
    <p><br>&nbsp;</p>
    <div id="expected">match</div>
    <p><br>&nbsp;</p>
    <div>
      <p>suffix</p>
    <div>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("expected")),
            *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on "match".
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("expected"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(5u, markers.at(0)->EndOffset());
}

// Ensure we scroll to text when its prefix and suffix are out of view.
TEST_F(TextFragmentAnchorTest, DistantElementContext) {
  SimRequest request(
      "https://example.com/test.html#:~:text=Prefix-,Cats,-Suffix",
      "text/html");
  LoadURL("https://example.com/test.html#:~:text=Prefix-,Cats,-Suffix");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 3000px;
      }
    </style>
    <p>Cats</p>
    <p>Prefix</p>
    <p id="text">Cats</p>
    <p>Suffix</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test specifying just one of the prefix and suffix
TEST_F(TextFragmentAnchorTest, OneContextTerm) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test-,page&text=page,-with%20real%20content",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test-,page&text=page,-with%20real%20content");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <p id="text1">This is a test page</p>
    <p id="text2">Not a page with real content</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("text1")),
            *GetDocument().CssTarget());

  // Expect marker on the first "page"
  auto* text1 = To<Text>(
      GetDocument().getElementById(AtomicString("text1"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text1, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(15u, markers.at(0)->StartOffset());
  EXPECT_EQ(19u, markers.at(0)->EndOffset());

  // Expect marker on the second "page"
  auto* text2 = To<Text>(
      GetDocument().getElementById(AtomicString("text2"))->firstCh
"""


```
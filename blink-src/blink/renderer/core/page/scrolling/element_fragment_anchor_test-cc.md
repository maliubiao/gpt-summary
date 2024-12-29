Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to understand what the `element_fragment_anchor_test.cc` file in the Chromium Blink engine does. This involves figuring out its purpose, how it interacts with web technologies, its testing logic, potential errors it helps catch, and how a developer might end up needing to debug it.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for recurring keywords and patterns. I see:
    * `TEST_F`: This strongly indicates it's a Google Test file.
    * `ElementFragmentAnchorTest`: This is the main test fixture class, suggesting the focus is on `ElementFragmentAnchor`.
    * `#include`: Many standard Blink headers are included, like `HTMLAnchorElement`, `HTMLFrameOwnerElement`, `CSSStyleDeclaration`, `LocalFrameView`, etc. This tells me it's testing something related to DOM elements, CSS, and frame management.
    * `SimTest`: This hints at a simulated environment for testing, not a full browser context.
    * `LoadURL`: This function is used to load HTML content, a core web operation.
    * `click()`, `addEventListener('focus', ...)`, `requestAnimationFrame(...)`: These are Javascript-related interactions being tested.
    * `background-color`, `width`, `height`, `transform`: These are CSS properties involved in the tests.
    * `#fragment`: This is a key indicator that the tests are dealing with URL fragments and scrolling to specific parts of a page.
    * `ScrollOffset`, `VisibleContentRect`: These are related to scrolling mechanics.
    * `GetDocument().getElementById(...)`:  Basic DOM manipulation.
    * `Compositor().BeginFrame()`:  Indicates involvement with the rendering pipeline.
    * `ThreadState::Current()->CollectAllGarbageForTesting()`: Points to memory management considerations in the tests.

3. **Identify Core Functionality:** Based on the keywords, the central theme seems to be testing the `ElementFragmentAnchor` class. This class likely handles the behavior of navigating to a specific element within a page using URL fragments (the `#something` part of a URL).

4. **Analyze Individual Tests:**  Go through each `TEST_F` function and try to understand its specific purpose:
    * **`FocusHandlerRunBeforeRaf`:** Tests the order of execution between focus event handlers and `requestAnimationFrame` callbacks when navigating to a fragment. This highlights a potential race condition or timing issue.
    * **`IframeFragmentNoLayoutUntilLoad`:** Checks that iframes are laid out *before* attempting to scroll to a fragment within them. This prevents issues where the iframe's layout isn't ready, and the fragment can't be located.
    * **`IframeFragmentDirtyLayoutAfterLoad`:** Similar to the previous test, but focuses on the scenario where the iframe has loaded, but its layout *becomes* dirty (needs recalculation) before the fragment scroll occurs.
    * **`AnchorRemovedBeforeBeginFrameCrash`:** Tests for crash resilience when the target element of a fragment navigation is removed from the DOM and garbage collected *before* a rendering frame is processed.
    * **`SVGDocumentDoesntCreateFragment`:** Verifies that SVG documents don't automatically try to scroll to a fragment if the URL doesn't explicitly have one. This prevents unintended scrolling behavior in SVGs.
    * **`HasURLEncodedCharacters`:** Tests the handling of URL fragments that contain URL-encoded characters. This ensures that special characters in fragment identifiers are correctly matched.

5. **Connect to Web Technologies:**  Relate the tests to HTML, CSS, and JavaScript concepts:
    * **HTML:**  The tests heavily use HTML elements like `<a>`, `<div>`, `<input>`, `<iframe>`, `<img>`, and SVG elements. Fragment identifiers are a core HTML feature.
    * **CSS:** CSS is used for styling elements (like background color, width, height) to influence layout and visual presentation, which is important for testing scrolling.
    * **JavaScript:** JavaScript event listeners (`focus`) and asynchronous operations (`requestAnimationFrame`) are used to manipulate the DOM and test timing aspects of fragment navigation.

6. **Infer Logic and Assumptions:**  For each test, consider the assumptions being made and the expected outcomes. For example, in `FocusHandlerRunBeforeRaf`, the assumption is that the rAF callback will change the background color, and the test verifies that this change is reflected *after* the focus event.

7. **Consider User/Developer Errors:** Think about common mistakes developers might make that these tests help prevent or diagnose. For example, relying on a specific order of execution without proper synchronization, or not accounting for layout invalidation.

8. **Trace User Actions:**  Imagine the steps a user might take in a browser to trigger the scenarios being tested. This helps connect the low-level code to real-world use cases. For instance, clicking a link with a fragment identifier.

9. **Debugging Hints:**  Based on the test scenarios, what kind of information would be helpful if something goes wrong?  Knowing the active element, the scroll position, the layout state of iframes, and the timing of events would be crucial.

10. **Structure the Answer:** Organize the findings logically, starting with a general overview and then going into the specifics of each test. Use clear language and provide illustrative examples. The request specifically asked for examples related to HTML, CSS, and JS, as well as assumptions, input/output, common errors, and debugging hints, so ensure these are covered.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about scrolling."
* **Correction:**  "No, it's specifically about *fragment* scrolling, and it touches on event handling, layout, and iframe interactions."
* **Initial thought:** "The tests are simple."
* **Correction:** "While the individual test *cases* might be relatively straightforward, the scenarios they cover involve complex interactions between different parts of the rendering engine."
* **Initial thought:** "Just list the functions."
* **Correction:** "Explain the *purpose* of each function and how it relates to the overall goal of testing fragment anchors."

By following this iterative process of reading, analyzing, connecting, and refining, you can arrive at a comprehensive understanding of the purpose and significance of the `element_fragment_anchor_test.cc` file.
这个文件 `blink/renderer/core/page/scrolling/element_fragment_anchor_test.cc` 是 Chromium Blink 引擎中的一个 **测试文件**。 它的主要功能是 **测试 `ElementFragmentAnchor` 类的行为和功能**。 `ElementFragmentAnchor` 类的职责是 **处理页面内通过 URL 片段标识符（例如 `#some-id`）进行的滚动定位**。

以下是更详细的分解：

**1. 主要功能：测试 `ElementFragmentAnchor` 类**

* **验证锚点滚动机制:**  该文件中的测试用例旨在验证当用户导航到包含片段标识符的 URL 时，浏览器是否正确地将页面滚动到与该标识符匹配的元素。
* **测试不同场景下的锚点行为:**  测试覆盖了各种复杂场景，例如：
    * 锚点元素在加载完成前后的行为。
    * 锚点元素在 iframe 中的行为。
    * 锚点元素在动态修改 DOM 时的行为。
    * 锚点元素在 SVG 文档中的行为。
    * 包含 URL 编码字符的锚点。
    * 焦点事件和 requestAnimationFrame 的交互。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

`ElementFragmentAnchor` 的功能直接关系到用户通过 URL 与 HTML 元素交互的方式。

* **HTML:**
    * **锚点链接 (`<a>` 标签):**  测试用例模拟点击带有 `href="#some-id"` 的锚点链接，验证页面是否滚动到 `id="some-id"` 的元素。
        ```html
        <a id="anchorlink" href="#bottom">Link to bottom of the page</a>
        <div style="height: 1000px;"></div>
        <input id="bottom">Bottom of the page</input>
        ```
        在这个例子中，点击 "Link to bottom of the page" 应该滚动页面到 `<input id="bottom">` 元素。
    * **ID 属性:**  测试依赖于 HTML 元素上的 `id` 属性来定位目标锚点。
    * **iframe (`<iframe>` 标签):**  测试用例验证了在包含 `src="child.html#fragment"` 的 iframe 加载时，父页面是否能够正确地将 iframe 滚动到 `#fragment` 元素的位置。

* **CSS:**
    * **布局影响:**  CSS 的布局属性（如 `height`, `width`, `transform`）会影响元素的位置和大小，进而影响滚动的位置。测试用例会考虑这些因素，例如在 `IframeFragmentDirtyLayoutAfterLoad` 测试中，修改 iframe 的宽度会改变其内容的位置，测试会验证滚动是否仍然正确。
    * **样式修改和事件顺序:** `FocusHandlerRunBeforeRaf` 测试验证了当通过 JavaScript 修改 CSS 属性（例如 `background-color`）时，事件处理程序和渲染帧的执行顺序。

* **JavaScript:**
    * **事件监听器 (`addEventListener`):** `FocusHandlerRunBeforeRaf` 测试使用了 `focus` 事件监听器来模拟在锚点目标元素获得焦点时执行 JavaScript 代码，并验证 `requestAnimationFrame` 的执行时机。
    * **`requestAnimationFrame`:**  该 API 用于在浏览器准备好重新绘制动画帧之前执行代码。测试用例验证了焦点事件处理程序中的 `requestAnimationFrame` 回调在渲染更新之前执行。
    * **DOM 操作:** 测试用例使用 JavaScript 的 DOM 操作 API（例如 `document.getElementById`, `remove()`) 来动态修改页面结构，并验证 `ElementFragmentAnchor` 在这些情况下的行为。

**3. 逻辑推理、假设输入与输出:**

以下以 `FocusHandlerRunBeforeRaf` 测试为例进行逻辑推理：

* **假设输入:**
    1. 一个包含指向页面底部锚点的链接的 HTML 页面。
    2. 页面底部有一个带有 `id="bottom"` 的输入框。
    3. 一个监听 `bottom` 元素 `focus` 事件的 JavaScript 代码，该代码使用 `requestAnimationFrame` 修改 `body` 的背景颜色。
    4. 用户点击锚点链接。

* **逻辑推理:**
    1. 点击锚点链接会触发导航到 `#bottom`。
    2. 浏览器会尝试将焦点设置到 `id="bottom"` 的元素。
    3. `bottom` 元素的 `focus` 事件被触发。
    4. `focus` 事件处理程序中的 `requestAnimationFrame` 被调用，计划在下一个渲染帧之前修改 `body` 的背景颜色。
    5. 浏览器执行渲染帧更新。

* **预期输出:**
    1. 页面滚动到 `id="bottom"` 的输入框。
    2. 输入框获得焦点。
    3. `body` 的背景颜色变为绿色 (`#00FF00`)。
    4. **关键:** 背景颜色应该在第一次 `Compositor().BeginFrame()` 调用 *之后* 更新，表明焦点处理程序中的 `requestAnimationFrame` 在渲染更新前执行。

**4. 用户或编程常见的使用错误及举例说明:**

* **忘记设置元素的 `id` 属性:** 用户可能在 URL 中使用了片段标识符，但忘记在目标 HTML 元素上设置对应的 `id` 属性，导致滚动失败。
    ```html
    <a href="#target">Go to target</a>
    <div>This is the target content</div>  <!-- 缺少 id="target" -->
    ```
* **`id` 属性值拼写错误:**  URL 中的片段标识符与目标元素的 `id` 属性值不匹配。
    ```html
    <a href="#tarGet">Go to target</a>
    <div id="target">This is the target content</div>
    ```
* **在动态加载的内容中使用锚点:** 如果目标元素是通过 JavaScript 异步加载的，并且在初始页面加载时不存在，则锚点滚动可能不会立即生效。需要确保在内容加载完成后再进行锚点链接。
* **CSS `overflow: hidden` 或 `overflow: auto` 的影响:**  如果包含目标元素的父元素设置了 `overflow: hidden` 或 `overflow: auto` 并且没有足够的空间来显示目标元素，则滚动可能不会达到预期的效果。
* **iframe 加载问题:**  如果指向 iframe 内元素的锚点在 iframe 完全加载之前被触发，滚动可能会失败。

**5. 用户操作如何一步步到达这里，作为调试线索:**

当开发者需要调试与页面内锚点滚动相关的问题时，可能会查看这个测试文件，以了解 Blink 引擎是如何处理这些情况的。以下是可能导致开发者查看此文件的用户操作步骤：

1. **用户点击页面内的锚点链接:** 这是最直接触发锚点滚动的操作。
2. **用户在地址栏中输入带有片段标识符的 URL 并访问:** 例如，输入 `https://example.com/page.html#section2`。
3. **用户通过 JavaScript 修改 `window.location.hash`:** JavaScript 代码可以动态改变 URL 的片段标识符，从而触发锚点滚动。
4. **页面加载时 URL 中已包含片段标识符:**  当用户首次访问一个包含片段标识符的页面时，浏览器需要执行锚点滚动。
5. **从其他页面跳转到当前页面的锚点:**  用户点击了另一个页面上指向当前页面特定锚点的链接。

**作为调试线索，这个测试文件可以帮助开发者理解以下内容:**

* **Blink 引擎处理锚点滚动的内部机制。**
* **在不同情况下（例如 iframe、动态 DOM）锚点滚动的行为。**
* **可能导致锚点滚动失败的因素。**
* **事件发生的顺序，例如焦点事件和渲染更新的执行顺序。**

通过阅读测试用例，开发者可以更好地理解预期的行为，并对比自己遇到的问题，从而找到问题的根源。例如，如果开发者遇到在 `focus` 事件处理程序中修改样式后，页面没有立即更新的问题，`FocusHandlerRunBeforeRaf` 测试可以提示他们 `requestAnimationFrame` 的作用以及事件的执行顺序。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/element_fragment_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/scrolling/element_fragment_anchor.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using test::RunPendingTasks;

class ElementFragmentAnchorTest : public SimTest {
  void SetUp() override {
    SimTest::SetUp();

    // Focus handlers aren't run unless the page is focused.
    GetDocument().GetPage()->GetFocusController().SetActive(true);
    GetDocument().GetPage()->GetFocusController().SetFocused(true);

    WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  }
};

// Ensure that the focus event handler is run before the rAF callback. We'll
// change the background color from a rAF set in the focus handler and make
// sure the computed background color of that frame was changed. See:
// https://groups.google.com/a/chromium.org/d/msg/blink-dev/5BJSTl-FMGY/JMtaKqGhBAAJ
TEST_F(ElementFragmentAnchorTest, FocusHandlerRunBeforeRaf) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_resource("https://example.com/sheet.css",
                                     "text/css");
  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body {
          background-color: red;
        }
      </style>
      <a id="anchorlink" href="#bottom">Link to bottom of the page</a>
      <div style="height: 1000px;"></div>
      <link rel="stylesheet" type="text/css" href="sheet.css">
      <input id="bottom">Bottom of the page</input>
      <script>
        document.getElementById("bottom").addEventListener('focus', () => {
          requestAnimationFrame(() => {
            document.body.style.backgroundColor = '#00FF00';
          });
        });
      </script>
    )HTML");

  // We're still waiting on the stylesheet to load so the load event shouldn't
  // yet dispatch.
  ASSERT_FALSE(GetDocument().IsLoadCompleted());

  // Click on the anchor element. This will cause a synchronous same-document
  // navigation. The fragment shouldn't activate yet as parsing will be blocked
  // due to the unloaded stylesheet.
  auto* anchor = To<HTMLAnchorElement>(
      GetDocument().getElementById(AtomicString("anchorlink")));
  anchor->click();
  ASSERT_EQ(GetDocument().body(), GetDocument().ActiveElement())
      << "Active element changed while rendering is blocked";

  // Complete the CSS stylesheet load so the document can finish parsing.
  css_resource.Complete("");
  test::RunPendingTasks();

  // Now that the document has fully parsed the anchor should invoke at this
  // point.
  ASSERT_EQ(GetDocument().getElementById(AtomicString("bottom")),
            GetDocument().ActiveElement());

  // The background color shouldn't yet be updated.
  ASSERT_EQ(GetDocument()
                .body()
                ->GetLayoutObject()
                ->Style()
                ->VisitedDependentColor(GetCSSPropertyBackgroundColor())
                .NameForLayoutTreeAsText(),
            Color(255, 0, 0).NameForLayoutTreeAsText());

  Compositor().BeginFrame();

  // Make sure the background color is updated from the rAF without requiring a
  // second BeginFrame.
  EXPECT_EQ(GetDocument()
                .body()
                ->GetLayoutObject()
                ->Style()
                ->VisitedDependentColor(GetCSSPropertyBackgroundColor())
                .NameForLayoutTreeAsText(),
            Color(0, 255, 0).NameForLayoutTreeAsText());
}

// This test ensures that when an iframe's document is closed, and the parent
// has dirty layout, the iframe is laid out prior to invoking its fragment
// anchor. Without performing this layout, the anchor cannot scroll to the
// correct location and it will be cleared since the document is closed.
TEST_F(ElementFragmentAnchorTest, IframeFragmentNoLayoutUntilLoad) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest child_resource("https://example.com/child.html#fragment",
                            "text/html");
  LoadURL("https://example.com/test.html");

  // Don't clcose the main document yet, since that'll cause it to layout.
  main_resource.Write(R"HTML(
      <!DOCTYPE html>
      <style>
        iframe {
          border: 0;
          width: 300px;
          height: 200px;
        }
      </style>
      <iframe id="child" src="child.html#fragment"></iframe>
    )HTML");

  // When the iframe document is loaded, it'll try to scroll the fragment into
  // view. Ensure it does so correctly by laying out first.
  child_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <div style="height:500px;">content</div>
      <div id="fragment">fragment content</div>
    )HTML");
  Compositor().BeginFrame();

  HTMLFrameOwnerElement* iframe = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("child")));
  ScrollableArea* child_viewport =
      iframe->contentDocument()->View()->LayoutViewport();
  Element* fragment =
      iframe->contentDocument()->getElementById(AtomicString("fragment"));

  gfx::Rect fragment_rect_in_frame =
      fragment->GetLayoutObject()->AbsoluteBoundingBoxRect();
  gfx::Rect viewport_rect(child_viewport->VisibleContentRect().size());

  EXPECT_TRUE(viewport_rect.Contains(fragment_rect_in_frame))
      << "Fragment element at [" << fragment_rect_in_frame.ToString()
      << "] was not scrolled into viewport rect [" << viewport_rect.ToString()
      << "]";

  main_resource.Finish();
}

// This test ensures that we correctly scroll the fragment into view in the
// case that the iframe has finished load but layout becomes dirty (in both
// parent and iframe) before we've had a chance to scroll the fragment into
// view.
TEST_F(ElementFragmentAnchorTest, IframeFragmentDirtyLayoutAfterLoad) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest child_resource("https://example.com/child.html#fragment",
                            "text/html");
  LoadURL("https://example.com/test.html");

  // Don't clcose the main document yet, since that'll cause it to layout.
  main_resource.Write(R"HTML(
      <!DOCTYPE html>
      <style>
        iframe {
          border: 0;
          width: 300px;
          height: 200px;
        }
      </style>
      <iframe id="child" src="child.html#fragment"></iframe>
    )HTML");

  // Use text so that changing the iframe width will change the y-location of
  // the fragment.
  child_resource.Complete(R"HTML(
      <!DOCTYPE html>
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum Lorem Ipsum
      <div id="fragment">fragment content</div>
    )HTML");

  HTMLFrameOwnerElement* iframe = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("child")));
  iframe->setAttribute(html_names::kStyleAttr, AtomicString("width:100px"));

  Compositor().BeginFrame();

  ScrollableArea* child_viewport =
      iframe->contentDocument()->View()->LayoutViewport();
  Element* fragment =
      iframe->contentDocument()->getElementById(AtomicString("fragment"));

  gfx::Rect fragment_rect_in_frame =
      fragment->GetLayoutObject()->AbsoluteBoundingBoxRect();
  gfx::Rect viewport_rect(child_viewport->VisibleContentRect().size());

  EXPECT_TRUE(viewport_rect.Contains(fragment_rect_in_frame))
      << "Fragment element at [" << fragment_rect_in_frame.ToString()
      << "] was not scrolled into viewport rect [" << viewport_rect.ToString()
      << "]";

  main_resource.Finish();
}

// Ensure that a BeginFrame after the element-to-focus is removed from the
// document doesn't cause a nullptr crash when the fragment anchor element has
// been removed and garbage collected.
TEST_F(ElementFragmentAnchorTest, AnchorRemovedBeforeBeginFrameCrash) {
  SimRequest main_resource("https://example.com/test.html#anchor", "text/html");
  SimSubresourceRequest css_resource("https://example.com/sheet.css",
                                     "text/css");
  LoadURL("https://example.com/test.html#anchor");

  main_resource.Complete(R"HTML(
        <!DOCTYPE html>
        <link rel="stylesheet" type="text/css" href="sheet.css">
        <div style="height: 1000px;"></div>
        <input id="anchor">Bottom of the page</input>
      )HTML");

  // We're still waiting on the stylesheet to load so the load event shouldn't
  // yet dispatch and parsing is deferred. This will install the anchor.
  ASSERT_FALSE(GetDocument().IsLoadCompleted());

  ASSERT_TRUE(GetDocument().View()->GetFragmentAnchor());
  ASSERT_TRUE(static_cast<ElementFragmentAnchor*>(
                  GetDocument().View()->GetFragmentAnchor())
                  ->anchor_node_.Get());

  // Remove the fragment anchor from the DOM and perform GC.
  GetDocument().getElementById(AtomicString("anchor"))->remove();
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_TRUE(GetDocument().View()->GetFragmentAnchor());
  EXPECT_FALSE(static_cast<ElementFragmentAnchor*>(
                   GetDocument().View()->GetFragmentAnchor())
                   ->anchor_node_.Get());

  // Now that the element has been removed and GC'd, unblock parsing. The
  // anchor should be installed at this point. When parsing finishes, a
  // synchronous layout update will run, which will invoke the fragment anchor.
  css_resource.Complete("");
  test::RunPendingTasks();

  // When the document finishes loading, it does a synchronous layout update,
  // which should clear LocalFrameView::fragment_anchor_ ...
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());

  // Allow any enqueued animation frame tasks to run
  // so their resources can be cleaned up.
  Compositor().BeginFrame();

  // Non-crash is considered a pass.
}

// Ensure that an SVG document doesn't automatically create a fragment anchor
// without the URL actually having a fragment.
TEST_F(ElementFragmentAnchorTest, SVGDocumentDoesntCreateFragment) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest svg_resource("https://example.com/file.svg", "image/svg+xml");

  LoadURL("https://example.com/test.html");

  main_resource.Complete(R"HTML(
      <!DOCTYPE html>
      <img id="image" src=file.svg>
    )HTML");

  // Load an SVG that's transformed outside of the container rect. Ensure that
  // we don't scroll it into view since we didn't specify a hash fragment.
  svg_resource.Complete(R"SVG(
      <svg id="svg" width="50" height="50" xmlns="http://www.w3.org/2000/svg">
         <style>
          #svg{
            transform: translateX(200px) translateY(200px);
          }
         </style>
         <circle class="path" cx="50" cy="50" r="20" fill="red"/>
      </svg>
    )SVG");

  auto* img =
      To<HTMLImageElement>(GetDocument().getElementById(AtomicString("image")));
  auto* svg = To<SVGImage>(img->CachedImage()->GetImage());
  auto* view =
      DynamicTo<LocalFrameView>(svg->GetPageForTesting()->MainFrame()->View());

  // Scroll should remain unchanged and no anchor should be set.
  ASSERT_EQ(ScrollOffset(), view->GetScrollableArea()->GetScrollOffset());
  ASSERT_FALSE(view->GetFragmentAnchor());

  // Check after a BeginFrame as well since SVG documents appear to process the
  // fragment at this time as well.
  Compositor().BeginFrame();
  ASSERT_EQ(ScrollOffset(), view->GetScrollableArea()->GetScrollOffset());
  ASSERT_FALSE(view->GetFragmentAnchor());
}

// This test ensures that we correctly scroll the fragment into view in the
// case that the fragment has characters which need to be URL encoded.
TEST_F(ElementFragmentAnchorTest, HasURLEncodedCharacters) {
  SimRequest main_resource(u"https://example.com/t.html#\u00F6", "text/html");
  LoadURL(u"https://example.com/t.html#\u00F6");

  main_resource.Complete(
      u"<html>\n"
      // SimRequest sends UTF-8 to parser but the parser defaults to UTF-16.
      u"    <head><meta charset=\"UTF-8\"></head>\n"
      u"    <body>\n"
      u"        <div style=\"height: 50cm;\">blank space</div>\n"
      u"        <h1 id=\"\u00F6\">\u00D6</h1>\n"
      // TODO(1117212): The escaped version currently takes precedence.
      // u"     <div style=\"height: 50cm;\">blank space</div>\n"
      // u"     <h1 id=\"%C3%B6\">\u00D62</h1>\n"
      u"        <div style=\"height: 50cm;\">blank space</div>\n"
      u"        <h1 id=\"non-umlaut\">non-umlaut</h1>\n"
      u"    </body>\n"
      u"</html>");

  Compositor().BeginFrame();

  ScrollableArea* viewport = GetDocument().View()->LayoutViewport();
  Element* fragment = GetDocument().getElementById(AtomicString(u"\u00F6"));
  ASSERT_NE(nullptr, fragment);

  gfx::Rect fragment_rect_in_frame =
      fragment->GetLayoutObject()->AbsoluteBoundingBoxRect();
  gfx::Rect viewport_rect(viewport->VisibleContentRect().size());

  EXPECT_TRUE(viewport_rect.Contains(fragment_rect_in_frame))
      << "Fragment element at [" << fragment_rect_in_frame.ToString()
      << "] was not scrolled into viewport rect [" << viewport_rect.ToString()
      << "]";
}

}  // namespace blink

"""

```
Response:
The user wants a summary of the functionality of the `scroll_into_view_test.cc` file in the Chromium Blink engine. I need to analyze the code to understand its purpose and then address the specific points requested by the user: relationship to web technologies, logical reasoning (test cases), common errors, user interaction, and finally, a concise summary of its functionality for this first part.

**Plan:**

1. **Identify the main purpose:** The filename and the included headers suggest this file contains tests for the `scrollIntoView` functionality.
2. **Analyze the tests:** Look at the different `TEST_P` functions to understand the specific scenarios being tested (e.g., instant scroll, smooth scroll, nested containers, scroll padding, etc.).
3. **Relate to web technologies:**  `scrollIntoView` is a JavaScript API. Consider how these tests relate to HTML elements and CSS properties (like `overflow`, `scroll-padding`, `scroll-behavior`).
4. **Identify logical reasoning (input/output):**  Each test case can be considered a logical deduction with an implied input (HTML structure and JavaScript calls) and expected output (scroll positions).
5. **Consider user/programming errors:** Think about what could go wrong when using `scrollIntoView` or related features.
6. **Trace user actions:**  How does a user's interaction eventually lead to this code being executed?
7. **Summarize for Part 1:** Condense the findings into a brief description of the file's function.
```
这是目录为blink/renderer/core/page/scrolling/scroll_into_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "cc/base/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features_generated.h"
#include "third_party/blink/public/mojom/frame/find_in_page.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_focus_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_to_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_boolean_scrollintoviewoptions.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

namespace {

class ScrollIntoViewTest : public SimTest,
                           public ::testing::WithParamInterface<
                               std::vector<base::test::FeatureRef>> {
 public:
  ScrollIntoViewTest() {
    feature_list_.InitWithFeatures(
        GetParam(),
        /*disabled_features=*/std::vector<base::test::FeatureRef>());
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    ,
    ScrollIntoViewTest,
    testing::Values(std::vector<base::test::FeatureRef>{},
                    std::vector<base::test::FeatureRef>{
                        features::kMultiSmoothScrollIntoView}));

TEST_P(ScrollIntoViewTest, InstantScroll) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      "<div id='space' style='height: 1000px'></div>"
      "<div id='content' style='height: 1000px'></div>");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  content->scrollIntoView(
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options));

  ASSERT_EQ(Window().scrollY(), content->OffsetTop());
}

TEST_P(ScrollIntoViewTest, ScrollPaddingOnDocumentElWhenBodyDefinesViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
      html {
        scroll-padding: 10px;
      }
      body {
        margin: 0px;
        height: 300px;
        overflow: scroll;
      }
      </style>
      <div id='space' style='height: 1000px'></div>
      <div id='target' style='height: 200px;'></div>
      <div id='space' style='height: 1000px'></div>
    )HTML");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().body(), GetDocument().ViewportDefiningElement());
  ASSERT_EQ(Window().scrollY(), target->OffsetTop() - 10);
}

TEST_P(ScrollIntoViewTest,
       ScrollPaddingOnDocumentElWhenDocumentElDefinesViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
      :root {
        height: 300px;
        overflow: scroll;
        scroll-padding: 10px;
      }
      </style>
      <div id='space' style='height: 1000px'></div>
      <div id='target' style='height: 200px;'></div>
      <div id='space' style='height: 1000px'></div>
    )HTML");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());
  ASSERT_EQ(Window().scrollY(), target->OffsetTop() - 10);
}

TEST_P(ScrollIntoViewTest, ScrollPaddingOnBodyWhenDocumentElDefinesViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
      :root {
        height: 300px;
        overflow: scroll;
        scroll-padding: 2px;
      }
      body {
        margin: 0px;
        height: 400px;
        overflow: scroll;
        scroll-padding: 10px;
      }
      </style>
      <div id='space' style='height: 1000px'></div>
      <div id='target' style='height: 200px;'></div>
      <div id='space' style='height: 1000px'></div>
    )HTML");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());

  // When body and document elements are both scrollable then both the body and
  // element should scroll and align with its padding.
  Element* body = GetDocument().body();
  ASSERT_EQ(body->scrollTop(), target->OffsetTop() - 10);
  ASSERT_EQ(Window().scrollY(), 10 - 2);
}

// When the sum of scroll-padding in a scroll container along a specific axis
// exceeds the length of that axis, it results in an empty scrollport. In this
// case, invoking scrollIntoView on a child element within the scrollport
// should not trigger scrolling.
// See https://crbug.com/40055750
TEST_P(ScrollIntoViewTest, EmptyScrollportSinceScrollPadding) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
        #container {
          width: 200px;
          display: flex;
          flex-direction: row;
          overflow-x: scroll;
          scroll-padding: 50px 0;
          height: 50px;
        }

        .item {
          width: 50px;
          height: 50px;
          flex-shrink: 0;
        }
      </style>
     <div id="container">
        <div class="item"></div>
        <div id="target" class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
      </div>
    )HTML");

  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();
  Element* scroller = GetDocument().getElementById(AtomicString("container"));

  ASSERT_EQ(scroller->scrollLeft(), 0);
}

TEST_P(ScrollIntoViewTest, SmoothScroll) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      "<div id='space' style='height: 1000px'></div>"
      "<div id='content' style='height: 1000px'></div>");

  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);

  content->scrollIntoView(arg);
  // Scrolling the container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);

  // Finish scrolling the container
  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), content->OffsetTop());
}

TEST_P(ScrollIntoViewTest, NestedContainer) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='space' style='height: 1000px'></div>
    <div id='container' style='height: 600px; overflow: scroll'>
      <div id='space1' style='height: 1000px'></div>
      <div id='content' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  content->scrollIntoView(arg);
  // Scrolling the outer container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also scroll the
    // inner container.
    ASSERT_NEAR(container->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  // Finish scrolling the outer container
  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), container->OffsetTop());
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also have
    // scrolled inner container.
    ASSERT_EQ(container->scrollTop(),
              content->OffsetTop() - container->OffsetTop());
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // The rest of the test depends on scrolling the inner and outer scrollers
    // sequentially, which we do not do if MultiSmoothScrollIntoView is enabled.
    return;
  }

  // Scrolling the inner container
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(container->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 794 : 299), 1);

  // Finish scrolling the inner container
  Compositor().BeginFrame(1);
  ASSERT_EQ(container->scrollTop(),
            content->OffsetTop() - container->OffsetTop());
}

TEST_P(ScrollIntoViewTest, NewScrollIntoViewAbortsCurrentAnimation) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='container2' style='height: 1000px; overflow: scroll'>
      <div id='space2' style='height: 1200px'></div>
      <div id='content2' style='height: 1000px'></div>
    </div>
    <div id='container1' style='height: 600px; overflow: scroll'>
      <div id='space1' style='height: 1000px'></div>
      <div id='content1' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container1 =
      GetDocument().getElementById(AtomicString("container1"));
  Element* container2 =
      GetDocument().getElementById(AtomicString("container2"));
  Element* content1 = GetDocument().getElementById(AtomicString("content1"));
  Element* content2 = GetDocument().getElementById(AtomicString("content2"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container1->scrollTop(), 0);
  ASSERT_EQ(container2->scrollTop(), 0);

  content1->scrollIntoView(arg);
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also scroll
    // container1.
    ASSERT_NEAR(container1->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container1->scrollTop(), 0);
  }

  content2->scrollIntoView(arg);
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 171 : 61), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the new scrollIntoView does not
    // cancel the first scrollIntoView so the scroll on container1 continues.
    ASSERT_GT(container1->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299));
  } else {
    ASSERT_EQ(container1->scrollTop(), 0);  // container1 should not scroll.
  }

  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), container2->OffsetTop());
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also have
    // scrolled inner container.
    ASSERT_EQ(container2->scrollTop(),
              content2->OffsetTop() - container2->OffsetTop());
  } else {
    ASSERT_EQ(container2->scrollTop(), 0);
  }

  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // The rest of the test depends on scrolling the inner and outer scrollers
    // sequentially, which we do not do if MultiSmoothScrollIntoView is enabled.
    return;
  }

  // Scrolling content2 in container2
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(container2->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 952 : 300), 1);

  // Finish all the animation to make sure there is no another animation queued
  // on container1.
  while (Compositor().NeedsBeginFrame()) {
    Compositor().BeginFrame();
  }
  ASSERT_EQ(Window().scrollY(), container2->OffsetTop());
  ASSERT_EQ(container2->scrollTop(),
            content2->OffsetTop() - container2->OffsetTop());
  ASSERT_EQ(container1->scrollTop(), 0);
}

// Ensure an in-progress smooth sequenced scroll isn't interrupted by a
// scrollIntoView call that doesn't actually cause scrolling.
TEST_P(ScrollIntoViewTest, NoOpScrollIntoViewContinuesCurrentAnimation) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div id='space' style='height: 500px'></div>
    <div id='visibleElement' style='height: 100px'></div>
    <div id='container' style='height: 300px; overflow: scroll'>
      <div id='space' style='height: 1000px'></div>
      <div id='content' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  Element* visibleElement =
      GetDocument().getElementById(AtomicString("visibleElement"));

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  {
    ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
    options->setBlock("start");
    options->setBehavior("smooth");
    auto* arg =
        MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
    content->scrollIntoView(arg);
  }

  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 250 : 241), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_NEAR(container->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  // Since visibleElement is already on screen, this call should be a no-op.
  {
    ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
    // "nearest" is a no-op if the element is fully on-screen.
    options->setBlock("nearest");
    options->setBehavior("smooth");
    auto* arg =
        MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
    visibleElement->scrollIntoView(arg);
  }

  // The window animation should continue running but the container shouldn't
  // yet have started unless MultiSmoothScrollIntoView support is enabled.
  Compositor().BeginFrame();
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 258 : 260), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_GT(container->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299));
  } else {
    // container should not have scrolled yet.
    ASSERT_EQ(container->scrollTop(), 0);
  }

  // Finish the animation to make sure the animation to content finishes
  // without interruption.
  while (Compositor().NeedsBeginFrame()) {
    Compositor().BeginFrame();
  }
  EXPECT_EQ(Window().scrollY(), container->OffsetHeight());
  EXPECT_EQ(container->scrollTop(), 1000);
}

TEST_P(ScrollIntoViewTest, ScrollWindowAbortsCurrentAnimation) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='space' style='height: 1000px'></div>
    <div id='container' style='height: 600px; overflow: scroll'>
      <div id='space1' style='height: 1000px'></div>
      <div id='content' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  content->scrollIntoView(arg);
  // Scrolling the outer container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_NEAR(container->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  ScrollToOptions* window_option = ScrollToOptions::Create();
  window_option->setLeft(0);
  window_option->setTop(0);
  window_option->setBehavior("smooth");
  Window().scrollTo(window_option);
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 165 : 58), 1);

  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), 0);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_EQ(container->scrollTop(),
              content->OffsetTop() - container->OffsetTop());
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }
}

TEST_P(ScrollIntoViewTest, BlockAndInlineSettings) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='container' style='height: 2500px; width: 2500px;'>
    <div id='content' style='height: 500px; width: 500px;
    margin-left: 1000px; margin-right: 1000px; margin-top: 1000px;
    margin-bottom: 1000px'></div></div>
  )HTML");

  int content_height = 500;
  int content_width = 500;
  int window_height = 600;
  int window_width = 800;

  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  ASSERT_EQ(Window().scrollY(), 0);

  options->setBlock("nearest");
  options->setInlinePosition("nearest");
  auto* arg1 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg1);
  ASSERT_EQ(Window().scrollX(),
            content->OffsetLeft() + content_width - window_width);
  ASSERT_EQ(Window().scrollY(),
            content->OffsetTop() + content_height - window_height);

  options->setBlock("start");
  options->setInlinePosition("start");
  auto* arg2 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg2);
  ASSERT_EQ(Window().scrollX(), content->OffsetLeft());
  ASSERT_EQ(Window().scrollY(), content->OffsetTop());

  options->setBlock("center");
  options->setInlinePosition("center");
  auto* arg3 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg3);
  ASSERT_EQ(Window().scrollX(),
            content->OffsetLeft() + (content_width - window_width) / 2);
  ASSERT_EQ(Window().scrollY(),
            content->OffsetTop() + (content_height - window_height) / 2);

  options->setBlock("end");
  options->setInlinePosition("end");
  auto* arg4 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg4);
  ASSERT_EQ(Window().scrollX(),
            content->OffsetLeft() + content_width - window_width);
  ASSERT_EQ(Window().scrollY(),
            content->OffsetTop() + content_height - window_height);
}

TEST_P(ScrollIntoViewTest, SmoothAndInstantInChain) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='space' style='height: 1000px'></div>
    <div id='container' style='height: 600px; overflow: scroll;
      scroll-behavior: smooth'>
      
### 提示词
```
这是目录为blink/renderer/core/page/scrolling/scroll_into_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "cc/base/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features_generated.h"
#include "third_party/blink/public/mojom/frame/find_in_page.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_focus_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_to_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_boolean_scrollintoviewoptions.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

namespace {

class ScrollIntoViewTest : public SimTest,
                           public ::testing::WithParamInterface<
                               std::vector<base::test::FeatureRef>> {
 public:
  ScrollIntoViewTest() {
    feature_list_.InitWithFeatures(
        GetParam(),
        /*disabled_features=*/std::vector<base::test::FeatureRef>());
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    ,
    ScrollIntoViewTest,
    testing::Values(std::vector<base::test::FeatureRef>{},
                    std::vector<base::test::FeatureRef>{
                        features::kMultiSmoothScrollIntoView}));

TEST_P(ScrollIntoViewTest, InstantScroll) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      "<div id='space' style='height: 1000px'></div>"
      "<div id='content' style='height: 1000px'></div>");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  content->scrollIntoView(
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options));

  ASSERT_EQ(Window().scrollY(), content->OffsetTop());
}

TEST_P(ScrollIntoViewTest, ScrollPaddingOnDocumentElWhenBodyDefinesViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
      html {
        scroll-padding: 10px;
      }
      body {
        margin: 0px;
        height: 300px;
        overflow: scroll;
      }
      </style>
      <div id='space' style='height: 1000px'></div>
      <div id='target' style='height: 200px;'></div>
      <div id='space' style='height: 1000px'></div>
    )HTML");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().body(), GetDocument().ViewportDefiningElement());
  ASSERT_EQ(Window().scrollY(), target->OffsetTop() - 10);
}

TEST_P(ScrollIntoViewTest,
       ScrollPaddingOnDocumentElWhenDocumentElDefinesViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
      :root {
        height: 300px;
        overflow: scroll;
        scroll-padding: 10px;
      }
      </style>
      <div id='space' style='height: 1000px'></div>
      <div id='target' style='height: 200px;'></div>
      <div id='space' style='height: 1000px'></div>
    )HTML");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());
  ASSERT_EQ(Window().scrollY(), target->OffsetTop() - 10);
}

TEST_P(ScrollIntoViewTest, ScrollPaddingOnBodyWhenDocumentElDefinesViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
      :root {
        height: 300px;
        overflow: scroll;
        scroll-padding: 2px;
      }
      body {
        margin: 0px;
        height: 400px;
        overflow: scroll;
        scroll-padding: 10px;
      }
      </style>
      <div id='space' style='height: 1000px'></div>
      <div id='target' style='height: 200px;'></div>
      <div id='space' style='height: 1000px'></div>
    )HTML");

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();

  // Sanity check that document element is the viewport defining element
  ASSERT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());

  // When body and document elements are both scrollable then both the body and
  // element should scroll and align with its padding.
  Element* body = GetDocument().body();
  ASSERT_EQ(body->scrollTop(), target->OffsetTop() - 10);
  ASSERT_EQ(Window().scrollY(), 10 - 2);
}

// When the sum of scroll-padding in a scroll container along a specific axis
// exceeds the length of that axis, it results in an empty scrollport. In this
// case, invoking scrollIntoView on a child element within the scrollport
// should not trigger scrolling.
// See https://crbug.com/40055750
TEST_P(ScrollIntoViewTest, EmptyScrollportSinceScrollPadding) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <style>
        #container {
          width: 200px;
          display: flex;
          flex-direction: row;
          overflow-x: scroll;
          scroll-padding: 50px 0;
          height: 50px;
        }

        .item {
          width: 50px;
          height: 50px;
          flex-shrink: 0;
        }
      </style>
     <div id="container">
        <div class="item"></div>
        <div id="target" class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
        <div class="item"></div>
      </div>
    )HTML");

  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->scrollIntoView();
  Element* scroller = GetDocument().getElementById(AtomicString("container"));

  ASSERT_EQ(scroller->scrollLeft(), 0);
}

TEST_P(ScrollIntoViewTest, SmoothScroll) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      "<div id='space' style='height: 1000px'></div>"
      "<div id='content' style='height: 1000px'></div>");

  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);

  content->scrollIntoView(arg);
  // Scrolling the container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);

  // Finish scrolling the container
  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), content->OffsetTop());
}

TEST_P(ScrollIntoViewTest, NestedContainer) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='space' style='height: 1000px'></div>
    <div id='container' style='height: 600px; overflow: scroll'>
      <div id='space1' style='height: 1000px'></div>
      <div id='content' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  content->scrollIntoView(arg);
  // Scrolling the outer container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also scroll the
    // inner container.
    ASSERT_NEAR(container->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  // Finish scrolling the outer container
  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), container->OffsetTop());
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also have
    // scrolled inner container.
    ASSERT_EQ(container->scrollTop(),
              content->OffsetTop() - container->OffsetTop());
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // The rest of the test depends on scrolling the inner and outer scrollers
    // sequentially, which we do not do if MultiSmoothScrollIntoView is enabled.
    return;
  }

  // Scrolling the inner container
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(container->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 794 : 299), 1);

  // Finish scrolling the inner container
  Compositor().BeginFrame(1);
  ASSERT_EQ(container->scrollTop(),
            content->OffsetTop() - container->OffsetTop());
}

TEST_P(ScrollIntoViewTest, NewScrollIntoViewAbortsCurrentAnimation) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='container2' style='height: 1000px; overflow: scroll'>
      <div id='space2' style='height: 1200px'></div>
      <div id='content2' style='height: 1000px'></div>
    </div>
    <div id='container1' style='height: 600px; overflow: scroll'>
      <div id='space1' style='height: 1000px'></div>
      <div id='content1' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container1 =
      GetDocument().getElementById(AtomicString("container1"));
  Element* container2 =
      GetDocument().getElementById(AtomicString("container2"));
  Element* content1 = GetDocument().getElementById(AtomicString("content1"));
  Element* content2 = GetDocument().getElementById(AtomicString("content2"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container1->scrollTop(), 0);
  ASSERT_EQ(container2->scrollTop(), 0);

  content1->scrollIntoView(arg);
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also scroll
    // container1.
    ASSERT_NEAR(container1->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container1->scrollTop(), 0);
  }

  content2->scrollIntoView(arg);
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 171 : 61), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the new scrollIntoView does not
    // cancel the first scrollIntoView so the scroll on container1 continues.
    ASSERT_GT(container1->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299));
  } else {
    ASSERT_EQ(container1->scrollTop(), 0);  // container1 should not scroll.
  }

  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), container2->OffsetTop());
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // If MultiSmoothScrollIntoView is enabled, the frames will also have
    // scrolled inner container.
    ASSERT_EQ(container2->scrollTop(),
              content2->OffsetTop() - container2->OffsetTop());
  } else {
    ASSERT_EQ(container2->scrollTop(), 0);
  }

  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    // The rest of the test depends on scrolling the inner and outer scrollers
    // sequentially, which we do not do if MultiSmoothScrollIntoView is enabled.
    return;
  }

  // Scrolling content2 in container2
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(container2->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 952 : 300), 1);

  // Finish all the animation to make sure there is no another animation queued
  // on container1.
  while (Compositor().NeedsBeginFrame()) {
    Compositor().BeginFrame();
  }
  ASSERT_EQ(Window().scrollY(), container2->OffsetTop());
  ASSERT_EQ(container2->scrollTop(),
            content2->OffsetTop() - container2->OffsetTop());
  ASSERT_EQ(container1->scrollTop(), 0);
}

// Ensure an in-progress smooth sequenced scroll isn't interrupted by a
// scrollIntoView call that doesn't actually cause scrolling.
TEST_P(ScrollIntoViewTest, NoOpScrollIntoViewContinuesCurrentAnimation) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div id='space' style='height: 500px'></div>
    <div id='visibleElement' style='height: 100px'></div>
    <div id='container' style='height: 300px; overflow: scroll'>
      <div id='space' style='height: 1000px'></div>
      <div id='content' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  Element* visibleElement =
      GetDocument().getElementById(AtomicString("visibleElement"));

  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  {
    ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
    options->setBlock("start");
    options->setBehavior("smooth");
    auto* arg =
        MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
    content->scrollIntoView(arg);
  }

  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 250 : 241), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_NEAR(container->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  // Since visibleElement is already on screen, this call should be a no-op.
  {
    ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
    // "nearest" is a no-op if the element is fully on-screen.
    options->setBlock("nearest");
    options->setBehavior("smooth");
    auto* arg =
        MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
    visibleElement->scrollIntoView(arg);
  }

  // The window animation should continue running but the container shouldn't
  // yet have started unless MultiSmoothScrollIntoView support is enabled.
  Compositor().BeginFrame();
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 258 : 260), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_GT(container->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299));
  } else {
    // container should not have scrolled yet.
    ASSERT_EQ(container->scrollTop(), 0);
  }

  // Finish the animation to make sure the animation to content finishes
  // without interruption.
  while (Compositor().NeedsBeginFrame()) {
    Compositor().BeginFrame();
  }
  EXPECT_EQ(Window().scrollY(), container->OffsetHeight());
  EXPECT_EQ(container->scrollTop(), 1000);
}

TEST_P(ScrollIntoViewTest, ScrollWindowAbortsCurrentAnimation) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='space' style='height: 1000px'></div>
    <div id='container' style='height: 600px; overflow: scroll'>
      <div id='space1' style='height: 1000px'></div>
      <div id='content' style='height: 1000px'></div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  options->setBehavior("smooth");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  content->scrollIntoView(arg);
  // Scrolling the outer container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_NEAR(container->scrollTop(),
                (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }

  ScrollToOptions* window_option = ScrollToOptions::Create();
  window_option->setLeft(0);
  window_option->setTop(0);
  window_option->setBehavior("smooth");
  Window().scrollTo(window_option);
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 165 : 58), 1);

  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), 0);
  if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
    ASSERT_EQ(container->scrollTop(),
              content->OffsetTop() - container->OffsetTop());
  } else {
    ASSERT_EQ(container->scrollTop(), 0);
  }
}

TEST_P(ScrollIntoViewTest, BlockAndInlineSettings) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='container' style='height: 2500px; width: 2500px;'>
    <div id='content' style='height: 500px; width: 500px;
    margin-left: 1000px; margin-right: 1000px; margin-top: 1000px;
    margin-bottom: 1000px'></div></div>
  )HTML");

  int content_height = 500;
  int content_width = 500;
  int window_height = 600;
  int window_width = 800;

  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  ASSERT_EQ(Window().scrollY(), 0);

  options->setBlock("nearest");
  options->setInlinePosition("nearest");
  auto* arg1 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg1);
  ASSERT_EQ(Window().scrollX(),
            content->OffsetLeft() + content_width - window_width);
  ASSERT_EQ(Window().scrollY(),
            content->OffsetTop() + content_height - window_height);

  options->setBlock("start");
  options->setInlinePosition("start");
  auto* arg2 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg2);
  ASSERT_EQ(Window().scrollX(), content->OffsetLeft());
  ASSERT_EQ(Window().scrollY(), content->OffsetTop());

  options->setBlock("center");
  options->setInlinePosition("center");
  auto* arg3 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg3);
  ASSERT_EQ(Window().scrollX(),
            content->OffsetLeft() + (content_width - window_width) / 2);
  ASSERT_EQ(Window().scrollY(),
            content->OffsetTop() + (content_height - window_height) / 2);

  options->setBlock("end");
  options->setInlinePosition("end");
  auto* arg4 =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  content->scrollIntoView(arg4);
  ASSERT_EQ(Window().scrollX(),
            content->OffsetLeft() + content_width - window_width);
  ASSERT_EQ(Window().scrollY(),
            content->OffsetTop() + content_height - window_height);
}

TEST_P(ScrollIntoViewTest, SmoothAndInstantInChain) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='space' style='height: 1000px'></div>
    <div id='container' style='height: 600px; overflow: scroll;
      scroll-behavior: smooth'>
      <div id='space1' style='height: 1000px'></div>
      <div id='inner_container' style='height: 1000px; overflow: scroll;'>
        <div id='space2' style='height: 1000px'></div>
        <div id='content' style='height: 1000px;'></div>
      </div>
    </div>
  )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* inner_container =
      GetDocument().getElementById(AtomicString("inner_container"));
  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);
  ASSERT_EQ(container->scrollTop(), 0);

  content->scrollIntoView(arg);
  // Instant scroll of the window should have finished.
  ASSERT_EQ(Window().scrollY(), container->OffsetTop());
  // Instant scroll of the inner container should not have started.
  ASSERT_EQ(container->scrollTop(), 0);
  // Smooth scroll should not have started.
  ASSERT_EQ(container->scrollTop(), 0);

  // Scrolling the container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(container->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 794 : 299), 1);

  // Finish scrolling the container
  Compositor().BeginFrame(1);
  ASSERT_EQ(container->scrollTop(),
            inner_container->OffsetTop() - container->OffsetTop());
  // Instant scroll of the inner container should have finished.
  ASSERT_EQ(inner_container->scrollTop(),
            content->OffsetTop() - inner_container->OffsetTop());
}

TEST_P(ScrollIntoViewTest, SmoothScrollAnchor) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html#link", "text/html");
  LoadURL("https://example.com/test.html#link");
  request.Complete(R"HTML(
    <div id='container' style='height: 600px; overflow: scroll;
      scroll-behavior: smooth'>
      <div id='space' style='height: 1000px'></div>
      <div style='height: 1000px'><a name='link'
    id='content'>hello</a></div>
    </div>
  )HTML");

  Element* content = GetDocument().getElementById(AtomicString("content"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container->scrollTop(), 0);

  // Scrolling the container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(container->scrollTop(),
              (::features::IsImpulseScrollAnimationEnabled() ? 794 : 299), 1);

  // Finish scrolling the container
  Compositor().BeginFrame(1);
  ASSERT_EQ(container->scrollTop(),
            content->OffsetTop() - container->OffsetTop());
}

TEST_P(ScrollIntoViewTest, FindDoesNotScrollOverflowHidden) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <div id='container' style='height: 400px; overflow: hidden;'>
      <div id='space' style='height: 500px'></div>
      <div style='height: 500px'>hello</div>
    </div>
  )HTML");
  Element* container = GetDocument().getElementById(AtomicString("container"));
  Compositor().BeginFrame();
  ASSERT_EQ(container->scrollTop(), 0);
  const int kFindIdentifier = 12345;
  auto options = mojom::blink::FindOptions::New();
  options->run_synchronously_for_testing = true;
  MainFrame().GetFindInPage()->FindInternal(
      kFindIdentifier, WebString::FromUTF8("hello"), *options, false);
  ASSERT_EQ(container->scrollTop(), 0);
}

TEST_P(ScrollIntoViewTest, ApplyRootElementScrollBehaviorToViewport) {
  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      "<html style='scroll-behavior: smooth'>"
      "<div id='space' style='height: 1000px'></div>"
      "<div id='content' style='height: 1000px'></div></html>");

  Element* content = GetDocument().getElementById(AtomicString("content"));
  ScrollIntoViewOptions* options = ScrollIntoViewOptions::Create();
  options->setBlock("start");
  auto* arg =
      MakeGarbageCollected<V8UnionBooleanOrScrollIntoViewOptions>(options);
  Compositor().BeginFrame();
  ASSERT_EQ(Window().scrollY(), 0);

  content->scrollIntoView(arg);
  // Scrolling the container
  Compositor().BeginFrame();  // update run_state_.
  Compositor().BeginFrame();  // Set start_time = now.
  Compositor().BeginFrame(0.2);
  ASSERT_NEAR(Window().scrollY(),
              (::features::IsImpulseScrollAnimationEnabled() ? 800 : 299), 1);

  // Finish scrolling the container
  Compositor().BeginFrame(1);
  ASSERT_EQ(Window().scrollY(), content->OffsetTop());
}

// This test ensures the for_focused_editable option works correctly to
// prevent scrolling a non-default root scroller from the page revealing
// ScrollIntoView (the layout viewport scroll will be animated, potentially
// with zoom, from WebViewImpl::FinishScrollFocusedEditableIntoView.
TEST_P(ScrollIntoViewTest, StopAtLayoutViewportForFocusedEditable) {
  ScopedImplicitRootScrollerForTest implicit_root_scroller(true);

  v8::HandleScope HandleScope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body,html {
        margin: 0;
        width: 100%;
        height: 100%;
      }
      #root {
        width: 100%;
        height: 100%;
        overflow: auto;
      }
      #inner {
        width: 100%;
        height: 100%;
        overflow: auto;
        margin-top: 1000px;
      }
      #target {
        margin-top: 1000px;
        margin-bottom: 1000px;
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='root'>
      <div id='inner'>
        <input id='target'>
      <div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* inner = GetDocument().getElementById(AtomicString("inner"));

  // Make sure the root scroller is set since that's what we're trying to test
  // here.
  {
    TopDocumentRootScrollerController& rs_controller =
        GetDocument().GetPage()->GlobalRootScrollerController();
    ASSERT_EQ(root, rs_controller.Glo
```
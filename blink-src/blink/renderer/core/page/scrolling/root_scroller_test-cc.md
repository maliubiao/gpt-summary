Response:
My thinking process to arrive at the summary of the `root_scroller_test.cc` file goes like this:

1. **Understand the Goal:** The request asks for a summary of the file's functionality, specifically focusing on its relation to web technologies (JavaScript, HTML, CSS), potential logical inferences, common user/programming errors it might test, and how a user's actions could lead to this code being executed. It also emphasizes this is part 1 of 4 and needs a concise summary.

2. **Initial Code Scan (Keywords and Imports):** I start by quickly scanning the `#include` directives and the `namespace blink` declaration. This immediately tells me the file is:
    * A C++ test file (`testing/gtest/include/gtest/gtest.h`).
    * Part of the Blink rendering engine (`blink::`).
    * Focused on scrolling (`blink/renderer/core/page/scrolling/`).
    * Specifically testing `RootScroller` functionality.
    * Using various Blink core components related to frames, pages, layout, and input.

3. **Identify Key Classes and Concepts:**  Looking at the included headers and the test fixture name (`RootScrollerTest`), I identify the central concepts being tested:
    * `RootScrollerController`: The core class managing the effective root scroller.
    * Effective Root Scroller: The DOM element responsible for scrolling the main content.
    * `Document`, `Element`: Core DOM nodes relevant to scrolling.
    * `LocalFrameView`, `VisualViewport`: Classes related to viewport and frame rendering.
    * `WebGestureEvent`:  Simulating user touch/scroll events.
    * Browser Controls (URL bar, bottom bar): Their interaction with scrolling.
    * Compositing: Whether scrolling happens on the GPU for performance.
    * Iframes: How nested frames interact with root scrolling.

4. **Analyze Test Case Names and Logic (High-Level):** I skim through the `TEST_F` macros and their names. This provides a good overview of the specific scenarios being tested:
    * `TestDefaultRootScroller`:  Verifies the document is the default.
    * `defaultEffectiveRootScrollerIsDocumentNode`: Checks document remains the default even after DOM changes.
    * `BrowserControlsAndOverscroll`:  Tests interaction between root scroller, browser UI, and overscroll effects.
    * `TestRemoveRootScrollerFromDom`: Ensures removal of the root scroller updates the effective scroller.
    * `TestRootScrollerBecomesInvalid`:  Tests scenarios where a designated root scroller becomes ineligible.
    * `RemoveCurrentRootScroller`: Similar to removal, focusing on lifecycle.
    * `AlwaysCreateCompositedScrollingLayers`:  Checks that root scrollers are composited.
    * `IFrameSwapToRemote`: Tests how changing an iframe's type affects the root scroller.
    * `UseVisualViewportScrollbars`, `UseVisualViewportScrollbarsIframe`: Tests Android-specific behavior with visual viewport scrollbars.
    * `TopControlsAdjustmentAppliedToRootScroller`:  Tests how browser control visibility affects scrolling.
    * `RotationAnchoring`: Tests how rotation affects scroll anchoring.
    * `InvalidDefaultRootScroller`: Tests handling of invalid default root scrollers.
    * `IFrameRootScrollerGetsNonFixedLayoutSize`: Focuses on iframe layout sizing when it becomes the root scroller.

5. **Connect to Web Technologies:**  Based on the identified concepts and test cases, I can connect them to JavaScript, HTML, and CSS:
    * **HTML:**  The tests manipulate the DOM structure (adding/removing elements, changing `documentElement`, working with iframes). The test files (`overflow-scrolling.html`, `root-scroller.html`, etc.) likely define HTML structures with scrollable content.
    * **CSS:**  CSS properties like `overflow: auto`, `display`, `width`, `height`, and `position: absolute` are used to influence scrollability and layout, which are directly tested.
    * **JavaScript:** The `ExecuteScript` function clearly indicates JavaScript is used within the tests to dynamically modify the DOM and CSS, triggering updates and allowing verification of the root scroller's behavior.

6. **Infer Logical Relationships and Potential Errors:** I consider the purpose of these tests:
    * **Logical Inference:** The code infers the correct root scroller based on DOM structure and CSS properties. It has to handle cases where the explicitly set root scroller is removed or becomes invalid.
    * **Common Errors:**  Potential developer errors include:
        * Incorrectly setting or removing the root scroller element.
        * Not accounting for browser controls when calculating scroll limits.
        * Assuming the document is always the root scroller.
        * Incorrectly using CSS properties that might invalidate a root scroller.

7. **User Actions and Debugging:**  I consider how a user's interaction can lead to this code being relevant:
    * **User Actions:** Scrolling with touch or mouse, resizing the browser window (especially rotation on mobile), interacting with iframes.
    * **Debugging:** If scrolling behavior is incorrect, understanding how the root scroller is determined is crucial. This test file provides insights into that logic. Stepping through the `RootScrollerController` code and observing how it reacts to DOM/CSS changes would be a debugging step.

8. **Synthesize the Summary:**  Finally, I combine all the above points into a concise summary, focusing on the core function of the test file and its relation to web technologies, logical flow, and potential errors, keeping in mind it's the first part of a larger set. I aim for clarity and avoid overly technical jargon where possible.

By following this process, I can systematically analyze the code snippet and generate a comprehensive yet concise summary that addresses all aspects of the request.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_hit_test_result.h"
#include "third_party/blink/public/web/web_remote_frame.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_node_string_trustedscript.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/dom_visual_viewport.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using blink::test::RunPendingTasks;
using testing::Mock;

namespace blink {

namespace {

class RootScrollerTest : public testing::Test,
                         private ScopedImplicitRootScrollerForTest {
 public:
  RootScrollerTest()
      : ScopedImplicitRootScrollerForTest(true),
        base_url_("http://www.test.com/") {
    RegisterMockedHttpURLLoad("overflow-scrolling.html");
    RegisterMockedHttpURLLoad("root-scroller.html");
    RegisterMockedHttpURLLoad("root-scroller-rotation.html");
    RegisterMockedHttpURLLoad("root-scroller-iframe.html");
    RegisterMockedHttpURLLoad("root-scroller-child.html");
  }

  ~RootScrollerTest() override {
    features_backup_.Restore();
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  WebViewImpl* Initialize(const String& page_name) {
    return InitializeInternal(base_url_ + page_name);
  }

  WebViewImpl* Initialize() { return InitializeInternal("about:blank"); }

  static void ConfigureSettings(WebSettings* settings) {
    settings->SetJavaScriptEnabled(true);
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        settings);
  }

  void RegisterMockedHttpURLLoad(const String& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString(base_url_), test::CoreTestDataPath(), WebString(file_name));
  }

  void ExecuteScript(const WebString& code) {
    ExecuteScript(code, *MainWebFrame());
  }

  void ExecuteScript(const WebString& code, WebLocalFrame& frame) {
    frame.ExecuteScript(WebScriptSource(code));
    frame.View()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
    RunPendingTasks();
  }

  WebViewImpl* GetWebView() const { return helper_->GetWebView(); }

  Page& GetPage() const { return *GetWebView()->GetPage(); }

  PaintLayerScrollableArea* GetScrollableArea(const Element& element) const {
    return To<LayoutBoxModelObject>(element.GetLayoutObject())
        ->GetScrollableArea();
  }

  LocalFrame* MainFrame() const {
    return GetWebView()->MainFrameImpl()->GetFrame();
  }

  WebLocalFrame* MainWebFrame() const { return GetWebView()->MainFrameImpl(); }

  LocalFrameView* MainFrameView() const {
    return GetWebView()->MainFrameImpl()->GetFrame()->View();
  }

  VisualViewport& GetVisualViewport() const {
    return GetPage().GetVisualViewport();
  }

  BrowserControls& GetBrowserControls() const {
    return GetPage().GetBrowserControls();
  }

  Node* EffectiveRootScroller(Document* doc) const {
    return &doc->GetRootScrollerController().EffectiveRootScroller();
  }

  WebGestureEvent GenerateTouchGestureEvent(WebInputEvent::Type type,
                                            int delta_x = 0,
                                            int delta_y = 0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          WebGestureDevice::kTouchscreen);
    event.SetPositionInWidget(gfx::PointF(100, 100));
    if (type == WebInputEvent::Type::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = delta_x;
      event.data.scroll_update.delta_y = delta_y;
    } else if (type == WebInputEvent::Type::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = delta_x;
      event.data.scroll_begin.delta_y_hint = delta_y;
    }
    return event;
  }

  void SetCreateWebFrameWidgetCallback(
      const frame_test_helpers::CreateTestWebFrameWidgetCallback&
          create_widget_callback) {
    create_widget_callback_ = create_widget_callback;
  }

  bool UsesCompositedScrolling(
      const PaintLayerScrollableArea* scrollable_area) {
    auto* property_trees =
        MainFrameView()->RootCcLayer()->layer_tree_host()->property_trees();
    auto* scroll_node =
        property_trees->scroll_tree_mutable().FindNodeFromElementId(
            scrollable_area->GetScrollElementId());
    return scroll_node->is_composited;
  }

 protected:
  WebViewImpl* InitializeInternal(const String& url) {
    helper_ = std::make_unique<frame_test_helpers::WebViewHelper>(
        create_widget_callback_);

    helper_->InitializeAndLoad(url.Utf8(), nullptr, nullptr,
                               &ConfigureSettings);

    // Initialize browser controls to be shown.
    gfx::Size viewport_size = gfx::Size(400, 400);
    GetWebView()->ResizeWithBrowserControls(viewport_size, 50, 60, true);
    GetWebView()->GetBrowserControls().SetShownRatio(1, 1);
    helper_->GetMainFrameWidget()->UpdateCompositorViewportRect(
        gfx::Rect(viewport_size));

    UpdateAllLifecyclePhases(MainFrameView());

    return GetWebView();
  }

  void UpdateAllLifecyclePhases(LocalFrameView* view) {
    view->UpdateAllLifecyclePhasesForTest();
  }

  test::TaskEnvironment task_environment_;
  String base_url_;
  frame_test_helpers::CreateTestWebFrameWidgetCallback create_widget_callback_;
  std::unique_ptr<frame_test_helpers::WebViewHelper> helper_;
  RuntimeEnabledFeatures::Backup features_backup_;
};

// Test that the document Node should be the default effective root scroller.
TEST_F(RootScrollerTest, TestDefaultRootScroller) {
  Initialize("overflow-scrolling.html");

  EXPECT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));
}

// Make sure that replacing the documentElement doesn't change the effective
// root scroller when no root scroller is set.
TEST_F(RootScrollerTest, defaultEffectiveRootScrollerIsDocumentNode) {
  Initialize("overflow-scrolling.html");

  Document* document = MainFrame()->GetDocument();
  Element* iframe = document->CreateRawElement(html_names::kIFrameTag);

  EXPECT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));

  // Replace the documentElement with the iframe. The effectiveRootScroller
  // should remain the same.
  HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>> nodes;
  nodes.push_back(
      MakeGarbageCollected<V8UnionNodeOrStringOrTrustedScript>(iframe));
  document->documentElement()->replaceWith(nodes, ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhases(MainFrameView());

  EXPECT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));
}

// Tests that a DIV which becomes the implicit root scroller will properly
// control url bar and bottom bar hiding and overscroll.
TEST_F(RootScrollerTest, BrowserControlsAndOverscroll) {
  Initialize("root-scroller.html");
  UpdateAllLifecyclePhases(MainFrameView());

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  // Content is 1000x1000, WebView is 400x400 but hiding the 50px top controls
  // and the 60px bottom controls makes it 400x510 so max scroll is 490px.
  double maximum_scroll = 490;

  auto* widget = helper_->GetMainFrameWidget();
  auto* layer_tree_host = helper_->GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));
  {
    // Scrolling over the #container DIV should cause the browser controls to
    // hide.
    EXPECT_FLOAT_EQ(1, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(1, GetBrowserControls().BottomShownRatio());
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, 0,
                                  -GetBrowserControls().TopHeight()));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_FLOAT_EQ(0, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(0, GetBrowserControls().BottomShownRatio());
  }

  {
    // Make sure we're actually scrolling the DIV and not the LocalFrameView.
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -100));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_FLOAT_EQ(100, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());
  }

  {
    // Scroll 50 pixels past the end. Ensure we report the 50 pixels as
    // overscroll.
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -440));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_TRUE(
        widget->last_overscroll()->Equals(mojom::blink::DidOverscrollParams(
            gfx::Vector2dF(0, 50), gfx::Vector2dF(0, 50), gfx::Vector2dF(),
            gfx::PointF(100, 100), cc::OverscrollBehavior())));

    EXPECT_FLOAT_EQ(maximum_scroll, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());
  }

  {
    // Continue the gesture overscroll.
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -20));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_TRUE(
        widget->last_overscroll()->Equals(mojom::blink::DidOverscrollParams(
            gfx::Vector2dF(0, 70), gfx::Vector2dF(0, 20), gfx::Vector2dF(),
            gfx::PointF(100, 100), cc::OverscrollBehavior())));

    EXPECT_FLOAT_EQ(maximum_scroll, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());
  }

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  {
    // Make sure a new gesture scroll still won't scroll the frameview and
    // overscrolls.
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));

    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -30));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_TRUE(
        widget->last_overscroll()->Equals(mojom::blink::DidOverscrollParams(
            gfx::Vector2dF(0, 30), gfx::Vector2dF(0, 30), gfx::Vector2dF(),
            gfx::PointF(100, 100), cc::OverscrollBehavior())));

    EXPECT_FLOAT_EQ(maximum_scroll, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());

    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());
  }

  {
    // Scrolling up should show the browser controls.
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));

    EXPECT_FLOAT_EQ(0, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(0, GetBrowserControls().BottomShownRatio());

    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, 30));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_FLOAT_EQ(0.6, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(0.6, GetBrowserControls().BottomShownRatio());

    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
  }

  // Reset manually to avoid lifetime issues with custom WebViewClient.
  helper_->Reset();
}

// Tests that removing the element that is the root scroller from the DOM tree
// changes the effective root scroller.
TEST_F(RootScrollerTest, TestRemoveRootScrollerFromDom) {
  Initialize("root-scroller.html");

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  UpdateAllLifecyclePhases(MainFrameView());

  EXPECT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  MainFrame()->GetDocument()->body()->RemoveChild(container);
  UpdateAllLifecyclePhases(MainFrameView());

  EXPECT_NE(container, EffectiveRootScroller(MainFrame()->GetDocument()));
}

// Test that the effective root scroller resets to the document Node when the
// current root scroller element becomes invalid as a scroller.
TEST_F(RootScrollerTest, TestRootScrollerBecomesInvalid) {
  Initialize("root-scroller.html");

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));

  {
    EXPECT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

    ExecuteScript(
        "document.querySelector('#container').style.display = 'inline'");
    UpdateAllLifecyclePhases(MainFrameView());

    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
  }

  ExecuteScript("document.querySelector('#container').style.display = 'block'");
  UpdateAllLifecyclePhases(MainFrameView());

  {
    EXPECT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

    ExecuteScript("document.querySelector('#container').style.width = '98%'");
    UpdateAllLifecyclePhases(MainFrameView());

    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
  }
}

// Ensures that disconnecting the element currently set as the root scroller
// recomputes the effective root scroller, before a lifecycle update.
TEST_F(RootScrollerTest, RemoveCurrentRootScroller) {
  Initialize();

  WebURL base_url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                     R"HTML(
                                     <!DOCTYPE html>
                                     <style>
                                       body,html {
                                         width: 100%;
                                         height: 100%;
                                         margin: 0px;
                                       }
                                       #container {
                                         width: 100%;
                                         height: 100%;
                                         position: absolute;
                                         overflow: auto;
                                       }
                                       #spacer {
                                         width: 200vw;
                                         height: 200vh;
                                       }
                                     </style>
                                     <div id='container'>
                                       <div id='spacer'></diiv>
                                     </div>)HTML",
                                     base_url);

  RootScrollerController& controller =
      MainFrame()->GetDocument()->GetRootScrollerController();
  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  UpdateAllLifecyclePhases(MainFrameView());
  ASSERT_EQ(container, controller.EffectiveRootScroller());

  // Remove the div from the document. It should be demoted from the effective
  // root scroller. The effective will fallback to the document Node.
  {
    MainFrame()->GetDocument()->body()->setTextContent("");
    EXPECT_EQ(MainFrame()->GetDocument(), controller.EffectiveRootScroller());
  }
}

// Ensures that the root scroller always gets composited with scrolling layers.
// This is necessary since we replace the Frame scrolling layers in CC as the
// OuterViewport, we need something to replace them with.
TEST_F(RootScrollerTest, AlwaysCreateCompositedScrollingLayers) {
  Initialize();
  GetPage().GetSettings().SetPreferCompositingToLCDTextForTesting(false);

  WebURL base_url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                     R"HTML(
      <!DOCTYPE html>
      <style>
        body,html {
          width: 100%;
          height: 100%;
          margin: 0px;
        }
        #container {
          width: 98%;
          height: 100%;
          position: absolute;
          overflow: auto;
        }
        #spacer {
          width: 200vw;
          height: 200vh;
        }
      </style>
      <div id='container'>
        <div id='spacer'></div>
      </div>)HTML",
                                     base_url);

  GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 400), 50, 0, true);
  UpdateAllLifecyclePhases(MainFrameView());

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));

  PaintLayerScrollableArea* container_scroller = GetScrollableArea(*container);
  ASSERT_FALSE(UsesCompositedScrolling(container_scroller));

  ExecuteScript("document.querySelector('#container').style.width = '100%'");
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  ASSERT_TRUE(UsesCompositedScrolling(container_scroller));

  ExecuteScript("document.querySelector('#container').style.width = '98%'");
  ASSERT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));

  EXPECT_FALSE(UsesCompositedScrolling(container_scroller));
}

// Make sure that if an effective root scroller becomes a remote frame, it's
// immediately demoted.
TEST_F(RootScrollerTest, IFrameSwapToRemote) {
  Initialize("root-scroller-iframe.html");
  Element* iframe =
      MainFrame()->GetDocument()->getElementById(AtomicString("iframe"));

  ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));

  // Swap in a remote frame. Make sure we revert back to the document.
  {
    frame_test_helpers::SwapRemoteFrame(MainWebFrame()->FirstChild(),
                                        frame_test_helpers::CreateRemote());
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
    GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 450), 50, 0, false);
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
  }
}

// Tests that removing the root scroller element from the DOM resets the
// effective root scroller without waiting for any lifecycle events.
TEST_F(RootScrollerTest, RemoveRootScrollerFromDom) {
  Initialize("root-scroller-iframe.html");

  {
    auto* iframe = To<HTMLFrameOwnerElement>(
        MainFrame()->GetDocument()->getElementById(AtomicString("iframe")));

    ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));

    iframe->contentDocument()->body()->setInnerHTML("");

    // If the root scroller wasn't updated by the DOM removal above, this
    // will touch the disposed root scroller's ScrollableArea.
    MainFrameView()->GetRootFrameViewport()->ServiceScrollAnimations(0);
  }
}

// Tests that we still have a global root scroller layer when the HTML element
// has no layout object. crbug.com/637036.
TEST_F(RootScrollerTest, DocumentElementHasNoLayoutObject) {
  Initialize("overflow-scrolling.html");

  // There's no rootScroller set on this page so we should default to the
  // document Node, which means we should use the layout viewport. Ensure this
  // happens even if the <html> element has no LayoutObject.
  ExecuteScript("document.documentElement.style.display = 'none';");

  const TopDocumentRootScrollerController& global_controller =
      MainFrame()->GetDocument()->GetPage()->GlobalRootScrollerController();

  EXPECT_EQ(MainFrame()->GetDocument(), global_controller.GlobalRootScroller());
}

// On Android, the main scrollbars are owned by the visual viewport and the
// LocalFrameView's disabled. This functionality should extend to a rootScroller
// that isn't the main LocalFrameView.
TEST_F(RootScrollerTest, UseVisualViewportScrollbars) {
  Initialize("root-scroller.html");

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  ScrollableArea* container_scroller = GetScrollableArea(*container);
  EXPECT_FALSE(container_scroller->HorizontalScrollbar());
  EXPECT_FALSE(container_scroller->VerticalScrollbar());
  EXPECT_GT(container_scroller->MaximumScrollOffset().x(), 0);
  EXPECT_GT(container_scroller->MaximumScrollOffset().y(), 0);
}

// On Android, the main scrollbars are owned by the visual viewport and the
// LocalFrameView's disabled. This functionality should extend to a rootScroller
// that's a nested iframe.
TEST_F(RootScrollerTest, UseVisualViewportScrollbarsIframe) {
  Initialize("root-scroller-iframe.html");

  Element* iframe =
      MainFrame()->GetDocument()->getElementById(AtomicString("iframe"));
  auto* child_frame =
      To<LocalFrame>(To<HTMLFrameOwnerElement>(iframe)->ContentFrame());

  ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));
  UpdateAllLifecyclePhases(MainFrameView());

  ScrollableArea* container_scroller = child_frame->View()->LayoutViewport();

  EXPECT_FALSE(container_scroller->HorizontalScrollbar());
  EXPECT_FALSE(container_scroller->VerticalScrollbar());
  EXPECT_GT(container_scroller->MaximumScrollOffset().x(), 0);
  EXPECT_GT(container_scroller->MaximumScrollOffset().y(), 0);
}

TEST_F(RootScrollerTest, TopControlsAdjustmentAppliedToRootScroller) {
  Initialize();

  WebURL base_url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body, html {"
                                     "    width: 100%;"
                                     "    height: 100%;"
                                     "    margin: 0px;"
                                     "  }"
                                     "  #container {"
Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/root_scroller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_hit_test_result.h"
#include "third_party/blink/public/web/web_remote_frame.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_node_string_trustedscript.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/dom_visual_viewport.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using blink::test::RunPendingTasks;
using testing::Mock;

namespace blink {

namespace {

class RootScrollerTest : public testing::Test,
                         private ScopedImplicitRootScrollerForTest {
 public:
  RootScrollerTest()
      : ScopedImplicitRootScrollerForTest(true),
        base_url_("http://www.test.com/") {
    RegisterMockedHttpURLLoad("overflow-scrolling.html");
    RegisterMockedHttpURLLoad("root-scroller.html");
    RegisterMockedHttpURLLoad("root-scroller-rotation.html");
    RegisterMockedHttpURLLoad("root-scroller-iframe.html");
    RegisterMockedHttpURLLoad("root-scroller-child.html");
  }

  ~RootScrollerTest() override {
    features_backup_.Restore();
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  WebViewImpl* Initialize(const String& page_name) {
    return InitializeInternal(base_url_ + page_name);
  }

  WebViewImpl* Initialize() { return InitializeInternal("about:blank"); }

  static void ConfigureSettings(WebSettings* settings) {
    settings->SetJavaScriptEnabled(true);
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        settings);
  }

  void RegisterMockedHttpURLLoad(const String& file_name) {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |helper_|.
    url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString(base_url_), test::CoreTestDataPath(), WebString(file_name));
  }

  void ExecuteScript(const WebString& code) {
    ExecuteScript(code, *MainWebFrame());
  }

  void ExecuteScript(const WebString& code, WebLocalFrame& frame) {
    frame.ExecuteScript(WebScriptSource(code));
    frame.View()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
    RunPendingTasks();
  }

  WebViewImpl* GetWebView() const { return helper_->GetWebView(); }

  Page& GetPage() const { return *GetWebView()->GetPage(); }

  PaintLayerScrollableArea* GetScrollableArea(const Element& element) const {
    return To<LayoutBoxModelObject>(element.GetLayoutObject())
        ->GetScrollableArea();
  }

  LocalFrame* MainFrame() const {
    return GetWebView()->MainFrameImpl()->GetFrame();
  }

  WebLocalFrame* MainWebFrame() const { return GetWebView()->MainFrameImpl(); }

  LocalFrameView* MainFrameView() const {
    return GetWebView()->MainFrameImpl()->GetFrame()->View();
  }

  VisualViewport& GetVisualViewport() const {
    return GetPage().GetVisualViewport();
  }

  BrowserControls& GetBrowserControls() const {
    return GetPage().GetBrowserControls();
  }

  Node* EffectiveRootScroller(Document* doc) const {
    return &doc->GetRootScrollerController().EffectiveRootScroller();
  }

  WebGestureEvent GenerateTouchGestureEvent(WebInputEvent::Type type,
                                            int delta_x = 0,
                                            int delta_y = 0) {
    WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                          WebInputEvent::GetStaticTimeStampForTests(),
                          WebGestureDevice::kTouchscreen);
    event.SetPositionInWidget(gfx::PointF(100, 100));
    if (type == WebInputEvent::Type::kGestureScrollUpdate) {
      event.data.scroll_update.delta_x = delta_x;
      event.data.scroll_update.delta_y = delta_y;
    } else if (type == WebInputEvent::Type::kGestureScrollBegin) {
      event.data.scroll_begin.delta_x_hint = delta_x;
      event.data.scroll_begin.delta_y_hint = delta_y;
    }
    return event;
  }

  void SetCreateWebFrameWidgetCallback(
      const frame_test_helpers::CreateTestWebFrameWidgetCallback&
          create_widget_callback) {
    create_widget_callback_ = create_widget_callback;
  }

  bool UsesCompositedScrolling(
      const PaintLayerScrollableArea* scrollable_area) {
    auto* property_trees =
        MainFrameView()->RootCcLayer()->layer_tree_host()->property_trees();
    auto* scroll_node =
        property_trees->scroll_tree_mutable().FindNodeFromElementId(
            scrollable_area->GetScrollElementId());
    return scroll_node->is_composited;
  }

 protected:
  WebViewImpl* InitializeInternal(const String& url) {
    helper_ = std::make_unique<frame_test_helpers::WebViewHelper>(
        create_widget_callback_);

    helper_->InitializeAndLoad(url.Utf8(), nullptr, nullptr,
                               &ConfigureSettings);

    // Initialize browser controls to be shown.
    gfx::Size viewport_size = gfx::Size(400, 400);
    GetWebView()->ResizeWithBrowserControls(viewport_size, 50, 60, true);
    GetWebView()->GetBrowserControls().SetShownRatio(1, 1);
    helper_->GetMainFrameWidget()->UpdateCompositorViewportRect(
        gfx::Rect(viewport_size));

    UpdateAllLifecyclePhases(MainFrameView());

    return GetWebView();
  }

  void UpdateAllLifecyclePhases(LocalFrameView* view) {
    view->UpdateAllLifecyclePhasesForTest();
  }

  test::TaskEnvironment task_environment_;
  String base_url_;
  frame_test_helpers::CreateTestWebFrameWidgetCallback create_widget_callback_;
  std::unique_ptr<frame_test_helpers::WebViewHelper> helper_;
  RuntimeEnabledFeatures::Backup features_backup_;
};

// Test that the document Node should be the default effective root scroller.
TEST_F(RootScrollerTest, TestDefaultRootScroller) {
  Initialize("overflow-scrolling.html");

  EXPECT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));
}

// Make sure that replacing the documentElement doesn't change the effective
// root scroller when no root scroller is set.
TEST_F(RootScrollerTest, defaultEffectiveRootScrollerIsDocumentNode) {
  Initialize("overflow-scrolling.html");

  Document* document = MainFrame()->GetDocument();
  Element* iframe = document->CreateRawElement(html_names::kIFrameTag);

  EXPECT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));

  // Replace the documentElement with the iframe. The effectiveRootScroller
  // should remain the same.
  HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>> nodes;
  nodes.push_back(
      MakeGarbageCollected<V8UnionNodeOrStringOrTrustedScript>(iframe));
  document->documentElement()->replaceWith(nodes, ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhases(MainFrameView());

  EXPECT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));
}

// Tests that a DIV which becomes the implicit root scroller will properly
// control url bar and bottom bar hiding and overscroll.
TEST_F(RootScrollerTest, BrowserControlsAndOverscroll) {
  Initialize("root-scroller.html");
  UpdateAllLifecyclePhases(MainFrameView());

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  // Content is 1000x1000, WebView is 400x400 but hiding the 50px top controls
  // and the 60px bottom controls makes it 400x510 so max scroll is 490px.
  double maximum_scroll = 490;

  auto* widget = helper_->GetMainFrameWidget();
  auto* layer_tree_host = helper_->GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));
  {
    // Scrolling over the #container DIV should cause the browser controls to
    // hide.
    EXPECT_FLOAT_EQ(1, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(1, GetBrowserControls().BottomShownRatio());
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, 0,
                                  -GetBrowserControls().TopHeight()));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_FLOAT_EQ(0, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(0, GetBrowserControls().BottomShownRatio());
  }

  {
    // Make sure we're actually scrolling the DIV and not the LocalFrameView.
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -100));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_FLOAT_EQ(100, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());
  }

  {
    // Scroll 50 pixels past the end. Ensure we report the 50 pixels as
    // overscroll.
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -440));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_TRUE(
        widget->last_overscroll()->Equals(mojom::blink::DidOverscrollParams(
            gfx::Vector2dF(0, 50), gfx::Vector2dF(0, 50), gfx::Vector2dF(),
            gfx::PointF(100, 100), cc::OverscrollBehavior())));

    EXPECT_FLOAT_EQ(maximum_scroll, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());
  }

  {
    // Continue the gesture overscroll.
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -20));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_TRUE(
        widget->last_overscroll()->Equals(mojom::blink::DidOverscrollParams(
            gfx::Vector2dF(0, 70), gfx::Vector2dF(0, 20), gfx::Vector2dF(),
            gfx::PointF(100, 100), cc::OverscrollBehavior())));

    EXPECT_FLOAT_EQ(maximum_scroll, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());
  }

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  {
    // Make sure a new gesture scroll still won't scroll the frameview and
    // overscrolls.
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));

    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, -30));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_TRUE(
        widget->last_overscroll()->Equals(mojom::blink::DidOverscrollParams(
            gfx::Vector2dF(0, 30), gfx::Vector2dF(0, 30), gfx::Vector2dF(),
            gfx::PointF(100, 100), cc::OverscrollBehavior())));

    EXPECT_FLOAT_EQ(maximum_scroll, container->scrollTop());
    EXPECT_FLOAT_EQ(0,
                    MainFrameView()->LayoutViewport()->GetScrollOffset().y());

    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());
  }

  {
    // Scrolling up should show the browser controls.
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));

    EXPECT_FLOAT_EQ(0, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(0, GetBrowserControls().BottomShownRatio());

    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, 0, 30));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    EXPECT_FLOAT_EQ(0.6, GetBrowserControls().TopShownRatio());
    EXPECT_FLOAT_EQ(0.6, GetBrowserControls().BottomShownRatio());

    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
  }

  // Reset manually to avoid lifetime issues with custom WebViewClient.
  helper_->Reset();
}

// Tests that removing the element that is the root scroller from the DOM tree
// changes the effective root scroller.
TEST_F(RootScrollerTest, TestRemoveRootScrollerFromDom) {
  Initialize("root-scroller.html");

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  UpdateAllLifecyclePhases(MainFrameView());

  EXPECT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  MainFrame()->GetDocument()->body()->RemoveChild(container);
  UpdateAllLifecyclePhases(MainFrameView());

  EXPECT_NE(container, EffectiveRootScroller(MainFrame()->GetDocument()));
}

// Test that the effective root scroller resets to the document Node when the
// current root scroller element becomes invalid as a scroller.
TEST_F(RootScrollerTest, TestRootScrollerBecomesInvalid) {
  Initialize("root-scroller.html");

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));

  {
    EXPECT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

    ExecuteScript(
        "document.querySelector('#container').style.display = 'inline'");
    UpdateAllLifecyclePhases(MainFrameView());

    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
  }

  ExecuteScript("document.querySelector('#container').style.display = 'block'");
  UpdateAllLifecyclePhases(MainFrameView());

  {
    EXPECT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

    ExecuteScript("document.querySelector('#container').style.width = '98%'");
    UpdateAllLifecyclePhases(MainFrameView());

    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
  }
}

// Ensures that disconnecting the element currently set as the root scroller
// recomputes the effective root scroller, before a lifecycle update.
TEST_F(RootScrollerTest, RemoveCurrentRootScroller) {
  Initialize();

  WebURL base_url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                     R"HTML(
                                     <!DOCTYPE html>
                                     <style>
                                       body,html {
                                         width: 100%;
                                         height: 100%;
                                         margin: 0px;
                                       }
                                       #container {
                                         width: 100%;
                                         height: 100%;
                                         position: absolute;
                                         overflow: auto;
                                       }
                                       #spacer {
                                         width: 200vw;
                                         height: 200vh;
                                       }
                                     </style>
                                     <div id='container'>
                                       <div id='spacer'></diiv>
                                     </div>)HTML",
                                     base_url);

  RootScrollerController& controller =
      MainFrame()->GetDocument()->GetRootScrollerController();
  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  UpdateAllLifecyclePhases(MainFrameView());
  ASSERT_EQ(container, controller.EffectiveRootScroller());

  // Remove the div from the document. It should be demoted from the effective
  // root scroller. The effective will fallback to the document Node.
  {
    MainFrame()->GetDocument()->body()->setTextContent("");
    EXPECT_EQ(MainFrame()->GetDocument(), controller.EffectiveRootScroller());
  }
}

// Ensures that the root scroller always gets composited with scrolling layers.
// This is necessary since we replace the Frame scrolling layers in CC as the
// OuterViewport, we need something to replace them with.
TEST_F(RootScrollerTest, AlwaysCreateCompositedScrollingLayers) {
  Initialize();
  GetPage().GetSettings().SetPreferCompositingToLCDTextForTesting(false);

  WebURL base_url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                     R"HTML(
      <!DOCTYPE html>
      <style>
        body,html {
          width: 100%;
          height: 100%;
          margin: 0px;
        }
        #container {
          width: 98%;
          height: 100%;
          position: absolute;
          overflow: auto;
        }
        #spacer {
          width: 200vw;
          height: 200vh;
        }
      </style>
      <div id='container'>
        <div id='spacer'></div>
      </div>)HTML",
                                     base_url);

  GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 400), 50, 0, true);
  UpdateAllLifecyclePhases(MainFrameView());

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));

  PaintLayerScrollableArea* container_scroller = GetScrollableArea(*container);
  ASSERT_FALSE(UsesCompositedScrolling(container_scroller));

  ExecuteScript("document.querySelector('#container').style.width = '100%'");
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  ASSERT_TRUE(UsesCompositedScrolling(container_scroller));

  ExecuteScript("document.querySelector('#container').style.width = '98%'");
  ASSERT_EQ(MainFrame()->GetDocument(),
            EffectiveRootScroller(MainFrame()->GetDocument()));

  EXPECT_FALSE(UsesCompositedScrolling(container_scroller));
}

// Make sure that if an effective root scroller becomes a remote frame, it's
// immediately demoted.
TEST_F(RootScrollerTest, IFrameSwapToRemote) {
  Initialize("root-scroller-iframe.html");
  Element* iframe =
      MainFrame()->GetDocument()->getElementById(AtomicString("iframe"));

  ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));

  // Swap in a remote frame. Make sure we revert back to the document.
  {
    frame_test_helpers::SwapRemoteFrame(MainWebFrame()->FirstChild(),
                                        frame_test_helpers::CreateRemote());
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
    GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 450), 50, 0, false);
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
  }
}

// Tests that removing the root scroller element from the DOM resets the
// effective root scroller without waiting for any lifecycle events.
TEST_F(RootScrollerTest, RemoveRootScrollerFromDom) {
  Initialize("root-scroller-iframe.html");

  {
    auto* iframe = To<HTMLFrameOwnerElement>(
        MainFrame()->GetDocument()->getElementById(AtomicString("iframe")));

    ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));

    iframe->contentDocument()->body()->setInnerHTML("");

    // If the root scroller wasn't updated by the DOM removal above, this
    // will touch the disposed root scroller's ScrollableArea.
    MainFrameView()->GetRootFrameViewport()->ServiceScrollAnimations(0);
  }
}

// Tests that we still have a global root scroller layer when the HTML element
// has no layout object. crbug.com/637036.
TEST_F(RootScrollerTest, DocumentElementHasNoLayoutObject) {
  Initialize("overflow-scrolling.html");

  // There's no rootScroller set on this page so we should default to the
  // document Node, which means we should use the layout viewport. Ensure this
  // happens even if the <html> element has no LayoutObject.
  ExecuteScript("document.documentElement.style.display = 'none';");

  const TopDocumentRootScrollerController& global_controller =
      MainFrame()->GetDocument()->GetPage()->GlobalRootScrollerController();

  EXPECT_EQ(MainFrame()->GetDocument(), global_controller.GlobalRootScroller());
}

// On Android, the main scrollbars are owned by the visual viewport and the
// LocalFrameView's disabled. This functionality should extend to a rootScroller
// that isn't the main LocalFrameView.
TEST_F(RootScrollerTest, UseVisualViewportScrollbars) {
  Initialize("root-scroller.html");

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  ScrollableArea* container_scroller = GetScrollableArea(*container);
  EXPECT_FALSE(container_scroller->HorizontalScrollbar());
  EXPECT_FALSE(container_scroller->VerticalScrollbar());
  EXPECT_GT(container_scroller->MaximumScrollOffset().x(), 0);
  EXPECT_GT(container_scroller->MaximumScrollOffset().y(), 0);
}

// On Android, the main scrollbars are owned by the visual viewport and the
// LocalFrameView's disabled. This functionality should extend to a rootScroller
// that's a nested iframe.
TEST_F(RootScrollerTest, UseVisualViewportScrollbarsIframe) {
  Initialize("root-scroller-iframe.html");

  Element* iframe =
      MainFrame()->GetDocument()->getElementById(AtomicString("iframe"));
  auto* child_frame =
      To<LocalFrame>(To<HTMLFrameOwnerElement>(iframe)->ContentFrame());

  ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));
  UpdateAllLifecyclePhases(MainFrameView());

  ScrollableArea* container_scroller = child_frame->View()->LayoutViewport();

  EXPECT_FALSE(container_scroller->HorizontalScrollbar());
  EXPECT_FALSE(container_scroller->VerticalScrollbar());
  EXPECT_GT(container_scroller->MaximumScrollOffset().x(), 0);
  EXPECT_GT(container_scroller->MaximumScrollOffset().y(), 0);
}

TEST_F(RootScrollerTest, TopControlsAdjustmentAppliedToRootScroller) {
  Initialize();

  WebURL base_url = url_test_helpers::ToKURL("http://www.test.com/");
  frame_test_helpers::LoadHTMLString(GetWebView()->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body, html {"
                                     "    width: 100%;"
                                     "    height: 100%;"
                                     "    margin: 0px;"
                                     "  }"
                                     "  #container {"
                                     "    width: 100%;"
                                     "    height: 100%;"
                                     "    overflow: auto;"
                                     "  }"
                                     "</style>"
                                     "<div id='container'>"
                                     "  <div style='height:1000px'>test</div>"
                                     "</div>",
                                     base_url);

  GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 400), 50, 50, true);

  auto* widget = helper_->GetMainFrameWidget();
  auto* layer_tree_host = helper_->GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  Element* container =
      MainFrame()->GetDocument()->getElementById(AtomicString("container"));
  ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

  ScrollableArea* container_scroller = GetScrollableArea(*container);

  // Hide the top controls and scroll down maximally. We should account for the
  // change in maximum scroll offset due to the top controls hiding. That is,
  // since the controls are hidden, the "content area" is taller so the maximum
  // scroll offset should shrink.
  ASSERT_EQ(1000 - 400, container_scroller->MaximumScrollOffset().y());

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));

  ASSERT_EQ(1, GetBrowserControls().TopShownRatio());
  ASSERT_EQ(1, GetBrowserControls().BottomShownRatio());

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollUpdate, 0,
                                -GetBrowserControls().TopHeight()));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ASSERT_EQ(0, GetBrowserControls().TopShownRatio());
  ASSERT_EQ(0, GetBrowserControls().BottomShownRatio());

  // TODO(crbug.com/1364851): This should be 1000 - 500, but the main thread's
  // maximum scroll offset does not account for the hidden bottom bar.
  EXPECT_EQ(1000 - 450, container_scroller->MaximumScrollOffset().y());

  widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureScrollUpdate, 0, -3000));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  // The compositor input handler correctly accounts for both top and bottom bar
  // in the calculation of scroll bounds. This is the true maximum.
  EXPECT_EQ(1000 - 500, container_scroller->GetScrollOffset().y());

  widget->DispatchThroughCcInputHandler(
      GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 450), 50, 50, false);

  // TODO(crbug.com/1364851): This should be 1000 - 500, but the main thread's
  // maximum scroll offset does not account for the hidden bottom bar.
  EXPECT_EQ(1000 - 450, container_scroller->MaximumScrollOffset().y());
}

TEST_F(RootScrollerTest, RotationAnchoring) {
  Initialize("root-scroller-rotation.html");

  auto* widget = helper_->GetMainFrameWidget();
  auto* layer_tree_host = helper_->GetLayerTreeHost();
  ScrollableArea* container_scroller;

  {
    GetWebView()->ResizeWithBrowserControls(gfx::Size(250, 1000), 0, 0, true);
    UpdateAllLifecyclePhases(MainFrameView());

    Element* container =
        MainFrame()->GetDocument()->getElementById(AtomicString("container"));
    ASSERT_EQ(container, EffectiveRootScroller(MainFrame()->GetDocument()));

    container_scroller = GetScrollableArea(*container);
  }

  Element* target =
      MainFrame()->GetDocument()->getElementById(AtomicString("target"));

  // Zoom in and scroll the viewport so that the target is fully in the
  // viewport and the visual viewport is fully scrolled within the layout
  // viepwort.
  {
    int scroll_x = 250 * 4;
    int scroll_y = 1000 * 4;

    GetWebView()->SetPageScaleFactor(2);
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollBegin));
    widget->DispatchThroughCcInputHandler(GenerateTouchGestureEvent(
        WebInputEvent::Type::kGestureScrollUpdate, -scroll_x, -scroll_y));
    widget->DispatchThroughCcInputHandler(
        GenerateTouchGestureEvent(WebInputEvent::Type::kGestureScrollEnd));
    layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                      base::OnceClosure());

    // The visual viewport should be 1.5 screens scrolled so that the target
    // occupies the bottom quadrant of the layout viewport.
    ASSERT_EQ((250 * 3) / 2, container_scroller->GetScrollOffset().x());
    ASSERT_EQ((1000 * 3) / 2, container_scroller->GetScrollOffset().y());

    // The visual viewport should have scrolled the last half layout viewport.
    ASSERT_EQ((250) / 2, GetVisualViewport().GetScrollOffset().x());
    ASSERT_EQ((1000) / 2, GetVisualViewport().GetScrollOffset().y());
  }

  // Now do a rotation resize.
  GetWebView()->ResizeWithBrowserControls(gfx::Size(1000, 250), 50, 0, false);
  UpdateAllLifecyclePhases(MainFrameView());

  // The visual viewport should remain fully filled by the target.
  DOMRect* rect = target->GetBoundingClientRect();
  EXPECT_EQ(rect->left(), GetVisualViewport().GetScrollOffset().x());
  EXPECT_EQ(rect->top(), GetVisualViewport().GetScrollOffset().y());
}

// Tests that we don't crash if the default documentElement isn't a valid root
// scroller. This can happen in some edge cases where documentElement isn't
// <html>. crbug.com/668553.
TEST_F(RootScrollerTest, InvalidDefaultRootScroller) {
  Initialize("overflow-scrolling.html");

  Document* document = MainFrame()->GetDocument();

  Element* br = document->CreateRawElement(html_names::kBrTag);
  document->ReplaceChild(br, document->documentElement());
  UpdateAllLifecyclePhases(MainFrameView());
  Element* html = document->CreateRawElement(html_names::kHTMLTag);
  Element* body = document->CreateRawElement(html_names::kBodyTag);
  html->AppendChild(body);
  body->AppendChild(br);
  document->AppendChild(html);
  UpdateAllLifecyclePhases(MainFrameView());
}

// Makes sure that when an iframe becomes the effective root scroller, its
// FrameView stops sizing layout to the frame rect and uses its parent's layout
// size instead. This allows matching the layout size semantics of the root
// FrameView since its layout size can differ from the frame rect due to
// resizes by the URL bar.
TEST_F(RootScrollerTest, IFrameRootScrollerGetsNonFixedLayoutSize) {
  In
"""


```
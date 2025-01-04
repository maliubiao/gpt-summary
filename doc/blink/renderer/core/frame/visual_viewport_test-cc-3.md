Response:
The user wants to understand the functionality of the `visual_viewport_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippets and summarize the tests being performed. Specifically, I need to identify:

1. **Core functionalities tested**: What aspects of the visual viewport are being verified?
2. **Relationship to web technologies**: How do these tests relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical reasoning**:  Are there tests that involve specific inputs and expected outputs? If so, describe them.
4. **Common user/programming errors**: Do any tests highlight potential mistakes users or developers might make?
5. **Overall summary**:  A concise description of the file's purpose.

Let's break down the code snippets:

* **Scrollbar positioning**:  Tests the layout and positioning of scrollbar layers within the visual viewport. This involves CSS layout and how Blink renders scrollbars.
* **Auto-resize behavior**: Checks how the visual viewport handles scenarios where its height is temporarily zero, especially in auto-resize mode. This relates to browser behavior and potentially JavaScript-driven resizing.
* **Main frame swapping**: Examines the visual viewport's state when a provisional frame is committed. This tests core frame loading and lifecycle within Blink.
* **Zooming behavior during frame swaps**:  Specifically tests frame swapping scenarios that result in the page being zoomed out (common on mobile).
* **Scrolling contents size**: Verifies the size of the scrolling content layer when it's smaller than the container. This relates to viewport meta tags and CSS layout.
* **`scrollIntoView` functionality**: Tests how the visual viewport handles programmatic scrolling, particularly to fixed-position elements. This directly relates to JavaScript's `scrollIntoView()` method.
* **Device emulation**: Checks the behavior of the visual viewport when device emulation is enabled, specifically focusing on viewport offset and scaling. This is relevant to developer tools and responsive design.
* **Scrollbar painting**: Verifies that scrollbars are correctly painted, including their scaling when device emulation is active. This is about how Blink renders visual elements.
* **Direct pinch zoom updates**:  Tests if direct updates to the viewport scale and translation during pinch zooming bypass the full paint process. This is an optimization within the compositor.
* **`in_subtree_of_page_scale` property**:  Examines the value of this property on various transform nodes, ensuring correct propagation of page scale information. This is an internal detail of Blink's property trees.
* **Color scheme for scrollbars**: Checks if the visual viewport correctly uses the color scheme defined in the root element for scrollbars. This relates to the CSS `color-scheme` property.
* **Scrollbar thumb color**: Tests if the visual viewport correctly applies the `scrollbar-color` CSS property.
* **Setting location before paint**: Verifies that setting the visual viewport's location before the paint phase is correctly handled. This relates to the order of operations in the rendering pipeline.
* **Scrollbar geometry on size change**: Checks how scrollbar positions and sizes are updated when the visual viewport size changes.
* **Preferred overlay scrollbar color theme**: Tests how the visual viewport determines the overlay scrollbar color theme based on the `<meta name="color-scheme">` tag and user preferences.

Now, I can formulate the detailed answer.
This is the 4th and final part of the `visual_viewport_test.cc` file, focusing on testing various functionalities of the `VisualViewport` class in the Chromium Blink engine. Here's a breakdown of its functions and related aspects:

**Overall Function of this Part:**

This section primarily tests scenarios related to:

* **Device Emulation:** How the visual viewport behaves when device emulation settings are applied (viewport offset, scale).
* **Scrollbar Rendering and Geometry:**  Ensuring scrollbars are correctly positioned, sized, and painted, especially when device emulation is active or the viewport size changes.
* **Direct Manipulation Optimizations:** Verifying optimizations related to pinch-zoom gestures, where property updates can happen directly without a full repaint.
* **Internal Property Tree Logic:** Checking internal details about how page scale is tracked within the property trees.
* **CSS Styling of Scrollbars:** Testing how CSS properties like `color-scheme` and `scrollbar-color` affect the appearance of visual viewport scrollbars.
* **Initialization Order:**  Ensuring the visual viewport can be initialized with a specific scale and offset even before the paint phase.
* **Overlay Scrollbar Theme:** Testing how the preferred color scheme impacts the appearance of overlay scrollbars.

**Specific Functionalities and Examples:**

* **Device Emulation (`DeviceEmulation` Test):**
    * **Function:** Tests how setting viewport offset and scale through device emulation affects the visual viewport's transform and whether it triggers repaints as expected.
    * **JavaScript/HTML/CSS Relation:** Device emulation is often used by developers via browser DevTools to simulate different screen sizes and pixel densities, impacting how HTML and CSS layouts are rendered.
    * **Logical Reasoning:**
        * **Input:** Enabling device emulation with a non-zero viewport offset (e.g., `gfx::PointF(314, 159)`).
        * **Output:** Expects the visual viewport to have a translation transform applied and a repaint to be triggered.
        * **Input:** Changing the device emulation scale (e.g., to `1.5f`).
        * **Output:** Expects the visual viewport to have a scale transform applied but *not* necessarily a full repaint (as it can be optimized).
    * **User/Programming Errors:**  Developers might incorrectly assume that any change in device emulation settings always triggers a full repaint, leading to performance concerns if they unnecessarily force repaints.

* **Scrollbar Painting with Device Emulation (`PaintScrollbar` Test):**
    * **Function:** Verifies that scrollbars are painted correctly and their transform is adjusted when device emulation scaling is active.
    * **JavaScript/HTML/CSS Relation:**  Scrollbars are a fundamental part of the browser UI for navigating content that overflows, and their appearance can be influenced by CSS. Device emulation impacts how these UI elements are rendered.
    * **Logical Reasoning:**
        * **Input:** Loading an HTML page with overflowing content and then enabling device emulation with a scale factor (e.g., `1.5f`).
        * **Output:** Expects the scrollbar layer to have a scaling transform applied in its property tree, while its screen space transform remains unaffected by the device emulation scale (as it's in the device's coordinate space). The test also verifies basic scrollbar properties like size and position.

* **Direct Pinch Zoom Update (`DirectPinchZoomPropertyUpdate` Test):**
    * **Function:** Tests an optimization where pinch-zoom gestures can directly update the visual viewport's scale and translation properties without requiring a full PaintArtifactCompositor update.
    * **JavaScript/HTML/CSS Relation:** This is related to how the browser handles user interactions (pinch-zoom) and optimizes rendering performance.
    * **Logical Reasoning:**
        * **Input:**  Navigating to a page, setting an initial visual viewport scale and offset, and then changing the scale and offset again.
        * **Output:** Expects that the `PaintArtifactCompositor` does *not* need an update after the direct manipulation.

* **Tracking Page Scale in Property Trees (`InSubtreeOfPageScale` Test):**
    * **Function:**  Verifies the correct setting of the `in_subtree_of_page_scale` flag in the transform property tree nodes, ensuring that nodes below the page scale transform are correctly identified.
    * **JavaScript/HTML/CSS Relation:** This is an internal mechanism within Blink's rendering pipeline for managing page zoom.
    * **Logical Reasoning:**  The test checks that the page scale transform node itself and its ancestors do *not* have `IsInSubtreeOfPageScale` set, while its descendants do.

* **CSS Color Scheme for Scrollbars (`UsedColorSchemeFromRootElement` Test):**
    * **Function:** Tests that the visual viewport uses the `color-scheme` property defined in the root `<html>` element to determine the scrollbar's color scheme.
    * **JavaScript/HTML/CSS Relation:** Directly tests the interaction between a CSS property and the browser's rendering of UI elements.
    * **Logical Reasoning:**
        * **Input:** Loading an HTML page with `<html style="color-scheme: dark">`.
        * **Output:** Expects the visual viewport's `UsedColorSchemeScrollbars()` to return `ColorScheme::kDark`.

* **CSS Scrollbar Thumb Color (`ScrollbarThumbColorFromRootElement` Test):**
    * **Function:** Checks if the visual viewport correctly applies the `scrollbar-color` CSS property to set the scrollbar thumb color.
    * **JavaScript/HTML/CSS Relation:**  Tests the application of a specific CSS property for styling scrollbars.
    * **Logical Reasoning:**
        * **Input:** Loading an HTML page with `<html style="scrollbar-color: rgb(255 0 0) transparent">`.
        * **Output:** Expects the visual viewport's `CSSScrollbarThumbColor()` to return the corresponding `blink::Color`.

* **Setting Location Before Paint (`SetLocationBeforePrePaint` Test):**
    * **Function:** Ensures that setting the visual viewport's scale and location before the initial paint (e.g., during frame restoration) is handled correctly.
    * **JavaScript/HTML/CSS Relation:** This is relevant to how the browser restores the scroll and zoom state when navigating back or reloading a page.
    * **Logical Reasoning:**
        * **Input:** Setting the scale and location of the visual viewport before the scrolling layer is created.
        * **Output:** Expects that the scrolling layer, once created, will have the correct scroll offset applied.

* **Scrollbar Geometry on Size Change (`ScrollbarGeometryOnSizeChange` Test):**
    * **Function:** Tests that the position and size of the scrollbar layers are updated correctly when the visual viewport's size changes (e.g., due to browser controls appearing or disappearing).
    * **JavaScript/HTML/CSS Relation:** This relates to how the browser dynamically adjusts the layout when the available viewport changes.
    * **Logical Reasoning:**
        * **Input:** Resizing the `WebView` (simulating changes in available screen space).
        * **Output:** Expects the `offset_to_transform_parent` and `bounds` of the horizontal and vertical scrollbar layers to be adjusted according to the new viewport size.

* **Preferred Overlay Scrollbar Color Theme (`PreferredOverlayScrollbarColorTheme` Test):**
    * **Function:**  Tests how the visual viewport determines the color scheme for overlay scrollbars based on the `<meta name="color-scheme">` tag and the user's preferred color scheme.
    * **JavaScript/HTML/CSS Relation:** This relates to the `color-scheme` meta tag and how browsers adapt their UI to user preferences.
    * **Logical Reasoning:**
        * **Input:** Loading an HTML page with `<meta name="color-scheme" content="light dark">` and setting the preferred color scheme to "dark".
        * **Output:** Expects the visual viewport's `GetOverlayScrollbarColorScheme()` to return `ColorScheme::kDark`.

**Common User/Programming Errors Highlighted:**

While these are unit tests and not directly testing user errors, they implicitly address potential programming errors within the Blink engine itself. For example:

* **Incorrectly calculating scrollbar positions:** The `ScrollbarGeometryOnSizeChange` test prevents errors where scrollbars might be placed outside the visible area after a resize.
* **Missing repaints after device emulation changes:** The `DeviceEmulation` test ensures that necessary repaints are triggered when the viewport offset changes, preventing rendering inconsistencies.
* **Inefficient repainting:** The `DirectPinchZoomPropertyUpdate` test verifies an optimization that avoids unnecessary full repaints during user interactions.
* **Incorrectly applying CSS scrollbar styles:** The `UsedColorSchemeFromRootElement` and `ScrollbarThumbColorFromRootElement` tests ensure that CSS properties related to scrollbar styling are correctly implemented.

**Summary of the File's Functionality:**

The `visual_viewport_test.cc` file comprehensively tests the behavior and internal logic of the `VisualViewport` class in the Chromium Blink engine. It covers various aspects, including how the visual viewport interacts with device emulation, renders scrollbars, optimizes for direct manipulations like pinch-zoom, manages internal property trees related to scaling, and responds to CSS styling for scrollbars. These tests are crucial for ensuring the correct and efficient rendering of web pages across different devices and user interactions.

Prompt: 
```
这是目录为blink/renderer/core/frame/visual_viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
                ->effect_tree()
                .FindNodeFromElementId((visual_viewport.GetScrollbarElementId(
                    ScrollbarOrientation::kVerticalScrollbar)))
                ->id);
  EXPECT_EQ(vertical_scrollbar->offset_to_transform_parent(),
            gfx::Vector2dF(400 - scrollbar_thickness, 0));

  EXPECT_EQ(horizontal_scrollbar->effect_tree_index(),
            horizontal_scrollbar->layer_tree_host()
                ->property_trees()
                ->effect_tree()
                .FindNodeFromElementId(visual_viewport.GetScrollbarElementId(
                    ScrollbarOrientation::kHorizontalScrollbar))
                ->id);
  EXPECT_EQ(horizontal_scrollbar->offset_to_transform_parent(),
            gfx::Vector2dF(0, 400 - scrollbar_thickness));

  EXPECT_EQ(GetEffectNode(vertical_scrollbar)->parent_id,
            GetEffectNode(horizontal_scrollbar)->parent_id);
}

// Make sure we don't crash when the visual viewport's height is 0. This can
// happen transiently in autoresize mode and cause a crash. This test passes if
// it doesn't crash.
TEST_P(VisualViewportTest, AutoResizeNoHeightUsesMinimumHeight) {
  InitializeWithDesktopSettings();
  WebView()->ResizeWithBrowserControls(gfx::Size(0, 0), 0, 0, false);
  UpdateAllLifecyclePhases();
  WebView()->EnableAutoResizeMode(gfx::Size(25, 25), gfx::Size(100, 100));
  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  frame_test_helpers::LoadHTMLString(WebView()->MainFrameImpl(),
                                     "<!DOCTYPE html>"
                                     "<style>"
                                     "  body {"
                                     "    margin: 0px;"
                                     "  }"
                                     "  div { height:110vh; width: 110vw; }"
                                     "</style>"
                                     "<div></div>",
                                     base_url);
}

// When a provisional frame is committed, it will get swapped in. At that
// point, the VisualViewport will be reset but the Document is in a detached
// state with no domWindow(). Ensure we correctly reset the viewport properties
// but don't crash trying to enqueue resize and scroll events in the document.
// https://crbug.com/1175916.
TEST_P(VisualViewportTest, SwapMainFrame) {
  InitializeWithDesktopSettings();

  WebView()->SetPageScaleFactor(2.0f);
  WebView()->SetVisualViewportOffset(gfx::PointF(10, 20));

  WebLocalFrame* local_frame =
      helper_.CreateProvisional(*helper_.LocalMainFrame());

  // Commit the provisional frame so it gets swapped in.
  RegisterMockedHttpURLLoad("200-by-300.html");
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "200-by-300.html");

  EXPECT_EQ(WebView()->PageScaleFactor(), 1.0f);
  EXPECT_EQ(WebView()->VisualViewportOffset().x(), 0.0f);
  EXPECT_EQ(WebView()->VisualViewportOffset().y(), 0.0f);
}

// Similar to above but checks the case where a page is loaded such that it
// will zoom out as a result of loading and layout (i.e. loading a desktop page
// on Android).
TEST_P(VisualViewportTest, SwapMainFrameLoadZoomedOut) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 150));

  WebLocalFrame* local_frame =
      helper_.CreateProvisional(*helper_.LocalMainFrame());

  // Commit the provisional frame so it gets swapped in.
  RegisterMockedHttpURLLoad("200-by-300.html");
  frame_test_helpers::LoadFrame(local_frame, base_url_ + "200-by-300.html");

  EXPECT_EQ(WebView()->PageScaleFactor(), 0.5f);
  EXPECT_EQ(WebView()->VisualViewportOffset().x(), 0.0f);
  EXPECT_EQ(WebView()->VisualViewportOffset().y(), 0.0f);
}

class VisualViewportSimTest : public SimTest {
 public:
  VisualViewportSimTest() {}

  void SetUp() override {
    SimTest::SetUp();
    frame_test_helpers::WebViewHelper::UpdateAndroidCompositingSettings(
        WebView().GetSettings());
    WebView().SetDefaultPageScaleLimits(0.25f, 5);
  }
};

// Test that we correctly size the visual viewport's scrolling contents layer
// when the layout viewport is smaller.
TEST_F(VisualViewportSimTest, ScrollingContentsSmallerThanContainer) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <meta name="viewport" content="width=320">
          <style>
            body {
              height: 2000px;
            }
          </style>
      )HTML");
  Compositor().BeginFrame();

  ASSERT_EQ(1.25f, WebView().MinimumPageScaleFactor());

  VisualViewport& visual_viewport = WebView().GetPage()->GetVisualViewport();
  EXPECT_EQ(gfx::Size(320, 480), visual_viewport.LayerForScrolling()->bounds());

  EXPECT_EQ(gfx::Rect(0, 0, 400, 600),
            visual_viewport.GetScrollNode()->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 320, 480),
            visual_viewport.GetScrollNode()->ContentsRect());

  WebView().MainFrameViewWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(1, 1), gfx::Vector2dF(), 2, false, 1, 0,
       cc::BrowserControlsState::kBoth});
  EXPECT_EQ(gfx::Size(320, 480), visual_viewport.LayerForScrolling()->bounds());

  EXPECT_EQ(gfx::Rect(0, 0, 400, 600),
            visual_viewport.GetScrollNode()->ContainerRect());
  EXPECT_EQ(gfx::Rect(0, 0, 320, 480),
            visual_viewport.GetScrollNode()->ContentsRect());
}

class VisualViewportScrollIntoViewTest
    : public VisualViewportSimTest,
      public ::testing::WithParamInterface<
          std::vector<base::test::FeatureRef>> {
 public:
  VisualViewportScrollIntoViewTest() {
    feature_list_.InitWithFeatures(
        GetParam(),
        /*disabled_features=*/std::vector<base::test::FeatureRef>());
  }

  void SetUp() override {
    VisualViewportSimTest::SetUp();

    // Setup a fixed-position element that's outside of an inset visual
    // viewport.
    WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));
    SimRequest request("https://example.com/test.html", "text/html");
    LoadURL("https://example.com/test.html");
    request.Complete(R"HTML(
              <!DOCTYPE html>
              <style>
               #bottom {
                    position: fixed;
                    bottom: 0;
                                width: 100%;
                                height: 20px;
                                text-align: center;
                }
              </style>
              <body>
                 <div id="bottom">Layout bottom</div>
              </body>
          )HTML");
    Compositor().BeginFrame();

    // Shrink the height such that the fixed element is now off screen.
    WebView().ResizeVisualViewport(gfx::Size(400, 600 - 100));
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    ,
    VisualViewportScrollIntoViewTest,
    testing::Values(std::vector<base::test::FeatureRef>{},
                    std::vector<base::test::FeatureRef>{
                        features::kMultiSmoothScrollIntoView}));

TEST_P(VisualViewportScrollIntoViewTest, ScrollingToFixed) {
  VisualViewport& visual_viewport = WebView().GetPage()->GetVisualViewport();
  EXPECT_EQ(0.f, visual_viewport.GetScrollOffset().y());
  WebDocument web_doc = WebView().MainFrameImpl()->GetDocument();
  Element* bottom_element = web_doc.GetElementById("bottom");
  bool is_for_scroll_sequence =
      !RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled();
  auto scroll_params = scroll_into_view_util::CreateScrollIntoViewParams(
      ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
      mojom::blink::ScrollType::kProgrammatic,
      /*make_visible_in_visual_viewport=*/true,
      mojom::blink::ScrollBehavior::kInstant, is_for_scroll_sequence);
  if (is_for_scroll_sequence) {
    GetDocument().GetFrame()->CreateNewSmoothScrollSequence();
  }
  WebView().GetPage()->GetVisualViewport().ScrollIntoView(
      bottom_element->BoundingBox(), PhysicalBoxStrut(), scroll_params);
  if (is_for_scroll_sequence) {
    visual_viewport.GetSmoothScrollSequencer()->RunQueuedAnimations();
  }
  EXPECT_EQ(100.f, visual_viewport.GetScrollOffset().y());
}

TEST_P(VisualViewportScrollIntoViewTest, ScrollingToFixedFromJavascript) {
  VisualViewport& visual_viewport = WebView().GetPage()->GetVisualViewport();
  EXPECT_EQ(0.f, visual_viewport.GetScrollOffset().y());
  GetDocument().getElementById(AtomicString("bottom"))->scrollIntoView();
  EXPECT_EQ(100.f, visual_viewport.GetScrollOffset().y());
}

TEST_P(VisualViewportTest, DeviceEmulation) {
  InitializeWithAndroidSettings();

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  NavigateTo("about:blank");
  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_FALSE(visual_viewport.GetDeviceEmulationTransformNode());
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());

  DeviceEmulationParams params;
  params.viewport_offset = gfx::PointF();
  params.viewport_scale = 1.f;
  WebView()->EnableDeviceEmulation(params);

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(visual_viewport.GetDeviceEmulationTransformNode());
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());

  // Set device mulation with viewport offset should repaint visual viewport.
  params.viewport_offset = gfx::PointF(314, 159);
  WebView()->EnableDeviceEmulation(params);

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());
  ASSERT_TRUE(visual_viewport.GetDeviceEmulationTransformNode());
  EXPECT_EQ(gfx::Transform::MakeTranslation(-params.viewport_offset.x(),
                                            -params.viewport_offset.y()),
            visual_viewport.GetDeviceEmulationTransformNode()->Matrix());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());

  // Change device emulation with scale should not repaint visual viewport.
  params.viewport_offset = gfx::PointF();
  params.viewport_scale = 1.5f;
  WebView()->EnableDeviceEmulation(params);

  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());
  ASSERT_TRUE(visual_viewport.GetDeviceEmulationTransformNode());
  EXPECT_EQ(gfx::Transform::MakeScale(1.5f),
            visual_viewport.GetDeviceEmulationTransformNode()->Matrix());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());

  // Set an identity device emulation transform and ensure the transform
  // paint property node is cleared and repaint visual viewport.
  WebView()->EnableDeviceEmulation(DeviceEmulationParams());
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());
  EXPECT_FALSE(visual_viewport.GetDeviceEmulationTransformNode());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());
}

TEST_P(VisualViewportTest, PaintScrollbar) {
  InitializeWithAndroidSettings();

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  frame_test_helpers::LoadHTMLString(WebView()->MainFrameImpl(),
                                     R"HTML(
        <!DOCTYPE html>"
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <body style='width: 2000px; height: 2000px'></body>
      )HTML",
                                     base_url);
  UpdateAllLifecyclePhases();

  auto check_scrollbar = [](const cc::Layer* scrollbar, float scale) {
    EXPECT_TRUE(scrollbar->draws_content());
    EXPECT_EQ(cc::HitTestOpaqueness::kTransparent,
              scrollbar->hit_test_opaqueness());
    EXPECT_TRUE(scrollbar->IsScrollbarLayerForTesting());
    EXPECT_EQ(
        cc::ScrollbarOrientation::kVertical,
        static_cast<const cc::ScrollbarLayerBase*>(scrollbar)->orientation());
    EXPECT_EQ(gfx::Size(7, 393), scrollbar->bounds());
    EXPECT_EQ(gfx::Vector2dF(393, 0), scrollbar->offset_to_transform_parent());

    // ScreenSpaceTransform is in the device emulation transform space, so it's
    // not affected by device emulation scale.
    gfx::Transform screen_space_transform;
    screen_space_transform.Translate(393, 0);
    EXPECT_EQ(screen_space_transform, scrollbar->ScreenSpaceTransform());

    gfx::Transform transform;
    transform.Scale(scale, scale);
    EXPECT_EQ(transform, scrollbar->layer_tree_host()
                             ->property_trees()
                             ->transform_tree()
                             .Node(scrollbar->transform_tree_index())
                             ->local);
  };

  // The last layer should be the vertical scrollbar.
  const cc::Layer* scrollbar =
      GetFrame()->View()->RootCcLayer()->children().back().get();
  check_scrollbar(scrollbar, 1.f);

  // Apply device emulation scale.
  DeviceEmulationParams params;
  params.viewport_offset = gfx::PointF();
  params.viewport_scale = 1.5f;
  WebView()->EnableDeviceEmulation(params);
  UpdateAllLifecyclePhases();
  ASSERT_EQ(scrollbar,
            GetFrame()->View()->RootCcLayer()->children().back().get());
  check_scrollbar(scrollbar, 1.5f);

  params.viewport_scale = 1.f;
  WebView()->EnableDeviceEmulation(params);
  UpdateAllLifecyclePhases();
  ASSERT_EQ(scrollbar,
            GetFrame()->View()->RootCcLayer()->children().back().get());
  check_scrollbar(scrollbar, 1.f);

  params.viewport_scale = 0.75f;
  WebView()->EnableDeviceEmulation(params);
  UpdateAllLifecyclePhases();
  ASSERT_EQ(scrollbar,
            GetFrame()->View()->RootCcLayer()->children().back().get());
  check_scrollbar(scrollbar, 0.75f);
}

// When a pinch-zoom occurs, the viewport scale and translation nodes can be
// directly updated without a PaintArtifactCompositor update.
TEST_P(VisualViewportTest, DirectPinchZoomPropertyUpdate) {
  InitializeWithAndroidSettings();

  RegisterMockedHttpURLLoad("200-by-800-viewport.html");
  NavigateTo(base_url_ + "200-by-800-viewport.html");

  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 200));

  // Scroll visual viewport to the right edge of the frame
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.SetScaleAndLocation(2.f, true, gfx::PointF(150, 10));

  EXPECT_VECTOR2DF_EQ(ScrollOffset(150, 10), visual_viewport.GetScrollOffset());
  EXPECT_EQ(2.f, visual_viewport.Scale());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  // Update the scale and location and ensure that a PaintArtifactCompositor
  // update is not required.
  visual_viewport.SetScaleAndLocation(3.f, true, gfx::PointF(120, 10));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_FALSE(paint_artifact_compositor()->NeedsUpdate());

  EXPECT_VECTOR2DF_EQ(ScrollOffset(120, 10), visual_viewport.GetScrollOffset());
  EXPECT_EQ(3.f, visual_viewport.Scale());
}

// |TransformPaintPropertyNode::in_subtree_of_page_scale| should be false for
// the page scale transform node and all ancestors, and should be true for
// descendants of the page scale transform node.
TEST_P(VisualViewportTest, InSubtreeOfPageScale) {
  InitializeWithAndroidSettings();
  RegisterMockedHttpURLLoad("200-by-800-viewport.html");
  NavigateTo(base_url_ + "200-by-800-viewport.html");

  UpdateAllLifecyclePhases();

  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  const auto* page_scale = visual_viewport.GetPageScaleNode();
  // The page scale is not in its own subtree.
  EXPECT_FALSE(page_scale->IsInSubtreeOfPageScale());
  // Ancestors of the page scale are not in the page scale's subtree.
  for (const auto* ancestor = page_scale->UnaliasedParent(); ancestor;
       ancestor = ancestor->UnaliasedParent()) {
    EXPECT_FALSE(ancestor->IsInSubtreeOfPageScale());
  }

  const auto* view = GetFrame()->View()->GetLayoutView();
  const auto& view_contents_transform =
      view->FirstFragment().ContentsProperties().Transform();
  // Descendants of the page scale node should have |IsInSubtreeOfPageScale|.
  EXPECT_TRUE(ToUnaliased(view_contents_transform).IsInSubtreeOfPageScale());
  for (const auto* ancestor = view_contents_transform.UnaliasedParent();
       ancestor != page_scale; ancestor = ancestor->UnaliasedParent()) {
    EXPECT_TRUE(ancestor->IsInSubtreeOfPageScale());
  }
}

TEST_F(VisualViewportSimTest, UsedColorSchemeFromRootElement) {
  ColorSchemeHelper color_scheme_helper(*(WebView().GetPage()));
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));

  const VisualViewport& visual_viewport =
      WebView().GetPage()->GetVisualViewport();

  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            visual_viewport.UsedColorSchemeScrollbars());

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            html { color-scheme: dark }
          </style>
      )HTML");
  Compositor().BeginFrame();

  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            visual_viewport.UsedColorSchemeScrollbars());
}

TEST_F(VisualViewportSimTest, ScrollbarThumbColorFromRootElement) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));

  const VisualViewport& visual_viewport =
      WebView().GetPage()->GetVisualViewport();

  EXPECT_EQ(std::nullopt, visual_viewport.CSSScrollbarThumbColor());

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            html { scrollbar-color: rgb(255 0 0) transparent }
          </style>
      )HTML");
  Compositor().BeginFrame();

  EXPECT_EQ(blink::Color(255, 0, 0), visual_viewport.CSSScrollbarThumbColor());
}

TEST_P(VisualViewportTest, SetLocationBeforePrePaint) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");

  // Simulate that the visual viewport is just created and FrameLoader is
  // restoring the previously saved scale and scroll state.
  VisualViewport& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  visual_viewport.DisposeImpl();
  ASSERT_FALSE(visual_viewport.LayerForScrolling());
  visual_viewport.SetScaleAndLocation(1.75, false, gfx::PointF(12, 34));
  EXPECT_EQ(gfx::PointF(12, 34), visual_viewport.ScrollPosition());

  UpdateAllLifecyclePhases();
  EXPECT_EQ(gfx::PointF(12, 34), visual_viewport.ScrollPosition());
  // When we create the scrolling layer, we should update its scroll offset.
  ASSERT_TRUE(visual_viewport.LayerForScrolling());

  auto* layer_tree_host = GetFrame()->View()->RootCcLayer()->layer_tree_host();
  EXPECT_EQ(
      gfx::PointF(12, 34),
      layer_tree_host->property_trees()->scroll_tree().current_scroll_offset(
          visual_viewport.GetScrollElementId()));
}

TEST_P(VisualViewportTest, ScrollbarGeometryOnSizeChange) {
  InitializeWithAndroidSettings();
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  UpdateAllLifecyclePhases();
  RegisterMockedHttpURLLoad("content-width-1000.html");
  NavigateTo(base_url_ + "content-width-1000.html");

  auto& visual_viewport = GetFrame()->GetPage()->GetVisualViewport();
  EXPECT_EQ(gfx::Size(100, 100), visual_viewport.Size());
  auto* horizontal_scrollbar = visual_viewport.LayerForHorizontalScrollbar();
  auto* vertical_scrollbar = visual_viewport.LayerForVerticalScrollbar();
  ASSERT_TRUE(horizontal_scrollbar);
  ASSERT_TRUE(vertical_scrollbar);
  EXPECT_EQ(gfx::Vector2dF(0, 93),
            horizontal_scrollbar->offset_to_transform_parent());
  EXPECT_EQ(gfx::Vector2dF(93, 0),
            vertical_scrollbar->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(93, 7), horizontal_scrollbar->bounds());
  EXPECT_EQ(gfx::Size(7, 93), vertical_scrollbar->bounds());

  // Simulate hiding of the top controls.
  WebView()->MainFrameViewWidget()->Resize(gfx::Size(100, 120));
  UpdateAllLifecyclePhasesExceptPaint();
  EXPECT_TRUE(
      GetFrame()->View()->VisualViewportOrOverlayNeedsRepaintForTesting());
  UpdateAllLifecyclePhases();
  EXPECT_EQ(gfx::Size(100, 120), visual_viewport.Size());
  ASSERT_EQ(horizontal_scrollbar,
            visual_viewport.LayerForHorizontalScrollbar());
  ASSERT_EQ(vertical_scrollbar, visual_viewport.LayerForVerticalScrollbar());
  EXPECT_EQ(gfx::Vector2dF(0, 113),
            horizontal_scrollbar->offset_to_transform_parent());
  EXPECT_EQ(gfx::Vector2dF(93, 0),
            vertical_scrollbar->offset_to_transform_parent());
  EXPECT_EQ(gfx::Size(93, 7), horizontal_scrollbar->bounds());
  EXPECT_EQ(gfx::Size(7, 113), vertical_scrollbar->bounds());
}

TEST_F(VisualViewportSimTest, PreferredOverlayScrollbarColorTheme) {
  ColorSchemeHelper color_scheme_helper(*(WebView().GetPage()));
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <meta name="color-scheme" content="light dark">
          <style>
            html { height: 2000px; }
          </style>
      )HTML");
  Compositor().BeginFrame();

  const VisualViewport& visual_viewport =
      WebView().GetPage()->GetVisualViewport();
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            visual_viewport.GetOverlayScrollbarColorScheme());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  Compositor().BeginFrame();
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            visual_viewport.GetOverlayScrollbarColorScheme());
}

}  // namespace
}  // namespace blink

"""


```
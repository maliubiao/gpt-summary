Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file, `scrollbars_test.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name strongly suggests it's a test file specifically for scrollbar behavior.

2. **Analyze the test structure:** The code uses the `testing` framework (`TEST_P`, `INSTANTIATE_TEST_SUITE_P`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_TRUE`, `ASSERT_EQ`). This confirms its role as a test suite.

3. **Categorize the tests:**  Look for patterns in the test names and the actions performed within each test. Many tests manipulate the DOM (by injecting HTML and CSS via `LoadURL` and `ExecuteScript`), simulate user interactions (like mouse movements and clicks), and then assert the state of scrollbars (visibility, overlay status, thumb position, etc.).

4. **Identify relationships with web technologies:** The tests frequently manipulate HTML elements, CSS styles (`style` attributes, inline styles), and use JavaScript (`ExecuteScript`). This clearly links the tests to the behavior of scrollbars as rendered in a web browser.

5. **Look for logical reasoning and assumptions:**  The tests set up specific scenarios (e.g., setting body dimensions, enabling/disabling overlay scrollbars, using device emulation) and then verify expected outcomes based on how scrollbars should behave in those situations. The input is the HTML/CSS/JS setup, and the output is the asserted state of the scrollbars.

6. **Consider potential user/developer errors:** Some tests implicitly cover potential errors. For example, testing how scrollbars behave with specific body dimensions helps ensure that developers setting these dimensions get the expected scrollbar behavior.

7. **Address the "part 3 of 5" instruction:**  Acknowledge that this is a segment of a larger file and the summary should reflect that.

**Pre-computation/Pre-analysis (Mental Walkthrough):**

* **Overlay vs. Non-overlay Scrollbars:** The frequent use of `ENABLE_OVERLAY_SCROLLBARS` and tests like `ScrollbarsHiddenIfOverlay` suggest a focus on testing the differences between these two types of scrollbars.

* **Size and Overflow:** Many tests manipulate element sizes and use `overflow: auto`, `overflow: scroll`, which are fundamental to when scrollbars appear.

* **User Interaction:**  The `HandleMouseMoveEvent`, `HandleMousePressEvent`, etc., indicate testing how scrollbars respond to mouse input.

* **Emulator and Device Modes:** The `NativeScrollbarChangeToMobileByEmulator` test highlights testing scrollbar appearance under different device emulation settings.

* **Autosizing:** Tests like `AutosizeTest` indicate testing how scrollbars interact with the browser's auto-resizing features.

* **Hit Testing:** Tests involving `HitTest` are verifying whether scrollbar elements can be targeted by mouse events.

* **Middle Click Behavior:** Tests related to `MiddleClickAutoscroll` are specifically checking how middle mouse button clicks interact with scrollbars.

* **Layering and Compositing:**  Tests involving `PaintLayer` suggest testing how scrollbars are managed within the browser's rendering layers, particularly in composited scenarios.

By following these steps and mentally processing the code, I can construct a comprehensive summary that addresses all the user's requirements.
Based on the provided C++ code snippet from `blink/renderer/core/layout/scrollbars_test.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet contains a series of unit tests designed to verify the behavior and rendering of scrollbars within the Blink rendering engine. Specifically, it tests various scenarios related to:

* **Scrollbar Visibility:**  Whether scrollbars appear or disappear based on content size, container size, and the `overflow` CSS property.
* **Overlay Scrollbars:** Tests specific behaviors of overlay scrollbars (scrollbars that don't take up layout space and often fade in/out). This includes their visibility state, fading behavior, and interaction with mouse events.
* **Native Scrollbars:** Tests the behavior of traditional (non-overlay) scrollbars, including their interaction with mouse events and how their appearance can be affected by device emulation settings.
* **Scrollbar Thumb Size and Position:** Verifies the calculation of the scrollbar thumb's length and position, especially in cases with very large content.
* **Interaction with Device Emulation:** Checks how enabling or disabling device emulation (like mobile mode) affects scrollbar appearance (e.g., switching to overlay scrollbars on mobile).
* **Interaction with Autosizing:** Tests how scrollbars behave when the web page or iframe is in an autosize mode, where the browser attempts to resize the viewport to avoid scrollbars.
* **Hit Testing on Scrollbars:**  Verifies that mouse clicks and movements on the scrollbar elements are correctly detected, particularly for overlay scrollbars.
* **Mouse Interaction with Scrollbars:** Tests how mouse events (mouse over, mouse out, mouse press, mouse release, including middle clicks) interact with scrollbar elements and their internal parts (thumb, track, buttons).
* **Integration with Compositing:** Checks how scrollbars are handled within the browser's compositing layers, especially when elements with scrollbars are composited.

**Relationship with JavaScript, HTML, and CSS:**

This test file directly relates to how JavaScript, HTML, and CSS affect scrollbar behavior:

* **HTML Structure:** The tests use HTML to create elements with specific sizes and content, which directly determines whether scrollbars are needed. For example, creating a `div` with a fixed height and then adding content that exceeds that height will trigger vertical scrollbars.
    * **Example:** The test `WideBodyShouldNotHaveScrollbars` loads HTML with a `body` element whose width is slightly less than the viewport. The test expects no horizontal scrollbar because the content fits.
* **CSS Styling:** CSS properties like `overflow`, `height`, `width`, `margin`, and `display` are crucial in controlling scrollbar visibility and appearance. The tests manipulate these properties using JavaScript's `style` API to set up different scrollbar scenarios.
    * **Example:** The test `OverlayScrollbarFadesOut` uses JavaScript to dynamically change the `height` of elements, triggering the appearance and disappearance of overlay scrollbars, and then verifies their fading behavior.
* **JavaScript Interaction:** JavaScript is used within the tests to:
    * Dynamically modify HTML and CSS.
    * Simulate user interactions like scrolling using `SetScrollOffset`.
    * Trigger layout and paint updates using `Compositor().BeginFrame()`.
    * Assert the state of scrollbar elements based on these manipulations.
    * **Example:** The test `MouseOverIFrameScrollbar` loads an iframe and then simulates a mouse movement over the iframe's scrollbar to verify the correct hover behavior.

**Logical Reasoning and Assumptions:**

* **Assumption:**  The tests assume a standard browser environment where scrollbar behavior is consistent with web standards and the Blink engine's implementation.
* **Input (Hypothetical):**  Consider the test `WidePercentageBodyShouldHaveScrollbar`.
    * **HTML Input:**  A body element with `width: 101%` and the `html` element with `height: 100%`. The browser window is resized to a specific size (e.g., 800x600).
    * **CSS Input:** The specified styles for `html` and `body`.
* **Output (Expected):** The layout viewport should have a horizontal scrollbar and no vertical scrollbar.

**User or Programming Common Usage Errors (Addressed by the Tests):**

* **Incorrectly assuming overlay scrollbars always take up zero space:**  While overlay scrollbars don't affect layout initially, some tests (although not explicitly showcasing errors) verify their interaction and hit-testing, ensuring developers understand they are interactive elements.
* **Unexpected scrollbar behavior with specific CSS combinations:** The tests cover various combinations of `height`, `width`, `overflow`, and percentage values to ensure scrollbars appear as expected, preventing developers from making incorrect assumptions about how these properties interact.
* **Forgetting to account for scrollbar size in fixed layouts:** While not directly tested in this snippet, the underlying scrollbar logic the tests verify ensures that fixed-size elements with overflow correctly display scrollbars without unexpected layout shifts.
* **Issues with hit-testing on overlay scrollbars:** The `OverlayScrollbarHitTest` and `RecorderedOverlayScrollbarHitTest` tests specifically address scenarios where developers might have issues targeting overlay scrollbars with mouse events.
* **Incorrect assumptions about middle-click behavior on scrollbars:** The tests related to `MiddleClickAutoscroll` ensure that the browser's behavior regarding middle-click autoscroll on scrollbars is correctly implemented.

**归纳一下它的功能 (Summary of its Functionality):**

This section of `scrollbars_test.cc` focuses on comprehensively testing the functionality of scrollbars within the Blink rendering engine. It sets up various web page scenarios using HTML and CSS, simulates user interactions (primarily mouse events), and then uses assertions to verify that scrollbars appear, disappear, and behave as expected under different conditions. This includes testing the nuances of overlay scrollbars, native scrollbars, their interaction with device emulation and autosizing features, and ensuring correct hit-testing and mouse event handling. Essentially, it's a suite of tests designed to catch bugs and ensure the reliability of scrollbar rendering and interaction in the Chromium browser.

### 提示词
```
这是目录为blink/renderer/core/layout/scrollbars_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ument.getElementById('space').style.height = '500px';"));
  Compositor().BeginFrame();

  EXPECT_TRUE(scrollable_area->ScrollbarsHiddenIfOverlay());

  MainFrame().ExecuteScript(WebScriptSource(
      "document.getElementById('container').style.height = '300px';"));
  Compositor().BeginFrame();

  EXPECT_FALSE(scrollable_area->ScrollbarsHiddenIfOverlay());
  RunTasksForPeriod(kMockOverlayFadeOutDelay);
  EXPECT_TRUE(scrollable_area->ScrollbarsHiddenIfOverlay());

  // Non-composited scrollbars don't fade out while mouse is over.
  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  scrollable_area->SetScrollOffset(ScrollOffset(20, 20),
                                   mojom::blink::ScrollType::kProgrammatic,
                                   mojom::blink::ScrollBehavior::kInstant);
  EXPECT_FALSE(scrollable_area->ScrollbarsHiddenIfOverlay());
  scrollable_area->MouseEnteredScrollbar(*scrollable_area->VerticalScrollbar());
  RunTasksForPeriod(kMockOverlayFadeOutDelay);
  EXPECT_FALSE(scrollable_area->ScrollbarsHiddenIfOverlay());
  scrollable_area->MouseExitedScrollbar(*scrollable_area->VerticalScrollbar());
  RunTasksForPeriod(kMockOverlayFadeOutDelay);
  EXPECT_TRUE(scrollable_area->ScrollbarsHiddenIfOverlay());

  mock_overlay_theme.SetOverlayScrollbarFadeOutDelay(base::TimeDelta());
}

enum { kUseOverlayScrollbars = 1 << 10 };

class ScrollbarAppearanceTest : public ScrollbarsTest {
 protected:
  bool UsesOverlayScrollbars() const {
    return GetParam() & kUseOverlayScrollbars;
  }
};

// Test both overlay and non-overlay scrollbars.
INSTANTIATE_TEST_SUITE_P(All,
                         ScrollbarAppearanceTest,
                         ::testing::Values(0, kUseOverlayScrollbars));

// Make sure native scrollbar can change by Emulator.
// Disable on Android since Android always enable OverlayScrollbar.
#if BUILDFLAG(IS_ANDROID)
TEST_P(ScrollbarAppearanceTest,
       DISABLED_NativeScrollbarChangeToMobileByEmulator) {
#else
TEST_P(ScrollbarAppearanceTest, NativeScrollbarChangeToMobileByEmulator) {
#endif
  ENABLE_OVERLAY_SCROLLBARS(UsesOverlayScrollbars());

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style type='text/css'>
    body {
      height: 10000px;
      margin: 0;
    }
    #d1 {
      height: 200px;
      width: 200px;
      overflow: auto;
    }
    #d2 {
      height: 2000px;
    }
    </style>
    <!-- flex creates DelayScrollOffsetClampScope to increase test coverge -->
    <div style='display: flex'>
      <div id='d1'>
        <div id='d2'/>
      </div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  ScrollableArea* root_scrollable = document.View()->LayoutViewport();

  Element* div = document.getElementById(AtomicString("d1"));

  auto* div_scrollable = GetScrollableArea(*div);

  VisualViewport& viewport = WebView().GetPage()->GetVisualViewport();

  DCHECK(root_scrollable->VerticalScrollbar());
  DCHECK(!root_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK_EQ(UsesOverlayScrollbars(),
            root_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  DCHECK(!root_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  DCHECK(!viewport.LayerForHorizontalScrollbar());

  DCHECK(div_scrollable->VerticalScrollbar());
  DCHECK(!div_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK_EQ(UsesOverlayScrollbars(),
            div_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  DCHECK(!div_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  // Turn on mobile emulator.
  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kMobile;
  WebView().EnableDeviceEmulation(params);

  // For root Scrollbar, mobile emulator will change them to page VisualViewport
  // scrollbar layer.
  EXPECT_TRUE(viewport.LayerForHorizontalScrollbar());

  // Ensure div scrollbar also change to mobile overlay theme.
  EXPECT_TRUE(div_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  EXPECT_TRUE(div_scrollable->VerticalScrollbar()->IsSolidColor());

  // Turn off mobile emulator.
  WebView().DisableDeviceEmulation();

  EXPECT_TRUE(root_scrollable->VerticalScrollbar());
  EXPECT_FALSE(root_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK_EQ(UsesOverlayScrollbars(),
            root_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  EXPECT_FALSE(root_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  DCHECK(!viewport.LayerForHorizontalScrollbar());

  EXPECT_TRUE(div_scrollable->VerticalScrollbar());
  EXPECT_FALSE(div_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK_EQ(UsesOverlayScrollbars(),
            div_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  EXPECT_FALSE(div_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());
}

#if !BUILDFLAG(IS_MAC)
// Ensure that the minimum length for a scrollbar thumb comes from the
// WebThemeEngine. Note, Mac scrollbars differ from all other platforms so this
// test doesn't apply there. https://crbug.com/682209.
TEST_P(ScrollbarAppearanceTest, ThemeEngineDefinesMinimumThumbLength) {
  ScopedStubThemeEngine scoped_theme;
  ENABLE_OVERLAY_SCROLLBARS(UsesOverlayScrollbars());

  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style> body { width: 1000000px; height: 1000000px; } </style>)HTML");
  ScrollableArea* scrollable_area = GetDocument().View()->LayoutViewport();

  Compositor().BeginFrame();
  ASSERT_TRUE(scrollable_area->VerticalScrollbar());
  ASSERT_TRUE(scrollable_area->HorizontalScrollbar());

  ScrollbarTheme& theme = scrollable_area->VerticalScrollbar()->GetTheme();
  EXPECT_EQ(StubWebThemeEngine::kMinimumHorizontalLength,
            theme.ThumbLength(*scrollable_area->HorizontalScrollbar()));
  EXPECT_EQ(StubWebThemeEngine::kMinimumVerticalLength,
            theme.ThumbLength(*scrollable_area->VerticalScrollbar()));
}

// Ensure thumb position is correctly calculated even at ridiculously large
// scales.
TEST_P(ScrollbarAppearanceTest, HugeScrollingThumbPosition) {
  ScopedStubThemeEngine scoped_theme;
  ENABLE_OVERLAY_SCROLLBARS(UsesOverlayScrollbars());

  v8::HandleScope handle_scope(
      WebView().GetPage()->GetAgentGroupScheduler().Isolate());
  WebView().MainFrameViewWidget()->Resize(gfx::Size(1000, 1000));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style> body { margin: 0px; height: 10000000px; } </style>)HTML");
  ScrollableArea* scrollable_area = GetDocument().View()->LayoutViewport();

  Compositor().BeginFrame();

  scrollable_area->SetScrollOffset(ScrollOffset(0, 10000000),
                                   mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();

  int scroll_y = scrollable_area->GetScrollOffset().y();
  ASSERT_EQ(9999000, scroll_y);

  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  ASSERT_TRUE(scrollbar);

  int max_thumb_position = WebView().MainFrameViewWidget()->Size().height() -
                           StubWebThemeEngine::kMinimumVerticalLength;
  max_thumb_position -= scrollbar->GetTheme().ScrollbarMargin(
                            scrollbar->ScaleFromDIP(), EScrollbarWidth::kAuto) *
                        2;

  EXPECT_EQ(max_thumb_position,
            scrollbar->GetTheme().ThumbPosition(*scrollbar));
}
#endif

// A body with width just under the window width should not have scrollbars.
TEST_P(ScrollbarsTest, WideBodyShouldNotHaveScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
      background: blue;
      height: 10px;
      width: 799px;
    }
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar());
  EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
}

// A body with height just under the window height should not have scrollbars.
TEST_P(ScrollbarsTest, TallBodyShouldNotHaveScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
      background: blue;
      height: 599px;
      width: 10px;
    }
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar());
  EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
}

// A body with dimensions just barely inside the window dimensions should not
// have scrollbars.
TEST_P(ScrollbarsTest, TallAndWideBodyShouldNotHaveScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
      background: blue;
      height: 599px;
      width: 799px;
    }
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar());
  EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
}

// A body with dimensions equal to the window dimensions should not have
// scrollbars.
TEST_P(ScrollbarsTest, BodySizeEqualWindowSizeShouldNotHaveScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
      background: blue;
      height: 600px;
      width: 800px;
    }
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar());
  EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
}

// A body with percentage width extending beyond the window width should cause a
// horizontal scrollbar.
TEST_P(ScrollbarsTest, WidePercentageBodyShouldHaveScrollbar) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      html { height: 100%; }
      body {
        margin: 0;
        width: 101%;
        height: 10px;
      }
    </style>
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar());
  EXPECT_TRUE(layout_viewport->HorizontalScrollbar());
}

// Similar to |WidePercentageBodyShouldHaveScrollbar| but with a body height
// equal to the window height.
TEST_P(ScrollbarsTest, WidePercentageAndTallBodyShouldHaveScrollbar) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      html { height: 100%; }
      body {
        margin: 0;
        width: 101%;
        height: 100%;
      }
    </style>
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_FALSE(layout_viewport->VerticalScrollbar());
  EXPECT_TRUE(layout_viewport->HorizontalScrollbar());
}

// A body with percentage height extending beyond the window height should cause
// a vertical scrollbar.
TEST_P(ScrollbarsTest, TallPercentageBodyShouldHaveScrollbar) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      html { height: 100%; }
      body {
        margin: 0;
        width: 10px;
        height: 101%;
      }
    </style>
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_TRUE(layout_viewport->VerticalScrollbar());
  EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
}

// Similar to |TallPercentageBodyShouldHaveScrollbar| but with a body width
// equal to the window width.
TEST_P(ScrollbarsTest, TallPercentageAndWideBodyShouldHaveScrollbar) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      html { height: 100%; }
      body {
        margin: 0;
        width: 100%;
        height: 101%;
      }
    </style>
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_TRUE(layout_viewport->VerticalScrollbar());
  EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
}

// A body with percentage dimensions extending beyond the window dimensions
// should cause scrollbars.
TEST_P(ScrollbarsTest, TallAndWidePercentageBodyShouldHaveScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      html { height: 100%; }
      body {
        margin: 0;
        width: 101%;
        height: 101%;
      }
    </style>
  )HTML");
  Compositor().BeginFrame();
  auto* layout_viewport = GetDocument().View()->LayoutViewport();
  EXPECT_TRUE(layout_viewport->VerticalScrollbar());
  EXPECT_TRUE(layout_viewport->HorizontalScrollbar());
}

TEST_P(ScrollbarsTest, MouseOverIFrameScrollbar) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/iframe.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    iframe {
      width: 200px;
      height: 200px;
    }
    </style>
    <iframe id='iframe' src='iframe.html'>
    </iframe>
  )HTML");

  frame_resource.Complete(R"HTML(
  <!DOCTYPE html>
  <style>
  body {
    margin: 0;
    height :500px;
  }
  </style>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();
  Element* iframe = document.getElementById(AtomicString("iframe"));
  DCHECK(iframe);

  // Ensure hittest has scrollbar.
  HitTestResult hit_test_result = HitTest(196, 10);
  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  EXPECT_TRUE(hit_test_result.GetScrollbar()->Enabled());

  // Mouse over scrollbar.
  HandleMouseMoveEvent(196, 5);

  // IFRAME hover.
  EXPECT_EQ(document.HoverElement(), iframe);
}

TEST_P(ScrollbarsTest, AutosizeTest) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(0, 0));
  SimRequest resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body, html {
      width: 100%;
      margin: 0;
    }
    #container {
      width: 100.7px;
      height: 150px;
    }
    </style>
    <div id="container"></div>
  )HTML");

  DCHECK(!GetScrollbarTheme().UsesOverlayScrollbars());

  // Needs to dispatch the load event so FramViewAutoSizeInfo doesn't prevent
  // down-sizing.
  test::RunPendingTasks();

  LocalFrameView* frame_view = WebView().MainFrameImpl()->GetFrameView();
  ScrollableArea* layout_viewport = frame_view->LayoutViewport();

  // Enable auto size mode where the frame is resized such that the content
  // doesn't need scrollbars (up to a maximum).
  WebView().EnableAutoResizeMode(gfx::Size(100, 100), gfx::Size(100, 200));

  // Note, the frame autosizer doesn't work correctly with subpixel sizes so
  // even though the container is a fraction larger than the frame, we don't
  // consider that for overflow.
  {
    Compositor().BeginFrame();
    EXPECT_FALSE(layout_viewport->VerticalScrollbar());
    EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
    EXPECT_EQ(100, frame_view->FrameRect().width());
    EXPECT_EQ(150, frame_view->FrameRect().height());
  }

  // Subsequent autosizes should be stable. Specifically checking the condition
  // from https://crbug.com/811478.
  {
    frame_view->SetNeedsLayout();
    Compositor().BeginFrame();
    EXPECT_FALSE(layout_viewport->VerticalScrollbar());
    EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
    EXPECT_EQ(100, frame_view->FrameRect().width());
    EXPECT_EQ(150, frame_view->FrameRect().height());
  }

  // Try again.
  {
    frame_view->SetNeedsLayout();
    Compositor().BeginFrame();
    EXPECT_FALSE(layout_viewport->VerticalScrollbar());
    EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
    EXPECT_EQ(100, frame_view->FrameRect().width());
    EXPECT_EQ(150, frame_view->FrameRect().height());
  }
}

TEST_P(ScrollbarsTest, AutosizeAlmostRemovableScrollbar) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);
  WebView().EnableAutoResizeMode(gfx::Size(25, 25), gfx::Size(800, 600));

  SimRequest resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  resource.Complete(R"HTML(
    <style>
    body { margin: 0; padding: 15px }
    #b1, #b2 { display: inline-block; width: 205px; height: 45px; }
    #b1 { background: #888; }
    #b2 { background: #bbb; }
    #spacer { width: 400px; height: 490px; background: #eee; }
    </style>
    <div id="b1"></div><div id="b2"></div>
    <div id="spacer"></div>
  )HTML");

  // Finish loading.
  test::RunPendingTasks();

  LocalFrameView* frame_view = WebView().MainFrameImpl()->GetFrameView();
  ScrollableArea* layout_viewport = frame_view->LayoutViewport();

  // Check three times to verify stability.
  for (int i = 0; i < 3; i++) {
    frame_view->SetNeedsLayout();
    Compositor().BeginFrame();
    EXPECT_TRUE(layout_viewport->VerticalScrollbar());
    EXPECT_FALSE(layout_viewport->HorizontalScrollbar());
    EXPECT_EQ(445, frame_view->Width());
    EXPECT_EQ(600, frame_view->Height());
  }
}

TEST_P(ScrollbarsTest, AutosizeExpandingContentScrollable) {
  ENABLE_OVERLAY_SCROLLBARS(true);

  SimRequest resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  resource.Complete(R"HTML(
    <style>
    body { margin: 0 }
    #spacer { width: 100px; height: 100px; }
    </style>
    <div id="spacer"></div>
  )HTML");
  test::RunPendingTasks();

  LocalFrameView* frame_view = WebView().MainFrameImpl()->GetFrameView();
  ScrollableArea* layout_viewport = frame_view->LayoutViewport();

  WebView().EnableAutoResizeMode(gfx::Size(800, 600), gfx::Size(800, 600));
  Compositor().BeginFrame();

  // Not scrollable due to no overflow.
  EXPECT_FALSE(layout_viewport->UserInputScrollable(kVerticalScrollbar));

  GetDocument()
      .getElementById(AtomicString("spacer"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 900px"));
  Compositor().BeginFrame();

  // Now scrollable due to overflow.
  EXPECT_TRUE(layout_viewport->UserInputScrollable(kVerticalScrollbar));
}

TEST_P(ScrollbarsTest,
       HideTheOverlayScrollbarNotCrashAfterPLSADisposedPaintLayer) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #div{ height: 100px; overflow-y:scroll; }
    .big{ height: 2000px; }
    .hide { display: none; }
    </style>
    <div id='div'>
      <div class='big'>
      </div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();
  Element* div = document.getElementById(AtomicString("div"));
  auto* scrollable_div = GetScrollableArea(*div);

  scrollable_div->SetScrollbarsHiddenForTesting(false);
  ASSERT_TRUE(scrollable_div);
  ASSERT_TRUE(scrollable_div->GetPageScrollbarTheme().UsesOverlayScrollbars());
  ASSERT_TRUE(scrollable_div->VerticalScrollbar());

  EXPECT_FALSE(scrollable_div->ScrollbarsHiddenIfOverlay());

  // Set display:none calls Dispose().
  div->setAttribute(html_names::kClassAttr, AtomicString("hide"));
  Compositor().BeginFrame();

  // After paint layer in scrollable dispose, we can still call scrollbar hidden
  // just not change scrollbar.
  scrollable_div->SetScrollbarsHiddenForTesting(true);

  EXPECT_FALSE(scrollable_div->ScrollbarsHiddenIfOverlay());
}

TEST_P(ScrollbarsTest, PLSADisposeShouldClearPointerInLayers) {
  SetPreferCompositingToLCDText(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    /* transform keeps the composited layer */
    #div { width: 100px; height: 100px; will-change: transform; }
    .scroller{ overflow: scroll; }
    .big{ height: 2000px; }
    /* positioned so we still keep the PaintLayer */
    .hide { overflow: visible; position: absolute; }
    </style>
    <div id='div' class='scroller' style='z-index:1'>
      <div class='big'>
      </div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();
  Element* div = document.getElementById(AtomicString("div"));
  auto* scrollable_div = GetScrollableArea(*div);

  ASSERT_TRUE(scrollable_div);

  PaintLayer* paint_layer = scrollable_div->Layer();
  ASSERT_TRUE(paint_layer);
  EXPECT_EQ(scrollable_div, paint_layer->GetScrollableArea());

  div->setAttribute(html_names::kClassAttr, AtomicString("hide"));
  document.UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(paint_layer->GetScrollableArea());
}

TEST_P(ScrollbarsTest, OverlayScrollbarHitTest) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));

  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest frame_resource("https://example.com/iframe.html", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
      height: 2000px;
    }
    iframe {
      height: 200px;
      width: 200px;
    }
    </style>
    <iframe id='iframe' src='iframe.html'>
    </iframe>
  )HTML");
  Compositor().BeginFrame();

  frame_resource.Complete("<!DOCTYPE html><body style='height: 999px'></body>");
  Compositor().BeginFrame();

  // Enable the main frame scrollbar.
  WebView()
      .MainFrameImpl()
      ->GetFrameView()
      ->LayoutViewport()
      ->SetScrollbarsHiddenForTesting(false);

  // Enable the iframe scrollbar.
  auto* iframe_element = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  iframe_element->contentDocument()
      ->View()
      ->LayoutViewport()
      ->SetScrollbarsHiddenForTesting(false);

  // Hit test on and off the main frame scrollbar.
  HitTestResult hit_test_result = HitTest(295, 5);
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  hit_test_result = HitTest(250, 5);
  EXPECT_FALSE(hit_test_result.GetScrollbar());

  // Hit test on and off the iframe scrollbar.
  hit_test_result = HitTest(195, 5);
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  hit_test_result = HitTest(150, 5);
  EXPECT_FALSE(hit_test_result.GetScrollbar());
}

TEST_P(ScrollbarsTest, RecorderedOverlayScrollbarHitTest) {
  ENABLE_OVERLAY_SCROLLBARS(true);
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  SimRequest resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>body { margin: 0; }</style>
    <div id="target" style="width: 200px; height: 200px; overflow: scroll">
      <div id="stacked" style="position: relative; height: 400px">
      </div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  auto* target =
      GetDocument().getElementById(AtomicString("target"))->GetLayoutBox();
  target->GetScrollableArea()->SetScrollbarsHiddenForTesting(false);
  ASSERT_TRUE(target->Layer()->NeedsReorderOverlayOverflowControls());

  // Hit test on and off the main frame scrollbar.
  HitTestResult result = HitTest(195, 5);
  EXPECT_TRUE(result.GetScrollbar());
  EXPECT_EQ(target->GetNode(), result.InnerNode());
  result = HitTest(150, 5);
  EXPECT_FALSE(result.GetScrollbar());
  EXPECT_EQ(GetDocument().getElementById(AtomicString("stacked")),
            result.InnerNode());
}

TEST_P(ScrollbarsTest,
       AllowMiddleButtonPressOnScrollbarWhenDisableMiddleClickAutoScroll) {
  ScopedMiddleClickAutoscrollForTest middle_click_autoscroll(false);
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #big {
      height: 800px;
    }
    </style>
    <div id='big'>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();

  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  ASSERT_TRUE(scrollbar);
  ASSERT_TRUE(scrollbar->Enabled());

  // allow press scrollbar with middle button.
  HandleMouseMoveEvent(195, 5);
  HandleMouseMiddlePressEvent(195, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  HandleMouseMiddleReleaseEvent(195, 5);
}

TEST_P(ScrollbarsTest,
       NotAllowMiddleButtonPressOnScrollbarWhenEnableMiddleClickAutoScroll) {
  ScopedMiddleClickAutoscrollForTest middle_click_autoscroll(true);
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #big {
      height: 800px;
    }
    </style>
    <div id='big'>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();

  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  ASSERT_TRUE(scrollbar);
  ASSERT_TRUE(scrollbar->Enabled());

  // Not allow press scrollbar with middle button.
  HandleMouseMoveEvent(195, 5);
  HandleMouseMiddlePressEvent(195, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  HandleMouseMiddleReleaseEvent(195, 5);
}

TEST_P(ScrollbarsTest, NotAllowNonLeftButtonPressOnScrollbar) {
  ScopedMiddleClickAutoscrollForTest middle_click_autoscroll(true);
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #big {
      height: 800px;
    }
    </style>
    <div id='big'>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();

  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  ASSERT_TRUE(scrollbar);
  ASSERT_TRUE(scrollbar->Enabled());

  // Not allow press scrollbar with non-left button.
  HandleMouseMoveEvent(195, 5);
  HandleMousePressEvent(195, 5, WebPointerProperties::Button::kForward);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  HandleMouseReleaseEvent(195, 5, WebPointerProperties::Button::kForward);
}

// Ensure Scrollbar not release press by middle button down.
TEST_P(ScrollbarsTest, MiddleDownShouldNotAffectScrollbarPress) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #big {
      height: 800px;
    }
    </style>
    <div id='big'>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();

  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  ASSERT_TRUE(scrollbar);
  ASSERT_TRUE(scrollbar->Enabled());

  // Press on scrollbar then move mouse out of scrollbar and middle click
  // should not release the press state. Then relase mouse left button should
  // release the scrollbar press state.

  // Move mouse to thumb.
  HandleMouseMoveEvent(195, 5);
  HandleMousePressEvent(195, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);

  // Move mouse out of scrollbar with press.
  WebMouseEvent event(WebInputEvent::Type::kMouseMove, gfx::PointF(5, 5),
                      gfx::PointF(5, 5), WebPointerProperties::Button::kLeft, 0,
                      WebInputEvent::Modifiers::kLeftButtonDown,
                      base::TimeTicks::Now());
  event.SetFrameScale(1);
  GetEventHandler().HandleMouseMoveEvent(event, Vector<WebMouseEvent>(),
                                         Vector<WebMouseEvent>());
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);

  // Middle click should not release scrollbar press state.
  HandleMouseMiddlePressEvent(5, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);

  // Middle button release should release scrollbar press state.
  HandleMouseMiddleReleaseEvent(5, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
}

TEST_P(ScrollbarsTest, UseCounterNegativeWhenThumbIsNotScrolledWithMouse) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
     #content { height: 350px; width: 350px; }
    </style>
    <div id='scrollable'>
     <div id='content'></div>
    </div>
```
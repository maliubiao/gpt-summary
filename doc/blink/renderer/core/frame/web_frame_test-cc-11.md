Response:
My thinking process to analyze the provided code snippet and fulfill the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze a C++ test file (`web_frame_test.cc`) for the Chromium Blink engine, specifically focusing on its functionalities, relationships to web technologies (JavaScript, HTML, CSS), logical reasoning with input/output examples, common usage errors, and a high-level summary of the provided section.

2. **High-Level Overview of the File:**  The filename `web_frame_test.cc` immediately suggests this file contains unit tests for the `WebFrame` class (or related functionalities) in the Blink rendering engine. Unit tests aim to verify specific aspects of a component's behavior.

3. **Skim the Code for Keywords and Patterns:** I'll quickly scan the code looking for recurring patterns and keywords:
    * `TEST_F(WebFrameTest, ...)`: This is a standard Google Test macro indicating individual test cases within the `WebFrameTest` fixture.
    * `RegisterMockedHttpURLLoad(...)`: This suggests the tests involve loading and interacting with web pages, implying HTML content.
    * `WebViewImpl`, `WebLocalFrameImpl`, `Document`, `Element`, `LayoutBox`: These are key Blink classes related to the structure and rendering of web pages.
    * `Fullscreen::RequestFullscreen(...)`, `web_view_impl->DidEnterFullscreen()`, `web_view_impl->DidExitFullscreen()`:  A significant portion of the code deals with testing the fullscreen API.
    * `EXPECT_EQ(...)`, `ASSERT_TRUE(...)`, `EXPECT_FLOAT_EQ(...)`: These are Google Test assertion macros used to verify expected outcomes.
    * `ExecuteScript(...)`:  Indicates interaction with JavaScript within the tested web pages.
    * `gfx::Size`: Used for specifying dimensions, likely related to viewport size and element dimensions.
    *  Look for specific HTML elements or attributes mentioned in the tests (e.g., `iframe`, `div`, `body`, `frameset`, `<meta name="viewport">`, `<link rel="manifest">`).

4. **Identify Key Functionality Blocks:** Based on the keyword scan, I can group the tests into logical blocks of functionality being tested:
    * **Fullscreen API:**  The majority of the provided snippet focuses on various aspects of the fullscreen API: requesting fullscreen, exiting fullscreen, nested fullscreen, fullscreen with different viewport configurations, and handling resizing during fullscreen.
    * **Manifest Fetching:** Tests related to fetching web app manifests and how Content Security Policy (CSP) affects these fetches.
    * **Reloading:** Testing the "reload bypassing cache" functionality.
    * **Drag Image:** Tests related to generating drag images for nodes, potentially involving CSS transformations and layout.
    * **Printing:** Basic printing functionality.
    * **Theme Color:**  Testing how the `<meta name="theme-color">` tag is processed and updated.
    * **Frame Management:** Tests related to detaching frames and propagating frame owner properties.

5. **Analyze Individual Test Cases:** For each test case, I'll try to understand:
    * **Setup:** What HTML content is loaded (`RegisterMockedHttpURLLoad`)? What initial conditions are set (e.g., viewport size)?
    * **Action:** What is the core action being performed in the test (e.g., requesting fullscreen on a specific element, executing JavaScript, triggering a reload)?
    * **Verification:** What assertions are used to check if the action produced the expected outcome (e.g., checking the fullscreen element, layout object dimensions, page scale factors, presence of specific layers)?

6. **Relate to Web Technologies (HTML, CSS, JavaScript):**  As I analyze the test cases, I'll specifically look for how they interact with:
    * **HTML:** Which HTML elements are being manipulated or tested (e.g., `<iframe>`, `<div>`, `<frameset>`, `<meta>` tags)?
    * **CSS:** Are there any tests involving CSS properties or selectors (e.g., transformations, `display: none`, viewport meta tag)? The "NodeImageTest" cases are strongly related to CSS rendering.
    * **JavaScript:** Are there tests that execute JavaScript code (`ExecuteScript`) to manipulate the DOM or trigger events?

7. **Infer Logical Reasoning and Examples:**
    * **Assumptions:** What are the underlying assumptions of the test (e.g., a user gesture is required to initiate fullscreen)?
    * **Input:** What are the initial conditions or parameters (e.g., specific HTML content, viewport dimensions, user interactions)?
    * **Output:** What is the expected outcome based on the input and the functionality being tested (e.g., a specific element becomes the fullscreen element, the page scale factor changes)? I'll try to create simple "if this happens, then this should be the result" scenarios.

8. **Identify Potential User/Programming Errors:** Based on the tests, I can infer potential misuse scenarios:
    * For example, the fullscreen tests highlight the requirement for user activation before requesting fullscreen. A common error would be trying to enter fullscreen without a preceding user interaction.
    * Tests involving viewport meta tags and scaling suggest potential confusion about how these settings interact with fullscreen mode.

9. **Synthesize a Summary:**  Finally, I'll condense the detailed analysis into a concise summary that captures the main functionalities covered by this section of the test file.

**Self-Correction/Refinement during the process:**

* **Initial Skim is Crucial:**  The initial skim gives a good overall direction. Without it, I might get bogged down in the details of a single test case.
* **Look for Patterns:** Recognizing recurring test patterns (like the fullscreen enter/exit sequences) helps in understanding the overall testing strategy.
* **Don't Need to Understand Every Line Initially:**  It's okay if some parts of the Blink-specific API are unfamiliar. Focus on the higher-level actions and verifications. I can always go back and look up specific classes or methods if needed.
* **Focus on the "Why":**  For each test, ask "Why is this test being done?" What specific behavior is being verified?  This helps in understanding the purpose of the code.

By following this structured approach, I can effectively analyze the C++ test file and address all aspects of the request.
Based on the provided C++ code snippet from `blink/renderer/core/frame/web_frame_test.cc`, here's a breakdown of its functionality:

**Overall Functionality of this Section (Part 12/19):**

This section of `web_frame_test.cc` primarily focuses on testing the **fullscreen API** and related behaviors within the Blink rendering engine. It verifies how web pages enter and exit fullscreen mode, how different scenarios (like iframes, nested fullscreen, viewport configurations, and navigation) affect fullscreen behavior, and how it interacts with layout and rendering. It also includes tests for related features like **WebXR immersive overlays**, **manifest fetching**, **reloading behavior**, **drag image generation**, **printing**, and **theme color handling**.

**Specific Functionalities and Examples:**

1. **Fullscreen API Testing:**
   - **Entering and Exiting Fullscreen:**  Tests if requesting fullscreen on an element (like the document element or a specific div) correctly makes that element fullscreen and if exiting works as expected.
     - **Example:** `TEST_F(WebFrameTest, FullscreenMainFrame)` checks if calling `RequestFullscreen` on the main document element makes it the fullscreen element. It then verifies that after resizing, the main frame remains scrollable.
     - **Assumption:**  Fullscreen requests require user activation.
     - **Input:** An HTML page is loaded. JavaScript (simulated by `LocalFrame::NotifyUserActivation`) triggers a fullscreen request.
     - **Output:** Assertions verify that `Fullscreen::FullscreenElementFrom()` returns the expected element and that scrollability is maintained.

   - **Fullscreen in Subframes (Iframes):** Checks if requesting fullscreen within an iframe works correctly and if the size of the fullscreen element is adjusted to the viewport.
     - **Example:** `TEST_F(WebFrameTest, FullscreenSubframe)` loads a page with an iframe, requests fullscreen on a div within the iframe, and verifies the div's dimensions match the viewport. It also tests how device rotation affects the fullscreen element's size.

   - **Nested Fullscreen:** Tests the scenario where a page and an iframe within it both enter fullscreen. It verifies that exiting fullscreen properly unwinds the nested state.
     - **Example:** `TEST_F(WebFrameTest, FullscreenNestedExit)` simulates entering fullscreen on the main document and then on an iframe's body. It then exits fullscreen and checks that no fullscreen elements remain in either document.

   - **Fullscreen with Tiny Viewports:** Examines how fullscreen behaves when the initial viewport is small (due to `<meta name="viewport">`). It checks if entering fullscreen overrides the viewport settings and restores them upon exiting.
     - **Example:** `TEST_F(WebFrameTest, FullscreenWithTinyViewport)` and `TEST_F(WebFrameTest, FullscreenResizeWithTinyViewport)` load a page with a small viewport, enter fullscreen, and verify the layout dimensions and page scale factors. They also test resizing while in fullscreen.

   - **Fullscreen and Page Scale Factors:**  Verifies that entering fullscreen sets the page scale factor to 1.0 and restores the original scale factor upon exiting. It also simulates scenarios with Android status bars affecting available screen space.
     - **Example:** `TEST_F(WebFrameTest, FullscreenRestoreScaleFactorUponExiting)` simulates real-world scenarios with status bars and verifies correct scale factor restoration.

   - **Fullscreen and Navigation:** Tests if navigating to a new page while in fullscreen correctly resets the fullscreen page scale constraints.
     - **Example:** `TEST_F(WebFrameTest, ClearFullscreenConstraintsOnNavigation)` loads a page, enters fullscreen, navigates to a new page, and verifies that the new page's scale constraints are not influenced by the previous fullscreen state.

   - **Fullscreen with Framesets:** Checks if requesting fullscreen on a `<frameset>` element works correctly.
     - **Example:** `TEST_F(WebFrameTest, FullscreenFrameSet)` requests fullscreen on a frameset and verifies it becomes the fullscreen element and is in the top layer.

2. **WebXR Immersive Overlay:**
   - Tests the functionality related to displaying elements as immersive overlays in WebXR experiences. This involves setting an element as an XR overlay and verifying how it affects compositing and the fullscreen state.
     - **Example:** `TEST_F(WebFrameTest, WebXrImmersiveOverlay)` sets a div as an XR overlay, enters fullscreen, and checks the composited layers and background color. It verifies that the overlay is only composited when in fullscreen.

3. **Visibility of Frames:**
   - Tests the `HasVisibleContent()` method for both visible and hidden frames (using CSS `visibility: hidden`).
     - **Example:** `TEST_F(WebFrameTest, HasVisibleContentOnVisibleFrames)` and `TEST_F(WebFrameTest, HasVisibleContentOnHiddenFrames)` load pages with visible and hidden iframes and verify the `HasVisibleContent()` result.

4. **Manifest Fetching:**
   - Tests the ability to fetch web app manifests and how Content Security Policy (CSP) affects these fetches.
     - **Example:** `TEST_F(WebFrameTest, ManifestFetch)` fetches a manifest and checks if it loads successfully. Other tests (`ManifestCSPFetchAllow`, `ManifestCSPFetchSelf`, `ManifestCSPFetchSelfReportOnly`) test different CSP directives for manifest sources.
     - **Assumption:**  Manifest fetching respects CSP rules.
     - **Input:** An HTML page with a link to a manifest file, possibly with CSP headers.
     - **Output:** Verification of whether the manifest is loaded successfully or if an error occurs due to CSP.

5. **Reload Bypassing Cache:**
   - Verifies that when a frame is reloaded bypassing the cache, the correct cache policy is set on the request.
     - **Example:** `TEST_F(WebFrameTest, ReloadBypassingCache)` initiates a reload bypassing the cache and checks the `FetchCacheMode`.

6. **Drag Image Generation:**
   - Tests the generation of drag images for DOM nodes in various scenarios, including CSS transformations (2D and 3D) and different layout types (inline-block, floats).
     - **Example:** `TEST_F(WebFrameTest, NodeImageTestCSSTransformDescendant)`, `TEST_F(WebFrameTest, NodeImageTestCSSTransform)`, etc., set up different HTML structures and CSS, then verify the generated drag image size and content.
     - **Assumption:** The generated drag image should accurately represent the visual appearance of the node.
     - **Input:** HTML with specific CSS styles applied to an element.
     - **Output:** Verification of the dimensions and pixel data of the generated `DragImage`.

7. **Basic Printing:**
   - Performs a simple test of the printing functionality.
     - **Example:** `TEST_F(WebFrameTest, PrintingBasic)` loads a basic HTML string and initiates printing, verifying the page count.

8. **Theme Color Handling:**
   - Tests how the `<meta name="theme-color">` tag is parsed and updated, including handling different color formats (RGB, HSL) and multiple theme-color tags.
     - **Example:** `TEST_F(WebFrameTest, ThemeColor)` loads a page with theme-color meta tags, uses JavaScript to modify them, and verifies that the `Document::ThemeColor()` reflects the correct value.
     - **Assumption:** The first valid theme-color meta tag is used.
     - **Input:** HTML with `<meta name="theme-color">` tags with different color values. JavaScript to modify these tags.
     - **Output:** Verification of the `Document::ThemeColor()` value after modifications.

9. **Frame Management (Detachment and Properties):**
   - Tests scenarios involving detaching frames and propagating frame owner properties (like `display: none`).
     - **Example:** `TEST_F(WebFrameTest, EmbedderTriggeredDetachWithRemoteMainFrame)` tests detaching a child frame. `TEST_F(WebFrameSwapTest, SwapMainFrame)` and related tests likely delve into frame swapping and property propagation, although the provided snippet cuts off before a complete example.

**Relationship to Javascript, HTML, and CSS:**

- **HTML:** The tests heavily rely on loading and manipulating HTML documents. They target specific HTML elements (`<div>`, `<iframe>`, `<frameset>`, `<meta>`) and their attributes.
- **CSS:**  CSS is used to style elements and influence layout, which is crucial for testing fullscreen behavior, drag image generation, and frame visibility. The `NodeImageTest` suite directly tests scenarios involving CSS transformations and layout properties.
- **Javascript:**  Javascript is used within the tests (simulated via `ExecuteScript`) to trigger actions like requesting fullscreen, modifying meta tags, and potentially interacting with the DOM in other ways.

**Logical Reasoning and Examples:**

- **Assumption:** Requesting fullscreen should make the targeted element fill the viewport.
  - **Input:** A web page with a `<div>` element and a button that calls `requestFullscreen()` on the `<div>`.
  - **Output:** After clicking the button, the `<div>` element should occupy the entire screen, and `document.fullscreenElement` in Javascript should point to that `<div>`.

- **Assumption:** Exiting fullscreen should revert the page to its previous state.
  - **Input:** A web page is in fullscreen mode. The user or script triggers the exit fullscreen action.
  - **Output:** The page should return to its original size and layout, and `document.fullscreenElement` should become `null`.

**Common Usage Errors:**

- **Attempting to request fullscreen without user activation:** Browsers typically require a user gesture (like a click or key press) to initiate fullscreen. Trying to call `requestFullscreen()` programmatically without such a gesture will often be blocked. The tests use `LocalFrame::NotifyUserActivation` to simulate this.
- **Misunderstanding viewport meta tags in fullscreen:** Developers might incorrectly assume that viewport settings continue to apply in fullscreen mode, leading to unexpected scaling or layout issues. The tests with "tiny viewports" highlight this.
- **Incorrectly handling nested fullscreen:**  Forgetting to exit fullscreen on inner frames before the outer frame can lead to unexpected behavior or a stuck fullscreen state. The `FullscreenNestedExit` test addresses this.
- **CSP configuration blocking manifest fetches:**  If the `manifest-src` directive in the Content Security Policy is not correctly configured, the browser will block the fetching of the web app manifest. The `ManifestCSPFetch` tests demonstrate this.

**Summary of Functionality:**

This section of `web_frame_test.cc` provides comprehensive tests for the fullscreen API in Blink, covering various scenarios and interactions with other web technologies. It also includes tests for related functionalities like WebXR overlays, manifest fetching, reloading, drag image generation, printing, and theme color handling, ensuring the correct behavior and robustness of these features within the Chromium rendering engine.

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第12部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
cumentElement(),
            Fullscreen::FullscreenElementFrom(*document));

  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(document->documentElement(),
            Fullscreen::FullscreenElementFrom(*document));

  // Verify that the main frame is still scrollable.
  scroll_node = GetScrollNode(*layout_view);
  ASSERT_TRUE(scroll_node->UserScrollableHorizontal());
  ASSERT_TRUE(scroll_node->UserScrollableVertical());

  // Verify the main frame still behaves correctly after a resize.
  web_view_helper.Resize(gfx::Size(viewport_height, viewport_width));
  scroll_node = GetScrollNode(*layout_view);
  ASSERT_TRUE(scroll_node->UserScrollableHorizontal());
  ASSERT_TRUE(scroll_node->UserScrollableVertical());
}

TEST_F(WebFrameTest, FullscreenSubframe) {
  RegisterMockedHttpURLLoad("fullscreen_iframe.html");
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_iframe.html", nullptr, nullptr, ConfigureAndroid);
  int viewport_width = 640;
  int viewport_height = 480;
  UpdateScreenInfoAndResizeView(&web_view_helper, viewport_width,
                                viewport_height);
  UpdateAllLifecyclePhases(web_view_impl);

  LocalFrame* frame =
      To<WebLocalFrameImpl>(
          web_view_helper.GetWebView()->MainFrame()->FirstChild())
          ->GetFrame();
  Document* document = frame->GetDocument();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Element* div_fullscreen = document->getElementById(AtomicString("div1"));
  Fullscreen::RequestFullscreen(*div_fullscreen);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);

  // Verify that the element is sized to the viewport.
  auto* fullscreen_layout_object =
      To<LayoutBox>(div_fullscreen->GetLayoutObject());
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalHeight().ToInt());

  // Verify it's updated after a device rotation.
  UpdateScreenInfoAndResizeView(&web_view_helper, viewport_height,
                                viewport_width);
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalHeight().ToInt());
}

// Tests entering nested fullscreen and then exiting via the same code path
// that's used when the browser process exits fullscreen.
TEST_F(WebFrameTest, FullscreenNestedExit) {
  RegisterMockedHttpURLLoad("fullscreen_iframe.html");
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "fullscreen_iframe.html");

  UpdateAllLifecyclePhases(web_view_impl);

  Document* top_doc = web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
  Element* top_body = top_doc->body();

  auto* iframe =
      To<HTMLIFrameElement>(top_doc->QuerySelector(AtomicString("iframe")));
  Document* iframe_doc = iframe->contentDocument();
  Element* iframe_body = iframe_doc->body();

  LocalFrame::NotifyUserActivation(
      top_doc->GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*top_body);

  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);

  LocalFrame::NotifyUserActivation(
      iframe_doc->GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*iframe_body);

  web_view_impl->DidEnterFullscreen();
  top_doc->GetAgent().event_loop()->PerformMicrotaskCheckpoint();
  UpdateAllLifecyclePhases(web_view_impl);

  // We are now in nested fullscreen, with both documents having a non-empty
  // fullscreen element stack.
  EXPECT_EQ(iframe, Fullscreen::FullscreenElementFrom(*top_doc));
  EXPECT_EQ(iframe_body, Fullscreen::FullscreenElementFrom(*iframe_doc));

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);

  // We should now have fully exited fullscreen.
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*top_doc));
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*iframe_doc));
}

TEST_F(WebFrameTest, FullscreenWithTinyViewport) {
  RegisterMockedHttpURLLoad("viewport-tiny.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-tiny.html", nullptr, nullptr, ConfigureAndroid);
  int viewport_width = 384;
  int viewport_height = 640;
  UpdateScreenInfoAndResizeView(&web_view_helper, viewport_width,
                                viewport_height);
  UpdateAllLifecyclePhases(web_view_impl);

  auto* layout_view = web_view_helper.GetWebView()
                          ->MainFrameImpl()
                          ->GetFrameView()
                          ->GetLayoutView();
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(533, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*frame->GetDocument()->documentElement());
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(384, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(640, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(533, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.2, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

TEST_F(WebFrameTest, FullscreenResizeWithTinyViewport) {
  RegisterMockedHttpURLLoad("viewport-tiny.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-tiny.html", nullptr, nullptr, ConfigureAndroid);
  int viewport_width = 384;
  int viewport_height = 640;
  UpdateScreenInfoAndResizeView(&web_view_helper, viewport_width,
                                viewport_height);
  UpdateAllLifecyclePhases(web_view_impl);

  auto* layout_view = web_view_helper.GetWebView()
                          ->MainFrameImpl()
                          ->GetFrameView()
                          ->GetLayoutView();
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*frame->GetDocument()->documentElement());
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(384, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(640, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  viewport_width = 640;
  viewport_height = 384;
  UpdateScreenInfoAndResizeView(&web_view_helper, viewport_width,
                                viewport_height);
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(640, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(384, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(192, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(2, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(2, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

TEST_F(WebFrameTest, FullscreenRestoreScaleFactorUponExiting) {
  // The purpose of this test is to more precisely simulate the sequence of
  // resize and switching fullscreen state operations on WebView, with the
  // interference from Android status bars like a real device does.
  // This verifies we handle the transition and restore states correctly.
  gfx::Size screen_size_minus_status_bars_minus_url_bar(598, 303);
  gfx::Size screen_size_minus_status_bars(598, 359);
  gfx::Size screen_size(640, 384);

  RegisterMockedHttpURLLoad("fullscreen_restore_scale_factor.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_restore_scale_factor.html", nullptr, nullptr,
      &ConfigureAndroid);
  UpdateScreenInfoAndResizeView(
      &web_view_helper, screen_size_minus_status_bars_minus_url_bar.width(),
      screen_size_minus_status_bars_minus_url_bar.height());
  auto* layout_view = web_view_helper.GetWebView()
                          ->MainFrameImpl()
                          ->GetFrameView()
                          ->GetLayoutView();
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.width(),
            layout_view->LogicalWidth().Floor());
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.height(),
            layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());

  {
    LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
    LocalFrame::NotifyUserActivation(
        frame, mojom::UserActivationNotificationType::kTest);
    Fullscreen::RequestFullscreen(*frame->GetDocument()->body());
  }

  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  UpdateScreenInfoAndResizeView(&web_view_helper,
                                screen_size_minus_status_bars.width(),
                                screen_size_minus_status_bars.height());
  UpdateScreenInfoAndResizeView(&web_view_helper, screen_size.width(),
                                screen_size.height());
  EXPECT_EQ(screen_size.width(), layout_view->LogicalWidth().Floor());
  EXPECT_EQ(screen_size.height(), layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  UpdateScreenInfoAndResizeView(&web_view_helper,
                                screen_size_minus_status_bars.width(),
                                screen_size_minus_status_bars.height());
  UpdateScreenInfoAndResizeView(
      &web_view_helper, screen_size_minus_status_bars_minus_url_bar.width(),
      screen_size_minus_status_bars_minus_url_bar.height());
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.width(),
            layout_view->LogicalWidth().Floor());
  EXPECT_EQ(screen_size_minus_status_bars_minus_url_bar.height(),
            layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

// Tests that leaving fullscreen by navigating to a new page resets the
// fullscreen page scale constraints.
TEST_F(WebFrameTest, ClearFullscreenConstraintsOnNavigation) {
  RegisterMockedHttpURLLoad("viewport-tiny.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  int viewport_width = 100;
  int viewport_height = 200;

  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-tiny.html", nullptr, nullptr, ConfigureAndroid);

  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  UpdateAllLifecyclePhases(web_view_impl);

  // viewport-tiny.html specifies a 320px layout width.
  auto* layout_view =
      web_view_impl->MainFrameImpl()->GetFrameView()->GetLayoutView();
  EXPECT_EQ(320, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(640, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(0.3125, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(0.3125, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*frame->GetDocument()->documentElement());
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);

  // Entering fullscreen causes layout size and page scale limits to be
  // overridden.
  EXPECT_EQ(100, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(200, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->PageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(1.0, web_view_impl->MaximumPageScaleFactor());

  const char kSource[] = "<meta name=\"viewport\" content=\"width=200\">";

  // Load a new page before exiting fullscreen.
  KURL test_url = ToKURL("about:blank");
  WebLocalFrame* web_frame = web_view_helper.LocalMainFrame();
  frame_test_helpers::LoadHTMLString(web_frame, kSource, test_url);
  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);

  // Make sure the new page's layout size and scale factor limits aren't
  // overridden.
  layout_view = web_view_impl->MainFrameImpl()->GetFrameView()->GetLayoutView();
  EXPECT_EQ(200, layout_view->LogicalWidth().Floor());
  EXPECT_EQ(400, layout_view->LogicalHeight().Floor());
  EXPECT_FLOAT_EQ(0.5, web_view_impl->MinimumPageScaleFactor());
  EXPECT_FLOAT_EQ(5.0, web_view_impl->MaximumPageScaleFactor());
}

TEST_F(WebFrameTest, WebXrImmersiveOverlay) {
  RegisterMockedHttpURLLoad("webxr_overlay.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "webxr_overlay.html", nullptr, nullptr);
  web_view_helper.Resize(gfx::Size(640, 480));

  // Ensure that the local frame view has a paint artifact compositor. It's
  // created lazily, and doing so after entering fullscreen would undo the
  // overlay layer modification.
  UpdateAllLifecyclePhases(web_view_impl);

  const cc::LayerTreeHost* layer_tree_host = web_view_helper.GetLayerTreeHost();

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();

  Element* overlay = document->getElementById(AtomicString("overlay"));
  EXPECT_FALSE(Fullscreen::IsFullscreenElement(*overlay));
  EXPECT_TRUE(layer_tree_host->background_color().isOpaque());

  // It's not legal to switch the fullscreen element while in immersive-ar mode,
  // so set the fullscreen element first before activating that. This requires
  // user activation.
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*overlay);
  EXPECT_FALSE(document->IsXrOverlay());
  document->SetIsXrOverlay(true, overlay);
  EXPECT_TRUE(document->IsXrOverlay());

  const cc::Layer* root_layer = layer_tree_host->root_layer();
  EXPECT_EQ(1u, CcLayersByName(root_layer,
                               "Scrolling background of LayoutView #document")
                    .size());
  EXPECT_EQ(1u, CcLayersByDOMElementId(root_layer, "other").size());
  // The overlay is not composited when it's not in full screen.
  EXPECT_EQ(0u, CcLayersByDOMElementId(root_layer, "overlay").size());
  EXPECT_EQ(1u, CcLayersByDOMElementId(root_layer, "inner").size());

  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_TRUE(Fullscreen::IsFullscreenElement(*overlay));
  EXPECT_TRUE(!layer_tree_host->background_color().isOpaque());

  root_layer = layer_tree_host->root_layer();
  EXPECT_EQ(0u, CcLayersByName(root_layer,
                               "Scrolling background of LayoutView #document")
                    .size());
  EXPECT_EQ(0u, CcLayersByDOMElementId(root_layer, "other").size());
  EXPECT_EQ(1u, CcLayersByDOMElementId(root_layer, "overlay").size());
  EXPECT_EQ(1u, CcLayersByDOMElementId(root_layer, "inner").size());

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_FALSE(Fullscreen::IsFullscreenElement(*overlay));
  EXPECT_TRUE(layer_tree_host->background_color().isOpaque());
  document->SetIsXrOverlay(false, overlay);

  root_layer = layer_tree_host->root_layer();
  EXPECT_EQ(1u, CcLayersByName(root_layer,
                               "Scrolling background of LayoutView #document")
                    .size());
  EXPECT_EQ(1u, CcLayersByDOMElementId(root_layer, "other").size());
  // The overlay is not composited when it's not in full screen.
  EXPECT_EQ(0u, CcLayersByDOMElementId(root_layer, "overlay").size());
  EXPECT_EQ(1u, CcLayersByDOMElementId(root_layer, "inner").size());
}

TEST_F(WebFrameTest, FullscreenFrameSet) {
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      "data:text/html,<frameset id=frameset></frameset>", nullptr, nullptr);
  web_view_helper.Resize(gfx::Size(640, 480));
  UpdateAllLifecyclePhases(web_view_impl);

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Element* frameset = document->getElementById(AtomicString("frameset"));
  Fullscreen::RequestFullscreen(*frameset);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(frameset, Fullscreen::FullscreenElementFrom(*document));
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(frameset, Fullscreen::FullscreenElementFrom(*document));

  // Verify that the element is in the top layer, attached to the LayoutView.
  EXPECT_TRUE(frameset->IsInTopLayer());
  auto* fullscreen_layout_object = To<LayoutBox>(frameset->GetLayoutObject());
  ASSERT_TRUE(fullscreen_layout_object);
  EXPECT_EQ(fullscreen_layout_object->Parent(), document->GetLayoutView());
}

TEST_F(WebFrameTest, HasVisibleContentOnVisibleFrames) {
  RegisterMockedHttpURLLoad("visible_frames.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "visible_frames.html");
  for (WebFrame* frame = web_view_impl->MainFrameImpl()->TraverseNext(); frame;
       frame = frame->TraverseNext()) {
    EXPECT_TRUE(frame->ToWebLocalFrame()->HasVisibleContent());
  }
}

TEST_F(WebFrameTest, HasVisibleContentOnHiddenFrames) {
  RegisterMockedHttpURLLoad("hidden_frames.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "hidden_frames.html");
  for (WebFrame* frame = web_view_impl->MainFrameImpl()->TraverseNext(); frame;
       frame = frame->TraverseNext()) {
    EXPECT_FALSE(frame->ToWebLocalFrame()->HasVisibleContent());
  }
}

static Resource* FetchManifest(Document* document, const KURL& url) {
  FetchParameters fetch_parameters =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_parameters.SetRequestContext(
      mojom::blink::RequestContextType::MANIFEST);

  return RawResource::FetchSynchronously(fetch_parameters, document->Fetcher());
}

TEST_F(WebFrameTest, ManifestFetch) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("link-manifest-fetch.json");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource =
      FetchManifest(document, ToKURL(base_url_ + "link-manifest-fetch.json"));

  EXPECT_TRUE(resource->IsLoaded());
}

TEST_F(WebFrameTest, ManifestCSPFetchAllow) {
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase(not_base_url_, "link-manifest-fetch.json");
  RegisterMockedHttpURLLoadWithCSP("foo.html", "manifest-src *");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource = FetchManifest(
      document, ToKURL(not_base_url_ + "link-manifest-fetch.json"));

  EXPECT_TRUE(resource->IsLoaded());
}

TEST_F(WebFrameTest, ManifestCSPFetchSelf) {
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase(not_base_url_, "link-manifest-fetch.json");
  RegisterMockedHttpURLLoadWithCSP("foo.html", "manifest-src 'self'");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource = FetchManifest(
      document, ToKURL(not_base_url_ + "link-manifest-fetch.json"));

  // Fetching resource wasn't allowed.
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->ErrorOccurred());
  EXPECT_TRUE(resource->GetResourceError().IsAccessCheck());
}

TEST_F(WebFrameTest, ManifestCSPFetchSelfReportOnly) {
  // TODO(crbug.com/751425): We should use the mock functionality
  // via the WebViewHelper instance in each test case.
  RegisterMockedURLLoadFromBase(not_base_url_, "link-manifest-fetch.json");
  RegisterMockedHttpURLLoadWithCSP("foo.html", "manifest-src 'self'",
                                   /* report only */ true);

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html");
  Document* document =
      web_view_helper.LocalMainFrame()->GetFrame()->GetDocument();

  Resource* resource = FetchManifest(
      document, ToKURL(not_base_url_ + "link-manifest-fetch.json"));

  EXPECT_TRUE(resource->IsLoaded());
}

TEST_F(WebFrameTest, ReloadBypassingCache) {
  // Check that a reload bypassing cache on a frame will result in the cache
  // policy of the request being set to ReloadBypassingCache.
  RegisterMockedHttpURLLoad("foo.html");
  TestBeginNavigationCacheModeClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "foo.html", &client);
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();
  frame_test_helpers::ReloadFrameBypassingCache(frame);
  EXPECT_EQ(mojom::FetchCacheMode::kBypassCache, client.GetCacheMode());
}

static void NodeImageTestValidation(const gfx::Size& reference_bitmap_size,
                                    DragImage* drag_image) {
  // Prepare the reference bitmap.
  SkBitmap bitmap;
  bitmap.allocN32Pixels(reference_bitmap_size.width(),
                        reference_bitmap_size.height());
  SkCanvas canvas(bitmap, SkSurfaceProps{});
  canvas.drawColor(SK_ColorGREEN);

  EXPECT_EQ(reference_bitmap_size.width(), drag_image->Size().width());
  EXPECT_EQ(reference_bitmap_size.height(), drag_image->Size().height());
  const SkBitmap& drag_bitmap = drag_image->Bitmap();
  EXPECT_EQ(0, memcmp(bitmap.getPixels(), drag_bitmap.getPixels(),
                      bitmap.computeByteSize()));
}

TEST_F(WebFrameTest, NodeImageTestCSSTransformDescendant) {
  frame_test_helpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image = NodeImageTestSetup(
      &web_view_helper, std::string("case-css-3dtransform-descendant"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(gfx::Size(40, 40), drag_image.get());
}

TEST_F(WebFrameTest, NodeImageTestCSSTransform) {
  frame_test_helpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image =
      NodeImageTestSetup(&web_view_helper, std::string("case-css-transform"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(gfx::Size(40, 40), drag_image.get());
}

TEST_F(WebFrameTest, NodeImageTestCSS3DTransform) {
  frame_test_helpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image =
      NodeImageTestSetup(&web_view_helper, std::string("case-css-3dtransform"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(gfx::Size(40, 40), drag_image.get());
}

TEST_F(WebFrameTest, NodeImageTestInlineBlock) {
  frame_test_helpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image =
      NodeImageTestSetup(&web_view_helper, std::string("case-inlineblock"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(gfx::Size(40, 40), drag_image.get());
}

TEST_F(WebFrameTest, NodeImageTestFloatLeft) {
  frame_test_helpers::WebViewHelper web_view_helper;
  std::unique_ptr<DragImage> drag_image = NodeImageTestSetup(
      &web_view_helper, std::string("case-float-left-overflow-hidden"));
  EXPECT_TRUE(drag_image);

  NodeImageTestValidation(gfx::Size(40, 40), drag_image.get());
}

// Crashes on Android: http://crbug.com/403804
#if BUILDFLAG(IS_ANDROID)
TEST_F(WebFrameTest, DISABLED_PrintingBasic)
#else
TEST_F(WebFrameTest, PrintingBasic)
#endif
{
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("data:text/html,Hello, world.");

  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  WebPrintParams print_params((gfx::SizeF(500, 500)));

  uint32_t page_count = frame->PrintBegin(print_params, WebNode());
  EXPECT_EQ(1u, page_count);
  frame->PrintEnd();
}

class ThemeColorTestLocalFrameHost : public FakeLocalFrameHost {
 public:
  ThemeColorTestLocalFrameHost() = default;
  ~ThemeColorTestLocalFrameHost() override = default;

  void Reset() { did_notify_ = false; }

  bool DidNotify() const { return did_notify_; }

 private:
  // FakeLocalFrameHost:
  void DidChangeThemeColor(std::optional<::SkColor> theme_color) override {
    did_notify_ = true;
  }

  bool did_notify_ = false;
};

TEST_F(WebFrameTest, ThemeColor) {
  RegisterMockedHttpURLLoad("theme_color_test.html");
  ThemeColorTestLocalFrameHost host;
  frame_test_helpers::TestWebFrameClient client;
  host.Init(client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "theme_color_test.html",
                                    &client);
  EXPECT_TRUE(host.DidNotify());
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ(SK_ColorBLUE, frame->GetDocument().ThemeColor());
  // Change color by rgb.
  host.Reset();
  frame->ExecuteScript(
      WebScriptSource("document.getElementById('tc1').setAttribute('content', "
                      "'rgb(0, 0, 0)');"));
  RunPendingTasks();
  EXPECT_TRUE(host.DidNotify());
  EXPECT_EQ(SK_ColorBLACK, frame->GetDocument().ThemeColor());
  // Change color by hsl.
  host.Reset();
  frame->ExecuteScript(
      WebScriptSource("document.getElementById('tc1').setAttribute('content', "
                      "'hsl(240,100%, 50%)');"));
  RunPendingTasks();
  EXPECT_TRUE(host.DidNotify());
  EXPECT_EQ(SK_ColorBLUE, frame->GetDocument().ThemeColor());
  // Change of second theme-color meta tag will not change frame's theme
  // color.
  host.Reset();
  frame->ExecuteScript(WebScriptSource(
      "document.getElementById('tc2').setAttribute('content', '#00FF00');"));
  RunPendingTasks();
  EXPECT_TRUE(host.DidNotify());
  EXPECT_EQ(SK_ColorBLUE, frame->GetDocument().ThemeColor());
  // Remove the first theme-color meta tag to apply the second.
  host.Reset();
  frame->ExecuteScript(
      WebScriptSource("document.getElementById('tc1').remove();"));
  RunPendingTasks();
  EXPECT_TRUE(host.DidNotify());
  EXPECT_EQ(SK_ColorGREEN, frame->GetDocument().ThemeColor());
  // Remove the name attribute of the remaining meta.
  host.Reset();
  frame->ExecuteScript(WebScriptSource(
      "document.getElementById('tc2').removeAttribute('name');"));
  RunPendingTasks();
  EXPECT_TRUE(host.DidNotify());
  EXPECT_EQ(std::nullopt, frame->GetDocument().ThemeColor());
}

// Make sure that an embedder-triggered detach with a remote frame parent
// doesn't leave behind dangling pointers.
TEST_F(WebFrameTest, EmbedderTriggeredDetachWithRemoteMainFrame) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebLocalFrame* child_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame());

  // Purposely keep the LocalFrame alive so it's the last thing to be destroyed.
  Persistent<Frame> child_core_frame = WebFrame::ToCoreFrame(*child_frame);
  helper.Reset();
  child_core_frame.Clear();
}

class WebFrameSwapTestClient : public frame_test_helpers::TestWebFrameClient {
 public:
  explicit WebFrameSwapTestClient(WebFrameSwapTestClient* parent = nullptr) {
    local_frame_host_ =
        std::make_unique<TestLocalFrameHostForFrameOwnerPropertiesChanges>(
            parent);
    local_frame_host_->Init(GetRemoteNavigationAssociatedInterfaces());
  }

  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType scope,
      const WebString& name,
      const WebString& fallback_name,
      const FramePolicy&,
      const WebFrameOwnerProperties&,
      FrameOwnerElementType,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      FinishChildFrameCreationFn finish_creation) override {
    return CreateLocalChild(
        *Frame(), scope, std::make_unique<WebFrameSwapTestClient>(this),
        std::move(policy_container_bind_params), finish_creation);
  }

  void DidChangeFrameOwnerProperties(
      mojom::blink::FrameOwnerPropertiesPtr properties) {
    did_propagate_display_none_ |= properties->is_display_none;
  }

  bool DidPropagateDisplayNoneProperty() const {
    return did_propagate_display_none_;
  }

 private:
  class TestLocalFrameHostForFrameOwnerPropertiesChanges
      : public FakeLocalFrameHost {
   public:
    explicit TestLocalFrameHostForFrameOwnerPropertiesChanges(
        WebFrameSwapTestClient* parent)
        : parent_(parent) {}
    ~TestLocalFrameHostForFrameOwnerPropertiesChanges() override = default;

    // FakeLocalFrameHost:
    void DidChangeFrameOwnerProperties(
        const blink::FrameToken& child_frame_token,
        mojom::blink::FrameOwnerPropertiesPtr properties) override {
      if (parent_)
        parent_->DidChangeFrameOwnerProperties(std::move(properties));
    }

    bool did_propagate_display_none_ = false;
    WebFrameSwapTestClient* parent_ = nullptr;
  };

  std::unique_ptr<TestLocalFrameHostForFrameOwnerPropertiesChanges>
      local_frame_host_;
  bool did_propagate_display_none_ = false;
};

class WebFrameSwapTest : public WebFrameTest {
 protected:
  WebFrameSwapTest() {
    RegisterMockedHttpURLLoad("frame-a-b-c.html");
    RegisterMockedHttpURLLoad("named-frame-a-b-c.html");
    RegisterMockedHttpURLLoad("subframe-a.html");
    RegisterMockedHttpURLLoad("subframe-b.html");
    RegisterMockedHttpURLLoad("subframe-c.html");
    RegisterMockedHttpURLLoad("subframe-hello.html");

    web_view_helper_.InitializeAndLoad(base_url_ + "frame-a-b-c.html",
                                       &main_frame_client_);
  }

  void Reset() { web_view_helper_.Reset(); }
  WebLocalFrame* MainFrame() const { return web_view_helper_.LocalMainFrame(); }
  WebViewImpl* WebView() const { return web_view_helper_.GetWebView(); }

 private:
  WebFrameSwapTestClient main_frame_client_;

 protected:
  // This must be destroyed before `main_frame_client_`; when the WebViewHelper
  // is deleted, it destroys child views that were created, but the list of
  // child views is maintained on `main_frame_client_`.
  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(WebFrameSwapTest, SwapMainFrame) {
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame(), remo
```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. The code appears to be testing scrolling-related features, specifically how touch and wheel events interact with different HTML structures and compositing scenarios.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core functionality:** The code is in `scrolling_test.cc`, and the tests are named like `ScrollingTest`, `IframeWindowTouchHandler`, `WheelEventRegion`, etc. This strongly suggests the primary function is testing scrolling behavior.

2. **Look for patterns in the tests:**  Many tests involve loading HTML, performing actions (often involving JavaScript event listeners), and then checking the state of the composited layers, particularly the `touch_action_region` and `wheel_event_region`. This indicates the tests are verifying how Blink handles input events related to scrolling.

3. **Identify key concepts:** The terms `touch_action_region`, `wheel_event_region`, "compositing", "main thread scroll hit test", "iframes", "plugins", "fixed positioning" appear repeatedly. These are the key areas being tested.

4. **Categorize the tests:** The tests seem to fall into several categories:
    * **Touch event handling:** How `touchstart` events and `touch-action` CSS property affect scrolling.
    * **Wheel event handling:** How `wheel` events are handled, including cases with `preventDefault()`.
    * **Interaction with iframes:** How scrolling and events propagate or are isolated within iframes.
    * **Interaction with plugins:** How plugins that need scroll events are handled.
    * **Non-composited scrolling:** Tests involving elements that are not composited, focusing on main-thread scroll hit testing.
    * **Visual updates during scrolling:** Tests involving visual changes like region capture and text selection during scrolling.

5. **Infer relationships to web technologies:**  The code interacts with HTML elements, CSS properties like `overflow`, `will-change`, `touch-action`, and JavaScript event listeners (`touchstart`, `wheel`). This establishes the connection to web development.

6. **Look for specific test scenarios:**  Tests often involve adding and removing event listeners, testing with and without `preventDefault()`, and testing different HTML structures (nested elements, fixed elements). This indicates the tests are exploring various edge cases and common web development patterns.

7. **Pay attention to `EXPECT_EQ` and `EXPECT_TRUE`:** These are assertion macros, showing what the expected outcome of each test is. For example, checking if a region is empty or has specific boundaries.

8. **Consider potential user/developer errors:** Tests involving `preventDefault()` highlight the importance of correctly handling these events to prevent default browser scrolling. The tests with non-composited elements and main-thread hit testing suggest scenarios where performance might be a concern if not handled correctly.

9. **Trace potential user actions:** Loading a webpage, interacting with scrollable elements via touch or mouse wheel, and the browser's need to determine how to handle these interactions are the user actions leading to the execution of this code.

10. **Formulate the summary:** Based on the above points, the summary should cover the main functionalities being tested, their relationship to web technologies, and any notable observations.
Based on the provided C++ code snippet from `blink/renderer/core/page/scrolling/scrolling_test.cc`, here's a summary of its functionality as part 2 of 5:

**Overall Functionality (Part 2):**

This section of the `scrolling_test.cc` file primarily focuses on testing the behavior of **touch and wheel event handling** in various scrolling scenarios within the Blink rendering engine. It examines how these events interact with different HTML structures, CSS properties, JavaScript event listeners, and the compositing process. A significant portion deals with defining and verifying the **regions that are considered targets for touch and wheel events**. It also delves into scenarios involving **non-composited scrolling** and how main-thread hit testing works in those cases.

**Specific Functionalities Covered:**

* **Touch Action Regions:**
    * Verifies that elements with `touch-action: none` correctly create touch action regions on their composited layers, preventing touch scrolling.
    * Tests how touch action regions are affected by the presence or absence of drawable content within a scrolling container.
    * Checks how touch event listeners (`touchstart` with `preventDefault()`) on iframes and the main window create touch action regions.
    * Examines the invalidation of touch action regions when touch event listeners are added or removed.
    * Tests the creation of touch action regions on elements even without content, when a blocking touch event listener is present.
    * Investigates how touch action regions are updated when a non-composited scrolling element's scroll position changes.

* **Wheel Event Regions:**
    * Verifies that elements with wheel event listeners (`wheel` with `preventDefault()`) create wheel event regions on their composited layers.
    * Tests the creation of wheel event regions on scrollable elements and their scrolling content layers.
    * Examines the invalidation of wheel event regions when wheel event listeners are added or removed.
    * Tests the creation of wheel event regions on elements even without content, when a blocking wheel event listener is present.
    * Checks how wheel event regions are formed when multiple elements have wheel event listeners within a scrollable container.
    * Investigates how wheel event regions are updated when a non-composited scrolling element's scroll position changes.
    * Confirms that box shadows are excluded from wheel event regions.
    * Tests how wheel event listeners on iframes and the main window create wheel event regions.

* **Interaction with Plugins:**
    * Ensures that the code handles scenarios where a plugin element becomes an inline layout object without crashing.
    * Verifies that wheel event regions are correctly generated for both fixed and in-flow plugins that require wheel events.

* **Non-Composited Scrolling and Hit Testing:**
    * Tests the creation of `main_thread_scroll_hit_test_region` and `non_composited_scroll_hit_test_rects` for scrollable elements that are not composited.
    * Examines how borders and border-radius affect the `main_thread_scroll_hit_test_region`.
    * Tests scenarios with nested non-composited scrollers and how their hit-test regions are determined.
    * Checks how covering elements (opaque or non-opaque) influence the fast non-composited scroll hit test regions.

* **Visual Updates during Scrolling:**
    * Tests how the capture bounds of a region captured element are updated during scrolling of non-composited elements.
    * Verifies how the position of text selection handles is updated during scrolling of non-composited elements.

**Relationship to JavaScript, HTML, and CSS:**

This test file heavily relies on JavaScript, HTML, and CSS concepts:

* **HTML:**  The tests use HTML to create various element structures (divs, iframes, objects) with different styling and nested relationships to simulate real-world web page layouts. The `id` attribute is used extensively to target specific elements for event listeners and layer retrieval.
* **CSS:** CSS properties like `width`, `height`, `overflow`, `will-change`, `touch-action`, `position`, `border`, `border-radius`, and `box-shadow` are used to control the appearance and scrolling behavior of elements, which are then tested for their impact on event handling and compositing.
* **JavaScript:** JavaScript is used to add event listeners (`touchstart`, `wheel`) to elements, often using `e.preventDefault()` to prevent default browser behavior and test how Blink handles these scenarios. The tests also manipulate the DOM (e.g., adding a label to a plugin) to trigger specific code paths.

**Examples:**

* **HTML & CSS (Touch Action):**
  ```html
  <div id="scrollable" style="overflow: scroll; touch-action: none;">
    <div id="content" style="height: 1000px;"></div>
  </div>
  ```
  This test verifies that because `#scrollable` has `touch-action: none`, a touch action region is created, preventing touch scrolling on this element.

* **JavaScript (Wheel Event):**
  ```javascript
  document.getElementById("scrollable").addEventListener('wheel', (e) => {
    e.preventDefault();
  });
  ```
  This JavaScript code, when included in the HTML, is used to test the creation of a wheel event region on the `#scrollable` element. The `preventDefault()` call is crucial for testing how Blink handles blocking wheel events.

**Logical Inferences (Hypothetical):**

* **Input:**  A user touches a scrollable area on a webpage where a `touchstart` event listener with `passive: false` and `preventDefault()` is attached to the window.
* **Output:** The test verifies that a touch action region encompassing the entire viewport (or relevant portion) is created on the main frame's scrolling contents layer, indicating that the touch event will be handled by the JavaScript and not the default scrolling mechanism.

* **Input:** A user uses the mouse wheel over an iframe that has a `wheel` event listener with `preventDefault()` attached to its window.
* **Output:** The test verifies that a wheel event region covering the iframe's content area is created on the iframe's scrolling contents layer, and that the main frame's wheel event region remains empty in that area, ensuring the wheel event is captured within the iframe.

**Common User/Programming Errors and Debugging Clues:**

* **Forgetting `preventDefault()` for blocking events:** If a developer intends to prevent default scrolling behavior for touch or wheel events but forgets to call `preventDefault()` in their event listener, the tests would likely show no corresponding touch/wheel action region being created. This highlights the importance of this call for controlling scrolling.
* **Incorrectly assuming passive listeners block scrolling:**  Using `passive: true` in event listeners means the listener cannot prevent the default action. The tests with `passive: false` demonstrate how to correctly block scrolling.
* **Overlapping event listeners:** If multiple elements with conflicting touch/wheel event listeners overlap, the tests help ensure that the correct event targeting and region creation logic is in place. The tests with nested elements exemplify this.
* **Debugging non-composited scrolling issues:** When dealing with non-composited scrolling, developers might encounter issues with hit testing and event handling. These tests provide a way to verify that the main-thread scroll hit test regions are correctly calculated, which is crucial for proper event routing.

**User Operation to Reach Here (Debugging Clues):**

A developer might be investigating issues related to:

1. **Unintentional scrolling prevention:**  A user might report that they cannot scroll a certain part of a webpage on a touch device, and the developer suspects a rogue `touchstart` listener is preventing default behavior. This would lead them to examine the code related to touch action regions.
2. **Unexpected wheel event behavior:** A user might experience that scrolling isn't working as expected when using the mouse wheel on a specific element. The developer might then look at how wheel event regions are being created and if any `wheel` listeners are interfering.
3. **Performance issues with non-composited scrolling:**  If a page has performance problems related to scrolling non-composited elements, a developer might investigate the `main_thread_scroll_hit_test_region` logic to optimize event handling in those areas.
4. **Issues with iframes and scrolling:** When scrolling within an iframe isn't working correctly, developers might use these tests as a reference to understand how scrolling contexts and event handling are isolated within iframes.
5. **Plugin interaction with scrolling:** If a plugin needs to handle scroll events, these tests help verify that the plugin is correctly receiving those events through the generated wheel event regions.

In essence, this part of the `scrolling_test.cc` file provides a comprehensive suite of tests to ensure the correct and efficient handling of touch and wheel events in various scrolling scenarios within the Blink rendering engine, covering both composited and non-composited content.

### 提示词
```
这是目录为blink/renderer/core/page/scrolling/scrolling_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ds(), gfx::Size(100, 150));
    EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 100, 150)), region);
  } else {
    // When HitTestOpaqueness is not enabled, the scrolling contents layer
    // contains only the drawable contents due to the lack of the hit test
    // data for the whole scrolling contents.
    EXPECT_EQ(scrolling_contents_layer->bounds(), gfx::Size(50, 150));
    EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 50, 150)), region);
  }

  const auto* container_layer = LayerByDOMElementId("scrollable");
  region = container_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kPanY | TouchAction::kInternalNotWritable);
  EXPECT_TRUE(region.IsEmpty());
  // TODO(crbug.com/324285520): Do we need touch action data in a ScrollHitTest
  // layer?
  EXPECT_EQ(container_layer->bounds(), gfx::Size(100, 100));

  // The area of the scroller (8,8 100x100) in the main frame scrolling
  // contents layer is also marked as pan-y.
  const auto* main_frame_scrolling_layer = MainFrameScrollingContentsLayer();
  region =
      main_frame_scrolling_layer->touch_action_region().GetRegionForTouchAction(
          TouchAction::kPanY | TouchAction::kInternalNotWritable);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 100)), region);
}

TEST_P(ScrollingTest, IframeWindowTouchHandler) {
  LoadHTML(R"HTML(
    <iframe style="width: 275px; height: 250px; will-change: transform">
    </iframe>
  )HTML");
  auto* child_frame =
      To<WebLocalFrameImpl>(GetWebView()->MainFrameImpl()->FirstChild());
  frame_test_helpers::LoadHTMLString(child_frame, R"HTML(
      <p style="margin: 1000px"> Hello </p>
      <script>
        window.addEventListener('touchstart', (e) => {
          e.preventDefault();
        }, {passive: false});
      </script>
    )HTML",
                                     url_test_helpers::ToKURL("about:blank"));
  ForceFullCompositingUpdate();

  const auto* child_cc_layer =
      FrameScrollingContentsLayer(*child_frame->GetFrame());
  cc::Region region_child_frame =
      child_cc_layer->touch_action_region().GetRegionForTouchAction(
          TouchAction::kNone);
  cc::Region region_main_frame =
      MainFrameScrollingContentsLayer()
          ->touch_action_region()
          .GetRegionForTouchAction(TouchAction::kNone);
  EXPECT_TRUE(region_main_frame.bounds().IsEmpty());
  EXPECT_FALSE(region_child_frame.bounds().IsEmpty());
  // We only check for the content size for verification as the offset is 0x0
  // due to child frame having its own composited layer.

  // Because touch action rects are painted on the scrolling contents layer,
  // the size of the rect should be equal to the entire scrolling contents area.
  EXPECT_EQ(gfx::Rect(child_cc_layer->bounds()), region_child_frame.bounds());
}

TEST_P(ScrollingTest, WindowTouchEventHandler) {
  LoadHTML(R"HTML(
    <style>
      html { width: 200px; height: 200px; }
      body { width: 100px; height: 100px; }
    </style>
    <script>
      window.addEventListener('touchstart', function(event) {
        event.preventDefault();
      }, {passive: false} );
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  auto* cc_layer = MainFrameScrollingContentsLayer();

  // The touch action region should include the entire frame, even though the
  // document is smaller than the frame.
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 320, 240)), region);
}

namespace {
class ScrollingTestMockEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event*) override {}
};
}  // namespace

TEST_P(ScrollingTest, WindowTouchEventHandlerInvalidation) {
  LoadHTML("");
  ForceFullCompositingUpdate();

  auto* cc_layer = MainFrameScrollingContentsLayer();

  // Initially there are no touch action regions.
  auto region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());

  // Adding a blocking window event handler should create a touch action region.
  auto* listener = MakeGarbageCollected<ScrollingTestMockEventListener>();
  auto* resolved_options =
      MakeGarbageCollected<AddEventListenerOptionsResolved>();
  resolved_options->setPassive(false);
  GetFrame()->DomWindow()->addEventListener(event_type_names::kTouchstart,
                                            listener, resolved_options);
  ForceFullCompositingUpdate();
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_FALSE(region.IsEmpty());

  // Removing the window event handler also removes the blocking touch action
  // region.
  GetFrame()->DomWindow()->RemoveAllEventListeners();
  ForceFullCompositingUpdate();
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_TRUE(region.IsEmpty());
}

TEST_P(ScrollingTest, TouchActionChangeWithoutContent) {
  LoadHTML(R"HTML(
    <div id="blocking"
        style="will-change: transform; width: 100px; height: 100px;"></div>
  )HTML");
  ForceFullCompositingUpdate();

  // Adding a blocking window event handler should create a touch action region.
  auto* listener = MakeGarbageCollected<ScrollingTestMockEventListener>();
  auto* resolved_options =
      MakeGarbageCollected<AddEventListenerOptionsResolved>();
  resolved_options->setPassive(false);
  auto* target_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("blocking"));
  target_element->addEventListener(event_type_names::kTouchstart, listener,
                                   resolved_options);
  ForceFullCompositingUpdate();

  const auto* cc_layer = LayerByDOMElementId("blocking");
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 100, 100)), region);
}

TEST_P(ScrollingTest, WheelEventRegion) {
  LoadHTML(R"HTML(
    <style>
      #scrollable {
        width: 200px;
        height: 200px;
        will-change: transform;
        overflow: scroll;
      }
      #content {
        width: 1000px;
        height: 1000px;
      }
    </style>
    <div id="scrollable">
      <div id="content"></div>
    </div>
    <script>
      document.getElementById("scrollable").addEventListener('wheel', (e) => {
        e.preventDefault();
      });
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());

  cc_layer = LayerByDOMElementId("scrollable");
  region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 200, 200)), region);

  cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");
  region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 1000, 1000)), region);
}

TEST_P(ScrollingTest, WheelEventHandlerInvalidation) {
  LoadHTML(R"HTML(
    <style>
      #scrollable {
        width: 200px;
        height: 200px;
        will-change: transform;
        overflow: scroll;
      }
      #content {
        width: 1000px;
        height: 1000px;
      }
    </style>
    <div id="scrollable">
      <div id="content"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  // Initially there are no wheel event regions.
  const auto* cc_layer = LayerByDOMElementId("scrollable");
  auto region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());

  const auto* cc_layer_content =
      ScrollingContentsLayerByDOMElementId("scrollable");
  region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());

  // Adding a blocking window event handler should create a wheel event region.
  auto* listener = MakeGarbageCollected<ScrollingTestMockEventListener>();
  auto* resolved_options =
      MakeGarbageCollected<AddEventListenerOptionsResolved>();
  resolved_options->setPassive(false);
  GetFrame()
      ->GetDocument()
      ->getElementById(AtomicString("scrollable"))
      ->addEventListener(event_type_names::kWheel, listener, resolved_options);
  ForceFullCompositingUpdate();
  region = cc_layer->wheel_event_region();
  EXPECT_FALSE(region.IsEmpty());
  region = cc_layer_content->wheel_event_region();
  EXPECT_FALSE(region.IsEmpty());

  // Removing the window event handler also removes the wheel event region.
  GetFrame()
      ->GetDocument()
      ->getElementById(AtomicString("scrollable"))
      ->RemoveAllEventListeners();
  ForceFullCompositingUpdate();
  region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());
  region = cc_layer_content->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());
}

TEST_P(ScrollingTest, WheelEventRegions) {
  LoadHTML(R"HTML(
    <style>
      #scrollable {
        width: 200px;
        height: 200px;
        will-change: transform;
        overflow: scroll;
      }
      #content {
        width: 1000px;
        height: 1000px;
      }
      .region {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id="scrollable">
      <div id="region1" class="region"></div>
      <div id="content"></div>
      <div id="region2" class="region"></div>
    </div>
    <script>
      document.getElementById("region1").addEventListener('wheel', (e) => {
        e.preventDefault();
      });
      document.getElementById("region2").addEventListener('wheel', (e) => {
        e.preventDefault();
      });
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  auto* cc_layer = LayerByDOMElementId("scrollable");
  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());

  cc_layer = ScrollingContentsLayerByDOMElementId("scrollable");
  region = cc_layer->wheel_event_region();

  EXPECT_EQ(RegionFromRects(
                {gfx::Rect(0, 0, 100, 100), gfx::Rect(0, 1100, 100, 100)}),
            region);
}

TEST_P(ScrollingTest, WheelEventRegionOnScrollWithoutDrawableContents) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <style>
      #noncomposited {
        width: 200px;
        height: 200px;
        overflow: auto;
        position: absolute;
        top: 50px;
      }
      #content {
        width: 100%;
        height: 1000px;
      }
      .region {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id="noncomposited">
      <div id="region" class="region"></div>
      <div id="content"></div>
    </div>
    <script>
      document.getElementById("region").addEventListener('wheel', (e) => {
        e.preventDefault();
      }, {passive: false});
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 100)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  Element* scrollable_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("noncomposited"));
  DCHECK(scrollable_element);

  // Change scroll position and verify that blocking wheel handler region is
  // updated accordingly.
  scrollable_element->setScrollTop(10.0);
  ForceFullCompositingUpdate();
  region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 90)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(ScrollingTest, WheelEventRegionOnScrollWithDrawableContents) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <style>
      #noncomposited {
        width: 200px;
        height: 200px;
        overflow: auto;
        position: absolute;
        top: 50px;
      }
      #content {
        width: 100%;
        height: 1000px;
        background: yellow;
      }
      .region {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id="noncomposited">
      <div id="region" class="region"></div>
      <div id="content"></div>
    </div>
    <script>
      document.getElementById("region").addEventListener('wheel', (e) => {
        e.preventDefault();
      }, {passive: false});
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 100)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  Element* scrollable_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("noncomposited"));
  ASSERT_TRUE(scrollable_element);

  scrollable_element->setScrollTop(10.0);
  ForceFullCompositingUpdate();
  region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 90)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(ScrollingTest, TouchActionRegionOnScrollWithoutDrawableContents) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <style>
      #noncomposited {
        width: 200px;
        height: 200px;
        overflow: auto;
        position: absolute;
        top: 50px;
      }
      #content {
        width: 100%;
        height: 1000px;
      }
      .region {
        width: 100px;
        height: 100px;
        touch-action: none;
      }
    </style>
    <div id="noncomposited">
      <div id="region" class="region"></div>
      <div id="content"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 100)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  Element* scrollable_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("noncomposited"));
  DCHECK(scrollable_element);

  // Change scroll position and verify that blocking wheel handler region is
  // updated accordingly.
  scrollable_element->setScrollTop(10.0);
  ForceFullCompositingUpdate();
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 90)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(ScrollingTest, TouchActionRegionOnScrollWithDrawableContents) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <style>
      #noncomposited {
        width: 200px;
        height: 200px;
        overflow: auto;
        position: absolute;
        top: 50px;
      }
      #content {
        width: 100%;
        height: 1000px;
        background: yellow;
      }
      .region {
        width: 100px;
        height: 100px;
        touch-action: none;
      }
    </style>
    <div id="noncomposited">
      <div id="region" class="region"></div>
      <div id="content"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();
  cc::Region region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 100)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  Element* scrollable_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("noncomposited"));
  ASSERT_TRUE(scrollable_element);

  scrollable_element->setScrollTop(10.0);
  ForceFullCompositingUpdate();
  region = cc_layer->touch_action_region().GetRegionForTouchAction(
      TouchAction::kNone);
  EXPECT_EQ(cc::Region(gfx::Rect(8, 50, 100, 90)), region);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("noncomposited"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(ScrollingTest, NonCompositedMainThreadRepaintWithCaptureRegion) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <div id="composited" style="width: 200px; height: 200px; overflow: scroll;
                                background: white">
      <div id="middle" style="width: 150px; height: 300px; overflow: scroll">
        <div id="inner" style="width: 100px; height: 400px; overflow: scroll">
          <div id="capture" style="width: 50px; height: 500px"></div>
          <div style="height: 1000px"></div>
        </div>
        <div style="height: 1000px"></div>
      </div>
    </div>
  )HTML");

  auto crop_id = base::Token::CreateRandom();
  Document& document = *GetFrame()->GetDocument();
  document.getElementById(AtomicString("capture"))
      ->SetRegionCaptureCropId(std::make_unique<RegionCaptureCropId>(crop_id));
  ForceFullCompositingUpdate();

  const cc::Layer* cc_layer =
      ScrollingContentsLayerByDOMElementId("composited");
  EXPECT_EQ(gfx::Rect(0, 0, 50, 300),
            cc_layer->capture_bounds().bounds().at(crop_id));
  ASSERT_COMPOSITED(ScrollNodeByDOMElementId("composited"));
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("middle"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("inner"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  document.getElementById(AtomicString("middle"))->setScrollTop(200);
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::Rect(0, 0, 50, 200),
            cc_layer->capture_bounds().bounds().at(crop_id));
  ASSERT_COMPOSITED(ScrollNodeByDOMElementId("composited"));
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("middle"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("inner"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  document.getElementById(AtomicString("inner"))->setScrollTop(200);
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::Rect(0, 0, 50, 100),
            cc_layer->capture_bounds().bounds().at(crop_id));
  ASSERT_COMPOSITED(ScrollNodeByDOMElementId("composited"));
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("middle"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("inner"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

TEST_P(ScrollingTest, NonCompositedMainThreadRepaintWithLayerSelection) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <div id="composited" style="width: 200px; height: 200px; overflow: scroll;
                                background: white">
      <div id="middle" style="width: 150px; height: 300px; overflow: scroll">
        <div id="inner" style="width: 100px; height: 400px; overflow: scroll">
          <div style="height: 150px"></div>
          <div id="text">TEXT</div>
          <div style="height: 1000px"></div>
        </div>
        <div style="height: 1000px"></div>
      </div>
    </div>
  )HTML");

  Document& document = *GetFrame()->GetDocument();
  document.GetPage()->GetFocusController().SetActive(true);
  document.GetPage()->GetFocusController().SetFocused(true);
  GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SelectAllChildren(*document.getElementById(AtomicString("text")))
          .Build(),
      SetSelectionOptions());
  GetFrame()->Selection().SetHandleVisibleForTesting();
  ForceFullCompositingUpdate();

  EXPECT_EQ(gfx::Point(0, 150), LayerTreeHost()->selection().start.edge_start);
  ASSERT_COMPOSITED(ScrollNodeByDOMElementId("composited"));
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("middle"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("inner"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  document.getElementById(AtomicString("middle"))->setScrollTop(50);
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::Point(0, 100), LayerTreeHost()->selection().start.edge_start);
  ASSERT_COMPOSITED(ScrollNodeByDOMElementId("composited"));
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("middle"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("inner"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);

  document.getElementById(AtomicString("inner"))->setScrollTop(50);
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::Point(0, 50), LayerTreeHost()->selection().start.edge_start);
  ASSERT_COMPOSITED(ScrollNodeByDOMElementId("composited"));
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("middle"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
  ASSERT_NOT_COMPOSITED(
      ScrollNodeByDOMElementId("inner"),
      cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText);
}

// Box shadow is not hit testable and should not be included in wheel region.
TEST_P(ScrollingTest, WheelEventRegionExcludesBoxShadow) {
  LoadHTML(R"HTML(
    <style>
      #shadow {
        width: 100px;
        height: 100px;
        box-shadow: 10px 5px 5px red;
      }
    </style>
    <div id="shadow"></div>
    <script>
      document.getElementById("shadow").addEventListener('wheel', (e) => {
        e.preventDefault();
      });
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = MainFrameScrollingContentsLayer();

  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(8, 8, 100, 100)), region);
}

TEST_P(ScrollingTest, IframeWindowWheelEventHandler) {
  LoadHTML(R"HTML(
    <iframe style="width: 275px; height: 250px; will-change: transform">
    </iframe>
  )HTML");
  auto* child_frame =
      To<WebLocalFrameImpl>(GetWebView()->MainFrameImpl()->FirstChild());
  frame_test_helpers::LoadHTMLString(child_frame, R"HTML(
      <p style="margin: 1000px"> Hello </p>
      <script>
        window.addEventListener('wheel', (e) => {
          e.preventDefault();
        }, {passive: false});
      </script>
    )HTML",
                                     url_test_helpers::ToKURL("about:blank"));
  ForceFullCompositingUpdate();

  const auto* child_cc_layer =
      FrameScrollingContentsLayer(*child_frame->GetFrame());
  cc::Region region_child_frame = child_cc_layer->wheel_event_region();
  cc::Region region_main_frame =
      MainFrameScrollingContentsLayer()->wheel_event_region();
  EXPECT_TRUE(region_main_frame.bounds().IsEmpty());
  EXPECT_FALSE(region_child_frame.bounds().IsEmpty());
  // We only check for the content size for verification as the offset is 0x0
  // due to child frame having its own composited layer.

  // Because blocking wheel rects are painted on the scrolling contents layer,
  // the size of the rect should be equal to the entire scrolling contents area.
  EXPECT_EQ(gfx::Rect(child_cc_layer->bounds()), region_child_frame.bounds());
}

TEST_P(ScrollingTest, WindowWheelEventHandler) {
  LoadHTML(R"HTML(
    <style>
      html { width: 200px; height: 200px; }
      body { width: 100px; height: 100px; }
    </style>
    <script>
      window.addEventListener('wheel', function(event) {
        event.preventDefault();
      }, {passive: false} );
    </script>
  )HTML");
  ForceFullCompositingUpdate();

  auto* cc_layer = MainFrameScrollingContentsLayer();

  // The wheel region should include the entire frame, even though the
  // document is smaller than the frame.
  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 320, 240)), region);
}

TEST_P(ScrollingTest, WindowWheelEventHandlerInvalidation) {
  LoadHTML("");
  ForceFullCompositingUpdate();

  auto* cc_layer = MainFrameScrollingContentsLayer();

  // Initially there are no wheel event regions.
  auto region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());

  // Adding a blocking window event handler should create a wheel event region.
  auto* listener = MakeGarbageCollected<ScrollingTestMockEventListener>();
  auto* resolved_options =
      MakeGarbageCollected<AddEventListenerOptionsResolved>();
  resolved_options->setPassive(false);
  GetFrame()->DomWindow()->addEventListener(event_type_names::kWheel, listener,
                                            resolved_options);
  ForceFullCompositingUpdate();
  region = cc_layer->wheel_event_region();
  EXPECT_FALSE(region.IsEmpty());

  // Removing the window event handler also removes the wheel event region.
  GetFrame()->DomWindow()->RemoveAllEventListeners();
  ForceFullCompositingUpdate();
  region = cc_layer->wheel_event_region();
  EXPECT_TRUE(region.IsEmpty());
}

TEST_P(ScrollingTest, WheelEventHandlerChangeWithoutContent) {
  LoadHTML(R"HTML(
    <div id="blocking"
        style="will-change: transform; width: 100px; height: 100px;"></div>
  )HTML");
  ForceFullCompositingUpdate();

  // Adding a blocking window event handler should create a wheel event region.
  auto* listener = MakeGarbageCollected<ScrollingTestMockEventListener>();
  auto* resolved_options =
      MakeGarbageCollected<AddEventListenerOptionsResolved>();
  resolved_options->setPassive(false);
  auto* target_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("blocking"));
  target_element->addEventListener(event_type_names::kWheel, listener,
                                   resolved_options);
  ForceFullCompositingUpdate();

  const auto* cc_layer = LayerByDOMElementId("blocking");
  cc::Region region = cc_layer->wheel_event_region();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 100, 100)), region);
}

// Ensure we don't crash when a plugin becomes a LayoutInline
TEST_P(ScrollingTest, PluginBecomesLayoutInline) {
  LoadHTML(R"HTML(
    <style>
      body {
        margin: 0;
        height: 3000px;
      }
    </style>
    <object id="plugin" type="application/x-webkit-test-plugin"></object>
    <script>
      document.getElementById("plugin")
              .appendChild(document.createElement("label"))
    </script>
  )HTML");

  // This test passes if it doesn't crash. We're trying to make sure
  // ScrollingCoordinator can deal with LayoutInline plugins when generating
  // MainThreadScrollHitTestRegion.
  auto* plugin = To<HTMLObjectElement>(
      GetFrame()->GetDocument()->getElementById(AtomicString("plugin")));
  ASSERT_TRUE(plugin->GetLayoutObject()->IsLayoutInline());
  ForceFullCompositingUpdate();
}

// Ensure blocking wheel event regions are correctly generated for both fixed
// and in-flow plugins that need them.
TEST_P(ScrollingTest, WheelEventRegionsForPlugins) {
  LoadHTML(R"HTML(
    <style>
      body {
        margin: 0;
        height: 3000px;
        /* Ensures the wheel hit test data doesn't conflict with this. */
        touch-action: none;
      }
      #plugin {
        width: 300px;
        height: 300px;
      }
      #pluginfixed {
        width: 200px;
        height: 200px;
      }
      #fixed {
        position: fixed;
        left: 300px;
      }
    </style>
    <div id="fixed">
      <object id="pluginfixed" type="application/x-webkit-test-plugin"></object>
    </div>
    <object id="plugin" type="application/x-webkit-test-plugin"></object>
  )HTML");

  auto* plugin = To<HTMLObjectElement>(
      GetFrame()->GetDocument()->getElementById(AtomicString("plugin")));
  auto* plugin_fixed = To<HTMLObjectElement>(
      GetFrame()->GetDocument()->getElementById(AtomicString("pluginfixed")));
  // Wheel event regions are generated for plugins that require wheel
  // events.
  plugin->OwnedPlugin()->SetWantsWheelEvents(true);
  plugin_fixed->OwnedPlugin()->SetWantsWheelEvents(true);

  ForceFullCompositingUpdate();

  // The non-fixed plugin should create a wheel event region in the
  // scrolling contents layer of the LayoutView.
  auto* viewport_non_fast_layer = MainFrameScrollingContentsLayer();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 300, 300)),
            viewport_non_fast_layer->wheel_event_region());

  // The fixed plugin should create a wheel event region in a fixed
  // cc::Layer.
  auto* fixed_layer = LayerByDOMElementId("fixed");
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 200, 200)),
            fixed_layer->wheel_event_region());
}

TEST_P(ScrollingTest, MainThreadScrollHitTestRegionWithBorder) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            body { margin: 0; }
            #scroller {
              height: 100px;
              width: 100px;
              overflow-y: scroll;
              border: 10px solid black;
            }
          </style>
          <div id="scroller">
            <div id="forcescroll" style="height: 1000px;"></div>
          </div>
      )HTML");
  ForceFullCompositingUpdate();

  auto* layer = MainFrameScrollingContentsLayer();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_TRUE(layer->main_thread_scroll_hit_test_region().IsEmpty());
    EXPECT_EQ(
        gfx::Rect(0, 0, 120, 120),
        layer->non_composited_scroll_hit_test_rects()->at(0).hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 120, 120)),
              layer->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(layer->non_composited_scroll_hit_test_rects()->empty());
  }
}

TEST_P(ScrollingTest, NonFastScrollableRegionWithBorderAndBorderRadius) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      body { margin: 0; }
      #scroller {
        height: 100px;
        width: 100px;
        overflow-y: scroll;
        border: 10px solid black;
        /* Make the box not eligible for fast scroll hit test. */
        border-radius: 5px;
      }
    </style>
    <div id="scroller">
      <div id="forcescroll" style="height: 1000px;"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  auto* layer = MainFrameScrollingContentsLayer();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 120, 120)),
            layer->main_thread_scroll_hit_test_region());
  EXPECT_TRUE(layer->non_composited_scroll_hit_test_rects()->empty());
}

TEST_P(ScrollingTest, FastNonCompositedScrollHitTest) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!doctype html>
    <style>
      body { margin: 50px; }
      .scroller { width: 100px; height: 100px; overflow: scroll; }
      .content { height: 1000px; position: relative; opacity: 0.5; }
    </style>
    <!-- 50,50 100x100 -->
    <div id="standalone" class="scroller">
      <div class="content"></div>
    </div>
    <!-- 50,150 100x100 -->
    <div id="nested-parent" class="scroller">
      <div id="nested-child" class="scroller">
        <div class="content"></div>
      </div>
      <div class="content"></div>
    </div>
    <!-- 50,250 100x100 -->
    <div id="covered1" class="scroller">
      <div class="content"></div>
    </div>
    <!-- This partly covers `covered1` -->
    <div style="position: absolute;
                top: 250px; left: 0; width: 100px; height: 50px">
    </div>
    <!-- 50,350 100x100 -->
    <div id="covered2" class="scroller">
      <div class="content"></div>
    </div>
    <!-- This scroller partly covers `covered2`, opaque to hit test. -->
    <div id="covering2" class="scroller"
         style="position: absolute; top: 350px; left: 0;
                width: 100px; height: 50px">
      <div class="content"></div>
    </div>
    <!-- 50,450 100x100 -->
    <div id="covered3" class="scroller">
      <div class="content"></div>
    </div>
    <!-- This scroller partly covers `covered3`, not opaque to hit test. -->
    <div id="covering3" class="scroller"
         style="position: absolute; top: 450px; left: 0;
                width: 100px; height: 50px; border-radius: 10px">
      <div class="content"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  auto* layer = MainFrameScrollingContentsLayer();
  const cc::Region& non_fast_region =
      layer->main_thread_scroll_hit_test_region();
  const std::vector<cc::ScrollHitTestRect>* scroll_hit_test_rects =
      layer->non_composited_scroll_hit_test_rects();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    cc::Region expected_non_fast_region(gfx::Rect(50, 150, 100, 400));
    EXPECT_EQ(RegionFromRects(
                  {// nested-pare
```
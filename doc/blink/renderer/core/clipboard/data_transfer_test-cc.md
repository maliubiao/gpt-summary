Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Initial Understanding of the Context:** The file path `blink/renderer/core/clipboard/data_transfer_test.cc` immediately suggests this is a test file within the Blink rendering engine (part of Chromium). The `clipboard` directory hints at functionality related to copy/paste and drag-and-drop operations. The `data_transfer` part likely refers to the object that manages the data being transferred during these operations. The `_test.cc` suffix confirms it's a testing file.

2. **High-Level Goal:** The primary goal of this file is to test the `DataTransfer` class, specifically its ability to create "drag images" from DOM nodes. This implies the tests will involve setting up various DOM structures and verifying the properties of the generated drag images (size, content, etc.).

3. **Dissecting the Code - Structure and Key Classes:**

   * **Includes:** The included headers provide valuable clues. `DataTransfer.h` is the class being tested. `gtest/gtest.h` indicates the use of Google Test framework. Other includes like `css/properties/longhands.h`, `dom/element.h`, `frame/...`, `layout/...`, `paint/...`, and `testing/...` point to the involved components: CSS styling, DOM manipulation, frame management, layout calculations, painting/rendering, and testing utilities.
   * **Namespace:** `namespace blink` clarifies the context.
   * **Test Fixture:** The `DataTransferTest` class inheriting from `PaintTestConfigurations` and `RenderingTest` is a standard pattern in Blink testing. It provides setup and utility methods for rendering tests. The `GetPage()`, `GetFrame()` methods are helper functions to access core objects.
   * **`INSTANTIATE_PAINT_TEST_SUITE_P(DataTransferTest);`:** This suggests parameterized testing, but the parameters aren't explicitly used in these tests, so it's less critical for understanding the *functionality* being tested right now. It's more about the *testing infrastructure*.
   * **Individual `TEST_P` functions:**  Each `TEST_P` function focuses on a specific aspect of drag image creation. The name of the test function usually gives a good hint about the scenario being tested (e.g., `NodeImage`, `NodeImageWithNestedElement`, `NodeImageWithPsuedoClassWebKitDrag`).

4. **Analyzing Individual Tests - Identifying Functionality and Relationships:**

   * **`NodeImage`:** Basic test. Creates a simple div and checks if the `NodeImage` method returns a `DragImage` with the correct size. This directly tests the core function of creating a drag image from an element.
   * **`NodeImageWithNestedElement`:** Introduces CSS styling (`-webkit-user-drag`, `:-webkit-drag`). Verifies that the styling of descendant elements is considered during drag image creation. This shows the interaction with CSS.
   * **`NodeImageWithPsuedoClassWebKitDrag`:** Tests the specific CSS pseudo-class `:-webkit-drag`, demonstrating how it can alter the appearance of the dragged image. Another CSS interaction.
   * **`NodeImageWithoutDraggedLayoutObject`:** Checks the behavior when `:-webkit-drag` causes the element to have no layout object (e.g., `display: none`). Tests error handling or specific logic for this case.
   * **`NodeImageWithChangingLayoutObject`:** Focuses on how `:-webkit-drag` can change the layout object of an element and how this impacts the drag image and subsequent rendering.
   * **Tests involving viewport bounds, scroll offset, page scale factor:** These tests explore how the position and scaling of the viewport affect the size and rendering of the drag image. They bring in concepts related to how the browser renders content and handles scrolling and zooming.
   * **Tests involving offscreen elements, scrolling, stacking contexts, positioned descendants:** These delve into more complex rendering scenarios and how the drag image captures the visual representation of the element in these situations.
   * **`NodeImageFixedChild`:** Specifically tests how absolutely positioned and fixed-position elements within the dragged node are rendered in the drag image.
   * **`CreateDragImageWithEmptyImageResource`:** Tests a specific edge case related to setting a drag image resource.
   * **`NodeImageTranslatedOutOfView`:** Tests how CSS `transform: translate` affects the rendering of the drag image, particularly when the element is moved outside the viewport.

5. **Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

   * **HTML:** The test setup heavily relies on creating HTML elements (`<div>`, `<span>`) using `SetBodyInnerHTML`. The structure of the HTML directly influences what the `NodeImage` function processes.
   * **CSS:**  Several tests explicitly use CSS styling (`<style>`) to change the appearance and layout of elements. The `-webkit-drag` property and pseudo-class are key examples. This highlights how CSS properties affect the generated drag image.
   * **JavaScript:** While the test file itself is C++, some tests mention JavaScript event handlers (`ondragstart="drag(event)"`). This suggests that the underlying drag-and-drop functionality is exposed to JavaScript, even though this particular test file focuses on the C++ implementation of drag image creation. The connection is less direct in this *specific* test file but important in the broader context of web development.

6. **Considering User and Programming Errors:**

   * **User Error:**  A user might expect the drag image to perfectly mirror the element on the page *at all times*. However, things like CSS `transition` effects active during a drag operation might not be fully captured in a static drag image.
   * **Programming Error:** A developer might assume the drag image will always have the exact dimensions of the original element without considering the impact of `:-webkit-drag` or nested elements. They might also incorrectly assume that elements with `display: none` due to `:-webkit-drag` will still produce a drag image.

7. **Tracing User Actions (Debugging Clues):**

   * The core user action is *dragging an element*.
   * The `draggable="true"` attribute on HTML elements makes them draggable.
   * The `ondragstart` event (often handled by JavaScript) is triggered when the drag operation begins.
   * The browser then needs to create a visual representation of the dragged element – this is where the `DataTransfer::NodeImage` function comes into play. Debugging would involve stepping through the `NodeImage` function to see how the drag image is constructed based on the element's properties and CSS styles.

8. **Refinement and Organization:** After analyzing the code, it's important to organize the findings into logical categories like "Functionality," "Relationships," "Assumptions and Outputs," "Errors," and "Debugging."  This structured approach makes the analysis clearer and easier to understand.

By following these steps, we can systematically understand the purpose and functionality of a complex C++ test file within a large project like Chromium. The key is to start with the high-level context, dissect the code into smaller parts, identify the core functionality being tested, and then connect it back to the relevant web technologies and potential user/developer issues.
This C++ source code file `data_transfer_test.cc` within the Chromium Blink engine is part of the unit testing framework for the `DataTransfer` class. The `DataTransfer` class is responsible for managing the data being transferred during drag-and-drop operations and clipboard interactions in a web browser.

Here's a breakdown of its functionalities and connections:

**Core Functionality:**

The primary function of this test file is to verify the correctness of the `DataTransfer::NodeImage()` method. This method is crucial for creating a visual representation (a bitmap image) of a DOM node that is being dragged. The tests cover various scenarios to ensure this image is generated correctly under different conditions.

**Relationship with JavaScript, HTML, and CSS:**

This test file directly interacts with JavaScript, HTML, and CSS concepts:

* **HTML:** The tests use HTML snippets (within the `SetBodyInnerHTML` calls) to create the DOM structure that will be used to generate the drag image. The presence and attributes of HTML elements directly influence the output of `NodeImage()`.
    * **Example:** The `<div id=sample></div>` in many tests sets up a basic element to be dragged.
    * **Example:** The `draggable="true"` attribute (although not directly tested in this file's methods, it's the trigger for drag-and-drop functionality) is implied.
* **CSS:** CSS styles are heavily used to influence the appearance and layout of the elements being dragged. The tests specifically check how CSS properties, including pseudo-classes like `:-webkit-drag`, affect the generated drag image.
    * **Example:** The test `NodeImageWithPsuedoClassWebKitDrag` verifies that styles applied using `:-webkit-drag` are reflected in the drag image's dimensions.
    * **Example:** The test `NodeImageWithNestedElement` checks if styles on descendant elements are considered.
* **JavaScript:** While this test file is written in C++, it tests functionality that is directly related to the JavaScript Drag and Drop API. The `DataTransfer` object is often manipulated through JavaScript during drag-and-drop events.
    * **Example:**  The comments in some tests mention `ondragstart`, which is a JavaScript event handler that is crucial for initiating a drag operation. The drag image created by `DataTransfer::NodeImage()` is the visual feedback users see during this JavaScript-driven process.

**Logic Reasoning and Examples:**

The tests perform logical reasoning by setting up specific HTML/CSS scenarios (input) and then asserting the expected properties of the generated `DragImage` (output).

* **Assumption:**  If an element has `width: 100px` and `height: 100px`, then `DataTransfer::NodeImage()` should produce a `DragImage` with a size of 100x100 pixels.
    * **Input:**
      ```html
      <style>
        #sample { width: 100px; height: 100px; }
      </style>
      <div id=sample></div>
      ```
    * **Output:** `EXPECT_EQ(gfx::Size(100, 100), image->Size());`

* **Assumption:** The `:-webkit-drag` pseudo-class should modify the appearance of the element *only* during a drag operation, and this change should be reflected in the drag image.
    * **Input:**
      ```html
      <style>
        #sample { width: 100px; height: 100px; }
        #sample:-webkit-drag { width: 200px; height: 200px; }
      </style>
      <div id=sample></div>
      ```
    * **Output:** `EXPECT_EQ(gfx::Size(200, 200), image->Size());`

* **Assumption:** If `:-webkit-drag` sets `display: none`, the element has no layout object during the drag, and `NodeImage()` should return null.
    * **Input:**
      ```html
      <style>
        #sample { width: 100px; height: 100px; }
        #sample:-webkit-drag { display:none }
      </style>
      <div id=sample></div>
      ```
    * **Output:** `EXPECT_EQ(nullptr, image.get());`

**User and Programming Common Errors:**

* **User Error:** A user might expect the drag image to perfectly represent the element's appearance at all times, even with complex CSS animations or transitions. However, `NodeImage()` likely captures a static representation at the start of the drag.
* **Programming Error:**
    * **Incorrectly assuming `:-webkit-drag` styles are always applied:** Developers might forget that `:-webkit-drag` only applies during the drag operation. Styles defined within it won't affect the element's normal rendering.
    * **Not considering the impact of nested elements and stacking contexts:** The tests cover scenarios where nested elements or elements in different stacking contexts can influence the size and content of the drag image. Developers need to be aware of these factors.
    * **Forgetting about viewport, scroll, and zoom:** The tests for `NodeImageExceedsViewportBounds`, `NodeImageUnderScrollOffset`, and `NodeImageSizeWithPageScaleFactor` highlight the importance of considering the visible portion of the page and any scaling factors when generating the drag image. A common error would be to assume the drag image always has the element's intrinsic size, ignoring these factors.

**User Operations Leading to This Code (Debugging Clues):**

This code is executed as part of the browser's internal drag-and-drop mechanism. Here's how a user operation might lead to the execution of `DataTransfer::NodeImage()` which is tested here:

1. **User selects an element:** The user clicks and holds the mouse button down on an element that has the `draggable="true"` attribute (or a default draggable element like an image or link).
2. **User starts dragging:** The user moves the mouse while holding the button down. This triggers a drag operation.
3. **Browser initiates drag:** The browser's rendering engine detects the drag event.
4. **`dragstart` event:** A `dragstart` JavaScript event is fired on the dragged element. JavaScript code might manipulate the `DataTransfer` object associated with this event.
5. **Creating the drag image:** The browser needs to visually represent the dragged element. Internally, the `DataTransfer` object (or a related component) will call `DataTransfer::NodeImage()` to capture a bitmap of the dragged element. This is where the code being tested comes into play.
6. **Displaying the drag image:** The generated `DragImage` is then displayed under the user's cursor as they continue to drag.

**Debugging Steps (if an issue is suspected with drag image creation):**

1. **Inspect the `dragstart` event:** Use browser developer tools to inspect the `dragstart` event and the associated `DataTransfer` object. Check if any custom drag image is being set via JavaScript.
2. **Breakpoints in `DataTransfer::NodeImage()`:** If no custom image is being set, set a breakpoint in the `DataTransfer::NodeImage()` method in the Chromium source code.
3. **Step through the code:**  Step through the code to see how the drag image is being generated for the specific element being dragged. Observe the values of relevant variables like element dimensions, applied styles, and viewport information.
4. **Verify layout and paint:** Ensure the element being dragged has a valid layout object and can be painted correctly. Issues with layout or painting can lead to incorrect drag images.
5. **Check CSS styles:** Carefully examine the CSS styles applied to the dragged element and any relevant parent or descendant elements, especially styles related to `-webkit-drag`.
6. **Consider stacking contexts:** If the drag image appears incorrect in terms of layering, investigate the stacking contexts of the dragged element and its ancestors.

In summary, `data_transfer_test.cc` is a crucial part of ensuring the correctness of the drag-and-drop functionality in Chromium by specifically testing how the browser generates the visual representation of dragged elements, taking into account HTML structure, CSS styling, and various rendering complexities.

### 提示词
```
这是目录为blink/renderer/core/clipboard/data_transfer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/clipboard/data_transfer.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/drag_image.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"

namespace blink {

class DataTransferTest : public PaintTestConfigurations, public RenderingTest {
 protected:
  Page& GetPage() const { return *GetDocument().GetPage(); }
  LocalFrame& GetFrame() const { return *GetDocument().GetFrame(); }
};

INSTANTIATE_PAINT_TEST_SUITE_P(DataTransferTest);

TEST_P(DataTransferTest, NodeImage) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #sample { width: 100px; height: 100px; }
    </style>
    <div id=sample></div>
  )HTML");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const std::unique_ptr<DragImage> image =
      DataTransfer::NodeImage(GetFrame(), *sample);
  EXPECT_EQ(gfx::Size(100, 100), image->Size());
}

TEST_P(DataTransferTest, NodeImageWithNestedElement) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div { -webkit-user-drag: element }
      span:-webkit-drag { color: #0F0 }
    </style>
    <div id=sample><span>Green when dragged</span></div>
  )HTML");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const std::unique_ptr<DragImage> image =
      DataTransfer::NodeImage(GetFrame(), *sample);
  EXPECT_EQ(Color::FromRGB(0, 255, 0),
            sample->firstChild()->GetLayoutObject()->ResolveColor(
                GetCSSPropertyColor()))
      << "Descendants node should have :-webkit-drag.";
}

TEST_P(DataTransferTest, NodeImageWithPsuedoClassWebKitDrag) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #sample { width: 100px; height: 100px; }
      #sample:-webkit-drag { width: 200px; height: 200px; }
    </style>
    <div id=sample></div>
  )HTML");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const std::unique_ptr<DragImage> image =
      DataTransfer::NodeImage(GetFrame(), *sample);
  EXPECT_EQ(gfx::Size(200, 200), image->Size())
      << ":-webkit-drag should affect dragged image.";
}

TEST_P(DataTransferTest, NodeImageWithoutDraggedLayoutObject) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #sample { width: 100px; height: 100px; }
      #sample:-webkit-drag { display:none }
    </style>
    <div id=sample></div>
  )HTML");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  const std::unique_ptr<DragImage> image =
      DataTransfer::NodeImage(GetFrame(), *sample);
  EXPECT_EQ(nullptr, image.get()) << ":-webkit-drag blows away layout object";
}

TEST_P(DataTransferTest, NodeImageWithChangingLayoutObject) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #sample { color: blue; }
      #sample:-webkit-drag { display: inline-block; color: red; }
    </style>
    <span id=sample>foo</span>
  )HTML");
  Element* sample = GetDocument().getElementById(AtomicString("sample"));
  UpdateAllLifecyclePhasesForTest();
  LayoutObject* before_layout_object = sample->GetLayoutObject();
  const std::unique_ptr<DragImage> image =
      DataTransfer::NodeImage(GetFrame(), *sample);

  EXPECT_TRUE(sample->GetLayoutObject() != before_layout_object)
      << ":-webkit-drag causes sample to have different layout object.";
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            sample->GetLayoutObject()->ResolveColor(GetCSSPropertyColor()))
      << "#sample has :-webkit-drag.";

  // Layout w/o :-webkit-drag
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            sample->GetLayoutObject()->ResolveColor(GetCSSPropertyColor()))
      << "#sample doesn't have :-webkit-drag.";
}

TEST_P(DataTransferTest, NodeImageExceedsViewportBounds) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #node { width: 2000px; height: 2000px; }
    </style>
    <div id='node'></div>
  )HTML");
  Element& node = *GetDocument().getElementById(AtomicString("node"));
  const auto image = DataTransfer::NodeImage(GetFrame(), node);
  EXPECT_EQ(gfx::Size(2000, 2000), image->Size());
}

TEST_P(DataTransferTest, NodeImageUnderScrollOffset) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #first { width: 500px; height: 500px; }
      #second { width: 800px; height: 900px; }
    </style>
    <div id='first'></div>
    <div id='second'></div>
  )HTML");

  const int scroll_amount = 10;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_amount), mojom::blink::ScrollType::kProgrammatic);

  // The first div should be offset by the scroll offset.
  Element& first = *GetDocument().getElementById(AtomicString("first"));
  const auto first_image = DataTransfer::NodeImage(GetFrame(), first);
  const int first_height = 500;
  EXPECT_EQ(gfx::Size(500, first_height), first_image->Size());

  // The second div should also be offset by the scroll offset. In addition,
  // the second div should be clipped by the viewport.
  Element& second = *GetDocument().getElementById(AtomicString("second"));
  const auto second_image = DataTransfer::NodeImage(GetFrame(), second);
  EXPECT_EQ(gfx::Size(800, 900), second_image->Size());
}

TEST_P(DataTransferTest, NodeImageSizeWithPageScaleFactor) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      #node { width: 200px; height: 141px; }
    </style>
    <div id='node'></div>
  )HTML");
  const int page_scale_factor = 2;
  GetPage().SetPageScaleFactor(page_scale_factor);
  Element& node = *GetDocument().getElementById(AtomicString("node"));
  const auto image = DataTransfer::NodeImage(GetFrame(), node);
  const int node_width = 200;
  const int node_height = 141;
  EXPECT_EQ(gfx::Size(node_width * page_scale_factor,
                      node_height * page_scale_factor),
            image->Size());

  // Check that a scroll offset is scaled to device coordinates which includes
  // page scale factor.
  const int scroll_amount = 10;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_amount), mojom::blink::ScrollType::kProgrammatic);
  const auto image_with_offset = DataTransfer::NodeImage(GetFrame(), node);
  EXPECT_EQ(gfx::Size(node_width * page_scale_factor,
                      node_height * page_scale_factor),
            image_with_offset->Size());
}

TEST_P(DataTransferTest, NodeImageSizeWithPageScaleFactorTooLarge) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      #node { width: 800px; height: 601px; }
    </style>
    <div id='node'></div>
  )HTML");
  const int page_scale_factor = 2;
  GetPage().SetPageScaleFactor(page_scale_factor);
  Element& node = *GetDocument().getElementById(AtomicString("node"));
  const auto image = DataTransfer::NodeImage(GetFrame(), node);
  const int node_width = 800;
  const int node_height = 601;
  EXPECT_EQ(gfx::Size(node_width * page_scale_factor,
                      node_height * page_scale_factor),
            image->Size());

  // Check that a scroll offset is scaled to device coordinates which includes
  // page scale factor.
  const int scroll_amount = 10;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_amount), mojom::blink::ScrollType::kProgrammatic);
  const auto image_with_offset = DataTransfer::NodeImage(GetFrame(), node);
  EXPECT_EQ(gfx::Size(node_width * page_scale_factor,
                      node_height * page_scale_factor),
            image_with_offset->Size());
}

TEST_P(DataTransferTest, NodeImageWithPageScaleFactor) {
  // #bluegreen is a 2x1 rectangle where the left pixel is blue and the right
  // pixel is green. The element is offset by a margin of 1px.
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #bluegreen {
        width: 1px;
        height: 1px;
        background: #0f0;
        border-left: 1px solid #00f;
        margin: 1px;
      }
    </style>
    <div id='bluegreen'></div>
  )HTML");
  const int page_scale_factor = 2;
  GetPage().SetPageScaleFactor(page_scale_factor);
  Element& blue_green =
      *GetDocument().getElementById(AtomicString("bluegreen"));
  const auto image = DataTransfer::NodeImage(GetFrame(), blue_green);
  const int blue_green_width = 2;
  const int blue_green_height = 1;
  EXPECT_EQ(gfx::Size(blue_green_width * page_scale_factor,
                      blue_green_height * page_scale_factor),
            image->Size());

  // Even though #bluegreen is offset by a margin of 1px (which is 2px in device
  // coordinates), we expect it to be painted at 0x0 and completely fill the 4x2
  // bitmap.
  SkBitmap expected_bitmap;
  expected_bitmap.allocN32Pixels(4, 2);
  expected_bitmap.eraseArea(SkIRect::MakeXYWH(0, 0, 2, 2), 0xFF0000FF);
  expected_bitmap.eraseArea(SkIRect::MakeXYWH(2, 0, 2, 2), 0xFF00FF00);
  const SkBitmap& bitmap = image->Bitmap();
  for (int x = 0; x < bitmap.width(); ++x)
    for (int y = 0; y < bitmap.height(); ++y)
      EXPECT_EQ(expected_bitmap.getColor(x, y), bitmap.getColor(x, y));
}

TEST_P(DataTransferTest, NodeImageFullyOffscreen) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #target {
      position: absolute;
      top: 800px;
      left: 0;
      height: 100px;
      width: 200px;
      background: lightblue;
      isolation: isolate;
    }
    </style>
    <div id="target" draggable="true" ondragstart="drag(event)"></div>
  )HTML");

  const int scroll_amount = 800;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_amount), mojom::blink::ScrollType::kProgrammatic);

  Element& target = *GetDocument().getElementById(AtomicString("target"));
  const auto image = DataTransfer::NodeImage(GetFrame(), target);

  EXPECT_EQ(gfx::Size(200, 100), image->Size());
}

TEST_P(DataTransferTest, NodeImageWithScrolling) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #target {
      position: absolute;
      top: 800px;
      left: 0;
      height: 100px;
      width: 200px;
      background: lightblue;
      isolation: isolate;
    }
    </style>
    <div id="target" draggable="true" ondragstart="drag(event)"></div>
  )HTML");

  Element& target = *GetDocument().getElementById(AtomicString("target"));
  const auto image = DataTransfer::NodeImage(GetFrame(), target);

  EXPECT_EQ(gfx::Size(200, 100), image->Size());
}

TEST_P(DataTransferTest, NodeImageInOffsetStackingContext) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #container {
        position: absolute;
        top: 4px;
        z-index: 10;
      }
      #drag {
        width: 5px;
        height: 5px;
        background: #0F0;
      }
    </style>
    <div id="container">
      <div id="drag" draggable="true"></div>
    </div>
  )HTML");
  Element& drag = *GetDocument().getElementById(AtomicString("drag"));
  const auto image = DataTransfer::NodeImage(GetFrame(), drag);
  constexpr int drag_width = 5;
  constexpr int drag_height = 5;
  EXPECT_EQ(gfx::Size(drag_width, drag_height), image->Size());

  // The dragged image should be (drag_width x drag_height) and fully green.
  const SkBitmap& bitmap = image->Bitmap();
  for (int x = 0; x < drag_width; ++x) {
    for (int y = 0; y < drag_height; ++y)
      EXPECT_EQ(SK_ColorGREEN, bitmap.getColor(x, y));
  }
}

TEST_P(DataTransferTest, NodeImageWithLargerPositionedDescendant) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #drag {
        position: absolute;
        top: 100px;
        left: 0;
        height: 1px;
        width: 1px;
        background: #00f;
      }
      #child {
        position: absolute;
        top: -1px;
        left: 0;
        height: 3px;
        width: 1px;
        background: #0f0;
      }
    </style>
    <div id="drag" draggable="true">
      <div id="child"></div>
    </div>
  )HTML");
  Element& drag = *GetDocument().getElementById(AtomicString("drag"));
  const auto image = DataTransfer::NodeImage(GetFrame(), drag);

  // The positioned #child should expand the dragged image's size.
  constexpr int drag_width = 1;
  constexpr int drag_height = 3;
  EXPECT_EQ(gfx::Size(drag_width, drag_height), image->Size());

  // The dragged image should be (drag_width x drag_height) and fully green
  // which is the color of the #child which fully covers the dragged element.
  const SkBitmap& bitmap = image->Bitmap();
  for (int x = 0; x < drag_width; ++x) {
    for (int y = 0; y < drag_height; ++y)
      EXPECT_EQ(SK_ColorGREEN, bitmap.getColor(x, y));
  }
}

TEST_P(DataTransferTest, NodeImageOutOfView) {
  SetBodyInnerHTML(R"HTML(
    <div id="drag" style="position: absolute; z-index: 1; top: -200px; left: 0;
                          width: 100px; height: 100px; background: green">
    </div>
  )HTML");

  auto image = DataTransfer::NodeImage(
      GetFrame(), *GetDocument().getElementById(AtomicString("drag")));
  EXPECT_EQ(gfx::Size(100, 100), image->Size());
  SkColor green = SkColorSetRGB(0, 0x80, 0);
  const SkBitmap& bitmap = image->Bitmap();
  for (int x = 0; x < 100; ++x) {
    for (int y = 0; y < 100; ++y)
      ASSERT_EQ(green, bitmap.getColor(x, y));
  }
}

TEST_P(DataTransferTest, NodeImageFixedChild) {
  SetBodyInnerHTML(R"HTML(
    <div id="drag" style="position: absolute; z-index: 1; top: 100px; left: 0;
                          width: 50px; height: 100px; background: green">
      <div style="position: fixed; top: 50px; width: 100px; height: 50px;
                  background: blue">
      </div>
    </div>
    <div style="height: 2000px"></div>
  )HTML");

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);

  auto image = DataTransfer::NodeImage(
      GetFrame(), *GetDocument().getElementById(AtomicString("drag")));
  EXPECT_EQ(gfx::Size(100, 100), image->Size());
  SkColor green = SkColorSetRGB(0, 0x80, 0);
  SkColor blue = SkColorSetRGB(0, 0, 0xFF);
  const SkBitmap& bitmap = image->Bitmap();
  for (int x = 0; x < 100; ++x) {
    for (int y = 0; y < 50; ++y) {
      ASSERT_EQ(x < 50 ? green : SK_ColorTRANSPARENT, bitmap.getColor(x, y));
    }
    for (int y = 50; y < 100; ++y)
      ASSERT_EQ(blue, bitmap.getColor(x, y));
  }
}

TEST_P(DataTransferTest, CreateDragImageWithEmptyImageResource) {
  DataTransfer* data_transfer = DataTransfer::Create();
  data_transfer->SetDragImageResource(
      MakeGarbageCollected<ImageResourceContent>(nullptr), gfx::Point());

  gfx::Point drag_offset;
  std::unique_ptr<DragImage> drag_image = data_transfer->CreateDragImage(
      drag_offset, /* device_scale_factor*/ 1, &GetFrame());
  // The test passes if the above call does not crash.
}

TEST_P(DataTransferTest, NodeImageTranslatedOutOfView) {
  // Given a node larger than the viewport and which is translated out of the
  // view, verify that the drag image is rendered without any clipping.
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      #container {
        background: #F00;
      }
      #drag {
        width: calc(100vw + 20px);
        height: calc(100vh + 20px);
        position: absolute;
        left: calc(-150vw);
        background: #0F0;
      }
    </style>
    <div id="container">
      <div id="drag" draggable="true"></div>
    </div>
  )HTML");

  const int viewport_width = 8;
  const int viewport_height = 6;

  GetDocument().View()->Resize(viewport_width, viewport_height);
  Element& drag = *GetDocument().getElementById(AtomicString("drag"));
  const auto image = DataTransfer::NodeImage(GetFrame(), drag);

  // The drag image size should be unchanged.
  EXPECT_EQ(gfx::Size(viewport_width + 20, viewport_height + 20),
            image->Size());

  const SkBitmap& bitmap = image->Bitmap();

  // Ensure all pixels are green.
  for (int x = 0; x < viewport_width + 20; ++x) {
    for (int y = 0; y < viewport_height + 20; ++y) {
      EXPECT_EQ(SK_ColorGREEN, bitmap.getColor(x, y));
    }
  }
}

}  // namespace blink
```
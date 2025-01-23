Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of `drag_controller_test.cc`, its relation to web technologies, logical inferences, common user errors, and debugging context.

2. **Identify the Core Component:** The filename itself, `drag_controller_test.cc`, immediately points to the core subject: testing the `DragController` class in Blink.

3. **Examine Includes:** The `#include` directives are crucial for understanding the dependencies and functionalities being tested. Let's list the key ones and what they suggest:
    * `drag_controller.h`:  This is the primary class being tested.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates this is a unit test file using the Google Test framework.
    * `public/common/page/drag_operation.h`:  Deals with drag and drop operations (copy, move, link).
    * `renderer/core/clipboard/...`:  Shows interactions with the clipboard and data transfer during drag and drop.
    * `renderer/core/editing/...`:  Suggests testing how dragging interacts with text selection and editing.
    * `renderer/core/frame/...`:  Points to tests involving frames (iframes), viewport, and frame views.
    * `renderer/core/html/forms/html_text_area_element.h`:  Indicates tests involving dragging from and to textareas.
    * `renderer/core/page/...`:  Highlights interactions with other page-level controllers like `AutoscrollController` and data structures like `DragData` and `DragState`.
    * `renderer/core/paint/...`:  Suggests testing aspects related to rendering and how the drag image is painted.
    * `renderer/core/testing/...`:  Confirms this is a test file within the Blink rendering engine.

4. **Analyze the Test Structure:**  Notice the use of `namespace blink`, test fixtures (`DragControllerTest`, `DragControllerSimTest`), and individual `TEST_F` macros. This is standard Google Test structure.

5. **Examine Test Fixtures:**
    * `DragMockChromeClient`: This is a *mock* class. Mocking is used to isolate the `DragController` and control its interactions with external components (like the browser's UI). The `StartDragging` method is being mocked, allowing the test to observe the drag image size and cursor offset.
    * `DragControllerTest`: This fixture sets up the basic rendering test environment, providing access to the frame and the mock Chrome client. The `PerformDragAndDropFromTextareaToTargetElement` helper function is important; it encapsulates a common drag-and-drop scenario.
    * `DragControllerSimTest`:  Inherits from `SimTest`, suggesting tests that involve more complex scenarios or asynchronous operations, possibly using a simulated environment.

6. **Deconstruct Individual Tests (`TEST_F`):** Go through each test case and understand its purpose:
    * **`DragImageForSelectionUsesPageScaleFactor`**:  Tests that the generated drag image is scaled correctly based on the page's zoom level.
    * **`DropURLOnNonNavigatingClearsState`**: Checks that the autoscroll state is cleared when a drag and drop occurs on an element that doesn't handle navigation.
    * **`ThrottledDocumentHandled`**:  Verifies that the `DragController` doesn't crash when hit testing is prevented due to throttling.
    * **`DragImageForSelectionClipsToViewport`**: Ensures the drag image for a selection is clipped correctly to the viewport boundaries, considering scrolling.
    * **`DragImageForSelectionClipsChildFrameToViewport`**: Similar to the above, but specifically for selections within iframes.
    * **`DragImageForSelectionClipsChildFrameToViewportWithPageScaleFactor`**:  Combines iframe clipping with page scale factor considerations.
    * **`DragImageOffsetWithPageScaleFactor`**: Tests the cursor offset of the drag image when the page has a scale factor.
    * **`DragLinkWithPageScaleFactor`**: Examines the drag image and offset for links, considering the page scale factor.
    * **`DragAndDropUrlFromTextareaToTextarea`**: Tests dragging a URL from a textarea to another textarea.
    * **`DragAndDropUrlFromTextareaToRichlyEditableDiv`**: Tests dragging a URL to a `contenteditable` div.
    * **`DragAndDropUrlFromTextareaToPlaintextonlyEditableDiv`**: Tests dragging a URL to a `contenteditable='plaintext-only'` div.
    * **`DragAndDropUrlFromTextareaToRichlyEditableParagraph`**:  Similar to the div test but with a paragraph.
    * **`DragAndDropUrlFromTextareaToPlaintextonlyEditableParagraph`**: Similar to the div test but with a paragraph and plaintext-only editing.

7. **Identify Relationships with Web Technologies:** As each test is analyzed, consider how the tested functionality relates to JavaScript, HTML, and CSS:
    * **JavaScript:** Drag and drop events (`dragstart`, `dragenter`, `dragover`, `drop`, etc.) are central to JavaScript interaction with dragging. The tests implicitly cover how the browser's drag-and-drop mechanism (implemented in C++) interacts with these JavaScript events. The `preventDefault()` call in the "ThrottledDocumentHandled" test is a direct JavaScript interaction.
    * **HTML:**  The tests use HTML elements like `<div>`, `<a>`, `<textarea>`, `<iframe>`, and their attributes (`contenteditable`). The structure and content of the HTML directly influence the drag-and-drop behavior.
    * **CSS:** CSS properties like `margin`, `width`, `height`, `overflow`, and `display` affect the layout and rendering of elements, which in turn impacts the calculation of drag image size and offset. The clipping tests directly relate to how the viewport (influenced by CSS) affects the drag image.

8. **Infer Logical Reasoning and Examples:**  For each test, think about the *why* behind it. What specific scenario is being validated?  Create simple examples to illustrate:
    * *Page Scale:*  A user zooms in on a webpage. The drag image needs to scale accordingly to remain crisp.
    * *Autoscroll:*  A user drags an item near the edge of the browser window. The page should automatically scroll.
    * *Viewport Clipping:* If a selection is partially outside the visible area, the drag image shouldn't extend beyond the viewport.
    * *Contenteditable:*  Dragging a link into a rich text editor should create a clickable link, while dragging it into a plaintext area should insert the raw URL.

9. **Consider User Errors:** Think about common mistakes developers might make when implementing drag-and-drop functionality, or things users might find unexpected:
    * Forgetting to handle drag events in JavaScript.
    * Incorrectly setting data transfer types.
    * Not accounting for different `contenteditable` modes.
    * Issues with scaling and coordinate systems.

10. **Trace User Actions for Debugging:**  Imagine the steps a user would take to trigger the code being tested:
    * Selecting text and dragging it.
    * Dragging a link.
    * Dragging content from a textarea.
    * Dragging content into different types of editable areas.
    * Performing these actions while zoomed in or with scrolling.

11. **Structure the Answer:** Organize the gathered information logically under the headings requested in the prompt. Use clear and concise language. Provide specific code snippets and examples where appropriate.

By following this detailed thought process, you can thoroughly analyze the test file and address all aspects of the request. The key is to connect the C++ code back to the user-facing web technologies and common interaction patterns.
This C++ source code file, `drag_controller_test.cc`, is a unit test file within the Chromium Blink rendering engine. Its primary function is to **test the functionality of the `DragController` class**. The `DragController` is responsible for handling drag and drop operations within a web page.

Here's a breakdown of its functionalities and relationships:

**1. Core Function: Testing `DragController` Functionality**

The file contains various test cases (using the Google Test framework) that exercise different aspects of the `DragController`. These tests aim to ensure that the `DragController` behaves correctly in various scenarios.

**2. Relationship with JavaScript, HTML, and CSS:**

The `DragController` directly interacts with the underlying mechanisms that enable drag and drop functionality, which is often exposed and manipulated via JavaScript, and affects how HTML elements behave visually (influenced by CSS).

* **JavaScript:**
    * **Event Handling:** The `DragController` is the backend component that handles the browser's drag and drop events (`dragstart`, `dragenter`, `dragover`, `drop`, `dragleave`). JavaScript event listeners can be attached to HTML elements to respond to these events, and the `DragController` is what triggers these events and manages the data being transferred.
    * **DataTransfer Object:**  The `DragController` works with the `DataTransfer` object, which is exposed to JavaScript. This object allows scripts to add data of various types (text, URLs, files) to the drag operation and access it during the drop. The tests in this file directly manipulate `DataObject` and `DataTransfer` objects in C++, which mirror the JavaScript API.
    * **Example:** A JavaScript might initiate a drag operation using `element.addEventListener('dragstart', (event) => { event.dataTransfer.setData('text/plain', 'Some text'); });`. The `DragController` would handle the underlying mechanics of starting this drag and storing the "Some text" data.

* **HTML:**
    * **Draggable Attribute:** HTML elements can be made draggable using the `draggable` attribute. The `DragController` recognizes this attribute and initiates drag operations for these elements.
    * **Drop Zones:**  HTML elements can act as drop zones. The `DragController` determines which element the dragged data is hovering over and dispatches the appropriate drag events.
    * **Example:**  A user might drag an image ( `<img draggable="true" src="...">`) or text selection. The `DragController` handles the initial mouse events and prepares the data for the drag.

* **CSS:**
    * **Visual Feedback:** CSS can be used to provide visual feedback during a drag operation (e.g., highlighting drop zones, changing cursor). While the `DragController` itself doesn't directly manipulate CSS, its actions can trigger repaints that reflect CSS styles.
    * **Layout and Positioning:**  The `DragController` needs to understand the layout and positioning of elements to determine hit targets during drag and drop. CSS styles influence this layout.
    * **Example:** The tests related to `DragImageForSelectionClipsToViewport` and `DragImageOffsetWithPageScaleFactor` demonstrate how the `DragController` considers the visual viewport and page scaling (which can be influenced by CSS zoom) when creating the drag image.

**3. Logical Reasoning and Examples:**

Let's look at some of the test cases and infer their logic:

* **`DragImageForSelectionUsesPageScaleFactor`:**
    * **Assumption:**  The size of the drag image for a text selection should scale proportionally to the page's zoom level.
    * **Input:**  Set the page scale factor to 1, select some text, get the drag image size. Then set the page scale factor to 2, select the same text, and get the drag image size.
    * **Output:** The width and height of the second drag image should be twice the width and height of the first drag image.

* **`DropURLOnNonNavigatingClearsState`:**
    * **Assumption:** If a drag and drop operation occurs on a component that doesn't handle navigation (e.g., a custom widget), any ongoing autoscroll initiated by the drag should be stopped.
    * **Input:** Simulate dragging a URL onto a `WebWidget` that is configured not to accept load drops.
    * **Output:** The `AutoscrollController` should not be in progress after the drop.

* **`DragAndDropUrlFromTextareaToTextarea`:**
    * **Assumption:** Dragging a URL from a textarea to another textarea should transfer the URL as plain text, and the default operation should be a "move" (clearing the source textarea).
    * **Input:**  Set the value of a source textarea to a URL, drag and drop it onto a target textarea.
    * **Output:** The target textarea's value should be the URL, and the source textarea's value should be empty.

**4. Common User or Programming Errors:**

* **Incorrect DataTransfer Type:** A common error in JavaScript drag and drop is setting the wrong `dataTransfer` type. For example, expecting an image when the data is actually text. The tests ensure the `DragController` correctly handles different data types.
* **Forgetting `preventDefault()`:**  In drag and drop event handlers, forgetting to call `event.preventDefault()` can lead to unexpected browser behavior, such as navigating to a dragged URL. The test `ThrottledDocumentHandled` indirectly touches upon this by testing how the `DragController` behaves when a `dragenter` event handler calls `preventDefault()`.
* **Coordinate System Issues:**  Mistakes in calculating or converting coordinates between different frames or the viewport can cause drag and drop to fail. Tests like `DragImageForSelectionClipsToViewport` and `DragImageOffsetWithPageScaleFactor` ensure the `DragController` handles coordinate transformations correctly.
* **Not Handling Drop Events:**  Failing to implement `drop` event handlers on target elements means the dragged data won't be processed. While this test file doesn't directly test JavaScript event handling, it tests the underlying `DragController` logic that would trigger these events.

**5. User Operations Leading to This Code (Debugging Clues):**

To reach the code tested in `drag_controller_test.cc`, a user would perform drag and drop operations within a web browser. Here are some specific scenarios that would engage the `DragController`:

* **Selecting Text and Dragging:**
    1. **User Action:**  The user clicks and holds the mouse button, drags the cursor over text to select it, and then continues to drag the selection.
    2. **Blink Internal:** The browser's input handling mechanism detects the mouse events and identifies the start of a potential drag operation.
    3. **`DragController` Involvement:** The `DragController` is invoked to manage the drag, create a drag image (as tested in `DragImageForSelectionUsesPageScaleFactor`), and prepare the data to be transferred (usually the selected text).

* **Dragging a Link:**
    1. **User Action:** The user clicks and holds the mouse button on a hyperlink and drags it.
    2. **Blink Internal:** Similar to text selection, the browser detects the drag on a link element.
    3. **`DragController` Involvement:** The `DragController` identifies the dragged element as a link, extracts the URL, and creates a drag image (potentially a representation of the URL, as tested in `DragLinkWithPageScaleFactor`).

* **Dragging Content from a Textarea:**
    1. **User Action:** The user selects text within a `<textarea>` element and drags the selection.
    2. **Blink Internal:** The browser recognizes the drag originating from a form control.
    3. **`DragController` Involvement:** The `DragController` extracts the selected text from the textarea and prepares it for the drag operation, as tested in scenarios like `DragAndDropUrlFromTextareaToTextarea`.

* **Dropping onto Different Elements:**
    1. **User Action:** The user releases the mouse button while dragging an item over another element.
    2. **Blink Internal:** The browser determines the element under the cursor at the time of the drop.
    3. **`DragController` Involvement:** The `DragController` dispatches the `drop` event to the target element and handles the transfer of data, as demonstrated in tests involving dropping onto textareas, editable divs, and paragraphs.

* **Dragging near the Edge of the Viewport:**
    1. **User Action:** The user drags an item close to the edge of the browser window.
    2. **Blink Internal:** The browser detects the cursor position near the edge.
    3. **`DragController` and `AutoscrollController` Involvement:** The `DragController` may interact with the `AutoscrollController` to initiate scrolling of the page, as tested in `DropURLOnNonNavigatingClearsState`.

By understanding these user actions and how they trigger the `DragController`, developers can use these tests as a guide for debugging issues related to drag and drop functionality in their web applications. If a drag and drop operation isn't behaving as expected, examining the relevant test cases in `drag_controller_test.cc` can provide insights into the expected behavior and potential areas for bugs in their code or in the browser engine itself.

### 提示词
```
这是目录为blink/renderer/core/page/drag_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/page/drag_controller.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/page/drag_operation.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/drag_data.h"
#include "third_party/blink/renderer/core/page/drag_image.h"
#include "third_party/blink/renderer/core/page/drag_state.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"

namespace blink {

class DragMockChromeClient : public RenderingTestChromeClient {
 public:
  DragMockChromeClient() = default;

  void StartDragging(LocalFrame*,
                     const WebDragData&,
                     DragOperationsMask,
                     const SkBitmap& drag_image,
                     const gfx::Vector2d& cursor_offset,
                     const gfx::Rect& drag_obj_rect) override {
    last_drag_image_size = gfx::Size(drag_image.width(), drag_image.height());
    last_cursor_offset = cursor_offset;
  }

  gfx::Size last_drag_image_size;
  gfx::Vector2d last_cursor_offset;
};

class DragControllerTest : public RenderingTest {
 protected:
  DragControllerTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()),

        chrome_client_(MakeGarbageCollected<DragMockChromeClient>()) {}
  LocalFrame& GetFrame() const { return *GetDocument().GetFrame(); }
  DragMockChromeClient& GetChromeClient() const override {
    return *chrome_client_;
  }
  void PerformDragAndDropFromTextareaToTargetElement(
      HTMLTextAreaElement* drag_text_area,
      DataObject* data_object,
      Element* drop_target) {
    const gfx::PointF drag_client_point(drag_text_area->OffsetLeft(),
                                        drag_text_area->OffsetTop());
    const gfx::PointF drop_client_point(drop_target->OffsetLeft(),
                                        drop_target->OffsetTop());

    WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                              WebInputEvent::kNoModifiers,
                              WebInputEvent::GetStaticTimeStampForTests());
    mouse_event.button = WebMouseEvent::Button::kLeft;
    mouse_event.SetPositionInWidget(drag_client_point);

    drag_text_area->SetValue("https://www.example.com/index.html");
    drag_text_area->Focus();
    UpdateAllLifecyclePhasesForTest();
    GetFrame().Selection().SelectAll();
    GetFrame().GetPage()->GetDragController().StartDrag(
        &GetFrame(), GetFrame().GetPage()->GetDragController().GetDragState(),
        mouse_event,
        gfx::Point(drag_text_area->OffsetLeft(), drag_text_area->OffsetTop()));
    DragData data(data_object,
                  GetFrame().GetPage()->GetVisualViewport().ViewportToRootFrame(
                      drop_client_point),
                  drop_client_point,
                  static_cast<DragOperationsMask>(kDragOperationMove), false);
    GetFrame().GetPage()->GetDragController().DragEnteredOrUpdated(&data,
                                                                   GetFrame());
    GetFrame().GetPage()->GetDragController().PerformDrag(&data, GetFrame());
  }

 private:
  Persistent<DragMockChromeClient> chrome_client_;
};

TEST_F(DragControllerTest, DragImageForSelectionUsesPageScaleFactor) {
  SetBodyInnerHTML(
      "<div>Hello world! This tests that the bitmap for drag image is scaled "
      "by page scale factor</div>");
  GetFrame().GetPage()->GetVisualViewport().SetScale(1);
  GetFrame().Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();
  const std::unique_ptr<DragImage> image1(
      DragController::DragImageForSelection(GetFrame(), 0.75f));
  GetFrame().GetPage()->GetVisualViewport().SetScale(2);
  GetFrame().Selection().SelectAll();
  UpdateAllLifecyclePhasesForTest();
  const std::unique_ptr<DragImage> image2(
      DragController::DragImageForSelection(GetFrame(), 0.75f));

  EXPECT_GT(image1->Size().width(), 0);
  EXPECT_GT(image1->Size().height(), 0);
  EXPECT_EQ(image1->Size().width() * 2, image2->Size().width());
  EXPECT_EQ(image1->Size().height() * 2, image2->Size().height());
}

class DragControllerSimTest : public SimTest {};

// Tests that dragging a URL onto a WebWidget that doesn't navigate on Drag and
// Drop clears out the Autoscroll state. Regression test for
// https://crbug.com/733996.
TEST_F(DragControllerSimTest, DropURLOnNonNavigatingClearsState) {
  auto renderer_preferences = WebView().GetRendererPreferences();
  renderer_preferences.can_accept_load_drops = false;
  WebView().SetRendererPreferences(renderer_preferences);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  // Page must be scrollable so that Autoscroll is engaged.
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<style>body,html { height: 1000px; width: 1000px; }</style>");

  Compositor().BeginFrame();

  WebDragData drag_data;
  WebDragData::StringItem item;
  item.type = "text/uri-list";
  item.data = WebString::FromUTF8("https://www.example.com/index.html");
  drag_data.AddItem(item);

  const gfx::PointF client_point(10, 10);
  const gfx::PointF screen_point(10, 10);
  WebFrameWidget* widget = WebView().MainFrameImpl()->FrameWidget();
  widget->DragTargetDragEnter(drag_data, client_point, screen_point,
                              kDragOperationCopy, 0, base::DoNothing());

  // The page should tell the AutoscrollController about the drag.
  EXPECT_TRUE(
      WebView().GetPage()->GetAutoscrollController().AutoscrollInProgress());

  widget->DragTargetDrop(drag_data, client_point, screen_point, 0,
                         base::DoNothing());
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      WebView().MainFrameImpl());

  // Once we've "performed" the drag (in which nothing happens), the
  // AutoscrollController should have been cleared.
  EXPECT_FALSE(
      WebView().GetPage()->GetAutoscrollController().AutoscrollInProgress());
}

// Verify that conditions that prevent hit testing - such as throttled
// lifecycle updates for frames - are accounted for in the DragController.
// Regression test for https://crbug.com/685030
TEST_F(DragControllerSimTest, ThrottledDocumentHandled) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  // Intercept event to indicate that the document will be handling the drag.
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<script>"
      "  document.addEventListener('dragenter', e => e.preventDefault());"
      "</script>");

  DataObject* object = DataObject::CreateFromString("hello world");
  DragData data(
      object, gfx::PointF(10, 10), gfx::PointF(10, 10),
      static_cast<DragOperationsMask>(kDragOperationCopy | kDragOperationLink |
                                      kDragOperationMove),
      false);

  WebView().GetPage()->GetDragController().DragEnteredOrUpdated(
      &data, *GetDocument().GetFrame());

  // Throttle updates, which prevents hit testing from yielding a node.
  WebView()
      .MainFrameImpl()
      ->GetFrameView()
      ->SetLifecycleUpdatesThrottledForTesting();

  WebView().GetPage()->GetDragController().PerformDrag(
      &data, *GetDocument().GetFrame());

  // Test passes if we don't crash.
}

TEST_F(DragControllerTest, DragImageForSelectionClipsToViewport) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      div {
        width: 20px;
        height: 1000px;
        font-size: 30px;
        overflow: hidden;
        margin-top: 2px;
      }
    </style>
    <div>
      a<br>b<br>c<br>d<br>e<br>f<br>g<br>h<br>i<br>j<br>k<br>l<br>m<br>n<br>
      a<br>b<br>c<br>d<br>e<br>f<br>g<br>h<br>i<br>j<br>k<br>l<br>m<br>n<br>
      a<br>b<br>c<br>d<br>e<br>f<br>g<br>h<br>i<br>j<br>k<br>l<br>m<br>n<br>
    </div>
  )HTML");
  const int page_scale_factor = 2;
  GetFrame().GetPage()->SetPageScaleFactor(page_scale_factor);
  GetFrame().Selection().SelectAll();

  const int node_width = 20;
  const int node_height = 1000;
  const int node_margin_top = 2;
  const int viewport_height_dip = 600;
  const int viewport_height_css = viewport_height_dip / page_scale_factor;

  // The top of the node should be visible but the bottom should be outside the
  // viewport.
  gfx::RectF expected_selection(0, node_margin_top, node_width,
                                viewport_height_css - node_margin_top);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(GetFrame()));
  auto selection_image(DragController::DragImageForSelection(GetFrame(), 1));
  gfx::Size expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // Scroll 500 css px down so the top of the node is outside the viewport.
  // Because the viewport is scaled to 300 css px tall, the bottom of the node
  // should also be outside the viewport. Therefore, the selection should cover
  // the entire viewport.
  int scroll_offset = 500;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 0, node_width, viewport_height_css);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(GetFrame()));
  selection_image = DragController::DragImageForSelection(GetFrame(), 1);
  expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // Scroll 800 css px down so the top of the node is outside the viewport and
  // the bottom of the node is now visible.
  scroll_offset = 800;
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(
      0, 0, node_width, node_height + node_margin_top - scroll_offset);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(GetFrame()));
  selection_image = DragController::DragImageForSelection(GetFrame(), 1);
  expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());
}

TEST_F(DragControllerTest, DragImageForSelectionClipsChildFrameToViewport) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      iframe {
        margin-top: 200px;
        border: none;
        width: 50px;
        height: 50px;
      }
    </style>
    <iframe></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      div {
        width: 30px;
        height: 20px;
        font-size: 30px;
        overflow: hidden;
        margin-top: 5px;
        margin-bottom: 500px;
      }
    </style>
    <div>abcdefg</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  auto& child_frame = *To<LocalFrame>(GetFrame().Tree().FirstChild());
  child_frame.Selection().SelectAll();

  // The iframe's selection rect is in the frame's local coordinates and should
  // not include the iframe's margin.
  gfx::RectF expected_selection(0, 5, 30, 20);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  auto selection_image(DragController::DragImageForSelection(child_frame, 1));
  gfx::Size expected_image_size = gfx::ToRoundedSize(expected_selection.size());
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // The iframe's selection rect is in the frame's local coordinates and should
  // not include scroll offset.
  int scroll_offset = 50;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 5, 30, 20);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  selection_image = DragController::DragImageForSelection(child_frame, 1);
  expected_image_size = gfx::ToRoundedSize(expected_selection.size());
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // The parent frame's scroll offset of 210 should cause the iframe content to
  // be shifted which should cause the iframe's selection rect to be clipped by
  // the visual viewport.
  scroll_offset = 210;
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 10, 30, 15);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  selection_image = DragController::DragImageForSelection(child_frame, 1);
  expected_image_size = gfx::ToRoundedSize(expected_selection.size());
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // Scrolling the iframe should shift the content so it is further under the
  // visual viewport clip.
  int iframe_scroll_offset = 7;
  child_frame.View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, iframe_scroll_offset),
      mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 10, 30, 8);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  selection_image = DragController::DragImageForSelection(child_frame, 1);
  expected_image_size = gfx::ToRoundedSize(expected_selection.size());
  EXPECT_EQ(expected_image_size, selection_image->Size());
}

TEST_F(DragControllerTest,
       DragImageForSelectionClipsChildFrameToViewportWithPageScaleFactor) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      iframe {
        margin-top: 200px;
        border: none;
        width: 50px;
        height: 50px;
      }
    </style>
    <iframe></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <style>
      * { margin: 0; }
      html, body { height: 2000px; }
      div {
        width: 30px;
        height: 20px;
        font-size: 30px;
        overflow: hidden;
        margin-top: 5px;
        margin-bottom: 500px;
      }
    </style>
    <div>abcdefg</div>
  )HTML");
  const int page_scale_factor = 2;
  GetFrame().GetPage()->SetPageScaleFactor(page_scale_factor);
  UpdateAllLifecyclePhasesForTest();
  auto& child_frame = *To<LocalFrame>(GetFrame().Tree().FirstChild());
  child_frame.Selection().SelectAll();

  // The iframe's selection rect is in the frame's local coordinates and should
  // not include the iframe's margin.
  gfx::RectF expected_selection(0, 5, 30, 20);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  auto selection_image(DragController::DragImageForSelection(child_frame, 1));
  gfx::Size expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // The iframe's selection rect is in the frame's local coordinates and should
  // not include the parent frame's scroll offset.
  int scroll_offset = 50;
  LocalFrameView* frame_view = GetDocument().View();
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 5, 30, 20);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  selection_image = DragController::DragImageForSelection(child_frame, 1);
  expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // The parent frame's scroll offset of 210 should cause the iframe content to
  // be shifted which should cause the iframe's selection rect to be clipped by
  // the visual viewport.
  scroll_offset = 210;
  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, scroll_offset), mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 10, 30, 15);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  selection_image = DragController::DragImageForSelection(child_frame, 1);
  expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());

  // Scrolling the iframe should shift the content so it is further under the
  // visual viewport clip.
  int iframe_scroll_offset = 7;
  child_frame.View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, iframe_scroll_offset),
      mojom::blink::ScrollType::kProgrammatic);
  expected_selection = gfx::RectF(0, 10, 30, 8);
  EXPECT_EQ(expected_selection, DragController::ClippedSelection(child_frame));
  selection_image = DragController::DragImageForSelection(child_frame, 1);
  expected_image_size = gfx::ToRoundedSize(
      gfx::ScaleSize(expected_selection.size(), page_scale_factor));
  EXPECT_EQ(expected_image_size, selection_image->Size());
}

TEST_F(DragControllerTest, DragImageOffsetWithPageScaleFactor) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      div {
        width: 50px;
        height: 40px;
        font-size: 30px;
        overflow: hidden;
        margin-top: 2px;
      }
    </style>
    <div id='drag'>abcdefg<br>abcdefg<br>abcdefg</div>
  )HTML");
  const int page_scale_factor = 2;
  GetFrame().GetPage()->SetPageScaleFactor(page_scale_factor);
  GetFrame().Selection().SelectAll();

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(5, 10);

  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionSelection;
  drag_state.drag_src_ = GetDocument().getElementById(AtomicString("drag"));
  drag_state.drag_data_transfer_ = DataTransfer::Create(
      DataTransfer::kDragAndDrop, DataTransferAccessPolicy::kWritable,
      DataObject::Create());
  GetFrame().GetPage()->GetDragController().StartDrag(
      &GetFrame(), drag_state, mouse_event, gfx::Point(5, 10));

  gfx::Size expected_image_size =
      gfx::Size(50 * page_scale_factor, 40 * page_scale_factor);
  EXPECT_EQ(expected_image_size, GetChromeClient().last_drag_image_size);
  // The drag image has a margin of 2px which should offset the selection
  // image by 2px from the dragged location of (5, 10).
  gfx::Vector2d expected_offset(5 * page_scale_factor,
                                (10 - 2) * page_scale_factor);
  EXPECT_EQ(expected_offset, GetChromeClient().last_cursor_offset);
}

TEST_F(DragControllerTest, DragLinkWithPageScaleFactor) {
  SetBodyInnerHTML(R"HTML(
    <style>
      * { margin: 0; }
      a {
        width: 50px;
        height: 40px;
        font-size: 30px;
        margin-top: 2px;
        display: block;
      }
    </style>
    <a id='drag' href='https://foobarbaz.com'>foobarbaz</a>
  )HTML");
  const int page_scale_factor = 2;
  GetFrame().GetPage()->SetPageScaleFactor(page_scale_factor);
  GetFrame().Selection().SelectAll();

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetFrameScale(1);
  mouse_event.SetPositionInWidget(5, 10);

  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionLink;
  drag_state.drag_src_ = GetDocument().getElementById(AtomicString("drag"));
  drag_state.drag_data_transfer_ = DataTransfer::Create(
      DataTransfer::kDragAndDrop, DataTransferAccessPolicy::kWritable,
      DataObject::Create());
  GetFrame().GetPage()->GetDragController().StartDrag(
      &GetFrame(), drag_state, mouse_event, gfx::Point(5, 10));

  gfx::Size link_image_size = GetChromeClient().last_drag_image_size;
  // The drag link image should be a textual representation of the drag url in a
  // system font (see: DeriveDragLabelFont in drag_image.cc) and should not be
  // an empty image.
  EXPECT_GT(link_image_size.Area64(), 0u);
  // Unlike the drag image in DragImageOffsetWithPageScaleFactor, the link
  // image is not offset by margin because the link image is not based on the
  // link's painting but instead is a generated image of the link's url. Because
  // link_image_size is already scaled, no additional scaling is expected.
  gfx::Vector2d expected_offset(link_image_size.width() / 2, 2);
  // The offset is mapped using integers which can introduce rounding errors
  // (see TODO in DragController::DoSystemDrag) so we accept values near our
  // expectation until more precise offset mapping is available.
  EXPECT_NEAR(expected_offset.x(), GetChromeClient().last_cursor_offset.x(), 1);
  EXPECT_NEAR(expected_offset.y(), GetChromeClient().last_cursor_offset.y(), 1);
}

// Verify that drag and drop of URL from textarea to textarea drops the entire
// URL
TEST_F(DragControllerTest, DragAndDropUrlFromTextareaToTextarea) {
  SetBodyInnerHTML(R"HTML(
    <style>
    body,html { height: 1000px; width: 1000px; }
    textarea { height: 100px; width: 250px; }
    </style>
    <textarea id='drag'>httts://www.example.com/index.html</textarea>
    <textarea id='drop'></textarea>
  )HTML");
  HTMLTextAreaElement* drag_text_area = DynamicTo<HTMLTextAreaElement>(
      *(GetDocument().getElementById(AtomicString("drag"))));
  HTMLTextAreaElement* drop_text_area = DynamicTo<HTMLTextAreaElement>(
      *(GetDocument().getElementById(AtomicString("drop"))));
  WebDragData web_drag_data;
  WebDragData::StringItem item1;
  item1.type = "text/uri-list";
  item1.data = WebString::FromUTF8("https://www.example.com/index.html");
  item1.title = "index.html";
  WebDragData::StringItem item2;
  item2.type = "text/plain";
  item2.data = "https://www.example.com/index.html";

  web_drag_data.AddItem(item1);
  web_drag_data.AddItem(item2);
  DataObject* data_object = DataObject::Create(web_drag_data);
  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionSelection;
  drag_state.drag_src_ = drag_text_area;
  drag_state.drag_data_transfer_ =
      DataTransfer::Create(DataTransfer::kDragAndDrop,
                           DataTransferAccessPolicy::kWritable, data_object);

  PerformDragAndDropFromTextareaToTargetElement(drag_text_area, data_object,
                                                drop_text_area);
  EXPECT_EQ("https://www.example.com/index.html", drop_text_area->Value());
  EXPECT_EQ("", drag_text_area->Value());  // verify drag operation is move
}

// Verify that drag and drop of URL from textarea to richly editable div adds an
// anchor element
TEST_F(DragControllerTest, DragAndDropUrlFromTextareaToRichlyEditableDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>
    body,html { height: 1000px; width: 1000px; }
    textarea { height: 100px; width: 250px; }
    </style>
    <textarea id='drag'>httts://www.example.com/index.html</textarea>
    <div id='drop' contenteditable='true'></div>
  )HTML");
  HTMLTextAreaElement* drag_text_area = DynamicTo<HTMLTextAreaElement>(
      *(GetDocument().getElementById(AtomicString("drag"))));
  Element* drop_div_rich = GetDocument().getElementById(AtomicString("drop"));
  WebDragData web_drag_data;
  WebDragData::StringItem item1;
  item1.type = "text/uri-list";
  item1.data = WebString::FromUTF8("https://www.example.com/index.html");
  item1.title = "index.html";
  WebDragData::StringItem item2;
  item2.type = "text/plain";
  item2.data = "https://www.example.com/index.html";

  web_drag_data.AddItem(item1);
  web_drag_data.AddItem(item2);
  DataObject* data_object = DataObject::Create(web_drag_data);
  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionSelection;
  drag_state.drag_src_ = drag_text_area;
  drag_state.drag_data_transfer_ =
      DataTransfer::Create(DataTransfer::kDragAndDrop,
                           DataTransferAccessPolicy::kWritable, data_object);

  PerformDragAndDropFromTextareaToTargetElement(drag_text_area, data_object,
                                                drop_div_rich);
  EXPECT_EQ("<a href=\"https://www.example.com/index.html\">index.html</a>",
            drop_div_rich->innerHTML());
  EXPECT_EQ("", drag_text_area->Value());
}

// Verify that drag and drop of URL from textarea to plaintext-only editable div
// populates the entire URL as text
TEST_F(DragControllerTest,
       DragAndDropUrlFromTextareaToPlaintextonlyEditableDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>
    body,html { height: 1000px; width: 1000px; }
    textarea { height: 100px; width: 250px; }
    </style>
    <textarea id='drag'>httts://www.example.com/index.html</textarea>
    <div id='drop' contenteditable='plaintext-only'></div>
  )HTML");
  HTMLTextAreaElement* drag_text_area = DynamicTo<HTMLTextAreaElement>(
      *(GetDocument().getElementById(AtomicString("drag"))));
  Element* drop_div_plain = GetDocument().getElementById(AtomicString("drop"));
  WebDragData web_drag_data;
  WebDragData::StringItem item1;
  item1.type = "text/uri-list";
  item1.data = WebString::FromUTF8("https://www.example.com/index.html");
  item1.title = "index.html";
  WebDragData::StringItem item2;
  item2.type = "text/plain";
  item2.data = "https://www.example.com/index.html";

  web_drag_data.AddItem(item1);
  web_drag_data.AddItem(item2);
  DataObject* data_object = DataObject::Create(web_drag_data);
  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionSelection;
  drag_state.drag_src_ = drag_text_area;
  drag_state.drag_data_transfer_ =
      DataTransfer::Create(DataTransfer::kDragAndDrop,
                           DataTransferAccessPolicy::kWritable, data_object);

  PerformDragAndDropFromTextareaToTargetElement(drag_text_area, data_object,
                                                drop_div_plain);
  EXPECT_EQ("https://www.example.com/index.html", drop_div_plain->innerHTML());
  EXPECT_EQ("", drag_text_area->Value());
}

TEST_F(DragControllerTest,
       DragAndDropUrlFromTextareaToRichlyEditableParagraph) {
  SetBodyInnerHTML(R"HTML(
    <style>
    body,html { height: 1000px; width: 1000px; }
    textarea { height: 100px; width: 250px; }
    </style>
    <textarea id='drag'>httts://www.example.com/index.html</textarea>
    <p id='drop' contenteditable='true'></p>
  )HTML");
  HTMLTextAreaElement* drag_text_area = DynamicTo<HTMLTextAreaElement>(
      *(GetDocument().getElementById(AtomicString("drag"))));
  Element* drop_paragraph_rich =
      GetDocument().getElementById(AtomicString("drop"));
  WebDragData web_drag_data;
  WebDragData::StringItem item1;
  item1.type = "text/uri-list";
  item1.data = WebString::FromUTF8("https://www.example.com/index.html");
  item1.title = "index.html";
  WebDragData::StringItem item2;
  item2.type = "text/plain";
  item2.data = "https://www.example.com/index.html";

  web_drag_data.AddItem(item1);
  web_drag_data.AddItem(item2);
  DataObject* data_object = DataObject::Create(web_drag_data);
  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionSelection;
  drag_state.drag_src_ = drag_text_area;
  drag_state.drag_data_transfer_ =
      DataTransfer::Create(DataTransfer::kDragAndDrop,
                           DataTransferAccessPolicy::kWritable, data_object);

  PerformDragAndDropFromTextareaToTargetElement(drag_text_area, data_object,
                                                drop_paragraph_rich);
  EXPECT_EQ("<a href=\"https://www.example.com/index.html\">index.html</a>",
            drop_paragraph_rich->innerHTML());
  EXPECT_EQ("", drag_text_area->Value());
}

TEST_F(DragControllerTest,
       DragAndDropUrlFromTextareaToPlaintextonlyEditableParagraph) {
  SetBodyInnerHTML(R"HTML(
    <style>
    body,html { height: 1000px; width: 1000px; }
    textarea { height: 100px; width: 250px; }
    </style>
    <textarea id='drag'>httts://www.example.com/index.html</textarea>
    <p id='drop' contenteditable='plaintext-only'></p>
  )HTML");
  HTMLTextAreaElement* drag_text_area = DynamicTo<HTMLTextAreaElement>(
      *(GetDocument().getElementById(AtomicString("drag"))));
  Element* drop_paragraph_plain =
      GetDocument().getElementById(AtomicString("drop"));
  WebDragData web_drag_data;
  WebDragData::StringItem item1;
  item1.type = "text/uri-list";
  item1.data = WebString::FromUTF8("https://www.example.com/index.html");
  item1.title = "index.html";
  WebDragData::StringItem item2;
  item2.type = "text/plain";
  item2.data = "https://www.example.com/index.html";

  web_drag_data.AddItem(item1);
  web_drag_data.AddItem(item2);
  DataObject* data_object = DataObject::Create(web_drag_data);
  auto& drag_state = GetFrame().GetPage()->GetDragController().GetDragState();
  drag_state.drag_type_ = kDragSourceActionSelection;
  drag_state.drag_src_ = drag_text_area;
  drag_state.drag_data_transfer_ =
      DataTransfer::Create(DataTransfer::kDragAndDrop,
                           DataTransferAccessPolicy::kWritable, data_object);

  PerformDragAndDropFromTextareaToTargetElement(drag_text_area, data_object,
                                                drop_paragraph_plain);
  EXPECT_EQ("https://www.example.com/index.html",
            drop_paragraph_plain->innerHTML());
  EXPECT_EQ("", drag_text_area->Value());
}

}  // namespace blink
```
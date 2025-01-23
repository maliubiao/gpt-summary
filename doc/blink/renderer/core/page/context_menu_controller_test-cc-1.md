Response:
The user wants a summary of the functionalities of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine's context menu controller.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `context_menu_controller_test.cc` immediately suggests that this code contains tests for the `ContextMenuController`. This is the central theme.

2. **Analyze Individual Tests:** Go through each `TEST_F` block and understand what it's testing. Look for the actions performed (e.g., setting innerHTML, simulating events, calling `ShowContextMenu`), the assertions made (`EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`), and the data being checked (e.g., `context_menu_data.selected_text`, `context_menu_data.media_type`).

3. **Group Related Tests:**  Notice patterns in the tests. Some tests focus on text selection, others on image handling within the context menu, and some on how elements above or with event listeners affect context menu behavior.

4. **Identify Key Concepts:** Extract the important concepts being tested, such as:
    * Text selection and its boundaries.
    * Context menus on images (standard, SVG).
    * Penetrating image selection through transparent elements.
    * Blocking image selection by opaque elements or elements with context menu listeners.
    * Context menus on canvas elements.
    * Context menus triggered by keyboard events.
    * Caching and retrieval of the image node associated with a context menu.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how the C++ code interacts with web technologies. The tests manipulate the DOM (HTML structure) using `setInnerHTML`, simulate user interactions that would normally be triggered by JavaScript events, and indirectly involve CSS through styling that affects element visibility and stacking (z-index).

6. **Consider Assumptions and Logic:** When a test sets up a specific scenario (e.g., an image overlaid by a transparent div), identify the assumption being tested (that the context menu should target the image). Note the expected outcome based on this setup.

7. **Identify Potential User Errors:** Think about what mistakes a web developer might make that these tests are designed to catch or demonstrate the correct behavior for. For example, expecting a context menu on an image when an opaque element covers it.

8. **Trace User Actions:**  Describe the series of user interactions (mouse clicks, long presses, keyboard shortcuts) that would lead to the context menu being displayed and these tests being relevant.

9. **Structure the Summary:** Organize the findings into logical categories:
    * Overall purpose.
    * Specific functionalities tested (list them).
    * Relationships to web technologies (with examples).
    * Logical inferences (with assumptions and outputs).
    * Common user errors (with examples).
    * User actions to reach this code.
    * Summary of the current snippet.

10. **Refine and Clarify:** Review the summary for clarity and accuracy. Ensure the examples are illustrative and the explanations are easy to understand. Specifically for Part 2, focus on summarizing the content of *this specific* code block.

Applying this process to the provided code snippet results in the detailed explanation given in the initial good answer. The process emphasizes understanding the code's purpose, breaking it down into manageable parts, connecting it to relevant concepts, and then synthesizing the information into a coherent summary.
好的，让我们归纳一下这部分代码的功能。

这部分代码主要集中在测试 `ContextMenuController` 在处理 **图片元素** 时的行为，特别是关于 **图片元素的命中测试 (hit test)** 和 **图片节点缓存与检索** 的功能。

以下是更详细的归纳：

**主要功能点：**

1. **验证图片元素的上下文菜单命中测试 (Hit Test)：**
   - 测试在不同情况下，右键点击或长按图片元素时，能否正确识别出图片，并生成包含图片信息的上下文菜单数据 (`ContextMenuData`)。
   - 验证 `ContextMenuData` 中的 `media_type` 是否为 `kImage`，`src_url` 是否为图片的 URL。
   - 测试 SVG 图片元素的上下文菜单命中测试。

2. **验证“穿透”选择 (Penetrating Selection) 逻辑对图片元素的影响：**
   - 测试当图片元素上方存在透明的 `div` 遮挡时，是否能够穿透遮挡层，正确命中并选择图片。

3. **验证“阻挡”选择 (Blocking Selection) 逻辑对图片元素的影响：**
   - 测试当图片元素上方存在不透明的 `div` 遮挡时，是否会阻止对图片的命中和选择。
   - 测试当图片元素上方存在绑定了 `contextmenu` 事件监听器的元素时，是否会阻止对图片的命中和选择。
   - 测试当图片元素自身绑定了 `contextmenu` 事件监听器时，是否会阻止对图片的命中和选择（如果它不是最顶层元素）。
   - 测试当图片元素的祖先元素绑定了 `contextmenu` 事件监听器时，在不同遮挡情况下是否会影响图片的命中和选择。

4. **验证画布 (Canvas) 元素的上下文菜单命中测试：**
   - 测试右键点击或长按画布元素时，能否正确识别出画布，并生成包含画布信息的上下文菜单数据，`media_type` 是否为 `kCanvas`。

5. **验证图片节点的缓存和检索机制：**
   - 测试在成功进行图片元素的上下文菜单命中测试后，是否能够缓存该图片节点。
   - 测试是否能够根据 Frame 对象检索到之前缓存的图片节点。
   - 测试在没有进行上下文菜单操作的情况下，是否无法检索到缓存的图片节点。
   - 测试在同一个 `ContextMenuController` 中进行多次上下文菜单操作后，旧的缓存是否会被清除。
   - 测试尝试从不同的 Frame 中检索缓存的图片节点是否会失败（跨 Frame 检索）。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:**  大量的测试通过 `GetDocument()->documentElement()->setInnerHTML(...)` 来设置 HTML 结构，创建包含 `<img>`、`<svg>`、`<canvas>`、`<div>` 等元素的页面结构，用于模拟不同的场景。例如，创建透明或不透明的遮挡层，或者创建带有事件监听器的元素。
* **CSS:**  部分测试通过内联样式来控制元素的 `position`、`width`、`height`、`z-index` 和 `background`，以此来模拟元素在页面上的层叠关系和可见性，例如 `z-index` 用于控制遮挡关系，`background: blue` 用于创建不透明的遮挡层。
* **JavaScript:** 虽然这部分代码本身是 C++ 测试代码，但它测试的行为是用户与网页交互时触发的，这些交互最终会影响 JavaScript 事件的处理。例如，`contextmenu` 事件监听器的存在会影响上下文菜单的行为，而这些监听器通常是通过 JavaScript 添加的。测试中通过模拟用户操作（例如长按）来触发上下文菜单，这与 JavaScript 事件的机制紧密相关。

**逻辑推理的假设输入与输出：**

* **假设输入 (ContextMenuImageHitTestSucceededPenetrating)：**
    * HTML 结构包含一个 `<img>` 元素和一个完全透明的 `<div>` 元素覆盖在图片之上。
    * 用户在 `<div>` 元素的位置触发长按手势。
* **预期输出：**
    * 上下文菜单能够正确识别出底层的 `<img>` 元素。
    * `context_menu_data.media_type` 为 `kImage`。
    * `context_menu_data.src_url` 为图片的 URL。
    * 相关的图像选择结果的直方图计数会更新，例如 `kImageFoundPenetrating` 计数会增加。

* **假设输入 (ContextMenuImageRetrievalCachedImageFound)：**
    * 用户在一个包含 `<img>` 元素的页面上触发了上下文菜单（例如长按）。
    * 之后，代码尝试获取该 Frame 对应的缓存图片节点。
* **预期输出：**
    * `ContextMenuController::ContextMenuImageNodeForFrame()` 方法返回该 `<img>` 元素的节点指针，不为空。
    * 相关的图像选择检索结果的直方图计数会更新，例如 `kImageFound` 计数会增加。

**涉及的用户或编程常见的使用错误举例：**

* **错误理解元素的层叠关系：** 开发者可能会认为点击一个被不透明元素覆盖的图片仍然会触发图片的上下文菜单。测试 `ContextMenuImageHitTestOpaqueNodeBlocking` 验证了这种情况是不会发生的。
* **过度使用事件监听器：** 开发者可能在不需要的情况下给元素绑定了 `contextmenu` 事件监听器，导致默认的上下文菜单行为被阻止。测试 `ContextMenuImageHitTestContextMenuListenerAboveImageBlocking` 和 `ContextMenuImageHitTestContextMenuListenerOnImageBlocking`  展示了这种情况。
* **错误地假设缓存的持久性：** 开发者可能错误地认为图片节点会被永久缓存，并在后续的交互中仍然有效。测试 `ContextMenuImageRetrievalAfterCachedImageReset`  说明了当进行新的上下文菜单操作时，旧的缓存会被清除。

**用户操作是如何一步步到达这里的（作为调试线索）：**

1. **用户浏览网页：** 用户通过浏览器加载包含图片或其他可操作元素的网页。
2. **用户触发上下文菜单：** 用户在想要操作的元素上执行特定的操作来触发上下文菜单，例如：
   - **鼠标右键点击：** 在桌面浏览器上，这是最常见的触发方式。
   - **触摸屏长按：** 在移动设备或支持触摸的设备上。
   - **键盘快捷键：** 例如 Shift + F10 (在非 Mac 平台上)。
3. **浏览器事件处理：** 浏览器捕获用户的操作，并生成相应的事件 (例如 `MouseEvent`, `TouchEvent`, `KeyboardEvent`)。
4. **Blink 引擎处理事件：** Blink 引擎接收到这些事件，并进行事件分发和处理。对于触发上下文菜单的事件，会调用 `ContextMenuController` 的相关方法。
5. **命中测试：** `ContextMenuController` 需要确定用户是在哪个元素上触发了上下文菜单。这涉及到命中测试，判断鼠标或触摸点下的最相关的元素。
6. **生成上下文菜单数据：**  根据命中测试的结果，`ContextMenuController` 会收集相关信息，例如选中的文本、链接 URL、图片 URL 等，并构建 `ContextMenuData` 对象。
7. **将上下文菜单数据传递给浏览器：** `ContextMenuData` 会被传递给浏览器的 UI 进程，用于显示实际的上下文菜单。

这部分测试代码模拟了从步骤 2 (用户触发上下文菜单) 到步骤 6 (生成上下文菜单数据) 的过程，并验证了 `ContextMenuController` 在处理图片元素时的命中测试和数据收集逻辑是否正确。

**本代码段的功能总结：**

总而言之，这部分代码主要针对 Blink 引擎的 `ContextMenuController` 中处理 **图片元素** 和 **画布元素** 的逻辑进行详细的单元测试，涵盖了在各种页面结构和用户交互场景下，上下文菜单的 **命中测试**、**穿透和阻挡选择逻辑** 以及 **图片节点的缓存与检索** 功能的正确性。

### 提示词
```
这是目录为blink/renderer/core/page/context_menu_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_NE(context_menu_data.selected_text, "");

  // Scroll the value of |input| to end.
  input_element->setScrollLeft(input_element->scrollWidth());

  // Select all the value of |input| to ensure the start of selection is
  // invisible.
  LocalMainFrame()->MoveRangeSelectionExtent(
      gfx::Point(rect->right(), rect->bottom()));
  LocalMainFrame()->LocalRootFrameWidget()->ShowContextMenu(
      ui::mojom::blink::MenuSourceType::kTouchHandle,
      gfx::Point(rect->right() / 2, rect->bottom() / 2));

  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.selected_text, "Sample Input Text");
}

#if !BUILDFLAG(IS_MAC)
// Mac has no way to open a context menu based on a keyboard event.
TEST_F(ContextMenuControllerTest,
       ValidateNonLocatedContextMenuOnLargeImageElement) {
  GetDocument()->documentElement()->setInnerHTML(
      "<img src=\"http://example.test/cat.jpg\" id=\"sample_image\" "
      "width=\"200\" height=\"10000\" tabindex=\"-1\" />");

  Document* document = GetDocument();
  Element* image_element =
      document->getElementById(AtomicString("sample_image"));
  // Set focus on the image element.
  image_element->Focus();
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // Simulate Shift + F10 key event.
  WebKeyboardEvent key_event(WebInputEvent::Type::kRawKeyDown,
                             WebInputEvent::kShiftKey,
                             WebInputEvent::GetStaticTimeStampForTests());

  key_event.windows_key_code = ui::VKEY_F10;
  GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.media_type,
            mojom::blink::ContextMenuDataMediaType::kImage);
}
#endif

TEST_F(ContextMenuControllerTest, ContextMenuImageHitTestSVGImageElement) {
  RegisterMockedImageURLLoad("http://test.png");
  Document* document = GetDocument();

  ContextMenuAllowedScope context_menu_allowed_scope;
  document->documentElement()->setInnerHTML(R"HTML(
    <svg>
      <image id="target" href="http://test.png" width="100" height="100"/>
    </svg>
  )HTML");

  // Flush the image-loading microtask.
  base::RunLoop().RunUntilIdle();

  url_test_helpers::ServeAsynchronousRequests();

  Element* image = document->getElementById(AtomicString("target"));
  EXPECT_TRUE(ShowContextMenuForElement(image, kMenuSourceLongPress));

  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ("http://test.png/", context_menu_data.src_url.spec());
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kImage,
            context_menu_data.media_type);
  EXPECT_TRUE(context_menu_data.has_image_contents);
}

TEST_F(ContextMenuControllerTest, SelectionRectClipped) {
  GetDocument()->documentElement()->setInnerHTML(
      "<textarea id='text-area' cols=6 rows=2>Sample editable text</textarea>");

  Document* document = GetDocument();
  Element* editable_element =
      document->getElementById(AtomicString("text-area"));
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  FrameSelection& selection = document->GetFrame()->Selection();

  // Select the 'Sample' of |textarea|.
  DOMRect* rect = editable_element->GetBoundingClientRect();
  WebGestureEvent gesture_event(
      WebInputEvent::Type::kGestureLongPress, WebInputEvent::kNoModifiers,
      base::TimeTicks::Now(), WebGestureDevice::kTouchscreen);
  gesture_event.SetPositionInWidget(gfx::PointF(rect->left(), rect->top()));
  GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(gesture_event, ui::LatencyInfo()));

  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.selected_text, "Sample");

  // The selection rect is not clipped.
  gfx::Rect anchor, focus;
  selection.ComputeAbsoluteBounds(anchor, focus);
  anchor = document->GetFrame()->View()->FrameToViewport(anchor);
  focus = document->GetFrame()->View()->FrameToViewport(focus);
  int left = std::min(focus.x(), anchor.x());
  int top = std::min(focus.y(), anchor.y());
  int right = std::max(focus.right(), anchor.right());
  int bottom = std::max(focus.bottom(), anchor.bottom());
  gfx::Rect selection_rect =
      document->GetFrame()->LocalFrameRoot().View()->FrameToViewport(
          gfx::Rect(left, top, right - left, bottom - top));
  EXPECT_EQ(context_menu_data.selection_rect, selection_rect);

  // Select all the content of |textarea|.
  selection.SelectAll();
  EXPECT_TRUE(ShowContextMenuForElement(editable_element, kMenuSourceMouse));

  context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(context_menu_data.selected_text, "Sample editable text");

  // The selection rect is clipped by the editable box.
  gfx::Rect clip_bound = editable_element->VisibleBoundsInLocalRoot();
  selection.ComputeAbsoluteBounds(anchor, focus);
  anchor = document->GetFrame()->View()->ConvertToRootFrame(anchor);
  focus = document->GetFrame()->View()->ConvertToRootFrame(focus);
  left = std::max(clip_bound.x(), std::min(focus.x(), anchor.x()));
  top = std::max(clip_bound.y(), std::min(focus.y(), anchor.y()));
  right = std::min(clip_bound.right(), std::max(focus.right(), anchor.right()));
  bottom =
      std::min(clip_bound.bottom(), std::max(focus.bottom(), anchor.bottom()));
  selection_rect =
      document->GetFrame()->LocalFrameRoot().View()->FrameToViewport(
          gfx::Rect(left, top, right - left, bottom - top));
  EXPECT_EQ(context_menu_data.selection_rect, selection_rect);
}

class MockEventListener final : public NativeEventListener {
 public:
  MOCK_METHOD2(Invoke, void(ExecutionContext*, Event*));
};

// Test that a basic image hit test works and is no† impacted by
// penetrating image selection logic.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageHitTestStandardImageSelection) {
  String url = "http://test.png";
  LOG(ERROR) << "URL IS: " << url.Utf8().c_str();
  RegisterMockedImageURLLoad(url);

  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
      </style>
      <img id=target src="http://test.png">
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ("http://test.png/", context_menu_data.src_url.spec());
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kImage,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that image selection can penetrate through a fully transparent div
// above the target image.
TEST_F(ContextMenuControllerTest, ContextMenuImageHitTestSucceededPenetrating) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <img id=target src='http://test.png'>
      <div id=occluder></div>
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ("http://test.png/", context_menu_data.src_url.spec());
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kImage,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that a basic image hit test works and is no† impacted by
// penetrating image selection logic.
TEST_F(ContextMenuControllerTest, ContextMenuImageHitTestStandardCanvas) {
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
      </style>
      <canvas id=target>
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kCanvas,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that  an image node will not be selected through an opaque div
// above the target image.
TEST_F(ContextMenuControllerTest, ContextMenuImageHitTestOpaqueNodeBlocking) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #opaque {
          background: blue;
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 3;
        }
      </style>

      <img id=target src='http://test.png'>
      <div id=opaque></div>
      <div id=occluder></div>
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kNone,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that an image node will not be selected if a node with a context menu
// listener is above the image node, but that we will still log the presence of
// the image.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageHitTestContextMenuListenerAboveImageBlocking) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #nodewithlistener {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 3;
        }
      </style>
      <img id=target src='http://test.png'>
      <div id=nodewithlistener></div>
      <div id=occluder></div>
    </body>
)HTML");

  Persistent<MockEventListener> event_listener =
      MakeGarbageCollected<MockEventListener>();
  base::HistogramTester histograms;

  Element* target_image = GetDocument()->getElementById(AtomicString("target"));
  target_image->addEventListener(event_type_names::kContextmenu,
                                 event_listener);

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kNone,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that an image node will not be selected if the image node itself has a
// context menu listener on it (and the image node is not the topmost element)
TEST_F(ContextMenuControllerTest,
       ContextMenuImageHitTestContextMenuListenerOnImageBlocking) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <img id=target src='http://test.png'>
      <div id=occluder></div>
    </body>
  )HTML");

  // Attaching a listener for the finished event indicates pending activity.
  Persistent<MockEventListener> event_listener =
      MakeGarbageCollected<MockEventListener>();
  base::HistogramTester histograms;

  Element* target_image = GetDocument()->getElementById(AtomicString("target"));
  target_image->addEventListener(event_type_names::kContextmenu,
                                 event_listener);

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kNone,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that an image node will be selected if the image node itself has an
// unrelated event listener on it.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageHitTestNonBlockingNonContextMenuListenerOnImage) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <img id=target src='http://test.png'>
      <div id=occluder></div>
    </body>
  )HTML");

  Persistent<MockEventListener> event_listener =
      MakeGarbageCollected<MockEventListener>();
  base::HistogramTester histograms;

  Element* target_image = GetDocument()->getElementById(AtomicString("target"));
  target_image->addEventListener(event_type_names::kClick, event_listener);

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kImage,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that an image node will still be selected if it is the topmost node
// despite an ancestor having a context menu listener attached to it.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageHitTestStandardContextMenuListenerAncestorNonBlocking) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #hiddenancestor {
          top: 0;
          left: 0;
          position: absolute;
          width: 1px;
          height: 1px;
          z-index: 1;
        }
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <div id=hiddenancestor>
        <img id=target src='http://test.png'>
      </div>
    </body>
  )HTML");

  Persistent<MockEventListener> event_listener =
      MakeGarbageCollected<MockEventListener>();
  base::HistogramTester histograms;

  Element* hidden_ancestor =
      GetDocument()->getElementById(AtomicString("hiddenancestor"));
  hidden_ancestor->addEventListener(event_type_names::kContextmenu,
                                    event_listener);

  // This hit test would miss the node with the listener if it was not an
  // ancestor.
  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  // EXPECT_TRUE(context_menu_data.has_image_contents);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that an image node will not be selected if a non image node with a
// context listener ancestor is above it and verify that topmost context menu
// listener special logic only applies if the topmost node is an image.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageHitTestContextMenuListenerAncestorBlocking) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #hiddenancestor {
          top: 0;
          left: 0;
          position: absolute;
          width: 1px;
          height: 1px;
          z-index: 2;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 3;
        }
      </style>
      <img id=target src='http://test.png'>
      <div id=hiddenancestor>
        <div id=occluder></div>
      </div>
    </body>
  )HTML");

  Persistent<MockEventListener> event_listener =
      MakeGarbageCollected<MockEventListener>();
  base::HistogramTester histograms;

  Element* hidden_ancestor =
      GetDocument()->getElementById(AtomicString("hiddenancestor"));
  hidden_ancestor->addEventListener(event_type_names::kContextmenu,
                                    event_listener);

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  // Context menu info are sent to the WebLocalFrameClient.
  ContextMenuData context_menu_data = GetWebFrameClient().GetContextMenuData();
  EXPECT_EQ(mojom::blink::ContextMenuDataMediaType::kNone,
            context_menu_data.media_type);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundStandard, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kImageFoundPenetrating, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByOpaqueNode, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kFoundContextMenuListener,
      1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.Outcome",
      ContextMenuController::ImageSelectionOutcome::kBlockedByCrossFrameNode,
      0);
}

// Test that an image node is successfully cached and retrieved in the common
// case.
TEST_F(ContextMenuControllerTest, ContextMenuImageRetrievalCachedImageFound) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <img id=target src='http://test.png'>
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location, kMenuSourceLongPress));

  Node* image_node =
      web_view_helper_.GetWebView()
          ->GetPage()
          ->GetContextMenuController()
          .ContextMenuImageNodeForFrame(GetDocument()->GetFrame());
  EXPECT_TRUE(image_node != nullptr);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageFound, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageNotFound, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::
          kCrossFrameRetrieval,
      0);
}

// Test that an image node is not successfully retrieved if a hit test was never
// conducted.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageRetrievalCachedImageNotFound) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #occluder {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 2;
        }
      </style>
      <img id=target src='http://test.png'>
    </body>
  )HTML");

  base::HistogramTester histograms;

  // Attempt to retrieve without an initial call to show the context menu.
  Node* image_node =
      web_view_helper_.GetWebView()
          ->GetPage()
          ->GetContextMenuController()
          .ContextMenuImageNodeForFrame(GetDocument()->GetFrame());
  EXPECT_TRUE(image_node == nullptr);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageFound, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageNotFound, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::
          kCrossFrameRetrieval,
      0);
}

// Test that the retrieved image node is null if another hit test has been
// conducted in the same controller before the retrieval occurred.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageRetrievalAfterCachedImageReset) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #linktarget {
          top: 100px;
          left: 100px;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
      </style>
      <img id=target src='http://test.png'>
      <a id=linktarget href='about:blank'>Content</a>
    </body>
  )HTML");

  base::HistogramTester histograms;

  PhysicalOffset location_with_image(LayoutUnit(5), LayoutUnit(5));
  EXPECT_TRUE(ShowContextMenu(location_with_image, kMenuSourceLongPress));

  PhysicalOffset location_with_link(LayoutUnit(105), LayoutUnit(105));
  ShowContextMenu(location_with_link, kMenuSourceLongPress);

  Node* image_node =
      web_view_helper_.GetWebView()
          ->GetPage()
          ->GetContextMenuController()
          .ContextMenuImageNodeForFrame(GetDocument()->GetFrame());
  EXPECT_TRUE(image_node == nullptr);

  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageFound, 0);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::kImageNotFound, 1);
  histograms.ExpectBucketCount(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome",
      ContextMenuController::ImageSelectionRetrievalOutcome::
          kCrossFrameRetrieval,
      0);
}

// Test that the retrieved image node is null if the retrieval frame is
// different than the one used in the initial context menu image selection.
TEST_F(ContextMenuControllerTest,
       ContextMenuImageRetrievalCachedImageCrossFrame) {
  RegisterMockedImageURLLoad("http://test.png");
  ContextMenuAllowedScope context_menu_allowed_scope;

  GetDocument()->documentElement()->setInnerHTML(R"HTML(
    <body>
      <style>
        #target {
          top: 0;
          left: 0;
          position: absolute;
          width: 100px;
          height: 100px;
          z-index: 1;
        }
        #occ
```
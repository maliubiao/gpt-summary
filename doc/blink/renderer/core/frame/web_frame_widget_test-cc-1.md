Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine, specifically `web_frame_widget_test.cc`. They want to know its functionalities and how they relate to web technologies like Javascript, HTML, and CSS. I also need to provide examples for logical inferences, common usage errors, and summarize the functionalities covered in this specific part of the file.

Based on the provided code, this section of the test file focuses on:

1. **Testing the `ProximateBoundsCollection` functionality**: This seems related to how the browser collects the bounding boxes of elements near a specific point, likely for stylus or touch input scenarios. The tests cover various scenarios with different HTML structures (input fields, contenteditable divs, elements inside SVG), and different focus points.

2. **Testing the `NotifySwapAndPresentationTimeForTesting` functionality**: This appears to be for testing how the browser tracks and reports the timing of compositor frame swaps and presentations. The tests simulate successful and failed presentations, and scenarios with failed commits.

3. **Testing how `is_pinch_gesture_active` is handled**: This test verifies that the pinch-to-zoom gesture status is not directly propagated from the render process to the compositor for the main frame.

4. **Testing touch event handling during drag and devtools scenarios**: This test checks if touch events are correctly ignored when a drag-and-drop operation is in progress or when devtools are set to ignore input events.

5. **Testing page scale propagation to remote frames**: This test verifies that when the page scale is changed in the main frame, the change is also applied to remote iframes.

6. **Testing the reporting of visible line bounds**:  These tests check if the browser correctly reports the bounding boxes of visible lines of text, particularly after focus changes in input fields.

7. **Testing the `display-state` media query**: This test checks if the browser correctly applies CSS styles based on the window's display state (normal, minimized, maximized, fullscreen).

8. **Testing the `resizable` media query**: This test checks if the browser correctly applies CSS styles based on whether the window is resizable.
这是 `blink/renderer/core/frame/web_frame_widget_test.cc` 文件的一部分，主要功能集中在以下几个方面：

**1. 测试临近边界的收集 (Proximate Bounds Collection)**

*   **功能:** 这部分测试验证了 `WebFrameWidget` 如何收集与特定焦点区域临近的可编辑文本范围的边界信息。这通常用于处理手写输入或者精确触摸输入，以便系统能更好地识别用户可能的目标位置。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **HTML:** 测试用例中使用了多种 HTML 结构，包括 `input` 元素、`contenteditable` 属性的 `div` 元素，以及位于 `<svg>` 元素内部的 `foreignObject` 中的可编辑元素。这些不同的 HTML 结构会影响边界的计算和收集。
    *   **CSS:**  测试用例中引用了 `styles.css`，虽然在给出的代码片段中没有具体内容，但可以推断 CSS 样式会影响元素的布局和大小，从而影响临近边界的计算。例如，元素的 `margin`、`padding`、`border` 和 `font-size` 都会影响其边界。
    *   **Javascript:** 虽然这段代码本身是 C++ 测试代码，但它测试的功能是为 Javascript 提供的 API 或事件处理做准备的。例如，当用户在屏幕上进行手写输入时，浏览器可能需要收集临近的文本框边界，并将这些信息传递给 Javascript 以进行后续处理（例如，确定用户想要输入的位置）。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:** 用户使用手写笔点击或触摸 `target_editable` 元素附近的区域。`get_focus_rect_in_widget` 函数根据不同的测试用例返回不同的 `gfx::Rect` 作为焦点区域。
    *   **输出:**  `GetLastProximateBounds()` 会返回一个包含临近文本范围的 `gfx::Range` 和对应的边界 `gfx::Rect` 向量的结构。如果没有找到合适的临近范围，则返回 `nullptr`。
*   **用户或编程常见的使用错误:**
    *   **错误假设焦点区域:** 开发者可能会错误地假设焦点区域能精准地覆盖目标可编辑元素，但实际情况可能由于布局或触摸精度问题导致焦点区域偏移，从而导致 `ProximateBoundsCollection` 无法找到正确的临近范围。例如，在测试用例中，如果 `get_focus_rect_in_widget` 返回的矩形完全落在只读元素上，那么期望的输出是 `touch_fallback` 元素获得焦点，并且没有临近边界被收集。

**2. 测试交换和呈现时间通知 (Notify Swap Times)**

*   **功能:** 这部分测试验证了 `WebFrameWidget` 如何通知关于渲染帧缓冲区交换（swap）和呈现（presentation）的时间信息。这对于性能监控和动画同步至关重要。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **Javascript:**  Javascript 动画通常依赖于浏览器的渲染循环。了解帧的交换和呈现时间可以帮助开发者编写更流畅的动画，并避免卡顿。例如，可以使用这些时间戳来同步 Javascript 动画与 CSS 动画或浏览器渲染过程。
    *   **HTML/CSS:** 复杂的 HTML 结构和大量的 CSS 样式可能会增加渲染的负担，导致帧交换和呈现的时间变长。这些测试有助于确保在各种情况下，时间通知机制的正确性。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:**  浏览器完成了一次渲染帧的合成，准备将其显示到屏幕上。
    *   **输出:**  注册的回调函数 (`NotifySwapAndPresentationTimeForTesting`) 会被调用，并接收到交换发生的时间戳以及呈现的详细信息（包括呈现时间戳）。
*   **用户或编程常见的使用错误:**
    *   **误解时间戳含义:** 开发者可能会混淆交换时间和呈现时间，或者错误地理解时间戳的单位和参照系，导致在同步动画或性能分析时出现错误。
    *   **未处理失败的呈现:** 测试用例中模拟了失败的呈现反馈。开发者编写的代码应该能够处理这种情况，例如，当呈现失败时，可能需要重新渲染或者采取其他补救措施。

**3. 测试 Pinch 手势激活状态 (Active Pinch Gesture)**

*   **功能:**  测试验证了主框架的 `LayerTreeHost` 是否会接收到外部 Pinch 手势激活状态的更新。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **Javascript:** Javascript 可以监听 touch 事件来检测 pinch 手势，但这个测试关注的是浏览器内部如何处理 pinch 手势状态。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:** 用户在屏幕上执行 pinch-to-zoom 手势。
    *   **输出:**  主框架的 `LayerTreeHost` 的 `is_external_pinch_gesture_active_for_testing()` 应该保持为 `false`，因为主框架的 pinch 手势由 Layer Tree 直接处理。

**4. 测试输入事件处理 (Input Events)**

*   **功能:** 测试在拖拽操作或 DevTools 开启忽略输入事件标志时，是否会正确缓冲和处理触摸事件。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **Javascript:**  Javascript 可以注册触摸事件监听器。这个测试验证了在特定场景下，这些监听器是否会被正确调用或忽略。
    *   **HTML:** HTML 元素可以触发各种输入事件。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:** 用户在页面上进行触摸操作。
    *   **输出:**  当没有拖拽操作且 DevTools 未设置忽略输入时，触摸事件监听器会被调用。反之，则不会被调用。
*   **用户或编程常见的使用错误:**
    *   **在拖拽期间误处理事件:** 开发者可能会编写在拖拽操作期间仍然响应触摸事件的代码，导致意外行为。

**5. 测试页面缩放传播 (Propagate Scale to Remote Frames)**

*   **功能:** 测试当主框架的页面缩放级别发生变化时，这个变化是否会传播到远程 iframe。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **HTML:**  涉及 iframe 元素的页面结构。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:**  调用 `widget->SetPageScaleStateAndLimits()` 更改主框架的页面缩放。
    *   **输出:**  远程 iframe 的 `pendingVisualPropertiesForTesting` 中的 `page_scale_factor` 应该与主框架的新缩放级别一致。

**6. 测试行边界 (Line Bounds)**

*   **功能:** 测试在焦点改变时，`WebFrameWidget` 是否能正确报告可见文本行的边界。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **HTML:**  测试用例使用了 `<input>` 元素。
    *   **CSS:**  CSS 样式（例如 `font-family`, `font-size`) 会影响文本行的布局和边界。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:** 用户聚焦到一个 `<input>` 元素。
    *   **输出:**  `widget->GetVisibleLineBoundsOnScreen()` 应该返回该输入框中可见文本行的正确边界矩形。

**7. 测试显示状态媒体查询 (Display State Media Query)**

*   **功能:** 测试浏览器是否能正确匹配 CSS 中的 `display-state` 媒体查询，并根据窗口的显示状态（normal, minimized, maximized, fullscreen）应用相应的样式。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **CSS:**  利用 `@media (display-state: ...)` 媒体查询来定义不同显示状态下的样式。
*   **逻辑推理 - 假设输入与输出:**
    *   **假设输入:**  将窗口的显示状态设置为最小化 (`kMinimized`)。
    *   **输出:**  应用了 `@media (display-state: minimized)` 中定义的 CSS 样式。

**8. 测试可调整大小媒体查询 (Resizable Media Query)**

*   **功能:** 测试浏览器是否能正确匹配 CSS 中的 `resizable` 媒体查询，并根据窗口是否可调整大小应用相应的样式。
*   **与 Javascript, HTML, CSS 的关系:**
    *   **CSS:** 利用 `@media (resizable: ...)` 媒体查询来定义不同可调整大小状态下的样式.

**总结 (针对第 2 部分):**

这段代码主要集中在测试 `WebFrameWidget` 的以下核心功能：

*   **收集临近可编辑区域的边界信息 (Proximate Bounds Collection)**，这对于精确输入交互至关重要。
*   **追踪和报告渲染帧的交换和呈现时间 (Notify Swap Times)**，这对于性能监控和动画同步很重要。
*   **处理输入事件，并在特定场景下正确地缓冲或忽略触摸事件。**
*   **确保页面缩放设置能够正确地传播到包含的远程框架。**
*   **正确地报告可见文本行的边界信息，并能根据窗口的显示状态和可调整大小状态应用相应的 CSS 样式。**

这些功能共同确保了 Web 内容能够正确地渲染、响应用户输入，并提供良好的用户体验。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_widget_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
rget_editable);
  EXPECT_EQ(GetLastProximateBounds(), nullptr);
}

TEST_F(WebFrameWidgetProximateBoundsCollectionSimTestF, EmptyTextRange) {
  LoadDocument(String(R"HTML(
    <!doctype html>
    <link rel="stylesheet" href="styles.css">
    <body>
      <div id='target_editable' contenteditable></div>
      <div id="touch_fallback" contenteditable></div>
    </body>
  )HTML"));
  HandlePointerDownEventOverTouchFallback();
  const Element& target_editable = *GetElementById("target_editable");
  StartStylusWritingOnElementCenter(target_editable);
  EXPECT_EQ(GetDocument().FocusedElement(), target_editable);
  EXPECT_EQ(GetLastProximateBounds(), nullptr);
}

TEST_F(WebFrameWidgetProximateBoundsCollectionSimTestF, EmptyFocusRect) {
  LoadDocument(String(R"HTML(
    <!doctype html>
    <link rel="stylesheet" href="styles.css">
    <body>
      <div id='target_editable' contenteditable></div>
      <div id="touch_fallback" contenteditable>ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
    </body>
  )HTML"));
  HandlePointerDownEventOverTouchFallback();
  OnStartStylusWriting(gfx::Rect());
  EXPECT_EQ(GetDocument().FocusedElement(), GetElementById("touch_fallback"));
  EXPECT_EQ(GetLastProximateBounds(), nullptr);
}

INSTANTIATE_TEST_SUITE_P(
    All,
    WebFrameWidgetProximateBoundsCollectionSimTestP,
    ::testing::ConvertGenerator<
        WebFrameWidgetProximateBoundsCollectionSimTestParam::TupleType>(
        testing::Combine(
            // std::get<0> enable_stylus_handwriting_win
            testing::Bool(),
            // std::get<1> document
            testing::Values(
                // input element test
                R"HTML(
                <!doctype html>
                <link rel="stylesheet" href="styles.css">
                <body>
                <input type='text' id='target_editable'
                       value='ABCDEFGHIJKLMNOPQRSTUVWXYZ'/>
                <div id="target_readonly">ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
                <div id="touch_fallback" contenteditable>Fallback Text</div>
                </body>
                )HTML",
                // contenteditable element test
                R"HTML(
                <!doctype html>
                <link rel="stylesheet" href="styles.css">
                <body>
                <div id='target_editable' contenteditable>ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
                <div id="target_readonly">ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
                <div id="touch_fallback" contenteditable>Fallback Text</div>
                </body>
                )HTML",
                // contenteditable child element test
                R"HTML(
                <!doctype html>
                <link rel="stylesheet" href="styles.css">
                <body>
                <div id='target_editable' contenteditable><span id='second'>ABCDEFGHIJKLMNOPQRSTUVWXYZ</span></div>
                <div id="target_readonly">ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
                <div id="touch_fallback" contenteditable>Fallback Text</div>
                </body>
                )HTML",
                // contenteditable inside <svg> <foreignObject> test
                R"HTML(
                <!doctype html>
                <link rel="stylesheet" href="styles.css">
                <svg viewBox="0 0 400 400" xmlns="http://www.w3.org/2000/svg">
                  <foreignObject x="0" y="0" width="400" height="400">
                    <div id='target_editable' contenteditable>ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
                    <div id="target_readonly">ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
                    <div id="touch_fallback" contenteditable>Fallback Text</div>
                  </foreignObject>
                </svg>
                )HTML"),
            // std::get<2> proximate_bounds_collection_args
            testing::Values(
                // Test that bounds collection expands in both
                // directions relative to the pivot position up-to
                // the `ProximateBoundsCollectionHalfLimit()`.
                ProximateBoundsCollectionArgs{
                    /*get_focus_rect_in_widget=*/base::BindRepeating(
                        [](const Document& document) -> gfx::Rect {
                          const Element* target = document.getElementById(
                              AtomicString("target_editable"));
                          gfx::Rect focus_rect_in_widget(
                              target->BoundsInWidget().top_center(),
                              gfx::Size());
                          focus_rect_in_widget.Outset(gfx::Outsets(25));
                          return focus_rect_in_widget;
                        }),
                    /*expected_focus_id=*/"target_editable",
                    /*expect_null_proximate_bounds=*/false,
                    /*expected_range=*/gfx::Range(11, 15),
                    /*expected_bounds=*/
                    {gfx::Rect(110, 0, 10, 10), gfx::Rect(120, 0, 10, 10),
                     gfx::Rect(130, 0, 10, 10), gfx::Rect(140, 0, 10, 10)}},
                // Test that bounds collection at the start of a text
                // range only expands in one direction up-to the
                // `ProximateBoundsCollectionHalfLimit()`.
                ProximateBoundsCollectionArgs{
                    /*get_focus_rect_in_widget=*/base::BindRepeating(
                        [](const Document& document) -> gfx::Rect {
                          const Element* target = document.getElementById(
                              AtomicString("target_editable"));
                          gfx::Rect focus_rect_in_widget(
                              target->BoundsInWidget().origin(), gfx::Size());
                          focus_rect_in_widget.Outset(gfx::Outsets(25));
                          return focus_rect_in_widget;
                        }),
                    /*expected_focus_id=*/"target_editable",
                    /*expect_null_proximate_bounds=*/false,
                    /*expected_range=*/gfx::Range(0, 2),
                    /*expected_bounds=*/
                    {gfx::Rect(0, 0, 10, 10), gfx::Rect(10, 0, 10, 10)}},
                // Test that bounds collection at the end of a text
                // range only expands in one direction up-to the
                // `ProximateBoundsCollectionHalfLimit()`.
                ProximateBoundsCollectionArgs{
                    /*get_focus_rect_in_widget=*/base::BindRepeating(
                        [](const Document& document) -> gfx::Rect {
                          const Element* target = document.getElementById(
                              AtomicString("target_editable"));
                          gfx::Rect focus_rect_in_widget(
                              target->BoundsInWidget().top_right() -
                                  gfx::Vector2d(1, 0),
                              gfx::Size());
                          focus_rect_in_widget.Outset(gfx::Outsets(25));
                          return focus_rect_in_widget;
                        }),
                    /*expected_focus_id=*/"target_editable",
                    /*expect_null_proximate_bounds=*/false,
                    /*expected_range=*/gfx::Range(24, 26),
                    /*expected_bounds=*/
                    {gfx::Rect(240, 0, 10, 10), gfx::Rect(250, 0, 9, 10)}},
                // Test that `touch_fallback` is focused when
                // `focus_rect_in_widget` misses, but it shouldn't collect
                // bounds because the pivot offset cannot be determined.
                ProximateBoundsCollectionArgs{
                    /*get_focus_rect_in_widget=*/base::BindRepeating(
                        [](const Document& document) -> gfx::Rect {
                          const Element* target = document.getElementById(
                              AtomicString("target_editable"));
                          gfx::Rect focus_rect_in_widget(
                              target->BoundsInWidget().right_center() +
                                  gfx::Vector2d(100, 0),
                              gfx::Size());
                          focus_rect_in_widget.Outset(gfx::Outsets(25));
                          return focus_rect_in_widget;
                        }),
                    /*expected_focus_id=*/"touch_fallback",
                    /*expect_null_proximate_bounds=*/true,
                    /*expected_range=*/gfx::Range(),
                    /*expected_bounds=*/{}},
                // Test that `touch_fallback` is focused when
                // `focus_rect_in_widget` hits non-editable content, but it
                // shouldn't collect bounds because the pivot offset cannot be
                // determined.
                ProximateBoundsCollectionArgs{
                    /*get_focus_rect_in_widget=*/base::BindRepeating(
                        [](const Document& document) -> gfx::Rect {
                          const Element* target = document.getElementById(
                              AtomicString("target_readonly"));
                          gfx::Rect focus_rect_in_widget(
                              target->BoundsInWidget().CenterPoint(),
                              gfx::Size());
                          focus_rect_in_widget.Outset(gfx::Outsets(25));
                          return focus_rect_in_widget;
                        }),
                    /*expected_focus_id=*/"touch_fallback",
                    /*expect_null_proximate_bounds=*/true,
                    /*expected_range=*/gfx::Range(),
                    /*expected_bounds=*/{}}))));

TEST_P(WebFrameWidgetProximateBoundsCollectionSimTestP,
       TestProximateBoundsCollection) {
  LoadDocument(String(GetParam().GetHTMLDocument()));
  HandlePointerDownEventOverTouchFallback();
  OnStartStylusWriting(GetParam().GetFocusRectInWidget(GetDocument()));
  if (!GetParam().IsStylusHandwritingWinEnabled()) {
    EXPECT_EQ(GetDocument().FocusedElement(), nullptr);
    EXPECT_EQ(GetLastProximateBounds(), nullptr);
    return;
  }

  // Focus expectations.
  const Element* expected_focus =
      GetElementById(GetParam().GetExpectedFocusId().c_str());
  const Element* actual_focus = GetDocument().FocusedElement();
  ASSERT_NE(actual_focus, nullptr);
  EXPECT_EQ(actual_focus, expected_focus);

  // `Proximate` bounds cache expectations.
  EXPECT_EQ(!GetLastProximateBounds(), GetParam().ExpectNullProximateBounds());
  if (!GetParam().ExpectNullProximateBounds()) {
    EXPECT_EQ(GetLastProximateBounds()->range, GetParam().GetExpectedRange());
    EXPECT_TRUE(std::equal(GetLastProximateBounds()->bounds.begin(),
                           GetLastProximateBounds()->bounds.end(),
                           GetParam().GetExpectedBounds().begin(),
                           GetParam().GetExpectedBounds().end()));
  }
}
#endif  // BUILDFLAG(IS_WIN)

class NotifySwapTimesWebFrameWidgetTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();

    WebView().StopDeferringMainFrameUpdate();
    FrameWidgetBase()->UpdateCompositorViewportRect(gfx::Rect(200, 100));
    Compositor().BeginFrame();

    auto* root_layer =
        FrameWidgetBase()->LayerTreeHostForTesting()->root_layer();
    auto color_layer = cc::SolidColorLayer::Create();
    color_layer->SetBounds(gfx::Size(100, 100));
    cc::CopyProperties(root_layer, color_layer.get());
    root_layer->SetChildLayerList(cc::LayerList({color_layer}));
    color_layer->SetBackgroundColor(SkColors::kRed);
  }

  WebFrameWidgetImpl* FrameWidgetBase() {
    return static_cast<WebFrameWidgetImpl*>(MainFrame().FrameWidget());
  }

  // |swap_to_presentation| determines how long after swap should presentation
  // happen. This can be negative, positive, or zero. If zero, an invalid (null)
  // presentation time is used.
  void CompositeAndWaitForPresentation(base::TimeDelta swap_to_presentation) {
    base::RunLoop swap_run_loop;
    base::RunLoop presentation_run_loop;

    // Register callbacks for swap and presentation times.
    base::TimeTicks swap_time;
    static_cast<WebFrameWidgetImpl*>(MainFrame().FrameWidget())
        ->NotifySwapAndPresentationTimeForTesting(
            {WTF::BindOnce(
                 [](base::OnceClosure swap_quit_closure,
                    base::TimeTicks* swap_time, base::TimeTicks timestamp) {
                   CHECK(!timestamp.is_null());
                   *swap_time = timestamp;
                   std::move(swap_quit_closure).Run();
                 },
                 swap_run_loop.QuitClosure(), WTF::Unretained(&swap_time)),
             WTF::BindOnce(
                 [](base::OnceClosure presentation_quit_closure,
                    const viz::FrameTimingDetails& presentation_details) {
                   base::TimeTicks timestamp =
                       presentation_details.presentation_feedback.timestamp;
                   CHECK(!timestamp.is_null());
                   std::move(presentation_quit_closure).Run();
                 },
                 presentation_run_loop.QuitClosure())});

    // Composite and wait for the swap to complete.
    Compositor().BeginFrame(/*time_delta_in_seconds=*/0.016, /*raster=*/true);
    swap_run_loop.Run();

    // Present and wait for it to complete.
    viz::FrameTimingDetails timing_details;
    if (!swap_to_presentation.is_zero()) {
      timing_details.presentation_feedback = gfx::PresentationFeedback(
          swap_time + swap_to_presentation, base::Milliseconds(16), 0);
    }
    auto* last_frame_sink = GetWebFrameWidget().LastCreatedFrameSink();
    last_frame_sink->NotifyDidPresentCompositorFrame(1, timing_details);
    presentation_run_loop.Run();
  }
};

// Verifies that the presentation callback is called after the first successful
// presentation (skips failed presentations in between).
TEST_F(NotifySwapTimesWebFrameWidgetTest, NotifyOnSuccessfulPresentation) {
  base::HistogramTester histograms;

  constexpr base::TimeDelta swap_to_failed = base::Microseconds(2);
  constexpr base::TimeDelta failed_to_successful = base::Microseconds(3);

  base::RunLoop swap_run_loop;
  base::RunLoop presentation_run_loop;

  base::TimeTicks failed_presentation_time;
  base::TimeTicks successful_presentation_time;

  WebFrameWidgetImpl::PromiseCallbacks callbacks = {
      base::BindLambdaForTesting([&](base::TimeTicks timestamp) {
        DCHECK(!timestamp.is_null());

        // Now that the swap time is known, we can determine what
        // timestamps should we use for the failed and the subsequent
        // successful presentations.
        DCHECK(failed_presentation_time.is_null());
        failed_presentation_time = timestamp + swap_to_failed;
        DCHECK(successful_presentation_time.is_null());
        successful_presentation_time =
            failed_presentation_time + failed_to_successful;

        swap_run_loop.Quit();
      }),
      base::BindLambdaForTesting(
          [&](const viz::FrameTimingDetails& presentation_details) {
            base::TimeTicks timestamp =
                presentation_details.presentation_feedback.timestamp;
            CHECK(!timestamp.is_null());
            CHECK(!failed_presentation_time.is_null());
            CHECK(!successful_presentation_time.is_null());

            // Verify that this callback is run in response to the
            // successful presentation, not the failed one before that.
            EXPECT_NE(timestamp, failed_presentation_time);
            EXPECT_EQ(timestamp, successful_presentation_time);

            presentation_run_loop.Quit();
          })};

#if BUILDFLAG(IS_MAC)
  // Assign a ca_layer error code.
  constexpr gfx::CALayerResult ca_layer_error_code =
      gfx::kCALayerFailedTileNotCandidate;

  callbacks.core_animation_error_code_callback = base::BindLambdaForTesting(
      [&](gfx::CALayerResult core_animation_error_code) {
        // Verify that the error code received here is the same as the
        // one sent to DidPresentCompositorFrame.
        EXPECT_EQ(ca_layer_error_code, core_animation_error_code);

        presentation_run_loop.Quit();
      });
#endif

  // Register callbacks for swap and presentation times.
  static_cast<WebFrameWidgetImpl*>(MainFrame().FrameWidget())
      ->NotifySwapAndPresentationTimeForTesting(std::move(callbacks));

  // Composite and wait for the swap to complete.
  Compositor().BeginFrame(/*time_delta_in_seconds=*/0.016, /*raster=*/true);
  swap_run_loop.Run();

  // Respond with a failed presentation feedback.
  DCHECK(!failed_presentation_time.is_null());
  viz::FrameTimingDetails failed_timing_details;
  failed_timing_details.presentation_feedback = gfx::PresentationFeedback(
      failed_presentation_time, base::Milliseconds(16),
      gfx::PresentationFeedback::kFailure);
  GetWebFrameWidget().LastCreatedFrameSink()->NotifyDidPresentCompositorFrame(
      1, failed_timing_details);

  // Respond with a successful presentation feedback.
  DCHECK(!successful_presentation_time.is_null());
  viz::FrameTimingDetails successful_timing_details;
  successful_timing_details.presentation_feedback = gfx::PresentationFeedback(
      successful_presentation_time, base::Milliseconds(16), 0);
#if BUILDFLAG(IS_MAC)
  successful_timing_details.presentation_feedback.ca_layer_error_code =
      ca_layer_error_code;
#endif
  GetWebFrameWidget().LastCreatedFrameSink()->NotifyDidPresentCompositorFrame(
      2, successful_timing_details);

  // Wait for the presentation callback to be called. It should be called with
  // the timestamp of the successful presentation.
  presentation_run_loop.Run();
}

// Tests that the presentation callback is only triggered if there’s
// a successful commit to the compositor.
TEST_F(NotifySwapTimesWebFrameWidgetTest,
       ReportPresentationOnlyOnSuccessfulCommit) {
  base::HistogramTester histograms;
  constexpr base::TimeDelta delta = base::Milliseconds(16);
  constexpr base::TimeDelta delta_from_swap_time = base::Microseconds(2);

  base::RunLoop swap_run_loop;
  base::RunLoop presentation_run_loop;
  base::TimeTicks presentation_time;

  // Register callbacks for swap and presentation times.
  static_cast<WebFrameWidgetImpl*>(MainFrame().FrameWidget())
      ->NotifySwapAndPresentationTimeForTesting(
          {base::BindLambdaForTesting([&](base::TimeTicks timestamp) {
             DCHECK(!timestamp.is_null());
             DCHECK(presentation_time.is_null());

             // Set the expected presentation time after the swap takes place.
             presentation_time = timestamp + delta_from_swap_time;
             swap_run_loop.Quit();
           }),
           base::BindLambdaForTesting(
               [&](const viz::FrameTimingDetails& presentation_details) {
                 base::TimeTicks timestamp =
                     presentation_details.presentation_feedback.timestamp;
                 CHECK(!timestamp.is_null());
                 CHECK(!presentation_time.is_null());

                 // Verify that the presentation is only reported on the
                 // successful commit to the compositor.
                 EXPECT_EQ(timestamp, presentation_time);
                 presentation_run_loop.Quit();
               })});

  // Simulate a failed commit to the compositor, which should not trigger either
  // a swap or a presentation callback in response.
  auto* layer_tree_host = Compositor().LayerTreeHost();
  layer_tree_host->GetSwapPromiseManager()->BreakSwapPromises(
      cc::SwapPromise::DidNotSwapReason::COMMIT_FAILS);

  // Check that a swap callback wasn't triggered for the above failed commit.
  EXPECT_TRUE(presentation_time.is_null());

  // Composite and wait for the swap to complete successfully.
  Compositor().BeginFrame(delta.InSecondsF(), true);
  swap_run_loop.Run();

  // Make sure that the swap is completed successfully.
  EXPECT_FALSE(presentation_time.is_null());

  // Respond with a presentation feedback.
  viz::FrameTimingDetails frame_timing_details;
  frame_timing_details.presentation_feedback =
      gfx::PresentationFeedback(presentation_time, delta, 0);
  GetWebFrameWidget().LastCreatedFrameSink()->NotifyDidPresentCompositorFrame(
      1, frame_timing_details);

  // Wait for the presentation callback to be called.
  presentation_run_loop.Run();
}

// Tests that the value of VisualProperties::is_pinch_gesture_active is
// not propagated to the LayerTreeHost when properties are synced for main
// frame.
TEST_F(WebFrameWidgetSimTest, ActivePinchGestureUpdatesLayerTreeHost) {
  auto* layer_tree_host =
      WebView().MainFrameViewWidget()->LayerTreeHostForTesting();
  EXPECT_FALSE(layer_tree_host->is_external_pinch_gesture_active_for_testing());
  VisualProperties visual_properties;
  visual_properties.screen_infos = display::ScreenInfos(display::ScreenInfo());

  // Sync visual properties on a mainframe RenderWidget.
  visual_properties.is_pinch_gesture_active = true;
  WebView().MainFrameViewWidget()->ApplyVisualProperties(visual_properties);
  // We do not expect the |is_pinch_gesture_active| value to propagate to the
  // LayerTreeHost for the main-frame. Since GesturePinch events are handled
  // directly by the layer tree for the main frame, it already knows whether or
  // not a pinch gesture is active, and so we shouldn't propagate this
  // information to the layer tree for a main-frame's widget.
  EXPECT_FALSE(layer_tree_host->is_external_pinch_gesture_active_for_testing());
}

class WebFrameWidgetInputEventsSimTest
    : public WebFrameWidgetSimTest,
      public testing::WithParamInterface<bool> {
 public:
  WebFrameWidgetInputEventsSimTest() {
    if (GetParam()) {
      feature_list_.InitAndEnableFeature(
          features::kPausePagesPerBrowsingContextGroup);
    } else {
      feature_list_.InitAndDisableFeature(
          features::kPausePagesPerBrowsingContextGroup);
    }
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebFrameWidgetInputEventsSimTest,
                         testing::Values(true, false));

// Tests that dispatch buffered touch events does not process events during
// drag and devtools handling.
TEST_P(WebFrameWidgetInputEventsSimTest, DispatchBufferedTouchEvents) {
  auto* widget = WebView().MainFrameViewWidget();

  auto* listener = MakeGarbageCollected<TouchMoveEventListener>();
  Window().addEventListener(
      event_type_names::kTouchmove, listener,
      MakeGarbageCollected<AddEventListenerOptionsResolved>());
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);

  // Send a start.
  SyntheticWebTouchEvent touch;
  touch.PressPoint(10, 10);
  touch.touch_start_or_first_touch_move = true;
  widget->ProcessInputEventSynchronouslyForTesting(
      WebCoalescedInputEvent(touch.Clone(), {}, {}, ui::LatencyInfo()),
      base::DoNothing());

  // Expect listener gets called.
  touch.MovePoint(0, 10, 10);
  widget->ProcessInputEventSynchronouslyForTesting(
      WebCoalescedInputEvent(touch.Clone(), {}, {}, ui::LatencyInfo()),
      base::DoNothing());
  EXPECT_TRUE(listener->GetInvokedStateAndReset());

  const base::UnguessableToken browsing_context_group_token =
      WebView().GetPage()->BrowsingContextGroupToken();

  // Expect listener does not get called, due to devtools flag.
  touch.MovePoint(0, 12, 12);
  WebFrameWidgetImpl::SetIgnoreInputEvents(browsing_context_group_token, true);
  widget->ProcessInputEventSynchronouslyForTesting(
      WebCoalescedInputEvent(touch.Clone(), {}, {}, ui::LatencyInfo()),
      base::DoNothing());
  EXPECT_TRUE(
      WebFrameWidgetImpl::IgnoreInputEvents(browsing_context_group_token));
  EXPECT_FALSE(listener->GetInvokedStateAndReset());
  WebFrameWidgetImpl::SetIgnoreInputEvents(browsing_context_group_token, false);

  // Expect listener does not get called, due to drag.
  touch.MovePoint(0, 14, 14);
  widget->StartDragging(MainFrame().GetFrame(), WebDragData(),
                        kDragOperationCopy, SkBitmap(), gfx::Vector2d(),
                        gfx::Rect());
  widget->ProcessInputEventSynchronouslyForTesting(
      WebCoalescedInputEvent(touch.Clone(), {}, {}, ui::LatencyInfo()),
      base::DoNothing());
  EXPECT_TRUE(widget->DoingDragAndDrop());
  EXPECT_FALSE(
      WebFrameWidgetImpl::IgnoreInputEvents(browsing_context_group_token));
  EXPECT_FALSE(listener->GetInvokedStateAndReset());
}

// Tests that page scale is propagated to all remote frames controlled
// by a widget.
TEST_F(WebFrameWidgetSimTest, PropagateScaleToRemoteFrames) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <iframe style='width: 200px; height: 100px;'
        srcdoc='<iframe srcdoc="plain text"></iframe>'>
        </iframe>

      )HTML");
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(WebView().MainFrame()->FirstChild());
  {
    WebFrame* grandchild = WebView().MainFrame()->FirstChild()->FirstChild();
    EXPECT_TRUE(grandchild);
    EXPECT_TRUE(grandchild->IsWebLocalFrame());
    frame_test_helpers::SwapRemoteFrame(grandchild,
                                        frame_test_helpers::CreateRemote());
  }
  auto* widget = WebView().MainFrameViewWidget();
  widget->SetPageScaleStateAndLimits(1.3f, true, 1.0f, 3.0f);
  EXPECT_EQ(
      To<WebRemoteFrameImpl>(WebView().MainFrame()->FirstChild()->FirstChild())
          ->GetFrame()
          ->GetPendingVisualPropertiesForTesting()
          .page_scale_factor,
      1.3f);
  WebView().MainFrame()->FirstChild()->FirstChild()->Detach();
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreEmptyBeforeFocus) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
        }
      </style>
      <input type='text' id='first' class='target' />
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(0U, actual.size());
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreCorrectAfterFocusChange) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
        }
      </style>
      <input type='text' id='first' class='target' />
      <input type='text' id='second' class='target' />
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  HTMLInputElement* first = DynamicTo<HTMLInputElement>(
      GetDocument().getElementById(AtomicString("first")));
  HTMLInputElement* second = DynamicTo<HTMLInputElement>(
      GetDocument().getElementById(AtomicString("second")));
  // Focus the first element and check the line bounds.
  first->SetValue("ABCD");
  first->Focus();
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  Vector<gfx::Rect> expected(Vector({gfx::Rect(0, 0, 40, 10)}));
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(expected.size(), actual.size());
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }

  // Focus the second element and check the line bounds have updated.
  second->SetValue("ABCD EFGH");
  second->Focus();
  gfx::Point origin =
      second->GetBoundingClientRect()->ToEnclosingRect().origin();
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  expected = Vector({gfx::Rect(origin.x(), origin.y(), 90, 10)});
  actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(expected.size(), actual.size());
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }
}

TEST_F(WebFrameWidgetSimTest, DisplayStateMatchesWindowShowState) {
  base::test::ScopedFeatureList feature_list(
      ScopedDesktopPWAsAdditionalWindowingControlsForTest);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
        <!doctype html>
        <style>
        body {
          background-color: white;
        }
        @media (display-state: normal) {
          body {
            background-color: yellow;
          }
        }
        @media (display-state: minimized) {
          body {
            background-color: cyan;
          }
        }
        @media (display-state: maximized) {
          body {
            background-color: red;
          }
        }
        @media (display-state: fullscreen) {
          body {
            background-color: blue;
          }
        }
      </style>
      <body></body>
      )HTML");

  auto* widget = WebView().MainFrameViewWidget();
  VisualProperties visual_properties;
  visual_properties.screen_infos = display::ScreenInfos(display::ScreenInfo());

  // display-state: normal
  // Default is set in /third_party/blink/renderer/core/frame/settings.json5.
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  EXPECT_EQ(Color::FromRGB(/*yellow*/ 255, 255, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));

  WTF::Vector<std::pair<ui::mojom::blink::WindowShowState, Color>> test_cases =
      {{ui::mojom::blink::WindowShowState::kMinimized,
        Color::FromRGB(/*cyan*/ 0, 255, 255)},
       {ui::mojom::blink::WindowShowState::kMaximized,
        Color::FromRGB(/*red*/ 255, 0, 0)},
       {ui::mojom::blink::WindowShowState::kFullscreen,
        Color::FromRGB(/*blue*/ 0, 0, 255)}};

  for (const auto& [show_state, color] : test_cases) {
    visual_properties.window_show_state = show_state;
    WebView().MainFrameWidget()->ApplyVisualProperties(visual_properties);
    widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
    EXPECT_EQ(color,
              GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                  GetCSSPropertyBackgroundColor()));
  }
}

TEST_F(WebFrameWidgetSimTest, ResizableMatchesCanResize) {
  base::test::ScopedFeatureList feature_list(
      ScopedDesktopPWAsAdditionalWindowingControlsForTest);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
        <!doctype html>
        <style>
          body {
            /* This should never activate. */
            background-color: white;
          }
          @media (resizable: true) {
            body {
              background-color: yellow;
            }
          }
          @media (resizable: false) {
            body {
              background-color: cyan;
            }
          }
        </style>
        <body></body>
      )HTML");

  auto* widget = WebView().MainFrameViewWidget();
  VisualProperties visual_properties;
  visual_properties.screen_infos = display::ScreenInfos(display::ScreenInfo());

  //
```
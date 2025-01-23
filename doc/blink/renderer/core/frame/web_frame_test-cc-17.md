Response:
The user wants a summary of the functionality of the `web_frame_test.cc` file in the Chromium Blink engine.

I need to:
1. **Identify the main purpose** of the test file.
2. **List the specific functionalities** being tested in the provided code snippet.
3. **Find examples** of how these tests relate to JavaScript, HTML, and CSS.
4. **Look for test cases with logical reasoning** and explain the assumptions and expected outputs.
5. **Pinpoint tests that illustrate common user or programming errors.**
6. **Synthesize a comprehensive summary** considering this is part 18 of 19.

Based on the code, this test file seems to focus on testing the functionalities of `WebFrameImpl`, the implementation of `WebFrame`, particularly in the context of rendering, user interaction, and integration with the browser process.

Here's a breakdown of the functionalities observed in the snippet:

*   **Frame relationships:** Testing `Opener()` functionality.
*   **Virtual Keyboard:** Simulating focus on input elements and verifying virtual keyboard requests.
*   **Context Menu:** Testing the data populated for context menus, including "Select All" functionality and selected text.
*   **Frame Transparency:** Verifying the background color of local frames with remote parents.
*   **Alt Text Rendering:** Checking if alt text is rendered correctly when an image fails to load.
*   **Printing:** Testing the printing functionality for detached iframes and specific page ranges, including verifying DOM node IDs associated with printed text runs and handling first-letter styles.
*   **User Activation:**  Testing how right-clicks activate the frame for commands like "Paste".
*   **Fullscreen API:** Verifying the reset of scroll and scale states when entering and exiting fullscreen.
*   **Page Size and Orientation:** Testing the application of `@page` CSS rules for size and orientation during printing.
*   **Frame Transformations:** Checking the pixel-snapping of main frame transform offsets.
*   **Media Queries:** Verifying that media queries work correctly in local frames within remote frames.
*   **Viewport and Mainframe Intersections:** Testing the calculation and application of viewport and mainframe intersections for nested frames.
*   **Favicon Updates:** Checking if the frame notifies the browser process about favicon URL changes.
*   **Focus Handling:** Testing if focus changes trigger the `FocusedElementChanged` event.
*   **Navigation Cancellation:** Verifying that form submissions cancel pending navigations.
*   **Download Referrer Policy:** Testing the referrer policy applied when downloading a URL via an anchor tag with the `download` attribute.
这是一个关于 Chromium Blink 引擎中 `WebFrameImpl` 的单元测试文件，专注于测试 Web 框架（frame）的各种功能。作为第 18 部分，可以推断此文件涵盖了 Web 框架功能测试的多个方面，并可能接近测试套件的尾声，专注于一些较为细节或者特定的场景。

**以下是根据提供的代码片段列举的功能以及相关说明：**

1. **测试获取 opener frame 的功能:**
    *   `TEST_F(WebFrameTest, Opener)` 测试了通过 `mainFrame()->Opener()` 能否正确获取到打开当前 frame 的 frame。
    *   **关系:** 这与浏览器 history 和 window 对象的 `opener` 属性相关，JavaScript 可以通过 `window.opener` 访问打开当前窗口的窗口对象。
    *   **假设输入与输出:** 假设一个页面 A 通过 `window.open()` 打开了页面 B，那么在页面 B 的测试中，`mainFrame()->Opener()` 应该返回代表页面 A 的 WebFrame。

2. **测试在元素获取焦点时显示虚拟键盘的功能:**
    *   `TEST_F(WebFrameTest, ShowVirtualKeyboardOnElementFocus)` 模拟了 input 元素获取焦点（通过 JavaScript 的 `focus()` 方法），并验证了相应的 `WidgetHost` 是否收到了显示虚拟键盘的请求。
    *   **关系:** 这与 HTML 的表单元素（如 `<input>`）以及 JavaScript 的 DOM 操作相关。当用户点击或通过脚本聚焦一个文本输入框时，操作系统可能会显示虚拟键盘。
    *   **举例说明:**  HTML 中有一个 `<input type="text">` 元素，JavaScript 代码 `document.querySelector('input').focus();` 会触发该元素获取焦点，从而可能触发虚拟键盘的显示。
    *   **假设输入与输出:**  加载包含一个 input 元素的 HTML 页面，然后执行 JavaScript 代码使其获取焦点。期望的结果是 `widget_host.VirtualKeyboardRequestCount()` 大于 0 (在非 ChromeOS 平台)。
    *   **用户或编程常见的使用错误:**  开发者可能错误地假设在所有情况下聚焦输入框都会显示虚拟键盘，而忽略了用户设置或者平台差异。例如，在桌面环境下，通常不会因为聚焦输入框就弹出虚拟键盘。

3. **测试上下文菜单数据的 "全选" 功能:**
    *   `TEST_F(WebFrameTest, ContextMenuDataSelectAll)` 使用 `TestSelectAll` 函数来测试在不同的 HTML 元素上点击右键时，上下文菜单数据中是否包含 "全选" (Select All) 选项。
    *   **关系:**  这与 HTML 元素的可编辑性 (`<textarea>`, `<input>`, `contenteditable` 属性) 以及浏览器提供的默认上下文菜单功能相关。
    *   **举例说明:**
        *   对于空的 `<textarea></textarea>`，上下文菜单不应该有 "全选"。
        *   对于包含文本的 `<textarea>nonempty</textarea>`，上下文菜单应该有 "全选"。
        *   对于空的 `<div contenteditable></div>`，上下文菜单不应该有 "全选"。
        *   对于包含文本的 `<div contenteditable>nonempty</div>`，上下文菜单应该有 "全选"。

4. **测试上下文菜单数据的选中文字:**
    *   `TEST_F(WebFrameTest, ContextMenuDataSelectedText)` 测试在 input 元素中选中文字后，右键点击时上下文菜单数据中 `selected_text` 字段是否包含正确的选中文字。
    *   **关系:** 这与 HTML 表单元素和 JavaScript 的文本选择功能相关。
    *   **假设输入与输出:**  加载包含 `<input value=' '>` 的 HTML 页面，使用 JavaScript 执行 `document.execCommand('SelectAll')` 选中空格，然后模拟右键点击。期望 `frame.GetMenuData().selected_text` 的值为 " " (空格)。

5. **测试密码类型 input 的上下文菜单选中文字:**
    *   `TEST_F(WebFrameTest, ContextMenuDataPasswordSelectedText)`  类似于上一个测试，但针对 `<input type='password'>` 元素，验证上下文菜单数据是否正确处理密码类型的选中文字。
    *   **关系:**  与 HTML 密码输入框的安全处理相关，浏览器通常不会将密码类型的选中文字直接显示在上下文菜单中。
    *   **假设输入与输出:** 加载包含 `<input type='password' value='password'>` 的 HTML 页面，选中密码，然后模拟右键点击。期望 `frame.GetMenuData().form_control_type` 为 `blink::mojom::FormControlType::kInputPassword`，并且 `frame.GetMenuData().selected_text` 不为空，但其具体内容可能被屏蔽或处理。

6. **测试非定位上下文菜单:**
    *   `TEST_F(WebFrameTest, ContextMenuDataNonLocatedMenu)` 测试在特定情况下（例如通过触摸事件触发上下文菜单），上下文菜单的数据是否正确。
    *   **关系:**  与触摸事件处理和上下文菜单的触发机制相关。
    *   **假设输入与输出:** 加载包含大字体文本的 HTML 页面，模拟双击选中文字，然后通过触摸事件显示上下文菜单。期望 `frame.GetMenuData().source_type` 为 `kMenuSourceTouch`，并且 `frame.GetMenuData().selected_text` 不为空。

7. **测试具有远程父级的本地 frame 的透明度:**
    *   `TEST_F(WebFrameTest, LocalFrameWithRemoteParentIsTransparent)` 验证当一个本地 frame 的父级是远程 frame 时，该本地 frame 的背景色是否为透明。
    *   **关系:** 这涉及到 Chromium 的进程模型和 frame 的渲染机制。
    *   **假设输入与输出:** 创建一个本地子 frame，其父 frame 是远程 frame。期望 `local_frame->GetFrameView()->BaseBackgroundColor()` 返回 `Color::kTransparent`。

8. **测试 about:blank 页面的 Alt 文本:**
    *   `TEST_F(WebFrameTest, AltTextOnAboutBlankPage)` 测试在 `about:blank` 页面中加载包含 `alt` 属性的 `<img>` 标签时，`alt` 文本是否被正确渲染。
    *   **关系:** 与 HTML 的 `<img>` 标签和 `alt` 属性相关。当图片无法加载时，`alt` 属性的值会作为替代文本显示。
    *   **假设输入与输出:** 在 `about:blank` 页面加载包含 `<img id='foo' src='foo' alt='foo alt' ...>` 的 HTML。期望找到 ID 为 "foo" 的元素的 LayoutObject，并检查其子元素的文本内容是否为 "foo alt"。

9. **测试打印分离的 iframe:**
    *   `TEST_F(WebFrameTest, PrintDetachedIframe)` 和 `TEST_F(WebFrameTest, PrintIframeUnderDetached)` 测试打印功能在处理分离的 iframe 时的行为。
    *   **关系:** 与浏览器的打印功能和 iframe 的处理方式相关。
    *   **假设输入与输出:** 加载包含分离 iframe 的 HTML 页面，调用打印功能。期望打印操作能够正常执行。

10. **测试打印特定页面:**
    *   `TEST_F(WebFrameTest, PrintSomePages)` 测试打印指定页码的功能，并验证打印输出中包含的文本内容。
    *   **关系:** 与浏览器的打印预览和打印功能相关。
    *   **假设输入与输出:** 加载一个多页的 HTML 文档，指定打印第 1、4 和 8 页。期望 `GetPrintedTextRunDOMNodeIds` 函数返回包含对应页码文本信息的 `TextRunDOMNodeIdInfo` 向量。

11. **测试打印所有页面:**
    *   `TEST_F(WebFrameTest, PrintAllPages)` 测试打印所有页面的功能，并验证打印输出中包含所有页面的文本内容。
    *   **关系:**  与浏览器的完整打印功能相关。

12. **测试打印时首字母是否具有 DOM 节点 ID:**
    *   `TEST_F(WebFrameTest, FirstLetterHasDOMNodeIdWhenPrinting)` 测试当使用 CSS 伪元素 `::first-letter` 设置样式时，打印输出中首字母的文本 run 是否关联了正确的 DOM 节点 ID。
    *   **关系:** 与 CSS 的 `::first-letter` 伪元素和浏览器的渲染及打印机制相关。
    *   **假设输入与输出:** 加载包含应用了 `::first-letter` 样式的 HTML 页面并执行打印。期望打印输出中，首字母和剩余文字的 text run 关联了相同的 DOM 节点 ID。

13. **测试右键单击激活 `ExecuteCommand`:**
    *   `TEST_F(WebFrameTest, RightClickActivatesForExecuteCommand)` 测试在页面上右键单击后，是否激活了用户激活状态，使得可以执行诸如 `ExecuteCommand` 的操作。
    *   **关系:**  与用户交互事件处理和浏览器的安全机制相关，某些操作需要用户激活才能执行。
    *   **假设输入与输出:** 在空白页面上模拟右键单击，然后尝试执行 `Paste` 命令。期望在右键单击后，`frame->GetFrame()->HasStickyUserActivation()` 返回 true。

14. **测试进入全屏时重置滚动和缩放状态:**
    *   `TEST_F(WebFrameSimTest, EnterFullscreenResetScrollAndScaleState)` 测试进入全屏模式时，页面的缩放比例和滚动位置是否被重置为默认值。
    *   **关系:**  与 Fullscreen API 和浏览器的viewport 控制相关。JavaScript 可以通过 `element.requestFullscreen()` 进入全屏。
    *   **假设输入与输出:** 加载一个可以滚动的页面，设置缩放比例和滚动位置，然后请求进入全屏。期望进入全屏后，缩放比例为 1.0，滚动位置为 (0, 0)。退出全屏后，缩放和滚动位置恢复到之前的状态。

15. **测试页面尺寸类型:**
    *   `TEST_F(WebFrameSimTest, PageSizeType)` 测试 CSS `@page` 规则中 `size` 属性对打印页面尺寸的影响。
    *   **关系:**  与 CSS 的分页媒体特性和浏览器的打印功能相关。
    *   **举例说明:**  CSS 中使用 `@page { size: auto; }`、`@page { size: portrait; }`、`@page { size: A4 landscape; }` 等来定义打印页面的尺寸和方向。
    *   **假设输入与输出:** 加载包含不同 `@page` 规则的 HTML 页面并开始打印。期望 `main_frame->GetPageDescription(0).page_size_type` 返回与 CSS 规则对应的 `PageSizeType` 枚举值。

16. **测试页面方向:**
    *   `TEST_F(WebFrameSimTest, PageOrientation)` 测试 CSS `@page` 规则中 `page-orientation` 属性对打印页面方向的影响。
    *   **关系:**  与 CSS 的分页媒体特性和浏览器的打印功能相关。
    *   **举例说明:**  CSS 中使用 `@page { page-orientation: upright; }`、`@page { page-orientation: rotate-right; }` 等来定义打印页面的方向。
    *   **假设输入与输出:** 加载包含使用 `page-orientation` 属性定义不同页面方向的 HTML 页面并开始打印。期望 `frame->GetPageDescription(index).orientation` 返回与 CSS 规则对应的 `PageOrientation` 枚举值。

17. **测试主 frame 变换偏移是否像素对齐:**
    *   `TEST_F(WebFrameSimTest, MainFrameTransformOffsetPixelSnapped)` 测试主 frame 的变换偏移是否会被像素对齐。
    *   **关系:**  与浏览器的渲染优化和 compositor 处理相关。
    *   **假设输入与输出:**  加载包含一个设置了非整数偏移量的 iframe 的 HTML 页面。期望 remote frame host 的 intersection state 中的主 frame 变换是单位矩阵或者整数平移。

18. **测试远程 frame 内本地 frame 的 Media Queries:**
    *   `TEST_F(WebFrameTest, MediaQueriesInLocalFrameInsideRemote)` 测试在远程 frame 内的本地 frame 中，Media Queries 是否能正确工作。
    *   **关系:**  与 CSS Media Queries 和浏览器的 frame 架构相关。
    *   **假设输入与输出:** 创建一个在远程 frame 内的本地 frame，并设置其屏幕信息。期望该本地 frame 的 MediaValues 对象能够正确反映设置的屏幕信息。

19. **测试
### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第18部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
ainFrame()->Opener());
}

TEST_F(WebFrameTest, ShowVirtualKeyboardOnElementFocus) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeRemote();

  WebLocalFrameImpl* local_frame = web_view_helper.CreateLocalChild(
      *web_view_helper.RemoteMainFrame(), "child", WebFrameOwnerProperties(),
      nullptr, nullptr);

  frame_test_helpers::TestWebFrameWidgetHost& widget_host =
      static_cast<frame_test_helpers::TestWebFrameWidget*>(
          local_frame->FrameWidgetImpl())
          ->WidgetHost();

  RegisterMockedHttpURLLoad("input_field_default.html");
  frame_test_helpers::LoadFrame(local_frame,
                                base_url_ + "input_field_default.html");

  // Simulate an input element focus leading to Element::focus() call with a
  // user gesture.
  LocalFrame::NotifyUserActivation(
      local_frame->GetFrame(), mojom::UserActivationNotificationType::kTest);
  local_frame->ExecuteScript(
      WebScriptSource("window.focus();"
                      "document.querySelector('input').focus();"));

  RunPendingTasks();
  // Verify that the right WidgetHost has been notified.
#if BUILDFLAG(IS_CHROMEOS)
  EXPECT_EQ(0u, widget_host.VirtualKeyboardRequestCount());
#else
  EXPECT_LT(0u, widget_host.VirtualKeyboardRequestCount());
#endif
  web_view_helper.Reset();
}

class ContextMenuWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  ContextMenuWebFrameClient() = default;
  ContextMenuWebFrameClient(const ContextMenuWebFrameClient&) = delete;
  ContextMenuWebFrameClient& operator=(const ContextMenuWebFrameClient&) =
      delete;
  ~ContextMenuWebFrameClient() override = default;

  // WebLocalFrameClient:
  void UpdateContextMenuDataForTesting(
      const ContextMenuData& data,
      const std::optional<gfx::Point>&) override {
    menu_data_ = data;
  }

  ContextMenuData GetMenuData() { return menu_data_; }

 private:
  ContextMenuData menu_data_;
};

bool TestSelectAll(const std::string& html) {
  ContextMenuWebFrameClient frame;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                     ToKURL("about:blank"));
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  web_view->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  RunPendingTasks();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  RunPendingTasks();

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(8, 8);
  mouse_event.click_count = 1;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
  RunPendingTasks();
  web_view_helper.Reset();
  return frame.GetMenuData().edit_flags &
         ContextMenuDataEditFlags::kCanSelectAll;
}

TEST_F(WebFrameTest, ContextMenuDataSelectAll) {
  EXPECT_FALSE(TestSelectAll("<textarea></textarea>"));
  EXPECT_TRUE(TestSelectAll("<textarea>nonempty</textarea>"));
  EXPECT_FALSE(TestSelectAll("<input>"));
  EXPECT_TRUE(TestSelectAll("<input value='nonempty'>"));
  EXPECT_FALSE(TestSelectAll("<div contenteditable></div>"));
  EXPECT_TRUE(TestSelectAll("<div contenteditable>nonempty</div>"));
  EXPECT_FALSE(TestSelectAll("<div contenteditable>\n</div>"));
}

TEST_F(WebFrameTest, ContextMenuDataSelectedText) {
  ContextMenuWebFrameClient frame;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  const std::string& html = "<input value=' '>";
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                     ToKURL("about:blank"));
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  RunPendingTasks();

  web_view->MainFrameImpl()->ExecuteCommand(WebString::FromUTF8("SelectAll"));

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(8, 8);
  mouse_event.click_count = 1;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
  RunPendingTasks();
  web_view_helper.Reset();
  EXPECT_EQ(frame.GetMenuData().selected_text, " ");
}

TEST_F(WebFrameTest, ContextMenuDataPasswordSelectedText) {
  ContextMenuWebFrameClient frame;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  const std::string& html = "<input type='password' value='password'>";
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                     ToKURL("about:blank"));
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  RunPendingTasks();

  web_view->MainFrameImpl()->ExecuteCommand(WebString::FromUTF8("SelectAll"));

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.SetPositionInWidget(8, 8);
  mouse_event.click_count = 1;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));

  RunPendingTasks();
  web_view_helper.Reset();
  EXPECT_EQ(frame.GetMenuData().form_control_type,
            blink::mojom::FormControlType::kInputPassword);
  EXPECT_FALSE(frame.GetMenuData().selected_text.empty());
}

TEST_F(WebFrameTest, ContextMenuDataNonLocatedMenu) {
  ContextMenuWebFrameClient frame;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.Initialize(&frame);
  const std::string& html =
      "<div style='font-size: 1000%; line-height: 0.7em'>Select me<br/>"
      "Next line</div>";
  frame_test_helpers::LoadHTMLString(web_view->MainFrameImpl(), html,
                                     ToKURL("about:blank"));
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  RunPendingTasks();

  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());

  mouse_event.button = WebMouseEvent::Button::kLeft;
  mouse_event.SetPositionInWidget(0, 0);
  mouse_event.click_count = 2;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));

  web_view->MainFrameImpl()->LocalRootFrameWidget()->ShowContextMenu(
      ui::mojom::blink::MenuSourceType::kTouch,
      web_view->MainFrameImpl()->GetPositionInViewportForTesting());

  RunPendingTasks();
  web_view_helper.Reset();
  EXPECT_EQ(frame.GetMenuData().source_type, kMenuSourceTouch);
  EXPECT_FALSE(frame.GetMenuData().selected_text.empty());
}

TEST_F(WebFrameTest, LocalFrameWithRemoteParentIsTransparent) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebLocalFrameImpl* local_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame());
  frame_test_helpers::LoadFrame(local_frame, "data:text/html,some page");

  // Local frame with remote parent should have transparent baseBackgroundColor.
  Color color = local_frame->GetFrameView()->BaseBackgroundColor();
  EXPECT_EQ(Color::kTransparent, color);
}

TEST_F(WebFrameTest, AltTextOnAboutBlankPage) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  web_view_helper.Resize(gfx::Size(640, 480));
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  const char kSource[] =
      "<img id='foo' src='foo' alt='foo alt' width='200' height='200'>";
  frame_test_helpers::LoadHTMLString(frame, kSource, ToKURL("about:blank"));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  RunPendingTasks();

  // Check LayoutText with alt text "foo alt"
  LayoutObject* layout_object = frame->GetFrame()
                                    ->GetDocument()
                                    ->getElementById(AtomicString("foo"))
                                    ->GetLayoutObject()
                                    ->SlowFirstChild();
  String text = "";
  for (LayoutObject* obj = layout_object; obj; obj = obj->NextInPreOrder()) {
    if (obj->IsText()) {
      text = To<LayoutText>(obj)->TransformedText();
      break;
    }
  }
  EXPECT_EQ("foo alt", text.Utf8());
}

static void TestFramePrinting(WebLocalFrameImpl* frame) {
  gfx::Size page_size(500, 500);
  WebPrintParams print_params((gfx::SizeF(page_size)));
  EXPECT_EQ(1u, frame->PrintBegin(print_params, WebNode()));
  cc::PaintRecorder recorder;
  frame->PrintPagesForTesting(recorder.beginRecording(), page_size);
  frame->PrintEnd();
}

TEST_F(WebFrameTest, PrintDetachedIframe) {
  RegisterMockedHttpURLLoad("print-detached-iframe.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "print-detached-iframe.html");
  TestFramePrinting(
      To<WebLocalFrameImpl>(web_view_helper.LocalMainFrame()->FirstChild()));
}

TEST_F(WebFrameTest, PrintIframeUnderDetached) {
  RegisterMockedHttpURLLoad("print-detached-iframe.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "print-detached-iframe.html");
  TestFramePrinting(To<WebLocalFrameImpl>(
      web_view_helper.LocalMainFrame()->FirstChild()->FirstChild()));
}

namespace {

struct TextRunDOMNodeIdInfo {
  int glyph_len;
  DOMNodeId dom_node_id;
};

// Given a PaintRecord and a starting DOMNodeId, recursively iterate over all of
// the (nested) paint ops, and populate |text_runs| with the number of glyphs
// and the DOMNodeId of each text run.
void RecursiveCollectTextRunDOMNodeIds(
    const PaintRecord& paint_record,
    DOMNodeId dom_node_id,
    std::vector<TextRunDOMNodeIdInfo>* text_runs) {
  for (const cc::PaintOp& op : paint_record) {
    if (op.GetType() == cc::PaintOpType::kDrawRecord) {
      const auto& draw_record_op = static_cast<const cc::DrawRecordOp&>(op);
      RecursiveCollectTextRunDOMNodeIds(draw_record_op.record, dom_node_id,
                                        text_runs);
    } else if (op.GetType() == cc::PaintOpType::kSetNodeId) {
      const auto& set_node_id_op = static_cast<const cc::SetNodeIdOp&>(op);
      dom_node_id = set_node_id_op.node_id;
    } else if (op.GetType() == cc::PaintOpType::kDrawTextBlob) {
      const auto& draw_text_op = static_cast<const cc::DrawTextBlobOp&>(op);
      SkTextBlob::Iter iter(*draw_text_op.blob);
      SkTextBlob::Iter::Run run;
      while (iter.next(&run)) {
        TextRunDOMNodeIdInfo text_run_info;
        text_run_info.glyph_len = run.fGlyphCount;
        text_run_info.dom_node_id = dom_node_id;
        text_runs->push_back(text_run_info);
      }
    }
  }
}

std::vector<TextRunDOMNodeIdInfo> GetPrintedTextRunDOMNodeIds(
    WebLocalFrame* frame,
    const WebVector<uint32_t>* pages = nullptr) {
  gfx::Size page_size(500, 500);
  WebPrintParams print_params((gfx::SizeF(page_size)));

  frame->PrintBegin(print_params, WebNode());
  cc::PaintRecorder recorder;
  frame->PrintPagesForTesting(recorder.beginRecording(), page_size, pages);
  frame->PrintEnd();

  cc::PaintRecord paint_record = recorder.finishRecordingAsPicture();
  std::vector<TextRunDOMNodeIdInfo> text_runs;
  RecursiveCollectTextRunDOMNodeIds(paint_record, 0, &text_runs);

  return text_runs;
}

}  // namespace

TEST_F(WebFrameTest, PrintSomePages) {
  RegisterMockedHttpURLLoad("print-pages.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "print-pages.html");

  WebVector<uint32_t> pages;
  pages.push_back(1);
  pages.push_back(4);
  pages.push_back(8);
  std::vector<TextRunDOMNodeIdInfo> text_runs =
      GetPrintedTextRunDOMNodeIds(web_view_helper.LocalMainFrame(), &pages);

  ASSERT_EQ(3u, text_runs.size());
  EXPECT_EQ(2, text_runs[0].glyph_len);  // Page 2
  EXPECT_EQ(5, text_runs[1].glyph_len);  // Page 5
  EXPECT_EQ(9, text_runs[2].glyph_len);  // Page 9
}

TEST_F(WebFrameTest, PrintAllPages) {
  RegisterMockedHttpURLLoad("print-pages.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "print-pages.html");

  std::vector<TextRunDOMNodeIdInfo> text_runs =
      GetPrintedTextRunDOMNodeIds(web_view_helper.LocalMainFrame());
  EXPECT_EQ(10u, text_runs.size());
}

TEST_F(WebFrameTest, FirstLetterHasDOMNodeIdWhenPrinting) {
  // When printing, every DrawText painting op needs to have an associated
  // DOM Node ID. This test ensures that when the first-letter style is used,
  // the drawing op for the first letter is correctly associated with the same
  // DOM Node ID as the following text.

  // Load a web page with two elements containing the text
  // "Hello" and "World", where "World" has a first-letter style.
  RegisterMockedHttpURLLoad("first-letter.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "first-letter.html");

  std::vector<TextRunDOMNodeIdInfo> text_runs =
      GetPrintedTextRunDOMNodeIds(web_view_helper.LocalMainFrame());

  // The first text run should be "Hello".
  ASSERT_EQ(3U, text_runs.size());
  EXPECT_EQ(5, text_runs[0].glyph_len);
  EXPECT_NE(kInvalidDOMNodeId, text_runs[0].dom_node_id);

  // The second text run should be "W", the first letter of "World".
  EXPECT_EQ(1, text_runs[1].glyph_len);
  EXPECT_NE(kInvalidDOMNodeId, text_runs[1].dom_node_id);

  // The last text run should be "orld", the rest of "World".
  EXPECT_EQ(4, text_runs[2].glyph_len);
  EXPECT_NE(kInvalidDOMNodeId, text_runs[2].dom_node_id);

  // The second and third text runs should have the same DOM Node ID.
  EXPECT_EQ(text_runs[1].dom_node_id, text_runs[2].dom_node_id);
}

TEST_F(WebFrameTest, RightClickActivatesForExecuteCommand) {
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  // Setup a mock clipboard host.
  PageTestBase::MockClipboardHostProvider mock_clipboard_host_provider(
      frame->GetFrame()->GetBrowserInterfaceBroker());

  EXPECT_FALSE(frame->GetFrame()->HasStickyUserActivation());
  frame->ExecuteScript(
      WebScriptSource(WebString("document.execCommand('copy');")));
  EXPECT_FALSE(frame->GetFrame()->HasStickyUserActivation());

  // Right-click to activate the page.
  WebMouseEvent mouse_event(WebInputEvent::Type::kMouseDown,
                            WebInputEvent::kNoModifiers,
                            WebInputEvent::GetStaticTimeStampForTests());
  mouse_event.button = WebMouseEvent::Button::kRight;
  mouse_event.click_count = 1;
  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_event, ui::LatencyInfo()));
  RunPendingTasks();

  frame->ExecuteCommand(WebString::FromUTF8("Paste"));
  EXPECT_TRUE(frame->GetFrame()->HasStickyUserActivation());
}

TEST_F(WebFrameSimTest, EnterFullscreenResetScrollAndScaleState) {
  UseAndroidSettings();
  WebView().MainFrameViewWidget()->Resize(gfx::Size(490, 500));
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetSettings()->SetTextAutosizingEnabled(false);
  WebView().SetDefaultPageScaleLimits(0.5f, 4);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body {
          margin: 0px;
          width: 10000px;
          height: 10000px;
        }
      </style>
  )HTML");

  Compositor().BeginFrame();

  // Make the page scale and scroll with the given parameters.
  EXPECT_EQ(0.5f, WebView().PageScaleFactor());
  WebView().SetPageScaleFactor(2.0f);
  WebView().MainFrameImpl()->SetScrollOffset(gfx::PointF(94, 111));
  WebView().SetVisualViewportOffset(gfx::PointF(12, 20));
  EXPECT_EQ(2.0f, WebView().PageScaleFactor());
  EXPECT_EQ(94, WebView().MainFrameImpl()->GetScrollOffset().x());
  EXPECT_EQ(111, WebView().MainFrameImpl()->GetScrollOffset().y());
  EXPECT_EQ(12, WebView().VisualViewportOffset().x());
  EXPECT_EQ(20, WebView().VisualViewportOffset().y());

  auto* frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  Element* element = frame->GetDocument()->body();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  WebView().DidEnterFullscreen();

  // Page scale factor must be 1.0 during fullscreen for elements to be sized
  // properly.
  EXPECT_EQ(1.0f, WebView().PageScaleFactor());

  // Confirm that exiting fullscreen restores back to default values.
  WebView().DidExitFullscreen();
  WebView().MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  EXPECT_EQ(0.5f, WebView().PageScaleFactor());
  EXPECT_EQ(94, WebView().MainFrameImpl()->GetScrollOffset().x());
  EXPECT_EQ(111, WebView().MainFrameImpl()->GetScrollOffset().y());
  EXPECT_EQ(0, WebView().VisualViewportOffset().x());
  EXPECT_EQ(0, WebView().VisualViewportOffset().y());
}

TEST_F(WebFrameSimTest, PageSizeType) {
  gfx::Size page_size(500, 500);
  WebView().MainFrameViewWidget()->Resize(page_size);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        @page {}
      </style>
  )HTML");

  Compositor().BeginFrame();
  RunPendingTasks();

  const struct {
    const char* size;
    PageSizeType page_size_type;
  } test_cases[] = {
      {"auto", PageSizeType::kAuto},
      {"portrait", PageSizeType::kPortrait},
      {"landscape", PageSizeType::kLandscape},
      {"a4", PageSizeType::kFixed},
      {"letter", PageSizeType::kFixed},
      {"a4 portrait", PageSizeType::kFixed},
      {"letter landscape", PageSizeType::kFixed},
      {"10in", PageSizeType::kFixed},
      {"10in 12cm", PageSizeType::kFixed},
  };

  auto* main_frame = WebView().MainFrame()->ToWebLocalFrame();
  auto* doc = To<LocalFrame>(WebView().GetPage()->MainFrame())->GetDocument();
  auto* sheet = To<CSSStyleSheet>(doc->StyleSheets().item(0));
  CSSStyleDeclaration* style_decl =
      To<CSSPageRule>(sheet->cssRules(ASSERT_NO_EXCEPTION)->item(0))->style();

  auto* frame = WebView().MainFrame()->ToWebLocalFrame();
  WebPrintParams print_params((gfx::SizeF(page_size)));
  frame->PrintBegin(print_params, WebNode());
  // Initially empty @page rule.
  EXPECT_EQ(PageSizeType::kAuto,
            main_frame->GetPageDescription(0).page_size_type);
  frame->PrintEnd();

  for (const auto& test : test_cases) {
    style_decl->setProperty(doc->GetExecutionContext(), "size", test.size, "",
                            ASSERT_NO_EXCEPTION);
    frame->PrintBegin(print_params, WebNode());
    EXPECT_EQ(test.page_size_type,
              main_frame->GetPageDescription(0).page_size_type);
    frame->PrintEnd();
  }
}

TEST_F(WebFrameSimTest, PageOrientation) {
  gfx::Size page_size(500, 500);
  WebView().MainFrameWidget()->Resize(page_size);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        @page upright { page-orientation: upright; }
        @page clockwise { page-orientation: rotate-right; }
        @page counter-clockwise { page-orientation: rotate-left; }
        div { height: 10px; }
      </style>
      <!-- First page: -->
      <div style="page:upright;"></div>
      <!-- Second page: -->
      <div style="page:counter-clockwise;"></div>
      <!-- Third page: -->
      <div style="page:clockwise;"></div>
      <div style="page:clockwise;"></div>
      <!-- Fourth page: -->
      <div></div>
  )HTML");

  Compositor().BeginFrame();
  RunPendingTasks();

  auto* frame = WebView().MainFrame()->ToWebLocalFrame();
  WebPrintParams print_params((gfx::SizeF(page_size)));
  EXPECT_EQ(4u, frame->PrintBegin(print_params, WebNode()));

  WebPrintPageDescription description = frame->GetPageDescription(0);
  EXPECT_EQ(description.orientation, PageOrientation::kUpright);

  description = frame->GetPageDescription(1);
  EXPECT_EQ(description.orientation, PageOrientation::kRotateLeft);

  description = frame->GetPageDescription(2);
  EXPECT_EQ(description.orientation, PageOrientation::kRotateRight);

  description = frame->GetPageDescription(3);
  EXPECT_EQ(description.orientation, PageOrientation::kUpright);

  frame->PrintEnd();
}

TEST_F(WebFrameSimTest, MainFrameTransformOffsetPixelSnapped) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <iframe id="iframe" style="position:absolute;top:7px;left:13.5px;border:none"></iframe>
  )HTML");
  TestViewportIntersection remote_frame_host;
  WebRemoteFrame* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      MainFrame().FirstChild(), remote_frame,
      remote_frame_host.BindNewAssociatedRemote());
  Compositor().BeginFrame();
  RunPendingTasks();
  EXPECT_TRUE(remote_frame_host.GetIntersectionState()
                  ->main_frame_transform.IsIdentityOrIntegerTranslation());
  EXPECT_EQ(gfx::Vector2dF(14.f, 7.f),
            remote_frame_host.GetIntersectionState()
                ->main_frame_transform.To2dTranslation());
  MainFrame().FirstChild()->Detach();
}

TEST_F(WebFrameTest, MediaQueriesInLocalFrameInsideRemote) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebLocalFrameImpl* local_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame(), WebString(),
                              WebFrameOwnerProperties(), nullptr, nullptr);

  frame_test_helpers::TestWebFrameWidget* local_frame_widget =
      static_cast<frame_test_helpers::TestWebFrameWidget*>(
          local_frame->FrameWidgetImpl());
  display::ScreenInfos screen_infos(
      local_frame_widget->GetOriginalScreenInfo());
  screen_infos.mutable_current().is_monochrome = false;
  screen_infos.mutable_current().depth_per_component = 8;
  local_frame_widget->UpdateScreenInfo(screen_infos);

  ASSERT_TRUE(local_frame->GetFrame());
  MediaValues* media_values =
      MediaValues::CreateDynamicIfFrameExists(local_frame->GetFrame());
  ASSERT_TRUE(media_values);
  EXPECT_EQ(0, media_values->MonochromeBitsPerComponent());
  EXPECT_EQ(8, media_values->ColorBitsPerComponent());
  // Need to explicitly reset helper to make sure local_frame is not deleted
  // first.
  helper.Reset();
}

TEST_F(WebFrameTest, RemoteViewportAndMainframeIntersections) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();
  WebLocalFrameImpl* local_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame(), "frameName");
  frame_test_helpers::LoadHTMLString(local_frame, R"HTML(
      <!DOCTYPE html>
      <style>
      #target {
        position: absolute;
        top: 10px;
        left: 20px;
        width: 200px;
        height: 100px;
      }
      </style>
      <div id=target></div>
      )HTML",
                                     ToKURL("about:blank"));

  Element* target = local_frame->GetFrame()->GetDocument()->getElementById(
      AtomicString("target"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(target->GetLayoutObject());

  // Simulate the local child frame being positioned at (7, -11) in the parent's
  // viewport, indicating that the top 11px of the child's content is clipped
  // by the parent. Let the local child frame be at (7, 40) in the parent
  // element.
  WebFrameWidget* widget = local_frame->FrameWidget();
  ASSERT_TRUE(widget);
  gfx::Transform viewport_transform;
  viewport_transform.Translate(7, -11);
  gfx::Rect viewport_intersection(0, 11, 200, 89);
  gfx::Rect mainframe_intersection(0, 0, 200, 140);
  blink::mojom::FrameOcclusionState occlusion_state =
      blink::mojom::FrameOcclusionState::kUnknown;

  static_cast<WebFrameWidgetImpl*>(widget)->ApplyViewportIntersectionForTesting(
      blink::mojom::blink::ViewportIntersectionState::New(
          viewport_intersection, mainframe_intersection, viewport_intersection,
          occlusion_state, gfx::Size(), gfx::Point(), viewport_transform));

  // The viewport intersection should be applied by the layout geometry mapping
  // code when these flags are used.
  int viewport_intersection_flags =
      kTraverseDocumentBoundaries | kApplyRemoteMainFrameTransform;

  // Expectation is: (target location) + (viewport offset) = (20, 10) + (7, -11)
  PhysicalOffset offset = target->GetLayoutObject()->LocalToAbsolutePoint(
      PhysicalOffset(), viewport_intersection_flags);
  EXPECT_EQ(PhysicalOffset(27, -1), offset);

  PhysicalRect rect(0, 0, 25, 35);
  local_frame->GetFrame()
      ->GetDocument()
      ->GetLayoutView()
      ->MapToVisualRectInAncestorSpace(nullptr, rect);
  EXPECT_EQ(PhysicalRect(7, 0, 25, 24), rect);

  // Without the main frame overflow clip the rect should not be clipped and the
  // coordinates returned are the rects coordinates in the viewport space.
  PhysicalRect mainframe_rect(0, 0, 25, 35);
  local_frame->GetFrame()
      ->GetDocument()
      ->GetLayoutView()
      ->MapToVisualRectInAncestorSpace(nullptr, mainframe_rect,
                                       kDontApplyMainFrameOverflowClip);
  EXPECT_EQ(PhysicalRect(7, -11, 25, 35), mainframe_rect);
}

class TestUpdateFaviconURLLocalFrameHost : public FakeLocalFrameHost {
 public:
  TestUpdateFaviconURLLocalFrameHost() = default;
  ~TestUpdateFaviconURLLocalFrameHost() override = default;

  // FakeLocalFrameHost:
  void UpdateFaviconURL(
      WTF::Vector<blink::mojom::blink::FaviconURLPtr> favicon_urls) override {
    did_notify_ = true;
  }

  bool did_notify_ = false;
};

// Ensure the render view sends favicon url update events correctly.
TEST_F(WebFrameTest, FaviconURLUpdateEvent) {
  TestUpdateFaviconURLLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();

  WebViewImpl* web_view = web_view_helper.GetWebView();
  LocalFrame* frame = web_view->MainFrameImpl()->GetFrame();

  // An event should be sent when a favicon url exists.
  frame->GetDocument()->documentElement()->setInnerHTML(
      "<html>"
      "<head>"
      "<link rel='icon' href='http://www.google.com/favicon.ico'>"
      "</head>"
      "</html>");
  RunPendingTasks();

  EXPECT_TRUE(frame_host.did_notify_);

  frame_host.did_notify_ = false;

  // An event should not be sent if no favicon url exists. This is an assumption
  // made by some of Chrome's favicon handling.
  frame->GetDocument()->documentElement()->setInnerHTML(
      "<html>"
      "<head>"
      "</head>"
      "</html>");
  RunPendingTasks();

  EXPECT_FALSE(frame_host.did_notify_);
  web_view_helper.Reset();
}

class TestFocusedElementChangedLocalFrameHost : public FakeLocalFrameHost {
 public:
  TestFocusedElementChangedLocalFrameHost() = default;
  ~TestFocusedElementChangedLocalFrameHost() override = default;

  // FakeLocalFrameHost:
  void FocusedElementChanged(bool is_editable_element,
                             bool is_richly_editable_element,
                             const gfx::Rect& bounds_in_frame_widget,
                             blink::mojom::FocusType focus_type) override {
    did_notify_ = true;
  }

  bool did_notify_ = false;
};

TEST_F(WebFrameTest, FocusElementCallsFocusedElementChanged) {
  TestFocusedElementChangedLocalFrameHost frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RunPendingTasks();
  auto* main_frame = web_view_helper.GetWebView()->MainFrameImpl();

  main_frame->GetFrame()->GetDocument()->documentElement()->setInnerHTML(
      "<input id='test1' value='hello1'></input>"
      "<input id='test2' value='hello2'></input>");
  RunPendingTasks();

  EXPECT_FALSE(frame_host.did_notify_);

  main_frame->ExecuteScript(
      WebScriptSource(WebString("document.getElementById('test1').focus();")));
  RunPendingTasks();
  EXPECT_TRUE(frame_host.did_notify_);
  frame_host.did_notify_ = false;

  main_frame->ExecuteScript(
      WebScriptSource(WebString("document.getElementById('test2').focus();")));
  RunPendingTasks();
  EXPECT_TRUE(frame_host.did_notify_);
  frame_host.did_notify_ = false;

  main_frame->ExecuteScript(
      WebScriptSource(WebString("document.getElementById('test2').blur();")));
  RunPendingTasks();
  EXPECT_TRUE(frame_host.did_notify_);
}

// Tests that form.submit() cancels any navigations already sent to the browser
// process.
TEST_F(WebFrameTest, FormSubmitCancelsNavigation) {
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("bar.html");
  auto* main_frame = web_view_helper.GetWebView()->MainFrameImpl();
  auto* local_frame = main_frame->GetFrame();
  auto* window = local_frame->DomWindow();

  window->document()->documentElement()->setInnerHTML(
      "<form id=formid action='http://internal.test/bar.html'></form>");
  ASSERT_FALSE(local_frame->Loader().HasProvisionalNavigation());

  FrameLoadRequest request(window,
                           ResourceRequest("http://internal.test/foo.html"));
  local_frame->Navigate(request, WebFrameLoadType::kStandard);
  ASSERT_TRUE(local_frame->Loader().HasProvisionalNavigation());

  main_frame->ExecuteScript(WebScriptSource(WebString("formid.submit()")));
  EXPECT_FALSE(local_frame->Loader().HasProvisionalNavigation());

  RunPendingTasks();
}

class TestLocalFrameHostForAnchorWithDownloadAttr : public FakeLocalFrameHost {
 public:
  TestLocalFrameHostForAnchorWithDownloadAttr() = default;
  ~TestLocalFrameHostForAnchorWithDownloadAttr() override = default;

  // FakeLocalFrameHost:
  void DownloadURL(mojom::blink::DownloadURLParamsPtr params) override {
    referrer_ = params->referrer ? params->referrer->url : KURL();
    referrer_policy_ = params->referrer
                           ? params->referrer->policy
                           : ReferrerUtils::MojoReferrerPolicyResolveDefault(
                                 network::mojom::ReferrerPolicy::kDefault);
  }

  KURL referrer_;
  network::mojom::ReferrerPolicy referrer_policy_;
};

TEST_F(WebFrameTest, DownloadReferrerPolicy) {
  TestLocalFrameHostForAnchorWithDownloadAttr frame_host;
  frame_test_helpers::TestWebFrameClient web_frame_client;
  frame_host.Init(web_frame_client.GetRemoteNavigationAssociatedInterfaces());
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  KURL test_url = ToKURL("http://www.test.com/foo/index.html");

  {
    // 1.<meta name='referrer' content='no-referrer'>
    MockPolicyContainerHost policy_container_host;
    frame->GetFrame()->DomWindow()->SetPolicyContainer(
        std::make_unique<PolicyContainer>(
            policy_container_host.BindNewEndpointAndPassDedicatedRemote(),
            mojom::blink::PolicyContainerPolicies::New()));
    EXPECT_CALL(policy_container_host,
                SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever));
    frame_test_helpers::LoadHTMLString(
        frame, GetHTMLStringForReferrerPolicy("no-referrer", std::string()),
        test_url);
    EXPECT_TRUE(frame_host.referrer_.IsEmpty());
    EXPECT_EQ(frame
```
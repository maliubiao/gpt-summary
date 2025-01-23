Response:
The user is asking for a summary of the provided C++ code snippet from a Chromium Blink engine test file. The file `web_plugin_container_test.cc` seems to focus on testing the functionality of `WebPluginContainer`, specifically how it handles various input events and its interaction with the rendering pipeline.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The tests seem to revolve around verifying how `WebPluginContainer` correctly receives and translates input events (mouse, touch, gesture) to the embedded plugin. This includes scenarios with scrolling and zooming.

2. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Plugins are often embedded using HTML `<embed>` or `<object>` tags. The tests manipulate the DOM (e.g., finding elements by ID) and simulate user interactions that would typically be triggered through JavaScript event listeners. CSS affects the layout and positioning of the plugin, which is crucial for correct event targeting.

3. **Analyze Individual Tests:**  Go through each `TEST_F` block and determine its purpose. Look for assertions (`EXPECT_EQ`) that indicate the expected outcome.

4. **Identify Logic and Assumptions:**  Note how the tests set up the environment (loading HTML pages, enabling plugins), simulate events, and check if the plugin received the correct event type and coordinates.

5. **Consider User Errors:** Think about what mistakes a web developer might make when embedding or interacting with plugins, and if these tests cover such scenarios.

6. **Trace User Actions:**  Imagine a user interacting with a webpage containing a plugin and how their actions translate into the events being tested.

7. **Synthesize a Summary:**  Combine the observations from the previous steps into a concise description of the code's functionality.

Applying this process to the provided code snippet:

* **Gesture Event Test:** Checks if a `kGestureLongPress` event is correctly dispatched to the plugin based on whether the event coordinates are within the plugin's bounds.
* **Mouse Event Buttons Test:** Verifies that mouse events, including modifier keys, are correctly passed to the plugin.
* **Mouse Wheel Event Translated Test:** Confirms that mouse wheel events are translated to plugin-relative coordinates.
* **Touch Event Scrolled Tests:** Examines how touch events are handled when the page is scrolled, ensuring the plugin receives the correct coordinates. It also tests coalesced touch events for low latency scenarios.
* **Mouse Wheel Event Scrolled Test:** Similar to the translated test, but with a scrolled page.
* **Mouse Event Scrolled Test:** Checks regular mouse events on a scrolled page.
* **Mouse/Wheel/Touch Event Zoomed Tests:** Verify correct event coordinate translation when the page is zoomed.
* **IsRectTopmost Tests:** Focus on determining if a given rectangle within the plugin is the topmost element, including scenarios where the document is detached or with odd/even dimensions.
* **ClippedRects Tests:**  Investigate how the visible portion (clip rect, unobscured rect) of a plugin is calculated, especially when it's inside an iframe, shifted within an iframe, or positioned using subpixels.
* **TopmostAfterDetachTest:** Checks the validity of `IsRectTopmost` after the plugin's frame is detached.
* **CompositedPlugin Test:** Deals with plugins that have their own compositing layers.

**Final Summary Construction:**  The summary should highlight the core purpose of the tests (verifying `WebPluginContainer` event handling), mention the types of events covered, and touch upon the different scenarios (scrolling, zooming, iframes, clipping).
这是对 `blink/renderer/core/exported/web_plugin_container_test.cc` 文件代码片段的第二部分。结合第一部分的内容，我们可以归纳一下这个测试文件的功能：

**总体功能:**

这个测试文件 `web_plugin_container_test.cc` 的主要功能是 **测试 Blink 引擎中 `WebPluginContainer` 类的行为和功能**。`WebPluginContainer` 负责管理和协调嵌入到网页中的插件（例如 Flash）。测试主要集中在以下几个方面：

1. **事件处理 (Event Handling):**  测试 `WebPluginContainer` 如何接收和处理各种用户输入事件（鼠标事件、触摸事件、手势事件），并将其正确地传递给插件。这包括：
    * **事件目标 (Event Targeting):** 验证事件是否被发送到插件的正确位置。
    * **事件坐标转换 (Event Coordinate Translation):** 确保事件的坐标被正确地转换为插件内部的坐标系，特别是当页面发生滚动或缩放时。
    * **事件修饰符 (Event Modifiers):** 检查事件的修饰符（例如 Shift 键、Ctrl 键）是否被正确传递。
    * **事件合并 (Event Coalescing):** 针对低延迟触摸事件，测试事件的合并机制。

2. **渲染和布局 (Rendering and Layout):**
    * **可视区域计算 (Visible Rect Calculation):** 测试如何计算插件的可视区域 (clip rect, unobscured rect)，尤其是在 iframe 中、滚动后或进行亚像素定位时。
    * **置顶判断 (Topmost Check):** 验证 `IsRectTopmost` 方法的正确性，判断插件的某个区域是否位于最顶层。

3. **生命周期管理 (Lifecycle Management):**
    * **插件的创建和销毁 (Plugin Creation and Destruction):**  测试在插件销毁后，某些状态（例如 `IsRectTopmost` 的返回值）是否正确。

**本部分代码的功能归纳:**

本部分的代码继续围绕着 `WebPluginContainer` 的事件处理和渲染布局进行测试，具体包括：

* **测试手势事件 (Gesture Event):** 验证长按 (LongPress) 手势事件是否能够正确地发送到插件，并区分事件是否发生在插件区域内。
* **测试鼠标按钮事件 (Mouse Event Buttons):**  测试鼠标事件中的按钮状态和修饰键状态是否能正确传递给插件。
* **测试鼠标滚轮事件的坐标转换 (Mouse Wheel Event Translated):**  验证鼠标滚轮事件的位置坐标是否能正确转换到插件内部坐标系。
* **测试页面滚动后触摸事件的处理 (Touch Event Scrolled):**  测试当页面滚动后，触摸事件的位置坐标是否能正确地传递给插件，并测试了原始触摸事件类型 (`kTouchEventRequestTypeRaw`) 和低延迟触摸事件类型 (`kTouchEventRequestTypeRawLowLatency`) 的合并情况。
* **测试页面滚动后鼠标滚轮事件的处理 (Mouse Wheel Event Scrolled):**  类似于触摸事件，测试页面滚动后鼠标滚轮事件的位置坐标是否能正确传递。
* **测试页面滚动后鼠标移动事件的处理 (MouseEvent Scrolled):**  测试页面滚动后鼠标移动事件的位置坐标是否能正确传递。
* **测试页面缩放后鼠标事件的处理 (MouseEvent Zoomed):**  测试当页面被缩放后，鼠标事件的位置坐标是否能正确地转换到插件内部坐标系。
* **测试页面缩放后鼠标滚轮事件的处理 (Mouse Wheel Event Zoomed):**  类似于鼠标事件，测试页面缩放后鼠标滚轮事件的坐标转换。
* **测试页面缩放后触摸事件的处理 (TouchEvent Zoomed):** 测试页面缩放后，触摸事件的位置坐标是否能正确地传递给插件。
* **测试 `IsRectTopmost` 在文档分离后的行为 (IsRectTopmostTest):**  验证当包含插件的文档被分离后，`IsRectTopmost` 方法返回 `false`。
* **测试 `IsRectTopmost` 在奇偶尺寸下的行为 (IsRectTopmostTestWithOddAndEvenDimensions):**  测试 `IsRectTopmost` 方法在插件尺寸为奇数和偶数时的正确性。
* **测试 iframe 中插件的可视区域计算 (ClippedRectsForIframedElement):** 测试当插件位于 iframe 中时，如何计算其可视区域。
* **测试滚动偏移的 iframe 中插件的可视区域计算 (ClippedRectsForShiftedIframedElement):**  测试当插件位于一个有滚动偏移的 iframe 中时，如何计算其可视区域。这涉及到父窗口和 iframe 的滚动状态。
* **测试亚像素定位插件的可视区域计算 (ClippedRectsForSubpixelPositionedPlugin):** 测试当插件使用亚像素进行定位时，可视区域的计算。
* **测试插件销毁后的 `IsRectTopmost` 行为 (TopmostAfterDetachTest):**  验证在插件的 `Destroy` 方法中调用 `IsRectTopmost` 会返回 `false`。
* **测试合成插件 (CompositedPlugin):**  开始测试具有合成层的插件。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:**  测试代码中使用了 `web_view->MainFrameImpl()->GetDocument().GetElementById(WebString::FromUTF8("translated-plugin"))` 来获取 HTML 元素，这模拟了 JavaScript 中通过 `document.getElementById()` 获取插件元素的操作。插件通常通过 `<embed>` 或 `<object>` 标签嵌入到 HTML 页面中。例如，`plugin_container.html` 文件可能包含如下代码：
  ```html
  <!DOCTYPE html>
  <html>
  <head>
      <title>Plugin Container Test</title>
  </head>
  <body>
      <embed id="translated-plugin" type="application/x-test-plugin" width="100" height="100">
      <embed id="odd-dimensions-plugin" type="application/x-test-plugin" width="101" height="101">
      <div style="position: absolute; left: 10.5px; top: 10.5px;">
          <embed id="subpixel-positioned-plugin" type="application/x-test-plugin" width="40" height="40">
      </div>
  </body>
  </html>
  ```
* **JavaScript:** 虽然测试代码本身是用 C++ 编写的，但它模拟了用户在网页上与插件交互的行为，这些行为通常是由 JavaScript 代码触发的。例如，用户点击插件，可能会触发 JavaScript 事件监听器，而测试代码则模拟了这种点击事件的发生。
* **CSS:** CSS 决定了插件在页面上的布局和位置。测试代码中的 `plugin_container_one_element.BoundsInWidget()` 方法获取了插件在页面上的边界，这直接受到 CSS 样式的影响。例如，如果插件的 CSS `position` 属性是 `absolute` 或 `fixed`，其位置计算方式会不同。

**逻辑推理的假设输入与输出举例:**

**测试用例： `TEST_F(WebPluginContainerTest, GestureEventTranslated)`**

* **假设输入:**
    * `plugin_container.html` 文件中包含一个 ID 为 "translated-plugin" 的插件。
    * 一个 `kGestureLongPress` 手势事件，其屏幕坐标分别为 (0, 0) 和 (插件中心坐标)。
* **逻辑推理:**
    * 如果手势事件的坐标 (0, 0) 不在插件的边界内，则插件不应该接收到该事件，`test_plugin->GetLastInputEventType()` 应该返回 `WebInputEvent::Type::kUndefined`。
    * 如果手势事件的坐标在插件的中心，则插件应该接收到该事件，`test_plugin->GetLastInputEventType()` 应该返回 `WebInputEvent::Type::kGestureLongPress`。
* **预期输出:**
    * 第一次事件发送后: `EXPECT_EQ(WebInputEvent::Type::kUndefined, test_plugin->GetLastInputEventType());`
    * 第二次事件发送后: `EXPECT_EQ(WebInputEvent::Type::kGestureLongPress, test_plugin->GetLastInputEventType());`

**用户或编程常见的使用错误举例:**

* **未启用插件:** 用户可能在其浏览器设置中禁用了插件。在这种情况下，即使网页中嵌入了插件，`WebPluginContainer` 也不会加载和激活插件。测试代码通过 `EnablePlugins(web_view, gfx::Size(300, 300));` 来确保测试环境中插件是启用的。
* **插件坐标计算错误:** 开发者在编写 JavaScript 代码时，可能错误地计算了插件在页面上的位置，导致事件监听器无法正确地附加到插件上。测试代码通过模拟不同位置的事件来验证坐标转换的正确性。
* **iframe 滚动同步问题:** 当插件位于 iframe 中时，开发者可能没有正确处理主窗口和 iframe 之间的滚动同步，导致插件的可视区域计算错误。测试代码中的 `ClippedRectsForShiftedIframedElement` 测试了这种情况。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户打开包含插件的网页:** 用户在浏览器中输入网址或点击链接，打开一个包含 `<embed>` 或 `<object>` 标签嵌入插件的网页。
2. **用户与插件交互:** 用户可能会对插件执行各种操作，例如：
    * **点击或触摸插件:**  这会触发鼠标或触摸事件。
    * **在插件上滚动鼠标滚轮:**  这会触发鼠标滚轮事件。
    * **长按插件:** 这会触发手势事件。
    * **拖拽插件（如果插件支持）:**  这会触发鼠标事件。
3. **浏览器处理用户输入:** 浏览器的渲染引擎 (Blink) 会捕获这些用户输入事件。
4. **事件路由到 `WebPluginContainer`:**  Blink 引擎会识别出事件发生在插件区域，并将相关事件路由到负责管理该插件的 `WebPluginContainer` 对象。
5. **`WebPluginContainer` 处理事件:** `WebPluginContainer` 会根据事件类型和位置等信息，决定如何处理该事件，例如将其传递给插件本身。

在调试与插件相关的事件问题时，可以关注以下几个方面：

* **检查 HTML 结构:**  确认插件是否正确地嵌入到页面中，`id` 属性是否正确。
* **检查 CSS 样式:**  确认插件的布局和位置是否符合预期，是否存在遮挡等问题。
* **使用开发者工具:**  使用浏览器的开发者工具 (Elements 面板查看 HTML 和 CSS，Network 面板查看资源加载，Performance 面板分析性能等)。
* **断点调试:**  在 Blink 引擎的源代码中设置断点，例如在 `WebPluginContainer::HandleInputEvent` 等方法中，跟踪事件的传递过程。

总而言之，这个测试文件的第二部分继续深入测试了 `WebPluginContainer` 在处理各种用户交互和页面布局变化时的正确行为，确保插件能够正确地接收和响应用户的操作，并正确地渲染其内容。

### 提示词
```
这是目录为blink/renderer/core/exported/web_plugin_container_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
tainer_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);

  // First, send an event that doesn't hit the plugin to verify that the
  // plugin doesn't receive it.
  event.SetPositionInWidget(gfx::PointF());

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kUndefined,
            test_plugin->GetLastInputEventType());

  // Next, send an event that does hit the plugin, and verify it does receive
  // it.
  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(
      gfx::PointF(rect.x() + rect.width() / 2, rect.y() + rect.height() / 2));

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kGestureLongPress,
            test_plugin->GetLastInputEventType());
}

TEST_F(WebPluginContainerTest, MouseEventButtons) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebMouseEvent event = frame_test_helpers::CreateMouseEvent(
      WebMouseEvent::Type::kMouseMove, WebMouseEvent::Button::kNoButton,
      gfx::Point(30, 30),
      WebInputEvent::kMiddleButtonDown | WebInputEvent::kShiftKey);

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(rect.x() + rect.width() / 2,
                            rect.y() + rect.height() / 2);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kMouseMove,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(WebInputEvent::kMiddleButtonDown | WebInputEvent::kShiftKey,
            test_plugin->GetLastEventModifiers());
}

TEST_F(WebPluginContainerTest, MouseWheelEventTranslated) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("translated-plugin"));
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebMouseWheelEvent event(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests());

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(rect.x() + rect.width() / 2,
                            rect.y() + rect.height() / 2);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kMouseWheel,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 2, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 2, test_plugin->GetLastEventLocation().y());
}

TEST_F(WebPluginContainerTest, TouchEventScrolled) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));
  web_view->SmoothScroll(0, 200, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRaw);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  WebPointerEvent event(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                           WebPointerProperties::Button::kLeft,
                           gfx::PointF(rect.x() + rect.width() / 2,
                                       rect.y() + rect.height() / 2),
                           gfx::PointF(rect.x() + rect.width() / 2,
                                       rect.y() + rect.height() / 2)),
      1.0f, 1.0f);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kTouchStart,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 2, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 2, test_plugin->GetLastEventLocation().y());
}

TEST_F(WebPluginContainerTest, TouchEventScrolledWithCoalescedTouches) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));
  web_view->SmoothScroll(0, 200, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRawLowLatency);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  {
    gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
    WebPointerEvent event(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(rect.x() + rect.width() / 2,
                                         rect.y() + rect.height() / 2),
                             gfx::PointF(rect.x() + rect.width() / 2,
                                         rect.y() + rect.height() / 2)),
        1.0f, 1.0f);

    WebCoalescedInputEvent coalesced_event(event, ui::LatencyInfo());

    web_view->MainFrameWidget()->HandleInputEvent(coalesced_event);
    web_view->MainFrameWidget()->DispatchBufferedTouchEvents();
    RunPendingTasks();

    EXPECT_EQ(static_cast<const size_t>(1),
              test_plugin->GetCoalescedEventCount());
    EXPECT_EQ(WebInputEvent::Type::kTouchStart,
              test_plugin->GetLastInputEventType());
    EXPECT_EQ(rect.width() / 2, test_plugin->GetLastEventLocation().x());
    EXPECT_EQ(rect.height() / 2, test_plugin->GetLastEventLocation().y());
  }

  {
    gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
    WebPointerEvent event1(
        WebInputEvent::Type::kPointerMove,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(rect.x() + rect.width() / 2 + 1,
                                         rect.y() + rect.height() / 2 + 1),
                             gfx::PointF(rect.x() + rect.width() / 2 + 1,
                                         rect.y() + rect.height() / 2 + 1)),
        1.0f, 1.0f);

    WebCoalescedInputEvent coalesced_event(event1, ui::LatencyInfo());

    WebPointerEvent event2(
        WebInputEvent::Type::kPointerMove,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(rect.x() + rect.width() / 2 + 2,
                                         rect.y() + rect.height() / 2 + 2),
                             gfx::PointF(rect.x() + rect.width() / 2 + 2,
                                         rect.y() + rect.height() / 2 + 2)),
        1.0f, 1.0f);
    WebPointerEvent event3(
        WebInputEvent::Type::kPointerMove,
        WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(rect.x() + rect.width() / 2 + 3,
                                         rect.y() + rect.height() / 2 + 3),
                             gfx::PointF(rect.x() + rect.width() / 2 + 3,
                                         rect.y() + rect.height() / 2 + 3)),
        1.0f, 1.0f);

    coalesced_event.AddCoalescedEvent(event2);
    coalesced_event.AddCoalescedEvent(event3);

    web_view->MainFrameWidget()->HandleInputEvent(coalesced_event);
    web_view->MainFrameWidget()->DispatchBufferedTouchEvents();
    RunPendingTasks();

    EXPECT_EQ(static_cast<const size_t>(3),
              test_plugin->GetCoalescedEventCount());
    EXPECT_EQ(WebInputEvent::Type::kTouchMove,
              test_plugin->GetLastInputEventType());
    EXPECT_EQ(rect.width() / 2 + 1, test_plugin->GetLastEventLocation().x());
    EXPECT_EQ(rect.height() / 2 + 1, test_plugin->GetLastEventLocation().y());
  }
}

TEST_F(WebPluginContainerTest, MouseWheelEventScrolled) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));
  web_view->SmoothScroll(0, 200, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRaw);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebMouseWheelEvent event(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests());

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(rect.x() + rect.width() / 2,
                            rect.y() + rect.height() / 2);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kMouseWheel,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 2, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 2, test_plugin->GetLastEventLocation().y());
}

TEST_F(WebPluginContainerTest, MouseEventScrolled) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));
  web_view->SmoothScroll(0, 200, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRaw);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebMouseEvent event(WebInputEvent::Type::kMouseMove,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(rect.x() + rect.width() / 2,
                            rect.y() + rect.height() / 2);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  EXPECT_EQ(WebInputEvent::Type::kMouseMove,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 2, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 2, test_plugin->GetLastEventLocation().y());
}

TEST_F(WebPluginContainerTest, MouseEventZoomed) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  DCHECK(web_view);
  web_view->GetSettings()->SetPluginsEnabled(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  web_view->SetPageScaleFactor(2);
  web_view->SmoothScroll(0, 300, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRaw);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebMouseEvent event(WebInputEvent::Type::kMouseMove,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests());

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(rect.x() + rect.width() / 2,
                            rect.y() + rect.height() / 2);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  // rect.width/height divided by 4 because the rect is in viewport bounds and
  // there is a scale of 2 set.
  EXPECT_EQ(WebInputEvent::Type::kMouseMove,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 4, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 4, test_plugin->GetLastEventLocation().y());
}

TEST_F(WebPluginContainerTest, MouseWheelEventZoomed) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  DCHECK(web_view);
  web_view->GetSettings()->SetPluginsEnabled(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  web_view->SetPageScaleFactor(2);
  web_view->SmoothScroll(0, 300, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRaw);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  WebMouseWheelEvent event(WebInputEvent::Type::kMouseWheel,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests());

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  event.SetPositionInWidget(rect.x() + rect.width() / 2,
                            rect.y() + rect.height() / 2);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();

  // rect.width/height divided by 4 because the rect is in viewport bounds and
  // there is a scale of 2 set.
  EXPECT_EQ(WebInputEvent::Type::kMouseWheel,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 4, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 4, test_plugin->GetLastEventLocation().y());
}

TEST_F(WebPluginContainerTest, TouchEventZoomed) {
  RegisterMockedURL("plugin_scroll.html");
  // Must outlive |web_view_helper|.
  CustomPluginWebFrameClient<EventTestPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_scroll.html", &plugin_web_frame_client);
  DCHECK(web_view);
  web_view->GetSettings()->SetPluginsEnabled(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  web_view->SetPageScaleFactor(2);
  web_view->SmoothScroll(0, 300, base::TimeDelta());
  UpdateAllLifecyclePhases(web_view);
  RunPendingTasks();

  WebElement plugin_container_one_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          WebString::FromUTF8("scrolled-plugin"));
  plugin_container_one_element.PluginContainer()->RequestTouchEventType(
      WebPluginContainer::kTouchEventRequestTypeRaw);
  WebPlugin* plugin = static_cast<WebPluginContainerImpl*>(
                          plugin_container_one_element.PluginContainer())
                          ->Plugin();
  EventTestPlugin* test_plugin = static_cast<EventTestPlugin*>(plugin);

  gfx::Rect rect = plugin_container_one_element.BoundsInWidget();
  WebPointerEvent event(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kTouch,
                           WebPointerProperties::Button::kLeft,
                           gfx::PointF(rect.x() + rect.width() / 2,
                                       rect.y() + rect.height() / 2),
                           gfx::PointF(rect.x() + rect.width() / 2,
                                       rect.y() + rect.height() / 2)),
      1.0f, 1.0f);

  web_view->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  web_view->MainFrameWidget()->DispatchBufferedTouchEvents();
  RunPendingTasks();

  // rect.width/height divided by 4 because the rect is in viewport bounds and
  // there is a scale of 2 set.
  EXPECT_EQ(WebInputEvent::Type::kTouchStart,
            test_plugin->GetLastInputEventType());
  EXPECT_EQ(rect.width() / 4, test_plugin->GetLastEventLocation().x());
  EXPECT_EQ(rect.height() / 4, test_plugin->GetLastEventLocation().y());
}

// Verify that isRectTopmost returns false when the document is detached.
TEST_F(WebPluginContainerTest, IsRectTopmostTest) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  auto* plugin_container_impl =
      To<WebPluginContainerImpl>(GetWebPluginContainer(
          web_view, WebString::FromUTF8("translated-plugin")));
  plugin_container_impl->SetFrameRect(gfx::Rect(0, 0, 300, 300));

  gfx::Rect rect = plugin_container_impl->GetElement().BoundsInWidget();
  EXPECT_TRUE(plugin_container_impl->IsRectTopmost(rect));

  // Cause the plugin's frame to be detached.
  web_view_helper.Reset();

  EXPECT_FALSE(plugin_container_impl->IsRectTopmost(rect));
}

// Verify that IsRectTopmost works with odd and even dimensions.
TEST_F(WebPluginContainerTest, IsRectTopmostTestWithOddAndEvenDimensions) {
  RegisterMockedURL("plugin_container.html");
  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  auto* even_plugin_container_impl =
      To<WebPluginContainerImpl>(GetWebPluginContainer(
          web_view, WebString::FromUTF8("translated-plugin")));
  even_plugin_container_impl->SetFrameRect(gfx::Rect(0, 0, 300, 300));
  auto even_rect = even_plugin_container_impl->GetElement().BoundsInWidget();
  EXPECT_TRUE(even_plugin_container_impl->IsRectTopmost(even_rect));

  auto* odd_plugin_container_impl =
      To<WebPluginContainerImpl>(GetWebPluginContainer(
          web_view, WebString::FromUTF8("odd-dimensions-plugin")));
  odd_plugin_container_impl->SetFrameRect(gfx::Rect(0, 0, 300, 300));
  auto odd_rect = odd_plugin_container_impl->GetElement().BoundsInWidget();
  EXPECT_TRUE(odd_plugin_container_impl->IsRectTopmost(odd_rect));
}

TEST_F(WebPluginContainerTest, ClippedRectsForIframedElement) {
  RegisterMockedURL("plugin_container.html");
  RegisterMockedURL("plugin_containing_page.html");

  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebView* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_containing_page.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_element = web_view->MainFrame()
                                  ->FirstChild()
                                  ->ToWebLocalFrame()
                                  ->GetDocument()
                                  .GetElementById("translated-plugin");
  auto* plugin_container_impl =
      To<WebPluginContainerImpl>(plugin_element.PluginContainer());

  DCHECK(plugin_container_impl);

  gfx::Rect window_rect, clip_rect, unobscured_rect;
  CalculateGeometry(plugin_container_impl, window_rect, clip_rect,
                    unobscured_rect);
  EXPECT_EQ(gfx::Rect(20, 220, 40, 40), window_rect);
  EXPECT_EQ(gfx::Rect(0, 0, 40, 40), clip_rect);
  EXPECT_EQ(gfx::Rect(0, 0, 40, 40), unobscured_rect);

  // Cause the plugin's frame to be detached.
  web_view_helper.Reset();
}

TEST_F(WebPluginContainerTest, ClippedRectsForShiftedIframedElement) {
  RegisterMockedURL("plugin_hidden_before_scroll.html");
  RegisterMockedURL("shifted_plugin_containing_page.html");

  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "shifted_plugin_containing_page.html",
      &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));
  UpdateAllLifecyclePhases(web_view);
  WebLocalFrame* iframe =
      web_view->MainFrame()->FirstChild()->ToWebLocalFrame();
  WebElement plugin_element =
      iframe->GetDocument().GetElementById("plugin-hidden-before-scroll");
  auto* plugin_container_impl =
      To<WebPluginContainerImpl>(plugin_element.PluginContainer());

  DCHECK(plugin_container_impl);

  gfx::Size plugin_size(40, 40);
  gfx::Size iframe_size(40, 40);

  gfx::Vector2d iframe_offset_in_root_frame(0, 300);
  gfx::Vector2d plugin_offset_in_iframe(0, 40);

  auto compute_expected_values = [=](gfx::Point root_document_scroll_to,
                                     gfx::Point iframe_scroll_to) {
    gfx::Vector2d offset_in_iframe =
        plugin_offset_in_iframe - iframe_scroll_to.OffsetFromOrigin();
    gfx::Vector2d offset_in_root_document =
        iframe_offset_in_root_frame -
        root_document_scroll_to.OffsetFromOrigin();
    // window_rect is a plugin rectangle in the root frame coordinates.
    gfx::Rect expected_window_rect(
        gfx::PointAtOffsetFromOrigin(offset_in_root_document +
                                     offset_in_iframe),
        plugin_size);

    // unobscured_rect is the visible part of the plugin, inside the iframe.
    gfx::Rect expected_unobscured_rect(iframe_scroll_to, iframe_size);
    expected_unobscured_rect.Intersect(gfx::Rect(
        gfx::PointAtOffsetFromOrigin(plugin_offset_in_iframe), plugin_size));
    expected_unobscured_rect.Offset(-plugin_offset_in_iframe);

    // clip_rect is the visible part of the unobscured_rect, inside the
    // root_frame.
    gfx::Rect expected_clip_rect = expected_unobscured_rect;
    expected_clip_rect.Offset(expected_window_rect.OffsetFromOrigin());
    expected_clip_rect.Intersect(gfx::Rect(300, 300));
    expected_clip_rect.Offset(-expected_window_rect.OffsetFromOrigin());

    return std::make_tuple(expected_window_rect, expected_clip_rect,
                           expected_unobscured_rect);
  };

  gfx::Point root_document_scrolls_to[] = {
      gfx::Point(0, 0), gfx::Point(0, 20), gfx::Point(0, 300),
      gfx::Point(0, 320), gfx::Point(0, 340)};

  gfx::Point iframe_scrolls_to[] = {gfx::Point(0, 0), gfx::Point(0, 20),
                                    gfx::Point(0, 40), gfx::Point(0, 60),
                                    gfx::Point(0, 80)};

  for (auto& root_document_scroll_to : root_document_scrolls_to) {
    for (auto& iframe_scroll_to : iframe_scrolls_to) {
      web_view->SmoothScroll(root_document_scroll_to.x(),
                             root_document_scroll_to.y(), base::TimeDelta());
      iframe->SetScrollOffset(gfx::PointF(iframe_scroll_to));
      UpdateAllLifecyclePhases(web_view);
      RunPendingTasks();

      auto expected_values =
          compute_expected_values(root_document_scroll_to, iframe_scroll_to);

      gfx::Rect window_rect, clip_rect, unobscured_rect;
      CalculateGeometry(plugin_container_impl, window_rect, clip_rect,
                        unobscured_rect);

      EXPECT_EQ(std::get<0>(expected_values), window_rect);
      EXPECT_EQ(std::get<1>(expected_values), clip_rect);

      // It seems that CalculateGeometry calculates x and y values for empty
      // rectangles slightly differently, but these values are not important in
      // the empty case.
      if(std::get<2>(expected_values).IsEmpty())
        EXPECT_TRUE(unobscured_rect.IsEmpty());
      else
        EXPECT_EQ(std::get<2>(expected_values), unobscured_rect);
    }
  }

  // Cause the plugin's frame to be detached.
  web_view_helper.Reset();
}

TEST_F(WebPluginContainerTest, ClippedRectsForSubpixelPositionedPlugin) {
  RegisterMockedURL("plugin_container.html");

  // Must outlive |web_view_helper|.
  TestPluginWebFrameClient plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  WebElement plugin_element =
      web_view->MainFrameImpl()->GetDocument().GetElementById(
          "subpixel-positioned-plugin");
  auto* plugin_container_impl =
      To<WebPluginContainerImpl>(plugin_element.PluginContainer());

  DCHECK(plugin_container_impl);

  gfx::Rect window_rect, clip_rect, unobscured_rect;
  CalculateGeometry(plugin_container_impl, window_rect, clip_rect,
                    unobscured_rect);
  EXPECT_EQ(gfx::Rect(0, 0, 40, 40), window_rect);
  EXPECT_EQ(gfx::Rect(0, 0, 40, 40), clip_rect);
  EXPECT_EQ(gfx::Rect(0, 0, 40, 40), unobscured_rect);

  // Cause the plugin's frame to be detached.
  web_view_helper.Reset();
}

TEST_F(WebPluginContainerTest, TopmostAfterDetachTest) {
  static constexpr gfx::Rect kTopmostRect(10, 10, 40, 40);

  // Plugin that checks isRectTopmost in destroy().
  class TopmostPlugin : public FakeWebPlugin {
   public:
    explicit TopmostPlugin(const WebPluginParams& params)
        : FakeWebPlugin(params) {}

    bool IsRectTopmost() { return Container()->IsRectTopmost(kTopmostRect); }

    void Destroy() override {
      // In destroy, IsRectTopmost is no longer valid.
      EXPECT_FALSE(Container()->IsRectTopmost(kTopmostRect));
      FakeWebPlugin::Destroy();
    }

   private:
    ~TopmostPlugin() override = default;
  };

  RegisterMockedURL("plugin_container.html");
  // The client must outlive WebViewHelper.
  CustomPluginWebFrameClient<TopmostPlugin> plugin_web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.InitializeAndLoad(
      base_url_ + "plugin_container.html", &plugin_web_frame_client);
  EnablePlugins(web_view, gfx::Size(300, 300));

  auto* plugin_container_impl =
      To<WebPluginContainerImpl>(GetWebPluginContainer(
          web_view, WebString::FromUTF8("translated-plugin")));
  plugin_container_impl->SetFrameRect(gfx::Rect(0, 0, 300, 300));

  EXPECT_TRUE(plugin_container_impl->IsRectTopmost(kTopmostRect));

  TopmostPlugin* test_plugin =
      static_cast<TopmostPlugin*>(plugin_container_impl->Plugin());
  EXPECT_TRUE(test_plugin->IsRectTopmost());

  // Cause the plugin's frame to be detached.
  web_view_helper.Reset();

  EXPECT_FALSE(plugin_container_impl->IsRectTopmost(kTopmostRect));
}

namespace {

class CompositedPlugin : public FakeWebPlugin {
 public:
  explicit CompositedPlugin(const WebPluginParams& params)
      : FakeWebPlugin(params), layer_(cc::Layer::Create()) {}

  cc::Layer* GetCcLayer() const { return layer_.get(); }

  // WebPlugin

  bool Initialize(WebPluginContainer* container) override {
    if (!FakeWebPlugin::Initialize(container))
      return false;
    container->SetCcLayer(layer_.get());
    return true;
  }

  void Destroy() override {
    Container()->SetCcLayer(nullptr);
    FakeWebPlugin::Destroy();
  }

 private:
  ~CompositedPlugin() override = default;

  scoped_refptr<cc::Layer> layer_;
};

}  // namespace

TEST_F(WebPluginContainerTest, CompositedPlugin) {
  RegisterMockedURL("plugin.html");
  // Must outlive |web_view_helper|
  CustomPluginWebFrameClient<CompositedPlugin> web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view = web_view_helper.
```
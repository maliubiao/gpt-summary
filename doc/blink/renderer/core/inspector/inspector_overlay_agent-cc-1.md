Response:
The user wants a summary of the functionality of the `InspectorOverlayAgent` class in the Chromium Blink engine, based on the provided C++ source code. I need to identify the core responsibilities of this class and how it interacts with other parts of the browser, particularly in the context of developer tools (inspector).

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The name "InspectorOverlayAgent" strongly suggests its primary role is to manage the visual overlays displayed in the browser window when the developer tools are active. This includes highlighting elements, showing layout grids, and other debugging aids.

2. **Analyze Key Methods:**  I'll go through the provided code snippets, focusing on the public methods as they represent the class's interface and functionalities.

    * **`setShowWindowSizeOnResize`:**  This clearly controls whether a visual indicator of the window size is shown during resizing.
    * **`highlightQuad`, `highlightNode`, `highlightRect`:** These methods are responsible for drawing different types of highlights on the screen, likely used for inspecting specific areas or elements. They take configuration objects as input, allowing customization of the highlight appearance.
    * **`highlightFrame`:** This suggests highlighting entire frames within the page.
    * **`highlightSourceOrder`:** This points to functionality for visualizing the source order of elements, useful for accessibility and SEO analysis.
    * **`highlightIsolatedElement`:** This hints at highlighting elements in specific isolation contexts, potentially related to shadow DOM or similar features.
    * **`hideHighlight`:**  A straightforward function to remove any active highlights.
    * **`getHighlightObjectForTest`, `getGridHighlightObjectsForTest`, `getSourceOrderHighlightObjectForTest`:** These "ForTest" methods suggest the class exposes internal highlight information for testing purposes.
    * **Input Event Handling (`HandleInputEvent`, `HandleInputEventInOverlay`):**  The class processes mouse and keyboard events, likely to enable interactive features within the overlay, such as selecting elements to inspect.
    * **Painting (`PaintOverlay`, `PaintOverlayPage`):** The class is responsible for drawing the overlay content onto the screen.
    * **Overlay Page Management (`LoadOverlayPageResource`, `OverlayMainFrame`, `Reset`, `EvaluateInOverlay`):** The code indicates the existence of a separate "overlay page" (likely an internal HTML page) used to render the inspector overlay. These methods manage the loading, communication, and synchronization with this overlay page.
    * **`setInspectMode`:**  This method seems to control the active inspection mode (e.g., selecting elements, capturing screenshots).
    * **`PickTheRightTool`:** This internal method decides which "tool" (an object responsible for specific overlay interactions) should be active based on the current state.
    * **`SetInspectTool`:**  This method activates a specific inspection tool.
    * **Configuration Methods (`SourceOrderConfigFromInspectorObject`, `HighlightConfigFromInspectorObject`, `ToGridHighlightConfig`, `ToFlexContainerHighlightConfig`):** These methods parse and convert configuration objects received from the DevTools frontend into internal representations.

3. **Identify Relationships with Web Technologies:**

    * **JavaScript:** The presence of `EvaluateInOverlay` strongly suggests communication with JavaScript code running in the overlay page. The loading of `IDR_INSPECT_TOOL_MAIN_JS` confirms this. The `Dispatch` method also indicates communication with JavaScript within the context of active tools.
    * **HTML:** The "overlay page" itself is likely an HTML document that structures the visual elements of the inspector overlay.
    * **CSS:** The various highlight configuration options (colors, outlines, dashes) directly relate to CSS styling concepts. The grid and flexbox highlighting features directly visualize CSS layout properties.

4. **Identify Logical Inferences and Assumptions:**

    * **Input/Output of `highlight...` methods:**  Input would be the node/element to highlight and configuration options. The output is the visual highlight on the screen.
    * **Input/Output of `setInspectMode`:** Input is the desired inspect mode and optional configuration. The output is the activation of the corresponding tool and visual changes in the overlay.
    * **Input/Output of input event handlers:** Input is a web input event. Output could be changes in the overlay, triggering actions in the inspected page, or suppressing default browser behavior.

5. **Identify Potential User/Programming Errors:**

    * **Invalid Node IDs:** Passing an incorrect node ID to highlighting methods will lead to errors.
    * **Incorrect Configuration:** Providing invalid color formats or other configuration values will result in errors or unexpected behavior.
    * **Calling Tool Methods Before Enabling:**  Trying to use inspection tools before the overlay is enabled will fail.

6. **Synthesize the Summary:** Based on the analysis, I'll organize the functionalities into logical groups and provide concrete examples where applicable. I'll also cover the relationships with web technologies and potential errors.

**(Self-Correction during the thought process):** Initially, I might focus too much on individual methods. It's important to step back and identify the larger patterns and core responsibilities. Realizing the importance of the "overlay page" and the communication between the C++ agent and the JavaScript in that page is crucial. Also, the "ForTest" methods provide valuable clues about the internal data structures and testing strategies. Paying attention to the different "tools" being created helps understand the modular design of the overlay functionality.
这是 `blink/renderer/core/inspector/inspector_overlay_agent.cc` 文件的第二部分，主要负责处理与 Inspector 覆盖层相关的各种功能。在前一部分已经初始化了覆盖层，并处理了一些基本的启用和禁用操作。

**本部分主要功能归纳：**

本部分继续增强 Inspector 覆盖层的功能，主要集中在以下几个方面：

1. **隔离元素的突出显示 (Isolation Mode Highlight):**
   - 允许高亮显示处于隔离模式的元素，例如 Shadow DOM 中的元素。
   - 可以为不同的隔离元素应用不同的高亮配置。

2. **源代码顺序突出显示 (Source Order Highlight):**
   - 允许根据元素在源代码中的顺序来高亮显示元素。
   - 可以自定义父元素和子元素的轮廓颜色。

3. **Frame 突出显示 (Frame Highlight):**
   - 允许高亮显示特定的 frame 边界。
   - 可以自定义填充和轮廓颜色。

4. **隐藏高亮 (Hide Highlight):**
   - 提供隐藏当前高亮显示的功能。

5. **测试相关的 API (For Test):**
   - 提供了一系列以 `get...ForTest` 命名的方法，用于获取高亮对象的 JSON 表示，主要用于自动化测试。
   - 这些方法允许测试人员验证特定节点的高亮配置，例如是否包含距离信息、样式信息、颜色格式等。
   - 涵盖了普通节点、Grid 布局节点和源代码顺序节点的高亮信息获取。

6. **覆盖层绘制和更新 (Paint Overlay, UpdatePrePaint):**
   - 负责在页面上绘制覆盖层的内容。
   - `PaintOverlay` 方法实际执行绘制操作。
   - `UpdatePrePaint` 方法可能在绘制前进行一些准备工作。

7. **输入事件处理 (HandleInputEvent, HandleInputEventInOverlay):**
   - 负责处理用户在覆盖层上的输入事件，例如鼠标移动、点击、键盘事件等。
   - `HandleInputEvent` 处理主框架的输入事件，并可能将事件转发给覆盖层。
   - `HandleInputEventInOverlay` 处理覆盖层自身的输入事件。

8. **覆盖层页面管理和通信 (LoadOverlayPageResource, OverlayMainFrame, Reset, EvaluateInOverlay):**
   - 代码中存在一个独立的 "覆盖层页面" (`overlay_page_`)，很可能是一个内部的 HTML 页面，用于渲染 Inspector 的 UI 元素。
   - `LoadOverlayPageResource` 负责加载覆盖层页面的资源（例如 JavaScript 代码）。
   - `OverlayMainFrame` 获取覆盖层的主框架。
   - `Reset` 方法用于重置覆盖层页面的状态，传递视口大小等信息。
   - `EvaluateInOverlay` 方法用于在覆盖层页面的 JavaScript 环境中执行代码，实现 C++ 和 JavaScript 之间的通信。

9. **检查模式控制 (setInspectMode, PickTheRightTool):**
   - `setInspectMode` 方法用于设置 Inspector 的检查模式，例如选择元素、查找节点等。
   - `PickTheRightTool` 方法根据当前的检查模式选择合适的 "工具" (Tool) 对象来处理交互。不同的 Tool 负责不同的高亮和交互行为。

10. **工具的激活和管理 (SetInspectTool, ClearInspectTool):**
    - `SetInspectTool` 方法用于激活特定的检查工具，并负责加载覆盖层页面资源和发送必要的指令到覆盖层页面。
    - `ClearInspectTool` 方法用于清除当前激活的检查工具。

11. **配置对象的转换 (SourceOrderConfigFromInspectorObject, HighlightConfigFromInspectorObject, ToGridHighlightConfig, ToFlexContainerHighlightConfig):**
    - 提供了一系列静态方法，用于将 Inspector 前端发送的配置对象转换为 C++ 中使用的内部配置对象。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    - `EvaluateInOverlay("drawingFinished", "");`  这行代码调用覆盖层页面 JavaScript 中的 `dispatch` 函数，并传递 "drawingFinished" 作为方法名。覆盖层页面的 JavaScript 代码可能会监听 "drawingFinished" 事件，并在收到后执行一些操作，例如隐藏加载动画。
    - `EvaluateInOverlay("setOverlay", inspect_tool->GetOverlayName());`  这行代码设置覆盖层要显示的具体内容，`inspect_tool->GetOverlayName()` 返回的字符串很可能是覆盖层页面中用于显示特定工具的组件名称。
    - `InspectorOverlayHost` 对象被暴露给覆盖层页面的 JavaScript，JavaScript 可以调用其上的方法与 C++ 代码进行交互。

* **HTML:**
    - `LoadOverlayPageResource()` 方法加载了 `IDR_INSPECT_TOOL_MAIN_JS`，这通常与一个内部的 HTML 页面相关联。这个 HTML 页面很可能包含了 Inspector 覆盖层 UI 的基本结构。
    - 覆盖层本身渲染在浏览器窗口的顶层，可以认为是动态生成的 HTML 元素。

* **CSS:**
    - `highlight_config->content = ParseColor(color.get());`  这里 `ParseColor` 函数会将前端传递的颜色值（很可能是 CSS 中使用的 RGBA 格式）解析为 C++ 中可以使用的颜色对象。这些颜色对象最终会影响覆盖层中高亮显示的样式。
    -  `InspectorGridHighlightConfig` 和 `InspectorFlexContainerHighlightConfig` 包含了各种与 CSS Grid 和 Flexbox 布局相关的样式配置，例如网格线颜色、虚线样式等。

**逻辑推理的假设输入与输出举例：**

**假设输入：** 调用 `highlightNode` 方法，传入一个 `node_id` 为 123 的 `div` 元素，并设置 `highlight_config->content` 的颜色为红色。

**输出：** 在浏览器窗口中，`node_id` 为 123 的 `div` 元素将被高亮显示，填充颜色为红色。

**用户或编程常见的使用错误举例：**

* **用户错误：**  在 Inspector 关闭的情况下，尝试使用 Inspector 的高亮功能，可能会导致功能无法正常工作或报错。例如，如果覆盖层没有被启用 (`enabled_.Get()` 为 false)，调用 `SetInspectTool` 会返回错误。
* **编程错误：**
    - 向 `AssertElement` 或 `AssertNode` 传递无效的 `node_id`，会导致断言失败或返回错误响应。
    - 在调用 `EvaluateInOverlay` 时，传递了覆盖层页面 JavaScript 中不存在的方法名，会导致 JavaScript 错误。
    - 在配置高亮样式时，使用了覆盖层不支持的颜色格式，可能会导致样式显示异常。

总而言之，这部分代码深入实现了 Inspector 覆盖层的核心功能，包括各种类型的元素高亮、与覆盖层页面的通信、以及处理用户交互，是 Inspector 功能实现的重要组成部分。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_overlay_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
figs) {
  if (!persistent_tool_) {
    persistent_tool_ =
        MakeGarbageCollected<PersistentTool>(this, GetFrontend());
  }

  HeapHashMap<WeakMember<Element>,
              std::unique_ptr<InspectorIsolationModeHighlightConfig>>
      configs;

  int idx = 0;
  for (std::unique_ptr<protocol::Overlay::IsolatedElementHighlightConfig>&
           config : *isolated_element_highlight_configs) {
    Element* element = nullptr;
    // Isolation mode can only be triggered on elements
    protocol::Response response =
        dom_agent_->AssertElement(config->getNodeId(), element);
    if (!response.IsSuccess()) {
      return response;
    }
    configs.insert(element,
                   InspectorOverlayAgent::ToIsolationModeHighlightConfig(
                       config->getIsolationModeHighlightConfig(), idx));
    idx++;
  }

  persistent_tool_->SetIsolatedElementConfigs(std::move(configs));

  PickTheRightTool();

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::highlightSourceOrder(
    std::unique_ptr<protocol::Overlay::SourceOrderConfig>
        source_order_inspector_object,
    Maybe<int> node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id) {
  Node* node = nullptr;
  protocol::Response response =
      dom_agent_->AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess()) {
    return response;
  }

  InspectorSourceOrderConfig config = SourceOrderConfigFromInspectorObject(
      std::move(source_order_inspector_object));
  std::unique_ptr<InspectorSourceOrderConfig> source_order_config =
      std::make_unique<InspectorSourceOrderConfig>(config);

  return SetInspectTool(MakeGarbageCollected<SourceOrderTool>(
      this, GetFrontend(), node, std::move(source_order_config)));
}

protocol::Response InspectorOverlayAgent::highlightFrame(
    const String& frame_id,
    Maybe<protocol::DOM::RGBA> color,
    Maybe<protocol::DOM::RGBA> outline_color) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  // FIXME: Inspector doesn't currently work cross process.
  if (!frame) {
    return protocol::Response::ServerError("Invalid frame id");
  }
  if (!frame->DeprecatedLocalOwner()) {
    PickTheRightTool();
    return protocol::Response::Success();
  }

  std::unique_ptr<InspectorHighlightConfig> highlight_config =
      std::make_unique<InspectorHighlightConfig>();
  highlight_config->show_info = true;  // Always show tooltips for frames.
  highlight_config->content = ParseColor(color.get());
  highlight_config->content_outline = ParseColor(outline_color.get());

  return SetInspectTool(MakeGarbageCollected<NodeHighlightTool>(
      this, GetFrontend(), frame->DeprecatedLocalOwner(), String(),
      std::move(highlight_config)));
}

protocol::Response InspectorOverlayAgent::hideHighlight() {
  if (inspect_tool_ && inspect_tool_->HideOnHideHighlight()) {
    PickTheRightTool();
  }

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::getHighlightObjectForTest(
    int node_id,
    Maybe<bool> include_distance,
    Maybe<bool> include_style,
    Maybe<String> colorFormat,
    Maybe<bool> show_accessibility_info,
    std::unique_ptr<protocol::DictionaryValue>* result) {
  Node* node = nullptr;
  protocol::Response response = dom_agent_->AssertNode(node_id, node);
  if (!response.IsSuccess()) {
    return response;
  }

  auto config = std::make_unique<InspectorHighlightConfig>(
      InspectorHighlight::DefaultConfig());
  config->show_styles = include_style.value_or(false);
  config->show_accessibility_info = show_accessibility_info.value_or(true);
  String format = colorFormat.value_or("hex");
  namespace ColorFormatEnum = protocol::Overlay::ColorFormatEnum;
  if (format == ColorFormatEnum::Hsl) {
    config->color_format = ColorFormat::kHsl;
  } else if (format == ColorFormatEnum::Hwb) {
    config->color_format = ColorFormat::kHwb;
  } else if (format == ColorFormatEnum::Rgb) {
    config->color_format = ColorFormat::kRgb;
  } else {
    config->color_format = ColorFormat::kHex;
  }
  NodeHighlightTool* tool = MakeGarbageCollected<NodeHighlightTool>(
      this, GetFrontend(), node, "" /* selector_list */, std::move(config));
  node->GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kInspector);
  *result = tool->GetNodeInspectorHighlightAsJson(
      true /* append_element_info */, include_distance.value_or(false));
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::getGridHighlightObjectsForTest(
    std::unique_ptr<protocol::Array<int>> node_ids,
    std::unique_ptr<protocol::DictionaryValue>* highlights) {
  PersistentTool* persistent_tool =
      MakeGarbageCollected<PersistentTool>(this, GetFrontend());

  HeapHashMap<WeakMember<Node>, std::unique_ptr<InspectorGridHighlightConfig>>
      configs;
  for (const int node_id : *node_ids) {
    Node* node = nullptr;
    protocol::Response response = dom_agent_->AssertNode(node_id, node);
    if (!response.IsSuccess()) {
      return response;
    }
    configs.insert(node, std::make_unique<InspectorGridHighlightConfig>(
                             InspectorHighlight::DefaultGridConfig()));
  }
  persistent_tool->SetGridConfigs(std::move(configs));
  *highlights = persistent_tool->GetGridInspectorHighlightsAsJson();
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::getSourceOrderHighlightObjectForTest(
    int node_id,
    std::unique_ptr<protocol::DictionaryValue>* result) {
  Node* node = nullptr;
  protocol::Response response = dom_agent_->AssertNode(node_id, node);
  if (!response.IsSuccess()) {
    return response;
  }

  auto config = std::make_unique<InspectorSourceOrderConfig>(
      InspectorSourceOrderHighlight::DefaultConfig());

  SourceOrderTool* tool = MakeGarbageCollected<SourceOrderTool>(
      this, GetFrontend(), node, std::move(config));
  *result = tool->GetNodeInspectorSourceOrderHighlightAsJson();
  return protocol::Response::Success();
}

void InspectorOverlayAgent::UpdatePrePaint() {
  if (frame_overlay_) {
    frame_overlay_->UpdatePrePaint();
  }
}

void InspectorOverlayAgent::PaintOverlay(GraphicsContext& context) {
  if (frame_overlay_) {
    frame_overlay_->Paint(context);
  }
}

bool InspectorOverlayAgent::IsInspectorLayer(const cc::Layer* layer) const {
  if (!frame_overlay_) {
    return false;
  }
  return layer == static_cast<const InspectorPageOverlayDelegate*>(
                      frame_overlay_->GetDelegate())
                      ->GetLayer();
}

LocalFrame* InspectorOverlayAgent::GetFrame() const {
  return frame_impl_->GetFrame();
}

void InspectorOverlayAgent::DispatchBufferedTouchEvents() {
  if (!inspect_tool_) {
    return;
  }
  OverlayMainFrame()->GetEventHandler().DispatchBufferedTouchEvents();
}

void InspectorOverlayAgent::SetPageIsScrolling(bool is_scrolling) {
  is_page_scrolling_ = is_scrolling;
}

WebInputEventResult InspectorOverlayAgent::HandleInputEvent(
    const WebInputEvent& input_event) {
  if (!enabled_.Get()) {
    return WebInputEventResult::kNotHandled;
  }

  if (input_event.GetType() == WebInputEvent::Type::kMouseUp &&
      swallow_next_mouse_up_) {
    swallow_next_mouse_up_ = false;
    return WebInputEventResult::kHandledSuppressed;
  }

  LocalFrame* frame = GetFrame();
  if (!frame || !frame->View() || !frame->ContentLayoutObject() ||
      !inspect_tool_) {
    return WebInputEventResult::kNotHandled;
  }

  bool handled = inspect_tool_->HandleInputEvent(
      frame_impl_->GetFrameView(), input_event, &swallow_next_mouse_up_);

  if (handled) {
    ScheduleUpdate();
    return WebInputEventResult::kHandledSuppressed;
  }

  if (inspect_tool_->ForwardEventsToOverlay()) {
    WebInputEventResult result = HandleInputEventInOverlay(input_event);
    if (result != WebInputEventResult::kNotHandled) {
      ScheduleUpdate();
      return result;
    }
  }

  // Exit tool upon unhandled Esc.
  if (input_event.GetType() == WebInputEvent::Type::kRawKeyDown) {
    const WebKeyboardEvent& keyboard_event =
        static_cast<const WebKeyboardEvent&>(input_event);
    if (keyboard_event.windows_key_code == VKEY_ESCAPE) {
      GetFrontend()->inspectModeCanceled();
      return WebInputEventResult::kNotHandled;
    }
  }

  if (input_event.GetType() == WebInputEvent::Type::kMouseMove &&
      inspect_tool_->HideOnMouseMove()) {
    PickTheRightTool();
  }

  return WebInputEventResult::kNotHandled;
}

WebInputEventResult InspectorOverlayAgent::HandleInputEventInOverlay(
    const WebInputEvent& input_event) {
  if (input_event.GetType() == WebInputEvent::Type::kGestureTap) {
    return OverlayMainFrame()->GetEventHandler().HandleGestureEvent(
        static_cast<const WebGestureEvent&>(input_event));
  }

  if (WebInputEvent::IsMouseEventType(input_event.GetType())) {
    WebMouseEvent mouse_event = static_cast<const WebMouseEvent&>(input_event);
    if (mouse_event.GetType() == WebInputEvent::Type::kMouseMove) {
      return OverlayMainFrame()->GetEventHandler().HandleMouseMoveEvent(
          mouse_event, {}, {});
    }
    if (mouse_event.GetType() == WebInputEvent::Type::kMouseDown) {
      return OverlayMainFrame()->GetEventHandler().HandleMousePressEvent(
          mouse_event);
    }
    if (mouse_event.GetType() == WebInputEvent::Type::kMouseUp) {
      return OverlayMainFrame()->GetEventHandler().HandleMouseReleaseEvent(
          mouse_event);
    }
    return WebInputEventResult::kNotHandled;
  }

  if (WebInputEvent::IsPointerEventType(input_event.GetType())) {
    return OverlayMainFrame()->GetEventHandler().HandlePointerEvent(
        static_cast<const WebPointerEvent&>(input_event),
        Vector<WebPointerEvent>(), Vector<WebPointerEvent>());
  }

  if (WebInputEvent::IsKeyboardEventType(input_event.GetType())) {
    return OverlayMainFrame()->GetEventHandler().KeyEvent(
        static_cast<const WebKeyboardEvent&>(input_event));
  }

  if (input_event.GetType() == WebInputEvent::Type::kMouseWheel) {
    return OverlayMainFrame()->GetEventHandler().HandleWheelEvent(
        static_cast<const WebMouseWheelEvent&>(input_event));
  }

  return WebInputEventResult::kNotHandled;
}

void InspectorOverlayAgent::ScheduleUpdate() {
  if (IsVisible()) {
    GetFrame()->GetPage()->GetChromeClient().ScheduleAnimation(
        GetFrame()->View());
  }
}

void InspectorOverlayAgent::PaintOverlayPage() {
  DCHECK(overlay_page_);

  LocalFrameView* view = frame_impl_->GetFrameView();
  LocalFrame* frame = GetFrame();
  if (!view || !frame) {
    return;
  }

  LocalFrame* overlay_frame = OverlayMainFrame();
  blink::VisualViewport& visual_viewport =
      frame->GetPage()->GetVisualViewport();
  // The emulation scale factor is backed in the overlay frame.
  gfx::Size viewport_size =
      gfx::ScaleToCeiledSize(visual_viewport.Size(), EmulationScaleFactor());
  overlay_frame->SetLayoutZoomFactor(WindowToViewportScale());
  overlay_frame->View()->Resize(viewport_size);
  OverlayMainFrame()->View()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kInspector);

  Reset(viewport_size, frame->View()->ViewportSizeForMediaQueries());

  float scale = WindowToViewportScale();

  if (inspect_tool_) {
    // Skip drawing persistent_tool_ on page scroll.
    if (!(inspect_tool_ == persistent_tool_ && is_page_scrolling_)) {
      inspect_tool_->Draw(scale);
    }
    if (persistent_tool_ && inspect_tool_->SupportsPersistentOverlays() &&
        !is_page_scrolling_) {
      persistent_tool_->Draw(scale);
    }
  }

  if (hinge_) {
    hinge_->Draw(scale);
  }

  EvaluateInOverlay("drawingFinished", "");

  OverlayMainFrame()->View()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kInspector);
}

float InspectorOverlayAgent::EmulationScaleFactor() const {
  return GetFrame()
      ->GetPage()
      ->GetChromeClient()
      .InputEventsScaleForEmulation();
}

void InspectorOverlayAgent::DidInitializeFrameWidget() {
  if (original_layer_tree_debug_state_) {
    return;
  }

  original_layer_tree_debug_state_ = std::make_unique<cc::LayerTreeDebugState>(
      *GetFrame()->GetWidgetForLocalRoot()->GetLayerTreeDebugState());
  Restore();
}

bool InspectorOverlayAgent::FrameWidgetInitialized() const {
  return !!original_layer_tree_debug_state_;
}

static std::unique_ptr<protocol::DictionaryValue> BuildObjectForSize(
    const gfx::Size& size) {
  std::unique_ptr<protocol::DictionaryValue> result =
      protocol::DictionaryValue::create();
  result->setInteger("width", size.width());
  result->setInteger("height", size.height());
  return result;
}

static std::unique_ptr<protocol::DictionaryValue> BuildObjectForSize(
    const gfx::SizeF& size) {
  std::unique_ptr<protocol::DictionaryValue> result =
      protocol::DictionaryValue::create();
  result->setDouble("width", size.width());
  result->setDouble("height", size.height());
  return result;
}

float InspectorOverlayAgent::WindowToViewportScale() const {
  LocalFrame* frame = GetFrame();
  if (!frame) {
    return 1.0f;
  }
  return frame->GetPage()->GetChromeClient().WindowToViewportScalar(frame,
                                                                    1.0f);
}

void InspectorOverlayAgent::LoadOverlayPageResource() {
  if (overlay_page_) {
    return;
  }

  ScriptForbiddenScope::AllowUserAgentScript allow_script;

  DCHECK(!overlay_chrome_client_);
  overlay_chrome_client_ = MakeGarbageCollected<InspectorOverlayChromeClient>(
      GetFrame()->GetPage()->GetChromeClient(), *this);
  overlay_page_ = Page::CreateNonOrdinary(
      *overlay_chrome_client_,
      *GetFrame()->GetFrameScheduler()->GetAgentGroupScheduler(),
      &GetFrame()->GetPage()->GetColorProviderColorMaps());
  overlay_host_ = MakeGarbageCollected<InspectorOverlayHost>(this);

  Settings& settings = GetFrame()->GetPage()->GetSettings();
  Settings& overlay_settings = overlay_page_->GetSettings();

  overlay_settings.GetGenericFontFamilySettings().UpdateStandard(
      settings.GetGenericFontFamilySettings().Standard());
  overlay_settings.GetGenericFontFamilySettings().UpdateFixed(
      settings.GetGenericFontFamilySettings().Fixed());
  overlay_settings.GetGenericFontFamilySettings().UpdateSerif(
      settings.GetGenericFontFamilySettings().Serif());
  overlay_settings.GetGenericFontFamilySettings().UpdateSansSerif(
      settings.GetGenericFontFamilySettings().SansSerif());
  overlay_settings.GetGenericFontFamilySettings().UpdateCursive(
      settings.GetGenericFontFamilySettings().Cursive());
  overlay_settings.GetGenericFontFamilySettings().UpdateFantasy(
      settings.GetGenericFontFamilySettings().Fantasy());
  overlay_settings.GetGenericFontFamilySettings().UpdateMath(
      settings.GetGenericFontFamilySettings().Math());
  overlay_settings.SetMinimumFontSize(settings.GetMinimumFontSize());
  overlay_settings.SetMinimumLogicalFontSize(
      settings.GetMinimumLogicalFontSize());
  overlay_settings.SetScriptEnabled(true);
  overlay_settings.SetPluginsEnabled(false);
  overlay_settings.SetLoadsImagesAutomatically(true);

  DEFINE_STATIC_LOCAL(Persistent<LocalFrameClient>, dummy_local_frame_client,
                      (MakeGarbageCollected<EmptyLocalFrameClient>()));
  auto* frame = MakeGarbageCollected<LocalFrame>(
      dummy_local_frame_client, *overlay_page_, nullptr, nullptr, nullptr,
      FrameInsertType::kInsertInConstructor, LocalFrameToken(), nullptr,
      nullptr, mojo::NullRemote());
  frame->SetView(MakeGarbageCollected<LocalFrameView>(*frame));
  frame->Init(/*opener=*/nullptr, DocumentToken(), /*policy_container=*/nullptr,
              StorageKey(), /*document_ukm_source_id=*/ukm::kInvalidSourceId,
              /*creator_base_url=*/KURL());
  frame->View()->SetCanHaveScrollbars(false);
  frame->View()->SetBaseBackgroundColor(Color::kTransparent);

  SegmentedBuffer data;

  data.Append("<script>", static_cast<size_t>(8));
  data.Append(UncompressResourceAsBinary(IDR_INSPECT_TOOL_MAIN_JS));
  data.Append("</script>", static_cast<size_t>(9));

  frame->ForceSynchronousDocumentInstall(AtomicString("text/html"),
                                         std::move(data));

  v8::Isolate* isolate = ToIsolate(frame);
  ScriptState* script_state = ToScriptStateForMainWorld(frame);
  DCHECK(script_state);
  ScriptState::Scope scope(script_state);
  v8::MicrotasksScope microtasks_scope(
      isolate, ToMicrotaskQueue(script_state),
      v8::MicrotasksScope::kDoNotRunMicrotasks);
  v8::Local<v8::Value> overlay_host_obj =
      ToV8Traits<InspectorOverlayHost>::ToV8(script_state, overlay_host_.Get());
  DCHECK(!overlay_host_obj.IsEmpty());
  script_state->GetContext()
      ->Global()
      ->Set(script_state->GetContext(),
            V8AtomicString(isolate, "InspectorOverlayHost"), overlay_host_obj)
      .ToChecked();

#if BUILDFLAG(IS_WIN)
  EvaluateInOverlay("setPlatform", "windows");
#elif BUILDFLAG(IS_MAC)
  EvaluateInOverlay("setPlatform", "mac");
#elif BUILDFLAG(IS_POSIX)
  EvaluateInOverlay("setPlatform", "linux");
#else
  EvaluateInOverlay("setPlatform", "other");
#endif
}

LocalFrame* InspectorOverlayAgent::OverlayMainFrame() {
  DCHECK(overlay_page_);
  return To<LocalFrame>(overlay_page_->MainFrame());
}

void InspectorOverlayAgent::Reset(
    const gfx::Size& viewport_size,
    const gfx::SizeF& viewport_size_for_media_queries) {
  std::unique_ptr<protocol::DictionaryValue> reset_data =
      protocol::DictionaryValue::create();
  reset_data->setDouble("deviceScaleFactor", WindowToViewportScale());
  reset_data->setDouble("emulationScaleFactor", EmulationScaleFactor());
  reset_data->setDouble("pageScaleFactor",
                        GetFrame()->GetPage()->GetVisualViewport().Scale());

  float physical_to_dips =
      1.f / GetFrame()->GetPage()->GetChromeClient().WindowToViewportScalar(
                GetFrame(), 1.f);
  gfx::Size viewport_size_in_dips =
      gfx::ScaleToFlooredSize(viewport_size, physical_to_dips);

  reset_data->setObject("viewportSize",
                        BuildObjectForSize(viewport_size_in_dips));
  reset_data->setObject("viewportSizeForMediaQueries",
                        BuildObjectForSize(viewport_size_for_media_queries));

  // The zoom factor in the overlay frame already has been multiplied by the
  // window to viewport scale (aka device scale factor), so cancel it.
  reset_data->setDouble("pageZoomFactor", GetFrame()->LayoutZoomFactor() /
                                              WindowToViewportScale());

  // TODO(szager): These values have been zero since root layer scrolling
  // landed. Probably they should be derived from
  // LocalFrameView::LayoutViewport(); but I have no idea who the consumers
  // of these values are, so I'm leaving them zero pending investigation.
  reset_data->setInteger("scrollX", 0);
  reset_data->setInteger("scrollY", 0);
  EvaluateInOverlay("reset", std::move(reset_data));
}

void InspectorOverlayAgent::EvaluateInOverlay(const String& method,
                                              const String& argument) {
  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  v8::HandleScope handle_scope(ToIsolate(OverlayMainFrame()));

  LocalFrame* local_frame = To<LocalFrame>(OverlayMainFrame());
  ScriptState* script_state = ToScriptStateForMainWorld(local_frame);
  DCHECK(script_state);

  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Context::Scope context_scope(context);

  v8::LocalVector<v8::Value> args(context->GetIsolate());
  int args_length = 2;
  v8::Local<v8::Array> params(
      v8::Array::New(context->GetIsolate(), args_length));
  v8::Local<v8::Value> local_method(V8String(context->GetIsolate(), method));
  v8::Local<v8::Value> local_argument(
      V8String(context->GetIsolate(), argument));
  params->CreateDataProperty(context, 0, local_method).Check();
  params->CreateDataProperty(context, 1, local_argument).Check();
  args.push_back(params);

  v8::Local<v8::Value> v8_method;
  if (!GetV8Property(context, context->Global(), "dispatch")
           .ToLocal(&v8_method) ||
      v8_method->IsUndefined()) {
    return;
  }

  local_frame->DomWindow()->GetScriptController().EvaluateMethodInMainWorld(
      v8::Local<v8::Function>::Cast(v8_method), context->Global(),
      static_cast<int>(args.size()), args.data());
}

void InspectorOverlayAgent::EvaluateInOverlay(
    const String& method,
    std::unique_ptr<protocol::Value> argument) {
  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  std::unique_ptr<protocol::ListValue> command = protocol::ListValue::create();
  command->pushValue(protocol::StringValue::create(method));
  command->pushValue(std::move(argument));
  std::vector<uint8_t> json;
  ConvertCBORToJSON(SpanFrom(command->Serialize()), &json);
  ClassicScript::CreateUnspecifiedScript(
      "dispatch(" + String(base::span(json)) + ")",
      ScriptSourceLocationType::kInspector)
      ->RunScript(To<LocalFrame>(OverlayMainFrame())->DomWindow(),
                  ExecuteScriptPolicy::kExecuteScriptWhenScriptsDisabled);
}

String InspectorOverlayAgent::EvaluateInOverlayForTest(const String& script) {
  ScriptForbiddenScope::AllowUserAgentScript allow_script;
  v8::Isolate* isolate = ToIsolate(OverlayMainFrame());
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::Value> string =
      ClassicScript::CreateUnspecifiedScript(
          script, ScriptSourceLocationType::kInspector)
          ->RunScriptAndReturnValue(
              To<LocalFrame>(OverlayMainFrame())->DomWindow(),
              ExecuteScriptPolicy::kExecuteScriptWhenScriptsDisabled)
          .GetSuccessValueOrEmpty();
  return ToCoreStringWithUndefinedOrNullCheck(isolate, string);
}

void InspectorOverlayAgent::OnResizeTimer(TimerBase*) {
  if (resize_timer_active_) {
    // Restore the original tool.
    PickTheRightTool();
    return;
  }

  // Show the resize tool.
  SetInspectTool(MakeGarbageCollected<ShowViewSizeTool>(this, GetFrontend()));
  resize_timer_active_ = true;
  resize_timer_.Stop();
  resize_timer_.StartOneShot(base::Seconds(1), FROM_HERE);
}

void InspectorOverlayAgent::Dispatch(const ScriptValue& message,
                                     ExceptionState& exception_state) {
  inspect_tool_->Dispatch(message, exception_state);
}

void InspectorOverlayAgent::PageLayoutInvalidated(bool resized) {
  if (resized && show_size_on_resize_.Get()) {
    resize_timer_active_ = false;
    // Handle the resize in the next cycle to decouple overlay page rebuild from
    // the main page layout to avoid document lifecycle issues caused by
    // EventLoop::PerformCheckpoint() called when we rebuild the overlay page.
    resize_timer_.Stop();
    resize_timer_.StartOneShot(base::Seconds(0), FROM_HERE);
    return;
  }
  ScheduleUpdate();
}

protocol::Response InspectorOverlayAgent::CompositingEnabled() {
  bool main_frame = frame_impl_->ViewImpl() && !frame_impl_->Parent();
  if (!main_frame || !frame_impl_->ViewImpl()
                          ->GetPage()
                          ->GetSettings()
                          .GetAcceleratedCompositingEnabled()) {
    return protocol::Response::ServerError("Compositing mode is not supported");
  }
  return protocol::Response::Success();
}

bool InspectorOverlayAgent::InSomeInspectMode() {
  return inspect_mode_.Get() != protocol::Overlay::InspectModeEnum::None;
}

void InspectorOverlayAgent::Inspect(Node* inspected_node) {
  if (!inspected_node) {
    return;
  }

  Node* node = inspected_node;
  while (node && !node->IsElementNode() && !node->IsDocumentNode() &&
         !node->IsDocumentFragment()) {
    node = node->ParentOrShadowHostNode();
  }
  if (!node) {
    return;
  }

  DOMNodeId backend_node_id = node->GetDomNodeId();
  if (!enabled_.Get()) {
    backend_node_id_to_inspect_ = backend_node_id;
    return;
  }

  GetFrontend()->inspectNodeRequested(IdentifiersFactory::IntIdForNode(node));
}

protocol::Response InspectorOverlayAgent::setInspectMode(
    const String& mode,
    Maybe<protocol::Overlay::HighlightConfig> highlight_inspector_object) {
  if (mode != protocol::Overlay::InspectModeEnum::None &&
      mode != protocol::Overlay::InspectModeEnum::SearchForNode &&
      mode != protocol::Overlay::InspectModeEnum::SearchForUAShadowDOM &&
      mode != protocol::Overlay::InspectModeEnum::CaptureAreaScreenshot &&
      mode != protocol::Overlay::InspectModeEnum::ShowDistances) {
    return protocol::Response::ServerError(
        String("Unknown mode \"" + mode + "\" was provided.").Utf8());
  }

  std::vector<uint8_t> serialized_config;
  if (highlight_inspector_object) {
    highlight_inspector_object->AppendSerialized(&serialized_config);
  }
  std::unique_ptr<InspectorHighlightConfig> config;
  protocol::Response response = HighlightConfigFromInspectorObject(
      std::move(highlight_inspector_object), &config);
  if (!response.IsSuccess()) {
    return response;
  }
  inspect_mode_.Set(mode);
  inspect_mode_protocol_config_.Set(serialized_config);
  PickTheRightTool();
  return protocol::Response::Success();
}

void InspectorOverlayAgent::PickTheRightTool() {
  InspectTool* inspect_tool = nullptr;

  if (persistent_tool_ && persistent_tool_->IsEmpty()) {
    persistent_tool_ = nullptr;
  }

  String inspect_mode = inspect_mode_.Get();
  if (inspect_mode == protocol::Overlay::InspectModeEnum::SearchForNode ||
      inspect_mode ==
          protocol::Overlay::InspectModeEnum::SearchForUAShadowDOM) {
    inspect_tool = MakeGarbageCollected<SearchingForNodeTool>(
        this, GetFrontend(), dom_agent_,
        inspect_mode ==
            protocol::Overlay::InspectModeEnum::SearchForUAShadowDOM,
        inspect_mode_protocol_config_.Get());
  } else if (inspect_mode ==
             protocol::Overlay::InspectModeEnum::CaptureAreaScreenshot) {
    inspect_tool = MakeGarbageCollected<ScreenshotTool>(this, GetFrontend());
  } else if (inspect_mode ==
             protocol::Overlay::InspectModeEnum::ShowDistances) {
    inspect_tool =
        MakeGarbageCollected<NearbyDistanceTool>(this, GetFrontend());
  } else if (!paused_in_debugger_message_.Get().IsNull()) {
    inspect_tool = MakeGarbageCollected<PausedInDebuggerTool>(
        this, GetFrontend(), v8_session_, paused_in_debugger_message_.Get());
  } else if (persistent_tool_) {
    inspect_tool = persistent_tool_;
  }

  SetInspectTool(inspect_tool);
}

void InspectorOverlayAgent::DisableFrameOverlay() {
  if (IsVisible() || !frame_overlay_) {
    return;
  }

  frame_overlay_.Release()->Destroy();
  auto& client = GetFrame()->GetPage()->GetChromeClient();
  client.SetCursorOverridden(false);
  client.SetCursor(PointerCursor(), GetFrame());

  if (auto* frame_view = frame_impl_->GetFrameView()) {
    frame_view->SetPaintArtifactCompositorNeedsUpdate();
  }
}

void InspectorOverlayAgent::EnsureEnableFrameOverlay() {
  if (frame_overlay_) {
    return;
  }

  frame_overlay_ = MakeGarbageCollected<FrameOverlay>(
      GetFrame(), std::make_unique<InspectorPageOverlayDelegate>(*this));
}

void InspectorOverlayAgent::ClearInspectTool() {
  inspect_tool_ = nullptr;
  if (!hinge_) {
    DisableFrameOverlay();
  }
}

protocol::Response InspectorOverlayAgent::SetInspectTool(
    InspectTool* inspect_tool) {
  ClearInspectTool();

  if (!inspect_tool) {
    return protocol::Response::Success();
  }

  if (!enabled_.Get()) {
    return protocol::Response::InvalidRequest(
        "Overlay must be enabled before a tool can be shown");
  }

  LocalFrameView* view = frame_impl_->GetFrameView();
  LocalFrame* frame = GetFrame();
  if (!view || !frame) {
    return protocol::Response::InternalError();
  }

  inspect_tool_ = inspect_tool;
  // If the tool supports persistent overlays, the resources of the persistent
  // tool will be included into the JS resource.
  LoadOverlayPageResource();
  EvaluateInOverlay("setOverlay", inspect_tool->GetOverlayName());
  EnsureEnableFrameOverlay();
  EnsureAXContext(frame->GetDocument());
  ScheduleUpdate();
  return protocol::Response::Success();
}

InspectorSourceOrderConfig
InspectorOverlayAgent::SourceOrderConfigFromInspectorObject(
    std::unique_ptr<protocol::Overlay::SourceOrderConfig>
        source_order_inspector_object) {
  InspectorSourceOrderConfig source_order_config = InspectorSourceOrderConfig();
  source_order_config.parent_outline_color =
      ParseColor(source_order_inspector_object->getParentOutlineColor());
  source_order_config.child_outline_color =
      ParseColor(source_order_inspector_object->getChildOutlineColor());

  return source_order_config;
}

protocol::Response InspectorOverlayAgent::HighlightConfigFromInspectorObject(
    Maybe<protocol::Overlay::HighlightConfig> highlight_inspector_object,
    std::unique_ptr<InspectorHighlightConfig>* out_config) {
  if (!highlight_inspector_object) {
    return protocol::Response::ServerError(
        "Internal error: highlight configuration parameter is missing");
  }

  protocol::Overlay::HighlightConfig& config = *highlight_inspector_object;

  String format = config.getColorFormat("hex");

  namespace ColorFormatEnum = protocol::Overlay::ColorFormatEnum;
  if (format != ColorFormatEnum::Rgb && format != ColorFormatEnum::Hex &&
      format != ColorFormatEnum::Hsl && format != ColorFormatEnum::Hwb) {
    return protocol::Response::InvalidParams("Unknown color format");
  }

  *out_config = InspectorOverlayAgent::ToHighlightConfig(&config);
  return protocol::Response::Success();
}

// static
std::unique_ptr<InspectorGridHighlightConfig>
InspectorOverlayAgent::ToGridHighlightConfig(
    protocol::Overlay::GridHighlightConfig* config) {
  if (!config) {
    return nullptr;
  }
  std::unique_ptr<InspectorGridHighlightConfig> highlight_config =
      std::make_unique<InspectorGridHighlightConfig>();
  highlight_config->show_positive_line_numbers =
      config->getShowPositiveLineNumbers(false);
  highlight_config->show_negative_line_numbers =
      config->getShowNegativeLineNumbers(false);
  highlight_config->show_area_names = config->getShowAreaNames(false);
  highlight_config->show_line_names = config->getShowLineNames(false);
  highlight_config->show_grid_extension_lines =
      config->getShowGridExtensionLines(false);
  highlight_config->grid_border_dash = config->getGridBorderDash(false);

  // cellBorderDash is deprecated. We only use it if defined and none of the new
  // properties are.
  bool hasLegacyBorderDash = !config->hasRowLineDash() &&
                             !config->hasColumnLineDash() &&
                             config->hasCellBorderDash();
  highlight_config->row_line_dash = hasLegacyBorderDash
                                        ? config->getCellBorderDash(false)
                                        : config->getRowLineDash(false);
  highlight_config->column_line_dash = hasLegacyBorderDash
                                           ? config->getCellBorderDash(false)
                                           : config->getColumnLineDash(false);

  highlight_config->show_track_sizes = config->getShowTrackSizes(false);
  highlight_config->grid_color =
      ParseColor(config->getGridBorderColor(nullptr));

  // cellBorderColor is deprecated. We only use it if defined and none of the
  // new properties are.
  bool hasLegacyBorderColors = !config->hasRowLineColor() &&
                               !config->hasColumnLineColor() &&
                               config->hasCellBorderColor();
  highlight_config->row_line_color =
      hasLegacyBorderColors ? ParseColor(config->getCellBorderColor(nullptr))
                            : ParseColor(config->getRowLineColor(nullptr));
  highlight_config->column_line_color =
      hasLegacyBorderColors ? ParseColor(config->getCellBorderColor(nullptr))
                            : ParseColor(config->getColumnLineColor(nullptr));

  highlight_config->row_gap_color = ParseColor(config->getRowGapColor(nullptr));
  highlight_config->column_gap_color =
      ParseColor(config->getColumnGapColor(nullptr));
  highlight_config->row_hatch_color =
      ParseColor(config->getRowHatchColor(nullptr));
  highlight_config->column_hatch_color =
      ParseColor(config->getColumnHatchColor(nullptr));
  highlight_config->area_border_color =
      ParseColor(config->getAreaBorderColor(nullptr));
  highlight_config->grid_background_color =
      ParseColor(config->getGridBackgroundColor(nullptr));
  return highlight_config;
}

// static
std::unique_ptr<InspectorFlexContainerHighlightConfig>
InspectorOverlayAgent::ToFlexContainerHighlightConfig(
    protocol::Overlay::FlexContainerHighlightConfig* config) {
  if (!config) {
    return nullptr;
  }
  std::unique_ptr<InspectorFlexContainerHighlightConfig> highlight_config =
```
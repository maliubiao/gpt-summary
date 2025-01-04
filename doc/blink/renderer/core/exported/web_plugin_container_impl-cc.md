Response:
The user wants a summary of the functionality of the `web_plugin_container_impl.cc` file in the Chromium Blink engine, along with explanations and examples of its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning, common user errors, and debugging clues. Since this is part 1 of 2, I need to focus on the overall function and high-level interactions for this part.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Function:** The filename `web_plugin_container_impl.cc` and the initial comments clearly indicate that this file is responsible for managing and representing embedded web plugins within the Blink rendering engine. It acts as a bridge between the browser's plugin system and the web content.

2. **Extract Key Interactions from Includes:**  The included header files provide significant clues about the file's responsibilities. I will look for patterns and categorize them:
    * **Plugin Interaction:** `web_plugin.h` is a direct indicator.
    * **Input Handling:**  Headers like `WebInputEvent.h`, `MouseEvent.h`, `KeyboardEvent.h`, `TouchEvent.h`, `WheelEvent.h`, and `DragEvent.h` point to input event processing.
    * **Rendering and Layout:**  `GraphicsContext.h`, `LayoutBox.h`, `PaintLayer.h`, `DisplayItem.h` are related to how the plugin is rendered and positioned on the page.
    * **Frame and Document Context:** `WebLocalFrame.h`, `WebDocument.h`, `LocalFrame.h`, `Document.h` indicate the plugin's integration within the document structure.
    * **Scripting:**  `v8_binding_for_core.h`, `V8Element.h` suggest interactions with JavaScript.
    * **Clipboard:** `Clipboard_utilities.h`, `DataTransfer.h`, `SystemClipboard.h` relate to copy/paste functionality.
    * **Fullscreen and Pointer Lock:** `Fullscreen.h`, `PointerLockController.h` indicate support for these features.
    * **Printing:** `WebPrintParams.h`, `WebPrintPresetOptions.h` suggest printing capabilities.
    * **Navigation:** `WebURLRequest.h`, `FrameLoadRequest.h` hint at navigation initiated by the plugin.

3. **Categorize Functionality based on Includes and Code Structure:** Based on the included headers and a quick skim of the code (even without fully understanding every line), I can identify major functional areas:
    * **Lifecycle Management:** Attaching, detaching, showing, hiding the plugin.
    * **Rendering:** Painting the plugin content on the screen, handling compositing.
    * **Event Handling:**  Processing various input events (mouse, keyboard, touch, wheel, drag) and forwarding them to the plugin.
    * **Focus Management:** Handling focus and input.
    * **Communication with Plugin:** Sending updates about geometry, visibility, and other events. Receiving results from the plugin (e.g., mouse lock).
    * **Integration with Browser Features:** Supporting copy/paste, find in page, fullscreen, pointer lock, printing.
    * **JavaScript Interaction:** Providing a scriptable object for the plugin.
    * **Navigation:**  Allowing plugins to initiate frame navigation.

4. **Relate Functionality to Web Technologies:**
    * **HTML:** The plugin is embedded within an HTML element (`<embed>`, `<object>`, or `<applet>`). The container manages the rendering and interaction within the bounds defined by this HTML element.
    * **CSS:** CSS affects the layout and positioning of the plugin element, which in turn is reflected in the geometry updates sent to the plugin.
    * **JavaScript:** JavaScript can interact with the plugin through the scriptable object provided by this container. It can also trigger actions that affect the plugin (e.g., focusing, making it fullscreen).

5. **Consider Logical Reasoning:** The code involves decision-making based on events, states, and plugin capabilities. I can create hypothetical scenarios to illustrate these:
    * *Input:* User clicks inside the plugin area. *Output:*  The `HandleMouseEvent` function is called, and the event is forwarded to the plugin.
    * *Input:* User requests fullscreen on the plugin. *Output:* The `RequestFullscreen` function calls the appropriate Blink fullscreen API.

6. **Identify Potential User/Programming Errors:**  Based on the file's function, some common errors include:
    * Incorrectly sizing the plugin element in HTML/CSS.
    * Assuming the plugin will handle events without proper configuration.
    * Not handling asynchronous operations correctly when communicating with the plugin.

7. **Trace User Operations:**  Think about how a user action leads to this code being executed:
    * The user opens a web page containing a plugin.
    * Blink parses the HTML and creates an `HTMLPlugInElement`.
    * The `WebPluginContainerImpl` is created to manage this element.
    * As the page renders and the user interacts, various functions in this file are called.

8. **Formulate the Summary for Part 1:**  Based on the above analysis, I will synthesize a concise summary of the file's primary role as an intermediary between the browser and the plugin, highlighting its key responsibilities.

By following these steps, I can construct a comprehensive and informative answer that addresses all aspects of the user's request for part 1.
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 * Copyright (C) 2014 Opera Software ASA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"

// ... (many includes) ...

namespace blink {

namespace {

#if BUILDFLAG(IS_MAC)
const WebInputEvent::Modifiers kEditingModifier = WebInputEvent::kMetaKey;
#else
const WebInputEvent::Modifiers kEditingModifier = WebInputEvent::kControlKey;
#endif

}  // namespace

// ... (MouseLockLostListener class) ...

// Public methods --------------------------------------------------------------

void WebPluginContainerImpl::AttachToLayout() {
  // ...
}

void WebPluginContainerImpl::DetachFromLayout() {
  // ...
}

void WebPluginContainerImpl::UpdateAllLifecyclePhases() {
  // ...
}

void WebPluginContainerImpl::Paint(GraphicsContext& context,
                                   PaintFlags,
                                   const CullRect& cull_rect,
                                   const gfx::Vector2d& paint_offset) const {
  // ...
}

void WebPluginContainerImpl::UpdateGeometry() {
  // ...
}

void WebPluginContainerImpl::Invalidate() {
  // ...
}

void WebPluginContainerImpl::SetFocused(bool focused,
                                        mojom::blink::FocusType focus_type) {
  // ...
}

bool WebPluginContainerImpl::IsErrorplaceholder() {
  // ...
}

void WebPluginContainerImpl::Show() {
  // ...
}

void WebPluginContainerImpl::Hide() {
  // ...
}

void WebPluginContainerImpl::HandleEvent(Event& event) {
  // ...
}

void WebPluginContainerImpl::EventListenersRemoved() {
  // ...
}

void WebPluginContainerImpl::ParentVisibleChanged() {
  // ...
}

void WebPluginContainerImpl::SetPlugin(WebPlugin* plugin) {
  // ...
}

void WebPluginContainerImpl::UsePluginAsFindHandler() {
  // ...
}

void WebPluginContainerImpl::ReportFindInPageMatchCount(int identifier,
                                                        int total,
                                                        bool final_update) {
  // ...
}

void WebPluginContainerImpl::ReportFindInPageSelection(int identifier,
                                                       int index,
                                                       bool final_update) {
  // ...
}

float WebPluginContainerImpl::PageScaleFactor() {
  // ...
}

float WebPluginContainerImpl::LayoutZoomFactor() {
  // ...
}

void WebPluginContainerImpl::SetCcLayer(cc::Layer* new_layer) {
  // ...
}

void WebPluginContainerImpl::RequestFullscreen() {
  // ...
}

bool WebPluginContainerImpl::IsFullscreenElement() const {
  // ...
}

void WebPluginContainerImpl::CancelFullscreen() {
  // ...
}

bool WebPluginContainerImpl::IsMouseLocked() {
  // ...
}

bool WebPluginContainerImpl::LockMouse(bool request_unadjusted_movement) {
  // ...
}

void WebPluginContainerImpl::UnlockMouse() {
  // ...
}

void WebPluginContainerImpl::HandleLockMouseResult(
    mojom::blink::PointerLockResult result) {
  // ...
}

void WebPluginContainerImpl::MaybeLostMouseLock() {
  // ...
}

bool WebPluginContainerImpl::SupportsPaginatedPrint() const {
  // ...
}

bool WebPluginContainerImpl::GetPrintPresetOptionsFromDocument(
    WebPrintPresetOptions* preset_options) const {
  // ...
}

int WebPluginContainerImpl::PrintBegin(
    const WebPrintParams& print_params) const {
  // ...
}

void WebPluginContainerImpl::PrintPage(int page_index, GraphicsContext& gc) {
  // ...
}

void WebPluginContainerImpl::PrintEnd() {
  // ...
}

void WebPluginContainerImpl::Copy() {
  // ...
}

bool WebPluginContainerImpl::ExecuteEditCommand(const WebString& name) {
  // ...
}

bool WebPluginContainerImpl::ExecuteEditCommand(const WebString& name,
                                                const WebString& value) {
  // ...
}

// static
bool WebPluginContainerImpl::SupportsCommand(const WebString& name) {
  // ...
}

WebElement WebPluginContainerImpl::GetElement() {
  // ...
}

WebDocument WebPluginContainerImpl::GetDocument() {
  // ...
}

void WebPluginContainerImpl::DispatchProgressEvent(const WebString& type,
                                                   bool length_computable,
                                                   uint64_t loaded,
                                                   uint64_t total,
                                                   const WebString& url) {
  // ...
}

void WebPluginContainerImpl::EnqueueMessageEvent(
    const WebDOMMessageEvent& event) {
  // ...
}

void WebPluginContainerImpl::ScheduleAnimation() {
  // ...
}

void WebPluginContainerImpl::ReportGeometry() {
  // ...
}

v8::Local<v8::Object> WebPluginContainerImpl::V8ObjectForElement() {
  // ...
}

void WebPluginContainerImpl::LoadFrameRequest(const WebURLRequest& request,
                                              const WebString& target) {
  // ...
}

bool WebPluginContainerImpl::IsRectTopmost(const gfx::Rect& rect) {
  // ...
}

void WebPluginContainerImpl::RequestTouchEventType(
    TouchEventRequestType request_type) {
  // ...
}

void WebPluginContainerImpl::SetWantsWheelEvents(bool wants_wheel_events) {
  // ...
}

gfx::Point WebPluginContainerImpl::RootFrameToLocalPoint(
    const gfx::Point& point_in_root_frame) {
  // ...
}

gfx::Point WebPluginContainerImpl::LocalToRootFramePoint(
    const gfx::Point& point_in_local) {
  // ...
}

bool WebPluginContainerImpl::WasTargetForLastMouseEvent() {
  // ...
}

void WebPluginContainerImpl::DidReceiveResponse(
    const ResourceResponse& response) {
  // ...
}

void WebPluginContainerImpl::DidReceiveData(base::span<const char> data) {
  // ...
}

void WebPluginContainerImpl::DidFinishLoading() {
  // ...
}

void WebPluginContainerImpl::DidFailLoading(const ResourceError& error) {
  // ...
}

cc::Layer* WebPluginContainerImpl::CcLayer() const {
  // ...
}

v8::Local<v8::Object> WebPluginContainerImpl::ScriptableObject(
    v8::Isolate* isolate) {
  // ...
}

bool WebPluginContainerImpl::SupportsKeyboardFocus() const {
  // ...
}

bool WebPluginContainerImpl::SupportsInputMethod() const {
  // ...
}

bool WebPluginContainerImpl::CanProcessDrag() const {
  // ...
}

bool WebPluginContainerImpl::WantsWheelEvents() const {
  // ...
}

// Private methods -------------------------------------------------------------

WebPluginContainerImpl::WebPluginContainerImpl(HTMLPlugInElement& element,
                                               WebPlugin* web_plugin)
    : EmbeddedContentView(gfx::Rect()),
      element_(element),
      web_plugin_(web_plugin) {}

WebPluginContainerImpl::~WebPluginContainerImpl() {
  // ...
}

LocalFrameView* WebPluginContainerImpl::ParentFrameView() const {
  // ...
}

LayoutEmbeddedContent* WebPluginContainerImpl::GetLayoutEmbeddedContent()
    const {
  // ...
}

void WebPluginContainerImpl::Dispose() {
  // ...
}

void WebPluginContainerImpl::SetFrameRect(const gfx::Rect& rect) {
  // ...
}

void WebPluginContainerImpl::Trace(Visitor* visitor) const {
  // ...
}

void WebPluginContainerImpl::HandleMouseEvent(MouseEvent& event) {
  // ...
}

void WebPluginContainerImpl::HandleDragEvent(MouseEvent& event) {
  // ...
}
```

## 功能归纳 (第 1 部分)

总的来说，`blink/renderer/core/exported/web_plugin_container_impl.cc` 文件的主要功能是**作为 Chromium Blink 引擎中嵌入式 Web 插件的容器和代理**。 它负责管理插件的生命周期、渲染、事件处理以及与浏览器其他组件的交互。

更具体地说，从提供的代码片段来看，这个文件的功能可以归纳为以下几点：

1. **插件生命周期管理:**
   -  负责插件的 **AttachToLayout** 和 **DetachFromLayout**，控制插件在渲染树中的存在。
   -  通过 **UpdateAllLifecyclePhases** 更新插件的生命周期阶段。
   -  在不再需要时，通过 **Dispose** 清理和销毁插件。

2. **插件渲染和显示:**
   -  使用 **Paint** 方法将插件的内容绘制到屏幕上，考虑裁剪区域 (**CullRect**) 和偏移量。
   -  通过 **UpdateGeometry** 通知插件其在页面上的位置和大小。
   -  使用 **Invalidate** 通知渲染引擎插件需要重绘。
   -  处理插件的显示和隐藏 (**Show**, **Hide**)，并通过 **ParentVisibleChanged** 感知父元素的可见性变化。
   -  支持硬件加速渲染，通过 **SetCcLayer** 管理插件的合成层 (**cc::Layer**)。

3. **事件处理:**
   -  作为插件的事件接收器，通过 **HandleEvent** 分发各种浏览器事件 (例如鼠标事件、键盘事件、触摸事件、拖拽事件) 给插件。
   -  针对不同类型的事件有专门的处理函数，例如 **HandleMouseEvent**, **HandleDragEvent** (尽管 `HandleDragEvent` 的代码在提供的片段中不完整)。
   -  处理插件的焦点 (**SetFocused**)。
   -  允许插件请求特定类型的触摸事件 (**RequestTouchEventType**) 和声明是否需要接收滚轮事件 (**SetWantsWheelEvents**)。

4. **与浏览器功能的集成:**
   -  支持插件参与页面查找功能 (**UsePluginAsFindHandler**, **ReportFindInPageMatchCount**, **ReportFindInPageSelection**)。
   -  处理插件的缩放 (**PageScaleFactor**, **LayoutZoomFactor**)。
   -  支持插件进入和退出全屏模式 (**RequestFullscreen**, **IsFullscreenElement**, **CancelFullscreen**)。
   -  处理鼠标锁定功能 (**IsMouseLocked**, **LockMouse**, **UnlockMouse**, **HandleLockMouseResult**, **MaybeLostMouseLock**)。
   -  支持插件的打印功能 (**SupportsPaginatedPrint**, **GetPrintPresetOptionsFromDocument**, **PrintBegin**, **PrintPage**, **PrintEnd**)。
   -  实现插件的复制 (**Copy**) 和执行编辑命令 (**ExecuteEditCommand**, **SupportsCommand**)。

5. **JavaScript 交互:**
   -  通过 **V8ObjectForElement** 和 **ScriptableObject** 提供插件的 JavaScript 可访问接口。
   -  允许插件调度进度事件 (**DispatchProgressEvent**) 和入队消息事件 (**EnqueueMessageEvent**)，以便与 JavaScript 代码通信。

6. **导航和资源加载:**
   -  允许插件发起新的框架加载请求 (**LoadFrameRequest**)。
   -  处理插件加载资源时的响应、数据和完成/失败状态 (**DidReceiveResponse**, **DidReceiveData**, **DidFinishLoading**, **DidFailLoading**)。

7. **坐标转换:**
   -  提供在插件局部坐标和根框架坐标之间转换的方法 (**RootFrameToLocalPoint**, **LocalToRootFramePoint**)。

简而言之，`WebPluginContainerImpl` 是一个关键的组件，它封装了嵌入式插件的复杂性，并将其无缝集成到 Blink 的渲染和事件处理管道中。 它充当了插件和浏览器之间的中介，确保插件能够正确显示、接收用户输入并与页面上的其他元素交互。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_plugin_container_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 * Copyright (C) 2014 Opera Software ASA. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"

#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_coalesced_input_event.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_dom_message_event.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_print_preset_options.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/events/drag_event.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/progress_event.h"
#include "third_party/blink/renderer/core/events/resource_progress_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"

namespace blink {

namespace {

#if BUILDFLAG(IS_MAC)
const WebInputEvent::Modifiers kEditingModifier = WebInputEvent::kMetaKey;
#else
const WebInputEvent::Modifiers kEditingModifier = WebInputEvent::kControlKey;
#endif

}  // namespace

class WebPluginContainerImpl::MouseLockLostListener final
    : public NativeEventListener {
 public:
  explicit MouseLockLostListener(WebPluginContainerImpl* plugin_container)
      : plugin_container_(plugin_container) {}

  void Disconnect() { plugin_container_ = nullptr; }

  void Invoke(ExecutionContext*, Event*) override {
    if (!plugin_container_)
      return;
    plugin_container_->MaybeLostMouseLock();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(plugin_container_);
    NativeEventListener::Trace(visitor);
  }

 private:
  Member<WebPluginContainerImpl> plugin_container_;
};

// Public methods --------------------------------------------------------------

void WebPluginContainerImpl::AttachToLayout() {
  DCHECK(!IsAttached());
  SetAttached(true);
  SetParentVisible(true);
}

void WebPluginContainerImpl::DetachFromLayout() {
  DCHECK(IsAttached());
  SetParentVisible(false);
  SetAttached(false);
}

void WebPluginContainerImpl::UpdateAllLifecyclePhases() {
  if (!web_plugin_)
    return;

  web_plugin_->UpdateAllLifecyclePhases(DocumentUpdateReason::kPlugin);
}

void WebPluginContainerImpl::Paint(GraphicsContext& context,
                                   PaintFlags,
                                   const CullRect& cull_rect,
                                   const gfx::Vector2d& paint_offset) const {
  // Don't paint anything if the plugin doesn't intersect.
  if (!cull_rect.Intersects(FrameRect()))
    return;

  gfx::Rect visual_rect = FrameRect();
  visual_rect.Offset(paint_offset);

  if (WantsWheelEvents()) {
    context.GetPaintController().RecordHitTestData(
        *GetLayoutEmbeddedContent(), visual_rect, TouchAction::kAuto,
        /*blocking_wheel=*/true, cc::HitTestOpaqueness::kMixed,
        DisplayItem::kWebPluginHitTest);
  }

  if (element_->GetRegionCaptureCropId()) {
    context.GetPaintController().RecordRegionCaptureData(
        *GetLayoutEmbeddedContent(), *(element_->GetRegionCaptureCropId()),
        visual_rect);
  }

  if (layer_) {
    layer_->SetBounds(Size());
    layer_->SetIsDrawable(true);
    layer_->SetHitTestable(true);
    // Composited plugins should have their layers inserted rather than invoking
    // WebPlugin::paint.
    RecordForeignLayer(context, *element_->GetLayoutObject(),
                       DisplayItem::kForeignLayerPlugin, layer_,
                       FrameRect().origin() + paint_offset);
    return;
  }

  if (DrawingRecorder::UseCachedDrawingIfPossible(
          context, *element_->GetLayoutObject(), DisplayItem::kWebPlugin))
    return;

  DrawingRecorder recorder(context, *element_->GetLayoutObject(),
                           DisplayItem::kWebPlugin, visual_rect);
  context.Save();

  // The plugin is positioned in the root frame's coordinates, so it needs to
  // be painted in them too.
  gfx::PointF origin(ParentFrameView()->ConvertToRootFrame(gfx::Point()));
  origin -= gfx::Vector2dF(paint_offset);
  context.Translate(-origin.x(), -origin.y());

  cc::PaintCanvas* canvas = context.Canvas();

  gfx::Rect window_rect =
      ParentFrameView()->ConvertToRootFrame(cull_rect.Rect());
  web_plugin_->Paint(canvas, window_rect);

  context.Restore();
}

void WebPluginContainerImpl::UpdateGeometry() {
  if (LayoutEmbeddedContent* layout = GetLayoutEmbeddedContent())
    layout->UpdateGeometry(*this);
}

void WebPluginContainerImpl::Invalidate() {
  // This can be called from Dispose when this plugin is no longer attached.
  // In this case, we return immediately.
  if (!IsAttached())
    return;

  if (auto* layout_object = element_->GetLayoutObject())
    layout_object->SetShouldDoFullPaintInvalidation();
}

void WebPluginContainerImpl::SetFocused(bool focused,
                                        mojom::blink::FocusType focus_type) {
  web_plugin_->UpdateFocus(focused, focus_type);
}

bool WebPluginContainerImpl::IsErrorplaceholder() {
  if (!web_plugin_)
    return false;
  return web_plugin_->IsErrorPlaceholder();
}

void WebPluginContainerImpl::Show() {
  SetSelfVisible(true);
  web_plugin_->UpdateVisibility(true);
}

void WebPluginContainerImpl::Hide() {
  SetSelfVisible(false);
  web_plugin_->UpdateVisibility(false);
}

void WebPluginContainerImpl::HandleEvent(Event& event) {
  // The events we pass are defined at:
  //    http://devedge-temp.mozilla.org/library/manuals/2002/plugin/1.0/structures5.html#1000000
  // Don't take the documentation as truth, however.  There are many cases
  // where mozilla behaves differently than the spec.
  if (auto* mouse_event = DynamicTo<MouseEvent>(event)) {
    HandleMouseEvent(*mouse_event);
  } else if (auto* wheel_event = DynamicTo<WheelEvent>(event)) {
    HandleWheelEvent(*wheel_event);
  } else if (auto* keyboard_event = DynamicTo<KeyboardEvent>(event)) {
    HandleKeyboardEvent(*keyboard_event);
  } else if (auto* touch_event = DynamicTo<TouchEvent>(event)) {
    HandleTouchEvent(*touch_event);
  } else if (auto* gesture_event = DynamicTo<GestureEvent>(event)) {
    HandleGestureEvent(*gesture_event);
  } else if (auto* drag_event = DynamicTo<DragEvent>(event);
             drag_event && web_plugin_->CanProcessDrag()) {
    HandleDragEvent(*drag_event);
  }

  // FIXME: it would be cleaner if EmbeddedContentView::HandleEvent returned
  // true/false and HTMLPluginElement called SetDefaultHandled or
  // DefaultEventHandler.
  if (!event.DefaultHandled())
    element_->Node::DefaultEventHandler(event);
}

void WebPluginContainerImpl::EventListenersRemoved() {
  // We're no longer registered to receive touch events, so don't try to remove
  // the touch event handlers in our destructor.
  touch_event_request_type_ = kTouchEventRequestTypeNone;
}

void WebPluginContainerImpl::ParentVisibleChanged() {
  // We override this function to make sure that geometry updates are sent
  // over to the plugin. For e.g. when a plugin is instantiated it does not
  // have a valid parent. As a result the first geometry update is ignored. This
  // function is called when the plugin eventually gets a parent.
  if (web_plugin_ && IsSelfVisible())
    web_plugin_->UpdateVisibility(IsVisible());
}

void WebPluginContainerImpl::SetPlugin(WebPlugin* plugin) {
  if (plugin == web_plugin_)
    return;

  element_->ResetInstance();
  web_plugin_ = plugin;
}

void WebPluginContainerImpl::UsePluginAsFindHandler() {
  WebLocalFrameImpl* frame =
      WebLocalFrameImpl::FromFrame(element_->GetDocument().GetFrame());
  if (!frame)
    return;
  frame->GetFindInPage()->SetPluginFindHandler(this);
}

void WebPluginContainerImpl::ReportFindInPageMatchCount(int identifier,
                                                        int total,
                                                        bool final_update) {
  WebLocalFrameImpl* frame =
      WebLocalFrameImpl::FromFrame(element_->GetDocument().GetFrame());
  if (!frame)
    return;

  frame->GetFindInPage()->ReportFindInPageMatchCount(identifier, total,
                                                     final_update);
}

void WebPluginContainerImpl::ReportFindInPageSelection(int identifier,
                                                       int index,
                                                       bool final_update) {
  WebLocalFrameImpl* frame =
      WebLocalFrameImpl::FromFrame(element_->GetDocument().GetFrame());
  if (!frame)
    return;

  frame->GetFindInPage()->ReportFindInPageSelection(identifier, index,
                                                    gfx::Rect(), final_update);
}

float WebPluginContainerImpl::PageScaleFactor() {
  Page* page = element_->GetDocument().GetPage();
  if (!page)
    return 1.0;
  return page->PageScaleFactor();
}

float WebPluginContainerImpl::LayoutZoomFactor() {
  LocalFrame* frame = element_->GetDocument().GetFrame();
  if (!frame)
    return 1.0;
  return frame->LayoutZoomFactor();
}

void WebPluginContainerImpl::SetCcLayer(cc::Layer* new_layer) {
  if (layer_ == new_layer)
    return;
  layer_ = new_layer;
  if (element_)
    element_->SetNeedsCompositingUpdate();
}

void WebPluginContainerImpl::RequestFullscreen() {
  Fullscreen::RequestFullscreen(*element_);
}

bool WebPluginContainerImpl::IsFullscreenElement() const {
  return Fullscreen::IsFullscreenElement(*element_);
}

void WebPluginContainerImpl::CancelFullscreen() {
  Fullscreen::FullyExitFullscreen(element_->GetDocument());
}

bool WebPluginContainerImpl::IsMouseLocked() {
  return element_->GetDocument().PointerLockElement() == element_;
}

bool WebPluginContainerImpl::LockMouse(bool request_unadjusted_movement) {
  if (Page* page = element_->GetDocument().GetPage()) {
    bool res = page->GetPointerLockController().RequestPointerLock(
        element_, WTF::BindOnce(&WebPluginContainerImpl::HandleLockMouseResult,
                                WrapWeakPersistent(this)));
    if (res) {
      mouse_lock_lost_listener_ =
          MakeGarbageCollected<MouseLockLostListener>(this);
      element_->GetDocument().addEventListener(
          event_type_names::kPointerlockchange, mouse_lock_lost_listener_,
          false);
    }
    return res;
  }
  return false;
}

void WebPluginContainerImpl::UnlockMouse() {
  element_->GetDocument().exitPointerLock();
}

void WebPluginContainerImpl::HandleLockMouseResult(
    mojom::blink::PointerLockResult result) {
  web_plugin_->DidReceiveMouseLockResult(
      result == mojom::blink::PointerLockResult::kSuccess);
}

void WebPluginContainerImpl::MaybeLostMouseLock() {
  if (!IsMouseLocked()) {
    if (mouse_lock_lost_listener_) {
      mouse_lock_lost_listener_->Disconnect();
      element_->GetDocument().removeEventListener(
          event_type_names::kPointerlockchange, mouse_lock_lost_listener_,
          false);
      mouse_lock_lost_listener_ = nullptr;
    }
    web_plugin_->DidLoseMouseLock();
  }
}

bool WebPluginContainerImpl::SupportsPaginatedPrint() const {
  return web_plugin_->SupportsPaginatedPrint();
}

bool WebPluginContainerImpl::GetPrintPresetOptionsFromDocument(
    WebPrintPresetOptions* preset_options) const {
  return web_plugin_->GetPrintPresetOptionsFromDocument(preset_options);
}

int WebPluginContainerImpl::PrintBegin(
    const WebPrintParams& print_params) const {
  return web_plugin_->PrintBegin(print_params);
}

void WebPluginContainerImpl::PrintPage(int page_index, GraphicsContext& gc) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(
          gc, *element_->GetLayoutObject(), DisplayItem::kWebPlugin))
    return;

  DrawingRecorder recorder(gc, *element_->GetLayoutObject(),
                           DisplayItem::kWebPlugin, FrameRect());
  gc.Save();

  cc::PaintCanvas* canvas = gc.Canvas();
  web_plugin_->PrintPage(page_index, canvas);
  gc.Restore();
}

void WebPluginContainerImpl::PrintEnd() {
  web_plugin_->PrintEnd();
}

void WebPluginContainerImpl::Copy() {
  if (!web_plugin_->CanCopy())
    return;

  if (!web_plugin_->HasSelection())
    return;

  LocalFrame* frame = element_->GetDocument().GetFrame();
  frame->GetSystemClipboard()->WriteHTML(web_plugin_->SelectionAsMarkup(),
                                         KURL());
  String text = web_plugin_->SelectionAsText();
  ReplaceNBSPWithSpace(text);
  frame->GetSystemClipboard()->WritePlainText(text);
  frame->GetSystemClipboard()->CommitWrite();
}

bool WebPluginContainerImpl::ExecuteEditCommand(const WebString& name) {
  return ExecuteEditCommand(name, WebString());
}

bool WebPluginContainerImpl::ExecuteEditCommand(const WebString& name,
                                                const WebString& value) {
  DCHECK(value.IsEmpty());

  // If the clipboard contains something other than text (e.g. an image),
  // ReadPlainText() returns an empty string. The empty string is then pasted,
  // replacing any selected text. This behavior is consistent with that of HTML
  // text form fields.
  String text;
  if (name == "Paste" || name == "PasteAndMatchStyle") {
    LocalFrame* frame = element_->GetDocument().GetFrame();
    text = frame->GetSystemClipboard()->ReadPlainText();
  }

  // If copying or cutting, make sure to copy the plugin text to the clipboard
  // before executing the command.
  if (name == "Copy" || (name == "Cut" && web_plugin_->CanEditText()))
    Copy();

  return web_plugin_->ExecuteEditCommand(name, text);
}

// static
bool WebPluginContainerImpl::SupportsCommand(const WebString& name) {
  return name == "Copy" || name == "Cut" || name == "Paste" ||
         name == "PasteAndMatchStyle" || name == "SelectAll" ||
         name == "Undo" || name == "Redo";
}

WebElement WebPluginContainerImpl::GetElement() {
  return WebElement(element_);
}

WebDocument WebPluginContainerImpl::GetDocument() {
  return WebDocument(&element_->GetDocument());
}

void WebPluginContainerImpl::DispatchProgressEvent(const WebString& type,
                                                   bool length_computable,
                                                   uint64_t loaded,
                                                   uint64_t total,
                                                   const WebString& url) {
  ProgressEvent* event;
  if (url.IsEmpty()) {
    event = ProgressEvent::Create(type, length_computable, loaded, total);
  } else {
    event = MakeGarbageCollected<ResourceProgressEvent>(type, length_computable,
                                                        loaded, total, url);
  }
  element_->DispatchEvent(*event);
}

void WebPluginContainerImpl::EnqueueMessageEvent(
    const WebDOMMessageEvent& event) {
  if (!element_->GetExecutionContext())
    return;
  element_->EnqueueEvent(*event, TaskType::kInternalDefault);
}

void WebPluginContainerImpl::ScheduleAnimation() {
  if (auto* frame_view = element_->GetDocument().View())
    frame_view->ScheduleAnimation();
}

void WebPluginContainerImpl::ReportGeometry() {
  // Ignore when SetFrameRect/ReportGeometry is called from
  // UpdateOnEmbeddedContentViewChange before plugin is attached.
  if (!IsAttached())
    return;

  gfx::Rect window_rect, clip_rect, unobscured_rect;
  CalculateGeometry(window_rect, clip_rect, unobscured_rect);
  web_plugin_->UpdateGeometry(window_rect, clip_rect, unobscured_rect,
                              IsSelfVisible());
}

v8::Local<v8::Object> WebPluginContainerImpl::V8ObjectForElement() {
  ExecutionContext* context = element_->GetExecutionContext();
  if (!context || !context->CanExecuteScripts(kNotAboutToExecuteScript))
    return v8::Local<v8::Object>();

  ScriptState* script_state = ToScriptStateForMainWorld(context);
  if (!script_state)
    return v8::Local<v8::Object>();

  v8::MaybeLocal<v8::Value> maybe_v8value =
      ToV8Traits<HTMLPlugInElement>::ToV8(script_state, element_.Get());
  v8::Local<v8::Value> v8value;
  if (!maybe_v8value.ToLocal(&v8value)) {
    return v8::Local<v8::Object>();
  }
  DCHECK(v8value->IsObject());

  return v8::Local<v8::Object>::Cast(v8value);
}

void WebPluginContainerImpl::LoadFrameRequest(const WebURLRequest& request,
                                              const WebString& target) {
  LocalDOMWindow* window = element_->GetDocument().domWindow();
  if (!window)
    return;

  FrameLoadRequest frame_request(window, request.ToResourceRequest());
  Frame* target_frame =
      window->GetFrame()
          ->Tree()
          .FindOrCreateFrameForNavigation(frame_request, target)
          .frame;
  if (target_frame)
    target_frame->Navigate(frame_request, WebFrameLoadType::kStandard);
}

bool WebPluginContainerImpl::IsRectTopmost(const gfx::Rect& rect) {
  // Disallow access to the frame during Dispose(), because it is not guaranteed
  // to be valid memory once this object has started disposal. In particular,
  // we might be being disposed because the frame has already be deleted and
  // then something else dropped the
  // last reference to the this object.
  if (!IsAttached() || !element_)
    return false;

  LocalFrame* frame = element_->GetDocument().GetFrame();
  if (!frame)
    return false;

  gfx::Rect frame_rect = rect;
  frame_rect.Offset(Location().OffsetFromOrigin());
  HitTestLocation location((PhysicalRect(frame_rect)));
  HitTestResult result = frame->GetEventHandler().HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive |
                    HitTestRequest::kListBased);
  const HitTestResult::NodeSet& nodes = result.ListBasedTestResult();
  if (nodes.size() != 1)
    return false;
  return nodes.front().Get() == element_;
}

void WebPluginContainerImpl::RequestTouchEventType(
    TouchEventRequestType request_type) {
  if (touch_event_request_type_ == request_type || !element_)
    return;

  if (auto* frame = element_->GetDocument().GetFrame()) {
    EventHandlerRegistry& registry = frame->GetEventHandlerRegistry();
    if (request_type == kTouchEventRequestTypeRawLowLatency) {
      if (touch_event_request_type_ != kTouchEventRequestTypeNone) {
        registry.DidRemoveEventHandler(
            *element_, EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
      }
      registry.DidAddEventHandler(
          *element_,
          EventHandlerRegistry::kTouchStartOrMoveEventBlockingLowLatency);
    } else if (request_type != kTouchEventRequestTypeNone) {
      if (touch_event_request_type_ == kTouchEventRequestTypeRawLowLatency) {
        registry.DidRemoveEventHandler(
            *element_,
            EventHandlerRegistry::kTouchStartOrMoveEventBlockingLowLatency);
      }
      if (touch_event_request_type_ == kTouchEventRequestTypeNone ||
          touch_event_request_type_ == kTouchEventRequestTypeRawLowLatency) {
        registry.DidAddEventHandler(
            *element_, EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
      }
    } else if (touch_event_request_type_ != kTouchEventRequestTypeNone) {
      registry.DidRemoveEventHandler(
          *element_,
          touch_event_request_type_ == kTouchEventRequestTypeRawLowLatency
              ? EventHandlerRegistry::kTouchStartOrMoveEventBlockingLowLatency
              : EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
    }
  }
  touch_event_request_type_ = request_type;
}

void WebPluginContainerImpl::SetWantsWheelEvents(bool wants_wheel_events) {
  if (wants_wheel_events_ == wants_wheel_events)
    return;

  if (auto* frame = element_->GetDocument().GetFrame()) {
    EventHandlerRegistry& registry = frame->GetEventHandlerRegistry();
    if (wants_wheel_events) {
      registry.DidAddEventHandler(*element_,
                                  EventHandlerRegistry::kWheelEventBlocking);
    } else {
      registry.DidRemoveEventHandler(*element_,
                                     EventHandlerRegistry::kWheelEventBlocking);
    }
  }

  wants_wheel_events_ = wants_wheel_events;

  if (IsAttached()) {
    // Scroll hit test data depend on wheel events. They are painted in the
    // background phase.
    GetLayoutEmbeddedContent()->SetBackgroundNeedsFullPaintInvalidation();
  }
}

gfx::Point WebPluginContainerImpl::RootFrameToLocalPoint(
    const gfx::Point& point_in_root_frame) {
  gfx::Point point_in_content =
      ParentFrameView()->ConvertFromRootFrame(point_in_root_frame);
  return ToRoundedPoint(element_->GetLayoutObject()->AbsoluteToLocalPoint(
      PhysicalOffset(point_in_content)));
}

gfx::Point WebPluginContainerImpl::LocalToRootFramePoint(
    const gfx::Point& point_in_local) {
  gfx::Point absolute_point =
      ToRoundedPoint(element_->GetLayoutObject()->LocalToAbsolutePoint(
          PhysicalOffset(point_in_local)));
  return ParentFrameView()->ConvertToRootFrame(absolute_point);
}

bool WebPluginContainerImpl::WasTargetForLastMouseEvent() {
  auto* frame = element_->GetDocument().GetFrame();
  if (!frame)
    return false;
  return frame->GetEventHandler().GetElementUnderMouse() == element_;
}

void WebPluginContainerImpl::DidReceiveResponse(
    const ResourceResponse& response) {
  // Make sure that the plugin receives window geometry before data, or else
  // plugins misbehave.
  ReportGeometry();

  WrappedResourceResponse url_response(response);
  web_plugin_->DidReceiveResponse(url_response);
}

void WebPluginContainerImpl::DidReceiveData(base::span<const char> data) {
  web_plugin_->DidReceiveData(data);
}

void WebPluginContainerImpl::DidFinishLoading() {
  web_plugin_->DidFinishLoading();
}

void WebPluginContainerImpl::DidFailLoading(const ResourceError& error) {
  web_plugin_->DidFailLoading(WebURLError(error));
}

cc::Layer* WebPluginContainerImpl::CcLayer() const {
  return layer_;
}

v8::Local<v8::Object> WebPluginContainerImpl::ScriptableObject(
    v8::Isolate* isolate) {
  // With Oilpan, on plugin element detach dispose() will be called to safely
  // clear out references, including the pre-emptive destruction of the plugin.
  //
  // It clearly has no scriptable object if in such a disposed state.
  if (!web_plugin_)
    return v8::Local<v8::Object>();

  v8::Local<v8::Object> object = web_plugin_->V8ScriptableObject(isolate);

  // If the plugin has been destroyed and the reference on the stack is the
  // only one left, then don't return the scriptable object.
  if (!web_plugin_)
    return v8::Local<v8::Object>();

  return object;
}

bool WebPluginContainerImpl::SupportsKeyboardFocus() const {
  return web_plugin_->SupportsKeyboardFocus();
}

bool WebPluginContainerImpl::SupportsInputMethod() const {
  return web_plugin_->SupportsInputMethod();
}

bool WebPluginContainerImpl::CanProcessDrag() const {
  return web_plugin_->CanProcessDrag();
}

bool WebPluginContainerImpl::WantsWheelEvents() const {
  return wants_wheel_events_;
}

// Private methods -------------------------------------------------------------

WebPluginContainerImpl::WebPluginContainerImpl(HTMLPlugInElement& element,
                                               WebPlugin* web_plugin)
    : EmbeddedContentView(gfx::Rect()),
      element_(element),
      web_plugin_(web_plugin) {}

WebPluginContainerImpl::~WebPluginContainerImpl() {
  // The plugin container must have been disposed of by now.
  DCHECK(!web_plugin_);
}

LocalFrameView* WebPluginContainerImpl::ParentFrameView() const {
  DCHECK(IsAttached());
  return element_->GetDocument().GetFrame()->View();
}

LayoutEmbeddedContent* WebPluginContainerImpl::GetLayoutEmbeddedContent()
    const {
  return element_->GetLayoutEmbeddedContent();
}

void WebPluginContainerImpl::Dispose() {
  SetAttached(false);

  RequestTouchEventType(kTouchEventRequestTypeNone);
  SetWantsWheelEvents(false);

  if (WebLocalFrameImpl* frame =
          WebLocalFrameImpl::FromFrame(element_->GetDocument().GetFrame())) {
    if (frame->GetFindInPage()->PluginFindHandler() == this)
      frame->GetFindInPage()->SetPluginFindHandler(nullptr);
  }

  if (web_plugin_) {
    // Plugins may execute script on being detached during the lifecycle update.
    ScriptForbiddenScope::AllowUserAgentScript allow_script;
    CHECK(web_plugin_->Container() == this);
    web_plugin_->Destroy();
    web_plugin_ = nullptr;
  }

  layer_ = nullptr;
}

void WebPluginContainerImpl::SetFrameRect(const gfx::Rect& rect) {
  gfx::Rect old_rect(FrameRect());
  EmbeddedContentView::SetFrameRect(rect);
  // We need to report every time SetFrameRect is called, even if there is no
  // change (if there is a change, FrameRectsChanged will do the reporting).
  if (old_rect == FrameRect())
    PropagateFrameRects();
}

void WebPluginContainerImpl::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  visitor->Trace(mouse_lock_lost_listener_);
}

void WebPluginContainerImpl::HandleMouseEvent(MouseEvent& event) {
  // TODO(dtapuska): Move WebMouseEventBuilder into the anonymous namespace
  // in this class.
  WebMouseEventBuilder transformed_event(element_->GetLayoutObject(), event);
  if (transformed_event.GetType() == WebInputEvent::Type::kUndefined)
    return;

  // We cache the parent LocalFrameView here as the plugin widget could be
  // deleted in the call to HandleEvent. See http://b/issue?id=1362948
  LocalFrameView* parent = ParentFrameView();

  if (event.type() == event_type_names::kMousedown)
    FocusPlugin();

  ui::Cursor cursor(ui::mojom::blink::CursorType::kPointer);
  if (web_plugin_ &&
      web_plugin_->HandleInputEvent(
          WebCoalescedInputEvent(transformed_event, ui::LatencyInfo()),
          &cursor) != WebInputEventResult::kNotHandled)
    event.SetDefaultHandled();

  // A windowless plugin can change the cursor in response to a mouse move
  // event.  We need to reflect the changed cursor in the frame view as the
  // mouse is moved in the boundaries of the windowless plugin.
  Page* page = parent->GetFrame().GetPage();
  if (!page)
    return;
  page->GetChromeClient().SetCursorForPlugin(
      cursor, &parent->GetFrame().LocalFrameRoot());
}

void WebPluginContainerImpl::HandleDragEvent(MouseEvent& event) {
  DCHECK(IsA<DragEvent>(event));

  WebDragStatus drag_status = kWebDragStatusUnknown;
  if (event.type() == event_type_names::kDragenter)
    drag_status = kWebDragStatusEnter;
  else if (event.type() == event_type_names::kDragleave)
    drag_status = kWebDragStatusLeave;
  else if (event.type() == event_type_names::kDragover)
    drag_status = kWebDragStatusOver;
  else if (event.type() == event_type_names::kDrop)
    drag_status = kWebDragStatusDrop;

  if (drag_status == kWebDragStatusUnknown)
    return;

  DataTransfer* data_transfer = event.getDataTransfer();
  WebDragData drag_data = data_transfer->GetDataObject()->ToWebDragData();
  DragOperationsMask drag_operation_mask = data_transfer->SourceOperation();
  gfx::PointF drag_screen_location(event.screenX(), event.screenY());
  gfx::Point location(Location());
  gfx::PointF drag_location(event.AbsoluteLocation().x() - location.x(),
                            event.AbsoluteLocation().y() - location.y());

  web_plugin_->HandleDragStatusU
"""


```
Response:
The user wants to understand the functionality of the `inspector_overlay_agent.cc` file in the Chromium Blink engine.

Here's a plan to address the request:

1. **Identify the core purpose:** Based on the name and the included headers, the agent seems responsible for drawing overlays on the web page during inspection.
2. **List key functionalities:** Analyze the methods and data members to pinpoint the actions the agent performs.
3. **Explain relations to web technologies (JavaScript, HTML, CSS):** Look for how the agent interacts with or visualizes elements related to these technologies.
4. **Provide examples for logic and data flow:** Create scenarios to illustrate how inputs to the agent result in specific outputs.
5. **Point out potential user/programming errors:** Consider common mistakes developers might make while interacting with or using the functionalities provided by the agent.
6. **Summarize the functionality:** Concisely describe the main responsibilities of the `InspectorOverlayAgent` based on the analysis of the provided code snippet.
这是Blink渲染引擎中 `inspector_overlay_agent.cc` 文件的第一部分，它主要负责**在网页上绘制各种调试和检查相关的覆盖层 (overlay)**。这些覆盖层用于辅助开发者进行页面元素的检查、布局调试、性能分析等。

以下是该部分代码体现的功能归纳：

**核心功能：**

1. **管理和控制调试覆盖层的显示:** `InspectorOverlayAgent` 负责创建、显示和隐藏各种覆盖层，例如高亮选中的元素、显示网格布局、展示Flex布局、显示滚动捕捉区域等。

2. **与前端调试工具通信:**  该 Agent 通过 Chrome DevTools Protocol (CDP) 与前端的开发者工具进行通信，接收来自前端的指令，并向前端发送状态更新。

3. **处理来自前端的指令:**  代码中定义了多个以 `protocol::Response` 开头的函数，这些函数对应了前端发送的各种命令，例如 `enable` (启用覆盖层)、`disable` (禁用覆盖层)、 `highlightNode` (高亮节点)、`setShowGridOverlays` (显示网格覆盖层) 等。

4. **绘制高亮效果:** 提供了多种方式来高亮页面元素或特定区域，例如 `highlightRect` (高亮一个矩形区域) 和 `highlightQuad` (高亮一个四边形区域)。

5. **支持多种类型的覆盖层:**  代码中提到了多种覆盖层类型，例如 "highlight" (普通高亮), "persistent" (持久性覆盖层), "sourceOrder" (源顺序), "distances" (距离), "viewportSize" (视口大小) 等。

6. **处理鼠标和键盘事件:**  `InspectTool` 类及其子类负责处理鼠标移动、点击等事件，以响应用户的交互操作。

7. **与DOM Agent协同工作:** `InspectorOverlayAgent` 依赖于 `InspectorDOMAgent` 来获取需要高亮的 DOM 节点信息。

8. **管理辅助功能上下文 (AXContext):**  提供了 `HasAXContext` 和 `EnsureAXContext` 函数，表明该 Agent 可能与辅助功能调试相关。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:**
    * `highlightNode` 函数接收 `nodeId` 或 `backend_node_id` 来定位 HTML 元素，并在该元素周围绘制高亮边框。例如，前端发送 `{"method": "Overlay.highlightNode", "params": {"nodeId": 123}}`，则 `InspectorOverlayAgent` 会找到 `nodeId` 为 123 的 HTML 元素并在页面上高亮显示。
* **CSS:**
    *  `setShowGridOverlays` 和 `setShowFlexOverlays` 函数用于可视化 CSS Grid 和 Flexbox 布局。前端发送相应的指令后，`InspectorOverlayAgent` 会在页面上绘制网格线或 Flexbox 的排列线，帮助开发者理解 CSS 布局。
    *  高亮元素的样式 (颜色、边框等) 可以通过前端发送的 `HighlightConfig` 进行配置，这涉及到 CSS 属性的应用。
* **JavaScript:**
    * `EvaluateInOverlay` 函数表明可以在覆盖层的上下文中执行 JavaScript 代码。例如，为了实现某些动态的覆盖层效果，可能会在覆盖层的 JavaScript 环境中执行一些脚本。

**逻辑推理举例：**

假设输入：前端发送命令 `{"method": "Overlay.highlightNode", "params": {"nodeId": 456, "highlightConfig": {"contentColor": {"r": 255, "g": 0, "b": 0, "a": 0.5}}}}`

输出：
1. `InspectorOverlayAgent` 会调用 `dom_agent_->AssertNode` 找到 `nodeId` 为 456 的 DOM 节点。
2. 如果找到该节点，则根据 `highlightConfig` 中的 `contentColor` (半透明红色)，在该节点周围绘制半透明红色的高亮区域。

**用户或编程常见的使用错误举例：**

* **未启用 DOM Agent:**  如果在使用覆盖层功能之前没有启用 DOM Agent，调用 `enable` 函数会返回错误 "DOM should be enabled first"。这是一个常见的编程顺序错误。
* **传递无效的节点 ID:**  如果前端传递了一个不存在的 `nodeId` 或 `backend_node_id` 给 `highlightNode` 函数，`dom_agent_->AssertNode` 会失败，导致高亮操作无法执行。
* **错误的 Quad 格式:** `highlightQuad` 函数要求 `quad_array` 必须包含 8 个数字，分别代表四边形四个点的 x 和 y 坐标。如果格式不正确，`ParseQuad` 函数会返回 `false`，导致高亮失败。

**功能归纳：**

`inspector_overlay_agent.cc` 的这部分代码定义了 Blink 渲染引擎中用于实现开发者工具覆盖层功能的核心 Agent。它负责接收前端的指令，管理不同类型的覆盖层，并利用 DOM Agent 提供的信息在网页上绘制可视化的调试信息，例如元素高亮、布局线等，从而辅助开发者进行页面检查和调试。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_overlay_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/inspector/inspector_overlay_agent.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "build/build_config.h"
#include "cc/layers/content_layer_client.h"
#include "cc/layers/picture_layer.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/public/resources/grit/inspector_overlay_resources_map.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_inspector_overlay_host.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/frame_overlay.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspect_tools.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_overlay_host.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/data_resource_helper.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/inspector_protocol/crdtp/json.h"
#include "ui/accessibility/ax_mode.h"
#include "v8/include/v8.h"

using crdtp::SpanFrom;
using crdtp::json::ConvertCBORToJSON;

namespace blink {

using protocol::Maybe;

namespace {

bool ParseQuad(std::unique_ptr<protocol::Array<double>> quad_array,
               gfx::QuadF* quad) {
  const size_t kCoordinatesInQuad = 8;
  if (!quad_array || quad_array->size() != kCoordinatesInQuad) {
    return false;
  }
  quad->set_p1(gfx::PointF((*quad_array)[0], (*quad_array)[1]));
  quad->set_p2(gfx::PointF((*quad_array)[2], (*quad_array)[3]));
  quad->set_p3(gfx::PointF((*quad_array)[4], (*quad_array)[5]));
  quad->set_p4(gfx::PointF((*quad_array)[6], (*quad_array)[7]));
  return true;
}

v8::MaybeLocal<v8::Value> GetV8Property(v8::Local<v8::Context> context,
                                        v8::Local<v8::Value> object,
                                        const String& name) {
  v8::Isolate* isolate = context->GetIsolate();
  v8::Local<v8::String> name_str = V8String(isolate, name);
  v8::Local<v8::Object> object_obj;
  if (!object->ToObject(context).ToLocal(&object_obj)) {
    return v8::MaybeLocal<v8::Value>();
  }
  return object_obj->Get(context, name_str);
}

Color ParseColor(protocol::DOM::RGBA* rgba) {
  if (!rgba) {
    return Color::kTransparent;
  }

  int r = rgba->getR();
  int g = rgba->getG();
  int b = rgba->getB();
  if (!rgba->hasA()) {
    return Color(r, g, b);
  }

  double a = rgba->getA(1);
  // Clamp alpha to the [0..1] range.
  if (a < 0) {
    a = 0;
  } else if (a > 1) {
    a = 1;
  }

  return Color(r, g, b, static_cast<int>(a * 255));
}

}  // namespace

// OverlayNames ----------------------------------------------------------------
const char* OverlayNames::OVERLAY_HIGHLIGHT = "highlight";
const char* OverlayNames::OVERLAY_PERSISTENT = "persistent";
const char* OverlayNames::OVERLAY_SOURCE_ORDER = "sourceOrder";
const char* OverlayNames::OVERLAY_DISTANCES = "distances";
const char* OverlayNames::OVERLAY_VIEWPORT_SIZE = "viewportSize";
const char* OverlayNames::OVERLAY_SCREENSHOT = "screenshot";
const char* OverlayNames::OVERLAY_PAUSED = "paused";
const char* OverlayNames::OVERLAY_WINDOW_CONTROLS_OVERLAY =
    "windowControlsOverlay";

// InspectTool -----------------------------------------------------------------
bool InspectTool::HandleInputEvent(LocalFrameView* frame_view,
                                   const WebInputEvent& input_event,
                                   bool* swallow_next_mouse_up) {
  if (input_event.GetType() == WebInputEvent::Type::kGestureTap) {
    // We only have a use for gesture tap.
    WebGestureEvent transformed_event = TransformWebGestureEvent(
        frame_view, static_cast<const WebGestureEvent&>(input_event));
    return HandleGestureTapEvent(transformed_event);
  }

  if (WebInputEvent::IsMouseEventType(input_event.GetType())) {
    WebMouseEvent transformed_event = TransformWebMouseEvent(
        frame_view, static_cast<const WebMouseEvent&>(input_event));
    return HandleMouseEvent(transformed_event, swallow_next_mouse_up);
  }

  if (WebInputEvent::IsPointerEventType(input_event.GetType())) {
    WebPointerEvent transformed_event = TransformWebPointerEvent(
        frame_view, static_cast<const WebPointerEvent&>(input_event));
    return HandlePointerEvent(transformed_event);
  }

  if (WebInputEvent::IsKeyboardEventType(input_event.GetType())) {
    return HandleKeyboardEvent(
        static_cast<const WebKeyboardEvent&>(input_event));
  }

  return false;
}

bool InspectTool::HandleMouseEvent(const WebMouseEvent& mouse_event,
                                   bool* swallow_next_mouse_up) {
  if (mouse_event.GetType() == WebInputEvent::Type::kMouseMove) {
    return HandleMouseMove(mouse_event);
  }

  if (mouse_event.GetType() == WebInputEvent::Type::kMouseDown) {
    return HandleMouseDown(mouse_event, swallow_next_mouse_up);
  }

  if (mouse_event.GetType() == WebInputEvent::Type::kMouseUp) {
    return HandleMouseUp(mouse_event);
  }

  return false;
}

bool InspectTool::HandleMouseDown(const WebMouseEvent&,
                                  bool* swallow_next_mouse_up) {
  return false;
}

bool InspectTool::HandleMouseUp(const WebMouseEvent&) {
  return false;
}

bool InspectTool::HandleMouseMove(const WebMouseEvent&) {
  return false;
}

bool InspectTool::HandleGestureTapEvent(const WebGestureEvent&) {
  return false;
}

bool InspectTool::HandlePointerEvent(const WebPointerEvent&) {
  return false;
}

bool InspectTool::HandleKeyboardEvent(const WebKeyboardEvent&) {
  return false;
}

bool InspectTool::ForwardEventsToOverlay() {
  return true;
}

bool InspectTool::SupportsPersistentOverlays() {
  return false;
}

bool InspectTool::HideOnMouseMove() {
  return false;
}

bool InspectTool::HideOnHideHighlight() {
  return false;
}

void InspectTool::Trace(Visitor* visitor) const {
  visitor->Trace(overlay_);
}

// Hinge -----------------------------------------------------------------------

Hinge::Hinge(gfx::QuadF quad,
             Color content_color,
             Color outline_color,
             InspectorOverlayAgent* overlay)
    : quad_(quad),
      content_color_(content_color),
      outline_color_(outline_color),
      overlay_(overlay) {}

String Hinge::GetOverlayName() {
  // TODO (soxia): In the future, we should make the hinge working properly
  // with tools using different resources.
  return OverlayNames::OVERLAY_HIGHLIGHT;
}

void Hinge::Trace(Visitor* visitor) const {
  visitor->Trace(overlay_);
}

void Hinge::Draw(float scale) {
  // scaling is applied at the drawHighlight code.
  InspectorHighlight highlight(1.f);
  highlight.AppendQuad(quad_, content_color_, outline_color_);
  overlay_->EvaluateInOverlay("drawHighlight", highlight.AsProtocolValue());
}

// InspectorOverlayAgent -------------------------------------------------------

class InspectorOverlayAgent::InspectorPageOverlayDelegate final
    : public FrameOverlay::Delegate,
      public cc::ContentLayerClient {
 public:
  explicit InspectorPageOverlayDelegate(InspectorOverlayAgent& overlay)
      : overlay_(&overlay) {
    layer_ = cc::PictureLayer::Create(this);
    layer_->SetIsDrawable(true);
    layer_->SetHitTestable(false);
  }
  ~InspectorPageOverlayDelegate() override {
    if (layer_) {
      layer_->ClearClient();
    }
  }

  void PaintFrameOverlay(const FrameOverlay& frame_overlay,
                         GraphicsContext& graphics_context,
                         const gfx::Size& size) const override {
    if (!overlay_->IsVisible()) {
      return;
    }

    CHECK_EQ(layer_->client(), this);

    overlay_->PaintOverlayPage();

    // The emulation scale factor is baked in the contents of the overlay layer,
    // so the size of the layer also needs to be scaled.
    layer_->SetBounds(
        gfx::ScaleToCeiledSize(size, overlay_->EmulationScaleFactor()));
    DEFINE_STATIC_DISPLAY_ITEM_CLIENT(client, "InspectorOverlay");
    // The overlay layer needs to be in the root property tree state (instead of
    // the default FrameOverlay state which is under the emulation scale
    // transform node) because the emulation scale is baked in the layer.
    auto property_tree_state = PropertyTreeState::Root();
    RecordForeignLayer(graphics_context, *client,
                       DisplayItem::kForeignLayerDevToolsOverlay, layer_,
                       gfx::Point(), &property_tree_state);
  }

  void Invalidate() override {
    overlay_->GetFrame()->View()->SetVisualViewportOrOverlayNeedsRepaint();
    if (layer_) {
      layer_->SetNeedsDisplay();
    }
  }

  const cc::Layer* GetLayer() const { return layer_.get(); }

 private:
  // cc::ContentLayerClient implementation
  bool FillsBoundsCompletely() const override { return false; }

  scoped_refptr<cc::DisplayItemList> PaintContentsToDisplayList() override {
    auto display_list = base::MakeRefCounted<cc::DisplayItemList>();
    display_list->StartPaint();
    display_list->push<cc::DrawRecordOp>(
        overlay_->OverlayMainFrame()->View()->GetPaintRecord());
    display_list->EndPaintOfUnpaired(gfx::Rect(layer_->bounds()));
    display_list->Finalize();
    return display_list;
  }

  Persistent<InspectorOverlayAgent> overlay_;
  scoped_refptr<cc::PictureLayer> layer_;
};

class InspectorOverlayAgent::InspectorOverlayChromeClient final
    : public EmptyChromeClient {
 public:
  InspectorOverlayChromeClient(ChromeClient& client,
                               InspectorOverlayAgent& overlay)
      : client_(&client), overlay_(&overlay) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(client_);
    visitor->Trace(overlay_);
    EmptyChromeClient::Trace(visitor);
  }

  void SetCursor(const ui::Cursor& cursor, LocalFrame* local_root) override {
    client_->SetCursorOverridden(false);
    client_->SetCursor(cursor, overlay_->GetFrame());
    client_->SetCursorOverridden(true);
  }

  void UpdateTooltipUnderCursor(LocalFrame& frame,
                                const String& tooltip,
                                TextDirection direction) override {
    DCHECK_EQ(&frame, overlay_->OverlayMainFrame());
    client_->UpdateTooltipUnderCursor(*overlay_->GetFrame(), tooltip,
                                      direction);
  }

 private:
  Member<ChromeClient> client_;
  Member<InspectorOverlayAgent> overlay_;
};

InspectorOverlayAgent::InspectorOverlayAgent(
    WebLocalFrameImpl* frame_impl,
    InspectedFrames* inspected_frames,
    v8_inspector::V8InspectorSession* v8_session,
    InspectorDOMAgent* dom_agent)
    : frame_impl_(frame_impl),
      inspected_frames_(inspected_frames),
      resize_timer_active_(false),
      resize_timer_(
          frame_impl->GetFrame()->GetTaskRunner(TaskType::kInternalInspector),
          this,
          &InspectorOverlayAgent::OnResizeTimer),
      disposed_(false),
      v8_session_(v8_session),
      dom_agent_(dom_agent),
      swallow_next_mouse_up_(false),
      backend_node_id_to_inspect_(0),
      enabled_(&agent_state_, false),
      show_ad_highlights_(&agent_state_, false),
      show_debug_borders_(&agent_state_, false),
      show_fps_counter_(&agent_state_, false),
      show_paint_rects_(&agent_state_, false),
      show_layout_shift_regions_(&agent_state_, false),
      show_scroll_bottleneck_rects_(&agent_state_, false),
      show_hit_test_borders_(&agent_state_, false),
      show_web_vitals_(&agent_state_, false),
      show_size_on_resize_(&agent_state_, false),
      paused_in_debugger_message_(&agent_state_, String()),
      inspect_mode_(&agent_state_, protocol::Overlay::InspectModeEnum::None),
      inspect_mode_protocol_config_(&agent_state_, std::vector<uint8_t>()) {
  DCHECK(dom_agent);

  frame_impl_->GetFrame()->GetProbeSink()->AddInspectorOverlayAgent(this);

  if (GetFrame()->GetWidgetForLocalRoot()) {
    original_layer_tree_debug_state_ =
        std::make_unique<cc::LayerTreeDebugState>(
            *GetFrame()->GetWidgetForLocalRoot()->GetLayerTreeDebugState());
  }
}

InspectorOverlayAgent::~InspectorOverlayAgent() {
  DCHECK(!overlay_page_);
  DCHECK(!inspect_tool_);
  DCHECK(!hinge_);
  DCHECK(!persistent_tool_);
  DCHECK(!frame_overlay_);
}

void InspectorOverlayAgent::Trace(Visitor* visitor) const {
  visitor->Trace(frame_impl_);
  visitor->Trace(inspected_frames_);
  visitor->Trace(overlay_page_);
  visitor->Trace(overlay_chrome_client_);
  visitor->Trace(overlay_host_);
  visitor->Trace(resize_timer_);
  visitor->Trace(dom_agent_);
  visitor->Trace(frame_overlay_);
  visitor->Trace(inspect_tool_);
  visitor->Trace(persistent_tool_);
  visitor->Trace(hinge_);
  visitor->Trace(document_to_ax_context_);
  InspectorBaseAgent::Trace(visitor);
}

void InspectorOverlayAgent::Restore() {
  if (enabled_.Get()) {
    enable();
  }
  setShowAdHighlights(show_ad_highlights_.Get());
  setShowDebugBorders(show_debug_borders_.Get());
  setShowFPSCounter(show_fps_counter_.Get());
  setShowPaintRects(show_paint_rects_.Get());
  setShowLayoutShiftRegions(show_layout_shift_regions_.Get());
  setShowScrollBottleneckRects(show_scroll_bottleneck_rects_.Get());
  setShowHitTestBorders(show_hit_test_borders_.Get());
  setShowViewportSizeOnResize(show_size_on_resize_.Get());
  setShowWebVitals(show_web_vitals_.Get());
  PickTheRightTool();
}

void InspectorOverlayAgent::Dispose() {
  InspectorBaseAgent::Dispose();
  disposed_ = true;

  frame_impl_->GetFrame()->GetProbeSink()->RemoveInspectorOverlayAgent(this);
}

protocol::Response InspectorOverlayAgent::enable() {
  if (!dom_agent_->Enabled()) {
    return protocol::Response::ServerError("DOM should be enabled first");
  }
  enabled_.Set(true);
  if (backend_node_id_to_inspect_) {
    GetFrontend()->inspectNodeRequested(
        static_cast<int>(backend_node_id_to_inspect_));
  }
  backend_node_id_to_inspect_ = 0;
  SetNeedsUnbufferedInput(true);
  return protocol::Response::Success();
}

bool InspectorOverlayAgent::HasAXContext(Node* node) {
  return document_to_ax_context_.Contains(&node->GetDocument());
}

void InspectorOverlayAgent::EnsureAXContext(Node* node) {
  EnsureAXContext(node->GetDocument());
}

void InspectorOverlayAgent::EnsureAXContext(Document& document) {
  if (!document_to_ax_context_.Contains(&document)) {
    auto context = std::make_unique<AXContext>(document, ui::kAXModeComplete);
    document_to_ax_context_.Set(&document, std::move(context));
  }
}

protocol::Response InspectorOverlayAgent::disable() {
  enabled_.Clear();
  setShowAdHighlights(false);
  setShowViewportSizeOnResize(false);
  paused_in_debugger_message_.Clear();
  inspect_mode_.Set(protocol::Overlay::InspectModeEnum::None);
  inspect_mode_protocol_config_.Set(std::vector<uint8_t>());

  if (FrameWidgetInitialized()) {
    GetFrame()->GetWidgetForLocalRoot()->SetLayerTreeDebugState(
        *original_layer_tree_debug_state_);
  }

  if (overlay_page_) {
    overlay_page_->WillBeDestroyed();
    overlay_page_.Clear();
    overlay_chrome_client_.Clear();
    overlay_host_->ClearDelegate();
    overlay_host_.Clear();
  }
  resize_timer_.Stop();
  resize_timer_active_ = false;

  if (frame_overlay_) {
    frame_overlay_.Release()->Destroy();
  }

  persistent_tool_ = nullptr;
  hinge_ = nullptr;
  PickTheRightTool();
  SetNeedsUnbufferedInput(false);
  document_to_ax_context_.clear();
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowAdHighlights(bool show) {
  show_ad_highlights_.Set(show);
  frame_impl_->ViewImpl()->GetPage()->GetSettings().SetHighlightAds(show);
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowDebugBorders(bool show) {
  show_debug_borders_.Set(show);
  if (show) {
    protocol::Response response = CompositingEnabled();
    if (!response.IsSuccess()) {
      return response;
    }
  }
  if (FrameWidgetInitialized()) {
    FrameWidget* widget = GetFrame()->GetWidgetForLocalRoot();
    cc::LayerTreeDebugState debug_state = *widget->GetLayerTreeDebugState();
    if (show) {
      debug_state.show_debug_borders.set();
    } else {
      debug_state.show_debug_borders.reset();
    }
    widget->SetLayerTreeDebugState(debug_state);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowFPSCounter(bool show) {
  show_fps_counter_.Set(show);
  if (show) {
    protocol::Response response = CompositingEnabled();
    if (!response.IsSuccess()) {
      return response;
    }
  }
  if (FrameWidgetInitialized()) {
    FrameWidget* widget = GetFrame()->GetWidgetForLocalRoot();
    cc::LayerTreeDebugState debug_state = *widget->GetLayerTreeDebugState();
    debug_state.show_fps_counter = show;
    widget->SetLayerTreeDebugState(debug_state);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowPaintRects(bool show) {
  show_paint_rects_.Set(show);
  if (show) {
    protocol::Response response = CompositingEnabled();
    if (!response.IsSuccess()) {
      return response;
    }
  }
  if (FrameWidgetInitialized()) {
    FrameWidget* widget = GetFrame()->GetWidgetForLocalRoot();
    cc::LayerTreeDebugState debug_state = *widget->GetLayerTreeDebugState();
    debug_state.show_paint_rects = show;
    widget->SetLayerTreeDebugState(debug_state);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowLayoutShiftRegions(bool show) {
  show_layout_shift_regions_.Set(show);
  if (show) {
    protocol::Response response = CompositingEnabled();
    if (!response.IsSuccess()) {
      return response;
    }
  }
  if (FrameWidgetInitialized()) {
    FrameWidget* widget = GetFrame()->GetWidgetForLocalRoot();
    cc::LayerTreeDebugState debug_state = *widget->GetLayerTreeDebugState();
    debug_state.show_layout_shift_regions = show;
    widget->SetLayerTreeDebugState(debug_state);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowScrollBottleneckRects(
    bool show) {
  show_scroll_bottleneck_rects_.Set(show);
  if (show) {
    protocol::Response response = CompositingEnabled();
    if (!response.IsSuccess()) {
      return response;
    }
  }
  if (FrameWidgetInitialized()) {
    FrameWidget* widget = GetFrame()->GetWidgetForLocalRoot();
    cc::LayerTreeDebugState debug_state = *widget->GetLayerTreeDebugState();
    debug_state.show_touch_event_handler_rects = show;
    debug_state.show_wheel_event_handler_rects = show;
    debug_state.show_main_thread_scroll_hit_test_rects = show;
    debug_state.show_main_thread_scroll_repaint_rects = show;
    debug_state.show_raster_inducing_scroll_rects = show;
    widget->SetLayerTreeDebugState(debug_state);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowHitTestBorders(bool show) {
  // This CDP command has been deprecated. Don't do anything and return success.
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowViewportSizeOnResize(
    bool show) {
  show_size_on_resize_.Set(show);
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowWebVitals(bool show) {
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowWindowControlsOverlay(
    protocol::Maybe<protocol::Overlay::WindowControlsOverlayConfig>
        wco_config) {
  // Hide WCO when called without a configuration.
  if (!wco_config) {
    SetInspectTool(nullptr);
    return protocol::Response::Success();
  }

  std::unique_ptr<protocol::DictionaryValue> result =
      protocol::DictionaryValue::create();

  protocol::Overlay::WindowControlsOverlayConfig& config = *wco_config;

  result->setBoolean("showCSS", config.getShowCSS());
  result->setString("selectedPlatform", config.getSelectedPlatform());
  result->setString("themeColor", config.getThemeColor());

  return SetInspectTool(MakeGarbageCollected<WindowControlsOverlayTool>(
      this, GetFrontend(), std::move(result)));
}

protocol::Response InspectorOverlayAgent::setPausedInDebuggerMessage(
    Maybe<String> message) {
  paused_in_debugger_message_.Set(message.value_or(String()));
  PickTheRightTool();
  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::highlightRect(
    int x,
    int y,
    int width,
    int height,
    Maybe<protocol::DOM::RGBA> color,
    Maybe<protocol::DOM::RGBA> outline_color) {
  std::unique_ptr<gfx::QuadF> quad =
      std::make_unique<gfx::QuadF>(gfx::RectF(x, y, width, height));
  return SetInspectTool(MakeGarbageCollected<QuadHighlightTool>(
      this, GetFrontend(), std::move(quad), ParseColor(color.get()),
      ParseColor(outline_color.get())));
}

protocol::Response InspectorOverlayAgent::highlightQuad(
    std::unique_ptr<protocol::Array<double>> quad_array,
    Maybe<protocol::DOM::RGBA> color,
    Maybe<protocol::DOM::RGBA> outline_color) {
  std::unique_ptr<gfx::QuadF> quad = std::make_unique<gfx::QuadF>();
  if (!ParseQuad(std::move(quad_array), quad.get())) {
    return protocol::Response::ServerError("Invalid Quad format");
  }
  return SetInspectTool(MakeGarbageCollected<QuadHighlightTool>(
      this, GetFrontend(), std::move(quad), ParseColor(color.get()),
      ParseColor(outline_color.get())));
}

protocol::Response InspectorOverlayAgent::setShowHinge(
    protocol::Maybe<protocol::Overlay::HingeConfig> tool_config) {
  // Hide the hinge when called without a configuration.
  if (!tool_config) {
    hinge_ = nullptr;
    if (!inspect_tool_) {
      DisableFrameOverlay();
    }
    ScheduleUpdate();
    return protocol::Response::Success();
  }

  // Create a hinge
  protocol::Overlay::HingeConfig& config = *tool_config;
  protocol::DOM::Rect* rect = config.getRect();
  int x = rect->getX();
  int y = rect->getY();
  int width = rect->getWidth();
  int height = rect->getHeight();
  if (x < 0 || y < 0 || width < 0 || height < 0) {
    return protocol::Response::InvalidParams("Invalid hinge rectangle.");
  }

  // Use default color if a content color is not provided.
  Color content_color = config.hasContentColor()
                            ? ParseColor(config.getContentColor(nullptr))
                            : Color(38, 38, 38);
  // outlineColor uses a kTransparent default from ParseColor if not provided.
  Color outline_color = ParseColor(config.getOutlineColor(nullptr));

  DCHECK(frame_impl_->GetFrameView() && GetFrame());

  gfx::QuadF quad(gfx::RectF(x, y, width, height));
  hinge_ =
      MakeGarbageCollected<Hinge>(quad, content_color, outline_color, this);

  LoadOverlayPageResource();
  EvaluateInOverlay("setOverlay", hinge_->GetOverlayName());
  EnsureEnableFrameOverlay();

  ScheduleUpdate();

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::highlightNode(
    std::unique_ptr<protocol::Overlay::HighlightConfig>
        highlight_inspector_object,
    Maybe<int> node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id,
    Maybe<String> selector_list) {
  Node* node = nullptr;
  protocol::Response response =
      dom_agent_->AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess()) {
    return response;
  }

  if (node->GetDocument().Lifecycle().GetState() <=
      DocumentLifecycle::LifecycleState::kInactive) {
    return protocol::Response::InvalidRequest(
        "The node's document is not active");
  }

  std::unique_ptr<InspectorHighlightConfig> highlight_config;
  response = HighlightConfigFromInspectorObject(
      std::move(highlight_inspector_object), &highlight_config);
  if (!response.IsSuccess()) {
    return response;
  }

  return SetInspectTool(MakeGarbageCollected<NodeHighlightTool>(
      this, GetFrontend(), node, selector_list.value_or(String()),
      std::move(highlight_config)));
}

protocol::Response InspectorOverlayAgent::setShowGridOverlays(
    std::unique_ptr<protocol::Array<protocol::Overlay::GridNodeHighlightConfig>>
        grid_node_highlight_configs) {
  if (!persistent_tool_) {
    persistent_tool_ =
        MakeGarbageCollected<PersistentTool>(this, GetFrontend());
  }

  HeapHashMap<WeakMember<Node>, std::unique_ptr<InspectorGridHighlightConfig>>
      configs;
  for (std::unique_ptr<protocol::Overlay::GridNodeHighlightConfig>& config :
       *grid_node_highlight_configs) {
    Node* node = nullptr;
    protocol::Response response =
        dom_agent_->AssertNode(config->getNodeId(), node);
    if (!response.IsSuccess()) {
      return response;
    }
    configs.insert(node, InspectorOverlayAgent::ToGridHighlightConfig(
                             config->getGridHighlightConfig()));
  }

  persistent_tool_->SetGridConfigs(std::move(configs));

  PickTheRightTool();

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowFlexOverlays(
    std::unique_ptr<protocol::Array<protocol::Overlay::FlexNodeHighlightConfig>>
        flex_node_highlight_configs) {
  if (!persistent_tool_) {
    persistent_tool_ =
        MakeGarbageCollected<PersistentTool>(this, GetFrontend());
  }

  HeapHashMap<WeakMember<Node>,
              std::unique_ptr<InspectorFlexContainerHighlightConfig>>
      configs;

  for (std::unique_ptr<protocol::Overlay::FlexNodeHighlightConfig>& config :
       *flex_node_highlight_configs) {
    Node* node = nullptr;
    protocol::Response response =
        dom_agent_->AssertNode(config->getNodeId(), node);
    if (!response.IsSuccess()) {
      return response;
    }
    configs.insert(node, InspectorOverlayAgent::ToFlexContainerHighlightConfig(
                             config->getFlexContainerHighlightConfig()));
  }

  persistent_tool_->SetFlexContainerConfigs(std::move(configs));

  PickTheRightTool();

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowScrollSnapOverlays(
    std::unique_ptr<
        protocol::Array<protocol::Overlay::ScrollSnapHighlightConfig>>
        scroll_snap_highlight_configs) {
  if (!persistent_tool_) {
    persistent_tool_ =
        MakeGarbageCollected<PersistentTool>(this, GetFrontend());
  }

  HeapHashMap<WeakMember<Node>,
              std::unique_ptr<InspectorScrollSnapContainerHighlightConfig>>
      configs;

  for (std::unique_ptr<protocol::Overlay::ScrollSnapHighlightConfig>& config :
       *scroll_snap_highlight_configs) {
    Node* node = nullptr;
    protocol::Response response =
        dom_agent_->AssertNode(config->getNodeId(), node);
    if (!response.IsSuccess()) {
      return response;
    }
    configs.insert(node,
                   InspectorOverlayAgent::ToScrollSnapContainerHighlightConfig(
                       config->getScrollSnapContainerHighlightConfig()));
  }

  persistent_tool_->SetScrollSnapConfigs(std::move(configs));

  PickTheRightTool();

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowContainerQueryOverlays(
    std::unique_ptr<
        protocol::Array<protocol::Overlay::ContainerQueryHighlightConfig>>
        container_query_highlight_configs) {
  if (!persistent_tool_) {
    persistent_tool_ =
        MakeGarbageCollected<PersistentTool>(this, GetFrontend());
  }

  HeapHashMap<WeakMember<Node>,
              std::unique_ptr<InspectorContainerQueryContainerHighlightConfig>>
      configs;

  for (std::unique_ptr<protocol::Overlay::ContainerQueryHighlightConfig>&
           config : *container_query_highlight_configs) {
    Node* node = nullptr;
    protocol::Response response =
        dom_agent_->AssertNode(config->getNodeId(), node);
    if (!response.IsSuccess()) {
      return response;
    }
    configs.insert(
        node, InspectorOverlayAgent::ToContainerQueryContainerHighlightConfig(
                  config->getContainerQueryContainerHighlightConfig()));
  }

  persistent_tool_->SetContainerQueryConfigs(std::move(configs));

  PickTheRightTool();

  return protocol::Response::Success();
}

protocol::Response InspectorOverlayAgent::setShowIsolatedElements(
    std::unique_ptr<
        protocol::Array<protocol::Overlay::IsolatedElementHighlightConfig>>
        isolated_element_highlight_con
"""


```
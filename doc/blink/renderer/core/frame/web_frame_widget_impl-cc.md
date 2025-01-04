Response:
The user wants a summary of the functionalities of the provided C++ code snippet for `web_frame_widget_impl.cc`.

I need to:
1. Identify the main responsibilities of this class based on the included headers and the methods it seems to be implementing.
2. Determine its relation to Javascript, HTML, and CSS, providing concrete examples.
3. Analyze if there's any logical inference happening in the code and exemplify it with input and output.
4. Pinpoint potential user or programming errors and illustrate them with examples.
5. Finally, provide a concise summary of the file's purpose as requested in the last instruction.

Based on the included headers and method names, `WebFrameWidgetImpl` seems to be a crucial component responsible for handling the interaction between the rendering engine (Blink) and the browser's UI. It deals with input events, drag and drop, focus management, and communication with the compositor. It also manages the lifecycle of the widget associated with a frame.
好的，根据你提供的代码片段， `blink/renderer/core/frame/web_frame_widget_impl.cc` 的第一部分主要负责以下功能：

**核心功能归纳:**

1. **作为WebLocalFrame的Widget实现:**  `WebFrameWidgetImpl` 是 `WebLocalFrame` 在渲染层（Renderer）中用于处理与窗口系统交互的部件（Widget）的实现。它负责处理诸如输入事件、焦点管理、拖放操作等。

2. **管理Compositor集成:** 它与 Compositor (cc 库) 集成，负责创建和管理 `LayerTreeHost`，这对于页面的渲染和动画至关重要。它处理与Compositor的通信，例如同步帧、处理合成输入等。

3. **输入事件处理:**  它接收并分发各种输入事件（鼠标、键盘、触摸等）给 Blink 渲染引擎进行处理。

4. **拖放支持:**  它实现了浏览器中的拖放操作，包括拖动开始、进入、悬停、离开和释放等各个阶段的处理。

5. **焦点管理:** 它参与管理页面的焦点，响应焦点变化事件。

6. **和Browser进程的通信桥梁:**  它通过 Mojo 接口 (`mojom::blink::FrameWidgetHostInterfaceBase`, `mojom::blink::FrameWidgetInterfaceBase`, `mojom::blink::WidgetHostInterfaceBase`, `mojom::blink::WidgetInterfaceBase`) 与浏览器进程进行通信，同步状态和发送指令。

7. **处理Stylus书写:** 实现了对 Stylus 书写输入的支持，包括检测书写开始、获取焦点元素信息等。

**与 Javascript, HTML, CSS 的关系举例:**

*   **Javascript:**
    *   当用户在网页上进行点击操作时（例如点击一个按钮），`WebFrameWidgetImpl` 会接收到鼠标事件，并将其传递给 Blink 的事件处理机制。 Javascript 代码中注册的事件监听器（例如 `onclick`）会被触发执行。
    *   假设 Javascript 代码调用了 `element.focus()` 方法来设置焦点，`WebFrameWidgetImpl` 会接收到焦点改变的通知，并更新内部状态，同时可能通知浏览器进程。
    *   当 Javascript 代码发起拖动操作 (例如使用 `draggable` 属性)， `WebFrameWidgetImpl` 会捕获拖动事件，并开始处理拖放流程。

*   **HTML:**
    *   当用户拖动 HTML 元素时，`WebFrameWidgetImpl` 的拖放逻辑会根据 HTML 结构和元素的属性（例如 `draggable`）来判断是否允许拖动，以及拖动的数据类型。
    *   当焦点移动到一个 HTML 表单元素（例如 `<input>`）时，`WebFrameWidgetImpl` 会更新焦点状态，并可能激活相关的输入法功能。

*   **CSS:**
    *   当鼠标悬停在一个应用了 CSS `hover` 伪类的元素上时，`WebFrameWidgetImpl` 接收到鼠标移动事件，Blink 渲染引擎会根据 CSS 规则更新元素的样式，从而改变元素的外观。
    *   CSS 的 `touch-action` 属性会影响 `WebFrameWidgetImpl` 如何处理触摸事件。例如，设置 `touch-action: none` 会阻止元素的默认触摸滚动行为。在 Stylus 书写的例子中，代码会检查元素的 `touch-action` 属性来判断是否允许书写。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. 用户在屏幕坐标 (100, 100) 处点击鼠标左键。
2. 该坐标对应于一个 `<a>` 链接元素。

**逻辑推理与输出:**

1. `WebFrameWidgetImpl` 接收到 `kMouseDown` 事件，坐标为 (100, 100)。
2. 它会将屏幕坐标转换为帧内的坐标。
3. 它会进行命中测试 (HitTest) 以确定点击位置的元素是 `<a>` 元素。
4. 如果该链接元素有对应的 Javascript 事件监听器 (例如 `onclick`)，则会触发该监听器。
5. 如果用户继续按下鼠标并释放，`WebFrameWidgetImpl` 会接收到 `kMouseUp` 事件。
6. 如果鼠标按下和释放都发生在同一个链接元素上，且没有阻止默认行为，则会触发链接的导航操作。
7. `WebFrameWidgetImpl` 可能通知浏览器进程进行页面导航。

**用户或编程常见的使用错误举例:**

*   **未正确处理拖放事件:** 开发者可能忘记在 Javascript 中注册必要的拖放事件监听器 (`dragenter`, `dragover`, `drop` 等)，导致拖放操作无法正常进行。例如，一个图片元素设置了 `draggable="true"`，但没有对应的 Javascript 代码处理 `drop` 事件，用户将图片拖放到目标区域时，不会发生任何预期行为。
*   **错误地阻止默认事件:**  开发者可能在事件监听器中错误地调用了 `event.preventDefault()`，导致浏览器的默认行为被阻止。例如，在 `dragover` 事件中调用 `event.preventDefault()` 是必要的，以允许 `drop` 事件发生，但如果在其他不恰当的事件中调用，可能会导致意外的行为。
*   **假设同步的Compositor交互:**  开发者可能会错误地假设与 Compositor 的通信是完全同步的，而实际上 Compositor 操作是异步的。这可能导致竞态条件和难以调试的问题。例如，在页面加载完成前就尝试获取 Compositor 的状态信息，可能会得到不一致的结果。
*   **在非UI线程访问UI相关的对象:** 虽然这个文件是 UI 线程的代码，但在其他部分，错误地在非 UI 线程访问例如 `LocalFrame` 或 `Document` 等对象，会导致崩溃或未定义的行为。

**本部分功能总结:**

这部分 `WebFrameWidgetImpl` 的代码主要负责作为渲染进程中 WebFrame 的窗口部件接口，接收和处理来自操作系统的底层输入事件，并通过与 Compositor 的交互来驱动页面的渲染更新。它也提供了基本的拖放和焦点管理功能，并为 Stylus 书写等高级输入功能提供了基础。它充当了 Blink 渲染引擎与宿主浏览器 UI 之间的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"

#include <memory>
#include <utility>

#include "base/auto_reset.h"
#include "base/debug/crash_logging.h"
#include "base/debug/dump_without_crashing.h"
#include "base/functional/callback_helpers.h"
#include "base/functional/function_ref.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/types/optional_ref.h"
#include "build/build_config.h"
#include "cc/animation/animation_host.h"
#include "cc/base/features.h"
#include "cc/input/browser_controls_offset_tags_info.h"
#include "cc/trees/compositor_commit_data.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/swap_promise.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/mojom/frame/intrinsic_sizing_info.mojom-blink.h"
#include "third_party/blink/public/mojom/input/input_handler.mojom-blink.h"
#include "third_party/blink/public/mojom/input/touch_event.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_non_composited_widget_client.h"
#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/accessibility/histogram_macros.h"
#include "third_party/blink/renderer/core/content_capture/content_capture_manager.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/ime/stylus_writing_gesture.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/events/current_input_event.h"
#include "third_party/blink/renderer/core/events/pointer_event_factory.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame_client.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/frame/screen_metrics_emulator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/anchor_element_viewport_position_tracker.h"
#include "third_party/blink/renderer/core/html/fenced_frame/document_fenced_frames.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/touch_action_util.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/drag_actions.h"
#include "third_party/blink/renderer/core/page/drag_data.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/paint/timing/first_meaningful_paint_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/graphics/animation_worklet_mutator_dispatcher_impl.h"
#include "third_party/blink/renderer/platform/graphics/compositor_mutator_client.h"
#include "third_party/blink/renderer/platform/graphics/paint_worklet_paint_dispatcher.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/widget/input/main_thread_event_queue.h"
#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_manager.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-blink.h"
#include "ui/base/mojom/menu_source_type.mojom-blink-forward.h"
#include "ui/base/mojom/window_show_state.mojom-blink.h"
#include "ui/gfx/geometry/point_conversions.h"

#if BUILDFLAG(IS_WIN)
#include "components/stylus_handwriting/win/features.h"
#endif  // BUILDFLAG(IS_WIN)

#if BUILDFLAG(IS_MAC)
#include "third_party/blink/renderer/core/editing/substring_util.h"
#include "third_party/blink/renderer/platform/fonts/mac/attributed_string_type_converter.h"
#include "ui/base/mojom/attributed_string.mojom-blink.h"
#include "ui/gfx/geometry/point.h"
#endif

namespace WTF {

template <>
struct CrossThreadCopier<blink::WebFrameWidgetImpl::PromiseCallbacks>
    : public CrossThreadCopierByValuePassThrough<
          blink::WebFrameWidgetImpl::PromiseCallbacks> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

using ::ui::mojom::blink::DragOperation;

void ForEachLocalFrameControlledByWidget(
    LocalFrame* frame,
    base::FunctionRef<void(WebLocalFrameImpl*)> callback) {
  callback(WebLocalFrameImpl::FromFrame(frame));
  for (Frame* child = frame->FirstChild(); child;
       child = child->NextSibling()) {
    if (auto* local_child = DynamicTo<LocalFrame>(child)) {
      ForEachLocalFrameControlledByWidget(local_child, callback);
    }
  }
}

// Iterate the remote children that will be controlled by the widget. Skip over
// any RemoteFrames have have another LocalFrame root as their parent.
void ForEachRemoteFrameChildrenControlledByWidget(
    Frame* frame,
    base::FunctionRef<void(RemoteFrame*)> callback) {
  for (Frame* child = frame->Tree().FirstChild(); child;
       child = child->Tree().NextSibling()) {
    if (auto* remote_frame = DynamicTo<RemoteFrame>(child)) {
      callback(remote_frame);
      ForEachRemoteFrameChildrenControlledByWidget(remote_frame, callback);
    } else if (auto* local_frame = DynamicTo<LocalFrame>(child)) {
      // If iteration arrives at a local root then don't descend as it will be
      // controlled by another widget.
      if (!local_frame->IsLocalRoot()) {
        ForEachRemoteFrameChildrenControlledByWidget(local_frame, callback);
      }
    }
  }

  if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
    if (Document* document = local_frame->GetDocument()) {
      // Iterate on any fenced frames owned by a local frame.
      if (auto* fenced_frames = DocumentFencedFrames::Get(*document)) {
        for (HTMLFencedFrameElement* fenced_frame :
             fenced_frames->GetFencedFrames()) {
          callback(To<RemoteFrame>(fenced_frame->ContentFrame()));
        }
      }
    }
  }
}

viz::FrameSinkId GetRemoteFrameSinkId(const HitTestResult& result) {
  Node* node = result.InnerNode();
  auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node);
  if (!frame_owner || !frame_owner->ContentFrame() ||
      !frame_owner->ContentFrame()->IsRemoteFrame())
    return viz::FrameSinkId();

  RemoteFrame* remote_frame = To<RemoteFrame>(frame_owner->ContentFrame());
  if (remote_frame->IsIgnoredForHitTest())
    return viz::FrameSinkId();
  LayoutObject* object = node->GetLayoutObject();
  DCHECK(object);
  if (!object->IsBox())
    return viz::FrameSinkId();

  PhysicalOffset local_point(ToRoundedPoint(result.LocalPoint()));
  if (!To<LayoutBox>(object)->ComputedCSSContentBoxRect().Contains(local_point))
    return viz::FrameSinkId();

  return remote_frame->GetFrameSinkId();
}

bool IsElementNotNullAndEditable(Element* element) {
  if (!element)
    return false;

  if (IsEditable(*element))
    return true;

  auto* text_control = ToTextControlOrNull(element);
  if (text_control && !text_control->IsDisabledOrReadOnly())
    return true;

  if (EqualIgnoringASCIICase(element->FastGetAttribute(html_names::kRoleAttr),
                             "textbox")) {
    return true;
  }

  return false;
}

bool& InputDisabledPerBrowsingContextGroup(
    const base::UnguessableToken& token) {
  using BrowsingContextGroupMap = std::map<base::UnguessableToken, bool>;
  DEFINE_STATIC_LOCAL(BrowsingContextGroupMap, values, ());
  return values[token];
}

// Get the root editable HTMLElement container that supports stylus handwriting.
Element* GetStylusHandwritingControlFromNode(const Node* node) {
  if (!node) {
    return nullptr;
  }
  Element* editable_control = EnclosingTextControl(node);
  if (!editable_control) {
    editable_control = RootEditableElement(*node);
  }
  if (!editable_control) {
    return nullptr;
  }
  const TouchAction effective_touch_action =
      touch_action_util::ComputeEffectiveTouchAction(*editable_control);
  if ((effective_touch_action & TouchAction::kInternalNotWritable) !=
      TouchAction::kInternalNotWritable) {
    return editable_control;
  }
  return nullptr;
}

#if BUILDFLAG(IS_WIN)
// Compute a PlainTextRange contained by `scope` relative to `pivot_position`
// that at most contains 2x `proximate_character_half_limit` characters.
// The range will be clamped, but may conceptually be represented with the
// following range notation:
//   [pivot_position - proximate_character_half_limit,
//    pivot_position + proximate_character_half_limit)
PlainTextRange ShellHandwritingProximateTextRange(
    const ContainerNode& scope,
    const Position& pivot_position,
    wtf_size_t proximate_character_half_limit) {
  CHECK(!pivot_position.IsNull());
  CHECK(proximate_character_half_limit);
  const EphemeralRange scope_range = EphemeralRange::RangeOfContents(scope);
  if (scope_range.IsCollapsed()) {
    return PlainTextRange();
  }

  const PlainTextRange pivot_to_end_text_range = PlainTextRange::Create(
      scope, EphemeralRange(pivot_position, scope_range.EndPosition()));

  const PlainTextRange result(
      base::ClampSub(pivot_to_end_text_range.Start(),
                     proximate_character_half_limit),
      base::ClampMin(base::ClampAdd(pivot_to_end_text_range.Start(),
                                    proximate_character_half_limit),
                     pivot_to_end_text_range.End()));
  CHECK_LE(result.length(), proximate_character_half_limit * 2);
  return result;
}
#endif  // BUILDFLAG(IS_WIN)

}  // namespace

// WebFrameWidget ------------------------------------------------------------

bool WebFrameWidgetImpl::ignore_input_events_ = false;

// static
void WebFrameWidgetImpl::SetIgnoreInputEvents(
    const base::UnguessableToken& browsing_context_group_token,
    bool value) {
  if (base::FeatureList::IsEnabled(
          features::kPausePagesPerBrowsingContextGroup)) {
    CHECK_NE(InputDisabledPerBrowsingContextGroup(browsing_context_group_token),
             value);
    InputDisabledPerBrowsingContextGroup(browsing_context_group_token) = value;
  } else {
    CHECK_NE(ignore_input_events_, value);
    ignore_input_events_ = value;
  }
}

// static
bool WebFrameWidgetImpl::IgnoreInputEvents(
    const base::UnguessableToken& browsing_context_group_token) {
  if (base::FeatureList::IsEnabled(
          features::kPausePagesPerBrowsingContextGroup)) {
    return InputDisabledPerBrowsingContextGroup(browsing_context_group_token);
  } else {
    return ignore_input_events_;
  }
}

WebFrameWidgetImpl::WebFrameWidgetImpl(
    base::PassKey<WebLocalFrame>,
    CrossVariantMojoAssociatedRemote<mojom::blink::FrameWidgetHostInterfaceBase>
        frame_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
        frame_widget,
    CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
        widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
        widget,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const viz::FrameSinkId& frame_sink_id,
    bool hidden,
    bool never_composited,
    bool is_for_child_local_root,
    bool is_for_nested_main_frame,
    bool is_for_scalable_page)
    : widget_base_(std::make_unique<WidgetBase>(
          /*widget_base_client=*/this,
          std::move(widget_host),
          std::move(widget),
          task_runner,
          hidden,
          never_composited,
          /*is_embedded=*/is_for_child_local_root || is_for_nested_main_frame,
          is_for_scalable_page)),
      frame_sink_id_(frame_sink_id),
      is_for_child_local_root_(is_for_child_local_root),
      is_for_scalable_page_(is_for_scalable_page) {
  DCHECK(task_runner);
  if (is_for_nested_main_frame)
    main_data().is_for_nested_main_frame = is_for_nested_main_frame;
  frame_widget_host_.Bind(std::move(frame_widget_host), task_runner);
  receiver_.Bind(std::move(frame_widget), task_runner);
}

WebFrameWidgetImpl::~WebFrameWidgetImpl() {
  // Ensure that Close is called and we aren't releasing |widget_base_| in the
  // destructor.
  // TODO(crbug.com/1139104): This CHECK can be changed to a DCHECK once
  // the issue is solved.
  CHECK(!widget_base_);
}

void WebFrameWidgetImpl::BindLocalRoot(WebLocalFrame& local_root) {
  local_root_ = To<WebLocalFrameImpl>(local_root);
  CHECK(local_root_ && local_root_->GetFrame());
  if (!IsHidden()) {
    animation_frame_timing_monitor_ =
        MakeGarbageCollected<AnimationFrameTimingMonitor>(
            *this, local_root_->GetFrame()->GetProbeSink());
  }
}

bool WebFrameWidgetImpl::ForTopMostMainFrame() const {
  return ForMainFrame() && !main_data().is_for_nested_main_frame;
}

void WebFrameWidgetImpl::Close(DetachReason detach_reason) {
  TRACE_EVENT0("navigation", "WebFrameWidgetImpl::Close");
  base::ScopedUmaHistogramTimer histogram_timer(
      "Navigation.WebFrameWidgetImpl.Close");
  // TODO(bokan): This seems wrong since the page may have other still-active
  // frame widgets. See also: https://crbug.com/1344531.
  GetPage()->WillStopCompositing();

  if (ForMainFrame()) {
    // Closing the WebFrameWidgetImpl happens in response to the local main
    // frame being detached from the Page/WebViewImpl.
    View()->SetMainFrameViewWidget(nullptr);
  }

  if (animation_frame_timing_monitor_) {
    animation_frame_timing_monitor_->Shutdown();
    animation_frame_timing_monitor_.Clear();
  }

  mutator_dispatcher_ = nullptr;
  local_root_ = nullptr;
  // Shut down the widget, but potentially delay the release of the resources
  // for LayerTreeView if we're closing because of a navigation. This is to
  // prevent delaying the navigation commit, as releasing the LayerTreeView
  // resources blocks on the compositor thread.
  bool delay_release =
      (base::FeatureList::IsEnabled(
           blink::features::kDelayLayerTreeViewDeletionOnLocalSwap) &&
       detach_reason == DetachReason::kNavigation);
  widget_base_->Shutdown(delay_release);
  widget_base_.reset();
  // These WeakPtrs must be invalidated for WidgetInputHandlerManager at the
  // same time as the WidgetBase is.
  input_handler_weak_ptr_factory_.InvalidateWeakPtrs();
  receiver_.reset();
  input_target_receiver_.reset();
}

WebLocalFrame* WebFrameWidgetImpl::LocalRoot() const {
  return local_root_.Get();
}

bool WebFrameWidgetImpl::RequestedMainFramePending() {
  return View() && View()->does_composite() && LayerTreeHost() &&
         LayerTreeHost()->RequestedMainFramePending();
}

ukm::UkmRecorder* WebFrameWidgetImpl::MainFrameUkmRecorder() {
  DCHECK(local_root_);
  if (!local_root_->IsOutermostMainFrame()) {
    return nullptr;
  }

  if (!local_root_->GetFrame() || !local_root_->GetFrame()->DomWindow()) {
    return nullptr;
  }

  return local_root_->GetFrame()->DomWindow()->UkmRecorder();
}
ukm::SourceId WebFrameWidgetImpl::MainFrameUkmSourceId() {
  DCHECK(local_root_);
  if (!local_root_->IsOutermostMainFrame()) {
    return ukm::kInvalidSourceId;
  }

  if (!local_root_->GetFrame() || !local_root_->GetFrame()->DomWindow()) {
    return ukm::kInvalidSourceId;
  }

  return local_root_->GetFrame()->DomWindow()->UkmSourceID();
}

gfx::Rect WebFrameWidgetImpl::ComputeBlockBound(
    const gfx::Point& point_in_root_frame,
    bool ignore_clipping) const {
  HitTestLocation location(local_root_->GetFrameView()->ConvertFromRootFrame(
      PhysicalOffset(point_in_root_frame)));
  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kReadOnly | HitTestRequest::kActive |
      (ignore_clipping ? HitTestRequest::kIgnoreClipping : 0);
  HitTestResult result =
      local_root_->GetFrame()->GetEventHandler().HitTestResultAtLocation(
          location, hit_type);
  result.SetToShadowHostIfInUAShadowRoot();

  Node* node = result.InnerNodeOrImageMapImage();
  if (!node)
    return gfx::Rect();

  // Find the block type node based on the hit node.
  // FIXME: This wants to walk flat tree with
  // LayoutTreeBuilderTraversal::parent().
  while (node &&
         (!node->GetLayoutObject() || node->GetLayoutObject()->IsInline()))
    node = LayoutTreeBuilderTraversal::Parent(*node);

  // Return the bounding box in the root frame's coordinate space.
  if (node) {
    gfx::Rect absolute_rect =
        node->GetLayoutObject()->AbsoluteBoundingBoxRect();
    LocalFrame* frame = node->GetDocument().GetFrame();
    return frame->View()->ConvertToRootFrame(absolute_rect);
  }
  return gfx::Rect();
}

void WebFrameWidgetImpl::DragTargetDragEnter(
    const WebDragData& web_drag_data,
    const gfx::PointF& point_in_viewport,
    const gfx::PointF& screen_point,
    DragOperationsMask operations_allowed,
    uint32_t key_modifiers,
    DragTargetDragEnterCallback callback) {
  auto* target = local_root_->GetFrame()->DocumentAtPoint(
      PhysicalOffset::FromPointFRound(ViewportToRootFrame(point_in_viewport)));

  // Any execution context should do the work since no file should ever be
  // created during drag events.
  current_drag_data_ = DataObject::Create(
      target ? target->GetExecutionContext() : nullptr, web_drag_data);
  operations_allowed_ = operations_allowed;

  DragTargetDragEnterOrOver(point_in_viewport, screen_point, kDragEnter,
                            key_modifiers);

  std::move(callback).Run(drag_operation_.operation,
                          drag_operation_.document_is_handling_drag);
}

void WebFrameWidgetImpl::DragTargetDragOver(
    const gfx::PointF& point_in_viewport,
    const gfx::PointF& screen_point,
    DragOperationsMask operations_allowed,
    uint32_t key_modifiers,
    DragTargetDragOverCallback callback) {
  operations_allowed_ = operations_allowed;

  DragTargetDragEnterOrOver(point_in_viewport, screen_point, kDragOver,
                            key_modifiers);

  std::move(callback).Run(drag_operation_.operation,
                          drag_operation_.document_is_handling_drag);
}

void WebFrameWidgetImpl::DragTargetDragLeave(
    const gfx::PointF& point_in_viewport,
    const gfx::PointF& screen_point) {
  base::ScopedClosureRunner runner(
      WTF::BindOnce(&WebFrameWidgetImpl::CancelDrag, WrapWeakPersistent(this)));
  if (ShouldIgnoreInputEvents() || !current_drag_data_) {
    return;
  }

  gfx::PointF point_in_root_frame(ViewportToRootFrame(point_in_viewport));
  DragData drag_data(current_drag_data_.Get(), point_in_root_frame,
                     screen_point, operations_allowed_,
                     /*force_default_action=*/false);

  GetPage()->GetDragController().DragExited(&drag_data,
                                            *local_root_->GetFrame());

  // FIXME: why is the drag scroll timer not stopped here?
}

void WebFrameWidgetImpl::DragTargetDrop(const WebDragData& web_drag_data,
                                        const gfx::PointF& point_in_viewport,
                                        const gfx::PointF& screen_point,
                                        uint32_t key_modifiers,
                                        base::OnceClosure callback) {
  base::ScopedClosureRunner callback_runner(std::move(callback));
  base::ScopedClosureRunner runner(
      WTF::BindOnce(&WebFrameWidgetImpl::CancelDrag, WrapWeakPersistent(this)));

  if (ShouldIgnoreInputEvents() || !current_drag_data_) {
    return;
  }

  auto* target = local_root_->GetFrame()->DocumentAtPoint(
      PhysicalOffset::FromPointFRound(ViewportToRootFrame(point_in_viewport)));

  current_drag_data_ = DataObject::Create(
      target ? target->GetExecutionContext() : nullptr, web_drag_data);

  // If this webview transitions from the "drop accepting" state to the "not
  // accepting" state, then our IPC message reply indicating that may be in-
  // flight, or else delayed by javascript processing in this webview.  If a
  // drop happens before our IPC reply has reached the browser process, then
  // the browser forwards the drop to this webview.  So only allow a drop to
  // proceed if our webview drag operation state is not DragOperation::kNone.

  if (drag_operation_.operation == DragOperation::kNone) {
    // IPC RACE CONDITION: do not allow this drop.
    DragTargetDragLeave(point_in_viewport, screen_point);
    return;
  }

  current_drag_data_->SetModifiers(key_modifiers);
  DragData drag_data(current_drag_data_.Get(),
                     ViewportToRootFrame(point_in_viewport), screen_point,
                     operations_allowed_, web_drag_data.ForceDefaultAction());
  GetPage()->GetDragController().PerformDrag(&drag_data,
                                             *local_root_->GetFrame());
}

void WebFrameWidgetImpl::DragSourceEndedAt(const gfx::PointF& point_in_viewport,
                                           const gfx::PointF& screen_point,
                                           DragOperation operation,
                                           base::OnceClosure callback) {
  base::ScopedClosureRunner callback_runner(std::move(callback));
  base::ScopedClosureRunner runner(
      WTF::BindOnce(&WebFrameWidgetImpl::DragSourceSystemDragEnded,
                    WrapWeakPersistent(this)));

  if (ShouldIgnoreInputEvents()) {
    return;
  }

  WebMouseEvent fake_mouse_move(
      WebInputEvent::Type::kMouseMove,
      GetPage()->GetVisualViewport().ViewportToRootFrame(point_in_viewport),
      screen_point, WebPointerProperties::Button::kLeft, 0,
      WebInputEvent::kNoModifiers, base::TimeTicks::Now());
  fake_mouse_move.SetFrameScale(1);
  local_root_->GetFrame()->GetEventHandler().DragSourceEndedAt(fake_mouse_move,
                                                               operation);
}

void WebFrameWidgetImpl::DragSourceSystemDragEnded() {
  CancelDrag();

  // It's possible for this to be false if the source stopped dragging at a
  // previous page.
  if (!doing_drag_and_drop_) {
    return;
  }
  GetPage()->GetDragController().DragEnded();
  doing_drag_and_drop_ = false;
}

gfx::Rect WebFrameWidgetImpl::GetAbsoluteCaretBounds() {
  LocalFrame* local_frame = GetPage()->GetFocusController().FocusedFrame();
  if (local_frame) {
    auto& selection = local_frame->Selection();
    if (selection.GetSelectionInDOMTree().IsCaret())
      return selection.AbsoluteCaretBounds();
  }
  return gfx::Rect();
}

void WebFrameWidgetImpl::OnStartStylusWriting(
#if BUILDFLAG(IS_WIN)
    const gfx::Rect& focus_rect_in_widget,
#endif  // BUILDFLAG(IS_WIN)
    OnStartStylusWritingCallback callback) {
  mojom::blink::StylusWritingFocusResultPtr focus_result;
  // Focus the stylus writable element for current touch sequence as we have
  // detected writing has started.
  LocalFrame* frame = LocalRootImpl()->GetFrame();
  if (!frame) {
    std::move(callback).Run(std::move(focus_result));
    return;
  }

  Element* stylus_writable_container = nullptr;
#if BUILDFLAG(IS_WIN)
  PositionWithAffinity proximate_pivot_position;
  if (!focus_rect_in_widget.IsEmpty()) {
    // TODO(crbug.com/355578906): Hit test using `focus_rect_in_widget` rather
    // than its CenterPoint(). The size of the rect will include the
    // "target screen area" inflated with "distance threshold" from
    // ITfFocusHandwritingTargetArgs::GetPointerTargetInfo.
    gfx::PointF frame_point =
        frame->GetPage()->GetVisualViewport().ViewportToRootFrame(
            gfx::PointF(focus_rect_in_widget.CenterPoint()));
    proximate_pivot_position =
        frame->PositionForPoint(PhysicalOffset::FromPointFFloor(frame_point));
    stylus_writable_container = GetStylusHandwritingControlFromNode(
        proximate_pivot_position.AnchorNode());
  }
#endif  // BUILDFLAG(IS_WIN)
  if (!stylus_writable_container) {
    stylus_writable_container = GetStylusHandwritingControlFromNode(
        frame->GetEventHandler().CurrentTouchDownElement());
    // TODO(crbug.com/355578906): Set `proximate_pivot_position` relative to
    // the touch down point that assigned `CurrentTouchDownElement()`.
  }
  if (!stylus_writable_container) {
    std::move(callback).Run(std::move(focus_result));
    return;
  }

  // TODO(crbug.com/355578906): If the element wasn't focused already, ensure
  // the caret position is set to `proximate_pivot_position`.
  stylus_writable_container->Focus(FocusParams(FocusTrigger::kUserGesture));
  Element* focused_element = FocusedElement();
  // Since the element can change after it gets focused, we just verify if
  // the focused element is editable to continue writing.
  if (IsElementNotNullAndEditable(focused_element)) {
    focus_result = mojom::blink::StylusWritingFocusResult::New();
    focus_result->focused_edit_bounds = focused_element->BoundsInWidget();
    focus_result->caret_bounds =
        frame->View()->FrameToViewport(GetAbsoluteCaretBounds());
#if BUILDFLAG(IS_WIN)
    focus_result->proximate_bounds =
        ComputeProximateCharacterBounds(proximate_pivot_position);
#endif  // BUILDFLAG(IS_WIN)
  }

  std::move(callback).Run(std::move(focus_result));
}

#if BUILDFLAG(IS_ANDROID)
void WebFrameWidgetImpl::PassImeRenderWidgetHost(
    mojo::PendingRemote<mojom::blink::ImeRenderWidgetHost> pending_remote) {
  ime_render_widget_host_ =
      HeapMojoRemote<mojom::blink::ImeRenderWidgetHost>(nullptr);
  ime_render_widget_host_.Bind(
      std::move(pending_remote),
      local_root_->GetTaskRunner(TaskType::kInternalDefault));
}
#endif  // BUILDFLAG(IS_ANDROID)

void WebFrameWidgetImpl::NotifyClearedDisplayedGraphics() {
  if (!LocalRootImpl() || !LocalRootImpl()->GetFrame() ||
      !LocalRootImpl()->GetFrame()->GetDocument()) {
    return;
  }

  auto& document = *LocalRootImpl()->GetFrame()->GetDocument();
  // If we've already been revealed, then we may have produced a frame already.
  if (document.domWindow() && document.domWindow()->HasBeenRevealed()) {
    return;
  }

  // Skip any incoming cross document transitions here.
  if (ViewTransition* transition =
          ViewTransitionUtils::GetIncomingCrossDocumentTransition(document)) {
    transition->SkipTransition();
  }
}

void WebFrameWidgetImpl::HandleStylusWritingGestureAction(
    mojom::blink::StylusWritingGestureDataPtr gesture_data,
    HandleStylusWritingGestureActionCallback callback) {
  LocalFrame* focused_frame = FocusedLocalFrameInWidget();
  if (!focused_frame) {
    std::move(callback).Run(mojom::blink::Hand
"""


```
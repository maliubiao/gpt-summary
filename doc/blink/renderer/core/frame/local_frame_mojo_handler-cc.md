Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze `local_frame_mojo_handler.cc` and identify its functions, especially those related to JavaScript, HTML, and CSS. The request also asks for examples, logical inferences, common errors, and a summary.

2. **Initial Scan for Keywords:** I'll quickly scan the code for keywords and common terms associated with web technologies:
    * **JavaScript:** "Script", "V8", "Evaluate", "Context", "Promise", "Console", "Error"
    * **HTML:** "Element", "Document", "Frame", "Fullscreen", "Selection", "Focus", "Meta", "Image", "Video", "Link", "Object", "Embed"
    * **CSS:**  "FrameOwnerProperties" (relates to styling), "color_scheme", "preferred_color_scheme", "MediaQuery"
    * **Mojo:** Obvious from the filename and repeated usage of `mojom::blink::` types and `BindNewEndpointAndPassReceiver`. This signals inter-process communication.

3. **Identify Core Functionality through Method Names:** I will go through the methods defined within the `LocalFrameMojoHandler` class. The method names are often indicative of their purpose. I will group related methods together:

    * **Frame Management:** `WasAttachedAsLocalMainFrame`, `DidDetachFrame`, `ClosePageForTesting`, `StopLoading`, `Collapse`, `EnableViewSourceMode`, `SwapInImmediately`
    * **Focus & Selection:** `Focus`, `ClearFocusedElement`, `GetTextSurroundingSelection`, `AdvanceFocusInFrame`, `AdvanceFocusForIME`
    * **JavaScript Execution:** `JavaScriptMethodExecuteRequest`, `JavaScriptExecuteRequestInIsolatedWorld`, `JavaScriptMethodExecuteRequestForTests`
    * **Console & Errors:** `AddMessageToConsole`, `ReportContentSecurityPolicyViolation`
    * **Frame Properties & Lifecycle:** `SetFrameOwnerProperties`, `NotifyUserActivation`, `CheckCompleted`, `BeforeUnload`, `DidUpdateFramePolicy`, `OnFrameVisibilityChanged`
    * **Media Interaction:** `MediaPlayerActionAt`, `RequestVideoFrameAtWithBoundsHint`
    * **Image Handling:** `CopyImageAt`, `SaveImageAt`
    * **Feature Usage Tracking:** `ReportBlinkFeatureUsage`
    * **Rendering:** `RenderFallbackContent`
    * **Inter-Frame Communication:** `PostMessageEvent`
    * **Device Posture:** `GetDevicePosture`, `OverrideDevicePostureForEmulation`, `DisableDevicePostureOverrideForEmulation`, `OnPostureChanged`
    * **Internal Mojo Setup:** `BindToLocalFrameReceiver`, `BindToMainFrameReceiver`, `BindFullscreenVideoElementReceiver`

4. **Analyze Relationships with Web Technologies:** For each identified function group, I'll think about how it relates to JavaScript, HTML, and CSS:

    * **JavaScript Execution:**  Directly involves executing JavaScript code within the frame's context. The `ScriptController` and `ScriptState` are key.
    * **HTML & DOM Interaction:** Many methods directly manipulate or query the DOM: setting properties, focusing elements, getting selections, interacting with media elements, handling events.
    * **CSS & Styling:** `SetFrameOwnerProperties` directly affects frame styling. `OnPostureChanged` and media queries highlight the interaction between device state and CSS.

5. **Construct Examples:** For the significant relationships, I'll create simple examples to illustrate the connection:

    * **JavaScript:**  `JavaScriptMethodExecuteRequest` example with `console.log`.
    * **HTML:** `SetFrameOwnerProperties` example demonstrating margin changes.
    * **CSS:** `OnPostureChanged` example illustrating a media query reacting to posture changes.

6. **Identify Logical Inferences:**  I'll look for methods where the output can be logically inferred based on the input:

    * **`GetTextSurroundingSelection`:** Input: `max_length`. Output: text within that limit.

7. **Consider User/Programming Errors:** I'll think about common mistakes when using related web APIs or how the Mojo interface might be misused:

    * **JavaScript execution:** Errors in the provided script.
    * **Mojo interface:** Potential for dangling pointers if the receiver isn't properly managed.

8. **Summarize the Functionality:** I will synthesize the findings into a concise summary, highlighting the core responsibilities of `LocalFrameMojoHandler`.

9. **Address the "Part 1" Constraint:** Since this is part 1 of 2, I will focus on the functionalities covered by the provided code snippet and avoid speculating on what might be in part 2. The summary will reflect the completeness of the analysis for this specific section.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on individual methods. **Correction:** Group related methods for better organization and understanding of broader functionalities.
* **Initial thought:**  Provide overly technical explanations. **Correction:**  Focus on explaining the *what* and *why* in relation to web technologies, rather than deep implementation details.
* **Initial thought:** Miss the significance of Mojo. **Correction:** Recognize Mojo's role in inter-process communication and how this class acts as a bridge.
* **Initial thought:** Overlook CSS aspects. **Correction:**  Identify methods that, while not directly manipulating CSS properties, influence layout and styling (e.g., `SetFrameOwnerProperties`).

By following these steps, I can systematically analyze the code, address all aspects of the request, and provide a comprehensive and well-structured answer.
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/local_frame_mojo_handler.h"

// ... other includes ...

namespace blink {

namespace {

// ... helper functions ...

}  // namespace

// ... ActiveURLMessageFilter class ...

LocalFrameMojoHandler::LocalFrameMojoHandler(blink::LocalFrame& frame)
    : frame_(frame) {
  frame.GetRemoteNavigationAssociatedInterfaces()->GetInterface(
      back_forward_cache_controller_host_remote_.BindNewEndpointAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalDefault)));
#if BUILDFLAG(IS_MAC)
  frame.GetBrowserInterfaceBroker().GetInterface(
      text_input_host_.BindNewPipeAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalDefault)));
#endif

  frame.GetBrowserInterfaceBroker().GetInterface(
      non_associated_local_frame_host_remote_.BindNewPipeAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalHighPriorityLocalFrame)));

  frame.GetRemoteNavigationAssociatedInterfaces()->GetInterface(
      local_frame_host_remote_.BindNewEndpointAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalDefault)));

  auto* registry = frame.GetInterfaceRegistry();
  registry->AddAssociatedInterface(
      WTF::BindRepeating(&LocalFrameMojoHandler::BindToLocalFrameReceiver,
                         WrapWeakPersistent(this)));
  registry->AddAssociatedInterface(WTF::BindRepeating(
      &LocalFrameMojoHandler::BindFullscreenVideoElementReceiver,
      WrapWeakPersistent(this)));
}

// ... Trace method ...

void LocalFrameMojoHandler::WasAttachedAsLocalMainFrame() {
  frame_->GetInterfaceRegistry()->AddAssociatedInterface(
      WTF::BindRepeating(&LocalFrameMojoHandler::BindToMainFrameReceiver,
                         WrapWeakPersistent(this)));
}

void LocalFrameMojoHandler::DidDetachFrame() {
  local_frame_receiver_.reset();
  main_frame_receiver_.reset();
  // TODO(tkent): Should we reset other receivers?
}

// ... other getter methods for mojo interfaces ...

void LocalFrameMojoHandler::BindToLocalFrameReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::LocalFrame> receiver) {
  if (frame_->IsDetached())
    return;

  local_frame_receiver_.Bind(std::move(receiver),
                             frame_->GetTaskRunner(TaskType::kInternalDefault));
  local_frame_receiver_.SetFilter(
      std::make_unique<ActiveURLMessageFilter>(frame_));
}

void LocalFrameMojoHandler::BindToMainFrameReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::LocalMainFrame> receiver) {
  if (frame_->IsDetached())
    return;

  main_frame_receiver_.Bind(std::move(receiver),
                            frame_->GetTaskRunner(TaskType::kInternalDefault));
  main_frame_receiver_.SetFilter(
      std::make_unique<ActiveURLMessageFilter>(frame_));
}

void LocalFrameMojoHandler::BindFullscreenVideoElementReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::FullscreenVideoElementHandler>
        receiver) {
  if (frame_->IsDetached())
    return;

  fullscreen_video_receiver_.Bind(
      std::move(receiver), frame_->GetTaskRunner(TaskType::kInternalDefault));
  fullscreen_video_receiver_.SetFilter(
      std::make_unique<ActiveURLMessageFilter>(frame_));
}

void LocalFrameMojoHandler::GetTextSurroundingSelection(
    uint32_t max_length,
    GetTextSurroundingSelectionCallback callback) {
  SurroundingText surrounding_text(frame_, max_length);

  if (surrounding_text.IsEmpty()) {
    std::move(callback).Run(g_empty_string, 0, 0);
    return;
  }

  std::move(callback).Run(surrounding_text.TextContent(),
                          surrounding_text.StartOffsetInTextContent(),
                          surrounding_text.EndOffsetInTextContent());
}

void LocalFrameMojoHandler::SendInterventionReport(const String& id,
                                                   const String& message) {
  Intervention::GenerateReport(frame_, id, message);
}

void LocalFrameMojoHandler::SetFrameOwnerProperties(
    mojom::blink::FrameOwnerPropertiesPtr properties) {
  GetDocument()->WillChangeFrameOwnerProperties(
      properties->margin_width, properties->margin_height,
      properties->scrollbar_mode, properties->is_display_none,
      properties->color_scheme, properties->preferred_color_scheme);

  frame_->ApplyFrameOwnerProperties(std::move(properties));
}

void LocalFrameMojoHandler::NotifyUserActivation(
    mojom::blink::UserActivationNotificationType notification_type) {
  frame_->NotifyUserActivation(notification_type);
}

void LocalFrameMojoHandler::NotifyVirtualKeyboardOverlayRect(
    const gfx::Rect& keyboard_rect) {
  Page* page = GetPage();
  if (!page)
    return;

  blink::LocalFrame& local_frame_root = frame_->LocalFrameRoot();
  const float window_to_viewport_factor =
      page->GetChromeClient().WindowToViewportScalar(&local_frame_root, 1.0f);
  const float zoom_factor = local_frame_root.LayoutZoomFactor();
  const float scale_factor = zoom_factor / window_to_viewport_factor;
  gfx::Rect scaled_rect(keyboard_rect.x() / scale_factor,
                        keyboard_rect.y() / scale_factor,
                        keyboard_rect.width() / scale_factor,
                        keyboard_rect.height() / scale_factor);

  frame_->NotifyVirtualKeyboardOverlayRectObservers(scaled_rect);
}

void LocalFrameMojoHandler::AddMessageToConsole(
    mojom::blink::ConsoleMessageLevel level,
    const WTF::String& message,
    bool discard_duplicates) {
  GetDocument()->AddConsoleMessage(
      MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther, level, message),
      discard_duplicates);
}

void LocalFrameMojoHandler::SwapInImmediately() {
  frame_->SwapIn();
  DomWindow()->GetScriptController().UpdateDocument();
}

void LocalFrameMojoHandler::CheckCompleted() {
  frame_->CheckCompleted();
}

void LocalFrameMojoHandler::StopLoading() {
  frame_->Loader().StopAllLoaders(/*abort_client=*/true);
  if (!frame_->IsAttached())
    return;
  WebLocalFrameClient* client = frame_->Client()->GetWebFrame()->Client();
  if (client)
    client->OnStopLoading();
}

void LocalFrameMojoHandler::Collapse(bool collapsed) {
  FrameOwner* owner = frame_->Owner();
  To<HTMLFrameOwnerElement>(owner)->SetCollapsed(collapsed);
}

void LocalFrameMojoHandler::EnableViewSourceMode() {
  DCHECK(frame_->IsOutermostMainFrame());
  frame_->SetInViewSourceMode(true);
}

void LocalFrameMojoHandler::Focus() {
  frame_->FocusImpl();
}

void LocalFrameMojoHandler::ClearFocusedElement() {
  Document* document = GetDocument();
  Element* old_focused_element = document->FocusedElement();
  document->ClearFocusedElement();
  if (!old_focused_element)
    return;

  document->UpdateStyleAndLayoutTree();
  if (IsEditable(*old_focused_element) ||
      old_focused_element->IsTextControl()) {
    frame_->Selection().Clear();
  }
}

void LocalFrameMojoHandler::CopyImageAt(const gfx::Point& window_point) {
  gfx::Point viewport_position =
      frame_->GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  frame_->CopyImageAtViewportPoint(viewport_position);
}

void LocalFrameMojoHandler::SaveImageAt(const gfx::Point& window_point) {
  frame_->SaveImageAt(window_point);
}

void LocalFrameMojoHandler::ReportBlinkFeatureUsage(
    const Vector<mojom::blink::WebFeature>& features) {
  DCHECK(!features.empty());
  auto* document = GetDocument();
  DCHECK(document);
  for (const auto& feature : features)
    document->CountUse(feature);
}

void LocalFrameMojoHandler::RenderFallbackContent() {
  frame_->RenderFallbackContent();
}

void LocalFrameMojoHandler::BeforeUnload(bool is_reload,
                                         BeforeUnloadCallback callback) {
  base::TimeTicks before_unload_start_time = base::TimeTicks::Now();
  bool proceed = frame_->Loader().ShouldClose(is_reload);
  DCHECK(!callback.is_null());
  base::TimeTicks before_unload_end_time = base::TimeTicks::Now();
  std::move(callback).Run(proceed, before_unload_start_time,
                          before_unload_end_time);
}

void LocalFrameMojoHandler::MediaPlayerActionAt(
    const gfx::Point& window_point,
    blink::mojom::blink::MediaPlayerActionPtr action) {
  gfx::Point viewport_position =
      frame_->GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  frame_->MediaPlayerActionAtViewportPoint(viewport_position, action->type,
                                           action->enable);
}

void LocalFrameMojoHandler::RequestVideoFrameAtWithBoundsHint(
    const gfx::Point& window_point,
    const gfx::Size& max_size,
    int max_area,
    RequestVideoFrameAtWithBoundsHintCallback callback) {
  gfx::Point viewport_position =
      frame_->GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  frame_->RequestVideoFrameAtWithBoundsHint(viewport_position, max_size,
                                            max_area, std::move(callback));
}

void LocalFrameMojoHandler::AdvanceFocusInFrame(
    mojom::blink::FocusType focus_type,
    const std::optional<RemoteFrameToken>& source_frame_token) {
  RemoteFrame* source_frame =
      source_frame_token ? SourceFrameForOptionalToken(*source_frame_token)
                         : nullptr;
  if (!source_frame) {
    SetInitialFocus(focus_type == mojom::blink::FocusType::kBackward);
    return;
  }

  GetPage()->GetFocusController().AdvanceFocusAcrossFrames(
      focus_type, source_frame, frame_);
}

void LocalFrameMojoHandler::AdvanceFocusForIME(
    mojom::blink::FocusType focus_type) {
  auto* focused_frame = GetPage()->GetFocusController().FocusedFrame();
  if (focused_frame != frame_)
    return;

  DCHECK(GetDocument());
  Element* element = GetDocument()->FocusedElement();
  if (!element)
    return;

  Element* next_element =
      GetPage()->GetFocusController().NextFocusableElementForImeAndAutofill(
          element, focus_type);
  if (!next_element)
    return;

  next_element->scrollIntoViewIfNeeded(true /*centerIfNeeded*/);
  next_element->Focus(FocusParams(FocusTrigger::kUserGesture));
}

void LocalFrameMojoHandler::ReportContentSecurityPolicyViolation(
    network::mojom::blink::CSPViolationPtr violation) {
  auto source_location = std::make_unique<SourceLocation>(
      violation->source_location->url, String(),
      violation->source_location->line, violation->source_location->column,
      nullptr);

  frame_->Console().AddMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kSecurity,
      mojom::blink::ConsoleMessageLevel::kError, violation->console_message,
      source_location->Clone()));

  auto directive_type =
      ContentSecurityPolicy::GetDirectiveType(violation->effective_directive);
  blink::LocalFrame* context_frame =
      directive_type == network::mojom::blink::CSPDirectiveName::FrameAncestors
          ? frame_
          : nullptr;

  DomWindow()->GetContentSecurityPolicy()->ReportViolation(
      violation->directive, directive_type, violation->console_message,
      violation->blocked_url, violation->report_endpoints,
      violation->use_reporting_api, violation->header, violation->type,
      ContentSecurityPolicyViolationType::kURLViolation,
      std::move(source_location), context_frame, nullptr /* Element */);
}

void LocalFrameMojoHandler::DidUpdateFramePolicy(
    const FramePolicy& frame_policy) {
  SECURITY_CHECK(IsA<RemoteFrameOwner>(frame_->Owner()));
  To<RemoteFrameOwner>(frame_->Owner())->SetFramePolicy(frame_policy);
}

void LocalFrameMojoHandler::OnFrameVisibilityChanged(
    mojom::blink::FrameVisibility visibility) {
  if (frame_->Client() && frame_->Client()->GetWebFrame() &&
      frame_->Client()->GetWebFrame()->Client()) {
    frame_->Client()->GetWebFrame()->Client()->OnFrameVisibilityChanged(
        visibility);
  }
}

void LocalFrameMojoHandler::OnPostureChanged(
    mojom::blink::DevicePostureType posture) {
  if (!RuntimeEnabledFeatures::DevicePostureEnabled(
          GetDocument()->GetExecutionContext())) {
    return;
  }
  current_device_posture_ = posture;
  frame_->MediaQueryAffectingValueChangedForLocalSubtree(
      MediaValueChange::kOther);
}

void LocalFrameMojoHandler::PostMessageEvent(
    const std::optional<RemoteFrameToken>& source_frame_token,
    const String& source_origin,
    const String& target_origin,
    BlinkTransferableMessage message) {
  frame_->PostMessageEvent(source_frame_token, source_origin, target_origin,
                           std::move(message));
}

void LocalFrameMojoHandler::JavaScriptMethodExecuteRequest(
    const String& object_name,
    const String& method_name,
    base::Value::List args,
    JavaScriptMethodExecuteRequestCallback callback) {
  std::unique_ptr<WebV8ValueConverter> converter =
      Platform::Current()->CreateWebV8ValueConverter();
  converter->SetDateAllowed(true);
  converter->SetRegExpAllowed(true);

  v8::MaybeLocal<v8::Value> maybe_result = CallMethodOnFrame(
      frame_.get(), object_name, method_name, std::move(args), converter.get());

  mojom::blink::JavaScriptExecutionResultType type =
      mojom::blink::JavaScriptExecutionResultType::kSuccess;
  base::Value result;
  if (v8::Local<v8::Value> local_result; maybe_result.ToLocal(&local_result)) {
    result = GetJavaScriptExecutionResult(local_result,
                                         MainWorldScriptContext(frame_.get()),
                                         converter.get());
  } else {
    type = mojom::blink::JavaScriptExecutionResultType::kException;
  }

  std::move(callback).Run(type, result);
}
```

## 对 `blink/renderer/core/frame/local_frame_mojo_handler.cc` 的功能归纳（第 1 部分）

`LocalFrameMojoHandler` 类是 Chromium Blink 渲染引擎中 `LocalFrame` 的一个助手类，主要负责处理来自浏览器进程的、通过 Mojo IPC（进程间通信）传递给该 `LocalFrame` 的各种请求和事件。 它的核心功能是**作为 `LocalFrame` 与浏览器进程之间的桥梁**，将浏览器进程的指令转化为 `LocalFrame` 内部的操作。

以下是该文件目前所展示的功能归纳：

**1. Mojo 接口绑定与管理:**

*   负责绑定和管理多个 Mojo 接口接收器 (Receivers)，这些接口定义了浏览器进程可以向 `LocalFrame` 发送的消息类型。 绑定的接口包括：
    *   `mojom::blink::LocalFrame`: 用于通用的 frame 操作。
    *   `mojom::blink::LocalMainFrame`: 用于主 frame 特有的操作。
    *   `mojom::blink::FullscreenVideoElementHandler`: 用于处理全屏视频元素相关的请求。
*   使用 `ActiveURLMessageFilter` 来在处理 Mojo 消息时设置活动 URL，用于调试目的。

**2. Frame 生命周期管理与状态同步:**

*   处理 frame 的附加 (`WasAttachedAsLocalMainFrame`) 和分离 (`DidDetachFrame`) 事件。
*   提供方法来停止 frame 的加载 (`StopLoading`)。
*   处理 frame 的立即交换显示 (`SwapInImmediately`)。
*   通知 frame 完成检查 (`CheckCompleted`)。
*   处理 frame 的折叠状态 (`Collapse`).
*   支持进入视图源模式 (`EnableViewSourceMode`).

**3. 焦点管理:**

*   提供设置 frame 焦点 (`Focus`) 和清除焦点元素 (`ClearFocusedElement`) 的功能。
*   支持在 frame 内前进或后退焦点 (`AdvanceFocusInFrame`)，可以指定起始 frame。
*   支持为 IME (输入法编辑器) 进行焦点前进 (`AdvanceFocusForIME`).

**4. 文本选择与操作:**

*   获取当前选区周围的文本 (`GetTextSurroundingSelection`).

**5. 用户交互通知:**

*   通知 frame 发生了用户激活 (`NotifyUserActivation`)。
*   通知 frame 虚拟键盘的覆盖区域 (`NotifyVirtualKeyboardOverlayRect`)。

**6. 控制台消息:**

*   向 frame 的控制台添加消息 (`AddMessageToConsole`)。

**7. 帧属性设置:**

*   设置 frame 所有者属性，例如 margin、scrollbar 模式、显示状态和颜色方案 (`SetFrameOwnerProperties`)。

**8. 图像操作:**

*   支持复制指定位置的图像 (`CopyImageAt`).
*   支持保存指定位置的图像 (`SaveImageAt`).

**9. Blink 特性使用报告:**

*   报告 Blink 特性的使用情况 (`ReportBlinkFeatureUsage`).

**10. 回退内容渲染:**

*   触发渲染回退内容 (`RenderFallbackContent`).

**11. 页面卸载处理:**

*   处理页面的卸载事件 (`BeforeUnload`)，判断是否应该允许页面关闭。

**12. 多媒体操作:**

*   在指定位置执行媒体播放器动作，例如播放或暂停视频 (`MediaPlayerActionAt`).
*   请求在指定位置的视频帧 (`RequestVideoFrameAtWithBoundsHint`).

**13. 安全策略 (CSP) 违规报告:**

*   报告内容安全策略 (CSP) 违规 (`ReportContentSecurityPolicyViolation`).

**14. 帧策略更新:**

*   更新 frame 策略 (`DidUpdateFramePolicy`).

**15. 帧可见性变化通知:**

*   通知 frame 的可见性发生了变化 (`OnFrameVisibilityChanged`).

**16. 设备姿态处理:**

*   处理设备姿态的变化 (`OnPostureChanged`).

**17. 跨文档消息传递:**

*   处理通过 `postMessage` API 发送的消息事件 (`PostMessageEvent`).

**18. JavaScript 方法执行:**

*   允许浏览器进程请求在 frame 中执行指定的 JavaScript 对象的方法 (`JavaScriptMethodExecuteRequest`)。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **JavaScript:** `JavaScriptMethodExecuteRequest` 允许浏览器进程调用 frame 内 JavaScript 代码。例如，浏览器进程可以请求执行 `window.scrollTo(0, 100)` 来滚动页面。
    *   **假设输入:** `object_name` 为 `"window"`, `method_name` 为 `"scrollTo"`, `args` 为 `[0, 100]`.
    *   **预期输出:**  页面滚动到垂直位置 100 像素处。
*   **HTML:** `SetFrameOwnerProperties` 可以影响渲染 frame 的 HTML 元素。 例如，设置 `properties->margin_width` 和 `properties->margin_height` 会改变 `<iframe>` 或 `<frame>` 元素的边距。
    *   **假设输入:** `properties->margin_width` 为 20, `properties->margin_height` 为 30。
    *   **预期输出:**  如果该 `LocalFrame` 对应一个 `<iframe>` 元素，则该元素的边距将被设置为左右 20px，上下 30px。
*   **CSS:** `SetFrameOwnerProperties` 中的 `properties->color_scheme` 和 `properties->preferred_color_scheme` 会影响 frame 的 CSS 颜色主题。
    *   **假设输入:** `properties->color_scheme` 为 `mojom::blink::ColorScheme::kDark`, `properties->preferred_color_scheme` 为 `mojom::blink::PreferredColorScheme::kDark`.
    *   **预期输出:**  Frame 内的渲染可能会根据暗色主题进行调整，例如背景色和文字颜色可能会发生变化。
*   **HTML & JavaScript:** `GetTextSurroundingSelection` 涉及到获取用户在 HTML 文档中选择的文本。
    *   **假设输入:** 用户在页面上选中了 "Hello World"。`max_length` 为 100。
    *   **预期输出:**  `callback` 将会收到包含 "Hello World" 的字符串，以及它在文档中的起始和结束偏移量。
*   **CSP (Content Security Policy):** `ReportContentSecurityPolicyViolation` 用于报告浏览器检测到的违反 CSP 策略的情况，这与 HTML 中通过 `<meta>` 标签或 HTTP 头定义的安全策略相关。
    *   **假设输入:**  一个内联的 `<script>` 标签被 CSP 阻止执行。
    *   **预期输出:**  会生成一个 `ConsoleMessage`，并在开发者工具中显示 CSP 违规信息。

**用户或编程常见的使用错误举例:**

*   **JavaScript 方法执行错误:**  在 `JavaScriptMethodExecuteRequest` 中，如果提供的 `object_name` 或 `method_name` 不存在，或者提供的参数类型不正确，会导致 JavaScript 运行时错误。
    *   **举例:** 尝试调用一个不存在的全局函数 `nonExistentFunction()`. 这将导致 `maybe_result` 为空，`type` 被设置为 `kException`.
*   **Mojo 接口未正确绑定:**  如果在 frame 分离后尝试通过绑定的 Mojo 接口发送消息，可能会导致程序崩溃或未定义行为，因为接收端可能已经被销毁。 这也是 `DidDetachFrame` 中需要 `reset()` 这些接收器的原因。

总而言之，`LocalFrameMojoHandler` 是一个关键的组件，它封装了 `LocalFrame` 的各种能力，并通过 Mojo 接口暴露给浏览器进程，使得浏览器进程能够对渲染过程进行细粒度的控制和管理。

### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_mojo_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/local_frame_mojo_handler.h"

#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/input/browser_controls_offset_tags_info.h"
#include "services/network/public/cpp/url_loader_completion_status.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/chrome_debug_urls.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/frame/frame_owner_element_type.h"
#include "third_party/blink/public/common/page_state/page_state.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/media_player_action.mojom-blink.h"
#include "third_party/blink/public/mojom/opengraph/metadata.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink-forward.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fullscreen_options.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/ignore_opens_during_unload_count_incrementer.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/surrounding_text.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/intervention.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/pausable_script_executor.h"
#include "third_party/blink/renderer/core/frame/remote_frame_owner.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/frame/savable_resources.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/view_transition/page_swap_event.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"

#if BUILDFLAG(IS_MAC)
#include "base/apple/foundation_util.h"
#include "third_party/blink/renderer/core/editing/substring_util.h"
#include "third_party/blink/renderer/platform/fonts/mac/attributed_string_type_converter.h"
#include "ui/base/mojom/attributed_string.mojom-blink.h"
#endif

namespace blink {

namespace {

constexpr char kInvalidWorldID[] =
    "JavaScriptExecuteRequestInIsolatedWorld gets an invalid world id.";

#if BUILDFLAG(IS_MAC)
size_t GetCurrentCursorPositionInFrame(LocalFrame* local_frame) {
  blink::WebRange range =
      WebLocalFrameImpl::FromFrame(local_frame)->SelectionRange();
  return range.IsNull() ? size_t{0} : static_cast<size_t>(range.StartOffset());
}
#endif

RemoteFrame* SourceFrameForOptionalToken(
    const std::optional<RemoteFrameToken>& source_frame_token) {
  if (!source_frame_token)
    return nullptr;
  return RemoteFrame::FromFrameToken(source_frame_token.value());
}

v8::Local<v8::Context> MainWorldScriptContext(LocalFrame* local_frame) {
  ScriptState* script_state = ToScriptStateForMainWorld(local_frame);
  DCHECK(script_state);
  return script_state->GetContext();
}

base::Value GetJavaScriptExecutionResult(v8::Local<v8::Value> result,
                                         v8::Local<v8::Context> context,
                                         WebV8ValueConverter* converter) {
  if (!result.IsEmpty()) {
    v8::Context::Scope context_scope(context);
    std::unique_ptr<base::Value> new_value =
        converter->FromV8Value(result, context);
    if (new_value)
      return std::move(*new_value);
  }
  return base::Value();
}

v8::MaybeLocal<v8::Value> GetProperty(v8::Local<v8::Context> context,
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

v8::MaybeLocal<v8::Value> CallMethodOnFrame(LocalFrame* local_frame,
                                            const String& object_name,
                                            const String& method_name,
                                            base::Value::List arguments,
                                            WebV8ValueConverter* converter) {
  v8::Local<v8::Context> context = MainWorldScriptContext(local_frame);

  v8::Context::Scope context_scope(context);
  v8::LocalVector<v8::Value> args(context->GetIsolate());
  for (const auto& argument : arguments) {
    args.push_back(converter->ToV8Value(argument, context));
  }

  v8::Local<v8::Value> object;
  v8::Local<v8::Value> method;
  if (!GetProperty(context, context->Global(), object_name).ToLocal(&object) ||
      !GetProperty(context, object, method_name).ToLocal(&method) ||
      !method->IsFunction()) {
    return v8::MaybeLocal<v8::Value>();
  }
  CHECK(method->IsFunction());

  return local_frame->DomWindow()
      ->GetScriptController()
      .EvaluateMethodInMainWorld(v8::Local<v8::Function>::Cast(method), object,
                                 static_cast<int>(args.size()), args.data());
}

HitTestResult HitTestResultForRootFramePos(
    LocalFrame* frame,
    const PhysicalOffset& pos_in_root_frame) {
  HitTestLocation location(
      frame->View()->ConvertFromRootFrame(pos_in_root_frame));
  HitTestResult result = frame->GetEventHandler().HitTestResultAtLocation(
      location, HitTestRequest::kReadOnly | HitTestRequest::kActive);
  result.SetToShadowHostIfInUAShadowRoot();
  return result;
}

void ParseOpenGraphProperty(const HTMLMetaElement& element,
                            const Document& document,
                            mojom::blink::OpenGraphMetadata* metadata) {
  if (element.Property() == "og:image" && !metadata->image)
    metadata->image = document.CompleteURL(element.Content());

  // Non-OpenGraph, non-standard thing that some sites use the same way:
  // using <meta itemprop="image" content="$url">, which means the same thing
  // as <meta property="og:image" content="$url".
  if (element.Itemprop() == "image" && !metadata->image)
    metadata->image = document.CompleteURL(element.Content());
}

// Convert the error to a string so it can be sent back to the test.
//
// We try to use .stack property so that the error message contains a stack
// trace, but otherwise fallback to .toString().
v8::Local<v8::String> ErrorToString(ScriptState* script_state,
                                    v8::Local<v8::Value> error) {
  if (!error.IsEmpty()) {
    v8::Local<v8::Context> context = script_state->GetContext();
    v8::Local<v8::Value> value =
        v8::TryCatch::StackTrace(context, error).FromMaybe(error);
    v8::Local<v8::String> value_string;
    if (value->ToString(context).ToLocal(&value_string))
      return value_string;
  }

  v8::Isolate* isolate = script_state->GetIsolate();
  return v8::String::NewFromUtf8Literal(isolate, "Unknown Failure");
}

class JavaScriptExecuteRequestForTestsHandler
    : public GarbageCollected<JavaScriptExecuteRequestForTestsHandler> {
 public:
  class PromiseCallback : public ThenCallable<IDLAny, PromiseCallback> {
   public:
    PromiseCallback(JavaScriptExecuteRequestForTestsHandler& handler,
                    mojom::blink::JavaScriptExecutionResultType type)
        : handler_(handler), type_(type) {}

    void React(ScriptState* script_state, ScriptValue value) {
      DCHECK(script_state);
      if (type_ == mojom::blink::JavaScriptExecutionResultType::kSuccess)
        handler_->SendSuccess(script_state, value.V8Value());
      else
        handler_->SendException(script_state, value.V8Value());
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(handler_);
      ThenCallable<IDLAny, PromiseCallback>::Trace(visitor);
    }

   private:
    Member<JavaScriptExecuteRequestForTestsHandler> handler_;
    const mojom::blink::JavaScriptExecutionResultType type_;
  };

  explicit JavaScriptExecuteRequestForTestsHandler(
      LocalFrameMojoHandler::JavaScriptExecuteRequestForTestsCallback callback)
      : callback_(std::move(callback)) {}

  ~JavaScriptExecuteRequestForTestsHandler() {
    if (callback_) {
      std::move(callback_).Run(
          mojom::blink::JavaScriptExecutionResultType::kException,
          base::Value(
              "JavaScriptExecuteRequestForTestsHandler was destroyed without "
              "running the callback. This is usually caused by Promise "
              "resolution functions getting destroyed without being called."));
    }
  }

  PromiseCallback* CreateResolveCallback(ScriptState* script_state,
                                         LocalFrame* frame) {
    return MakeGarbageCollected<PromiseCallback>(
        *this, mojom::blink::JavaScriptExecutionResultType::kSuccess);
  }

  PromiseCallback* CreateRejectCallback(ScriptState* script_state,
                                        LocalFrame* frame) {
    return MakeGarbageCollected<PromiseCallback>(
        *this, mojom::blink::JavaScriptExecutionResultType::kException);
  }

  void SendSuccess(ScriptState* script_state, v8::Local<v8::Value> value) {
    SendResponse(script_state,
                 mojom::blink::JavaScriptExecutionResultType::kSuccess, value);
  }

  void SendException(ScriptState* script_state, v8::Local<v8::Value> error) {
    SendResponse(script_state,
                 mojom::blink::JavaScriptExecutionResultType::kException,
                 ErrorToString(script_state, error));
  }

  void Trace(Visitor* visitor) const {}

 private:
  void SendResponse(ScriptState* script_state,
                    mojom::blink::JavaScriptExecutionResultType type,
                    v8::Local<v8::Value> value) {
    std::unique_ptr<WebV8ValueConverter> converter =
        Platform::Current()->CreateWebV8ValueConverter();
    converter->SetDateAllowed(true);
    converter->SetRegExpAllowed(true);

    CHECK(callback_) << "Promise resolved twice";
    std::move(callback_).Run(
        type, GetJavaScriptExecutionResult(value, script_state->GetContext(),
                                           converter.get()));
  }

  LocalFrameMojoHandler::JavaScriptExecuteRequestForTestsCallback callback_;
};

}  // namespace

ActiveURLMessageFilter::~ActiveURLMessageFilter() {
  if (debug_url_set_) {
    Platform::Current()->SetActiveURL(WebURL(), WebString());
  }
}

bool ActiveURLMessageFilter::WillDispatch(mojo::Message* message) {
  // We expect local_frame_ always to be set because this MessageFilter
  // is owned by the LocalFrame. We do not want to introduce a Persistent
  // reference so we don't cause a cycle. If you hit this CHECK then you
  // likely didn't reset your mojo receiver in Detach.
  CHECK(local_frame_);
  debug_url_set_ = true;
  Platform::Current()->SetActiveURL(local_frame_->GetDocument()->Url(),
                                    local_frame_->Top()
                                        ->GetSecurityContext()
                                        ->GetSecurityOrigin()
                                        ->ToString());
  return true;
}

void ActiveURLMessageFilter::DidDispatchOrReject(mojo::Message* message,
                                                 bool accepted) {
  Platform::Current()->SetActiveURL(WebURL(), WebString());
  debug_url_set_ = false;
}

LocalFrameMojoHandler::LocalFrameMojoHandler(blink::LocalFrame& frame)
    : frame_(frame) {
  frame.GetRemoteNavigationAssociatedInterfaces()->GetInterface(
      back_forward_cache_controller_host_remote_.BindNewEndpointAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalDefault)));
#if BUILDFLAG(IS_MAC)
  // It should be bound before accessing TextInputHost which is the interface to
  // respond to GetCharacterIndexAtPoint.
  frame.GetBrowserInterfaceBroker().GetInterface(
      text_input_host_.BindNewPipeAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalDefault)));
#endif

  frame.GetBrowserInterfaceBroker().GetInterface(
      non_associated_local_frame_host_remote_.BindNewPipeAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalHighPriorityLocalFrame)));

  frame.GetRemoteNavigationAssociatedInterfaces()->GetInterface(
      local_frame_host_remote_.BindNewEndpointAndPassReceiver(
          frame.GetTaskRunner(TaskType::kInternalDefault)));

  auto* registry = frame.GetInterfaceRegistry();
  registry->AddAssociatedInterface(
      WTF::BindRepeating(&LocalFrameMojoHandler::BindToLocalFrameReceiver,
                         WrapWeakPersistent(this)));
  registry->AddAssociatedInterface(WTF::BindRepeating(
      &LocalFrameMojoHandler::BindFullscreenVideoElementReceiver,
      WrapWeakPersistent(this)));
}

void LocalFrameMojoHandler::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(back_forward_cache_controller_host_remote_);
#if BUILDFLAG(IS_MAC)
  visitor->Trace(text_input_host_);
#endif
  visitor->Trace(reporting_service_);
  visitor->Trace(device_posture_provider_service_);
  visitor->Trace(local_frame_host_remote_);
  visitor->Trace(non_associated_local_frame_host_remote_);
  visitor->Trace(local_frame_receiver_);
  visitor->Trace(main_frame_receiver_);
  visitor->Trace(fullscreen_video_receiver_);
  visitor->Trace(device_posture_receiver_);
}

void LocalFrameMojoHandler::WasAttachedAsLocalMainFrame() {
  frame_->GetInterfaceRegistry()->AddAssociatedInterface(
      WTF::BindRepeating(&LocalFrameMojoHandler::BindToMainFrameReceiver,
                         WrapWeakPersistent(this)));
}

void LocalFrameMojoHandler::DidDetachFrame() {
  // We reset receivers explicitly because HeapMojoReceiver does not
  // automatically reset on context destruction.
  local_frame_receiver_.reset();
  main_frame_receiver_.reset();
  // TODO(tkent): Should we reset other receivers?
}

void LocalFrameMojoHandler::ClosePageForTesting() {
  ClosePage(base::DoNothing());
}

mojom::blink::BackForwardCacheControllerHost&
LocalFrameMojoHandler::BackForwardCacheControllerHostRemote() {
  return *back_forward_cache_controller_host_remote_.get();
}

#if BUILDFLAG(IS_MAC)
mojom::blink::TextInputHost& LocalFrameMojoHandler::TextInputHost() {
  DCHECK(text_input_host_.is_bound());
  return *text_input_host_.get();
}

void LocalFrameMojoHandler::ResetTextInputHostForTesting() {
  text_input_host_.reset();
}

void LocalFrameMojoHandler::RebindTextInputHostForTesting() {
  frame_->GetBrowserInterfaceBroker().GetInterface(
      text_input_host_.BindNewPipeAndPassReceiver(
          frame_->GetTaskRunner(TaskType::kInternalDefault)));
}
#endif

mojom::blink::ReportingServiceProxy* LocalFrameMojoHandler::ReportingService() {
  if (!reporting_service_.is_bound()) {
    frame_->GetBrowserInterfaceBroker().GetInterface(
        reporting_service_.BindNewPipeAndPassReceiver(
            frame_->GetTaskRunner(TaskType::kInternalDefault)));
  }
  return reporting_service_.get();
}

mojom::blink::DevicePostureProvider*
LocalFrameMojoHandler::DevicePostureProvider() {
  if (!frame_->IsLocalRoot()) {
    return frame_->LocalFrameRoot().GetDevicePostureProvider();
  }

  DCHECK(frame_->IsLocalRoot());
  if (!device_posture_provider_service_.is_bound()) {
    auto task_runner = frame_->GetTaskRunner(TaskType::kInternalDefault);
    frame_->GetBrowserInterfaceBroker().GetInterface(
        device_posture_provider_service_.BindNewPipeAndPassReceiver(
            task_runner));
  }
  return device_posture_provider_service_.get();
}

mojom::blink::DevicePostureType LocalFrameMojoHandler::GetDevicePosture() {
  if (!frame_->IsLocalRoot()) {
    return frame_->LocalFrameRoot().GetDevicePosture();
  }

  DCHECK(frame_->IsLocalRoot());
  if (device_posture_receiver_.is_bound()) {
    return current_device_posture_;
  }

  auto task_runner = frame_->GetTaskRunner(TaskType::kInternalDefault);
  DevicePostureProvider()->AddListenerAndGetCurrentPosture(
      device_posture_receiver_.BindNewPipeAndPassRemote(task_runner),
      WTF::BindOnce(&LocalFrameMojoHandler::OnPostureChanged,
                    WrapPersistent(this)));
  return current_device_posture_;
}

void LocalFrameMojoHandler::OverrideDevicePostureForEmulation(
    mojom::blink::DevicePostureType device_posture_param) {
  DevicePostureProvider()->OverrideDevicePostureForEmulation(
      device_posture_param);
}

void LocalFrameMojoHandler::DisableDevicePostureOverrideForEmulation() {
  DevicePostureProvider()->DisableDevicePostureOverrideForEmulation();
}

Page* LocalFrameMojoHandler::GetPage() const {
  return frame_->GetPage();
}

LocalDOMWindow* LocalFrameMojoHandler::DomWindow() const {
  return frame_->DomWindow();
}

Document* LocalFrameMojoHandler::GetDocument() const {
  return frame_->GetDocument();
}

void LocalFrameMojoHandler::BindToLocalFrameReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::LocalFrame> receiver) {
  if (frame_->IsDetached())
    return;

  local_frame_receiver_.Bind(std::move(receiver),
                             frame_->GetTaskRunner(TaskType::kInternalDefault));
  local_frame_receiver_.SetFilter(
      std::make_unique<ActiveURLMessageFilter>(frame_));
}

void LocalFrameMojoHandler::BindToMainFrameReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::LocalMainFrame> receiver) {
  if (frame_->IsDetached())
    return;

  main_frame_receiver_.Bind(std::move(receiver),
                            frame_->GetTaskRunner(TaskType::kInternalDefault));
  main_frame_receiver_.SetFilter(
      std::make_unique<ActiveURLMessageFilter>(frame_));
}

void LocalFrameMojoHandler::BindFullscreenVideoElementReceiver(
    mojo::PendingAssociatedReceiver<mojom::blink::FullscreenVideoElementHandler>
        receiver) {
  if (frame_->IsDetached())
    return;

  fullscreen_video_receiver_.Bind(
      std::move(receiver), frame_->GetTaskRunner(TaskType::kInternalDefault));
  fullscreen_video_receiver_.SetFilter(
      std::make_unique<ActiveURLMessageFilter>(frame_));
}

void LocalFrameMojoHandler::GetTextSurroundingSelection(
    uint32_t max_length,
    GetTextSurroundingSelectionCallback callback) {
  SurroundingText surrounding_text(frame_, max_length);

  // |surrounding_text| might not be correctly initialized, for example if
  // |frame_->SelectionRange().IsNull()|, in other words, if there was no
  // selection.
  if (surrounding_text.IsEmpty()) {
    // Don't use WTF::String's default constructor so that we make sure that we
    // always send a valid empty string over the wire instead of a null pointer.
    std::move(callback).Run(g_empty_string, 0, 0);
    return;
  }

  std::move(callback).Run(surrounding_text.TextContent(),
                          surrounding_text.StartOffsetInTextContent(),
                          surrounding_text.EndOffsetInTextContent());
}

void LocalFrameMojoHandler::SendInterventionReport(const String& id,
                                                   const String& message) {
  Intervention::GenerateReport(frame_, id, message);
}

void LocalFrameMojoHandler::SetFrameOwnerProperties(
    mojom::blink::FrameOwnerPropertiesPtr properties) {
  GetDocument()->WillChangeFrameOwnerProperties(
      properties->margin_width, properties->margin_height,
      properties->scrollbar_mode, properties->is_display_none,
      properties->color_scheme, properties->preferred_color_scheme);

  frame_->ApplyFrameOwnerProperties(std::move(properties));
}

void LocalFrameMojoHandler::NotifyUserActivation(
    mojom::blink::UserActivationNotificationType notification_type) {
  frame_->NotifyUserActivation(notification_type);
}

void LocalFrameMojoHandler::NotifyVirtualKeyboardOverlayRect(
    const gfx::Rect& keyboard_rect) {
  Page* page = GetPage();
  if (!page)
    return;

  // The rect passed to us from content is in DIP, relative to the main frame.
  // This doesn't take the page's zoom factor into account so we must scale by
  // the inverse of the page zoom in order to get correct client coordinates.
  // WindowToViewportScalar is the device scale factor while LayoutZoomFactor is
  // the combination of the device scale factor and the zoom factor of the
  // page.
  blink::LocalFrame& local_frame_root = frame_->LocalFrameRoot();
  const float window_to_viewport_factor =
      page->GetChromeClient().WindowToViewportScalar(&local_frame_root, 1.0f);
  const float zoom_factor = local_frame_root.LayoutZoomFactor();
  const float scale_factor = zoom_factor / window_to_viewport_factor;
  gfx::Rect scaled_rect(keyboard_rect.x() / scale_factor,
                        keyboard_rect.y() / scale_factor,
                        keyboard_rect.width() / scale_factor,
                        keyboard_rect.height() / scale_factor);

  frame_->NotifyVirtualKeyboardOverlayRectObservers(scaled_rect);
}

void LocalFrameMojoHandler::AddMessageToConsole(
    mojom::blink::ConsoleMessageLevel level,
    const WTF::String& message,
    bool discard_duplicates) {
  GetDocument()->AddConsoleMessage(
      MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther, level, message),
      discard_duplicates);
}

void LocalFrameMojoHandler::SwapInImmediately() {
  frame_->SwapIn();
  // Normally, this happens as part of committing a cross-Document navigation.
  // However, there is no navigation being committed here. Instead, the browser
  // navigation code is optimistically early-swapping in this frame to replace a
  // crashed subframe after starting a navigation.
  //
  // While the provisional frame has a unique opaque origin, the Blink bindings
  // code still expects the WindowProxy to be initialized for the access check
  // failed callbacks.
  DomWindow()->GetScriptController().UpdateDocument();
}

void LocalFrameMojoHandler::CheckCompleted() {
  frame_->CheckCompleted();
}

void LocalFrameMojoHandler::StopLoading() {
  frame_->Loader().StopAllLoaders(/*abort_client=*/true);

  // The stopLoading handler may run script, which may cause this frame to be
  // detached/deleted. If that happens, return immediately.
  if (!frame_->IsAttached())
    return;

  // Notify RenderFrame observers.
  WebLocalFrameClient* client = frame_->Client()->GetWebFrame()->Client();
  if (client)
    client->OnStopLoading();
}

void LocalFrameMojoHandler::Collapse(bool collapsed) {
  FrameOwner* owner = frame_->Owner();
  To<HTMLFrameOwnerElement>(owner)->SetCollapsed(collapsed);
}

void LocalFrameMojoHandler::EnableViewSourceMode() {
  DCHECK(frame_->IsOutermostMainFrame());
  frame_->SetInViewSourceMode(true);
}

void LocalFrameMojoHandler::Focus() {
  frame_->FocusImpl();
}

void LocalFrameMojoHandler::ClearFocusedElement() {
  Document* document = GetDocument();
  Element* old_focused_element = document->FocusedElement();
  document->ClearFocusedElement();
  if (!old_focused_element)
    return;

  // If a text field has focus, we need to make sure the selection controller
  // knows to remove selection from it. Otherwise, the text field is still
  // processing keyboard events even though focus has been moved to the page and
  // keystrokes get eaten as a result.
  document->UpdateStyleAndLayoutTree();
  if (IsEditable(*old_focused_element) ||
      old_focused_element->IsTextControl()) {
    frame_->Selection().Clear();
  }
}

void LocalFrameMojoHandler::CopyImageAt(const gfx::Point& window_point) {
  gfx::Point viewport_position =
      frame_->GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  frame_->CopyImageAtViewportPoint(viewport_position);
}

void LocalFrameMojoHandler::SaveImageAt(const gfx::Point& window_point) {
  frame_->SaveImageAt(window_point);
}

void LocalFrameMojoHandler::ReportBlinkFeatureUsage(
    const Vector<mojom::blink::WebFeature>& features) {
  DCHECK(!features.empty());

  // Assimilate all features used/performed by the browser into UseCounter.
  auto* document = GetDocument();
  DCHECK(document);
  for (const auto& feature : features)
    document->CountUse(feature);
}

void LocalFrameMojoHandler::RenderFallbackContent() {
  frame_->RenderFallbackContent();
}

void LocalFrameMojoHandler::BeforeUnload(bool is_reload,
                                         BeforeUnloadCallback callback) {
  base::TimeTicks before_unload_start_time = base::TimeTicks::Now();

  // This will execute the BeforeUnload event in this frame and all of its
  // local descendant frames, including children of remote frames.  The browser
  // process will send separate IPCs to dispatch beforeunload in any
  // out-of-process child frames.
  bool proceed = frame_->Loader().ShouldClose(is_reload);

  DCHECK(!callback.is_null());
  base::TimeTicks before_unload_end_time = base::TimeTicks::Now();
  std::move(callback).Run(proceed, before_unload_start_time,
                          before_unload_end_time);
}

void LocalFrameMojoHandler::MediaPlayerActionAt(
    const gfx::Point& window_point,
    blink::mojom::blink::MediaPlayerActionPtr action) {
  gfx::Point viewport_position =
      frame_->GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  frame_->MediaPlayerActionAtViewportPoint(viewport_position, action->type,
                                           action->enable);
}

void LocalFrameMojoHandler::RequestVideoFrameAtWithBoundsHint(
    const gfx::Point& window_point,
    const gfx::Size& max_size,
    int max_area,
    RequestVideoFrameAtWithBoundsHintCallback callback) {
  gfx::Point viewport_position =
      frame_->GetWidgetForLocalRoot()->DIPsToRoundedBlinkSpace(window_point);
  frame_->RequestVideoFrameAtWithBoundsHint(viewport_position, max_size,
                                            max_area, std::move(callback));
}

void LocalFrameMojoHandler::AdvanceFocusInFrame(
    mojom::blink::FocusType focus_type,
    const std::optional<RemoteFrameToken>& source_frame_token) {
  RemoteFrame* source_frame =
      source_frame_token ? SourceFrameForOptionalToken(*source_frame_token)
                         : nullptr;
  if (!source_frame) {
    SetInitialFocus(focus_type == mojom::blink::FocusType::kBackward);
    return;
  }

  GetPage()->GetFocusController().AdvanceFocusAcrossFrames(
      focus_type, source_frame, frame_);
}

void LocalFrameMojoHandler::AdvanceFocusForIME(
    mojom::blink::FocusType focus_type) {
  auto* focused_frame = GetPage()->GetFocusController().FocusedFrame();
  if (focused_frame != frame_)
    return;

  DCHECK(GetDocument());
  Element* element = GetDocument()->FocusedElement();
  if (!element)
    return;

  Element* next_element =
      GetPage()->GetFocusController().NextFocusableElementForImeAndAutofill(
          element, focus_type);
  if (!next_element)
    return;

  next_element->scrollIntoViewIfNeeded(true /*centerIfNeeded*/);
  next_element->Focus(FocusParams(FocusTrigger::kUserGesture));
}

void LocalFrameMojoHandler::ReportContentSecurityPolicyViolation(
    network::mojom::blink::CSPViolationPtr violation) {
  auto source_location = std::make_unique<SourceLocation>(
      violation->source_location->url, String(),
      violation->source_location->line, violation->source_location->column,
      nullptr);

  frame_->Console().AddMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kSecurity,
      mojom::blink::ConsoleMessageLevel::kError, violation->console_message,
      source_location->Clone()));

  auto directive_type =
      ContentSecurityPolicy::GetDirectiveType(violation->effective_directive);
  blink::LocalFrame* context_frame =
      directive_type == network::mojom::blink::CSPDirectiveName::FrameAncestors
          ? frame_
          : nullptr;

  DomWindow()->GetContentSecurityPolicy()->ReportViolation(
      violation->directive, directive_type, violation->console_message,
      violation->blocked_url, violation->report_endpoints,
      violation->use_reporting_api, violation->header, violation->type,
      ContentSecurityPolicyViolationType::kURLViolation,
      std::move(source_location), context_frame, nullptr /* Element */);
}

void LocalFrameMojoHandler::DidUpdateFramePolicy(
    const FramePolicy& frame_policy) {
  // At the moment, this is only used to replicate sandbox flags and container
  // policy for frames with a remote owner.
  SECURITY_CHECK(IsA<RemoteFrameOwner>(frame_->Owner()));
  To<RemoteFrameOwner>(frame_->Owner())->SetFramePolicy(frame_policy);
}

void LocalFrameMojoHandler::OnFrameVisibilityChanged(
    mojom::blink::FrameVisibility visibility) {
  if (frame_->Client() && frame_->Client()->GetWebFrame() &&
      frame_->Client()->GetWebFrame()->Client()) {
    frame_->Client()->GetWebFrame()->Client()->OnFrameVisibilityChanged(
        visibility);
  }
}

void LocalFrameMojoHandler::OnPostureChanged(
    mojom::blink::DevicePostureType posture) {
  if (!RuntimeEnabledFeatures::DevicePostureEnabled(
          GetDocument()->GetExecutionContext())) {
    return;
  }
  current_device_posture_ = posture;
  // A change of the device posture requires re-evaluation of media queries
  // for the local frame subtree (the device posture affect the
  // "device-posture" feature).
  frame_->MediaQueryAffectingValueChangedForLocalSubtree(
      MediaValueChange::kOther);
}

void LocalFrameMojoHandler::PostMessageEvent(
    const std::optional<RemoteFrameToken>& source_frame_token,
    const String& source_origin,
    const String& target_origin,
    BlinkTransferableMessage message) {
  frame_->PostMessageEvent(source_frame_token, source_origin, target_origin,
                           std::move(message));
}

void LocalFrameMojoHandler::JavaScriptMethodExecuteRequest(
    const String& o
```
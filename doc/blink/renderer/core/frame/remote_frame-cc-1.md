Response:
The user wants a summary of the functionality of the provided C++ code snippet from `remote_frame.cc`. I need to explain what the code does, focusing on its relationship with web technologies like JavaScript, HTML, and CSS. I also need to provide examples of logical reasoning (input/output) and common usage errors if applicable. Since this is the second part of the request, I should focus on summarizing the functionality of *this specific* code block, assuming the first part covered earlier sections of the same file.

**Plan:**

1. **Identify the core purpose:**  This section of the code seems to handle communication and synchronization of visual properties and other frame-related information between different processes in Chromium.
2. **Break down functionality by method:** Analyze what each function does.
3. **Connect to web technologies:** Explain how these operations relate to rendering, layout, and JavaScript interactions.
4. **Provide logical reasoning examples:** Illustrate how certain inputs to these functions would lead to specific outputs or actions.
5. **Identify potential user/programming errors:** Point out common mistakes when dealing with these kinds of inter-process communication and frame management.
6. **Summarize:**  Provide a concise overview of the functionality in this specific code block.
这是 `blink/renderer/core/frame/remote_frame.cc` 文件的一部分，主要负责管理和同步**远程 Frame** 的状态和属性。远程 Frame 指的是在不同的渲染进程中渲染的 iframe 或 fenced frame 等。这部分代码侧重于以下功能：

**功能归纳:**

1. **获取主框架的尺寸和滚动位置:**
   - `GetOutermostMainFrameSize()`:  获取最外层主框架的尺寸。
   - `GetOutermostMainFrameScrollPosition()`: 获取最外层主框架的滚动位置。
   - 这两个函数都依赖于 `DeprecatedLocalOwner()`，这意味着它们主要用于获取嵌入该远程 Frame 的父框架的信息。

2. **管理 Opener 关系:**
   - `SetOpener(Frame* opener_frame)`:  设置或更新该远程 Frame 的 opener（打开它的 Frame）。
   - 这个操作会通知浏览器进程，并且只有 `LocalFrame`（即调用 `window.open` 的框架）才能更新其他框架的 opener。

3. **同步 TextAutosizer 信息:**
   - `UpdateTextAutosizerPageInfo(mojom::blink::TextAutosizerPageInfoPtr mojo_remote_page_info)`: 更新页面级别的文本自动缩放信息。
   - 这个操作只在主框架是远程框架时生效，并将信息同步到所有框架。

4. **处理作为远程主框架的附加:**
   - `WasAttachedAsRemoteMainFrame(mojo::PendingAssociatedReceiver<mojom::blink::RemoteMainFrame> main_frame)`:  当该远程 Frame 作为主框架附加时，绑定一个 Mojo 接收器，用于接收来自浏览器进程的消息。

5. **管理和同步 Compositor 图层和 Surface ID:**
   - `GetLocalSurfaceId() const`: 获取用于合成的本地 Surface ID。
   - `SetCcLayerForTesting(scoped_refptr<cc::Layer> layer, bool is_surface_layer)`: 用于测试，设置 Compositor 图层。
   - `GetFrameSinkId()`: 获取用于合成的 FrameSink ID。
   - `SetFrameSinkId(const viz::FrameSinkId& frame_sink_id, bool allow_paint_holding)`: 设置 FrameSink ID，并管理 `ParentLocalSurfaceIdAllocator`。当 FrameSink ID 改变时，会重新发送视觉属性。
   - `ChildProcessGone()`: 当子进程崩溃时调用，通知 CompositingHelper。

6. **处理命中测试忽略:**
   - `IsIgnoredForHitTest() const`:  判断该远程 Frame 是否被忽略进行命中测试。这通常与 CSS 的 `pointer-events: none` 属性有关。

7. **处理焦点前进:**
   - `AdvanceFocus(mojom::blink::FocusType type, LocalFrame* source)`:  将焦点前进到下一个或上一个可聚焦元素，并通知远程主机。

8. **分离子框架:**
   - `DetachChildren()`: 分离该远程 Frame 的所有子框架。

9. **应用复制的权限策略头部:**
   - `ApplyReplicatedPermissionsPolicyHeader()`:  根据父框架和自身的策略初始化权限策略。

10. **同步视觉属性 (Visual Properties):**
    - `SynchronizeVisualProperties(bool propagate, ChildFrameCompositingHelper::AllowPaintHolding allow_paint_holding)`:  核心功能，用于同步各种视觉属性到远程渲染进程，例如大小、位置、缩放、滚动、视口信息等。
    - `RecordSentVisualProperties()`: 记录已发送的视觉属性。
    - `ResendVisualProperties()` 和 `ResendVisualPropertiesInternal()`: 重新发送视觉属性。
    - `DidUpdateVisualProperties(const cc::RenderFrameMetadata& metadata)`:  接收来自渲染进程的视觉属性更新，并进行相应的处理。

11. **管理视口交叉状态:**
    - `SetViewportIntersection(const mojom::blink::ViewportIntersectionState& intersection_state)`:  设置视口与远程 Frame 的交叉状态，用于优化渲染。

12. **更新合成层边界:**
    - `UpdateCompositedLayerBounds()`:  根据当前的本地框架大小更新合成层的边界。

13. **响应屏幕信息变化:**
    - `DidChangeScreenInfos(const display::ScreenInfos& screen_infos)`: 当屏幕信息改变时更新视觉属性。

14. **响应缩放因子变化:**
    - `ZoomFactorChanged(double zoom_factor)`: 当缩放因子改变时更新视觉属性，并区分浏览器缩放和 CSS 缩放。

15. **响应根视口分段变化:**
    - `DidChangeRootViewportSegments(const std::vector<gfx::Rect>& root_widget_viewport_segments)`:  当根视口分段改变时更新视觉属性。

16. **响应页面缩放因子变化:**
    - `PageScaleFactorChanged(float page_scale_factor, bool is_pinch_gesture_active)`: 当页面缩放因子改变时更新视觉属性。

17. **响应可见视口大小变化:**
    - `DidChangeVisibleViewportSize(const gfx::Size& visible_viewport_size)`: 当可见视口大小改变时更新视觉属性。

18. **更新捕获序列号:**
    - `UpdateCaptureSequenceNumber(uint32_t capture_sequence_number)`: 更新用于屏幕捕获的序列号。

19. **响应光标可访问性缩放因子变化:**
    - `CursorAccessibilityScaleFactorChanged(float scale_factor)`:  当光标可访问性缩放因子改变时更新视觉属性。

20. **启用和禁用自动调整大小:**
    - `EnableAutoResize(const gfx::Size& min_size, const gfx::Size& max_size)`:  启用远程 Frame 的自动调整大小功能。
    - `DisableAutoResize()`: 禁用自动调整大小功能。

21. **创建远程子框架:**
    - `CreateRemoteChild(...)`: 通知客户端创建远程子框架。
    - `CreateRemoteChildren(...)`: 通知客户端批量创建远程子框架。

22. **转发 Fenced Frame 事件:**
    - `ForwardFencedFrameEventToEmbedder(const WTF::String& event_type)`: 将 Fenced Frame 的特定事件转发到嵌入器。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * `SetOpener()` 与 JavaScript 的 `window.open()` 相关。当一个脚本在父窗口中使用 `window.open()` 创建一个新窗口或 iframe 时，父窗口的 `LocalFrame` 会调用子窗口的 `RemoteFrame::SetOpener()` 来建立 opener 关系。
        * **假设输入:**  JavaScript 代码 `let newWindow = window.open('https://example.com');` 在主框架中执行。
        * **输出:** 主框架的 `LocalFrame` 会调用新窗口对应的 `RemoteFrame` 的 `SetOpener()` 方法，将主框架设置为新窗口的 opener。
    * 视觉属性的同步（例如大小、滚动位置）影响 JavaScript 获取到的窗口和元素属性，例如 `window.innerWidth`, `element.getBoundingClientRect()`, `window.scrollY` 等。

* **HTML:**
    * `RemoteFrame` 对应 HTML 中的 `<iframe>` 和 `<fencedframe>` 元素。
    * `CreateRemoteChild()` 在解析到 `<iframe>` 或 `<fencedframe>` 标签时会被调用，以在新的渲染进程中创建对应的 `RemoteFrame` 对象。
    * `IsIgnoredForHitTest()` 与 HTML 元素的 `pointer-events` CSS 属性相关。如果一个 `<iframe>` 设置了 `pointer-events: none;`，那么 `IsIgnoredForHitTest()` 可能会返回 `true`。

* **CSS:**
    * CSS 的布局和渲染属性会影响 `RemoteFrame` 的视觉属性，例如 `width`, `height`, `transform`, `zoom` 等。
    * `ZoomFactorChanged()` 方法响应 CSS 的 `zoom` 属性或浏览器的缩放操作。
    * `DidChangeVisibleViewportSize()`  与 CSS 中的视口单位 (例如 `vw`, `vh`) 的计算有关。

**逻辑推理举例:**

* **假设输入:**  一个 iframe 的 HTML 元素设置了 `width="500" height="300"`。
* **输出:** 当该 iframe 对应的 `RemoteFrame` 的 `SynchronizeVisualProperties()` 被调用时，`pending_visual_properties_.local_frame_size` 将会被设置为 `gfx::Size(500, 300)`，并同步到远程渲染进程，最终影响 iframe 的渲染大小。

* **假设输入:** 用户在包含一个 iframe 的页面上进行了捏合缩放操作。
* **输出:**  `PageScaleFactorChanged()` 方法会被调用，`pending_visual_properties_.page_scale_factor` 会更新为新的缩放值，并且 `pending_visual_properties_.is_pinch_gesture_active` 会被设置为 `true`，这些信息会同步到远程 iframe 的渲染进程。

**用户或编程常见的使用错误举例:**

* **错误地假设 RemoteFrame 可以直接访问 LocalFrame 的信息:** 由于 RemoteFrame 和 LocalFrame 运行在不同的进程中，直接访问是不可能的。必须通过 IPC 机制（如 Mojo）进行通信和数据同步。开发者可能会尝试直接访问 `Opener()` 返回的 `Frame` 对象的某些属性，而没有考虑到它可能是一个 `RemoteFrame`，从而导致错误或未定义的行为。
* **视觉属性同步的延迟问题:**  开发者可能会期望在本地立即获取到远程 iframe 的最新视觉属性，但由于同步需要时间，可能会出现短暂的不同步状态。例如，在 JavaScript 中获取 iframe 的 `offsetWidth` 或 `offsetHeight` 时，如果远程进程的渲染尚未完成或同步，获取到的值可能不是最新的。

**总结:**

这部分 `remote_frame.cc` 代码的核心职责是管理和维护跨进程的 Frame 对象的状态同步，特别是关于视觉属性、窗口关系和合成等方面。它充当了本地 Frame (LocalFrame) 和远程渲染进程中 Frame 之间的桥梁，确保了 Web 页面的正确渲染和交互。这些功能与 JavaScript 操作、HTML 结构以及 CSS 样式息息相关，共同构成了现代 Web 应用的运行基础。

### 提示词
```
这是目录为blink/renderer/core/frame/remote_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
nt().GetFrame());
  return owner->GetDocument().GetFrame()->GetOutermostMainFrameSize();
}

gfx::Point RemoteFrame::GetOutermostMainFrameScrollPosition() const {
  HTMLFrameOwnerElement* owner = DeprecatedLocalOwner();
  DCHECK(owner);
  DCHECK(owner->GetDocument().GetFrame());
  return owner->GetDocument().GetFrame()->GetOutermostMainFrameScrollPosition();
}

void RemoteFrame::SetOpener(Frame* opener_frame) {
  if (Opener() == opener_frame)
    return;

  // A proxy shouldn't normally be disowning its opener.  It is possible to
  // get here when a proxy that is being detached clears its opener, in
  // which case there is no need to notify the browser process.
  if (opener_frame) {
    // Only a LocalFrame (i.e., the caller of window.open) should be able to
    // update another frame's opener.
    DCHECK(opener_frame->IsLocalFrame());
    GetRemoteFrameHostRemote().DidChangeOpener(
        opener_frame
            ? std::optional<blink::LocalFrameToken>(
                  opener_frame->GetFrameToken().GetAs<LocalFrameToken>())
            : std::nullopt);
  }
  SetOpenerDoNotNotify(opener_frame);
}

void RemoteFrame::UpdateTextAutosizerPageInfo(
    mojom::blink::TextAutosizerPageInfoPtr mojo_remote_page_info) {
  // Only propagate the remote page info if our main frame is remote.
  DCHECK(IsMainFrame());
  Frame* root_frame = GetPage()->MainFrame();
  DCHECK(root_frame->IsRemoteFrame());
  if (*mojo_remote_page_info == GetPage()->TextAutosizerPageInfo())
    return;

  GetPage()->SetTextAutosizerPageInfo(*mojo_remote_page_info);
  TextAutosizer::UpdatePageInfoInAllFrames(root_frame);
}

void RemoteFrame::WasAttachedAsRemoteMainFrame(
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteMainFrame> main_frame) {
  main_frame_receiver_.Bind(std::move(main_frame), task_runner_);
}

const viz::LocalSurfaceId& RemoteFrame::GetLocalSurfaceId() const {
  return parent_local_surface_id_allocator_->GetCurrentLocalSurfaceId();
}

void RemoteFrame::SetCcLayerForTesting(scoped_refptr<cc::Layer> layer,
                                       bool is_surface_layer) {
  SetCcLayer(layer, is_surface_layer);
}

viz::FrameSinkId RemoteFrame::GetFrameSinkId() {
  return frame_sink_id_;
}

void RemoteFrame::SetFrameSinkId(const viz::FrameSinkId& frame_sink_id,
                                 bool allow_paint_holding) {
  remote_process_gone_ = false;

  // The same ParentLocalSurfaceIdAllocator cannot provide LocalSurfaceIds for
  // two different frame sinks, so recreate it here.
  if (frame_sink_id_ != frame_sink_id) {
    parent_local_surface_id_allocator_ =
        std::make_unique<viz::ParentLocalSurfaceIdAllocator>();
  }
  frame_sink_id_ = frame_sink_id;

  // Resend the FrameRects and allocate a new viz::LocalSurfaceId when the view
  // changes.
  ResendVisualPropertiesInternal(
      allow_paint_holding
          ? ChildFrameCompositingHelper::AllowPaintHolding::kYes
          : ChildFrameCompositingHelper::AllowPaintHolding::kNo);
}

void RemoteFrame::ChildProcessGone() {
  remote_process_gone_ = true;
  compositing_helper_->ChildFrameGone(
      ancestor_widget_->GetOriginalScreenInfo().device_scale_factor);
}

bool RemoteFrame::IsIgnoredForHitTest() const {
  HTMLFrameOwnerElement* owner = DeprecatedLocalOwner();
  if (!owner || !owner->GetLayoutObject())
    return false;

  return !visible_to_hit_testing_;
}

void RemoteFrame::AdvanceFocus(mojom::blink::FocusType type,
                               LocalFrame* source) {
  GetRemoteFrameHostRemote().AdvanceFocus(type, source->GetLocalFrameToken());
}

bool RemoteFrame::DetachChildren() {
  using FrameVector = HeapVector<Member<Frame>>;
  FrameVector children_to_detach;
  children_to_detach.reserve(Tree().ChildCount());
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling())
    children_to_detach.push_back(child);
  for (const auto& child : children_to_detach)
    child->Detach(FrameDetachType::kRemove);

  return !!Client();
}

void RemoteFrame::ApplyReplicatedPermissionsPolicyHeader() {
  const PermissionsPolicy* parent_permissions_policy = nullptr;
  if (Frame* parent_frame = Parent()) {
    parent_permissions_policy =
        parent_frame->GetSecurityContext()->GetPermissionsPolicy();
  }
  ParsedPermissionsPolicy container_policy;
  if (Owner())
    container_policy = Owner()->GetFramePolicy().container_policy;
  security_context_.InitializePermissionsPolicy(
      permissions_policy_header_, container_policy, parent_permissions_policy);
}

bool RemoteFrame::SynchronizeVisualProperties(
    bool propagate,
    ChildFrameCompositingHelper::AllowPaintHolding allow_paint_holding) {
  if (!GetFrameSinkId().is_valid() || remote_process_gone_)
    return false;

  auto capture_sequence_number_changed =
      (sent_visual_properties_ &&
       sent_visual_properties_->capture_sequence_number !=
           pending_visual_properties_.capture_sequence_number)
          ? ChildFrameCompositingHelper::CaptureSequenceNumberChanged::kYes
          : ChildFrameCompositingHelper::CaptureSequenceNumberChanged::kNo;

  if (view_) {
    pending_visual_properties_.compositor_viewport =
        view_->GetCompositingRect();
    pending_visual_properties_.compositing_scale_factor =
        view_->GetCompositingScaleFactor();
  }

  bool synchronized_props_changed =
      !sent_visual_properties_ ||
      sent_visual_properties_->auto_resize_enabled !=
          pending_visual_properties_.auto_resize_enabled ||
      sent_visual_properties_->min_size_for_auto_resize !=
          pending_visual_properties_.min_size_for_auto_resize ||
      sent_visual_properties_->max_size_for_auto_resize !=
          pending_visual_properties_.max_size_for_auto_resize ||
      sent_visual_properties_->local_frame_size !=
          pending_visual_properties_.local_frame_size ||
      sent_visual_properties_->rect_in_local_root.size() !=
          pending_visual_properties_.rect_in_local_root.size() ||
      sent_visual_properties_->screen_infos !=
          pending_visual_properties_.screen_infos ||
      sent_visual_properties_->zoom_level !=
          pending_visual_properties_.zoom_level ||
      sent_visual_properties_->css_zoom_factor !=
          pending_visual_properties_.css_zoom_factor ||
      sent_visual_properties_->page_scale_factor !=
          pending_visual_properties_.page_scale_factor ||
      sent_visual_properties_->compositing_scale_factor !=
          pending_visual_properties_.compositing_scale_factor ||
      sent_visual_properties_->cursor_accessibility_scale_factor !=
          pending_visual_properties_.cursor_accessibility_scale_factor ||
      sent_visual_properties_->is_pinch_gesture_active !=
          pending_visual_properties_.is_pinch_gesture_active ||
      sent_visual_properties_->visible_viewport_size !=
          pending_visual_properties_.visible_viewport_size ||
      sent_visual_properties_->compositor_viewport !=
          pending_visual_properties_.compositor_viewport ||
      sent_visual_properties_->root_widget_viewport_segments !=
          pending_visual_properties_.root_widget_viewport_segments ||
      sent_visual_properties_->capture_sequence_number !=
          pending_visual_properties_.capture_sequence_number;

  if (synchronized_props_changed)
    parent_local_surface_id_allocator_->GenerateId();
  pending_visual_properties_.local_surface_id = GetLocalSurfaceId();

  viz::SurfaceId surface_id(frame_sink_id_,
                            pending_visual_properties_.local_surface_id);
  DCHECK(ancestor_widget_);
  DCHECK(surface_id.is_valid());
  DCHECK(!remote_process_gone_);

  compositing_helper_->SetSurfaceId(surface_id, capture_sequence_number_changed,
                                    allow_paint_holding);

  bool rect_changed = !sent_visual_properties_ ||
                      sent_visual_properties_->rect_in_local_root !=
                          pending_visual_properties_.rect_in_local_root;
  bool visual_properties_changed = synchronized_props_changed || rect_changed;

  if (visual_properties_changed && propagate) {
    GetRemoteFrameHostRemote().SynchronizeVisualProperties(
        pending_visual_properties_);
    RecordSentVisualProperties();
  }

  return visual_properties_changed;
}

void RemoteFrame::RecordSentVisualProperties() {
  sent_visual_properties_ = pending_visual_properties_;
  TRACE_EVENT_WITH_FLOW2(
      TRACE_DISABLED_BY_DEFAULT("viz.surface_id_flow"),
      "RenderFrameProxy::SynchronizeVisualProperties Send Message",
      TRACE_ID_GLOBAL(
          pending_visual_properties_.local_surface_id.submission_trace_id()),
      TRACE_EVENT_FLAG_FLOW_OUT, "message",
      "FrameHostMsg_SynchronizeVisualProperties", "local_surface_id",
      pending_visual_properties_.local_surface_id.ToString());
}

void RemoteFrame::ResendVisualProperties() {
  ResendVisualPropertiesInternal(
      ChildFrameCompositingHelper::AllowPaintHolding::kNo);
}

void RemoteFrame::ResendVisualPropertiesInternal(
    ChildFrameCompositingHelper::AllowPaintHolding allow_paint_holding) {
  sent_visual_properties_ = std::nullopt;
  SynchronizeVisualProperties(/*propagate=*/true, allow_paint_holding);
}

void RemoteFrame::DidUpdateVisualProperties(
    const cc::RenderFrameMetadata& metadata) {
  if (!parent_local_surface_id_allocator_->UpdateFromChild(
          metadata.local_surface_id.value_or(viz::LocalSurfaceId()))) {
    return;
  }

  // The viz::LocalSurfaceId has changed so we call SynchronizeVisualProperties
  // here to embed it.
  SynchronizeVisualProperties();
}

void RemoteFrame::SetViewportIntersection(
    const mojom::blink::ViewportIntersectionState& intersection_state) {
  std::optional<FrameVisualProperties> visual_properties;
  if (SynchronizeVisualProperties(/*propagate=*/false)) {
    visual_properties.emplace(pending_visual_properties_);
    RecordSentVisualProperties();
  }
  GetRemoteFrameHostRemote().UpdateViewportIntersection(
      intersection_state.Clone(), visual_properties);
}

void RemoteFrame::UpdateCompositedLayerBounds() {
  if (cc_layer_)
    cc_layer_->SetBounds(pending_visual_properties_.local_frame_size);
}

void RemoteFrame::DidChangeScreenInfos(
    const display::ScreenInfos& screen_infos) {
  pending_visual_properties_.screen_infos = screen_infos;
  SynchronizeVisualProperties();
}

void RemoteFrame::ZoomFactorChanged(double zoom_factor) {
  // zoom_factor includes device scale factor, browser zoom, and css zoom.
  WebViewImpl* view = GetPage()->GetChromeClient().GetWebView();
  double device_scale_factor = view->ZoomFactorForViewportLayout();
  if (Owner() && Owner()->IsLocal()) {
    DCHECK(ancestor_widget_);
    double zoom_level = ancestor_widget_->GetZoomLevel();
    pending_visual_properties_.zoom_level = zoom_level;
    double browser_zoom_factor = view->ZoomLevelToZoomFactor(zoom_level);
    pending_visual_properties_.css_zoom_factor =
        zoom_factor / (device_scale_factor * browser_zoom_factor);
  } else {
    pending_visual_properties_.zoom_level =
        ZoomFactorToZoomLevel(zoom_factor / device_scale_factor);
    pending_visual_properties_.css_zoom_factor = 1.0;
  }
  SynchronizeVisualProperties();
}

void RemoteFrame::DidChangeRootViewportSegments(
    const std::vector<gfx::Rect>& root_widget_viewport_segments) {
  pending_visual_properties_.root_widget_viewport_segments =
      std::move(root_widget_viewport_segments);
  SynchronizeVisualProperties();
}

void RemoteFrame::PageScaleFactorChanged(float page_scale_factor,
                                         bool is_pinch_gesture_active) {
  pending_visual_properties_.page_scale_factor = page_scale_factor;
  pending_visual_properties_.is_pinch_gesture_active = is_pinch_gesture_active;
  SynchronizeVisualProperties();
}

void RemoteFrame::DidChangeVisibleViewportSize(
    const gfx::Size& visible_viewport_size) {
  pending_visual_properties_.visible_viewport_size = visible_viewport_size;
  SynchronizeVisualProperties();
}

void RemoteFrame::UpdateCaptureSequenceNumber(
    uint32_t capture_sequence_number) {
  pending_visual_properties_.capture_sequence_number = capture_sequence_number;
  SynchronizeVisualProperties();
}

void RemoteFrame::CursorAccessibilityScaleFactorChanged(float scale_factor) {
  pending_visual_properties_.cursor_accessibility_scale_factor = scale_factor;
  SynchronizeVisualProperties();
}

void RemoteFrame::EnableAutoResize(const gfx::Size& min_size,
                                   const gfx::Size& max_size) {
  pending_visual_properties_.auto_resize_enabled = true;
  pending_visual_properties_.min_size_for_auto_resize = min_size;
  pending_visual_properties_.max_size_for_auto_resize = max_size;
  SynchronizeVisualProperties();
}

void RemoteFrame::DisableAutoResize() {
  pending_visual_properties_.auto_resize_enabled = false;
  SynchronizeVisualProperties();
}

void RemoteFrame::CreateRemoteChild(
    const RemoteFrameToken& token,
    const std::optional<FrameToken>& opener_frame_token,
    mojom::blink::TreeScopeType tree_scope_type,
    mojom::blink::FrameReplicationStatePtr replication_state,
    mojom::blink::FrameOwnerPropertiesPtr owner_properties,
    bool is_loading,
    const base::UnguessableToken& devtools_frame_token,
    mojom::blink::RemoteFrameInterfacesFromBrowserPtr remote_frame_interfaces) {
  Client()->CreateRemoteChild(
      token, opener_frame_token, tree_scope_type, std::move(replication_state),
      std::move(owner_properties), is_loading, devtools_frame_token,
      std::move(remote_frame_interfaces));
}

void RemoteFrame::CreateRemoteChildren(
    Vector<mojom::blink::CreateRemoteChildParamsPtr> params) {
  Client()->CreateRemoteChildren(params);
}

void RemoteFrame::ForwardFencedFrameEventToEmbedder(
    const WTF::String& event_type) {
  // This will also CHECK if the conversion to HTMLFrameOwnerElement fails.
  CHECK(To<HTMLFrameOwnerElement>(Owner())->IsHTMLFencedFrameElement());
  static_cast<HTMLFencedFrameElement*>(Owner())->DispatchFencedEvent(
      event_type);
}

}  // namespace blink
```
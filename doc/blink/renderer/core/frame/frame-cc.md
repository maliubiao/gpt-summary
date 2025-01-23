Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/frame/frame.cc`. I need to identify the core responsibilities of the `Frame` class and how it interacts with other parts of the Blink rendering engine, specifically mentioning connections to JavaScript, HTML, and CSS. I also need to provide examples of logical reasoning based on the code, and highlight potential user or programming errors.

Here's a breakdown of how to approach this:

1. **Identify the core class:** The central element is the `Frame` class.

2. **Analyze member variables:** Look at the member variables declared and how they relate to frame properties (parent, children, owner, page, etc.) and functionalities (window proxy, event handling, etc.).

3. **Analyze key methods:** Focus on methods like `Detach`, `Swap`, `InsertAfter`, `FocusImpl`, and methods related to user activation. Understand their purpose and side effects.

4. **Relate to web technologies:**  Consider how `Frame` instances represent HTML `<iframe>` elements or the main document frame. Think about how JavaScript interacts with frames (e.g., `window.parent`, `window.open`), and how CSS affects frame rendering (e.g., `iframe` styling).

5. **Identify logical inferences:**  Look for conditional statements and operations that suggest a cause-and-effect relationship. For example, how detaching a frame affects its parent or children.

6. **Consider potential errors:** Think about common mistakes when dealing with iframes or frame navigation, such as accessing detached frames or incorrect frame manipulation.

7. **Structure the summary:** Organize the findings into logical categories like core functionality, relationship to web technologies, logical reasoning, and potential errors.

8. **Address specific instructions:** Ensure the summary explicitly mentions the relationship to JavaScript, HTML, and CSS with examples, provides hypothetical inputs and outputs for logical inferences, and illustrates user/programming errors.

9. **Keep it concise:**  Since this is part 1 of a 2-part request, focus on the functionality covered by this specific code snippet.
```
功能列表:
1. **表示和管理浏览器的帧 (Frame):** `Frame` 类是 Blink 渲染引擎中表示浏览器帧的核心类。它可以是主框架，也可以是内嵌的子框架 (例如，通过 `<iframe>` 创建)。
2. **维护帧的树状结构:**  `Frame` 类通过 `tree_node_` 成员以及 `parent_`, `first_child_`, `next_sibling_` 等指针来维护帧在页面中的层级关系。
3. **管理帧的生命周期:**  包括帧的创建、加载、卸载、分离 (Detach) 和交换 (Swap) 等过程。`Detach` 方法负责将帧从其父帧和页面中移除。
4. **关联帧和页面 (Page):** 每个 `Frame` 对象都关联着一个 `Page` 对象，代表包含该帧的整个浏览器页面。
5. **关联帧和所有者元素 (FrameOwner):** 对于内嵌框架，`Frame` 对象会关联一个 `FrameOwner` 对象，通常是 `HTMLFrameOwnerElement` (例如 `<iframe>`, `<object>`)。
6. **处理和传递用户激活状态:**  `NotifyUserActivationInFrameTree` 和相关方法用于在帧树中传递用户激活状态，这对于某些需要用户交互才能触发的功能（例如弹出窗口）至关重要。
7. **处理表单提交:** `ScheduleFormSubmission` 和 `CancelFormSubmission` 用于管理表单的提交过程。
8. **管理窗口代理 (WindowProxy):**  `window_proxy_manager_` 用于管理与帧关联的 JavaScript `window` 对象的代理。
9. **处理焦点 (Focus):** `FocusImpl` 和 `FocusPage` 用于处理帧的焦点控制。
10. **处理帧的属性:**  例如，通过 `ApplyFrameOwnerProperties` 应用来自渲染进程的帧属性。
11. **处理帧的嵌入 token:**  `embedding_token_` 用于唯一标识一个帧的嵌入。
12. **管理帧的打开器 (Opener):**  `opener_` 记录了哪个帧打开了当前帧。
13. **处理 fenced frame (实验性特性):** 代码中包含一些与 fenced frame 相关的逻辑，例如 `IsInFencedFrameTree` 和 `IsFencedFrameRoot`。
14. **维护帧的加载状态:** `is_loading_` 标志表示帧是否正在加载资源。
15. **提供调试信息:** `devtools_frame_token_` 用于在开发者工具中唯一标识帧。

与 JavaScript, HTML, CSS 的功能关系:

* **HTML:**
    * **关系:** `Frame` 对象直接对应 HTML 中的 `<iframe>`, `<frame>`, `<object>` 等元素创建的框架结构。
    * **举例:** 当 HTML 解析器遇到 `<iframe>` 标签时，会创建一个新的 `LocalFrame` 对象。 `Frame::Initialize()` 方法可能会被调用来完成帧的初始化，并将其与对应的 `HTMLIFrameElement` 关联起来。
* **JavaScript:**
    * **关系:** `Frame` 对象是 JavaScript 中 `window` 对象概念在渲染引擎中的表示。每个 `Frame` 对象都关联一个 `WindowProxy`，JavaScript 代码通过这个代理与帧进行交互。
    * **举例:** 当 JavaScript 代码访问 `window.parent` 时，引擎会通过当前 `Frame` 对象的 `Tree().Parent()` 方法找到父 `Frame`，然后返回父 `Frame` 关联的 `WindowProxy` 对象。  `Frame::GetWindowProxy()` 方法负责获取与特定 DOM 世界关联的 `WindowProxy`。
* **CSS:**
    * **关系:** CSS 的渲染结果会受到帧结构的影响。例如，一个 `<iframe>` 元素的样式会影响其在页面上的布局和显示。
    * **举例:** `Frame::UpdateInertIfPossible()` 方法检查帧的所有者元素（例如 `<iframe>`）的计算样式中是否设置了 `inert` 属性。如果设置了，该帧及其子帧可能会被标记为 `inert`，从而阻止用户交互。

逻辑推理 (假设输入与输出):

假设输入:
1. 一个包含 `<iframe>` 标签的 HTML 页面被加载。
2. JavaScript 代码尝试通过 `window.open()` 打开一个新的窗口。

逻辑推理:

* **场景 1 (iframe 加载):**
    * **假设输入:** HTML 解析器遇到 `<iframe src="child.html"></iframe>`。
    * **逻辑推理:** Blink 会创建一个新的 `LocalFrame` 对象来加载 `child.html`。这个新的 `LocalFrame` 的 `parent_` 指针会指向包含该 `<iframe>` 的父 `Frame`。父 `Frame` 的 `first_child_` 或 `last_child_` (以及兄弟节点的 `next_sibling_` 和 `previous_sibling_`) 会被更新，以反映新的帧结构 (通过 `Frame::InsertAfter`)。
    * **预期输出:**  在 Blink 的帧树结构中，新创建的 `LocalFrame` 成为父 `Frame` 的子节点。
* **场景 2 (window.open()):**
    * **假设输入:**  在某个 `LocalFrame` 的 JavaScript 环境中执行了 `window.open('https://example.com')`。
    * **逻辑推理:** Blink 会创建一个新的顶级 `LocalFrame` (因为没有父框架)。这个新 `Frame` 的 `opener_` 指针会指向执行 `window.open()` 的 `Frame`。执行 `window.open()` 的 `Frame` 的 `opened_frame_tracker_` 会记录新打开的 `Frame`。
    * **预期输出:**  一个新的顶级 `LocalFrame` 被创建，并且存在父子/打开者关系。

用户或编程常见的使用错误:

1. **访问已分离的帧:**  JavaScript 代码可能会尝试访问一个已经被移除 (detached) 的 `<iframe>` 的 `contentWindow` 或 `contentDocument`。
    * **举例:**
    ```javascript
    let iframe = document.getElementById('myIframe');
    iframe.remove(); // iframe 被移除，对应的 Frame 会被 detach
    console.log(iframe.contentWindow); // 尝试访问已分离的帧，可能导致错误
    ```
    * **Blink 内部处理:**  在 `Frame::Detach()` 方法被调用后，与该 `Frame` 关联的客户端会被设置为 null，尝试访问 `client_` 相关的成员可能会导致断言失败或空指针访问。

2. **在帧被销毁后仍然持有其引用:**  在 C++ 代码中，如果一个 `Frame` 对象被 `Detach` 了，但仍然有其他对象持有指向它的原始指针，那么访问这个指针可能会导致悬挂指针错误。
    * **举例:**  假设一个自定义的类持有一个 `Member<Frame>` 指针，指向一个 `<iframe>` 对应的 `Frame` 对象。如果该 `<iframe>` 被从 DOM 中移除，`Frame` 对象被销毁，那么这个 `Member<Frame>` 指针就会变成悬挂指针。

3. **不正确地管理用户激活状态:**  开发者可能会错误地认为一个操作是在用户激活状态下进行的，而实际上并非如此，导致某些需要用户交互权限的功能无法正常工作。
    * **举例:**  尝试在没有用户手势的情况下调用 `window.open()` 可能会被浏览器阻止，因为 `Frame::NotifyUserActivationInFrameTree` 没有被正确调用或传递。

归纳一下它的功能 (第 1 部分):

这份代码是 Chromium Blink 引擎中 `Frame` 类的实现，它负责表示和管理浏览器的帧结构。 这部分代码主要关注 `Frame` 的基本生命周期管理（创建、分离、交换）、帧树的维护、与页面和所有者元素的关联、用户激活状态的传递、表单提交的管理、窗口代理的管理以及一些基础的属性处理。 它体现了 `Frame` 类作为 Blink 核心组件在连接 HTML 结构、JavaScript 交互和 CSS 渲染方面的关键作用。代码中还包含了一些与实验性特性（如 fenced frame）相关的逻辑。
```
### 提示词
```
这是目录为blink/renderer/core/frame/frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1998, 1999 Torben Weis <weis@kde.org>
 *                     1999 Lars Knoll <knoll@kde.org>
 *                     1999 Antti Koivisto <koivisto@kde.org>
 *                     2000 Simon Hausmann <hausmann@kde.org>
 *                     2000 Stefan Schimanski <1Stein@gmx.de>
 *                     2001 George Staikos <staikos@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2005 Alexey Proskuryakov <ap@nypop.com>
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008 Google Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/frame/frame.h"

#include <memory>

#include "base/metrics/histogram_functions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fenced_frame/fenced_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_owner_properties.mojom-blink.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy_manager.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/buildflags.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/increment_load_event_delay_count.h"
#include "third_party/blink/renderer/core/execution_context/window_agent_factory.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/page_dismissal_scope.h"
#include "third_party/blink/renderer/core/frame/remote_frame_owner.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/form_submission.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

namespace blink {

// static
Frame* Frame::ResolveFrame(const FrameToken& frame_token) {
  if (frame_token.Is<RemoteFrameToken>())
    return RemoteFrame::FromFrameToken(frame_token.GetAs<RemoteFrameToken>());
  DCHECK(frame_token.Is<LocalFrameToken>());
  return LocalFrame::FromFrameToken(frame_token.GetAs<LocalFrameToken>());
}

Frame::~Frame() {
  InstanceCounters::DecrementCounter(InstanceCounters::kFrameCounter);
  DCHECK(!owner_);
  DCHECK(IsDetached());
}

void Frame::Trace(Visitor* visitor) const {
  visitor->Trace(tree_node_);
  visitor->Trace(page_);
  visitor->Trace(owner_);
  visitor->Trace(window_proxy_manager_);
  visitor->Trace(dom_window_);
  visitor->Trace(client_);
  visitor->Trace(opener_);
  visitor->Trace(parent_);
  visitor->Trace(previous_sibling_);
  visitor->Trace(next_sibling_);
  visitor->Trace(first_child_);
  visitor->Trace(last_child_);
  visitor->Trace(provisional_frame_);
  visitor->Trace(navigation_rate_limiter_);
  visitor->Trace(window_agent_factory_);
  visitor->Trace(opened_frame_tracker_);
}

bool Frame::Detach(FrameDetachType type) {
  TRACE_EVENT0("blink", "Frame::Detach");
  const std::string_view histogram_suffix =
      (type == FrameDetachType::kRemove) ? "Remove" : "Swap";
  base::ScopedUmaHistogramTimer histogram_timer(
      base::StrCat({"Navigation.Frame.Detach.", histogram_suffix}));
  DCHECK(client_);
  // Detach() can be re-entered, so this can't simply DCHECK(IsAttached()).
  DCHECK(!IsDetached());
  lifecycle_.AdvanceTo(FrameLifecycle::kDetaching);
  PageDismissalScope in_page_dismissal;

  if (!DetachImpl(type))
    return false;

  DCHECK(!IsDetached());
  DCHECK(client_);

  GetPage()->GetFocusController().FrameDetached(this);
  // FrameDetached() can fire JS event listeners, so `this` might have been
  // reentrantly detached.
  if (!client_)
    return false;

  DCHECK(!IsDetached());

  // TODO(dcheng): FocusController::FrameDetached() *should* fire JS events,
  // hence the above check for `client_` being null. However, when this was
  // previously placed before the `FrameDetached()` call, nothing crashes, which
  // is suspicious. Investigate if we really don't need to fire JS events--and
  // if we don't, move `forbid_scripts` up to be instantiated sooner and
  // simplify this code.
  ScriptForbiddenScope forbid_scripts;

  if (type == FrameDetachType::kRemove) {
    if (provisional_frame_) {
      provisional_frame_->Detach(FrameDetachType::kRemove);
    }
    SetOpener(nullptr);
    opened_frame_tracker_.Dispose();
    // Clearing the window proxies can call back into `LocalFrameClient`, so
    // this must be done before nulling out `client_` below.
    GetWindowProxyManager()->ClearForClose();
  } else {
    // In the case of a swap, detach is carefully coordinated with `Swap()`.
    // Intentionally avoid clearing the opener with `SetOpener(nullptr)` here,
    // since `Swap()` needs the original value to clone to the new frame.
    DCHECK_EQ(FrameDetachType::kSwap, type);

    // Clearing the window proxies can call back into `LocalFrameClient`, so
    // this must be done before nulling out `client_` below.
    // `ClearForSwap()` preserves the v8::Objects that represent the global
    // proxies; `Swap()` will later use `ReleaseGlobalProxies()` +
    // `SetGlobalProxies()` to adopt the global proxies into the new frame.
    GetWindowProxyManager()->ClearForSwap();
  }

  // After this, we must no longer talk to the client since this clears
  // its owning reference back to our owning LocalFrame.
  client_->Detached(type);
  client_ = nullptr;
  // Mark the frame as detached once |client_| is null, as most of the frame has
  // been torn down at this point.
  // TODO(dcheng): Once https://crbug.com/820782 is fixed, Frame::Client() will
  // also assert that it is only accessed when the frame is not detached.
  lifecycle_.AdvanceTo(FrameLifecycle::kDetached);
  // TODO(dcheng): This currently needs to happen after calling
  // FrameClient::Detached() to make it easier for FrameClient::Detached()
  // implementations to detect provisional frames and avoid removing them from
  // the frame tree. https://crbug.com/578349.
  DisconnectOwnerElement();
  page_ = nullptr;
  embedding_token_ = std::nullopt;

  return true;
}

void Frame::DisconnectOwnerElement() {
  if (!owner_)
    return;

  // TODO(https://crbug.com/578349): If this is a provisional frame, the frame
  // owner doesn't actually point to this frame, so don't clear it. Note that
  // this can't use IsProvisional() because the |client_| is null already.
  if (owner_->ContentFrame() == this)
    owner_->ClearContentFrame();

  owner_ = nullptr;
}

Page* Frame::GetPage() const {
  return page_.Get();
}

bool Frame::IsMainFrame() const {
  return !Tree().Parent();
}

bool Frame::IsOutermostMainFrame() const {
  return IsMainFrame() && !IsInFencedFrameTree();
}

bool Frame::IsCrossOriginToNearestMainFrame() const {
  DCHECK(GetSecurityContext());
  const SecurityOrigin* security_origin =
      GetSecurityContext()->GetSecurityOrigin();
  return !security_origin->CanAccess(
      Tree().Top().GetSecurityContext()->GetSecurityOrigin());
}

bool Frame::IsCrossOriginToOutermostMainFrame() const {
  return IsCrossOriginToNearestMainFrame() || IsInFencedFrameTree();
}

bool Frame::IsCrossOriginToParentOrOuterDocument() const {
  DCHECK(GetSecurityContext());
  if (IsInFencedFrameTree())
    return true;
  if (IsMainFrame())
    return false;
  Frame* parent = Tree().Parent();
  const SecurityOrigin* parent_security_origin =
      parent->GetSecurityContext()->GetSecurityOrigin();
  const SecurityOrigin* security_origin =
      GetSecurityContext()->GetSecurityOrigin();
  return !security_origin->CanAccess(parent_security_origin);
}

HTMLFrameOwnerElement* Frame::DeprecatedLocalOwner() const {
  return DynamicTo<HTMLFrameOwnerElement>(owner_.Get());
}

static ChromeClient& GetEmptyChromeClient() {
  DEFINE_STATIC_LOCAL(Persistent<EmptyChromeClient>, client,
                      (MakeGarbageCollected<EmptyChromeClient>()));
  return *client;
}

ChromeClient& Frame::GetChromeClient() const {
  if (Page* page = GetPage())
    return page->GetChromeClient();
  return GetEmptyChromeClient();
}

Frame* Frame::FindUnsafeParentScrollPropagationBoundary() {
  Frame* current_frame = this;
  Frame* ancestor_frame = Tree().Parent();

  while (ancestor_frame) {
    if (!ancestor_frame->GetSecurityContext()->GetSecurityOrigin()->CanAccess(
            GetSecurityContext()->GetSecurityOrigin()))
      return current_frame;
    current_frame = ancestor_frame;
    ancestor_frame = ancestor_frame->Tree().Parent();
  }
  return nullptr;
}

LayoutEmbeddedContent* Frame::OwnerLayoutObject() const {
  if (!DeprecatedLocalOwner())
    return nullptr;
  return DeprecatedLocalOwner()->GetLayoutEmbeddedContent();
}

Settings* Frame::GetSettings() const {
  if (GetPage())
    return &GetPage()->GetSettings();
  return nullptr;
}

WindowProxy* Frame::GetWindowProxy(DOMWrapperWorld& world) {
  return window_proxy_manager_->GetWindowProxy(world);
}

WindowProxy* Frame::GetWindowProxyMaybeUninitialized(DOMWrapperWorld& world) {
  return window_proxy_manager_->GetWindowProxyMaybeUninitialized(world);
}

void Frame::DidChangeVisibilityState() {
  HeapVector<Member<Frame>> child_frames;
  for (Frame* child = Tree().FirstChild(); child;
       child = child->Tree().NextSibling())
    child_frames.push_back(child);
  for (wtf_size_t i = 0; i < child_frames.size(); ++i)
    child_frames[i]->DidChangeVisibilityState();
}

void Frame::NotifyUserActivationInFrameTreeStickyOnly() {
  NotifyUserActivationInFrameTree(
      mojom::blink::UserActivationNotificationType::kNone,
      /*sticky_only=*/true);
}

void Frame::NotifyUserActivationInFrameTree(
    mojom::blink::UserActivationNotificationType notification_type,
    bool sticky_only) {
  for (Frame* node = this; node; node = node->Tree().Parent()) {
    NotifyUserActivationInFrame(node, notification_type, sticky_only);
  }

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
  if (RuntimeEnabledFeatures::DocumentPictureInPictureUserActivationEnabled()) {
    // If we are contained in a document picture-in-picture window, then also
    // propagate the activation up to our opener frame.
    auto* local_top_frame = DynamicTo<LocalFrame>(Tree().Top());
    if (local_top_frame && local_top_frame->GetDocument()) {
      LocalDOMWindow* pip_owner =
          PictureInPictureController::GetDocumentPictureInPictureOwner(
              *local_top_frame->GetDocument());
      if (pip_owner) {
        NotifyUserActivationInFrame(pip_owner->GetFrame(), notification_type,
                                    sticky_only);
      }
    }
  }
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

  // See the "Same-origin Visibility" section in |UserActivationState| class
  // doc.
  auto* local_frame = DynamicTo<LocalFrame>(this);
  if (local_frame &&
      RuntimeEnabledFeatures::UserActivationSameOriginVisibilityEnabled()) {
    const SecurityOrigin* security_origin =
        local_frame->GetSecurityContext()->GetSecurityOrigin();

    for (Frame* node = &Tree().Top(); node;
         node = node->Tree().TraverseNext()) {
      auto* local_frame_node = DynamicTo<LocalFrame>(node);
      if (local_frame_node &&
          security_origin->CanAccess(
              local_frame_node->GetSecurityContext()->GetSecurityOrigin())) {
        NotifyUserActivationInFrame(node, notification_type, sticky_only);
      }
    }

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
    if (RuntimeEnabledFeatures::
            DocumentPictureInPictureUserActivationEnabled()) {
      // If we are contained in a frame that owns a document picture-in-picture
      // window, then also activate same-origin frames in the document
      // picture-in-picture window.
      auto* local_top_frame = DynamicTo<LocalFrame>(Tree().Top());
      if (local_top_frame) {
        LocalDOMWindow* pip_window =
            PictureInPictureController::GetDocumentPictureInPictureWindow(
                *local_top_frame->GetDocument());
        for (Frame* node = pip_window ? pip_window->GetFrame() : nullptr; node;
             node = node->Tree().TraverseNext()) {
          auto* local_frame_node = DynamicTo<LocalFrame>(node);
          if (local_frame_node &&
              security_origin->CanAccess(local_frame_node->GetSecurityContext()
                                             ->GetSecurityOrigin())) {
            NotifyUserActivationInFrame(node, notification_type, sticky_only);
          }
        }
      }
    }
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)
  }
}

bool Frame::ConsumeTransientUserActivationInFrameTree() {
  bool was_active = user_activation_state_.IsActive();
  Frame& root = Tree().Top();

  // To record UMA once per consumption, we arbitrarily picked the LocalFrame
  // for root.
  if (IsA<LocalFrame>(root))
    root.user_activation_state_.RecordPreconsumptionUma();

  for (Frame* node = &root; node; node = node->Tree().TraverseNext())
    node->user_activation_state_.ConsumeIfActive();

#if !BUILDFLAG(TARGET_OS_IS_ANDROID)
  if (RuntimeEnabledFeatures::DocumentPictureInPictureUserActivationEnabled()) {
    auto* local_top_frame = DynamicTo<LocalFrame>(Tree().Top());
    if (local_top_frame) {
      // If we are contained in a document picture-in-picture window, then also
      // consume user activation in our owner.
      LocalDOMWindow* pip_owner =
          PictureInPictureController::GetDocumentPictureInPictureOwner(
              *local_top_frame->GetDocument());
      for (Frame* node = pip_owner ? pip_owner->GetFrame() : nullptr; node;
           node = node->Tree().TraverseNext()) {
        node->user_activation_state_.ConsumeIfActive();
      }

      // If we are contained in a frame that owns a document picture-in-picture
      // window, then also consume user activation in same-origin frames in the
      // document picture-in-picture window.
      LocalDOMWindow* pip_window =
          PictureInPictureController::GetDocumentPictureInPictureWindow(
              *local_top_frame->GetDocument());
      for (Frame* node = pip_window ? pip_window->GetFrame() : nullptr; node;
           node = node->Tree().TraverseNext()) {
        node->user_activation_state_.ConsumeIfActive();
      }
    }
  }
#endif  // !BUILDFLAG(TARGET_OS_IS_ANDROID)

  return was_active;
}

void Frame::ClearUserActivationInFrameTree() {
  for (Frame* node = this; node; node = node->Tree().TraverseNext(this)) {
    node->user_activation_state_.Clear();
    auto* local_node = DynamicTo<LocalFrame>(node);
    if (local_node) {
      local_node->SetHadUserInteraction(false);
    }
  }
}

void Frame::RenderFallbackContent() {
  // Fallback has been requested by the browser navigation code, so triggering
  // the fallback content should also dispatch an error event.
  To<HTMLObjectElement>(Owner())->RenderFallbackContent(
      HTMLObjectElement::ErrorEventPolicy::kDispatch);
}

bool Frame::IsInFencedFrameTree() const {
  DCHECK(!IsDetached());
  if (!features::IsFencedFramesEnabled())
    return false;

  return GetPage() && GetPage()->IsMainFrameFencedFrameRoot();
}

bool Frame::IsFencedFrameRoot() const {
  DCHECK(!IsDetached());
  if (!features::IsFencedFramesEnabled())
    return false;

  return IsInFencedFrameTree() && IsMainFrame();
}

std::optional<blink::FencedFrame::DeprecatedFencedFrameMode>
Frame::GetDeprecatedFencedFrameMode() const {
  DCHECK(!IsDetached());

  if (!features::IsFencedFramesEnabled())
    return std::nullopt;

  if (!IsInFencedFrameTree())
    return std::nullopt;

  return GetPage()->DeprecatedFencedFrameMode();
}

void Frame::SetOwner(FrameOwner* owner) {
  owner_ = owner;
  UpdateInertIfPossible();
  UpdateInheritedEffectiveTouchActionIfPossible();
}

void Frame::UpdateInertIfPossible() {
  if (auto* frame_owner_element =
          DynamicTo<HTMLFrameOwnerElement>(owner_.Get())) {
    const ComputedStyle* style = frame_owner_element->GetComputedStyle();
    const LocalFrame* parent = DynamicTo<LocalFrame>(Parent());
    SetIsInert((style && style->IsInert()) || (parent && parent->IsInert()));
  }
}

void Frame::UpdateInheritedEffectiveTouchActionIfPossible() {
  if (owner_) {
    Frame* owner_frame = owner_->ContentFrame();
    if (owner_frame) {
      SetInheritedEffectiveTouchAction(
          owner_frame->InheritedEffectiveTouchAction());
    }
  }
}

void Frame::UpdateVisibleToHitTesting() {
  bool parent_visible_to_hit_testing = true;
  if (auto* parent = Tree().Parent())
    parent_visible_to_hit_testing = parent->GetVisibleToHitTesting();

  bool self_visible_to_hit_testing = true;
  if (auto* local_owner = DynamicTo<HTMLFrameOwnerElement>(owner_.Get())) {
    self_visible_to_hit_testing =
        local_owner->GetLayoutObject()
            ? local_owner->GetLayoutObject()->Style()->VisibleToHitTesting()
            : true;
  }

  bool visible_to_hit_testing =
      parent_visible_to_hit_testing && self_visible_to_hit_testing;
  bool changed = visible_to_hit_testing_ != visible_to_hit_testing;
  visible_to_hit_testing_ = visible_to_hit_testing;
  if (changed)
    DidChangeVisibleToHitTesting();
}

const String& Frame::GetFrameIdForTracing() {
  // token's ToString() is latin1.
  if (!trace_value_)
    trace_value_ = String(devtools_frame_token_.ToString());
  return trace_value_.value();
}

void Frame::SetEmbeddingToken(const base::UnguessableToken& embedding_token) {
  embedding_token_ = embedding_token;
  if (auto* owner = DynamicTo<HTMLFrameOwnerElement>(Owner())) {
    // The embedding token is also used as the AXTreeID to reference the child
    // accessibility tree for an HTMLFrameOwnerElement, so we need to notify the
    // AXObjectCache object whenever this changes, to get the AX tree updated.
    if (AXObjectCache* cache = owner->GetDocument().ExistingAXObjectCache())
      cache->EmbeddingTokenChanged(owner);
  }
}

Frame::Frame(FrameClient* client,
             Page& page,
             FrameOwner* owner,
             Frame* parent,
             Frame* previous_sibling,
             FrameInsertType insert_type,
             const FrameToken& frame_token,
             const base::UnguessableToken& devtools_frame_token,
             WindowProxyManager* window_proxy_manager,
             WindowAgentFactory* inheriting_agent_factory)
    : tree_node_(this),
      page_(&page),
      owner_(owner),
      client_(client),
      window_proxy_manager_(window_proxy_manager),
      parent_(parent),
      navigation_rate_limiter_(*this),
      window_agent_factory_(inheriting_agent_factory
                                ? inheriting_agent_factory
                                : MakeGarbageCollected<WindowAgentFactory>(
                                      page.GetAgentGroupScheduler())),
      is_loading_(false),
      devtools_frame_token_(devtools_frame_token),
      frame_token_(frame_token) {
  InstanceCounters::IncrementCounter(InstanceCounters::kFrameCounter);
  if (parent_ && insert_type == FrameInsertType::kInsertInConstructor) {
    parent_->InsertAfter(this, previous_sibling);
  } else {
    CHECK(!previous_sibling);
  }
}

void Frame::Initialize() {
  // This frame must either be local or remote.
  DCHECK_NE(IsLocalFrame(), IsRemoteFrame());

  if (owner_)
    owner_->SetContentFrame(*this);
  else
    page_->SetMainFrame(this);
}

void Frame::FocusImpl() {
  // This uses FocusDocumentView rather than SetFocusedFrame so that blur
  // events are properly dispatched on any currently focused elements.
  // It is currently only used when replicating focus changes for
  // cross-process frames so |notify_embedder| is false to avoid sending
  // DidFocus updates from FocusController to the browser process,
  // which already knows the latest focused frame.
  GetPage()->GetFocusController().FocusDocumentView(
      this, false /* notify_embedder */);
}

void Frame::ApplyFrameOwnerProperties(
    mojom::blink::FrameOwnerPropertiesPtr properties) {
  // At the moment, this is only used to replicate frame owner properties
  // for frames with a remote owner.
  auto* owner = To<RemoteFrameOwner>(Owner());

  owner->SetBrowsingContextContainerName(properties->name);
  owner->SetScrollbarMode(properties->scrollbar_mode);
  owner->SetMarginWidth(properties->margin_width);
  owner->SetMarginHeight(properties->margin_height);
  owner->SetAllowFullscreen(properties->allow_fullscreen);
  owner->SetAllowPaymentRequest(properties->allow_payment_request);
  owner->SetIsDisplayNone(properties->is_display_none);
  owner->SetColorScheme(properties->color_scheme);
  owner->SetPreferredColorScheme(properties->preferred_color_scheme);
}

void Frame::InsertAfter(Frame* new_child, Frame* previous_sibling) {
  // Parent must match the one set in the constructor
  CHECK_EQ(new_child->parent_, this);

  Frame* next;
  if (!previous_sibling) {
    // Insert at the beginning if no previous sibling is specified.
    next = first_child_;
    first_child_ = new_child;
  } else {
    DCHECK_EQ(previous_sibling->parent_, this);
    next = previous_sibling->next_sibling_;
    previous_sibling->next_sibling_ = new_child;
    new_child->previous_sibling_ = previous_sibling;
  }

  if (next) {
    new_child->next_sibling_ = next;
    next->previous_sibling_ = new_child;
  } else {
    last_child_ = new_child;
  }

  Tree().InvalidateScopedChildCount();

  // When a frame is inserted, we almost always want to increment the
  // subframe count that is local to the current `blink::Page`. The exception is
  // if in the frame's embedder process, it is a state-preserving atomic move
  // that triggers the insert. In that case, skip the increment, because the
  // insertion under these circumstances is really a "move" operation. During
  // a move, we never decremented the subframe count since frame did not
  // detach, so we shouldn't re-increment it here.
  HTMLFrameOwnerElement* local_owner = new_child->DeprecatedLocalOwner();
  const bool increment_subframe_count =
      // When `local_owner` is null, then this code is running in an OOPIF's
      // inner process, where its embedder is remote. The concept of a
      // state-preserving atomic move does not apply there, so increment the
      // subframe count as usual.
      !local_owner ||
      // If `local_owner` is non-null but is not experiencing a state-preserving
      // atomic move, then increment the subframe count as usual.
      !local_owner->GetDocument().StatePreservingAtomicMoveInProgress();

  if (increment_subframe_count) {
    GetPage()->IncrementSubframeCount();
  }
}

base::OnceClosure Frame::ScheduleFormSubmission(
    FrameScheduler* scheduler,
    FormSubmission* form_submission) {
  form_submit_navigation_task_ = PostCancellableTask(
      *scheduler->GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      WTF::BindOnce(&FormSubmission::Navigate,
                    WrapPersistent(form_submission)));
  form_submit_navigation_task_version_++;

  return WTF::BindOnce(&Frame::CancelFormSubmissionWithVersion,
                       WrapWeakPersistent(this),
                       form_submit_navigation_task_version_);
}

void Frame::CancelFormSubmission() {
  form_submit_navigation_task_.Cancel();
}

void Frame::CancelFormSubmissionWithVersion(uint64_t version) {
  if (form_submit_navigation_task_version_ == version)
    form_submit_navigation_task_.Cancel();
}

bool Frame::IsFormSubmissionPending() {
  return form_submit_navigation_task_.IsActive();
}

void Frame::FocusPage(LocalFrame* originating_frame) {
  // We only allow focus to move to the |frame|'s page when the request comes
  // from a user gesture. (See https://bugs.webkit.org/show_bug.cgi?id=33389.)
  if (originating_frame &&
      LocalFrame::HasTransientUserActivation(originating_frame)) {
    // Ask the broswer process to focus the page.
    GetPage()->GetChromeClient().FocusPage();

    // Tattle on the frame that called |window.focus()|.
    originating_frame->GetLocalFrameHostRemote().DidCallFocus();
  }

  // Always report the attempt to focus the page to the Chrome client for
  // testing purposes (i.e. see WebViewTest.FocusExistingFrameOnNavigate()).
  GetPage()->GetChromeClient().DidFocusPage();
}

void Frame::SetOpenerDoNotNotify(Frame* opener) {
  if (opener_)
    opener_->opened_frame_tracker_.Remove(this);
  if (opener)
    opener->opened_frame_tracker_.Add(this);
  opener_ = opener;
}

Frame* Frame::Parent() const {
  // |parent_| will be null if detached, return early before accessing
  // Page.
  if (!parent_)
    return nullptr;

  return parent_.Get();
}

Frame* Frame::Top() {
  Frame* parent = this;
  while (true) {
    Frame* next_parent = parent->Parent();
    if (!next_parent)
      break;
    parent = next_parent;
  }
  return parent;
}

bool Frame::AllowFocusWithoutUserActivation() {
  if (!features::IsFencedFramesEnabled())
    return true;

  if (IsDetached()) {
    return true;
  }

  if (!IsInFencedFrameTree())
    return true;

  // Inside a fenced frame tree, a frame can only request focus is its focus
  // controller already has focus.
  return GetPage()->GetFocusController().IsFocused();
}

bool Frame::Swap(WebLocalFrame* new_web_frame) {
  return SwapImpl(new_web_frame, mojo::NullAssociatedRemote(),
                  mojo::NullAssociatedReceiver());
}

bool Frame::Swap(WebRemoteFrame* new_web_frame,
                 mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
                     remote_frame_host,
                 mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame>
                     remote_frame_receiver) {
  return SwapImpl(new_web_frame, std::move(remote_frame_host),
                  std::move(remote_frame_receiver));
}

bool Frame::SwapImpl(
    WebFrame* new_web_frame,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame>
        remote_frame_receiver) {
  TRACE_EVENT0("navigation", "Frame::SwapImpl");
  std::string_view histogram_suffix =
      (new_web_frame->IsWebLocalFrame() ? "Local" : "Remote");
  base::ScopedUmaHistogramTimer histogram_timer(
      base::StrCat({"Navigation.Frame.SwapImpl.", histogram_suffix}));
  DCHECK(IsAttached());

  using std::swap;

  // Important: do not cache frame tree pointers (e.g.  `previous_sibling_`,
  // `next_sibling_`, `first_child_`, `last_child_`) here. It is possible for
  // `Detach()` to mutate the frame tree and cause cached values to become
  // invalid.
  FrameOwner* owner = owner_;
  FrameSwapScope frame_swap_scope(owner);
  Page* page = page_;
  AtomicString name = Tree().GetName();

  // TODO(dcheng): This probably isn't necessary if we fix the ordering of
  // events in `Swap()`, e.g. `Detach()` should not happen before
  // `new_web_frame` is swapped in.
  // If there is a local parent, it might incorrectly declare itself complete
  // during the detach phase of this swap. Suppress its completion until swap is
  // over, at which point its completion will be correctly dependent on its
  // newly swapped-in child.
  auto* parent_local_frame = DynamicTo<LocalFrame>(parent_.Get());
  std::unique_ptr<IncrementLoadEventDelayCount> delay_parent_load =
      parent_local_frame ? std::make_unique<IncrementLoadEventDelayCount>(
                               *parent_local_frame->GetDocument())
                         : nullptr;

  // Unload the current Document in this frame: this calls unload handlers,
  // detaches child frames, etc. Since this runs script, make sure this frame
  // wasn't detached before continuing with the swap.
  if (!Detach(FrameDetachType::kSwap)) {
    // If the Swap() fails, it should be because the frame has been detached
    // already. Otherwise the caller will not detach the frame when we return
    // false, and the browser and renderer will disagree about the destruction
    // of |this|.
    CHECK(IsDetached());
    return false;
  }

  // Otherwise, on a successful `Detach()` for swap, `this` is now detached--but
  // crucially--still linked into the frame tree.

  if (provisional_frame_) {
    // `this` is about to be replaced, so if `provisional_frame_` is set, it
    // should match `frame` which is being swapped in.
    DCHECK_EQ(provisional_frame_, WebFrame::ToCoreFrame(*new_web_frame));
    provisional_frame_ = nullptr;
  }

  v8::Isolate* isolate = page->GetAgentGroupScheduler().Isolate();
  v8::HandleScope handle_scope(isolate);
  WindowProxyManager::GlobalProxyVector global_proxies(isolate);
  GetWindowProxyManager()->ReleaseGlobalProxies(global_proxies);

  if (new_web_frame->IsWebRemoteFrame()) {
    DCHECK(remote_frame_host && remote_frame_receiver);
    CHECK(!WebFrame::ToCoreFrame(*new_web_frame));
    To<WebRemoteFrameImpl>(new_web_frame)
        ->InitializeCoreFrame(*page, owner, WebFrame::FromCoreFrame(parent_),
                              nullptr, FrameInsertType::kInsertLater, name,
                              &window_agent_factory(), devtools_frame_token_,
                              std::move(remote_frame_host),
                              std::move(remote_frame_receiver));
    // At this point, a `RemoteFrame` will have already updated
    // `Page::MainFrame()` or `FrameOwner::ContentFrame()` as appropriate, and
    // its `parent_` pointer is also populated.
  } else {
    // This is local frame created by `WebLocalFrame::CreateProvisional()`. The
    // `parent` pointer was set when it was constructed; however,
    // `Page::MainFrame()` or `FrameOwner::ContentFrame()` updates are deferred
    // until after `new_frame` is linked into the frame tree.
    // TODO(dcheng): Make local and remote frame updates more uniform.
    DCHECK(!remote_frame_host && !remote_frame_receiver);
  }

  Frame* new_frame = WebFrame::ToCoreFrame(*new_web_frame);
  CHECK(new_frame);

  // At this point, `new_frame->parent_` is correctly set, but `new_frame`'s
  // sibling pointers are both still null and not yet updated. In addition, the
  // parent frame (if any) still has not updated its `first_child_` and
  // `last_child_` pointers.
  CHECK_EQ(new_frame->parent_, parent_);
  CHECK(!new_frame->previous_sibling_);
  CHECK(!new_frame->next_sibling_);
  if (previous_sibling_) {
    previous_sibling_->next_sibling_ = new_frame;
  }
  swap(previous_sibling_, new_frame->previous_sibling_);
  if (next_sibling_) {
    next_sibling_->previous_sibling_ = new_frame;
  }
  swap(next_sibling_, new_frame->next_sibling_);

  if (parent_) {
    if (parent_->first_child_ == this) {
      pare
```
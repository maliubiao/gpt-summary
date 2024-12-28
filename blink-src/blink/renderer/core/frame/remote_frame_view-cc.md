Response:
Let's break down the thought process for analyzing the `remote_frame_view.cc` file and answering the request.

1. **Understand the Core Function:** The filename itself, `remote_frame_view.cc`, immediately suggests this class is responsible for the *view* aspect of a *remote frame*. In Chromium's Blink rendering engine, "View" often relates to how something is displayed and interacted with. "Remote Frame" signifies a frame (like an iframe) that lives in a different process. This gives us the fundamental concept: managing the display of content from another process.

2. **Scan the Includes:** The included headers provide clues about the class's responsibilities and interactions:
    * `<algorithm>`: General utilities.
    * `base/feature_list.h`: Feature flags, indicating conditional behavior.
    * `base/metrics/histogram_macros.h`:  Metrics tracking.
    * `components/paint_preview/...`: Handling paint previews.
    * `printing/buildflags/...`: Conditional printing support.
    * `third_party/blink/public/common/frame/...`:  Core frame concepts, inter-process communication.
    * `third_party/blink/public/common/page/...`: Page-level concepts.
    * `third_party/blink/renderer/core/dom/...`: Document Object Model.
    * `third_party/blink/renderer/core/frame/...`:  Local and remote frame management.
    * `third_party/blink/renderer/core/html/...`: HTML-specific elements.
    * `third_party/blink/renderer/core/layout/...`: The layout tree, determining element positions and sizes.
    * `third_party/blink/renderer/core/page/...`: Page-level structures.
    * `third_party/blink/renderer/platform/graphics/...`: Graphics operations and painting.
    * `third_party/blink/renderer/platform/widget/...`: Platform-specific UI components.
    * `ui/gfx/geometry/...`: Geometry primitives.

3. **Examine the Class Definition:** Look at the constructor, destructor, and member variables:
    * `RemoteFrameView(RemoteFrame* remote_frame)`: Takes a `RemoteFrame` pointer, establishing the core association.
    * `~RemoteFrameView()`:  Destructor.
    * `remote_frame_`: Stores the associated `RemoteFrame`.
    * `needs_frame_rect_propagation_`: A flag related to updating frame geometry.
    * `last_intersection_state_`:  Stores the last viewport intersection state.
    * `needs_occlusion_tracking_`:  Indicates if occlusion tracking is needed.
    * `compositing_rect_`: The rectangle used for compositing.
    * `compositing_scale_factor_`: The scale factor for compositing.
    * `frozen_size_`:  An optional frozen size for the frame.
    * `intrinsic_sizing_info_`, `has_intrinsic_sizing_info_`:  Information about the frame's intrinsic size.

4. **Analyze Key Methods and Their Interactions:** This is where the bulk of understanding happens. Go through the methods and consider what they do and how they interact with other parts of the system. Look for patterns and connections to the include headers.

    * **Attachment/Detachment (`AttachToLayout`, `DetachFromLayout`):**  How the `RemoteFrameView` connects to and disconnects from the layout tree. This immediately links to layout concepts.
    * **Viewport Intersection (`UpdateViewportIntersectionsForSubtree`, `SetViewportIntersection`):** How the visibility and intersection of the remote frame with the viewport are managed. This is crucial for performance and relates to concepts like lazy loading and occlusion. The mention of `mojom::blink::ViewportIntersectionState` points to inter-process communication.
    * **Occlusion Tracking (`SetNeedsOcclusionTracking`):**  Optimizing rendering by tracking what's visible.
    * **Compositing (`ComputeCompositingRect`, `UpdateCompositingRect`, `UpdateCompositingScaleFactor`):** How the rendering of the remote frame is handled by the compositor. This involves calculating the visible area and scaling.
    * **Frame Rect Management (`SetFrameRect`, `UpdateFrozenSize`, `PropagateFrameRects`):** Updating and propagating the position and size of the remote frame to the parent frame.
    * **Painting (`Paint`):** The actual drawing of the remote frame's content. The checks for `IsPrintingOrPaintingPreview()` and the use of `DrawingRecorder` and `RecordForeignLayer` are significant.
    * **Visibility (`Hide`, `Show`, `ParentVisibleChanged`, `VisibilityForThrottlingChanged`, `VisibilityChanged`):**  Managing the visibility state and how it affects rendering and inter-process communication.
    * **Intrinsic Sizing (`SetIntrinsicSizeInfo`, `GetIntrinsicSizingInfo`, `HasIntrinsicSizingInfo`):**  Handling the intrinsic (natural) size of the remote frame.
    * **Printing and Paint Preview (`Print`, `CapturePaintPreview`):**  Specific functionalities for printing and capturing paint previews of the remote frame's content. The interaction with `printing/metafile_skia.h` and `components/paint_preview/...` is key here.

5. **Connect to JavaScript, HTML, and CSS:**  Consider how the functionalities relate to web development concepts:
    * **HTML:**  The `RemoteFrameView` directly corresponds to the `<iframe>` element (or `<fencedframe>`). Its size and position are determined by the HTML structure and CSS styles applied to the iframe.
    * **CSS:** CSS properties (like `width`, `height`, `transform`, `visibility`, `overflow`) on the iframe element directly influence the calculations within `RemoteFrameView` (e.g., frame rect, compositing rect, scaling).
    * **JavaScript:** JavaScript can manipulate the iframe element's properties, triggering updates in the `RemoteFrameView`. It can also interact with the content within the iframe (though with security restrictions).

6. **Identify Logical Reasoning:** Look for conditional logic and calculations. For example, the calculation of `compositing_rect_` based on viewport size and the handling of `frozen_size_`. Consider hypothetical inputs and outputs.

7. **Spot Potential User/Programming Errors:** Think about common mistakes when working with iframes:
    * Incorrectly setting the iframe's dimensions in HTML/CSS.
    * Not accounting for CSS transformations when positioning iframes.
    * Assuming the content inside the iframe will always be immediately available.
    * Issues related to cross-origin communication and security.

8. **Structure the Answer:** Organize the findings into clear categories: functionality, relationship to web technologies, logical reasoning, and potential errors. Use examples to illustrate the points. Use bullet points and clear language.

9. **Review and Refine:** Check for accuracy, completeness, and clarity. Ensure the examples are relevant and easy to understand.

**Self-Correction/Refinement Example During the Process:**

Initially, I might focus too much on the low-level graphics details. Then, realizing the request asks about the *functionality*, I'd shift focus to the broader responsibilities like managing visibility, handling size, and the interactions with the parent frame. I'd also make sure to connect the technical details to the user-facing web technologies (HTML, CSS, JavaScript). Similarly, if I only listed the method names without explaining their *purpose*, I'd go back and add descriptions. The key is to move from a code-centric view to a more functional and user-centric perspective when answering the prompt.
好的，让我们来分析一下 `blink/renderer/core/frame/remote_frame_view.cc` 这个文件。

**功能概述:**

`RemoteFrameView` 类是 Blink 渲染引擎中负责管理和显示跨进程（通常是 iframe 或 fenced frame）远程帧的视图。简单来说，当一个网页中嵌入了来自不同源的 iframe 时，当前页面的渲染进程会创建一个 `RemoteFrameView` 对象，作为该 iframe 内容的代理视图。  它不直接包含 iframe 的内容，而是作为本地渲染进程和远程 iframe 渲染进程之间的桥梁，负责处理以下关键功能：

1. **管理远程帧的几何信息:**  包括远程帧在父框架中的位置、大小、裁剪区域等。这些信息对于正确渲染和布局远程帧至关重要。
2. **处理远程帧的可见性:**  决定远程帧是否可见，并根据其可见性状态进行优化，例如暂停或恢复渲染。
3. **处理远程帧的合成（Compositing）:**  参与决定如何将远程帧的内容与当前页面的内容进行合成渲染，包括计算合成层的大小和缩放因子。
4. **处理远程帧的事件:** 虽然这个文件本身不直接处理事件，但它维护着远程帧视图的状态，这些状态会影响事件的路由。
5. **支持打印和 Paint Preview:**  允许将远程帧的内容包含在打印输出或 Paint Preview 中。
6. **管理远程帧的 Intersection Observer:** 跟踪远程帧与视口的交叉情况，用于实现懒加载等优化。
7. **与远程帧进行通信:**  通过 `remote_frame_->GetRemoteFrameHostRemote()` 获取到远程帧的 Host 接口，用于向远程进程发送各种指令，例如更新渲染状态、发送几何信息等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`RemoteFrameView` 的功能与 JavaScript, HTML, CSS 息息相关，因为它负责渲染由这些技术构建的远程帧内容。

* **HTML (`<iframe>`, `<fencedframe>`):**
    * **关系:**  当 HTML 中包含 `<iframe>` 或 `<fencedframe>` 元素时，Blink 会创建对应的 `RemoteFrame` 和 `RemoteFrameView` 对象（如果该 frame 是跨进程的）。
    * **举例:**  假设有如下 HTML 代码：
      ```html
      <!-- 主页面 (origin A) -->
      <!DOCTYPE html>
      <html>
      <head>
          <title>Main Page</title>
      </head>
      <body>
          <h1>Main Content</h1>
          <iframe src="https://example.com/iframe.html" width="500" height="300"></iframe>
      </body>
      </html>
      ```
      当浏览器加载这个页面时，由于 `iframe` 的 `src` 属性指向不同的源 (`https://example.com`)，Blink 会为这个 `iframe` 创建一个 `RemoteFrame` 对象，并在主页面的渲染进程中创建一个 `RemoteFrameView` 对象来代表这个远程 iframe。`RemoteFrameView` 会根据 HTML 中设置的 `width` 和 `height` 初始化其大小。

* **CSS:**
    * **关系:** CSS 样式可以影响 `<iframe>` 或 `<fencedframe>` 元素的布局和外观，这些样式会间接地影响 `RemoteFrameView` 的行为。
    * **举例:** 如果 CSS 设置了 iframe 的 `transform` 属性，例如旋转或缩放，`RemoteFrameView` 的 `UpdateCompositingScaleFactor()` 方法会计算出相应的合成缩放因子，并将其传递给远程进程，以确保远程 iframe 的内容能够正确地合成到主页面中。
    * **举例:** CSS 的 `visibility: hidden` 或 `display: none` 属性作用在 `<iframe>` 元素上，会通过 `RemoteFrameView` 的 `Hide()` 方法传递到远程帧，可能导致远程帧暂停渲染以节省资源。

* **JavaScript:**
    * **关系:** JavaScript 可以动态地创建、修改 `<iframe>` 或 `<fencedframe>` 元素，这些操作会触发 `RemoteFrameView` 的更新。
    * **举例:** JavaScript 可以修改 iframe 的 `src` 属性，导致远程帧的导航。虽然 `RemoteFrameView` 不直接处理导航，但它会在导航完成后与新的远程帧建立关联。
    * **举例:**  JavaScript 可以使用 `getBoundingClientRect()` 获取 iframe 的位置和大小，这些信息与 `RemoteFrameView` 维护的几何信息相关。
    * **举例:**  Intersection Observer API (JavaScript) 可以用来监听 iframe 是否进入或离开视口，这与 `RemoteFrameView` 中处理 viewport intersection 的逻辑相对应。当 JavaScript 使用 Intersection Observer 监听 iframe 时，Blink 内部会利用 `RemoteFrameView` 的 `UpdateViewportIntersectionsForSubtree` 和 `SetViewportIntersection` 方法来更新交叉状态。

**逻辑推理 (假设输入与输出):**

假设输入：

* 一个包含跨域 `<iframe>` 的主页面被加载。
* CSS 样式设置了 `iframe` 的宽度为 600px，高度为 400px。
* 用户滚动页面，使得 iframe 完全进入视口。

逻辑推理过程及输出：

1. **初始状态:**  `RemoteFrameView` 对象被创建，并关联到对应的 `RemoteFrame`。
2. **几何信息同步:**  `RemoteFrameView` 的 `SetFrameRect()` 方法会被调用，根据 CSS 样式（宽度 600px，高度 400px）设置其内部的 `FrameRect()`。
3. **AttachToLayout:** `RemoteFrameView` 被添加到布局树中，`needs_frame_rect_propagation_` 被设置为 `true`。
4. **PropagateFrameRects:**  由于 `needs_frame_rect_propagation_` 为 `true`，`PropagateFrameRects()` 方法会被调用。
   * **输入:**  `FrameRect()` 返回的矩形 (例如，原点可能依赖于 iframe 在页面中的位置，但大小是 600x400)。
   * **输出:**  调用 `remote_frame_->FrameRectsChanged(gfx::Size(600, 400), rect_in_local_root)`，将 iframe 的大小和相对于本地根框架的位置信息发送到远程 iframe 进程。
5. **Viewport Intersection:** 当用户滚动页面，使得 iframe 进入视口时，`UpdateViewportIntersectionsForSubtree()` 和 `SetViewportIntersection()` 方法会被调用。
   * **假设输入:**  父框架的视口信息以及 iframe 在父框架坐标系中的位置。
   * **逻辑推理:**  `ComputeIntersectionsContext` 计算出 iframe 与视口的交叉区域。
   * **输出:**  `SetViewportIntersection()` 方法会被调用，传入一个 `mojom::blink::ViewportIntersectionState` 对象，该对象包含了 iframe 与视口的交叉信息（例如，`is_visible=true`，`intersection_rect` 等）。这个状态会被发送到远程 iframe 进程，告知它当前是否可见。
6. **Compositing:**  `UpdateCompositingRect()` 方法会被调用，计算用于合成的矩形区域。
   * **假设输入:**  当前视口大小，iframe 的位置和大小。
   * **逻辑推理:**  如果 iframe 完全在视口内，合成矩形可能与 iframe 的 `FrameRect()` 近似。如果 iframe 部分超出视口，合成矩形可能会进行调整以优化性能。
   * **输出:**  更新 `compositing_rect_` 成员变量，并将信息传递给远程帧进行合成。

**用户或编程常见的使用错误举例说明:**

1. **忘记设置 iframe 的尺寸:**
   * **错误:**  在 HTML 中创建 `<iframe>` 元素但没有显式设置 `width` 和 `height` 属性，也没有通过 CSS 设置尺寸。
   * **后果:**  `RemoteFrameView` 可能会使用默认尺寸（通常很小），导致 iframe 内容显示不全或布局错乱。远程帧可能无法正确判断其渲染区域。

2. **CSS `transform` 导致的定位问题:**
   * **错误:**  使用 CSS `transform` (例如 `translate`, `scale`) 来移动或缩放 `<iframe>` 元素，但没有考虑到这些变换对远程帧内部坐标系的影响。
   * **后果:**  可能会导致远程帧的事件处理错位，或者在进行打印或 Paint Preview 时，远程帧的内容没有按照预期进行变换。虽然 `RemoteFrameView` 会尝试同步变换信息，但复杂的变换可能引入误差或性能问题。

3. **假设远程帧内容立即加载:**
   * **错误:**  在主页面 JavaScript 中尝试立即访问远程 iframe 的 `contentDocument` 或 `contentWindow`，而没有等待远程帧加载完成。
   * **后果:**  可能导致 JavaScript 错误，因为远程帧的内容可能尚未准备好。虽然这更多是 JavaScript 编程错误，但理解 `RemoteFrameView` 作为代理视图，其内容加载是异步的，有助于避免这类错误。

4. **滥用 `position: fixed` 在 iframe 内部:**
   * **错误:**  在远程 iframe 的 CSS 中使用 `position: fixed`，期望其相对于主页面的视口固定，而实际上它是相对于 iframe 自身的视口固定的。
   * **后果:**  可能导致固定定位的元素在主页面滚动时行为异常。虽然这与 `RemoteFrameView` 的直接功能关联较弱，但理解 iframe 的渲染边界有助于避免这类布局问题。

5. **Intersection Observer 使用不当:**
   * **错误:**  在使用 Intersection Observer 监听 iframe 的可见性时，没有考虑到跨域的限制或者配置不当。
   * **后果:**  可能无法正确地观察到 iframe 的交叉状态，导致懒加载等功能失效。`RemoteFrameView` 负责底层的交叉状态跟踪，但错误的 JavaScript 配置会影响最终结果。

总而言之，`RemoteFrameView` 是 Blink 渲染引擎中处理跨进程 iframe 的关键组件，它负责管理远程帧的视图信息，并与远程进程进行通信，以确保远程内容能够正确地集成到主页面中。理解其功能有助于开发者更好地理解和调试涉及 iframe 的 Web 应用。

Prompt: 
```
这是目录为blink/renderer/core/frame/remote_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/remote_frame_view.h"

#include <algorithm>

#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "components/paint_preview/common/paint_preview_tracker.h"
#include "printing/buildflags/buildflags.h"
#include "third_party/blink/public/common/frame/frame_owner_element_type.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_client.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/transform_util.h"

#if BUILDFLAG(ENABLE_PRINTING)
// nogncheck because dependency on //printing is conditional upon
// enable_printing flags.
#include "printing/metafile_skia.h"  // nogncheck
#endif

namespace blink {

BASE_FEATURE(kSkipUnnecessaryRemoteFrameGeometryPropagation,
             "SkipUnnecessaryRemoteFrameGeometryPropagation",
             base::FEATURE_DISABLED_BY_DEFAULT);

RemoteFrameView::RemoteFrameView(RemoteFrame* remote_frame)
    : FrameView(gfx::Rect()), remote_frame_(remote_frame) {
  DCHECK(remote_frame);
  Show();
}

RemoteFrameView::~RemoteFrameView() = default;

LocalFrameView* RemoteFrameView::ParentFrameView() const {
  if (!IsAttached())
    return nullptr;

  HTMLFrameOwnerElement* owner = remote_frame_->DeprecatedLocalOwner();
  if (owner && owner->OwnerType() == FrameOwnerElementType::kFencedframe) {
    return owner->GetDocument().GetFrame()->View();
  }

  // |is_attached_| is only set from AttachToLayout(), which ensures that the
  // parent is a local frame.
  return To<LocalFrame>(remote_frame_->Tree().Parent())->View();
}

LayoutEmbeddedContent* RemoteFrameView::GetLayoutEmbeddedContent() const {
  return remote_frame_->OwnerLayoutObject();
}

LocalFrameView* RemoteFrameView::ParentLocalRootFrameView() const {
  if (!IsAttached())
    return nullptr;

  HTMLFrameOwnerElement* owner = remote_frame_->DeprecatedLocalOwner();
  if (owner && owner->OwnerType() == FrameOwnerElementType::kFencedframe) {
    return owner->GetDocument().GetFrame()->LocalFrameRoot().View();
  }

  // |is_attached_| is only set from AttachToLayout(), which ensures that the
  // parent is a local frame.
  return To<LocalFrame>(remote_frame_->Tree().Parent())
      ->LocalFrameRoot()
      .View();
}

void RemoteFrameView::AttachToLayout() {
  DCHECK(!IsAttached());
  SetAttached(true);
  if (ParentFrameView()->IsVisible())
    SetParentVisible(true);
  UpdateFrameVisibility(true);
  UpdateRenderThrottlingStatus(
      IsHiddenForThrottling(),
      ParentFrameView()->CanThrottleRenderingForPropagation(),
      IsDisplayLocked());
  needs_frame_rect_propagation_ = true;
  ParentFrameView()->SetNeedsUpdateGeometries();
}

void RemoteFrameView::DetachFromLayout() {
  DCHECK(IsAttached());
  SetParentVisible(false);
  SetAttached(false);
}

bool RemoteFrameView::UpdateViewportIntersectionsForSubtree(
    unsigned parent_flags,
    ComputeIntersectionsContext&) {
  UpdateViewportIntersection(parent_flags, needs_occlusion_tracking_);
  return needs_occlusion_tracking_;
}

void RemoteFrameView::SetViewportIntersection(
    const mojom::blink::ViewportIntersectionState& intersection_state) {
  TRACE_EVENT0("blink", __PRETTY_FUNCTION__);
  mojom::blink::ViewportIntersectionState new_state(intersection_state);
  new_state.compositor_visible_rect = compositing_rect_;

  auto is_equal = [](mojom::blink::ViewportIntersectionState& a,
                     mojom::blink::ViewportIntersectionState& b,
                     bool ignore_outermost_main_frame_scroll_position) {
    if (ignore_outermost_main_frame_scroll_position) {
      auto b_copy = b;
      b_copy.outermost_main_frame_scroll_position =
          a.outermost_main_frame_scroll_position;
      return a.Equals(b_copy);
    }
    return a.Equals(b);
  };

  bool needs_update;
  if (base::FeatureList::IsEnabled(
          kSkipUnnecessaryRemoteFrameGeometryPropagation)) {
    // When the remote frame is not intersecting with the viewport, we don't
    // need to propagate up to date outermost frame scroll offsets, since they
    // are not relevant in this case. This is a non-trivial saving, since
    // common pages can have 10+ remote frames, and the scroll offset changes at
    // every frame while scrolling. Since the interface used to talk to the
    // remote frames is (a) a Channel-assocaited interface, and (b) goes through
    // CrossProcessFrameConnector in the browser process, this incurs a *lot* of
    // context switches.
    bool outside_viewport =
        frame_visibility() &&
        (*frame_visibility() == mojom::blink::FrameVisibility::kNotRendered ||
         *frame_visibility() ==
             mojom::blink::FrameVisibility::kRenderedOutOfViewport);
    needs_update =
        !is_equal(last_intersection_state_, new_state, outside_viewport);
  } else {
    needs_update = !last_intersection_state_.Equals(new_state);
  }

  UMA_HISTOGRAM_BOOLEAN(
      "Blink.UpdateViewportIntersection.RemoteFrameNeedsUpdate", needs_update);
  if (needs_update) {
    last_intersection_state_ = new_state;
    remote_frame_->SetViewportIntersection(new_state);
  } else if (needs_frame_rect_propagation_) {
    PropagateFrameRects();
  }
}

void RemoteFrameView::SetNeedsOcclusionTracking(bool needs_tracking) {
  if (needs_occlusion_tracking_ == needs_tracking)
    return;
  needs_occlusion_tracking_ = needs_tracking;
  if (needs_tracking) {
    if (LocalFrameView* parent_view = ParentLocalRootFrameView()) {
      parent_view->SetIntersectionObservationState(LocalFrameView::kRequired);
      parent_view->ScheduleAnimation();
    }
  }
}

gfx::Rect RemoteFrameView::ComputeCompositingRect() const {
  LocalFrameView* local_root_view = ParentLocalRootFrameView();
  LayoutEmbeddedContent* owner_layout_object =
      remote_frame_->OwnerLayoutObject();

  // For main frames we constrain the rect that gets painted to the viewport.
  // If the local frame root is an OOPIF itself, then we use the root's
  // intersection rect. This represents a conservative maximum for the area
  // that needs to be rastered by the OOPIF compositor.
  gfx::Rect viewport_rect(gfx::Point(), local_root_view->Size());
  if (local_root_view->GetPage()->MainFrame() != local_root_view->GetFrame()) {
    viewport_rect = local_root_view->GetFrame().RemoteViewportIntersection();
  }

  // The viewport rect needs to account for intermediate CSS transforms before
  // being compared to the frame size.
  TransformState local_root_transform_state(
      TransformState::kApplyTransformDirection);
  local_root_transform_state.Move(
      owner_layout_object->PhysicalContentBoxOffset());
  owner_layout_object->MapLocalToAncestor(nullptr, local_root_transform_state,
                                          kTraverseDocumentBoundaries);
  gfx::Transform matrix =
      local_root_transform_state.AccumulatedTransform().InverseOrIdentity();
  PhysicalRect local_viewport_rect = PhysicalRect::EnclosingRect(
      matrix.ProjectQuad(gfx::QuadF(gfx::RectF(viewport_rect))).BoundingBox());
  gfx::Rect compositing_rect = ToEnclosingRect(local_viewport_rect);
  gfx::Size frame_size = Size();

  // Iframes that fit within the window viewport get fully rastered. For
  // iframes that are larger than the window viewport, add a 30% buffer to the
  // draw area to try to prevent guttering during scroll.
  // TODO(kenrb): The 30% value is arbitrary, it gives 15% overdraw in both
  // directions when the iframe extends beyond both edges of the viewport, and
  // it seems to make guttering rare with slow to medium speed wheel scrolling.
  // Can we collect UMA data to estimate how much extra rastering this causes,
  // and possibly how common guttering is?
  compositing_rect.Outset(
      gfx::Outsets::VH(ceilf(local_viewport_rect.Height() * 0.15f),
                       ceilf(local_viewport_rect.Width() * 0.15f)));
  compositing_rect.set_width(
      std::min(frame_size.width(), compositing_rect.width()));
  compositing_rect.set_height(
      std::min(frame_size.height(), compositing_rect.height()));
  gfx::Point compositing_rect_location = compositing_rect.origin();
  compositing_rect_location.SetToMax(gfx::Point());
  compositing_rect.set_origin(compositing_rect_location);

  return compositing_rect;
}

void RemoteFrameView::UpdateCompositingRect() {
  remote_frame_->UpdateCompositedLayerBounds();
  gfx::Rect previous_rect = compositing_rect_;
  compositing_rect_ = gfx::Rect();
  LocalFrameView* local_root_view = ParentLocalRootFrameView();
  LayoutEmbeddedContent* owner_layout_object =
      remote_frame_->OwnerLayoutObject();
  if (!local_root_view || !owner_layout_object) {
    needs_frame_rect_propagation_ = true;
    return;
  }

  // The |compositing_rect_| provides the child compositor the rectangle (in its
  // local coordinate space) which should be rasterized/composited. Its based on
  // the child frame's intersection with the viewport and an optimization to
  // avoid large iframes rasterizing their complete viewport.
  // Since this rectangle is dependent on the child frame's position in the
  // embedding frame, updating this can be used for communication with a fenced
  // frame. So if the frame size is frozen, we use the complete viewport of the
  // child frame as its compositing rect.
  if (frozen_size_) {
    compositing_rect_ = gfx::Rect(*frozen_size_);
  } else {
    compositing_rect_ = ComputeCompositingRect();
  }

  if (compositing_rect_ != previous_rect)
    needs_frame_rect_propagation_ = true;
}

void RemoteFrameView::UpdateCompositingScaleFactor() {
  float previous_scale_factor = compositing_scale_factor_;

  LocalFrameView* local_root_view = ParentLocalRootFrameView();
  LayoutEmbeddedContent* owner_layout_object =
      remote_frame_->OwnerLayoutObject();
  if (!local_root_view || !owner_layout_object)
    return;

  TransformState local_root_transform_state(
      TransformState::kApplyTransformDirection);
  local_root_transform_state.Move(
      owner_layout_object->PhysicalContentBoxOffset());
  owner_layout_object->MapLocalToAncestor(nullptr, local_root_transform_state,
                                          kTraverseDocumentBoundaries);

  float frame_to_local_root_scale_factor = 1.0f;
  gfx::Transform local_root_transform =
      local_root_transform_state.AccumulatedTransform();
  std::optional<gfx::Vector2dF> scale_components =
      gfx::TryComputeTransform2dScaleComponents(local_root_transform);
  if (!scale_components) {
    frame_to_local_root_scale_factor =
        gfx::ComputeApproximateMaxScale(local_root_transform);
  } else {
    frame_to_local_root_scale_factor =
        std::max(scale_components->x(), scale_components->y());
  }

  // The compositing scale factor is calculated by multiplying the scale factor
  // from the local root to main frame with the scale factor between child frame
  // and local root.
  FrameWidget* widget = local_root_view->GetFrame().GetWidgetForLocalRoot();
  compositing_scale_factor_ =
      widget->GetCompositingScaleFactor() * frame_to_local_root_scale_factor;

  // Force compositing scale factor to be within reasonable minimum and maximum
  // values to prevent dependent values such as scroll deltas in the compositor
  // going to zero or extremely high memory usage due to large raster scales.
  // It's possible for the calculated scale factor to become very large or very
  // small since it depends on arbitrary intermediate CSS transforms.
  constexpr float kMinCompositingScaleFactor = 0.25f;
  constexpr float kMaxCompositingScaleFactor = 5.0f;
  compositing_scale_factor_ =
      std::clamp(compositing_scale_factor_, kMinCompositingScaleFactor,
                 kMaxCompositingScaleFactor);

  if (compositing_scale_factor_ != previous_scale_factor)
    remote_frame_->SynchronizeVisualProperties();
}

void RemoteFrameView::Dispose() {
  HTMLFrameOwnerElement* owner_element = remote_frame_->DeprecatedLocalOwner();
  // ownerElement can be null during frame swaps, because the
  // RemoteFrameView is disconnected before detachment.
  if (owner_element && owner_element->OwnedEmbeddedContentView() == this)
    owner_element->SetEmbeddedContentView(nullptr);
}

void RemoteFrameView::SetFrameRect(const gfx::Rect& rect) {
  UpdateFrozenSize();
  EmbeddedContentView::SetFrameRect(rect);
  if (needs_frame_rect_propagation_)
    PropagateFrameRects();
}

void RemoteFrameView::UpdateFrozenSize() {
  auto* layout_embedded_content = GetLayoutEmbeddedContent();
  if (!layout_embedded_content)
    return;
  std::optional<PhysicalSize> frozen_phys_size =
      layout_embedded_content->FrozenFrameSize();
  if (!frozen_phys_size)
    return;
  const gfx::Size rounded_frozen_size(frozen_phys_size->width.Ceil(),
                                      frozen_phys_size->height.Ceil());
  frozen_size_ = rounded_frozen_size;
  needs_frame_rect_propagation_ = true;
}

void RemoteFrameView::ZoomFactorChanged(float zoom_factor) {
  remote_frame_->ZoomFactorChanged(zoom_factor);
}

void RemoteFrameView::PropagateFrameRects() {
  // Update the rect to reflect the position of the frame relative to the
  // containing local frame root. The position of the local root within
  // any remote frames, if any, is accounted for by the embedder.
  needs_frame_rect_propagation_ = false;
  gfx::Rect frame_rect(FrameRect());
  gfx::Rect rect_in_local_root = frame_rect;

  if (LocalFrameView* parent = ParentFrameView()) {
    rect_in_local_root = parent->ConvertToRootFrame(rect_in_local_root);
  }

  gfx::Size frame_size = frozen_size_.value_or(frame_rect.size());
  remote_frame_->FrameRectsChanged(frame_size, rect_in_local_root);
}

void RemoteFrameView::Paint(GraphicsContext& context,
                            PaintFlags flags,
                            const CullRect& rect,
                            const gfx::Vector2d& paint_offset) const {
  if (!rect.Intersects(FrameRect()))
    return;

  const auto& owner_layout_object = *GetFrame().OwnerLayoutObject();
  if (owner_layout_object.GetDocument().IsPrintingOrPaintingPreview()) {
    DrawingRecorder recorder(context, owner_layout_object,
                             DisplayItem::kDocumentBackground);
    context.Save();
    context.Translate(paint_offset.x(), paint_offset.y());
    DCHECK(context.Canvas());

    uint32_t content_id = 0;
    if (owner_layout_object.GetDocument().Printing()) {
      // Inform the remote frame to print.
      content_id = Print(FrameRect(), context.Canvas());
    } else {
      DCHECK_NE(Document::kNotPaintingPreview,
                owner_layout_object.GetDocument().GetPaintPreviewState());
      // Inform the remote frame to capture a paint preview.
      content_id = CapturePaintPreview(FrameRect(), context.Canvas());
    }
    // Record the place holder id on canvas.
    context.Canvas()->recordCustomData(content_id);
    context.Restore();
  }

  if (GetFrame().GetCcLayer()) {
    RecordForeignLayer(
        context, owner_layout_object, DisplayItem::kForeignLayerRemoteFrame,
        GetFrame().GetCcLayer(), FrameRect().origin() + paint_offset);
  }
}

void RemoteFrameView::UpdateGeometry() {
  if (LayoutEmbeddedContent* layout = GetLayoutEmbeddedContent())
    layout->UpdateGeometry(*this);
}

void RemoteFrameView::Hide() {
  SetSelfVisible(false);
  UpdateFrameVisibility(
      !last_intersection_state_.viewport_intersection.IsEmpty());
}

void RemoteFrameView::Show() {
  SetSelfVisible(true);
  UpdateFrameVisibility(
      !last_intersection_state_.viewport_intersection.IsEmpty());
}

void RemoteFrameView::ParentVisibleChanged() {
  if (IsSelfVisible()) {
    UpdateFrameVisibility(
        !last_intersection_state_.viewport_intersection.IsEmpty());
  }
}

void RemoteFrameView::VisibilityForThrottlingChanged() {
  TRACE_EVENT0("blink", "RemoteFrameView::VisibilityForThrottlingChanged");
  // TODO(szager,vmpstr): Send IsSubtreeThrottled() and IsDisplayLocked() as
  // separate bits.
  remote_frame_->GetRemoteFrameHostRemote().UpdateRenderThrottlingStatus(
      IsHiddenForThrottling(), IsSubtreeThrottled(), IsDisplayLocked());
}

void RemoteFrameView::VisibilityChanged(
    blink::mojom::FrameVisibility visibility) {
  remote_frame_->GetRemoteFrameHostRemote().VisibilityChanged(visibility);
}

bool RemoteFrameView::CanThrottleRendering() const {
  return IsHiddenForThrottling() || IsSubtreeThrottled() || IsDisplayLocked();
}

void RemoteFrameView::SetIntrinsicSizeInfo(
    const IntrinsicSizingInfo& size_info) {
  intrinsic_sizing_info_ = size_info;
  has_intrinsic_sizing_info_ = true;
}

bool RemoteFrameView::GetIntrinsicSizingInfo(
    IntrinsicSizingInfo& sizing_info) const {
  if (!has_intrinsic_sizing_info_)
    return false;

  sizing_info = intrinsic_sizing_info_;
  return true;
}

bool RemoteFrameView::HasIntrinsicSizingInfo() const {
  return has_intrinsic_sizing_info_;
}

uint32_t RemoteFrameView::Print(const gfx::Rect& rect,
                                cc::PaintCanvas* canvas) const {
#if BUILDFLAG(ENABLE_PRINTING)
  auto* metafile = canvas->GetPrintingMetafile();
  DCHECK(metafile);

  // Create a place holder content for the remote frame so it can be replaced
  // with actual content later.
  // TODO(crbug.com/1093929): Consider to use an embedding token which
  // represents the state of the remote frame. See also comments on
  // https://crrev.com/c/2245430/.
  uint32_t content_id = metafile->CreateContentForRemoteFrame(
      rect, remote_frame_->GetFrameToken().value());

  // Inform browser to print the remote subframe.
  remote_frame_->GetRemoteFrameHostRemote().PrintCrossProcessSubframe(
      rect, metafile->GetDocumentCookie());
  return content_id;
#else
  return 0;
#endif
}

uint32_t RemoteFrameView::CapturePaintPreview(const gfx::Rect& rect,
                                              cc::PaintCanvas* canvas) const {
  auto* tracker = canvas->GetPaintPreviewTracker();
  DCHECK(tracker);  // |tracker| must exist or there is a bug upstream.

  // RACE: there is a possibility that the embedding token will be null and
  // still be in a valid state. This can occur is the frame has recently
  // navigated and the embedding token hasn't propagated from the FrameTreeNode
  // to this HTMLFrameOwnerElement yet (over IPC). If the token is null the
  // failure can be handled gracefully by simply ignoring the subframe in the
  // result.
  std::optional<base::UnguessableToken> maybe_embedding_token =
      remote_frame_->GetEmbeddingToken();
  if (!maybe_embedding_token.has_value())
    return 0;
  uint32_t content_id =
      tracker->CreateContentForRemoteFrame(rect, maybe_embedding_token.value());

  // Send a request to the browser to trigger a capture of the remote frame.
  remote_frame_->GetRemoteFrameHostRemote()
      .CapturePaintPreviewOfCrossProcessSubframe(rect, tracker->Guid());
  return content_id;
}

void RemoteFrameView::Trace(Visitor* visitor) const {
  visitor->Trace(remote_frame_);
}

}  // namespace blink

"""

```
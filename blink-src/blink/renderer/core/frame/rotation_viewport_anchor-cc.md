Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the explanation.

1. **Understand the Goal:** The request asks for the functionality of `rotation_viewport_anchor.cc`, its relationship to web technologies (JS, HTML, CSS), and examples of logic, potential errors, and input/output.

2. **Identify the Core Class:** The filename and the code itself point to the `RotationViewportAnchor` class as the central piece. The constructor and destructor immediately give clues about its lifecycle and purpose.

3. **Analyze the Constructor and Destructor:**
   - Constructor: `RotationViewportAnchor(...)`. The parameters hint at its involvement with the viewport, scaling, and an anchor point. The call to `SetAnchor()` suggests initialization logic.
   - Destructor: `~RotationViewportAnchor()`. The call to `RestoreToAnchor()` suggests a cleanup or rollback mechanism. This hints that the class temporarily modifies something and needs to revert it.

4. **Examine Key Methods:**
   - `SetAnchor()`: This is crucial. The comments and code reveal its purpose: to store the current viewport state and identify an anchor point based on user interaction. The use of `HitTestResultAtLocation` strongly suggests finding an element under a specific coordinate. The logic for handling large nodes is interesting and worth noting.
   - `RestoreToAnchor()`: This method calculates and applies new viewport settings based on the stored anchor information. The involvement of `page_scale_constraints_set_` is significant for understanding how scaling is managed.
   - `ComputeOrigins()`: This function seems to be the core of the restoration logic, calculating the new viewport position. It involves complex calculations with `outer_size`, `inner_size`, and offsets.
   - `GetInnerOrigin()`:  This method appears to calculate the target position of the viewport based on the anchor node's current position. The checks for node connection and layout object existence are important for robustness.
   - Helper functions like `FindNonEmptyAnchorNode`, `MoveToEncloseRect`, and `MoveIntoRect` provide supporting logic for the main methods. Understanding their individual roles (finding the anchor, ensuring a rectangle contains another, moving a rectangle within bounds) is essential.

5. **Identify Key Data Members:**  The member variables like `anchor_node_`, `anchor_in_inner_view_coords_`, `old_page_scale_factor_`, etc., store the state needed for the anchor mechanism.

6. **Infer Functionality:** Based on the method and member analysis, the primary function of `RotationViewportAnchor` is to maintain a specific point of focus on the page when the viewport size changes (likely due to screen rotation). It "anchors" to an element or a point on the page and attempts to keep that point in the same visual location after rotation.

7. **Connect to Web Technologies:**
   - **JavaScript:**  While this C++ code isn't directly JS, it reacts to user interactions (like touches or clicks) that can be initiated by JS. JS can trigger layout changes or page scaling, and this code helps maintain visual consistency. Examples: `window.scrollTo()`, `element.getBoundingClientRect()`, touch event handlers.
   - **HTML:** The anchor point is often an HTML element. The code uses `Node` and `LayoutObject`, which directly correspond to the DOM structure created by HTML.
   - **CSS:** CSS properties influence the layout and size of elements, affecting the bounding boxes used for anchoring. Media queries that trigger layout changes based on screen orientation are a direct connection.

8. **Construct Logic Examples (Input/Output):** Think about a simple scenario:
   - **Input:** User taps on a button. The coordinates of the tap are the initial `anchor_in_inner_view_coords_`.
   - **Process:** `SetAnchor()` finds the button element.
   - **Action:** The screen rotates.
   - **Output:** `RestoreToAnchor()` adjusts the scroll position and zoom level to try and keep the button in roughly the same spot on the screen.

9. **Identify Potential Usage Errors:** Consider common developer mistakes or browser behaviors:
   - Deleting the anchor node after setting the anchor but before restoring.
   - Rapidly changing the zoom level or scrolling while an anchor is active.
   - Anchoring to elements with dynamically changing sizes or positions.

10. **Structure the Explanation:**  Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logic Examples, Usage Errors. Use clear and concise language.

11. **Refine and Elaborate:** Review the generated explanation. Are there any ambiguities? Can any points be clarified with more specific examples?  For instance, elaborating on how `HitTestResultAtLocation` works.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just about simple scrolling. **Correction:** The mention of "rotation" and the complex scaling logic indicates something more specific than basic scrolling.
* **Focusing too much on low-level details:**  Realize that the request is about understanding the *functionality* at a higher level, not just the individual lines of code. Shift focus to the overall purpose and how it interacts with the web.
* **Not enough concrete examples:**  Recognize the need for specific examples of how this C++ code relates to JS, HTML, and CSS. Think of concrete web development scenarios.
* **Overly technical language:**  Simplify the language to be more accessible, avoiding excessive jargon where possible.

By following these steps and incorporating self-correction, we can arrive at a comprehensive and informative explanation of the `rotation_viewport_anchor.cc` file.
这个C++源代码文件 `rotation_viewport_anchor.cc` 实现了 Chromium Blink 引擎中一个关键的功能：**在页面缩放或旋转等导致视口变化的场景下，维持用户关注点的功能，即“旋转视口锚定” (Rotation Viewport Anchoring)**。

更具体地说，它的作用是：

1. **记录锚点信息 (Setting the Anchor):**
   - 当需要固定视口焦点时（例如，在触摸缩放或双指旋转开始时），它会记录当前视口的缩放比例、最小缩放比例以及一个锚点。
   - 这个锚点可以是用户触摸或点击的位置，并通过 `FindNonEmptyAnchorNode` 函数找到该位置对应的 DOM 节点。
   - 它会记录锚点在视口坐标系和被锚定节点坐标系中的相对位置。
   - 如果找不到合适的 DOM 节点，它会退回到使用绝对的文档坐标作为锚点。

2. **在视口变化后恢复锚点 (Restoring to Anchor):**
   - 当视口的缩放比例或位置发生变化后（例如，旋转屏幕导致视口尺寸和比例变化），它会尝试将之前记录的锚点重新定位到屏幕上的相似位置。
   - 它会根据新的视口约束和之前的锚点信息，计算出新的视口缩放比例和位置。
   - 核心思想是，即使视口大小或形状改变，用户最初关注的那个点或元素仍然尽可能地保持在屏幕的相似相对位置。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个文件是用 C++ 编写的，但它直接影响用户与网页的交互体验，并与 JavaScript, HTML, CSS 的功能息息相关：

* **JavaScript:**
    * **触摸事件 (Touch Events):**  旋转视口锚定通常在用户进行触摸操作（例如双指缩放或旋转）时触发。JavaScript 可以监听这些触摸事件 (`touchstart`, `touchmove`, `touchend`)，并可能间接地触发 Blink 引擎中的相关逻辑，最终调用到 `RotationViewportAnchor` 的功能。
    * ** programmatic scrolling 和 zooming:** JavaScript 可以通过 `window.scrollTo()`, `window.scrollBy()`, 或者一些库来实现页面的滚动和缩放。当这些操作发生时，`RotationViewportAnchor` 的逻辑会被触发，以确保用户关注的点不会丢失。
    * **获取元素位置和大小:**  `RotationViewportAnchor` 内部使用 `HitTestResult` 来查找点击位置对应的 DOM 节点，这与 JavaScript 中使用 `document.elementFromPoint()` 等方法获取元素信息的功能类似。它也需要获取元素的布局信息，这与 JavaScript 中使用 `element.getBoundingClientRect()` 获取元素尺寸和位置息息相关。

    **举例说明:**  假设用户使用移动设备浏览网页，并双指放大查看图片中的某个细节。当用户松开手指后，即使视口可能因为缩放而改变，`RotationViewportAnchor` 的功能会确保用户关注的那个图片细节仍然在屏幕的中心附近，而不是因为缩放而完全移出视野。这个过程可能由底层的触摸事件处理触发，但最终目的是保持用户在 JavaScript 层面上关注的视觉区域。

* **HTML:**
    * **DOM 结构:** `RotationViewportAnchor` 的核心功能是找到用户点击位置对应的 DOM 节点，并根据该节点的位置来计算锚点。HTML 提供的 DOM 结构是其工作的基础。
    * **元素布局:**  锚定操作依赖于 HTML 元素的布局信息（位置、大小）。Blink 引擎需要根据 HTML 结构和 CSS 样式计算出元素的最终布局，才能准确地确定锚点。

    **举例说明:** 用户点击了一个 HTML 的 `<button>` 元素。`RotationViewportAnchor` 会找到这个按钮对应的 `Node` 对象，并记录其在页面中的位置和大小作为锚点信息。

* **CSS:**
    * **布局和渲染:** CSS 决定了网页元素的布局和渲染方式，直接影响元素的尺寸和位置，而这些信息是 `RotationViewportAnchor` 计算锚点所必需的。
    * **视口元标签 (Viewport Meta Tag):**  `<meta name="viewport" ...>`  标签的设置会影响视口的初始大小、缩放级别等，这些设置会影响 `RotationViewportAnchor` 的初始状态和行为。
    * **CSS 变换 (CSS Transforms):**  CSS `transform` 属性可以改变元素的位置、旋转和缩放。虽然 `RotationViewportAnchor` 主要关注视口级别的变化，但元素自身的变换可能会影响锚点的计算。

    **举例说明:** 网页使用了响应式设计，不同的屏幕尺寸会导致不同的 CSS 布局。当屏幕旋转时，CSS 媒体查询可能会改变元素的布局。`RotationViewportAnchor` 需要能够适应这些布局变化，确保锚定功能仍然有效。

**逻辑推理与假设输入/输出：**

假设用户在浏览一个包含一个大图片的网页。

**假设输入：**

1. **用户操作:** 用户在图片的中心位置进行了一次触摸操作（例如，开始双指缩放）。
2. **视口状态:** 初始视口缩放比例为 1.0，滚动位置为 (0, 0)。
3. **锚点查找:** `FindNonEmptyAnchorNode` 函数找到了图片对应的 `<img>` 元素的 `LayoutObject`。
4. **锚点信息记录:**  记录了图片的边界信息、触摸点在视口中的相对位置 (例如 0.5, 0.5)，以及触摸点在图片坐标系中的相对位置。
5. **视口变化:** 用户进行了放大操作，视口缩放比例变为 2.0。

**逻辑推理：**

1. `RotationViewportAnchor::SetAnchor()` 被调用，记录初始视口状态和锚点信息（图片中心）。
2. 当视口缩放比例变化时，`RotationViewportAnchor::RestoreToAnchor()` 被调用。
3. `ComputeOrigins` 函数根据新的缩放比例和之前记录的锚点信息，计算出新的视口位置。它的目标是让之前触摸的图片中心点仍然位于屏幕的中心位置。
4. 它会考虑到视口的边界和页面的内容大小，确保新的视口位置是合法的。

**假设输出：**

新的视口位置会调整，使得图片的中心（用户触摸的位置）大致保持在屏幕的中心位置。例如，如果初始状态图片中心在屏幕中心，放大后，视口会滚动，使得放大后的图片中心仍然在屏幕中心。

**用户或编程常见的使用错误：**

1. **在锚定后删除锚点元素:** 如果在调用 `SetAnchor()` 后，但在 `RestoreToAnchor()` 之前，对应的 DOM 节点被删除，`GetInnerOrigin` 函数会返回回退的视口位置，可能导致锚定失效或不准确。

   **举例:**  JavaScript 代码动态地移除了用户点击的元素，然后触发了视口的重新定位。由于锚点元素已不存在，系统可能无法正确恢复到预期的位置。

2. **快速连续的视口变化:**  如果视口在极短的时间内发生多次变化（例如，快速连续的缩放操作），`RotationViewportAnchor` 可能无法完美地处理每一次变化，可能导致轻微的视觉跳跃或不流畅。

3. **锚定到频繁移动或大小变化的元素:** 如果锚定到一个自身位置或大小会频繁变化的元素（例如，正在播放动画的元素），锚定的效果可能不理想，因为在 `RestoreToAnchor()` 时，锚点元素的位置已经和记录时不同了。

   **举例:**  用户点击了一个正在进行 CSS `transform: translate()` 动画的元素，然后屏幕旋转。在恢复锚点时，由于元素的位置已经发生了变化，可能会导致最终的视口位置不是用户期望的。

4. **错误地配置视口元标签:**  如果 `<meta name="viewport">` 标签配置不当，例如禁用了用户缩放，可能会影响 `RotationViewportAnchor` 的工作或使其变得不必要。

总而言之，`rotation_viewport_anchor.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它通过精巧的算法和对页面结构的理解，提升了用户在面对视口变化时的浏览体验，确保了用户关注点的连贯性。它虽然是 C++ 代码，但与 Web 前端技术 JavaScript, HTML, CSS 紧密相连，共同构建了现代网页的交互体验。

Prompt: 
```
这是目录为blink/renderer/core/frame/rotation_viewport_anchor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/rotation_viewport_anchor.h"

#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

namespace {

static const float kViewportAnchorRelativeEpsilon = 0.1f;
static const int kViewportToNodeMaxRelativeArea = 2;

Node* FindNonEmptyAnchorNode(const gfx::PointF& absolute_point,
                             const gfx::Rect& view_rect,
                             EventHandler& event_handler) {
  gfx::Point point = gfx::ToFlooredPoint(absolute_point);
  HitTestLocation location(point);
  Node* node =
      event_handler
          .HitTestResultAtLocation(
              location, HitTestRequest::kReadOnly | HitTestRequest::kActive)
          .InnerNode();

  if (!node)
    return nullptr;

  // If the node bounding box is sufficiently large, make a single attempt to
  // find a smaller node; the larger the node bounds, the greater the
  // variability under resize.
  gfx::Size node_size =
      node->GetLayoutObject()
          ? node->GetLayoutObject()->AbsoluteBoundingBoxRect().size()
          : gfx::Size();
  const int max_node_area =
      view_rect.width() * view_rect.height() * kViewportToNodeMaxRelativeArea;
  if (node_size.width() * node_size.height() > max_node_area) {
    gfx::Size point_offset = gfx::ScaleToFlooredSize(
        view_rect.size(), kViewportAnchorRelativeEpsilon);
    HitTestLocation alternative_location(
        point + gfx::Vector2d(point_offset.width(), point_offset.height()));
    node = event_handler
               .HitTestResultAtLocation(
                   alternative_location,
                   HitTestRequest::kReadOnly | HitTestRequest::kActive)
               .InnerNode();
  }

  while (node &&
         (!node->GetLayoutObject() ||
          node->GetLayoutObject()->AbsoluteBoundingBoxRect().IsEmpty())) {
    node = node->parentNode();
  }

  return node;
}

void MoveToEncloseRect(gfx::Rect& outer, const gfx::RectF& inner) {
  gfx::Point minimum_position = gfx::ToCeiledPoint(
      inner.bottom_right() - gfx::Vector2dF(outer.width(), outer.height()));
  gfx::Point maximum_position = gfx::ToFlooredPoint(inner.origin());

  gfx::Point outer_origin = outer.origin();
  outer_origin.SetToMax(minimum_position);
  outer_origin.SetToMin(maximum_position);

  outer.set_origin(outer_origin);
}

void MoveIntoRect(gfx::RectF& inner, const gfx::Rect& outer) {
  gfx::PointF minimum_position = gfx::PointF(outer.origin());
  gfx::PointF maximum_position = gfx::PointF(outer.bottom_right()) -
                                 gfx::Vector2dF(inner.width(), inner.height());

  // Adjust maximumPosition to the nearest lower integer because
  // VisualViewport::maximumScrollPosition() does the same.
  // The value of minumumPosition is already adjusted since it is
  // constructed from an integer point.
  maximum_position = gfx::PointF(gfx::ToFlooredPoint(maximum_position));

  gfx::PointF inner_origin = inner.origin();
  inner_origin.SetToMax(minimum_position);
  inner_origin.SetToMin(maximum_position);

  inner.set_origin(inner_origin);
}

}  // namespace

RotationViewportAnchor::RotationViewportAnchor(
    LocalFrameView& root_frame_view,
    VisualViewport& visual_viewport,
    const gfx::PointF& anchor_in_inner_view_coords,
    PageScaleConstraintsSet& page_scale_constraints_set)
    : root_frame_view_(&root_frame_view),
      visual_viewport_(&visual_viewport),
      anchor_node_(nullptr),
      anchor_in_inner_view_coords_(anchor_in_inner_view_coords),
      page_scale_constraints_set_(&page_scale_constraints_set) {
  SetAnchor();
}

RotationViewportAnchor::~RotationViewportAnchor() {
  RestoreToAnchor();
}

void RotationViewportAnchor::SetAnchor() {
  RootFrameViewport* root_frame_viewport =
      root_frame_view_->GetRootFrameViewport();
  DCHECK(root_frame_viewport);

  old_page_scale_factor_ = visual_viewport_->Scale();
  old_minimum_page_scale_factor_ =
      page_scale_constraints_set_->FinalConstraints().minimum_scale;

  // Save the absolute location in case we won't find the anchor node, we'll
  // fall back to that.
  visual_viewport_in_document_ =
      gfx::PointF(root_frame_viewport->VisibleContentRect().origin());

  anchor_node_ = nullptr;
  anchor_node_bounds_ = PhysicalRect();
  anchor_in_node_coords_ = gfx::PointF();
  normalized_visual_viewport_offset_ = gfx::Vector2dF();

  gfx::Rect inner_view_rect = root_frame_viewport->VisibleContentRect();

  // Preserve origins at the absolute screen origin.
  if (inner_view_rect.origin().IsOrigin() || inner_view_rect.IsEmpty())
    return;

  gfx::Rect outer_view_rect =
      LayoutViewport().VisibleContentRect(kIncludeScrollbars);

  // Normalize by the size of the outer rect
  DCHECK(!outer_view_rect.IsEmpty());
  normalized_visual_viewport_offset_ = gfx::ScaleVector2d(
      visual_viewport_->GetScrollOffset(), 1.0 / outer_view_rect.width(),
      1.0 / outer_view_rect.height());

  // Note, we specifically use the unscaled visual viewport size here as the
  // conversion into content-space below will apply the scale.
  gfx::PointF anchor_offset(visual_viewport_->Size().width(),
                            visual_viewport_->Size().height());
  anchor_offset.Scale(anchor_in_inner_view_coords_.x(),
                      anchor_in_inner_view_coords_.y());

  // Note, we specifically convert to the rootFrameView contents here, rather
  // than the layout viewport. That's because hit testing works from the
  // LocalFrameView's absolute coordinates even if it's not the layout viewport.
  const gfx::PointF anchor_point_in_document =
      root_frame_view_->RootFrameToDocument(
          visual_viewport_->ViewportToRootFrame(anchor_offset));

  Node* node = FindNonEmptyAnchorNode(
      root_frame_view_->DocumentToFrame(anchor_point_in_document),
      inner_view_rect, root_frame_view_->GetFrame().GetEventHandler());
  if (!node || !node->GetLayoutObject())
    return;

  anchor_node_ = node;
  anchor_node_bounds_ = root_frame_view_->FrameToDocument(
      PhysicalRect(node->GetLayoutObject()->AbsoluteBoundingBoxRect()));
  anchor_in_node_coords_ =
      anchor_point_in_document - gfx::Vector2dF(anchor_node_bounds_.offset);
  anchor_in_node_coords_.Scale(1.f / anchor_node_bounds_.Width(),
                               1.f / anchor_node_bounds_.Height());
}

void RotationViewportAnchor::RestoreToAnchor() {
  float new_page_scale_factor =
      old_page_scale_factor_ / old_minimum_page_scale_factor_ *
      page_scale_constraints_set_->FinalConstraints().minimum_scale;
  new_page_scale_factor =
      page_scale_constraints_set_->FinalConstraints().ClampToConstraints(
          new_page_scale_factor);

  gfx::SizeF visual_viewport_size(visual_viewport_->Size());
  visual_viewport_size.Scale(1 / new_page_scale_factor);

  gfx::Point main_frame_origin;
  gfx::PointF visual_viewport_origin;

  ComputeOrigins(visual_viewport_size, main_frame_origin,
                 visual_viewport_origin);

  LayoutViewport().SetScrollOffset(
      ScrollOffset(main_frame_origin.OffsetFromOrigin()),
      mojom::blink::ScrollType::kProgrammatic);

  // Set scale before location, since location can be clamped on setting scale.
  visual_viewport_->SetScale(new_page_scale_factor);
  visual_viewport_->SetLocation(visual_viewport_origin);
}

ScrollableArea& RotationViewportAnchor::LayoutViewport() const {
  RootFrameViewport* root_frame_viewport =
      root_frame_view_->GetRootFrameViewport();
  DCHECK(root_frame_viewport);
  return root_frame_viewport->LayoutViewport();
}

void RotationViewportAnchor::ComputeOrigins(
    const gfx::SizeF& inner_size,
    gfx::Point& main_frame_origin,
    gfx::PointF& visual_viewport_origin) const {
  gfx::Size outer_size = LayoutViewport().VisibleContentRect().size();

  // Compute the viewport origins in CSS pixels relative to the document.
  gfx::Vector2dF abs_visual_viewport_offset =
      gfx::ScaleVector2d(normalized_visual_viewport_offset_, outer_size.width(),
                         outer_size.height());

  gfx::PointF inner_origin = GetInnerOrigin(inner_size);
  gfx::PointF outer_origin = inner_origin - abs_visual_viewport_offset;

  gfx::Rect outer_rect(gfx::ToFlooredPoint(outer_origin), outer_size);
  gfx::RectF inner_rect(inner_origin, inner_size);

  MoveToEncloseRect(outer_rect, inner_rect);

  outer_rect.set_origin(gfx::PointAtOffsetFromOrigin(
      LayoutViewport().ClampScrollOffset(outer_rect.OffsetFromOrigin())));

  MoveIntoRect(inner_rect, outer_rect);

  main_frame_origin = outer_rect.origin();
  visual_viewport_origin = inner_rect.origin() - outer_rect.OffsetFromOrigin();
}

gfx::PointF RotationViewportAnchor::GetInnerOrigin(
    const gfx::SizeF& inner_size) const {
  if (!anchor_node_ || !anchor_node_->isConnected() ||
      !anchor_node_->GetLayoutObject())
    return visual_viewport_in_document_;

  const PhysicalRect current_node_bounds = root_frame_view_->FrameToDocument(
      PhysicalRect(anchor_node_->GetLayoutObject()->AbsoluteBoundingBoxRect()));
  if (anchor_node_bounds_ == current_node_bounds)
    return visual_viewport_in_document_;

  RootFrameViewport* root_frame_viewport =
      root_frame_view_->GetRootFrameViewport();
  const PhysicalRect current_node_bounds_in_layout_viewport =
      root_frame_viewport->RootContentsToLayoutViewportContents(
          *root_frame_view_, current_node_bounds);

  // Compute the new anchor point relative to the node position
  gfx::Vector2dF anchor_offset_from_node(
      current_node_bounds_in_layout_viewport.size.width,
      current_node_bounds_in_layout_viewport.size.height);
  anchor_offset_from_node.Scale(anchor_in_node_coords_.x(),
                                anchor_in_node_coords_.y());
  gfx::PointF anchor_point =
      gfx::PointF(current_node_bounds_in_layout_viewport.offset) +
      anchor_offset_from_node;

  // Compute the new origin point relative to the new anchor point
  gfx::Vector2dF anchor_offset_from_origin = gfx::ScaleVector2d(
      gfx::Vector2dF(inner_size.width(), inner_size.height()),
      anchor_in_inner_view_coords_.x(), anchor_in_inner_view_coords_.y());
  return anchor_point - anchor_offset_from_origin;
}

}  // namespace blink

"""

```